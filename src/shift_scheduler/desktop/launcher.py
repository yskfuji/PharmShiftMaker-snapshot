"""Start, supervise and stop the desktop edition.

Protocol with the Electron shell (stdout, one JSON object per line):
  {"event": "stage", "stage": "..."}                  progress
  {"event": "ready", "url": ..., "ca": ..., "setup_token": ...}
  {"event": "error", "stage": ..., "message": ..., "log": ...}
The shell closes our stdin to request shutdown; we also stop when it dies,
because its end of the pipe then closes. Nothing else is written to stdout.
"""

from __future__ import annotations

import json
import os
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any

from shift_scheduler.desktop import environment, layout, secrets, tls
from shift_scheduler.desktop.layout import DataLayout, RuntimeLayout

LOG_LIMIT = 10 * 1024 * 1024
STOP_SECONDS = 10.0
READY_SECONDS = 120.0
RENEW_DAYS = 30


class LaunchError(RuntimeError):
    def __init__(self, stage: str, message: str, log: Path | None = None) -> None:
        super().__init__(message)
        self.stage, self.log = stage, log


def emit(event: str, **fields: Any) -> None:
    sys.stdout.write(json.dumps({"event": event, **fields}, ensure_ascii=False) + "\n")
    sys.stdout.flush()


# ---------------------------------------------------------------- directories


def prepare_directories(data: DataLayout) -> None:
    for directory in data.directories():
        if directory.is_symlink():
            raise LaunchError("data", f"{directory} must not be a link")
        directory.mkdir(mode=0o700, parents=directory == data.root, exist_ok=True)
        if sys.platform == "win32":
            raise LaunchError(
                "data", "Windows data directories require the M3 ACL support"
            )
        os.chmod(directory, 0o700)


def open_log(data: DataLayout, name: str) -> IO[bytes]:
    path = data.logs / f"{name}.log"
    if path.exists() and path.stat().st_size > LOG_LIMIT:
        os.replace(path, path.with_suffix(".log.1"))
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    return os.fdopen(fd, "ab")


# ------------------------------------------------------------------ processes


@dataclass
class Child:
    name: str
    process: subprocess.Popen[bytes]
    log: Path


@dataclass
class Supervisor:
    data: DataLayout
    runtime: RuntimeLayout
    children: list[Child] = field(default_factory=list)

    def run(
        self,
        name: str,
        argv: Sequence[str | Path],
        env: Mapping[str, str],
        cwd: Path,
        timeout: float = 600,
    ) -> None:
        """Run a one-shot command; output goes to its log."""
        with open_log(self.data, name) as log:
            result = subprocess.run(
                [str(part) for part in argv],
                env=dict(env),
                cwd=cwd,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                timeout=timeout,
                check=False,
            )
        if result.returncode != 0:
            raise LaunchError(
                name, f"exited with {result.returncode}", self.data.logs / f"{name}.log"
            )

    def start(
        self, name: str, argv: Sequence[str | Path], env: Mapping[str, str], cwd: Path
    ) -> Child:
        log = open_log(self.data, name)
        flags = 0
        if sys.platform == "win32":
            flags = subprocess.CREATE_NEW_PROCESS_GROUP
        try:
            process = subprocess.Popen(
                [str(part) for part in argv],
                env=dict(env),
                cwd=cwd,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                creationflags=flags,
            )
        finally:
            log.close()
        child = Child(name, process, self.data.logs / f"{name}.log")
        self.children.append(child)
        return child

    def exited(self) -> Child | None:
        for child in self.children:
            if child.process.poll() is not None:
                return child
        return None

    def stop_children(self) -> None:
        for child in reversed(self.children):
            if child.process.poll() is None:
                child.process.terminate()
        deadline = time.monotonic() + STOP_SECONDS
        for child in reversed(self.children):
            try:
                child.process.wait(max(0.1, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                child.process.kill()
                child.process.wait()
        self.children.clear()


# ----------------------------------------------------------------- postgresql


def _pg_running(sup: Supervisor) -> bool:
    result = subprocess.run(
        [str(sup.runtime.pg("pg_ctl")), "-D", str(sup.data.pgdata), "status"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def init_cluster(sup: Supervisor, secret: Mapping[str, str]) -> None:
    pgdata = sup.data.pgdata
    if (pgdata / "PG_VERSION").exists():
        return
    if pgdata.exists() and any(pgdata.iterdir()):
        raise LaunchError("initdb", f"{pgdata} exists but is not a database cluster")
    password_file = sup.data.state / "initdb.pw"
    if password_file.exists():
        password_file.unlink()
    secrets.write_private(password_file, secret["db_password"].encode())
    try:
        sup.run(
            "initdb",
            [
                sup.runtime.pg("initdb"),
                "-D",
                pgdata,
                "-U",
                layout.DB_USER,
                f"--pwfile={password_file}",
                "-A",
                "scram-sha-256",
                "-E",
                "UTF8",
                "--locale=C",
            ],
            environment.postgres(os.environ, secret),
            sup.data.root,
        )
    finally:
        password_file.unlink(missing_ok=True)
    with (pgdata / "postgresql.conf").open("a", encoding="utf-8") as conf:
        conf.write(
            "\n# PharmShiftMaker desktop\n"
            f"listen_addresses = '{layout.HOST}'\n"
            f"port = {layout.DB_PORT}\n"
            "unix_socket_directories = ''\n"
            "password_encryption = 'scram-sha-256'\n"
        )
    (pgdata / "pg_hba.conf").write_text(
        f"host all {layout.DB_USER} {layout.HOST}/32 scram-sha-256\n", encoding="utf-8"
    )


def start_postgres(sup: Supervisor, secret: Mapping[str, str]) -> None:
    pg_ctl = sup.runtime.pg("pg_ctl")
    env = environment.postgres(os.environ, secret)
    if _pg_running(sup):
        # Left over from a crashed session: restart under our supervision.
        sup.run(
            "pg_stop",
            [pg_ctl, "-D", sup.data.pgdata, "-m", "fast", "-w", "stop"],
            env,
            sup.data.root,
        )
    log = sup.data.logs / "postgres.log"
    sup.run(
        "pg_start",
        [pg_ctl, "-D", sup.data.pgdata, "-l", log, "-w", "-t", "60", "start"],
        env,
        sup.data.root,
    )


def stop_postgres(sup: Supervisor, secret: Mapping[str, str]) -> None:
    if _pg_running(sup):
        sup.run(
            "pg_stop",
            [
                sup.runtime.pg("pg_ctl"),
                "-D",
                sup.data.pgdata,
                "-m",
                "fast",
                "-w",
                "stop",
            ],
            environment.postgres(os.environ, secret),
            sup.data.root,
        )


def ensure_databases(secret: Mapping[str, str]) -> None:
    import psycopg
    from psycopg import sql

    with psycopg.connect(
        host=layout.HOST,
        port=layout.DB_PORT,
        user=layout.DB_USER,
        password=secret["db_password"],
        dbname="postgres",
        autocommit=True,
    ) as connection:
        for name in (layout.APP_DB, layout.CONTROL_DB):
            exists = connection.execute(
                "select 1 from pg_database where datname = %s", (name,)
            ).fetchone()
            if not exists:
                connection.execute(
                    sql.SQL("create database {} encoding 'UTF8'").format(
                        sql.Identifier(name)
                    )
                )


# ----------------------------------------------------------------- readiness


def tls_context(data: DataLayout) -> ssl.SSLContext:
    return ssl.create_default_context(cafile=str(data.ca))


def wait_tls(port: int, context: ssl.SSLContext, child: Child) -> None:
    deadline = time.monotonic() + READY_SECONDS
    while time.monotonic() < deadline:
        if child.process.poll() is not None:
            raise LaunchError(child.name, "exited during startup", child.log)
        try:
            with (
                socket.create_connection((layout.HOST, port), timeout=2) as raw,
                context.wrap_socket(raw, server_hostname=layout.HOST),
            ):
                return
        except OSError:
            time.sleep(0.5)
    raise LaunchError(child.name, "did not become ready", child.log)


def wait_http(url: str, context: ssl.SSLContext, child: Child) -> None:
    deadline = time.monotonic() + READY_SECONDS
    while time.monotonic() < deadline:
        if child.process.poll() is not None:
            raise LaunchError(child.name, "exited during startup", child.log)
        try:
            with urllib.request.urlopen(url, context=context, timeout=5) as response:
                if response.status < 500:
                    return
        except urllib.error.HTTPError as error:
            if error.code < 500:
                return
        except OSError:
            pass
        time.sleep(0.5)
    raise LaunchError(child.name, "did not become ready", child.log)


def ports_free() -> None:
    for port in (layout.WEB_PORT, layout.API_PORT, layout.CONTROL_PORT, layout.DB_PORT):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            if probe.connect_ex((layout.HOST, port)) == 0:
                raise LaunchError(
                    "ports", f"port {port} on {layout.HOST} is already in use"
                )


def enroll_source(secret: Mapping[str, str], context: ssl.SSLContext) -> None:
    import httpx

    from shift_scheduler.control.client import AuthorityClient

    client = AuthorityClient(
        layout.CONTROL_URL,
        environment.OPERATOR,
        secret["operator_token"],
        secret["authority_public_key"],
        transport=httpx.HTTPTransport(verify=context),
    )
    client.request(
        "POST", "/nodes", {"node_id": environment.SOURCE_NODE, "role": "source"}
    )


# --------------------------------------------------------------------- launch


def launch(data: DataLayout, runtime: RuntimeLayout, stop: threading.Event) -> int:
    sup = Supervisor(data, runtime)
    secret: Mapping[str, str] | None = None
    try:
        emit("stage", stage="data")
        prepare_directories(data)
        secret = secrets.load_or_create(data.secrets)
        if data.cert.exists() and tls.leaf_expires_within(data.cert, RENEW_DAYS):
            data.cert.unlink()
        tls.ensure(data.ca, data.cert, data.key)
        ports_free()

        emit("stage", stage="database")
        init_cluster(sup, secret)
        start_postgres(sup, secret)
        ensure_databases(secret)

        python = runtime.python
        app_env = environment.application(os.environ, secret, data)
        control_env = environment.control(os.environ, secret, data)
        control_env["PYTHONPATH"] = environment.python_path(runtime)

        emit("stage", stage="migrate")
        sup.run(
            "migrate",
            [python, "-m", "alembic", "upgrade", "head"],
            app_env,
            runtime.app,
        )
        sup.run(
            "control_init",
            [python, "-m", "scripts.control_authority"],
            control_env,
            runtime.app,
        )

        context = tls_context(data)
        uvicorn_tls: list[str | Path] = [
            "--ssl-certfile",
            data.cert,
            "--ssl-keyfile",
            data.key,
        ]
        uvicorn_common: list[str | Path] = [
            "--host",
            layout.HOST,
            "--no-access-log",
            "--no-server-header",
        ]

        emit("stage", stage="control")
        control = sup.start(
            "control",
            [
                python,
                "-m",
                "uvicorn",
                "scripts.control_authority:build_app",
                "--factory",
                "--port",
                str(layout.CONTROL_PORT),
                *uvicorn_common,
                *uvicorn_tls,
            ],
            control_env,
            runtime.app,
        )
        wait_tls(layout.CONTROL_PORT, context, control)
        enroll_source(secret, context)

        emit("stage", stage="api")
        api = sup.start(
            "api",
            [
                python,
                "-m",
                "uvicorn",
                "shift_scheduler.api.main:app",
                "--port",
                str(layout.API_PORT),
                *uvicorn_common,
                *uvicorn_tls,
            ],
            app_env,
            runtime.app,
        )
        wait_http(layout.API_URL + "/healthz", context, api)
        sup.start(
            "worker",
            [python, "-m", "shift_scheduler.application.worker"],
            app_env,
            runtime.app,
        )

        emit("stage", stage="web")
        web = sup.start(
            "web",
            [runtime.node, runtime.web / "desktop-server.cjs"],
            environment.web(os.environ, data),
            runtime.web,
        )
        wait_http(layout.WEB_ORIGIN + "/login", context, web)

        emit(
            "ready",
            url=layout.WEB_ORIGIN,
            ca=str(data.ca),
            setup_token=secret["setup_token"],
        )
        while not stop.wait(0.5):
            gone = sup.exited()
            if gone:
                raise LaunchError(
                    gone.name,
                    f"stopped unexpectedly ({gone.process.returncode})",
                    gone.log,
                )
        return 0
    except LaunchError as error:
        emit(
            "error",
            stage=error.stage,
            message=str(error),
            log=str(error.log) if error.log else None,
        )
        return 2
    except Exception as error:  # report, then stop everything below
        emit(
            "error",
            stage="unexpected",
            message=f"{type(error).__name__}: {error}",
            log=None,
        )
        return 2
    finally:
        sup.stop_children()
        if secret is not None:
            try:
                stop_postgres(sup, secret)
            except LaunchError as error:
                emit("error", stage=error.stage, message=str(error), log=str(error.log))


def _watch_stdin(stop: threading.Event) -> None:
    try:
        while sys.stdin.buffer.read(1):
            pass
    finally:
        stop.set()


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) not in (1, 2):
        sys.stderr.write(
            "usage: python -m shift_scheduler.desktop RUNTIME_DIR [DATA_DIR]\n"
        )
        return 64
    runtime = RuntimeLayout(Path(args[0]).resolve())
    data = DataLayout(
        Path(args[1]).resolve() if len(args) == 2 else layout.default_data_root()
    )
    stop = threading.Event()
    threading.Thread(target=_watch_stdin, args=(stop,), daemon=True).start()
    if sys.platform != "win32":
        for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(number, lambda *_: stop.set())
    return launch(data, runtime, stop)
