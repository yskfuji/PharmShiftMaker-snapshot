"""Unit tests of the desktop launcher's pure parts (no PostgreSQL, no children)."""

from __future__ import annotations

import datetime
import ipaddress
import json
import os
import stat
import sys
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from shift_scheduler.api.auth import settings as auth_settings
from shift_scheduler.config import desktop as desktop_config
from shift_scheduler.desktop import environment, layout, secrets, tls
from shift_scheduler.desktop.layout import DataLayout, RuntimeLayout

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")


def test_issue_signs_loopback_leaf_and_discards_ca_key() -> None:
    ca_pem, leaf_pem, key_pem = tls.issue()
    ca = x509.load_pem_x509_certificate(ca_pem)
    leaf = x509.load_pem_x509_certificate(leaf_pem)
    public = ca.public_key()
    assert isinstance(public, ec.EllipticCurvePublicKey)
    leaf.verify_directly_issued_by(ca)
    constraints = ca.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert constraints.ca and constraints.path_length == 0
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.IPAddress) == [
        ipaddress.ip_address("127.0.0.1")
    ]
    assert not leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    assert b"PRIVATE KEY" in key_pem and b"PRIVATE KEY" not in ca_pem


@posix_only
def test_ensure_writes_owner_only_files_and_reissues_partial_sets(
    tmp_path: Path,
) -> None:
    ca, cert, key = tmp_path / "ca.pem", tmp_path / "server.pem", tmp_path / "key.pem"
    tls.ensure(ca, cert, key)
    for path in (ca, cert, key):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    first = ca.read_bytes()
    tls.ensure(ca, cert, key)
    assert ca.read_bytes() == first  # complete set is kept
    cert.unlink()
    tls.ensure(ca, cert, key)
    assert ca.read_bytes() != first  # partial set: whole new CA and leaf
    leaf = x509.load_pem_x509_certificate(cert.read_bytes())
    leaf.verify_directly_issued_by(x509.load_pem_x509_certificate(ca.read_bytes()))


def test_leaf_renewal_window(tmp_path: Path) -> None:
    ca, cert, key = tmp_path / "ca.pem", tmp_path / "server.pem", tmp_path / "key.pem"
    tls.ensure(ca, cert, key)
    assert not tls.leaf_expires_within(cert, 30)
    assert tls.leaf_expires_within(cert, tls.LEAF_DAYS + 1)


@posix_only
def test_secrets_created_once_and_owner_only(tmp_path: Path) -> None:
    path = tmp_path / "secrets.json"
    first = secrets.load_or_create(path)
    assert set(first) == set(secrets.FIELDS)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert secrets.load_or_create(path) == first
    assert len(first["jwt_secret"]) >= 32 and len(first["setup_token"]) >= 32
    assert len(bytes.fromhex(first["authority_private_key"])) == 32


@posix_only
def test_secrets_refuse_group_readable_or_incomplete(tmp_path: Path) -> None:
    path = tmp_path / "secrets.json"
    secrets.load_or_create(path)
    os.chmod(path, 0o640)
    with pytest.raises(PermissionError):
        secrets.load_or_create(path)
    os.chmod(path, 0o600)
    path.write_text(json.dumps({"install_id": "x"}), encoding="utf-8")
    with pytest.raises(ValueError, match="incomplete"):
        secrets.load_or_create(path)


def test_write_private_never_overwrites(tmp_path: Path) -> None:
    path = tmp_path / "file"
    secrets.write_private(path, b"one")
    with pytest.raises(FileExistsError):
        secrets.write_private(path, b"two")
    assert path.read_bytes() == b"one"


def _secret() -> dict[str, str]:
    return secrets.generate()


def test_children_do_not_inherit_unlisted_variables(tmp_path: Path) -> None:
    parent = {"PATH": "/bin", "AWS_SECRET_ACCESS_KEY": "x", "DATABASE_URL": "other"}
    data = DataLayout(tmp_path)
    secret = _secret()
    for env in (
        environment.application(parent, secret, data),
        environment.control(parent, secret, data),
        environment.web(parent, data),
        environment.postgres(parent, secret),
    ):
        assert "AWS_SECRET_ACCESS_KEY" not in env
        assert env["PATH"] == "/bin"
    assert environment.application(parent, secret, data)["DATABASE_URL"] != "other"


def test_web_and_control_do_not_receive_application_secrets(tmp_path: Path) -> None:
    data, secret = DataLayout(tmp_path), _secret()
    web = environment.web({}, data)
    control = environment.control({}, secret, data)
    for value in (
        secret["jwt_secret"],
        secret["db_password"],
        secret["setup_token"],
    ):
        assert value not in json.dumps(web)
    assert secret["jwt_secret"] not in json.dumps(control)
    assert "DATABASE_URL" not in control


def test_application_and_control_use_separate_databases(tmp_path: Path) -> None:
    data, secret = DataLayout(tmp_path), _secret()
    app_url = environment.application({}, secret, data)["DATABASE_URL"]
    control_url = environment.control({}, secret, data)["PHARMSHIFT_AUTHORITY_DB_URL"]
    assert app_url.endswith(f"/{layout.APP_DB}")
    assert control_url.endswith(f"/{layout.CONTROL_DB}")
    assert "control" in layout.CONTROL_DB and "control" not in layout.APP_DB


def test_credentials_match_the_client_settings(tmp_path: Path) -> None:
    data, secret = DataLayout(tmp_path), _secret()
    app = environment.application({}, secret, data)
    granted = json.loads(
        environment.control({}, secret, data)["PHARMSHIFT_AUTHORITY_CREDENTIALS"]
    )
    node = granted[app["PHARMSHIFT_CONTROL_NODE"]]
    assert node == {"role": "source", "token": app["PHARMSHIFT_CONTROL_TOKEN"]}
    assert granted[environment.OPERATOR]["role"] == "operator"


@posix_only
def test_application_environment_passes_the_desktop_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path.resolve() / "data"
    data = DataLayout(root)
    data.storage.mkdir(parents=True, mode=0o700)
    os.chmod(data.storage, 0o700)
    env = environment.application({}, _secret(), data)
    for key in list(os.environ):
        if key.startswith(("PHARMSHIFT_", "AUTH_", "API_", "FRONTEND_", "DATABASE_")):
            monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(desktop_config, "_local_filesystem", lambda _path: True)
    auth_settings.get_auth_mode.cache_clear()
    auth_settings.get_session_settings.cache_clear()
    try:
        desktop_config.check_desktop()
    finally:
        auth_settings.get_auth_mode.cache_clear()
        auth_settings.get_session_settings.cache_clear()


def test_runtime_layout_paths() -> None:
    runtime = RuntimeLayout(Path("/r"))
    if sys.platform == "win32":
        assert runtime.python == Path("/r/python/python.exe")
    else:
        assert runtime.python == Path("/r/python/bin/python3")
        assert runtime.pg("pg_ctl") == Path("/r/pg/bin/pg_ctl")
    assert runtime.web == Path("/r/web")


def test_cert_lifetime_constants_are_sane() -> None:
    assert tls.LEAF_DAYS <= 825
    now = datetime.datetime.now(datetime.UTC)
    leaf = x509.load_pem_x509_certificate(tls.issue(now)[1])
    assert leaf.not_valid_before_utc <= now
