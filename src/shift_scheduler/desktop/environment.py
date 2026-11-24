"""Environment of each child process (pure functions, unit-tested).

Children receive only what they need. The parent environment is not inherited
except for a small allowlist the OS and runtimes require.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from urllib.parse import quote

from shift_scheduler.desktop import layout
from shift_scheduler.desktop.layout import DataLayout, RuntimeLayout

SOURCE_NODE = "desktop-source"
OPERATOR = "desktop-operator"

_INHERITED = (
    "PATH",
    "SYSTEMROOT",
    "WINDIR",
    "TEMP",
    "TMP",
    "TMPDIR",
    "HOME",
    "USERPROFILE",
    "LOCALAPPDATA",
    "APPDATA",
    "LANG",
    "LC_ALL",
    "TZ",
)


def _base(parent: Mapping[str, str]) -> dict[str, str]:
    env = {key: parent[key] for key in _INHERITED if key in parent}
    env["PYTHONNOUSERSITE"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONUTF8"] = "1"
    return env


def db_url(secret: Mapping[str, str], database: str) -> str:
    password = quote(secret["db_password"], safe="")
    return (
        f"postgresql+psycopg://{layout.DB_USER}:{password}@{layout.HOST}:"
        f"{layout.DB_PORT}/{database}"
    )


def credentials(secret: Mapping[str, str]) -> dict[str, dict[str, str]]:
    return {
        SOURCE_NODE: {"role": "source", "token": secret["source_token"]},
        OPERATOR: {"role": "operator", "token": secret["operator_token"]},
    }


def postgres(parent: Mapping[str, str], secret: Mapping[str, str]) -> dict[str, str]:
    env = _base(parent)
    env.update(
        PGPASSWORD=secret["db_password"],
        PGUSER=layout.DB_USER,
        PGHOST=layout.HOST,
        PGPORT=str(layout.DB_PORT),
    )
    return env


def control(
    parent: Mapping[str, str], secret: Mapping[str, str], data: DataLayout
) -> dict[str, str]:
    env = _base(parent)
    env.update(
        PHARMSHIFT_ENV="desktop",
        PHARMSHIFT_AUTHORITY_DB_URL=db_url(secret, layout.CONTROL_DB),
        PHARMSHIFT_AUTHORITY_PRIVATE_KEY=secret["authority_private_key"],
        PHARMSHIFT_AUTHORITY_CREDENTIALS=json.dumps(credentials(secret)),
        SSL_CERT_FILE=str(data.ca),
    )
    return env


def application(
    parent: Mapping[str, str], secret: Mapping[str, str], data: DataLayout
) -> dict[str, str]:
    """API and worker: the settings validated by config/desktop.py."""
    env = _base(parent)
    env.update(
        PHARMSHIFT_ENV="desktop",
        AUTH_MODE="local",
        SHIFT_SCHEDULER_DATA_BACKEND="db",
        DATABASE_URL=db_url(secret, layout.APP_DB),
        AUTH_JWT_SECRET=secret["jwt_secret"],
        AUTH_COOKIE_SECURE="true",
        AUTH_COOKIE_SAMESITE="strict",
        FRONTEND_BASE_URL=layout.WEB_ORIGIN,
        API_CORS_ALLOW_ORIGINS=layout.WEB_ORIGIN,
        PHARMSHIFT_BIND_HOST=layout.HOST,
        PHARMSHIFT_INSTALL_ID=secret["install_id"],
        PHARMSHIFT_SETUP_TOKEN=secret["setup_token"],
        PHARMSHIFT_MANAGED_STORAGE=str(data.storage),
        PHARMSHIFT_CONTROL_URL=layout.CONTROL_URL,
        PHARMSHIFT_CONTROL_NODE=SOURCE_NODE,
        PHARMSHIFT_CONTROL_TOKEN=secret["source_token"],
        PHARMSHIFT_CONTROL_PUBLIC_KEY=secret["authority_public_key"],
        PHARMSHIFT_ERASURE_MANIFEST_KEY=secret["erasure_manifest_key"],
        PHARMSHIFT_ARCHIVE_KEY=secret["archive_key"],
        PHARMSHIFT_ARCHIVE_KEY_ID="desktop-1",
        SSL_CERT_FILE=str(data.ca),
    )
    return env


def web(parent: Mapping[str, str], data: DataLayout) -> dict[str, str]:
    env = _base(parent)
    env.update(
        NODE_ENV="production",
        NEXT_TELEMETRY_DISABLED="1",
        NODE_EXTRA_CA_CERTS=str(data.ca),
        NEXT_SSL_CERT_PATH=str(data.cert),
        NEXT_SSL_KEY_PATH=str(data.key),
        NEXT_PUBLIC_API_BASE_URL=layout.WEB_ORIGIN + "/api",
        INTERNAL_API_BASE_URL=layout.API_URL,
        HOSTNAME=layout.HOST,
        PORT=str(layout.WEB_PORT),
    )
    return env


def python_path(runtime: RuntimeLayout) -> str:
    """scripts/control_authority.py is not part of the installed package."""
    return str(runtime.app)
