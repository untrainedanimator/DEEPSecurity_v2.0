"""mask_database_url covers every DB URI shape operators actually paste.

Regression guard for v2.3 audit finding: cli.py was echoing
settings.database_url verbatim into stdout, which on Postgres DSNs
leaks the password into terminal history / log files / screenshots.
"""
from __future__ import annotations

import pytest

from deepsecurity.secret_masking import mask_database_url


@pytest.mark.parametrize(
    "raw, expected",
    [
        # 1. SQLite relative path — no credentials, return unchanged.
        (
            "sqlite:///data/deepscan.db",
            "sqlite:///data/deepscan.db",
        ),
        # 2. SQLite absolute Windows path — no credentials, unchanged.
        (
            "sqlite:///C:/Apps/DEEPSecurity_v2.0/data/deepscan.db",
            "sqlite:///C:/Apps/DEEPSecurity_v2.0/data/deepscan.db",
        ),
        # 3. Postgres with user + password — password must be masked, everything
        #    else preserved (user, host, port, dbname are needed for triage).
        (
            "postgres://admin:hunter2@db.example.com:5432/deepsec",
            "postgres://admin:***@db.example.com:5432/deepsec",
        ),
        # 4. SQLAlchemy-style dialect+driver with password.
        (
            "postgresql+psycopg://svc:s3cret!@pg.internal/prod",
            "postgresql+psycopg://svc:***@pg.internal/prod",
        ),
        # 5. MySQL DSN with user but NO password — nothing to mask, unchanged.
        (
            "mysql://reader@10.0.0.5/audit",
            "mysql://reader@10.0.0.5/audit",
        ),
    ],
)
def test_mask_database_url_variants(raw: str, expected: str) -> None:
    assert mask_database_url(raw) == expected


def test_mask_handles_empty_and_malformed() -> None:
    """The CLI calls this in a log path. Raising would be worse than
    echoing the original string. Empty / malformed input must not blow up."""
    assert mask_database_url("") == ""
    assert mask_database_url(":memory:") == ":memory:"
    assert mask_database_url("not-a-url") == "not-a-url"


def test_mask_preserves_query_and_fragment() -> None:
    """sslmode, application_name, etc. live in the query. Those aren't
    secrets and we must not drop them — the operator needs them when
    debugging a connection error from the masked output."""
    raw = "postgres://u:p@h/db?sslmode=require&application_name=deepsec"
    out = mask_database_url(raw)
    assert "***" in out
    assert "sslmode=require" in out
    assert "application_name=deepsec" in out
