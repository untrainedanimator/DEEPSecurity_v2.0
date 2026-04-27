"""initial baseline — captures the v2.4.0 schema as it shipped before Alembic

Revision ID: 0001_initial_baseline
Revises:
Create Date: 2026-04-26 00:00:00

This is a no-op upgrade. The first migration after Alembic was wired up
captures the live schema as the baseline; the actual table creation is
performed by ``deepsecurity.models.Base.metadata.create_all`` in
``deepsecurity.db.bootstrap_schema()`` for fresh installs (idempotent), and
this migration tags the alembic_version table so subsequent ``upgrade head``
calls behave correctly.

Migrations from v2.5.0 onwards (e.g. an OIDC user/session table) will be
real. Anyone running an existing v2.4.x deployment can run
``alembic stamp head`` once to mark themselves at this baseline without
touching their data.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa  # noqa: F401  (kept for symmetry with future revisions)
from alembic import op  # noqa: F401  (kept for symmetry with future revisions)

# revision identifiers, used by Alembic.
revision: str = "0001_initial_baseline"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # No-op: the v2.4.x schema is created via metadata.create_all on first
    # boot. This migration exists solely so alembic_version has a head to
    # point at and ``alembic stamp head`` is meaningful.
    pass


def downgrade() -> None:
    # Cannot meaningfully downgrade past the baseline.
    raise RuntimeError("cannot downgrade past initial baseline")
