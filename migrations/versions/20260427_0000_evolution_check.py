"""evolution check — exercises the upgrade/downgrade machinery

Revision ID: 0002_evolution_check
Revises: 0001_initial_baseline
Create Date: 2026-04-27 00:00:00

This migration is a deliberate no-op against production data. Its sole
purpose is to validate that the Alembic framework can:

    1. Apply a real DDL change on top of the initial baseline
       (``alembic upgrade head``).
    2. Roll that DDL change back cleanly
       (``alembic downgrade -1``).
    3. Re-apply it without drift
       (``alembic upgrade head`` again).

We use a dedicated marker table (``_alembic_evolution_check``) so that:

* No production table is altered, locked, or rewritten.
* SQLite and Postgres both handle it identically — no batch-mode tricks
  required, no dialect-specific SQL.
* If a future schema change goes sideways, ops can drop this table
  manually without worrying about cascade effects.

This migration was added in v3.0.0 alongside the GA bump. Going forward,
real schema evolutions (new columns, new tables, index adds) should
follow this same pattern: a clean upgrade, a meaningful downgrade, and
no implicit reliance on ``metadata.create_all``.

Smoke-test from a fresh SQLite DB:

    alembic upgrade head           # applies 0001 then 0002 — table exists
    alembic downgrade -1           # rolls back 0002 — table is gone
    alembic upgrade head           # re-applies 0002 — table exists again
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0002_evolution_check"
down_revision: str | Sequence[str] | None = "0001_initial_baseline"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_TABLE = "_alembic_evolution_check"


def upgrade() -> None:
    """Create the evolution-check marker table."""
    op.create_table(
        _TABLE,
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "marker",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'v3_evolution'"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    # Insert a single sentinel row so a SELECT after upgrade() proves the
    # migration ran end-to-end (table created AND row written). The
    # f-string interpolates ``_TABLE`` (a module-private constant), not
    # user input — S608 is suppressed at the per-file-ignores level for
    # the whole migrations tree (see pyproject.toml).
    op.execute(sa.text(f"INSERT INTO {_TABLE} (marker) VALUES ('v3_evolution')"))


def downgrade() -> None:
    """Drop the evolution-check marker table."""
    op.drop_table(_TABLE)
