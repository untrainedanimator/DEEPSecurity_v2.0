"""Alembic environment for DEEPSecurity.

The DB URL is read from settings (DEEPSEC_DATABASE_URL) at runtime — never
hardcoded into alembic.ini. That makes the same migration script work
identically against SQLite, Postgres, and any test fixture URL.

Target metadata is taken from deepsecurity.models.Base so future
``alembic revision --autogenerate`` runs see the live schema.
"""
from __future__ import annotations

import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import engine_from_config, pool

# Make sure the project package is importable when alembic runs from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from deepsecurity.config import settings  # path tweak above
from deepsecurity.models import Base  # path tweak above

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Inject the runtime DB URL.
config.set_main_option("sqlalchemy.url", settings.database_url)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations without a live connection (emit SQL)."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
        # SQLite does not support ALTER COLUMN by default; render_as_batch
        # asks Alembic to copy-recreate the table for us.
        render_as_batch=url.startswith("sqlite:"),
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations against a live engine."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        is_sqlite = connection.dialect.name == "sqlite"
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
            render_as_batch=is_sqlite,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
