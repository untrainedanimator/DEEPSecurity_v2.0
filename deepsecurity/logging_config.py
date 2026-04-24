"""Structured logging setup.

Two modes:
    - `log_json=True`  → JSON logs suitable for shipping to any log aggregator.
    - `log_json=False` → Pretty console output for local development.

Call `configure_logging()` exactly once, at application startup.
"""
from __future__ import annotations

import logging
import sys
from typing import Any

import structlog

from deepsecurity.config import settings


def configure_logging() -> None:
    """Configure structlog + stdlib logging. Idempotent."""
    level = getattr(logging, settings.log_level)

    # stdlib logging routes through structlog.
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=level,
    )

    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    if settings.log_json:
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=False)

    structlog.configure(
        processors=[*shared_processors, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Return a bound structlog logger. Safe to call before configure_logging()."""
    return structlog.get_logger(name)  # type: ignore[return-value]
