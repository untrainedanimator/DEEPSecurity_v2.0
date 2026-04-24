"""Secret-masking helpers.

The only consumer right now is the CLI, which echoes connection URIs to
stdout during init-db / reset-db. If the operator swaps the dev SQLite
default for a Postgres DSN, the URL contains a password — we must not
log it verbatim (audit finding, v2.3 pre-release). This module is the
one authoritative place that knows how to render a DB URI so it's safe
to print into a terminal, a log file, or a support ticket screenshot.

Pure stdlib; no side effects; safe to import anywhere.
"""
from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit


def mask_database_url(url: str) -> str:
    """Return a copy of ``url`` with any embedded password replaced by ``***``.

    Handles the three shapes operators actually paste in the wild:

    - ``sqlite:///data/deepscan.db`` → unchanged (no credentials)
    - ``postgres://user:secret@host:5432/db`` → ``postgres://user:***@host:5432/db``
    - ``postgresql+psycopg://user:secret@host/db`` → ``postgresql+psycopg://user:***@host/db``
    - ``mysql://user@host/db`` → unchanged (no password present)
    - ``:memory:`` / empty / malformed → returned as-is rather than raising

    We ONLY mask the password. User, host, port, database name and
    query params are left alone — they aren't secrets and redacting them
    would make support triage impossible.
    """
    if not url or "://" not in url:
        return url
    try:
        parts = urlsplit(url)
    except ValueError:
        # Malformed URL; better to return the original than raise — caller
        # is usually in a log path where raising is worse than echoing.
        return url

    # Nothing to mask.
    if not parts.password:
        return url

    # Reconstruct netloc with the password replaced. urllib gives us the
    # components via parts.username / password / hostname / port; we have
    # to rebuild because there's no setter on SplitResult.
    user = parts.username or ""
    host = parts.hostname or ""
    netloc = f"{user}:***@{host}"
    if parts.port is not None:
        netloc += f":{parts.port}"

    return urlunsplit(
        (parts.scheme, netloc, parts.path, parts.query, parts.fragment)
    )
