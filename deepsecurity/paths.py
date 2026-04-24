"""Path sanitisation utilities.

The scanner and every API route that accepts a user-supplied path MUST pass it
through `resolve_under_root()` before doing anything with it. This is our
defence against path traversal.
"""
from __future__ import annotations

from pathlib import Path


class PathOutsideRootError(ValueError):
    """Raised when a caller tries to use a path outside the configured scan root."""


def resolve_under_root(user_path: str | Path, root: Path | list[Path]) -> Path:
    """Resolve `user_path` against an allow-list (or permit anything absolute).

    `root` may be:
        - a single Path — the candidate must be inside it
        - a list of Paths — the candidate must be inside AT LEAST one of them
        - an EMPTY list — permissive mode: any absolute path is accepted

    In every mode we refuse relative paths. Forcing an absolute path means
    the operator is deliberately choosing the target and the audit log
    captures it unambiguously.

    Returns the resolved absolute path. Raises PathOutsideRootError on
    relative paths or paths that fall outside every allowed root.
    """
    roots = [root] if isinstance(root, Path) else list(root)
    user_p = Path(user_path).expanduser()

    # We always require an absolute path so the audit trail is meaningful
    # regardless of the server's cwd.
    if not user_p.is_absolute():
        raise PathOutsideRootError(
            f"path must be absolute: {user_path!r} "
            f"(use a full path like C:\\\\folder or /abs/folder)"
        )

    candidate = user_p.resolve(strict=False)

    # Permissive mode — no allow-list, so any absolute path passes.
    if not roots:
        return candidate

    for r in roots:
        r_resolved = r.resolve()
        try:
            candidate.relative_to(r_resolved)
            return candidate
        except ValueError:
            continue

    allowed = ", ".join(str(r.resolve()) for r in roots) or "<none>"
    raise PathOutsideRootError(
        f"path {candidate} is outside every configured scan root ({allowed})"
    )


def ensure_dir(path: Path) -> Path:
    """Create a directory (and parents) if absent. Return the resolved path."""
    path.mkdir(parents=True, exist_ok=True)
    return path.resolve()
