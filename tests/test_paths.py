"""Path sanitisation — our defence against path traversal."""
from __future__ import annotations

from pathlib import Path

import pytest

from deepsecurity.paths import PathOutsideRootError, resolve_under_root


def test_accepts_path_inside_root(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    inside = root / "file.txt"
    inside.write_text("x")

    resolved = resolve_under_root(str(inside), root)
    assert resolved == inside.resolve()


def test_rejects_parent_escape(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "evil.txt"
    outside.write_text("x")

    with pytest.raises(PathOutsideRootError):
        resolve_under_root(str(outside), root)


def test_rejects_double_dot_traversal(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    traversal = root / ".." / "evil.txt"

    with pytest.raises(PathOutsideRootError):
        resolve_under_root(str(traversal), root)


def test_rejects_symlink_to_outside(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside_target = tmp_path / "outside.txt"
    outside_target.write_text("x")
    link = root / "link.txt"
    try:
        link.symlink_to(outside_target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported on this filesystem")

    with pytest.raises(PathOutsideRootError):
        resolve_under_root(str(link), root)


def test_rejects_junction_to_outside(tmp_path: Path) -> None:
    """Windows-specific parallel to ``test_rejects_symlink_to_outside``.

    Symlinks on Windows require developer-mode or admin to create, so the
    symlink test above skips on most CI runners. **Junctions (directory
    reparse points) do NOT require elevation** — any user can create them
    via ``mklink /J`` — and they're the attack a malicious user is most
    likely to reach for on Windows. Path traversal via junction must
    still be caught by ``resolve_under_root``.
    """
    import os
    import subprocess
    import sys

    if sys.platform != "win32":
        pytest.skip("junction points are a Windows-only concept")

    root = tmp_path / "root"
    root.mkdir()
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    (outside_dir / "secret.txt").write_text("sensitive")

    junction = root / "junction_link"
    # mklink /J <link> <target> — directory junction, no admin needed.
    # Use full path to cmd.exe to avoid the shim's "cannot find" problem
    # under some pytest configurations.
    result = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(outside_dir)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.skip(f"mklink /J failed: {result.stderr.strip() or result.stdout.strip()}")

    # Now a read THROUGH the junction resolves to the outside directory.
    # resolve_under_root should detect the escape and reject.
    with pytest.raises(PathOutsideRootError):
        resolve_under_root(str(junction / "secret.txt"), root)

    # Cleanup: rmdir removes the junction without touching the target.
    try:
        os.rmdir(str(junction))
    except OSError:
        pass
