"""YARA-based memory scanner for fileless malware detection.

v3.1 — closes the gap "fileless malware — moderate, depends on pattern
coverage". The DLP-pattern scanner (``inspector.scan_pid``) already
catches secrets and well-known string patterns; this module adds YARA
rule evaluation against the same memory regions so we can detect
things like Cobalt Strike beacons, Mimikatz signatures, and reflective
DLL loaders by structural pattern, not just substring.

Architecture:

    1. ``compile_rules(rules_dir)`` — loads every ``.yar``/``.yara``
       file under ``rules_dir`` and returns a single compiled
       ``yara.Rules`` object. Cached at module level so we don't
       re-compile on every scan.
    2. ``match_bytes(rules, blob)`` — returns a list of ``YaraMatch``
       for one memory region.
    3. ``scan_pid_yara(pid, ...)`` — full integration: walks the
       target's memory regions and runs the rules against each.

YARA is optional. If ``yara-python`` isn't installed, ``compile_rules``
returns None and ``scan_pid_yara`` becomes a no-op. The base DLP scan
keeps working either way.

Operators add rules by dropping ``.yar`` files into the configured
rules directory (default: ``data/yara_rules/``). A starter rule
``starter.yar`` ships with a handful of well-known signatures; pull
more from the public Yara-Rules / signature-base / Elastic protections
repos as your threat model requires.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from deepsecurity.logging_config import get_logger

_log = get_logger(__name__)

_RULES_CACHE: dict[str, Any] = {"rules": None, "rules_dir_mtime": 0}


@dataclass(frozen=True)
class YaraMatch:
    """One YARA-rule hit inside a memory region."""

    pid: int
    address: int
    region_size: int
    rule_name: str
    namespace: str
    severity: str
    tags: tuple[str, ...]
    matched_strings: tuple[str, ...]


# ---------------------------------------------------------------------------
# Rule loading + caching
# ---------------------------------------------------------------------------


def compile_rules(rules_dir: Path | str) -> Any | None:
    """Load every YARA rule file under ``rules_dir`` into one ``Rules`` obj.

    Returns the compiled object on success, ``None`` if YARA isn't
    installed or if the directory is missing/empty. Cached on the
    directory's mtime so subsequent calls are cheap.
    """
    try:
        import yara  # type: ignore[import-not-found]
    except ImportError:
        _log.info(
            "memory_yara.unavailable",
            hint='pip install "deepsecurity[yara]"',
        )
        return None

    rules_path = Path(rules_dir)
    if not rules_path.exists() or not rules_path.is_dir():
        _log.info("memory_yara.no_rules_dir", path=str(rules_path))
        return None

    # Stat the dir for cache invalidation. We hash the (path, mtime,
    # filenames) tuple so adding/removing a rule file refreshes the
    # cache without an explicit reload call.
    files = sorted(p for p in rules_path.glob("*.yar")) + sorted(
        p for p in rules_path.glob("*.yara")
    )
    if not files:
        _log.info("memory_yara.empty_rules_dir", path=str(rules_path))
        return None

    cache_key = "|".join(f"{p}:{p.stat().st_mtime}" for p in files)
    if _RULES_CACHE.get("key") == cache_key and _RULES_CACHE.get("rules") is not None:
        return _RULES_CACHE["rules"]

    try:
        # ``compile`` accepts a {namespace: filepath} dict; we use the
        # filename as the namespace so a rule's matches show their origin.
        compiled = yara.compile(filepaths={p.stem: str(p) for p in files})
    except Exception as exc:
        _log.warning(
            "memory_yara.compile_failed",
            error=f"{type(exc).__name__}: {exc}",
            files=[str(p) for p in files],
        )
        return None

    _RULES_CACHE["rules"] = compiled
    _RULES_CACHE["key"] = cache_key
    _log.info(
        "memory_yara.compiled",
        rule_files=len(files),
        rules_dir=str(rules_path),
    )
    return compiled


# ---------------------------------------------------------------------------
# Match against bytes
# ---------------------------------------------------------------------------


def match_bytes(
    rules: Any,
    blob: bytes,
    *,
    timeout_s: int = 5,
) -> list[Any]:
    """Run ``rules`` against ``blob``. Returns a list of YARA Match objs.

    Empty list on no match, on timeout, or if ``rules`` is None.
    """
    if rules is None or not blob:
        return []
    try:
        return list(rules.match(data=blob, timeout=timeout_s))
    except Exception as exc:
        _log.debug("memory_yara.match_failed", error=str(exc), size=len(blob))
        return []


# ---------------------------------------------------------------------------
# Per-pid scan integration
# ---------------------------------------------------------------------------


def scan_pid_yara(
    pid: int,
    *,
    rules_dir: Path | str,
    max_bytes: int = 256 * 1024 * 1024,
) -> list[YaraMatch]:
    """Walk the process's memory and report YARA matches.

    Returns an empty list if YARA isn't installed, the rules dir is
    missing, or the process isn't openable. Never raises.
    """
    rules = compile_rules(rules_dir)
    if rules is None:
        return []

    # Local import — keep ctypes/win32 paths lazy.
    from deepsecurity.memory_scan.inspector import _close, _iter_regions, _open

    handle = _open(pid)
    if handle is None:
        return []

    out: list[YaraMatch] = []
    try:
        for base, size, blob in _iter_regions(handle, max_bytes=max_bytes):
            for m in match_bytes(rules, blob):
                # YARA Match.meta is a dict of metadata declared in the
                # rule; we look for ``severity`` and fall back to medium.
                meta = getattr(m, "meta", {}) or {}
                severity = str(meta.get("severity", "medium")).lower()
                # Match.strings is a list of (offset, identifier, data);
                # capture identifiers so the operator sees what fired.
                idents: tuple[str, ...] = ()
                try:
                    idents = tuple({s[1] for s in (m.strings or ())})
                except Exception:  # pragma: no cover  # YARA ABI variation
                    idents = ()
                out.append(
                    YaraMatch(
                        pid=pid,
                        address=base,
                        region_size=size,
                        rule_name=getattr(m, "rule", "unknown"),
                        namespace=getattr(m, "namespace", ""),
                        severity=severity,
                        tags=tuple(getattr(m, "tags", ()) or ()),
                        matched_strings=idents,
                    )
                )
    finally:
        _close(handle)

    if out:
        _log.info(
            "memory_yara.matches",
            pid=pid,
            count=len(out),
            rules=sorted({m.rule_name for m in out}),
        )
    else:
        _log.debug("memory_yara.no_matches", pid=pid)
    return out
