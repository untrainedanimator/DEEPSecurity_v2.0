"""YARA rule engine — optional.

If `yara-python` is not installed, `YaraEngine.enabled` is False and
`match()` returns an empty list. The scanner calls through this shim so
the rest of the code doesn't care whether YARA is present.

Rules directory is configured via DEEPSEC_YARA_RULES_DIR. Every `.yar`
file in that directory is compiled on startup and cached. Recompile by
restarting the process (or via `POST /api/yara/reload` — admin only).
"""
from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from deepsecurity.logging_config import get_logger

_log = get_logger(__name__)

try:  # pragma: no cover — optional dep
    import yara  # type: ignore[import-not-found]

    _YARA_AVAILABLE = True
except ImportError:  # pragma: no cover
    yara = None
    _YARA_AVAILABLE = False


# Wall-clock budget for the one-time rule compile. Legit rule packs
# compile in well under a second; a pathological rule with runaway
# backtracking can in theory take forever. We cap at 10 seconds and
# fail-safe-disabled — better to run without YARA than to block startup.
YARA_COMPILE_TIMEOUT_S = 10.0


def _compile_with_timeout(
    filepaths: dict[str, str], timeout_s: float
) -> tuple[Any | None, str | None]:
    """Compile in a daemon thread; return (rules, None) or (None, reason).

    reason is one of: ``"timeout"``, the str(Exception) on compile error.
    The thread is daemon so it won't block process exit if compile is
    still running when we give up.
    """
    result: list[Any] = []
    crash: list[BaseException] = []
    done = threading.Event()

    def _worker() -> None:
        try:
            compiled = yara.compile(filepaths=filepaths)  # type: ignore[attr-defined]
            result.append(compiled)
        except BaseException as e:  # noqa: BLE001
            crash.append(e)
        finally:
            done.set()

    t = threading.Thread(target=_worker, daemon=True, name="yara-compile")
    t.start()
    if not done.wait(timeout_s):
        return None, "timeout"
    if crash:
        return None, str(crash[0])
    return result[0], None


@dataclass(frozen=True)
class YaraMatch:
    rule: str
    namespace: str
    tags: tuple[str, ...]
    meta: dict[str, str]


class YaraEngine:
    """Thin wrapper around yara-python. Stateless-ish: rules compiled once."""

    def __init__(self, rules_dir: Path | None) -> None:
        self._rules_dir = rules_dir
        self._compiled: "yara.Rules | None" = None  # type: ignore[name-defined]
        self._load()

    @property
    def enabled(self) -> bool:
        return _YARA_AVAILABLE and self._compiled is not None

    def _load(self) -> None:
        if not _YARA_AVAILABLE:
            _log.info("yara.disabled", reason="yara-python not installed")
            return
        if self._rules_dir is None or not self._rules_dir.exists():
            _log.info("yara.disabled", reason="rules dir missing", dir=str(self._rules_dir))
            return
        paths = {p.stem: str(p) for p in self._rules_dir.glob("*.yar")}
        paths.update({p.stem: str(p) for p in self._rules_dir.glob("*.yara")})
        if not paths:
            _log.info("yara.disabled", reason="no .yar files", dir=str(self._rules_dir))
            return
        # Bounded compile. A pathological rule must not hang app startup
        # forever; we give it ``YARA_COMPILE_TIMEOUT_S`` and then fall
        # through to the disabled-engine state so the Flask app still boots.
        compiled, reason = _compile_with_timeout(paths, YARA_COMPILE_TIMEOUT_S)
        if compiled is None:
            if reason == "timeout":
                _log.warning(
                    "yara.compile_timeout",
                    rule_files=len(paths),
                    timeout_s=YARA_COMPILE_TIMEOUT_S,
                )
            else:
                _log.error("yara.compile_failed", reason=reason)
            self._compiled = None
            return
        self._compiled = compiled
        _log.info("yara.loaded", rule_files=len(paths))

    def match(self, path: Path) -> list[YaraMatch]:
        if not self.enabled:
            return []
        try:
            matches = self._compiled.match(str(path))  # type: ignore[union-attr]
        except Exception:
            _log.exception("yara.match_failed", path=str(path))
            return []
        return [
            YaraMatch(
                rule=m.rule,
                namespace=m.namespace,
                tags=tuple(m.tags or ()),
                meta={str(k): str(v) for k, v in (m.meta or {}).items()},
            )
            for m in matches
        ]
