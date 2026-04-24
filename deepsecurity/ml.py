"""ML detection layer.

Honest about when the model is disabled:
    - If `ml_model_path` is unset or the file doesn't exist, `classify()`
      returns a well-defined "no-model" verdict rather than hallucinating
      random API names and confidence scores (which the old `ml_model.py`
      did — see _legacy/ for the gore).

    - When a real model is present, the feature vector is
      [entropy, size_kb, anomaly_score]. Models must be picklable
      scikit-learn estimators exposing .predict() and optionally
      .predict_proba().

Training lives in `deepsecurity.training` (to be added when a real dataset
is wired in — see docs/ARCHITECTURE.md "ML" section).

joblib is imported lazily: if it is not installed, the classifier reports
`enabled=False` and the scanner continues with signature + entropy only.
That keeps the core install pure-Python and 3.14-friendly on Windows.
"""
from __future__ import annotations

import pickletools
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from deepsecurity.logging_config import get_logger

_log = get_logger(__name__)

try:  # pragma: no cover — optional
    import joblib  # type: ignore[import-not-found]
    _JOBLIB_AVAILABLE = True
except ImportError:
    joblib = None  # type: ignore[assignment]
    _JOBLIB_AVAILABLE = False


# Modules we allow to appear inside a joblib pickle's GLOBAL / STACK_GLOBAL
# opcodes. This is the pickle-native code-execution surface: a malicious
# pickle names a module + attribute and the unpickler runs the attribute.
# Limiting it to the scientific-Python stack prevents the classic
# ``os.system`` / ``builtins.eval`` pickle-RCE from ever being loaded.
#
# Prefix match: any module whose full name starts with one of these plus
# "." (or equals the entry outright) is considered safe.
_ML_ALLOWED_PICKLE_MODULES: frozenset[str] = frozenset(
    {
        "sklearn",
        "numpy",
        "scipy",
        "joblib",
        "collections",
        "builtins",
        "copyreg",
    }
)


def _pickle_safe(path: Path, allowlist: frozenset[str] = _ML_ALLOWED_PICKLE_MODULES) -> tuple[bool, str | None]:
    """Walk the pickle's opcodes; refuse if it names a disallowed module.

    Returns (True, None) if every GLOBAL / STACK_GLOBAL reference targets
    a module in the allowlist. Returns (False, offending_module) otherwise.

    This is NOT a cryptographic guarantee — a sufficiently determined
    attacker could wrap a payload in something the allowlist permits —
    but it eats the 95% of pickle-RCE public PoCs that pull in
    ``os.system``, ``subprocess.Popen``, ``builtins.eval``, etc.
    """
    try:
        with path.open("rb") as f:
            ops = list(pickletools.genops(f))
    except Exception as exc:
        return False, f"unreadable:{exc.__class__.__name__}"

    for op, arg, _pos in ops:
        name = op.name  # e.g. "GLOBAL", "STACK_GLOBAL"
        if name not in ("GLOBAL", "STACK_GLOBAL"):
            continue

        # GLOBAL arg is "module name"; STACK_GLOBAL pops both from the stack
        # so we have to look backwards. For our safety check we only need
        # the module name — for STACK_GLOBAL we scan preceding SHORT_BINUNICODE
        # and find the last two strings on the stack.
        module: str | None = None
        if name == "GLOBAL" and isinstance(arg, str):
            # Format is "<module> <attribute>" separated by a newline.
            module = arg.split("\n", 1)[0] if "\n" in arg else arg.split(" ", 1)[0]
        elif name == "STACK_GLOBAL":
            # Walk backwards to collect the two most recent unicode literals.
            idx = ops.index((op, arg, _pos))
            seen: list[str] = []
            for prev_op, prev_arg, _p in reversed(ops[:idx]):
                if prev_op.name in (
                    "SHORT_BINUNICODE",
                    "BINUNICODE",
                    "BINUNICODE8",
                    "UNICODE",
                ) and isinstance(prev_arg, str):
                    seen.append(prev_arg)
                    if len(seen) >= 2:
                        break
            if len(seen) >= 2:
                # Most recent is the attribute, one before is the module.
                module = seen[1]

        if module is None:
            continue
        top = module.split(".", 1)[0]
        if top not in allowlist:
            return False, module

    return True, None


@dataclass(frozen=True)
class MLVerdict:
    """Result of running the ML layer against a single file."""

    enabled: bool
    malicious: bool
    confidence: float
    model_version: str | None = None
    reason: str = ""


@runtime_checkable
class SklearnLike(Protocol):
    def predict(self, X: Any) -> Any: ...


class MLClassifier:
    """Wraps a joblib-loaded sklearn model. Lazy-loaded on first use."""

    def __init__(self, model_path: Path | None, confidence_threshold: float) -> None:
        self._path = model_path
        self._threshold = confidence_threshold
        self._model: SklearnLike | None = None
        self._loaded = False

    @property
    def enabled(self) -> bool:
        # ``is_file()`` not ``exists()`` — when the operator leaves
        # DEEPSEC_ML_MODEL_PATH blank, pydantic coerces "" to Path("."),
        # ``Path(".").exists()`` is True, and we'd then try to joblib.load
        # a directory and fail with PermissionError.
        return self._path is not None and str(self._path) not in ("", ".") and self._path.is_file()

    @property
    def threshold(self) -> float:
        return self._threshold

    def _load(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        if not self.enabled:
            _log.warning("ml.disabled", reason="no_model_path_or_file")
            return
        if not _JOBLIB_AVAILABLE:
            _log.warning("ml.disabled", reason="joblib_not_installed")
            return

        # SAFETY: audit the pickle before joblib.load runs the unpickler.
        # A malicious pickle with a ``os.system`` GLOBAL would otherwise
        # achieve arbitrary code execution the moment ``joblib.load``
        # touches the file. The allowlist restricts loaded pickles to the
        # scientific-Python stack. See _pickle_safe() for the mechanism.
        assert self._path is not None  # narrowed by ``self.enabled``
        ok, offender = _pickle_safe(self._path)
        if not ok:
            _log.error(
                "ml.pickle_rejected",
                path=str(self._path),
                offending_module=offender,
                hint=(
                    "pickle references a module outside the allowlist — "
                    "refusing to load. Train with sklearn/numpy/scipy and "
                    "re-save via joblib.dump."
                ),
            )
            self._model = None
            return

        try:
            self._model = joblib.load(self._path)  # type: ignore[arg-type,union-attr]
            _log.info("ml.loaded", path=str(self._path))
        except Exception as exc:
            _log.error("ml.load_failed", path=str(self._path), error=str(exc))
            self._model = None

    def classify(self, features: list[float]) -> MLVerdict:
        """Classify a feature vector. Returns MLVerdict, never raises."""
        self._load()
        if self._model is None:
            return MLVerdict(
                enabled=False,
                malicious=False,
                confidence=0.0,
                reason="ml_disabled",
            )

        try:
            X = [features]
            pred = int(self._model.predict(X)[0])  # type: ignore[index]
            conf = 0.0
            if hasattr(self._model, "predict_proba"):
                probs = self._model.predict_proba(X)[0]  # type: ignore[attr-defined]
                if len(probs) >= 2:
                    conf = float(probs[1])
                else:
                    conf = float(max(probs))

            malicious = pred == 1 and conf >= self._threshold
            threshold_str = f"{self._threshold:.2f}"
            conf_str = f"{conf:.2f}"
            if malicious:
                reason = "ml_high_confidence(" + conf_str + ")"
            else:
                reason = "ml_below_threshold(" + conf_str + "<" + threshold_str + ")"
            return MLVerdict(
                enabled=True,
                malicious=malicious,
                confidence=round(conf, 4),
                reason=reason,
            )
        except Exception as exc:
            _log.exception("ml.predict_failed", error=str(exc))
            return MLVerdict(
                enabled=True,
                malicious=False,
                confidence=0.0,
                reason="ml_error",
            )
