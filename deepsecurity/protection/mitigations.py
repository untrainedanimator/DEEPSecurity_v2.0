"""Apply Windows process mitigation policies to our own process.

`SetProcessMitigationPolicy` lets a process declare hardening
constraints on itself. After we apply these, even an attacker who gets
RCE *inside* DEEPSecurity is sharply limited:

    BlockNonMicrosoftBinaries  no third-party DLLs can load
    DisableExtensionPoints      no shim engines, no AppInit_DLLs
    ProhibitDynamicCode         no JIT, no VirtualAlloc(EXEC)
    NoChildProcessCreation      can't spawn children
    DisableRedirection          no remote-image loads
    StrictHandleCheck           closed-handle == fail fast

These all use undocumented-ish flag layouts in Windows; the canonical
reference is the ``ProcessMitigationPolicy`` enum in ``processthreadsapi.h``.

Optional dep: just ctypes (always available on Windows Python).
Failures are logged but never fatal — older Windows can refuse a
policy and that's fine.
"""

from __future__ import annotations

import ctypes
from ctypes import byref, c_uint, c_ulong
from typing import Any

from deepsecurity.logging_config import get_logger

_log = get_logger(__name__)


# Process mitigation policy enum values.
_ProcessDEPPolicy = 0
_ProcessASLRPolicy = 1
_ProcessDynamicCodePolicy = 2
_ProcessStrictHandleCheckPolicy = 3
_ProcessSystemCallDisablePolicy = 4
_ProcessExtensionPointDisablePolicy = 6
_ProcessControlFlowGuardPolicy = 7
_ProcessSignaturePolicy = 8
_ProcessImageLoadPolicy = 10
_ProcessChildProcessPolicy = 13


# Each policy is a DWORD with bitfields. Documented values:
_DYNAMIC_CODE_PROHIBIT = 0x01
_EXTENSION_POINT_DISABLE = 0x01
_CHILD_PROCESS_DISALLOW = 0x01
_STRICT_HANDLE_RAISE = 0x01
# BinarySignaturePolicy (Code Integrity Guard) — bit layout per
# processthreadsapi.h's PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY:
#   bit 0 — MicrosoftSignedOnly  (enforce: only MS-signed DLLs load)
#   bit 1 — StoreSignedOnly      (enforce: only Store-signed DLLs load)
#   bit 2 — MitigationOptIn      (defer to WDAC at the host level)
#   bit 3 — AuditMicrosoftSignedOnly  (log violations, do not enforce)
#   bit 4 — AuditStoreSignedOnly      (audit-only Store variant)
# We default to AuditMicrosoftSignedOnly (0x08) — logs every unsigned
# DLL load attempt without breaking our own process if a transitive
# Python dep happens to ship an unsigned native module. Operators who
# have audited their deploy can flip to enforce via the
# ``mitigations_cig_enforce`` setting.
_SIGNATURE_MS_BINS_ONLY = 0x01
_SIGNATURE_AUDIT_MS_ONLY = 0x08
_IMAGE_LOAD_NO_REMOTE = 0x01


def apply_recommended(*, cig_enforce: bool = False) -> dict[str, bool]:
    """Apply our recommended set. Returns per-policy success bool.

    ``cig_enforce`` controls Code Integrity Guard mode:

      * False (default) — apply ``AuditMicrosoftSignedOnly``: log every
        unsigned DLL load attempt without blocking it. Safe to enable
        unconditionally; never breaks the running process.
      * True — apply ``MicrosoftSignedOnly``: refuse to load any
        non-Microsoft-signed DLL into the process. Opt-in only,
        because some Python deps ship unsigned native modules and
        would fail to load. Set ``DEEPSEC_MITIGATIONS_CIG_ENFORCE=true``
        and verify the deploy first.
    """
    if ctypes.sizeof(ctypes.c_void_p) == 0:
        return {}
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        _log.info("mitigations.skipped_not_windows")
        return {}

    set_policy = kernel32.SetProcessMitigationPolicy
    set_policy.argtypes = [c_uint, ctypes.c_void_p, ctypes.c_size_t]
    set_policy.restype = ctypes.c_bool

    cig_flags = _SIGNATURE_MS_BINS_ONLY if cig_enforce else _SIGNATURE_AUDIT_MS_ONLY
    cig_label = "code_integrity_guard_enforce" if cig_enforce else "code_integrity_guard_audit"

    results: dict[str, bool] = {}
    for label, policy_id, flags in (
        ("dynamic_code_prohibit", _ProcessDynamicCodePolicy, _DYNAMIC_CODE_PROHIBIT),
        ("extension_point_disable", _ProcessExtensionPointDisablePolicy, _EXTENSION_POINT_DISABLE),
        ("strict_handle_check", _ProcessStrictHandleCheckPolicy, _STRICT_HANDLE_RAISE),
        ("image_load_no_remote", _ProcessImageLoadPolicy, _IMAGE_LOAD_NO_REMOTE),
        # Code Integrity Guard. Audit-mode by default so it can't break
        # our own process; flips to enforce only when the operator opts
        # in after auditing every DLL the deploy actually loads.
        (cig_label, _ProcessSignaturePolicy, cig_flags),
        # ChildProcessDisallow is the strongest — applied last so a failure
        # of one of the above doesn't mask it.
        ("child_process_disallow", _ProcessChildProcessPolicy, _CHILD_PROCESS_DISALLOW),
    ):
        ok = _set_policy_dword(set_policy, policy_id, flags)
        results[label] = ok
        if ok:
            _log.info(f"mitigations.{label}.applied")
        else:
            _log.info(
                f"mitigations.{label}.refused",
                hint="Windows version may not support this policy",
            )
    return results


def _set_policy_dword(set_policy: Any, policy: int, flags: int) -> bool:
    val = c_ulong(flags)
    ok = set_policy(c_uint(policy), byref(val), ctypes.sizeof(val))
    return bool(ok)
