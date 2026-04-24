"""Data Loss Prevention — secret / PII detection by pattern.

Scans text-bearing files for high-value strings that shouldn't be there:
private keys, cloud credentials, credit-card numbers, emails, SSNs.

Design:
    - Runs ONLY on files below a configurable byte cap (default 2 MiB) to
      avoid reading huge binaries that won't match anyway.
    - Runs ONLY on files whose MIME looks textual or is `application/octet-
      stream` with a small size — explicitly skips media/archive types.
    - Every finding is redacted: we store a preview with the matched value
      replaced by `****`. The raw secret never touches the database.
    - High-severity findings (private keys, cloud creds) fire an alert via
      the alerts bus. Low-severity (emails, single credit-card matches)
      are logged but not alerted by default.
"""
from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from deepsecurity.logging_config import get_logger

_log = get_logger(__name__)

Severity = Literal["observe", "low", "medium", "high", "critical"]
# ``observe`` — shipped as part of the DLP v2 library. Records a finding
# in the DB and exposes it through /api/dlp/findings, but never triggers
# an alert, never quarantines, never appears as an audit "critical" event.
# Use it to trial new patterns in shadow mode for N days before promoting
# them to medium/high/critical.


# Per-pattern wall-clock budget. A catastrophically-backtracking regex
# against a large input would otherwise pin a worker thread forever; we
# cap each pattern at 2 seconds. This is a LOT of headroom for every
# legit regex in PATTERNS — the ones that matter finish in microseconds.
DLP_REGEX_TIMEOUT_S = 2.0


def _finditer_with_timeout(
    pattern: re.Pattern[str], text: str, timeout_s: float
) -> list[re.Match[str]] | None:
    """Return all matches or ``None`` if we hit ``timeout_s`` first.

    Python's ``re`` module has no native timeout, and there's no safe
    way to kill a CPython thread. We run the match in a daemon thread
    and ``Event.wait(timeout_s)`` in the caller; if the match hasn't
    completed by then, we abandon the thread (it'll finish or bleed
    into process exit — either way the main scan continues).

    Returns:
        list of Match objects on success, [] if the match produced
        nothing, or None if the pattern exceeded the budget.
    """
    result: list[re.Match[str]] = []
    done = threading.Event()
    crash: list[BaseException] = []

    def _worker() -> None:
        try:
            for m in pattern.finditer(text):
                result.append(m)
        except BaseException as e:  # noqa: BLE001 — bubble via crash[]
            crash.append(e)
        finally:
            done.set()

    t = threading.Thread(target=_worker, daemon=True, name="dlp-regex")
    t.start()
    if not done.wait(timeout_s):
        # Timed out. Thread keeps running until the regex returns; we
        # just stop waiting.
        return None
    if crash:
        # Re-raise so the caller can log with pattern context.
        raise crash[0]
    return result


@dataclass(frozen=True)
class DLPPattern:
    name: str
    regex: re.Pattern[str]
    severity: Severity
    # How many bytes of context to keep around the match for the preview.
    context: int = 20


def _c(p: str, flags: int = re.MULTILINE) -> re.Pattern[str]:
    return re.compile(p, flags)


# Maintained as data, not code, so operators can diff it and add rules.
PATTERNS: tuple[DLPPattern, ...] = (
    # --- Critical: cloud credentials + private keys --------------------
    DLPPattern(
        "aws_access_key_id",
        _c(r"\bAKIA[0-9A-Z]{16}\b"),
        "critical",
    ),
    DLPPattern(
        "aws_secret_access_key",
        _c(r"\b(?i:aws_secret_access_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
        "critical",
    ),
    DLPPattern(
        "gcp_service_account",
        _c(r'"type"\s*:\s*"service_account"'),
        "critical",
    ),
    DLPPattern(
        "private_key_pem",
        _c(r"-----BEGIN (RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----"),
        "critical",
    ),
    DLPPattern(
        "slack_token",
        _c(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        "critical",
    ),
    DLPPattern(
        "github_pat",
        _c(r"\bghp_[A-Za-z0-9]{36}\b"),
        "critical",
    ),
    DLPPattern(
        "huggingface_token",
        _c(r"\bhf_[A-Za-z0-9]{34,}\b"),
        "critical",
    ),
    DLPPattern(
        "stripe_secret_key",
        _c(r"\bsk_(?:live|test)_[A-Za-z0-9]{24,}\b"),
        "critical",
    ),
    # --- High: generic bearer tokens ----------------------------------
    DLPPattern(
        "jwt_token",
        _c(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"),
        "high",
    ),
    DLPPattern(
        "generic_api_key",
        _c(
            r"(?i)\b(api[_-]?key|apikey|access[_-]?token|auth[_-]?token)\b"
            r"\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{24,})['\"]?"
        ),
        "high",
    ),
    # --- Medium: PII -------------------------------------------------
    DLPPattern(
        "us_ssn",
        _c(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
        "medium",
    ),
    DLPPattern(
        "credit_card_number",
        # Visa/MC/Amex/Discover prefixes, Luhn-unchecked for speed.
        _c(r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011)[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"),
        "medium",
    ),
    # --- Low: emails (PII, often legitimate) -------------------------
    DLPPattern(
        "email_address",
        _c(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
        "low",
    ),
    # --- DLP v2 (v2.4.0) — API keys for LLM / SaaS services ----------
    # OpenAI: sk-<20+ chars of base64url>. Project/org keys use
    # ``sk-proj-`` and ``sk-org-`` prefixes with varying lengths.
    DLPPattern(
        "openai_key",
        _c(r"\bsk-(?:proj-|org-)?[A-Za-z0-9_\-]{20,}\b"),
        "critical",
    ),
    # Anthropic API keys — sk-ant-... with variable suffix length.
    DLPPattern(
        "anthropic_key",
        _c(r"\bsk-ant-(?:api|admin)[0-9]{2}-[A-Za-z0-9_\-]{20,}\b"),
        "critical",
    ),
    # Stripe webhook signing secret — whsec_...
    DLPPattern(
        "stripe_webhook_secret",
        _c(r"\bwhsec_[A-Za-z0-9]{20,}\b"),
        "critical",
    ),
    # Twilio account SID — 34-char identifier starting with ``AC``.
    DLPPattern(
        "twilio_account_sid",
        _c(r"\bAC[a-fA-F0-9]{32}\b"),
        "critical",
    ),
    # Azure storage / service-bus connection string. The canonical shape
    # is ``DefaultEndpointsProtocol=...;AccountName=...;AccountKey=<b64>``.
    # We specifically look for ``AccountKey=`` followed by ≥20 base64
    # characters — that's the actual credential and is the anchor we
    # want the pattern tied to.
    DLPPattern(
        "azure_connection_string",
        _c(
            r"(?i)(?:DefaultEndpointsProtocol=[^;]+;)?"
            r"(?:AccountName|SharedAccessKeyName)=[^;]+;"
            r"(?:AccountKey|SharedAccessKey)=[A-Za-z0-9+/=]{20,}"
        ),
        "critical",
    ),
    # Slack incoming-webhook full URL (as opposed to a bare xox* token).
    DLPPattern(
        "slack_webhook_full_url",
        _c(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,}"),
        "high",
    ),
    # Discord bot token — three-part dot-separated base64-ish.
    DLPPattern(
        "discord_bot_token",
        _c(r"\b[MN][A-Za-z0-9]{23}\.[\w\-]{6}\.[\w\-]{27,}\b"),
        "high",
    ),
    # Bearer tokens in Authorization headers — distinct from the bare
    # JWT pattern above because the "Bearer " prefix is a strong signal
    # that the following string IS the credential, not a coincidence.
    DLPPattern(
        "jwt_bearer_header",
        _c(r"(?i)Authorization:\s*Bearer\s+eyJ[A-Za-z0-9_-]{5,}\."),
        "high",
    ),
    # --- DLP v2 — regional PII identifiers ---------------------------
    # UK National Insurance Number. Two letters, six digits, one of
    # {A,B,C,D} as the suffix. Excludes invalid prefixes.
    DLPPattern(
        "uk_nino",
        _c(
            r"\b(?!BG|GB|NK|KN|TN|NT|ZZ)[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]"
            r"\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]?\b"
        ),
        "medium",
    ),
    # India Aadhaar — 12 digits, spaces or hyphens optional.
    # Excludes sequences starting with 0 or 1 (not valid Aadhaar prefixes).
    DLPPattern(
        "india_aadhaar",
        _c(r"\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b"),
        "medium",
    ),
    # EU VAT number — country code + numeric block. We match a handful
    # of the most-common member state formats.
    DLPPattern(
        "eu_vat",
        _c(
            r"\b(?:AT|BE|BG|CY|CZ|DE|DK|EE|EL|ES|FI|FR|GB|HR|HU|IE|IT|"
            r"LT|LU|LV|MT|NL|PL|PT|RO|SE|SI|SK)\s?[0-9A-Z]{8,12}\b"
        ),
        "medium",
    ),
    # Canadian SIN — 9 digits grouped 3-3-3. Luhn-unchecked for speed.
    DLPPattern(
        "canada_sin",
        _c(r"\b\d{3}[\s-]\d{3}[\s-]\d{3}\b"),
        "medium",
    ),
    # --- DLP v2 — observe tier (shadow-mode rules) -------------------
    # ICD-10 diagnosis code in a context that looks like a medical record.
    # Observe-only for now: false-positive rate too high to alert on.
    DLPPattern(
        "icd10_code",
        _c(
            r"(?i)\b(?:diagnosis|icd[-\s]?10|condition)\b[^\n]{0,40}?"
            r"\b[A-TV-Z][0-9][0-9A-Z](?:\.[0-9A-Z]{1,4})?\b"
        ),
        "observe",
    ),
    # Source-code comment that self-announces a secret. High-value
    # signal but the regex is noisy enough to start in observe mode.
    # We match any comment-leader (``#``, ``//``, ``/*``) followed by
    # non-newline content that contains one of the secret keywords,
    # bounded to the same line. This catches realistic phrasing like
    # ``# TODO: rotate this secret before we ship`` where a colon /
    # other punctuation sits between the comment and the keyword.
    DLPPattern(
        "source_code_secret_comment",
        _c(
            r"(?:#|//|/\*)[^\n]{0,80}"
            r"\b(?:secret|password|passwd|token|apikey|api[\s_-]key|credential)s?\b"
        ),
        "observe",
    ),
    # SSH public keys — not secret, but often co-located with private
    # keys, so useful as a forensic signal. Observe-only.
    DLPPattern(
        "ssh_public_key",
        _c(r"\bssh-(?:rsa|ed25519|ecdsa-sha2-[a-z0-9\-]+)\s+AAAA[A-Za-z0-9+/]{32,}"),
        "observe",
    ),
)


@dataclass(frozen=True)
class DLPFinding:
    file_path: str
    pattern_name: str
    severity: Severity
    redacted_preview: str
    line_number: int


# MIME prefixes / exact types we consider worth scanning for secrets.
# Everything else is skipped.
_TEXT_MIMES = (
    "text/",
    "application/json",
    "application/xml",
    "application/yaml",
    "application/x-yaml",
    "application/x-sh",
    "application/javascript",
    "application/x-httpd-php",
    "application/x-python",
)


def _is_text_candidate(mime: str, size: int, max_bytes: int) -> bool:
    if size > max_bytes:
        return False
    if mime == "application/octet-stream" and size < 64 * 1024:
        # Small unknowns — scripts sometimes have no extension. Give them a look.
        return True
    return any(mime.startswith(prefix) for prefix in _TEXT_MIMES)


def _redact(raw: str, start: int, end: int) -> str:
    """Replace the matched substring with ****, keep surrounding context."""
    return raw[:start] + "****" + raw[end:]


def scan_text(content: str, file_path: str) -> list[DLPFinding]:
    """Apply every pattern to the given string. Returns findings (possibly empty)."""
    findings: list[DLPFinding] = []
    lines = content.split("\n")
    # Build an index: byte offset -> line number, via cumulative length.
    offsets: list[int] = []
    acc = 0
    for ln in lines:
        offsets.append(acc)
        acc += len(ln) + 1

    for pat in PATTERNS:
        # Per-pattern timeout: a catastrophically-backtracking regex on
        # a pathological input would otherwise hang the scan worker. We
        # abandon the pattern after DLP_REGEX_TIMEOUT_S, log it once,
        # and continue with the next pattern — loss of one signal is
        # strictly better than a wedged scanner.
        try:
            matches = _finditer_with_timeout(pat.regex, content, DLP_REGEX_TIMEOUT_S)
        except Exception:
            _log.exception(
                "dlp.regex_error", pattern=pat.name, file_path=file_path
            )
            continue
        if matches is None:
            _log.warning(
                "dlp.regex_timeout",
                pattern=pat.name,
                file_path=file_path,
                timeout_s=DLP_REGEX_TIMEOUT_S,
            )
            continue

        for m in matches:
            # Find the line number this match starts on.
            pos = m.start()
            line_no = 1
            for i, off in enumerate(offsets):
                if off > pos:
                    line_no = i
                    break
                line_no = i + 1

            # Extract a short context window and redact the secret.
            window_start = max(0, pos - pat.context)
            window_end = min(len(content), m.end() + pat.context)
            window = content[window_start:window_end]
            rel_start = pos - window_start
            rel_end = m.end() - window_start
            preview = _redact(window, rel_start, rel_end).replace("\n", " ⏎ ")

            findings.append(
                DLPFinding(
                    file_path=file_path,
                    pattern_name=pat.name,
                    severity=pat.severity,
                    redacted_preview=preview[:200],
                    line_number=line_no,
                )
            )
    return findings


def scan_file_for_secrets(
    path: Path, mime: str, *, max_bytes: int = 2 * 1024 * 1024
) -> list[DLPFinding]:
    """Scan a single file on disk. Returns findings; empty for binaries, missing
    files, permission errors, and files above `max_bytes`."""
    try:
        size = path.stat().st_size
    except OSError:
        return []
    if not _is_text_candidate(mime, size, max_bytes):
        return []
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        _log.warning("dlp.read_failed", path=str(path))
        return []
    return scan_text(content, str(path))
