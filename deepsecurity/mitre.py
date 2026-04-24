"""MITRE ATT&CK mapping for every detection source DEEPSecurity emits.

Every detection rule gets one or more technique IDs. This is what a SOC
queries against — "show me all T1496 (resource hijacking) events in the
last 24 h" is a realistic ask, and without ATT&CK tags the answer is
"parse free-text reasons, good luck".

Tags are attached in `scanner.classify()`, `dlp.scan_text()`, and
`processes.classify_process()`. The ORM stores the free-text reasons
unchanged; tags are re-derived at API read time via `tags_for_reason()`
so no DB migration is required.

Reference: https://attack.mitre.org/  (v14, April 2024+)
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class MitreTag:
    technique_id: str       # e.g. "T1496"
    name: str               # e.g. "Resource Hijacking"
    tactic: str             # e.g. "Impact"
    reference: str          # e.g. "https://attack.mitre.org/techniques/T1496/"


# ---------------------------------------------------------------------------
# The canonical tag catalog.
# ---------------------------------------------------------------------------

_CATALOG: dict[str, MitreTag] = {
    t.technique_id: t
    for t in (
        MitreTag(
            "T1027",
            "Obfuscated Files or Information",
            "Defense Evasion",
            "https://attack.mitre.org/techniques/T1027/",
        ),
        MitreTag(
            "T1055",
            "Process Injection",
            "Defense Evasion, Privilege Escalation",
            "https://attack.mitre.org/techniques/T1055/",
        ),
        MitreTag(
            "T1218",
            "System Binary Proxy Execution",
            "Defense Evasion",
            "https://attack.mitre.org/techniques/T1218/",
        ),
        MitreTag(
            "T1486",
            "Data Encrypted for Impact",
            "Impact",
            "https://attack.mitre.org/techniques/T1486/",
        ),
        MitreTag(
            "T1496",
            "Resource Hijacking",
            "Impact",
            "https://attack.mitre.org/techniques/T1496/",
        ),
        MitreTag(
            "T1552",
            "Unsecured Credentials",
            "Credential Access",
            "https://attack.mitre.org/techniques/T1552/",
        ),
        MitreTag(
            "T1552.001",
            "Unsecured Credentials: Credentials In Files",
            "Credential Access",
            "https://attack.mitre.org/techniques/T1552/001/",
        ),
        MitreTag(
            "T1552.004",
            "Unsecured Credentials: Private Keys",
            "Credential Access",
            "https://attack.mitre.org/techniques/T1552/004/",
        ),
        MitreTag(
            "T1528",
            "Steal Application Access Token",
            "Credential Access",
            "https://attack.mitre.org/techniques/T1528/",
        ),
        MitreTag(
            "T1059",
            "Command and Scripting Interpreter",
            "Execution",
            "https://attack.mitre.org/techniques/T1059/",
        ),
        MitreTag(
            "T1566",
            "Phishing",
            "Initial Access",
            "https://attack.mitre.org/techniques/T1566/",
        ),
        MitreTag(
            "T1588.001",
            "Obtain Capabilities: Malware",
            "Resource Development",
            "https://attack.mitre.org/techniques/T1588/001/",
        ),
        MitreTag(
            "T1005",
            "Data from Local System",
            "Collection",
            "https://attack.mitre.org/techniques/T1005/",
        ),
        MitreTag(
            "T1090",
            "Proxy",
            "Command and Control",
            "https://attack.mitre.org/techniques/T1090/",
        ),
    )
}


def lookup(technique_id: str) -> MitreTag | None:
    return _CATALOG.get(technique_id)


def details(tags: list[str] | tuple[str, ...]) -> list[dict[str, str]]:
    """Expand a list of technique IDs to their full catalog entries.
    Unknown IDs are returned with minimal fields so the UI always renders."""
    out: list[dict[str, str]] = []
    for t in tags:
        tag = _CATALOG.get(t)
        if tag is None:
            out.append({"technique_id": t, "name": "Unknown", "tactic": "", "reference": ""})
        else:
            out.append(
                {
                    "technique_id": tag.technique_id,
                    "name": tag.name,
                    "tactic": tag.tactic,
                    "reference": tag.reference,
                }
            )
    return out


# ---------------------------------------------------------------------------
# Per-source tag assignments.
# ---------------------------------------------------------------------------


# DLP patterns → technique IDs.
DLP_PATTERN_TAGS: dict[str, tuple[str, ...]] = {
    "aws_access_key_id": ("T1552.001",),
    "aws_secret_access_key": ("T1552.001",),
    "gcp_service_account": ("T1552.001",),
    "private_key_pem": ("T1552.004",),
    "slack_token": ("T1528", "T1552.001"),
    "github_pat": ("T1528", "T1552.001"),
    "huggingface_token": ("T1528", "T1552.001"),
    "stripe_secret_key": ("T1552.001",),
    "jwt_token": ("T1528", "T1552.001"),
    "generic_api_key": ("T1552.001",),
    "us_ssn": ("T1005",),
    "credit_card_number": ("T1005",),
    "email_address": ("T1005",),
}


# Process classifier reasons → tags.
PROCESS_REASON_TAGS: dict[str, tuple[str, ...]] = {
    "known_miner": ("T1496",),
    "lolbin": ("T1218", "T1059"),
    "high_cpu": ("T1496",),
    "signature_match": ("T1588.001",),
    "suspicious_parent": ("T1059",),
}


# Scanner (file) classify() reasons → tags.
SCANNER_REASON_TAGS: dict[str, tuple[str, ...]] = {
    "signature_match": ("T1588.001",),
    "entropy_spike": ("T1027",),
    "yara": ("T1027",),
    "ml_high_confidence": ("T1588.001",),
    "ransomware_rate": ("T1486",),
}


def tags_for_reason(reason: str) -> tuple[str, ...]:
    """Given a single reason string (as emitted by classify() / dlp / processes),
    return the technique IDs it maps to.

    Reason strings may be prefixed/suffixed: 'yara:Some_Rule', 'known_miner:xmrig',
    'entropy_spike(2.7)', 'ml_high_confidence(0.92)', 'signature_match'. We match
    on the prefix.
    """
    head = reason.split(":", 1)[0].split("(", 1)[0].strip()
    for table in (SCANNER_REASON_TAGS, PROCESS_REASON_TAGS):
        if head in table:
            return table[head]
    return ()


def tags_for_reasons(reasons: list[str] | tuple[str, ...]) -> list[str]:
    """Deduplicated list of technique IDs for a sequence of reasons."""
    out: list[str] = []
    seen: set[str] = set()
    for r in reasons:
        for t in tags_for_reason(r):
            if t not in seen:
                seen.add(t)
                out.append(t)
    return out


def tags_for_dlp_pattern(pattern_name: str) -> list[str]:
    return list(DLP_PATTERN_TAGS.get(pattern_name, ()))
