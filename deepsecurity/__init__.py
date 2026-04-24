"""DEEPSecurity — user-space policy, DLP, and compliance overlay for endpoints.

Runs alongside your AV (Windows Defender, SentinelOne, CrowdStrike) — not as
a replacement. Catches what AV punts on: secrets in source code, PII in
shared folders, suspicious parent chains, LOLBins, ransomware write-rate
anomalies. Every detection is MITRE ATT&CK-tagged, every action audit-logged,
every finding stored redacted.

Public surface:

    from deepsecurity.config import settings
    from deepsecurity.scanner import scan_directory, scan_file
    from deepsecurity.api import create_app

Philosophy:
    - Safe by default. Never delete files automatically.
    - Explicit over implicit. No module-level side effects at import.
    - Reproducible. Pinned deps, deterministic configs.
    - Honest about the ceiling. User-space, not kernel. See docs/THREAT_MODEL.md.
"""

__version__ = "2.4.0"
