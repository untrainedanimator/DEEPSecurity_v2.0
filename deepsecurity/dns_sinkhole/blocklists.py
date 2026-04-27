"""Fetch + cache known-bad domain lists.

Source feeds (all free, all maintained):
    - Steven Black /hosts (https://github.com/StevenBlack/hosts) — adblock + malware.
    - URLhaus (abuse.ch) — active malware delivery URLs.
    - Phishing.Database — operator-curated phishing list.

The fetcher writes a single ``data/sinkhole_blocklist.txt`` (one domain
per line) which the server reloads on a configurable interval.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from pathlib import Path

from deepsecurity.logging_config import get_logger

_log = get_logger(__name__)


FEEDS: tuple[tuple[str, str], ...] = (
    (
        "stevenblack",
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    ),
    (
        "urlhaus_hostnames",
        "https://urlhaus.abuse.ch/downloads/hostfile/",
    ),
)


def fetch_all(target: Path, *, timeout_s: int = 30) -> dict:
    """Fetch every feed and write a deduplicated blocklist.

    Returns ``{"sources": {feed_name: count}, "total": N, "path": str}``.
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    seen: set[str] = set()
    counts: dict[str, int] = {}

    for name, url in FEEDS:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "DEEPSecurity"})
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
        except (urllib.error.URLError, TimeoutError) as exc:
            _log.warning("sinkhole.feed_failed", feed=name, error=str(exc))
            counts[name] = 0
            continue

        added = 0
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # /etc/hosts format: "0.0.0.0 example.com" or "127.0.0.1 example.com"
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
                domain = parts[1].lower()
            else:
                domain = parts[0].lower()
            # Skip wildcards or comments masquerading as domains.
            if "." not in domain or domain.startswith("#"):
                continue
            if domain in seen:
                continue
            seen.add(domain)
            added += 1
        counts[name] = added
        _log.info("sinkhole.feed_loaded", feed=name, added=added)

    target.write_text("\n".join(sorted(seen)), encoding="utf-8")
    return {"sources": counts, "total": len(seen), "path": str(target)}


def load(path: Path) -> set[str]:
    if not path.exists():
        return set()
    return {
        ln.strip().lower() for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()
    }
