"""Agent-local config storage.

Lives at ~/.deepsec-agent/config.json (or %USERPROFILE%\\.deepsec-agent\\config.json).
Holds: server URL, agent_id, api_key. Never checked into source control.
"""
from __future__ import annotations

import json
import os
import platform
import stat
from dataclasses import asdict, dataclass
from pathlib import Path


def _default_config_path() -> Path:
    base = Path(os.environ.get("DEEPSEC_AGENT_HOME") or Path.home() / ".deepsec-agent")
    return base / "config.json"


@dataclass
class AgentConfig:
    server_url: str
    agent_id: str = ""
    api_key: str = ""
    hostname: str = ""
    labels: list[str] | None = None

    @property
    def registered(self) -> bool:
        return bool(self.agent_id and self.api_key)


def load(path: Path | None = None) -> AgentConfig | None:
    p = path or _default_config_path()
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return AgentConfig(**data)


def save(cfg: AgentConfig, path: Path | None = None) -> Path:
    p = path or _default_config_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(asdict(cfg), indent=2), encoding="utf-8")
    # Lock down permissions on POSIX — config contains the API key.
    if platform.system() != "Windows":
        try:
            os.chmod(p, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
    return p


def default_path() -> Path:
    return _default_config_path()
