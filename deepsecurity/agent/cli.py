"""Command-line entry point for the endpoint agent.

    deepsec-agent register --server https://deepsec.example --token <token>
    deepsec-agent run
    deepsec-agent status
    deepsec-agent show-config
"""
from __future__ import annotations

import json
import platform
import sys

import click

from deepsecurity.agent import __version__
from deepsecurity.agent.config import AgentConfig, default_path, load, save
from deepsecurity.agent.transport import AgentTransport, TransportError
from deepsecurity.agent.worker import run as run_agent
from deepsecurity.logging_config import configure_logging


@click.group()
@click.version_option(__version__, prog_name="deepsec-agent")
def main() -> None:
    """DEEPSecurity endpoint agent."""
    try:
        configure_logging()
    except Exception:
        pass


@main.command("register")
@click.option("--server", required=True, help="https://your-deepsec-server")
@click.option("--token", required=True, help="enrolment token from the operator")
@click.option("--label", multiple=True, help="free-form label (repeatable)")
def register_cmd(server: str, token: str, label: tuple[str, ...]) -> None:
    """Register this host with the control plane. One-time."""
    t = AgentTransport(server_url=server)
    try:
        resp = t.register(
            enrolment_token=token,
            hostname=platform.node(),
            os_name=platform.system(),
            os_version=platform.version(),
            agent_version=__version__,
            labels=list(label),
        )
    except TransportError as exc:
        click.echo(f"registration failed: {exc}", err=True)
        sys.exit(2)

    cfg = AgentConfig(
        server_url=server,
        agent_id=resp["agent_id"],
        api_key=resp["api_key"],
        hostname=platform.node(),
        labels=list(label),
    )
    path = save(cfg)
    click.echo(f"registered. agent_id={cfg.agent_id}")
    click.echo(f"config written: {path}")


@main.command("run")
@click.option("--interval", type=float, default=30.0, show_default=True)
def run_cmd(interval: float) -> None:
    """Run the main loop (heartbeat / poll / execute / report). Blocking."""
    cfg = load()
    if cfg is None or not cfg.registered:
        click.echo(
            "no agent config found. run `deepsec-agent register` first.",
            err=True,
        )
        sys.exit(2)
    try:
        run_agent(cfg, interval_seconds=interval)
    except KeyboardInterrupt:
        click.echo("stopped")


@main.command("status")
def status_cmd() -> None:
    """Print registration + test connectivity."""
    cfg = load()
    if cfg is None:
        click.echo("not configured")
        sys.exit(1)
    click.echo(f"server: {cfg.server_url}")
    click.echo(f"agent_id: {cfg.agent_id or '— not registered —'}")
    click.echo(f"hostname: {cfg.hostname}")

    if cfg.registered:
        t = AgentTransport(
            server_url=cfg.server_url,
            agent_id=cfg.agent_id,
            api_key=cfg.api_key,
        )
        try:
            t.heartbeat(
                {
                    "hostname": platform.node(),
                    "os": platform.system(),
                    "agent_version": __version__,
                    "status_probe": True,
                }
            )
            click.echo("heartbeat: ok")
        except TransportError as exc:
            click.echo(f"heartbeat: FAILED — {exc}")
            sys.exit(1)


@main.command("show-config")
def show_config_cmd() -> None:
    """Dump the current config (redacts the API key)."""
    cfg = load()
    if cfg is None:
        click.echo(f"no config at {default_path()}")
        sys.exit(1)
    data = {
        "server_url": cfg.server_url,
        "agent_id": cfg.agent_id,
        "api_key": ("****" + cfg.api_key[-6:]) if cfg.api_key else "",
        "hostname": cfg.hostname,
        "labels": cfg.labels or [],
    }
    click.echo(json.dumps(data, indent=2))


if __name__ == "__main__":
    sys.exit(main())
