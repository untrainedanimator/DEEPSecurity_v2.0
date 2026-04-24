"""HTTPS client between the agent and the control plane.

Stdlib only (urllib) so the agent footprint stays tiny. Robust to network
blips: connect + read timeouts, retries on 5xx, honest JSON parsing.
"""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request
from typing import Any


class TransportError(RuntimeError):
    pass


class AgentTransport:
    def __init__(
        self,
        *,
        server_url: str,
        agent_id: str | None = None,
        api_key: str | None = None,
        timeout: float = 15.0,
    ) -> None:
        self._base = server_url.rstrip("/")
        self._agent_id = agent_id
        self._api_key = api_key
        self._timeout = timeout
        self._ctx = ssl.create_default_context()

    # -- internal -------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: Any = None,
        authed: bool = True,
        retries: int = 2,
    ) -> dict[str, Any]:
        url = self._base + path
        headers: dict[str, str] = {"Accept": "application/json"}
        data: bytes | None = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if authed:
            if not self._agent_id or not self._api_key:
                raise TransportError("agent is not registered")
            headers["X-DEEPSEC-AGENT-ID"] = self._agent_id
            headers["X-DEEPSEC-AGENT-KEY"] = self._api_key

        last_err: Exception | None = None
        for attempt in range(retries + 1):
            try:
                req = urllib.request.Request(url, data=data, method=method, headers=headers)
                with urllib.request.urlopen(req, timeout=self._timeout, context=self._ctx) as resp:
                    raw = resp.read()
                if not raw:
                    return {}
                return json.loads(raw.decode("utf-8"))
            except urllib.error.HTTPError as e:
                if e.code in {502, 503, 504} and attempt < retries:
                    time.sleep(1.5 ** attempt)
                    continue
                try:
                    payload = json.loads((e.read() or b"").decode("utf-8"))
                except Exception:
                    payload = {"error": f"http_{e.code}"}
                raise TransportError(f"HTTP {e.code}: {payload}") from e
            except (urllib.error.URLError, TimeoutError) as e:
                last_err = e
                if attempt < retries:
                    time.sleep(1.5 ** attempt)
                    continue
                raise TransportError(f"network: {e}") from e
        raise TransportError(f"retries exhausted: {last_err}")

    # -- public API -----------------------------------------------------

    def register(
        self,
        *,
        enrolment_token: str,
        hostname: str,
        os_name: str,
        os_version: str | None,
        agent_version: str,
        labels: list[str] | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            "/api/agents/register",
            body={
                "enrolment_token": enrolment_token,
                "hostname": hostname,
                "os": os_name,
                "os_version": os_version,
                "agent_version": agent_version,
                "labels": labels or [],
            },
            authed=False,
        )

    def set_credentials(self, agent_id: str, api_key: str) -> None:
        self._agent_id = agent_id
        self._api_key = api_key

    def heartbeat(self, summary: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", "/api/agents/heartbeat", body=summary)

    def pull_commands(self) -> list[dict[str, Any]]:
        out = self._request("GET", "/api/agents/commands")
        return list(out.get("commands", []))

    def post_result(self, command_id: int, success: bool, result: Any) -> None:
        self._request(
            "POST",
            "/api/agents/results",
            body={"command_id": command_id, "success": success, "result": result},
        )

    def post_event(self, kind: str, severity: str, payload: dict[str, Any]) -> None:
        self._request(
            "POST",
            "/api/agents/events",
            body={"kind": kind, "severity": severity, "payload": payload},
        )

    def get_policy(self) -> dict[str, Any]:
        """Fetch the agent's own policy. Returns the full {policy_sha,
        policy, updated_at, updated_by} dict; empty policy if none set.

        v2.4 FLEET_POLICY — operator pushes a policy via POST
        /api/agents/<id>/policy, agent reads its own via GET on the
        same route. Identity is enforced server-side (agent can only
        fetch its own id).
        """
        return self._request("GET", f"/api/agents/{self._agent_id}/policy")
