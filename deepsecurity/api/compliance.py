"""Compliance + retention API."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from flask import Blueprint, Response, jsonify, request

from deepsecurity.api.auth import require_role
from deepsecurity.compliance import (
    DateWindow,
    audit_csv_export,
    generate_report,
    purge_older_than,
)
from deepsecurity.compliance_templates import REGISTRY as TEMPLATE_REGISTRY
from deepsecurity.compliance_templates import list_templates
from deepsecurity.config import settings
from deepsecurity.db import session_scope

compliance_bp = Blueprint("compliance", __name__)


def _jsonable(obj: Any) -> Any:
    """Recursively coerce datetimes to ISO strings; dicts and lists preserved."""
    if isinstance(obj, datetime):
        return obj.isoformat() if obj.tzinfo else obj.replace(tzinfo=timezone.utc).isoformat()
    if isinstance(obj, dict):
        return {k: _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_jsonable(v) for v in obj]
    return obj


@compliance_bp.route("/report", methods=["GET"])
@require_role("admin", "security")
def report() -> Any:
    days = int(request.args.get("days", 30))
    window = DateWindow.last_days(days)
    report = generate_report(window)
    # jsonify doesn't like datetime — stringify any stragglers.
    if report.get("retention", {}).get("oldest_event"):
        report["retention"]["oldest_event"] = report["retention"]["oldest_event"].isoformat()
    return jsonify(report)


@compliance_bp.route("/audit.csv", methods=["GET"])
@require_role("admin", "security")
def audit_csv() -> Any:
    days = int(request.args.get("days", 30))
    window = DateWindow.last_days(days)
    csv_text = audit_csv_export(window)
    return Response(
        csv_text,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=audit-last-{days}d.csv"},
    )


@compliance_bp.route("/purge", methods=["POST"])
@require_role("admin")
def purge() -> Any:
    """Enforce retention. Admin-only."""
    days = int(request.args.get("days", settings.retention_days))
    if days < 1:
        return jsonify({"error": "days_must_be_positive"}), 400
    counts = purge_older_than(days)
    return jsonify({"retention_days": days, **counts})


# ---------------------------------------------------------------------------
# Named compliance templates — SOC2 / ISO 27001 / HIPAA evidence packs.
# ---------------------------------------------------------------------------


@compliance_bp.route("/templates", methods=["GET"])
@require_role("admin", "security", "analyst")
def list_available_templates() -> Any:
    """Directory of every registered compliance template. Cheap metadata
    only — no DB queries — so it's safe to poll from a UI."""
    return jsonify({"templates": list_templates()})


@compliance_bp.route("/template/<template_id>", methods=["GET"])
@require_role("admin", "security")
def get_template(template_id: str) -> Any:
    """Build the named compliance evidence pack for the given window.

    Query params:
        days   — window size (default 30; clamped to 1..3650)
        format — "json" (default). "pdf" returns 501 unless an optional
                 weasyprint build is installed on the operator's box.

    The template modules themselves live in
    ``deepsecurity/compliance_templates/``. Each one owns the shape of
    its own evidence pack; this route is just a dispatcher.
    """
    mod = TEMPLATE_REGISTRY.get(template_id)
    if mod is None:
        return (
            jsonify(
                {
                    "error": "unknown_template",
                    "template_id": template_id,
                    "available": sorted(TEMPLATE_REGISTRY.keys()),
                }
            ),
            404,
        )

    try:
        days = int(request.args.get("days", 30))
    except (TypeError, ValueError):
        return jsonify({"error": "bad_param", "param": "days"}), 400
    days = max(1, min(days, 3650))
    window = DateWindow.last_days(days)

    fmt = (request.args.get("format") or "json").lower()

    with session_scope() as s:
        payload = mod.build(s, window)

    payload = _jsonable(payload)

    if fmt == "pdf":
        # PDF rendering is an optional capability. weasyprint pulls in
        # native deps (cairo, pango, gdk-pixbuf) that don't install
        # cleanly on every operator's Windows venv; we keep it out of
        # the core requirements.txt. If it's installed, honour the
        # request; if not, return a 501 with a concrete hint.
        try:
            from weasyprint import HTML  # type: ignore[import-not-found]
        except ImportError:
            return (
                jsonify(
                    {
                        "error": "pdf_unavailable",
                        "message": (
                            "weasyprint is not installed in this venv. "
                            "Install with `pip install weasyprint` (note: "
                            "native deps required on Windows) or fetch "
                            "the report as JSON and render externally."
                        ),
                    }
                ),
                501,
            )
        html = _template_to_html(payload)
        pdf_bytes = HTML(string=html).write_pdf()
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={
                "Content-Disposition": (
                    f"attachment; filename={template_id}-last-{days}d.pdf"
                )
            },
        )

    return jsonify(payload)


def _template_to_html(payload: dict) -> str:
    """Minimal HTML wrapper for PDF export. Intentionally plain — the
    auditor wants the content, not the styling. Escapes values via
    json.dumps so operator-controlled strings can't inject markup."""
    import json as _json

    body = _json.dumps(payload, indent=2, default=str)
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        f"<title>{payload.get('title', 'DEEPSecurity compliance')}</title>"
        "<style>body{font-family:system-ui,-apple-system,sans-serif;"
        "margin:2rem;line-height:1.4} pre{background:#f6f8fa;"
        "padding:1rem;border:1px solid #d0d7de;border-radius:4px;"
        "white-space:pre-wrap;word-break:break-word}</style></head>"
        "<body>"
        f"<h1>{payload.get('title', 'Compliance report')}</h1>"
        f"<p><strong>Control reference:</strong> {payload.get('control_ref', '')}</p>"
        f"<p>{payload.get('description', '')}</p>"
        f"<p><strong>Generated at:</strong> {payload.get('generated_at', '')}</p>"
        "<h2>Evidence (JSON)</h2>"
        f"<pre>{body}</pre>"
        "</body></html>"
    )
