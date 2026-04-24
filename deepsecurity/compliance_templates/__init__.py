"""Named compliance templates — SOC2 / ISO 27001 / HIPAA evidence packs.

Each template is a module under this package that exports:

    TEMPLATE_ID     — short identifier used in the URL / CLI (kebab-case)
    TITLE           — human-readable title
    CONTROL_REF     — which control the evidence maps to
    DESCRIPTION     — one paragraph summarising what the evidence covers
    build(session, window) -> dict[str, Any]
                    — builds the evidence pack. ``session`` is an open
                      SQLAlchemy session; ``window`` is a
                      ``compliance.DateWindow``.

The public registry is ``REGISTRY`` — a dict keyed by TEMPLATE_ID mapping
to the module itself. The API route and the CLI both look up templates
via this registry.

Design notes:

- One template per module, not one file per framework. Mixing controls
  from the same framework in one module would bury the structure an
  auditor cares about (they ask for "CC6.1 evidence", not "SOC2
  evidence").
- Every template is OBJECTIVE and deterministic: given the same DB +
  window, it produces the same dict. No timestamps in the payload
  beyond the `generated_at` key (always the current UTC now).
- Templates do NOT persist data, only read it. Audit trail is in the
  underlying tables, not in the template output.
- No new deps. Reuses ``deepsecurity.compliance`` helpers and the
  existing models.
"""
from __future__ import annotations

from types import ModuleType

from deepsecurity.compliance_templates import (
    hipaa_164_308_a_1,
    hipaa_164_312_a_1,
    iso27001_a_8_1,
    iso27001_a_8_9,
    iso27001_a_12_4,
    soc2_cc6_1,
    soc2_cc6_6,
    soc2_cc7_1,
)


REGISTRY: dict[str, ModuleType] = {
    # SOC2 — AICPA Trust Services Criteria (2017 rev, ref. 2022 points-of-focus)
    soc2_cc6_1.TEMPLATE_ID: soc2_cc6_1,
    soc2_cc6_6.TEMPLATE_ID: soc2_cc6_6,
    soc2_cc7_1.TEMPLATE_ID: soc2_cc7_1,
    # ISO/IEC 27001:2022 Annex A
    iso27001_a_8_1.TEMPLATE_ID: iso27001_a_8_1,
    iso27001_a_8_9.TEMPLATE_ID: iso27001_a_8_9,
    iso27001_a_12_4.TEMPLATE_ID: iso27001_a_12_4,
    # HIPAA Security Rule — 45 CFR §164.308 / §164.312
    hipaa_164_308_a_1.TEMPLATE_ID: hipaa_164_308_a_1,
    hipaa_164_312_a_1.TEMPLATE_ID: hipaa_164_312_a_1,
}


def list_templates() -> list[dict[str, str]]:
    """Metadata-only listing — safe for an unauthenticated directory page."""
    return [
        {
            "template_id": m.TEMPLATE_ID,
            "title": m.TITLE,
            "control_ref": m.CONTROL_REF,
            "description": m.DESCRIPTION,
        }
        for m in REGISTRY.values()
    ]
