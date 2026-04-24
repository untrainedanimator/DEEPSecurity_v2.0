"""Prometheus text exposition."""
from __future__ import annotations

from flask import Blueprint, Response

from deepsecurity.metrics import metrics

metrics_bp = Blueprint("metrics", __name__)


@metrics_bp.route("/metrics", methods=["GET"])
def scrape() -> Response:
    return Response(metrics.render(), mimetype="text/plain; version=0.0.4")
