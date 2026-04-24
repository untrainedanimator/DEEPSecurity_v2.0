"""Uniform JSON error handlers."""
from __future__ import annotations

import sys
import traceback
from typing import Any

from flask import Flask, jsonify
from werkzeug.exceptions import HTTPException

from deepsecurity.config import settings
from deepsecurity.logging_config import get_logger
from deepsecurity.paths import PathOutsideRootError

_log = get_logger(__name__)


def register_error_handlers(app: Flask) -> None:
    @app.errorhandler(HTTPException)
    def _http(exc: HTTPException) -> Any:
        return (
            jsonify({"error": exc.name.lower().replace(" ", "_"), "message": exc.description}),
            exc.code or 500,
        )

    @app.errorhandler(PathOutsideRootError)
    def _path_outside(exc: PathOutsideRootError) -> Any:
        _log.warning("api.path_rejected", message=str(exc))
        return jsonify({"error": "path_outside_scan_root", "message": str(exc)}), 400

    @app.errorhandler(Exception)
    def _unhandled(exc: Exception) -> Any:
        # structlog entry (JSON) for log aggregators.
        _log.exception("api.unhandled_exception")
        # Also print a plain traceback to stderr so it shows up in the
        # interactive `deepsec serve` window even if the JSON log is buffered.
        print(
            f"\n[api.unhandled_exception] {type(exc).__name__}: {exc}",
            file=sys.stderr,
            flush=True,
        )
        traceback.print_exception(exc, file=sys.stderr)

        body: dict[str, Any] = {
            "error": "internal_error",
            "message": "see server logs",
        }
        # In dev, include the exception class + message in the response so
        # the operator doesn't have to alt-tab to the server window.
        if settings.env != "production":
            body["exception"] = f"{type(exc).__name__}: {exc}"
        return jsonify(body), 500
