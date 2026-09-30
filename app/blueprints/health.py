"""Unauthenticated liveness probe."""

from __future__ import annotations

from typing import Any, Dict, Tuple

from flask import Blueprint, Response, current_app, jsonify

health_bp = Blueprint("health", __name__)


@health_bp.get("/health")
def health() -> Tuple[Response, int]:
    """Return service liveness. Exposes no version or environment detail."""
    payload: Dict[str, Any] = {"status": "ok", "service": "lab1-secure-rest-api"}
    if current_app.config.get("TESTING"):
        payload["environment"] = "testing"
    return jsonify(payload), 200
