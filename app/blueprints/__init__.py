"""HTTP blueprints."""

from __future__ import annotations

from app.blueprints.api import api_bp
from app.blueprints.auth import auth_bp
from app.blueprints.health import health_bp

__all__ = ["api_bp", "auth_bp", "health_bp"]
