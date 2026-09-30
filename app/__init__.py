"""Application factory for the lab1 secure REST API."""

from __future__ import annotations

import secrets
from typing import Any, Optional

from flask import Flask
from flask_cors import CORS

from app.cli import register_cli
from app.config import BaseConfig, get_config
from app.errors import register_error_handlers
from app.extensions import db, limiter
from app.logging_conf import configure_logging
from app.security.headers import register_security_headers

__version__ = "1.0.0"


def create_app(config_name: Optional[str] = None, **overrides: Any) -> Flask:
    """Build and configure a Flask application instance."""
    app = Flask(__name__)

    config_class = get_config(config_name)
    app.config.from_object(config_class)
    app.config.update(overrides)
    # Logging first, so that even the very first startup warning is structured.
    configure_logging(app)
    _ensure_secrets(app, config_class)
    config_class.validate(dict(app.config))

    db.init_app(app)
    _configure_rate_limiting(app)
    _configure_cors(app)
    register_security_headers(app)
    register_error_handlers(app)
    _register_blueprints(app)
    register_cli(app)

    if app.config.get("AUTO_CREATE_TABLES", True):
        with app.app_context():
            db.create_all()

    app.logger.info(
        "app.started",
        extra={"event": "app.started", "environment": app.config.get("ENV_NAME")},
    )
    return app


def _ensure_secrets(app: Flask, config_class: type) -> None:
    """Guarantee a signing key exists without ever hardcoding one.

    Production refuses to start without ``JWT_SECRET_KEY`` (see
    :meth:`ProductionConfig.validate`). Outside production an ephemeral random
    key is generated, so a leaked repository can never contain a usable secret.
    """
    if getattr(config_class, "ENV_NAME", "") == "production":
        return

    if not app.config.get("JWT_SECRET_KEY"):
        app.config["JWT_SECRET_KEY"] = secrets.token_urlsafe(48)
        if not app.config.get("TESTING"):
            app.logger.warning(
                "config.jwt_secret.generated",
                extra={
                    "event": "config.jwt_secret.generated",
                    "detail": (
                        "JWT_SECRET_KEY was not set; a random per-process key was "
                        "generated. Tokens will not survive a restart."
                    ),
                },
            )
    if not app.config.get("SECRET_KEY"):
        app.config["SECRET_KEY"] = secrets.token_urlsafe(48)


def _configure_rate_limiting(app: Flask) -> None:
    """Wire up Flask-Limiter.

    The extension reads ``RATELIMIT_ENABLED``, ``RATELIMIT_DEFAULT``,
    ``RATELIMIT_STORAGE_URI`` and ``RATELIMIT_HEADERS_ENABLED`` straight from
    ``app.config``; the test suite simply sets ``RATELIMIT_ENABLED=False``.
    """
    limiter.init_app(app)


def _configure_cors(app: Flask) -> None:
    """Enable CORS only for explicitly allow-listed origins."""
    origins = app.config.get("CORS_ORIGINS") or []
    if not origins:
        return
    CORS(
        app,
        origins=list(origins),
        supports_credentials=False,
        allow_headers=["Authorization", "Content-Type"],
        methods=["GET", "POST", "DELETE", "OPTIONS"],
        max_age=600,
    )


def _register_blueprints(app: Flask) -> None:
    from app.blueprints.api import api_bp
    from app.blueprints.auth import auth_bp
    from app.blueprints.health import health_bp

    app.register_blueprint(health_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp)


__all__ = ["BaseConfig", "__version__", "create_app"]
