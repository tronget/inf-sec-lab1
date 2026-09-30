"""Configuration hardening, CLI commands and infrastructure behaviour."""

from __future__ import annotations

import pytest

from app import create_app
from app.config import DevelopmentConfig, ProductionConfig, get_config
from app.extensions import db
from app.security.tokens import purge_expired_tokens


def test_get_config_resolves_known_environments():
    assert get_config("development") is DevelopmentConfig
    assert get_config("production") is ProductionConfig
    with pytest.raises(RuntimeError):
        get_config("does-not-exist")


def test_production_requires_a_jwt_secret():
    with pytest.raises(RuntimeError, match="JWT_SECRET_KEY must be set"):
        ProductionConfig.validate({"JWT_SECRET_KEY": "", "DEBUG": False})


def test_production_rejects_a_short_jwt_secret():
    with pytest.raises(RuntimeError, match="too short"):
        ProductionConfig.validate({"JWT_SECRET_KEY": "abc", "DEBUG": False})


def test_production_rejects_placeholder_secrets():
    for placeholder in ("change-me", "CHANGEME", "  secret  ", "insecure"):
        with pytest.raises(RuntimeError, match="placeholder"):
            ProductionConfig.validate({"JWT_SECRET_KEY": placeholder, "DEBUG": False})


def test_production_rejects_low_entropy_secrets():
    with pytest.raises(RuntimeError, match="entropy"):
        ProductionConfig.validate({"JWT_SECRET_KEY": "a" * 64, "DEBUG": False})


def test_production_refuses_debug_mode():
    strong = "Kq7-vZ2fR9pL0sXbN4mT6wYc1hJ8dGuA3eIoP5rSzQ"
    with pytest.raises(RuntimeError, match="DEBUG"):
        ProductionConfig.validate({"JWT_SECRET_KEY": strong, "DEBUG": True})


def test_development_app_generates_an_ephemeral_secret(monkeypatch):
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
    application = create_app("development", DATABASE_URL="sqlite+pysqlite:///:memory:")
    assert len(application.config["JWT_SECRET_KEY"]) >= 32
    assert application.config["SECRET_KEY"]


def test_production_app_boots_with_a_strong_secret():
    application = create_app(
        "production",
        JWT_SECRET_KEY="Kq7-vZ2fR9pL0sXbN4mT6wYc1hJ8dGuA3eIoP5rSzQ",
        DATABASE_URL="sqlite+pysqlite:///:memory:",
    )
    assert application.config["ENABLE_HSTS"] is True
    assert application.config["DEBUG"] is False


def test_cors_is_disabled_without_an_allow_list(client, alice):
    response = client.get("/api/data", headers=alice["headers"])
    assert "Access-Control-Allow-Origin" not in response.headers


def test_cors_allows_only_listed_origins():
    application = create_app(
        "testing",
        CORS_ORIGINS=["https://trusted.example"],
        DATABASE_URL="sqlite+pysqlite:///:memory:",
    )
    test_client = application.test_client()
    allowed = test_client.get("/health", headers={"Origin": "https://trusted.example"})
    blocked = test_client.get("/health", headers={"Origin": "https://evil.example"})
    assert allowed.headers.get("Access-Control-Allow-Origin") == "https://trusted.example"
    assert "Access-Control-Allow-Origin" not in blocked.headers


def test_unhandled_exception_returns_opaque_500(app, client):
    @app.get("/boom")
    def _boom():
        raise RuntimeError("internal detail that must not leak")

    response = client.get("/boom")
    assert response.status_code == 500
    assert response.get_json() == {
        "error": {"code": "internal_error", "message": "An internal error occurred."}
    }
    assert "internal detail" not in response.get_data(as_text=True)


def test_rate_limit_blocks_login_brute_force():
    application = create_app(
        "testing",
        RATELIMIT_ENABLED=True,
        RATELIMIT_LOGIN="3 per minute",
        DATABASE_URL="sqlite+pysqlite:///:memory:",
    )
    test_client = application.test_client()
    statuses = [
        test_client.post(
            "/auth/login", json={"username": "ghost", "password": "Wr0ng!Pass123"}
        ).status_code
        for _ in range(5)
    ]
    assert 429 in statuses
    limited = [status for status in statuses if status == 429]
    assert len(limited) >= 1


def test_rate_limited_response_is_json():
    application = create_app(
        "testing",
        RATELIMIT_ENABLED=True,
        RATELIMIT_LOGIN="1 per minute",
        DATABASE_URL="sqlite+pysqlite:///:memory:",
    )
    test_client = application.test_client()
    test_client.post("/auth/login", json={"username": "ghost", "password": "Wr0ng!Pass123"})
    response = test_client.post(
        "/auth/login", json={"username": "ghost", "password": "Wr0ng!Pass123"}
    )
    assert response.status_code == 429
    assert response.get_json()["error"]["code"] == "rate_limited"


# --- CLI --------------------------------------------------------------------


def test_seed_db_command(app):
    runner = app.test_cli_runner()
    result = runner.invoke(args=["seed-db"])
    assert result.exit_code == 0
    assert "Seeded 2 user(s)" in result.output
    # Running it twice is idempotent.
    assert "Seeded 0 user(s)" in runner.invoke(args=["seed-db"]).output


def test_init_db_command(app):
    result = app.test_cli_runner().invoke(args=["init-db"])
    assert result.exit_code == 0
    assert "schema created" in result.output


def test_create_user_command(app):
    runner = app.test_cli_runner()
    result = runner.invoke(
        args=["create-user", "--username", "clara", "--password", "Clara-Str0ng!1"]
    )
    assert result.exit_code == 0
    assert "Created user clara" in result.output

    duplicate = runner.invoke(
        args=["create-user", "--username", "clara", "--password", "Clara-Str0ng!1"]
    )
    assert duplicate.exit_code != 0

    weak = runner.invoke(args=["create-user", "--username", "dave", "--password", "weak"])
    assert weak.exit_code != 0


def test_purge_tokens_command(app, client):
    runner = app.test_cli_runner()
    result = runner.invoke(args=["purge-tokens"])
    assert result.exit_code == 0
    assert "expired denylist entries" in result.output


def test_purge_expired_tokens_removes_stale_rows(app):
    from datetime import datetime, timedelta, timezone

    from app.models import RevokedToken

    db.s.add(
        RevokedToken(
            jti="stale-token",
            token_type="access",
            user_id=1,
            expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        )
    )
    db.s.commit()
    assert purge_expired_tokens() == 1
    assert purge_expired_tokens() == 0


def test_json_log_formatter_emits_valid_json():
    import json
    import logging

    from app.logging_conf import JsonFormatter

    record = logging.LogRecord("test", logging.INFO, __file__, 1, "hello", None, None)
    record.event = "unit.test"
    payload = json.loads(JsonFormatter().format(record))
    assert payload["message"] == "hello"
    assert payload["event"] == "unit.test"
    assert payload["level"] == "INFO"
