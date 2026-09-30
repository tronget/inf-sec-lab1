"""Liveness endpoint and response hardening headers."""

from __future__ import annotations

import pytest

from app.security.headers import STATIC_HEADERS


def test_health_returns_ok(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"
    assert response.headers["Content-Type"].startswith("application/json")


@pytest.mark.parametrize("header", sorted(STATIC_HEADERS))
def test_security_headers_present(client, header):
    response = client.get("/health")
    assert response.headers.get(header) == STATIC_HEADERS[header]


def test_server_header_does_not_leak_framework(client):
    response = client.get("/health")
    assert "werkzeug" not in response.headers.get("Server", "").lower()


def test_hsts_enabled_by_configuration(app, client):
    app.config["ENABLE_HSTS"] = True
    response = client.get("/health")
    assert "max-age=31536000" in response.headers["Strict-Transport-Security"]


def test_auth_responses_are_never_cached(client):
    response = client.post("/auth/login", json={"username": "nobody", "password": "whatever1234"})
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"


def test_unknown_route_returns_json_error(client):
    response = client.get("/does-not-exist")
    assert response.status_code == 404
    assert response.get_json()["error"]["code"] == "not_found"


def test_method_not_allowed_returns_json_error(client):
    response = client.delete("/health")
    assert response.status_code == 405
    assert response.get_json()["error"]["code"] == "method_not_allowed"
