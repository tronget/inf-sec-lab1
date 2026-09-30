"""Shared pytest fixtures.

Every test gets a brand-new application bound to its own in-memory SQLite
database, so tests are fully isolated and leave nothing on disk.
"""

from __future__ import annotations

from typing import Any, Dict, Iterator

import pytest
from flask import Flask
from flask.testing import FlaskClient

from app import create_app
from app.extensions import db

#: Passwords used across the suite. Strong enough to satisfy the policy.
ALICE_PASSWORD = "Alice-Str0ng!Pass"
BOB_PASSWORD = "Bob-Str0ng!Passw0rd"


@pytest.fixture()
def app() -> Iterator[Flask]:
    application = create_app("testing")
    with application.app_context():
        db.create_all()
        yield application
        db.s.remove()
        db.drop_all()


@pytest.fixture()
def client(app: Flask) -> FlaskClient:
    return app.test_client()


@pytest.fixture()
def register_user(client: FlaskClient):
    def _register(username: str, password: str) -> Dict[str, Any]:
        response = client.post("/auth/register", json={"username": username, "password": password})
        assert response.status_code == 201, response.get_json()
        return response.get_json()

    return _register


@pytest.fixture()
def login(client: FlaskClient):
    def _login(username: str, password: str) -> Dict[str, Any]:
        response = client.post("/auth/login", json={"username": username, "password": password})
        assert response.status_code == 200, response.get_json()
        return response.get_json()

    return _login


@pytest.fixture()
def alice(register_user, login) -> Dict[str, Any]:
    """A registered, logged-in user with ready-to-use auth headers."""
    register_user("alice", ALICE_PASSWORD)
    tokens = login("alice", ALICE_PASSWORD)
    return {
        "username": "alice",
        "password": ALICE_PASSWORD,
        "tokens": tokens,
        "headers": {"Authorization": "Bearer " + tokens["access_token"]},
        "refresh_headers": {"Authorization": "Bearer " + tokens["refresh_token"]},
    }


@pytest.fixture()
def bob(register_user, login) -> Dict[str, Any]:
    register_user("bob", BOB_PASSWORD)
    tokens = login("bob", BOB_PASSWORD)
    return {
        "username": "bob",
        "password": BOB_PASSWORD,
        "tokens": tokens,
        "headers": {"Authorization": "Bearer " + tokens["access_token"]},
    }


@pytest.fixture()
def make_note(client: FlaskClient):
    def _make(headers: Dict[str, str], title: str, content: str = "") -> Dict[str, Any]:
        response = client.post(
            "/api/data", headers=headers, json={"title": title, "content": content}
        )
        assert response.status_code == 201, response.get_json()
        return response.get_json()

    return _make
