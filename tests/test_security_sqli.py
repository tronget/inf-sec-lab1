"""SQL injection: classic payloads must be treated as data, never as SQL."""

from __future__ import annotations

import pytest
from sqlalchemy import inspect, select

from app.extensions import db
from app.models import Note, User
from app.security.sanitize import escape_like
from tests.conftest import ALICE_PASSWORD

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "admin'--",
    "'; DROP TABLE users;--",
    "' UNION SELECT username, password_hash FROM users--",
    '" OR ""="',
    "1; DELETE FROM notes WHERE 1=1;--",
]


@pytest.mark.parametrize("payload", SQLI_PAYLOADS)
def test_login_username_injection_does_not_authenticate(client, alice, payload):
    response = client.post("/auth/login", json={"username": payload, "password": payload})
    assert response.status_code in (401, 422)
    assert "access_token" not in (response.get_json() or {})


@pytest.mark.parametrize("payload", SQLI_PAYLOADS)
def test_login_password_injection_does_not_authenticate(client, alice, payload):
    response = client.post("/auth/login", json={"username": "alice", "password": payload})
    assert response.status_code == 401


@pytest.mark.parametrize("payload", SQLI_PAYLOADS)
def test_search_injection_returns_no_rows_and_keeps_schema(app, client, alice, payload):
    response = client.get("/api/data", headers=alice["headers"], query_string={"q": payload})
    assert response.status_code == 200
    assert response.get_json()["total"] == 0

    # The schema and the data are untouched: nothing was executed as SQL.
    tables = set(inspect(db.engine).get_table_names())
    assert {"users", "notes", "revoked_tokens"} <= tables
    assert db.s.execute(select(User)).scalars().all()


def test_injection_payload_is_stored_verbatim_as_data(client, alice, make_note):
    payload = "'; DROP TABLE notes;--"
    note = make_note(alice["headers"], payload)
    stored = db.s.get(Note, note["id"])
    assert stored.title == payload  # stored as a plain string, not executed
    assert client.get("/api/data", headers=alice["headers"]).get_json()["total"] == 1


@pytest.mark.parametrize("payload", ["%", "_", "%%", "a_b", "100%", "\\"])
def test_like_wildcards_in_search_are_escaped(client, alice, make_note, payload):
    make_note(alice["headers"], "totally unrelated title")
    response = client.get("/api/data", headers=alice["headers"], query_string={"q": payload})
    assert response.status_code == 200
    # A bare '%' must not act as "match everything".
    assert response.get_json()["total"] == 0


def test_search_finds_literal_percent_sign(client, alice, make_note):
    make_note(alice["headers"], "battery at 100% charge")
    make_note(alice["headers"], "no digits here")
    body = client.get("/api/data", headers=alice["headers"], query_string={"q": "100%"}).get_json()
    assert body["total"] == 1


def test_path_parameter_is_typed_and_never_reaches_sql_as_text(client, alice):
    # Flask's <int:note_id> converter rejects non-numeric input before the view runs.
    assert client.get("/api/data/1 OR 1=1", headers=alice["headers"]).status_code == 404
    assert client.get("/api/data/abc", headers=alice["headers"]).status_code == 404


def test_escape_like_helper():
    assert escape_like("100%") == "100\\%"
    assert escape_like("a_b") == "a\\_b"
    assert escape_like("back\\slash") == "back\\\\slash"


def test_registered_user_still_authenticates_after_injection_attempts(client, alice):
    for payload in SQLI_PAYLOADS:
        client.post("/auth/login", json={"username": payload, "password": payload})
    response = client.post("/auth/login", json={"username": "alice", "password": ALICE_PASSWORD})
    assert response.status_code == 200
