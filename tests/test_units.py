"""Focused unit tests for helpers and defensive branches."""

from __future__ import annotations

import json
import logging

import pytest
from pydantic import ValidationError

from app.config import _env_bool, _env_int, _env_list
from app.logging_conf import JsonFormatter
from app.schemas import DataQuery, NoteCreateRequest
from app.security.decorators import extract_bearer_token
from app.security.tokens import TokenError, is_revoked, revoke


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("1", True), ("true", True), ("YES", True), ("on", True), ("0", False), ("no", False)],
)
def test_env_bool(monkeypatch, raw, expected):
    monkeypatch.setenv("SOME_FLAG", raw)
    assert _env_bool("SOME_FLAG", not expected) is expected


def test_env_bool_default(monkeypatch):
    monkeypatch.delenv("SOME_FLAG", raising=False)
    assert _env_bool("SOME_FLAG", True) is True


@pytest.mark.parametrize(("raw", "expected"), [("42", 42), ("", 7), ("not-a-number", 7)])
def test_env_int(monkeypatch, raw, expected):
    monkeypatch.setenv("SOME_INT", raw)
    assert _env_int("SOME_INT", 7) == expected


def test_env_list(monkeypatch):
    monkeypatch.setenv("SOME_LIST", " a , b ,, c ")
    assert _env_list("SOME_LIST") == ["a", "b", "c"]
    monkeypatch.delenv("SOME_LIST")
    assert _env_list("SOME_LIST") == []


def test_note_title_cannot_be_only_control_characters():
    with pytest.raises(ValidationError):
        NoteCreateRequest(title="\x00\x01\x02", content="")


def test_blank_search_query_is_treated_as_absent():
    assert DataQuery(q="   ").q is None
    assert DataQuery().q is None
    assert DataQuery(q="hello").q == "hello"


@pytest.mark.parametrize("header", [None, "Bearer", "Basic x", "Bearer    "])
def test_extract_bearer_token_rejects_bad_headers(header):
    with pytest.raises(TokenError):
        extract_bearer_token(header)


def test_extract_bearer_token_accepts_a_valid_header():
    assert extract_bearer_token("Bearer abc.def.ghi") == "abc.def.ghi"


def test_empty_jti_is_treated_as_revoked(app):
    assert is_revoked("") is True


def test_revoke_is_idempotent_and_ignores_empty_jti(app, alice):
    import jwt

    token = alice["tokens"]["access_token"]
    claims = jwt.decode(
        token,
        app.config["JWT_SECRET_KEY"],
        algorithms=["HS256"],
        audience=app.config["JWT_AUDIENCE"],
        issuer=app.config["JWT_ISSUER"],
    )
    revoke(claims)
    revoke(claims)  # second call is a no-op, must not raise
    revoke({"jti": "", "exp": 0, "sub": "1"})  # nothing to do
    assert is_revoked(claims["jti"]) is True


def test_json_formatter_includes_exception_info():
    try:
        raise ValueError("boom")
    except ValueError:
        record = logging.LogRecord(
            "test", logging.ERROR, __file__, 1, "failed", None, __import__("sys").exc_info()
        )
    payload = json.loads(JsonFormatter().format(record))
    assert "ValueError: boom" in payload["exc_info"]


def test_registration_rate_limit_is_enforced():
    from app import create_app

    application = create_app(
        "testing",
        RATELIMIT_ENABLED=True,
        RATELIMIT_REGISTER="2 per hour",
        DATABASE_URL="sqlite+pysqlite:///:memory:",
    )
    test_client = application.test_client()
    statuses = [
        test_client.post(
            "/auth/register",
            json={"username": f"user{index}", "password": "Str0ng!Passw0rd"},
        ).status_code
        for index in range(4)
    ]
    assert statuses.count(429) >= 1


def test_teardown_rolls_back_on_error(app, client):
    from app.extensions import db
    from app.models import Note

    @app.get("/explode")
    def _explode():
        db.s.add(Note(owner_id=1, title="never committed", content=""))
        raise RuntimeError("failure after a pending write")

    assert client.get("/explode").status_code == 500
    assert db.s.query(Note).count() == 0
