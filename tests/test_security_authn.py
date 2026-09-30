"""JWT hardening: forged, expired, wrong-typed and malformed tokens."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt
import pytest

from app.security.passwords import (
    MAX_PASSWORD_BYTES,
    dummy_hash,
    hash_password,
    validate_password_policy,
    verify_password,
)
from app.security.tokens import TokenError, decode_token


def _claims(app, **overrides):
    now = datetime.now(timezone.utc)
    payload = {
        "sub": "1",
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(minutes=5),
        "jti": "test-jti-0001",
        "sid": "test-sid-0001",
        "iss": app.config["JWT_ISSUER"],
        "aud": app.config["JWT_AUDIENCE"],
        "typ": "access",
    }
    payload.update(overrides)
    return payload


def _bearer(token: str):
    return {"Authorization": "Bearer " + token}


def test_tampered_signature_is_rejected(client, alice):
    token = alice["tokens"]["access_token"]
    forged = token[:-3] + ("aaa" if not token.endswith("aaa") else "bbb")
    assert client.get("/api/data", headers=_bearer(forged)).status_code == 401


def test_alg_none_token_is_rejected(app, client, alice):
    forged = jwt.encode(_claims(app), key="", algorithm="none")
    response = client.get("/api/data", headers=_bearer(forged))
    assert response.status_code == 401


def test_token_signed_with_another_secret_is_rejected(app, client, alice):
    forged = jwt.encode(_claims(app), "attacker-controlled-key-0123456789", algorithm="HS256")
    assert client.get("/api/data", headers=_bearer(forged)).status_code == 401


def test_expired_token_is_rejected(app, client, alice):
    past = datetime.now(timezone.utc) - timedelta(hours=2)
    expired = jwt.encode(
        _claims(app, iat=past, nbf=past, exp=past + timedelta(minutes=1)),
        app.config["JWT_SECRET_KEY"],
        algorithm="HS256",
    )
    response = client.get("/api/data", headers=_bearer(expired))
    assert response.status_code == 401
    assert "expired" in response.get_json()["error"]["message"].lower()


def test_not_yet_valid_token_is_rejected(app, client, alice):
    future = datetime.now(timezone.utc) + timedelta(hours=1)
    token = jwt.encode(
        _claims(app, nbf=future, iat=future, exp=future + timedelta(minutes=5)),
        app.config["JWT_SECRET_KEY"],
        algorithm="HS256",
    )
    assert client.get("/api/data", headers=_bearer(token)).status_code == 401


def test_wrong_issuer_is_rejected(app, client, alice):
    token = jwt.encode(
        _claims(app, iss="https://evil.example"), app.config["JWT_SECRET_KEY"], algorithm="HS256"
    )
    assert client.get("/api/data", headers=_bearer(token)).status_code == 401


def test_wrong_audience_is_rejected(app, client, alice):
    token = jwt.encode(
        _claims(app, aud="some-other-service"), app.config["JWT_SECRET_KEY"], algorithm="HS256"
    )
    assert client.get("/api/data", headers=_bearer(token)).status_code == 401


def test_missing_required_claims_are_rejected(app, client, alice):
    payload = _claims(app)
    payload.pop("jti")
    token = jwt.encode(payload, app.config["JWT_SECRET_KEY"], algorithm="HS256")
    assert client.get("/api/data", headers=_bearer(token)).status_code == 401


def test_refresh_token_cannot_access_protected_api(client, alice):
    assert client.get("/api/data", headers=alice["refresh_headers"]).status_code == 401


def test_token_for_deleted_account_is_rejected(app, client, alice):
    from sqlalchemy import select

    from app.extensions import db
    from app.models import User

    user = db.s.execute(select(User).where(User.username == "alice")).scalar_one()
    db.s.delete(user)
    db.s.commit()
    assert client.get("/api/data", headers=alice["headers"]).status_code == 401


def test_token_for_disabled_account_is_rejected(app, client, alice):
    from sqlalchemy import select

    from app.extensions import db
    from app.models import User

    user = db.s.execute(select(User).where(User.username == "alice")).scalar_one()
    user.is_active = False
    db.s.commit()
    assert client.get("/api/data", headers=alice["headers"]).status_code == 401


@pytest.mark.parametrize(
    "header",
    [
        "",
        "Bearer",
        "Bearer ",
        "Basic dXNlcjpwYXNz",
        "Token abc.def.ghi",
        "Bearer a b",
        "bearer",
        "Bearer not-a-jwt",
        "Bearer a.b.c",
    ],
)
def test_malformed_authorization_headers_are_rejected(client, alice, header):
    response = client.get("/api/data", headers={"Authorization": header})
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"


def test_lowercase_bearer_scheme_is_accepted(client, alice):
    token = alice["tokens"]["access_token"]
    assert client.get("/api/data", headers={"Authorization": "bearer " + token}).status_code == 200


def test_non_numeric_subject_is_rejected(app, alice):
    token = jwt.encode(
        _claims(app, sub="not-a-number"), app.config["JWT_SECRET_KEY"], algorithm="HS256"
    )
    with pytest.raises(TokenError):
        decode_token(token, expected_type="access")


def test_decode_token_rejects_wrong_type(app, alice):
    token = alice["tokens"]["access_token"]
    with pytest.raises(TokenError):
        decode_token(token, expected_type="refresh")


# --- password hashing -------------------------------------------------------


def test_hash_password_produces_a_salted_bcrypt_hash():
    first = hash_password("Str0ng!Passw0rd", rounds=4)
    second = hash_password("Str0ng!Passw0rd", rounds=4)
    assert first != second  # unique salt per hash
    assert verify_password("Str0ng!Passw0rd", first)
    assert not verify_password("wrong", first)


def test_hash_password_rejects_over_long_input():
    with pytest.raises(ValueError):
        hash_password("x" * (MAX_PASSWORD_BYTES + 1), rounds=4)


def test_verify_password_fails_closed_on_a_corrupt_hash():
    assert verify_password("anything", "not-a-bcrypt-hash") is False


def test_dummy_hash_is_stable_and_never_matches():
    assert dummy_hash(4) == dummy_hash(4)
    assert not verify_password("Str0ng!Passw0rd", dummy_hash(4))


def test_password_policy_reports_every_problem():
    assert validate_password_policy("Str0ng!Passw0rd") == []
    assert validate_password_policy("short") != []
    assert any("weak passwords" in item for item in validate_password_policy("password1234"))
    assert any("72 bytes" in item for item in validate_password_policy("Aa1!" + "x" * 80))
