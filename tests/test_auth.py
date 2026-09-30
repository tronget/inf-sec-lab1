"""Registration, login, refresh and logout."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.extensions import db
from app.models import User
from tests.conftest import ALICE_PASSWORD


def test_register_creates_user_and_never_returns_password(client):
    response = client.post(
        "/auth/register", json={"username": "newbie", "password": "Newbie-Str0ng!1"}
    )
    assert response.status_code == 201
    body = response.get_json()
    assert body["username"] == "newbie"
    assert "password" not in body
    assert "password_hash" not in body


def test_register_stores_only_a_bcrypt_hash(app, client):
    client.post("/auth/register", json={"username": "hashed", "password": ALICE_PASSWORD})
    user = db.s.execute(select(User).where(User.username == "hashed")).scalar_one()
    assert user.password_hash != ALICE_PASSWORD
    assert user.password_hash.startswith("$2b$")
    assert ALICE_PASSWORD not in user.password_hash


def test_register_duplicate_username_conflicts(client, register_user):
    register_user("dupe", ALICE_PASSWORD)
    response = client.post("/auth/register", json={"username": "dupe", "password": ALICE_PASSWORD})
    assert response.status_code == 409
    assert response.get_json()["error"]["code"] == "conflict"


@pytest.mark.parametrize(
    "password",
    [
        "short1!A",  # below the minimum length
        "alllowercaseletters",  # only one character class
        "password1234",  # well-known weak password
    ],
)
def test_register_rejects_weak_passwords(client, password):
    response = client.post("/auth/register", json={"username": "weak", "password": password})
    assert response.status_code == 422
    assert response.get_json()["error"]["code"] == "validation_error"


def test_register_rejects_password_longer_than_bcrypt_limit(client):
    response = client.post(
        "/auth/register", json={"username": "toolong", "password": "A1!" + "x" * 80}
    )
    assert response.status_code == 422


@pytest.mark.parametrize("username", ["ab", "x" * 33, "bad user", "drop;table", "<script>"])
def test_register_rejects_invalid_usernames(client, username):
    response = client.post(
        "/auth/register", json={"username": username, "password": ALICE_PASSWORD}
    )
    assert response.status_code == 422


def test_register_rejects_unknown_fields(client):
    response = client.post(
        "/auth/register",
        json={"username": "extra", "password": ALICE_PASSWORD, "is_admin": True},
    )
    assert response.status_code == 422


def test_register_rejects_non_object_body(client):
    response = client.post("/auth/register", json=["not", "an", "object"])
    assert response.status_code == 400
    assert response.get_json()["error"]["code"] == "bad_request"


def test_login_returns_access_and_refresh_tokens(alice):
    tokens = alice["tokens"]
    assert tokens["token_type"] == "Bearer"
    assert tokens["access_token"] and tokens["refresh_token"]
    assert tokens["access_token"] != tokens["refresh_token"]
    assert tokens["expires_in"] > 0
    assert tokens["user"]["username"] == "alice"


def test_login_with_wrong_password_is_indistinguishable_from_unknown_user(client, alice):
    wrong = client.post("/auth/login", json={"username": "alice", "password": "Wr0ng!Passw0rd"})
    unknown = client.post("/auth/login", json={"username": "ghost", "password": "Wr0ng!Passw0rd"})
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.get_json() == unknown.get_json()
    assert wrong.get_json()["error"]["message"] == "Invalid credentials."
    assert wrong.headers["WWW-Authenticate"] == "Bearer"


def test_login_of_disabled_account_is_rejected(app, client, alice):
    user = db.s.execute(select(User).where(User.username == "alice")).scalar_one()
    user.is_active = False
    db.s.commit()
    response = client.post("/auth/login", json={"username": "alice", "password": ALICE_PASSWORD})
    assert response.status_code == 401


def test_login_requires_json_object(client):
    response = client.post("/auth/login", data="not json", content_type="application/json")
    assert response.status_code == 400


def test_refresh_issues_a_new_access_token(client, alice):
    response = client.post("/auth/refresh", headers=alice["refresh_headers"])
    assert response.status_code == 200
    body = response.get_json()
    assert body["token_type"] == "Bearer"
    assert body["access_token"] != alice["tokens"]["access_token"]
    assert "refresh_token" not in body


def test_refresh_rejects_an_access_token(client, alice):
    response = client.post("/auth/refresh", headers=alice["headers"])
    assert response.status_code == 401
    assert "token type" in response.get_json()["error"]["message"].lower()


def test_logout_revokes_the_token(client, alice):
    assert client.post("/auth/logout", headers=alice["headers"]).status_code == 204
    replay = client.get("/api/data", headers=alice["headers"])
    assert replay.status_code == 401
    assert "revoked" in replay.get_json()["error"]["message"].lower()


def test_logout_twice_is_rejected_after_revocation(client, alice):
    client.post("/auth/logout", headers=alice["headers"])
    assert client.post("/auth/logout", headers=alice["headers"]).status_code == 401


def test_me_returns_the_authenticated_profile(client, alice):
    response = client.get("/api/me", headers=alice["headers"])
    assert response.status_code == 200
    body = response.get_json()
    assert body["username"] == "alice"
    assert body["is_active"] is True
    assert "password_hash" not in body


# --- session termination ----------------------------------------------------
# Regression tests for an incomplete-logout defect: revoking only the access
# token left the refresh token alive, so a logged-out client could immediately
# mint a new access token. Both tokens of a login share a `sid`, and logout
# denies that `sid`.


def test_logout_also_kills_the_refresh_token(client, alice):
    """After logout the refresh token must not be exchangeable any more."""
    assert client.post("/auth/logout", headers=alice["headers"]).status_code == 204

    response = client.post("/auth/refresh", headers=alice["refresh_headers"])
    assert response.status_code == 401
    assert response.get_json()["error"]["message"] == "Token has been revoked."


def test_access_token_minted_from_refresh_dies_with_the_session(client, alice):
    """A token obtained via /auth/refresh belongs to the same session."""
    refreshed = client.post("/auth/refresh", headers=alice["refresh_headers"])
    assert refreshed.status_code == 200
    renewed = {"Authorization": "Bearer " + refreshed.get_json()["access_token"]}
    assert client.get("/api/data", headers=renewed).status_code == 200

    # Logging out with the *original* access token must invalidate the renewed
    # one as well, because both carry the same session id.
    assert client.post("/auth/logout", headers=alice["headers"]).status_code == 204
    assert client.get("/api/data", headers=renewed).status_code == 401


def test_login_and_refresh_tokens_share_one_session_id(app, alice):
    import jwt

    def claims_of(token):
        return jwt.decode(
            token,
            app.config["JWT_SECRET_KEY"],
            algorithms=["HS256"],
            audience=app.config["JWT_AUDIENCE"],
            issuer=app.config["JWT_ISSUER"],
        )

    access = claims_of(alice["tokens"]["access_token"])
    refresh = claims_of(alice["tokens"]["refresh_token"])
    assert access["sid"] == refresh["sid"]
    assert access["jti"] != refresh["jti"]  # but they remain distinct tokens


def test_other_sessions_survive_a_logout(client, login, alice):
    """Logging out one device must not sign the user out everywhere."""
    second = login("alice", alice["password"])
    second_headers = {"Authorization": "Bearer " + second["access_token"]}

    assert client.post("/auth/logout", headers=alice["headers"]).status_code == 204
    assert client.get("/api/data", headers=alice["headers"]).status_code == 401
    assert client.get("/api/data", headers=second_headers).status_code == 200


def test_token_without_session_id_is_rejected(app, client, alice):
    """`sid` is a required claim: a token missing it cannot be used."""
    from datetime import datetime, timedelta, timezone

    import jwt

    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "sub": "1",
            "iat": now,
            "nbf": now,
            "exp": now + timedelta(minutes=5),
            "jti": "no-session-id",
            "iss": app.config["JWT_ISSUER"],
            "aud": app.config["JWT_AUDIENCE"],
            "typ": "access",
        },
        app.config["JWT_SECRET_KEY"],
        algorithm="HS256",
    )
    assert client.get("/api/data", headers={"Authorization": "Bearer " + token}).status_code == 401
