"""Authentication endpoints (``/auth/*``).

Implements the "Broken Authentication" controls required by the assignment:
bcrypt password storage, JWT issuing, access-token renewal via a refresh token
and session-wide revocation on logout.
"""

from __future__ import annotations

from typing import Any, Dict, Tuple

from flask import Blueprint, Response, current_app, g, jsonify, request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.errors import ApiError
from app.extensions import db, limiter
from app.models import User, to_utc_iso
from app.schemas import LoginRequest, RegisterRequest
from app.security.decorators import current_user, jwt_required
from app.security.passwords import dummy_hash, hash_password, verify_password
from app.security.sanitize import sanitize_text
from app.security.tokens import (
    ACCESS_TOKEN_TYPE,
    REFRESH_TOKEN_TYPE,
    create_access_token,
    create_token_pair,
    revoke,
)

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

#: One generic message for *every* failed login: wrong password, unknown user
#: and disabled account are indistinguishable to the client (anti-enumeration).
INVALID_CREDENTIALS = "Invalid credentials."

#: RFC 6750 challenge returned with every 401 from this API.
BEARER_CHALLENGE = {"WWW-Authenticate": "Bearer"}


def _json_body() -> Dict[str, Any]:
    """Parse the request body as JSON or raise a 400 with a safe message."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ApiError(400, "bad_request", "Request body must be a JSON object.")
    return data


def _login_limit() -> str:
    return str(current_app.config["RATELIMIT_LOGIN"])


def _register_limit() -> str:
    return str(current_app.config["RATELIMIT_REGISTER"])


@auth_bp.post("/register")
@limiter.limit(_register_limit)
def register() -> Tuple[Response, int]:
    """Create an account. The password is hashed with bcrypt, never stored raw."""
    payload = RegisterRequest.model_validate(_json_body())

    rounds = int(current_app.config["BCRYPT_ROUNDS"])
    user = User(
        username=payload.username,
        password_hash=hash_password(payload.password, rounds=rounds),
    )
    db.s.add(user)
    try:
        db.s.commit()
    except IntegrityError:
        db.s.rollback()
        raise ApiError(409, "conflict", "Username is already taken.") from None

    current_app.logger.info(
        "auth.register.success",
        extra={"event": "auth.register.success", "user_id": user.id},
    )
    body = {
        "id": user.id,
        "username": sanitize_text(user.username),
        "created_at": to_utc_iso(user.created_at),
    }
    return jsonify(body), 201


@auth_bp.post("/login")
@limiter.limit(_login_limit)
def login() -> Tuple[Response, int]:
    """Authenticate and issue an access/refresh JWT pair."""
    payload = LoginRequest.model_validate(_json_body())
    rounds = int(current_app.config["BCRYPT_ROUNDS"])

    stmt = select(User).where(User.username == payload.username)
    user = db.s.execute(stmt).scalar_one_or_none()

    if user is None:
        # Spend the same CPU time as a real verification so that the response
        # latency does not reveal whether the account exists.
        verify_password(payload.password, dummy_hash(rounds))
        _log_failed_login(None)
        raise ApiError(401, "unauthorized", INVALID_CREDENTIALS, headers=dict(BEARER_CHALLENGE))

    if not user.is_active or not verify_password(payload.password, user.password_hash):
        _log_failed_login(user.id)
        raise ApiError(401, "unauthorized", INVALID_CREDENTIALS, headers=dict(BEARER_CHALLENGE))

    tokens = create_token_pair(user.id)
    current_app.logger.info(
        "auth.login.success",
        extra={
            "event": "auth.login.success",
            "user_id": user.id,
            "client_ip": request.remote_addr,
        },
    )
    tokens["user"] = {"id": user.id, "username": sanitize_text(user.username)}
    return jsonify(tokens), 200


@auth_bp.post("/refresh")
@jwt_required(token_type=REFRESH_TOKEN_TYPE)
def refresh() -> Tuple[Response, int]:
    """Exchange a valid *refresh* token for a fresh access token.

    The new access token inherits the refresh token's ``sid``, so it stays part
    of the same session and dies with it when the session is revoked.
    """
    user = current_user()
    sid = str(g.token_claims.get("sid") or "") or None
    access_token, _jti, expires_at = create_access_token(user.id, sid=sid)
    current_app.logger.info(
        "auth.refresh.success",
        extra={"event": "auth.refresh.success", "user_id": user.id},
    )
    from datetime import datetime, timezone

    expires_in = int((expires_at - datetime.now(timezone.utc)).total_seconds())
    return (
        jsonify(
            {
                "token_type": "Bearer",
                "access_token": access_token,
                "expires_in": max(expires_in, 0),
            }
        ),
        200,
    )


@auth_bp.post("/logout")
@jwt_required(token_type=ACCESS_TOKEN_TYPE)
def logout() -> Tuple[str, int]:
    """Terminate the session: both the access token and its refresh token die.

    The denylist receives the token's ``jti`` *and* its ``sid``. Revoking only
    the access token would be an incomplete logout - the refresh token from the
    same login would still mint new access tokens.
    """
    claims = g.token_claims
    revoke(claims)
    current_app.logger.info(
        "token.revoked",
        extra={
            "event": "token.revoked",
            "user_id": current_user().id,
            "jti": claims.get("jti"),
            "sid": claims.get("sid"),
        },
    )
    return "", 204


def _log_failed_login(user_id: Any) -> None:
    current_app.logger.warning(
        "auth.login.failure",
        extra={
            "event": "auth.login.failure",
            "user_id": user_id,
            "client_ip": request.remote_addr,
        },
    )
