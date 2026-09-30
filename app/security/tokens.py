"""JWT issuing and verification (OWASP A07:2021 - Authentication Failures).

Hardening applied here:

* the algorithm is **pinned to HS256** on both sides, which defeats the classic
  ``{"alg": "none"}`` forgery and HMAC/RSA confusion attacks;
* ``iss``, ``aud``, ``exp``, ``nbf``, ``iat``, ``sub`` and ``jti`` are required
  and verified, not merely read;
* a custom ``typ`` claim separates *access* from *refresh* tokens so a refresh
  token can never be replayed against ``/api/*``;
* every token carries a unique ``jti`` so it can be revoked via the denylist;
* the access token and the refresh token issued by one login share a ``sid``
  (session id), so ``POST /auth/logout`` terminates the *whole* session. Without
  this, revoking only the access token would leave the refresh token alive and
  the client could immediately mint a new access token - an incomplete logout
  (OWASP A07:2021 - "Session Termination").
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

import jwt
from flask import current_app
from sqlalchemy import select

from app.extensions import db
from app.models import RevokedToken

# These are JWT `typ` claim *values*, not credentials. bandit B105 / ruff S105
# match on the substring "TOKEN" in the identifier, so the false positive is
# suppressed inline with this justification rather than globally.
ACCESS_TOKEN_TYPE = "access"  # nosec B105  # noqa: S105
REFRESH_TOKEN_TYPE = "refresh"  # nosec B105  # noqa: S105

_REQUIRED_CLAIMS = ["exp", "iat", "nbf", "sub", "jti", "sid", "iss", "aud", "typ"]

#: ``token_type`` marker of the denylist row that kills an entire session.
SESSION_TOKEN_TYPE = "session"  # nosec B105  # noqa: S105


class TokenError(Exception):
    """Raised when a token is missing, malformed, expired or revoked."""

    def __init__(self, message: str = "Invalid or expired token.") -> None:
        super().__init__(message)
        self.message = message


def _secret() -> str:
    key = str(current_app.config.get("JWT_SECRET_KEY") or "")
    if not key:  # pragma: no cover - create_app() guarantees a key
        raise RuntimeError("JWT_SECRET_KEY is not configured.")
    return key


def new_session_id() -> str:
    """Generate the identifier shared by every token of one login session."""
    return secrets.token_urlsafe(24)


def _build_token(
    user_id: int, token_type: str, lifetime: timedelta, sid: Optional[str] = None
) -> Tuple[str, str, datetime]:
    now = datetime.now(timezone.utc)
    expires_at = now + lifetime
    jti = secrets.token_urlsafe(24)
    payload: Dict[str, Any] = {
        "sub": str(user_id),  # PyJWT requires `sub` to be a string
        "iat": now,
        "nbf": now,
        "exp": expires_at,
        "jti": jti,
        "sid": sid or new_session_id(),
        "iss": current_app.config["JWT_ISSUER"],
        "aud": current_app.config["JWT_AUDIENCE"],
        "typ": token_type,
    }
    token = jwt.encode(payload, _secret(), algorithm=current_app.config["JWT_ALGORITHM"])
    return token, jti, expires_at


def create_access_token(user_id: int, sid: Optional[str] = None) -> Tuple[str, str, datetime]:
    """Issue a short-lived access token, optionally inside an existing session."""
    minutes = int(current_app.config["ACCESS_TOKEN_TTL_MINUTES"])
    return _build_token(user_id, ACCESS_TOKEN_TYPE, timedelta(minutes=minutes), sid=sid)


def create_refresh_token(user_id: int, sid: Optional[str] = None) -> Tuple[str, str, datetime]:
    """Issue a long-lived refresh token, optionally inside an existing session."""
    days = int(current_app.config["REFRESH_TOKEN_TTL_DAYS"])
    return _build_token(user_id, REFRESH_TOKEN_TYPE, timedelta(days=days), sid=sid)


def create_token_pair(user_id: int) -> Dict[str, Any]:
    """Issue an access + refresh pair sharing one session id."""
    sid = new_session_id()
    access_token, _access_jti, access_exp = create_access_token(user_id, sid=sid)
    refresh_token, _refresh_jti, _refresh_exp = create_refresh_token(user_id, sid=sid)
    expires_in = int((access_exp - datetime.now(timezone.utc)).total_seconds())
    return {
        "token_type": "Bearer",
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_in": max(expires_in, 0),
    }


def decode_token(token: str, expected_type: Optional[str] = None) -> Dict[str, Any]:
    """Verify ``token`` and return its claims, or raise :class:`TokenError`."""
    try:
        claims = jwt.decode(
            token,
            _secret(),
            # Pinning the algorithm list is what blocks `alg: none` forgeries.
            algorithms=[current_app.config["JWT_ALGORITHM"]],
            issuer=current_app.config["JWT_ISSUER"],
            audience=current_app.config["JWT_AUDIENCE"],
            leeway=int(current_app.config.get("JWT_LEEWAY_SECONDS", 0)),
            options={
                "require": _REQUIRED_CLAIMS,
                "verify_signature": True,
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iat": True,
                "verify_aud": True,
                "verify_iss": True,
            },
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenError("Token has expired.") from exc
    except jwt.InvalidTokenError as exc:
        # Covers bad signature, alg mismatch, wrong iss/aud, missing claims.
        raise TokenError("Invalid or expired token.") from exc

    if expected_type is not None and claims.get("typ") != expected_type:
        raise TokenError("Wrong token type for this endpoint.")

    # Either this exact token, or the whole session it belongs to, may be denied.
    if is_revoked(str(claims.get("jti", ""))) or is_revoked(str(claims.get("sid", ""))):
        raise TokenError("Token has been revoked.")

    try:
        int(claims["sub"])
    except (KeyError, TypeError, ValueError) as exc:
        raise TokenError("Invalid or expired token.") from exc

    return claims


def is_revoked(identifier: str) -> bool:
    """Check the denylist for a ``jti`` or a ``sid`` (populated by ``/auth/logout``)."""
    if not identifier:
        return True
    stmt = select(RevokedToken.id).where(RevokedToken.jti == identifier)
    return db.s.execute(stmt).first() is not None


def _deny(identifier: str, token_type: str, user_id: Optional[int], expires_at: datetime) -> bool:
    """Insert one denylist row unless it is already there."""
    if not identifier or is_revoked(identifier):
        return False
    db.s.add(
        RevokedToken(
            jti=identifier,
            token_type=token_type,
            user_id=user_id,
            expires_at=expires_at,
        )
    )
    return True


def revoke(claims: Dict[str, Any]) -> None:
    """Terminate the session the token belongs to. Idempotent.

    Two rows are written: the token's own ``jti`` and its ``sid``. Denying the
    ``sid`` is what also invalidates the *refresh* token issued by the same
    login, so a logged-out client cannot mint a fresh access token.
    """
    jti = str(claims.get("jti", ""))
    sid = str(claims.get("sid", ""))
    if not jti and not sid:
        return

    user_id = None
    try:
        user_id = int(claims["sub"])
    except (KeyError, TypeError, ValueError):
        user_id = None

    changed = False
    if jti:
        token_expiry = datetime.fromtimestamp(int(claims["exp"]), tz=timezone.utc)
        changed |= _deny(jti, str(claims.get("typ", "unknown")), user_id, token_expiry)
    if sid:
        # The session row must outlive the *refresh* token, not just the access
        # token, otherwise purging it would silently resurrect the session.
        days = int(current_app.config["REFRESH_TOKEN_TTL_DAYS"])
        session_expiry = datetime.now(timezone.utc) + timedelta(days=days)
        changed |= _deny(sid, SESSION_TOKEN_TYPE, user_id, session_expiry)

    if changed:
        db.s.commit()


def purge_expired_tokens() -> int:
    """Delete denylist rows whose tokens have expired anyway. Returns the count."""
    now = datetime.now(timezone.utc)
    stmt = select(RevokedToken).where(RevokedToken.expires_at < now)
    rows = list(db.s.execute(stmt).scalars())
    for row in rows:
        db.s.delete(row)
    db.s.commit()
    return len(rows)
