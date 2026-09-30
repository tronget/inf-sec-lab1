"""The authentication middleware used by every protected endpoint.

``@jwt_required()`` is applied as a decorator, which makes the protection
explicit and auditable at each route (a blanket ``before_request`` hook is easy
to bypass accidentally when a new blueprint is added).
"""

from __future__ import annotations

import functools
from typing import Any, Callable, Dict, Optional, Tuple, TypeVar, cast

from flask import g, request
from sqlalchemy import select

from app.extensions import db
from app.models import User
from app.security.tokens import ACCESS_TOKEN_TYPE, TokenError, decode_token

F = TypeVar("F", bound=Callable[..., Any])

_UNAUTHORIZED_HEADERS = {"WWW-Authenticate": "Bearer"}


def _unauthorized(message: str) -> Any:
    from app.errors import ApiError

    return ApiError(401, "unauthorized", message, headers=dict(_UNAUTHORIZED_HEADERS))


def extract_bearer_token(header_value: Optional[str]) -> str:
    """Parse ``Authorization: Bearer <token>`` strictly.

    Anything else - missing header, wrong scheme, no token, extra segments - is
    rejected rather than guessed at.
    """
    if not header_value:
        raise TokenError("Authorization header is missing.")
    parts = header_value.split()
    if len(parts) != 2:
        raise TokenError("Authorization header must be 'Bearer <token>'.")
    scheme, token = parts
    if scheme.lower() != "bearer":
        raise TokenError("Unsupported authorization scheme.")
    if not token.strip():
        raise TokenError("Bearer token is empty.")
    return token


def authenticate(token_type: str = ACCESS_TOKEN_TYPE) -> Tuple[User, Dict[str, Any]]:
    """Validate the request's bearer token and load the owning user."""
    token = extract_bearer_token(request.headers.get("Authorization"))
    claims = decode_token(token, expected_type=token_type)

    stmt = select(User).where(User.id == int(claims["sub"]))
    user = db.s.execute(stmt).scalar_one_or_none()
    if user is None or not user.is_active:
        # The token is cryptographically valid but the account is gone/disabled.
        raise TokenError("Account is not available.")
    return user, claims


def jwt_required(token_type: str = ACCESS_TOKEN_TYPE) -> Callable[[F], F]:
    """Decorator factory guarding a view with a JWT of the given ``typ``."""

    def decorator(view: F) -> F:
        @functools.wraps(view)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            from flask import current_app

            try:
                user, claims = authenticate(token_type)
            except TokenError as exc:
                current_app.logger.info(
                    "auth.token.rejected",
                    extra={
                        "event": "auth.token.rejected",
                        "reason": exc.message,
                        "path": request.path,
                        "client_ip": request.remote_addr,
                    },
                )
                raise _unauthorized(exc.message) from exc

            g.current_user = user
            g.token_claims = claims
            return view(*args, **kwargs)

        return cast(F, wrapper)

    return decorator


def current_user() -> User:
    """Return the user attached to the request by :func:`jwt_required`."""
    user = getattr(g, "current_user", None)
    if user is None:  # pragma: no cover - defensive
        raise RuntimeError("current_user() used outside a @jwt_required view.")
    return cast(User, user)
