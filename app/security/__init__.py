"""Security primitives: password hashing, JWT handling, sanitisation, headers."""

from __future__ import annotations

from app.security.decorators import current_user, jwt_required
from app.security.headers import register_security_headers
from app.security.passwords import hash_password, validate_password_policy, verify_password
from app.security.sanitize import sanitize_text, strip_control_chars
from app.security.tokens import TokenError, create_token_pair, decode_token

__all__ = [
    "TokenError",
    "create_token_pair",
    "current_user",
    "decode_token",
    "hash_password",
    "jwt_required",
    "register_security_headers",
    "sanitize_text",
    "strip_control_chars",
    "validate_password_policy",
    "verify_password",
]
