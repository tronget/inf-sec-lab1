"""Request validation with pydantic v2 (positive/allow-list validation).

``extra="forbid"`` rejects unknown keys outright - mass-assignment and
parameter-pollution attempts fail with 422 instead of being silently ignored.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.security.passwords import validate_password_policy
from app.security.sanitize import normalize_text

#: Allow-list for usernames. Restricting the character set is defence in depth
#: on top of parameterised queries and output encoding.
USERNAME_PATTERN = r"^[A-Za-z0-9_.-]{3,32}$"


class StrictModel(BaseModel):
    """Base model: no unknown fields, whitespace trimmed."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class RegisterRequest(StrictModel):
    """Body of ``POST /auth/register``."""

    username: str = Field(..., min_length=3, max_length=32, pattern=USERNAME_PATTERN)
    password: str = Field(..., min_length=1, max_length=200)

    @field_validator("password")
    @classmethod
    def _check_policy(cls, value: str) -> str:
        problems = validate_password_policy(value)
        if problems:
            raise ValueError("Password " + "; ".join(problems) + ".")
        return value


class LoginRequest(StrictModel):
    """Body of ``POST /auth/login``.

    Deliberately *not* policy-validated: a login attempt with a weak password
    must fail with the same generic 401 as a wrong password, otherwise the error
    shape itself becomes an oracle.
    """

    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=200)


class NoteCreateRequest(StrictModel):
    """Body of ``POST /api/data``."""

    title: str = Field(..., min_length=1, max_length=200)
    content: str = Field(default="", max_length=5000)

    @field_validator("title", "content")
    @classmethod
    def _normalize(cls, value: str) -> str:
        return normalize_text(value)

    @field_validator("title")
    @classmethod
    def _title_not_empty(cls, value: str) -> str:
        if not value:
            raise ValueError("Title must not be empty after normalisation.")
        return value


class DataQuery(StrictModel):
    """Query string of ``GET /api/data``."""

    page: int = Field(default=1, ge=1, le=10_000)
    per_page: int = Field(default=20, ge=1, le=100)
    q: Optional[str] = Field(default=None, max_length=100)

    @field_validator("q")
    @classmethod
    def _normalize_query(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = normalize_text(value, max_length=100)
        return normalized or None
