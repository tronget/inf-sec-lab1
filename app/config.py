"""Application configuration.

Every security-relevant setting is sourced from the environment so that no
secret ever lives in the source tree (OWASP A05:2021 - Security Misconfiguration
and A07:2021 - Identification and Authentication Failures).

The production configuration *fails closed*: the process refuses to start if
``JWT_SECRET_KEY`` is missing, too short, or one of the well-known development
placeholders.
"""

from __future__ import annotations

import os
from typing import Dict, List, Optional, Type

#: Values that must never be used as a signing key outside local development.
_FORBIDDEN_KEYS = frozenset(
    {
        "change-me",
        "changeme",
        "dev",
        "development",
        "insecure",
        "please-change-me",
        "secret",
        "test",
    }
)

#: Minimum length required from the JWT signing key.
MIN_JWT_KEY_LENGTH = 32

#: Minimum number of *distinct* characters - rejects keys like 'aaaa...'.
MIN_JWT_KEY_ALPHABET = 8


def _env_bool(name: str, default: bool) -> bool:
    """Read a boolean flag from the environment."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    """Read an integer from the environment, falling back on malformed input."""
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError:  # pragma: no cover - defensive
        return default


def _env_list(name: str) -> List[str]:
    """Read a comma-separated list from the environment."""
    raw = os.environ.get(name, "")
    return [item.strip() for item in raw.split(",") if item.strip()]


class BaseConfig:
    """Settings shared by every environment."""

    ENV_NAME = "base"
    DEBUG = False
    TESTING = False
    PROPAGATE_EXCEPTIONS = False

    # Reject oversized bodies before they are parsed (DoS hardening).
    MAX_CONTENT_LENGTH = _env_int("MAX_CONTENT_LENGTH", 64 * 1024)

    # --- Database ---------------------------------------------------------
    DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///app.db")
    SQLALCHEMY_ECHO = _env_bool("SQLALCHEMY_ECHO", False)
    AUTO_CREATE_TABLES = _env_bool("AUTO_CREATE_TABLES", True)

    # --- Cryptography / authentication ------------------------------------
    SECRET_KEY = os.environ.get("SECRET_KEY", "")
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "")
    JWT_ALGORITHM = "HS256"  # pinned: blocks `alg: none` and algorithm confusion
    JWT_ISSUER = os.environ.get("JWT_ISSUER", "lab1-secure-rest-api")
    JWT_AUDIENCE = os.environ.get("JWT_AUDIENCE", "lab1-secure-rest-api-clients")
    ACCESS_TOKEN_TTL_MINUTES = _env_int("ACCESS_TOKEN_TTL_MINUTES", 15)
    REFRESH_TOKEN_TTL_DAYS = _env_int("REFRESH_TOKEN_TTL_DAYS", 7)
    JWT_LEEWAY_SECONDS = _env_int("JWT_LEEWAY_SECONDS", 5)
    BCRYPT_ROUNDS = _env_int("BCRYPT_ROUNDS", 12)

    # --- Rate limiting ----------------------------------------------------
    RATELIMIT_ENABLED = _env_bool("RATELIMIT_ENABLED", True)
    RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
    RATELIMIT_DEFAULT = os.environ.get("RATELIMIT_DEFAULT", "200 per hour")
    RATELIMIT_LOGIN = os.environ.get("RATELIMIT_LOGIN", "5 per minute;20 per hour")
    RATELIMIT_REGISTER = os.environ.get("RATELIMIT_REGISTER", "5 per hour")
    RATELIMIT_HEADERS_ENABLED = True

    # --- Transport / browser hardening ------------------------------------
    CORS_ORIGINS = _env_list("CORS_ORIGINS")
    ENABLE_HSTS = _env_bool("ENABLE_HSTS", False)
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
    JSON_LOGGING = _env_bool("JSON_LOGGING", True)

    @classmethod
    def validate(cls, values: Dict[str, object]) -> None:
        """Hook for environment specific validation. No-op by default."""


class DevelopmentConfig(BaseConfig):
    """Local development: verbose, but still never ships a hardcoded secret."""

    ENV_NAME = "development"
    DEBUG = _env_bool("FLASK_DEBUG", False)
    BCRYPT_ROUNDS = _env_int("BCRYPT_ROUNDS", 12)


class TestingConfig(BaseConfig):
    """Test suite: in-memory database, cheap hashing, no rate limiting."""

    ENV_NAME = "testing"
    TESTING = True
    DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "sqlite+pysqlite:///:memory:")
    BCRYPT_ROUNDS = _env_int("TEST_BCRYPT_ROUNDS", 4)
    RATELIMIT_ENABLED = False
    JSON_LOGGING = False
    LOG_LEVEL = "CRITICAL"


class ProductionConfig(BaseConfig):
    """Production: fail closed on weak or missing secrets."""

    ENV_NAME = "production"
    DEBUG = False
    ENABLE_HSTS = _env_bool("ENABLE_HSTS", True)

    @classmethod
    def validate(cls, values: Dict[str, object]) -> None:
        key = str(values.get("JWT_SECRET_KEY") or "")
        if not key:
            raise RuntimeError(
                "JWT_SECRET_KEY must be set in production. "
                'Generate one with: python -c "import secrets; print(secrets.token_urlsafe(48))"'
            )
        if key.strip().lower() in _FORBIDDEN_KEYS:
            raise RuntimeError("JWT_SECRET_KEY is a well-known placeholder value.")
        if len(key) < MIN_JWT_KEY_LENGTH:
            raise RuntimeError(
                "JWT_SECRET_KEY is too short: "
                f"at least {MIN_JWT_KEY_LENGTH} characters are required."
            )
        if len(set(key)) < MIN_JWT_KEY_ALPHABET:
            raise RuntimeError(
                "JWT_SECRET_KEY has insufficient entropy: "
                f"at least {MIN_JWT_KEY_ALPHABET} distinct characters are required."
            )
        if values.get("DEBUG"):
            raise RuntimeError("DEBUG must be disabled in production.")


_CONFIGS: Dict[str, Type[BaseConfig]] = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
}


def get_config(name: Optional[str] = None) -> Type[BaseConfig]:
    """Return the configuration class for ``name`` (or ``APP_ENV``)."""
    resolved = (name or os.environ.get("APP_ENV") or "development").strip().lower()
    if resolved not in _CONFIGS:
        raise RuntimeError(f"Unknown APP_ENV '{resolved}'.")
    return _CONFIGS[resolved]
