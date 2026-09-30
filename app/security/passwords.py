"""Password hashing and password policy (OWASP A07:2021).

* bcrypt with a configurable cost factor (12 by default, 4 in the test suite).
* Only the hash is persisted - the plaintext never leaves the request scope.
* A constant-work dummy verification runs when the account does not exist, so
  response timing cannot be used to enumerate valid usernames.
"""

from __future__ import annotations

from typing import Dict, List

import bcrypt

#: bcrypt truncates anything past 72 *bytes*; longer inputs are rejected instead
#: of being silently shortened (which would weaken the password).
MAX_PASSWORD_BYTES = 72
MIN_PASSWORD_LENGTH = 12

#: A tiny sample of the classic weak-credential list. A production deployment
#: would check against the full "Have I Been Pwned" k-anonymity range API.
_WEAK_CREDENTIAL_DENYLIST = frozenset(
    {
        "123456789012",
        "administrator",
        "changeme1234",
        "iloveyou1234",
        "letmein12345",
        "passw0rd1234",
        "password1234",
        "qwerty123456",
        "welcome12345",
    }
)

_DUMMY_HASHES: Dict[int, bytes] = {}


def _rounds(value: int) -> int:
    """Clamp the cost factor into the range bcrypt accepts."""
    return max(4, min(int(value), 16))


def hash_password(password: str, rounds: int = 12) -> str:
    """Return the bcrypt hash of ``password``."""
    encoded = password.encode("utf-8")
    if len(encoded) > MAX_PASSWORD_BYTES:
        raise ValueError("Password exceeds the maximum supported length.")
    return bcrypt.hashpw(encoded, bcrypt.gensalt(rounds=_rounds(rounds))).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """Constant-time comparison of ``password`` against a stored bcrypt hash."""
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        # Malformed/corrupted hash in the database: fail closed, never raise.
        return False


def dummy_hash(rounds: int = 12) -> str:
    """A throw-away hash used to equalise timing for unknown usernames."""
    key = _rounds(rounds)
    if key not in _DUMMY_HASHES:
        _DUMMY_HASHES[key] = bcrypt.hashpw(b"invalid-account-placeholder", bcrypt.gensalt(key))
    return _DUMMY_HASHES[key].decode("utf-8")


def validate_password_policy(password: str) -> List[str]:
    """Return a list of policy violations (empty list means the password is fine)."""
    problems: List[str] = []
    encoded = password.encode("utf-8")

    if len(password) < MIN_PASSWORD_LENGTH:
        problems.append(f"must be at least {MIN_PASSWORD_LENGTH} characters long")
    if len(encoded) > MAX_PASSWORD_BYTES:
        problems.append(f"must not exceed {MAX_PASSWORD_BYTES} bytes (bcrypt truncation limit)")

    classes = 0
    classes += any(char.islower() for char in password)
    classes += any(char.isupper() for char in password)
    classes += any(char.isdigit() for char in password)
    classes += any(not char.isalnum() for char in password)
    if classes < 3:
        problems.append("must combine at least 3 of: lowercase, uppercase, digits, symbols")

    if password.strip().lower() in _WEAK_CREDENTIAL_DENYLIST:
        problems.append("is present in the list of well-known weak passwords")

    return problems
