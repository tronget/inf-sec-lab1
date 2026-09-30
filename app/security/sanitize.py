"""Output encoding and input normalisation (OWASP A03:2021 - Injection / XSS).

For a JSON API the decisive controls are:

1. always answering with ``Content-Type: application/json`` so a browser never
   sniffs the body as HTML (reinforced by ``X-Content-Type-Options: nosniff``);
2. HTML-escaping every attacker-controlled string that is echoed back, so that a
   careless front-end which injects the value with ``innerHTML`` still cannot
   execute it.

``markupsafe.escape`` ships with Flask, so no extra dependency is required.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any, Optional

from markupsafe import escape

#: C0/C1 control characters except tab, newline and carriage return. They are
#: used for log forging and to smuggle payloads past naive filters.
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


def strip_control_chars(value: str) -> str:
    """Remove control characters from ``value`` (input normalisation)."""
    return _CONTROL_CHARS.sub("", value)


def normalize_text(value: str, *, max_length: Optional[int] = None) -> str:
    """Normalise user input: NFKC, control characters removed, trimmed."""
    normalized = unicodedata.normalize("NFKC", value)
    normalized = strip_control_chars(normalized).strip()
    if max_length is not None:
        normalized = normalized[:max_length]
    return normalized


def sanitize_text(value: Any) -> str:
    """HTML-escape ``value`` for safe inclusion in an API response.

    ``<script>`` becomes ``&lt;script&gt;``; quotes become ``&#34;``/``&#39;``.
    """
    if value is None:
        return ""
    return str(escape(strip_control_chars(str(value))))


def escape_like(value: str) -> str:
    """Escape LIKE/ILIKE wildcards so ``?q=`` cannot widen the search.

    ``%`` and ``_`` are wildcards in SQL ``LIKE``; a user searching for ``100%``
    must not match everything. The escape character itself is escaped first.
    This is *not* an SQL-injection control (bound parameters handle that) - it
    protects the semantics of the pattern.
    """
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
