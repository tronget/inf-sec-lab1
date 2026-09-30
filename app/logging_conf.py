"""Structured logging that never records credentials or tokens.

Only non-reversible identifiers (user id, token ``jti``, client ip) are logged.
Passwords, password hashes and raw JWTs are deliberately absent from every call
site in this project.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Any, Dict

_RESERVED = frozenset(vars(logging.LogRecord("", 0, "", 0, "", None, None)).keys()) | {
    "asctime",
    "message",
    "taskName",
}


class JsonFormatter(logging.Formatter):
    """Render log records as single-line JSON documents."""

    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


def configure_logging(app: Any) -> None:
    """Install the configured handler on the Flask application logger."""
    level = str(app.config.get("LOG_LEVEL", "INFO")).upper()
    handler = logging.StreamHandler(stream=sys.stdout)
    if app.config.get("JSON_LOGGING", True):
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(levelname)s %(name)s %(message)s"))

    app.logger.handlers.clear()
    app.logger.addHandler(handler)
    app.logger.setLevel(level)
    app.logger.propagate = False
