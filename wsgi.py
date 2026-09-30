"""WSGI entry point.

Development:  flask --app wsgi run
Production:   gunicorn --bind 0.0.0.0:8000 wsgi:app
"""

from __future__ import annotations

from app import create_app

app = create_app()

if __name__ == "__main__":  # pragma: no cover - manual invocation only
    # Bind to loopback by default; container deployments use gunicorn.
    app.run(host="127.0.0.1", port=8000)
