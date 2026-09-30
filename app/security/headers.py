"""Response hardening headers.

A JSON API is not rendered by a browser, but these headers still matter: they
neutralise content sniffing, framing and referrer leaks if a response is ever
opened directly, and they cost nothing.
"""

from __future__ import annotations

from flask import Flask, Response

#: `sandbox` + `default-src 'none'` means: even if the body were treated as
#: HTML, nothing in it could load or execute.
CONTENT_SECURITY_POLICY = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; sandbox"

STATIC_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=(), interest-cohort=()",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
    # Do not advertise the server/framework version (information disclosure).
    "Server": "secure-rest-api",
}


def register_security_headers(app: Flask) -> None:
    """Add the hardening headers to every response."""

    @app.after_request
    def _apply(response: Response) -> Response:
        for name, value in STATIC_HEADERS.items():
            response.headers[name] = value

        if app.config.get("ENABLE_HSTS"):
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        # Never let a proxy or browser cache credentials or tokens.
        from flask import request

        if request.path.startswith("/auth"):
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
        else:
            response.headers.setdefault("Cache-Control", "no-store")

        response.headers.pop("X-Powered-By", None)
        return response
