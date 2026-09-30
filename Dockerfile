# ---------------------------------------------------------------------------
# Hardened multi-stage image.
#   * Python 3.12 (Python 3.9 is end-of-life; 3.10+ also gets the patched
#     dependency versions selected by the markers in requirements.txt)
#   * dependencies built in a separate stage, only the wheels are copied over
#   * runs as an unprivileged user on a read-only-friendly layout
#   * gunicorn as the WSGI server (never the Flask development server)
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build
COPY requirements.txt .
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip \
    && /opt/venv/bin/pip install -r requirements.txt


FROM python:3.12-slim AS runtime

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_ENV=production \
    DATABASE_URL=sqlite:////data/app.db

# Unprivileged runtime account.
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin appuser \
    && mkdir -p /data \
    && chown -R appuser:appuser /data

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
COPY --chown=appuser:appuser app ./app
COPY --chown=appuser:appuser wsgi.py ./

USER appuser
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status == 200 else 1)"

# JWT_SECRET_KEY must be injected at run time; the app refuses to start without it.
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--threads", "4", \
     "--timeout", "30", "--access-logfile", "-", "--error-logfile", "-", "wsgi:app"]
