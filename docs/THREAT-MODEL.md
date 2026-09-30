# Threat Model

Scope: the REST API in this repository (Flask application + SQLite database),
as deployed by `Dockerfile` / `docker-compose.yml`.

## 1. Assets

| Asset | Why it matters |
| --- | --- |
| User credentials | Reuse across other services; account takeover |
| Password hashes | Offline cracking if the database leaks |
| JWT signing key | Forging tokens for any account |
| Access / refresh tokens | Impersonation until expiry |
| Note contents | User data, confidentiality |

## 2. Trust boundaries

```
[ Client / browser ]  --HTTPS-->  [ Reverse proxy / TLS ]  -->  [ Flask app ]  -->  [ SQLite ]
       untrusted                        out of scope              trusted           trusted
```

Everything arriving from a client - body, query string, path segments, headers -
is untrusted input. TLS termination and network filtering are assumed to be
handled by the deployment platform and are out of scope for the application.

## 3. Actors

* **Anonymous attacker** - can reach `/health`, `/auth/register`, `/auth/login`.
* **Authenticated user** - has a valid access token; may try to reach other
  users' data.
* **Passive observer** - sees traffic if TLS is absent or terminated wrongly.
* **Attacker with database read access** - e.g. through a backup leak.

## 4. STRIDE / OWASP Top 10 (2021) mapping

| # | Threat | OWASP | Control | Where |
| --- | --- | --- | --- | --- |
| T1 | Read or delete another user's note (IDOR) | A01 | Ownership check on every single-resource route; list queries always filtered by `owner_id` | `app/blueprints/api.py` |
| T2 | Forge a token by switching the algorithm to `none` | A02 / A07 | `algorithms=["HS256"]` pinned at decode time | `app/security/tokens.py` |
| T3 | Crack leaked password hashes | A02 | bcrypt, cost 12, unique salt per hash | `app/security/passwords.py` |
| T4 | SQL injection through login, search or path parameters | A03 | SQLAlchemy ORM + named bind parameters everywhere; typed `<int:...>` path converter; LIKE wildcards escaped | `app/blueprints/*.py` |
| T5 | Stored XSS through a note title consumed by a front-end | A03 | `markupsafe.escape()` on output, control characters stripped on input, JSON content type + `nosniff` + CSP | `app/security/sanitize.py`, `app/security/headers.py` |
| T6 | Mass assignment (`owner_id`, `is_admin`, ...) | A04 | pydantic schemas with `extra="forbid"`; ownership taken from the token, never from the body | `app/schemas.py` |
| T7 | Weak or default signing key in production | A05 | Startup validation: non-empty, >= 32 chars, >= 8 distinct characters, not a known placeholder | `app/config.py` |
| T8 | Stack traces / framework version leaking | A05 | Uniform opaque error envelope; `Server` header overwritten; `DEBUG` forced off in production | `app/errors.py`, `app/security/headers.py` |
| T9 | Known CVE in a dependency | A06 | Fully pinned requirements, `pip-audit` gate in CI, weekly scheduled re-scan, Dependabot | `.github/workflows/ci.yml` |
| T10 | Credential stuffing / brute force | A07 | Flask-Limiter: 5/min and 20/h on login, 5/h on register, 200/h global | `app/blueprints/auth.py` |
| T11 | Username enumeration via error text or response time | A07 | One generic `"Invalid credentials."` message; a dummy bcrypt verification runs when the account does not exist | `app/blueprints/auth.py` |
| T12 | Token replay after logout | A07 | Denylist checked on every request against both the token's `jti` and its session `sid`, so logout kills the access *and* the refresh token; `purge-tokens` CLI command prunes expired rows | `app/security/tokens.py` |
| T13 | Refresh token used as an access token | A07 | `typ` claim verified per endpoint | `app/security/decorators.py` |
| T14 | Token still valid after the account is disabled or deleted | A07 | The user row is loaded and its `is_active` flag checked on every request | `app/security/decorators.py` |
| T15 | Secret committed to git | A05 / A07 | `.env` git-ignored, no hardcoded default key, gitleaks job in CI | `.gitignore`, CI |
| T16 | Denial of service via a huge body | A05 | `MAX_CONTENT_LENGTH` = 64 KB, `per_page` capped at 100 | `app/config.py`, `app/schemas.py` |
| T17 | Cross-origin data theft from a browser | A05 | CORS disabled unless origins are explicitly allow-listed; no cookies, no credentialed CORS | `app/__init__.py` |
| T18 | Sensitive data in logs | A09 | Structured logging records only user id, `jti` and IP - never passwords, hashes or raw tokens | `app/logging_conf.py` |
| T19 | Attack goes unnoticed | A09 | `auth.login.failure`, `auth.token.rejected`, `authz.denied` and `token.revoked` events are logged | across `app/` |
| T20 | Container escalation | A05 | Non-root user, dropped capabilities, `no-new-privileges`, read-only filesystem | `Dockerfile`, `docker-compose.yml` |

## 5. Residual risks and non-goals

* **No TLS in the application itself.** Tokens are bearer credentials: without
  HTTPS in front, T2/T12 are trivially bypassed by interception. The deployment
  must terminate TLS and set `ENABLE_HSTS=true`.
* **In-memory rate-limit storage.** The default `memory://` backend is per
  process; a multi-worker or multi-replica deployment needs Redis
  (`RATELIMIT_STORAGE_URI`).
* **No MFA and no account lockout.** Rate limiting only slows credential
  stuffing down; a production system would add step-up authentication.
* **Refresh tokens are not rotated.** `POST /auth/logout` does invalidate the
  refresh token (via the session `sid`), but a stolen refresh token that the
  victim never logs out of stays valid for its full 7-day TTL. Rotation on every
  use, with reuse detection, is the natural next step.
* **Weak-password denylist is a small sample.** A real deployment should check
  candidates against the Have I Been Pwned k-anonymity range API.
* **SQLite.** Fine for the lab; it offers no row-level security and does not
  scale to concurrent writers. `DATABASE_URL` accepts PostgreSQL unchanged.
* **No audit-log integrity.** Logs go to stdout and can be tampered with by
  anyone who controls the host.
