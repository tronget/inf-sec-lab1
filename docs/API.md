# API Reference

Base URL (local): `http://127.0.0.1:8000`

All responses are `application/json`. All protected endpoints expect
`Authorization: Bearer <access_token>`.

## Error envelope

Every error - validation, authentication, authorisation, rate limiting or an
unexpected exception - uses the same shape:

```json
{
  "error": {
    "code": "validation_error",
    "message": "Request payload failed validation.",
    "details": { "fields": { "password": "Value error, Password must be ..." } }
  }
}
```

`details` is present only when there is something safe to say. Internal
exception messages and stack traces are never included.

## Status codes

| Code | Meaning |
| --- | --- |
| 200 | OK |
| 201 | Resource created |
| 204 | Success, no body |
| 400 | Malformed body (not a JSON object) |
| 401 | Missing, malformed, expired, wrong-typed or revoked token; bad credentials |
| 403 | Authenticated, but the resource belongs to someone else |
| 404 | Resource does not exist |
| 405 | Method not allowed on this path |
| 409 | Username already taken |
| 413 | Body larger than `MAX_CONTENT_LENGTH` (64 KB by default) |
| 422 | Schema/policy validation failed |
| 429 | Rate limit exceeded |
| 500 | Unexpected server error (opaque message) |

## Security headers

Every response carries:

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none'; sandbox
Referrer-Policy: no-referrer
Permissions-Policy: geolocation=(), microphone=(), camera=(), interest-cohort=()
Cross-Origin-Resource-Policy: same-origin
Cross-Origin-Opener-Policy: same-origin
Cache-Control: no-store
Server: secure-rest-api
```

`Strict-Transport-Security` is added when `ENABLE_HSTS=true` (default in
production).

---

## `GET /health`

Liveness probe. No authentication.

```bash
curl -s http://127.0.0.1:8000/health
```

```json
{ "status": "ok", "service": "lab1-secure-rest-api" }
```

---

## `POST /auth/register`

Create an account. Rate limit: 5 per hour per IP.

**Request**

```bash
curl -s -X POST http://127.0.0.1:8000/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"Alice-Str0ng!Pass"}'
```

| Field | Rules |
| --- | --- |
| `username` | 3-32 chars, `^[A-Za-z0-9_.-]+$`, unique |
| `password` | 12-72 bytes, at least 3 of {lowercase, uppercase, digit, symbol}, not in the weak-password denylist |

Unknown fields are rejected (`extra="forbid"`).

**201**

```json
{ "id": 1, "username": "alice", "created_at": "2026-09-05T10:48:23.542057+00:00" }
```

**Errors:** 400 (not a JSON object), 409 (username taken), 422 (policy),
429 (rate limit).

---

## `POST /auth/login`

Authenticate and receive a token pair. Rate limit: 5/minute and 20/hour per IP.

```bash
curl -s -X POST http://127.0.0.1:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"Alice-Str0ng!Pass"}'
```

**200**

```json
{
  "token_type": "Bearer",
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9....",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9....",
  "expires_in": 900,
  "user": { "id": 1, "username": "alice" }
}
```

**401** - identical response for a wrong password, an unknown username and a
disabled account:

```json
{ "error": { "code": "unauthorized", "message": "Invalid credentials." } }
```

### Token claims

| Claim | Value |
| --- | --- |
| `sub` | user id, as a string |
| `iat` / `nbf` / `exp` | issued-at / not-before / expiry |
| `jti` | unique id of this token, used by the revocation denylist |
| `sid` | session id shared by the access and refresh token of one login |
| `iss` | `JWT_ISSUER` (default `lab1-secure-rest-api`) |
| `aud` | `JWT_AUDIENCE` (default `lab1-secure-rest-api-clients`) |
| `typ` | `access` or `refresh` |

Algorithm: **HS256 only**, on both signing and verification.
Access token TTL: 15 minutes. Refresh token TTL: 7 days.

---

## `POST /auth/refresh`

Exchange a **refresh** token for a new access token. An access token here
returns 401.

```bash
curl -s -X POST http://127.0.0.1:8000/auth/refresh \
  -H "Authorization: Bearer ${REFRESH_TOKEN}"
```

**200**

```json
{ "token_type": "Bearer", "access_token": "eyJhbGciOi...", "expires_in": 900 }
```

---

## `POST /auth/logout`

Terminate the session. Both the token's own `jti` **and** its `sid` are added
to the denylist, so the refresh token issued by the same login stops working
too - revoking only the access token would be an incomplete logout. Sessions
created by other logins (other devices) are unaffected.

```bash
curl -s -X POST http://127.0.0.1:8000/auth/logout \
  -H "Authorization: Bearer ${ACCESS_TOKEN}"
```

**204** - no body. Replaying either the access token or the refresh token
afterwards returns 401 `"Token has been revoked."`

---

## `GET /api/me`

Profile of the authenticated user.

```bash
curl -s http://127.0.0.1:8000/api/me -H "Authorization: Bearer ${ACCESS_TOKEN}"
```

**200**

```json
{ "id": 1, "username": "alice", "is_active": true, "created_at": "2026-09-05T10:48:23.542057+00:00" }
```

---

## `GET /api/data`

List the caller's notes. Only the caller's own rows are ever returned.

| Query param | Default | Rules |
| --- | --- | --- |
| `page` | 1 | 1..10000 |
| `per_page` | 20 | 1..100 |
| `q` | - | free text, max 100 chars, matched against the title |

```bash
curl -s "http://127.0.0.1:8000/api/data?page=1&per_page=20&q=shopping" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}"
```

**200**

```json
{
  "items": [
    {
      "id": 1,
      "owner_id": 1,
      "title": "&lt;script&gt;alert(1)&lt;/script&gt;",
      "content": "first note",
      "created_at": "2026-09-05T10:48:23.589476+00:00",
      "updated_at": "2026-09-05T10:48:23.589477+00:00"
    }
  ],
  "page": 1,
  "per_page": 20,
  "total": 1,
  "query": "shopping"
}
```

Unknown query parameters are rejected with 422.

---

## `POST /api/data`

Create a note owned by the caller. This is the assignment's third,
free-choice endpoint.

```bash
curl -s -X POST http://127.0.0.1:8000/api/data \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H 'Content-Type: application/json' \
  -d '{"title":"Groceries","content":"milk, bread"}'
```

| Field | Rules |
| --- | --- |
| `title` | 1-200 chars, NFKC-normalised, control characters stripped, must be non-empty afterwards |
| `content` | up to 5000 chars, same normalisation |

`owner_id` cannot be supplied - it is taken from the token, and unknown fields
are rejected with 422.

**201** - the created note, with `title` and `content` HTML-escaped.

---

## `GET /api/data/{id}`

Fetch one note. Returns 403 if the note belongs to another user, 404 if it does
not exist.

```bash
curl -s http://127.0.0.1:8000/api/data/1 -H "Authorization: Bearer ${ACCESS_TOKEN}"
```

---

## `DELETE /api/data/{id}`

Delete one of the caller's own notes.

```bash
curl -s -X DELETE http://127.0.0.1:8000/api/data/1 \
  -H "Authorization: Bearer ${ACCESS_TOKEN}"
```

**204** - no body. 403 for someone else's note, 404 if it does not exist.
