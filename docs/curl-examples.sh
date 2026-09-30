#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# End-to-end smoke test of the API with curl.
#
#   Terminal 1:  make run          # or: .venv/bin/flask --app wsgi run --port 8000
#   Terminal 2:  ./docs/curl-examples.sh
#
# Covers the full assignment scenario:
#   register -> login -> 401 without a token -> 200 with a token
#            -> POST 201 -> GET 200 -> DELETE 204 -> logout -> replay 401
# Exits non-zero as soon as any step returns an unexpected status code.
# ---------------------------------------------------------------------------
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8000}"
USERNAME="${USERNAME:-demo_$(date +%s)}"
PASSWORD="${PASSWORD:-Demo-Str0ng!Pass1}"

bold() { printf '\n\033[1m%s\033[0m\n' "$*"; }
ok()   { printf '  \033[32m[OK]\033[0m   %s\n' "$*"; }
fail() { printf '  \033[31m[FAIL]\033[0m %s\n' "$*"; exit 1; }

# json_get <json> <key> - read a top-level string field without needing jq.
json_get() {
  python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get(sys.argv[2], ""))' "$1" "$2"
}

# request <METHOD> <PATH> [DATA] [TOKEN] -> sets HTTP_STATUS and HTTP_BODY
# A single curl call per request: the status code is appended on its own line
# and split off afterwards, so no request is ever replayed.
request() {
  local method="$1" path="$2" data="${3:-}" auth="${4:-}"
  local args=(-sS -w '\n%{http_code}' -X "$method" "${BASE_URL}${path}")

  if [ -n "$data" ]; then
    args+=(-H 'Content-Type: application/json' -d "$data")
  fi
  if [ -n "$auth" ]; then
    args+=(-H "Authorization: Bearer ${auth}")
  fi

  local raw
  raw="$(curl "${args[@]}")"
  HTTP_STATUS="${raw##*$'\n'}"
  HTTP_BODY="${raw%$'\n'*}"
}

expect() {
  local expected="$1" label="$2"
  if [ "$HTTP_STATUS" = "$expected" ]; then
    ok "${label} -> ${HTTP_STATUS}"
  else
    printf '  body: %s\n' "$HTTP_BODY"
    fail "${label} -> expected ${expected}, got ${HTTP_STATUS}"
  fi
}

bold "0. Health check"
request GET /health
expect 200 "GET  /health"
printf '  %s\n' "$HTTP_BODY"

bold "1. Register a new account (POST /auth/register)"
request POST /auth/register "{\"username\":\"${USERNAME}\",\"password\":\"${PASSWORD}\"}"
expect 201 "POST /auth/register"
printf '  %s\n' "$HTTP_BODY"

bold "1b. Registering the same username again is rejected"
request POST /auth/register "{\"username\":\"${USERNAME}\",\"password\":\"${PASSWORD}\"}"
expect 409 "POST /auth/register (duplicate)"

bold "1c. A weak password is rejected by the policy"
request POST /auth/register "{\"username\":\"weak_${USERNAME}\",\"password\":\"password\"}"
expect 422 "POST /auth/register (weak password)"

bold "2. Log in (POST /auth/login)"
request POST /auth/login "{\"username\":\"${USERNAME}\",\"password\":\"${PASSWORD}\"}"
expect 200 "POST /auth/login"
ACCESS_TOKEN="$(json_get "$HTTP_BODY" access_token)"
REFRESH_TOKEN="$(json_get "$HTTP_BODY" refresh_token)"
[ -n "$ACCESS_TOKEN" ] || fail "no access_token in the login response"
printf '  access_token:  %s...\n' "${ACCESS_TOKEN:0:40}"
printf '  refresh_token: %s...\n' "${REFRESH_TOKEN:0:40}"

bold "2b. Wrong password returns the same generic error"
request POST /auth/login "{\"username\":\"${USERNAME}\",\"password\":\"Wr0ng!Password1\"}"
expect 401 "POST /auth/login (wrong password)"
printf '  %s\n' "$HTTP_BODY"

bold "3. GET /api/data WITHOUT a token must be denied"
request GET /api/data
expect 401 "GET  /api/data (no token)"
printf '  %s\n' "$HTTP_BODY"

bold "4. GET /api/data WITH a token succeeds"
request GET /api/data "" "$ACCESS_TOKEN"
expect 200 "GET  /api/data (bearer token)"
printf '  %s\n' "$HTTP_BODY"

bold "5. Create a note (POST /api/data) - the XSS payload comes back escaped"
request POST /api/data '{"title":"<script>alert(1)</script>","content":"first note"}' "$ACCESS_TOKEN"
expect 201 "POST /api/data"
printf '  %s\n' "$HTTP_BODY"
NOTE_ID="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["id"])' "$HTTP_BODY")"
case "$HTTP_BODY" in
  *'<script>'*) fail "the response contains an unescaped <script> tag" ;;
  *) ok "the stored payload is HTML-escaped in the response" ;;
esac

bold "6. SQL-injection attempt in the search parameter is treated as data"
request GET "/api/data?q=%27%20OR%20%271%27%3D%271" "" "$ACCESS_TOKEN"
expect 200 "GET  /api/data?q=' OR '1'='1"
printf '  %s\n' "$HTTP_BODY"

bold "7. Read the note back (GET /api/data/<id>)"
request GET "/api/data/${NOTE_ID}" "" "$ACCESS_TOKEN"
expect 200 "GET  /api/data/${NOTE_ID}"

bold "8. Refresh the access token (POST /auth/refresh)"
request POST /auth/refresh "" "$REFRESH_TOKEN"
expect 200 "POST /auth/refresh"

bold "9. Delete the note (DELETE /api/data/<id>)"
request DELETE "/api/data/${NOTE_ID}" "" "$ACCESS_TOKEN"
expect 204 "DELETE /api/data/${NOTE_ID}"

bold "10. Log out and confirm the token is revoked"
request POST /auth/logout "" "$ACCESS_TOKEN"
expect 204 "POST /auth/logout"
request GET /api/data "" "$ACCESS_TOKEN"
expect 401 "GET  /api/data (revoked token)"
printf '  %s\n' "$HTTP_BODY"

bold "All checks passed."
