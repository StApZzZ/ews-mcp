#!/bin/sh
# DAST pre-flight smoke for ews-mcp v5 (POSIX sh + curl only).
#
# Asserts the unauthenticated HTTP surface of a server started in OAuth mode
# against an unreachable Exchange (no mailbox needed):
#   GET  /livez                                        -> 200
#   GET  /.well-known/oauth-authorization-server       -> 200 JSON (issuer, token_endpoint)
#   GET  /.well-known/oauth-protected-resource/mcp     -> 200 JSON (resource, authorization_servers)
#   POST /mcp without a token                          -> 401 + WWW-Authenticate: ... resource_metadata=
#   POST /mcp with a bogus bearer token                -> 401
#
# Usage:  sh scripts/dast_smoke.sh [BASE_URL]        (default http://127.0.0.1:8000)
#   or:   BASE_URL=http://host:8000 sh scripts/dast_smoke.sh
#   piped into a container:  docker run -i ... --entrypoint sh curlimages/curl -s -- URL < dast_smoke.sh
# Env:    SMOKE_WAIT_SECONDS  how long to wait for /livez first (default 60)
# Exit:   0 all checks passed, 1 at least one failed.

set -u

BASE_URL="${1:-${BASE_URL:-http://127.0.0.1:8000}}"
BASE_URL="${BASE_URL%/}"
WAIT="${SMOKE_WAIT_SECONDS:-60}"

TMP="$(mktemp -d 2>/dev/null || mktemp -d -t dastsmoke)"
trap 'rm -rf "$TMP"' EXIT INT TERM

FAILS=0
pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; FAILS=$((FAILS + 1)); }

# req METHOD PATH [extra curl args...]
# -> $STATUS, headers in $TMP/h, body in $TMP/b
req() {
    _m="$1"; _p="$2"; shift 2
    : > "$TMP/h"; : > "$TMP/b"
    STATUS="$(curl -sS -X "$_m" --max-time 10 -o "$TMP/b" -D "$TMP/h" \
        -w '%{http_code}' "$@" "$BASE_URL$_p" 2>"$TMP/e")" || STATUS="000"
}

header_has() {  # header_has NAME SUBSTRING  (case-insensitive name)
    grep -i "^$1:" "$TMP/h" | grep -q "$2"
}

body_is_json_object() {
    [ "$(tr -d ' \t\r\n' < "$TMP/b" | cut -c1)" = "{" ]
}

body_has_key() {
    grep -q "\"$1\"" "$TMP/b"
}

show() {  # context for a failed check
    printf '      status=%s\n' "$STATUS"
    sed 's/^/      < /' "$TMP/h" | tr -d '\r' | head -n 15
    printf '      body: %s\n' "$(head -c 300 "$TMP/b")"
    [ -s "$TMP/e" ] && printf '      curl: %s\n' "$(cat "$TMP/e")"
}

printf 'dast_smoke: target %s\n' "$BASE_URL"

# --- wait for the process (never-exit boot: /livez is up before Exchange) ---
elapsed=0
while :; do
    code="$(curl -s -o /dev/null --max-time 3 -w '%{http_code}' "$BASE_URL/livez" 2>/dev/null)" || code="000"
    [ "$code" = "200" ] && break
    if [ "$elapsed" -ge "$WAIT" ]; then
        break
    fi
    sleep 2
    elapsed=$((elapsed + 2))
done

# 1. liveness
req GET /livez
if [ "$STATUS" = "200" ]; then pass "GET /livez -> 200"; else fail "GET /livez -> $STATUS (expected 200)"; show; fi

# 2. OAuth authorization server metadata (RFC 8414)
req GET /.well-known/oauth-authorization-server -H 'Accept: application/json'
if [ "$STATUS" = "200" ] && header_has content-type 'application/json' && body_is_json_object \
        && body_has_key issuer && body_has_key token_endpoint; then
    pass "GET /.well-known/oauth-authorization-server -> 200 JSON"
else
    fail "GET /.well-known/oauth-authorization-server -> $STATUS (expected 200 JSON with issuer/token_endpoint)"; show
fi

# 3. Protected resource metadata for /mcp (RFC 9728)
req GET /.well-known/oauth-protected-resource/mcp -H 'Accept: application/json'
if [ "$STATUS" = "200" ] && body_is_json_object \
        && body_has_key resource && body_has_key authorization_servers; then
    pass "GET /.well-known/oauth-protected-resource/mcp -> 200 JSON"
else
    fail "GET /.well-known/oauth-protected-resource/mcp -> $STATUS (expected 200 JSON with resource/authorization_servers)"; show
fi

INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"dast-smoke","version":"0"}}}'

# 4. /mcp without a token -> 401 + resource_metadata pointer (MCP auth spec)
req POST /mcp -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' --data "$INIT"
if [ "$STATUS" = "401" ] && header_has www-authenticate 'resource_metadata='; then
    pass "POST /mcp (no token) -> 401 + WWW-Authenticate resource_metadata="
else
    fail "POST /mcp (no token) -> $STATUS (expected 401 with WWW-Authenticate: ... resource_metadata=)"; show
fi

# 5. /mcp with a forged token -> 401 (token is validated, not just present)
req POST /mcp -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' \
    -H 'Authorization: Bearer dast-smoke-not-a-real-token' --data "$INIT"
if [ "$STATUS" = "401" ]; then
    pass "POST /mcp (bogus token) -> 401"
else
    fail "POST /mcp (bogus token) -> $STATUS (expected 401)"; show
fi

if [ "$FAILS" -gt 0 ]; then
    printf 'dast_smoke: %s check(s) FAILED\n' "$FAILS"
    exit 1
fi
printf 'dast_smoke: all checks passed\n'
