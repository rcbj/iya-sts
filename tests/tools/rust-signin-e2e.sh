#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# File: tests/tools/rust-signin-e2e.sh
#
# ---------------------------------------------------------------------------
# PHASE 5'S FIRST MILESTONE CHECK: THE UNCHANGED SIGN-IN BUNDLE SIGNS A
# PERSON IN AGAINST THE RUST RUNTIME, ON A STORE A NODE 1.x SERVICE WROTE
# (#444, rust/DESIGN.md section 4.7's method, D11).
#
#   tests/tools/rust-signin-e2e.sh <node image> <rust image> [out-dir]
#
# Nothing here is a compose stack: every container is started by name on a
# network of its own and removed at the end (KEEP=1 leaves them).
#
#   1. postgres:18 with postgres/'s own scripts, TLS on; a KEK in a file.
#   2. NODE, product mode, writes the store: two people through
#      /admin-api, the second enrolling an authenticator app at the sign-in
#      screen (product asks everybody for one), then
#      authn.allowOptionalSecondFactor so the first signs in with a password
#      alone. Two sign-ins are begun at /oauth2/authorize — the user
#      portal's client — and Node is stopped (the pending rows flushed).
#   3. RUST on the same store, KEK, appconfig, port and host name. Headless
#      Chrome loads the UNCHANGED bundle from it, at /authn/login#authn=…,
#      and signs the first person in with a password and the second with a
#      password and a one-time code. Each ends with an `sts_session`.
#   4. RUST signs the first person out at its own /logout (the logout
#      slice): headless Chrome holding that session's cookie loads the
#      UNCHANGED sign-out bundle, which draws the inventory from Rust's
#      /authn-api/logout, and presses Global logout; the result is drawn
#      and the browser no longer holds the cookie.
#   5. NODE again on the store Rust wrote: it reads the session Rust set
#      and kept (`GET /authn-api/logout`'s view names the person), and no
#      longer honours the one Rust signed out (401, nobody).
#   6. The same two sign-ins against Node, for the comparison.
#
# Writes <out-dir> (default tests/vectors/rust-signin-e2e, gitignored).
# Needs google-chrome on the host and NODE_PATH holding `ws`.
# ---------------------------------------------------------------------------
set -euo pipefail

NODE_IMAGE="$1"
RUST_IMAGE="$2"
cd "$(dirname "$0")/../.."
REPO="$PWD"
OUT="${3:-tests/vectors/rust-signin-e2e}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
TAG="${E2E_TAG:-iya-sts-444-p5-authnapi-e2e}"
PORT="${E2E_PORT:-19745}"
NET="$TAG-net"
DB="$TAG-db"
SVC="$TAG-svc"
BASE="https://localhost:$PORT"
SUMMARY="$OUT/summary.txt"
: > "$SUMMARY"
FAILED=0
DRIVER="node $REPO/tests/tools/rust-signin-e2e.js"

for img in "$NODE_IMAGE" "$RUST_IMAGE"; do
  label="$(docker image inspect --format \
    '{{index .Config.Labels "com.docker.compose.project"}}' "$img")"
  if [ -n "$label" ]; then
    echo "refusing: $img carries the compose label '$label'" >&2
    exit 2
  fi
done

say() { printf '%s\n' "$*" | tee -a "$SUMMARY"; }
pass() { say "  PASS  $*"; }
fail() { say "  FAIL  $*"; FAILED=1; }

cleanup() {
  docker logs "$SVC" > "$OUT/last.log" 2>&1 || true
  if [ -z "${KEEP:-}" ]; then
    docker rm -f "$SVC" "$DB" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

rand() { openssl rand -hex 24; }
APP_PW="$(rand)"; OWNER_PW="$(rand)"; SECRET="$(rand)"
SECRETS="$OUT/secrets"
mkdir -p "$SECRETS"
rm -f "$SECRETS/sts-kek"
openssl rand -base64 32 > "$SECRETS/sts-kek"
chmod 0444 "$SECRETS/sts-kek"
docker rm -f "$SVC" "$DB" >/dev/null 2>&1 || true
docker network rm "$NET" >/dev/null 2>&1 || true
docker network create "$NET" >/dev/null

say "== the database =="
docker run -d --name "$DB" --network "$NET" --network-alias db \
  -e POSTGRES_USER=sts -e STS_POSTGRES_PASSWORD="$OWNER_PW" \
  -e POSTGRES_DB=sts -e STS_DB_APP_USER=sts_app \
  -e STS_DB_APP_PASSWORD="$APP_PW" -e POSTGRES_TLS_CN=db \
  -v "$REPO/postgres/db-secrets.sh:/usr/local/bin/db-secrets.sh:ro" \
  -v "$REPO/postgres/generate-tls.sh:/usr/local/bin/generate-tls.sh:ro" \
  -v "$REPO/postgres/require-tls.sh:/docker-entrypoint-initdb.d/00-require-tls.sh:ro" \
  -v "$REPO/postgres/apply-schema.sh:/docker-entrypoint-initdb.d/10-apply-schema.sh:ro" \
  -v "$REPO/postgres/schema.sql:/usr/local/share/sts/schema.sql:ro" \
  postgres:18 bash -c "$(printf '%s ' \
    '. /usr/local/bin/db-secrets.sh && /usr/local/bin/generate-tls.sh &&' \
    'exec docker-entrypoint.sh postgres -c ssl=on' \
    '-c shared_preload_libraries=pg_stat_statements' \
    '-c ssl_cert_file=/var/lib/postgresql/tls/server.crt' \
    '-c ssl_key_file=/var/lib/postgresql/tls/server.key')" >/dev/null
for _ in $(seq 1 120); do
  docker exec "$DB" pg_isready -h 127.0.0.1 -U sts -d sts >/dev/null 2>&1 \
    && break
  sleep 1
done
sleep 3
rm -f "$SECRETS/server.crt"
docker cp "$DB:/var/lib/postgresql/tls/server.crt" "$SECRETS/server.crt"
chmod 0644 "$SECRETS/server.crt"
DB_URL="postgres://sts_app:$APP_PW@db:5432/sts?sslmode=verify-full"
pass "postgres is up"

printf '%s\n' "CONFIG_FILE=./env/local.js" "STS_MODE=product" \
  "STS_HTTPS=true" "STS_PUBLIC_BASE_URL=$BASE" \
  "STS_PERSISTENCE_MODE=postgres" "STS_DATABASE_URL=$DB_URL" \
  "STS_DATABASE_TLS_CA_FILE=/run/secrets/db-ca.crt" \
  "STS_PERSISTENCE_COORDINATE=true" "STS_KEYS_SOURCE=persisted" \
  "STS_KEYS_KEK_PROVIDER=file" "STS_KEYS_KEK_FILE=/run/secrets/sts-kek" \
  "STS_SECRETS_ALLOW_LOCAL_SECRETS=true" "STS_CLUSTER_MODE=off" \
  "STS_WORKERS_REQUEST_COUNT=0" "STS_DEBUGGER_ENABLED=off" \
  "STS_CSRF_SECRET=$(rand)" \
  "ADMIN_API_CLIENT_SECRET=$SECRET" > "$OUT/service.env"

start() {
  local image="$1" what="$2"
  local extra=()
  if [ "$image" = "$RUST_IMAGE" ] && [ -f "$OUT/version.json" ]; then
    extra=(-v "$OUT/version.json:/usr/src/sts/version.json:ro")
  fi
  docker rm -f "$SVC" >/dev/null 2>&1 || true
  docker run -d --name "$SVC" --hostname sts --network "$NET" \
    -p "127.0.0.1:$PORT:8081" --env-file "$OUT/service.env" "${extra[@]}" \
    -v "$SECRETS/sts-kek:/run/secrets/sts-kek:ro" \
    -v "$SECRETS/server.crt:/run/secrets/db-ca.crt:ro" "$image" >/dev/null
  for _ in $(seq 1 180); do
    if [ "$(curl -sk -o /dev/null -w '%{http_code}' "$BASE/healthcheck")" \
         = 200 ]; then
      pass "$what is serving on $PORT"
      return 0
    fi
    sleep 1
  done
  docker logs "$SVC" > "$OUT/$what.failed.log" 2>&1 || true
  fail "$what started (see $OUT/$what.failed.log)"
  exit 1
}
stop() {
  docker stop -t 30 "$SVC" >/dev/null
  docker logs "$SVC" > "$OUT/$1.log" 2>&1 || true
  docker rm "$SVC" >/dev/null
}

cid="$(docker create "$NODE_IMAGE")"
docker cp "$cid:/usr/src/sts/version.json" "$OUT/version.json" >/dev/null
docker rm "$cid" >/dev/null
chmod 0644 "$OUT/version.json"

say "== Node writes the store =="
start "$NODE_IMAGE" node-writer
if $DRIVER setup "$BASE" "$SECRET" "$OUT/people.json" >> "$SUMMARY" 2>&1
then pass "two people, the second with an authenticator app"
else fail "the people were made (see summary)"; exit 1; fi
$DRIVER begin "$BASE" "$OUT/pending.json" >> "$SUMMARY" 2>&1
pass "two sign-ins begun at /oauth2/authorize"
stop node-writer

browse() {
  local who="$1" label="$2" id user pw secret
  id="$(jq -r ".$who" "$OUT/pending.json")"
  if [ "$who" = pwd ]; then user=e2e.pwd; else user=e2e.totp; fi
  pw="$(jq -r ".\"$user\".password" "$OUT/people.json")"
  secret="$(jq -r ".\"$user\".secret // \"\"" "$OUT/people.json")"
  if $DRIVER browser "$BASE" "$id" "$user" "$pw" $secret \
       > "$OUT/$label-$who.json" 2>> "$SUMMARY"; then
    local cookie location
    cookie="$(jq -r .cookie "$OUT/$label-$who.json")"
    location="$(jq -r .location "$OUT/$label-$who.json")"
    # FINISHED means the bundle left the sign-in pages for the address the
    # answer named — the authorization request it interrupted (Rust serves
    # no /oauth2/authorize yet; Node goes on to the portal's callback) —
    # and the browser holds the session cookie that answer set.
    if [ -n "$cookie" ] &&
       echo "$location" | grep -qE '/oauth2/authorize|/portal/callback\?code='
    then
      pass "$label: $user signed in ($(jq -r '.steps | join(", ")' \
        "$OUT/$label-$who.json")) and holds $(echo "$cookie" | cut -d= -f1)"
    else
      fail "$label: $user did not finish: $(cat "$OUT/$label-$who.json")"
    fi
  else
    fail "$label: the $user sign-in in the browser (see summary)"
  fi
}

say "== Rust on the store Node wrote: the unchanged bundle in Chrome =="
# The enrolment spent this step's code: the next one is the person's next.
sleep 31
start "$RUST_IMAGE" rust
browse pwd rust
browse totp rust

say "== Rust signs the first person out at /logout: the unchanged bundle =="
cookie="$(jq -r .cookie "$OUT/rust-pwd.json" 2>/dev/null || true)"
if [ -n "$cookie" ] && $DRIVER signout "$BASE" "$cookie" \
     > "$OUT/rust-signout.json" 2>> "$SUMMARY"; then
  if [ "$(jq -r .drawn "$OUT/rust-signout.json")" = true ] &&
     [ "$(jq -r .cookieKept "$OUT/rust-signout.json")" = false ]; then
    pass "rust: e2e.pwd signed out ($(jq -r .heading \
      "$OUT/rust-signout.json")), and the browser holds no sts_session"
  else
    fail "rust: the sign-out did not finish: $(cat "$OUT/rust-signout.json")"
  fi
else
  fail "rust: the sign-out in the browser (see summary)"
fi
stop rust

say "== Node reads the sessions Rust set =="
start "$NODE_IMAGE" node-reader
for who in pwd totp; do
  cookie="$(jq -r .cookie "$OUT/rust-$who.json" 2>/dev/null || true)"
  [ -n "$cookie" ] || continue
  got="$($DRIVER honours "$BASE" "$cookie")"
  echo "$got" > "$OUT/honours-$who.json"
  name="$(echo "$got" | jq -r .username)"
  if [ "$who" = pwd ]; then
    # SIGNED OUT AT RUST'S /logout: the old cookie names nobody here.
    if [ "$(echo "$got" | jq -r .status)" = 401 ] && [ -z "$name" ]; then
      pass "Node no longer honours the session Rust signed out (401)"
    else
      fail "Node still honours the session Rust signed out: $got"
    fi
  elif [ "$name" = "e2e.$who" ]; then
    pass "Node honours the session Rust set for $name"
  else
    fail "Node did not honour Rust's session for e2e.$who: $got"
  fi
done

say "== The same two sign-ins against Node =="
$DRIVER begin "$BASE" "$OUT/pending.json" >> "$SUMMARY" 2>&1
sleep 31
browse pwd node
browse totp node
stop node-reader

say "== $( [ "$FAILED" = 0 ] && echo PASSED || echo FAILED ) =="
exit "$FAILED"
