#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# File: tests/tools/rust-console-e2e.sh
#
# ---------------------------------------------------------------------------
# PHASE 5'S MILESTONE: THE UNCHANGED CONSOLE AND PORTAL BUNDLES SIGN IN
# AGAINST THE RUST RUNTIME, ON A STORE A NODE 1.x SERVICE WROTE (#444, the
# `oauth2` slice; rust-signin-e2e.sh's method).
#
#   tests/tools/rust-console-e2e.sh <node image> <rust image> [out-dir]
#
#   1. postgres:18 with postgres/'s own scripts, TLS on; a KEK in a file.
#   2. NODE, product mode, writes the store: the bootstrap administrator's
#      first sign-in (its password changed, an authenticator app enrolled,
#      as product asks) and a person's, at /authn-api.
#   3. RUST on the same store. Headless Chrome opens /admin and signs the
#      administrator in at the screen the console sends it to, then /portal
#      for the person: the code flow, PKCE, `resource`, DPoP. What the page
#      then asks of its API is recorded with each status.
#   4. The same two against Node, for the comparison.
#
# Writes <out-dir> (default tests/vectors/rust-console-e2e, gitignored).
# Needs google-chrome on the host and NODE_PATH holding `ws`.
# ---------------------------------------------------------------------------
set -euo pipefail

NODE_IMAGE="$1"
RUST_IMAGE="$2"
cd "$(dirname "$0")/../.."
REPO="$PWD"
OUT="${3:-tests/vectors/rust-console-e2e}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
TAG="${E2E_TAG:-iya-sts-444-p5-oauth2-e2e}"
PORT="${E2E_PORT:-19763}"
NET="$TAG-net"
DB="$TAG-db"
SVC="$TAG-svc"
BASE="https://localhost:$PORT"
SUMMARY="$OUT/summary.txt"
: > "$SUMMARY"
FAILED=0
DRIVER="node $REPO/tests/tools/rust-console-e2e.js"

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
ADMIN_PW="Boot-$(rand)-9q"
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
  "ADMIN_API_CLIENT_SECRET=$SECRET" \
  "STS_ADMIN_BOOTSTRAP_PASSWORD=$ADMIN_PW" > "$OUT/service.env"

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
if $DRIVER setup "$BASE" "$SECRET" "$ADMIN_PW" "$OUT/people.json" \
     >> "$SUMMARY" 2>&1
then pass "the administrator and a person signed in once on Node"
else fail "the people were made (see summary)"; exit 1; fi
stop node-writer

surface() {
  local label="$1" path="$2" user="$3" pw secret
  pw="$(jq -r ".\"$user\".password" "$OUT/people.json")"
  secret="$(jq -r ".\"$user\".secret // \"\"" "$OUT/people.json")"
  if $DRIVER surface "$BASE" "$path" "$user" "$pw" "$secret" \
       > "$OUT/$label-${path#/}.json" 2>> "$SUMMARY"; then
    local got
    got="$OUT/$label-${path#/}.json"
    if jq -e '.calls | map(select(.url == "/oauth2/token" and .status == 200
                                  and .answer.token_type == "DPoP"))
              | length > 0' "$got" >/dev/null; then
      pass "$label $path: $user signed in ($(jq -r '.steps | join(", ")' \
        "$got")); a DPoP-bound token for $(jq -r '[.calls[] |
        select(.url == "/oauth2/token") | .answer.aud][0]' "$got"), \
        refresh $(jq -r '[.calls[] | select(.url == "/oauth2/token") |
        .answer.refresh][0]' "$got"); then $(jq -r '[.calls[] |
        select(.url | test("-api/")) | "\(.url) \(.status)"] | unique |
        join("; ")' "$got")"
    else
      fail "$label $path: no DPoP-bound token: $(cat "$got")"
    fi
  else
    fail "$label $path: the browser run (see summary)"
  fi
}

say "== Rust on the store Node wrote: the unchanged bundles in Chrome =="
sleep 31
start "$RUST_IMAGE" rust
surface rust /admin admin
sleep 31
surface rust /portal e2e.ann
stop rust

say "== The same two against Node =="
start "$NODE_IMAGE" node-reader
sleep 31
surface node /admin admin
sleep 31
surface node /portal e2e.ann
stop node-reader

say "== $( [ "$FAILED" = 0 ] && echo PASSED || echo FAILED ) =="
exit "$FAILED"
