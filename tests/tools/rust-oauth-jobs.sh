#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# File: tests/tools/rust-oauth-jobs.sh
#
# ---------------------------------------------------------------------------
# THE OAUTH PROTOCOL JOBS AGAINST RUST BESIDE NODE (#444, phase 5, the
# `oauth2` slice):
#
#   tests/tools/rust-oauth-jobs.sh <node image> <rust image> <job>... 
#
# Every job sets itself up through /admin-api, which the Rust runtime does
# not serve yet. So each job runs twice:
#
#   1. against NODE alone, on a fresh store — the comparison;
#   2. against RUST, through tests/tools/rust-oauth-proxy.js: Node and Rust
#      on ONE postgres store (each coordinating through its change log), the
#      proxy sending /admin-api to Node and every other path — the
#      authorization endpoint, the token endpoint, discovery, the JWKS, the
#      sign-in screens — to Rust. Both are told the proxy's address as
#      global.publicBaseUrl, so an issuer is one address whichever runtime
#      minted the token.
#
# Product mode, as the jobs' product cells run; E2E_MODE=development runs
# the development cells instead (a sign-in there checks no password, so a
# job that signs a person in reaches the protocol). Writes <out>/summary.txt
# (tests/vectors/rust-oauth-jobs, gitignored). Needs the jobs' packages on
# NODE_PATH (bunyan, commander, node-forge, xml-crypto, @xmldom/xmldom).
# ---------------------------------------------------------------------------
set -euo pipefail

NODE_IMAGE="$1"; RUST_IMAGE="$2"; shift 2
JOBS=("$@")
cd "$(dirname "$0")/../.."
REPO="$PWD"
OUT="${OUT:-tests/vectors/rust-oauth-jobs}"
mkdir -p "$OUT"; OUT="$(cd "$OUT" && pwd)"
TAG="${E2E_TAG:-iya-sts-444-p5-oauth2-jobs}"
MODE="${E2E_MODE:-product}"
PN="${E2E_NODE_PORT:-19771}"; PR="${E2E_RUST_PORT:-19772}"
PP="${E2E_PROXY_PORT:-19773}"
NET="$TAG-net"; DB="$TAG-db"; SVCN="$TAG-node"; SVCR="$TAG-rust"
SUMMARY="$OUT/summary.txt"; : > "$SUMMARY"; FAILED=0
PROXY_PID=""

say() { printf '%s\n' "$*" | tee -a "$SUMMARY"; }
pass() { say "  PASS  $*"; }
fail() { say "  FAIL  $*"; FAILED=1; }

cleanup() {
  [ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null || true
  docker logs "$SVCN" > "$OUT/node.log" 2>&1 || true
  docker logs "$SVCR" > "$OUT/rust.log" 2>&1 || true
  if [ -z "${KEEP:-}" ]; then
    docker rm -f "$SVCN" "$SVCR" "$DB" >/dev/null 2>&1 || true
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
fresh_db() {
docker rm -f "$SVCN" "$SVCR" "$DB" >/dev/null 2>&1 || true
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
}


env_for() {
  printf '%s\n' "CONFIG_FILE=./env/local.js" "STS_MODE=$MODE" \
    "STS_HTTPS=true" "STS_PUBLIC_BASE_URL=$1" \
    "STS_PERSISTENCE_MODE=postgres" "STS_DATABASE_URL=$DB_URL" \
    "STS_DATABASE_TLS_CA_FILE=/run/secrets/db-ca.crt" \
    "STS_PERSISTENCE_COORDINATE=true" "STS_KEYS_SOURCE=persisted" \
    "STS_KEYS_KEK_PROVIDER=file" "STS_KEYS_KEK_FILE=/run/secrets/sts-kek" \
    "STS_SECRETS_ALLOW_LOCAL_SECRETS=true" "STS_CLUSTER_MODE=off" \
    "STS_WORKERS_REQUEST_COUNT=0" "STS_DEBUGGER_ENABLED=off" \
    "STS_CSRF_SECRET=$CSRF" "ADMIN_API_CLIENT_SECRET=$SECRET" \
    > "$OUT/$2.env"
}
run_svc() {
  local name="$1" image="$2" port="$3" envf="$4" extra=()
  if [ "$image" = "$RUST_IMAGE" ]; then
    extra=(-v "$OUT/version.json:/usr/src/sts/version.json:ro")
  fi
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker run -d --name "$name" --hostname sts --network "$NET" \
    -p "127.0.0.1:$port:8081" --env-file "$OUT/$envf.env" "${extra[@]}" \
    -v "$SECRETS/sts-kek:/run/secrets/sts-kek:ro" \
    -v "$SECRETS/server.crt:/run/secrets/db-ca.crt:ro" "$image" >/dev/null
  for _ in $(seq 1 180); do
    if [ "$(curl -sk -o /dev/null -w '%{http_code}' \
           "https://localhost:$port/healthcheck")" = 200 ]; then
      return 0
    fi
    sleep 1
  done
  docker logs "$name" > "$OUT/$name.failed.log" 2>&1 || true
  fail "$name started (see $OUT/$name.failed.log)"; exit 1
}
job() {
  local label="$1" base="$2" file="$3" token
  token="$(STS_ADMIN_API_CLIENT_SECRET=$SECRET \
    node "$REPO/tests/tools/admin-api-token.js" "$base" 2>/dev/null || true)"
  if ( cd "$REPO/tests/protocol" && \
       WSTRUST_STS_URL="$base/sts" OID4VCI_ISSUER_URL="$base" \
       NODE_TLS_REJECT_UNAUTHORIZED=0 CONFIG_FILE=./env/local.js \
       STS_ADMIN_API_TOKEN="$token" STS_MODE="$MODE" \
       NODE_OPTIONS="--require $REPO/tests/tools/attach-admin-token.js" \
       timeout 900 node "$file" ) > "$OUT/$label-${file%.js}.log" 2>&1; then
    pass "$label $file"
  else
    fail "$label $file (tail: $(tail -c 400 "$OUT/$label-${file%.js}.log" \
      | tr '\n' ' '))"
  fi
}

CSRF="$(rand)"
cid="$(docker create "$NODE_IMAGE")"
docker cp "$cid:/usr/src/sts/version.json" "$OUT/version.json" >/dev/null
docker rm "$cid" >/dev/null; chmod 0644 "$OUT/version.json"

say "== Node alone =="
fresh_db
env_for "https://localhost:$PN" node-alone
run_svc "$SVCN" "$NODE_IMAGE" "$PN" node-alone
for j in "${JOBS[@]}"; do job node "https://localhost:$PN" "$j"; done
docker rm -f "$SVCN" >/dev/null

say "== Rust's authorization server, Node's /admin-api, one store =="
fresh_db
env_for "https://localhost:$PP" shared
run_svc "$SVCN" "$NODE_IMAGE" "$PN" shared
run_svc "$SVCR" "$RUST_IMAGE" "$PR" shared
node "$REPO/tests/tools/rust-oauth-proxy.js" "$PP" "https://localhost:$PR" \
  "https://localhost:$PN" > "$OUT/proxy.log" 2>&1 &
PROXY_PID=$!
sleep 2
for j in "${JOBS[@]}"; do job rust "https://localhost:$PP" "$j"; done
kill "$PROXY_PID" 2>/dev/null || true; PROXY_PID=""

say "== $( [ "$FAILED" = 0 ] && echo PASSED || echo FAILED ) =="
exit "$FAILED"
