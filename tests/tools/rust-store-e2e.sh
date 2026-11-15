#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# File: tests/tools/rust-store-e2e.sh
#
# ---------------------------------------------------------------------------
# PHASE 3'S END-TO-END CHECK: THE RUST RUNTIME OPENS A STORE A NODE 1.x
# SERVICE WROTE (#444, rust/DESIGN.md section 3, D11).
#
#   tests/tools/rust-store-e2e.sh <postgres|mariadb> <node image> \
#       <rust image> <tests image> [out-dir]
#
# Nothing here is a compose stack: every container is started by name, on a
# network of its own, and removed at the end (KEEP=1 leaves them for a
# look). The images must carry no compose label.
#
#   1. A database server (postgres:18 with postgres/'s own scripts, or
#      mariadb:11.8 with mariadb/schema.sql), TLS on, the schema built by
#      its owner and the application account the service dials with.
#   2. A key-encryption key in a file, made here, mounted read-only.
#   3. NODE, in product mode on that store, writes a real one through
#      /admin-api: the realms `acme` and `diff`, a process-wide setting and
#      a realm setting, a person and an application in `acme`; its two
#      JWKS documents are kept. Then it is stopped (SIGTERM: the last flush,
#      the origin released).
#   4. The store is copied for the comparison below (`sts_node`): Node and
#      Rust are never on one store at once — there is no coexistence.
#   5. RUST, from rust/Dockerfile, on the SAME store, KEK and appconfig and
#      under the same host name (so the same stable origin): it must open
#      the store, adopt the origin, read the KEK, restore the realms and
#      the settings, and serve the shells, /web, /healthcheck and the two
#      JWKS documents — the same keys Node published — over HTTPS.
#   6. NODE again, on the copy, and tests/tools/http-differential.js and
#      tests/tools/tls-handshake-compare.sh between the two.
#   7. What Rust does not serve yet (a family route, a sign-in) is LISTED
#      with the status it answered, never failed.
#
# Writes <out-dir> (default tests/vectors/rust-e2e-<engine>, gitignored):
# each container's log, the two JWKS pairs, the differential report, the
# handshake diff and summary.txt. Exits 1 when a check fails.
# ---------------------------------------------------------------------------
set -euo pipefail

if [ "$#" -lt 4 ]; then
  sed -n '9,11p' "$0" >&2
  exit 2
fi
ENGINE="$1"
NODE_IMAGE="$2"
RUST_IMAGE="$3"
TESTS_IMAGE="$4"
cd "$(dirname "$0")/../.."
REPO="$PWD"
OUT="${5:-tests/vectors/rust-e2e-$ENGINE}"
case "$ENGINE" in
  postgres|mariadb) ;;
  *) echo "the engine is postgres or mariadb, not '$ENGINE'" >&2; exit 2 ;;
esac
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
TAG="${E2E_TAG:-iya-sts-444-p3-wiring-e2e-$ENGINE}"
NODE_PORT="${E2E_NODE_PORT:-19711}"
RUST_PORT="${E2E_RUST_PORT:-19712}"
NET="$TAG-net"
DB="$TAG-db"
NODE="$TAG-node"
RUST="$TAG-rust"
BASE="https://localhost:$NODE_PORT"
SUMMARY="$OUT/summary.txt"
: > "$SUMMARY"
FAILED=0

for img in "$NODE_IMAGE" "$RUST_IMAGE" "$TESTS_IMAGE"; do
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
check() {
  local what="$1"; shift
  if "$@"; then pass "$what"; else fail "$what"; fi
}

cleanup() {
  for c in "$NODE" "$RUST"; do
    docker logs "$c" > "$OUT/$c.last.log" 2>&1 || true
  done
  if [ -z "${KEEP:-}" ]; then
    docker rm -f "$NODE" "$RUST" "$DB" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

rand() { openssl rand -hex 24; }
APP_PW="$(rand)"
OWNER_PW="$(rand)"
SECRET="$(rand)"
SECRETS="$OUT/secrets"
mkdir -p "$SECRETS"
# The KEK: 32 random bytes, base64, as keys.kekFile documents it. Readable
# by the containers' uid 10001 (a key readable by others is REPORTED, not
# refused); it never leaves the out-dir, which is gitignored.
rm -f "$SECRETS/sts-kek"
openssl rand -base64 32 > "$SECRETS/sts-kek"
chmod 0444 "$SECRETS/sts-kek"

docker rm -f "$NODE" "$RUST" "$DB" >/dev/null 2>&1 || true
docker network rm "$NET" >/dev/null 2>&1 || true
docker network create "$NET" >/dev/null

# ---------------------------------------------------------------------------
# 1. The database.
# ---------------------------------------------------------------------------
say "== $ENGINE: the database =="
if [ "$ENGINE" = postgres ]; then
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
      '-c ssl_key_file=/var/lib/postgresql/tls/server.key')" \
    >/dev/null
  ready=""
  for _ in $(seq 1 120); do
    if docker exec "$DB" pg_isready -h 127.0.0.1 -U sts -d sts \
         >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 1
  done
  if [ -z "$ready" ]; then
    docker logs "$DB" > "$OUT/db.failed.log" 2>&1 || true
    fail "the postgres server came up (see $OUT/db.failed.log)"
    exit 1
  fi
  rm -f "$SECRETS/server.crt"
  docker cp "$DB:/var/lib/postgresql/tls/server.crt" "$SECRETS/server.crt"
  chmod 0644 "$SECRETS/server.crt"
  DB_URL="postgres://sts_app:$APP_PW@db:5432/sts?sslmode=verify-full"
  COPY_URL="postgres://sts_app:$APP_PW@db:5432/sts_node?sslmode=verify-full"
else
  rm -f "$SECRETS/server.key" "$SECRETS/server.crt"
  openssl req -new -x509 -nodes -newkey rsa:2048 -sha256 -days 2 \
    -subj "/CN=db/O=iya-sts" -addext "subjectAltName=DNS:db,DNS:localhost" \
    -keyout "$SECRETS/server.key" -out "$SECRETS/server.crt" 2>/dev/null
  chmod 0644 "$SECRETS/server.key" "$SECRETS/server.crt"
  docker run -d --name "$DB" --network "$NET" --network-alias db \
    -e MARIADB_ROOT_PASSWORD="$OWNER_PW" -e MARIADB_ROOT_HOST=% \
    -v "$SECRETS/server.crt:/tls/server.crt:ro" \
    -v "$SECRETS/server.key:/tls/server.key:ro" \
    mariadb:11.8 --ssl-cert=/tls/server.crt --ssl-key=/tls/server.key \
    --require-secure-transport=ON --innodb-buffer-pool-size=128M \
    --performance-schema=OFF >/dev/null
  ready=""
  for _ in $(seq 1 120); do
    if docker exec "$DB" healthcheck.sh --connect --innodb_initialized \
         >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 1
  done
  if [ -z "$ready" ]; then
    docker logs "$DB" > "$OUT/db.failed.log" 2>&1 || true
    fail "the mariadb server came up (see $OUT/db.failed.log)"
    exit 1
  fi
  maria() { docker exec -i "$DB" mariadb -uroot -p"$OWNER_PW" "$@"; }
  for d in sts_store sts_node; do
    maria -e "CREATE DATABASE IF NOT EXISTS $d"
    maria --init-command="SET @sts_app_password='$APP_PW'" "$d" \
      < mariadb/schema.sql
  done
  DB_URL="mariadb://sts_app:$APP_PW@db:3306/sts_store"
  COPY_URL="mariadb://sts_app:$APP_PW@db:3306/sts_node"
fi
pass "the $ENGINE server is up, the schema built"

# What both runtimes are given: the same appconfig (the image's
# env/local.js), the same KEK, the same store, the same public base URL,
# and the database's certificate as its trust anchor — product mode
# verifies the database whatever databaseTlsRejectUnauthorized says.
service_env() {
  local url="$1"
  printf '%s\n' \
    "CONFIG_FILE=./env/local.js" \
    "STS_MODE=product" \
    "STS_HTTPS=true" \
    "STS_PUBLIC_BASE_URL=$BASE" \
    "STS_PERSISTENCE_MODE=$ENGINE" \
    "STS_DATABASE_URL=$url" \
    "STS_DATABASE_TLS_CA_FILE=/run/secrets/db-ca.crt" \
    "STS_PERSISTENCE_COORDINATE=true" \
    "STS_KEYS_SOURCE=persisted" \
    "STS_KEYS_KEK_PROVIDER=file" \
    "STS_KEYS_KEK_FILE=/run/secrets/sts-kek" \
    "STS_SECRETS_ALLOW_LOCAL_SECRETS=true" \
    "STS_CLUSTER_MODE=off" \
    "STS_WORKERS_REQUEST_COUNT=0" \
    "STS_DEBUGGER_ENABLED=off" \
    "ADMIN_API_CLIENT_SECRET=$SECRET"
}

start() {
  local name="$1" image="$2" port="$3" url="$4"
  service_env "$url" > "$OUT/$name.env"
  local extra=()
  if [ "$image" = "$RUST_IMAGE" ]; then
    extra=(-v "$OUT/version.json:/usr/src/sts/version.json:ro")
  fi
  docker run -d --name "$name" --hostname sts --network "$NET" \
    -p "127.0.0.1:$port:8081" --env-file "$OUT/$name.env" "${extra[@]}" \
    -v "$SECRETS/sts-kek:/run/secrets/sts-kek:ro" \
    -v "$SECRETS/server.crt:/run/secrets/db-ca.crt:ro" "$image" >/dev/null
  for _ in $(seq 1 180); do
    if [ "$(curl -sk -o /dev/null -w '%{http_code}' \
             "https://localhost:$port/healthcheck")" = 200 ]; then
      return 0
    fi
    if [ "$(docker inspect -f '{{.State.Running}}' "$name")" != true ]; then
      break
    fi
    sleep 1
  done
  docker logs "$name" > "$OUT/$name.failed.log" 2>&1 || true
  return 1
}

# ---------------------------------------------------------------------------
# 3. Node writes a real store.
# ---------------------------------------------------------------------------
say "== Node writes the store =="
if ! start "$NODE" "$NODE_IMAGE" "$NODE_PORT" "$DB_URL"; then
  fail "Node started (see $OUT/$NODE.failed.log)"
  exit 1
fi
pass "Node is serving on $NODE_PORT"
token() {
  curl -sk -u "sts-api-client:$SECRET" \
    --data-urlencode grant_type=client_credentials \
    --data-urlencode "scope=admin:read admin:write" \
    --data-urlencode "resource=$BASE/admin-api" \
    "https://localhost:$NODE_PORT/oauth2/token" | jq -r '.access_token // ""'
}
TOKEN="$(token)"
[ -n "$TOKEN" ] || { fail "a /admin-api token from Node"; exit 1; }
api() {
  local path="$1" body="$2"
  curl -sk -o "$OUT/last-api.json" -w '%{http_code}' \
    -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
    -d "$body" "https://localhost:$NODE_PORT$path"
}
ok_api() {
  local what="$1" path="$2" body="$3"
  local status
  status="$(api "$path" "$body")"
  if [ "$status" = 200 ]; then
    pass "$what"
  else
    fail "$what: $status $(head -c 300 "$OUT/last-api.json")"
  fi
}
ok_api "realm acme created" /admin-api/realms/create \
  '{"id":"acme","domain":"acme.example.net","name":"Acme"}'
ok_api "realm diff created (the differential's realm)" \
  /admin-api/realms/create \
  '{"id":"diff","domain":"diff.example.net","name":"Differential"}'
ok_api "a process-wide setting (branding.displayName)" /admin-api/config/set \
  '{"key":"branding.displayName","value":"Iya E2E"}'
ok_api "a realm setting (acme's branding.accentColor)" \
  /realm/acme/admin-api/config/set \
  '{"key":"branding.accentColor","value":"#0b5d1e"}'
ok_api "a person in acme" /realm/acme/admin-api/users/create \
  '{"username":"e2e.person","invent":false,"credential":"password",
    "password":"Correct-Horse-Battery-9","attributes":{"cn":"E2E Person",
    "givenName":"E2E","sn":"Person","mail":"e2e.person@acme.example.net"}}'
ok_api "an application in acme" /realm/acme/admin-api/applications/create \
  '{"identifier":"e2e-app","name":"E2E app","protocols":["oauth2","oidc"],
    "fields":{"oauthClientId":"e2e-app",
    "oauthRedirectUri":["https://app.example.net/cb"],
    "oauthTokenEndpointAuthMethod":"none",
    "oauthGrantType":["authorization_code"],"oauthScope":["openid"]}}'
for r in "" /realm/acme; do
  n="$(basename "${r:-default}")"
  curl -sk "https://localhost:$NODE_PORT$r/oauth2/jwks" > "$OUT/jwks-$n-node.json"
  curl -sk "https://localhost:$NODE_PORT$r/web/theme.css" > "$OUT/theme-$n-node.css"
done
check "Node published acme's accent colour" \
  grep -q '#0b5d1e' "$OUT/theme-acme-node.css"
docker stop -t 30 "$NODE" >/dev/null
docker logs "$NODE" > "$OUT/node-writer.log" 2>&1
docker rm "$NODE" >/dev/null
check "Node stopped cleanly (its store flushed and closed)" \
  grep -q 'store was flushed and closed' "$OUT/node-writer.log"

# ---------------------------------------------------------------------------
# 4. The copy Node is run on for the comparison.
# ---------------------------------------------------------------------------
if [ "$ENGINE" = postgres ]; then
  docker exec "$DB" psql -q -U sts -d postgres -v ON_ERROR_STOP=1 \
    -c "CREATE DATABASE sts_node TEMPLATE sts" \
    -c "ALTER DATABASE sts_node SET search_path = sts, public" \
    -c "GRANT CONNECT ON DATABASE sts_node TO sts_app" >/dev/null
else
  docker exec "$DB" sh -c "mariadb-dump -uroot -p'$OWNER_PW' \
    --single-transaction --no-create-info --skip-triggers sts_store \
    | mariadb -uroot -p'$OWNER_PW' sts_node"
fi
pass "the store copied for the comparison (sts_node)"

# THE SAME BUILD: the shells, the catalogs and the footer name the build
# (`version.json`: the version, the commit and the build INSTANT), which no
# two image builds share. Rust is given the Node image's, so a difference
# below is a difference of what the two serve, not of when they were built.
cid="$(docker create "$NODE_IMAGE")"
docker cp "$cid:/usr/src/sts/version.json" "$OUT/version.json" >/dev/null
docker rm "$cid" >/dev/null
chmod 0644 "$OUT/version.json"

# ---------------------------------------------------------------------------
# 5. Rust on the store Node wrote.
# ---------------------------------------------------------------------------
say "== Rust opens the store Node wrote =="
if ! start "$RUST" "$RUST_IMAGE" "$RUST_PORT" "$DB_URL"; then
  fail "Rust started (see $OUT/$RUST.failed.log)"
  exit 1
fi
pass "Rust is serving HTTPS on $RUST_PORT"
docker logs "$RUST" > "$OUT/rust.log" 2>&1
LOG="$OUT/rust.log"
check "opened the $ENGINE store and restored the realms and settings" \
  grep -qE "persistence: $ENGINE store open; restored [0-9]+ directory entry/entries, [2-9][0-9]* defined realm\(s\) and [1-9][0-9]* appconfig override" "$LOG"
check "adopted the origin Node wrote under (sts:front)" \
  grep -qE 'writes as origin n:sts:front' "$LOG"
check "read the KEK and checked every stored key set" \
  grep -qE 'keystore: [3-9][0-9]* realm key set\(s\) read from the store and checked' "$LOG"
check "coordinates through the change log" \
  grep -q 'coordinating with other processes against this store' "$LOG"
rust_get() {
  curl -sk -o "$2" -w '%{http_code}' "https://localhost:$RUST_PORT$1"
}
for p in /healthcheck / /admin /portal /report /web/card.css \
         /realm/acme/admin /realm/acme/portal; do
  status="$(rust_get "$p" "$OUT/body")"
  if [ "$status" = 200 ]; then pass "GET $p is 200"; else
    fail "GET $p is $status"; fi
done
status="$(rust_get /realm/nope/admin "$OUT/body")"
check "an undefined realm is the ordinary 404" [ "$status" = 404 ]
for r in "" /realm/acme; do
  n="$(basename "${r:-default}")"
  rust_get "$r/oauth2/jwks" "$OUT/jwks-$n-rust.json" >/dev/null
  rust_get "$r/web/theme.css" "$OUT/theme-$n-rust.css" >/dev/null
  # THE SAME KEYS: every key Node published, its id and its public
  # members, is one Rust publishes — read from the store, opened under the
  # KEK. What the DOCUMENT holds besides (which algorithms the signing
  # policy publishes, the x5c chain) is the OAuth phase's, and is listed.
  check "the $n realm's JWKS carries the key set Node made" \
    jq -e -n --slurpfile a "$OUT/jwks-$n-node.json" \
      --slurpfile b "$OUT/jwks-$n-rust.json" \
      '[$a[0].keys[] | {kid, kty, crv, n, e, x, y, pub}]
       - [$b[0].keys[] | {kid, kty, crv, n, e, x, y, pub}] | length == 0' \
      >/dev/null
  if ! cmp -s "$OUT/jwks-$n-node.json" "$OUT/jwks-$n-rust.json"; then
    say "  NOT YET  the $n JWKS document as the signing policy draws it:" \
      "$(jq -n -r --slurpfile a "$OUT/jwks-$n-node.json" \
          --slurpfile b "$OUT/jwks-$n-rust.json" \
          '([$b[0].keys[].kid] - [$a[0].keys[].kid]) as $extra
           | ([$a[0].keys[] | {kid, c: (.x5c // [] | length)}]
              - [$b[0].keys[] | {kid, c: (.x5c // [] | length)}]) as $x5c
           | "Rust also publishes \($extra | join(", "));"
             + " x5c differs for \([$x5c[].kid] | join(", "))"')"
  fi
  check "the $n realm's /web/theme.css is Node's" \
    cmp -s "$OUT/theme-$n-node.css" "$OUT/theme-$n-rust.css"
done
check "acme's restored accent colour is served" \
  grep -q '#0b5d1e' "$OUT/theme-acme-rust.css"

say "== What Rust does not serve yet (listed, not failed) =="
for p in "GET /.well-known/openid-configuration" "POST /oauth2/token" \
         "GET /authn/login" "GET /admin-api/status" "GET /realm/acme/scim/v2/Users" \
         "GET /home-api/front"; do
  m="${p%% *}"; path="${p#* }"
  status="$(curl -sk -X "$m" -o /dev/null -w '%{http_code}' \
    "https://localhost:$RUST_PORT$path")"
  say "  NOT YET  $p -> $status"
done

# ---------------------------------------------------------------------------
# 6. Node again, on the copy, and the two compared.
# ---------------------------------------------------------------------------
say "== Node and Rust compared =="
if ! start "$NODE" "$NODE_IMAGE" "$NODE_PORT" "$COPY_URL"; then
  fail "Node started again on the copy (see $OUT/$NODE.failed.log)"
  exit 1
fi
pass "Node is serving the copy on $NODE_PORT"
# The harness as this checkout has it, over the image's copy.
if docker run --rm --network host -v "$OUT:/out" \
     -v "$REPO/tests/tools/http-differential.js:/usr/src/sts/tests/tools/http-differential.js:ro" \
     "$TESTS_IMAGE" \
     node tests/tools/http-differential.js --node "$BASE" \
     --rust "https://localhost:$RUST_PORT" --admin-secret "$SECRET" \
     --report /out/http-differential-report.json \
     > "$OUT/http-differential.txt" 2>&1; then
  pass "http-differential: $(head -1 "$OUT/http-differential.txt")"
else
  fail "http-differential: $(grep -m1 '^http-differential' "$OUT/http-differential.txt" || tail -1 "$OUT/http-differential.txt")"
fi
if tests/tools/tls-handshake-compare.sh "$TESTS_IMAGE" \
     "localhost:$NODE_PORT" "localhost:$RUST_PORT" "$OUT/tls" \
     > "$OUT/tls-compare.txt" 2>&1; then
  pass "tls-handshake-compare: the two listeners answered alike"
else
  fail "tls-handshake-compare: see $OUT/tls/diff.txt"
fi
docker logs "$RUST" > "$OUT/rust.log" 2>&1

# Rust stops as Node does: the last flush, the origin released.
docker stop -t 30 "$RUST" >/dev/null
docker logs "$RUST" > "$OUT/rust.log" 2>&1
check "Rust stopped and closed the store without an error" \
  bash -c "! grep -q 'STS-STORE-0001' '$OUT/rust.log'"

say "== $ENGINE: $( [ "$FAILED" = 0 ] && echo PASSED || echo FAILED ) =="
exit "$FAILED"
