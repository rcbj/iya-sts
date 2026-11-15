#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# File: tests/tools/rust-apis-jobs.sh
#
# ---------------------------------------------------------------------------
# PROTOCOL JOBS AGAINST RUST'S OWN /admin-api, BESIDE NODE (#444, phase 5,
# the `apis` slice):
#
#   tests/tools/rust-apis-jobs.sh <node image> <rust image> <job>...
#
# Each job runs twice, each time on a fresh postgres store:
#
#   1. against NODE alone — the comparison;
#   2. against RUST alone: Node is started first on the store only to seed
#      what a 1.x install holds (the management API's client and its
#      secret, the key sets, the certificate authority), then stopped, and
#      the Rust runtime is started on that store, so every request the job
#      makes — its set-up through /admin-api included — is Rust's.
#
# Product mode, as the jobs' product cells run; E2E_MODE=development runs
# both halves in development instead (the `apis4` slice), as
# rust-oauth-jobs.sh does. Writes <out>/summary.txt
# (tests/vectors/rust-apis-jobs, gitignored). Needs the jobs' packages on
# NODE_PATH.
#
# SEED=1 (the `apis4` slice): in each half, after the jobs, a realm is
# created through that half's own /admin-api (`seed-diff`), and its whole
# directory (GET /admin-api/ldap/directory), its groups and its
# applications' rows are read and held to each other, member by member,
# less what is minted at the instant (the timestamps, a random entryUUID,
# the registration's issue time and tokens, the sealed and masked
# values).
# ---------------------------------------------------------------------------
set -euo pipefail

NODE_IMAGE="$1"; RUST_IMAGE="$2"; shift 2
JOBS=("$@")
cd "$(dirname "$0")/../.."
REPO="$PWD"
OUT="${OUT:-tests/vectors/rust-apis-jobs}"
mkdir -p "$OUT"; OUT="$(cd "$OUT" && pwd)"
TAG="${E2E_TAG:-iya-sts-444-p5-apis-jobs}"
PN="${E2E_NODE_PORT:-19781}"; PR="${E2E_RUST_PORT:-19782}"
NET="$TAG-net"; DB="$TAG-db"; SVCN="$TAG-node"; SVCR="$TAG-rust"
SUMMARY="$OUT/summary.txt"; : > "$SUMMARY"; FAILED=0
MODE="${E2E_MODE:-product}"

say() { printf '%s\n' "$*" | tee -a "$SUMMARY"; }
pass() { say "  PASS  $*"; }
fail() { say "  FAIL  $*"; FAILED=1; }

cleanup() {
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
# JOB_IMAGE: run each job inside that image (a tests image under this
# slice's tag, whose node and packages are the jobs' own) on the host's
# network, with this worktree's tests/protocol mounted over its own;
# without it, the host's node and NODE_PATH.
job() {
  local label="$1" base="$2" file="$3" token
  if [ -n "${JOB_IMAGE:-}" ]; then
    token="$(docker run --rm --network host \
      -e STS_ADMIN_API_CLIENT_SECRET="$SECRET" -e NODE_TLS_REJECT_UNAUTHORIZED=0 \
      "$JOB_IMAGE" node tests/tools/admin-api-token.js "$base" 2>/dev/null \
      || true)"
    if docker run --rm --network host \
         -v "$REPO/tests/protocol:/usr/src/sts/tests/protocol:ro" \
         -w /usr/src/sts/tests/protocol \
         -e WSTRUST_STS_URL="$base/sts" -e OID4VCI_ISSUER_URL="$base" \
         -e NODE_TLS_REJECT_UNAUTHORIZED=0 -e CONFIG_FILE=./env/local.js \
         -e STS_ADMIN_API_TOKEN="$token" -e STS_MODE="$MODE" \
         -e NODE_OPTIONS="--require /usr/src/sts/tests/tools/attach-admin-token.js" \
         "$JOB_IMAGE" timeout 900 node "$file" \
         > "$OUT/$label-${file%.js}.log" 2>&1; then
      pass "$label $file"
    else
      fail "$label $file (tail: $(tail -c 400 "$OUT/$label-${file%.js}.log" \
        | tr '\n' ' '))"
    fi
    return 0
  fi
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

# VIEWS=1 (the `apis2` slice): after the Node-alone jobs, every realm's
# certificate authority and enrollment views are read from Node, Node is
# stopped, the Rust runtime is started on THAT store under the same base
# URL, and the same views are read from it and held to Node's, member for
# member. `since` and `processes` are left out: they say when and in how
# many processes the counters were kept, which a restart changes.
VIEWS_READ=(${VIEWS_LIST:-pki acme acme/monitor est est/monitor scep scep/monitor groups})
# The `apis3` slice: every group's drill-down is read too (the first ten of
# each realm), its two members not yet ported in Rust left out of both
# sides — `policyReferences` (no policy kind declares a group reference in
# that runtime yet) and `ownership`.
VIEWS_DETAIL_DEL='del(.since, .processes, .policyReferences, .ownership)'

read_views() {
  # `head` closing a pipe is not a failure here.
  set +o pipefail
  local label="$1" base="$2" token dir="$OUT/views-$1"
  rm -rf "$dir"; mkdir -p "$dir"
  token="$(docker run --rm --network host \
    -e STS_ADMIN_API_CLIENT_SECRET="$SECRET" -e NODE_TLS_REJECT_UNAUTHORIZED=0 \
    "$JOB_IMAGE" node tests/tools/admin-api-token.js "$base" 2>/dev/null)"
  curl -sk -H "Authorization: Bearer $token" "$base/admin-api/realms?per=300" \
    | jq -r '.realms[] | (.pathPrefix // "")' > "$dir/realms.txt"
  while read -r prefix; do
    for v in "${VIEWS_READ[@]}"; do
      curl -sk -o "$dir/raw" -w '%{http_code}' \
        -H "Authorization: Bearer $token" \
        "$base$prefix/admin-api/$v?per=100" > "$dir/status"
      jq -S 'del(.since, .processes)' "$dir/raw" \
        > "$dir/$(echo "${prefix:-/default}$v" | tr '/' '_').json" \
        2>/dev/null || cp "$dir/raw" "$dir/$(echo "${prefix:-/default}$v" \
        | tr '/' '_').json"
      printf '%s %s\n' "$(cat "$dir/status")" "${prefix:-}/$v" \
        >> "$dir/statuses.txt"
    done
    if [ -s "$dir/$(echo "${prefix:-/default}groups" | tr '/' '_').json" ]; then
      jq -r '.groups[]?.dn' \
        "$dir/$(echo "${prefix:-/default}groups" | tr '/' '_').json" \
        2>/dev/null | head -10 | while read -r gdn; do
        enc="$(jq -rn --arg v "$gdn" '$v|@uri')"
        curl -sk -o "$dir/raw" -H "Authorization: Bearer $token" \
          "$base$prefix/admin-api/groups?group=$enc"
        jq -S "$VIEWS_DETAIL_DEL" "$dir/raw" > "$dir/$(echo \
          "${prefix:-/default}group-$gdn" | tr '/,= ' '____').json" \
          2>/dev/null || true
      done
    fi
    # One person's drill-down, for the members Rust ports
    # (`GET /admin-api/users?user=`): the first five people the realm's
    # groups list. The register row's artifacts are not counted in Rust.
    cat "$dir"/$(echo "${prefix:-/default}group-" | tr '/,= ' '____')*.json \
      2>/dev/null | jq -r '.group.members[]?.userKey // empty' 2>/dev/null \
      | sort -u | head -5 | while read -r who; do
      enc="$(jq -rn --arg v "$who" '$v|@uri')"
      curl -sk -o "$dir/raw" -H "Authorization: Bearer $token" \
        "$base$prefix/admin-api/users?user=$enc"
      jq -S '{known, subject, ldap, user: (.user | if type == "object"
               then del(.artifacts, .artifactKinds, .lastActivityAt)
               else . end)}' "$dir/raw" > "$dir/$(echo \
        "${prefix:-/default}user-$who" | tr '/,= ' '____').json" \
        2>/dev/null || true
    done
  done < "$dir/realms.txt"
  rm -f "$dir/raw" "$dir/status"
  set -o pipefail
}

# The realm a half creates for SEED=1, read back as that half answers it.
SEED_DEL='del(.. | objects | .createTimestamp?, .modifyTimestamp?,
  .createdAt?, .modifiedAt?,
  .appFirstSeen?, .appLastSeen?, .appRegistrationJson?,
  .appRegistrationAccessToken?, .oauthClientSecret?, .pwdChangedTime?,
  .stsBootstrapAdministrator?, .pwdReset?, .userPassword?)'
read_seed() {
  set +o pipefail
  local label="$1" base="$2" token dir="$OUT/seed-$1" id="seed-diff"
  rm -rf "$dir"; mkdir -p "$dir"
  token="$(docker run --rm --network host \
    -e STS_ADMIN_API_CLIENT_SECRET="$SECRET" -e NODE_TLS_REJECT_UNAUTHORIZED=0 \
    "$JOB_IMAGE" node tests/tools/admin-api-token.js "$base" 2>/dev/null)"
  curl -sk -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
    -d "{\"id\":\"$id\"}" "$base/admin-api/realms/create" \
    | sed "s#${base#https://}#localhost:PORT#g" \
    | jq -S 'del(.password)' > "$dir/create.json"
  curl -sk -H "Authorization: Bearer $token" \
    "$base/realm/$id/admin-api/ldap/directory?per=300" \
    | sed "s#${base#https://}#localhost:PORT#g" > "$dir/raw"
  # An application's entryUUID is random; a seeded entry's is derived
  # from the realm and the DN, and is kept.
  jq -S "$SEED_DEL | .entries |= map(if (.origin == \"seed\" or
           .origin == \"roles\") then . else
           del(.attributes.entryUUID) end)" "$dir/raw" \
    > "$dir/directory.json" 2>/dev/null || cp "$dir/raw" "$dir/directory.json"
  curl -sk -H "Authorization: Bearer $token" \
    "$base/realm/$id/admin-api/groups?per=100" \
    | sed "s#${base#https://}#localhost:PORT#g" \
    | jq -S "del(.since, .processes) | $SEED_DEL" > "$dir/groups.json"
  rm -f "$dir/raw"
  set -o pipefail
}
compare_seed() {
  for f in "$OUT"/seed-node/*.json; do
    one="$(basename "$f")"
    if diff -q "$f" "$OUT/seed-rust/$one" >/dev/null 2>&1; then
      pass "a realm Rust created is the realm Node created: $one"
    else
      fail "a realm Rust created differs from Node's: $one" \
        "($(diff <(jq -c 'paths(scalars) as $p | [$p, getpath($p)]' "$f" \
        2>/dev/null) <(jq -c 'paths(scalars) as $p | [$p, getpath($p)]' \
        "$OUT/seed-rust/$one" 2>/dev/null) | grep -c '^[<>]') leaf diff(s))"
    fi
  done
}

say "== Node alone =="
fresh_db
env_for "https://localhost:$PN" node-alone
run_svc "$SVCN" "$NODE_IMAGE" "$PN" node-alone
for j in "${JOBS[@]}"; do job node "https://localhost:$PN" "$j"; done
if [ -n "${SEED:-}" ]; then read_seed node "https://localhost:$PN"; fi
if [ -n "${VIEWS:-}" ]; then
  read_views node "https://localhost:$PN"
  docker stop -t 30 "$SVCN" >/dev/null; docker rm "$SVCN" >/dev/null
  run_svc "$SVCR" "$RUST_IMAGE" "$PN" node-alone
  read_views rust "https://localhost:$PN"
  docker rm -f "$SVCR" >/dev/null
  for f in "$OUT"/views-node/*.json; do
    one="$(basename "$f")"
    if diff -q "$f" "$OUT/views-rust/$one" >/dev/null 2>&1; then
      pass "the same view from Rust on Node's store: $one"
    else
      fail "the view differs from Rust on Node's store: $one" \
        "($(diff <(jq -c 'paths(scalars) as $p | [$p, getpath($p)]' "$f" \
        2>/dev/null) <(jq -c 'paths(scalars) as $p | [$p, getpath($p)]' \
        "$OUT/views-rust/$one" 2>/dev/null) | grep -c '^[<>]') leaf diff(s))"
    fi
  done
else
  docker rm -f "$SVCN" >/dev/null
fi

say "== Rust's /admin-api on a store Node seeded =="
fresh_db
env_for "https://localhost:$PR" shared
run_svc "$SVCN" "$NODE_IMAGE" "$PR" shared
docker stop -t 30 "$SVCN" >/dev/null; docker rm "$SVCN" >/dev/null
run_svc "$SVCR" "$RUST_IMAGE" "$PR" shared
for j in "${JOBS[@]}"; do job rust "https://localhost:$PR" "$j"; done
if [ -n "${SEED:-}" ]; then
  read_seed rust "https://localhost:$PR"
  compare_seed
fi

say "== $( [ "$FAILED" = 0 ] && echo PASSED || echo FAILED ) =="
exit "$FAILED"
