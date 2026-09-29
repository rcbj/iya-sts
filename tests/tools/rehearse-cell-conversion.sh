#!/bin/bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# File: tests/tools/rehearse-cell-conversion.sh
#
# ===========================================================================
# A LOCAL REHEARSAL OF THE ONE-TIME CONVERSION OF A SINGLE-CELL STORE INTO A
# CELL (#98, persistence/cell_convert.js) AGAINST REAL POSTGRESQL — above all
# that the risk scoring history survives it.
#
#   tests/tools/rehearse-cell-conversion.sh [--no-build] [--keep]
#
# It is what turning the single-region `testidp` into cell `usw2` of
# `testidpna` does, with the compose stacks this repository already has in
# place of AWS:
#
#   1. A SINGLE-CELL product-mode service on postgres — the `single-node`
#      mode's settings with no request workers, which are the `cells` mode's
#      — is seeded over HTTP (tests/tools/rehearse-cell-conversion.js
#      seed): a second realm, clients, people, a group, sign-ins good and
#      bad, and a tiny SYNTHETIC operator deny list. The people and every
#      `sts_risk_*` table are counted in SQL, and the realm key rows are
#      digested.
#   2. The service is stopped, and the `cells` mode's global database and
#      cell keys are brought up beside the database it leaves.
#   3. The tool is run as the `cells` mode's cell A (`cella`) — the `sts`
#      service's own definition, image and settings, as a one-off
#      container: a dry run (nothing may change), the conversion, and a
#      re-run (nothing may change).
#   4. The `cells` mode's two cells start — cell A on the converted database
#      — and the verify phase checks over HTTP, with the trust anchor saved
#      in step 1: the key ids, every person signing in at cell A, a person
#      starting at cell B restarted at cell A, the risk history, the index.
#      SQL checks the counts again.
#
# EVERYTHING IS ITS OWN: compose project `f98c`, subnet 172.30.97.0/24, and
# every container named `f98c-…` through the `*_CONTAINER_NAME` variables
# the compose files read (run-tests.sh's arrangement). It refuses to start
# when a container of that prefix or a network on that subnet exists, and
# the teardown is `down -v` of project `f98c` and nothing else — no prune,
# no other project touched. The images are tagged `f98c`.
#
# The record of the run — the counts before and after, the tool's summary
# lines, what the verify phase saw — is left in tests/report/f98c-rehearsal/
# (gitignored). Exit 0 when every check held.
# ===========================================================================
set -u -o pipefail

ROOT="$(cd "$(dirname "$(realpath "$0")")/../.." && pwd)"
cd "${ROOT}" || exit 1

BUILD=1
KEEP=0
for arg in "$@"; do
  case "${arg}" in
    --no-build) BUILD=0 ;;
    --keep) KEEP=1 ;;
    *) echo "usage: $0 [--no-build] [--keep]" >&2; exit 2 ;;
  esac
done

PROJECT=f98c
NET=172.30.97
OUT="${ROOT}/tests/report/f98c-rehearsal"
rm -rf "${OUT}"
mkdir -p "${OUT}"
chmod 777 "${OUT}"

say() {
  echo "rehearse: $*" | tee -a "${OUT}/rehearsal.log"
}

fail() {
  say "FAILED: $*"
  exit 1
}

freshSecret() {
  head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 24
}

# ---------------------------------------------------------------------------
# THE ENVIRONMENT THE TWO COMPOSE FILES READ.
# ---------------------------------------------------------------------------
export COMPOSE_PROJECT_NAME="${PROJECT}"
export IMAGE_TAG="${PROJECT}"
export STS_NETWORK_SUBNET="${NET}.0/24"
export STS_ADDRESS="${NET}.10"
export STS_SPIFFE_GRPC_HOST="${NET}.10"
export STS_EXTRA_IPS="${NET}.11/24 ${NET}.12/24 ${NET}.13/24"
export STS2_ADDRESS="${NET}.20"
export STS_CELL_LINK_ADDRESS="${NET}.21"
export STS_CELL_A_REACHES_B="${NET}.21"
export STS_CELL_B_REACHES_A="${NET}.10"
export STS_TEST_ENTRY_ADDRESS="${NET}.10"
export CONFORMANCE_MONGO_ADDRESS="${NET}.40"
export CONFORMANCE_SERVER_ADDRESS="${NET}.41"
export CONFORMANCE_NGINX_ADDRESS="${NET}.42"
export CONFORMANCE_TLS_ADDRESS="${NET}.47"
export SAML_SHIB_ADDRESS="${NET}.43"
export SAML_SSP_ADDRESS="${NET}.44"
export SAML_PYSAML2_ADDRESS="${NET}.45"
export SAML_KEYCLOAK_ADDRESS="${NET}.46"
export STS_CONTAINER_NAME="${PROJECT}-sts"
export STS2_CONTAINER_NAME="${PROJECT}-sts2"
export STS_TEST_POSTGRES_CONTAINER_NAME="${PROJECT}-postgres"
export STS_POSTGRES_GLOBAL_CONTAINER_NAME="${PROJECT}-postgres-global"
export STS_POSTGRES_CELLB_CONTAINER_NAME="${PROJECT}-postgres-cellb"
export STS_BAO_CONTAINER_NAME="${PROJECT}-openbao"
export STS_BAO_TLS_CONTAINER_NAME="${PROJECT}-openbao-tls"
export STS_BAO_SEED_CONTAINER_NAME="${PROJECT}-openbao-seed"
export STS_MAILPIT_CONTAINER_NAME="${PROJECT}-mailpit"
export STS_MAILPIT_TLS_CONTAINER_NAME="${PROJECT}-mailpit-tls"
export XACML_PEP_CONTAINER_NAME="${PROJECT}-xacml-pep"
export STS_TESTS_CONTAINER_NAME="${PROJECT}-tests"
export STS_CELL_KEK_CONTAINER_NAME="${PROJECT}-cell-kek"
export STS_CELL_LINK_CONTAINER_NAME="${PROJECT}-cell-link"
export STS_CONFORMANCE_MONGO_CONTAINER_NAME="${PROJECT}-conformance-mongo"
export STS_CONFORMANCE_SERVER_CONTAINER_NAME="${PROJECT}-conformance-server"
export STS_CONFORMANCE_NGINX_CONTAINER_NAME="${PROJECT}-conformance-nginx"
export STS_CONFORMANCE_TLS_CONTAINER_NAME="${PROJECT}-conformance-tls"
export STS_SAML_SHIB_CONTAINER_NAME="${PROJECT}-saml-shib"
export STS_SAML_SSP_CONTAINER_NAME="${PROJECT}-saml-ssp"
export STS_SAML_PYSAML2_CONTAINER_NAME="${PROJECT}-saml-pysaml2"
export STS_SAML_KEYCLOAK_CONTAINER_NAME="${PROJECT}-saml-keycloak"
export CONFIG_FILE=./env/test.js
export STS_LOG_LEVEL=info
export STS_HTTPS=true
export STS_TEST_SERVICE_URL=https://sts:8081
export STS_PUBLIC_BASE_URL=https://sts:8081
export ADMIN_API_CLIENT_SECRET
ADMIN_API_CLIENT_SECRET="$(freshSecret)"
export KRB5_KRBTGT_PASSWORD
KRB5_KRBTGT_PASSWORD="$(freshSecret)"
export KRB5_SERVICE_PASSWORD
KRB5_SERVICE_PASSWORD="$(freshSecret)"
# The `cells` mode's settings (tests/tools/modes.sh), in BOTH halves: the
# single-cell service is that mode's cell with no cell configured, so the
# only thing that changes across the conversion is the cells layer.
while IFS= read -r line; do
  case "${line}" in
    STS_TEST_*) ;;
    *=*) export "${line?}" ;;
  esac
done < <(. tests/tools/modes.sh && stsModeEnv cells)

BASE_FILES=(-f docker-compose-run-tests.yml)
CELL_FILES=(-f docker-compose-run-tests.yml
            -f tests/docker-compose-run-tests-cells.yml)
dc() {
  docker compose -p "${PROJECT}" "${BASE_FILES[@]}" "$@"
}
dcc() {
  docker compose -p "${PROJECT}" "${CELL_FILES[@]}" "$@"
}

# ---------------------------------------------------------------------------
# NOTHING OF ANYBODY ELSE'S.
# ---------------------------------------------------------------------------
if docker ps -a --format '{{.Names}}' | grep -q "^${PROJECT}-"; then
  fail "containers named ${PROJECT}-* already exist; this script touches " \
       "none it did not start. Remove them (docker compose -p ${PROJECT} " \
       "down -v) if they are a previous rehearsal's."
fi
for n in $(docker network ls -q); do
  if docker network inspect -f '{{range .IPAM.Config}}{{.Subnet}} {{end}}' \
       "${n}" 2>/dev/null | grep -q "^${NET}\.\| ${NET}\."; then
    fail "a docker network already uses ${NET}.0/24: $(docker network \
inspect -f '{{.Name}}' "${n}")"
  fi
done

teardown() {
  if [ "${KEEP}" = "1" ]; then
    say "--keep: project ${PROJECT} left running; remove it with" \
        "docker compose -p ${PROJECT} ${CELL_FILES[*]} down -v"
    return
  fi
  say "tearing down project ${PROJECT}"
  dcc logs --no-color > "${OUT}/stack.log" 2>&1 || true
  dcc down -v --remove-orphans --timeout 30 >> "${OUT}/rehearsal.log" 2>&1 \
    || true
}
trap teardown EXIT

# ---------------------------------------------------------------------------
# SQL, AS THE DATABASE'S SUPERUSER OVER ITS OWN SOCKET.
# ---------------------------------------------------------------------------
sql() {
  docker exec "$1" psql -U sts -d sts -At -v ON_ERROR_STOP=1 \
    -c "SET search_path TO sts, public;" -c "$2" | tail -n +2
}

# Every sts_risk_* table and its row count, one `table=n` per line.
riskCounts() {
  local c="$1" t
  for t in $(sql "${c}" "SELECT table_name FROM information_schema.tables \
WHERE table_schema = 'sts' AND table_name LIKE 'sts\_risk\_%' ORDER BY 1"); do
    echo "${t}=$(sql "${c}" "SELECT count(*) FROM ${t}")"
  done
}

people() {
  sql "$1" "SELECT count(*) FROM sts_ldap_entries WHERE dn_key LIKE \
'uid=%,ou=users,%'"
}

# A digest of a table's whole content, for "nothing changed".
tableDigest() {
  sql "$1" "SELECT coalesce(md5(string_agg(t::text, '|' ORDER BY \
t::text)), 'empty') FROM $2 t"
}

STATE_TABLES="sts_realms sts_appconfig sts_keys sts_ldap_entries sts_minted \
sts_used_assertions sts_cluster_secrets sts_cell_routing"

stateOf() {
  local c="$1" t
  for t in ${STATE_TABLES}; do
    echo "${t}=$(tableDigest "${c}" "${t}")"
  done
}

# The `msg` of every bunyan line of a log that starts with a prefix.
messages() {
  node -e '
    const lines = require("fs").readFileSync(process.argv[1], "utf8")
      .split("\n");
    for (const l of lines) {
      try {
        const m = JSON.parse(l).msg;
        if (String(m).indexOf(process.argv[2]) === 0) {
          console.log(m);
        }
      } catch (e) {
        // Not a log line: compose'"'"'s own output.
      }
    }' "$1" "$2" 2>/dev/null || grep -a "$2" "$1"
}

waitHealthy() {
  local c="$1" i s
  for i in $(seq 1 180); do
    s="$(docker inspect -f '{{.State.Health.Status}}' "${c}" 2>/dev/null)"
    [ "${s}" = "healthy" ] && return 0
    sleep 5
  done
  fail "${c} did not become healthy"
}

# The HTTP half, in the tests image. With a browser's User-Agent preloaded,
# as run-report.js gives every protocol job: a first sign-in from a client
# `isbot` names is HIGH risk and refused in product mode
# (tests/tools/browser-user-agent.js argues it).
runner() {
  local mode="$1"; shift
  local files=("${BASE_FILES[@]}")
  [ "${mode}" = "cells" ] && files=("${CELL_FILES[@]}")
  docker compose -p "${PROJECT}" "${files[@]}" run --rm --no-deps -T \
    -v "${OUT}:/rehearse" \
    -v "${ROOT}/tests/tools/rehearse-cell-conversion.js:/usr/src/sts/tests/tools/rehearse-cell-conversion.js:ro" \
    -e ADMIN_API_CLIENT_SECRET -e STS_TEST_CELL_A_URL=https://sts:8081 \
    -e STS_TEST_CELL_B_URL=https://sts2:8081 \
    -e NODE_OPTIONS="--require /usr/src/sts/tests/tools/browser-user-agent.js" \
    "$@"
}

# ---------------------------------------------------------------------------
# 0. THE IMAGES.
# ---------------------------------------------------------------------------
if [ "${BUILD}" = "1" ]; then
  say "building the service and tests images, tagged ${IMAGE_TAG}"
  tests/tools/corpora-preflight.sh || fail "the corpora preflight refused"
  dc build sts tests >> "${OUT}/build.log" 2>&1 \
    || fail "the build failed; see ${OUT}/build.log"
fi

# ---------------------------------------------------------------------------
# 1. A SINGLE-CELL SERVICE, SEEDED.
# ---------------------------------------------------------------------------
say "1. a single-cell product-mode service on postgres"
dc up -d --no-build sts >> "${OUT}/rehearsal.log" 2>&1 \
  || fail "the single-cell stack did not start"
waitHealthy "${STS_CONTAINER_NAME}"
runner single -e NODE_TLS_REJECT_UNAUTHORIZED=0 tests \
  node tests/tools/rehearse-cell-conversion.js seed /rehearse \
  > "${OUT}/seed.log" 2>&1 || fail "seeding failed; see ${OUT}/seed.log"
say "seeded; stopping the single-cell service"
dc stop -t 60 sts >> "${OUT}/rehearsal.log" 2>&1
dc rm -f sts >> "${OUT}/rehearsal.log" 2>&1
PG="${STS_TEST_POSTGRES_CONTAINER_NAME}"
PGG="${STS_POSTGRES_GLOBAL_CONTAINER_NAME}"
PG_ID_BEFORE="$(docker inspect -f '{{.Id}}' "${PG}")"
PEOPLE_BEFORE="$(people "${PG}")"
riskCounts "${PG}" > "${OUT}/risk-before.txt"
KEYS_BEFORE="$(tableDigest "${PG}" sts_keys)"
REALMS_BEFORE="$(tableDigest "${PG}" sts_realms)"
say "before: ${PEOPLE_BEFORE} people; sts_keys ${KEYS_BEFORE}"
sed 's/^/rehearse:   /' "${OUT}/risk-before.txt" | tee -a "${OUT}/rehearsal.log"

# ---------------------------------------------------------------------------
# 2. THE GLOBAL DATABASE AND THE CELL KEYS.
# ---------------------------------------------------------------------------
say "2. the global database, built empty at the current schema"
dcc up -d --no-build postgres-global sts-cell-kek \
  >> "${OUT}/rehearsal.log" 2>&1 || fail "the global database did not start"
waitHealthy "${PGG}"
for i in $(seq 1 60); do
  s="$(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' \
       "${STS_CELL_KEK_CONTAINER_NAME}" 2>/dev/null)"
  [ "${s}" = "exited 0" ] && break
  sleep 2
done
[ "$(people "${PGG}")" = "0" ] || fail "the global database is not empty"

# ---------------------------------------------------------------------------
# 3. THE TOOL, AS CELL A: dry run, conversion, re-run.
# ---------------------------------------------------------------------------
# AS THE AWS ONE-OFF TASK RUNS IT (deploy/aws, the `cell-convert`
# container): STS_CLUSTER_NODE_NAME=convert, no TLS files, and a risk upload
# directory with nothing mounted behind it. The tool must bind nothing, join
# no cluster and leave no claim — the cluster tables are digested either
# side of all three runs.
convert() {
  dcc run --rm --no-deps -T -e STS_CLUSTER_NODE_NAME=convert \
    -e STS_RISK_UPLOAD_DIRECTORY=/nonexistent/risk-uploads \
    -e STS_TLS_CERT_FILE= -e STS_TLS_KEY_FILE= \
    sts node persistence/cell_convert.js "$@"
}
CLUSTER_TABLES="sts_cluster_nodes sts_cluster_leases sts_cluster_claims \
sts_change_readers sts_changes"
clusterOf() {
  local c="$1" t
  for t in ${CLUSTER_TABLES}; do
    echo "${t}=$(tableDigest "${c}" "${t}")"
  done
}
clusterOf "${PG}" > "${OUT}/cluster-cell-0.txt"
clusterOf "${PGG}" > "${OUT}/cluster-global-0.txt"
stateOf "${PG}" > "${OUT}/cell-0.txt"
stateOf "${PGG}" > "${OUT}/global-0.txt"
say "3a. cell_convert --dry-run"
convert --dry-run > "${OUT}/convert-dry.log" 2>&1 \
  || fail "the dry run exited non-zero; see ${OUT}/convert-dry.log"
stateOf "${PG}" > "${OUT}/cell-1.txt"
stateOf "${PGG}" > "${OUT}/global-1.txt"
cmp -s "${OUT}/cell-0.txt" "${OUT}/cell-1.txt" \
  && cmp -s "${OUT}/global-0.txt" "${OUT}/global-1.txt" \
  || fail "the dry run changed a database"
say "3b. cell_convert"
T0="$(date +%s)"
convert > "${OUT}/convert.log" 2>&1 \
  || fail "the conversion exited non-zero; see ${OUT}/convert.log"
say "the conversion took $(( $(date +%s) - T0 )) s, container start included"
stateOf "${PG}" > "${OUT}/cell-2.txt"
stateOf "${PGG}" > "${OUT}/global-2.txt"
say "3c. cell_convert again"
convert > "${OUT}/convert-again.log" 2>&1 \
  || fail "the re-run exited non-zero; see ${OUT}/convert-again.log"
stateOf "${PG}" > "${OUT}/cell-3.txt"
stateOf "${PGG}" > "${OUT}/global-3.txt"
cmp -s "${OUT}/cell-2.txt" "${OUT}/cell-3.txt" \
  && cmp -s "${OUT}/global-2.txt" "${OUT}/global-3.txt" \
  || fail "the re-run changed a database"
clusterOf "${PG}" > "${OUT}/cluster-cell-3.txt"
clusterOf "${PGG}" > "${OUT}/cluster-global-3.txt"
cmp -s "${OUT}/cluster-cell-0.txt" "${OUT}/cluster-cell-3.txt" \
  && cmp -s "${OUT}/cluster-global-0.txt" "${OUT}/cluster-global-3.txt" \
  || fail "the tool wrote a cluster table (membership, a lease, a claim, " \
          "a change reader or the change log)"
grep -q 'already converted' "${OUT}/convert-again.log" \
  || fail "the re-run did not report the store already converted"
for f in convert-dry convert convert-again; do
  messages "${OUT}/${f}.log" 'cell_convert: ' \
    | sed "s/^/rehearse: ${f}: /" | tee -a "${OUT}/rehearsal.log"
done

riskCounts "${PG}" > "${OUT}/risk-converted.txt"
cmp -s "${OUT}/risk-before.txt" "${OUT}/risk-converted.txt" \
  || fail "the sts_risk_* counts changed across the conversion"
PEOPLE_CELL="$(people "${PG}")"
PEOPLE_GLOBAL="$(people "${PGG}")"
[ "${PEOPLE_CELL}" = "${PEOPLE_BEFORE}" ] \
  || fail "the cell holds ${PEOPLE_CELL} people, not ${PEOPLE_BEFORE}"
[ "${PEOPLE_GLOBAL}" = "0" ] \
  || fail "the global database holds ${PEOPLE_GLOBAL} people"
[ "$(tableDigest "${PGG}" sts_keys)" = "${KEYS_BEFORE}" ] \
  || fail "the global sts_keys are not the single-cell store's"
[ "$(tableDigest "${PGG}" sts_realms)" = "${REALMS_BEFORE}" ] \
  || fail "the global sts_realms are not the single-cell store's"
[ "$(sql "${PG}" 'SELECT count(*) FROM sts_keys')" = "0" ] \
  || fail "the cell still holds key rows"
ROUTES="$(sql "${PGG}" "SELECT count(*) FROM sts_cell_routing WHERE \
cell = 'cella'")"
[ "${ROUTES}" = "$((2 * PEOPLE_BEFORE))" ] \
  || fail "the index holds ${ROUTES} rows for ${PEOPLE_BEFORE} people"
say "converted: cell ${PEOPLE_CELL} people, global ${PEOPLE_GLOBAL}; " \
    "${ROUTES} index rows; keys and realms identical; risk counts identical"

# ---------------------------------------------------------------------------
# 4. TWO CELLS, CELL A ON THE CONVERTED DATABASE.
# ---------------------------------------------------------------------------
say "4. the cells: cella on the converted database, cellb beside it"
dcc up -d --no-build sts sts2 >> "${OUT}/rehearsal.log" 2>&1 \
  || fail "the cells did not start; see ${OUT}/rehearsal.log"
waitHealthy "${STS_CONTAINER_NAME}"
waitHealthy "${STS2_CONTAINER_NAME}"
[ "$(docker inspect -f '{{.Id}}' "${PG}")" = "${PG_ID_BEFORE}" ] \
  || fail "the cell database container was recreated"
riskCounts "${PG}" > "${OUT}/risk-cells-up.txt"
cmp -s "${OUT}/risk-before.txt" "${OUT}/risk-cells-up.txt" \
  || say "NOTE: the sts_risk_* counts moved when the cells started" \
         "(see risk-cells-up.txt)"
runner cells -e NODE_EXTRA_CA_CERTS=/rehearse/sts-certificate.pem tests \
  node tests/tools/rehearse-cell-conversion.js verify /rehearse \
  > "${OUT}/verify.log" 2>&1 || fail "verification failed; see \
${OUT}/verify.log"
riskCounts "${PG}" > "${OUT}/risk-after.txt"
while IFS='=' read -r t n; do
  m="$(grep "^${t}=" "${OUT}/risk-after.txt" | cut -d= -f2)"
  [ "${m:-0}" -ge "${n}" ] || fail "${t} went from ${n} rows to ${m}"
done < "${OUT}/risk-before.txt"
[ "$(people "${PG}")" = "${PEOPLE_BEFORE}" ] \
  || fail "cell A holds $(people "${PG}") people after the sign-ins"

say "RESULT: every check held"
say "people: ${PEOPLE_BEFORE} before, ${PEOPLE_CELL} in cell A after, " \
    "0 in the global tier; ${ROUTES} index rows"
paste -d' ' "${OUT}/risk-before.txt" "${OUT}/risk-converted.txt" \
  "${OUT}/risk-cells-up.txt" "${OUT}/risk-after.txt" \
  | sed 's/^/rehearse: risk (before, converted, cells up, after verify): /' \
  | tee -a "${OUT}/rehearsal.log"
messages "${OUT}/verify.log" 'rehearse: verified' \
  | tee -a "${OUT}/rehearsal.log"
exit 0
