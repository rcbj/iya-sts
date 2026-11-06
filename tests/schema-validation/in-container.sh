#!/bin/bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# tests/schema-validation/in-container.sh — THE RUN, INSIDE THE ONE CONTAINER.
#
# Each stage is a mode of tests/tools/modes.sh: the same settings, so the stage
# means what that mode means. The service runs in a network namespace of its own
# so that two nodes can each hold the same ports (389, 88, 8081...) in one
# container; the stores, the secret store, the balancer and the jobs share the
# container's own. A stage starts from nothing and leaves nothing.
#
# **WHAT PASSES IS NOT WHAT THE WHOLE SUITE ASKS.** The verdict is:
#   1. no `STS-API-0139` and no `STS-API-0140` in any node's log, whichever job
#      caused it: every answer every job drew was held to its model;
#   2. `tests/openapi_response_models.js` passes, and
#      `tests/protocol/sts_outside_values.js` passes in every stage it ran in.
# Any other job's failure is REPORTED and does not fail the mode, because this
# container has no test peer, remote PEP, mail relay, conformance suite or SAML
# peers, and a job that needs one fails or skips for that. `./run-tests.sh`'s
# other modes answer whether those pass.
set -u -o pipefail

cd "$(dirname "$(realpath "$0")")/../.." || exit 1

# shellcheck source=tests/tools/modes.sh
. tests/tools/modes.sh

OUT=/out
BAO_SEAL_KEY="$(openssl rand -base64 32)"
ADMIN_SECRET="$(openssl rand -hex 24)"
PGBIN="$(dirname "$(ls -d /usr/lib/postgresql/*/bin/initdb | tail -1)")"
NODE_PIDS=()
HELPER_PIDS=()
FAILED=0

say() {
  echo "schema-validation: $*"
}

secret() {
  openssl rand -hex 24
}

# ---- The namespaces, once: a bridge here and a veth to each node.
network() {
  ip link add br0 type bridge
  ip addr add 10.77.0.1/24 dev br0
  ip link set br0 up
  ip link set lo up
  local ns addr
  for pair in a:10.77.0.10 b:10.77.0.20; do
    ns="${pair%%:*}"; addr="${pair##*:}"
    ip netns add "sts-${ns}"
    ip link add "ve-${ns}" type veth peer name eth0 netns "sts-${ns}"
    ip link set "ve-${ns}" master br0 up
    ip netns exec "sts-${ns}" ip addr add "${addr}/24" dev eth0
    ip netns exec "sts-${ns}" ip link set eth0 up
    ip netns exec "sts-${ns}" ip link set lo up
    ip netns exec "sts-${ns}" ip route add default via 10.77.0.1
  done
  # The addresses a realm's SPIFFE listener binds (docker-compose-run-tests.yml).
  for extra in 11 12 13; do
    ip netns exec sts-a ip addr add "10.77.0.${extra}/24" dev eth0
  done
}

waitFor() {
  local what="$1" deadline; shift
  deadline=$(( $(date +%s) + 180 ))
  until "$@" > /dev/null 2>&1; do
    if [ "$(date +%s)" -ge "${deadline}" ]; then
      say "${what} did not come up."
      return 1
    fi
    sleep 2
  done
}

startPostgres() {
  local data=/var/lib/sts-pg
  rm -rf "${data}" /run/secrets/database-ca
  mkdir -p "${data}" /run/secrets/database-ca /var/run/postgresql
  chown postgres:postgres "${data}" /var/run/postgresql
  printf 'sts\n' > /tmp/pgpass
  chown postgres /tmp/pgpass
  su postgres -c "${PGBIN}/initdb -D ${data} -U sts --pwfile=/tmp/pgpass \
    --auth-host=scram-sha-256 --auth-local=trust" > /dev/null || return 1
  echo "host all all 10.77.0.0/24 scram-sha-256" >> "${data}/pg_hba.conf"
  POSTGRES_TLS_DIR="${data}/tls" POSTGRES_TLS_PUBLIC_DIR=/run/secrets/database-ca \
    bash postgres/generate-tls.sh || return 1
  chown -R postgres:postgres "${data}/tls"
  PGDATA="${data}" bash postgres/require-tls.sh > /dev/null || return 1
  su postgres -c "${PGBIN}/postgres -D ${data} -c listen_addresses='*' \
    -c max_connections=200 -c ssl=on \
    -c ssl_cert_file=${data}/tls/server.crt \
    -c ssl_key_file=${data}/tls/server.key" \
    > "${STAGE_OUT}/postgres.log" 2>&1 &
  HELPER_PIDS+=($!)
  waitFor postgres su postgres -c "${PGBIN}/pg_isready -U sts -d postgres" \
    || return 1
  su postgres -c "${PGBIN}/createdb -U sts sts" || return 1
  su postgres -c "POSTGRES_USER=sts POSTGRES_DB=sts \
    STS_SCHEMA_SQL=${PWD}/postgres/schema.sql bash postgres/apply-schema.sh" \
    > "${STAGE_OUT}/postgres-schema.log" 2>&1
}

startMariadb() {
  local data=/var/lib/sts-mariadb tls=/run/secrets/mariadb-tls/tls
  rm -rf "${data}" /run/secrets/mariadb-tls
  mkdir -p "${data}" "${tls}" /run/mysqld
  chown -R mysql:mysql "${data}" /run/mysqld
  STS_BAO_TLS_DIR="${tls}" STS_BAO_RAFT_DIR=/tmp/mariadb-tls-unused \
    STS_BAO_TLS_NAMES=mariadb,localhost STS_BAO_TLS_IPS=127.0.0.1,10.77.0.1 \
    node openbao/generate-tls.js > /dev/null || return 1
  chown mysql:mysql "${tls}" "${tls}/server.key" "${tls}/server.crt"
  chmod 711 "${tls}"; chmod 600 "${tls}/server.key"; chmod 644 "${tls}/server.crt"
  mariadb-install-db --user=mysql --datadir="${data}" > /dev/null || return 1
  mariadbd --user=mysql --datadir="${data}" --bind-address=0.0.0.0 \
    --ssl-cert="${tls}/server.crt" --ssl-key="${tls}/server.key" \
    --require-secure-transport=ON --performance-schema=OFF \
    --innodb-buffer-pool-size="${STS_MARIADB_BUFFER_POOL:-1G}" \
    > "${STAGE_OUT}/mariadb.log" 2>&1 &
  HELPER_PIDS+=($!)
  waitFor mariadb mariadb --protocol=socket -e 'SELECT 1' || return 1
  mariadb --protocol=socket -e "CREATE USER IF NOT EXISTS 'root'@'%' \
    IDENTIFIED BY 'sts'; GRANT ALL ON *.* TO 'root'@'%' WITH GRANT OPTION; \
    CREATE DATABASE IF NOT EXISTS sts; \
    CREATE DATABASE IF NOT EXISTS sts_store;" || return 1
  mariadb --protocol=socket \
    --init-command="SET @sts_app_password='sts_app'" sts_store \
    < mariadb/schema.sql || return 1
}

startOpenbao() {
  rm -rf /openbao/file/* /openbao/client/* /openbao/startup/*
  mkdir -p /openbao/file/raft
  STS_BAO_TLS_DIR=/openbao/file/tls STS_BAO_TLS_NAMES=openbao,localhost \
    STS_BAO_TLS_IPS=127.0.0.1,10.77.0.1 node openbao/generate-tls.js \
    > /dev/null || return 1
  BAO_STATIC_SEAL_CURRENT_KEY_ID=sts \
    BAO_STATIC_SEAL_CURRENT_KEY="${BAO_SEAL_KEY}" \
    bao server -config=openbao/bao.hcl > "${STAGE_OUT}/openbao.log" 2>&1 &
  HELPER_PIDS+=($!)
  STS_BAO_ADDR=https://openbao:8200 STS_BAO_CA_FILE=/openbao/file/tls/server.crt \
    STS_BAO_POLICY_FILE="${PWD}/openbao/read-only.hcl" STS_BAO_CLIENT_CN=sts \
    STS_DB_APP_PASSWORD=sts_app STS_ADMIN_API_CLIENT_SECRET="${ADMIN_SECRET}" \
    STS_KRB5_KRBTGT_PASSWORD="${KRBTGT}" STS_KRB5_SERVICE_PASSWORD="${KRBSVC}" \
    STS_BAO_STARTUP_NODES="$1" STS_BAO_STARTUP_DIR=/openbao/startup \
    STS_BAO_PRINT_CREDENTIALS=false node openbao/seed.js \
    > "${STAGE_OUT}/openbao-seed.log" 2>&1
}

# One node, in its namespace. `$1` the namespace, `$2` the node's name for the
# secret store, `$3` its cluster name, `$4` its address.
startNode() {
  local ns="$1" node="$2" name="$3" address="$4" startup
  if [ "${STS_PERSISTENCE_MODE}" != memory ]; then
    startup="$(STS_BAO_STARTUP_NODE="${node}" STS_BAO_ADDR=https://openbao:8200 \
      STS_KEYS_VAULT_CA_CERT=/openbao/client/bao-ca.crt \
      STS_STARTUP_SECRETS_DIR="/run/sts-startup-${node}" \
      STS_BAO_SERVICE_UID=0 STS_BAO_SERVICE_GID=0 \
      node openbao/startup-secrets.js)" || return 1
  else
    startup="export ADMIN_API_CLIENT_SECRET=${ADMIN_SECRET}"
  fi
  (
    eval "${startup}"
    export STS_BAO_STARTUP_NODE="${node}" STS_CLUSTER_NODE_NAME="${name}" \
           STS_SPIFFE_GRPC_HOST="${address}"
    exec ip netns exec "sts-${ns}" node server.js
  ) > "${STAGE_OUT}/service-${name}.log" 2>&1 &
  NODE_PIDS+=($!)
}

probe() {
  node -e '
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
    fetch(process.argv[1] + "/healthcheck").then(function (r) {
      process.exit(r.status === 200 ? 0 : 1);
    }, function () { process.exit(1); });' "$1"
}

# The nodes first: a store stopped under a node is a failed write in its log.
stopStage() {
  local pid
  for pid in ${NODE_PIDS[@]+"${NODE_PIDS[@]}"}; do
    kill "${pid}" 2> /dev/null
  done
  for pid in ${NODE_PIDS[@]+"${NODE_PIDS[@]}"}; do
    wait "${pid}" 2> /dev/null
  done
  for pid in ${HELPER_PIDS[@]+"${HELPER_PIDS[@]}"}; do
    kill "${pid}" 2> /dev/null
  done
  for pid in ${HELPER_PIDS[@]+"${HELPER_PIDS[@]}"}; do
    wait "${pid}" 2> /dev/null
  done
  NODE_PIDS=(); HELPER_PIDS=()
  pkill -x haproxy 2> /dev/null
}

stage() {
  local mode="$1"; shift
  STAGE_OUT="${OUT}/${mode}"
  rm -rf "${STAGE_OUT}"; mkdir -p "${STAGE_OUT}" /run/sts-test
  say "=== ${mode}: $(stsModeDescription "${mode}" | head -1)"
  local line
  while IFS= read -r line; do
    [ -n "${line}" ] && export "${line?}"
  done < <(stsModeEnv "${mode}")

  local url=https://sts:8081 nodes=sts
  KRBTGT="$(secret)"; KRBSVC="$(secret)"
  unset STS_DATABASE_URL STS_DATABASE_TLS_CA_FILE
  # THE CAPS ARE PROCESS-WIDE AND NO JOB REMOVES A REALM. A run side by side has
  # the bulk jobs raise them early; serially those come last and the suite's own
  # growth fills the directory near job 976, after which every job fails at its
  # set-up and exercises nothing.
  export LDAP_MAX_ENTRIES=500000 STS_APPLICATIONS_MAX=100000 \
    STS_REALMS_MAX_COUNT=5000
  export CONFIG_FILE=./env/docker-tests.js STS_HTTPS=true STS_LOG_LEVEL=info \
    STS_DATABASE_PASSWORD_PROVIDER=vault \
    STS_DATABASE_PASSWORD_FIELD=databasePassword \
    STS_KEYS_KEK_PROVIDER=vault STS_KEYS_KEK_VAULT=https://openbao:8200 \
    STS_KEYS_KEK_REF=secret/data/sts STS_KEYS_KEK_FIELD=kek \
    STS_KEYS_VAULT_CLIENT_CERT=/run/secrets/openbao/client.crt \
    STS_KEYS_VAULT_CLIENT_KEY=/run/secrets/openbao/client.key \
    STS_KEYS_VAULT_CA_CERT=/run/secrets/openbao/bao-ca.crt \
    STS_RISK_BREACH_CHECK=off STS_DEVICES_ANDROID_STATUS_URL= \
    STS_RISK_NETWORK_FAILURE_THRESHOLD=1000000 \
    STS_RISK_MEDIUM_SCORE_PERCENT=1000 \
    STS_SPIFFE_WORKLOAD_TCP_SOURCE_AUTHENTICATED=true \
    PKI_DISTRIBUTION_BASE_URL=http://sts:8082 PKI_DISTRIBUTION_LDAP_HOST=sts \
    ADMIN_API_CLIENT_SECRET="${ADMIN_SECRET}" \
    STS_ADMIN_API_CLIENT_SECRET="${ADMIN_SECRET}"
  unset STS_PUBLIC_BASE_URL STS_TRUSTED_PROXIES STS_TLS_HOSTNAMES \
        KRB5_KRBTGT_PASSWORD KRB5_SERVICE_PASSWORD
  if [ "${STS_MODE}" = product ]; then
    export STS_PUBLIC_BASE_URL="${url}" KRB5_KRBTGT_PASSWORD="${KRBTGT}" \
           KRB5_SERVICE_PASSWORD="${KRBSVC}"
  fi
  if [ "${mode}" = cluster ]; then
    url=https://sts-lb:8081; nodes=sts,sts2
    export STS_PUBLIC_BASE_URL="${url}" STS_TRUSTED_PROXIES=10.77.0.1/32 \
      STS_TLS_HOSTNAMES=sts-lb,sts-lb.example.com,localhost,sts,sts2 \
      PKI_DISTRIBUTION_BASE_URL=http://sts-lb:8082 \
      PKI_DISTRIBUTION_LDAP_HOST=sts-lb
  fi

  # What every stage's jobs read about the database gets it whichever the store.
  case "${STS_PERSISTENCE_MODE}" in
    postgres)
      export STS_DATABASE_URL='postgres://sts_app@postgres:5432/sts?sslmode=verify-full' \
             STS_DATABASE_TLS_CA_FILE=/run/secrets/database-ca
      startPostgres || { say "postgres failed"; FAILED=1; stopStage; return; }
      startOpenbao "${nodes}" || { say "openbao failed"; FAILED=1; stopStage; return; }
      ;;
    mariadb)
      export STS_DATABASE_URL='mariadb://sts_app@mariadb:3306/sts_store' \
             STS_DATABASE_TLS_CA_FILE=/run/secrets/mariadb-tls/tls/server.crt
      startMariadb || { say "mariadb failed"; FAILED=1; stopStage; return; }
      startOpenbao "${nodes}" || { say "openbao failed"; FAILED=1; stopStage; return; }
      ;;
  esac

  startNode a sts node-a 10.77.0.10 || { say "node a failed"; FAILED=1; stopStage; return; }
  if [ "${mode}" = cluster ]; then
    startNode b sts2 node-b 10.77.0.20 || { say "node b failed"; FAILED=1; stopStage; return; }
    sed -e '/^resolvers docker/,/^$/d' -e 's/ resolvers docker//' \
        -e 's/ init-addr last,libc,none//' tests/cluster/haproxy.cfg \
        > /tmp/haproxy.cfg
    STS_LB_PROXY_PROTOCOL="${STS_PROXY_PROTOCOL}" haproxy -f /tmp/haproxy.cfg \
      > "${STAGE_OUT}/haproxy.log" 2>&1 &
    HELPER_PIDS+=($!)
  fi

  if ! waitFor "the service" probe "${url}"; then
    FAILED=1; stopStage; return
  fi
  local token
  token="$(NODE_TLS_REJECT_UNAUTHORIZED=0 \
    node tests/tools/admin-api-token.js "${url}" 2> /dev/null | tail -n 1)"
  export STS_ADMIN_API_TOKEN="${token}" STS_TEST_SERVICE_URL="${url}" \
    STS_LDAP_URL="ldap://${url#https://}"
  STS_LDAP_URL="${STS_LDAP_URL%:8081}:389"; export STS_LDAP_URL
  export OUTBOUND_TEST_CA_DIR=/run/sts-test BULK_USERS=1000 BULK_GROUPS=10 \
    BULK_MEMBERS_PER_GROUP=100 GNAP_PUSH_HOST=tests \
    STS_TEST_PEER_URL= XACML_PEP_URL= MAILPIT_API_URL= \
    STS_TEST_ATTRIBUTE_DB_URL= STS_TEST_ATTRIBUTE_MYSQL_URL= \
    STS_TEST_PERSISTENCE_DB_URL=

  # WHAT A NODE IS GIVEN IS NOT THE JOBS' TO SEE: in the compose stacks the
  # runner is another container. An in-process test that builds its own store
  # reads these and looks for a secret store's files it has no business with.
  local name
  for name in $(compgen -e | grep -E '^(STS_|PKI_|KRB5_|LDAP_MAX)' \
                | grep -vE '^STS_(TEST_|LDAP_URL$|ADMIN_API_)'); do
    unset "${name}"
  done

  local reportArgs=("--service-url=${url}" "--report-dir=${STAGE_OUT}/report"
                    --serial)
  # The in-process half is one answer whatever the deployment: once.
  [ "${mode}" = memory ] || reportArgs+=(--protocol)
  CONFIG_FILE=./env/local.js node tests/tools/run-report.js "${reportArgs[@]}" "$@" \
    > "${STAGE_OUT}/run-report.log" 2>&1
  local reportRc=$?

  stopStage
  verdict "${mode}" "${reportRc}"
}

verdict() {
  local mode="$1" reportRc="$2" dir="${OUT}/$1" ok=1
  grep -hE 'STS-API-0139\] An answer|STS-API-0140\] A handler' \
    "${dir}"/service-*.log > "${dir}/violations.log"
  local count
  count="$(wc -l < "${dir}/violations.log")"
  [ "${count}" -eq 0 ] || ok=0
  local key
  for key in sts_outside_values openapi_response_models; do
    if grep -E "(FAIL|failed).*${key}|${key}.*(FAIL|failed)" \
         "${dir}/run-report.log" > /dev/null; then
      ok=0
      echo "${key} failed" >> "${dir}/violations.log"
    fi
  done
  {
    echo "stage: ${mode}"
    echo "answers refused or thrown (STS-API-0139/0140 lines): ${count}"
    echo "run-report exit: ${reportRc} (other jobs may need what this container lacks)"
    echo "verdict: $([ "${ok}" = 1 ] && echo pass || echo FAIL)"
  } | tee "${dir}/verdict.txt"
  [ "${ok}" = 1 ] || FAILED=1
}

network || { say "the network namespaces could not be made"; exit 1; }
IFS=',' read -r -a STAGES <<< "${STS_SCHEMA_STAGES:-memory}"
for one in "${STAGES[@]}"; do
  stage "${one}" "$@"
done
if [ "${FAILED}" -ne 0 ]; then
  say "FAILED."
  exit 1
fi
say "every answer matched its model in: ${STAGES[*]}."
exit 0
