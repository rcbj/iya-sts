#!/bin/bash
# ===========================================================================
# THE KEYCLOAK PEER'S START (#192).
#
# 1. A fresh bootstrap-admin password, made now and written where the job
#    reads it (the shared volume) — never in an image, a compose file or git.
# 2. WAIT FOR THE SERVICE'S TLS ANCHOR. Keycloak reads its truststore once, at
#    start, and needs it for the back channel (the back-channel LogoutRequest
#    it POSTs to this service); the anchor is the service's Root of THIS run,
#    which a job may even rebuild mid-run, so the job hands it over when it
#    starts driving Keycloak, and Keycloak starts then.
# 3. Keycloak in development mode, its log to a file the job reads — the
#    harness's error-and-warning source.
# ===========================================================================
set -euo pipefail

DIR="${SAML_PEER_LOG_DIR:-/run/sts-test/saml-peers/keycloak}"
HOST="${SAML_PEER_HOST:-saml-keycloak}"
mkdir -p "${DIR}"
chmod 0777 "${DIR}"
rm -f "${DIR}/keycloak.log" "${DIR}/admin.json" "${DIR}/sts-ca.pem"
# A FRESH KEYCLOAK ON EVERY START: its development database would keep the
# previous start's bootstrap admin, whose password is gone, and every realm in
# it is a job's to create anyway.
rm -rf /opt/keycloak/data/h2

PASSWORD="$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
printf '{"username": "admin", "password": "%s"}\n' "${PASSWORD}" \
  > "${DIR}/admin.json"

echo "waiting for the job to hand over the service's TLS anchor..."
until [ -s "${DIR}/sts-ca.pem" ];
do
  sleep 1
done

export KC_BOOTSTRAP_ADMIN_USERNAME=admin
export KC_BOOTSTRAP_ADMIN_PASSWORD="${PASSWORD}"
exec /opt/keycloak/bin/kc.sh start-dev \
  --http-port=8080 \
  --hostname="http://${HOST}:8080" \
  --truststore-paths="${DIR}/sts-ca.pem" \
  --log=console,file \
  --log-file="${DIR}/keycloak.log" \
  --log-level=info
