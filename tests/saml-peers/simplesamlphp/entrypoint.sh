#!/bin/bash
# ===========================================================================
# THE SIMPLESAMLPHP PEER'S START (#191): the SP's key pair and the secret
# salt, made now; the log directory on the volume the job reads; Apache.
# ===========================================================================
set -euo pipefail

HOST="${SAML_PEER_HOST:-saml-ssp}"
LOG_DIR="${SAML_PEER_LOG_DIR:-/run/sts-test/saml-peers/simplesamlphp}"
STATE=/var/simplesamlphp-peer

mkdir -p "${LOG_DIR}" "${STATE}/cert" "${STATE}/tmp" "${STATE}/cache"
chmod 0777 "${LOG_DIR}"
ln -sfn "${LOG_DIR}" /run/saml-peer-log
rm -f "${LOG_DIR}"/*.log

openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 2 \
  -subj "/CN=${HOST}" -keyout "${STATE}/cert/sp.key" \
  -out "${STATE}/cert/sp.crt" 2> /dev/null
cat > "${STATE}/peer.json" <<JSON
{"host": "${HOST}",
 "secretsalt": "$(openssl rand -hex 32)",
 "adminpassword": "$(openssl rand -hex 16)"}
JSON
touch "${LOG_DIR}/simplesamlphp.log"
chown -R www-data:www-data "${STATE}" "${LOG_DIR}"
exec apache2-foreground
