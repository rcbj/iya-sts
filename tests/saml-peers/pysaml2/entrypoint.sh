#!/bin/bash
# THE PYSAML2 PEER'S START (#190): its key pair, made now; its log on the
# volume the job reads; the SP.
set -euo pipefail
HOST="${SAML_PEER_HOST:-saml-pysaml2}"
LOG_DIR="${SAML_PEER_LOG_DIR:-/run/sts-test/saml-peers/pysaml2}"
mkdir -p "${LOG_DIR}" /var/lib/pysaml2-peer
chmod 0777 "${LOG_DIR}"
ln -sfn "${LOG_DIR}" /run/saml-peer-log
rm -f "${LOG_DIR}"/*.log
openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 2 \
  -subj "/CN=${HOST}" -keyout /var/lib/pysaml2-peer/sp.key \
  -out /var/lib/pysaml2-peer/sp.crt 2> /dev/null
export SAML_PEER_HOST="${HOST}"
exec /usr/local/sbin/peer.py
