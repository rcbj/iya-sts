#!/bin/bash
# ===========================================================================
# THE SHIBBOLETH PEER'S START (#189).
#
# 1. THE SP'S KEYS, MADE NOW: a signing pair and an encryption pair from the
#    package's own keygen.sh, so no key is ever in an image or in git.
# 2. THE LOGS, WHERE THE JOB CAN READ THEM: shibd's, mod_shib's and Apache's
#    go to SAML_PEER_LOG_DIR (by default a directory of the volume the suite
#    shares with its runner), because the peer's own log is this harness's
#    error-and-warning source and a container's stdout is not readable from
#    another container.
# 3. PLACEHOLDER METADATA until the job configures it: shibd will not start
#    on a metadata file that does not exist, and the real ones belong to a
#    realm the job has not created yet. There is no TLS anchor to hold a place
#    for since #248: the back channel is trusted from the metadata.
# 4. shibd, the control server, and Apache in the foreground.
# ===========================================================================
set -euo pipefail

HOST="${SAML_PEER_HOST:-saml-shib}"
ENTITY_ID="${SAML_PEER_ENTITY_ID:-http://${HOST}/shibboleth}"
LOG_DIR="${SAML_PEER_LOG_DIR:-/run/sts-test/saml-peers/shibboleth}"

mkdir -p "${LOG_DIR}"
chmod 0777 "${LOG_DIR}"
ln -sfn "${LOG_DIR}" /run/saml-peer-log
# Previous runs' lines are not this run's findings.
rm -f "${LOG_DIR}"/*.log "${LOG_DIR}"/*.stdout

cd /etc/shibboleth
./keygen.sh -f -u shibd -g shibd -h "${HOST}" -y 1 -e "${ENTITY_ID}" \
  -n sp-signing > /dev/null
./keygen.sh -f -u shibd -g shibd -h "${HOST}" -y 1 -e "${ENTITY_ID}" \
  -n sp-encrypt > /dev/null

sed -i "s#@ENTITY_ID@#${ENTITY_ID}#" shibboleth2.xml
for logger in shibd.logger native.logger;
do
  sed -i -E "s#fileName=/var/log/shibboleth(-www)?/#fileName=${LOG_DIR}/#" \
    "${logger}"
done
# The native module logs as Apache's user.
chmod 0777 "${LOG_DIR}"

mkdir -p /etc/shibboleth/peer
# systemd-tmpfiles makes shibd's socket directory on a host; nothing does in a
# container.
mkdir -p /run/shibboleth
chown shibd:shibd /run/shibboleth
for doc in idp-saml2.xml idp-saml11.xml;
do
  if [ ! -s "/etc/shibboleth/peer/${doc}" ];
  then
    cat > "/etc/shibboleth/peer/${doc}" <<EOF
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="urn:placeholder:${doc}">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <AssertionConsumerService index="1" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://placeholder.invalid/"/>
  </SPSSODescriptor>
</EntityDescriptor>
EOF
  fi
done

export SAML_PEER_HOST="${HOST}"
/usr/local/sbin/control.py > "${LOG_DIR}/control.stdout" 2>&1 &
( /usr/sbin/shibd -F -f >> "${LOG_DIR}/shibd.stdout" 2>&1 & )
exec /usr/sbin/httpd -DFOREGROUND
