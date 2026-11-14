#!/bin/bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# Starts c-icap once clamd answers. c-icap asks clamd for its version as it
# loads, and if that fails the engine is never registered and every file is
# answered 204 from then on, so it must not start before clamd is ready. A
# socket left by an earlier clamd exists without answering, so this asks.
#
# ICAP_TLS=false listens in the clear instead. Otherwise a certificate is made
# at every start and only its public half is published
# on the volume, which is what the service names in malwareScan.caFile. The
# key stays in this container's /tmp.
set -u
socket=/clamd-socket/clamd.sock
name="${ICAP_TLS_NAME:-icap}"

until [ "$(printf 'PING\n' | socat -t5 - "UNIX-CONNECT:${socket}" 2>/dev/null)" = "PONG" ]; do
  echo "Waiting for clamd at ${socket}."
  sleep 5
done

if [ "${ICAP_TLS:-true}" = "false" ]; then
  echo "TLS is off: listening in the clear on 1344."
  listen="Port 1344"
else
  openssl req -x509 -newkey rsa:3072 -nodes -days 825 \
    -keyout /tmp/icap.key -out /tmp/icap.crt -subj "/CN=${name}" \
    -addext "subjectAltName=DNS:${name}" \
    -addext "extendedKeyUsage=serverAuth" 2>/dev/null || exit 1
  cp /tmp/icap.crt /icap-tls/icap.crt || exit 1
  listen="TlsPort 11344 cert=/tmp/icap.crt key=/tmp/icap.key tls-options=SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1|SSL_OP_NO_TLSv1_1"
fi
sed "s#^LISTEN_LINE\$#${listen}#" /etc/c-icap/c-icap.conf > /tmp/c-icap.conf
exec /usr/bin/c-icap -N -D -f /tmp/c-icap.conf
