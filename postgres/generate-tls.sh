#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# File: postgres/generate-tls.sh
#
# ---------------------------------------------------------------------------
# A SERVER KEY PAIR FOR POSTGRES, GENERATED AT CONTAINER START.
#
# This is the same decision this service makes about every other key in this
# stack (`common/keystore.js`, `tls/tls_server.js`), applied to the one process
# that did not have one: **a certificate committed to a repository is a private
# key committed to a repository.** So the pair is made on first start, lives in
# the data volume beside the database, and is remade if it is ever removed.
#
# IT IS NOT REGENERATED ON EVERY START, and that is where this differs from the
# STS's own keys in development mode. Those are regenerated per start
# deliberately — the `kid` is derived from the key material, and a client is
# expected to refetch. (Product mode keeps them, sealed, in the store.)
# A database client is not: `sslmode=verify-*` pins this certificate, and a
# stack that handed its client a different one every morning would be teaching
# people to turn verification off, which is the habit this whole change exists
# to break. Delete the files (or the volume) to get a new pair.
#
# WHY openssl AND NOT THE STS'S OWN GENERATOR. The STS mints certificates with
# its own certificate authority (`common/pki.js`) and could mint this one — but
# it would have to be RUNNING to do it, and
# this key is needed by the database the STS refuses to start without. A
# circular dependency at boot is a worse thing to own than four lines of
# openssl in the image that already ships it.
#
# THE CERTIFICATE IS SHARED, AND THE KEY IS NOT (2026-10-12). The service
# verifies this certificate by default
# (`persistence.databaseTlsRejectUnauthorized`), and a self-signed one
# verifies only against itself — so with
# POSTGRES_TLS_PUBLIC_DIR set, the certificate (and nothing else) is copied
# to `${POSTGRES_TLS_PUBLIC_DIR}/${CN}.crt`, a directory the stacks share
# read-only with the `sts` container, which names it in
# `persistence.databaseTlsCaFile`. The key stays in TLS_DIR, which no other
# container mounts. One file per CN, so the three databases of the cells
# stack can share one directory without writing each other's file. Copied
# on EVERY start, not only after a generation, so a restored data volume
# and a recreated share agree; written to a temporary name and renamed, so
# a reader never sees half a certificate.
# ---------------------------------------------------------------------------
set -euo pipefail

TLS_DIR="${POSTGRES_TLS_DIR:-/var/lib/postgresql/tls}"
CRT="${TLS_DIR}/server.crt"
KEY="${TLS_DIR}/server.key"
# The name the STS dials, which is the compose service name on the private
# bridge. It is a SAN and not only a CN because RFC 6125 has said the CN is
# ignored since 2011, and `sslmode=verify-full` is the mode this exists to make
# possible.
CN="${POSTGRES_TLS_CN:-postgres}"

mkdir -p "${TLS_DIR}"

if [ -s "${CRT}" ] && [ -s "${KEY}" ]; then
  echo "postgres-tls: a key pair is already in ${TLS_DIR}; keeping it."
else
  echo "postgres-tls: generating a server key pair in ${TLS_DIR} for CN=${CN}."
  openssl req -new -x509 -nodes -newkey rsa:2048 -sha256 -days 825 \
    -subj "/CN=${CN}/O=iya-sts" \
    -addext "subjectAltName=DNS:${CN},DNS:localhost,IP:127.0.0.1" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
    -addext "extendedKeyUsage=serverAuth" \
    -keyout "${KEY}" -out "${CRT}" 2>/dev/null
fi

# POSTGRES REFUSES TO START IF THE KEY IS GROUP- OR WORLD-READABLE, and the
# message it gives ("private key file has group or world access") names the
# permission and not the cause. Set both every time rather than only after a
# generation: a volume restored from a backup, or copied between machines,
# commonly arrives with the mode widened.
chmod 600 "${KEY}"
chmod 644 "${CRT}"
chown postgres:postgres "${KEY}" "${CRT}" 2>/dev/null || true

PUBLIC_DIR="${POSTGRES_TLS_PUBLIC_DIR:-}"
if [ -n "${PUBLIC_DIR}" ]; then
  mkdir -p "${PUBLIC_DIR}"
  cp "${CRT}" "${PUBLIC_DIR}/.${CN}.crt.tmp"
  chmod 644 "${PUBLIC_DIR}/.${CN}.crt.tmp"
  mv -f "${PUBLIC_DIR}/.${CN}.crt.tmp" "${PUBLIC_DIR}/${CN}.crt"
  echo "postgres-tls: the certificate (not the key) is shared as" \
    "${PUBLIC_DIR}/${CN}.crt."
fi

# ---------------------------------------------------------------------------
# A CLIENT CERTIFICATE FOR THE SERVICE ROLE, WHEN THE STACK ASKS FOR ONE
# (#2254). Off unless POSTGRES_CLIENT_CERT is `cert` (the certificate alone
# authenticates the service role) or `verify-full` (the certificate AND the
# password). Then a client CA is made once in TLS_DIR — the database trusts
# it as `ssl_ca_file`, which require-tls.sh names when the cluster is
# created — and a certificate for the service role (CN = STS_DB_APP_USER,
# which is what pg_hba's `cert` method matches) is issued from it. The pair
# is copied to POSTGRES_TLS_CLIENT_DIR, a volume only the `sts` container
# mounts, owned by POSTGRES_TLS_CLIENT_UID (the service's user, 10001) so the
# key can be mode 0600; the service names the two files in
# persistence.databaseTlsClientCertFile and persistence.databaseTlsClientKeyFile.
# The CA's key never leaves TLS_DIR. Generated, never committed, like the
# server's pair; delete client.crt to have the next start issue a new one,
# which is how a renewal is exercised (the service reads the files again
# every persistence.databasePasswordRefreshS).
# ---------------------------------------------------------------------------
CLIENT_MODE="${POSTGRES_CLIENT_CERT:-off}"
case "${CLIENT_MODE}" in
  off|'') ;;
  cert|verify-full)
    CA_CRT="${TLS_DIR}/client-ca.crt"
    CA_KEY="${TLS_DIR}/client-ca.key"
    CL_CRT="${TLS_DIR}/client.crt"
    CL_KEY="${TLS_DIR}/client.key"
    APP_ROLE="${STS_DB_APP_USER:-sts_app}"
    if [ ! -s "${CA_CRT}" ] || [ ! -s "${CA_KEY}" ]; then
      echo "postgres-tls: generating the client CA in ${TLS_DIR}."
      openssl req -new -x509 -nodes -newkey rsa:2048 -sha256 -days 825 \
        -subj "/CN=iya-sts database client CA/O=iya-sts" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -keyout "${CA_KEY}" -out "${CA_CRT}" 2>/dev/null
      rm -f "${CL_CRT}" "${CL_KEY}"
    fi
    if [ ! -s "${CL_CRT}" ] || [ ! -s "${CL_KEY}" ]; then
      echo "postgres-tls: issuing a client certificate for ${APP_ROLE}."
      EXT="$(mktemp)"
      printf '%s\n' "basicConstraints=critical,CA:FALSE" \
        "keyUsage=critical,digitalSignature" \
        "extendedKeyUsage=clientAuth" > "${EXT}"
      openssl req -new -nodes -newkey rsa:2048 -sha256 \
        -subj "/CN=${APP_ROLE}/O=iya-sts" \
        -keyout "${CL_KEY}" -out "${TLS_DIR}/client.csr" 2>/dev/null
      openssl x509 -req -in "${TLS_DIR}/client.csr" -CA "${CA_CRT}" \
        -CAkey "${CA_KEY}" -CAcreateserial -days 90 -sha256 \
        -extfile "${EXT}" -out "${CL_CRT}" 2>/dev/null
      rm -f "${EXT}" "${TLS_DIR}/client.csr"
    fi
    chmod 600 "${CA_KEY}" "${CL_KEY}"
    chmod 644 "${CA_CRT}" "${CL_CRT}"
    chown postgres:postgres "${CA_KEY}" "${CA_CRT}" "${CL_KEY}" \
      "${CL_CRT}" 2>/dev/null || true
    CLIENT_DIR="${POSTGRES_TLS_CLIENT_DIR:-}"
    if [ -n "${CLIENT_DIR}" ]; then
      CLIENT_UID="${POSTGRES_TLS_CLIENT_UID:-10001}"
      mkdir -p "${CLIENT_DIR}"
      for f in crt key; do
        install -m 600 -o "${CLIENT_UID}" -g "${CLIENT_UID}" \
          "${TLS_DIR}/client.${f}" "${CLIENT_DIR}/.client.${f}.tmp"
        mv -f "${CLIENT_DIR}/.client.${f}.tmp" "${CLIENT_DIR}/client.${f}"
      done
      echo "postgres-tls: the client pair is shared as" \
        "${CLIENT_DIR}/client.crt and client.key."
    fi
    ;;
  *)
    echo "postgres-tls: POSTGRES_CLIENT_CERT=${CLIENT_MODE} is not off," \
      "cert or verify-full." >&2
    exit 1
    ;;
esac

echo "postgres-tls: ready."
