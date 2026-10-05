#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# File: deploy/azure/node-init/cert.sh
#
# ---------------------------------------------------------------------------
# THE PUBLIC CERTIFICATE AND ITS KEY, LEFT WHERE THE NODE READS THEM — Azure's
# counterpart of deploy/aws/cert-init/export.sh, and deploy/gcp/node-init/
# cert.sh against Key Vault and Azure DNS (#96).
#
# AWS exports an exportable ACM certificate on every start. An App Service or
# Key Vault certificate from Azure's own issuers could be exported too, but
# only for names Azure validates its own way and at a price per certificate;
# the certificate here is an ACME one (Let's Encrypt by default), kept in the
# environment's vault — the foundation's, so it outlives the environment — as
# ONE PEM BUNDLE, the key, then the leaf, then its issuers. This script:
#
#   1. reads the bundle; if it names every name and has more than
#      STS_ACME_RENEW_DAYS left, writes it out and is done — every start of
#      every node but the first after an expiry;
#   2. otherwise, on node-a (STS_CERT_ISSUER=true), obtains a new one against
#      a DNS-01 challenge in the public zone, adds it as the secret's new
#      version, disables the old ones, and writes it out;
#   3. on the other nodes, waits for node-a to have done so — they start
#      after node-a, so on a fresh environment it is normally there.
#
# ONLY node-a ISSUES: three nodes issuing at once would spend three of the
# FIVE certificates a week Let's Encrypt allows for one set of names, and
# leave the secret with whichever finished last. (In a multi-region
# environment each CELL's node-a issues its own, for the shared name and the
# cell's own — a different set of names in each cell, so each has its own
# five.)
#
# The foundation's placeholder (`not-issued`) is not a certificate, so it
# reads as "not issued yet".
#
# Writes exactly what tls.certificateFile and tls.keyFile name:
#   ${STS_TLS_DIR}/certificate.pem   the leaf FIRST, then its issuers
#   ${STS_TLS_DIR}/key.pem           the key, unencrypted, 0400
#
# A node that cannot get the certificate must FAIL, and the unit then keeps
# iya-sts from starting — a node serving a self-signed certificate under a
# public name would look healthy (AWS's argument, word for word).
# ---------------------------------------------------------------------------
set -euo pipefail
. /usr/local/lib/sts/lib.sh

: "${STS_TLS_SECRET:?STS_TLS_SECRET is required}"
: "${STS_TLS_HOSTNAME:?STS_TLS_HOSTNAME is required}"
: "${STS_VAULT_URL:?STS_VAULT_URL is required}"
: "${AZURE_CLIENT_ID:?AZURE_CLIENT_ID is required}"
: "${AZURE_SUBSCRIPTION_ID:?AZURE_SUBSCRIPTION_ID is required}"
: "${AZURE_RESOURCE_GROUP:?AZURE_RESOURCE_GROUP is required}"
: "${AZURE_ZONE_NAME:?AZURE_ZONE_NAME is required}"
OUT="${STS_TLS_DIR:-/run/sts/tls}"
ISSUER="${STS_CERT_ISSUER:-false}"
RENEW_DAYS="${STS_ACME_RENEW_DAYS:-30}"
ACME_SERVER="${STS_ACME_SERVER:-https://acme-v02.api.letsencrypt.org/directory}"
ATTEMPTS="${STS_CERT_WAIT_ATTEMPTS:-40}"
# EVERY NAME THE CERTIFICATE MUST CARRY: the host name, and in a cell its
# own console name too (#361, comma-separated). All of them are in the one
# Azure DNS zone.
NAMES=("${STS_TLS_HOSTNAME}")
IFS=',' read -r -a alt_names <<< "${STS_TLS_ALT_NAMES:-}"
for n in "${alt_names[@]}"; do
  [ -n "${n}" ] && NAMES+=("${n}")
done

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
umask 077
mkdir -p "${OUT}"

# Is ${1} (a bundle) a certificate for the host name with more than
# RENEW_DAYS left?
usable() {
  local bundle="$1" leaf="${work}/leaf.pem"
  openssl x509 -in "${bundle}" -out "${leaf}" 2> /dev/null || return 1
  openssl x509 -in "${leaf}" -noout -checkend "$((RENEW_DAYS * 86400))" \
    > /dev/null || return 1
  local n
  for n in "${NAMES[@]}"; do
    openssl x509 -in "${leaf}" -noout -checkhost "${n}" |
      grep -q 'does match' || return 1
  done
}

# Splits a bundle into the two files the node reads.
write_out() {
  local bundle="$1"
  openssl pkey -in "${bundle}" -out "${OUT}/key.pem"
  # Every certificate in the bundle, in order: the leaf first.
  awk '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/' \
    "${bundle}" > "${OUT}/certificate.pem"
  chmod 0444 "${OUT}/certificate.pem"
  chmod 0400 "${OUT}/key.pem"
  echo "sts-cert: wrote ${OUT}/certificate.pem and ${OUT}/key.pem"
  openssl x509 -in "${OUT}/certificate.pem" -noout -subject -issuer -dates
}

current="${work}/current.pem"
read_current() {
  local rc=0
  sts_secret_read "${STS_TLS_SECRET}" > "${current}" || rc=$?
  return "${rc}"
}

rc=0
read_current || rc=$?
if [ "${rc}" -eq 0 ] && usable "${current}";
then
  echo "sts-cert: the certificate in ${STS_TLS_SECRET} is current."
  write_out "${current}"
  exit 0
fi
if [ "${rc}" -ne 0 ] && [ "${rc}" -ne 3 ];
then
  echo "sts-cert: could not read ${STS_TLS_SECRET}." >&2
  exit 1
fi

if [ "${ISSUER}" != "true" ];
then
  attempt=0
  until read_current && usable "${current}"; do
    attempt=$((attempt + 1))
    if [ "${attempt}" -ge "${ATTEMPTS}" ];
    then
      echo "sts-cert: no current certificate for ${STS_TLS_HOSTNAME} in" \
           "${STS_TLS_SECRET} after ${attempt} attempts; node-a issues it." >&2
      exit 1
    fi
    echo "sts-cert: waiting for node-a to issue the certificate" \
         "(attempt ${attempt})." >&2
    sleep 15
  done
  write_out "${current}"
  exit 0
fi

# node-a: issue. A fresh ACME account each time — nothing about the account
# is worth keeping between issuances sixty days apart, and not keeping it
# means no account key to store.
echo "sts-cert: obtaining a certificate for ${NAMES[*]} from ${ACME_SERVER}."
domain_args=()
for n in "${NAMES[@]}"; do
  domain_args+=(--domains "${n}")
done
email_args=()
[ -z "${STS_ACME_EMAIL:-}" ] || email_args=(--email "${STS_ACME_EMAIL}")
# lego's `azuredns` provider with the VM's MANAGED IDENTITY
# (AZURE_AUTH_METHOD=msi, AZURE_CLIENT_ID): it writes and removes
# `_acme-challenge.<name>` TXT records in AZURE_ZONE_NAME, which is all the
# foundation's role lets this identity do there. The zone is named, so lego
# need not list the subscription's zones.
AZURE_AUTH_METHOD=msi \
AZURE_ENVIRONMENT=public \
AZURE_PRIVATE_ZONE=false \
AZURE_TTL="${AZURE_TTL:-60}" \
AZURE_PROPAGATION_TIMEOUT="${AZURE_PROPAGATION_TIMEOUT:-600}" \
AZURE_POLLING_INTERVAL="${AZURE_POLLING_INTERVAL:-10}" \
  lego --accept-tos "${email_args[@]}" \
    --server "${ACME_SERVER}" \
    --path "${work}/lego" \
    --key-type ec256 \
    --dns azuredns \
    "${domain_args[@]}" \
    run

crt="${work}/lego/certificates/${STS_TLS_HOSTNAME}.crt"
key="${work}/lego/certificates/${STS_TLS_HOSTNAME}.key"
bundle="${work}/bundle.pem"
# The key FIRST, then lego's .crt, which is the leaf followed by its issuers.
cat "${key}" "${crt}" > "${bundle}"
usable "${bundle}" || {
  echo "sts-cert: the new certificate does not name ${NAMES[*]} or is already near expiry." >&2
  exit 1
}

version="$(sts_secret_add "${STS_TLS_SECRET}" "${bundle}")"
echo "sts-cert: stored as ${version}."
sts_secret_disable_others "${STS_TLS_SECRET}" "${version}"
write_out "${bundle}"
