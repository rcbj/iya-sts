#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# File: deploy/gcp/node-init/cert.sh
#
# ---------------------------------------------------------------------------
# THE PUBLIC CERTIFICATE AND ITS KEY, LEFT WHERE THE NODE READS THEM — GCP's
# counterpart of deploy/aws/cert-init/export.sh.
#
# AWS exports an exportable ACM certificate on every start. Google releases
# the key of no certificate it issues, so here the certificate is an ACME one
# (Let's Encrypt by default), kept in the foundation's secret as ONE PEM
# BUNDLE — the key, then the leaf, then its issuers — and this script:
#
#   1. reads the bundle; if it names STS_TLS_HOSTNAME and has more than
#      STS_ACME_RENEW_DAYS left, writes it out and is done — every start of
#      every node but the first after an expiry;
#   2. otherwise, on node-a (STS_CERT_ISSUER=true), obtains a new one against
#      a DNS-01 challenge in the public zone, adds it as the secret's new
#      version, disables the old ones, and writes it out;
#   3. on the other nodes, waits for node-a to have done so — they start
#      after node-a is stable, so on a fresh environment it is already there.
#
# ONLY node-a ISSUES: three nodes issuing at once would spend three of the
# FIVE certificates a week Let's Encrypt allows for one name, and leave the
# secret with whichever finished last.
#
# Writes exactly what tls.certificateFile and tls.keyFile name:
#   ${STS_TLS_DIR}/certificate.pem   the leaf FIRST, then its issuers
#   ${STS_TLS_DIR}/key.pem           the key, unencrypted, 0400
#
# A node that cannot get the certificate must FAIL, and the unit then keeps
# mock-sts from starting — a node serving a self-signed certificate under a
# public name would look healthy (AWS's argument, word for word).
# ---------------------------------------------------------------------------
set -euo pipefail
. /usr/local/lib/sts/lib.sh

: "${STS_TLS_SECRET:?STS_TLS_SECRET is required}"
: "${STS_TLS_HOSTNAME:?STS_TLS_HOSTNAME is required}"
: "${GCE_PROJECT:?GCE_PROJECT is required}"
OUT="${STS_TLS_DIR:-/run/sts/tls}"
ISSUER="${STS_CERT_ISSUER:-false}"
RENEW_DAYS="${STS_ACME_RENEW_DAYS:-30}"
ACME_SERVER="${STS_ACME_SERVER:-https://acme-v02.api.letsencrypt.org/directory}"
ATTEMPTS="${STS_CERT_WAIT_ATTEMPTS:-40}"
# EVERY NAME THE CERTIFICATE MUST CARRY: the host name, and in a cell of a
# multi-cloud environment (#97) its own console name too (comma-separated).
# The cell's names are in Route 53, and each `_acme-challenge.<name>` there is
# a CNAME into the Cloud DNS zone (deploy/multicloud/interconnect), which
# lego follows — so the challenge is written here, with this VM's rights.
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
# GCE_ZONE_ID names the zone, so lego need not LIST the project's zones —
# the node's account holds dns.admin on this one zone and nothing else.
GCE_PROPAGATION_TIMEOUT="${GCE_PROPAGATION_TIMEOUT:-600}" \
GCE_POLLING_INTERVAL="${GCE_POLLING_INTERVAL:-10}" \
  lego --accept-tos "${email_args[@]}" \
    --server "${ACME_SERVER}" \
    --path "${work}/lego" \
    --key-type ec256 \
    --dns gcloud \
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
