#!/usr/bin/env bash
#
# File: deploy/aws/cert-init/export.sh
#
# ---------------------------------------------------------------------------
# EXPORT THE PUBLIC ACM CERTIFICATE AND LEAVE IT WHERE THE NODE READS IT.
#
# The task definition supplies every value and this script supplies none of
# its own, so what it writes and where is visible in one place:
#
#   STS_ACM_CERTIFICATE_ARN   the certificate to export (environment/dns.tf)
#   STS_TLS_DIR               the shared volume both containers mount
#   AWS_REGION                the region the certificate is in
#
# It writes exactly the two files `tls.certificateFile` and `tls.keyFile`
# name:
#
#   ${STS_TLS_DIR}/certificate.pem   the leaf FIRST, then its issuers — which
#                                    is the order that file must be in, and
#                                    what lets a client build a path to a root
#                                    it already holds
#   ${STS_TLS_DIR}/key.pem           the key, UNENCRYPTED, because this
#                                    service is never given a passphrase to
#                                    prompt for (common/config.js, tls.keyFile)
#
# THE PASSPHRASE IS THIS CONTAINER'S AND NOBODY ELSE'S. `ExportCertificate`
# will not hand over a key in the clear, so one is generated per run, used for
# the two calls that need it, and deleted on the way out. It is never a
# secret, never in the task definition and never logged: it exists for the
# few milliseconds between ACM encrypting the key and openssl decrypting it.
#
# IT RETRIES, because a task can start while the certificate is still being
# issued or while the task role's first credentials settle. It does NOT retry
# for ever: a node that cannot get the public certificate must fail, so that
# ECS stops it rather than letting it start and serve a self-signed
# certificate under a public name — which a browser would show as the one
# error this deployment exists to avoid.
# ---------------------------------------------------------------------------
set -euo pipefail

: "${STS_ACM_CERTIFICATE_ARN:?STS_ACM_CERTIFICATE_ARN is required}"

OUT="${STS_TLS_DIR:-/var/run/sts-tls}"
ATTEMPTS="${STS_CERT_EXPORT_ATTEMPTS:-20}"

work="$(mktemp -d)"
passfile="${work}/passphrase"
bundle="${work}/export.json"
# Whatever happens below, the passphrase and the JSON holding the encrypted
# key go with this shell. `EXIT` covers the `set -e` failures too.
cleanup() {
  rm -rf "${work}"
}
trap cleanup EXIT

mkdir -p "${OUT}"

# NO TRAILING NEWLINE. `fileb://` hands ACM the file's BYTES, so a newline
# would be part of the passphrase ACM encrypts under, while openssl's `file:`
# reads the first LINE and would leave it out — the two would disagree and the
# key would not decrypt, with an error about neither of them.
printf '%s' "$(openssl rand -hex 32)" > "${passfile}"
chmod 0400 "${passfile}"

attempt=0
until aws acm export-certificate \
        --certificate-arn "${STS_ACM_CERTIFICATE_ARN}" \
        --passphrase "fileb://${passfile}" \
        --output json > "${bundle}" 2> "${work}/error";
do
  attempt=$((attempt + 1))
  if [ "${attempt}" -ge "${ATTEMPTS}" ];
  then
    echo "sts-cert: could not export ${STS_ACM_CERTIFICATE_ARN} after" \
         "${attempt} attempts." >&2
    # The last error, once, at the end: the reason is nearly always one of
    # three and each names itself — the certificate was not requested as
    # exportable, the task role lacks acm:ExportCertificate, or the
    # permissions boundary does (deploy/aws/CLAUDE.md).
    cat "${work}/error" >&2
    exit 1
  fi
  echo "sts-cert: export attempt ${attempt} failed; retrying in 15s." >&2
  sleep 15
done

# THE LEAF FIRST, THEN THE CHAIN. `.Certificate` is the leaf and
# `.CertificateChain` the issuers above it; everything that reads a
# certificate back out of this file takes the FIRST one (the fingerprint, the
# subject, the names, `GET /tls/server-certificate`), so the order is not
# cosmetic.
jq -r '.Certificate' "${bundle}" > "${OUT}/certificate.pem"
jq -r '.CertificateChain' "${bundle}" >> "${OUT}/certificate.pem"

# `openssl pkey` takes the passphrase off and writes PKCS#8, which is one of
# the two shapes tls.keyFile accepts, whatever key algorithm the certificate
# was requested with.
jq -r '.PrivateKey' "${bundle}" |
  openssl pkey -passin "file:${passfile}" -out "${OUT}/key.pem"

chmod 0444 "${OUT}/certificate.pem"
chmod 0400 "${OUT}/key.pem"

# What was written, and for whom — the subject and the expiry, so the log says
# which certificate this node is about to serve without anybody fetching it.
# The key is never printed, and neither is the passphrase.
echo "sts-cert: wrote ${OUT}/certificate.pem and ${OUT}/key.pem"
openssl x509 -in "${OUT}/certificate.pem" -noout -subject -issuer -dates
echo "sts-cert: done."
