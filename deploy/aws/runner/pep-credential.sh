#!/usr/bin/env bash
#
# File: deploy/aws/runner/pep-credential.sh
#
# ---------------------------------------------------------------------------
# THE SUITE TASK'S FIRST CONTAINER: the remote PEP's client certificate.
#
# What ./run-tests.sh's mintThePepCredential() does, for the task in
# environment/runner.tf: wait for the load balancer, mint a Root, an Issuing
# CA and a TLS client leaf with tests/tools/pep-credential.js (which POSTs the
# Root to /tls/trust), and leave them on the task's shared volume at
# /shared/pep, with server/ made for the listener pair the job writes later.
#
# A FAILURE IS NOT THE RUN'S: the PEP starts without a certificate, every
# /xacml/pep call it makes is refused, and sts_xacml_remote_pep says so. The
# container exits 0 either way so the PEP's `COMPLETE` dependency is met.
# ---------------------------------------------------------------------------
set -uo pipefail

URL="${STS_SUITE_SERVICE_URL:?STS_SUITE_SERVICE_URL is required}"
URL="${URL%/}"
OUT=/shared/pep
SUBJECT="${XACML_PEP_SUBJECT:-CN=remote-pep-1,OU=remote-peps,O=mock-sts}"

mkdir -p "${OUT}/server"
chmod 0777 "${OUT}" "${OUT}/server"

deadline=$(( $(date +%s) + ${STS_SUITE_WAIT_SECS:-900} ))
until node -e '
  require("https").get(process.argv[1] + "/healthcheck",
    { rejectUnauthorized: false, timeout: 5000 },
    function (r) { process.exit(r.statusCode === 200 ? 0 : 1); })
    .on("error", function () { process.exit(1); })
    .on("timeout", function () { process.exit(1); });' "${URL}";
do
  if [ "$(date +%s)" -ge "${deadline}" ];
  then
    echo "pep-credential: ${URL}/healthcheck did not answer; no credential." >&2
    exit 0
  fi
  sleep 5
done

# A PRODUCT-MODE SERVICE ACCEPTS AN ANCHOR ONLY THROUGH /admin-api
# (2026-09-18), so the credential step mints the management API's token when
# the task hands it the client secret; pep-credential.js tries that door first.
if [ -n "${STS_ADMIN_API_CLIENT_SECRET:-}" ];
then
  STS_ADMIN_API_TOKEN="$(node tests/tools/admin-api-token.js "${URL}")" || \
    STS_ADMIN_API_TOKEN=""
  export STS_ADMIN_API_TOKEN
fi

if node tests/tools/pep-credential.js --url="${URL}" --out="${OUT}" \
     --subject="${SUBJECT}";
then
  # The PEP container runs as another user; this key lives for one run.
  chmod 0644 "${OUT}/pep.key" 2>/dev/null || true
  echo "pep-credential: minted ${SUBJECT} into ${OUT}."
else
  echo "pep-credential: the credential could not be minted; the PEP starts" \
       "without one and sts_xacml_remote_pep will say so." >&2
fi
exit 0
