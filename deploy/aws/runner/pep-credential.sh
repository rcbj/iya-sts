#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# File: deploy/aws/runner/pep-credential.sh
#
# ---------------------------------------------------------------------------
# THE SUITE TASK'S FIRST CONTAINER: the remote PEP's assertion key.
#
# What ./run-tests.sh's mintThePepCredential() does, for the task in
# environment/runner.tf: generate the key the PEP signs its RFC 7523
# self-assertion and DPoP proofs with, and its certificate request, with
# tests/tools/pep-credential.js --assertion --csr-only, and leave them on the
# task's shared volume at /shared/pep, with server/ made for the listener
# pair the job writes later. sts_xacml_remote_pep sends the request to
# issue-pep-credential once it has made the PEP's entry in its realm.
#
# NO CLIENT CERTIFICATE SINCE PHASE 4 OF #1827's FOLLOW-UP (rcbj,
# 2026-11-16). Until then this also minted a Root, an Issuing CA and a TLS
# client leaf (adding the Root through POST /admin-api/tls/trust/add, with a
# management API token), named the PEP's CRL distribution point, and the job
# stored the leaf on the PEP's entry. The PEP no longer presents a client
# certificate, so none of that is done and the container needs no secret.
#
# A FAILURE IS NOT THE RUN'S: the PEP starts without a key, every
# /xacml/pep call it makes is refused, and sts_xacml_remote_pep says so. The
# container exits 0 either way so the PEP's `COMPLETE` dependency is met.
# ---------------------------------------------------------------------------
set -uo pipefail

URL="${STS_SUITE_SERVICE_URL:?STS_SUITE_SERVICE_URL is required}"
URL="${URL%/}"
OUT=/shared/pep

mkdir -p "${OUT}/server"
chmod 0777 "${OUT}" "${OUT}/server"

# THE TASK'S ADDRESS, FOR THE PEP CONTAINER TOO (2026-11-14). The remote PEP
# is a Rust binary in an image with no node (#444), so it cannot ask the task
# metadata endpoint itself; it builds PEP_NOTIFY_URL from ${OUT}/task-ip,
# written here before anything that can fail, and falls back to
# `hostname -I` when the file is empty.
TASK_IP="$(node -e "fetch(process.env.ECS_CONTAINER_METADATA_URI_V4+'/task').then(r=>r.json()).then(t=>process.stdout.write(t.Containers[0].Networks[0].IPv4Addresses[0]))" 2>/dev/null || true)"
printf '%s' "${TASK_IP}" > "${OUT}/task-ip" 2>/dev/null || true
chmod 0644 "${OUT}/task-ip" 2>/dev/null || true

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

# THE ASSERTION KEY AND ITS REQUEST (#1827's follow-up, phase 3): the PEP
# signs its RFC 7523 self-assertion with it (PEP_ASSERTION_KEY), and
# sts_xacml_remote_pep sends the request to issue-pep-credential once it has
# made the PEP's entry in its realm, which does not exist yet here. The key
# never leaves this volume. 0644: the PEP container is another user.
if node tests/tools/pep-credential.js --assertion --csr-only --out="${OUT}" \
     --name="${XACML_PEP_NAME:-remote-pep-1}" > /dev/null;
then
  chmod 0644 "${OUT}/pep-assertion.key" 2>/dev/null || true
  echo "pep-credential: generated the assertion key and its request in ${OUT}."
else
  echo "pep-credential: the assertion key could not be generated; the PEP" \
       "cannot authenticate and sts_xacml_remote_pep will say so." >&2
fi
exit 0
