#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# File: tests/client-lab/smoke.sh
#
# ---------------------------------------------------------------------------
# THE CLIENT LAB, END TO END, FROM THE HOST (#2056). Not a stack: one lab
# container of its own and the tests image, nothing else, nothing published.
#
#   tests/client-lab/smoke.sh [--build]
#
#   1. every client answers and each card answers its own (bin/lab-smoke:
#      gpg --card-status on the OpenPGP card, yubico-piv-tool -a status on
#      the PIV card, OpenSC's PKCS#11 module seeing both);
#   2. the `yubikey` PIV card's attestation of a 9a key (bin/lab-piv-attest,
#      under a root made now) is ACCEPTED by the service's own verifier,
#      common/piv_attestation.ts, in process in the tests image
#      (verify-attestation.js) — piv-auth, tls-client and smartcard-logon —
#      and refused for piv-sign (STS-PIV-0008);
#   3. a STOCK PivApplet card's attestation is REFUSED: STS-PIV-0006 under a
#      YubiKey-named f9 certificate, STS-PIV-0007 (no serial) under an f9
#      certificate named as PivApplet's fixed issuer.
#
#   CLIENT_LAB_IMAGE    the lab image (default sts-client-lab:local; --build
#                       builds it from tests/client-lab first)
#   STS_NPM_TEST_IMAGE  the tests image (default iya-sts-npm-test:local, as
#                       ./docker-npm-test.sh builds it)
#
# The container is named after this process, so two runs, or a run beside
# a stack, never share one; it is removed on the way out.
# ---------------------------------------------------------------------------
set -euo pipefail

cd "$(dirname "$0")/../.."

LAB_IMAGE="${CLIENT_LAB_IMAGE:-sts-client-lab:local}"
TESTS_IMAGE="${STS_NPM_TEST_IMAGE:-iya-sts-npm-test:local}"
NAME="client-lab-smoke-$$"
OUT="$(mktemp -d)"
cleanup() {
  docker rm -f "${NAME}" > /dev/null 2>&1 || true
  rm -rf "${OUT:?}"
}
trap cleanup EXIT

if [ "${1:-}" = "--build" ]; then
  # shellcheck disable=SC2046
  docker build $(tests/tools/mirror-contexts.sh) -t "${LAB_IMAGE}" \
    tests/client-lab
fi

docker run -d --name "${NAME}" "${LAB_IMAGE}" > /dev/null
for i in $(seq 1 120); do
  if docker exec "${NAME}" curl -fsS http://127.0.0.1:9610/health \
       > /dev/null 2>&1; then
    break
  fi
  sleep 1
done
docker exec "${NAME}" curl -fsS http://127.0.0.1:9610/health
echo

fails=0
echo "=== 1. the clients and the cards"
if ! docker exec "${NAME}" /opt/client-lab/bin/lab-smoke; then
  fails=$((fails + 1))
fi

# One attestation made in the lab, copied out, and put to the verifier.
attest() {
  local dir="$1" f9="$2"
  shift 2
  docker exec "${NAME}" /opt/client-lab/bin/lab-piv-attest \
    "/run/client-lab/work/${dir}" 9a "${f9}" > "${OUT}/${dir}.log" 2>&1
  docker cp "${NAME}:/run/client-lab/work/${dir}" "${OUT}/${dir}"
  local script=tests/client-lab/verify-attestation.js
  if docker run --rm -v "${OUT}/${dir}:/attest:ro" \
       -v "${PWD}/${script}:/usr/src/sts/${script}:ro" \
       "${TESTS_IMAGE}" node tests/client-lab/verify-attestation.js \
       /attest "$@" > "${OUT}/${dir}.json" 2> "${OUT}/${dir}.err"; then
    echo "ok   ${dir}: $*"
  else
    echo "FAIL ${dir}: $*"
    cat "${OUT}/${dir}.json" "${OUT}/${dir}.err" | grep -v '^{"name"'
    fails=$((fails + 1))
  fi
}

echo "=== 2. the yubikey card's attestation is accepted"
attest yubikey "/CN=Yubico PIV Attestation" piv-auth=ok tls-client=ok \
  smartcard-logon=ok piv-sign=STS-PIV-0008

echo "=== 3. a stock PivApplet card's attestation is refused"
docker exec "${NAME}" /opt/client-lab/bin/lab-piv-card stock > /dev/null
attest stock-yubico-f9 "/CN=Yubico PIV Attestation" \
  piv-auth=STS-PIV-0006 tls-client=STS-PIV-0006
docker exec "${NAME}" /opt/client-lab/bin/lab-piv-card stock > /dev/null
attest stock-pivapplet-f9 "/CN=PIVApplet Attestation" \
  piv-auth=STS-PIV-0007 tls-client=STS-PIV-0007

if [ "${fails}" -ne 0 ]; then
  echo "client-lab smoke: ${fails} part(s) failed"
  exit 1
fi
echo "client-lab smoke: every part passed"
