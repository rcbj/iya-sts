#!/usr/bin/env bash
#
# File: tests/tlsfuzzer/build-tlsfuzzer.sh
#
# ---------------------------------------------------------------------------
# tlsfuzzer AND tlslite-ng, FETCHED AT PINNED COMMITS, CHECKED BY SHA-256,
# NEVER VENDORED (#212, 2026-09-26).
#
#   github.com/tlsfuzzer/tlsfuzzer   GPL-2.0    Python
#   github.com/tlsfuzzer/tlslite-ng  LGPL-2.1   Python (its TLS implementation)
#
# Run by tests/Dockerfile at image build time. The output is <dest>:
#   tlsfuzzer/   the upstream `tlsfuzzer/` package and `scripts/`, LICENSE,
#                README.md and COMMIT — NOT its `tests/` directory, which holds
#                about forty private keys this repository will not carry even
#                in an image (the job makes every key it needs at run time)
#   tlslite-ng/  the upstream `tlslite/` package, LICENSE and COMMIT
#   venv/        a virtual environment with requirements.txt's packages
#
# THE PINS ARE COMMITS. tlsfuzzer tags no releases; tlslite-ng's commit is
# the one its v0.9.0b2 tag names, which is the version tlsfuzzer's own
# requirements.txt asks for. A tarball that does not match stops the build:
# a fuzzer that changed under us is a different test.
#
# WHY NOT THE #253 CORPORA IMAGE: that image exists because a corpus was
# hundreds of paced fetches from hosts that rate-limit (w3.org answered 429
# for an hour). This is two tarballs from GitHub and four wheels from PyPI,
# fetched in a layer that only rebuilds when this script or requirements.txt
# changes; and it is GPL and LGPL code, which is better run from upstream
# than republished in a registry of ours.
#
#   tests/tlsfuzzer/build-tlsfuzzer.sh <destination> <requirements.txt>
# ---------------------------------------------------------------------------
set -euo pipefail

DEST="${1:?usage: build-tlsfuzzer.sh <destination> <requirements.txt>}"
REQUIREMENTS="${2:?usage: build-tlsfuzzer.sh <destination> <requirements.txt>}"
TLSFUZZER_COMMIT=5eebc4464e5197a7f7392fb9acda99cfc32441f7
TLSFUZZER_SHA256=d1848c68d58d49b3f74b8ef07d5bf3c67d8c25e93641b8d422bd786079858b6d
TLSLITE_COMMIT=02d1506badb16473faf50ebc3a413c6d789fe31f
TLSLITE_SHA256=767d0540522e790703fce5bdebc594bf97ce181688d86b1a9631fa34378221e3
WORK="$(mktemp -d)"

fetch() {
  local repo="$1" commit="$2" sha="$3"
  curl -fsSL --retry 5 --retry-all-errors --retry-delay 10 \
    -o "${WORK}/${repo}.tar.gz" \
    "https://github.com/tlsfuzzer/${repo}/archive/${commit}.tar.gz"
  echo "${sha}  ${WORK}/${repo}.tar.gz" | sha256sum -c -
  tar -xzf "${WORK}/${repo}.tar.gz" -C "${WORK}"
}

fetch tlsfuzzer "${TLSFUZZER_COMMIT}" "${TLSFUZZER_SHA256}"
fetch tlslite-ng "${TLSLITE_COMMIT}" "${TLSLITE_SHA256}"

mkdir -p "${DEST}/tlsfuzzer" "${DEST}/tlslite-ng"
SRC="${WORK}/tlsfuzzer-${TLSFUZZER_COMMIT}"
cp -r "${SRC}/tlsfuzzer" "${SRC}/scripts" "${SRC}/LICENSE" "${SRC}/README.md" \
  "${DEST}/tlsfuzzer/"
echo "${TLSFUZZER_COMMIT}" > "${DEST}/tlsfuzzer/COMMIT"
SRC="${WORK}/tlslite-ng-${TLSLITE_COMMIT}"
cp -r "${SRC}/tlslite" "${SRC}/LICENSE" "${DEST}/tlslite-ng/"
echo "${TLSLITE_COMMIT}" > "${DEST}/tlslite-ng/COMMIT"
if find "${DEST}" -name '*.pem' -o -name '*.key' | grep -q .; then
  echo "build-tlsfuzzer.sh: key material under ${DEST}; refusing" >&2
  exit 1
fi

python3 -m venv "${DEST}/venv"
"${DEST}/venv/bin/pip" install --no-cache-dir --require-hashes --no-deps \
  -r "${REQUIREMENTS}"
rm -rf "${WORK}"
echo "build-tlsfuzzer.sh: tlsfuzzer ${TLSFUZZER_COMMIT}, tlslite-ng" \
  "${TLSLITE_COMMIT} in ${DEST}"
