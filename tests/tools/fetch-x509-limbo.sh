#!/usr/bin/env bash
#
# File: tests/tools/fetch-x509-limbo.sh
#
# ---------------------------------------------------------------------------
# C2SP x509-limbo, FETCHED WHEN THE TESTS IMAGE IS BUILT AND NEVER COMMITTED
# (#201).
#
# `limbo.json` is the whole corpus `tests/x509_limbo.js` drives through every
# certificate path validator in this service: about ten thousand testcases,
# each a set of trusted certificates, untrusted intermediates, a leaf and the
# answer a conforming validator gives. It is Apache-2.0 — but about two
# hundred of those cases carry the leaf's PRIVATE KEY (`peer_certificate_key`),
# and this repository commits no key material of any kind, test keys in a
# published corpus included (rcbj's rule). So it is fetched here, at a pinned
# commit, and refused unless its SHA-256 is the one recorded below: a moved
# branch or a rewritten file is a build failure, never a different suite.
#
# The pin is moved by hand, in one commit that changes the two values below and
# whatever the new corpus makes `tests/x509_limbo.js` say — its denominator and
# its exceptions are checked against THIS corpus, so a pin moved on its own
# fails that file first.
#
# Usage: fetch-x509-limbo.sh <destination directory>
# Writes <dest>/limbo.json and <dest>/LICENSE.
# ---------------------------------------------------------------------------
set -euo pipefail

DEST="${1:?usage: fetch-x509-limbo.sh <destination directory>}"

# The commit of github.com/C2SP/x509-limbo the corpus is read at (2026-09-24,
# "Add testcases exercising general CRL structure (#577)").
LIMBO_COMMIT="554528a9b0c0d95e071f55de018326f0b65a8364"
LIMBO_JSON_SHA256="611e337b9fb477b927bae65434650692cb9d2070ff5b05f975d0403510acd4de"
LIMBO_LICENSE_SHA256="aac73b3148f6d1d7111dbca32099f68d26c644c6813ae1e4f05f6579aa2663fe"

BASE="https://raw.githubusercontent.com/C2SP/x509-limbo/${LIMBO_COMMIT}"

mkdir -p "${DEST}"

fetch() {
  local name="$1" want="$2"
  echo "fetch-x509-limbo.sh: ${BASE}/${name}"
  curl -fsSL --retry 5 --retry-all-errors --retry-delay 10 \
       -o "${DEST}/${name}" "${BASE}/${name}"
  local got
  got="$(sha256sum "${DEST}/${name}" | cut -d' ' -f1)"
  if [ "${got}" != "${want}" ]; then
    echo "fetch-x509-limbo.sh: ${name} has SHA-256 ${got}, not the pinned" >&2
    echo "  ${want}. The corpus at ${LIMBO_COMMIT} is not what was" >&2
    echo "  recorded; nothing is run against a corpus nobody checked." >&2
    rm -f "${DEST}/${name}"
    exit 1
  fi
}

fetch limbo.json "${LIMBO_JSON_SHA256}"
fetch LICENSE "${LIMBO_LICENSE_SHA256}"
echo "${LIMBO_COMMIT}" > "${DEST}/COMMIT"
echo "fetch-x509-limbo.sh: x509-limbo ${LIMBO_COMMIT} verified in ${DEST}."
