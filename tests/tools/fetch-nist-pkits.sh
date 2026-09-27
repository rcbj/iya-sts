#!/usr/bin/env bash
#
# File: tests/tools/fetch-nist-pkits.sh
#
# ---------------------------------------------------------------------------
# NIST PKITS, FETCHED WHEN THE TESTS IMAGE IS BUILT AND NEVER COMMITTED (#201).
#
# The Public Key Interoperability Test Suite (NIST, csrc.nist.gov/projects/
# pki-testing) is 405 certificates and 173 CRLs whose paths exercise RFC 5280
# section 6 — signatures, validity, names, basic constraints, key usage,
# certificate POLICIES, policy mappings and constraints, name constraints,
# distribution points and delta CRLs. The data also carries a PKCS #12 with
# every private key, and this repository commits no key material, so the
# archive is fetched here and refused unless its SHA-256 is the one recorded
# below. PKITS.pdf, the document that states each test's expected result, is
# fetched and pinned beside it.
#
# THE TEST TABLE is the PDF's section 4 as BoringSSL's generator transcribed
# it (`pki/testdata/nist-pkits/pkits_testcases-inl.h`, ISC-licensed; its
# generator reads the PDF itself): every test, every subpart's inputs —
# initial-policy-set, initial-explicit-policy, initial-policy-mapping-inhibit,
# initial-inhibit-any-policy — and the expected result and
# user-constrained-policy-set. It holds no key material; it is fetched at a
# pinned commit rather than transcribed a second time by hand, because a
# second hand transcription is a second place for a policy test's
# expectation to be wrong.
#
# Usage: fetch-nist-pkits.sh <destination directory>
# ---------------------------------------------------------------------------
set -euo pipefail

DEST="${1:?usage: fetch-nist-pkits.sh <destination directory>}"

NIST="https://csrc.nist.gov/CSRC/media/Projects/PKI-Testing/documents"
PKITS_DATA_SHA256="592f66030d2eff80fced7ad022e197d96b7ee4ccce7da9df9c9b2007b1665665"
PKITS_PDF_SHA256="506913f4b727704ee1b52b17aa472dc6fbcf01e41e7ad88ba505f29c1a74d9ea"

BSSL_COMMIT="bc97b7a8e1952bab69fea961301a90e5ad3344e9"
BSSL="https://raw.githubusercontent.com/google/boringssl/${BSSL_COMMIT}"
BSSL_TABLE_SHA256="787949eaf716e5e10b57f3a09765d643fa52fb3f7e14330219c27331a834af22"
BSSL_LICENSE_SHA256="a78d37138db9a43843736b2973284b61af19cd5384cf3c752e922171b0d4fc56"

mkdir -p "${DEST}"

fetch() {
  local url="$1" out="$2" want="$3"
  echo "fetch-nist-pkits.sh: ${url}"
  curl -fsSL --retry 5 --retry-all-errors --retry-delay 10 \
       -o "${DEST}/${out}" "${url}"
  local got
  got="$(sha256sum "${DEST}/${out}" | cut -d' ' -f1)"
  if [ "${got}" != "${want}" ]; then
    echo "fetch-nist-pkits.sh: ${out} has SHA-256 ${got}, not the pinned" >&2
    echo "  ${want}. Nothing is run against a corpus nobody checked." >&2
    rm -f "${DEST}/${out}"
    exit 1
  fi
}

fetch "${NIST}/PKITS_data.zip" PKITS_data.zip "${PKITS_DATA_SHA256}"
fetch "${NIST}/PKITS.pdf" PKITS.pdf "${PKITS_PDF_SHA256}"
fetch "${BSSL}/pki/testdata/nist-pkits/pkits_testcases-inl.h" \
      pkits_testcases-inl.h "${BSSL_TABLE_SHA256}"
fetch "${BSSL}/LICENSE" BORINGSSL-LICENSE "${BSSL_LICENSE_SHA256}"
(cd "${DEST}" && unzip -q -o PKITS_data.zip certs/'*' crls/'*' \
   && rm -f PKITS_data.zip)
echo "${BSSL_COMMIT}" > "${DEST}/TABLE_COMMIT"
echo "fetch-nist-pkits.sh: PKITS verified in ${DEST}."
