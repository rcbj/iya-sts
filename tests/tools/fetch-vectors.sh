#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# File: tests/tools/fetch-vectors.sh
#
# ---------------------------------------------------------------------------
# THE EXTERNAL TEST-VECTOR CORPORA, FETCHED AT A PINNED COMMIT AND
# CHECKED BY SHA-256 (#202, #203, 2026-09-24; the HPKE ones #82, 2026-09-27).
#
#   C2SP Wycheproof   Apache-2.0      -> <dest>/wycheproof/
#   NIST ACVP-Server  public domain   -> <dest>/acvp/<vector set>/
#   HPKE and JOSE-HPKE   IETF / IRTF  -> <dest>/hpke/
#     draft-ietf-hpke-pq's test-vectors.json (hpkewg/hpke-pq), the concrete
#     hybrid KEM draft's (cfrg/draft-irtf-cfrg-concrete-hybrid-kems) and the
#     JOSE working group's HPKE JWEs (ietf-wg-jose/draft-ietf-jose-hpke-
#     encrypt, tag draft-ietf-jose-hpke-encrypt-22), each a contribution
#     under BCP 78 and the IETF Trust Legal Provisions — tests/jwe_pq_kem.js
#
# Run by tests/Dockerfile at IMAGE BUILD TIME, above the source copy, so the
# layer is cached until this file or tests/tools/vectors.sha256 changes. It
# is never needed on a checkout and nothing it writes is committed
# (tests/vectors/ is in .gitignore and .dockerignore): both corpora carry
# test keys — private RSA and EC keys, ML-DSA and ML-KEM seeds — and this
# repository commits no key material, generated or borrowed.
# tests/CLAUDE.md, *The external test vectors*, carries the provenance and
# the licences.
#
# A checksum that does not match stops the build. That is the point of the
# pin: a vector file that changed under us is a different test, and a pass
# against it says nothing about the one this commit was reviewed with.
#
#   tests/tools/fetch-vectors.sh <destination directory>
# ---------------------------------------------------------------------------
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
DEST="${1:?usage: fetch-vectors.sh <destination directory>}"
SUMS="${HERE}/vectors.sha256"

# The pins. Change them only together with vectors.sha256.
WYCHEPROOF_COMMIT=3fa63dd0344abb611f1fb1d77e119938603ea230
ACVP_COMMIT=975de31eb83d87039ec88934fdc47d8c312b892d
HPKE_PQ_COMMIT=6433c8fce0b8b749dfc86c1095081a88698ccfab
CONCRETE_HYBRID_COMMIT=e76e1939fb5bec71d3d6c206de20ca2c008f1f80
JOSE_HPKE_COMMIT=2fa0c6b2b6d82013aa87a6d83c121de6f2fec3f0
ACVP_SETS="ML-DSA-keyGen-FIPS204 ML-DSA-sigGen-FIPS204
           ML-DSA-sigGen-FIPS204-tr1 ML-DSA-sigVer-FIPS204
           ML-KEM-keyGen-FIPS203 ML-KEM-encapDecap-FIPS203
           ML-KEM-encapDecap-FIPS203-tr1 SLH-DSA-keyGen-FIPS205
           SLH-DSA-sigGen-FIPS205 SLH-DSA-sigVer-FIPS205"

fetch() {
  # $1 the URL, $2 the file to write
  curl -fsSL --retry 5 --retry-all-errors --retry-delay 10 -o "$2" "$1"
}

mkdir -p "${DEST}/wycheproof" "${DEST}/acvp" "${DEST}/hpke"

# Wycheproof: ONE archive of the whole tree at the commit, so that every
# vector file upstream has is present and tests/wycheproof.js can classify
# each one — applied, or not applicable with the reason. Only the vectors and
# the licence are kept.
fetch "https://github.com/C2SP/wycheproof/archive/${WYCHEPROOF_COMMIT}.tar.gz" \
      "${DEST}/wycheproof.tar.gz"
( cd "${DEST}" && grep ' wycheproof.tar.gz$' "${SUMS}" | sha256sum -c - )
tar -xzf "${DEST}/wycheproof.tar.gz" -C "${DEST}/wycheproof" \
    --strip-components=1 \
    "wycheproof-${WYCHEPROOF_COMMIT}/testvectors_v1" \
    "wycheproof-${WYCHEPROOF_COMMIT}/LICENSE"
rm -f "${DEST}/wycheproof.tar.gz"
echo "${WYCHEPROOF_COMMIT}" > "${DEST}/wycheproof/COMMIT"

# ACVP: the repository is far too large to take whole, so each vector set
# for an algorithm this service has is fetched as its internalProjection.json
# — the prompt, the expected results and each case's metadata in one file.
for SET in ${ACVP_SETS}; do
  mkdir -p "${DEST}/acvp/${SET}"
  fetch "https://raw.githubusercontent.com/usnistgov/ACVP-Server/${ACVP_COMMIT}/gen-val/json-files/${SET}/internalProjection.json" \
        "${DEST}/acvp/${SET}/internalProjection.json"
done
( cd "${DEST}" && grep ' acvp/' "${SUMS}" | sha256sum -c - )
echo "${ACVP_COMMIT}" > "${DEST}/acvp/COMMIT"

# HPKE, the hybrid KEMs and JOSE-HPKE (#82): three JSON files, each from
# the document's own repository at the commit the pinned draft was cut from.
fetch "https://raw.githubusercontent.com/hpkewg/hpke-pq/${HPKE_PQ_COMMIT}/test-vectors.json" \
      "${DEST}/hpke/hpke-pq.json"
fetch "https://raw.githubusercontent.com/cfrg/draft-irtf-cfrg-concrete-hybrid-kems/${CONCRETE_HYBRID_COMMIT}/test-vectors.json" \
      "${DEST}/hpke/concrete-hybrid-kems.json"
fetch "https://raw.githubusercontent.com/ietf-wg-jose/draft-ietf-jose-hpke-encrypt/${JOSE_HPKE_COMMIT}/examples/jose-vectors.json" \
      "${DEST}/hpke/jose-hpke.json"
( cd "${DEST}" && grep ' hpke/' "${SUMS}" | sha256sum -c - )
printf 'hpke-pq %s\nconcrete-hybrid-kems %s\njose-hpke-encrypt %s\n' \
  "${HPKE_PQ_COMMIT}" "${CONCRETE_HYBRID_COMMIT}" "${JOSE_HPKE_COMMIT}" \
  > "${DEST}/hpke/COMMIT"

echo "fetch-vectors.sh: Wycheproof ${WYCHEPROOF_COMMIT}, ACVP" \
     "${ACVP_COMMIT} and the HPKE vectors in ${DEST}"
