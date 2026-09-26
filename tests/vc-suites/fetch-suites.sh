#!/usr/bin/env bash
#
# File: tests/vc-suites/fetch-suites.sh
#
# ---------------------------------------------------------------------------
# THE W3C VERIFIABLE CREDENTIALS AND DID TEST SUITES, FETCHED AT PINNED
# COMMITS, CHECKED BY SHA-256 AND INSTALLED (#194-#199, 2026-09-26).
#
#   w3c/vc-data-model-2.0-test-suite        #194  mocha
#   w3c/vc-di-eddsa-test-suite              #195  mocha
#   w3c/vc-di-ecdsa-test-suite              #196  mocha, + w3c/vc-di-ecdsa's
#                                                 TestVectors (its postinstall
#                                                 clones that repository's
#                                                 HEAD; here it is pinned)
#   w3c/vc-bitstring-status-list-test-suite #197  mocha
#   w3c/vc-jose-cose-test-suite             #198  mocha
#   w3c/did-test-suite                      #199  jest, lerna
#
# Run by the `vc-suites` stage of tests/Dockerfile at IMAGE BUILD TIME; the
# runner copies <dest> and nothing else. Nothing is vendored and nothing it
# writes is committed — several of these carry test PRIVATE keys (the ECDSA
# and JOSE/COSE suites' key files, vc-di-ecdsa's TestVectors), and this
# repository commits no key material.
#
# THE PINS. Each suite is a tarball of one commit (upstream tags none), and a
# tarball that does not hash to the sum below stops the build: a suite that
# changed under us is a different test. Its dependencies are its own
# package-lock.json, `npm ci`, which pins even the two GitHub dependencies
# (vc-test-suite-implementations, data-integrity-test-suite-assertion) to a
# commit. **THOSE SUITES' `pretest` IS NOT RUN** — it reinstalls
# vc-test-suite-implementations from `main`, which is an unpinned download at
# test time; the lockfile's commit is used instead, and the jobs run mocha
# directly. `--ignore-scripts` for the same reason (the ECDSA suite's
# postinstall is a `git clone` of a moving HEAD); the did-test-suite is the
# exception, because its lerna postinstall BUILDS its matcher package and
# reaches nothing unpinned.
#
# Licences: the VC suites are the W3C 3-clause BSD licence / W3C test suite
# licence (their LICENSE.md and LICENSES/); did-test-suite is W3C's
# (LICENSE.md). Each is kept in the suite's directory as it arrived.
#
#   tests/vc-suites/fetch-suites.sh <destination directory>
# ---------------------------------------------------------------------------
set -euo pipefail

DEST="${1:?usage: fetch-suites.sh <destination directory>}"
WORK="$(mktemp -d)"
mkdir -p "${DEST}"

# npm reaches the lockfiles' GitHub dependencies over https, not the ssh
# their lockfiles name: an image build holds no ssh key.
git config --global --add url."https://github.com/".insteadOf \
  "ssh://git@github.com/"
git config --global --add url."https://github.com/".insteadOf \
  "git@github.com:"

# repo commit sha256
SUITES="
w3c/vc-data-model-2.0-test-suite 62836458636bd1b8309214626ec8fc85de43f8bd da3b0a126d7d5dd1f6cb45e92037bd385eaccb938ab4e1a02939269018412fbf
w3c/vc-di-eddsa-test-suite 1e86cc4ca16d77eb76cd15e3905a624bc16c0879 2c89794ffe0e1c2458c8423f4794230f5433f0057359c630a0717d5110ff44fd
w3c/vc-di-ecdsa-test-suite 94dca21d8c1c7ad3dc31f21144d4d957567726b5 55535dee3d9762e03da7f1657c98e0670e3bc1696dfbbf338950f4702597dc9e
w3c/vc-bitstring-status-list-test-suite 960ab9a3ad275bb5e56dd3f300939f83cba759b7 f31a375fcc959a751bb74c9950d699a16d501643c40ce1cb83ed11cd8601be22
w3c/vc-jose-cose-test-suite cf4c93ddf7e1bfef5a3e5db4b9a798b02ea778a9 cfd0ebf7d61bc732eacdd5f39ed4c8bdfad4291bf6c8a6f47da96d9d2187b57b
w3c/did-test-suite 939b31d07d5b1699340ac0702ec0fa46ffcdef0a c4e464d3f49d265a4023f646a77db7abc0992ff844d3055c180cd1c1c86717bd
w3c/vc-di-ecdsa 59df72ca8cdb275d97eb496086fea6fac4fa7f0f c53b628f6c189fd23fdab59ce7da430869261326f96aa6067c6ab2690327b3be
"

fetch() {
  local repo="$1" commit="$2" sum="$3" name
  name="$(basename "${repo}")"
  curl -fsSL --retry 5 --retry-all-errors --retry-delay 10 \
    -o "${WORK}/${name}.tar.gz" \
    "https://github.com/${repo}/archive/${commit}.tar.gz"
  echo "${sum}  ${WORK}/${name}.tar.gz" | sha256sum -c -
  tar -xzf "${WORK}/${name}.tar.gz" -C "${WORK}"
  rm -rf "${DEST:?}/${name}"
  mv "${WORK}/${name}-${commit}" "${DEST}/${name}"
  echo "${commit}" > "${DEST}/${name}/COMMIT"
}

echo "${SUITES}" | while read -r repo commit sum; do
  [ -n "${repo}" ] || continue
  fetch "${repo}" "${commit}" "${sum}"
done

for suite in vc-data-model-2.0-test-suite vc-di-eddsa-test-suite \
             vc-di-ecdsa-test-suite vc-bitstring-status-list-test-suite \
             vc-jose-cose-test-suite; do
  ( cd "${DEST}/${suite}" \
    && npm ci --ignore-scripts --no-audit --no-fund \
    && npm cache clean --force )
done

# The ECDSA suite's vectors, where its postinstall would have cloned them.
mkdir -p "${DEST}/vc-di-ecdsa-test-suite/tests/input"
mv "${DEST}/vc-di-ecdsa" "${DEST}/vc-di-ecdsa-test-suite/tests/input/vc-di-ecdsa"

# The DID suite: its root postinstall bootstraps and builds the packages.
( cd "${DEST}/did-test-suite" \
  && npm ci --no-audit --no-fund \
  && npm cache clean --force )

rm -rf "${WORK}"
echo "fetch-suites.sh: the W3C VC and DID suites in ${DEST}"
