#!/usr/bin/env bash
#
# File: tests/scim-conformance/build-test-suite.sh
#
# ---------------------------------------------------------------------------
# THE SECOND SCIM HARNESS, scim2/test-suite, FETCHED AT A PINNED COMMIT,
# CHECKED BY SHA-256 AND COMPILED (#206, 2026-09-26).
#
#   github.com/scim2/test-suite   Apache-2.0   Go
#
# Run by the `scim2-test-suite` stage of tests/Dockerfile, in a golang image,
# at image build time; the stage's only output is <dest>: the compiled test
# binary (`go test -c ./compliance/`), the upstream LICENSE and COMMIT. The
# runner image copies that directory and has no Go toolchain. Nothing is
# vendored and nothing it writes is committed.
#
# WHY IT IS HERE AT ALL: scim2-tester (the harness #206 names) exercises
# discovery, create, read, replace, PATCH and delete per resource type and
# the `attributes` parameter, and NOTHING ELSE — no filter expression, no
# sortBy, no startIndex/count, no Bulk, no ETag/If-Match, no error-format
# check beyond one random URL. The ticket's instruction was to evaluate
# scim2/test-suite for what scim2-tester leaves uncovered; it covers every
# one of those, requirement by requirement against the RFC 7643 and 7644
# text, so it runs beside it. tests/CLAUDE.md, *The SCIM conformance
# harnesses*, is the provenance.
#
# THE PIN IS A COMMIT because upstream has tagged no release. A tarball that
# does not match stops the build: a harness that changed under us is a
# different test. The Go modules it needs are checked by go.sum, which is
# upstream's.
#
#   tests/scim-conformance/build-test-suite.sh <destination directory>
# ---------------------------------------------------------------------------
set -euo pipefail

DEST="${1:?usage: build-test-suite.sh <destination directory>}"
COMMIT=3d80a46970a02ce114efeeb38f3f112b5d736d16
SHA256=da76d730fd562a3c8221995810accb0db0616d2292fed0cf37ff53286c9bcb75
WORK="$(mktemp -d)"

curl -fsSL --retry 5 --retry-all-errors --retry-delay 10 \
  -o "${WORK}/test-suite.tar.gz" \
  "https://github.com/scim2/test-suite/archive/${COMMIT}.tar.gz"
echo "${SHA256}  ${WORK}/test-suite.tar.gz" | sha256sum -c -
tar -xzf "${WORK}/test-suite.tar.gz" -C "${WORK}"
mkdir -p "${DEST}"
( cd "${WORK}/test-suite-${COMMIT}" \
  && go test -c -o "${DEST}/scim-compliance" ./compliance/ \
  && cp LICENSE "${DEST}/LICENSE" )
echo "${COMMIT}" > "${DEST}/COMMIT"
rm -rf "${WORK}"
echo "build-test-suite.sh: scim2/test-suite ${COMMIT} in ${DEST}"
