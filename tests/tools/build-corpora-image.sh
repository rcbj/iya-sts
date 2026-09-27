#!/usr/bin/env bash
#
# File: tests/tools/build-corpora-image.sh
#
# ---------------------------------------------------------------------------
# BUILD THE TEST CORPORA IMAGE, PUSH IT TO GHCR.IO, AND SAY WHICH DIGEST TO PIN
# (#253, 2026-09-26).
#
#   tests/tools/build-corpora-image.sh            build, then push and pin
#   tests/tools/build-corpora-image.sh --no-push  build only (a local check)
#
# Run it when a corpus pin changes: one of the five fetch scripts, or
# tests/tools/w3c-xmlsec.sha256 / vectors.sha256 / tests/xml-schemas.
# tests/corpora/Dockerfile says what goes in and why the image is PRIVATE.
#
# What it does:
#   1. builds tests/corpora/Dockerfile from the repository root, where each
#      fetch script verifies every file's sha256 as it always did;
#   2. tags it ghcr.io/rcbj/iya-sts-test-corpora:<UTC date>-<commit>, and
#      pushes that tag (and `latest`);
#   3. reads back the REGISTRY digest and rewrites the default of
#      STS_CORPORA_IMAGE at the top of tests/Dockerfile to it, so the next
#      commit pins exactly what was pushed. It does not commit.
#
# Pushing needs `docker login ghcr.io` with a token holding write:packages
# (`gh auth refresh -h github.com -s write:packages,read:packages`, then
# `gh auth token | docker login ghcr.io -u <user> --password-stdin`). A NEW
# package on ghcr.io is PRIVATE, which is what this one must stay.
# ---------------------------------------------------------------------------
set -euo pipefail

cd "$(dirname "$0")/../.."

REPO="${STS_CORPORA_REPO:-ghcr.io/rcbj/iya-sts-test-corpora}"
PUSH=1
if [ "${1:-}" = "--no-push" ]; then
  PUSH=0
fi

stamp="$(date -u +%Y%m%d)-$(git rev-parse --short HEAD)"
echo "build-corpora-image: building ${REPO}:${stamp}"
# --network=host: this machine's docker has no BuildKit and its bridge has
# failed builds before (npm "Exit handler never called").
docker build --network=host -f tests/corpora/Dockerfile \
  --label "org.opencontainers.image.source=https://github.com/rcbj/iya-sts" \
  --label "org.opencontainers.image.description=iya-sts third-party test corpora (private: carries published test private keys)" \
  -t "${REPO}:${stamp}" -t "${REPO}:latest" .

if [ "${PUSH}" = 0 ]; then
  echo "build-corpora-image: built ${REPO}:${stamp}; not pushed (--no-push)."
  exit 0
fi

docker push "${REPO}:${stamp}"
docker push "${REPO}:latest"

digest="$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' \
            "${REPO}:${stamp}" | grep "^${REPO}@sha256:" | head -1)"
if [ -z "${digest}" ]; then
  echo "build-corpora-image: pushed, but no registry digest was reported for" \
       "${REPO}:${stamp}. Pin it by hand in tests/Dockerfile." >&2
  exit 1
fi

# The one line tests/Dockerfile pins: `ARG STS_CORPORA_IMAGE=<repo>@sha256:…`.
sed -i "s#^ARG STS_CORPORA_IMAGE=.*#ARG STS_CORPORA_IMAGE=${digest}#" \
  tests/Dockerfile
echo "build-corpora-image: pushed ${REPO}:${stamp}"
echo "build-corpora-image: tests/Dockerfile now pins ${digest}"
echo "build-corpora-image: commit tests/Dockerfile to use it."
