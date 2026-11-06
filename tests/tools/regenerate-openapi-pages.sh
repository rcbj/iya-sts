#!/bin/bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# tests/tools/regenerate-openapi-pages.sh — WRITES docs/openapi/ FROM THE CODE.
#
# A changed operation or response model owes this, in the same commit:
# tests/openapi_pages.js fails when the committed pages differ. It runs in the
# tests image, because the service is compiled only in an image build.
set -euo pipefail

cd "$(dirname "$(realpath "$0")")/../.."

TAG="${STS_NPM_TEST_IMAGE:-iya-sts-npm-test:openapi-pages}"
tests/tools/corpora-preflight.sh
# shellcheck disable=SC2046
docker build -q $(tests/tools/mirror-contexts.sh) -f tests/Dockerfile \
  -t "${TAG}" . > /dev/null
mkdir -p docs/openapi
docker run --rm --label com.docker.compose.project=none \
  -v "${PWD}/docs/openapi:/out" "${TAG}" bash -c \
  "node tests/tools/openapi_pages.js --write /out && \
   chown -R $(id -u):$(id -g) /out"
