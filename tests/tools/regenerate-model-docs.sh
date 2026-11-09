#!/bin/bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# tests/tools/regenerate-model-docs.sh — WRITES THE MODEL READING PAGES.
#
# A change to the directory or persistence model owes this, in the same
# change: tests/model_directory.js and tests/model_postgres.js fail when
# the committed pages or TypeSpec differ. It runs in the tests image,
# because the emitter is compiled only in an image build. It writes
#
#   models/persistence/persistence.tsp
#   docs/data-model-directory.md
#   docs/data-model-persistence.md
#
set -euo pipefail

cd "$(dirname "$(realpath "$0")")/../.."

TAG="${STS_NPM_TEST_IMAGE:-iya-sts-npm-test:model-docs}"
tests/tools/corpora-preflight.sh
# shellcheck disable=SC2046
docker build -q $(tests/tools/mirror-contexts.sh) -f tests/Dockerfile \
  -t "${TAG}" . > /dev/null
mkdir -p docs models/directory models/persistence
docker run --rm --label com.docker.compose.project=none \
  -v "${PWD}/docs:/out/docs" \
  -v "${PWD}/models:/out/models" \
  "${TAG}" bash -c \
  "node common/model_emit.js --docs && \
   cp docs/data-model-directory.md docs/data-model-persistence.md /out/docs/ && \
   cp models/persistence/persistence.tsp /out/models/persistence/ && \
   chown $(id -u):$(id -g) \
     /out/docs/data-model-directory.md \
     /out/docs/data-model-persistence.md \
     /out/models/persistence/persistence.tsp"
