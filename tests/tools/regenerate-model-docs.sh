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
#   postgres/schema.sql
#   mariadb/schema.sql
#   types/domain.generated.d.ts
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
mkdir -p docs postgres mariadb
docker run --rm --label com.docker.compose.project=none \
  -v "${PWD}/docs:/out/docs" \
  -v "${PWD}/postgres:/out/postgres" \
  -v "${PWD}/mariadb:/out/mariadb" \
  -v "${PWD}/types:/out/types" \
  "${TAG}" bash -c \
  "node common/model_emit.js --docs && \
   cp docs/data-model-directory.md docs/data-model-persistence.md /out/docs/ && \
   cp models/generated/schema.sql /out/postgres/schema.sql && \
   cp models/generated/mariadb.schema.sql /out/mariadb/schema.sql && \
   cp models/generated/domain.d.ts /out/types/domain.generated.d.ts && \
   chown $(id -u):$(id -g) \
     /out/docs/data-model-directory.md \
     /out/docs/data-model-persistence.md \
     /out/postgres/schema.sql \
     /out/mariadb/schema.sql \
     /out/types/domain.generated.d.ts"
