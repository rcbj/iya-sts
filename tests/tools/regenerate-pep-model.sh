#!/bin/bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# tests/tools/regenerate-pep-model.sh — WRITES WHAT THE REMOTE PEP'S MODEL
# GENERATES (#1830).
#
# A change to models/pep/ owes this, in the same commit: tests/model_pep.js
# fails when a committed file differs. It runs in the tests image, because
# the TypeSpec compiler is a dependency of tests/ only. It writes
#
#   xacml-pep/openapi/*.json                      the OpenAPI documents
#   rust/crates/sts-model-pep/src/generated/*.rs  the Rust data types
#
# and then `cargo test -p sts-model-pep` is the check that the types compile
# and read every example the documents carry.
set -euo pipefail

cd "$(dirname "$(realpath "$0")")/../.."

TAG="${STS_NPM_TEST_IMAGE:-iya-sts-npm-test:pep-model}"
tests/tools/corpora-preflight.sh
# shellcheck disable=SC2046
docker build -q $(tests/tools/mirror-contexts.sh) -f tests/Dockerfile \
  -t "${TAG}" . > /dev/null
mkdir -p xacml-pep/openapi rust/crates/sts-model-pep/src/generated
docker run --rm --label com.docker.compose.project=none \
  -v "${PWD}/models/pep:/usr/src/sts/models/pep:ro" \
  -v "${PWD}/xacml-pep/openapi:/usr/src/sts/xacml-pep/openapi" \
  -v "${PWD}/rust/crates/sts-model-pep:/usr/src/sts/rust/crates/sts-model-pep" \
  "${TAG}" bash -c \
  "node models/tools/generate_pep.mjs && \
   chown -R $(id -u):$(id -g) xacml-pep/openapi \
     rust/crates/sts-model-pep/src/generated"
