#!/bin/bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# tests/tools/oasdiff-gate.sh <base-ref> — FAILS ON A BREAKING API CHANGE.
#
# Generates the five OpenAPI documents from this tree and from <base-ref>, each
# inside a tests image because the model compiles only in an image build, and
# asks oasdiff whether anything a caller relies on has gone (#1390). Needs
# docker and curl and nothing else.
set -euo pipefail

BASE_REF="${1:?usage: oasdiff-gate.sh <base-ref>}"
OASDIFF_VERSION=1.37.0
OASDIFF_SHA256=eac87307d31d08c36800c58a409c247f1c5db37fbb72e2544402f22a87cbca3c
DOCUMENTS="management console account authn report"

cd "$(dirname "$(realpath "$0")")/../.."
WORK="$(mktemp -d)"
trap 'git worktree remove --force "${WORK}/base-tree" 2>/dev/null || true; rm -rf "${WORK}"' EXIT

curl -fsSL -o "${WORK}/oasdiff.tar.gz" \
  "https://github.com/oasdiff/oasdiff/releases/download/v${OASDIFF_VERSION}/oasdiff_${OASDIFF_VERSION}_linux_amd64.tar.gz"
echo "${OASDIFF_SHA256}  ${WORK}/oasdiff.tar.gz" | sha256sum -c -
tar -xzf "${WORK}/oasdiff.tar.gz" -C "${WORK}" oasdiff

# Writes one tree's generated documents into a directory.
documents_of() {
  local tree="$1" out="$2" tag="$3"
  mkdir -p "${out}"
  # shellcheck disable=SC2046
  (cd "${tree}" && docker build -q $(tests/tools/mirror-contexts.sh) \
    -f tests/Dockerfile -t "${tag}" . > /dev/null)
  docker run --rm --label com.docker.compose.project=none \
    -v "${out}:/out" --entrypoint bash "${tag}" -c \
    "cp models/generated/openapi.*.json /out/ && rm -f /out/openapi.every.json && chmod -R a+rw /out"
}

git worktree add -q --detach "${WORK}/base-tree" "${BASE_REF}"
git -C "${WORK}/base-tree" submodule update -q --init --recursive
documents_of "${WORK}/base-tree" "${WORK}/base" iya-sts-npm-test:oasdiff-base
documents_of "${PWD}" "${WORK}/head" iya-sts-npm-test:oasdiff-head

status=0
for name in ${DOCUMENTS}; do
  echo "== ${name}"
  "${WORK}/oasdiff" breaking --fail-on ERR \
    "${WORK}/base/openapi.${name}.json" "${WORK}/head/openapi.${name}.json" ||
    status=1
done
exit "${status}"
