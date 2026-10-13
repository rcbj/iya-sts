#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# File: tests/tools/mirror-contexts.sh
#
# ---------------------------------------------------------------------------
# THE ghcr.io MIRROR AS `docker build` FLAGS (2026-09-27).
#
#   docker build $(tests/tools/mirror-contexts.sh) -f tests/Dockerfile .
#
# Prints one `--build-context <name>=docker-image://<mirror>/<path>` per line
# of .github/image-mirror.txt. BuildKit resolves a FROM against a named
# context before any registry, so every base image — intermediate stages
# included — comes from the private mirror and not from Docker Hub. It is
# what `x-mirror-contexts` in docker-compose-run-tests.yml does for a build
# compose runs; this is for the builds it does not (docker-npm-test.sh,
# build-container.yml, tests/tools/build-corpora-image.sh).
#
# The name is the upstream reference with `:latest` dropped, because BuildKit
# looks `FROM ubuntu:latest` up as `ubuntu`. A context no FROM names is
# never consulted, so the whole list is printed.
#
# IMAGE_MIRROR overrides the prefix; it must match the compose file's default.
# Output is on one line, space-separated, for `$(...)`.
# ---------------------------------------------------------------------------
set -euo pipefail

cd "$(dirname "$0")/../.."

IMAGE_MIRROR="${IMAGE_MIRROR:-ghcr.io/rcbj/iya-sts/mirror}"

flags=()
while read -r src path;
do
  case "${src}" in
    ''|'#'*)
      continue
      ;;
  esac
  flags+=("--build-context" "${src%:latest}=docker-image://${IMAGE_MIRROR}/${path}")
done < .github/image-mirror.txt
echo "${flags[*]}"
