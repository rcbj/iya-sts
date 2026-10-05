#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# File: tests/tools/corpora-preflight.sh
#
# ---------------------------------------------------------------------------
# CAN THIS MACHINE PULL THE TEST CORPORA IMAGE? (#253, 2026-09-26)
#
# tests/Dockerfile copies the third-party corpora out of a PRIVATE image on
# ghcr.io, pinned by digest (its `ARG STS_CORPORA_IMAGE=` line). Without a
# `docker login ghcr.io` the build dies on a pull error that names neither
# the registry login nor this repository — so every launcher that builds that
# Dockerfile asks here first and stops with a sentence that says what to do.
#
#   tests/tools/corpora-preflight.sh    exit 0 when the image is here or can
#                                       be pulled; 1, with the reason, if not
#
# Present locally (a digest already pulled) costs nothing; otherwise one
# `docker pull`, which is what the build would have done anyway.
#
# AND THE IMAGE MIRROR (2026-09-27). Every third-party image the test stack
# pulls or builds FROM is a private copy under ghcr.io/rcbj/iya-sts/mirror
# (.github/image-mirror.txt). The same login reads it, so one manifest
# request for one of its images is asked here too; a mirror that has not been
# filled yet says so rather than failing the build on "denied".
# ---------------------------------------------------------------------------
set -euo pipefail

cd "$(dirname "$0")/../.."

image="$(sed -n 's/^ARG STS_CORPORA_IMAGE=//p' tests/Dockerfile | head -1)"
if [ -z "${image}" ]; then
  echo "corpora-preflight: tests/Dockerfile names no STS_CORPORA_IMAGE." >&2
  exit 1
fi
mirror="${IMAGE_MIRROR:-ghcr.io/rcbj/iya-sts/mirror}"
probe="${mirror}/ubuntu:latest"
if ! docker manifest inspect "${probe}" >/dev/null 2>&1; then
  cat >&2 <<EOF
corpora-preflight: cannot read the image mirror
  ${probe}
Every third-party image the test stack pulls or builds FROM is a PRIVATE
copy under ${mirror} (.github/image-mirror.txt). Log this machine in with a
token that can read packages, then run again:

  gh auth refresh -h github.com -s read:packages
  gh auth token | docker login ghcr.io -u <your GitHub user> --password-stdin

If the login works and the image is missing, the mirror has not been filled:
run the "Mirror Images" workflow, or .github/scripts/mirror-images.sh missing
(which needs write:packages).
EOF
  exit 1
fi
if docker image inspect "${image}" >/dev/null 2>&1; then
  exit 0
fi
if docker pull -q "${image}" >/dev/null 2>&1; then
  exit 0
fi
cat >&2 <<EOF
corpora-preflight: cannot pull the test corpora image
  ${image}
It is a PRIVATE package on GitHub Container Registry (#253). Log this machine
in with a token that can read packages, then run again:

  gh auth refresh -h github.com -s read:packages
  gh auth token | docker login ghcr.io -u <your GitHub user> --password-stdin

In GitHub Actions the workflow logs in with GITHUB_TOKEN (packages: read).
EOF
exit 1
