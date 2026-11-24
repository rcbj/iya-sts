#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# File: .github/scripts/stack-images.sh
#
# ---------------------------------------------------------------------------
# HAND THE IMAGES ONE CI JOB BUILT TO THE OTHERS, WITHOUT PUBLISHING THEM
# (2026-11-14).
#
#   .github/scripts/stack-images.sh save <file.tar.zst>
#   .github/scripts/stack-images.sh load <file.tar.zst>
#
# tests.yml builds every image docker-compose-run-tests.yml builds ONCE, in
# its `build` job (./run-tests.sh --build-only), and each test job runs
# ./run-tests.sh --no-build against them. They travel as a workflow
# artifact (`docker save`, compressed with zstd) and never as a registry
# push: rcbj holds every iya-sts image back from publication, and until this
# day tests.yml pushed these to ghcr.io (push-stack-images.sh, deleted), four
# of them as PUBLIC packages. An artifact stays inside the run, works for a
# pull request from a fork, and is gone after its retention.
#
# run-tests.sh names every one ${IMAGE_REGISTRY}/<name>:${IMAGE_TAG}; NAMES
# below is that list, and tests/image_mirror_coverage.js holds the two
# equal. One archive for all of them, so the layers the images share are
# written once. An image that is not there is a FAILED save: a test job
# loading an archive without it builds nothing (--no-build) and fails much
# later, at `up`, on a pull error naming neither this script nor the build.
# ---------------------------------------------------------------------------
set -euo pipefail

IMAGE_REGISTRY="${IMAGE_REGISTRY:-ghcr.io/rcbj/iya-sts}"
IMAGE_TAG="${IMAGE_TAG:?IMAGE_TAG must be set}"
NAMES="sts xacml-pep iya-sts-tests sts-saml-shibboleth sts-saml-simplesamlphp
       sts-saml-pysaml2 sts-saml-keycloak sts-test-peer sts-companion
       sts-client-lab"

ACTION="${1:?usage: stack-images.sh save|load <file.tar.zst>}"
ARCHIVE="${2:?usage: stack-images.sh save|load <file.tar.zst>}"

requireZstd()
{
  echo "Entering requireZstd()."
  if ! command -v zstd > /dev/null 2>&1;
  then
    sudo apt-get update -q
    sudo apt-get install -y -q zstd
  fi
  echo "Leaving requireZstd()."
}

saveImages()
{
  echo "Entering saveImages()."
  local name image images=()
  for name in ${NAMES};
  do
    image="${IMAGE_REGISTRY}/${name}:${IMAGE_TAG}"
    if ! docker image inspect "${image}" > /dev/null 2>&1;
    then
      echo "::error::${image} was not built; nothing is saved."
      echo "Leaving saveImages(). ${image} absent."
      return 1
    fi
    images+=("${image}")
  done
  docker save "${images[@]}" | zstd -q -T0 -3 -o "${ARCHIVE}"
  ls -l "${ARCHIVE}"
  echo "Leaving saveImages()."
}

loadImages()
{
  echo "Entering loadImages()."
  zstd -q -dc "${ARCHIVE}" | docker load
  # The archive is gigabytes on a runner with little disk to spare, and the
  # images now hold everything it did.
  rm -f "${ARCHIVE}"
  echo "Leaving loadImages()."
}

requireZstd
case "${ACTION}" in
  save) saveImages ;;
  load) loadImages ;;
  *)    echo "stack-images.sh: no action \"${ACTION}\" (save or load)." >&2
        exit 2 ;;
esac
