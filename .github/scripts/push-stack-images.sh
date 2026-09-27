#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# File: .github/scripts/push-stack-images.sh
#
# ---------------------------------------------------------------------------
# PUSH THE IMAGES A TEST RUN BUILT TO ghcr.io (2026-09-27).
#
#   .github/scripts/push-stack-images.sh [extra-tag]
#
# run-tests.sh names every image docker-compose-run-tests.yml builds
# ${IMAGE_REGISTRY}/<name>:${IMAGE_TAG}. This pushes each one that exists
# locally under that tag and, when given, under a second tag too (tests.yml
# passes the branch name, so `sts:develop` is always the last develop
# build). An image that is not there — the build failed before reaching it,
# or the run never built the SAML peers — is reported and skipped rather
# than failing the step: the run's own failure is the one worth reading.
#
# The packages are created PRIVATE on first push; see
# .github/workflows/mirror-images.yml for why that holds. The parent
# project's script of the same name is the original.
# ---------------------------------------------------------------------------
set -euo pipefail

IMAGE_REGISTRY="${IMAGE_REGISTRY:-ghcr.io/rcbj/iya-sts}"
IMAGE_TAG="${IMAGE_TAG:?IMAGE_TAG must be set}"
EXTRA_TAG="${1:-}"
NAMES="sts xacml-pep mock-sts-tests sts-saml-shibboleth sts-saml-simplesamlphp
       sts-saml-pysaml2 sts-saml-keycloak"

pushImage()
{
  echo "Entering pushImage()."
  local image="$1" target
  if ! docker image inspect "${image}" >/dev/null 2>&1;
  then
    echo "::warning::${image} was not built; not pushed."
    echo "Leaving pushImage(). ${image} absent."
    return 0
  fi
  docker push "${image}"
  if [ -n "${EXTRA_TAG}" ];
  then
    target="${image%:*}:${EXTRA_TAG}"
    docker tag "${image}" "${target}"
    docker push "${target}"
  fi
  echo "Leaving pushImage(). ${image} pushed."
}

for name in ${NAMES};
do
  pushImage "${IMAGE_REGISTRY}/${name}:${IMAGE_TAG}"
done
