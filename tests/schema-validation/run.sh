#!/bin/bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# tests/schema-validation/run.sh — `./run-tests.sh --modes=schema-validation`.
#
# EVERY ANSWER HELD TO ITS MODEL, ON EVERY DEPLOYMENT, IN ONE CONTAINER (#1353,
# rcbj 2026-11-06). The service, its stores, its secret store, a balancer, the
# jobs, Chrome and Selenium all run inside one container, so this needs docker
# and nothing else, starts no compose project, takes no fixed container name but
# its own and publishes no port. tests/schema-validation/in-container.sh is the
# run and argues what passes.
#
#   STS_SCHEMA_STAGES  which stages, default memory,single-node,mariadb,cluster
#   STS_SCHEMA_CPUS    the container's bound, default 6
#   STS_SCHEMA_MEMORY  the container's bound, default 24g
#   any argument       handed to run-report.js, e.g. --only=sts_outside_values
#
# Reports land in tests/report/schema-validation/<stage>/, with each stage's
# service log and verdict.txt beside them.
set -u -o pipefail

cd "$(dirname "$(realpath "$0")")/../.." || exit 1

BASE="${STS_SCHEMA_BASE_IMAGE:-iya-sts-schema-base:local}"
IMAGE="${STS_SCHEMA_IMAGE:-iya-sts-schema-validation:local}"
NAME="${STS_SCHEMA_CONTAINER:-iya-sts-schema-validation}"
OUT="${PWD}/tests/report/schema-validation"

tests/tools/corpora-preflight.sh || exit 1
# shellcheck disable=SC2046
docker build $(tests/tools/mirror-contexts.sh) -f tests/Dockerfile \
  -t "${BASE}" . || exit 1
docker build --build-arg "STS_SCHEMA_BASE=${BASE}" \
  -f tests/schema-validation/Dockerfile -t "${IMAGE}" . || exit 1

# A tests image built by compose carries its project's label, and a container
# holding that label joins that project's run and can abort it. These are built
# here, so this is a check, and it stops rather than risk a run in progress.
LABEL="$(docker image inspect --format \
  '{{index .Config.Labels "com.docker.compose.project"}}' "${IMAGE}")"
if [ -n "${LABEL}" ]; then
  echo "schema-validation: ${IMAGE} carries the compose project" \
       "\"${LABEL}\"; not running it." >&2
  exit 1
fi

mkdir -p "${OUT}"
docker rm -f "${NAME}" > /dev/null 2>&1
# The capabilities are for the two network namespaces the nodes run in; the
# bounds are so that this can run beside other work on one machine.
docker run --rm --name "${NAME}" \
  --cap-add NET_ADMIN --cap-add SYS_ADMIN --cap-add IPC_LOCK \
  --security-opt seccomp=unconfined --security-opt apparmor=unconfined \
  --cpus "${STS_SCHEMA_CPUS:-6}" --memory "${STS_SCHEMA_MEMORY:-24g}" \
  --shm-size 2g \
  --add-host sts:10.77.0.10 --add-host sts2:10.77.0.20 \
  --add-host sts-lb:10.77.0.1 --add-host sts-lb.example.com:10.77.0.1 \
  --add-host sts.example.com:10.77.0.10 --add-host postgres:10.77.0.1 \
  --add-host mariadb:10.77.0.1 --add-host openbao:10.77.0.1 \
  --add-host tests:10.77.0.1 \
  -e "STS_SCHEMA_STAGES=${STS_SCHEMA_STAGES:-memory,single-node,mariadb,cluster}" \
  -v "${OUT}:/out" \
  "${IMAGE}" ./tests/schema-validation/in-container.sh "$@"
exit $?
