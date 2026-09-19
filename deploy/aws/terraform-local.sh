#!/usr/bin/env bash
#
# File: deploy/aws/terraform-local.sh
#
# ---------------------------------------------------------------------------
# RUN THE AWS CLUSTER'S TERRAFORM, OR ITS SUITE, ENTIRELY INSIDE DOCKER
# (issue #51). The parent project's infra/terraform-local.sh arrangement, over
# the same image and entrypoint the workflow uses (deploy/aws/Dockerfile,
# deploy/aws/entrypoint.sh). Nothing but Docker and the AWS CLI, for your
# credentials, runs on the host.
#
# Usage:
#   deploy/aws/terraform-local.sh [env] [action]
#     env    = an environment name, 2-12 [a-z0-9]      (default: dev)
#     action = init | validate | plan | apply | destroy | output | suite
#              | ecr-password                           (default: plan)
#
#   deploy/aws/terraform-local.sh dev plan
#   deploy/aws/terraform-local.sh dev apply          # IMAGE_TAG=<tag> required
#   deploy/aws/terraform-local.sh dev suite          # report in tests/report/aws-dev
#   TF_STACK=foundation deploy/aws/terraform-local.sh dev apply # administrator
#   TF_STACK=spiffe-realm REALM=acme WORKLOAD_PORT=9092 SERVER_PORT=9181 \
#     deploy/aws/terraform-local.sh testidp apply  # a realm's SPIFFE ports
#     (deploy/aws/CLAUDE.md, *A realm's SPIFFE ports*; `destroy` needs REALM
#     only)
#     (the env name is not used by `foundation`, but entrypoint.sh still
#     checks its shape, so it must be a valid name and not `-`)
#
# CREDENTIALS: the AWS_* variables already in your environment if there are any
# (the deployer user's key, or role credentials), through a private --env-file,
# never a command line; the deployer user's key is exchanged for the deployer
# role inside. OTHERWISE YOUR HOST SESSION (an `aws login` or SSO session, or a
# profile), SERVED LIVE (2026-09-18): host-credentials.js answers on
# 127.0.0.1 in the shape of the ECS container credentials endpoint, the
# container runs on the host network and is pointed at it, and the SDKs ask
# again before what they hold expires. It was a snapshot until then, and an
# `aws login` snapshot lasts about fifteen minutes — so every longer apply
# died with an expired token and left the state LOCKED (twice on testidp,
# each needing a force-unlock). Static keys in the environment still travel
# as a snapshot, because there is nothing to refresh them from.
#
# plan and apply need two more: IMAGE_TAG (the commit the images were pushed
# under — deploy/aws/CLAUDE.md, *Running it by hand*, builds them) and
# ALLOWED_CIDR, which defaults to this host's public address and may be a
# comma-separated list (every address the load balancer should admit).
#
# TF_CLI_ARGS, TF_CLI_ARGS_plan, TF_CLI_ARGS_apply and TF_CLI_ARGS_destroy are
# passed through — terraform reads them itself, so
#   TF_CLI_ARGS_apply='-target=aws_ecs_service.first' … testidp apply
# applies one resource with nothing added to entrypoint.sh.
#
# AN INTERRUPT IS RELAYED, NOT FATAL (2026-09-18): INT or TERM to this script
# becomes an INT to terraform inside the container (entrypoint.sh's `tf`),
# which stops cleanly and RELEASES THE STATE LOCK. It used to kill terraform
# where it stood and leave the lock held.
#
# Override docker with DOCKER (e.g. DOCKER="sudo docker").
# ---------------------------------------------------------------------------
set -euo pipefail

IMAGE_NAME="${IMAGE_NAME:-mock-sts-terraform}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

TF_ENV="${TF_ENV:-${1:-dev}}"
TF_ACTION="${TF_ACTION:-${2:-plan}}"
TF_STACK="${TF_STACK:-environment}"

if [ -n "${DOCKER:-}" ]; then
  read -r -a DOCKER_CMD <<< "${DOCKER}"
elif docker info >/dev/null 2>&1; then
  DOCKER_CMD=(docker)
elif command -v sudo >/dev/null 2>&1; then
  DOCKER_CMD=(sudo docker)
else
  echo "ERROR: docker is required and not reachable." >&2
  exit 1
fi

# Before the container exists an interrupt has nothing to relay; it stops
# here, once whatever is running (the image build) returns, rather than being
# lost and letting terraform start anyway. Replaced by `relay` below.
trap 'echo "==> Interrupted before terraform started" >&2; exit 130' INT TERM

CREDS_ENV_FILE="$(mktemp)"
NETWORK_ARGS=()
chmod 600 "${CREDS_ENV_FILE}"
trap 'rm -f "${CREDS_ENV_FILE}"' EXIT
if [ -n "${AWS_ACCESS_KEY_ID:-}" ] && [ -n "${AWS_SECRET_ACCESS_KEY:-}" ];
then
  echo "==> Using the AWS credentials in this environment" >&2
  {
    echo "AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}"
    echo "AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}"
    [ -z "${AWS_SESSION_TOKEN:-}" ] || echo "AWS_SESSION_TOKEN=${AWS_SESSION_TOKEN}"
  } > "${CREDS_ENV_FILE}"
else
  command -v aws >/dev/null 2>&1 || {
    echo "ERROR: no AWS_* credentials in the environment and no AWS CLI to resolve a session." >&2
    exit 1
  }
  echo "==> Serving your AWS session to the container as it refreshes${AWS_PROFILE:+ (profile: ${AWS_PROFILE})}" >&2
  # Fail here, naming the fix, rather than inside the container naming a
  # credentials endpoint.
  if ! aws configure export-credentials --format process >/dev/null 2>&1;
  then
    echo "ERROR: could not resolve AWS credentials. Sign in first (aws sso login, aws login)," >&2
    echo "       or export the deployer user's key as AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY." >&2
    exit 1
  fi
  command -v node >/dev/null 2>&1 || {
    echo "ERROR: node is needed on the host to serve a refreshing session (host-credentials.js)." >&2
    exit 1
  }
  CREDS_TOKEN_FILE="$(mktemp)"
  chmod 600 "${CREDS_TOKEN_FILE}"
  trap 'rm -f "${CREDS_ENV_FILE}" "${CREDS_TOKEN_FILE}"' EXIT
  head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "${CREDS_TOKEN_FILE}"
  # A coprocess: this shell holds its stdin, so it exits when the launcher
  # does, however the launcher ends.
  coproc HOST_CREDS { exec node "${REPO_ROOT}/deploy/aws/host-credentials.js" "${CREDS_TOKEN_FILE}"; }
  CREDS_PORT=""
  read -r -t 20 CREDS_PORT <&"${HOST_CREDS[0]}" || true
  [ -n "${CREDS_PORT}" ] || { echo "ERROR: host-credentials.js did not start." >&2; exit 1; }
  {
    echo "AWS_CONTAINER_CREDENTIALS_FULL_URI=http://127.0.0.1:${CREDS_PORT}/"
    echo "AWS_CONTAINER_AUTHORIZATION_TOKEN=$(cat "${CREDS_TOKEN_FILE}")"
  } > "${CREDS_ENV_FILE}"
  # The container reaches 127.0.0.1 only on the host's network.
  NETWORK_ARGS=(--network host)
fi

TF_VARS=()
if [ "${TF_STACK}" = "environment" ] && { [ "${TF_ACTION}" = "plan" ] || [ "${TF_ACTION}" = "apply" ] || [ "${TF_ACTION}" = "import" ]; };
then
  [ -n "${IMAGE_TAG:-}" ] || { echo "ERROR: ${TF_ACTION} needs IMAGE_TAG." >&2; exit 1; }
  if [ -z "${ALLOWED_CIDR:-}" ];
  then
    MY_IP="$(curl -fsS --max-time 10 https://checkip.amazonaws.com 2>/dev/null | tr -d '[:space:]')"
    [ -n "${MY_IP}" ] || { echo "ERROR: could not resolve this host's public IP; set ALLOWED_CIDR." >&2; exit 1; }
    ALLOWED_CIDR="${MY_IP}/32"
  fi
  # A comma-separated list admits several addresses; each becomes one entry of
  # allowed_cidrs, and the list REPLACES what the load balancer admitted.
  ALLOWED_JSON="$(printf '%s' "${ALLOWED_CIDR}" | tr -d '[:space:]' |
    awk -F, '{ for (i = 1; i <= NF; i++) if ($i != "") printf "%s\"%s\"", (n++ ? "," : ""), $i }')"
  echo "==> The load balancer will admit ${ALLOWED_CIDR}" >&2
  TF_VARS=(-e "TF_VAR_image_tag=${IMAGE_TAG}" -e "TF_VAR_allowed_cidrs=[${ALLOWED_JSON}]")
fi

if [ "${TF_STACK}" = "spiffe-realm" ];
then
  [ -n "${REALM:-}" ] || { echo "ERROR: TF_STACK=spiffe-realm needs REALM (a realm id, or default)." >&2; exit 1; }
  TF_VARS+=(-e "TF_REALM=${REALM}")
  if [ "${TF_ACTION}" = "plan" ] || [ "${TF_ACTION}" = "apply" ];
  then
    [ -n "${WORKLOAD_PORT:-}" ] && [ -n "${SERVER_PORT:-}" ] || {
      echo "ERROR: ${TF_ACTION} needs WORKLOAD_PORT and SERVER_PORT, the realm's spiffe.workloadPort and spiffe.serverPort." >&2
      exit 1
    }
    TF_VARS+=(-e "TF_VAR_workload_port=${WORKLOAD_PORT}" -e "TF_VAR_server_port=${SERVER_PORT}")
  fi
fi

if [ "${TF_STACK}" = "suite-callbacks" ] && [ -n "${IMAGE_TAG:-}" ];
then
  TF_VARS+=(-e "TF_VAR_image_tag=${IMAGE_TAG}")
fi

for v in TF_CLI_ARGS TF_CLI_ARGS_plan TF_CLI_ARGS_apply TF_CLI_ARGS_destroy; do
  [ -z "${!v:-}" ] || TF_VARS+=(-e "${v}=${!v}")
done

REPORT_ARGS=()
if [ "${TF_ACTION}" = "suite" ];
then
  REPORT_DIR="${REPO_ROOT}/tests/report/aws-${TF_ENV}"
  mkdir -p "${REPORT_DIR}"
  # The container runs as uid 10001, which is not you.
  chmod 0777 "${REPORT_DIR}"
  REPORT_ARGS=(-v "${REPORT_DIR}:/workspace/report")
  for v in STS_SUITE_EXCLUDE STS_SUITE_ONLY STS_SUITE_KEEP_REALMS STS_SUITE_JOB_TIMEOUT_MS; do
    [ -z "${!v:-}" ] || REPORT_ARGS+=(-e "${v}=${!v}")
  done
fi

echo "==> Building ${IMAGE_NAME}" >&2
"${DOCKER_CMD[@]}" build -q -t "${IMAGE_NAME}" -f "${REPO_ROOT}/deploy/aws/Dockerfile" "${REPO_ROOT}" >/dev/null

# Named, in the background, and waited for, so that an interrupt here can be
# relayed to it: a foreground `docker run` is a child bash will not interrupt,
# and killing the client leaves the container running without this script's
# credentials endpoint. `wait` returns early on a trapped signal, hence the
# loop.
CONTAINER_NAME="mock-sts-terraform-${TF_ENV}${REALM:+-${REALM}}-$$"
relay() {
  echo "==> Interrupted: telling terraform to stop cleanly and release the lock" >&2
  "${DOCKER_CMD[@]}" kill --signal INT "${CONTAINER_NAME}" >/dev/null 2>&1 || true
}
trap relay INT TERM
"${DOCKER_CMD[@]}" run --rm --name "${CONTAINER_NAME}" \
  --env-file "${CREDS_ENV_FILE}" \
  "${NETWORK_ARGS[@]}" \
  -e AWS_REGION="${AWS_REGION:-us-west-2}" \
  -e TF_STACK="${TF_STACK}" \
  -e TF_ENV="${TF_ENV}" \
  -e TF_ACTION="${TF_ACTION}" \
  -e TF_IMPORT_ADDRESS="${TF_IMPORT_ADDRESS:-}" \
  -e TF_IMPORT_ID="${TF_IMPORT_ID:-}" \
  "${TF_VARS[@]}" \
  "${REPORT_ARGS[@]}" \
  "${IMAGE_NAME}" &
RUN_PID=$!
rc=0
while :; do
  wait "${RUN_PID}" && rc=0 || rc=$?
  kill -0 "${RUN_PID}" 2>/dev/null || break
done
exit "${rc}"
