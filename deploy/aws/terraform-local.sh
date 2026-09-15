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
#                                                       (default: plan)
#
#   deploy/aws/terraform-local.sh dev plan
#   deploy/aws/terraform-local.sh dev apply          # IMAGE_TAG=<tag> required
#   deploy/aws/terraform-local.sh dev suite          # report in tests/report/aws-dev
#   TF_STACK=foundation deploy/aws/terraform-local.sh - apply   # administrator
#
# CREDENTIALS: the AWS_* variables already in your environment if there are any
# (the deployer user's key, or role credentials), otherwise whatever
# `aws configure export-credentials` resolves (an SSO session or a profile).
# They reach the container through a private --env-file, never a command line.
# The deployer user's key is exchanged for the deployer role inside.
#
# plan and apply need two more: IMAGE_TAG (the commit the images were pushed
# under — deploy/aws/CLAUDE.md, *Running it by hand*, builds them) and
# ALLOWED_CIDR, which defaults to this host's public address.
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

CREDS_ENV_FILE="$(mktemp)"
chmod 600 "${CREDS_ENV_FILE}"
trap 'rm -f "${CREDS_ENV_FILE}"' EXIT
if [ -n "${AWS_ACCESS_KEY_ID:-}" ] && [ -n "${AWS_SECRET_ACCESS_KEY:-}" ];
then
  echo "==> Using the AWS credentials in this environment"
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
  echo "==> Resolving AWS credentials${AWS_PROFILE:+ (profile: ${AWS_PROFILE})}"
  if ! aws configure export-credentials --format env-no-export > "${CREDS_ENV_FILE}" 2>/dev/null \
     || [ ! -s "${CREDS_ENV_FILE}" ];
  then
    echo "ERROR: could not resolve AWS credentials. Sign in first (aws sso login, aws login)," >&2
    echo "       or export the deployer user's key as AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY." >&2
    exit 1
  fi
fi

TF_VARS=()
if [ "${TF_STACK}" = "environment" ] && { [ "${TF_ACTION}" = "plan" ] || [ "${TF_ACTION}" = "apply" ]; };
then
  [ -n "${IMAGE_TAG:-}" ] || { echo "ERROR: ${TF_ACTION} needs IMAGE_TAG." >&2; exit 1; }
  if [ -z "${ALLOWED_CIDR:-}" ];
  then
    MY_IP="$(curl -fsS --max-time 10 https://checkip.amazonaws.com 2>/dev/null | tr -d '[:space:]')"
    [ -n "${MY_IP}" ] || { echo "ERROR: could not resolve this host's public IP; set ALLOWED_CIDR." >&2; exit 1; }
    ALLOWED_CIDR="${MY_IP}/32"
  fi
  echo "==> The load balancer will admit ${ALLOWED_CIDR}"
  TF_VARS=(-e "TF_VAR_image_tag=${IMAGE_TAG}" -e "TF_VAR_allowed_cidrs=[\"${ALLOWED_CIDR}\"]")
fi

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

echo "==> Building ${IMAGE_NAME}"
"${DOCKER_CMD[@]}" build -q -t "${IMAGE_NAME}" -f "${REPO_ROOT}/deploy/aws/Dockerfile" "${REPO_ROOT}" >/dev/null

"${DOCKER_CMD[@]}" run --rm \
  --env-file "${CREDS_ENV_FILE}" \
  -e AWS_REGION="${AWS_REGION:-us-west-2}" \
  -e TF_STACK="${TF_STACK}" \
  -e TF_ENV="${TF_ENV}" \
  -e TF_ACTION="${TF_ACTION}" \
  "${TF_VARS[@]}" \
  "${REPORT_ARGS[@]}" \
  "${IMAGE_NAME}"
