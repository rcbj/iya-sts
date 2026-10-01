#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# File: deploy/multicloud/terraform-local.sh
#
# ---------------------------------------------------------------------------
# ONE MULTI-CLOUD ENVIRONMENT, APPLIED OR DESTROYED FROM THIS MACHINE (#97).
#
#   GOOGLE_CLOUD_PROJECT=<project> IMAGE_TAG=<tag> \
#     deploy/multicloud/terraform-local.sh testidpmc apply
#   GOOGLE_CLOUD_PROJECT=<project> deploy/multicloud/terraform-local.sh testidpmc destroy
#   TF_STEP=gcp-cell:gase1:full … testidpmc apply     # one step
#
# CREDENTIALS FOR BOTH CLOUDS, handed over as each single-cloud launcher
# hands over its own: the AWS session served live on 127.0.0.1 by
# deploy/aws/host-credentials.js (or the AWS_* keys in the environment), and
# the GCP application-default credentials through a private env file.
#
# IMAGE_TAG names the images in BOTH registries (ECR and Artifact Registry,
# pushed under the same tag); ALLOWED_CIDR admits this host by default. An
# interrupt stops terraform cleanly and releases its lock.
# ---------------------------------------------------------------------------
set -euo pipefail

IMAGE_NAME="${IMAGE_NAME:-mock-sts-terraform-mc}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

TF_ENV="${TF_ENV:-${1:-testidpmc}}"
TF_ACTION="${TF_ACTION:-${2:-plan}}"

if [ -n "${DOCKER:-}" ]; then
  read -r -a DOCKER_CMD <<< "${DOCKER}"
elif docker info > /dev/null 2>&1; then
  DOCKER_CMD=(docker)
elif command -v sudo > /dev/null 2>&1; then
  DOCKER_CMD=(sudo docker)
else
  echo "ERROR: docker is required and not reachable." >&2
  exit 1
fi

trap 'echo "==> Interrupted before terraform started" >&2; exit 130' INT TERM

PROJECT="${GOOGLE_CLOUD_PROJECT:-$(gcloud config get-value project 2> /dev/null || true)}"
[ -n "${PROJECT}" ] || { echo "ERROR: set GOOGLE_CLOUD_PROJECT." >&2; exit 1; }
GCLOUD_DIR="${CLOUDSDK_CONFIG:-${HOME}/.config/gcloud}"
[ -f "${GCLOUD_DIR}/application_default_credentials.json" ] || {
  echo "ERROR: no GCP application-default credentials; run: gcloud auth application-default login" >&2
  exit 1
}

CREDS_ENV_FILE="$(mktemp)"
chmod 600 "${CREDS_ENV_FILE}"
trap 'rm -f "${CREDS_ENV_FILE}"' EXIT
printf 'GCP_ADC_B64=%s\n' "$(base64 -w0 < "${GCLOUD_DIR}/application_default_credentials.json")" > "${CREDS_ENV_FILE}"

NETWORK_ARGS=()
if [ -n "${AWS_ACCESS_KEY_ID:-}" ] && [ -n "${AWS_SECRET_ACCESS_KEY:-}" ];
then
  {
    echo "AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}"
    echo "AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}"
    [ -z "${AWS_SESSION_TOKEN:-}" ] || echo "AWS_SESSION_TOKEN=${AWS_SESSION_TOKEN}"
  } >> "${CREDS_ENV_FILE}"
else
  aws configure export-credentials --format process > /dev/null 2>&1 || {
    echo "ERROR: no AWS credentials; sign in (aws sso login, aws login) or export the deployer's key." >&2
    exit 1
  }
  CREDS_TOKEN_FILE="$(mktemp)"
  chmod 600 "${CREDS_TOKEN_FILE}"
  trap 'rm -f "${CREDS_ENV_FILE}" "${CREDS_TOKEN_FILE}"' EXIT
  head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "${CREDS_TOKEN_FILE}"
  coproc HOST_CREDS { exec node "${REPO_ROOT}/deploy/aws/host-credentials.js" "${CREDS_TOKEN_FILE}"; }
  CREDS_PORT=""
  read -r -t 20 CREDS_PORT <&"${HOST_CREDS[0]}" || true
  [ -n "${CREDS_PORT}" ] || { echo "ERROR: host-credentials.js did not start." >&2; exit 1; }
  {
    echo "AWS_CONTAINER_CREDENTIALS_FULL_URI=http://127.0.0.1:${CREDS_PORT}/"
    echo "AWS_CONTAINER_AUTHORIZATION_TOKEN=$(cat "${CREDS_TOKEN_FILE}")"
  } >> "${CREDS_ENV_FILE}"
  NETWORK_ARGS=(--network host)
fi

TF_VARS=()
if [ "${TF_ACTION}" = "apply" ] || [ "${TF_ACTION}" = "plan" ];
then
  [ -n "${IMAGE_TAG:-}" ] || { echo "ERROR: ${TF_ACTION} needs IMAGE_TAG." >&2; exit 1; }
  if [ -z "${ALLOWED_CIDR:-}" ];
  then
    MY_IP="$(curl -fsS --max-time 10 https://checkip.amazonaws.com 2> /dev/null | tr -d '[:space:]')"
    [ -n "${MY_IP}" ] || { echo "ERROR: could not resolve this host's public IP; set ALLOWED_CIDR." >&2; exit 1; }
    ALLOWED_CIDR="${MY_IP}/32"
  fi
  ALLOWED_JSON="$(printf '%s' "${ALLOWED_CIDR}" | tr -d '[:space:]' |
    awk -F, '{ for (i = 1; i <= NF; i++) if ($i != "") printf "%s\"%s\"", (n++ ? "," : ""), $i }')"
  echo "==> Every cell's load balancer will admit ${ALLOWED_CIDR}" >&2
  TF_VARS=(-e "TF_VAR_image_tag=${IMAGE_TAG}" -e "TF_VAR_allowed_cidrs=[${ALLOWED_JSON}]")
fi
for v in TF_STEP MOCK_STS_CONFLICTING_ENV TF_CLI_ARGS TF_CLI_ARGS_plan TF_CLI_ARGS_apply TF_CLI_ARGS_destroy; do
  [ -z "${!v:-}" ] || TF_VARS+=(-e "${v}=${!v}")
done

echo "==> Building ${IMAGE_NAME}" >&2
"${DOCKER_CMD[@]}" build -q -t "${IMAGE_NAME}" -f "${REPO_ROOT}/deploy/multicloud/Dockerfile" "${REPO_ROOT}" > /dev/null

CONTAINER_NAME="mock-sts-terraform-mc-${TF_ENV}-$$"
relay() {
  echo "==> Interrupted: telling terraform to stop cleanly and release the lock" >&2
  "${DOCKER_CMD[@]}" kill --signal INT "${CONTAINER_NAME}" > /dev/null 2>&1 || true
}
trap relay INT TERM
"${DOCKER_CMD[@]}" run --rm --name "${CONTAINER_NAME}" \
  --env-file "${CREDS_ENV_FILE}" \
  "${NETWORK_ARGS[@]}" \
  -e AWS_REGION="${AWS_REGION:-us-west-2}" \
  -e GOOGLE_CLOUD_PROJECT="${PROJECT}" \
  -e TF_ENV="${TF_ENV}" \
  -e TF_ACTION="${TF_ACTION}" \
  "${TF_VARS[@]}" \
  "${IMAGE_NAME}" &
RUN_PID=$!
rc=0
while :; do
  wait "${RUN_PID}" && rc=0 || rc=$?
  kill -0 "${RUN_PID}" 2> /dev/null || break
done
exit "${rc}"
