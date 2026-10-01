#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# File: deploy/gcp/terraform-local.sh
#
# ---------------------------------------------------------------------------
# RUN THE GCP CLUSTER'S TERRAFORM ENTIRELY INSIDE DOCKER (issue #95) —
# deploy/aws/terraform-local.sh's arrangement over deploy/gcp/Dockerfile and
# deploy/gcp/entrypoint.sh. Nothing but Docker and gcloud (for your
# credentials) runs on the host.
#
# Usage:
#   GOOGLE_CLOUD_PROJECT=<project> deploy/gcp/terraform-local.sh [env] [action]
#     env    = an environment name, 2-12 [a-z0-9]           (default: dev)
#     action = init | validate | plan | apply | destroy | import | output
#              | output-json                                 (default: plan)
#
#   deploy/gcp/terraform-local.sh dev plan
#   IMAGE_TAG=<tag> deploy/gcp/terraform-local.sh testidp apply
#   TF_STACK=foundation deploy/gcp/terraform-local.sh dev apply   # administrator
#
# CREDENTIALS: your application-default credentials (`gcloud auth
# application-default login`, in $CLOUDSDK_CONFIG or ~/.config/gcloud), handed
# to the container through a private env file, as AWS's launcher hands over
# keys; with them the container impersonates the deployer, which your account
# may do once the foundation lists it in `deployer_members`.
# They are refreshed by the provider as they expire, so a long apply cannot
# outlive them (AWS needed host-credentials.js for that).
#
# plan, apply and import need IMAGE_TAG (the commit the three images were
# pushed under — deploy/gcp/CLAUDE.md, *Running it by hand*) and ALLOWED_CIDR,
# which defaults to this host's public address and may be a comma-separated
# list. The list REPLACES what the firewall admitted.
#
# TF_CLI_ARGS, TF_CLI_ARGS_plan, TF_CLI_ARGS_apply and TF_CLI_ARGS_destroy
# pass through. INT or TERM becomes an interrupt to terraform, which releases
# the state lock.
#
# Override docker with DOCKER (e.g. DOCKER="sudo docker").
# ---------------------------------------------------------------------------
set -euo pipefail

IMAGE_NAME="${IMAGE_NAME:-iya-sts-terraform-gcp}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

TF_ENV="${TF_ENV:-${1:-dev}}"
TF_ACTION="${TF_ACTION:-${2:-plan}}"
TF_STACK="${TF_STACK:-environment}"

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
[ -n "${PROJECT}" ] || {
  echo "ERROR: set GOOGLE_CLOUD_PROJECT (or gcloud config set project)." >&2
  exit 1
}

GCLOUD_DIR="${CLOUDSDK_CONFIG:-${HOME}/.config/gcloud}"
[ -f "${GCLOUD_DIR}/application_default_credentials.json" ] || {
  echo "ERROR: no application-default credentials in ${GCLOUD_DIR}." >&2
  echo "       Run: gcloud auth application-default login" >&2
  exit 1
}

CREDS_ENV_FILE="$(mktemp)"
chmod 600 "${CREDS_ENV_FILE}"
trap 'rm -f "${CREDS_ENV_FILE}"' EXIT
printf 'GCP_ADC_B64=%s\n' "$(base64 -w0 < "${GCLOUD_DIR}/application_default_credentials.json")" > "${CREDS_ENV_FILE}"

TF_VARS=()
if [ "${TF_STACK}" = "environment" ] && { [ "${TF_ACTION}" = "plan" ] || [ "${TF_ACTION}" = "apply" ] || [ "${TF_ACTION}" = "import" ]; };
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
  echo "==> The firewall will admit ${ALLOWED_CIDR}" >&2
  TF_VARS=(-e "TF_VAR_image_tag=${IMAGE_TAG}" -e "TF_VAR_allowed_cidrs=[${ALLOWED_JSON}]")
fi

for v in TF_CLI_ARGS TF_CLI_ARGS_plan TF_CLI_ARGS_apply TF_CLI_ARGS_destroy TF_IMPORT_ADDRESS TF_IMPORT_ID IYA_STS_DEPLOYER; do
  [ -z "${!v:-}" ] || TF_VARS+=(-e "${v}=${!v}")
done

echo "==> Building ${IMAGE_NAME}" >&2
"${DOCKER_CMD[@]}" build -q -t "${IMAGE_NAME}" -f "${REPO_ROOT}/deploy/gcp/Dockerfile" "${REPO_ROOT}" > /dev/null

CONTAINER_NAME="iya-sts-terraform-gcp-${TF_ENV}-$$"
relay() {
  echo "==> Interrupted: telling terraform to stop cleanly and release the lock" >&2
  "${DOCKER_CMD[@]}" kill --signal INT "${CONTAINER_NAME}" > /dev/null 2>&1 || true
}
trap relay INT TERM
"${DOCKER_CMD[@]}" run --rm --name "${CONTAINER_NAME}" \
  --env-file "${CREDS_ENV_FILE}" \
  -e GOOGLE_CLOUD_PROJECT="${PROJECT}" \
  -e TF_STACK="${TF_STACK}" \
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
