#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# File: deploy/azure/terraform-local.sh
#
# ---------------------------------------------------------------------------
# RUN THE AZURE CLUSTER'S TERRAFORM ENTIRELY INSIDE DOCKER (issue #96) —
# deploy/gcp/terraform-local.sh's arrangement over deploy/azure/Dockerfile and
# deploy/azure/entrypoint.sh. Nothing but Docker and the Azure CLI (for your
# login) runs on the host.
#
# Usage:
#   AZURE_SUBSCRIPTION_ID=<id> deploy/azure/terraform-local.sh [env] [action]
#     env    = an environment name, 2-12 [a-z0-9]           (default: dev)
#     action = init | validate | plan | apply | destroy | import | output
#              | output-json                                 (default: plan)
#
#   deploy/azure/terraform-local.sh dev plan
#   IMAGE_TAG=<tag> deploy/azure/terraform-local.sh testidp apply     # 1 region
#   IMAGE_TAG=<tag> deploy/azure/terraform-local.sh testidpna apply   # 2 regions
#   IMAGE_TAG=<tag> deploy/azure/terraform-local.sh globalidp apply   # 3 regions
#   TF_CELL=zcnc IMAGE_TAG=<tag> deploy/azure/terraform-local.sh testidpna plan
#   TF_STACK=foundation deploy/azure/terraform-local.sh dev apply     # administrator
#
# CREDENTIALS: your Azure CLI login (`az login`, in $AZURE_CONFIG_DIR or
# ~/.azure), handed to the container as a tar through a private env file, as
# GCP's launcher hands over its application-default credentials. Terraform
# runs AS YOU, and applies what your grants allow — the deployer's, which the
# foundation gives the principals in `deployer_principal_ids`.
#
# plan, apply and import of an environment need IMAGE_TAG (the commit the
# three images were pushed under — deploy/azure/CLAUDE.md, *Running it by
# hand*) and ALLOWED_CIDR, which defaults to this host's public address and
# may be a comma-separated list. The list REPLACES what the security groups
# admitted.
#
# TF_CLI_ARGS, TF_CLI_ARGS_plan, TF_CLI_ARGS_apply and TF_CLI_ARGS_destroy
# pass through. INT or TERM becomes an interrupt to terraform, which releases
# the state lock.
#
# Override docker with DOCKER (e.g. DOCKER="sudo docker").
# ---------------------------------------------------------------------------
set -euo pipefail

IMAGE_NAME="${IMAGE_NAME:-iya-sts-terraform-azure}"
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

SUBSCRIPTION="${AZURE_SUBSCRIPTION_ID:-$(az account show --query id -o tsv 2> /dev/null || true)}"
[ -n "${SUBSCRIPTION}" ] || {
  echo "ERROR: set AZURE_SUBSCRIPTION_ID (or az account set --subscription <id>)." >&2
  exit 1
}

AZ_DIR="${AZURE_CONFIG_DIR:-${HOME}/.azure}"
[ -f "${AZ_DIR}/azureProfile.json" ] || {
  echo "ERROR: no Azure CLI login in ${AZ_DIR}." >&2
  echo "       Run: az login" >&2
  exit 1
}

CREDS_ENV_FILE="$(mktemp)"
chmod 600 "${CREDS_ENV_FILE}"
trap 'rm -f "${CREDS_ENV_FILE}"' EXIT
# The profile and the token cache, nothing else of the directory (its logs,
# its command index).
AZ_FILES=()
for f in azureProfile.json msal_token_cache.json msal_token_cache.bin \
         service_principal_entries.json clouds.config config; do
  [ -e "${AZ_DIR}/${f}" ] && AZ_FILES+=("${f}")
done
printf 'AZURE_CONFIG_B64=%s\n' "$(tar -czf - -C "${AZ_DIR}" "${AZ_FILES[@]}" | base64 -w0)" \
  > "${CREDS_ENV_FILE}"

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
  echo "==> The security groups will admit ${ALLOWED_CIDR}" >&2
  TF_VARS=(-e "TF_VAR_image_tag=${IMAGE_TAG}" -e "TF_VAR_allowed_cidrs=[${ALLOWED_JSON}]")
fi

for v in TF_CLI_ARGS TF_CLI_ARGS_plan TF_CLI_ARGS_apply TF_CLI_ARGS_destroy TF_IMPORT_ADDRESS TF_IMPORT_ID \
         TF_CELL TF_CELL_PHASE STATE_STORAGE_ACCOUNT STATE_RESOURCE_GROUP; do
  [ -z "${!v:-}" ] || TF_VARS+=(-e "${v}=${!v}")
done

echo "==> Building ${IMAGE_NAME}" >&2
"${DOCKER_CMD[@]}" build -q -t "${IMAGE_NAME}" -f "${REPO_ROOT}/deploy/azure/Dockerfile" "${REPO_ROOT}" > /dev/null

CONTAINER_NAME="iya-sts-terraform-azure-${TF_ENV}-$$"
relay() {
  echo "==> Interrupted: telling terraform to stop cleanly and release the lock" >&2
  "${DOCKER_CMD[@]}" kill --signal INT "${CONTAINER_NAME}" > /dev/null 2>&1 || true
}
trap relay INT TERM
"${DOCKER_CMD[@]}" run --rm --name "${CONTAINER_NAME}" \
  --env-file "${CREDS_ENV_FILE}" \
  -e AZURE_SUBSCRIPTION_ID="${SUBSCRIPTION}" \
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
