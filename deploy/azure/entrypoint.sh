#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# File: deploy/azure/entrypoint.sh
#
# ---------------------------------------------------------------------------
# ONE ENVIRONMENT, ONE ACTION, INSIDE THE AZURE TERRAFORM IMAGE (issue #96) —
# deploy/gcp/entrypoint.sh's contract, and deploy/aws/entrypoint.sh's
# ordering of a multi-region environment's cells.
#
#   TF_STACK      environment (default) | global | foundation
#   TF_ENV        an environment name, 2-12 [a-z0-9]
#   TF_ACTION     init | validate | plan | apply | destroy | import | output |
#                 output-json
#   TF_CELL       one cell of a multi-region environment (e.g. zwus2); empty
#                 means every cell, in order, with the global stack between
#   TF_CELL_PHASE base | full, with TF_CELL (default full)
#   AZURE_SUBSCRIPTION_ID   the subscription (required)
#
# CREDENTIALS: the host's Azure CLI login, handed over by terraform-local.sh
# as AZURE_CONFIG_B64 (a tar of ~/.azure) through a private env file, and
# unpacked here into this user's own AZURE_CONFIG_DIR. The provider and the
# state backend authenticate through that CLI and refresh its tokens as they
# expire — so the expired-session lock AWS's host-credentials.js exists for
# cannot happen. The person must hold the deployer's grants for an
# environment (deploy/azure/foundation/iam_deployer.tf), and be an
# administrator for the foundation.
#
# A MULTI-REGION ENVIRONMENT (one with envs/<env>.cells.tfvars.json), applied
# with no TF_CELL, is every stack in AWS's order (deploy/azure/CLAUDE.md,
# *The apply order*):
#   1. each cell with no state yet, `base`, the primary first — everything
#      but running nodes, and no read of the global state;
#   2. global/ — the global database, the peering, the shared secrets,
#      Traffic Manager; it reads every cell's state;
#   3. each cell, `full`, the primary first — the nodes, told where the
#      global tier is; the primary's make the global schema.
# DESTROY reverses it: global/ while the cells it reads still exist, then
# each cell in `base`, so that no cell's destroy reads a global state that is
# gone. The cells run one after another, not at once as AWS's do (#367):
# each cell's node-a answers an ACME challenge in the one zone, and three at
# once is three writers of one TXT record set.
#
# deploy/azure/dns-delegation/ IS NOT A STACK HERE: it needs AWS credentials
# as well, and is applied once by hand (deploy/azure/CLAUDE.md).
# ---------------------------------------------------------------------------
set -euo pipefail

TF_STACK="${TF_STACK:-environment}"
TF_ENV="${TF_ENV:-dev}"
TF_ACTION="${TF_ACTION:-plan}"
TF_CELL="${TF_CELL:-}"
TF_CELL_PHASE="${TF_CELL_PHASE:-full}"

say() { echo "==> [azure/${TF_STACK}/${TF_ENV}${TF_CELL:+/${TF_CELL}}] $*" >&2; }
die() { echo "ERROR: $*" >&2; exit 1; }

command -v terraform > /dev/null 2>&1 || die "terraform not found in the container."
command -v az > /dev/null 2>&1 || die "the Azure CLI not found in the container."

if ! [[ "${TF_ENV}" =~ ^[a-z][a-z0-9]{1,11}$ ]];
then
  die "TF_ENV='${TF_ENV}' is not an environment name (2-12 lower-case letters and digits, starting with a letter)."
fi

SUBSCRIPTION="${AZURE_SUBSCRIPTION_ID:-}"
[ -n "${SUBSCRIPTION}" ] || die "AZURE_SUBSCRIPTION_ID is required: the subscription the foundation was applied to."
export TF_VAR_subscription_id="${SUBSCRIPTION}"
export ARM_SUBSCRIPTION_ID="${SUBSCRIPTION}"

# --- Credentials --------------------------------------------------------------
export AZURE_CONFIG_DIR="${HOME}/.azure"
if [ -n "${AZURE_CONFIG_B64:-}" ];
then
  mkdir -p "${AZURE_CONFIG_DIR}"
  chmod 0700 "${AZURE_CONFIG_DIR}"
  ( umask 077; printf '%s' "${AZURE_CONFIG_B64}" | base64 -d | tar -xzf - -C "${AZURE_CONFIG_DIR}" )
  unset AZURE_CONFIG_B64
fi
az account set --subscription "${SUBSCRIPTION}" > /dev/null 2>&1 || \
  die "the Azure CLI login cannot use subscription ${SUBSCRIPTION}. Run 'az login' on the host first."
say "acting as $(az account show --query user.name -o tsv 2> /dev/null || echo '(unknown)')"

# --- The state ------------------------------------------------------------------
# bootstrap-state.sh's names; the account's is a formula of the subscription,
# so no stack has to be told it.
STATE_GROUP="${STATE_RESOURCE_GROUP:-mock-sts-terraform-state}"
STATE_ACCOUNT="${STATE_STORAGE_ACCOUNT:-$(printf 'mockststate%s' "${SUBSCRIPTION//-/}" | cut -c1-24)}"
export TF_VAR_state_storage_account="${STATE_ACCOUNT}"
export TF_VAR_state_resource_group="${STATE_GROUP}"
backend_args() {
  printf '%s\n' \
    "-backend-config=subscription_id=${SUBSCRIPTION}" \
    "-backend-config=resource_group_name=${STATE_GROUP}" \
    "-backend-config=storage_account_name=${STATE_ACCOUNT}" \
    "-backend-config=key=$1"
}

ROOT=/workspace/deploy/azure
ENVS="${ROOT}/environment/envs"
CELLS_FILE="${ENVS}/${TF_ENV}.cells.tfvars.json"

# INT and TERM become an INTERRUPT to terraform, which finishes what is in
# flight, writes state and releases the lock (deploy/aws/entrypoint.sh's `tf`).
tf() {
  terraform "$@" &
  TF_PID=$!
  trap 'kill -INT "${TF_PID}" 2>/dev/null || true' INT TERM
  local rc=0
  while :; do
    wait "${TF_PID}" && rc=0 || rc=$?
    kill -0 "${TF_PID}" 2>/dev/null || break
  done
  trap - INT TERM
  return "${rc}"
}

# run <action> <stack dir> <state key> [var-file args…] — one stack, one action.
run() {
  local action="$1" dir="$2" key="$3"
  shift 3
  local -a backend vars=("$@")
  mapfile -t backend < <(backend_args "${key}")
  (
    cd "${dir}"
    terraform init -input=false -no-color -reconfigure "${backend[@]}" >&2
    case "${action}" in
      init)     say "init only." ;;
      validate) terraform validate -no-color ;;
      plan)     tf plan -input=false -no-color "${vars[@]}" ;;
      apply)    tf apply -input=false -no-color -auto-approve "${vars[@]}" ;;
      destroy)
        # A destroy that fails half way leaves VMs and databases billing. The
        # usual causes are a replica still being deleted when its primary is
        # asked to go, and a private endpoint's connection still draining;
        # once more after a minute, before giving up.
        if ! tf destroy -input=false -no-color -auto-approve "${vars[@]}";
        then
          say "destroy failed; retrying once in 60 seconds"
          sleep 60
          tf destroy -input=false -no-color -auto-approve "${vars[@]}" || \
            die "DESTROY FAILED TWICE — '${TF_ENV}' may still be running and billing. Re-run the destroy."
        fi
        ;;
      # Adopt a resource an interrupted apply created and did not record
      # (deploy/aws/entrypoint.sh argues it).
      import)
        [ -n "${TF_IMPORT_ADDRESS:-}" ] && [ -n "${TF_IMPORT_ID:-}" ] || \
          die "import needs TF_IMPORT_ADDRESS and TF_IMPORT_ID."
        tf import -input=false -no-color "${vars[@]}" \
          "${TF_IMPORT_ADDRESS}" "${TF_IMPORT_ID}"
        ;;
      output)      terraform output -no-color ;;
      output-json) terraform output -json ;;
      *) die "unknown TF_ACTION='${action}' (init | validate | plan | apply | destroy | import | output | output-json)." ;;
    esac
  )
}

# --- The foundation ---------------------------------------------------------------
if [ "${TF_STACK}" = "foundation" ];
then
  unset TF_VAR_image_tag TF_VAR_allowed_cidrs
  run "${TF_ACTION}" "${ROOT}/foundation" foundation.tfstate
  say "${TF_ACTION} complete."
  exit 0
fi

export TF_VAR_environment="${TF_ENV}"
ENV_VARS=()
[ -f "${ENVS}/${TF_ENV}.tfvars" ] && ENV_VARS=(-var-file="envs/${TF_ENV}.tfvars")

# --- A single-cell environment ------------------------------------------------------
if [ ! -f "${CELLS_FILE}" ];
then
  [ "${TF_STACK}" = "environment" ] || die "${TF_ENV} has no cells file, so it has no ${TF_STACK} stack."
  [ -z "${TF_CELL}" ] || die "${TF_ENV} has no cells file; TF_CELL means nothing to it."
  [ "${#ENV_VARS[@]}" -eq 0 ] || say "using envs/${TF_ENV}.tfvars"
  run "${TF_ACTION}" "${ROOT}/environment" "environment/${TF_ENV}.tfstate" "${ENV_VARS[@]}"
  say "${TF_ACTION} complete."
  exit 0
fi

# --- A multi-region environment -------------------------------------------------------
PRIMARY="$(jq -r '.primary_cell' "${CELLS_FILE}")"
mapfile -t CELLS < <(jq -r --arg p "${PRIMARY}" '[$p] + ([.cells | keys[]] - [$p]) | .[]' "${CELLS_FILE}")
say "cells: ${CELLS[*]} (primary ${PRIMARY})"

cell() {
  local action="$1" id="$2" phase="$3"
  say "cell ${id}, ${phase}: ${action}"
  TF_VAR_cell="${id}" TF_VAR_cell_phase="${phase}" \
    run "${action}" "${ROOT}/environment" "environment/${TF_ENV}/${id}.tfstate" \
      "${ENV_VARS[@]}" -var-file="envs/${TF_ENV}.cells.tfvars.json" || \
    die "cell ${id} (${phase}): ${action} failed. The steps before it stand; the same command resumes."
}

global() {
  local action="$1"
  say "global: ${action}"
  (
    unset TF_VAR_image_tag TF_VAR_allowed_cidrs
    run "${action}" "${ROOT}/global" "environment/${TF_ENV}/global.tfstate" \
      -var-file="${CELLS_FILE}"
  ) || die "global: ${action} failed. The steps before it stand; the same command resumes."
}

# Whether a cell's state holds any resource: a cell that has one is past
# `base`, and applying `base` again would scale a running cell to nothing.
has_state() {
  local id="$1" n
  n="$(
    cd "${ROOT}/environment" &&
    mapfile -t backend < <(backend_args "environment/${TF_ENV}/${id}.tfstate") &&
    terraform init -input=false -no-color -reconfigure "${backend[@]}" > /dev/null 2>&1 &&
    terraform state pull 2> /dev/null | jq '[.resources[]?] | length' 2> /dev/null
  )" || n=0
  [ "${n:-0}" -gt 0 ]
}

if [ "${TF_STACK}" = "global" ];
then
  global "${TF_ACTION}"
  say "${TF_ACTION} complete."
  exit 0
fi

if [ -n "${TF_CELL}" ];
then
  jq -e --arg c "${TF_CELL}" '.cells | has($c)' "${CELLS_FILE}" > /dev/null || \
    die "${TF_CELL} is not a cell of ${TF_ENV}."
  cell "${TF_ACTION}" "${TF_CELL}" "${TF_CELL_PHASE}"
  say "${TF_ACTION} complete."
  exit 0
fi

case "${TF_ACTION}" in
  apply)
    for c in "${CELLS[@]}"; do
      if has_state "${c}";
      then
        say "cell ${c} has state; no base phase"
      else
        cell apply "${c}" base
      fi
    done
    global apply
    for c in "${CELLS[@]}"; do
      cell apply "${c}" full
    done
    global output
    ;;
  plan)
    global plan
    for c in "${CELLS[@]}"; do
      cell plan "${c}" full
    done
    ;;
  destroy)
    global destroy
    for c in "${CELLS[@]}"; do
      cell destroy "${c}" base
    done
    ;;
  output)
    for c in "${CELLS[@]}"; do
      cell output "${c}" full
    done
    global output
    ;;
  *) die "${TF_ACTION} on a multi-region environment wants TF_CELL (or TF_STACK=global)." ;;
esac

say "${TF_ACTION} complete."
