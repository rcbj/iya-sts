#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# File: deploy/multicloud/entrypoint.sh
#
# ---------------------------------------------------------------------------
# ONE MULTI-CLOUD ENVIRONMENT, EVERY STACK, IN ORDER (#97).
#
#   TF_ENV      the environment; deploy/multicloud/envs/<env>.cells.tfvars.json
#               must exist, and <env>.aws.tfvars and <env>.gcp.tfvars beside it
#   TF_ACTION   apply | destroy | plan | output
#   TF_STEP     optional: ONE step — aws-cell:<id>:<base|full>,
#               gcp-cell:<id>:<base|full>, interconnect, aws-global,
#               gcp-global — with TF_ACTION apply, destroy or plan
#   GOOGLE_CLOUD_PROJECT, and both clouds' credentials (terraform-local.sh)
#
# THE ORDER, AND WHY (deploy/multicloud/CLAUDE.md argues each):
#   1. every AWS cell with no state, `base`, the primary first
#   2. every GCP cell with no state, `base`   — each needs the shared network,
#      which the GCP foundation made
#   3. interconnect   — the VPNs, names and Route 53 tree; reads every cell
#   4. aws-global     — the writer (and its publication's parameters), the
#      AWS replicas and peering, the global secrets
#   5. gcp-global     — the global secrets copied to GCP, the Cloud SQL copies
#   6. every AWS cell `full`, the primary first (its global-schema-init makes
#      the publication), then every GCP cell `full` (each subscribes)
# DESTROY is the reverse: interconnect, gcp-global, aws-global, then every
# cell in `base`, so that no cell's destroy reads a global state that is gone.
#
# State keys match the single-cloud tools', so `deploy/aws/terraform-local.sh`
# with TF_CELL and `deploy/gcp/...` can still read a cell; neither may
# ORCHESTRATE this environment, which only this script knows the order of.
# ---------------------------------------------------------------------------
set -euo pipefail

TF_ENV="${TF_ENV:?TF_ENV is required}"
TF_ACTION="${TF_ACTION:-plan}"
TF_STEP="${TF_STEP:-}"

say() { echo "==> [multicloud/${TF_ENV}${TF_STEP:+/${TF_STEP}}] $*" >&2; }
die() { echo "ERROR: $*" >&2; exit 1; }

command -v terraform > /dev/null 2>&1 || die "terraform not found in the container."
command -v aws > /dev/null 2>&1 || die "the aws CLI not found in the container."

[[ "${TF_ENV}" =~ ^[a-z][a-z0-9]{1,10}$ ]] || \
  die "TF_ENV='${TF_ENV}': a multi-cloud environment is 2-11 lower-case letters and digits."

ROOT=/workspace/deploy
ENVS="${ROOT}/multicloud/envs"
CELLS_FILE="${ENVS}/${TF_ENV}.cells.tfvars.json"
[ -f "${CELLS_FILE}" ] || die "no ${CELLS_FILE}: not a multi-cloud environment."
for f in aws gcp; do
  [ -f "${ENVS}/${TF_ENV}.${f}.tfvars" ] || die "no ${ENVS}/${TF_ENV}.${f}.tfvars."
done

PROJECT="${GOOGLE_CLOUD_PROJECT:?GOOGLE_CLOUD_PROJECT is required}"
PRIMARY="$(jq -r '.primary_cell' "${CELLS_FILE}")"
mapfile -t AWS_CELLS < <(jq -r --arg p "${PRIMARY}" \
  '[$p] + ([.cells | to_entries[] | select((.value.cloud // "aws") == "aws") | .key] - [$p]) | .[]' "${CELLS_FILE}")
mapfile -t GCP_CELLS < <(jq -r \
  '.cells | to_entries[] | select(.value.cloud == "gcp") | .key' "${CELLS_FILE}")
say "AWS cells: ${AWS_CELLS[*]} (primary ${PRIMARY}); GCP cells: ${GCP_CELLS[*]}"

# --- AWS: who we are, and the deployer role (deploy/aws/entrypoint.sh) -------
identity="$(aws sts get-caller-identity --output json 2> /dev/null)" || \
  die "no valid AWS credentials."
account="$(jq -r .Account <<< "${identity}")"
arn="$(jq -r .Arn <<< "${identity}")"
role_arn="${MOCK_STS_DEPLOYER_ROLE_ARN:-}"
for user in ${MOCK_STS_DEPLOYER_USERS:-mock-sts/mock-sts-deployer git_user6}; do
  if [ -z "${role_arn}" ] && [[ "${arn}" == *":user/${user}" ]];
  then
    role_arn="arn:aws:iam::${account}:role/mock-sts-deployer"
  fi
done
if [ -n "${role_arn}" ];
then
  creds="$(aws sts assume-role --role-arn "${role_arn}" \
    --role-session-name "mock-sts-${TF_ENV}-mc-$(date -u +%s)" \
    --duration-seconds "${MOCK_STS_ROLE_SECONDS:-14400}" \
    --query Credentials --output json)" || die "could not assume ${role_arn}."
  export AWS_ACCESS_KEY_ID="$(jq -r .AccessKeyId <<< "${creds}")"
  export AWS_SECRET_ACCESS_KEY="$(jq -r .SecretAccessKey <<< "${creds}")"
  export AWS_SESSION_TOKEN="$(jq -r .SessionToken <<< "${creds}")"
  arn="$(aws sts get-caller-identity --query Arn --output text)"
fi
say "AWS: acting as ${arn}"
AWS_BUCKET="mock-sts-terraform-state-${account}"

# --- GCP: the host's ADC, impersonating the deployer (deploy/gcp/entrypoint.sh)
if [ -n "${GCP_ADC_B64:-}" ];
then
  adc_dir="${HOME}/.config/gcloud"
  mkdir -p "${adc_dir}"
  chmod 0700 "${adc_dir}"
  ( umask 077; printf '%s' "${GCP_ADC_B64}" | base64 -d > "${adc_dir}/application_default_credentials.json" )
  unset GCP_ADC_B64
  export GOOGLE_APPLICATION_CREDENTIALS="${adc_dir}/application_default_credentials.json"
fi
[ -n "${GOOGLE_APPLICATION_CREDENTIALS:-}" ] || die "no GCP application-default credentials."
export GOOGLE_IMPERSONATE_SERVICE_ACCOUNT="${MOCK_STS_GCP_DEPLOYER:-mock-sts-deployer@${PROJECT}.iam.gserviceaccount.com}"
say "GCP: acting as ${GOOGLE_IMPERSONATE_SERVICE_ACCOUNT} (impersonated)"
GCP_BUCKET="mock-sts-terraform-state-${PROJECT}"

# INT and TERM become an interrupt to terraform, which releases its lock
# (deploy/aws/entrypoint.sh's `tf`).
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

# --- The steps ----------------------------------------------------------------
# stack <dir> <backend args…> -- <var-file args…>, then the action in $1 of run.
STEP_DIR=""
STEP_BACKEND=()
STEP_VARS=()

describe_step() {
  local kind="$1" cell="${2:-}" phase="${3:-full}"
  STEP_VARS=(-var-file="${CELLS_FILE}")
  unset TF_VAR_cell TF_VAR_cell_phase
  export TF_VAR_environment="${TF_ENV}"
  case "${kind}" in
    aws-cell)
      STEP_DIR="${ROOT}/aws/environment"
      STEP_BACKEND=(-backend-config="bucket=${AWS_BUCKET}" -backend-config="key=environment/${TF_ENV}/${cell}.tfstate")
      STEP_VARS=(-var-file="${ENVS}/${TF_ENV}.aws.tfvars" "${STEP_VARS[@]}")
      export TF_VAR_cell="${cell}" TF_VAR_cell_phase="${phase}"
      ;;
    gcp-cell)
      STEP_DIR="${ROOT}/gcp/environment"
      STEP_BACKEND=(-backend-config="bucket=${GCP_BUCKET}" -backend-config="prefix=environment/${TF_ENV}/${cell}")
      STEP_VARS=(-var-file="${ENVS}/${TF_ENV}.gcp.tfvars" "${STEP_VARS[@]}")
      export TF_VAR_cell="${cell}" TF_VAR_cell_phase="${phase}" TF_VAR_project_id="${PROJECT}"
      ;;
    aws-global)
      STEP_DIR="${ROOT}/aws/global"
      STEP_BACKEND=(-backend-config="bucket=${AWS_BUCKET}" -backend-config="key=environment/${TF_ENV}/global.tfstate")
      ;;
    interconnect)
      STEP_DIR="${ROOT}/multicloud/interconnect"
      STEP_BACKEND=(-backend-config="bucket=${AWS_BUCKET}" -backend-config="key=environment/${TF_ENV}/interconnect.tfstate")
      export TF_VAR_project_id="${PROJECT}"
      ;;
    gcp-global)
      STEP_DIR="${ROOT}/multicloud/gcp-global"
      STEP_BACKEND=(-backend-config="bucket=${GCP_BUCKET}" -backend-config="prefix=environment/${TF_ENV}/gcp-global")
      export TF_VAR_project_id="${PROJECT}"
      ;;
    *) die "unknown step kind '${kind}'." ;;
  esac
}

# The stacks' variables that are not in every stack (image_tag,
# allowed_cidrs) are set only for the cells, which declare them.
run_step() {
  local action="$1" kind="$2" cell="${3:-}" phase="${4:-full}"
  describe_step "${kind}" "${cell}" "${phase}"
  local label="${kind}${cell:+:${cell}}${cell:+:${phase}}"
  say "${label}: ${action}"
  (
    cd "${STEP_DIR}"
    if [ "${kind}" != "aws-cell" ] && [ "${kind}" != "gcp-cell" ];
    then
      unset TF_VAR_image_tag TF_VAR_allowed_cidrs
    fi
    terraform init -input=false -no-color -reconfigure "${STEP_BACKEND[@]}" >&2
    case "${action}" in
      apply)   tf apply -input=false -no-color -auto-approve "${STEP_VARS[@]}" ;;
      plan)    tf plan -input=false -no-color "${STEP_VARS[@]}" ;;
      destroy) tf destroy -input=false -no-color -auto-approve "${STEP_VARS[@]}" ;;
      output)  terraform output -no-color ;;
      *) die "unknown action '${action}'." ;;
    esac
  ) || die "${label}: ${action} failed. The steps before it stand; the same command resumes."
}

# Whether a step's state holds any resource: a cell that has one is past
# `base`, and applying `base` again would scale a running cell to nothing.
has_state() {
  local kind="$1" cell="$2" tmp
  tmp="$(mktemp)"
  case "${kind}" in
    aws-cell)
      aws s3 cp "s3://${AWS_BUCKET}/environment/${TF_ENV}/${cell}.tfstate" "${tmp}" \
        > /dev/null 2>&1 || { rm -f "${tmp}"; return 1; }
      ;;
    gcp-cell)
      # Read through terraform, which holds the GCP credentials.
      describe_step gcp-cell "${cell}" base
      ( cd "${STEP_DIR}" &&
        terraform init -input=false -no-color -reconfigure "${STEP_BACKEND[@]}" > /dev/null 2>&1 &&
        terraform state pull > "${tmp}" 2> /dev/null ) || { rm -f "${tmp}"; return 1; }
      ;;
  esac
  local n
  n="$(jq '[.resources[]?] | length' "${tmp}" 2> /dev/null || echo 0)"
  rm -f "${tmp}"
  [ "${n}" -gt 0 ]
}

# testidpna answers the same public name: it and a multi-cloud environment
# that also does cannot both run (deploy/multicloud/CLAUDE.md).
guard_public_name() {
  local other="${MOCK_STS_CONFLICTING_ENV:-testidpna}" tmp n
  tmp="$(mktemp)"
  if aws s3 cp "s3://${AWS_BUCKET}/environment/${other}/global.tfstate" "${tmp}" > /dev/null 2>&1;
  then
    n="$(jq '[.resources[]?] | length' "${tmp}" 2> /dev/null || echo 0)"
    rm -f "${tmp}"
    [ "${n}" -eq 0 ] || \
      die "${other} is standing and answers the same public name; destroy it first (or set MOCK_STS_CONFLICTING_ENV)."
  fi
  rm -f "${tmp}"
}

if [ -n "${TF_STEP}" ];
then
  IFS=':' read -r kind cell phase <<< "${TF_STEP}"
  run_step "${TF_ACTION}" "${kind}" "${cell:-}" "${phase:-full}"
  say "done."
  exit 0
fi

case "${TF_ACTION}" in
  apply)
    guard_public_name
    for c in "${AWS_CELLS[@]}"; do
      has_state aws-cell "${c}" || run_step apply aws-cell "${c}" base
    done
    for c in "${GCP_CELLS[@]}"; do
      has_state gcp-cell "${c}" || run_step apply gcp-cell "${c}" base
    done
    run_step apply interconnect
    run_step apply aws-global
    run_step apply gcp-global
    for c in "${AWS_CELLS[@]}"; do
      run_step apply aws-cell "${c}" full
    done
    for c in "${GCP_CELLS[@]}"; do
      run_step apply gcp-cell "${c}" full
    done
    run_step output interconnect
    ;;
  plan)
    run_step plan interconnect
    run_step plan aws-global
    run_step plan gcp-global
    for c in "${AWS_CELLS[@]}"; do
      run_step plan aws-cell "${c}" full
    done
    for c in "${GCP_CELLS[@]}"; do
      run_step plan gcp-cell "${c}" full
    done
    ;;
  destroy)
    run_step destroy interconnect
    run_step destroy gcp-global
    run_step destroy aws-global
    for c in "${GCP_CELLS[@]}"; do
      run_step destroy gcp-cell "${c}" base
    done
    for c in "${AWS_CELLS[@]}"; do
      run_step destroy aws-cell "${c}" base
    done
    ;;
  output)
    run_step output interconnect
    ;;
  *) die "unknown TF_ACTION='${TF_ACTION}' (apply | destroy | plan | output)." ;;
esac

say "${TF_ACTION} complete."
