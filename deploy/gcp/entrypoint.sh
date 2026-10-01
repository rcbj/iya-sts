#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# File: deploy/gcp/entrypoint.sh
#
# ---------------------------------------------------------------------------
# ONE STACK, ONE ENVIRONMENT, ONE ACTION, INSIDE THE GCP TERRAFORM IMAGE
# (issue #95) — deploy/aws/entrypoint.sh's contract without the cells.
#
#   TF_STACK    environment (default) | foundation
#   TF_ENV      an environment name, 2-12 [a-z0-9]
#   TF_ACTION   init | validate | plan | apply | destroy | import | output |
#               output-json
#   GOOGLE_CLOUD_PROJECT   the project (required)
#
# CREDENTIALS: the host's application-default credentials, handed over by
# terraform-local.sh as GCP_ADC_B64 through a private env file (never a
# command line, never a bind mount — the host's file is 0600 and this
# container is not its owner), written here to a file only this user reads.
#
# THE DEPLOYER IS IMPERSONATED for the environment stack
# (GOOGLE_IMPERSONATE_SERVICE_ACCOUNT, which the provider honours): the
# person's own credentials only mint the deployer's hour-long tokens, and the
# provider mints them again as they expire — so the expired-session failure
# that left AWS's state locked (deploy/aws/CLAUDE.md, *Running it by hand*)
# cannot happen here. The foundation is applied as the person, who must be
# an administrator of the project.
#
# deploy/gcp/dns-delegation/ IS NOT A STACK HERE: it needs AWS credentials as
# well, and is applied once by hand (deploy/gcp/CLAUDE.md).
# ---------------------------------------------------------------------------
set -euo pipefail

TF_STACK="${TF_STACK:-environment}"
TF_ENV="${TF_ENV:-dev}"
TF_ACTION="${TF_ACTION:-plan}"

say() { echo "==> [gcp/${TF_STACK}/${TF_ENV}] $*" >&2; }
die() { echo "ERROR: $*" >&2; exit 1; }

command -v terraform > /dev/null 2>&1 || die "terraform not found in the container."

if ! [[ "${TF_ENV}" =~ ^[a-z][a-z0-9]{1,11}$ ]];
then
  die "TF_ENV='${TF_ENV}' is not an environment name (2-12 lower-case letters and digits, starting with a letter)."
fi

PROJECT="${GOOGLE_CLOUD_PROJECT:-}"
[ -n "${PROJECT}" ] || die "GOOGLE_CLOUD_PROJECT is required: the project the foundation was applied to."
export TF_VAR_project_id="${PROJECT}"

# --- Credentials --------------------------------------------------------------
if [ -n "${GCP_ADC_B64:-}" ];
then
  adc_dir="${HOME}/.config/gcloud"
  mkdir -p "${adc_dir}"
  chmod 0700 "${adc_dir}"
  ( umask 077; printf '%s' "${GCP_ADC_B64}" | base64 -d > "${adc_dir}/application_default_credentials.json" )
  unset GCP_ADC_B64
  export GOOGLE_APPLICATION_CREDENTIALS="${adc_dir}/application_default_credentials.json"
fi
[ -n "${GOOGLE_APPLICATION_CREDENTIALS:-}" ] || \
  die "no application-default credentials. Run 'gcloud auth application-default login' on the host first."

DEPLOYER="${MOCK_STS_DEPLOYER:-mock-sts-deployer@${PROJECT}.iam.gserviceaccount.com}"
if [ "${TF_STACK}" != "foundation" ];
then
  export GOOGLE_IMPERSONATE_SERVICE_ACCOUNT="${DEPLOYER}"
  say "acting as ${DEPLOYER} (impersonated)"
else
  say "acting as the host's own credentials (the foundation is an administrator's)"
fi

# --- The stack and its state --------------------------------------------------
bucket="mock-sts-terraform-state-${PROJECT}"
BACKEND_ARGS=(-backend-config="bucket=${bucket}")
case "${TF_STACK}" in
  environment)
    TF_DIR=/workspace/deploy/gcp/environment
    BACKEND_ARGS+=(-backend-config="prefix=environment/${TF_ENV}")
    export TF_VAR_environment="${TF_ENV}"
    ;;
  foundation)
    # Its prefix is in its own backend block.
    TF_DIR=/workspace/deploy/gcp/foundation
    ;;
  *) die "unknown TF_STACK='${TF_STACK}' (environment | foundation)." ;;
esac

VAR_FILE_ARGS=()
if [ "${TF_STACK}" = "environment" ] && [ -f "${TF_DIR}/envs/${TF_ENV}.tfvars" ];
then
  say "using envs/${TF_ENV}.tfvars"
  VAR_FILE_ARGS=(-var-file="envs/${TF_ENV}.tfvars")
fi

cd "${TF_DIR}"

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

say "terraform init"
terraform init -input=false -no-color -reconfigure "${BACKEND_ARGS[@]}" >&2

case "${TF_ACTION}" in
  init)     say "init only." ;;
  validate) terraform validate -no-color ;;
  plan)     tf plan -input=false -no-color "${VAR_FILE_ARGS[@]}" ;;
  apply)    tf apply -input=false -no-color -auto-approve "${VAR_FILE_ARGS[@]}" ;;
  destroy)
    # A destroy that fails half way leaves VMs and a database billing. The
    # usual causes are an instance group still draining and Cloud SQL
    # refusing to delete a primary while its replica is being deleted; once
    # more after a minute, before giving up.
    if ! tf destroy -input=false -no-color -auto-approve "${VAR_FILE_ARGS[@]}";
    then
      say "destroy failed; retrying once in 60 seconds"
      sleep 60
      tf destroy -input=false -no-color -auto-approve "${VAR_FILE_ARGS[@]}" || \
        die "DESTROY FAILED TWICE — '${TF_ENV}' may still be running and billing. Re-run the destroy."
    fi
    ;;
  # Adopt a resource an interrupted apply created and did not record
  # (deploy/aws/entrypoint.sh argues it).
  import)
    [ -n "${TF_IMPORT_ADDRESS:-}" ] && [ -n "${TF_IMPORT_ID:-}" ] || \
      die "import needs TF_IMPORT_ADDRESS and TF_IMPORT_ID."
    tf import -input=false -no-color "${VAR_FILE_ARGS[@]}" \
      "${TF_IMPORT_ADDRESS}" "${TF_IMPORT_ID}"
    ;;
  output)      terraform output -no-color ;;
  output-json) terraform output -json ;;
  *) die "unknown TF_ACTION='${TF_ACTION}' (init | validate | plan | apply | destroy | import | output | output-json)." ;;
esac

say "${TF_ACTION} complete."
