#!/usr/bin/env bash
#
# File: deploy/aws/entrypoint.sh
#
# ---------------------------------------------------------------------------
# CONTAINER ENTRYPOINT: ONE TERRAFORM STACK, ONE ENVIRONMENT, ONE ACTION
# (issue #51). The parent project's infra/entrypoint.sh arrangement. State is
# remote (S3), so this runs the same in GitHub Actions and on a laptop.
#
# AWS credentials come from OUTSIDE the container, as environment variables.
# When they are the key of one of the deployer role's two IAM USERS —
# `mock-sts-deployer` (a person's) or `git_user6` (the workflow's), neither of
# which may do anything else — the entrypoint assumes the `mock-sts-deployer`
# ROLE first, so a caller needs the user's key and nothing else (the two
# repository secrets).
# Any other identity (an administrator, or role credentials already assumed) is
# used as it is. MOCK_STS_DEPLOYER_ROLE_ARN forces a role.
#
# Config (env vars):
#   TF_STACK     environment | foundation | spiffe-realm
#                | suite-callbacks                               (environment)
#   TF_ENV       the environment's name, 2-12 [a-z0-9]           (dev)
#   TF_REALM     spiffe-realm only: the realm id, or `default`
#   TF_ACTION    init | validate | plan | apply | destroy | output
#                | output-json | suite | ecr-password                          (plan)
#   AWS_REGION                                                   (us-west-2)
#
#   TF_VAR_image_tag      the service image tag (the commit), for plan/apply
#   TF_VAR_allowed_cidrs  JSON list, e.g. ["203.0.113.4/32"], for plan/apply
#   TF_VAR_workload_port, TF_VAR_server_port   spiffe-realm plan/apply: the
#                         realm's two SPIFFE ports (deploy/aws/CLAUDE.md)
#   TF_VAR_image_tag      suite-callbacks plan/apply: the run's image tag
#                         (run-suite.sh pushes runner-<tag> and pep-<tag>)
#   STS_SUITE_EXCLUDE, STS_SUITE_ONLY, STS_SUITE_KEEP_REALMS,
#   STS_SUITE_JOB_TIMEOUT_MS   passed through by the `suite` action
#
# THE TWO ACTIONS THE PARENT DOES NOT HAVE:
#   suite         deploy/aws/run-suite-in-aws.sh against TF_ENV: start the
#                 suite task in the environment's VPC, wait for it, and put its
#                 report in /workspace/report (mount a directory there). Exits
#                 with the suite's code.
#   ecr-password  prints `aws ecr get-login-password` for the credentials the
#                 container ends up with, so a host that builds the images can
#                 `docker login` without installing the AWS CLI.
#
# `foundation` is an administrator's stack (the deployer cannot create itself)
# and is only reachable here with administrator credentials, from
# terraform-local.sh; the workflow never names it.
# ---------------------------------------------------------------------------
set -euo pipefail

: "${TF_STACK:=environment}"
: "${TF_ENV:=dev}"
: "${TF_ACTION:=plan}"
: "${AWS_REGION:=us-west-2}"
export AWS_REGION AWS_DEFAULT_REGION="${AWS_REGION}"

say() { echo "==> [${TF_STACK}${TF_STACK:+/}${TF_ENV}] $*" >&2; }
die() { echo "ERROR: $*" >&2; exit 1; }

command -v terraform >/dev/null 2>&1 || die "terraform not found in the container."
command -v aws >/dev/null 2>&1 || die "the aws CLI not found in the container."

if ! [[ "${TF_ENV}" =~ ^[a-z][a-z0-9]{1,11}$ ]];
then
  die "TF_ENV='${TF_ENV}' is not an environment name (2-12 lower-case letters and digits, starting with a letter)."
fi

# --- Who we are, and the deployer role when we are its user ----------------
identity="$(aws sts get-caller-identity --output json 2>/dev/null)" || \
  die "no valid AWS credentials. Provide AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY (and AWS_SESSION_TOKEN for temporary ones)."
account="$(jq -r .Account <<<"${identity}")"
arn="$(jq -r .Arn <<<"${identity}")"

role_arn="${MOCK_STS_DEPLOYER_ROLE_ARN:-}"
# The deployer role's two users (foundation/iam_deployer.tf): a person's, and
# the workflow's (git_user6). MOCK_STS_DEPLOYER_USERS names others.
deployer_users="${MOCK_STS_DEPLOYER_USERS:-mock-sts/mock-sts-deployer git_user6}"
for user in ${deployer_users}; do
  if [ -z "${role_arn}" ] && [[ "${arn}" == *":user/${user}" ]];
  then
    role_arn="arn:aws:iam::${account}:role/mock-sts-deployer"
  fi
done
if [ -n "${role_arn}" ];
then
  say "assuming ${role_arn}"
  creds="$(aws sts assume-role --role-arn "${role_arn}" \
    --role-session-name "mock-sts-${TF_ENV}-${TF_ACTION}-$(date -u +%s)" \
    --duration-seconds "${MOCK_STS_ROLE_SECONDS:-14400}" \
    --query Credentials --output json)" || die "could not assume ${role_arn}."
  export AWS_ACCESS_KEY_ID="$(jq -r .AccessKeyId <<<"${creds}")"
  export AWS_SECRET_ACCESS_KEY="$(jq -r .SecretAccessKey <<<"${creds}")"
  export AWS_SESSION_TOKEN="$(jq -r .SessionToken <<<"${creds}")"
  arn="$(aws sts get-caller-identity --query Arn --output text)"
fi
say "acting as ${arn}"

if [ "${TF_ACTION}" = "ecr-password" ];
then
  aws ecr get-login-password
  exit 0
fi

# --- The stack and its state ------------------------------------------------
bucket="mock-sts-terraform-state-${account}"
case "${TF_STACK}" in
  environment)
    TF_DIR=/workspace/deploy/aws/environment
    STATE_KEY="environment/${TF_ENV}.tfstate"
    export TF_VAR_environment="${TF_ENV}"
    ;;
  foundation)
    TF_DIR=/workspace/deploy/aws/foundation
    STATE_KEY="foundation/terraform.tfstate"
    ;;
  spiffe-realm)
    # ONE STATE PER (ENVIRONMENT, REALM), under `environment/` because that is
    # the only prefix the deployer role may write state under. The realm id is
    # the service's own grammar (common/realms.js), checked here because it
    # goes into an S3 key before Terraform ever sees it.
    [[ "${TF_REALM:-}" =~ ^[a-z0-9][a-z0-9-]{0,30}$ ]] || \
      die "TF_STACK=spiffe-realm needs TF_REALM, a realm id (or 'default'); got '${TF_REALM:-}'."
    TF_DIR=/workspace/deploy/aws/spiffe-realm
    STATE_KEY="environment/${TF_ENV}/spiffe-realm/${TF_REALM}.tfstate"
    export TF_VAR_environment="${TF_ENV}" TF_VAR_realm="${TF_REALM}"
    ;;
  suite-callbacks)
    # The suite's callback task for one run (deploy/aws/suite-callbacks/),
    # created and destroyed by run-suite.sh around each run.
    TF_DIR=/workspace/deploy/aws/suite-callbacks
    STATE_KEY="environment/${TF_ENV}/suite-callbacks.tfstate"
    export TF_VAR_environment="${TF_ENV}"
    ;;
  *) die "unknown TF_STACK='${TF_STACK}' (environment | foundation | spiffe-realm | suite-callbacks)." ;;
esac

# The environment's two variables with no default. plan and apply need the
# real ones — a guessed allowed_cidrs is a load balancer that refuses whoever
# is meant to use it, and a guessed image tag deploys an image that does not
# exist. Every other action reads state or destroys it, and Terraform still
# insists on a value, so a placeholder is given there and said so.
if [ "${TF_STACK}" = "environment" ];
then
  case "${TF_ACTION}" in
    plan|apply)
      [ -n "${TF_VAR_image_tag:-}" ] || die "TF_ACTION=${TF_ACTION} needs TF_VAR_image_tag (the commit the images were pushed under)."
      [ -n "${TF_VAR_allowed_cidrs:-}" ] || die "TF_ACTION=${TF_ACTION} needs TF_VAR_allowed_cidrs, e.g. '[\"203.0.113.4/32\"]'."
      ;;
    *)
      : "${TF_VAR_image_tag:=unused}"
      : "${TF_VAR_allowed_cidrs:=[\"192.0.2.1/32\"]}"
      export TF_VAR_image_tag TF_VAR_allowed_cidrs
      ;;
  esac
fi

# The realm's two ports, the same way: real ones for plan and apply, and a
# placeholder where the action only reads or destroys what state records.
if [ "${TF_STACK}" = "suite-callbacks" ];
then
  case "${TF_ACTION}" in
    plan|apply)
      [ -n "${TF_VAR_image_tag:-}" ] || die "TF_ACTION=${TF_ACTION} needs TF_VAR_image_tag (the run's runner-/pep- image tag)."
      ;;
    *)
      : "${TF_VAR_image_tag:=unused}"
      export TF_VAR_image_tag
      ;;
  esac
fi

if [ "${TF_STACK}" = "spiffe-realm" ];
then
  case "${TF_ACTION}" in
    plan|apply)
      [ -n "${TF_VAR_workload_port:-}" ] || die "TF_ACTION=${TF_ACTION} needs TF_VAR_workload_port (the realm's spiffe.workloadPort)."
      [ -n "${TF_VAR_server_port:-}" ] || die "TF_ACTION=${TF_ACTION} needs TF_VAR_server_port (the realm's spiffe.serverPort)."
      ;;
    *)
      : "${TF_VAR_workload_port:=65001}"
      : "${TF_VAR_server_port:=65002}"
      export TF_VAR_workload_port TF_VAR_server_port
      ;;
  esac
fi

cd "${TF_DIR}"
say "${TF_DIR}"

# AN ENVIRONMENT'S OWN VALUES, when it has a file of them: envs/<name>.tfvars.
# `dev` and `ci` have none and take the variables' defaults, which are the test
# arrangement; a deployment (`testidp`) names what differs.
VAR_FILE_ARGS=()
if [ "${TF_STACK}" = "environment" ] && [ -f "envs/${TF_ENV}.tfvars" ];
then
  say "variables: envs/${TF_ENV}.tfvars"
  VAR_FILE_ARGS=(-var-file="envs/${TF_ENV}.tfvars")
fi
say "state: s3://${bucket}/${STATE_KEY}"

# TERRAFORM IS A CHILD OF THIS SCRIPT, AND THIS SCRIPT IS PID 1 (2026-09-18).
# `docker stop`, `docker kill -s INT` and the launcher's own interrupt reach
# PID 1 only, and bash does not pass a signal on to its foreground child — so
# an interrupted apply was a terraform KILLED when the container went, with
# the S3 state lock still held (twice on testidp). `tf` runs terraform in the
# background and relays INT and TERM to it as an INTERRUPT, which terraform
# answers by finishing what is in flight, writing state and releasing the
# lock. `wait` returns early when a trapped signal arrives, hence the loop.
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
if [ "${TF_STACK}" != "foundation" ];
then
  terraform init -input=false -no-color \
    -backend-config="bucket=${bucket}" -backend-config="key=${STATE_KEY}" >&2
else
  terraform init -input=false -no-color \
    -backend-config="bucket=${bucket}" >&2
fi

case "${TF_ACTION}" in
  init)     say "init only." ;;
  validate) terraform validate -no-color ;;
  plan)     tf plan -input=false -no-color "${VAR_FILE_ARGS[@]}" ;;
  apply)    tf apply -input=false -no-color -auto-approve "${VAR_FILE_ARGS[@]}" ;;
  destroy)
    # A destroy that fails half way leaves resources running and billing; the
    # usual cause is an ENI a stopped task has not released yet. Once more,
    # after a minute, before giving up.
    if ! tf destroy -input=false -no-color -auto-approve "${VAR_FILE_ARGS[@]}";
    then
      say "destroy failed; retrying once in 60 seconds"
      sleep 60
      tf destroy -input=false -no-color -auto-approve "${VAR_FILE_ARGS[@]}" || \
        die "DESTROY FAILED TWICE — '${TF_ENV}' may still be running and billing. Re-run the destroy."
    fi
    ;;
  output)   terraform output -no-color ;;
  # The outputs as JSON on stdout and nothing else there, for a script
  # (run-suite.sh) to read.
  output-json) terraform output -json ;;
  suite)
    [ "${TF_STACK}" = "environment" ] || die "the suite runs against an environment."
    export STS_SUITE_REPORT_DIR="${STS_SUITE_REPORT_DIR:-/workspace/report}"
    cd /workspace
    exec deploy/aws/run-suite-in-aws.sh "${TF_ENV}"
    ;;
  *) die "unknown TF_ACTION='${TF_ACTION}' (init | validate | plan | apply | destroy | output | output-json | suite | ecr-password)." ;;
esac

say "${TF_ACTION} complete."
