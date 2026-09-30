#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
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
#   TF_STACK     environment | global | foundation | spiffe-realm
#                | suite-callbacks                               (environment)
#   TF_ENV       the environment's name, 2-12 [a-z0-9]           (dev)
#   TF_CELL      a MULTI-CELL environment's cell, e.g. `cac1`: one cell's
#                environment, spiffe-realm or suite-callbacks stack. Unset
#                for an `environment` apply/destroy/plan/output, which then
#                does every cell and the global stack IN ORDER (below)
#   TF_CONVERT   1: a multi-cell environment's CONVERSION from a single-region
#                one — envs/<env>.conversion.tfvars.json laid over the cells
#                file, a restored cell's database converted before its nodes
#                start (#98, `convert_cell` below)
#   TF_CONVERT_TIMEOUT  seconds to wait for a conversion task       (7200)
#   TF_REALM     spiffe-realm only: the realm id, or `default`
#   TF_ACTION    init | validate | plan | apply | destroy | output
#                | output-json | ecr-password                                  (plan)
#   AWS_REGION   the HOME region: the state bucket, the image repository
#                images are pushed to, and every AWS CLI call made here. A
#                cell's region comes from its cells file, never from this
#                                                                (us-west-2)
#
# A MULTI-CELL ENVIRONMENT (issue #98, 2026-09-28) is one with
# `environment/envs/<env>.cells.tfvars.json`: its cells, their regions and
# which one holds the global database's writer. Each cell is the
# `environment` stack with TF_CELL (state `environment/<env>/<cell>.tfstate`),
# and the environment has one `global` stack besides
# (`environment/<env>/global.tfstate`). Without that file an environment is
# single-cell and everything below behaves as it always did.
#
#   TF_VAR_image_tag      the service image tag (the commit), for plan/apply
#   TF_VAR_allowed_cidrs  JSON list, e.g. ["203.0.113.4/32"], for plan/apply
#   TF_VAR_workload_port, TF_VAR_server_port   spiffe-realm plan/apply: the
#                         realm's two SPIFFE ports (deploy/aws/CLAUDE.md)
#   TF_VAR_image_tag      suite-callbacks plan/apply: the run's image tag
#                         (run-suite.sh pushes runner-<tag> and pep-<tag>)
#
# THE ACTION THE PARENT DOES NOT HAVE (there were two until 2026-09-21: `suite`
# ran deploy/aws/run-suite-in-aws.sh, the in-VPC runner, which was removed that
# day — the suite runs from deploy/aws/run-suite.sh, through ./run-tests.sh's
# AWS targets):
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

say() { echo "==> [${TF_STACK}${TF_STACK:+/}${TF_ENV}${TF_CELL:+/${TF_CELL}}] $*" >&2; }
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

# --- A multi-cell environment's cells -----------------------------------------
# The cells file, when there is one, is the whole description of the
# environment's cells (deploy/aws/CLAUDE.md, *Cells*). jq reads it here — the
# reason it is JSON and not HCL — and Terraform reads the same file as a
# variable file, so the two cannot disagree.
CELLS_FILE="/workspace/deploy/aws/environment/envs/${TF_ENV}.cells.tfvars.json"
MULTI_CELL=""
if [ -f "${CELLS_FILE}" ];
then
  MULTI_CELL=1
  jq -e '.cells | type == "object"' "${CELLS_FILE}" >/dev/null || \
    die "${CELLS_FILE} has no \`cells\` object."
  PRIMARY_CELL="$(jq -r '.primary_cell' "${CELLS_FILE}")"
  # The primary cell FIRST, then the others in the file's order: its nodes
  # apply the global schema, so every other cell's nodes start against one.
  mapfile -t CELLS < <(jq -r --arg p "${PRIMARY_CELL}" \
    '[$p] + ([.cells | keys_unsorted[]] - [$p]) | .[]' "${CELLS_FILE}")
  if [ -n "${TF_CELL:-}" ];
  then
    CELL_REGION="$(jq -r --arg c "${TF_CELL}" '.cells[$c].region // empty' "${CELLS_FILE}")"
    [ -n "${CELL_REGION}" ] || die "TF_CELL='${TF_CELL}' is not a cell of ${TF_ENV} (${CELLS[*]})."
  fi
elif [ -n "${TF_CELL:-}" ];
then
  die "TF_CELL='${TF_CELL}' was given, but ${TF_ENV} is single-cell (no envs/${TF_ENV}.cells.tfvars.json)."
fi

# --- A conversion from a single-region environment (#98, 2026-09-28) --------
# TF_CONVERT=1 lays `envs/<env>.conversion.tfvars.json` OVER the cells file:
# its `cells.<id>.db_snapshot_identifier` are merged into the cells (jq's
# deep merge, restricted to that one field, so it can add a snapshot to a
# cell and never a cell or anything else), and its `carryover_secret` is
# given to the global stack. The cells file stays the environment's
# description, so a fresh apply of the same environment by anybody else —
# without TF_CONVERT — builds empty databases and generates its secrets, and
# never depends on a snapshot or a carry-over secret that may since have been
# deleted (deploy/aws/CLAUDE.md, *Converting a single-region environment into
# cells*). The file's other fields (`source_environment`, `source_snapshots`)
# are the runbook's, deploy/aws/convert-to-cells.sh, and reach no Terraform.
CONVERSION_FILE="/workspace/deploy/aws/environment/envs/${TF_ENV}.conversion.tfvars.json"
if [ -n "${TF_CONVERT:-}" ] && [ "${TF_CONVERT}" != "0" ];
then
  [ -n "${MULTI_CELL}" ] || \
    die "TF_CONVERT is for a multi-cell environment; ${TF_ENV} has no envs/${TF_ENV}.cells.tfvars.json."
  [ -f "${CONVERSION_FILE}" ] || \
    die "TF_CONVERT is set, but there is no envs/${TF_ENV}.conversion.tfvars.json to convert with."
  unknown="$(jq -r --slurpfile c "${CELLS_FILE}" \
    '[(.cells // {}) | keys[] | select(. as $k | $c[0].cells | has($k) | not)] | join(" ")' \
    "${CONVERSION_FILE}")"
  [ -z "${unknown}" ] || \
    die "envs/${TF_ENV}.conversion.tfvars.json names cells that are not in the cells file: ${unknown}."
  MERGED_CELLS_FILE="$(mktemp /tmp/cells.XXXXXX.tfvars.json)"
  jq -s '.[0] * { cells: ((.[1].cells // {}) | map_values({ db_snapshot_identifier })) }' \
    "${CELLS_FILE}" "${CONVERSION_FILE}" > "${MERGED_CELLS_FILE}"
  CELLS_FILE="${MERGED_CELLS_FILE}"
  CARRYOVER_SECRET="$(jq -r '.carryover_secret // empty' "${CONVERSION_FILE}")"
  if [ "${TF_STACK}" = "global" ] && [ -n "${CARRYOVER_SECRET}" ];
  then
    export TF_VAR_carryover_secret="${CARRYOVER_SECRET}"
  fi
fi

# A cell's snapshot, from the (possibly merged) cells file; empty for a cell
# made empty.
cell_snapshot() {
  [ -n "${MULTI_CELL}" ] || return 0
  jq -r --arg c "$1" '.cells[$c].db_snapshot_identifier // empty' "${CELLS_FILE}"
}

# --- The stack and its state ------------------------------------------------
bucket="mock-sts-terraform-state-${account}"
case "${TF_STACK}" in
  environment)
    TF_DIR=/workspace/deploy/aws/environment
    STATE_KEY="environment/${TF_ENV}.tfstate"
    export TF_VAR_environment="${TF_ENV}"
    if [ -n "${MULTI_CELL}" ] && [ -n "${TF_CELL:-}" ];
    then
      # ONE CELL: its own state, beside the environment's other cells and
      # its global stack, and the phase entrypoint's own orchestration chose
      # (full unless told otherwise — see `orchestrate_cells` below).
      STATE_KEY="environment/${TF_ENV}/${TF_CELL}.tfstate"
      export TF_VAR_cell="${TF_CELL}" TF_VAR_cell_phase="${TF_CELL_PHASE:-full}"
      # A RESTORED CELL'S ONE HELD APPLY (environment/conversion.tf): `full`
      # with no node running, before its conversion. Set by
      # `orchestrate_cells` only.
      if [ -n "${TF_CELL_HOLD:-}" ];
      then
        export TF_VAR_cell_hold_nodes=true
      fi
    fi
    ;;
  global)
    # THE GLOBAL TIER OF A MULTI-CELL ENVIRONMENT (#98): the global database,
    # the global secrets, the peering mesh. Only for an environment with cells.
    [ -n "${MULTI_CELL}" ] || \
      die "TF_STACK=global is for a multi-cell environment; ${TF_ENV} has no envs/${TF_ENV}.cells.tfvars.json."
    TF_DIR=/workspace/deploy/aws/global
    STATE_KEY="environment/${TF_ENV}/global.tfstate"
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
  *) die "unknown TF_STACK='${TF_STACK}' (environment | global | foundation | spiffe-realm | suite-callbacks)." ;;
esac

# A STACK BUILT ON ONE CELL (#98) is that cell's: its state is under the
# cell's own prefix, and it is applied in the cell's region.
if [ -n "${MULTI_CELL}" ];
then
  case "${TF_STACK}" in
    spiffe-realm|suite-callbacks)
      [ -n "${TF_CELL:-}" ] || \
        die "${TF_ENV} is multi-cell (${CELLS[*]}): TF_STACK=${TF_STACK} needs TF_CELL, the cell whose load balancer it is for."
      STATE_KEY="environment/${TF_ENV}/${TF_CELL}/${STATE_KEY#"environment/${TF_ENV}/"}"
      export TF_VAR_cell="${TF_CELL}" TF_VAR_aws_region="${CELL_REGION}"
      ;;
  esac
fi

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

# EVERY STACK BUILT ON TOP OF AN ENVIRONMENT COMES DOWN BEFORE IT
# (2026-09-21). `spiffe-realm/` puts two listeners, two target groups and
# FOUR SECURITY-GROUP RULES on the environment's own `nlb` and `nodes`
# groups, which it finds with `data` rather than owning; `suite-callbacks/`
# puts a subnet and a NAT gateway behind an address the load balancer
# admits. Terraform removes the rules ITS OWN state records — a rule another
# state owns is invisible to it, and keeps the group alive, so
# DeleteSecurityGroup answers DependencyViolation, the provider retries for
# fifteen minutes per group, and the destroy ends with both groups and the
# VPC still standing.
#
# **THAT IS WHAT HAPPENED TO `testidp` ON 2026-09-20**: the default realm's
# 8092/8181 rules outlived the environment they were attached to, the
# workflow spent 33 minutes failing twice over, and re-running it could not
# help — the second run had the same blind spot as the first. The two groups
# and the VPC were still there on 2026-09-21 and were removed by hand.
#
# The state keys ARE the enumeration, so nothing has to be told which realms
# an environment was given: one object per dependent stack, under a prefix
# the deployer role may already list (foundation/iam_deployer.tf,
# `TerraformStateList`). A dependent whose state is empty destroys nothing
# and costs one `init`, which is the right price for not having to know.
#
# Order matters in the other direction too: `spiffe-realm` reads the
# environment's remote state and looks its load balancer up by name, so it
# can only be destroyed WHILE the environment still exists. Here, not after.
#
# IN A MULTI-CELL ENVIRONMENT (#98) a dependent stack belongs to ONE cell and
# its state is under that cell's prefix, `environment/<env>/<cell>/`; the
# cells' own states and the global stack's sit one level up, beside those
# prefixes, and are not dependents — they are the orchestration's
# (`orchestrate_cells`, below).
destroy_dependent_stacks() {
  local prefix="${1:-environment/${TF_ENV}/}"
  local cell="${2:-}"
  local keys key realm
  # A failure to list is reported and not fatal: an environment with no
  # dependents must still come down when the listing is what broke.
  if ! keys="$(aws s3api list-objects-v2 --bucket "${bucket}" \
    --prefix "${prefix}" --query 'Contents[].Key' --output text 2>/dev/null)";
  then
    say "WARNING: could not list s3://${bucket}/${prefix} — if a stack built"
    say "         on this environment still holds security-group rules, the"
    say "         destroy below will fail with DependencyViolation."
    return 0
  fi
  [ "${keys}" = "None" ] && keys=""
  for key in ${keys}; do
    case "${key}" in
      "${prefix}spiffe-realm/"*.tfstate)
        realm="${key#"${prefix}"spiffe-realm/}"
        realm="${realm%.tfstate}"
        say "dependent stack first: spiffe-realm/${realm}"
        # The credentials of this process, already the deployer role: the
        # child's own assume step sees an assumed-role ARN, not a user's,
        # and leaves them alone. The forced-role variable is cleared so it
        # cannot try to chain a second assume from them.
        MOCK_STS_DEPLOYER_ROLE_ARN= TF_STACK=spiffe-realm TF_CELL="${cell}" \
          TF_REALM="${realm}" TF_ACTION=destroy "$0" || \
          die "the spiffe-realm stack for '${realm}' would not destroy, so '${TF_ENV}' was left alone. Fix that stack and run this again."
        ;;
      "${prefix}suite-callbacks.tfstate")
        say "dependent stack first: suite-callbacks"
        MOCK_STS_DEPLOYER_ROLE_ARN= TF_STACK=suite-callbacks TF_CELL="${cell}" \
          TF_ACTION=destroy "$0" || \
          die "the suite-callbacks stack would not destroy, so '${TF_ENV}' was left alone. Fix that stack and run this again."
        ;;
      "${prefix}"*/*|"${prefix}global.tfstate")
        # A multi-cell environment's cell prefixes, its cells' own states and
        # its global stack's (#98): not dependents of anything listed here,
        # and destroyed by the orchestration in its own order.
        ;;
      *)
        # A key under this environment's prefix that is not a stack this
        # script knows how to destroy. Said out loud rather than skipped
        # silently, because the next DependencyViolation will be its doing.
        say "NOTE: state key left alone (no stack here owns it): ${key}"
        ;;
    esac
  done
}

# ---------------------------------------------------------------------------
# A MULTI-CELL ENVIRONMENT, IN ORDER (#98, 2026-09-28). `environment` with no
# TF_CELL on an environment with cells runs this, which runs this same script
# once per step — each step an ordinary single-stack run with its own state,
# lock, retry and output — and stops at the first step that fails.
#
#   APPLY    1. every cell with NO STATE YET, primary first, phase `base`:
#               its VPC, load balancer, cell database, and the subnet group,
#               security group and namespace the global stack needs — with no
#               node running, since the global database does not exist yet
#            2. `global`: the global database's writer and replicas IN those
#               VPCs, the global secrets and their replicas, the peering mesh
#               and its routes, the inter-cell names shared between VPCs
#            3. every cell, primary first, phase `full`: the nodes, told where
#               the global tier is. The primary cell's nodes apply the global
#               schema; the others start after, against it.
#            A cell that already has state skips step 1: `base` scales its
#            nodes to zero, which on a running cell is an outage.
#
#   DESTROY  1. every cell's DEPENDENT stacks (spiffe-realm, suite-callbacks),
#               while the cells they sit on still exist — the lesson of
#               2026-09-20 (destroy_dependent_stacks)
#            2. `global`, while the cells it reads still exist: routes,
#               peerings, zone associations, the replicas and then the writer
#               (RDS will not delete a writer with replicas), the secrets and
#               their replicas. Everything it put INTO a cell's VPC goes here,
#               or that VPC would not delete
#            3. every cell, phase `base` — its destroy must not read a global
#               state that is gone.
#
#   PLAN     every cell, `full`, and `global` (a plan of a cell that has no
#            global stack yet fails reading its state, which is the order
#            above saying so)
#   OUTPUT   every cell's, then global's, each under a heading. `output-json`
#            is one document for a script, so it needs TF_CELL (run-suite.sh)
# ---------------------------------------------------------------------------
state_exists() {
  aws s3api head-object --bucket "${bucket}" --key "$1" >/dev/null 2>&1
}

# A step: this script again, in the background so that an interrupt reaches
# it (and through it terraform) the way `tf` relays one below. The role is
# already assumed; the forced-role variable is cleared so the child does not
# try to chain a second assume from it.
step() {
  env MOCK_STS_DEPLOYER_ROLE_ARN= "$@" "$0" &
  local pid=$! rc=0
  trap 'kill -INT "${pid}" 2>/dev/null || true' INT TERM
  while :; do
    wait "${pid}" && rc=0 || rc=$?
    kill -0 "${pid}" 2>/dev/null || break
  done
  trap - INT TERM
  return "${rc}"
}

# ---------------------------------------------------------------------------
# A CELL CONVERTED FROM A SINGLE-REGION ENVIRONMENT (#98, 2026-09-28;
# environment/conversion.tf, deploy/aws/CLAUDE.md *Converting a single-region
# environment into cells*). Within the apply above, for a cell whose database
# is restored from a snapshot:
#
#   base    as any new cell — and the restore happens here, because the cell
#           database is a `base` resource. The cell is marked PENDING first.
#   global  as always (with TF_CONVERT, the carry-over secret's values)
#   full    TWICE, with the conversion between:
#             1. `full` with TF_CELL_HOLD: task definitions, the global
#                tier's addresses, the conversion task definition — and
#                every node service at a desired count of 0;
#             2. the conversion task, once (`convert_cell`): the two schema
#                inits, then `node persistence/cell_convert.js`, in the
#                cell's cluster and network, waited for; a non-zero exit
#                STOPS THE APPLY with the cell's nodes still at 0, the
#                marker still pending, and the cells after it not applied;
#             3. the marker set DONE, and `full` as usual: the nodes start.
#
# THE MARKER is one object beside the cell's state,
# `environment/<env>/<cell>.conversion.json` — under the prefix the deployer
# already writes state under, outside the cell's own prefix (so
# destroy_dependent_stacks never mistakes it for a stack), and deleted with
# the cell. PENDING is what makes a re-apply safe after a failure: the held
# apply and the conversion run again (the tool is idempotent), and an apply
# without TF_CONVERT refuses rather than starting nodes on unconverted rows.
# DONE is what makes every later apply skip it, without re-reading the
# snapshot or running the tool for nothing. A snapshot named for a cell that
# already existed restored nothing — rds.tf ignores it — and is said so.
# ---------------------------------------------------------------------------
conversion_marker_key() {
  echo "environment/${TF_ENV}/$1.conversion.json"
}

# pending | done | (empty: never restored)
conversion_state() {
  local body
  body="$(mktemp)"
  if aws s3api get-object --bucket "${bucket}" \
    --key "$(conversion_marker_key "$1")" "${body}" >/dev/null 2>&1;
  then
    jq -r '.state // empty' "${body}" 2>/dev/null || true
  fi
  rm -f "${body}"
}

write_conversion_marker() {
  local body
  body="$(mktemp)"
  jq -n --arg state "$2" --arg snapshot "$(cell_snapshot "$1")" \
    --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{ state: $state, snapshot: $snapshot, at: $at }' > "${body}"
  aws s3api put-object --bucket "${bucket}" --key "$(conversion_marker_key "$1")" \
    --body "${body}" --content-type application/json >/dev/null || \
    die "could not write s3://${bucket}/$(conversion_marker_key "$1") (${2}); nothing after it was applied."
  rm -f "${body}"
  say "cell $1: conversion ${2}"
}

# The conversion task, once, and waited for. The cell's own outputs say what
# to run and where (environment/outputs.tf). A conversion task ALREADY
# RUNNING in the cell's cluster — an earlier apply interrupted while it
# waited — is waited for instead of a second one started beside it.
convert_cell() {
  local c="$1" out region cluster td network task status rc reason
  local deadline=$(( $(date +%s) + ${TF_CONVERT_TIMEOUT:-7200} ))
  out="$(step TF_STACK=environment TF_CELL="${c}" TF_ACTION=output-json)" || \
    die "cell ${c}: could not read its outputs to run the conversion; its nodes stay at 0."
  region="$(jq -r '.aws_region.value' <<<"${out}")"
  cluster="$(jq -r '.ecs_cluster.value' <<<"${out}")"
  td="$(jq -r '.conversion_task_definition.value // empty' <<<"${out}")"
  [ -n "${td}" ] || \
    die "cell ${c}: no conversion task definition in its outputs (was TF_CONVERT=1 given?); its nodes stay at 0."
  network="$(jq -c '.conversion_network.value | { awsvpcConfiguration: {
      subnets: .subnets, securityGroups: .security_groups,
      assignPublicIp: .assign_public_ip } }' <<<"${out}")"

  task="$(aws ecs list-tasks --region "${region}" --cluster "${cluster}" \
    --started-by mock-sts-cell-convert --desired-status RUNNING \
    --query 'taskArns[0]' --output text 2>/dev/null || true)"
  if [ -n "${task}" ] && [ "${task}" != "None" ];
  then
    say "cell ${c}: a conversion task is already running (${task}); waiting for it"
  else
    say "cell ${c}: running the conversion (${td##*/})"
    task="$(aws ecs run-task --region "${region}" --cluster "${cluster}" \
      --task-definition "${td}" --launch-type FARGATE --count 1 \
      --started-by mock-sts-cell-convert \
      --network-configuration "${network}" \
      --query 'tasks[0].taskArn' --output text)" || \
      die "cell ${c}: the conversion task could not be started; its nodes stay at 0."
    { [ -n "${task}" ] && [ "${task}" != "None" ]; } || \
      die "cell ${c}: ECS started no conversion task (see RunTask's failures); its nodes stay at 0."
  fi

  while :; do
    status="$(aws ecs describe-tasks --region "${region}" --cluster "${cluster}" \
      --tasks "${task}" --query 'tasks[0].lastStatus' --output text 2>/dev/null || echo UNKNOWN)"
    [ "${status}" = "STOPPED" ] && break
    if [ "$(date +%s)" -ge "${deadline}" ];
    then
      die "cell ${c}: the conversion task ${task} has not finished in ${TF_CONVERT_TIMEOUT:-7200} s and is STILL RUNNING. Its nodes stay at 0 and the cell is still pending: wait for it (the next apply waits for a running one rather than starting another), or raise TF_CONVERT_TIMEOUT."
    fi
    sleep 15
  done

  rc="$(aws ecs describe-tasks --region "${region}" --cluster "${cluster}" \
    --tasks "${task}" \
    --query "tasks[0].containers[?name=='cell-convert'].exitCode | [0]" --output text)"
  if [ "${rc}" != "0" ];
  then
    reason="$(aws ecs describe-tasks --region "${region}" --cluster "${cluster}" \
      --tasks "${task}" --output json \
      | jq -r '.tasks[0] | "stopped: \(.stoppedReason // "?"); " +
          ([.containers[] | "\(.name) exit \(.exitCode // "none")\(if .reason then " (" + .reason + ")" else "" end)"] | join(", "))')"
    die "cell ${c}: THE CONVERSION FAILED (${reason}). The tool leaves its sources in place; the cell's nodes stay at 0 and it is still pending. Its log: group /mock-sts/containers in ${region}, streams ${TF_ENV}-${c}-convert/*/${task##*/}. Fix the cause and apply again with TF_CONVERT=1."
  fi
  say "cell ${c}: converted (${task##*/})"
}

orchestrate_cells() {
  local c
  say "multi-cell environment: cells ${CELLS[*]} (primary ${PRIMARY_CELL})"
  case "${TF_ACTION}" in
    apply)
      for c in "${CELLS[@]}"; do
        if state_exists "environment/${TF_ENV}/${c}.tfstate";
        then
          say "cell ${c}: has state, so no base phase"
        else
          # A RESTORED CELL IS MARKED PENDING BEFORE ITS DATABASE EXISTS, so
          # that no later apply can start its nodes on the restored rows
          # before the conversion has run, however this one ends.
          if [ -n "$(cell_snapshot "${c}")" ];
          then
            write_conversion_marker "${c}" pending
          fi
          say "cell ${c}: base phase (no nodes yet)"
          step TF_STACK=environment TF_CELL="${c}" TF_CELL_PHASE=base TF_ACTION=apply || \
            die "cell ${c} did not apply its base phase; nothing after it was applied."
        fi
      done
      say "global"
      step TF_STACK=global TF_ACTION=apply || \
        die "the global stack did not apply; no cell's nodes were started or changed."
      for c in "${CELLS[@]}"; do
        case "$(conversion_state "${c}")" in
          pending)
            [ -n "$(cell_snapshot "${c}")" ] || \
              die "cell ${c}'s database was restored from a snapshot and has NOT been converted yet (s3://${bucket}/$(conversion_marker_key "${c}") says pending), and this apply has no conversion to run: re-run it with TF_CONVERT=1. Its nodes were not started."
            say "cell ${c}: full, nodes HELD at 0 until its conversion has run"
            step TF_STACK=environment TF_CELL="${c}" TF_CELL_PHASE=full TF_CELL_HOLD=1 TF_ACTION=apply || \
              die "cell ${c} did not apply its held phase; its conversion did not run and the cells after it (in: ${CELLS[*]}) were not applied."
            convert_cell "${c}"
            write_conversion_marker "${c}" "done"
            ;;
          "done")
            say "cell ${c}: converted already (s3://${bucket}/$(conversion_marker_key "${c}")); not converting again"
            ;;
          *)
            if [ -n "$(cell_snapshot "${c}")" ];
            then
              say "NOTE: cell ${c} names a snapshot, but it existed before this"
              say "      apply and was not restored from it, so there is nothing"
              say "      to convert. The snapshot is ignored (rds.tf,"
              say "      ignore_changes)."
            fi
            ;;
        esac
        say "cell ${c}: full"
        step TF_STACK=environment TF_CELL="${c}" TF_CELL_PHASE=full TF_ACTION=apply || \
          die "cell ${c} did not apply; the cells after it (in: ${CELLS[*]}) were not applied."
      done
      ;;
    destroy)
      for c in "${CELLS[@]}"; do
        say "cell ${c}: its dependent stacks first"
        destroy_dependent_stacks "environment/${TF_ENV}/${c}/" "${c}"
      done
      if state_exists "environment/${TF_ENV}/global.tfstate";
      then
        say "global"
        step TF_STACK=global TF_ACTION=destroy || \
          die "the global stack would not destroy, so no cell was touched. Fix it and run this again."
      fi
      for c in "${CELLS[@]}"; do
        say "cell ${c}"
        step TF_STACK=environment TF_CELL="${c}" TF_CELL_PHASE=base TF_ACTION=destroy || \
          die "cell ${c} would not destroy. Re-run the destroy; the ones before it are gone."
        # Its conversion marker goes with it: a cell made again under the
        # same name is a new database, restored or empty.
        aws s3api delete-object --bucket "${bucket}" \
          --key "$(conversion_marker_key "${c}")" >/dev/null 2>&1 || true
      done
      ;;
    plan|output)
      for c in "${CELLS[@]}"; do
        say "cell ${c}"
        echo "== cell ${c}"
        step TF_STACK=environment TF_CELL="${c}" TF_ACTION="${TF_ACTION}" || \
          die "cell ${c}: ${TF_ACTION} failed."
      done
      say "global"
      echo "== global"
      step TF_STACK=global TF_ACTION="${TF_ACTION}" || die "global: ${TF_ACTION} failed."
      ;;
    *)
      die "${TF_ENV} is multi-cell (${CELLS[*]}): TF_ACTION=${TF_ACTION} needs TF_CELL, or TF_STACK=global."
      ;;
  esac
  say "${TF_ACTION} of every cell and the global stack complete."
}

if [ -n "${MULTI_CELL}" ] && [ "${TF_STACK}" = "environment" ] && [ -z "${TF_CELL:-}" ];
then
  orchestrate_cells
  exit 0
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
# A cell and the global stack both read the environment's cells file (#98).
if [ -n "${MULTI_CELL}" ] && { [ "${TF_STACK}" = "global" ] || [ "${TF_STACK}" = "environment" ]; };
then
  say "cells: envs/${TF_ENV}.cells.tfvars.json"
  VAR_FILE_ARGS+=(-var-file="${CELLS_FILE}")
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
  # -reconfigure: a multi-cell apply runs every cell's step in ONE container,
  # over one .terraform directory, and each step names its own state key —
  # without it the second cell's init stopped at "Backend configuration
  # changed" (testidpna, 2026-09-30). The state is always in S3, so there is
  # nothing to migrate; the key is simply the one this step is for.
  terraform init -input=false -no-color -reconfigure \
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
    if [ "${TF_STACK}" = "environment" ];
    then
      if [ -n "${MULTI_CELL}" ];
      then
        destroy_dependent_stacks "environment/${TF_ENV}/${TF_CELL}/" "${TF_CELL}"
      else
        destroy_dependent_stacks
      fi
    fi
    # A destroy that fails half way leaves resources running and billing; the
    # usual cause is an ENI a stopped task has not released yet. Once more,
    # after a minute, before giving up.
    if ! tf destroy -input=false -no-color -auto-approve "${VAR_FILE_ARGS[@]}";
    then
      say "destroy failed; retrying once in 60 seconds"
      sleep 60
      tf destroy -input=false -no-color -auto-approve "${VAR_FILE_ARGS[@]}" || \
        die "DESTROY FAILED TWICE — '${TF_ENV}' may still be running and billing. Re-run the destroy. A DependencyViolation on a security group means something OUTSIDE this state holds a rule on it; find what put it there, destroy that, and run this again."
    fi
    ;;
  # ADOPT A RESOURCE THAT EXISTS AND THE STATE DOES NOT RECORD (2026-09-19):
  # an apply interrupted after AWS created something (an RDS instance takes
  # minutes, and an expired session is enough) leaves it running and billing
  # while the next apply fails with "already exists". Importing it is the
  # non-destructive repair. TF_IMPORT_ADDRESS is the resource address,
  # TF_IMPORT_ID the provider's identifier (an RDS instance's is its name).
  #   TF_IMPORT_ADDRESS=aws_db_instance.primary \
  #   TF_IMPORT_ID=mock-sts-testidp-primary IMAGE_TAG=<tag> \
  #   deploy/aws/terraform-local.sh testidp import
  import)
    [ -n "${TF_IMPORT_ADDRESS:-}" ] && [ -n "${TF_IMPORT_ID:-}" ] || \
      die "import needs TF_IMPORT_ADDRESS and TF_IMPORT_ID."
    tf import -input=false -no-color "${VAR_FILE_ARGS[@]}" \
      "${TF_IMPORT_ADDRESS}" "${TF_IMPORT_ID}"
    ;;
  output)   terraform output -no-color ;;
  # The outputs as JSON on stdout and nothing else there, for a script
  # (run-suite.sh) to read.
  output-json) terraform output -json ;;
  *) die "unknown TF_ACTION='${TF_ACTION}' (init | validate | plan | apply | destroy | import | output | output-json | ecr-password). The `suite` action was removed on 2026-09-21: run ./run-tests.sh --target=aws:<env>." ;;
esac

say "${TF_ACTION} complete."
