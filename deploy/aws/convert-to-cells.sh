#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# File: deploy/aws/convert-to-cells.sh
#
# ---------------------------------------------------------------------------
# CONVERT A SINGLE-REGION ENVIRONMENT INTO A CELL OF A MULTI-CELL ONE, WITHOUT
# LOSING ITS DATABASE (#98, 2026-09-28) — the runbook, for `testidp` becoming
# cell `usw2` of `testidpna`.
#
# Usage:
#   deploy/aws/convert-to-cells.sh <from-env> <to-env>                  # check
#   deploy/aws/convert-to-cells.sh <from-env> <to-env> --carry-secrets  # step
#   deploy/aws/convert-to-cells.sh <from-env> <to-env> --copy-snapshot  # step
#
# BY DEFAULT IT ONLY LOOKS AND PRINTS: every call it makes is a Describe, a
# Get of a key's metadata or a HeadObject — never a secret's VALUE, never a
# write — and it ends with the whole sequence, in order, and what is still
# missing from it. Each flag is ONE mutating step, and each refuses to redo
# what is already done:
#
#   --carry-secrets  reads the four values the restored database depends on
#                    from `mock-sts/<from-env>/…` and writes them, as one JSON
#                    secret under the project key, to the carry-over secret
#                    the conversion file names (`mock-sts/carryover/<from>`).
#                    A value is never printed, never on a command line, and
#                    only ever in a file of this process's own (umask 077,
#                    removed on exit). Which four, and why each: global/
#                    secrets.tf, *A converted environment's secrets*.
#   --copy-snapshot  copies each source snapshot the conversion file names to
#                    the name its cell restores from, RE-ENCRYPTED under the
#                    cell's own key, and waits until it is available. A
#                    restore keeps the snapshot's key (RDS's
#                    RestoreDBInstanceFromDBSnapshot has no key parameter), so
#                    a snapshot under the project key would restore under the
#                    project key — environment/conversion.tf.
#
# **IT NEVER APPLIES OR DESTROYS ANYTHING.** Those are `terraform-local.sh`'s,
# and it prints them for the operator, with what each costs: the old
# environment's destroy deletes its database with NO final snapshot
# (`skip_final_snapshot`) and its secrets with NO recovery window, so the
# snapshot copy and the carry-over secret must exist BEFORE it, which is what
# the checks are for; and the service is down from that destroy until the new
# environment's converted cell is serving.
#
# WHAT IT READS: the two files beside each other in environment/envs/ —
# `<to-env>.cells.tfvars.json` (the cells, their regions, the primary) and
# `<to-env>.conversion.tfvars.json` (`source_environment`, which must be
# <from-env>; `source_snapshots.<cell>`, what to copy; `cells.<cell>.
# db_snapshot_identifier`, the copy the cell restores from; and
# `carryover_secret`). The same file entrypoint.sh lays over the cells file
# when TF_CONVERT=1.
#
# CREDENTIALS: whatever the AWS CLI on this host resolves — the deployer role
# (foundation/iam_deployer.tf: RdsRestoreAndCopyProjectSnapshots, the project
# secrets and keys) or an administrator. AWS_REGION is the HOME region, where
# the old environment, its secrets and the carry-over secret are (us-west-2).
# ---------------------------------------------------------------------------
set -euo pipefail

NAME="${MOCK_STS_NAME:-mock-sts}"
HOME_REGION="${AWS_REGION:-us-west-2}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENVS="${REPO_ROOT}/deploy/aws/environment/envs"

say() { echo "==> $*" >&2; }
die() { echo "ERROR: $*" >&2; exit 1; }
usage() {
  sed -n '/^# Usage:/,/^#$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
  exit 2
}

[ "$#" -ge 2 ] || usage
FROM="$1"
TO="$2"
shift 2
ACTION=check
for arg in "$@"; do
  case "${arg}" in
    --carry-secrets|--copy-snapshot)
      [ "${ACTION}" = "check" ] || \
        die "one step at a time: --carry-secrets and --copy-snapshot are separate runs."
      ACTION="${arg#--}"
      ;;
    -h|--help) usage ;;
    *) die "unknown argument '${arg}'." ;;
  esac
done
for e in "${FROM}" "${TO}"; do
  [[ "${e}" =~ ^[a-z][a-z0-9]{1,11}$ ]] || \
    die "'${e}' is not an environment name (2-12 lower-case letters and digits)."
done
command -v aws >/dev/null 2>&1 || die "the AWS CLI is required."
command -v jq >/dev/null 2>&1 || die "jq is required."

CELLS_FILE="${ENVS}/${TO}.cells.tfvars.json"
CONV_FILE="${ENVS}/${TO}.conversion.tfvars.json"
[ -f "${CELLS_FILE}" ] || \
  die "${TO} is not a multi-cell environment: no ${CELLS_FILE#"${REPO_ROOT}/"}."
[ -f "${CONV_FILE}" ] || \
  die "no ${CONV_FILE#"${REPO_ROOT}/"}: write it first (deploy/aws/CLAUDE.md, *Converting a single-region environment into cells*)."
[ "$(jq -r '.source_environment // empty' "${CONV_FILE}")" = "${FROM}" ] || \
  die "${CONV_FILE#"${REPO_ROOT}/"} converts '$(jq -r '.source_environment // "?"' "${CONV_FILE}")', not '${FROM}'."
[ ! -f "${ENVS}/${FROM}.cells.tfvars.json" ] || \
  die "${FROM} is itself multi-cell; this converts a single-region environment."

CARRYOVER="$(jq -r '.carryover_secret // empty' "${CONV_FILE}")"
mapfile -t CONV_CELLS < <(jq -r '(.cells // {}) | keys[]' "${CONV_FILE}")
for c in "${CONV_CELLS[@]}"; do
  jq -e --arg c "${c}" '.cells | has($c)' "${CELLS_FILE}" >/dev/null || \
    die "the conversion file names cell '${c}', which ${TO} does not have."
done

ACCOUNT="$(aws sts get-caller-identity --query Account --output text)" || \
  die "no AWS credentials (sign in, or export the deployer user's key)."

WORK="$(umask 077 && mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

MISSING=0
ok()   { printf '   ok       %s\n' "$*"; }
todo() { printf '   MISSING  %s\n' "$*"; MISSING=$((MISSING + 1)); }
note() { printf '   note     %s\n' "$*"; }

# The new environment's db_allocated_storage: its envs/<env>.tfvars, or the
# variable's default. A restore may not be smaller than the snapshot.
to_allocated_storage() {
  local v
  v="$(sed -n 's/^db_allocated_storage *= *\([0-9][0-9]*\).*/\1/p' \
    "${ENVS}/${TO}.tfvars" 2>/dev/null | head -1)"
  echo "${v:-20}"
}

cell_region() { jq -r --arg c "$1" '.cells[$c].region' "${CELLS_FILE}"; }
target_of()   { jq -r --arg c "$1" '.cells[$c].db_snapshot_identifier // empty' "${CONV_FILE}"; }
source_of()   { jq -r --arg c "$1" '.source_snapshots[$c] // empty' "${CONV_FILE}"; }

# A snapshot's description as JSON, or nothing when there is none.
describe_snapshot() {
  aws rds describe-db-snapshots --region "$1" --db-snapshot-identifier "$2" \
    --query 'DBSnapshots[0]' --output json 2>/dev/null || true
}

cell_key_arn() {
  aws kms describe-key --region "$1" --key-id "alias/${NAME}-cell-$2" \
    --query KeyMetadata.Arn --output text 2>/dev/null || true
}

secret_exists() {
  aws secretsmanager describe-secret --region "${HOME_REGION}" \
    --secret-id "$1" >/dev/null 2>&1
}

# The values the carry-over holds, and whether each is required: the KEK and
# the management client's secret always; the other two are product mode's,
# and a development environment has neither (global/secrets.tf).
CARRIED=(kek:required admin-api-client-secret:required
         bootstrap-admin-password:product krb5-service-password:product)

# ---------------------------------------------------------------------------
# --carry-secrets
# ---------------------------------------------------------------------------
carry_secrets() {
  local entry key need args=()
  [ -n "${CARRYOVER}" ] || die "the conversion file names no carryover_secret."
  if secret_exists "${CARRYOVER}";
  then
    die "${CARRYOVER} exists already and is not overwritten. If it is stale, delete it (aws secretsmanager delete-secret --force-delete-without-recovery --secret-id ${CARRYOVER}) and run this again — while mock-sts/${FROM}/kek still exists."
  fi
  for entry in "${CARRIED[@]}"; do
    key="${entry%%:*}"
    need="${entry#*:}"
    if aws secretsmanager get-secret-value --region "${HOME_REGION}" \
      --secret-id "${NAME}/${FROM}/${key}" --query SecretString --output text \
      > "${WORK}/${key}" 2>/dev/null;
    then
      # The CLI's text output ends the value with a newline it did not have.
      printf '%s' "$(cat "${WORK}/${key}")" > "${WORK}/${key}"
      args+=(--rawfile "${key}" "${WORK}/${key}")
      say "read ${NAME}/${FROM}/${key}"
    elif [ "${need}" = "required" ];
    then
      die "could not read ${NAME}/${FROM}/${key}; without it the restored database is unusable, so nothing was written."
    else
      say "no ${NAME}/${FROM}/${key} (a development environment has none); left out"
    fi
  done
  jq -n "${args[@]}" '$ARGS.named' > "${WORK}/carryover.json"
  aws secretsmanager create-secret --region "${HOME_REGION}" \
    --name "${CARRYOVER}" --kms-key-id "alias/${NAME}" \
    --description "mock-sts: ${FROM}'s secrets, carried into ${TO} (#98 conversion)" \
    --tags Key=Project,Value=STS Key=Environment,Value="${TO}" \
    --secret-string "file://${WORK}/carryover.json" >/dev/null || \
    die "could not create ${CARRYOVER}."
  say "wrote ${CARRYOVER} ($(jq -r 'keys | join(", ")' "${WORK}/carryover.json"); values not shown)"
}

# ---------------------------------------------------------------------------
# --copy-snapshot
# ---------------------------------------------------------------------------
copy_snapshots() {
  local c region src target key src_region src_id
  src_region="${HOME_REGION}"
  for c in "${CONV_CELLS[@]}"; do
    region="$(cell_region "${c}")"
    src="$(source_of "${c}")"
    target="$(target_of "${c}")"
    [ -n "${src}" ] && [ -n "${target}" ] || \
      die "cell ${c}: the conversion file needs both source_snapshots.${c} and cells.${c}.db_snapshot_identifier."
    if [ -n "$(describe_snapshot "${region}" "${target}")" ];
    then
      say "cell ${c}: ${target} exists already in ${region}; not copied again"
      continue
    fi
    key="$(cell_key_arn "${region}" "${c}")"
    [ -n "${key}" ] && [ "${key}" != "None" ] || \
      die "cell ${c}: no key alias/${NAME}-cell-${c} in ${region}; foundation/ must be re-applied with ${region} in permitted_regions first."
    # The same region takes the source's name; another region its ARN, and
    # the CLI signs the source region's half of the call itself.
    src_id="${src}"
    local cross=()
    if [ "${region}" != "${src_region}" ];
    then
      src_id="arn:aws:rds:${src_region}:${ACCOUNT}:snapshot:${src}"
      cross=(--source-region "${src_region}")
    fi
    say "cell ${c}: copying ${src} to ${target} in ${region}, under ${key}"
    aws rds copy-db-snapshot --region "${region}" "${cross[@]}" \
      --source-db-snapshot-identifier "${src_id}" \
      --target-db-snapshot-identifier "${target}" \
      --kms-key-id "${key}" --copy-tags >/dev/null || \
      die "cell ${c}: the copy was refused."
    say "cell ${c}: waiting for ${target} to be available (minutes, by size)"
    aws rds wait db-snapshot-available --region "${region}" \
      --db-snapshot-identifier "${target}" || \
      die "cell ${c}: ${target} did not become available in the waiter's time; run this again to check it (it will not copy twice)."
    say "cell ${c}: ${target} available"
  done
}

# ---------------------------------------------------------------------------
# The checks, and the sequence (the default)
# ---------------------------------------------------------------------------
check() {
  local c region src target sj tj key tkey entry key_name need from_primary
  local src_version src_storage src_time
  echo "Converting ${FROM} (single-region, ${HOME_REGION}) into ${TO}'s cells, account ${ACCOUNT}."
  echo "Read only: nothing below was changed."
  echo
  echo "1. The snapshots each converted cell restores from"
  for c in "${CONV_CELLS[@]}"; do
    region="$(cell_region "${c}")"
    src="$(source_of "${c}")"
    target="$(target_of "${c}")"
    echo " cell ${c} (${region})"
    key="$(cell_key_arn "${region}" "${c}")"
    if [ -z "${key}" ] || [ "${key}" = "None" ];
    then
      todo "the cell key alias/${NAME}-cell-${c} in ${region} (foundation/ re-applied with ${region} permitted)"
    else
      ok "cell key alias/${NAME}-cell-${c}: ${key}"
    fi
    sj="$(describe_snapshot "${HOME_REGION}" "${src}")"
    if [ -z "${src}" ] || [ -z "${sj}" ] || [ "${sj}" = "null" ];
    then
      todo "source snapshot '${src:-<source_snapshots.${c} unset>}' in ${HOME_REGION}"
    else
      src_version="$(jq -r .EngineVersion <<<"${sj}")"
      src_storage="$(jq -r .AllocatedStorage <<<"${sj}")"
      src_time="$(jq -r .SnapshotCreateTime <<<"${sj}")"
      if [ "$(jq -r .Status <<<"${sj}")" = "available" ];
      then
        ok "source ${src}: available, taken ${src_time}, PostgreSQL ${src_version}, ${src_storage} GiB, encrypted $(jq -r .Encrypted <<<"${sj}") under $(jq -r .KmsKeyId <<<"${sj}")"
      else
        todo "source ${src} is $(jq -r .Status <<<"${sj}"), not available"
      fi
      if [ "$(jq -r .KmsKeyId <<<"${sj}")" = "${key}" ];
      then
        note "the source is already under the cell key; no copy is needed, and the conversion file could name it directly"
      fi
      [[ "${src_version}" == 18.* ]] || \
        todo "the source is PostgreSQL ${src_version}; the cell's parameter group is postgres18"
      [ "${src_storage}" -le "$(to_allocated_storage)" ] || \
        todo "the source has ${src_storage} GiB; set db_allocated_storage in envs/${TO}.tfvars at least that high"
      note "anything ${FROM} wrote after ${src_time} is NOT in it (step 0 below)"
    fi
    tj="$(describe_snapshot "${region}" "${target}")"
    if [ -z "${target}" ];
    then
      todo "cells.${c}.db_snapshot_identifier in the conversion file"
    elif [ -z "${tj}" ] || [ "${tj}" = "null" ];
    then
      todo "the copy ${target} in ${region} under the cell key (--copy-snapshot)"
    else
      tkey="$(jq -r .KmsKeyId <<<"${tj}")"
      if [ "$(jq -r .Status <<<"${tj}")" != "available" ];
      then
        todo "the copy ${target} is $(jq -r .Status <<<"${tj}") ($(jq -r .PercentProgress <<<"${tj}")%)"
      elif [ -n "${key}" ] && [ "${tkey}" != "${key}" ];
      then
        todo "the copy ${target} is under ${tkey}, NOT the cell key: it would restore under the wrong key. Delete it and --copy-snapshot again"
      else
        ok "copy ${target}: available in ${region}, under the cell key"
      fi
    fi
  done
  echo
  echo "2. The secrets the restored database was written under"
  if [ -z "${CARRYOVER}" ];
  then
    todo "carryover_secret in the conversion file"
  elif secret_exists "${CARRYOVER}";
  then
    ok "carry-over ${CARRYOVER} exists (its values are not read by this check)"
  else
    todo "carry-over ${CARRYOVER} (--carry-secrets, BEFORE ${FROM} is destroyed)"
  fi
  for entry in "${CARRIED[@]}"; do
    key_name="${entry%%:*}"
    need="${entry#*:}"
    if secret_exists "${NAME}/${FROM}/${key_name}";
    then
      ok "source ${NAME}/${FROM}/${key_name} exists"
    elif [ "${need}" = "required" ];
    then
      if secret_exists "${CARRYOVER}";
      then
        note "source ${NAME}/${FROM}/${key_name} is gone; the carry-over is the only copy"
      else
        todo "source ${NAME}/${FROM}/${key_name} — GONE, and not carried: the database cannot be converted"
      fi
    else
      note "source ${NAME}/${FROM}/${key_name} absent (only a product environment has it)"
    fi
  done
  echo
  echo "3. The two environments"
  from_primary="$(aws rds describe-db-instances --region "${HOME_REGION}" \
    --db-instance-identifier "${NAME}-${FROM}-primary" \
    --query 'DBInstances[0].DBInstanceStatus' --output text 2>/dev/null || true)"
  if [ -n "${from_primary}" ] && [ "${from_primary}" != "None" ];
  then
    note "${FROM} is running (${NAME}-${FROM}-primary: ${from_primary}); it must be destroyed before ${TO} is applied — both answer the same public name"
  else
    note "${FROM}'s database is gone; ${FROM} has been destroyed"
  fi
  if aws s3api list-objects-v2 --bucket "${NAME}-terraform-state-${ACCOUNT}" \
    --prefix "environment/${TO}/" --query 'Contents[].Key' --output text 2>/dev/null \
    | grep -q '\.tfstate';
  then
    note "${TO} has state already: a cell that exists is NOT restored (rds.tf ignores the snapshot); convert only into an environment that does not exist yet"
  else
    ok "${TO} does not exist yet"
  fi
  echo
  sequence
  echo
  if [ "${MISSING}" -eq 0 ];
  then
    echo "Nothing missing: steps 1-3 are done, and the next is 4, the destroy of ${FROM}."
  else
    echo "${MISSING} thing(s) MISSING above. Do not destroy ${FROM} until this check shows none."
  fi
}

sequence() {
  local c
  local REGIONS_JSON
  REGIONS_JSON="$(jq -c --arg h "${HOME_REGION}" '[$h] + ([.cells[].region] - [$h])' "${CELLS_FILE}")"
  cat <<EOF
The sequence, in order. This script runs only steps 2 and 3, and only when asked.

 0. (optional, to lose nothing written since the snapshot) stop ${FROM}'s writes
    and snapshot its PRIMARY; then name that snapshot in source_snapshots and a
    new copy name in cells.<cell>.db_snapshot_identifier:
      for n in node-a node-b node-c; do
        aws ecs update-service --region ${HOME_REGION} --cluster ${NAME}-${FROM} \\
          --service ${NAME}-${FROM}-\${n} --desired-count 0; done
      aws rds create-db-snapshot --region ${HOME_REGION} \\
        --db-instance-identifier ${NAME}-${FROM}-primary \\
        --db-snapshot-identifier ${NAME}-${FROM}-pre-cells-<yyyymmddhhmm>
    (DOWNTIME starts here if you do this.)
 1. (administrator, once) foundation/ re-applied with every cell's region in
    permitted_regions and the RdsRestoreAndCopyProjectSnapshots statement
    (deploy/aws/CLAUDE.md, *What foundation/ must be re-applied with first*):
      TF_CLI_ARGS_apply='-var=permitted_regions=${REGIONS_JSON}' \\
        TF_STACK=foundation deploy/aws/terraform-local.sh ${FROM} apply
 2. deploy/aws/convert-to-cells.sh ${FROM} ${TO} --carry-secrets
 3. deploy/aws/convert-to-cells.sh ${FROM} ${TO} --copy-snapshot
    and run this check again: nothing MISSING.
 4. DESTROY ${FROM}. DOWNTIME from here until step 5 ends. Its database is
    deleted with NO final snapshot (skip_final_snapshot) and its automated
    backups with it; its secrets are deleted with NO recovery window. The
    snapshot copy and the carry-over (steps 2-3) are what survive:
      deploy/aws/terraform-local.sh ${FROM} destroy
    (or .github/workflows/${FROM}-destroy.yml, if it has one)
 5. APPLY ${TO} WITH THE CONVERSION — base (the cell database RESTORED), global
    (the carried secrets), then per cell: nodes held at 0, the conversion task
    (schema inits, then node persistence/cell_convert.js), and only then the
    nodes. A failed conversion stops here with the nodes at 0; fix and re-run
    the same command:
      TF_CONVERT=1 IMAGE_TAG=<tag> deploy/aws/terraform-local.sh ${TO} apply
 6. Verify: sign in as the bootstrap administrator (the same password as
    before: aws secretsmanager get-secret-value --region ${HOME_REGION}
    --secret-id ${NAME}/${TO}/bootstrap-admin-password), Monitoring -> Risk
    shows the datasets, a kinit to the KDC works.
 7. Every later apply WITHOUT TF_CONVERT:
      IMAGE_TAG=<tag> deploy/aws/terraform-local.sh ${TO} apply
    When satisfied (administrator): delete the carry-over secret and the
    snapshots$(for c in "${CONV_CELLS[@]}"; do printf ' %s %s' "$(source_of "${c}")" "$(target_of "${c}")"; done).
EOF
}

case "${ACTION}" in
  check)          check ;;
  carry-secrets)  carry_secrets ;;
  copy-snapshot)  copy_snapshots ;;
esac
