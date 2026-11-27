#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# File: deploy/gcp/pep-cluster/provision.sh
#
# ---------------------------------------------------------------------------
# A GCP REMOTE PEP CLUSTER'S MEMBERS, PROVISIONED INTO SECRET MANAGER (#1284).
#
# deploy/aws/pep-cluster/provision.sh, on GCP: what the stack cannot do,
# because no private key may be in its state.
#
#   1. utilities/register-remote-pep.js, run from the SERVICE IMAGE on this
#      machine against the identity service at --idp-url: the entry, the
#      remote PEPs group, the service account, the assertion key (generated
#      here; the service gets only a PKCS #10 request), and — once the member
#      has registered — its HTTPS listener pair, naming --pep-host. Idempotent:
#      the member's secrets seed its --out, so a certified key is not
#      certified again and an issued pair is not reissued.
#   2. The member's FIVE SECRETS, `<name>-<env>-pep-<cluster>-<member>-<part>`
#      (assertion-key, assertion-cert, https-cert, https-key, service-ca), one
#      PEM value each — a VM reads them as files (node-init/secret-files.sh),
#      and a PEM value cannot be an env-file line. Each is in the region, under
#      the project key, as the environments' are (environment/secrets.tf). A
#      new value is a new version and the older versions are DISABLED; an
#      empty value is never written, so a part not issued yet has no version
#      and is left absent on the VM. The working directory is mode 700 and
#      removed on exit.
#   3. The service's PEP cluster (`create-pep-cluster`,
#      `add-pep-cluster-member`).
#   4. WITHOUT --nudge, nudging stopped on each member's row
#      (`xacml/disable-pep`): the load balancer admits the nudge only from
#      `notify_cidrs`, and with none the members converge on their poll.
#   5. A member given a new pair in this run is replaced (`rolling-action
#      replace`), so its VM reads the pair at boot.
#   6. With --pep-app, the companion's /pep-app on the cluster's reverse proxy
#      (the utility's step 8, with the first member), its client secret
#      WITHHELD from the output: the PEP receives it on its own pull.
#
# THE ORDER IS TWO PASSES, because the realm issues a listener pair only to a
# PEP that has REGISTERED:
#   provision.sh …               entries and keys; no pair yet
#   terraform-local.sh … apply   the members start, register, poll
#   provision.sh …               the pairs; each member replaced with its pair
#
#   GOOGLE_CLOUD_PROJECT=<p> deploy/gcp/pep-cluster/provision.sh --env=testpep \
#     --idp-url=https://test-idp.gcp.iyasec.io --idp-env=testidp \
#     --pep-host=test-pep.gcp.iyasec.io --image=<service image> \
#     [--count=2] [--pep-app] [--nudge]
#   GOOGLE_CLOUD_PROJECT=<p> deploy/gcp/pep-cluster/provision.sh --env=testpep --remove
#
# --idp-env names the iya-sts environment IN THIS PROJECT whose seeded
# management client this borrows (`<name>-<idp env>-admin-api-client-secret`);
# ADMIN_API_CLIENT_SECRET_FILE names another client's secret instead. Needs
# gcloud (signed in, with secretmanager.admin and compute.instanceAdmin.v1 —
# the deployer's roles), docker (signed in to Artifact Registry), curl and jq.
#
# WRITTEN AND CHECKED STATICALLY ONLY (deploy/gcp/CLAUDE.md): `bash -n` and
# ShellCheck passed; it has never run against GCP.
# ---------------------------------------------------------------------------
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# Linux, or Windows under Cygwin (#512): hostPath() for every path docker.exe
# or gcloud is handed, HOST_USER_ARGS for `--user`, and the CR-stripping
# shims. See its header.
# shellcheck source=../../../tests/tools/host-platform.sh
. "${REPO_ROOT}/tests/tools/host-platform.sh"

ENV_NAME=""
IDP_URL=""
IDP_ENV=""
PEP_HOST=""
NUDGE=0
CLUSTER="aws"
MODE="per-instance"
COUNT=2
REALM=""
IMAGE=""
REGION="${GOOGLE_CLOUD_REGION:-us-west1}"
PROJECT="${GOOGLE_CLOUD_PROJECT:-}"
NAME="iya-sts"
REMOVE=0
PEP_APP=0
CA_FILE=""

say() { echo "==> [gcp/pep-cluster/${ENV_NAME}/${CLUSTER}] $*" >&2; }
die() { echo "provision.sh: $*" >&2; exit 1; }

for a in "$@"; do
  case "${a}" in
    --env=*) ENV_NAME="${a#*=}" ;;
    --idp-url=*) IDP_URL="${a#*=}" ;;
    --idp-env=*) IDP_ENV="${a#*=}" ;;
    --pep-host=*) PEP_HOST="${a#*=}" ;;
    --nudge) NUDGE=1 ;;
    --cluster=*) CLUSTER="${a#*=}" ;;
    --mode=*) MODE="${a#*=}" ;;
    --count=*) COUNT="${a#*=}" ;;
    --realm=*) REALM="${a#*=}" ;;
    --image=*) IMAGE="${a#*=}" ;;
    --region=*) REGION="${a#*=}" ;;
    --project=*) PROJECT="${a#*=}" ;;
    --ca=*) CA_FILE="${a#*=}" ;;
    --remove) REMOVE=1 ;;
    --pep-app) PEP_APP=1 ;;
    -h|--help) sed -n '8,59p' "$0"; exit 0 ;;
    *) die "unknown argument '${a}' (--help)." ;;
  esac
done

[[ "${ENV_NAME}" =~ ^[a-z][a-z0-9]{1,11}$ ]] || die "--env is a PEP environment name, 2-12 [a-z0-9], starting with a letter."
[[ "${CLUSTER}" =~ ^[a-z][a-z0-9-]{0,11}$ ]] || die "--cluster is 1-12 [a-z0-9-], starting with a letter (the stack's variable)."
[[ "${COUNT}" =~ ^[1-9]$ ]] || die "--count is 1 to 9."
case "${MODE}" in per-instance|shared) ;; *) die "--mode is per-instance or shared." ;; esac
[ -n "${PROJECT}" ] || die "GOOGLE_CLOUD_PROJECT (or --project) is the project the foundation was applied to."
for c in gcloud jq curl docker; do
  # `hash`, not the other builtin: tests/host_platform.js reads any `-v "${…}"`
  # as a bind mount that has to go through hostPath().
  hash "${c}" 2>/dev/null || die "needs ${c}."
done

PREFIX="${NAME}-${ENV_NAME}"
KMS_KEY="projects/${PROJECT}/locations/${REGION}/keyRings/${NAME}/cryptoKeys/${NAME}"
G=(gcloud --project="${PROJECT}" --quiet)
PARTS=(assertion-key assertion-cert https-cert https-key service-ca)

# The file each part is, under a member's --out (register-remote-pep.js's
# layout).
part_file() {
  case "$1" in
    assertion-key) echo "pep-assertion.key" ;;
    assertion-cert) echo "pep-assertion.crt" ;;
    https-cert) echo "server/pep-server.crt" ;;
    https-key) echo "server/pep-server.key" ;;
    service-ca) echo "service-ca.pem" ;;
  esac
}

# The members, named exactly as the stack names them (main.tf, `members`).
MEMBERS=()
if [ "${MODE}" = "per-instance" ];
then
  for i in $(seq 1 "${COUNT}"); do
    MEMBERS+=("${CLUSTER}-pep-${i}")
  done
else
  MEMBERS+=("${CLUSTER}-pep")
fi

secret_id() { echo "${PREFIX}-pep-${CLUSTER}-$1-$2"; }

# --- --remove: the secrets, after the stack is destroyed -------------------
# The service-side entries are left alone: removing a PEP from the service is
# remote-pep.md's *Removing one*, an administrator's decision.
if [ "${REMOVE}" = "1" ];
then
  names="$("${G[@]}" secrets list --filter="name~/secrets/${PREFIX}-pep-${CLUSTER}-" --format='value(name.basename())')"
  for n in ${names}; do
    say "deleting ${n}"
    "${G[@]}" secrets delete "${n}" > /dev/null
  done
  [ -n "${names}" ] || say "no member secrets for ${PREFIX}-pep-${CLUSTER}-*"
  exit 0
fi

[ -n "${IDP_URL}" ] || die "--idp-url is the identity service's publicBaseUrl: the token endpoint takes only that as a resource."
[ -n "${PEP_HOST}" ] || die "--pep-host is the PEP environment's public_hostname: its listener certificates name it, and with --pep-app it is the callback's origin."
[ -n "${IMAGE}" ] || die "--image is the service image (it ships register-remote-pep.js)."
[ -n "${IDP_ENV}" ] || [ -n "${ADMIN_API_CLIENT_SECRET_FILE:-}" ] ||
  die "--idp-env names the iya-sts environment whose management client to use, or set ADMIN_API_CLIENT_SECRET_FILE."

URL="${IDP_URL%/}"
PDP_URL="${URL}${REALM:+/realm/${REALM}}"

# THE WORKING DIRECTORY: private, and gone however this exits.
BASE="${XDG_RUNTIME_DIR:-${TMPDIR:-/tmp}}"
WORK="$(mktemp -d "${BASE}/pep-provision.XXXXXX")"
chmod 700 "${WORK}"
trap 'rm -rf "${WORK}"' EXIT

if [ -n "${ADMIN_API_CLIENT_SECRET_FILE:-}" ];
then
  cp "${ADMIN_API_CLIENT_SECRET_FILE}" "${WORK}/client-secret"
else
  "${G[@]}" secrets versions access latest \
    --secret="${NAME}-${IDP_ENV}-admin-api-client-secret" > "${WORK}/client-secret"
fi
chmod 600 "${WORK}/client-secret"

CURL_CA=()
if [ -n "${CA_FILE}" ];
then
  cp "${CA_FILE}" "${WORK}/service-ca.pem"
  CURL_CA=(--cacert "${WORK}/service-ca.pem")
fi

token() {
  curl -fsS "${CURL_CA[@]}" -u "sts-api-client:$(cat "${WORK}/client-secret")" \
    -d grant_type=client_credentials \
    --data-urlencode 'scope=admin:read admin:write' \
    --data-urlencode "resource=${URL}/admin-api" "${URL}/oauth2/token" |
    jq -r '.access_token // empty'
}

# Whether secret $1 exists at all.
secret_exists() {
  "${G[@]}" secrets describe "$1" --format='value(name)' > /dev/null 2>&1
}

# The latest version of secret $1 into file $2; false when it has none.
secret_read() {
  "${G[@]}" secrets versions access latest --secret="$1" > "$2" 2>/dev/null
}

# File $2 becomes secret $1's only enabled version: created when missing,
# a new version, and every older enabled version disabled.
secret_write() {
  local id="$1" file="$2" v keep
  if ! secret_exists "${id}";
  then
    "${G[@]}" secrets create "${id}" \
      --replication-policy=user-managed --locations="${REGION}" \
      --kms-key-name="${KMS_KEY}" \
      --labels="environment=${ENV_NAME},pep-cluster=${CLUSTER}" > /dev/null
  fi
  keep="$("${G[@]}" secrets versions add "${id}" --data-file="$(hostPath "${file}")" \
          --format='value(name)')"
  for v in $("${G[@]}" secrets versions list "${id}" --filter='state=ENABLED' \
               --format='value(name.basename())'); do
    [ "${v}" = "$(basename "${keep}")" ] && continue
    "${G[@]}" secrets versions disable "${v}" --secret="${id}" > /dev/null
  done
}

REDEPLOY=()
for m in "${MEMBERS[@]}"; do
  out="${WORK}/${m}"
  mkdir -p "${out}/server"
  had_pair=0

  # SEED --out FROM THE SECRETS, so the utility sees the key it certified
  # last time and the pair it issued, and asks for neither again.
  for part in "${PARTS[@]}"; do
    f="${out}/$(part_file "${part}")"
    if secret_read "$(secret_id "${m}" "${part}")" "${f}.seed" && [ -s "${f}.seed" ];
    then
      mv "${f}.seed" "${f}"
      cp "${f}" "${f}.old"
    else
      rm -f "${f}.seed"
    fi
  done
  [ -s "${out}/server/pep-server.crt" ] && had_pair=1

  say "registering ${m}"
  # The companion's path, with the first member only (the AWS script's
  # reasoning); the members are GCP's VMs, so the utility starts nothing.
  APP_ARGS=()
  if [ "${PEP_APP}" = "1" ] && [ "${m}" = "${MEMBERS[0]}" ];
  then
    APP_ARGS=(--cluster="${CLUSTER}" --create-cluster --pep-app
              --upstream="http://127.0.0.1:9700"
              --public-base="https://${PEP_HOST}")
  fi
  docker run --rm "${HOST_USER_ARGS[@]}" \
    -v "$(hostPath "${WORK}"):/work" \
    -e ADMIN_API_CLIENT_SECRET_FILE=/work/client-secret \
    -e HOME=/work -e REGISTER_PEP_NO_START=1 \
    --entrypoint node "${IMAGE}" utilities/register-remote-pep.js \
    --url="${URL}" ${REALM:+--realm="${REALM}"} --name="${m}" \
    --out="/work/${m}" --pdp-url="${PDP_URL}" --https-dns="${PEP_HOST}" \
    ${CA_FILE:+--ca=/work/service-ca.pem} "${APP_ARGS[@]}" |
    sed -E 's/(Client secret for "[^"]*" \(shown once\): ).*/\1[withheld by provision.sh: the PEP receives it on its pull]/' >&2 ||
    die "register-remote-pep.js failed for ${m}; nothing of it was stored."

  # Only what changed, and never an empty value.
  for part in "${PARTS[@]}"; do
    f="${out}/$(part_file "${part}")"
    id="$(secret_id "${m}" "${part}")"
    if [ ! -s "${f}" ];
    then
      secret_exists "${id}" || "${G[@]}" secrets create "${id}" \
        --replication-policy=user-managed --locations="${REGION}" \
        --kms-key-name="${KMS_KEY}" \
        --labels="environment=${ENV_NAME},pep-cluster=${CLUSTER}" > /dev/null
      continue
    fi
    if [ -f "${f}.old" ] && cmp -s "${f}" "${f}.old";
    then
      continue
    fi
    secret_write "${id}" "${f}"
    say "${id}: written"
  done

  if [ "${had_pair}" = "0" ] && [ -s "${out}/server/pep-server.crt" ];
  then
    REDEPLOY+=("${m}")
  elif [ ! -s "${out}/server/pep-server.crt" ];
  then
    say "${m}: no listener pair yet — the realm issues one only once the" \
        "member has registered. Apply the stack, then run this again."
  fi
done

# --- 3. The service's PEP cluster ------------------------------------------
TOKEN="$(token)"
[ -n "${TOKEN}" ] || die "could not mint a management API token at ${URL}/oauth2/token."
API="${URL}${REALM:+/realm/${REALM}}/admin-api"
api() {
  curl -sS "${CURL_CA[@]}" -H "Authorization: Bearer ${TOKEN}" "$@"
}
clusters="$(api "${API}/xacml/pep-clusters")"
if ! jq -e --arg c "${CLUSTER}" '.clusters[]? | select(.name == $c)' \
       > /dev/null <<<"${clusters}";
then
  api -H 'Content-Type: application/json' \
    -d "$(jq -n --arg c "${CLUSTER}" '{cluster: $c}')" \
    "${API}/xacml/create-pep-cluster" | jq -e '.ok' > /dev/null ||
    die "could not create the PEP cluster ${CLUSTER}."
  say "PEP cluster ${CLUSTER}: created"
  clusters="$(api "${API}/xacml/pep-clusters")"
fi
for m in "${MEMBERS[@]}"; do
  if jq -e --arg c "${CLUSTER}" --arg m "${m}" \
       '.clusters[]? | select(.name == $c) | .members[]? | select(.pep == $m)' \
       > /dev/null <<<"${clusters}";
  then
    continue
  fi
  api -H 'Content-Type: application/json' \
    -d "$(jq -n --arg c "${CLUSTER}" --arg m "${m}" '{cluster: $c, pep: $m}')" \
    "${API}/xacml/add-pep-cluster-member" | jq -e '.ok' > /dev/null ||
    die "could not add ${m} to the PEP cluster ${CLUSTER}."
  say "PEP cluster ${CLUSTER}: ${m} joined"
done

# --- 4. Nudging stopped, unless the load balancer admits the nudge ---------
if [ "${NUDGE}" = "0" ];
then
  for m in "${MEMBERS[@]}"; do
    answer="$(api -H 'Content-Type: application/json' \
      -d "$(jq -n --arg m "${m}" '{name: $m}')" "${API}/xacml/disable-pep")"
    if jq -e '.ok' > /dev/null <<<"${answer}";
    then
      say "${m}: nudging stopped; it converges on its poll"
    else
      say "${m}: nudging not stopped yet ($(jq -r '.why // "no answer"' <<<"${answer}"))." \
          "Run this again once it has registered."
    fi
  done
fi

# --- 5. A member that has just been given its pair is replaced -------------
for m in "${REDEPLOY[@]}"; do
  group="${PREFIX}-${m}"
  if [ "${MODE}" = "shared" ];
  then
    group="${PREFIX}-${CLUSTER}-pep"
    where=(--region="${REGION}")
  else
    zone="$("${G[@]}" compute instance-groups managed list \
      --filter="name=${group}" --format='value(zone.basename())')"
    [ -n "${zone}" ] || continue
    where=(--zone="${zone}")
  fi
  "${G[@]}" compute instance-groups managed rolling-action replace "${group}" \
    "${where[@]}" > /dev/null
  say "${group}: replaced, to read its listener pair"
done
say "done."
