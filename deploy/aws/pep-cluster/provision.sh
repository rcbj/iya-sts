#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# File: deploy/aws/pep-cluster/provision.sh
#
# ---------------------------------------------------------------------------
# A REMOTE PEP CLUSTER'S MEMBERS, PROVISIONED INTO SECRETS MANAGER (#1284).
#
# What the pep-cluster/ stack cannot do, because it must never hold a private
# key in its state: for each member, the service-side registration and the
# key material, in the order docs/v1.2.0/remote-pep.md's *Registering a new
# remote PEP* gives it.
#
#   1. utilities/register-remote-pep.js, run from the SERVICE IMAGE on this
#      machine: the entry, the remote PEPs group, the service account, the
#      assertion key (generated here; the service gets only a PKCS #10
#      request), and — once the member has registered — its HTTPS listener
#      pair, naming the public name and the load balancer's direct name
#      (main.tf, *TWO NAMES*). It is idempotent: the
#      member's secret seeds its --out, so a key already certified is not
#      certified again and a pair already issued is not reissued.
#   2. The member's secret, `<secret path>/pep/<cluster>/<member>`, sealed
#      under the project key, holding five JSON members: assertion_key,
#      assertion_cert, https_cert, https_key, service_ca. Written only when
#      it changed. The working directory is mode 700 and removed on exit.
#   3. The service's PEP cluster (`create-pep-cluster`,
#      `add-pep-cluster-member`), so the members share one configuration.
#   4. When a pair was issued in this run and the member's ECS service
#      exists, a new deployment of it, so the tasks start with the pair.
#   5. With --pep-app, the companion's `/pep-app` on the cluster's reverse
#      proxy (the utility's step 8, asked once, with the first member):
#      the role `pep-app`, the confidential client `pep-app` with its
#      callback at the load balancer's 9543, global consent for its four
#      scopes, and one session route to `http://127.0.0.1:9700` — each
#      member's own companion sidecar (the stack's `companion = true`).
#      THE CLIENT SECRET IS WITHHELD: the utility prints a new one once, and
#      this script replaces it in that line, because the PEP receives the
#      secret on its own authenticated pull and nobody else needs it.
#
# THE ORDER IS TWO PASSES, because the realm issues a listener pair only to a
# PEP that has REGISTERED:
#   provision.sh …            entries and keys; no pair yet
#   terraform-local.sh … apply  the members start, register, poll
#   provision.sh …            the pairs; each member redeployed with its pair
#
#   deploy/aws/pep-cluster/provision.sh --env=testidp \
#     --host=test-idp.iyasec.io --direct-host=direct.test-idp.iyasec.io \
#     --image=<service image> [--count=2] [--pep-app]
#   deploy/aws/pep-cluster/provision.sh --env=testidp --remove   # the secrets
#
# Needs docker, the aws CLI (credentials for the account), curl and jq. The
# service image is the one the environment runs (it ships the utility and
# its npm dependencies); pass it with --image.
# ---------------------------------------------------------------------------
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# Linux, or Windows under Cygwin (#512): hostPath() for every path docker.exe
# or aws.exe is handed, HOST_USER_ARGS for `--user`, and the CR-stripping
# shims. See its header.
# shellcheck source=../../../tests/tools/host-platform.sh
. "${REPO_ROOT}/tests/tools/host-platform.sh"

ENV_NAME=""
HOST=""
DIRECT_HOST=""
CLUSTER="aws"
MODE="per-instance"
COUNT=2
REALM=""
CELL=""
IMAGE=""
REGION="${AWS_REGION:-us-west-2}"
NAME="iya-sts"
REMOVE=0
PEP_APP=0
PROXY_PORT=9543
CA_FILE=""

say() { echo "==> [pep-cluster/${ENV_NAME}/${CLUSTER}] $*" >&2; }
die() { echo "provision.sh: $*" >&2; exit 1; }

for a in "$@"; do
  case "${a}" in
    --env=*) ENV_NAME="${a#*=}" ;;
    --host=*) HOST="${a#*=}" ;;
    --direct-host=*) DIRECT_HOST="${a#*=}" ;;
    --cluster=*) CLUSTER="${a#*=}" ;;
    --mode=*) MODE="${a#*=}" ;;
    --count=*) COUNT="${a#*=}" ;;
    --realm=*) REALM="${a#*=}" ;;
    --cell=*) CELL="${a#*=}" ;;
    --image=*) IMAGE="${a#*=}" ;;
    --region=*) REGION="${a#*=}" ;;
    --ca=*) CA_FILE="${a#*=}" ;;
    --remove) REMOVE=1 ;;
    --pep-app) PEP_APP=1 ;;
    --proxy-port=*) PROXY_PORT="${a#*=}" ;;
    -h|--help) sed -n '8,56p' "$0"; exit 0 ;;
    *) die "unknown argument '${a}' (--help)." ;;
  esac
done

[[ "${ENV_NAME}" =~ ^[a-z0-9]{2,12}$ ]] || die "--env is an environment name, 2-12 [a-z0-9]."
[[ "${CLUSTER}" =~ ^[a-z0-9][a-z0-9-]{0,11}$ ]] || die "--cluster is 1-12 [a-z0-9-] (the stack's variable)."
[[ "${COUNT}" =~ ^[1-9]$ ]] || die "--count is 1 to 9."
case "${MODE}" in per-instance|shared) ;; *) die "--mode is per-instance or shared." ;; esac
for c in aws jq curl docker; do
  # `hash`, not `command -v`: tests/host_platform.js reads any `-v "${…}"`
  # as a bind mount that has to go through hostPath().
  hash "${c}" 2>/dev/null || die "needs ${c}."
done

if [ -n "${CELL}" ];
then
  SECRET_PATH="${NAME}/${ENV_NAME}/${CELL}"
  KMS_ALIAS="alias/${NAME}-cell-${CELL}"
  ECS_PREFIX="${NAME}-${ENV_NAME}-${CELL}"
else
  SECRET_PATH="${NAME}/${ENV_NAME}"
  KMS_ALIAS="alias/${NAME}"
  ECS_PREFIX="${NAME}-${ENV_NAME}"
fi

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

secret_name() { echo "${SECRET_PATH}/pep/${CLUSTER}/$1"; }

# --- --remove: the secrets, after the stack is destroyed -------------------
# The service-side entries are left alone: removing a PEP from the service is
# remote-pep.md's *Removing one*, an administrator's decision.
if [ "${REMOVE}" = "1" ];
then
  # Every member secret under the cluster's prefix, whatever count made it.
  names="$(aws secretsmanager list-secrets --region "${REGION}" \
    --filters Key=name,Values="${SECRET_PATH}/pep/${CLUSTER}/" \
    --query 'SecretList[].Name' --output text)"
  [ "${names}" = "None" ] && names=""
  for n in ${names}; do
    say "deleting ${n}"
    aws secretsmanager delete-secret --region "${REGION}" --secret-id "${n}" \
      --force-delete-without-recovery >/dev/null
  done
  [ -n "${names}" ] || say "no member secrets under ${SECRET_PATH}/pep/${CLUSTER}/"
  exit 0
fi

[ -n "${HOST}" ] || die "--host is the environment's public_hostname (terraform output public_hostname): the token endpoint's resource, and what the VPC resolves to the load balancer."
[ -n "${IMAGE}" ] || die "--image is the service image the environment runs (it ships register-remote-pep.js)."

URL="https://${HOST}"
PDP_URL="${URL}${REALM:+/realm/${REALM}}"

# THE WORKING DIRECTORY: private, and gone however this exits. Under the
# user's runtime directory where there is one (a tmpfs on most systems), so
# a key never touches a disk that outlives the session.
BASE="${XDG_RUNTIME_DIR:-${TMPDIR:-/tmp}}"
WORK="$(mktemp -d "${BASE}/pep-provision.XXXXXX")"
chmod 700 "${WORK}"
trap 'rm -rf "${WORK}"' EXIT

# The seeded management API client's secret (environment/secrets.tf): the
# utility mints its own token with it, and so does step 3 below.
aws secretsmanager get-secret-value --region "${REGION}" \
  --secret-id "${SECRET_PATH}/admin-api-client-secret" \
  --query SecretString --output text > "${WORK}/client-secret"
chmod 600 "${WORK}/client-secret"

CURL_CA=()
if [ -n "${CA_FILE}" ];
then
  cp "${CA_FILE}" "${WORK}/service-ca.pem"
  CURL_CA=(--cacert "${WORK}/service-ca.pem")
fi

# A management API token for the default realm, which may act on every realm.
token() {
  curl -fsS "${CURL_CA[@]}" -u "sts-api-client:$(cat "${WORK}/client-secret")" \
    -d grant_type=client_credentials \
    --data-urlencode 'scope=admin:read admin:write' \
    --data-urlencode "resource=${URL}/admin-api" "${URL}/oauth2/token" |
    jq -r '.access_token // empty'
}

# Writes the JSON member $2 of secret file $1 to file $3, when it is set.
seed() {
  local v
  v="$(jq -r --arg k "$2" '.[$k] // ""' "$1")"
  if [ -n "${v}" ];
  then
    mkdir -p "$(dirname "$3")"
    printf '%s\n' "${v}" > "$3"
  fi
}

# Reads file $1 into a JSON string, or "" when it is absent.
member_json() {
  local out="$1"
  jq -n \
    --rawfile ak <(cat "${out}/pep-assertion.key" 2>/dev/null || true) \
    --rawfile ac <(cat "${out}/pep-assertion.crt" 2>/dev/null || true) \
    --rawfile hc <(cat "${out}/server/pep-server.crt" 2>/dev/null || true) \
    --rawfile hk <(cat "${out}/server/pep-server.key" 2>/dev/null || true) \
    --rawfile ca <(cat "${out}/service-ca.pem" 2>/dev/null || true) \
    '{assertion_key: $ak, assertion_cert: $ac, https_cert: $hc,
      https_key: $hk, service_ca: $ca}'
}

REDEPLOY=()
for m in "${MEMBERS[@]}"; do
  sn="$(secret_name "${m}")"
  out="${WORK}/${m}"
  mkdir -p "${out}/server"
  had_pair=0

  # SEED --out FROM THE SECRET, so the utility sees the key it certified last
  # time and the pair it issued, and asks for neither again.
  exists=0
  if aws secretsmanager get-secret-value --region "${REGION}" --secret-id "${sn}" \
       --query SecretString --output text > "${WORK}/${m}.old" 2>/dev/null;
  then
    exists=1
    seed "${WORK}/${m}.old" assertion_key "${out}/pep-assertion.key"
    seed "${WORK}/${m}.old" assertion_cert "${out}/pep-assertion.crt"
    seed "${WORK}/${m}.old" https_cert "${out}/server/pep-server.crt"
    seed "${WORK}/${m}.old" https_key "${out}/server/pep-server.key"
    seed "${WORK}/${m}.old" service_ca "${out}/service-ca.pem"
    [ -s "${out}/server/pep-server.crt" ] && had_pair=1
  else
    echo '{}' > "${WORK}/${m}.old"
  fi

  say "registering ${m}"
  # As this user (HOST_USER_ARGS), so the files it writes are this user's
  # and the mode-700 directory is writable; the image's own user (10001)
  # could not. Empty under Cygwin, where Docker Desktop's mount is the
  # user's anyway.
  # THE COMPANION'S PATH, with the first member only: the utility's
  # --cluster is what asks it, and its own cluster step creates the cluster
  # when it is not there yet (step 3 below then finds it). The members'
  # containers are Fargate's, so the utility starts none
  # (REGISTER_PEP_NO_START).
  APP_ARGS=()
  if [ "${PEP_APP}" = "1" ] && [ "${m}" = "${MEMBERS[0]}" ];
  then
    APP_ARGS=(--cluster="${CLUSTER}" --create-cluster --pep-app
              --upstream="http://127.0.0.1:9700"
              --public-base="https://${DIRECT_HOST:-${HOST}}:${PROXY_PORT}")
  fi
  docker run --rm "${HOST_USER_ARGS[@]}" \
    -v "$(hostPath "${WORK}"):/work" \
    -e ADMIN_API_CLIENT_SECRET_FILE=/work/client-secret \
    -e HOME=/work -e REGISTER_PEP_NO_START=1 \
    --entrypoint node "${IMAGE}" utilities/register-remote-pep.js \
    --url="${URL}" ${REALM:+--realm="${REALM}"} --name="${m}" \
    --out="/work/${m}" --pdp-url="${PDP_URL}" --https-dns="${HOST}" \
    ${DIRECT_HOST:+--https-dns="${DIRECT_HOST}"} \
    ${CA_FILE:+--ca=/work/service-ca.pem} "${APP_ARGS[@]}" |
    sed -E 's/(Client secret for "[^"]*" \(shown once\): ).*/\1[withheld by provision.sh: the PEP receives it on its pull]/' >&2 ||
    die "register-remote-pep.js failed for ${m}; nothing of it was stored."

  member_json "${out}" > "${WORK}/${m}.new"
  if [ "$(jq -S . "${WORK}/${m}.old")" = "$(jq -S . "${WORK}/${m}.new")" ];
  then
    say "${sn}: unchanged"
  elif [ "${exists}" = "1" ];
  then
    aws secretsmanager put-secret-value --region "${REGION}" --secret-id "${sn}" \
      --secret-string "file://$(hostPath "${WORK}/${m}.new")" >/dev/null
    say "${sn}: updated"
  else
    aws secretsmanager create-secret --region "${REGION}" --name "${sn}" \
      --description "iya-sts ${ENV_NAME}: remote PEP ${m} (cluster ${CLUSTER})" \
      --kms-key-id "${KMS_ALIAS}" \
      --secret-string "file://$(hostPath "${WORK}/${m}.new")" >/dev/null
    say "${sn}: created"
  fi

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
       >/dev/null <<<"${clusters}";
then
  api -H 'Content-Type: application/json' \
    -d "$(jq -n --arg c "${CLUSTER}" '{cluster: $c}')" \
    "${API}/xacml/create-pep-cluster" | jq -e '.ok' >/dev/null ||
    die "could not create the PEP cluster ${CLUSTER}."
  say "PEP cluster ${CLUSTER}: created"
  clusters="$(api "${API}/xacml/pep-clusters")"
fi
for m in "${MEMBERS[@]}"; do
  if jq -e --arg c "${CLUSTER}" --arg m "${m}" \
       '.clusters[]? | select(.name == $c) | .members[]? | select(.pep == $m)' \
       >/dev/null <<<"${clusters}";
  then
    continue
  fi
  api -H 'Content-Type: application/json' \
    -d "$(jq -n --arg c "${CLUSTER}" --arg m "${m}" '{cluster: $c, pep: $m}')" \
    "${API}/xacml/add-pep-cluster-member" | jq -e '.ok' >/dev/null ||
    die "could not add ${m} to the PEP cluster ${CLUSTER}."
  say "PEP cluster ${CLUSTER}: ${m} joined"
done

# --- 4. A member that has just been given its pair starts again with it ----
for m in "${REDEPLOY[@]}"; do
  svc="${ECS_PREFIX}-pep-${m}"
  if aws ecs describe-services --region "${REGION}" --cluster "${ECS_PREFIX}" \
       --services "${svc}" --query 'services[?status==`ACTIVE`].serviceName' \
       --output text 2>/dev/null | grep -q .;
  then
    aws ecs update-service --region "${REGION}" --cluster "${ECS_PREFIX}" \
      --service "${svc}" --force-new-deployment >/dev/null
    say "${svc}: redeployed with its listener pair"
  fi
done
say "done."
