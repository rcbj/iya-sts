#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# File: deploy/azure/pep-cluster/provision.sh
#
# ---------------------------------------------------------------------------
# A REMOTE PEP CLUSTER'S MEMBERS, PROVISIONED INTO KEY VAULT (#1284) —
# deploy/aws/pep-cluster/provision.sh against Azure: the same steps, the
# vault the foundation made for the PEP environment in place of Secrets
# Manager, and a VM restart in place of an ECS deployment.
#
# What the pep-cluster/ stack cannot do, because it must never hold a private
# key in its state: for each member, the service-side registration and the
# key material, in the order docs/v1.2.0/remote-pep.md's *Registering a new
# remote PEP* gives it.
#
#   1. utilities/register-remote-pep.js, run from the SERVICE IMAGE on this
#      machine against the identity service at --idp-url: the entry, the
#      remote PEPs group, the service account, the assertion key (generated
#      here; the service gets only a PKCS #10 request), and — once the member
#      has registered — its HTTPS listener pair, naming the PEP environment's
#      public name (the gateway checks the member's certificate against it).
#      Idempotent: the member's secret seeds its --out, so a key already
#      certified is not certified again and a pair already issued is not
#      reissued.
#   2. The member's secret, `pep-<cluster>-<member>` in the vault
#      `mp<env>-<hash>`, five JSON members: assertion_key, assertion_cert,
#      https_cert, https_key, service_ca. Written only when it changed. The
#      working directory is mode 700 and removed on exit.
#   3. The service's PEP cluster (`create-pep-cluster`,
#      `add-pep-cluster-member`), so the members share one configuration.
#   4. WITHOUT --nudge, nudging stopped on each member's row
#      (`xacml/disable-pep`): the gateway admits the identity service's nudge
#      only from `notify_cidrs`, and with none the members converge on their
#      poll. A member that has not registered yet has no row; the second pass
#      stops it.
#   5. When a pair was issued in this run, a restart of that member's VMs, so
#      they read the pair at boot (pep-secrets.sh); and the identity
#      service's Root, the last certificate of the pair's chain, written to
#      pep-cluster/anchors/<env>.crt — what the gateway verifies every
#      member's pair against. terraform-local.sh hands it to the stack: APPLY
#      AGAIN after this pass (deploy/azure/CLAUDE.md, *A remote PEP cluster*).
#   6. With --pep-app, the companion's `/pep-app` on the cluster's reverse
#      proxy (the utility's step 8, asked once, with the first member): the
#      role `pep-app`, the confidential client `pep-app` with its callback at
#      https://<pep host>/.iya-pep/callback, its consent and its signals
#      grant, and one session route to `http://127.0.0.1:9700` — each
#      member's own companion. THE CLIENT SECRET IS WITHHELD: the utility
#      prints a new one once, and this script replaces it in that line,
#      because the PEP receives it on its own authenticated pull.
#
# THE ORDER IS TWO PASSES AND TWO APPLIES, because the realm issues a
# listener pair only to a PEP that has REGISTERED, and the gateway verifies
# that pair:
#   provision.sh …              entries and keys; no pair yet
#   terraform-local.sh … apply  the members start, register, poll
#   provision.sh …              the pairs, the anchor; members restarted
#   terraform-local.sh … apply  the gateway trusts the members
#
#   deploy/azure/pep-cluster/provision.sh --env=testpep \
#     --idp-url=https://test-idp.azure.iyasec.io --idp-env=testidp \
#     --pep-host=test-pep.azure.iyasec.io --image=<service image> \
#     [--count=2] [--pep-app] [--nudge]
#   deploy/azure/pep-cluster/provision.sh --env=testpep --remove   # the secrets
#
# --env is the PEP ENVIRONMENT (its vault, its VMs); --idp-url the identity
# service, at its publicBaseUrl; --idp-env the Azure iya-sts environment
# whose seeded management client this borrows (`admin-api-client-secret` in
# that environment's vault) — or name a file holding another client's
# secret with ADMIN_API_CLIENT_SECRET_FILE. Needs docker, the Azure CLI
# (logged in as a deployer), curl, jq and sha1sum.
# ---------------------------------------------------------------------------
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# Linux, or Windows under Cygwin (#512): hostPath() for every path docker.exe
# is handed, HOST_USER_ARGS for `--user`, and the CR-stripping shims. See its
# header.
# shellcheck source=../../../tests/tools/host-platform.sh
. "${REPO_ROOT}/tests/tools/host-platform.sh"

ENV_NAME=""
IDP_URL=""
IDP_ENV=""
PEP_HOST=""
NUDGE=0
CLUSTER="azure"
MODE="per-instance"
COUNT=2
REALM=""
IMAGE=""
NAME="iya-sts"
REMOVE=0
PEP_APP=0
CA_FILE=""

say() { echo "==> [azure/pep-cluster/${ENV_NAME}/${CLUSTER}] $*" >&2; }
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
    --ca=*) CA_FILE="${a#*=}" ;;
    --remove) REMOVE=1 ;;
    --pep-app) PEP_APP=1 ;;
    -h|--help) sed -n '8,72p' "$0"; exit 0 ;;
    *) die "unknown argument '${a}' (--help)." ;;
  esac
done

[[ "${ENV_NAME}" =~ ^[a-z][a-z0-9]{1,11}$ ]] || die "--env is a PEP environment's name, 2-12 [a-z0-9], starting with a letter."
[[ "${CLUSTER}" =~ ^[a-z0-9][a-z0-9-]{0,11}$ ]] || die "--cluster is 1-12 [a-z0-9-] (the stack's variable)."
[[ "${COUNT}" =~ ^[1-9]$ ]] || die "--count is 1 to 9."
case "${MODE}" in per-instance|shared) ;; *) die "--mode is per-instance or shared." ;; esac
for c in az jq curl docker sha1sum; do
  # `hash`, not `command -v`: tests/host_platform.js reads any `-v "${…}"`
  # as a bind mount that has to go through hostPath().
  hash "${c}" 2>/dev/null || die "needs ${c}."
done

SUBSCRIPTION="${AZURE_SUBSCRIPTION_ID:-$(az account show --query id -o tsv)}"
[ -n "${SUBSCRIPTION}" ] || die "no subscription: set AZURE_SUBSCRIPTION_ID, or az login."

# THE FOUNDATION'S NAMES, by its formulas (../foundation/pep_units.tf,
# ../foundation/locals.tf), so nothing reads its state.
hash4() { printf '%s' "$1" | sha1sum | cut -c1-4; }
PEP_GROUP="${NAME}-${ENV_NAME}"
PEP_VAULT="mp${ENV_NAME}-$(hash4 "${SUBSCRIPTION}/${NAME}/pep/${ENV_NAME}")"
ANCHOR_FILE="${REPO_ROOT}/deploy/azure/pep-cluster/anchors/${ENV_NAME}.crt"

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

secret_name() { echo "pep-${CLUSTER}-$1"; }

# --- --remove: the secrets, after the stack is destroyed -------------------
# Deleted, and soft-deleted for the vault's seven days, as the environments'
# are; a later run of this script recovers a name it needs. The service-side
# entries are left alone (remote-pep.md, *Removing one*).
if [ "${REMOVE}" = "1" ];
then
  names="$(az keyvault secret list --vault-name "${PEP_VAULT}" \
    --query "[?starts_with(name, 'pep-${CLUSTER}-')].name" -o tsv)"
  for n in ${names}; do
    say "deleting ${n}"
    az keyvault secret delete --vault-name "${PEP_VAULT}" --name "${n}" > /dev/null
  done
  [ -n "${names}" ] || say "no member secrets named pep-${CLUSTER}-* in ${PEP_VAULT}"
  if [ -f "${ANCHOR_FILE}" ];
  then
    rm -f -- "${ANCHOR_FILE}"
    say "removed ${ANCHOR_FILE}"
  fi
  exit 0
fi

[ -n "${IDP_URL}" ] || die "--idp-url is the identity service's publicBaseUrl (https://test-idp.azure.iyasec.io): the token endpoint takes only that as a resource."
[ -n "${PEP_HOST}" ] || die "--pep-host is the PEP environment's public_hostname: its listener certificates name it, and with --pep-app it is the callback's origin."
[ -n "${IMAGE}" ] || die "--image is the service image (it ships register-remote-pep.js)."
[ -n "${IDP_ENV}" ] || [ -n "${ADMIN_API_CLIENT_SECRET_FILE:-}" ] ||
  die "--idp-env names the Azure iya-sts environment whose management client to use, or set ADMIN_API_CLIENT_SECRET_FILE."

URL="${IDP_URL%/}"
PDP_URL="${URL}${REALM:+/realm/${REALM}}"

# THE WORKING DIRECTORY: private, and gone however this exits. Under the
# user's runtime directory where there is one (a tmpfs on most systems), so
# a key never touches a disk that outlives the session.
BASE="${XDG_RUNTIME_DIR:-${TMPDIR:-/tmp}}"
WORK="$(mktemp -d "${BASE}/pep-provision.XXXXXX")"
chmod 700 "${WORK}"
cleanup() {
  [ -n "${WORK}" ] && [ -d "${WORK}" ] && find "${WORK}" -mindepth 1 -delete && rmdir "${WORK}"
}
trap cleanup EXIT

# The management API client's secret: the identity environment's seeded
# `sts-api-client`, in that environment's vault (../environment/secrets.tf;
# the vault is ../foundation/locals.tf's `ms<env>-<hash>`), or a file of the
# caller's. The utility mints its own token with it, and so do steps 3 and 4.
if [ -n "${ADMIN_API_CLIENT_SECRET_FILE:-}" ];
then
  cp "${ADMIN_API_CLIENT_SECRET_FILE}" "${WORK}/client-secret"
else
  idp_vault="ms${IDP_ENV}-$(hash4 "${SUBSCRIPTION}/${NAME}/${IDP_ENV}/")"
  az keyvault secret show --vault-name "${idp_vault}" \
    --name admin-api-client-secret --query value -o tsv > "${WORK}/client-secret"
fi
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

# The five members of a member's secret, from the files in $1.
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

# Writes file $2 as secret $1, recovering the name first if a --remove left it
# soft-deleted.
put_secret() {
  if ! az keyvault secret set --vault-name "${PEP_VAULT}" --name "$1" \
         --file "$2" --encoding utf-8 > /dev/null 2>&1;
  then
    az keyvault secret recover --vault-name "${PEP_VAULT}" --name "$1" > /dev/null 2>&1 || true
    sleep 15
    az keyvault secret set --vault-name "${PEP_VAULT}" --name "$1" \
      --file "$2" --encoding utf-8 > /dev/null
  fi
}

REDEPLOY=()
for m in "${MEMBERS[@]}"; do
  sn="$(secret_name "${m}")"
  out="${WORK}/${m}"
  mkdir -p "${out}/server"
  had_pair=0

  # SEED --out FROM THE SECRET, so the utility sees the key it certified last
  # time and the pair it issued, and asks for neither again.
  if az keyvault secret show --vault-name "${PEP_VAULT}" --name "${sn}" \
       --query value -o tsv > "${WORK}/${m}.old" 2>/dev/null;
  then
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
  # THE COMPANION'S PATH, with the first member only: the utility's
  # --cluster is what asks it, and its own cluster step creates the cluster
  # when it is not there yet (step 3 then finds it). The members are VMs,
  # so the utility starts no container (REGISTER_PEP_NO_START).
  APP_ARGS=()
  if [ "${PEP_APP}" = "1" ] && [ "${m}" = "${MEMBERS[0]}" ];
  then
    APP_ARGS=(--cluster="${CLUSTER}" --create-cluster --pep-app
              --upstream="http://127.0.0.1:9700"
              --public-base="https://${PEP_HOST}")
  fi
  # As this user (HOST_USER_ARGS), so the files it writes are this user's
  # and the mode-700 directory is writable.
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

  member_json "${out}" > "${WORK}/${m}.new"
  if [ "$(jq -S . "${WORK}/${m}.old" 2>/dev/null)" = "$(jq -S . "${WORK}/${m}.new")" ];
  then
    say "${PEP_VAULT}/${sn}: unchanged"
  else
    put_secret "${sn}" "${WORK}/${m}.new"
    say "${PEP_VAULT}/${sn}: written"
  fi

  if [ -s "${out}/server/pep-server.crt" ];
  then
    [ "${had_pair}" = "0" ] && REDEPLOY+=("${m}")
    # THE IDENTITY SERVICE'S ROOT: the last certificate of the pair's chain
    # (leaf, Issuing CA, Intermediate, Root). Public; the gateway's anchor.
    mkdir -p "$(dirname "${ANCHOR_FILE}")"
    awk '/-----BEGIN CERTIFICATE-----/ { buf = "" } { buf = buf $0 "\n" }
         /-----END CERTIFICATE-----/ { last = buf } END { printf "%s", last }' \
      "${out}/server/pep-server.crt" > "${WORK}/anchor.crt"
    if ! cmp -s "${WORK}/anchor.crt" "${ANCHOR_FILE}" 2>/dev/null;
    then
      cp "${WORK}/anchor.crt" "${ANCHOR_FILE}"
      say "the gateway's anchor written to ${ANCHOR_FILE}: apply the stack again"
    fi
  else
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

# --- 4. Nudging stopped, unless the gateway admits the nudge -----------------
if [ "${NUDGE}" = "0" ];
then
  for m in "${MEMBERS[@]}"; do
    answer="$(api -H 'Content-Type: application/json' \
      -d "$(jq -n --arg m "${m}" '{name: $m}')" "${API}/xacml/disable-pep")"
    if jq -e '.ok' >/dev/null <<<"${answer}";
    then
      say "${m}: nudging stopped; it converges on its poll"
    else
      say "${m}: nudging not stopped yet ($(jq -r '.why // "no answer"' <<<"${answer}"))." \
          "Run this again once it has registered."
    fi
  done
fi

# --- 5. A member that has just been given its pair starts again with it ------
# Its VMs are restarted, so pep-secrets.sh reads the pair at boot; a
# scale set that does not exist yet is skipped (pass 1, before an apply).
for m in "${REDEPLOY[@]}"; do
  vmss="${NAME}-${ENV_NAME}-${m}"
  ids="$(az vmss list-instances --resource-group "${PEP_GROUP}" --name "${vmss}" \
    --query '[].id' -o tsv 2>/dev/null || true)"
  if [ -n "${ids}" ];
  then
    # shellcheck disable=SC2086 # one id per word
    az vm restart --ids ${ids} --no-wait > /dev/null
    say "${vmss}: restarted, to read its listener pair"
  fi
done
say "done."
