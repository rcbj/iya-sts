# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
# shellcheck shell=bash
#
# File: deploy/azure/node-init/lib.sh
#
# Key Vault over REST, with the VM's own managed identity — what both
# commands in this image share. Sourced, never run. deploy/gcp/node-init/
# lib.sh's four functions, against Key Vault's API.
#
#   STS_VAULT_URL     https://<vault>.vault.azure.net (no trailing slash)
#   AZURE_CLIENT_ID   the node identity's client id: the VM has one
#                     user-assigned identity, and naming it means the
#                     metadata endpoint never has to choose

IMDS="http://169.254.169.254/metadata/identity/oauth2/token"
KV_API="api-version=7.5"

# The node identity's token for Key Vault, from the instance metadata
# endpoint. Fetched per call: a token lasts an hour and these commands take
# seconds, except an ACME issuance, which is why it is not cached.
sts_token() {
  curl -fsS -H Metadata:true \
    "${IMDS}?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net&client_id=${AZURE_CLIENT_ID}" |
    jq -r .access_token
}

# The current value of secret <name>, on stdout. Exit 3 when there is no
# such secret, or its current version is disabled (a 404 or a 403
# Forbidden-by-state); any other failure non-zero — the caller tells "not
# issued yet" from "broken".
sts_secret_read() {
  local name="$1" out code
  out="$(mktemp)"
  code="$(curl -sS -o "${out}" -w '%{http_code}' \
    -H "Authorization: Bearer $(sts_token)" \
    "${STS_VAULT_URL}/secrets/${name}?${KV_API}")" || {
      rm -f "${out}"
      return 1
    }
  case "${code}" in
    200)
      jq -j .value "${out}"
      rm -f "${out}"
      return 0
      ;;
    404)
      rm -f "${out}"
      return 3
      ;;
    *)
      echo "sts-init: reading ${name} answered HTTP ${code}:" >&2
      cat "${out}" >&2
      rm -f "${out}"
      return 1
      ;;
  esac
}

# A new version of <name> holding the file <path>; prints the new version's
# id (https://<vault>/secrets/<name>/<version>).
sts_secret_add() {
  local name="$1" path="$2"
  jq -n --rawfile v "${path}" \
    '{ value: $v, contentType: "application/x-pem-file" }' |
    curl -fsS -X PUT \
      -H "Authorization: Bearer $(sts_token)" \
      -H 'Content-Type: application/json' \
      --data @- \
      "${STS_VAULT_URL}/secrets/${name}?${KV_API}" | jq -r .id
}

# Every ENABLED version of <name> except <keep> is disabled: the old key can
# no longer be read, and a disabled version costs nothing. Follows the
# listing's `nextLink` pages.
sts_secret_disable_others() {
  local name="$1" keep="$2" url v
  url="${STS_VAULT_URL}/secrets/${name}/versions?${KV_API}"
  while [ -n "${url}" ] && [ "${url}" != "null" ]; do
    page="$(curl -fsS -H "Authorization: Bearer $(sts_token)" "${url}")"
    for v in $(printf '%s' "${page}" |
               jq -r '.value[]? | select(.attributes.enabled) | .id');
    do
      [ "${v}" = "${keep}" ] && continue
      curl -fsS -X PATCH -H "Authorization: Bearer $(sts_token)" \
        -H 'Content-Type: application/json' \
        --data '{ "attributes": { "enabled": false } }' \
        "${v}?${KV_API}" > /dev/null
      echo "sts-cert: disabled ${v}."
    done
    url="$(printf '%s' "${page}" | jq -r '.nextLink // empty')"
  done
}
