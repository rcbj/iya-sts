#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
# Creates the regular (non-admin) user walletuser1 on the 8081 STS for the
# eudi-dev wallet run, with a generated password printed once. Same token
# path as ../create-rcbj-apps-8081.sh. Safe to run again: an existing user is
# left alone.
set -euo pipefail
# Under Cygwin (#512), the shim that takes the CR off what docker.exe prints,
# so the secret read back from it is the secret; nothing on Linux.
. "$(dirname "$0")/../tools/host-platform.sh"
BASE="${STS_BASE:-https://localhost:8081}"
NAME="${WALLET_USER:-walletuser1}"

OT="$(docker logs sts-openbao-seed 2>/dev/null | grep 'OPERATOR TOKEN' | tail -1 |
  jq -r .msg | sed -E 's/.*: //')"
[ -n "$OT" ] || { echo "no operator token in sts-openbao-seed's log" >&2; exit 1; }
SECRET="$(docker exec -e BAO_TOKEN="$OT" sts-openbao bao kv get \
  -address=https://127.0.0.1:8200 -ca-cert=/openbao/file/tls/server.crt \
  -field=adminApiClientSecret secret/sts-admin)"
TOKEN="$(curl -sk -u "sts-management-api:${SECRET}" \
  --data-urlencode grant_type=client_credentials \
  --data-urlencode "scope=admin:read admin:write" \
  --data-urlencode "resource=${BASE}/admin-api" \
  "${BASE}/oauth2/token" | jq -r '.access_token // empty')"
[ -n "$TOKEN" ] || { echo "could not get an /admin-api token" >&2; exit 1; }

DN="uid=${NAME},ou=users,dc=example,dc=com"
if curl -sk -H "Authorization: Bearer ${TOKEN}" \
     "${BASE}/admin-api/ldap/directory?q=uid%3D${NAME}&per=50" |
   jq -e --arg dn "$DN" '[.entries[]? | select(.dn == $dn)] | length > 0' >/dev/null; then
  echo "${NAME} already exists; password unchanged"
  exit 0
fi
curl -sk -X POST -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' \
  --data "$(jq -n --arg u "$NAME" '{username:$u, invent:false, credential:"generate"}')" \
  "${BASE}/admin-api/users/create" |
  jq '{ok, username: (.username // null), password: (.password // null), credentialError: (.credentialError // null)}'
