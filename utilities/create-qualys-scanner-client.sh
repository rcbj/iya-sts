#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
# create-qualys-scanner-client.sh — a READ-ONLY client for an authenticated
# Qualys WAS scan of /admin-api (rcbj, 2026-11-10).
#
# The first scan of test-idp.iyasec.io reached /admin-api ~60,000 times and was
# answered 401 every time: it tested the gate, not the operations. This makes
# the client a scanner signs in as, and nothing more:
#
#   app   qualys-scanner  a confidential OAuth 2.0 client on client_credentials
#                         only (no redirect URI, no ID Token), secret by
#                         client_secret_basic or client_secret_post
#   grant urn:sts:admin-api:admin:read on sts-management-api (#1141), the
#         delegated permission that lets it ASK for admin:read
#   role  ADMIN_READ      which AUTHORIZES admin:read (#302, #303): without it
#                         the scope is not issued
#
# NOT admin:write, admin:security or report:use, and not Admin Write: a scanner
# sends hostile input to every operation it finds, and with write it would
# create, change and delete for real. Read-only, it probes every GET.
#
# Safe to run again: the client is forgotten and recreated, so each run
# issues a NEW secret, printed ONCE (no secret is kept in this file).
#
#   utilities/create-qualys-scanner-client.sh
#
# Overrides (environment):
#   STS_BASE                 default https://localhost:8081
#   ADMIN_API_CLIENT_SECRET  sts-api-client's secret; default: read from
#                            OpenBao with the seeder's operator token, as
#                            create-rcbj-apps-8081.sh does. On test-idp it is
#                            Secrets Manager's iya-sts/testidp/admin-api-client-secret
#   STS_BAO_CONTAINER        default sts-openbao
#   STS_BAO_SEED_CONTAINER   default sts-openbao-seed
#   SCANNER_CLIENT_ID        default qualys-scanner
#
# AT THE END it proves what it made: a token for admin:read is issued and
# reads /admin-api; one asked for admin:write is refused that scope; and the
# read token is refused a write (403).
set -euo pipefail

BASE="${STS_BASE:-https://localhost:8081}"
BAO_CONTAINER="${STS_BAO_CONTAINER:-sts-openbao}"
SEED_CONTAINER="${STS_BAO_SEED_CONTAINER:-sts-openbao-seed}"
CLIENT="${SCANNER_CLIENT_ID:-qualys-scanner}"
READ_PERMISSION="urn:sts:admin-api:admin:read"
ROLE=ADMIN_READ

need() { command -v "$1" >/dev/null || { echo "needs $1" >&2; exit 1; }; }
need curl; need jq; need openssl

# CYGWIN: a Windows jq or docker ends every line with CRLF
# (create-rcbj-apps-8081.sh argues it).
jq() { command jq "$@" | tr -d '\r'; }
docker() { command docker "$@" | tr -d '\r'; }

ADMIN_SECRET="${ADMIN_API_CLIENT_SECRET:-}"
if [ -z "$ADMIN_SECRET" ]; then
  OPERATOR_TOKEN="$(docker logs "$SEED_CONTAINER" 2>/dev/null |
    grep 'OPERATOR TOKEN' | tail -1 | jq -r .msg | sed -E 's/.*: //')"
  if [ -z "$OPERATOR_TOKEN" ]; then
    echo "no operator token in ${SEED_CONTAINER}'s log; run \`docker compose up\`" \
         "in iya-sts to print a fresh one, or set ADMIN_API_CLIENT_SECRET" >&2
    exit 1
  fi
  ADMIN_SECRET="$(docker exec -e BAO_TOKEN="$OPERATOR_TOKEN" "$BAO_CONTAINER" \
    bao kv get -address=https://127.0.0.1:8200 \
      -ca-cert=/openbao/file/tls/server.crt \
      -field=adminApiClientSecret secret/sts-admin)" || {
    echo "could not read secret/sts-admin from OpenBao" >&2
    exit 1
  }
fi

# token CLIENT SECRET SCOPE — the whole token response.
token() {
  curl -sk -u "$1:$2" \
    --data-urlencode grant_type=client_credentials \
    --data-urlencode "scope=$3" \
    --data-urlencode "resource=${BASE}/admin-api" \
    "${BASE}/oauth2/token"
}

TOKEN="$(token sts-api-client "$ADMIN_SECRET" "admin:read admin:write" |
  jq -r '.access_token // empty')"
[ -n "$TOKEN" ] || { echo "could not get an /admin-api token" >&2; exit 1; }

# post PATH JSON [allow-failure]
post() {
  local reply status
  reply="$(curl -sk -w '\n%{http_code}' -X POST \
    -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' \
    --data "$2" "${BASE}/admin-api$1")"
  status="${reply##*$'\n'}"; REPLY_BODY="${reply%$'\n'*}"
  if [ "${3:-}" != "allow-failure" ] &&
     { [ "$status" != 200 ] || [ "$(jq -r '.ok' <<<"$REPLY_BODY")" = false ]; }; then
    echo "FAILED $1 ($status): $REPLY_BODY" >&2; exit 1
  fi
  echo "  $1 -> $status"
}

echo "== Forgetting any earlier ${CLIENT}"
# THE ROLE FIRST: forgetting an application does not take it out of the roles
# it held (common/applications.js deleteApplication(), 2026-11-10), and a role
# names its member by identifier, so a client made again under this name would
# find itself still in ADMIN_READ — and add-member would refuse it as
# "already holds". A 400 on either line only means it was not there.
post /roles/remove-member "$(jq -n --arg r "$ROLE" --arg m "$CLIENT" \
  '{role:$r, kind:"application", member:$m}')" allow-failure
post /applications/forget "$(jq -n --arg a "$CLIENT" '{application:$a}')" allow-failure

echo "== Creating ${CLIENT} (client_credentials, admin:read only)"
SECRET="$(openssl rand -base64 48 | tr -d '\n=+/' | cut -c1-64)"
post /applications/create "$(jq -n --arg id "$CLIENT" --arg secret "$SECRET" '{
  identifier: $id, name: "Qualys WAS scanner (read-only)", protocols: ["oauth2"],
  fields: {
    oauthClientId: $id,
    oauthClientSecret: $secret,
    oauthConfidential: "TRUE",
    oauthTokenEndpointAuthMethod: ["client_secret_basic", "client_secret_post"],
    oauthGrantType: ["client_credentials"],
    oauthAllowedScope: ["admin:read"] } }')"

echo "== Granting ${CLIENT} admin:read on sts-management-api"
post /permissions/grant-permission "$(jq -n --arg c "$CLIENT" \
  --arg p "$READ_PERMISSION" '{client:$c, permission:$p}')"

echo "== ${CLIENT} into ${ROLE}"
post /roles/add-member "$(jq -n --arg r "$ROLE" --arg m "$CLIENT" \
  '{role:$r, kind:"application", member:$m}')"

# --------------------------------------------------------------- the proof
echo "== Proving it"
READ="$(token "$CLIENT" "$SECRET" "admin:read")"
READ_TOKEN="$(jq -r '.access_token // empty' <<<"$READ")"
[ -n "$READ_TOKEN" ] || { echo "FAILED: no admin:read token: $READ" >&2; exit 1; }
echo "  admin:read issued (scope: $(jq -r '.scope // ""' <<<"$READ"))"

status="$(curl -sk -o /dev/null -w '%{http_code}' \
  -H "Authorization: Bearer ${READ_TOKEN}" "${BASE}/admin-api/applications")"
[ "$status" = 200 ] || { echo "FAILED: a read answered ${status}" >&2; exit 1; }
echo "  GET /admin-api/applications -> 200"

WRITE="$(token "$CLIENT" "$SECRET" "admin:write")"
if jq -e '.access_token and ((.scope // "") | split(" ") | index("admin:write"))' \
     <<<"$WRITE" >/dev/null; then
  echo "FAILED: admin:write was issued to ${CLIENT}" >&2; exit 1
fi
echo "  admin:write refused ($(jq -r '.error // ("scope: " + (.scope // ""))' <<<"$WRITE"))"

# A write the read token must not be allowed; the body names a role that is
# not there, so even a wrongly admitted call would change nothing.
status="$(curl -sk -o /dev/null -w '%{http_code}' -X POST \
  -H "Authorization: Bearer ${READ_TOKEN}" -H 'Content-Type: application/json' \
  --data '{"role":"qualys-scanner-probe-not-a-role"}' \
  "${BASE}/admin-api/roles/delete-role")"
[ "$status" = 403 ] || { echo "FAILED: a write with the read token answered ${status}" >&2; exit 1; }
echo "  POST /admin-api/roles/delete-role with it -> 403"

cat <<EOF
== Done. For the Qualys WAS authentication record (OAuth 2.0, Client Credentials):
  Token URL:      ${BASE}/oauth2/token
  Client ID:      ${CLIENT}
  Client secret:  ${SECRET}   (shown once; run this again for a new one)
  Scope:          admin:read
  Extra parameter: resource=${BASE}/admin-api   (the token's audience)
  Client authentication: client_secret_basic (HTTP Basic) or client_secret_post
EOF
