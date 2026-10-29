#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
# create-rcbj-apps-8081.sh — rebuilds, on the port-8081 STS, everything around rcbj0002 and rcbj0003:
#
#   user  rcbj      (uid=rcbj,ou=users) — a password, nothing invented
#   users tester1, tester2 — service accounts, owned by rcbj
#   group group1    holding rcbj
#   role  role1     held by group1 and rcbj0002
#   app   rcbj0003  the resource: an OAuth 2.0 resource server (#1139) that
#                   exposes read and write — never a client, so it holds no
#                   credential and its client_id is refused at the token
#                   endpoint (STS-OAUTH-0985)
#   app   rcbj0002  the confidential OIDC client, granted read and write,
#                   home page and CORS origin https://idptools.com,
#                   client_secret_basic and client_secret_post, and global
#                   consent to openid email profile offline_access read write
#
# rcbj is made an OWNER of tester1, tester2, group1, role1, rcbj0002 and
# rcbj0003 (an owner grants nothing; the portal lists what rcbj owns).
#
# Safe to run again. The two applications and role1 are deleted and recreated
# exactly. The user and the group are created only when absent (/admin-api has
# no delete for either); an existing group1 just gets rcbj added if missing.
# tester1 and tester2 are made service accounts owned by rcbj on every run.
#
#   utilities/create-rcbj-apps-8081.sh
#
# THE SCOPE RULES IT IS WRITTEN TO (#1139, #1140, #1141): an API is an
# application object holding its audience (`oauthAudience`) and the scopes it
# defines (its permissions), and is never a client; a client is a separate
# object GRANTED those permissions (delegated permissions are the client's
# half of "may it ask for this scope"); a token is minted only for an
# audience some application object holds. The admin token below is
# `sts-api-client`'s, the bootstrap client since #1139 — `sts-management-api`
# is the management API's own resource object now.
#
# Overrides (environment):
#   STS_BASE                 default https://localhost:8081
#   ADMIN_API_CLIENT_SECRET  sts-api-client's secret; default: read from
#                            OpenBao with the seeder's operator token
#   STS_BAO_CONTAINER        default sts-openbao
#   STS_BAO_SEED_CONTAINER   default sts-openbao-seed
#   RCBJ0002_SECRET          rcbj0002's client secret. Unset: one is generated
#                            and printed ONCE (no secret is kept in this file)
#   RCBJ_PASSWORD            the user rcbj's password when the user is created.
#                            Unset: one is generated and printed ONCE.
#   TESTER_PASSWORD          tester1's and tester2's password when created.
#                            Unset: each gets one generated, printed ONCE.
#   RCBJ_GIVEN_NAME, RCBJ_SURNAME, RCBJ_MAIL
#                            rcbj's givenName, sn and mail when created.
#                            Unset: the username, and <username>@example.com.
#
# THE ATTRIBUTE POLICY (#396): product mode requires every person to hold uid,
# cn, sn, givenName and mail, so each user is created with all of them; a
# service account gets the username for each name and <name>@example.com.
set -euo pipefail

BASE="${STS_BASE:-https://localhost:8081}"
BAO_CONTAINER="${STS_BAO_CONTAINER:-sts-openbao}"
SEED_CONTAINER="${STS_BAO_SEED_CONTAINER:-sts-openbao-seed}"
RESOURCE=rcbj0003
CLIENT=rcbj0002
USER_NAME=rcbj
SERVICE_ACCOUNTS=(tester1 tester2)
GROUP=group1
ROLE=role1
PERMISSION_BASE="https://rcbj0003.iyasec.io/"
CLIENT_SECRET="${RCBJ0002_SECRET:-}"

need() { command -v "$1" >/dev/null || { echo "needs $1" >&2; exit 1; }; }
need curl; need jq; need openssl

# CYGWIN: the jq and docker found there are usually Windows builds (jq.exe,
# Docker Desktop's docker.exe), which end every line with CRLF. A value taken
# with $(...) then keeps a trailing \r — the operator token, the client secret,
# the access token — and the next request fails with nothing pointing at why.
# Every jq and docker call goes through these, which strip the \r; pipefail
# (set above) keeps the command's own exit status, so `jq -e` still decides.
jq() { command jq "$@" | tr -d '\r'; }
docker() { command docker "$@" | tr -d '\r'; }

ADMIN_SECRET="${ADMIN_API_CLIENT_SECRET:-}"
if [ -z "$ADMIN_SECRET" ]; then
  # The compose stack keeps the secret in OpenBao (secret/sts-admin, field
  # adminApiClientSecret); the file it hands the service is deleted once read.
  # The seeder prints an operator token, good for 24h, on every `docker
  # compose up` — that token reads this one secret and nothing else.
  OPERATOR_TOKEN="$(docker logs "$SEED_CONTAINER" 2>/dev/null |
    grep 'OPERATOR TOKEN' | tail -1 | jq -r .msg | sed -E 's/.*: //')"
  if [ -z "$OPERATOR_TOKEN" ]; then
    echo "no operator token in ${SEED_CONTAINER}'s log; run \`docker compose up\`" \
         "in iya-sts to print a fresh one" >&2
    exit 1
  fi
  ADMIN_SECRET="$(docker exec -e BAO_TOKEN="$OPERATOR_TOKEN" "$BAO_CONTAINER" \
    bao kv get -address=https://127.0.0.1:8200 \
      -ca-cert=/openbao/file/tls/server.crt \
      -field=adminApiClientSecret secret/sts-admin)" || {
    echo "could not read secret/sts-admin from OpenBao (operator token" \
         "expired? run \`docker compose up\` in iya-sts)" >&2
    exit 1
  }
fi

# The service's certificate is issued by its own CA, so -k.
TOKEN="$(curl -sk -u "sts-api-client:${ADMIN_SECRET}" \
  --data-urlencode grant_type=client_credentials \
  --data-urlencode "scope=admin:read admin:write" \
  --data-urlencode "resource=${BASE}/admin-api" \
  "${BASE}/oauth2/token" | jq -r '.access_token // empty')"
[ -n "$TOKEN" ] || { echo "could not get an /admin-api token" >&2; exit 1; }

get() {
  curl -sk -H "Authorization: Bearer ${TOKEN}" "${BASE}/admin-api$1"
}

# post PATH JSON [allow-failure]   — the reply body is left in $REPLY_BODY
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

# --------------------------------------------------------------- the users
# create_user NAME PASSWORD — creates uid=NAME,ou=users when absent; an
# existing entry is left as it is, password unchanged.
create_user() {
  local name="$1" password="$2" given="${3:-$1}" surname="${4:-$1}"
  local mail="${5:-$1@example.com}" dn body pw err attrs cn
  echo "== User ${name}"
  dn="uid=${name},ou=users,dc=example,dc=com"
  if get "/ldap/directory?q=uid%3D${name}&per=50" |
     jq -e --arg dn "$dn" '[.entries[]? | select(.dn == $dn)] | length > 0' >/dev/null; then
    echo "  already there; left as it is (password unchanged)"
    return
  fi
  cn="$given $surname"
  [ "$given" = "$surname" ] && cn="$given"
  attrs="$(jq -n --arg cn "$cn" --arg g "$given" --arg s "$surname" \
    --arg m "$mail" '{cn:$cn, givenName:$g, sn:$s, mail:$m}')"
  if [ -n "$password" ]; then
    body="$(jq -n --arg u "$name" --arg p "$password" --argjson a "$attrs" \
      '{username:$u, invent:false, attributes:$a, credential:"password", password:$p, passwordConfirm:$p}')"
  else
    body="$(jq -n --arg u "$name" --argjson a "$attrs" \
      '{username:$u, invent:false, attributes:$a, credential:"generate"}')"
  fi
  post /users/create "$body"
  pw="$(jq -r '.password // empty' <<<"$REPLY_BODY")"
  [ -n "$pw" ] && echo "  generated password for ${name} (shown once): ${pw}"
  err="$(jq -r '.credentialError // empty' <<<"$REPLY_BODY")"
  [ -n "$err" ] && echo "  WARNING: credential not set: ${err}" >&2
  return 0
}

USER_DN="uid=${USER_NAME},ou=users,dc=example,dc=com"
create_user "$USER_NAME" "${RCBJ_PASSWORD:-}" "${RCBJ_GIVEN_NAME:-}" \
  "${RCBJ_SURNAME:-}" "${RCBJ_MAIL:-}"

# The service accounts. set-service-account's `owners` REPLACES the list the
# account names, so running this again leaves rcbj its one owner.
for sa in "${SERVICE_ACCOUNTS[@]}"; do
  create_user "$sa" "${TESTER_PASSWORD:-}"
  echo "== ${sa}: a service account owned by ${USER_NAME}"
  post /users/set-service-account "$(jq -n --arg u "$sa" --arg o "$USER_NAME" \
    '{user:$u, serviceAccount:true, owners:[$o]}')"
done

# --------------------------------------------------------------- the group
echo "== Group ${GROUP}"
if get "/groups" | jq -e --arg g "$GROUP" '[.groups[]? | select(.cn == $g)] | length > 0' >/dev/null; then
  if get "/ldap/directory?q=${GROUP}&per=50" |
     jq -e --arg g "cn=${GROUP},ou=groups,dc=example,dc=com" --arg m "$USER_DN" \
       '[.entries[]? | select(.dn == $g) | .attributes.member[]? | select(ascii_downcase == ($m|ascii_downcase))] | length > 0' >/dev/null; then
    echo "  already there, with ${USER_NAME} in it"
  else
    post /groups/add-member "$(jq -n --arg g "$GROUP" --arg m "$USER_NAME" '{group:$g, member:$m}')"
  fi
else
  post /groups/create "$(jq -n --arg g "$GROUP" --arg m "$USER_NAME" \
    '{group:$g, note:"group1", members:[$m]}')"
fi

echo "== ${GROUP}: owned by ${USER_NAME}"
post /groups/add-owner "$(jq -n --arg g "$GROUP" --arg o "$USER_NAME" '{group:$g, owner:$o}')"

# ------------------------------------------- the applications (recreated)
echo "== Forgetting any earlier ${CLIENT} and ${RESOURCE} and ${ROLE}"
# A 400 here only means it was not there.
post /roles/delete-role "{\"role\":\"${ROLE}\"}" allow-failure
post /applications/forget "{\"application\":\"${CLIENT}\"}" allow-failure
post /applications/forget "{\"application\":\"${RESOURCE}\"}" allow-failure

echo "== Creating ${RESOURCE} (the resource)"
# KIND oauth2-resource-server (#1139): the audience and the permissions, and
# nothing a client would hold — no auth method, no grant, no redirect URI.
post /applications/create "$(jq -n --arg id "$RESOURCE" --arg aud "${PERMISSION_BASE%/}" '{
  identifier: $id, name: $id, protocols: ["oauth2"],
  kind: "oauth2-resource-server",
  fields: { oauthClientId: $id, oauthAudience: [$aud] } }')"
post /permissions/set-permission-base \
  "$(jq -n --arg r "$RESOURCE" --arg b "$PERMISSION_BASE" '{resource:$r, baseUri:$b}')"
post /permissions/define-permission \
  "$(jq -n --arg r "$RESOURCE" '{resource:$r, name:"read", description:"Read access to rcbj0003"}')"
post /permissions/define-permission \
  "$(jq -n --arg r "$RESOURCE" '{resource:$r, name:"write", description:"Write access to rcbj0003"}')"

echo "== Creating ${CLIENT} (the client)"
if [ -z "$CLIENT_SECRET" ]; then
  CLIENT_SECRET="$(openssl rand -base64 48 | tr -d '\n=+/' | cut -c1-64)"
  echo "  generated client secret for ${CLIENT} (shown once): ${CLIENT_SECRET}"
fi
post /applications/create "$(jq -n --arg id "$CLIENT" --arg secret "$CLIENT_SECRET" \
  --arg pb "$PERMISSION_BASE" '{
  identifier: $id, name: $id, protocols: ["oauth2", "oidc"],
  fields: {
    oauthClientId: $id,
    oauthClientSecret: $secret,
    oauthConfidential: "TRUE",
    oauthTokenEndpointAuthMethod: ["client_secret_basic", "client_secret_post"],
    oauthRedirectUri: ["https://idptools.com/callback"],
    oauthPostLogoutRedirectUri: ["https://idptools.com/logout"],
    oauthGrantType: ["authorization_code", "refresh_token"],
    oauthResponseType: ["code"],
    oauthAllowedScope: ["openid", "profile", "email",
                        ($pb + "read"), ($pb + "write"), "offline_access"],
    appHomePageUrl: "https://idptools.com",
    appCorsOrigin: ["https://idptools.com"],
    appRequiredRole: ["EVERYBODY"] } }')"

# THE GRANT IS THE CLIENT'S HALF (#1141): rcbj0002 may ask for read and
# write because it holds these delegated permissions on rcbj0003.
echo "== Granting ${CLIENT} read and write on ${RESOURCE}"
for p in read write; do
  post /permissions/grant-permission \
    "$(jq -n --arg c "$CLIENT" --arg p "${PERMISSION_BASE}${p}" '{client:$c, permission:$p}')"
done

echo "== Global consent on ${CLIENT} (nobody is asked about these scopes)"
for scope in openid email profile offline_access \
             "${PERMISSION_BASE}read" "${PERMISSION_BASE}write"; do
  post /consent/grant-global-consent \
    "$(jq -n --arg c "$CLIENT" --arg s "$scope" '{client:$c, scope:$s}')"
done

# ---------------------------------------------------------------- the role
echo "== Role ${ROLE}"
post /roles/create-role "$(jq -n --arg r "$ROLE" \
  '{role:$r, description:"role1", displayName:"role1"}')"
post /roles/add-member "$(jq -n --arg r "$ROLE" --arg m "$GROUP" '{role:$r, kind:"group", member:$m}')"
# rcbj0002 only: a role is held by a subject, and rcbj0003 is a resource,
# never the subject of a token (#1139).
post /roles/add-member "$(jq -n --arg r "$ROLE" --arg m "$CLIENT" '{role:$r, kind:"application", member:$m}')"

# -------------------------------------------------------------- the owners
# The role and both applications were just recreated, so each is given its
# owner here; add-owner on one already listed is ok with changed: false.
echo "== Owners: ${USER_NAME} owns ${ROLE}, ${CLIENT} and ${RESOURCE}"
post /roles/add-owner "$(jq -n --arg r "$ROLE" --arg o "$USER_NAME" '{role:$r, owner:$o}')"
for app in "$CLIENT" "$RESOURCE"; do
  post /applications/add-owner "$(jq -n --arg a "$app" --arg o "$USER_NAME" '{application:$a, owner:$o}')"
done

# ------------------------------------------------------------- read-back
echo "== Done."
echo "-- ${CLIENT} holds:"
get "/applications?application=${CLIENT}" | jq -r '.fields.oauthDelegatedPermission[]'
echo "-- ${ROLE}:"
get "/roles" | jq -c --arg r "$ROLE" '.roles[] | select(.name == $r) | {groups, applications, users}'
