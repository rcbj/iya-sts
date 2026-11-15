#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# File: tests/tools/rust-nodefixes-probe.sh
#
# THE NODEFIXES SLICE'S HAND PROBE (#444, phase 5): #26, #28 and #36 over the
# wire, where no whole job reaches them on Rust yet. Run by
# tests/tools/rust-apis-jobs.sh as its E2E_PROBE, against each runtime:
#
#   E2E_PROBE=tests/tools/rust-nodefixes-probe.sh JOB_IMAGE=<tests image> \
#     tests/tools/rust-apis-jobs.sh <node image> <rust image>
#
# called as <label> <base> <api secret>; JOB_IMAGE mints the token.
set -uo pipefail
BASE="$2"; IMG="${JOB_IMAGE:?}"; SECRET="$3"; ID="nfx$RANDOM"; P="nfp$RANDOM"
RED="https://client.nfx.example/cb"
tok() { docker run --rm --network host -e STS_ADMIN_API_CLIENT_SECRET="$SECRET" \
  -e NODE_TLS_REJECT_UNAUTHORIZED=0 "$IMG" node tests/tools/admin-api-token.js "$BASE" 2>/dev/null; }
T="$(tok)"
c() { curl -sk -H "Authorization: Bearer $T" -H 'content-type: application/json' "$@"; }
mk() { c -o /dev/null -w '%{http_code}' -d "{\"id\":\"$1\",\"domain\":\"$1.example.net\",\"name\":\"$1\",\"overrides\":$2}" "$BASE/admin-api/realms/create"; }
echo "create $ID: $(mk "$ID" '{"global.mode":"development","oauth2.accessTokenRequireDpop":true,"est.serverKeyGeneration":false}')"
echo "#28 realm /admin-api/groups with the default realm's bearer, the realm requiring DPoP: $(c -o /dev/null -w '%{http_code}' -D - "$BASE/realm/$ID/admin-api/groups?per=1" | tr -d '\r' | grep -iE '^HTTP|^www-authenticate' | tr '\n' ' ')"
echo "#36 anonymous serverkeygen, the switch off: $(curl -sk -o /dev/null -w '%{http_code}' -H 'content-type: application/pkcs10' --data-binary 'MA==' "$BASE/realm/$ID/.well-known/est/serverkeygen")"
echo "create $P (product): $(mk "$P" '{"global.mode":"product","risk.assessSignIns":false,"oauth2.consentRequired":false}')"
echo "  app: $(c -o /dev/null -w '%{http_code}' -d "{\"identifier\":\"nfx-app\",\"protocols\":[\"oauth2\"],\"fields\":{\"oauthClientId\":\"nfx-app\",\"oauthClientSecret\":\"s3cret-s3cret-s3cret-s3cret\",\"oauthTokenEndpointAuthMethod\":\"client_secret_post\",\"oauthRedirectUri\":[\"$RED\"],\"oauthGrantType\":[\"authorization_code\"]}}" "$BASE/realm/$P/admin-api/applications/create")"
q="response_type=code&scope=openid&client_id=nfx-app&redirect_uri=$(printf %s "$RED" | jq -sRr @uri)&state=s1&nonce=n1&code_challenge=$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=')&code_challenge_method=S256&resource=https%3A%2F%2Fnobody.nfx.example%2Fapi"
echo "#26 product, nobody signed in, unregistered resource at the client's own redirect_uri: $(curl -sk -o /dev/null -w '%{http_code} %{redirect_url}' "$BASE/realm/$P/oauth2/authorize?$q")"
q2="${q//redirect_uri=*&state/redirect_uri=$(printf %s 'https://elsewhere.nfx.example/cb' | jq -sRr @uri)\&state}"
echo "#26 the same at an unregistered redirect_uri (stays a page): $(curl -sk -o /dev/null -w '%{http_code}' "$BASE/realm/$P/oauth2/authorize?$q2")"
