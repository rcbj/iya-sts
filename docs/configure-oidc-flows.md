---
title: "Configuring OpenID Connect flows"
---

# Configuring OpenID Connect flows

This page shows how to set up iya-sts, as an OpenID Provider, for each
OpenID Connect flow and each related specification it supports. For each one
it covers the relying party (RP) to register, the settings to change, and the
request the RP then sends. Each recipe is given twice: once as steps in the
**admin console** and once as **Management API** calls.

The values come from this repository's test jobs in `tests/vendored/`, and
each recipe names the job it is taken from.
[Configuring OAuth 2.0 grants](configure-oauth2-grants.md#before-you-start)
explains the shared mechanics: the API token, the `api` shell helper used
below, the console's **Set** / **Add to** / **Remove from** forms, and what
development and product mode change. Read that section first. The OAuth 2.0
grants themselves (code, refresh, client credentials, device, CIBA, token
exchange and the assertion grants) are on that page too.

* TOC
{:toc}

## Two things to know first

**A client is held to the response types and grant types it declares.**
`oauthResponseType` and `oauthGrantType` are the lists, whether a dynamic
registration wrote them (`POST /oauth2/register`, RFC 7591 `response_types`
and `grant_types`) or an administrator set them in the console or through
`/admin-api`. A response type or grant not on a list is refused with
`unauthorized_client`, in both modes. An empty list restricts nothing, so a
client with neither list may use every response type the server advertises.
Write each response type as one value, its words separated by spaces
(`code id_token`). What a client has actually used is recorded separately, in
`oauthResponseTypeObserved` and `oauthGrantTypeObserved`.

**Some client metadata exists only as registration members.** That includes
the JARM algorithms, the signing and encryption algorithms for UserInfo and
the ID Token, and `default_acr_values` / `default_max_age`. No console or API
attribute holds them, so a client that needs them must use dynamic
registration.

**Consent is on by default.** Unless the person has already approved the
client, the flow stops at `/oauth2/consent`. For a first-party client, grant
consent for everybody in advance. In the console that is **Consent**
(`/admin/consent`) → **Consent a scope for everybody** → pick the
**Application**, type the **Scope**, then **Consent it for everybody**. The
API call is:

```bash
api consent/grant-global-consent '{"client":"parmon-a","scope":"openid"}'
```

## The rules that hold for every flow

Every authorization request, in every mode, must follow these rules:
* `redirect_uri` is required, and must match a registered URI exactly when
  the client has any.
* A response type that returns an `id_token` needs the `openid` scope and a
  `nonce`.
* The implicit flow refuses an `http` redirect URI that is not a loopback
  address.

Product mode adds more: it refuses an unregistered client, it requires PKCE
`S256` from a public client, and it refuses any response type that contains
`token`. See
[OAuth 2.0 and OpenID Connect → development and product mode](oauth-oidc.md).

## Authorization Code flow

`response_type=code`. The RP exchanges the code at `/oauth2/token`. PKCE
accepts `S256` and, in development only, `plain`.

Taken from `sts_oauth2_monitor.js` and `sts_oidc_core.js`.

**Console:**
1. Go to **Directory → Applications → New application ›**. Set **Identifier** to `parmon-a`.
2. Tick **OAuth 2.0** and **OpenID Connect**.
3. Fill in the fields that appear:
   - `oauthClientId`: `parmon-a`.
   - **Where responses go back to**: `https://rp.parmon.example.test/cb`.
   - **The client secret**: click **Generate Secret**.
4. Click **Create the application**.
5. On the application's page, **Tick** `client_secret_basic` under `oauthTokenEndpointAuthMethod`, and nothing else.
6. Grant consent for `openid` on **Consent**, as described above.

**API:**
```bash
api applications/create '{"identifier":"parmon-a","name":"parmon-a",
  "protocols":["oauth2","oidc"],
  "fields":{"oauthClientId":"parmon-a",
            "oauthRedirectUri":["https://rp.parmon.example.test/cb"],
            "oauthClientSecret":"'"$SECRET"'",
            "oauthTokenEndpointAuthMethod":"client_secret_basic"}}'
api consent/grant-global-consent '{"client":"parmon-a","scope":"openid"}'
```

**Requests:**
```
GET /oauth2/authorize?response_type=code&client_id=parmon-a
    &redirect_uri=https://rp.parmon.example.test/cb&scope=openid
    &state=<random>&nonce=<random>
    &code_challenge=<S256 challenge>&code_challenge_method=S256

POST /oauth2/token        (HTTP Basic: parmon-a / secret)
  grant_type=authorization_code&code=<code>
  &redirect_uri=https://rp.parmon.example.test/cb&code_verifier=<verifier>
```

The authorization request can also be sent as a form `POST`. For a public
client, see [the public-client recipe](configure-oauth2-grants.md#a-public-client-a-browser-or-native-app).

## Implicit flow

`response_type=id_token` or `id_token token`. The response is always
returned in the fragment, and an explicit `response_mode=query` is refused.

* **`id_token`** works in every mode and needs no configuration beyond a
  registered redirect URI. The job `sts_oidc_core.js` sends
  `response_type=id_token&scope=openid email&nonce=<random>`, and with
  `id_token` alone the scope's claims go into the ID Token.
* **`id_token token`**, and any other type containing `token`, is refused in
  RFC 9700 mode and in product mode. In those modes it is also removed from
  `response_types_supported`. To use it you need development mode with
  `oauth2.rfc9700` off.

A client that registers itself must list `implicit` in `grant_types`
whenever one of its `response_types` contains `token`.

## Hybrid flow

`code id_token`, `code token` and `code id_token token`. The ID Token carries
`c_hash` and `at_hash`, plus `s_hash` when a `state` was sent. The response
goes in the fragment. `code id_token` and `code id_token token` require a
`nonce`.

* **`code id_token`** works in every mode. The job `sts_oidc_core.js` runs it
  across `id_token_signed_response_alg` values `RS256`, `RS384`, `PS512`,
  `ES512`, `EdDSA` and `ML-DSA-44`. That algorithm is a registration member,
  so those clients are registered dynamically.
* **`code token`** and **`code id_token token`** are refused in RFC 9700 mode
  and product mode.

The OpenID conformance job (`sts_oidcc_conformance.js`) registers its hybrid
client like this, after setting `oauth2.openRegistration` to `true` in the
realm:

```
POST /realm/<id>/oauth2/register
{"redirect_uris":["https://rp.example.com/callback"],
 "token_endpoint_auth_method":"client_secret_basic",
 "grant_types":["authorization_code","refresh_token","implicit"],
 "response_types":["code id_token token"],
 "scope":"openid profile email address phone offline_access"}
```

## Response modes: query, fragment, form_post, JARM

| `response_mode` | Configuration | Notes |
|---|---|---|
| `query` | none | The default for `code` and `none`. |
| `fragment` | none | The default for everything else. |
| `form_post` | none | Answers with a self-submitting form (`/oauth2/autopost.js`) that also has a real submit button. Refused to a private-use (native) redirect URI. |
| `jwt`, `query.jwt`, `fragment.jwt`, `form_post.jwt` (JARM) | optional registration members `authorization_signed_response_alg` (default `RS256`), `authorization_encrypted_response_alg` and `_enc` | Works in every mode. `query.jwt` carrying a token is refused unless the response is encrypted. `oauth2.jarmResponseLifetimeS` defaults to 600. |

Taken from `sts_form_post.js`, which sets `oauth2.openRegistration` and
`oauth2.rfc9700` to `true` in its realm and registers:

```
POST /realm/<id>/oauth2/register
{"redirect_uris":["https://rp.formpost.example/cb"],"grant_types":["authorization_code"],
 "response_types":["code"],"token_endpoint_auth_method":"client_secret_basic"}
```

## UserInfo and the claims parameter

`GET` or `POST /oauth2/userinfo` takes the access token from an
`Authorization: Bearer` or `DPoP` header, or as `access_token` in a form body.
The token must carry the `openid` scope, or the answer is 403
`insufficient_scope`.

* **Which claims are released** is set per scope on **Protocols → OAuth2 /
  OIDC → UserInfo claims** (`/admin/userinfo-claims`) and **Claims**
  (`/admin/claims`). Product mode takes every value from the person's
  directory entry, so fill the entry in:
  ```bash
  api users/create '{"username":"alice","invent":false,"credential":"password",
    "password":"<password>","attributes":{"cn":"Alice Example","givenName":"Alice",
    "sn":"Example","mail":"alice@example.com","telephoneNumber":"+1 555 0100",
    "street":"1 Main St","l":"Springfield","postalCode":"12345","c":"US"}}'
  ```
  (These attributes are the ones `sts_oidc_core.js` creates.)
* **Signed or encrypted UserInfo** is chosen by the registration members
  `userinfo_signed_response_alg` and `userinfo_encrypted_response_alg`. The
  job for this is `sts_userinfo_protected.js`.
* **`claims=`** (OIDC Core 5.5) needs no configuration. `essential`, `value`
  and `values` are carried through but not enforced, except that an essential
  `acr` is enforced, and so is anything inside `verified_claims`.
  `oauth2.maxRequestedClaims` (default 64) caps the size of the request.

## Pushed Authorization Requests

The RP POSTs its authorization request to `/oauth2/par`, authenticating as it
would at the token endpoint. The answer is a `request_uri`, which the RP then
uses at `/oauth2/authorize`. PAR is on by default.

**Settings** (on `/admin/oauth2`):

| Setting | Default | What it does |
|---|---|---|
| `oauth2.pushedAuthorizationRequests` | `true` | Serves the endpoint; `false` makes it answer 404. |
| `oauth2.requirePushedAuthorizationRequests` | `false` | Refuses a plain authorization request from every client. |
| `oauth2.parRequestUriLifetimeS` | `60` | Sets how long a `request_uri` is valid. |

**To require PAR from one client only:**
```bash
api applications/set '{"application":"parmon-a",
  "attribute":"oauthRequirePushedAuthorizationRequests","value":"TRUE"}'
```

**Requests** (from `sts_oauth2_monitor.js`, with the `parmon-a` client above):
```
POST /oauth2/par      (HTTP Basic)
  response_type=code&redirect_uri=https://rp.parmon.example.test/cb&scope=openid
  &state=…&nonce=…&code_challenge=…&code_challenge_method=S256
→ 201 {"request_uri":"urn:ietf:params:oauth:request_uri:…","expires_in":60}

GET /oauth2/authorize?client_id=parmon-a&request_uri=urn:ietf:params:oauth:request_uri:…
```

Development mode only logs a failed client authentication at PAR. RFC 9700,
OAuth 2.1 and product mode refuse it.

## Request objects (JAR)

`request=<JWT>` or `request_uri=<URL>`. A `request_uri` is fetched only if it
is registered on the client, so add each one:

```bash
api applications/add '{"application":"parmon-a","attribute":"oauthRequestUri",
  "value":"https://rp.parmon.example.test/request.jwt"}'
api applications/set '{"application":"parmon-a","attribute":"oauthJwksUri",
  "value":"https://rp.parmon.example.test/jwks.json"}'
```

These attributes also apply:
* `oauthRequestObjectSigningAlg`, and `oauthRequestObjectEncryptionAlg` / `…Enc` for an encrypted object.
* `oauthRequireSignedRequestObject` set to `TRUE`, which requires a signed object from this client.
* The client's keys, in `oauthJwks` or `oauthJwksUri`.

The realm settings `oauth2.requireSignedRequestObject`,
`oauth2.requireRequestObjectType` and
`oauth2.requireRequestObjectIssuerAudience` (all `false` by default) apply the
same checks to every client. Development mode accepts an `http` request URI
and an `alg: none` object. Product mode refuses both. The job that covers this
is `tests/rfc9101_request_objects.js`, which signs with `ES256` and
`typ: oauth-authz-req+jwt`.

## CIBA

The whole recipe is on [Configuring OAuth 2.0 grants → CIBA](configure-oauth2-grants.md#ciba).
Here is what differs between the three delivery modes (from `sts_ciba.js`):

| Delivery mode | Client attributes |
|---|---|
| `poll` | `oauthBackchannelTokenDeliveryMode`: `poll` |
| `ping` | `…DeliveryMode`: `ping`, and `oauthBackchannelClientNotificationEndpoint`: `https://client.example.com/ping` |
| `push` | `…DeliveryMode`: `push`, and the notification endpoint (refused under any FAPI profile) |

These attributes can be set only on a client declared for **OpenID Connect**.
Setting `oauthBackchannelAuthenticationRequestSigningAlg` requires the client
to send a signed `request`. Ping and push deliveries are listed on
**Outbound deliveries** (`/admin/deliveries`).

## Native SSO

Native SSO lets apps from one vendor on one device share a sign-in. The first
app gets a `device_secret`, and the others exchange it together with the ID
Token. There is no setting to turn it on or off. A client takes part when it
has the flag and a group.

Taken from `sts_native_sso.js`.

**Console:** create a public client (see
[the public-client recipe](configure-oauth2-grants.md#a-public-client-a-browser-or-native-app))
declared for **OpenID Connect**. Then, on its page:
- **Set** `oauthNativeSso` to `TRUE`.
- **Set** `oauthNativeSsoGroup` to `vendor.one`.

**API:**
```bash
api applications/create '{"identifier":"nsso-first","name":"nsso-first",
  "protocols":["oauth2","oidc"],
  "fields":{"oauthClientId":"nsso-first","oauthTokenEndpointAuthMethod":"none",
            "oauthConfidential":"FALSE",
            "oauthRedirectUri":["https://nsso-first.example.test/cb"],
            "oauthResponseType":["code"],
            "oauthGrantType":["authorization_code","refresh_token",
                              "urn:ietf:params:oauth:grant-type:token-exchange"],
            "oauthScope":["openid","device_sso"],
            "oauthNativeSso":"TRUE","oauthNativeSsoGroup":"vendor.one"}}'
```

Create the second app, `nsso-second`, the same way with the same group. Only
apps in the same group share sessions.

**Requests:**
```
1. First app:  /oauth2/authorize?response_type=code&scope=openid device_sso&…(PKCE, nonce)
               → token response includes device_secret; ID Token carries ds_hash and sid
2. Second app: POST /oauth2/token
                 grant_type=urn:ietf:params:oauth:grant-type:token-exchange
                 &client_id=nsso-second
                 &subject_token=<id_token>&subject_token_type=urn:ietf:params:oauth:token-type:id_token
                 &actor_token=<device_secret>&actor_token_type=urn:openid:params:token-type:device-secret
                 &audience=<issuer>&scope=openid
```

If a client without the flag asks for `device_sso`, it gets `invalid_scope`.
An exchange across groups gets `unauthorized_client`. A dynamic registration
may set `native_sso` only inside a trusted software statement.

## RP-Initiated Logout

The RP sends the person to `GET` or `POST /oauth2/logout` with
`post_logout_redirect_uri`, `id_token_hint` or `client_id`, and `state`.

**The return address must be registered.** In the console, use **Where a
sign-out goes** on the new-application form, or **Add to**
`oauthPostLogoutRedirectUri` on an existing client. Through the API:

```bash
api applications/add '{"application":"parmon-a",
  "attribute":"oauthPostLogoutRedirectUri","value":"https://rp.rplogout.example/signed-out"}'
```

**Request** (from `sts_rp_initiated_logout.js`):
```
GET /oauth2/logout?client_id=parmon-a
    &post_logout_redirect_uri=https://rp.rplogout.example/signed-out&state=st-1
→ 302 https://rp.rplogout.example/signed-out?state=st-1
```

If the client has registered return URIs, the request must match one exactly,
in every mode. If it has registered none, development mode follows the
return anyway, and product and OAuth 2.1 mode never do. A request that names
no client is never redirected. If there is no `id_token_hint` whose `sid`
matches the current session, the person sees a confirmation page first. A
return that is refused still signs the person out.

## Front-Channel Logout

When a session ends, the logout page loads each RP's front-channel URI in a
hidden iframe. It then moves on to the return address after
`oauth2.frontchannelLogoutWaitS` seconds.

**Settings:** `oauth2.frontchannelLogout` (default `true`) and
`oauth2.frontchannelLogoutWaitS` (default `3`, range 0–60).

**Client** (on its page, or through the API; the values are from
`sts_frontchannel_logout.js`):
```bash
api applications/set '{"application":"parmon-a","attribute":"oauthFrontchannelLogoutUri",
  "value":"https://rp.parmon.example.test/fc"}'
api applications/set '{"application":"parmon-a",
  "attribute":"oauthFrontchannelLogoutSessionRequired","value":"TRUE"}'
```

**The URI must be on the origin of one of the client's redirect URIs.** A URI
on any other origin is refused with 400. With `…SessionRequired` set to
`TRUE`, the service appends `iss` and `sid` to the URI.

## Back-Channel Logout

When a session ends or expires, the service POSTs a signed Logout Token
(`logout_token=…`) to each RP's back-channel URI. Each delivery is stored,
retried and, if it keeps failing, dead-lettered.

**Settings:** `oauth2.backchannelLogout` (default `true`) and
`oauth2.backchannelLogoutOnExpiry` (default `true`). There are also tuning
settings such as `…TokenTtlS` (120), `…Attempts` (3) and `…TimeoutMs` (5000).

**Client** (from the in-process job `tests/backchannel_logout.js`):
```bash
api applications/create '{"identifier":"bcl-ok","name":"bcl-ok","protocols":["oauth2","oidc"],
  "fields":{"oauthClientId":"bcl-ok","oauthClientSecret":"'"$SECRET"'",
            "oauthRedirectUri":["https://rp.backchannel.example/cb"],
            "oauthGrantType":["authorization_code"],
            "oauthTokenEndpointAuthMethod":"client_secret_basic",
            "oauthBackchannelLogoutUri":"https://rp.backchannel.example/bcl",
            "oauthBackchannelLogoutSessionRequired":"TRUE"}}'
```

A public client cannot have an `http` back-channel URI, and product mode never
sends to `http`. Failed deliveries are listed on **Sign-out**
(`/admin/logout`) → **Back-channel Logout Tokens**, which has a State filter
and a **Retry** button on each dead row, and on **Outbound deliveries**
(`/admin/deliveries`). The API equivalents are
`GET /admin-api/logout?deliveryState=dead` and
`POST /admin-api/logout/retry-backchannel {"delivery":"<id>"}`.

## Session Management

The OP iframe (`/oauth2/check_session`) and `session_state` on each
authentication response. It is **off by default** and needs only a setting;
no client attributes are involved.

```bash
api config/set '{"key":"oauth2.sessionManagement","value":true}'
```

Once it is on, `check_session_iframe` appears in discovery. Only the
redirect-URI origins registered in the realm may frame the iframe. Browsers
that block third-party cookies never send the cookie the iframe reads.
`sts_session_management.js` registers its RP with
`redirect_uris: ["https://rp.sessmgmt.example/cb"]`.

## Step-up authentication (acr_values, max_age)

A client asks for a stronger or more recent sign-in with `acr_values` and
`max_age`. A resource server can require one by naming it on its own
application. The levels are `0` < `1` < `mfa`, plus
`urn:sts:acr:compliant-device`. If the person cannot meet the requirement,
the answer is `unmet_authentication_requirements` in every mode.

Taken from `sts_step_up.js`.

**Set the requirement on the resource, not on the client:**
```bash
api applications/create '{"identifier":"su-api","name":"su-api","protocols":["oauth2"],
  "fields":{"oauthAudience":["https://api.stepup.example.test/"],
            "oauthStepUpAcrValues":"mfa","oauthStepUpMaxAge":"600"}}'
```

**Request:**
```
GET /oauth2/authorize?response_type=code&client_id=su-client&scope=openid
    &redirect_uri=https://rp.stepup.example.test/cb&nonce=…&code_challenge=…&code_challenge_method=S256
    &acr_values=mfa&max_age=600&resource=https://api.stepup.example.test/
```

For this service's own resource servers, use the settings
`oauth2.stepUpAcrValues` (for example `mfa`) and `oauth2.stepUpMaxAgeS`
(`-1` turns it off). The person needs a second factor enrolled to reach
`mfa`; see [Authentication](authentication.md).

## Subject types: public, pairwise, ephemeral

| `oauthSubjectType` | `sub` in the ID Token and UserInfo |
|---|---|
| `public` (the default) | `urn:uuid:<entryUUID>` |
| `pairwise` | a different value per sector (the host of `oauthSectorIdentifierUri`, or the one host all redirect URIs share) |
| `ephemeral` | a new random value per session and client |

```bash
api applications/set '{"application":"parmon-a","attribute":"oauthSubjectType","value":"pairwise"}'
```

A pairwise client whose redirect URIs span several hosts must also set
`oauthSectorIdentifierUri`, pointing to an `https` JSON array that lists every
redirect URI. Both attributes need the client to be declared for **OpenID
Connect**. The jobs `sts_ephemeral_subjects.js` and `sts_oidc_core.js` register
with `subject_type` instead.

## Dynamic Client Registration

This is the alternative to the console. The RP registers itself at
`POST /oauth2/register` and manages its registration at
`/oauth2/register/<client_id>`, using the `registration_access_token` it was
given.

* **Development mode:** registration is always open.
* **Product mode:** it is closed (403) unless `oauth2.openRegistration` is
  `true`, or the request carries a software statement from a trusted issuer
  (`oauth2.softwareStatementOpensRegistration`, on by default). An
  administrator issues software statements from the application page's
  **Software statements** section (API `applications/issue-software-statement`).

```bash
api config/set '{"key":"oauth2.openRegistration","value":true}'
```

```
POST /oauth2/register
{"client_name":"Endpoint Test Client","redirect_uris":["https://rp.example.com/callback"],
 "grant_types":["authorization_code","refresh_token"],
 "response_types":["code"],"token_endpoint_auth_method":"client_secret_basic"}
→ 201 client_id, client_secret, registration_access_token, registration_client_uri
```

A registered client appears in the Applications list like any other, marked
as registered through RFC 7591. The application page's **Revoke the RFC 7591
registration** button (API `applications/revoke-registration`) ends the
registration.

## Related

* [OAuth 2.0 and OpenID Connect](oauth-oidc.md): each feature in depth.
* [Signing out](signing-out.md) and [Sessions](sessions.md).
* [Configuring OAuth 2.0 grants](configure-oauth2-grants.md) and [Configuring SAML profiles](configure-saml.md).
