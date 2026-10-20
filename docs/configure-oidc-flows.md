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

## Where a client is configured in the console

A relying party is an application entry. In the console:

* **Create it** on **Directory → Applications → New application ›**
  (`/admin/applications/new`). Under **What it is called**, the
  **Identifier** is also the `client_id` unless you give `oauthClientId`
  another value. Under **Protocol families it is declared for**, tick
  **OAuth 2.0** and **OpenID Connect**. **Its fields** then shows the
  attributes most clients need, by name: `oauthRedirectUri`,
  `oauthPostLogoutRedirectUri`, `oauthClientSecret` (with **Generate
  Secret** and its **Lifetime (days)**), `oauthTokenEndpointAuthMethod`,
  `oauthGrantType`, `oauthResponseType`, `oauthAllowedScope` and others.
  **Show every field (advanced view)** shows the rest. Click **Create the
  application**.
* **Change it** on its page (`/admin/applications?application=<id>`),
  **Configuration** tab, **OAuth 2.0 / OpenID Connect** sub-tab. Change the
  fields and click **Save OAuth 2.0 / OpenID Connect**. A field the sub-tab
  does not show at first is under **Advanced view (every field)**. A list has
  one box per value: **+** adds a value and the bin deletes one. A field with
  a fixed set of values, such as `oauthGrantType`, offers them to choose from.
* **Change one attribute by name** is on the **Directory entry** tab, folded.
  Its **Set**, **Add to** and **Remove from** forms write any editable
  attribute.

Through the API, `applications/set` writes a single-valued attribute, and
`applications/add` / `applications/remove` add or remove one value of a list.
A write against the attribute's kind (a `set` of a list, say) is refused
(`STS-REG-0008`). `oauthScope` records the scopes a client has asked for. It
grants nothing, and an `add` to it is refused (`STS-REG-0361`). The scopes a
client may be issued are `oauthAllowedScope`.

## Two things to know first

**A client is held to the response types and grant types it declares.**
`oauthResponseType` and `oauthGrantType` are the lists, whether a dynamic
registration wrote them (`POST /oauth2/register`, RFC 7591 `response_types`
and `grant_types`) or an administrator set them in the console or through
`/admin-api`. A response type or grant not on a list is refused with
`unauthorized_client`, in both modes. An empty list restricts nothing, so a
client with neither list may use every response type the server advertises.
The console offers one checkbox per value: the eight response types and
every grant this service implements. A console or API write of any other value
is refused. Through the API, write each response type as one value, its words
separated by spaces (`code id_token`); it is stored with its words in that
order whatever order they were given in. What a client has actually used is
recorded separately, in `oauthResponseTypeObserved` and
`oauthGrantTypeObserved`, and shown read-only at the top of the
**Configuration** tab's **OAuth 2.0 / OpenID Connect** sub-tab, one line
each.

**How responses are signed and encrypted is an attribute too.** The JARM
algorithms, the signing and encryption algorithms for the ID Token and
UserInfo, and `default_acr_values` / `default_max_age` are held on the
application entry, whether a registration wrote them or an administrator set
them in the console or through `/admin-api`:

| Registration member | Attribute |
|---|---|
| `id_token_signed_response_alg` | `oauthIdTokenSignedResponseAlg` |
| `id_token_encrypted_response_alg` / `_enc` | `oauthIdTokenEncryptedResponseAlg` / `Enc` |
| `userinfo_signed_response_alg` | `oauthUserinfoSignedResponseAlg` |
| `userinfo_encrypted_response_alg` / `_enc` | `oauthUserinfoEncryptedResponseAlg` / `Enc` |
| `authorization_signed_response_alg` | `oauthAuthorizationSignedResponseAlg` |
| `authorization_encrypted_response_alg` / `_enc` | `oauthAuthorizationEncryptedResponseAlg` / `Enc` |
| `default_acr_values` | `oauthDefaultAcrValues` (space-separated, most preferred first) |
| `default_max_age` | `oauthDefaultMaxAge` (seconds) |

The console, the API and a registration refuse the same values. An RFC 7592
update replaces them: a member it leaves out is cleared. An encryption
algorithm encrypts to the key in `oauthJwks` or `oauthJwksUri`. For example,
an ES256 ID Token for a client created through the API:

```bash
api applications/set '{"application":"parmon-a",
  "attribute":"oauthIdTokenSignedResponseAlg","value":"ES256"}'
```

**Consent is on by default.** Unless the person has already approved the
client, the flow stops at `/oauth2/consent`. For a first-party client, grant
consent for everybody in advance. In the console that is **Monitoring →
Consent** (`/admin/consent`) → **Consent a scope for everybody** → pick the
**Application**, type the **Scope**, then **Consent it for everybody**. The
value lands in the client's `oauthGlobalConsent`, which the create form also
offers. The API call is:

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

**An error before the person has signed in is shown on a page, not
redirected** (RFC 9700 section 4.11.2). The page has a link that carries the
error on to the client. `oauth2.errorPageAutoRedirectS` (default `0`, at most
`60`) makes the page also continue by itself after that many seconds. That
weakens the protection the page exists for, so leave it at `0` unless a
client cannot cope. A `form_post` error keeps its button whatever the value.
`tests/error_page_auto_redirect.js` sets it to `5`:

```bash
api config/set '{"key":"oauth2.errorPageAutoRedirectS","value":5}'
```

## Authorization Code flow

`response_type=code`. The RP exchanges the code at `/oauth2/token`. PKCE
accepts `S256` and, in development only, `plain`.

Taken from `sts_oauth2_monitor.js` and `sts_oidc_core.js`.

**Console:**
1. Go to **Directory → Applications → New application ›**. Set **Identifier** to `parmon-a`; it is the `client_id` too.
2. Under **Protocol families it is declared for**, tick **OAuth 2.0** and **OpenID Connect**.
3. In **Its fields**:
   - `oauthRedirectUri`: `https://rp.parmon.example.test/cb`.
   - `oauthClientSecret`: click **Generate Secret**, and copy the value.
   - `oauthTokenEndpointAuthMethod`: tick `client_secret_basic`, and nothing else.
4. Click **Create the application**.
5. Grant consent for `openid` on **Consent**, as described above.

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
  `response_types_supported`, so the request is refused as a type the
  server does not advertise: `unsupported_response_type`, recorded as
  `STS-OAUTH-0163`. With nobody signed in the error is shown on a page whose
  link carries it to the client (RFC 9700 section 4.11.2: no redirect before
  the user is authenticated); with somebody signed in it is redirected to the
  client. The job `sts_admin_client_policies.js` checks both. To use it you
  need development mode with `oauth2.rfc9700` off.

A client that registers itself must list `implicit` in `grant_types`
whenever one of its `response_types` contains `token`.

## Hybrid flow

`code id_token`, `code token` and `code id_token token`. The ID Token carries
`c_hash` and `at_hash`, plus `s_hash` when a `state` was sent. The response
goes in the fragment. `code id_token` and `code id_token token` require a
`nonce`.

* **`code id_token`** works in every mode. The job `sts_oidc_core.js` runs it
  across `id_token_signed_response_alg` values `RS256`, `RS384`, `PS512`,
  `ES512`, `EdDSA` and `ML-DSA-44`, registering each client dynamically, and
  sets `oauthIdTokenSignedResponseAlg` on a client it creates through
  `/admin-api`.
* **`code token`** and **`code id_token token`** are refused in RFC 9700 mode
  and product mode, the same way as `id_token token` above
  (`sts_admin_client_policies.js` checks `code token`).

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
| `jwt`, `query.jwt`, `fragment.jwt`, `form_post.jwt` (JARM) | optional `oauthAuthorizationSignedResponseAlg` (registration member `authorization_signed_response_alg`, default `RS256`), `oauthAuthorizationEncryptedResponseAlg` and `Enc` | Works in every mode. `query.jwt` carrying a token is refused unless the response is encrypted. `oauth2.jarmResponseLifetimeS` defaults to 600. |

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

* **Which claims are released** is set per scope on **Protocols → OAuth 2.0
  / OIDC** (`/admin/oauth2`), on its **UserInfo claims** and **Custom claims**
  tabs (`/admin/userinfo-claims` and `/admin/claims` open the same tabs). Product mode takes every value from the person's
  directory entry, so fill the entry in:
  ```bash
  api users/create '{"username":"alice","invent":false,"credential":"password",
    "password":"<password>","attributes":{"cn":"Alice Example","givenName":"Alice",
    "sn":"Example","mail":"alice@example.com","telephoneNumber":"+1 555 0100",
    "street":"1 Main St","l":"Springfield","postalCode":"12345","c":"US"}}'
  ```
  (These attributes are the ones `sts_oidc_core.js` creates.)
* **Signed or encrypted UserInfo** is chosen by `oauthUserinfoSignedResponseAlg`
  and `oauthUserinfoEncryptedResponseAlg` (registration members
  `userinfo_signed_response_alg` and `userinfo_encrypted_response_alg`). The
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

With the attribute `TRUE`, a plain authorization request from that client is
answered `400 invalid_request` on a page and is never redirected
(`STS-OAUTH-0419`); written `FALSE` again, the plain request reaches the
sign-in screen. The job `sts_admin_client_policies.js` checks this for a
client created through `/admin-api`, in a development and a product realm.

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
and an `alg: none` object. Product mode refuses both, and refuses an `http`
request URI when it is registered, before any request is made (RFC 9101
section 5.2). The `https` host is verified under the federation outbound
policy, so a private CA is named by `federation.outboundCaFile`.

The job `sts_jar_admin_client.js` creates such a client through `/admin-api`
and serves its request objects and key set itself. It checks that:
* a registered `request_uri` is fetched, and its object is verified with the
  key at the registered `jwks_uri`;
* the flow ends at the client with the object's `state`, not the query's;
* a `request_uri` that was not registered is refused and never fetched;
* an object signed with another algorithm, or with a key that is not in the
  set, is refused;
* an unsigned object is refused while `oauthRequireSignedRequestObject` is
  `TRUE`.

`tests/rfc9101_request_objects.js` covers the rest in process, signing with
`ES256` and `typ: oauth-authz-req+jwt`.

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
declared for **OpenID Connect**. Then, on its **Configuration** tab's
**OAuth 2.0 / OpenID Connect** sub-tab, under **Advanced view (every field)**:
- set `oauthNativeSso` to `TRUE`;
- set `oauthNativeSsoGroup` to `vendor.one`;
- click **Save OAuth 2.0 / OpenID Connect**.

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

## Third-party-initiated login (/launch)

A sign-in can start here instead of at the client. The person follows this
service's link `/launch/<client_id>`, signs in if they have no session, and
is sent to the client's `initiate_login_uri` with `iss`, `login_hint` and
`target_link_uri` (OpenID Connect Core section 4). The client then sends an
ordinary authorization request. No ID Token is posted to the client
unasked. [Identity-provider-initiated sign-in](idp-initiated-sso.md) covers
the link for every protocol.

**It is off by default**, for every client. While it is off the link is
refused (`STS-LAUNCH-0005`), and the user portal shows no **Sign in** link for
the client either.

Taken from `sts_idp_initiated_launch.js`.

**Console:** on the client's **Configuration** tab, **OAuth 2.0 / OpenID
Connect** sub-tab, **Advanced view (every field)**, under **Who may start a
sign-in**:
- set `oauthThirdPartyInitiatedLogin` to `TRUE`;
- set `oauthInitiateLoginUri` to the client's `initiate_login_uri`, for
  example `https://rp.launch.example/login`;
- click **Save OAuth 2.0 / OpenID Connect**.

`appHomePageUrl`, on the **Every protocol** sub-tab (saved with **Save Every
protocol**), is where the person lands when the link names no `target`.

The sub-tab shows the link at its top, with a copy button, and says what is
missing while the client cannot be launched.

**API** (the job's public client, which also turns its own start off):
```bash
api applications/create '{"identifier":"launch-rp","name":"launch-rp",
  "kind":"oauth2-client","protocols":["oauth2","oidc"],
  "fields":{"oauthClientId":["launch-rp"],
            "oauthRedirectUri":["https://rp.launch.example/cb"],
            "oauthGrantType":["authorization_code"],"oauthResponseType":["code"],
            "oauthAllowedScope":["openid"],"oauthTokenEndpointAuthMethod":"none",
            "appHomePageUrl":"https://rp.launch.example/home",
            "oauthInitiateLoginUri":"https://rp.launch.example/login",
            "oauthThirdPartyInitiatedLogin":"TRUE","oauthSpInitiatedSso":"FALSE"}}'
api consent/grant-global-consent '{"client":"launch-rp","scope":"openid"}'
```

To turn it on for every client in the realm instead (a client's own value
still wins):
```bash
api config/set '{"key":"oauth2.thirdPartyInitiatedLogin","value":true}'
```

**Requests:**
```
GET /launch/launch-rp
→ 303 https://rp.launch.example/login?iss=<issuer>&login_hint=<username>
      &target_link_uri=https://rp.launch.example/home   (plus tenant in a trust realm)

GET /oauth2/authorize?response_type=code&client_id=launch-rp&…   (sent by the client)
```

* **`target` must be one of the client's registered addresses**: a redirect
  URI, its `oauthInitiateLoginUri` or its `appHomePageUrl`, https, matched
  exactly. Any other is refused (400, `STS-LAUNCH-0007`).
* **`oauthSpInitiatedSso` `FALSE`** (realm setting `oauth2.spInitiatedSso`,
  on by default) means the client may start a sign-in only right after a
  launch. Its authorization request is answered once per launch, within
  `oauth2.launchWindowS` (default `300` seconds). Any other request is refused
  `unauthorized_client` (`STS-OAUTH-0959`).
* `/admin-api/applications?application=launch-rp` returns the link as
  `page.launchUrls`.

## Key-bound ID Tokens (OpenID Connect Key Binding)

A client that asks for the `bound_key` scope, with a `dpop_jkt` and the code
flow, gets an ID Token bound to its DPoP key (`cnf.jwk`,
`typ: dpop+id_token`). The token request then proves the key with `c_s256`,
and every refresh must come from the same key.
[OAuth 2.0 and OpenID Connect](oauth-oidc.md#key-bound-id-tokens-openid-connect-key-binding)
describes it.

It is **on by default** (`oauth2.keyBinding`). Turn it off where relying
parties request every advertised scope and know nothing of Key Binding:

```bash
api config/set '{"key":"oauth2.keyBinding","value":false}'
```

Off, `bound_key` leaves `scopes_supported`, a request carrying it is not
refused, the scope is not granted and nothing is bound. A grant bound before
still needs its key on refresh. `sts_device_key_binding.js` checks both
states; its client registers with `"scope":"openid offline_access bound_key"`.

## RP-Initiated Logout

The RP sends the person to `GET` or `POST /oauth2/logout` with
`post_logout_redirect_uri`, `id_token_hint` or `client_id`, and `state`.

**The return address must be registered.** In the console, it is the
`oauthPostLogoutRedirectUri` field, on the new-application form or on the
client's **OAuth 2.0 / OpenID Connect** sub-tab (**+** adds a value). Through
the API:

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

**Client** (from the in-process job `tests/backchannel_logout.js`; the job
`sts_backchannel_logout.js` registers the same attributes through
`/admin-api`):
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
sends to `http`. **Product mode also never sends to an address on a private,
loopback, link-local or reserved network**: the delivery is dead-lettered
with `STS-OAUTH-0534` and nothing is dialled. A relying party on a private
network is reached only from a development-mode realm.

The job `sts_backchannel_logout.js` delivers to the test peer, which plays
the relying party and verifies each Logout Token as section 2.6 asks (the
signature, `typ: logout+jwt`, `iss`, `aud`, `iat`, `jti`, the event, `sub` or
`sid`, no `nonce`, no replay). In a development realm, RP-initiated logout and
the console's global logout each send one token, naming the ID Token's `sub`
and `sid`. In a product realm the same sign-out sends nothing to the peer's
private address and records `STS-OAUTH-0534`. Failed deliveries are listed on **Sign-out**
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

## Several accounts in one browser (prompt=select_account)

With `authn.multipleAccounts` on, one browser can stay signed in as several
people, and an authorization request chooses between them.
[Several accounts in one browser](multiple-accounts.md) describes it in full.
It is **off by default** in both modes, and off nothing below happens.

Taken from `sts_multi_account.js`.

**Setting** (console: **Server configuration → Configuration**, the **Web
security** group; it is per realm):
```bash
api config/set '{"key":"authn.multipleAccounts","value":true}'
```

`authn.maxBrowserAccounts` (default `10`) and `authn.rememberedAccountDays`
(default `30`) bound the list. No client attribute is involved.

**What the request does:**

| The request carries | With several accounts signed in |
|---|---|
| `login_hint=<username>` | that account is answered, with no screen; a hint naming nobody signed in here goes to the sign-in screen |
| an `id_token_hint` | the account its `sub` and `sid` name |
| `prompt=select_account` | the account picker (`/authn/accounts`), whatever the hint |
| `prompt=login` | a fresh sign-in, never the picker |
| `prompt=none` and nothing that names an account | the error `account_selection_required` |
| nothing | the account picker |

`max_age` and `acr_values` are asked of the chosen account's session. Logout
with an `id_token_hint` ends the session its `sid` names and leaves the other
accounts signed in.

## Step-up authentication (acr_values, max_age)

A client asks for a stronger or more recent sign-in with `acr_values` and
`max_age`. The authorization endpoint honours them in every mode. The levels
are `0` < `1` < `mfa`, so a stronger sign-in meets a request for a weaker
one. `hwk` is met by two factors that include a security key. The other
published values, `phr`, `phrh` and `urn:sts:acr:compliant-device`, are not
on that ladder (see [below](#phishing-resistant-sign-in-phr-and-phrh)).
`acr_values_supported` in discovery lists them all. If the person cannot meet
the requirement, the answer is `unmet_authentication_requirements` in every
mode.

Taken from `sts_step_up.js`.

**A resource server states its requirement on its own application.** The
API itself sends the RFC 9470 challenge (401
`insufficient_user_authentication` with the `acr_values` it needs); this
service does not answer for it. In the job, the API is the test peer.

```bash
api applications/create '{"identifier":"su-api","name":"su-api","protocols":["oauth2"],
  "fields":{"oauthAudience":["https://api.stepup.example.test/"],
            "oauthStepUpAcrValues":"mfa","oauthStepUpMaxAge":"600"}}'
```

In the console these are the `oauthStepUpAcrValues` and `oauthStepUpMaxAge`
fields on the API's **OAuth 2.0 / OpenID Connect** sub-tab.

**Request** (the client repeats what the challenge named):
```
GET /oauth2/authorize?response_type=code&client_id=su-client&scope=openid
    &redirect_uri=https://rp.stepup.example.test/cb&nonce=…&code_challenge=…&code_challenge_method=S256
    &acr_values=mfa&max_age=600&resource=https://api.stepup.example.test/
```

The token carries the most preferred requested value that was met, and
`auth_time`. A client can also ask by default: `oauthDefaultAcrValues` and
`oauthDefaultMaxAge` (registration members `default_acr_values` and
`default_max_age`).

For this service's own resource servers (UserInfo, the OpenID4VCI credential
endpoints, SCIM and the Shared Signals API), use the settings
`oauth2.stepUpAcrValues` (empty by default, for example `mfa`) and
`oauth2.stepUpMaxAgeS` (`-1`, the default, turns it off). The person needs a
second factor enrolled to reach `mfa`; see [Authentication](authentication.md).

## Phishing-resistant sign-in (phr and phrh)

OpenID Connect EAP ACR Values 1.0 defines `phr` (phishing-resistant) and
`phrh` (the same, with the key in hardware). They need no setting and no
client attribute. A client asks with `acr_values=phr` or `acr_values=phrh`,
with an essential `acr` claims request, or by default through
`oauthDefaultAcrValues`, and reads the answer in the ID Token's `acr`.

Taken from `tests/eap_acr_values.js`, which signs in with a software
authenticator over HTTP. `sts_step_up.js` checks that discovery publishes both
values.

```
GET /oauth2/authorize?response_type=code&client_id=<id>&scope=openid
    &redirect_uri=…&nonce=…&code_challenge=…&code_challenge_method=S256
    &acr_values=phr
```

* A request naming only `phr` or `phrh` makes the sign-in screen ask for a
  passkey or security key. A password and a one-time code do not earn either
  value, and `mfa` does not meet `phr`.
* `phrh` needs a key whose attestation this realm trusts, with the
  backup-eligible flag clear. So it needs `webauthn.attestationPolicy` set to
  `verify-if-present` or `require-trusted` when the key is registered. A
  synced passkey earns `phr` only.
* A sign-in that did not earn the value is refused
  `unmet_authentication_requirements` (`STS-OAUTH-0970`, or `STS-OAUTH-0971`
  for `phrh` on a key that earned only `phr`).
* To require it whatever the client asks, use the issuance policy's
  `requirePhishingResistant` and `requireHardwareProtected` options for the
  application.

[Security profiles → Phishing-resistant sign-in](oauth-security.md#phishing-resistant-sign-in-phr-phrh)
has the table of what earns which value.

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
  **Software statements** tab (API `applications/issue-software-statement`).

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
as registered through RFC 7591. **Revoke the RFC 7591 registration**, on the
application page's **Remove** tab (API `applications/revoke-registration`),
ends the registration.

## Related

* [OAuth 2.0 and OpenID Connect](oauth-oidc.md): each feature in depth.
* [Signing out](signing-out.md) and [Sessions](sessions.md).
* [Identity-provider-initiated sign-in](idp-initiated-sso.md) and [Several accounts in one browser](multiple-accounts.md).
* [Security profiles](oauth-security.md): RFC 9700, OAuth 2.1, FAPI, step-up and `phr` / `phrh`.
* [Configuring OAuth 2.0 grants](configure-oauth2-grants.md) and [Configuring SAML profiles](configure-saml.md).
