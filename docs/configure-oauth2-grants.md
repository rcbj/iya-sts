---
title: "Configuring OAuth 2.0 grants"
---

# Configuring OAuth 2.0 grants

This page shows how to set up iya-sts for each OAuth 2.0 grant type it
supports: the application to register, the settings to turn on, and the
request a client then sends. Each recipe is given twice, once as steps in the
**admin console** (`/admin`) and once as calls to the **Management API**
(`/admin-api`).

**The values come from this repository's own test jobs** in
`tests/protocol/`, and each recipe names the job it is taken from. Those jobs
run against a service in both development and product mode, so the values are
known to work in both. Change the identifiers, URLs and secrets to your own.

What each grant *is*, and every setting in full, is on
[OAuth 2.0 and OpenID Connect](oauth-oidc.md). This page covers only what to
fill in. The OpenID Connect flows (implicit, hybrid, logout, session
management and so on) are on [Configuring OpenID Connect flows](configure-oidc-flows.md).

* TOC
{:toc}

## Before you start

### A token for the Management API

Every `/admin-api` call below needs an access token with the `admin:write`
scope. [Management API → Getting a token](management-api.md#getting-a-token)
shows how to get one. The examples here assume these variables and this helper
function:

```bash
BASE=https://localhost:8081            # add /realm/<id> to work in a trust realm
TOKEN=...                              # from management-api.md#getting-a-token

api() {   # api <path under /admin-api> '<json body>'
  curl -sk -X POST "$BASE/admin-api/$1" \
    -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
    -d "$2"
}
```

### Four operations do almost all of the work

| What | Console | API |
|---|---|---|
| Register an application | **Directory → Applications → New application ›** (`/admin/applications/new`), then **Create the application** | `POST /admin-api/applications/create` with `{identifier, name?, protocols, fields, lifetimeDays?}` |
| Change one of its fields | the application's page (`/admin/applications?application=<id>`), **Configuration** tab, the protocol's sub-tab (for example **OAuth 2.0 / OpenID Connect**), then **Save <sub-tab>** | `POST /admin-api/applications/set` with `{application, attribute, value}`, for a single-valued attribute (an empty value clears it) |
| Add or remove one value of a list | the same sub-tab: **+** adds a box, the bin deletes one, then **Save <sub-tab>**; or the **Directory entry** tab → **Change one attribute by name** → **Add to** / **Remove from** | `POST /admin-api/applications/add` and `/remove`, with the same three members |
| Change a setting | **Protocols → OAuth 2.0 / OIDC** (`/admin/oauth2`), **Global settings** tab, then the group's **Save <group>** button; **Reset** on a row puts that row back | `POST /admin-api/config/set` with `{key, value}`, `/config/set-many` with `{"<key>": value, …}`, `/config/reset` with `{key}` |

`applications/set` on a list attribute is refused (`STS-REG-0008`): use
`add` and `remove` for those.

Settings are per [trust realm](trust-realms.md). A console page saves to the
realm it is shown in, and `/realm/<id>/admin-api/config/...` saves to that
realm. To give a new realm its settings from the start, use
`POST /admin-api/realms/create` with an `overrides` object. The OAuth 2.1 job
(`sts_oauth21.js`) does this:

```bash
api realms/create '{"id":"r1","domain":"r1.example.net","name":"r1",
  "overrides":{"oauth2.oauth21":true,"oauth2.consentRequired":false}}'
```

**The new-application form.** Under **What it is called** you type the
**Identifier** and, if you like, a **Name**. Under **Protocol families it is
declared for** you tick the families. Under **Its fields** the form shows a
grid of attributes, by their attribute names, for the families ticked. The
*simplified view* shows the fields most clients need, among them
`oauthRedirectUri`, `oauthTokenEndpointAuthMethod`,
`oauthGrantType`, `oauthResponseType`, `oauthAllowedScope`, `oauthAudience`
and `oauthClientSecret`. **Show every field (advanced view)** shows the rest.
The registry writes `oauthConfidential` from the authentication method, so
the form does not offer that attribute.
A list holds one box per value, with **+** to add one. A list with a fixed set
of values, such as `oauthGrantType`, is a row of checkboxes; a long URN is
shown by its last two parts (`grant-type:device_code`), with the whole value
in its tooltip. A `TRUE`/`FALSE` attribute is a choice of **true**, **false**
or the default.

Three things are filled in for you:
* **The identifier is the client_id** unless you give `oauthClientId`
  yourself (#393). The simplified view does not ask for it again. The same
  goes for a SAML `samlEntityId` and the other families' identifiers.
* **The auth method follows the credential.** If the create names no
  `oauthTokenEndpointAuthMethod`, a client secret makes it
  `client_secret_basic`, an `oauthJwks` or `oauthJwksUri` makes it
  `private_key_jwt`, and no credential makes it `none`, a public client.
* **The confidential flag follows the method.** `none`, or no method on an
  application created by hand, is recorded as `oauthConfidential` FALSE. Any
  other method is TRUE. A create may send that same value. A value that
  disagrees is refused (`STS-REG-0363`). The method is what an operator
  edits, and the registry writes the flag.
* **The first secret's lifetime** is the **Lifetime (days)** box beside
  **Generate Secret**, or `lifetimeDays` on the API create. See
  [Client secrets](#client-secrets).

`oauthScope` is not a permission. It records the scopes a client has asked
for, so an `add` to it is refused (`STS-REG-0361`). The scopes a client may be
issued are `oauthAllowedScope`.

### What development and product mode change

The same registration behaves differently in the two modes (`global.mode`):

* **Development mode makes things up.** An unknown `client_id` and its
  redirect URI are accepted and recorded, a wrong client credential is logged
  rather than refused (outside RFC 9700, OAuth 2.1 and FAPI mode), and any
  scope is issued. Registering first is still the right habit, and every
  recipe here does it.
* **Product mode implies [RFC 9700 mode](oauth-security.md).** It refuses an
  unregistered client, matches redirect URIs exactly, requires PKCE with
  `S256` from a public client, refuses the implicit and password grants, and
  rotates refresh tokens. A client that declared a confidential method must
  authenticate with it.
* **Product mode holds a client to its protocol families.** An application
  declared for OAuth 2.0 alone is refused an ID Token (`STS-XACML-0084`).
  Declare **OpenID Connect** as well for any client that asks for `openid`.
* **Scopes in product mode come from `oauthAllowedScope`.** A scope that is
  not listed there is refused with `invalid_scope`. If the list is empty,
  product mode issues only the standard set: `openid profile email address
  phone offline_access` and `bound_key` (while `oauth2.keyBinding` is on),
  plus the realm's OpenID4VCI scopes. This service's own protected scopes must
  be listed in **both** modes; see
  [This service's own scopes](#this-services-own-scopes).
* **`oauthGrantType` restricts the client, in both modes.** The token
  endpoint refuses any grant the list does not name with `unauthorized_client`,
  whether the list came from a dynamic registration (RFC 7591 `grant_types`) or
  an administrator. A client whose list omits `refresh_token` is issued no
  refresh token. An empty list restricts nothing. The console offers one
  checkbox per grant this service implements, and a console or API write of
  any other value is refused. What a client has actually used is recorded
  separately, in `oauthGrantTypeObserved`, shown read-only beside
  `oauthGrantType` on the application's **OAuth 2.0 / OpenID Connect**
  sub-tab.
* **Consent is on by default** (`oauth2.consentRequired`). A person approves
  each client on `/oauth2/consent` the first time. Test realms often turn it
  off with `"oauth2.consentRequired": false`. In production, leave it on.

## Which grants are available

| Grant (`grant_type`) | Available | Recipe |
|---|---|---|
| `authorization_code` | always; PKCE is required of public clients in RFC 9700, OAuth 2.1 and product mode | [below](#authorization-code-with-pkce) |
| `client_credentials` | always; refused for a public client in product mode | [below](#client-credentials) |
| `refresh_token` | always | [below](#refresh-token) |
| `password` | **development mode only**, and not while `oauth2.rfc9700` is on | [below](#password-development-only) |
| `urn:ietf:params:oauth:grant-type:device_code` | while `oauth2.deviceAuthorization` is on (off by default) | [below](#device-authorization-rfc-8628) |
| `urn:ietf:params:oauth:grant-type:jwt-bearer` | while `oauth2.jwtBearerGrant` is on (on by default) | [below](#jwt-bearer-rfc-7523) |
| `urn:ietf:params:oauth:grant-type:saml2-bearer` | while `oauth2.saml2BearerGrant` is on (on by default) | [below](#saml-20-bearer-rfc-7522) |
| `urn:ietf:params:oauth:grant-type:token-exchange` | always | [below](#token-exchange-rfc-8693) |
| `urn:openid:params:grant-type:ciba` | while `oauth2.ciba` is on (off by default) | [below](#ciba) |
| `urn:ietf:params:oauth:grant-type:pre-authorized_code` | always | [below](#pre-authorized-code-openid4vci) |
| implicit (`response_type=token`) | not in RFC 9700 mode, and so not in product mode | [Configuring OpenID Connect flows](configure-oidc-flows.md) |

The live list for a realm is `grant_types_supported` in
`/.well-known/openid-configuration`. A grant that is not listed there is
refused with `unsupported_grant_type`.

## Authorization code, with PKCE

A person signs in through a browser and the client exchanges the code it
receives for tokens. The code is valid for `oauth2.authorizationCodeTtlS`
(300 s by default, and never longer). It is presented once: its first token
request spends it, whatever that request's outcome, and a second presentation
is refused and revokes what the first one bought. `oauth2.codeReplayIdempotent`
relaxes that rule. It is off by default; leave it off.

### A public client (a browser or native app)

Taken from `oauth2_sts_endpoints.js`.

**Console:**
1. **Directory → Applications → New application ›**.
2. Under **What it is called**, set **Identifier** to `sts-endpoint-test-client-native` (the name is optional). It is also the client_id.
3. Under **Protocol families it is declared for**, tick **OAuth 2.0** and **OpenID Connect**.
4. Under **Its fields**, in the **OAuth 2.0 / OpenID Connect** group:
   - `oauthRedirectUri`: `com.example.oauth2stsendpoints:/callback`.
   - `oauthTokenEndpointAuthMethod`: tick `none`, and nothing else. The
     registry records `oauthConfidential` FALSE because the method is `none`.
   - `oauthGrantType`: tick `authorization_code` and `refresh_token`.
   - `oauthResponseType`: tick `code`.
   - `oauthAllowedScope`: `openid`, `profile` and `email`, one box each (**+** adds a box).
5. Click **Create the application**.

**API:**
```bash
api applications/create '{
  "identifier": "sts-endpoint-test-client-native",
  "name": "sts-endpoint-test-client-native",
  "protocols": ["oauth2", "oidc"],
  "fields": {
    "oauthRedirectUri": ["com.example.oauth2stsendpoints:/callback"],
    "oauthResponseType": ["code"],
    "oauthGrantType": ["authorization_code", "refresh_token"],
    "oauthAllowedScope": ["openid", "profile", "email"],
    "oauthTokenEndpointAuthMethod": "none"
  }}'
```

The registry writes `oauthConfidential` FALSE from `none`. Sending
`"oauthConfidential": "FALSE"` states the same value. A different value is
refused (`STS-REG-0363`).

### A confidential client (a web server)

Taken from `sts_token_revocation.js`.

**Console:** create the application as for the public client above, with
**Identifier** `rv-a` and `oauthRedirectUri` `https://rp.revoke.example.test/cb`.
Beside `oauthClientSecret`, click **Generate Secret**, and copy the value
before you create the application. Leave **Lifetime (days)** empty for the
realm's default. Then:
- `oauthTokenEndpointAuthMethod`: tick `client_secret_basic`, and nothing else.
- `oauthAllowedScope`: `openid`.

An application that already exists gets a secret on its **Credentials** tab,
under **Client secrets**. See [Client secrets](#client-secrets).

**API:**
```bash
SECRET=$(openssl rand -base64 32)
api applications/create '{
  "identifier": "rv-a", "name": "rv-a", "kind": "oauth2-client",
  "protocols": ["oauth2", "oidc"],
  "fields": {
    "oauthClientId": ["rv-a"],
    "oauthRedirectUri": ["https://rp.revoke.example.test/cb"],
    "oauthGrantType": ["authorization_code", "refresh_token"],
    "oauthAllowedScope": ["openid"],
    "oauthTokenEndpointAuthMethod": "client_secret_basic",
    "oauthClientSecret": "'"$SECRET"'"
  }}'
```

`POST /admin-api/applications/generate-secret` with `{}` returns a random
secret and stores nothing, if you would rather have the service choose one.
Pass it in `fields.oauthClientSecret`.

### The requests

```
GET /oauth2/authorize?response_type=code&client_id=rv-a
    &redirect_uri=https://rp.revoke.example.test/cb&scope=openid&state=<random>
    &code_challenge=<BASE64URL(SHA256(verifier))>&code_challenge_method=S256

POST /oauth2/token
  Authorization: Basic base64(rv-a:<secret>)   # a public client sends client_id=… instead
  grant_type=authorization_code&code=<code>
  &redirect_uri=https://rp.revoke.example.test/cb&code_verifier=<verifier>
```

`redirect_uri` on the token request must be exactly the one on the
authorization request. [OAuth 2.1 mode](oauth-security.md) (`oauth2.oauth21`)
lets a public client that used PKCE leave it out. RFC 9700 mode alone does
not.

**Settings** (console: **Protocols → OAuth 2.0 / OIDC**, **Global settings** tab):

| Setting | Default | Why you would change it |
|---|---|---|
| `oauth2.rfc9700` | `false` | Turns on RFC 9700 mode in development. Product mode implies it. |
| `oauth2.oauth21` | `false` | Turns on OAuth 2.1 mode, which implies RFC 9700 mode. |
| `oauth2.consentRequired` | `true` | Asks the person to approve each client. |
| `oauth2.authorizationCodeTtlS` | `300` | Sets how long a code is valid: 30 to 300 seconds. |

## Client credentials

A service gets a token for itself. No person is involved, and no refresh
token or ID Token is issued. The token's `sub` is the client_id; in RFC 9700
mode, and so in product, it is `urn:sts:client:<client_id>`.

Taken from `sts_scope_policy.js`, which suffixes each identifier with its
realm's name.

**Console:**
1. Create the application: **Identifier** `sp-listed`, tick **OAuth 2.0**,
   and click **Generate Secret** beside `oauthClientSecret`. No redirect URI is
   needed.
2. In the same grid:
   - `oauthTokenEndpointAuthMethod`: tick `client_secret_post`, and nothing else.
   - `oauthGrantType`: tick `client_credentials`.
   - `oauthAllowedScope`: each scope it may be issued, here `sp:custom`.

**API:**
```bash
api applications/create '{
  "identifier": "sp-listed", "name": "sp-listed", "kind": "oauth2-client",
  "protocols": ["oauth2"],
  "fields": {
    "oauthClientId": ["sp-listed"],
    "oauthClientSecret": "'"$SECRET"'",
    "oauthGrantType": ["client_credentials"],
    "oauthTokenEndpointAuthMethod": "client_secret_post",
    "oauthAllowedScope": ["sp:custom"]
  }}'
```

**Request:**
```
POST /oauth2/token
  grant_type=client_credentials&client_id=sp-listed&client_secret=<secret>&scope=sp:custom
  [&resource=https://api.example.com]
```

In product mode, a scope not listed in `oauthAllowedScope` is refused with
`invalid_scope`, and a public client (auth method `none`) is refused this
grant with `unauthorized_client`.

**The audience.** A request that names a `resource`, `authorization_details`,
a scope naming another application or a delegated permission, or a scope of
this service's own resource server (`openid` and the other OpenID Connect
scopes, the SCIM, Shared Signals, management API and grant management scopes)
gets the audience those name. A request that names none of these gets a token
addressed to the client itself: its `oauthAudience` values, or its `client_id`
when it declares none (#550). That is the token to send as an RFC 8693
`actor_token`.

**Permissions on another application come from a role** (#551). A delegated
grant (`oauthDelegatedPermission`) authorizes a permission only on a person's
behalf, so it does not count here. To let the client use a permission itself,
make it a member of a role whose `rolePermission` names the permission — an
app role of the resource (`<role>@<resource>`) or a realm role. Without one the
permission is left off the token, and a request asking for nothing else is
refused with `invalid_scope`. See
[Permissions on another application](oauth-oidc.md#permissions-on-another-application-delegated-or-the-applications-own). The seeded `sts-management-api` client is a
working example of this grant.

### This service's own scopes

Some scopes are for this service's own APIs. They are issued only to a client
whose `oauthAllowedScope` lists them, **in both modes**, and each API asks
again on every call, so removing a value cuts off a token already issued.
They are:

* the Management API's `admin:read`, `admin:write` and `admin:console`, and
  the owner scopes `owner:read` and `owner:write`;
* SCIM's two, `scim.scopeRead` and `scim.scopeWrite` (`scim:read` and
  `scim:write` by default);
* Shared Signals' `ssf.read` and `ssf.manage`, and the names in
  `ssf.authScopeRead` and `ssf.authScopeWrite` (by default the same two);
* `account:manage`, `device:compliance`, `grant_management_query`,
  `grant_management_revoke`, `vc-api:issue`, `vc-api:verify` and the embedded
  debugger's `urn:sts:debugger-api:debugger`.

**For Shared Signals, write includes read** (#334). A client that declares
`ssf.manage` may also be issued `ssf.read`, and a token carrying
`ssf.manage` may read. `ssf:write` is not a Shared Signals scope any more.
The job `sts_scope_policy.js` does this with a client declared for
**Shared Signals**:

```bash
api applications/create '{"identifier":"sp-ssf","name":"sp-ssf","kind":"oauth2-client",
  "protocols":["oauth2","ssf"],
  "fields":{"oauthClientId":["sp-ssf"],"oauthClientSecret":"'"$SECRET"'",
            "oauthGrantType":["client_credentials"],
            "oauthTokenEndpointAuthMethod":"client_secret_post"}}'
api applications/add '{"application":"sp-ssf","attribute":"oauthAllowedScope","value":"ssf.read"}'
api applications/add '{"application":"sp-ssf","attribute":"oauthAllowedScope","value":"ssf.manage"}'
```

```
POST /oauth2/token
  grant_type=client_credentials&client_id=sp-ssf&client_secret=<secret>
  &scope=ssf.read ssf.manage
```

The job then removes `ssf.read`: the same token still reads, because
`ssf.manage` includes it. Removing `ssf.manage` too makes the Shared Signals
endpoints answer 403 to that token.
[Shared Signals](shared-signals.md) says which operation needs which scope.

## Resource indicators (RFC 8707)

A request may name the API its token is for with `resource`, on every grant.
[OAuth 2.0 and OpenID Connect](oauth-oidc.md) explains how the audience is
chosen. Three rules matter when you configure a client:

* **In product mode a resource must be a registered target**: one of this
  service's own resource servers, or an application registered in the realm,
  named by its `oauthAudience`, permission base URI, `client_id` or
  identifier. Anything else is `invalid_target`. Development mode accepts any
  absolute URI.
* **An authorization code may name several resources** (#607). The code
  request is refused only when no one of them could be issued a token alone.
  Each token request then names the one resource its access token is for, and
  a token request naming none or several of them is refused. Implicit and
  hybrid responses carry a token from the authorization endpoint, so they keep
  the stricter rule.
* **A client_credentials request may name two resources and no scope.** Its
  token is then addressed to both. Two resources with a scope tied to neither
  is `invalid_target`. `tests/rfc9068_access_tokens.js` checks both.

## Refresh token

A refresh token is issued with the authorization code grant (and with the
device, CIBA and token exchange grants). Request `offline_access` if it should
outlive the sign-on session. Without that scope the refresh token is
*online*, and it stops working when the session ends.

**Request** (from `sts_token_revocation.js`):
```
POST /oauth2/token
  Authorization: Basic base64(rv-a:<secret>)
  grant_type=refresh_token&refresh_token=<token>[&scope=openid]
```

A `scope` on the request narrows the new access token. The refresh token that
comes back still carries the whole grant.

**Settings.** The lifetimes are on **Protocols → OAuth 2.0 / OIDC**, the
**Token lifetimes** tab (button **Save lifetimes**; API:
`POST /admin-api/token-lifetimes/set`). The other settings are on the
**Global settings** tab.

| Setting | Default | What it does |
|---|---|---|
| `oauth2.refreshTokenTtlS` | `86400` | The refresh token's absolute lifetime. |
| `oauth2.refreshIdleSeconds` | `86400` | How long an unused refresh token stays valid, in RFC 9700 mode only. |
| `oauth2.revokeRefreshOnLogout` | `true` | Signing out ends the person's refresh tokens. |
| `oauth2.refreshTokenRotation` | `false` | Issues a new refresh token on each use. Rotation is already on in RFC 9700, OAuth 2.1, FAPI and product mode. A replayed refresh token revokes the whole family. |
| `oauth2.refreshTokenRequireDpop` / `…RequireMtls` | `false` | Requires the refresh token to be sender-constrained. |
| `oauth2.refreshRequiresConsent` | `true` | Requires a consent record for the refresh. |

**Per-client overrides.** Each application can override the lifetimes. In
the console they are fields of their own names: on the new-application form,
and on the application's **Configuration** tab, **OAuth 2.0 / OpenID Connect**
sub-tab, under **Show every field (advanced view)**. Empty a field to take the
realm's value again. Through the API:

```bash
api applications/set '{"application":"rv-a","attribute":"oauthRefreshTokenTtlS","value":"3600"}'
```

The override attributes are `oauthAccessTokenTtlS`, `oauthIdTokenTtlS`,
`oauthRefreshTokenTtlS`, `oauthRefreshIdleSeconds` and
`oauthRevokeRefreshOnLogout` (`TRUE` or `FALSE`).

## Password (development only)

The resource owner password credentials grant exists here so that a client's
handling of it can be tested. **It is refused in product mode and whenever
`oauth2.rfc9700` is on**, so do not build anything on it.

Taken from `oauth2_sts_endpoints.js`. First add `password` to the client's
`oauthGrantType`. The person must already exist in the directory:

```bash
api users/create '{"username":"alice","invent":false,"credential":"password",
  "password":"<password>","attributes":{"cn":"alice","givenName":"alice",
  "sn":"alice","mail":"alice@suite.example.test"}}'
```

A realm's attribute policy may require more of a person; product mode
requires `givenName`, `sn` and `mail` by default.

**Request:**
```
POST /oauth2/token
  grant_type=password&username=alice&password=<password>&scope=openid
  &client_id=<id>&client_secret=<secret>
```

In development mode any password is accepted except the reserved value
`invalid`, which is refused with `invalid_grant`.

## Device authorization (RFC 8628)

A device with no browser shows the person a code, and the person approves it
on another device.

**Settings** (**Protocols → OAuth 2.0 / OIDC**, **Global settings** tab; the values are from `sts_device_key_binding.js`):

```bash
api config/set '{"key":"oauth2.deviceAuthorization","value":true}'
api config/set '{"key":"oauth2.deviceCodeIntervalS","value":1}'   # default 5
```

`oauth2.deviceCodeLifetimeS` (default 600) sets how long a code is valid. While
`oauth2.deviceAuthorization` is off, `/oauth2/device_authorization` answers
404.

**Client.** The test registers its client dynamically (with
`oauth2.openRegistration` set to `true`), so the grant is part of the
client's registration:

```
POST /oauth2/register
{"redirect_uris":["https://rp.keybinding.example/cb"],
 "token_endpoint_auth_method":"client_secret_post",
 "grant_types":["authorization_code","refresh_token",
                "urn:ietf:params:oauth:grant-type:device_code"],
 "response_types":["code"],"scope":"openid offline_access"}
```

A dynamically registered client whose `grant_types` does not include
`device_code` is refused with `unauthorized_client`. For a client you register
in the console or through `/admin-api`, add
`urn:ietf:params:oauth:grant-type:device_code` to `oauthGrantType`. The job
`sts_admin_client_policies.js` covers that path: a public client created
through `/admin-api` with the grant is issued tokens once the person approves
on `/portal/device`, and a client whose `oauthGrantType` leaves the grant out
is refused at `/oauth2/device_authorization` with `unauthorized_client`
(`STS-OAUTH-0692`).

**Requests:**
```
POST /oauth2/device_authorization
  client_id=<id>&client_secret=<secret>&scope=openid offline_access
→ device_code, user_code (XXXX-XXXX), verification_uri=<BASE>/portal/device,
  verification_uri_complete, expires_in, interval

(the person signs in at /portal/device, enters the code, and approves)

POST /oauth2/token
  grant_type=urn:ietf:params:oauth:grant-type:device_code
  &device_code=<code>&client_id=<id>&client_secret=<secret>
```

Poll no faster than `interval`. Until the person approves, the token request
answers `authorization_pending`, and polling too fast gets `slow_down`, which
adds 5 seconds to the interval. After that the answer is the tokens, or
`access_denied` or `expired_token`.

## JWT bearer (RFC 7523)

A JWT signed by an issuer the service trusts is exchanged for an access
token. **Step-by-step instructions are in
[JWT assertions → the shortest path](jwt-assertions.md).** The values below
are from `sts_jwt_bearer_grant.js`.

1. The realm needs a certificate authority. In the console that is
   **Protocols → PKI** (`/admin/pki`). Through the API:
   ```bash
   api pki/build '{"organisation":"Assertion Test","country":"US"}'
   ```
2. Create the application that holds the issuer's key:
   ```bash
   api applications/create '{"identifier":"assert-issuer-1","name":"assert-issuer-1",
     "protocols":["oauth2","oidc"],
     "fields":{"oauthClientId":"assert-issuer-1","oauthClientSecret":"'"$SECRET"'",
               "oauthTokenEndpointAuthMethod":"client_secret_post"}}'
   ```
3. Give it a key. In the console, on the application's **Credentials** tab,
   under **Assertion key pairs → RFC 7523 — a JWT assertion**, click **Issue a
   key pair from this realm's CA** (fields **Key algorithm** and **Days**), or
   use **Upload the certificate** for a key you already hold. Through the API:
   ```bash
   api pki/issue '{"identifier":"assert-issuer-1"}'
   ```
   The reply contains the `kid` (`app-…`) and the JWS algorithm (`RS256`).
   The private key is never in a `GET`. Collect it once with
   `reveal-secret`, which writes an audit row:
   ```bash
   api applications/reveal-secret '{"application":"assert-issuer-1",
     "secret":"oauthAssertionPrivateKey"}'
   ```
4. **Declare the issuer.** This is the trust decision. An assertion from an
   undeclared issuer is refused with `invalid_grant` in every mode:
   ```bash
   api applications/add '{"application":"assert-issuer-1",
     "attribute":"oauthAssertionIssuer","value":"https://issuer.example.test/jwtbearer"}'
   ```

**Request.** It carries no client authentication:
```
POST /oauth2/token
  grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=<JWS>&scope=openid profile

JWS header  {"alg":"RS256","typ":"JWT","kid":"<kid>"}
JWS claims  {"iss":"https://issuer.example.test/jwtbearer","sub":"alice",
             "aud":"<BASE>/oauth2/token","iat":…,"exp":iat+120,"jti":"<random>"}
```

**Settings** (**Protocols → OAuth 2.0 / OIDC**, **Global settings** tab):

| Setting | Default | What it does |
|---|---|---|
| `oauth2.jwtBearerGrant` | `true` | Enables the grant. |
| `oauth2.jwtBearerRequireRegisteredIssuer` | `true` | Refuses an issuer nobody declared. |
| `oauth2.jwtBearerMaxLifetimeS` | `300` | The longest `exp − iat` accepted. |
| `oauth2.clientAssertionSkewS` | `60` | Clock skew allowed on assertion times. |

A person can also be an issuer, but only about themselves:
`POST /admin-api/pki/issue {"identifier":"alice","target":"person"}`, then
`iss` = `sub` = `alice`. Each assertion is accepted once, ever.

## SAML 2.0 bearer (RFC 7522)

A signed SAML 2.0 assertion is exchanged for an access token.
**Step-by-step instructions are in
[SAML assertions → the shortest path](saml-assertions.md).** The values below
are from `sts_saml2_bearer_grant.js`.

1. Create the application exactly as in [JWT bearer](#jwt-bearer-rfc-7523),
   step 2 (identifier `saml-assert-issuer-1`).
2. Give it a SAML signing key. In the console that is the **Credentials** tab,
   **Assertion key pairs → RFC 7522 — a SAML 2.0 assertion → Issue a key pair
   from this realm's CA**. Its private key is collected with `reveal-secret`
   naming `oauthSamlAssertionPrivateKey`.
   Through the API:
   ```bash
   api pki/issue '{"identifier":"saml-assert-issuer-1","purpose":"saml"}'
   ```
   To trust an identity provider's existing certificate instead, set
   `oauthSamlAssertionSigningCertificate` to it.
3. **Declare the `<Issuer>`, on the SAML attribute.** `oauthAssertionIssuer`
   is the JWT declaration and does not count here:
   ```bash
   api applications/add '{"application":"saml-assert-issuer-1",
     "attribute":"oauthSamlAssertionIssuer","value":"https://issuer.example.test/saml2bearer"}'
   ```

**Request.** It carries no client authentication:
```
POST /oauth2/token
  grant_type=urn:ietf:params:oauth:grant-type:saml2-bearer
  &assertion=<base64url of the signed XML>&scope=openid profile
```

The assertion must have:
* `Issuer` equal to the declared value, and `NameID` equal to the username;
* a bearer `SubjectConfirmation` whose `Recipient` is the token endpoint,
  with `NotOnOrAfter` about 120 s ahead;
* `Audience` equal to the token endpoint;
* an enveloped RSA-SHA256 signature.

The settings are `oauth2.saml2BearerGrant`, `…RequireRegisteredIssuer` and
`…MaxLifetimeS`, with the same defaults as the JWT settings.

## Token exchange (RFC 8693)

A client exchanges a token it holds for a token for another audience. The
exchange is a **delegation** (the result carries a nested `act` claim naming
the actor) or an **impersonation** (it does not), as the issuance policy
chooses — the request may ask with `exchange_semantics`. Who may do either is
decided by the same controls as WS-Trust and Kerberos: see
[Delegation and impersonation](delegation.md) for the model.

Taken from `sts_delegation_policy.js`.

**The applications.** The job makes every application a confidential client
declared for OAuth 2.0, OpenID Connect and WS-Trust, with its own URL as its
audience. `dp-back` is the target, `dp-mid` an intermediary that may delegate
to it, and `dp-mid2` one that may also impersonate:

```bash
for app in dp-back dp-mid dp-mid2; do
api applications/create '{"identifier":"'$app'","name":"'$app'",
  "protocols":["oauth2","oidc","wstrust"],
  "fields":{"oauthClientId":["'$app'"],"oauthClientSecret":"'"$SECRET"'",
            "oauthTokenEndpointAuthMethod":"client_secret_post",
            "oauthGrantType":["client_credentials",
                              "urn:ietf:params:oauth:grant-type:token-exchange"],
            "oauthAllowedScope":["api","openid"],
            "oauthAudience":["https://'$app'.example"],
            "wstrustAppliesTo":["https://'$app'.example"]}}'
done
```

**The policy:**
```bash
# a token issued for dp-mid may be handed on to dp-back …
api applications/add '{"application":"dp-mid","attribute":"appAllowedToDelegateTo","value":"dp-back"}'
# … and dp-mid2 may delegate or impersonate, as the request asks
api applications/add '{"application":"dp-mid2","attribute":"appDelegationSemantics","value":"delegation"}'
api applications/add '{"application":"dp-mid2","attribute":"appDelegationSemantics","value":"impersonation"}'
```

In the console these are on the application's **Configuration** tab, the
**Every protocol** sub-tab, under **Delegation / Impersonation**. A list there
opens a search of other applications (or of the realm's groups) when you work
in it, five results a page, each with an **Add**. Then click
**Save Every protocol**.

More controls can take part:
* `appAllowedToActOnBehalfOf`, on the **target**, lists the applications (and people) that may act toward it. The job sets it on `dp-back` for `dp-mid2` and a person.
* `appDelegationSubjectGroup`, on the actor, holds group DNs that limit whose tokens it may exchange.
* `appDefaultDelegationSemantics`, `appNotDelegated` and `appMayAct` on an application.
* The person's own settings: `POST /admin-api/users/set-not-delegated {"user","value":true}`, `POST /admin-api/users/set-may-act {"user","delegate":"<DN of a person or application>"}` and `POST /admin-api/users/set-delegation-semantics {"user","semantics":["delegation"],"default":"delegation"}`.

To read the whole policy back, use `GET /admin-api/delegation/policy`. In the
console, the delegated permissions are on **Protocols → Delegation**
(`/admin/delegation-settings`), and each act, with what development would
have refused, is on **Monitoring → Delegation** (`/admin/delegation`).

**Request:**
```
POST /oauth2/token
  grant_type=urn:ietf:params:oauth:grant-type:token-exchange
  &client_id=dp-mid&client_secret=<secret>
  &subject_token=<token>&subject_token_type=urn:ietf:params:oauth:token-type:access_token
  &audience=https://dp-back.example&scope=api
  [&exchange_semantics=delegation|impersonation]
  [&actor_token=<a token about the actor>
   &actor_token_type=urn:ietf:params:oauth:token-type:access_token]
```

**The actor_token must be the client's own, in both modes (#550).** It must
have been issued to the exchanging client: its `client_id` (or `azp`) is that
client, and a token carrying neither names the client in `aud`. Its `aud` must
also name this authorization server (its issuer or token endpoint) or the
exchanging client (its `client_id`, identifier or `oauthAudience`). A client's
own `client_credentials` token that asked for nothing else meets both. Anything
else is refused with `invalid_request`: another client's token, or a token
minted for some other resource, which that resource could replay as its own
actor.

**Modes.** Product mode enforces the policy, refusing with `invalid_request`
or `invalid_target`. It also verifies both tokens and refuses a scope wider
than the subject token's. Development mode issues the token anyway and records
on **Monitoring → Delegation** that it would have been refused. `may_act` is
enforced in both modes. Whether an exchange also returns a refresh token is set by
`oauth2.tokenExchangeRefreshToken` (`never`, `when-requested` (the default) or
`always`). The per-client override is `oauthTokenExchangeRefreshToken`.

### An assertion as the subject or actor token

A signed assertion from a declared issuer may be the `subject_token` or the
`actor_token` (#114). Taken from `sts_token_exchange_assertions.js`:

| Assertion | `subject_token_type` | The issuer's application needs |
|---|---|---|
| RFC 7523 JWT | `urn:ietf:params:oauth:token-type:jwt` | `oauthAssertionIssuer`, and a key: `pki/issue`, or the issuer's own keys in `oauthAssertionJwks` |
| RFC 7522 SAML 2.0 | `urn:ietf:params:oauth:token-type:saml2` | `oauthSamlAssertionIssuer`, and `pki/issue` with `"purpose":"saml"` |
| SAML 1.1 | `urn:ietf:params:oauth:token-type:saml1` | the same as SAML 2.0 |

```bash
api applications/add '{"application":"txa-jwt-idp","attribute":"oauthAssertionIssuer",
  "value":"https://txa-jwt-idp.example"}'
api applications/set '{"application":"txa-jwt-idp","attribute":"oauthAssertionJwks",
  "value":"{\"keys\":[<the issuer'"'"'s public JWK>]}"}'
```

```
POST /oauth2/token
  grant_type=urn:ietf:params:oauth:grant-type:token-exchange
  &client_id=txa-client&client_secret=<secret>
  &subject_token=<the JWS>&subject_token_type=urn:ietf:params:oauth:token-type:jwt
```

The assertion is checked as the assertion grant checks it, and spent in the
same one-use history: one used at the grant cannot then be exchanged, nor the
reverse. By default its audience must name this token endpoint or issuer.
`oauth2.tokenExchangeAudience` set to `any-declared-relying-party` also
accepts an audience naming an application registered in the realm. That is
token forwarding; read the setting's warning before turning it on.

[Native SSO](configure-oidc-flows.md#native-sso) is a form of token exchange
with an ID Token and a device secret.

## CIBA

With Client-Initiated Backchannel Authentication, a client asks for a named
person to be authenticated. The person approves on `/portal/ciba`, and the
client collects the tokens by polling or is notified. Taken from
`sts_ciba.js`.

**Setting** (**Protocols → OAuth 2.0 / OIDC**, **Global settings** tab):
```bash
api config/set '{"key":"oauth2.ciba","value":true}'
```

The other CIBA settings are `oauth2.cibaDefaultExpiryS` (120),
`oauth2.cibaMaxExpiryS` (600), `oauth2.cibaIntervalS` (5) and
`oauth2.cibaMaxPendingPerPerson` (5).

**Client:**
```bash
api applications/create '{"identifier":"ciba-poll","name":"ciba-poll",
  "protocols":["oauth2","oidc"],
  "fields":{"oauthClientId":"ciba-poll","oauthClientSecret":"'"$SECRET"'",
            "oauthTokenEndpointAuthMethod":"client_secret_post",
            "oauthGrantType":["urn:openid:params:grant-type:ciba"],
            "oauthAllowedScope":["openid"],
            "oauthBackchannelTokenDeliveryMode":"poll"}}'
```

A client with no delivery mode is refused with `unauthorized_client`. For the
other two delivery modes:
* **ping** or **push**: also set `oauthBackchannelClientNotificationEndpoint`,
  for example to `https://client.example.com/ping`.
* To make the client send a `user_code`, set
  `oauthBackchannelUserCodeParameter` to `TRUE`.

**Requests:**
```
POST /oauth2/bc-authorize
  client_id=ciba-poll&client_secret=<secret>&scope=openid&login_hint=alice
  [&binding_message=…][&client_notification_token=…]
→ auth_req_id, expires_in, interval

(alice approves on /portal/ciba)

POST /oauth2/token
  grant_type=urn:openid:params:grant-type:ciba&auth_req_id=<id>
  &client_id=ciba-poll&client_secret=<secret>
```

## Pre-authorized code (OpenID4VCI)

A credential offer carries a pre-authorized code, and a wallet exchanges it
for an access token to the credential endpoint:

```
POST /oauth2/token
  grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code
  &pre-authorized_code=<code>&tx_code=<PIN>
```

No application needs registering, because the offer is the grant. The
settings are `oid4vci.txCodeLength` (default 5) and `oid4vci.txCodeMaxAttempts`
(default 5). See [OpenID4VCI](oid4vci.md).

## Client authentication methods

`oauthTokenEndpointAuthMethod` names the methods: a checkbox per method on the
application's **OAuth 2.0 / OpenID Connect** sub-tab, and a list in the API (`applications/add` and
`applications/remove`, or an array in `create`). **A client may hold several**
— a secret and a key pair, say — and the token endpoint accepts whichever one
a request presents: a `client_assertion` is `private_key_jwt` or
`client_secret_jwt` (by its `alg` where both are held), an `Authorization:
Basic` header is `client_secret_basic`, a `client_secret` in the body is
`client_secret_post`, the attestation headers are the attestation methods and
a client certificate is `tls_client_auth` or `self_signed_tls_client_auth`.
**`none` cannot be held with any other method**, because it is what makes a
client public; a save that ticks it beside another is refused
(`STS-REG-0207`). Registration (RFC 7591) reports the first method held, since
its `token_endpoint_auth_method` is a single value. Each method needs something
more on the application:

| Method | What the application needs | How the client presents it | Job |
|---|---|---|---|
| `none` | nothing more (a public client) | `client_id` only; PKCE `S256` in product mode | `oauth_fixtures.js` |
| `client_secret_basic` | `oauthClientSecret` | `Authorization: Basic` | `sts_token_revocation.js` |
| `client_secret_post` | `oauthClientSecret` | `client_id` and `client_secret` in the body | `sts_scope_policy.js` |
| `client_secret_jwt` | `oauthClientSecret`; optionally `oauthTokenEndpointAuthSigningAlg` (`HS256`/`HS384`/`HS512`) | a client assertion with an HMAC signature, addressed to the issuer or the token endpoint. An `HS512` key must be at least 512 bits (RFC 7518 section 3.2). | `sts_client_authentication.js` |
| `private_key_jwt` | a key: `pki/issue` as in [JWT bearer](#jwt-bearer-rfc-7523), or `oauthJwks` or `oauthJwksUri` | `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`, with `iss` = `sub` = the client_id and `aud` = the token endpoint | `sts_jwt_bearer_grant.js` |
| `saml2_bearer` | `pki/issue` with `"purpose":"saml"` | `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:saml2-bearer`, with `Issuer` = `Subject` = the client_id | `sts_saml2_bearer_grant.js` |
| `tls_client_auth` | a certificate issued on its **Credentials** tab (**Mutual TLS (RFC 8705) → Issue a TLS client certificate from this realm's CA**; API: `applications/issue-tls-client-certificate`), or exactly one of `oauthTlsClientAuthSubjectDn`, `…SanDns`, `…SanUri`, `…SanIp`, `…SanEmail` | the certificate in the TLS handshake; the token is bound to it (`cnf.x5t#S256`) | `sts_client_authentication.js` (a certificate from this realm's CA), `tests/rfc8705_mtls.js` (the subject parameters) |
| `self_signed_tls_client_auth` | `oauthJwks` with `x5c`, or `oauthTlsClientCertificateThumbprint` | the certificate in the TLS handshake | `sts_client_authentication.js` (`x5c`), `tests/rfc8705_mtls.js` (thumbprint) |
| `attest_jwt_client_auth` | the realm setting `oauth2.clientAttestationTrustAnchors` or `…TrustedKeys` | the `OAuth-Client-Attestation` and `…-PoP` headers | `sts_client_attestation.js` |

**What development mode checks.** Outside RFC 9700 mode, development mode
observes a `client_secret_jwt` assertion without verifying its HMAC or its
`jti`, so a wrong secret or a replay is still issued a token there; product
mode refuses both. A registered `oauthTokenEndpointAuthSigningAlg` and both
RFC 8705 methods are checked in every mode. `sts_client_authentication.js`
asserts each of these in a development and a product realm.

[OAuth 2.0 and OpenID Connect → Client authentication](oauth-oidc.md)
describes every method in full.

## Client secrets

An application may hold several client secrets at once, each with its own
expiry, up to `oauth2.clientSecretsMax` (5). The token endpoint accepts any
one of them; product mode refuses one that has expired. The newest is the primary: it is the one this
service signs HS256 ID Tokens and JARM responses with.

**The first secret's lifetime is set on the create** (#394). On the
new-application form, type it in **Lifetime (days)** beside **Generate
Secret**. Through the API, give `lifetimeDays` beside `fields`:

```bash
api applications/create '{"identifier":"generate-secret-app","protocols":["oauth2"],
  "fields":{"oauthClientSecret":"'"$SECRET"'"},"lifetimeDays":30}'
```

The value is whole days, 0 to 730, and 0 never expires. Left out or empty, it
is `oauth2.clientSecretLifetimeDays`, which is 0 by default. A lifetime given
with no secret is refused. `tests/application_generate_secret.js` creates
with 30 and with 0.

**An application that exists** has its secrets on its **Credentials** tab,
under **Client secrets**: a table of the secrets held, each with its expiry
and a **Remove** button, and these forms:

| Console | API (`POST /admin-api/applications/…`) | What it does |
|---|---|---|
| **Lifetime (days)**, **Description**, **Add a client secret** | `add-secret` `{application, lifetimeDays?, description?}` | Mints a secret and adds it. The others keep working until their own expiry. |
| **Rotate the client secret** | `rotate-secret` `{application}` | Adds a new secret and moves every live one to expire after `oauth2.clientSecretOverlapS` (604800, seven days). |
| **Regenerate: replace every secret** (**Generate a client secret** when it holds none) | `regenerate-secret` `{application}` | Makes a new secret the only one. Every other secret stops working at once. |
| **Remove** on a row | `remove-secret` `{application, secret}` | Removes one secret by its id, at once. |

```bash
api applications/add-secret '{"application":"rv-a","lifetimeDays":30}'
```

The answer to each of the first three carries the new secret in
`clientSecret`. It is the one time the value is handed out. Afterwards a
`GET` shows each secret's id and expiry, never its value; `reveal-secret`
with the secret's id hands it back and writes an audit row.
`tests/client_secret_rotation.js` covers rotation, the cap and the lifetimes.

| Setting | Default | What it does |
|---|---|---|
| `oauth2.clientSecretLifetimeDays` | `0` | The lifetime of a secret when none is given. 0 never expires. |
| `oauth2.clientSecretOverlapS` | `604800` | How long a rotation leaves the old secrets working. 0 makes a rotation a regeneration. |
| `oauth2.clientSecretsMax` | `5` | How many secrets one application may hold (`STS-REG-0208` past it). |
| `oauth2.clientSecretExpiryWarningDays` | `14` | How far ahead the daily job `oauth2.client-secret-expiry` warns about a secret that is about to expire. |

## Related

* [OAuth 2.0 and OpenID Connect](oauth-oidc.md): every setting, and why.
* [Security profiles](oauth-security.md): RFC 9700, OAuth 2.1, DPoP, mTLS, FAPI.
* [Applications](applications.md): the registry these recipes write to.
* [Management API](management-api.md): the token, and the OpenAPI document at `/admin-api/openapi.json`.
* [Configuring OpenID Connect flows](configure-oidc-flows.md) and [Configuring SAML profiles](configure-saml.md).
