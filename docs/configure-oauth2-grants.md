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
`tests/vendored/`, and each recipe names the job it is taken from. Those jobs
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
| Register an application | **Applications → New application ›** (`/admin/applications/new`), then **Create the application** | `POST /admin-api/applications/create` with `{identifier, name, kind?, protocols, fields}` |
| Change one attribute of it | the application's page (`/admin/applications?application=<id>`), section **Change what it is allowed to do**: the **Set** form, then **Set** | `POST /admin-api/applications/set` with `{application, attribute, value}` (an empty value clears it) |
| Add or remove one value of a list attribute | same section: the **Add to** / **Remove from** forms, then **Add** / **Remove** | `POST /admin-api/applications/add` and `/remove`, with the same three members |
| Change a setting | the protocol's settings page, then the group's **Save <group>** button; **Reset** on a row puts that row back | `POST /admin-api/config/set` with `{key, value}`, `/config/set-many` with `{"<key>": value, …}`, `/config/reset` with `{key}` |

Settings are per [trust realm](trust-realms.md). A console page saves to the
realm it is shown in, and `/realm/<id>/admin-api/config/...` saves to that
realm. To give a new realm its settings from the start, use
`POST /admin-api/realms/create` with an `overrides` object. The OAuth 2.1 job
does this:

```bash
api realms/create '{"id":"r1","domain":"r1.example.net","name":"r1",
  "overrides":{"oauth2.oauth21":true,"oauth2.consentRequired":false}}'
```

**The new-application form lacks four attributes.** It does not offer
`oauthTokenEndpointAuthMethod`, `oauthGrantType`, `oauthScope` or
`oauthAllowedScope`. In the console, create the application first and then set
those in **Change what it is allowed to do**. Through the API they can all go
in `fields` on the create. If you give a client secret when you create the
application, the auth method becomes `client_secret_basic` unless you name
another.

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
* **Scopes in product mode come from `oauthAllowedScope`.** A scope that is
  not listed there is refused with `invalid_scope`. If the list is empty,
  product mode issues only the standard set: `openid profile email address
  phone offline_access`, plus the realm's OpenID4VCI scopes. This service's
  own protected scopes (`admin:*`, `scim:*`, the Shared Signals and debugger
  scopes) must be listed in **both** modes.
* **`oauthGrantType` restricts the client, in both modes.** The token
  endpoint refuses any grant the list does not name with `unauthorized_client`,
  whether the list came from a dynamic registration (RFC 7591 `grant_types`) or
  an administrator. A client whose list omits `refresh_token` is issued no
  refresh token. An empty list restricts nothing. What a client has actually
  used is recorded separately, in `oauthGrantTypeObserved`.
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
(300 s by default) and can be used only once. `oauth2.codeReplayIdempotent`
relaxes that rule, and is off by default.

### A public client (a browser or native app)

Taken from `oauth_fixtures.js` and `oauth2_sts_endpoints.js`.

**Console:**
1. **Applications → New application ›**.
2. Under **What it is called**, set **Identifier** to `sts-endpoint-test-client-native` (the name is optional).
3. Under **Protocol families it is declared for**, tick **OAuth 2.0** and **OpenID Connect**.
4. In **Where responses go back to**, enter `com.example.oauth2stsendpoints:/callback`, one URI per line.
5. Click **Create the application**.
6. On the application's page, in **Change what it is allowed to do**:
   - **Tick** `none` under `oauthTokenEndpointAuthMethod`, and nothing else.
   - **Set** `oauthConfidential` to `FALSE`.
   - **Add to** `oauthGrantType` the values `authorization_code` and `refresh_token`.
   - **Add to** `oauthAllowedScope` the values `openid`, `profile` and `email`.

**API:**
```bash
api applications/create '{
  "identifier": "sts-endpoint-test-client-native",
  "name": "sts-endpoint-test-client-native",
  "protocols": ["oauth2", "oidc"],
  "fields": {
    "oauthClientId": "sts-endpoint-test-client-native",
    "oauthRedirectUri": ["com.example.oauth2stsendpoints:/callback"],
    "oauthResponseType": ["code"],
    "oauthGrantType": ["authorization_code", "refresh_token"],
    "oauthScope": ["openid", "profile", "email"],
    "oauthAllowedScope": ["openid", "profile", "email"],
    "oauthTokenEndpointAuthMethod": "none",
    "oauthConfidential": "FALSE"
  }}'
```

### A confidential client (a web server)

Taken from `sts_token_revocation.js`.

**Console:** create the application as for the public client above, with
**Identifier** `rv-a` and redirect URI `https://rp.revoke.example.test/cb`. In
**The client secret**, click **Generate Secret**, and copy the value before
you create the application. Then, on the application's page:
- **Tick** `client_secret_basic` under `oauthTokenEndpointAuthMethod`, and nothing else.
- **Add to** `oauthAllowedScope` the value `openid`.

An application that already exists gets a secret from the **Credentials →
Client secret** button: **Generate a client secret**, or **Regenerate the
client secret**.

**API:**
```bash
SECRET=$(openssl rand -base64 32)
api applications/create '{
  "identifier": "rv-a", "name": "rv-a", "kind": "oauth2-client",
  "protocols": ["oauth2"],
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

**Settings** (console: **OAuth 2.0 / OIDC settings**, `/admin/oauth2`):

| Setting | Default | Why you would change it |
|---|---|---|
| `oauth2.rfc9700` | `false` | Turns on RFC 9700 mode in development. Product mode implies it. |
| `oauth2.oauth21` | `false` | Turns on OAuth 2.1 mode, which implies RFC 9700 mode. |
| `oauth2.consentRequired` | `true` | Asks the person to approve each client. |
| `oauth2.authorizationCodeTtlS` | `300` | Sets how long a code is valid. |

## Client credentials

A service gets a token for itself. No person is involved, and no refresh
token or ID Token is issued. The token's `sub` is the client_id; in RFC 9700
mode, and so in product, it is `urn:sts:client:<client_id>`.

Taken from `sts_scope_policy.js` and `oauth2_sts_endpoints.js`.

**Console:**
1. Create the application: **Identifier** `svc`, tick **OAuth 2.0**, and
   generate a secret in **The client secret**. No redirect URI is needed.
2. On its page:
   - **Tick** `client_secret_post` under `oauthTokenEndpointAuthMethod`, and nothing else.
   - **Add to** `oauthGrantType` the value `client_credentials`.
   - **Add to** `oauthAllowedScope` each scope it may be issued, for example `api`.

**API:**
```bash
api applications/create '{
  "identifier": "svc", "name": "svc", "kind": "oauth2-client",
  "protocols": ["oauth2"],
  "fields": {
    "oauthClientId": ["svc"],
    "oauthClientSecret": "'"$SECRET"'",
    "oauthGrantType": ["client_credentials"],
    "oauthTokenEndpointAuthMethod": "client_secret_post"
  }}'
api applications/add '{"application":"svc","attribute":"oauthAllowedScope","value":"api"}'
```

**Request:**
```
POST /oauth2/token
  grant_type=client_credentials&client_id=svc&client_secret=<secret>&scope=api
  [&resource=https://api.example.com]
```

In product mode, a scope not listed in `oauthAllowedScope` is refused with
`invalid_scope`, and a public client (auth method `none`) is refused this
grant with `unauthorized_client`. The seeded `sts-management-api` client is a
working example of this grant.

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

**Settings.** The lifetimes are on **Token lifetimes** (`/admin/token-lifetimes`,
button **Save lifetimes**; API: `POST /admin-api/token-lifetimes/set`). The
other settings are on `/admin/oauth2`.

| Setting | Default | What it does |
|---|---|---|
| `oauth2.refreshTokenTtlS` | `86400` | The refresh token's absolute lifetime. |
| `oauth2.refreshIdleSeconds` | `86400` | How long an unused refresh token stays valid, in RFC 9700 mode only. |
| `oauth2.revokeRefreshOnLogout` | `true` | Signing out ends the person's refresh tokens. |
| `oauth2.refreshTokenRotation` | `false` | Issues a new refresh token on each use. Rotation is already on in RFC 9700, OAuth 2.1, FAPI and product mode. A replayed refresh token revokes the whole family. |
| `oauth2.refreshTokenRequireDpop` / `…RequireMtls` | `false` | Requires the refresh token to be sender-constrained. |
| `oauth2.refreshRequiresConsent` | `true` | Requires a consent record for the refresh. |

**Per-client overrides.** Each application can override the lifetimes. Use
**Set** on its page, the **What OAuth 2.0 / OIDC issues for this client**
section of the new-application form, or the API:

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
  "password":"<password>","attributes":{"cn":"Alice","sn":"A","mail":"alice@example.com"}}'
```

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

**Settings** (on `/admin/oauth2`; the values are from `sts_device_key_binding.js`):

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
`urn:ietf:params:oauth:grant-type:device_code` to `oauthGrantType`. No test job
covers that path yet.

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

1. The realm needs a certificate authority. In the console that is **PKI**
   (`/admin/pki`). Through the API:
   ```bash
   api pki/build '{"organisation":"Assertion Test","country":"US"}'
   ```
2. Create the application that holds the issuer's key:
   ```bash
   api applications/create '{"identifier":"assert-issuer-1","name":"assert-issuer-1",
     "protocols":["oauth2"],
     "fields":{"oauthClientId":"assert-issuer-1","oauthClientSecret":"'"$SECRET"'",
               "oauthTokenEndpointAuthMethod":"client_secret_post"}}'
   ```
3. Give it a key. In the console, on the application's page, open
   **Credentials → RFC 7523 — a JWT assertion** and click **Issue a key pair
   from this realm's CA** (fields **Key algorithm** and **Days**), or use
   **Upload the certificate** for a key you already hold. Through the API:
   ```bash
   api pki/issue '{"identifier":"assert-issuer-1"}'
   ```
   The reply contains the `kid` (`app-…`), and the private key is at
   `GET /admin-api/applications?application=assert-issuer-1`, in
   `oauthAssertionPrivateKey`.
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

**Settings** (on `/admin/oauth2`):

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
2. Give it a SAML signing key. In the console that is **Credentials → RFC
   7522 — a SAML 2.0 assertion → Issue a key pair from this realm's CA**.
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

**The target and the intermediary** (console: create both with
**New application ›**, then use the attribute editor):

```bash
api applications/create '{"identifier":"dp-back","name":"dp-back",
  "protocols":["oauth2","wstrust"],
  "fields":{"oauthClientId":"dp-back","oauthAudience":["https://dp-back.example"],
            "wstrustAppliesTo":["https://dp-back.example"]}}'

api applications/create '{"identifier":"dp-mid","name":"dp-mid","protocols":["oauth2"],
  "fields":{"oauthClientId":["dp-mid"],"oauthClientSecret":"'"$SECRET"'",
            "oauthTokenEndpointAuthMethod":"client_secret_post",
            "oauthGrantType":["client_credentials",
                              "urn:ietf:params:oauth:grant-type:token-exchange"],
            "oauthAllowedScope":["api","openid"]}}'
```

**The policy:**
```bash
# a token issued for dp-mid may be handed on to dp-back …
api applications/add '{"application":"dp-mid","attribute":"appAllowedToDelegateTo","value":"dp-back"}'
# … and dp-mid may also impersonate, when the request asks for it
api applications/add '{"application":"dp-mid","attribute":"appDelegationSemantics","value":"delegation"}'
api applications/add '{"application":"dp-mid","attribute":"appDelegationSemantics","value":"impersonation"}'
```

More controls can take part:
* `appAllowedToActOnBehalfOf`, on the **target**, lists the applications (and people) that may act toward it.
* `appDelegationSubjectGroup`, on the actor, holds group DNs that limit whose tokens it may exchange.
* `appDefaultDelegationSemantics` and `appNotDelegated` on an application.
* The person's own settings: `POST /admin-api/users/set-not-delegated {"user","value":true}`, `POST /admin-api/users/set-may-act {"user","delegate":"<application DN>"}` and `POST /admin-api/users/set-delegation-semantics {"user","semantics":["delegation"],"default":"delegation"}`.

To read the whole policy back, use `GET /admin-api/delegation/policy`; in the
console it is `/admin/delegation`.

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

**Modes.** Product mode enforces the policy, refusing with `invalid_request`
or `invalid_target`. It also verifies both tokens and refuses a scope wider
than the subject token's. Development mode issues the token anyway and records
on `/admin/delegation` that it would have been refused. `may_act` is enforced
in both modes. Whether an exchange also returns a refresh token is set by
`oauth2.tokenExchangeRefreshToken` (`never`, `when-requested` (the default) or
`always`). The per-client override is `oauthTokenExchangeRefreshToken`.

[Native SSO](configure-oidc-flows.md#native-sso) is a form of token exchange
with an ID Token and a device secret.

## CIBA

With Client-Initiated Backchannel Authentication, a client asks for a named
person to be authenticated. The person approves on `/portal/ciba`, and the
client collects the tokens by polling or is notified. Taken from
`sts_ciba.js`.

**Setting** (on `/admin/oauth2`):
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
            "oauthScope":["openid"],
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
application's page, and a list in the API (`applications/add` and
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
| `client_secret_jwt` | `oauthClientSecret`; optionally `oauthTokenEndpointAuthSigningAlg` (`HS256`/`HS384`/`HS512`) | a client assertion with an HMAC signature | `sts_oidc_core.js` |
| `private_key_jwt` | a key: `pki/issue` as in [JWT bearer](#jwt-bearer-rfc-7523), or `oauthJwks` or `oauthJwksUri` | `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`, with `iss` = `sub` = the client_id and `aud` = the token endpoint | `sts_jwt_bearer_grant.js` |
| `saml2_bearer` | `pki/issue` with `"purpose":"saml"` | `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:saml2-bearer`, with `Issuer` = `Subject` = the client_id | `sts_saml2_bearer_grant.js` |
| `tls_client_auth` | a certificate issued on its page (**Credentials → Mutual TLS (RFC 8705) → Issue a TLS client certificate from this realm's CA**; API: `applications/issue-tls-client-certificate`), or exactly one of `oauthTlsClientAuthSubjectDn`, `…SanDns`, `…SanUri`, `…SanIp`, `…SanEmail` | the certificate in the TLS handshake | `tests/rfc8705_mtls.js` |
| `self_signed_tls_client_auth` | `oauthJwks` with `x5c`, or `oauthTlsClientCertificateThumbprint` | the certificate in the TLS handshake | `tests/rfc8705_mtls.js` |
| `attest_jwt_client_auth` | the realm setting `oauth2.clientAttestationTrustAnchors` or `…TrustedKeys` | the `OAuth-Client-Attestation` and `…-PoP` headers | `sts_client_attestation.js` |

Two more ways to manage secrets:
* **Rotate the client secret** (API: `applications/rotate-secret`) keeps the
  old secret working for `oauth2.clientSecretOverlapS`, which is seven days
  by default.
* **Regenerate** (`applications/regenerate-secret`) ends the old secret at
  once.

[OAuth 2.0 and OpenID Connect → Client authentication](oauth-oidc.md)
describes every method in full.

## Related

* [OAuth 2.0 and OpenID Connect](oauth-oidc.md): every setting, and why.
* [Security profiles](oauth-security.md): RFC 9700, OAuth 2.1, DPoP, mTLS, FAPI.
* [Applications](applications.md): the registry these recipes write to.
* [Management API](management-api.md): the token, and the OpenAPI document at `/admin-api/openapi.json`.
* [Configuring OpenID Connect flows](configure-oidc-flows.md) and [Configuring SAML profiles](configure-saml.md).
