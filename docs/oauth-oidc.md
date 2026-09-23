---
title: OAuth 2.0 & OpenID Connect
---

# OAuth 2.0 and OpenID Connect

iya-sts is a full **OAuth 2.0 authorization server**
([RFC 6749](https://www.rfc-editor.org/rfc/rfc6749)) and **OpenID Connect
provider** ([OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)),
with the extensions around them: discovery, PKCE, dynamic registration, token
exchange, pushed and JWT-secured authorization requests, rich authorization
requests, introspection, revocation, JWT access tokens and both OpenID Connect
logout notifications. Every trust realm is its own authorization server, with
its own issuer, keys, clients, codes and tokens, and one realm (or one process)
can publish several named authorization servers side by side.

It is **permissive by default**, because it exists to exercise clients. The
compliance modes, sender constraints and step-up authentication that make it
strict are on their own page: [OAuth security](oauth-security.md).

## Features

### Discovery and keys

Both discovery documents are served, built from one object so they cannot
disagree:

* `/.well-known/oauth-authorization-server`
  ([RFC 8414](https://www.rfc-editor.org/rfc/rfc8414)), and
* `/.well-known/openid-configuration`
  ([OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)).

For an issuer with a path, both shapes are answered: RFC 8414 *inserts* the
path after the well-known segment (`/.well-known/openid-configuration/tenant1`)
and OpenID Connect Discovery *appends* it
(`/tenant1/.well-known/openid-configuration`). That difference is the usual
reason a discovery fetch 404s.

**Discovery follows the realms on the one listener.** An issuer here is
`https://host[/realm/<id>][/<server>]`: a [trust realm](trust-realms.md), and
optionally a named authorization server inside it. Both shapes read that
path, and the document comes from the realm it names, with the realm's issuer,
keys and endpoints:

| Issuer | Inserted (RFC 8414) | Appended (OIDC Discovery) |
|---|---|---|
| `https://host/realm/acme` | `/.well-known/openid-configuration/realm/acme` | `/realm/acme/.well-known/openid-configuration` |
| `https://host/realm/acme/t1` | `/.well-known/openid-configuration/realm/acme/t1` | `/realm/acme/t1/.well-known/openid-configuration` |

`oauth-authorization-server` takes the same paths. A path that names no issuer
(an unknown realm, or more than one segment after the realm) is a 404, and it
creates no authorization server.

**WebFinger** (Discovery section 2) is at `/.well-known/webfinger` on the host
root and answers for every realm:

* `acct:alice@acme.example`, `alice@acme.example` or a host `acme.example`
  resolve to the realm whose DNS domain it is. The default realm's domain is
  `global.domain`. The person is never looked up, so WebFinger cannot be used
  to find out whether an account exists. An unknown domain is a 404.
* An `https` URL on this service resolves by its path:
  `https://host/realm/acme` is realm acme's issuer.

```bash
curl -s 'https://localhost:8081/.well-known/webfinger?resource=acct:alice@acme.example&rel=http://openid.net/specs/connect/1.0/issuer'
```

The answer is a JRD (`application/jrd+json`) with the issuer link, and it
carries `Access-Control-Allow-Origin: *`, as RFC 7033 section 5 asks. It is
the one response exempt from the CORS allowlist (`global.corsOrigins` and each
application's `appCorsOrigin`), because it holds nothing but a public URL.

The signing keys are at `/oauth2/jwks`. Both documents carry a
`signed_metadata` member (RFC 8414 section 2.1), signed once and reused while
the document is unchanged. The issuer is the base URL the request arrived on
unless `oauth2.issuer` pins it, so one process answers correctly as
`localhost`, under a compose service name and through a published port.
`global.publicBaseUrl` fixes the base for a deployed service.

**What a document says, this server does.** Where a feature is switched off,
the member that advertises it is removed. A document never lists a grant,
response type or endpoint that would be refused.

### Flows and response types

* **Authorization code**, with **PKCE**
  ([RFC 7636](https://www.rfc-editor.org/rfc/rfc7636), `S256` and `plain`).
* **Implicit and hybrid**: every combination of `code`, `token` and
  `id_token`, including `id_token token`.
* **Response modes** `query`, `fragment` and `form_post`. `form_post` is
  answered with a self-submitting form that also has a real submit button.
  Without an explicit mode, `code` alone answers in the query and every
  response type that returns a token or an ID Token answers in the fragment
  ([Multiple Response Type Encoding
  Practices](https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html)
  section 2.1). **An error goes where the success would have gone**, so an
  implicit or hybrid request gets its error in the fragment. An explicit
  `response_mode=query` is ignored for a response type that returns a token.
* **JWT-secured responses (JARM)**: the response modes `query.jwt`,
  `fragment.jwt`, `form_post.jwt` and `jwt` (a query for `code`, a fragment
  otherwise) answer with one `response` parameter, a JWT carrying what the
  response would have carried plus `iss`, `aud` and `exp`. It is signed with
  the client's `authorization_signed_response_alg` (RS256 by default, PS256
  under FAPI 1.0 Advanced), and encrypted to its `jwks` where it registered
  `authorization_encrypted_response_alg`. Errors are answered the same way.
  `query.jwt` is refused with a token or ID Token in clear.
* A hybrid response's ID Token carries **`s_hash`** as well as `c_hash`
  whenever the client sent `state` (FAPI 1.0 Advanced's detached signature).
* The **`iss` authorization response parameter**
  ([RFC 9207](https://www.rfc-editor.org/rfc/rfc9207)) is on every
  authorization response, errors included.
* `prompt=none`, `prompt=login`, `prompt=select_account` (the sign-in screen,
  where whoever signs in is the account selected) and `prompt=consent` for the
  consent screen (below). `none` combined with any other value is refused
  `invalid_request`.
* **OpenID Connect requests need `openid`.** A response type that returns an
  ID Token is refused `invalid_scope` without the `openid` scope. A request
  with no scope gets no scope; it is not given `openid`.
* **The implicit flow** (`id_token`, `id_token token`) requires a `nonce` and
  refuses an `http` redirect URI that is not a loopback address, in every mode
  (OpenID Connect Core section 3.2.2.1).
* **`id_token_hint`** is verified as an ID Token this authorization server
  issued to the client, with any of its signing algorithms; an expired one is
  still a valid hint, and an encrypted one is refused. If the person signed in
  is not the one it names, `prompt=none` answers `login_required` and
  otherwise the person is asked to sign in again.
* **`display`** (`page`, `popup`, `touch`), **`ui_locales`** and
  **`claims_locales`** are accepted. There is one sign-in page and it is in
  English, so each is answered in English, which the specification permits.

The authorization endpoint takes **`GET` and `POST`** `/oauth2/authorize`; a
POST carries the request form-serialized (`application/x-www-form-urlencoded`,
OpenID Connect Core section 3.1.2.1). When nobody is signed
in, it hands the browser to the sign-in service
([Authentication](authentication.md)) and continues when the person comes back.
Every protocol here shares that one session.

### Grants at the token endpoint

`POST /oauth2/token` performs every grant its metadata advertises:

| Grant | Notes |
|---|---|
| `authorization_code` | PKCE, DPoP and certificate binding are checked before the code is spent. In every mode the code is redeemed only by the client it was issued to, and `redirect_uri` must be sent and identical to the authorization request's |
| `refresh_token` | carries the scope, resources and authorization details it was granted, and never widens them. Without `offline_access` it is an **online** refresh token and is refused once the sign-on session it came from has ended |
| `client_credentials` | for a client acting in its own name |
| `password` | development mode only (see below) |
| `urn:ietf:params:oauth:grant-type:token-exchange` | [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) |
| `urn:ietf:params:oauth:grant-type:jwt-bearer` | [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523) section 2.1 — see [JWT assertions](jwt-assertions.md) |
| `urn:ietf:params:oauth:grant-type:saml2-bearer` | [RFC 7522](https://www.rfc-editor.org/rfc/rfc7522) section 2.1 — see [SAML assertions](saml-assertions.md) |
| `urn:ietf:params:oauth:grant-type:pre-authorized_code` | OpenID4VCI — see [OpenID4VCI](oid4vci.md) |

**Resource indicators** ([RFC 8707](https://www.rfc-editor.org/rfc/rfc8707))
are read for every grant, repeated or not. A scope that names another
application's `client_id` also becomes the token's audience, and a scope naming a
**delegated permission** (a resource application's base URI plus a permission
name, such as `https://example.com/write`) addresses the token to that base URI
and puts the bare permission name in `scope`. **A token for an API is for that
API alone.** The OpenID Connect scopes are left off it, so a client that wants
UserInfo asks for a separate token.

**A redeemed code is replayed, not refused, outside the compliance modes.** An
identical repeat of the token request, made while the code would still have been
valid, gets the same token set back. A different request is refused, and the
refusal names the field that differs. RFC 9700 mode refuses the repeat and
revokes what the code bought.

### Client authentication

Every method in `token_endpoint_auth_methods_supported` is verified when there
is something to verify against: `client_secret_basic`, `client_secret_post`,
`client_secret_jwt`, `private_key_jwt`, `tls_client_auth`,
`self_signed_tls_client_auth`, and `saml2_bearer` (this service's own name for
RFC 7522 section 2.2, which registers none). `none` declares a public client.
A method this service cannot verify is refused rather than waved through. A
client that registered **`token_endpoint_auth_signing_alg`** has an assertion
signed with any other algorithm refused `invalid_client`, in every mode (OpenID
Connect Core section 9).

**Redirect URIs.** A client with redirect URIs of its own is held to an exact
match against them in every mode (OpenID Connect Core section 3.1.2.1). A
`client_id` with nothing registered is accepted with any redirect URI in
development mode only; product mode refuses an unregistered client.

A client's keys come from its registered JWKS, from key pairs this service's
certificate authority issued it, or from an `x5c` chain to this realm's Root.
**A registered `jwks_uri` is fetched** when a key is needed, under the
outbound policy (https, no redirects, a size cap, internal addresses refused in
product mode). The key set is cached for `oauth2.clientJwksCacheS` and fetched
again for an unknown `kid` at most every `oauth2.clientJwksRefetchS`. The mutual TLS methods are
described in [OAuth security](oauth-security.md#mutual-tls-rfc-8705).

**Client secrets expire and rotate.** A secret past `oauthClientSecretExpiresAt`
(or the registration's `client_secret_expires_at`) is refused in product mode.
**Rotate secret** keeps the old secret working for `oauth2.clientSecretOverlapS`
beside the new one, and **Regenerate secret** ends it at once. A daily scheduler
job warns about secrets that are close to expiry.

### Consent

`GET /oauth2/consent` is drawn the first time a person signs in to an
application for a scope they have not agreed to. Nothing is issued until they
choose **Allow**; **Deny** returns `access_denied`. The answer is written as
`oauthConsent` on the person's own directory entry, one value per (person,
application, scope), so later sign-ins are silent and an `ldapsearch` shows what
was agreed. `oauthGlobalConsent` on an application's entry consents a scope for
everybody without recording anything about anybody. `prompt=consent` asks again,
and `prompt=none` with something outstanding answers `consent_required`.

**`offline_access`** (OpenID Connect Core section 11) is honoured only for a
response type that returns a code, and only with `prompt=consent` or a recorded
consent to `offline_access` for that client. Otherwise it is removed from the
grant. A refresh token issued with it outlives the sign-on session; one issued
without it is refused after the session ends. A recorded consent counts even
with `oauth2.consentRequired` off.

This service's own console, portal and embedded debugger ask for
`offline_access`, and their seeded consent grants it. That is what lets a
console stay signed in after the sign-on session times out (up to the refresh
token's lifetime). Signing out still ends them and revokes their refresh
tokens. Remove `offline_access` from an application's global consent on
`/admin/applications` to turn this off.

Consent is **on by default** (`oauth2.consentRequired`). Turning it off means
nothing is asked and nothing is recorded; it does not mean everybody consented.
The token endpoint never asks anything, so a grant that was already issued is
not judged again. `/admin/consent` is the register.

### Scopes a client may be issued

A client is issued only the scopes it **declares** (#110). The list is
`oauthAllowedScope` on its application entry — RFC 7591 section 2's `scope`,
written there by a registration, returned by the registration and by RFC 7592's
read, and edited on the application's console page or with
`POST /admin-api/applications/add` and `remove`. `oauthScope` beside it only
records what the client has asked for.

* **This service's own protected scopes** — `admin:read`, `admin:write`, the
  SCIM scopes (`scim.scopeRead`, `scim.scopeWrite`), the Shared Signals scopes
  (`ssf.authScopeRead`, `ssf.authScopeWrite`) and the embedded debugger's
  permission — are issued only to a client that lists them, **in both modes**.
  `/admin-api`, SCIM and Shared Signals ask again on every call, so withdrawing
  a declaration cuts off tokens already issued. A registration cannot declare
  one (`invalid_client_metadata`); an administrator does. The seeded
  `sts-management-api` and `sts-admin-console` declare the admin scopes.
* **Every other scope, in product mode**, is issued only when the list names it.
  A client with **no list** has the default set: `openid`, `profile`, `email`,
  `address`, `phone`, `offline_access` and this realm's OpenID4VCI credential
  scopes. In development any scope is issued.
* **A scope naming another application or a delegated permission** keeps its own
  rules: the first becomes the access token's audience, the second needs a grant
  (`oauthDelegatedPermission`), which product mode always requires.

The authorization, pushed authorization and token endpoints refuse anything else
with `invalid_scope` (RFC 6749 section 3.3). A grant that carries its scope from
earlier — a refresh, a token exchange inheriting the subject token's scope, an
assertion grant — is issued without the scope instead, and the token response's
`scope` says what was issued.

### ID Tokens

An ID Token carries `nonce`, `at_hash` and `c_hash` in all three flows, plus
`auth_time`, `amr` and `acr` where an authentication is behind it; `auth_time`
is left out when the time is not known rather than set to the issue time. A
refreshed ID Token keeps the **original** `auth_time`, `amr` and `acr` (OpenID
Connect Core section 12.2). An ID Token issued on a browser session carries
`sid` while either logout notification is on.

* **`at_hash` and `c_hash`** use the hash of the ID Token's own `alg`:
  SHA-256 for the 256 algorithms, SHA-384 for the 384 ones and SHA-512 for the
  512 ones. Where the specification names no hash, this service uses the hash
  of the same security level: SHA-512 for EdDSA (Ed25519), SHA-256, SHA-384
  and SHA-512 for ML-DSA-44, -65 and -87, SHA-256 for the SLH-DSA 128-bit sets,
  and a composite algorithm's traditional half (SHAKE256 with a 114-byte output
  for the Ed448 composite).
* **Profile claims** (`name`, `email` and the rest of section 5.4's scopes) are
  in the ID Token **only for `response_type=id_token`**, where there is no
  access token to fetch them with. Every other flow gets them from UserInfo, or
  in the ID Token by naming them in a `claims` request.

* **Signing**: a client may register `id_token_signed_response_alg`. Every
  algorithm in this service's table is offered, the post-quantum ones included.
* **Encryption** (OpenID Connect Core section 10.2): a client that registers
  `id_token_encrypted_response_alg` gets a signed-then-encrypted token,
  encrypted to a key in its **inline** `jwks`. Only asymmetric key management
  is offered. A registration with no key to encrypt to is refused, and so is
  an issuance that cannot be encrypted. It is never sent in the clear.
* **Subject**: `sub` is `urn:uuid:<entryUUID>` of the person's directory entry,
  the same for every `public` client. A renamed person keeps their `sub`. A
  person deleted and re-created under the same name is a different subject.
* **Pairwise subjects** (OpenID Connect Core section 8): a client registered
  with `subject_type=pairwise` (the `oauthSubjectType` attribute) is given a
  `sub` of its own, derived from the person, the client's **sector** and a
  secret every node shares (`STS_OIDC_PAIRWISE_SECRET` pins it). The sector is
  the host of `sector_identifier_uri` (`oauthSectorIdentifierUri`) or, without
  one, the host all the client's redirect URIs share. A registration that
  names a `sector_identifier_uri` has it fetched once, and it must serve a
  JSON array listing every redirect URI; a value an administrator writes on
  the console is not fetched. UserInfo and Logout Tokens name the same
  pairwise `sub` as the ID Token.

### UserInfo and the claims request

`GET` or `POST /oauth2/userinfo` answers from four layers, later ones winning:

1. the configured **UserInfo claim set** (`/admin/userinfo-claims`),
2. the scope-driven claims of OpenID Connect Core section 5.4 (`profile`,
   `email`, `address` and `phone`, each claim from the person object or the
   directory entry, absent when neither holds it),
3. the claims named individually in an OpenID Connect Core section 5.5
   **`claims` request**, read from the person's directory entry,
4. `sub`, which is always set last.

A `claims` request is parsed at the authorization endpoint (a malformed one is
refused `invalid_request` there), carried **inside the access token** and
honoured in the ID Token (`id_token` member) and at UserInfo (`userinfo`
member). A refresh keeps it. An **`acr` marked `essential` with `value` or
`values` is a requirement**, met or refused like `acr_values` (section
5.5.1.1). For every other claim, `essential`, `value` and `values` are carried
and **not enforced**: an unavailable claim is left out and logged, and a value
that does not match is answered with the value this service holds.

UserInfo takes the access token in the `Authorization` header or, on a
form-encoded `POST`, as an `access_token` body parameter (RFC 6750 section
2.2). Sending both is refused.

As a debugging aid that no specification defines, UserInfo also accepts
`?claims={json}` and repeated `?claim=name` on the request itself. These are a
**union** with what the token carries and can never remove a claim from it.

A client may register `userinfo_signed_response_alg` and
`userinfo_encrypted_response_alg` for a signed or encrypted response. UserInfo
verifies the token it is given (signature, type, revocation and the `openid`
scope) and refuses a token that another issuer signed.

### Custom claims — `/admin/claims`

**Protocols → OAuth2 / OIDC → Custom claims** says what to add to every access
token and every ID Token issued **from now on**. There are two sets because the
two tokens go to different readers (a resource server and a client). Each set
takes typed claims, LDAP attribute types ticked from those found under
`ou=users`, and the groups claim.

Custom claims are **additive only**. A name the protocol sets itself (`exp`,
`scope`, `iss` and the rest) is refused when you configure it, because a
setting like that would produce tokens that fail to verify. Nothing already
issued changes. The page shares one store with **Custom SAML attributes**
(`/admin/saml-attributes`), which holds the SAML 2.0 and SAML 1.1 sets. The API
is `/admin-api/claims`.

### UserInfo claims — `/admin/userinfo-claims`

**Protocols → OAuth2 / OIDC → UserInfo claims** configures the same kind of
set for the UserInfo response. The response is built on **every call**, so a
claim added here reaches a client that signed in an hour ago, with no new
sign-in. It is the one claim set a client can add to, through the section 5.5
`claims` request above. `claims_supported` in discovery deliberately does not
try to follow these runtime changes. `GET /admin-api/userinfo-claims` gives the
live list of claims a request may name.

### Token lifetimes — `/admin/token-lifetimes`

**Protocols → OAuth2 / OIDC → Token lifetimes** holds the four timing
settings (see [Configuration](configuration.md#the-four-token-lifetimes)):

| Setting | Default |
|---|---|
| `oauth2.accessTokenTtlS` | one hour |
| `oauth2.idTokenTtlS` | one hour, separate from the access token |
| `oauth2.refreshTokenTtlS` | twenty-four hours |
| `oauth2.clockSkewS` | 30 seconds, applied wherever this service reads back its own tokens and on every console screen |

Each lifetime is a whole number of thirty-second units, and a change reaches
the **next** token only. To take a token that was already issued out of
circulation, revoke it. Give the access token and the ID Token different
lifetimes to see which one a client actually notices. The page also carries the
per-client settings a client may override on its own entry: the three
lifetimes, and RFC 9700 mode's refresh idle timeout and revoke-on-logout.
`/admin-api/token-lifetimes` and `POST /admin-api/token-lifetimes/set` are the
same controls.

### Refresh tokens

Every refresh token is a **nested JWT**: signed, then encrypted as a JWE to this
realm's own keys, so it is opaque to the client. It opens only in the realm that
minted it. A refresh token that was not encrypted is refused. A refresh
**hands on the grant it was given**: narrowing `scope` or `resource` narrows the
new access token, and the rotated refresh token still carries the whole grant.
Rotation with replay detection belongs to [OAuth security](oauth-security.md).

### JWT access tokens (RFC 9068)

Every access token is a [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068) JWT
access token, **in every mode**: header `typ: at+jwt`, the seven required claims,
`preferred_username` for a person, and `auth_time`, `amr` and `acr` where an
authentication is behind the grant. Every resource server here (UserInfo, the
OpenID4VCI endpoints, SCIM, Shared Signals, `/admin-api` and the embedded
debugger) applies section 4: the type, an issuer this service publishes **at
the request's address**, and itself in `aud`, compared as the whole URL. A token
minted at `localhost` is therefore refused at `127.0.0.1`. Set
`global.publicBaseUrl` for a service reached under several names. Scopes naming
two APIs, or an API the request did not address, are refused (section 3).

Access and refresh tokens are signed **RS256** by default.
`oauth2.accessTokenSigningAlg` chooses another algorithm this realm holds a key
for (`PS256`, `ES256`, `EdDSA` and the rest of the RSA and elliptic-curve
table), and a named authorization server can set its own
`access_token_signing_alg`. Under FAPI 1.0 Advanced the default is **PS256**,
and anything other than PS256 or ES256 is replaced by it.

### Token exchange (RFC 8693)

With no `actor_token`, an exchange is **impersonation**: the token that comes
back names the subject and nothing else. With an `actor_token` it is
**delegation**, and the token carries a nested `act` claim naming the actor.
Both are recorded on `/admin/delegation`. `audience` and `resource` may be used
together. A refresh token comes back when the client asks with
`requested_token_type=urn:ietf:params:oauth:token-type:refresh_token`, or as
`oauth2.tokenExchangeRefreshToken` says; `issued_token_type` is always
`access_token`. `may_act` is neither issued nor read.

### Pushed authorization requests (RFC 9126)

`POST /oauth2/par` takes an authorization request over the back channel, with
the client authenticating as it would at the token endpoint, and answers with a
one-time `request_uri` (256 random bits) for the browser to carry. The push is
checked by the **same code** as a request at the authorization endpoint, so a
request that could never be answered is refused while the client can still be
told. The pushed parameters are checked again when the `request_uri` is used.
The `request_uri` is bound to its client and to the authorization server it was
pushed to, and it is spent when a response is issued, so the reads before and
after sign-in count as one use. PAR can be required for the whole realm, by a
client's `require_pushed_authorization_requests`, or by a named authorization
server.

### JWT-secured authorization requests (RFC 9101)

An authorization request may arrive as a signed and optionally encrypted
`request` object, or as a `request_uri`. **A `request_uri` is fetched only when
the client registered that exact address** (`require_request_uri_registration`
is `true`), with no redirects, a timeout and a size cap. The object's
parameters **replace** the query, so every check runs on what was signed, and
the round trip through sign-in carries the object rather than its resolved
parameters. Each realm publishes an RSA and an EC key with `use: enc` for
encrypting to it, and the symmetric algorithms are keyed from the client
secret. A request object's `jti` is accepted once.

### Rich authorization requests (RFC 9396)

`authorization_details` is accepted at the authorization, token and PAR
endpoints. A **type belongs to the resource application that declares it**
(`oauthAuthorizationDetailsType`, a name or a JSON definition with a JSON
Schema), plus the built-in OpenID4VCI `openid_credential`. An unknown or
non-conforming detail is refused `invalid_authorization_details` in every mode.
The token is addressed to the type's resource. Consent draws each detail and is
asked **every time**. The refresh token keeps the whole grant, and a token
request may narrow it under section 6's subset rule.

### Introspection and revocation

`POST /oauth2/introspect` answers as
[RFC 7662](https://www.rfc-editor.org/rfc/rfc7662) JSON or, when the `Accept`
header names `application/token-introspection+jwt`, as an
[RFC 9701](https://www.rfc-editor.org/rfc/rfc9701) signed (and optionally
encrypted) JWT addressed to the resource server that asked. A JWT request must
authenticate in every mode, because its `aud` has to name the caller. An
authenticated caller learns only about tokens meant for it; any other token is
reported as `{"active": false}`. The answer includes `cnf`, `acr`, `auth_time`
and `authorization_details`.

`POST /oauth2/revoke` ([RFC 7009](https://www.rfc-editor.org/rfc/rfc7009))
authenticates nobody in any mode. It writes to the same revocation set as the
console's **Revoke** buttons.

### Dynamic registration and software statements

`POST /oauth2/register` ([RFC 7591](https://www.rfc-editor.org/rfc/rfc7591))
and the [RFC 7592](https://www.rfc-editor.org/rfc/rfc7592) read, update and
delete operations at `/oauth2/register/{client_id}`. A registration becomes an
entry under `ou=applications`. The registry is not a cache, so an `ldapmodify`
of the entry changes what the endpoints accept. What an endpoint would refuse,
registration refuses too. The registered `scope` is the list the client may be
issued (`oauthAllowedScope`, see [Scopes](#scopes-a-client-may-be-issued)), and
it may not name this service's own protected scopes.

**Registration applies OpenID Connect Registration's rules in every mode.**

* The defaults are stored and returned: `client_secret_basic`,
  `authorization_code`, `code` and `application_type` `web`.
* A `native` client's redirect URIs must be loopback `http` or a private-use
  scheme. A `web` client using the implicit grant must use `https` and not
  `localhost`.
* `grant_types` and `response_types` must agree. They are then **enforced**:
  a response type the client did not register is `unauthorized_client` at the
  authorization endpoint, and so is an unregistered grant at the token
  endpoint. A client that did not register `refresh_token` gets no refresh
  token.
* `jwks` and `jwks_uri` together are refused.
* `default_max_age` and `default_acr_values` apply unless the request names
  its own `max_age`, or its own `acr_values` or essential `acr`.
* An `initiate_login_uri` must be `https`. The user portal (`/portal/applications`) shows a
  **Sign in** link to it, carrying `iss` and `login_hint` (Core section 4).

An RFC 7592 update must name the client's own `client_id` and, if it sends a
`client_secret`, the one it was issued. A registration access token for a
client that no longer exists is revoked and answered `401 invalid_token`.

A **software statement** (RFC 7591 section 2.3) is trusted when this realm
issued it (from an application's page or
`POST /admin-api/applications/issue-software-statement`), or when an
application declares its issuer on `oauthSoftwareStatementIssuer` and holds the
signing key. A trusted statement's claims take precedence over the JSON. A
client admitted through a closed endpoint by a statement must present a
statement from the same issuer with every update. A publisher's `jwks_uri` is
fetched like a client's. No initial access token is issued.

Applications can also be created by hand on `/admin/applications/new`, which can
import an [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728) protected resource
metadata document.

### Multiple authorization servers — `/admin/authorization-servers`

**Protocols → OAuth2 / OIDC → Authorization servers.** The path component that
both discovery shapes carry selects an **authorization server profile**. Each
profile is a real authorization server with its own endpoints
(`/{id}/oauth2/authorize`, `/{id}/oauth2/token` and the rest), its own issuer
and its own audience. **A credential does not cross between them**: a code
issued by one is refused at another's token endpoint.

Any metadata member can be set, including one this service has never heard of.
Members marked *enforced* on the page drive the endpoints — response types,
grant types, PKCE methods, client authentication methods, DPoP algorithms, the
request object and introspection lists, and the authorization details types —
so narrowing one narrows that server alone. Any other member is published and
reported as **drift**. A name nobody configured is created with the defaults the
first time it is used. `GET|POST /admin-api/authorization-servers` does the same
from a script.

### Logout

* **[RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)**:
  `/oauth2/logout` accepts GET and POST.
  * The request is validated before anything ends. A malformed request is a
    page, and the person stays signed in.
  * An `id_token_hint` is verified as an ID Token this server issued. An
    expired one still counts. Its audience names the client.
  * Without a hint for the current session, the person is asked to confirm on
    a page with a real button and no script.
  * `post_logout_redirect_uri` is followed only if the client registered it
    exactly, in every mode. Development still follows one for a client that
    registered none. `state` is returned with it.
* **[Front-Channel Logout 1.0](https://openid.net/specs/openid-connect-frontchannel-1_0.html)**:
  every sign-out page renders a hidden iframe per registered
  `frontchannel_logout_uri`, with a visible link beside each one.
* **[Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html)**:
  when a session ends — by any sign-out, an account being disabled, or
  **expiry** — every relying party on it that registered a
  `backchannel_logout_uri` is POSTed a `logout+jwt`. The Logout Token is signed
  like the client's ID Token and encrypted where it registered encryption. Each
  delivery is a persisted row: it is sent once for the cluster, retried with
  backoff across restarts, and dead-lettered on a final failure (listed and
  retried on `/admin/logout`). An `http` logout URI is accepted only from a
  confidential client, and only where the outbound policy sends over `http`
  (`federation.outboundAllowHttp`, development mode).
* **Refresh tokens at sign-out** (Back-Channel Logout section 2.7): in every
  mode, a sign-out revokes the refresh tokens issued on that session without
  `offline_access`. Tokens granted `offline_access` are kept.

### Session Management

[OpenID Connect Session Management 1.0](https://openid.net/specs/openid-connect-session-1_0.html)
is **off by default**. Turn it on per realm with `oauth2.sessionManagement`.
When it is on:

* Discovery names `check_session_iframe`.
* Every OpenID Connect authentication response to an `http(s)` redirect URI
  carries `session_state`. That includes errors, `prompt=none` and JARM
  responses.
* `/oauth2/check_session` is the OP iframe. A relying party frames it and
  posts `client_id session_state`. It answers `changed`, `unchanged` or
  `error`.
* Only the origins of the realm's registered redirect URIs may frame it.

The OP browser state is the cookie `sts_op_browser_state`. Script can read
it, and on an HTTPS port it is `SameSite=None` so the iframe is sent it. It
changes at every sign-in and is cleared at every sign-out.

**Limitations:**

* Browsers that block third-party cookies never send the cookie to the
  iframe.
* An expired or administratively ended session shows as `unchanged` until the
  relying party asks the authorization endpoint again. Use
  [Back-Channel Logout](#logout) for that.
* A native client, whose redirect URI uses a private-use scheme, gets no
  `session_state`.

[Signing out](signing-out.md) describes the protocol-independent `/logout` and
what it reaches.

### Not implemented

* The device authorization grant: there is no device authorization endpoint.
* Aggregated and distributed claims (#147) and a Self-Issued OP (#129).
* Enforcing `value`/`values` or `essential` in a claims request, other than
  for `acr`.
* Encrypted access tokens, and the RFC 9068 `roles` and `entitlements` claims.
* An initial access token for registration.
* `may_act` in token exchange, and a foreign `subject_token` issuer in product
  mode.
* Enrichment of declared `authorization_details` types (RFC 9396 section 7).

## Development and product mode

`global.mode` changes a good deal here. The full list, with the reasoning, is
on [What is not checked](what-is-not-checked.md).

| | Development (default) | Product |
|---|---|---|
| Client authentication | nothing is required: a client may send only a `client_id` | a confidential client must present its credential and it must verify; a public client (`token_endpoint_auth_method=none`) is allowed |
| RFC 9700 | only where `oauth2.rfc9700` or `oauth2.oauth21` is set | **always**, for every realm — see [OAuth security](oauth-security.md) |
| Unknown client or authorization server | created the first time it is named | refused; create it ahead of time |
| Redirect URIs | any | only one registered for the client |
| Password grant | offered; accepts any password but `invalid` | not offered (RFC 9700 section 2.4) |
| Grants for a public client | all | authorization code and refresh only |
| `POST /oauth2/register` | open | closed unless `oauth2.openRegistration`, or a trusted software statement |
| JSON introspection | answers anybody holding the token | the caller must authenticate |
| Request objects | `alg: none` accepted unless a signature is required; `request_uri` may be `http` | must be signed; `request_uri` must be https and answer a JWT media type |
| Token exchange | an unverified `subject_token` or `actor_token` is exchanged | both must verify against this realm's key |
| Expired client secret | accepted and logged | refused `invalid_client` |
| Scopes | any; this service's protected scopes only to a client declaring them | only those the client declares, or the default set; `invalid_scope` otherwise |
| Ungranted delegated permission | honoured unless `oauth2.delegatedPermissionsEnforced` | refused `invalid_scope` |
| Profile claims | an invented persona fills gaps | from the directory entry or omitted; `email_verified` is never set |
| Signing keys | new on every start | persisted, sealed, and rotated with an overlap |
| `/logout?username=` | honoured (`logout.anyUser`) | ignored |

## Configuration

These are the `oauth2.*` settings that are not about security modes, plus
`oidcRp.*` (this service's own console and portal as relying parties) and
`logout.*`. The compliance, DPoP, sender-constraint and step-up settings are
on [OAuth security](oauth-security.md#configuration).

### Issuer, discovery and signing

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `oauth2.issuer` | `STS_OAUTH2_ISSUER` | *(empty)* | yes | Pins the `issuer` in both discovery documents and the `iss` of every token; empty names the base URL each request arrived on. |
| `oauth2.maxAuthorizationServerProfiles` | `STS_OAUTH2_MAX_AUTHORIZATION_SERVER_PROFILES` | `200` | yes | How many path-selected authorization server profiles are recorded; a name past it is still served, with the defaults. |
| `oauth2.signedMetadataAlgorithm` | `STS_OAUTH2_SIGNED_METADATA_ALGORITHM` | `RS256` | yes | The JWS algorithm of `signed_metadata` in the RFC 8414, OpenID Provider and OID4VCI issuer metadata. |
| `oauth2.signedMetadataCacheS` | `STS_OAUTH2_SIGNED_METADATA_CACHE_S` | `60` | yes | How long one signature over an unchanged metadata document is reused; 0 signs per request. |
| `oauth2.maxSignedMetadataEntries` | `STS_OAUTH2_MAX_SIGNED_METADATA_ENTRIES` | `64` | yes | How many distinct signed metadata documents are cached (the key includes the Host the request arrived on). |
| `oauth2.signedMetadataCertificateHeader` | `STS_OAUTH2_SIGNED_METADATA_CERTIFICATE_HEADER` | `x5u` | yes | Whether `signed_metadata` names its signing certificate chain: `x5u`, `x5c`, `both` or `none`. |
| `oauth2.accessTokenSigningAlg` | `STS_OAUTH2_ACCESS_TOKEN_SIGNING_ALG` | `default` | yes | The JWS algorithm of access and refresh tokens. `default` is RS256, or PS256 under FAPI 1.0 Advanced. |
| `oauth2.jarmResponseLifetimeS` | `STS_OAUTH2_JARM_RESPONSE_LIFETIME_S` | `600` | yes | The `exp` of a JARM response, in seconds after it is signed (at most 600). |
| `oauth2.eddsaCurve` | `STS_OAUTH2_EDDSA_CURVE` | `Ed25519` | yes | Which Edwards curve an `EdDSA` signature uses; both keys are published in the JWKS under different kids. |
| `oauth2.basicAuthRealm` | `STS_OAUTH2_BASIC_AUTH_REALM` | `sts` | yes | The `realm` in the `WWW-Authenticate: Basic` challenge the token endpoint sends on a failed `client_secret_basic`. |

### Lifetimes, codes and the token register

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `oauth2.accessTokenTtlS` | `STS_OAUTH2_ACCESS_TOKEN_TTL_S` | `3600` | yes | An access token's lifetime and `expires_in`; read per token, in steps of 30 seconds. |
| `oauth2.idTokenTtlS` | `STS_OAUTH2_ID_TOKEN_TTL_S` | `3600` | yes | An ID Token's lifetime, separate from the access token's. |
| `oauth2.refreshTokenTtlS` | `STS_OAUTH2_REFRESH_TOKEN_TTL_S` | `86400` | yes | A refresh token's absolute lifetime, in both modes (it was thirty days before; `2592000` restores that). |
| `oauth2.clockSkewS` | `STS_OAUTH2_CLOCK_SKEW_S` | `30` | yes | The allowance on `exp` and `nbf` wherever this service reads back a token it issued, and on every console screen's state. |
| `oauth2.authorizationCodeTtlS` | `STS_OAUTH2_AUTHORIZATION_CODE_TTL_S` | `300` | yes | How long an authorization code may wait to be redeemed; RFC 9700 mode's transaction memory is measured from it. |
| `oauth2.redeemedCodeCacheSize` | `STS_OAUTH2_REDEEMED_CODE_CACHE_SIZE` | `10000` | yes | How many redeemed codes are remembered so an identical repeat gets the same tokens and a different one is refused by name. |
| `oauth2.expiredTokenRetentionS` | `STS_OAUTH2_EXPIRED_TOKEN_RETENTION_S` | `86400` | yes | How long an expired token stays in the `/admin/tokens` register before the hourly purge job deletes its record. |

### Certificate chain headers

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `oauth2.accessTokenCertificateHeader` | `STS_OAUTH2_ACCESS_TOKEN_CERTIFICATE_HEADER` | `x5u` | yes | Whether an access token names its signing certificate chain: `x5u` (an address), `x5c` (inline), `both` or `none`. |
| `oauth2.idTokenCertificateHeader` | `STS_OAUTH2_ID_TOKEN_CERTIFICATE_HEADER` | `x5u` | yes | The same for an ID Token. |
| `oauth2.refreshTokenCertificateHeader` | `STS_OAUTH2_REFRESH_TOKEN_CERTIFICATE_HEADER` | `x5u` | yes | The same for the signed JWT inside a refresh token. |
| `oauth2.userinfoCertificateHeader` | `STS_OAUTH2_USERINFO_CERTIFICATE_HEADER` | `x5u` | yes | The same for a signed UserInfo response. |
| `oauth2.introspectionCertificateHeader` | `STS_OAUTH2_INTROSPECTION_CERTIFICATE_HEADER` | `x5u` | yes | The same for an RFC 9701 JWT introspection response. |

### Refresh token encryption

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `oauth2.refreshTokenEncryptionAlg` | `STS_OAUTH2_REFRESH_TOKEN_ENCRYPTION_ALG` | `RSA-OAEP-256` | yes | The JWE key management algorithm every refresh token is sealed under, to this realm's own keys. |
| `oauth2.refreshTokenEncryptionEnc` | `STS_OAUTH2_REFRESH_TOKEN_ENCRYPTION_ENC` | `A256GCM` | yes | The JWE content encryption algorithm for refresh tokens. |
| `oauth2.refreshTokenEncryptionKeyBits` | `STS_OAUTH2_REFRESH_TOKEN_ENCRYPTION_KEY_BITS` | `2048` | yes | The size of each realm's RSA refresh-token encryption key; reaches keys made after the change. |
| `oauth2.refreshTokenEncryptionCurve` | `STS_OAUTH2_REFRESH_TOKEN_ENCRYPTION_CURVE` | `P-256` | yes | The curve of each realm's EC refresh-token encryption key; reaches keys made after the change. |

### Consent, permissions and claims

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `oauth2.consentRequired` | `STS_OAUTH2_CONSENT_REQUIRED` | `true` | yes | Ask the person, on `/oauth2/consent`, before issuing for a scope they have not agreed to for that application. |
| `oauth2.delegatedPermissionsEnforced` | `STS_OAUTH2_DELEGATED_PERMISSIONS_ENFORCED` | `false` | yes | In development, refuse `invalid_scope` a request for a delegated permission the client has not been granted; off, it is honoured and logged. Product mode always refuses one. |
| `oauth2.maxRequestedClaims` | `STS_OAUTH2_MAX_REQUESTED_CLAIMS` | `64` | yes | The most claims one OpenID Connect Core 5.5 claims request may name. |

### Grants and assertions

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `oauth2.tokenExchangeRefreshToken` | `STS_OAUTH2_TOKEN_EXCHANGE_REFRESH_TOKEN` | `when-requested` | yes | Whether an RFC 8693 exchange returns a refresh token: `never`, `when-requested` or `always`. |
| `oauth2.jwtBearerGrant` | `STS_OAUTH2_JWT_BEARER_GRANT` | `true` | yes | Offer and advertise the RFC 7523 JWT bearer grant. |
| `oauth2.jwtBearerRequireRegisteredIssuer` | `STS_OAUTH2_JWT_BEARER_REQUIRE_REGISTERED_ISSUER` | `true` | yes | Refuse an RFC 7523 grant whose `iss` no application declares on `oauthAssertionIssuer`. |
| `oauth2.jwtBearerMaxLifetimeS` | `STS_OAUTH2_JWT_BEARER_MAX_LIFETIME_S` | `300` | yes | The longest `iat`-to-`exp` span accepted in an RFC 7523 grant (and, in product mode, a client assertion); 0 is off. |
| `oauth2.saml2BearerGrant` | `STS_OAUTH2_SAML2_BEARER_GRANT` | `true` | yes | Offer and advertise the RFC 7522 SAML 2.0 bearer grant. |
| `oauth2.saml2BearerRequireRegisteredIssuer` | `STS_OAUTH2_SAML2_BEARER_REQUIRE_REGISTERED_ISSUER` | `true` | yes | Refuse an RFC 7522 grant whose `<Issuer>` no application declares on `oauthSamlAssertionIssuer`. |
| `oauth2.saml2BearerMaxLifetimeS` | `STS_OAUTH2_SAML2_BEARER_MAX_LIFETIME_S` | `300` | yes | The longest `IssueInstant`-to-expiry span accepted in an RFC 7522 grant; 0 is off. |
| `oauth2.clientAssertionSkewS` | `STS_OAUTH2_CLIENT_ASSERTION_SKEW_S` | `60` | yes | How far out a client assertion's `exp`, `nbf` and `iat` may be, and how long past expiry its `jti` is remembered. |
| `oauth2.assertionReplayCacheSize` | `STS_OAUTH2_ASSERTION_REPLAY_CACHE_SIZE` | `1000` | yes | How many live rows the used-assertion history holds per realm; a full history refuses the next assertion. |

### Registration and client secrets

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `oauth2.openRegistration` | `STS_OAUTH2_OPEN_REGISTRATION` | `false` | yes | Whether `POST /oauth2/register` accepts anybody in product mode (development always does). |
| `oauth2.softwareStatementRequireTrustedIssuer` | `STS_OAUTH2_SOFTWARE_STATEMENT_REQUIRE_TRUSTED_ISSUER` | `true` | yes | Refuse a `software_statement` whose issuer this realm does not trust, in both modes. |
| `oauth2.softwareStatementOpensRegistration` | `STS_OAUTH2_SOFTWARE_STATEMENT_OPENS_REGISTRATION` | `true` | yes | Let a registration carrying a trusted software statement through a closed registration endpoint. |
| `oauth2.softwareStatementRequired` | `STS_OAUTH2_SOFTWARE_STATEMENT_REQUIRED` | `false` | yes | Refuse a registration or RFC 7592 update that carries no software statement. |
| `oauth2.softwareStatementLifetimeS` | `STS_OAUTH2_SOFTWARE_STATEMENT_LIFETIME_S` | `31536000` | yes | How long a software statement this realm issues is valid; 0 issues one with no `exp`. |
| `oauth2.registeredClientIdPrefix` | `STS_OAUTH2_REGISTERED_CLIENT_ID_PREFIX` | `sts-client-` | yes | What a dynamically registered `client_id` starts with. |
| `oauth2.registeredClientIdBytes` | `STS_OAUTH2_REGISTERED_CLIENT_ID_BYTES` | `8` | yes | How many random bytes follow that prefix. |
| `oauth2.registeredSecretBytes` | `STS_OAUTH2_REGISTERED_SECRET_BYTES` | `24` | yes | How many random bytes make a registered client's secret and registration access token. |
| `oauth2.registeredSecretLifetimeS` | `STS_OAUTH2_REGISTERED_SECRET_LIFETIME_S` | `0` | yes | The `client_secret_expires_at` published for a registered client, as seconds after registration; 0 is never. |
| `oauth2.clientSecretOverlapS` | `STS_OAUTH2_CLIENT_SECRET_OVERLAP_S` | `604800` | yes | How long a rotated-out client secret keeps working beside the new one; 0 ends it at once. |
| `oauth2.clientSecretExpiryWarningDays` | `STS_OAUTH2_CLIENT_SECRET_EXPIRY_WARNING_DAYS` | `14` | yes | How many days before a client secret expires the daily job warns and the console marks it. |

### Request objects (RFC 9101)

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `oauth2.requireSignedRequestObject` | `STS_OAUTH2_REQUIRE_SIGNED_REQUEST_OBJECT` | `false` | yes | Refuse every authorization request that is not JWT-secured, or whose object is unsigned; published as `require_signed_request_object`. |
| `oauth2.requireRequestObjectType` | `STS_OAUTH2_REQUIRE_REQUEST_OBJECT_TYPE` | `false` | yes | Require every request object to be typed `oauth-authz-req+jwt`. |
| `oauth2.requireRequestObjectIssuerAudience` | `STS_OAUTH2_REQUIRE_REQUEST_OBJECT_ISSUER_AUDIENCE` | `false` | yes | Require `iss` and `aud` in a request object (each is checked wherever present either way). |
| `oauth2.requestObjectJtiOnce` | `STS_OAUTH2_REQUEST_OBJECT_JTI_ONCE` | `true` | yes | Accept a request object's `jti` once per client; an object with no `jti` is accepted either way. |
| `oauth2.requestObjectJtiRetentionS` | `STS_OAUTH2_REQUEST_OBJECT_JTI_RETENTION_S` | `3600` | yes | How long a spent `jti` is remembered when its object has no `exp`. |
| `oauth2.requestUriTimeoutMs` | `STS_OAUTH2_REQUEST_URI_TIMEOUT_MS` | `5000` | yes | How long a registered `request_uri` may take to answer. |
| `oauth2.requestUriMaxBytes` | `STS_OAUTH2_REQUEST_URI_MAX_BYTES` | `65536` | yes | The largest answer a `request_uri` may give. |
| `oauth2.clientJwksCacheS` | `STS_OAUTH2_CLIENT_JWKS_CACHE_S` | `300` | yes | How long a key set fetched from a client's `jwks_uri` is reused. |
| `oauth2.clientJwksRefetchS` | `STS_OAUTH2_CLIENT_JWKS_REFETCH_S` | `30` | yes | The least time between two fetches of one `jwks_uri` for a `kid` the cached set lacks. |
| `oauth2.requestUriCacheS` | `STS_OAUTH2_REQUEST_URI_CACHE_S` | `0` | yes | How long a fetched `request_uri` answer is reused; 0 fetches every time. |
| `oauth2.requestObjectEncryptionKeyBits` | `STS_OAUTH2_REQUEST_OBJECT_ENCRYPTION_KEY_BITS` | `2048` | yes | The size of the RSA key each realm publishes (`use: enc`) for encrypted request objects. |
| `oauth2.requestObjectEncryptionCurve` | `STS_OAUTH2_REQUEST_OBJECT_ENCRYPTION_CURVE` | `P-256` | yes | The curve of the EC key each realm publishes for ECDH-ES request object encryption. |

### Pushed authorization requests (RFC 9126)

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `oauth2.pushedAuthorizationRequests` | `STS_OAUTH2_PUSHED_AUTHORIZATION_REQUESTS` | `true` | yes | Offer `POST /oauth2/par` and advertise it; off answers 404. |
| `oauth2.requirePushedAuthorizationRequests` | `STS_OAUTH2_REQUIRE_PUSHED_AUTHORIZATION_REQUESTS` | `false` | yes | Refuse any authorization request that was not pushed first; published as `require_pushed_authorization_requests`. |
| `oauth2.parRequestUriLifetimeS` | `STS_OAUTH2_PAR_REQUEST_URI_LIFETIME_S` | `60` | yes | How long a pushed `request_uri` lives — the whole sign-in, since it is read again on the way back. |
| `oauth2.parMaxRequests` | `STS_OAUTH2_PAR_MAX_REQUESTS` | `10000` | yes | The most pushed requests a realm holds; a full store refuses the next push (503). |
| `oauth2.parMaxBodyBytes` | `STS_OAUTH2_PAR_MAX_BODY_BYTES` | `65536` | yes | The largest body `/oauth2/par` accepts (413 otherwise). |
| `oauth2.parRequestsPerMinute` | `STS_OAUTH2_PAR_REQUESTS_PER_MINUTE` | `600` | yes | Pushes one client may make from one address per rate-limit window before 429. |
| `oauth2.parAllowUnregisteredRedirectUris` | `STS_OAUTH2_PAR_ALLOW_UNREGISTERED_REDIRECT_URIS` | `false` | yes | RFC 9126 section 2.4: let an authenticated client push a redirect URI it never registered. |

### Rich authorization requests (RFC 9396)

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `oauth2.authorizationDetailsMaxEntries` | `STS_OAUTH2_AUTHORIZATION_DETAILS_MAX_ENTRIES` | `20` | yes | How many objects one `authorization_details` array may carry. |

### Logout

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `oauth2.sessionManagement` | `STS_OAUTH2_SESSION_MANAGEMENT` | `false` | yes | Session Management 1.0: `check_session_iframe`, `session_state` and the OP browser state cookie. |
| `oauth2.frontchannelLogout` | `STS_OAUTH2_FRONTCHANNEL_LOGOUT` | `true` | yes | Front-Channel Logout 1.0: the discovery members, the `sid` claim and a hidden iframe per registered `frontchannel_logout_uri`. |
| `oauth2.backchannelLogout` | `STS_OAUTH2_BACKCHANNEL_LOGOUT` | `true` | yes | Back-Channel Logout 1.0: the discovery members, the `sid` claim and a Logout Token POSTed to every registered `backchannel_logout_uri`. |
| `oauth2.backchannelLogoutOnExpiry` | `STS_OAUTH2_BACKCHANNEL_LOGOUT_ON_EXPIRY` | `true` | yes | Send Logout Tokens when a session expires, not only when somebody signs out. |
| `oauth2.backchannelLogoutTokenTtlS` | `STS_OAUTH2_BACKCHANNEL_LOGOUT_TOKEN_TTL_S` | `120` | yes | How far in the future a Logout Token's `exp` is. |
| `oauth2.backchannelLogoutAttempts` | `STS_OAUTH2_BACKCHANNEL_LOGOUT_ATTEMPTS` | `3` | yes | How many times one Logout Token is POSTed before its delivery is a dead letter. |
| `oauth2.backchannelLogoutTimeoutMs` | `STS_OAUTH2_BACKCHANNEL_LOGOUT_TIMEOUT_MS` | `5000` | yes | How long one POST of a Logout Token may take. |
| `oauth2.backchannelLogoutBackoffMs` | `STS_OAUTH2_BACKCHANNEL_LOGOUT_BACKOFF_MS` | `1000` | yes | The wait before the second attempt, doubling after. |
| `oauth2.backchannelLogoutLeaseMs` | `STS_OAUTH2_BACKCHANNEL_LOGOUT_LEASE_MS` | `60000` | yes | How long one process holds its claim on one delivery attempt before another may take it over. |
| `oauth2.backchannelLogoutSweepS` | `STS_OAUTH2_BACKCHANNEL_LOGOUT_SWEEP_S` | `10` | yes | How often the scheduler looks for deliveries that are due. |
| `oauth2.backchannelLogoutRetentionS` | `STS_OAUTH2_BACKCHANNEL_LOGOUT_RETENTION_S` | `86400` | yes | How long a delivery is kept; one still pending past it is dead-lettered. |
| `oauth2.backchannelLogoutMaxRows` | `STS_OAUTH2_BACKCHANNEL_LOGOUT_MAX_ROWS` | `2000` | yes | The most deliveries one realm keeps; finished rows go first. |
| `oauth2.backchannelLogoutConcurrency` | `STS_OAUTH2_BACKCHANNEL_LOGOUT_CONCURRENCY` | `8` | yes | How many due deliveries one process attempts at once. |
| `oauth2.backchannelLogoutSummaryS` | `STS_OAUTH2_BACKCHANNEL_LOGOUT_SUMMARY_S` | `60` | yes | At most one summary log line per realm per interval. |
| `logout.anyUser` | `LOGOUT_ANY_USER` | `true` | yes | `/logout` honours a `username` naming somebody else (development only; ignored in product mode). |
| `logout.kerberosSignOut` | `LOGOUT_KERBEROS_SIGN_OUT` | `true` | yes | Signing out stamps an instant on the Kerberos principal, after which older tickets are refused at the TGS. |
| `logout.ldapDisconnect` | `LOGOUT_LDAP_DISCONNECT` | `true` | yes | Signing out closes every directory connection bound as that person. |
| `logout.maxRows` | `LOGOUT_MAX_ROWS` | `500` | yes | How many sessions and credentials `/logout` lists for one person (a global logout still ends all of them). |

### The console and portal as relying parties

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `oidcRp.maxFlows` | `STS_OIDC_RP_MAX_FLOWS` | `200` | yes | How many unfinished sign-in flows the console and portal may hold per realm. |
| `oidcRp.backChannelTimeoutS` | `STS_OIDC_RP_BACK_CHANNEL_TIMEOUT_S` | `10` | yes | How long the console and portal wait for this service's own token endpoint and JWKS. |
| `oidcRp.maxRedirectUris` | `STS_OIDC_RP_MAX_REDIRECT_URIS` | `20` | yes | The most callback addresses `sts-admin-console` and `sts-user-portal` may learn (development mode only). |
| `oidcRp.renewBeforeExpiryS` | `STS_OIDC_RP_RENEW_BEFORE_EXPIRY_S` | `60` | yes | How long before its tokens expire the console or portal renews them with the refresh grant. |

These tables are a copy of rows in `common/config.js`. The live source is
`/admin/oauth2` (and `/admin/token-lifetimes` for the lifetimes) and
`GET /admin-api/config`, which also give each row's full description. See
[Configuration](configuration.md) for how a value is resolved. Change a value on
the console page or with `POST /admin-api/config/set`. Runtime settings may also
be set per [trust realm](trust-realms.md).

## Design decisions

* **Permissive by default, strict by switch.** A client is exercised by both
  answers. One that has only met a permissive server has never run its own
  refusal paths, and one that has only met a strict server cannot reproduce the
  behaviour it is trying to detect. The strict answers are in
  [OAuth security](oauth-security.md).
* **Two discovery documents from one object.** RFC 8414 and OpenID Connect
  Discovery overlap in about twenty-five members. Two hand-kept copies would
  drift, and a client configured from one would then behave differently from a
  client configured from the other.
* **A metadata member is a promise.** A switched-off grant, endpoint or
  capability is removed from discovery, and a named authorization server's
  enforced members drive its endpoints. The document is the behaviour.
* **No URL a request supplies is fetched to verify something.** A `jwks_uri`
  and a `request_uri` are fetched only because the client REGISTERED them,
  under the outbound policy.
* **Consent is on by default, unlike every other policy here.** Every real
  authorization server shows a consent screen at first sign-in, and a client
  that has never met one has never run the code that handles it. The screen adds
  a test case rather than removing one.
* **A grant already issued is never judged again.** The token endpoint asks
  nobody anything. Turning on consent or delegated-permission enforcement does
  not break a refresh of an earlier grant, and revoking a consent does not
  recall a token.
* **A token for an API is for that API alone.** RFC 9068 section 2.2.3 says
  every scope on a token must mean something to its audience, so the OpenID
  Connect scopes are left off a token addressed to an API. They stay granted.
* **RFC 9068 checks apply in every mode.** The profile is what the token *is*.
  If some resource servers could validate it only under a restart-only flag,
  that would be two formats under one name.
* **An address is part of an issuer.** Tokens, software statements and
  audiences are compared as whole URLs. The earlier path-only match accepted a
  token narrowed to somebody else's `/resource`.
* **A redeemed code answers an identical repeat.** A reloaded page, a
  double-submitted form and a retry after a bad `code_verifier` are
  indistinguishable from a stolen code. Answering with the same tokens, and
  naming what differs otherwise, tells the client what happened. RFC 9700 mode
  turns this off.
* **Refresh tokens are encrypted to their realm.** Nobody but this service
  needs to read one, and a token from one realm cannot be redeemed in another.
* **Claims requests are honoured and never echoed.** `value`/`values` could be
  satisfied by repeating what the client asked for. A UserInfo response that
  agreed with whatever it was asked would be useless for testing.
* **An encrypted response is refused rather than downgraded.** A client that
  registered ID Token, UserInfo or introspection encryption never gets a
  plaintext answer.
* **Back-Channel Logout follows expiry; front-channel cannot.** A Logout Token
  needs no browser, so it goes out wherever a session ends. An iframe needs a
  sign-out page, so it cannot follow an expiry.
* **One delivery row per Logout Token, sent once for the cluster.** HTTP is
  at-least-once, so every retry carries the same token and `jti`, and the
  relying party deduplicates on it.

## In the running service

The console's **Protocols → OAuth2 / OIDC** group:

| Page | What it is for |
|---|---|
| `/admin/oauth2` | the `oauth2.*` settings: issuer, both compliance modes, redirect URIs, logout, the deliberate `breakIdTokenNonce` defect |
| `/admin/authorization-servers` | named authorization server profiles, their members and their drift |
| `/admin/token-lifetimes` | the three lifetimes and the clock skew, beside a count of what has expired |
| `/admin/claims` | the access token and ID Token custom claim sets |
| `/admin/userinfo-claims` | the UserInfo claim set, and what a claims request can reach |

Elsewhere: `/admin/applications` (clients, their secrets, keys and
registrations), `/admin/consent`, `/admin/delegation`, `/admin/tokens` (every
issued token by response, with **Revoke**), `/admin/used-assertions`,
`/admin/logout` (back-channel dead letters), and **Monitoring → OAuth 2.0 /
OIDC activity** (`/admin/oauth2/monitor`), which counts pushed requests and
step-up outcomes per client.

The management API mirrors these: `/admin-api/oauth2`,
`/admin-api/authorization-servers`, `/admin-api/token-lifetimes`,
`/admin-api/claims`, `/admin-api/userinfo-claims`, `/admin-api/consent`,
`/admin-api/oauth2/monitor`. `GET /admin-api/openapi.json` lists every
operation.

Live, self-describing endpoints: the two discovery documents,
`GET /oauth2/rfc9700` and `GET /oauth2/oauth21` (the compliance models), and
`GET /admin/sts-metadata` for every endpoint this service registers.

## Related

* [OAuth security](oauth-security.md) — RFC 9700 mode, OAuth 2.1 mode, DPoP,
  mutual TLS, sender constraints, step-up
* [JWT assertions](jwt-assertions.md) and [SAML assertions](saml-assertions.md)
  — RFC 7523 and RFC 7522
* [Accepted tokens](accepted-tokens.md) — which tokens each door takes
* [Authentication](authentication.md) and [Sessions](sessions.md)
* [Signing out](signing-out.md)
* [OpenID4VCI](oid4vci.md) — the pre-authorized code grant and
  `openid_credential`
* [Trust realms](trust-realms.md), [Configuration](configuration.md),
  [What is not checked](what-is-not-checked.md), [Error codes](error-codes.md)
