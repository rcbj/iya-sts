---
title: OAuth security
---

# OAuth security

This page covers what makes iya-sts's [authorization server](oauth-oidc.md)
**strict**. There are two compliance modes:
[RFC 9700](https://www.rfc-editor.org/rfc/rfc9700) (the OAuth 2.0 Security
Best Current Practice) and
[OAuth 2.1](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/)
(draft-ietf-oauth-v2-1-16). A security profile,
[FAPI 1.0 Baseline](https://openid.net/specs/openid-financial-api-part-1-1_0.html),
builds on the first, and [FAPI 1.0
Advanced](https://openid.net/specs/openid-financial-api-part-2-1_0.html) on
that. There are two sender constraints:
[DPoP](https://www.rfc-editor.org/rfc/rfc9449) (RFC 9449) and
[mutual TLS](https://www.rfc-editor.org/rfc/rfc8705) (RFC 8705). Five settings
ask for more than either mode does, and
[RFC 9470](https://www.rfc-editor.org/rfc/rfc9470) adds step-up
authentication. Everything here can be set per [trust realm](trust-realms.md),
so one process can serve a permissive pass, an RFC 9700 pass and an OAuth 2.1
pass at once.

## Features

### RFC 9700 mode

`oauth2.rfc9700` is **off by default**. While it is off, nothing in the mode
runs. On, the authorization flow is held to the whole of RFC 9700 section 2:

* **Redirect URIs** are matched by exact string against what the client
  registered, or against `oauth2.redirectUris` for a client that registered
  none. (A client that registered its own is held to them in every mode since
  #118; what this mode adds is the `oauth2.redirectUris` list for the others.) A loopback URI may use any port (RFC 8252 section 7.3). There is no open
  redirector at either redirecting endpoint, and no `http` redirect URI except
  on the loopback. A bad `redirect_uri` is answered with a 400 on this server,
  never redirected.
* **PKCE** is required of every client not known to be confidential, `S256`
  only. A downgrade is refused, and so is a reused challenge or nonce.
* A **nonce** is required with any `id_token` — hybrid included; OpenID
  Connect Core already requires one for the implicit flow in every mode — and
  no response type that issues an access token from the authorization endpoint
  (the implicit grant) is accepted.
* **Authorization codes**: a repeated redemption is refused, and everything the
  code bought is revoked (section 4.5).
* **Refresh tokens rotate** with replay detection. A replay revokes the whole
  family. An idle chain stops working after `oauth2.refreshIdleSeconds`. A
  browser sign-out revokes the refresh tokens issued on that session without
  `offline_access` in every mode, not only this one (Back-Channel Logout
  section 2.7, `oauth2.revokeRefreshOnLogout`).
* **No password grant** (section 2.4), and **no CORS at the authorization
  endpoint**.
* A **registered confidential client must authenticate** at the token endpoint.
* Registration refuses metadata the endpoints would refuse in use, and both
  discovery documents stop advertising what the mode refuses.

**It also binds the main port as HTTPS.** Section 2.1 says an authorization
response must not travel over an unencrypted connection. That is a property of
the socket, not something a request can be refused for, so `global.https`
defaults to on when either mode is on. For that reason the setting is
**restart-only for the process**. A trust realm may still carry it, because a
realm binds no socket: `/oauth2/authorize` can stay permissive while
`/realm/<id>/oauth2/authorize` is compliant. A compliant realm on a plain-HTTP
process enforces every check, and `/oauth2/rfc9700` reports the TLS rows as not
met.

**Every refusal names RFC 9700 and the section.** `GET /oauth2/rfc9700`
publishes the whole model: every requirement, its section and level, and
whether it is *enforced*, only *detected*, *always* true here, a property of the
*deployment*, or *not* enforced, with the reason. Read it rather than a copy.

Some requirements belong to the client, so they are **observed rather than
refused**: a reused challenge, an unbound access token, a client using a
shared secret, and the client's duty to check the ID Token's `nonce`. For that
last one, `oauth2.breakIdTokenNonce` puts a deliberately wrong nonce in every ID
Token, so you can see whether a client notices. It is reported on
`/oauth2/rfc9700` as it is in force, is not part of the mode, and works in
**development mode only**: a product realm ignores it — even one still stored
from before the realm was switched — and refuses turning it on.

### OAuth 2.1 mode

`oauth2.oauth21` follows **draft-ietf-oauth-v2-1-16**, an Internet-Draft, and
every refusal names that revision. **It turns RFC 9700 mode on**, and then:

* **loosens** two things. A token request may omit `redirect_uri` (section
  10.2), except for a code issued without PKCE under the nonce exemption. An
  authorization request may omit it when the client registered exactly one.
* **adds** PKCE for confidential clients too (unless one has a credential on
  file, asks for `openid` and sends a `nonce`), `code_challenge_method`
  required, a client's own registered redirect URI (`oauth2.redirectUris` is not
  read), a token request naming an undeclared client or no client at all
  refused, a presented credential that must verify, one authentication method
  per request, client credentials only for an authenticated client, a JWT client
  assertion whose `aud` is the issuer alone, no SAML client authentication, no
  repeated parameters, a ten-minute cap on a code, and `error_description`
  limited to its grammar.

`GET /oauth2/oauth21` lists every row. An RFC 7523 or RFC 7522 grant that
carries no client gets an access token and **no refresh token**, because a
refresh chain that belongs to nobody cannot be checked.

### FAPI 1.0 Baseline

`oauth2.fapi=1-baseline` enforces FAPI 1.0 Part 1: Baseline (final). **It
turns RFC 9700 mode on**, as OAuth 2.1 mode does, and adds what the profile
asks beyond it:

* **Confidential clients authenticate with** `tls_client_auth`,
  `self_signed_tls_client_auth`, `private_key_jwt` or `client_secret_jwt`.
  `client_secret_basic` and `client_secret_post` are refused at registration
  and at the token and PAR endpoints, and are not advertised (item 4).
* **Keys:** RSA of 2048 bits or more, elliptic curve of 160 or more, checked at
  registration (items 5 and 6).
* **PKCE with S256 for every client**, confidential ones included (item 7).
* **`redirect_uri` is required and must be https** (items 9 and 20); it is
  matched exactly, as RFC 9700 mode already does.
* **`nonce` whenever `openid` is asked for, and `state` when it is not**
  (sections 5.2.2.2 and 5.2.2.3).
* **Explicit consent** (item 12). The consent screen is shown whatever
  `oauth2.consentRequired` says, and an administrator's global consent does
  not count as the person's approval, for this service's own console and
  portal too.
* **One client per request** (item 19). A Basic header, the body's
  `client_id` and a client assertion's `sub` must name the same client, or the
  request is refused `invalid_client`.
* **Short unbound access tokens** (item 21): an access token that is not
  sender-constrained lives 600 seconds at most. One bound by DPoP or mutual
  TLS keeps the configured lifetime.

A trust realm may carry the setting, and so may a **named authorization
server**: its `fapi` member on `/admin/authorization-servers` is a profile of
its own, or `off` to opt out of its realm's. `GET /oauth2/fapi` (and
`GET /{id}/oauth2/fapi`) lists every requirement with how it is enforced.

**The console, the portal and the embedded debugger authenticate by
`private_key_jwt`** at the token endpoint in every mode, not only under FAPI.
Each one's key is issued by the realm's certificate authority on first use,
kept (private half sealed) on its application entry, and replaced before it
expires. No client secret is created for them, and nothing about their client
authentication reaches a browser.

### FAPI 1.0 Advanced

`oauth2.fapi=1-advanced` enforces FAPI 1.0 Part 2: Advanced (final). It is
**Baseline and more**, with one relaxation Part 2 makes itself: PKCE is
required only of a request pushed to `/oauth2/par`. On top of Baseline:

* **A signed request object** (by value or pushed), with `exp` and `nbf`
  within 60 minutes of each other, `nbf` at most 60 minutes old, and `aud`
  this authorization server's issuer. Only its parameters are used.
* **`response_type=code id_token`**, or **`code` with `response_mode=jwt`**
  ([JARM](oauth-oidc.md#flows-and-response-types)). The ID Token returned
  from the authorization endpoint carries `c_hash` and `s_hash`.
* **Sender-constrained access tokens only.** A token request that presents
  neither a TLS client certificate nor a DPoP proof is refused.
  `oauth2.fapiRequireMtls` makes it mutual TLS only, as FAPI 1.0 names.
  `mtls_endpoint_aliases` is published where the main port is TLS.
* **Client authentication** by `tls_client_auth`,
  `self_signed_tls_client_auth` or `private_key_jwt`. `client_secret_jwt` and
  public clients are refused.
* **PS256 or ES256 for every signature**, in both directions, and never
  `RSA1_5`. This server signs ID Tokens, access tokens, JARM responses and
  introspection responses with PS256 by default, and the discovery lists are
  narrowed to the two.

The console, portal and embedded debugger **conform** in an Advanced realm.
Each sends a signed request object through PAR, asks for a JARM response and
verifies it, and binds its tokens with DPoP. With `oauth2.fapiRequireMtls`
on, each also presents the client certificate the realm's CA issued with its
signing key.

### FAPI 2.0 Security Profile

`oauth2.fapi=2-security` enforces the FAPI 2.0 Security Profile (final). It
is a profile of its own, not FAPI 1.0 with more rules. It turns RFC 9700
mode on and adds:

* **Confidential clients only**, authenticated by mutual TLS or
  `private_key_jwt`. A client assertion's `aud` must be the issuer, as a
  single string.
* **Sender-constrained access tokens only**, by mutual TLS or DPoP. DPoP
  server nonces stay optional (`oauth2.dpopNonceRequired`), as the profile
  allows.
* **Every authorization request pushed** to `/oauth2/par` by an
  authenticated client, carrying `redirect_uri`, with `response_type=code`
  and PKCE `S256`. A `request_uri` expires in under 600 seconds and a code in
  60.
* **No refresh-token rotation.** Setting `oauth2.refreshTokenRotation`
  forces it anyway; that is the "extraordinary circumstance" section 5.3.2.1
  allows.
* **Timestamps.** A client assertion, request object or DPoP proof whose
  `iat` or `nbf` is more than 60 seconds in the future is refused.
* **PS256, ES256 or EdDSA** (Ed25519) for every signature, RSA keys of 2048
  bits and elliptic-curve keys of 224. This server signs PS256 by default.
* **The ordinary consent rules.** FAPI 1.0's "the person's own consent" rule
  does not apply under 2.0.
* **TLS**: BCP 195's cipher suites with TLS 1.3 preferred. This is every
  listener's default (see [TLS](tls.md)), not a per-realm switch.

The console, portal and debugger conform. Each pushes its request with
`private_key_jwt`, receives a `code`, and binds its tokens with DPoP.

#### The FAPI 2.0 Attacker Model, and what stops each attacker

The Attacker Model has no normative requirements of its own; a deployment
that enforces the profile meets its goals. Here is how:

| Attacker | What it can do | What stops it here |
|---|---|---|
| A1, web attacker | Runs its own sites and clients, lures the user | Exact redirect URI matching, PKCE, client authentication and PAR bind a code to the client that pushed the request |
| A1a, mix-up | Poses as an authorization server to a client that talks to several | The RFC 9207 `iss` on every response, and a client assertion addressed to this issuer alone |
| A2, network attacker | Controls the network between parties | TLS everywhere, BCP 195's suites, TLS 1.3 preferred |
| A3a, request leakage | Reads authorization requests (logs, referrers) | The request is pushed over the back channel, and the browser carries only a one-time `request_uri` |
| A3b, response leakage | Reads authorization responses | A code lives 60 seconds, is spent once and is bound by PKCE, and a DPoP-bound request binds it to the client's key |
| A5, token leakage | Obtains an access or refresh token | Every access token is sender-constrained (mTLS or DPoP), and so is the refresh token |
| Code injection | Replays a stolen code into another session | PKCE S256 on every request, and single-use codes |
| Open redirectors | Uses the server to redirect elsewhere | Refused in every mode that RFC 9700 mode governs |

### FAPI 2.0 Message Signing

`oauth2.fapi=2-message-signing` is FAPI 2.0 Message Signing (final) on top of
the Security Profile, with all three of its components required:

* **Signed requests** (section 5.3): every pushed request is a JAR-signed
  request object whose `aud` is the issuer, whose `nbf` is at most 60 minutes
  old, and whose `exp` is at most 60 minutes after its `nbf`. A push of plain
  parameters is refused.
* **Signed responses** (section 5.4): JARM is required, so a request must ask
  for a JWT response mode (`response_mode=jwt`). The `iss` travels inside the
  response JWT. Discovery lists only JARM's modes.
* **Signed introspection** (section 5.5): an RFC 9701 introspection response
  is a signed JWT, PS256 by default.

The console, portal and debugger conform. Each pushes a signed request object,
asks for JARM, and verifies the response before reading the code.

#### Non-repudiation (section 5.2)

The section is guidance. Non-repudiation holds for individual signed messages:
pushed requests, authorization responses, introspection responses and ID
Tokens. It is **not** provided for a front-channel request. Proving later that
this service signed something takes two things a deployment has to keep:

* **The public keys.** A rotated signing key stays published in the JWKS for
  `signing.retiredKeyGraceDays`. Archive the JWKS, or every retired key, for as
  long as a signature has to remain provable.
* **The record.** Every issuance and refusal is a row in the audit log. It is
  a ring of `audit.maxEvents` rows (5000 by default), persisted where minted
  state is (product mode on postgres), and the oldest rows are dropped, so it
  is not an archive. Export it, or the service log, to storage you control
  for the retention period your regulator sets. Section 7 warns that a signed message can carry personal data, so
  limit access to it and keep it no longer than you need.

HTTP message signatures on resource requests and responses (RFC 9421) are not
part of the final Message Signing specification. They are tracked in #178.

Not covered yet: running the OpenID Foundation's conformance suite against
this service (#176).

### DPoP (RFC 9449)

* All **twelve section 4.3 proof checks**, each numbered in the source,
  including the four that are easiest to leave out: `typ`, `htm`/`htu`, `ath`
  and the comparison against `cnf.jkt`.
* `cnf.jkt` on **access and refresh tokens**. A proof at the token endpoint
  binds both, and a token exchange made with a proof mints a bound refresh
  token.
* **`dpop_jkt`** at the authorization request and at `/oauth2/par`, binding the
  code to a key before it is issued.
* **Replay detection**: a proof's `jti` is reserved on arrival and kept only
  when the proof is accepted. On a cluster it is claimed once across all nodes.
* The **nonce handshake** (sections 8 and 9), when `oauth2.dpopNonceRequired`
  is on. It makes proofs fresher and never makes them mandatory: a request
  with no `DPoP` header is still a Bearer request. In development,
  `POST /dpop/nonce-mode` flips the setting for the realm it is reached in.
* **A bound token presented as `Bearer` is refused** at every protected
  endpoint: UserInfo, the OpenID4VCI endpoints, SCIM, Shared Signals,
  `/admin-api` and the embedded debugger.

The `htu` a proof is checked against comes from the request URL.
`X-Forwarded-Proto` and `X-Forwarded-Host` are believed only while
`global.trustProxy` is on. Behind a TLS-terminating proxy, turn it on, or every
proof naming the public URL is refused (the refusal names the setting). With
no proxy, leave it off, or a client could choose the `htu` its own proof is
checked against.

### Mutual TLS (RFC 8705)

Both halves are available **in every mode**, wherever the main port is TLS
(`global.https`). The port asks every connection for a client certificate and
requires none. **A client certificate is never read from a header.**

**Client authentication (section 2).**

| Method | What authenticates the client |
|---|---|
| `tls_client_auth`, implicit | a TLS client certificate **this realm issued to this application**, still listed on its record. Issuing it was the registration. |
| `tls_client_auth`, explicit | a certificate whose chain verified against the client truststore, carrying the **one** subject parameter the client registered: `tls_client_auth_subject_dn` (compared as a name), `_san_dns`, `_san_uri`, `_san_ip` or `_san_email` |
| `self_signed_tls_client_auth` | the `x5c[0]` of a key in the client's registered `jwks`, or a registered thumbprint; no chain is checked |

A certificate issued here as somebody else's identity (another application's,
or a person's) never authenticates a client, and neither does a revoked one.
**A client that declares a certificate method is held to it in every mode.**
Issue an application its certificate from the **Mutual TLS** part of its
*Credentials* section on `/admin/applications`, or with
`POST /admin-api/applications/issue-tls-client-certificate`.

**Certificate-bound tokens (section 3).** A token request made over a
connection with a client certificate gets `cnf["x5t#S256"]`, the SHA-256 of the
certificate's DER, on the access and refresh tokens. The protected endpoints
compare it with the certificate on their own connection. An **unverified**
certificate still binds: section 3 binds to the certificate itself and permits a
self-signed one. A client that registers
`tls_client_certificate_bound_access_tokens: true` is refused a token without a
certificate. A client that authenticated **by certificate** may refresh with a
new certificate (section 7.1), and the new tokens bind to it.
`tls_client_certificate_bound_access_tokens` is advertised only where the port
is TLS.

### Requiring a sender constraint — five settings

Neither mode requires DPoP or mutual TLS. OAuth 2.1 section 4.3.1 lets a public
client's refresh token be **either** sender-constrained **or** rotated, and this
service rotates. RFC 9700 section 2.2.1 makes a sender-constrained access token
a SHOULD. These five settings go further, and every one of them is **off by
default**:

| Setting | Effect |
|---|---|
| `oauth2.refreshTokenRotation` | rotation with replay detection, with both modes off |
| `oauth2.refreshTokenRequireDpop` | no refresh token is minted without a DPoP proof, and an unbound one is refused at the refresh grant |
| `oauth2.refreshTokenRequireMtls` | the same for a client certificate (section 7.1 still passes a certificate-authenticated client) |
| `oauth2.accessTokenRequireDpop` | every protected resource refuses an access token that is not DPoP-bound and proved |
| `oauth2.accessTokenRequireMtls` | the same for a certificate-bound token |

* **The refresh settings refuse the whole token request**, access token
  included. Half a token set is worse than an error, because the client finds
  the missing half an hour later, at a refresh it cannot make.
* **An unbound refresh token is refused**, not bound on first use. Binding it
  would let whoever holds it choose the key.
* **The access-token settings apply at the resource side only.** The token
  endpoint keeps minting Bearer tokens and the resources refuse them, so a
  client can be driven against the refusal. They cover UserInfo, the step-up
  resource, the OpenID4VCI endpoints, `/scim/v2`, Shared Signals,
  `/admin-api` and the debugger. They do not cover GNAP tokens, a registration
  access token, or endpoints that take a token as a parameter (introspection,
  revocation, token exchange). A token this service did not issue is held to
  the rule too. `/admin/api-explorer` stops working while
  `oauth2.accessTokenRequireDpop` is on.
* **The mutual TLS settings need `global.https`.** Without it, every affected
  request is refused.
* The console and portal clients (`sts-admin-console`, `sts-user-portal`) are
  exempt from `oauth2.refreshTokenRequireMtls` only. They redeem over loopback,
  and they carry DPoP proofs of their own. `sts-debugger-ui` is not exempt from
  anything.

### Step-up authentication (RFC 9470)

* **The authorization endpoint honours `acr_values` and `max_age` in every
  mode.** A session that meets them is used. One that does not is sent to sign
  in again, **once**, with a second factor demanded where every value the screen
  can produce needs two. A requirement still unmet on the way back is refused
  `unmet_authentication_requirements`. With `prompt=none` the answer is
  `login_required`.
* **Levels are ordered `0` < `1` < `mfa`** and are published as
  `acr_values_supported`. A token carries the most preferred **requested**
  value that was met. `hwk`, `phr` and `phrh` are met by two factors including a
  security key. Any other value is met only by a sign-in that reports exactly
  that `acr`.
* `acr` and `auth_time` ride in the access token and in introspection, and a
  refresh keeps them.
* **The challenge** (section 3) comes from two places. This service's own
  protected endpoints require `oauth2.stepUpAcrValues` and
  `oauth2.stepUpMaxAgeS`, which require nothing by default. A registered API
  declares its own requirement as `oauthStepUpAcrValues` / `oauthStepUpMaxAge`,
  and `/oauth2/step-up/resource/{application}` stands in for it. A token that
  falls short is answered 401 with
  `WWW-Authenticate: Bearer error="insufficient_user_authentication"`, plus the
  `acr_values` and `max_age` it needs.

### Not implemented

* `mtls_endpoint_aliases` (RFC 8705 section 5): the endpoints already ask for a
  certificate where they are.
* A client certificate forwarded in a header by a TLS-terminating proxy.
* `acr_values` on the device and token-exchange grants; GNAP's interaction does
  not read a step-up requirement.

## Development and product mode

* **Product mode implies RFC 9700 mode**, for every client in every realm, and
  a realm cannot turn it off. A public client is allowed in return. It is held
  to PKCE with `S256`, an exactly matched registered redirect URI, rotating
  refresh tokens, and the authorization code and refresh grants only.
* OAuth 2.1 mode, FAPI and the five sender-constraint settings are **not**
  implied by product mode. Turn them on explicitly.
* `POST /dpop/nonce-mode` is a development test control. Product mode refuses
  it, and `oauth2.dpopNonceRequired` is then changed only through
  `/admin/oauth2` or `POST /admin-api/config/set`.
* RFC 8705's declared refusals, RFC 9068 and RFC 9470 apply **in every mode**.
* Certificate revocation is **soft-fail** in development and **hard-fail** in
  product (`pki.revocationCheck=auto`). This decides whether a certificate from
  another authority whose status cannot be fetched may authenticate a client.
  See [PKI](pki.md).

## Configuration

`global.https` (the HTTPS main port) and `global.trustProxy` (forwarded
headers) are described on [Configuration](configuration.md) and
[TLS](tls.md).

### Compliance modes

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `oauth2.rfc9700` | `STS_OAUTH2_RFC9700` | `false` | restart (a realm may carry it) | RFC 9700 mode: enforce the OAuth 2.0 Security BCP on the authorization flow, and bind the main port as HTTPS. |
| `oauth2.oauth21` | `STS_OAUTH2_OAUTH21` | `false` | restart (a realm may carry it) | OAuth 2.1 mode (draft-ietf-oauth-v2-1-16): turns RFC 9700 mode on and adds the draft's own requirements. |
| `oauth2.fapi` | `STS_OAUTH2_FAPI` | `off` | restart (a realm, or a named authorization server, may carry it) | A FAPI security profile: `off`, `1-baseline` (FAPI 1.0 Part 1), `1-advanced` (Part 2), `2-security` (the FAPI 2.0 Security Profile) or `2-message-signing` (FAPI 2.0 Message Signing over it). Turns RFC 9700 mode on and adds the profile's requirements. |
| `oauth2.fapiRequireMtls` | `STS_OAUTH2_FAPI_REQUIRE_MTLS` | `false` | yes | Under FAPI 1.0 Advanced, accept only mutual TLS as the sender constraint; off, a DPoP-bound token counts too. |
| `oauth2.redirectUris` | `STS_OAUTH2_REDIRECT_URIS` | *(empty)* | yes | The redirect URIs RFC 9700 mode compares against, by exact string, for a client that registered none of its own. |
| `oauth2.loopbackPortWildcard` | `STS_OAUTH2_LOOPBACK_PORT_WILDCARD` | `true` | yes | In RFC 9700 mode, let a registered loopback redirect URI match on any port (RFC 8252 section 7.3). |
| `oauth2.refreshIdleSeconds` | `STS_OAUTH2_REFRESH_IDLE_SECONDS` | `86400` | yes | In RFC 9700 mode, how long a refresh chain may go unused before it stops working; 0 is off. |
| `oauth2.revokeRefreshOnLogout` | `STS_OAUTH2_REVOKE_REFRESH_ON_LOGOUT` | `true` | yes | In every mode, revoke the refresh tokens issued on a browser session without `offline_access` when that session ends (Back-Channel Logout section 2.7). |
| `oauth2.maxPendingTransactions` | `STS_OAUTH2_MAX_PENDING_TRANSACTIONS` | `500` | yes | How many authorization transactions RFC 9700 mode remembers to refuse a reused PKCE challenge or nonce. |
| `oauth2.maxRefreshTokenFamilies` | `STS_OAUTH2_MAX_REFRESH_TOKEN_FAMILIES` | `2000` | yes | How many refresh tokens are tracked for rotation and replay detection. |
| `oauth2.breakIdTokenNonce` | `STS_OAUTH2_BREAK_ID_TOKEN_NONCE` | `false` | yes | Put a deliberately wrong `nonce` in every ID Token, to find out whether a client checks it. Development mode only. |

### DPoP

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `oauth2.dpopNonceRequired` | `STS_OAUTH2_DPOP_NONCE_REQUIRED` | `false` | yes | Require every DPoP proof to carry a nonce this server supplied; makes proofs fresher, never mandatory. |
| `oauth2.dpopIatSkewS` | `STS_OAUTH2_DPOP_IAT_SKEW_S` | `300` | yes | How far a proof's `iat` may be from now, either way. |
| `oauth2.dpopNonceTtlS` | `STS_OAUTH2_DPOP_NONCE_TTL_S` | `300` | yes | How long a server-supplied nonce is accepted. |
| `oauth2.dpopReplayCacheSize` | `STS_OAUTH2_DPOP_REPLAY_CACHE_SIZE` | `100000` | yes | How many live proof `jti`s a realm remembers; a full history refuses the next proof. |
| `oauth2.dpopNonceCacheSize` | `STS_OAUTH2_DPOP_NONCE_CACHE_SIZE` | `10000` | yes | How many issued nonces a realm holds; past it the oldest is dropped. |

### Sender constraints

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `oauth2.refreshTokenRotation` | `STS_OAUTH2_REFRESH_TOKEN_ROTATION` | `false` | yes | Rotate refresh tokens with replay detection even with both compliance modes off. |
| `oauth2.refreshTokenRequireDpop` | `STS_OAUTH2_REFRESH_TOKEN_REQUIRE_DPOP` | `false` | yes | Refuse to issue a refresh token without a DPoP proof, and refuse an unbound one at the refresh grant. |
| `oauth2.refreshTokenRequireMtls` | `STS_OAUTH2_REFRESH_TOKEN_REQUIRE_MTLS` | `false` | yes | The same for RFC 8705 client certificates; needs `global.https`. |
| `oauth2.accessTokenRequireDpop` | `STS_OAUTH2_ACCESS_TOKEN_REQUIRE_DPOP` | `false` | yes | Refuse any presented access token that is not DPoP-bound and proved, at every resource. |
| `oauth2.accessTokenRequireMtls` | `STS_OAUTH2_ACCESS_TOKEN_REQUIRE_MTLS` | `false` | yes | Refuse any presented access token not bound to the connection's client certificate; needs `global.https`. |

### Step-up

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `oauth2.stepUpAcrValues` | `STS_OAUTH2_STEP_UP_ACR_VALUES` | *(empty)* | yes | The `acr` values this service's own protected endpoints require, in order of preference; empty requires nothing. |
| `oauth2.stepUpMaxAgeS` | `STS_OAUTH2_STEP_UP_MAX_AGE_S` | `-1` | yes | The `max_age` those endpoints require; -1 requires nothing (0 is a real requirement). |

These tables are a copy of rows in `common/config.js`. The live source is
`/admin/oauth2` (and `/admin/token-lifetimes` for the two per-client refresh
settings) and `GET /admin-api/config`, which also give each row's full
description. See [Configuration](configuration.md) for how a value is resolved.
Change a value on the console page or with `POST /admin-api/config/set`. A
client may override `oauth2.refreshIdleSeconds` and
`oauth2.revokeRefreshOnLogout` on its own entry.

## Design decisions

* **The BCP is a mode, not the default.** A client is exercised by both
  answers. The existing callers of this service (unregistered redirect URIs, no
  PKCE, the implicit grant) would simply stop working if the mode were always
  on, with no explanation.
* **A mode that is off runs nothing.** With `oauth2.rfc9700` off, every endpoint
  behaves exactly as it did before the mode existed.
* **TLS is a property of the socket, so it is settled at `listen()`.** A request
  cannot usefully be refused for arriving over HTTP, because it has already
  arrived and the refusal would go back over the same channel. That is why the
  flag is restart-only for the process and not for a realm.
* **The model is published, and every requirement has a row.**
  `/oauth2/rfc9700` states which requirements are enforced, detected or not,
  with reasons. A compliance mode that quietly skipped something it advertises
  would be the most misleading thing in the service.
* **OAuth 2.1 is a mode of its own.** In two places RFC 9700 mode refuses a
  client that follows OAuth 2.1 to the letter, so 2.1 cannot be RFC 9700 mode
  renamed.
* **FAPI is a profile over RFC 9700 mode, not a third mode beside it.** FAPI
  1.0 predates RFC 9700, and most of what it asks is already a row there. The
  profile holds only the difference, and it can be set per authorization
  server because a FAPI deployment usually sits beside an ordinary one.
* **FAPI's consent rule applies to this service's own surfaces too.** A
  seeded global consent is an administrator's decision, and FAPI asks for the
  person's.
* **The idle timeout refuses without revoking.** An idle chain is a client that
  went away. A replayed chain is one that was copied. Treating the two the same
  would make the replay refusal mean nothing.
* **`oauth2.breakIdTokenNonce` is not part of the mode.** A compliance flag that
  also breaks tokens is one nobody would turn on. It belongs to development
  mode instead (#104): product ignores it where the ID Token is built and
  refuses writing it.
* **No DPoP-required mode; five explicit settings instead.** Neither
  specification asks for them. They exist so a client can meet a strict server
  here before it meets one in production, and nothing turns them on implicitly.
* **An unverified client certificate still binds a token.** RFC 8705 section 3
  binds to the certificate and allows a self-signed one. Requiring verification
  would make binding unreachable, because the truststore starts empty.
* **No certificate from a header.** Anybody can write `X-Client-Cert`. The cost
  (a proxy terminating mutual TLS cannot pass the certificate through) is
  accepted and stated.
* **One decision about forwarded headers.** The published URLs and the DPoP
  `htu` check read `X-Forwarded-*` through one switch, `global.trustProxy`, so
  the two cannot disagree.
* **A refusal the client asked for applies in every mode.** A declared
  certificate method, `tls_client_certificate_bound_access_tokens`, and an
  unmeetable `acr_values` are refused even in development, because the client
  chose them.
* **One step-up attempt.** A person who fails a step-up gets exactly one more
  sign-in. After that the request is refused rather than looping.

## In the running service

* `/admin/oauth2` holds every setting on this page and reports which mode is in
  force, and why.
* `GET /oauth2/rfc9700`, `GET /oauth2/oauth21` and `GET /oauth2/fapi` publish
  the requirement tables, with what is enforced and the sender-constraint
  state.
* `/admin/applications` holds a client's certificate methods, subject
  parameters, TLS client certificates and step-up requirement.
* **Monitoring → OAuth 2.0 / OIDC activity** (`/admin/oauth2/monitor`) counts
  step-up outcomes and challenges per client.
* `GET /tls` and `/tls/forwarded` show what a connection presented and which
  forwarded headers were believed.
* `GET /dpop/nonce-mode` reports whether nonces are required in this realm.

## Related

* [OAuth 2.0 & OpenID Connect](oauth-oidc.md)
* [TLS](tls.md) — the main port, the client truststore, certificate sign-in
* [PKI](pki.md) — the certificate authority that issues client certificates
* [Accepted tokens](accepted-tokens.md)
* [Authentication](authentication.md) — second factors behind `mfa`
* [Configuration](configuration.md), [Trust realms](trust-realms.md),
  [What is not checked](what-is-not-checked.md), [Error codes](error-codes.md)
