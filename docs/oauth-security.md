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
* A **nonce** is required with any `id_token` — OpenID Connect Core already
  requires one, in every mode, for the implicit flow and for the hybrid
  `code id_token` and `code id_token token` — and
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

### The OpenID Foundation's conformance suite

The FAPI profiles are checked against the OpenID Foundation's own
conformance suite as part of `./run-tests.sh` (#176). Each plan runs in a
realm of its own under the profile it tests, and a module that fails fails the
run. The plans, and where they stood on 2026-09-24 with suite
`release-v5.3.1`:

| Plan | Variant | Result |
|---|---|---|
| FAPI 2.0 Security Profile (final) | `private_key_jwt`, DPoP, Grant Management | no failures |
| FAPI 2.0 Message Signing (final) | signed request at PAR, JARM | no failures |
| FAPI 1.0 Advanced (final) | `private_key_jwt`, mutual TLS, request by value | no failures |
| FAPI-CIBA (ID1) | poll, `private_key_jwt`, mutual TLS | no failures |

Every module ends with a WARNING, because this service's key set carries
post-quantum keys the suite cannot read. The suite has no FAPI 1.0 Baseline
plan any more. Baseline is covered by this repository's own tests only.

A resource this service serves (UserInfo, `/oauth2/grants/{id}` and the
step-up resource) returns `x-fapi-interaction-id`: the client's value when it
sent a UUID, and a new UUID when it did not (FAPI 1.0 Baseline section 6.2.1).

### FAPI-CIBA

Wherever a FAPI profile (`oauth2.fapi`) and CIBA (`oauth2.ciba`) are both on,
the backchannel authentication endpoint applies the
[FAPI CIBA profile](https://github.com/openid/fapi/blob/main/fapi-ciba.md).
It has no setting of its own.

* **Confidential clients only**, authenticated with a method the profile
  allows, a client assertion signed with its algorithms (and, under FAPI 2.0,
  dated no more than a minute ahead).
* **A `binding_message` in every request.** It is what the person compares on
  the two devices.
* **Poll and ping, never push.** `backchannel_token_delivery_modes_supported`
  lists the two; a push client is refused at registration and at the endpoint.
* **Signed and unsigned requests.** A signed one lasts at most 60 minutes and
  is signed with the profile's algorithms.
* **`request_context`**, a JSON object about the consumption device, is
  accepted and shown to the person on `/portal/ciba`.
* **Sender-constrained tokens.** The token endpoint's profile checks apply to
  the CIBA grant as to every other.

### DPoP (RFC 9449)

* All **twelve section 4.3 proof checks**, each numbered in the source,
  including the four that are easiest to leave out: `typ`, `htm`/`htu`, `ath`
  and the comparison against `cnf.jkt`.
* `cnf.jkt` on **access and refresh tokens**. A proof at the token endpoint
  binds the access token. It binds the refresh token only for a client that
  did not authenticate: section 5 says a confidential client's refresh token
  is constrained by its authentication instead, so that client may prove a
  new key at each refresh. `oauth2.refreshTokenRequireDpop` binds every
  refresh token.
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

* A client certificate forwarded in a header by a TLS-terminating proxy.
* `acr_values` on the device and token-exchange grants; GNAP's interaction does
  not read a step-up requirement.
* The `web_message` response mode (RFC 9700 section 4.17). A request for it is
  refused; see [In-browser communication](#in-browser-communication-section-417).

## RFC 9700 mode in detail

This service is permissive on purpose in development mode, and a client that
has only ever been pointed at a permissive server has never run the code paths
it will need in production. RFC 9700 is a list of things a real authorization
server refuses, so it is here as a switch. With `oauth2.rfc9700` off, nothing in
`oauth2_bcp.js` runs. With it on, the whole of section 2 is enforced, both
discovery documents stop advertising what would now be refused, and the main
port is an HTTPS listener, so every URL those documents publish, the issuer
included, names `https`.

Every refusal the mode introduces names RFC 9700 and the section, because a 400
saying only `invalid_request` sends somebody looking through their own code for
a decision this server made. RFC 9700 defines no discovery member and no
endpoint of its own, so `GET /oauth2/rfc9700` is the only way a client can find
out which kind of server it is talking to: whether the mode is on, the settings,
and every requirement with its section, level, whom it binds and whether it is
enforced. The subsections below explain the reasoning behind the rows; the rows
themselves are published there.

### Redirect URIs (section 2.1)

`redirect_uri` is compared to the registered URIs by **exact string match**
(RFC 3986 section 6.2.1): no normalisation, no trailing-slash forgiveness, no
case folding of the path, and no pattern syntax in the comparison at all. That
last part is the only way to be sure of the *MUST NOT* beside it: a matcher that
supports wildcards and is configured not to use them is one configuration
mistake away from an open redirector.

The registered set is the client's own `redirect_uris`, or the
`oauth2.redirectUris` setting for a client that registered none. That setting is
empty by default, so turning the mode on with nothing configured refuses every
authorization request from such a client. The refusal names the setting and the
registration endpoint.

The exception is **RFC 8252 section 7.3**: a native application cannot reserve
a port, so a registered loopback URI (`127.0.0.1`, `[::1]` or `localhost`)
matches on any port. Everything else about it must still match, and the host
must be the same literal: a registration for `http://127.0.0.1/cb` does not
authorise `http://localhost/cb`, because treating two names as one is a pattern
match by another route. `oauth2.loopbackPortWildcard=false` turns the exception
off, which makes this server deliberately **non**-compliant; that is how a
native client is shown a server that got this wrong.

`http` is refused off the loopback (section 2.6).

**The order of the checks matters.** The `redirect_uri` is matched first, and a
failure is answered here as a 400. Every other refusal is reported by
redirecting to `redirect_uri`, which is right once that URI is known to be
registered and is an open redirector until then: `error=invalid_request`
forwarded to an arbitrary URL is still the browser forwarded to an arbitrary
URL.

`post_logout_redirect_uri` at `/oauth2/logout` is held to the client's own
registered list in every mode (#124). Development mode still follows an address
for a client that registered none; this mode, OAuth 2.1 mode and product mode
do not.

### The HTTPS port (section 2.1)

*Authorization responses MUST NOT be sent over unencrypted connections* is the
one requirement no check can satisfy: by the time any code runs the request has
arrived, and refusing it would report the problem down the same channel. So the
mode settles it where the socket is bound, through `global.https`, whose default
is the mode's flag. It is a setting of its own so that each direction can be set
independently. The main port serves the same certificate LDAPS 636 and the
embedded debugger's listener serve, so a caller trusts this service once.

**Everything a client reads follows the socket by itself.** Every URL is built
from the scheme and the Host header of the request (or `global.publicBaseUrl`),
so the RFC 8414 document, the OpenID Provider Configuration, the OID4VCI and
OID4VP metadata, the federation metadata, the DID document and the `iss` of
every token move together. Nothing pins a scheme.

The one exception is a **pinned issuer**. A pinned `http://` `oauth2.issuer`
served over `https` has its scheme upgraded, and the upgrade is logged. It is an
upgrade rather than a refusal because a conforming relying party must reject a
document whose `issuer` differs from where it fetched it, so every client would
fail with a message about the issuer, leaving the reader to work out that the
scheme moved. A pinned issuer with a different **host** or path is left alone:
that mismatch is worth producing on purpose.

**The setting is restart-only for the process.** A flag that was runtime for
its checks and restart-only for its socket would report the mode as on at
`/admin/oauth2` while every authorization response still went out over plain
HTTP. Set it in the appconfig file or as `STS_OAUTH2_RFC9700` and restart;
`POST /admin-api/config/set` refuses it with that reason. A **trust realm** may
carry it anyway (`oauth2.oauth21` too), because a realm binds no socket:

```bash
curl -k -X POST https://localhost:8081/admin-api/realms/create \
     -H 'Content-Type: application/json' \
     -d '{"id":"rfc9700","name":"RFC 9700 mode",
          "overrides":{"oauth2.rfc9700":true}}'
```

gives one process a permissive authorization server at `/oauth2/authorize` and a
compliant one at `/realm/rfc9700/oauth2/authorize`, each with its own issuer,
signing key, codes and tokens. `/admin/oauth2` reached under that prefix offers
the control the default realm's page refuses. What a realm does not bring is a
scheme: a compliant realm on a plain-HTTP process enforces every check, still
publishes `http://` endpoints, and `GET /oauth2/rfc9700` reports the four
deployment requirements as `no` rather than `deployment`. Turn `global.https` on
for the process (`STS_HTTPS=true`) and leave `oauth2.rfc9700` to the realm for a
compliant pass over HTTPS.

**With the port on TLS there is no plain listener**, so the first fetch of
`GET /tls/server-certificate` or `POST /tls/trust` is made without verifying the
certificate (`curl -k`). That is the same act as trusting the PEM the endpoint
hands back, one step earlier. `/tls`, `/admin/sts-metadata` and the startup line
say so, and the compose healthcheck picks its scheme from the environment.

The session cookie is `Secure` when, and only when, the port is TLS: a browser
drops a `Secure` cookie that arrives over plain HTTP, so an unconditional flag
would leave a plain-HTTP deployment with a sign-in that seems to work and a
session that is never there.

`global.https=false` runs every other check over plain HTTP for a client that
cannot be taught to trust the certificate. `GET /oauth2/rfc9700` reports that
case as `response-over-tls: no`, with the reason.

### The authorization code flow (section 2.1.1)

**PKCE is required of every client this server cannot see to be
confidential.** A client is confidential only when its entry declares a
`token_endpoint_auth_method` other than `none`; a registration that omits the
member is confidential, since RFC 7591 section 2 makes `client_secret_basic` the
default. Everything else, including a `client_id` never registered, is public
and must send a `code_challenge`. For a confidential client PKCE is a *SHOULD*:
the request is answered and the omission logged, because a server a client is
calibrated against should not be stricter than the specification.

`code_challenge_method=plain` is refused and `code_challenge_methods_supported`
drops to `S256` alone, so the document and the endpoint agree. An `S256`
challenge must be 43 characters of base64url, which catches a verifier sent as a
challenge at the authorization request instead of leaving it to fail as a
mismatch later.

At the token endpoint the mode adds the **PKCE downgrade** refusal (section
4.8.2): a `code_verifier` for a code issued *without* a challenge is rejected
rather than ignored. Ignoring it is how the downgrade works.

**Transaction-specific values are detected.** A `code_challenge` or `nonce` is
remembered from the moment a code is issued for it, with its client and whether
the code was redeemed. Presenting it for a *new* request after that code was
redeemed is refused, and so is the same value from a different `client_id`. The
same value while the earlier code is still unredeemed is **not** refused: that
is a reloaded tab or a retried request, and refusing it is how a check like this
gets turned off by the people it was meant to help. A response carrying no code
ends its transaction at once, so its `nonce` is recorded as spent immediately;
otherwise reuse would be undetectable in the one flow where the nonce is the
only protection. The check runs immediately before a code is minted, because an
authorization request passes through `/oauth2/authorize` twice (before and after
the sign-in screen) and would otherwise collide with itself.
`oauth2.maxPendingTransactions` bounds how many are remembered.

A `nonce` is required whenever `response_type` names `id_token`: the nonce is
what makes an injected code detectable for a client without PKCE (section
4.5.3.2).

### Sender-constrained tokens (sections 2.2 and 2.2.1)

The BCP names two mechanisms and both are here: [DPoP](#dpop-rfc-9449), which
works for public clients (which is why the wallet flows use it), and
[certificate binding](#mutual-tls-rfc-8705). A certificate-bound grant binds the
**refresh token** too: otherwise the long-lived half of the grant would be a
bearer credential minting bound tokens for whoever holds it, and the `cnf` on
what it mints would imply a guarantee nobody checked.

The two resource-server MUSTs, that a proof of possession is validated and its
replay prevented, are checked at `presentedAccessToken()`, the one check the
protected endpoints share. `/admin-api` and the embedded debugger's listener
verify their own tokens, and each also refuses a DPoP-bound token presented as
`Bearer` (`STS-API-0120`, `STS-DBG-0031`) and reads `Authorization: DPoP`. That
refusal holds in every mode whatever the settings say, because it honours a
constraint the token already carries. Requiring a constraint where the token has
none is the job of the [five settings](#requiring-a-sender-constraint--five-settings).

### Audience restriction and least privilege (section 2.3)

A single fixed audience, `<base>/resource`, is a restriction that buys nothing.
[RFC 8707 resource indicators](oauth-oidc.md#grants-at-the-token-endpoint) make
the audience something a client asks for:

* `resource` must be an absolute URI with **no fragment** (a fragment is never
  sent to a server, so an audience with one names something no resource server
  can match). Repeating it asks for the small set section 2.3 allows.
* It is read for **every grant**, and a malformed one is `invalid_target`. The
  token endpoint may **narrow** what the authorization request asked for and
  never widen it; the other grants had no authorization request, so what is
  asked for is what is granted. RFC 8693's `audience` and `resource` are
  unioned.
* **The resource server refuses a token meant for somebody else**: a token for
  `https://api.example.com/v1` presented at `/oauth2/userinfo` is
  `401 invalid_token`, naming the audience it was for. This applies to tokens
  this service issued; "this resource server" is the whole URL
  (`<base>/resource`, or `<base>/<id>/resource` for a named authorization
  server), as RFC 9068 section 4 requires.
* A request that sends no `resource` is unaffected, in either mode: this is a
  feature, not a mode behaviour.

**A scope naming another application is an audience too**, because a scope list
is how clients name a resource server in practice. A scope value that is the
`oauthClientId` of another application in the registry becomes the `aud`
verbatim and comes off the scope claim. A spec-defined scope is never an
audience, so a client registered as `profile` cannot readdress every OIDC token,
and a client's own `client_id` is skipped. **A token for an API is for the API
alone**: `scope=openid email profile apigw1` produces `aud: apigw1` without the
OpenID Connect scopes on the access token, because RFC 9068 section 2.2.3 says
every scope on a token must mean something to its audience. Those scopes are
still granted: the ID Token is issued and the refresh token keeps the whole
scope. [RFC 9068 section 3](oauth-oidc.md#jwt-access-tokens-rfc-9068)'s
ambiguous requests are refused:

| Request | Answer |
|---|---|
| a scope naming two applications or two APIs' permissions | `invalid_scope` |
| `resource=A` with a scope naming application B | `invalid_scope` |
| two or more `resource` values and a scope tied to none of them | `invalid_target` |

A multi-audience token may carry a delegated permission (kept whole, since it
names its API) and, where this service's own resource server is an audience,
OpenID Connect scopes.

For least privilege, a refresh may not widen a scope and the audience is
restrictable. In development mode this service grants a scope it does not
advertise rather than refusing it, because callers test exactly that, and logs
it as a least-privilege observation; product mode holds a client to the scopes
it declares. RFC 9396 `authorization_details` is the finer-grained mechanism the
section points at.

### Authorization code protection (section 4.5)

Outside the compliance modes an **identical** repeat of a token request gets back
the tokens it already got (see
[Grants](oauth-oidc.md#grants-at-the-token-endpoint)). RFC 6749 section 4.1.2
says a real server refuses that, so **in this mode it does**, and does the
SHOULD beside it (section 10.5): the access, refresh and ID Tokens the code bought
are revoked through the same set `/oauth2/revoke` writes to, so they report
`active: false` at introspection at once. A code presented twice means two
holders, and nothing can tell which is the client. The refusal says how long
ago the code was redeemed, by which client, and how many tokens went with it.

Two more specific refusals stay ahead of it in every mode: a repeat that
**differs** names the field that differed, and an expired code says so and
points at the refresh token from the first redemption. The code is bound to its
client (`transaction-bound`).

### Open redirectors (section 4.11.2)

Exact matching closes most of this. What is left works **even when every URI is
registered**: send a victim to a legitimate client's authorization request with
something wrong in it, and a server that bounces errors straight back sends them
to that client's registered URI carrying the attacker's `state`, with nobody
having signed in.

So in this mode an error is redirected automatically **only when there is a
session**. Otherwise the person gets a page naming the application, where it
wants them sent, the `state` and the error, with a link they may follow (the
section's *inform the user and rely on the user to make the correct decision*).
The page has **no script and no button**; an interstitial that submitted itself
would be an automatic redirect with an extra page in front. Two exceptions come
from the specification: **`prompt=none`**, whose whole contract is that nothing
is shown and `login_required` is the answer, and **a refusal coming back from the
sign-in screen**, where the person is present and has just decided. A success is
never affected, because it implies a session.

A request with **no `client_id`** is a 400 and never redirected: RFC 6749
section 4.1.2.1 forbids redirecting for an invalid `client_id` and
`redirect_uri` combination, and no client means the URI belongs to nobody.

*Redirect only to trusted URIs* is the exact-match list. URI analytics and
content reputation, which the BCP also suggests, are not attempted, and the row
says so. The client's half, *clients MUST NOT expose open redirectors*, is a row
with `enforced: no`.

### The nonce is the client's job (section 4.5.3.2)

*The client MUST validate the nonce in the ID Token and MUST NOT use any token
until it has.* Nothing this server can observe separates a client that checks
from one that does not, so both requirements are rows with `enforced: no`. This
server's half is that the ID Token always carries the nonce from the request,
and that the mode refuses a request for an `id_token` without one.

`oauth2.breakIdTokenNonce` lets a client author test the other half: every ID
Token that should carry a nonce gets a deliberately wrong one. It is the same
kind of device as the reserved password `invalid`: a reachable negative, off by
default, not part of the mode, reported on `GET /oauth2/rfc9700` whichever mode
is in force, and logged on every token it spoils. In a product-mode realm it is
ignored where the ID Token is built (logged once, `STS-CORE-0106`), and turning
it on is refused (`STS-CORE-0103`).

### The implicit grant (section 2.1.2)

Any `response_type` naming `token` (`token`, `code token`, `id_token token`,
`code id_token token`) is refused `unsupported_response_type`, and the metadata
drops all four and the `implicit` grant type. `id_token` and `code id_token`
remain, because they issue no access token from the authorization endpoint.

### Refresh tokens (section 2.2.2)

*Refresh tokens for public clients MUST be sender-constrained or rotate.*
"Public" is the safe reading of a client this service cannot authenticate, so
**rotation applies to every client**: redeeming a refresh token retires it
through the revocation set, so the old token reports `active: false` at
introspection. `oauth2.refreshTokenRotation` turns rotation and its replay
detection on with both modes off, and nothing else: the idle timeout, the client
binding and the scope subset check stay with the mode. With a mode on, the
setting changes nothing.

**Replay detection** is why a retired token is remembered. One coming back means
the chain was copied, and nothing can tell whether the client or an attacker
holds it, so both lose it. Every refresh token descended from one grant is a
**family**, recorded at issuance so a long chain is one lookup, and a replay
revokes the family, saying how many and why. Access tokens already minted are
left alone: they are short-lived, and revoking them would remove the evidence
of what the lost credential was used for.

Under the mode a refresh must come from the client the token was issued to
(`client_id` is required, RFC 6749 section 6), and the requested `scope` must be
a **subset** of what was granted. The refresh token also carries its
**resources**, so a token narrowed with RFC 8707 cannot be refreshed into one
with the default audience; asking for a resource the grant does not carry is
`invalid_target`.

**An idle chain expires** after `oauth2.refreshIdleSeconds`, measured from the
last redemption anywhere in the chain, so a client that refreshes regularly
keeps its grant. It **refuses** rather than revoking the family, because an idle
chain is a client that went away, not a chain that was copied. `0` turns it off.

**Signing out revokes them**, in every mode: the section's MAY names logout,
and without it signing out would leave a long-lived credential with the client.
It happens where every protocol's sign-out ends a session, so there is one
place to disagree with. Access tokens are left to expire.

The remaining MUSTs have rows. A refresh token is a signed and encrypted JWT
with a 128-bit random `jti`, and the grant verifies it before reading a claim,
which is what makes its client binding and resource list worth anything. This
service keeps no copy of a refresh token to protect in storage, only the
identifiers it needs for rotation and revocation. The risk assessment is a
written policy: a refresh token is issued only where a grant has an end user
behind it, so `client_credentials` gets none (RFC 6749 section 4.4.3).

### The password grant (section 2.4)

The one grant RFC 9700 rules out: it hands the person's password to the client
and cannot carry a second factor. In this mode `grant_type=password` is
`unsupported_grant_type`, it leaves `grant_types_supported` in both discovery
documents, and **`POST /oauth2/register` refuses to register a client for it**
(`invalid_client_metadata`, RFC 7591 section 3.2.2), so the client learns when it
registers rather than at its first token request. The same registration check
refuses `grant_types: ["implicit"]`, any `response_types` naming `token`, and an
`http://` redirect URI off the loopback. Returning metadata silently different
from what was asked, which RFC 7591 permits, would make a client compare the
two documents field by field to notice.

In development mode outside the compliance modes the grant stays available,
because a client with code for it needs somewhere to run that code.

### Client authentication (section 2.5)

Section 2.5 applies where there is a process for issuing credentials, and
`POST /oauth2/register` is one (the `client-credential-issuance` row). A client
whose entry is **confidential** must authenticate by the method its entry
declares, and every method is verified:

| Method | What proves the client |
|---|---|
| `client_secret_basic` / `client_secret_post` | the secret, compared in constant time |
| `client_secret_jwt` | an assertion signed HS256 with the secret |
| `private_key_jwt` | an assertion signed with the client's key: its registered `jwks` or `jwks_uri`, a JWKS this service's certificate authority issued it (`oauthAssertionJwks`), or an `x5c` chain to this realm's Root CA |
| `tls_client_auth` | a verified client certificate, issued by this realm to this application or carrying the one subject it registered (RFC 8705 section 2.1) |
| `self_signed_tls_client_auth` | the certificate is the `x5c` of a key in its `jwks`, or matches its registered thumbprint (RFC 8705 section 2.2) |

The JWT methods get RFC 7523 section 3 in full: the signature, `iss` **and**
`sub` both the client, the audience (the token endpoint *or* the issuer, because
RFC 7523 and OpenID Connect Core section 9 differ and client libraries pick one
each), expiry with a configurable skew, and a `jti` accepted **once, ever**. One
used-assertion history covers client authentication and both assertion grants,
persists in the `ldif` and `postgres` stores in both modes, is claimed
atomically on postgres, and spends an assertion only when its request issues
tokens; `/admin/used-assertions` lists it.

An assertion may arrive **encrypted** (RFC 7523 section 3, claim 10): a JWE whose
plaintext is the JWS, in any of sixteen key management and six content
encryption algorithms. An asymmetric one is encrypted to the key published at
`/oauth2/jwks`, and a symmetric one under the client secret, the only shared
key there is. A JWE whose plaintext is not a signed JWT is refused: encryption
says nothing about who wrote a document. `RSA1_5` is refused by name (RFC 8017
deprecated it, and a safe implementation needs unwrap failures to be
indistinguishable along a whole code path).

**An assertion nominating `HS256` for `private_key_jwt` is refused**, not
verified: verifying it would use the client's *public* key as an HMAC secret,
the classic JWT forgery. **`client_id` may be omitted** with `private_key_jwt`
(OpenID Connect Core section 9): the `sub` selects the client, and the assertion
must then verify against that client's keys with `iss` and `sub` matching, so a
forged `sub` picks a client whose key will not verify it.

`token_endpoint_auth_methods_supported` is built from what the verifier can
check, and the certificate methods appear only where there is a TLS handshake.
A client using a shared secret is answered and **logged** every time as the
asymmetric RECOMMENDED it did not follow; refusing a SHOULD would be stricter
than the specification. A failing client secret is **rate limited** wherever it
is checked, in every mode, per realm and per client and address together, so
nobody elsewhere can lock a client out.

In development mode, a client with nothing on its entry to check against is left
alone, and so is a `client_id` never seen; product mode refuses an unknown
client. **No end user's password is checked by this mode**; that is
`global.mode`'s decision (see [What is not checked](what-is-not-checked.md)).

### Authorization server metadata, and more than one of them (section 2.6)

The point of the section is that clients should not hard-code what a server can
advertise. Both documents are built from one object so they cannot disagree,
and `code_challenge_methods_supported` is among them (the one capability with no
other signal: a server that supports PKCE and does not say so will never be
asked for it).

The question worth asking about a client is what it does **when the metadata
says something else**, so a discovery document selects an
[authorization server](oauth-oidc.md#multiple-authorization-servers--adminauthorization-servers):

```
/.well-known/oauth-authorization-server            the default
/.well-known/oauth-authorization-server/tenant1    tenant1   (RFC 8414 section 3.1 inserts)
/tenant1/.well-known/openid-configuration          the same  (OIDC Discovery section 4 appends)
```

**What the document says is what that server does.** The members marked
*enforced* drive its endpoints, so narrowing one narrows that server alone:

```
POST /admin-api/authorization-servers/set
  {"profile":"tenant-alpha","member":"grant_types_supported","value":["authorization_code"]}

POST /oauth2/token               grant_type=client_credentials  →  access_token
POST /tenant-alpha/oauth2/token  grant_type=client_credentials  →  unsupported_grant_type
```

* **Every authorization server starts equal**: one never configured has the
  default's capabilities, and a profile with no overrides publishes exactly the
  default document.
* **Every client may use every one.** `/admin/applications` records which each
  client has used, on `appAuthorizationServer`.
* **Any configuration is valid.** A member this service has never heard of is
  stored and published, because answering with something a client did not
  expect is half the value. The catalogue on the page is help, not a schema.
* **Drift** means a member this service cannot honour however it is set:
  `id_token_signing_alg_values_supported: ["ES256"]` where nothing signs ES256, a
  `token_endpoint` on another host, or an invented member. It is still
  published, since a misconfigured document is what a client's error paths
  need, and it is reported:

  ```
  require_pushed_authorization_requests   invented   Nothing here backs it.
  x_vendor                                invented   Nothing here backs it.
  ```

* **Remove and reset are different.** Reset undoes an override; remove publishes
  an absence. Removing an enforced member stops the check it drives, because a
  client cannot learn from an absent `code_challenge_methods_supported` that
  PKCE is unavailable, and a server refusing on the strength of a removed member
  would enforce something it never said.

`/admin/sts-metadata` lists the authorization servers this process has served,
described by hand because one route (`/:as/oauth2/…`) serves all of them. The
authorization servers of a realm sign with that realm's keys: separate issuers
sharing keys, which a real deployment would not do. The profiles are
configuration, kept in the persistence store (gone on restart in development
mode, kept in product mode on postgres), not in the directory.

### TLS and reverse proxies (section 2.6)

*Use TLS, end to end where possible; if TLS terminates at a proxy, secure the
proxy-to-application hop and have the proxy sanitise inbound security-sensitive
headers.* Every endpoint here (authorization, token, discovery, UserInfo and the
credential endpoints) is on one listener, so *end to end* is true inside this
process.

The application's half of the proxy rule is `global.trustProxy`, **off by
default**, the one switch that decides whether `X-Forwarded-Proto` and
`X-Forwarded-Host` are believed, for both the published URLs and the DPoP `htu`
check. Two answers to the same question would each be wrong for the other's
deployment: behind a proxy, ignoring the headers publishes `http://` URLs and
names the last hop as issuer; with no proxy, believing them lets a client choose
the `htu` its own proof is checked against, and so replay a proof captured at
another endpoint. With it off, `X-Forwarded-Host: attacker.example` changes
nothing; with it on, `X-Forwarded-Host: sts.example.com` produces
`issuer: https://sts.example.com` and every endpoint with it. A DPoP proof
made against a proxy's URL while it is off is refused, and the refusal names the
setting.

**No client certificate is ever read from a header** (`X-Client-Cert`,
`X-Forwarded-Client-Cert`, `X-SSL-Client-Cert` or any vendor spelling): a header
costs nothing to forge. The cost, stated rather than hidden, is that a proxy
terminating mutual TLS cannot pass the certificate through.

`GET /tls/forwarded` reports every forwarding and certificate header a request
carried, whether any was believed, and the effective base URL. Certificate
headers are listed even though they are ignored. Stripping inbound headers at
the proxy and protecting the proxy-to-application hop are rows with
`enforced: no`: they are decisions about a link this process cannot see.

### CORS at the authorization endpoint (section 2.6)

CORS headers are right for the token, UserInfo, metadata and JWKS endpoints an
in-browser client fetches, for the origins this service allows
(`global.corsOrigins` and each application's `appCorsOrigin`, see
[Configuration](configuration.md)). A browser *navigates* to the authorization
endpoint, so nothing legitimate reads them there, and in this mode they are
withheld from `/oauth2/authorize` for every origin, preflight included.

### Token leakage through the browser (section 4.3)

* **The `Referer` header.** Every response carries
  `Referrer-Policy: no-referrer`, and the pages a browser lands on load no
  third-party resource. The content security policy (`default-src 'none'`,
  `img-src 'self' data:`) means one could not load if added by accident.
* **Browser history.** An access token is read only from the `Authorization`
  header. In this mode `?access_token=` is inspected **only to refuse it**, with
  a message saying why (a URL goes into history, the address bar, server logs
  and the `Referer` of whatever the page fetches). The token is never echoed
  back, and the audit log redacts `access_token` and eight other query keys.
  A bare code goes in the query and anything carrying a token in the fragment.
* **`response_mode=form_post`**, in every mode: the response, errors included,
  travels in a form body, never in a URL. The page is a real form with a real
  submit button plus the script `/oauth2/autopost.js`; with the script blocked
  the button is the whole mechanism. `form-action` is left out of the policy
  because the form posts to the client's `redirect_uri`, another origin.
* **A code exposed through history is useless**: single use (with the replay
  relaxation off), a second presentation revoking what the first bought, bound
  to its client, and worthless without the PKCE verifier.

### 303, never 307 (section 4.12)

A `307` preserves the method and the body, so the redirect after a sign-in POST
would resend the username and password to the client. A `302` after a POST is
historically ambiguous. The section asks for **303**, and every sign-in screen
here answers with it. This is not mode-gated: no client can tell the
difference, so gating it would buy nobody an exercise. This service emits no
307 or 308 anywhere.

### Telling a client apart from a person (section 4.13)

`POST /oauth2/register` generates the `client_id` and ignores any proposed. But
development mode issues to any `client_id` that asks, which is the shared
namespace the section warns about. The two modes use **different mechanisms**,
and a resource server testing for the wrong one would take a client credential
for a person's:

| | How to tell |
|---|---|
| mode off | `sub` **equals** `client_id` on a `client_credentials` token and on nothing else (the comparison RFC 9700 suggests) |
| mode on | **separate namespaces**: `urn:sts:client:<id>` beside a person's `urn:uuid:<entryUUID>`, so the two cannot collide |

With the mode on, `sub` no longer equals `client_id` on a client's token, so a
resource server written against the comparison must read the prefix. A person's
`sub` is the same in either mode.

### Clickjacking (section 4.14)

Every response carries `X-Frame-Options: DENY` and CSP's
`frame-ancestors 'none'`: the first for browsers that still read it, the second
because it is the one that governs. `frame-ancestors` has **no fallback from
`default-src`**, so every route that relaxes the policy goes through
`app.contentSecurityPolicy()`, which re-adds the framing clauses whatever the
caller asks. The policy is also re-checked when a response is flushed, because
Express's own 404 handler replaces it with `default-src 'none'`; the check is
"does it still carry the clause", so legitimate relaxations are untouched. The
404 **body** is left as Express writes it (`Cannot GET /path`), because tests
use it to tell an unrouted path from an endpoint answering 404.

The one page that may be framed is the OpenID Connect Session Management OP
iframe, off by default (see
[Session Management](oauth-oidc.md#session-management)), and it narrows the
clause to the realm's registered redirect origins rather than dropping it.
There is no device authorization grant, so there is no `user_code` page; the row
exists so a reader checking the table against the section finds the answer.

### In-browser communication (section 4.17)

No authorization response is delivered by in-browser messaging. The response
mode the section is about, `web_message`, is not performed, and `response_mode`
is checked against what **this authorization server advertises** in
`response_modes_supported`, so a request for it is `invalid_request` naming the
modes that are performed instead of a 302 that leaves a client waiting for a
message that never arrives. That check is per authorization server (one
configured with `["form_post"]` refuses `query` at its own endpoint) and is not
gated on the mode. The OP iframe, when Session Management is on, answers a
relying party's session-state question and carries no authorization response.

If `web_message` is ever added, the rows say what it costs: every message's
target origin is the client's **registered** origin matched exactly, never
`"*"`, and every other response protection applies unchanged. The client's
half, verifying `event.origin`, is a row with `enforced: no`.

### One row that says this service does the wrong thing

*Resource servers MUST treat access tokens as secrets and MUST NOT store them in
plaintext.* This service keeps the tokens it issues and shows them on
`/admin/tokens`, which is what lets the console show somebody the JWT they just
received. The audit log redacts them. A real resource server must do the
opposite, and the row (`tokens-are-secrets`, `enforced: no`) says not to copy
this part.

### What is observed rather than refused

Three requirements are the client's, so this server reports them: a **reused
`code_challenge` or `nonce`** (above); an **unbound access token**, logged at
issuance, since section 2.2's sender constraint is a SHOULD and a client binds by
sending a proof; and a client authenticating with a **shared secret**. The mode
requires no sender constraint, because this service exists to exercise Bearer
clients too; the [five settings](#requiring-a-sender-constraint--five-settings)
are how an operator goes further than RFC 9700, deliberately and by an act.

### What the mode does not cover

The flag does not mean *RFC 9700 compliant*, full stop. The whole of section 2
has rows, including what was already true here (`iss` on every authorization
response, RFC 8414 metadata, a `client_id` a client cannot choose, no access
token accepted in a query parameter, audience restriction), and the
client-side requirements are rows with `enforced: no`: this service can detect
several of them and fix none. Not this mode's to decide:

* [Pushed authorization requests](oauth-oidc.md#pushed-authorization-requests-rfc-9126)
  (RFC 9126) and [RFC 8705](#mutual-tls-rfc-8705), features in every mode.
* Client authentication at `/oauth2/introspect` and `/oauth2/revoke`: an RFC 9701
  JWT introspection request authenticates in every mode and a JSON one in
  product mode, and a revocation request authenticates in product mode and in
  development whenever it presents a credential (RFC 7009, #102). See
  [Introspection and revocation](oauth-oidc.md#introspection-and-revocation).

## OAuth 2.1 mode in detail

OAuth 2.1 describes itself as OAuth 2.0 with the best current practices applied,
so `oauth2.oauth21` turns RFC 9700 mode on and does not enforce it a second time.
Every refusal and `GET /oauth2/oauth21` name draft-ietf-oauth-v2-1-16, because a
later revision may say something different.

It is a mode of its own because RFC 9700 mode refuses a client that follows
OAuth 2.1 to the letter in two places:

* **A token request with no `redirect_uri`.** RFC 6749 section 4.1.3 required
  it; OAuth 2.1 section 10.2 removed it, because PKCE binds the code. An
  identical one is still required when it is sent, in every mode. A code issued
  without PKCE under the OpenID Connect nonce exemption still needs it.
* **An authorization request with no `redirect_uri`** from a client that
  registered exactly one (section 4.1.1). With several it is refused.

What it adds:

| Refused in OAuth 2.1 mode | Draft section |
|---|---|
| A code requested with no PKCE, unless the client is confidential **with a credential on file**, asks for `openid` and sends a `nonce` | 7.5.1.1 |
| `code_challenge` with no `code_challenge_method` | 4.1.1 |
| A client with no redirect URI of its own (`oauth2.redirectUris` is **not read**) | 2.3.1 |
| A token request naming a client whose entry declares nothing a sighting would not have written | 2.5, 3.2.1 |
| A token request naming **no client at all** on the four grants a client makes in its own name (`authorization_code`, `refresh_token`, `client_credentials`, token exchange) | 2.3.1, 2.5 |
| An RFC 7523 or RFC 7522 assertion grant that **names** a client this server does not know | 2.3.1, 2.5 |
| A client secret or assertion that was sent and did not verify; two authentication methods in one request | 3.2.2, 2.4 |
| The client credentials grant from a client that did not authenticate | 4.2 |
| A JWT client assertion whose `aud` is not the issuer as its **sole** value | 2.4 → draft-ietf-oauth-rfc7523bis-11 |
| SAML bearer client authentication (also dropped from the metadata and refused at registration) | 2.4 → rfc7523bis |
| A repeated request parameter (`resource` and `audience` may repeat) | 3.1, 3.2 |

It also ignores `oauth2.loopbackPortWildcard` (a loopback redirect may use any
port, section 8.4.2), caps a code's lifetime at ten minutes, and limits
`error_description` to the characters section 3.2.4 allows.

**What it does not hold to the registered-client rule**: the OpenID4VCI
pre-authorized code grant, whose anonymous access is that specification's
design, and RFC 7523 and RFC 7522 grants that carry no client, which
authenticate the *subject* with a signature and may legitimately name nobody. An
OpenID4VCI wallet using the authorization code flow with an unregistered
`client_id` **is** refused: register it, or use a realm without this mode.

**An assertion grant carrying no client gets an access token and no refresh
token.** Section 4.3.1's rotation is bookkeeping about a chain belonging to a
client, and the refresh grant would refuse every redemption of a chain that
belongs to nobody. RFC 6749 section 5.1 makes `refresh_token` optional, so
withholding it is recorded rather than refused.

**Section 4.3.1 is a choice of two** for refresh tokens: sender-constrained, or
rotated with replay detection. This service rotates, for every client. Neither
the draft nor RFC 9700 requires DPoP; `oauth2.refreshTokenRequireDpop` and
`oauth2.refreshTokenRequireMtls` ask for the first way as well.

**Three changes that came with the mode apply in every mode**, because they are
fixes rather than policy:

* A **private-use redirect URI** such as `com.example.app:/callback` is
  accepted. A scheme with no period (`myapp:`) is refused, and so is
  `response_mode=form_post` to one, since a protocol handler is never handed a
  request body.
* A refresh that narrows `scope` or `resource` narrows the access token, and the
  rotated refresh token keeps what the presented one carried (RFC 6749 section
  6).
* A **client secret that fails is rate limited** wherever it is checked.

Like RFC 9700 mode it is restart-only for the process and may be carried by a
trust realm, which runs a permissive pass, an RFC 9700 pass and an OAuth 2.1 pass
against one service:

```bash
curl -k -X POST https://localhost:8081/admin-api/realms/create \
     -H 'Content-Type: application/json' \
     -d '{"id":"oauth21","name":"OAuth 2.1 mode",
          "overrides":{"oauth2.oauth21":true}}'
```

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
* `/admin/authorization-servers` holds the named authorization servers, their
  members and their drift; `/admin/sts-metadata` lists the ones this process
  has served.
* `/admin/used-assertions` lists the client and grant assertions already
  spent.
* `/admin/tokens` shows the tokens issued, in full (see
  [One row that says this service does the wrong thing](#one-row-that-says-this-service-does-the-wrong-thing)).

## Related

* [OAuth 2.0 & OpenID Connect](oauth-oidc.md)
* [TLS](tls.md) — the main port, the client truststore, certificate sign-in
* [PKI](pki.md) — the certificate authority that issues client certificates
* [Accepted tokens](accepted-tokens.md)
* [Authentication](authentication.md) — second factors behind `mfa`
* [Configuration](configuration.md), [Trust realms](trust-realms.md),
  [What is not checked](what-is-not-checked.md), [Error codes](error-codes.md)
