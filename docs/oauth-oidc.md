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

An OAuth client looks for `oauth-authorization-server`; an OpenID Connect
client looks for `openid-configuration` and nowhere else, so both are needed
for this service to be configurable from either. **The OpenID Connect document
is the RFC 8414 document extended**, not a second copy. It adds only what
Discovery defines on top: `subject_types_supported`,
`id_token_signing_alg_values_supported`, `claims_supported`,
`claim_types_supported`, `prompt_values_supported`, the request and
claims-parameter booleans, `end_session_endpoint` and the logout-notification
booleans. RFC 8414 was written from Discovery and shares its member registry,
so the overlap is real.

* **`check_session_iframe` is absent** unless `oauth2.sessionManagement` is on.
  An invented value would be worse than the member's absence.
* **`acr_values_supported`** is published because the authorization endpoint
  honours `acr_values` (see [OAuth security](oauth-security.md#step-up-authentication-rfc-9470)).
* **`end_session_endpoint`** is advertised because `/oauth2/logout` is the
  whole of RP-Initiated Logout 1.0 (see [Logout](#logout)).
* **`response_types_supported`** includes `id_token token`, and
  **`authorization_response_iss_parameter_supported`** (RFC 9207) is `true`:
  `iss` is on every authorization response, errors included, and a client may
  only *require* it — and so refuse a mix-up attacker's response without it —
  if the metadata says the server sends it.
* The encryption members for ID Tokens, UserInfo and request objects are
  published because each is implemented.

**The appended form rebuilds the issuer from the path it was reached at.** A
document fetched under `/tenant1` that claims to be issued by the bare origin
is one a conforming client must reject. The inserted form behaves like its
`oauth-authorization-server` twin.

### Flows and response types

* **Authorization code**, with **PKCE**
  ([RFC 7636](https://www.rfc-editor.org/rfc/rfc7636), `S256` and `plain`).
* **Implicit and hybrid**: every combination of `code`, `token` and
  `id_token`, including `id_token token`.
* **`response_type=none`**: nothing is issued. The response carries `state`
  and `iss`, in the query. `none` combined with another value is refused
  (Multiple Response Type Encoding Practices section 4).
* **Response modes** `query`, `fragment` and `form_post`. `form_post` is
  answered with a self-submitting form that also has a real submit button.
  When an error is shown instead of redirected (RFC 9700 mode, nobody signed
  in), a `form_post` request's way on is a form with a button that POSTs the
  error, never a link carrying it in the URL.
  Without an explicit mode, `code` alone answers in the query and every
  response type that returns a token or an ID Token answers in the fragment
  ([Multiple Response Type Encoding
  Practices](https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html)
  section 2.1). **An error goes where the success would have gone**, so an
  implicit or hybrid request gets its error in the fragment. An explicit
  `response_mode=query` for a response type that returns a token or an ID
  Token is **refused**, and the error goes in the fragment, because section
  2.1 says that encoding MUST NOT be used.
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

RFC 6749 makes a code single use and section 10.5 says a second presentation
SHOULD invalidate what the first issued. A bare *already-used* refusal is
equally true of a stolen code, a reloaded page, a double-submitted form and a
client retrying after a bad `code_verifier`, and names none of them. So:

* **Nothing before redemption consumes the code.** A wrong `redirect_uri`, PKCE
  verifier or `dpop_jkt` binding is refused and the code stays redeemable, so
  the corrected request gets tokens rather than a complaint about reuse.
* **A redeemed code is idempotent for the rest of its own lifetime**
  (`oauth2.authorizationCodeTtlS`, five minutes). An identical repeat — same
  client, `redirect_uri`, PKCE verifier and DPoP key — gets the **same** token
  set, down to the `jti`. Nothing is minted twice, and a warning is logged
  each time saying a real authorization server would refuse. This is the one
  departure from the RFC.
* **The refusals say what happened.** A code presented with anything different
  is refused naming the field that differed, when the code was redeemed and by
  which client. A code this service has no record of gets its own message:
  codes are held in memory only, so one issued before the last restart (or by
  a different authorization server) is *gone* rather than *used*, and the
  message says how long the process has been up.
* The OpenID4VCI **pre-authorized code** is not relaxed: its single use is a
  property of the Credential Offer under test.
* **RFC 9700 mode** turns the relaxation off, as its section 4.5 asks.

### Client authentication

Every method in `token_endpoint_auth_methods_supported` is verified when there
is something to verify against: `client_secret_basic`, `client_secret_post`,
`client_secret_jwt`, `private_key_jwt`, `tls_client_auth`,
`self_signed_tls_client_auth`, `attest_jwt_client_auth` and
`attest_jwt_client_auth_dpop` (below, where the realm trusts a client
attester), and `saml2_bearer` (this service's own name for RFC 7522 section
2.2, which registers none). `none` declares a public client.
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

#### Mutual TLS clients (RFC 8705)

The methods, certificate binding and the settings that require a binding are
on [OAuth security](oauth-security.md#mutual-tls-rfc-8705). What a client
operator also needs to know:

* **`client_id` is required** in a request that authenticates by certificate.
  An explicit `tls_client_auth_subject_dn` is compared as a name: attribute
  types, OIDs, escapes, case and a multi-valued RDN's order do not matter.
  `_san_uri` is compared exactly, `_san_ip` by value and `_san_email` with the
  domain case-insensitive. The implicit mapping needs a certificate carrying
  `clientAuth`, the application's identifier as CN and
  `urn:sts:application:<identifier>` as a subjectAltName.
* **A declared certificate method is held to in every mode.** Without a
  certificate that authenticates the client, `/oauth2/token` and `/oauth2/par`
  answer `invalid_client` even in development, where client authentication is
  otherwise only observed.
* **Issuing a certificate**: `POST /admin-api/applications/issue-tls-client-certificate`
  takes `application`, `password` and optionally `keyAlg`, `label` and `days`.
  The reply carries the only copy of the private key — a PKCS#12, an encrypted
  PEM key and the PEM chain, all under `password`.
  `revoke-tls-client-certificate` revokes one of the application's own, and
  `pki.applicationTlsClientCertificateMax` caps how many valid ones it holds.
  An application's certificate presented at `GET /tls/sign-in` signs nobody
  in: it is a client credential.
* **The subject parameters are ordinary attributes**
  (`oauthTlsClientAuthSubjectDn`, `oauthTlsClientAuthSanDns`, `…SanUri`,
  `…SanIp`, `…SanEmail`), set with the attribute editor or through RFC 7591
  registration. A second one is refused.
* **Bound tokens at the resources.** UserInfo, the credential endpoints, SCIM,
  Shared Signals, `/admin-api` and the embedded debugger refuse a
  certificate-bound token on a connection without that certificate (401
  `invalid_token`), and `/oauth2/introspect` reports the `cnf`. A registration
  asking for `tls_client_certificate_bound_access_tokens` while the main port
  is not TLS is refused. A **public** client's refresh token is bound to its
  certificate (section 4).
* **Not done**: binding at the authorization endpoint's implicit flow, which
  the RFC puts out of scope (section 6.4). A setting that requires a
  certificate binding while the main port is not HTTPS refuses every affected
  request (`STS-OAUTH-0527`) rather than letting it through.
* The error codes are `STS-OAUTH-0480..0488`, `STS-REG-0130..0136`,
  `STS-PKI-0180..0181`, `STS-ADMIN-0720..0724`, `STS-API-0110` and
  `STS-DBG-0030`; the settings that require a sender constraint add
  `STS-OAUTH-0521..0531`, `STS-API-0120..0121` and `STS-DBG-0031..0032`. See
  [Error codes](error-codes.md).

#### Attestation-based client authentication (Wallet Attestation)

This is [OAuth 2.0 Attestation-Based Client
Authentication](https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/11/),
**draft 11**. The OpenID4VC High Assurance Interoperability Profile (HAIP 1.0
section 4.4.1) calls it Wallet Attestation. A client attester (the wallet's
backend) signs a **Client Attestation JWT** that binds a key the client
instance holds (`cnf.jwk`). The instance proves that key on every request.
Nothing goes in the body: the attestation is the `OAuth-Client-Attestation`
header field.

* **Two methods.**
  * `attest_jwt_client_auth` proves the key with an
    `OAuth-Client-Attestation-PoP` header: a JWT with typ
    `oauth-client-attestation-pop+jwt`, `aud` the issuer identifier, a `jti`,
    an `iat` and the current `challenge`.
  * `attest_jwt_client_auth_dpop` (the "combined mode") proves it with the
    DPoP proof alone, signed by the attested key. The combined mode works at
    `/oauth2/token` and `/oauth2/par`, the two endpoints that verify a DPoP
    proof.
  * Introspection, revocation and CIBA take the first method.
  * A registration declares one of the two methods, and the client is held to
    that method's proof.
* **Which attesters are trusted** is set per realm:
  * `oauth2.clientAttestationTrustAnchors` holds PEM trust anchors. An
    attestation carrying `x5c` must chain to one of them, and its signing
    certificate may not be self-signed.
  * `oauth2.clientAttestationTrustedKeys` holds a JWKS of attester keys, used
    for an attestation without `x5c` and selected by `kid`.
  * With both empty (the default), the two methods and the
    `challenge_endpoint` are not advertised. Every attestation is then
    refused.
  * Only asymmetric algorithms are accepted, including the post-quantum ones.
    A MAC-protected attestation is not accepted.
* **Challenges are required** (`oauth2.clientAttestationChallengeRequired`, on
  by default).
  * `POST /oauth2/challenge` answers `{ "attestation_challenge": … }`, with
    `Cache-Control: no-store`, and with a `DPoP-Nonce` when DPoP nonces are
    required.
  * Every response to a request that carried an attestation also carries a
    fresh challenge in `OAuth-Client-Attestation-Challenge`. Use the most
    recent one.
  * Each challenge and each PoP `jti` is good for one successful request. A
    missing or spent challenge is answered 400 `use_attestation_challenge`
    with a fresh challenge.
  * An attestation older than `oauth2.clientAttestationMaxAgeS` is answered
    400 `use_fresh_attestation`.
* **`client_id` may be left out** of a token request. The attestation's `sub`
  names the client. Where the request does name a `client_id`, it must equal
  the `sub`.
* **Bound to the client instance.** A refresh token issued on an attestation
  is redeemed only with an attestation of the same instance key. A code whose
  authorization request was pushed with an attestation is redeemed only by
  that instance. Both refusals are `invalid_grant`.
* **As an additional signal.** A client using another method may send an
  attestation as well. Where the realm trusts an attester, that attestation is
  verified and must hold.
* **Under FAPI 2.0** the two methods are accepted only with
  `oauth2.fapiAllowClientAttestation` on (HAIP's arrangement). FAPI 1.0 never
  accepts them.
* **Not done**: `jku`, a Wallet Attestation's status list, an attester
  certificate's revocation, and the resource-server half of the draft.
* **The error codes** are `STS-OAUTH-0720..0751`. See
  [Error codes](error-codes.md).

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
tokens. Withdraw `offline_access` from an application's global consent on
`/admin/consent` to turn this off: every session of that surface standing on it
ends at its next token renewal, and the person is asked at their next sign-in.

Consent is **on by default** (`oauth2.consentRequired`). Turning it off means
nothing is asked and nothing is recorded; it does not mean everybody consented,
so turning it back on asks again. `/admin/consent` is the register. The
settings are listed under [Configuration](#consent-permissions-and-claims) and
on the [Configuration](configuration.md) page.

#### How an answer is recorded

Each `oauthConsent` value is three fields separated by a space — when it was
agreed (a GeneralizedTime), the scope, and the `client_id`:

```
oauthConsent: 20260901143000Z openid webapp1
oauthConsent: 20260901143000Z https://example.com/write webapp1
```

* **The `client_id` is last** because it is the only field that may contain
  anything, spaces included; it takes the rest of the value. A scope never
  contains a space. The timestamp is checked against its own shape, so a
  sentence left on the entry by an `ldapmodify` is not read as a consent.
* **One value per (person, application, scope)**, never one per request.
  `openid profile` and `profile openid` are the same agreement, and adding a
  scope to a request does not throw away the agreement to the others. A
  second visit asks only about the **new** scopes, with the ones already
  agreed to under a fold.
* **A delegated permission is recorded by its whole identifier**
  (`https://example.com/write`, never `write`), because two resources may each
  expose a permission of the same name.

**`oauthGlobalConsent`**, on the client application's entry, is an
**override** rather than a record: a scope named there is never asked about,
for anybody, and nothing is written about anybody. Two things follow:

* **Removing one asks everybody again**, including people who would have said
  yes, because nothing was ever written about them. Removing a person's own
  `oauthConsent` asks only that person.
* **It is keyed on (application, scope)**, never on the scope alone. Consenting
  `read` for one application does not consent it for another that spells the
  same word.

Both are ordinary attributes on directory entries, so an `ldapmodify` changes
them like any other configuration, and they persist wherever the directory
does.

#### The consent screen

* `prompt=consent` asks again whatever is recorded, and **takes nothing away**:
  somebody who cancels keeps what they had. `prompt=none` with something
  outstanding is **`consent_required`** (OpenID Connect Core section 3.1.2.6)
  rather than the general `interaction_required`, so a client can tell a
  missing consent from a missing session.
* **The pending consent is server-side.** The only thing in the URL is an
  unguessable id, so there is no return address to rewrite. The answer is a
  **POST** (a GET that recorded consent could be given by anything that
  prefetches a link), the id is spent when it is answered, and the session
  presenting the answer must be the person who was asked.
* **The screen carries no script** — two buttons in a form.
* Consent is a question asked of somebody already signed in. It is not a
  password check.

#### Withdrawing consent

A consent is withdrawn at `/admin/consent` or through
`POST /admin-api/consent/{action}` by an administrator, or by the person
themselves on `/portal/consents`, the user portal's list of what they have
agreed each application may ask for. Whichever door is used:

* **Every token issued under it is revoked at once.** That is every access and
  refresh token the application holds for that person carrying the scope, and a
  refresh token's whole grant with it (RFC 7009 section 2.1). The revocation
  goes on the register every node reads, so the tokens introspect inactive
  everywhere. Withdrawing one scope revokes the whole refresh token.
* **The instant is recorded**: `oauthConsentWithdrawn` on the person's entry,
  and `oauthGlobalConsentWithdrawn` on the application's entry for a global
  consent. A refresh token carries the instant its grant was made, and the
  refresh grant refuses it (`invalid_grant`) when a consent it stood on was
  withdrawn at or after that instant. Consenting again does not revive it.
* **The refresh grant re-checks consent at every refresh**, in both modes,
  against the directory. That makes it hold on every node, including for a
  token the withdrawal's revocation never saw.
* **`oauth2.refreshRequiresConsent`** (on by default) also refuses a refresh
  token from the authorization endpoint whose scopes no recorded consent covers
  while consent is required. That is a token obtained while consent was off.
  **Turning it off renews grants nobody agreed to**, including `offline_access`
  ones that run while the person is away.

Withdrawing a global consent revokes the tokens of everybody it covered, except
people who agreed to the scope themselves. It is the only way to take a global
consent away: removing `oauthGlobalConsent` through the generic application
edit is refused, because that door would do half a withdrawal.

`/admin/consent` shows both halves under headings that say which is which, with
five controls: consent a scope for everybody, stop consenting it, take back one
person's answer, withdraw everything one person agreed to for one application,
and forget everything one person agreed to. `GET /admin-api/consent` and
`POST /admin-api/consent/{action}` are the same five.

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
  encrypted to a key in its `jwks` or registered `jwks_uri`. Only asymmetric key management
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
* **Ephemeral subjects** (the Ephemeral Subject Identifier draft, #149): a
  client registered with `subject_type=ephemeral` is given a random `sub`
  (160 bits) for each authentication. Everything one sign-in issues it — the
  ID Token, UserInfo, a refreshed ID Token, the Logout Token — names that
  one `sub`. The next sign-in gets another, never reused. The mapping is
  kept only as long as a token or the session of that sign-in can last, and
  a scheduler job removes it after that. An `id_token_hint` carrying an
  ephemeral `sub` still names the person while the mapping lasts.
* **Shared Signals events** sent to a stream a pairwise or ephemeral client
  owns name that client's `sub` for the person, not the public one.

### UserInfo and the claims request

`GET` or `POST /oauth2/userinfo` answers from four layers, later ones winning:

1. the configured **UserInfo claim set** (`/admin/userinfo-claims`),
2. the scope-driven claims of OpenID Connect Core section 5.4 (`profile`,
   `email`, `address` and `phone`, each claim from the person object or the
   directory entry, absent when neither holds it),
3. the claims named individually in an OpenID Connect Core section 5.5
   **`claims` request**, read from the person's directory entry,
4. `sub`, which is always set last.

**The Identity Assurance Claims Registration's claims** can be asked for by
name in a `claims` request, and are listed in `claims_supported`:

* `place_of_birth`: `country` (ISO 3166-1 alpha-3), `region` and `locality`.
* `nationalities`: an array of ICAO three-letter codes.
* `birth_family_name`, `birth_given_name`, `birth_middle_name` and
  `also_known_as`.
* `salutation`, and `title`, which is the **honorific** ("Dr"). The job title
  is `job_title`.
* `msisdn`, the mobile number as E.164 digits.
* `address.country_code`, the ISO 3166-1 alpha-3 code beside `country`.

A `claims` request is parsed at the authorization endpoint (a malformed one is
refused `invalid_request` there), carried **inside the access token** and
honoured in the ID Token (`id_token` member) and at UserInfo (`userinfo`
member). A refresh keeps it. An **`acr` marked `essential` with `value` or
`values` is a requirement**, met or refused like `acr_values` (section
5.5.1.1). For every other claim, `essential`, `value` and `values` are carried
and **not enforced**: an unavailable claim is left out and logged, and a value
that does not match is answered with the value this service holds.

### Native SSO (OpenID Connect Native SSO for Mobile Apps 1.0)

Apps from one vendor on one device can share a sign-in:

1. **The first app** signs in with the authorization code flow and
   `scope=openid device_sso`. The token response carries a `device_secret`,
   and the ID Token a `ds_hash` of it and the `sid` of the session. The app
   stores both where the vendor's other apps can read them.
2. **The second app** calls the token endpoint with
   `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`,
   `subject_token` the first app's ID Token
   (`subject_token_type=urn:ietf:params:oauth:token-type:id_token`),
   `actor_token` the device secret
   (`actor_token_type=urn:openid:params:token-type:device-secret`) and
   `audience` this service's issuer, and is issued tokens of its own for the
   same session.

**Both apps must be enabled** — `oauthNativeSso` TRUE and the same
`oauthNativeSsoGroup` on their application entries, set on the console or
through `/admin-api` (a dynamic registration can set them only through a
trusted software statement). Anything else is refused `invalid_scope` or
`unauthorized_client`, in every mode.

**The device secret lasts as long as the sign-on session.** Signing out, the
session expiring, the account being disabled or a Shared Signals
`session-revoked` all end it; `/oauth2/revoke` revokes it on its own. It is
never rotated: a later sign-in whose code grant sends it back as
`device_secret` keeps the same device and the same secret.

**Each device is an entry in the directory** under `ou=devices`, owned by the
person and linked to every application that used it. People see theirs on
`/portal/devices`; administrators on the person's page and at
`GET /admin-api/users/devices`, and either can remove one. A person holds at
most `oauth2.maxDevicesPerPerson` (20).

**Token exchange reads its token types.** Every RFC 8693 exchange must send
`subject_token_type` (and `actor_token_type` with an `actor_token`); each
must be `access_token`, `refresh_token`, `id_token` or `jwt`; and a token this
service issued must be the type it is declared as. Anything else is refused
`invalid_request`.

### Backchannel sign-in (OpenID Connect CIBA Core 1.0)

A client that cannot show the person a browser — a call centre, a point of
sale — can ask this service to sign them in **on a device of their own**.
It is **off by default**; turn on `oauth2.ciba` in the realm.

1. **Register the client** with `backchannel_token_delivery_mode` — `poll`,
   `ping` or `push` — and, for ping and push,
   `backchannel_client_notification_endpoint` (https). Optionally
   `backchannel_authentication_request_signing_alg` (every request must then
   be a signed `request`) and `backchannel_user_code_parameter`.
2. **The client asks** at `POST /oauth2/bc-authorize`, authenticating as it
   would at the token endpoint, with `scope` including `openid` and exactly
   one of `login_hint` (a username), `id_token_hint` or `login_hint_token`.
   It may add `binding_message` (shown to the person), `acr_values`,
   `requested_expiry`, `user_code`, and — for ping and push —
   `client_notification_token`. The answer is an `auth_req_id`,
   `expires_in` and, except for push, `interval`.
3. **The person approves or denies** on `/portal/ciba`, their own sign-in
   requests page. If the request's `acr_values` ask for more than their
   sign-in proved, they sign in again with it first.
4. **The client collects its tokens**:
   * **poll** — `grant_type=urn:openid:params:grant-type:ciba` with the
     `auth_req_id` at the token endpoint; `authorization_pending` until the
     person answers, `slow_down` (and a longer interval) when asked too soon;
   * **ping** — this service POSTs `{"auth_req_id": …}` to the notification
     endpoint with the `client_notification_token` as a Bearer, and the
     client then makes that token request;
   * **push** — this service POSTs the tokens themselves (or the error) to
     the notification endpoint. A push client may not poll.

The ID Token carries `urn:openid:params:jwt:claim:auth_req_id`, and `rt_hash`
beside a refresh token. A ping or push that fails is retried with a growing
back-off and given up after `oauth2.cibaNotifyAttempts` tries.

**An unknown person is `unknown_user_id` in every mode**, and at most
`oauth2.cibaMaxPendingPerPerson` (5) requests may wait for one person. A
person's **user code** is set on the same portal page; a client registered
with `backchannel_user_code_parameter` must send it with every request.

### Verified claims (OpenID Connect for Identity Assurance 1.0)

A `claims` request may ask for **`verified_claims`** in its `id_token` or
`userinfo` member — one element or an array — each with a `verification`
(which must name `trust_framework`, `null` for any) and a non-empty `claims`
object:

```json
{"userinfo": {"verified_claims": {
  "verification": {"trust_framework": {"value": "eidas"},
                   "time": {"max_age": 31536000},
                   "evidence": [{"type": {"value": "document"},
                                 "document_details": {"type": null}}]},
  "claims": {"given_name": null, "family_name": null, "birthdate": null}}}}
```

It is answered from the **identity verifications recorded for the person**:

* an administrator records them on the person's page under Directory → Users,
  or with `POST /admin-api/users/record-verification` (and lists them with
  `GET /admin-api/users/verifications`) — a trust framework from
  `oauth2.idaTrustFrameworks`, one of the four evidence types (`document`,
  `electronic_record`, `vouch`, `electronic_signature`), and the claims that
  were checked;
* a **wallet sign-in** with a credential this realm issued records an
  `electronic_record` of the disclosed claims the directory agrees with, and a
  **client certificate sign-in** an `electronic_signature` of the subject's,
  while `oauth2.idaAutomaticVerifications` is on (the default).

`value`, `values` and `time.max_age` on the verification and its evidence
**choose** which record answers; an element no record satisfies is left out
entirely, and only the members you asked for are returned. A claim is released
as verified only **while the directory still holds the value that was
verified** — change the entry and the claim drops out of `verified_claims`
(the ordinary claim carries the new value). A malformed request —
no `verification`, no `trust_framework` member, empty `claims`, a `purpose`
outside 3 to 300 characters — is refused `invalid_request`.

**In development mode** a person with no recorded verification is answered
with an invented one under the trust framework `urn:sts:demo`, so any account
can exercise a client's parser; a request naming a real framework never
matches it. **Product mode** releases recorded verifications only.

Discovery publishes `verified_claims_supported`, `trust_frameworks_supported`,
`evidence_supported`, `documents_supported`,
`documents_check_methods_supported`, `electronic_records_supported` and
`claims_in_verified_claims_supported`. Aggregated and distributed verified
claims, and attachments, are not supported.

### Enterprise Extensions: `session_expiry`, `tenant`, `aud_sub`, `domain_hint`

OpenID Connect Enterprise Extensions 1.0 (#148), in every mode:

* **The ID Token** carries `tenant` (the trust realm's id) and, when it is
  issued on a sign-on session, `session_expiry`: the session's absolute end.
  A later sign-in does not extend a session, so a relying party can end its
  own session no later than this. Where an administrator recorded the
  account id a client knows the person by (`POST
  /admin-api/users/set-aud-sub`, or the person's page on the console), the
  ID Token for that client carries it as `aud_sub`.
* **`tenant` on an authorization request** must be the realm's own id. One
  naming another realm is refused with `invalid_request`: a realm is chosen
  by the path the request is sent to, never by a parameter.
* **`domain_hint`** is home-realm discovery. A federation relationship whose
  `fedHomeRealmDomain` lists the domain receives the person's sign-in
  directly, unless the application names a partner of its own.
* **Third-party-initiated login** from the portal adds `tenant`,
  `domain_hint` (the realm's DNS domain) and `target_link_uri` (the
  application's registered https home page) to `iss` and `login_hint`.

### Signing in a device (RFC 8628)

A television, a console or a command line with no usable browser can sign a
person in **on another device**. It is **off by default**; turn on
`oauth2.deviceAuthorization` in the realm.

1. **Register the client** with the grant type
   `urn:ietf:params:oauth:grant-type:device_code`.
2. **The device asks** at `POST /oauth2/device_authorization`, authenticating
   as it would at the token endpoint (a public client sends its `client_id`),
   with an optional `scope`. It gets a `device_code`, a `user_code` such as
   `WDJB-MJHT`, `verification_uri` (`/portal/device`),
   `verification_uri_complete`, `expires_in` and `interval`.
3. **The person** opens `/portal/device`, types the code (or follows the
   complete URI), is shown which application asks and for what, and
   approves or denies. Five codes that match nothing lock the session out
   for ten minutes.
4. **The device polls** `POST /oauth2/token` with
   `grant_type=urn:ietf:params:oauth:grant-type:device_code` and the
   `device_code`, no faster than `interval`: `authorization_pending`,
   `slow_down` (the interval grows by five seconds), `expired_token`,
   `access_denied`, and then the tokens, once.

A DPoP proof on the device request binds the device code to its key; the
tokens are then issued only to a proof from that key.

### Key-bound ID Tokens (OpenID Connect Key Binding)

A client that asks for the `bound_key` scope gets an ID Token bound to its
DPoP key, in every mode:

* the authorization request carries `dpop_jkt` and `response_type=code`
  (otherwise `invalid_request`);
* the token request's DPoP proof carries `c_s256`, the base64url SHA-256 of
  the authorization code (or device code);
* the ID Token carries `cnf.jwk` and the JOSE header `typ: dpop+id_token`;
* a refresh must carry a proof from the same key, and the renewed ID Token
  is bound to it;
* a bound ID Token presented as a token exchange `subject_token` (Native SSO
  included) needs a DPoP proof from its key.

DPoP keys may be ML-DSA-44, ML-DSA-65 or ML-DSA-87 (`kty: AKP`) as well as
RSA, EC and OKP.

### OpenID Provider Commands

This service can tell a relying party what to do with an account. It sends
an OpenID Provider Commands 1.0 (draft 02) Command Token to the
`command_endpoint` the relying party registered. It is **off by default**;
turn on `oauth2.providerCommands` in the realm.

1. **Register the client** with `command_endpoint` (https, no fragment), in
   `POST /oauth2/register`, on `/admin/applications` or through the API.
2. **Send `metadata`** from Protocols → Provider Commands (`/admin/commands`)
   or `POST /admin-api/commands/send-tenant`. The answer records what the
   relying party supports and whether it needs an `aud_sub`.
3. **Send a command:**
   * an **account command** about one person: `activate`, `maintain`,
     `suspend`, `reactivate`, `archive`, `restore`, `delete`, `audit`,
     `invalidate`, `migrate`, or any of them with `_async`;
   * a **tenant command** about everybody: `audit_tenant`, `suspend_tenant`,
     `archive_tenant`, `delete_tenant`, `invalidate_tenant`. These are read
     as a Server-Sent Events stream.

   Each account state the relying party reports is kept, per relying party.
4. **Automatic commands** (`oauth2.commandAutomatic`, on while commands are)
   are sent on these events:

   | Event | Command |
   |---|---|
   | a disable | `suspend` |
   | an enable | `reactivate` |
   | a directory or SCIM delete | `delete` |
   | a change to the person or their groups | `maintain` |
   | an administrator's global sign-out | `invalidate` |

   A command goes only to a relying party that listed it and where the person
   has an account.

A relying party posts `_async` results, and asks for a fresh `metadata` or
`audit_tenant`, at `POST /oauth2/commands/callback`, Bearer the
`callback_token` its command carried. A command that cannot be delivered is
a dead letter on Monitoring → Outbound deliveries (`/admin/deliveries`),
beside undelivered Logout Tokens and CIBA notifications, with a Retry.

Command Tokens name an `iss`. Set `global.publicBaseUrl` so an automatic
command knows its issuer before any command has been sent from the console.

### Aggregated and distributed claims (Claims Providers)

A realm can hand a relying party claims that another OpenID Provider vouches
for (OpenID Connect Core section 5.6.2, and the Claims Aggregation draft).

1. **An administrator registers the Claims Provider** on
   `/admin/claim-providers` or `POST /admin-api/claim-providers/add-provider`.
   The registration names the provider's issuer (its endpoints can be filled
   from its discovery document), this realm's client id and secret there
   (the secret is sealed), and the claims it supplies. It also says whether
   those claims are delivered **aggregated** (the default) or
   **distributed**. At the provider, register this realm as a client whose
   redirect URI is the one the page shows
   (`<realm>/portal/claim-sources/callback`). Its UserInfo responses must be
   signed.
2. **A person links the provider** on `/portal/claim-sources`. They sign in
   and agree at the provider, and come back linked. Their tokens there are
   kept sealed on their own directory entry. An administrator sees every link
   and can revoke one.
3. **A relying party asks for one of those claims by name** with the `claims`
   request parameter. If the person's own entry does not answer it, the ID
   Token or UserInfo response carries `_claim_names` and `_claim_sources`:
   * **aggregated**: the provider's signed UserInfo JWT, which this service
     verified against the provider's keys, for the person's subject there;
   * **distributed**: the provider's endpoint and an access token for it.

   A value the person's own entry holds is never replaced.

`claim_types_supported` lists `normal`, `aggregated` and `distributed`.

**As a federation service provider**, claim sources an upstream OpenID
Provider sends are resolved too, but only from a Claims Provider registered in
the realm, and only when that provider's keys verify them.

UserInfo takes the access token in the `Authorization` header or, on a
form-encoded `POST`, as an `access_token` body parameter (RFC 6750 section
2.2). Sending both is refused.

As a debugging aid that no specification defines, UserInfo also accepts
`?claims={json}` and repeated `?claim=name` on the request itself, on `GET` and
on a form-encoded `POST`. These are a **union** with what the token carries and
can never remove a claim from it. They exist so that comparing what the
endpoint does with `address`, `address.locality` and a name nothing can produce
is three requests rather than three authorization flows. A malformed one is
refused `invalid_request` rather than ignored, because an ignored mistyped
parameter looks exactly like one never sent.

### UserInfo: the token, and a protected response

**UserInfo verifies the token it is given**, and refuses one another issuer
signed. The OpenID4VCI endpoints may accept a token they cannot verify in
development, because OID4VCI lets the authorization server be somebody else;
UserInfo answers *who did you authenticate*, and about the subject of a
signature it cannot check this server knows nothing. It is also what gives
`cnf.jkt` meaning here, since a DPoP binding is real only on a token whose
signature was checked. Each check has its own answer, because a bare
`invalid_token` sends people looking in the wrong place:

* the signature and expiry (401, saying which);
* the `typ`, which is what tells an access token from a refresh token or an ID
  Token;
* revocation, so `/oauth2/revoke` is honoured here as everywhere;
* the `openid` scope — 403 `insufficient_scope` otherwise, which is what a
  `client_credentials` or token-exchange token gets: it has no end-user and so
  no profile. A missing `openid` is the usual reason a working token exchange
  looks broken.

**A scope changes the answer.** `openid` alone returns only `sub`; `profile`,
`email`, `address` and `phone` ask for their claim sets here (section 5.4).

**Layer 3 beats layer 2** (see [UserInfo and the claims request](#userinfo-and-the-claims-request)):
a scope asks for a *category* and a claims request names a *claim*, so
answering `{"email":null}` with an invented address while the entry holds a
real `mail` would defeat the point. A claims request can never reach a
structural claim: every name it resolves comes from the attribute catalogue or
the persona's claims. A nested claim may be asked for by its flat name
(`address.locality`) or its top-level name (`address`, the whole Address Claim
of Core 5.1.1), and a language tag is part of the name (`family_name#ja-Kana-JP`
comes back under exactly that name, with the one value this service holds). An
essential claim this service cannot produce is left out and logged at warn
level, as section 5.5.1 requires; a `value`/`values` mismatch is reported in the
log and the response's artifact. `claims_supported` deliberately does not list
what `/admin/userinfo-claims` adds or the whole catalogue a request can reach,
because discovery is cached by clients and both change at runtime.
`GET /admin-api/userinfo-claims` is the live answer.

**The response can be signed, encrypted, or both**, decided entirely by what
the client registered (RFC 7591, OpenID Connect Core section 5.3.2):

* `userinfo_signed_response_alg` gives a JWS (`application/jwt`) carrying `iss`
  and `aud` — without them a signed profile issued for one client is one any
  other client would also believe. Every signing algorithm in this service's
  table is offered: the fourteen of the JWS registry (RS, PS and ES at 256, 384
  and 512, ES256K, EdDSA, and HS256/384/512 keyed by the client's own secret)
  and the eleven post-quantum ones.
* `userinfo_encrypted_response_alg` gives a JWE: RSA-OAEP, RSA-OAEP-256,
  ECDH-ES and its three key-wrapping variants, over any of the three AES-GCM
  and three AES-CBC-HMAC content encryptions. **`enc` defaults to
  `A128CBC-HS256`** when only an `alg` is registered, as the registration
  specification says. The recipient key comes from the client's inline `jwks`
  or its registered `jwks_uri`, fetched and cached (see
  [Client authentication](#client-authentication)).
* Both give a **Nested JWT**, signed then encrypted, with `cty: "JWT"`.

The three lists are advertised as `userinfo_signing_alg_values_supported`,
`userinfo_encryption_alg_values_supported` and
`userinfo_encryption_enc_values_supported`. **An algorithm this service cannot
perform is refused, never downgraded to JSON**: a client that registered
protection and got an unprotected 200 would go on believing it had verified
something.

The RFC 6750 `WWW-Authenticate` challenge carries the same
`error_description` as the JSON body, folded to ASCII, because an HTTP field
value is ASCII; the body keeps the original text.

### Signing algorithms and keys

The keys and algorithm table belong to the whole service, and every JOSE
surface reads them: ID Tokens and UserInfo offer every signing algorithm, and
DPoP proofs, OpenID4VCI proofs of possession, Key Binding JWTs and client
assertions accept every asymmetric one. The advertised metadata lists are
derived from the same table, so what is advertised is what is accepted.

* **The traditional keys**: RSA, P-256, P-384, P-521, secp256k1, Ed25519 and
  Ed448, all published in `/oauth2/jwks` (RSA first, since the default
  signature is RS256). ES256K's signature is the R‖S concatenation RFC 7518
  section 3.4 requires, not OpenSSL's DER.
* **Eleven post-quantum algorithms**: ML-DSA at three parameter sets (FIPS 204,
  RFC 9964), SLH-DSA at two (FIPS 205), and the six composite ML-DSA +
  traditional algorithms of draft-ietf-jose-pq-composite-sigs, published as
  `kty: "AKP"` JWKs. The JOSE framing is written independently of the parent
  debugger's, so a misunderstanding cannot be shared by both ends; the
  traditional half of a composite runs on node's OpenSSL.
* **The post-quantum keys are generated lazily.** All eleven take about two
  seconds, almost all of it one SLH-DSA key, so the first thing that needs one
  (in practice the first JWKS fetch on a realm) pays once.
* **`oauth2.eddsaCurve`** chooses Ed25519 or Ed448 for `EdDSA`, since RFC 8037
  registers one `alg` for both curves. Both keys are published under different
  `kid`s whatever it says, so a verifier follows the `kid` and a cached JWKS
  never changes shape.

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
`access_token`.

**Which tokens are verified.** In product mode the `subject_token` and
`actor_token` must both verify against this realm's key. In development a
token this server signed is verified, and one it did not is **read without
any signature check**, and the log says so. The interesting exchange is the
federated one, where the subject token came from a real identity provider this
service has no key for; refusing it would make the grant untestable. It is
also exactly what would be a critical vulnerability in a real authorization
server, which is why it is development only.

**The refresh token.** RFC 8693 section 2.2.1 says one is worth issuing where
the client "needs the ability to access a resource even when the original
credential is no longer valid" — the user-not-present case, where there is no
session by design. `oauth2.tokenExchangeRefreshToken` has three values,
because real authorization servers differ and a client meets all of them:

| Value | Behaviour |
|---|---|
| `when-requested` (default) | a refresh token only when `requested_token_type` asks for one |
| `never` | the ask is ignored: the exchange succeeds without one, and the log names the setting (`requested_token_type` is a request, not an instruction) |
| `always` | every exchange gets one, asked or not — which tests whether a client leaks a credential it never asked for |

`oauthTokenExchangeRefreshToken` on the **client's** entry overrides it for that
client. What comes back is an ordinary refresh token of this service: the same
lifetime (`oauth2.refreshTokenTtlS`), redeemable at the refresh grant, revocable
at `/oauth2/revoke`, listed at `/admin/tokens`, rotated wherever rotation is
required, bound to the DPoP key or client certificate the exchange was made
with, and holding the RFC 8707 resources the exchange named so a renewal cannot
widen the audience. It is in `refresh_token`; `issued_token_type` describes the
`access_token` member. Any other `requested_token_type` is accepted and answered
as an access token.

An exchanged token is issued with the scope asked for, so without `openid` it
gets 403 `insufficient_scope` at UserInfo: there is no end-user behind it.

**Who may act for whom** is decided by the delegation policy (#108): the client,
and the actor it names, must be allowed to reach every `audience` and `resource` — by
`appAllowedToDelegateTo` on its own entry or `appAllowedToActOnBehalfOf` on the
target's — an exchange with no `actor_token` needs `appTrustedToImpersonate`,
the subject must be in one of the client's `appDelegationSubjectGroup` groups
where it names any, and a person carrying `stsNotDelegated` or on the console
roster is never delegated. The issuance policy may then Deny the action-id
`delegate` ([XACML](xacml.md)). In **product** mode a refusal is `invalid_request`,
or `invalid_target` for a target (RFC 8693 section 2.2.2), and a requested
`scope` wider than the subject_token's is `invalid_scope`; in **development**
the exchange is issued and `/admin/delegation` says what would have been
refused. A client exchanging its own token needs nothing. The same attributes
are edited on the application's page, through `POST
/admin-api/applications/update`, and listed at `GET
/admin-api/delegation/policy`.

**`may_act`** (section 4.4) is read in every mode: a subject_token whose
`may_act` names somebody other than the actor (or the client, with no
`actor_token`) is refused `invalid_request`. It is issued in every access token
about a person who has named a delegate — `stsMayAct`, set on
`/portal/delegate` or with `POST /admin-api/users/set-may-act`. **`act` nests**:
a prior actor stays beneath the new one (section 4.1).

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

```
POST /oauth2/par                 Authorization: Basic …   (as at the token endpoint)
response_type=code&redirect_uri=…&scope=openid&state=…&code_challenge=…

201 {"request_uri":"urn:ietf:params:oauth:request_uri:<256 bits>","expires_in":60}

GET /oauth2/authorize?client_id=app1&request_uri=urn:ietf:params:oauth:request_uri:…
```

Every named authorization server has its own at `/{id}/oauth2/par`.

* **Client authentication** (section 2) is refused when it fails in RFC 9700
  mode, OAuth 2.1 mode and product mode, and observed in development. A client
  assertion may name the issuer, the token endpoint or the PAR endpoint as its
  audience.
* **The push is validated as an authorization request** — the authorization
  endpoint's own checks plus the `resource`, `claims`, `authorization_details`,
  permission and RFC 9068 audience parsers — and refused as JSON, before any
  person is involved. `request_uri` in a push is refused (section 2.1), and so
  is a repeated parameter other than `resource`. 405 for any method but POST,
  413 past `oauth2.parMaxBodyBytes`, 429 past `oauth2.parRequestsPerMinute`,
  503 when the realm already holds `oauth2.parMaxRequests`.
* **A `request` object may carry the parameters** (section 3), verified as
  RFC 9101 requires. The authenticated client must be its `client_id` claim,
  and nothing else may sit in the form beside it. Where a signed object is
  required, a plain push is refused.
* **A DPoP proof sent with the push binds the authorization code** to its key
  (RFC 9449 section 10.1); a `dpop_jkt` naming another key is refused.
* **The `request_uri`** lives `oauth2.parRequestUriLifetimeS` (60 seconds by
  default, 5–600) and only the pushed parameters are used; the query's own are
  ignored. An unknown, expired, spent, other client's or other server's
  `request_uri` is refused `invalid_request_uri` as a 400 on this server, never
  redirected. A client's policy is checked again when its `request_uri` is
  used, so a plain push is refused once a signed object becomes required.
* **Section 2.4**: with `oauth2.parAllowUnregisteredRedirectUris` on (off by
  default), a client that **authenticated** at the push may name a redirect URI
  it never registered. A public client never may, and the setting is asked
  again at the authorization endpoint.

Both discovery documents carry `pushed_authorization_request_endpoint` and
`require_pushed_authorization_requests`. With
`oauth2.pushedAuthorizationRequests` off the endpoint answers 404 and the
member is removed; a `request_uri` already issued still works.
`/admin/oauth2/monitor` counts pushes, reads, spends, expiries and refusals per
client and lists the `request_uri`s still held.

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

The query's `client_id` must be present and identical to the object's;
anything else in the query is ignored, and the redirect URI, PKCE and RFC 9700
checks all run on what was signed.

* **Signed** with any JWS algorithm this service verifies, by a key the client
  registered (`jwks`, `jwks_uri`, or an issued assertion key pair) or, for
  HS256/384/512, its client secret. A `kid` must name one of those keys, and a
  certificate on the key has its chain and revocation checked. A client may
  register `request_object_signing_alg` to pin one.
* **Unsigned** (`alg: none`, OpenID Connect Core section 6.1) is accepted in
  development and refused in product, and refused anywhere a signed object is
  required: `oauth2.requireSignedRequestObject`, the client's
  `require_signed_request_object`, or a named authorization server publishing
  it.
* **Encrypted** as a Nested JWT to the realm's own RSA or EC key (published in
  `/oauth2/jwks` with `use: "enc"`) or, for the symmetric algorithms, to a key
  derived from the client secret (OpenID Connect Core section 10.2). A client
  that registers `request_object_encryption_alg` / `_enc` is then refused a
  plain object.
* **`iss`, `aud`, `exp` and `nbf`** are checked where present. `typ` is refused
  only when it names another kind of JWT, unless
  `oauth2.requireRequestObjectType` is on.
* **`request_uri`**: the client registers it in `request_uris`. In product mode
  it must be `https` and answer `application/oauth-authz-req+jwt` (or
  `application/jwt`). A fragment of 43 base64url characters must be the
  SHA-256 of the content (OpenID Connect Core section 6.2), and
  `oauth2.requestUriCacheS` caches by URI. A pushed request's URN goes to the
  PAR store instead and is never fetched.
* **The `jti`** is checked on every pass through the authorization endpoint
  and spent only when an authorization response is issued on the object, or
  when `POST /oauth2/par` keeps a pushed one, so the passes before and after
  the sign-in screen are one request; a replay afterwards is refused
  `invalid_request_object`. It is kept in the used-assertion history
  (`/admin/used-assertions`) beside RFC 7523 JWTs, until `exp` plus the clock
  skew, or for `oauth2.requestObjectJtiRetentionS` when there is no `exp`.
  `oauth2.requestObjectJtiOnce=false` accepts a replay; an object with no
  `jti` is accepted either way.

Errors are RFC 9101's own — `invalid_request_object`, `invalid_request_uri`,
`request_not_supported`, `request_uri_not_supported` — answered as a 400 on this
server. Both discovery documents carry `request_parameter_supported`,
`request_uri_parameter_supported`, `require_request_uri_registration`,
`require_signed_request_object` and the three
`request_object_*_values_supported` lists, and a named authorization server's
profile narrows each at its endpoint. The sign-in and consent screens say when
the request was a verified request object.

### Rich authorization requests (RFC 9396)

`authorization_details` is accepted at the authorization, token and PAR
endpoints. A **type belongs to the resource application that declares it**
(`oauthAuthorizationDetailsType`, a name or a JSON definition with a JSON
Schema), plus the built-in OpenID4VCI `openid_credential`. An unknown or
non-conforming detail is refused `invalid_authorization_details` in every mode.
The token is addressed to the type's resource. Consent draws each detail and is
asked **every time**. The refresh token keeps the whole grant, and a token
request may narrow it under section 6's subset rule.

```json
[{"type": "payment_initiation",
  "locations": ["https://pay.bank.example/"],
  "actions": ["initiate"],
  "instructedAmount": {"currency": "EUR", "amount": "12.50"}}]
```

**A type is declared by the resource that understands it.** An application
acting as a resource server lists its types in `oauthAuthorizationDetailsType`,
one per value: a bare name, or a JSON definition such as

```json
{"type": "payment_initiation", "description": "Initiate a payment",
 "locations": ["https://pay.bank.example/"],
 "schema": {"type": "object", "required": ["instructedAmount"]}}
```

written on the console, through `/admin-api`, or proposed by the RFC 9728
import from a resource's `authorization_details_types_supported`.
`authorization_details_types_supported` in both discovery documents is
`openid_credential` plus every declared type in the realm. A named
authorization server may publish a narrower list, and a client may register
`authorization_details_types` (section 10) to limit itself. `authorization_details`
is also accepted inside a request object.

* **Refused in every mode** with `invalid_authorization_details`: unreadable
  JSON, an entry with no `type`, a malformed common field (`locations`,
  `actions`, `datatypes`, `identifier`, `privileges`), a type nobody declares
  (section 5), a type outside the client's or the authorization server's list,
  a detail failing its type's schema, and a location the resource does not
  answer to.
* **One token is for one resource**: the detail's `locations`, or the
  resource's permission base URI, `oauthAudience` or client_id. Details of two
  resources, or a `resource` or scope naming a different API beside them, are
  refused (`invalid_authorization_details`, `invalid_target`, `invalid_scope`).
* **Consent draws every detail, member by member.** A detail is about one
  transaction, so Allow holds for exactly that array, that person and that
  client, once; it is not remembered like a scope. `prompt=none` answers
  `consent_required`. `openid_credential` follows the scope rules.
* **What was granted travels with the token**: the access token's
  `authorization_details` claim, the token response and `/oauth2/introspect`.
  A subset (section 6) is fewer actions or locations with the same values
  otherwise, on an authorization code or a refresh token. A direct grant
  (`client_credentials`, `password`, the assertion grants, token exchange) is
  granted the details it asks for. `oauth2.authorizationDetailsMaxEntries` caps
  the array.

**`openid_credential` and a subset of the claims.** OpenID4VCI 1.0 puts a
wallet's claim selection in the `claims` member of an `openid_credential`
detail (section 5.1.1), not in the Credential Request, so it is made when the
issuance is authorized and travels inside the signed access token; a wallet
cannot widen it. Each entry is a claims description object (Appendix A.1)
whose `path` is a claims path pointer (Appendix B) — an array, since a claim
may be nested (`["address","locality"]`) or address array elements with
integers or `null`. The paths are exactly those the issuer metadata publishes
for the configuration's format: top-level for `dc+sd-jwt`, under
`credentialSubject` for `jwt_vc_json`, the flat context terms for `ldp_vc`.
Refused with `invalid_authorization_details`: a `claims` that is not a
non-empty array, a `path` that is not a non-empty array of strings, nulls and
integers, a claim described twice (A.3), and a path this issuer does not
advertise. **Absent is not empty**: no `claims` member means the whole
configured set. The token request may carry `authorization_details` too
(section 6.1.1), which is the only route the pre-authorized code flow has; a
detail naming a configuration the Credential Offer did not is refused, and the
refresh grant carries the granted details forward. See
[OpenID4VCI](oid4vci.md).

### Lodging an intent (the FAPI lodging intent pattern)

The lodging intent pattern keeps a large or sensitive authorization request —
a payment, a consent to share accounts — off the browser: the client lodges
it with the authorization server first, and the browser carries only a
reference. Here that is **rich authorization requests pushed through PAR**,
and there is no separate intent endpoint:

1. The client POSTs its `authorization_details` (and the rest of the request)
   to `/oauth2/par`, authenticating as it does at the token endpoint. The
   details are validated against the type the resource application declared.
2. The answer is a `request_uri` — the lodged intent's reference.
3. The browser goes to `/oauth2/authorize?client_id=…&request_uri=…`. The
   person sees each detail on the consent screen and approves it.
4. The token is addressed to the type's resource, and the token response
   carries the approved `authorization_details` back.

```
POST /oauth2/par
client_id=bank-app&response_type=code&redirect_uri=https%3A%2F%2Fapp.example%2Fcb
&code_challenge=…&code_challenge_method=S256
&authorization_details=[{"type":"payment_initiation","actions":["initiate"],
  "locations":["https://pay.bank.example/"],
  "instructedAmount":{"currency":"EUR","amount":"12.50"}}]
```

### Grant management (Grant Management for OAuth 2.0)

A **confidential** client can name and manage what a person let it do
([Grant Management for OAuth 2.0](https://github.com/openid/fapi/blob/main/oauth-v2-grant-management.md),
draft 03). It is on in every mode.

* **Creating, merging and replacing.** An authorization request (or a pushed
  or signed one, or a CIBA request) carries `grant_management_action`:
  `create` makes a new grant; `merge` adds this request's permissions to the
  grant named by `grant_id`; `replace` makes that grant hold only this
  request's. The token response carries `grant_id`.
* **A grant exists once its tokens are claimed** at the token endpoint. An
  authorization nobody redeems leaves nothing behind.
* **Merge and replace invalidate the refresh tokens issued before**, on every
  node. A merge carries the grant's earlier scopes forward only while the
  person's consent still covers them.
* **Reading and revoking.** `GET /oauth2/grants/{grant_id}` answers the
  grant: its `scopes` (with their `resource`s), `claims`,
  `authorization_details`, `created_at`, `last_updated`, `expires_at` and
  `updated_by`. `DELETE` revokes it (204): every refresh token issued under it
  is refused from then on, and every token this realm recorded under it is
  revoked. Both need an access token of **the client that holds the grant**,
  carrying `grant_management_query` or `grant_management_revoke`. These are
  protected scopes: the client must declare them (`oauthAllowedScope`).
* **A grant expires with its last token.** The hourly
  `oauth2.grant-management-purge` job removes it then.
* **Refusals.** `invalid_request` for an unknown action, a `grant_id` with
  `create` or without an action, `merge` or `replace` without a `grant_id`, a
  public client, or a response type that returns an access token from the
  authorization endpoint; `invalid_grant_id` for a grant this client and this
  person do not hold.

The console lists every grant on **Monitoring → Grants** (`/admin/grants`,
`GET /admin-api/grants`), with a Revoke button each
(`POST /admin-api/grants/revoke-grant`). What the person agreed to is
**Consent**, beside it.

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

#### Introspection as a JWT (RFC 9701)

The JWT is chosen when `Accept` **names** `application/token-introspection+jwt`
with a quality at least as high as `application/json`'s, at
`/oauth2/introspect` and `/{as}/oauth2/introspect`:

```
header  {"typ": "token-introspection+jwt", "alg": "RS256", "kid": "..."}
claims  {"iss": "<this authorization server>",
         "aud": "<the resource server's client_id>",
         "iat": 1789000000,
         "token_introspection": {"active": true, "scope": "...", "sub": "...", ...}}
```

An inactive token's claim is `{"active": false}` and nothing else. The JWT
carries no `sub` and no `exp`, so it cannot be mistaken for an access token,
and it is not recorded in `/admin/tokens`: it is a response, not a credential.

* **The caller authenticates in every mode.** No credential, an unknown or
  public client, a client with nothing on file to verify, or a credential that
  does not verify is **400 `invalid_client`** (section 5). Every token-endpoint
  method works, through the same check and the same secret rate limit. A JSON
  request in product mode is refused **401 `invalid_client`** without one
  (RFC 7662 section 2.3).
* **What the resource server registers decides the protection** (section 6):

  | Member | Attribute on the application | Default |
  |---|---|---|
  | `introspection_signed_response_alg` | `oauthIntrospectionSignedResponseAlg` | `RS256` — any JWS algorithm in `introspection_signing_alg_values_supported`, HMAC keyed by the client secret; never `none` |
  | `introspection_encrypted_response_alg` | `oauthIntrospectionEncryptedResponseAlg` | not encrypted — RSA-OAEP, RSA-OAEP-256 or ECDH-ES(+A*KW), to a key in the client's `jwks` or registered `jwks_uri` |
  | `introspection_encrypted_response_enc` | `oauthIntrospectionEncryptedResponseEnc` | `A128CBC-HS256` once an `alg` is set; refused without one |

  Set them in an RFC 7591 registration (an RFC 7592 update clears a member it
  omits), on the application's console page, or with
  `POST /admin-api/applications/set`. A value this service cannot honour is
  refused where it is written (`invalid_client_metadata`); one written by
  `ldapmodify` makes the JWT response fail **500 `server_error`** with the
  reason, rather than go out with different protection. An encrypted response
  is a Nested JWT with `cty: "JWT"` and the same `typ`.
* The discovery documents publish `introspection_signing_alg_values_supported`,
  `introspection_encryption_alg_values_supported` and
  `introspection_encryption_enc_values_supported`;
  `oauth2.introspectionCertificateHeader` decides whether the signature names
  its certificate chain.
* **Tokens meant for the caller.** Wherever the caller authenticated, a token
  is active only if it is the caller's own (`client_id`), if its `aud` is this
  service's default resource indicator (`<base>/resource`, or a named
  authorization server's), or if its `aud` names the caller's application by
  `oauthClientId`, `oauthAudience` or `oauthPermissionBaseUri`. A refresh token
  is reported only to its own client. An anonymous development JSON caller is
  not restricted.
* **A named authorization server's profile can narrow it**:
  `introspection_endpoint_auth_methods_supported` refuses a client whose
  method is not listed, and the three `introspection_*_values_supported` lists
  refuse a resource server whose algorithm (or the RS256 default) is not
  listed, both `invalid_client`. Removing a member turns its check off.
* **OAuth 2.1 mode** refuses a request carrying two client authentication
  methods (section 2.4).
* **Not done**: RFC 9701 section 9's legal basis for releasing a token's data
  is the deployment's to establish.

`POST /oauth2/revoke` ([RFC 7009](https://www.rfc-editor.org/rfc/rfc7009))
writes to the same revocation set as the console's **Revoke** buttons, and
since [#102](https://github.com/rcbj/iya-sts/issues/102) it follows section 2.1:

* **The client first.** In product mode every request comes from a client: a
  confidential one presents a credential that verifies, by any method the
  token endpoint accepts, and a public one names its registered `client_id`.
  Anything else is 401 `invalid_client`. In development a request with no
  credential still revokes, but a credential that is presented is verified,
  and one that fails is refused the same way.
* **A client revokes only its own tokens.** A token issued to another client
  is refused `invalid_grant` and nothing is revoked.
* **Access and refresh tokens only.** An ID Token, or any other token this
  realm signed, is `unsupported_token_type` (section 2.2.1). A token that does
  not verify is still answered 200, as section 2.2 says.
* **`token` is required** (`invalid_request` without it), and
  `token_type_hint` is a hint: an unknown value is ignored.
* **A refresh token takes its grant with it.** Revoking one revokes every
  refresh token of its family and every access token issued beside them.
  Revoking an access token revokes that token alone.

`revocation_endpoint_auth_methods_supported` is the same list as
introspection's, `none` included.

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
  **Sign in** link to it, carrying `iss` and `login_hint` (Core section 4) and
  Enterprise Extensions' `tenant`, `domain_hint` and `target_link_uri`.

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

#### Front-Channel Logout in detail

```
POST /oauth2/register
  { "frontchannel_logout_uri": "https://rp.example/logout",
    "frontchannel_logout_session_required": true }

GET /.well-known/openid-configuration
  "frontchannel_logout_supported": true
  "frontchannel_logout_session_required": true

id_token: { …, "sid": "EO-iqvyoBaXVAwJMzzHQuEcBlw4dcI36" }

any sign-out ->  <iframe src="https://rp.example/logout?iss=…&sid=EO-iqvy…">
```

* **`sid` is in the ID Token because the specification needs it** (section 3).
  `oauth2.frontchannelLogout` off removes the members; `sid` goes too only
  when `oauth2.backchannelLogout` is off as well.
* **`iss` and `sid` go only to a client that registered
  `frontchannel_logout_session_required`** (section 2). An omitted boolean is
  false (RFC 7591 section 2), and an RP that did not ask may be validating the
  query string it gets.
* **Every URL is printed as a link beside its iframe.** The provider cannot
  know whether a notification succeeded (section 5): a dead relying party, a
  certificate the browser refuses and a mistyped URI all look like success.
  The link is something a person can click to see.
* **A redirect becomes a page when there is a fan-out.** A 302 to
  `post_logout_redirect_uri` would abandon the document before any iframe
  loads, so `/oauth2/logout` renders the iframes and offers the return as a
  link. Where there is nothing to notify, the redirect is unchanged.

#### Back-Channel Logout in detail

```
POST /oauth2/register
  { "backchannel_logout_uri": "https://rp.example/bc-logout",
    "backchannel_logout_session_required": true }

GET /.well-known/openid-configuration
  "backchannel_logout_supported": true
  "backchannel_logout_session_supported": true

any sign-out ->  POST https://rp.example/bc-logout
                 Content-Type: application/x-www-form-urlencoded
                 logout_token=eyJ0eXAiOiJsb2dvdXQrand0Ii…
```

Any sign-out sends it: `/oauth2/logout`, `/logout`, `wsignout1.0`, SAML Single
Logout, the console and `/admin-api`.

* **The token** is typed `logout+jwt` and carries `iss` (the issuer the
  client's ID Token came from), `aud`, `iat`, `exp` (`oauth2.backchannelLogoutTokenTtlS`
  on), `jti`, the `http://schemas.openid.net/event/backchannel-logout` event,
  `sub` and `sid`, and no `nonce`. It is signed like the client's ID Token, and
  encrypted as a Nested JWT where the client registered
  `id_token_encrypted_response_alg`.
* **Sent after the sign-out has answered, and written down.** 200 and 204 are
  success; **400 is final** (section 2.8); a timeout, a connection failure,
  5xx, 408 and 429 are retried `oauth2.backchannelLogoutAttempts` times with a
  doubling backoff, by any node and across a restart, because the row carries
  the state and the token. A sign-out's result lists each delivery as
  `pending`, and `/admin/logout` (and `GET /admin-api/logout`) lists where each
  got to, from every node. Every final outcome is one `logout.backchannel`
  audit row (a failure with its `STS-OAUTH-05xx` code), and the log gets a
  periodic summary rather than a line per failure.
* **A delivery that never succeeds is a dead letter** — refused with 400,
  refused by the outbound policy, or out of attempts — kept with its reason and
  sent again only by **Retry** on `/admin/logout`
  (`POST /admin-api/logout/retry-backchannel`), which mints a new token and
  uses the client's current address.
* **The outbound policy applies**: nothing at all with `federation.outbound`
  off, https with the certificate verified, no redirect followed, and in
  product mode no loopback, private or link-local address — the name is
  resolved once and the connection pinned to the address that was checked.
* **Expiry and disabling send too.** `oauth2.backchannelLogoutOnExpiry` (on)
  sends when a session expires, since a relying party never told keeps a
  session this service no longer vouches for. An account disabled from
  `/admin/users` ends every session and sends them as well.
* **Several processes send it once.** The process that reports the session's
  end sends, and each attempt is claimed with a lease, so an attempt by a
  process that dies is taken over once the lease lapses, and the stalled
  process cannot overwrite the outcome when it wakes.

`oauth2.backchannelLogout` off removes the members, the fan-out and this
feature's half of `sid` together.

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

### DPoP and step-up at these endpoints

The proof checks, the nonce handshake and the settings that require a binding
are on [OAuth security](oauth-security.md#dpop-rfc-9449). As they meet the
endpoints on this page:

* **DPoP** binds the access **and** refresh tokens (`cnf.jkt`). A wallet or
  other public client's unbound refresh token would be a bearer credential that
  mints bound access tokens for whoever holds it. The metadata advertises
  `dpop_signing_alg_values_supported` (section 5.1), the only signal that DPoP
  is on offer; `dpop_jkt` binds a code before it is issued (section 10);
  introspection reports `token_type` `DPoP`.
* **Where DPoP applies.** OpenID4VCI recommends it and lets the Credential
  Issuer send a `DPoP-Nonce`, so it covers the token endpoint and the
  Credential, Deferred Credential and Notification endpoints. OpenID4VP has no
  access token to bind — its proof of possession is the Key Binding JWT — so it
  does not apply there. DPoP binds an OAuth token, not a credential, so it
  works unchanged for every credential format.
* **The nonce request has two shapes**: the authorization server asks with a
  400 JSON body, a resource server with a 401 `WWW-Authenticate` challenge.
  `POST /dpop/nonce-mode`, a non-spec switch listed as such on
  `/admin/sts-metadata`, writes `oauth2.dpopNonceRequired` for the realm it is
  reached in; product mode refuses it.
* **A foreign token's `cnf.jkt` is only a claim.** For a token this service
  did not issue (accepted by the OpenID4VCI endpoints in development), anyone
  could have written it; the binding is real only for tokens issued here,
  which is why UserInfo refuses foreign tokens.
* **Step-up** (RFC 9470): the authorization endpoint honours `acr_values` and
  `max_age` with or without `openid`, and an elapsed `max_age` re-authenticates,
  which OpenID Connect Core requires anyway. An `mfa` session asked for
  `acr_values=1` is issued `acr: "1"` — the most preferred requested value that
  was met.
  ```
  GET /oauth2/step-up/resource/api1          Authorization: Bearer <acr "1">
  401 WWW-Authenticate: Bearer error="insufficient_user_authentication",
        error_description="…", acr_values="mfa", max_age="600"

  GET /oauth2/authorize?client_id=app1&…&acr_values=mfa&max_age=600
  ```
  At `/oauth2/step-up/resource/{application}` the token must verify, be this
  service's `at+jwt` and name the application in its `aud`; then the answer is
  the challenge or a 200 describing the authentication it met. A token with no
  `auth_time` does not meet a `max_age`. `/admin/oauth2/monitor` counts
  requirements met by the session or by a sign-in, people sent to sign in
  again, both refusals and resource-server challenges, per client.

### Not implemented

* The device authorization grant: there is no device authorization endpoint.
* A Self-Issued OP (#129).
* Enforcing `value`/`values` or `essential` in a claims request, other than
  for `acr`.
* Encrypted access tokens, and the RFC 9068 `roles` and `entitlements` claims.
* An initial access token for registration.
* A foreign `subject_token` issuer in product mode.
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
| Profile claims | an invented persona fills gaps | from the directory entry or omitted; `email_verified` is `true` only for an address the person verified ([mail](mail.md)), else `false` |
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
| `oauth2.registeredSecretBytes` | `STS_OAUTH2_REGISTERED_SECRET_BYTES` | `48` | yes | How many random bytes make a registered client's secret and registration access token. 48 by default so a `client_secret_jwt` secret is long enough for HS512 (RFC 7518 section 3.2, enforced in product). **Below 24, even HS256 is refused in product.** |
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

### Client attestation

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `oauth2.clientAttestationTrustAnchors` | `STS_OAUTH2_CLIENT_ATTESTATION_TRUST_ANCHORS` | (empty) | yes | PEM trust anchors for an attestation's `x5c`. |
| `oauth2.clientAttestationTrustedKeys` | `STS_OAUTH2_CLIENT_ATTESTATION_TRUSTED_KEYS` | (empty) | yes | A JWKS of trusted attester keys. |
| `oauth2.clientAttestationChallengeRequired` | `STS_OAUTH2_CLIENT_ATTESTATION_CHALLENGE_REQUIRED` | `true` | yes | Require a challenge in every PoP. **Off is weaker and not recommended.** |
| `oauth2.clientAttestationChallengeTtlS` | `STS_OAUTH2_CLIENT_ATTESTATION_CHALLENGE_TTL_S` | `300` | yes | How long a challenge is accepted. |
| `oauth2.clientAttestationChallengeCacheSize` | `STS_OAUTH2_CLIENT_ATTESTATION_CHALLENGE_CACHE_SIZE` | `10000` | yes | Unexpired challenges a realm holds; the oldest goes first. |
| `oauth2.clientAttestationMaxAgeS` | `STS_OAUTH2_CLIENT_ATTESTATION_MAX_AGE_S` | `86400` | yes | The oldest attestation (by `iat`) accepted. |
| `oauth2.clientAttestationPopMaxAgeS` | `STS_OAUTH2_CLIENT_ATTESTATION_POP_MAX_AGE_S` | `300` | yes | The oldest PoP (by `iat`) accepted. |
| `oauth2.fapiAllowClientAttestation` | `STS_OAUTH2_FAPI_ALLOW_CLIENT_ATTESTATION` | `false` | yes | Accept the two methods under FAPI 2.0 (HAIP 1.0 section 4). |

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
* **A withdrawn consent ends the grant it covered** (#172). Withdrawing a
  consent revokes every token issued under it, and the refresh grant re-checks
  consent at every refresh: a refresh token granted before a withdrawal is
  refused even after consent is given again. With
  `oauth2.refreshRequiresConsent` on (the default), turning consent on also
  refuses a refresh of a grant nobody consented to. Delegated-permission
  enforcement still does not re-judge an earlier grant.
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
* **UserInfo refuses a token it did not issue.** Unlike the OpenID4VCI
  endpoints in development, it answers *who did you authenticate*, and a
  profile made up for an unverifiable token would teach a client the wrong
  lesson.
* **A front-channel fan-out turns a redirect into a page.** An iframe cannot
  load in a document that has already been redirected away, and a visible link
  per notification is the only way a person can see one that silently failed.
* **The token-exchange refresh setting has three values, not two.** A boolean
  could not express `always`, which is where a client that leaks a credential
  it never asked for is caught.
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
| `/admin/oauth2` | the `oauth2.*` settings: issuer, both compliance modes, redirect URIs, logout, the deliberate `breakIdTokenNonce` defect (development mode only) |
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
