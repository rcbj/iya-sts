---
title: Departures from the specifications
---

# Departures from the specifications

This page lists every place where iya-sts's **default** behaviour departs from
what a specification requires (MUST, SHALL, REQUIRED) or recommends (SHOULD,
RECOMMENDED). Each row cites the clause and says three things: what the
service does, whether product mode differs, and which setting changes it.

The page describes the service as it is now, and lists only departures that
have been checked against the code. For the official suites the service is
tested against, and the exceptions recorded there, see
[Conformance and interoperability suites](conformance.md).

## Reading this page

**The default mode is development.** `global.mode` defaults to
`development`, a deliberately permissive mode whose purpose is to exercise
clients. It checks no password, registers unknown clients and service
providers when it first sees them, and accepts some tokens it cannot verify.
A client that has only met a strict server has never run its own refusal
paths. **Product mode** (`global.mode` = `product`) is the one meant to be
deployed. Most departures below apply in development only, and the
*Product mode* column says what product does instead.
[What is not checked](what-is-not-checked.md) draws the line between the two
modes in full.

**Within each table, rows that apply in both modes come first.** Those are
the ones a deployment inherits.

Each row starts with one of four kinds:

| Kind | Meaning |
|---|---|
| **Weaker.** | Accepts what the specification says to refuse, skips a check it requires, or does not follow a SHOULD. |
| **Stricter.** | Refuses something a conforming peer may send, for example an algorithm the specification makes mandatory to implement. Choosing the more secure of two options a specification allows is not listed. |
| **Not implemented.** | A MUST or SHOULD feature of a specification the service claims. Optional features that are missing are not listed. |
| **Different.** | A deliberate reading that differs from the specification's text. |

**RFC 9700 is summarised in one row.** The service publishes the full list of
RFC 9700 requirements, and whether each is enforced, at `GET /oauth2/rfc9700`.
This page does not copy that list.

## Credentials development mode does not check

In development mode no password is verified anywhere. Any password is accepted
for any name, and the name typed becomes the identity in every token and
assertion. Two refusals are kept so the failure paths can still be reached: the
reserved password `invalid`, and an account an administrator has disabled. A
TOTP code, a recovery code and a WebAuthn assertion are verified in both modes.
Product mode verifies every presented password against the scrypt hash in the
person's `userPassword`, and a person with none set cannot sign in.

| Door | What iya-sts does by default | What the specification says | Product mode | Changing it |
|---|---|---|---|---|
| The sign-in screen (`/authn/login`), and so every browser sign-in behind it: OpenID Connect, SAML, WS-Federation, the portal, the password step after a wallet | **Weaker.** Any password is accepted. A wallet presentation followed by any password counts as two factors (`acr` `mfa`). | [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) section 3.1.2.3: the server MUST authenticate the End-User. [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html) section 3.1.1.2: the verifier compares the password with the stored one. | Verified | `global.mode`, default `development`. By design: development exists to exercise clients. See [Authentication](authentication.md#passwords). |
| The OAuth 2.0 password grant (`grant_type=password`) | **Weaker.** The grant is offered, and any password is accepted. | [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749) section 4.3.2: the server MUST validate the resource owner's credentials. | The grant does not exist | `global.mode`. That the grant is offered at all is part of RFC 9700 mode; see the OAuth section. |
| LDAP simple bind, on 389 and 636 | **Weaker.** Any DN binds with any password, and failed binds are not rate limited. | [RFC 4513](https://www.rfc-editor.org/rfc/rfc4513) section 5.1.3: the server verifies the password and answers `invalidCredentials` when it is wrong. | Verified and rate limited | `global.mode`. Anonymous and unauthenticated binds and the plain listener are covered in the LDAP section. See [LDAP](ldap.md). |
| A WS-Security UsernameToken at the WS-Trust STS | **Weaker.** The token is read for its name. The password is not checked. | [WSS UsernameToken Profile 1.1.1](https://docs.oasis-open.org/wss-m/wss/v1.1.1/os/wss-UsernameTokenProfile-v1.1.1-os.html): the password is the secret the recipient checks. | Verified | `global.mode`. A request carrying no credential at all is covered in the WS-Trust section. |
| SCIM HTTP Basic, Digest and HOBA (`/scim/v2`) | **Weaker.** Basic accepts any password. Digest accepts any username with the one shared `scim.digestPassword` (`password!`). Anyone may register a HOBA key for any name. | [RFC 7644](https://www.rfc-editor.org/rfc/rfc7644) section 2 relies on standard HTTP authentication ([RFC 7617](https://www.rfc-editor.org/rfc/rfc7617), [RFC 7616](https://www.rfc-editor.org/rfc/rfc7616), [RFC 7486](https://www.rfc-editor.org/rfc/rfc7486)) to establish who the client is. | Basic verified. Digest not offered. A HOBA key is registered only by its owner. | `scim.authBasic`, `scim.authDigest`, `scim.authHoba`, each default `true`. See [SCIM](scim.md). |
| Shared Signals HTTP Basic (`/ssf` stream management) | **Weaker.** Any username with any password passes, holds `ssf:read` and `ssf:write`, and owns the streams it creates. Bearer tokens are verified in both modes. | [SSF 1.0](https://openid.net/specs/openid-sharedsignals-framework-1_0.html): the Transmitter authenticates and authorizes the Receiver on the management API. | Verified | `ssf.authBasic`, default `true`, removes the scheme. See [Shared Signals](shared-signals.md). |
| EST HTTP Basic, and an application's `client_secret` (`/.well-known/est`) | **Weaker.** Any password for an existing person, or any secret for an existing client, authenticates. A TLS client certificate is verified in both modes. | [RFC 7030](https://www.rfc-editor.org/rfc/rfc7030) section 3.2.3: HTTP-based client authentication identifies the client that the server then authorizes. | Verified | `est.basicAuthentication`, default `true`. See [EST](est.md). |
| A security key's attestation statement at registration | **Weaker.** `webauthn.attestationPolicy` is `by-mode`, which is `off` in development. The format is recorded and nothing is verified, so a forged statement is recorded as if it were genuine. | [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/) section 7.1: the Relying Party MUST verify the attestation statement with its format's verification procedure. | Every statement that is present is verified, including chain, FIDO metadata and revocation. `none` and self attestation are accepted as untrusted. | `webauthn.attestationPolicy`, default `by-mode`. Set `verify-if-present` or `require-trusted`. See [Authentication](authentication.md#webauthn). |
| The passwordless box on the sign-in screen, for a name holding no key | **Weaker.** A key is enrolled on the spot and no password is asked for. The first person to claim a username gets the account. | [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html) section 4.1 (authenticator binding): binding a new authenticator SHALL require authentication at the level the new authenticator will be used at. | Refused. A key is added on `/portal/keys`, by an activation link, or by an operator. | `webauthn.primaryAllowed`, default `true`, removes the passwordless box in both modes. |

Because no password is checked, development also accepts the password alone
from a person who holds or is required to hold a second factor, at the five
password-only doors above (LDAP, UsernameToken, SCIM, SSF and EST Basic).
Product refuses it there and accepts an app password instead;
`authn.passwordAloneDoors` (default empty) reopens named doors. The Kerberos KDC
is covered in its own section. Two development conveniences follow from the
same premise but depart from no specification: `/logout?username=` lets anyone
sign any named person out (`logout.anyUser`, default `true`, ignored in
product), and while the bootstrap `admin` has not yet signed in to `/admin`,
every signed-in person holds both console roles (`admin.openWhenEmpty`, default
`true`, ignored in product).

## OAuth 2.0 and OpenID Connect

| What iya-sts does by default | What the specification says | Product mode | Changing it |
|---|---|---|---|
| **Weaker.** At the RFC 7522 SAML assertion grant, the `<Audience>` values of every `<AudienceRestriction>` are pooled into one list, and the assertion is accepted if any of them names this authorization server. An assertion restricted to this server *and* to another party is accepted. | [SAML 2.0 Core](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf) section 2.5.1.4: several `<AudienceRestriction>` elements MAY appear, and each MUST be evaluated independently. [RFC 7522](https://www.rfc-editor.org/rfc/rfc7522) section 3 relies on that audience check. | Same | — (the federation service provider evaluates each restriction separately; this grant does not yet) |
| **Stricter.** An RFC 7523 JWT authorization grant with no `jti` is refused `invalid_grant`. One that carries a `jti` is accepted once, ever. | [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523) section 3: `jti` is OPTIONAL, and the server MAY reject a reused JWT. | Same | — by design: an assertion with no `jti` cannot be remembered, so it would be a replayable credential. See [JWT assertions](jwt-assertions.md). |
| **Stricter.** When a `request_uri` carries a fragment shaped like a SHA-256 hash, the fetched request object must hash to it. A mismatch is refused. | [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html) section 6.2: the fragment SHOULD be a hash of the contents, so a server can tell when to re-fetch. Nothing asks the server to verify it, and clients that put other values there are conforming. | Same | `oauth2.requestUriFragmentCheck`, default `true` |
| **Different.** `token_endpoint_auth_methods_supported` includes `saml2_bearer`, a name this service made up for RFC 7522 client authentication. | [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591) section 2: a `token_endpoint_auth_method` value is either registered with IANA or an absolute URI. [RFC 7522](https://www.rfc-editor.org/rfc/rfc7522) registers no method name. | Same (OAuth 2.1 mode drops it) | — (RFC 7522 defines no name). See [SAML assertions](saml-assertions.md). |
| **Different.** An RFC 7592 update that leaves out `jwks`, `jwks_uri`, `post_logout_redirect_uris`, the logout URIs or `client_uri` keeps the stored value. `redirect_uris` in an update are added to the ones already held, not substituted for them. So a key or redirect URI the client withdrew stays usable. | [RFC 7592](https://www.rfc-editor.org/rfc/rfc7592) section 2.2: an update replaces the registration. The server MUST treat omitted fields as null or empty, meaning the client asked for them to be deleted. | Same | — |
| **Not implemented.** A registered client's `policy_uri` and `tos_uri` are never shown to the person on the consent screen. | [OpenID Connect Dynamic Client Registration](https://openid.net/specs/openid-connect-registration-1_0.html) section 2: the OpenID Provider SHOULD display each URL to the End-User when it is given. | Same | — |
| **Not implemented.** A claims request that asks for `sub` with a specific `value` is not checked. The person who signs in gets a positive response whatever `sub` was asked for. | [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html) section 5.5.1: when `sub` is requested with a value, the server MUST only send a positive response if that End-User has an active session or authenticated during the request. | Same | — |
| **Not implemented.** An `id_token_hint` whose `sub` is pairwise cannot be mapped back to a person. At `/oauth2/authorize` the hint then gives no user. At `/oauth2/bc-authorize` (CIBA) the request is refused as naming nobody. Ephemeral subjects are mapped back. | [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html) section 3.1.2.1 (`id_token_hint`) and section 8.1 (pairwise identifiers); [CIBA Core](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html) section 7.1: an ID Token previously issued to the client identifies the user. | Same | — (only clients registered with `subject_type` `pairwise`) |
| **Different.** An administrator with Admin Write can restore a revoked token on `/admin/tokens` or `POST /admin-api/tokens/restore`. Introspection then reports the token active again. | [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009) section 2: revocation invalidates the token. The RFC has no way to undo it. | Same | — by design: a test gets a working credential back without a restart |
| **Weaker.** RFC 9700 mode is off. PKCE is not required and `plain` is accepted. The implicit grant, token-bearing response types and the password grant are offered. A client that registered no redirect URI may use any absolute one. Refresh tokens for public clients are neither rotated nor sender-constrained. `GET /oauth2/rfc9700` lists every requirement and whether it is enforced. | [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700) (MUSTs on PKCE, exact redirect-URI matching, the password grant and public-client refresh tokens); [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html) section 3.1.2.1: `redirect_uri` MUST exactly match a pre-registered value. | Enforced: product mode implies RFC 9700 mode. Two rows stay unenforced in every mode: sender-constrained access tokens (a SHOULD), and `tokens-are-secrets`, because the console keeps issued tokens to show them. | `oauth2.rfc9700`, default `false`; `oauth2.oauth21`, default `false`. Sender constraint: `oauth2.accessTokenRequireDpop` / `oauth2.accessTokenRequireMtls`, default `false`. See [OAuth security](oauth-security.md#rfc-9700-mode). |
| **Weaker.** Client authentication at the token endpoint and at `/oauth2/par` is observed, not enforced. A wrong secret, or a client assertion whose signature fails, is logged and the request proceeds. An unknown `client_id` is registered on first use. | [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749) section 3.2.1: confidential clients MUST authenticate at the token endpoint. [RFC 9126](https://www.rfc-editor.org/rfc/rfc9126) section 2.1: the server MUST authenticate the client at the PAR endpoint as it would at the token endpoint. | Enforced: a client that declared a confidential method must present a credential that verifies. Unknown clients are refused. | `global.mode`; `oauth2.rfc9700`, `oauth2.oauth21` or `oauth2.fapi` enforce it in development too |
| **Weaker.** A public client (`token_endpoint_auth_method` `none`) may use the client credentials grant. | [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749) section 4.4: the client credentials grant MUST only be used by confidential clients. | Refused `unauthorized_client` | `global.mode` |
| **Weaker.** A `private_key_jwt` or `client_secret_jwt` client assertion with no `exp` is accepted, and its lifetime is not capped. | [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523) section 3: the JWT MUST contain `exp`, and the server MUST validate the JWT against section 3's criteria before accepting it. | Refused. The lifetime is capped at `oauth2.jwtBearerMaxLifetimeS` (default 300). | `global.mode` |
| **Weaker.** A client secret past its `client_secret_expires_at` is still accepted. The use is logged. | [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591) section 3.2.1: `client_secret_expires_at` is when the secret expires. | Refused `invalid_client` | `global.mode` |
| **Weaker.** `/oauth2/introspect` gives an RFC 7662 JSON answer to anyone holding the token string. The caller needs no credential and is not limited to its own tokens. (An RFC 9701 JWT response requires client authentication in both modes.) | [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662) section 2.1: the endpoint MUST require some form of authorization, to prevent token scanning. | Client authentication required (401 `invalid_client`) | `global.mode` |
| **Weaker.** A request to `/oauth2/revoke` with no client credential revokes any token the realm issued. A credential that is presented is verified, and the caller may then revoke only its own tokens. | [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009) section 2.1: the server first validates the client's credentials (for a confidential client), then checks that the token was issued to that client. | The client must authenticate (or, if public, name its registered `client_id`) and may revoke only its own tokens | `global.mode` |
| **Weaker.** At RFC 8693 token exchange, a `subject_token` this realm cannot verify is read without a signature check and exchanged. An `actor_token` is never verified. A revoked token this realm issued is refused. | [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) section 2.1: the server MUST validate the subject token, and any actor token, as their token types require. | Both tokens must verify, be unexpired and not revoked; otherwise `invalid_request` | `global.mode` |
| **Weaker.** An unsigned (`alg: none`) request object is accepted unless a signed one is required. A registered `request_uri` may be plain `http`, and its response may have any media type. | [RFC 9101](https://www.rfc-editor.org/rfc/rfc9101) section 4 defines the request object as signed, optionally also encrypted; [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html) section 6.2: a `request_uri` MUST use `https` unless the object is signed verifiably. OpenID Connect Core section 6.1 allows `none`. | Unsigned objects refused `invalid_request_object`; `https` and a JWT media type required | `oauth2.requireSignedRequestObject`, default `false`, or the client's `require_signed_request_object` |
| **Weaker.** Claim values the directory does not hold are invented. They include a persona surname and an address at a domain nobody owns with `email_verified: true`. `verified_claims` is answered with a demonstration verification under trust framework `urn:sts:demo`. | [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html) section 5.1: `email_verified` is true only if the address was verified. [Identity Assurance](https://openid.net/specs/openid-connect-4-identity-assurance-1_0.html): `verification` describes a verification that was actually performed. | Only directory values. `email_verified` is true only for an address confirmed by mailed link. Only recorded verifications are released. | `global.mode` |
| **Weaker.** At RP-Initiated Logout, a `post_logout_redirect_uri` is followed for a named client that registered none. (A client that registered some is held to an exact match, and a request naming no client is never redirected, in both modes.) | [RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) section 3: the OP MUST NOT redirect to a value that does not exactly match one the client previously registered. | Refused | `global.mode` |
| **Weaker.** Importing protected-resource metadata on `/admin/applications/new` reports a `resource` that differs from the identifier the URL was built from (or is not `https`), then imports it anyway. | [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728) section 3.3: if the values are not identical, the data in the response MUST NOT be used. | Refused | `global.mode` |
| **Different.** Once the admin console is a public client (it is confidential until its conversion to a static application is finished), it may sign in to a realm whose `oauth2.fapi` profile supports no public client. Every token issued to it is DPoP-bound. | [FAPI 2.0 Security Profile](https://openid.net/specs/fapi-security-profile-2_0.html) section 5.3.2.1: the authorization server shall support confidential clients only. [FAPI 1.0 Advanced](https://openid.net/specs/openid-financial-api-part-2-1_0.html) section 5.2.2: shall not support public clients. | The same | None: the exception is for the seeded `sts-admin-console` client alone. See [OAuth security](oauth-security.md#the-admin-console-as-a-public-client). |

The opt-in profiles are not departures while they are off. When one is turned on, one reading differs from the strict text: under `oauth2.fapi` `1-advanced`, a DPoP-bound token counts as sender-constrained where [FAPI 1.0 Advanced](https://openid.net/specs/openid-financial-api-part-2-1_0.html) names mutual TLS. Set `oauth2.fapiRequireMtls` (default `false`) for the strict reading.

## JOSE and published keys

| What iya-sts does by default | What the specification says | Product mode | Changing it |
|---|---|---|---|
| **Weaker.** A JWS verifies with an RSA key under 2048 bits, or an HMAC key shorter than the hash output. An empty HMAC key is refused. | [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518) section 3.2: an HMAC key at least the size of the hash output MUST be used. Section 3.3: an RSA key of 2048 bits or more MUST be used. | Refused | `global.mode` |

Every realm's JWKS also publishes post-quantum keys (`kty` `AKP`) beside the classical ones, and the metadata algorithm lists include ML-DSA, SLH-DSA and composite algorithms, some of whose identifiers come from drafts. That conforms to [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517) section 5, which says a consumer SHOULD ignore a key whose `kty` it does not understand; a consumer that instead rejects the whole set cannot read these JWKS, and the OpenID conformance suite warns about them.

## OpenID Federation

| What iya-sts does by default | What the specification says | Product mode | Changing it |
|---|---|---|---|
| **Different.** The resolve endpoint (`/oidfed/resolve`) never walks a trust chain for its caller. It answers only for this service's own realms, and for entities an administrator has already resolved on the console or through `POST /admin-api/oidfed/resolve` (cached for at most `oidfed.resolveCacheS`). | [OpenID Federation](https://openid.net/specs/openid-federation-1_1.html), Resolve Entity endpoint: the resolver collects and verifies the trust chain for the requested subject and Trust Anchor. | Same | — by design: an unauthenticated request must not make the service fetch across the federation (the specification's security considerations). See [OpenID Federation](oidfed.md). |

No default departure was found for GNAP (RFC 9635, RFC 9767). Its development-mode choices (keys registered on first sight, pinned mutual-TLS keys) are ones the RFC allows.

## SAML 2.0 and 1.1

| What iya-sts does by default | What the specification says | Product mode | Changing it |
|---|---|---|---|
| **Different.** A `ProtocolBinding` of HTTP-Redirect is honoured for the `<Response>`. A response longer than `saml2.redirectWarnLength` characters is logged at WARN and sent anyway. | [SAML 2.0 Profiles](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf) §4.1.2: the HTTP Redirect binding MUST NOT be used to deliver the `<Response>`. | Same | —; by design: a service provider with no server behind its ACS can receive nothing else. Ask for `HTTP-POST` or `HTTP-Artifact`. See [SAML 2.0 Web Browser SSO](saml2-sso.md). |
| **Weaker.** Any `NameIDPolicy` `Format` is answered with the format asked for. Every format except `transient` and `emailAddress` carries the plain username as its value, including `persistent` and `X509SubjectName`. | [SAML 2.0 Core](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf) §8.3.7: a persistent identifier MUST be pseudo-random, with no discernible correspondence to the username. §3.4.1.4: a policy the IdP cannot satisfy is refused, with `InvalidNameIDPolicy`. | Same | —; by design: no second identifier is invented. Use `transient`. The request is refused only if the SP's consumed metadata lists its formats. |
| **Different.** Single Logout is not propagated. An SP's `LogoutRequest` ends the session and is answered `PartialLogout` if other SPs were signed in; none of them is sent a `LogoutRequest`. A bare `GET /saml2/slo` shows signed `LogoutRequest`s as links for the person to follow. | [SAML 2.0 Core](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf) §3.7.3.2: the session authority MUST attempt to send a `<LogoutRequest>` to each session participant other than the requester. | Same | —; by design: a blind fan-out would claim a logout it cannot observe. See [Single Logout](saml2-sso.md#single-logout). |
| **Different.** With no registered SingleLogoutService, the `LogoutResponse` goes to the ACS URL the SP last used. This is logged as a guess. | [SAML 2.0 Profiles](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf) §4.4: logout messages go to the SP's SingleLogoutService endpoint. | Same | `saml2.defaultSingleLogoutService`, default empty; or consume the SP's metadata. |
| **Not implemented.** The ECP profile, whose PAOS binding is refused by name, and Name Identifier Management. | [SAML 2.0 Conformance](https://docs.oasis-open.org/security/saml/v2.0/saml-conformance-2.0-os.pdf) §3: the feature matrix lists both for the identity provider operational mode. | Same | —. See [Not implemented](saml2-sso.md#not-implemented). |
| **Weaker.** The `AssertionConsumerServiceURL` (and SAML 1.1's `shire`) is used as the request names it, unless the SP's metadata has been consumed. An unknown entityID is registered on sight, even from an unsigned request. | [SAML 2.0 Profiles](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf) §4.1.4.1: whether or not the request is signed, the IdP MUST verify that the ACS URL or index belongs to the SP the response is sent to. | Refused unless it is a registered, confirmed address; no entry is created. | `saml2.autocreateApplications`, default `true`, controls only the registration. The address rule follows the mode. |
| **Weaker.** An unsigned `LogoutRequest` or `LogoutResponse` from an SP is accepted. So is a signed one from an SP with no registered certificate, which is recorded as not verified. A signature that can be checked is always verified. | [SAML 2.0 Profiles](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf) §4.4.4.1–4.4.4.2: the requester or responder MUST authenticate itself and protect integrity, by signing or by a binding mechanism. | Refused | `saml2.requireSignedAuthnRequests`, default `auto` (off in development, on in product). |
| **Weaker.** The artifact resolver at `/saml2/ars` and `/saml11/responder`, and the caller of the SAML 2.0 attribute authority `/saml2/aa`, must name the right SP but need not prove it. | [SAML 2.0 Bindings](https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf) §3.6 and [Profiles](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf) §5: the artifact's message goes only to its intended recipient, which requires authenticating the requester. | Required: a signed request, or a registered certificate at the TLS handshake. | `saml2.requireSignedAuthnRequests`, default `auto`. |
| **Weaker.** The SAML 1.1 responder answers an `AttributeQuery` or `AuthenticationQuery` from anybody, about anybody named. | [SAML 1.1 Bindings](https://www.oasis-open.org/committees/download.php/3405/oasis-sstc-saml-bindings-1.1.pdf) §3.1.2: the SOAP binding authenticates the requester, by mutual TLS. | Answered only to a registered relying party that authenticates, about a person it holds a live session for. | —. See [SAML 1.1](saml11.md). |

These apply to every SAML surface. Inbound XML signatures and encryption are
under *XML Signature and XML Encryption* below.

## WS-Trust

| What iya-sts does by default | What the specification says | Product mode | Changing it |
|---|---|---|---|
| **Weaker.** `Validate` returns `wst:Status` `valid` whenever `ValidateTarget` holds a token. The token's signature, issuer and expiry are not checked. | [WS-Trust 1.4](http://docs.oasis-open.org/ws-sx/ws-trust/v1.4/ws-trust.html), Validation Binding: the status reports the result of validating the token. | Same (the requester must still authenticate) | —. See [WS-Trust](ws-trust.md). |
| **Weaker.** `Cancel` answers `wst:RequestedTokenCancelled`, but nothing already issued is recalled. `Validate` and `Renew` still accept the token. | [WS-Trust 1.4](http://docs.oasis-open.org/ws-sx/ws-trust/v1.4/ws-trust.html), Cancel Binding: a cancelled token is no longer valid. | Same | —. |
| **Not implemented.** A `ds:Signature` in the request's `wsse:Security` header is not verified. | [WS-Security 1.1 SOAP Message Security](http://docs.oasis-open.org/wss-m/wss/v1.1.1/os/wss-SOAPMessageSecurity-v1.1.1-os.html) §8: the receiver validates a signature it processes, and faults if it fails. | Same | —. |
| **Different.** A 2004/04 answer's `wsp:AppliesTo` and `wsa:EndpointReference` use the 2004/09 WS-Policy and 2005/08 WS-Addressing namespaces. The answer is still schema-valid, through a lax wildcard. | WS-Trust 2004/04 imports WS-Policy 2002/12 and WS-Addressing 2004/03. | Same | —. |

In development mode the STS also does the following:

- It answers a request that carries no credential, with a token for the subject `anonymous`.
- It believes a SAML assertion presented as a credential without verifying it.
- It issues `OnBehalfOf` and `ActAs` tokens with no requester credential, and records what the delegation policy would have refused.

See *Credentials development mode does not check*. WS-Trust leaves requester authentication and delegation to the STS's policy, so none of these is listed as a departure.

## WS-Federation

No default departure was confirmed for the passive requestor profile.
`wreqptr` is not dereferenced, `wattr1.0` and `wpseudo1.0` answer 501, and
`wct` is not enforced. All three are optional in WS-Federation 1.2. In
development, a `wreply` is used as the request names it, which is the same
posture as SAML's ACS URL. WS-Federation 1.2 states no rule for it, so it is
not listed. Product requires a registered `wsfedReplyUrl`.

## Federation relationships

| What iya-sts does by default | What the specification says | Product mode | Changing it |
|---|---|---|---|
| **Not implemented.** An outbound SAML 2.0 `AuthnRequest` on the HTTP-Redirect binding is never signed. With `fedSignRequest` on, it goes unsigned and a warning is logged. A partner whose metadata says `WantAuthnRequestsSigned="true"` refuses it. | [SAML 2.0 Bindings](https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf) §3.4.4.1: on the Redirect binding, the signature is `SigAlg` and `Signature` over the query string. | Same | Set the relationship's `fedBinding` to `HTTP-POST` (default `HTTP-Redirect`) to send a signed request. See [Federation](federation.md). |
| **Different.** `/federation/metadata/{id}` publishes the NameIDFormat `urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified`, a URI no SAML specification defines. | [SAML 2.0 Core](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf) §8.3.1: the unspecified format is `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified`. | Same | `federation.spNameIdFormat`, default the 2.0 URI. |
| **Stricter.** A partner's encrypted assertion is refused if it uses AES-CBC or `rsa-1_5`. An encrypted ID Token is refused if it uses `RSA1_5` or any `A*CBC-HS*` content encryption. A relationship accepts only the GCM algorithm and key management it publishes. | [XML Encryption 1.1](https://www.w3.org/TR/xmlenc-core1/) §5.1: AES-128-CBC and AES-256-CBC are REQUIRED. [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518) §5.1: `A128CBC-HS256` is REQUIRED. | Same | —; by design: an XML AES-CBC padding oracle and a Bleichenbacher oracle. The relationship's `fedContentEncryptionAlgorithm` takes only GCM. |
| **Different.** A partner's `wsignoutcleanup1.0` or `wsignout1.0` ends nothing by itself. `/federation/slo/{id}` shows a confirmation button, and the session ends only when the person presses it. | [WS-Federation 1.2](http://docs.oasis-open.org/wsfed/federation/v1.2/os/ws-federation-1.2-spec-os.html) §13 (sign-out): a clean-up request tells the relying party to end the session, typically answered with an image and no user interaction. | Same | —; by design: the messages are unsigned, so a silent accept would let anyone sign a person out. |
| **Stricter.** In product mode, a partner's unencrypted SAML or WS-Federation assertion, or unencrypted `form_post` ID Token, is refused. Development accepts it. | Assertion and ID Token encryption are optional in SAML 2.0, WS-Federation and OpenID Connect. | Refused | `fedAllowUnencrypted` per relationship, default `false`. See [Federation](federation.md). |

## XML Signature and XML Encryption

These apply to every XML signature iya-sts verifies: SAML 2.0 and 1.1, federation, WS-Trust and WS-Federation.

| What iya-sts does by default | What the specification says | Product mode | Changing it |
|---|---|---|---|
| **Stricter.** Any SHA-1 `SignatureMethod` (`rsa-sha1`, `ecdsa-sha1`, `dsa-sha1`) or SHA-1 `DigestMethod` is refused before any cryptography runs. | [XML Signature 1.1](https://www.w3.org/TR/xmldsig-core1/) §6.1: the SHA-1 digest is REQUIRED (its use DISCOURAGED), and RSAwithSHA1 is REQUIRED for verification. | Refused; the setting cannot be turned on | `saml.allowSha1Signatures`, default `false`, development only. |
| **Stricter.** Every HMAC `SignatureMethod` is refused. | [XML Signature 1.1](https://www.w3.org/TR/xmldsig-core1/) §6.1: HMAC-SHA256 and HMAC-SHA1 are REQUIRED. | Same | —; by design: signatures are verified against registered certificates, and no shared secret is held. |
| **Not implemented.** Canonical XML 1.1 is not supported. A signature that names it is refused. | [XML Signature 1.1](https://www.w3.org/TR/xmldsig-core1/) §6.1: Canonical XML 1.1 is REQUIRED. | Same | —. |
| **Different.** Inclusive Canonical XML 1.0 is incomplete. A signed element does not get the `xml:*` attributes it inherits from its ancestors, when signing or when verifying. A nested element signed with inclusive C14N is refused. | [Canonical XML 1.0](https://www.w3.org/TR/2001/REC-xml-c14n-20010315) §2.4: a document subset's apex carries the `xml:*` attributes in scope. XML Signature 1.1 §6.1: Canonical XML 1.0 is REQUIRED. | Same | —. iya-sts signs with exclusive C14N only (`saml.canonicalizationAlgorithm`). |
| **Different.** Under a `#WithComments` method, a `URI=""` or `#id` reference keeps its comments, when signing or when verifying. | [XML Signature 1.1](https://www.w3.org/TR/xmldsig-core1/) §4.4.3.3: dereferencing `""` or a bare name MUST give a node-set without comments. | Same | —. |
| **Not implemented.** The XPath and XPath Filter 2.0 transforms, and the `#xpointer(/)` and `#xpointer(id('…'))` references. | [XML Signature 1.1](https://www.w3.org/TR/xmldsig-core1/) §6.1: both transforms are RECOMMENDED. §4.4.3.3: the two XPointer forms are RECOMMENDED where a comment-preserving canonicalization is supported. | Same | —. SAML allows only `""` and `#id` references. |
| **Not implemented.** A `Reference` to an external URI is never fetched, so its signature does not verify. | [XML Signature 1.1](https://www.w3.org/TR/xmldsig-core1/) §4.4.3.1: RECOMMENDS dereferencing URIs in the HTTP scheme. | Same | —; by design: iya-sts fetches nothing a signed document names. |
| **Different.** A DER-encoded ECDSA `SignatureValue` is accepted as well as the specified `r‖s`. | [XML Signature 1.1](https://www.w3.org/TR/xmldsig-core1/) §6.4.3: the value is the concatenation of `r` and `s`. | Same | —. |
| **Stricter.** TripleDES content encryption and TripleDES key wrap are refused. | [XML Encryption 1.1](https://www.w3.org/TR/xmlenc-core1/) §5.1: TRIPLEDES block encryption and TRIPLEDES KeyWrap are REQUIRED. | Same | —. |
| **Stricter.** In product mode, `rsa-1_5` key transport is refused before unwrapping. Development unwraps it. | [XML Encryption 1.1](https://www.w3.org/TR/xmlenc-core1/) §5.5.1 defines RSA-v1.5 key transport; §6.1.2 warns about it. | Refused | —; by design: an `rsa-1_5` unwrap is a Bleichenbacher oracle. |

In every mode, ECDH-ES agreement whose ConcatKDF uses SHA-1 is also refused.

## Authentication and account security

| What iya-sts does by default | What the specification says | Product mode | Changing it |
|---|---|---|---|
| **Weaker.** Failed password attempts are limited only per time window: `security.rateLimitPerIdentity` (5) and `security.rateLimitPerAddress` (20) per `security.rateLimitWindowS` (60 s). Nothing caps consecutive failures on an account. The image's `env/local.js` raises the limits to 100 and 500. | [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html) section 3.2.2: the verifier SHALL limit consecutive failed authentication attempts on one account to no more than 100. | Same. Refused passwords also raise the account's [risk score](risk-scoring.md). | The three `security.rateLimit*` settings. Lower the image's values in a deployed appconfig. |
| **Weaker.** The breached-password check fails open. If the Pwned Passwords API does not answer within `risk.breachTimeoutMs` (3000 ms), the password is set unscreened. Development screens no password at all. | NIST SP 800-63B-4 section 3.1.1.2: verifiers SHALL compare a prospective password against a blocklist of commonly used, expected or compromised values. | Screened when a password is set and at sign-in, fail-open on an outage | `risk.breachCheck`, default `on`, product only. `risk.breachApiUrl` can point at a mirror inside the network. See [Risk scoring](risk-scoring.md#breached-passwords). |
| **Weaker.** The built-in password policy's minimum length is 12. By default a second factor is required only of people who hold one, so most passwords are single-factor. | NIST SP 800-63B-4 section 3.1.1.2: a password used as a single factor SHALL be at least 15 characters (8 within multi-factor authentication). | Enforced at 12 | Directory → Policies, `minLength` (`pwdMinLength`), default 12. |
| **Stricter.** The built-in password policy requires at least one symbol, one uppercase letter and one digit. A password that meets NIST's rules can be refused. | NIST SP 800-63B-4 section 3.1.1.2: verifiers SHALL NOT impose other composition rules, such as requiring mixtures of character types. | Enforced (development checks no password) | Directory → Policies: set `minSymbols` to 0 and turn off `requireUppercase` and `requireDigit`. |
| **Different.** An email address written by an administrator (console, `/admin-api`, an LDAP write holding Admin Write), by SCIM, or by a federation partner that did not say `email_verified: false` is recorded as verified. `email_verified` is then `true` with no proof of control. | [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) section 5.1: `true` means the OP took affirmative steps to ensure the address was controlled by the End-User. How it verifies is context specific. | Same | — by design: those sources are treated as trusted provisioning. See [Mail](mail.md). |
| **Weaker.** The TOTP shared secret is stored on the directory entry as plain base32. | [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238) section 5.1: keys are RECOMMENDED to be stored securely and encrypted. | Sealed under the key-encryption key | — by design: development's key-encryption key changes every start, so a sealed secret would stop working at the next restart. |

Sessions have an absolute lifetime of an hour (`authn.sessionLifetimeS`, 3600)
and no idle timeout (`authn.sessionIdleTimeoutS`, 0), which is within NIST SP
800-63B-4's limits. The emailed code and sign-in link, which NIST SP
800-63B-4 section 3.1.3.1 forbids as out-of-band authenticators, are off in the
built-in authentication policy; turning them on is a documented weaker option.
Development also invents profile values, including verified-looking email
addresses; that is covered in the OpenID Connect section.

## Kerberos

| What iya-sts does by default | What the specification says | Product mode | Changing it |
|---|---|---|---|
| **Weaker.** The KDC offers and accepts `rc4-hmac` (etype 23): every account has an RC4 key, and a client that offers only RC4 gets a ticket. | [RFC 8429](https://www.rfc-editor.org/rfc/rfc8429) deprecates RC4-HMAC: implementations and deployments SHOULD NOT use it. | Etype 23 is withheld everywhere; an RC4-only request gets `KDC_ERR_ETYPE_NOSUPP`. | `krb5.enctypes`, default `18,17,20,19,23`; 23 is honoured only in development. See [Kerberos](kerberos.md). |
| **Weaker.** Any client name authenticates with one shared password, and a name the KDC has never seen is created on first use instead of being refused. Service principals, `krbtgt` and a trusted realm (`PARTNER.COM`) are keyed from published passwords. | [RFC 4120 section 3.1.3](https://www.rfc-editor.org/rfc/rfc4120#section-3.1.3): a client principal not in the KDC's database is answered `KDC_ERR_C_PRINCIPAL_UNKNOWN`; each principal has its own secret long-term key. | Keys come from each person's own directory password; nothing is created; `krbtgt` is random and rotated; there is no cross-realm trust. | `krb5.userPassword`, default `password!`. `krb5.unknownUsers` (default `nosuchuser,nobody`) keeps names unknown on purpose. |

PKINIT ([RFC 4556](https://www.rfc-editor.org/rfc/rfc4556)) is not implemented. It is an optional extension, but it means that in product mode a person whose only second factor is a security key cannot get a ticket (open: #179).

## TLS

This applies to every TLS listener: the main port, LDAPS 636 and the embedded debugger's listener. The TLS protocol itself is implemented by Node.js's OpenSSL, and where it differs in detail from RFC 8446 the service cannot configure it; those differences are not listed here.

| What iya-sts does by default | What the specification says | Product mode | Changing it |
|---|---|---|---|
| **Stricter.** TLS 1.2 offers only four ECDHE AES-GCM suites. There is no RSA key exchange, CBC, finite-field DHE or CCM, so a TLS 1.2 peer that offers only `TLS_RSA_WITH_AES_128_CBC_SHA` fails the handshake. | [RFC 5246 section 9](https://www.rfc-editor.org/rfc/rfc5246#section-9): unless an application profile says otherwise, a TLS 1.2 application MUST implement `TLS_RSA_WITH_AES_128_CBC_SHA`. | Same. | `tls.ciphers`, default the [RFC 9325](https://www.rfc-editor.org/rfc/rfc9325) (BCP 195) list. See [TLS](tls.md). |

In development, `POST /tls/trust` and `POST /tls/trust/clear` let anybody add or clear client-certificate trust anchors. No specification covers this, but it decides whose certificates count; product answers 403 (see [TLS](tls.md)).

## OpenID4VCI, OpenID4VP and verifiable credentials

| What iya-sts does by default | What the specification says | Product mode | Changing it |
|---|---|---|---|
| **Weaker.** The Credential, Deferred Credential and Notification endpoints read an access token's claims without verifying it and issue a credential. A revoked token or another issuer's token is accepted. A credential issued this way can never sign anybody in. | [OpenID4VCI 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) section 8: the Credential Request carries an access token. [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749) section 7: the resource server MUST validate it. | Refused, 401 `invalid_token` | `global.mode`. See [OpenID4VCI](oid4vci.md#development-and-product-mode). |
| **Weaker.** Wrong Transaction Codes (`tx_code`, five digits) are not counted, so a code can be guessed within the offer's 600-second lifetime. | OpenID4VCI 1.0, security considerations for the Pre-Authorized Code Flow: the Transaction Code protects against guessing, and attempts are to be limited. | The fifth wrong code (`oid4vci.txCodeMaxAttempts`) spends the pre-authorized code | `global.mode` |
| **Weaker.** `/issuer/offer` mints a pre-authorized code for `oid4vci.offerUsername` (`diploma.student`) for anyone who loads the page. | OpenID4VCI 1.0, Pre-Authorized Code Flow: the code stands for an End-User the Credential Issuer has already authenticated and authorized. | Minted only for the signed-in person | `global.mode`. By design: a test control. |

Development fills attributes a person's entry lacks with invented values before
signing them into a credential; product omits them. Credentials are signed RS256
and name their chain by `x5u` by default (`oid4vci.credentialSigningAlgorithm`,
`oid4vci.credentialCertificateHeader`), and key attestation is not required
(`oid4vci.keyAttestationRequired`, `false`). Both are allowed by OpenID4VCI and
SD-JWT VC, but a realm meant to meet HAIP 1.0 must set `x5c` and an ES256 key.
The Verifier refuses every presented credential that names no status that
resolves VALID (`oid4vp.requireStatusReference`, default `all`), although the
status reference is optional in SD-JWT VC and the VC Data Model. A wallet whose
credentials carry none needs its issuer listed in `oid4vp.statusOptionalIssuers`.

## LDAP

| What iya-sts does by default | What the specification says | Product mode | Changing it |
|---|---|---|---|
| **Not implemented.** No StartTLS, no SASL and no other extended operation. TLS is available only as LDAPS on port 636. | [RFC 4513 section 2](https://www.rfc-editor.org/rfc/rfc4513#section-2): an implementation that supports name/password authentication MUST be able to protect it with TLS established by StartTLS ([RFC 4511 section 4.14](https://www.rfc-editor.org/rfc/rfc4511#section-4.14)). | Same. | — the directory library (node-ldapjs) implements no extended operation. Connect to 636. See [LDAP](ldap.md). |
| **Different.** The directory is schemaless. No structural object class is required and MUST/MAY attributes and syntaxes are not checked. The console, `/admin-api` and SCIM create a `groupOfNames` with no `member`. | [RFC 4512 section 2.4](https://www.rfc-editor.org/rfc/rfc4512#section-2.4): an entry belongs to exactly one structural object class and MUST carry its required attributes. [RFC 4519 section 3.5](https://www.rfc-editor.org/rfc/rfc4519#section-3.5): `member` is MUST on `groupOfNames`. | Same. | — by design: an empty group is allowed so that SCIM and the console agree. See [LDAP schema](ldap-schema.md). |
| **Weaker.** The plain listener on 389 is open, and a bind that carries a password is accepted there without TLS. | [RFC 4513 section 2](https://www.rfc-editor.org/rfc/rfc4513#section-2): implementations SHOULD disallow name/password authentication by default when no data-security service (TLS) is in place. | 389 still listens, but every bind there is refused with 13, `confidentialityRequired`. | `ldap.plainListener`, default `true`. Password checking: see *Credentials development mode does not check*. |
| **Weaker.** An unauthenticated bind (a DN with an empty password) succeeds. | [RFC 4513 section 5.1.2](https://www.rfc-editor.org/rfc/rfc4513#section-5.1.2): servers SHOULD by default fail an unauthenticated bind with `unwillingToPerform`. | Refused with 53, `unwillingToPerform`. | — |
| **Weaker.** A client can write `createTimestamp`, `modifyTimestamp` and `entryDN` like any other attribute. | [RFC 4512 section 3.4](https://www.rfc-editor.org/rfc/rfc4512#section-3.4): these are NO-USER-MODIFICATION operational attributes that the server maintains. | Refused with 19, `constraintViolation`, even for an administrator. | — |

## SCIM 2.0

| What iya-sts does by default | What the specification says | Product mode | Changing it |
|---|---|---|---|
| **Different.** `active` is always returned: `true` unless the account is disabled. A PATCH `remove` of `active` is accepted and reads back `true`. | [RFC 7644 section 3.5.2.2](https://www.rfc-editor.org/rfc/rfc7644#section-3.5.2.2): after a `remove`, a single-valued attribute SHALL be considered unassigned. | Same. | — by design: `active` is the account's disabled state, and an absent value would mislead a client that filters on `active eq false`. See [SCIM](scim.md). |
| **Stricter.** `emails.type` accepts only `work`, `phoneNumbers.type` only `work` or `mobile`, and `addresses.type` only `work`. A `home` email is refused with 400 `invalidValue`. | [RFC 7643 section 4.1.2](https://www.rfc-editor.org/rfc/rfc7643#section-4.1.2) gives `work`, `home` and `other` as the canonical email types. | Same. | — by design: the directory's `mail` has no type to hold `home`. |
| **Stricter.** A `userName` that is a UUID or a `urn:uuid:` value is refused with 400 `invalidValue`, and so is the literal `invalid`. | [RFC 7643 section 4.1.1](https://www.rfc-editor.org/rfc/rfc7643#section-4.1.1): `userName` is a REQUIRED unique string, with no format restriction. | Same. | — by design: a person's subject is `urn:uuid:<entryUUID>`, and `invalid` is a reserved test value. |
| **Different.** A `password` on create or replace is accepted and thrown away, although `/Schemas` lists the attribute. | [RFC 7643 section 4.1.1](https://www.rfc-editor.org/rfc/rfc7643#section-4.1.1): `password` is used to set or replace the user's password. | Same. | — the ServiceProviderConfig says `changePassword` is not supported. |
| **Weaker.** HTTP Digest accepts any username with the one shared password, and anybody may register a HOBA key for any account. | [RFC 7616](https://www.rfc-editor.org/rfc/rfc7616) computes the Digest response from the named user's own password. [RFC 7486](https://www.rfc-editor.org/rfc/rfc7486) binds a HOBA key to an account its owner controls. | Digest is not offered. A HOBA key can be registered only by the signed-in owner of an existing account. | `scim.authDigest` and `scim.authHoba`, both default `true`. `scim.digestPassword`, default `password!`. Basic: see *Credentials development mode does not check*. |
| **Different.** A person created over SCIM is filled with invented attribute values the client never sent. | [RFC 7644 section 3.3](https://www.rfc-editor.org/rfc/rfc7644#section-3.3): the response is the resource as created from the request. | Nothing is invented. | `scim.inventOnCreate`, default `true` (development only). |

## XACML 3.0

| What iya-sts does by default | What the specification says | Product mode | Changing it |
|---|---|---|---|
| **Different.** A request with `CombinedDecision="true"` gets an ordinary single decision. So does one with several `<Attributes>` of the same category. The Multiple Decision Profile is not implemented, and neither request is refused. | [XACML 3.0](https://docs.oasis-open.org/xacml/3.0/xacml-3.0-core-spec-os-en.html) §5.42: a PDP without the Multiple Decision Profile must return Indeterminate with `processing-error` for `CombinedDecision="true"`. | Same | —. See [XACML](xacml.md). |
| **Weaker.** The embedded access and issuance PEPs grant on Permit without checking the decision's obligations. An obligation they do not know, returned by an operator's policy, is dropped. The demo PEP at `/xacml/protected` and the remote PEP do refuse one. | [XACML 3.0](https://docs.oasis-open.org/xacml/3.0/xacml-3.0-core-spec-os-en.html) §7.2: on Permit with obligations, the PEP SHALL permit access only if it understands and can discharge them. | Same | —. |
| **Weaker.** A Deny from the issuance policy's risk rules is recorded, and the issuance proceeds on the roles alone. | [XACML 3.0](https://docs.oasis-open.org/xacml/3.0/xacml-3.0-core-spec-os-en.html) §7.2: if the decision is Deny, the PEP SHALL deny access. | Enforced | `risk.enforceInDevelopment`, default `false`. |

## Shared Signals (SSF, CAEP, RISC)

| What iya-sts does by default | What the specification says | Product mode | Changing it |
|---|---|---|---|
| **Different.** This service's five private event types (`signing-key-rotated`, `federation-key-rotated`, `spiffe-authority-rotated`, `tls-certificate-changed`, `kerberos-tickets-invalidated`) carry no `sub_id`. They reach only streams that request them. | [SSF 1.0](https://openid.net/specs/openid-sharedsignals-framework-1_0.html), the SET profile: a top-level `sub_id` is REQUIRED on every SSF event. | Same | — by design: each is about the issuer, not a subject. See [Shared Signals](shared-signals.md). |
| **Different.** A complex stream subject matches an event only when at least one member is defined in both. So a `{ device }` subject does not match session events that name no device. | SSF 1.0, stream subject matching: a complex subject matches when every member defined in both is identical. | Same | — by design: otherwise a device subject would match every session event of every person. |
| **Weaker.** A receiver (`POST /ssf/receive`, the console and portal receivers, a federation partner's push or poll) records a SET whose signature does not verify and answers 202. Nothing acts on it. | [RFC 8935](https://www.rfc-editor.org/rfc/rfc8935) section 2.3: a SET that fails validation SHALL be answered 400, for example `invalid_key`. [RFC 8936](https://www.rfc-editor.org/rfc/rfc8936) reports the same through `setErrs`. | Refused, 400 `invalid_key` | `ssf.receiveRequireSignature`, default `false`. See [Signals received](signals-received.md). |
| **Different.** A person with no `mail` is named in automatic RISC and CAEP event subjects by an invented `@example.com` address. | [RFC 9493](https://www.rfc-editor.org/rfc/rfc9493) section 3.2.2: the `email` format identifies the subject by their email address. | The entry's real value or `iss_sub` is used. RISC's identifier events are not sent without a real value. | `global.mode` |

Events about an application are sent under SSF 1.0's complex subject with an
`application` member (`opaque`, the client_id), and a service account is a
person entry, named as one (#221). RISC 1.0 section 2.8's opt-out is not
applied to an application or a service account — neither has an account holder
to make the choice — and the register and the portal say so.

## X.509 certificates and revocation

| What iya-sts does by default | What the specification says | Product mode | Changing it |
|---|---|---|---|
| **Weaker.** Revocation is soft-fail. A presented certificate whose CRL or OCSP status cannot be established is accepted and reported; only a certificate known to be revoked is refused. A certificate from another CA that names no CRL and no OCSP responder is also accepted. | [RFC 5280 section 6.1.3](https://www.rfc-editor.org/rfc/rfc5280#section-6.1.3), item (a)(3): path processing checks that the certificate is not revoked. Section 6.3.3 returns UNDETERMINED when the status cannot be found, and leaves the treatment to local policy. | Hard-fail: an undetermined status is refused, and so is a CA-issued certificate that can never be revoked. | `pki.revocationCheck` and `pki.revocationRequireDistributionPoint`, both default `auto` (soft in development, hard in product). See [PKI](pki.md). |

## ACME, EST and SCEP

| What iya-sts does by default | What the specification says | Product mode | Changing it |
|---|---|---|---|
| **Different.** ACME offers none of the standard challenges (`http-01`, `dns-01`, `tls-alpn-01`, and `email-reply-00` for email). An authorization is `valid` at `newOrder`, with one private challenge type, `sts-entry-binding-01`. An identifier is issued only if it is registered on the directory entry the account is bound to; any other identifier is refused with `rejectedIdentifier`. | [RFC 8555 section 8](https://www.rfc-editor.org/rfc/rfc8555#section-8): the client proves control of an identifier by completing a challenge; no single challenge type is mandatory. [RFC 8823 section 3](https://www.rfc-editor.org/rfc/rfc8823#section-3): an `email` identifier is validated with `email-reply-00`. | Same. | — by design: no challenge dials an address, and the directory decides ownership. See [ACME](acme.md). |
| **Different.** The certificate is built from the order and the directory entry, not copied from the CSR. It always carries a `urn:sts:person:` or `urn:sts:application:` URI subjectAltName that the order did not request, and its subject is `CN=<first host or entry>, UID=<entry>, O=<organisation>`. | [RFC 8555 section 7.4](https://www.rfc-editor.org/rfc/rfc8555#section-7.4): the server MUST NOT issue a certificate with contents other than those requested. | Same. | — by design: every certificate names exactly one directory entry. EST and SCEP do the same, and their specifications let the CA decide. |

## SPIFFE

| What iya-sts does by default | What the specification says | Product mode | Changing it |
|---|---|---|---|
| **Weaker.** The Workload API is served over TCP on `0.0.0.0:8092`. TCP callers are not attested, and an entry that selects only the transport is issued to anyone who connects. | [SPIFFE Workload Endpoint section 3](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_Endpoint.md): TCP MUST NOT be used unless the network lets the server strongly authenticate the workload by source address. Section 2: the endpoint SHOULD NOT be exposed to more than one host. | TCP is not bound unless `spiffe.workloadTcpSourceAuthenticated` is on and `spiffe.grpcHost` names an address. Entries that select nothing identifying are refused. | `spiffe.workloadPort`, default `8092`. `spiffe.grpcHost`, default `0.0.0.0`. `spiffe.workloadTcpSourceAuthenticated`, default `false`. See [SPIFFE](spiffe.md). |
| **Weaker.** A caller that matches no entry is given an invented entry, `spiffe://<trust domain>/workload`, and an SVID for it. | [SPIFFE Workload API section 5.2.1](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md): an SVID goes only to a workload that is entitled to it; others SHOULD get `PermissionDenied`. | Nothing is invented. The caller is refused `PermissionDenied`. | `spiffe.autoCreateEntries`, default `true`. |

## The persistence store and the cluster

| What iya-sts does by default | What the specification says | Product mode | Changing it |
|---|---|---|---|
| **Weaker.** With `persistence.mode` = `postgres`, TLS to the database encrypts but does not verify the server's certificate. `sslmode=verify-ca` or `verify-full` in the URL is removed and does not turn verification on. (The connection itself is always TLS: a URL with no `sslmode` is `require`, and `disable` or `allow` is refused at start — #273.) | [RFC 9525 section 6](https://www.rfc-editor.org/rfc/rfc9525#section-6): a TLS client verifies the server's identity. libpq's `verify-ca` and `verify-full` mean the certificate (and, for `verify-full`, the host name) is checked. | Same. | `persistence.databaseTlsRejectUnauthorized`, default `false`. The default store is `memory`, which has no connection. See [Encryption at rest](encryption-at-rest.md). |

No departures were found in the cluster. It is off unless product mode runs on postgres.

## Risk scoring and device registration

No default here departs from a specification. Risk decisions are only recorded
in development (`risk.enforceInDevelopment`, `false`), and development registers
device keys without attestation; neither behaviour is governed by a
specification. A registered device's `unknown` compliance is sent over CAEP as
`not-compliant`, because CAEP defines only two values. Two attestation gaps are
tracked: Google's Android attestation revocation list is not consulted (open:
#256), and TPM CSR attestation freshness is recorded but not required (open:
#257).

## Related

* [What is not checked](what-is-not-checked.md): the full line between
  development and product mode.
* [Security profiles: RFC 9700, OAuth 2.1, DPoP, mTLS](oauth-security.md),
  and `GET /oauth2/rfc9700` on a running service.
* [Conformance and interoperability suites](conformance.md): what the
  official suites check, and the exceptions they record.
* [Configuration](configuration.md): every setting named above, with its
  environment variable.
