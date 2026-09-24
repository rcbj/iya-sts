---
title: WS-Trust
---

# WS-Trust

iya-sts is a **WS-Trust security token service**: a SOAP
`RequestSecurityToken` endpoint that speaks
[WS-Trust 1.4](https://docs.oasis-open.org/ws-sx/ws-trust/v1.4/ws-trust.html),
[1.3](https://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html)
and the pre-standard 1.0 (2004/04) and February 2005 namespaces, issuing SAML
2.0 assertions and JWTs. Every trust realm has its own STS, with its own token
issuer and signing key.

One parser answers all four versions: the elements are read by local name with
the namespace ignored, and the response is written in whatever trust namespace
the request used.

## Features

### Endpoints

| Path | What it is |
|---|---|
| `POST /sts` | the `RequestSecurityToken` endpoint, SOAP 1.1 or SOAP 1.2 |
| `GET /sts` | what the endpoint is, the issuer it uses, and whether that disagrees with `saml.issuer` |
| `GET /sts/cert` | the signing certificate, the key a relying party verifies an assertion with |

In a trust realm every path is under `/realm/{id}`. The full, current list is
at `/admin/sts-metadata`.

The SOAP version is taken from the envelope's namespace (or, failing that, the
content type: `text/xml` is SOAP 1.1) and the response uses the same one.

### The four operations

The operation is the last path segment of `wst:RequestType`, so any version's
namespace works:

| `RequestType` | Answer |
|---|---|
| `Issue` | an RSTR Collection carrying a freshly minted, signed token, its `wst:Lifetime`, the `KeyType` asked for (Bearer by default) and a reference to the token |
| `Renew` | an RSTR carrying a fresh token for the subject of the `RenewTarget` |
| `Validate` | an RSTR carrying `wst:Status` — `valid` when the `ValidateTarget` holds a token, `invalid` when it holds none |
| `Cancel` | an RSTR carrying `wst:RequestedTokenCancelled` |

**Each version is answered in its own schema's elements.** The 2004/04
namespace has no collection of one response, no `RequestedAttachedReference`
and no Cancel, so there an `Issue` is answered with the RSTR itself, the
reference is `wst:RequestedTokenReference`, and a `Cancel` is refused with a
`wst:InvalidRequest` fault. Every answer, in every version, validates against
its version's published OASIS schema.

**Every operation authenticates the requester first**, above the choice of
operation, so a credential refused for an Issue is refused for a Validate or a
Cancel too.

### Token types

| `TokenType` | What is issued |
|---|---|
| `urn:ietf:params:oauth:token-type:jwt` | a JWT signed with `wstrust.jwtAlgorithm` |
| anything else, or none | a signed SAML 2.0 assertion, the default |

**The SAML assertion** comes from the same builder the
[SAML 2.0 identity provider](saml2-sso.md) uses, so its issuer is `saml.issuer`,
its audience is the `AppliesTo`, its validity window is widened by
`saml.clockSkewS`, and it carries the SAML 2.0
[custom SAML attributes](saml2-sso.md#custom-saml-attributes). Its
`AuthnContextClassRef` names the credential that was presented:
`PasswordProtectedTransport` for a UsernameToken, `PreviousSession` for an
assertion, `unspecified` for a delegation or nothing. The `wsu:Lifetime` around
it states the lifetime without the skew.

**The JWT** has `iss` `wstrust.issuer`, a `jti`, and the realm key's `kid` in
its header (published at `/oauth2/jwks`). Its `sub` is the person's stable
subject, `urn:uuid:<entryUUID>`; a JWT for somebody the directory does not hold
is refused with a SOAP Fault rather than issued with a bare name. By default the
header also carries `x5u`, the address of the signing key's certificate chain
(`wstrust.jwtCertificateHeader`).

### Lifetime

With no `wst:Lifetime` the token lives `wstrust.tokenLifetimeMin`. A requested
lifetime is honoured up to `wstrust.maxTokenLifetimeMin` and **clamped** beyond
it, in both modes; the RSTR's own `wst:Lifetime` states what was actually
issued.

### Credentials

The requester's credential is looked for in `wsse:Security`, never inside an
element that holds somebody else's token:

* a **WS-Security UsernameToken** — a username and a password;
* a **SAML assertion** in the security header;
* a request with **no credential** (development only — see below).

The reserved password `invalid` is always refused, so a negative test has
something to fail on. A successful authentication is recorded like any other
sign-in — the audit log, the person's directory entry — and starts a session in
the shared session store; an assertion credential's session carries no `pwd`
method.

### Delegation: `OnBehalfOf` and `ActAs`

* **`wst:OnBehalfOf`** (WS-Trust 1.3) asks for a token **about** the named
  subject: impersonation, where the relying party sees an ordinary sign-in.
* **`wst14:ActAs`** (WS-Trust 1.4) asks for a token about the subject with the
  requester **acting**: delegation.

Both are recorded as such on `/admin/delegation`, with the requester as the
intermediary and the application registered for the `AppliesTo` as the target,
so a chain of hops (a web application, then an ESB, then a back end) draws as
one chain. The token inside `OnBehalfOf` is recorded as consumed, so
`/admin/tokens` can follow a lineage from one exchange to the next. A request
carrying both elements is attributed to `OnBehalfOf`. **A delegation starts no
session** — the person named was not there.

**Who may act for whom** is decided by the delegation policy (#108), from
attributes on application entries: the requester's `appAllowedToDelegateTo`,
or the target's `appAllowedToActOnBehalfOf`, must allow the `AppliesTo`;
`OnBehalfOf` needs `appTrustedToImpersonate` on the requester as well; the
requester's `appDelegationSubjectGroup` narrows who it may act for; and a
person carrying `stsNotDelegated` or on the console roster is never delegated.
Only an **application** may delegate: the requester's name must be an
application entry's identifier (its credential may be kept on a service account
of the same name). In **product** mode a refusal is a SOAP Fault whose code is
WS-Trust 1.4 section 11's `wst:RequestFailed` — the SOAP 1.2 Subcode under
`soap:Sender`, or the SOAP 1.1 `faultcode`. In **development** the token is
issued and the act on `/admin/delegation` says what would have been refused.
The policy is listed at `GET /admin-api/delegation/policy`. An `ActAs` token
does not state in the assertion that a middle tier acted.

### The `AppliesTo`

The `AppliesTo` address is the token's audience, and it is resolved through the
application registry (`wstrustAppliesTo`, then `samlEntityId`) so that the
console names an application rather than a URL. That is a lookup, not a
permission: an unregistered address is still answered. The issuance policy —
XACML, where it is configured — can refuse a token for a subject and audience
with a SOAP Fault.

### Encryption, as a test control

`POST /sts?encrypt=1` (**not part of WS-Trust**) encrypts the SAML assertion to
the certificate in the request's own WS-Security signature (`X509Certificate`),
with the algorithms `saml2.encryptionAlgorithm` and
`saml2.keyTransportAlgorithm` answer for the `AppliesTo`. A request with no
such certificate, or one that cannot be encrypted to, is answered in clear in
development and refused in product.

### Not implemented

Request signatures are not verified; `Validate` reports whether a token is
**present**, not whether it verifies; `Cancel` recalls nothing already issued;
refusals other than the delegation policy's send a generic SOAP Fault rather
than one of section 11's `wst:` codes; and a SAML assertion presented as a
credential is trusted only when **this** STS signed it — there is no register
of foreign issuers.

## Development and product mode

| | Development | Product |
|---|---|---|
| A request with no credential | a token for the literal subject `anonymous` (a Renew for whoever its `RenewTarget` names) | refused, with a SOAP Fault naming what to present |
| A UsernameToken password | any password but `invalid` | verified against the person's stored `userPassword`; a person who holds or must hold a second factor is refused their own password with the same fault a wrong one gets, and presents an [app password](authentication.md#the-password-only-doors-and-app-passwords) scoped to `wstrust` |
| A SAML assertion as the credential | believed | must verify against this realm's own signing certificate (`/sts/cert`) and be inside its `Conditions` |
| `OnBehalfOf` / `ActAs` | needs no requester credential | needs the requester's own credential, and the inner token must be an assertion this STS signed |
| Who may act for whom | the delegation policy is asked and the act says what would have been refused; the token is issued | the requester must be an application whose attributes allow the `AppliesTo` (and `appTrustedToImpersonate` for `OnBehalfOf`), or a `wst:RequestFailed` fault |
| An assertion with no NameID | subjects such as `saml-subject` are invented | refused |
| `?encrypt=1` that cannot encrypt | plaintext, logged | refused |

The lifetime clamp, the authentication context, the JWT's `jti` and `kid`, and
"a delegation starts no session" hold in **both** modes. See
[What is not checked](what-is-not-checked.md).

## Configuration

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `wstrust.issuer` | `STS_WSTRUST_ISSUER` (or `STS_ISSUER`) | `urn:wstrust:mock:sts` | yes | The `iss` of an issued JWT and the issuer named on `GET /sts`; a SAML token carries `saml.issuer` instead. |
| `wstrust.tokenLifetimeMin` | `STS_WSTRUST_TOKEN_LIFETIME_MIN` | `60` | yes | Token lifetime when the RST carries no `wst:Lifetime`. |
| `wstrust.maxTokenLifetimeMin` | `STS_WSTRUST_MAX_TOKEN_LIFETIME_MIN` | `1440` | yes | The ceiling a requested `wst:Lifetime` is clamped to, in both modes. |
| `wstrust.jwtAlgorithm` | `STS_WSTRUST_JWT_ALGORITHM` | `RS256` | yes | The JWT's `alg`: `RS256`–`RS512`, `PS256`–`PS512`, `ES256`–`ES512` or `EdDSA`. |
| `wstrust.jwtCertificateHeader` | `STS_WSTRUST_JWT_CERTIFICATE_HEADER` | `x5u` | yes | Whether a JWT names its signing chain: `x5u` (an address), `x5c` (inline), `both` or `none`. |

A SAML token is shaped by the shared `saml.*` settings and the SAML 2.0
assertion settings — see the
[SAML 2.0 configuration](saml2-sso.md#configuration) and
[the assertion settings](saml2-sso.md#the-assertion-settings-every-application-inherits);
`?encrypt=1` uses `saml2.encryptionAlgorithm` and
`saml2.keyTransportAlgorithm`. This table is a copy; the live source is
`/admin/wstrust` and `GET /admin-api/config`. See
[Configuration](configuration.md) for how a value is resolved; a setting is
changed on `/admin/wstrust` or with `POST /admin-api/config/set`.

## Design decisions

* **One parser for every version.** Matching elements by local name lets one
  `RequestSecurityToken` reader serve 1.0 through 1.4, and the response echoes
  the request's namespace so a client of any version is answered in its own.
* **Authenticate before choosing the operation.** Validate and Cancel once
  answered without authenticating anybody; every operation now authenticates
  first, so every requester is recorded and `invalid` is refused everywhere.
* **A credential is read only from the requester's own place.** A document
  carrying an `OnBehalfOf` token holds several identities, and the one inside
  somebody else's token is not the requester.
* **`OnBehalfOf` and `ActAs` are two mechanisms.** The token issued is the same,
  but impersonation and delegation are different facts, and the delegation page
  draws them differently.
* **A requested lifetime is a request.** WS-Trust 1.4 section 4.1 makes the
  issued lifetime the STS's decision; an unbounded honour would let a caller
  mint a year-long bearer token in any mode.
* **The authentication context names the real credential.** Calling every
  token a password sign-in, including an anonymous one, misled relying parties
  that read it.
* **A delegation starts no session**, because the session would be in the name
  of somebody who was not there.
* **The smallest honest answer to "which issuer is trusted".** In product a
  SAML credential must be one this STS signed — the key it already publishes —
  rather than any assertion at all.
* **Two issuer settings, and disagreement is reported rather than
  reconciled.** `wstrust.issuer` names the STS and `saml.issuer` the signer of
  an assertion; `GET /sts` and the startup log say when they differ.
* **A JWT needs a directory entry.** A bare name as `sub` would be inherited by
  a person created later under that name.

## In the running service

* **Protocols → WS-Trust** (`/admin/wstrust`): the STS's endpoint and its own
  settings. What an assertion contains is on the SAML pages —
  [SAML assertions](saml2-sso.md#the-assertion-settings-every-application-inherits)
  and [Custom SAML attributes](saml2-sso.md#custom-saml-attributes).
* **`/admin/delegation`** draws `OnBehalfOf` and `ActAs` chains;
  **`/admin/tokens`** follows what one exchange produced into the next.
* `GET /admin-api/wstrust` returns the same settings; the full API is in
  `/admin-api/openapi.json`.
* `GET /sts` describes the endpoint live. Failures are recorded under
  `STS-WSTRUST-NNNN` codes — see [Error codes](error-codes.md).

## Related

* [SAML 2.0 Web Browser SSO](saml2-sso.md) — the assertion builder, assertion
  settings and custom attributes WS-Trust shares
* [WS-Federation](ws-federation.md), the browser profile that carries an RSTR
* [SAML 1.1 browser profiles](saml11.md)
* [SAML 2.0 assertions](saml-assertions.md) — presenting an assertion at the
  OAuth token endpoint (RFC 7522)
* [OAuth 2.0 and OpenID Connect](oauth-oidc.md) — RFC 8693 token exchange, the
  other way this service exchanges one token for another
* [Accepted tokens](accepted-tokens.md), [PKI](pki.md),
  [Trust realms](trust-realms.md), [What is not checked](what-is-not-checked.md),
  [Configuration](configuration.md)
