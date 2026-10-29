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
| `GET /sts` | what the endpoint is, and the issuer every token it issues names: the realm's OAuth 2.0 issuer (#523) |
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
| `http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1` or `urn:oasis:names:tc:SAML:1.0:assertion` | a signed SAML 1.1 assertion, from the SAML 1.1 builder, with the application's SAML 1.1 attributes (#487). An ActAs in SAML 1.1 names who acted in a `delegates` attribute (namespace `urn:iya:sts:delegation`, one value per party, earliest first), because SAML 1.1 has no Delegation Restriction |
| anything else, or none | a signed SAML 2.0 assertion, the default |

**The SAML assertion** comes from the same builder the
[SAML 2.0 identity provider](saml2-sso.md) uses; its issuer is the realm's OAuth
2.0 issuer, the `iss` a JWT from the same request carries (#523),
its audience is the `AppliesTo`, its validity window is widened by
`saml.clockSkewS`, and it carries the SAML 2.0
[custom SAML attributes](saml2-sso.md#custom-saml-attributes). Its
`AuthnContextClassRef` names the credential that was presented:
`PasswordProtectedTransport` for a UsernameToken, `PreviousSession` for an
assertion, `TLSClient` for a TLS client certificate, `X509` for a
WS-Security signature over the request, `unspecified` for a
delegation or nothing. The `wsu:Lifetime` around
it states the lifetime without the skew.

**The JWT** has `iss` the realm's OAuth 2.0 issuer, the one
`/.well-known/oauth-authorization-server` publishes and `GET /sts` names as
`JWT issuer:`. It also has a `jti`, and the realm key's `kid` in its header
(published at `/oauth2/jwks`). Its `sub` is the person's stable
subject, `urn:uuid:<entryUUID>`; a JWT for somebody the directory does not hold
is refused with a SOAP Fault rather than issued with a bare name. By default the
header also carries `x5u`, the address of the signing key's certificate chain
(`wstrust.jwtCertificateHeader`).

The JWT's structure and claims follow
[RFC 9068](https://www.rfc-editor.org/rfc/rfc9068) and
[RFC 8693](https://www.rfc-editor.org/rfc/rfc8693):

* its header carries `typ: at+jwt`;
* it carries `iss`, `sub`, `aud` (the `AppliesTo`), `iat`, `exp` (the
  lifetime the RSTR's `wst:Lifetime` states) and `jti`;
* `client_id` is the application the requester authenticated as;
* `act` (for `ActAs`) has the shape this service's OAuth tokens give it:
  * the current actor outermost;
  * each entry with `iss`;
  * an application named `urn:sts:client:<client_id>` in RFC 9700 mode and
    by its bare client_id otherwise.

Some claims are left out on purpose:

* **No `client_id` for a person's own token.** A person who asks for a token
  about themselves with their own UsernameToken has no client.
* **No `scope` unless the application configures it.** An RST asks for
  none. The AppliesTo's application may list OAuth 2.0 scopes on
  `wstrustJwtScope` (Configuration → WS-Trust). They are judged as an
  access token's are, with the application as the client: its
  `oauthAllowedScope` in product, and the issuance policy. What is left off
  is audited.
* **No `auth_time` or `acr`.** RFC 9068 makes them optional. **`amr`** is
  carried on a token about the requester itself (#1046): `["pwd"]` for a
  UsernameToken, `["swk"]` for a TLS client certificate or a signed request
  (#521). A delegated token,
  and one issued on an assertion or a JWT, carries none.

`iss` is the realm's OAuth issuer, so RFC 9068 section 4's check against the
authorization server's metadata holds (#480). The RST and RSTR are unchanged: the `wst:TokenType` answered is still
`urn:ietf:params:oauth:token-type:jwt`.

### Lifetime

With no `wst:Lifetime` the token lives `wstrust.tokenLifetimeMin`. A requested
lifetime is honoured up to `wstrust.maxTokenLifetimeMin` and **clamped** beyond
it, in both modes; the RSTR's own `wst:Lifetime` states what was actually
issued.

### Credentials

The requester's credential is looked for in `wsse:Security`, never inside an
element that holds somebody else's token:

* a **WS-Security UsernameToken** — a username and a password. The username
  is a person's (a service account is a person), or, where no person has that
  name, an **application's** identifier or client_id, with one of the
  application's client secrets as the password;
* a **SAML assertion** (SAML 2.0 or SAML 1.1) in the security header;
* a **JWT** this service issued, in the `wsse:BinarySecurityToken` an RSTR
  hands one back in (ValueType `urn:ietf:params:oauth:token-type:jwt`);
* a **WS-Security signature over the request** (#521), made with a
  message-signing certificate — see below. It is asked first;
* the **TLS client certificate** on the connection, when `wsse:Security`
  carries none of the above (#1046) — see below;
* a request with **no credential** (development only — see below).

#### The TLS client certificate

On the main port with `global.https` on, a client may present a TLS client
certificate at the handshake. It is the requester's credential, in both
modes, when all of these hold:

* it verified against the client truststore;
* this realm issued it to a person or an application — a TLS client
  certificate from the user portal (*Signing key*) or an application's
  *Credentials* section, or one enrolled over [ACME, EST or SCEP](pki.md);
  the person or application it names is the requester — **or** it is from an
  outside certificate authority in the truststore and is stored byte for
  byte in `userCertificate` on exactly one person's or application's entry,
  which is the requester ([TLS](tls.md#a-certificate-from-an-outside-certificate-authority));
* it is not revoked, and its holder's record still lists it;
* for a person, the account is not disabled.

A certificate that verified and fails one of these is refused with
`wst:FailedAuthentication` (`STS-WSTRUST-0034` to `0037`) rather than
treated as no credential, and so is one from an anchor somebody added at
`/admin/tls/trust` that is stored on no entry (`STS-WSTRUST-0038`) or on
more than one (`STS-WSTRUST-0039`); its common name and subject are never
read. One that did not verify is ignored. A UsernameToken, an assertion or a JWT in the message
always wins: the certificate is asked only when the message carries none.

The token issued says a certificate was used: `TLSClient` as a SAML 2.0
assertion's `AuthnContextClassRef`, `urn:ietf:rfc:2246` as a SAML 1.1
`AuthenticationMethod`, and `amr` `["swk"]` in a JWT. A person's certificate
starts a session with method `swk`, as `GET /tls/sign-in` does; an
application's starts none. `wstrust.acceptClientCertificate` turns the
credential off.

```bash
curl --cert alice.pem --key alice-key.pem --cacert root.pem \
  -H 'Content-Type: application/soap+xml' --data @rst.xml \
  https://sts.example.com:8081/sts
```

where `rst.xml` is an `Issue` with an empty `wsse:Security` header (or none).

#### A signed request

A requester may sign its RST instead of presenting a password or a token
(WS-Security 1.1 with the X.509 Token Profile 1.1, #521). The `ds:Signature`
is a child of the one `wsse:Security` header and must cover, by `wsu:Id`,
**the** SOAP `Body` (the Envelope's own child) and **the** `wsu:Timestamp` of
that header. The certificate is named by the signature's
`wsse:SecurityTokenReference`, in any of four forms:

* a `wsse:Reference` to an X.509 v3 `wsse:BinarySecurityToken` in the same
  header, which carries the certificate;
* a `wsse:KeyIdentifier` with the certificate's SHA-1 thumbprint
  (`#ThumbprintSHA1`);
* a `wsse:KeyIdentifier` with its Subject Key Identifier
  (`#X509SubjectKeyIdentifier`);
* an `ds:X509IssuerSerial`.

The last three find a certificate this realm's **message-signing** Issuing CA
issued; a certificate stored on an entry is sent in a BinarySecurityToken.

**Which certificates count.** Each authenticates exactly one person or
application, and nothing else does:

* a **message-signing certificate** this realm issued — from the realm's
  `message-signing` Issuing CA ([PKI](pki.md)), `digitalSignature` only, the
  holder's `urn:sts:person:` or `urn:sts:application:` name. An administrator
  issues one to a person on `/admin/users` or to an application on
  `/admin/applications` (and through `/admin-api`); the private key is handed
  over once;
* a certificate from **any other authority stored byte for byte in
  `userCertificate`** on exactly one person's or application's entry
  ([TLS](tls.md#a-certificate-from-an-outside-certificate-authority) says how
  to store one), whose key usage includes `digitalSignature`.

A TLS client certificate is **not** a message-signing credential, and a
message-signing certificate signs nobody in over TLS. A certificate nobody
holds authenticates nobody: its common name and subject are never read.

**What product mode checks**, each refusal with its own
[error code](error-codes.md):

| Check | Refused as |
|---|---|
| One signature; unique ids; exclusive XML canonicalization; the Body and the Timestamp covered; an algorithm this service verifies (SHA-1 only with `saml.allowSha1Signatures`, never in product); a key reference it reads | `STS-WSTRUST-0040`, `wst:FailedAuthentication` (`wst:AuthenticationBadElements` when the Body or the Timestamp is not covered) |
| The reference finds a certificate | `0041` |
| The certificate is a message-signing identity of this realm, valid now; stored on exactly one entry | `0042`; `0043` stored on none; `0044` on two |
| The signature verifies with that certificate, and no signed part was altered | `0045` |
| Every part of the request (the `RequestSecurityToken`, its `RequestType`, `AppliesTo`, `OnBehalfOf` and the rest) is inside the signed Body | `0046` |
| The Timestamp has a `Created` and an `Expires`; `Created` is not ahead of the clock and `Expires` not behind it, each by `oauth2.clockSkewS` | `0047`; `0048`, `wst:ExpiredData`, when expired |
| The certificate is not revoked: the register for one this realm issued, the certificate's own OCSP responder and CRL for a stored one, under `pki.revocationCheck` | `0049` |
| The request was not accepted before: its signature is spent once in the [used-assertion history](oauth-oidc.md) until the Timestamp expires | `0050`; `0051`, `wst:RequestFailed`, when the history cannot be asked |
| A person's account is not disabled | `0052` |

A replay is refused only after a request is answered: a request refused for
some other reason may be signed again and sent.

**Beside another credential.** The signature authenticates. A UsernameToken,
an assertion or a JWT in the same header is still checked (a password is
verified in product) and must name the same person or application, or the
request is refused (`STS-WSTRUST-0053`) in every mode.

**What the token says.** `X509` as a SAML 2.0 `AuthnContextClassRef`,
`urn:oasis:names:tc:SAML:1.0:am:X509-PKI` as a SAML 1.1
`AuthenticationMethod`, and `amr` `["swk"]` in a JWT. A person's signature
starts a session; an application's starts none. With `OnBehalfOf` or `ActAs`
the signer is the requester the [delegation policy](delegation.md) asks about.

**In development** the certificate is read and believed, as a UsernameToken
is: the signature's structure and its certificate reference are still read,
and the holder is whoever the certificate maps to, else the name in its
`urn:sts:` subjectAltName, else its common name. The signature value, the
Timestamp, revocation and replay are not checked, and the authentication
row says so.

A client builds the request with any WS-Security 1.1 stack (Apache WSS4J,
Metro, .NET's `SecurityBindingElement`), configured to sign the Body and the
Timestamp with exclusive canonicalization and an X.509 token. The key and
certificate come from the PKCS#12 the console hands over.

Any of the three token types can be the credential, the token inside
`OnBehalfOf` / `ActAs`, and the token issued, in any combination. So a
middle tier that has no person entry can first ask, with its application's
client secret, for a token about itself (with its own identifier as the
`AppliesTo`), and then present that token as its credential when it asks
for a token about somebody else. A token issued to an application is about
the application: a JWT's `sub` is `urn:sts:client:<client_id>` where the
token endpoint names clients that way (RFC 9700 mode, which product mode
implies), and the bare client_id otherwise.

In product mode a token presented as the credential must be addressed to
its holder — an audience the holder's application registers, which is what
a token a tier asked for itself carries — or to this identity provider: the
WS-Trust issuer name `GET /sts` reports, the realm's SAML entityID, the
realm's OAuth issuer, or the `/sts` address. A person who wants a token to
present as their own credential asks for one with one of those names as the
`AppliesTo`; product issues for them as it does for a registered
application.

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

The token inside either element is one this STS issued: a SAML 2.0
assertion, or a JWT in the `wsse:BinarySecurityToken` an RSTR carries one
in. In product it must verify with this realm's key, be unexpired, carry
this STS's issuer and name a person in the directory. Its audience is S, and
a JWT's `act` supplies the earlier delegates.

Both are recorded as such on `/admin/delegation`, with the requester as the
intermediary and the application registered for the `AppliesTo` as the target,
so a chain of hops (a web application, then an ESB, then a back end) draws as
one chain. The token inside `OnBehalfOf` is recorded as consumed, so
`/admin/tokens` can follow a lineage from one exchange to the next. A request
carrying both elements is attributed to `OnBehalfOf`. **A delegation starts no
session** — the person named was not there.

**Who may act for whom, and as what**, is decided by the issuance policy, with
the same controls as the OAuth 2.0 token exchange and Kerberos — see
[Delegation and impersonation](delegation.md). The requester is the actor, the
delegated assertion's `Audience` is the application it was issued for, and the
`AppliesTo` is the target; `ActAs` asks for delegation and `OnBehalfOf` for
impersonation, and both in one request is `wst:InvalidRequest` in every mode.
In **product** mode a refusal is a SOAP Fault whose code is WS-Trust 1.4
section 11's `wst:RequestFailed` — the SOAP 1.2 Subcode under `soap:Sender`, or
the SOAP 1.1 `faultcode`. In **development** the token is issued and the act on
`/admin/delegation` says what would have been refused.
The policy is listed at `GET /admin-api/delegation/policy`. An `ActAs` token
does not state in the assertion that a middle tier acted.

### The `AppliesTo`

The `AppliesTo` address is the token's audience, and it is resolved through the
application registry (`wstrustAppliesTo`, then `samlEntityId`) so that the
console names an application rather than a URL. In **development** that is a
lookup, not a permission: an unregistered address, and a request with no
`AppliesTo` at all, are still answered, and the address is filed in the
register. In **product** a token is issued only for a **registered**
application — one an administrator, RFC 7591, an OpenID Federation or this
service's own seeding put in the register; an address the register merely
recorded from an earlier request is not one. An `AppliesTo` that resolves to
no registered application is refused with `wst:InvalidScope`, and a request
with no `AppliesTo` with `wst:InvalidRequest`, for every token type and for
`OnBehalfOf` / `ActAs`, before the requester is authenticated or anything is
recorded (#496). The issuance policy — XACML, where it is configured — can
refuse a token for a subject and audience with a SOAP Fault.

### Encryption, as a test control

`POST /sts?encrypt=1` (**not part of WS-Trust**) encrypts the SAML assertion to
the certificate in the request's own WS-Security signature (`X509Certificate`),
with the algorithms `saml2.encryptionAlgorithm` and
`saml2.keyTransportAlgorithm` answer for the `AppliesTo`. A request with no
such certificate, or one that cannot be encrypted to, is answered in clear in
development and refused in product.

### Not implemented

A signed request's certificate is found by thumbprint, issuer and serial or
Subject Key Identifier only among the certificates this realm issued; a
stored one is sent in a `BinarySecurityToken`. Only a signature over the
request is read: a signed or encrypted response is not offered, and
`?encrypt=1` reads its recipient from an `X509Certificate`, not a
`BinarySecurityToken`. `Validate` reports whether a token is
**present**, not whether it verifies; `Cancel` recalls nothing already issued;
and a SAML assertion presented as a credential is trusted only when **this**
STS signed it — there is no register of foreign issuers.

### Faults

Every refusal is a SOAP Fault carrying one of WS-Trust 1.4 section 11's fault
codes, in the request's own trust namespace: on SOAP 1.1 it is the
`faultcode`, and on SOAP 1.2 it is the `Subcode` under `soap:Sender`.

| Refusal | Fault code |
|---|---|
| The body is not well-formed XML | `wst:InvalidRequest` |
| An `AppliesTo` that resolves to no registered application (product) | `wst:InvalidScope` |
| No `AppliesTo`, or an empty one, on a request that issues (product) | `wst:InvalidRequest` |
| The requester's credential is incomplete, wrong, or an assertion or JWT that does not verify, is not yet valid, names nobody or is addressed neither to its holder nor to this IdP (product); no credential at all (product); a delegation with no requester credential (product); a signed request refused for its signature, certificate or a replay (see [A signed request](#a-signed-request)) | `wst:FailedAuthentication` |
| A signed request whose signature does not cover the Body or the Timestamp | `wst:AuthenticationBadElements` |
| An assertion or a JWT, as the credential or inside `OnBehalfOf` / `ActAs`, that has expired; a signed request whose Timestamp has expired (product) | `wst:ExpiredData` |
| The token inside `OnBehalfOf` / `ActAs` is not an assertion or a JWT this STS issued, or does not verify, is not yet valid or names nobody (product) | `wst:InvalidRequest` |
| Both `OnBehalfOf` and `ActAs`; `Cancel` in WS-Trust 2004/04; `?encrypt=1` with no recipient certificate (product) | `wst:InvalidRequest` |
| The issuance policy refuses the token or the delegation; a JWT about somebody the directory does not hold; `?encrypt=1` to a certificate that cannot be used (product); a delegation about a person in another cell that cannot be fetched | `wst:RequestFailed` |

A failure of the service itself, not of the request, is `soap:Receiver` (SOAP
1.2) or `soap:Server` (SOAP 1.1), with no `wst:` code. `Validate` with no token
to validate is not a fault: it answers `wst:Status` `invalid`. The fault never
says whether a username or a password was wrong. Each refusal's error code is
in [Error codes](error-codes.md).

## Development and product mode

| | Development | Product |
|---|---|---|
| The `AppliesTo` | any address, or none; the address is filed in the register | a registered application only, or a `wst:InvalidScope` fault; none is a `wst:InvalidRequest` fault |
| A request with no credential | a token for the literal subject `anonymous` (a Renew for whoever its `RenewTarget` names) | refused, with a SOAP Fault naming what to present |
| A UsernameToken password | any password but `invalid` | verified against the person's stored `userPassword`; a person who holds or must hold a second factor is refused their own password with the same fault a wrong one gets, and presents an [app password](authentication.md#the-password-only-doors-and-app-passwords) scoped to `wstrust` |
| A UsernameToken naming an application | any password but `invalid` | one of the application's unexpired client secrets |
| A SAML assertion as the credential | believed | must verify against this realm's own signing certificate (`/sts/cert`) and be inside its `Conditions` |
| A TLS client certificate as the credential | the same as product: it must verify and be this realm's, for a person or an application; a refused one is a fault | as development |
| A signed request | its structure and certificate reference are read and the certificate's holder believed; the signature, Timestamp, revocation and replay are not checked | every check in [A signed request](#a-signed-request) |
| A JWT as the credential | believed | must verify with this realm's own key (`/oauth2/jwks`), be within its `exp`, carry the realm's OAuth issuer, and name a person or an application this realm holds |
| `OnBehalfOf` / `ActAs` | needs no requester credential | needs the requester's own credential, and the inner token must be an assertion or a JWT this STS signed |
| Who may act for whom | the issuance policy is asked and the act says what would have been refused; the token is issued | the policy must allow the act ([Delegation and impersonation](delegation.md)), or a `wst:RequestFailed` fault |
| An assertion with no NameID | subjects such as `saml-subject` are invented | refused |
| `?encrypt=1` that cannot encrypt | plaintext, logged | refused |

The lifetime clamp, the authentication context, the JWT's `jti` and `kid`, and
"a delegation starts no session" hold in **both** modes. See
[What is not checked](what-is-not-checked.md).

## Configuration

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `wstrust.tokenLifetimeMin` | `STS_WSTRUST_TOKEN_LIFETIME_MIN` | `60` | yes | Token lifetime when the RST carries no `wst:Lifetime`. |
| `wstrust.maxTokenLifetimeMin` | `STS_WSTRUST_MAX_TOKEN_LIFETIME_MIN` | `1440` | yes | The ceiling a requested `wst:Lifetime` is clamped to, in both modes. |
| `wstrust.jwtAlgorithm` | `STS_WSTRUST_JWT_ALGORITHM` | `RS256` | yes | The JWT's `alg`: `RS256`–`RS512`, `PS256`–`PS512`, `ES256`–`ES512` or `EdDSA`. |
| `wstrust.jwtCertificateHeader` | `STS_WSTRUST_JWT_CERTIFICATE_HEADER` | `x5u` | yes | Whether a JWT names its signing chain: `x5u` (an address), `x5c` (inline), `both` or `none`. |
| `wstrust.acceptClientCertificate` | `STS_WSTRUST_ACCEPT_CLIENT_CERTIFICATE` | `true` | yes | Whether the verified TLS client certificate on the connection authenticates a requester whose `wsse:Security` carries no credential (see [Credentials](#credentials)). |

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
* **One issuer, in every token** (#523). A SAML 2.0 or SAML 1.1 assertion's
  Issuer and a JWT's `iss` are the realm's OAuth 2.0 issuer, for every
  AppliesTo — the name SAML SSO and WS-Federation publish as their entityID.
  Who asked is named by the delegation itself (the last `del:Delegate`, the
  SAML 1.1 `delegates` attribute, the JWT's `act`), never by the Issuer. The
  issuer settings (`wstrust.issuer`, `saml.issuer`) are retired.
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
