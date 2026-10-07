---
title: GNAP
nav_order: 13
---

# GNAP

iya-sts is an **authorization server for the Grant Negotiation and
Authorization Protocol** ([RFC 9635](https://www.rfc-editor.org/rfc/rfc9635))
and speaks the **resource server connections** of
[RFC 9767](https://www.rfc-editor.org/rfc/rfc9767). Every trust realm has its
own, with its own grants, tokens, keys and settings.

Where OAuth 2.0 starts from a `client_id` and a redirect URI, GNAP starts from a
**key**. A client instance presents its key in the first request and proves it on
every request after. The grant is a **negotiation**: it can wait for a person,
be continued, be modified onto different access, and be revoked.

```
  client instance                     iya-sts                         resource owner
       │                                  │                                  │
       │  POST /gnap  (signed) ──────────▶│                                  │
       │  ◀── interact.redirect, continue │                                  │
       │                                  │◀── GET /gnap/interact/{id} ──────│
       │                                  │    sign in, /gnap/approve/{id}   │
       │  ◀──────────── finish URI ?hash=…&interact_ref=… ───────────────────│
       │  POST /gnap/continue/{grant} ───▶│                                  │
       │  ◀── access_token                │                                  │
       │                                  │                                  │
       │  GET /gnap/rs/resource  Authorization: GNAP <token>  (signed)       │
```

## Endpoints

| Path | Method | What it is |
|---|---|---|
| `/gnap` | POST | the grant endpoint (RFC 9635 section 2) |
| `/gnap` | OPTIONS | discovery (section 9) |
| `/{as}/gnap` | POST, OPTIONS | the same for a named authorization server profile |
| `/gnap/continue/{grant}` | POST · PATCH · DELETE | continue or poll · modify · revoke (section 5) |
| `/gnap/token/{handle}` | POST · DELETE | rotate, including client key rotation · revoke (section 6) |
| `/gnap/interact/{id}` | GET | the redirect interaction start (4.1.1) |
| `/gnap/app/{id}` | GET | the app interaction start (4.1.4) |
| `/gnap/code` | GET · POST | user code entry, and `user_code_uri` (4.1.2, 4.1.3) |
| `/gnap/approve/{id}` | GET · POST | the resource owner's approval page |
| `/.well-known/gnap-as-rs` | GET | resource server discovery (RFC 9767 section 3.1) |
| `/gnap/introspect` | POST | token introspection (RFC 9767 section 3.3) |
| `/gnap/resource` | POST | resource set registration (RFC 9767 section 3.4) |
| `/gnap/keys` | GET | the public keys that verify the self-contained token formats |
| `/gnap/zcap/controller` | GET | the controller document a zcap token's root capability names |
| `/gnap/biscuit/revocations` | GET | the revocation identifiers of revoked biscuit tokens (this service's own; see [revocation](#seeing-a-revocation-without-introspection)) |
| `/status-lists/access-tokens` | GET | the realm's access-token status list, shared with OAuth (see [revocation](#seeing-a-revocation-without-introspection)) |
| `/gnap/rs/resource` | GET · POST | a demonstration resource server |
| `/gnap/rs/spend` | POST | the demonstration resource server's operation that spends against a right's [limits](#limits) |

In a trust realm every path is under `/realm/{id}`.

## What is supported

Everything the two specifications define on the authorization server's side:

* **Interaction start modes:** `redirect`, `app`, `user_code`, `user_code_uri`.
  **Finish methods:** `redirect` and `push`, with the section 4.2.3 interaction
  hash in any Named Information hash method (`sha-256` by default).
* **Key proofing:** `httpsig` (RFC 9421 HTTP message signatures with an RFC
  9530 `Content-Digest`), `mtls` (pinned or held to a PKI — see
  [mutual TLS trust](#mutual-tls-trust)), `jwsd` and `jws`. **Key formats:** `jwk`,
  `cert`, `cert#S256`, and a key **reference** to a key registered on an
  application entry, including a shared symmetric key.
* **Grants:** single and multiple access tokens, `bearer` tokens, subject
  identifiers in the RFC 9493 formats (the `opaque` one per client),
  `id_token` and `saml2` assertions, `instance_id`, user references, polling
  with `wait` and `too_fast`, modification, revocation, a trusted client that
  needs no interaction, and a grant lifetime separate from the token
  lifetime.
* **Token management:** rotation, revocation, and client **key rotation**
  proved by both keys.
* **RFC 9767:** discovery, introspection, resource set registration, and
  **token derivation** — a resource server sends `existing_access_token` to the
  grant endpoint and receives a downstream token with no more access, naming
  it in an `act` chain (see [acting for somebody else](#acting-for-somebody-else)).
* **Error responses:** every error code of RFC 9635 section 3.6, with
  `Cache-Control: no-store`.

## Access token formats

All five formats RFC 9767 registers are minted and verified.

| Format | What it is | How a resource server verifies it |
|---|---|---|
| `jwt-signed` | a JWT whose protected header carries `typ` `gnap-at+jwt`, signed with the realm key | `/oauth2/jwks`, and refuse any other header `typ` (see below) |
| `jwt-encrypted` | that JWT inside a JWE | to the resource server's own `gnapJweKey` (RSA-OAEP-256 or ECDH-ES+A256KW), else `dir` A256GCM that only introspection can open |
| `macaroon` | the V2 binary format, HMAC-SHA256, first-party caveats | the root key written onto the resource server's application entry as `gnapMacaroonKey` |
| `biscuit` | Ed25519, Datalog facts and checks | the root public key in `/gnap/keys` |
| `zcap` | a ZCAP-LD capability with a Data Integrity `eddsa-jcs-2022` proof (see [below](#zcap-proof-suites)) | the controller document at `/gnap/zcap/controller` |

Which format a token gets is decided in this order: a registered resource set
that accepts only some formats, then the resource server's
`gnapAccessTokenFormat`, then the client's, then `gnap.accessTokenFormat`.

**Resource servers can always introspect**, whatever the format.

### The JWT formats' type

A `jwt-signed` token's protected header is
`{"alg": "RS256", "typ": "gnap-at+jwt", "kid": …}` (with `x5c` or `x5u` where
`gnap.accessTokenCertificateHeader` asks), and the JWS inside a
`jwt-encrypted` token carries the same header. Every JWT this realm signs —
ID Tokens, RFC 9068 access tokens, logout tokens — is signed with the same
key, so **a resource server must check the header `typ`** (RFC 8725 section
3.11, explicit typing), comparing it case-insensitively and accepting
`application/gnap-at+jwt` as the same type (RFC 7515 section 4.1.9). This
service's own resource server does, and refuses anything else
(`STS-GNAP-0343`); an OAuth resource server here likewise refuses a GNAP
token, whose header is not `at+jwt`.

> **`gnap-at+jwt` is a private media type.** RFC 9767 registers no media type
> for a JWT access token, so this service names one the way RFC 9068 named
> `at+jwt`. It is not in the IANA media types registry, and another GNAP
> implementation will not use it.

The payload also carries `"typ": "GNAP"`. That is a private claim, the
marker every token this service signs carries for its own token register
(`Bearer`, `ID`, `Refresh` on the OAuth tokens); it is not the token's type,
and a resource server should not dispatch on it.

### Seeing a revocation without introspection

A resource server that verifies a token itself, rather than introspecting it,
still needs to learn that the token was revoked (RFC 9767 section 6.3). Each
format gets the mechanism it has, and none is invented for a format that has
none:

| Format | How a self-checking resource server sees a revocation |
|---|---|
| `jwt-signed`, `jwt-encrypted` | The JWT carries `status: { "status_list": { "idx", "uri" } }` ([Token Status List](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/), section 6.1). Fetch the list at `uri`, verify its signature against `/oauth2/jwks`, and read bit `idx`: `1` means revoked. |
| `biscuit` | `GET /gnap/biscuit/revocations` returns `{ "revocation_ids": [...], "ttl": ... }`. Refuse a biscuit if any of its blocks' revocation identifiers is on the list. |
| `macaroon`, `zcap` | **No standard mechanism.** Introspect, or keep token lifetimes short (`gnap.accessTokenLifetimeS`) and rely on rotation. |

**The access-token status list is the realm's one list.** GNAP's JWTs share it
with OAuth's [RFC 9068 access tokens](oauth-oidc.md#jwt-access-tokens-rfc-9068).
It holds one bit per token over 1,048,576 indexes. Each index is allocated at
random when the token is minted and freed when the token expires. The bit is
computed from the revocation itself, so it is set however the token is revoked:
at its management URI, by rotation, by revoking its grant, on `/admin/tokens`
or `/admin/gnap`, or by a global sign-out.

The list is served as `application/statuslist+jwt`, or as
`application/statuslist+cwt` when `Accept` asks for it. It is signed with the
realm's RS256 key, and carries a `ttl` and an `exp` taken from
`oauth2.accessTokenStatusListTtlS` (60 seconds) and
`oauth2.accessTokenStatusListLifetimeS`. The `ttl` is how long a revocation
can take to reach a resource server that caches the list.

**Where a resource server finds the lists:**

* The RS-facing discovery document (`/.well-known/gnap-as-rs`) has two extra
  members, `status_list_aggregation_endpoint` and `biscuit_revocation_endpoint`.
* `/gnap/keys` has the same two, under `jwt` and `biscuit`.

Neither member is in RFC 9767's registry, so both are this service's own. The
biscuit list is also this service's own. A revoked biscuit stays on it until
the token's own `exp`. After that, every verifier refuses the token anyway.

**Revocation by push:** see [Shared Signals](#shared-signals). A resource server
can own a stream and be told when a token audienced to it is revoked.

### zcap proof suites

RFC 9767 registers `zcap` with a reference to *Authorization Capabilities for
Linked Data v0.3* (ZCAP-LD), which requires a Data Integrity proof but names no
particular one. `gnap.zcapCryptosuite` chooses it, per realm, and **a realm
accepts only the suite it is set to** — a token signed any other way is refused
(`STS-GNAP-0336`) before its signature is looked at.

| `gnap.zcapCryptosuite` | Specification | Signs | The controller document publishes |
|---|---|---|---|
| **`eddsa-jcs-2022`** (default) | W3C Data Integrity EdDSA Cryptosuites v1.0 (Recommendation), section 3.3 | the JSON itself, canonicalized by RFC 8785 (JCS), with the realm's Ed25519 key | a `Multikey`, `z6Mk…` |
| `mldsa44-jcs-2024` | W3C Quantum-Resistant Cryptosuites v1.0 (First Public Working Draft), section 3.3 | the JSON (JCS), with the realm's ML-DSA-44 key | a `Multikey`, base64url (`u…`) |
| `slhdsa128-jcs-2024` | the same draft, section 3.4 | the JSON (JCS), with the realm's SLH-DSA-SHA2-128s key — each signature takes about two seconds | a `Multikey`, base64url (`u…`) |
| `Ed25519Signature2020` | EdDSA Cryptosuites v1.0, Appendix A — kept there as "an earlier version" | the **RDF canonicalization** (URDNA2015) of the capability | an `Ed25519VerificationKey2020` |

A capability signed with a JCS suite has the `@context`
`["https://w3id.org/zcap/v1", "https://w3id.org/security/data-integrity/v2", {GNAP terms}]`
— ZCAP-LD v0.4's form — and a proof carrying `type: DataIntegrityProof`, the
`cryptosuite`, `proofPurpose: capabilityDelegation`, `capabilityChain` (the
root capability's id) and the same `@context`. To verify one, a resource server
needs no JSON-LD processor: remove `proofValue` from the proof and the proof
from the capability, take SHA-256 of each one's JCS form, concatenate the two
hashes (the proof's first), and check the signature over that with the key the
controller document publishes.

The two post-quantum suites exist for resource servers that want signatures a
quantum computer cannot forge. Their specification is a draft, so few ZCAP
verifiers outside this service accept them yet.

> **Warning: `Ed25519Signature2020` is for compatibility only.** Use it only
> for a resource server that can verify nothing newer. It signs the RDF graph
> the capability expands to, not the JSON a resource server reads, so two
> different JSON documents can share one valid signature: a changed
> `@context` that remaps a term produces the same graph. This service refuses
> any `@context` other than the exact one it writes, which closes that gap
> here, but a resource server has to do the same. A resource server also needs
> a JSON-LD processor and an RDF canonicalizer to check the signature at all.
> The EdDSA Recommendation itself advises new implementations to move off this
> suite.

Changing `gnap.zcapCryptosuite` strands zcap tokens already issued in that
realm, which are refused until they expire (`gnap.accessTokenLifetimeS`).

## Clients and resource servers are applications

Every GNAP client instance and resource server is an entry in the application
registry (`/admin/applications`), with **GNAP** as its protocol and one of two
kinds: `gnap-client` or `gnap-resource-server`. The attributes:

| Attribute | What it holds |
|---|---|
| `gnapKey` | the client's or resource server's public key, as the JSON `key` object |
| `gnapKeyReference` | a reference name a request may send instead of the key |
| `gnapSymmetricKey` | a shared secret for an HMAC proof — **sealed at rest** |
| `gnapKeyProof`, `gnapSymmetricAlg` | the proof method and the HMAC algorithm for a referenced key |
| `gnapInstanceId` | an instance identifier this entry answers to |
| `gnapFinishUri` | the finish URIs a redirect or push may use |
| `gnapInteractionStartModes` | narrows the start modes this client may use |
| `gnapAllowedAccess` | the access types and references a client may request (read by the issuance policy's `gnap-right-not-listed` rule), or a resource server may register |
| `oauthAuthorizationDetailsType` | the access types a resource server owns — the [catalogue](#access-types-and-the-issuance-policy) shared with RFC 9396 |
| `gnapBearerTokens`, `gnapSkipInteraction` | per-client permissions. `gnapSkipInteraction` lets a client skip the approval page **where every requested right's access type allows it** (see [who must be asked](#who-must-be-asked-and-how-strongly-signed-in)); it does **not** let it act for a person — see [acting for somebody else](#acting-for-somebody-else) |
| `gnapAccessTokenFormat`, `gnapAccessTokenLifetimeS` | per-application overrides |
| `gnapResourceServerUri` | the locations a resource server answers for |
| `gnapOwnerLookupUri` | where a resource server answers who owns a resource: an https template with `{identifier}` as one path segment — see [who owns a resource](#who-owns-a-resource) |
| `gnapJweKey` | the public key `jwt-encrypted` tokens are encrypted to |
| `gnapMacaroonKey` | the macaroon root key, written by this service — **sealed at rest** |
| `gnapScopedSignals` | `FALSE` lets this application's streams hear about everybody |
| `gnapMtlsTrust` | `pki` holds this client's mutual TLS key to a PKI where the realm pins; `pinned` where the realm requires a PKI is refused — see [mutual TLS trust](#mutual-tls-trust) |
| `oauthTlsClientAuthSubjectDn`, `oauthTlsClientAuthSan*` | RFC 8705's certificate subject, shared with OAuth: under a PKI, a certificate carrying it is this client's |
| `gnapClassId`, `gnapDisplayUri`, `gnapLogoUri` | what the approval page shows |

**An unknown key** is given an entry on first sight in development mode. In
product mode it is refused `invalid_client` until it is registered — and so
is a key, or an instance identifier, belonging to an entry development
created that way: an entry made on first sight is not a registration (#496,
`STS-GNAP-0902`). Register the client through the console or `/admin-api`.

**A right's locations must name a registered resource server in product
mode** (#505). Each location of each access right must be at or under the
`gnapResourceServerUri` of a registered resource server, be one of this
service's own resource servers (the demonstration resource server at
`/gnap/rs/resource`, the default resource indicator, `/admin-api`), or name
a registered application by its audience, permission base URI, `client_id`
or identifier. Otherwise the request is refused `invalid_request` (400,
`STS-GNAP-0903`) at creation, modification and derivation alike — the right
is not quietly left out of the token's audience, as it is in development
mode.

The two sealed attributes are encrypted under the process key-encryption key
whenever keys persist — see [encryption at rest](encryption-at-rest.md).

## Mutual TLS trust

A key proved by mutual TLS (RFC 9635 section 7.3.2) is the TLS client
certificate the connection was made with. The main port asks every connection
for one and requires none. How that certificate is trusted is
`gnap.mtlsTrust`:

| Model | What is required | Default in |
|---|---|---|
| `pki` (section 11.4) | the certificate chains to the client truststore (this realm's TLS client authority, or an anchor installed at `/tls/trust`) **and** is bound to the client's application entry: issued to it by this realm, or carrying the one RFC 8705 subject parameter the entry registers (`oauthTlsClientAuthSubjectDn` or an `oauthTlsClientAuthSan*` attribute) | product (`auto`) |
| `pinned` (section 7.3.2) | the certificate is the one the key names, by thumbprint or public key; self-signed is allowed and no chain is built | development (`auto`) |

**A revoked certificate is refused in both models**, under
`pki.revocationCheck`: one this service issued is looked up in its own
register, one from another authority against the list it names.

**Under `pki` a certificate can be rotated at the authority.** A client
presents a new certificate from the authority and no registration changes. The
certificate is found by the entry it is bound to, never by its thumbprint, and
its thumbprint is then recorded on the entry (`gnapKeyIdentity`). A client
that sends its instance identifier or key reference proves the certificate on
its connection rather than the one pinned in `gnapKey`. A key sent by value
must still be the certificate on the connection.

**An application may be stricter than its realm, never weaker.** Set
`gnapMtlsTrust=pki` on its entry in a pinned realm. `pinned` in a realm that
requires a PKI is refused when written (`STS-REG-0196`), and a value written
earlier is ignored.

> **Warning:** `pinned` gives up chain validation and rotation at a
> certificate authority. A stolen self-signed key stays good until the entry
> that pins it is edited. Revocation still applies, but only to a certificate
> some authority issued.

A certificate forwarded by a TLS-terminating proxy (RFC 9440 `Client-Cert`) is
not read. Only this service's own socket counts.

## Acting for somebody else

GNAP has two ways for one party to obtain a token about somebody else, and
both are decided by the same [delegation and impersonation](delegation.md)
policy as the OAuth 2.0 token exchange, WS-Trust and Kerberos — with the same
settings on the same directory entries. There are no GNAP-specific delegation
settings.

| GNAP act | Semantics | Actor | Subject | Target (R) |
|---|---|---|---|---|
| A client with `gnapSkipInteraction` presents a verified `id_token` or `saml2` assertion in `user` and gets tokens for that person, with nobody asked (RFC 9635 sections 2.3.3 and 2.4) | **impersonation** — like Kerberos S4U2Self | the client's application entry | the person the assertion names | each resource server the requested rights resolve to; the client itself when they name none |
| A resource server sends `existing_access_token` and gets a token for a downstream resource server (RFC 9767 section 4) | **delegation** — like Kerberos S4U2Proxy | the deriving resource server | the person the original token is about | each downstream resource server; the deriving one itself when it only narrows |

So, for example:

* For **impersonation**, the client's `appDelegationSemantics` must include
  `impersonation`, and each resource server must be the client itself, on its
  `appAllowedToDelegateTo`, or accept it in `appAllowedToActOnBehalfOf`.
* For **derivation**, the deriving resource server's `appAllowedToDelegateTo`
  must name the downstream one, or the downstream one's
  `appAllowedToActOnBehalfOf` must name it.
* In both, the person must not be protected (`stsNotDelegated`, a
  `delegation.protectedGroups` group, the console's rosters), must be in the
  actor's `appDelegationSubjectGroup` if it has one, and must hold the roles
  the application requires. A `may_act` claim in a presented ID Token must name
  the client.

**Product mode refuses** with `request_denied` (HTTP 403). **Development
mode** issues the token and records that it *would have been refused*. A
`may_act` naming somebody else is refused in both. Every act, issued or
refused, is listed on **Monitoring → Delegation** and at `GET
/admin-api/delegation` under protocol `GNAP`.

**The assertion must have been issued to the client presenting it**, in
both modes: an ID Token's `aud` must name the client (its identifier or one
of its `oauthClientId` values), and a SAML assertion's `Audience` likewise.
An assertion issued to another client is refused `unknown_user`
(`STS-GNAP-0073`): RFC 9635 section 11.13 names a captured assertion
presented by a client that is not its audience as the way an end user is
impersonated. A web application that signed a person in with OpenID Connect
presents its own ID Token; it cannot hand that token to a back-end service
to present in its place.

A client that skips interaction **without** a user assertion acts for nobody:
nothing is asked, and no subject information is released.

### What a derived token carries

* **No more access than the original.** A right the original token does not
  cover is refused, in every mode — unless the [access-type
  catalogue](#access-types-and-the-issuance-policy) declares its type
  `derivableFrom` a type the original carries. Such a right is still put to
  the issuance policy and to the delegation question for its resource server.
* **The chain of who derived it**, as RFC 8693 section 4.1's `act`: the
  deriving resource server, with any earlier ones nested under it. Every
  format carries it, in the part only this authorization server can write:

  | Format | Where |
  |---|---|
  | `jwt-signed`, `jwt-encrypted` | the `act` claim |
  | `macaroon` | a `gnap:act=` caveat before the `gnap:access=` caveat; one appended after it is refused |
  | `biscuit` | `actor(0, "<resource server>")` facts in the authority block, 0 the most recent |
  | `zcap` | the capability's `gnapActor` member, under its proof |

  Introspection returns it as `act`, and rotation keeps it.
* **At most `gnap.maxDerivationDepth` links** (2 by default). A derivation past
  it is refused in every mode.

## Access types and the issuance policy

### One catalogue for GNAP and RFC 9396

An access right's `type` (RFC 9635 section 8) is declared by the resource
server that owns it, in the same place OAuth's rich authorization requests
read: the resource application's `oauthAuthorizationDetailsType`, edited on the
application's **Access types** tab or through
`POST /admin-api/applications/set-access-type` and `/remove-access-type`. One
definition per type:

```json
{"type": "payment", "description": "Initiate and track a payment",
 "actions": ["initiate", "status", "refund"],
 "datatypes": ["card", "transfer"],
 "required": ["actions"],
 "bearer": false, "maxLifetimeS": 300,
 "derivableFrom": ["account"],
 "introspectionClaims": ["email"],
 "limits": {"type": "object",
            "properties": {"amount": {"type": "number", "minimum": 0}},
            "required": ["amount"], "additionalProperties": false}}
```

| Member | What it does for GNAP |
|---|---|
| `actions`, `datatypes`, `privileges`, `locations` | the values a right may name; another is refused `invalid_request` (`STS-GNAP-0812`). `locations` beside the resource server's own `gnapResourceServerUri` and audiences |
| `required` | members a right must carry (`STS-GNAP-0812`) |
| `schema` | a JSON Schema the whole right must meet (`STS-GNAP-0812`) |
| `limits` | the JSON Schema (a subset) a right's `limits` must meet (`STS-GNAP-0814`); a type declaring none refuses `limits` (`STS-GNAP-0813`) |
| `bearer: false` | a bearer token carrying the type is refused (`STS-GNAP-0811`) |
| `maxLifetimeS` | a token carrying it lives no longer |
| `derivableFrom` | a derived token (RFC 9767 section 4) may add a right of this type when the original carries one of these |
| `introspectionClaims` | the person's claims the owning resource server is told at `/gnap/introspect` |
| `interaction` | `never`: issued with nobody asked, to any client acting as itself; `default`: a `gnapSkipInteraction` client may skip the page; `always`: the resource owner sees the page every time — no skip, no remembered approval |
| `consentActions` | a right naming one of these actions (or no actions, which is every action) needs the resource owner on the page, as `always` does |
| `acr` | the authentication level the approving session must meet; the approval page sends the person to sign in again with it first |

**A right of a catalogued type that names no location is for its owning
resource server**: the token is audienced to it and minted in its format.

**An uncatalogued type** is granted in development mode and refused
`request_denied` in product mode (`STS-GNAP-0810`). A reference string is not
a type: `gnap.unknownAccessReferences` still decides an unregistered one.

### Each right is a question to the issuance policy

Every access right is put to the issuance policy as its own XACML question,
action-id `issue-gnap-right`, with the right, the token it is for (label,
bearer flag, format, resource servers), the client and its registered class,
who approved it and how (`pending`, `interaction`, `remembered`, `skipped`,
`derived`, or `owner` — the resource owner on their portal), the session's `acr` and `amr`, its risk and registered device, and
what the catalogue declares for its type. It is asked twice: when the grant is
requested, modified or derived (a refusal answers the client) and when tokens
are issued (a refusal leaves the right out of its token).

The built-in policy refuses a bearer token the realm (`gnap.bearerTokens`) or
the client (`gnapBearerTokens`) refuses (`invalid_flag`, `STS-GNAP-0111`), one
of this service's protected scopes the client does not declare
(`STS-GNAP-0719`), a right `gnapAllowedAccess` does not list or an unknown
reference where the setting refuses one (`STS-GNAP-0112`), and the catalogue's
rules above; it caps the token at the type's `maxLifetimeS` and keeps
everything else. `gate.check()` still decides whether the token is issued at
all.

**A realm's own issuance policy** (`xacml.issuancePolicy`) may refuse a right
with a code of its own or **narrow** it — take actions, locations, datatypes or
privileges off — through the obligation `urn:sts:xacml:obligation:gnap-right`.
A narrowing never widens: taking a value off a dimension the right left open
subtracts it from the values the catalogue lists, and a narrowing that cannot
be carried out that way, leaves nothing, or fails the catalogue again is a
refusal (`STS-GNAP-0817`). **The approval page says what was narrowed** before
the person was asked. [XACML](xacml.md) describes the obligation.

## Who owns a resource

An access right may name one resource with `identifier` (RFC 9635 section
8): an account, an album, a mailbox. **Only the resource's owner may approve
access to it.** A person who signs in on the approval page — or answers a request
waiting on their `/portal/ciba` — and does not own it is told so and cannot
approve; the request waits for its owner.

The resource server says who owns what, in one of two ways:

**On a registered resource set.** A registration (`POST /gnap/resource`, RFC
9767 section 3.4) may carry `resource_owners`, mapping an identifier in the
set's `access` to the DN of a person or a group in the realm's directory:

```json
{
  "access": [{ "type": "account", "identifier": "acct-14", "actions": ["read"] }],
  "resource_server": { "key": { "proof": "httpsig", "jwk": { … } } },
  "resource_owners": { "acct-14": "cn=finance,ou=groups,dc=example,dc=com" }
}
```

An owner that is neither a person nor a group, or an identifier the set does
not carry, is refused (`STS-GNAP-0865`, `0864`). The newest registration
that names an owner for an identifier is the one used.

**By a lookup.** Set `gnapOwnerLookupUri` on the resource server's
application entry to an https URL template with `{identifier}` as one whole
path segment, such as `https://rs.example.com/owners/{identifier}`. This
service fetches it with the identifier percent-encoded into that segment and
expects `{"owner": "<DN>"}`, or 404 when nobody owns the resource. The
request uses the outbound policy (the certificate verified, internal
addresses refused in product mode, no redirects, a timeout and a size cap)
and the answer is held for `gnap.ownerLookupCacheS` (60 seconds).

> **Warning.** A lookup that fails (a timeout, an error status, an answer
> that is not `{"owner": …}`) refuses the right (`STS-GNAP-0863`): a
> resource server that declared a lookup said the identifier has an owner. A
> longer `gnap.ownerLookupCacheS` keeps a former owner able to approve for
> that long after the resource server changes its answer.

A person owns a resource when the owner DN is their own entry or a group
they are a direct member of. An identifier no resource server declares an
owner for is not checked.

The decision is the issuance policy's (`issue-gnap-right`, with the facts
`urn:sts:xacml:gnap:owner-known`, `owner`, `owner-source`,
`owner-unresolved` and `owner-matches`): the built-in rules refuse a
non-owner (`STS-GNAP-0861`) and an unanswered lookup, and a realm's own
policy can allow a delegate or require more. A client that skips the
approval page, a derived token and a remembered approval meet the same rule
when the token is issued, and the right is left out of the token.

## Limits

A catalogued access type may declare a `limits` schema, and a right of that
type may then carry `limits`. Six members have a meaning to this service:

| Member | Value | Means |
|---|---|---|
| `amount` | a decimal (string or number), at most 6 fraction digits | the most that may be spent, per interval where one is given |
| `currency` | an ISO 4217 code | what `amount` is in — required beside it |
| `count` | a non-negative integer | the most operations, per interval |
| `receiver` | a string, or an array of strings | who an operation may be for |
| `interval` | an ISO 8601 repeating interval, `R[n]/<RFC 3339 start>/<duration>` | the totals reset at each boundary; before the start or after the last repetition nothing is allowed |
| `window` | `{ "notBefore", "notAfter" }`, RFC 3339 times | operations only inside it |

Any other member is the resource server's own: carried and shown, never
changed here. A request whose limits use these members wrongly is refused
`invalid_request` (`STS-GNAP-0860`); an RFC 9396 authorization detail of the
same type is refused the same way (`STS-OAUTH-0916`).

**The person may lower a limit on the approval page — or on `/portal/ciba`,
when they approve a request that waited for them there — never raise it**: a
smaller amount or count, fewer receivers, a narrower window, or an interval
with the same start and a period no shorter and no more repetitions (a
shorter period resets the budget more often, so it is more). Removing a
limit, or adding an interval, is a raise. A later modification that drops or
raises a limit goes back to the person, and a derived token cannot carry
more than the original (`STS-GNAP-0868`).

**The token states the limits** in each right of `access`, in all five
formats, where only this service writes (a biscuit also carries them as
`access_limit_amount`, `access_limit_count`, `access_limit_receiver`,
`access_limit_interval`, `access_limit_not_before` and
`access_limit_not_after` authority facts a resource server's own block can
test), together with the **grant** they are counted against: `grant_id` in
the JWT formats, `gnap:grant=` in a macaroon, `grant(id)` in a biscuit,
`gnapGrant` in a zcap. Introspection returns the limits and `grant_id`. A
rotated token keeps the grant; a derived token carries the original's, so
deriving does not create a second budget.

**The resource server keeps the running totals** — this service does not:
there is no standard spend call, and a resource server would otherwise
depend on this one for every operation. A resource server should:

1. key its totals by `grant_id`, the right's `type` and its `identifier`;
2. check the window and the interval, and find the current period;
3. check the receiver and the currency;
4. add the operation's amount and one to the count **atomically**, and
   refuse with `403` and `error="insufficient_scope"` when that would pass a
   limit;
5. reset the totals at each interval boundary;
6. give a spend back when the operation then fails.

`POST /gnap/rs/spend` is the reference. It needs a token granting the action
`spend` on `urn:iya-sts:gnap:demo` and takes
`{ "amount": "12.50", "currency": "EUR", "receiver": "bob" }` (each
optional; `"simulateFailure": true` makes the operation fail after the spend
so you can see it refunded). It answers the totals and what remains for the
period, `403` past a limit (`STS-GNAP-0870`), outside the window or interval
(`0871`), for another receiver (`0872`) or currency (`0873`), and keeps the
totals in one store every node shares (`sts_cluster_budgets` on postgres),
so a cluster spends one budget. A right with no limits is spent unaccounted.

## The resource owner

A person approves a grant by signing in through the **same authentication
service** every other protocol here uses, and gets the same directory entry
however they signed in. An approval is remembered in the consent register, so
the same application asking the same person for the same rights is not asked
again (`gnap.rememberApprovals`).

### Who must be asked, and how strongly signed in

The access type's `interaction`, `consentActions` and `acr` are rules of the
issuance policy, and the grant engine does what they say:

| The rights asked for | What happens |
|---|---|
| every right of a type declaring `interaction: never` | issued with nobody asked, to any client — acting as itself. A request that names a person or asks who they are still goes to that person |
| `default` types (and references, and uncatalogued types in development) | a client with `gnapSkipInteraction` skips the approval page; any other goes to it |
| any right of a type declaring `interaction: always`, or naming an action the type lists in `consentActions` (or naming no actions, which is every action) | the resource owner sees the approval page, every time. A client trusted to skip is sent there too, and is refused `invalid_interaction` if it offers no way to reach the person. **A remembered approval does not count**, and neither does `gnap.consentRequired` off |
| any right of a type declaring an `acr` | the person's sign-in must meet every such level before the page is drawn; a session that does not is sent to sign in again — with a second factor or a security key, as the level needs and the realm's authentication policy allows — and refused `request_denied` if it comes back short. Nothing needing an `acr` is issued without such a session: not by skipping, and not by deriving from a token whose approval did not meet it |

The same `acr` holds for OAuth: an authorization request whose
`authorization_details` carry such a type asks the person to sign in again
with it (every type's level, beside any `acr_values`) and is refused
`unmet_authentication_requirements` if they come back short, and no token
endpoint grant — client credentials included — issues the detail without an
authentication that meets it.

A realm's own issuance policy may make any of these stricter — `always` for
a class of client, an `acr` for one action — because the most demanding
answer wins. What the person achieved is recorded on the grant (`acr`), and
each right is checked against it again when tokens are issued.

### When the person asked is not the person here

A request's `user` may name somebody who is not at the approval page — or a
client may offer no interaction at all. Where the realm turns on
**`gnap.ownerApproval`** (off by default), the grant then **waits for the
person it names** (RFC 9635 sections 1.4 and 2.4):

* it is listed on their portal under **Sign-in requests** (`/portal/ciba`),
  with the application, each right (untick what you do not want to allow),
  who was using the application when it asked, the sign-in level it needs
  and when it runs out; they are told by mail as well (a notification they
  may turn off — the request waits on the portal either way);
* the client keeps polling its continuation; the `wait` it is told is long
  enough that `gnap.maxPolls` polls cover `gnap.ownerApprovalLifetimeS`, and
  polling sooner is `too_fast`;
* approved, the client's next poll collects the tokens; denied, it is told
  `user_denied`; not answered in time, it is told so and the grant is
  finalized as **rejected**;
* a person has at most `gnap.ownerApprovalMaxPending` such requests waiting,
  and a name nobody here holds is `unknown_user`.

Where it is off, a different person's approval is answered `unknown_user`, and
a request offering no interaction that needs a person is refused.
**`gnap.allowCrossUser`, which let whoever signed in approve a grant naming
somebody else, no longer exists.**

### What a person sees: `/portal/gnap`

Every grant a person is the resource owner of is listed on their own portal,
under **Your account → GNAP grants** (`/portal/gnap`): the application, what
the grant allows (each access right, with any limits it carries), the tokens
issued under it (label, format, expiry and whether each still works — never a
token's value), how long the grant can still be renewed, and, once it has
ended, why. **Revoke this grant** ends it at once: every token issued under it
stops working, the application can no longer continue or modify it, and CAEP
`session-revoked` is sent — exactly what the application would see had it
revoked the grant itself (section 5.4). The page takes no name from the
request: it lists and revokes only the signed-in person's own grants.

An administrator sees the same list on the person's page in the console, in
its **GNAP grants** tab (`/admin/users?user=…`), with a Revoke on each, and
the management API carries it as `gnapGrants` on `GET
/admin-api/users?user=…`. `POST /admin-api/gnap/revoke-grant` with both
`grant` and `user` revokes a grant only if that person is its resource owner.

In a service deployed as several [cells](cells.md), each list is the grants
the cell holds; a grant whose client instance is registered in another cell
stays there and is listed there, and the page says so.

### Why a grant ended

Every finalized grant records one of four reasons, shown on the console, the
portal and in the audit log (`gnap.grant.finalize`):

| Reason | What happened |
|---|---|
| `issued` | Its tokens were released and nothing more can be asked of it (an approved grant answered with no `continue`, `gnap.continueAfterApproval` off). Its tokens keep working. |
| `revoked` | Ended by its client (`DELETE` on the continuation URI), an administrator, or its resource owner on `/portal/gnap`. |
| `rejected` | Refused: no way to interact, an interaction that could not start, too many polls, an interaction reference presented out of turn, or a grant that ran out after its resource owner said no. |
| `expired` | Its interaction ran out, or its grant lifetime did. |

### The grant lifetime

A grant has a lifetime of its own, `gnap.grantLifetimeS` (a day by default),
counted from its request and separate from the access token lifetime. Past it
the grant cannot be continued or modified (`invalid_continuation`), none of
its tokens can be rotated (`invalid_rotation`), and it is finalized as
`expired`. No token issued under a grant is given an expiry later than the
grant's. A longer lifetime lets a client keep access by rotating its tokens
for longer on the strength of one approval.

### What a client is told about the person

* **Subject identifiers are per client.** An `opaque` identifier is different
  for every client instance (or for every client of one registered sector —
  the application's `oauthSectorIdentifierUri`), so two clients cannot match
  their records on it. The same value doubles as a **user reference**
  (section 2.4.1), and it resolves only for the client it was given to; from
  any other client it is `unknown_user`. `iss_sub` carries the `sub` the
  client's ID Token carries — pairwise for a client registered as pairwise —
  and `uri`, which is the person's public subject, is given only to a client
  told the public `sub`.
* **Subject information is released once, and only on an authorization**: the
  person leaving "Who you are" ticked on the approval page, or a delegation
  decision for a trusted client acting for a person by a verified assertion.
  Nothing later in the grant's life — a continuation, a modification within
  what was approved, a token rotation — sends it again. A modification that
  asks for it again goes back to the person.
* **`class_id` and `display` are what the client says about itself**, and
  never raise trust. A name, home page or logo the application's entry does
  not hold is shown on the approval page as the application's own
  description, which this service has not verified; a self-declared logo is
  not drawn. Nothing about either changes what a client may be granted, and
  an application entry made on first sight in development mode records only
  the key.

## Every request body is validated

Before any handler reads a GNAP request, the body is:

1. bounded in depth and key count,
2. held to a **JSON Schema** (ajv, draft 2020-12) that bounds every string,
   array and object, checks URI formats, and **refuses a control character in
   any member**, and
3. checked against what RFC 9635 or RFC 9767 requires of that document.

A refusal at any layer is `invalid_request` (or the error the section names),
with a sentence saying what was wrong.

## Shared Signals

* A **grant revoked** — by its client, on `/admin/gnap`, on the person's
  console page or by the person on `/portal/gnap` — sends CAEP
  `session-revoked` whose session is `gnap-grant:<id>`.
* A **token revoked** at its management URI sends `session-revoked` whose
  session is `gnap-token:<jti>`.
* A **grant modified** sends `token-claims-change` carrying the new `access`.
* A GNAP web application can **own a stream**: it presents its GNAP access token
  to `/ssf/stream` with the `GNAP` scheme and a proof, with `ssf:read` or
  `ssf:write` in the token's access. Those rights are this service's own
  protected scopes: a grant asking for them is refused `request_denied`
  (`STS-GNAP-0719`) unless the application's `oauthAllowedScope` declares them,
  and the transmitter asks again on every call. The transmitter metadata lists
  `urn:ietf:rfc:9635` for it.
* A stream a GNAP web application owns is **scoped**: it hears only about
  people who approved a grant to that application.
* **A federation partner's signal can revoke grants.** A verified CAEP or
  RISC event from a federation relationship that signs people in —
  `session-revoked`, `account-disabled`, `account-purged` or
  `credential-compromise` by default — revokes every GNAP grant the person
  approved, with every OAuth grant, token and authorization code held for
  them; a `session-revoked` reaches only what was issued on the sessions that
  partner started. It is the `signal-revoke-grants` rule of the
  `signal-response` policy, and `ssf.signalsRevokeGrants` (on by default)
  turns it off. See [signals received](signals-received.md).
* A **registered resource server** can own a stream the same way: its
  application entry is a `gnap-resource-server`, and it asks for `ssf:read` /
  `ssf:write` as a client with its own key. Its stream hears **only**
  `session-revoked` for `gnap-token:<jti>` and `gnap-grant:<id>`, and only for
  tokens audienced to it. A token is audienced to it if its access resolved to
  that server, or its `aud` names the server's identifier or one of its
  `gnapResourceServerUri`s. A grant counts when any of its tokens was. It is
  told about tokens no person approved too: their `session-revoked` names the
  session alone. An entry that is both a web application and a resource server
  hears what either rule allows. `gnap.scopedSignals` off, or
  `gnapScopedSignals` `FALSE` on the entry, removes the scope.

See [CAEP events](caep-events.md).

## What ends a grant besides its client

A grant ends when its client revokes it (RFC 9635 section 5.4), and also when:

| What happens | What it ends |
|---|---|
| The person signs out everywhere (`/logout`), is signed out by an administrator (`/admin/logout`, `/admin-api/logout`), or is **disabled** or deleted | every grant they approved, and every token on it |
| A sign-out ends one of their sessions (a Revoke on `/admin/sessions`, a partner's sign-out) | the grants approved on that session |
| An administrator revokes the grant on `/admin/gnap` or `/admin/sessions` | that grant |
| The client's application entry is **deleted** | every grant of that client |
| The entry's `gnapKey`, `gnapKeyIdentity` or `gnapKeyReference` is **removed or replaced** | the grants bound to a key the entry no longer names. Rotating an access token's key (section 6.1.1) changes nothing |
| A registered **device is marked compromised** | the grants whose client key is one of the device's keys (by value or by its certificate, for mutual TLS), and the OAuth tokens bound to them by DPoP or mutual TLS |
| A federation partner's verified signal (above) | the person's grants and tokens |

Ending a grant revokes its tokens, finalizes it — a continuation is refused
and introspection answers `active: false` — and sends CAEP `session-revoked`
about it. Separately, **every use is checked**: a token or grant whose
resource owner is disabled, or whose client's entry is gone or no longer names
its key, is refused at its next continuation, rotation, derivation,
presentation or introspection (`STS-GNAP-0730`–`0735`), whatever changed the
account or the entry and on a cluster node the change has not reached yet.

The person's grants appear on `/admin/logout` and as **GNAP grant** rows on
`/admin/sessions`. A sign-out of one application elsewhere (`/oauth2/logout`,
SAML Single Logout) and a session simply expiring do **not** end them: a
grant is given to outlive the browser.

## The console

* **Protocols → GNAP** (`/admin/gnap`): the endpoints, what each authorization
  server profile advertises, the token formats and their verification material,
  the grants this realm holds with a **Revoke** on each, the registered resource
  sets with a **Delete** on each, and every `gnap.*` setting.
* **Monitoring → GNAP grants** (`/admin/gnap/monitor`): every application that
  uses GNAP and what it has done — grant requests, approvals, denials,
  refusals, tokens by format, rotations, revocations and introspections.

The management API mirrors both: `GET /admin-api/gnap`,
`GET /admin-api/gnap/monitor`, and `POST /admin-api/gnap/revoke-grant` and
`/delete-resource-set`.

## Configuration

Every `gnap.*` setting is runtime and may be set per trust realm, because each
realm runs its own GNAP authorization server. The list-valued ones are the
defaults of the section 9 discovery document; a named authorization server
profile (`/admin/authorization-servers`) may override or remove each, and what
it then publishes is what its grant endpoint enforces.

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `gnap.enabled` | `STS_GNAP_ENABLED` | `true` | yes | Off makes every `/gnap` endpoint and the resource-owner pages answer that GNAP is off in this realm; grants and tokens are kept. |
| `gnap.accessTokenFormat` | `STS_GNAP_ACCESS_TOKEN_FORMAT` | `jwt-signed` | yes | The RFC 9767 format issued when no resource set, resource server or client decides (`jwt-signed`, `jwt-encrypted`, `macaroon`, `biscuit`, `zcap`). |
| `gnap.tokenFormats` | `STS_GNAP_TOKEN_FORMATS` | `jwt-signed,jwt-encrypted,macaroon,biscuit,zcap` | yes | `token_formats_supported`: a format not listed is never issued, and a resource set accepting only unlisted formats is refused. |
| `gnap.zcapCryptosuite` | `STS_GNAP_ZCAP_CRYPTOSUITE` | `eddsa-jcs-2022` | yes | The proof a zcap token is signed with, and the only one accepted: `eddsa-jcs-2022`, `mldsa44-jcs-2024`, `slhdsa128-jcs-2024`, or — **with the [warning above](#zcap-proof-suites)** — `Ed25519Signature2020`. |
| `gnap.accessTokenLifetimeS` | `STS_GNAP_ACCESS_TOKEN_LIFETIME_S` | `3600` | yes | The `expires_in` of every access token; a client may override it with `gnapAccessTokenLifetimeS`. |
| `gnap.grantLifetimeS` | `STS_GNAP_GRANT_LIFETIME_S` | `86400` | yes | How long a grant lives, separate from its tokens: past it the grant cannot be continued, modified or have a token rotated, and no token issued under it expires later. **A longer one lets a client keep access by rotation for longer on one approval.** |
| `gnap.interactionLifetimeS` | `STS_GNAP_INTERACTION_LIFETIME_S` | `600` | yes | How long a pending grant's interaction start URIs and user codes stay usable. |
| `gnap.continueWaitS` | `STS_GNAP_CONTINUE_WAIT_S` | `5` | yes | The `wait` of every continuation response; continuing sooner is `too_fast`, and `0` lets a test run without sleeping. |
| `gnap.maxPolls` | `STS_GNAP_MAX_POLLS` | `60` | yes | Continuation polls a pending grant accepts before it is finalized with `too_many_attempts`. |
| `gnap.signatureMaxAgeS` | `STS_GNAP_SIGNATURE_MAX_AGE_S` | `300` | yes | How far a key proof's created time may be from now; nonces and JWS proofs are remembered for twice this. |
| `gnap.replayCacheSize` | `STS_GNAP_REPLAY_CACHE_SIZE` | `10000` | yes | Live signed requests a realm remembers; a full history refuses the next request (`STS-GNAP-0718`) rather than forgetting a live one. **At the default that is about 16 signed requests a second, sustained; past it every signed request in the realm is refused until entries age out.** Raise it for a busier realm. |
| `gnap.interactionStartModes` | `STS_GNAP_INTERACTION_START_MODES` | `redirect,app,user_code,user_code_uri` | yes | `interaction_start_modes_supported`; a client may narrow it with `gnapInteractionStartModes`. |
| `gnap.finishMethods` | `STS_GNAP_FINISH_METHODS` | `redirect,push` | yes | `interaction_finish_methods_supported`; `push` is also switched by `gnap.pushFinish`. |
| `gnap.keyProofs` | `STS_GNAP_KEY_PROOFS` | `httpsig,mtls,jwsd,jws` | yes | `key_proofs_supported`; `mtls` needs the main port on HTTPS so a client certificate can arrive. |
| `gnap.mtlsTrust` | `STS_GNAP_MTLS_TRUST` | `auto` | yes | How a key proved by mutual TLS is trusted: `pki` or `pinned` ([mutual TLS trust](#mutual-tls-trust)). `auto` is `pki` in product and `pinned` in development. **Warning:** `pinned` gives up chain validation and rotation at the authority. |
| `gnap.subIdFormats` | `STS_GNAP_SUB_ID_FORMATS` | `opaque,iss_sub,email,account,uri,phone_number,aliases` | yes | `sub_id_formats_supported` in RFC 9493's spellings; a format is released only when the entry holds the fact it needs. |
| `gnap.assertionFormats` | `STS_GNAP_ASSERTION_FORMATS` | `id_token,saml2` | yes | `assertion_formats_supported`, built by the same code the OIDC and SAML families use. |
| `gnap.assertionMaxAgeS` | `STS_GNAP_ASSERTION_MAX_AGE_S` | `300` | yes | How long past its `exp` an assertion this realm signed is still accepted as a user hint (section 2.4). |
| `gnap.keyRotation` | `STS_GNAP_KEY_ROTATION` | `true` | yes | `key_rotation_supported` (section 6.1.1); off answers `key_rotation_not_supported`. |
| `gnap.tokenManagement` | `STS_GNAP_TOKEN_MANAGEMENT` | `true` | yes | Whether access tokens carry a manage URI and management token (section 6). |
| `gnap.bearerTokens` | `STS_GNAP_BEARER_TOKENS` | `true` | yes | Off refuses the `bearer` flag with `invalid_flag` for every client; `gnapBearerTokens` FALSE refuses one. |
| `gnap.durableTokens` | `STS_GNAP_DURABLE_TOKENS` | `false` | yes | Section 3.2.1's `durable` flag: a token survives the grant being modified. |
| `gnap.revokeOnModify` | `STS_GNAP_REVOKE_ON_MODIFY` | `true` | yes | A modification revokes the grant's earlier tokens, unless they were issued durable (section 5.3). |
| `gnap.instanceIds` | `STS_GNAP_INSTANCE_IDS` | `true` | yes | A client that sent its key by value is handed an `instance_id` to send by reference next time (section 3.5). |
| `gnap.continueAfterApproval` | `STS_GNAP_CONTINUE_AFTER_APPROVAL` | `true` | yes | Whether an approved grant's response carries `continue`, so the client can modify or revoke it later. |
| `gnap.consentRequired` | `STS_GNAP_CONSENT_REQUIRED` | `true` | yes | Off approves every interactive grant as soon as the resource owner has signed in, with no approval page. |
| `gnap.rememberApprovals` | `STS_GNAP_REMEMBER_APPROVALS` | `true` | yes | Records what a resource owner approved in the consent register on their entry, so the same rights are not asked for again. |
| `gnap.ownerApproval` | `STS_GNAP_OWNER_APPROVAL` | `false` | yes | Sections 1.4 and 2.4: a request naming a person who is not at the approval page, or offering no interaction, waits for that person on `/portal/ciba` (with a mail notice) while the client polls. Off: `unknown_user`, or refused. Replaced `gnap.allowCrossUser` (#432). |
| `gnap.ownerApprovalLifetimeS` | `STS_GNAP_OWNER_APPROVAL_LIFETIME_S` | `600` | yes | Seconds an absent owner has to answer before the grant is finalized as rejected. |
| `gnap.ownerApprovalMaxPending` | `STS_GNAP_OWNER_APPROVAL_MAX_PENDING` | `5` | yes | The most grants that may wait for one person at once. |
| `gnap.userCodeLength` | `STS_GNAP_USER_CODE_LENGTH` | `8` | yes | The length of a user code; section 3.3.3 recommends six to eight characters. |
| `gnap.unknownAccessReferences` | `STS_GNAP_UNKNOWN_ACCESS_REFERENCES` | `accept` | yes | An access reference naming no registered resource set and not in `gnapAllowedAccess`: carried onto the token (`accept`) or `request_denied` (`refuse`). |
| `gnap.introspection` | `STS_GNAP_INTROSPECTION` | `true` | yes | RFC 9767 section 3.3 token introspection. |
| `gnap.resourceRegistration` | `STS_GNAP_RESOURCE_REGISTRATION` | `true` | yes | RFC 9767 section 3.4 resource set registration. |
| `gnap.tokenDerivation` | `STS_GNAP_TOKEN_DERIVATION` | `true` | yes | RFC 9767 section 4: a resource server exchanges a token it was given for one to a downstream resource server. |
| `gnap.maxDerivationDepth` | `STS_GNAP_MAX_DERIVATION_DEPTH` | `2` | yes | How many resource servers a derived token's actor chain (`act`) may name. Each derivation adds the deriving resource server; one past this depth is refused in every mode. |
| `gnap.pushFinish` | `STS_GNAP_PUSH_FINISH` | `true` | yes | The section 4.2.2 push finish; off makes no outbound request at all and stops advertising `push`. |
| `gnap.pushAllowHttp` | `STS_GNAP_PUSH_ALLOW_HTTP` | `false` | yes | Allows a push to a plain `http` URI, logged as a warning: any host in development, a loopback address only in product (RFC 9635 section 2.5.2.1). |
| `gnap.pushSkipTlsVerification` | `STS_GNAP_PUSH_SKIP_TLS_VERIFICATION` | `false` | yes | **Development only — a warning.** Pushes to an `https` URI whose certificate does not verify, logged on every push. Ignored in product mode, and refused on write there. |
| `gnap.pushCaFile` | `STS_GNAP_PUSH_CA_FILE` | *(empty)* | yes | A PEM file of CA certificates a client's push listener may chain to, beside node's own store — how product reaches a privately certified client. |
| `gnap.pushAllowedHosts` | `STS_GNAP_PUSH_ALLOWED_HOSTS` | *(empty)* | yes | Host names a push may go to; empty means any host a finish URI names (product mode already restricts these to registered URIs). |
| `gnap.pushTimeoutMs` | `STS_GNAP_PUSH_TIMEOUT_MS` | `5000` | yes | How long a push finish may take. |
| `gnap.jweEnc` | `STS_GNAP_JWE_ENC` | `A256GCM` | yes | The `enc` of a `jwt-encrypted` token encrypted to a resource server's own key; one encrypted to this server is always `dir` with `A256GCM`. |
| `gnap.accessTokenCertificateHeader` | `STS_GNAP_ACCESS_TOKEN_CERTIFICATE_HEADER` | `x5u` | yes | Whether a `jwt-signed` or `jwt-encrypted` token's JWS names its signing certificate chain (`x5u`, `x5c`, `both`, `none`); see [PKI](pki.md#a-signed-token-names-its-certificate-chain). |
| `gnap.demoResourceServer` | `STS_GNAP_DEMO_RESOURCE_SERVER` | `true` | yes | Runs `/gnap/rs/resource`, which judges a token in any of the five formats and answers the RS-first challenge. |
| `gnap.ownerLookupCacheS` | `STS_GNAP_OWNER_LOOKUP_CACHE_S` | `60` | yes | How long the owner a resource server's gnapOwnerLookupUri named for an identifier is held before it is asked again (#432 phase 5): a grant asks at its request, on its approval page and at issue. A failed lookup is never held. 0 asks every time; a longer one keeps a former owner able to approve for that long after the resource server says otherwise. |
| `gnap.caepEvents` | `STS_GNAP_CAEP_EVENTS` | `true` | yes | Sends CAEP `session-revoked` on a revoked grant or token and `token-claims-change` on a modified grant. |
| `gnap.scopedSignals` | `STS_GNAP_SCOPED_SIGNALS` | `true` | yes | Scopes a GNAP web application's Shared Signals stream to people who approved a grant to it; `gnapScopedSignals` FALSE opts one out. A stream owned by a GNAP resource server hears only `session-revoked` for the GNAP tokens and grants audienced to it (#432). |

Every setting is on `/admin/gnap` and in [*Every setting*](configuration.md#every-setting). See
[Configuration](configuration.md) for how a value resolves and where it is
changed — the console page, or `POST /admin-api/config/set`.

## Design decisions

* **The authorization server is per trust realm.** Each realm has its own
  grants, tokens, keys and settings, so a realm is a separate GNAP authorization
  server rather than a view of a shared one. See
  [trust realms](trust-realms.md).
* **A client instance and a resource server are application entries.** Every
  identity here maps to a directory entry, so a GNAP client is registered,
  listed, monitored and scoped for signals exactly as any other application is
  — see [above](#clients-and-resource-servers-are-applications).
* **Mutual TLS is pinned or held to a PKI, by mode.** Section 7.3.2 allows a
  pinned certificate and section 11.4 a PKI. Only the PKI lets a key be revoked
  and rotated at an authority, so product uses it and development pins, so a
  client can bring the self-signed certificate it just made. Revocation is
  consulted in both. See [mutual TLS trust](#mutual-tls-trust).
* **An unknown client key is mode-gated.** Development mode creates an
  application entry on first sight so a client can be exercised with nothing
  registered; product mode refuses `invalid_client` until the key is
  registered.
* **The resource owner signs in through the one authentication service.** A
  GNAP approval uses the same session and the same directory entry as every
  other protocol, however the person signed in, rather than a sign-in of its
  own.
* **All five RFC 9767 token formats, and nothing fetched to verify them.** The
  two JWT formats go through the same JOSE code as every other token; macaroons,
  biscuits and ZCAP-LD capabilities through libraries. The JSON-LD contexts a
  ZCAP needs are vendored, and a biscuit's Datalog is evaluated with limits,
  because Datalog carried in a token is code its holder wrote.
* **Every body is held to a JSON Schema before the RFC's own rules.** Types,
  bounds, URI formats and control characters are refused first, and what RFC
  9635 or RFC 9767 requires is checked after, so a refusal names the section
  that was broken — see [above](#every-request-body-is-validated).
* **Every one-time value is spent once across a cluster.** Continuation and
  management tokens, interaction references, start links, user codes, key
  proofs and the resource owner's decision are each claimed in the shared
  store, so two nodes cannot both accept one; a store that cannot be asked
  refuses rather than guessing.
* **A full replay history refuses rather than forgets.** A forgotten signature
  can be replayed, so when `gnap.replayCacheSize` is reached the next signed
  request is refused (`STS-GNAP-0718`) instead of the oldest live entry being
  dropped.
* **A person's opaque identifier is derived per client from their stable
  subject.** It is an HMAC over the client's sector and the person's directory
  subject rather than their name, so a rename keeps it, a name deleted and
  re-created gets a new one — RFC 9635 section 3.4's "SHOULD NOT reuse" held
  across a directory edit — and two clients are never given the same one.
  `account` is a name by definition and still follows a rename.
* **Instance attestation is not used.** OAuth 2.0 Attestation-Based Client
  Authentication could vouch for a client instance's `class_id`; it is
  optional in the plan for GNAP and not wired here, so `class_id` stays a
  self-declared hint.
* **Remembered approvals live in the consent register, as digests.** Each
  approved access right is stored on the person's own entry as a `gnap:` digest
  of that right, in the same consent register the OAuth consent screen uses,
  rather than in a store of GNAP's own.
* **Signals go out, and a partner's come in.** Revoking or modifying a grant
  sends CAEP, and a GNAP web application can own a scoped stream. Since #432 a
  federation partner's verified signal about a person can revoke their grants
  (`signal-revoke-grants`, `ssf.signalsRevokeGrants`); this service's own
  signals, played back to its own console and portal, never do.
* **The push finish is the only outbound request, and it is constrained.** It
  goes to a URI the client supplied, so it verifies TLS by default, can be
  limited to `gnap.pushAllowedHosts`, is restricted to registered URIs in
  product mode, and can be switched off entirely.
* **The two shared keys are sealed at rest.** `gnapSymmetricKey` and
  `gnapMacaroonKey` are encrypted under the process key-encryption key whenever
  keys persist — see [encryption at rest](encryption-at-rest.md).
* **The Ed25519 key rotates with the realm's signing keys.** Biscuits and ZCAPs
  are signed with the realm's Ed25519 key, so they rotate on the same schedule;
  verification tries every live generation, and `/gnap/keys` and the ZCAP
  controller document list them all. A zcap token on a post-quantum suite is
  signed with the realm's ML-DSA-44 or SLH-DSA-SHA2-128s key, which rotates the
  same way.

## Error codes

Every GNAP failure is recorded under an `STS-GNAP-NNNN` code on the audit row
and at the front of the log line. The code is never sent to a client. See
[error codes](error-codes.md).

## Related

* [OAuth 2.0 and OpenID Connect](oauth-oidc.md) — the other authorization
  server here, which shares the realm's signing keys and consent register
* [Authentication](authentication.md) — the sign-in service a resource owner
  approves through
* [Shared Signals](shared-signals.md) and [CAEP events](caep-events.md)
* [PKI](pki.md) — the certificate chain a signed token names
* [Trust realms](trust-realms.md)
* [Encryption at rest](encryption-at-rest.md)
* [What is not checked](what-is-not-checked.md)
* [Configuration](configuration.md) and [error codes](error-codes.md)
