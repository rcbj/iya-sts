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
| `/gnap/rs/resource` | GET · POST | a demonstration resource server |

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
  identifiers in the RFC 9493 formats, `id_token` and `saml2` assertions,
  `instance_id`, user references, polling with `wait` and `too_fast`,
  modification, revocation, and a trusted client that needs no interaction.
* **Token management:** rotation, revocation, and client **key rotation**
  proved by both keys.
* **RFC 9767:** discovery, introspection, resource set registration, and
  **token derivation** — a resource server sends `existing_access_token` to the
  grant endpoint and receives a downstream token with no more access.
* **Error responses:** every error code of RFC 9635 section 3.6, with
  `Cache-Control: no-store`.

## Access token formats

All five formats RFC 9767 registers are minted and verified.

| Format | What it is | How a resource server verifies it |
|---|---|---|
| `jwt-signed` | a JWT with `typ` `GNAP`, signed with the realm key | `/oauth2/jwks` |
| `jwt-encrypted` | that JWT inside a JWE | to the resource server's own `gnapJweKey` (RSA-OAEP-256 or ECDH-ES+A256KW), else `dir` A256GCM that only introspection can open |
| `macaroon` | the V2 binary format, HMAC-SHA256, first-party caveats | the root key written onto the resource server's application entry as `gnapMacaroonKey` |
| `biscuit` | Ed25519, Datalog facts and checks | the root public key in `/gnap/keys` |
| `zcap` | a ZCAP-LD capability with a Data Integrity `eddsa-jcs-2022` proof (see [below](#zcap-proof-suites)) | the controller document at `/gnap/zcap/controller` |

Which format a token gets is decided in this order: a registered resource set
that accepts only some formats, then the resource server's
`gnapAccessTokenFormat`, then the client's, then `gnap.accessTokenFormat`.

**Resource servers can always introspect**, whatever the format.

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
| `gnapAllowedAccess` | the access types a resource server may register |
| `gnapBearerTokens`, `gnapSkipInteraction` | per-client permissions |
| `gnapAccessTokenFormat`, `gnapAccessTokenLifetimeS` | per-application overrides |
| `gnapResourceServerUri` | the locations a resource server answers for |
| `gnapJweKey` | the public key `jwt-encrypted` tokens are encrypted to |
| `gnapMacaroonKey` | the macaroon root key, written by this service — **sealed at rest** |
| `gnapScopedSignals` | `FALSE` lets this application's streams hear about everybody |
| `gnapMtlsTrust` | `pki` holds this client's mutual TLS key to a PKI where the realm pins; `pinned` where the realm requires a PKI is refused — see [mutual TLS trust](#mutual-tls-trust) |
| `oauthTlsClientAuthSubjectDn`, `oauthTlsClientAuthSan*` | RFC 8705's certificate subject, shared with OAuth: under a PKI, a certificate carrying it is this client's |
| `gnapClassId`, `gnapDisplayUri`, `gnapLogoUri` | what the approval page shows |

**An unknown key** is given an entry on first sight in development mode. In
product mode it is refused `invalid_client` until it is registered.

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

## The resource owner

A person approves a grant by signing in through the **same authentication
service** every other protocol here uses, and gets the same directory entry
however they signed in. An approval is remembered in the consent register, so
the same application asking the same person for the same rights is not asked
again (`gnap.rememberApprovals`).

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

* A **grant revoked** — by its client or on `/admin/gnap` — sends CAEP
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

See [CAEP events](caep-events.md).

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
| `gnap.interactionLifetimeS` | `STS_GNAP_INTERACTION_LIFETIME_S` | `600` | yes | How long a pending grant's interaction start URIs and user codes stay usable. |
| `gnap.continueWaitS` | `STS_GNAP_CONTINUE_WAIT_S` | `5` | yes | The `wait` of every continuation response; continuing sooner is `too_fast`, and `0` lets a test run without sleeping. |
| `gnap.maxPolls` | `STS_GNAP_MAX_POLLS` | `60` | yes | Continuation polls a pending grant accepts before it is finalized with `too_many_attempts`. |
| `gnap.signatureMaxAgeS` | `STS_GNAP_SIGNATURE_MAX_AGE_S` | `300` | yes | How far a key proof's created time may be from now; nonces and JWS proofs are remembered for twice this. |
| `gnap.replayCacheSize` | `STS_GNAP_REPLAY_CACHE_SIZE` | `100000` | yes | Live signed requests a realm remembers; a full history refuses the next request (`STS-GNAP-0718`) rather than forgetting a live one. |
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
| `gnap.allowCrossUser` | `STS_GNAP_ALLOW_CROSS_USER` | `false` | yes | On lets whoever signs in approve a grant that named a different user, instead of `unknown_user` (section 2.4). |
| `gnap.userCodeLength` | `STS_GNAP_USER_CODE_LENGTH` | `8` | yes | The length of a user code; section 3.3.3 recommends six to eight characters. |
| `gnap.unknownAccessReferences` | `STS_GNAP_UNKNOWN_ACCESS_REFERENCES` | `accept` | yes | An access reference naming no registered resource set and not in `gnapAllowedAccess`: carried onto the token (`accept`) or `request_denied` (`refuse`). |
| `gnap.introspection` | `STS_GNAP_INTROSPECTION` | `true` | yes | RFC 9767 section 3.3 token introspection. |
| `gnap.resourceRegistration` | `STS_GNAP_RESOURCE_REGISTRATION` | `true` | yes | RFC 9767 section 3.4 resource set registration. |
| `gnap.tokenDerivation` | `STS_GNAP_TOKEN_DERIVATION` | `true` | yes | RFC 9767 section 4: a resource server exchanges a token it was given for one to a downstream resource server. |
| `gnap.pushFinish` | `STS_GNAP_PUSH_FINISH` | `true` | yes | The section 4.2.2 push finish; off makes no outbound request at all and stops advertising `push`. |
| `gnap.pushAllowHttp` | `STS_GNAP_PUSH_ALLOW_HTTP` | `false` | yes | Allows a push to a plain `http` URI, logged as a warning: any host in development, a loopback address only in product (RFC 9635 section 2.5.2.1). |
| `gnap.pushSkipTlsVerification` | `STS_GNAP_PUSH_SKIP_TLS_VERIFICATION` | `false` | yes | **Development only — a warning.** Pushes to an `https` URI whose certificate does not verify, logged on every push. Ignored in product mode, and refused on write there. |
| `gnap.pushCaFile` | `STS_GNAP_PUSH_CA_FILE` | *(empty)* | yes | A PEM file of CA certificates a client's push listener may chain to, beside node's own store — how product reaches a privately certified client. |
| `gnap.pushAllowedHosts` | `STS_GNAP_PUSH_ALLOWED_HOSTS` | *(empty)* | yes | Host names a push may go to; empty means any host a finish URI names (product mode already restricts these to registered URIs). |
| `gnap.pushTimeoutMs` | `STS_GNAP_PUSH_TIMEOUT_MS` | `5000` | yes | How long a push finish may take. |
| `gnap.jweEnc` | `STS_GNAP_JWE_ENC` | `A256GCM` | yes | The `enc` of a `jwt-encrypted` token encrypted to a resource server's own key; one encrypted to this server is always `dir` with `A256GCM`. |
| `gnap.accessTokenCertificateHeader` | `STS_GNAP_ACCESS_TOKEN_CERTIFICATE_HEADER` | `x5u` | yes | Whether a `jwt-signed` or `jwt-encrypted` token's JWS names its signing certificate chain (`x5u`, `x5c`, `both`, `none`); see [PKI](pki.md#a-signed-token-names-its-certificate-chain). |
| `gnap.demoResourceServer` | `STS_GNAP_DEMO_RESOURCE_SERVER` | `true` | yes | Runs `/gnap/rs/resource`, which judges a token in any of the five formats and answers the RS-first challenge. |
| `gnap.caepEvents` | `STS_GNAP_CAEP_EVENTS` | `true` | yes | Sends CAEP `session-revoked` on a revoked grant or token and `token-claims-change` on a modified grant. |
| `gnap.scopedSignals` | `STS_GNAP_SCOPED_SIGNALS` | `true` | yes | Scopes a GNAP web application's Shared Signals stream to people who approved a grant to it; `gnapScopedSignals` FALSE opts one out. |

Every setting is on `/admin/gnap` and in the README's settings table. See
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
* **A person's opaque identifier is derived from their stable subject.** It is
  an HMAC over the person's directory subject rather than their name, so a
  rename keeps it and a name deleted and re-created gets a new one — RFC 9635
  section 3.4's "SHOULD NOT reuse" held across a directory edit. `account` is a
  name by definition and still follows a rename.
* **Remembered approvals live in the consent register, as digests.** Each
  approved access right is stored on the person's own entry as a `gnap:` digest
  of that right, in the same consent register the OAuth consent screen uses,
  rather than in a store of GNAP's own.
* **Signals go out and never come in.** Revoking or modifying a grant sends
  CAEP, and a GNAP web application can own a scoped stream; nothing listens to
  CAEP or RISC to revoke a grant, by decision.
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
