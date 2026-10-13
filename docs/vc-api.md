---
title: W3C VC API
---

# The W3C Verifiable Credentials API

iya-sts serves the W3C CCG's
[Verifiable Credentials API](https://w3c.github.io/vcalm/) (VCALM, formerly
the "VC API") at `/vc-api` in any [trust realm](trust-realms.md) that turns
it on: an **issuer** that secures a credential it is handed, a **holder**
that proves a presentation and derives a selective disclosure, a
**verifier** of credentials and presentations, a **status service** over the
realm's Bitstring Status Lists, and **DID resolution**.

It is **off by default** (`vcApi.enabled`), in development and product mode
alike, because it signs documents its caller wrote. It issues through the
same cryptosuites and status lists as [OpenID4VCI](oid4vci.md) and verifies
with the same code as [OpenID4VP](oid4vp.md), but **signs with keys of its
own**, never with the keys that sign the realm's tokens.

Until #598 (2026-10-12) it was a development-only test control for the W3C
test suites; it became a product surface on that issue.

## Turning it on

```bash
# in the default realm
curl -X POST https://sts.example/admin-api/config/set \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"key":"vcApi.enabled","value":true}'
# in a realm: /realm/<id>/admin-api/config/set
```

Or on the **OpenID4VCI** tab of **Protocols → Verifiable Credentials**
(`/admin/vc`), where its two settings are drawn. Off, every `/vc-api` path
answers `501` with `{ "errors": [{ "message": … }] }` — the feature is off,
the URL is not wrong, as `scim.enabled` and `ssf.enabled` answer.

| Setting | Default | What it does |
|---|---|---|
| `vcApi.enabled` | `false` | Serve the VC API in this realm |
| `vcApi.maxPerWindow` | `600` | Calls one client, and one address, may make per `security.rateLimitWindowS` window; past it `429` with `Retry-After` |

## Authentication

Every call needs an **OAuth 2.0 access token this realm issued**, in every
mode, carrying the scope its endpoint names:

| Scope | Endpoints |
|---|---|
| `vc-api:issue` | issue, prove, derive, status, the issuer list |
| `vc-api:verify` | verify a credential or a presentation, resolve, dereference |

Both are **protected scopes**: a client is issued them only when an
administrator adds them to its `oauthAllowedScope`, and every call asks
again. A coordinator usually takes them with the client credentials grant:

```bash
curl -X POST https://sts.example/admin-api/applications/create \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"identifier":"vc-coordinator","kind":"oauth2-client","name":"VC coordinator",
       "protocols":["oauth2"],
       "fields":{"oauthClientId":["vc-coordinator"],"oauthClientSecret":"…",
                 "oauthTokenEndpointAuthMethod":"client_secret_post",
                 "oauthAllowedScope":["vc-api:issue","vc-api:verify"],
                 "oauthGrantType":["client_credentials"]}}'
```

A token without the scope is `403`; a revoked one, one another realm issued,
or one whose client no longer declares the scope is `401`.

## Features

### Issuing

`POST /vc-api/issuers/{issuer}/credentials/issue` with
`{ "credential": {…}, "options": {…} }` secures the credential and answers
`201 { "verifiableCredential": … }`. `{issuer}` names the securing mechanism
and the curve:

| Issuer | Secures with |
|---|---|
| `eddsa-rdfc-2022`, `eddsa-jcs-2022` | an embedded Data Integrity proof by the VC API's Ed25519 key |
| `ecdsa-rdfc-2019-p256`, `ecdsa-rdfc-2019-p384`, `ecdsa-jcs-2019-p256`, `ecdsa-jcs-2019-p384` | the same, by its P-256 or P-384 key |
| `ecdsa-sd-2023-p256` | a selective disclosure base proof; `options.mandatoryPointers` names what every disclosure must reveal |
| `jose-p256`, `sd-jwt-p256`, `cose-p256` | a VC-JOSE-COSE envelope; `options.disclosurePaths` names what an SD-JWT makes disclosable |

Each key is named by its `did:key`, which is what the credential's `issuer`
must be: this service never signs as somebody else. `GET /vc-api/issuers`
lists them with their endpoints. Before anything is signed the credential is
held to the data model and to JSON-LD safe mode over the contexts this
service ships — a context it does not ship is refused, never fetched.
`options.credentialStatus` (`{ "type": "BitstringStatusListEntry",
"statusPurpose"?: … }`) gives the credential an index in the realm's own
status lists; `options.created` sets a proof's creation time.

### Verifying

`POST /vc-api/credentials/verify` and `POST /vc-api/presentations/verify`
answer `200` or `400` with `{ verified, checks, warnings, errors }`. They check
the data model, JSON-LD safe mode, every proof of a proof set or chain (the
verification methods `did:key` and `did:jwk`; nothing is fetched) or the
envelope, a presentation's challenge and domain, every credential inside a
presentation, and — when asked (`options.checks`) or named — the credential's
status. For an envelope whose `kid` resolves to nothing,
`options.verificationMethod` may name the public key to verify it with; a
private member there is refused.

### Holders, selective disclosure and status

* `POST /vc-api/holders/{holder}/presentations/prove` secures a presentation
  as the same keys, with `options.challenge` and `options.domain`.
* `POST /vc-api/credentials/derive` derives an `ecdsa-sd-2023` disclosure
  from a base proof, revealing `options.selectivePointers`.
* `POST /vc-api/credentials/status` revokes, suspends or lifts the suspension
  of a credential the VC API issued with a status. It is the act
  [`Credential status`](oid4vci.md#status-lists) performs on
  [`/admin/vc#vc-tab-status`](oid4vci.md#status-lists); a revocation is
  final.
* The Bitstring Status List credentials answer as JSON-LD with an
  `eddsa-rdfc-2022` proof when `Accept` asks for JSON-LD or JSON, and as a
  JWT otherwise.

### Options

VCALM requires an implementation to refuse an option it does not
understand, and this one does: each endpoint reads only the options named
above, each checked for its shape, and anything else is `400` naming it.

### DID resolution

`GET /vc-api/resolve?did=…` (`&function=resolveRepresentation&accept=…`) and
`GET /vc-api/dereference?didUrl=…` are DID Core's resolve,
resolveRepresentation and dereference for `did:key`, `did:jwk` and the
realm's own `did:web`, in `application/did+json` and
`application/did+ld+json`. Another `did:web` is `notFound`: it would have to
be fetched.

### Publishing a status list

A status list here is computed on every read, so it is always current. The
W3C suites' "publish the list now" is an administrator's act:
`POST /admin-api/vc-status/publish` with `{ "purpose": "revocation" }` (Admin
Write), or the **Publish now** button beside each Bitstring Status List on
the Credential status tab. It used to be `…/bitstring/{purpose}/publish`
beside the list, which is gone.

## Not built

zcap authorization; workflows and exchanges; challenges; storing credentials
and presentations (`GET` and `DELETE` of `/credentials/{id}`); VCALM's
`operation:path` scopes; issuer instances configured per realm (the
instances are fixed, one per securing mechanism and curve); `ecdsa-sd-2023`
over P-384; Bitstring Status Lists of the `message` purpose.

## Design decisions

* **Off by default.** An endpoint that signs whatever it is handed is a
  decision a realm's administrator makes, not one a deployment makes for
  them.
* **Keys of its own.** A VC-JOSE-COSE issuer produces a JWS over a document
  the caller wrote. Signed with the realm's token keys, that JWS could carry
  any `iss`, `sub` or `aud` the caller liked and verify as one of the
  realm's tokens (RFC 8725 section 3.12). The VC API's keys are made with the
  realm's key set, sealed in product, and published nowhere but in their
  `did:key`.
* **The same code as the product paths.** The cryptosuites, the status lists
  and the DID documents are the ones OpenID4VCI and OpenID4VP use, so a
  suite's finding is a finding about them.
* **Nothing is fetched.** JSON-LD contexts, verification methods and DID
  documents come from what the service ships or can compute. A document that
  needs anything else is refused, with the URL named.
* **Where a suite's fixture and a specification disagree, the specification
  wins**, and the test records the exception with the clause: for example
  VC-JOSE-COSE forbids the `vp` claim that the VC Data Model suite's
  enveloped presentation carries.

## The W3C test suites

Six suites run against it from this repository's test suite, each pinned to
a commit, in a throwaway realm that turns the VC API on:

| Suite | What it holds this service to |
|---|---|
| [VC Data Model 2.0](https://github.com/w3c/vc-data-model-2.0-test-suite) | every MUST of the data model, on what is issued and what is refused; enveloped credentials |
| [Data Integrity EdDSA](https://github.com/w3c/vc-di-eddsa-test-suite) | `eddsa-rdfc-2022` and `eddsa-jcs-2022`, issuing and verifying |
| [Data Integrity ECDSA](https://github.com/w3c/vc-di-ecdsa-test-suite) | `ecdsa-rdfc-2019` and `ecdsa-jcs-2019` over P-256 and P-384, and `ecdsa-sd-2023` |
| [Bitstring Status List](https://github.com/w3c/vc-bitstring-status-list-test-suite) | the status entry, the status list credential, the check |
| [VC-JOSE-COSE](https://github.com/w3c/vc-jose-cose-test-suite) | `vc+jwt`, `vc+sd-jwt`, `vc+cose` and the presentation forms |
| [DID Core](https://github.com/w3c/did-test-suite) | this service's DID documents, and its DID resolution and dereferencing |

## In the running service

`GET /admin/sts-metadata` lists every endpoint of the *W3C VC API* group
with what it does and the specifications it answers to, and the
Verifiable Credentials page lists them among its realm's endpoints.

## Related

* [OpenID4VCI and status lists](oid4vci.md)
* [OpenID4VP, wallet sign-in and DIDs](oid4vp.md)
* [Trust realms](trust-realms.md)
* [Every setting](configuration.md)
