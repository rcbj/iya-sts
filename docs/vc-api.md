---
title: W3C VC-API test endpoints
---

# The W3C VC-API test endpoints and the W3C test suites

The W3C Verifiable Credentials and DID Working Groups test implementations
with their own suites, and those suites drive an issuer and a verifier
through the endpoints of the W3C CCG's
[Verifiable Credentials API](https://w3c-ccg.github.io/vc-api/). iya-sts
issues through [OpenID4VCI](oid4vci.md) and verifies through
[OpenID4VP](oid4vp.md), and neither secures a document somebody else wrote,
so it offers the VC-API endpoints as a **test control**: an adapter over the
same cryptosuites, keys and status lists, in a development
[trust realm](trust-realms.md) only.

Six suites run against it from this repository's test suite, each pinned to
a commit:

| Suite | What it holds this service to |
|---|---|
| [VC Data Model 2.0](https://github.com/w3c/vc-data-model-2.0-test-suite) | every MUST of the data model, on what is issued and what is refused; enveloped credentials |
| [Data Integrity EdDSA](https://github.com/w3c/vc-di-eddsa-test-suite) | `eddsa-rdfc-2022` and `eddsa-jcs-2022`, issuing and verifying |
| [Data Integrity ECDSA](https://github.com/w3c/vc-di-ecdsa-test-suite) | `ecdsa-rdfc-2019` and `ecdsa-jcs-2019` over P-256 and P-384, and `ecdsa-sd-2023` |
| [Bitstring Status List](https://github.com/w3c/vc-bitstring-status-list-test-suite) | the status entry, the status list credential, the check |
| [VC-JOSE-COSE](https://github.com/w3c/vc-jose-cose-test-suite) | `vc+jwt`, `vc+sd-jwt`, `vc+cose` and the presentation forms |
| [DID Core](https://github.com/w3c/did-test-suite) | this service's DID documents, and its DID resolution and dereferencing |

## Features

### Issuing

`POST /vc-api/issuers/{issuer}/credentials/issue` with
`{ "credential": {…}, "options": {…} }` secures the credential and answers
`201 { "verifiableCredential": … }`. `{issuer}` names the securing mechanism
and the realm key:

| Issuer | Secures with |
|---|---|
| `eddsa-rdfc-2022`, `eddsa-jcs-2022` | an embedded Data Integrity proof by the realm's Ed25519 key |
| `ecdsa-rdfc-2019-p256`, `ecdsa-rdfc-2019-p384`, `ecdsa-jcs-2019-p256`, `ecdsa-jcs-2019-p384` | the same, by the realm's P-256 or P-384 key |
| `ecdsa-sd-2023-p256` | a selective disclosure base proof; `options.mandatoryPointers` names what every disclosure must reveal |
| `jose-p256`, `sd-jwt-p256`, `cose-p256` | a VC-JOSE-COSE envelope; `options.disclosurePaths` names what an SD-JWT makes disclosable |

Each key is named by its `did:key`, which is what the credential's `issuer`
must be: this service never signs as somebody else. `GET /vc-api/issuers`
lists them. Before anything is signed the credential is held to the data
model and to JSON-LD safe mode over the contexts this service ships — a
context it does not ship is refused, never fetched. `options.credentialStatus`
of type `BitstringStatusListEntry` gives the credential an index in the
realm's own status lists.

### Verifying

`POST /vc-api/credentials/verify` and `POST /vc-api/presentations/verify`
answer `200` or `400` with `{ verified, checks, warnings, errors }`. They check
the data model, JSON-LD safe mode, every proof of a proof set or chain (the
verification methods `did:key` and `did:jwk`; nothing is fetched) or the
envelope, a presentation's challenge and domain, every credential inside a
presentation, and — when asked or named — the credential's status.

### Holders, selective disclosure and status

* `POST /vc-api/holders/{holder}/presentations/prove` secures a presentation
  as the same keys.
* `POST /vc-api/credentials/derive` derives an `ecdsa-sd-2023` disclosure
  from a base proof, revealing `options.selectivePointers`.
* `POST /vc-api/credentials/status` revokes, suspends or lifts the suspension
  of a credential this adapter issued with a status. It is the act
  [`/admin/vc-status`](oid4vci.md#status-lists) performs; a revocation is
  final.
* The Bitstring Status List credentials answer as JSON-LD with an
  `eddsa-rdfc-2022` proof when `Accept` asks for JSON-LD or JSON, and as a
  JWT otherwise.

### DID resolution

`GET /vc-api/resolve?did=…` (`&function=resolveRepresentation&accept=…`) and
`GET /vc-api/dereference?didUrl=…` are DID Core's resolve,
resolveRepresentation and dereference for `did:key`, `did:jwk` and the
realm's own `did:web`, in `application/did+json` and
`application/did+ld+json`. Another `did:web` is `notFound`: it would have to
be fetched.

## Development and product mode

| | Development | Product |
|---|---|---|
| Every `/vc-api/*` route, and the status list's `…/publish` | Answers, behind an access token | 404, as though it did not exist |

A realm's mode is its own, so a development realm of a product service has
them. They always need an access token issued by the realm, carrying
`vc-api:issue` (issue, prove, derive, status) or `vc-api:verify` (verify,
resolve, dereference). Both are protected scopes: a client is issued them
only when an administrator adds them to its `oauthAllowedScope`.

## Configuration

There are no settings. The keys are the realm's own signing keys; the
contexts are fixed.

## Design decisions

* **A test control, not a feature.** An endpoint that signs whatever it is
  handed with a realm's key is what a conformance suite needs and what no
  deployment should expose.
* **The same code as the product paths.** The cryptosuites, the keys, the
  status lists and the DID documents are the ones OpenID4VCI and OpenID4VP
  use, so a suite's finding is a finding about them.
* **Nothing is fetched.** JSON-LD contexts, verification methods and DID
  documents come from what the service ships or can compute. A document that
  needs anything else is refused, with the URL named.
* **Where a suite's fixture and a specification disagree, the specification
  wins**, and the test records the exception with the clause: for example
  VC-JOSE-COSE forbids the `vp` claim that the VC Data Model suite's
  enveloped presentation carries.

## In the running service

`GET /admin/sts-metadata` lists every endpoint of the *W3C VC-API (test
endpoints)* group with what it does and the specifications it answers to.

## Related

* [OpenID4VCI and status lists](oid4vci.md)
* [OpenID4VP, wallet sign-in and DIDs](oid4vp.md)
* [Trust realms](trust-realms.md)
