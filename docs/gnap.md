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
  9530 `Content-Digest`), `mtls`, `jwsd` and `jws`. **Key formats:** `jwk`,
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
| `zcap` | a ZCAP-LD capability signed with Ed25519Signature2020 | the controller document at `/gnap/zcap/controller` |

Which format a token gets is decided in this order: a registered resource set
that accepts only some formats, then the resource server's
`gnapAccessTokenFormat`, then the client's, then `gnap.accessTokenFormat`.

**Resource servers can always introspect**, whatever the format.

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
| `gnapClassId`, `gnapDisplayUri`, `gnapLogoUri` | what the approval page shows |

**An unknown key** is given an entry on first sight in development mode. In
product mode it is refused `invalid_client` until it is registered.

The two sealed attributes are encrypted under the process key-encryption key
whenever keys persist — see [encryption at rest](encryption-at-rest.md).

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
  `ssf:write` in the token's access. The transmitter metadata lists
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

## Settings

Every `gnap.*` setting is on `/admin/gnap` and in the README's settings table.
The ones most worth knowing:

| Setting | Default | What it changes |
|---|---|---|
| `gnap.enabled` | `true` | the whole family, per realm |
| `gnap.continueWaitS` | `5` | the `wait` a pending grant states; `0` for a test |
| `gnap.accessTokenFormat` | `jwt-signed` | the format when nothing more specific decides |
| `gnap.keyRotation`, `gnap.tokenManagement`, `gnap.bearerTokens` | `true` | the optional features of section 6 and 7.2 |
| `gnap.introspection`, `gnap.resourceRegistration`, `gnap.tokenDerivation` | `true` | the RFC 9767 endpoints |
| `gnap.pushFinish`, `gnap.pushAllowInsecure`, `gnap.pushAllowedHosts` | `true`, `false`, empty | whether and where a push finish dials |
| `gnap.caepEvents`, `gnap.scopedSignals` | `true` | the Shared Signals behaviour above |

## Error codes

Every GNAP failure is recorded under an `STS-GNAP-NNNN` code on the audit row
and at the front of the log line. The code is never sent to a client. See
[error codes](error-codes.md).
