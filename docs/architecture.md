---
title: Architecture
nav_order: 2
---

# Architecture

[![iya-sts architecture: the leader process and its listeners, the request dispatcher, three worker pools and the caches, the protocol subsystems and hosted surfaces, the shared layer of tokens and sessions, the shared services, and the embedded directory and key material above their stores](iya-sts-architecture.jpeg)](iya-sts-architecture.jpeg)

*Select the diagram for full size.* It shows one node. The layers below go
through it from top to bottom.

## The leader process and its listeners

**One node process owns every socket.** That covers the HTTPS main port, LDAP
and LDAPS, the Kerberos KDC, the SPIFFE gRPC ports and the Workload API's
domain sockets. A socket can't be handed to another process, so every listener
stays in the leader, including when worker pools are turned on.

| Listener | What is on it |
|---|---|
| 88 TCP / UDP | The Kerberos KDC |
| 389, 636 | The embedded directory, over plain LDAP and over LDAPS |
| 8081 HTTPS | The main port: every path-based protocol, `/admin`, `/portal` and `/admin-api`. It asks every connection for a client certificate and requires none; `GET /tls/sign-in` signs the holder of a verified one in (there are no separate 8443 and 9443 TLS endpoints) |
| 8888 TCP | The Kerberized test service that accepts an AP-REQ |
| 8092, 8181 gRPC | The SPIFFE Workload API, and the SPIRE Server API (always mutual TLS) |
| Domain sockets | The Workload API at `/tmp/spire-agent/public/api.sock` (on), and the SPIRE Server API's private socket at `/tmp/spire-server/private/api.sock` (off by default) |

The diagram leaves out two listeners. **8082** is plain HTTP and serves only
`/pki/`: CRLs, OCSP and CA certificates. **8444** is the embedded protocol
debugger. [Getting started](getting-started.md#the-ports) lists every port with
its setting.

**A listener that fails to bind is recorded, not fatal.** The rest of the
service keeps running, and each socket reports its own state. The persistence
store is the one exception: if it can't be opened, the service doesn't start.

## The request dispatcher and the worker pools

The dispatcher hands work from the leader to three pools of child processes:

| Pool | What a worker runs | Setting | Default |
|---|---|---|---|
| **Crypto** | Post-quantum signing and verification, key generation, password hashing: slow computations that would otherwise freeze every listener | `workers.count` | 2, forked only when the first such job arrives |
| **Admin** | Only the admin console and the user portal | `workers.surfaceCount` | 0 (off) |
| **Request** | The whole protocol stack | `workers.requestCount` | 0 (off) |

With the admin and request pools off, the leader answers every request itself.
When they are on, the processes share state through the persistence store and
not through memory. For that reason, turning dispatch on without
[coordination](persistence.md#processes-against-one-store-coordinate) is refused
at startup: it would give wrong answers, not just slow ones.

**Several nodes work the same way.** A cluster is several containers against
one PostgreSQL store. [A cluster in AWS](aws-cluster.md) shows three of them
behind a load balancer.

**The caches** (45 and counting) are what the service remembers instead of
working out or fetching again, plus the replay stores that make one-time values
work only once. [Caches](caches.md) lists each one, how long it holds a value,
and the setting that bounds it.

## Protocol subsystems

Each box is a protocol family, or a group of closely related ones, and each has
a directory of its own in the repository. One file registers every family's
routes, in one order, and that order is the order in which routes match; see
[How the code is put together](#how-the-code-is-put-together).

| Subsystem | Read more |
|---|---|
| OAuth2, OIDC | The authorization server and OpenID provider: `/oauth2/*`. [JWT assertions](jwt-assertions.md), [GNAP](gnap.md) |
| SAML profiles | SAML 2.0 and SAML 1.1, each with its own identity provider. [SAML assertions](saml-assertions.md) |
| WS-Trust, WS-Federation | `/wstrust`, `/wsfed` |
| Kerberos, SPNEGO | A KDC per trust realm on the shared port 88, told apart by the Kerberos realm name in each request, plus the protected service and MS-KKDCP. SPNEGO also signs a person in with a Kerberos ticket. [Trust realms](trust-realms.md) |
| LDAP protocol | The directory's socket view of the embedded LDAP store below |
| SCIM | `/scim/v2`, provisioning into the same directory with no store of its own |
| SPIFFE | A trust domain per realm: the bundle endpoint, the Workload API and the SPIRE Server API |
| PKI / X.509 | One Root, an Intermediate per realm, CRLs and OCSP. [PKI](pki.md) |
| ACME / EST / SCEP | Certificate enrollment through the PKI. [ACME](acme.md), [EST](est.md), [SCEP](scep.md) |
| VC, DID | OpenID4VCI, OpenID4VP and DID Core |
| WebAuthn / CTAP | The second factors: WebAuthn, TOTP and recovery codes |
| SSF / CAEP / RISC | Shared Signals: a transmitter, with this service's console and portal as receivers. [CAEP events](caep-events.md), [Signals received](signals-received.md) |
| XACML / ALFA | The PDP, the policy repository and the embedded PEPs. [Remote PEP](remote-pep.md) |
| GNAP | RFC 9635, with its resource-server connections. [GNAP](gnap.md) |

The live list is at `/admin/sts-metadata`. It reads every protocol and endpoint
off the running router, so it can't go out of date. [Endpoints](endpoints.md)
explains how to read it.

## Hosted surfaces

| Surface | Where |
|---|---|
| Admin UI | `/admin`, the operator console |
| Management API | `/admin-api`: every console control, for machines, behind an OAuth 2.0 access token. Its OpenAPI document is at `/admin-api/openapi.json` |
| User Portal | `/portal`, the pages that belong to the person signed in |
| Authentication Service | `/authn`, the sign-in screen and the second factors. **It owns the session** |
| Debugger UI + API | The embedded protocol debugger, on a listener and origin of its own (8444), open only to console administrators |

The admin console and the user portal are **OpenID Connect clients of this
service's own authorization server**. They sign people in through the same code
flow any other application uses.

## Tokens, assertions, tickets and DIDs, over sessions

**An authenticated identity is a session, not any one protocol's token.** A
session holds a subject, the authentication events that established it, and a
stable id. Every artifact the service issues (an ID Token, a SAML assertion, a
Kerberos ticket, a verifiable credential) is a projection of that session.
Every credential it accepts is evidence recorded on an authentication event.
That is why signing in once works for every protocol, and why
[signing out](signing-out.md) has one list to end. [Sessions](sessions.md)
defines the session.

## Shared services

| Service | |
|---|---|
| Audit | One audit log per trust realm. Every failure is recorded with an [error code](error-codes.md), which is never sent to a client |
| Logging | Structured logs, `info` by default and `debug` for the full record |
| Crypto library | The one module in the service that signs, verifies, encrypts and decrypts |
| System metadata | `/admin/sts-metadata` and `/admin/crypto-metadata`, both generated from the running service |
| AppConfig | Five layers of configuration, some settings changeable at runtime. [Configuration](configuration.md) |
| Monitoring / Metrics | The Monitoring section of the admin console: per-protocol counters, the database, encryption, dead letters |

## The directory and the key material, over their stores

**The embedded LDAP directory** holds people, groups, applications and roles. It
has one tree per trust realm, rooted at the realm's DNS domain (`iyasec.io` is
`dc=iyasec,dc=io`; the default realm's is `global.domain`). LDAP on
389/636, SCIM and the admin console are three views of the same store. It is
written to the **persistence store**: `memory`, `ldif` or `postgres`.
[Persistence](persistence.md) covers what survives a restart in each.

**Crypto material**, meaning signing keys and the certificate authority,
depends on the mode. In development mode it is regenerated on every start. In
product mode it is generated once, kept in the persistence store and **sealed
under a key-encryption key that the service never generates**. That key is read
from **secure secrets storage**: OpenBao in the compose stack, or AWS Secrets
Manager in the AWS cluster. [Encryption at rest](encryption-at-rest.md) covers
both.

## What the diagram does not show: trust realms

A trust realm is a separate logical copy of the service, with its own
configuration, keys, sessions, directory subtree and audit log. All realms
share this one process and its sockets, and a path prefix tells them apart
(`/realm/acme/oauth2/token`). The process-level parts are shared by every
realm: the listeners and worker pools, the two TLS endpoints, the persistence
store and the key-encryption key.

**A shared socket does not always mean a shared service.** Where the protocol
carries a name of its own, a realm gets its own service on the same port: the
directory is told apart by DN on 389 and 636, and **Kerberos by the realm name
inside each request** — a realm with its own `krb5.realm` has a KDC, a principal
database and keys of its own on port 88. SPIFFE is the other way round, told
apart by the address its sockets are bound to. [Trust realms](trust-realms.md)
covers what a realm separates and what it doesn't.

## How the code is put together

The service is split by protocol family into directories (the table above), and
at the package root there are only two modules. `server.js` is the shell: it
loads the protocol stack and listens. `sts_metadata.ts` reads the router to
list what everything else registered, so it is loaded last.

**One composition root registers every endpoint, in one order.**
`common/protocol_stack.ts` requires each module and registers its routes
against the shared express app from `common/app.js`. A module written in
TypeScript registers nothing when it is required: it exports
`registerRoutes(app)`, and the composition root calls it at the place in the
sequence where its routes belong. The modules still written in JavaScript (the
locked Kerberos files, `tls/tls_server.js` and `ldap/ldap_server.js`) still
register when they are required, and the composition root requires them at
their places, so the two kinds interleave in a fixed order. That order is the
order in which routes match. The middleware lives in `app.js` because express
applies middleware only to routes added after it. The request workers load the
same file without binding any socket, so the leader and the workers cannot
disagree about which handler wins.

**Some modules exist to break require cycles, not to group code.**
`oid4vc/vc_configs.ts` holds the credential configurations, which both the
issuer and the authorization server read. `oid4vc/vc_offers.ts` holds the
Credential Offer's pre-authorized codes, which are *minted* by the offer pages
and *redeemed at the token endpoint*, so that state cannot live in either
OID4VCI or OAuth 2.0 without the two requiring each other. A require cycle in
node does not fail loudly: it hands back a half-initialised module whose exports
are `undefined`, and the symptom arrives later as something that is not a
function. Five helpers (`userFor`, `parseBody`, `oauthError`, `vciError`,
`signJwt`) are in `common/helpers.js` for the same reason, not because they are
especially general.

**Some modules are libraries: they register nothing.** Their place in the
require order does not matter, and they are kept small in what they require so
that they cannot join a cycle.

* `oauth-oidc/dpop.ts` requires only `helpers.js` and npm packages.
* `common/admin_stats.js` needs the property more: it is called from `app.js`'s
  call log, from `signJwt()`, from both SAML assertion builders, from the KDC
  and from the credential issuer, so anything it required, all of those would
  require in turn. Where it needs something it cannot require, the owner of
  that thing fills a slot in it instead.
* `authn/webauthn.js` falls back to a silent logger when `helpers.js` is not
  resolvable. The parent project's cross-implementation test copies that one
  file next to its own scripts, and a verifier written to be checked by
  somebody else has no business dragging the service in behind it.

One file in the tree is not a module at all: `mgmt-api/admin_api_explorer.js`
is browser code, read off disk and served verbatim at
`/admin/api-explorer/explorer.js`. Nothing in node requires it.

### The Kerberos files are a stack

Bottom up, the codec files in `kerberos/` are:

| File | What it holds |
|---|---|
| `krb5_primitives.js` | What no runtime provides: CTS, RC4, MD4, MD5 |
| `krb5_crypto.js` | The RFC 3961 framework and the encryption types |
| `krb5_asn1.js` | DER for RFC 4120's ASN.1 |
| `krb5_messages.js` | The messages, the pre-authentication and the [MS-SFU] structures |
| `krb5_ndr.js`, `krb5_pac.js` | The PAC, which arrives in Windows' RPC marshalling rather than in ASN.1 |
| `krb5_principals.js` | The principal database, salts and PAC identities |
| `krb5_gss.js` | The RFC 4121 framing a real service is handed |
| `krb5_kdc.js` | The KDC |
| `krb5_service.js` | The acceptor |

Only the last two register anything. All of these files come from the parent project
and are not edited here. [Kerberos](kerberos.md) covers what the KDC does.

**Kerberos bends two rules.** Its modules register their HTTP views like
everything else, but their **sockets are started by an exported `listen()`**
that `server.js` calls: a route cannot fail to register, and binding a
privileged port can. The same holds for every socket owner (LDAP, SPIFFE, the
plain-HTTP revocation listener, the embedded debugger), which is why a listener
that fails to bind is recorded rather than fatal.

And the codec files that **also run in the browser** (everything except
`krb5_principals.js`, `krb5_kdc.js` and `krb5_service.js`, which reach for
`helpers.js`, `net` and `dgram`) must not `require("crypto")` at all. They are
staged into the parent project's client tree and bundled by browserify, which
substitutes a bare `require("crypto")` with crypto-browserify and ships
`elliptic` (GHSA-848j-6mx2-7j84, no patched version) into the bundle. So the
codec is written against `globalThis.crypto.subtle`, which is why every
function in `krb5_crypto.js` is async, and why MD5 and RC4 are written out by
hand in `krb5_primitives.js` even though node has both: Web Crypto does not,
and one module that behaves differently in the two places is worse than one
that is slower in both.

That sharing is the opposite arrangement from `webauthn.js` and `bbs2023.js`,
deliberately. A codec has to produce the same bytes wherever it runs, so the
tests over it are a **round-trip oracle** (re-encoding what was read) and
byte-level pinning, rather than two implementations agreeing with each other.

## Signing keys

In development mode a realm's signing keys are regenerated on every start; in
product mode they are generated once and kept, sealed, in the persistence store
(see [the directory and the key material](#the-directory-and-the-key-material-over-their-stores)).
Two consequences follow, and both are deliberate.

* **The `kid` is derived from the key material** (`sts-` and the start of a
  SHA-256 digest of its certificate) rather than being a constant. Two
  instances, such as a stale container beside a fresh one, cannot both claim
  the same `kid` over different keys and make "the signature does not verify"
  look like a corrupt document instead of the wrong issuer. `keys.kidFormat`
  can name keys by their RFC 9278 JWK Thumbprint URI instead.
* **Every document that carries or describes a key is served
  `Cache-Control: no-store`**: RFC 8414 metadata, OID4VCI credential issuer
  metadata, `jwt-vc-issuer`, the JWKS, the DID document and the DID
  Configuration. A cached copy outlives the key it describes.

Every JWT this service issues is signed with the realm's key, so it verifies
against the realm's advertised JWKS. Access tokens are RS256 by default
(`oauth2.accessTokenSigningAlg`; PS256 under FAPI 1.0 Advanced).

## One crypto module

**Every signature, verification, encryption and decryption in this service goes
through one module, `common/crypto.js`.** Scattered implementations (XML
signers and verifiers, the halves of a JWE, JWK thumbprints, self-signed
certificate builders, constant-time comparisons) can each be correct on the day
they are written; what they cannot do is stay correct together.

Three things it holds are worth knowing as a *user* of this service:

* **The XML signer is the debugger's own**, vendored byte-identical into
  `common/vendored/xmldsig.js`. Both ends of a SAML or WS-Federation exchange
  with this service canonicalize with the same code. That matters because a
  disagreement about canonicalization is invisible until it is a signature
  that verifies on one side and not the other.
* **A verifier is always told which element it is checking.** A SAML Response
  carrying a signed assertion has two signatures. Asking "is this Response
  signed by us" and being answered about the assertion is a step away from
  accepting a response whose assertion was swapped. A signature whose reference
  names a different element is refused outright.
* **The reference always names the element's real id**: `ID`, `AssertionID`,
  `ResponseID` or `RequestID`. Nothing is ever invented.

The OpenID4VCI endpoints read this service's own access tokens back with the
configured `oauth2.clockSkewS` allowance, like every other reader, so a token
that introspects active is not refused at a credential endpoint seconds early.

`tests/crypto_module.js` checks the whole surface against `xml-crypto`, an
independent implementation, in both directions.

## The JSON-LD contexts are not optional

`common/vendored/bbs2023.js` reads the three files in
`common/vendored/contexts/` **when it is loaded**, at module scope. A missing
one is not a degraded feature: the service does not start at all. They are
vendored rather than fetched because a signature is computed over canonicalized
statements. A one-byte difference in a context fails every signature later,
which looks like a crypto bug and is not one.

## Origins

This service was extracted from the
[OAuth2/OIDC Debugger](https://idptools.com). Two things were adapted rather
than copied:

* the **Dockerfile**, whose `COPY` paths were relative to the parent
  repository's root and are now relative to this one;
* the **JSON-LD contexts**, which live in the parent project's client tree.
  `bbs2023.js` resolves two layouts, and a sibling `contexts/` directory is its
  second candidate, so no code changed. That is also why the contexts sit
  beside `bbs2023.js` in `common/vendored/` rather than anywhere else: keeping
  them a sibling is what lets a vendored file stay byte-identical.

The protocol suite is written in the parent project and a copy of it runs here,
in `tests/vendored/`; jobs that only this service needs are written here and
marked `local: true`. Some of the parent's tests are interesting for *how* they
check rather than what: the Kerberos codec tests use the codec's own symmetry as
a round-trip oracle, pin every byte of the 0x8003 checksum and cover the RFC
3961 encryption types against published test vectors, and the WebAuthn
cross-implementation test runs `webauthn.js` and the debugger's own independent
decoder over the same real ceremonies and requires the same verdict from both.
That last one is why `webauthn.js` must stay loadable on its own.

**WS-Federation's tests are thin**, which is worth saying plainly because the
mock relying party makes it *look* covered: `/wsfed/rp` verifies a sign-in
response check by check and shows every verdict, but a person has to click it
and read the page. `tests/wsfed_wauth_step_up.js` holds the `wauth` step-up and
its refusals. What a real test would add is the other negatives: a `wctx` that
came back altered, `wfresh` read as seconds, and an assertion whose signature
reference does not resolve because the SAML 1.1 id attribute was not named. A
passive requestor that issues a good token and posts it to a working relying
party looks finished and proves almost nothing.
