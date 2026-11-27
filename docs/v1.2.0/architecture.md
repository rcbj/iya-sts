---
title: Architecture
nav_order: 2
---

# Architecture

[![iya-sts architecture, one node: the front process and its listeners, the request dispatcher, the scheduler and the libuv thread pool; the request and surface worker pools; the protocol stack with its protocol families and hosted applications over one session; the shared services; and the embedded directory and key material over the persistence store and the secret store](architecture.svg)](architecture.svg)

*Select the diagram for full size.* It shows one node. The sections below go
through it from top to bottom.

## The front process and its listeners

**One node process owns every socket.** That covers the HTTPS main port, any
custom listeners, LDAP and LDAPS, the Kerberos KDC, the SPIFFE gRPC ports and
the Workload API's domain sockets. A socket can't be handed to another thread
or process, so every listener stays in the front process, including when the
worker pools are on. (In a cluster, one front process is also the scheduler's
*leader*; that is a different role, described
[below](#periodic-work-is-a-scheduler-job).)

| Listener | What is on it |
|---|---|
| 88 TCP / UDP | The Kerberos KDC |
| 389, 636 | The embedded directory, over plain LDAP and over LDAPS |
| 8081 HTTPS | The main port: every path-based protocol and every hosted application. It asks every connection for a client certificate and requires none; `GET /tls/sign-in` signs the holder of a verified one in. There are no separate 8443 and 9443 TLS ports any more |
| Custom listeners | More HTTPS ports, each with its own address, certificate, TLS policy and client authentication, answering the hosted applications you map to it. [Listeners](listeners.md) |
| 8082 HTTP | `/pki/` only: CRLs, OCSP and CA certificates, in plain HTTP as relying parties expect |
| 8444 HTTPS | The embedded protocol debugger, on an origin of its own |
| 8092, 8181 gRPC | The SPIFFE Workload API (product mode binds 8092 only where the network authenticates source addresses; an AWS cluster does not publish it), and the SPIRE Server API (always mutual TLS) |
| Domain sockets | The Workload API at `/tmp/spire-agent/public/api.sock` (on), and the SPIRE Server API's private socket at `/tmp/spire-server/private/api.sock` (off by default) |

[Getting started](getting-started.md#the-ports) lists every port with its
setting.

**A listener that fails to bind is recorded, not fatal.** The rest of the
service keeps running, and each socket reports its own state. The persistence
store is the one exception: if it can't be opened, the service doesn't start.

## The request dispatcher and the worker pools

The dispatcher hands work from the front process to worker threads, each a
`worker_threads` Worker inside the same process with its own JavaScript heap
and event loop:

| Pool | What a worker runs | Setting | Default |
|---|---|---|---|
| **Request** | The whole protocol stack, the hosted applications included | `workers.requestCount` | 1 where the store coordinates (PostgreSQL); 0 on the memory or LDIF store |
| **Surface** | Only the admin console and the user portal, when you want them kept apart from protocol traffic | `workers.surfaceCount` | 0 (off: they go to the request workers) |

The sockets that do not speak HTTP hand their work to the same workers as
*operations*: the front process keeps the connection and the framing and a
worker answers the request. That covers every LDAP operation, every message to
the KDC on port 88, the unary SPIFFE Workload and SPIRE Server API calls, and
the Broker API's FetchJWTSVID once the front process has attested the workload
it names. Streams stay in the front process.

`workers.dispatch` (default `*`, everything) says what goes to a worker, and
`workers.readYourWrite` (default `session`) makes a worker catch up with the
writes a request depends on before it answers; [Where a request
waits](request-path.md) follows a request through every wait on the way.
**Batch traffic has a lane of its own**: SCIM and the Shared Signals receive
endpoints (`workers.batch`) may use only a share of each pool
(`workers.batchWorkerShare`) and a bounded number in flight, so a bulk load
cannot take every worker; [Availability](availability.md) has the limits.

Every worker is a whole second copy of the service's memory, so one is the
default; add more only where the node has the cores to use them.

Post-quantum signing, verification and key generation, and password
hashing, are not a pool. They run natively on Node's OpenSSL, on libuv's
thread pool, so they neither freeze the listeners nor need a thread of their
own.

With the pools off, the front process answers every request itself. When they
are on, **the first worker starts alone and the rest start as many at once as
memory allows** (`workers.startConcurrency`, default 0): what the first start
added to the process is measured, and the others start together as far as the
room under the container's limit holds at one and a half starts each. A number
from 1 up fixes the width; 1 starts them one at a time. The listener opens once
the first worker of each pool is up, and the rest start behind it. **Every
thread has a heap limit** derived from the container's memory limit and the
number of threads (`workers.heapLimitMb`: 0 to derive, -1 for none). Each
thread records its memory every five minutes (the `process.memory-report`
job); Monitoring → Scheduler shows the latest. A worker whose heap reaches its
limit ends on its own and is replaced, and the service goes on
(`STS-WORKER-0046`); a container that reaches its memory limit loses the whole
process, which is why few threads are better than many.

Monitoring → Worker Pools (`/admin/worker-pools`) shows each pool of the node:
its workers now, busy and free, its maximum and initial size, its crashes and
restarts, and its average response time. Monitoring → Node Health
(`/admin/node-health`) shows the container's CPU and memory, the process's,
and each worker thread's heap.

When they are on, the front process and the workers share state through the
persistence store and not through memory. For that reason, asking for workers
explicitly without
[coordination](persistence.md#processes-against-one-store-coordinate) is refused
at startup: it would give wrong answers, not just slow ones. The default of one
worker simply becomes none on a store that can't coordinate.

**Several nodes work the same way.** A cluster is several containers against
one PostgreSQL store. [A cluster in AWS](aws-cluster.md) shows three of them
behind a load balancer, and [How the cluster works](cluster-concepts.md)
explains how they agree.

**The caches** are what the service remembers instead of working out or
fetching again, plus the replay stores that make one-time values work only
once. Each thread has its own. [Caches](caches.md) lists each one, how long it
holds a value, and the setting that bounds it.

## Periodic work is a scheduler job

**Anything the service does on a timer is a job on one scheduler**: key and
certificate rotation, CRLs, deliveries, report runs, risk dataset refreshes,
and clearing expired cache entries. No module starts a timer of its own.

* A **cluster** job runs once, on one node. The scheduler's leader holds a
  lease and hands the job to another node when that one goes; the body itself
  runs on the node's least-loaded request worker unless the job must run in
  the front process.
* A **per-process** job runs in every thread that holds the state it cleans,
  such as a cache's expired entries, because nothing else can reach that
  state.

Monitoring → Scheduler (`/admin/scheduler`) lists every job, when it last ran
and where, and lets you switch one off.
[How the cluster works](cluster-concepts.md#7-the-scheduler-each-job-runs-once-on-one-node)
explains the leases and fences.

## The protocol stack

**One composition root, `common/protocol_stack.ts`, registers every route, in
one order**, and that order is the order in which routes match. The front
process and every worker load the same file, so they cannot disagree about
which handler wins. See
[How the code is put together](#how-the-code-is-put-together).

### Protocol families

Each box is a protocol family, or a group of closely related ones, and each has
a directory of its own in the repository.

| Family | Read more |
|---|---|
| OAuth 2.0, OpenID Connect | The authorization server and OpenID provider: `/oauth2/*`. [OAuth 2.0 and OpenID Connect](oauth-oidc.md), [JWT assertions](jwt-assertions.md) |
| SAML 2.0, SAML 1.1 | Each with its own identity provider. [SAML 2.0](saml2-sso.md), [SAML 1.1](saml11.md), [SAML assertions](saml-assertions.md) |
| WS-Trust, WS-Federation | `/wstrust`, `/wsfed`. [WS-Trust](ws-trust.md), [WS-Federation](ws-federation.md) |
| Federation | Either end of a relationship with a partner, in five protocols. [Federation](federation.md) |
| OpenID Federation 1.1 | Entity statements and trust chains. [OpenID Federation](oidfed.md) |
| Kerberos, SPNEGO | A KDC per trust realm on the shared port 88, told apart by the Kerberos realm name in each request, plus MS-KKDCP. SPNEGO signs a person in with a Kerberos ticket. [Kerberos](kerberos.md) |
| LDAP | The directory's socket view of the embedded store below. [LDAP](ldap.md) |
| SCIM | `/scim/v2`, provisioning into the same directory, and an outbound client. [SCIM](scim.md) |
| SPIFFE | A trust domain per realm: the bundle endpoint, the Workload API and the SPIRE Server API. [SPIFFE](spiffe.md) |
| TLS | Certificate sign-in on any HTTPS listener. [TLS](tls.md) |
| PKI / X.509 | One Root, an Intermediate per realm, CRLs and OCSP. [PKI](pki.md) |
| ACME, EST, SCEP | Certificate enrollment through the PKI. [ACME](acme.md), [EST](est.md), [SCEP](scep.md) |
| OpenID4VCI, OpenID4VP, DID | Verifiable credentials, issued and verified, and the wallet sign-in. [Verifiable credentials](verifiable-credentials.md) |
| WebAuthn, TOTP, recovery codes | The second factors and passkeys. [Passkeys](passkeys.md), [The sign-in service](authentication.md) |
| SSF, CAEP, RISC | Shared Signals: a transmitter and a receiver. [Shared Signals](shared-signals.md) |
| XACML, ALFA | The PDP, the policy repository and the embedded PEPs. [XACML](xacml.md), [Remote PEP](remote-pep.md) |
| AuthZEN | The AuthZEN Authorization API, over the XACML engine. [AuthZEN](authzen.md) |
| GNAP, UMA | [GNAP](gnap.md) (RFC 9635) and [User-Managed Access 2.0](uma.md) |
| Risk scoring | Scores a sign-in from its datasets; policy decides. [Risk scoring](risk-scoring.md) |
| Attribute sources | Operators' SQL databases a realm reads attributes from. [Attribute sources](attribute-sources.md) |

The live list is at `/admin/sts-metadata`. It reads every protocol and endpoint
off the running router, so it can't go out of date. [Endpoints](endpoints.md)
explains how to read it.

### Hosted applications

| Application | Path | Its API |
|---|---|---|
| Sign-in service | `/authn`: the sign-in screen and the second factors. **It owns the session** | `/authn-api` ([The sign-in API](authn-api.md)) |
| Admin console | `/admin`, the operator console | `/admin-api` ([Management API](management-api.md)), which machines call too |
| User portal | `/portal`, the pages that belong to the person signed in | `/account-api` ([Account API](account-api.md)) |
| Reports | `/report` | `/report-api` ([Reports](reporting.md)) |
| Front door, sign-out, launch | `/`, `/logout`, `/launch/{app}` (the identity-provider-initiated link per application) | — |
| Debugger | The embedded protocol debugger, on its own listener and origin (8444), open only to console administrators | — |

**The applications are static.** Each `/admin/*`, `/portal/*` or `/report/*`
path answers one document and one script, and the page is drawn in the browser
from its API: everything it shows comes from an API answer and everything it
changes goes through an API call. The console, the portal and the reports
application sign in **in the browser, as public OAuth clients of this
service's own authorization server**, with PKCE and a DPoP-bound access token
held in memory. Every API answer is checked against its published OpenAPI
model before it is sent ([Management API](management-api.md)).

A specification's own pages — auto-POST forms, the OP iframe, front-channel
logout — stay server-drawn, exactly as the specification describes them.
[User-facing pages](user-facing-pages.md) lists every page a person can see.

### Tokens, assertions, tickets and credentials, over one session

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
| Crypto | `common/crypto.js`, the one module that signs, verifies, encrypts, decrypts, hashes and imports keys. See [One crypto module](#one-crypto-module) |
| Certificate trust | One validation door for every certificate the service is shown, with a signer truststore per realm and, in product mode, paranoid PKI checks. [Signer truststore](signer-truststore.md), [PKI](pki.md) |
| Audit and logging | One audit log per trust realm, exportable to your own destinations ([Audit export](audit-export.md)). Every failure is recorded with an [error code](error-codes.md), which is never sent to a client. Logs are structured, `info` by default and `debug` for the full record |
| Configuration | Five levels of configuration, many settings changeable at runtime and per realm. [Configuration](configuration.md) |
| Mail | Sending only, for codes, links and notices. [Mail](mail.md) |
| Metadata and monitoring | `/admin/sts-metadata` and `/admin/crypto-metadata`, both generated from the running service, and the console's Monitoring section |

## The directory and the key material, over their stores

**The embedded LDAP directory** holds people, groups, applications, roles and
policies. It has one tree per trust realm, rooted at the realm's DNS domain
(`iyasec.io` is `dc=iyasec,dc=io`; the default realm's is `global.domain`). LDAP
on 389/636, SCIM, the admin console and `/admin-api` are views of the same
store. What each object holds is described once, in an
[abstract data model](data-model.md) the service is built from.

Everything is written to the **persistence store**: `memory`, `ldif`, or a SQL
database (PostgreSQL, or MariaDB). Only a SQL store lets several threads or
nodes coordinate. [Persistence](persistence.md) covers what survives a
restart in each.

**Key material**, meaning signing keys and the certificate authority, depends on
the mode. In development mode it is regenerated on every start. In product mode
it is generated once, kept in the persistence store and **sealed under a
key-encryption key that the service never generates**. That key is read from a
**secret store**: OpenBao in the compose stack, or the cloud's secrets manager in
a cluster. [Encryption at rest](encryption-at-rest.md) and
[Key management](key-management.md) cover both.

## What the diagram does not show: trust realms

A trust realm is a separate logical copy of the service, with its own
configuration, keys, sessions, directory subtree, administrators and audit log.
All realms share this one process and its sockets, and a path prefix tells them
apart (`/realm/acme/oauth2/token`). The process-level parts are shared by every
realm: the listeners and worker pools, the persistence store and the
key-encryption key.

**A shared socket does not always mean a shared service.** Where the protocol
carries a name of its own, a realm gets its own service on the same port: the
directory is told apart by DN on 389 and 636, and **Kerberos by the realm name
inside each request** — a realm with its own `krb5.realm` has a KDC, a principal
database and keys of its own on port 88. SPIFFE is the other way round, told
apart by the address its sockets are bound to. A client certificate at the TLS
handshake carries no realm, so a certificate sign-in goes to the realm whose
authority signed it. [Trust realms](trust-realms.md) covers what a realm
separates and what it doesn't.

## How the code is put together

The service is split by protocol family into directories (the tables above),
and at the package root there are only two modules. `server.js` is the shell: it
loads the protocol stack and listens. `sts_metadata.ts` reads the router to
list what everything else registered, so it is loaded last.

**Most of the service is TypeScript, and it runs from an image.** The
TypeScript is compiled only inside the image build; `node server.js` on a
source checkout refuses to start and says why. `docker build` (or the published
image) is how it runs; [Getting started](getting-started.md) has the commands.

**One composition root registers every endpoint, in one order.**
`common/protocol_stack.ts` requires each module and registers its routes
against the shared express app from `common/app.js`. A module written in
TypeScript registers nothing when it is required: it exports
`registerRoutes(app)`, and the composition root calls it at the place in the
sequence where its routes belong. The modules still written in JavaScript (the
three Kerberos route modules, `tls/tls_server.js` and `ldap/ldap_server.js`)
still register when they are required, and the composition root requires them
at their places, so the two kinds interleave in a fixed order. That order is
the order in which routes match. The middleware lives in `app.js` because
express applies middleware only to routes added after it. The request workers
load the same file without binding any socket, so the front process and the
workers cannot disagree about which handler wins.

**The model comes first.** Directory objects, PostgreSQL tables and every
published API's request and answer bodies are written once in TypeSpec under
`models/`, and the image build generates what the service reads from it. An
answer that does not match its model is refused with a 500 rather than sent.
[Abstract data model](data-model.md) explains the namespaces.

**Some modules exist to break require cycles, not to group code.**
`oid4vc/vc_configs.ts` holds the credential configurations, which both the
issuer and the authorization server read. `oid4vc/vc_offers.ts` holds the
Credential Offer's pre-authorized codes, which are *minted* by the portal's
offer and *redeemed at the token endpoint*, so that state cannot live in either
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
| `krb5_spnego.js` | The RFC 4178 SPNEGO codec |
| `krb5_kdc.js` | The KDC |
| `krb5_service.js` | The acceptor |

Only the last two register anything; the TypeScript modules beside them add
FAST, PKINIT, delegation, cross-realm trusts and keytabs. These files began as
copies of the parent project's codec and have been this service's own since
#1280. [Kerberos](kerberos.md) covers what the KDC does.

**Kerberos bends two rules.** Its modules register their HTTP views like
everything else, but their **sockets are started by an exported `listen()`**
that `server.js` calls: a route cannot fail to register, and binding a
privileged port can. The same holds for every socket owner (LDAP, SPIFFE, the
plain-HTTP revocation listener, the embedded debugger), which is why a listener
that fails to bind is recorded rather than fatal.

And the codec is written against `globalThis.crypto.subtle` rather than node's
`crypto`, because it was written to run unchanged in a browser as well. That is
why every function in `krb5_crypto.js` is async, and why MD5 and RC4 are written
out by hand in `krb5_primitives.js` even though node has both: Web Crypto does
not, and one module that behaves differently in two places is worse than one
that is slower in both. A codec has to produce the same bytes wherever it runs,
so the tests over it are a **round-trip oracle** (re-encoding what was read) and
byte-level pinning against published test vectors.

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
(`oauth2.accessTokenSigningAlg`; PS256 under FAPI 1.0 Advanced), and
`keys.signingAlgorithms` narrows a realm to the algorithms you name.

## One crypto module

**Every cryptographic operation in this service — signing, verification,
encryption, decryption, hashing and key import — goes through one module,
`common/crypto.js`**, over the engines in `common/crypto_impl/`. Scattered
implementations (XML signers and verifiers, the halves of a JWE, JWK
thumbprints, self-signed certificate builders, constant-time comparisons) can
each be correct on the day they are written; what they cannot do is stay
correct together.

Three things it holds are worth knowing as a *user* of this service:

* **The XML signer began as the debugger's own**, copied into
  `common/crypto_impl/xmldsig.js`. Both ends of a SAML or WS-Federation exchange
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

`common/crypto_impl/bbs2023.js` reads the three files in
`common/crypto_impl/contexts/` **when it is loaded**, at module scope. A missing
one is not a degraded feature: the service does not start at all. They ship
with the service rather than being fetched because a signature is computed over
canonicalized statements. A one-byte difference in a context fails every
signature later, which looks like a crypto bug and is not one.

## Origins

This service was extracted from the
[OAuth2/OIDC Debugger](https://idptools.com). Since #1280 nothing is copied
between the two in either direction: the crypto engines, the Kerberos codec and
`authn/webauthn.js` are this service's own.

The protocol suite was written in the parent project and a copy of it runs here,
in `tests/protocol/`; jobs written for this service are marked `local: true`,
and new ones are written here. Some of the tests are interesting for *how* they
check rather than what: the Kerberos codec tests use the codec's own symmetry as
a round-trip oracle, pin every byte of the 0x8003 checksum and cover the RFC
3961 encryption types against published test vectors, and the WebAuthn
cross-implementation test runs `webauthn.js` and the debugger's own independent
decoder over the same real ceremonies and requires the same verdict from both.

**WS-Federation's tests are thin**, which is worth saying plainly.
`sts_saml11.js` posts a sign-in response to the test peer's relying party,
which verifies it, and `tests/wsfed_wauth_step_up.js` holds the `wauth` step-up
and its refusals. What a real test would add is the other negatives: a `wctx`
that came back altered, `wfresh` read as seconds, and an assertion whose
signature reference does not resolve because the SAML 1.1 id attribute was not
named. A passive requestor that issues a good token and posts it to a working
relying party looks finished and proves almost nothing.
