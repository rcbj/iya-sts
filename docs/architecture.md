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
| 8081 HTTPS | The main port: every path-based protocol, `/admin`, `/portal` and `/admin-api`. It asks every connection for a client certificate and requires none; `GET /tls/sign-in` signs the holder of a verified one in (the separate 8443 and 9443 TLS endpoints were removed on 2026-09-16) |
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
a directory of its own in the repository. Requiring a module registers its
routes, so the order in which they load is also the order in which routes
match.

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
