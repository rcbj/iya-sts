---
title: iya-sts
nav_order: 1
---

# iya-sts

An identity service that speaks **nineteen protocol families** in one small
Node process, in one of two modes (`global.mode`).

**Development mode, the default, exists to exercise *clients*:** it checks no
end user's password, creates whoever and whatever a request names, and accepts
tokens it cannot verify at the doors where a client under test needs to. A
client that has only ever met a permissive server has never run its own refusal
paths — and a client that has only met a strict one cannot reproduce the
behaviour it is trying to detect.

**Product mode is meant to be deployed:** it verifies every password, creates
nothing because something named it, invents no claim value, and implies RFC
9700 mode. Neither mode attests a workload.
[What is not checked](what-is-not-checked.md) says exactly where the line is in
each.

## Index of pages

Every page on this site, grouped by what a reader is looking for.

**Using it**

- [Getting started](getting-started.md) — running it, the ports, the container
- [Architecture](architecture.md) — the diagram, layer by layer: the leader process and its listeners, the dispatcher and worker pools, the subsystems and hosted surfaces, the session every artifact is projected from, and the stores underneath
- [Configuration](configuration.md) — every setting, and which can change at runtime
- [Endpoints](endpoints.md) — how to find out, rather than a list that goes stale
- [Trust realms](trust-realms.md) — several logical identity services in one process, told apart by a path segment: what each one separates, and what every realm shares
- [What is not checked](what-is-not-checked.md) — what development and product mode each check, what neither does, and the features that refuse in both
- [Accepted tokens](accepted-tokens.md) — every door that takes a token from a caller, what the token must be, and the one place a token from another issuer still gets through
- [Error codes](error-codes.md) — every way this service can fail or refuse, by subsystem: the `STS-…` code recorded on the audit row and in the log, and what the client is told instead (a code is never sent to a client)

**Sessions and signals**

- [Sessions](sessions.md) — what a session IS here: the browser sign-on session every protocol shares, the Kerberos TGT, the LDAP connection, the five things that are not sessions, and the six places one is visible
- [Signing out](signing-out.md) — `/logout`: one list of everything you are still signed into, across every family, and what cannot be ended
- [CAEP events](caep-events.md) — the eight Continuous Access Evaluation Profile events: which activities in this service emit each one, which five nobody here can cause and how to send those by hand, and the three gates every event passes on its way to a receiver
- [Signals received](signals-received.md) — the admin console and the user portal are registered Shared Signals receivers of this service's own transmitter: why the delivery is a real HTTP push rather than a function call, the five reasons an inbox is empty, and what a person is shown about themselves and never about anybody else

**Assertions at the token endpoint**

- [JWT assertions](jwt-assertions.md) — RFC 7521 and RFC 7523: a signed JWT instead of a client secret, and instead of an authorization code — two uses of one format, and why they are not the same feature
- [SAML 2.0 assertions](saml-assertions.md) — RFC 7521 and RFC 7522: the same framework's other profile, a separate implementation, and a separate key pair per application that cannot sign for the JWT one

**Authorization**

- [GNAP](gnap.md) — an RFC 9635 authorization server per trust realm, with RFC 9767's resource server connections: a grant that starts from a key and is negotiated rather than redirected
- [Remote PEP](remote-pep.md) — the second container: a remote XACML Policy Enforcement Point that pulls this service's policy repository and decides in its own process, with a worked authorization decision for an application

**Certificates**

- [PKI](pki.md) — the certificate authority at `/admin/pki`: one Root for the service, an Intermediate per trust realm, an Issuing CA per use case, and every key pair this service generates as a leaf of it
- [ACME](acme.md) — an RFC 8555 server per trust realm: accounts bound for life to one person or application by an External Account Binding key, identifiers authorized from the directory with no challenge dialling out, the nine certificate profiles, revocation and RFC 9773 renewal information, with certbot and acme.sh examples
- [EST](est.md) — an RFC 7030 server per trust realm: a PKCS#10 request from an authenticated device, person or application, answered from the realm's EST Issuing CA and kept on the directory entry it names
- [SCEP](scep.md) — an RFC 8894 server per trust realm: a device with a single-use challenge password, a signed and encrypted request, and a certificate from the realm's SCEP Issuing CA

**Operating it**

- [Persistence](persistence.md) — what survives a restart and what never can: three modes, and the reason nothing this service mints is ever written down
- [Encryption at rest](encryption-at-rest.md) — the two different questions behind that phrase: what this service seals before a value reaches a store (and why there is ONE key for every trust realm rather than one each), and what encrypts everything else — LUKS, ZFS, cloud disks, the forks that have TDE, and why column-level encryption leaves plaintext in the WAL
- [Caches](caches.md) — everything this service remembers instead of working out or fetching again, and every replay store that makes a one-time value work once: what each holds, how long, the setting that bounds it, and the windows in which an answer can be out of date
- [A cluster in AWS](aws-cluster.md) — three active-active nodes on ECS Fargate across three availability zones behind a Network Load Balancer, RDS PostgreSQL 18 with a read replica, the key and database password in Secrets Manager: the Terraform, what it costs, and the workflow that brings one up, runs the suite and tears it down

**For contributors**

- [Repository layout](layout.md) — where the code is
- [Parent project migration](parent-project-migration.md) — what the OAuth2/OIDC Debugger, of which this repository is a submodule, needs when its `sts/` pin is bumped: the paths it reaches in by, and the COPY set that has to follow every new require

## Start here

```bash
git clone --recursive https://github.com/rcbj/iya-sts.git
cd iya-sts
docker build -t iya-sts .
docker run --rm -p 8081:8081 iya-sts
```

It runs from an image: part of the service is TypeScript, compiled while the
image is built, and a checkout does not run on its own.

**https, and your browser will warn you once.** Every appconfig file here sets
`global.https`, so the main port is TLS on the same self-signed certificate the
LDAPS 636 listener uses — one pair, regenerated on every start,
so nothing can have trusted it in advance. Accept it, or fetch it with
`curl -k https://localhost:8081/tls/server-certificate`; `STS_HTTPS=false` runs
the plain port this used to be.

Then open <https://localhost:8081/> — a front page with the five things worth
having on one: this repository, its issues, this site, and the two surfaces on
that instance that a person rather than a client goes to — the admin console,
and the user portal at `/portal`, which is that instance's account page for
whoever signs in to it. Its Overview draws **every standard inetOrgPerson
attribute** the signed-in person's directory entry could hold — all fifty,
grouped by the three object classes a person here is filed under, with the LDAP
attribute name and the RFC printed under each value, because the reason to read
it on a mock is usually to find out what something is called before writing it
over LDAP.

The page worth going to next is <https://localhost:8081/admin/sts-metadata> —
every protocol this service speaks, and every endpoint it registers, read off
the live Express router, with a sentence about each and a link to the
specification it implements. It is a page of the admin console, so it asks you
to sign in first: in development mode any username will do, because no password
is checked; in product mode sign in as the bootstrap administrator `admin`,
whose password is written to the log once at the first start unless
`admin.bootstrapPassword` supplied one.

[Getting started](getting-started.md) has the rest: the ports, the container, and
what to do when 389 or 88 will not bind.

## Architecture

One leader process owns every listener, and a request dispatcher hands work
from it to three worker pools. The protocol subsystems and hosted surfaces
share one session model and one set of services, over an embedded directory
and key material sealed in their stores. [Architecture](architecture.md) has
the diagram and a walk through each layer.

## What it speaks

| Family | Where |
|---|---|
| OAuth 2.0 and OpenID Connect — a full authorization server | `/oauth2/*`, `/.well-known/openid-configuration` |
| DPoP (RFC 9449) and certificate-bound tokens (RFC 8705) | the token endpoint and the four protected endpoints |
| RFC 9700, the Security BCP, as an optional MODE | `GET /oauth2/rfc9700` |
| OAuth 2.1 (draft-16) as an optional MODE, which turns the one above on | `GET /oauth2/oauth21` |
| WS-Trust 1.0 – 1.4 | `/wstrust` |
| WS-Federation 1.2, passive requestor, with a mock relying party | `/wsfed`, `/wsfed/rp` |
| SAML 2.0 Web Browser SSO — a full identity provider, all three bindings | `/saml2`, `/saml2/metadata/{sp}`, `/saml2/sp` |
| SAML 1.1 browser profiles — Browser/POST and Browser/Artifact, and an attribute authority | `/saml11`, `/saml11/metadata/{rp}`, `/saml11/rp` |
| SAML 2.0 and SAML 1.1 assertions | inside all four above |
| **Federation** — this service as either end of a relationship with a foreign identity service, in five of those protocols | `/federation`, `/admin/federation` |
| **JWT assertions (RFC 7521, RFC 7523)** — both halves: an assertion instead of a client secret, and an assertion instead of an authorization code | the token endpoint |
| **SAML 2.0 assertions (RFC 7521, RFC 7522)** — the same framework's other profile: a signed `<saml:Assertion>` instead of a client secret, and instead of an authorization code. A **separate key pair per application** from the JWT one, and neither can sign for the other | the token endpoint |
| **A certificate authority** — ONE Root for the service, an Intermediate per trust realm and per the process, an Issuing CA per use case, and **every key pair this service generates as a leaf of it** | `/admin/pki`, `/admin-api/pki` |
| WebAuthn Level 3 over FIDO CTAP2, the relying party's half — a second factor or the only credential on an account | the login screen, `/portal/keys`, `/admin/webauthn` |
| **TOTP (RFC 6238)** — an authenticator app as a second factor, enrolled as a QR code and **genuinely verified** | `/portal/mfa`, `/authn/totp`, `/admin/totp` |
| **Recovery codes** — the way back in when the second factor is not to hand, issued **automatically and once** by the act of enrolling one, and the only mechanism here that no specification defines | `/portal/mfa`, `/authn/backup-code`, `/admin/backup-codes` |
| Kerberos v5 — a KDC, a protected service, and MS-KKDCP | TCP/UDP 88, `/KdcProxy` |
| SPNEGO (RFC 4559/4178) | `/spnego` |
| LDAP v3 (RFC 4511) and LDAPS | TCP 389 and 636 |
| SCIM 2.0 provisioning | `/scim/v2` |
| TLS and mutual TLS — a client certificate asked for and never required, and a sign-in for a verified one | the main port, `/tls`, `/tls/sign-in` |
| SPIFFE — bundle endpoint, Workload API, SPIRE Server API | `/spiffe`, four gRPC sockets |
| OpenID4VCI 1.0 — a Credential Issuer | `/oid4vci/*` |
| OpenID4VP 1.0 — a Verifier, and a sign-in with a wallet in any credential format, through the W3C Digital Credentials API | `/oid4vp/verifier`, `/authn/wallet` |
| Token Status List and W3C Bitstring Status List — what this issuer publishes about what it issued | `/oid4vci/status-lists*`, `/admin/vc-status` |
| W3C DID Core with DIF domain linkage | `/.well-known/did.json` |

## The four things to know before you rely on it

**In development mode nothing you would miss persists.** The signing keys and
the certificate authority are regenerated on every start — deliberately, so that
a client cannot cache a key it should be re-fetching — and every document that
carries a key is served `Cache-Control: no-store`. Product mode keeps them,
sealed under a key-encryption key; [persistence](persistence.md) says what
survives in each.

**Every surface tells you what it does not do.** That is not modesty; it is the
point. `GET /oauth2/rfc9700` publishes every BCP requirement with `yes`,
`detected`, `always`, `deployment` or `no` and the reason. `GET /spiffe` names
the six of forty-two SPIRE methods that are unimplemented and why each one is.
`GET /admin/ldap/service` says the directory is schemaless. A mock that quietly pretended
would teach you something false about every real server you will ever meet.

**The admin console at `/admin` asks for a sign-in and a role** — unconditionally,
with no setting that opens it — and the roles are two ordinary groups in the
embedded directory. In development mode it is a turnstile and not a lock: no
password is checked, so anybody who can reach this port can sign in as anybody.
In both modes, until the bootstrap administrator `admin` first signs in, anybody
who signs in holds both roles. The console can revoke tokens, add claims to every
future token and assertion, and create people in the directory. Do not put a
development-mode instance on a public address.

**`/admin-api` requires an OAuth 2.0 access token** since 2026-09-09 —
audienced to this API, carrying `admin:read` to read and `admin:write` to
change anything. Ask the token endpoint for one with the client-credentials
grant as the seeded `sts-management-api` client, whose secret is
`adminApi.clientSecret`, and send `resource=<base>/admin-api` so the audience is
right. `adminApi.authRequired=false` opens the API in development mode; in
product mode it falls back to the console's session and roles.

**Federation is the one feature that refuses by default, and that is deliberate.**
Everywhere else this service accepts what it is given. It cannot do that where it
CONSUMES somebody else's assertions: `/federation/acs/{id}` receives an
unauthenticated HTTP request claiming to be a person, and the session it would
produce is the same one every other protocol here reads — so "accept anything"
would be an authentication bypass for the whole process rather than a permissive
mock. A relationship must be configured, is created disabled, and refuses an
assertion that does not verify against the certificate configured on it. **The
gate is on the signer, not the subject**: any person a partner asserts is
accepted — created on first sight in development, required to exist already in
product. See [what is not checked](what-is-not-checked.md).
