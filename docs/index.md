---
title: mock-sts
nav_order: 1
---

# mock-sts

A mock identity service that speaks **nineteen protocol families** in one small
Node process. It exists to exercise *clients*: it checks no password, validates
no access token and attests no workload.

That last sentence is the whole design, and it is worth reading twice before
using this for anything. A real identity provider refuses things; this one mostly
does not, on purpose, because a client that has only ever met a permissive server
has never run its own refusal paths — and a client that has only met a strict one
cannot reproduce the behaviour it is trying to detect. Where this service *can*
be told to be strict, it can, and [what is not checked](what-is-not-checked.md)
says exactly where the line is.

## Start here

```bash
git clone --recursive https://github.com/rcbj/mock-sts.git
cd mock-sts
npm install
CONFIG_FILE=./env/local.js node server.js
```

**https, and your browser will warn you once.** Every appconfig file here sets
`global.https`, so the main port is TLS on the same self-signed certificate the
8443, 9443 and LDAPS 636 listeners use — one pair, regenerated on every start,
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
to sign in first: any username will do, because no password is checked anywhere
in this service.

[Getting started](getting-started.md) has the rest: the ports, the container, and
what to do when 389 or 88 will not bind.

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
| TLS and mutual TLS reporting | 8443 and 9443 |
| SPIFFE — bundle endpoint, Workload API, SPIRE Server API | `/spiffe`, four gRPC sockets |
| OpenID4VCI 1.0 — a Credential Issuer | `/oid4vci/*` |
| OpenID4VP 1.0 — a Verifier | `/oid4vp/verifier` |
| W3C DID Core with DIF domain linkage | `/.well-known/did.json` |

## The four things to know before you rely on it

**Nothing persists.** Every store is a Map in this process. The signing key is
regenerated on every start — deliberately, so that a client cannot cache a key it
should be re-fetching — and every document that carries it is served
`Cache-Control: no-store`.

**Every surface tells you what it does not do.** That is not modesty; it is the
point. `GET /oauth2/rfc9700` publishes every BCP requirement with `yes`,
`detected`, `always`, `deployment` or `no` and the reason. `GET /spiffe` names
the six of forty-two SPIRE methods that are unimplemented and why each one is.
`GET /admin/ldap/service` says the directory is schemaless. A mock that quietly pretended
would teach you something false about every real server you will ever meet.

**The admin console at `/admin` asks for a sign-in and a role** — unconditionally,
with no setting that opens it — and the roles are two ordinary groups in the
embedded directory.
It is a turnstile and not a lock: no password is checked at that screen either,
so anybody who can reach this port can sign in as anybody and — while neither
role group has a member — hold both roles. The console can revoke tokens, add
claims to every future token and assertion, and create people in the directory.
Do not put this on a public address.

**`/admin-api` requires an OAuth 2.0 access token** since 2026-09-09 —
audienced to this API, carrying `admin:read` to read and `admin:write` to
change anything. Ask the token endpoint for one with the client-credentials
grant as the seeded `sts-management-api` client, whose secret is
`adminApi.clientSecret`, and send `resource=<base>/admin-api` so the audience is
right. `adminApi.authRequired=false` restores the open API, which is what this
paragraph described until that date.

**Federation is the one feature that refuses by default, and that is deliberate.**
Everywhere else this service accepts what it is given. It cannot do that where it
CONSUMES somebody else's assertions: `/federation/acs/{id}` receives an
unauthenticated HTTP request claiming to be a person, and the session it would
produce is the same one every other protocol here reads — so "accept anything"
would be an authentication bypass for the whole process rather than a permissive
mock. A relationship must be configured, is created disabled, and refuses an
assertion that does not verify against the certificate configured on it. **Past
that gate everything is as permissive as the rest**: any username in a verified
assertion is accepted. See [what is not checked](what-is-not-checked.md).

## Pages

- [Getting started](getting-started.md) — running it, the ports, the container
- [Configuration](configuration.md) — every setting, and which can change at runtime
- [Endpoints](endpoints.md) — how to find out, rather than a list that goes stale
- [Trust realms](trust-realms.md) — several logical identity services in one process, told apart by a path segment: what each one separates, and what every realm shares
- [Signing out](signing-out.md) — `/logout`: one list of everything you are still signed into, across every family, and what cannot be ended
- [Sessions](sessions.md) — what a session IS here: the browser sign-on session every protocol shares, the Kerberos TGT, the LDAP connection, the five things that are not sessions, and the six places one is visible
- [CAEP events](caep-events.md) — the eight Continuous Access Evaluation Profile events: which activities in this service emit each one, which five nobody here can cause and how to send those by hand, and the three gates every event passes on its way to a receiver
- [Signals received](signals-received.md) — the admin console and the user portal are registered Shared Signals receivers of this service's own transmitter: why the delivery is a real HTTP push rather than a function call, the five reasons an inbox is empty, and what a person is shown about themselves and never about anybody else
- [Persistence](persistence.md) — what survives a restart and what never can: three modes, and the reason nothing this service mints is ever written down
- [Encryption at rest](encryption-at-rest.md) — the two different questions behind that phrase: what this service seals before a value reaches a store (and why there is ONE key for every trust realm rather than one each), and what encrypts everything else — LUKS, ZFS, cloud disks, the forks that have TDE, and why column-level encryption leaves plaintext in the WAL
- [Caches](caches.md) — everything this service remembers instead of working out or fetching again, and every replay store that makes a one-time value work once: what each holds, how long, the setting that bounds it, and the windows in which an answer can be out of date
- [ACME](acme.md) — an RFC 8555 server per trust realm: accounts bound for life to one person or application by an External Account Binding key, identifiers authorized from the directory with no challenge dialling out, the nine certificate profiles, revocation and RFC 9773 renewal information, with certbot and acme.sh examples
- [Remote PEP](remote-pep.md) — the second container: a remote XACML Policy Enforcement Point that pulls this service's policy repository and decides in its own process, with a worked authorization decision for an application
- [What is not checked](what-is-not-checked.md) — the permissive posture, its three exceptions, and the one feature that inverts it
- [Error codes](error-codes.md) — every way this service can fail or refuse, by subsystem: the `STS-…` code recorded on the audit row and in the log, and what the client is told instead (a code is never sent to a client)
- [Repository layout](layout.md) — where the code is, for contributors
