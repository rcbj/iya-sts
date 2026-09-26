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

## Where to read

The sidebar on every page is the full list, grouped as below. The protocol
pages share one shape — features, what development and product mode change,
every setting with its environment variable and default, and the design
decisions behind the behaviour — so the same question has the same place on
each.

**Start here** —
[Getting started](getting-started.md) ·
[Architecture](architecture.md) ·
[Configuration](configuration.md) ·
[Endpoints](endpoints.md) ·
[Trust realms](trust-realms.md) ·
[What is not checked](what-is-not-checked.md) ·
[Accepted tokens](accepted-tokens.md) ·
[Token samples](token-samples.md) ·
[Error codes](error-codes.md)

**Administration** —
[Admin console](admin-console.md): `/admin`, who may use it and what its pages
do ·
[Applications](applications.md): the registry of every client, relying party
and service provider ·
[Management API](management-api.md): `/admin-api`, every console control
reachable by a machine with an OAuth 2.0 access token.

**Sessions and signals** —
[Sessions](sessions.md) ·
[Signing out](signing-out.md) ·
[Risk scoring](risk-scoring.md) ·
[Devices](devices.md) ·
[Mail](mail.md) ·
[CAEP events](caep-events.md) ·
[Signals received](signals-received.md)

**Operating it** —
[Persistence](persistence.md) ·
[PostgreSQL schema](postgres-schema.md) ·
[LDAP schema](ldap-schema.md) ·
[Encryption at rest](encryption-at-rest.md) ·
[Caches](caches.md) ·
[A cluster in AWS](aws-cluster.md)

**For contributors** —
[Repository layout](layout.md) ·
[Parent project migration](parent-project-migration.md)

### Protocols, by the admin console's Protocols menu

Every page under **Protocols** in the admin console, and the page here that
documents it.

| Console group | Console pages | Documentation |
|---|---|---|
| OAuth2 / OIDC | `/admin/oauth2`, `/admin/authorization-servers`, `/admin/token-lifetimes`, `/admin/claims`, `/admin/userinfo-claims` | [OAuth 2.0 and OpenID Connect](oauth-oidc.md), [Security profiles: RFC 9700, OAuth 2.1, DPoP, mTLS](oauth-security.md), [JWT assertions](jwt-assertions.md) |
| SAML | `/admin/saml2`, `/admin/saml11`, `/admin/saml-assertions`, `/admin/saml-attributes` | [SAML 2.0 Web Browser SSO](saml2-sso.md), [SAML 1.1](saml11.md), [SAML assertions as grants (RFC 7522)](saml-assertions.md) |
| Verifiable Credentials | `/admin/oid4vci`, `/admin/vc`, `/admin/vc-status`, `/admin/oid4vp`, `/admin/vc-verifier-config` | [OpenID4VCI and status lists](oid4vci.md), [OpenID4VP and wallet sign-in](oid4vp.md) |
| XACML | `/admin/xacml`, `/admin/xacml/policies`, `/admin/xacml/editor`, `/admin/xacml/peps`, `/admin/xacml/decide` | [XACML 3.0 and ALFA](xacml.md), [Remote PEP](remote-pep.md) |
| SCIM | `/admin/scim` | [SCIM 2.0](scim.md) |
| Shared Signals, CAEP, RISC | `/admin/ssf`, `/admin/caep`, `/admin/risc` | [Shared Signals](shared-signals.md), [CAEP events](caep-events.md), [Signals received](signals-received.md) |
| Federation | `/admin/federation` | [Federation](federation.md) |
| OpenID Federation | `/admin/oidfed` | [OpenID Federation](oidfed.md) |
| GNAP | `/admin/gnap` | [GNAP](gnap.md) |
| TOTP MFA, Recovery codes, WebAuthn | `/admin/totp`, `/admin/backup-codes`, `/admin/webauthn` | [Authentication](authentication.md) |
| Device registration | `/admin/device-registration` | [Devices](devices.md) |
| Kerberos | `/admin/kerberos`, `/admin/kerberos/principals` | [Kerberos and SPNEGO](kerberos.md) |
| LDAP / LDAPS | `/admin/ldap` | [LDAP](ldap.md) |
| WS-Trust | `/admin/wstrust` | [WS-Trust](ws-trust.md) |
| WS-Federation | `/admin/wsfed` | [WS-Federation](ws-federation.md) |
| PKI | `/admin/pki` | [PKI](pki.md) |
| Certificate enrollment | `/admin/acme`, `/admin/est`, `/admin/scep` | [ACME](acme.md), [EST](est.md), [SCEP](scep.md) |
| SPIFFE | `/admin/spiffe`, `/admin/spiffe/entries`, `/admin/spiffe/agents` | [SPIFFE](spiffe.md) |
| TLS / mutual TLS | `/admin/tls`, `/admin/tls/trust` | [TLS and mutual TLS](tls.md) |

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

| Family | Where | Read |
|---|---|---|
| OAuth 2.0 and OpenID Connect — a full authorization server | `/oauth2/*`, `/.well-known/openid-configuration` | [oauth-oidc](oauth-oidc.md) |
| DPoP (RFC 9449) and certificate-bound tokens (RFC 8705) | the token endpoint and the four protected endpoints | [oauth-security](oauth-security.md) |
| RFC 9700, the Security BCP, as an optional MODE | `GET /oauth2/rfc9700` | [oauth-security](oauth-security.md) |
| OAuth 2.1 (draft-16) as an optional MODE, which turns the one above on | `GET /oauth2/oauth21` | [oauth-security](oauth-security.md) |
| WS-Trust 1.0 – 1.4 | `/sts` | [ws-trust](ws-trust.md) |
| WS-Federation 1.2, passive requestor, with a mock relying party | `/wsfed`, `/wsfed/rp` | [ws-federation](ws-federation.md) |
| SAML 2.0 Web Browser SSO — a full identity provider, all three bindings | `/saml2`, `/saml2/metadata/{sp}`, `/saml2/sp` | [saml2-sso](saml2-sso.md) |
| SAML 1.1 browser profiles — Browser/POST and Browser/Artifact, and an attribute authority | `/saml11`, `/saml11/metadata/{rp}`, `/saml11/rp` | [saml11](saml11.md) |
| SAML 2.0 and SAML 1.1 assertions | inside all four above | [saml2-sso](saml2-sso.md) |
| **Federation** — this service as either end of a relationship with a foreign identity service, in five of those protocols | `/federation`, `/admin/federation` | [federation](federation.md) |
| **OpenID Federation 1.1** — every realm a federation entity (Trust Anchor, Intermediate or Leaf) with its own Federation Entity Keys; Subordinate Statements with metadata policy and constraints, Trust Chain resolution, Trust Marks, and the section 8 endpoints | `/.well-known/openid-federation`, `/oidfed/*`, `/admin/oidfed` | [oidfed](oidfed.md) |
| **JWT assertions (RFC 7521, RFC 7523)** — both halves: an assertion instead of a client secret, and an assertion instead of an authorization code | the token endpoint | [jwt-assertions](jwt-assertions.md) |
| **SAML 2.0 assertions (RFC 7521, RFC 7522)** — the same framework's other profile: a signed `<saml:Assertion>` instead of a client secret, and instead of an authorization code. A **separate key pair per application** from the JWT one, and neither can sign for the other | the token endpoint | [saml-assertions](saml-assertions.md) |
| **A certificate authority** — ONE Root for the service, an Intermediate per trust realm and per the process, an Issuing CA per use case, and **every key pair this service generates as a leaf of it** | `/admin/pki`, `/admin-api/pki` | [pki](pki.md) |
| WebAuthn Level 3 over FIDO CTAP2, the relying party's half — a second factor or the only credential on an account | the login screen, `/portal/keys`, `/admin/webauthn` | [authentication](authentication.md) |
| **TOTP (RFC 6238)** — an authenticator app as a second factor, enrolled as a QR code and **genuinely verified** | `/portal/mfa`, `/authn/totp`, `/admin/totp` | [authentication](authentication.md) |
| **Recovery codes** — the way back in when the second factor is not to hand, generated by the person, shown **once** and stored as a hash, and the only mechanism here that no specification defines | `/portal/mfa`, `/authn/backup-code`, `/admin/backup-codes` | [authentication](authentication.md) |
| **App passwords** — what a person with a second factor gives a client at the five doors that take only a password (LDAP, WS-Trust, SCIM, SSF and EST Basic), which in product refuse their own password; generated, shown **once**, hashed, scoped to the doors named and never accepted at a browser sign-in | `/portal/app-passwords`, `/admin/users`, `/admin-api/users/app-passwords` | [authentication](authentication.md#the-password-only-doors-and-app-passwords) |
| Kerberos v5 — a KDC, a protected service, and MS-KKDCP; a person's **keytab**, derived from a password in hand | TCP/UDP 88, `/KdcProxy`, `/portal/kerberos` | [kerberos](kerberos.md) |
| SPNEGO (RFC 4559/4178) | `/spnego` | [kerberos](kerberos.md) |
| LDAP v3 (RFC 4511) and LDAPS | TCP 389 and 636 | [ldap](ldap.md) |
| SCIM 2.0 provisioning | `/scim/v2` | [scim](scim.md) |
| TLS and mutual TLS — a client certificate asked for and never required, and a sign-in for a verified one | the main port, `/tls`, `/tls/sign-in` | [tls](tls.md) |
| SPIFFE — bundle endpoint, Workload API, SPIRE Server API | `/spiffe`, four gRPC sockets | [spiffe](spiffe.md) |
| OpenID4VCI 1.0 — a Credential Issuer | `/oid4vci/*` | [oid4vci](oid4vci.md) |
| OpenID4VP 1.0 — a Verifier, and a sign-in with a wallet in any credential format, through the W3C Digital Credentials API | `/oid4vp/verifier`, `/authn/wallet` | [oid4vp](oid4vp.md) |
| Token Status List and W3C Bitstring Status List — what this issuer publishes about what it issued | `/oid4vci/status-lists*`, `/admin/vc-status` | [oid4vci](oid4vci.md) |
| W3C DID Core with DIF domain linkage | `/.well-known/did.json` | [oid4vp](oid4vp.md) |
| The W3C VC-API test endpoints — Data Integrity (RDFC, JCS, ecdsa-sd-2023), VC-JOSE-COSE and DID resolution for the W3C test suites; a development test control | `/vc-api/*` | [vc-api](vc-api.md) |
| Shared Signals (SSF 1.0) with CAEP and RISC — a transmitter, and a receiver of its own | `/ssf/*`, `/admin/ssf` | [shared-signals](shared-signals.md) |
| XACML 3.0 and ALFA — a PDP, a policy repository, and the PEPs that decide this service's own issuance | `/xacml/*`, `/admin/xacml` | [xacml](xacml.md) |
| GNAP (RFC 9635) with RFC 9767 resource server connections | `/gnap/*`, `/admin/gnap` | [gnap](gnap.md) |
| ACME, EST and SCEP certificate enrollment | `/enroll/acme`, `/.well-known/est`, `/enroll/scep` | [acme](acme.md), [est](est.md), [scep](scep.md) |

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
In development mode, until the bootstrap administrator `admin` first signs in,
anybody who signs in holds both roles; product mode never opens it that way, and
`admin` claims it only by signing in with its password. The console can revoke tokens, add claims to every
future token and assertion, and create people in the directory. Do not put a
development-mode instance on a public address.
[Admin console](admin-console.md) has the rest.

**`/admin-api` requires an OAuth 2.0 access token** —
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
assertion that does not verify against the certificate configured on it. **And
the gate is on the subject too**: a partner signs in only the person its subject
is linked to, and an unlinked one naming an existing person must first sign in
here as that person (#109). See [federation](federation.md) and
[what is not checked](what-is-not-checked.md).
