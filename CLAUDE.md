# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in
this repository.

**It is the thin one, and on 2026-09-13 it was made thin a second time.** Almost
every fact about a module lives in the `CLAUDE.md` of the directory that module
is in, and this file keeps only what is genuinely cross-cutting: where things
are, the require order and the rules about libraries and hooks, the two CSP
rules, the endpoint-drift rule, the error-code rule, the code style, the
submodule warnings, the state of the tests, and an INDEX of what this service
deliberately does not do. **There is one copy of each fact.** If something here
looks like a summary of a directory file, it is a bug — say so rather than
reconciling the two.

**It had grown back to 1957 lines in eight days**, the same way it grew the
first time: a date-stamped paragraph added here beside the directory file that
already said it, until a table cell ran to a page. The rule that stops it is the
one above, and the test for a new paragraph is short — *would a reader of the
directory's own file miss this?* If yes it goes there, and this file gets at
most a row in a table.

**Two different things happen to the text that leaves, and they are worth
telling apart.** Prose that had no home elsewhere is MOVED — verbatim, into the
directory that owns it. Prose that was a summary of a directory file is DELETED,
because the destination already says it, usually better and always in more
detail.

| What left this file | Where it is now |
|---|---|
| **2026-09-05** — the worker pool's five things to know, the realm's eleven keys, the per-realm store rule | `common/CLAUDE.md` |
| **2026-09-05** — why the main port is HTTPS, the appconfig files | `env/CLAUDE.md` |
| **2026-09-05** — `persistence.js` binding nothing and still going first | `persistence/CLAUDE.md` |
| **2026-09-05** — the job table, the TLS anchor every job gets, the launchers, the coverage run | `tests/CLAUDE.md` |
| **2026-09-05** — what a SCIM, SPIFFE, UserInfo, SPNEGO test would cover | each family's file |
| **2026-09-05** — the two shell scripts the database container runs | `postgres/CLAUDE.md` |
| **2026-09-13** — the hosted surfaces as OIDC relying parties, the realm split, the `Location` header | `common/CLAUDE.md` (`oidc_rp.js`) |
| **2026-09-13** — one listener process and N workers, `protocol_stack.ts`, BOTH worker pools, the barrier, the tickets, `readYourWrite`, the measurements | `common/CLAUDE.md` |
| **2026-09-13** — LDAP as a dispatched operation, the connection mirror | `ldap/CLAUDE.md` |
| **2026-09-13** — SPIFFE's dispatched gRPC methods, per-realm trust domains | `spiffe/CLAUDE.md` |
| **2026-09-13** — the listener certificate after `build-root`, the truststore pin | `tls/CLAUDE.md` |
| **2026-09-13** — the signing key in development mode, `mode.js`, versioning, the error-code design | `common/CLAUDE.md` |
| **2026-09-13** — the remote PEP's version reporting | `xacml-pep/CLAUDE.md` |
| **2026-09-13** — the XACML gates and `POST /xacml/pip` | `xacml/CLAUDE.md` |
| **2026-09-13** — `/admin-api`'s access token | `mgmt-api/CLAUDE.md` |
| **2026-09-13** — the per-slot arguments of rule 3e, the second metadata page, the account menu and certificate dialog refusals | `admin-ui/CLAUDE.md` |
| **2026-09-13** — `portal.setDirectory()`, `/portal/keys`' script | `portal/CLAUDE.md` |
| **2026-09-13** — the parent project's Kerberos COPY closure, and what it is owed | `kerberos/CLAUDE.md` |
| **2026-09-13** — where a new test goes, the negatives note | `tests/CLAUDE.md` |
| **2026-09-13** — the prose of every row of *Things this service deliberately does not do* | the file each row names |

## Where things are

The 2026-08-23 reorganisation moved every module out of the package root. The
files did not change; the paths did.

| Directory | What is in it |
|---|---|
| `common/` | Everything more than one family reads — settings, the express app, **`crypto.js` (the one place this service signs, verifies, encrypts and decrypts)**, trust realms, both worker pools and the shared require order, the registers (applications, delegation, permissions, consent, roles, the issuance gate), the certificate authority (`pki.js`), the second factors, the password policy, the error-code table, `outbound_tls.ts` (whether an outbound request may be plain http, and whether the peer's certificate is verified — #171), **the mail channel** (`mail.ts` and its transports, templates and uses — #63), and **`mode.js`, the one place `development` and `product` are told apart**. `common/CLAUDE.md`. |
| `common/vendored/` | Byte-identical copies of the parent project's files — `xmldsig.js`, the PKI and post-quantum encoders — plus the JSON-LD `contexts/`. **Do not edit them here.** `common/vendored/CLAUDE.md`. |
| `home/` | The front door: `GET /` and the one image on it. `home/CLAUDE.md`. |
| `logout/` | The protocol-independent sign-out at `GET|POST /logout`, and the one model of what a live session is, per identity (`/admin/logout`) and service-wide (`/admin/sessions`). `logout/CLAUDE.md`. |
| `portal/` | **The user portal**: the pages that belong to the person looking at them, where no route takes an identity from the request, behind a navigation column that is not the console's. `portal/CLAUDE.md`. |
| `oauth-oidc/` | The authorization server and OpenID provider: RFC 9700 mode, DPoP, mTLS, client authentication, both RFC 7523 and RFC 7522 assertion profiles, the multi-AS profiles, the consent screen and UserInfo. `oauth-oidc/CLAUDE.md`. |
| `authn/` | The sign-in service, which **owns the SESSION**: the WebAuthn relying party and the TOTP and recovery-code steps. `/authn/spnego` lives in `kerberos/`, `/authn/wallet` in `oid4vc/`. `authn/CLAUDE.md`. |
| `saml/` | The SAML 2.0 and SAML 1.1 assertion builders, each with a SEPARATE browser-facing identity provider rather than one with a version flag. `saml/CLAUDE.md`. |
| `ws-trust/` | WS-Trust 1.0–1.4. `ws-trust/CLAUDE.md`. |
| `ws-federation/` | WS-Federation 1.2's passive requestor profile and a mock relying party. `ws-federation/CLAUDE.md`. |
| `pki/` | `pki_service.ts`: the certificate authority's PUBLIC surface — a CRL and an OCSP responder per CA, each CA's own certificate, and the chain documents at `/pki/chain/`. `crypto_metadata_document.ts` (#42, 2026-09-22): `/crypto/metadata` per realm, every signer GENERATION with its chain, in JSON, XML and signed forms. No gate and no credential, by construction; the authority itself is `common/pki.js`. Each header is its file's documentation (no `CLAUDE.md`). |
| `federation/` | Federation relationships in either direction, in five protocols; `ou=federations` is the register, and it holds the first and strongest of the outbound requests. `federation/CLAUDE.md`. |
| `oidfed/` | **OpenID Federation 1.1** (#132, #133): every realm a federation entity — Trust Anchor, Intermediate or Leaf — with an Entity Configuration, a Federation Entity Key of its own, subordinates it vouches for and Trust Anchors it trusts (`ou=oidfed`), metadata policy and constraints, Trust Chain resolution, Trust Marks, and the section 8 endpoints — and the three extensions (#135–#137): the Extended Subordinate Listing, the Entity Collection (a crawl of the realm's own subtree) and each subordinate's history, kept for good, with suspension. NOT `federation/`, which is bilateral. `oidfed/CLAUDE.md`. |
| `kerberos/` | The KDC, the acceptor, SPNEGO (the negotiation, the page, and the sign-in that turns a ticket into a session), and eight codec modules **VENDORED from the parent project and not editable here**, despite not being under `common/vendored/`. `kerberos/CLAUDE.md`. |
| `ldap/` | The embedded directory — the store for people, groups, applications and the SPIFFE registry — and the eight `/admin/ldap/*` console pages that show it. `ldap/CLAUDE.md`. |
| `cluster/` | **Several containers against one postgres store** (#46, 2026-09-14): membership and leases with a fencing token every write transaction checks, the gate in front of `cluster.mode` (active-passive by default in product mode on postgres; active-active refused while a capability is missing), atomic claims, the secrets every node shares, and the cross-node read barrier — and **the scheduler every periodic job runs on** (#49, `scheduler.ts`). Libraries — no route but `/admin/cluster`'s status block; `/admin/scheduler` is `admin-ui/scheduler_admin.ts`. `cluster/CLAUDE.md`. |
| `persistence/` | The one place this service writes anything down (`memory`, `ldif`, `postgres`), and the coordination of several processes through one change log — state, not sockets. `persistence/CLAUDE.md`. |
| `scim/` | `/scim/v2`, its authentication and attribute mapping, and two console pages (`/admin/scim`, `/admin/scim/monitor`). `scim/CLAUDE.md`. |
| `ssf/` | The Shared Signals Framework — the one family here that TALKS BACK — with CAEP and RISC as the two vocabularies over it and this service's own console and portal as registered receivers. `ssf/CLAUDE.md`. |
| `spiffe/` | Six libraries, one server module and the vendored `protos/`: a trust domain per realm under the service Root, bound on an address of its own when turned on. `spiffe/CLAUDE.md`. |
| `tls/` | The certificate three sockets share, the client truststore, the sighting on the main port, the client's JA4 TLS fingerprint (`client_hello.ts`, #62) and `GET /tls/sign-in`. **It owned the 8443 and 9443 listeners until 2026-09-16 and owns no socket now.** `tls/CLAUDE.md`. |
| `oid4vc/` | OpenID4VCI, OpenID4VP and DID Core, the wallet sign-in at `/authn/wallet` (`vc_signin.ts`, the W3C Digital Credentials API included), and the status lists every credential names (`vc_status.ts`). `oid4vc/CLAUDE.md`. |
| `admin-core/` | What both admin surfaces DO, in a directory neither owns: `admin_actions.js`, `admin_views.js`, `certificate_views.js`. It requires route-registering modules, so it may be required at 18 or later and is not in `common/`. `admin-core/CLAUDE.md`. |
| `admin-ui/` | The console at `/admin`, its gate and two roles, every setting drawn on its protocol's page (`SETTING_HOMES`), the two server-laid-out drawings, and the pages that report on this service itself — `/admin/crypto-metadata`, `/admin/pki`, `/admin/secrets`, `/admin/api-explorer`. `admin-ui/CLAUDE.md`. |
| `mgmt-api/` | `/admin-api` — every console control, reachable by a machine (rule 7), gated by an OAuth 2.0 access token — its generated OpenAPI document, and the explorer's assets. `mgmt-api/CLAUDE.md`. |
| `tests/` | **The only test directory**: `tests/*.js` is the in-process half (`npm test`), `tests/vendored/` the protocol half driven over HTTP against a container built from this tree, with `MANIFEST.js` the count and the record of which jobs are copies and which are `local: true`; `tools/`, `Dockerfile` and `run-tests-in-container.sh` are tooling, not tests. `tests/CLAUDE.md`. |
| `xacml/` | XACML 3.0 and ALFA — the engine (held to the vendored OASIS suite, Apache-2.0), the `ou=policies` repository, the PIP, the embedded PEPs that decide this service's own issuance and access, the PAP console, and the PDP side of the remote PEP. `xacml/CLAUDE.md`. |
| `gnap/` | GNAP (RFC 9635) and its resource server connections (RFC 9767): a key-proofed authorization server per trust realm, issuing tokens in five formats. `gnap/CLAUDE.md`. |
| `risk/` | **Risk scoring (#62)**: the external datasets a score reads (geolocation, ASN, Tor exits, IP reputation, an operator's allow and deny lists), imported by version into `sts_risk_*`, verified before they are active, looked up by SQL; and every refused password attributed to a person or a name's digest and a network. Every sign-in is scored (a port of Freeman et al.'s model plus evaluators) and recorded, and since P3 its facts go to the issuance policy, which decides on them — nothing in `risk/` decides. Monitoring → Risk is `admin-ui/risk_admin.ts`. `risk/CLAUDE.md`. |
| `acme/`, `est/`, `scep/` | **CERTIFICATE ENROLLMENT, IN THREE PROTOCOLS (2026-09-13)** — ACME (RFC 8555) at `/enroll/acme`, EST (RFC 7030) at `/.well-known/est` and SCEP (RFC 8894) at `/enroll/scep`, each with an Issuing CA of its own under the realm's Intermediate, a console page under Protocols and one under Monitoring, both in a *Cert issuance* group (2026-09-22; the Protocols group holds SPIFFE too, because an X509-SVID is a certificate this realm issues), and `/admin-api` operations declared in `<family>_api.js`. **None of the three decides who may have a certificate for whom or what goes in it**: that is `common/cert_enrollment.ts` (rule 3ag) — yourself, or any person or application in the realm for a holder of Admin Write; the nine leaf profiles of `/admin/pki` and the five refused; names built from the ENTRY, a host name only when registered on it; every certificate kept on the entry it names, and a private key only when this service generated it (EST `/serverkeygen`). Authentication is protocol-native: an ACME account bound FOR LIFE by an External Account Binding key, EST's password, client secret or realm-issued certificate, a SCEP single-use challenge password. A person makes their own EAB key and challenge on `/portal/certificates`. Each directory's `CLAUDE.md` carries its RFC coverage and its documented exceptions. |
| `xacml-pep/` | **Not part of the mock**: a second container, a remote XACML PEP that pulls policy from `/xacml/pep/policies` and decides with a build-time copy of the engine. `xacml-pep/CLAUDE.md`. |
| `openbao/` | **Not part of the mock**: the files a secret-store container runs, from which the compose stack reads its key-encryption key and database password with a read-only client certificate. `openbao/CLAUDE.md`. |
| `deploy/aws/` | **Not part of the mock**: Terraform for a three-node active-active cluster on ECS Fargate behind an NLB, against RDS PostgreSQL 18 with a replica, with the key-encryption key and database password in AWS Secrets Manager — a long-lived `foundation/` (deployer identity, KMS, ECR, logs) and a per-run `environment/`, the schema-init image, the suite runner, and `.github/workflows/aws-cluster.yml`. `deploy/aws/CLAUDE.md`. |
| `debugger/` | **The embedded identity protocol debugger** (2026-09-13): the parent project's client and api served on a listener of their own (`debugger.port`), signed in to through this service's authorization server, the api a FORKED CHILD behind an access token only a console administrator is issued. `debugger/embedded/` is that project's build output, never source. `debugger/CLAUDE.md`. |
| `postgres/` | Four files the database container runs, never this service: TLS setup, TLS enforcement, the schema and the least-privilege `sts_app` role. `postgres/CLAUDE.md`. |
| `docs/` | The GitHub Pages site — how to USE this service. `docs/CLAUDE.md`. |
| `types/`, `tsconfig.json`, `tsconfig.build.json`, `build-typescript.sh` | **THE TYPESCRIPT CONVERSION (#50, 2026-09-16)**: `types/` is declarations only, loaded by nothing at runtime — the shared shapes (`cluster/` results, a password policy profile, the fields this service hangs on a request) and the optional SDKs `common/secrets.js` loads. `tsc` checks every file that carries `// @ts-check` — since 2026-09-16 every directory the service runs from, and `server.js`, all but the vendored copies, beside the `.ts` files (`sts_metadata.ts` at the root among them), which are always checked — and `tests/typecheck.js` runs it and holds the list. `build-typescript.sh` compiles — inside an image build only — each `x.ts` to `x.js` beside it (`tsconfig.build.json`), and with `--strip` removes the sources for the service image. The decisions for the rest of the conversion are on issue #50. |
| `env/` | The appconfig files, each a layer over the generated `defaults.js`. `env/CLAUDE.md`. |

At the package root there are exactly two modules, and both earn it:
**`server.js`**, the shell that requires the others and listens, and
**`sts_metadata.ts`**, which reads the router to list what everything else
registered and is therefore required last.

**Read the directory's own `CLAUDE.md` before changing anything in it.** They are
not summaries — the reasoning is in them, and most of it is the record of
something having gone wrong once.

`README.md` is a short landing page: the protocol families, how to build and
run the service, the ports and the tests. `docs/` is the user-facing
documentation; this file and the directory files are the maintainer-facing
half.

## Overview

A mock identity service — and, in `product` mode, a deployable one — that speaks
these protocol families:

- **Kerberos v5**: a KDC on TCP/UDP 88 and MS-KKDCP, a protected service, and SPNEGO (RFC 4559/4178).
- **WS-Trust** 1.0–1.4.
- **SAML 2.0**: assertions, and Web Browser SSO over four bindings (Redirect, POST, POST-SimpleSign, Artifact) with Single Logout.
- **SAML 1.1**: assertions, Browser/POST and Browser/Artifact, and an attribute-authority responder.
- **WS-Federation 1.2**: the passive requestor profile.
- **Federation**: either end of a relationship with a foreign identity service, in five protocols.
- **OpenID Federation 1.1**: every realm a federation entity with its own keys, subordinates, Trust Anchors and Trust Marks; the default realm a Trust Anchor over the others.
- **OAuth 2.0 / OpenID Connect**: a full authorization server, with DPoP — Native SSO, whose devices are entries in the directory, and CIBA, approved on the portal.
- **Device registration** (#164, #218): a register of devices per realm, owned by a person or an application and recognised by any key they proved. Each device is attested or self-asserted, and its compliance comes from an administrator or an MDM feed. Devices feed CAEP and RISC, risk scoring, the issuance policy, `urn:sts:acr:compliant-device` and a `device_id` claim (`docs/devices.md`).
- **RFC 7521/7523 and RFC 7521/7522**: JWT and SAML assertions as client credentials and as grants.
- **WebAuthn Level 3, RFC 6238 TOTP and recovery codes**: the second factors on the sign-in screen — and, OFF by default (NIST SP 800-63B-4 section 3.1.3.1), an emailed code or sign-in link as a first or second factor (#64), each where the realm's authentication policy on Directory → Policies allows it.
- **OpenID4VCI 1.0, OpenID4VP 1.0**, and W3C DID Core with DIF domain linkage — and a wallet sign-in, `/authn/wallet`, which also takes a SIOPv2 self-issued ID Token from an enrolled key.
- **LDAP v3**: an embedded directory on 389 and LDAPS 636.
- **SCIM 2.0**: provisioning into that same directory, with no store of its own.
- **TLS / mutual TLS**: the main port asks every connection for a client certificate and requires none; `GET /tls/sign-in` signs the holder of a verified one in.
- **Shared Signals** (SSF 1.0, with CAEP and RISC): a transmitter, and a receiver of its own.
- **A certificate authority**: one Root, an Intermediate per realm, CRLs and OCSP (`/admin/pki`).
- **SPIFFE**: the bundle endpoint, the Workload API and the SPIRE Server API, per trust realm.
- **XACML 3.0** and **GNAP** (RFC 9635).
- **Mail, sending only** (#63): SMTP with STARTTLS or implicit TLS and DKIM, Amazon SES, Azure Communication Services and the Gmail API — for self-service password reset, address verification, an administrator's links and security notices.

It exists to exercise *clients*: in development mode it checks no password,
validates no access token and **attests no Workload API caller over TCP**
(the Unix socket's are attested, #40; product serves TCP only on a declared
network, #166). The surfaces below are
the exceptions, and each is argued where it lives.

| Surface | What it requires | Argued in |
|---|---|---|
| `/scim/v2` | a credential in any of RFC 7644 section 2's six schemes; the OAuth ones need `scim:read` or `scim:write` | `scim/CLAUDE.md` |
| the SPIRE Server API | an X509-SVID over mutual TLS, authorized against SPIRE's per-method table | `spiffe/CLAUDE.md` |
| `/admin` | a session of its own, got through the OIDC code flow, and one of two roles held through directory groups | `admin-ui/CLAUDE.md` |
| `/federation/acs/{id}` | a signature verifying against the relationship's certificate — **not a turnstile, cannot be made permissive** | `federation/CLAUDE.md` |
| `/authn/spnego` | a Kerberos ticket verified against a real long-term key — **not a refusal at all** | `kerberos/CLAUDE.md` |
| the SPIFFE Broker API (`spiffe.brokerPort`) | an X509-SVID over mutual TLS naming a broker in `spiffe.brokers`, and a reference type that broker may use; the workload it references is attested here (#170) | `spiffe/CLAUDE.md` |
| `/xacml/pep/*`, `POST /xacml/pip` | a verified client certificate whose subject DN resolves to an entry holding `REMOTE_PEPS` | `xacml/CLAUDE.md` |
| `GET /xacml`, `POST /xacml/pdp`, `GET /xacml/policies`, `GET /xacml/protected` | the same chain, holding `XACML_USER` | `xacml/CLAUDE.md` |
| `/admin-api` | an OAuth 2.0 access token audienced to it, with `admin:read` / `admin:write`, issued to a client that declares them (#110); `adminApi.authRequired` restores the open API | `mgmt-api/CLAUDE.md` |
| `/oauth2/introspect` | client authentication — for an RFC 9701 JWT response in every mode, for RFC 7662 JSON in product mode only | `oauth-oidc/CLAUDE.md` (3ai) |
| the debugger listener (`debugger.port`) | an access token audienced to `urn:sts:debugger-api:` carrying the debugger permission — issued to console administrators only — or the debugger client's session holding one; four landing paths excepted. **Cannot be turned off** | `debugger/CLAUDE.md` |

**The first three are turnstiles, and none of them can be turned off** — the
`*.authRequired` settings that did it were removed on 2026-09-06; what
`global.mode` changes is whether what they ask for is CHECKED
(`common/CLAUDE.md`, `mode.js`). **The Workload API is the opposite case**: it
authenticates nobody because its specification says it MUST NOT, and what it
lacks is ATTESTATION, not authentication (`spiffe/CLAUDE.md`).

Extracted from the [OAuth2/OIDC Debugger](https://idptools.com). **The protocol
suite is still WRITTEN in that project and a copy of it RUNS here** — see
*Tests* below.

## Running it

```bash
docker build -t iya-sts .
docker run --rm -p 8081:8081 iya-sts           # 8081; STS_PORT overrides
```

**THE SERVICE RUNS FROM AN IMAGE, NOT FROM A CHECKOUT, SINCE 2026-09-16 (#50).**
Part of it is TypeScript, compiled only inside an image build
(`build-typescript.sh`, the `typescript` stage of `Dockerfile`), and rcbj's
rules are that nothing compiled is written to the host and no `.ts` is in the
final image. `node server.js` on a checkout refuses and says why
(`common/compiled_tree.js`, `STS-CORE-0093`). On the host,
`tests/node_modules/.bin/tsc -p tsconfig.json` checks the types and writes
nothing.

**That port is HTTPS** — every appconfig file in `env/` sets `global.https`, and
`STS_HTTPS=false` is the supported way back (`env/CLAUDE.md`). **The selected
file is a layer, not the whole configuration**, and a setting with no value
anywhere stops the service from starting: `common/CLAUDE.md` argues the five
levels, `env/CLAUDE.md` lists the files, and `docs/configuration.md`'s *Every
setting* lists every setting.

## Architecture, and the rules that hold it together

`server.js` is a shell: it requires the modules and listens. What each directory
holds is the table above; what each module is for is that directory's
`CLAUDE.md`.

1. **A composition root registers every endpoint, in one order.** Since #50's
   R1 (2026-09-16) a module converted to TypeScript registers NOTHING when it
   is required: it exports `registerRoutes(app)`, and
   `common/protocol_stack.ts` (class `ProtocolStack`) calls each one against
   the shared app from `app.js`, at the point in its sequence where requiring
   that module used to register the routes. That is the owner's decision on
   issue #50 — `registerRoutes(app)` plus a composition root, rather than a
   `register()` at each module's top level. **The modules still written in
   JavaScript still register when they are required** — the parent project's
   locked Kerberos files (`krb5_kdc`, `krb5_service`, `spnego`),
   `tls/tls_server.js` and `ldap/ldap_server.js` — and
   `protocol_stack.ts` requires them at their old places, so the two kinds
   interleave exactly as they did (Express's layer list, 603 layers with their
   handlers, was compared before and after and is identical).
   `debugger/debugger_server.ts` registers on an express app of its OWN and is
   outside this. So **the route order is the order of the `register()` calls
   and of the JavaScript requires in `protocol_stack.ts`**, and the middleware
   still has to live in `app.js`, because express applies middleware only to
   routes added after it.

   **The consequence for anything that loads a module by itself** — a test, a
   script, another module: requiring a converted route module gets you its
   exports and none of its routes. Call its `registerRoutes(app)`, or require
   `common/protocol_stack` for the whole stack. And the old argument "a
   require from here would drag X's routes to the front of the router" is now
   true only where X is one of the JavaScript modules above; for a converted
   X a require moves no route, though it can still close a cycle or run X's
   load-time effects (slot fills, stores) early — see *The require order and
   the route order*, below.

2. **`vc_configs.ts` and `vc_offers.ts` exist to break require cycles, not to group
   code.** The credential configurations are read by both the issuer and the
   authorization server; the Credential Offer's pre-authorized codes are minted by
   the offer pages and redeemed at the token endpoint. A cycle in node does not fail
   loudly — it hands back a half-initialised module whose exports are `undefined`,
   and the symptom arrives later as something that is not a function.

3. **`dpop.js` is a library, not a protocol module.** It registers nothing, so its
   position in the require order does not matter, and it requires only `helpers.js`
   (plus npm leaves) so it cannot join a cycle. Keep it that way. It is also why
   `presentedAccessToken()` — the Bearer-or-DPoP check the four protected endpoints
   share — lives there rather than in `vc_issuer.ts` where it was written: the
   fourth caller is in `oauth2.ts`, which vc_issuer.ts cannot be required from
   without building a cycle or — before #50's R1, when a require registered
   routes — moving OID4VCI ahead of OAuth2 in the route order.

3e. **`admin_stats.js` now has three inverted hooks and one require of a
   library, and they are four different problems rather than a pattern.**
   `helpers.js` offers `setJwtRecorder()` and this file fills it, because
   `helpers.js` cannot require the counter that `signJwt()` has to reach.
   `admin_stats.js` offers `setUserObserver()` and `ldap_server.js` fills it, so
   that seeding a directory entry cannot drag `/ldap`'s routes to the front of
   the router. `admin_stats.js` offers `setAttributeResolver()` and
   `claim_attributes.js` fills it, because `vc_claims.ts` requires this file.
   `admin_stats.js` offers `setGroupResolver()` and `group_claims.js` fills it,
   because that module requires this file AND what it needs is the directory,
   which only `ldap_server.js` can answer. And `audit.js` is a plain require in
   the ordinary direction, because it requires nothing here. Each is justified
   by a specific thing that would otherwise break; **do not add a sixth by
   analogy** — a slot is what you reach for when a require would close a cycle
   or move a route, and it costs a reader an indirection every time. The group
   resolver is the one to check a new proposal against: it was added only after
   showing it failed that test BOTH ways round.

   **THE TEST IS THE RULE; the slots that have passed it are an inventory, and
   each one's argument lives beside the module that offers it.** A new slot is
   validated WHOLE when installed (a filler that installs half of it leaves a
   page able to list and unable to act), and is argued both ways round — the
   require one way closes a cycle, the require the other way moves routes.
   **Since #50's R1 "moves routes" is true only of a require that reaches a
   JavaScript route module** (rule 1); a require of a converted module moves
   none, so for those the case for a slot is a cycle or a load-time effect
   that would run in the wrong place, and it has to be made on those terms.

   | Offered by | Slots | Argued in |
   |---|---|---|
   | `admin-ui/admin.ts` | `setLogoutReader`, `setCryptoReporter`, `setSignalsReporter`, `setCaepReporter`, `setRiscReporter`, `setDirectoryPages`, `setDirectoryReader`, `setDirectoryWriter`, `setGroupReader`, `setGroupWriter`, `setScimReader`, `setSpiffeReader`, `setXacmlPages`, `setRolePreviewer`, `setTruststore` | `admin-ui/CLAUDE.md`, and the filler's own file |
   | `admin-ui/crypto_metadata.ts` | `setProtocolFamilies`, filled by `sts_metadata.ts` | `admin-ui/CLAUDE.md` |
   | `portal/portal.ts` | `setDirectory`, filled by `ldap/ldap_server.js` | `portal/CLAUDE.md` |
   | `authn/authn.ts` | `setSessionObserver`, filled by `ssf/ssf.ts` | `authn/CLAUDE.md`, `ssf/CLAUDE.md` |
   | `common/admin_stats.js` | `setUserObserver` (three kinds of event, still one slot), `setAttributeResolver`, `setGroupResolver`, `setRevocationObserver` (#239, filled by `oauth-oidc/oauth_grant_signals.ts`) | `common/CLAUDE.md` |
   | `common/helpers.js` | `setSubjectResolver` (a person's `sub` from their entry's `entryUUID`, and back), filled by `ldap/ldap_server.js` (2026-09-14) | `ldap/CLAUDE.md` |

   **`setTruststore()` is the one slot not filled by the module that owns what
   it carries** — `common/protocol_stack.ts` fills it, because the owner is first
   loaded from inside `admin.js`'s own require (`tls/CLAUDE.md`).

## Trust realms: several logical copies of this service in one process

A **trust realm** has its own configuration, signing key, sessions, tokens,
statistics and audit log, answers on the SAME sockets, and is told apart by a
segment at the front of the path (`/realm/acme/oauth2/token`). **The default
realm has an empty prefix, and a service with no realms defined behaves exactly
as it did.** The design is argued in `common/CLAUDE.md`; six things reach
outside it:

1. **The realm is AMBIENT**, entered by `app.js`'s first middleware, which also
   strips the prefix. **Nothing may be registered above it.** — `common/CLAUDE.md`
2. **A store becomes per realm at its DECLARATION and nowhere else**;
   `tests/realm_isolation.js` is the guard. — `common/CLAUDE.md`
3. **The embedded directory is per realm too**, a tree of its own rooted at the realm's DNS domain (fixed at creation; the default realm's is `global.domain`). — `ldap/CLAUDE.md`, `common/CLAUDE.md`
4. **A realm has administrators of its own, CONFINED to it** (2026-09-14, #32; it
   read *deliberately NOT separated* until then). The console asks the roster of
   the realm a person signed in through; the default realm's is the service
   roster over every realm, and `admin-ui/admin_scope.ts` refuses a realm's own
   everything about the process. — `admin-ui/CLAUDE.md` 8d, `mgmt-api/CLAUDE.md`
5. **A client certificate at the handshake is still shared**, having no path
   and no name inside the protocol to put a realm in — the two TLS listeners
   left this list on 2026-09-16 by being DELETED, and what replaced them is a
   route, so the SESSION goes in the realm of the authority that signed the
   leaf. SPIFFE left it on 2026-09-12 — a realm gets a trust domain and sockets
   of its own, told apart by ADDRESS — and **Kerberos left it on 2026-09-15
   (#33)**: a KDC per realm on the shared port 88, told apart by the Kerberos
   realm NAME in the request, with the two sockets and the development-mode
   trust still the process's. — `tls/CLAUDE.md`, `spiffe/CLAUDE.md`,
   `kerberos/CLAUDE.md`
6. **A realm may be in RFC 9700 mode — or OAuth 2.1 mode, which implies it —
   while the process is not** — the `realmRuntime` marker, which must not grow
   rows by analogy. — `common/CLAUDE.md`, `oauth-oidc/CLAUDE.md`

## This service's own two surfaces are clients of its own authorization server

`/admin` and `/portal` are **OpenID Connect relying parties** of this service
(since 2026-09-06): seeded confidential clients, a real back-channel HTTP request
to `/oauth2/token`, a relying-party session that names the sign-on session it
came from and dies with it, and a Sign out on each that ends both.
`common/CLAUDE.md` (`oidc_rp.js`) carries the design, the realm split and the
`Location`-header bug; `authn/CLAUDE.md` the two kinds of session;
`admin-ui/CLAUDE.md` and `portal/CLAUDE.md` the gate exemptions and sign-out.

## What an authenticated identity is

**It is `authn/`'s session: an internal, protocol-independent record, and no
protocol's token** (2026-09-14). A subject (`urn:uuid:<entryUUID>`), a list of
authentication events, and a session with a stable `sid` and a rotating cookie
handle. Every artifact this service issues is a PROJECTION of it; every
credential it accepts is EVIDENCE on an event. A protocol module that issues or
accepts anything is bound by it. `authn/CLAUDE.md` argues it; a session needs
a directory entry to be the subject of, so federation's provisioning switches
(`federation/CLAUDE.md`) and SCIM's ids (`scim/CLAUDE.md`) follow from it.

## One front process, and what a socket cannot share

**This service is one node process that owns every listener**, and node runs all
of them on one thread. Two pools take work off it, and they are different kinds
of worker — `common/CLAUDE.md` argues both:

| | `common/worker_pool.js` | `common/request_pool.js` |
|---|---|---|
| A worker runs | a JOB TABLE — four leaf computations | THE SERVICE — the whole protocol stack |
| Forked | lazily, on the first post-quantum job | eagerly, before the listener binds |
| Setting | `workers.count` | `workers.requestCount` (0 — off by default), and `workers.surfaceCount` (0) for a second pool that runs only `/admin` and `/portal` |

**The cross-cutting rule is one sentence: a store is shared by coordination, and
anything that is NOT a row in a store — a socket, a timer, a listener, a
certificate a socket presents — is held by one process and reachable from no
other.** Each such thing needs the argument made again rather than an earlier
mechanism copied: the LDAP connection took a mirror and an instruction on the
response (`ldap/CLAUDE.md`), the TLS listener certificate took a reconcile in
the front process (`tls/CLAUDE.md`), and the client-certificate truststore took
a pin (`tls/CLAUDE.md`). **Dispatch without coordination is refused and the
service does not start**, because it answers WRONGLY rather than slowly.

## Anything periodic is a scheduler job

**rcbj's architectural directive, 2026-09-21: anything that has to be done
periodically in the background is a job on the central scheduler** (#49,
`cluster/scheduler.ts`, built 2026-09-22 — `cluster/CLAUDE.md`, *The
scheduler*), which runs each job on exactly one node, on the serving front
process and never in a request worker, and hands it to another node when that
one goes. Monitoring → Scheduler (`/admin/scheduler`) lists every job. **No new module may start a timer of its
own** — no `setInterval`, no `setTimeout` chain, no sweep armed at require or
wire time — for work that repeats.

**Cache and store clean-up is included**, and none of it is a job yet: a
cache here drops an entry only when it is read and found expired, when a size
cap evicts the oldest on an insert, or when a purge piggy-backs on the next
request that uses the store (claims, used assertions, rate-limit windows and
minted tombstones, each at most every 60 s or so). Ejecting expired entries is
periodic work, so it becomes a job. **Two checks stay where they are, because
they are correctness rather than housekeeping**: the expiry check at the read
(an expired entry is never answered, whenever the sweep last ran) and the size
cap at the insert (a bound cannot wait for a timer).

**So a job is one of two kinds, and the owner says which.** A *cluster* job
(the default) runs once, on the leader: a rotation, a CRL, a delivery. A
*per-process* job runs in every process that holds the state it cleans,
because that state is reachable from no other process (*One front process*,
above): the ejection from an in-memory cache, a process's own change-log pull,
its own decrypted-key purge. A per-process job takes no claim, and is still
registered with, reported by and switched through the scheduler.

What does NOT count: a per-request timeout, a debounce, a retry delay inside
one operation, and the cluster heartbeat with its lease and origin-claim
renewals, which are what the scheduler's own leadership stands on.

**Every timer that existed has moved (#49 P1 and P5, 2026-09-22)** — the
session sweep, the CRL directory refresh, the back-channel logout and SSF
sweeps, the SAML metadata refresher, the change-log pull and trim, the cache
report, the LDAP mirror's maintenance — and so have the purges piggy-backed on
requests (claims, used assertions, rate-limit windows, minted tombstones).
`cluster/CLAUDE.md` has the table of jobs; `tests/no_periodic_timers.js`
holds that nothing else repeats, with the permanent exceptions and why.

## The require order and the route order

**There are two orders, and until 2026-09-16 they were one.** Rule 1 made the
require order the route order; since #50's R1 they are kept apart, in ONE file,
side by side:

* **The require order** decides the LOAD-TIME effects: which slot is filled
  before whom (rule 3e), which store exists when a seed is written, which
  `require` would close a cycle, and — for the JavaScript modules rule 1 names —
  where their routes land.
* **The route order** is the order of `ProtocolStack.register()` calls (and of
  those JavaScript requires) and decides which handler wins and which
  middleware a route sits behind.

**Both live in `common/protocol_stack.ts`**, which `server.js` loads before
binding sockets and `common/request_worker.ts` loads without binding any — one
copy, so the two processes cannot disagree about which handler wins. Each
converted module is required and then registered on the next line, at the
place its routes always had, so every row below holds for both orders; where a
row's argument is "requiring X would drag X's routes", it now applies to the
`register()` call for a converted X and to the require only for a JavaScript
one. **A composite registration is still one row**: `mgmt-api/admin_api`
registers its gate and then its operations, `portal/portal` its pages and then
`/portal/certificates`, and a family whose route module requires its `_admin`
module is still one require but one `register()` per module (`acme` then
`acme_admin`, likewise `est` and `scep`; `xacml_admin` before `xacml`; `gnap`,
`gnap_interact`, `gnap_admin`) — in the order the load-time registration ran,
and `oid4vc/vc_offers` is registered just BEFORE `oauth-oidc/oauth2`, because
`oauth2` requires it and that is where its routes landed. Every constraint
below is a DEPENDENCY, not a preference; this table says what the constraint
is and the named file says why.

| # | Required (then registered, if converted) | Constraint | Argument in |
|---|---|---|---|
| 0 | `common/compiled_tree` | Before everything (#50): refuses a tree whose TypeScript is not compiled, and requires nothing of this service. Called by `server.js` itself rather than listed in `protocol_stack.ts`. | `common/CLAUDE.md` |
| 1 | `common/config_file` | First of all that configures anything; every reader of `CONFIG_FILE` is below it. | `common/CLAUDE.md` |
| 2 | `common/app` | Before every protocol module and every `register()` call: routes are registered against it, and middleware applies only to routes added after it. Also installs the JWT recorder (rule 3e). | `common/CLAUDE.md` |
| 2a | `common/realms` | No line of its own (loaded by `app` and `helpers`), but above every setting read and every store: requiring it fills `config.js`'s realm slot (rule 3m). | `common/CLAUDE.md` |
| 3–4 | `common/helpers`, `common/config` | `config.js` is below `helpers.js` and requires nothing here. | `common/CLAUDE.md` |
| 4a | `persistence/persistence` | Below `config`, above everything else: fills the override-store slot and subscribes to `realms.onChange()`. A library; it opens nothing here — `persistence.start()` does, before any listener binds. | `persistence/CLAUDE.md` |
| 4b | `common/crypto` | Loaded by `helpers`. A LEAF library that may never require `helpers` back. | `common/CLAUDE.md` |
| 5 | `common/claim_attributes` | Ahead of everything that ISSUES: it fills `setAttributeResolver()`. | `common/CLAUDE.md` |
| 6 | `common/group_claims` | Same reason, for `setGroupResolver()`. | `common/CLAUDE.md` |
| 6a | `home/home` | No constraint; first among the route modules, and so the first `register()`. | `home/CLAUDE.md` |
| 8 | `authn/authn` | Before `oauth2`: it owns the session that module reads. | `authn/CLAUDE.md` |
| 7 | `ws-trust/wstrust` | After `authn` since 2026-09-05 (it calls `startSession()`); the number predates the move. | `ws-trust/CLAUDE.md` |
| 8-email | `authn/email_factor` (and `common/mail_factor`, a library built with it) | Just after `authn`, whose pending steps it reads through that module's exports and whose three `/authn/email-*` paths it registers (#64) — `vc_signin`'s and `spnego_authn`'s arrangement. | `authn/CLAUDE.md` |
| 8a | `portal/portal` | After `authn`, whose session every portal route reads; an OIDC relying party of `oauth2`, which needs that module's routes registered, not required. | `portal/CLAUDE.md` |
| 8a-mail | `common/mail`, `common/mail_uses`, `portal/portal_mail` | Built with the portal, before it: the portal's `registerRoutes()` registers `portal_mail`'s three pages. The channel and its uses are LIBRARIES; the directory fills the channel's slot at 21. | `common/CLAUDE.md` |
| 8b | `oauth-oidc/consent_screen` | After `authn`, before `oauth2`. | `oauth-oidc/CLAUDE.md` |
| 9 | `oauth-oidc/oauth2` | Before `admin-ui/admin` (rule 5). | `oauth-oidc/CLAUDE.md` |
| 10 | `ws-federation/wsfed` | After `authn` (rule 4), whose session it signs people in to. | `ws-federation/CLAUDE.md` |
| 10a | `saml/saml2_sso` | After `authn`; it has no sign-in screen of its own. | `saml/CLAUDE.md` |
| 10b | `saml/saml11_sso` | After `authn` and after `saml2_sso` (`slugOf()`). | `saml/CLAUDE.md` |
| 10c | `federation/federation_sp` | After `authn`; it calls `startSession()` directly. | `federation/CLAUDE.md` |
| 10c-ii | `federation/federation_slo` | After `federation_sp` (its context store and key verifier) and `authn`. Requires `logout/logout` LAZILY: a require here would load `ldap_server.js` and drag its routes forward. | `federation/CLAUDE.md` |
| 11–14 | `oid4vc/*` | `vc_offers` before `vc_issuer` (rule 2). `vc_offers` is loaded by `oauth2` and so REGISTERED just before `oauth2`'s own routes, where its routes always landed. `vc_issued` (a library) is built before `vc_issuer`, and since 2026-09-17 so are `vc_status_codec`, `vc_data_integrity` and `vc_status` — the issuer allocates a status index while it builds a credential, and `vc_status` registers `/oid4vci/status-lists/*` here, ahead of it. | `oid4vc/CLAUDE.md` |
| 14-vcapi | `oid4vc/vc_api` (and its libraries `vc_jsonld`, `vc_data_model`, `vc_ecdsa_sd`, `vc_jose_cose` built before `vc_data_integrity`, `vc_did_resolver` just before it) | After `vc_verifier`, whose libraries it reads; a TEST CONTROL (`/vc-api/*`, #194-#199) that requires no route module. | `oid4vc/CLAUDE.md` |
| 14a | `oid4vc/vc_signin` | After `vc_verifier`, whose transactions it reads, and after `authn` (8), whose session it starts; `authn` declares its two paths and requires nothing here — `spnego_authn`'s arrangement (#38). | `oid4vc/CLAUDE.md` |
| 14b | `oidfed/federation_keys`, `oidfed/oidfed` | After `oauth2` and `vc_verifier`, whose metadata the Entity Configuration carries (read lazily). `federation_keys` is a library whose wire step registers its two scheduler jobs; `oidfed` registers `/.well-known/openid-federation` (the verifier's until #132) and `/oidfed/*`, the three extensions' routes among them — `extended_listing` and `entity_collection` (#135, #136) are built beside it, reached lazily, and register no route; the collection's wire step registers `oidfed.collection-crawl`. | `oidfed/CLAUDE.md` |
| 15–16 | `kerberos/krb5_kdc`, `krb5_service` | JavaScript, locked: their routes register at this require. Listeners start from `listen()`, not here. | `kerberos/CLAUDE.md` |
| 17 | `kerberos/spnego` | JavaScript, locked: registers at this require. After `krb5_service`: it calls that module's `accept()`. | `kerberos/CLAUDE.md` |
| 17a | `kerberos/spnego_authn` | After `spnego` AND after `authn/authn`; it lives in `kerberos/` so that `authn` never requires it, which would load the JavaScript `spnego` early and drag its routes ahead of `oauth2`. | `kerberos/CLAUDE.md`, `authn/CLAUDE.md` |
| 17b | `pki/pki_service` | No constraint: it requires only libraries. Here, ahead of the console, so `/admin/sts-metadata` groups the revocation endpoints with the protocols. | `common/protocol_stack.ts` (17b) |
| 17c | `pki/crypto_metadata_document` | 17b's reason (#42): libraries only, `pki.js`, `oauth2.ts`'s signer and the revocation module each LAZILY, so it may sit beside the revocation endpoints. | `common/protocol_stack.ts` (17c) |
| 18 | `admin-ui/admin` | After `oauth2` (rule 5), and before the families whose modules would otherwise have to be required from it — which is why it offers slots (rule 3e). | `admin-ui/CLAUDE.md` |
| 18-core | `admin-core/*` | No line of its own. Registers nothing, but requires `oauth2`, `saml2`, `saml11` and `federation`, so it may be required at 18 or later and nowhere earlier — since R1 such a require moves no route, but it still runs those modules' load-time code out of order. | `admin-core/CLAUDE.md` |
| 18a | `admin-ui/pki_admin` | After `admin-ui/admin`, before `mgmt-api/admin_api`, so the API's require of it is a cache hit and it needs no slot (and since R1 that require could register nothing anyway). | `admin-ui/CLAUDE.md` |
| 18b–d | `admin-ui/encryption_admin`, `database_admin`, `secrets_admin` | 18a's placement and 18a's reason: the console's shell, libraries already loaded, and `mgmt-api/admin_api` requires each in the ordinary direction. | `admin-ui/CLAUDE.md` |
| 18e | `debugger/debugger_admin` | Beside the other report pages, before `mgmt-api/admin_api` which requires it. Reads the listener's status LAZILY, because `debugger_server` requires `tls/tls_server` (20). | `debugger/CLAUDE.md` |
| 18f | `oauth-oidc/oauth2_monitor_admin` | Beside the other report pages and for 18a's reason: it requires the console's shell and libraries already loaded, and `oauth2.ts` (9) cannot require it without closing a cycle through the console. | `oauth-oidc/CLAUDE.md` |
| 18g | `admin-ui/caches_admin` | 18a's placement and 18a's reason (#74): the console's shell and libraries already loaded, and `mgmt-api/admin_api` requires it. It reads `common/cache_registry.js` when drawn, so an owner registered later still appears. | `admin-ui/CLAUDE.md` |
| 18h | `admin-ui/vc_status_admin` | 18a's placement and 18a's reason (2026-09-17): the console's shell and `oid4vc/vc_status` already loaded, and `mgmt-api/admin_api` requires it. | `admin-ui/CLAUDE.md` |
| 18i | `admin-ui/scheduler_admin` | 18a's placement and 18a's reason (#49): the console's shell and `cluster/scheduler` (a library the job owners above already loaded), and `mgmt-api/admin_api` requires it. A job registered later still appears: the page asks the scheduler when it is drawn. | `cluster/CLAUDE.md` |
| 18j | `risk/risk_store`, `risk_datasets`, `risk_failures`, `risk_upload`, `risk_engine`, then `admin-ui/risk_admin` | 18a's placement and 18a's reason (#62): libraries, then the page, after the scheduler (whose risk jobs `risk_datasets` and `risk_upload` register when wired), before `mgmt-api/admin_api`, which requires the page. **Nothing requires the libraries earlier**: `persistence.js`, `credentials.ts` and `authn.ts` reach them lazily. `risk_upload` (#215) is after the datasets it hands files to. | `risk/CLAUDE.md` |
| 18j-ii | `admin-ui/geo_map`, then `admin-ui/geolocation_admin` | 18a's placement and 18a's reason (#255): Monitoring → Geolocation, after the risk libraries whose assessments it counts, before `mgmt-api/admin_api`, which requires it. `geo_map` is a library, built just before the page. | `admin-ui/CLAUDE.md` |
| 18k | `admin-ui/mode_admin` | 18a's placement and 18a's reason (#181): the console's shell and `common/mode` (a leaf), and `mgmt-api/admin_api` requires it for `GET /admin-api/mode`. | `admin-ui/CLAUDE.md` |
| 18l | `admin-ui/mail_admin` | 18a's placement and 18a's reason (#63): Server configuration → Mail and Monitoring → Mail outbox, one module; the console's shell and the channel (8a-mail) already loaded, and `mgmt-api/admin_api` requires it. | `admin-ui/CLAUDE.md`, `common/CLAUDE.md` |
| 18m | `oauth-oidc/grant_management_admin` | 18a's placement and 18a's reason (#142): Monitoring → Grants, beside Consent; the console's shell and the grant register (built with `oauth2` at 9, which registers `/oauth2/grants/{id}` just after its own routes) already loaded. | `oauth-oidc/CLAUDE.md` (3bf) |
| 18n | `oauth-oidc/claims_providers_admin` | 18a's placement and 18a's reason (#147): the Claims Provider register's page, beside Federation; the register (built with `oauth2`'s libraries) already loaded, and `mgmt-api/admin_api` reads the API's routes out of `claims_providers_api`. | `oauth-oidc/CLAUDE.md` (3bh) |
| 18q | `admin-ui/devices_admin` | 18a's placement and 18a's reason (#164, #218): Directory → Devices, Protocols → Device registration and Monitoring → Devices, one module; the console's shell, the device register (built with `credentials`) and `oauth2` (9), whose `sessionIsLive()` it asks, already loaded, and `mgmt-api/admin_api` requires it. `/admin/ldap/devices` is `ldap_server`'s, at 21. | `admin-ui/CLAUDE.md` |
| 19 | `mgmt-api/admin_api` | After `admin-ui/admin` (rule 7). | `mgmt-api/CLAUDE.md` |
| 19a | `admin-ui/api_explorer` | After `admin-ui/admin` (the shell and gate) and `mgmt-api/admin_api` (the route table its OpenAPI document is built from); a file of its own so `admin.ts` never requires the API. | `mgmt-api/CLAUDE.md`, `admin-ui/CLAUDE.md` |
| 20 | `tls/tls_server` | JavaScript: registers its `/tls*` views at this require. Before `ldap/ldap_server`, which serves its certificate on 636. | `tls/CLAUDE.md` |
| 20a | `admin-ui/crypto_metadata` | After `tls/tls_server`: it reads algorithm tables out of eleven modules and must find each already loaded — two of them (`tls_server`, `krb5_kdc`) are JavaScript, whose require would register their routes wherever it first ran. | `admin-ui/CLAUDE.md` |
| 21 | `ldap/ldap_server` | JavaScript: registers the `/admin/ldap/*` pages at this require. After `admin-ui/admin` and `tls/tls_server` (rule 6). Fills the directory's slots. | `ldap/CLAUDE.md` |
| 22 | `scim/scim` | After `ldap/ldap_server`, as a plain require. | `scim/CLAUDE.md` |
| 23 | `spiffe/spiffe_server` | After `ldap/ldap_server` and `tls/tls_server`; its registry's store is the directory. | `spiffe/CLAUDE.md` |
| 23b | `ssf/ssf` | After `admin-ui/admin`, whose slots it fills; also fills `authn.setSessionObserver()`. Starts nothing. | `ssf/CLAUDE.md`, `authn/CLAUDE.md` |
| 23b-ii | `common/signing_rotation` | After `ssf/ssf`, whose `signingKeyRotated()` it calls (lazily, so the order is for a reader). A library: registers the `signing.rotate` and `signing.retire` scheduler jobs when built and no route. | `common/signing_rotation.ts` (#42) |
| 23b-vi | `oauth-oidc/oauth_grant_signals` | After `ssf/ssf` (23b), which it delivers through lazily, so the order is for a reader. A library: filling `admin_stats.setRevocationObserver()` when built is its whole installation, and it registers no route (#239). | `oauth-oidc/CLAUDE.md` |
| 23b-iii | `kerberos/krb5_krbtgt_rotation` | After `ldap/ldap_server` (21), whose directory slot the krbtgt key is written through (#169). A library: registers the `krb5.krbtgt-rotate` and `krb5.krbtgt-rotate-now` scheduler jobs when built and no route; reaches everything lazily. | `kerberos/CLAUDE.md` |
| 23c | `xacml/xacml` | After `admin-ui/admin`, whose slots this family fills; one require for the family, and two `register()` calls — `xacml_admin`, then `xacml`. **Requiring `xacml_role_pep.ts` here is what arms every issuance site** — before this REQUIRE (a load-time effect, not a route) `issuance_gate.js` answers "allowed". | `xacml/CLAUDE.md` |
| 23d | `gnap/gnap` | After `admin-ui/admin` and `ssf/ssf`; one require for the family, and three `register()` calls — `gnap`, `gnap_interact`, `gnap_admin`. | `gnap/CLAUDE.md` |
| 23e–g | `acme/acme`, `est/est`, `scep/scep` | **After `admin-ui/admin`** (18), whose shell each family's `_admin.ts` draws its two pages with, and after `ldap/ldap_server` (21), whose slot `common/cert_enrollment.ts` reads entries through. Each requires its own `_admin.ts`, so each family is one require in `common/protocol_stack.ts`, followed by two `register()` calls (the family, then its `_admin`); `mgmt-api/admin_api.ts` spreads each `<family>_api.ts`, which registers no route and requires its view model lazily. No constraint between the three. | `acme/CLAUDE.md`, `est/CLAUDE.md`, `scep/CLAUDE.md` |
| 23g-ii | `oidfed/oidfed_admin` | After the console (18), whose shell it draws `/admin/oidfed` with; the family itself is 14b. | `oidfed/CLAUDE.md` |
| 23h | `debugger/debugger_server` | A socket owner: builds its OWN express app and registers nothing on this one. After `authn`, `oauth2`, `tls/tls_server` and the console, all of which it reads. | `debugger/CLAUDE.md` |
| 23a | `logout/logout` | Second to last: it reads nine modules' stores. | `logout/CLAUDE.md` |
| 24 | `sts_metadata` | TypeScript (#50): its `wire` step hands `PROTOCOLS` to the crypto page (20a), and its `register()` — `/admin/sts-metadata` — is the last one. **Last, for everybody.** It reads the router to list what everything else registered. | *Adding an endpoint*, below |

### Where the numbered rules live now

The prose throughout this repository cites rules by number, and the numbering is
kept rather than renumbered — a renumber would silently invalidate every citation
in every file, including the ones in the source comments. This is the index.

| Rule | About | File |
|---|---|---|
| 1 | A composition root (`common/protocol_stack.ts`) registers every converted module's endpoints, in order; a JavaScript module still registers when required | this file |
| 2 | `vc_configs.ts` / `vc_offers.ts` break require cycles | this file, `oid4vc/CLAUDE.md` |
| 3 | A library registers nothing (`dpop.js`) | this file |
| 3a, 3a-ii | `vc_claims.ts`, `vc_verifier_config.ts` | `oid4vc/CLAUDE.md` |
| 3b, 3c, 3d, 3d-ii | `admin_stats.js`, `audit.js`, `claim_attributes.js`, `group_claims.js` | `common/CLAUDE.md` |
| 3d-iii | `scim_map.ts` | `scim/CLAUDE.md` |
| 3e | The inverted hooks, and the test for adding one | this file |
| 3f, 3h, 3i, 3j | `oauth2_bcp.js`, `mtls.js`, `client_auth.js`, `authorization_servers.js` | `oauth-oidc/CLAUDE.md` |
| 3ah | `oauth21.js`, OAuth 2.1 as a mode that implies RFC 9700 mode, and why it is a mode of its own | `oauth-oidc/CLAUDE.md` |
| 3an | RFC 8705 both halves: `tls_client_auth`'s implicit (issued to the application) and explicit (one of five subject parameters) mappings over a verified chain, the declaration held in every mode, section 7.1's refresh rule | `oauth-oidc/CLAUDE.md` |
| 3g | `applications.js` | `common/CLAUDE.md` |
| 3r | `crypto.js`, why it is a leaf, why the verifier is told which element, and why XML encryption moved rather than being replaced | `common/CLAUDE.md` |
| 4a | `saml2_sso.ts` after `authn.js`, and why it has no screen | `saml/CLAUDE.md` |
| 4b | `federation_sp.ts` after `authn.js`, and why it needs no screen at all | `federation/CLAUDE.md` |
| 4b | `saml11_sso.ts` after `authn.js` and after `saml2_sso.ts`, and why the two profiles are separate implementations | `saml/CLAUDE.md` |
| 3l | `delegation.js`, and why it has no funnel | `common/CLAUDE.md` |
| 3az | `delegation_policy.ts`, who may act for whom at WS-Trust and RFC 8693: Kerberos's model on application entries, the person's two flags, `may_act`, the deny-only XACML layer, enforced in product | `common/CLAUDE.md` |
| 3s | `app_permissions.js`, why a CONFIGURED register is not the observed one with a flag on it, and why the ordering rule lives in `applications.js` | `common/CLAUDE.md` |
| 3t | `consent.js`, why an OVERRIDE is not a RECORD, and why the client_id is the last field of the value | `common/CLAUDE.md` |
| 4c | `consent_screen.js` after `authn.js` and before `oauth2.js`, and why the screen holds the records while the register holds none | `oauth-oidc/CLAUDE.md` |
| 3u | `roles.js`, the two relations it keeps apart (who HOLDS a role against what REQUIRES one), the six computed built-ins, and why it is a plain require rather than a fifth inverted hook | `common/CLAUDE.md` |
| 3v | `issuance_gate.js`, why an empty decider means ISSUE, and why the one case that must fail CLOSED lives in the PEP rather than here | `common/CLAUDE.md` |
| 3w | `pki.js`, why the hierarchy is three tiers or none, why it keeps no store of its own, and what a path check must refuse | `common/CLAUDE.md` |
| 3aa | `pki_authoring.js`, the Certificate & Key Configuration pane as a model: why it is not `pki.js` and not the renderer, why the FORM is the state, why the field table is a table, and why the slow key generation deliberately does not use the worker pool | `common/CLAUDE.md` |
| 3x | `assertion_grant.js`, why RFC 7521 and RFC 7523 are one file, why `client_auth.js` requires it and never the reverse, and why the issuer must be declared | `oauth-oidc/CLAUDE.md` |
| 3ab | `person_assertions.js`, a PERSON as an RFC 7523 issuer, and why their key may assert about them and about nobody else | `common/CLAUDE.md` |
| 3ac | `password_policy.js`, the password policy's default profile as a directory entry, why it is not seeded, why a save carries every field, the generator, and why `credentials.preparePassword()` is where every door — the LDAP modify included — asks it | `common/CLAUDE.md` |
| 3ad | `revocation_status.js`, revocation CONSULTED for a presented certificate: the register for this service's own, the CRL for anybody else's, the policy by mode, and why the main port is annotated rather than refused | `common/CLAUDE.md` |
| 3ak | `request_object.js`, RFC 9101: registered-only `request_uri`, the query replaced by what was signed, the round trip that carries the object, the refusal order, OIDC 10.2's symmetric key | `oauth-oidc/CLAUDE.md` |
| 3am | `authorization_details.js`, RFC 9396: types declared by resource applications, refused in every mode, the audience as an input to RFC 9068's plan, section 6's subset with the refresh token keeping the grant, consent asked every time and spent once | `oauth-oidc/CLAUDE.md` |
| 3an | `step_up.js`, RFC 9470: a session assessed against `acr_values` and `max_age` before it is answered, one sign-in then `unmet_authentication_requirements` in every mode, ordered acr levels and the requested value in the token, the challenge from the stand-in resource and this service's own resource server | `oauth-oidc/CLAUDE.md` |
| 3al | `par.js`, RFC 9126: a push validated by the authorization endpoint's own `vetAuthorizationRequest()`, client authentication as at the token endpoint, the URN resolved through JAR, spent when a response is issued, the two policies asked before vetting | `oauth-oidc/CLAUDE.md` |
| 3aj | `software_statement.js`, RFC 7591 section 2.3: who is trusted, precedence, the closed-endpoint door and the update binding | `oauth-oidc/CLAUDE.md` |
| 3ai | `introspection_jwt.js`, RFC 9701: why a JWT request authenticates in every mode, the Accept reading, what keeps the response from being a token, and refused-never-downgraded | `oauth-oidc/CLAUDE.md` |
| 3ah | `jwt_access_token.js`, RFC 9068 in every mode: the `at+jwt` header, why `issuerOf()` moved there, section 4 at every resource server, and the audience-and-scope plan behind section 3's refusals | `oauth-oidc/CLAUDE.md` |
| 3z | `saml_assertion_grant.js`, why RFC 7522 is a SECOND implementation rather than a format flag on 3x, why its two sections are one function where 3x's are two files, why a bare certificate path is not enough here, and the three items of section 3 whose lenient reading is the usual bug | `oauth-oidc/CLAUDE.md` |
| 3y | `backup_codes.js`, why a set is issued by an ACT and not a request, why ONCE is about the set rather than the account, and why the codes were once ENCRYPTED and are now scrypt-HASHED per code, as `userPassword` is (2026-09-12) | `common/CLAUDE.md` |
| 3z | `inetorgperson.js`, why the account page draws a FIXED LIST rather than the entry, and the two kinds of attribute `rowFor()` refuses | `common/CLAUDE.md` |
| 3ac | `error_codes.js`, the three ways a code is recorded, why a returned refusal carries its code under a Symbol, and the three changes it made to `audit.js` | `common/CLAUDE.md` |
| 3ae | `used_assertions.js`, why an RFC 7523 or RFC 7522 assertion is accepted once EVER — one history for both uses, persisted in every store with one and in both modes, claimed atomically on postgres, and spent only when tokens are issued | `common/CLAUDE.md` |
| 3ag | `cert_enrollment.js`, the core ACME, EST and SCEP issue through: the identity rule, the profiles, the proof of possession, names from the entry, storage on the entry, the two entry-bound credentials | `common/CLAUDE.md` |
| 3ar | `vc_issued.ts`, the register of credentials this realm issued for a person on an access token it verified, why a credential's own `sub` cannot say whom a presentation signs in, its two kinds of row, and the three acts that DISOWN one | `oid4vc/CLAUDE.md` |
| 3as | `vc_status.ts` and `vc_status_codec.ts`, the Token Status List and the two Bitstring Status Lists a realm publishes: one index per credential, a bit that is COMPUTED rather than stored twice, and the Verifier's check against this realm's own entries and a trusted foreign issuer's fetched list | `oid4vc/CLAUDE.md` |
| 3at | `vc_data_integrity.ts`, the holder's Data Integrity proof on a presentation (the three JCS cryptosuites, `did:jwk` and `did:key`), which is what gives `ldp_vc` a holder binding it had none of | `oid4vc/CLAUDE.md` |
| 3ax | `app_passwords.ts` and `credentials.ts`'s `secondFactorRefusal()`, #101: a second-factor person's own password refused at the five password-only doors in product as a wrong password is, and the app passwords — generated, hashed, scoped to doors, found by a public id, never at a browser sign-in — accepted there instead | `common/CLAUDE.md`, `authn/CLAUDE.md` |
| 3bb | Native SSO (#130) in `oauth2.ts` and `devices.ts`: the device_sso scope held to a flag and a shared group, the device secret on a session-bound `ou=devices` entry and never rotated, the section 4 exchange, RFC 8693's token types read for every exchange | `oauth-oidc/CLAUDE.md`, `common/CLAUDE.md`, `ldap/CLAUDE.md` |
| 3bd | OpenID Federation 1.1 (#132, #133), `oidfed/`: the realm's Entity Identifier is its issuer; every role per realm with the default realm a Trust Anchor over the others; a Federation Entity Key table of its own rather than a unit of the key generations; resolution walking only toward a configured Trust Anchor, bounded, never for an unauthenticated resolve; Trust Marks in full | `oidfed/CLAUDE.md` |
| 3bf | `grant_management.ts`, Grant Management for OAuth 2.0 (#142): a register of its own written only when a grant's tokens are claimed, create/merge/replace at the authorization and CIBA endpoints, refresh tokens bound to the grant's generation, `/oauth2/grants/{id}` under two protected scopes, a DELETE revoking every recorded token; and FAPI-CIBA as `fapi.js` rules at `bc-authorize` whenever a FAPI profile is on | `oauth-oidc/CLAUDE.md` |
| 3bg | What the OpenID conformance suite found (#176): RFC 9449 section 5's unbound refresh token for a client that authenticated, RFC 6749's error_description set in every mode, RFC 9101 section 4's nested request refused, a client assertion naming no client or two, `x-fapi-interaction-id` on the protected resources, Grant Management's query after revoke | `oauth-oidc/CLAUDE.md` |
| 3bn | `vc_api.ts` and its libraries (#194-#199): the W3C VC-API test endpoints as a development-only test control behind the protected `vc-api:*` scopes, the RDFC suites and `ecdsa-sd-2023` over a closed JSON-LD loader that fetches nothing, the data model's MUSTs, VC-JOSE-COSE, DID resolution, and the six W3C suites that hold them | `oid4vc/CLAUDE.md`, `tests/CLAUDE.md` |
| 3bh | `claims_providers.ts`, OpenID Connect Claims Aggregation (#147): the `ou=claimproviders` register, the person's link on `/portal/claim-sources` with their tokens sealed on their entry, aggregated or distributed per provider for a claim the entry does not answer, and `federation_sp` honouring a source only from a registered provider its keys verify | `oauth-oidc/CLAUDE.md` |
| 3bm | `client_attestation.ts`, OAuth 2.0 Attestation-Based Client Authentication (#229, draft 11): `attest_jwt_client_auth` and `_dpop` through `client_auth.js`'s one path, attesters trusted per realm (x5c anchors or a JWKS), single-use challenges, the PoP spent in the used-assertion history, refresh tokens and PAR codes bound to the instance key, FAPI 2.0 only behind HAIP's setting | `oauth-oidc/CLAUDE.md` |
| 3bi | OpenID Connect Enterprise Extensions (#148): `session_expiry`, `tenant` (the realm id) and `aud_sub` in the ID Token, a `tenant` naming another realm refused, `domain_hint` home-realm discovery through `fedHomeRealmDomain`, the portal launch's three parameters | `oauth-oidc/CLAUDE.md` |
| 3bj | The Ephemeral Subject Identifier (#149) in `pairwise_subjects.ts`: a random `sub` per authentication and client held in `oauth2.ephemeralSubjects` and purged by a job, the session passed wherever a client-facing `sub` is made, `localFor()` for an id_token_hint, and SSF naming the owning client's `sub` | `oauth-oidc/CLAUDE.md` |
| 3bk | RFC 8628 (#150) in `device_authorization.ts` and `/portal/device`: device codes in a persisted per-realm map swept by a job, one claimed redemption per approval, section 5's two protections on the page; and OpenID Connect Key Binding — `bound_key` with `dpop_jkt`, `c_s256`, `cnf.jwk` with `typ: dpop+id_token`, `kb_jkt` across refresh, section 7 at token exchange — and ML-DSA DPoP keys | `oauth-oidc/CLAUDE.md` |
| 3bl | OpenID Provider Commands (#151) in `provider_commands.ts`, and `outbound_delivery.ts` — ONE durable outbound queue whose kinds are back-channel logout, CIBA ping/push and Command Tokens; tenant commands over `federation_http.streamEvents()`; the account-state register; automatic commands through `ldap_server`'s `addAccountObserver()` and `logout.terminate()`; the callback; the mock relying party | `oauth-oidc/CLAUDE.md` |
| 3bo | The registered device in decisions (#164 phases 5 and 6), `devices.ts` and `device_recognition.ts`: five risk signals (two of them lowering) and the device's own level; the device's facts in every issuance request, a compromised device refused by default and a compliant one required only where a realm says; `urn:sts:acr:compliant-device`; `device_id` by the subject rule (per sector for pairwise, none for ephemeral) | `common/CLAUDE.md`, `risk/CLAUDE.md`, `xacml/CLAUDE.md`, `oauth-oidc/CLAUDE.md` |
| 3bp | What the rest of the OpenID conformance suite found (#187): every other plan that applies (OpenID Connect, logout, Identity Assurance, the FAPI variants, SSF, OpenID Federation, OpenID4VCI and OpenID4VP), each finding fixed in every mode, and the warnings and plans that stay with their reasons | `oauth-oidc/CLAUDE.md` |
| 3bc | `ciba.ts` and `oauth2.ts`'s `/oauth2/bc-authorize`, CIBA (#131): the person approves on `/portal/ciba` as strongly as `acr_values` asks, poll / ping / push with each notification a persisted delivery retried by the `oauth2.ciba-sweep` job and dead-lettered, nothing relaxed in development | `oauth-oidc/CLAUDE.md`, `portal/CLAUDE.md` |
| 3ba | `siop.ts`, SIOPv2 as the relying party (#129): a self-issued subject enrolled on the entry (by proof on the portal, by value by an administrator), refused unenrolled in both modes, section 11.1, a did:web fetched only when enrolled, the four Client Identifier prefixes | `oid4vc/CLAUDE.md` |
| 3ay | `identity_assurance.ts`, OpenID Connect for Identity Assurance 1.0 (#127): verifications recorded on the entry by an administrator or a wallet or certificate sign-in, only directory values verified and released while unchanged, `value`/`values` enforced on the verification only, development's `urn:sts:demo` | `common/CLAUDE.md` |
| 3ba | `mail.ts`, `mail_transports.ts`, `mail_templates.ts`, `mail_uses.ts`, #63: one outbound mail channel — a per-realm persisted outbox delivered once for the cluster by a claimed lease and the `mail.deliver` job, five transports behind one method, recipients from the directory only, links on the pinned origin, ceilings and duplicates, templates that load nothing, and the four uses | `common/CLAUDE.md` |
| 3bd | `authn_policy.ts` and `admin-core/policy_kinds.ts`, #64: which mechanisms a realm accepts as first and second factors — a policy of its own, inherited from the default realm, on the ONE Policies page that holds every kind of policy; it retired `authn.mfaRequired`, `totp.enabled` and `backupCodes.enabled` | `common/CLAUDE.md` |
| 3be | `mail_factor.ts` and `authn/email_factor.ts`, #64: the emailed code and sign-in link, off by default (NIST SP 800-63B-4 3.1.3.1), a person's opt-in, hashed single-use secrets, a link bound to its browser, and which addresses are verified by whom | `common/CLAUDE.md`, `authn/CLAUDE.md` |
| 3ap | `cache_registry.js`, every cache and replay store describing itself to `/admin/caches`: why a leaf in JavaScript, why a row is five members, where a lookup is counted, and why valid is the owner's call | `common/CLAUDE.md` |
| 3p | `user_graph.js`, and why the union of two registers is a library rather than a page | `common/CLAUDE.md` |
| 3o | `federation.js`, why four modules may require it, and why `PATHS` is not beside the routes | `federation/CLAUDE.md` |
| 3m | `realms.js`, the realm slot in `config.js`, and why the realm is ambient | `common/CLAUDE.md` |
| 3q | `persistence.js`, the override-store slot in `config.js`, the directory slot it offers, and why `realms.onChange()` is an event rather than a third slot | `persistence/CLAUDE.md` |
| 3m | `logout/logout.ts` holds no state, and the reading order is not the ending order | `logout/CLAUDE.md` |
| 3n | `frontchannel_logout.js` | `oauth-oidc/CLAUDE.md` |
| 3aq | `backchannel_logout.ts`, OpenID Connect Back-Channel Logout 1.0: triggered where a session ends OR EXPIRES, each delivery a persisted row sent once through a claimed lease whose time is the fence, retried by any node across restarts, dead-lettered and retried by hand | `oauth-oidc/CLAUDE.md` |
| 3as | `id_token_encryption.ts`, OIDC Core 10.2's encrypted ID Token — and the Logout Token encrypted the same way | `oauth-oidc/CLAUDE.md` |
| 3at | `account_state.ts`, a DISABLED account: the one place `pwdAccountLockedTime` is written, what ending everything it holds means, and the doors that ask | `common/CLAUDE.md`, `authn/CLAUDE.md` |
| 3au | `scope_policy.ts` and `scopeRefusal()`, #110: a scope tied to the client that declares it (`oauthAllowedScope`) — this service's protected scopes in both modes, every other scope in product, refused at the endpoints, narrowed in `tokenSet()`, re-checked by `/admin-api`, SCIM and Shared Signals | `common/CLAUDE.md`, `oauth-oidc/CLAUDE.md` |
| 3av | `fapi.js`, the FAPI profiles over RFC 9700 mode — 1.0 Baseline (#138) and Advanced (#139), and FAPI 2.0's Security Profile (#140) and Message Signing (#141): per realm or per named authorization server (ambient), the checks beyond that mode, consent, the sender constraint, rotation, PS256 by default, and the hosted surfaces conforming | `oauth-oidc/CLAUDE.md` |
| 3aw | `jarm.ts`, JARM (#143) in every mode: one place sends it (`redirectBack()`), the four modes, the signed and optionally encrypted response, never sent unsecured | `oauth-oidc/CLAUDE.md` |
| 3ax | `session_management.js`, OpenID Connect Session Management 1.0 (#121), off by default: the OP browser state minted with the session handle, `session_state` on every authentication response, the OP iframe framed only by registered relying parties, and its script | `oauth-oidc/CLAUDE.md` |
| 3k | SPIFFE's six modules | `spiffe/CLAUDE.md` |
| 4 | `wsfed.ts` after `authn.js` | `ws-federation/CLAUDE.md` |
| 5 | `admin.js` after `oauth2.js` | `admin-ui/CLAUDE.md` |
| 6 | `ldap_server.js` after `admin.js` and `tls_server.js` | `ldap/CLAUDE.md` |
| 6a (SCIM), 6a-ii | `scim.ts`, `scim_auth.ts` | `scim/CLAUDE.md` |
| 6a (SPIFFE) | `spiffe_server.js` | `spiffe/CLAUDE.md` |
| 7, 7a | The console/API parity rule, the breadcrumb trail | `mgmt-api/CLAUDE.md`, `admin-ui/CLAUDE.md` |
| 8, 8a, 8b | The console's gate, its two roles, and the claim they qualify | `admin-ui/CLAUDE.md` |

Two rules share the number `6a` and always did — one for SCIM and one for
SPIFFE. They are now in different files, which is the first thing that has ever
made that collision harmless.

---

## Socket owners start their listeners from `listen()`, not at require time

The two Kerberos modules, `ldap/ldap_server.js`, `spiffe/spiffe_server.ts`,
`pki/pki_service.ts` (the plain-HTTP revocation listener) and
`debugger/debugger_server.ts` are the exception to rule 1 in one direction
only: their HTTP views are registered like everything else — at the require
for the three JavaScript modules, by `common/protocol_stack.ts`'s `register()`
for `spiffe_server` and `pki_service` since #50's R1, and on an express app of
its own for the debugger — but **their own listeners are started from
`listen()` in `server.js`**, never from a require or a `registerRoutes()`:
binding a port can fail, and a `require` that throws takes the whole service
down where a route cannot. A failure to bind is RECORDED rather than thrown
and published on the family's own view (`GET /admin/ldap/service`, SPIFFE per
socket) or logged under its error code, because the HTTP view answers 200
either way. **`tls/tls_server.js` was on that list until
2026-09-16**, when its two listeners were deleted; it keeps `listen()` as a
no-op so the call site did not change on the same day (`tls/CLAUDE.md`).

**`persistence/persistence.js` binds nothing and still goes first**: the store
is opened by `persistence.start()` before any listener binds, and **a failure
there is FATAL where the others are recorded** — the only place in this
repository where failing to open something stops the process.
`persistence/CLAUDE.md` argues both halves.

## `frame-ancestors` is the one CSP clause a page may not drop

RFC 9700 section 4.14. `app.js` sets the policy on every response, and a
growing number of routes relax it — the eleven scripted pages below, and others
that widen `img-src`, `style-src`, `frame-src` or `connect-src` — by SETTING
THE WHOLE HEADER, so each of them could lose the framing clause with nothing
failing: the page works, the script runs, and the protection is gone.
**`frame-ancestors` has no fallback from `default-src`**, which is why
`default-src 'none'` alone is not enough and why this needs saying.

Two rules come out of it:

* **A relaxation goes through `app.contentSecurityPolicy(overrides)`**, which re-adds
  `frame-ancestors` and `base-uri` whatever the caller asked for. A caller cannot turn
  them off — that is deliberate, not an oversight in the API.
* **The policy is re-checked when the response is flushed.** Express's own 404 handler
  REPLACES the header with `default-src 'none'`, so every unrouted path was framable
  as far as CSP was concerned; nothing here could have shown it, because the header
  this service set was correct and something else overwrote it. The check is "does it
  still carry the clause", not "is it the value I set", so the relaxations are
  untouched.

**THE ONE PAGE THAT MAY BE FRAMED IS THE OP IFRAME (#121, 2026-09-23)**, and
it narrows the clause rather than dropping it: `app.framedContentSecurityPolicy()`
— a second, named door, so `contentSecurityPolicy()` keeps its rule — sets
`frame-ancestors` to the origins of the realm's registered redirect URIs, and
to `'none'` when there are none or when anything given is not an http(s)
origin. `*` is unreachable through it. OpenID Connect Session Management
cannot work otherwise, since the iframe exists to be framed by a relying
party; it is off by default (`oauth2.sessionManagement`). `oauth-oidc/CLAUDE.md`
argues it.

**Do not replace Express's 404 body.** `Cannot GET /path` is how
`tests/vendored/sts_metadata.js` tells an unrouted path from an endpoint legitimately answering
404. Fixing the header was the whole fix; a prettier 404 would break that test
silently.


## Eleven pages here have a script on them, and each is the same exception

`app.js` sets `script-src 'none'` for the whole service, and the reason is in its
own comment: it is what makes the family of reflected-content problems moot rather
than merely unlikely. Eleven pages need a script and each takes the SAME shape of
exception — `script-src 'self'` naming one resource, never `'unsafe-inline'` —
and **each but the OP iframe carries a REAL SUBMIT BUTTON as well**, because
with the script blocked the button is the whole mechanism. The OP iframe has
no person in front of it and nothing to submit; its argument is its row.

| Page | Script | Argued in |
|---|---|---|
| `/authn/webauthn` | `/authn/webauthn.js` | `authn/CLAUDE.md` |
| WS-Federation's sign-in response | `/wsfed/autopost.js` | `ws-federation/CLAUDE.md` |
| `response_mode=form_post` | `/oauth2/autopost.js` | `oauth-oidc/CLAUDE.md` |
| `/admin/api-explorer` — the one console page with a script | the explorer | `mgmt-api/CLAUDE.md`, `admin-ui/CLAUDE.md` |
| the SAML 2.0 HTTP POST binding | `/saml2/autopost.js` | `saml/CLAUDE.md` |
| the SAML 1.1 Browser/POST profile | `/saml11/autopost.js` | `saml/CLAUDE.md` |
| `/portal/keys` | `/authn/webauthn.js` — the SAME resource, not a copy | `portal/CLAUDE.md` |
| `/portal/devices`, **only while a WebAuthn link ceremony is armed** (#164 phase 2) | `/authn/webauthn.js` in `get` mode — a fresh assertion links a platform credential to a device; the page's key-proof form beside it runs no script | `portal/CLAUDE.md` |
| `/authn/wallet/wait` (2026-09-17) | `/authn/wallet.js` — the W3C Digital Credentials API call, which no markup can make | `oid4vc/CLAUDE.md`, `authn/CLAUDE.md` |
| the sign-in screen `/authn/login`, **only while `risk.fingerprinting` is on in the realm** (#62 P6, off by default) | `/authn/fingerprint.js` — FingerprintJS (MIT, served with its notice) computing a browser identifier, which no markup can; the form works with it blocked, the field simply empty | `authn/CLAUDE.md`, `risk/CLAUDE.md` |
| `/oauth2/check_session` (#121, 2026-09-23, off by default) | `/oauth2/check_session.js` — it answers a relying party's `postMessage`, which no markup can; so it is the one page here with **NO submit button**, and with script off a relying party's question simply goes unanswered | `oauth-oidc/CLAUDE.md` |

**The embedded debugger's pages are NOT on this list, because they are not on
this origin** (2026-09-13): `debugger/debugger_server.ts` serves them on a
listener of its own with a policy that allows their inline scripts THERE, which
is the reason it is a separate origin — `debugger/CLAUDE.md` argues it.

**The test for a script is that the page CANNOT work without one**, and the
refusals are what establish it. Each is argued in its own file:

| Refused | Because | Argued in |
|---|---|---|
| federation's outbound HTTP-POST binding | a person LEAVING this service gets a real form and a real button | `federation/CLAUDE.md` |
| the delegation and federation pictures | laid out on the server, arriving as ordinary markup | `admin-ui/CLAUDE.md` |
| the console's collapsible prose | a `<details>` needs no script | `admin-ui/CLAUDE.md` |
| the one-time code screen `/authn/totp` | typing six digits needs none, and the QR code is a server-rendered SVG | `authn/CLAUDE.md` |
| the wallet sign-in's wait page `/authn/wallet/wait` | a `<meta>` refresh is the poll, and its QR code is a server-rendered SVG | `oid4vc/CLAUDE.md` |
| the console's account menu | `<details>`/`<summary>`; the cost (it does not close on an outside click) is stated on the page | `admin-ui/CLAUDE.md` |
| the certificate details dialog | a link and a server-drawn overlay, a round trip per open | `admin-ui/CLAUDE.md` |
| the wallet sign-in's QR page (`?qr=1`) | a `<meta>` refresh is the poll and the code is a server-drawn SVG — the page next to it argued its own script from scratch | `oid4vc/CLAUDE.md` |

**A new scripted page needs the argument made again from scratch, and "the same
as the page next door" is not one.** The federation picture is the delegation
picture in every respect a reader would cite and got its own argument anyway;
`/authn/totp` sits beside a page that DOES relax the policy and still had to
argue its own case.

---

## Adding an endpoint costs one entry in `sts_metadata.ts`

`GET /admin/sts-metadata` reads the endpoint list **from the running Express router**, so
it cannot go stale — but it reports two kinds of drift and this repository's own
`tests/vendored/sts_metadata.js` fails on both: a route registered and undescribed, and a
description whose path is not registered (what a rename produces). See
`docs/endpoints.md`.

It is a **console page** since 2026-08-24 (it was `/sts-metadata`), so it is
behind the console gate and is drawn by `admin.js`'s `page()`: this module
builds the body and `admin.respond()` supplies the shell. Adding a PROTOCOL
family costs a card in that file's `PROTOCOLS` as well as the entry above —
the page reports an endpoint group no card claims, so leaving it out fails the
same test rather than going quietly.

**A new route module written in TypeScript also owes a `register()` line in
`common/protocol_stack.ts`**, after its require, at the place its routes
belong (rule 1): requiring it registers nothing, so without that line its
routes do not exist, and the drift check below reports every description of
them as a path that is not registered.

**So adding a protocol family costs four things**: an entry in `ENDPOINTS`, a
card in `sts_metadata.ts`'s `PROTOCOLS`, a row in
`admin-ui/crypto_metadata.ts`'s `FAMILIES` — the second metadata page,
`/admin/crypto-metadata`, checks its family list against `PROTOCOLS` in both
directions — and the card's name in the `cards` of a row of
`common/realms.js`'s `realmSupport()`, which is what `/admin/realms` draws as
*What is separated, and what is shared*. `tests/vendored/sts_metadata.js`
fails on the first two, `tests/vendored/admin_api.js` on the third and
`tests/realm_support.js` on the fourth. What nothing checks, and what a
settings group also owes, is a row in `admin-ui/admin.ts`'s `SETTING_HOMES`;
`admin-ui/CLAUDE.md` carries that and the second page's argument. **A new
page under Protocols also owes a row in `admin-core/protocol_endpoints.ts`**
(the endpoints of its realm, drawn on the page) or an exemption with its
reason; `tests/protocol_endpoints.js` fails otherwise.

**AND A CARD IS NOT ALWAYS A PROTOCOL, WHICH IS WHY THE COUNT IN THE OVERVIEW
AND THE COUNT ON THAT PAGE ARE DIFFERENT NUMBERS.** Two cards carry
`notAProtocol` — the User portal, which is an APPLICATION, and **Recovery codes
(2026-09-10), which is a credential mechanism with an endpoint, a verifier and a
store, and simply has no document**: nobody ever wrote a specification for a
recovery code. The marker says which of those two situations a reader is looking
at, and `tests/vendored/sts_metadata.js` asserts that every other card names a
specification — so the marker is what keeps that rule strict for everything it
was written for. A card still costs all three things above whether or not it is
a protocol, because the rule the page enforces is *no endpoint group without a
card*, and paying it here is cheaper than making the rule conditional.

**Those drift checks are enforcement rather than documentation**: `sts_metadata.ts`
is this repository's own job and a route registered and undescribed fails the
suite here.

Reading the router has one blind spot: **a protocol that registers no route is
invisible to it**, which is exactly what the KDC's raw TCP/UDP 88 listeners are — and
the directory's two, plain 389 and LDAPS 636. Those
have to be described by hand or they go unlisted with nothing failing.

Coverage notes in that file **must start `full`, `partial` or `mock`** and say what is
missing. A list of fifty specifications that did not mention that this service
checks no passwords and validates no access tokens would be the most misleading thing
in the repository.

## Every failure has an error code, and no client ever sees one

Every way this service can fail or refuse has a code `STS-<SUBSYSTEM>-<NNNN>` in
the ONE table in `common/error_codes.js`; `docs/error-codes.md` is generated from
it. **The code is an operator's name and is RECORDED, NEVER SENT** — it goes on
the audit row and at the front of a log line, never in a response, and it
changes no specification's error.

**A new failure is not finished until it has a code**, and that is enforced:
a row in the table, a `mark()` / `errorCode:` / `tag()` where the failure is
detected, and `node common/error_codes.js --docs`. `tests/error_codes.js` fails
otherwise. A code is never renumbered or reused. `common/CLAUDE.md` argues the
design.

## Code style

**THESE ARE THE PARENT PROJECT'S RULES SINCE 2026-09-12** — its root
`CLAUDE.md`'s *Style Notes* — adopted here and swept across the tree that day.
They bind every `.js` file except `common/vendored/`, the eight Kerberos codec
copies, the `node-ldapjs` submodule and the non-`local` copies in
`tests/vendored/`, none of which may be edited here.

* **Every named function is entered and left out loud.** Its first statement
  is `log.debug("Entering NAME().")` and every exit goes through
  `log.debug("Leaving NAME().")`, where `NAME` is its own name — declarations,
  `const f = function () {…}`, object and class methods. Several `Leaving`
  lines in one body is correct: one before each `return`, and one before a
  trailing `throw`. Anonymous inline callbacks are left alone. **The standing
  exception is a hot path, and it must say so** in a comment above the function
  naming it — a comment such as "no Entering/Leaving pair … would drown the
  log" is what the sweep honoured, and an exception without one is
  indistinguishable from an oversight. Code that runs in a browser or in a
  `node -e` child is exempt, and `common/config_file.js` (no logger exists yet)
  says why in its header; `mgmt-api/admin_api_explorer.js` carries a
  console-backed `log` of bunyan's shape instead, the parent's arrangement for
  files that cannot reach bunyan.
* **No swallowed exception.** Every `catch` does something with what it caught:
  `log.debug("Caught in NAME(): " + ((e && e.message) || e))` at the least, and
  a promise `.catch()` or `.then(ok, fail)` handler the same. A catch that runs
  before the module's logger exists records the error in a variable
  (`logLevelProblem`, `appconfigProblem`) and the line after the logger is made
  reports it; code in a `node -e` child carries it on the result it returns.
  The comment saying WHY it is handled that way is still required as well.
* **No single-line `try`/`catch`**, and no one-line block a log line has to go
  into — `if (x) { return y; }`, `case X: return y;` and a callback's
  `{ return x; }` open out. JavaScript inside a string (a script served to a
  browser, a child process's program) is data and stays as written.
* **80 columns.** Break at a comma, after a binary operator (it stays on the
  first line), after `?` and `:`, before each `.method()` of a long chain, and
  after `=` as a last resort; a long string becomes a concatenation. A
  continuation keeps the column the construct already uses. What stays long:
  a `require()` string, a regex literal, a URL, a template literal, a test
  vector that cannot be cut into fitting pieces, a comment holding a table or an
  aligned layout, and an `error-code: none —` exemption (it must stay within two
  lines of the line it exempts). About 560 lines are over for those reasons.
  **A source-inspection test must read a statement rather than a line** —
  `tests/error_codes.js` and `tests/return_address_provenance.js` both broke on
  this sweep and were fixed that way.
* **One blank line between one function and the next.**
* **The log level is `info` in every appconfig file in `env/`** (2026-09-12),
  because every function now logs its entry and exit at `debug`.
  `STS_LOG_LEVEL=debug` is the run that asks for the whole record.
* **Never read a setting as `Number(config.value(key) || n)` where `0` is a legal
  value.** `0 || n` is `n`, so the setting silently cannot be set to the one
  value its own description often calls out — `totp.window`'s "a perfectly
  synchronised clock" and `backupCodes.groupSize`'s "unbroken" were both
  unreachable until 2026-09-12, and two readers of `pki.crlLifetimeMinutes`
  floored a `min: 1` row at sixty. Let the row's `min`/`max` bound it and read the
  value directly.
* **A behaviour that differs between development and product is a `common/mode.js`
  predicate at the call site, never a literal and never `mode.isProduct()`.** An
  audit on 2026-09-12 found roughly thirty development behaviours written as
  literals with no mode check at all — fixture passwords, a persona surname in
  every ID Token, an ungated trust-anchor endpoint, a return address taken from
  the request — so product mode had shipped every one. The predicates are named
  for the QUESTION (`seedsDemoData()`, `inventsClaimValues()`,
  `acceptsUnregisteredAddresses()`, `opensTestControls()`,
  `sendsWeakerThanAsked()` beside the older four), and `mode.js`'s
  `REQUIREMENTS` is where each is described to `/admin/mode` and the API. A new
  tunable is a `config.js` row whose default is the old literal, read where it
  is used.
* **A file in a type-checked directory starts with `// @ts-check`** (after a
  `#!` line, if it has one), and `npm test` fails on a type error in it
  (`tests/typecheck.js`). Every service directory is one (#50). A type
  the JavaScript cannot state goes in `types/` as a declaration, or in JSDoc
  beside the code; a cast (`/** @type {any} */ (x)`) is for a library whose
  declared types are wrong, and says so in a comment. **Checking may not
  change behaviour** — an edit made for the checker is the same program.
* **A module converted to TypeScript (#50) is a CLASS whose dependencies arrive
  through its constructor**, requires with `import x = require('...')` (the
  same `require` once compiled, so the require order is untouched) and exports
  with `export =`. **A converted route module registers nothing at load**: it
  exports `registerRoutes(app)` and `common/protocol_stack.ts` calls it (rule
  1, #50's R1). A small helper is a STATIC method of a utility class
  (`common/html.ts`'s `Html.esc()`), never a free function. Until the
  composition root also CONSTRUCTS the modules (#50's R2), a converted module
  also exports the names its unconverted callers require, and its
  `registerRoutes`, from an instance it builds — marked TRANSITIONAL. `common/realm_chooser.ts` is the pattern.
* **A refusal or a failure carries an error code** — see *Every failure has an
  error code* above. `errorCodes.mark(res, 'STS-…')` on the line before the
  call that sends an HTTP refusal, `errorCode: 'STS-…'` on an audit row, and
  `errorCodes.tag('STS-…')` at the front of a `log.error` that has neither.
* Comments carry the *reasoning*, especially where something went wrong once. The
  density in this codebase is deliberate; match it rather than trimming it.


## node-ldapjs is a SUBMODULE, it is nested, and it is changed only in the fork

**The fork is `rcbj/node-ldapjs` and it is ours to change (2026-09-18)** —
the first change is the `routeAnonymousBinds` server option
(`ldap/CLAUDE.md`, the bind refusals). A change goes in THE FORK, never as a
patch from this repository into the library: an option whose default is
upstream's behaviour, a test in the fork's own `test/` (tap), a line in its
`docs/`, a commit pushed to `rcbj/node-ldapjs`, and the submodule pin bumped
here in the same change that starts using it. The service asks whether an
option took rather than assuming the submodule is current, because an older
checkout ignores an option it does not know.

`ldap_server.js` is built on `ldapjs` 3.0.7, which resolves to `./node-ldapjs` —
a git submodule pinned to [`rcbj/node-ldapjs`](https://github.com/rcbj/node-ldapjs)
(`"ldapjs": "file:node-ldapjs"` in package.json). Four things follow, and three of
them have already cost something:

* **This repository is itself a submodule of the parent project, so this one is
  NESTED.** `git submodule update --init sts` over there stops one level short of
  it; `--recursive` is required, and the parent's launchers and CI workflows pass
  it. An uninitialised submodule is an EMPTY DIRECTORY, so the COPY succeeds, npm
  installs a package with no `main`, and the failure arrives at runtime as
  `Cannot find module 'ldapjs'` — which names a package.
* **It has to sit inside this package root.** npm installs a `file:` dependency as
  a symlink and node resolves that package's own requires by walking up from where
  the REAL directory lives, so a copy one level up never reaches `node_modules`
  here. The failure is `Cannot find module 'abstract-logging'` from inside ldapjs.
* **`npm install` brings its devDependencies.** ldapjs's are tap and eslint —
  about 200 packages and a dozen advisories that have nothing to do with this
  service. `.npmrc` carries `omit=dev` and the Dockerfile passes `--omit=dev` as
  well; the duplication is deliberate.


## Signing keys, and any document that publishes one

**In development mode — the default — the signing keys are regenerated on every
start; in product mode they are generated once and kept in the persistence store,
sealed under a key-encryption key this service never generates.** A service that
cannot read its own signing key does not start. `common/CLAUDE.md` argues both
(`keystore.js`, `secrets.js`).

**The cross-cutting rule: every document that carries or describes a key is
served `Cache-Control: no-store`.** If you add one, it needs that header too —
`tests/vendored/sts_metadata_anonymous.js` asks it of every metadata document
and fails until the row is there.

## Versioning: M.N.O, fixed when an artifact is BUILT

`VERSION` at the repo root holds M.N; the build number is the UTC build instant,
stamped into `version.json` by the `Dockerfile` so a restarted container reports
the same build. **There is one source**, `common/version.js` (a port of the
parent project's `client/version.js`), and every surface that draws a version
reads it — `tests/version.js` asserts the source each reads, not the string it
renders. **A version may never be the thing that stops this service starting.**
`common/CLAUDE.md` argues it; `xacml-pep/CLAUDE.md` carries the remote PEP's
copy.

## Tests

**The protocol suite is WRITTEN in the parent project and a COPY of it RUNS here.**
Those are two claims and keeping them apart is the whole of this section.

```bash
./docker-npm-test.sh                    # the in-process half, in the tests image (#50)
./run-tests.sh                          # EVERY job, every mode, in containers; what CI runs
./run-tests.sh --target=aws:testidp     # the protocol half against an AWS environment
./run-tests.sh --target=aws-ephemeral   # apply `ci`, run the suite against it from here, destroy it
./run-coverage.sh                       # coverage, collected by a run of its own
```

**`./run-tests.sh` IS THE ONE LAUNCHER FOR THE WHOLE SUITE, WHEREVER THE SERVICE
IS (2026-09-21).** It was `./docker-run-tests.sh`; `deploy/aws/run-suite.sh`
and the apply-test-destroy of `aws-cluster.yml` were launchers of their own and
are its AWS targets' machinery now. Its header argues the targets. **The local
modes are `memory`, `single-node` and `cluster`, and a bare run runs all
three** — the baseline, a single-node production deployment (product mode,
postgres, request workers) and two such nodes behind a balancer, kept apart
because single-node and multi-node differ in too much to read one failure;
`tests/tools/modes.sh` argues it and what replaced what. CI runs
`--modes=memory,single-node` and `--modes=cluster` as two jobs. Every local
mode runs every job, both halves; an AWS target runs the protocol half only,
because the in-process files cannot be pointed at a URL.

**`npm test` refuses on a checkout since #50** (the TypeScript is compiled
only inside an image), so `./docker-npm-test.sh` builds the tests image and
runs it there. **`./local-run-tests.sh` was removed on 2026-09-16**: it ran
its jobs on the host, which #50 made impossible (`--modes=` narrows the local
run; `tests/CLAUDE.md` has the options).

Where a new test goes, asked in this order:

1. **Is it about this service's own `/admin` or `/admin-api`?** Then `tests/vendored/`, `local: true` — an ownership argument, not a capability one.
2. **Can it be asserted over HTTP against a running service?** Then **`tests/vendored/`, `local: true` — written HERE since 2026-09-21** (rcbj's decision; it was `../id-proto-debugger/tests/`). A protocol job is the only kind an AWS target and the `product` mode can run, so a feature covered only in process is uncovered there.
3. **Otherwise here**: it chooses how the process starts, needs a second container on the service's network, or needs a socket no stack publishes.

**Never edit a vendored copy** — the next
`node tests/tools/vendor-check.js --sync` overwrites it and the
fix never reaches the parent. The `local: true` jobs are the inversion, edited
here only. `tests/vendored/MANIFEST.js` says which is which.

`tests/CLAUDE.md` carries the job table, the launchers, the coverage run, the
rules that are not optional there, and the three kinds of test that belong here.
**What each surface still has NO test for is recorded in that surface's own
file.**

## Things this service deliberately does not do

Worth knowing before "fixing" one of them. **This is an INDEX** — each row names
the thing in one line and points at the file that argues it. A row that grows a
paragraph here is the drift this file exists to prevent; the paragraph goes in
the file the row names.

| It does not | Where the argument is |
|---|---|
| Enforce anything by default, **in development mode** — `oauth2.rfc9700` and `oauth2.oauth21` (which turns it on) are the modes, off unless set. **Product mode implies RFC 9700 mode since 2026-09-17**, which is what lets it allow public clients | `oauth-oidc/CLAUDE.md`, `common/mode.js` |
| Federate with anybody it was not CONFIGURED to federate with — the one place it refuses by default, and not a mode | `federation/CLAUDE.md` |
| Poll a partner about a person while the session lasts — ~~consume a federated sign-out~~ **reversed 2026-09-23 (#167)**: a partner's sign-out ends the session it started, and its `SessionNotOnOrAfter` bounds it; ~~decrypt an assertion a federation partner encrypted~~ **reversed 2026-09-23 (#168)**: each relationship holds and publishes an encryption key, and product refuses plaintext unless `fedAllowUnencrypted` | `federation/CLAUDE.md` |
| Dial a URL a CALLER supplied to fetch something FROM (`wreqptr`) — the URLs it does dial are addresses somebody asked to be SENT something at. **The one exception is the embedded debugger's api (2026-09-13)**, a separate child process that dials what a console administrator names, allow-listed to this service's own addresses in product mode. **The second is the RFC 9728 import on `/admin/applications/new` (2026-09-13)**, an Admin Write act under the federation outbound policy that refuses internal addresses in product mode. **The third is an RFC 9101 `request_uri` (2026-09-13)** — fetched only when the client REGISTERED that exact address, so a request cannot choose it. **The fourth is a STATUS LIST (2026-09-17)** — an address inside a credential, which is a caller's kind of URL; what makes it the administrator's is where it sits, under a signature that verified against a certificate in `oid4vp.trustedIssuerCertificates`, and it is never fetched for a credential this realm signed (whose list is in its own store). **The fifth is a SAML MDQ lookup (2026-09-17)** — the operator's `saml2.mdqBaseUrl`, with only a request's entityID as its path, never awaited. **The sixth is SPIFFE's `http_challenge` (2026-09-21, #40)** — a host name the attesting agent names, fetched only after it matched the realm's `spiffe.httpChallengeAllowedDnsPatterns` (empty refuses all), internal addresses refused in product mode, no redirect, 64 bytes. **The seventh is an OpenID Connect `sector_identifier_uri` (2026-09-22, #118)** — fetched once, when a client REGISTERS it, through `federation_http.fetchPublished()`, never while issuing. **The eighth is a client's registered `jwks_uri` (2026-09-22, #120)** — which this row named as a refusal until then: fetched when a key is needed, through the same `fetchPublished()`, cached by `oauth-oidc/client_jwks.js`, and never beside an inline `jwks`. **The ninth is the Pwned Passwords range API (2026-09-22, #62 P6)** — the operator's `risk.breachApiUrl` with a five-character SHA-1 prefix computed here as its path, product mode only, through `fetchPublished()`; off in every suite stack. **The tenth is the FIDO MDS3 BLOB (2026-09-23, #105)** — the operator's `risk.mdsUrl`, which no request can name, downloaded by the `risk.mds-refresh` scheduler job through `fetchPublished()` with a cap of its own, and imported only after #62's full verification. **The eleventh is a container image's REGISTRY (2026-09-23, #170)** — named by the image a workload runs, so the caller's kind; the docker attestor fetches the image's cosign signature from it only when `spiffe.dockerSigstoreAllowedRegistries` names it (and the token realm, and any blob redirect), https only, every blob checked against its digest. **The twelfth is a SIOPv2 `did:web` subject (2026-09-23, #129)** — the presenter's kind of URL, fetched only after it is found ENROLLED on a person's entry (by them, proving the key, or by an administrator), through `fetchPublished()`; an unenrolled one is refused unfetched. **The thirteenth is an OpenID Federation Trust Chain (2026-09-23, #132)** — an entity's configuration and each superior its `authority_hints` name, the caller's kind of URL, walked only TOWARDS a Trust Anchor the realm configured, bounded by `oidfed.maxAuthorityHints`, `maxChainDepth` and `maxFetchesPerResolution` with loops refused, through `fetchPublished()`; started by an administrator's act and never by the unauthenticated resolve endpoint. **The fourteenth is the Entity Collection crawl (2026-09-24, #136)** — going DOWN the realm's own subtree: a list is fetched only from an entity whose chain to the realm already validated, at the endpoint its resolved metadata names, and each entity on it is only resolved towards the realm; bounded by `oidfed.collectionMaxEntities` and `collectionMaxFetches`, through `fetchPublished()`, started by the `oidfed.collection-crawl` job or an administrator's Crawl now and never by the anonymous collection endpoint. **The fifteenth is a FOREIGN SSF TRANSMITTER (2026-09-26, #153)** — an administrator registers its issuer; the configuration document is fetched from that issuer's well-known address and must name it, and every endpoint dialled after (stream management, status, subjects, verification, poll, the jwks_uri) is one that document named, through `fetchPublished()`; a request can name none of them | `oidfed/CLAUDE.md`, `oid4vc/CLAUDE.md`, `federation/CLAUDE.md`, `ssf/CLAUDE.md`, `xacml/CLAUDE.md`, `oauth-oidc/CLAUDE.md`, `debugger/CLAUDE.md`, `admin-ui/CLAUDE.md`, `saml/CLAUDE.md`, `spiffe/CLAUDE.md`, `risk/CLAUDE.md` |
| ~~Ask anybody's permission before it issues something~~ — **reversed 2026-09-01**: `/oauth2/consent`, with `oauth2.consentRequired` ON by default | `common/CLAUDE.md`, `oauth-oidc/CLAUDE.md` |
| Let a page on another origin read an answer (`Access-Control-Allow-Origin: *` until 2026-09-13) — unless the origin is this service's own or an application lists it in `appCorsOrigin`, per client where the request names one; in both modes, on every path | `common/CLAUDE.md` (`cors.js`) |
| Check an end user's password, **in development mode** — product verifies every presented password; a Kerberos ticket, a TOTP code and a recovery code are verified in BOTH modes | `authn/CLAUDE.md`, `kerberos/CLAUDE.md`, `common/CLAUDE.md` |
| Verify a client's credential, **in development mode outside RFC 9700, OAuth 2.1 and FAPI mode** — those modes verify whatever method a client declared, and product mode implies RFC 9700 mode, refuses an unknown `client_id` and allows a declared public client. A caller at `/oauth2/introspect` authenticates for an RFC 9701 JWT in every mode and for JSON in product; one at `/oauth2/revoke` authenticates in product, and in development only when it presents a credential (#102, `mode.opensRevocation()`) | `oauth-oidc/CLAUDE.md` |
| Refuse an LDAP bind, **in development mode**, except the reserved password `invalid` and a disabled account | `ldap/CLAUDE.md` |
| Authorize an LDAP write or read, **in development mode** — product authorizes both per bound identity (reads since 2026-09-23, #106), and only a person binds | `ldap/CLAUDE.md` |
| Check a Kerberos password, **in development mode** — though it cannot not check the KEY | `kerberos/CLAUDE.md` |
| Verify an access token at the three OpenID4VCI endpoints, **in development mode** — product refuses one it cannot verify, and a revoked one (2026-09-18). Every other door that takes a token verifies it in both modes: UserInfo, `/admin-api`, SCIM, Shared Signals, the step-up resource, introspection and the RFC 7523 / 7522 client authentication and grants. **RFC 8693 token exchange verifies its `subject_token` and `actor_token` in product only (2026-09-21)** — until then it exchanged an unverified token in both modes, and development still does (`mode.exchangesUnverifiedTokens()`) | `oauth-oidc/CLAUDE.md`, `oid4vc/CLAUDE.md` |
| Accept an RFC 7523 assertion from an issuer nobody DECLARED — a refusal ON by default; a PERSON as issuer may assert only about themselves | `oauth-oidc/CLAUDE.md`, `common/CLAUDE.md` |
| Accept an RFC 7522 assertion from an `<Issuer>` nobody DECLARED (a separate declaration), or on a certificate that merely chains to the realm's CA | `oauth-oidc/CLAUDE.md`, `common/CLAUDE.md` |
| ~~Revoke a certificate it issued~~ — **reversed 2026-09-11**: a CRL and OCSP per CA, and consulted for presented certificates since 2026-09-12 | `common/CLAUDE.md`, `admin-ui/CLAUDE.md`, `docs/pki.md` |
| Keep a certificate authority across a restart, **in development mode** | `common/CLAUDE.md` |
| Enforce `value`/`values` in an OIDC Core 5.5 claims request, or treat `essential` as an instruction | `oauth-oidc/CLAUDE.md` |
| ~~Require DPoP — nonce mode makes proofs fresher, not mandatory~~ — **reversed 2026-09-15 (#34)**: five settings, all off by default because neither OAuth 2.1 nor RFC 9700 asks for any of them (rule 3ao) | `oauth-oidc/CLAUDE.md` |
| ~~Turn a verified client certificate into a login~~ — **reversed 2026-09-05**, with revocation consulted first since 2026-09-12 | `tls/CLAUDE.md` |
| Verify anything in an issued credential's values, which are invented | `oid4vc/CLAUDE.md` |
| ~~Turn a verified presentation into a sign-on~~ — **reversed 2026-09-17 (#38)**: `/authn/wallet` signs in the entry a holder-bound SD-JWT VC this realm issued was issued for; any other presentation still verifies and signs nobody in | `oid4vc/CLAUDE.md`, `authn/CLAUDE.md` |
| ~~Publish a status for a credential it issued~~ — **reversed 2026-09-17**: a Token Status List and two Bitstring Status Lists per realm, a reference in every credential, and the Verifier consults them — this realm's from its own store, a trusted foreign issuer's by fetching the list | `oid4vc/CLAUDE.md` |
| ~~Deactivate anybody on SCIM `active: false`~~ — **reversed 2026-09-17**: it is `pwdAccountLockedTime` on the entry, the same DISABLED state an administrator writes from `/admin/users`, and every door refuses the person while it is set | `scim/CLAUDE.md`, `common/CLAUDE.md` (3at), `authn/CLAUDE.md` |
| ~~Attest a workload or a node~~ — **reversed 2026-09-21 (#40)**: all nine of SPIRE's node attestors verify or refuse, and the Workload API's Unix socket attests its caller (`unix`, `docker`, `k8s`) through a native module built into the image. A caller over TCP is still not attested, so product serves TCP only where `spiffe.workloadTcpSourceAuthenticated` declares the network authenticates source addresses, and refuses an entry selecting nothing but the transport (#166) | `spiffe/CLAUDE.md` |
| Revoke a SPIFFE credential — the directory records who may still be ISSUED one, which is a different claim | `spiffe/CLAUDE.md`, `ldap/CLAUDE.md` |
| Let a group grant anything BY BEING A GROUP — what a group grants is what a role or a roster names it for: the console rosters, REMOTE_PEPS and XACML_USER, and a configured role's group members; the groups claim grants nothing | `admin-ui/CLAUDE.md`, `common/CLAUDE.md` |
| Let an authenticator app be a FIRST factor | `common/CLAUDE.md` |
| ~~Issue a set of recovery codes on request~~ — **reversed 2026-09-11**: a person generates a set, is shown it once, and it is stored HASHED | `common/CLAUDE.md`, `portal/CLAUDE.md` |
| Offer a self-service reset of a second factor | `admin-ui/CLAUDE.md` |
| Require a compliant registered device, **by default in either mode** — `devices.requireCompliantDevice` switches the issuance policy's rule on per realm (#164 decision 3); a COMPROMISED device is refused by default | `xacml/CLAUDE.md`, `common/CLAUDE.md` |
| ~~Decide who may delegate to whom IN THE ACT, in two of the three families that can~~ — **reversed 2026-09-23 (#108)**: WS-Trust `OnBehalfOf` / `ActAs` and RFC 8693 are decided by `delegation_policy.ts`, Kerberos's model on application entries, enforced in product and recorded in development; `may_act` read in every mode | `common/CLAUDE.md` (3az), `kerberos/CLAUDE.md`, `oauth-oidc/CLAUDE.md`, `ws-trust/CLAUDE.md` |
| ~~Give every trust realm a certificate authority of its own~~ — **reversed 2026-09-11**: one Root, an Intermediate per realm, and the boundary moved down a tier | `common/CLAUDE.md`, `docs/pki.md` |
| ~~Give a trust realm its own Kerberos KDC or TLS listeners~~ — **reversed 2026-09-15 (#33)**: a KDC, a Kerberos realm and keys per trust realm, routed by the realm name on the shared port 88. The TLS listeners left this row on 2026-09-16 by being DELETED, and the directory and SPIFFE came off it earlier — so nothing is left of what it used to say | `common/CLAUDE.md`, `ldap/CLAUDE.md`, `spiffe/CLAUDE.md`, `kerberos/CLAUDE.md`, `tls/CLAUDE.md` |
| ~~Give a trust realm its own administrator~~ — **reversed 2026-09-14 (#32)**: a realm's own roster, confined to the realm; the default realm's stays the service roster | `admin-ui/CLAUDE.md`, `mgmt-api/CLAUDE.md`, `ldap/CLAUDE.md` |
| ~~Persist anything it MINTS~~ — **reversed 2026-09-06, in product mode on postgres only** | `persistence/CLAUDE.md`, `admin-ui/CLAUDE.md` |
| Deliver a response to an address nobody registered, **in product mode** — an address development merely observed is marked and refused until confirmed | `common/applications.js`, `saml/CLAUDE.md`, `common/oidc_rp.ts` |
| Start with demonstration data, invent a claim value, or open a test control to anybody, **in product mode** | `common/mode.js`, `common/CLAUDE.md` |
| Dial its database in the clear — and it does not authenticate that server either | `persistence/CLAUDE.md` |
| Send mail to an address a request supplies, through a relay a caller names, or in the clear (#63) — every recipient is a directory entry, the only address dialled is the operator's configured relay or provider endpoint, a mailed link is built on `global.publicBaseUrl` and never on the request, and SMTP is STARTTLS-required or implicit TLS with the relay verified in both modes | `common/CLAUDE.md` (`mail.ts`) |
| ~~Coordinate several processes through that store~~ — **reversed 2026-09-06**: the change log is the contract; it shares state and not sockets | `persistence/CLAUDE.md`, `common/CLAUDE.md` |
| Recall anything it has already ISSUED — it DISOWNS them, which is a different claim | `logout/CLAUDE.md`, `common/CLAUDE.md` |
| ~~Perform back-channel logout. Front-channel IS implemented~~ — **reversed 2026-09-17 (#36)**: a signed (and, where registered, encrypted) Logout Token POSTed to every relying party on a session any sign-out ends, an EXPIRY ends or a DISABLE ends — a persisted row per delivery, sent once for the cluster, retried by any node across restarts, dead-lettered and retried by hand. Front-channel still cannot follow an expiry: it needs the browser | `oauth-oidc/CLAUDE.md` (3aq), `logout/CLAUDE.md`, `authn/CLAUDE.md`, `federation/CLAUDE.md` |
| ~~Fake WS-Federation's `wauth`~~ — **reversed 2026-09-17 (#36)**, as a step-up rather than a fake: an unmet demand sends the person to sign in again with what it asked for — a second factor, or a SECURITY KEY in either role — and is refused only if that fails | `ws-federation/CLAUDE.md`, `authn/CLAUDE.md` |
| Dereference WS-Federation's `wreqptr` — a URL in a query parameter to fetch the request from is a server-side request forgery | `ws-federation/CLAUDE.md` |
| ~~Verify a SAML AuthnRequest's signature, or consume SP metadata — both recorded, neither checked~~ — **reversed 2026-09-17 (#37)**: a present signature is verified against the SP's registered certificate in every mode, an unsigned one refused where `saml2.requireSignedAuthnRequests` says, and consumed metadata registers the SP's endpoints and keys | `saml/CLAUDE.md`, `saml/request_signature.ts`, `saml/sp_metadata.ts` |
| Encrypt an assertion it was asked to encrypt but holds no certificate for — **product refuses** (Responder, `STS-SAML-0011`); development sends it in CLEAR and says so; an SP whose metadata publishes an encryption key is encrypted to in both | `saml/CLAUDE.md` |
| Dial a service provider's metadata URL WHILE ISSUING | `saml/CLAUDE.md` |

## The parent project's paths into this repository

**The `sts/` COPY set in the parent's `tests/Dockerfile` is the transitive
closure of what `krb5_kdc.js`, `krb5_service.js` and `spnego.js` require, and it
moves on THIS repository's schedule.** Add a require reachable from any of them
and the commit that bumps the `sts/` pin must add the COPY line too, or four
in-process Kerberos jobs die at load with `Cannot find module`, which names a
file nobody edited. What is owed now, and why `mockStsModule()`'s callers pass
bare filenames: `kerberos/CLAUDE.md`. The walk itself:
`docs/parent-project-migration.md`.
