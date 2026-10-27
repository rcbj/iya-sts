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
| **2026-10-13** — the eighteen URLs this service dials that a caller's kind of URL could name | `federation/CLAUDE.md` |
| **2026-10-13** — node-ldapjs as a nested submodule changed only in the fork | `ldap/CLAUDE.md` |
| **2026-10-13** — `./run-tests.sh` as the one launcher, and what it replaced | `tests/CLAUDE.md` |
| **2026-10-13** — the console's and `/oauth2/check_session`'s no-submit-button reasoning | `admin-ui/CLAUDE.md`, `oauth-oidc/CLAUDE.md` |
| **2026-10-13** — every other paragraph-sized table cell (the directory table, the turnstiles, the require order, the rule index, the scripted pages): DELETED as summaries of the file each names | — |

## Where things are

The 2026-08-23 reorganisation moved every module out of the package root. Each
directory's `CLAUDE.md` is the documentation of what is in it.

| Directory | What is in it |
|---|---|
| `common/` | Everything more than one family reads: settings, the express app, `crypto.js` (the one place this service signs, verifies, encrypts and decrypts), realms, the registers, `pki.js`, `mode.js`, the error codes, mail, cells, the hosted applications, the static surfaces' `web_*.ts`. `common/CLAUDE.md`. |
| `common/crypto_impl/` | Byte-identical copies of the parent project's files. **Do not edit them here** (except `pqc.js`, `pqc_x509.js`, `xmldsig.js`). `common/crypto_impl/CLAUDE.md`. |
| `home/` | The front door, `GET /`, and `/home-api`. `home/CLAUDE.md`. |
| `logout/` | The protocol-independent sign-out at `/logout`, and the one model of a live session. `logout/CLAUDE.md`. |
| `launch/` | `/launch/{app}`, the one identity-provider-initiated sign-in link per application (#426). `launch/CLAUDE.md`. |
| `portal/` | The user portal, a static application over `/account-api`. `portal/CLAUDE.md`. |
| `account-api/` | `/account-api`, the portal's only door. `account-api/CLAUDE.md`. |
| `report/` | The reports application at `/report` and its API at `/report-api` (#956). `report/CLAUDE.md`. |
| `oauth-oidc/` | The authorization server and OpenID provider. `oauth-oidc/CLAUDE.md`. |
| `authn/` | The sign-in service, which **owns the SESSION**, and its static screens over `/authn-api`. `authn/CLAUDE.md`. |
| `saml/` | SAML 2.0 and SAML 1.1, each a separate identity provider. `saml/CLAUDE.md`. |
| `ws-trust/` | WS-Trust 1.0–1.4. `ws-trust/CLAUDE.md`. |
| `ws-federation/` | WS-Federation 1.2's passive requestor profile. `ws-federation/CLAUDE.md`. |
| `pki/` | The certificate authority's PUBLIC surface (CRL, OCSP, chains) and `/crypto/metadata`; no gate. No `CLAUDE.md`: each file's header is its documentation. |
| `federation/` | Bilateral federation relationships, in either direction. `federation/CLAUDE.md`. |
| `oidfed/` | OpenID Federation 1.1. `oidfed/CLAUDE.md`. |
| `kerberos/` | The KDC, the acceptor, SPNEGO, and eight codec modules **VENDORED and not editable here**. `kerberos/CLAUDE.md`. |
| `ldap/` | The embedded directory, the store for people, groups and applications. `ldap/CLAUDE.md`. |
| `cluster/` | Several containers against one postgres store, and the scheduler every periodic job runs on. `cluster/CLAUDE.md`. |
| `persistence/` | The one place this service writes anything down. `persistence/CLAUDE.md`. |
| `scim/` | `/scim/v2`, and the outbound SCIM client. `scim/CLAUDE.md`. |
| `ssf/` | The Shared Signals Framework, CAEP and RISC. `ssf/CLAUDE.md`. |
| `spiffe/` | SPIFFE, a trust domain per realm. `spiffe/CLAUDE.md`. |
| `tls/` | The shared certificate, the client truststore, `GET /tls/sign-in`, and the custom listeners. `tls/CLAUDE.md`. |
| `oid4vc/` | OpenID4VCI, OpenID4VP, DID Core and the wallet sign-in. `oid4vc/CLAUDE.md`. |
| `admin-core/` | What both admin surfaces DO. `admin-core/CLAUDE.md`. |
| `admin-ui/` | The console at `/admin`, a static application over `/admin-api`. `admin-ui/CLAUDE.md`. |
| `mgmt-api/` | `/admin-api`, every console control reachable by a machine. `mgmt-api/CLAUDE.md`. |
| `tests/` | **The only test directory.** `tests/CLAUDE.md`. |
| `xacml/` | XACML 3.0 and ALFA, the embedded PEPs, the PDP. `xacml/CLAUDE.md`. |
| `gnap/` | GNAP (RFC 9635, RFC 9767). `gnap/CLAUDE.md`. |
| `attribute-sources/` | Operators' SQL databases a realm reads attributes from. `attribute-sources/CLAUDE.md`. |
| `risk/` | Risk scoring and its datasets; it decides nothing. `risk/CLAUDE.md`. |
| `acme/`, `est/`, `scep/` | Certificate enrollment in three protocols over one core, `common/cert_enrollment.ts` (rule 3ag). Each directory's `CLAUDE.md`. |
| `xacml-pep/` | **Not part of the mock**: the remote XACML PEP container (a Rust binary). `xacml-pep/CLAUDE.md`. |
| `companion/` | **Not part of the service**: a development-only container for the click-through demonstrations. `companion/CLAUDE.md`. |
| `openbao/` | **Not part of the mock**: the secret-store container's files. `openbao/CLAUDE.md`. |
| `deploy/aws/`, `deploy/gcp/`, `deploy/azure/`, `deploy/multicloud/` | **Not part of the mock**: Terraform for the cluster on each cloud (only AWS has been applied). Each directory's `CLAUDE.md`. |
| `debugger/` | The embedded identity protocol debugger, on a listener of its own. `debugger/embedded/` is build output, never source. `debugger/CLAUDE.md`. |
| `rust/` | The Rust conversion (#444); `rust/DESIGN.md` is the design. Only the remote PEP runs on it; the Node service runs none of it. |
| `postgres/` | The database container's files, never this service's. `postgres/CLAUDE.md`. |
| `docs/` | The GitHub Pages site: how to USE this service. `docs/CLAUDE.md`. |
| `env/` | The appconfig files, each a layer over `defaults.js`. `env/CLAUDE.md`. |
| `types/`, `tsconfig*.json`, `build-typescript.sh` | **The TypeScript conversion (#50)**: `types/` is declarations only. `tsc` checks every `// @ts-check` file and every `.ts` (`tests/typecheck.js`). `build-typescript.sh` runs inside an image build only: it compiles each `x.ts` to `x.js` beside it, bundles each static surface for a browser with esbuild, and with `--strip` removes the sources and every comment from the shipped `.js` (`tests/tools/strip-comments.js`). The decisions are on issue #50. |

At the package root there are exactly two modules: **`server.js`**, the shell
that requires the others and listens, and **`sts_metadata.ts`**, which reads
the router and is therefore required last.

**Read the directory's own `CLAUDE.md` before changing anything in it.** The
reasoning is there, and most of it is the record of something having gone
wrong once. `README.md` is a short landing page and `docs/` the user-facing
documentation; this file and the directory files are the maintainer-facing
half.

## Overview

A mock identity service — and, in `product` mode, a deployable one — that speaks
these protocol families:

- **Kerberos v5**: a KDC on TCP/UDP 88, MS-KKDCP and SPNEGO.
- **WS-Trust** 1.0–1.4.
- **SAML 2.0**: assertions and Web Browser SSO with Single Logout.
- **SAML 1.1**: assertions and the browser profiles.
- **WS-Federation 1.2**: the passive requestor profile.
- **Federation**: either end of a relationship, in five protocols, and its Shared Signals.
- **OpenID Federation 1.1**.
- **OAuth 2.0 / OpenID Connect**: a full authorization server.
- **Device registration**: a register of devices per realm (`docs/devices.md`).
- **RFC 7521/7523 and RFC 7521/7522**: assertions as client credentials and grants.
- **WebAuthn Level 3, TOTP, recovery codes**, and (off by default) emailed codes and links.
- **OpenID4VCI 1.0, OpenID4VP 1.0**, W3C DID Core, and a wallet sign-in.
- **LDAP v3**: an embedded directory on 389 and LDAPS 636.
- **SCIM 2.0**: provisioning into that directory.
- **TLS / mutual TLS**, and certificate sign-in.
- **Shared Signals** (SSF 1.0, CAEP, RISC): a transmitter and a receiver.
- **A certificate authority**: one Root, an Intermediate per realm, CRLs and OCSP.
- **SPIFFE**: the bundle endpoint, the Workload API and the SPIRE Server API.
- **XACML 3.0** and **GNAP** (RFC 9635).
- **Mail, sending only**.

It exists to exercise *clients*: in development mode it checks no password,
validates no access token and attests no Workload API caller over TCP. The
surfaces below are the exceptions, each argued where it lives.

| Surface | What it requires | Argued in |
|---|---|---|
| `/scim/v2` | a credential in one of RFC 7644's six schemes | `scim/CLAUDE.md` |
| the SPIRE Server API | an X509-SVID over mutual TLS | `spiffe/CLAUDE.md` |
| `/admin` | the console's DPoP-bound `/admin-api` token and a console role | `admin-ui/CLAUDE.md`, `mgmt-api/CLAUDE.md` |
| `/federation/acs/{id}` | a signature from the relationship's certificate; cannot be made permissive | `federation/CLAUDE.md` |
| `/authn/spnego` | a Kerberos ticket verified against a real key | `kerberos/CLAUDE.md` |
| the SPIFFE Broker API | an X509-SVID naming a configured broker | `spiffe/CLAUDE.md` |
| `/xacml/pep/*`, `POST /xacml/pip` | a client certificate holding `REMOTE_PEPS` | `xacml/CLAUDE.md` |
| `GET /xacml`, `POST /xacml/pdp`, `GET /xacml/policies` | a client certificate holding `XACML_USER` | `xacml/CLAUDE.md` |
| `/account-api` | this realm's DPoP-bound `account:manage` token; the person is always its subject | `account-api/CLAUDE.md` |
| `/report-api` | this realm's `report:use` or `report:admin` token (DPoP-bound from `sts-report`), its subject holding REPORT_USE or REPORT_ADMIN now, and the access-control policy per definition and job (#1030) | `report/CLAUDE.md` |
| `/admin-api` | an access token audienced to it, with the scope the operation needs | `mgmt-api/CLAUDE.md` |
| `/oauth2/introspect` | client authentication | `oauth-oidc/CLAUDE.md` (3ai) |
| the debugger listener | a token only console administrators are issued; cannot be turned off | `debugger/CLAUDE.md` |

**The first three are turnstiles, and none of them can be turned off**; what
`global.mode` changes is whether what they ask for is CHECKED (`common/CLAUDE.md`,
`mode.js`). **The Workload API is the opposite case**: its specification says
it MUST NOT authenticate, and what it lacks is attestation (`spiffe/CLAUDE.md`).

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

## `docker-compose.yml` carries no comments (2026-10-07)

**rcbj removed all of them: 994 of the file's 1234 lines were comments, and the
file was unreadable.** Keep it that way. Only the two SPDX lines stay. What a
user needs is in `docs/docker-compose.md`; the reasoning about a service is in
its directory's file (`postgres/`, `openbao/`, `xacml-pep/`, `spiffe/`,
`tests/tools/compose.sh` for the launchers). A change to the file that needs
explaining goes into one of those, not into a comment. These rules have no other
home:

* **`version: '2.4'` stays.** It matches the parent project's files and keeps
  docker-compose v1 parsing `healthcheck` and `depends_on: condition:`. The
  "obsolete" warning from v2 is the whole cost.
* **A value is `${VAR:-default}` unless an EMPTY value would be wrong; then it
  is BARE** (`- STS_LOG_LEVEL`, `- STS_KEYS_SOURCE`, `- ADMIN_API_*`), which
  passes it only when the host has it. `STS_LOG_LEVEL=""` makes bunyan throw
  `unknown level name` before anything listens. A variable that is in neither
  form never reaches the container, whatever a launcher exports: that is how
  the first dispatch run ran with an ephemeral key-encryption key.
* **A new substitution a launcher sets needs a row in that launcher's
  `COMPOSE_ENV`**, because `sudo` empties the environment
  (`tests/tools/compose.sh`). Without the row the default is used and nothing
  says so.
* **`container_name`, image tags and the subnet are machine-wide**, which is
  why each is a variable (`STS_IMAGE`, `*_CONTAINER_NAME`,
  `STS_NETWORK_SUBNET`). `tests/stack_network.js` holds the subnet default
  outside every launcher's range.
* **The `sts` healthcheck picks its scheme** from `STS_HTTPS`, or from
  `STS_OAUTH2_RFC9700` / `STS_OAUTH2_OAUTH21` when that is unset, and does not
  verify the certificate. A probe speaking the wrong scheme marks a working
  container `unhealthy`. It uses `node -e` rather than curl so that it needs
  only the runtime, and it fails on a non-200, not just on a closed port.
* **The `sts` build context is the repository root with the default
  Dockerfile** (`COPY . ./`, `.dockerignore` deciding what goes in).
  **`image:` defaults to the PUBLISHED name, `iyasec/iya-sts`** (and
  `iyasec/iya-sts-xacml-pep` for the PEP), since 2026-10-07, so a bare
  `docker compose up` on a machine without the image PULLS it from Docker Hub
  and builds only when the pull fails; `--build` builds from the checkout. A
  local build therefore carries the registry's name, and a later pull replaces
  it without a word — `docs/docker-compose.md` tells a user to set
  `STS_IMAGE` to a name no registry has. Until then it was `rcbj/sts`, the
  parent project's name, which no registry serves.
* **`tests/delivered_secrets.js`, `tests/postgres_schema.js` and
  `tests/stack_network.js` read this file's values**, never its comments.

## Architecture, and the rules that hold it together

`server.js` is a shell: it requires the modules and listens. What each directory
holds is the table above; what each module is for is that directory's
`CLAUDE.md`.

1. **A composition root registers every endpoint, in one order.** Since #50's
   R1 (2026-09-16, the owner's decision on #50) a module converted to
   TypeScript registers NOTHING when it is required: it exports
   `registerRoutes(app)`, and `common/protocol_stack.ts` (class
   `ProtocolStack`) calls each one against the shared app from `app.js`, at
   the point where requiring that module used to register the routes. **The
   modules still written in JavaScript still register when they are
   required** — `krb5_kdc`, `krb5_service` and `spnego` (in the parent
   project's test-image COPY closure; what "locked" means is in
   `kerberos/CLAUDE.md`), `tls/tls_server.js` and `ldap/ldap_server.js` — and
   `protocol_stack.ts` requires them at their old places, so the two kinds
   interleave exactly as they did (`common/CLAUDE.md`, `protocol_stack.ts`).
   `debugger/debugger_server.ts` registers on an express app of its OWN and is
   outside this. So **the route order is the order of the `register()` calls
   and of the JavaScript requires in `protocol_stack.ts`**, and the middleware
   still has to live in `app.js`, because express applies middleware only to
   routes added after it.

   **The consequence for anything that loads a module by itself** — a test, a
   script, another module: requiring a converted route module gets you its
   exports and none of its routes. Call its `registerRoutes(app)`, or require
   `common/protocol_stack` for the whole stack. And "a require from here would
   drag X's routes to the front of the router" is now true only where X is one
   of the JavaScript modules above; for a converted X a require moves no
   route, though it can still close a cycle or run X's load-time effects (slot
   fills, stores) early — see *The require order and the route order*, below.

2. **`vc_configs.ts` and `vc_offers.ts` exist to break require cycles, not to
   group code** (`oid4vc/CLAUDE.md`). A cycle in node does not fail loudly — it
   hands back a half-initialised module whose exports are `undefined`, and the
   symptom arrives later as something that is not a function.

3. **`dpop.js` is a library, not a protocol module.** It registers nothing, so
   its position in the require order does not matter, and it requires only
   `helpers.js` (plus npm leaves) so it cannot join a cycle. Keep it that way.
   Why `presentedAccessToken()` lives there is in `oauth-oidc/CLAUDE.md`.

3e. **The inverted hooks ("slots"), and the test for adding one.** A slot is
   what you reach for when a require would close a cycle or move a route, and
   it costs a reader an indirection every time; each one is justified by a
   specific thing that would otherwise break, and **none is added by
   analogy**. `admin_stats.js`'s and `helpers.js`'s first four
   (`setJwtRecorder`, `setUserObserver`, `setAttributeResolver`,
   `setGroupResolver`, beside `audit.js`'s plain require) are four different
   problems rather than a pattern, argued in `common/CLAUDE.md` 3b–3d-ii. The
   group resolver is the one to check a new proposal against: it was added
   only after showing it failed that test BOTH ways round.

   **THE TEST IS THE RULE; the slots that have passed it are an inventory, and
   each one's argument lives beside the module that offers it.** A new slot is
   validated WHOLE when installed (a filler that installs half of it leaves a
   page able to list and unable to act), and is argued both ways round — the
   require one way closes a cycle, the require the other way moves routes.
   **Since #50's R1 "moves routes" is true only of a require that reaches a
   JavaScript route module** (rule 1); for a converted module the case for a
   slot is a cycle or a load-time effect that would run in the wrong place,
   and it has to be made on those terms.

   | Offered by | Slots | Argued in |
   |---|---|---|
   | `admin-ui/admin.ts` | `setLogoutReader`, `setCryptoReporter`, `setSignalsReporter`, `setCaepReporter`, `setRiscReporter`, `setDirectoryPages`, `setDirectoryReader`, `setDirectoryWriter`, `setGroupReader`, `setGroupWriter`, `setScimReader`, `setSpiffeReader`, `setXacmlPages`, `setRolePreviewer`, `setTruststore` | `admin-ui/CLAUDE.md`, and the filler's own file |
   | `admin-ui/crypto_metadata.ts` | `setProtocolFamilies`, filled by `sts_metadata.ts` | `admin-ui/CLAUDE.md` |
   | `portal/portal.ts` | `setDirectory`, filled by `ldap/ldap_server.js` | `portal/CLAUDE.md` |
   | `authn/authn.ts` | `setSessionObserver`, filled by `ssf/ssf.ts` | `authn/CLAUDE.md`, `ssf/CLAUDE.md` |
   | `common/admin_stats.js` | `setUserObserver` (three kinds of event, still one slot), `setAttributeResolver`, `setGroupResolver`, `setRevocationObserver` (#239, filled by `oauth-oidc/oauth_grant_signals.ts`), `setStatusMarker` (#820, filled by `oauth-oidc/access_token_status.ts`) | `common/CLAUDE.md` |
   | `common/helpers.js` | `setSubjectResolver` (a person's `sub` from their entry's `entryUUID`, and back), filled by `ldap/ldap_server.js` (2026-09-14) | `ldap/CLAUDE.md` |
| `common/passkey_report.ts` | `setDirectory` (the holder scan, a group population, the people count), filled by `ldap/ldap_server.js` (#942) | `common/CLAUDE.md` (3cs) |

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

**Both were OpenID Connect relying parties run by this process** (the portal
since 2026-09-06): seeded confidential clients, a back-channel request to
`/oauth2/token`, a relying-party session dying with the sign-on session it
came from. `common/CLAUDE.md` (`oidc_rp.ts`) still carries that design, the
realm split and the `Location`-header bug, for the embedded debugger, which
is one still.

**`/portal` has been a STATIC application since #568 (2026-10-12)**, on the
console's pattern below: every `/portal/*` path answers one document and
`/portal/portal.js`, which signs in in the browser as the PUBLIC client
`sts-user-portal` (PKCE S256, `resource` the realm's `/account-api`,
`account:manage`), holds a DPoP-bound token in memory, and draws every page
from `/account-api` and sends every form there. rcbj's decisions on #568 —
the console's pattern, reversing #444's D9 for the portal too; `/account-api`;
the pages for nobody drawn the same way; the console-session adoption
dropped. `account-api/CLAUDE.md` and `portal/CLAUDE.md` argue it.

**`/admin` was one too until the cutover of #446 (2026-10-05), and is now a
STATIC application**: every `/admin/*` path answers one document and
`/admin/console.js`, which signs in IN THE BROWSER as the public client
`sts-admin-console` (the code flow with PKCE S256, `resource` the realm's
`/admin-api`), holds a DPoP-bound token in memory only, renews it with the
refresh grant, and draws every page from its `/admin-api` operation and sends
every form there. The console holds no session of its own; its Sign out is
`/logout`. `admin-ui/CLAUDE.md` (`web_runtime.ts`) argues it.

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

**This service is one node process that owns every listener**, and node runs
all of them on one thread. **`common/request_pool.js` takes work off it**:
`worker_threads` Workers that run the whole protocol stack, started before
the listener binds (`workers.requestCount`, and `workers.surfaceCount` for a
pool that runs only `/admin` and `/portal`), each sharing nothing with the
front but the store; **post-quantum signing and scrypt run natively on libuv's
thread pool** (`common/pq_native.js`). `common/CLAUDE.md` argues both.

**The cross-cutting rule is one sentence: a store is shared by coordination, and
anything that is NOT a row in a store — a socket, a timer, a listener, a
certificate a socket presents — is held by one process and reachable from no
other.** Each such thing needs the argument made again rather than an earlier
mechanism copied: the LDAP connection took a mirror and an instruction on the
response (`ldap/CLAUDE.md`), the TLS listener certificate took a reconcile in
the front process (`tls/CLAUDE.md`), and the client-certificate truststore took
a pin (`tls/CLAUDE.md`). **Dispatch without coordination is refused and the
service does not start**, because it answers WRONGLY rather than slowly.

**No STARTED process exits over an unexpected error (#355)**: a new kind of
process installs `common/fault_boundary.ts`'s handlers once it has started,
and a new express app is covered by the guard already —
`common/CLAUDE.md` (`fault_boundary.ts`).

## Anything periodic is a scheduler job

**rcbj's architectural directive, 2026-09-21: anything that has to be done
periodically in the background is a job on the central scheduler** (#49,
`cluster/scheduler.ts`), which runs each job on exactly one node and hands
it to another node when that one goes. The serving front process leads and
keeps the lease, the claims, the fences and the run rows; since #408 a
cluster job's BODY runs on the node's least-loaded ready request worker,
unless the job names an `onFront` reason (`cluster/CLAUDE.md`, *Where a
cluster run's body runs*). **No new module may start a timer of its own** — no
`setInterval`, no `setTimeout` chain, no sweep armed at require or wire time —
for work that repeats.

**Cache and store clean-up is included**: ejecting expired entries is periodic
work, so it is a job. **Two checks stay where they are, because they are
correctness rather than housekeeping**: the expiry check at the read (an
expired entry is never answered, whenever the sweep last ran) and the size cap
at the insert (a bound cannot wait for a timer).

**A job is one of two kinds, and the owner says which.** A *cluster* job (the
default) runs once, on the leader: a rotation, a CRL, a delivery. A
*per-process* job runs in every process that holds the state it cleans,
because that state is reachable from no other process (*One front process*,
above): an in-memory cache's ejection, a process's own change-log pull. It
takes no claim, and is still registered with, reported by and switched
through the scheduler.

What does NOT count: a per-request timeout, a debounce, a retry delay inside
one operation, and the cluster heartbeat with its lease and origin-claim
renewals, which are what the scheduler's own leadership stands on.

`cluster/CLAUDE.md` (*The scheduler*) has the table of jobs;
`tests/no_periodic_timers.js` holds that nothing else repeats, with the
permanent exceptions and why.

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
one. A composite registration is still one row (`common/CLAUDE.md`,
`protocol_stack.ts`, lists them). Every constraint below is a DEPENDENCY, not a
preference; this table says what the constraint is and the named file says why.

| # | Required (then registered, if converted) | Constraint | Argument in |
|---|---|---|---|
| 0 | `common/compiled_tree` | Before everything (#50): refuses a tree whose TypeScript is not compiled, and requires nothing of this service. Called by `server.js` itself rather than listed in `protocol_stack.ts`. | `common/CLAUDE.md` |
| 1 | `common/config_file` | First of all that configures anything; every reader of `CONFIG_FILE` is below it. | `common/CLAUDE.md` |
| 1a | `common/process_memory` | Right after `config_file` (#341), called by `server.js` itself: it may re-execute the process with a heap limit before anything else is loaded. A leaf. | `common/CLAUDE.md` |
| 2 | `common/app` | Before every protocol module and every `register()` call: routes are registered against it, and middleware applies only to routes added after it. Also installs the JWT recorder (rule 3e). | `common/CLAUDE.md` |
| 2a | `common/realms` | No line of its own (loaded by `app` and `helpers`), but above every setting read and every store: requiring it fills `config.js`'s realm slot (rule 3m). | `common/CLAUDE.md` |
| 3–4 | `common/helpers`, `common/config` | `config.js` is below `helpers.js` and requires nothing here. | `common/CLAUDE.md` |
| 4a | `persistence/persistence` | Below `config`, above everything else: fills the override-store slot and subscribes to `realms.onChange()`. Opens nothing here — `persistence.start()` does, before any listener binds. | `persistence/CLAUDE.md` |
| 4b | `common/crypto` | Loaded by `helpers`. A LEAF library that may never require `helpers` back. | `common/CLAUDE.md` |
| 5 | `common/claim_attributes` | Ahead of everything that ISSUES: it fills `setAttributeResolver()`. | `common/CLAUDE.md` |
| 6 | `common/group_claims` | Same reason, for `setGroupResolver()`. | `common/CLAUDE.md` |
| 6a | `home/home` | No constraint; first among the route modules, and so the first `register()`. | `home/CLAUDE.md` |
| 6a-web | `common/public_assets` | No constraint (#570): libraries only, and `/web/*` collides with nothing. | `common/CLAUDE.md` (3cl) |
| 8 | `authn/authn` | Before `oauth2`: it owns the session that module reads. | `authn/CLAUDE.md` |
| 8-api | `authn/authn_api` | Just after `authn` (#571), whose views and acts it reaches through that module's exports; `/authn-api/*` collides with nothing. | `authn/CLAUDE.md` |
| 7 | `ws-trust/wstrust` | After `authn` since 2026-09-05 (it calls `startSession()`); the number predates the move. | `ws-trust/CLAUDE.md` |
| 8-email | `authn/email_factor` (and `common/mail_factor`) | Just after `authn`, whose pending steps it reads through that module's exports (#64). | `authn/CLAUDE.md` |
| 8-dbsc | `authn/device_bound_sessions` | Just after `authn` (#725), which requires it as a library; it reaches `authn` and `logout` lazily, and `/authn/dbsc/*` collides with nothing. | `authn/CLAUDE.md` |
| 8a | `portal/portal` | After `authn`, whose session every portal route reads. | `portal/CLAUDE.md` |
| 8a-mail | `common/mail`, `common/mail_uses`, `portal/portal_mail` | Built before the portal, whose `registerRoutes()` registers `portal_mail`'s pages. Libraries; the directory fills the channel's slot at 21. | `common/CLAUDE.md` |
| 8a-acct | `portal/account_*` (seven), then `account-api/account_api` | Just after the portal (#568): the account API's `register()` gathers every portal page module's operations, so all must be built first. | `account-api/CLAUDE.md` |
| 8b | `oauth-oidc/consent_screen` | After `authn`, before `oauth2`. | `oauth-oidc/CLAUDE.md` |
| 9 | `oauth-oidc/oauth2` | Before `admin-ui/admin` (rule 5). | `oauth-oidc/CLAUDE.md` |
| 9a | `oauth-oidc/access_token_status` | Just after `oauth2` and `grant_management` (#432); requires the status-list codec (11–14) only at request time. | `oauth-oidc/CLAUDE.md` |
| 10 | `ws-federation/wsfed` | After `authn` (rule 4), whose session it signs people in to. | `ws-federation/CLAUDE.md` |
| 10a | `saml/saml2_sso` | After `authn`; it has no sign-in screen of its own. | `saml/CLAUDE.md` |
| 10b | `saml/saml11_sso` | After `authn` and after `saml2_sso` (`slugOf()`). | `saml/CLAUDE.md` |
| 10c | `federation/federation_sp` | After `authn`; it calls `startSession()` directly. | `federation/CLAUDE.md` |
| 10c-ii | `federation/federation_slo` | After `federation_sp` (its context store and key verifier) and `authn`. Requires `logout/logout` LAZILY: a require here would load `ldap_server.js` and drag its routes forward. | `federation/CLAUDE.md` |
| 11–14 | `oid4vc/*` | `vc_offers` before `vc_issuer` (rule 2), and REGISTERED just before `oauth2`'s own routes, because `oauth2` requires it. `vc_issued`, `vc_status_codec`, `vc_data_integrity` and `vc_status` before `vc_issuer`, which allocates a status index as it builds a credential. | `oid4vc/CLAUDE.md` |
| 14-vcapi | `oid4vc/vc_api` (and its libraries) | After `vc_verifier`, whose libraries it reads; requires no route module. | `oid4vc/CLAUDE.md` |
| 14a | `oid4vc/vc_signin` | After `vc_verifier`, whose transactions it reads, and after `authn` (8), whose session it starts; `authn` requires nothing here — `spnego_authn`'s arrangement (#38). | `oid4vc/CLAUDE.md` |
| 14b | `oidfed/federation_keys`, `oidfed/oidfed` | After `oauth2` and `vc_verifier`, whose metadata the Entity Configuration carries (read lazily). | `oidfed/CLAUDE.md` |
| 14c | `kerberos/krb5_home` | Just BEFORE `krb5_kdc` (#98): its `POST /KdcProxy` must run first and call `next()` for a request homed here, so the KDC's handler and the parent's COPY closure stay unchanged; `install()` hands it the KDC just after `krb5_kdc` is required. | `kerberos/CLAUDE.md` |
| 15–16 | `kerberos/krb5_kdc`, `krb5_service` | JavaScript, in the parent's COPY closure (a new require owes the parent a COPY line): the KDC's routes register at this require. Listeners start from `listen()`, not here. | `kerberos/CLAUDE.md` |
| 17 | `kerberos/spnego` | JavaScript, in the parent's COPY closure: registers nothing since #595. After `krb5_service`, in the order `spnego_exchange.js` needs them. | `kerberos/CLAUDE.md` |
| 17a | `kerberos/spnego_authn` | After `spnego` AND after `authn/authn`; it lives in `kerberos/` so that `authn` never requires it, which would load the JavaScript `spnego` early and drag its routes ahead of `oauth2`. | `kerberos/CLAUDE.md`, `authn/CLAUDE.md` |
| 17b | `pki/pki_service` | No constraint: it requires only libraries. Here, ahead of the console, so `/admin/sts-metadata` groups the revocation endpoints with the protocols. | `common/protocol_stack.ts` (17b) |
| 17c | `pki/crypto_metadata_document` | 17b's reason (#42): libraries only, each LAZILY, so it may sit beside the revocation endpoints. | `common/protocol_stack.ts` (17c) |
| 18 | `admin-ui/admin` | After `oauth2` (rule 5), and before the families whose modules would otherwise have to be required from it — which is why it offers slots (rule 3e). | `admin-ui/CLAUDE.md` |
| 18-core | `admin-core/*` | No line of its own. Requires `oauth2`, `saml2`, `saml11` and `federation`, so it may be required at 18 or later and nowhere earlier, or it runs their load-time code out of order. | `admin-core/CLAUDE.md` |
| 18a | `admin-ui/pki_admin` | After `admin-ui/admin`, before `mgmt-api/admin_api`, so the API's require of it is a cache hit and it needs no slot. | `admin-ui/CLAUDE.md` |
| 18b–d | `admin-ui/encryption_admin`, `database_admin`, `secrets_admin` | 18a's placement and 18a's reason. | `admin-ui/CLAUDE.md` |
| 18e | `debugger/debugger_admin` | 18a's placement. Reads the listener's status LAZILY, because `debugger_server` requires `tls/tls_server` (20). | `debugger/CLAUDE.md` |
| 18f | `oauth-oidc/oauth2_monitor_admin` | 18a's placement and reason; `oauth2.ts` (9) cannot require it without closing a cycle through the console. | `oauth-oidc/CLAUDE.md` |
| 18g | `admin-ui/caches_admin` | 18a's placement and 18a's reason (#74). | `admin-ui/CLAUDE.md` |
| 18h | `admin-ui/vc_status_admin` | 18a's placement and 18a's reason, after `oid4vc/vc_status`. | `admin-ui/CLAUDE.md` |
| 18i | `admin-ui/scheduler_admin` | 18a's placement and 18a's reason (#49); the page asks the scheduler when drawn, so a job registered later still appears. | `cluster/CLAUDE.md` |
| 18i-report | `report/report_app`, `report/report_api` | After the scheduler is in hand (the module registers its six jobs at load), and after `oauth2` and `authn` (the API's lazy dependencies). The two paths collide with nothing. | `report/CLAUDE.md` |
| 18j | `risk/risk_store`, `risk_datasets`, `risk_failures`, `risk_upload`, `risk_engine`, then `admin-ui/risk_admin` | 18a's placement and reason (#62): libraries, then the page, after the scheduler. **Nothing requires the libraries earlier** — they are reached lazily. | `risk/CLAUDE.md` |
| 18j-iii | `common/attestation_revocation` | Inside 18j, after `risk/risk_datasets` (#256). A library: registers scheduler jobs, no route; reached lazily. | `common/CLAUDE.md` (3cf) |
| 18j-iv | `common/passkey_report` | After 18j-iii, before `ldap/ldap_server` (21), whose require fills its directory slot and whose key-writing doors note there (#942). A library: a scheduler job, no route. | `common/CLAUDE.md` (3cs) |
| 18j-ii | `admin-ui/geo_map`, then `admin-ui/geolocation_admin` | 18a's placement and reason (#255), after the risk libraries whose assessments it counts. | `admin-ui/CLAUDE.md` |
| 18k | `admin-ui/mode_admin` | 18a's placement and 18a's reason (#181). | `admin-ui/CLAUDE.md` |
| 18k-iii | `admin-ui/listeners_admin` | 18a's placement and reason (#423); `tls/tls_server` (20) and `tls/listeners` are reached lazily. Its paths are in `NEVER_DISPATCHED`. | `tls/CLAUDE.md` |
| 18k-ii | `admin-ui/cells_admin` | 18a's placement and reason (#98); its `registerRoutes()` also registers two inter-cell operations. | `admin-ui/cells_admin.ts` |
| 18l | `admin-ui/mail_admin` | 18a's placement and reason (#63), after the channel (8a-mail). | `admin-ui/CLAUDE.md`, `common/CLAUDE.md` |
| 18m | `oauth-oidc/grant_management_admin` | 18a's placement and reason (#142); the grant register is built with `oauth2` (9), which registers `/oauth2/grants/{id}` just after its own routes. | `oauth-oidc/CLAUDE.md` (3bf) |
| 18n | `oauth-oidc/claims_providers_admin` | 18a's placement and reason (#147); the register is built with `oauth2`'s libraries. | `oauth-oidc/CLAUDE.md` (3bh) |
| 18q | `admin-ui/devices_admin` | 18a's placement and reason (#164, #218), after `oauth2` (9), whose `sessionIsLive()` it asks. | `admin-ui/CLAUDE.md` |
| 18r | `attribute-sources/attribute_sources`, then `attribute_sources_admin` | 18a's placement and reason (#94); `ldap_server` fills its directory slot at 21 into a module-level holder, so that order cannot matter. | `attribute-sources/CLAUDE.md` |
| 18r-ii | `common/secret_destinations` | 18r's placement (#221 P3): a library and no route, before `mgmt-api/admin_api`, which spreads its API's routes. | `common/CLAUDE.md` (3ce) |
| 18s | `cluster/node_snapshots`, then `admin-ui/worker_pools_admin` | 18a's placement and reason (#327, #332); the pools are reached lazily. Its paths are in `NEVER_DISPATCHED`. | `admin-ui/CLAUDE.md` |
| 18t | `admin-ui/node_health_admin` | 18s's placement and 18a's reason (#329). Its paths are in `NEVER_DISPATCHED`. | `admin-ui/CLAUDE.md` |
| 19 | `mgmt-api/admin_api` | After `admin-ui/admin` (rule 7). | `mgmt-api/CLAUDE.md` |
| 19a | `admin-ui/api_explorer` | After `admin-ui/admin` (the shell and gate) and `mgmt-api/admin_api` (the route table its OpenAPI document is built from); a file of its own so `admin.ts` never requires the API. | `mgmt-api/CLAUDE.md`, `admin-ui/CLAUDE.md` |
| 20 | `tls/tls_server` | JavaScript: registers its `/tls*` views at this require. Before `ldap/ldap_server`, which serves its certificate on 636. | `tls/CLAUDE.md` |
| 20a | `admin-ui/crypto_metadata` | After `tls/tls_server`: it reads algorithm tables out of eleven modules and must find each already loaded — two of them (`tls_server`, `krb5_kdc`) are JavaScript, whose require would register their routes wherever it first ran. | `admin-ui/CLAUDE.md` |
| 21 | `ldap/ldap_server` | JavaScript: registers the `/admin/ldap/*` pages at this require. After `admin-ui/admin` and `tls/tls_server` (rule 6). Fills the directory's slots. | `ldap/CLAUDE.md` |
| 22 | `scim/scim`, then `scim/scim_client` | After `ldap/ldap_server`, as a plain require; `scim_client` (#552) listens to the directory filled at 21. | `scim/CLAUDE.md` |
| 23 | `spiffe/spiffe_server` | After `ldap/ldap_server` and `tls/tls_server`; its registry's store is the directory. | `spiffe/CLAUDE.md` |
| 23b | `ssf/ssf` | After `admin-ui/admin`, whose slots it fills; also fills `authn.setSessionObserver()`. Starts nothing. | `ssf/CLAUDE.md`, `authn/CLAUDE.md` |
| 23b-ii | `common/signing_rotation` | After `ssf/ssf`, whose `signingKeyRotated()` it calls (lazily, so the order is for a reader). A library: scheduler jobs, no route. | `common/signing_rotation.ts` (#42) |
| 23b-vi | `oauth-oidc/oauth_grant_signals` | After `ssf/ssf` (23b), which it delivers through lazily, so the order is for a reader. Filling `admin_stats.setRevocationObserver()` is its whole installation (#239). | `oauth-oidc/CLAUDE.md` |
| 23b-vii | `common/cell_sessions` | After `ssf/ssf` and the grant signals, for a reader (#98); `app.js` loads it for its middleware at #2. | `common/cell_sessions.ts` |
| 23b-ii-b | `common/service_account_rotation` | Beside the two rotations above (#221 P4), for a reader: a library, scheduler jobs, no route, everything reached lazily. | `common/CLAUDE.md` (3cd) |
| 23b-iii | `kerberos/krb5_krbtgt_rotation` | After `ldap/ldap_server` (21), whose directory slot the krbtgt key is written through (#169). A library: scheduler jobs, no route. | `kerberos/CLAUDE.md` |
| 23c | `xacml/xacml` | After `admin-ui/admin`, whose slots this family fills; one require, two `register()` calls — `xacml_admin`, then `xacml`. **This REQUIRE arms every issuance site** (a load-time effect): before it, `issuance_gate.js` answers "allowed". | `xacml/CLAUDE.md` |
| 23d | `gnap/gnap` | After `admin-ui/admin` and `ssf/ssf`; one require for the family, and three `register()` calls — `gnap`, `gnap_interact`, `gnap_admin`. | `gnap/CLAUDE.md` |
| 23e–g | `acme/acme`, `est/est`, `scep/scep` | After `admin-ui/admin` (18), whose shell each `_admin.ts` draws with, and after `ldap/ldap_server` (21), whose slot `common/cert_enrollment.ts` reads entries through. Each one require, then two `register()` calls (the family, then its `_admin`). No constraint between the three. | `acme/CLAUDE.md`, `est/CLAUDE.md`, `scep/CLAUDE.md` |
| 23g-ii | `oidfed/oidfed_admin` | After the console (18), whose shell it draws `/admin/oidfed` with; the family itself is 14b. | `oidfed/CLAUDE.md` |
| 23h | `debugger/debugger_server` | A socket owner: builds its OWN express app and registers nothing on this one. After `authn`, `oauth2`, `tls/tls_server` and the console, all of which it reads. | `debugger/CLAUDE.md` |
| 23a-launch | `launch/launch` | After every family it hands the browser to (9, 10, 10a, 10b) and `authn` (8); its one path collides with nothing. Its link builder `common/launch_links.ts` is a library the account API (8a-acct) and the management API (19) require earlier, which moves no route. | `launch/CLAUDE.md` |
| 23a | `logout/logout` | Second to last: it reads nine modules' stores. | `logout/CLAUDE.md` |
| 24 | `sts_metadata` | **Last, for everybody.** It reads the router to list what everything else registered; its `wire` step hands `PROTOCOLS` to the crypto page (20a). | *Adding an endpoint*, below |

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
| 3ah | `oauth21.js`: OAuth 2.1 as a mode implying RFC 9700 mode | `oauth-oidc/CLAUDE.md` |
| 3an | RFC 8705, both halves: `tls_client_auth`'s certificate mappings | `oauth-oidc/CLAUDE.md` |
| 3g | `applications.js` | `common/CLAUDE.md` |
| 3r | `crypto.js`: the one crypto module, and why it is a leaf | `common/CLAUDE.md` |
| 4a | `saml2_sso.ts` after `authn.js`, with no screen | `saml/CLAUDE.md` |
| 4b | `federation_sp.ts` after `authn.js`, with no screen | `federation/CLAUDE.md` |
| 4b | `saml11_sso.ts` after `authn.js` and `saml2_sso.ts`; two separate profiles | `saml/CLAUDE.md` |
| 3l | `delegation.js`, and why it has no funnel | `common/CLAUDE.md` |
| 3az | `delegation_policy.ts` (#108, #186): who may act for whom | `common/CLAUDE.md`, `xacml/CLAUDE.md` |
| 3s | `app_permissions.js`: the configured permission register | `common/CLAUDE.md` |
| 3t | `consent.js`: an override is not a record | `common/CLAUDE.md` |
| 4c | `consent_screen.js` after `authn.js`, before `oauth2.js` | `oauth-oidc/CLAUDE.md` |
| 3u | `roles.js`: who holds a role, what requires one | `common/CLAUDE.md` |
| 3v | `issuance_gate.js`: an empty decider means issue | `common/CLAUDE.md` |
| 3br | `xacml/xacml_request.js` (#306): the one AuthorizationRequest builder | `xacml/CLAUDE.md`, `xacml-pep/CLAUDE.md` |
| 3bt | The scope rules as issuance policy (#305) | `xacml/CLAUDE.md`, `common/CLAUDE.md`, `oauth-oidc/CLAUDE.md` |
| 3bu | `cell_transfer.ts` (#98): where a person's data may go, as policy | `common/CLAUDE.md`, `xacml/CLAUDE.md` |
| 3bs | The per-scope `issue-scope` verdict (#304) | `xacml/CLAUDE.md`, `common/CLAUDE.md` |
| 3bq | `role_permissions.ts` (#302, #303): a scope requested, a role authorizing it | `common/CLAUDE.md`, `mgmt-api/CLAUDE.md`, `xacml/CLAUDE.md` |
| 3w | `pki.js`: the CA hierarchy and path checks | `common/CLAUDE.md` |
| 3aa | `pki_authoring.js`: the Certificate & Key Configuration pane as a model | `common/CLAUDE.md` |
| 3x | `assertion_grant.js`: RFC 7521 and RFC 7523 | `oauth-oidc/CLAUDE.md` |
| 3ab | `person_assertions.js`: a person as an RFC 7523 issuer | `common/CLAUDE.md` |
| 3ac | `password_policy.js`: the password policy and its generator | `common/CLAUDE.md` |
| 3ad | `revocation_status.js`: revocation consulted for a presented certificate | `common/CLAUDE.md` |
| 3ak | `request_object.js`: RFC 9101 (JAR) | `oauth-oidc/CLAUDE.md` |
| 3am | `authorization_details.js`: RFC 9396 rich authorization requests | `oauth-oidc/CLAUDE.md` |
| 3an | `step_up.js`: RFC 9470 step-up authentication | `oauth-oidc/CLAUDE.md` |
| 3al | `par.js`: RFC 9126 pushed authorization requests | `oauth-oidc/CLAUDE.md` |
| 3aj | `software_statement.js`: RFC 7591 section 2.3 | `oauth-oidc/CLAUDE.md` |
| 3ai | `introspection_jwt.js`: RFC 9701 JWT introspection responses | `oauth-oidc/CLAUDE.md` |
| 3ah | `jwt_access_token.js`: RFC 9068 access tokens in every mode | `oauth-oidc/CLAUDE.md` |
| 3z | `saml_assertion_grant.js`: RFC 7522, a second implementation | `oauth-oidc/CLAUDE.md` |
| 3y | `backup_codes.js`: recovery codes, hashed per code | `common/CLAUDE.md` |
| 3z | `inetorgperson.js`: the account page's fixed attribute list | `common/CLAUDE.md` |
| 3ac | `error_codes.js`: how a code is recorded, never sent | `common/CLAUDE.md` |
| 3ae | `used_assertions.js`: an RFC 7523 / 7522 assertion accepted once ever | `common/CLAUDE.md` |
| 3ag | `cert_enrollment.js`: the core ACME, EST and SCEP issue through | `common/CLAUDE.md` |
| 3ar | `vc_issued.ts`: the register of credentials this realm issued | `oid4vc/CLAUDE.md` |
| 3as | `vc_status.ts`, `vc_status_codec.ts`: the credential status lists | `oid4vc/CLAUDE.md` |
| 3at | `vc_data_integrity.ts`: the holder's Data Integrity proof | `oid4vc/CLAUDE.md` |
| 3ax | `app_passwords.ts`, `secondFactorRefusal()` (#101): app passwords | `common/CLAUDE.md`, `authn/CLAUDE.md` |
| 3bb | Native SSO (#130) in `oauth2.ts` and `devices.ts` | `oauth-oidc/CLAUDE.md`, `common/CLAUDE.md`, `ldap/CLAUDE.md` |
| 3bd | OpenID Federation 1.1 (#132, #133), `oidfed/` | `oidfed/CLAUDE.md` |
| 3bf | `grant_management.ts` (#142): Grant Management, and FAPI-CIBA | `oauth-oidc/CLAUDE.md` |
| 3bg | What the OpenID conformance suite found (#176) | `oauth-oidc/CLAUDE.md` |
| 3bn | `vc_api.ts` and its libraries (#194-#199): the W3C VC API | `oid4vc/CLAUDE.md`, `tests/CLAUDE.md` |
| 3bh | `claims_providers.ts` (#147): OpenID Connect Claims Aggregation | `oauth-oidc/CLAUDE.md` |
| 3by | `exchange_assertions.ts` (#114): assertions as RFC 8693 tokens | `oauth-oidc/CLAUDE.md` |
| 3bm | `client_attestation.ts` (#229): attestation-based client authentication | `oauth-oidc/CLAUDE.md` |
| 3bi | OpenID Connect Enterprise Extensions (#148) | `oauth-oidc/CLAUDE.md` |
| 3bj | `pairwise_subjects.ts` (#149): the Ephemeral Subject Identifier | `oauth-oidc/CLAUDE.md` |
| 3bk | `device_authorization.ts` (#150): RFC 8628, and OpenID Connect Key Binding | `oauth-oidc/CLAUDE.md` |
| 3bl | `provider_commands.ts`, `outbound_delivery.ts` (#151): OpenID Provider Commands | `oauth-oidc/CLAUDE.md` |
| 3bo | `devices.ts`, `device_recognition.ts` (#164): the registered device in decisions | `common/CLAUDE.md`, `risk/CLAUDE.md`, `xacml/CLAUDE.md`, `oauth-oidc/CLAUDE.md` |
| 3bp | What the rest of the OpenID conformance suite found (#187) | `oauth-oidc/CLAUDE.md` |
| 3bc | `ciba.ts` and `/oauth2/bc-authorize` (#131): CIBA | `oauth-oidc/CLAUDE.md`, `portal/CLAUDE.md` |
| 3ba | `siop.ts` (#129): SIOPv2 as the relying party | `oid4vc/CLAUDE.md` |
| 3ay | `identity_assurance.ts` (#127): OpenID Connect for Identity Assurance | `common/CLAUDE.md` |
| 3ba | `mail.ts` and its transports, templates and uses (#63): the mail channel | `common/CLAUDE.md` |
| 3bd | `authn_policy.ts`, `admin-core/policy_kinds.ts` (#64): the authentication policy | `common/CLAUDE.md` |
| 3be | `mail_factor.ts`, `authn/email_factor.ts` (#64): emailed codes and links | `common/CLAUDE.md`, `authn/CLAUDE.md` |
| 3ap | `cache_registry.js`: every cache describing itself to `/admin/caches` | `common/CLAUDE.md` |
| 3p | `user_graph.js`: the union of two registers as a library | `common/CLAUDE.md` |
| 3o | `federation.js`: who may require it, and `PATHS` | `federation/CLAUDE.md` |
| 3m | `realms.js`, the realm slot in `config.js`, the ambient realm | `common/CLAUDE.md` |
| 3q | `persistence.js`: the override-store and directory slots | `persistence/CLAUDE.md` |
| 3m | `logout/logout.ts` holds no state | `logout/CLAUDE.md` |
| 3n | `frontchannel_logout.js` | `oauth-oidc/CLAUDE.md` |
| 3aq | `backchannel_logout.ts`: OpenID Connect Back-Channel Logout 1.0 | `oauth-oidc/CLAUDE.md` |
| 3as | `id_token_encryption.ts`: encrypted ID Tokens and Logout Tokens | `oauth-oidc/CLAUDE.md` |
| 3at | `account_state.ts`: a disabled account | `common/CLAUDE.md`, `authn/CLAUDE.md` |
| 3au | `scope_policy.ts`, `scopeRefusal()` (#110): a scope tied to its declaring client | `common/CLAUDE.md`, `oauth-oidc/CLAUDE.md` |
| 3av | `fapi.js`: the FAPI 1.0 and 2.0 profiles (#138–#141) | `oauth-oidc/CLAUDE.md` |
| 3aw | `jarm.ts` (#143): JARM in every mode | `oauth-oidc/CLAUDE.md` |
| 3ax | `session_management.js` (#121): OpenID Connect Session Management 1.0 | `oauth-oidc/CLAUDE.md` |
| 3bx | Cells (#98): `cells.ts` and the five `cell_*.ts` | `common/CLAUDE.md`, `persistence/CLAUDE.md` |
| 3bz | The access-type catalogue and the per-right GNAP question (#432) | `gnap/CLAUDE.md`, `xacml/CLAUDE.md`, `oauth-oidc/CLAUDE.md` |
| 3ca | `http_signatures.ts` (#178): FAPI 2.0 HTTP Signatures | `oauth-oidc/CLAUDE.md` |
| 3cb | The admin console as a public client, DPoP mandatory (#446) | `oauth-oidc/CLAUDE.md` |
| 3cc | The console's own operations, `/admin-api/console`, `admin:console` (#454) | `mgmt-api/CLAUDE.md`, `common/CLAUDE.md`, `xacml/CLAUDE.md` |
| 3cd | Service accounts and the service-account policy (#221) | `common/CLAUDE.md` |
| 3ce | `secret_destinations.ts`, `pushSecret()` (#221 P3): rotated passwords pushed | `common/CLAUDE.md` |
| 3cf | `attestation_revocation.ts` (#256): Google's Android attestation status list | `common/CLAUDE.md` |
| 3ch | `passkey_policy.ts` (#527): the passkey policy | `common/CLAUDE.md` |
| 3ci | `i18n.ts`, `page_locale.ts`, `locale_policy.ts` (#539): locales | `common/CLAUDE.md` |
| 3cj | `scope_claims.ts` (#395): scope claims and declared access-token claims | `common/CLAUDE.md`, `oauth-oidc/CLAUDE.md` |
| 3ck | `server_prose.ts` (#543): console prose translated by `/admin-api` | `common/CLAUDE.md` |
| 3cg | `hosted_applications.js`, `listener_map.js` (#472): hosted applications and listeners | `common/CLAUDE.md`, `tls/CLAUDE.md` |
| 3ck | `account_api.ts` (#568): the user portal's only door | `account-api/CLAUDE.md`, `portal/CLAUDE.md` |
| 3cl | `common/web_*.ts` and friends (#570): the static surfaces' foundation | `common/CLAUDE.md` |
| 3cm | The mock relying parties (#581) — deleted by #592; number kept | `common/CLAUDE.md` |
| 3cn | `ownership.ts` (#607): owners, and OWNER_READ / OWNER_WRITE | `common/CLAUDE.md`, `xacml/CLAUDE.md`, `mgmt-api/CLAUDE.md` |
| 3cr | `device_bound_sessions.ts` (#725): the sign-on session bound to the browser's key (DBSC) | `authn/CLAUDE.md` |
| 3co | `attribute_policy.ts` (#396): what every person must hold, and a realm's custom attributes | `common/CLAUDE.md`, `ldap/CLAUDE.md` |
| 3cp | `phishing_resistance.ts` (#723): OpenID Connect EAP's `phr` and `phrh`, earned, requested and required | `common/CLAUDE.md`, `oauth-oidc/CLAUDE.md`, `xacml/CLAUDE.md` |
| 3cq | `recoveryAssurance` (#724): account recovery no weaker than the passkey it replaces | `common/CLAUDE.md`, `authn/CLAUDE.md`, `xacml/CLAUDE.md` |
| 3cs | `passkey_report.ts` (#942): who holds which passkey algorithm, kept rather than counted | `common/CLAUDE.md` |
| 3cw | `opaque_access_token.ts` (#501): opaque OAuth access tokens, off by default | `oauth-oidc/CLAUDE.md` |
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
growing number of routes relax it — the scripted pages below, and others
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
`tests/protocol/sts_metadata.js` tells an unrouted path from an endpoint legitimately answering
404. Fixing the header was the whole fix; a prettier 404 would break that test
silently.


## Pages with a script: the static surfaces, and one named script each

`app.js` sets `script-src 'none'` for the whole service, and the reason is in its
own comment: it is what makes the family of reflected-content problems moot rather
than merely unlikely. Two kinds of page carry a script, and each takes the SAME
shape of exception — `script-src 'self'` naming this service's own files, never
`'unsafe-inline'`, the policy set ONLY through `app.contentSecurityPolicy()`.

**A STATIC SURFACE** (#446, #568; the rule since #570) is an application drawn
in the browser from its API: everything it shows comes from an API answer and
everything it changes goes through an API call. **#569 converts every
human-facing page outside `/admin` and `/portal` into one, surface by surface**
(each switches when its own ticket merges), and every one keeps this rule:

* **SCRIPT IS REQUIRED** (rcbj on #569). No server-drawn fallback and no submit
  button stands in for the script; the shell's `<noscript>` says the page
  needs its script and nothing else is drawn.
* **ONE STATIC RUNTIME PER SURFACE**, built with the image by
  `build-typescript.sh`'s `bundle_surface`, its `web_*.ts` modules requiring
  nothing but other `web_*.ts` (a server module does not resolve, and the
  image does not build). What the surfaces share is `common/web_*.ts`.
* **ONE SHELL WRITER**: `common/shell_document.ts` draws the one document a
  surface answers and sends it with `script-src 'self'` and `connect-src
  'self'` plus the origins of the other listeners its runtime calls, through
  `app.contentSecurityPolicy()` — so `frame-ancestors` and `base-uri` cannot
  be dropped.
* **THE BROWSER TRANSLATES** (rcbj's decision 3 on #570), in #539's order, from
  the catalogs served as static JSON under `/web`; the APIs stay
  language-free and errors stay English.
* **A specification's endpoint is never converted** (#569's rule): its status,
  headers, body and the documents it answers — the auto-POST forms, the OP
  iframe, front-channel fan-out, the RFC 4559 exchange — stay as they are,
  and so do their rows in the second table.

| Surface | Script (and what its policy adds, each `'self'`) | Argued in |
|---|---|---|
| `/admin`, `/admin/*` — the console (#446) | `/admin/console.js`; `connect-src 'self'` | `admin-ui/CLAUDE.md`, `mgmt-api/CLAUDE.md` |
| `/portal`, `/portal/*` — the portal (#568) | `/portal/portal.js`; `connect-src 'self'`, `img-src 'self' data:` | `portal/CLAUDE.md`, `account-api/CLAUDE.md` |
| `/report`, `/report/*` — the reports application (#956) | `/report/report.js`; `connect-src` the sign-in origins, `style-src 'self'` | `report/CLAUDE.md` |
| `/` — the front door (#579) | `/home.js`; `style-src`, `connect-src` (+ the sign-in origin) | `home/CLAUDE.md` |
| `/authn/login`, `/authn/select-idp`, `/authn/password-change` (#571) | `/authn/signin.js`; `style-src`, `connect-src` | `authn/CLAUDE.md` |
| the steps after the screen: `/authn/totp`, `/authn/webauthn`, `/authn/backup-code`, `/authn/password-factor`, `/authn/mfa-setup`, `/authn/email-*` (#572, #573) | `/authn/signin.js`; the same | `authn/CLAUDE.md` |
| `/authn/wallet`, `/authn/wallet/wait` (#574) | `/authn/signin.js`; the same | `oid4vc/CLAUDE.md`, `authn/CLAUDE.md` |
| `/logout` (#577) | `/logout/signout.js`; `style-src`, `connect-src` | `logout/CLAUDE.md` |
| `/oauth2/consent` (#576) | `/oauth2/consent.js`; `style-src`, `connect-src` | `oauth-oidc/CLAUDE.md` (4c), `authn/CLAUDE.md` |
| GNAP's interaction pages (#578) | `/gnap/interaction.js`; `style-src`, `connect-src` (+ the sign-in origin) | `gnap/CLAUDE.md` |
| `/federation` and its login and link pages (#580) | `/federation/pages.js`; `style-src`, `connect-src` (+ the sign-in origin) | `federation/CLAUDE.md` |
| `/saml2`, `/saml11`, `/xacml`, `/ssf`, `/scim`, `/spiffe` — description pages (#584) | `<family>/description.js`; `style-src`, `connect-src` (+ the sign-in origin) | `common/CLAUDE.md` (3cl), each family's file |
| each public surface #569 converts | its own bundle over `common/web_surface.ts`; no token, the `sts_session` cookie | `common/CLAUDE.md` (3cl) |

**A SERVER-DRAWN PAGE WITH ONE NAMED SCRIPT** is the older exception, and each
but the OP iframe carries a REAL SUBMIT BUTTON as well, because with the
script blocked the button is the whole mechanism; the OP iframe has no person
in front of it and nothing to submit. A row leaves this table when its
surface is converted; the protocol documents never do.

| Page | Script | Argued in |
|---|---|---|
| WS-Federation's sign-in response | `/wsfed/autopost.js` | `ws-federation/CLAUDE.md` |
| `response_mode=form_post` | `/oauth2/autopost.js` | `oauth-oidc/CLAUDE.md` |
| the SAML 2.0 HTTP POST binding | `/saml2/autopost.js` | `saml/CLAUDE.md` |
| the SAML 1.1 Browser/POST profile | `/saml11/autopost.js` | `saml/CLAUDE.md` |
| `/oauth2/check_session` (#121, off by default) | `/oauth2/check_session.js` — no submit button | `oauth-oidc/CLAUDE.md` |

**The embedded debugger's pages are NOT on this list, because they are not on
this origin** (2026-09-13): `debugger/debugger_server.ts` serves them on a
listener of its own with a policy that allows their inline scripts THERE, which
is the reason it is a separate origin — `debugger/CLAUDE.md` argues it.

**For a server-drawn page, the test for a script is that the page CANNOT work
without one**, and the refusals are what establish it. Each is argued in its
own file:

| Refused | Because | Argued in |
|---|---|---|
| federation's outbound HTTP-POST binding | a person LEAVING this service gets a real form and a real button | `federation/CLAUDE.md` |
| the delegation and federation pictures | laid out on the server, arriving as ordinary markup | `admin-ui/CLAUDE.md` |
| the console's collapsible prose | a `<details>` needs no script | `admin-ui/CLAUDE.md` |
| the console's account menu | `<details>`/`<summary>`; the cost (it does not close on an outside click) is stated on the page | `admin-ui/CLAUDE.md` |
| the certificate details dialog | a link and a server-drawn overlay, a round trip per open | `admin-ui/CLAUDE.md` |

**A new scripted server-drawn page needs the argument made again from scratch,
and "the same as the page next door" is not one** — while a new static surface
needs none of it, because the rule above is the argument: it follows the
recipe in `common/CLAUDE.md` (3cl). The federation picture is the delegation
picture in every respect a reader would cite and got its own argument anyway;
the wallet's QR page sits beside a page that DOES relax the policy and still
had to argue its own case.

---

## Adding an endpoint costs one entry in `sts_metadata.ts`

`GET /admin/sts-metadata` reads the endpoint list **from the running Express router**, so
it cannot go stale — but it reports two kinds of drift and this repository's own
`tests/protocol/sts_metadata.js` fails on both: a route registered and undescribed, and a
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
*What is separated, and what is shared*. `tests/protocol/sts_metadata.js`
fails on the first two, `tests/protocol/admin_api.js` on the third and
`tests/realm_support.js` on the fourth. What nothing checks, and what a
settings group also owes, is a row in `admin-ui/admin.ts`'s `SETTING_HOMES`;
`admin-ui/CLAUDE.md` carries that and the second page's argument. **A new
page under Protocols also owes a row in `admin-core/protocol_endpoints.ts`**
(the endpoints of its realm, drawn on the page) or an exemption with its
reason; `tests/protocol_endpoints.js` fails otherwise.

**AND A CARD IS NOT ALWAYS A PROTOCOL, WHICH IS WHY THE COUNT IN THE OVERVIEW
AND THE COUNT ON THAT PAGE ARE DIFFERENT NUMBERS.** Three cards carry
`notAProtocol` — the User portal and Reporting (#956), which are
applications, and **Email codes and
links (#64), a credential mechanism that a guideline says is not an
authenticator at all** (it names NIST SP 800-63B-4 and RFC 8176 anyway).
**Recovery codes carried it until #283 (2026-10-07)** on the claim that nobody
wrote a specification for a recovery code; NIST SP 800-63B-4 section 3.1.2's
*look-up secrets* are one, and the card now names it.
`tests/protocol/sts_metadata.js` asserts that every card without the marker
names a specification — so the marker is what keeps that rule strict for
everything it was written for. A card still costs all three things above whether or not it is
a protocol, because the rule the page enforces is *no endpoint group without a
card*, and paying it here is cheaper than making the rule conditional.

**Those drift checks are enforcement rather than documentation**: `sts_metadata.ts`
is this repository's own job and a route registered and undescribed fails the
suite here.

Reading the router has one blind spot: **a protocol that registers no route is
invisible to it**, which is exactly what the KDC's raw TCP/UDP 88 listeners are — and
the directory's two, plain 389 and LDAPS 636. Those
have to be described by hand or they go unlisted with nothing failing.

Coverage notes in that file **must start `full`, `partial` or `minimal`** and say what is
missing. A list of fifty specifications that did not mention that in
development mode this service checks no passwords and validates no access
tokens would be the most misleading thing in the repository.

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
They bind every `.js` file except `common/crypto_impl/`, the eight Kerberos codec
copies, the `node-ldapjs` submodule and the non-`local` copies in
`tests/protocol/`, none of which may be edited here.

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
  files that cannot reach bunyan. A line below the level costs one comparison
  (#627), but its argument is still built, so on a hot path a debug line whose
  message is computed is guarded with `if (log.debug())` — `common/CLAUDE.md`,
  *Disabled debug lines*.
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
* **Every source file this repository owns starts with its two SPDX lines**
  (2026-09-27) — the copyright text naming Iya CyberSecurity Solutions, LLC
  and the licence identifier BUSL-1.1 (the Business Source License 1.1 since
  2026-09-30; MIT until then), in the form `LICENSE.md` shows, after a `#!`
  line or `// @ts-check`, in the file's own comment syntax. A file that cannot carry a
  comment, a vendored copy and third-party material are declared in
  `REUSE.toml` instead, and never given a header — the parent project's
  copies stay MIT there. `tests/copyright_notices.js` fails on a missing
  one; `LICENSE.md` says what is not under the BSL, and `reuse lint` is the
  whole-repository check.
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

**A change to ldapjs goes in the fork, `rcbj/node-ldapjs`**, never as a patch
from this repository, with the pin bumped here in the change that uses it. **The
submodule is NESTED** (this repository is the parent's submodule), so the
parent needs `git submodule update --init --recursive`; without it the failure
is `Cannot find module 'ldapjs'` at runtime. `ldap/CLAUDE.md` has the rest.

## Signing keys, and any document that publishes one

**In development mode — the default — the signing keys are regenerated on every
start; in product mode they are generated once and kept in the persistence store,
sealed under a key-encryption key this service never generates.** A service that
cannot read its own signing key does not start. `common/CLAUDE.md` argues both
(`keystore.js`, `secrets.js`).

**The cross-cutting rule: every document that carries or describes a key is
served `Cache-Control: no-store`.** If you add one, it needs that header too —
`tests/protocol/sts_metadata_anonymous.js` asks it of every metadata document
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
./run-jsdoc.sh                          # the API reference (TypeDoc) into ./apidocs
```

**`./run-tests.sh` is the one launcher, wherever the service is**; its local
modes are `memory`, `single-node` and `cluster` (a bare run runs all three),
`cells` runs only when named, and an AWS target runs the protocol half only.
**`npm test` refuses on a checkout since #50**, which is why
`./docker-npm-test.sh` exists. `tests/CLAUDE.md` argues all of it.

Where a new test goes, asked in this order:

1. **Is it about this service's own `/admin` or `/admin-api`?** Then `tests/protocol/`, `local: true` — an ownership argument, not a capability one.
2. **Can it be asserted over HTTP against a running service?** Then **`tests/protocol/`, `local: true` — written HERE since 2026-09-21** (rcbj's decision; it was `../id-proto-debugger/tests/`). A protocol job is the only kind an AWS target and the `product` mode can run, so a feature covered only in process is uncovered there.
3. **Otherwise here**: it chooses how the process starts, needs a second container on the service's network, or needs a socket no stack publishes.

**Never edit a vendored copy** — the next
`node tests/tools/vendor-check.js --sync` overwrites it and the
fix never reaches the parent. The `local: true` jobs are the inversion, edited
here only. `tests/protocol/MANIFEST.js` says which is which.

`tests/CLAUDE.md` carries the job table, the launchers, the modes, the image
mirror, the coverage run and the rules that are not optional there. **What
each surface still has NO test for is recorded in that surface's own file.**

## Things this service deliberately does not do

Worth knowing before "fixing" one of them. **This is an INDEX** — each row names
the thing in one line and points at the file that argues it. A row that grows a
paragraph here is the drift this file exists to prevent; the paragraph goes in
the file the row names.

| It does not | Where the argument is |
|---|---|
| Enforce anything by default, **in development mode** — product mode implies RFC 9700 mode | `oauth-oidc/CLAUDE.md`, `common/mode.js` |
| Federate with anybody it was not CONFIGURED to federate with — the one refusal by default | `federation/CLAUDE.md` |
| Poll a partner about a person while the session lasts; ~~consume a federated sign-out~~ reversed 2026-09-23 (#167); ~~decrypt a partner's encrypted assertion~~ reversed 2026-09-23 (#168) | `federation/CLAUDE.md` |
| Dial a URL a CALLER supplied to fetch something FROM (`wreqptr`) — nineteen argued exceptions | `federation/CLAUDE.md`, *The URLs this service dials that a caller's kind of URL could name* |
| ~~Ask anybody's permission before it issues something~~ — reversed 2026-09-01 (`/oauth2/consent`) | `common/CLAUDE.md`, `oauth-oidc/CLAUDE.md` |
| Let a page on another origin read an answer, unless it is this service's own or listed in `appCorsOrigin` | `common/CLAUDE.md` (`cors.js`) |
| Check an end user's password, **in development mode** | `authn/CLAUDE.md`, `kerberos/CLAUDE.md`, `common/CLAUDE.md` |
| Verify a client's credential, **in development mode outside RFC 9700, OAuth 2.1 and FAPI mode** | `oauth-oidc/CLAUDE.md` |
| Refuse an LDAP bind, **in development mode**, except the password `invalid` and a disabled account | `ldap/CLAUDE.md` |
| Authorize an LDAP write or read, **in development mode** | `ldap/CLAUDE.md` |
| Check a Kerberos password, **in development mode** — though it cannot not check the KEY | `kerberos/CLAUDE.md` |
| Verify an access token at the OpenID4VCI endpoints or in RFC 8693 token exchange, **in development mode** | `oauth-oidc/CLAUDE.md`, `oid4vc/CLAUDE.md` |
| Accept an RFC 7523 assertion from an issuer nobody DECLARED | `oauth-oidc/CLAUDE.md`, `common/CLAUDE.md` |
| Accept an RFC 7522 assertion from an `<Issuer>` nobody DECLARED, or on a certificate that merely chains to the realm's CA | `oauth-oidc/CLAUDE.md`, `common/CLAUDE.md` |
| ~~Revoke a certificate it issued~~ — reversed 2026-09-11 | `common/CLAUDE.md`, `admin-ui/CLAUDE.md`, `docs/pki.md` |
| Keep a certificate authority across a restart, **in development mode** | `common/CLAUDE.md` |
| Enforce `value`/`values` in an OIDC Core 5.5 claims request, or treat `essential` as an instruction | `oauth-oidc/CLAUDE.md` |
| ~~Require DPoP~~ — reversed 2026-09-15 (#34), five settings off by default (rule 3ao) | `oauth-oidc/CLAUDE.md` |
| ~~Turn a verified client certificate into a login~~ — reversed 2026-09-05 | `tls/CLAUDE.md` |
| Verify anything in an issued credential's values, which are invented | `oid4vc/CLAUDE.md` |
| ~~Turn a verified presentation into a sign-on~~ — reversed 2026-09-17 (#38) | `oid4vc/CLAUDE.md`, `authn/CLAUDE.md` |
| ~~Publish a status for a credential it issued~~ — reversed 2026-09-17 | `oid4vc/CLAUDE.md` |
| ~~Deactivate anybody on SCIM `active: false`~~ — reversed 2026-09-17 | `scim/CLAUDE.md`, `common/CLAUDE.md` (3at), `authn/CLAUDE.md` |
| ~~Attest a workload or a node~~ — reversed 2026-09-21 (#40); a TCP caller still is not (#166) | `spiffe/CLAUDE.md` |
| Revoke a SPIFFE credential — the directory records who may still be ISSUED one | `spiffe/CLAUDE.md`, `ldap/CLAUDE.md` |
| Match a client certificate from an outside CA by its common name or subject, or create an entry for one — it is the one entry storing it in `userCertificate` (#1061) | `common/CLAUDE.md` (3ag), `tls/CLAUDE.md`, `ldap/CLAUDE.md` |
| Let a group grant anything BY BEING A GROUP | `admin-ui/CLAUDE.md`, `common/CLAUDE.md` |
| Let an authenticator app be a FIRST factor | `common/CLAUDE.md` |
| ~~Issue a set of recovery codes on request~~ — reversed 2026-09-11 | `common/CLAUDE.md`, `portal/CLAUDE.md` |
| Offer a self-service reset of a second factor | `admin-ui/CLAUDE.md` |
| Require a compliant registered device, **by default in either mode** (#164) | `xacml/CLAUDE.md`, `common/CLAUDE.md` |
| ~~Decide who may delegate to whom IN THE ACT~~ — reversed 2026-09-23 (#108), in policy since #186 | `common/CLAUDE.md` (3az), `kerberos/CLAUDE.md`, `oauth-oidc/CLAUDE.md`, `ws-trust/CLAUDE.md` |
| ~~Give every trust realm a certificate authority of its own~~ — reversed 2026-09-11 | `common/CLAUDE.md`, `docs/pki.md` |
| ~~Give a trust realm its own Kerberos KDC~~ — reversed 2026-09-15 (#33) | `kerberos/CLAUDE.md`, `common/CLAUDE.md` |
| ~~Give a trust realm its own administrator~~ — reversed 2026-09-14 (#32) | `admin-ui/CLAUDE.md`, `mgmt-api/CLAUDE.md`, `ldap/CLAUDE.md` |
| ~~Persist anything it MINTS~~ — reversed 2026-09-06, in product mode on postgres only | `persistence/CLAUDE.md`, `admin-ui/CLAUDE.md` |
| Deliver a response to an address nobody registered, **in product mode** | `common/applications.js`, `saml/CLAUDE.md`, `common/oidc_rp.ts` |
| Start with demonstration data, invent a claim value, or open a test control to anybody, **in product mode** | `common/mode.js`, `common/CLAUDE.md` |
| Ship a demonstration endpoint at all, **in any mode** (#591) | `companion/CLAUDE.md`, `tests/peer/`, `tests/demo_endpoints.js` (the guard) |
| Dial its database in the clear (#273); ~~or authenticate that server by default~~ — reversed 2026-10-12 | `persistence/CLAUDE.md` |
| Send mail to an address a request supplies, through a relay a caller names, or in the clear (#63) | `common/CLAUDE.md` (`mail.ts`) |
| ~~Coordinate several processes through that store~~ — reversed 2026-09-06 | `persistence/CLAUDE.md`, `common/CLAUDE.md` |
| Recall anything it has already ISSUED — it DISOWNS them | `logout/CLAUDE.md`, `common/CLAUDE.md` |
| ~~Perform back-channel logout~~ — reversed 2026-09-17 (#36) | `oauth-oidc/CLAUDE.md` (3aq), `logout/CLAUDE.md`, `authn/CLAUDE.md`, `federation/CLAUDE.md` |
| ~~Fake WS-Federation's `wauth`~~ — reversed 2026-09-17 (#36), as a step-up | `ws-federation/CLAUDE.md`, `authn/CLAUDE.md` |
| Dereference WS-Federation's `wreqptr` | `ws-federation/CLAUDE.md` |
| Post an unsolicited ID Token to an OpenID Connect client's `redirect_uri` — its identity-provider-initiated sign-in is Core section 4 (#426) | `launch/CLAUDE.md`, `oauth-oidc/CLAUDE.md` |
| Start a sign-in at this identity provider for an application that did not opt in — off by default in every protocol (#426) | `launch/CLAUDE.md` |
| ~~Verify a SAML AuthnRequest's signature, or consume SP metadata~~ — reversed 2026-09-17 (#37) | `saml/CLAUDE.md`, `saml/request_signature.ts`, `saml/sp_metadata.ts` |
| Encrypt an assertion it holds no certificate for — **product refuses**, development sends it in CLEAR | `saml/CLAUDE.md` |
| Dial a service provider's metadata URL WHILE ISSUING | `saml/CLAUDE.md` |
| Release a person's DID unless they proved it, preferred it and consented to it themselves — to a pairwise or ephemeral client only by its opt-in, and never in a SAML assertion (#693) | `oauth-oidc/CLAUDE.md` (*The `did` claim*) |

## The parent project's paths into this repository

**The `sts/` COPY set in the parent's `tests/Dockerfile` is the transitive
closure of what `krb5_kdc.js`, `krb5_service.js` and `spnego.js` require, and it
moves on THIS repository's schedule.** Add a require reachable from any of them
and the commit that bumps the `sts/` pin must add the COPY line too, or four
in-process Kerberos jobs die at load with `Cannot find module`, which names a
file nobody edited. What is owed now, and why `mockStsModule()`'s callers pass
bare filenames: `kerberos/CLAUDE.md`. The walk itself:
`docs/parent-project-migration.md`.
