# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in
this repository.

**It is the thin one, and on 2026-09-05 it was made thin again.** Almost every
fact about a module lives in the `CLAUDE.md` of the directory that module is in,
and this file keeps only what is genuinely cross-cutting: the require order, the
rules about libraries and hooks, the two CSP rules, the endpoint-drift rule, the
code style, the submodule warnings, and the state of the tests. **There is one
copy of each fact.** If something here looks like a summary of a directory file,
it is a bug — say so rather than reconciling the two.

**That sentence had stopped being true and this file is the record of putting it
back.** It had grown to 1775 lines, more than a third of them a *Tests* section
that described the protocol jobs, three launchers and the coverage renderer while
`tests/CLAUDE.md` described the same things beside it.

**Two different things happened to the text that left, and they are worth
telling apart.** Prose that had no home elsewhere was MOVED — verbatim, into the
directory that owns it, with a pointer or the rule it was an instance of left
here. Prose that was a summary of a directory file was DELETED, because that is
what the paragraph above says to do with it; the destination already said it,
usually better and always in more detail.

| What left this file | Where it is now | Moved or deleted |
|---|---|---|
| The worker pool's five things to know, and the realm's eleven keys | `common/CLAUDE.md` | moved |
| The per-realm store rule, and the two stores found process-wide on 2026-08-28 | `common/CLAUDE.md` | moved |
| Why the main port is HTTPS, and the appconfig files | `env/CLAUDE.md` | moved |
| The appconfig LAYERING | `common/CLAUDE.md` | deleted — it was already there |
| `persistence.js` binding nothing and still going first | `persistence/CLAUDE.md` | moved |
| The failed-open-is-fatal argument | `persistence/CLAUDE.md` | deleted — it was already there |
| The job table, and the TLS anchor every job gets | `tests/CLAUDE.md` | moved |
| The launchers, the five items, the coverage run | `tests/CLAUDE.md`, and the launchers' own headers | deleted — argued where they live |
| What a SCIM test would cover | `scim/CLAUDE.md` | moved |
| What a SPIFFE test would cover | `spiffe/CLAUDE.md` | moved |
| What a UserInfo claims-request test would cover | `oauth-oidc/CLAUDE.md` | moved |
| The two halves of the SPNEGO sign-in's test | `kerberos/CLAUDE.md` | moved |
| What a SAML, federation or WS-Federation test would cover | those three files | deleted — already there |
| The per-page arguments for the six scripted pages | the six files, and the pages themselves | deleted — already there |
| The two shell scripts the database container runs | `postgres/CLAUDE.md` | moved |

**`env/` and `postgres/` had no `CLAUDE.md` at all until that day** — they were
described only by a cell in the table below, which is the shape of drift this
arrangement exists to prevent.

Four facts turned out to live ONLY in this file and were rehomed rather than
lost: the TLS anchor `tests/tools/trust.js` hands every job, the rule that a
test restores a setting with `reset` rather than by writing the old value back,
that the parent's launchers compute the SAML metadata digest with `sha256sum` so
`slugOf()` cannot move alone, and why `tests/saml_encrypted_sso.js` is
deliberately not paired.

## Where things are

The 2026-08-23 reorganisation moved every module out of the package root. The
files did not change; the paths did.

| Directory | What is in it |
|---|---|
| `common/` | Everything more than one family reads: `config.js`, `helpers.js`, **`crypto.js`**, `app.js`, `realms.js`, `admin_stats.js`, `audit.js`, `applications.js`, `delegation.js`, **`app_permissions.js`** (the CONFIGURED delegation register — who MAY reach what, in Entra ID's shape, against `delegation.js`'s record of what DID), `user_graph.js`, `claim_attributes.js`, `group_claims.js`, `config_file.js`, and — since 2026-08-30 — **`worker.js` and `worker_pool.js`, the child-process pool the post-quantum signing runs in** (see *One listener process, N stateless workers* below). **`crypto.js` is THE ONE PLACE THIS SERVICE SIGNS, VERIFIES, ENCRYPTS AND DECRYPTS since 2026-08-27** — before that it did all four in about twenty places, including six XML signers and four XML signature verifiers. `common/CLAUDE.md` argues it. **And since 2026-09-06 `mode.js`, `credentials.js`, `keystore.js` and `secrets.js` — the four files that make this service a PRODUCT as well as a mock.** `mode.js` is the one place `development` and `product` are told apart, and every surface that used to decide for itself whether a credential was required asks it instead; `credentials.js` is the one place a presented password is verified, over the hashed `userPassword` on the person's own entry; `keystore.js` holds the signing keys that survive a restart in product mode; `secrets.js` reads the key that encrypts them, from a mounted file or one of four cloud secret stores. **And since 2026-09-05 `roles.js` and `issuance_gate.js`, which are the two halves of the fourth register — the one a USER, a GROUP and an APPLICATION are all first-class members of.** `roles.js` holds who HOLDS a role (`ou=roles` is its store) and the six computed built-in ones; `issuance_gate.js` is the LEAF nine issuance sites ask before this service issues anything, whose decider `xacml/xacml_role_pep.js` fills at 23c. **An empty decider means ISSUE**, which is what keeps a process without the XACML family a smaller service rather than a broken one. And since 2026-09-01 `consent.js`, the register of what a PERSON agreed an application may ask for on their behalf — the third register in the `delegation.js` / `app_permissions.js` family and the first whose rows have a person in them, holding no store of its own because both halves are attributes in the directory (`oauthConsent` on a person, `oauthGlobalConsent` on an application). |
| `common/vendored/` | Byte-identical copies of the parent project's files, plus the JSON-LD `contexts/`. **Do not edit them here.** Since 2026-08-27 that includes `xmldsig.js`, the parent's own XML Signature and XML Encryption module, which is now the signer behind every signed document this service emits — so both ends of a SAML exchange canonicalize with the same code. |
| `home/` | The front door: `GET /` and the one image on it. |
| `logout/` | The protocol-independent sign-out: `GET|POST /logout`, and the one model of what a live session IS across every family — for ONE identity (`inventoryFor()`, what `/admin/logout` draws) and, since 2026-09-04, for the whole service (`liveSessions()`, what **`/admin/sessions`** and `GET /admin-api/sessions` draw, with a Revoke on every row that goes through the same `terminate()`). |
| `oauth-oidc/` | The authorization server, RFC 9700 mode, DPoP, mTLS, client authentication, the multi-AS profiles, **the CONSENT SCREEN at `/oauth2/consent`** (2026-09-01 — the one thing between a signed-in person and an issued credential, and the one policy in this service that is ON by default), and **the UserInfo endpoint's four layers** — a claim set of its own configured at `/admin/userinfo-claims`, the scope-driven set, OIDC Core 5.5's claims request, and `sub`. |
| `authn/` | The authentication service and the WebAuthn relying party. Owns the SESSION. **One endpoint in its own path space lives elsewhere**: `/authn/spnego` is `kerberos/spnego_authn.js`, for a require-order reason both files argue. |
| `saml/` | The two assertion builders, and A BROWSER-FACING IDENTITY PROVIDER FOR EACH: SAML 2.0's Web Browser SSO profile (all three bindings, Single Logout, metadata per service provider) and SAML 1.1's two browser profiles (Browser/POST, Browser/Artifact, a SOAP responder that is also an attribute authority, metadata per relying party). **They are separate implementations, not one with a version flag** — SAML 1.1 has no request message, no Single Logout, and a different spelling for almost every shared element; `saml/CLAUDE.md` has the table. |
| `ws-trust/` | WS-Trust 1.0–1.4. |
| `ws-federation/` | WS-Federation 1.2, the passive requestor profile, and the mock relying party. |
| `federation/` | **Federation relationships, in either direction, in five protocols.** The register (`ou=federations` IS the store), the attribute mapping, the four endpoints, the graph the console's picture is drawn from — and the FIRST OF THREE OUTBOUND REQUESTS in this repository, in a module of its own that will not take a URL from anywhere but a relationship entry. It is the STRONGEST of the three and the other two each argue their own case rather than citing it — SSF's is `ssf/ssf_http.js` and XACML's nudge is `xacml/xacml_pep_http.js`. |
| `kerberos/` | The KDC, the acceptor, SPNEGO in three layers — the negotiation, the page that explains it, and **the SIGN-IN that turns a ticket into this service's session** — and the eight codec modules they rest on, **all eight VENDORED from the parent project and not editable here**, despite not being under `common/vendored/`. See `kerberos/CLAUDE.md`. |
| `ldap/` | The embedded directory. Also the STORE for people, groups, applications and the SPIFFE registry. **And, since 2026-09-01, the ADMIN CONSOLE PAGES that show that store — five then and EIGHT since 2026-09-05** — `/admin/ldap/directory` (every entry, every attribute, paged), `/admin/ldap/applications`, `/admin/ldap/federations`, `/admin/ldap/spiffe`, and — since 2026-09-05 — `/admin/ldap/roles`, `/admin/ldap/policies` and `/admin/ldap/peps` (each a container with the SCHEMA it uses, because this directory is schemaless) and `/admin/ldap/service` (the two raw sockets as they actually are, which nothing that walks the router can see). **The last three closed a gap rather than adding a feature**: `common/roles.js`, `xacml/xacml_store.js` and `xacml/xacml_pep_registry.js` each PUBLISHED a schema whose comment said it was drawn on a page under `/admin/ldap/*`, and for three of them no such page had ever been written — so `ou=roles` reported `0 user(s)` for a role somebody held and `ou=policies` drew a DISABLED policy as enabled, both because the store lower-cases an attribute name and none of the three schemas was merged into `learnName()`. They were `/ldap*`, in a shell of their own, outside the console and outside its gate; a console page is a `path` and a `label` in `admin-ui/admin.js`'s `SECTIONS` whoever builds the body, which is the arrangement `/admin/sts-metadata` has had since 2026-08-24. |
| `persistence/` | **THE ONE PLACE THIS SERVICE WRITES ANYTHING DOWN, since 2026-08-27, and the first time it ever has.** Three modes — `memory` (the default, and what this service always did), `ldif` (an RFC 2849 file per realm, no database) and `postgres` — behind one driver interface. THREE THINGS PERSIST: the embedded directory, the trust realm registry, and the runtime appconfig overrides. **NOTHING THIS SERVICE MINTS EVER DOES**, in any mode, because the signing key is regenerated on every start. It is PERSISTENCE and not COORDINATION, and `persistence/CLAUDE.md` says what the second one still needs. |
| `scim/` | `/scim/v2`, its authentication, and its attribute mapping. |
| `ssf/` | **The Shared Signals Framework (OpenID SSF 1.0, final September 2025), and the one family here that TALKS BACK** — every other answers a request, and this one agrees a STREAM and then delivers a Security Event Token at the moment something happens. Six modules: the routes, an RFC 9493 subject grammar written out here rather than vendored (a grammar is a READING, and one implementation read by both ends hides the misunderstandings they share), the RFC 8417 envelope, the streams and their queues per realm, the gate, and **the SECOND outbound request in this repository** — which is a weaker case than federation's and `ssf/CLAUDE.md` argues rather than cites, because RFC 8935 push IS the receiver telling the transmitter where to post. (The THIRD is XACML's change nudge, and it is weaker still and argued in its turn: no specification asks for it at all, and what pays for it is that it is never the mechanism — a PEP pulls and converges without it.) **SSF is the PIPE and not the vocabulary**: it defines two events of its own, both about the pipe, and CAEP (what happened to a SESSION, since 2026-09-03) and RISC (what happened to an ACCOUNT, since 2026-09-04) are the two vocabularies spoken over it. **Eight modules now**: the seventh is `caep.js`, the eighth `risc.js`, and they are siblings rather than one generalized register — a session begins, is used and ends and there are many per person, and an account IS the person and outlives every session on it. Two observers, on two different stores: CAEP watches `authn.js` and RISC watches `ldap/ldap_server.js`, which is the authentication layer and the provisioning layer, and the whole difference between the two profiles is which of them the sentence is about. |
| `spiffe/` | Six libraries, one server module, and the vendored `protos/`. |
| `tls/` | The 8443 and 9443 listeners, and the certificate three other sockets share. |
| `oid4vc/` | OpenID4VCI, OpenID4VP, DID Core. |
| `admin-ui/` | The console at `/admin`, the two roles that decide who may use it, **every setting drawn on the page for the protocol it configures** (2026-08-27 — `SETTING_HOMES` is the table, `/admin/config` keeps the rows belonging to no protocol and the index of the rest), and the TWO DRAWINGS in this service — `/admin/delegation/map` and `/admin/federation/map`, both laid out on the server. They share a palette, a hexagon and a text metric and NOTHING ELSE: one flattens a layered layout on purpose and the other is a layered layout, so each has its own renderer. `admin-ui/CLAUDE.md` argues why that is not duplication. **And since 2026-08-30 the CRYPTO REPORT** (`crypto_metadata.js`, `/admin/crypto-metadata`): what this service does when it signs, verifies, encrypts or decrypts, for every identity service it advertises, with every algorithm table READ FROM THE MODULE THAT PERFORMS THE ALGORITHM — the same argument `sts_metadata.js` makes about the router, one layer down. |
| `mgmt-api/` | `/admin-api`, its generated OpenAPI document, and the explorer. |
| `tests/` | **THE ONLY TEST DIRECTORY HERE**, and since 2026-08-28 it holds BOTH halves of this service's coverage. `tests/*.js` is the in-process half — assertions about this repository's own module contracts, `npm test`, no port and no container and under a second. **`tests/vendored/` is the protocol half**: nineteen jobs driven over HTTP against a CONTAINER built from this tree by `docker-compose.yml` (a throwaway in-process copy under `--no-docker`, and under coverage), plus the wallet modules five of them verify against. NINE are byte-identical copies of the parent project's mock-only jobs and are NOT edited here; **TEN are this repository's own** — the ones that drive this service's `/admin` console and `/admin-api`, marked `local: true` since 2026-08-28, with no copy over there to sync from and the editing rule inverted for them. `tests/vendored/MANIFEST.js` says which is which and where each copy came from, and `--vendor-check` reports drift in the nine copies. See *Tests* below for what changed and `tests/CLAUDE.md` for the rules that are not optional there. **`tests/tools/` is not tests**: the report generator, the coverage renderer, the compose-stack helpers (`compose.sh`, shared by both launchers) and the throwaway-service launcher `./local-run-tests.sh`, `./docker-run-tests.sh` and `./run-coverage.sh` drive — in a subdirectory precisely so that `run.js`'s discovery rule needs no exclusion list. **`tests/Dockerfile`, its own `.dockerignore` and `tests/run-tests-in-container.sh` are not tests either**: they are the RUNNER as a container, which `docker-compose-run-tests.yml` brings up beside the service so that a host with docker and nothing else runs all forty-four jobs — `tests/CLAUDE.md` argues it. `federation-e2e/` sat beside it until trust realms made its three-container stack unnecessary; that test is `tests/federation_sso.js` in the parent project's suite now. |
| `xacml/` | **XACML 3.0 and ALFA: the engine, the policy repository, the PIP, an embedded PEP and the PAP.** Fourteen DOM-free modules plus `xacml.js` and `xacml_admin.js`, the two that register routes — seven under `/xacml`, five console pages under `/admin/xacml`, seventeen operations under `/admin-api/xacml` — required at 23c. **`ou=policies` in the embedded directory IS the repository**, the way `ou=federations` is the federation register. **THE ONLY FAMILY HERE THAT ANSWERS A QUESTION ABOUT SOMEBODY ELSE'S BOUNDARY** — every other protocol authenticates or provisions somebody, and this one is handed a subject authenticated elsewhere and asked whether they may. Held to the VENDORED OASIS conformance suite (**454 of 455 mandatory cases**), which is **Apache-2.0 rather than this repository's MIT** and says so in `LICENSE.md`. **ONE MODEL, THREE RENDERINGS**: the core XML, the JSON Profile, and **ALFA** — which is a VIEW and never a second stored copy, and whose contract is that anything it writes it reads back *and the policy decides identically either way*, asserted on seven probes because a swapped comparison round-trips perfectly and decides the opposite. **The guided editor has NO JAVASCRIPT**: this console is `script-src 'none'`, so every "pick the next valid element" dropdown is computed on the server by the same code that validates the result. `xacml/CLAUDE.md` indexes the twelve defects the tests caught. **AND SINCE 2026-09-05 IT DECIDES THIS SERVICE'S OWN ISSUANCE**, which is the one thing in this directory that is not about somebody else's boundary: `xacml_role_pep.js` is an EMBEDDED PEP that turns a token, an assertion, a ticket or a session into a XACML request and fills `common/issuance_gate.js`'s decider. The policy it evaluates is BUILT IN — the `role-issuance` template, called rather than seeded, because `ou=policies` is per realm and a seed written once in the default realm left every later realm unable to use roles at all — and a repository entry named by `xacml.issuancePolicy` overrides it. **THE REMOTE PEP LANDED 2026-09-05 and its container is `xacml-pep/`, below** — what is in this directory is the PDP's side: `ou=peps`, three endpoints under `/xacml/pep`, a fifth console page, and the nudge, which is this repository's THIRD outbound request. |
| `xacml-pep/` | **THE ONLY DIRECTORY HERE THAT IS NOT PART OF THE MOCK.** A second container: a remote XACML Policy Enforcement Point that holds its own copy of the engine, PULLS the policy repository from `/xacml/pep/policies` and decides in its own process. `server.js` does not require it and nothing here does; `docker compose --profile xacml up` starts it. **THE PULL IS THE CONTRACT** — the nudge this service sends on a change is an optimisation over the polling interval and never a replacement for it, which is what makes a third outbound requester affordable. The engine is copied out of `xacml/` AT BUILD TIME, so there is one copy of the evaluator in this tree; `tests/xacml_pep.js` asserts the Dockerfile's COPY set against the module list. **Its thirty-line `common/helpers.js` shim is the most valuable thing in phase five** — it is what makes "the engine is a library with no I/O" a checked claim rather than a comment at the top of seven files. `xacml-pep/CLAUDE.md` argues all of it. |
| `postgres/` | **Two shell scripts the database container runs, and nothing else.** `generate-tls.sh` makes its server key pair on first start — the same decision every other key here follows, because a certificate committed to a repository is a private key committed to a repository — and `require-tls.sh` rewrites every `host` rule in `pg_hba.conf` to `hostssl` so that TLS is REQUIRED rather than merely available. Both are mounted into the image by `docker-compose.yml`; neither is run by this service. `persistence/CLAUDE.md` argues them. |
| `docs/` | The GitHub Pages site. See `docs/CLAUDE.md`. |
| `env/` | The appconfig files. `CONFIG_FILE` selects one, and it is unioned on top of `defaults.js`, which is GENERATED by `generate_defaults.js` and is not selected by anything. |

At the package root there are exactly two modules, and both earn it:
**`server.js`**, the shell that requires the others and listens, and
**`sts_metadata.js`**, which reads the router to list what everything else
registered and is therefore required last.

**Read the directory's own `CLAUDE.md` before changing anything in it.** They are
not summaries — the reasoning that used to be in this file is in them, verbatim,
and most of it is the record of something having gone wrong once.

`README.md` is the substantive document and is still at the root. `docs/` is the
user-facing half — how to USE this service — and is published as a GitHub Pages
site; this file and the directory files are the maintainer-facing half.

## Overview

A mock identity service that speaks seventeen protocol families — Kerberos v5 (a KDC on
raw TCP/UDP 88 and over MS-KKDCP, plus a Kerberos-protected service and the same
acceptor over HTTP as **SPNEGO**, RFC 4559/4178), WS-Trust
1.0–1.4, **SAML 2.0** (assertions, and the Web Browser SSO profile over all three
bindings with Single Logout and per-service-provider metadata) and **SAML 1.1**
(assertions, and BOTH browser profiles — Browser/POST and Browser/Artifact —
with a SOAP responder behind the second that is also an attribute authority,
answering AttributeQuery and AuthenticationQuery),
WS-Federation 1.2 (the passive requestor profile),
**FEDERATION** (this service as EITHER END of a relationship with a foreign
identity service, in five of those protocols — consuming somebody else's
assertions as a service provider, or asserting to a foreign service provider
with a per-partner attribute release policy),
OAuth 2.0 / OIDC (a full authorization server), WebAuthn Level 3 (the relying party's
half, on the login screen), DPoP, OpenID4VCI 1.0, OpenID4VP 1.0, W3C DID Core with
DIF domain linkage, and **LDAP v3** (RFC 4511 — an embedded directory on raw TCP 389 and,
over TLS, on raw TCP 636 as **LDAPS**, one set of handlers and one store behind
both, built on the node-ldapjs SUBMODULE and used unmodified), **SCIM 2.0**
(RFC 7642/7643/7644 — a provisioning endpoint at `/scim/v2` that writes into that
same directory, entry for entry, with no store of its own), and **TLS / mutual TLS**
(two HTTPS listeners of its own, 8443 and 9443, whose whole content is what the
SERVER saw of the connection — see README.md; and, when `global.https` is set,
the main port too, on the same certificate), and **SHARED SIGNALS** (SSF 1.0 — a TRANSMITTER: stream
management, subjects in all eight RFC 9493 formats and the complex subject,
verification, and delivery by RFC 8935 push or RFC 8936 poll, plus a receiver
of its own so that a client can be the transmitter), and **SPIFFE** (an issuing
authority
for one trust domain, in all three of its server-side shapes: the bundle endpoint
over plain HTTPS, and the **Workload API** and **SPIRE Server API** over gRPC on
FOUR MORE SOCKETS — a Unix socket and a TCP port each). It exists to exercise
*clients*: it checks no password, validates no access token and **attests no
workload**.

**FIVE surfaces are the exception to that last sentence, and each is argued
where it lives rather than here.** This is the index; every one of them is a
turnstile rather than a lock, and the first three can be turned off.

| Surface | What it requires | Why | Argued in |
|---|---|---|---|
| `/scim/v2` | a credential, in any of RFC 7644 section 2's six schemes; the OAuth ones need `scim:read` or `scim:write` | it creates and DELETES accounts | `scim/CLAUDE.md` |
| the SPIRE Server API | an X509-SVID over mutual TLS, authorized against SPIRE's own per-method table | what comes out of it is a credential another service will believe | `spiffe/CLAUDE.md` |
| `/admin` | a browser sign-on session and one of two roles — **Admin Read** and **Admin Write**, ordinary groups in the directory | it is the one surface that can change what every protocol endpoint does | `admin-ui/CLAUDE.md` |
| `/federation/acs/{id}` | a signature that verifies against the certificate configured on the relationship | **this one is NOT a turnstile and cannot be made permissive** | `federation/CLAUDE.md` |
| `/authn/spnego` | a Kerberos ticket, verified against a real long-term key | **this one is not a refusal at all** | `kerberos/CLAUDE.md` |

The first three are a turnstile in the same sense: anybody can get a token with
either SCIM scope, any password but one passes Basic, anybody can register a
HOBA key, anybody can ask the local socket to mint an SVID, and no password is
checked at the console's sign-in screen either — what the gate proves is that
somebody typed a name that holds a role. Each can be turned off
(`scim.authRequired`, `spiffe.authRequired`, `admin.authRequired`).

**The last two are different in KIND and both files say why at length.**
Federation is the one feature here that must be CONFIGURED before it does
anything, because there is no permissive answer available — "accept any SAML
Response" means letting anybody who can reach this port get a browser sign-on
session as anybody, and that session is the same one `/oauth2/authorize`,
`/wsfed`, `/saml2/sso`, `/saml11/sso` and `/admin` all read. The gate is on the
SIGNER, not on the subject. And `/authn/spnego` verifies a credential not
because it guards anything but because **Kerberos cannot be permissive the way
the rest of this service is** — the password there IS the key — so the
permissiveness moved into the KDC's ACCOUNT POLICY and left the verification
real. **The verification is real and the account policy is not**, and those are
two different sentences that this repository's prose has to keep apart.

**`/admin-api` is NOT gated and that is deliberate** — it is what a test drives,
and it is the way back in when nobody holds a role. Which means anybody who can
reach this port can grant themselves both roles through it; see
`mgmt-api/CLAUDE.md`, where that is argued rather than assumed.

**The Workload API is the opposite case and the distinction matters**: it
authenticates nobody because its specification says it MUST NOT — a workload has
no root of trust until that call gives it one. What it lacks there is
ATTESTATION, not authentication.

**Both browser SSO profiles exist, and they are SEPARATE IMPLEMENTATIONS rather
than one with a version flag** — `/saml2` (all three bindings, Single Logout,
per-service-provider signed metadata, encryption since 2026-08-27) and `/saml11`
(both browser profiles, and a SOAP responder behind Browser/Artifact that is
also an attribute authority). SAML 1.1 has no request message, no Single Logout
and a different spelling for almost every shared element; **`saml/CLAUDE.md` has
the table of the six differences, and what each profile still does not do.** The
WS-Federation metadata publishes no IDPSSODescriptor, which is a fact about that
document rather than about this service: the IDPSSODescriptors are at
`/saml2/metadata` and `/saml11/metadata`.

are at `/saml2/metadata` and `/saml11/metadata`.

Extracted from the [OAuth2/OIDC Debugger](https://idptools.com). **The protocol
suite is still WRITTEN in that project and since 2026-08-28 a copy of it RUNS
here** — those are two different claims and keeping them apart is the whole of
the *Tests* section below.


## Running it

```bash
npm install
CONFIG_FILE=./env/local.js node server.js      # 8081; STS_PORT overrides
```

`CONFIG_FILE` selects a file in `env/`. At the default `debug` every endpoint
**THAT PORT IS HTTPS SINCE 2026-08-30, AND THE INVOCATION ABOVE IS UNCHANGED.**
The switch is in the appconfig files rather than in the setting — all three in
`env/` carry `global.https: true`, and both compose files set `STS_HTTPS` to the
same answer — so a service handed somebody else's appconfig file still gets
plain HTTP. `STS_HTTPS=false` is the way back and is a supported configuration.
**`env/CLAUDE.md` carries the argument and what it costs**; `tls/CLAUDE.md` says
what it takes away from `/tls/trust`, and `docs/configuration.md` is the
user-facing half.

**THAT FILE IS A LAYER, NOT THE WHOLE CONFIGURATION, AND A SETTING WITH NO VALUE
ANYWHERE STOPS THE SERVICE FROM STARTING.** There are five levels and no sixth —
`env/defaults.js`, the selected file over it, the environment over both, and the
runtime overrides the console and `/admin-api` set in memory. **`common/CLAUDE.md`
argues the layering and `env/CLAUDE.md` lists the files**; README.md's
*Configuration* lists every setting, its environment variable and its default.

The invocation above did not change when the modules moved, and that took one new
file to keep true: `common/config_file.js` makes `CONFIG_FILE` absolute before
anything reads it, because a relative path resolves against the directory of the
module doing the requiring and thirteen modules read it directly.

## Architecture, and the rules that hold it together

`server.js` is a shell: it requires the modules and listens. Nothing else lives at
the root except `sts_metadata.js`. What each directory holds is the table above;
what each module is for is that directory's `CLAUDE.md`.

1. **Requiring a module registers its endpoints.** Each calls `app.get(...)` at its
   top level against the shared app from `app.js`, rather than exporting a
   `register()`. So **the require order in `server.js` is the route order**, and the
   middleware has to live in `app.js`, because express applies middleware only to
   routes added after it.

2. **`vc_configs.js` and `vc_offers.js` exist to break require cycles, not to group
   code.** The credential configurations are read by both the issuer and the
   authorization server; the Credential Offer's pre-authorized codes are minted by
   the offer pages and redeemed at the token endpoint. A cycle in node does not fail
   loudly — it hands back a half-initialised module whose exports are `undefined`,
   and the symptom arrives later as something that is not a function.

3. **`dpop.js` is a library, not a protocol module.** It registers nothing, so its
   position in the require order does not matter, and it requires only `helpers.js`
   (plus npm leaves) so it cannot join a cycle. Keep it that way. It is also why
   `presentedAccessToken()` — the Bearer-or-DPoP check the four protected endpoints
   share — lives there rather than in `vc_issuer.js` where it was written: the
   fourth caller is in `oauth2.js`, which vc_issuer.js cannot be required from
   without building a cycle or moving OID4VCI ahead of OAuth2 in the route order.

3e. **`admin_stats.js` now has three inverted hooks and one require of a
   library, and they are four different problems rather than a pattern.**
   `helpers.js` offers `setJwtRecorder()` and this file fills it, because
   `helpers.js` cannot require the counter that `signJwt()` has to reach.
   `admin_stats.js` offers `setUserObserver()` and `ldap_server.js` fills it, so
   that seeding a directory entry cannot drag `/ldap`'s routes to the front of
   the router. `admin_stats.js` offers `setAttributeResolver()` and
   `claim_attributes.js` fills it, because `vc_claims.js` requires this file.
   `admin_stats.js` offers `setGroupResolver()` and `group_claims.js` fills it,
   because that module requires this file AND what it needs is the directory,
   which only `ldap_server.js` can answer. And `audit.js` is a plain require in
   the ordinary direction, because it requires nothing here. Each is justified
   by a specific thing that would otherwise break; **do not add a sixth by
   analogy** — a slot is what you reach for when a require would close a cycle
   or move a route, and it costs a reader an indirection every time. The group
   resolver is the one to check a new proposal against: it was added only after
   showing it failed that test BOTH ways round.

   **`admin.js`'s SIXTH slot is `setLogoutReader()`, filled by
   `logout/logout.js`, and it is the second one that passed that test both ways
   round.** That module requires `ldap/ldap_server.js` for the bound
   connections that ARE the LDAP session, and `ldap_server.js` requires
   `admin.js` — so a require in the obvious direction closes a cycle AND drags
   every `/ldap` route into the router ahead of the console's own. It carries
   ONE object, validated whole when it is installed, because a partial one
   would leave `/admin/logout` listing what is live and unable to end any of
   it. See `logout/CLAUDE.md` and `admin-ui/CLAUDE.md`.

   **`admin.js`'s SEVENTH SLOT IS `setCryptoReporter()`, filled by
   `admin-ui/crypto_metadata.js`, and it is the third to pass that test both
   ways round.** A require from `mgmt-api/admin_api.js` (19) to that module
   (20a) would MOVE ROUTES — its own page's, and `tls/tls_server.js`'s three,
   which it requires for the server certificate — ahead of the management
   API's own and of ldap, scim and spiffe; and a require from `admin.js` to it
   would CLOSE A CYCLE, because it requires `admin.js` for the shell. It
   carries ONE function, the whole report, so that the page and
   `/admin-api/crypto` cannot disagree about what this service's cryptography
   is.

   **`admin.js`'s EIGHTH SLOT IS `setSignalsReporter()`, FILLED BY
   `ssf/ssf.js`, AND IT IS THE FOURTH TO PASS THAT TEST BOTH WAYS ROUND.** A
   require from `admin.js` to that module would CLOSE A CYCLE — it requires
   `admin.js` for the page shell and the gate — and a require from
   `mgmt-api/admin_api.js` (19) to it would MOVE ROUTES: every `/ssf` endpoint
   and the `/.well-known/ssf-configuration` document ahead of the management
   API's own and of ldap, scim and spiffe. It carries ONE object, validated
   whole, because a filler that installed the reader without the action would
   leave `/admin/ssf` able to LIST streams and unable to change any of them.
   **Its `action` returns a PROMISE and it is the only slot here that does**:
   transmitting a Security Event Token signs a JWS — possibly on the worker
   pool — and then POSTs it to somebody else's endpoint, and answering before
   either had happened would be the page reporting "sent" about nothing.

   **`admin.js`'s NINTH SLOT IS `setDirectoryPages()`, FILLED BY
   `ldap/ldap_server.js`, AND IT IS THE FIFTH TO PASS THAT TEST BOTH WAYS
   ROUND.** On 2026-09-01 the five HTML pages that were `/ldap`,
   `/ldap/directory`, `/ldap/applications`, `/ldap/federations` and
   `/ldap/spiffe` became ADMIN CONSOLE PAGES under `/admin/ldap/` — drawn by
   that module still, in this console's shell through `admin.respond()`,
   exactly as `sts_metadata.js` draws `/admin/sts-metadata`. Rule 7 then owed
   each of them an operation on `/admin-api`, and this slot is how the
   management API reaches the five view functions: a require from `admin.js` to
   `ldap_server.js` would CLOSE A CYCLE (that module requires this one for the
   shell and the gate), and a require from `mgmt-api/admin_api.js` (19) to it
   would MOVE ROUTES, since it sits at 21 precisely so the management API's own
   routes are registered first. It carries FIVE functions and is validated
   whole, for `setLogoutReader()`'s reason: a filler that installed four would
   leave one operation answering "no directory is loaded" on a service whose
   directory plainly is. **What the move itself bought is a refusal**: a dump of
   every attribute of every entry prints `oauthClientSecret` and
   `fedClientSecret` in the clear, and those pages were the one surface here
   handing them to anybody who could reach the port. `/admin-api` is still
   ungated and mirrors all five, which is what a test drives.

   **`admin.js`'s ELEVENTH SLOT IS `setRolePreviewer()`, FILLED BY
   `xacml/xacml_role_pep.js`, AND IT IS THE SIXTH TO PASS THAT TEST BOTH WAYS
   ROUND.** `/admin/roles` answers "would alice be issued a token for this
   application" and the only thing that can answer it is the embedded PEP. A
   require from `admin.js` (18) to that module would load the XACML engine
   there and — much worse — fill `issuance_gate.js`'s DECIDER from the
   console, so a process that loaded the console and not `xacml/xacml.js`
   would gate every issuance in the service with half that family present. A
   require the other way would close a cycle, because `xacml_admin.js`
   requires `admin.js` for the page shell. It carries TWO functions, validated
   together for `setLogoutReader()`'s reason: a preview installed without the
   thing that says WHICH POLICY answered would be a page able to ask a
   question and unable to explain the answer.

   **THAT MODULE OFFERS A SLOT OF ITS OWN, `setProtocolFamilies()`, AND
   `sts_metadata.js` FILLS IT** — the only slot in this service that is not on
   `admin.js`. Same test, one direction: a `require('./sts_metadata')` from
   `crypto_metadata.js` would load at 20a the one module whose whole constraint
   is that it is required LAST. What crosses it is the protocol family list, so
   that "every identity service this mock advertises" means the same fourteen
   on both pages and a disagreement is REPORTED rather than reconciled.

   **`setUserObserver()` NOW CARRIES THREE KINDS OF EVENT AND IS STILL ONE
   SLOT**, which is the same rule read the other way: `ldap_server.js` is
   offered an `event` of `authentication`, `issuance` (an X509-SVID was minted
   for a SPIFFE identity) or `credential-status` (the SPIFFE registry ended or
   restored an identity's ability to obtain one). Two more slots would have been
   two more indirections for one cycle. **An absent `event` means an
   authentication**, so an older copy of either module behaves as it did. See
   `common/CLAUDE.md` and `spiffe/CLAUDE.md`.


---

---

## Trust realms: several logical copies of this service in one process

Since 2026-08-24 this service can run as more than one logical identity
service at once. A **trust realm** has its own configuration, its own signing
key, its own sessions, authorization codes, tokens, offers, artifacts,
statistics and audit log, answers on the SAME sockets as every other, and is
told apart by a segment at the front of the path:

```
http://host:8081/oauth2/token                the DEFAULT realm
http://host:8081/realm/acme/oauth2/token     the realm `acme`
```

`/admin/realms` defines them, `POST /admin-api/realms/create` does it without a
browser, and `GET /realms` is the ungated directory a client discovers them
from. The console carries a realm switcher on every page and shows ONE realm at
a time — including every settings form, which reads AND WRITES the realm it is
reached in.

**THE DEFAULT REALM HAS AN EMPTY PREFIX, AND A SERVICE WITH NO REALMS DEFINED
BEHAVES EXACTLY AS IT DID.** That is a property of one predicate in
`common/realms.js` rather than a claim spread over twenty files, and it is the
first thing to check if something here ever seems to have changed for a caller
that has never heard of realms.

**The whole design is argued in `common/CLAUDE.md`** and is not summarised here.
Six things reach outside that file, and this is the index of them — each line is
the rule, and the file named at the end of it is where the argument is:

1. **The realm is AMBIENT**, in an `AsyncLocalStorage` that `app.js`'s FIRST
   middleware enters. That middleware also strips the prefix before the router
   sees the URL, which is why no route registration in this service carries a
   realm and no protocol module was edited. **Nothing may be registered above
   it.** — `common/CLAUDE.md`
2. **A store becomes per realm at its DECLARATION and nowhere else**, and the
   test to check a converted store against is not "is it `realms.map()`" but
   **"is everything this thing is made of"** — the two halves of one claim set
   were held in two modules and only one of them was per realm.
   `tests/realm_isolation.js` is the guard. — `common/CLAUDE.md`
3. **THE EMBEDDED DIRECTORY IS PER REALM TOO** — a store of its own behind the
   one socket, `dc=<id>` beneath `ldap.baseDn`. The realm is in the DN because
   the socket has no path to put a segment in, and a subtree search is scoped to
   the realm its base names. — `ldap/CLAUDE.md`
4. **THE TWO ADMIN CONSOLE ROLES ARE THE ONE THING DELIBERATELY NOT SEPARATED.**
   They are groups in the DEFAULT realm's directory, read there from every
   realm, and the console's gate accepts that realm's session only — because a
   per-realm roster would mean anybody who can create a realm can make
   themselves an administrator of the service. — `admin-ui/CLAUDE.md`,
   `authn/CLAUDE.md`
5. **Kerberos, the two TLS listeners and SPIFFE's four sockets are still
   shared**, because a socket has no path to put a segment in and — unlike the
   directory — no name inside it to put one in either. `realmSupport()` is the
   index, and both `/admin/realms` and `GET /realms` render it. —
   `common/CLAUDE.md`
6. **A REALM MAY BE IN RFC 9700 MODE WHILE THE PROCESS IS NOT** — the
   `realmRuntime` marker, which has exactly one row and must not get a second by
   analogy. A realm binds no socket, so the reason `oauth2.rfc9700` is
   restart-only service-wide does not reach it; what a realm does NOT get is a
   scheme of its own. — `common/CLAUDE.md`, `oauth-oidc/CLAUDE.md`

## One listener process, N stateless workers

**This service is one node process and it owns six listener families** — the
express app, the KDC on TCP and UDP 88, the Kerberos service on 8888, the LDAP
directory, two gRPC surfaces and two HTTPS endpoints. Node runs all of them on
ONE THREAD, so a synchronous computation does not slow this service down, it
STOPS it.

Post-quantum signing is that computation, and until 2026-08-30 it ran on that
thread. Stalls measured on 2026-08-29 while the parent project's suite ran:

| Stall | Operation |
|---|---|
| 23.3s | a composite `verify()` |
| 17.8s | a composite `verify()` |
| 15.4s | `signJwtAs()` SLH-DSA-SHAKE-128s |
| 14.6s | `signJwtAs()` SLH-DSA-SHAKE-128s |

For those seconds this service answered nobody, and **a KDC that does not answer
looks from the outside exactly like a KDC that is not there** — which is why not
one of the failures they caused named one. They were a Kerberos reply that never
came, a Populate button never drawn, a login screen that never arrived, and a
refresh request whose socket this service closed on its way back out. The parent
project marked two of its jobs `EXCLUSIVE` to work around it (its issue #268)
and this is what that marking was interim to.

**The design is one front process and N stateless children.** This process keeps
every socket AND ALL THE STATE; a child is handed everything it needs in the job
and hands back everything it produced.

**Workers hold no state, and that is load-bearing rather than a
simplification.** The state here is read and written ACROSS sessions, not within
one: `operatorConfig`, `realms`, the KDC `replayCache`, `digestNonces` /
`hobaChallenges` / `hobaSeen`, `principals`, the SPIFFE registry, and the tokens
this service mints — minted on one worker and introspected from another. Split
N ways those fail SILENTLY: replay detection that stops detecting, a config
change that lands on one worker of four, an introspection 404 for a token that
exists. Session affinity narrows that window; it does not close it. So nothing
is split, and **two workers can never disagree about anything because neither
remembers anything.**

Five things are worth knowing before touching any of it.

**The five things to know before touching any of it are in `common/CLAUDE.md`**,
beside the two modules — the pool is lazy and nothing is forked until the first
post-quantum job; `workers.count = 0` is supported and produces the same bytes;
requiring `worker_pool.js` is what arms `pq_jose.js`; exactly four call paths
are asynchronous because of this and no others; and **a realm may not carry
`workers.count`**, which is the first setting marked `perProcess` and a SECOND
rule beside the `realms.*` prefix rather than the same one spelt twice. That
file also carries what the pool made affordable: a realm's eleven post-quantum
keys are now generated when the realm is, and the five-second federation
timeout that had been winning a race it was never allowed to run in.

`tests/worker_pool.js` has the four contracts and the measurement that shows the
loop is free.

---

## The require order in `server.js` IS the route order

Because of rule 1. Every constraint below is a DEPENDENCY, not a preference, and
each one's argument lives in the directory `CLAUDE.md` of the module that carries
it — this table says only what the constraint is, so that somebody adding a
require can see at a glance whether they are about to break one.

| # | Required | Constraint | Argument in |
|---|---|---|---|
| 1 | `common/config_file` | First of all. Every reader of `CONFIG_FILE` is below it. | `common/CLAUDE.md` |
| 2 | `common/app` | Before every protocol module — they register against it, and middleware only applies to routes added after it. Requiring it is also what installs the JWT recorder (rule 3e). | `common/CLAUDE.md` |
| 2a | `common/realms` | Loaded BY `app` and by `helpers`, so it has no line of its own in `server.js` — but it is above every setting read and every store in this service, because requiring it is what fills `config.js`'s realm slot (rule 3m) and what installs the reserved-id provider. | `common/CLAUDE.md` |
| 3–4 | `common/helpers`, `common/config` | `config.js` is below `helpers.js` and requires nothing here. | `common/CLAUDE.md` |
| 4a | `persistence/persistence` | Below `config`, which it reads, and above everything else: requiring it fills `config.js`'s override-store slot (rule 3q) and subscribes to `realms.onChange()`. A LIBRARY — it registers no route, so its place in the ROUTE order is not a place. **It opens nothing here**: the store is opened and READ from `persistence.start()` in `server.js`, before the listener binds, because a `require` cannot await a connection pool. | `persistence/CLAUDE.md` |
| 4b | `common/crypto` | Loaded BY `helpers`, so it has no line of its own in `server.js`. A LIBRARY — it registers no route, so its place in the ROUTE order is not a place. It is a LEAF and must stay one: it requires npm packages, `common/vendored/xmldsig.js` and `config`, which requires nothing here, so `helpers` may require it and it may NEVER require `helpers` back. Every function in it takes the key it is to use as a parameter for exactly that reason. | `common/CLAUDE.md` |
| 5 | `common/claim_attributes` | Ahead of everything that ISSUES, because requiring it fills `setAttributeResolver()`. An empty slot means tokens without their configured attributes. | `common/CLAUDE.md` |
| 6 | `common/group_claims` | Same reason, for `setGroupResolver()`. | `common/CLAUDE.md` |
| 6a | `home/home` | No constraint. Two EXACT paths (`/` and `/logo.png`) and nothing but the app behind them; first among the route modules so that the page a person meets first heads the list on `/admin/sts-metadata`. | `home/CLAUDE.md` |
| 7 | `ws-trust/wstrust` | No constraint. | `ws-trust/CLAUDE.md` |
| 8 | `authn/authn` | Before `oauth-oidc/oauth2` — it owns the session that module reads, and fills `audit.js`'s `setActorResolver()`. | `authn/CLAUDE.md` |
| 8b | `oauth-oidc/consent_screen` | **After `authn`** — it reads that module's session to check that the person answering is the person the question was asked of, and draws with its stylesheet. **And before `oauth2`**, which calls its `beginConsent()` and takes the browser back afterwards: exactly the arrangement `authn.js` already has with `beginAuthentication()`, one-way in the same way. It holds the pending records and nothing else; the REGISTER is `common/consent.js`. | `oauth-oidc/CLAUDE.md` |
| 9 | `oauth-oidc/oauth2` | Before `ws-federation/wsfed` and before `admin-ui/admin`. | `oauth-oidc/CLAUDE.md` |
| 10 | `ws-federation/wsfed` | **After `oauth2`** — rule 4. Single sign-on across the two protocols. |
| 10a | `saml/saml2_sso` | **After `authn`**, and a stronger dependency than WS-Federation's: it has NO sign-in screen of its own and reaches that service's through `beginAuthentication()`. No constraint against `wsfed` either way. | `saml/CLAUDE.md` | `ws-federation/CLAUDE.md` |
| 10b | `saml/saml11_sso` | **After `authn`** for the same reason as 10a, and **after `saml2_sso`** — it takes `slugOf()` from it, because one application must have one handle across both profiles. It needs no POST-to-GET hop: a SAML 1.1 flow arrives as a top-level GET. | `saml/CLAUDE.md` |
| 10c | `federation/federation_sp` | **After `authn`**, and stronger than 10a and 10b: it has no sign-in screen AND does not go through `beginAuthentication()` either — a federated sign-in calls `startSession()` directly, because the person authenticated somewhere else. No constraint against the four profiles above it in either direction; what joins the two halves is the SESSION. Only this module is required — the other three in that directory are libraries. | `federation/CLAUDE.md` |
| 11–14 | `oid4vc/*` | `vc_offers` before `vc_issuer`; both read `vc_configs`, which is why that module exists (rule 2). | `oid4vc/CLAUDE.md` |
| 15–16 | `kerberos/krb5_kdc`, `krb5_service` | Their listeners start from `listen()`, not here. | `kerberos/CLAUDE.md` |
| 17 | `kerberos/spnego` | **After `krb5_service`** — it calls that module's `accept()` and adds no check of its own. | `kerberos/CLAUDE.md` |
| 17a | `kerberos/spnego_authn` | **After `spnego` AND after `authn/authn`.** It draws with that module's page shell and negotiates through `spnego_exchange.js`; and it calls `authn.startSession()`, which is why the endpoint is HERE and not in `authn/` — a require the other way would drag the KDC's routes ahead of `oauth2.js` and close a cycle. It needs no slot: the two things `authn.js` must know are a path it declares itself and one setting they both read. | `kerberos/CLAUDE.md`, `authn/CLAUDE.md` |
| 18 | `admin-ui/admin` | **After `oauth2`** — rule 5. And before `ldap`, `scim` and `spiffe`, which is why it offers five slots rather than requiring them. | `admin-ui/CLAUDE.md` |
| 19 | `mgmt-api/admin_api` | **After `admin-ui/admin`** — rule 7. It calls that module's action functions and JSON views. | `mgmt-api/CLAUDE.md` |
| 20 | `tls/tls_server` | **Before `ldap/ldap_server`**, which serves its certificate and key on 636. | `tls/CLAUDE.md` |
| 20a | `admin-ui/crypto_metadata` | **After `tls/tls_server`, and that is the constraint that decides the line.** It reads an algorithm table out of eleven modules — `common/crypto`, `pq_jose`, the vendored `xmldsig`, `krb5_crypto`, `webauthn`, `oauth2`/`dpop`/`client_auth`/`mtls`, `spiffe_ca`, `scim_auth` and `tls_server` — and requiring one this file has not yet loaded would REGISTER ITS ROUTES HERE (rule 1). Here every one of them is a cache hit. Also after `admin-ui/admin` for the shell and the gate. Fills `admin.setCryptoReporter()`; `sts_metadata.js` fills ITS `setProtocolFamilies()`. | `admin-ui/CLAUDE.md` |
| 21 | `ldap/ldap_server` | **After `admin-ui/admin` and after `tls/tls_server`** — rule 6. Fills SEVEN slots at require time — the newest is `consent.setDirectory()` (2026-09-01), which carries the four functions that put a person's answer on their own entry and read it back — and registers the EIGHT `/admin/ldap/*` console pages it draws — five since 2026-09-01 and three more on 2026-09-05, when `ou=roles`, `ou=policies` and `ou=peps` each got the page its own module's schema comment had been claiming. | `ldap/CLAUDE.md` |
| 22 | `scim/scim` | **After `ldap/ldap_server`** — a plain require, and rule 3e's test is why. | `scim/CLAUDE.md` |
| 23 | `spiffe/spiffe_server` | **After `ldap/ldap_server` and `tls/tls_server`.** Its registry's store is the directory. | `spiffe/CLAUDE.md` |
| 23b | `ssf/ssf` | **After `admin-ui/admin`**, whose EIGHTH and NINTH slots it fills, and whose page shell and gate it requires — so a require the other way would close a cycle, and one from `mgmt-api/admin_api.js` would move every `/ssf` route and the well-known document ahead of the management API's own. Rule 3e's test answers yes both ways. It starts nothing and holds no socket. **Since 2026-09-03 it also fills `authn.setSessionObserver()`** — the CAEP profile, where a session starting, being presented or ending sends a Security Event Token with nobody having asked. That is an INVERTED HOOK for the same reason the admin slots are: `authn` is 8, so a require the other way would register every `/ssf` route there. | `ssf/CLAUDE.md`, `authn/CLAUDE.md` |
| 23c | `xacml/xacml` | **After `admin-ui/admin`**, whose TENTH and ELEVENTH slots `xacml_admin.js` and `xacml_role_pep.js` fill and whose page shell, settings block and action responder it requires — so a require the other way would close a cycle, and one from `mgmt-api/admin_api.js` would move every `/xacml` route and all five `/admin/xacml*` pages ahead of the management API's own. It requires `xacml_admin.js` ITSELF rather than `server.js` doing it, so this family has ONE line in the require order; that module requires this one back LAZILY, inside the one function that needs it. **And after `ldap/ldap_server` (21) in effect** — not as an ordering constraint, since both registers take their directory across a slot that module fills, but because a process that loaded this one and not that has an empty repository and answers NotApplicable to everything. Since 2026-09-05 it also requires `oauth-oidc/mtls` for the remote PEP's client certificate, which is a LIBRARY (rule 3) and registers nothing, so it cannot move a route or join a cycle. **AND IT REQUIRES `xacml_role_pep.js`, WHICH IS WHAT ARMS EVERY ISSUANCE SITE IN THE SERVICE**: that module fills `common/issuance_gate.js`'s decider at require time, so from this line onward the nine `gate.check()` calls reach the engine and before it — in `npm test`, in the parent project's in-process Kerberos jobs, in the remote PEP container — they answer "allowed". | `xacml/CLAUDE.md` |
| 23a | `logout/logout` | **Second to last.** It READS NINE MODULES — the session store, the token registry, the codes, the offers, the directory's connections, the principal database — so it must come after every one of them. Nine plain requires and no slot; the one exception is `admin.js`, which it fills. | `logout/CLAUDE.md` |
| 24 | `sts_metadata` | **Last, for everybody.** It reads the router to list what everything else registered. | this file, below |

### Where the numbered rules live now

The prose throughout this repository cites rules by number, and the numbering is
kept rather than renumbered — a renumber would silently invalidate every citation
in every file, including the ones in the source comments. This is the index.

| Rule | About | File |
|---|---|---|
| 1 | Requiring a module registers its endpoints | this file |
| 2 | `vc_configs.js` / `vc_offers.js` break require cycles | this file, `oid4vc/CLAUDE.md` |
| 3 | A library registers nothing (`dpop.js`) | this file |
| 3a, 3a-ii | `vc_claims.js`, `vc_verifier_config.js` | `oid4vc/CLAUDE.md` |
| 3b, 3c, 3d, 3d-ii | `admin_stats.js`, `audit.js`, `claim_attributes.js`, `group_claims.js` | `common/CLAUDE.md` |
| 3d-iii | `scim_map.js` | `scim/CLAUDE.md` |
| 3e | The inverted hooks, and the test for adding one | this file |
| 3f, 3h, 3i, 3j | `oauth2_bcp.js`, `mtls.js`, `client_auth.js`, `authorization_servers.js` | `oauth-oidc/CLAUDE.md` |
| 3g | `applications.js` | `common/CLAUDE.md` |
| 3r | `crypto.js`, why it is a leaf, why the verifier is told which element, and why XML encryption moved rather than being replaced | `common/CLAUDE.md` |
| 4a | `saml2_sso.js` after `authn.js`, and why it has no screen | `saml/CLAUDE.md` |
| 4b | `federation_sp.js` after `authn.js`, and why it needs no screen at all | `federation/CLAUDE.md` |
| 4b | `saml11_sso.js` after `authn.js` and after `saml2_sso.js`, and why the two profiles are separate implementations | `saml/CLAUDE.md` |
| 3l | `delegation.js`, and why it has no funnel | `common/CLAUDE.md` |
| 3s | `app_permissions.js`, why a CONFIGURED register is not the observed one with a flag on it, and why the ordering rule lives in `applications.js` | `common/CLAUDE.md` |
| 3t | `consent.js`, why an OVERRIDE is not a RECORD, and why the client_id is the last field of the value | `common/CLAUDE.md` |
| 4c | `consent_screen.js` after `authn.js` and before `oauth2.js`, and why the screen holds the records while the register holds none | `oauth-oidc/CLAUDE.md` |
| 3u | `roles.js`, the two relations it keeps apart (who HOLDS a role against what REQUIRES one), the six computed built-ins, and why it is a plain require rather than a fifth inverted hook | `common/CLAUDE.md` |
| 3v | `issuance_gate.js`, why an empty decider means ISSUE, and why the one case that must fail CLOSED lives in the PEP rather than here | `common/CLAUDE.md` |
| 3p | `user_graph.js`, and why the union of two registers is a library rather than a page | `common/CLAUDE.md` |
| 3o | `federation.js`, why four modules may require it, and why `PATHS` is not beside the routes | `federation/CLAUDE.md` |
| 3m | `realms.js`, the realm slot in `config.js`, and why the realm is ambient | `common/CLAUDE.md` |
| 3q | `persistence.js`, the override-store slot in `config.js`, the directory slot it offers, and why `realms.onChange()` is an event rather than a third slot | `persistence/CLAUDE.md` |
| 3m | `logout/logout.js` holds no state, and the reading order is not the ending order | `logout/CLAUDE.md` |
| 3n | `frontchannel_logout.js` | `oauth-oidc/CLAUDE.md` |
| 3k | SPIFFE's six modules | `spiffe/CLAUDE.md` |
| 4 | `wsfed.js` after `oauth2.js` | `ws-federation/CLAUDE.md` |
| 5 | `admin.js` after `oauth2.js` | `admin-ui/CLAUDE.md` |
| 6 | `ldap_server.js` after `admin.js` and `tls_server.js` | `ldap/CLAUDE.md` |
| 6a (SCIM), 6a-ii | `scim.js`, `scim_auth.js` | `scim/CLAUDE.md` |
| 6a (SPIFFE) | `spiffe_server.js` | `spiffe/CLAUDE.md` |
| 7, 7a | The console/API parity rule, the breadcrumb trail | `mgmt-api/CLAUDE.md`, `admin-ui/CLAUDE.md` |
| 8, 8a, 8b | The console's gate, its two roles, and the claim they qualify | `admin-ui/CLAUDE.md` |

Two rules share the number `6a` and always did — one for SCIM and one for
SPIFFE. They are now in different files, which is the first thing that has ever
made that collision harmless.

---

## Four modules start listeners from `listen()`, not at require time

The two Kerberos modules, `ldap_server.js` AND `tls_server.js` are the exception to
rule 1 in one direction only: requiring them registers their HTTP views
(`/KdcProxy`, `/krb5/principals`, the eight `/admin/ldap/*` pages, `/tls`) like everything
else, but their
**own listeners are started from `listen()` in `server.js`, not at require time** —
binding a port can fail, and a `require` that throws takes the whole service down
where a route cannot. A failure to bind is RECORDED rather than thrown, and both
`ldap_server.js` and `tls_server.js` publish it (`listening` / `listenError` on
`GET /admin/ldap/service` and `GET /tls`), because the HTTP view answers 200 either way and there
is otherwise no way to tell a running listener from one whose port was already taken
— by the host's own slapd, or by a second copy of this service.

The fourth is `spiffe/spiffe_server.js`, with four sockets of its own.
Each is reported SEPARATELY, because "389 is up and 636 is not" is the
ordinary outcome of a host run and one flag could only report one of them.

**THE FIFTH IS `persistence/persistence.js` AND IT BINDS NOTHING**, which is why
it is on this list rather than a list of its own: opening a connection pool is
ASYNCHRONOUS and a `require` cannot await, so the store is opened from
`persistence.start()`, which `server.js` calls BEFORE the HTTP listener binds and
before the four socket families above start. **It goes first among the five, and
a failure there is FATAL where the other four are recorded** — the two are
opposite because the states are, and `persistence/CLAUDE.md` argues both halves.
It is the only place in this repository where a failure to open something stops
the process.

## `frame-ancestors` is the one CSP clause a page may not drop

RFC 9700 section 4.14. `app.js` sets the policy on every response, and five routes
relax it to load a named script by SETTING THE WHOLE HEADER — so each of them could
lose the framing clause with nothing failing: the page works, the script runs, and
the protection is gone. **`frame-ancestors` has no fallback from `default-src`**,
which is why `default-src 'none'` alone is not enough and why this needs saying.

Two rules come out of it:

* **A relaxation goes through `app.contentSecurityPolicy(overrides)`**, which re-adds
  `frame-ancestors` and `base-uri` whatever the caller asked for. A caller cannot turn
  them off — that is deliberate, not an oversight in the API.
* **The policy is re-checked when the response is flushed.** Express's own 404 handler
  REPLACES the header with `default-src 'none'`, so every unrouted path was framable
  as far as CSP was concerned; nothing here could have shown it, because the header
  this service set was correct and something else overwrote it. The check is "does it
  still carry the clause", not "is it the value I set", so the five relaxations are
  untouched.

**Do not replace Express's 404 body.** `Cannot GET /path` is how
`tests/vendored/sts_metadata.js` tells an unrouted path from an endpoint legitimately answering
404. Fixing the header was the whole fix; a prettier 404 would break that test
silently.


## Six pages here have a script on them, and each is the same exception

`app.js` sets `script-src 'none'` for the whole service, and the reason is in its
own comment: it is what makes the family of reflected-content problems moot rather
than merely unlikely. Six pages need a script and each takes the SAME shape of
exception — `script-src 'self'` naming one resource, never `'unsafe-inline'`.

**Each of them carries a REAL SUBMIT BUTTON as well**, and that is not a
fallback nobody sees: with the script blocked the button is the whole mechanism,
so it is labelled for a person rather than hidden.

**The inventory is the cross-cutting part and the argument for each is made
where the page is**, which is why this is a table of pointers:

| Page | Script | Argued in |
|---|---|---|
| `/authn/webauthn` | `/authn/webauthn.js` | `authn/CLAUDE.md` |
| WS-Federation's sign-in response | `/wsfed/autopost.js` | `ws-federation/CLAUDE.md` |
| `response_mode=form_post` | `/oauth2/autopost.js` | `oauth-oidc/CLAUDE.md` |
| `/admin-api/docs` | the explorer | `mgmt-api/CLAUDE.md` |
| the SAML 2.0 HTTP POST binding | `/saml2/autopost.js` | `saml/CLAUDE.md` |
| the SAML 1.1 Browser/POST profile | `/saml11/autopost.js` | `saml/CLAUDE.md` |

**THE RULE THAT MATTERS IS THE ONE FOUR REFUSALS ESTABLISH, AND IT IS READ
BACKWARDS FROM THAT TABLE.** The test for a script is that the page CANNOT work
without one. Four candidates were refused on it: federation's outbound HTTP-POST
binding, which is a real form with a real button because that is a person
LEAVING this service (`federation/CLAUDE.md`); the delegation picture and the
federation picture, both laid out by `@dagrejs/dagre` on the SERVER and arriving
inline as ordinary markup, so `script-src 'none'` is untouched and `img-src` is
not even reached (`admin-ui/CLAUDE.md`); and the console's collapsible prose,
which is a `<details>` and needs no script at all.

**A NEW SCRIPTED PAGE NEEDS THE ARGUMENT MADE AGAIN FROM SCRATCH, AND "the same
as the page next door" IS NOT ONE.** That is what the second and third refusals
are for: the federation picture is the delegation picture in every respect a
reader would cite, and it got its own argument anyway — **the second refusal was
not cheaper than the first.** Likewise the SAML 1.1 autopost stands alone rather
than citing the SAML 2.0 one beside it: two specifications arrived at the
self-submitting form independently, and that page would be here if SAML 2.0 had
never been written. What the refusals cost is pan and zoom on the two pictures
and a collapse-all switch on the console, each said out loud on the page rather
than left to be wondered at.

---

## Adding an endpoint costs one entry in `sts_metadata.js`

`GET /admin/sts-metadata` reads the endpoint list **from the running Express router**, so
it cannot go stale — but it reports two kinds of drift and this repository's own
`tests/vendored/sts_metadata.js` fails on both: a route registered and undescribed, and a
description whose path is not registered (what a rename produces). See README.md.

It is a **console page** since 2026-08-24 (it was `/sts-metadata`), so it is
behind `admin.authRequired` and is drawn by `admin.js`'s `page()`: this module
builds the body and `admin.respond()` supplies the shell. Adding a PROTOCOL
family costs a card in that file's `PROTOCOLS` as well as the entry above —
the page reports an endpoint group no card claims, so leaving it out fails the
same test rather than going quietly.

**THERE IS A SECOND METADATA PAGE SINCE 2026-08-30 AND IT IS NOT A SUMMARY OF
THIS ONE.** `/admin/crypto-metadata` answers the question underneath the
endpoint list: when this service SIGNS, VERIFIES, ENCRYPTS or DECRYPTS
something, which digest, which algorithm, which cipher, which key, and which
envelope. It follows the same design — every algorithm table is read from the
**THERE IS A SECOND METADATA PAGE SINCE 2026-08-30 AND IT IS NOT A SUMMARY OF
THIS ONE.** `/admin/crypto-metadata` answers the question underneath the
endpoint list — when this service SIGNS, VERIFIES, ENCRYPTS or DECRYPTS
something, which digest, which algorithm, which cipher, which key, which
envelope — and it follows the same design: every algorithm table is read from
the module that performs the algorithm rather than written down. It checks its
family list against THIS page's `PROTOCOLS` in both directions, which is why
`sts_metadata.js` requires it and hands that list over.

**So adding a protocol family costs three things**: an entry in `ENDPOINTS`, a
card in `sts_metadata.js`'s `PROTOCOLS`, and a row in `crypto_metadata.js`'s
`FAMILIES`. `tests/vendored/sts_metadata.js` fails on the first two and
`tests/vendored/admin_api.js` on the third, so none of them goes quietly.
`admin-ui/CLAUDE.md` argues the second page; **`ssf/CLAUDE.md` carries the full
list of what adding the seventeenth family actually cost, which was nine files
rather than three** — it is the record of one family, where this is the rule.

**THOSE DRIFT CHECKS ARE ENFORCEMENT RATHER THAN DOCUMENTATION, AND THIS
PARAGRAPH SAID THE OPPOSITE UNTIL 2026-08-28.** It read "until they are here,
they are documentation rather than enforcement" — true while the only copy of
`sts_metadata.js` was in a checkout this repository could not count on. That
file is THIS repository's own now, it runs on every `./local-run-tests.sh`, and
a route registered and undescribed fails the suite here.

Reading the router has one blind spot: **a protocol that registers no route is
invisible to it**, which is exactly what the KDC's raw TCP/UDP 88 listeners are — and
the directory's two, plain 389 and LDAPS 636. Those
have to be described by hand or they go unlisted with nothing failing.

Coverage notes in that file **must start `full`, `partial` or `mock`** and say what is
missing. A list of fifty specifications that did not mention that this service
checks no passwords and validates no access tokens would be the most misleading thing
in the repository.


## Code style

* **No one-liner `try`/`catch`.** Braces and a body, always.
* **Every function longer than about ten lines opens with
  `log.debug("Entering fn().")` and returns through `log.debug("Leaving fn().")`.**
  Several `Leaving` lines in one body is correct, not a mistake — one per exit.
* **Every swallowed `catch` explains itself in a comment.** "Not JSON; the raw text
  is what gets shown" is a reason. An empty block is not.
* Comments carry the *reasoning*, especially where something went wrong once. The
  density in this codebase is deliberate; match it rather than trimming it.


## node-ldapjs is a SUBMODULE, it is nested, and it is not modified

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

## The signing key is regenerated on every start — IN DEVELOPMENT MODE

**THIS SECTION WAS UNCONDITIONAL UNTIL 2026-09-06 AND THE HEADING IS THE ONLY
PART THAT CHANGED.** Everything below is still exactly what a development-mode
service does, and development is the default. What is new is that `product` mode
generates the keys ONCE and reads them back from the persistence store — which
is why product mode REQUIRES a store — encrypted with AES-256-GCM under a key
this service never generates and never stores, read from a mounted file (the
default), AWS Secrets Manager, GCP Secret Manager, Azure Key Vault or HashiCorp
Vault. `common/keystore.js` and `common/secrets.js` are the two halves and
`common/CLAUDE.md` argues both; `persistence/CLAUDE.md` carries what it means
for the store.

**A service that cannot read its own signing key does not start.** It does not
generate a replacement and carry on: that would stop every token, assertion and
signed document it has ever issued from verifying, silently, at somebody else's
relying party.

Deliberate, and two things depend on it: the `kid` is derived from the key material
(`sts-mock-<thumbprint>`) so two instances cannot claim the same kid over different
keys, and every document that carries or describes the key is served
`Cache-Control: no-store`. If you add a document that publishes the key, it needs
that header too.



## Tests

**THE PROTOCOL SUITE IS WRITTEN IN THE PARENT PROJECT AND A COPY OF IT RUNS
HERE.** Those are two claims and keeping them apart is the whole of this
section; `tests/CLAUDE.md` carries everything else, including the eighteen-job
table, the three launchers, the coverage run and the rules that are not optional
there.

```bash
npm test                      # the in-process half alone: no port, no container, under 2s
./local-run-tests.sh          # ALL 44 jobs — the development loop
./docker-run-tests.sh         # the same 44, runner and service both in containers. What CI runs
./run-coverage.sh             # the same run with coverage collected
```

**Where a new test goes is decided by one question, and since 2026-08-28 by a
second one that comes before it.**

1. **Is the thing under test this service's own `/admin` console or its
   `/admin-api`?** If so it belongs HERE — in `tests/vendored/`, marked
   `local: true` — whatever the answer to the next question. That is an
   OWNERSHIP argument rather than a capability one: the tree that ADDS a control
   to that console is the tree that should go red when the control loses its
   operation. Ten jobs are here on it.
2. **Otherwise: can it be asserted by driving the running service over HTTP?**
   If yes it goes in `../id-proto-debugger/tests/`, where it costs one entry in
   `run-report.js` and runs in three stacks without anything being invented for
   it. Only if NO does it belong here — a test that needs to choose how the
   PROCESS was started, or that hands a document to an independent
   implementation in the same address space.

**Editing a vendored copy instead of the parent's original is the one thing this
arrangement cannot survive** — the copy is overwritten by the next
`--vendor-sync` and the fix never reaches the stack that gates that project. The
nine marked `local: true` are the exact inversion of that rule: they are edited
here and only here, and there is no copy over there to sync from.
`tests/vendored/MANIFEST.js` says which is which, and `--vendor-check` reports
drift in the others.

**What each surface still has NO test for is recorded in that surface's own
file**, not here — `scim/`, `spiffe/`, `oauth-oidc/` (the UserInfo claims
request), `ws-federation/`, `federation/` (the refusals, which is the surface
where the gap costs most, because it is the only one here whose bugs are
SECURITY bugs rather than fidelity bugs), `saml/` and `kerberos/`. Each of those
lists is almost entirely NEGATIVES, for the reason `tests/sts_dpop.js` gives: an
identity provider that hands a working relying party a signed assertion looks
finished and can be worth nothing.

## Things this service deliberately does not do

Worth knowing before "fixing" one of them. **This is an INDEX, not a summary** —
each line names the thing and points at the file that argues it, because an
argument in two places is an argument that will disagree with itself.

| It does not | Where the argument is |
|---|---|
| Enforce anything by default — `oauth2.rfc9700` is the one mode, off unless set | `oauth-oidc/CLAUDE.md` |
| Federate with anybody it was not CONFIGURED to federate with — the one place this service refuses by default, and the one refusal that is not a mode | `federation/CLAUDE.md` |
| Decrypt an assertion a federation partner encrypted, consume a federated SIGN-OUT, or re-check a federated person after the session exists | `federation/CLAUDE.md` |
| Dial any URL a CALLER supplied for this service to fetch something FROM — `jwks_uri` on an application entry and WS-Federation's `wreqptr` are still never followed, and that is the position both files argue. **THREE URLs are dialled and each is an address somebody is asking to be SENT something at**: a federation relationship's, which an administrator configured; an SSF receiver's push endpoint, which RFC 8935 defines as the receiver telling the transmitter where to post; and a registered XACML PEP's notify URL, which is the weakest of the three and pays for itself by carrying nothing — the PEP pulls and converges whether or not the nudge arrives | `federation/CLAUDE.md`, `ssf/CLAUDE.md`, `xacml/CLAUDE.md`, `oauth-oidc/CLAUDE.md` |
| ASK anybody's permission before it issues something — **this row is REVERSED since 2026-09-01 and is the one entry in this table that now reads the other way.** `/oauth2/consent` asks, and `oauth2.consentRequired` is ON by default, which no other policy here is. It is not a refusal and that is why: it is the screen every real authorization server draws on a first sign-in, and a client that has never met one has never run the code that survives it. It still checks nothing — the person has already been let in under any name they typed | `common/CLAUDE.md`, `oauth-oidc/CLAUDE.md` |
| Check any end user's password, in any protocol — **with one exception since 2026-08-26**: a Kerberos ticket presented at `/authn/spnego` is verified against a real long-term key before a session is minted, because Kerberos cannot be permissive the way everything else here is. The KDC behind it still is | `authn/CLAUDE.md`, `kerberos/CLAUDE.md` |
| Check any credential except a registered client's secret, in RFC 9700 mode only | `oauth-oidc/CLAUDE.md` |
| Refuse any LDAP bind — any DN, any password, anonymous, on 389 and 636 alike | `ldap/CLAUDE.md` |
| Check a Kerberos password, though it cannot not check the KEY | `kerberos/CLAUDE.md` |
| Verify an access token it did not issue, except at UserInfo | `oauth-oidc/CLAUDE.md` |
| Enforce `value` or `values` in an OIDC Core 5.5 claims request, or treat `essential` as an instruction — all three are carried, checked and reported, and section 5.5.1 says a server MUST NOT error for an unavailable claim | `oauth-oidc/CLAUDE.md` |
| Require DPoP — nonce mode makes proofs fresher, not mandatory | `oauth-oidc/CLAUDE.md` |
| ~~Turn a verified client certificate into a login~~ — **REVERSED 2026-09-05.** A request on a connection carrying a verified client certificate now starts a sign-on session for its common name. What has NOT changed is that no revocation is checked, and every report says so beside the session | `tls/CLAUDE.md` |
| Verify anything in an issued credential's values, which are invented | `oid4vc/CLAUDE.md` |
| Turn a verified presentation into a sign-on | `oid4vc/CLAUDE.md` |
| Deactivate anybody on SCIM `active: false` | `scim/CLAUDE.md` |
| Attest a workload or a node | `spiffe/CLAUDE.md` |
| Revoke a SPIFFE credential — the directory now records who may still be ISSUED one, which is a different claim | `spiffe/CLAUDE.md`, `ldap/CLAUDE.md` |
| Let a group grant anything — bar the TWO that grant the admin console and nothing else | `admin-ui/CLAUDE.md`, `common/CLAUDE.md` |
| Decide who may delegate to whom IN THE ACT, in two of the three families that can — the KDC polices S4U on every request; WS-Trust polices nothing. **RFC 8693 is no longer on this row unqualified**: since 2026-09-01 a DELEGATED PERMISSION may be configured between two OAuth application entries, and `oauth2.delegatedPermissionsEnforced` — off by default — refuses a request for one the client does not hold | `common/CLAUDE.md`, `kerberos/CLAUDE.md`, `oauth-oidc/CLAUDE.md` |
| Give a trust realm its own Kerberos KDC, TLS listeners or SPIFFE signing authority — those three socket families have no path to put a realm segment in and no name inside the protocol to put one in either. **The DIRECTORY is no longer on this list**: it is a subtree per realm since 2026-08-25, because a DN is a name a client can carry | `common/CLAUDE.md`, `ldap/CLAUDE.md` |
| Give a trust realm its own administrator — the two console roles are groups in the DEFAULT realm's directory, read there from every realm, and the console's gate accepts that realm's session only. Deliberate: a per-realm roster would let anybody who can create a realm administer the whole service | `common/CLAUDE.md`, `admin-ui/CLAUDE.md`, `ldap/CLAUDE.md` |
| Persist anything it MINTS — sessions, tokens, codes, artifacts, Kerberos tickets, the statistics, the audit log — in any mode, because the signing key is regenerated on every start and a token that outlived it would verify against nothing. **What it DOES persist since 2026-08-27, when a store is configured, is the three things somebody TYPED**: the embedded directory, the trust realm registry and the runtime appconfig overrides. This row said "persist anything at all" until that date | `persistence/CLAUDE.md`, `admin-ui/CLAUDE.md` |
| Dial its database in the clear — since 2026-08-30 the compose stack's PostgreSQL refuses a plaintext connection (`hostssl` on every rule) and the client asks for `sslmode=require`, so both ends say it. It does NOT authenticate that server: the certificate is generated in the container and signed by nobody, which `/admin/persistence` reports as two facts rather than one tick | `persistence/CLAUDE.md` |
| COORDINATE several processes through that store — two copies pointed at one database each hold their own directory in memory and never see each other's writes. Persistence is not clustering, and the store's own status says so | `persistence/CLAUDE.md` |
| Recall anything it has already ISSUED — a SAML assertion, a Kerberos service ticket, an X509-SVID. **Still true, and QUALIFIED since 2026-09-05: it now DISOWNS them.** A sign-out marks each revoked in this service's own record, which is a different claim from recalling one and must never be drawn as the same — the credential still verifies, still decrypts, still chains, because nothing consults this service when it is presented and nothing can be made to. What the mark buys is that a sign-out can say what it disowned, that CAEP can carry it to a receiver that subscribed, and that SAML Single Logout can carry it for an assertion from a browser profile. `revocationReach` on every row of the issued list is the field that keeps the two apart | `logout/CLAUDE.md`, `common/CLAUDE.md` |
| Perform back-channel logout. Front-channel IS implemented; the metadata says which | `oauth-oidc/CLAUDE.md` |
| Fake WS-Federation's `wauth`, or dereference `wreqptr` | `ws-federation/CLAUDE.md` |
| Verify a SAML AuthnRequest's signature, or consume SP metadata — both recorded, neither checked | `saml/CLAUDE.md` |
| Encrypt an assertion **to a service provider it holds no certificate for** — it sends it in CLEAR and says so loudly, rather than refusing to issue. Encryption itself arrived 2026-08-27 and this row said the opposite until then | `saml/CLAUDE.md` |
| Dial a service provider's metadata URL WHILE ISSUING — the fetch is an explicit action that writes the certificate onto the entry, so no sign-in waits on somebody else's web server | `saml/CLAUDE.md` |

FOUR exceptions to the whole of that list, and each is worth knowing before
reading further. **The SCIM endpoints REQUIRE a credential** — in any of the six
schemes RFC 7644 section 2 names, with the OAuth ones needing `scim:read` or
`scim:write` — because they create and DELETE accounts. **The SPIRE Server
API requires an X509-SVID over mutual TLS** and authorizes every method against
SPIRE's own per-method table, because what comes out of that surface is a
credential another service will believe. And **the ADMIN CONSOLE at `/admin`
requires a sign-on session and one of two roles**, because it is the one surface
that can change what every protocol endpoint does. All three are a turnstile
rather than a lock, and each can be turned off (`scim.authRequired`,
`spiffe.authRequired`, `admin.authRequired`).

**A FOURTH IS NOT A TURNSTILE AND IS NOT GUARDING ANYTHING**: `/authn/spnego`,
where a KERBEROS TICKET is verified against a real long-term key before a
session is minted. It is on this list only because Kerberos cannot be permissive
the way the rest of this service is — the password there IS the key — so the
mock's permissiveness had to move into the KDC's ACCOUNT POLICY (one shared
password, an account for any name) and leave the verification real. The row
above about not checking passwords holds everywhere else, and the reason it
cannot hold here is `kerberos/CLAUDE.md`'s. `krb5.spnegoAuthentication` turns
that door off.

The console's is the newest and the one with the most surprising edges, all of
which are argued in `admin-ui/CLAUDE.md`: the two roles are ORDINARY DIRECTORY
GROUPS rather than a store of the console's own, so four doors write one
membership; **`/admin-api` is deliberately NOT gated**, which is what a test
drives and what somebody locked out reaches for — and also means anybody who can
reach this port can grant themselves both roles; and while NEITHER role group has
a member, anybody who signs in holds both, because this service has no password
anywhere to bootstrap an administrator with.

**The Workload API is the opposite case and the distinction matters**: it
authenticates nobody because its specification says it MUST NOT — a workload has
no root of trust until that call gives it one. What it lacks there is
ATTESTATION, not authentication.

## The parent project's paths into this repository are RIGHT, and what keeps them so

**This section said they were wrong until 2026-08-28, and the migration it
described has happened.** `../id-proto-debugger` reaches in here by path in three
places — `tests/Dockerfile`'s `COPY sts/…` block, `tests/module_paths.js`'s
`mockStsModule()`, and the two byte-compare tests — and the 2026-08-23
reorganisation broke all three. All three are fixed over there, and the `sts/`
gitlink has moved on twice since — it is at `c3b4294` on `feature/201` as of
2026-08-29, rather than the pre-reorganisation `cae2066` this file named for
five days.

One of the three came out differently from what was prescribed, and that is the
part worth knowing here: **`mockStsModule()` SEARCHES the subdirectories rather
than being handed one**, so its four Kerberos callers still pass BARE filenames
and are correct. Do not "fix" them.

What is left is not a migration but a standing obligation, and it is the one
thing about that project this file carries: **the `sts/` COPY set in
`tests/Dockerfile` is the transitive closure of what `krb5_kdc.js`,
`krb5_service.js` and `spnego.js` require, and it moves on THIS repository's
schedule.** Add a require reachable from any of those three and that project
needs a COPY line, in the commit that bumps the pin across the change — miss it
and four in-process Kerberos jobs die at load with `Cannot find module`, which
names a file nobody edited. The closure is in `docs/parent-project-migration.md`.

**THAT DOCUMENT'S ONE OUTSTANDING ITEM WAS PAID ON 2026-08-28 AND THE OBLIGATION
IS NOT.** `common/pq_jose.js` was the file the next bump owed, and the parent
committed `COPY sts/common/pq_jose.js ./sts/common/` in the same change that
moved the pin to `c3b4294` — which carries that file — so the two landed
together exactly as that document says they must. Walking the closure against
the current pin today finds all thirty files copied and nothing missing. The
obligation stands for the NEXT require added under those three entry points; it
is the walk that is standing, not any particular file.
