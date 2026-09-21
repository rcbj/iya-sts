const path = require('path');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'MANIFEST',
  level: process.env.LOG_LEVEL || 'info' });

// ===========================================================================
// MANIFEST.js — what is vendored here, where each file came from, and which of
// them are JOBS rather than the helpers the jobs share.
//
// ---------------------------------------------------------------------------
// WHY THERE IS A LIST HERE AT ALL, WHEN THE REST OF tests/ HAS NONE.
//
// `run.js` discovers a test as *any .js file in tests/ that is not itself or
// harness.js*, and `tests/CLAUDE.md` argues that at length: the standing
// objection to a second suite is that it is a second place to forget, so the
// in-process suite has no such place. Nothing about that changes here, because
// the files in THIS directory are not this repository's to discover. They are
// COPIES, and a copy needs two things a discovered file does not:
//
//   1. AN ORIGIN, so drift can be detected. `tools/vendor-check.js` byte-
//      compares every entry below against the parent checkout when there is
//      one beside this repository. Without a list there is nothing to compare.
//   2. A JOB/HELPER SPLIT, because it cannot be derived from the content any
//      more. The rule the runner used while these files lived over there was
//      "does it mention WSTRUST_STS_URL or OID4VCI_ISSUER_URL" — and
//      `sts_applications.js` mentions both and is a HELPER, while
//      `sts_saml_encryption.js` is a job that declares no `--url` option and
//      would be missed by a guard looking for one. Two misclassifications in
//      nineteen files is a derivation that does not work, and a wrong answer
//      here is a job that silently never runs, which is the exact failure this
//      whole directory was created to stop.
//
// So the list is the price of vendoring, and it buys the drift check. It is
// NOT a precedent for listing anything else in tests/.
//
// ---------------------------------------------------------------------------
// THESE FILES ARE NOT EDITED HERE, AND THAT IS THE SAME RULE `common/vendored/`
// CARRIES.
//
// The parent project's `tests/` is the source of truth: those jobs are
// developed against that suite's own conventions, run in its containerized
// stack and its host stack, and are what its CI drives. A fix made HERE would
// be overwritten by the next sync and would never reach the stack that
// actually gates that project. **Edit the parent's copy, then re-sync** —
// `node tests/tools/vendor-check.js --sync` does the copy and
// `node tests/tools/vendor-check.js` reports what differs.
//
// THE EXCEPTION IS EVERY JOB MARKED `local: true` BELOW — most of them drive
// this service's own `/admin` console and `/admin-api`, and the note above
// JOBS says why each of the others is local. Those are NOT copies of anything:
// the parent deleted the first of them on 2026-08-28, and they are edited here
// and only here. The rule above applies to every other file in this directory.
//
// What vendoring buys is that this repository's suite RUNS with no parent
// checkout beside it. Before 2026-08-28 a machine with only this repository on
// it ran ten in-process files and reported the other thirteen jobs as absent;
// since then it runs every job it has. The drift check is the part that needs
// both checkouts, and it is therefore a TOOL rather than a job — see
// `tools/vendor-check.js` for why that distinction is deliberate.
// ===========================================================================

// ---------------------------------------------------------------------------
// TWO SOURCE DIRECTORIES, AND THE SECOND ONE IS THE SURPRISE.
//
// `tests/` is the obvious half: the jobs and the helpers they share.
//
// `client/src/` is the DEBUGGER'S OWN WALLET AND CRYPTO CODE, and several of
// the copied jobs load it deliberately. That is not an accident of layout — it
// is the POINT of those tests. `vc_did.js` checks that a credential this
// service issued verifies under the wallet's DID resolver;
// `sts_jws_verification.js` checks a signature against the debugger's PQC
// engine; `sts_userinfo_protected.js` opens an encrypted UserInfo response
// with the debugger's JWE engine. Each is the same argument `tests/CLAUDE.md`
// makes for keeping `xml-crypto` in package.json while no module requires it:
// an INDEPENDENT implementation is what makes "our signature verifies" mean
// something, and a test where both ends came from one implementation passes on
// a shared misunderstanding and interoperates with nobody.
//
// So those modules are vendored too, FLAT — `did.js` beside the job that reads
// it — which needs no edit to any vendored file, because `module_paths.js`
// already looks for exactly that layout as its second candidate. It is what
// the parent's own tests image does.
// ---------------------------------------------------------------------------
const SOURCE_DIR = 'tests';
const CLIENT_SOURCE_DIR = path.join('client', 'src');

// ---------------------------------------------------------------------------
// THE JOBS. Each is spawned as its own process by `tools/run-report.js`, with
// this directory as its cwd — which is what makes `CONFIG_FILE=./env/local.js`
// resolve, and what makes each job's `require('./random_username.js')` find the
// copy beside it rather than one over there.
//
// `browser: true` means the job drives Chrome through selenium-webdriver. There
// are TWO, and both are console coverage against this working tree, which is
// why `--no-browser` names them when it leaves them out.
// `sts_admin_console.js` walks every page; `sts_xacml_editor.js` drives ONE
// page in depth — the guided policy editor, whose forty forms per render, whose
// menus and whose nested-form hazard are markup rather than behaviour, and are
// therefore invisible to the in-process suite that already holds its grammar.
// They are not redundant: the first would notice the editor page failing to
// draw, and nothing but the second notices it drawing a menu against the wrong
// row's path.
//
// ---------------------------------------------------------------------------
// `docker: true` MEANS THE JOB NEEDS A REMOTE PEP CONTAINER, AND IT IS A
// FALLBACK FLAG RATHER THAN A REQUIREMENT. There is ONE such job,
// `sts_xacml_remote_pep.js`, and the ordinary way it gets its container is that
// the LAUNCHER brought one up:
//
//   * `./local-run-tests.sh` added `--profile xacml` to the project it already
//     started the service in and published the PEP on a free host port, until
//     it was removed on 2026-09-16;
//   * `./run-tests.sh` declares an `xacml-pep` service in
//     `docker-compose-run-tests.yml`, on the bridge the tests container shares
//     with the service.
//
// Each exports (or exported) `XACML_PEP_URL`, `XACML_PEP_NAME` and
// `XACML_PEP_REALM`, and the job drives that container over HTTP and shells
// out to nothing. **THAT IS WHY THE LAUNCHER OWNS IT**: the containerized
// runner is a container with no docker in it, deliberately, so a job that
// started its own could never run in the stack that gates this repository.
//
// The flag matters only when NEITHER launcher is involved — a bare
// `node tests/tools/run-report.js`, or a coverage run, both of which drive a
// service that is a plain process with no compose network to join. There the
// job builds the image and starts a container itself, which needs a daemon; and
// where there is none, `tools/run-report.js` reports the job SKIPPED with the
// reason — amber in the report, `<skipped>` in the JUnit, a line in the summary
// — instead of failing it or, worse, going green.
//
// **THAT SKIP IS A DELIBERATE EXCLUSION AND NOT A CAPABILITY TEST DODGED**,
// which is the distinction `tests/CLAUDE.md` draws between a skip and a
// failure, and it is now a narrow one: it is reachable only by driving a
// service nobody's launcher started, on a machine with no docker.
// ---------------------------------------------------------------------------
//
// `local: true` means THIS REPOSITORY OWNS THE FILE and there is no copy of it
// over there to compare against. THE LIST BELOW IS THE AUTHORITY ON HOW MANY
// THERE ARE — this paragraph used to open by counting them and the count went
// stale twice, which is exactly the drift a manifest exists to stop — and the
// list of names that replaced the count went stale the same way, so the entries
// below, with the comment above each later one, are the list. Most of them
// drive this service's OWN `/admin` console and its `/admin-api`; the first
// were `sts_metadata.js`, `admin_api.js`, `sts_admin_api_operations.js`,
// `sts_admin_console.js`, `sts_delegated_permissions_example.js`,
// `sts_consent.js`, `sts_global_logout.js`, `sts_portal_sessions.js`,
// `sts_portal_totp.js`, `sts_second_factor_pages.js`,
// `sts_webauthn_second_factor.js`, `sts_portal_backup_keys.js`,
// `sts_roles.js`, `sts_roles_builtin.js`, `sts_route_inputs.js`,
// `sts_metadata_anonymous.js`,
// `sts_xacml_endpoints.js`, `sts_xacml_editor.js` and
// `sts_xacml_remote_pep.js`. **TWO OF THOSE ARE HERE ON A DIFFERENT ARGUMENT
// AND DRIVE NO CONSOLE AT ALL**: `sts_route_inputs.js` and
// `sts_metadata_anonymous.js` READ THIS WORKING TREE — one discovers the route
// list it probes, the other checks its coverage against `sts_metadata.js`'s
// own PROTOCOLS table — so a copy over there would read the pinned `sts/`
// gitlink and check a service that is not the one running. Each argues it in
// its own header. The rest are the console jobs — the later ones of which are
// covered by the argument below for the same reason: one builds an example
// THROUGH `/admin-api` for somebody to read on `/admin`, and another grants a
// GLOBAL CONSENT through `/admin-api/consent` and then watches a sign-in stop
// being asked, which is a console control with a protocol consequence and could
// not be asserted at all from a repository holding only one half of it. THE
// THREE XACML JOBS ARE HERE FOR THAT SAME REASON AND IT IS THE STRONGEST CASE
// OF ALL: a PDP with an empty repository answers NotApplicable to everything,
// so there is no question worth asking `/xacml/pdp` until a policy exists, and
// the only way to put one there over HTTP is `/admin-api/xacml`. Every
// assertion in any of the three therefore spans a console door and a protocol
// door — a template built on `/admin-api` deciding at `/xacml/pdp`, a policy
// disabled on the console disappearing from what a remote PEP pulls, a rule
// built by pressing buttons on `/admin/xacml/editor` changing what
// `/xacml/protected` allows — and a test with the two halves in two
// repositories could not make one of them. **`sts_xacml_remote_pep.js` IS THE
// THIRD AND IS ALSO THE ONLY JOB HERE THAT STARTS A SECOND PROCESS OF ITS
// OWN**: it runs `xacml-pep/pep.js` — the real container's program, not a
// stand-in — registers it, deploys policy through `/admin-api/xacml` and
// asserts that what that separate process ALLOWS changes with it. So it answers
// YES to the console question above AND NO to CLAUDE.md's second one ("can it
// be asserted by driving the running service over HTTP?"), which is the case
// reserved for this repository, and both answers put it here.
// Read the paragraph below as though it said all of them: they build
// something THROUGH `/admin-api` for somebody to read on `/admin`, so the tree
// that changes those doors is the tree that should go red when it stops
// working. They ran from the parent project's `tests/` until
// 2026-08-28 and were removed there on that date, on the argument that a test
// asserting something about this console belongs in the tree where a control
// is added to that console — the tree that should go red when the control
// loses its operation. They still SIT here rather than in `tests/` because
// nothing about how they run changed: they are spawned as processes by
// `tools/run-report.js` with this directory as their cwd, and they
// `require('./random_username.js')` and the rest out of it. `run.js` discovers
// `tests/*.js` and runs it IN PROCESS against harness.js, which is a different
// kind of file entirely.
//
// What `local` buys is that `tools/vendor-check.js` does not compare them:
// `allFiles()` leaves them out, so a parent checkout beside this one reports
// clean instead of a screenful of GONE UPSTREAM, and `--vendor-sync` cannot
// overwrite them. THE EDITING RULE IS THEREFORE INVERTED FOR EVERY `local`
// JOB — they are changed HERE, and only here.
// ---------------------------------------------------------------------------
const JOBS = [
  // FIRST, AND ABOUT THE STACK RATHER THAN THE SERVICE (2026-09-14, #46): that
  // the `cluster` mode's jobs really reach both nodes — both kinds of client,
  // round robin through the load balancer — and that every other mode's reach
  // one. A mode that is not what it says would otherwise be reported green by
  // every job after it. Its header argues why it is local and why it is first.
  { file: 'sts_cluster_alternation.js',  browser: false, local: true },
  { file: 'admin_api.js',                browser: false, local: true },
  { file: 'ldp_vc_issuance.js',          browser: false },
  { file: 'ldp_vc_refresh.js',           browser: false },
  { file: 'oauth2_sts_endpoints.js',     browser: false },
  // THE GATE IN FRONT OF THAT API, as opposed to what is behind it
  // (2026-09-09). `sts_admin_api_operations.js` walks every documented
  // operation; this one asserts that none of them can be reached
  // without an access token audienced to this API and carrying the
  // scope the action needs. Two jobs because they fail for different
  // reasons: one goes red when an operation drifts from its document,
  // the other when the surface stops refusing.
  { file: 'sts_admin_api_auth.js',       browser: false, local: true },
  { file: 'sts_admin_api_operations.js', browser: false, local: true },
  // AN HOUR (2026-09-19): it walks every console page in a real browser, and
  // against a three-node cluster across the internet (run-suite.sh testidp)
  // that took longer than the 20-minute default, killed while still passing.
  { file: 'sts_admin_console.js',        browser: true,  local: true,
    timeoutMs: 3600000 },
  // A TRUST REALM'S OWN ADMINISTRATORS (2026-09-14, #32): the realm chooser,
  // a realm administrator confined to their realm in the console and through
  // a realm's own management API token, and the service administrator over
  // every realm. Its two realms are left standing; it touches the default
  // realm's roster only when that realm's bootstrap window is closed, and
  // then revokes what it granted.
  { file: 'sts_realm_administrators.js', browser: false, local: true },
  { file: 'sts_consent.js',              browser: false, local: true },
  { file: 'sts_delegated_permissions_example.js', browser: false, local: true },
  { file: 'sts_dpop.js',                 browser: false },
  // GNAP (2026-09-12). `local: true` on the second of tests/CLAUDE.md's
  // reasons: GNAP exists in this repository and nowhere else, so there is no
  // copy anywhere to sync from. Three jobs because there are three parties —
  // the client instance (core), the resource server (rs, RFC 9767) and a
  // Shared Signals receiver (signals) — and each asserts through its own door.
  // All three drive `gnap_client.js`, a client written from the RFCs with no
  // code from `gnap/`, and each runs in a throwaway realm it leaves behind.
  { file: 'sts_gnap_core.js',            browser: false, local: true },
  { file: 'sts_gnap_rs.js',              browser: false, local: true },
  { file: 'sts_gnap_signals.js',         browser: false, local: true },
  // CERTIFICATE ENROLLMENT (2026-09-13): ACME, EST and SCEP, each driven by an
  // independent client written from its RFC with no code from acme/, est/ or
  // scep/, each in a throwaway realm it leaves behind.
  // ===== ACME jobs =====
  { file: 'sts_acme_enrollment.js',      browser: false, local: true },
  // ===== EST jobs =====
  { file: 'sts_est_enrollment.js',       browser: false, local: true },
  // ===== SCEP jobs =====
  // It waits out a sixty-second challenge lifetime for the expiry case, which
  // is why the watchdog is raised.
  { file: 'sts_scep_enrollment.js',      browser: false, local: true,
    timeoutMs: 600000 },
  // The portal's /portal/certificates page: a person's own enrollment
  // credentials and certificates, driven with two signed-in browsers.
  { file: 'sts_portal_certificates.js',  browser: false, local: true },
  // ssfAllowedEvents (2026-09-12): an application entry limiting which Shared
  // Signals event types a stream it owns is sent. `local: true` because the
  // attribute is this repository's own and the assertion spans an /admin-api
  // write and a protocol delivery.
  { file: 'sts_ssf_allowed_events.js',   browser: false, local: true },
  // THE CONSOLE AND THE PORTAL RENEW THEIR TOKENS INSIDE THE SAME SESSION
  // (2026-09-12). Both surfaces are this repository's own, and section 5 waits
  // out a sixty-second sign-on session, which is why the watchdog is raised.
  { file: 'sts_hosted_surface_renewal.js', browser: false, local: true,
    timeoutMs: 420000 },
  { file: 'sts_jws_verification.js',     browser: false },
  { file: 'sts_route_inputs.js',         browser: false, local: true },
  { file: 'sts_global_logout.js',        browser: false, local: true },
  { file: 'sts_metadata.js',             browser: false, local: true },
  // THE DOCUMENTS THEMSELVES, as opposed to the index that lists them
  // (2026-09-10). `sts_metadata.js` drives /admin/sts-metadata and signs
  // into the console to do it; this one holds every metadata document the
  // protocol families publish — nineteen of them — and holds NOTHING ELSE:
  // no cookie, no Authorization header, no certificate. Two jobs because
  // they fail for opposite reasons: one goes red when the index and the
  // router disagree, the other when a document a client must read before it
  // can authenticate stops answering somebody who cannot yet authenticate.
  // It is `local: true` on sts_route_inputs.js's argument — its coverage
  // check reads this working tree's own PROTOCOLS table.
  { file: 'sts_metadata_anonymous.js',   browser: false, local: true },
  { file: 'sts_portal_sessions.js',      browser: false, local: true },
  { file: 'sts_portal_backup_codes.js',  browser: false, local: true },
  { file: 'sts_portal_directory_attributes.js', browser: false, local: true },
  // RFC 6238, over HTTP. `local: true` on sts_portal_sessions.js's argument —
  // it drives this service's own /portal, /admin and /admin-api. It is NOT
  // covered by tests/totp.js beside it and the split is worth knowing: that
  // file checks the ARITHMETIC against both RFCs' published vectors and sends
  // no request, and this one computes a code with an implementation of its own
  // and asserts that the DOORS are wired up. Neither implies the other.
  { file: 'sts_portal_totp.js',          browser: false, local: true },
  // THE PERSON'S OWN RFC 7523 SIGNING KEY (2026-09-12). `local: true` on the
  // job above's argument: it drives this repository's own /portal and
  // /admin-api. It is the SEAM between four modules that are each asserted
  // apart in process — the page renders and writes, common/pki.js issues,
  // common/person_assertions.js seals and resolves, and
  // oauth-oidc/assertion_grant.js verifies — and the one claim none of them
  // can make alone: the PEM this page shows once obtains a token as its holder
  // and obtains nothing as anybody else.
  { file: 'sts_portal_signing_key.js',   browser: false, local: true },
  // THE SECRET STORE (2026-09-12). `local: true`: it drives this repository's
  // own /admin-api. It asserts the half `openbao/seed.js` cannot — that the
  // RUNNING SERVICE took the path the store was built for.
  //
  // **IT HAS TWO GATES AND THE FIRST VERSION HAD ONE**, which cost two of the
  // three modes. The DATABASE PASSWORD comes out of the store in EVERY mode,
  // because the compose file's connection string carries none at all; the
  // KEY-ENCRYPTION KEY is only read where the keystore is ON. Gating the whole
  // file on "is anything coming from vault" therefore ran the key half in
  // `memory` and `postgres` and failed with `no key was read at all` about a
  // service behaving exactly as those modes define. It skips whole against a
  // service with no stack behind it, and runs the database half alone where
  // the keystore is off — saying which it is doing either way.
  { file: 'sts_secret_store.js',         browser: false, local: true },
  // RFC 7521 / RFC 7523 (2026-09-10). `local: true` on the THIRD argument
  // `tests/CLAUDE.md` gives and at its plainest: every assertion spans an
  // AUTHORING door and a PROTOCOL door. A signing key pair does not exist
  // until `/admin-api/pki` issues one and an assertion issuer is not trusted
  // until `oauthAssertionIssuer` is written through
  // `/admin-api/applications` — so there is no question worth asking
  // `/oauth2/token` until both have been used, which is the shape
  // `sts_xacml_endpoints.js` has with a repository that starts empty.
  //
  // It is NOT covered by `tests/pki.js` or `tests/assertion_grant.js` beside
  // it, and the split is the usual one: those two assert what the MODULES
  // decide — the path check, the ninety-six encryption combinations, the
  // twelve claims that may never reach a token — and send no request, so
  // neither can see a grant that is registered and unreachable or a key pair
  // written to the wrong six attributes.
  // SECTION 13 SINCE 2026-09-11 IS A PERSON AS THE ISSUER, and it is in this
  // job rather than one of its own because it is the same grant at the same
  // endpoint with one field different on the issue — a second job would be a
  // second place to keep the realm, the CA and the signer in step.
  { file: 'sts_jwt_bearer_grant.js',     browser: false, local: true },
  // RFC 7521 / RFC 7522 (2026-09-11), the SAML 2.0 profile of the same
  // framework. `local: true` on the job above's argument word for word — the
  // key pair comes from `/admin-api/pki` and the trust decision from
  // `/admin-api/applications`, so there is no question worth asking
  // `/oauth2/token` until both of this repository's own doors have been used.
  //
  // AFTER `sts_jwt_bearer_grant.js` on purpose, and it is the ONE ordering
  // here that is about an assertion rather than about state: section 6 of this
  // job presents each profile's key pair at the OTHER profile's grant, which
  // is the claim the whole feature rests on. Reading the JWT job's result
  // first is what tells a reader of the report that the RFC 7523 half was
  // already green when the crossing was refused.
  //
  // It is NOT covered by `tests/saml_assertion_grant.js` beside it, on the
  // usual split: that file asserts what the MODULE decides — the eleven items
  // of section 3 as a table, the two attribute sets read out of the source —
  // and sends no request, so it cannot see a grant that is registered and
  // unreachable, a metadata member that promises what the endpoint refuses, or
  // a console control that issues for the wrong profile.
  { file: 'sts_saml2_bearer_grant.js',   browser: false, local: true },
  // THE CRL AND OCSP ENDPOINTS, AND THE REVOCATION PANE (2026-09-11).
  // `local: true` on the FIRST of `tests/CLAUDE.md`'s two questions: most of
  // what it drives is `/admin-api/pki` and a pane on `/admin/pki`, and the
  // tree that adds a control to that console is the tree that should go red
  // when the control loses its operation.
  //
  // AFTER the two assertion-grant jobs on purpose, and it is an ordering about
  // STATE: both of those issue key pairs from this hierarchy, so by the time
  // this job runs each authority has leaves to revoke. Running first would
  // leave it asserting against whatever the startup happened to certify, which
  // is fewer certificates and a narrower test for no reason.
  //
  // It is NOT covered by `tests/pki_revocation.js` beside it, on the usual
  // split — that file holds the REGISTER and the two documents, in process,
  // with an OpenSSL-built request and an OpenSSL verification of the CRL, and
  // sends no request. Four things only a socket can show: that the four
  // endpoints answer with NO CREDENTIAL while the console page stays gated
  // (a revocation list behind an admin gate is a revocation nobody acts on,
  // and that is one line of middleware away from being true); that the media
  // types are what a revocation client dispatches on; that the DER survives
  // the transport rather than arriving stringified, which every in-process
  // assertion about its structure would still pass; and that the console's
  // two controls reach the register at all.
  { file: 'sts_pki_revocation.js',       browser: false, local: true },
  // EVERY REVOCATION ADDRESS EVERY CERTIFICATE NAMES, FOLLOWED AS WRITTEN, IN
  // EVERY TRUST REALM (2026-09-13). `local: true` on `tests/CLAUDE.md`'s third
  // kind: whether an address inside a certificate answers from where the
  // runner stands is decided by how the LAUNCHER published this stack's ports
  // and told the service which ones it got — `PKI_DISTRIBUTION_PORT`,
  // `PKI_DISTRIBUTION_LDAP_PORT` or a whole `PKI_DISTRIBUTION_BASE_URL` — and
  // no copy over there could hold that. The job beside it built its paths by
  // hand and was green while every certificate named a port nothing answered
  // on; this one rewrites nothing, and holds each CRL, OCSP answer and
  // caIssuers certificate to RFC 5280, RFC 4516/4523, RFC 5019 and RFC 6960.
  { file: 'sts_pki_distribution_points.js', browser: false, local: true },
  // THE POSTGRESQL METRICS PAGE (2026-09-11). `local: true` on the first of
  // `tests/CLAUDE.md`'s two questions — it drives `/admin/database` and
  // `/admin-api/database`, and the tree that adds a page to that console is
  // the tree that should go red when the page stops answering.
  //
  // **IT IS THE ONLY JOB IN EITHER SUITE THAT ASSERTS ANYTHING ABOUT THE
  // DATABASE'S OWN CATALOG**, and the only one whose subject is a surface
  // whose SHAPE this repository does not decide: the page draws the columns
  // PostgreSQL hands back, so what a test can hold is that they arrive and
  // never which ones. `tests/database_metrics.js` beside it holds everything
  // that needs no server — every statement a read, the probe table against
  // the page's sections — and can assert none of this.
  //
  // **IT SKIPS RATHER THAN FAILS WHEN `persistence.mode` IS NOT `postgres`,
  // AND THAT IS A NARROW EXCEPTION THIS SUITE OTHERWISE REFUSES.** The
  // standing rule is that a job which cannot run FAILS naming what it needed,
  // because a skip is how a suite comes to report green having driven
  // nothing. What earns the exception is that this one cannot arrange its own
  // precondition at all: `persistence.mode` is RESTART-ONLY — the store is
  // opened before the listener binds — so unlike a job that needs a realm or
  // a setting, there is no door it could knock on. It says so in the log and
  // still asserts the no-database sentence on the way past, which is the half
  // that IS true of a memory-mode service.
  { file: 'sts_database_metrics.js',     browser: false, local: true },
  // THE TWO SECOND-FACTOR MECHANISM PAGES AND THE ROSTER THAT ABSORBED
  // /admin/mfa (2026-09-10). `local: true` on sts_portal_totp.js's argument
  // one step further along: every assertion in it is about this service's own
  // console or its /admin-api, and the tree that MOVES a control is the tree
  // that should go red when the control lands nowhere.
  //
  // It is NOT covered by tests/webauthn_policy.js beside it and the split is
  // the usual one: that file asserts what the settings module DECIDES — none
  // of which is reachable over HTTP — and this one asserts that any of it
  // reaches a page, an operation and a button. A settings group whose page was
  // renamed and now has none is invisible in process and obvious in a request.
  //
  // AFTER sts_portal_totp.js on purpose: that job enrols an authenticator and
  // clears it, and this one asserts a clear REFUSES for somebody holding
  // nothing. Running before it would be asserting against a person this job
  // created, which is what it does; running after leaves that unchanged and
  // keeps the two clears in the order a reader of the report expects.
  { file: 'sts_second_factor_pages.js',  browser: false, local: true },
  // A REAL WEBAUTHN CEREMONY AGAINST THE SIGN-IN SCREEN (2026-09-10), and the
  // job that proves the two credential stores became one. `local: true` for
  // sts_consent.js's third reason: the ceremony is a protocol surface and
  // would sit happily in the parent suite, and what makes the claim worth
  // anything is reading the credential back out of `GET /admin-api/users` —
  // this repository's own API, and the register the sign-in screen consults.
  //
  // It carries an AUTHENTICATOR of its own — a real P-256 key, real CBOR, a
  // real signature — rather than importing `authn/webauthn.js`, on
  // sts_dpop.js's rule: two ends of one exchange from one implementation would
  // make a shared misunderstanding pass.
  //
  // AFTER the pages job because that one asserts a clear REFUSES for somebody
  // holding nothing, and this one enrols a key and clears it. Reversed, the
  // pages job would be asserting against this job's person.
  { file: 'sts_webauthn_second_factor.js', browser: false, local: true },
  // BACKUP KEYS (2026-09-10): two enrolled from /portal/keys, the first taken
  // away, the second still signing them in. `local: true` on the job above's
  // argument — the ceremony is driven at this repository's own portal and the
  // credential is read back out of its own API — and it carries its own
  // AUTHENTICATOR for `sts_dpop.js`'s reason, three of them in fact: the
  // original, the backup, and one that is never enrolled.
  //
  // AFTER `sts_webauthn_second_factor.js`, which asserts the SIGN-IN door's
  // enrol-on-first-use path. This one needs `/portal/keys` to be the door and
  // would otherwise be asserting against a store the other job is still
  // filling.
  { file: 'sts_portal_backup_keys.js',   browser: false, local: true },
  { file: 'sts_pki_workbench.js',        browser: false, local: true },
  // AN APPLICATION'S CREDENTIALS (2026-09-13): its key pair replaced by an
  // issue from this realm's CA or by an uploaded certificate — an external
  // authority's with its full chain — and its client secret regenerated.
  // `local: true` on the first of `tests/CLAUDE.md`'s questions: the controls
  // are this console's and their operations this API's, and the assertion
  // spans those doors and `/oauth2/token` — the replaced key refused, the
  // application's own accepted, the old secret refused in RFC 9700 mode.
  { file: 'sts_application_credentials.js', browser: false, local: true },
  // A PERSON'S RFC 7523 AND RFC 7522 KEY PAIRS (2026-09-13), the same
  // arrangement for the Credentials section of `/admin/users?user=`: issued
  // and uploaded through `/admin-api/pki` with `target=person`, and used at
  // `/oauth2/token` — a person's SAML assertion about themselves accepted and
  // about somebody else refused, the replaced key refused, the held key
  // accepted, one profile taken off leaving the other.
  { file: 'sts_user_credentials.js',     browser: false, local: true },
  // OAUTH 2.1 MODE (2026-09-13), on the third reason: the mode is a realm
  // setting written through `/admin-api/realms/create` and every assertion is
  // at `/oauth2/*` — a public client with PKCE and no token-request
  // redirect_uri getting a token where an RFC 9700 realm beside it refuses the
  // same request, and the refusals 2.1 adds.
  { file: 'sts_oauth21.js',              browser: false, local: true },
  // THE OAUTH 2.0 / OIDC MONITORING PAGE (2026-09-13), with RFC 9126 pushed
  // authorization requests as its first section. `local: true` on the first
  // question and the third reason: the page and its operations are this
  // console's and this API's, and the assertion that matters spans them and
  // `/oauth2/par` and `/oauth2/authorize` — a request pushed there is listed
  // and counted here, and one withdrawn here, through the API or a real
  // console form, is refused invalid_request_uri there.
  { file: 'sts_oauth2_monitor.js',       browser: false, local: true },
  // RFC 9470 STEP-UP AUTHENTICATION (2026-09-13), on the third reason: a
  // resource application's requirement and `oauth2.stepUpAcrValues` are
  // written through `/admin-api` and counted on the monitor, and every
  // assertion is at `/oauth2/*` — a one-factor session sent to sign in again
  // for acr_values=mfa, stepped up with a TOTP code enrolled at
  // `/portal/mfa`, and the challenge the stand-in resource and UserInfo send.
  // After the monitor job, in a throwaway realm it leaves standing.
  { file: 'sts_step_up.js',              browser: false, local: true },
  { file: 'sts_roles.js',              browser: false, local: true },
  { file: 'sts_roles_builtin.js',        browser: false, local: true },
  { file: 'sts_saml11.js',               browser: false },
  { file: 'sts_saml_encryption.js',      browser: false },
  // Signs a UserInfo response and an ID Token with every advertised
  // algorithm, and one SLH-DSA-SHAKE-128s signature takes 190-310s under the
  // coverage run's instrumentation (2026-09-15). The job took 434s on a run
  // that passed and would be past the coverage watchdog's 900s on a runner
  // twice as slow, which is why it is raised — its own busy window, ten
  // minutes per request, is what reports a mock that has really stopped.
  { file: 'sts_userinfo_protected.js',   browser: false,
    timeoutMs: 1500000 },
  { file: 'sts_xacml_editor.js',         browser: true,  local: true },
  { file: 'sts_xacml_endpoints.js',      browser: false, local: true },
  { file: 'sts_xacml_remote_pep.js',     browser: false, local: true,
    docker: true },
  // THE SOCKETS AND DOORS A DEPLOYED CLUSTER IS MOST LIKELY TO BREAK
  // (2026-09-18): every one of these families was covered in process and by
  // nothing driven over the network, so a stack behind a load balancer said
  // nothing about them. Each drives its protocol against the address the
  // service is reached at, in both modes.
  { file: 'sts_ldaps.js',                browser: false, local: true },
  { file: 'sts_kerberos_spnego.js',      browser: false, local: true },
  { file: 'sts_spiffe_grpc.js',          browser: false, local: true },
  { file: 'sts_oid4vp_wallet.js',        browser: false, local: true },
  { file: 'sts_federation_realms.js',    browser: false, local: true },
  { file: 'vc_did.js',                   browser: false },
  // ---------------------------------------------------------------------
  // LAST, ALL THREE OF THEM, AND THE ORDER IS THE WHOLE OF WHY IT IS SAFE
  // (2026-09-06).
  //
  // The three bulk-load jobs put five thousand people, fifty groups and five
  // thousand memberships EACH into the DEFAULT REALM and delete none of it —
  // that is what they are for, and their headers argue both halves. Every job
  // above them therefore runs against the directory it has always run against,
  // and the one that walks every console page does so before the store has
  // fifteen thousand rows in it. A job added after this line inherits a large
  // directory; one added above it does not.
  //
  // **THEY DO THE SAME WORK THROUGH THREE DIFFERENT DOORS** — SCIM, the raw
  // LDAP socket and this service's own management API — and everything they
  // share is in `bulk_load.js`, so a difference between their numbers is a
  // difference in the door. Each stamps every name it invents with its own
  // door (`bulk-scim-…`, `bulk-ldap-…`, `bulk-api-…`), which is what lets
  // three of them run in one suite against one directory that nothing deletes
  // from.
  //
  // **THE ORDER AMONG THE THREE IS DELIBERATE AND IT IS NOT ALPHABETICAL.**
  // SCIM first, LDAP second, `/admin-api` last, because each raises
  // `ldap.maxEntries` for what IT is about to add and the one that runs last
  // leaves the highest ceiling — so a person poking at the service afterwards
  // is not up against a full directory. Reversing them works and leaves a
  // ceiling sized for the smallest of the three runs.
  //
  // **AND THEY CARRY A TIMEOUT OF THEIR OWN**, which no other entry here does.
  // Ten thousand sequential writes take about four minutes against a warm
  // local service and more in a container on a loaded CI host, against the
  // runner's 300s default — so without this each would be killed partway
  // through and reported as a hang rather than as the measurement it is.
  //
  // **THE LDAP ONE NEEDS THE DIRECTORY'S OWN SOCKET**, which
  // `docker-compose.yml` deliberately does not publish. The launchers arrange
  // it and hand the job `STS_LDAP_URL` — `./run-tests.sh` by putting
  // the runner on the bridge with the service, and `./local-run-tests.sh`
  // (removed 2026-09-16) by layering `tests/docker-compose-ldap.yml` with a
  // free host port. It is NOT
  // marked `docker: true`: that flag is for a job needing a DAEMON, and this
  // one needs a port. Run by hand with neither, it FAILS naming the variable
  // rather than reporting green having driven nothing.
  { file: 'sts_directory_bulk_load_scim.js', browser: false, local: true,
    timeoutMs: 1800000 },
  { file: 'sts_directory_bulk_load_ldap.js', browser: false, local: true,
    timeoutMs: 1800000 },
  { file: 'sts_directory_bulk_load_api.js',  browser: false, local: true,
    timeoutMs: 1800000 },
  // FIFTY THOUSAND OVER LDAP, and LAST — it leaves the directory an order of
  // magnitude larger than the three above found it, so every job that walks a
  // page or reads a register has run before it. It drives
  // sts_directory_bulk_load_ldap.js's file at a different scale rather than
  // copying its client; that file argues why. The watchdog is sized for the
  // failure it exists to report — a quadratic come back — rather than for the
  // half minute the adds actually take.
  //
  // **DISABLED 2026-09-13, TO MAKE THE SUITE FASTER.** Commented out rather
  // than deleted: the file is kept and nothing else in the suite depends on
  // it, so putting this entry back is the whole of re-enabling it. While it is
  // out, nothing holds the LDAP add path to constant time past five thousand.
  // { file: 'sts_directory_bulk_load_ldap_50k.js', browser: false, local: true,
  //   timeoutMs: 3600000 }
];

// ---------------------------------------------------------------------------
// THE HELPERS, and `env/local.js`. None of these is a job; every one of them is
// reached by a `require` from at least one job above, which is the whole reason
// it is here. The set was computed as the transitive local-require closure of
// the copied jobs, not chosen — so a job that grows a new
// `require('./x.js')` over there arrives here as a MISSING MODULE at load time,
// which is a failed job with a name in it rather than a silent gap.
// ---------------------------------------------------------------------------
const HELPERS = [
  'browser_flags.js',
  'consent_screen.js',
  'expectation.js',
  'jwt_vc_json_common.js',
  'module_paths.js',
  // Required by jwt_vc_json_common.js since the parent's 2026-09-17 copy;
  // missing here from 5ecc178 until 2026-09-18, which failed every job that
  // loads that helper with MODULE_NOT_FOUND — exactly what the note above
  // says a missing helper looks like.
  'page_load.js',
  'random_username.js',
  'sts_applications.js',
  'wait_for.js',
  'env/local.js'
];

// ---------------------------------------------------------------------------
// THE HELPERS THAT ARE OURS (2026-09-06). Same idea as a job's `local: true`
// and it needed a list of its own for the same reason: `HELPERS` above is
// vendored FROM the parent, and a file of ours listed there is reported GONE
// UPSTREAM by `--vendor-check` for ever — which is a permanent red line about
// a file that is exactly where it should be.
//
// They are still listed rather than merely present, because the reason HELPERS
// exists at all is the other half of that check: the set was computed as the
// transitive local-require closure of the jobs, so a job that grows a
// `require('./x.js')` arrives as a MISSING MODULE at load time rather than as
// a silent gap. A local helper that nothing lists gets that guarantee from
// nothing.
const LOCAL_HELPERS = [
  // A Kerberos client over raw TCP 88 and MS-KKDCP — AS, TGS, the GSS-wrapped
  // AP-REQ and SPNEGO — for `sts_kerberos_spnego.js` (2026-09-18). It reuses
  // the service's codec for the encodings and works out key usages and
  // checksums itself, so the exchange is not the KDC agreeing with itself.
  'krb5_wire.js',
  // What the three sts_directory_bulk_load_*.js jobs share, which is
  // everything except the door.
  'bulk_load.js',
  // A SAML 2.0 assertion and an XML Signature, built by this suite's own code
  // — `sts_saml2_bearer_grant.js` signs with it, and so does the in-process
  // `tests/saml_assertion_grant.js`, which was the first require from `tests/`
  // into this directory and argues it at the top of that file (several
  // in-process files have followed it, here and to the enrollment and GNAP
  // clients below). There is ONE independent XML Signature implementation here
  // on purpose: a second copy would be a second place for exclusive
  // canonicalization to be wrong, which is the one thing a wrong copy would
  // hide.
  'saml_xmldsig.js',
  // GNAP's independent client instance (RFC 9421 signatures, RFC 9530 digests,
  // detached and attached JWS, the interaction hash) and the resource-owner
  // harness the three GNAP jobs share. Node built-ins only; nothing from gnap/.
  'gnap_client.js',
  'gnap_flow.js',
  // ACME's independent client (RFC 8555 flattened JWS, RFC 7638, the External
  // Account Binding MAC, RFC 9773's certificate identifier). Node's crypto, the
  // vendored PKI encoder for CSRs and pkijs; nothing from acme/.
  'acme_client.js',
  // EST's independent client (RFC 7030, RFC 8951): a DER reader, the
  // certs-only, csrattrs and multipart parsers, and a KEM template CSR.
  // Node built-ins only; nothing from est/ or common/cert_enrollment.js.
  'est_client.js',
  // SCEP's independent client (RFC 8894): node-forge for the PKCS#10, the
  // self-signed signer and the envelope, forge.asn1 and node's crypto for the
  // SignedData and the CertRep. Nothing from scep/ or cert_enrollment.js.
  'scep_client.js',
  // A registered OAuth client and a PKCE pair, for the jobs that start an
  // authorization request: product mode refuses an unknown client_id and a
  // public client without PKCE (2026-09-18).
  'oauth_fixtures.js',
  // What the service under test IS — its mode, its Kerberos realm, its base DN
  // — read from /admin-api/config rather than assumed (2026-09-18).
  'service_facts.js'
];

// ---------------------------------------------------------------------------
// THE WALLET AND CRYPTO MODULES, from client/src/. The first seven are named
// by a job; the last six are their transitive requires, computed rather than
// chosen — so a module that grows a new `require('./x.js')` over there arrives
// here as MODULE_NOT_FOUND at load, which is a failed job with a name in it.
//
// The modules the jobs reach in THIS repository — `bbs2023.js` in
// common/vendored/, `client_auth.js` in oauth-oidc/ — are NOT vendored and
// must not be: they are the code under test. `run-report.js` points
// MOCK_STS_DIR at the repository root so `module_paths.js` finds them where
// they actually live.
// ---------------------------------------------------------------------------
const CLIENT_MODULES = [
  // named directly by a job
  'did.js',
  'jose_jwe.js',
  'jws.js',
  'metadata_client.js',
  'pqc.js',
  'sd_jwt_vc.js',
  'vci_wallet.js',
  // reached only through the seven above
  'crypto_bytes.js',
  'dpop.js',
  'op_metadata.js',
  'pk_encryption.js',
  'symmetric_crypto.js',
  'vci_metadata.js'
];

// Everything under version control here THAT CAME FROM OVER THERE, for the
// drift check: each entry says which of the parent's directories it came from,
// because the two halves are copied from different places into one flat
// directory. A `local` job is skipped — it has no upstream to differ from, and
// listing it would report it GONE UPSTREAM for ever. See the note on JOBS.
function allFiles() {
  log.debug("Entering allFiles().");
  const out = [];
  JOBS.forEach(function (j) {
    if (j.local) {
      return;
    }
    out.push({ rel: j.file, source: SOURCE_DIR });
  });
  HELPERS.forEach(function (h) {
    out.push({ rel: h, source: SOURCE_DIR });
  });
  // LOCAL_HELPERS is deliberately NOT here, for the reason a `local` job is
  // not: it has no upstream to differ from.

  CLIENT_MODULES.forEach(function (c) {
    out.push({ rel: c, source: CLIENT_SOURCE_DIR });
  });
  log.debug("Leaving allFiles().");
  return out;
}

module.exports = { SOURCE_DIR: SOURCE_DIR, CLIENT_SOURCE_DIR: CLIENT_SOURCE_DIR,
                   JOBS: JOBS, HELPERS: HELPERS,
                   LOCAL_HELPERS: LOCAL_HELPERS,
                   CLIENT_MODULES: CLIENT_MODULES, allFiles: allFiles };
