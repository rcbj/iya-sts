// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_xacml_remote_pep.js
//
// ===========================================================================
// PHASE FIVE, END TO END: THE REMOTE PEP AS A CONTAINER ON THE SAME DOCKER
// NETWORK AS THE SERVICE, REGISTERED OVER MUTUAL TLS, FED POLICY, AND
// ENFORCING IT WHERE THE PDP CANNOT SEE.
//
// Every other test of the remote PEP asserts ONE side of the seam. This one is
// the seam, and since 2026-09-06 it is the seam AS DEPLOYED:
//
//   * `tests/xacml_pep.js` loads the container's modules in a child process and
//     compares them with the mock's — the engine against the thirty-line shim,
//     the Dockerfile's COPY set against `engine.js`, and the two `enforce()`
//     implementations over seven decisions. It never starts the PEP, never
//     pulls anything and never makes an HTTP request.
//   * `tests/vendored/sts_xacml_endpoints.js` drives `POST
//     /xacml/pep/register`, `GET /xacml/pep/policies` and `POST
//     /xacml/pep/heartbeat` over HTTP — but the caller there is the TEST
//     impersonating a PEP. It asserts the bytes of the pull; nothing evaluates
//     them.
//
// So `xacml-pep/sync.js` — the registrar and the poller, which is the whole
// client half of the feature — was loaded by no test at all, and no test
// anywhere asserted that a policy written at the PAP ever changed what a
// separate process ALLOWS.
//
// ---------------------------------------------------------------------------
// A CONTAINER AND NOT A CHILD PROCESS, AND THE DIFFERENCE IS NOT COSMETIC.
//
// The first version of this file spawned `node xacml-pep/pep.js` on the
// machine running the suite. That asserted the program and it quietly did not
// assert the DEPLOYMENT, which is where a remote PEP actually lives. Six things
// are only true of the container, and every one of them is a way this feature
// can be broken while a host run stays green:
//
//   1. **THE IMAGE IS BUILT FROM THIS TREE, HERE, EVERY RUN.** The Dockerfile
//      copies seven engine modules out of `xacml/` by name.
//      `tests/xacml_pep.js` compares that COPY list with `engine.js`'s
//      `MODULES` as TEXT; this file runs the result. A module added to the
//      engine and not to the Dockerfile is an image that dies at load with
//      MODULE_NOT_FOUND, and the host run could never see it because on a
//      developer's machine the engine is one directory up and is always there.
//   2. **THE PEP RESOLVES THE PDP BY COMPOSE DNS**, `https://sts:8081`, on the
//      private bridge — not `localhost`, and not the published port. That is
//      the address `docker-compose.yml` ships, and it is a different name in
//      the certificate.
//   3. **IT DOES NOT YET VERIFY THAT CERTIFICATE.** This read "it verifies it
//      for real, with `PEP_TLS_CA`", and no path here has ever done that: both
//      the launchers' container and the one `startThePep()` makes run with
//      `PEP_TLS_INSECURE=true`, which is what `docker-compose.yml` ships,
//      because development mode regenerates the service Root on every start
//      (`xacml-pep/sync.js` argues it). `PEP_TLS_CA` is supported by `pep.js`
//      and exercised by nothing in this file.
//   4. **THE NUDGE IS DELIVERABLE.** The PDP dials `http://<pep>:9090/notify`
//      across the bridge — the third outbound request this repository grew,
//      and the only one of the first three with no test against a real
//      listener anywhere until this file. Section 6 measures it: a change
//      reaches the PEP in tens of milliseconds against a five-second poll,
//      and the PDP's own row records what the PEP answered.
//   5. **A MOUNT PUTS THE CLIENT CERTIFICATE WHERE `pep.js` READS ONE**, so
//      the registration is a real mutual-TLS handshake between two containers
//      and the row on `/admin/xacml/peps` is marked authenticated by a
//      certificate this service saw on a connection.
//   6. **THE CONTAINER IS THE UNIT THAT DIES.** A PEP that exits at load, binds
//      nothing, or cannot resolve its PDP is a stopped container with a log,
//      and every failure message below carries `docker logs`.
//
// ---------------------------------------------------------------------------
// WHY IT IS IN THIS DIRECTORY, WHICH IS TWO ARGUMENTS AND NOT ONE.
//
// The root CLAUDE.md's placement rule asks two questions in order, and this
// file answers the first one YES and the second one NO, so both point here:
//
//   1. Is the thing under test this service's `/admin` console or `/admin-api`?
//      It is, in part: the policies below are deployed, promoted, disabled and
//      re-enabled through `/admin-api/xacml`, the nudge is turned on through
//      `/admin-api/config`, and the PEP's own counters are read back off
//      `/admin-api/xacml/peps`.
//   2. Can it be asserted by driving the running service over HTTP? NO. It
//      builds an image and starts a container on the service's own network.
//
// ---------------------------------------------------------------------------
// WHO STARTS THE CONTAINER: THE LAUNCHER, AND ONLY OTHERWISE THIS JOB.
//
// **BOTH LAUNCHERS BRING A REMOTE PEP UP AS PART OF THE STACK** and hand this
// job three variables — `XACML_PEP_URL`, `XACML_PEP_NAME` and
// `XACML_PEP_REALM` — plus, until phase 4 of #1827's follow-up retired the
// PEP's client certificate (2026-11-16), `XACML_PEP_CA_PEM` (the anchor for
// the certificate they minted and mounted; read where a launcher still sets
// it) and, since 2026-09-13,
// `XACML_PEP_HTTPS_URL` and `XACML_PEP_SERVER_CERT_DIR` for section 1b. That
// is the primary arrangement and the one CI runs:
//
//   * `./local-run-tests.sh` added `--profile xacml` to the project it
//     already brought the service up in, on a free host port, and exported
//     the three — until that launcher was removed on 2026-09-16.
//   * `./run-tests.sh` declares the service in
//     `docker-compose-run-tests.yml`; the tests container reaches it at
//     `http://xacml-pep:9090` on the bridge they share.
//
// **THE LAUNCHER OWNS IT BECAUSE THE CI RUNNER CANNOT.** Over there the suite
// runs INSIDE a container with no docker in it — deliberately, and that file
// argues why — so a job that started its own could never run in the stack that
// gates this repository. One arrangement that works in both is worth more than
// a shorter one that works in the loop a developer happens to use.
//
// **WITH NO SUCH VARIABLES THIS JOB BUILDS AND STARTS ONE ITSELF**, which is
// what a hand-run `node tests/tools/run-report.js` gets and what a coverage run
// gets, since those drive a service that is a plain process with no compose
// network to join. That path needs a docker daemon; without one the runner
// reports this job SKIPPED with the reason rather than green — amber in the
// report, `<skipped>` in the JUnit, a line in the summary — because a run that
// checked nothing must never read as a pass.
//
// The two paths differ in WHO CREATES THE CONTAINER and in nothing else. The
// configuration is identical, deliberately: a client certificate minted by
// `tests/tools/pep-credential.js` and mounted at `/certs`, the same bias, the
// same unverified PDP certificate — see `startThePep()`'s header, which
// records the three days the two paths were NOT identical.
//
// ---------------------------------------------------------------------------
// THE REALM IS CREATED BY THIS JOB AND THE CONTAINER IS POINTED AT IT FIRST.
//
// A launcher-started PEP comes up minutes before this job runs, aimed at
// `/realm/<XACML_PEP_REALM>` — a realm that does not exist yet. So it fails to
// register, fails to pull, and says so. **`xacml-pep/sync.js` RETRIES ITS
// REGISTRATION ON THE POLL TIMER**, so once this job creates the realm the
// container converges on a console row exactly as it converges on policy, and
// section 1 asserts it took more than one attempt to get there.
//
// That retry is a change made for this arrangement and it is right
// independently of it: before it, a PEP that came up before its PDP — or
// survived a PDP restart it started during — enforced correctly FOR EVER while
// appearing on nobody's console. `sync.js`'s header argues it.
//
// ---------------------------------------------------------------------------
// A CLIENT CERTIFICATE, AND THE REALM LEFT AT ITS DEFAULTS.
//
// `docker-compose.yml` still ships this container WITHOUT one and says why:
// putting a key in the image would mean committing a private key to this
// repository or writing a first-start script for a demonstration container.
// This job used to match that by turning `xacml.pepRequireCertificate` off in
// its realm and asserting an UNAUTHENTICATED row. Since 2026-09-06
// `/xacml/pep/*` requires a VERIFIED chain holding `REMOTE_PEPS`, so the
// container here carries a minted certificate, the realm is left at its
// defaults, and section 1 asserts the row is AUTHENTICATED — see the comment
// in `test()` where the setting used to be turned off.
//
// **THE REGISTRATION'S SECURITY HALF IS ASSERTED NEXT DOOR**:
// `sts_xacml_endpoints.js` section 7 presents a certificate AND a body
// claiming to be somebody else, which this job's container never does.
//
// ---------------------------------------------------------------------------
// THE ONE THING THIS JOB WILL NOT DO UNTIL SECTION 6.
//
// **THE NUDGE IS DELIBERATELY OFF FOR SECTIONS 1–5**, because the PULL is the
// contract and the nudge is an optimisation over it. POST /notify is HTTPS
// only, and this container's listener certificate does not exist until
// section 1b writes it, so the first registration advertises no notify URL.
// This job also turns `xacml.pepNotify` OFF as soon as it creates the realm,
// so the PDP dials nothing either way. Section 1 asserts that empty
// registration. Every convergence up to section 5 is a POLL and nothing else.
//
// Section 6 then turns the nudge on IN THIS REALM and measures the
// difference, which is the only way to have both claims: that the PEP
// converges without the nudge, and that the nudge works. **The nudge is
// verified against this realm's `pep-tls` Issuing CA with nothing set**: the
// PEP's HTTPS pair is the one section 1b issued, and no
// `xacml.pepNotifyCaFile` is named — in product mode as in development.
//
// ---------------------------------------------------------------------------
// WHAT WOULD FAIL HERE AND NOWHERE ELSE.
//
//   1. `sync.js` failing to register, pull, or parse what it pulled — nothing
//      else loads that file.
//   2. The IMAGE being unbuildable or unloadable — the COPY set, the shim's
//      path inside the image, the two npm packages.
//   3. A policy change at the PAP never reaching a PEP: a sync token computed
//      over something that does not change, a `?since=` answering 304 when the
//      repository moved, a poll timer that never fires.
//   4. A DISABLED policy going on being enforced in a process the console
//      cannot reach.
//   5. The remote PEP and the PDP disagreeing about an attribute SPELLING.
//      `xacml_pip.js` answers both the bare name and the
//      `urn:sts:xacml:attribute:` form; `pep.js` asserts both. A change to
//      either side that dropped one would deny everything under a policy that
//      is working perfectly — which `xacml-pep/CLAUDE.md` records as having
//      cost a run already.
//   6. **THE NUDGE NOT BEING DELIVERED, OR BEING DELIVERED AND NOT RECORDED.**
//      `xacml_pep_http.js` is dialled against a real listener only here.
//   7. The heartbeat's counters, which are the only way enforcement done in
//      another process is visible on this console at all.
//   8. **A PDP OUTAGE DENYING EVERYTHING**, which is the trade `sync.js` argues
//      and section 9 is the only place that has ever checked.
//   9. **THE CONTAINER AS A REVERSE PROXY (#1760, section 10)**: the
//      configuration saved at `/admin-api` naming registered applications
//      and pulled, each mechanism (session as the application's own
//      confidential client, OAuth 2.0 JWT and opaque, Basic, SAML 2.0)
//      allowed and refused in front of the companion's `/pep-app`, a
//      sign-out at the service ending the proxy session (by CAEP, and by
//      the liveness door), a rotated secret and a deleted application
//      reaching the PEP, and deny-by-default — with the
//      application's own counter saying what reached it. A route whose
//      policy names a configured role permits a member of that role and
//      refuses a member of another role, and a public route is reached
//      with no credential and refuses a method it does not take. The
//      launchers
//      hand it `XACML_PEP_PROXY_URL`, `XACML_PEP_PROXY_HTTPS_URL` and
//      `XACML_PEP_UPSTREAM_URL`; started here, the job builds and starts
//      the companion beside its own PEP.
//
// ---------------------------------------------------------------------------
// THREE THINGS IT DELIBERATELY DOES NOT ASSERT, each because somewhere else
// asserts it better:
//
//   * that the two `enforce()` implementations agree — `tests/xacml_pep.js`
//     compares them over all seven decisions in one process, which is a
//     comparison, where this file could only observe one of them;
//   * the registration's security rule (a certificate names the PEP, a body
//     cannot) — `sts_xacml_endpoints.js` section 7 drives that from both sides
//     with a certificate claiming to be somebody else;
//   * the Dockerfile's COPY set as a LIST — a file comparison, and there is no
//     endpoint that could answer it. This file runs the image that list
//     produces, which is the other half of the same claim.
// ===========================================================================

const assert = require("assert");
const fs = require("fs");
const net = require("net");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");
const { URL } = require("url");
const { Command, Option } = require("commander");
const names = require("./random_username.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason tests/vendored/wait_for.js gives.
  appconfigProblem = e;
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_xacml_remote_pep",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug('CONFIG_FILE could not be read, so the configuration is empty: ' +
            appconfigProblem.message);
}
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");

// THE REPOSITORY ROOT. `tests/vendored/` is two levels below it, and the image
// is built from there because `xacml-pep/Dockerfile` copies the engine out of
// `xacml/` — building from inside that directory fails on the first COPY,
// which is the right way for it to fail.
const REPO_ROOT = path.join(__dirname, "..", "..");
const PEP_DOCKERFILE = path.join("xacml-pep", "Dockerfile");

// **`:test` RATHER THAN THE BARE `rcbj/xacml-pep` THE COMPOSE FILE BUILDS.**
// The content is identical — same Dockerfile, same context — so the layer cache
// is shared and a rebuild here is a fraction of a second. What the tag buys is
// that a suite run cannot retag an image somebody built from another checkout
// and then wonder why `docker compose --profile xacml up` is serving code they
// have never seen.
const IMAGE = "rcbj/xacml-pep:test";

// ---------------------------------------------------------------------------
// WHICH PEP THIS JOB IS DRIVING, AND THEREFORE WHICH REALM AND WHICH NAME.
//
// All three arrive together or none of them does — see the header. A URL with
// no realm would have this file creating policy in one place and asserting
// against a container polling another, and the failure would look like a PEP
// that never converges rather than like the misconfiguration it is.
// ---------------------------------------------------------------------------
const PROVIDED_URL = String(process.env.XACML_PEP_URL || "").replace(/\/+$/,
                                                                     "");
const LAUNCHER_STARTED_IT = !!PROVIDED_URL;

// **THE REALM IS FIXED WHEN THE LAUNCHER OWNS THE CONTAINER**, because that
// container's `PEP_PDP_URL` was decided when the stack came up and cannot be
// told about a name minted here. When this job starts its own it mints one, for
// the reason the sibling job records — two runs against one long-lived service
// must not meet each other's leavings.
const REALM = (LAUNCHER_STARTED_IT
  ? String(process.env.XACML_PEP_REALM || "")
  : "pepe2e-" + names.runStamp()).toLowerCase()
    .replace(/[^a-z0-9-]/g, "").slice(0, 40);

// The PEP's name AND its container's hostname — one string, deliberately.
// `sync.js` sends `?pep=<PEP_NAME>` on every pull to move its own `lastSeen`,
// and the PDP nudges whatever host the notify URL names. Two different strings
// would leave a registered row no pull ever touched and a nudge nothing ever
// answered.
const PEP_NAME = (LAUNCHER_STARTED_IT
  ? String(process.env.XACML_PEP_NAME || "")
  : "pep-" + names.runStamp()).toLowerCase()
    .replace(/[^a-z0-9-]/g, "").slice(0, 40);

// THE TWO PEOPLE THE POLICY DECIDES ABOUT, created by `createThePeople()` in
// this realm rather than seeded (2026-09-12) — see that function.
//
// **THE LAUNCHERS' PEP IDENTITY IS NO LONGER A SEED (#1061).** When a
// launcher owns the container, PEP_NAME is `remote-pep-1`, and this job now
// makes its entry in the run's realm, STORES the launcher's leaf on it and
// puts it in `remote-peps` (`admit()`), as the self-started path does in
// `provisionTheContainersIdentity()`: an outside certificate names only the
// entry storing it, so the seeded `cn=remote-pep-1` group member no longer
// admits anything. The container retries its registration until then.
const ADMIN_PERSON = "pep-admin-person";
const STAFF_PERSON = "pep-staff-person";

const POLICY_A = "remote-pep-baseline";
const POLICY_B = "remote-pep-widened";
// `xacml_templates.js` builds every policy id as this prefix plus the slug of
// the name it was created under. Written out rather than read back from the
// service, so that the assertions below say WHICH document the PEP is starting
// from and not merely that it changed.
const ID_OF = {};
ID_OF[POLICY_A] = "urn:sts:xacml:policy:" + POLICY_A;
ID_OF[POLICY_B] = "urn:sts:xacml:policy:" + POLICY_B;

// THE POLL INTERVAL IS THE MEASUREMENT INSTRUMENT of sections 4, 5, 6 and 9,
// which is why it is here rather than left at the image's fifteen seconds.
// Long enough that a nudge-driven convergence is unmistakably faster (section 6
// sees tens of milliseconds against this), short enough that four poll-driven
// convergences do not dominate the run.
const POLL_MS = 5000;
const HEARTBEAT_MS = 2000;
const CONVERGE_MS = 40000;

var checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.debug("check passed: " + what);
  log.debug("Leaving check().");
}

function realmUrl(p) {
  log.debug("Entering realmUrl().");
  log.debug("Leaving realmUrl().");
  return base + "/realm/" + REALM + p;
}

function api(p) {
  log.debug("Entering api().");
  log.debug("Leaving api().");
  return realmUrl("/admin-api" + p);
}

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) { setTimeout(resolve, ms); });
}

// ---------------------------------------------------------------------------
// THE VERBS. Most of this file speaks JSON over `fetch` against `/admin-api`
// and against the PEP's own surface, and needs no credential for either.
//
// **ONE EXCHANGE HERE DOES NEED ONE NOW, AND THIS PARAGRAPH USED TO SAY IT DID
// NOT.** `askThePdp()` drives `POST /xacml/pdp`, which went behind the
// built-in `XACML_USER` role on 2026-09-06 — so section 3, the one that puts
// the PDP's answer beside the PEP's, could no longer ask the PDP at all. The
// registration is still the OTHER one, and the PEP still makes that itself
// from inside its container with a certificate this file put there.
//
// `fetch` cannot present a client certificate, so that one exchange goes
// through `https.request` with a credential minted by
// `tests/tools/pep-credential.js` — the same tool the launcher uses for the
// container, for the reason `sts_xacml_endpoints.js` states: a second way of
// building a chain is a second set of edge cases.
//
// **THE CN IS `xacml-user-1` AND NOT `remote-pep-1`.** The container's
// identity holds `REMOTE_PEPS`, which is refused at `/xacml/pdp`; this file
// therefore holds BOTH kinds of caller at once, which is the honest shape of a
// deployment and not an inconvenience.
// ---------------------------------------------------------------------------
const https = require("https");
const credentials = require("../tools/pep-credential.js");
// Roots this job minted. Removed when it finishes, pass or fail (#335). The
// launcher's PEP anchor is not one of them: the container stays up for the
// task. The truststore is service-wide and holds 32. tests/CLAUDE.md.
const addedAnchors = [];

var xacmlUser = null;

async function mintTheCredential() {
  log.debug("Entering mintTheCredential().");
  xacmlUser = await credentials.mint({
    subject: "CN=xacml-user-1,OU=xacml-users,O=iya-sts tests" });
  // Recorded before it is posted (#1307): an add applied but answered late
  // is still removed when the job finishes.
  const posted = await credentials.trustRecorded(base, xacmlUser.anchorPem,
                                                 addedAnchors);
  assert.ok(posted.ok, "POST /admin-api/tls/trust/add should accept the " +
    "Root CA this file " +
    "just built; it answered " + posted.status + ". Without the anchor the " +
    "certificate verifies against nothing and section 3 cannot ask the PDP " +
    "anything at all.");
  log.info("Minted an XACML_USER credential for " + xacmlUser.subject +
           " — the PDP's four endpoints want that role, where the container " +
           "holds REMOTE_PEPS.");

  // =====================================================================
  // AND THE CONTAINER'S OWN ANCHOR, PUT BACK (2026-09-06).
  //
  // The launcher posted it once, before this container started, and **the
  // truststore is a Map in the service's process that ANY job can empty**:
  // `POST /tls/trust/clear` needed no credential until #597 deleted it, and a
  // job that exercises the truststore through /admin-api/tls/trust is still
  // entitled to remove what it finds.
  //
  // **NOTHING NOTICED UNTIL THE DAY A CLIENT CERTIFICATE STOPPED BEING A
  // TURNSTILE.** This container's pull, its heartbeat and — since the PIP
  // landed — every attribute query all resolve a VERIFIED chain to a
  // directory entry. So a run in which some earlier job cleared the
  // truststore left this container authenticating as nobody for the rest of
  // it, reporting `UNABLE_TO_GET_ISSUER_CERT_LOCALLY` about an anchor that
  // had been posted correctly before anything started. **The symptom names a
  // certificate and the cause is another job**, which is the hardest shape of
  // failure to read in a suite.
  //
  // **THE FIX IS NOT TO STOP OTHER JOBS CLEARING IT.** That endpoint deserves
  // a test, and a suite where one job may not use a documented operation
  // because another depends on its side effects is a suite with an
  // undocumented ordering in it. The fix is for the job that DEPENDS on this
  // anchor to establish it — which is exactly what the mint above already
  // does for its own credential, applied to the one this file did not make.
  //
  // POSTING IT AGAIN IS FREE WHEN IT IS ALREADY THERE: `addAnchors()`
  // fingerprints, so an anchor that survived is reported as a duplicate and
  // nothing changes. And a launcher that did not export it is not a failure —
  // a developer running this job by hand against a stack they brought up
  // themselves has no such variable, and the container's own registration
  // will say plainly whether its certificate verifies.
  // =====================================================================
  // NOT RECORDED FOR REMOVAL (#335). This is the launcher's anchor, and the
  // PEP container stays up for the task. Only roots this job minted are
  // removed when the job finishes.
  const containerAnchor = String(process.env.XACML_PEP_CA_PEM || "");
  if (containerAnchor.indexOf("BEGIN CERTIFICATE") >= 0) {
    const back = await credentials.trustAnchor(base, containerAnchor);
    assert.ok(back.ok,
      "POST /admin-api/tls/trust/add should accept the PEP container's " +
      "Root CA, which the " +
      "launcher minted and exported as XACML_PEP_CA_PEM; it answered " +
      back.status + ". Every assertion below rests on that container's " +
      "certificate VERIFYING, and an earlier job in this run may have " +
      "emptied the truststore since the launcher posted it.");
    // `postAnchor()` answers the body as TEXT rather than parsed — it is a
    // build tool with no JSON reader in it — so the count is read here, and
    // read defensively: this line is a log line and must not be the thing
    // that fails a passing job.
    let added = null;
    try {
      added = JSON.parse(String(back.body || "")).added;
    } catch (e) {
      log.debug("Caught in mintTheCredential(): " + ((e && e.message) || e));
      // Not JSON. The status already said it worked; how many were added is
      // a nicety.
      added = null;
    }
    log.info("Re-posted the PEP container's Root CA (" +
             (added === 0 ? "already there — nothing had emptied the "
                          + "truststore"
                          : added > 0 ? "ADDED, so an earlier job in this run "
                            + "had emptied the truststore and this container "
                            + "would otherwise have authenticated as nobody"
                          : "accepted") + ").");
  } else {
    // PHASE 4 OF #1827's FOLLOW-UP (rcbj, 2026-11-16): the launchers mint
    // no client certificate for the container any more — it authenticates
    // on its assertion key alone — so there is no anchor to put back.
    log.info("XACML_PEP_CA_PEM is not set: the container presents no " +
             "client certificate (it authenticates on its assertion key), " +
             "so there is no Root CA of its to put back.");
  }
  log.debug("Leaving mintTheCredential().");
}

// `postJson()` with that certificate on the connection.
function certPostJson(url, payload) {
  log.debug("Entering certPostJson(). url=" + url);
  log.debug("Leaving certPostJson().");
  return new Promise(function (resolve, reject) {
    const target = new URL(url);
    const data = JSON.stringify(payload || {});
    const request = https.request({
      host: target.hostname, port: target.port || 443,
      path: target.pathname + target.search, method: "POST",
      rejectUnauthorized: false,
      cert: xacmlUser ? xacmlUser.certPem : undefined,
      key: xacmlUser ? xacmlUser.keyPem : undefined,
      // A full handshake every time (#406): the main port's sessions resume on
      // either node, and a session first made before this job's anchor
      // reached that node keeps its "not verified" verdict — a 403 for an
      // unauthenticated caller in the 2026-10-07 cluster run.
      agent: false,
      headers: { "Content-Type": "application/json",
                 "Content-Length": Buffer.byteLength(data) }
    }, function (response) {
      let text = "";
      response.on("data", function (chunk) { text += chunk; });
      response.on("end", function () {
        let body;
        try {
          body = JSON.parse(text);
        } catch (e) {
          log.debug("Caught in a callback in certPostJson(): " +
                    ((e && e.message) || e));
          body = null;
        }
        resolve({ status: response.statusCode, body: body, text: text });
      });
    });
    request.on("error", reject);
    request.write(data);
    request.end();
  });
}

async function fetchJson(url, options) {
  log.debug("Entering fetchJson(). url=" + url);
  const r = await fetch(url, options || {});
  const text = await r.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in fetchJson(): " + ((e && e.message) || e));
    // Not JSON — an HTML page, or an empty 204 from the PEP's nudge endpoint.
    // The caller reports the status and the raw text, which says more than a
    // parse error would.
    body = null;
  }
  log.debug("Leaving fetchJson(). status=" + r.status);
  return { status: r.status, body: body, text: text };
}

function get(url) {
  log.debug("Entering get().");
  log.debug("Leaving get().");
  return fetchJson(url);
}

function postJson(url, payload) {
  log.debug("Entering postJson().");
  log.debug("Leaving postJson().");
  return fetchJson(url, { method: "POST",
                          headers: { "Content-Type": "application/json" },
                          body: JSON.stringify(payload || {}) });
}

// An /admin-api action that must have worked. The refusal is quoted whole:
// every one of these handlers answers `why` with a sentence naming what it
// wanted, and a test that reported only the status would throw that away.
async function act(action, payload, what) {
  log.debug("Entering act().");
  const r = await postJson(api("/xacml/" + action), payload || {});
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST /admin-api/xacml/" + action + " should have " + what + "; it " +
    "answered " + r.status + " " +
    JSON.stringify((r.body && (r.body.why || r.body.error_description)) ||
                   r.body || r.text).slice(0, 400));
  log.debug("Leaving act().");
  return r.body;
}

async function setSetting(key, value) {
  log.debug("Entering setSetting().");
  const r = await postJson(api("/config/set"), { key: key, value: value });
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "setting " + key + " in the realm should have worked; it answered " +
    r.status + " " + String(r.text).slice(0, 300));
  log.debug("Leaving setSetting().");
}

// ===========================================================================
// DOCKER.
//
// Two wrappers and no library. One THROWS, because a docker command this job
// depends on failing is the end of the job and its stderr is the information;
// the other never does, because the teardown must run to completion whatever
// state the run is in.
// ===========================================================================
function docker(args, what) {
  log.debug("Entering docker(). " + args.slice(0, 3).join(" "));
  const r = spawnSync("docker", args, { encoding: "utf8",
                                        maxBuffer: 32 * 1024 * 1024 });
  if (r.error) {
    throw new Error("could not run docker (" + what + "): " + r.error.message);
  }
  if (r.status !== 0) {
    throw new Error("docker " + args.slice(0, 2).join(" ") + " failed while " +
                    what + " (exit " + r.status + "): " +
                    String(r.stderr || r.stdout || "").trim().slice(0, 2000));
  }
  log.debug("Leaving docker().");
  return String(r.stdout || "").trim();
}

function dockerQuiet(args) {
  log.debug("Entering dockerQuiet().");
  const r = spawnSync("docker", args, { encoding: "utf8",
                                        maxBuffer: 32 * 1024 * 1024 });
  log.debug("Leaving dockerQuiet().");
  return { ok: !r.error && r.status === 0,
           out: String((r && r.stdout) || "").trim(),
           err: String((r && r.stderr) || "").trim() };
}

// Everything the PEP container owns, so the teardown has one thing to take
// down and every failure message has one thing to quote.
var pep = { url: "", network: "", mode: "", pdpUrl: "", created: false,
            dir: "", certDir: "", hostPort: 0, containerPort: 9090,
            // The HTTPS listener (2026-09-13): where this job dials it, and the
            // directory it writes the issued pair into — the PEP's
            // `/certs/server`, as THIS process sees it.
            httpsUrl: "", serverCertDir: "", httpsContainerPort: 9443,
            // The reverse proxy (#1760, section 10): its two listeners as
            // this job reaches them, the application behind it as the PEP
            // dials it (`upstreamUrl`) and as this job reads it directly
            // (`upstreamDirectUrl`), the anchor section 1b's pair chains to,
            // and the companion container this job started, if it did.
            proxyUrl: "", proxyHttpsUrl: "", upstreamUrl: "",
            upstreamDirectUrl: "", listenerAnchorPem: "",
            companionCreated: false,
            // THE ASSERTION KEY (#1827's follow-up, phase 3): what
            // issue-pep-credential answered for the container's key, or
            // null where nothing registered one (an older launcher that
            // wrote no request).
            assertion: null,
            // The two PEPs section 11 starts on keys alone, by name.
            keyPeps: [] };

// The last of the container's own log. Every failure message below ends with
// this, because the interesting failures here are ones where the PEP said
// exactly what was wrong — "the PDP answered 401", "NONE IS THE ROOT",
// MODULE_NOT_FOUND naming an engine module the Dockerfile forgot — and a test
// that reported only its own timeout would throw that sentence away.
function pepLog(lines) {
  log.debug("Entering pepLog().");
  if (!pep.created && !LAUNCHER_STARTED_IT) {
    log.debug("Leaving pepLog().");
    return "\n(the PEP container was never created)";
  }
  // TRIED EVEN FOR A CONTAINER THIS JOB DID NOT CREATE, because under
  // ./local-run-tests.sh (removed 2026-09-16) the launcher's container and
  // this process were on the same machine, and its log is the most useful
  // thing a failure here can carry. Under ./run-tests.sh there is no
  // docker to ask, so the fallback names the container and the command
  // rather than pretending.
  const got = dockerQuiet(["logs", "--tail", String(lines || 30), PEP_NAME]);
  if (!got.ok && LAUNCHER_STARTED_IT) {
    log.debug("Leaving pepLog().");
    return "\n(this runner cannot read the PEP container's log — there is no " +
           "docker here. It is the container the launcher started; " +
           "`docker logs " + PEP_NAME + "` on the machine running the stack " +
           "is where its own account of this is.)";
  }
  const state = dockerQuiet(["inspect", "-f",
                             "{{.State.Status}} exit={{.State.ExitCode}}",
                             PEP_NAME]);
  log.debug("Leaving pepLog().");
  return "\n--- the PEP container (" + (state.out || "state unknown") +
         ") ---\n" + (got.out || got.err || "(no output)") +
         "\n--- end of the PEP container's log ---";
}

// ---------------------------------------------------------------------------
// WHERE THE SERVICE IS, AND THEREFORE WHERE THE PEP GOES.
//
// This job has been run in three stacks (two since 2026-09-16) and the service
// is not the same KIND of thing in each, so the network is discovered rather
// than assumed:
//
//   * `./run-tests.sh` puts the service in a CONTAINER on a compose
//     network (as `./local-run-tests.sh` did, with a published port, until it
//     was removed on 2026-09-16). The PEP joins that
//     network, dials the service by its container HOSTNAME on the INTERNAL port
//     — which is what `docker-compose.yml` ships and is a name in the
//     certificate — and publishes a port of its own for this job to reach.
//   * a coverage run and a bare `run-report.js` run the service as a plain
//     process on this machine. There is no compose network to join, so the PEP
//     runs on the HOST network: it dials the same URL this job was given, and
//     the nudge comes back to a port on the same loopback. It is still the
//     image, still built from this tree, and still a container.
//
// The discriminator is a container publishing the port this job was pointed at.
// Nothing else here reads it, and a wrong answer is a failure at the first pull
// with the PEP's own message in it rather than a silent fallback.
// ---------------------------------------------------------------------------
function findTheNetwork() {
  log.debug("Entering findTheNetwork().");
  const target = new URL(base);
  const port = target.port ||
               (target.protocol === "https:" ? "443" : "80");
  const local = ["localhost", "127.0.0.1", "::1", "[::1]"];
  if (local.indexOf(target.hostname) < 0) {
    // The service is somewhere this job cannot reason about — which in practice
    // means a containerized runner dialling a compose name, and that runner has
    // no docker and never reaches this function. Said plainly rather than
    // guessed at.
    throw new Error("the service under test is at " + target.hostname +
                    ", which is neither this machine nor a published port " +
                    "this job can find a container for. It cannot work out " +
                    "which docker network to put the PEP on.");
  }
  const listed = dockerQuiet(["ps", "--format", "{{.Names}}\t{{.Ports}}"]);
  let found = null;
  listed.out.split("\n").forEach(function (line) {
    if (found || !line.trim()) {
      return;
    }
    const parts = line.split("\t");
    // `0.0.0.0:18081->8081/tcp` — the published port, then the one inside.
    const mapping = new RegExp(":" + port + "->(\\d+)/tcp").exec(
        parts[1] || "");
    if (mapping) {
      found = { container: parts[0], containerPort: mapping[1] };
    }
  });
  if (!found) {
    log.info("No container publishes port " + port + ", so the service under " +
             "test is a plain process on this machine. The PEP will run on " +
             "the HOST network and dial " + base + " directly.");
    log.debug("Leaving findTheNetwork(). Host.");
    return { mode: "host", network: "host", pdpUrl: base + "/realm/" + REALM };
  }
  const hostname = docker(["inspect", "-f", "{{.Config.Hostname}}",
                           found.container], "reading the service's hostname");
  const networks = docker(["inspect", "-f",
                           "{{range $k,$v := .NetworkSettings.Networks}}" +
                           "{{$k}} {{end}}", found.container],
                          "reading the service's networks").split(/\s+/)
                     .filter(function (n) { return n; });
  const network = networks[0];
  if (!network || network === "bridge" || network === "host") {
    // THE DEFAULT BRIDGE HAS NO DNS. Container names resolve only on a
    // user-defined network, which is what compose creates — so a service on
    // `bridge` would leave the PEP unable to resolve the name in the
    // certificate, and the honest answer is the host network rather than an IP
    // address that no certificate names.
    log.warn("The service container " + found.container + " is on \"" +
             (network || "no") + "\" network, which has no DNS for container " +
             "names. Falling back to the HOST network.");
    log.debug("Leaving findTheNetwork(). Host, no usable network.");
    return { mode: "host", network: "host", pdpUrl: base + "/realm/" + REALM };
  }
  const scheme = target.protocol.replace(/:$/, "");
  const pdpUrl = scheme + "://" + hostname + ":" + found.containerPort +
                 "/realm/" + REALM;
  log.info("The service is the container \"" + found.container + "\" on the " +
           "network \"" + network + "\". The PEP will join it and dial " +
           pdpUrl + " — the compose name and the INTERNAL port, which is " +
           "what docker-compose.yml ships and what the certificate names.");
  log.debug("Leaving findTheNetwork(). Bridge.");
  return { mode: "bridge", network: network, pdpUrl: pdpUrl };
}

// A PORT NOTHING ELSE HOLDS, for the HOST-network case only — on a bridge the
// container port is 9090 and docker picks the published one. Asked for rather
// than picked out of a range, for `tests/tools/service.js`'s reason: a fixed
// port is a job that fails when somebody's own stack is up.
function freePort() {
  log.debug("Entering freePort().");
  log.debug("Leaving freePort().");
  return new Promise(function (resolve, reject) {
    const probe = net.createServer();
    probe.on("error", reject);
    probe.listen(0, "127.0.0.1", function () {
      const port = probe.address().port;
      probe.close(function () {
        log.debug("Leaving freePort(). " + port);
        resolve(port);
      });
    });
  });
}

// The loopback port docker published a container port of the PEP's on
// (#1760: the proxy's two listeners, beside 9090 and 9443 above).
function publishedPort(containerPort) {
  log.debug("Entering publishedPort(). " + containerPort);
  const mapped = docker(["port", PEP_NAME, containerPort],
                        "reading the PEP's published port " + containerPort);
  const parsed = /:(\d+)\s*$/.exec(mapped.split("\n")[0] || "");
  assert.ok(parsed, "docker port said \"" + mapped + "\" for " +
            containerPort + ", which carries no port this job can dial");
  log.debug("Leaving publishedPort(). " + parsed[1]);
  return parsed[1];
}

// ---------------------------------------------------------------------------
// THE IMAGE, BUILT FROM THIS TREE ON EVERY RUN.
//
// Not "if it is missing": a cached rebuild is a fifth of a second and a STALE
// image is the one failure this whole file would be unable to report — it would
// go green about an engine nobody is running. The build is also an assertion in
// its own right, and the loudest one here: the Dockerfile names the seven
// engine modules individually, so a module added to `engine.js` and not to it
// fails RIGHT HERE with the missing file named.
// ---------------------------------------------------------------------------
function buildTheImage() {
  log.debug("Entering buildTheImage().");
  const started = Date.now();
  log.info("Building " + IMAGE + " from " + REPO_ROOT + " with " +
           PEP_DOCKERFILE + " — the same Dockerfile and the same context " +
           "docker-compose.yml uses.");
  const id = docker(["build", "--quiet", "--tag", IMAGE,
                     "--file", path.join(REPO_ROOT, PEP_DOCKERFILE),
                     REPO_ROOT],
                    "building the remote PEP image. THE BUILD ITSELF IS AN " +
                    "ASSERTION: xacml-pep/Dockerfile names the seven engine " +
                    "modules one at a time, so a module added to engine.js " +
                    "and not to that file fails here");
  log.info("Built " + IMAGE + " (" + id.slice(0, 19) + "…) in " +
           (Date.now() - started) + "ms.");
  log.debug("Leaving buildTheImage().");
}

// ---------------------------------------------------------------------------
// THE CONTAINER THE LAUNCHER STARTED. Nothing is created here and nothing is
// torn down — `tests/CLAUDE.md`'s rule for the service applies to this exactly
// as it does to that: WHOEVER STARTED IT STOPS IT, and two owners of one
// container is how a run ends by taking down a stack somebody asked to keep.
//
// What this does is check the three variables agree with each other and that
// something is answering. It does NOT wait for the PEP to be holding anything:
// it cannot be, because the realm it polls is created later in this file.
// ---------------------------------------------------------------------------
async function attachToThePep() {
  log.debug("Entering attachToThePep().");
  assert.ok(REALM, "XACML_PEP_URL is set and XACML_PEP_REALM is not. The " +
    "three variables arrive together: without the realm this job would " +
    "create policy in one place and assert against a container polling " +
    "another, and the failure would look like a PEP that never converges.");
  assert.ok(PEP_NAME, "XACML_PEP_URL is set and XACML_PEP_NAME is not. The " +
    "name is how this job finds the PEP's row on /admin-api/xacml/peps, and " +
    "a wrong one reads as a PEP that never registered.");
  pep.url = PROVIDED_URL;
  pep.mode = "provided";
  pep.network = "the launcher's stack";
  // The HTTPS listener's two facts arrive from the launcher with the other
  // three. Their absence is not asserted here, where it would stop every
  // section: `theListenerServesARealmCertificate()` names the missing variable
  // when it gets there.
  pep.httpsUrl = String(process.env.XACML_PEP_HTTPS_URL || "")
    .replace(/\/+$/, "");
  pep.serverCertDir = String(process.env.XACML_PEP_SERVER_CERT_DIR || "");
  log.info("Driving the remote PEP container the launcher started: " +
           pep.url + ", registered as \"" + PEP_NAME + "\", polling the " +
           "realm \"" + REALM + "\" which this job creates below.");
  await until("the PEP container the launcher started to answer",
              async function () {
    const r = await pepGet("/healthcheck");
    return { ok: r.status === 200, note: "GET /healthcheck said " + r.status };
  });
  log.debug("Leaving attachToThePep().");
}

// ---------------------------------------------------------------------------
// OR ONE OF THIS JOB'S OWN, WHICH IS WHAT A HAND-RUN AND A COVERAGE RUN GET.
//
// Configured IDENTICALLY to the one the launchers start — the same intervals,
// the same bias, and **a client certificate** — so that what the sections
// below assert is one deployment rather than two. The only thing that differs
// is who created it, and therefore who removes it.
//
// **THAT WORD "IDENTICALLY" WAS A LIE FOR THREE DAYS AND THIS COMMENT SAID IT
// OUT LOUD.** It read "no client certificate, no anchor", which was an
// accurate description of both deployments until 2026-09-06 — the day
// `/xacml/pep/*` began requiring a VERIFIED chain holding `REMOTE_PEPS`. The
// launchers were taught to mint one (`tests/tools/pep-credential.js`,
// mounted at `/certs`); this path was not, so a container started here
// registered as an unauthenticated caller and the PDP refused it with 403.
//
// **NOTHING CAUGHT IT BECAUSE NOTHING RAN IT.** Both launchers take the
// attach path, and the two that take this one — `./run-coverage.sh` and a
// bare `run-report.js` — were red on `/admin-api`'s own gate from the same
// day, dying in the preflight 136ms before they reached any of this. One
// masked gate hid another.
// ---------------------------------------------------------------------------

// **THE COMMON NAME IS `PEP_NAME` AND THAT IS FORCED, NOT CHOSEN.** An
// authenticated registration is named by the PDP from the CERTIFICATE and
// never from the body — `xacml.js` says why in as many words: a PEP that
// could name itself while holding a certificate could register as somebody
// else's PEP and take over their row, which is the one thing in this family
// that would be a security bug rather than a fidelity one. So the CN, the row
// in `ou=peps`, the `?pep=` every pull carries and this container's hostname
// are one string, which is exactly what PEP_NAME's own comment already
// requires of the other three.
//
// The LAUNCHERS get this for free by pinning both to the seeded
// `remote-pep-1`. This path cannot: its container name has to be unique per
// run, so the identity has to be created rather than found — which is the
// same two directory writes a real second enforcement point costs, and
// `ldap_server.js`'s seed comment describes them exactly ("a deployment using
// a different common name adds its own member to this group").
function containerSubject() {
  log.debug("Entering containerSubject().");
  log.debug("Leaving containerSubject().");
  return "CN=" + PEP_NAME + ",OU=remote-peps,O=iya-sts tests";
}

// The entry and the membership, in THIS RUN'S REALM — the directory is per
// realm, so the seeded `remote-peps` group in the default realm is not the one
// the PDP will read when it resolves this certificate.
async function provisionTheContainersIdentity() {
  log.debug("Entering provisionTheContainersIdentity().");
  // With the attributes a real entry carries and nothing invented — product
  // mode invents no persona onto an entry, and a directory entry for an
  // enforcement point is a record somebody reads. The realm's attribute
  // policy (#396) requires givenName, sn and mail of every entry under
  // ou=users in product mode.
  //
  // **A DEVELOPMENT REALM ALREADY HOLDS IT** (2026-11-16, the first local
  // memory run after phase 4): development seeds `cn=remote-pep-1` in every
  // realm's directory and in `remote-peps` (ldap_server.js, demo data), so a
  // create there is refused as a username already held (STS-LDAP-0005).
  // That entry is the one the container's assertion key is registered on,
  // so it is used as it stands; product seeds none and the create runs.
  const existing = await get(api("/users/certificates?user=" +
                                 encodeURIComponent(PEP_NAME)));
  if (existing.status === 200) {
    log.info(PEP_NAME + " is already in " + REALM + "'s directory (" +
             ((existing.body || {}).dn || "?") + "), which is development's " +
             "seed; it is used as it stands.");
  }
  const made = existing.status === 200 ? existing :
    await postJson(api("/users/create"), {
    username: PEP_NAME, invent: false,
    attributes: { cn: PEP_NAME, givenName: "Remote", sn: "Remote PEP",
                  mail: PEP_NAME + "@xacml-remote-pep.test",
                  displayName: PEP_NAME,
                  description:
                    "the remote XACML PEP container this job drives" }
  });
  assert.ok(made.status === 200,
    "POST /admin-api/users/create should put " + PEP_NAME + " in " + REALM +
    "'s directory; it answered " + made.status + ". A client certificate " +
    "whose subject resolves to NO entry is an unauthenticated caller however " +
    "well it verifies, so the registration below would be refused with a 403 " +
    "naming REMOTE_PEPS and nothing would say the entry was the missing part.");
  const joined = await postJson(api("/groups/add-member"),
                                { group: "remote-peps", member: PEP_NAME });
  assert.ok(joined.status === 200,
    "POST /admin-api/groups/add-member should put " + PEP_NAME + " in " +
    "cn=remote-peps; it answered " + joined.status + ". That group is what " +
    "`roles.remotePepGroup` names and the built-in REMOTE_PEPS role is " +
    "computed from — the certificate says WHO and this says WHETHER, and " +
    "without it the chain verifies perfectly and is still refused.");
  log.debug("Leaving provisionTheContainersIdentity().");
}

// THE CONTAINER'S ONE CREDENTIAL: ITS ASSERTION KEY (#1827's follow-up).
// Through phase 3 a client certificate was minted here too, its Root CA
// trusted and its leaf stored on the entry; PHASE 4 (rcbj, 2026-11-16)
// retired the PEP's client certificate, so only the key is made.
async function mintTheContainersCredential() {
  log.debug("Entering mintTheContainersCredential().");
  await provisionTheContainersIdentity();
  // ON DISK BECAUSE THE PEP READS FILES, and in a directory of this job's
  // own rather than the launcher's `tests/report/pep-credential`: two runs on
  // one machine must not share it, and this one is removed with the
  // container. `mkdtemp` rather than a name built from the stamp, so the
  // collision cannot be constructed at all.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "iya-sts-pep-cert-"));
  // THE ASSERTION KEY (#1827's follow-up, phase 3), generated HERE — the
  // service never sees it — and registered from its request, which is
  // what a launcher does with the request it wrote (registerTheKey()).
  // 0644 AND NOT 0600, deliberately: the mount is read-only and the process
  // inside that image is not this user, so a key only this user can read
  // is a container that starts and quietly has no key.
  const made = await credentials.assertionRequest({ keyAlg: "ec-p256",
                                                    name: PEP_NAME });
  fs.writeFileSync(path.join(dir, "pep-assertion.key"), made.privateKeyPem,
                   { mode: 0o644 });
  await registerTheKey(made.csrPem);
  log.info("Registered the assertion key the PEP container signs its " +
           "token requests with; it is mounted at /certs.");
  log.debug("Leaving mintTheContainersCredential().");
  return dir;
}

async function startThePep() {
  log.debug("Entering startThePep().");
  buildTheImage();
  const where = findTheNetwork();
  pep.mode = where.mode;
  pep.network = where.network;
  pep.pdpUrl = where.pdpUrl;

  const environment = {
    PEP_PDP_URL: pep.pdpUrl,
    PEP_NAME: PEP_NAME,
    PEP_RESOURCE: "https://example.test/records",
    PEP_BIAS: "deny-biased",
    PEP_POLL_INTERVAL_MS: String(POLL_MS),
    PEP_HEARTBEAT_INTERVAL_MS: String(HEARTBEAT_MS),
    PEP_TIMEOUT_MS: "5000",
    PEP_LOG_LEVEL: appconfig.LOG_LEVEL || "info",
    // THE SHIPPED SETTING. The mock regenerates and self-signs its key on every
    // start, so no image, CA bundle or environment can hold an anchor for it —
    // which is why `docker-compose.yml` sets this too and why `pep.js` logs it
    // on every start rather than once.
    PEP_TLS_INSECURE: "true",
    // THE ASSERTION KEY (#1827's follow-up, phase 3), as the launchers mount
    // it: every call carries a DPoP-bound token from it, and nothing else —
    // no PEP_TLS_CERT since phase 4 retired the PEP's client certificate.
    PEP_ASSERTION_KEY: "/certs/pep-assertion.key",
    // THE HTTPS LISTENER'S PAIR (2026-09-13): two paths that are empty when the
    // container starts, exactly as the launchers arrange it — the realm issues
    // the pair only once the PEP has registered, and this job writes it.
    PEP_HTTPS_CERT: "/certs/server/pep-server.crt",
    PEP_HTTPS_KEY: "/certs/server/pep-server.key",
    PEP_HTTPS_RELOAD_INTERVAL_MS: "1000",
    // THE REVERSE PROXY'S LISTENERS (#1760), as the launchers set them, and
    // the session recheck at zero for section 10's sign-out.
    PEP_PROXY_PORT: "9180",
    PEP_PROXY_HTTPS_PORT: "9543",
    PEP_PROXY_SESSION_RECHECK_MS: "0",
    // PLAIN HTTP ON, EXPLICITLY (#1760: off by default): this job asserts
    // the registration, the pull and the refused nudge over 9090 before it
    // has issued the HTTPS pair, and the credential's CRLs are served there
    // (docker-compose-run-tests.yml gives the stack's reasons in full).
    PEP_HTTP: "true",
    PEP_PROXY_HTTP: "true"
  };

  pep.certDir = await mintTheContainersCredential();
  pep.serverCertDir = path.join(pep.certDir, "server");
  // World-writable for the reason the launchers give: the container is not
  // this user, and nothing in it is a key worth more than one run.
  fs.mkdirSync(pep.serverCertDir, { mode: 0o777 });
  fs.chmodSync(pep.serverCertDir, 0o777);

  const create = ["create", "--name", PEP_NAME, "--hostname", PEP_NAME,
                  "--network", pep.network,
                  // READ-ONLY: this container has no business writing to a
                  // private key, and the mount is the only thing standing
                  // between a test credential and the image.
                  "--volume", pep.certDir + ":/certs:ro"];
  if (pep.mode === "bridge") {
    // PUBLISHED ON THE LOOPBACK AND ON A PORT DOCKER CHOOSES. This job reaches
    // the PEP from outside the network, and a fixed 9090 would collide with the
    // demonstration container `docker compose --profile xacml up` starts.
    create.push("--publish", "127.0.0.1::9090");
    create.push("--publish", "127.0.0.1::9443");
    create.push("--publish", "127.0.0.1::9180");
    create.push("--publish", "127.0.0.1::9543");
    // NO PEP_NOTIFY_URL: THE PEP DERIVES IT (2026-11-14, rcbj's "option
    // 1"). The PDP dials it across the bridge by the container's own name,
    // over HTTPS: the container's hostname is PEP_NAME, section 1b's
    // certificate names it (the registered name) beside `localhost`, and
    // the PEP picks the certificate's DNS name that equals its hostname —
    // https://<PEP_NAME>:9443/notify, which section 6 asserts.
  } else {
    pep.containerPort = await freePort();
    pep.hostPort = pep.containerPort;
    environment.PEP_PORT = String(pep.containerPort);
    pep.httpsContainerPort = await freePort();
    environment.PEP_HTTPS_PORT = String(pep.httpsContainerPort);
    const proxyPort = await freePort();
    const proxyHttpsPort = await freePort();
    environment.PEP_PROXY_PORT = String(proxyPort);
    environment.PEP_PROXY_HTTPS_PORT = String(proxyHttpsPort);
    pep.proxyUrl = "http://127.0.0.1:" + proxyPort;
    pep.proxyHttpsUrl = "https://localhost:" + proxyHttpsPort;
    // On the host network the service is a process on this same loopback, so
    // this is the address it dials — and it is still a real outbound request
    // made by the PDP to a listener it does not share a process with. SET,
    // not derived (2026-11-14): the service dials the loopback ADDRESS,
    // which derivation never yields (IP addresses are skipped), and on the
    // host network the hostname is this machine's, which the certificate
    // section 1b issues does not name.
    environment.PEP_NOTIFY_URL = "https://127.0.0.1:" +
                                 pep.httpsContainerPort + "/notify";
  }
  Object.keys(environment).forEach(function (key) {
    create.push("--env", key + "=" + environment[key]);
  });
  create.push(IMAGE);

  dockerQuiet(["rm", "-f", PEP_NAME]);
  docker(create, "creating the PEP container");
  pep.created = true;
  docker(["start", PEP_NAME], "starting the PEP container");

  if (pep.mode === "bridge") {
    const mapped = docker(["port", PEP_NAME, "9090"],
                          "reading the PEP's published port");
    const parsed = /:(\d+)\s*$/.exec(mapped.split("\n")[0] || "");
    assert.ok(parsed, "docker port said \"" + mapped + "\", which carries no " +
              "port this job can dial");
    pep.hostPort = parsed[1];
    const mappedHttps = docker(["port", PEP_NAME, "9443"],
                               "reading the PEP's published HTTPS port");
    const parsedHttps = /:(\d+)\s*$/.exec(mappedHttps.split("\n")[0] || "");
    assert.ok(parsedHttps, "docker port said \"" + mappedHttps + "\" for " +
              "9443, which carries no port this job can dial");
    pep.httpsUrl = "https://localhost:" + parsedHttps[1];
    pep.proxyUrl = "http://127.0.0.1:" + publishedPort("9180");
    pep.proxyHttpsUrl = "https://localhost:" + publishedPort("9543");
  } else {
    pep.httpsUrl = "https://localhost:" + pep.httpsContainerPort;
  }
  pep.url = "http://127.0.0.1:" + pep.hostPort;

  log.info("The PEP container " + PEP_NAME + " is starting on the " +
           pep.network + " network; this job reaches it at " + pep.url + ".");

  // `pep.js` REGISTERS AND PULLS BEFORE IT LISTENS, which is what makes this
  // wait worth more than a liveness check: by the time the port answers, the
  // first registration and the first pull have both been attempted and their
  // outcome — whatever it was — is already on `GET /`.
  await until("the PEP container's port to answer", async function () {
    const r = await pepGet("/healthcheck");
    return { ok: r.status === 200, note: "GET /healthcheck said " + r.status };
  });
  log.info("The PEP is up.");
  log.debug("Leaving startThePep().");
}

function stopThePep() {
  log.debug("Entering stopThePep().");
  stopTheCompanion();
  if (!pep.created) {
    // WHOEVER STARTED IT STOPS IT. A launcher-provided container belongs to the
    // launcher's teardown, which also collects its log into the run's report
    // directory — and a second owner is how a run ends by removing a container
    // somebody asked to keep.
    if (LAUNCHER_STARTED_IT) {
      log.info("Leaving the PEP container alone: the launcher started it and " +
               "the launcher's teardown removes it.");
    }
    log.debug("Leaving stopThePep(). Nothing was created here.");
    return;
  }
  // THE LOG FIRST AND THE REMOVAL SECOND, at debug, so that a run somebody is
  // reading afterwards has the container's own account of itself even though
  // the container is gone. `docker rm -f` rather than a stop and a wait: this
  // container holds two unref'd timers and a listener and there is no shutdown
  // path in `pep.js` that closes them, because a container is stopped by its
  // runtime and that is the whole of its lifecycle.
  const tail = dockerQuiet(["logs", "--tail", "80", PEP_NAME]);
  log.debug("The PEP container's log:\n" + (tail.out || tail.err || "(none)"));
  const removed = dockerQuiet(["rm", "-f", PEP_NAME]);
  if (!removed.ok) {
    log.warn("Could not remove the PEP container " + PEP_NAME + ": " +
             removed.err);
  } else {
    log.info("Removed the PEP container " + PEP_NAME + ".");
  }
  pep.created = false;
  // AND THE CREDENTIAL, WHICH OUTLIVES THE CONTAINER BY NOTHING. It is a
  // private key in the machine's temp directory; leaving it there would be
  // this job's one durable side effect, and the realm it deliberately leaves
  // behind is a realm rather than a key. Failure to remove it is a warning
  // and never the thing that fails a passing run.
  if (pep.certDir) {
    try {
      fs.rmSync(pep.certDir, { recursive: true, force: true });
    } catch (e) {
      log.warn("Could not remove the PEP container's credential directory " +
               pep.certDir + ": " + e.message);
    }
    pep.certDir = "";
  }
  log.debug("Leaving stopThePep().");
}

function pepGet(p) {
  log.debug("Entering pepGet().");
  log.debug("Leaving pepGet().");
  return fetchJson(pep.url + p);
}

// The PEP's whole self-report. Everything below reads it through this, so that
// a failure message can always say what the PEP thought it was holding.
async function pepOverview() {
  log.debug("Entering pepOverview().");
  const r = await pepGet("/");
  assert.strictEqual(r.status, 200,
    "GET / on the PEP answered " + r.status + ". " + pepLog());
  log.debug("Leaving pepOverview().");
  return r.body;
}

// ---------------------------------------------------------------------------
// WAITING FOR SOMETHING TO CONVERGE, WHICH IS MOST OF WHAT THIS FILE DOES.
//
// Two rules, and both are `wait_for.js`'s from the browser jobs, restated for a
// job that polls HTTP rather than a page:
//
//   1. IT MUST STILL BE ABLE TO FAIL. A wait that cannot time out is worse than
//      a sleep, so this one has a budget and throws when it runs out.
//   2. THE FAILURE SAYS WHAT IT LAST SAW, and here it says what the CONTAINER
//      said too. A timeout that reported only "gave up after 40s" would throw
//      away the one sentence that explains it — `sync.js` writes a reason for
//      every failed pull, and it is nearly always the answer.
//
// It also checks that the container is still RUNNING on every turn, because the
// commonest way for a wait here to be doomed is a container that exited, and
// waiting forty seconds to say "the port did not answer" about a process that
// died in the first second is the least useful thing this could do.
// ---------------------------------------------------------------------------
async function until(what, probe, budgetMs) {
  log.debug("Entering until(). what=" + what);
  const budget = budgetMs || CONVERGE_MS;
  const started = Date.now();
  const deadline = started + budget;
  let last = "nothing was seen at all";
  while (Date.now() < deadline) {
    // ASKED ONLY WHERE IT CAN BE ANSWERED. `dockerQuiet` reports failure
    // rather than throwing, so a runner with no docker simply never takes this
    // branch — and the commonest doomed wait, a container that exited, is
    // still caught wherever the daemon is reachable.
    const state = dockerQuiet(["inspect", "-f", "{{.State.Running}}",
                               PEP_NAME]);
    if (state.ok && state.out === "false") {
      throw new Error("Waiting for " + what + ", but THE PEP CONTAINER HAS " +
                      "STOPPED. " + pepLog());
    }
    let seen;
    try {
      /* eslint-disable no-await-in-loop */
      seen = await probe();
      /* eslint-enable no-await-in-loop */
    } catch (e) {
      // A REFUSED CONNECTION IS AN ORDINARY POLL RESULT HERE, not a failure:
      // this loop is what waits for the container's listener to come up in the
      // first place. It is kept as the "last seen" so that a genuine outage
      // still reports the error rather than a bare timeout.
      seen = { ok: false, note: "the probe threw: " + e.message };
    }
    if (seen.ok) {
      seen.ms = Date.now() - started;
      log.debug("Leaving until(). " + what + " — after " + seen.ms + "ms.");
      return seen;
    }
    last = seen.note;
    /* eslint-disable no-await-in-loop */
    await sleep(100);
    /* eslint-enable no-await-in-loop */
  }
  log.debug("Leaving until().");
  throw new Error("Gave up after " + budget + "ms waiting for " + what +
                  ". Last seen: " + last + pepLog());
}

// A decision AT THE REMOTE PEP. Every parameter other than the three XACML ones
// becomes a subject attribute the CALLER asserted about itself — which is all
// a PEP had to work from before `xacml-pep/pip.js`, and what section 3 still
// shows deciding where the directory holds nothing.
async function askThePep(query) {
  log.debug("Entering askThePep(). " + JSON.stringify(query));
  const url = new URL(pep.url + "/protected");
  Object.keys(query).forEach(function (key) {
    url.searchParams.set(key, query[key]);
  });
  const r = await fetchJson(url.toString());
  assert.ok(r.body && typeof r.body.allowed === "boolean",
    "GET /protected on the PEP should answer a decision either way; it " +
    "answered " + r.status + " " + String(r.text).slice(0, 300) + pepLog());
  log.debug("Leaving askThePep(). " + r.status + " " + r.body.decision);
  return r;
}

// The same question AT THE PDP, in the JSON Profile, so that section 3 can put
// the two answers beside each other.
async function askThePdp(subject, action) {
  log.debug("Entering askThePdp(). subject=" + subject + " action=" + action);
  const r = await certPostJson(realmUrl("/xacml/pdp"), { Request: {
    AccessSubject: { Attribute: [
      { AttributeId: "urn:oasis:names:tc:xacml:1.0:subject:subject-id",
        Value: subject }
    ] },
    Action: { Attribute: [
      { AttributeId: "urn:oasis:names:tc:xacml:1.0:action:action-id",
        Value: action }
    ] },
    Resource: { Attribute: [
      { AttributeId: "urn:oasis:names:tc:xacml:1.0:resource:resource-id",
        Value: "https://example.test/records", DataType: "anyURI" }
    ] }
  } });
  // THE LENGTH AS WELL AS THE TYPE. A JSON Profile response is an object with a
  // Response ARRAY, and an empty one would take the next line into a TypeError
  // about `undefined` — which names this file rather than the answer that was
  // wrong.
  assert.ok(r.status === 200 && r.body && Array.isArray(r.body.Response) &&
            r.body.Response.length,
    "POST /xacml/pdp answered " + r.status + " " +
    String(r.text).slice(0, 300));
  log.debug("Leaving askThePdp(). " + r.body.Response[0].Decision);
  return r.body.Response[0];
}

// The PEP's row on the PDP's console, by name. `null` when the register has
// never heard of it, which is a state section 1 has to be able to tell from a
// row that exists and says something unwelcome.
async function pepRow() {
  log.debug("Entering pepRow().");
  const r = await get(api("/xacml/peps"));
  assert.strictEqual(r.status, 200,
    "GET /admin-api/xacml/peps answered " + r.status);
  const found = (r.body.peps || []).filter(function (one) {
    return one.name === PEP_NAME;
  });
  log.debug("Leaving pepRow().");
  return { register: r.body, row: found.length ? found[0] : null };
}

// ---------------------------------------------------------------------------
// WAIT FOR THE CONTAINER TO FIND THE REALM THIS JOB JUST MADE.
//
// A launcher-started PEP has been polling `/realm/<REALM>` since the stack came
// up, getting a 404 from a realm that did not exist and failing to register.
// Now that it does exist, two things have to happen on ITS timers and not on
// this job's: the retried registration has to succeed, and a pull has to load
// the policy. Both land within one polling interval.
//
// **THIS IS A WAIT AND NOT AN ASSERTION.** Section 1 makes the assertions, and
// it can only make them once the state has settled — a read taken while the
// container is still holding what it had before would fail on a race rather
// than on a defect. What this does assert is the SHAPE of a failure to settle:
// the container believes it is registered and this realm's register does not
// list it, which `registerIfNeeded()` cannot recover from — it does not try
// again once it has succeeded, so that container never comes back on the
// console.
//
// **THAT USED TO BE THE ORDINARY OUTCOME OF A HAND-RUN AGAINST A KEPT STACK
// AND IS NOT ANY MORE**, which is worth saying because the sentence below is
// what a person will read when it fires. The row went away with the realm the
// previous run REMOVED; this suite removes no realms since 2026-09-06, so a
// leftover container's row is still there and its realm still stands. What is
// left to cause it is a row removed by hand at /admin/xacml/peps, or a
// container registered against a DIFFERENT realm — a stack whose
// XACML_PEP_REALM changed under a container that outlived it.
// ---------------------------------------------------------------------------
async function waitForItToFindTheRealm() {
  log.debug("Entering waitForItToFindTheRealm().");
  log.info("Waiting for the PEP to register in " + REALM + " and pull " +
           POLICY_A + " — on its own timers, at most one " + POLL_MS +
           "ms interval away.");
  await until("the PEP to register in the realm this job just created",
              async function () {
    const seen = await pepOverview();
    if (seen.registration.registered) {
      return { ok: true };
    }
    return { ok: false, note: "it is not registered yet: " +
                              seen.registration.why };
  });
  const registered = await pepOverview();
  const there = await pepRow();
  assert.ok(there.row,
    "the PEP believes it is registered (\"" + registered.registration.why +
    "\") and " + REALM + "'s register does not list \"" + PEP_NAME + "\". " +
    "THE LIKELIEST CAUSE IS A CONTAINER REGISTERED SOMEWHERE ELSE: it " +
    "registered against another realm — a stack whose XACML_PEP_REALM " +
    "changed under a container that outlived it — or its row was removed by " +
    "hand at /admin/xacml/peps. `registerIfNeeded()` does not try again once " +
    "it has succeeded, so it will not recover on its own. Both launchers " +
    "recreate the container, so this is a hand-run against a kept stack — " +
    "restart it. The register holds " +
    JSON.stringify((there.register.peps || []).map(function (one) {
      return one.name;
    })) + pepLog());
  await until("the PEP to pull the policy this job just deployed",
              async function () {
    const seen = await pepOverview();
    return { ok: seen.holding.loaded &&
                 seen.holding.root === ID_OF[POLICY_A] &&
                 seen.holding.policyCount === 1,
             note: "it holds " + seen.holding.policyCount + " policy(ies), " +
                   "root " + seen.holding.root + " — " +
                   seen.holding.lastPullWhy };
  });
  log.info("The PEP has found the realm and is holding " + POLICY_A + ".");
  log.debug("Leaving waitForItToFindTheRealm().");
}

// ===========================================================================
// 1. THE CONTAINER REGISTERS — RETRYING UNTIL ITS PDP EXISTS — AND PULLS.
//
// What is asserted is that both sides agree about the same facts — that it
// registered and how, that it holds one policy, and WHICH document it starts
// evaluation from.
//
// **AND THAT IT GOT THERE BY RETRYING**, when the launcher started it: that
// container was aimed at a realm which did not exist for the first minutes of
// its life, so a registration that succeeded on the first attempt would mean
// something other than what this job thinks is running.
// ===========================================================================
// ===========================================================================
// THE ASSERTION KEY (#1827's follow-up, phase 3; rcbj 2026-11-16: "the
// service never holds the PEP's private key").
//
// The container signs an RFC 7523 self-assertion with ONE key
// (PEP_ASSERTION_KEY) for a DPoP-bound token per audience, and the service
// accepts that key once it is REGISTERED on the PEP's entry as an RFC 7523
// key certified by the realm's Issuing CA. The key is generated where the PEP
// is — by the launcher (`pep-credential.js --assertion --csr-only`, beside
// pep.key) or by this job for a container of its own — and only its
// certificate request reaches the service, through issue-pep-credential,
// which this job sends once the PEP's entry exists in its realm.
// ===========================================================================

// The launcher's request, beside the server pair's directory as pep.crt is
// (`launcherLeafPem()`); '' where the launcher wrote none.
function launcherAssertionCsr() {
  log.debug("Entering launcherAssertionCsr().");
  if (!process.env.XACML_PEP_SERVER_CERT_DIR) {
    log.debug("Leaving launcherAssertionCsr(). No directory.");
    return "";
  }
  const file = path.join(path.dirname(
    String(process.env.XACML_PEP_SERVER_CERT_DIR)), "pep-assertion.csr");
  let pem = "";
  try {
    pem = fs.readFileSync(file, "utf8");
  } catch (e) {
    log.debug("Caught in launcherAssertionCsr(): " + ((e && e.message) || e));
    pem = "";
  }
  log.debug("Leaving launcherAssertionCsr(). " + (pem ? "found" : "none"));
  return pem.indexOf("CERTIFICATE REQUEST") >= 0 ? pem : "";
}

// issue-pep-credential for the PEP's own request. Must work: the entry is in
// the group and so a service account (`designateRemotePep()`).
async function registerTheKey(csrPem) {
  log.debug("Entering registerTheKey().");
  pep.assertion = await credentials.issueAssertionCredential(
    { post: postJson }, base, "/realm/" + REALM, PEP_NAME, csrPem);
  log.info("Registered the PEP's assertion key: " + pep.assertion.urn +
           ", kid " + pep.assertion.kid + ".");
  log.debug("Leaving registerTheKey().");
}

async function registerTheLaunchersKey() {
  log.debug("Entering registerTheLaunchersKey().");
  const csr = launcherAssertionCsr();
  if (!csr) {
    log.warn("The launcher wrote no pep-assertion.csr beside " +
             String(process.env.XACML_PEP_SERVER_CERT_DIR || "(unset)") +
             ", so the container has no registered assertion key and " +
             "cannot authenticate (it presents no client certificate since " +
             "phase 4 of #1827's follow-up). Section 1c asserts what it can " +
             "without one.");
    log.debug("Leaving registerTheLaunchersKey(). None.");
    return;
  }
  await registerTheKey(csr);
  log.debug("Leaving registerTheLaunchersKey().");
}

// ---------------------------------------------------------------------------
// SECTION 1c: THE CONTAINER ON ITS KEY, AND THE REFUSALS AROUND IT.
// ---------------------------------------------------------------------------
async function itAuthenticatesOnItsKey() {
  log.debug("Entering itAuthenticatesOnItsKey().");
  log.info("=== 1c. The PEP authenticates on its own key ===");
  if (pep.assertion) {
    check("the PEP's key was certified as urn:sts:sa:" + PEP_NAME, function () {
      assert.strictEqual(pep.assertion.urn, "urn:sts:sa:" + PEP_NAME);
      assert.ok(!/PRIVATE KEY-----/.test(JSON.stringify(pep.assertion)),
        "issue-pep-credential's answer carries a private key; the service " +
        "never had one");
    });
    let seen = null;
    await until("the PEP to hold a DPoP-bound token for /xacml/pep",
                async function () {
      seen = await pepOverview();
      const token = ((seen.credential || {}).tokens || {})["xacml-pep"] || {};
      return { ok: token.held === true,
               note: "credential=" + JSON.stringify(seen.credential || null)
                 .slice(0, 400) };
    });
    check("its calls carry a token from PEP_ASSERTION_KEY", function () {
      assert.strictEqual(seen.credential.keySource, "PEP_ASSERTION_KEY",
        "the PEP signs with " + seen.credential.keySource);
    });
    // PHASE 4: no client certificate goes beside the token.
    check("and no client certificate beside it", function () {
      assert.strictEqual(seen.credential.clientCertificate, false,
        "GET /'s credential.clientCertificate is " +
        JSON.stringify(seen.credential.clientCertificate));
    });
  }

  // THE REFUSALS, each needing nothing from the container.
  const stranger = await postJson(api("/xacml/issue-pep-credential"),
    { name: STAFF_PERSON,
      csr: (await credentials.assertionRequest({})).csrPem });
  check("issue-pep-credential refuses a person outside remote-peps",
        function () {
    assert.strictEqual(stranger.status, 400,
      "issuing a PEP key to " + STAFF_PERSON + " answered " +
      stranger.status + " " + String(stranger.text).slice(0, 300));
  });
  const fresh = await credentials.assertionRequest({ keyAlg: "ec-p256",
                                                     name: PEP_NAME });
  const der = Buffer.from(fresh.csrPem.replace(/-----[A-Z ]+-----/g, "")
                            .replace(/\s+/g, ""), "base64");
  der[der.length - 3] ^= 0x5a;
  const tampered = await postJson(api("/xacml/issue-pep-credential"),
    { name: PEP_NAME, csr: der.toString("base64") });
  check("a request whose signature does not prove possession is refused",
        function () {
    assert.strictEqual(tampered.status, 400,
      "a tampered request answered " + tampered.status + " " +
      String(tampered.text).slice(0, 300));
  });
  const unregistered = await credentials.pepAccessToken(realmUrl(""),
    PEP_NAME, fresh.privateKeyPem, "xacml:pep", "/xacml/pep");
  check("a key that is not registered is refused at the grant", function () {
    assert.ok(unregistered.status === 400 || unregistered.status === 401,
      "a self-assertion signed with an unregistered key answered " +
      unregistered.status + " " + String(unregistered.text).slice(0, 300));
  });

  // A KEY THIS JOB HOLDS, for the two calls only a holder can make: the
  // token as Bearer, refused; as DPoP, admitted. Revoked afterwards.
  const probe = await credentials.issueAssertionCredential({ post: postJson },
    base, "/realm/" + REALM, PEP_NAME, fresh.csrPem);
  const got = await credentials.pepAccessToken(realmUrl(""), PEP_NAME,
    fresh.privateKeyPem, "xacml:pep", "/xacml/pep");
  check("a registered key is issued a DPoP-bound xacml:pep token",
        function () {
    assert.ok(got.status === 200 && got.token &&
              got.body.token_type === "DPoP",
      "the grant answered " + got.status + " " +
      String(got.text).slice(0, 300));
  });
  const where = realmUrl("/xacml/pep/policies");
  const asBearer = await fetchJson(where, { headers:
    credentials.dpopHeaders(fresh.privateKeyPem, "GET", where, got.token,
                            "Bearer") });
  check("the token sent as Bearer is refused", function () {
    assert.strictEqual(asBearer.status, 401,
      "GET /xacml/pep/policies with the token as Bearer answered " +
      asBearer.status + " " + String(asBearer.text).slice(0, 300));
  });
  const asDpop = await fetchJson(where, { headers:
    credentials.dpopHeaders(fresh.privateKeyPem, "GET", where, got.token) });
  check("the token sent as DPoP pulls the policies", function () {
    assert.strictEqual(asDpop.status, 200,
      "GET /xacml/pep/policies on the DPoP-bound token answered " +
      asDpop.status + " " + String(asDpop.text).slice(0, 300));
  });
  const revoked = await postJson(api("/pki/revoke"), {
    target: "person", identifier: PEP_NAME, purpose: "jwt",
    handle: probe.kid, reason: "cessationOfOperation" });
  const after = await credentials.pepAccessToken(realmUrl(""), PEP_NAME,
    fresh.privateKeyPem, "xacml:pep", "/xacml/pep");
  check("revoking that key refuses it at the grant", function () {
    assert.strictEqual(revoked.status, 200,
      "POST /admin-api/pki/revoke answered " + revoked.status + " " +
      String(revoked.text).slice(0, 300));
    assert.ok(after.status === 400 || after.status === 401,
      "the revoked key's grant answered " + after.status);
  });
  log.debug("Leaving itAuthenticatesOnItsKey().");
}

// ---------------------------------------------------------------------------
// SECTION 11: TWO PEPS ON KEYS ALONE, AS 8081 RUNS THEM (#1827's follow-up,
// phase 3). A realm of their own with `xacml.pepAuthentication` `token` —
// the default since phase 4, set anyway so the section means the same
// against an older service — so a certificate alone is refused there; two
// entries in its remote-peps group,
// each with a key generated here and registered from its request; and two
// containers with PEP_ASSERTION_KEY and NO PEP_TLS_CERT. Both must register
// and pull. The key reaches each container by `docker cp` before it starts,
// so no host path is needed.
//
// IT NEEDS A DOCKER DAEMON THIS JOB CAN REACH, which a launcher's runner
// container does not have (see test()). Without one the section says so at
// warn and asserts nothing; with one — a hand run, a coverage run — it runs.
// ---------------------------------------------------------------------------
async function twoPepsOnKeysAlone() {
  log.debug("Entering twoPepsOnKeysAlone().");
  log.info("=== 11. Two PEPs on keys alone, xacml.pepAuthentication=token ===");
  if (!pep.network || !pep.pdpUrl ||
      !dockerQuiet(["version", "--format", "{{.Server.Version}}"]).ok) {
    log.warn("Section 11 needs a docker daemon and the network this job's " +
             "own container ran on, and this run has neither (a launcher " +
             "owns the PEP). It asserted nothing.");
    log.debug("Leaving twoPepsOnKeysAlone(). Skipped.");
    return;
  }
  const realm = (REALM + "-keys").slice(0, 40);
  const prefix = "/realm/" + realm;
  const made = await postJson(base + "/admin-api/realms/create", {
    id: realm, domain: realm + ".example.net",
    name: "Remote PEPs on keys", description: "Created by " +
      "sts_xacml_remote_pep.js section 11; LEFT IN PLACE." });
  assert.ok(made.status === 200 && made.body && made.body.ok !== false,
    "creating " + realm + " answered " + made.status + " " +
    String(made.text).slice(0, 300));
  const setting = await postJson(base + prefix + "/admin-api/config/set",
    { key: "xacml.pepAuthentication", value: "token" });
  assert.ok(setting.status === 200,
    "setting xacml.pepAuthentication to token in " + realm + " answered " +
    setting.status + " " + String(setting.text).slice(0, 300));
  await postJson(base + prefix + "/admin-api/xacml/create-from-template", {
    template: "rbac", name: POLICY_A, p_roleAttribute: "employeeType",
    p_adminRoles: "admin", p_readerRoles: "staff",
    p_readerActions: "GET, HEAD" });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "iya-sts-pep-keys-"));
  try {
    for (const n of [1, 2]) {
      const name = (PEP_NAME + "-k" + n).slice(0, 40);
      const user = await postJson(base + prefix + "/admin-api/users/create", {
        username: name, invent: false,
        attributes: { cn: name, givenName: "Remote", sn: "Remote PEP",
                      mail: name + "@xacml-remote-pep.test",
                      displayName: name } });
      assert.strictEqual(user.status, 200, "creating " + name + " answered " +
                         user.status + " " + String(user.text).slice(0, 300));
      const joined = await postJson(base + prefix +
        "/admin-api/groups/add-member", { group: "remote-peps",
                                          member: name });
      assert.strictEqual(joined.status, 200, "adding " + name + " to " +
        "remote-peps answered " + joined.status);
      const key = await credentials.assertionRequest({ keyAlg: n === 1
        ? "ec-p256" : "rsa-2048", name: name });
      await credentials.issueAssertionCredential({ post: postJson }, base,
        prefix, name, key.csrPem);
      const file = path.join(dir, name + ".key");
      fs.writeFileSync(file, key.privateKeyPem, { mode: 0o644 });
      dockerQuiet(["rm", "-f", name]);
      docker(["create", "--name", name, "--hostname", name,
              "--network", pep.network,
              "--env", "PEP_PDP_URL=" +
                String(pep.pdpUrl).replace(/\/realm\/[^/]+\/?$/, "") + prefix,
              "--env", "PEP_NAME=" + name,
              "--env", "PEP_ASSERTION_KEY=/keys/pep-assertion.key",
              "--env", "PEP_TLS_INSECURE=true",
              "--env", "PEP_POLL_INTERVAL_MS=" + String(POLL_MS),
              "--env", "PEP_HEARTBEAT_INTERVAL_MS=" + String(HEARTBEAT_MS),
              "--env", "PEP_PORT=" + String(await freePort()),
              "--env", "PEP_HTTPS_PORT=" + String(await freePort()),
              "--env", "PEP_PROXY_PORT=" + String(await freePort()),
              "--env", "PEP_PROXY_HTTPS_PORT=" + String(await freePort()),
              IMAGE], "creating " + name);
      pep.keyPeps.push(name);
      docker(["cp", file, name + ":/keys/pep-assertion.key"],
             "copying " + name + "'s key into it");
      docker(["start", name], "starting " + name);
    }
    for (const name of pep.keyPeps) {
      let row = null;
      await until(name + " to register in " + realm + " on its key alone " +
                  "and pull", async function () {
        const r = await get(base + prefix + "/admin-api/xacml/peps");
        row = ((r.body && r.body.peps) || []).filter(function (one) {
          return one.name === name;
        })[0] || null;
        return { ok: !!row && row.authenticated === true &&
                     !!row.syncToken,
                 note: "row=" + JSON.stringify(row).slice(0, 300) + " " +
                       (dockerQuiet(["logs", "--tail", "5", name]).out ||
                        "") };
      });
      check(name + " registered and pulls with no client certificate, " +
            "xacml.pepAuthentication=token", function () {
        assert.ok(row && row.authenticated === true);
      });
    }
  } finally {
    pep.keyPeps.forEach(function (name) {
      dockerQuiet(["rm", "-f", name]);
    });
    pep.keyPeps = [];
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch (e) {
      log.warn("Could not remove " + dir + ": " + e.message);
    }
  }
  log.debug("Leaving twoPepsOnKeysAlone().");
}

async function itRegistersAndPulls() {
  log.debug("Entering itRegistersAndPulls().");
  log.info("=== The PEP container registers and pulls what is deployed ===");

  const seen = await pepOverview();

  check("the PEP registered with the PDP", function () {
    assert.strictEqual(seen.registration.registered, true,
      "the PEP could not register: " + seen.registration.why + pepLog());
    assert.strictEqual(seen.registration.name, PEP_NAME,
      "it registered as \"" + seen.registration.name + "\" and this job " +
      "drives \"" + PEP_NAME + "\"");
    assert.strictEqual(seen.registration.authenticated, true,
      "ON ITS ASSERTION KEY, BETWEEN TWO CONTAINERS. The launcher generated " +
      "the key with tests/tools/pep-credential.js --assertion and mounted " +
      "it; this job registered its request through issue-pep-credential, " +
      "and the registration carried a DPoP-bound token from it. It says " +
      JSON.stringify(seen.registration) + pepLog());
  });

  if (LAUNCHER_STARTED_IT) {
    check("and it got there by RETRYING, because its PDP did not exist when " +
          "it started", function () {
      assert.ok(seen.registration.attempts > 1,
        "the launcher started this container against /realm/" + REALM +
        " minutes before this job created that realm, so its first " +
        "registration MUST have failed and a later one MUST have succeeded. " +
        "It reports " + seen.registration.attempts + " attempt(s). One " +
        "attempt means something else is answering — a container from an " +
        "earlier run, or a realm this job did not create. Before " +
        "xacml-pep/sync.js retried, this arrangement was impossible: a PEP " +
        "that came up before its PDP enforced correctly for ever and " +
        "appeared on nobody's console." + pepLog());
    });
  }

  check("it is dialling the realm this job owns, by the address " +
        "docker-compose.yml ships", function () {
    // THE REALM FIRST, because it is the assertion that catches the
    // misconfiguration this job cannot otherwise see: a container pointed at
    // some other realm would register, pull, and answer every question below
    // about somebody else's repository.
    assert.ok(seen.pdp.replace(/\/+$/, "").endsWith("/realm/" + REALM),
      "the PEP reports it is dialling " + seen.pdp + " and this job owns the " +
      "realm " + REALM + ". Under a launcher that URL is decided when the " +
      "stack comes up (XACML_PEP_PDP_URL) and this job is told which realm " +
      "to use (XACML_PEP_REALM); the two disagreeing means one of them was " +
      "changed alone.");
    if (pep.pdpUrl) {
      // Only when this job configured it — an attached container was told
      // where to dial by somebody else, and the check above is what holds it.
      assert.strictEqual(seen.pdp, pep.pdpUrl,
        "the PEP reports " + seen.pdp + " and this job configured " +
        pep.pdpUrl);
    }
    if (pep.mode !== "host") {
      assert.ok(seen.pdp.indexOf("localhost") < 0 &&
                seen.pdp.indexOf("127.0.0.1") < 0,
        "ON A DOCKER NETWORK IT MUST NOT BE LOCALHOST. The point of the " +
        "container is that the PEP resolves the service by its compose name " +
        "on the private network, on the INTERNAL port, against a certificate " +
        "issued for THAT name — none of which a PEP dialling a published " +
        "port on loopback ever does. It says " + seen.pdp);
    }
  });

  // -------------------------------------------------------------------------
  // THE BUILD IT IS RUNNING, ON ITS OWN PAGE AND ON THE PDP'S ROW (2026-09-06).
  //
  // `options.version` rides on the registration and on every heartbeat, the
  // PDP stores it as `xacmlPepVersion`, and `/admin/xacml/peps` draws it in a
  // column headed Version. **It was the hand-written string `'mock-sts
  // xacml-pep, phase five'` until that day** — a console column answering
  // "which build is that enforcement point running" with the name of a
  // development phase, unchanged since it was typed and incapable of changing.
  //
  // Two claims, and only one of them is checkable in process. `tests/
  // xacml_pep.js` holds the SOURCE — that the Dockerfile copies and stamps the
  // module and that `pep.js` computes the constant. What needs a running
  // container and a live PDP is that the value SURVIVES the trip: it is put on
  // a registration, sent over mutual TLS, stored on a directory entry as a
  // lower-cased attribute and read back. Every one of those steps can drop a
  // field silently, and a missing version renders as an empty column.
  // -------------------------------------------------------------------------
  // THE TWO READS ARE TAKEN FIRST AND THE CHECK BELOW IS SYNCHRONOUS, which
  // is not a style choice: `check()` calls its function and does NOT await it,
  // so an `async` body would return a promise nobody looks at — every
  // assertion in it would run after the check had already been counted, and a
  // failure would surface as an unhandled rejection rather than as a failed
  // test. That is this suite's own classic way of passing while proving
  // nothing, and it is the reason every other check in this file is a plain
  // function over values fetched above it.
  const seenByThePdp = await pepRow();
  const pdpIndex = await get(base + "/admin-api");

  check("the PEP reports the release and its build, and the PDP's row " +
        "carries it", function () {
    // M.N.O.<build> (#1317): the release, then the build number — the UTC
    // build instant, or a release build's own — the same rules as the PDP.
    const FULL = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
    assert.ok(FULL.test(String(seen.version)),
      "the PEP reports version " + JSON.stringify(seen.version) + ", which " +
      "is not M.N.O.<build>. A version that is a LABEL rather than a number " +
      "is what this container shipped until 2026-09-06." + pepLog());
    assert.ok(seen.build && typeof seen.build === "object",
      "and it should break the build out beside it — commit, build instant, " +
      "and whether it was stamped — so a client comparing this PEP against " +
      "the PDP reads fields rather than parsing a string. It says " +
      JSON.stringify(seen.build) + pepLog());
    assert.ok(!!seen.build.at && !isNaN(Date.parse(seen.build.at)) &&
              String(seen.version).split(".").slice(3).join(".") ===
                String(seen.build.number) &&
              typeof seen.build.release === "boolean" &&
              (seen.build.release || /^\d{14}$/.test(seen.build.number)),
      "`build` should carry the instant (`at`), the `number` the version " +
      "ends with — YYYYMMDDHHMMSS unless it is a release — and `release` " +
      "(#1317); it says " + JSON.stringify(seen.build));
    assert.strictEqual(seen.build.stamped, true,
      "THIS CONTAINER MUST BE A BUILT ARTIFACT. `stamped: false` means it " +
      "computed its build record when the process started — so its build " +
      "instant moves on every restart and comparing it with the PDP's says " +
      "nothing at all. Under either launcher this image was just built by " +
      "compose, so a false here means the Dockerfile's --stamp step did not " +
      "reach the image." + pepLog());

    // AND THE SAME STRING ON THE PDP'S SIDE. This is the half that crosses the
    // wire: registration -> mutual TLS -> a directory attribute -> the row.
    assert.ok(seenByThePdp.row,
      "the PDP has no row for " + PEP_NAME + " to carry a version on");
    assert.strictEqual(seenByThePdp.row.version, seen.version,
      "THE PDP'S ROW MUST SAY WHAT THE PEP SAYS. The container reports " +
      JSON.stringify(seen.version) + " and the register holds " +
      JSON.stringify(seenByThePdp.row.version) + ". The value travels on the " +
      "registration and on every heartbeat and is stored as an attribute on " +
      "a directory entry, and every one of those steps can drop it in a way " +
      "that renders as an empty column rather than as an error.");

    // AND THE RELEASE IS THE PDP'S OWN. The two images are built from ONE
    // tree and one VERSION file, so M.N.O must be the same string. The
    // build numbers need not agree: they are two artifacts, each numbered
    // by the instant it was built (#1317) — unless BOTH were built as the
    // same release, when the whole version must agree. This is the
    // assertion that catches a PEP left behind across a release, which is
    // the whole reason that column is on the console.
    assert.strictEqual(pdpIndex.status, 200,
      "GET /admin-api answered " + pdpIndex.status);
    const releaseOf = function (v) {
      return String(v).split(".").slice(0, 3).join(".");
    };
    assert.strictEqual(releaseOf(seen.version),
      releaseOf(pdpIndex.body.version),
      "the PEP is release " + releaseOf(seen.version) + " and the PDP is " +
      releaseOf(pdpIndex.body.version) + ". Both images are built from this " +
      "one tree and read the same repo-root VERSION file, so a difference " +
      "here is not a stale container — it is a build that took its VERSION " +
      "from somewhere else. (The BUILD NUMBERS may legitimately differ: " +
      seen.version + " against " + pdpIndex.body.version + ".)");
    if (seen.build.release && pdpIndex.body.release === true) {
      assert.strictEqual(seen.version, String(pdpIndex.body.version),
        "both are release builds, so they must be the SAME release build: " +
        seen.version + " against " + pdpIndex.body.version);
    }
    log.info("[version] the PEP is " + seen.version + " and the PDP is " +
             pdpIndex.body.version + " — the same release.");
  });

  // THE URL ARRIVES WITH THE CERTIFICATE, NOT WITH THE FIRST REGISTRATION.
  // derive_notify_url() returns nothing while the HTTPS listener serves no
  // certificate, and section 1b is what writes that pair. Section 6 reads
  // the row again, after the reload and a heartbeat, and that is where the
  // derived https://<name>:9443/notify has to be usable.
  check("before its listener certificate, the PEP registers no notify URL",
        function () {
    assert.ok(seen.registration.notify,
      "the registration answer should carry the PDP's verdict on the notify " +
      "URL; the PEP recorded " + JSON.stringify(seen.registration));
    assert.strictEqual(seen.registration.notify.url, null,
      "POST /notify is HTTPS only, and nothing is listening for it until " +
      "section 1b's certificate is served; it registered " +
      JSON.stringify(seen.registration.notify));
    assert.strictEqual(seen.registration.notify.usable, false,
      "with no URL the PDP does not nudge. xacml.pepNotify is also OFF, " +
      "so sections 4 and 5 converge by polling; section 6 turns the nudge " +
      "on once the certificate is served. The PDP said " +
      JSON.stringify(seen.registration.notify));
  });

  check("the first pull loaded the policy that was deployed before it started",
        function () {
    assert.strictEqual(seen.holding.lastPullOk, true,
      "the first pull failed: " + seen.holding.lastPullWhy + pepLog());
    assert.strictEqual(seen.holding.loaded, true,
      "a PEP with nothing loaded decides NotApplicable to everything and its " +
      "bias refuses it, which from the outside is indistinguishable from a " +
      "policy that denies. It says: " + seen.holding.lastPullWhy + pepLog());
    assert.strictEqual(seen.holding.policyCount, 1,
      "one policy was deployed into this realm; the PEP pulled " +
      seen.holding.policyCount);
    assert.strictEqual(seen.holding.root, ID_OF[POLICY_A],
      "AND IT MUST BE THE RIGHT DOCUMENT. The PEP starts evaluation from the " +
      "policy it believes is the root, and one that started from the wrong " +
      "one would decide confidently and wrongly. It holds " +
      seen.holding.root);
    assert.deepStrictEqual(seen.holding.refused, [],
      "no policy should have failed to load in the PEP's own validator — it " +
      "parses what it pulled rather than trusting the PDP, and a refusal " +
      "here is the two ends disagreeing about a document. It refused " +
      JSON.stringify(seen.holding.refused));
  });

  const there = await pepRow();
  check("and the PDP's register shows the same PEP, authenticated and fresh",
        function () {
    assert.ok(there.row,
      "the PDP's /admin-api/xacml/peps does not list \"" + PEP_NAME + "\". " +
      "It lists " + JSON.stringify((there.register.peps || [])
        .map(function (one) { return one.name; })) + pepLog());
    assert.strictEqual(there.row.authenticated, true,
      "the row should record that a credential (the PEP's token) proved " +
      "something; it says " + there.row.authenticated);
    // **EITHER RDN ATTRIBUTE, AND THAT IS NOT A WEAKENING.** What is being
    // asserted is WHICH ENTRY the certificate resolved to, and the entry is
    // named by the RDN's VALUE. Which ATTRIBUTE carries it is a property of
    // the door the entry came in through: `ldap_server.js` seeds
    // `cn=remote-pep-1` and `POST /admin-api/users/create` writes `uid=`. The
    // launchers meet the first because they reuse the seeded identity; a
    // self-started container has to create one, so it meets the second. An
    // assertion naming `cn=` was asserting the seed.
    assert.ok(new RegExp('^(cn|uid)=' + PEP_NAME + ',', 'i')
      .test(String(there.row.identity)),
      "AND THE IDENTITY IS THE DIRECTORY ENTRY THE CERTIFICATE RESOLVED TO, " +
      "not the name in the body — which is the whole of how this PEP got " +
      "past the access policy: that entry is a member of cn=remote-peps, " +
      "which grants the built-in REMOTE_PEPS role that /xacml/pep/* " +
      "requires. The row says " + there.row.identity);
    assert.strictEqual(there.row.bias, "deny-biased",
      "the PEP reported its bias at registration; the row says " +
      there.row.bias);
    assert.strictEqual(there.row.stale, false,
      "the PEP has just registered and pulled, so it cannot be stale. The " +
      "row says lastSeen=" + there.row.lastSeen);
    // #1760: the entry a remote PEP's certificate maps to is a SERVICE
    // ACCOUNT, owned by the realm's administrators — made one when it joined
    // the REMOTE_PEPS group, or at the realm's creation for the seed. That
    // the PEP registered and pulled above, as one, is the other half: its
    // mutual-TLS door is no service-account door.
    const account = there.row.identityAccount;
    assert.ok(account && account.serviceAccount === true,
      "THE PEP'S IDENTITY ENTRY SHOULD BE A SERVICE ACCOUNT (#1760). The " +
      "row's identityAccount is " + JSON.stringify(account));
    assert.ok(Array.isArray(account.owners) && account.owners.length >= 1 &&
              account.owners.every(function (one) {
                return one.kind === "group" || one.kind === "person";
              }),
      "and it should name an owner — the realm's Admin Write group, or its " +
      "bootstrap administrator. It names " + JSON.stringify(account.owners));
    assert.ok(there.row.lastSeen &&
              Date.now() - Date.parse(there.row.lastSeen) < 60000,
      "and lastSeen should be seconds old — a pull moves it as well as a " +
      "heartbeat, because a PEP that is polling is plainly alive. It is " +
      there.row.lastSeen);
  });

  log.info("[register] OK — a container, registered on attempt " +
           seen.registration.attempts + ", holding " +
           seen.holding.policyCount + " policy(ies) at token " +
           String(seen.holding.syncToken).slice(0, 12) + "…");
  log.debug("Leaving itRegistersAndPulls().");
}

// ===========================================================================
// 1b. ITS HTTPS LISTENER, CERTIFIED BY THE REALM IT REGISTERED TO (2026-09-13).
//
// A remote PEP answers its own clients, and it answers them over HTTPS with a
// key pair this service's realm issued it: the `pep-tls` Issuing CA under this
// realm's Intermediate, reached through `POST /admin-api/xacml/
// issue-pep-certificate`. The private key comes back ONCE, in that reply, and
// this job does what an operator does with it — writes the pair to the two
// files the container names — and then dials the container as a client that
// holds nothing but the service Root.
//
// **WHAT IS ONLY TRUE OF THE DEPLOYMENT, which is why it is here and not only
// in `tests/pep_listener_certificate.js`:** the container starts with no pair
// (the realm did not exist, so it could not have one), finds the files after
// they are written on a mount it does not own, starts a listener in the image
// without a restart, and serves a chain a client verifies BY THE NAME IT
// DIALLED — which is a different name in each launcher's stack.
// ===========================================================================

// A TLS request to the PEP's HTTPS listener, trusting ONLY `anchorPem`, with
// hostname checking left on. Answers the status, the parsed body, and what
// the handshake saw of the chain.
function pepHttpsGet(p, anchorPem, post) {
  log.debug("Entering pepHttpsGet(). path=" + p);
  const target = new URL(pep.httpsUrl + p);
  const sent = post ? JSON.stringify(post) : "";
  log.debug("Leaving pepHttpsGet().");
  return new Promise(function (resolve) {
    const request = https.request({
      host: target.hostname, port: target.port, path: target.pathname +
      target.search, method: post ? "POST" : "GET", ca: [anchorPem],
      servername: target.hostname, agent: false,
      headers: post ? { "Content-Type": "application/json",
                        "Content-Length": Buffer.byteLength(sent) } : {}
    }, function (response) {
      const peer = response.socket.getPeerCertificate(true);
      let text = "";
      response.on("data", function (chunk) {
        text += chunk.toString("utf8");
      });
      response.on("end", function () {
        let body = null;
        try {
          body = JSON.parse(text);
        } catch (e) {
          log.debug("Caught in pepHttpsGet(): " + ((e && e.message) || e));
          body = null;
        }
        resolve({ status: response.statusCode, body: body, text: text,
                  authorized: response.socket.authorized,
                  serialHex: String((peer && peer.serialNumber) || ""),
                  issuerCn: peer && peer.issuerCertificate
                    ? String(peer.issuerCertificate.subject.CN || "") : "",
                  intermediateCn: peer && peer.issuerCertificate &&
                    peer.issuerCertificate.issuerCertificate
                    ? String(peer.issuerCertificate.issuerCertificate.subject
                      .CN || "") : "" });
      });
    });
    request.on("error", function (e) {
      resolve({ status: 0, error: e.message, authorized: false });
    });
    request.end(sent || undefined);
  });
}

function sameSerial(a, b) {
  log.debug("Entering sameSerial().");
  const tidy = function (one) {
    log.debug("Entering tidy().");
    log.debug("Leaving tidy().");
    return String(one || "").toLowerCase().replace(/[^0-9a-f]/g, "")
      .replace(/^0+/, "");
  };
  log.debug("Leaving sameSerial().");
  return !!tidy(a) && tidy(a) === tidy(b);
}

async function theListenerServesARealmCertificate() {
  log.debug("Entering theListenerServesARealmCertificate().");
  log.info("=== The PEP's HTTPS listener, certified by its realm ===");
  assert.ok(pep.httpsUrl && pep.serverCertDir,
    "the launcher started the PEP and did not say where its HTTPS listener " +
    "is or where to write its certificate: XACML_PEP_HTTPS_URL=\"" +
    pep.httpsUrl + "\" and XACML_PEP_SERVER_CERT_DIR=\"" + pep.serverCertDir +
    "\". Both launchers export them beside XACML_PEP_URL; a stack brought up " +
    "by hand needs them set to the published 9443 port and to the host path " +
    "of the container's /certs/server.");

  // BEFORE: configured, waiting, and saying why.
  const waiting = await pepOverview();
  check("before a pair is written the listener is configured and waiting",
        function () {
    assert.ok(waiting.https && waiting.https.configured === true &&
              waiting.https.listening === false,
      "GET / should report an HTTPS listener that is configured and not yet " +
      "listening; it says " + JSON.stringify(waiting.https) + pepLog());
    assert.ok(/does not exist/.test(String(waiting.https.problem || "")),
      "and say the pair is not there yet; it says " +
      JSON.stringify(waiting.https.problem));
  });

  // A NAME NOTHING REGISTERED IS REFUSED: the realm is decided by the row.
  const stranger = await postJson(api("/xacml/issue-pep-certificate"),
                                  { name: "no-such-pep-" + PEP_NAME });
  check("a certificate for a PEP not registered in this realm is refused",
        function () {
    assert.strictEqual(stranger.status, 400,
      "issuing for an unregistered name should answer 400; it answered " +
      stranger.status + " " + String(stranger.text).slice(0, 300));
    assert.ok(!stranger.text || stranger.text.indexOf("PRIVATE KEY") < 0,
      "and hand back no key");
  });

  // THE ISSUE, naming the host this job dials the listener by.
  const host = new URL(pep.httpsUrl).hostname;
  const isIp = net.isIP(host) !== 0;
  const issued = await postJson(api("/xacml/issue-pep-certificate"), {
    name: PEP_NAME,
    dnsNames: isIp ? [] : [host],
    ipAddresses: isIp ? [host] : []
  });
  const got = issued.body || {};
  // Kept for section 9, which nudges the PEP itself over HTTPS.
  pep.anchorPem = String(got.anchorPem || "");
  check("the realm issues the PEP a listener certificate and its key, once",
        function () {
    assert.strictEqual(issued.status, 200,
      "POST /admin-api/xacml/issue-pep-certificate answered " + issued.status +
      " " + String(issued.text).slice(0, 400));
    assert.ok(/BEGIN PRIVATE KEY/.test(String(got.privateKeyPem || "")),
      "the reply carries the private key");
    // SINCE #1064 (2026-10-27) EVERY REPORTED CHAIN ENDS AT THE SERVICE
    // ROOT (pki.chainThroughRoot()), so the chain is four certificates and
    // the last of them is `anchorPem`. Until then it was three, "no Root",
    // and this check said so; run #6 of 2026-10-28 found it still saying so.
    const chainCerts = String(got.fullChainPem || "")
      .split(/(?<=-----END CERTIFICATE-----)/)
      .map(function (one) {
        return one.replace(/\s+/g, "");
      }).filter(function (one) {
        return one.length > 0;
      });
    assert.ok(chainCerts.length === 4,
      "fullChainPem is the leaf, its Issuing CA, the realm Intermediate and " +
      "the service Root (#1064) — four certificates; it holds " +
      chainCerts.length);
    assert.strictEqual(chainCerts[chainCerts.length - 1],
                       String(got.anchorPem || "").replace(/\s+/g, ""),
      "and the last certificate of fullChainPem is anchorPem, the service " +
      "Root a client installs");
    assert.strictEqual(got.realm, REALM,
      "it was issued by the realm the PEP registered to");
    assert.ok(got.dnsNames.concat(got.ipAddresses).indexOf(host) >= 0 &&
              got.dnsNames.indexOf(PEP_NAME) >= 0,
      "it names the host this job dials (" + host + ") and the PEP's " +
      "registered name; it names " +
      JSON.stringify(got.dnsNames.concat(got.ipAddresses)));
  });

  const register = await get(api("/xacml/peps"));
  check("the PDP's row records the certificate and not the key", function () {
    const row = ((register.body || {}).peps || []).filter(function (one) {
      return one.name === PEP_NAME;
    })[0] || {};
    assert.ok(row.listenerCertificate &&
              row.listenerCertificate.serialHex === got.serialHex,
      "GET /admin-api/xacml/peps should carry the issued serial on the " +
      "PEP's row; it has " + JSON.stringify(row.listenerCertificate));
    assert.ok(String(register.text).indexOf("PRIVATE KEY") < 0,
      "and no private key anywhere in that reply");
  });

  // Kept for section 10 (#1760): the proxy's https listener serves this pair.
  pep.listenerAnchorPem = String(got.anchorPem || "");

  // WHAT AN OPERATOR DOES WITH THE REPLY: two files on the container's mount.
  fs.writeFileSync(path.join(pep.serverCertDir, "pep-server.crt"),
                   got.fullChainPem, { mode: 0o644 });
  fs.writeFileSync(path.join(pep.serverCertDir, "pep-server.key"),
                   got.privateKeyPem, { mode: 0o644 });
  log.info("Wrote the issued pair to " + pep.serverCertDir + "; waiting for " +
           "the container to start its listener.");

  await until("the PEP to start its HTTPS listener with the issued pair",
              async function () {
    const seen = await pepOverview();
    const h = seen.https || {};
    return { ok: h.listening === true && h.certificate &&
                 sameSerial(h.certificate.serialHex, got.serialHex),
             note: "listening=" + h.listening + ", problem=" + h.problem };
  });

  const overHttps = await pepHttpsGet("/", got.anchorPem);
  check("a client holding only the service Root reaches it over HTTPS",
        function () {
    assert.ok(overHttps.status === 200 && overHttps.authorized,
      "GET " + pep.httpsUrl + "/ trusting only the service Root answered " +
      overHttps.status + " (" + (overHttps.error || "authorized=" +
      overHttps.authorized) + ")" + pepLog());
    assert.ok(sameSerial(overHttps.serialHex, got.serialHex),
      "with the certificate the realm issued; it was served " +
      overHttps.serialHex);
    assert.ok(overHttps.body && overHttps.body.https &&
              overHttps.body.https.listening === true,
      "and it is the same PEP, reporting itself");
  });
  check("the chain runs through this realm's own Intermediate", function () {
    assert.ok(/Remote PEP TLS Issuing CA/.test(overHttps.issuerCn),
      "issued by the Remote PEP listeners Issuing CA; the issuer is " +
      overHttps.issuerCn);
    assert.ok(overHttps.intermediateCn.indexOf("(" + REALM + ")") >= 0,
      "under " + REALM + "'s Intermediate; it is " + overHttps.intermediateCn);
  });

  const decided = await pepHttpsGet("/protected?subject=" + ADMIN_PERSON +
                                    "&employeeType=admin&action=GET",
                                    got.anchorPem);
  check("the protected resource answers over HTTPS as it does over HTTP",
        function () {
    assert.ok(decided.status === 200 && decided.body &&
              decided.body.decision === "Permit",
      "GET /protected over HTTPS for an admin should be a Permit decided in " +
      "the container; it answered " + decided.status + " " +
      String(decided.text || decided.error).slice(0, 300));
  });

  log.info("[https] OK — serving " + got.serialHex + " from " + REALM +
           "'s Remote PEP listeners Issuing CA at " + pep.httpsUrl + ".");
  log.debug("Leaving theListenerServesARealmCertificate().");
}

// ===========================================================================
// 2. THE DECISION HAPPENS IN THE CONTAINER.
//
// The four cases below are decided by the deny-unless-permit RBAC policy, so
// the answers do not depend on the PEP's bias at all — which is deliberate.
// This section is about WHERE the decision was made, and a case whose answer
// came from the bias would be one where the policy had not been consulted.
//
// **THE PDP SEES NONE OF THESE REQUESTS.** That is not a claim this job can
// make by looking at the PDP — there is no per-decision counter there to watch
// stay still. What it can do is check the two things that would be false if the
// PEP were secretly asking: the answer names the PEP that decided and the token
// it decided against, and the exchange works over a port the PDP does not
// listen on. Section 7 closes the loop from the other end: the only way those
// decisions ever reach this console is the heartbeat.
// ===========================================================================
async function itDecidesInItsOwnProcess() {
  log.debug("Entering itDecidesInItsOwnProcess().");
  log.info("=== Four decisions, made inside the container ===");

  const cases = [
    { what: "an admin may do anything",
      query: { subject: ADMIN_PERSON, employeeType: "admin", action: "DELETE" },
      allowed: true, decision: "Permit" },
    { what: "staff may GET",
      query: { subject: STAFF_PERSON, employeeType: "staff", action: "GET" },
      allowed: true, decision: "Permit" },
    { what: "staff may NOT DELETE",
      query: { subject: STAFF_PERSON, employeeType: "staff", action: "DELETE" },
      allowed: false, decision: "Deny" },
    { what: "a role nobody granted anything to is denied",
      query: { subject: "mallory", employeeType: "contractor", action: "GET" },
      allowed: false, decision: "Deny" }
  ];

  for (const one of cases) {
    const r = await askThePep(one.query);
    check("the remote PEP: " + one.what, function () {
      assert.strictEqual(r.body.decision, one.decision,
        JSON.stringify(one.query) + " should be " + one.decision +
        " under the baseline policy; the PEP's own engine said " +
        r.body.decision + " " + JSON.stringify(r.body.status));
      assert.strictEqual(r.body.allowed, one.allowed,
        "and the enforcement should be " + (one.allowed ? "200" : "403") +
        "; it answered " + r.status + " because: " + r.body.why);
      assert.strictEqual(r.status, one.allowed ? 200 : 403,
        "the status and the decision must agree; " + r.status + " with " +
        "allowed=" + r.body.allowed);
    });
  }

  const decided = await askThePep({ subject: ADMIN_PERSON,
                                    employeeType: "admin",
                                    action: "GET" });
  check("the answer names the PEP that decided and the policy it applied",
        function () {
    assert.strictEqual(decided.body.decidedBy.pep, PEP_NAME,
      "the decision should be attributed to this PEP; it names " +
      decided.body.decidedBy.pep);
    assert.ok(decided.body.decidedBy.syncToken,
      "AND THE TOKEN IT DECIDED AGAINST, which is the field that makes a " +
      "disagreement between two PEPs diagnosable rather than mysterious. It " +
      "carries " + JSON.stringify(decided.body.decidedBy));
    assert.ok(String(decided.body.decidedBy.note).indexOf(
        "PDP did not see") > 0,
      "and it should say plainly that the PDP saw none of this; it says " +
      decided.body.decidedBy.note);
    assert.ok((decided.body.applicablePolicies || []).length >= 1,
      "returnPolicyIdList is on in this PEP, so a Permit should name the " +
      "policy that produced it; it named " +
      JSON.stringify(decided.body.applicablePolicies));
  });

  check("the deny-unless-permit policy makes the bias irrelevant", function () {
    // Worth asserting rather than assuming: every case above is a Permit or a
    // Deny, which is exactly where the two biases AGREE (section 7.2). So this
    // section measured the POLICY, not the enforcement rule. The one state
    // where the bias decides is an empty holding, and section 5 goes there.
    assert.strictEqual(decided.body.bias, "deny-biased",
      "this PEP was started deny-biased; it reports " + decided.body.bias);
    assert.ok(String(decided.body.why).indexOf("Permit") >= 0,
      "and the reason it gives should be the policy's answer rather than a " +
      "fallback; it says " + decided.body.why);
  });

  log.info("[decide] OK — four decisions inside the container, none of which " +
           "reached the PDP.");
  log.debug("Leaving itDecidesInItsOwnProcess().");
}

// ===========================================================================
// 3. THE PIP THAT CONTAINER DOES NOT HAVE, REACHED OVER HTTP — AND THE
//    ATTRIBUTE COMING OUT OF THE MOCK'S EMBEDDED LDAP DIRECTORY.
//
// **THIS SECTION USED TO ASSERT THE OPPOSITE AND THE INVERSION IS THE POINT.**
// It was called `thereIsNoPipOutHere()` and it held, in both directions, that
// the remote PEP decides on what the request asserts and nothing else: the PDP
// permitted somebody this container refused, and this container permitted
// somebody the PDP refused. That was a real property of the deployment and it
// was also **one policy deciding two ways in two enforcement points**, which is
// exactly the drift a shared repository exists to prevent, reappearing one
// layer down.
//
// The PDP publishes its Policy Information Point at `POST /xacml/pip` now, and
// `xacml-pep/pip.js` uses it. So this section asserts the thing the old one
// asserted the absence of.
//
// ---------------------------------------------------------------------------
// WHAT IS ACTUALLY BEING PROVED, AND WHY EACH STEP IS NEEDED.
//
// The policy is the `rbac` template over `employeeType`, and **ADMIN_PERSON
// carries `employeeType: admin` on their entry under `ou=users` in the
// embedded directory** — put there by THIS JOB, in `createThePeople()`, through
// the realm's own `/admin-api/users/create`. (Until 2026-09-12 it was `carol`,
// put there by `ldap_server.js`'s development-mode seed; product mode seeds
// nobody.) Nothing about them travels in the request below: the query names a
// subject and an action and asserts NO attribute at all.
//
// So a Permit can only have come from one place. Four checks, and each rules
// out a different way of being right by accident:
//
//   1. **THE PEP PERMITS HER**, deciding in its own process against its own
//      copy of the engine. On its own this could be a policy that permits
//      everybody.
//   2. **AND REFUSES SOMEBODY THE DIRECTORY HAS NEVER HEARD OF**, asked the
//      same way. That rules out the permit-everything reading.
//   3. **AND THE ANSWER SAYS THE PIP WAS USED**, naming the subject and the
//      number of designators resolved. That rules out a value that arrived
//      some other way — the request, a default, a cached decision.
//   4. **AND THE PDP AGREES WITH IT.** The two enforcement points reach the
//      same answer about the same person under the same policy, which is the
//      property the whole phase exists for and the one the old section
//      recorded the absence of.
//
// ---------------------------------------------------------------------------
// THE NO-PIP BEHAVIOUR IS STILL HERE AND IS STILL ASSERTED.
//
// It has not been replaced by this, it has been made a CONFIGURATION: a
// request-asserted attribute still decides where the directory holds nothing,
// which is the second half of the old section and the reason the fallback is
// worth having. `PEP_PIP=false` and a container with no client certificate
// both reach it too, and `pep.js` reports which state it is in on `GET /`.
//
// **AND THAT REPORT IS CHECKED**, because "the PIP is working" is otherwise
// something a reader infers from decisions that changed — which is the
// hardest possible way to notice that it quietly stopped.
// ===========================================================================
async function thePipReachesTheDirectory() {
  log.debug("Entering thePipReachesTheDirectory().");
  log.info("=== The remote PEP resolving an attribute out of the mock's " +
           "embedded LDAP ===");

  // NOTHING IS ASSERTED ABOUT HER. No employeeType, no role, no attribute of
  // any kind — only a name and an action. Every attribute the policy reads has
  // to come from the directory, through the PIP, or the request is refused.
  const adminAsked = await askThePep({ subject: ADMIN_PERSON,
                                       action: "DELETE" });
  check("the PEP PERMITS " + ADMIN_PERSON + " on an attribute it pulled from " +
        "the PDP's directory, with the request asserting nothing", function () {
    assert.strictEqual(adminAsked.body.decision, "Permit",
      ADMIN_PERSON + " carries employeeType=admin on their entry under " +
      "ou=users in the embedded directory and NOTHING in this request says " +
      "so. The policy is the rbac template over employeeType, so a Permit " +
      "can only have come from POST /xacml/pip resolving that designator " +
      "against her entry. The PEP said " + adminAsked.body.decision + " — " +
      String(adminAsked.body.why).slice(0, 300));
    assert.strictEqual(adminAsked.status, 200,
      "and the access is allowed; it answered " + adminAsked.status);
  });

  check("and it SAYS the PIP answered, rather than leaving it to be inferred",
        function () {
    assert.ok(adminAsked.body.pip && adminAsked.body.pip.used === true,
      "the answer should carry a pip block saying the query was made — two " +
      "decisions that differ only because one had an attribute the other did " +
      "not are otherwise identical on the wire. It carries " +
      JSON.stringify(adminAsked.body.pip));
    assert.strictEqual(adminAsked.body.pip.subject, ADMIN_PERSON,
      "naming the subject it asked about; it says " +
      adminAsked.body.pip.subject);
    assert.ok(adminAsked.body.pip.resolved >= 1,
      "and how many designators came back with values. A Permit with ZERO " +
      "resolved would mean the attribute arrived some other way, which is " +
      "the one reading this whole section exists to rule out. It resolved " +
      adminAsked.body.pip.resolved + " of " + adminAsked.body.pip.designators +
      ".");
  });

  // THE SAME QUESTION AT THE PDP. Two enforcement points, one policy, one
  // directory — and now one answer.
  const pdpOnAdmin = await askThePdp(ADMIN_PERSON, "DELETE");
  check("AND THE PDP AGREES WITH IT, which is the whole point", function () {
    assert.strictEqual(pdpOnAdmin.Decision, "Permit",
      "the PDP resolves the same attribute through its own embedded PIP and " +
      "said " + pdpOnAdmin.Decision);
    assert.strictEqual(pdpOnAdmin.Decision, adminAsked.body.decision,
      "the two enforcement points must reach the SAME decision about the " +
      "same person under the same policy. The PDP said " +
      pdpOnAdmin.Decision + " and the remote PEP said " +
      adminAsked.body.decision + ". This assertion is the inversion of what " +
      "this section used to hold: before POST /xacml/pip existed these two " +
      "disagreed BY DESIGN, and the disagreement was the drift a shared " +
      "policy repository is supposed to prevent.");
  });

  // ---------------------------------------------------------------------
  // AND THE PERSON THE DIRECTORY HAS NEVER HEARD OF, asked the same way.
  // Without this the section above is satisfied by a policy that permits
  // everybody, which is the commonest way for a test like this to be
  // accidentally right.
  // ---------------------------------------------------------------------
  const ghost = await askThePep({ subject: "nobody-at-all", action: "DELETE" });
  const pdpOnGhost = await askThePdp("nobody-at-all", "DELETE");
  check("a name the directory has never heard of is refused at BOTH, and for " +
        "the same reason", function () {
    assert.strictEqual(ghost.body.decision, "Deny",
      "there is no entry, so the PIP answers an empty bag, so nothing " +
      "matches and deny-unless-permit denies. The PEP said " +
      ghost.body.decision);
    assert.strictEqual(pdpOnGhost.Decision, "Deny",
      "and the PDP said " + pdpOnGhost.Decision);
    assert.strictEqual(ghost.status, 403,
      "and the access is refused; it answered " + ghost.status);
  });

  check("and the PEP reports WHY nothing was resolved rather than reporting " +
        "nothing", function () {
    assert.ok(ghost.body.pip && ghost.body.pip.used === true,
      "the query was still MADE — a subject that resolves to no entry is an " +
      "ordinary answer and not a failure, and reporting it as one would make " +
      "a missing person look like a broken PIP. It says " +
      JSON.stringify(ghost.body.pip).slice(0, 300));
    assert.strictEqual(ghost.body.pip.resolved, 0,
      "with nothing resolved; it resolved " + ghost.body.pip.resolved);
    const reasons = (ghost.body.pip.unresolved || []).map(function (one) {
      return one.why;
    }).join(" ");
    assert.ok(reasons.indexOf("nobody-at-all") >= 0,
      "and the PDP's <Unresolved> reason should NAME the subject it could " +
      "not find, because *there is no such person* and *that person holds no " +
      "such attribute* need opposite fixes. The reasons are " +
      reasons.slice(0, 300));
  });

  // ---------------------------------------------------------------------
  // THE FALLBACK, WHICH HAS NOT GONE AWAY.
  //
  // A request-asserted attribute still decides where the directory holds
  // nothing. That was the SECOND half of the old section — the PEP permitting
  // somebody the PDP refuses — and it is still true and still worth having:
  // it is what a PEP with no PIP does, it is what this container does when
  // `PEP_PIP` is off or its certificate is refused, and it is the shape of
  // every real enforcement point that trusts its own context.
  // ---------------------------------------------------------------------
  const asserted = await askThePep({ subject: "nobody-at-all",
                                     employeeType: "admin", action: "DELETE" });
  check("a request-asserted attribute still decides where the directory " +
        "holds nothing", function () {
    assert.strictEqual(asserted.body.decision, "Permit",
      "THE PEP STILL BELIEVES WHAT IT WAS TOLD when the PIP has nothing to " +
      "say — the request asserted employeeType=admin for a name no entry " +
      "matches, and the policy permits an admin. That is what a PEP with no " +
      "PIP does and is the state this container is in with PEP_PIP off or a " +
      "certificate the PDP refuses. It said " + asserted.body.decision);
    assert.strictEqual(pdpOnGhost.Decision, "Deny",
      "and the PDP still refuses the same name, because ITS PIP reads the " +
      "directory and the request it was given asserted nothing. So the two " +
      "still differ where the INFORMATION differs — which is the honest " +
      "reading of what a PIP is for: it removes the disagreements that come " +
      "from " +
      "MISSING information, not the ones that come from a caller asserting " +
      "something about itself.");
  });

  // ---------------------------------------------------------------------
  // WHAT THE CONTAINER SAYS ABOUT ITSELF. `GET /` used to carry a `noPip`
  // sentence; it carries a `pip` block now, and the block has to say the
  // feature is on AND that a credential is mounted — because the endpoint
  // refuses an uncredentialed PEP, and a container reporting the feature ON
  // while every query is refused would be the most misleading state available.
  // ---------------------------------------------------------------------
  const overview = await pepOverview();
  check("the PEP SAYS it has a PIP, and that it holds the credential the " +
        "endpoint requires", function () {
    assert.ok(overview.pip && overview.pip.enabled === true,
      "GET / should report the PIP as enabled; it says " +
      JSON.stringify(overview.pip).slice(0, 300));
    assert.ok(overview.pip.credentialed === true,
      "and that a client certificate is mounted — POST /xacml/pip requires " +
      "one whose subject holds the built-in REMOTE_PEPS role, so a container " +
      "reporting the feature on without one would be reporting something " +
      "that cannot work. It says credentialed=" + overview.pip.credentialed);
    assert.ok(String(overview.pip.endpoint).indexOf("/xacml/pip") > 0,
      "naming the endpoint it uses; it says " + overview.pip.endpoint);
    assert.ok(overview.pip.lastQuery && overview.pip.lastQuery.used === true,
      "and the last query's outcome, so that 'the PIP stopped working' is " +
      "something a reader SEES rather than infers from decisions that " +
      "changed. It says " +
      JSON.stringify(overview.pip.lastQuery).slice(0, 200));
  });

  log.info("[pip] OK — the same policy, two enforcement points, one " +
           "directory, and now one answer.");
  log.debug("Leaving thePipReachesTheDirectory().");
}

// ===========================================================================
// 4. A POLICY DEPLOYED AT THE PAP CHANGES WHAT THE CONTAINER ALLOWS.
//
// THIS IS THE ASSERTION THE WHOLE FILE EXISTS FOR. A second policy is built
// through `/admin-api/xacml/create-from-template` and promoted to root, and the
// PEP — which cannot be nudged yet, see section 1 — converges on its own
// polling interval and starts allowing something it refused a moment ago.
//
// The wait is on the ENFORCEMENT rather than on the sync token, deliberately. A
// token that changed while the decision did not would be a PEP that pulled and
// failed to load, and waiting on the token would have called that a pass.
// ===========================================================================
async function aDeployedPolicyConverges() {
  log.debug("Entering aDeployedPolicyConverges().");
  log.info("=== A new policy, deployed at the PAP, reaching the container ===");

  const before = await askThePep({ subject: STAFF_PERSON, employeeType: "staff",
                                   action: "DELETE" });
  check("before the change, staff may not DELETE", function () {
    assert.strictEqual(before.status, 403,
      "the baseline policy grants staff GET and HEAD only; the PEP answered " +
      before.status);
  });

  await act("create-from-template", {
    template: "rbac", name: POLICY_B,
    p_roleAttribute: "employeeType",
    p_adminRoles: "admin",
    p_readerRoles: "staff",
    p_readerActions: "GET, HEAD, DELETE"
  }, "created the widened policy");
  const promoted = await act("set-root", { name: POLICY_B },
                             "made the widened policy the root");
  check("the PAP says the new policy is the root", function () {
    assert.ok(String(promoted.what).indexOf("root") > 0,
      "POST /admin-api/xacml/set-root said: " + promoted.what);
  });

  const arrived = await until(
    "the remote PEP to enforce the policy deployed a moment ago",
    async function () {
      const r = await askThePep({ subject: STAFF_PERSON, employeeType: "staff",
                                  action: "DELETE" });
      return { ok: r.status === 200,
               note: "the PEP still answers " + r.status + " (" +
                     r.body.decision + ")" };
    });

  const after = await pepOverview();
  check("the PEP converged BY POLLING, with no nudge, and is now enforcing " +
        "the new policy", function () {
    assert.strictEqual(after.holding.root, ID_OF[POLICY_B],
      "it should now start from the promoted document; it holds " +
      after.holding.root);
    assert.strictEqual(after.holding.policyCount, 2,
      "both policies are enabled, so both are pulled — only one of them is " +
      "the root. The PEP holds " + after.holding.policyCount);
    // THE LATENCY IS THE POLLING INTERVAL AND NOTHING ELSE, which is the trade
    // `xacml-pep/CLAUDE.md` states. Not asserted as a lower bound — a machine
    // is allowed to be fast — but LOGGED, and section 6 asserts the comparison
    // against it, which is the assertion that would notice a nudge having been
    // delivered here after all.
    log.info("The PEP took " + arrived.ms + "ms to converge by polling; its " +
             "interval is " + POLL_MS + "ms and no nudge was delivered.");
  });

  const both = await askThePep({ subject: ADMIN_PERSON, employeeType: "admin",
                                 action: "DELETE" });
  check("and the rule the old policy already granted still holds", function () {
    assert.strictEqual(both.status, 200,
      "an admin could DELETE under both documents, so this must not have " +
      "changed; the PEP answered " + both.status);
  });

  log.info("[converge] OK — a policy written through /admin-api is enforced " +
           "in a container " + arrived.ms + "ms later.");
  log.debug("Leaving aDeployedPolicyConverges().");
  return arrived.ms;
}

// ===========================================================================
// 4b. AN OBLIGATION THE CONTAINER CANNOT DISCHARGE (#596).
//
// Section 7.2's part implementations skip: an obligation is the half of a
// decision that says "yes, AND you must also do this", so a PEP that cannot
// discharge one turns a Permit into a REFUSAL. This was asserted at the
// service's embedded demonstration PEP, `/xacml/protected`, in
// `sts_xacml_endpoints.js` section 5 until #596 deleted that PEP; it is
// asserted HERE now, at the PEP that replaced it, which is the stronger
// claim: the obligation is written at the PAP, PULLED, and refused in
// another process.
//
// The pair is what makes it assertable: the editor's `add-policy-obligation`
// mints `urn:sts:xacml:obligation:1`, which no PEP knows, and
// `edit-obligation` renames it to the one both PEPs discharge. Same policy,
// same request, same Permit — and the enforcement flips, which shows the
// refusal was about the OBLIGATION and not about the decision.
// ===========================================================================
const DISCHARGEABLE = "urn:sts:xacml:obligation:log";

async function anUndischargeableObligationRefuses() {
  log.debug("Entering anUndischargeableObligationRefuses().");
  log.info("=== An obligation the container cannot discharge ===");
  const ask = { subject: ADMIN_PERSON, employeeType: "admin", action: "GET" };

  await act("add-policy-obligation", { policy: POLICY_B, path: "",
                                       on: "Permit" },
            "added an obligation to the root policy");
  const refused = await until(
    "the PEP to refuse a Permit carrying an obligation it cannot discharge",
    async function () {
      const r = await askThePep(ask);
      return { ok: r.status === 403 && r.body.decision === "Permit",
               r: r, note: "the PEP answered " + r.status + " (" +
                           r.body.decision + ")" };
    });
  check("an undischargeable obligation turns the Permit into a refusal — " +
        "in the container, on policy it pulled", function () {
    const body = refused.r.body;
    assert.strictEqual(body.allowed, false);
    assert.ok(String(body.why).indexOf("obligation") > 0,
      "the refusal should name the obligation as the cause; it says: " +
      body.why);
    assert.deepStrictEqual(body.obligations,
      [{ id: "urn:sts:xacml:obligation:1", discharged: false }],
      "the obligation should be reported UNDISCHARGED rather than omitted; " +
      "it reports " + JSON.stringify(body.obligations));
  });

  const tree = await get(api("/xacml/editor?policy=" + POLICY_B));
  const obligation = ((tree.body && tree.body.tree) || [])
    .filter(function (row) {
      return row.kind === "obligation";
    })[0];
  assert.ok(obligation, "no obligation row in the editor tree: " +
    String(tree.text).slice(0, 300));
  await act("edit-obligation", { policy: POLICY_B, path: obligation.path,
                                 id: DISCHARGEABLE, on: "Permit" },
            "renamed the obligation to the one a PEP knows");
  const discharged = await until(
    "the PEP to discharge the obligation it knows",
    async function () {
      const r = await askThePep(ask);
      return { ok: r.status === 200, r: r,
               note: "the PEP answered " + r.status };
    });
  check("the one obligation the PEP knows IS discharged, and access returns",
        function () {
    assert.deepStrictEqual(discharged.r.body.obligations,
      [{ id: DISCHARGEABLE, discharged: true }],
      "and it should say so rather than silently allowing; it reports " +
      JSON.stringify(discharged.r.body.obligations));
  });

  await act("remove", { policy: POLICY_B, path: obligation.path },
            "removed the obligation again");
  const clean = await until("the PEP to hold the policy without it",
    async function () {
      const r = await askThePep(ask);
      return { ok: r.status === 200 && r.body.obligations.length === 0,
               r: r, note: "the PEP reports " +
                           JSON.stringify(r.body.obligations) };
    });
  check("removing the obligation leaves an ordinary Permit", function () {
    assert.strictEqual(clean.r.body.decision, "Permit");
  });

  log.info("[obligations] OK — one Permit enforced three ways in another " +
           "process, and only the obligation changed.");
  log.debug("Leaving anUndischargeableObligationRefuses().");
}

// ===========================================================================
// 5. A DISABLED POLICY STOPS BEING ENFORCED — WHICH IS A DIFFERENT CLAIM FROM
//    "IT IS LEFT OUT OF THE PULL".
//
// `sts_xacml_endpoints.js` asserts the pull's BYTES: a disabled policy is left
// out rather than sent with a flag. What it cannot assert is the consequence,
// because nothing over there evaluates what it pulled. Here the consequence is
// the whole assertion, and it is made twice:
//
//   * disabling the ROOT leaves the other policy the only enabled one, and the
//     PEP falls back to enforcing THAT — the same convenience rule
//     `xacml_store.js` applies, restated in `sync.js` rather than relied on,
//     and the two now demonstrably agree;
//   * disabling both leaves the PEP holding NOTHING, which is the one state
//     where its bias is what decides. A deny-biased PEP then refuses everything
//     — including the admin it was permitting a second ago.
//
// The second is the state that matters in a real deployment and the one nobody
// tests: it is what an operator produces by disabling a policy to "turn it off"
// while a PEP somewhere is still serving traffic.
// ===========================================================================
async function aDisabledPolicyStopsBeingEnforced() {
  log.debug("Entering aDisabledPolicyStopsBeingEnforced().");
  log.info("=== Disabling policy, and what the container does about it ===");

  await act("disable", { name: POLICY_B }, "disabled the widened policy");
  await until("the PEP to stop enforcing the disabled policy",
              async function () {
    const r = await askThePep({ subject: STAFF_PERSON, employeeType: "staff",
                                action: "DELETE" });
    return { ok: r.status === 403,
             note: "staff DELETE still answers " + r.status };
  });

  const fellBack = await pepOverview();
  check("a disabled policy is not merely flagged — it stops being enforced",
        function () {
    assert.strictEqual(fellBack.holding.policyCount, 1,
      "the disabled document must not reach the PEP at all; it holds " +
      fellBack.holding.policyCount + " policy(ies)");
    assert.strictEqual(fellBack.holding.root, ID_OF[POLICY_A],
      "AND THE PEP FALLS BACK TO THE ONE POLICY LEFT. Neither document " +
      "carries the root flag now — set-root cleared the first one — so both " +
      "ends apply the same convenience rule: a repository with exactly one " +
      "enabled policy has an obvious root. `sync.js` restates that rule " +
      "rather than trusting the PDP to have set isRoot, and this is the " +
      "assertion that the two readings agree. The PEP starts from " +
      fellBack.holding.root);
  });

  const stillAllowed = await askThePep({ subject: ADMIN_PERSON,
                                         employeeType: "admin",
                                         action: "DELETE" });
  check("the fallback policy is really being evaluated, not just held",
        function () {
    assert.strictEqual(stillAllowed.status, 200,
      "the baseline policy permits an admin anything, so this must still be " +
      "allowed — a PEP that had merely stopped deciding would refuse it too " +
      "and would have passed the assertion above. It answered " +
      stillAllowed.status);
  });

  // AND NOW THE STATE WHERE THE BIAS IS WHAT DECIDES.
  await act("disable", { name: POLICY_A }, "disabled the baseline policy too");
  await until("the PEP to be holding no policy at all", async function () {
    const r = await askThePep({ subject: ADMIN_PERSON, employeeType: "admin",
                                action: "DELETE" });
    return { ok: r.status === 403,
             note: "the admin is still allowed (" + r.status + ")" };
  });

  const empty = await pepOverview();
  const refused = await askThePep({ subject: ADMIN_PERSON,
                                    employeeType: "admin",
                                    action: "DELETE" });
  check("with nothing to enforce, the deny-biased PEP refuses everything — " +
        "and says so", function () {
    assert.strictEqual(empty.holding.policyCount, 0,
      "no policy is enabled, so the pull carries none; the PEP holds " +
      empty.holding.policyCount);
    assert.strictEqual(empty.holding.loaded, false,
      "AND `loaded: false` IS NOT THE SAME AS AN EMPTY REPOSITORY. `sync.js` " +
      "reports them differently on purpose, because \"no policy\" and \"a " +
      "policy that permits nothing\" are indistinguishable from outside and " +
      "want opposite fixes. It reports loaded=" + empty.holding.loaded);
    assert.strictEqual(refused.body.decision, "NotApplicable",
      "there is nothing to evaluate, so the decision is NotApplicable rather " +
      "than a Deny; it said " + refused.body.decision);
    assert.strictEqual(refused.status, 403,
      "and the deny-biased PEP turns that into a refusal; it answered " +
      refused.status);
    assert.ok(String(refused.body.note || "").indexOf("NotApplicable") > 0,
      "and the answer should explain that the BIAS decided rather than a " +
      "policy — the one case where a 403 is not a rule refusing anybody. It " +
      "says " + JSON.stringify(refused.body.note));
  });

  // BACK ON AGAIN, because a PEP that latched would pass everything above.
  await act("enable", { name: POLICY_A }, "re-enabled the baseline policy");
  await until("the PEP to recover when the policy comes back",
              async function () {
    const r = await askThePep({ subject: ADMIN_PERSON, employeeType: "admin",
                                action: "DELETE" });
    return { ok: r.status === 200,
             note: "the admin is still refused (" + r.status + ")" };
  });
  const recovered = await pepOverview();
  check("and it recovers rather than latching", function () {
    assert.strictEqual(recovered.holding.loaded, true,
      "the policy is enabled again and the PEP should be holding it; it says " +
      recovered.holding.lastPullWhy);
    assert.strictEqual(recovered.holding.root, ID_OF[POLICY_A]);
  });

  log.info("[disable] OK — a disabled policy stops being enforced in another " +
           "container, and an empty holding is the one state the bias " +
           "decides.");
  log.debug("Leaving aDisabledPolicyStopsBeingEnforced().");
}

// ===========================================================================
// 6. THE NUDGE, DELIVERED FOR REAL, ACROSS THE DOCKER NETWORK.
//
// **THIS SECTION IS THE REASON THE PEP IS A CONTAINER RATHER THAN A CHILD
// PROCESS**, and it is the only test anywhere that dials `xacml_pep_http.js`'s
// outbound request at a listener that answers. Every outbound request this
// service makes is argued separately (the root CLAUDE.md indexes them); the
// nudge was one of the first three and the weakest of them, and pays for
// itself by carrying nothing — and until this section it had never been
// delivered to anything in a test.
//
// **THE PROOF IS THE PDP'S OWN ROW AND THE TIMING IS THE CORROBORATION**, and
// they are that way round on purpose. `recordNotify()` writes what the PEP
// ANSWERED onto the row, so a row reading "The PEP answered 204." at a stamp
// later than the change is direct evidence that this service dialled that
// container and it replied. The latency cannot be direct evidence of anything:
// the poll interval is a uniform window, so a poll that happened to fire just
// after the change looks exactly like a nudge. What the latency adds is the
// other direction — a nudge that was delivered but somehow did not cause a
// pull would leave the row correct and the convergence slow — so both are
// asserted and neither is asked to carry the other's weight.
// ===========================================================================
async function theNudgeIsDelivered(polledMs) {
  log.debug("Entering theNudgeIsDelivered().");
  log.info("=== The nudge, over the bridge, for real ===");

  // THE NUDGE ON, IN THIS REALM, AND NOTHING ELSE (2026-11-14): the notify
  // URL is the PEP's HTTPS listener, and no xacml.pepNotifyCaFile is named,
  // so a delivery below proves the default trust — this realm's pep-tls
  // Issuing CA, which issued the pair section 1b wrote — in whatever mode
  // the realm is in. Plain http has no setting to turn on any more.
  await setSetting("xacml.pepNotify", true);
  const readied = await pepRow();
  check("with the nudge on, the PDP considers the PEP nudgeable over https",
        function () {
    assert.strictEqual(readied.row.notifyProblem, null,
      "an https notify URL raises no problem; the row reports: " +
      readied.row.notifyProblem);
    assert.ok(/^https:\/\//.test(String(readied.row.notifyUrl || "")),
      "and the row should carry the HTTPS address the PEP registered; it " +
      "has " + readied.row.notifyUrl);
    assert.ok(!String((readied.register && readied.register.notify &&
                       readied.register.notify.transport &&
                       readied.register.notify.transport.caFile) || ""),
      "and no CA file is named, so what verifies the PEP is the realm's own " +
      "pep-tls chain");
    if (pep.mode === "bridge") {
      assert.ok(readied.row.notifyUrl.indexOf(PEP_NAME) > 0,
        "on the bridge that address is the PEP's container name, which only " +
        "resolves inside the network — so a nudge that arrives proves the " +
        "two containers found each other. It is " + readied.row.notifyUrl);
    }
  });

  const started = Date.now();
  // ONE ACTION AND NOT TWO. Re-enabling the widened policy makes it the root
  // again on its own — `disable` left its isRoot flag alone and
  // `xacml_store.js` picks the single flagged enabled policy — so this is
  // exactly one repository change and therefore exactly one nudge to measure.
  await act("enable", { name: POLICY_B }, "re-enabled the widened policy");
  const arrived = await until(
    "the nudged PEP to enforce the change",
    async function () {
      const r = await askThePep({ subject: STAFF_PERSON, employeeType: "staff",
                                  action: "DELETE" });
      return { ok: r.status === 200,
               note: "the PEP still answers " + r.status };
    });
  const elapsed = Date.now() - started;

  const after = await pepOverview();
  check("and it is enforcing the right document, not merely a different one",
        function () {
    assert.strictEqual(after.holding.root, ID_OF[POLICY_B],
      "the re-enabled policy carries the root flag, so both ends should make " +
      "it the root again; the PEP starts from " + after.holding.root);
    assert.strictEqual(after.holding.policyCount, 2,
      "and both policies are enabled again; it holds " +
      after.holding.policyCount);
  });

  // THE PDP'S OWN ACCOUNT OF IT, AND THE HALF THAT ACTUALLY PROVES THE
  // DELIVERY. `recordNotify()` writes what the PEP answered onto the row, so a
  // nudge that was refused before dialling, timed out, or reached something
  // that was not this PEP leaves a DIFFERENT sentence here — while the poll
  // converges anyway and every other assertion in this section still passes.
  // ---------------------------------------------------------------------
  // POLLED, BECAUSE THE OUTCOME IS WRITTEN AFTER THE RESPONSE (2026-09-08).
  //
  // The save deliberately does not wait on the nudge — that is asserted a few
  // sections up — so `recordNotify()` writes this row once the PEP has
  // answered, with no request left for anything to hold. In ONE process that
  // write is in memory before the next line runs. Across REQUEST WORKERS it is
  // a store write that has to replicate, and the pool's read barrier cannot
  // cover it: there is no ticket, because there is no request behind it.
  //
  // Reading it once therefore raced, and lost by about a hundred milliseconds:
  // the row still carried the DELIBERATE refusal from section 1 — "plain http
  // and xacml.pepNotifyAllowHttp is off" — while the service log showed
  // the nudge going out correctly, "over plain http (… is on)", moments
  // before. That is the hardest kind of false failure to read, because the
  // sentence it reports is a real one this job put there on purpose.
  //
  // The ASSERTION IS UNCHANGED: it must still say the PEP answered 20x. Only
  // the reading is retried, which is what `until()` exists for and what every
  // other cross-process claim in this file already does.
  // ---------------------------------------------------------------------
  const recorded = await until(
    "the PDP to record the nudge's outcome on the PEP's row",
    async function () {
      const seen = (await pepRow()).row;
      return { ok: !!seen.lastNotify && /answered 20\d/.test(seen.lastNotify),
               note: "the row says " + (seen.lastNotify || "nothing at all"),
               row: seen };
    });
  const row = recorded.row || (await pepRow()).row;
  check("the PDP recorded the delivery on the PEP's own row", function () {
    assert.ok(row.lastNotify,
      "xacml_pep_http.js records every nudge's outcome through " +
      "recordNotify(); this row carries nothing at all, which means no nudge " +
      "was ever dialled. The row is " + JSON.stringify(row) + pepLog());
    assert.ok(/answered 20\d/.test(row.lastNotify),
      "AND IT MUST SAY THE PEP ANSWERED. `pep.js` answers a nudge 204 " +
      "immediately and pulls afterwards, so a delivered nudge reads \"The " +
      "PEP answered 204.\" — anything else is a nudge that was refused " +
      "before dialling, timed out, or reached something that was not this " +
      "PEP. It says: " + row.lastNotify);
    const at = Date.parse(String(row.lastNotify).split(" — ")[0]);
    assert.ok(at >= started - 1000,
      "and it must be THIS nudge rather than an older one; it is stamped " +
      row.lastNotify + " and the change was made at " +
      new Date(started).toISOString());
  });

  // AND ONLY NOW WHICH PULL DID IT. The row above is the deterministic half
  // and it is asserted FIRST on purpose: a broken nudge must fail on "no
  // nudge was ever dialled". What the row cannot say is that the delivery
  // actually CAUSED this convergence rather than a poll racing it.
  //
  // THIS WAS A LATENCY UNTIL 2026-09-26 — under a quarter of the poll
  // interval — and it stopped meaning that when the suite began running jobs
  // side by side: with the bulk loads beside it the PDP answered the nudged
  // pull in 2.5s, the nudge had worked, and the number said it had not. So
  // the PEP now records what asked for the pull that changed its holding
  // (`sync.js`'s `lastChangeCause`), and that is asserted instead. The
  // latency is still logged.
  // AND SINCE 2026-09-30 A POLL MAY WIN THE RACE, BY A MOMENT, AND THAT IS
  // NOT A FAILURE. The PEP polls every POLL_MS on its own clock, so a poll
  // that fires between the save and the nudge's pull brings the change, and
  // the nudge's pull finds nothing new: `lastChangeCause` says "poll" for a
  // PEP that did exactly what it should. It failed a single-node run at 1.3s
  // of latency — about one run in four at that speed. What the check exists
  // to catch is a nudge ANSWERED AND NOT ACTED ON, so it now reads the PEP's
  // record of its last nudge-caused pull (`lastNudgeAt`, `lastNudgeResult`,
  // `sync.js`): either that pull brought the change, or it ran after the
  // change was in and found it already there.
  const nudged = await until(
    "the PEP to record the pull this nudge caused",
    async function () {
      const seen = (await pepOverview()).holding;
      return { ok: !!seen.lastNudgeAt &&
                   Date.parse(seen.lastNudgeAt) >= started - 1000,
               note: "its last nudged pull is " +
                     (seen.lastNudgeAt || "none") + " (" +
                     (seen.lastNudgeResult || "no result") + ")",
               holding: seen };
    });
  const holding = nudged.holding || (await pepOverview()).holding;
  check("and the NUDGE's pull acted on it, whether or not a poll beat it",
        function () {
    const byNudge = holding.lastChangeCause === "nudge";
    // THE NUDGE BROUGHT IT, AND A POLL ALREADY IN FLIGHT ANSWERED LATER
    // (2026-10-07). A poll that set off with the old ETag before the nudged
    // pull landed comes back "changed" too, a few milliseconds after, and is
    // then the last change recorded — memory mode, 0de7bca4: the nudge's
    // pull "changed" at :40.671 and the poll at :40.682. The nudge acted on
    // it; what this check refuses is a nudged pull that found nothing.
    const nudgeChanged = holding.lastNudgeResult === "changed" &&
      Date.parse(holding.lastNudgeAt) >= started - 1000;
    const pollFirst = holding.lastChangeCause === "poll" &&
      holding.lastNudgeResult === "unchanged" &&
      Date.parse(holding.lastNudgeAt) >= Date.parse(holding.lastChangeAt);
    assert.ok(byNudge || nudgeChanged || pollFirst,
      "the PEP records what asked for the pull that last changed its " +
      "holding (\"" + holding.lastChangeCause + "\" at " +
      holding.lastChangeAt + ") and what its last nudged pull found (\"" +
      holding.lastNudgeResult + "\" at " + holding.lastNudgeAt + "). A " +
      "nudge recorded as delivered whose pull neither brought the change nor " +
      "found it already there is a PEP that answers a nudge without acting " +
      "on it, which looks identical from every other angle. This " +
      "convergence took " + elapsed + "ms against " + polledMs +
      "ms by polling and a " + POLL_MS + "ms interval." + pepLog());
    log.info("Nudged convergence: " + elapsed + "ms, against " + polledMs +
             "ms by polling and a " + POLL_MS + "ms interval; the change " +
             "came by " + holding.lastChangeCause + ".");
  });

  log.info("[nudge] OK — the PDP dialled the PEP across the " + pep.network +
           " network, the PEP answered, and the change was enforced " +
           elapsed + "ms after it was made.");
  log.debug("Leaving theNudgeIsDelivered().");
}

// ===========================================================================
// 7. THE PDP'S CONSOLE SHOWS COUNTERS FOR DECISIONS IT NEVER SAW.
//
// This is the closing half of section 2's claim. Every decision above was made
// in the container; the ONLY reason any of them is visible on
// `/admin-api/xacml/peps` is that the PEP reported its counters on a heartbeat.
//
// The numbers are compared against the PEP'S OWN, read from `GET /`, rather
// than against constants — a test that counted its own requests would have to
// be edited every time a section above added one, and would then be asserting
// its own arithmetic rather than the transport.
// ===========================================================================
async function thePdpSeesWhatItNeverSaw() {
  log.debug("Entering thePdpSeesWhatItNeverSaw().");
  log.info("=== The heartbeat: counters from another container ===");

  const mine = (await pepOverview()).enforced;
  assert.ok(mine.decisions > 0,
    "this section is worthless unless decisions have been made; the PEP " +
    "reports " + JSON.stringify(mine));

  // WAIT FOR THE BEAT RATHER THAN FOR A CLOCK. The PEP heartbeats every
  // HEARTBEAT_MS, and the row carries what the LAST beat said — so a run that
  // slept a fixed interval and then read would be betting on a timer.
  await until("the PDP's register to catch up with the PEP's own counters",
              async function () {
    const there = await pepRow();
    if (!there.row) {
      return { ok: false, note: "the register does not list " + PEP_NAME };
    }
    return { ok: there.row.decisions >= mine.decisions,
             note: "the row reports " + there.row.decisions +
                   " decision(s) and the PEP has made " + mine.decisions };
  });

  // Re-read both TOGETHER at the end, because the wait above may itself have
  // taken a beat or two and the PEP has answered nothing since.
  const finalMine = (await pepOverview()).enforced;
  const finalRow = (await pepRow()).row;
  check("every decision the container made is reported on the PDP's console",
        function () {
    assert.strictEqual(finalRow.decisions, finalMine.decisions,
      "the PEP has decided " + finalMine.decisions + " time(s) and the " +
      "register reports " + finalRow.decisions + ". THE PDP SAW NONE OF " +
      "THOSE REQUESTS — this number exists only because the PEP sent it.");
    assert.strictEqual(finalRow.allowed, finalMine.allowed,
      "allowed: PEP " + finalMine.allowed + ", register " + finalRow.allowed);
    assert.strictEqual(finalRow.refused, finalMine.refused,
      "refused: PEP " + finalMine.refused + ", register " + finalRow.refused);
    assert.ok(finalMine.allowed > 0 && finalMine.refused > 0,
      "and the run should have produced some of each, or the comparison " +
      "above is weaker than it looks: " + JSON.stringify(finalMine));
  });

  check("and the register agrees with the PEP about what it is holding",
        function () {
    assert.strictEqual(finalRow.policyCount, 2,
      "the PEP holds both policies after section 6; the row says " +
      finalRow.policyCount);
    assert.strictEqual(finalRow.current, true,
      "CURRENT IS A COMPARISON THE PDP PERFORMS, between the token the PEP " +
      "last reported and the one the repository has now — which is what " +
      "makes \"is everybody deciding with the same policy\" answerable at " +
      "all. The row says current=" + finalRow.current + " (it holds " +
      String(finalRow.syncToken).slice(0, 12) + "…)");
    assert.strictEqual(finalRow.stale, false,
      "and it is being heard from; lastSeen=" + finalRow.lastSeen);
  });

  log.info("[heartbeat] OK — " + finalRow.decisions + " decision(s) made in " +
           "another container and visible here because that container said " +
           "so.");
  log.debug("Leaving thePdpSeesWhatItNeverSaw().");
}

// ===========================================================================
// 8. THE NUDGE CARRIES NOTHING, AND IS ANSWERED BEFORE THE PULL.
//
// Section 6 proved the PDP's nudge is delivered. This one is about what a PEP
// may believe of ANY caller that can reach its notify endpoint, and it is
// driven from HERE rather than from the PDP for the reason that makes it worth
// asserting at all: the PDP's nudge carries `{event, at, pdp}` and nothing
// else, so only a hand-made request can ask what happens when one carries
// policy. Two contracts, both `pep.js`'s own:
//
//   1. IT ANSWERS IMMEDIATELY AND PULLS AFTERWARDS. The PDP times a nudge out
//      at `xacml.pepNotifyTimeoutMs` — 2000ms by default — and a PEP that held
//      the request open for the length of a pull would appear UNREACHABLE on
//      somebody's console while working perfectly.
//   2. NOTHING IN THE BODY IS READ. A nudge says only that something changed;
//      what changed is discovered by pulling from the PEP's own configured URL.
//      A nudge that could tell a PEP what the policy now is would be an
//      unauthenticated caller supplying policy — and it is precisely because
//      the nudge carries nothing that it was affordable as an outbound request
//      at all (`xacml/CLAUDE.md`, indexed from the root CLAUDE.md's *Things
//      this service deliberately does not do*).
//
// The second is asserted with a body that WOULD change the decision if it were
// believed, which is the only version of that assertion worth making.
// ===========================================================================
async function theNudgeCarriesNothing() {
  log.debug("Entering theNudgeCarriesNothing().");
  log.info("=== A nudge is believed about nothing ===");

  const before = await pepOverview();

  // THE NUDGE IS HTTPS ONLY (2026-11-14): over plain HTTP the PEP refuses it.
  const plain = await fetchJson(pep.url + "/notify", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: "{}" });
  check("a nudge over plain HTTP is refused, naming the HTTPS listener",
        function () {
    assert.strictEqual(plain.status, 404,
      "POST /notify over plain HTTP answered " + plain.status + " " +
      String(plain.text).slice(0, 200));
    assert.ok(/HTTPS listener only/.test(String(plain.text)),
      "and it says where the nudge is answered: " +
      String(plain.text).slice(0, 200));
  });

  const started = Date.now();
  const nudged = await pepHttpsGet("/notify", pep.anchorPem, {
      changed: true,
      syncToken: "a-token-this-pep-should-not-adopt",
      policies: [{ name: "hostile", policyId: "urn:test:hostile", isRoot: true,
                   document: "<Policy " +
                             "xmlns=\"urn:oasis:names:tc:xacml:3.0:core:schema:wd-17\" " +
                             "PolicyId=\"urn:test:hostile\" Version=\"1.0\" " +
                             "RuleCombiningAlgId=\"urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:permit-overrides\">" +
                             "<Target/><Rule RuleId=\"urn:test:hostile:all\" " +
                             "Effect=\"Permit\"><Target/></Rule></Policy>" }],
      policiesUrl: "http://127.0.0.1:1/xacml/pep/policies"
  });
  // A POLICY THAT PERMITS EVERYTHING, offered to the PEP by an
  // unauthenticated caller. If any of this were read, the assertions below
  // would fail — which is the whole reason to send it rather than `{}`.
  const answeredIn = Date.now() - started;

  check("a nudge is answered 204 and well inside the PDP's timeout",
        function () {
    assert.strictEqual(nudged.status, 204,
      "POST /notify answered " + nudged.status + " " +
      String(nudged.text).slice(0, 200));
    assert.ok(answeredIn < 2000,
      "IT MUST ANSWER BEFORE IT PULLS. xacml.pepNotifyTimeoutMs is 2000ms by " +
      "default, and a PEP that held the request open for the length of a " +
      "pull would be recorded as unreachable on /admin/xacml/peps while " +
      "working perfectly. This one answered in " + answeredIn + "ms.");
  });

  // The nudged pull happens after the answer, so give it a moment to land
  // before asserting what the PEP is holding — otherwise this section could
  // pass by reading the state from before the pull it just triggered.
  await sleep(1500);
  const after = await pepOverview();

  check("and NOTHING in the nudge was believed", function () {
    assert.strictEqual(after.holding.syncToken, before.holding.syncToken,
      "the body offered a sync token and the PEP must not have adopted it; " +
      "it holds " + String(after.holding.syncToken).slice(0, 20) + "…");
    assert.strictEqual(after.holding.root, ID_OF[POLICY_B],
      "the body offered a permit-everything policy as the root. The PEP is " +
      "starting from " + after.holding.root + ", which is the document it " +
      "PULLED from the PDP. A PEP that read a nudge's body would be one an " +
      "unauthenticated caller could hand policy to.");
    assert.strictEqual(after.holding.policyCount, 2,
      "and it holds only what the repository has; it holds " +
      after.holding.policyCount);
  });

  const stillRefused = await askThePep({ subject: "mallory",
                                         employeeType: "contractor",
                                         action: "GET" });
  check("the access the hostile policy would have granted is still refused",
        function () {
    assert.strictEqual(stillRefused.status, 403,
      "the offered document permits EVERYTHING, including this role that no " +
      "rule mentions; if any of it had been adopted this would be a 200. It " +
      "answered " + stillRefused.status + " — " + stillRefused.body.why);
  });

  log.info("[body] OK — 204 in " + answeredIn + "ms, and the body changed " +
           "nothing.");
  log.debug("Leaving theNudgeCarriesNothing().");
}

// ===========================================================================
// 9. THE PDP GOES AWAY AND THE CONTAINER GOES ON ENFORCING.
//
// **THE TRADE `sync.js` ARGUES AT LENGTH AND NOTHING HAS EVER CHECKED.** A PDP
// that is down, unreachable or answering nonsense does not make a PEP stop
// deciding — it makes it go on deciding with what it last pulled, and mark
// itself stale. The alternative is a distributed authorization system in which
// a PDP outage denies everything everywhere, which is the failure mode that
// makes people take authorization services out.
//
// **THE OUTAGE USED TO BE MADE BY REMOVING THE REALM AND IS NOT SINCE
// 2026-09-06**, because a realm a test run created stays — it is what a person
// reads when the run went red, and in this job it holds the policy documents
// the whole file is about. It is made by turning `xacml.remotePeps` OFF in the
// realm instead, which is a better instrument as well as a permitted one: the
// three endpoints under /xacml/pep and `POST /xacml/pip` answer 501 to that
// container and to nothing else in the service, so the outage is scoped
// exactly to the seam under test and is REVERSIBLE, where a removal was not.
// From the PEP's side the two are the same event — a pull that does not return
// a policy set — and `sync.js` takes any non-200 through the same `keep()`.
//
// Stopping the `sts` container would be the more literal outage and is not
// available: the rest of the suite is using it.
//
// IT IS LEFT OFF. Turning it back on would erase the state this section is
// about from the realm a person is meant to be able to read afterwards, and
// the container is stopped a moment later anyway. The teardown says so.
//
// Both halves are asserted, because they are two different claims: that it goes
// on ENFORCING, and that it says it is STALE rather than hiding it. A PEP that
// kept enforcing and reported itself healthy would be the dangerous one.
// ===========================================================================
async function itKeepsEnforcingWhenThePdpIsGone() {
  log.debug("Entering itKeepsEnforcingWhenThePdpIsGone().");
  log.info("=== The PDP disappears, and the container carries on ===");

  const held = await pepOverview();
  await setSetting("xacml.remotePeps", false);
  log.info("xacml.remotePeps is now OFF in " + REALM + ": every endpoint " +
           "under /xacml/pep answers 501 to that container, which is the " +
           "outage.");

  await until("the PEP to notice its PDP has gone", async function () {
    const r = await pepOverview();
    return { ok: r.holding.lastPullOk === false,
             note: "its last pull still reports ok=" + r.holding.lastPullOk };
  });

  const stranded = await pepOverview();
  check("a PDP it cannot reach does NOT make the PEP stop deciding",
        function () {
    assert.strictEqual(stranded.holding.loaded, true,
      "IT KEEPS THE LAST GOOD POLICY SET. A failed pull must not empty the " +
      "holding — that would turn a PDP outage into a service that denies " +
      "everything everywhere, which is the failure that makes people remove " +
      "authorization systems. It reports loaded=" + stranded.holding.loaded);
    assert.strictEqual(stranded.holding.policyCount, held.holding.policyCount,
      "and it holds the same count as before the outage: " +
      held.holding.policyCount + " then, " + stranded.holding.policyCount +
      " now");
    assert.strictEqual(stranded.holding.root, ID_OF[POLICY_B],
      "starting from the same document: " + stranded.holding.root);
    assert.ok(String(stranded.holding.lastPullWhy).indexOf("KEEPING") > 0,
      "and it should SAY it is going on with what it has, because a policy " +
      "change made during an outage is not enforced here and hiding that " +
      "would be the dangerous half. It says: " + stranded.holding.lastPullWhy);
  });

  const allowed = await askThePep({ subject: STAFF_PERSON,
                                    employeeType: "staff",
                                    action: "DELETE" });
  const denied = await askThePep({ subject: "mallory",
                                   employeeType: "contractor",
                                   action: "GET" });
  check("and it goes on deciding CORRECTLY, both ways, with no PDP at all",
        function () {
    assert.strictEqual(allowed.status, 200,
      "the widened policy it last pulled permits staff to DELETE; with the " +
      "PDP gone it answered " + allowed.status + " — " + allowed.body.why);
    assert.strictEqual(denied.status, 403,
      "AND IT MUST STILL REFUSE. A PEP that answered 200 to everything after " +
      "an outage would pass the assertion above and be the worst possible " +
      "failure. It answered " + denied.status);
  });

  check("the PEP reports itself STALE rather than hiding it", function () {
    // `stale` here is the PEP's OWN verdict — three missed polls — and is
    // deliberately not the same measurement as the PDP's, which counts missed
    // heartbeats. The PDP's row survives the outage now that it is a setting
    // rather than a removal, but its own clock is not what this asks about:
    // the heartbeat endpoint is off too, so the PDP is measuring the same
    // silence from the other end and would only report it later. This is the
    // half a person debugging the container would reach for.
    assert.strictEqual(stranded.holding.lastPullOk, false,
      "its last pull failed and it should say so: " +
      stranded.holding.lastPullWhy);
    assert.ok(stranded.staleAfterMs > 0,
      "and it should publish how long it waits before calling itself stale; " +
      "it says " + stranded.staleAfterMs);
  });

  log.info("[outage] OK — the PDP is gone, the container is stale, and it is " +
           "still deciding correctly in both directions.");
  log.debug("Leaving itKeepsEnforcingWhenThePdpIsGone().");
}

// ===========================================================================
// 10. THE CONTAINER AS A REVERSE PROXY IN FRONT OF AN APPLICATION (#1760).
//
// The PEP can stand in front of an application: an administrator gives a
// registered PEP an upstream and an ordered list of routes through
// `POST /admin-api/xacml/set-pep-proxy`, the PEP pulls that configuration
// over its mutual TLS (`GET /xacml/pep/proxy`), and on its own two
// listeners (9180 plain, 9543 over section 1b's pair) it authenticates
// each request by the route's mechanism, asks its own engine, and forwards
// what is allowed. The issue's decisions D1–D9 are the contract this
// section is written against.
//
// **THE APPLICATION IS THE COMPANION'S `/pep-app`** (rcbj on #1760:
// `companion/pep_app.js`, development only), which echoes what reached it
// as JSON — method, raw path, query, every header — so each sub-case below
// asserts what the proxy FORWARDED, not only what it answered. Its own hit
// counter (`/pep-app/_hits`) is read DIRECTLY, never through the proxy, so
// "refused and the application never reached" is a fact this job sees.
//
// **THE DECISION IS THE REALM'S OWN POLICY**, the widened RBAC document of
// section 4 that is still the root: an `admin` may do anything, `staff`
// GET, HEAD and DELETE, anyone else nothing — the subject the proxy builds
// is the person's USERNAME, and the PIP reads `employeeType` off their
// entry exactly as section 3 showed. So ADMIN_PERSON is permitted, a staff
// POST and an outsider's GET are XACML refusals (403), and no new policy
// is deployed — every section after this one counts two.
//
// **IN DEVELOPMENT MODE, AND BACK.** The proxy is driven with credentials
// a development realm makes cheap: the password grant for a person's own
// JWT, an RFC 8707 `resource` naming an audience nobody registered, any
// password but the reserved `invalid` at the Basic door, a WS-Trust
// UsernameToken for a SAML 2.0 assertion. A product realm refuses the
// first and holds the second to a registered target, so the realm is put
// in development for the section and returned to what it was — the
// product half of the proxy is the PEP's (`cargo test -p xacml-pep`) and
// the service's own validation doors', not this section's.
//
// **A ROUTE NAMES AN APPLICATION (D10)**, and the job registers them first
// through `/admin-api/applications/create`: `pep-app`, the application
// behind the proxy — a confidential OpenID Connect client with the proxy's
// callback registered, the session routes' relying party (D5 revised: the
// PEP is the RP OF that application, through the `oidc-caep-risc` crate),
// and the API route's audience; `pep-app-saml`, the SAML SP whose entity ID
// is the assertion's Audience; `pep-app-scratch`, deleted in 10i; and a
// public client and a callback-less one that a session route must refuse.
// No secret of theirs may appear in an `/admin-api` answer the proxy's
// configuration travels in. **The session routes need the https listener**
// (the relying party refuses a non-loopback http redirect URI), so with no
// pair from section 1b they are left out and their sub-cases skipped.
// ===========================================================================
const http = require("http");
const nodeCrypto = require("crypto");
const authnSignin = require("./authn_signin");
const ssfRoles = require("./ssf_roles.js");

const OUTSIDER_PERSON = "pep-outsider-person";
// Two people, each a member of one configured role, for the route whose
// simple policy names only the first role (section 10j).
const ROLE_READERS = "pep-proxy-readers";
const ROLE_OTHERS = "pep-proxy-others";
const ROLE_READER = "pep-role-reader";
const ROLE_OTHER = "pep-role-other";
const PROXY_API_AUDIENCE = "https://pep-app.example.test/api";
const PROXY_SAML_AUDIENCE = "https://pep-app.example.test/saml";
const PROXY_OTHER_AUDIENCE = "https://somebody-else.example.test/api";
const PROXY_TIMEOUT_MS = 3000;
// THE APPLICATIONS THE ROUTES NAME (D10), in this run's realm.
const PROXY_APP = "pep-app";
const PROXY_SAML_APP = "pep-app-saml";
const PROXY_SCRATCH_APP = "pep-app-scratch";
const PROXY_PUBLIC_APP = "pep-app-public-client";
const PROXY_NO_CALLBACK_APP = "pep-app-no-callback";
// The client secrets this job registered or was handed: never logged, and
// held to every /admin-api answer the proxy's configuration travels in.
const PROXY_SECRETS = [];
// How long a sign-out at the service may take to reach the relying party's
// CAEP poll stream: the library polls every 5 s by default, plus the
// transmitter's own delivery.
const PROXY_SIGNAL_MS = 45000;
// D11's `headers` mode, on every route that forwards headers: who, how, and
// three of the person's claims.
const PROXY_IDENTITY_HEADERS = {
  mode: "headers", separator: ",",
  headers: [{ name: "X-Remote-User", claim: "username" },
            { name: "X-Remote-Auth", claim: "mechanism" },
            { name: "X-Iya-User", claim: "sub" },
            { name: "X-Iya-Email", claim: "email" },
            { name: "X-Iya-Groups", claim: "groups" }]
};
const PROXY_MAX_BODY = 4096;
const COMPANION_IMAGE = "rcbj/iya-sts-companion:test";
const SAML2_TOKEN_TYPE =
  "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";

// The companion this job starts beside its own PEP, by the PEP's name so two
// runs on one machine do not meet.
function companionName() {
  log.debug("Entering companionName().");
  log.debug("Leaving companionName().");
  return "companion-" + PEP_NAME;
}

// THE APPLICATION, WHEN THIS JOB STARTED THE PEP: the companion image built
// from this tree and run where the PEP can dial it — on the PEP's network
// by name, or on the host network on a free port. The launchers start it
// themselves (`docker-compose-run-tests.yml`'s `companion`). This is the
// simplest arrangement that keeps the two paths one deployment: the same
// image, the same application, a name the PEP dials.
async function startTheCompanion() {
  log.debug("Entering startTheCompanion().");
  const started = Date.now();
  docker(["build", "--quiet", "--tag", COMPANION_IMAGE,
          path.join(REPO_ROOT, "companion")],
         "building the companion image, whose /pep-app the proxy protects");
  log.info("Built " + COMPANION_IMAGE + " in " + (Date.now() - started) +
           "ms.");
  const name = companionName();
  const create = ["create", "--name", name, "--hostname", name,
                  "--network", pep.network,
                  "--env", "COMPANION_KRB5_SERVICE_PORT=off",
                  "--env", "COMPANION_STS_TLS_INSECURE=true",
                  "--env", "COMPANION_LOG_LEVEL=" +
                           (appconfig.LOG_LEVEL || "info")];
  let port = 9700;
  if (pep.mode === "bridge") {
    create.push("--publish", "127.0.0.1::9700");
    create.push("--env", "COMPANION_PORT=9700");
  } else {
    port = await freePort();
    create.push("--env", "COMPANION_PORT=" + port);
  }
  create.push(COMPANION_IMAGE);
  dockerQuiet(["rm", "-f", name]);
  docker(create, "creating the companion container");
  pep.companionCreated = true;
  docker(["start", name], "starting the companion container");
  if (pep.mode === "bridge") {
    const mapped = docker(["port", name, "9700"],
                          "reading the companion's published port");
    const parsed = /:(\d+)\s*$/.exec(mapped.split("\n")[0] || "");
    assert.ok(parsed, "docker port said \"" + mapped + "\" for the " +
              "companion, which carries no port this job can dial");
    pep.upstreamUrl = "http://" + name + ":9700";
    pep.upstreamDirectUrl = "http://127.0.0.1:" + parsed[1];
  } else {
    pep.upstreamUrl = "http://127.0.0.1:" + port;
    pep.upstreamDirectUrl = pep.upstreamUrl;
  }
  log.info("The companion " + name + " is the proxy's upstream at " +
           pep.upstreamUrl + "; this job reads it at " +
           pep.upstreamDirectUrl + ".");
  log.debug("Leaving startTheCompanion().");
}

function stopTheCompanion() {
  log.debug("Entering stopTheCompanion().");
  if (!pep.companionCreated) {
    log.debug("Leaving stopTheCompanion(). Nothing was created here.");
    return;
  }
  const tail = dockerQuiet(["logs", "--tail", "80", companionName()]);
  log.debug("The companion container's log:\n" +
            (tail.out || tail.err || "(none)"));
  const removed = dockerQuiet(["rm", "-f", companionName()]);
  if (!removed.ok) {
    log.warn("Could not remove the companion container " + companionName() +
             ": " + removed.err);
  }
  pep.companionCreated = false;
  log.debug("Leaving stopTheCompanion().");
}

// ONE REQUEST TO THE PROXY OR THE APPLICATION, WITH THE PATH SENT AS
// WRITTEN. `fetch` resolves `..` and `%2e%2e` away before a byte leaves this
// process, which would make the traversal cases ask about a path nobody
// sent; `http.request` sends the target verbatim. HTTPS trusts ONLY the
// anchor section 1b's pair chains to, with the host name checked.
function proxyRequest(method, url, options) {
  log.debug("Entering proxyRequest(). " + method + " " + url);
  const o = options || {};
  const m = /^(https?):\/\/([^/:]+)(?::(\d+))?(\/.*)?$/.exec(String(url));
  assert.ok(m, "proxyRequest() was handed " + url + ", which it cannot send");
  const secure = m[1] === "https";
  const headers = Object.assign({}, o.headers || {});
  const body = o.body === undefined ? null : Buffer.from(o.body);
  if (body) {
    headers["content-length"] = String(body.length);
  }
  log.debug("Leaving proxyRequest().");
  return new Promise(function (resolve) {
    const started = Date.now();
    const request = (secure ? https : http).request({
      host: m[2], port: m[3] || (secure ? 443 : 80), path: m[4] || "/",
      method: method, headers: headers, agent: false,
      ca: secure && pep.listenerAnchorPem ? [pep.listenerAnchorPem]
                                          : undefined,
      servername: secure ? m[2] : undefined
    }, function (response) {
      const chunks = [];
      response.on("data", function (chunk) {
        chunks.push(chunk);
      });
      response.on("end", function () {
        const text = Buffer.concat(chunks).toString("utf8");
        let json = null;
        try {
          json = JSON.parse(text);
        } catch (e) {
          log.debug("Caught in a callback in proxyRequest(): " +
                    ((e && e.message) || e));
          json = null;
        }
        resolve({ status: response.statusCode, headers: response.headers,
                  text: text, json: json, ms: Date.now() - started });
      });
    });
    request.setTimeout(o.timeoutMs || 20000, function () {
      request.destroy(new Error("no answer within " +
                                (o.timeoutMs || 20000) + "ms"));
    });
    request.on("error", function (e) {
      resolve({ status: 0, headers: {}, text: "", json: null,
                error: e.message, ms: Date.now() - started });
    });
    request.end(body || undefined);
  });
}

// What reached the application, by path, read off it directly.
async function upstreamHits() {
  log.debug("Entering upstreamHits().");
  const r = await proxyRequest("GET", pep.upstreamDirectUrl +
                               "/pep-app/_hits");
  assert.strictEqual(r.status, 200,
    "GET " + pep.upstreamDirectUrl + "/pep-app/_hits should answer the " +
    "companion's hit counter; it answered " + r.status + " " +
    (r.error || r.text.slice(0, 200)) + ". The companion is the " +
    "application behind the proxy; `docker logs` on it says why.");
  log.debug("Leaving upstreamHits().");
  return (r.json && r.json.byPath) || {};
}

function hitsOn(byPath, p) {
  log.debug("Entering hitsOn().");
  log.debug("Leaving hitsOn().");
  return Number(byPath[p] || 0);
}

// A short description of a proxy answer for a failure message.
function told(r) {
  log.debug("Entering told().");
  log.debug("Leaving told().");
  return r.status + " " + (r.error || String(r.text || "").slice(0, 300)) +
         " (www-authenticate: " +
         JSON.stringify((r.headers || {})["www-authenticate"] || null) +
         ", location: " + JSON.stringify((r.headers || {}).location || null) +
         ")";
}

// The echo's identity header, which the route names `X-Remote-User`.
function echoedUser(r) {
  log.debug("Entering echoedUser().");
  log.debug("Leaving echoedUser().");
  return String(((r.json || {}).headers || {})["x-remote-user"] || "");
}

function echoedMechanism(r) {
  log.debug("Entering echoedMechanism().");
  log.debug("Leaving echoedMechanism().");
  return String(((r.json || {}).headers || {})["x-remote-auth"] || "");
}

// A realm setting's value in force, read fresh (`service_facts.js` caches).
async function realmSetting(key) {
  log.debug("Entering realmSetting(). " + key);
  const r = await get(api("/config"));
  assert.strictEqual(r.status, 200,
    "GET /admin-api/config answered " + r.status);
  let found;
  ((r.body || {}).groups || []).forEach(function (group) {
    (group.settings || []).forEach(function (row) {
      if (row.key === key) {
        found = row.value;
      }
    });
  });
  log.debug("Leaving realmSetting(). " + found);
  return found;
}

// A person's own access token from this realm, by the password grant, for
// the RFC 8707 resource asked — a JWT, or an opaque handle when the realm
// issues those.
async function personsToken(username, resource) {
  log.debug("Entering personsToken(). " + username + " " + resource);
  const r = await fetchJson(realmUrl("/oauth2/token"), {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "password", username: username,
                                password: "pep-proxy-" + username,
                                client_id: "pep-proxy-test-client",
                                scope: "openid", resource: resource })
      .toString() });
  assert.ok(r.status === 200 && r.body && r.body.access_token,
    "the password grant for " + username + " with resource " + resource +
    " should issue an access token in this development realm; it " +
    "answered " + r.status + " " + String(r.text).slice(0, 300));
  log.debug("Leaving personsToken().");
  return String(r.body.access_token);
}

function basic(username, password) {
  log.debug("Entering basic().");
  log.debug("Leaving basic().");
  return "Basic " + Buffer.from(username + ":" + password).toString("base64");
}

// A SAML 2.0 assertion THIS REALM ISSUED, for the audience asked: WS-Trust's
// Issue with a UsernameToken (any password but `invalid` in development)
// and AppliesTo naming the audience, the assertion cut out of the RSTR as
// the bytes the service signed.
async function realmAssertion(username, audience) {
  log.debug("Entering realmAssertion(). " + username + " " + audience);
  const rst = '<?xml version="1.0" encoding="UTF-8"?>' +
    '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">' +
    '<soap:Header><wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/' +
    '2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">' +
    '<wsse:UsernameToken><wsse:Username>' + username + '</wsse:Username>' +
    '<wsse:Password>pep-proxy-' + username + '</wsse:Password>' +
    '</wsse:UsernameToken></wsse:Security></soap:Header>' +
    '<soap:Body><wst:RequestSecurityToken ' +
    'xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">' +
    '<wst:RequestType>' +
    'http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType>' +
    '<wst:TokenType>' + SAML2_TOKEN_TYPE + '</wst:TokenType>' +
    '<wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">' +
    '<wsa:EndpointReference ' +
    'xmlns:wsa="http://www.w3.org/2005/08/addressing"><wsa:Address>' +
    audience + '</wsa:Address></wsa:EndpointReference></wsp:AppliesTo>' +
    '</wst:RequestSecurityToken></soap:Body></soap:Envelope>';
  const r = await fetch(realmUrl("/sts"), {
    method: "POST", headers: { "content-type": "application/soap+xml" },
    body: rst });
  const text = await r.text();
  assert.strictEqual(r.status, 200,
    "WS-Trust Issue at " + realmUrl("/sts") + " should issue a SAML 2.0 " +
    "assertion for " + username + "; it answered " + r.status + " " +
    text.slice(0, 300));
  const m = /<((?:[A-Za-z0-9_-]+:)?)Assertion[\s>][\s\S]*?<\/\1Assertion>/
    .exec(text);
  assert.ok(m && /urn:oasis:names:tc:SAML:2\.0:assertion/.test(m[0]),
    "the RSTR should carry a SAML 2.0 Assertion that declares its own " +
    "namespace, so it stands alone; it carries " + text.slice(0, 400));
  log.debug("Leaving realmAssertion().");
  return m[0];
}

// THE BROWSER: one jar per origin, the proxy reached with `proxyRequest()`
// (it may be https under section 1b's anchor) and the service with `fetch`
// (the run's trust bundle), every redirect followed, and the service's
// sign-in and consent screens answered over `/authn-api` as their pages do.
function browserJars() {
  log.debug("Entering browserJars().");
  log.debug("Leaving browserJars().");
  return {};
}

function originOf(url) {
  log.debug("Entering originOf().");
  const m = /^(https?:\/\/[^/]+)/.exec(String(url));
  log.debug("Leaving originOf().");
  return m ? m[1].toLowerCase() : "";
}

function jarHeader(jars, url) {
  log.debug("Entering jarHeader().");
  const jar = jars[originOf(url)] || {};
  log.debug("Leaving jarHeader().");
  return Object.keys(jar).map(function (name) {
    return name + "=" + jar[name];
  }).join("; ");
}

function jarTake(jars, url, lines) {
  log.debug("Entering jarTake().");
  const origin = originOf(url);
  jars[origin] = jars[origin] || {};
  [].concat(lines || []).forEach(function (line) {
    const pair = String(line).split(";")[0];
    const at = pair.indexOf("=");
    if (at <= 0) {
      return;
    }
    const name = pair.slice(0, at).trim();
    const value = pair.slice(at + 1).trim();
    if (value === "" || /Max-Age=0|Expires=Thu, 01 Jan 1970/i.test(line)) {
      delete jars[origin][name];
    } else {
      jars[origin][name] = value;
    }
  });
  log.debug("Leaving jarTake().");
}

function isProxyUrl(url) {
  log.debug("Entering isProxyUrl().");
  const origin = originOf(url);
  log.debug("Leaving isProxyUrl().");
  return origin === originOf(pep.proxyUrl) ||
         (!!pep.proxyHttpsUrl && origin === originOf(pep.proxyHttpsUrl));
}

async function browserGet(jars, url) {
  log.debug("Entering browserGet(). " + url);
  const cookie = jarHeader(jars, url);
  const headers = { accept: "text/html,application/xhtml+xml" };
  if (cookie) {
    headers.cookie = cookie;
  }
  if (isProxyUrl(url)) {
    const r = await proxyRequest("GET", url, { headers: headers });
    jarTake(jars, url, r.headers["set-cookie"]);
    log.debug("Leaving browserGet(). The proxy: " + r.status);
    return { status: r.status, location: r.headers.location || "",
             text: r.text, json: r.json, headers: r.headers, url: url };
  }
  const r = await fetch(url, { redirect: "manual", headers: headers });
  jarTake(jars, url, r.headers.getSetCookie ? r.headers.getSetCookie() : []);
  const text = r.status >= 300 && r.status < 400 ? "" : await r.text();
  log.debug("Leaving browserGet(). The service: " + r.status);
  return { status: r.status, location: r.headers.get("location") || "",
           text: text, json: null, headers: {}, url: url };
}

// From `url`, through every redirect and screen, until an answer that is
// neither. Answers the last response and every address it passed.
async function browse(jars, url, username) {
  log.debug("Entering browse(). " + url);
  const passed = [];
  let at = url;
  let r = await browserGet(jars, at);
  for (let n = 0; n < 25; n += 1) {
    passed.push(r.status + " " + at.replace(/([?&](code|state)=)[^&]+/g,
                                             "$1…"));
    if (r.status >= 300 && r.status < 400 && r.location) {
      at = new URL(r.location, at).toString();
      r = await browserGet(jars, at);
      continue;
    }
    if (r.status === 200 && /\/authn\/signin\.js/.test(r.text || "")) {
      const answer = await authnSignin.submit(realmUrl(""), at,
        { action: "login", username: username,
          password: "pep-proxy-" + username },
        { cookie: jarHeader(jars, at) });
      jarTake(jars, at, answer.headers.getSetCookie());
      assert.strictEqual(answer.next, "redirect",
        "signing " + username + " in at the service's screen should send " +
        "the browser on; it answered " + answer.status + " " +
        JSON.stringify(answer.json).slice(0, 300));
      at = answer.location;
      r = await browserGet(jars, at);
      continue;
    }
    if (r.status === 200 && authnSignin.isConsent(at)) {
      const answer = await authnSignin.consentFor(at, jarHeader(jars, at));
      jarTake(jars, at, answer.headers.getSetCookie());
      assert.strictEqual(answer.next, "redirect",
        "the consent screen should send the browser on; it answered " +
        answer.status);
      at = answer.location;
      r = await browserGet(jars, at);
      continue;
    }
    break;
  }
  log.debug("Leaving browse(). " + r.status);
  return { r: r, url: at, passed: passed };
}

// THE CONFIGURATION, D2's document as D10 shapes it: every non-public route
// names an APPLICATION of this realm's registry and copies nothing of it —
// the audience, the SAML SP entity and the OIDC client are resolved from
// the application's entry at the pull. First match wins. The two session
// routes are there only when the https listener is (the relying party
// refuses a non-loopback http redirect URI, D5).
//
// EVERY ROUTE MAKES ONE AUTHORIZATION CHOICE (#1760, rcbj 2026-11-15: "All
// authorization decisions are made in XACML"): the two public routes are
// Public, decided by the policy the save generates for each, and every
// other route chooses the realm's ROOT policy by name — the policy this
// job deployed — with the request's path and method, so what it decides
// is what the root decided before routes named their own policy.
function proxyConfiguration(publicBaseUrl, withSession, policyName) {
  log.debug("Entering proxyConfiguration().");
  // D11: the identity reaches the application in one of three modes. Most
  // routes use `headers`, naming five claims; the jwt and saml-app routes
  // below are the other two modes.
  const decidedBy = { kind: "policy", policy: policyName };
  const identity = { forwardCredentials: false, authorization: decidedBy,
                     identity: PROXY_IDENTITY_HEADERS };
  const routes = [
    { id: "public", path: "/pep-app/public", match: "prefix",
      methods: ["GET", "HEAD"], authorization: { kind: "public" } },
    { id: "slow", path: "/pep-app/slow", match: "exact",
      methods: ["GET"], authorization: { kind: "public" } }
  ];
  if (withSession) {
    routes.push(Object.assign({ id: "protected-fallback",
                                path: "/pep-app/protected-fallback",
                                match: "prefix", methods: ["GET", "HEAD"],
                                mechanisms: ["session"],
                                application: PROXY_APP, signals: false },
                              identity));
    routes.push(Object.assign({ id: "protected", path: "/pep-app/protected",
                                match: "prefix", methods: ["GET", "HEAD"],
                                mechanisms: ["session"],
                                application: PROXY_APP, signals: true },
                              identity));
  }
  routes.push(Object.assign({ id: "api", path: "/pep-app/api",
                              match: "prefix", methods: ["GET", "POST"],
                              mechanisms: ["oauth2", "basic"],
                              application: PROXY_APP }, identity));
  routes.push(Object.assign({ id: "saml", path: "/pep-app/saml",
                              match: "prefix", methods: ["GET"],
                              mechanisms: ["saml2"],
                              application: PROXY_SAML_APP }, identity));
  routes.push({ id: "jwt", path: "/pep-app/jwt", match: "prefix",
                methods: ["GET"], mechanisms: ["oauth2", "basic"],
                application: PROXY_APP, forwardCredentials: false,
                authorization: decidedBy, identity: { mode: "jwt" } });
  routes.push({ id: "saml-app", path: "/pep-app/saml-app", match: "prefix",
                methods: ["GET"], mechanisms: ["basic"],
                application: PROXY_SAML_APP, forwardCredentials: false,
                authorization: decidedBy, identity: { mode: "saml" } });
  routes.push(Object.assign({ id: "scratch", path: "/pep-app/scratch",
                              match: "prefix", methods: ["GET"],
                              mechanisms: ["basic"],
                              application: PROXY_SCRATCH_APP }, identity));
  log.debug("Leaving proxyConfiguration().");
  return {
    enabled: true,
    upstream: pep.upstreamUrl,
    publicBaseUrl: publicBaseUrl,
    upstreamTimeoutMs: PROXY_TIMEOUT_MS,
    maxBodyBytes: PROXY_MAX_BODY,
    routes: routes
  };
}

// The callback every session route's application must register (D10).
function proxyCallback() {
  log.debug("Entering proxyCallback().");
  log.debug("Leaving proxyCallback().");
  return (pep.proxyHttpsUrl || "https://pep-app.example.test") +
         "/.iya-pep/callback";
}

// A text with every secret this job holds taken out, for a failure message.
function withoutSecrets(text) {
  log.debug("Entering withoutSecrets().");
  let out = String(text || "");
  PROXY_SECRETS.forEach(function (one) {
    if (one) {
      out = out.split(one).join("<client secret>");
    }
  });
  log.debug("Leaving withoutSecrets().");
  return out;
}

// No secret this job registered may appear in an answer of /admin-api's
// that is not the secret's own door.
function carriesNoSecret(text) {
  log.debug("Entering carriesNoSecret().");
  const t = String(text || "");
  log.debug("Leaving carriesNoSecret().");
  return PROXY_SECRETS.every(function (one) {
    return !one || t.indexOf(one) < 0;
  });
}

// `ssf_roles.js`'s poster shape over this file's `postJson()`.
async function ssfPost(url, body) {
  log.debug("Entering ssfPost().");
  const r = await postJson(url, body);
  log.debug("Leaving ssfPost().");
  return { status: r.status, text: r.text, json: r.body };
}

async function createApplication(identifier, protocols, fields, what) {
  log.debug("Entering createApplication(). " + identifier);
  const r = await postJson(api("/applications/create"), {
    identifier: identifier, name: identifier, protocols: protocols,
    fields: fields });
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST /admin-api/applications/create should register " + identifier +
    " (" + what + "); it answered " + r.status + " " +
    withoutSecrets(r.text).slice(0, 300));
  log.debug("Leaving createApplication().");
}

// THE APPLICATIONS THE ROUTES NAME (D10), registered as an administrator
// registers any application: the application behind the proxy as an
// ordinary CONFIDENTIAL OpenID Connect client — the session routes'
// relying party, with the proxy's callback among its redirect URIs, and,
// for the library's CAEP/RISC poll stream, the client credentials grant,
// the two Shared Signals scopes and their roles, as the library's own
// `scripts/configure_iya_sts.py` registers its demonstration — whose
// `oauthAudience` is the API route's audience; a SAML 2.0 service provider
// whose entity ID (and WS-Trust AppliesTo) is the assertion's Audience; a
// scratch application section 10i deletes; and two a session route must
// refuse — a PUBLIC client, and a confidential one without the callback.
async function registerTheApplications() {
  log.debug("Entering registerTheApplications().");
  PROXY_SECRETS.length = 0;
  PROXY_SECRETS.push(nodeCrypto.randomBytes(24).toString("base64url"));
  PROXY_SECRETS.push(nodeCrypto.randomBytes(24).toString("base64url"));
  PROXY_SECRETS.push(nodeCrypto.randomBytes(24).toString("base64url"));
  const callback = proxyCallback();
  await createApplication(PROXY_APP, ["oauth2", "oidc"], {
    oauthClientId: [PROXY_APP], oauthClientSecret: PROXY_SECRETS[0],
    oauthRedirectUri: [callback], oauthResponseType: ["code"],
    oauthGrantType: ["authorization_code", "refresh_token",
                     "client_credentials"],
    oauthAllowedScope: ["openid", "profile", "email", "offline_access",
                        "ssf.read", "ssf.manage"],
    oauthTokenEndpointAuthMethod: "client_secret_basic",
    oauthIdTokenSignedResponseAlg: "RS256",
    oauthAudience: [PROXY_API_AUDIENCE]
  }, "the confidential client behind the proxy");
  await createApplication(PROXY_SAML_APP, ["saml2", "wstrust"], {
    samlEntityId: [PROXY_SAML_AUDIENCE],
    // THE APPLICATION'S OWN ACS (D11's `saml` mode): the companion's, as the
    // PEP dials it, where the proxy POSTs the assertion server-side.
    samlAssertionConsumerService: [pep.upstreamUrl + "/pep-app/saml/acs"],
    wstrustAppliesTo: [PROXY_SAML_AUDIENCE]
  }, "the SAML 2.0 service provider the saml route names");
  await createApplication(PROXY_SCRATCH_APP, ["oauth2"], {
    oauthClientId: [PROXY_SCRATCH_APP], oauthClientSecret: PROXY_SECRETS[1],
    oauthTokenEndpointAuthMethod: "client_secret_basic",
    oauthAudience: ["https://pep-app.example.test/scratch"]
  }, "the scratch application section 10i deletes");
  await createApplication(PROXY_PUBLIC_APP, ["oauth2", "oidc"], {
    oauthClientId: [PROXY_PUBLIC_APP], oauthRedirectUri: [callback],
    oauthResponseType: ["code"], oauthGrantType: ["authorization_code"],
    oauthTokenEndpointAuthMethod: "none"
  }, "a public client a session route must refuse");
  await createApplication(PROXY_NO_CALLBACK_APP, ["oauth2", "oidc"], {
    oauthClientId: [PROXY_NO_CALLBACK_APP],
    oauthClientSecret: PROXY_SECRETS[2],
    oauthRedirectUri: ["https://elsewhere.example.test/callback"],
    oauthResponseType: ["code"], oauthGrantType: ["authorization_code"],
    oauthTokenEndpointAuthMethod: "client_secret_basic"
  }, "a confidential client without the callback or an audience");
  // THE SHARED SIGNALS THE RELYING PARTY'S POLL STREAM NEEDS: the
  // transmitter and CAEP on in this realm (both default on; set so the
  // section rests on no other job's leavings), the client in SSF_READ and
  // SSF_MANAGE, and the person in the two groups, as the library's own
  // registration script does for its test user.
  await setSetting("ssf.enabled", true);
  await setSetting("caep.enabled", true);
  await ssfRoles.mapApplication(ssfPost, api(""), PROXY_APP,
                                "ssf.read ssf.manage");
  for (const group of ["ssf-read", "ssf-manage"]) {
    const r = await postJson(api("/groups/add-member"),
                             { group: group, member: ADMIN_PERSON });
    assert.ok(r.status === 200 || /already/.test(String(r.text)),
      "adding " + ADMIN_PERSON + " to " + group + " answered " + r.status +
      " " + String(r.text).slice(0, 300));
  }
  log.info("Registered " + PROXY_APP + " (confidential; its callback " +
           callback + "), " + PROXY_SAML_APP + ", " + PROXY_SCRATCH_APP +
           " and the two a session route must refuse.");
  log.debug("Leaving registerTheApplications().");
}

// Where this job reaches the proxy and the application, from the launcher
// or from what `startThePep()` and `startTheCompanion()` made. Answers why
// the section cannot run, or "".
async function findTheProxy() {
  log.debug("Entering findTheProxy().");
  if (LAUNCHER_STARTED_IT) {
    pep.proxyUrl = String(process.env.XACML_PEP_PROXY_URL || "")
      .replace(/\/+$/, "");
    pep.proxyHttpsUrl = String(process.env.XACML_PEP_PROXY_HTTPS_URL || "")
      .replace(/\/+$/, "");
    pep.upstreamUrl = String(process.env.XACML_PEP_UPSTREAM_URL || "")
      .replace(/\/+$/, "");
    pep.upstreamDirectUrl = pep.upstreamUrl;
    if (!pep.proxyUrl || !pep.upstreamUrl) {
      log.debug("Leaving findTheProxy(). Not named.");
      return "the launcher named no proxy listener (XACML_PEP_PROXY_URL=\"" +
             pep.proxyUrl + "\") or no application to put behind it " +
             "(XACML_PEP_UPSTREAM_URL=\"" + pep.upstreamUrl + "\"). " +
             "./run-tests.sh names both in every local mode and starts " +
             "the companion; a stack brought up some other way has no " +
             "application for the proxy to protect.";
    }
  } else {
    await startTheCompanion();
  }
  if (!pep.listenerAnchorPem) {
    // Section 1b wrote no pair, so 9543 does not listen.
    pep.proxyHttpsUrl = "";
  }
  log.debug("Leaving findTheProxy().");
  return "";
}

// ---------------------------------------------------------------------------
// SECTION 9b (#1760): THE SETTINGS THE SERVICE SETS FOR THE PEP.
//
// What the PEP's console page saves reaches the CONTAINER on its next poll,
// with no restart: GET / says each setting's value and whether it is the
// service's, the environment's or the default, and the PDP's row carries
// the same report from the heartbeat and says the PEP holds what was set.
// Cleared, the environment is back. Only settings no later section reads are
// changed (the description, the log level, the bias for one round trip),
// and every one is cleared before the proxy section.
// ---------------------------------------------------------------------------
async function itTakesItsSettingsFromTheService() {
  log.debug("Entering itTakesItsSettingsFromTheService().");
  const before = await pepOverview();
  check("the PEP reports its settings and the service offers them",
        function () {
          assert.ok(before.settings && before.settings.offered === true &&
            before.settings.values && before.settings.values.bias,
            "GET / should carry `settings` with `offered: true` against " +
            "this service; it said " +
            JSON.stringify(before.settings).slice(0, 400));
          assert.notStrictEqual(before.settings.values.bias.source,
            "service", "nothing is set for this PEP yet");
        });
  const marker = "set by sts_xacml_remote_pep " + Date.now();
  const saved = await act("set-pep-settings", {
    name: PEP_NAME,
    settings: { description: marker, logLevel: "info",
                bias: "permit-biased" }
  }, "saved the PEP's settings");
  check("set-pep-settings answers what it saved", function () {
    assert.ok(saved.settings && saved.settings.description === marker,
      "the answer should carry the settings; it said " +
      JSON.stringify(saved).slice(0, 300));
  });
  await until("the PEP to apply the service's settings", async function () {
    const now = await pepOverview();
    const v = now.settings && now.settings.values;
    if (v && v.description && v.description.value === marker &&
        v.description.source === "service" && now.bias === "permit-biased") {
      return { ok: true };
    }
    return { ok: false, note: "GET / settings: " +
             JSON.stringify(now.settings).slice(0, 300) };
  });
  // GET /'s `bias` is what every decision is enforced with (`now().bias`),
  // so the wait above is the bias assertion.
  checks += 1;
  await until("the PDP's row to say the PEP holds them", async function () {
    const r = await get(api("/xacml/peps?pep=" +
                            encodeURIComponent(PEP_NAME)));
    const row = r.body && r.body.peps && r.body.peps[0];
    if (r.status === 200 && r.body.found === true && row &&
        row.settingsCurrent === true && row.settingsInUse &&
        row.settingsInUse.values.description &&
        row.settingsInUse.values.description.source === "service") {
      return { ok: true };
    }
    return { ok: false, note: r.status + " " + JSON.stringify(row && {
      settingsCurrent: row.settingsCurrent,
      settingsInUse: row.settingsInUse }).slice(0, 300) };
  });
  const page = await get(api("/xacml/peps?pep=" +
                              encodeURIComponent(PEP_NAME)));
  check("the PEP's page answers that row alone, with the catalogue",
        function () {
          // SETTINGS in xacml/xacml_pep_settings.ts, description through
          // auditBuffer. proxyMaxAccounts and proxyStripCookies are the two
          // past the old count of 23, and auditEnabled, auditIntervalMs,
          // auditBatch and auditBuffer (#1827's decision records) the four
          // past 25.
          const catalogue = page.body.settingsCatalogue;
          const n = catalogue && catalogue.settings
            ? catalogue.settings.length : 0;
          assert.ok(page.status === 200 && page.body.peps &&
            page.body.peps.length === 1 && n === 29,
            "GET /admin-api/xacml/peps?pep= should answer one row and the " +
            "catalogue of 29 settings; it answered " + page.status +
            " with " + ((page.body.peps && page.body.peps.length) || 0) +
            " row(s) and " + n + " settings");
        });
  const refused = await postJson(api("/xacml/set-pep-settings"),
    { name: PEP_NAME, settings: { pollIntervalMs: 5 } });
  check("an out-of-bounds setting is refused and nothing changes",
        function () {
          assert.ok(refused.status === 400 && refused.body &&
            refused.body.ok === false,
            "pollIntervalMs 5 should be refused; it answered " +
            refused.status + " " + String(refused.text).slice(0, 300));
        });
  await act("clear-pep-settings", { name: PEP_NAME },
            "cleared the PEP's settings");
  await until("the PEP to fall back to its environment", async function () {
    const now = await pepOverview();
    const v = now.settings && now.settings.values;
    if (v && v.description && v.description.source !== "service" &&
        now.settings.configured === false &&
        now.bias === before.bias) {
      return { ok: true };
    }
    return { ok: false, note: "GET / settings: " +
             JSON.stringify(now.settings).slice(0, 300) };
  });
  log.info("[settings] OK — the PEP applied the service's settings and " +
           "fell back to its environment when they were cleared, without " +
           "a restart.");
  log.debug("Leaving itTakesItsSettingsFromTheService().");
}

// ---------------------------------------------------------------------------
// SECTION 10a (#1760): THE LISTENERS THE SERVICE DEFINES. One HTTP and one
// HTTPS API listener are defined on the PEP's page through /admin-api; the
// PEP binds them on its next poll and reports them on its next heartbeat,
// the HTTPS one with the certificate this realm issued over the key the PEP
// generated; a renewal serves a new serial; removing them unbinds them. Where
// this job shares the PEP's network (a launcher's stack) it dials the new
// ports too; where it reaches the PEP through published ports only the
// report is asserted, since a port defined at run time is not published.
// ---------------------------------------------------------------------------
async function itBindsTheListenersTheServiceDefines() {
  log.debug("Entering itBindsTheListenersTheServiceDefines().");
  const host = new URL(pep.url).hostname;
  const dialable = pep.mode === "provided";
  const rowOf = async function () {
    const r = await get(api("/xacml/peps?pep=" +
                            encodeURIComponent(PEP_NAME)));
    return (r.body && r.body.peps && r.body.peps[0]) || null;
  };
  const listenerOf = function (row, id) {
    return ((row && row.listenerRows) || []).filter(function (one) {
      return one.id === id;
    })[0] || null;
  };
  await until("the PEP to report its environment's listeners",
              async function () {
    const row = await rowOf();
    const env = listenerOf(row, "api-http");
    return { ok: !!env && !!env.reported &&
                 env.reported.state === "listening",
             note: JSON.stringify(row && row.listenerRows).slice(0, 300) };
  });
  const clash = await postJson(api("/xacml/set-pep-listener"),
    { name: PEP_NAME, id: "clash", protocol: "http", purpose: "api",
      port: 9090 });
  check("a listener on the environment's API port is refused", function () {
    assert.ok(clash.status === 400 && clash.body && clash.body.ok === false,
      "port 9090 is api-http's; it answered " + clash.status + " " +
      String(clash.text).slice(0, 300));
  });
  await act("set-pep-listener", { name: PEP_NAME, id: "probe-http",
    protocol: "http", purpose: "api", port: 9191 },
    "defined an HTTP API listener");
  await act("set-pep-listener", { name: PEP_NAME, id: "probe-https",
    protocol: "https", purpose: "api", port: 9445,
    dnsNames: [/^[0-9.]+$/.test(host) ? "localhost" : host] },
    "defined an HTTPS API listener");
  let first = null;
  await until("the PEP to bind both and report the HTTPS certificate",
              async function () {
    const row = await rowOf();
    const plain = listenerOf(row, "probe-http");
    const tls = listenerOf(row, "probe-https");
    const ok = plain && plain.reported &&
      plain.reported.state === "listening" && tls && tls.reported &&
      tls.reported.state === "listening" && tls.reported.certificate &&
      tls.issued &&
      tls.issued.serialHex.toLowerCase().replace(/^0+/, "") ===
        String(tls.reported.certificate.serialHex).toLowerCase()
          .replace(/^0+/, "");
    if (ok) {
      first = tls.issued.serialHex;
    }
    return { ok: !!ok, note: JSON.stringify([plain, tls]).slice(0, 500) +
             pepLog() };
  });
  checks += 1;
  if (dialable) {
    const r = await fetchJson("http://" + host + ":9191/healthcheck");
    check("the defined HTTP listener answers", function () {
      assert.strictEqual(r.status, 200, "GET /healthcheck on 9191 said " +
                         r.status);
    });
  }
  await act("renew-pep-listener-certificate",
            { name: PEP_NAME, listener: "probe-https" },
            "asked for a new certificate");
  await until("the PEP to serve a new certificate on the same listener",
              async function () {
    const tls = listenerOf(await rowOf(), "probe-https");
    return { ok: !!tls && !!tls.issued && tls.issued.serialHex !== first &&
                 tls.reported && tls.reported.renew === 1 &&
                 tls.reported.state === "listening",
             note: JSON.stringify(tls).slice(0, 400) };
  });
  checks += 1;
  await act("remove-pep-listener", { name: PEP_NAME, listener: "probe-http" },
            "removed the HTTP listener");
  await act("remove-pep-listener", { name: PEP_NAME, listener: "probe-https" },
            "removed the HTTPS listener");
  await until("the PEP to unbind them", async function () {
    const row = await rowOf();
    const left = ((row && row.listenersInUse &&
                   row.listenersInUse.listeners) || [])
      .filter(function (one) {
        return one.source === "service";
      });
    return { ok: !!row && row.listenerRows.length === 4 && !left.length,
             note: JSON.stringify(left) };
  });
  checks += 1;
  if (dialable) {
    let gone = 0;
    try {
      gone = (await fetchJson("http://" + host + ":9191/healthcheck")).status;
    } catch (e) {
      // A refused connection is the answer this waits for.
      log.debug("Caught in itBindsTheListenersTheServiceDefines(): " +
                ((e && e.message) || e));
      gone = 0;
    }
    check("the removed listener no longer answers", function () {
      assert.strictEqual(gone, 0, "9191 still answered " + gone);
    });
  }
  log.info("[listeners] OK — the PEP bound, renewed and unbound the " +
           "listeners the service defined, without a restart.");
  log.debug("Leaving itBindsTheListenersTheServiceDefines().");
}

async function itProxiesAnApplication() {
  log.debug("Entering itProxiesAnApplication().");
  log.info("=== The container as a reverse proxy in front of an " +
           "application (#1760) ===");
  const why = await findTheProxy();
  if (why) {
    log.warn("[proxy] SKIPPED — " + why);
    log.debug("Leaving itProxiesAnApplication(). Skipped.");
    return;
  }
  await until("the application behind the proxy to answer",
              async function () {
    const r = await proxyRequest("GET", pep.upstreamDirectUrl +
                                 "/pep-app/_hits");
    return { ok: r.status === 200,
             note: "GET /pep-app/_hits said " + told(r) };
  });

  // WHAT THE APPLICATION TRUSTS (D11): its ACS checks the realm's SAML
  // signature, read from the realm's IdP metadata, for the SP entity the
  // saml-app route's application is; its echo checks a Bearer JWT against
  // the realm's JWKS. Both as the COMPANION reaches the service.
  const realmAsTheCompanionSees = LAUNCHER_STARTED_IT ? realmUrl("")
                                                      : pep.pdpUrl;
  const setUp = await proxyRequest("POST", pep.upstreamDirectUrl +
    "/pep-app/saml/_setup", {
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      audience: PROXY_SAML_AUDIENCE,
      metadataUrl: realmAsTheCompanionSees + "/saml2/metadata",
      jwksUrl: realmAsTheCompanionSees + "/oauth2/jwks" }) });
  assert.ok(setUp.status === 200 && setUp.json &&
            setUp.json.certificates > 0,
    "POST /pep-app/saml/_setup should read the realm's signing " +
    "certificate from " + realmAsTheCompanionSees + "/saml2/metadata; it " +
    "answered " + told(setUp));
  const modeBefore = await realmSetting("global.mode");
  if (modeBefore !== "development") {
    await setSetting("global.mode", "development");
  }
  try {
    await createTheOutsider();
    await registerTheApplications();
    await theProxyIsConfigured();
    await theProxyRefusesWhatIsNotRouted();
    await theProxyTakesAnAccessToken();
    await theProxyTakesBasic();
    await theProxyTakesAnAssertion();
    await theProxyForwardsTheIdentity();
    if (pep.proxyHttpsUrl) {
      await theProxyHoldsASession();
    } else {
      log.warn("[proxy] the SESSION sub-cases are SKIPPED: the proxy's " +
               "https listener is not available (section 1b wrote no " +
               "pair, or the launcher named no XACML_PEP_PROXY_HTTPS_URL), " +
               "and the relying party refuses a non-loopback http " +
               "redirect URI (D5).");
    }
    await theProxyGuardsTheWire();
    await theProxyLosesAnApplication();
    await theProxyDecidesByRole();
    await theProxyIsCleared();
  } finally {
    if (modeBefore !== "development") {
      await setSetting("global.mode", String(modeBefore));
    }
  }
  log.info("[proxy] OK — the PEP stood in front of " + pep.upstreamUrl +
           " on " + pep.proxyUrl + (pep.proxyHttpsUrl ? " and " +
           pep.proxyHttpsUrl : "") + ", by session, OAuth 2.0, Basic and " +
           "SAML 2.0, permitting a member of the route's role and refusing " +
           "a member of another, and serving its public routes, deciding " +
           "each request in its own engine.");
  log.debug("Leaving itProxiesAnApplication().");
}

// A THIRD PERSON, whom the RBAC policy grants nothing: employeeType
// `contractor`, read off the entry by the PIP like the other two.
async function createTheOutsider() {
  log.debug("Entering createTheOutsider().");
  const r = await postJson(api("/users/create"), {
    username: OUTSIDER_PERSON, invent: false,
    attributes: { cn: "Remote PEP Outsider Person", givenName: "Remote",
                  sn: "Outsider Person", displayName: "Remote PEP Outsider",
                  mail: OUTSIDER_PERSON + "@xacml-remote-pep.test",
                  employeeType: "contractor" }
  });
  assert.ok(r.status === 200 && r.body && r.body.ok,
    "POST /admin-api/users/create should put " + OUTSIDER_PERSON +
    " (employeeType=contractor) in " + REALM + "; it answered " + r.status +
    " " + String(r.text).slice(0, 300));
  log.debug("Leaving createTheOutsider().");
}

// 10a. NOTHING BEFORE A CONFIGURATION; THE CONFIGURATION SAVED, REFUSED BY
// NAME WHEN WRONG, PULLED, AND IN FORCE.
async function theProxyIsConfigured() {
  log.debug("Entering theProxyIsConfigured().");
  const before = await pepRow();
  const unconfigured = await proxyRequest("GET", pep.proxyUrl +
                                          "/pep-app/public/");
  check("before a configuration the proxy answers 404 and the row holds " +
        "none", function () {
    assert.ok(before.row && !before.row.proxy,
      "GET /admin-api/xacml/peps should list " + PEP_NAME + " with no " +
      "proxy yet; its row holds " +
      JSON.stringify(before.row && before.row.proxy));
    assert.strictEqual(unconfigured.status, 404,
      "an unconfigured PEP's proxy answers 404 to everything (D3); " +
      "GET /pep-app/public/ answered " + told(unconfigured) + pepLog());
  });

  const withSession = !!pep.proxyHttpsUrl;
  const publicBase = pep.proxyHttpsUrl || pep.proxyUrl;
  // The routes choose the realm's root by name (#1760): the policy this
  // job deployed, whichever it made the root.
  const repository = await get(api("/xacml/policies"));
  const rootName = repository.body && repository.body.root;
  assert.ok(rootName, "GET /admin-api/xacml/policies should name the " +
    "realm's root before the proxy is configured; it answered " +
    String(repository.text).slice(0, 300));
  const config = proxyConfiguration(publicBase, withSession, rootName);
  const savedAnswer = await postJson(api("/xacml/set-pep-proxy"),
                                     { name: PEP_NAME, proxy: config });
  assert.ok(savedAnswer.status === 200 && savedAnswer.body &&
            savedAnswer.body.ok !== false,
    "POST /admin-api/xacml/set-pep-proxy should save the configuration " +
    "for " + PEP_NAME + "; it answered " + savedAnswer.status + " " +
    withoutSecrets(savedAnswer.text).slice(0, 400));
  const saved = await pepRow();
  const listed = await get(api("/xacml/peps"));
  check("the configuration names applications and carries no client secret",
        function () {
    assert.ok(carriesNoSecret(savedAnswer.text) &&
              carriesNoSecret(listed.text),
      "set-pep-proxy's answer and GET /admin-api/xacml/peps must carry no " +
      "client secret of an application a route names (D10: resolved at the " +
      "pull, over mutual TLS, never on /admin-api)");
    ((((saved.row || {}).proxy || {}).routes) || []).forEach(function (one) {
      assert.ok(!("clientSecret" in one) && !("audience" in one) &&
                !("clientId" in one),
        "a saved route holds a reference, never copied fields; route " +
        one.id + " holds " + JSON.stringify(Object.keys(one)));
    });
  });
  check("the PEP's row carries the configuration it was given", function () {
    const p = (saved.row || {}).proxy || {};
    assert.strictEqual(p.upstream, config.upstream,
      "the row's proxy should name the upstream; it holds " +
      JSON.stringify(p).slice(0, 400));
    assert.strictEqual((p.routes || []).length, config.routes.length,
      "and its " + config.routes.length + " routes, in order");
    assert.deepStrictEqual((p.routes || []).map(function (one) {
      return one.id;
    }), config.routes.map(function (one) {
      return one.id;
    }), "in the order they were given: first match wins");
  });

  const refusals = [
    { what: "a route path with a dot segment",
      body: { name: PEP_NAME, proxy: Object.assign({}, config, {
        routes: [{ id: "bad", path: "/pep-app/../admin", match: "prefix",
                   methods: ["GET"], authorization: { kind: "public" } }] }) } },
    { what: "a route making no authorization choice (#1760)",
      body: { name: PEP_NAME, proxy: Object.assign({}, config, {
        routes: [{ id: "nochoice", path: "/pep-app/api", match: "prefix",
                   methods: ["GET"], mechanisms: ["oauth2"],
                   application: PROXY_APP }] }) } },
    { what: "a route stating no methods (#1760)",
      body: { name: PEP_NAME, proxy: Object.assign({}, config, {
        routes: [{ id: "nomethods", path: "/pep-app/public",
                   match: "prefix", authorization: { kind: "public" } }] }) } },
    { what: "an upstream carrying userinfo",
      body: { name: PEP_NAME, proxy: Object.assign({}, config, {
        upstream: "http://someone:secret@companion:9700" }) } },
    { what: "a route naming no application",
      body: { name: PEP_NAME, proxy: Object.assign({}, config, {
        routes: [{ id: "noapp", path: "/pep-app/api", match: "prefix",
                   methods: ["GET"], authorization: { kind: "policy", policy: rootName },
                   mechanisms: ["oauth2"] }] }) } },
    { what: "a route naming an application this realm does not hold",
      body: { name: PEP_NAME, proxy: Object.assign({}, config, {
        routes: [{ id: "unknown", path: "/pep-app/api", match: "prefix",
                   methods: ["GET"], authorization: { kind: "policy", policy: rootName },
                   mechanisms: ["oauth2"],
                   application: "no-such-application-" + PEP_NAME }] }) } },
    { what: "an OAuth 2.0 route whose application has no audience",
      body: { name: PEP_NAME, proxy: Object.assign({}, config, {
        routes: [{ id: "noaud", path: "/pep-app/api", match: "prefix",
                   methods: ["GET"], authorization: { kind: "policy", policy: rootName },
                   mechanisms: ["oauth2"],
                   application: PROXY_NO_CALLBACK_APP }] }) } },
    { what: "a SAML 2.0 route whose application has no SP entity ID",
      body: { name: PEP_NAME, proxy: Object.assign({}, config, {
        routes: [{ id: "nosp", path: "/pep-app/saml", match: "prefix",
                   methods: ["GET"], authorization: { kind: "policy", policy: rootName },
                   mechanisms: ["saml2"],
                   application: PROXY_SCRATCH_APP }] }) } },
    { what: "a PEP that never registered",
      body: { name: "no-such-pep-" + PEP_NAME, proxy: config } }
  ];
  if (withSession) {
    const sessionRoute = function (application) {
      log.debug("Entering sessionRoute().");
      log.debug("Leaving sessionRoute().");
      return { name: PEP_NAME, proxy: Object.assign({}, config, {
        routes: [{ id: "session", path: "/pep-app/protected",
                   match: "prefix", methods: ["GET"],
                   authorization: { kind: "policy", policy: rootName },
                   mechanisms: ["session"], application: application }] }) };
    };
    refusals.push(
      { what: "a session route whose application is a public client",
        body: sessionRoute(PROXY_PUBLIC_APP) },
      { what: "a session route whose application does not register the " +
              "proxy's callback",
        body: sessionRoute(PROXY_NO_CALLBACK_APP) },
      { what: "a session route naming an unknown application",
        body: sessionRoute("no-such-application-" + PEP_NAME) },
      { what: "a session route with a plain-http publicBaseUrl",
        body: Object.assign(sessionRoute(PROXY_APP), {
          proxy: Object.assign(sessionRoute(PROXY_APP).proxy,
                               { publicBaseUrl: pep.proxyUrl }) }) });
  }
  for (const one of refusals) {
    const r = await postJson(api("/xacml/set-pep-proxy"), one.body);
    check("set-pep-proxy refuses " + one.what, function () {
      assert.ok(r.status >= 400 || (r.body && r.body.ok === false),
        "POST /admin-api/xacml/set-pep-proxy with " + one.what + " should " +
        "be refused by name; it answered " + r.status + " " +
        String(r.text).slice(0, 300));
      assert.ok(String(r.text).indexOf("STS-") < 0,
        "and no error code reaches the caller; it said " +
        String(r.text).slice(0, 300));
    });
  }
  const unchanged = await pepRow();
  check("a refused configuration changes nothing", function () {
    assert.strictEqual(((unchanged.row || {}).proxy || {}).upstream,
                       config.upstream,
      "the saved upstream should still stand; the row holds " +
      JSON.stringify((unchanged.row || {}).proxy).slice(0, 300));
  });

  const arrived = await until("the PEP to pull its proxy configuration " +
                              "and serve the public route",
                              async function () {
    const r = await proxyRequest("GET", pep.proxyUrl + "/pep-app/public/");
    return { ok: r.status === 200,
             note: "GET /pep-app/public/ through the proxy said " + told(r) };
  });
  log.info("The PEP converged on its proxy configuration in " + arrived.ms +
           "ms (its poll is " + POLL_MS + "ms).");

  const hitsBefore = await upstreamHits();
  const open = await proxyRequest("GET", pep.proxyUrl +
                                  "/pep-app/public/page?x=1");
  const hitsAfter = await upstreamHits();
  check("a public route needs no credential and reaches the application",
        function () {
    assert.strictEqual(open.status, 200, "GET /pep-app/public/page " +
                       "answered " + told(open));
    assert.ok(open.json && open.json.app === "pep-app" &&
              open.json.page === "public" &&
              open.json.path === "/pep-app/public/page" &&
              open.json.query.x === "1",
      "the echo should be the application's public page with the path " +
      "and query forwarded; it is " + open.text.slice(0, 300));
    assert.strictEqual(hitsOn(hitsAfter, "/pep-app/public/page"),
                       hitsOn(hitsBefore, "/pep-app/public/page") + 1,
      "and the application counted exactly that one request");
    assert.ok(!echoedUser(open),
      "a public route names nobody to the application; X-Remote-User " +
      "arrived as " + echoedUser(open));
  });
  if (pep.proxyHttpsUrl) {
    const secure = await proxyRequest("GET", pep.proxyHttpsUrl +
                                      "/pep-app/public/");
    check("the proxy's https listener serves the realm's pair", function () {
      assert.ok(secure.status === 200 && secure.json &&
                secure.json.page === "public",
        "GET " + pep.proxyHttpsUrl + "/pep-app/public/ trusting only the " +
        "service Root should reach the application; it answered " +
        told(secure));
    });
  } else {
    log.warn("[proxy] the https listener is not checked: section 1b " +
             "wrote no pair, or the launcher named no " +
             "XACML_PEP_PROXY_HTTPS_URL. The configuration carries no " +
             "session route, and the session sub-cases are skipped.");
  }
  log.debug("Leaving theProxyIsConfigured().");
}

// 10b. DENY BY DEFAULT: AN UNROUTED PATH, A TRAVERSAL, A METHOD THE ROUTE
// DOES NOT TAKE — EACH REFUSED, AND THE APPLICATION NEVER REACHED.
async function theProxyRefusesWhatIsNotRouted() {
  log.debug("Entering theProxyRefusesWhatIsNotRouted().");
  const token = await personsToken(ADMIN_PERSON, PROXY_API_AUDIENCE);
  const before = await upstreamHits();
  const unrouted = await proxyRequest("GET", pep.proxyUrl +
                                      "/pep-app/secret");
  const counter = await proxyRequest("GET", pep.proxyUrl +
                                     "/pep-app/_hits");
  const traversal = await proxyRequest("GET", pep.proxyUrl +
                                       "/pep-app/public/../protected");
  const encoded = await proxyRequest("GET", pep.proxyUrl +
                                     "/pep-app/public/%2e%2e/protected");
  const put = await proxyRequest("PUT", pep.proxyUrl + "/pep-app/api/items",
    { headers: { authorization: "Bearer " + token,
                 "content-type": "application/json" }, body: "{}" });
  const after = await upstreamHits();
  check("an unrouted path is 404 and never reaches the application",
        function () {
    assert.strictEqual(unrouted.status, 404,
      "GET /pep-app/secret matches no route; it answered " + told(unrouted));
    assert.strictEqual(counter.status, 404,
      "and the application's own counter is not routed either; " +
      "GET /pep-app/_hits through the proxy answered " + told(counter));
    assert.strictEqual(hitsOn(after, "/pep-app/secret"),
                       hitsOn(before, "/pep-app/secret"),
      "the application must never see an unrouted request");
  });
  check("a path that does not normalise is 400, plain or percent-encoded",
        function () {
    assert.strictEqual(traversal.status, 400,
      "GET /pep-app/public/../protected answered " + told(traversal));
    assert.strictEqual(encoded.status, 400,
      "GET /pep-app/public/%2e%2e/protected answered " + told(encoded));
    assert.strictEqual(hitsOn(after, "/pep-app/protected"),
                       hitsOn(before, "/pep-app/protected"),
      "and neither reached the protected page");
  });
  check("a method the route does not take is 405 with Allow", function () {
    assert.strictEqual(put.status, 405,
      "PUT /pep-app/api/items on a GET, POST route answered " + told(put));
    const allow = String(put.headers.allow || "").toUpperCase();
    assert.ok(/\bGET\b/.test(allow) && /\bPOST\b/.test(allow),
      "with an Allow header naming GET and POST; it sent " +
      JSON.stringify(put.headers.allow || null));
    assert.strictEqual(hitsOn(after, "/pep-app/api/items"),
                       hitsOn(before, "/pep-app/api/items"),
      "and the application saw nothing");
  });
  log.debug("Leaving theProxyRefusesWhatIsNotRouted().");
}

// 10c. OAUTH 2.0: A JWT CHECKED IN THE CONTAINER, AN OPAQUE HANDLE ASKED OF
// THE SERVICE, THE AUDIENCE HELD, THE CREDENTIAL STRIPPED, THE IDENTITY
// PASSED, AND THE DECISION THE POLICY'S.
async function theProxyTakesAnAccessToken() {
  log.debug("Entering theProxyTakesAnAccessToken().");
  const admin = await personsToken(ADMIN_PERSON, PROXY_API_AUDIENCE);
  const staff = await personsToken(STAFF_PERSON, PROXY_API_AUDIENCE);
  const outsider = await personsToken(OUTSIDER_PERSON, PROXY_API_AUDIENCE);
  const elsewhere = await personsToken(ADMIN_PERSON, PROXY_OTHER_AUDIENCE);
  const items = pep.proxyUrl + "/pep-app/api/items";

  const allowed = await proxyRequest("GET", items, {
    headers: { authorization: "Bearer " + admin,
               "x-remote-user": "mallory", "x-remote-auth": "forged",
               "x-forwarded-for": "203.0.113.66" } });
  check("a JWT for the route's audience is allowed for a permitted person",
        function () {
    assert.ok(admin.split(".").length === 3,
      "the realm should have issued a JWT here (RFC 9068)");
    assert.strictEqual(allowed.status, 200,
      "GET /pep-app/api/items with " + ADMIN_PERSON + "'s token answered " +
      told(allowed) + pepLog());
    assert.strictEqual((allowed.json || {}).page, "items",
      "and the application's items page answered it");
  });
  check("the token is not forwarded; the identity is, and the client's own " +
        "identity and forwarding headers are overwritten", function () {
    const h = (allowed.json || {}).headers || {};
    assert.ok(!("authorization" in h),
      "forwardCredentials is false, so Authorization must not reach the " +
      "application; it arrived as " + JSON.stringify(h.authorization));
    assert.strictEqual(echoedUser(allowed), ADMIN_PERSON,
      "X-Remote-User is the person the token names, never what the client " +
      "sent (mallory); it arrived as " + JSON.stringify(echoedUser(allowed)));
    assert.ok(echoedMechanism(allowed) && echoedMechanism(allowed) !==
              "forged" && /oauth/i.test(echoedMechanism(allowed)),
      "X-Remote-Auth names the OAuth 2.0 mechanism; it arrived as " +
      JSON.stringify(echoedMechanism(allowed)));
    assert.ok(String(h["x-forwarded-for"] || "").indexOf("203.0.113.66") < 0,
      "a client-supplied X-Forwarded-For is not passed on; it arrived as " +
      JSON.stringify(h["x-forwarded-for"] || null));
  });

  const before = await upstreamHits();
  const none = await proxyRequest("GET", items);
  const wrongAudience = await proxyRequest("GET", items, {
    headers: { authorization: "Bearer " + elsewhere } });
  const forged = await proxyRequest("GET", items, {
    headers: { authorization: "Bearer " + admin.slice(0, -4) + "AAAA" } });
  const denied = await proxyRequest("GET", items, {
    headers: { authorization: "Bearer " + outsider } });
  const after = await upstreamHits();
  check("no credential is 401 with a challenge for each mechanism",
        function () {
    assert.strictEqual(none.status, 401, "GET with nothing: " + told(none));
    const challenge = String(none.headers["www-authenticate"] || "");
    assert.ok(/Bearer/i.test(challenge) && /Basic/i.test(challenge),
      "WWW-Authenticate should offer Bearer and Basic, the route's two " +
      "mechanisms; it sent " + JSON.stringify(challenge));
  });
  check("a token for another audience is 401", function () {
    assert.strictEqual(wrongAudience.status, 401,
      "a token issued for " + PROXY_OTHER_AUDIENCE + " answered " +
      told(wrongAudience));
  });
  check("a token whose signature does not verify is 401", function () {
    assert.strictEqual(forged.status, 401,
      "a JWT with its signature altered answered " + told(forged));
  });
  check("the policy's Deny for somebody it grants nothing is 403",
        function () {
    assert.strictEqual(denied.status, 403,
      OUTSIDER_PERSON + " (employeeType contractor) answered " +
      told(denied));
    assert.strictEqual(hitsOn(after, "/pep-app/api/items"),
                       hitsOn(before, "/pep-app/api/items"),
      "and none of the four refusals reached the application");
  });

  const body = JSON.stringify({ name: "widget", made: names.runStamp(),
                                note: "written through the remote PEP" });
  const digest = nodeCrypto.createHash("sha256").update(body).digest("hex");
  const wrote = await proxyRequest("POST", items, {
    headers: { authorization: "Bearer " + admin,
               "content-type": "application/json" }, body: body });
  const beforeRefusedWrite = await upstreamHits();
  const refusedWrite = await proxyRequest("POST", items, {
    headers: { authorization: "Bearer " + staff,
               "content-type": "application/json" }, body: body });
  const tooLarge = await proxyRequest("POST", items, {
    headers: { authorization: "Bearer " + admin,
               "content-type": "application/octet-stream" },
    body: Buffer.alloc(PROXY_MAX_BODY * 2, 0x61) });
  const afterWrites = await upstreamHits();
  check("a write by a permitted person reaches the application whole",
        function () {
    assert.strictEqual(wrote.status, 201,
      "POST /pep-app/api/items by " + ADMIN_PERSON + " answered " +
      told(wrote));
    const got = (wrote.json || {}).body || {};
    assert.ok(got.length === Buffer.byteLength(body) && got.sha256 === digest,
      "the application should have received the body byte for byte (" +
      Buffer.byteLength(body) + " bytes, " + digest + "); it got " +
      JSON.stringify(got));
  });
  check("a write by somebody the policy limits to reads is 403",
        function () {
    assert.strictEqual(refusedWrite.status, 403,
      "POST by " + STAFF_PERSON + " (staff: GET, HEAD, DELETE) answered " +
      told(refusedWrite));
    assert.strictEqual(hitsOn(afterWrites, "/pep-app/api/items"),
                       hitsOn(beforeRefusedWrite, "/pep-app/api/items"),
      "and the refused write never reached the application");
  });
  check("a body over maxBodyBytes is 413", function () {
    assert.strictEqual(tooLarge.status, 413,
      "a " + (PROXY_MAX_BODY * 2) + "-byte body against a " + PROXY_MAX_BODY +
      "-byte bound answered " + told(tooLarge));
  });

  // AN OPAQUE ACCESS TOKEN (3cw), which the container cannot read and asks
  // the service about (`POST /xacml/pep/introspect`, D7).
  const formatBefore = await realmSetting("oauth2.accessTokenFormat");
  const switched = await postJson(api("/config/set"),
    { key: "oauth2.accessTokenFormat", value: "opaque" });
  if (switched.status !== 200 ||
      (switched.body && switched.body.ok === false)) {
    log.warn("[proxy] the opaque-token case is SKIPPED: this realm would " +
             "not issue opaque access tokens (oauth2.accessTokenFormat " +
             "answered " + switched.status + " " +
             String(switched.text).slice(0, 200) + ").");
  } else {
    try {
      const opaque = await personsToken(ADMIN_PERSON, PROXY_API_AUDIENCE);
      const viaService = await proxyRequest("GET", items, {
        headers: { authorization: "Bearer " + opaque } });
      const opaqueElsewhere = await personsToken(ADMIN_PERSON,
                                                 PROXY_OTHER_AUDIENCE);
      const refusedOpaque = await proxyRequest("GET", items, {
        headers: { authorization: "Bearer " + opaqueElsewhere } });
      check("an opaque access token is allowed through the service's " +
            "introspection", function () {
        assert.ok(opaque.indexOf(".") < 0,
          "the realm should have issued an opaque handle; it issued a " +
          "token with " + opaque.split(".").length + " parts");
        assert.strictEqual(viaService.status, 200,
          "GET with an opaque token answered " + told(viaService));
        assert.strictEqual(echoedUser(viaService), ADMIN_PERSON,
          "naming the person the service's introspection gave");
      });
      check("an opaque access token for another audience is 401",
            function () {
        assert.strictEqual(refusedOpaque.status, 401,
          "an opaque token for " + PROXY_OTHER_AUDIENCE + " answered " +
          told(refusedOpaque));
      });
    } finally {
      await setSetting("oauth2.accessTokenFormat",
                       String(formatBefore || "jwt"));
    }
  }
  log.debug("Leaving theProxyTakesAnAccessToken().");
}

// 10d. HTTP BASIC: NEVER CHECKED IN THE CONTAINER, ALWAYS AT THE SERVICE.
async function theProxyTakesBasic() {
  log.debug("Entering theProxyTakesBasic().");
  const items = pep.proxyUrl + "/pep-app/api/items";
  const right = await proxyRequest("GET", items, {
    headers: { authorization: basic(ADMIN_PERSON,
                                    "pep-proxy-" + ADMIN_PERSON) } });
  const before = await upstreamHits();
  const wrong = await proxyRequest("GET", items, {
    headers: { authorization: basic(ADMIN_PERSON, "invalid") } });
  const staffWrite = await proxyRequest("POST", items, {
    headers: { authorization: basic(STAFF_PERSON,
                                    "pep-proxy-" + STAFF_PERSON),
               "content-type": "application/json" }, body: "{}" });
  const after = await upstreamHits();
  check("Basic with a password the service accepts is allowed", function () {
    assert.strictEqual(right.status, 200,
      "GET with Basic for " + ADMIN_PERSON + " answered " + told(right));
    assert.strictEqual(echoedUser(right), ADMIN_PERSON,
      "naming the person to the application");
    assert.ok(/basic/i.test(echoedMechanism(right)),
      "and X-Remote-Auth names Basic; it arrived as " +
      JSON.stringify(echoedMechanism(right)));
    assert.ok(!("authorization" in ((right.json || {}).headers || {})),
      "and the password does not reach the application");
  });
  check("Basic with the reserved refused password is 401", function () {
    assert.strictEqual(wrong.status, 401,
      "the password `invalid` is refused in development (authn/CLAUDE.md); " +
      "it answered " + told(wrong));
    assert.ok(/Basic/i.test(String(wrong.headers["www-authenticate"] || "")),
      "with a Basic challenge");
  });
  check("Basic for somebody the policy limits to reads cannot write",
        function () {
    assert.strictEqual(staffWrite.status, 403,
      "POST with Basic for " + STAFF_PERSON + " answered " +
      told(staffWrite));
    assert.strictEqual(hitsOn(after, "/pep-app/api/items"),
                       hitsOn(before, "/pep-app/api/items"),
      "and neither refusal reached the application");
  });
  log.debug("Leaving theProxyTakesBasic().");
}

// 10e. SAML 2.0: AN ASSERTION THIS REALM SIGNED, FOR THE ROUTE'S AUDIENCE.
async function theProxyTakesAnAssertion() {
  log.debug("Entering theProxyTakesAnAssertion().");
  const page = pep.proxyUrl + "/pep-app/saml/document";
  const assertion = await realmAssertion(ADMIN_PERSON, PROXY_SAML_AUDIENCE);
  const encoded = Buffer.from(assertion, "utf8").toString("base64");
  const allowed = await proxyRequest("GET", page, {
    headers: { authorization: "SAML " + encoded } });
  // ONE VALUE CHANGED IN THE SIGNED BYTES — the person's name where the
  // assertion carries it, else its IssueInstant — so the signature no
  // longer verifies, locally or at the service.
  const altered = assertion.indexOf(ADMIN_PERSON) >= 0
    ? assertion.split(ADMIN_PERSON).join(STAFF_PERSON)
    : assertion.replace(/IssueInstant="(\d)/, function (all, digit) {
      return 'IssueInstant="' + (digit === "1" ? "2" : "1");
    });
  const tampered = Buffer.from(altered, "utf8").toString("base64");
  const otherAudience = Buffer.from(await realmAssertion(ADMIN_PERSON,
    PROXY_OTHER_AUDIENCE), "utf8").toString("base64");
  const before = await upstreamHits();
  const refused = await proxyRequest("GET", page, {
    headers: { authorization: "SAML " + tampered } });
  const elsewhere = await proxyRequest("GET", page, {
    headers: { authorization: "SAML " + otherAudience } });
  const after = await upstreamHits();
  check("an assertion this realm issued for the route's audience is " +
        "allowed", function () {
    assert.strictEqual(allowed.status, 200,
      "GET /pep-app/saml/document with Authorization: SAML answered " +
      told(allowed) + pepLog());
    assert.strictEqual(echoedUser(allowed), ADMIN_PERSON,
      "naming the person the assertion is about");
    assert.ok(/saml/i.test(echoedMechanism(allowed)),
      "and X-Remote-Auth names SAML; it arrived as " +
      JSON.stringify(echoedMechanism(allowed)));
    assert.ok(!("authorization" in ((allowed.json || {}).headers || {})),
      "and the assertion does not reach the application");
  });
  check("a tampered assertion is 401", function () {
    assert.ok(tampered !== encoded, "the tampering changed the bytes");
    assert.strictEqual(refused.status, 401,
      "an assertion whose signed NameID was altered answered " +
      told(refused));
  });
  check("an assertion for another audience is 401", function () {
    assert.strictEqual(elsewhere.status, 401,
      "an assertion for " + PROXY_OTHER_AUDIENCE + " answered " +
      told(elsewhere));
    assert.strictEqual(hitsOn(after, "/pep-app/saml/document"),
                       hitsOn(before, "/pep-app/saml/document"),
      "and neither refusal reached the application");
  });
  log.debug("Leaving theProxyTakesAnAssertion().");
}

// 10e-ii. HOW THE IDENTITY REACHES THE APPLICATION (D11), in each of the
// three modes, and what a client may not put there itself.
async function theProxyForwardsTheIdentity() {
  log.debug("Entering theProxyForwardsTheIdentity().");
  const admin = await personsToken(ADMIN_PERSON, PROXY_API_AUDIENCE);
  const adminSub = String((jwsPayloadOf(admin) || {}).sub || "");
  const items = pep.proxyUrl + "/pep-app/api/items";

  // HEADERS MODE: the five claims, and a client's own copy of one of them —
  // in an odd case, sent twice — removed before the proxy adds its own.
  const viaHeaders = await proxyRequest("GET", items, {
    headers: { authorization: "Bearer " + admin,
               "X-iYa-UsEr": ["forged-one", "forged-two"],
               "x-iya-email": "mallory@evil.test" } });
  const h = (viaHeaders.json || {}).headers || {};
  check("headers mode: the configured claims reach the application",
        function () {
    assert.strictEqual(viaHeaders.status, 200,
      "GET /pep-app/api/items answered " + told(viaHeaders));
    assert.ok(adminSub, "the realm's JWT carries a sub");
    assert.strictEqual(h["x-iya-user"], adminSub,
      "X-Iya-User is the person's sub; it arrived as " +
      JSON.stringify(h["x-iya-user"]));
    assert.strictEqual(h["x-iya-email"],
                       ADMIN_PERSON + "@xacml-remote-pep.test",
      "X-Iya-Email is the entry's mail; it arrived as " +
      JSON.stringify(h["x-iya-email"]));
    assert.ok(String(h["x-iya-groups"] || "").split(",")
      .indexOf("ssf-read") >= 0,
      "X-Iya-Groups lists the person's groups, joined by the separator; it " +
      "arrived as " + JSON.stringify(h["x-iya-groups"]));
  });
  check("headers mode: a client's own identity header is removed whatever " +
        "its case and however often it was sent", function () {
    assert.ok(String(h["x-iya-user"]).indexOf("forged") < 0 &&
              String(h["x-iya-email"]).indexOf("mallory") < 0,
      "the client sent X-iYa-UsEr twice and x-iya-email once; the " +
      "application saw " + JSON.stringify({ user: h["x-iya-user"],
                                            email: h["x-iya-email"] }));
  });

  // JWT MODE: a token the service issued for the application's audience.
  const byBasic = await proxyRequest("GET", pep.proxyUrl + "/pep-app/jwt/a",
    { headers: { authorization: basic(ADMIN_PERSON,
                                      "pep-proxy-" + ADMIN_PERSON) } });
  const byToken = await proxyRequest("GET", pep.proxyUrl + "/pep-app/jwt/b",
    { headers: { authorization: "Bearer " + admin } });
  const issued = function (r) {
    log.debug("Entering issued().");
    log.debug("Leaving issued().");
    return ((r.json || {}).jwt) || {};
  };
  check("jwt mode: the application is sent a Bearer token the service " +
        "issued for its audience, about the person", function () {
    assert.strictEqual(byBasic.status, 200,
      "GET /pep-app/jwt/a with Basic answered " + told(byBasic));
    const sent = String(((byBasic.json || {}).headers || {}).authorization ||
                        "");
    assert.ok(/^Bearer\s+\S+\.\S+\.\S+$/.test(sent),
      "Authorization reaching the application is a Bearer JWT, not the " +
      "client's Basic credential; it is " + sent.slice(0, 20));
    const jwt = issued(byBasic);
    assert.strictEqual(jwt.verified, true,
      "and it verifies against the realm's JWKS: " + jwt.why);
    assert.strictEqual(String((jwt.payload || {}).sub), adminSub,
      "its sub is the person's; it is " + JSON.stringify(jwt.payload));
    assert.ok([].concat((jwt.payload || {}).aud || [])
      .indexOf(PROXY_API_AUDIENCE) >= 0,
      "its aud is the application's audience " + PROXY_API_AUDIENCE);
  });
  check("jwt mode: the client's own Authorization is gone", function () {
    assert.strictEqual(byToken.status, 200,
      "GET /pep-app/jwt/b with a Bearer token answered " + told(byToken));
    const sent = String(((byToken.json || {}).headers || {}).authorization ||
                        "");
    assert.ok(sent && sent !== "Bearer " + admin,
      "the application must be sent the token the service issued for it, " +
      "never the client's own");
    assert.strictEqual(issued(byToken).verified, true,
      "and that token verifies: " + issued(byToken).why);
  });

  // SAML MODE: the proxy POSTs the service's assertion to the
  // application's ACS server-side and forwards the request with the
  // application's cookie, which the browser never sees.
  const hitsBefore = await upstreamHits();
  const viaSaml = await proxyRequest("GET", pep.proxyUrl +
    "/pep-app/saml-app/page", { headers: { authorization:
      basic(ADMIN_PERSON, "pep-proxy-" + ADMIN_PERSON) } });
  const hitsAfter = await upstreamHits();
  check("saml mode: the application's ACS was sent an assertion about the " +
        "person and the request arrives in that session", function () {
    assert.strictEqual(viaSaml.status, 200,
      "GET /pep-app/saml-app/page answered " + told(viaSaml) + pepLog());
    const saml = (viaSaml.json || {}).saml || {};
    const nameId = String(saml.nameId || "");
    assert.ok(nameId && (nameId === ADMIN_PERSON || nameId === adminSub ||
                         nameId.indexOf(ADMIN_PERSON) >= 0),
      "the echo's saml.nameId names the person; the echo holds " +
      JSON.stringify(viaSaml.json && viaSaml.json.saml));
    assert.ok(hitsOn(hitsAfter, "/pep-app/saml/acs") >
              hitsOn(hitsBefore, "/pep-app/saml/acs"),
      "and the ACS was posted to");
  });
  check("saml mode: the browser never receives the application's cookie",
        function () {
    const set = [].concat(viaSaml.headers["set-cookie"] || []).join(" ");
    assert.ok(set.indexOf("pep_app_saml") < 0,
      "the proxy keeps the application's cookie in a jar of its own; it " +
      "sent the client " + JSON.stringify(set));
  });
  log.debug("Leaving theProxyForwardsTheIdentity().");
}

// The payload of a compact JWS this job holds, unverified.
function jwsPayloadOf(token) {
  log.debug("Entering jwsPayloadOf().");
  try {
    const part = String(token || "").split(".")[1] || "";
    const out = JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
    log.debug("Leaving jwsPayloadOf().");
    return out;
  } catch (e) {
    log.debug("Caught in jwsPayloadOf(): " + ((e && e.message) || e));
    log.debug("Leaving jwsPayloadOf(). Not a JWS.");
    return null;
  }
}

// 10f. THE SESSION MECHANISM (D5 revised, D10): THE PROXY IS THE RELYING
// PARTY OF THE APPLICATION BEHIND IT. Signed in through the service as
// that confidential client, kept by the proxy's own cookie, and ended by a
// sign-out at the service — through the library's CAEP poll stream on a
// `signals: true` route, and through `POST /xacml/pep/session` on a
// `signals: false` one.

// One person signed in through the proxy at `page` with a fresh browser.
async function signInThroughTheProxy(page) {
  log.debug("Entering signInThroughTheProxy(). " + page);
  const jars = browserJars();
  const walked = await browse(jars, page, ADMIN_PERSON);
  log.debug("Leaving signInThroughTheProxy(). " + walked.r.status);
  return { jars: jars, walked: walked };
}

async function signOutAtTheService(jars) {
  log.debug("Entering signOutAtTheService().");
  const serviceJarUrl = realmUrl("/logout");
  const out = await authnSignin.signOut(realmUrl(""), { scope: "global" },
    { cookie: jarHeader(jars, serviceJarUrl) });
  jarTake(jars, serviceJarUrl, out.setCookies);
  assert.strictEqual(out.status, 200,
    "the global sign-out at the service answered " + out.status + " " +
    String(out.text).slice(0, 200));
  log.debug("Leaving signOutAtTheService().");
}

function signedInOn(walked, page) {
  log.debug("Entering signedInOn().");
  assert.strictEqual(walked.r.status, 200,
    "the sign-in should end on " + page + "; it ended " + walked.r.status +
    " at " + walked.url + " after " + JSON.stringify(walked.passed) + " " +
    withoutSecrets(walked.r.text).slice(0, 300) + pepLog());
  assert.ok(walked.passed.some(function (one) {
    return one.indexOf("/.iya-pep/callback") >= 0;
  }), "through the proxy's callback; it passed " +
      JSON.stringify(walked.passed));
  assert.strictEqual(echoedUser(walked.r), ADMIN_PERSON,
    "naming the person who signed in to the application");
  assert.ok(/session/i.test(echoedMechanism(walked.r)),
    "by the session mechanism; X-Remote-Auth arrived as " +
    JSON.stringify(echoedMechanism(walked.r)));
  log.debug("Leaving signedInOn().");
}

async function theProxyHoldsASession() {
  log.debug("Entering theProxyHoldsASession().");
  const origin = pep.proxyHttpsUrl;
  const protectedPage = origin + "/pep-app/protected/report";
  const before = await upstreamHits();
  const machine = await proxyRequest("GET", protectedPage, {
    headers: { accept: "application/json" } });
  const jars = browserJars();
  const first = await browserGet(jars, protectedPage);
  const afterFirst = await upstreamHits();
  check("a browser with no session is sent to sign in at the service as " +
        "the application's own client", function () {
    assert.ok(machine.status === 401 || machine.status === 302,
      "a request with no session and no browser Accept is refused; it " +
      "answered " + told(machine));
    assert.strictEqual(first.status, 302,
      "GET " + protectedPage + " as a browser should be a 302 to sign in " +
      "(D8); it answered " + first.status + " " +
      String(first.text).slice(0, 200));
    const to = new URL(first.location, protectedPage);
    assert.ok(/\/oauth2\/authorize$/.test(to.pathname) &&
              to.pathname.indexOf("/realm/" + REALM + "/") >= 0,
      "to this realm's authorization endpoint; it is " + to.pathname);
    assert.strictEqual(to.searchParams.get("client_id"), PROXY_APP,
      "as the confidential client the route's application is (D10); it " +
      "asked as " + to.searchParams.get("client_id"));
    assert.strictEqual(to.searchParams.get("redirect_uri"),
                       origin + "/.iya-pep/callback",
      "returning to the proxy's reserved callback under publicBaseUrl");
    assert.strictEqual(to.searchParams.get("code_challenge_method"), "S256",
      "with PKCE S256, which the relying party library requires");
    assert.ok(carriesNoSecret(first.location),
      "and no client secret in the address");
    assert.strictEqual(hitsOn(afterFirst, "/pep-app/protected/report"),
                       hitsOn(before, "/pep-app/protected/report"),
      "and the application saw neither request");
  });

  const walked = await browse(jars, protectedPage, ADMIN_PERSON);
  const proxyCookies = Object.assign({}, jars[originOf(origin)] || {});
  check("signed in at the service, the browser reaches the protected page " +
        "with the identity headers and a proxy session of its own",
        function () {
    signedInOn(walked, protectedPage);
    assert.strictEqual((walked.r.json || {}).page, "protected",
      "the application's protected page answered");
    assert.ok(Object.keys(proxyCookies).length > 0,
      "and the proxy set a cookie on its own origin");
    const forwarded = String(((walked.r.json || {}).headers || {}).cookie ||
                             "");
    Object.keys(proxyCookies).forEach(function (name) {
      assert.ok(forwarded.indexOf(name + "=" + proxyCookies[name]) < 0,
        "the proxy's own cookie " + name + " must not reach the " +
        "application; it forwarded " + JSON.stringify(forwarded));
    });
  });

  const again = await browserGet(jars, protectedPage);
  check("the proxy session carries the next access without a sign-in",
        function () {
    assert.ok(again.status === 200 && echoedUser(again) === ADMIN_PERSON,
      "a second GET with the proxy's cookie answered " + again.status);
  });

  // THE SIGN-OUT, BY CAEP (D5 revised): the relying party's poll stream is
  // sent `session-revoked` for the session it signed in under, and the
  // library removes that session. Polled for a bounded time, because the
  // library polls on an interval of its own.
  await signOutAtTheService(jars);
  const revoked = await until("the PEP's relying party to end the proxy " +
                              "session on the CAEP session-revoked",
                              async function () {
    const r = await browserGet(jars, protectedPage);
    return { ok: r.status === 302 || r.status === 401,
             note: "GET " + protectedPage + " still answered " + r.status };
  }, PROXY_SIGNAL_MS);
  log.info("The CAEP session-revoked ended the proxy session " +
           revoked.ms + "ms after the sign-out at the service.");
  const beforeEnded = await upstreamHits();
  const ended = await browserGet(jars, protectedPage);
  const afterEnded = await upstreamHits();
  check("a sign-out at the service ends the proxy session through the CAEP " +
        "poll stream, and nothing reaches the application after it",
        function () {
    assert.ok(ended.status === 302 || ended.status === 401,
      "the access after the session-revoked must stay refused; it " +
      "answered " + ended.status + pepLog());
    assert.strictEqual(hitsOn(afterEnded, "/pep-app/protected/report"),
                       hitsOn(beforeEnded, "/pep-app/protected/report"),
      "and the application saw nothing");
  });

  // THE STREAMS' HEALTH ON THE PDP'S ROW (#1760). The PEP reports
  // `GET /`'s `proxy.signals` on every heartbeat, and
  // `/admin-api/xacml/peps` carries it as counts and ages only. Waited for
  // on the beat rather than a clock, like section 7's counters: the
  // session-revoked above was a SET the receiver accepted, so the row
  // catches up once a heartbeat after it arrives.
  const SIGNAL_MEMBERS = "at,healthy,librarySessions," +
    "mostConsecutiveFailures,oldestSuccessAgeMs,pollIntervalMs,receivers," +
    "sessionsEnded,setsAccepted,setsRefused,stale,staleAfterMs";
  await until("the PDP's row to carry the PEP's signal-stream health",
              async function () {
    const there = (await pepRow()).row;
    const held = there && there.signals;
    return { ok: !!held && held.receivers >= 1 && held.setsAccepted >= 1,
             note: "the row's signals say " + JSON.stringify(held) };
  }, CONVERGE_MS);
  const signalRow = (await pepRow()).row;
  const signalHere = ((await pepOverview()).proxy || {}).signals;
  check("the PDP's row carries the proxy's CAEP/RISC stream health, " +
        "counts and ages only", function () {
    // ONE ROW PER STREAM (#1760) rides beside the counts and is checked
    // below; the counts are held to their members as before.
    const held = Object.assign({}, signalRow.signals);
    delete held.streams;
    assert.strictEqual(Object.keys(held).sort().join(","), SIGNAL_MEMBERS,
      "the row's signals should hold exactly these members; it holds " +
      JSON.stringify(held));
    assert.strictEqual(Object.keys(held.librarySessions).sort().join(","),
      "evicted,expired,held,max,ttlSec",
      "and the library stores' five counts");
    assert.ok(!/https?:|127\.0\.0\.1|sts-pep|pep-app|Error/i
                .test(JSON.stringify(held)),
      "no URL, client id or error text may reach the row: " +
      JSON.stringify(held));
    assert.ok(held.healthy >= 1 && held.stale === 0,
      "the stream that just delivered the session-revoked is healthy: " +
      JSON.stringify(held) + pepLog());
    assert.ok(!isNaN(Date.parse(held.at)) &&
              Math.abs(Date.parse(held.at) - Date.parse(signalRow.lastSeen))
                < CONVERGE_MS,
      "`at` is the heartbeat it came on (" + held.at + ", last seen " +
      signalRow.lastSeen + ")");
    assert.ok(signalHere && signalHere.receivers === held.receivers &&
              signalHere.staleAfterMs === held.staleAfterMs &&
              signalHere.pollIntervalMs === held.pollIntervalMs,
      "and it agrees with the PEP's own GET /: " + JSON.stringify(signalHere));
  });
  check("the row has one stream per receiver, each naming the application " +
        "it serves, and GET / names none", function () {
    const streams = signalRow.signals.streams;
    assert.ok(Array.isArray(streams) &&
              streams.length === signalRow.signals.receivers,
      "a row per receiver: " + JSON.stringify(streams));
    streams.forEach(function (one) {
      assert.ok(one.streamId && one.running === true &&
                !isNaN(Date.parse(one.lastSuccessAt)) &&
                one.applications.length >= 1 && one.routes.length >= 1,
        "each stream names its stream id, its last success and the " +
        "applications and routes it serves: " + JSON.stringify(one));
      assert.ok(!/https?:|Error/i.test(JSON.stringify(one)),
        "and no URL or error text: " + JSON.stringify(one));
    });
    assert.ok(signalHere && signalHere.streams === undefined &&
              !/clientId/.test(JSON.stringify(signalHere)),
      "GET / answers anybody, so it carries no stream row: " +
      JSON.stringify(signalHere));
  });

  // THE FALLBACK (`signals: false`): no poll stream; the PEP asks
  // `POST /xacml/pep/session` before each access
  // (PEP_PROXY_SESSION_RECHECK_MS=0 in this stack), so the very next access
  // after a sign-out is refused.
  const fallbackPage = origin + "/pep-app/protected-fallback/report";
  const viaFallback = await signInThroughTheProxy(fallbackPage);
  check("a signals:false session route signs in the same way", function () {
    signedInOn(viaFallback.walked, fallbackPage);
  });
  await signOutAtTheService(viaFallback.jars);
  const beforeFallback = await upstreamHits();
  const fallbackEnded = await browserGet(viaFallback.jars, fallbackPage);
  const afterFallback = await upstreamHits();
  check("on a signals:false route the next access after a sign-out is " +
        "refused, asked of the service", function () {
    assert.ok(fallbackEnded.status === 302 || fallbackEnded.status === 401,
      "with PEP_PROXY_SESSION_RECHECK_MS=0 the PEP asks " +
      "POST /xacml/pep/session before this access; it answered " +
      fallbackEnded.status + pepLog());
    assert.strictEqual(
      hitsOn(afterFallback, "/pep-app/protected-fallback/report"),
      hitsOn(beforeFallback, "/pep-app/protected-fallback/report"),
      "and the application saw nothing");
  });

  // A ROTATED SECRET (D10): `regenerate-secret` replaces the client secret
  // at once, which moves the pull's sync token; after the next pull a new
  // sign-in through the proxy works with the new one.
  const rotated = await postJson(api("/applications/regenerate-secret"),
                                 { application: PROXY_APP });
  assert.ok(rotated.status === 200 && rotated.body &&
            rotated.body.ok !== false && rotated.body.clientSecret,
    "POST /admin-api/applications/regenerate-secret for " + PROXY_APP +
    " answered " + rotated.status + " " +
    withoutSecrets(rotated.text).slice(0, 200));
  PROXY_SECRETS.push(String(rotated.body.clientSecret));
  const listedAfter = await get(api("/xacml/peps"));
  check("the regenerated secret is not on the PEP's row either",
        function () {
    assert.ok(carriesNoSecret(listedAfter.text),
      "GET /admin-api/xacml/peps must carry no client secret");
  });
  const afterRotation = await until("a new sign-in through the proxy to " +
                                    "work with the regenerated secret",
                                    async function () {
    const one = await signInThroughTheProxy(protectedPage);
    return { ok: one.walked.r.status === 200 &&
                 echoedUser(one.walked.r) === ADMIN_PERSON,
             note: "the sign-in ended " + one.walked.r.status + " after " +
                   JSON.stringify(one.walked.passed) };
  }, CONVERGE_MS);
  log.info("A sign-in worked " + afterRotation.ms + "ms after the secret " +
           "was regenerated (the PEP's poll is " + POLL_MS + "ms).");
  check("after a secret rotation and a pull, a new sign-in works",
        function () {
    assert.ok(afterRotation.ok, "the sign-in worked");
  });
  log.debug("Leaving theProxyHoldsASession().");
}

// 10i. AN APPLICATION A ROUTE NAMES IS DELETED: the route is refused (403)
// after the next pull — never admitted on a stale copy — and the PEP's row
// says the route is unusable (D10).
async function theProxyLosesAnApplication() {
  log.debug("Entering theProxyLosesAnApplication().");
  const page = pep.proxyUrl + "/pep-app/scratch/page";
  const credential = { authorization: basic(ADMIN_PERSON,
                                            "pep-proxy-" + ADMIN_PERSON) };
  const before = await proxyRequest("GET", page, { headers: credential });
  check("a route whose application exists is served", function () {
    assert.strictEqual(before.status, 200,
      "GET /pep-app/scratch/page with Basic answered " + told(before));
  });
  const forgot = await postJson(api("/applications/forget"),
                                { application: PROXY_SCRATCH_APP });
  assert.ok(forgot.status === 200 && forgot.body && forgot.body.ok !== false,
    "POST /admin-api/applications/forget for " + PROXY_SCRATCH_APP +
    " answered " + forgot.status + " " + String(forgot.text).slice(0, 200));
  const refused = await until("the PEP to refuse the route whose " +
                              "application was deleted", async function () {
    const r = await proxyRequest("GET", page, { headers: credential });
    return { ok: r.status === 403,
             note: "GET /pep-app/scratch/page answered " + told(r) };
  });
  log.info("The PEP refused the scratch route " + refused.ms + "ms after " +
           "its application was deleted.");
  const hitsBefore = await upstreamHits();
  const still = await proxyRequest("GET", page, { headers: credential });
  const hitsAfter = await upstreamHits();
  const row = await pepRow();
  check("a route whose application is gone is refused and reaches nothing",
        function () {
    assert.strictEqual(still.status, 403,
      "the route stays refused; it answered " + told(still));
    assert.strictEqual(hitsOn(hitsAfter, "/pep-app/scratch/page"),
                       hitsOn(hitsBefore, "/pep-app/scratch/page"),
      "and the application saw nothing");
  });
  check("the PEP's row says the route is unusable", function () {
    const route = ((((row.row || {}).proxy || {}).routes) || [])
      .filter(function (one) {
        return one.id === "scratch";
      })[0] || {};
    const resolved = route.resolved || {};
    assert.ok(resolved.usable === false || route.usable === false,
      "GET /admin-api/xacml/peps should mark the scratch route unusable " +
      "(D10); it holds " + JSON.stringify(route).slice(0, 300));
  });
  log.debug("Leaving theProxyLosesAnApplication().");
}

// 10g. WHAT THE PROXY DOES WITH THE WIRE: A SLOW UPSTREAM AND A RESPONSE'S
// HOP-BY-HOP HEADERS.
async function theProxyGuardsTheWire() {
  log.debug("Entering theProxyGuardsTheWire().");
  const slow = await proxyRequest("GET", pep.proxyUrl +
    "/pep-app/slow?ms=" + (PROXY_TIMEOUT_MS * 3), { timeoutMs: 30000 });
  check("an upstream slower than upstreamTimeoutMs is 504", function () {
    assert.strictEqual(slow.status, 504,
      "GET /pep-app/slow?ms=" + (PROXY_TIMEOUT_MS * 3) + " against a " +
      PROXY_TIMEOUT_MS + "ms timeout answered " + told(slow));
    assert.ok(slow.ms < PROXY_TIMEOUT_MS * 3,
      "and answered before the upstream would have (" + slow.ms + "ms)");
  });
  const hop = await proxyRequest("GET", pep.proxyUrl + "/pep-app/public/hop");
  check("the application's hop-by-hop headers stop at the proxy",
        function () {
    assert.strictEqual(hop.status, 200, "GET /pep-app/public/hop answered " +
                       told(hop));
    assert.ok(!("x-upstream-secret" in hop.headers),
      "X-Upstream-Secret is named by the application's Connection header, " +
      "so it is hop-by-hop (RFC 9110 section 7.6.1) and must not be " +
      "forwarded; the proxy sent " + JSON.stringify(hop.headers));
    assert.ok(String(hop.headers.connection || "").toLowerCase()
      .indexOf("x-upstream-secret") < 0,
      "nor the application's Connection header itself");
    assert.ok(!("keep-alive" in hop.headers) ||
              !/timeout=5/.test(String(hop.headers["keep-alive"])),
      "nor its Keep-Alive");
    assert.strictEqual(hop.headers["x-upstream-visible"], "end-to-end",
      "while an end-to-end header passes untouched");
  });
  log.debug("Leaving theProxyGuardsTheWire().");
}

// 10j. A CONFIGURED ROLE, AND A PUBLIC ROUTE.
//
// The routes above are decided by the realm's root, which reads
// employeeType. This one is a simple policy: GET is `read`, and only a
// member of ROLE_READERS may take it. ROLE_OTHER is a member of a
// different role, so the same request is a Deny. The public route needs
// no credential, still admits that refused person, and refuses a method
// it does not take before anything reaches the application.
async function theProxyDecidesByRole() {
  log.debug("Entering theProxyDecidesByRole().");
  const people = [[ROLE_READER, "Reader"], [ROLE_OTHER, "Other"]];
  for (const one of people) {
    const r = await postJson(api("/users/create"), {
      username: one[0], invent: false,
      attributes: { cn: "Remote PEP " + one[1], givenName: "Remote",
                    sn: one[1], displayName: "Remote PEP " + one[1],
                    mail: one[0] + "@xacml-remote-pep.test" }
    });
    assert.ok(r.status === 200 && r.body && r.body.ok,
      "POST /admin-api/users/create should put " + one[0] + " in " +
      REALM + "; it answered " + r.status + " " +
      String(r.text).slice(0, 300));
  }
  const roles = [[ROLE_READERS, ROLE_READER], [ROLE_OTHERS, ROLE_OTHER]];
  for (const one of roles) {
    const made = await postJson(api("/roles/create-role"),
                                { role: one[0],
                                  description: "Reverse-proxy route test" });
    assert.ok(made.status === 200 && made.body && made.body.ok !== false,
      "POST /admin-api/roles/create-role for " + one[0] + " answered " +
      made.status + " " + String(made.text).slice(0, 300));
    const member = await postJson(api("/roles/add-member"),
                                  { role: one[0], kind: "user",
                                    member: one[1] });
    assert.ok(member.status === 200 && member.body &&
              member.body.ok !== false,
      "POST /admin-api/roles/add-member should give " + one[1] + " " +
      one[0] + "; it answered " + member.status + " " +
      String(member.text).slice(0, 300));
  }
  await act("set-pep-route", {
    name: PEP_NAME, id: "role-protected", path: "/pep-app/role",
    match: "prefix", methods: ["GET", "POST"], methodsGiven: "true",
    mechanisms: ["oauth2", "basic"], application: PROXY_APP,
    authzKind: "simple", authzActionModel: "read-write",
    authzActions: ["read"], "authzRole.read": [ROLE_READERS],
    forwardCredentials: "false", signals: "false", mode: "headers",
    headerName: ["X-Remote-User", "X-Remote-Auth"],
    headerClaim: ["username", "mechanism"]
  }, "added a route only " + ROLE_READERS + " may read");

  const page = pep.proxyUrl + "/pep-app/role/page";
  const reader = await personsToken(ROLE_READER, PROXY_API_AUDIENCE);
  const other = await personsToken(ROLE_OTHER, PROXY_API_AUDIENCE);
  const allowed = await until("the PEP to permit a member of " +
                              ROLE_READERS, async function () {
    const r = await proxyRequest("GET", page, {
      headers: { authorization: "Bearer " + reader } });
    return { ok: r.status === 200,
             note: "GET /pep-app/role/page as " + ROLE_READER +
                   " answered " + told(r) };
  });
  log.info("A member of " + ROLE_READERS + " was permitted " +
           allowed.ms + "ms after the route was saved.");
  check("a member of the route's role may read the protected resource",
        function () {
    assert.strictEqual(allowed.ok, true,
      ROLE_READER + " holds " + ROLE_READERS + " and GET should be " +
      "permitted");
  });
  const seen = await proxyRequest("GET", page, {
    headers: { authorization: "Bearer " + reader,
               "x-remote-user": "mallory" } });
  check("the permitted member is the person named to the application",
        function () {
    assert.strictEqual(seen.status, 200,
      "GET /pep-app/role/page answered " + told(seen));
    assert.strictEqual((seen.json || {}).page, "other",
      "the application echoes an unmatched /pep-app path as page " +
      "\"other\"; it said " + JSON.stringify((seen.json || {}).page));
    assert.strictEqual(echoedUser(seen), ROLE_READER,
      "X-Remote-User is the member, never the client's mallory; it " +
      "arrived as " + JSON.stringify(echoedUser(seen)));
    assert.ok(!("authorization" in ((seen.json || {}).headers || {})),
      "forwardCredentials is false, so the token must not reach the " +
      "application");
  });

  const before = await upstreamHits();
  const refused = await proxyRequest("GET", page, {
    headers: { authorization: "Bearer " + other } });
  const wrote = await proxyRequest("POST", page, {
    headers: { authorization: "Bearer " + reader,
               "content-type": "application/json" }, body: "{}" });
  const none = await proxyRequest("GET", page);
  const after = await upstreamHits();
  check("a member of another role is refused the protected resource",
        function () {
    assert.strictEqual(refused.status, 403,
      ROLE_OTHER + " holds " + ROLE_OTHERS + ", which this route does " +
      "not grant, so GET should be 403; it answered " + told(refused));
  });
  check("a member of the read role may not take an action it does not " +
        "grant", function () {
    assert.strictEqual(wrote.status, 403,
      "POST is write, and " + ROLE_READERS + " is granted read only; " +
      "it answered " + told(wrote));
  });
  check("the protected resource still wants a credential", function () {
    assert.strictEqual(none.status, 401,
      "GET /pep-app/role/page with nothing answered " + told(none));
    assert.ok(/Bearer/i.test(String(none.headers["www-authenticate"] ||
                                    "")),
      "with a Bearer challenge");
  });
  check("none of those refusals reached the application", function () {
    assert.strictEqual(hitsOn(after, "/pep-app/role/page"),
                       hitsOn(before, "/pep-app/role/page"),
      "the refused GET, the refused POST and the missing credential " +
      "must not be counted");
  });

  const openBefore = await upstreamHits();
  const open = await proxyRequest("GET", pep.proxyUrl +
                                  "/pep-app/public/page?x=2");
  const openAsOther = await proxyRequest("GET", pep.proxyUrl +
                                         "/pep-app/public/open", {
    headers: { authorization: "Bearer " + other } });
  const openAfter = await upstreamHits();
  const postedBefore = await upstreamHits();
  const posted = await proxyRequest("POST", pep.proxyUrl +
                                    "/pep-app/public/page", {
    headers: { "content-type": "application/json" }, body: "{}" });
  const postedAfter = await upstreamHits();
  check("a public endpoint needs no credential and reaches the " +
        "application", function () {
    assert.strictEqual(open.status, 200,
      "GET /pep-app/public/page answered " + told(open));
    assert.ok(open.json && open.json.page === "public" &&
              open.json.query && open.json.query.x === "2",
      "the echo should be the public page with the query forwarded; " +
      "it is " + String(open.text).slice(0, 300));
    assert.ok(!echoedUser(open),
      "a public route names nobody; X-Remote-User arrived as " +
      echoedUser(open));
    assert.strictEqual(hitsOn(openAfter, "/pep-app/public/page"),
                       hitsOn(openBefore, "/pep-app/public/page") + 1,
      "and the application counted that request");
  });
  check("a public endpoint still admits a person another route refused",
        function () {
    assert.strictEqual(openAsOther.status, 200,
      ROLE_OTHER + " was refused /pep-app/role/page and should still " +
      "reach the public route; it answered " + told(openAsOther));
    assert.ok(openAsOther.json && openAsOther.json.page === "public",
      "the echo should be the public page; it is " +
      String(openAsOther.text).slice(0, 300));
    assert.ok(!echoedUser(openAsOther),
      "a public route forwards nobody, including a signed-in caller; " +
      "X-Remote-User arrived as " + echoedUser(openAsOther));
    assert.strictEqual(hitsOn(openAfter, "/pep-app/public/open"),
                       hitsOn(openBefore, "/pep-app/public/open") + 1,
      "and the application counted that request too");
  });
  check("a method a public endpoint does not take is refused",
        function () {
    assert.strictEqual(posted.status, 405,
      "POST /pep-app/public/page on a GET, HEAD route answered " +
      told(posted));
    const allow = String(posted.headers.allow || "").toUpperCase();
    assert.ok(/\bGET\b/.test(allow) && /\bHEAD\b/.test(allow),
      "with Allow naming GET and HEAD; it sent " +
      JSON.stringify(posted.headers.allow || null));
    assert.strictEqual(hitsOn(postedAfter, "/pep-app/public/page"),
                       hitsOn(postedBefore, "/pep-app/public/page"),
      "and the application saw nothing");
  });
  log.debug("Leaving theProxyDecidesByRole().");
}

// 10h. CLEARED, THE PROXY ANSWERS NOTHING AGAIN.
async function theProxyIsCleared() {
  log.debug("Entering theProxyIsCleared().");
  await act("clear-pep-proxy", { name: PEP_NAME },
            "cleared the proxy configuration of " + PEP_NAME);
  const row = await pepRow();
  check("a cleared PEP's row holds no proxy", function () {
    assert.ok(row.row && !row.row.proxy,
      "the row still holds " + JSON.stringify(row.row && row.row.proxy));
  });
  const gone = await until("the PEP to drop its proxy configuration",
                           async function () {
    const r = await proxyRequest("GET", pep.proxyUrl + "/pep-app/public/");
    return { ok: r.status === 404,
             note: "GET /pep-app/public/ through the proxy said " + told(r) };
  });
  log.info("The PEP stopped proxying " + gone.ms + "ms after the clear.");
  log.debug("Leaving theProxyIsCleared().");
}

// ---------------------------------------------------------------------------
// THE REALM, AND WHY IT IS LEFT STANDING (2026-09-06).
//
// It used to be removed here, and section 9 called that teardown early because
// the removal WAS its outage. Both of those are gone: **a realm a test run
// created stays, because it is what a person reads when the run went red**,
// and in this job it holds the two policy documents the whole file is about,
// the PEP's row in ou=peps with everything that container ever reported, and
// the settings the sections changed. Section 9 makes its outage with
// `xacml.remotePeps` instead, which is scoped to the seam under test and is
// reversible where a removal was not.
// ---------------------------------------------------------------------------

async function createTheRealm() {
  log.debug("Entering createTheRealm().");
  // **IT USED TO REMOVE THE REALM FIRST AND IT MUST NOT ANY MORE**, which is
  // the one place the "leave every realm standing" rule costs this job
  // something rather than nothing. The id is FIXED when the launcher owns the
  // container — that container's PEP_PDP_URL was decided when the stack came
  // up — so a second run against a service that already holds this realm is
  // now a REFUSAL rather than a silent re-create, and it has to be, because
  // the alternatives are both worse: reusing the realm would run every
  // assertion below against a previous run's policy documents, and removing it
  // would throw away exactly the record somebody kept the stack to read.
  //
  // A fresh stack — which is what both launchers give it — never meets this.
  const r = await postJson(base + "/admin-api/realms/create", {
    id: REALM,
    domain: REALM + ".example.net",
    name: "Remote PEP end-to-end realm",
    description: "Created by tests/vendored/sts_xacml_remote_pep.js; LEFT " +
                 "IN PLACE on purpose, so a failed run can be read afterwards."
  });
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "creating the throwaway realm " + REALM + " answered " + r.status + " " +
    String(r.text).slice(0, 300) + ". Every assertion in this file is made " +
    "inside it, so this is a failure and not something to work around. IF IT " +
    "SAYS THE REALM IS ALREADY DEFINED, that is a previous run of this job " +
    "against this same service: this suite leaves the realms it creates " +
    "standing so they can be read afterwards, and the id is fixed when a " +
    "launcher owns the PEP container. Restart the stack, or remove " + REALM +
    " by hand once you have finished reading it.");
  log.info("Created the throwaway realm " + REALM + ".");
  await theRealmsCertificateAuthority();
  log.debug("Leaving createTheRealm().");
}

// THE REALM'S CERTIFICATE AUTHORITY IS BUILT BEHIND THE CREATE (2026-11-16).
// `realms/create` answers once the realm exists, and its branch under the
// service Root — the Intermediate and the Issuing CAs, the PEP-assertion
// one among them — is built just after: on the first local memory run the
// create answered at 03:21:57, issue-pep-credential was refused at 03:21:58
// with "no certificate authority yet" (STS-PKI-0008), and the branch was
// logged built at 03:22:00. Since phase 4 the PEP's key is registered
// straight after the create, so this waits for the chain to be readable on
// the realm's `GET /admin-api/pki` rather than meeting that race.
async function theRealmsCertificateAuthority() {
  log.debug("Entering theRealmsCertificateAuthority().");
  const deadline = Date.now() + 60000;
  let last = null;
  while (Date.now() < deadline) {
    last = await get(api("/pki"));
    const tiers = (last.body && last.body.chain && last.body.chain.tiers) ||
                  [];
    if (last.status === 200 && tiers.some(function (t) {
      return t && t.tier === "intermediate";
    })) {
      log.debug("Leaving theRealmsCertificateAuthority(). " + tiers.length +
                " tier(s).");
      return;
    }
    await new Promise(function (resolve) {
      setTimeout(resolve, 500);
    });
  }
  log.debug("Leaving theRealmsCertificateAuthority(). Timed out.");
  assert.fail("the realm " + REALM + " had no certificate authority 60 s " +
              "after it was created (GET /admin-api/pki answered " +
              (last && last.status) + "), so nothing can be issued in it");
}

// THE TWO PEOPLE THE RBAC POLICY DECIDES ABOUT, created in this run's realm
// (2026-09-12). They were the seeded `carol` (admin) and `alice` (staff); the
// requests that assert an `employeeType` still assert the same one, and the PIP
// section now resolves ADMIN_PERSON's from an entry this job wrote.
async function createThePeople() {
  log.debug("Entering createThePeople().");
  for (const one of [[ADMIN_PERSON, "admin", "Admin"],
                     [STAFF_PERSON, "staff", "Staff"]]) {
    const r = await postJson(api("/users/create"), {
      username: one[0], invent: false,
      attributes: { cn: "Remote PEP " + one[2] + " Person", givenName: "Remote",
                    sn: one[2] + " Person", displayName: "Remote PEP " + one[2],
                    mail: one[0] + "@xacml-remote-pep.test",
                    employeeType: one[1] }
    });
    assert.ok(r.status === 200 && r.body && r.body.ok,
      "POST /admin-api/users/create should put " + one[0] + " (employeeType=" +
      one[1] + ") in " + REALM + "; it answered " + r.status + " " +
      String(r.text).slice(0, 300));
  }
  log.debug("Leaving createThePeople().");
}

function theRealmIsLeftBehind() {
  log.debug("Entering theRealmIsLeftBehind().");
  log.info("The realm " + REALM + " is LEFT IN PLACE on purpose. It holds " +
           "the policy documents this run deployed, the PEP's row in " +
           "ou=peps with everything " + PEP_NAME + " reported, and — if " +
           "section 9 ran — `xacml.remotePeps` still turned OFF, which is " +
           "the outage that section asserts and is left as it was found so " +
           "that it can be read. It is at " + base + "/realm/" + REALM +
           "/admin/xacml. Remove it by hand, or restart the stack, when you " +
           "are done with it — and note that this job cannot run twice " +
           "against the same service while it stands, because a " +
           "launcher-owned PEP fixes the realm id.");
  log.debug("Leaving theRealmIsLeftBehind().");
}

function cleanUpTheCertificates() {
  log.debug("Entering cleanUpTheCertificates().");
  if (!pep.dir) {
    log.debug("Leaving cleanUpTheCertificates(). Nothing was written.");
    return;
  }
  try {
    fs.rmSync(pep.dir, { recursive: true, force: true });
  } catch (e) {
    // Best effort on a temporary directory. **The realm that certificate
    // registers into SURVIVES the run now**, so this is no longer a key for a
    // credential nothing could ever accept again and it is worth removing on
    // its own account rather than out of tidiness. It is still not worth
    // failing a passing job over: it is one directory under the system
    // temporary path, the container that used it is stopped, and the row it
    // authenticates as can be taken off /admin/xacml/peps.
    log.warn("Could not remove " + pep.dir + ": " + e.message);
  }
  log.debug("Leaving cleanUpTheCertificates().");
}

// ---------------------------------------------------------------------------
// THE RUN.
// ---------------------------------------------------------------------------
// THE MEMBERSHIPS PRODUCT MODE DOES NOT SEED (2026-09-21): `xacml-user-1`
// for section 3's askThePdp, and — when a launcher owns the container — its
// `remote-pep-1`, which the self-started path provisions for itself
// (provisionTheContainersIdentity()). sts_xacml_endpoints.js's admit()
// argues the DN; in development both writes change nothing.
// **AND SINCE #1061 THE MEMBER IS THE ENTRY STORING THE CERTIFICATE.** These
// are outside authorities' certificates, which name nobody by their CN any
// more: `admit()` makes the entry where it is missing, STORES the leaf on it
// (`pep-credential.js`'s `storeOnEntry()`), and adds that entry by name —
// where it used to add a `cn=<CN>` DN that need not exist.
async function admit(commonName, group, leafPem) {
  log.debug("Entering admit(). " + commonName + " " + group);
  await credentials.storeOnEntry({ get: get, post: postJson }, base,
                                 "/realm/" + REALM, commonName, leafPem);
  const member = commonName;
  const joined = await postJson(api("/groups/add-member"),
                                { group: group, member: member });
  assert.ok(joined.status === 200 && joined.body && joined.body.ok,
    "adding " + member + " to " + group + " answered " + joined.status +
    " " + String(joined.text).slice(0, 300));
  log.debug("Leaving admit().");
}

// THE LAUNCHER'S LEAF (#1061), which this job has to store on the PEP's entry
// because the launcher minted it before this job created the realm the entry
// is in. `XACML_PEP_CERT_PEM` when a launcher exports it; otherwise the file
// both launchers mount, `pep.crt` beside the server pair's directory —
// `XACML_PEP_SERVER_CERT_DIR`'s parent — whose first block is the leaf.
function launcherLeafPem() {
  log.debug("Entering launcherLeafPem().");
  let pem = String(process.env.XACML_PEP_CERT_PEM || "");
  if (pem.indexOf("BEGIN CERTIFICATE") < 0 &&
      process.env.XACML_PEP_SERVER_CERT_DIR) {
    const file = path.join(path.dirname(
      String(process.env.XACML_PEP_SERVER_CERT_DIR)), "pep.crt");
    try {
      pem = fs.readFileSync(file, "utf8");
    } catch (e) {
      log.debug("Caught in launcherLeafPem(): " + ((e && e.message) || e));
      pem = "";
    }
  }
  // '' WHERE THERE IS NONE, which since phase 4 of #1827's follow-up is
  // the ordinary case: the launchers mint no client certificate.
  log.debug("Leaving launcherLeafPem(). " +
            (pem.indexOf("BEGIN CERTIFICATE") >= 0 ? "found" : "none"));
  return pem.indexOf("BEGIN CERTIFICATE") >= 0 ? pem : "";
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving a REAL remote PEP CONTAINER against " + base);

  // A SERVICE THAT IS NOT THERE IS A FAILURE AND NOT A SKIP, which is the rule
  // tests/CLAUDE.md records the 2026-08-28 default flip for: a job that reports
  // green having driven nothing is worse than one that is honestly absent.
  const status = await get(base + "/admin-api/status");
  assert.strictEqual(status.status, 200,
    "GET /admin-api/status answered " + status.status + " at " + base +
    ". This job needs the mock and a docker daemon.");
  assert.ok(LAUNCHER_STARTED_IT ||
            fs.existsSync(path.join(REPO_ROOT, PEP_DOCKERFILE)),
    "the remote PEP's Dockerfile is not at " +
    path.join(REPO_ROOT, PEP_DOCKERFILE) + ". With no launcher-provided PEP " +
    "this job builds and runs THE IMAGE FROM THIS TREE rather than a " +
    "stand-in, so there is nothing to fall back to.");
  // DOCKER IS NEEDED ONLY WHEN THIS JOB HAS TO START ITS OWN CONTAINER. Under
  // either launcher one is already running and this job never shells out —
  // which is the whole reason the launcher owns it, because the containerized
  // runner has no docker in it. `tools/run-report.js` skips this job when the
  // daemon is absent AND no launcher provided a PEP; reaching the assertion
  // below means docker was expected and is not working.
  if (!LAUNCHER_STARTED_IT) {
    const daemon = dockerQuiet(["version", "--format", "{{.Server.Version}}"]);
    assert.ok(daemon.ok,
      "no XACML_PEP_URL was provided, so this job has to build an image and " +
      "run a container of its own — and no docker daemon answered: " +
      (daemon.err || "docker is not on the PATH") + ".");
    log.info("No PEP was provided by a launcher, so this job will build and " +
             "start one. docker " + daemon.out + " is answering.");
  }

  // THE CREDENTIAL BEFORE THE REALM, because the truststore is process-wide
  // while the realm is not: one anchor covers every realm this file works in,
  // and doing it first means section 3 cannot be the place a certificate
  // problem is first noticed.
  await mintTheCredential();
  await createTheRealm();
  try {
    // THE NUDGE OFF UNTIL SECTION 6 (2026-11-14): the PEP's notify URL is
    // its HTTPS listener, which the PDP could dial once section 1b has
    // written the pair — so sections 1 to 5 would converge by nudge as well
    // as by poll. Off in this realm, they converge by polling alone.
    await setSetting("xacml.pepNotify", false);
    await createThePeople();
    await admit("xacml-user-1", "xacml-users", xacmlUser.leaf.pem);
    if (LAUNCHER_STARTED_IT) {
      // PHASE 4 OF #1827's FOLLOW-UP: the launchers mint no client
      // certificate for the container, so its entry is made and put in the
      // group without one; a launcher that still writes pep.crt has it
      // stored as before (an older stack), which costs nothing.
      const leaf = launcherLeafPem();
      if (leaf) {
        await admit(PEP_NAME, "remote-peps", leaf);
      } else {
        await provisionTheContainersIdentity();
      }
      await registerTheLaunchersKey();
    }
    // THE TWO THINGS THE CONTAINER NEEDS BEFORE IT CAN SETTLE, in this order
    // and both before anything is asserted about it.
    //
    // **NOTHING IS TURNED OFF HERE AND THAT IS NEW.** This job used to set
    // `xacml.pepRequireCertificate` to false, because the container had no
    // certificate to present. It has one now — the launcher mints it, trusts
    // its Root CA and mounts it — so the realm below is left at its DEFAULTS
    // and the PEP is admitted by the ordinary path: a verified certificate
    // whose DN resolves to a directory entry holding REMOTE_PEPS. A job that
    // has to weaken a service to drive it is a job that is not driving the
    // service anybody runs.
    //
    // THERE MUST BE SOMETHING TO PULL. A PEP that registered against an empty
    // repository would hold nothing, and section 1 could not tell that from a
    // PEP that failed to pull.
    const built = await act("create-from-template", {
      template: "rbac", name: POLICY_A,
      p_roleAttribute: "employeeType",
      p_adminRoles: "admin",
      p_readerRoles: "staff",
      p_readerActions: "GET, HEAD"
    }, "created the baseline policy");
    assert.ok(String(built.what).indexOf("root") > 0,
      "the first policy in an empty repository becomes the root; the PAP " +
      "said: " + built.what);

    if (LAUNCHER_STARTED_IT) {
      await attachToThePep();
    } else {
      await startThePep();
    }
    try {
      await waitForItToFindTheRealm();
      await itRegistersAndPulls();
      await itAuthenticatesOnItsKey();
      await theListenerServesARealmCertificate();
      await itDecidesInItsOwnProcess();
      await thePipReachesTheDirectory();
      const polledMs = await aDeployedPolicyConverges();
      await anUndischargeableObligationRefuses();
      await aDisabledPolicyStopsBeingEnforced();
      await theNudgeIsDelivered(polledMs);
      await thePdpSeesWhatItNeverSaw();
      await theNudgeCarriesNothing();
      // Section 10 (#1760) BEFORE section 9, which takes the PDP away for
      // good: the proxy pulls its configuration and validates credentials
      // at the service, so it needs the seam section 9 cuts.
      await itTakesItsSettingsFromTheService();
      await itBindsTheListenersTheServiceDefines();
      await itProxiesAnApplication();
      // Section 11 (#1827's follow-up, phase 3) before section 9 too: its
      // two PEPs need the PDP.
      await twoPepsOnKeysAlone();
      await itKeepsEnforcingWhenThePdpIsGone();
    } finally {
      stopThePep();
    }
  } finally {
    theRealmIsLeftBehind();
    cleanUpTheCertificates();
  }

  // A FLOOR ON THE COUNT, for the reason sts_admin_console.js gives: a section
  // that stops being called takes its assertions with it and the run still says
  // "passed", which is the one failure mode a suite cannot report about itself.
  assert.ok(checks >= 29,
    "only " + checks + " checks ran. This file makes more than twenty-nine " +
    "against a healthy service, so a count this low means a SECTION STOPPED " +
    "BEING CALLED rather than that the surface got simpler.");
  log.info(checks + " checks passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_xacml_remote_pep")
  .description("Build the remote XACML PEP image from this tree, run it as a " +
      "CONTAINER on the service's own docker network, register it over " +
      "mutual TLS, deploy policy through /admin-api/xacml, and assert that " +
      "what that container ALLOWS and REFUSES changes with it — by polling, " +
      "then by a nudge the PDP delivers across the bridge, and finally with " +
      "the PDP taken away from it entirely.")
  .addOption(new Option("-u, --url <url>", "base url of the STS under test")
      .default(base))
  .parse(process.argv);
base = String(program.opts().url || base).replace(/\/+$/, "");

test().then(function () {
  return credentials.settleAnchors(base, addedAnchors, null);
}, function (e) {
  // Cleanup still runs, and the original failure is passed through
  // settleAnchors(), which rethrows it.
  log.debug("Caught in test(): " + ((e && e.message) || e));
  return credentials.settleAnchors(base, addedAnchors, e);
}).catch(async function (e) {
  log.error(e.stack || e.message);
  // THE TEARDOWN RUNS EVEN WHEN SOMETHING THREW FROM OUTSIDE THE try/finally
  // above — a failure in the image build, in createTheRealm() or in
  // startThePep() lands here. All of it is best effort and none of it may mask
  // the original failure, which has already been logged. **A LEFTOVER
  // CONTAINER IS THE ONE THING THAT MUST NOT SURVIVE A FAILURE**: it would go
  // on polling for as long as the machine is up. The REALM is the opposite
  // case and survives on purpose — see theRealmIsLeftBehind().
  try {
    stopThePep();
    theRealmIsLeftBehind();
    cleanUpTheCertificates();
  } catch (another) {
    log.warn("The teardown after a failure also failed: " + another.message);
  }
  process.exit(1);
});
