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
//   3. **IT VERIFIES THAT CERTIFICATE FOR REAL**, with `PEP_TLS_CA` pointing at
//      an anchor copied into the container, rather than `PEP_TLS_INSECURE`.
//      Both are supported and the insecure one is what the compose file ships;
//      this job takes the strict path so that a certificate this service could
//      not actually be verified under fails HERE.
//   4. **THE NUDGE IS DELIVERABLE.** The PDP dials `http://<pep>:9090/notify`
//      across the bridge — this repository's THIRD outbound request, and the
//      only one of the three with no test against a real listener anywhere
//      until this file. Section 6 measures it: a change reaches the PEP in tens
//      of milliseconds against a five-second poll, and the PDP's own row
//      records what the PEP answered.
//   5. **`docker cp` PUTS THE CLIENT CERTIFICATE WHERE `pep.js` READS ONE**, so
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
// CLAUDE.md's placement rule asks two questions in order, and this file answers
// the first one YES and the second one NO, so both point here:
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
// `XACML_PEP_REALM`. That is the primary arrangement and the one CI runs:
//
//   * `./local-run-tests.sh` adds `--profile xacml` to the project it already
//     brings the service up in, on a free host port, and exports the three.
//   * `./docker-run-tests.sh` declares the service in
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
// configuration is identical, deliberately: no client certificate, no anchor,
// the same intervals — which is exactly what `docker-compose.yml` ships, so
// what is asserted below is the deployment somebody actually gets rather than
// one this file arranged for itself.
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
// NO CLIENT CERTIFICATE, AND THAT IS THE SHIPPED DEFAULT RATHER THAN A GAP.
//
// `docker-compose.yml` ships this container without one and says why: putting
// a key in the image would mean committing a private key to this repository or
// writing a first-start script for a demonstration container. So this job turns
// `xacml.pepRequireCertificate` off IN ITS OWN REALM and asserts the row is
// marked UNAUTHENTICATED — which is what the PDP does with a registration that
// proved nothing, and is worth checking precisely because it is the state an
// operator will actually be looking at.
//
// **THE AUTHENTICATED PATH IS ASSERTED NEXT DOOR AND MORE STRICTLY THAN THIS
// JOB COULD**: `sts_xacml_endpoints.js` section 7 presents a real certificate
// over a real handshake AND presents one claiming to be somebody else, which is
// the security half of that door.
//
// ---------------------------------------------------------------------------
// THE ONE THING THIS JOB WILL NOT DO UNTIL SECTION 6.
//
// **THE NUDGE IS DELIBERATELY UNDELIVERABLE FOR SECTIONS 1–5**, because the
// PULL is the contract and the nudge is an optimisation over it. The PEP
// registers a plain-http notify URL while `xacml.pepNotifyAllowInsecure` is
// off, so the PDP refuses to dial it and says so in the registration reply —
// which section 1 asserts rather than assumes. Every convergence up to section
// 5 is therefore a POLL and nothing else.
//
// Section 6 then turns that setting on IN THIS REALM and measures the
// difference, which is the only way to have both claims: that the PEP converges
// without the nudge, and that the nudge works.
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
// **THE LAUNCHERS' PEP IDENTITY IS STILL A SEED**, and that is recorded rather
// than changed: when a launcher owns the container, PEP_NAME is the seeded
// `remote-pep-1` in the seeded `remote-peps` group, and product mode seeds
// neither. The self-started path already creates both, in
// `provisionTheContainersIdentity()`; the launcher path would need the same two
// writes made before the container's first registration attempt, which is the
// launcher's to arrange.
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

var xacmlUser = null;

async function mintTheCredential() {
  log.debug("Entering mintTheCredential().");
  xacmlUser = await credentials.mint({
    subject: "CN=xacml-user-1,OU=xacml-users,O=mock-sts tests" });
  const posted = await credentials.trustAnchor(base, xacmlUser.anchorPem);
  assert.ok(posted.ok, "POST /tls/trust should accept the Root CA this file " +
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
  // `POST /tls/trust/clear` needs no credential, and a job that exercises the
  // truststore is entitled to use it.
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
  const containerAnchor = String(process.env.XACML_PEP_CA_PEM || "");
  if (containerAnchor.indexOf("BEGIN CERTIFICATE") >= 0) {
    const back = await credentials.trustAnchor(base, containerAnchor);
    assert.ok(back.ok,
      "POST /tls/trust should accept the PEP container's Root CA, which the " +
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
    log.warn("XACML_PEP_CA_PEM is not set, so this job cannot put the PEP " +
             "container's Root CA back if an earlier job emptied the " +
             "truststore. Both launchers export it; running this file by " +
             "hand against your own stack does not, and the container's " +
             "registration will say whether its certificate verifies.");
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
            dir: "", certDir: "", hostPort: 0, containerPort: 9090 };

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
  // ./local-run-tests.sh the launcher's container and this process are on the
  // same machine and its log is the most useful thing a failure here can
  // carry. Under ./docker-run-tests.sh there is no docker to ask, so the
  // fallback names the container and the command rather than pretending.
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
// This job is run in three stacks and the service is not the same KIND of thing
// in all three, so the network is discovered rather than assumed:
//
//   * `./local-run-tests.sh` and `./docker-run-tests.sh` put the service in a
//     CONTAINER on a compose network with a published port. The PEP joins that
//     network, dials the service by its container HOSTNAME on the INTERNAL port
//     — which is what `docker-compose.yml` ships and is a name in the
//     certificate — and publishes a port of its own for this job to reach.
//   * `--no-docker` and a bare `run-report.js` run the service as a plain
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
  return "CN=" + PEP_NAME + ",OU=remote-peps,O=mock-sts tests";
}

// The entry and the membership, in THIS RUN'S REALM — the directory is per
// realm, so the seeded `remote-peps` group in the default realm is not the one
// the PDP will read when it resolves this certificate.
async function provisionTheContainersIdentity() {
  log.debug("Entering provisionTheContainersIdentity().");
  // With the attributes a real entry carries and nothing invented — product
  // mode invents no persona onto an entry, and a directory entry for an
  // enforcement point is a record somebody reads.
  const made = await postJson(api("/users/create"), {
    username: PEP_NAME, invent: false,
    attributes: { cn: PEP_NAME, sn: "Remote PEP", displayName: PEP_NAME,
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

async function mintTheContainersCredential() {
  log.debug("Entering mintTheContainersCredential().");
  await provisionTheContainersIdentity();
  const cred = await credentials.mint({ subject: containerSubject() });
  const posted = await credentials.trustAnchor(base, cred.anchorPem);
  assert.ok(posted.ok,
    "POST /tls/trust should accept the Root CA for the PEP container this " +
    "job is about to start; it answered " + posted.status + ". Without the " +
    "anchor that container's certificate verifies against nothing, it " +
    "registers as an unauthenticated caller, and the PDP refuses it with a " +
    "403 naming REMOTE_PEPS.");

  // ON DISK BECAUSE `pep.js` READS FILES, and in a directory of this job's
  // own rather than the launcher's `tests/report/pep-credential`: two runs on
  // one machine must not share it, and this one is removed with the
  // container. `mkdtemp` rather than a name built from the stamp, so the
  // collision cannot be constructed at all.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mock-sts-pep-cert-"));
  // The leaf FOLLOWED BY THE INTERMEDIATE, which is what `certPem` already
  // is — the service holds only the root, so a container sending the leaf
  // alone presents a chain that cannot be built.
  fs.writeFileSync(path.join(dir, "pep.crt"), cred.certPem, { mode: 0o644 });
  // 0644 AND NOT 0600, deliberately: the mount is read-only and the process
  // inside that image is not this user, so a key only this user can read is a
  // container that starts and quietly has no certificate.
  fs.writeFileSync(path.join(dir, "pep.key"), cred.keyPem, { mode: 0o644 });
  log.info("Minted the PEP container's client certificate (" + cred.subject +
           ") and trusted its Root CA. It is mounted at /certs.");
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
    // THE CLIENT CERTIFICATE, WHICH IS WHAT THE PDP'S GATE ASKS FOR. The
    // launchers pass these two through docker-compose as XACML_PEP_TLS_CERT /
    // XACML_PEP_TLS_KEY onto the same names; here the mount below is /certs
    // for the same reason it is there.
    PEP_TLS_CERT: "/certs/pep.crt",
    PEP_TLS_KEY: "/certs/pep.key"
  };

  pep.certDir = await mintTheContainersCredential();

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
    // The PDP dials this across the bridge by the container's own name.
    environment.PEP_NOTIFY_URL = "http://" + PEP_NAME + ":9090/notify";
  } else {
    pep.containerPort = await freePort();
    pep.hostPort = pep.containerPort;
    environment.PEP_PORT = String(pep.containerPort);
    // On the host network the service is a process on this same loopback, so
    // this is the address it dials — and it is still a real outbound request
    // made by the PDP to a listener it does not share a process with.
    environment.PEP_NOTIFY_URL = "http://127.0.0.1:" + pep.containerPort +
                                 "/notify";
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
// becomes a subject attribute the CALLER asserted about itself — which is what
// a PEP with no Policy Information Point has to work from, and is the whole
// subject of section 3.
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
      "OVER MUTUAL TLS, BETWEEN TWO CONTAINERS. The launcher minted a client " +
      "certificate with tests/tools/pep-credential.js, POSTed its Root CA to " +
      "/tls/trust and mounted the leaf and key into this container; the " +
      "handshake at /xacml/pep/register carried it. It says " +
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

  check("the PEP reports a real build number, and the PDP's row carries it",
        function () {
    const MNO = /^\d+\.\d+\.[A-Za-z0-9._-]+$/;
    assert.ok(MNO.test(String(seen.version)),
      "the PEP reports version " + JSON.stringify(seen.version) + ", which " +
      "is not M.N.O. A version that is a LABEL rather than a number is what " +
      "this container shipped until 2026-09-06: it cannot change, so the " +
      "console column that shows it cannot be trusted." + pepLog());
    assert.ok(seen.build && typeof seen.build === "object",
      "and it should break the provenance out beside it — build number, " +
      "commit, and whether it was stamped — so a client comparing this PEP " +
      "against the PDP reads fields rather than parsing a string. It says " +
      JSON.stringify(seen.build) + pepLog());
    assert.strictEqual(seen.version,
      seen.version.split(".").slice(0, 2).join(".") + "." + seen.build.number,
      "`version` should be M.N joined to `build.number`; they are " +
      seen.version + " and " + seen.build.number);
    assert.strictEqual(seen.build.stamped, true,
      "THIS CONTAINER MUST BE A BUILT ARTIFACT. `stamped: false` means it " +
      "computed its build number when the process started — so it renumbers " +
      "itself on every restart and comparing it with the PDP's build says " +
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

    // AND M.N MATCHES THE PDP'S OWN. The two images are built from ONE tree
    // and one VERSION file, so the release must agree even though the build
    // numbers need not — they are two artifacts and compose stamps each with
    // its own instant unless one BUILD_NUMBER was passed to both. This is the
    // assertion that catches a PEP left behind across a release, which is the
    // whole reason that column is on the console.
    assert.strictEqual(pdpIndex.status, 200,
      "GET /admin-api answered " + pdpIndex.status);
    const pdpMN = String(pdpIndex.body.version).split(".").slice(0, 2)
                    .join(".");
    const pepMN = seen.version.split(".").slice(0, 2).join(".");
    assert.strictEqual(pepMN, pdpMN,
      "the PEP is release " + pepMN + " and the PDP is " + pdpMN + ". Both " +
      "images are built from this one tree and read the same repo-root " +
      "VERSION file, so a difference here is not a stale container — it is a " +
      "build that took its VERSION from somewhere else. (The BUILD NUMBERS " +
      "may legitimately differ: " + seen.build.number + " against " +
      pdpIndex.body.build + ".)");
    log.info("[version] the PEP is " + seen.version + " and the PDP is " +
             pdpIndex.body.version + " — same release " + pdpMN + ".");
  });

  check("the PDP will NOT nudge this PEP yet, and said so in the " +
        "registration reply", function () {
    assert.ok(seen.registration.notify,
      "the registration answer should carry the PDP's verdict on the notify " +
      "URL; the PEP recorded " + JSON.stringify(seen.registration));
    assert.strictEqual(seen.registration.notify.usable, false,
      "THIS IS THE PREMISE OF SECTIONS 4 AND 5. The PEP registered an http " +
      "notify URL and xacml.pepNotifyAllowInsecure is off, so the PDP will " +
      "not dial it — which means the convergences up to section 5 happened " +
      "by POLLING. Section 6 turns it on and measures the difference. The " +
      "PDP said " + JSON.stringify(seen.registration.notify));
    assert.ok(String(seen.registration.notify.why)
                .indexOf("pepNotifyAllowInsecure") > 0,
      "and it should name the setting rather than merely refusing; it says " +
      seen.registration.notify.why);
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
      "the row should record that a certificate proved something; it says " +
      there.row.authenticated);
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
// outbound request at a listener that answers. This service makes exactly three
// outbound requests and CLAUDE.md argues each separately; the nudge is the
// weakest of the three and pays for itself by carrying nothing — and until this
// section it had never been delivered to anything in a test.
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

  await setSetting("xacml.pepNotifyAllowInsecure", true);
  const readied = await pepRow();
  check("with the setting on, the PDP now considers the PEP nudgeable",
        function () {
    assert.strictEqual(readied.row.notifyProblem, null,
      "THE VERDICT IS COMPUTED RATHER THAN REMEMBERED, which is what lets a " +
      "setting changed after a registration change what this page says about " +
      "it. The row still reports: " + readied.row.notifyProblem);
    assert.ok(readied.row.notifyUrl,
      "and the row should carry the address the PEP registered; it has " +
      readied.row.notifyUrl);
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
  // and xacml.pepNotifyAllowInsecure is off" — while the service log showed
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

  // AND ONLY NOW THE LATENCY. The row above is the deterministic half and it is
  // asserted FIRST on purpose: a broken nudge must fail on "no nudge was ever
  // dialled" rather than on a number, because the number is the one assertion
  // here that a lucky poll can satisfy. This one adds what the row cannot say —
  // that the delivery actually shortened the wait.
  check("and the change reached the container in a FRACTION of the polling " +
        "interval", function () {
    assert.ok(elapsed < POLL_MS / 4,
      "the poll interval is " + POLL_MS + "ms and section 4 took " + polledMs +
      "ms to converge without a nudge. This one took " + elapsed + "ms, and " +
      "a delivered nudge is TENS of milliseconds — the PDP posts as the " +
      "store is written and the PEP pulls on the way out of answering 204. A " +
      "number up in the hundreds means the nudge was recorded as delivered " +
      "and did not cause THIS convergence: the poll did the work, and a PEP " +
      "that answers a nudge without acting on it looks identical from every " +
      "other angle.");
    log.info("Nudged convergence: " + elapsed + "ms, against " + polledMs +
             "ms by polling and a " + POLL_MS + "ms interval.");
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
//      the nudge carries nothing that a third outbound requester was affordable
//      at all (CLAUDE.md).
//
// The second is asserted with a body that WOULD change the decision if it were
// believed, which is the only version of that assertion worth making.
// ===========================================================================
async function theNudgeCarriesNothing() {
  log.debug("Entering theNudgeCarriesNothing().");
  log.info("=== A nudge is believed about nothing ===");

  const before = await pepOverview();

  const started = Date.now();
  const nudged = await fetchJson(pep.url + "/notify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    // A POLICY THAT PERMITS EVERYTHING, offered to the PEP by an
    // unauthenticated caller. If any of this were read, the assertions below
    // would fail — which is the whole reason to send it rather than `{}`.
    body: JSON.stringify({
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
    })
  });
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
// three endpoints under /xacml/pep answer 501 to that container and to nothing
// else in the service, so the outage is scoped exactly to the seam under test
// and is REVERSIBLE, where a removal was not. From the PEP's side the two are
// the same event — a pull that does not return a policy set — and `sync.js`
// takes any non-200 through the same `keep()`.
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
    id: REALM, name: "Remote PEP end-to-end realm",
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
  log.debug("Leaving createTheRealm().");
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
async function test() {
  log.debug("Entering test().");
  log.info("Driving a REAL remote PEP CONTAINER against " + base);

  // A SERVICE THAT IS NOT THERE IS A FAILURE AND NOT A SKIP, which is the rule
  // CLAUDE.md records the 2026-08-28 default flip for: a job that reports green
  // having driven nothing is worse than one that is honestly absent.
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
    await createThePeople();
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
      await itDecidesInItsOwnProcess();
      await thePipReachesTheDirectory();
      const polledMs = await aDeployedPolicyConverges();
      await aDisabledPolicyStopsBeingEnforced();
      await theNudgeIsDelivered(polledMs);
      await thePdpSeesWhatItNeverSaw();
      await theNudgeCarriesNothing();
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
  assert.ok(checks >= 26,
    "only " + checks + " checks ran. This file makes more than twenty-six " +
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

test().catch(async function (e) {
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
