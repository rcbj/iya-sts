// File: sts_xacml_endpoints.js
//
// ---------------------------------------------------------------------------
// THE EIGHT /xacml ENDPOINTS, DRIVEN OVER HTTP.
//
// `tests/xacml_conformance.js` holds the ENGINE to 455 cases somebody else
// wrote, `tests/xacml_service.js` holds the store, the PIP and the JSON
// Profile, and `tests/xacml_pep.js` holds the two things about the remote PEP
// that no running service can be asked. All three are in process, and between
// them they never make one HTTP request — so until this file existed, every
// route in `xacml/xacml.ts` was uncovered: the decision endpoint, the
// repository, the embedded PEP, the three the remote PEP lives on and — since
// 2026-09-06 — the PIP.
//
// That gap is not academic. The engine being right says nothing about whether
// the endpoint in front of it PARSES what a PEP sends, whether a malformed
// request is a 400 rather than an Indeterminate, whether a disabled policy is
// left out of what a remote PEP pulls, or whether a registration can name
// itself as somebody else's PEP. Every one of those is a property of this
// file's subject and of nothing the in-process suite touches.
//
// ---------------------------------------------------------------------------
// WHERE THIS FILE STOPS, AND WHAT PICKS IT UP.
//
// **THE CALLER HERE IS THIS TEST IMPERSONATING A PEP.** Sections 6 and 7 drive
// `GET /xacml/pep/policies`, `POST /xacml/pep/register` and
// `POST /xacml/pep/heartbeat` over `https.request` with a client certificate
// minted by `tests/tools/pep-credential.js`, which is the right way to assert
// what those endpoints ANSWER — the ETag, the 304, the disabled policy left
// out, the name taken from the certificate and never from the body. What it
// cannot assert is any CONSEQUENCE of those bytes, because nothing here
// evaluates them: the document pulled in section 6 is checked for a `<Policy`
// and thrown away.
//
// `tests/vendored/sts_xacml_remote_pep.js` (2026-09-06) drives
// `xacml-pep/pep.js` in a second CONTAINER and asserts the other half — that a
// policy deployed through `/admin-api/xacml` reaches it by POLLING and changes
// what it ALLOWS, and that a policy disabled here stops being ENFORCED there.
// Keep the two apart when editing either: an assertion about what an endpoint
// answers belongs in this file, and one about what a PEP does with the answer
// belongs in that one.
//
// ---------------------------------------------------------------------------
// WHY THIS IS THIS REPOSITORY'S OWN (`local: true`) AND NOT THE PARENT'S.
//
// The root CLAUDE.md's rule is that anything drivable over HTTP belongs in the
// parent project's suite, and a naive reading puts the whole of this file
// there. It does not survive the first assertion.
//
// **A PDP WITH AN EMPTY REPOSITORY ANSWERS NotApplicable TO EVERYTHING.** There
// is no interesting question to ask this surface until a policy exists, and the
// only way to put one there over HTTP is
// `/admin-api/xacml/create-from-template` — a door this repository owns, on the
// console this repository's own jobs cover. So every section below is a CONSOLE
// CONTROL WITH A PROTOCOL CONSEQUENCE: a template built through `/admin-api`
// decides at `/xacml/pdp`, a policy disabled on `/admin/xacml/policies`
// disappears from what a remote PEP pulls, an obligation added in the editor
// turns a Permit into a refusal at `/xacml/protected`, and a PEP disabled on
// `/admin/xacml/peps` stays disabled when it re-registers. That is exactly the
// argument `sts_consent.js` makes one file over, and splitting these in two was
// refused for its reason: the assertion that matters is that the authoring door
// changes what the DECIDING door says, and a test with the two halves in two
// repositories could not make it.
//
// ---------------------------------------------------------------------------
// IT RUNS IN A TRUST REALM OF ITS OWN, AND THAT IS NOT MERELY TIDINESS.
//
// `ou=policies` is per realm, and a realm's repository starts EMPTY — the
// seeded policy is written once, at require time, in the default realm. So a
// throwaway realm gives this job the one thing it cannot otherwise have: a
// repository whose entire contents it wrote. Every count below is exact rather
// than "at least", the sync token moves only when this file moves it, and the
// "no root policy" state — which the default realm can never be in — is
// reachable and asserted.
//
// It also makes the SETTINGS safe. Six sections turn `xacml.enabled`,
// `xacml.remotePeps`, `xacml.pepBias` and `xacml.pepRequireCertificate` off and
// on, and every one of those is process-wide when set at the top level: a job
// that turned XACML off and died would leave every later job in the run driving
// a service answering 501. Set inside the realm they reach nothing else — and
// that is what lets the realm be LEFT STANDING at the end rather than removed,
// which it is since 2026-09-06. See theRealmIsLeftBehind().
//
// ---------------------------------------------------------------------------
// THE CLIENT CERTIFICATE IS MINTED HERE, AND IT IS WHAT MAKES TWO OF THESE
// ASSERTIONS POSSIBLE AT ALL.
//
// `POST /xacml/pep/register` names a PEP from the COMMON NAME of the
// certificate it registered with, and falls back to the `name` in the body only
// when there is none — because a PEP that could name itself while holding a
// certificate could register as somebody else's PEP and take over their row.
// The heartbeat follows the same rule. Those are the two places in this family
// where a defect would be a security bug rather than a fidelity one, and
// neither can be checked without presenting a certificate: the refusal path
// proves only that something was demanded, not that what was presented was
// believed over what was claimed. So this file presents a certificate and
// sends those requests through `https.request`, because node's `fetch` cannot
// present one.
//
// The certificate chained to nothing until 2026-09-06, when these doors began
// requiring a VERIFIED chain whose DN resolves to a directory entry holding a
// role: it is minted now by `tests/tools/pep-credential.js` under a Root this
// file posts to `/tls/trust` — see *A trusted client credential* below.
// (`selfSignedFor()` is what built the old one.)
// ---------------------------------------------------------------------------
//
// ---------------------------------------------------------------------------
// IT WAS MUTATION-TESTED AGAINST SIX MUTANTS BEFORE IT WAS COMMITTED, which is
// `tests/CLAUDE.md`'s rule and is not optional here either: a guard that has
// never failed has not been shown to guard anything. Each was applied to a
// COPY of the tree, driven, and reverted:
//
//   1. a malformed request answered `Indeterminate` instead of 400 — caught by
//      the four refusals in section 4, which is the mutant that section exists
//      for;
//   2. the embedded PEP taught to discharge the obligation it does not know —
//      caught by section 5, where the Permit stops being refused;
//   3. `GET /xacml/pep/policies` sending disabled policies too — caught by
//      section 6, which is a PEP enforcing a policy this service does not;
//   4. a registration taking its name from the BODY in preference to the
//      certificate — caught by section 7, and it is the security-shaped one;
//   5. `?since=` never answering 304 — caught by section 6;
//   6. `xacml.enabled` stopping being honoured — caught by section 9.
//
// The fourth is the one worth keeping in mind when this file is edited: it is
// the only mutant here whose effect is invisible to every other assertion, and
// the only one that needs a client certificate to see at all.
// ---------------------------------------------------------------------------

"use strict";

const assert = require("assert");
const https = require("https");
const { URL } = require("url");
const { Command, Option } = require("commander");
const forge = require("node-forge");
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
var log = bunyan.createLogger({ name: "sts_xacml_endpoints",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug('CONFIG_FILE could not be read, so the configuration is empty: ' +
            appconfigProblem.message);
}
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");

// The throwaway realm. Lower-cased and folded to what a realm id may hold,
// because the registry refuses anything else and a job that fails on its own
// setup names the wrong thing.
const REALM = ("xacml-" + names.runStamp()).toLowerCase()
    .replace(/[^a-z0-9-]/g, "").slice(0, 40);

const POLICY = "rbac-under-test";
// **THE SEEDED IDENTITY, NOT A RANDOM ONE, SINCE 2026-09-06.** It was
// `pep-<runStamp>` — unique per run, which is this suite's habit and was right
// while any certificate at all could register. The three endpoints are gated
// now: a client certificate is resolved to a directory entry by its subject DN
// and that entry has to be a member of `cn=remote-peps`, which every realm is
// seeded with holding exactly `cn=remote-pep-1` (in development mode; product
// mode seeds the group without it). A random common name resolves to an entry
// in no group and is refused — which is section 7's rogue assertion rather
// than an obstacle to work around.
const PEP_CN = "remote-pep-1";
// A second identity from the SAME trusted authority, for the one case that
// matters most: verified, named, and holding no role.
const ROGUE_CN = "rogue-pep-" + names.runStamp();
// THE SEEDED XACML_USER IDENTITY, and it is a FIXED name rather than a stamped
// one — `cn=xacml-user-1` is what `ldap_server.js` seeds into `cn=xacml-users`
// in every realm in development mode, so a certificate for it is admitted
// with nothing configured.
// The rogue name above is stamped precisely because it must resolve to an
// entry that exists and holds NOTHING, which a fresh name does.
const XACML_USER_CN = "xacml-user-1";
// THE TWO PEOPLE THE RBAC POLICY DECIDES ABOUT, CREATED BY THIS JOB IN ITS
// REALM (2026-09-12). They were the seeded `carol` (employeeType=admin) and
// `alice` (employeeType=staff), whom every realm's directory holds in
// development and in product nobody. Two people with the same `employeeType`
// are made in `createThePeople()` instead, with the attributes a real account
// carries — `mail` and `sn` among them, because the PIP section reads both —
// so every decision below is still about an attribute the PIP fetches and the
// request never carries, and none of it depends on a seed.
//
// **THE TWO CERTIFICATE IDENTITIES ABOVE STILL ARE SEEDS**, and that is
// recorded rather than changed: `cn=remote-pep-1` and `cn=xacml-user-1` are
// resolved in THIS realm and in the DEFAULT one (sections 9 and 10 read the
// default realm's repository with the same certificate), so replacing them
// means provisioning an entry and a group membership in both — which writes
// to the default realm's role groups, a change every later job in the run
// inherits.
const ADMIN_PERSON = "xacml-admin-person";
const STAFF_PERSON = "xacml-staff-person";
// The XACML core namespace and the access-subject category, written out here
// because the PIP section below builds XML by hand — a job driving a wire
// format has to spell it rather than import the service's own constant, or it
// would be asserting that the service agrees with itself.
const XACML_NS = "urn:oasis:names:tc:xacml:3.0:core:schema:wd-17";
const SUBJECT_CATEGORY =
  "urn:oasis:names:tc:xacml:1.0:subject-category:access-subject";

// The one obligation the embedded PEP knows how to discharge. Written out here
// rather than read from the service, because the whole assertion in section 5
// is that THIS string and no other is discharged — reading it from the module
// under test would make the check agree with whatever the module said.
const DISCHARGEABLE = "urn:sts:xacml:obligation:log";

var checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.debug("check passed: " + what);
  log.debug("Leaving check().");
}

function realmUrl(path) {
  log.debug("Entering realmUrl().");
  log.debug("Leaving realmUrl().");
  return base + "/realm/" + REALM + path;
}

function api(path) {
  log.debug("Entering api().");
  log.debug("Leaving api().");
  return realmUrl("/admin-api" + path);
}

// ---------------------------------------------------------------------------
// THE VERBS.
// ---------------------------------------------------------------------------
async function fetchJson(url, options) {
  log.debug("Entering fetchJson(). url=" + url);
  const r = await fetch(url, options || {});
  const text = await r.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in fetchJson(): " + ((e && e.message) || e));
    // Not JSON — an HTML page or an empty 304. The caller reports the status
    // and the raw text, which says more than a parse error would.
    body = null;
  }
  log.debug("Leaving fetchJson(). status=" + r.status);
  return { status: r.status, body: body, text: text,
           etag: r.headers.get("etag") || "",
           type: r.headers.get("content-type") || "" };
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

// A raw body, for malformed requests like section 4's. `JSON.stringify`
// cannot produce them, which is the point.
function postRaw(url, raw) {
  log.debug("Entering postRaw().");
  log.debug("Leaving postRaw().");
  return fetchJson(url, { method: "POST",
                          headers: { "Content-Type": "application/json" },
                          body: raw });
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

async function resetSetting(key) {
  log.debug("Entering resetSetting().");
  // `reset` RATHER THAN WRITING THE OLD VALUE BACK, for the reason
  // tests/CLAUDE.md's *Restore a setting with `reset`* records: a `set` leaves
  // `source: override` behind, and tests/vendored/admin_api.js reads that
  // field.
  const r = await postJson(api("/config/reset"), { key: key });
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "resetting " + key + " should have worked; it answered " + r.status);
  log.debug("Leaving resetSetting().");
}

// ---------------------------------------------------------------------------
// A JSON PROFILE REQUEST, built the way a PEP would.
// ---------------------------------------------------------------------------
function requestFor(subject, action, resource) {
  log.debug("Entering requestFor().");
  const request = { Request: {} };
  if (subject !== null) {
    request.Request.AccessSubject = { Attribute: [
      { AttributeId: "urn:oasis:names:tc:xacml:1.0:subject:subject-id",
        Value: subject }
    ] };
  }
  request.Request.Action = { Attribute: [
    { AttributeId: "urn:oasis:names:tc:xacml:1.0:action:action-id",
      Value: action }
  ] };
  request.Request.Resource = { Attribute: [
    { AttributeId: "urn:oasis:names:tc:xacml:1.0:resource:resource-id",
      Value: resource || "https://example.test/records",
      DataType: "anyURI" }
  ] };
  log.debug("Leaving requestFor().");
  return request;
}

async function decisionFor(subject, action, resource) {
  log.debug("Entering decisionFor().");
  const r = await xPost("/xacml/pdp", requestFor(subject, action, resource));
  assert.strictEqual(r.status, 200,
    "POST /xacml/pdp should answer 200 with a JSON Profile response even " +
    "when the answer is a refusal; it answered " + r.status + " " +
    String(r.text).slice(0, 300));
  assert.ok(r.body && Array.isArray(r.body.Response) && r.body.Response.length,
    "a JSON Profile response is an object with a Response ARRAY; this one is " +
    String(r.text).slice(0, 300));
  log.debug("Leaving decisionFor().");
  return r.body.Response[0];
}

// ---------------------------------------------------------------------------
// A CLIENT CERTIFICATE, AND THE ONE REQUEST SHAPE THAT CAN CARRY ONE.
//
// `fetch` in node has no way to present a client certificate, so the two
// requests that need one go through `https.request`. Everything else here is
// fetch, deliberately — a second HTTP client used everywhere would be a second
// thing that could be wrong about a status code.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// A TRUSTED CLIENT CREDENTIAL, MINTED FOR THIS RUN (2026-09-06).
//
// The three `/xacml/pep` endpoints no longer accept a certificate that chains
// to nothing: a DN is only worth resolving to a directory entry if this service
// verified the chain it came from. So this file builds a Root CA, an Issuing CA
// and a client leaf on the SAME engine `spiffe/spiffe_ca.ts` issues X509-SVIDs
// with, and POSTs the root to `/tls/trust` — which is exactly what the parent
// project's `tests/pki_mutual_tls.js` has always done, and what
// `tests/tools/pep-credential.js` does for the launchers.
//
// **IT REQUIRES THAT TOOL RATHER THAN REIMPLEMENTING IT.** A second way of
// building a chain in this file would be a second set of edge cases, and the
// one thing worse than a test that fails is one that passes against a
// certificate built differently from the one the product uses.
// ---------------------------------------------------------------------------
const credentials = require("../tools/pep-credential.js");

var trusted = null;   // the identity this file registers with — REMOTE_PEPS
var rogue = null;     // verified, and in no group
// ---------------------------------------------------------------------------
// A THIRD IDENTITY, AND IT IS A THIRD BECAUSE THERE ARE TWO ROLES.
//
// The four XACML endpoints proper — GET /xacml, POST /xacml/pdp, GET
// /xacml/policies, GET /xacml/protected — went behind the same certificate
// chain as /xacml/pep/* and a DIFFERENT role: `XACML_USER`, granted by
// `cn=xacml-users`, where the three PEP endpoints want `REMOTE_PEPS` from
// `cn=remote-peps`.
//
// **SO THIS FILE HOLDS TWO ADMITTED IDENTITIES AND NEITHER OPENS THE OTHER'S
// DOOR**, which is the property section 0 below asserts in both directions. A
// single identity put in both groups would have been fewer lines and would
// have made that assertion unwritable — and the whole reason there are two
// roles is that admitting a caller to the demonstration surface must not
// silently admit it to the endpoints publishing the documents this service
// enforces its own access with.
// ---------------------------------------------------------------------------
// verified, in cn=xacml-users — XACML_USER and not REMOTE_PEPS
var xacmlUser = null;

async function mintTheCredentials() {
  log.debug("Entering mintTheCredentials().");
  trusted = await credentials.mint({
    subject: "CN=" + PEP_CN + ",OU=remote-peps,O=mock-sts tests" });
  rogue = await credentials.mint({
    subject: "CN=" + ROGUE_CN + ",OU=remote-peps,O=mock-sts tests" });
  xacmlUser = await credentials.mint({
    subject: "CN=" + XACML_USER_CN + ",OU=xacml-users,O=mock-sts tests" });
  for (const one of [trusted, rogue, xacmlUser]) {
    const posted = await credentials.trustAnchor(base, one.anchorPem);
    assert.ok(posted.ok, "POST /tls/trust should accept the Root CA this " +
      "file just built; it answered " + posted.status + " " +
      String(posted.why || posted.body).slice(0, 200) + ". Without the " +
      "anchor every assertion below is about an unverified certificate.");
  }
  log.info("Minted a REMOTE_PEPS credential for " + trusted.subject +
           ", an XACML_USER one for " + xacmlUser.subject +
           " and a rogue one for " + rogue.subject +
           "; all three Root CAs are in the truststore.");
  log.debug("Leaving mintTheCredentials().");
}

// A request carrying one of those identities. `fetch` in node cannot present a
// client certificate, so everything that has to be authenticated goes through
// `https.request` — which is why these two exist beside the fetch-based verbs
// above rather than replacing them.
function pepRequest(method, url, identity, payload, rawBody) {
  log.debug("Entering pepRequest(). " + method + " " + url);
  log.debug("Leaving pepRequest().");
  return new Promise(function (resolve, reject) {
    const target = new URL(url);
    // A RAW STRING WINS OVER A PAYLOAD, for section 4's malformed bodies and
    // the PIP section's XML: `JSON.stringify` cannot produce them, which is
    // the point, and they have to travel down THIS path now that /xacml/pdp
    // needs a certificate and `fetch` cannot present one.
    const data = rawBody !== undefined && rawBody !== null ? rawBody
      : (payload === undefined ? null : JSON.stringify(payload));
    const request = https.request({
      host: target.hostname,
      port: target.port || 443,
      path: target.pathname + target.search,
      method: method,
      rejectUnauthorized: false,
      cert: identity ? identity.certPem : undefined,
      key: identity ? identity.keyPem : undefined,
      headers: data ? { "Content-Type": "application/json",
                        "Content-Length": Buffer.byteLength(data) } : {}
    }, function (response) {
      let text = "";
      response.on("data", function (chunk) { text += chunk; });
      response.on("end", function () {
        let body;
        try {
          body = JSON.parse(text);
        } catch (e) {
          log.debug("Caught in a callback in pepRequest(): " +
                    ((e && e.message) || e));
          // A non-JSON answer from a door that answers JSON is worth reporting
          // whole rather than as a parse failure.
          body = null;
        }
        log.debug("Leaving pepRequest(). status=" + response.statusCode);
        // `type` as well, because the fetch-based `get()` reports it and the
        // one assertion that reads it — GET /xacml must be HTML for a person —
        // moved onto this path when that endpoint began asking for a
        // certificate.
        resolve({ status: response.statusCode, body: body, text: text,
                  etag: response.headers.etag || "",
                  type: response.headers["content-type"] || "" });
      });
    });
    request.on("error", reject);
    if (data) {
      request.write(data);
    }
    request.end();
  });
}

function pepGet(path, identity) {
  log.debug("Entering pepGet().");
  log.debug("Leaving pepGet().");
  return pepRequest("GET", realmUrl(path),
                    identity === undefined ? trusted : identity);
}

function pepPost(path, payload, identity) {
  log.debug("Entering pepPost().");
  log.debug("Leaving pepPost().");
  return pepRequest("POST", realmUrl(path),
                    identity === undefined ? trusted : identity, payload || {});
}

// ---------------------------------------------------------------------------
// THE FOUR XACML ENDPOINTS PROPER, AS AN ADMITTED CALLER.
//
// These are `get()` and `postJson()` with a client certificate on the
// connection, and they exist because those two are `fetch` and node's fetch
// cannot present one. They default to `xacmlUser` — the identity holding the
// role these four require — so a call site reads as "ask this endpoint" and
// the credential is not repeated forty times; passing an identity explicitly
// is how the gate assertions in section 0 drive the same endpoints as somebody
// else, or as nobody.
// ---------------------------------------------------------------------------
function xGet(path, identity) {
  log.debug("Entering xGet().");
  log.debug("Leaving xGet().");
  return pepRequest("GET", path.indexOf("http") === 0 ? path : realmUrl(path),
                    identity === undefined ? xacmlUser : identity);
}

function xPost(path, payload, identity) {
  log.debug("Entering xPost().");
  log.debug("Leaving xPost().");
  return pepRequest("POST", path.indexOf("http") === 0 ? path : realmUrl(path),
                    identity === undefined ? xacmlUser : identity,
                    payload || {});
}

// A raw body, for the malformed requests in section 4 and the PIP's XML.
// `JSON.stringify` cannot produce them, which is the point.
function xPostRaw(path, raw, identity) {
  log.debug("Entering xPostRaw().");
  log.debug("Leaving xPostRaw().");
  return pepRequest("POST", path.indexOf("http") === 0 ? path : realmUrl(path),
                    identity === undefined ? xacmlUser : identity,
                    undefined, raw);
}

function selfSignedFor(commonName) {
  log.debug("Entering selfSignedFor(). cn=" + commonName);
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const certificate = forge.pki.createCertificate();
  certificate.publicKey = keys.publicKey;
  certificate.serialNumber = "01" + Date.now().toString(16);
  certificate.validity.notBefore = new Date(Date.now() - 60 * 1000);
  certificate.validity.notAfter = new Date(Date.now() + 24 * 3600 * 1000);
  const attributes = [{ name: "commonName", value: commonName },
                      { name: "organizationName", value: "mock-sts tests" }];
  certificate.setSubject(attributes);
  certificate.setIssuer(attributes);
  certificate.sign(keys.privateKey, forge.md.sha256.create());
  log.debug("Leaving selfSignedFor().");
  return { cert: forge.pki.certificateToPem(certificate),
           key: forge.pki.privateKeyToPem(keys.privateKey) };
}

function postWithCertificate(url, payload, identity) {
  log.debug("Entering postWithCertificate(). url=" + url);
  log.debug("Leaving postWithCertificate().");
  return new Promise(function (resolve, reject) {
    const target = new URL(url);
    const data = JSON.stringify(payload || {});
    const request = https.request({
      host: target.hostname,
      port: target.port || 443,
      path: target.pathname + target.search,
      method: "POST",
      // THE SERVER'S certificate is not the subject here and is regenerated on
      // every start; `tests/tools/trust.js` hands the run an anchor for it and
      // node uses it, but a hand-run without one must still reach the door.
      rejectUnauthorized: false,
      cert: identity.cert,
      key: identity.key,
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
          log.debug("Caught in a callback in postWithCertificate(): " +
                    ((e && e.message) || e));
          // As above: a non-JSON answer from a door that answers JSON is worth
          // reporting whole rather than as a parse failure.
          body = null;
        }
        log.debug("Leaving postWithCertificate(). status=" +
                  response.statusCode);
        resolve({ status: response.statusCode, body: body, text: text });
      });
    });
    request.on("error", reject);
    request.write(data);
    request.end();
  });
}

// ===========================================================================
// 1. THE SURFACE DESCRIBES ITSELF, AND THE DESCRIPTION IS READ OFF THE SERVICE.
//
// `GET /xacml` is the document a client meets first. The assertion is not that
// it renders: it is that the eight endpoints it advertises are the eight that
// answer, and that every count on it agrees with the endpoint that owns the
// number. A description that drifted from the surface it describes is the one
// defect a page like this can have.
// ===========================================================================
async function theSurfaceDescribesItself() {
  log.debug("Entering theSurfaceDescribesItself().");
  log.info("=== GET /xacml — what this surface says it is ===");

  const html = await xGet("/xacml");
  check("GET /xacml draws a page", function () {
    assert.strictEqual(html.status, 200,
      "GET /xacml answered " + html.status);
    assert.ok(/text\/html/.test(html.type),
      "GET /xacml should be HTML for a person; it is " + html.type);
    assert.ok(html.text.indexOf("Policy Decision Point") > 0,
      "the page should say what this service is; it says " +
      html.text.slice(0, 200));
  });

  const doc = await xGet("/xacml?format=json");
  check("?format=json answers the same document as JSON", function () {
    assert.strictEqual(doc.status, 200, "?format=json answered " + doc.status);
    assert.ok(doc.body && doc.body.enabled === true,
      "XACML should be on in a realm nobody has turned it off in; the " +
      "document says " + JSON.stringify(doc.body).slice(0, 200));
  });

  // THE EIGHT, ASKED FOR RATHER THAN COUNTED. Each is driven for real
  // elsewhere in this file; what is checked here is that the DOCUMENT names
  // exactly them, because a route added without a line here is invisible to
  // every client that reads this page.
  const advertised = (doc.body.endpoints || []).map(function (one) {
    return one.method + " " + one.path;
  }).sort();
  check("the document advertises exactly the eight endpoints", function () {
    assert.deepStrictEqual(advertised, [
      "GET /xacml",
      "GET /xacml/pep/policies",
      "GET /xacml/policies",
      "GET /xacml/protected",
      "POST /xacml/pdp",
      "POST /xacml/pep/heartbeat",
      "POST /xacml/pep/register",
      "POST /xacml/pip"
    ], "GET /xacml advertises " + JSON.stringify(advertised) + ". A route " +
       "added to xacml.js without a line in description() is a route no " +
       "client reading this page can find.");
  });

  // ---------------------------------------------------------------------
  // AND EVERY ROW SAYS WHICH ROLE IT WANTS. That column is the only place
  // the two-role split is machine-readable, and it is what stops a reader
  // having to infer a role from a path — which is exactly what `POST
  // /xacml/pip` would have them get wrong, since it sits outside
  // `/xacml/pep/` and wants `REMOTE_PEPS`.
  // ---------------------------------------------------------------------
  const requires = {};
  (doc.body.endpoints || []).forEach(function (one) {
    requires[one.method + " " + one.path] = one.requires;
  });
  check("every endpoint says which role it requires", function () {
    assert.deepStrictEqual(requires, {
      "GET /xacml": "XACML_USER",
      "POST /xacml/pdp": "XACML_USER",
      "GET /xacml/policies": "XACML_USER",
      "GET /xacml/protected": "XACML_USER",
      "POST /xacml/pep/register": "REMOTE_PEPS",
      "GET /xacml/pep/policies": "REMOTE_PEPS",
      "POST /xacml/pep/heartbeat": "REMOTE_PEPS",
      "POST /xacml/pip": "REMOTE_PEPS"
    }, "the Requires column is " + JSON.stringify(requires) + ". POST " +
       "/xacml/pip is the one row whose role does not follow its path, and " +
       "it is deliberate: what comes back is a person's directory " +
       "attributes rather than a rule anybody may check.");
  });

  check("and the page names the two groups that grant them", function () {
    assert.ok(doc.body.access && doc.body.access.enforced === true,
      "access enforcement should be ON in a realm nobody has turned it off " +
      "in; the document says " + JSON.stringify(doc.body.access));
    assert.notStrictEqual(doc.body.access.xacmlUserGroup,
                          doc.body.access.remotePepGroup,
      "THE TWO GROUPS MUST NOT BE THE SAME ONE. If they ever are, admitting " +
      "a caller to the demonstration surface silently admits it to the " +
      "endpoints publishing the documents this service enforces its own " +
      "access with. Both are \"" + doc.body.access.xacmlUserGroup + "\".");
  });

  // THE COUNTS AGREE WITH THE ENDPOINT THAT OWNS THEM. This is the check that
  // would catch a description reading its own cached idea of the repository.
  const policies = await xGet("/xacml/policies");
  check("the repository counts on /xacml agree with /xacml/policies",
        function () {
    assert.strictEqual(doc.body.repository.policies,
                       (policies.body.policies || []).length,
      "GET /xacml says " + doc.body.repository.policies + " policy(ies) and " +
      "GET /xacml/policies lists " + (policies.body.policies || []).length);
    assert.strictEqual(doc.body.repository.root, policies.body.root,
      "the two documents disagree about which policy is the root: " +
      doc.body.repository.root + " vs " + policies.body.root);
  });

  check("a brand new realm's repository is EMPTY", function () {
    assert.strictEqual((policies.body.policies || []).length, 0,
      "this realm was created seconds ago and its ou=policies holds " +
      JSON.stringify((policies.body.policies || []).map(function (one) {
        return one.name;
      })) + ". The seeded policy is written once, in the DEFAULT realm, at " +
      "require time — a realm that inherited it would mean every count in " +
      "this file is measuring somebody else's repository as well as its own.");
    assert.strictEqual(policies.body.root, null,
      "an empty repository has no root; this one names " + policies.body.root);
    assert.ok(String(policies.body.rootNote || "").indexOf("NotApplicable") > 0,
      "a repository with no root should SAY that every decision is " +
      "NotApplicable rather than leaving it to be discovered; it says " +
      policies.body.rootNote);
  });

  log.info("[surface] OK — the document names eight endpoints, each with the " +
           "role it wants, and its counts come from the repository rather " +
           "than from itself.");
  log.debug("Leaving theSurfaceDescribesItself().");
}

// ===========================================================================
// 2. AN EMPTY REPOSITORY, AND THE ONE CASE THE TWO PEP BIASES DISAGREE ABOUT.
//
// This section exists because it can only be run HERE. `NotApplicable` is what
// a PDP says when nothing applies, and the default realm always has a root
// policy — so the state where the two biases differ is unreachable there. XACML
// section 7.2's whole point is that deny-biased and permit-biased agree on
// every Permit and every Deny and differ on exactly this, which is the answer
// nobody writes a test for.
// ===========================================================================
async function anEmptyRepositoryDecidesNothing() {
  log.debug("Entering anEmptyRepositoryDecidesNothing().");
  log.info("=== An empty repository, and the bias that reads it ===");

  const answer = await decisionFor(ADMIN_PERSON, "GET");
  check("a PDP with no root policy answers NotApplicable", function () {
    assert.strictEqual(answer.Decision, "NotApplicable",
      "an empty repository has nothing to say about a request, which is " +
      "precisely NotApplicable. It answered " + answer.Decision);
    assert.strictEqual(answer.Status.StatusCode.Value,
                       "urn:oasis:names:tc:xacml:1.0:status:ok",
      "and it is not an ERROR — a repository with no policy in it is a " +
      "state, not a fault. The status is " +
      JSON.stringify(answer.Status));
  });

  const denied = await xGet("/xacml/protected?subject=" + ADMIN_PERSON +
                            "&action=GET");
  check("the deny-biased PEP refuses that with 403", function () {
    assert.strictEqual(denied.status, 403,
      "deny-biased means anything that is not Permit is a refusal; the " +
      "embedded PEP answered " + denied.status);
    assert.strictEqual(denied.body.decision, "NotApplicable",
      "and it should report the DECISION beside the enforcement, because " +
      "they are different facts; it reported " + denied.body.decision);
    assert.strictEqual(denied.body.allowed, false, "allowed should be false");
    assert.strictEqual(denied.body.bias, "deny-biased",
      "the bias it enforced with is " + denied.body.bias);
  });

  await setSetting("xacml.pepBias", "permit-biased");
  const allowed = await xGet("/xacml/protected?subject=" + ADMIN_PERSON +
                             "&action=GET");
  check("the SAME decision is allowed by a permit-biased PEP", function () {
    assert.strictEqual(allowed.status, 200,
      "permit-biased means anything that is not Deny is allowed; the PEP " +
      "answered " + allowed.status + " " + String(allowed.text).slice(0, 200));
    assert.strictEqual(allowed.body.decision, "NotApplicable",
      "THE PDP MUST NOT HAVE CHANGED ITS MIND. `xacml.pepBias` is the PEP's " +
      "decision and not the PDP's, so the decision either side of the flip " +
      "must be the same NotApplicable and only the enforcement differs. It " +
      "answered " + allowed.body.decision + ", which would mean the setting " +
      "reached the engine.");
    assert.strictEqual(allowed.body.allowed, true, "allowed should be true");
    assert.strictEqual(allowed.body.bias, "permit-biased",
      "the bias it enforced with is " + allowed.body.bias);
  });
  await resetSetting("xacml.pepBias");

  const back = await xGet("/xacml/protected?subject=" + ADMIN_PERSON +
                          "&action=GET");
  check("resetting the setting puts the refusal back", function () {
    assert.strictEqual(back.status, 403,
      "after /admin-api/config/reset the PEP should be deny-biased again; " +
      "it answered " + back.status);
  });

  log.info("[bias] OK — one decision, two enforcements, and the PDP said the " +
           "same thing both times.");
  log.debug("Leaving anEmptyRepositoryDecidesNothing().");
}

// ===========================================================================
// 3. A POLICY BUILT THROUGH THE CONSOLE'S API DECIDES AT /xacml/pdp.
//
// The template is the RBAC one: `employeeType=admin` may do anything,
// `employeeType=staff` may GET or HEAD, and the combining algorithm is
// deny-unless-permit so anything else is a Deny rather than a NotApplicable.
// The two people `createThePeople()` makes in this realm carry those attributes
// — ADMIN_PERSON is the admin, STAFF_PERSON is staff — which is what makes the
// decisions below predictable. (Until 2026-09-12 they were the seeded `carol`
// and `alice`, and this said the file wrote no directory entry.)
//
// THE ATTRIBUTE COMES FROM THE PIP AND NOT FROM THE REQUEST, which is the half
// worth stating: nothing below sends an `employeeType`, so a Permit here is the
// PDP having asked the embedded directory about the person the request names.
// ===========================================================================
async function aPolicyBuiltThroughTheApiDecides() {
  log.debug("Entering aPolicyBuiltThroughTheApiDecides().");
  log.info("=== A template built on /admin-api decides at /xacml/pdp ===");

  const built = await act("create-from-template", {
    template: "rbac", name: POLICY,
    p_roleAttribute: "employeeType",
    p_adminRoles: "admin",
    p_readerRoles: "staff",
    p_readerActions: "GET, HEAD"
  }, "created the policy");

  check("the first policy in an empty repository becomes the root",
        function () {
    assert.ok(String(built.what).indexOf("root") > 0,
      "a repository with a policy and no root decides nothing, so the first " +
      "one created should say it became the root. It said: " + built.what);
  });

  const listed = await xGet("/xacml/policies");
  check("GET /xacml/policies now lists it, with its document", function () {
    const rows = listed.body.policies || [];
    assert.strictEqual(rows.length, 1, "the repository should hold exactly " +
      "the one policy this file created; it holds " + rows.length);
    assert.strictEqual(rows[0].name, POLICY);
    assert.strictEqual(listed.body.root, POLICY,
      "and it should be the root; the root is " + listed.body.root);
    // THE DOCUMENT IS PRESENT ON PURPOSE and is a deliberate departure from
    // how /admin/ldap/* treats the directory. A policy is a rule, and a rule
    // nobody can read is a rule nobody can check.
    assert.ok(String(rows[0].document).indexOf("<Policy") >= 0,
      "the policy DOCUMENT should be in this answer; the row carries " +
      Object.keys(rows[0]).join(", "));
    assert.deepStrictEqual(rows[0].problems, [],
      "a policy built from a template should type-check; it reports " +
      JSON.stringify(rows[0].problems));
  });

  const cases = [
    { who: ADMIN_PERSON, action: "DELETE", decision: "Permit",
      why: ADMIN_PERSON + " is the admin, and an admin may do anything" },
    { who: ADMIN_PERSON, action: "GET", decision: "Permit",
      why: "an admin may GET as well" },
    { who: STAFF_PERSON, action: "GET", decision: "Permit",
      why: STAFF_PERSON + " is staff, and staff may GET" },
    { who: STAFF_PERSON, action: "DELETE", decision: "Deny",
      why: "staff may not DELETE, and deny-unless-permit denies rather than " +
           "answering NotApplicable" },
    { who: "nobody-at-all", action: "GET", decision: "Deny",
      why: "a person the directory has never heard of holds no employeeType, " +
           "so the PIP returns an EMPTY BAG and no rule matches" }
  ];
  for (const one of cases) {
    const answer = await decisionFor(one.who, one.action);
    check("POST /xacml/pdp: " + one.who + " " + one.action + " -> " +
          one.decision, function () {
      assert.strictEqual(answer.Decision, one.decision,
        one.who + " asking to " + one.action + " should be " + one.decision +
        " — " + one.why + ". The PDP said " + answer.Decision + " " +
        JSON.stringify(answer.Status));
    });
  }

  // A REQUEST WITH NO SUBJECT AT ALL. Not an error: a resource-only decision is
  // perfectly ordinary, and the PIP hands back an empty bag rather than
  // refusing to answer.
  const anonymous = await decisionFor(null, "GET");
  check("a request naming no subject is answered rather than refused",
        function () {
    assert.strictEqual(anonymous.Decision, "Deny",
      "a request with no subject-id gets an empty bag for every subject " +
      "attribute and no rule matches, so deny-unless-permit denies. It " +
      "answered " + anonymous.Decision);
    assert.strictEqual(anonymous.Status.StatusCode.Value,
                       "urn:oasis:names:tc:xacml:1.0:status:ok",
      "and it is not an error; the status is " +
      JSON.stringify(anonymous.Status));
  });

  log.info("[pdp] OK — five decisions, each resolved against an attribute " +
           "the request never carried.");
  log.debug("Leaving aPolicyBuiltThroughTheApiDecides().");
}

// ===========================================================================
// 4. A MALFORMED REQUEST IS A 400 AND NEVER AN INDETERMINATE.
//
// This is the distinction `xacml.js` argues at the endpoint and the one a PEP
// most needs: an Indeterminate is an answer ABOUT the request, and a 400 says
// there was no request to answer about. Collapsing them has a PEP enforce its
// bias over somebody's typo — under a permit-biased PEP, that is an allowance.
//
// All four are NEGATIVES, which is most of what this section is worth. A
// decision endpoint that answers good requests correctly looks finished.
// ===========================================================================
async function aMalformedRequestIsRefused() {
  log.debug("Entering aMalformedRequestIsRefused().");
  log.info("=== The four ways a request is not a request ===");

  const bad = [
    { what: "not JSON at all", body: "{ this is not json",
      says: "valid JSON" },
    { what: "JSON with no Request member", body: '{"nope":1}',
      says: "Request" },
    { what: "a Request that is not an object", body: '{"Request":"please"}',
      says: "Request" },
    { what: "an attribute with an unknown DataType",
      body: JSON.stringify({ Request: { AccessSubject: { Attribute: [
        { AttributeId: "x", Value: "y", DataType: "cheese" } ] } } }),
      says: "DataType" }
  ];
  for (const one of bad) {
    const r = await xPostRaw("/xacml/pdp", one.body);
    check("a request that is " + one.what + " is refused 400", function () {
      assert.strictEqual(r.status, 400,
        "a malformed request must be a 400 and never a decision: an " +
        "Indeterminate here would be enforced by the PEP's bias, which under " +
        "permit-bias is an ALLOWANCE for somebody's typo. It answered " +
        r.status + " " + String(r.text).slice(0, 300));
      assert.strictEqual(r.body.error, "invalid_request",
        "the refusal should be invalid_request; it is " +
        JSON.stringify(r.body).slice(0, 200));
      assert.ok(String(r.body.error_description).indexOf(one.says) >= 0,
        "and it should say what was wrong — the description should mention " +
        '"' + one.says + '". It says: ' + r.body.error_description);
    });
  }

  // AND THE ENDPOINT IS STILL ALIVE AFTERWARDS. Four refusals in a row is
  // exactly the shape that catches a handler which throws past its own error
  // path and leaves the route wedged.
  const after = await decisionFor(ADMIN_PERSON, "GET");
  check("the endpoint still decides after four refusals", function () {
    assert.strictEqual(after.Decision, "Permit",
      "after four malformed requests the endpoint answered " + after.Decision);
  });

  log.info("[refusals] OK — four shapes refused 400, each naming what was " +
           "wrong, and the endpoint still decides.");
  log.debug("Leaving aMalformedRequestIsRefused().");
}

// ===========================================================================
// 5. THE EMBEDDED PEP, AND THE PART OF SECTION 7.2 IMPLEMENTATIONS SKIP.
//
// An obligation is the half of a decision that says "yes, AND you must also do
// this". A PEP that allows the access while dropping the obligation has
// enforced half a policy and reported success — so an obligation this PEP
// cannot discharge turns a Permit into a REFUSAL.
//
// The pair below is what makes that assertable: the editor's `add-obligation`
// mints `urn:sts:xacml:obligation:1`, which this PEP has never heard of,
// and `edit-obligation` renames it to the one it knows. Same policy, same
// request, same Permit — and the enforcement flips, which is the only way to
// show that the refusal was about the OBLIGATION and not about the decision.
// ===========================================================================
async function anUndischargeableObligationRefuses() {
  log.debug("Entering anUndischargeableObligationRefuses().");
  log.info("=== The embedded PEP and an obligation it cannot discharge ===");

  const before = await xGet("/xacml/protected?subject=" + ADMIN_PERSON +
                            "&action=GET");
  check(ADMIN_PERSON + " is allowed before any obligation exists", function () {
    assert.strictEqual(before.status, 200,
      ADMIN_PERSON + " is the admin and the policy permits them; the PEP " +
                     "answered " +
      before.status + " " + String(before.text).slice(0, 200));
    assert.deepStrictEqual(before.body.obligations, [],
      "and the decision carries no obligations yet; it carries " +
      JSON.stringify(before.body.obligations));
  });

  await act("add-policy-obligation", { policy: POLICY, path: "", on: "Permit" },
            "added an obligation to the policy");

  const refused = await xGet("/xacml/protected?subject=" + ADMIN_PERSON +
                             "&action=GET");
  check("an undischargeable obligation turns the Permit into a refusal",
        function () {
    assert.strictEqual(refused.status, 403,
      "section 7.2: a PEP that cannot discharge an obligation must refuse. " +
      "It answered " + refused.status + " " +
      String(refused.text).slice(0, 300));
    assert.strictEqual(refused.body.decision, "Permit",
      "AND THE DECISION IS STILL PERMIT, which is the whole point — the PDP " +
      "permitted and the PEP refused, and reporting the refusal as a Deny " +
      "would hide which of the two said no. It reported " +
      refused.body.decision);
    assert.strictEqual(refused.body.allowed, false);
    assert.ok(String(refused.body.why).indexOf("obligation") > 0,
      "and the refusal should name the obligation as the cause; it says: " +
      refused.body.why);
    assert.deepStrictEqual(refused.body.obligations,
      [{ id: "urn:sts:xacml:obligation:1", discharged: false }],
      "the obligation should be reported UNDISCHARGED rather than omitted; " +
      "it reports " + JSON.stringify(refused.body.obligations));
  });

  // Find it in the tree rather than guessing its path: the editor's own view is
  // where a person would read it, and a hard-coded `obligations.0` would keep
  // passing if the tree stopped listing obligations at all.
  const tree = await get(api("/xacml/editor?policy=" + POLICY));
  const obligation = (tree.body.tree || []).filter(function (row) {
    return row.kind === "obligation";
  })[0];
  check("the editor's tree shows the obligation that was added", function () {
    assert.ok(obligation, "no obligation row in the editor tree: " +
      JSON.stringify((tree.body.tree || []).map(function (r) {
        return r.kind;
      })));
  });

  await act("edit-obligation",
            { policy: POLICY, path: obligation.path, id: DISCHARGEABLE,
              on: "Permit" },
            "renamed the obligation to the one this PEP knows");

  const discharged = await xGet("/xacml/protected?subject=" + ADMIN_PERSON +
                                "&action=GET");
  check("the one obligation this PEP knows IS discharged, and access returns",
        function () {
    assert.strictEqual(discharged.status, 200,
      "with the obligation renamed to " + DISCHARGEABLE + " the PEP can " +
      "discharge it and the Permit stands; it answered " + discharged.status +
      " " + String(discharged.text).slice(0, 300));
    assert.deepStrictEqual(discharged.body.obligations,
      [{ id: DISCHARGEABLE, discharged: true }],
      "and it should say so on the row rather than silently allowing; it " +
      "reports " + JSON.stringify(discharged.body.obligations));
  });

  // Put the policy back to what section 6 and 7 expect. The obligation was the
  // subject here; leaving it would make every later Permit carry one.
  await act("remove", { policy: POLICY, path: obligation.path },
            "removed the obligation again");
  const clean = await xGet("/xacml/protected?subject=" + ADMIN_PERSON +
                           "&action=GET");
  check("removing the obligation leaves an ordinary Permit", function () {
    assert.strictEqual(clean.status, 200);
    assert.deepStrictEqual(clean.body.obligations, [],
      "the obligation should be gone; the decision carries " +
      JSON.stringify(clean.body.obligations));
  });

  log.info("[obligations] OK — one Permit enforced three ways, and only the " +
           "obligation changed.");
  log.debug("Leaving anUndischargeableObligationRefuses().");
}

// ===========================================================================
// 6. WHAT A REMOTE PEP PULLS, AND THE THREE DIFFERENCES FROM WHAT A PERSON
//    READS.
//
// `GET /xacml/pep/policies` is for a MACHINE about to evaluate what it gets:
// disabled policies are left out, the static problem list is not there, and it
// carries a sync token and honours `?since=`. The last is what makes polling
// cheap enough to be the contract — and THE PULL IS THE CONTRACT is the claim
// the whole remote-PEP design rests on.
// ===========================================================================
async function aRemotePepPulls() {
  log.debug("Entering aRemotePepPulls().");
  log.info("=== What a remote PEP pulls ===");

  const first = await pepGet("/xacml/pep/policies");
  check("a pull answers the enabled policies with a sync token", function () {
    assert.strictEqual(first.status, 200, "the pull answered " + first.status);
    assert.ok(first.body.syncToken, "there is no syncToken on the answer: " +
      JSON.stringify(first.body).slice(0, 200));
    assert.strictEqual(first.etag, '"' + first.body.syncToken + '"',
      "the token should be in an ETag as well, so an ordinary HTTP cache or " +
      "a client library that already speaks conditional requests behaves " +
      "correctly knowing nothing about XACML. The ETag is " + first.etag);
    assert.strictEqual((first.body.policies || []).length, 1,
      "one enabled policy should come back; " +
      (first.body.policies || []).length + " did");
    assert.strictEqual(first.body.root, POLICY);
  });

  check("the pull carries the document and NOT the static problem list",
        function () {
    const row = first.body.policies[0];
    assert.ok(String(row.document).indexOf("<Policy") >= 0,
      "a PEP evaluates the document, so the document must be here");
    assert.strictEqual(row.problems, undefined,
      "the static problems are for a PERSON looking at /xacml/policies — a " +
      "PEP has its own validator and will refuse a bad document again. The " +
      "row carries " + Object.keys(row).join(", "));
  });

  const unchanged = await pepGet(
    "/xacml/pep/policies?since=" + encodeURIComponent(first.body.syncToken));
  check("?since= with the current token answers 304 and no body", function () {
    assert.strictEqual(unchanged.status, 304,
      "an unchanged repository must answer 304 rather than 200 with a flag — " +
      "this is the answer a PEP polling every few seconds gets almost every " +
      "time. It answered " + unchanged.status);
    assert.strictEqual(unchanged.text, "",
      "a 304 carries no body; this one carried " +
      String(unchanged.text).slice(0, 200));
    assert.strictEqual(unchanged.etag, '"' + first.body.syncToken + '"',
      "and it should still carry the ETag; it carried " + unchanged.etag);
  });

  const stale = await pepGet("/xacml/pep/policies?since=not-the-token");
  check("?since= with a token this repository never had answers 200",
        function () {
    assert.strictEqual(stale.status, 200,
      "a PEP holding a token from another repository, or from before a " +
      "restart, must be given the policies rather than a 304 it would read " +
      "as 'you are current'. It answered " + stale.status);
  });

  // A DISABLED POLICY IS LEFT OUT RATHER THAN SENT WITH A FLAG, because a PEP
  // that loaded one would enforce a policy this service does not. That is the
  // difference from /xacml/policies, which lists it — asserted here in both
  // directions in one breath.
  await act("disable", { name: POLICY }, "disabled the policy");
  const withoutIt = await pepGet("/xacml/pep/policies");
  const stillListed = await xGet("/xacml/policies");
  check("a disabled policy leaves the pull and stays on the repository page",
        function () {
    assert.strictEqual((withoutIt.body.policies || []).length, 0,
      "a disabled policy must not reach a PEP; the pull sent " +
      JSON.stringify((withoutIt.body.policies || []).map(function (one) {
        return one.name;
      })));
    assert.strictEqual(withoutIt.body.root, null,
      "and with the only policy disabled there is no root; the pull says " +
      withoutIt.body.root);
    assert.strictEqual((stillListed.body.policies || []).length, 1,
      "while /xacml/policies still lists it, because that answer is for " +
      "somebody looking at the repository. It listed " +
      (stillListed.body.policies || []).length);
    assert.strictEqual(stillListed.body.policies[0].enabled, false,
      "with enabled: false on the row");
  });

  check("the sync token moved when the repository changed", function () {
    assert.notStrictEqual(withoutIt.body.syncToken, first.body.syncToken,
      "the token is a digest of what would be SENT, so disabling the only " +
      "policy must move it. It is still " + withoutIt.body.syncToken);
  });

  await act("enable", { name: POLICY }, "enabled the policy again");
  const restored = await pepGet("/xacml/pep/policies");
  check("re-enabling it restores the token it had", function () {
    assert.strictEqual(restored.body.syncToken, first.body.syncToken,
      "the token is over the BYTES that would be sent, so a repository " +
      "returned to a previous state has its previous token — which is what " +
      "lets a PEP that missed both changes discover it never needed to pull. " +
      "It is " + restored.body.syncToken + " and was " + first.body.syncToken);
  });

  log.info("[pull] OK — 200, 304, a token that moves with the bytes, and a " +
           "disabled policy that reaches nobody.");
  log.debug("Leaving aRemotePepPulls().");
}

// ===========================================================================
// 7. REGISTERING, AND THE TWO PLACES A DEFECT WOULD BE A SECURITY BUG.
//
// Every door in this family asks for a credential since 2026-09-06, and
// registering asks a different question from the rest: not who the decision is
// about, but WHICH PEP IS THIS. What rests on the answer is a directory entry,
// a row on the console and an address this service will later dial.
//
// The two assertions that matter are the ones about NAMING. A PEP holding a
// certificate is named from the certificate and never from the body — on the
// registration and on the heartbeat alike — because otherwise anything that can
// complete a handshake could take over somebody else's row and file counters
// against it.
// ===========================================================================
async function registeringAPep() {
  log.debug("Entering registeringAPep().");
  log.info("=== Registering a remote PEP ===");

  // The shape `postWithCertificate()` below takes, which is not the shape
  // `mint()` returns — that one names its fields `certPem`/`keyPem` because it
  // is what `pep.js` and the launchers read. Converted once, here, rather than
  // teaching a helper two spellings.
  const identity = { cert: trusted.certPem, key: trusted.keyPem };

  // BEFORE ANY REGISTRATION IN THIS REALM, which is the only moment a caller is
  // past the access policy and absent from the register at once. A heartbeat
  // must not CREATE a row: one made here would carry no certificate subject, no
  // notify URL and no registration date, and would look on the console exactly
  // like a PEP somebody had deliberately admitted.
  const ghost = await pepPost("/xacml/pep/heartbeat", {});
  check("a heartbeat from an identity that never registered is refused 404",
        function () {
    assert.strictEqual(ghost.status, 404,
      "this certificate is trusted and its DN holds REMOTE_PEPS, so it is " +
      "past the gate — and it has not registered, so there is no row to beat " +
      "against. It answered " + ghost.status + " " +
      String(ghost.text).slice(0, 200));
    assert.ok(String(ghost.body.error_description).indexOf("register") > 0,
      "and it should name the registration endpoint; it says " +
      ghost.body.error_description);
  });

  // **THIS WAS A 401 FROM `xacml.pepRequireCertificate` UNTIL 2026-09-06 AND IS
  // NOW A 403 FROM THE ACCESS POLICY**, and the change is the feature rather
  // than a regression. These endpoints are gated by the same embedded PEP and
  // the same access-control document that decide the console and the
  // management API: a caller with no certificate resolves to no directory
  // entry, holds no REMOTE_PEPS role, and is refused BEFORE the certificate
  // requirement is ever consulted. The old refusal still exists behind this
  // one — turn `xacml.enforceAccess` off and it is what answers.
  const refused = await postJson(realmUrl("/xacml/pep/register"),
                                 { name: "no-certificate-here" });
  check("a registration with no client certificate is refused by POLICY",
        function () {
    assert.strictEqual(refused.status, 403,
      "the access policy should refuse a caller it cannot name; the door " +
      "answered " + refused.status + " " + String(refused.text).slice(0, 300));
    assert.strictEqual(refused.body.error, "access_denied");
    assert.ok(String(refused.body.error_description)
                .indexOf("REMOTE_PEPS") > 0,
      "the refusal should name the role the caller is missing; it says: " +
      refused.body.error_description);
    assert.ok(String(refused.body.error_description)
                .indexOf("roles.remotePepGroup") > 0,
      "AND THE SETTING THAT NAMES THE GROUP THAT GRANTS IT, because that is " +
      "the one thing an operator changes to fix this. It says: " +
      refused.body.error_description);
    assert.ok(String(refused.body.error_description)
                .indexOf("no client certificate") > 0,
      "and it should say WHICH of the three ways to fail this was — no " +
      "certificate, one that did not verify, or one that verified and holds " +
      "no role — because they need different fixes: " +
      refused.body.error_description);
  });

  // ---- THE CASE THE WHOLE CHAIN EXISTS FOR --------------------------------
  // A certificate this service VERIFIED, naming an identity it can resolve,
  // holding no role. It is the difference between authentication and
  // authorization made visible: nothing is wrong with this certificate.
  const rogueTried = await pepPost("/xacml/pep/register", {}, rogue);
  check("a VERIFIED certificate whose DN is in no group is refused too",
        function () {
    assert.strictEqual(rogueTried.status, 403,
      "this certificate chains to an anchor in the truststore and names " +
      ROGUE_CN + "; it is not a member of cn=remote-peps and must be " +
      "refused. The door answered " + rogueTried.status + " " +
      String(rogueTried.text).slice(0, 300));
    assert.ok(String(rogueTried.body.error_description)
                .indexOf("VERIFIED") > 0,
      "AND THE REFUSAL MUST SAY THE CERTIFICATE WAS FINE. Somebody debugging " +
      "this needs to know the handshake is not the problem — otherwise they " +
      "regenerate a certificate that was never wrong. It says: " +
      rogueTried.body.error_description);
    assert.ok(String(rogueTried.body.error_description)
                .indexOf("cn=" + ROGUE_CN.toLowerCase()) > 0,
      "and it should name the entry the certificate resolved to, which is " +
      "what somebody adds to the group: " + rogueTried.body.error_description);
  });

  const rogueRead = await pepGet("/xacml/pep/policies", rogue);
  check("and it cannot pull the repository either", function () {
    assert.strictEqual(rogueRead.status, 403,
      "the pull is gated by the same policy as the registration; it answered " +
      rogueRead.status);
  });

  const registered = await postWithCertificate(
    realmUrl("/xacml/pep/register"),
    // THE BODY CLAIMS TO BE SOMEBODY ELSE. That is the test.
    { name: "somebody-elses-pep", notifyUrl: "https://127.0.0.1:9/notify",
      bias: "deny-biased", version: "test", resource: "https://example.test/" },
    identity);
  check("a registration with a certificate is named from the CERTIFICATE",
        function () {
    assert.strictEqual(registered.status, 201,
      "a first registration is a 201; it answered " + registered.status + " " +
      String(registered.text).slice(0, 300));
    assert.strictEqual(registered.body.name, PEP_CN,
      "THE NAME MUST COME FROM THE COMMON NAME OF THE CERTIFICATE AND NEVER " +
      "FROM THE BODY. This registration presented a certificate for " +
      PEP_CN + " and asked to be called \"somebody-elses-pep\"; it was " +
      "registered as \"" + registered.body.name + "\". A PEP that could name " +
      "itself while holding a certificate could take over another PEP's row, " +
      "which is the one thing in this family that would be a security bug " +
      "rather than a fidelity one.");
    assert.strictEqual(registered.body.authenticated, true,
      "and the row should record that something was proved");
    assert.ok(String(registered.body.identity).indexOf(PEP_CN) >= 0,
      "the identity should be the certificate's DN; it is " +
      registered.body.identity);
  });

  check("the registration answers the contract rather than implying it",
        function () {
    assert.ok(String(registered.body.note).indexOf("PULL IS THE CONTRACT") > 0,
      "the answer should say that polling is the mechanism and the nudge an " +
      "optimisation; it says: " + String(registered.body.note).slice(0, 200));
    assert.ok(registered.body.policiesUrl &&
              registered.body.policiesUrl.indexOf("/realm/" + REALM) > 0,
      "and it should hand back the URLs IN THE REALM it was registered in, " +
      "because a PEP given the default realm's would poll somebody else's " +
      "repository for ever. It handed back " + registered.body.policiesUrl);
    assert.strictEqual(registered.body.notify.usable, true,
      "an https notify URL is usable; the answer says " +
      JSON.stringify(registered.body.notify));
  });

  const again = await postWithCertificate(realmUrl("/xacml/pep/register"),
                                          { notifyUrl: "http://127.0.0.1:9/n" },
                                          identity);
  check("re-registering is a 200 and says so", function () {
    assert.strictEqual(again.status, 200,
      "a re-registration is not a creation; it answered " + again.status);
    assert.strictEqual(again.body.created, false);
  });
  check("a plain http notify URL is reported unusable, with the reason",
        function () {
    assert.strictEqual(again.body.notify.usable, false,
      "xacml.pepNotifyAllowInsecure is off, so an http notify URL cannot be " +
      "dialled. The answer says " + JSON.stringify(again.body.notify));
    assert.ok(String(again.body.notify.why).indexOf(
        "pepNotifyAllowInsecure") > 0,
      "AND IT IS SAID BACK IMMEDIATELY rather than discovered the first time " +
      "a nudge is not delivered — a PEP whose notify URL this service will " +
      "never dial should find out while somebody is still looking at the " +
      "deployment. It says: " + again.body.notify.why);
  });

  // Put the usable URL back: section 8 saves a policy with this PEP registered
  // and asserts that the save does not wait on the nudge.
  await postWithCertificate(realmUrl("/xacml/pep/register"),
                            { notifyUrl: "https://127.0.0.1:9/notify" },
                            identity);

  // ---- TWO ASSERTIONS THE GATE MADE UNREACHABLE, AND WHAT REPLACED THEM ----
  //
  // This file used to check that a NAMELESS heartbeat is refused 400 and that a
  // heartbeat naming something UNREGISTERED is refused 404. Both were made with
  // no client certificate, and both are now unreachable through the front door:
  // the access policy refuses a caller it cannot name before either branch is
  // reached, and a caller it CAN name is one whose name came from a
  // certificate — so there is no such thing as a nameless heartbeat that got
  // this far.
  //
  // **THOSE BRANCHES STILL EXIST AND ARE STILL RIGHT**; they are simply behind
  // a door now. `xacml.enforceAccess=false` reaches them, and section 9 already
  // drives the off-switches. What is asserted here instead is the refusal that
  // replaced them, and the ONE case that survived intact: a heartbeat from an
  // identity the register has never heard of must not create a row — checked
  // below with the trusted certificate BEFORE it registers, which is the only
  // moment in this file when a caller is past the gate and off the register at
  // the same time.
  const namelessNoCert = await postJson(realmUrl("/xacml/pep/heartbeat"), {});
  check("a heartbeat with no certificate is refused by POLICY, not by the " +
        "name check", function () {
    assert.strictEqual(namelessNoCert.status, 403,
      "the access policy answers first now; the door said " +
      namelessNoCert.status + " " + String(namelessNoCert.text).slice(0, 200));
    assert.strictEqual(namelessNoCert.body.error, "access_denied");
  });

  const misfiled = await postWithCertificate(realmUrl("/xacml/pep/heartbeat"),
    { name: "somebody-elses-pep", syncToken: "a-stale-token", decisions: 7,
      allowed: 4, refused: 3 }, identity);
  check("a heartbeat with a certificate files against the CERTIFICATE's row",
        function () {
    assert.strictEqual(misfiled.status, 200,
      "the heartbeat answered " + misfiled.status + " " +
      String(misfiled.text).slice(0, 200));
    assert.strictEqual(misfiled.body.name, PEP_CN,
      "the same rule as the registration and for the same reason: a PEP " +
      "holding a certificate must not be able to file its counters against " +
      "somebody else's row. This one claimed to be \"somebody-elses-pep\" " +
      "and was filed as \"" + misfiled.body.name + "\".");
  });
  check("and it is TOLD it is behind rather than left to compare", function () {
    assert.strictEqual(misfiled.body.current, false,
      "the token it reported is not the repository's, so it is behind; the " +
      "answer says current=" + misfiled.body.current);
    assert.ok(String(misfiled.body.action).indexOf("pull") >= 0,
      "and it should be told what to do about it: " + misfiled.body.action);
  });

  const current = await pepGet("/xacml/pep/policies");
  const uptodate = await postWithCertificate(realmUrl("/xacml/pep/heartbeat"),
    { syncToken: current.body.syncToken, policyCount: 1 }, identity);
  check("a heartbeat holding the current token is told it is current",
        function () {
    assert.strictEqual(uptodate.body.current, true,
      "this PEP holds the repository's own token and was told current=" +
      uptodate.body.current);
    assert.ok(String(uptodate.body.action).indexOf("nothing") >= 0,
      "and the action should be nothing: " + uptodate.body.action);
  });

  // THE COUNTERS REACHED THE CONSOLE. A remote PEP's enforcement happened in
  // another process and this service saw none of it — the heartbeat is the only
  // way it is visible here at all, which makes the read-back the point rather
  // than a formality.
  const console_ = await get(api("/xacml/peps"));
  const row = (console_.body.peps || []).filter(function (one) {
    return one.name === PEP_CN;
  })[0];
  check("the PEP's counters are on /admin-api/xacml/peps", function () {
    assert.ok(row, "the register holds " +
      JSON.stringify((console_.body.peps || []).map(function (one) {
        return one.name;
      })));
    assert.strictEqual(row.decisions, 7,
      "the decisions it reported should be on its row; the row says " +
      row.decisions);
    assert.strictEqual(row.allowed, 4);
    assert.strictEqual(row.refused, 3);
    assert.strictEqual(row.authenticated, true,
      "and the row should record that it registered over mutual TLS");
  });

  // ---------------------------------------------------------------------------
  // THE ONE THAT WOULD HAVE BEEN A SECURITY-SHAPED MISTAKE THE OTHER WAY ROUND:
  // a PEP an administrator disabled must not be able to re-enable itself by
  // reconnecting.
  // ---------------------------------------------------------------------------
  await act("disable-pep", { name: PEP_CN }, "disabled the PEP");
  const afterDisable = await postWithCertificate(
      realmUrl("/xacml/pep/register"),
                                                 {}, identity);
  const rows = await get(api("/xacml/peps"));
  const still = (rows.body.peps || []).filter(function (one) {
    return one.name === PEP_CN;
  })[0];
  check("a disabled PEP cannot re-enable itself by re-registering",
        function () {
    assert.strictEqual(afterDisable.status, 200,
      "the re-registration itself is accepted; it answered " +
      afterDisable.status);
    assert.strictEqual(still.enabled, false,
      "BUT THE ROW MUST STAY DISABLED. An administrator disabled this PEP on " +
      "the console; a component that could undo that by reconnecting would " +
      "make the control on that page meaningless. The row says enabled=" +
      still.enabled);
  });

  // ---------------------------------------------------------------------------
  // WHAT A RE-REGISTRATION KEEPS AND WHAT IT TAKES FROM THE BODY, which is one
  // split rather than two behaviours and is easy to get backwards in either
  // direction. The registration above carried an EMPTY body:
  //
  //   * the COUNTERS and the registration date survive it, because a PEP that
  //     restarted has not un-enforced anything and a date that reset on every
  //     restart could never show a component restarting every few minutes;
  //   * the NOTIFY URL does not, because it is the PEP's own address — this is
  //     how one that moved says so, and how one that no longer wants to be
  //     nudged stops being. A URL that survived a registration omitting it
  //     could only be cleared by an administrator.
  // ---------------------------------------------------------------------------
  check("a re-registration keeps the counters and takes the address afresh",
        function () {
    assert.strictEqual(still.decisions, 7,
      "the counters this PEP reported before it re-registered should still " +
      "be on its row; it says decisions=" + still.decisions);
    assert.strictEqual(still.notifyUrl, "",
      "and the notify URL should have gone with the registration that did " +
      "not carry one; the row says " + JSON.stringify(still.notifyUrl));
    assert.ok(String(still.registeredAt || "").length > 0,
      "while the original registration date survives; the row says " +
      JSON.stringify(still.registeredAt));
  });

  await act("enable-pep", { name: PEP_CN }, "enabled the PEP again");
  // AND THE ADDRESS BACK, because section 8 asserts what happens when the
  // repository changes with an unreachable PEP registered.
  await postWithCertificate(realmUrl("/xacml/pep/register"),
                            { notifyUrl: "https://127.0.0.1:9/notify" },
                            identity);

  log.info("[register] OK — the certificate names the PEP on both doors, and " +
           "a disabled one stays disabled.");
  log.debug("Leaving registeringAPep().");
}

// ===========================================================================
// 8. A POLICY SAVE DOES NOT WAIT ON A PEP THAT IS NOT THERE.
//
// The registered PEP's notify URL points at a port nothing is listening on.
// When the repository changes, this service tries to nudge it — and NOTHING
// WAITS ON THAT: the promise is deliberately not awaited, because the console
// form that saved a policy has finished its work whether or not four PEPs
// answered. A save that blocked on somebody else's web server would be the
// mistake `saml/CLAUDE.md` records about not dialling a service provider's
// metadata URL while issuing.
//
// The assertion is a clock, which is unusual here and is the only way to make
// it: the save must return in far less than the nudge's own timeout.
// ===========================================================================
// The PEP's row once the nudge dispatcher has recorded an outcome on it, or the
// row as it stands after the wait — so the assertion reports what was actually
// there rather than a timeout.
async function waitForNotifyRecord() {
  log.debug("Entering waitForNotifyRecord().");
  let row = null;
  for (let i = 0; i < 60; i += 1) {
    const rows = await get(api("/xacml/peps"));
    row = ((rows.body || {}).peps || []).filter(function (one) {
      return one.name === PEP_CN;
    })[0] || null;
    if (row && String(row.lastNotify || "").length > 0) {
      log.debug("Leaving waitForNotifyRecord(). Recorded after " + i +
                " poll(s).");
      return row;
    }
    await new Promise(function (resolve) { setTimeout(resolve, 100); });
  }
  log.debug("Leaving waitForNotifyRecord(). Nothing was recorded.");
  return row;
}

async function aSaveDoesNotWaitOnTheNudge() {
  log.debug("Entering aSaveDoesNotWaitOnTheNudge().");
  log.info("=== A policy save with an unreachable PEP registered ===");

  // The nudge's own timeout, read off the page that owns it rather than
  // written down here: a deployment that raised it would otherwise make this
  // section's budget meaningless without anything saying so.
  const register = await get(api("/xacml/peps"));
  const notifyTimeout = ((register.body || {}).notify || {}).timeoutMs;
  const budget = 4000;
  const started = Date.now();
  await act("disable", { name: POLICY }, "disabled the policy");
  await act("enable", { name: POLICY }, "enabled it again");
  const took = Date.now() - started;

  check("two repository changes return promptly with a dead PEP registered",
        function () {
    assert.ok(took < budget,
      "two policy writes took " + took + "ms with a PEP registered whose " +
      "notify URL is a port nothing answers on. The nudge is dispatched and " +
      "never awaited, so this should be milliseconds — a number near the " +
      "notify timeout means a save is now waiting on somebody else's web " +
      "server. (xacml.pepNotifyTimeoutMs is " + notifyTimeout + ".)");
  });

  // POLLED, AND THE POLL IS THE OTHER HALF OF THE ASSERTION ABOVE. The record
  // of what a PEP answered cannot be there when the save returns — if it were,
  // the save had waited for it. So this waits for the dispatcher to finish
  // failing, which it does as fast as a refused connection to a closed port.
  const row = await waitForNotifyRecord();
  check("the failed nudge is recorded on the PEP's own row", function () {
    assert.ok(row, "the PEP should still be registered");
    assert.ok(String(row.lastNotify || "").length > 0,
      "what each PEP answered — or did not — is recorded on its row and read " +
      "on /admin/xacml/peps, because nothing was waiting to be told. The row " +
      "says lastNotify=" + JSON.stringify(row.lastNotify));
  });

  const pulled = await pepGet("/xacml/pep/policies");
  check("and the PEP converges by PULLING, nudge or no nudge", function () {
    assert.strictEqual(pulled.status, 200);
    assert.strictEqual((pulled.body.policies || []).length, 1,
      "the policy is enabled again and a pull returns it, which is the whole " +
      "contract: a PEP that is never successfully nudged still converges. " +
      "The pull returned " + (pulled.body.policies || []).length);
  });

  log.info("[nudge] OK — the save did not wait, the failure is on the row, " +
           "and the pull is unaffected.");
  log.debug("Leaving aSaveDoesNotWaitOnTheNudge().");
}

// ===========================================================================
// 9. TURNING IT OFF, IN TWO SENTENCES THAT ARE NOT THE SAME SENTENCE.
//
// `xacml.enabled` off means XACML is off here. `xacml.remotePeps` off means
// XACML is on and remote enforcement points are not. A caller told the first
// when the second is true goes looking in the wrong place — which is why there
// are two checks in `xacml.js` rather than one with a parameter.
//
// Both answer 501 and never 404: the routes stay REGISTERED, because the
// feature being off and the URL being wrong are different sentences to a
// client. And both are set IN THIS REALM, which is also the assertion that the
// default realm goes on answering — a job that turned XACML off process-wide
// would quietly disarm every later job in the run.
// ===========================================================================
async function turningItOff() {
  log.debug("Entering turningItOff().");
  log.info("=== xacml.enabled and xacml.remotePeps, off ===");

  await setSetting("xacml.remotePeps", false);
  // FOUR, NOT THREE: `POST /xacml/pip` is behind this switch too, because the
  // only caller it exists for is a remote PEP and a switch that took remote
  // enforcement points away while leaving an endpoint handing out a named
  // person's directory attributes would not be doing what its description
  // says.
  const pepOff = [
    ["GET", "/xacml/pep/policies"],
    ["POST", "/xacml/pep/register"],
    ["POST", "/xacml/pep/heartbeat"],
    ["POST", "/xacml/pip"]
  ];
  for (const [method, path] of pepOff) {
    // WITH THE CERTIFICATE, because these four are gated and a 403 would be
    // read here as a 501 that never happened. The OFF CHECK RUNS FIRST in the
    // handler, so an unadmitted caller would in fact still see the 501 — but
    // asserting that by accident is asserting the wrong thing, and it would
    // stop being true the moment the two checks were ordered the other way.
    const r = method === "GET" ? await pepGet(path)
                               : await pepPost(path, {});
    check("remotePeps off: " + method + " " + path + " answers 501",
          function () {
      assert.strictEqual(r.status, 501,
        method + " " + path + " answered " + r.status + " with remote PEPs " +
        "off. It must be 501 and not 404: the route is registered and the " +
        "feature is off, which is a different sentence from a wrong URL.");
      assert.ok(String(r.body.error_description).indexOf(
          "xacml.remotePeps") > 0,
        "and the 501 should name the setting AND say that the register is " +
        "untouched; it says: " + r.body.error_description);
    });
  }
  const stillDeciding = await decisionFor(ADMIN_PERSON, "GET");
  check("remotePeps off leaves the PDP deciding", function () {
    assert.strictEqual(stillDeciding.Decision, "Permit",
      "turning remote enforcement points off must not turn the decision " +
      "endpoint off; it answered " + stillDeciding.Decision);
  });
  await resetSetting("xacml.remotePeps");

  await setSetting("xacml.enabled", false);
  const allOff = [
    ["POST", "/xacml/pdp"], ["GET", "/xacml/policies"],
    ["GET", "/xacml/protected"], ["GET", "/xacml/pep/policies"],
    ["POST", "/xacml/pep/register"], ["POST", "/xacml/pep/heartbeat"],
    ["POST", "/xacml/pip"]
  ];
  for (const [method, path] of allOff) {
    // EACH WITH THE IDENTITY ITS OWN GATE WANTS — two roles, so two
    // credentials, and a job that used one for all seven would be asserting a
    // 501 that a 403 could have been mistaken for.
    // `/xacml/pip` takes the PEP's identity even though it is not under
    // /xacml/pep/ — the one endpoint whose role does not follow its path.
    const identity = (path.indexOf("/xacml/pep/") === 0 ||
                      path === "/xacml/pip") ? trusted : xacmlUser;
    const r = method === "GET" ? await xGet(path, identity)
                               : await xPost(path, {}, identity);
    check("xacml off: " + method + " " + path + " answers 501", function () {
      assert.strictEqual(r.status, 501,
        method + " " + path + " answered " + r.status + " with XACML off");
      assert.ok(String(r.body.error_description).indexOf("xacml.enabled") > 0,
        "the 501 should name xacml.enabled; it says: " +
        r.body.error_description);
    });
  }

  // THE ONE THAT MAKES THE REALM WORTH USING. Every setting above is
  // process-wide when set at the top level.
  const elsewhere = await xGet(base + "/xacml/policies");
  check("the default realm goes on answering while this one is off",
        function () {
    assert.strictEqual(elsewhere.status, 200,
      "xacml.enabled was set INSIDE " + REALM + ", so every other realm — " +
      "and every later job in this run — must be untouched. The default " +
      "realm's repository answered " + elsewhere.status);
    assert.ok((elsewhere.body.policies || []).length >= 1,
      "and it should still hold its own seeded policy");
  });

  await resetSetting("xacml.enabled");
  const back = await xGet("/xacml/policies");
  check("turning it back on decides against the same policies", function () {
    assert.strictEqual(back.status, 200, "it answered " + back.status);
    assert.strictEqual((back.body.policies || []).length, 1,
      "the repository in ou=policies is untouched by the setting, so the " +
      "policy is still here; the repository holds " +
      (back.body.policies || []).length);
    assert.strictEqual(back.body.root, POLICY);
  });

  log.info("[off] OK — two settings, two sentences, 501 both times, and the " +
           "default realm untouched.");
  log.debug("Leaving turningItOff().");
}

// ===========================================================================
// 10. THE REPOSITORY IS THIS REALM'S OWN.
//
// `ou=policies` is per realm, so the policy this file wrote must be invisible
// from the default realm and the seeded one invisible from here. It is one
// assertion and it is worth having explicitly: the store's readers take the
// realm from an AsyncLocalStorage, and a store declared `new Map()` rather than
// `realms.map()` would pass every other check in this file and pool every
// realm's policies into one repository.
// ===========================================================================
async function theRepositoryIsPerRealm() {
  log.debug("Entering theRepositoryIsPerRealm().");
  log.info("=== ou=policies is this realm's own ===");

  const here = await xGet("/xacml/policies");
  const there = await xGet(base + "/xacml/policies");
  const hereNames = (here.body.policies || []).map(function (one) {
    return one.name;
  });
  const thereNames = (there.body.policies || []).map(function (one) {
    return one.name;
  });

  check("this realm's policy is not in the default realm's repository",
        function () {
    assert.ok(hereNames.indexOf(POLICY) >= 0,
      "the policy should be here; this realm holds " +
      JSON.stringify(hereNames));
    assert.ok(thereNames.indexOf(POLICY) < 0,
      "and it must NOT be in the default realm; that repository holds " +
      JSON.stringify(thereNames));
  });

  check("and the default realm's seeded policy is not in this one",
        function () {
    assert.ok(thereNames.indexOf("seeded-rbac") >= 0,
      "the default realm should still hold its seeded policy; it holds " +
      JSON.stringify(thereNames));
    assert.ok(hereNames.indexOf("seeded-rbac") < 0,
      "and this realm must not have inherited it; it holds " +
      JSON.stringify(hereNames));
  });

  const registers = await get(base + "/admin-api/xacml/peps");
  check("the PEP register is per realm too", function () {
    const there_ = (registers.body.peps || []).map(function (one) {
      return one.name;
    });
    assert.ok(there_.indexOf(PEP_CN) < 0,
      "the PEP registered in " + REALM + " must not appear in the default " +
      "realm's register, which holds " + JSON.stringify(there_));
  });

  log.info("[realm] OK — two repositories, two registers, nothing shared.");
  log.debug("Leaving theRepositoryIsPerRealm().");
}

// ---------------------------------------------------------------------------
// THE REALM, AND WHY IT IS LEFT STANDING (2026-09-06).
//
// This file used to remove it here and assert the removal. **A realm a test
// run created stays now, because it is what a person reads when the run went
// red**: its ou=policies, its ou=peps, its directory subtree and its
// configuration overrides are the whole record of what these sections did,
// and a teardown that took them destroyed the evidence at exactly the moment
// it was worth something.
//
// The old argument for removing it was that a realm left behind with
// `xacml.enabled: false` on it must not be met by a later run of this same
// file. That is answered by the ID rather than by the teardown: it carries
// `names.runStamp()`, so a second run mints a second realm. Nothing here is
// process-wide except the truststore anchor, which is posted once and shared
// on purpose.
// ---------------------------------------------------------------------------
async function createTheRealm() {
  log.debug("Entering createTheRealm().");
  const r = await fetchJson(base + "/admin-api/realms/create", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      id: REALM,
      domain: REALM + ".example.net",
      name: "XACML endpoint test realm",
      description: "Created by tests/vendored/sts_xacml_endpoints.js; LEFT " +
                   "IN PLACE on purpose, so that a failed run can be read " +
                   "afterwards. Remove it by hand when you are done with it."
    })
  });
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "creating the throwaway realm " + REALM + " answered " + r.status + " " +
    String(r.text).slice(0, 300) + ". Every assertion in this file is made " +
    "inside it, so this is a failure and not something to work around.");
  log.info("Created the throwaway realm " + REALM + ".");
  log.debug("Leaving createTheRealm().");
}

async function createThePeople() {
  log.debug("Entering createThePeople().");
  for (const one of [[ADMIN_PERSON, "admin", "Admin"],
                     [STAFF_PERSON, "staff", "Staff"]]) {
    const r = await postJson(api("/users/create"), {
      username: one[0], invent: false,
      attributes: { cn: "XACML " + one[2] + " Person", givenName: "XACML",
                    sn: one[2] + " Person", displayName: "XACML " + one[2],
                    mail: one[0] + "@xacml-endpoints.test",
                    employeeType: one[1] }
    });
    assert.ok(r.status === 200 && r.body && r.body.ok,
      "POST /admin-api/users/create should put " + one[0] + " (employeeType=" +
      one[1] + ") in " + REALM + "'s directory; it answered " + r.status + " " +
      String(r.text).slice(0, 300));
  }
  log.info("Created " + ADMIN_PERSON + " (admin) and " + STAFF_PERSON +
           " (staff) in " + REALM + ".");
  log.debug("Leaving createThePeople().");
}

async function theRealmIsLeftBehind() {
  log.debug("Entering theRealmIsLeftBehind().");
  // IT IS STILL READ BACK, and that is the half of the old teardown worth
  // keeping: a job that thinks it has been writing into a realm the registry
  // has never heard of has been writing somewhere else, and the last thing it
  // does should be to say which. The check is now "it is there", where it used
  // to be "it is gone".
  const left = await fetchJson(base + "/admin-api/realms");
  const found = ((left.body && left.body.realms) || []).filter(function (one) {
    return one.id === REALM;
  });
  assert.strictEqual(found.length, 1,
    "the realm " + REALM + " should still be in the registry at the end of " +
    "the run — this file no longer removes it, and every assertion above was " +
    "made inside it. The registry holds " +
    JSON.stringify(((left.body && left.body.realms) || []).map(function (one) {
      return one.id;
    })));
  log.info("The throwaway realm " + REALM + " is LEFT IN PLACE on purpose — " +
           "its ou=policies, its ou=peps and its overrides are the record of " +
           "this run. Read them at " + base + "/realm/" + REALM + "/admin, " +
           "or remove the realm by hand when you are done with it.");
  log.debug("Leaving theRealmIsLeftBehind().");
}

// ===========================================================================
// 0. THE GATE, AND THE TWO ROLES THAT ARE NOT ONE ROLE (2026-09-06).
//
// **THIS SECTION IS AN INVERTED MATRIX AND THAT IS THE WHOLE VALUE OF IT.**
// Every one of these eight endpoints is behind the same four-link chain — a
// certificate this service VERIFIED, a DN resolved to a directory entry, the
// roles that entry holds, a policy decision — and they split on the LAST link
// into two roles granted by two groups.
//
// A single "the gate refuses an anonymous caller" assertion would pass against
// a service that had collapsed the two roles into one, which is the change
// somebody tidying up will make. So each identity is driven against BOTH sets:
//
//                        the four proper     /xacml/pep/* and /xacml/pip
//   nobody                    403                      403
//   a rogue, verified         403                      403
//   XACML_USER                200                      403   ← the interesting one
//   REMOTE_PEPS               403   ← and this one     200
//
// The two diagonal cells are the ones no other assertion in this file can
// produce, and they are what "two groups" MEANS. If either ever goes green in
// the wrong direction, admitting a caller to a demonstration policy has
// silently admitted it to the documents this service decides its own
// admissions with, or to somebody's directory attributes.
//
// **THE ROGUE IS FULLY AUTHENTICATED AND STILL REFUSED**, which is the third
// thing worth pinning: its certificate verifies, its DN resolves, and it holds
// neither role — so the refusal says the certificate was fine, because
// somebody debugging it otherwise regenerates a certificate that was never
// wrong.
// ===========================================================================
async function theGateSplitsOnTheRole() {
  log.debug("Entering theGateSplitsOnTheRole().");
  log.info("=== The gate: two roles, two groups, four callers ===");

  const proper = [["GET", "/xacml"], ["POST", "/xacml/pdp"],
                  ["GET", "/xacml/policies"], ["GET", "/xacml/protected"]];
  const pepSide = [["POST", "/xacml/pep/register"],
                   ["GET", "/xacml/pep/policies"],
                   ["POST", "/xacml/pep/heartbeat"],
                   ["POST", "/xacml/pip"]];

  async function drive(method, path, identity) {
    log.debug("Entering drive().");
    log.debug("Leaving drive().");
    return method === "GET" ? await xGet(path, identity)
                            : await xPost(path, {}, identity);
  }

  for (const [method, path] of proper.concat(pepSide)) {
    const anonymous = await drive(method, path, null);
    check("no certificate: " + method + " " + path + " is refused",
          function () {
      assert.strictEqual(anonymous.status, 403,
        method + " " + path + " answered " + anonymous.status + " to a " +
        "caller presenting nothing. Every endpoint in this family asks now.");
      assert.ok(String(anonymous.body && anonymous.body.error_description)
                  .indexOf("client certificate") > 0,
        "and the refusal should say what to present; it says " +
        JSON.stringify(anonymous.body).slice(0, 300));
    });

    const stranger = await drive(method, path, rogue);
    check("a VERIFIED certificate in neither group: " + method + " " + path +
          " is refused", function () {
      assert.strictEqual(stranger.status, 403,
        method + " " + path + " answered " + stranger.status + " to " +
        ROGUE_CN + ". The certificate says WHO and the group says WHETHER; " +
        "this one is fully authenticated and in no group.");
      assert.ok(String(stranger.body && stranger.body.error_description)
                  .indexOf("VERIFIED") > 0,
        "and the refusal must say the certificate was FINE, or somebody " +
        "debugging it regenerates a certificate that was never wrong. It " +
        "says " + JSON.stringify(stranger.body).slice(0, 300));
    });
  }

  // THE TWO DIAGONALS. Everything above this point would pass against a
  // service holding one role for all eight endpoints.
  for (const [method, path] of proper) {
    const wrongRole = await drive(method, path, trusted);
    check("REMOTE_PEPS does NOT open " + method + " " + path, function () {
      assert.strictEqual(wrongRole.status, 403,
        method + " " + path + " answered " + wrongRole.status + " to the " +
        "identity holding REMOTE_PEPS. These four want XACML_USER, and a " +
        "service where one role opened both sets would pass every other " +
        "assertion in this file.");
      assert.ok(String(wrongRole.body && wrongRole.body.error_description)
                  .indexOf("XACML_USER") > 0,
        "and the refusal should name the role it wanted; it says " +
        JSON.stringify(wrongRole.body).slice(0, 300));
    });
  }
  for (const [method, path] of pepSide) {
    const wrongRole = await drive(method, path, xacmlUser);
    check("XACML_USER does NOT open " + method + " " + path, function () {
      assert.strictEqual(wrongRole.status, 403,
        method + " " + path + " answered " + wrongRole.status + " to the " +
        "identity holding XACML_USER. These four want REMOTE_PEPS: three of " +
        "them publish the documents this service enforces its own access " +
        "with, and /xacml/pip publishes a named person's directory " +
        "attributes.");
      assert.ok(String(wrongRole.body && wrongRole.body.error_description)
                  .indexOf("REMOTE_PEPS") > 0,
        "and the refusal should name the role it wanted; it says " +
        JSON.stringify(wrongRole.body).slice(0, 300));
    });
  }

  // AND THE ONE WAY PAST IT, asserted because a gate with no documented way
  // out is a gate somebody will work around with a worse one. It is reset
  // immediately: everything after this section is driven WITH credentials, so
  // leaving it off would quietly make the rest of this file assert nothing
  // about the gate at all.
  await setSetting("xacml.enforceAccess", false);
  const open = await drive("GET", "/xacml", null);
  check("xacml.enforceAccess off opens it to a caller presenting nothing",
        function () {
    assert.strictEqual(open.status, 200,
      "with enforcement off, GET /xacml answered " + open.status +
      " to an anonymous caller. That setting is the documented way past this " +
      "layer and a deployment that has turned it off has said so.");
  });
  await resetSetting("xacml.enforceAccess");
  const shutAgain = await drive("GET", "/xacml", null);
  check("and resetting it closes the door again", function () {
    assert.strictEqual(shutAgain.status, 403,
      "GET /xacml answered " + shutAgain.status + " after the setting was " +
      "reset. A test that left this open would silently un-gate every " +
      "section below it.");
  });

  log.info("[gate] OK — four callers against eight endpoints, and the two " +
           "diagonals that show the roles are not one role.");
  log.debug("Leaving theGateSplitsOnTheRole().");
}

// ===========================================================================
// THE PIP OVER HTTP, WHICH IS THE ONE ENDPOINT HERE THAT SPEAKS XACML XML BOTH
// WAYS (2026-09-06).
//
// A remote PEP holds the engine and NOT the directory, so a designator the
// request did not carry resolves to an empty bag out there and to a real value
// in here. `POST /xacml/pip` closes that, and the property that makes it worth
// having is not "it returns some values" — it is that **what comes back is a
// REQUEST FRAGMENT**, so a PEP splices it into its own request and its engine
// finds the values where a designator looks for them, with no translation.
//
// So this section asserts the SHAPE as hard as the content: the `<Attributes>`
// are in the XACML core namespace, an unresolved designator is an ABSENT
// `<Attribute>` rather than an empty one, and the diagnostics are in a
// namespace of this service's own so that a PEP reading only OASIS's never
// meets them.
// ===========================================================================
function pipQuery(subject, designators) {
  log.debug("Entering pipQuery().");
  const dz = designators.map(function (one) {
    return '  <AttributeDesignator xmlns="' + XACML_NS + '" Category="' +
           (one.category || SUBJECT_CATEGORY) + '" AttributeId="' + one.id +
           '" DataType="' + (one.type ||
             "http://www.w3.org/2001/XMLSchema#string") +
           '" MustBePresent="false"/>';
  }).join("\n");
  const subjectBlock = subject === null ? "" :
    '    <Attributes Category="' + SUBJECT_CATEGORY + '">\n' +
    '      <Attribute AttributeId="urn:oasis:names:tc:xacml:1.0:subject:' +
    'subject-id" IncludeInResult="true">\n' +
    '        <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#' +
    'string">' + subject + '</AttributeValue>\n' +
    '      </Attribute>\n    </Attributes>\n';
  log.debug("Leaving pipQuery().");
  return '<?xml version="1.0" encoding="UTF-8"?>\n' +
         '<PIPRequest xmlns="urn:sts:xacml:pip:1.0">\n' +
         '  <Request xmlns="' + XACML_NS + '" CombinedDecision="false" ' +
         'ReturnPolicyIdList="false">\n' + subjectBlock + '  </Request>\n' +
         dz + '\n</PIPRequest>\n';
}

async function thePipAnswersInXacmlsOwnXml() {
  log.debug("Entering thePipAnswersInXacmlsOwnXml().");
  log.info("=== POST /xacml/pip — the PIP, in XACML's own XML ===");

  const answered = await xPostRaw("/xacml/pip", pipQuery(ADMIN_PERSON, [
    { id: "mail" }, { id: "employeeType" },
    { id: "urn:sts:xacml:attribute:sn" },
    { id: "noSuchAttributeAnywhere" },
    { id: "mail",
      category: "urn:oasis:names:tc:xacml:3.0:attribute-category:resource" }
  ]), trusted);

  check("it answers XML and not JSON", function () {
    assert.strictEqual(answered.status, 200,
      "POST /xacml/pip answered " + answered.status + " " +
      String(answered.text).slice(0, 300));
    assert.ok(/xml/.test(answered.type),
      "XACML defines no PIP protocol, so this endpoint speaks XACML's own " +
      "XML rather than a vocabulary of this service's own. It answered " +
      answered.type);
    assert.ok(answered.text.indexOf("<PIPResponse") >= 0,
      "the document should be a <PIPResponse>; it is " +
      answered.text.slice(0, 200));
  });

  check("THE PAYLOAD IS A REQUEST FRAGMENT, in XACML's namespace", function () {
    assert.ok(answered.text.indexOf('<Attributes xmlns="' + XACML_NS +
                                    '"') > 0,
      "the <Attributes> must be in the XACML CORE namespace, because the " +
      "whole design is that a PEP splices them into its own <Request> and " +
      "evaluates. The document is " + answered.text.slice(0, 600));
    assert.ok(answered.text.indexOf('Category="' + SUBJECT_CATEGORY + '"') > 0,
      "and carry the category the designator named");
    assert.ok(answered.text.indexOf('IncludeInResult="false"') > 0,
      "IncludeInResult must be written FALSE explicitly: a PEP splicing this " +
      "into a request it then echoes must not start reporting this " +
      "service's directory contents back to its own callers");
  });

  check("it resolves both spellings of a directory attribute", function () {
    assert.ok(answered.text.indexOf('AttributeId="mail"') > 0 &&
              answered.text.indexOf("@") > 0,
      ADMIN_PERSON + "'s mail should come back with a value; the document is " +
      answered.text.slice(0, 800));
    assert.ok(answered.text.indexOf(
      'AttributeId="urn:sts:xacml:attribute:sn"') > 0,
      "and the urn:sts:xacml:attribute: form should resolve too — a PEP " +
      "asserting only one of the two spellings is the defect " +
      "xacml-pep/CLAUDE.md records having cost a run");
  });

  check("AN UNRESOLVED DESIGNATOR IS AN ABSENT <Attribute>, not an empty one",
        function () {
    assert.ok(answered.text.indexOf(
      'AttributeId="noSuchAttributeAnywhere" IncludeInResult') < 0,
      "an attribute the directory does not hold must not appear in the " +
      "<Attributes> at all. The schema requires at least one " +
      "<AttributeValue> inside an <Attribute>, so an empty one is not a " +
      "legal request fragment — and a PEP that receives NOTHING behaves " +
      "exactly as the embedded PDP does when the PIP answers nothing, with " +
      "no branch of its own. The document is " +
      answered.text.slice(0, 800));
  });

  check("and the reason is in this service's OWN namespace, out of the way",
        function () {
    assert.ok(answered.text.indexOf("<Unresolved>") > 0,
      "the five reasons a bag can be empty are useless to a PDP and " +
      "essential to a person, so they come back named rather than in a log " +
      "the caller cannot read");
    assert.ok(answered.text.indexOf("does not hold") > 0,
      "the entry-does-not-hold-it reason should be distinguished from the " +
      "others; the document says " + answered.text.slice(-800));
    assert.ok(answered.text.indexOf("Only the access-subject category") > 0,
      "and a resource designator should say THAT rather than looking like a " +
      "missing attribute");
  });

  const noDesignators = await xPostRaw("/xacml/pip",
    '<?xml version="1.0" encoding="UTF-8"?>\n' +
    '<PIPRequest xmlns="urn:sts:xacml:pip:1.0">\n  <Request xmlns="' +
    XACML_NS + '"/>\n</PIPRequest>\n', trusted);
  check("a query naming no designator is a 400 and never an empty answer",
        function () {
    assert.strictEqual(noDesignators.status, 400,
      "it answered " + noDesignators.status + ". An unresolved designator is " +
      "a legitimate ANSWER here, so a malformed query that came back as one " +
      "would be indistinguishable from the attribute being absent — and the " +
      "caller's PDP would go on to decide on it.");
    assert.ok(noDesignators.text.indexOf("<PIPError") >= 0,
      "and the refusal should be XML too, since nothing else on this " +
      "endpoint is JSON; it answered " + noDesignators.text.slice(0, 200));
  });

  const notXml = await xPostRaw("/xacml/pip", "{\"Designator\":[]}", trusted);
  check("and so is a body that is not a PIPRequest at all", function () {
    assert.strictEqual(notXml.status, 400,
      "a JSON body answered " + notXml.status + ". This endpoint took JSON " +
      "in its first draft, and an old client sending it must be refused " +
      "rather than quietly answered nothing.");
  });

  // ---------------------------------------------------------------------
  // WHAT A CALLER MAY CHOOSE THE SIZE OF, AND THE ANSWER IS NOTHING.
  //
  // The XML readers are held to 454 of 455 OASIS conformance cases, so what a
  // designator IS is not re-checked at this door — but a conformance suite has
  // no opinion about an AttributeId a megabyte long, and **three of these
  // scalars come back out again**: an unresolved designator is echoed into
  // <Unresolved>, every one is named in this service's audit log, and the
  // subject is handed to the directory's locateEntry(), which walks the tree
  // comparing it against every DN.
  //
  // **THE RATE LIMIT IS DELIBERATELY NOT DRIVEN HERE.** Its buckets are per
  // PROCESS and not per realm, so a job that drove one to its ceiling would
  // leave the next job in the run meeting 429s that are nothing to do with it
  // — which this suite has been bitten by before. It is asserted in process by
  // `tests/portal_access.js`, where the bucket can be cleared afterwards.
  // ---------------------------------------------------------------------
  const oversizedId = await xPostRaw("/xacml/pip",
    pipQuery(ADMIN_PERSON, [{ id: "a".repeat(400) }]), trusted);
  check("an AttributeId longer than an identifier is refused", function () {
    assert.strictEqual(oversizedId.status, 400,
      "it answered " + oversizedId.status + ". That string is echoed into " +
      "<Unresolved> and written into this service's audit log, so its " +
      "length is not the caller's to choose.");
    assert.ok(oversizedId.text.indexOf("<PIPError") >= 0,
      "and the refusal is XML like everything else on this endpoint");
  });

  const controlChar = await xPostRaw("/xacml/pip",
    pipQuery(ADMIN_PERSON, [{ id: "ma\u0007il" }]), trusted);
  check("and so is one carrying a control character", function () {
    assert.strictEqual(controlChar.status, 400,
      "it answered " + controlChar.status + ". A BEL in an AttributeId ends " +
      "up in an XML attribute value in the reply and in a log line, and " +
      "xmlEscape() has nothing to say about C0 — it handles < > & and quotes.");
  });

  const longSubject = await xPostRaw("/xacml/pip",
    pipQuery("x".repeat(300), [{ id: "mail" }]), trusted);
  check("a subject-id longer than a name is refused before the directory " +
        "sees it", function () {
    assert.strictEqual(longSubject.status, 400,
      "it answered " + longSubject.status + ". This is the one scalar that " +
      "goes somewhere other than a log: locateEntry() walks the tree " +
      "comparing it against every DN, every uid and every certificate " +
      "subject, and this is the only door that takes it from a stranger.");
  });

  // A BODY OVER THE CEILING. `validation.parseXml()`'s CAP.LARGE is a MEGABYTE
  // and app.js's body parser stops at five, so without the tighter cap a
  // caller chooses how much of this process's memory one request costs.
  const huge = '<?xml version="1.0"?><PIPRequest xmlns="urn:sts:xacml:' +
               'pip:1.0"><Request/><!--' + "z".repeat(1100000) +
               '--></PIPRequest>';
  const oversizedBody = await xPostRaw("/xacml/pip", huge, trusted);
  check("and a body over the megabyte ceiling never reaches the parser",
        function () {
    assert.strictEqual(oversizedBody.status, 400,
      "it answered " + oversizedBody.status + ". The engine's own " +
      "parseDocument() has NO size ceiling — it is the right reader for a " +
      "policy and the wrong one for a body a stranger POSTs.");
  });

  // ENTITY EXPANSION, ASSERTED RATHER THAN ASSUMED. @xmldom/xmldom resolves no
  // entity declared in a DTD, so a billion-laughs document is refused as not
  // well-formed rather than expanded — and this check is what stops that
  // becoming an assumption the day the parser is swapped.
  let entities = '<!ENTITY lol "aaaaaaaaaa">';
  let prev = "lol";
  for (let i = 1; i <= 6; i += 1) {
    entities += '<!ENTITY lol' + i + ' "' + ('&' + prev + ';').repeat(10) +
                '">';
    prev = "lol" + i;
  }
  const bomb = '<?xml version="1.0"?><!DOCTYPE PIPRequest [' + entities +
               ']><PIPRequest xmlns="urn:sts:xacml:pip:1.0"><Request/>' +
               '<x>&' + prev + ';</x></PIPRequest>';
  const started = Date.now();
  const laughs = await xPostRaw("/xacml/pip", bomb, trusted);
  check("a billion-laughs document is refused rather than expanded",
        function () {
    assert.strictEqual(laughs.status, 400,
      "it answered " + laughs.status + ". This parser resolves no entity " +
      "declared in a DTD — internal or external — so the document is not " +
      "well-formed rather than being a bomb. Asserting it is what stops that " +
      "becoming an assumption the day the parser is swapped.");
    assert.ok(Date.now() - started < 2000,
      "and it does it immediately; it took " + (Date.now() - started) + "ms");
  });

  log.info("[pip] OK — XML both ways, a request fragment a PEP can splice, " +
           "an absent <Attribute> for every empty bag, and nothing about the " +
           "query whose size the caller chooses.");
  log.debug("Leaving thePipAnswersInXacmlsOwnXml().");
}

// ---------------------------------------------------------------------------
// THE RUN.
// ---------------------------------------------------------------------------
async function test() {
  log.debug("Entering test().");
  log.info("Driving the mock STS's XACML endpoints at " + base + "/xacml");

  // A SERVICE THAT IS NOT THERE IS A FAILURE AND NOT A SKIP, which is the rule
  // tests/CLAUDE.md records the 2026-08-28 default flip for: a job that reports
  // green having driven nothing is worse than one that is honestly absent.
  const status = await fetchJson(base + "/admin-api/status");
  assert.strictEqual(status.status, 200,
    "GET /admin-api/status answered " + status.status + " at " + base +
    ". This job needs the mock and nothing else.");

  // THE CREDENTIALS BEFORE THE REALM, because the truststore is process-wide
  // while the realm is not: posting the anchor once covers every realm this
  // file works in, and doing it first means the register section cannot be the
  // place a certificate problem is first noticed.
  await mintTheCredentials();
  await createTheRealm();
  try {
    await createThePeople();
    await theGateSplitsOnTheRole();
    await theSurfaceDescribesItself();
    await anEmptyRepositoryDecidesNothing();
    await aPolicyBuiltThroughTheApiDecides();
    await aMalformedRequestIsRefused();
    await anUndischargeableObligationRefuses();
    await aRemotePepPulls();
    await registeringAPep();
    await aSaveDoesNotWaitOnTheNudge();
    await thePipAnswersInXacmlsOwnXml();
    await turningItOff();
    await theRepositoryIsPerRealm();
  } finally {
    await theRealmIsLeftBehind();
  }

  // A FLOOR ON THE COUNT, for the reason sts_admin_console.js gives: a section
  // that stops being called takes its assertions with it and the run still says
  // "passed", which is the one failure mode a suite cannot report about itself.
  assert.ok(checks >= 90,
    "only " + checks + " checks ran. This file makes well over a hundred " +
    "against " +
    "a healthy service, so a count this low means a SECTION STOPPED BEING " +
    "CALLED rather than that the surface got simpler.");
  log.info(checks + " checks passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_xacml_endpoints")
  .description("Drive the mock STS's eight /xacml endpoints over HTTP in a " +
      "throwaway trust realm: the decision endpoint and its refusals, the " +
      "repository, the embedded PEP's bias and its obligation rule, and the " +
      "three a remote PEP registers, pulls and reports on.")
  .addOption(new Option("-u, --url <url>", "base url of the STS under test")
      .default(base))
  .parse(process.argv);
base = String(program.opts().url || base).replace(/\/+$/, "");

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
