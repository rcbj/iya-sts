// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_xacml_pep_embedded.js
//
// ===========================================================================
// AN EMBEDDED REMOTE PEP, OVER THE WIRE (#2026, work item 3 of #1206).
//
// `tests/xacml_pep_embedded.js` holds the rules in process. This job drives
// them as the `iya-pep` package does — RFC 7523 self-assertion through
// `sts-remote-pep`, DPoP-bound, one token per audience — against the
// running service, in a realm of its own:
//
//   R. REGISTER: bound to nothing (403, STS-XACML-0338 on the audit log),
//      bound to another application (403, 0339), an unsupported protocol
//      version (400, 0340), mode with a container (400, 0341); then the
//      package's body accepted, and `/admin-api/xacml/peps` carrying kind,
//      application, mode and protocol version;
//   H. HEARTBEAT: `policyEvents` stored and on the row; the binding moved,
//      the next heartbeat refused (403, 0339);
//   Z. AUTHZEN, central MODE: the bound PEP, in no AuthZEN group, asks
//      `POST /access/v1/evaluation` about its application (200) and about
//      another (403, STS-AUTHZEN-0025); the batch the same.
//
// OWNED HERE (local: true): the PEP control plane and /admin-api are ours.
// ===========================================================================

const assert = require("assert");
const K = require("./oauth_wire_kit.js").kit("sts_xacml_pep_embedded");
const credentials = require("../tools/pep-credential.js");

const log = K.log;
const check = K.check;

let realm = null;
const PEP = "pep-embd-" + K.STAMP.slice(-8).toLowerCase();
const APP_A = "embd-app-a-" + K.STAMP.slice(-8).toLowerCase();
const APP_B = "embd-app-b-" + K.STAMP.slice(-8).toLowerCase();
const VERSION = "iya-pep-rust/0.1.0";
let key = null;
const tokens = {};

function api(path) {
  log.debug("Entering api().");
  log.debug("Leaving api().");
  return K.rb(realm) + "/admin-api" + path;
}

// A request on one of the PEP's tokens, DPoP-bound to its key.
async function asPep(scope, method, path, body) {
  log.debug("Entering asPep(). " + method + " " + path);
  const url = K.rb(realm) + path;
  const headers = credentials.dpopHeaders(key.privateKeyPem, method,
                                          url.split("?")[0], tokens[scope]);
  const r = await K.send(url, body === undefined
    ? { method: method, headers: headers }
    : { method: method, headers: headers, json: body });
  log.debug("Leaving asPep(). " + r.status);
  return r;
}

function embedded(extra) {
  log.debug("Entering embedded().");
  log.debug("Leaving embedded().");
  return Object.assign({ name: PEP, kind: "embedded", application: APP_A,
    mode: "central", protocolVersion: 1, version: VERSION }, extra || {});
}

async function row() {
  log.debug("Entering row().");
  const r = await K.send(api("/xacml/peps?pep=" + encodeURIComponent(PEP)));
  assert.strictEqual(r.status, 200, K.shown(r));
  log.debug("Leaving row().");
  return ((r.json && r.json.peps) || []).filter(function (one) {
    return one.name === PEP;
  })[0] || null;
}

function bindTo(application) {
  log.debug("Entering bindTo(). " + application);
  log.debug("Leaving bindTo().");
  return K.ok(api("/xacml/set-pep-application"),
              { name: PEP, application: application },
              "bound " + PEP + " to " + application);
}

async function setUp() {
  log.debug("Entering setUp().");
  realm = await K.realm("pepembd", "development");
  await K.app(realm, APP_A, {});
  await K.app(realm, APP_B, {});
  // THE PEP'S ACCOUNT: a person put in `remote-peps`, which makes it a
  // service account (#1760), with its own key certified from its request.
  await K.ok(api("/users/create"), { username: PEP, invent: false,
    attributes: { cn: PEP, sn: "Embedded PEP", givenName: "Embedded",
                  mail: PEP + "@pep-embedded.test" } },
    "created " + PEP);
  await K.ok(api("/groups/add-member"),
             { group: "remote-peps", member: PEP },
             "put " + PEP + " in remote-peps");
  key = await credentials.assertionRequest({ keyAlg: "ec-p256", name: PEP });
  await credentials.issueAssertionCredential({
    post: async function (url, payload) {
      log.debug("Entering post().");
      const r = await K.send(url, { json: payload });
      log.debug("Leaving post().");
      return { status: r.status, body: r.json, text: r.text };
    }
  }, K.base, "/realm/" + realm, PEP, key.csrPem);
  const audiences = { "xacml:pep": "/xacml/pep",
                      "authzen:evaluate": "/access/v1" };
  for (const scope of Object.keys(audiences)) {
    const got = await credentials.pepAccessToken(K.rb(realm), PEP,
      key.privateKeyPem, scope, audiences[scope]);
    assert.ok(got.status === 200 && got.token, "the PEP's " + scope +
              " token answered " + got.status + " " +
              String(got.text).slice(0, 300));
    tokens[scope] = got.token;
  }
  log.debug("Leaving setUp().");
}

async function registration() {
  log.debug("Entering registration().");
  log.info("=== R. register ===");
  const unbound = await K.coded(realm, "STS-XACML-0338", function () {
    return asPep("xacml:pep", "POST", "/xacml/pep/register", embedded());
  });
  check("R1. embedded with the entry bound to nothing is refused 403 " +
        "STS-XACML-0338", function () {
    assert.strictEqual(unbound.answer.status, 403, K.shown(unbound.answer));
    assert.strictEqual(unbound.answer.json.error, "access_denied");
    assert.ok(unbound.rose >= 1, String(unbound.rose));
  });
  await bindTo(APP_B);
  const elsewhere = await K.coded(realm, "STS-XACML-0339", function () {
    return asPep("xacml:pep", "POST", "/xacml/pep/register", embedded());
  });
  check("R2. embedded naming an application other than its binding is " +
        "refused 403 STS-XACML-0339", function () {
    assert.strictEqual(elsewhere.answer.status, 403,
                       K.shown(elsewhere.answer));
    assert.ok(elsewhere.rose >= 1, String(elsewhere.rose));
  });
  await bindTo(APP_A);
  const version = await K.coded(realm, "STS-XACML-0340", function () {
    return asPep("xacml:pep", "POST", "/xacml/pep/register",
                 embedded({ protocolVersion: 99 }));
  });
  check("R3. an unsupported protocolVersion is refused 400 STS-XACML-0340",
        function () {
    assert.strictEqual(version.answer.status, 400, K.shown(version.answer));
    assert.strictEqual(version.answer.json.error, "invalid_request");
    assert.ok(version.rose >= 1, String(version.rose));
  });
  const mode = await K.coded(realm, "STS-XACML-0341", function () {
    return asPep("xacml:pep", "POST", "/xacml/pep/register",
                 { name: PEP, kind: "container", mode: "local" });
  });
  check("R4. mode with a container is refused 400 STS-XACML-0341",
        function () {
    assert.strictEqual(mode.answer.status, 400, K.shown(mode.answer));
    assert.ok(mode.rose >= 1, String(mode.rose));
  });
  const before = await row();
  const good = await asPep("xacml:pep", "POST", "/xacml/pep/register",
                           embedded());
  const after = await row();
  check("R5. nothing refused left a row; the package's registration is " +
        "accepted, and /admin-api/xacml/peps says embedded in its " +
        "application, central, protocol 1", function () {
    assert.strictEqual(before, null, JSON.stringify(before));
    assert.ok(good.status === 201 || good.status === 200, K.shown(good));
    assert.ok(after, "no row for " + PEP);
    assert.strictEqual(after.kind, "embedded");
    assert.strictEqual(after.application, APP_A);
    assert.strictEqual(after.registeredApplication, APP_A);
    assert.strictEqual(after.mode, "central");
    assert.strictEqual(after.protocolVersion, 1);
    assert.strictEqual(after.version, VERSION);
  });
  log.debug("Leaving registration().");
}

async function heartbeat() {
  log.debug("Entering heartbeat().");
  log.info("=== H. heartbeat ===");
  const beat = await asPep("xacml:pep", "POST", "/xacml/pep/heartbeat",
    embedded({ decisions: 2, allowed: 1, refused: 1, undischargeable: 0,
               policyEvents: "excluded" }));
  const held = await row();
  check("H1. a heartbeat's policyEvents is on the row", function () {
    assert.strictEqual(beat.status, 200, K.shown(beat));
    assert.strictEqual(typeof beat.json.current, "boolean");
    assert.strictEqual(held.policyEvents, "excluded");
  });
  await bindTo(APP_B);
  const moved = await K.coded(realm, "STS-XACML-0339", function () {
    return asPep("xacml:pep", "POST", "/xacml/pep/heartbeat", embedded());
  });
  check("H2. once the binding moves, the next heartbeat is refused 403 " +
        "STS-XACML-0339", function () {
    assert.strictEqual(moved.answer.status, 403, K.shown(moved.answer));
    assert.ok(moved.rose >= 1, String(moved.rose));
  });
  await bindTo(APP_A);
  log.debug("Leaving heartbeat().");
}

function question(application) {
  log.debug("Entering question().");
  log.debug("Leaving question().");
  return { subject: { type: "user", id: "someone-" + K.rand(6) },
           action: { name: "read" },
           resource: { type: "document", id: "d1" },
           context: { application: application } };
}

async function authzen() {
  log.debug("Entering authzen().");
  log.info("=== Z. AuthZEN, central mode ===");
  const own = await asPep("authzen:evaluate", "POST",
                          "/access/v1/evaluation", question(APP_A));
  check("Z1. the bound PEP, in no AuthZEN group, is admitted for its own " +
        "application", function () {
    assert.strictEqual(own.status, 200, K.shown(own));
    assert.strictEqual(typeof own.json.decision, "boolean", K.shown(own));
  });
  const other = await K.coded(realm, "STS-AUTHZEN-0025", function () {
    return asPep("authzen:evaluate", "POST", "/access/v1/evaluation",
                 question(APP_B));
  });
  check("Z2. another application is refused 403 STS-AUTHZEN-0025",
        function () {
    assert.strictEqual(other.answer.status, 403, K.shown(other.answer));
    assert.ok(other.rose >= 1, String(other.rose));
  });
  const batch = await asPep("authzen:evaluate", "POST",
    "/access/v1/evaluations", Object.assign(question(APP_A), {
      evaluations: [{ action: { name: "read" } },
                    { action: { name: "write" } }] }));
  const batchOther = await asPep("authzen:evaluate", "POST",
    "/access/v1/evaluations", Object.assign(question(APP_B), {
      evaluations: [{ action: { name: "read" } }] }));
  check("Z3. the batch is admitted for its own application and refused " +
        "for another", function () {
    assert.strictEqual(batch.status, 200, K.shown(batch));
    assert.ok(Array.isArray(batch.json.evaluations), K.shown(batch));
    // A batch answers 200 with each item's own refusal (AuthZEN 1.0).
    const item = (batchOther.json.evaluations || [])[0] || {};
    assert.strictEqual(batchOther.status, 200, K.shown(batchOther));
    assert.strictEqual(item.decision, false, K.shown(batchOther));
    assert.strictEqual(((item.context || {}).error || {}).status, 403,
                       K.shown(batchOther));
  });
  log.debug("Leaving authzen().");
}

async function test() {
  log.debug("Entering test().");
  await setUp();
  await registration();
  await heartbeat();
  await authzen();
  log.debug("Leaving test().");
}

K.main(test, 10);
