// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_xacml_pep_binding.js
//
// ===========================================================================
// AN EMBEDDED REMOTE PEP'S APPLICATION, OVER THE WIRE (#2025, part of #1206).
//
// `tests/xacml_pep_binding.js` holds `xacml/xacml_pep_binding.ts` in
// process. This job drives the same rules through the management API the
// console calls — `POST /admin-api/xacml/set-pep-application`,
// `clear-pep-application`, `issue-pep-credential` with an `application`,
// and `GET /admin-api/applications?application=` — in a realm of its own,
// so an AWS target and the product mode cover them too:
//
//   B. BIND: a service account in `remote-peps` bound to an application,
//      the application's page listing it under `embeddedPeps`; the same
//      binding again changes nothing; a second application replaces the
//      first, which no longer lists it;
//   R. THE REFUSALS, each a 400 with `errors` and its code on the audit
//      log: no name and nobody by that name (STS-XACML-0334), a person
//      outside `remote-peps` (STS-XACML-0335), an application the registry
//      does not hold (STS-XACML-0336) — and none of them changed the binding;
//   I. ISSUE: `issue-pep-credential` with an `application` certifies the
//      PEP's own key and binds it in the one call; with an application the
//      registry does not hold it is refused before anything is certified;
//   D. DELETE: deleting the application a PEP is bound to clears the
//      binding (`noteApplicationRemoved()`), so nothing names an
//      application that is gone;
//   C. CLEAR: the binding removed and the application listing nobody; a
//      second clear is not a failure;
// and throughout, every change is an `xacml.pep.binding` audit row while an
// unchanged bind or an empty clear writes none (B2, D1, C1, C2).
//
// What it does not do: register the PEP or pull its policies (the
// registration is #2026's, and `sts_xacml_remote_pep.js` drives the
// container), or draw the console (`sts_admin_console.js` walks the page).
//
// OWNED HERE (local: true): the binding and the API are ours.
// ===========================================================================

const assert = require("assert");
const K = require("./oauth_wire_kit.js").kit("sts_xacml_pep_binding");
const credentials = require("../tools/pep-credential.js");

const log = K.log;
const check = K.check;

let realm = null;
const PEP = "pep-emb-" + K.STAMP.slice(-8).toLowerCase();
const PERSON = "pep-person-" + K.STAMP.slice(-8).toLowerCase();
const APP_A = "pep-app-a-" + K.STAMP.slice(-8).toLowerCase();
const APP_B = "pep-app-b-" + K.STAMP.slice(-8).toLowerCase();
const APP_GONE = "pep-app-gone-" + K.STAMP.slice(-8).toLowerCase();

function api(path) {
  log.debug("Entering api().");
  log.debug("Leaving api().");
  return K.rb(realm) + "/admin-api" + path;
}

function act(action, body) {
  log.debug("Entering act(). " + action);
  log.debug("Leaving act().");
  return K.send(api("/xacml/" + action), { json: body || {} });
}

function refused(r) {
  log.debug("Entering refused().");
  log.debug("Leaving refused().");
  return r.status === 400 && r.json && r.json.ok === false &&
    Array.isArray(r.json.errors) && r.json.errors.length > 0;
}

// The PEPs an application's page lists as embedded in it.
async function embedded(application) {
  log.debug("Entering embedded(). " + application);
  const r = await K.send(api("/applications?application=" +
                             encodeURIComponent(application)));
  assert.strictEqual(r.status, 200, K.shown(r));
  log.debug("Leaving embedded().");
  // The page's tabs are drawn from `page` (#446), never the entry's own
  // members, which are its attributes.
  return (r.json && r.json.page && r.json.page.embeddedPeps) || [];
}

async function bindingRows() {
  log.debug("Entering bindingRows().");
  const r = await K.send(api("/audit?per=500&action=xacml.pep.binding"));
  assert.strictEqual(r.status, 200, K.shown(r));
  log.debug("Leaving bindingRows().");
  return Number((r.json && r.json.matched) || 0);
}

async function setUp() {
  log.debug("Entering setUp().");
  realm = await K.realm("pepbind", "development");
  await K.app(realm, APP_A, {});
  await K.app(realm, APP_B, {});
  await K.app(realm, APP_GONE, {});
  // THE PEP'S ACCOUNT: a person put in `remote-peps`, which makes it a
  // service account owned by the realm's Admin Write group (#1760).
  await K.ok(api("/users/create"), { username: PEP, invent: false,
    attributes: { cn: PEP, sn: "Embedded PEP", givenName: "Embedded",
                  mail: PEP + "@pep-binding.test" } },
    "created " + PEP);
  await K.ok(api("/groups/add-member"),
             { group: "remote-peps", member: PEP },
             "put " + PEP + " in remote-peps");
  await K.person(realm, PERSON, "Pep-Binding-" + K.rand(8));
  log.debug("Leaving setUp().");
}

async function bind() {
  log.debug("Entering bind().");
  log.info("=== B. bind ===");
  const first = await act("set-pep-application",
                          { name: PEP, application: APP_A });
  const listedA = await embedded(APP_A);
  check("B1. a service account in remote-peps is bound to an application, " +
        "and the application's page lists it", function () {
    assert.strictEqual(first.status, 200, K.shown(first));
    assert.strictEqual(first.json.ok, true, K.shown(first));
    assert.strictEqual(first.json.application, APP_A);
    assert.strictEqual(first.json.previous || "", "");
    assert.deepStrictEqual(listedA, [PEP]);
  });
  const before = await bindingRows();
  const again = await act("set-pep-application",
                          { name: PEP, application: APP_A });
  const after = await bindingRows();
  check("B2. the same binding again succeeds and changes nothing: no " +
        "audit row", function () {
    assert.strictEqual(again.status, 200, K.shown(again));
    assert.strictEqual(again.json.ok, true, K.shown(again));
    assert.strictEqual(again.json.previous, APP_A);
    assert.strictEqual(after, before);
  });
  const moved = await act("set-pep-application",
                          { pep: PEP, application: APP_B });
  const nowA = await embedded(APP_A);
  const nowB = await embedded(APP_B);
  check("B3. a second application replaces the first (`pep` taken as the " +
        "name), and only the second lists it", function () {
    assert.strictEqual(moved.status, 200, K.shown(moved));
    assert.strictEqual(moved.json.application, APP_B);
    assert.strictEqual(moved.json.previous, APP_A);
    assert.deepStrictEqual(nowA, []);
    assert.deepStrictEqual(nowB, [PEP]);
  });
  log.debug("Leaving bind().");
}

async function refusals() {
  log.debug("Entering refusals().");
  log.info("=== R. the refusals ===");
  const noName = await K.coded(realm, "STS-XACML-0334", function () {
    return act("set-pep-application", { application: APP_A });
  });
  const nobody = await K.coded(realm, "STS-XACML-0334", function () {
    return act("set-pep-application",
               { name: "nobody-" + K.rand(6), application: APP_A });
  });
  check("R1. no name, and a name that is nobody in ou=users, are refused " +
        "STS-XACML-0334", function () {
    assert.ok(refused(noName.answer), K.shown(noName.answer));
    assert.ok(refused(nobody.answer), K.shown(nobody.answer));
    assert.ok(noName.rose >= 1 && nobody.rose >= 1,
              noName.rose + " " + nobody.rose);
  });
  const person = await K.coded(realm, "STS-XACML-0335", function () {
    return act("set-pep-application", { name: PERSON, application: APP_A });
  });
  check("R2. a person outside remote-peps is refused STS-XACML-0335",
        function () {
    assert.ok(refused(person.answer), K.shown(person.answer));
    assert.ok(person.rose >= 1, String(person.rose));
  });
  const unknown = await K.coded(realm, "STS-XACML-0336", function () {
    return act("set-pep-application",
               { name: PEP, application: "no-such-app-" + K.rand(6) });
  });
  const noApp = await K.coded(realm, "STS-XACML-0336", function () {
    return act("set-pep-application", { name: PEP });
  });
  check("R3. an application the registry does not hold, and none named, " +
        "are refused STS-XACML-0336", function () {
    assert.ok(refused(unknown.answer), K.shown(unknown.answer));
    assert.ok(refused(noApp.answer), K.shown(noApp.answer));
    assert.ok(unknown.rose >= 1 && noApp.rose >= 1,
              unknown.rose + " " + noApp.rose);
  });
  const stillB = await embedded(APP_B);
  const stillA = await embedded(APP_A);
  check("R4. no refusal changed the binding: the PEP is still bound to the " +
        "second application", function () {
    assert.deepStrictEqual(stillB, [PEP]);
    assert.deepStrictEqual(stillA, []);
  });
  log.debug("Leaving refusals().");
}

async function issue() {
  log.debug("Entering issue().");
  log.info("=== I. issue-pep-credential with an application ===");
  const made = await credentials.assertionRequest({ keyAlg: "ec-p256",
                                                    name: PEP });
  const wrong = await K.coded(realm, "STS-XACML-0336", function () {
    return act("issue-pep-credential", { name: PEP, csr: made.csrPem,
      application: "no-such-app-" + K.rand(6) });
  });
  check("I1. a credential naming an application the registry does not " +
        "hold is refused STS-XACML-0336 and certifies nothing",
        function () {
    assert.ok(refused(wrong.answer), K.shown(wrong.answer));
    assert.ok(wrong.rose >= 1, String(wrong.rose));
    assert.ok(!wrong.answer.json.kid, K.shown(wrong.answer));
  });
  const api2 = {
    post: async function (url, payload) {
      log.debug("Entering post(). " + url);
      const r = await K.send(url, { json: payload });
      log.debug("Leaving post().");
      return { status: r.status, body: r.json, text: r.text };
    }
  };
  const issued = await credentials.issueAssertionCredential(api2, K.base,
    "/realm/" + realm, PEP, made.csrPem);
  check("I2. without an application the credential is issued and the " +
        "binding is left as it was", function () {
    assert.ok(issued.kid, JSON.stringify(issued).slice(0, 300));
  });
  assert.deepStrictEqual(await embedded(APP_B), [PEP]);
  const fresh = await credentials.assertionRequest({ keyAlg: "ec-p256",
                                                     name: PEP });
  const both = await act("issue-pep-credential", { name: PEP,
    csr: fresh.csrPem, application: APP_A });
  const listedA = await embedded(APP_A);
  const listedB = await embedded(APP_B);
  check("I3. with an application the key is certified and the PEP bound " +
        "to it in the same call", function () {
    assert.strictEqual(both.status, 200, K.shown(both));
    assert.strictEqual(both.json.ok, true, K.shown(both));
    assert.ok(both.json.kid, K.shown(both));
    assert.strictEqual(both.json.application, APP_A, K.shown(both));
    assert.deepStrictEqual(listedA, [PEP]);
    assert.deepStrictEqual(listedB, []);
  });
  log.debug("Leaving issue().");
}

async function deleted() {
  log.debug("Entering deleted().");
  log.info("=== D. the application deleted ===");
  await K.ok(api("/xacml/set-pep-application"),
             { name: PEP, application: APP_GONE },
             "bound " + PEP + " to " + APP_GONE);
  assert.deepStrictEqual(await embedded(APP_GONE), [PEP]);
  const before = await bindingRows();
  await K.ok(api("/applications/forget"), { application: APP_GONE },
             "deleted " + APP_GONE);
  const after = await bindingRows();
  const cleared = await act("clear-pep-application", { name: PEP });
  check("D1. deleting the application cleared the binding, with an audit " +
        "row: nothing was left to clear", function () {
    assert.ok(after > before, before + " -> " + after);
    assert.strictEqual(cleared.status, 200, K.shown(cleared));
    assert.strictEqual(cleared.json.ok, true, K.shown(cleared));
    assert.strictEqual(cleared.json.previous || "", "", K.shown(cleared));
  });
  log.debug("Leaving deleted().");
}

async function clear() {
  log.debug("Entering clear().");
  log.info("=== C. clear ===");
  await K.ok(api("/xacml/set-pep-application"),
             { name: PEP, application: APP_A },
             "bound " + PEP + " to " + APP_A);
  const before = await bindingRows();
  const cleared = await act("clear-pep-application", { name: PEP });
  const mid = await bindingRows();
  const listed = await embedded(APP_A);
  check("C1. the binding is removed, with an audit row, and the " +
        "application lists nobody", function () {
    assert.strictEqual(cleared.status, 200, K.shown(cleared));
    assert.strictEqual(cleared.json.previous, APP_A, K.shown(cleared));
    assert.strictEqual(cleared.json.application, "");
    assert.ok(mid > before, before + " -> " + mid);
    assert.deepStrictEqual(listed, []);
  });
  const again = await act("clear-pep-application", { name: PEP });
  const after = await bindingRows();
  check("C2. a second clear succeeds and writes no audit row", function () {
    assert.strictEqual(again.status, 200, K.shown(again));
    assert.strictEqual(again.json.ok, true, K.shown(again));
    assert.strictEqual(again.json.previous || "", "");
    assert.strictEqual(after, mid);
  });
  const nobody = await K.coded(realm, "STS-XACML-0334", function () {
    return act("clear-pep-application", { name: "nobody-" + K.rand(6) });
  });
  check("C3. clearing nobody is refused STS-XACML-0334", function () {
    assert.ok(refused(nobody.answer), K.shown(nobody.answer));
    assert.ok(nobody.rose >= 1, String(nobody.rose));
  });
  log.debug("Leaving clear().");
}

async function test() {
  log.debug("Entering test().");
  await setUp();
  await bind();
  await refusals();
  await issue();
  await deleted();
  await clear();
  log.debug("Leaving test().");
}

K.main(test, 14);
