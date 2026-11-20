// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_authzen_admin_view.js
//
// ===========================================================================
// THE AUTHZEN TAB'S VIEW AND ITS ACTS' EFFECTS, OVER THE WIRE (#444 D12
// phase 8; #1162).
//
// `tests/authzen_admin.js` holds `/admin-api/xacml/authzen` in process;
// `sts_authzen_codes.js` carries its refusals by code. This job reads the
// view a running service answers, in a development realm, and what the
// acts change in it:
//
//   V. the view: the realm's API object, an empty catalogue, mutual TLS as
//      the default door, the AuthZEN settings group alone; a member of the
//      callers' group listed, scoped to nothing;
//   C. set-attribute adds a row and, for the same object and property,
//      REPLACES it (`replaced`, the new attribute id and multiplicity in the
//      view); remove-attribute takes it off;
//   S. set-scope's applications read back in the view, and an empty scope
//      clearing them.
//
// (d), with the reason: S2 (an application caller's own identifier always
// in its scope) is the scope reader's, a function a request reaches only
// as a caller's decision (`sts_authzen_codes.js`'s scoped evaluations); the
// page's HTML (the console is a static surface since #446).
//
// OWNED HERE (local: true): the AuthZEN API is ours.
// ===========================================================================

const assert = require("assert");
const K = require("./oauth_wire_kit.js").kit("sts_authzen_admin_view");

const log = K.log;
const check = K.check;

let realm = null;

function api(path) {
  log.debug("Entering api().");
  log.debug("Leaving api().");
  return K.rb(realm) + "/admin-api" + path;
}

async function view() {
  log.debug("Entering view().");
  const r = await K.send(api("/xacml/authzen"));
  assert.strictEqual(r.status, 200, K.shown(r));
  log.debug("Leaving view().");
  return r.json;
}

function callerOf(v, name) {
  log.debug("Entering callerOf().");
  log.debug("Leaving callerOf().");
  return (v.callers || []).filter(function (one) {
    return one.name === name;
  })[0] || null;
}

async function test() {
  log.debug("Entering test().");
  realm = await K.realm("azv", "development");
  await K.ok(api("/users/create"), { username: "azv-pep", invent: false,
    attributes: { cn: "azv-pep", sn: "azv-pep", givenName: "azv-pep",
                  mail: "azv-pep@azv.example" } }, "created azv-pep");
  await K.ok(api("/groups/add-member"), { group: "authzen-peps",
    member: "azv-pep" }, "azv-pep in authzen-peps");
  let v = await view();
  const groups = ((v.settings || {}).groups || []).map(function (one) {
    return one.group;
  });
  check("V1. the view carries the realm's API object, an empty catalogue, " +
        "mtls as the default door, and the AuthZEN settings alone",
        function () {
    assert.ok(v.apiObject, JSON.stringify(Object.keys(v)));
    assert.strictEqual(((v.catalogue || {}).rows || []).length, 0,
                       JSON.stringify(v.catalogue));
    assert.strictEqual(v.callerAuthentication, "mtls");
    assert.deepStrictEqual(groups, ["AuthZEN"]);
  });
  check("V2. the group's member is listed, scoped to nothing", function () {
    const one = callerOf(v, "azv-pep");
    assert.ok(one, JSON.stringify(v.callers));
    assert.deepStrictEqual(one.applications || [], []);
  });
  const added = await K.send(api("/xacml/authzen/set-attribute"), { json: {
    object: "resource", property: "classification",
    attributeId: "urn:example:classification" } });
  check("C1. set-attribute adds a row", function () {
    assert.ok(added.status === 200 && added.json.ok && !added.json.replaced,
              K.shown(added));
  });
  const replaced = await K.send(api("/xacml/authzen/set-attribute"), {
    json: { object: "resource", property: "classification",
            attributeId: "urn:example:class", multiplicity: "bag" } });
  v = await view();
  check("C2. the same object and property again REPLACES the row",
        function () {
    assert.ok(replaced.status === 200 && replaced.json.replaced,
              K.shown(replaced));
    const rows = (v.catalogue || {}).rows || [];
    assert.strictEqual(rows.length, 1, JSON.stringify(rows));
    assert.strictEqual(rows[0].attributeId, "urn:example:class");
    assert.strictEqual(rows[0].multiplicity, "bag");
  });
  await K.ok(api("/xacml/authzen/remove-attribute"), { object: "resource",
    property: "classification" }, "removed the row");
  v = await view();
  check("C3. remove-attribute takes the row off", function () {
    assert.strictEqual(((v.catalogue || {}).rows || []).length, 0,
                       JSON.stringify(v.catalogue));
  });
  await K.ok(api("/xacml/authzen/set-scope"), { caller: "azv-pep",
    applications: ["todo-app", "wiki"] }, "scoped azv-pep");
  v = await view();
  check("S1. a caller's scope reads back in the view", function () {
    const one = callerOf(v, "azv-pep");
    assert.deepStrictEqual((one.applications || []).slice().sort(),
                           ["todo-app", "wiki"], JSON.stringify(one));
  });
  await K.ok(api("/xacml/authzen/set-scope"), { caller: "azv-pep",
    applications: "" }, "cleared azv-pep's scope");
  v = await view();
  check("S3. an empty scope clears it", function () {
    assert.deepStrictEqual(callerOf(v, "azv-pep").applications || [], []);
  });
  log.debug("Leaving test().");
}

K.main(test, 7);
