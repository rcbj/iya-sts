// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_delegation_facts.js
//
// ===========================================================================
// WHO MAY ACT FOR WHOM: THE FACTS' DOORS AND THE REGISTER, OVER THE WIRE
// (#444 D12 phase 8; #108, #186).
//
// `tests/delegation_policy.js` gathers the delegation policy's facts from
// real entries in process. `sts_delegation_policy.js` (vendored) drives
// every outcome at the two doors that ask it — WS-Trust and RFC 8693 — and
// the paged policy view. This job carries the rest of the in-process file
// that a request reaches: the doors that WRITE those facts and the
// register that reads them back, in a development realm:
//
//   J. THE PERSON'S HALF: `users/set-may-act` naming another person, then
//      an application, the register reading each back; a DN naming nobody
//      (STS-AUTHN-0227) and the person themselves refused; cleared;
//      `users/set-delegation-semantics` with a value that is neither
//      (STS-AUTHN-0295), both values with a default, and an empty set
//      clearing them; `users/set-not-delegated` on and off; an
//      application's `appMayAct` naming a party by DN;
//   K. THE ATTRIBUTES' GRAMMAR (STS-REG-0194): appNotDelegated not TRUE or
//      FALSE, appDelegationSemantics neither value, a subject group or
//      appMayAct not named by DN, the retired appTrustedToImpersonate;
//      the register (`GET /admin-api/delegation/policy`) carrying a pair
//      per relationship set on either end, the applications with
//      semantics, a subject group or appNotDelegated, the people with
//      stsNotDelegated or semantics, and the roster groups it protects;
//      the view paged, each list on its own parameter.
//
// (d), with the reason: the policy's verdicts (A-I) are
// `sts_delegation_policy.js`'s over both doors; `mayActNames()` (J7) is a
// function whose outcome is that job's may_act refusals; J2's and J10's
// may_act CLAIM on a person's token — `users/set-may-act` was seen in
// phase 8 not to reach the ID Token (`sts_gnap_delegation_codes.js`), and
// that job's I12/I13 entry stands; L (WS-Trust) is that job's W.
//
// OWNED HERE (local: true): the policy and the API are ours.
// ===========================================================================

const assert = require("assert");
const K = require("./oauth_wire_kit.js").kit("sts_delegation_facts");

const log = K.log;
const check = K.check;

let realm = null;

function api(path) {
  log.debug("Entering api().");
  log.debug("Leaving api().");
  return K.rb(realm) + "/admin-api" + path;
}

function refused(r) {
  log.debug("Entering refused().");
  log.debug("Leaving refused().");
  return r.status >= 400 || (r.json && r.json.ok === false);
}

async function coded(code, what, path, body) {
  log.debug("Entering coded(). " + code);
  const c = await K.coded(realm, code, function () {
    return K.send(api(path), { json: body });
  });
  check(what + " (" + code + ")", function () {
    assert.ok(refused(c.answer), K.shown(c.answer));
    assert.ok(c.rose >= 1, code + " rose " + c.rose);
  });
  log.debug("Leaving coded().");
}

async function refusedAt(what, path, body) {
  log.debug("Entering refusedAt().");
  const r = await K.send(api(path), { json: body });
  check(what, function () {
    assert.ok(refused(r) && r.status < 500, K.shown(r));
  });
  log.debug("Leaving refusedAt().");
}

async function register(query) {
  log.debug("Entering register().");
  const r = await K.send(api("/delegation/policy" + (query || "")));
  assert.strictEqual(r.status, 200, K.shown(r));
  log.debug("Leaving register().");
  return r.json;
}

async function dnOf(kind, name) {
  log.debug("Entering dnOf(). " + kind + " " + name);
  const r = await K.send(api(kind === "user" ? "/users?user=" +
    encodeURIComponent(name) : "/applications?application=" +
    encodeURIComponent(name)));
  const text = JSON.stringify(r.json || {});
  const found = /"dn":"([^"]+)"/.exec(text);
  assert.ok(found, kind + " " + name + " has no dn: " + text.slice(0, 300));
  log.debug("Leaving dnOf().");
  return found[1];
}

function personOf(view, username) {
  log.debug("Entering personOf().");
  log.debug("Leaving personOf().");
  return (view.people || []).filter(function (one) {
    return one.username === username;
  })[0] || null;
}

async function setUp() {
  log.debug("Entering setUp().");
  realm = await K.realm("dfx", "development");
  for (const name of ["dfx-alice", "dfx-bob", "dfx-carol", "dfx-frank"]) {
    await K.ok(api("/users/create"), { username: name, invent: false,
      attributes: { cn: name, sn: name } }, "created " + name);
  }
  await K.app(realm, "dfx-back", { oauthClientId: ["dfx-back"] },
              { protocols: ["oauth2"] });
  await K.app(realm, "dfx-front", { oauthClientId: ["dfx-front"],
    appAllowedToDelegateTo: ["dfx-back"] }, { protocols: ["oauth2"] });
  await K.app(realm, "dfx-rbcd-back", { oauthClientId: ["dfx-rbcd-back"] },
              { protocols: ["oauth2"] });
  await K.app(realm, "dfx-rbcd-front", { oauthClientId: ["dfx-rbcd-front"] },
              { protocols: ["oauth2"] });
  await K.app(realm, "dfx-imp", { oauthClientId: ["dfx-imp"],
    appDelegationSemantics: ["delegation", "impersonation"] },
    { protocols: ["oauth2"] });
  await K.app(realm, "dfx-svc", { oauthClientId: ["dfx-svc"],
    appNotDelegated: "TRUE" }, { protocols: ["oauth2"] });
  await K.app(realm, "dfx-mid", { oauthClientId: ["dfx-mid"] },
              { protocols: ["oauth2"] });
  // The resource-based end names its intermediary by identifier (a DN
  // there is listed with "No application here" as its warning).
  const set = await K.send(api("/applications/add"), { json: {
    application: "dfx-rbcd-back", attribute: "appAllowedToActOnBehalfOf",
    value: "dfx-rbcd-front" } });
  assert.ok(!refused(set), K.shown(set));
  log.debug("Leaving setUp().");
}

async function personHalf() {
  log.debug("Entering personHalf().");
  log.info("=== J. the person's half ===");
  const carol = await dnOf("user", "dfx-carol");
  const alice = await dnOf("user", "dfx-alice");
  const front = await dnOf("application", "dfx-front");
  await K.ok(api("/users/set-may-act"), { user: "dfx-alice",
    delegate: carol }, "J1. a person names another person as delegate");
  let view = await register();
  check("J1. a person names another person as their delegate, and the " +
        "register reads it back", function () {
    const one = personOf(view, "dfx-alice");
    assert.ok(one && JSON.stringify(one).indexOf(carol) >= 0,
              JSON.stringify(view.people).slice(0, 600));
  });
  await K.ok(api("/users/set-may-act"), { user: "dfx-alice",
    delegate: front }, "J3. an application named as delegate");
  view = await register();
  check("J3. an application is named too", function () {
    const one = personOf(view, "dfx-alice");
    assert.ok(one && JSON.stringify(one).indexOf(front) >= 0,
              JSON.stringify(one));
  });
  await coded("STS-AUTHN-0227", "J4. a DN naming nobody is refused",
              "/users/set-may-act", { user: "dfx-alice",
              delegate: "uid=nobody-here,ou=users,dc=x" });
  await refusedAt("J5. and so is the person themselves",
                  "/users/set-may-act", { user: "dfx-alice",
                                          delegate: alice });
  await K.ok(api("/users/set-may-act"), { user: "dfx-alice", delegate: "" },
             "J6. cleared");
  view = await register();
  check("J6. clearing it takes the delegate away", function () {
    const one = personOf(view, "dfx-alice");
    assert.ok(!one || JSON.stringify(one).indexOf(front) < 0,
              JSON.stringify(one));
  });
  await coded("STS-AUTHN-0295", "J8. a person's semantics are delegation " +
              "or impersonation", "/users/set-delegation-semantics",
              { user: "dfx-carol", semantics: "sideways" });
  await K.ok(api("/users/set-delegation-semantics"), { user: "dfx-carol",
    semantics: ["delegation", "impersonation"],
    "default": "impersonation" }, "N5. both semantics and a default");
  await K.ok(api("/users/set-delegation-semantics"), { user: "dfx-frank",
    semantics: ["delegation"] }, "frank's semantics");
  view = await register();
  check("N5. set-delegation-semantics writes both attributes", function () {
    const one = personOf(view, "dfx-carol");
    assert.ok(one, JSON.stringify(view.people).slice(0, 600));
    assert.deepStrictEqual(one.semantics, ["delegation", "impersonation"],
                           JSON.stringify(one));
  });
  await K.ok(api("/users/set-delegation-semantics"), { user: "dfx-carol",
    semantics: "" }, "N7. cleared");
  view = await register();
  check("N7. and an empty set clears them", function () {
    const one = personOf(view, "dfx-carol");
    assert.ok(!one || !(one.semantics || []).length, JSON.stringify(one));
  });
  await K.ok(api("/users/set-not-delegated"), { user: "dfx-bob",
    value: true }, "N1. stsNotDelegated on");
  await K.ok(api("/users/set-not-delegated"), { user: "dfx-carol",
    value: true }, "carol not delegated");
  await K.ok(api("/users/set-not-delegated"), { user: "dfx-carol",
    value: false }, "N2. and off");
  view = await register();
  check("N1. set-not-delegated writes stsNotDelegated, and N2. value " +
        "false clears it", function () {
    const bob = personOf(view, "dfx-bob");
    const carolRow = personOf(view, "dfx-carol");
    assert.ok(bob && bob.notDelegated, JSON.stringify(bob));
    assert.ok(!carolRow || !carolRow.notDelegated, JSON.stringify(carolRow));
  });
  const named = await K.send(api("/applications/set"), { json: {
    application: "dfx-mid", attribute: "appMayAct", value: front } });
  check("J9. an application's appMayAct names its delegate by DN",
        function () {
    assert.ok(!refused(named), K.shown(named));
  });
  log.debug("Leaving personHalf().");
}

async function grammarAndRegister() {
  log.debug("Entering grammarAndRegister().");
  log.info("=== K. the grammar and the register ===");
  const rows = [
    ["K1. appNotDelegated must be TRUE or FALSE", "set",
     "appNotDelegated", "yes"],
    ["K2. appDelegationSemantics holds delegation or impersonation", "add",
     "appDelegationSemantics", "sideways"],
    ["K3. a subject group is named by its DN", "add",
     "appDelegationSubjectGroup", "dfx-staff"],
    ["K3b. appMayAct names its delegate by DN", "set", "appMayAct",
     "dfx-front"]];
  for (const row of rows) {
    await coded("STS-REG-0194", row[0], "/applications/" + row[1], {
      application: "dfx-mid", attribute: row[2], value: row[3] });
  }
  await refusedAt("K4. appTrustedToImpersonate is gone: merged into " +
                  "appDelegationSemantics", "/applications/set",
                  { application: "dfx-mid",
                    attribute: "appTrustedToImpersonate", value: "TRUE" });
  const view = await register();
  check("K5. the register has a pair for each relationship, set on each " +
        "end", function () {
    const pairs = view.pairs || [];
    assert.ok(pairs.some(function (one) {
      return one.intermediary === "dfx-front" && one.target === "dfx-back" &&
             one.mechanism === "constrained";
    }), JSON.stringify(pairs).slice(0, 800));
    assert.ok(pairs.some(function (one) {
      return one.intermediary === "dfx-rbcd-front" &&
             one.target === "dfx-rbcd-back" &&
             one.mechanism === "resource-based";
    }), JSON.stringify(pairs).slice(0, 800));
  });
  check("K6. and the applications carrying semantics or appNotDelegated",
        function () {
    const listed = view.intermediaries || [];
    assert.ok(listed.some(function (one) {
      return one.application === "dfx-imp" && one.impersonates;
    }), JSON.stringify(listed).slice(0, 800));
    assert.ok(listed.some(function (one) {
      return one.application === "dfx-svc" && one.notDelegated;
    }), JSON.stringify(listed).slice(0, 800));
  });
  check("K7. and the people carrying stsNotDelegated or semantics",
        function () {
    const bob = personOf(view, "dfx-bob");
    const frank = personOf(view, "dfx-frank");
    assert.ok(bob && bob.notDelegated, JSON.stringify(view.people));
    assert.ok(frank && (frank.semantics || []).join() === "delegation",
              JSON.stringify(view.people));
  });
  check("K8. and it names the roster groups it protects", function () {
    assert.ok((view.protectedGroups || []).length >= 1,
              JSON.stringify(view).slice(0, 400));
  });
  const paged = await register("?per=1");
  check("N8. the view is PAGED, each list on its own parameter",
        function () {
    assert.strictEqual((paged.pairs || []).length, 1,
                       JSON.stringify(paged.pairsPaging));
    assert.ok(paged.pairsPaging && paged.pairsPaging.pages >= 2,
              JSON.stringify(paged.pairsPaging));
    assert.ok(paged.peoplePaging && paged.intermediariesPaging,
              JSON.stringify(Object.keys(paged)));
  });
  log.debug("Leaving grammarAndRegister().");
}

async function test() {
  log.debug("Entering test().");
  await setUp();
  await personHalf();
  await grammarAndRegister();
  log.debug("Leaving test().");
}

K.main(test, 20);
