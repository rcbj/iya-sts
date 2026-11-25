// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_xacml_pep_scope.js
//
// ===========================================================================
// THE POLICY PULL SCOPED TO A BOUND APPLICATION, OVER THE WIRE (#2027, work
// item 4 of #1206).
//
// `tests/xacml_pep_scope.js` holds `boundPull()` in process. This job pulls
// `GET /xacml/pep/policies?scope=bound-application` as the `iya-pep`
// package does — its own DPoP-bound `xacml:pep` token, `?pep=<name>`,
// `If-None-Match` — in a realm of its own holding a root PolicySet that
// references one policy, a policy nothing references, and two applications
// that enforce fine-grained authorization:
//
//   A. an enforcing application's local PEP is sent that application's own
//      policy, as the root, and no other PEP is (the other application's
//      local PEP, a central PEP, a container);
//   C. an application that enforces nothing: the realm root and its
//      closure, not the unreferenced policy, not the other application's
//      policy the root names, never the access policy;
//   T. the token: 304 on If-None-Match, unchanged when the unreferenced
//      policy changes (the repository's moves), moved when the referenced
//      one does; and a heartbeat holding the scope's token is current;
//   R. the refusals: a central PEP, a container (403 STS-XACML-0345), an
//      unknown scope (400 STS-XACML-0346), each code on the audit log;
//   V. what the console reads: the row's pullScope, and one xacml.pep.scope
//      audit row for a PEP that polls.
//
// OWNED HERE (local: true): the PEP control plane and /admin-api are ours.
// ===========================================================================

const assert = require("assert");
const K = require("./oauth_wire_kit.js").kit("sts_xacml_pep_scope");
const credentials = require("../tools/pep-credential.js");

const log = K.log;
const check = K.check;

let realm = null;
const S = K.STAMP.slice(-7).toLowerCase();
const APP_F = "scope-fga-" + S;
const APP_O = "scope-oth-" + S;
const APP_R = "scope-root-" + S;
const VERSION = "iya-pep-rust/0.1.0";
const peps = {};

function api(path) {
  log.debug("Entering api().");
  log.debug("Leaving api().");
  return K.rb(realm) + "/admin-api" + path;
}

async function must(path, body, what) {
  log.debug("Entering must(). " + path);
  const r = await K.ok(api(path), body, what);
  log.debug("Leaving must().");
  return r;
}

async function editor(name) {
  log.debug("Entering editor(). " + name);
  const r = await K.send(api("/xacml/editor?policy=" +
                             encodeURIComponent(name)));
  assert.strictEqual(r.status, 200, K.shown(r));
  log.debug("Leaving editor().");
  return r.json;
}

async function fgaPolicy(identifier) {
  log.debug("Entering fgaPolicy(). " + identifier);
  const r = await K.send(api("/applications?application=" +
                             encodeURIComponent(identifier)));
  assert.strictEqual(r.status, 200, K.shown(r));
  const fga = (r.json && r.json.page && r.json.page.fga) || {};
  log.debug("Leaving fgaPolicy().");
  return String((fga.policy || {}).name || "");
}

// A request on one of a PEP's tokens, DPoP-bound to its key.
async function asPep(pep, scope, method, path, body, headers) {
  log.debug("Entering asPep(). " + pep.name + " " + method + " " + path);
  const url = K.rb(realm) + path;
  const h = Object.assign(credentials.dpopHeaders(pep.key.privateKeyPem,
    method, url.split("?")[0], pep.tokens[scope]), headers || {});
  const r = await K.send(url, body === undefined
    ? { method: method, headers: h }
    : { method: method, headers: h, json: body });
  log.debug("Leaving asPep(). " + r.status);
  return r;
}

function pull(pep, scope, etag) {
  log.debug("Entering pull().");
  log.debug("Leaving pull().");
  return asPep(pep, "xacml:pep", "GET", "/xacml/pep/policies" +
    "?pep=" + encodeURIComponent(pep.name) +
    (scope ? "&scope=" + scope : ""), undefined,
    etag ? { "If-None-Match": '"' + etag + '"' } : {});
}

function names(r) {
  log.debug("Entering names().");
  log.debug("Leaving names().");
  return ((r.json && r.json.policies) || []).map(function (one) {
    return one.name;
  }).sort();
}

// A PEP's account, key, tokens, binding and registration.
async function makePep(label, application, mode) {
  log.debug("Entering makePep(). " + label);
  const name = "pep-scope-" + label + "-" + S;
  await K.ok(api("/users/create"), { username: name, invent: false,
    attributes: { cn: name, sn: "Scope PEP", givenName: "Scope",
                  mail: name + "@pep-scope.test" } }, "created " + name);
  await K.ok(api("/groups/add-member"),
             { group: "remote-peps", member: name },
             "put " + name + " in remote-peps");
  const key = await credentials.assertionRequest({ keyAlg: "ec-p256",
                                                   name: name });
  await credentials.issueAssertionCredential({
    post: async function (url, payload) {
      log.debug("Entering post().");
      const r = await K.send(url, { json: payload });
      log.debug("Leaving post().");
      return { status: r.status, body: r.json, text: r.text };
    }
  }, K.base, "/realm/" + realm, name, key.csrPem);
  const tokens = {};
  const got = await credentials.pepAccessToken(K.rb(realm), name,
    key.privateKeyPem, "xacml:pep", "/xacml/pep");
  assert.ok(got.status === 200 && got.token, "the xacml:pep token " +
            "answered " + got.status + " " + String(got.text).slice(0, 300));
  tokens["xacml:pep"] = got.token;
  const pep = { name: name, key: key, tokens: tokens };
  if (application) {
    await K.ok(api("/xacml/set-pep-application"),
               { name: name, application: application },
               "bound " + name + " to " + application);
  }
  const body = application
    ? { name: name, kind: "embedded", application: application, mode: mode,
        protocolVersion: 1, version: VERSION }
    : { name: name, version: VERSION };
  const registered = await asPep(pep, "xacml:pep", "POST",
                                 "/xacml/pep/register", body);
  assert.ok(registered.status === 201 || registered.status === 200,
            K.shown(registered));
  log.debug("Leaving makePep().");
  return pep;
}

async function setUp() {
  log.debug("Entering setUp().");
  realm = await K.realm("pepscope", "development");
  for (const id of [APP_F, APP_O, APP_R]) {
    await K.app(realm, id, {});
  }
  await must("/applications/fga-enable", { application: APP_F },
             "enabled fine-grained authorization on " + APP_F);
  await must("/applications/fga-enable", { application: APP_O },
             "enabled fine-grained authorization on " + APP_O);
  // THE REPOSITORY: a root PolicySet referencing scope-shared and the
  // other application's own policy; scope-unrelated referenced by nothing.
  await must("/xacml/create-from-template", { template: "blank",
    name: "scope-root", p_kind: "PolicySet" }, "the root set");
  await must("/xacml/set-root", { name: "scope-root" }, "made it the root");
  for (const name of ["scope-shared", "scope-unrelated"]) {
    await must("/xacml/create-from-template", { template: "blank",
      name: name }, "the policy " + name);
  }
  const shared = await editor("scope-shared");
  const otherPolicy = await fgaPolicy(APP_O);
  assert.ok(otherPolicy, "no fine-grained policy is named for " + APP_O);
  const other = await editor(otherPolicy);
  const idOf = function (view) {
    log.debug("Entering idOf().");
    const policy = (view && view.policy) || {};
    log.debug("Leaving idOf().");
    return String(policy.policyId || policy.id || "");
  };
  assert.ok(idOf(shared) && idOf(other), JSON.stringify([shared.policy,
                                                         other.policy]));
  for (const ref of [idOf(shared), idOf(other)]) {
    await must("/xacml/add-policy-reference",
               { policy: "scope-root", path: "", ref: ref },
               "the root references " + ref);
  }
  peps.fga = await makePep("fga", APP_F, "local");
  peps.other = await makePep("oth", APP_O, "local");
  peps.root = await makePep("root", APP_R, "local");
  peps.central = await makePep("cen", APP_F, "central");
  peps.box = await makePep("box", "", "");
  log.debug("Leaving setUp().");
}

async function ownPolicy() {
  log.debug("Entering ownPolicy().");
  log.info("=== A. an enforcing application's own policy ===");
  const mine = await fgaPolicy(APP_F);
  const otherPolicy = await fgaPolicy(APP_O);
  const r = await pull(peps.fga, "bound-application");
  check("A1. an enforcing application's local PEP is sent its own policy " +
        "alone, as the root", function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.deepStrictEqual(names(r), [mine], K.shown(r));
    assert.strictEqual(r.json.policies[0].isRoot, true);
    assert.strictEqual(r.json.source, "application");
    assert.strictEqual(r.json.application, APP_F);
    assert.ok(r.json.syncToken, K.shown(r));
  });
  const o = await pull(peps.other, "bound-application");
  const repository = await pull(peps.root, "");
  check("A2. no other PEP is sent it: the other application's local PEP " +
        "gets its own, and the repository pull withholds both", function () {
    assert.strictEqual(o.status, 200, K.shown(o));
    assert.deepStrictEqual(names(o), [otherPolicy]);
    assert.strictEqual(repository.status, 200, K.shown(repository));
    assert.ok(names(repository).indexOf(mine) < 0 &&
              names(repository).indexOf(otherPolicy) < 0,
              names(repository).join(" "));
  });
  log.debug("Leaving ownPolicy().");
}

async function rootClosure() {
  log.debug("Entering rootClosure().");
  log.info("=== C. the root and its closure ===");
  const r = await pull(peps.root, "bound-application");
  check("C1. an application that enforces nothing is sent the root and " +
        "what it references, and nothing else", function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.deepStrictEqual(names(r), ["scope-root", "scope-shared"],
                           K.shown(r));
    assert.strictEqual(r.json.source, "root");
    assert.strictEqual(r.json.policies.filter(function (one) {
      return one.isRoot;
    }).map(function (one) {
      return one.name;
    }).join(), "scope-root");
    assert.ok(names(r).indexOf("access-control") < 0);
  });
  log.debug("Leaving rootClosure().");
}

async function tokens() {
  log.debug("Entering tokens().");
  log.info("=== T. the token ===");
  const first = await pull(peps.root, "bound-application");
  const token = first.json.syncToken;
  const same = await pull(peps.root, "bound-application", token);
  check("T1. If-None-Match with the scope's token answers 304", function () {
    assert.strictEqual(same.status, 304, K.shown(same));
  });
  const repoBefore = (await pull(peps.root, "")).json.syncToken;
  await must("/xacml/add-rule", { policy: "scope-unrelated", path: "",
                                  effect: "Permit" }, "changed the unrelated");
  const repoAfter = (await pull(peps.root, "")).json.syncToken;
  const still = await pull(peps.root, "bound-application", token);
  check("T2. a change to a policy outside the closure moves the " +
        "repository's token and not the scope's (304)", function () {
    assert.notStrictEqual(repoAfter, repoBefore);
    assert.strictEqual(still.status, 304, K.shown(still));
  });
  await must("/xacml/add-rule", { policy: "scope-shared", path: "",
                                  effect: "Permit" }, "changed the shared");
  const moved = await pull(peps.root, "bound-application", token);
  check("T3. a change inside the closure moves it: 200 and a new token",
        function () {
    assert.strictEqual(moved.status, 200, K.shown(moved));
    assert.notStrictEqual(moved.json.syncToken, token);
  });
  const beat = await asPep(peps.root, "xacml:pep", "POST",
    "/xacml/pep/heartbeat", { name: peps.root.name, kind: "embedded",
      application: APP_R, mode: "local", protocolVersion: 1,
      syncToken: moved.json.syncToken, policyCount: 2,
      policyEvents: "requested" });
  check("T4. a heartbeat holding the scope's token is current, and the " +
        "answer names that token", function () {
    assert.strictEqual(beat.status, 200, K.shown(beat));
    assert.strictEqual(beat.json.current, true, K.shown(beat));
    assert.strictEqual(beat.json.syncToken, moved.json.syncToken);
  });
  log.debug("Leaving tokens().");
}

async function refusals() {
  log.debug("Entering refusals().");
  log.info("=== R. the refusals ===");
  for (const [label, pep] of [["R1. a central PEP", peps.central],
                              ["R2. a container", peps.box]]) {
    const refused = await K.coded(realm, "STS-XACML-0345", function () {
      return pull(pep, "bound-application");
    });
    check(label + " is refused the scoped pull, 403 " +
          "STS-XACML-0345", function () {
      assert.strictEqual(refused.answer.status, 403,
                         K.shown(refused.answer));
      assert.ok(refused.rose >= 1, String(refused.rose));
    });
  }
  const unknown = await K.coded(realm, "STS-XACML-0346", function () {
    return pull(peps.root, "everything");
  });
  check("R3. an unknown scope is refused 400 STS-XACML-0346", function () {
    assert.strictEqual(unknown.answer.status, 400, K.shown(unknown.answer));
    assert.ok(unknown.rose >= 1, String(unknown.rose));
  });
  log.debug("Leaving refusals().");
}

async function visible() {
  log.debug("Entering visible().");
  log.info("=== V. what the console reads ===");
  await pull(peps.fga, "bound-application");
  await pull(peps.fga, "bound-application");
  const r = await K.send(api("/xacml/peps?pep=" +
                             encodeURIComponent(peps.fga.name)));
  const row = ((r.json && r.json.peps) || [])[0] || {};
  const audited = await K.send(api("/audit?per=500&action=xacml.pep.scope"));
  const rows = ((audited.json && (audited.json.rows ||
    audited.json.entries || audited.json.events)) || []).filter(
    function (one) {
      return one.target === peps.fga.name || one.actor === peps.fga.name;
    });
  check("V1. the PEP's row says it pulls bound-application, and a PEP " +
        "that pulled several times is one xacml.pep.scope audit row",
        function () {
    assert.strictEqual(row.pullScope, "bound-application", K.shown(r));
    assert.strictEqual(audited.status, 200, K.shown(audited));
    assert.strictEqual(rows.length, 1, K.shown(audited));
  });
  log.debug("Leaving visible().");
}

async function test() {
  log.debug("Entering test().");
  await setUp();
  await ownPolicy();
  await rootClosure();
  await tokens();
  await refusals();
  await visible();
  log.debug("Leaving test().");
}

K.main(test, 11);
