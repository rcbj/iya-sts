// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_xacml_pap.js
//
// ===========================================================================
// THE POLICY ADMINISTRATION POINT, OVER THE WIRE (#444 D12 phase 8).
//
// `tests/xacml_pap.js` holds the templates, the editor's grammar and the
// XML writer under both in process. `sts_xacml_editor.js` (vendored) drives
// the editor's page in a browser. This job asks the API the page is drawn
// from — `GET /admin-api/xacml/policies`, `GET /admin-api/xacml/editor`
// and `POST /admin-api/xacml/{action}` — in a development realm whose
// repository it wrote:
//
//   T. THE TEMPLATES: every one the catalogue lists builds through
//      create-from-template, type-checks (the editor reports no problem)
//      and parses back; one called with no answers falls back to its own
//      defaults; a role holding XML metacharacters survives into the
//      document intact; an unknown template is refused naming the ones that
//      exist (STS-XACML-0036); the blank template as a PolicySet carries the
//      POLICY-combining algorithm, and as a Policy denies everything until a
//      rule is added;
//   E. THE EDITS: six in a row apply and the document still type-checks; a
//      removal; an action the editor does not implement is refused out loud
//      (STS-XACML-0032, the refusal listing the actions); a path that no
//      longer resolves; an expression edit at the document root (#1356); an
//      integer Match with a non-integer literal and a dateTime value that is
//      not one — each refused with the stored document unchanged — and a
//      valid integer accepted; the menu the editor offers at a path names
//      only actions the API takes;
//   P. THE PAP'S ACTIONS: an ABAC policy created, disabled, edited through
//      the API (the store validates the edit), deleted;
//   O. A PATH NAMES THE POLICY'S OWN MEMBERS: add-rule, edit-policy and
//      remove at a path through an inherited member are refused, and the API
//      still answers afterwards (no STS-API-0140, no STS-API-0139);
//   S. A POLICY SET: add-rule refused on a set, add-policy accepted, the
//      child in the document.
//
// (d), with the reason: the writer's byte-identical round trip and the
// match menu's function list are functions of the model; their outcome
// here is that every stored document parses back (`problems` empty).
// Variables, selectors, optional syntax and combiner parameters are edits
// of the same door; this job carries the grammar's refusals, not each
// production.
//
// OWNED HERE (local: true): the PAP and the API are ours.
// ===========================================================================

const assert = require("assert");
const K = require("./oauth_wire_kit.js").kit("sts_xacml_pap");

const log = K.log;
const check = K.check;
const F1 = "urn:oasis:names:tc:xacml:1.0:function:";
const POLICY_ALG = "urn:oasis:names:tc:xacml:3.0:policy-combining-algorithm:";
const DENY_OVERRIDES =
  "urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides";

let realm = null;

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

async function editor(name) {
  log.debug("Entering editor(). " + name);
  const r = await K.send(api("/xacml/editor?policy=" +
                             encodeURIComponent(name)));
  assert.strictEqual(r.status, 200, K.shown(r));
  log.debug("Leaving editor().");
  return r.json;
}

function rulesOf(view) {
  log.debug("Entering rulesOf().");
  log.debug("Leaving rulesOf().");
  return (view.tree || []).filter(function (row) {
    return /^\.?rules\.\d+$/.test(row.path);
  }).length;
}

function refused(r) {
  log.debug("Entering refused().");
  log.debug("Leaving refused().");
  return r.status >= 400 || (r.json && r.json.ok === false);
}

function whyOf(r) {
  log.debug("Entering whyOf().");
  log.debug("Leaving whyOf().");
  return String((r.json && (r.json.why ||
    (r.json.errors || []).join(" "))) || r.text);
}

async function coded(code, what, action, body, verdict) {
  log.debug("Entering coded(). " + code);
  const c = await K.coded(realm, code, function () {
    return act(action, body);
  });
  check(what + " (" + code + ")", function () {
    assert.ok(refused(c.answer), K.shown(c.answer));
    if (verdict) {
      verdict(c.answer);
    }
    assert.ok(c.rose >= 1, code + " rose " + c.rose);
  });
  log.debug("Leaving coded().");
  return c.answer;
}

async function templates() {
  log.debug("Entering templates().");
  log.info("=== T. the templates ===");
  const listed = await K.send(api("/xacml/policies"));
  const catalogue = ((listed.json && listed.json.templates) || [])
    .map(function (one) {
      return one.id || one.template || one.name;
    }).filter(Boolean);
  check("T1. the catalogue lists the templates", function () {
    assert.ok(catalogue.indexOf("rbac") >= 0 &&
              catalogue.indexOf("blank") >= 0, listed.text.slice(0, 600));
  });
  const failed = [];
  for (const id of catalogue) {
    const name = "pap-t-" + id;
    const r = await act("create-from-template", { template: id, name: name });
    if (r.status !== 200 || !r.json || r.json.ok === false) {
      failed.push(id + ": " + K.shown(r));
      continue;
    }
    const view = await editor(name);
    if ((view.problems || []).length || view.problem ||
        !view.policy || !view.policy.policyId) {
      failed.push(id + " has problems: " + JSON.stringify(view.problems));
    }
  }
  check("T2. every template in the catalogue builds with no answers, is " +
        "stored (so it type-checked) and reports no static problems (" +
        catalogue.length + ")", function () {
    assert.deepStrictEqual(failed, []);
  });
  const rbac = await editor("pap-t-rbac");
  check("T3. a template called with NO answers falls back to its own " +
        "defaults rather than producing an empty policy", function () {
    assert.ok(rulesOf(rbac) > 0, JSON.stringify(rbac.tree).slice(0, 400));
  });
  await K.ok(api("/xacml/create-from-template"), { template: "rbac",
    name: "pap-awkward", p_adminRoles: "a\"b<c&d", p_readerRoles: "" },
    "T4. a template accepts a role containing XML metacharacters");
  const awkward = await editor("pap-awkward");
  check("T4. the document a role with XML metacharacters produces parses " +
        "back with the value intact", function () {
    assert.deepStrictEqual(awkward.problems || [], []);
    assert.ok(awkward.document.indexOf("a&quot;b&lt;c&amp;d") >= 0 ||
              awkward.document.indexOf("a\"b&lt;c&amp;d") >= 0,
              awkward.document.slice(0, 1200));
    assert.ok(String(awkward.alfa || "").indexOf("a\\\"b<c&d") >= 0 ||
              String(awkward.alfa || "").indexOf("a\"b<c&d") >= 0,
              String(awkward.alfa).slice(0, 800));
  });
  await coded("STS-XACML-0036", "T5. an unknown template is refused, and " +
              "the refusal names the ones that exist",
              "create-from-template", { template: "nonesuch",
                                        name: "pap-nonesuch" },
              function (r) {
    assert.ok(/rbac/.test(whyOf(r)), whyOf(r));
  });
  await K.ok(api("/xacml/create-from-template"), { template: "blank",
    name: "pap-set", p_kind: "PolicySet" }, "the blank template as a set");
  const set = await editor("pap-set");
  check("T6. the blank template as a PolicySet carries the POLICY-" +
        "combining algorithm", function () {
    assert.strictEqual(set.policy.kind, "PolicySet",
                       JSON.stringify(set.policy));
    assert.ok(String(set.policy.combiningAlgId).indexOf(POLICY_ALG) === 0,
              set.policy.combiningAlgId);
  });
  const blank = await editor("pap-t-blank");
  check("T7. the blank template as a Policy has no rule", function () {
    assert.strictEqual(blank.policy.kind, "Policy");
    assert.strictEqual(rulesOf(blank), 0, JSON.stringify(blank.tree));
  });
  await K.ok(api("/xacml/set-root"), { name: "pap-t-blank" },
             "the blank policy made the root");
  const decided = await K.send(api("/xacml/decide?subject=pap-anybody&" +
                                   "action=GET"));
  check("T8. and IT DENIES EVERYTHING until a rule is added", function () {
    assert.strictEqual(decided.json && decided.json.decision, "Deny",
                       K.shown(decided));
  });
  log.debug("Leaving templates().");
}

async function edits() {
  log.debug("Entering edits().");
  log.info("=== E. the edits ===");
  await K.ok(api("/xacml/create-from-template"), { template: "rbac",
    name: "pap-edits" }, "an RBAC policy to edit");
  const before = rulesOf(await editor("pap-edits"));
  const R = "rules." + before;
  const steps = [
    ["", "add-rule", { effect: "Deny" }],
    [R, "edit-rule", { id: "urn:test:rule:blocked", effect: "Deny" }],
    [R, "add-target-anyof", { matchId: F1 + "string-equal",
                              value: "contractor",
                              attributeId: "employeeType" }],
    [R, "add-condition", {}],
    [R + ".target.anyOf.0", "add-allof", { value: "intern",
                                           attributeId: "employeeType" }],
    ["", "edit-policy", { combiningAlgId: DENY_OVERRIDES }]];
  const failed = [];
  for (const step of steps) {
    const r = await act(step[1], Object.assign({ policy: "pap-edits",
                                                 path: step[0] }, step[2]));
    if (refused(r)) {
      failed.push(step[1] + ": " + K.shown(r));
    }
  }
  let view = await editor("pap-edits");
  check("E1. a sequence of six edits applies, the rule is added, the " +
        "combining algorithm changed, and the document still type-checks",
        function () {
    assert.deepStrictEqual(failed, []);
    assert.strictEqual(rulesOf(view), before + 1);
    assert.strictEqual(view.policy.combiningAlgId, DENY_OVERRIDES);
    assert.deepStrictEqual(view.problems || [], []);
  });
  const removed = await act("remove", { policy: "pap-edits", path: R });
  view = await editor("pap-edits");
  check("E2. a rule can be removed, and the policy still type-checks",
        function () {
    assert.ok(!refused(removed), K.shown(removed));
    assert.strictEqual(rulesOf(view), before);
    assert.deepStrictEqual(view.problems || [], []);
  });
  await coded("STS-XACML-0032", "E3. an action nobody implements is " +
              "refused out loud, and the refusal lists the actions there are",
              "add-unicorn", { policy: "pap-edits", path: "" },
              function (r) {
    assert.ok(/add-rule/.test(r.text) && /import-alfa/.test(r.text),
              r.text.slice(0, 400));
  });
  const document = view.document;
  const stale = await act("edit-rule", { policy: "pap-edits",
                                         path: "rules.99", id: "x" });
  check("E4. a path that no longer resolves is refused rather than " +
        "guessing", function () {
    assert.ok(refused(stale) && /not there any more/.test(whyOf(stale)),
              K.shown(stale));
  });
  const root = await act("set-expression-apply", { policy: "pap-edits",
    path: "", functionId: F1 + "string-equal" });
  check("E5. an expression edit at the document root is refused, not a " +
        "crash (#1356)", function () {
    assert.ok(refused(root) && root.status < 500 &&
              /is the policy itself/.test(whyOf(root)), K.shown(root));
  });
  const match = "rules.0.target.anyOf.0.allOf.0.matches.0";
  const notInt = await act("edit-match", { policy: "pap-edits", path: match,
    matchId: F1 + "integer-equal", value: "notanint" });
  view = await editor("pap-edits");
  check("E6. an integer Match with a non-integer literal is refused and " +
        "the stored document is unchanged", function () {
    assert.ok(refused(notInt) && /not a valid integer/.test(whyOf(notInt)),
              K.shown(notInt));
    assert.strictEqual(view.document, document);
  });
  const fine = await act("edit-match", { policy: "pap-edits", path: match,
    matchId: F1 + "integer-equal", value: "42" });
  check("E7. a valid integer literal is accepted", function () {
    assert.ok(!refused(fine), K.shown(fine));
  });
  await K.ok(api("/xacml/add-condition"), { policy: "pap-edits",
    path: "rules.0" }, "a condition to hold a plain value");
  view = await editor("pap-edits");
  const valueRow = (view.tree || []).filter(function (row) {
    return row.path.replace(/^\./, "") === "rules.0.condition.args.0";
  })[0];
  check("E8. the new condition has a first argument to hold a value",
        function () {
    assert.ok(valueRow && valueRow.kind === "expression",
              JSON.stringify(valueRow));
  });
  const kept = view.document;
  const notTime = await act("edit-value", { policy: "pap-edits",
    path: "rules.0.condition.args.0", lexical: "soon",
    type: "http://www.w3.org/2001/XMLSchema#dateTime" });
  const after = await editor("pap-edits");
  check("E9. an edit-value that is not a dateTime is refused, the document " +
        "unchanged", function () {
    assert.ok(refused(notTime), K.shown(notTime));
    assert.strictEqual(after.document, kept);
  });
  const offered = [];
  (after.tree || []).forEach(function (row) {
    ((row.options || {}).additions || []).forEach(function (one) {
      offered.push(one.action || "");
    });
    if ((row.options || {}).removable) {
      offered.push("remove");
    }
  });
  const known = await act("add-unicorn", {});
  const unknown = offered.filter(function (one) {
    return one && known.text.indexOf(one) < 0;
  });
  check("E10. every action the editor's menu offers is one the API takes",
        function () {
    assert.ok(offered.length > 0, JSON.stringify(after.tree).slice(0, 300));
    assert.deepStrictEqual(unknown, []);
  });
  log.debug("Leaving edits().");
}

async function papActions() {
  log.debug("Entering papActions().");
  log.info("=== P. the PAP's actions ===");
  await K.ok(api("/xacml/create-from-template"), { template: "abac",
    name: "pap-test", p_subjectAttribute: "employeeType",
    p_subjectValue: "staff" }, "P1. the PAP creates a policy from a template");
  let rows = (await K.send(api("/xacml/policies"))).json.policies || [];
  const row = function (name) {
    return rows.filter(function (one) {
      return one.name === name;
    })[0];
  };
  check("P1. the PAP creates a policy from a template, and it is in the " +
        "repository", function () {
    assert.ok(row("pap-test"), JSON.stringify(rows).slice(0, 400));
  });
  await K.ok(api("/xacml/disable"), { name: "pap-test" }, "disabled");
  rows = (await K.send(api("/xacml/policies"))).json.policies || [];
  check("P2. it can be disabled, and it is", function () {
    assert.strictEqual(row("pap-test").enabled, false);
  });
  const before = rulesOf(await editor("pap-test"));
  await K.ok(api("/xacml/add-rule"), { policy: "pap-test", path: "",
    effect: "Deny" }, "a rule added through the PAP action");
  const view = await editor("pap-test");
  check("P3. a rule can be added through the API, and the policy is still " +
        "readable with the new rule in it", function () {
    assert.strictEqual(rulesOf(view), before + 1);
    assert.deepStrictEqual(view.problems || [], []);
  });
  await K.ok(api("/xacml/delete"), { name: "pap-test" }, "deleted");
  rows = (await K.send(api("/xacml/policies"))).json.policies || [];
  check("P4. it can be deleted, and it is gone", function () {
    assert.ok(!row("pap-test"));
  });
  log.debug("Leaving papActions().");
}

async function ownPaths() {
  log.debug("Entering ownPaths().");
  log.info("=== O. a path names the policy's own members ===");
  const hostile = ["__proto__", "constructor", "constructor.prototype",
                   "rules.__proto__", "rules.0.__proto__",
                   "rules.constructor", "rules.length", "toString",
                   "rules.-1", "rules.1e0"];
  const actions = [["add-rule", { effect: "Deny" }],
                   ["edit-policy", { description: "polluted" }],
                   ["remove", {}]];
  const before0140 = await K.codeCount(realm, "STS-API-0140");
  const before0139 = await K.codeCount(realm, "STS-API-0139");
  const accepted = [];
  for (const one of hostile) {
    for (const a of actions) {
      const r = await act(a[0], Object.assign({ policy: "pap-t-rbac",
                                                path: one }, a[1]));
      if (!refused(r) || r.status >= 500) {
        accepted.push(a[0] + " at " + one + ": " + K.shown(r));
      }
    }
  }
  check("O1. every edit at a path through an inherited member is refused (" +
        hostile.length * actions.length + " tried)", function () {
    assert.deepStrictEqual(accepted, []);
  });
  const listed = await K.send(api("/xacml/policies"));
  const own = await act("add-rule", { policy: "pap-t-rbac", path: "",
                                      effect: "Deny" });
  check("O2. and the API still answers, nothing inheriting a member: the " +
        "repository lists, the root path still takes a rule, and neither " +
        "STS-API-0140 nor STS-API-0139 was recorded", function () {
    assert.strictEqual(listed.status, 200, K.shown(listed));
    assert.ok(!refused(own), K.shown(own));
  });
  const a0140 = await K.codeCount(realm, "STS-API-0140");
  const a0139 = await K.codeCount(realm, "STS-API-0139");
  check("O3. no response model refused an answer afterwards", function () {
    assert.strictEqual(a0140 - before0140, 0);
    assert.strictEqual(a0139 - before0139, 0);
  });
  log.debug("Leaving ownPaths().");
}

async function policySets() {
  log.debug("Entering policySets().");
  log.info("=== S. a policy set ===");
  const rule = await act("add-rule", { policy: "pap-set", path: "",
                                       effect: "Deny" });
  check("S1. add-rule on a policy set is refused rather than reported " +
        "added and dropped from the document", function () {
    assert.ok(refused(rule), K.shown(rule));
  });
  const child = await act("add-policy", { policy: "pap-set", path: "" });
  const view = await editor("pap-set");
  check("S2. add-policy is accepted and the child is in the document",
        function () {
    assert.ok(!refused(child), K.shown(child));
    assert.ok(/<PolicySet[\s\S]*<Policy /.test(view.document),
              view.document.slice(0, 800));
    assert.deepStrictEqual(view.problems || [], []);
  });
  log.debug("Leaving policySets().");
}

async function test() {
  log.debug("Entering test().");
  realm = await K.realm("pap", "development");
  await templates();
  await edits();
  await papActions();
  await ownPaths();
  await policySets();
  log.debug("Leaving test().");
}

K.main(test, 27);
