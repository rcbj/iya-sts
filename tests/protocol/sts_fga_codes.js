// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_fga_codes.js
//
// ===========================================================================
// APPLICATION-SCOPED FINE-GRAINED AUTHORIZATION, EACH REFUSAL BY ITS CODE,
// OVER THE WIRE (#444 D12 phase 8; #564, #1210).
//
// `tests/fga_policies.js`, `fga_issuance.js`, `fga_console.js` and
// `fga_owned_policy_names.js` hold the policy an application owns, the
// gate and the console's acts in process; `sts_fga.js` asks a running
// service by status. This job adds the code each refusal records on
// `/admin-api/audit`, in a development realm:
//
//   P. the policy an application owns: made the repository root
//      (STS-FGA-0002), deleted while the application names it (0022), the
//      reset unconfirmed (0020), an act naming an application the registry
//      does not hold (0009), xacml.maxApplicationPolicies reached (the
//      application made without a policy, `fga-create-policy` refused
//      0024), a reset of an application with no policy (0021);
//   S. the switch and the types: enabling while a member is uncovered
//      (0018), a type written to an enforcing application leaving a member
//      uncovered (0019), a mapping row removed that is not on the type
//      (0023, a 400 naming `path` — #40; it was a 500, STS-API-0139, which
//      this job pinned), and a row that does not read (0023);
//   I. issuance: the default policy issuing a read, the application's
//      policy disabled — the token endpoint's server_error (0006);
//   N. applications named `constructor`, `toString`, `valueOf`,
//      `hasOwnProperty`: XACML → Policies answers 200, and STS-API-0140 is
//      not recorded (fga_owned_policy_names).
//
// (d), with the reason: 0003-0005, 0007, 0008, 0010-0013 need an entry or a
// policy no door writes (an appFgaPolicy naming a missing or another's
// policy, a policy that does not parse — the doors refuse each first) or a
// directory that refuses, which a request cannot cause; 0015 an
// Indeterminate the default policy never reaches; 0016 a process with no
// decider (the stack always installs one); 0100-0107 are the adapter's
// questions as functions (their outcomes are I's). Owed: 0014 (a policy
// denying delete at the token endpoint — `sts_fga.js` by status; writing
// the application's own policy as ALFA is not one import), 0017 (the
// exchange's bound, `sts_fga.js` by status), 0025 (a REMOTE_PEPS holder
// whose grant fails), fga_pep_grant's tab.
//
// OWNED HERE (local: true): the policies and the API are ours.
// ===========================================================================

const assert = require("assert");
const nodeCrypto = require("crypto");
const K = require("./oauth_wire_kit.js").kit("sts_fga_codes");

const log = K.log;
const check = K.check;
const TYPE = "fgc_document";
const LOCATION = "https://fgc-docs.example.net/api";
const DENY_DELETE = [
  "namespace fgcdeny {",
  "    attribute act { category = actionCat",
  "        id = \"urn:oasis:names:tc:xacml:1.0:action:action-id\"",
  "        type = string }",
  "    policy fgcDenyDelete {",
  "        id = \"urn:test:fgc-deny-delete\"",
  "        apply firstApplicable",
  "        rule noDelete { deny target clause act == \"delete\" }",
  "        rule rest { permit }",
  "    }",
  "}"
].join("\n");

let realm = null;
let DOCS = "";
const SECRET = "fgc-" + nodeCrypto.randomBytes(24).toString("base64url");

function api(path) {
  log.debug("Entering api().");
  log.debug("Leaving api().");
  return K.rb(realm) + "/admin-api" + path;
}

async function coded(code, what, act, verdict) {
  log.debug("Entering coded(). " + code);
  const c = await K.coded(realm, code, act);
  check(what + " (" + code + ")", function () {
    (verdict || function (r) {
      assert.ok(r.status >= 400 || (r.json && r.json.ok === false),
                K.shown(r));
    })(c.answer);
    assert.ok(c.rose >= 1, code + " rose " + c.rose);
  });
  log.debug("Leaving coded().");
  return c.answer;
}

async function fgaOf(identifier) {
  log.debug("Entering fgaOf().");
  const r = await K.send(api("/applications?application=" +
                             encodeURIComponent(identifier)));
  log.debug("Leaving fgaOf().");
  return (r.json && r.json.page && r.json.page.fga) || {};
}

function typeBody(extraProperties) {
  log.debug("Entering typeBody().");
  const properties = { type: { const: TYPE },
                       locations: { type: "array",
                                    items: { type: "string" } },
                       actions: { type: "array",
                                  items: { type: "string" } },
                       identifier: { type: "string" },
                       classification: { type: "string" },
                       note: { type: "string" } };
  Object.assign(properties, extraProperties || {});
  log.debug("Leaving typeBody().");
  return { application: DOCS, type: TYPE, locations: [LOCATION],
           actions: ["read", "delete"],
           schema: { type: "object", additionalProperties: false,
                     properties: properties },
           xacml: [{ path: "classification",
                     attributeId: "urn:example:classification" }] };
}

function tokenFor(actions) {
  log.debug("Entering tokenFor().");
  log.debug("Leaving tokenFor().");
  return K.send(K.rb(realm) + "/oauth2/token", {
    headers: { Authorization: K.basic(DOCS, SECRET) },
    form: { grant_type: "client_credentials",
            authorization_details: JSON.stringify([{ type: TYPE,
              locations: [LOCATION], actions: actions, identifier: "d1",
              classification: "internal", note: "kept out" }]) } });
}

async function setUp() {
  log.debug("Entering setUp().");
  realm = await K.realm("fgc", "development");
  DOCS = "fgc-docs-" + K.STAMP;
  await K.app(realm, DOCS, { oauthClientId: [DOCS],
    oauthClientSecret: SECRET, oauthGrantType: ["client_credentials"],
    oauthTokenEndpointAuthMethod: "client_secret_basic" },
    { protocols: ["oauth2"] });
  await K.ok(api("/applications/set-access-type"), typeBody(),
             "declared " + TYPE);
  log.debug("Leaving setUp().");
}

async function switchAndTypes() {
  log.debug("Entering switchAndTypes().");
  log.info("=== S. the switch and the types ===");
  await coded("STS-FGA-0018", "S1. enabling while a member is neither " +
              "mapped nor listed is refused", function () {
    return K.send(api("/applications/fga-enable"),
                  { json: { application: DOCS } });
  });
  await K.ok(api("/applications/set-not-for-policy"), { application: DOCS,
    type: TYPE, notForPolicy: ["note"] }, "note listed as not for policy");
  await K.ok(api("/applications/fga-enable"), { application: DOCS },
             "FGA enabled once covered");
  await coded("STS-FGA-0019", "S2. a type written to the enforcing " +
              "application leaving a member uncovered is refused",
              function () {
    return K.send(api("/applications/set-access-type"), { json: typeBody({
      colour: { type: "string" } }) });
  });
  // A 400 RECORDING STS-FGA-0023 (#40, 2026-11-15): the refusal's `field`
  // is a member of the operation's response model now. Until #40 the
  // answer was replaced by a 500 and STS-API-0139 (#1353's model gap), which
  // this check pinned.
  const before0139 = await K.codeCount(realm, "STS-API-0139");
  await coded("STS-FGA-0023", "S3. a mapping row removed that is not on " +
              "the type is refused 400, naming the path (#40)", function () {
    return K.send(api("/applications/remove-access-type-row"), { json: {
      application: DOCS, type: TYPE, path: "never-mapped" } });
  }, function (r) {
    assert.strictEqual(r.status, 400, K.shown(r));
    assert.strictEqual(r.json && r.json.ok, false, K.shown(r));
    assert.strictEqual(r.json && r.json.field, "path", K.shown(r));
  });
  // The sibling: set-access-type-row's refusal carries `field` too.
  await coded("STS-FGA-0023", "S3b. a mapping row that does not read is " +
              "refused 400, naming its member (#40)", function () {
    return K.send(api("/applications/set-access-type-row"), { json: {
      application: DOCS, type: TYPE, path: "classification",
      attributeId: "urn:example:c", category: "not-a-category" } });
  }, function (r) {
    assert.strictEqual(r.status, 400, K.shown(r));
    assert.ok(r.json && typeof r.json.field === "string", K.shown(r));
  });
  const after0139 = await K.codeCount(realm, "STS-API-0139");
  check("S3c. and neither is a model gap (no STS-API-0139)", function () {
    assert.strictEqual(after0139, before0139, before0139 + " -> " +
                       after0139);
  });
  log.debug("Leaving switchAndTypes().");
}

async function issuance(policy) {
  log.debug("Entering issuance().");
  log.info("=== I. issuance ===");
  const r = await tokenFor(["read"]);
  check("I0. the enforcing application's default policy issues a read",
        function () {
    assert.strictEqual(r.status, 200, K.shown(r));
  });
  await K.ok(api("/xacml/disable"), { name: policy },
             "disabled the application's policy");
  await coded("STS-FGA-0006", "I1. the application's policy disabled: the " +
              "token endpoint answers server_error", function () {
    return tokenFor(["read"]);
  }, function (one) {
    assert.ok(one.status >= 400, K.shown(one));
  });
  await K.ok(api("/xacml/enable"), { name: policy },
             "enabled the application's policy again");
  log.debug("Leaving issuance().");
}

async function policies() {
  log.debug("Entering policies().");
  log.info("=== P. the policy an application owns ===");
  const fga = await fgaOf(DOCS);
  const policy = fga.reference || (fga.policy && fga.policy.name) || "";
  assert.ok(policy, "the application has a policy: " + JSON.stringify(fga));
  await coded("STS-FGA-0002", "P1. the application's policy made the " +
              "repository root is refused", function () {
    return K.send(api("/xacml/set-root"), { json: { name: policy } });
  });
  await coded("STS-FGA-0022", "P2. the application's policy deleted " +
              "while the application names it is refused", function () {
    return K.send(api("/xacml/delete"), { json: { name: policy } });
  });
  await coded("STS-FGA-0020", "P3. the reset to the template, " +
              "unconfirmed, is refused", function () {
    return K.send(api("/applications/fga-reset-policy"),
                  { json: { application: DOCS } });
  });
  await coded("STS-FGA-0009", "P4. an act naming an application the " +
              "registry does not hold is refused", function () {
    return K.send(api("/applications/fga-enable"),
                  { json: { application: "fgc-nobody-" + K.STAMP } });
  });
  await K.set(realm, "xacml.maxApplicationPolicies", 1);
  const extra = "fgc-extra-" + K.STAMP;
  // The create stands without a policy (its hook only logs); the act that
  // asks for one is refused with the code.
  const made = await K.send(api("/applications/create"), { json: {
    identifier: extra, name: extra, protocols: ["oauth2"],
    fields: { oauthClientId: [extra] } } });
  assert.strictEqual(made.status, 200, K.shown(made));
  const extraFga = await fgaOf(extra);
  check("P5. past xacml.maxApplicationPolicies the application is made " +
        "and its policy is not", function () {
    assert.ok(!extraFga.reference, JSON.stringify(extraFga).slice(0, 300));
  });
  await coded("STS-FGA-0024", "P6. and asking for its policy is refused",
              function () {
    return K.send(api("/applications/fga-create-policy"),
                  { json: { application: extra } });
  });
  await coded("STS-FGA-0021", "P7. resetting the policy of an application " +
              "that has none is refused", function () {
    return K.send(api("/applications/fga-reset-policy"),
                  { json: { application: extra, confirm: true } });
  });
  await K.unset(realm, "xacml.maxApplicationPolicies");
  log.debug("Leaving policies().");
  return policy;
}

async function names() {
  log.debug("Entering names().");
  log.info("=== N. applications named like a property of every object ===");
  for (const one of ["constructor", "toString", "valueOf",
                     "hasOwnProperty"]) {
    await K.ok(api("/applications/create"), { identifier: one, name: one,
      protocols: ["oauth2"], fields: { oauthClientId: [one] } },
      "created " + one);
  }
  const c = await K.coded(realm, "STS-API-0140", function () {
    return K.send(api("/xacml/policies"));
  });
  check("N1. XACML → Policies answers 200 with those applications' " +
        "policies, and STS-API-0140 is not recorded", function () {
    assert.strictEqual(c.answer.status, 200, K.shown(c.answer));
    assert.strictEqual(c.rose, 0);
    assert.ok(/constructor/.test(c.answer.text));
  });
  log.debug("Leaving names().");
}

async function test() {
  log.debug("Entering test().");
  await setUp();
  await switchAndTypes();
  const policy = await policies();
  await issuance(policy);
  await names();
  log.debug("Leaving test().");
}

K.main(test, 13);
