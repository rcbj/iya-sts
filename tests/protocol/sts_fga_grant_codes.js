// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_fga_grant_codes.js
//
// ===========================================================================
// FINE-GRAINED AUTHORIZATION: THE REMOTE PEPS' GRANT, AND THE CODES
// `sts_fga_codes.js` LEFT, OVER THE WIRE (#444 D12 phase 8; #564, #1210).
//
// `tests/fga_pep_grant.js` holds the grant an enable makes to the realm's
// REMOTE_PEPS holders, and `fga_issuance.js` / `fga_authzen.js` the gate's
// refusals, in process; `sts_fga.js` drives them by status. This job adds,
// in a development realm with an application enforcing its own policy:
//
//   G. THE GRANT (#1210): a person holding REMOTE_PEPS before the enable
//      is granted membership of `authzen-peps` and the application in its
//      AuthZEN scope (read back on the tab's view); a second enable finds
//      it held, its scope neither doubled nor narrowed; disable removes
//      nothing; a holder added later is not granted retroactively, and a
//      re-enable grants it;
//   X. THE EXCHANGE'S BOUND: a token exchange asking a detail beyond the
//      subject token's is refused (STS-FGA-0017);
//   D. THE POLICY DENYING `delete`, imported in ALFA over the application's
//      own: the token endpoint refuses delete (STS-FGA-0014) and grants
//      read;
//   Z. AUTHZEN, as the granted holder: delete false and read true by the
//      application's policy; the policy disabled, an evaluation about the
//      application is 500 (STS-AUTHZEN-0046), never false.
//
// (d), with the reason: STS-FGA-0025 (a holder whose grant fails) needs a
// directory that refuses the write or a remote-peps member naming no entry
// — the group door refuses an unknown member and a deletion cleans its
// memberships (#1613), so no request leaves one; the audit rows per holder
// (`admin.authzen.pep.granted`) are read as the view's effect here.
//
// OWNED HERE (local: true): the policies and the API are ours. Posts two
// outside test Roots to the client truststore and removes them.
// ===========================================================================

const assert = require("assert");
const https = require("https");
const nodeCrypto = require("crypto");
const K = require("./oauth_wire_kit.js").kit("sts_fga_grant_codes");
const credentials = require("../tools/pep-credential.js");

const log = K.log;
const check = K.check;
const TYPE = "fgg_document";
const LOCATION = "https://fgg-docs.example.net/api";
const EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
// At issuance the question is `grant-authorization-detail` with the
// detail's action beside it; at access time the action itself
// (`sts_fga.js`'s NO_DELETE, docs/v1.1.0/fga.md's two examples in one
// document).
const DENY_DELETE = [
  "namespace fggdeny {",
  "    attribute act { category = actionCat",
  "        id = \"urn:oasis:names:tc:xacml:1.0:action:action-id\"",
  "        type = string }",
  "    attribute detailAction { category = actionCat",
  "        id = \"urn:sts:xacml:fga:detail:action\" type = string }",
  "    attribute stage { category = environmentCat",
  "        id = \"urn:sts:xacml:fga:stage\" type = string }",
  "    policy fggDenyDelete {",
  "        id = \"urn:test:fgg-deny-delete\"",
  "        apply firstApplicable",
  "        rule noDeleteDetail {",
  "            deny",
  "            target clause act == \"grant-authorization-detail\"",
  "            target clause detailAction == \"delete\"",
  "        }",
  "        rule noDeleteNow {",
  "            deny",
  "            target clause stage == \"access\"",
  "            target clause act == \"delete\"",
  "        }",
  "        rule rest { permit }",
  "    }",
  "}"
].join("\n");
const SECRET = "fgg-" + nodeCrypto.randomBytes(24).toString("base64url");

let realm = null;
let DOCS = "";
let holder = null;
const added = [];
const stored = [];

function api(path) {
  log.debug("Entering api().");
  log.debug("Leaving api().");
  return K.rb(realm) + "/admin-api" + path;
}

function get(url) {
  log.debug("Entering get().");
  log.debug("Leaving get().");
  return K.send(url).then(function (r) {
    return { status: r.status, body: r.json, text: r.text };
  });
}

function post(url, payload) {
  log.debug("Entering post().");
  log.debug("Leaving post().");
  return K.send(url, { json: payload || {} }).then(function (r) {
    return { status: r.status, body: r.json, text: r.text };
  });
}

function pep(path, payload) {
  log.debug("Entering pep(). " + path);
  return new Promise(function (resolve, reject) {
    const target = new URL(K.base + "/realm/" + realm + path);
    const data = JSON.stringify(payload);
    const request = https.request({
      host: target.hostname, port: target.port || 443,
      path: target.pathname, method: "POST", rejectUnauthorized: false,
      cert: holder.certPem, key: holder.keyPem,
      headers: { "Content-Type": "application/json",
                 "Content-Length": Buffer.byteLength(data) }
    }, function (response) {
      let text = "";
      response.on("data", function (chunk) {
        text += chunk;
      });
      response.on("end", function () {
        let body = null;
        try {
          body = JSON.parse(text);
        } catch (e) {
          log.debug("Caught in pep(): " + ((e && e.message) || e));
          // Not JSON: the caller reads the status and the text.
          body = null;
        }
        log.debug("Leaving pep(). " + response.statusCode);
        resolve({ status: response.statusCode, json: body, text: text });
      });
    });
    request.on("error", reject);
    request.write(data);
    request.end();
  });
}

function detail(actions) {
  log.debug("Entering detail().");
  log.debug("Leaving detail().");
  return { type: TYPE, locations: [LOCATION], actions: actions,
           identifier: "d1", classification: "internal", note: "kept out" };
}

function token(form) {
  log.debug("Entering token().");
  log.debug("Leaving token().");
  return K.send(K.rb(realm) + "/oauth2/token", {
    headers: { Authorization: K.basic(DOCS, SECRET) }, form: form });
}

function clientCredentials(actions) {
  log.debug("Entering clientCredentials().");
  log.debug("Leaving clientCredentials().");
  return token({ grant_type: "client_credentials",
                 authorization_details: JSON.stringify([detail(actions)]) });
}

function evaluate(action) {
  log.debug("Entering evaluate(). " + action);
  log.debug("Leaving evaluate().");
  return pep("/access/v1/evaluation", {
    subject: { type: "user", id: "fgg-ann" }, action: { name: action },
    resource: { type: "document", id: "d1" },
    context: { application: DOCS } });
}

async function coded(code, what, act, verdict) {
  log.debug("Entering coded(). " + code);
  const c = await K.coded(realm, code, act);
  check(what + " (" + code + ")", function () {
    verdict(c.answer);
    assert.ok(c.rose >= 1, code + " rose " + c.rose + " " +
              String(c.answer.text).slice(0, 300));
  });
  log.debug("Leaving coded().");
  return c.answer;
}

async function callerIn(name) {
  log.debug("Entering callerIn(). " + name);
  const r = await K.send(api("/xacml/authzen"));
  assert.strictEqual(r.status, 200, K.shown(r));
  log.debug("Leaving callerIn().");
  return ((r.json || {}).callers || []).filter(function (one) {
    return one.name === name;
  })[0] || null;
}

async function person(name, minted) {
  log.debug("Entering person(). " + name);
  stored.push(await credentials.storeOnEntry({ get: get, post: post },
    K.base, "/realm/" + realm, name, minted.leaf.pem));
  await K.ok(api("/groups/add-member"), { group: "remote-peps",
    member: name }, name + " in remote-peps");
  log.debug("Leaving person().");
}

async function setUp() {
  log.debug("Entering setUp().");
  realm = await K.realm("fgg", "development");
  DOCS = "fgg-docs-" + K.STAMP;
  await K.ok(api("/users/create"), { username: "fgg-ann", invent: false,
    attributes: { cn: "fgg-ann", sn: "fgg-ann", givenName: "fgg-ann",
                  mail: "fgg-ann@fgg.example" } }, "created fgg-ann");
  await K.app(realm, DOCS, { oauthClientId: [DOCS],
    oauthClientSecret: SECRET,
    oauthGrantType: ["client_credentials", EXCHANGE],
    oauthTokenEndpointAuthMethod: "client_secret_basic" },
    { protocols: ["oauth2"] });
  await K.ok(api("/applications/set-access-type"), { application: DOCS,
    type: TYPE, locations: [LOCATION], actions: ["read", "delete"],
    schema: { type: "object", additionalProperties: false, properties: {
      type: { const: TYPE },
      locations: { type: "array", items: { type: "string" } },
      actions: { type: "array", items: { type: "string" } },
      identifier: { type: "string" }, classification: { type: "string" },
      note: { type: "string" } } },
    xacml: [{ path: "classification",
              attributeId: "urn:example:classification" }] },
    "declared " + TYPE);
  await K.ok(api("/applications/set-not-for-policy"), { application: DOCS,
    type: TYPE, notForPolicy: ["note"] }, "note not for policy");
  for (const one of [["fgg-pep", "first"], ["fgg-late", "late"]]) {
    const minted = await credentials.mint({ subject: "CN=" + one[0] + "-" +
      K.STAMP + ",OU=remote-peps,O=iya-sts tests" });
    const posted = await credentials.trustRecorded(K.base, minted.anchorPem,
                                                   added);
    assert.ok(posted.ok, "the truststore took the test Root: " +
              posted.status);
    if (one[1] === "first") {
      holder = minted;
      await person(one[0], minted);
    } else {
      holder.late = minted;
    }
  }
  log.debug("Leaving setUp().");
}

async function grant() {
  log.debug("Entering grant().");
  log.info("=== G. the grant ===");
  const before = await callerIn("fgg-pep");
  await K.ok(api("/applications/fga-enable"), { application: DOCS },
             "FGA enabled");
  const granted = await callerIn("fgg-pep");
  check("G1. the enable grants the REMOTE_PEPS holder membership of " +
        "authzen-peps and the application in its scope", function () {
    assert.ok(!before || (before.applications || []).indexOf(DOCS) < 0,
              JSON.stringify(before));
    assert.ok(granted && (granted.applications || []).indexOf(DOCS) >= 0,
              JSON.stringify(granted));
  });
  const again = await K.send(api("/applications/fga-enable"), { json: {
    application: DOCS } });
  const held = await callerIn("fgg-pep");
  check("G2. a second enable finds it held: the scope neither doubled nor " +
        "narrowed", function () {
    assert.strictEqual(again.status, 200, K.shown(again));
    assert.deepStrictEqual(held.applications, granted.applications);
  });
  await K.ok(api("/applications/fga-disable"), { application: DOCS },
             "FGA disabled");
  const kept = await callerIn("fgg-pep");
  check("G3. disable removes nothing: the membership and scope are kept",
        function () {
    assert.ok(kept && (kept.applications || []).indexOf(DOCS) >= 0,
              JSON.stringify(kept));
  });
  await person("fgg-late", holder.late);
  const later = await callerIn("fgg-late");
  check("G4. a holder added later is not granted retroactively",
        function () {
    assert.ok(!later || (later.applications || []).indexOf(DOCS) < 0,
              JSON.stringify(later));
  });
  await K.ok(api("/applications/fga-enable"), { application: DOCS },
             "FGA enabled again");
  const now = await callerIn("fgg-late");
  check("G5. a re-enable grants it", function () {
    assert.ok(now && (now.applications || []).indexOf(DOCS) >= 0,
              JSON.stringify(now));
  });
  log.debug("Leaving grant().");
}

async function exchangeBound() {
  log.debug("Entering exchangeBound().");
  log.info("=== X. the exchange's bound ===");
  const r = await clientCredentials(["read"]);
  assert.strictEqual(r.status, 200, K.shown(r));
  const exchange = function (actions) {
    return token({ grant_type: EXCHANGE,
      subject_token: r.json.access_token,
      subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
      authorization_details: JSON.stringify([detail(actions)]) });
  };
  const same = await exchange(["read"]);
  check("X1. an exchange for the detail the subject token carries is " +
        "granted", function () {
    assert.strictEqual(same.status, 200, K.shown(same));
  });
  await coded("STS-FGA-0017", "X2. one asking beyond the subject token's " +
              "detail is refused", function () {
    return exchange(["read", "delete"]);
  }, function (one) {
    assert.ok(one.status >= 400, K.shown(one));
  });
  log.debug("Leaving exchangeBound().");
}

async function policyOf() {
  log.debug("Entering policyOf().");
  const r = await K.send(api("/applications?application=" +
                             encodeURIComponent(DOCS)));
  const fga = (r.json && r.json.page && r.json.page.fga) || {};
  log.debug("Leaving policyOf().");
  return fga.reference || (fga.policy && fga.policy.name) || "";
}

async function denyingDelete(policy) {
  log.debug("Entering denyingDelete().");
  log.info("=== D. a policy denying delete ===");
  // The repository needs a root first: an import into one with none is
  // made its root, which an application's policy may not be (STS-FGA-0001).
  await K.ok(api("/xacml/import-alfa"), { name: "fgg-root", alfa: [
    "namespace fggroot {", "    policy fggRoot {",
    "        id = \"urn:test:fgg-root\"", "        apply firstApplicable",
    "        rule all { permit }", "    }", "}"].join("\n") },
    "an ordinary root policy");
  await K.ok(api("/xacml/import-alfa"), { name: policy, alfa: DENY_DELETE },
             "the application's policy denies delete");
  await coded("STS-FGA-0014", "D1. the token endpoint refuses delete",
              function () {
    return clientCredentials(["delete"]);
  }, function (one) {
    assert.ok(one.status >= 400, K.shown(one));
  });
  const read = await clientCredentials(["read"]);
  check("D2. and grants read", function () {
    assert.strictEqual(read.status, 200, K.shown(read));
  });
  log.debug("Leaving denyingDelete().");
}

async function atAccessTime(policy) {
  log.debug("Entering atAccessTime().");
  log.info("=== Z. AuthZEN, as the granted holder ===");
  const del = await evaluate("delete");
  const read = await evaluate("read");
  check("Z1. the application's policy answers delete false and read true",
        function () {
    assert.strictEqual(del.json && del.json.decision, false, del.text);
    assert.strictEqual(read.json && read.json.decision, true, read.text);
  });
  await K.ok(api("/xacml/disable"), { name: policy }, "disabled the policy");
  await coded("STS-AUTHZEN-0046", "Z2. the policy disabled, an evaluation " +
              "about the application is 500, never false", function () {
    return evaluate("read");
  }, function (one) {
    assert.strictEqual(one.status, 500, one.status + " " + one.text);
  });
  await K.ok(api("/xacml/enable"), { name: policy }, "enabled the policy");
  log.debug("Leaving atAccessTime().");
}

async function test() {
  log.debug("Entering test().");
  try {
    await setUp();
    await grant();
    await exchangeBound();
    const policy = await policyOf();
    assert.ok(policy, "the application has a policy");
    await denyingDelete(policy);
    await atAccessTime(policy);
  } finally {
    await credentials.forgetStored({ get: get, post: post }, K.base, stored);
    await credentials.settleAnchors(K.base, added, null);
  }
  log.debug("Leaving test().");
}

K.main(test, 11);
