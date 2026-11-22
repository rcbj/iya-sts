// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_authzen_codes.js
//
// ===========================================================================
// THE AUTHZEN MAPPING CONTRACT, THE DOORS AND THE BATCH, EACH REFUSAL BY
// ITS CODE, OVER THE WIRE (#444 D12 phase 8; #563, #1160-#1165).
//
// `tests/authzen_map.js`, `tests/authzen_evaluation.js` and
// `tests/authzen_admin.js` hold the mapping as functions and the doors in a
// child process; `sts_authzen.js` asks a running service by status and
// decision. This job adds the code each refusal records on
// `/admin-api/audit`, in a development realm whose catalogue and root
// policy it writes, the caller a person in `authzen-peps` presenting a
// client certificate from an authority this job makes
// (`tools/pep-credential.js`, posted to the client truststore and removed
// at the end):
//
//   M. the catalogue and the tab's acts: an unknown member
//      (STS-AUTHZEN-0010), a reserved identifier however cased (0011), a
//      subject property under a bare directory attribute name (0012), an
//      unknown act (0030), a remove of no row (0031), a scope of 65
//      applications (0032) and of nobody (0033);
//   E. the evaluation: not an object (0001), no subject (0002), a wrong
//      JSON type (0003), an undeclared property (0004), null (0005), a
//      value that does not fit its datatype (0006), an array for a single
//      row (0007), an object for a value (0008), no certificate (0015), a
//      caller without AUTHZEN_PEPS (0024), an application out of scope
//      (0025), a caller scoped to several naming none (0027) and one
//      scoped to none (0026), a processing error answered 500 (0028), the
//      API switched off (0013);
//   B. the batch: an unknown semantic (0036), more items than
//      authzen.maxEvaluations (0038), a body over authzen.maxBodyBytes
//      (0037), the batch switched off (0039);
//   D. the metadata naming no PDP (0035);
//   R. the access request and approval profile (authzen_access_request):
//      a request that is not an object of the three (0071), with no denial
//      (0072), for another subject than its denial's (0074), with a
//      callback not registered (0079); the 202 task; an Idempotency-Key
//      reused for another body (0076); the task asked by another caller
//      (0080); approved through `/admin-api`, approved again (0089),
//      cancelled once terminal (0082); an approval this realm cannot
//      resolve not used (0084); the profile off (0070).
//
// (d), with the reason: authzen_map's grammar defaults and the request
// builder's XACML output are functions (their outcomes are E's decisions);
// 0016 and 0017 need a certificate that does not verify, or one verified
// and stored nowhere, which the truststore's handshake refuses before the
// door on this listener; the bearer modes (0018-0023) are
// `sts_authzen_conformance.js`'s.
//
// OWNED HERE (local: true): the AuthZEN API is ours.
// ===========================================================================

const assert = require("assert");
const https = require("https");
const K = require("./oauth_wire_kit.js").kit("sts_authzen_codes");
const credentials = require("../tools/pep-credential.js");
const serviceTrust = require("../tools/service_trust.js");

const log = K.log;
const check = K.check;
const APPLICATION = "azc-todo";
const POLICY = [
  "namespace azc {",
  "    attribute act { category = actionCat",
  "        id = \"urn:oasis:names:tc:xacml:1.0:action:action-id\"",
  "        type = string }",
  "    attribute tags { category = resourceCat id = \"urn:example:tags\"",
  "        type = string }",
  "    attribute approval { category = environmentCat",
  "        id = \"urn:sts:xacml:authzen:approval-id\" type = string }",
  "    policy azcRoot {",
  "        id = \"urn:test:azc-root\"",
  "        apply firstApplicable",
  "        rule read { permit target clause act == \"read\" }",
  "        rule approvedPublish {",
  "            permit",
  "            target clause act == \"publish\"",
  "            condition integerGreaterThan(stringBagSize(approval), 0)",
  "        }",
  "        rule requestablePublish {",
  "            deny",
  "            target clause act == \"publish\"",
  "            on deny {",
  "                advice \"urn:sts:xacml:advice:access-request\" {",
  "                    \"urn:sts:xacml:advice:access-request:approver-group\"",
  "                        = \"azc-approvers\"",
  "                }",
  "            }",
  "        }",
  "        rule explode {",
  "            permit",
  "            target clause act == \"explode\"",
  "            condition stringEqual(stringOneAndOnly(tags), \"x\")",
  "        }",
  "    }",
  "}"
].join("\n");

let realm = null;
let PREFIX = "";
const added = [];
const stored = [];
let caller = null;
let rogue = null;
let lonely = null;

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

// One request with a client certificate, as an AuthZEN PEP sends it.
function pep(method, path, identity, payload, extra) {
  log.debug("Entering pep(). " + method + " " + path);
  return new Promise(function (resolve, reject) {
    const target = new URL(K.base + path);
    const data = payload === undefined ? null
      : (typeof payload === "string" ? payload : JSON.stringify(payload));
    const request = https.request({
      host: target.hostname, port: target.port || 443,
      path: target.pathname + target.search, method: method,
      ca: serviceTrust.trustedCa(),
      cert: identity ? identity.certPem : undefined,
      key: identity ? identity.keyPem : undefined,
      headers: Object.assign(data ? { "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(data) } : {}, extra || {})
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
    if (data) {
      request.write(data);
    }
    request.end();
  });
}

function question(extra) {
  log.debug("Entering question().");
  log.debug("Leaving question().");
  return Object.assign({ subject: { type: "user", id: "azc-ann" },
                         action: { name: "read" },
                         resource: { type: "todo", id: "t1" },
                         context: { application: APPLICATION } },
                       extra || {});
}

async function coded(code, what, act, verdict) {
  log.debug("Entering coded(). " + code);
  const c = await K.coded(realm, code, act);
  check(what + " (" + code + ")", function () {
    verdict(c.answer);
    assert.ok(c.rose >= 1, code + " rose " + c.rose);
  });
  log.debug("Leaving coded().");
  return c.answer;
}

function status(n) {
  log.debug("Entering status().");
  log.debug("Leaving status().");
  return function (r) {
    assert.strictEqual(r.status, n, r.status + " " +
                       String(r.text).slice(0, 300));
  };
}

function api(path) {
  log.debug("Entering api().");
  log.debug("Leaving api().");
  return K.rb(realm) + "/admin-api" + path;
}

async function setUp() {
  log.debug("Entering setUp().");
  realm = await K.realm("azc", "development");
  PREFIX = "/realm/" + realm;
  await K.send(api("/users/create"), { json: { username: "azc-ann",
    invent: false, attributes: { cn: "ann", sn: "ann", givenName: "ann",
                                 mail: "ann@azc.example" } } });
  const stamp = K.STAMP;
  caller = await credentials.mint({ subject: "CN=azc-pep-" + stamp +
                                    ",OU=authzen,O=iya-sts tests" });
  rogue = await credentials.mint({ subject: "CN=azc-rogue-" + stamp +
                                   ",OU=authzen,O=iya-sts tests" });
  lonely = await credentials.mint({ subject: "CN=azc-lonely-" + stamp +
                                    ",OU=authzen,O=iya-sts tests" });
  for (const one of [caller, rogue, lonely]) {
    const posted = await credentials.trustRecorded(K.base, one.anchorPem,
                                                   added);
    assert.ok(posted.ok, "the client truststore took the test Root: " +
              posted.status);
  }
  const io = { get: get, post: post };
  stored.push(await credentials.storeOnEntry(io, K.base, PREFIX,
    "azc-pep-" + stamp, caller.leaf.pem));
  stored.push(await credentials.storeOnEntry(io, K.base, PREFIX,
    "azc-rogue-" + stamp, rogue.leaf.pem));
  stored.push(await credentials.storeOnEntry(io, K.base, PREFIX,
    "azc-lonely-" + stamp, lonely.leaf.pem));
  await K.ok(api("/groups/add-member"), { group: "authzen-peps",
    member: "azc-pep-" + stamp }, "the caller in authzen-peps");
  await K.ok(api("/groups/add-member"), { group: "authzen-peps",
    member: "azc-lonely-" + stamp }, "a scopeless caller in authzen-peps");
  await K.ok(api("/xacml/authzen/set-scope"), { caller: "azc-pep-" + stamp,
    applications: [APPLICATION, "azc-wiki"] }, "the caller's scope");
  for (const row of [
    { object: "resource", property: "tags", multiplicity: "bag",
      attributeId: "urn:example:tags" },
    { object: "resource", property: "priority", dataType: "integer",
      attributeId: "urn:example:priority" },
    { object: "resource", property: "label",
      attributeId: "urn:example:label" }]) {
    await K.ok(api("/xacml/authzen/set-attribute"), row,
               "declared " + row.property);
  }
  await K.ok(api("/xacml/import-alfa"), { name: "azc-root", alfa: POLICY },
             "imported the root policy");
  await K.ok(api("/xacml/set-root"), { name: "azc-root" }, "set the root");
  log.debug("Leaving setUp().");
}

async function catalogue() {
  log.debug("Entering catalogue().");
  log.info("=== M. the catalogue and the tab's acts ===");
  const door = function (action, body) {
    log.debug("Entering door(). " + action);
    log.debug("Leaving door().");
    return K.send(api("/xacml/authzen/" + action), { json: body });
  };
  // The operation's request model refuses an unknown member, and a list of
  // 65, before the door's own reading (STS-API-0009, the wire's half).
  await coded("STS-API-0009", "M1. a catalogue row with a member the " +
              "row does not take is refused", function () {
    return door("set-attribute", { object: "resource", property: "x1",
      attributeId: "urn:example:x1", colour: "blue" });
  }, function (r) {
    assert.ok(r.status >= 400, K.shown(r));
  });
  await coded("STS-AUTHZEN-0011", "M2. a row onto urn:sts:xacml:, however " +
              "cased, is refused as reserved", function () {
    return door("set-attribute", { object: "resource", property: "x2",
      attributeId: "URN:STS:XACML:protocol" });
  }, function (r) {
    assert.ok(r.status >= 400, K.shown(r));
  });
  await coded("STS-AUTHZEN-0012", "M3. a subject property under a bare " +
              "directory attribute name is refused", function () {
    return door("set-attribute", { object: "subject", property: "mail",
                                   attributeId: "mail" });
  }, function (r) {
    assert.ok(r.status >= 400, K.shown(r));
  });
  await coded("STS-AUTHZEN-0030", "M4. an act the tab does not have is " +
              "refused", function () {
    return door("teleport", {});
  }, function (r) {
    assert.ok(r.status >= 400, K.shown(r));
  });
  await coded("STS-AUTHZEN-0031", "M5. remove-attribute of no row is " +
              "refused", function () {
    return door("remove-attribute", { object: "resource",
                                      property: "never-declared" });
  }, function (r) {
    assert.ok(r.status >= 400, K.shown(r));
  });
  const many = [];
  for (let i = 0; i < 65; i += 1) {
    many.push("azc-app-" + i);
  }
  await coded("STS-API-0009", "M6. a scope of 65 applications is " +
              "refused", function () {
    return door("set-scope", { caller: "azc-pep-" + K.STAMP,
                               applications: many });
  }, function (r) {
    assert.ok(r.status >= 400, K.shown(r));
  });
  await coded("STS-AUTHZEN-0033", "M7. a scope for nobody in the realm is " +
              "refused", function () {
    return door("set-scope", { caller: "azc-nobody-" + K.STAMP,
                               applications: [APPLICATION] });
  }, function (r) {
    assert.ok(r.status >= 400, K.shown(r));
  });
  log.debug("Leaving catalogue().");
}

async function evaluation() {
  log.debug("Entering evaluation().");
  log.info("=== E. the evaluation ===");
  const EV = PREFIX + "/access/v1/evaluation";
  const r = await pep("POST", EV, caller, question());
  check("E0. a well-formed question is decided true", function () {
    assert.strictEqual(r.status, 200, r.text);
    assert.strictEqual(r.json.decision, true, r.text);
  });
  const cases = [
    ["STS-AUTHZEN-0001", "E1. a body that is not an object", "[1]", 400],
    ["STS-AUTHZEN-0002", "E2. no subject",
     { action: { name: "read" }, resource: { type: "todo", id: "t1" },
       context: { application: APPLICATION } }, 400],
    ["STS-AUTHZEN-0003", "E3. a subject id that is a number",
     question({ subject: { type: "user", id: 7 } }), 400],
    ["STS-AUTHZEN-0004", "E4. a property the catalogue does not declare",
     question({ resource: { type: "todo", id: "t1",
                            properties: { colour: "blue" } } }), 400],
    ["STS-AUTHZEN-0005", "E5. null for a property",
     question({ resource: { type: "todo", id: "t1",
                            properties: { label: null } } }), 400],
    ["STS-AUTHZEN-0006", "E6. a value that does not fit its datatype",
     question({ resource: { type: "todo", id: "t1",
                            properties: { priority: "high" } } }), 400],
    ["STS-AUTHZEN-0007", "E7. an array for a single row",
     question({ resource: { type: "todo", id: "t1",
                            properties: { label: ["a", "b"] } } }), 400],
    ["STS-AUTHZEN-0008", "E8. an object for a value",
     question({ resource: { type: "todo", id: "t1",
                            properties: { label: { x: 1 } } } }), 400],
    ["STS-AUTHZEN-0025", "E10. an application the caller is not scoped to",
     question({ context: { application: "azc-elsewhere" } }), 403],
    ["STS-AUTHZEN-0027", "E11. a caller scoped to several naming none",
     question({ context: {} }), 400]
  ];
  for (const one of cases) {
    await coded(one[0], one[1] + " is refused", function () {
      return pep("POST", EV, caller, one[2]);
    }, status(one[3]));
  }
  await coded("STS-AUTHZEN-0015", "E9. no client certificate is 401",
              function () {
    return pep("POST", EV, null, question());
  }, status(401));
  await coded("STS-AUTHZEN-0024", "E12. a caller whose entry lacks " +
              "AUTHZEN_PEPS is 403", function () {
    return pep("POST", EV, rogue, question());
  }, status(403));
  await coded("STS-AUTHZEN-0026", "E13. a caller scoped to no application " +
              "may ask about none", function () {
    return pep("POST", EV, lonely, question({ context: {} }));
  }, function (one) {
    assert.ok(one.status >= 400, one.text);
  });
  await coded("STS-AUTHZEN-0028", "E14. a processing error is answered " +
              "500, never false", function () {
    return pep("POST", EV, caller, question({ action: { name: "explode" },
      resource: { type: "todo", id: "t1",
                  properties: { tags: ["x", "y"] } } }));
  }, status(500));
  await K.set(realm, "authzen.enabled", false);
  await coded("STS-AUTHZEN-0013", "E15. a realm whose AuthZEN API is off " +
              "refuses", function () {
    return pep("POST", EV, caller, question());
  }, function (one) {
    assert.ok(one.status >= 400, one.text);
  });
  await K.unset(realm, "authzen.enabled");
  log.debug("Leaving evaluation().");
}

async function batch() {
  log.debug("Entering batch().");
  log.info("=== B. the batch, D. the metadata ===");
  const EVS = PREFIX + "/access/v1/evaluations";
  const items = function (n) {
    log.debug("Entering items().");
    const out = [];
    for (let i = 0; i < n; i += 1) {
      out.push({ resource: { type: "todo", id: "t" + i } });
    }
    log.debug("Leaving items().");
    return out;
  };
  const shared = { subject: { type: "user", id: "azc-ann" },
                   action: { name: "read" },
                   context: { application: APPLICATION } };
  await coded("STS-AUTHZEN-0036", "B1. an unknown evaluations_semantic is " +
              "refused", function () {
    return pep("POST", EVS, caller, Object.assign({ evaluations: items(2),
      options: { evaluations_semantic: "first_come" } }, shared));
  }, status(400));
  await K.set(realm, "authzen.maxEvaluations", 2);
  await coded("STS-AUTHZEN-0038", "B2. more items than " +
              "authzen.maxEvaluations is refused whole", function () {
    return pep("POST", EVS, caller, Object.assign({ evaluations: items(3) },
                                                  shared));
  }, function (one) {
    assert.ok(one.status >= 400, one.text);
  });
  await K.unset(realm, "authzen.maxEvaluations");
  await K.set(realm, "authzen.maxBodyBytes", 1024);
  await coded("STS-AUTHZEN-0037", "B3. a body over authzen.maxBodyBytes is " +
              "refused unread", function () {
    return pep("POST", EVS, caller, Object.assign({ evaluations: items(40) },
                                                  shared));
  }, function (one) {
    assert.ok(one.status >= 400, one.text);
  });
  await K.unset(realm, "authzen.maxBodyBytes");
  await K.set(realm, "authzen.batchEnabled", false);
  await coded("STS-AUTHZEN-0039", "B4. the batch switched off refuses",
              function () {
    return pep("POST", EVS, caller, Object.assign({ evaluations: items(1) },
                                                  shared));
  }, function (one) {
    assert.ok(one.status >= 400, one.text);
  });
  await K.unset(realm, "authzen.batchEnabled");
  const c = await K.coded(null, "STS-AUTHZEN-0035", function () {
    return K.send(K.base + "/.well-known/authzen-configuration/realm/" +
                  "azc-nowhere-" + K.STAMP);
  });
  check("D1. the metadata naming no PDP is 404 (STS-AUTHZEN-0035)",
        function () {
    assert.strictEqual(c.answer.status, 404, K.shown(c.answer));
    assert.ok(c.rose >= 1, "STS-AUTHZEN-0035 rose " + c.rose);
  });
  log.debug("Leaving batch().");
}

async function accessRequests() {
  log.debug("Entering accessRequests().");
  log.info("=== R. access requests and approvals (#1180) ===");
  const AR = PREFIX + "/access/v1/access-requests";
  await K.ok(api("/groups/create"), { group: "azc-approvers" },
             "the approvers' group");
  await K.ok(api("/xacml/authzen/set-scope"), { caller: "azc-lonely-" +
    K.STAMP, applications: [APPLICATION] }, "a second scoped caller");
  const asked = question({ action: { name: "publish" } });
  const denied = await pep("POST", PREFIX + "/access/v1/evaluation", caller,
                           asked);
  const ar = ((denied.json || {}).context || {}).access_request || {};
  check("R0. a publish without an approval is a requestable denial",
        function () {
    assert.strictEqual(denied.json && denied.json.decision, false,
                       denied.text);
    assert.ok(ar.binding_token && ar.expires_at, denied.text);
  });
  const denial = { expires_at: ar.expires_at,
                   binding_token: ar.binding_token };
  await coded("STS-AUTHZEN-0071", "R1. an access request that is not an " +
              "object of subject, resource and action is refused",
              function () {
    return pep("POST", AR, caller, { denial: denial });
  }, function (r) {
    assert.ok(r.status >= 400, r.text);
  });
  await coded("STS-AUTHZEN-0072", "R2. an access request carrying no " +
              "denial is refused", function () {
    return pep("POST", AR, caller, asked);
  }, function (r) {
    assert.ok(r.status >= 400, r.text);
  });
  await coded("STS-AUTHZEN-0074", "R3. an access request for another " +
              "subject than its denial's is refused", function () {
    return pep("POST", AR, caller, Object.assign({}, asked, {
      subject: { type: "user", id: "azc-somebody-else" },
      denial: denial }));
  }, function (r) {
    assert.ok(r.status >= 400, r.text);
  });
  await coded("STS-AUTHZEN-0079", "R4. a callback that is not an https " +
              "endpoint registered for the caller is refused", function () {
    return pep("POST", AR, caller, Object.assign({}, asked, {
      denial: denial, callback: { endpoint: "http://azc.example/cb" } }));
  }, function (r) {
    assert.ok(r.status >= 400, r.text);
  });
  const key = "azc-" + K.STAMP;
  const submitted = await pep("POST", AR, caller, Object.assign({}, asked,
    { denial: denial }), { "Idempotency-Key": key });
  const task = (submitted.json || {}).task || {};
  check("R5. the submission is 202 with a pending Task Handle", function () {
    assert.strictEqual(submitted.status, 202, submitted.text);
    assert.strictEqual(task.status, "pending");
  });
  await coded("STS-AUTHZEN-0076", "R6. the Idempotency-Key reused for a " +
              "different body is refused", function () {
    return pep("POST", AR, caller, Object.assign({}, asked, {
      denial: denial, context: { application: APPLICATION,
                                 business_justification: "other" } }),
               { "Idempotency-Key": key });
  }, function (r) {
    assert.ok(r.status >= 400, r.text);
  });
  await coded("STS-AUTHZEN-0080", "R7. the task asked about by a caller " +
              "who is not its requester is refused", function () {
    return pep("GET", new URL(String(task.status_endpoint)).pathname,
               lonely);
  }, function (r) {
    assert.ok(r.status >= 400, r.text);
  });
  await K.ok(api("/xacml/authzen/approve-access-request"),
             { request: task.id }, "approved the access request");
  await coded("STS-AUTHZEN-0089", "R8. an approval naming no pending " +
              "request is refused", function () {
    return K.send(api("/xacml/authzen/approve-access-request"),
                  { json: { request: task.id } });
  }, function (r) {
    assert.ok(r.status >= 400, K.shown(r));
  });
  await coded("STS-AUTHZEN-0082", "R9. cancelling a task already approved " +
              "is refused", function () {
    return pep("POST", new URL(String(task.status_endpoint)).pathname +
               "/cancel", caller, {});
  }, function (r) {
    assert.ok(r.status >= 400, r.text);
  });
  await coded("STS-AUTHZEN-0084", "R10. an approval this realm cannot " +
              "resolve is not used: the evaluation is false", function () {
    return pep("POST", PREFIX + "/access/v1/evaluation", caller,
               Object.assign({}, asked, { context: {
                 application: APPLICATION,
                 approval: { id: "apr_nothing-" + K.STAMP } } }));
  }, function (r) {
    assert.strictEqual(r.json && r.json.decision, false, r.text);
  });
  await K.set(realm, "authzen.accessRequests", false);
  await coded("STS-AUTHZEN-0070", "R11. the profile switched off refuses " +
              "an access request", function () {
    return pep("POST", AR, caller, Object.assign({}, asked,
                                                 { denial: denial }));
  }, function (r) {
    assert.ok(r.status >= 400, r.text);
  });
  await K.unset(realm, "authzen.accessRequests");
  log.debug("Leaving accessRequests().");
}

async function test() {
  log.debug("Entering test().");
  try {
    await setUp();
    await catalogue();
    await evaluation();
    await batch();
    await accessRequests();
  } finally {
    await credentials.forgetStored({ get: get, post: post }, K.base, stored);
    await credentials.settleAnchors(K.base, added, null);
  }
  log.debug("Leaving test().");
}

K.main(test, 40);
