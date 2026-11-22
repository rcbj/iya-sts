// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_xacml_service.js
//
// ===========================================================================
// THE STORE, THE PIP AND THE JSON PROFILE, OVER THE WIRE (#444 D12 phase 8).
//
// `tests/xacml_service.js` holds the half of XACML that is not the engine
// in process: the store's round trip through LDAP, its write-time
// refusals, the PIP's mapping, the decisions it feeds, the JSON Profile's
// number types, bags and short datatypes, and the response shape.
// `sts_xacml_endpoints.js` (vendored) drives the seven endpoints by
// status. This job asks the same questions of a running service, in a
// development realm whose repository it wrote, through `/admin-api/xacml`
// and `POST /xacml/pdp` with a client certificate holding XACML_USER:
//
//   R. the repository: an imported policy listed with its PolicyId (not
//      its entry name), kind Policy, enabled, the root because the
//      repository had none; a second one not the root; set-root moving
//      the flag; ALFA that does not parse (STS-XACML-0037), a policy that
//      fails static type checking (STS-XACML-0028) and a bad entry name
//      (STS-XACML-0029) refused at write;
//   P. the PIP: a bare AttributeId and the `urn:sts:xacml:attribute:`
//      prefix read the person's directory entry (defects 1 and 2), a
//      person with no entry is denied, and an attribute the request
//      asserts wins over the directory;
//   J. the JSON Profile: an integer and a double (defect 4), an array as
//      a bag of three, the short datatype `date`, and a body with no
//      Request member refused (400) rather than decided;
//   S. the response: a Response array of one Result, a Decision of the
//      four, a status code.
//
// (d), with the reason: a second root written beside the first (STS-
// XACML-0030) — every door clears the old flag first (import-alfa sets the
// root only when there is none, set-root clears it), so no request writes
// two; `pip.available()` is the slot (its outcome is P's decisions); the
// embedded PEP's undischargeable obligation is `sts_xacml_endpoints.js`'s
// (anUndischargeableObligationRefuses).
//
// OWNED HERE (local: true): the XACML surface and the API are ours.
// ===========================================================================

const assert = require("assert");
const https = require("https");
const K = require("./oauth_wire_kit.js").kit("sts_xacml_service");
const credentials = require("../tools/pep-credential.js");
const serviceTrust = require("../tools/service_trust.js");

const log = K.log;
const check = K.check;
const SUBJECT_ID = "urn:oasis:names:tc:xacml:1.0:subject:subject-id";
const ACTION_ID = "urn:oasis:names:tc:xacml:1.0:action:action-id";
const POLICY = [
  "namespace xsv {",
  "    attribute act { category = actionCat id = \"" + ACTION_ID + "\"",
  "        type = string }",
  "    attribute et { category = subjectCat id = \"employeeType\"",
  "        type = string }",
  "    attribute dept { category = subjectCat",
  "        id = \"urn:sts:xacml:attribute:departmentNumber\" type = string }",
  "    attribute count { category = resourceCat id = \"urn:test:count\"",
  "        type = integer }",
  "    attribute ratio { category = resourceCat id = \"urn:test:ratio\"",
  "        type = double }",
  "    attribute tags { category = resourceCat id = \"urn:test:tags\"",
  "        type = string }",
  "    attribute when { category = resourceCat id = \"urn:test:when\"",
  "        type = date }",
  "    policy xsvRoot {",
  "        id = \"urn:test:xsv-root\"",
  "        apply denyUnlessPermit",
  "        rule staffGet { permit target clause act == \"GET\"",
  "            and et == \"staff\" }",
  "        rule adminDelete { permit target clause act == \"DELETE\"",
  "            and et == \"admin\" }",
  "        rule deptRead { permit target clause act == \"READ\"",
  "            and dept == \"xsv-42\" }",
  "        rule five { permit target clause act == \"count\"",
  "            condition integerEqual(integerOneAndOnly(count), 5) }",
  "        rule half { permit target clause act == \"ratio\"",
  "            condition doubleGreaterThan(doubleOneAndOnly(ratio), 5.0) }",
  "        rule three { permit target clause act == \"bag\"",
  "            condition integerEqual(stringBagSize(tags), 3) }",
  "        rule day { permit target clause act == \"when\"",
  "            condition dateEqual(dateOneAndOnly(when),",
  "                date(\"2026-09-04\")) }",
  "    }",
  "}"
].join("\n");
const SECOND = [
  "namespace xsvtwo {",
  "    policy xsvTwo {",
  "        id = \"urn:test:xsv-two\"",
  "        apply denyUnlessPermit",
  "        rule all { permit }",
  "    }",
  "}"
].join("\n");
const UNTYPED = [
  "namespace xsvbad {",
  "    policy xsvBad {",
  "        id = \"urn:test:xsv-bad\"",
  "        apply denyUnlessPermit",
  "        rule r { permit condition integerEqual(integerAdd(1, \"2\"), 3) }",
  "    }",
  "}"
].join("\n");

let realm = null;
let PREFIX = "";
let user = null;
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

// POST /xacml/pdp in the realm with the XACML_USER certificate.
function pdp(payload) {
  log.debug("Entering pdp().");
  return new Promise(function (resolve, reject) {
    const target = new URL(K.base + PREFIX + "/xacml/pdp");
    const data = typeof payload === "string" ? payload
      : JSON.stringify(payload);
    const request = https.request({
      host: target.hostname, port: target.port || 443,
      path: target.pathname, method: "POST", ca: serviceTrust.trustedCa(),
      cert: user.certPem, key: user.keyPem,
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
          log.debug("Caught in pdp(): " + ((e && e.message) || e));
          // Not JSON: the caller reads the status and the text.
          body = null;
        }
        log.debug("Leaving pdp(). " + response.statusCode);
        resolve({ status: response.statusCode, json: body, text: text });
      });
    });
    request.on("error", reject);
    request.write(data);
    request.end();
  });
}

function ask(subject, action, subjectExtra, resource) {
  log.debug("Entering ask().");
  const request = { Request: {
    Action: { Attribute: [{ AttributeId: ACTION_ID, Value: action }] } } };
  if (subject) {
    request.Request.AccessSubject = { Attribute: [
      { AttributeId: SUBJECT_ID, Value: subject }].concat(
      subjectExtra || []) };
  }
  if (resource) {
    request.Request.Resource = { Attribute: resource };
  }
  log.debug("Leaving ask().");
  return pdp(request);
}

function decisionOf(r) {
  log.debug("Entering decisionOf().");
  log.debug("Leaving decisionOf().");
  return r.json && Array.isArray(r.json.Response) && r.json.Response[0]
    ? r.json.Response[0].Decision : "(" + r.status + " " +
      String(r.text).slice(0, 300) + ")";
}

async function decides(what, expected, asking) {
  log.debug("Entering decides(). " + what);
  const r = await asking;
  check(what, function () {
    assert.strictEqual(decisionOf(r), expected, r.text.slice(0, 400));
  });
  log.debug("Leaving decides().");
  return r;
}

async function coded(code, what, body) {
  log.debug("Entering coded(). " + code);
  const c = await K.coded(realm, code, function () {
    return K.send(api("/xacml/import-alfa"), { json: body });
  });
  check(what + " (" + code + ")", function () {
    assert.strictEqual(c.answer.status, 400, K.shown(c.answer));
    assert.ok(c.rose >= 1, code + " rose " + c.rose);
  });
  log.debug("Leaving coded().");
}

async function policyRows() {
  log.debug("Entering policyRows().");
  const r = await K.send(api("/xacml/policies"));
  assert.strictEqual(r.status, 200, K.shown(r));
  log.debug("Leaving policyRows().");
  return (r.json && r.json.policies) || [];
}

function rowOf(rows, name) {
  log.debug("Entering rowOf().");
  log.debug("Leaving rowOf().");
  return rows.filter(function (one) {
    return one.name === name;
  })[0] || null;
}

async function setUp() {
  log.debug("Entering setUp().");
  realm = await K.realm("xsv", "development");
  PREFIX = "/realm/" + realm;
  for (const one of [["xsv-ann", "staff", "xsv-1"],
                     ["xsv-bob", "admin", "xsv-42"]]) {
    await K.ok(api("/users/create"), { username: one[0], invent: false,
      attributes: { cn: one[0], sn: one[0], givenName: one[0],
                    mail: one[0] + "@xsv.example", employeeType: one[1],
                    departmentNumber: one[2] } }, "created " + one[0]);
  }
  const cn = "xsv-user-" + K.STAMP;
  user = await credentials.mint({ subject: "CN=" + cn +
                                  ",OU=xacml,O=iya-sts tests" });
  const posted = await credentials.trustRecorded(K.base, user.anchorPem,
                                                 added);
  assert.ok(posted.ok, "the client truststore took the test Root: " +
            posted.status);
  const io = { get: get, post: post };
  for (const prefix of [PREFIX, ""]) {
    stored.push(await credentials.storeOnEntry(io, K.base, prefix, cn,
                                               user.leaf.pem));
    await K.ok(K.base + prefix + "/admin-api/groups/add-member",
               { group: "xacml-users", member: cn },
               "the caller in xacml-users" + (prefix ? " (realm)" : ""));
  }
  log.debug("Leaving setUp().");
}

async function repository() {
  log.debug("Entering repository().");
  log.info("=== R. the repository ===");
  const before = await policyRows();
  const imported = await K.send(api("/xacml/import-alfa"), { json: {
    name: "xsv-root", alfa: POLICY } });
  check("R1. a policy imported into an empty repository is made its root",
        function () {
    assert.strictEqual(before.length, 0, JSON.stringify(before));
    assert.strictEqual(imported.status, 200, K.shown(imported));
    assert.ok(/It is the root/.test(imported.json.what), imported.text);
  });
  await K.ok(api("/xacml/import-alfa"), { name: "xsv-two", alfa: SECOND },
             "imported a second policy");
  let rows = await policyRows();
  const root = rowOf(rows, "xsv-root");
  const two = rowOf(rows, "xsv-two");
  check("R2. the listed row carries its PolicyId apart from its entry " +
        "name, kind Policy, enabled, and the root flag", function () {
    assert.ok(root && two, JSON.stringify(rows).slice(0, 600));
    assert.strictEqual(root.policyId, "urn:test:xsv-root",
                       JSON.stringify(root));
    assert.strictEqual(root.kind, "Policy", JSON.stringify(root));
    assert.strictEqual(root.enabled, true, JSON.stringify(root));
    assert.strictEqual(root.isRoot, true, JSON.stringify(root));
  });
  check("R3. the second policy is not the root", function () {
    assert.strictEqual(two.isRoot, false, JSON.stringify(two));
  });
  await K.ok(api("/xacml/set-root"), { name: "xsv-two" }, "moved the root");
  rows = await policyRows();
  check("R4. set-root moves the flag: one root, never two", function () {
    const roots = rows.filter(function (one) {
      return one.isRoot;
    }).map(function (one) {
      return one.name;
    });
    assert.deepStrictEqual(roots, ["xsv-two"], JSON.stringify(rows));
  });
  await K.ok(api("/xacml/set-root"), { name: "xsv-root" },
             "moved the root back");
  await coded("STS-XACML-0037", "R5. ALFA that does not parse is refused",
              { name: "xsv-junk", alfa: "this is not ALFA {" });
  await coded("STS-XACML-0028", "R6. a policy that parses and fails static " +
              "type checking is refused at write rather than going " +
              "Indeterminate on every request",
              { name: "xsv-bad", alfa: UNTYPED });
  await coded("STS-XACML-0029", "R7. an entry name that is not 1 to 128 " +
              "letters, digits, dot, dash or underscore is refused",
              { name: "xsv bad name!", alfa: SECOND });
  rows = await policyRows();
  check("R8. none of the refused writes is in the repository", function () {
    assert.deepStrictEqual(rows.map(function (one) {
      return one.name;
    }).sort(), ["xsv-root", "xsv-two"], JSON.stringify(rows));
  });
  log.debug("Leaving repository().");
}

async function throughThePip() {
  log.debug("Entering throughThePip().");
  log.info("=== P. decisions through the PIP ===");
  await decides("P1. ann is staff IN THE DIRECTORY and may GET (a bare " +
                "AttributeId is a directory attribute)", "Permit",
                ask("xsv-ann", "GET"));
  await decides("P2. staff may not DELETE", "Deny", ask("xsv-ann", "DELETE"));
  await decides("P3. bob is admin in the directory and may DELETE",
                "Permit", ask("xsv-bob", "DELETE"));
  await decides("P4. somebody with no directory entry is denied", "Deny",
                ask("xsv-nobody", "GET"));
  await decides("P5. the urn:sts:xacml:attribute: prefix names a directory " +
                "attribute too", "Permit", ask("xsv-bob", "READ"));
  await decides("P6. and ann's departmentNumber is not bob's", "Deny",
                ask("xsv-ann", "READ"));
  await decides("P7. an attribute asserted in the request overrides the " +
                "directory", "Permit", ask("xsv-ann", "DELETE",
                [{ AttributeId: "employeeType", Value: "admin" }]));
  log.debug("Leaving throughThePip().");
}

async function jsonProfile() {
  log.debug("Entering jsonProfile().");
  log.info("=== J. the JSON Profile ===");
  await decides("J1. a JSON number with no fractional part is an integer",
                "Permit", ask("xsv-ann", "count", null,
                [{ AttributeId: "urn:test:count", Value: 5 }]));
  await decides("J2. a JSON number with one is a double", "Permit",
                ask("xsv-ann", "ratio", null,
                [{ AttributeId: "urn:test:ratio", Value: 5.5 }]));
  await decides("J3. an integer where the policy reads a double is not one",
                "Deny", ask("xsv-ann", "ratio", null,
                [{ AttributeId: "urn:test:ratio", Value: 6 }]));
  await decides("J4. an array Value is a bag of three rather than one " +
                "array", "Permit", ask("xsv-ann", "bag", null,
                [{ AttributeId: "urn:test:tags", Value: ["a", "b", "c"] }]));
  await decides("J5. the short datatype name \"date\" resolves to the XML " +
                "Schema URI", "Permit", ask("xsv-ann", "when", null,
                [{ AttributeId: "urn:test:when", Value: "2026-09-04",
                   DataType: "date" }]));
  const r = await pdp({ NotARequest: {} });
  check("J6. a body with no Request member is refused rather than decided",
        function () {
    assert.strictEqual(r.status, 400, r.status + " " + r.text.slice(0, 300));
  });
  log.debug("Leaving jsonProfile().");
}

async function responseShape() {
  log.debug("Entering responseShape().");
  log.info("=== S. the response ===");
  const r = await ask("xsv-ann", "GET");
  check("S1. a JSON Profile response holds an array of one Result, a " +
        "Decision of the four and a status code", function () {
    assert.ok(Array.isArray(r.json.Response) && r.json.Response.length === 1,
              r.text.slice(0, 300));
    const one = r.json.Response[0];
    assert.ok(["Permit", "Deny", "NotApplicable",
               "Indeterminate"].indexOf(one.Decision) >= 0, r.text);
    assert.ok(one.Status && one.Status.StatusCode &&
              one.Status.StatusCode.Value, r.text);
  });
  log.debug("Leaving responseShape().");
}

async function test() {
  log.debug("Entering test().");
  try {
    await setUp();
    await repository();
    await throughThePip();
    await jsonProfile();
    await responseShape();
  } finally {
    await credentials.forgetStored({ get: get, post: post }, K.base, stored);
    await credentials.settleAnchors(K.base, added, null);
  }
  log.debug("Leaving test().");
}

K.main(test, 22);
