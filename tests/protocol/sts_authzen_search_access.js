// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_authzen_search_access.js
//
// ===========================================================================
// AUTHZEN SEARCH AND THE ACCESS REQUEST PROFILE'S REMAINING REFUSALS, BY
// CODE, OVER THE WIRE (#444 D12 phase 8; #1161, #1180).
//
// `sts_authzen_codes.js` carries `authzen_evaluation`'s and
// `authzen_access_request`'s refusals by code, less the ones this job
// adds, in a development realm with `authzen_model_wire.js`'s root policy
// (a read is permitted with an approval or on an internal document, and
// otherwise denied with requestable advice allowing emergency access):
//
//   S. SEARCH: a page that is not an object (STS-AUTHZEN-0042), a
//      page.token this search did not issue (0043), `authzen.searchEnabled`
//      off (0044), more candidates than `authzen.searchMaxCandidates` —
//      answered for the first only (0045);
//   R. ACCESS REQUESTS: a binding_token this realm did not issue (0073), a
//      denial past `authzen.accessRequestDenialLifetimeS` (30, its least)
//      and the 30 s skew (0075, 410 — the job waits a minute for it), past `authzen.accessRequestMaxPending`
//      (0078), emergency access with no business justification (0083); an
//      approval used for another tuple (0086), and revoked (0085), each
//      answered as a plain denial.
//
// (d), with the reason: 0073's other case — a denial with no binding_token
// — is refused by the request model's denial member first (WIRE: answered
// not_requestable under the model's code).
//
// OWNED HERE (local: true): the AuthZEN API is ours. Posts an outside test
// Root to the client truststore and removes it.
// ===========================================================================

const assert = require("assert");
const https = require("https");
const K = require("./oauth_wire_kit.js").kit("sts_authzen_search_access");
const credentials = require("../tools/pep-credential.js");

const log = K.log;
const check = K.check;
const ADVICE = "urn:sts:xacml:advice:access-request";
const POLICY = function (ns) {
  return [
    'namespace ' + ns + ' {',
    '    attribute act { category = actionCat',
    '        id = "urn:oasis:names:tc:xacml:1.0:action:action-id"',
    '        type = string }',
    '    attribute protocol { category = environmentCat',
    '        id = "urn:sts:xacml:protocol" type = string }',
    '    attribute classification { category = resourceCat',
    '        id = "urn:example:classification" type = string }',
    '    attribute tags { category = resourceCat id = "urn:example:tags"',
    '        type = string }',
    '    attribute rtype { category = resourceCat',
    '        id = "urn:sts:xacml:authzen:resource-type" type = string }',
    '    attribute approval { category = environmentCat',
    '        id = "urn:sts:xacml:authzen:approval-id" type = string }',
    '    policy ' + ns + 'Root {',
    '        id = "urn:test:' + ns + '-root"',
    '        apply firstApplicable',
    '        target clause protocol == "authzen"',
    '        rule approvedRead {',
    '            permit',
    '            target clause act == "read"',
    '            condition integerGreaterThan(stringBagSize(approval), 0)',
    '        }',
    '        rule readInternal {',
    '            permit',
    '            target clause act == "read"',
    '            target clause classification == "internal"',
    '        }',
    '        rule requestableRead {',
    '            deny',
    '            target clause act == "read"',
    '            on deny {',
    '                advice "' + ADVICE + '" {',
    '                    "' + ADVICE + ':approver-group" = "azwapprovers"',
    '                    "' + ADVICE + ':max-approval-seconds" = "3600"',
    '                    "' + ADVICE + ':emergency" = "true"',
    '                }',
    '            }',
    '        }',
    '        rule noDelete {',
    '            deny',
    '            target clause act == "delete"',
    '        }',
    '        rule inspectApplications {',
    '            permit',
    '            target clause act == "inspect"',
    '            target clause rtype == "application" or rtype == "api"',
    '        }',
    '        rule approve {',
    '            permit',
    '            target clause act == "approve"',
    '            on permit {',
    '                obligation "urn:sts:xacml:authzen:obligation:step-up" {',
    '                    "acr_value" = "phr"',
    '                }',
    '            }',
    '        }',
    '        rule explode {',
    '            permit',
    '            target clause act == "explode"',
    '            condition stringEqual(stringOneAndOnly(tags), "x")',
    '        }',
    '    }',
    '}'
  ].join('\n');
};

const added = [];
const stored = [];
let realm = null;
let PREFIX = "";
let pepCred = null;

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

function pep(method, path, payload) {
  log.debug("Entering pep(). " + method + " " + path);
  return new Promise(function (resolve, reject) {
    const target = new URL(K.base + PREFIX + path);
    const data = payload === undefined ? null : JSON.stringify(payload);
    const request = https.request({
      host: target.hostname, port: target.port || 443,
      path: target.pathname + target.search, method: method,
      rejectUnauthorized: false, cert: pepCred.certPem,
      key: pepCred.keyPem,
      headers: data ? { "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(data) } : {}
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

function refusedWith(n) {
  log.debug("Entering refusedWith().");
  log.debug("Leaving refusedWith().");
  return function (r) {
    assert.strictEqual(r.status, n, r.status + " " +
                       String(r.text).slice(0, 300));
  };
}

function question(extra) {
  log.debug("Entering question().");
  log.debug("Leaving question().");
  return Object.assign({ subject: { type: "user", id: "azalice" },
                         action: { name: "read" },
                         resource: { type: "document", id: "doc-2" },
                         context: { application: "todo-app" } },
                       extra || {});
}

async function setUp() {
  log.debug("Entering setUp().");
  realm = await K.realm("asr", "development");
  PREFIX = "/realm/" + realm;
  for (const name of ["azalice", "azbob", "azpep"]) {
    await K.ok(api("/users/create"), { username: name, invent: false,
      attributes: { cn: name, sn: name, givenName: name,
                    mail: name + "@asr.example" } }, "created " + name);
  }
  pepCred = await credentials.mint({ subject: "CN=asr-pep-" + K.STAMP +
                                     ",O=Outside" });
  const posted = await credentials.trustRecorded(K.base, pepCred.anchorPem,
                                                 added);
  assert.ok(posted.ok, "the truststore took the test Root: " +
            posted.status);
  stored.push(await credentials.storeOnEntry({ get: get, post: post },
    K.base, PREFIX, "azpep", pepCred.leaf.pem));
  await K.ok(api("/groups/add-member"), { group: "authzen-peps",
    member: "azpep" }, "azpep in authzen-peps");
  await K.ok(api("/xacml/authzen/set-scope"), { caller: "azpep",
    applications: ["todo-app"] }, "azpep's scope");
  await K.ok(api("/groups/create"), { group: "azwapprovers",
    members: ["azbob"] }, "the approvers");
  await K.ok(api("/xacml/authzen/set-attribute"), { object: "resource",
    property: "classification", attributeId: "urn:example:classification" },
    "the classification row");
  await K.ok(api("/xacml/import-alfa"), { name: "asr-root",
    alfa: POLICY("asr") }, "the root policy");
  for (const id of ["asr-app-a", "asr-app-b", "asr-app-c"]) {
    await K.app(realm, id, { oauthClientId: [id] }, { protocols: ["oauth2"] });
  }
  log.debug("Leaving setUp().");
}

async function search() {
  log.debug("Entering search().");
  log.info("=== S. search ===");
  const SEARCH = "/access/v1/search/resource";
  const base = { subject: { type: "user", id: "azalice" },
                 action: { name: "inspect" },
                 resource: { type: "application" },
                 context: { application: "todo-app" } };
  await coded("STS-AUTHZEN-0042", "S1. a page that is not an object is " +
              "refused", function () {
    return pep("POST", SEARCH, Object.assign({}, base, { page: [] }));
  }, refusedWith(400));
  await coded("STS-AUTHZEN-0043", "S2. a page.token this search did not " +
              "issue is refused", function () {
    return pep("POST", SEARCH, Object.assign({}, base,
                                            { page: { token: "asr-bogus" } }));
  }, refusedWith(400));
  await K.set(realm, "authzen.searchMaxCandidates", 1);
  await coded("STS-AUTHZEN-0045", "S3. more candidates than " +
              "authzen.searchMaxCandidates: only the first are decided",
              function () {
    return pep("POST", SEARCH, base);
  }, function (r) {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.ok(((r.json || {}).results || []).length <= 1, r.text);
  });
  await K.unset(realm, "authzen.searchMaxCandidates");
  await K.set(realm, "authzen.searchEnabled", false);
  await coded("STS-AUTHZEN-0044", "S4. authzen.searchEnabled off refuses " +
              "a search", function () {
    return pep("POST", SEARCH, base);
  }, function (r) {
    assert.ok(r.status >= 400, r.status + " " + r.text.slice(0, 300));
  });
  await K.unset(realm, "authzen.searchEnabled");
  log.debug("Leaving search().");
}

async function denial(id) {
  log.debug("Entering denial().");
  const asked = question({ resource: { type: "document", id: id } });
  const r = await pep("POST", "/access/v1/evaluation", asked);
  const ar = ((r.json || {}).context || {}).access_request || {};
  assert.ok(r.json && r.json.decision === false && ar.binding_token,
            "a requestable denial: " + r.text.slice(0, 400));
  log.debug("Leaving denial().");
  return { asked: asked, denial: { expires_at: ar.expires_at,
                                   binding_token: ar.binding_token } };
}

async function accessRequests() {
  log.debug("Entering accessRequests().");
  log.info("=== R. access requests ===");
  const AR = "/access/v1/access-requests";
  // A denial with the shortest lifetime (30 s), kept for R2: past it and
  // the 30 s skew the submission is refused.
  await K.set(realm, "authzen.accessRequestDenialLifetimeS", 30);
  const brief = await denial("doc-4");
  const briefAt = Date.now();
  await K.unset(realm, "authzen.accessRequestDenialLifetimeS");
  const one = await denial("doc-2");
  await coded("STS-AUTHZEN-0073", "R1. a binding_token this realm did not " +
              "issue is refused", function () {
    return pep("POST", AR, Object.assign({}, one.asked, { denial: {
      expires_at: one.denial.expires_at,
      binding_token: one.denial.binding_token.replace(/\.[^.]*$/,
                                                      ".AAAA") } }));
  }, function (r) {
    assert.strictEqual(r.status, 400, r.status + " " + r.text.slice(0, 300));
  });
  await coded("STS-AUTHZEN-0083", "R3. emergency access with no business " +
              "justification is refused", function () {
    return pep("POST", AR, Object.assign({}, one.asked, {
      denial: one.denial, requested_access: { emergency: true } }));
  }, function (r) {
    assert.ok(r.status >= 400, r.status + " " + r.text.slice(0, 300));
  });
  await K.set(realm, "authzen.accessRequestMaxPending", 1);
  const first = await pep("POST", AR, Object.assign({}, one.asked,
                                                    { denial: one.denial }));
  const task = (first.json || {}).task || {};
  check("R4. a submission is accepted, pending", function () {
    assert.strictEqual(first.status, 202, first.text.slice(0, 300));
  });
  const two = await denial("doc-3");
  await coded("STS-AUTHZEN-0078", "R5. past authzen.accessRequestMaxPending " +
              "a second submission is refused", function () {
    return pep("POST", AR, Object.assign({}, two.asked,
                                         { denial: two.denial }));
  }, function (r) {
    assert.ok(r.status >= 400, r.status + " " + r.text.slice(0, 300));
  });
  await K.unset(realm, "authzen.accessRequestMaxPending");
  await K.ok(api("/xacml/authzen/approve-access-request"),
             { request: task.id }, "approved the request");
  const status = await pep("GET", new URL(String(task.status_endpoint))
    .pathname.slice(PREFIX.length));
  const approval = ((status.json || {}).result || {}).approval || {};
  const used = await pep("POST", "/access/v1/evaluation",
    question({ context: { application: "todo-app", approval: approval } }));
  check("R6. the approval permits the tuple it approved", function () {
    assert.strictEqual(used.json && used.json.decision, true,
                       used.text.slice(0, 300));
  });
  await coded("STS-AUTHZEN-0086", "R7. an approval presented for another " +
              "tuple is not used: a plain denial", function () {
    return pep("POST", "/access/v1/evaluation", question({
      resource: { type: "document", id: "doc-9" },
      context: { application: "todo-app", approval: approval } }));
  }, function (r) {
    assert.strictEqual(r.json && r.json.decision, false, r.text);
  });
  await K.ok(api("/xacml/authzen/revoke-access-request"),
             { request: task.id }, "revoked the approval");
  await coded("STS-AUTHZEN-0085", "R8. a revoked approval is not used: a " +
              "plain denial", function () {
    return pep("POST", "/access/v1/evaluation", question({
      context: { application: "todo-app", approval: approval } }));
  }, function (r) {
    assert.strictEqual(r.json && r.json.decision, false, r.text);
  });
  const wait = briefAt + 62000 - Date.now();
  if (wait > 0) {
    log.info("waiting " + Math.ceil(wait / 1000) + " s for the brief " +
             "denial to expire");
    await K.sleep(wait);
  }
  await coded("STS-AUTHZEN-0075", "R2. a denial past its lifetime (and the " +
              "skew) is refused, 410", function () {
    return pep("POST", AR, Object.assign({}, brief.asked,
                                         { denial: brief.denial }));
  }, refusedWith(410));
  log.debug("Leaving accessRequests().");
}

async function test() {
  log.debug("Entering test().");
  try {
    await setUp();
    await search();
    await accessRequests();
  } finally {
    await credentials.forgetStored({ get: get, post: post }, K.base, stored);
    await credentials.settleAnchors(K.base, added, null);
  }
  log.debug("Leaving test().");
}

K.main(test, 12);
