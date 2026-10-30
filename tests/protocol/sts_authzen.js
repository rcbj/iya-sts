// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: sts_authzen.js
//
// ---------------------------------------------------------------------------
// THE AUTHZEN AUTHORIZATION API, DRIVEN OVER HTTP (#563 phase 6, #1165).
//
// `tests/authzen_map.js`, `tests/authzen_evaluation.js` and
// `tests/authzen_admin.js` hold the mapping, the doors and the tab in
// process. This job asks the same questions of a RUNNING service, in a
// throwaway trust realm whose whole repository and catalogue it wrote, so
// every answer is about state this file made:
//
//   1. THE SETUP, all through `/admin-api`: the realm, the people, the
//      caller's certificate stored on its entry and the caller in
//      `authzen-peps`, its application scope, the catalogue rows, and the
//      root policy written in ALFA.
//   2. THE TODO SCENARIO — the AuthZEN interop "Todo" application's rules
//      (five people, five actions, an owner rule) written in ALFA and
//      decided here, case by case.
//   3. THE RESULT MAPPING: Permit, Deny, NotApplicable, and a processing
//      error answered 500, never false.
//   4. THE REQUEST'S SHAPE AND VALUES: a missing member, a wrong JSON type,
//      an undeclared property, null, an empty value, a bag and an array for
//      a single row.
//   5. TRUST BOUNDARIES: a catalogue row onto a reserved identifier refused
//      at the write; an application out of scope; another realm's door; no
//      certificate; a caller without AUTHZEN_PEPS.
//   6. THE BATCH: each semantic, a partial failure, an oversized batch.
//   7. THE METADATA: the inserted form, the identifier, nothing
//      unimplemented advertised, every advertised URL answering.
//   8. REGRESSION: the XACML surface's own gate is unchanged — an AuthZEN
//      caller is not an XACML_USER.
//
// **THE BEARER DOOR IS HELD IN PROCESS ONLY** (`tests/authzen_evaluation.js`
// B): issuing a client a delegated permission grant of `authzen:evaluate`
// over `/admin-api` and a token over the network is a second stack's worth
// of setup for a door whose checks are the report API's, which its own jobs
// drive. Mutual TLS, the default, is what this job drives.
//
// WHY `local: true`: the API, its catalogue and its policy are this
// repository's, and the root CLAUDE.md's rule is that what can be asserted
// over HTTP is asserted here.
// ---------------------------------------------------------------------------

const assert = require("assert");
const https = require("https");
const { URL } = require("url");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const credentials = require("../tools/pep-credential.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason tests/vendored/wait_for.js gives.
  appconfigProblem = e;
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_authzen",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug('CONFIG_FILE could not be read, so the configuration is empty: ' +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");

const REALM = ("authzen-" + names.runStamp()).toLowerCase()
    .replace(/[^a-z0-9-]/g, "").slice(0, 40);
const PREFIX = "/realm/" + REALM;
const CALLER = "authzen-pep-" + names.runStamp().toLowerCase()
    .replace(/[^a-z0-9-]/g, "");
const ROGUE = "authzen-rogue-" + names.runStamp().toLowerCase()
    .replace(/[^a-z0-9-]/g, "");
const APPLICATION = "todo";

// THE TODO APPLICATION'S PEOPLE (the AuthZEN interop scenario): their roles,
// held here as `employeeType`, and the address a todo's owner is named by.
const PEOPLE = [
  ["rick", ["admin", "evil_genius"], "rick@the-citadel.com"],
  ["morty", ["editor"], "morty@the-citadel.com"],
  ["summer", ["editor"], "summer@the-smiths.com"],
  ["beth", ["viewer"], "beth@the-smiths.com"],
  ["jerry", ["viewer"], "jerry@the-smiths.com"]
];

// THE TODO RULES, IN ALFA: anybody reads users and todos; an admin or an
// editor creates; an evil genius updates anything; an admin deletes
// anything; an editor updates or deletes their own. `can_ban` is the one
// Deny, and `explode` the processing error section 3 needs.
const TODO_POLICY = [
  'namespace todo {',
  '    attribute act { category = actionCat',
  '        id = "urn:oasis:names:tc:xacml:1.0:action:action-id"',
  '        type = string }',
  '    attribute protocol { category = environmentCat',
  '        id = "urn:sts:xacml:protocol" type = string }',
  '    attribute role { category = subjectCat id = "employeeType"',
  '        type = string }',
  '    attribute mail { category = subjectCat id = "mail" type = string }',
  '    attribute owner { category = resourceCat',
  '        id = "urn:example:todo:owner-id" type = string }',
  '    attribute tags { category = resourceCat id = "urn:example:tags"',
  '        type = string }',
  '    policy todoRoot {',
  '        id = "urn:test:authzen-todo"',
  '        apply firstApplicable',
  '        target clause protocol == "authzen"',
  '        rule readUser { permit target clause act == "can_read_user" }',
  '        rule readTodos { permit target clause act == "can_read_todos" }',
  '        rule create {',
  '            permit',
  '            target clause act == "can_create_todo"',
  '            target clause role == "admin" or role == "editor"',
  '        }',
  '        rule updateAny {',
  '            permit',
  '            target clause act == "can_update_todo"',
  '            target clause role == "evil_genius"',
  '        }',
  '        rule updateOwn {',
  '            permit',
  '            target clause act == "can_update_todo"',
  '            target clause role == "editor"',
  '            condition stringIsIn(stringOneAndOnly(owner), mail)',
  '        }',
  '        rule deleteAny {',
  '            permit',
  '            target clause act == "can_delete_todo"',
  '            target clause role == "admin"',
  '        }',
  '        rule deleteOwn {',
  '            permit',
  '            target clause act == "can_delete_todo"',
  '            target clause role == "editor"',
  '            condition stringIsIn(stringOneAndOnly(owner), mail)',
  '        }',
  '        rule ban { deny target clause act == "can_ban" }',
  '        rule explode {',
  '            permit',
  '            target clause act == "explode"',
  '            condition stringEqual(stringOneAndOnly(tags), "x")',
  '        }',
  '    }',
  '}'
].join('\n');

var checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.debug("check passed: " + what);
  log.debug("Leaving check().");
}

function api(path) {
  log.debug("Entering api().");
  log.debug("Leaving api().");
  return base + PREFIX + "/admin-api" + path;
}

async function fetchJson(url, options) {
  log.debug("Entering fetchJson(). url=" + url);
  const r = await fetch(url, options || {});
  const text = await r.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in fetchJson(): " + ((e && e.message) || e));
    // Not JSON; the caller reports the status and the text.
    body = null;
  }
  log.debug("Leaving fetchJson(). status=" + r.status);
  return { status: r.status, body: body, text: text, headers: r.headers };
}

function get(url) {
  log.debug("Entering get().");
  log.debug("Leaving get().");
  return fetchJson(url);
}

function postJson(url, payload) {
  log.debug("Entering postJson().");
  log.debug("Leaving postJson().");
  return fetchJson(url, { method: "POST",
                          headers: { "Content-Type": "application/json" },
                          body: JSON.stringify(payload || {}) });
}

// An /admin-api call that must have worked, its refusal quoted whole.
async function must(path, payload, what) {
  log.debug("Entering must(). " + path);
  const r = await postJson(api(path), payload);
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST " + PREFIX + "/admin-api" + path + " should have " + what +
    "; it answered " + r.status + " " + String(r.text).slice(0, 400));
  log.debug("Leaving must().");
  return r.body;
}

// One request with a client certificate, as an AuthZEN PEP sends it.
function pep(method, path, identity, payload, headers) {
  log.debug("Entering pep(). " + method + " " + path);
  log.debug("Leaving pep().");
  return new Promise(function (resolve, reject) {
    const target = new URL(path.indexOf("http") === 0 ? path : base + path);
    const data = payload === undefined ? null
      : (typeof payload === "string" ? payload : JSON.stringify(payload));
    const sent = Object.assign(data ? {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(data) } : {}, headers || {});
    const request = https.request({
      host: target.hostname, port: target.port || 443,
      path: target.pathname + target.search, method: method,
      rejectUnauthorized: false,
      cert: identity ? identity.certPem : undefined,
      key: identity ? identity.keyPem : undefined,
      headers: sent
    }, function (response) {
      let text = "";
      response.on("data", function (chunk) { text += chunk; });
      response.on("end", function () {
        let body;
        try {
          body = JSON.parse(text);
        } catch (e) {
          log.debug("Caught in a callback in pep(): " +
                    ((e && e.message) || e));
          body = null;
        }
        resolve({ status: response.statusCode, body: body, text: text,
                  headers: response.headers });
      });
    });
    request.on("error", reject);
    if (data) {
      request.write(data);
    }
    request.end();
  });
}

function evaluate(body, identity, headers) {
  log.debug("Entering evaluate().");
  log.debug("Leaving evaluate().");
  return pep("POST", PREFIX + "/access/v1/evaluation",
             identity === undefined ? caller : identity, body, headers);
}

// A Todo question: who, which action, and about whose todo.
function todo(who, action, owner) {
  log.debug("Entering todo().");
  const out = {
    subject: { type: "user", id: who },
    action: { name: action },
    resource: owner
      ? { type: "todo", id: "todo-1", properties: { ownerID: owner } }
      : { type: "user", id: who },
    context: { application: APPLICATION }
  };
  log.debug("Leaving todo().");
  return out;
}

const addedAnchors = [];
const storedHere = [];
var caller = null;
var rogue = null;

async function setUp() {
  log.debug("Entering setUp().");
  const made = await fetchJson(base + "/admin-api/realms/create", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      id: REALM, domain: REALM + ".example.net",
      name: "AuthZEN test realm",
      description: "Created by tests/protocol/sts_authzen.js; LEFT IN PLACE " +
                   "on purpose, so that a failed run can be read afterwards.",
      overrides: { "global.mode": "development" } })
  });
  assert.ok(made.status === 200 && made.body && made.body.ok !== false,
    "creating the throwaway realm " + REALM + " answered " + made.status +
    " " + String(made.text).slice(0, 300));
  for (const one of PEOPLE) {
    const r = await postJson(api("/users/create"), {
      username: one[0], invent: false,
      attributes: { cn: one[0], sn: one[0], givenName: one[0],
                    mail: one[2], employeeType: one[1] } });
    assert.ok(r.status === 200 && r.body && r.body.ok,
      "POST /admin-api/users/create for " + one[0] + " answered " +
      r.status + " " + String(r.text).slice(0, 300));
  }
  caller = await credentials.mint({
    subject: "CN=" + CALLER + ",OU=authzen,O=iya-sts tests" });
  rogue = await credentials.mint({
    subject: "CN=" + ROGUE + ",OU=authzen,O=iya-sts tests" });
  for (const one of [caller, rogue]) {
    const posted = await credentials.trustAnchor(base, one.anchorPem);
    assert.ok(posted.ok, "POST /admin-api/tls/trust/add should accept the " +
      "Root CA this file built; it answered " + posted.status);
    addedAnchors.push(one.anchorPem);
  }
  storedHere.push(await credentials.storeOnEntry({ get: get, post: postJson },
    base, PREFIX, CALLER, caller.leaf.pem));
  storedHere.push(await credentials.storeOnEntry({ get: get, post: postJson },
    base, PREFIX, ROGUE, rogue.leaf.pem));
  await must("/groups/add-member", { group: "authzen-peps", member: CALLER },
             "put the caller in authzen-peps");
  await must("/xacml/authzen/set-scope",
             { caller: CALLER, applications: [APPLICATION, "wiki"] },
             "scoped the caller to todo and wiki");
  for (const row of [
    { object: "resource", property: "ownerID",
      attributeId: "urn:example:todo:owner-id" },
    { object: "resource", property: "tags", multiplicity: "bag",
      attributeId: "urn:example:tags" },
    { object: "resource", property: "priority", dataType: "integer",
      attributeId: "urn:example:todo:priority" },
    { object: "context", property: "note",
      attributeId: "urn:example:note" }]) {
    await must("/xacml/authzen/set-attribute", row,
               "declared " + row.object + "." + row.property);
  }
  await must("/xacml/import-alfa", { name: "todo-root", alfa: TODO_POLICY },
             "imported the Todo policy");
  await must("/xacml/set-root", { name: "todo-root" },
             "made the Todo policy the root");
  log.info("Set up " + REALM + ": five people, the caller " + CALLER +
           " in authzen-peps scoped to " + APPLICATION + ", four catalogue " +
           "rows and the Todo policy as root.");
  log.debug("Leaving setUp().");
}

async function theTodoScenario() {
  log.debug("Entering theTodoScenario().");
  log.info("=== 2. the AuthZEN interop Todo scenario ===");
  const cases = [
    ["rick", "can_read_user", null, true],
    ["jerry", "can_read_todos", null, true],
    ["morty", "can_create_todo", null, true],
    ["beth", "can_create_todo", null, false],
    ["morty", "can_update_todo", "morty@the-citadel.com", true],
    ["morty", "can_update_todo", "rick@the-citadel.com", false],
    ["rick", "can_update_todo", "morty@the-citadel.com", true],
    ["summer", "can_delete_todo", "summer@the-smiths.com", true],
    ["summer", "can_delete_todo", "morty@the-citadel.com", false],
    ["rick", "can_delete_todo", "beth@the-smiths.com", true],
    ["jerry", "can_delete_todo", "jerry@the-smiths.com", false]
  ];
  for (const one of cases) {
    const r = await evaluate(todo(one[0], one[1], one[2]));
    check(one[0] + " " + one[1] + (one[2] ? " of " + one[2] : ""),
          function () {
      assert.ok(r.status === 200 && r.body && r.body.decision === one[3],
        one[0] + " " + one[1] + (one[2] ? " (owner " + one[2] + ")" : "") +
        " should be " + one[3] + "; it answered " + r.status + " " +
        String(r.text).slice(0, 300));
    });
  }
  log.debug("Leaving theTodoScenario().");
}

async function theResultMapping() {
  log.debug("Entering theResultMapping().");
  log.info("=== 3. the result mapping ===");
  const id = "authzen-" + names.runStamp();
  let r = await evaluate(todo("rick", "can_read_user"), caller,
                         { "X-Request-ID": id });
  check("a Permit is 200 true, X-Request-ID echoed", function () {
    assert.ok(r.status === 200 && r.body.decision === true &&
              r.headers["x-request-id"] === id,
      "answered " + r.status + " " + r.text + " id=" +
      r.headers["x-request-id"]);
  });
  r = await evaluate(todo("rick", "can_ban"));
  check("a Deny is 200 false", function () {
    assert.ok(r.status === 200 && r.body.decision === false,
      "answered " + r.status + " " + r.text);
  });
  r = await evaluate(todo("rick", "can_fly"));
  check("NotApplicable is 200 false", function () {
    assert.ok(r.status === 200 && r.body.decision === false,
      "answered " + r.status + " " + r.text);
  });
  const exploding = todo("rick", "explode", "rick@the-citadel.com");
  exploding.resource.properties.tags = ["a", "b"];
  r = await evaluate(exploding);
  check("a processing error the PDP reaches is 500, never false",
        function () {
    assert.ok(r.status === 500 && !(r.body && r.body.decision === false) &&
              r.body && r.body.error && r.body.error.status === 500,
      "answered " + r.status + " " + r.text);
  });
  log.debug("Leaving theResultMapping().");
}

async function theShapeAndValues() {
  log.debug("Entering theShapeAndValues().");
  log.info("=== 4. the request's shape and values ===");
  const bad = async function (what, body, status) {
    log.debug("Entering bad().");
    const r = await evaluate(body);
    check(what, function () {
      assert.strictEqual(r.status, status || 400,
        what + ": answered " + r.status + " " + String(r.text).slice(0, 300));
    });
    log.debug("Leaving bad().");
    return r;
  };
  const without = todo("rick", "can_read_user");
  delete without.subject;
  await bad("no subject is 400", without);
  const numeric = todo("rick", "can_read_user");
  numeric.resource.id = 7;
  await bad("a number for resource.id is 400", numeric);
  const undeclared = todo("rick", "can_update_todo", "rick@the-citadel.com");
  undeclared.resource.properties.colour = "red";
  await bad("an undeclared property is 400", undeclared);
  const nulled = todo("rick", "can_update_todo", "rick@the-citadel.com");
  nulled.resource.properties.priority = null;
  await bad("null is 400", nulled);
  const fraction = todo("rick", "can_update_todo", "rick@the-citadel.com");
  fraction.resource.properties.priority = 1.5;
  await bad("a fraction for an integer row is 400", fraction);
  const array = todo("rick", "can_update_todo", "rick@the-citadel.com");
  array.resource.properties.priority = [1];
  await bad("an array for a single row is 400", array);
  const empty = todo("rick", "can_update_todo", "rick@the-citadel.com");
  empty.context.note = "";
  empty.resource.properties.tags = [];
  const r = await evaluate(empty);
  check("an empty value and an empty bag are accepted", function () {
    assert.ok(r.status === 200 && r.body.decision === true,
      "answered " + r.status + " " + r.text);
  });
  log.debug("Leaving theShapeAndValues().");
}

async function theTrustBoundaries() {
  log.debug("Entering theTrustBoundaries().");
  log.info("=== 5. trust boundaries ===");
  let r = await postJson(api("/xacml/authzen/set-attribute"), {
    object: "subject", property: "roles", attributeId: "urn:sts:xacml:role" });
  check("a catalogue row onto urn:sts:xacml:role is refused", function () {
    assert.ok(r.status === 400 && r.body && r.body.ok === false,
      "answered " + r.status + " " + String(r.text).slice(0, 300));
  });
  const outside = todo("rick", "can_read_user");
  outside.context.application = "payroll";
  r = await evaluate(outside);
  check("an application outside the caller's scope is 403", function () {
    assert.strictEqual(r.status, 403, r.text);
  });
  const unnamed = todo("rick", "can_read_user");
  delete unnamed.context;
  r = await evaluate(unnamed);
  check("two applications in scope and none named is 400", function () {
    assert.strictEqual(r.status, 400, r.text);
  });
  r = await evaluate(todo("rick", "can_read_user"), null);
  check("no certificate is 401", function () {
    assert.strictEqual(r.status, 401, r.text);
  });
  r = await evaluate(todo("rick", "can_read_user"), rogue);
  check("a stored certificate whose entry lacks AUTHZEN_PEPS is 403",
        function () {
    assert.ok(r.status === 403 && /AUTHZEN_PEPS/.test(r.text), r.text);
  });
  r = await pep("POST", "/access/v1/evaluation", caller,
                todo("rick", "can_read_user"));
  check("the default realm's door does not know this realm's caller",
        function () {
    assert.ok(r.status === 401 || r.status === 403,
      "answered " + r.status + " " + r.text);
  });
  log.debug("Leaving theTrustBoundaries().");
}

async function theBatch() {
  log.debug("Entering theBatch().");
  log.info("=== 6. the batch ===");
  const batch = function (semantic, actions) {
    log.debug("Entering batch().");
    const body = { subject: { type: "user", id: "beth" },
                   resource: { type: "user", id: "beth" },
                   context: { application: APPLICATION },
                   evaluations: actions.map(function (one) {
                     return one === "bad"
                       ? { action: { name: "can_read_user" },
                           resource: { type: "user", id: "beth",
                                       properties: { colour: "red" } } }
                       : { action: { name: one } };
                   }) };
    if (semantic) {
      body.options = { evaluations_semantic: semantic };
    }
    log.debug("Leaving batch().");
    return pep("POST", PREFIX + "/access/v1/evaluations", caller, body);
  };
  let r = await batch(null, ["can_read_user", "can_create_todo", "bad"]);
  check("execute_all answers each, a partial failure in context.error",
        function () {
    const all = (r.body && r.body.evaluations) || [];
    assert.ok(r.status === 200 && all.length === 3 &&
              all[0].decision === true && all[1].decision === false &&
              all[2].decision === false && all[2].context &&
              all[2].context.error && all[2].context.error.status === 400,
      "answered " + r.status + " " + r.text);
  });
  r = await batch("deny_on_first_deny",
                  ["can_read_user", "can_create_todo", "can_read_todos"]);
  check("deny_on_first_deny stops at the first false", function () {
    assert.ok(r.status === 200 && r.body.evaluations.length === 2, r.text);
  });
  r = await batch("permit_on_first_permit",
                  ["can_create_todo", "can_read_user", "can_create_todo"]);
  check("permit_on_first_permit stops at the first true", function () {
    assert.ok(r.status === 200 && r.body.evaluations.length === 2, r.text);
  });
  const set = await postJson(api("/config/set"),
                             { key: "authzen.maxEvaluations", value: 2 });
  assert.ok(set.status === 200, "setting authzen.maxEvaluations answered " +
            set.status + " " + set.text);
  try {
    r = await batch(null, ["can_read_user", "can_read_user",
                           "can_read_user"]);
  } finally {
    await postJson(api("/config/reset"), { key: "authzen.maxEvaluations" });
  }
  check("a batch over authzen.maxEvaluations is 400 whole", function () {
    assert.strictEqual(r.status, 400, r.text);
  });
  log.debug("Leaving theBatch().");
}

// THE TODO SCENARIO'S QUESTIONS AS SEARCHES (#1175): who may create a todo,
// and what beth may do with her own.
async function theSearches() {
  log.debug("Entering theSearches().");
  log.info("=== 6b. the searches ===");
  let r = await pep("POST", PREFIX + "/access/v1/search/subject", caller, {
    subject: { type: "user" }, action: { name: "can_create_todo" },
    resource: { type: "todo", id: "todo-1" },
    context: { application: APPLICATION } });
  const who = ((r.body && r.body.results) || []).map(function (one) {
    return one.id;
  }).sort();
  check("Subject Search: who may create a todo", function () {
    assert.ok(r.status === 200 && who.indexOf("rick") >= 0 &&
              who.indexOf("morty") >= 0 && who.indexOf("summer") >= 0 &&
              who.indexOf("beth") < 0 && who.indexOf("jerry") < 0,
      "answered " + r.status + " " + String(r.text).slice(0, 300));
  });
  r = await pep("POST", PREFIX + "/access/v1/search/action", caller, {
    subject: { type: "user", id: "beth" },
    resource: { type: "todo", id: "todo-1",
                properties: { ownerID: "beth@the-smiths.com" } },
    context: { application: APPLICATION } });
  const can = ((r.body && r.body.results) || []).map(function (one) {
    return one.name;
  });
  check("Action Search: what a viewer may do with a todo", function () {
    assert.ok(r.status === 200 && can.indexOf("can_read_todos") >= 0 &&
              can.indexOf("can_create_todo") < 0 &&
              can.indexOf("can_delete_todo") < 0,
      "answered " + r.status + " " + String(r.text).slice(0, 300));
  });
  log.debug("Leaving theSearches().");
}

async function theMetadata() {
  log.debug("Entering theMetadata().");
  log.info("=== 7. the metadata ===");
  const r = await get(base + "/.well-known/authzen-configuration" + PREFIX);
  const doc = r.body || {};
  check("the realm's document names its own PDP identifier", function () {
    assert.ok(r.status === 200 &&
              /\/realm\//.test(String(doc.policy_decision_point)) &&
              String(doc.policy_decision_point).slice(-PREFIX.length) ===
                PREFIX,
      "answered " + r.status + " " + r.text);
  });
  check("the searches are advertised, no capabilities, and signed_metadata " +
        "is a JWT", function () {
    assert.ok(!doc.capabilities && typeof doc.signed_metadata === "string" &&
              ["subject", "resource", "action"].every(function (kind) {
                return /\/access\/v1\/search\//.test(
                  String(doc["search_" + kind + "_endpoint"]));
              }), JSON.stringify(doc));
  });
  for (const key of Object.keys(doc)) {
    if (!/_endpoint$/.test(key)) {
      continue;
    }
    const at = String(doc[key]);
    const answered = await pep("POST", at, null, {});
    check(key + " answers", function () {
      assert.ok(answered.status !== 404, key + " " + at + " answered " +
                answered.status);
    });
  }
  log.debug("Leaving theMetadata().");
}

async function theXacmlSurfaceIsUnchanged() {
  log.debug("Entering theXacmlSurfaceIsUnchanged().");
  log.info("=== 8. regression: the XACML surface's own gate ===");
  const r = await pep("POST", PREFIX + "/xacml/pdp", caller,
                      { Request: { Action: { Attribute: [
                        { AttributeId: "urn:oasis:names:tc:xacml:1.0:" +
                                       "action:action-id",
                          Value: "read" }] } } });
  check("an AuthZEN caller is not an XACML_USER at /xacml/pdp", function () {
    assert.ok(r.status === 403 && /XACML_USER/.test(r.text),
      "answered " + r.status + " " + String(r.text).slice(0, 300));
  });
  log.debug("Leaving theXacmlSurfaceIsUnchanged().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving IYA STS's AuthZEN API at " + base + PREFIX +
           "/access/v1");
  const status = await fetchJson(base + "/admin-api/status");
  assert.strictEqual(status.status, 200,
    "GET /admin-api/status answered " + status.status + " at " + base);
  await setUp();
  await theTodoScenario();
  await theResultMapping();
  await theShapeAndValues();
  await theTrustBoundaries();
  await theBatch();
  await theSearches();
  await theMetadata();
  await theXacmlSurfaceIsUnchanged();
  assert.ok(checks >= 35,
    "only " + checks + " checks ran; a section stopped being called.");
  log.info(checks + " checks passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_authzen")
  .description("Drive IYA STS's AuthZEN Authorization API over HTTP in a " +
      "throwaway trust realm: the interop Todo scenario in ALFA, the " +
      "result mapping, the value rules, the trust boundaries, the batch " +
      "and the metadata.")
  .addOption(new Option("-u, --url <url>", "base url of the STS under test")
      .default(base))
  .parse(process.argv);
base = String(program.opts().url || base).replace(/\/+$/, "");

function forgetTheStored() {
  log.debug("Entering forgetTheStored().");
  log.debug("Leaving forgetTheStored().");
  return credentials.forgetStored({ get: get, post: postJson }, base,
                                  storedHere);
}

test().then(function () {
  return forgetTheStored().then(function () {
    return credentials.settleAnchors(base, addedAnchors, null);
  });
}, function (e) {
  log.debug("Caught in test(): " + ((e && e.message) || e));
  return forgetTheStored().then(function () {
    return credentials.settleAnchors(base, addedAnchors, e);
  });
}).catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
