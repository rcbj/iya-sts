// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_app_roles.js
//
// ---------------------------------------------------------------------------
// ROLES THAT BELONG TO ONE APPLICATION, AND AN APPLICATION'S PERMISSIONS,
// OVER THE WIRE.
//
// D12 (#444): carries over
//
//   * tests/app_roles.js (#310, #93, #458) — what it held through
//     `adminActions.rolesAction()`, `roles.rolesOf()`, `stats.jwtClaims()`
//     and `gate.check()`, asked here of `POST /admin-api/roles/<action>`,
//     `GET /admin-api/roles`, the application's GET and real tokens:
//       A. two applications each with a `reader`; a realm-wide name with the
//          separator refused, and a role for an application nobody
//          registered;
//       B/C. an ID Token for payroll carries payroll's `reader` and the
//          realm-wide role, one for hr only the realm-wide role, and bob,
//          hr's reader, is not payroll's; an access token audienced to the
//          realm's resource carries only realm-wide roles;
//       D. payroll requiring `reader` issues to its own reader and refuses
//          hr's at the token endpoint (STS-OAUTH-0191, the issuance policy's
//          STS-XACML-0040 beside it);
//       F. an application's role takes its own application's permission and
//          not another's; editing it keeps its application; the register
//          knows which requirement a role meets and which nothing does;
//       G. member types (STS-XACML-0082, -0083; an unknown type is refused
//          by the schema), the display name and
//          the entryUUID id kept across edits, and the roles an application
//          holds and is offered, on its page and as `applicationRoles`;
//       H. the Roles tab's requirement section: the grid does not draw
//          `appRequiredRole`, the form does, `required` resolved to the
//          application's own role, the realm's, or nothing, `requirable`,
//          and the add and remove that write it.
//     Its E — the XACML PIP naming an application's role by its full name —
//     is asked of `POST /xacml/pip` only with a REMOTE_PEPS client
//     certificate, and stays with tests/app_roles.js (class (d) for now).
//   * tests/app_permissions.js — the string rules a caller CAN reach: a
//     permission identifier is the base and the name joined once (a base
//     with no separator gets one), the description is everything after the
//     first `|`, a name that is no scope token is refused, so is one naming
//     an operator code (and the refusal does not repeat it), and a base that
//     is not absolute. The rest of that file — the configured-permission
//     PICTURE's geometry and colour, and graphs (a dangling grant, a
//     self-grant) only an `ldapmodify` can make — stays in process (d).
//
// In a throwaway realm this job creates, removed at the end only when
// STS_TEST_REMOVE_REALMS=1 (removeRealms() says why). OWNED HERE
// (local: true).
// ---------------------------------------------------------------------------

const assert = require("assert");
const names = require("./random_username.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand run without one still loads.
  appconfigProblem = e;
  appconfig = {};
}
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_app_roles",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "");
const REALM = ("approles-" + STAMP).slice(0, 31);
const API = base + "/realm/" + REALM + "/admin-api";
const RUN = STAMP.slice(-8);
const PAYROLL = "payroll-" + RUN;
const HR = "hr-" + RUN;
const ALICE = "ar-alice-" + RUN;
const BOB = "ar-bob-" + RUN;
const STAFF = "ar-staff-" + RUN;

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

async function send(url, options) {
  log.debug("Entering send(). url=" + url);
  const r = await fetch(url, Object.assign({ redirect: "manual" },
                                           options || {}));
  const raw = await r.text();
  let body = null;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in send(): " + ((e && e.message) || e));
    // Not JSON — an empty answer or a page; the caller reads `raw`.
    body = null;
  }
  log.debug("Leaving send(). status=" + r.status);
  return { status: r.status, body: body, raw: raw };
}

function post(url, payload) {
  log.debug("Entering post().");
  log.debug("Leaving post().");
  return send(url, { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}) });
}

function errorsOf(r) {
  log.debug("Entering errorsOf().");
  log.debug("Leaving errorsOf().");
  return ((r.body && r.body.errors) || []).join(" ");
}

function roleAct(action, payload) {
  log.debug("Entering roleAct(). " + action);
  log.debug("Leaving roleAct().");
  return post(API + "/roles/" + action, payload);
}

function appAct(action, payload) {
  log.debug("Entering appAct(). " + action);
  log.debug("Leaving appAct().");
  return post(API + "/applications/" + action, payload);
}

async function ok(promise, what) {
  log.debug("Entering ok().");
  const r = await promise;
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    what + ": answered " + r.status + " " + String(r.raw).slice(0, 400));
  log.debug("Leaving ok().");
  return r.body;
}

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) { setTimeout(resolve, ms); });
}

async function codeCount(code) {
  log.debug("Entering codeCount(). " + code);
  const r = await send(API + "/audit?per=500&code=" + encodeURIComponent(code));
  const rows = (r.body && r.body.events) || [];
  log.debug("Leaving codeCount(). " + rows.length);
  return rows.length;
}

// Runs `fn`, and answers its result and whether the realm's audit log
// gained a row carrying each of `codes`. A code is never sent.
async function recording(codes, fn) {
  log.debug("Entering recording(). " + codes.join(","));
  const before = [];
  for (const code of codes) {
    before.push(await codeCount(code));
  }
  const out = await fn();
  const seen = {};
  for (let i = 0; i < 20; i += 1) {
    let all = true;
    for (let n = 0; n < codes.length; n += 1) {
      if (!seen[codes[n]]) {
        seen[codes[n]] = (await codeCount(codes[n])) > before[n];
      }
      all = all && seen[codes[n]];
    }
    if (all) {
      break;
    }
    await sleep(100);
  }
  log.debug("Leaving recording().");
  return { out: out, seen: seen };
}

async function roleRow(name) {
  log.debug("Entering roleRow(). " + name);
  const r = await send(API + "/roles?role=" + encodeURIComponent(name));
  assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
  log.debug("Leaving roleRow().");
  return r.body.role;
}

async function application(identifier) {
  log.debug("Entering application(). " + identifier);
  const r = await send(API + "/applications?application=" +
                       encodeURIComponent(identifier));
  assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
  log.debug("Leaving application().");
  return r.body;
}

function claimsOf(jwt) {
  log.debug("Entering claimsOf().");
  const parts = String(jwt || "").split(".");
  assert.strictEqual(parts.length, 3, "not a JWT: " + String(jwt)
    .slice(0, 80));
  log.debug("Leaving claimsOf().");
  return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
}

// A password grant for `user` at `client` in this realm, with an ID Token.
// Development mode checks no password, which is what makes it the shortest
// way to a token naming a person.
function passwordGrant(client, user) {
  log.debug("Entering passwordGrant(). " + client + " " + user);
  log.debug("Leaving passwordGrant().");
  return send(base + "/realm/" + REALM + "/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "password", username: user,
      password: "development-mode-checks-none", client_id: client,
      client_secret: client + "-secret-" + RUN, scope: "openid" })
      .toString() });
}

async function rolesFor(client, user) {
  log.debug("Entering rolesFor(). " + client + " " + user);
  const r = await passwordGrant(client, user);
  assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
  const id = claimsOf(r.body.id_token);
  const access = claimsOf(r.body.access_token);
  log.debug("Leaving rolesFor().");
  return { id: (id.roles || []).slice(0).sort(),
           access: (access.roles || []).slice(0).sort() };
}

async function setUp() {
  log.debug("Entering setUp().");
  await ok(post(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "App roles " + STAMP }),
    "created the realm " + REALM);
  for (const id of [PAYROLL, HR]) {
    await ok(appAct("create", { identifier: id,
      protocols: ["oauth2", "oidc"], "field.oauthClientId": id,
      "field.oauthClientSecret": id + "-secret-" + RUN,
      "field.oauthGrantType": "password",
      "field.oauthPermissionBaseUri": "https://" + id + ".example/",
      "field.oauthPermission": "read" }), "registered " + id);
  }
  for (const name of [ALICE, BOB]) {
    await ok(post(API + "/users/create", { username: name, invent: false,
      attributes: { cn: name, sn: "Roles" } }), "created " + name);
  }
  log.debug("Leaving setUp().");
}

async function naming() {
  log.debug("Entering naming().");
  log.info("=== A. naming ===");
  const a = await roleAct("create-role", { role: "reader",
                                           application: PAYROLL });
  const b = await roleAct("create-role", { role: "reader", application: HR });
  const c = await roleAct("create-role", { role: STAFF });
  check("A1. payroll and hr each have a reader, beside a realm-wide role",
        function () {
    assert.ok(a.status === 200 && b.status === 200 && c.status === 200,
              a.raw.slice(0, 200) + b.raw.slice(0, 200) + c.raw.slice(0, 200));
  });
  const row = await roleRow("reader@" + PAYROLL);
  check("A2. registered as reader@payroll, belonging to payroll",
        function () {
    assert.ok(row && row.application === PAYROLL &&
              row.localName === "reader", JSON.stringify(row));
  });
  const sep = await roleAct("create-role", { role: "x@" + PAYROLL });
  check("A3. a realm-wide role's name may not contain the separator",
        function () {
    assert.strictEqual(sep.status, 400, sep.raw.slice(0, 300));
    assert.ok(/may not contain "@"/.test(errorsOf(sep)),
              sep.raw.slice(0, 300));
  });
  const nobody = await roleAct("create-role", { role: "reader",
                                                application: "nobody-" + RUN });
  check("A4. nor may a role be made for an application nobody registered",
        function () {
    assert.strictEqual(nobody.status, 400, nobody.raw.slice(0, 300));
    assert.ok(/no application/.test(errorsOf(nobody)),
              nobody.raw.slice(0, 300));
  });
  for (const m of [["reader@" + PAYROLL, ALICE], ["reader@" + HR, BOB],
                   [STAFF, ALICE], [STAFF, BOB]]) {
    await ok(roleAct("add-member", { role: m[0], kind: "user",
                                     member: m[1] }),
             "made " + m[1] + " a member of " + m[0]);
  }
  log.debug("Leaving naming().");
}

async function resolutionAndClaim() {
  log.debug("Entering resolutionAndClaim().");
  log.info("=== B/C. resolution, and the claim ===");
  const alicePayroll = await rolesFor(PAYROLL, ALICE);
  const aliceHr = await rolesFor(HR, ALICE);
  const bobPayroll = await rolesFor(PAYROLL, BOB);
  check("B1/C1. an ID Token for payroll carries alice's payroll reader and " +
        "the realm-wide role", function () {
    assert.deepStrictEqual(alicePayroll.id, [STAFF, "reader"].sort());
  });
  check("B2/C2. one for hr carries only the realm-wide role — never " +
        "another application's", function () {
    assert.deepStrictEqual(aliceHr.id, [STAFF]);
  });
  check("B3. bob, hr's reader, is not payroll's reader", function () {
    assert.deepStrictEqual(bobPayroll.id, [STAFF]);
  });
  check("B4. an access token audienced to the realm's resource, for no " +
        "application, carries only realm-wide roles", function () {
    assert.deepStrictEqual(alicePayroll.access, [STAFF]);
  });
  log.debug("Leaving resolutionAndClaim().");
}

async function requirement() {
  log.debug("Entering requirement().");
  log.info("=== D. the requirement ===");
  await ok(appAct("add", { application: PAYROLL,
    attribute: "appRequiredRole", value: "reader" }),
    "made payroll require reader");
  const alice = await passwordGrant(PAYROLL, ALICE);
  const bob = await recording(["STS-OAUTH-0191", "STS-XACML-0040"],
    function () {
      return passwordGrant(PAYROLL, BOB);
    });
  check("D1. payroll's requirement issues to its own reader and refuses " +
        "hr's: access_denied, recorded STS-OAUTH-0191 and STS-XACML-0040",
        function () {
    assert.strictEqual(alice.status, 200, alice.raw.slice(0, 300));
    assert.strictEqual(bob.out.status, 400, bob.out.raw.slice(0, 300));
    assert.strictEqual(bob.out.body.error, "access_denied");
    assert.ok(/requires reader/.test(bob.out.body.error_description),
              bob.out.raw.slice(0, 300));
    assert.ok(bob.seen["STS-OAUTH-0191"] && bob.seen["STS-XACML-0040"],
              JSON.stringify(bob.seen));
  });
  log.debug("Leaving requirement().");
}

async function permissions() {
  log.debug("Entering permissions().");
  log.info("=== F. permissions and edits ===");
  const own = await roleAct("add-permission", { role: "reader@" + PAYROLL,
    permission: "https://" + PAYROLL + ".example/read" });
  const other = await roleAct("add-permission", { role: "reader@" + PAYROLL,
    permission: "https://" + HR + ".example/read" });
  check("F1. an application's role takes its own application's permission " +
        "and not another's", function () {
    assert.strictEqual(own.status, 200, own.raw.slice(0, 300));
    assert.strictEqual(other.status, 400, other.raw.slice(0, 300));
  });
  await ok(roleAct("describe-role", { role: "reader@" + PAYROLL,
    description: "reads payroll" }), "described the role");
  const row = await roleRow("reader@" + PAYROLL);
  check("F2. editing it keeps its application", function () {
    assert.strictEqual(row.application, PAYROLL);
    assert.strictEqual(row.description, "reads payroll");
  });
  await ok(appAct("add", { application: HR, attribute: "appRequiredRole",
                           value: "writer" }), "made hr require writer");
  const register = (await send(API + "/roles")).body;
  const of = function (id) {
    return (register.requiring || []).filter(function (one) {
      return one.application === id;
    })[0];
  };
  check("F3. the register knows payroll's reader meets its requirement, " +
        "and that nothing meets hr's writer", function () {
    assert.ok(of(PAYROLL) && of(PAYROLL).unknown.length === 0,
              JSON.stringify(register.requiring));
    assert.deepStrictEqual(of(HR) && of(HR).unknown, ["writer"]);
  });
  log.debug("Leaving permissions().");
}

async function memberTypes() {
  log.debug("Entering memberTypes().");
  log.info("=== G. application permissions (#93) ===");
  const MACHINES = "ar-machines-" + RUN;
  const PEOPLE = "ar-people-" + RUN;
  await ok(roleAct("create-role", { role: MACHINES,
    displayName: "Batch machines", memberTypes: ["application"] }),
    "made an applications-only role");
  const made = await roleRow(MACHINES);
  check("G1. a role is made with a display name, applications only, and " +
        "an entryUUID id", function () {
    assert.strictEqual(made.displayName, "Batch machines");
    assert.deepStrictEqual(made.memberTypes, ["application"]);
    assert.ok(/^[0-9a-f-]{36}$/.test(made.id), made.id);
  });
  const person = await recording(["STS-XACML-0082"], function () {
    return roleAct("add-member", { role: MACHINES, kind: "user",
                                   member: ALICE });
  });
  const group = await recording(["STS-XACML-0082"], function () {
    return roleAct("add-member", { role: MACHINES, kind: "group",
                                   member: "developers" });
  });
  check("G2/G3. a person, and a group, are refused on an applications-only " +
        "role, STS-XACML-0082", function () {
    assert.ok(person.out.status === 400 && person.seen["STS-XACML-0082"],
              person.out.raw.slice(0, 300));
    assert.ok(group.out.status === 400 && group.seen["STS-XACML-0082"],
              group.out.raw.slice(0, 300));
  });
  await ok(roleAct("add-member", { role: MACHINES, kind: "application",
                                   member: HR }), "added hr to it");
  await ok(roleAct("add-permission", { role: MACHINES,
    permission: "https://" + PAYROLL + ".example/read" }),
    "added a permission to it");
  const kept = await roleRow(MACHINES);
  check("G4/G5. an application is added and a permission beside it, and " +
        "both keep the display name, the member types and the id",
        function () {
    assert.strictEqual(kept.displayName, "Batch machines");
    assert.deepStrictEqual(kept.memberTypes, ["application"]);
    assert.strictEqual(kept.id, made.id);
  });
  const narrowing = await recording(["STS-XACML-0082"], function () {
    return roleAct("describe-role", { role: MACHINES, description: "batch",
                                      memberTypes: ["user"] });
  });
  const afterNarrow = await roleRow(MACHINES);
  check("G6. restricting it to people while an application holds it is " +
        "refused STS-XACML-0082, and nothing changes", function () {
    assert.ok(narrowing.out.status === 400 &&
              narrowing.seen["STS-XACML-0082"],
              narrowing.out.raw.slice(0, 300));
    assert.deepStrictEqual(afterNarrow.memberTypes, ["application"]);
  });
  await ok(roleAct("describe-role", { role: MACHINES,
                                      description: "batch jobs" }),
           "described it");
  const described = await roleRow(MACHINES);
  check("G7. describe-role with only a description keeps the display name " +
        "and member types", function () {
    assert.strictEqual(described.description, "batch jobs");
    assert.strictEqual(described.displayName, "Batch machines");
    assert.deepStrictEqual(described.memberTypes, ["application"]);
  });
  // Over this API the schema's closed list of member types refuses the
  // unknown one before the action, where in process the action's own check
  // (STS-XACML-0081) does; the observed refusal is the schema's.
  const unknown = await roleAct("create-role", { role: "ar-odd-" + RUN,
                                                 memberTypes: ["robot"] });
  const odd = await roleRow("ar-odd-" + RUN);
  check("G8. an unknown member type is refused, by the schema's closed " +
        "list, and no role is made", function () {
    assert.strictEqual(unknown.status, 400, unknown.raw.slice(0, 300));
    assert.ok(/"robot", which is not one of the 2 values/
      .test(errorsOf(unknown)), unknown.raw.slice(0, 300));
    assert.ok(!odd || odd.found === false, JSON.stringify(odd));
  });
  const consoleRole = await recording(["STS-XACML-0083"], function () {
    return roleAct("describe-role", { role: "ADMIN_READ",
                                      memberTypes: ["application"] });
  });
  check("G9. a console role cannot be restricted, STS-XACML-0083",
        function () {
    assert.ok(consoleRole.out.status === 400 &&
              consoleRole.seen["STS-XACML-0083"],
              consoleRole.out.raw.slice(0, 300));
  });
  await ok(roleAct("create-role", { role: PEOPLE, memberTypes: ["user"] }),
           "made a people-only role");
  const hr = await application(HR);
  const state = hr.page.roles;
  const held = (state.held || []).filter(function (one) {
    return one.name === MACHINES;
  })[0];
  check("G10. the application's page lists the role it holds, realm-wide, " +
        "with its label and id", function () {
    assert.ok(held && held.displayName === "Batch machines" &&
              held.id === made.id && held.carriedAs === MACHINES &&
              held.application === "", JSON.stringify(state.held));
  });
  check("G11. it is offered neither a people-only role nor one it holds, " +
        "and is offered an unrestricted one", function () {
    assert.ok(state.offerable.indexOf(PEOPLE) < 0 &&
              state.offerable.indexOf(MACHINES) < 0 &&
              state.offerable.indexOf(STAFF) >= 0,
              JSON.stringify(state.offerable));
  });
  check("G12. and the GET answer carries the same, as applicationRoles",
        function () {
    assert.ok(hr.applicationRoles.held.some(function (one) {
      return one.name === MACHINES;
    }), JSON.stringify(hr.applicationRoles));
  });
  log.debug("Leaving memberTypes().");
}

function fieldNamed(list, attribute) {
  log.debug("Entering fieldNamed().");
  log.debug("Leaving fieldNamed().");
  return (list || []).some(function (one) {
    return one.attribute === attribute;
  });
}

async function requirementSection() {
  log.debug("Entering requirementSection().");
  log.info("=== H. the Roles tab's requirement section (#458) ===");
  const payroll = await application(PAYROLL);
  const form = (await send(API + "/applications/new")).body;
  check("H1. the application page's Configuration grid does not draw " +
        "appRequiredRole", function () {
    assert.ok(!fieldNamed(payroll.page.config.fields, "appRequiredRole"));
  });
  check("H2. the new-application form still offers it", function () {
    assert.ok(fieldNamed(form.fields, "appRequiredRole"));
  });
  const p = payroll.page.roles;
  check("H3. the page and the API both carry payroll's requirement, " +
        "resolved to its own reader", function () {
    assert.strictEqual(p.required.length, 1, JSON.stringify(p.required));
    assert.strictEqual(p.required[0].name, "reader");
    assert.strictEqual(p.required[0].resolves, "application");
    assert.strictEqual(p.required[0].role, "reader@" + PAYROLL);
    assert.deepStrictEqual(payroll.applicationRoles.required, p.required);
  });
  check("H4. it is offered the realm-wide and built-in roles, but not " +
        "EVERYBODY, not what it requires and never another application's",
        function () {
    assert.ok(p.requirable.indexOf(STAFF) >= 0 &&
              p.requirable.indexOf("ALL_AUTHENTICATED_USERS") >= 0 &&
              p.requirable.indexOf("EVERYBODY") < 0 &&
              p.requirable.indexOf("reader") < 0 &&
              p.requirable.indexOf("reader@" + HR) < 0,
              JSON.stringify(p.requirable));
  });
  const hr = (await application(HR)).page.roles;
  check("H5. hr's writer, which nothing defines, resolves to nothing; its " +
        "own reader is offered by its name inside it", function () {
    assert.ok(hr.required.length === 1 && hr.required[0].name === "writer" &&
              hr.required[0].resolves === "none", JSON.stringify(hr));
    assert.ok(hr.requirable.indexOf("reader") >= 0,
              JSON.stringify(hr.requirable));
  });
  await ok(appAct("add", { application: HR, attribute: "appRequiredRole",
                           value: STAFF }), "required the staff role");
  await ok(appAct("remove", { application: HR, attribute: "appRequiredRole",
                              value: "writer" }), "removed writer");
  const after = (await application(HR)).page.roles;
  check("H6/H7. Require and Remove write appRequiredRole, and the section " +
        "shows the realm-wide role, no longer offered", function () {
    assert.ok(after.required.length === 1 &&
              after.required[0].name === STAFF &&
              after.required[0].resolves === "realm",
              JSON.stringify(after.required));
    assert.ok(after.requirable.indexOf(STAFF) < 0);
  });
  await ok(appAct("remove", { application: HR, attribute: "appRequiredRole",
                              value: STAFF }), "removed the last");
  const none = (await application(HR)).page.roles;
  const anybody = await passwordGrant(HR, ALICE);
  check("H8. removing the last leaves it requiring nothing, which is " +
        "everybody: anybody is issued a token for it", function () {
    assert.strictEqual(none.required.length, 0, JSON.stringify(none));
    assert.strictEqual(anybody.status, 200, anybody.raw.slice(0, 300));
  });
  log.debug("Leaving requirementSection().");
}

async function permissionRules() {
  log.debug("Entering permissionRules().");
  log.info("=== P. a permission's identifier and name " +
           "(app_permissions.js) ===");
  const API_APP = "perm-" + RUN;
  await ok(appAct("create", { identifier: API_APP, protocols: ["oauth2"],
    "field.oauthPermissionBaseUri": "https://perm-" + RUN + ".example",
    "field.oauthPermission.0": "write|Change widgets|now",
    "field.oauthPermission.1": "read" }), "created an API");
  const exposes = (await application(API_APP)).delegatedPermissions.exposes;
  const write = exposes.filter(function (one) {
    return one.name === "write";
  })[0];
  check("P1. a base with no separator gets one: the identifier is the base " +
        "and the name, joined once", function () {
    assert.ok(write, JSON.stringify(exposes));
    assert.strictEqual(write.id, "https://perm-" + RUN + ".example/write");
  });
  check("P2. the description is everything after the FIRST delimiter",
        function () {
    assert.strictEqual(write.description, "Change widgets|now");
    const read = exposes.filter(function (one) {
      return one.name === "read";
    })[0];
    assert.strictEqual(read.description, "");
  });
  await ok(appAct("set", { application: API_APP,
    attribute: "oauthPermissionBaseUri", value: "api://8f2c" }),
    "set an api:// base");
  const entra = (await application(API_APP)).delegatedPermissions.exposes
    .filter(function (one) {
      return one.name === "read";
    })[0];
  check("P3. any absolute base is accepted, Entra ID's api:// spelling " +
        "included", function () {
    assert.strictEqual(entra.id, "api://8f2c/read");
  });
  const spaced = await appAct("add", { application: API_APP,
    attribute: "oauthPermission", value: "read write" });
  check("P4. a name with a space, which is no scope token, is refused",
        function () {
    assert.strictEqual(spaced.status, 400, spaced.raw.slice(0, 300));
    assert.ok(/not a legal OAuth scope token/.test(errorsOf(spaced)));
  });
  for (const value of ["audit|refused at sign-in (STS-AUTHN-0294)",
                       "STS-AUTHN-0294"]) {
    const coded = await appAct("add", { application: API_APP,
      attribute: "oauthPermission", value: value });
    check("P5. a permission naming an operator code is refused (" +
          value.slice(0, 20) + "), and the refusal does not repeat it",
          function () {
      assert.strictEqual(coded.status, 400, coded.raw.slice(0, 300));
      assert.ok(/operator error code/.test(errorsOf(coded)));
      assert.ok(!/STS-[A-Z]+-[0-9]{4}/.test(errorsOf(coded)), coded.raw);
    });
  }
  const relative = await appAct("set", { application: API_APP,
    attribute: "oauthPermissionBaseUri", value: "example.com" });
  check("P6. a base that is not absolute is refused", function () {
    assert.strictEqual(relative.status, 400, relative.raw.slice(0, 300));
    assert.ok(/not an absolute URI/.test(errorsOf(relative)));
  });
  log.debug("Leaving permissionRules().");
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. a throwaway realm " + REALM + " ===");
  await setUp();
  await naming();
  await resolutionAndClaim();
  await requirement();
  await permissions();
  await memberTypes();
  await requirementSection();
  await permissionRules();
  log.info(checks + " checks passed.");
  log.debug("Leaving test().");
}

// REMOVAL IS OPT-IN (#444 D12). tests/CLAUDE.md's *No job removes a realm*
// is the rule for a suite run, whose realms an operator reads afterwards;
// a run against a private probe sets STS_TEST_REMOVE_REALMS=1 so that the
// realms this job made do not fill a directory shared with other runs.
async function removeRealms(ids) {
  log.debug("Entering removeRealms().");
  if (process.env.STS_TEST_REMOVE_REALMS !== "1") {
    log.debug("Leaving removeRealms(). Kept.");
    return;
  }
  for (const id of ids) {
    try {
      const r = await fetch(base + "/admin-api/realms/remove", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: id }) });
      log.info("removed the realm " + id + ": " + r.status);
    } catch (e) {
      log.debug("Caught in removeRealms(): " + ((e && e.message) || e));
      // A removal that fails leaves the realm standing, which is what a
      // suite run does anyway; the job's verdict is already decided.
    }
  }
  log.debug("Leaving removeRealms().");
}

async function main() {
  log.debug("Entering main().");
  try {
    try {
      await test();
    } finally {
      await removeRealms([REALM]);
    }
    log.info("Test completed successfully.");
    log.debug("Leaving main().");
    process.exit(0);
  } catch (e) {
    log.error("Test failed: " + ((e && e.stack) || e));
    log.debug("Leaving main(). Failed.");
    process.exit(1);
  }
}

main();
