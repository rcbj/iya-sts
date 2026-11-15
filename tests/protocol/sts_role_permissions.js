// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_role_permissions.js
//
// ---------------------------------------------------------------------------
// A SCOPE IS A REQUEST; A ROLE IS WHAT AUTHORIZES IT, OVER THE WIRE (#302,
// #303, #551).
//
// D12 (#444): carries over tests/role_permissions.js A, B, C, D, H and I as
// a client sees them, at a throwaway development realm's own token endpoint
// and `/admin-api`:
//
//   A. the realm is seeded with ADMIN_READ, ADMIN_WRITE and SECURITY_ADMIN,
//      each held by sts-api-client and authorizing its own admin scope; a
//      person cannot be written onto one here, one cannot be deleted, and
//      its permission cannot be changed;
//   B. once the roster names somebody, a person holding no console role is
//      issued neither admin scope (one STS-ADMIN-0821 row records what was
//      taken off, and the access token does not carry them), Admin Read is
//      issued admin:read alone, Admin Write both, and only admin:write for
//      Admin Read is invalid_scope;
//   C. a client declaring both admin scopes but holding no role is issued
//      neither; in ADMIN_READ admin:read; sts-api-client both;
//      DEVICE_COMPLIANCE is native, seeded with no member, authorizing
//      device:compliance only to a member, and cannot be deleted;
//   D. an application permission, ungated, is issued as it always was;
//      gating a name the resource does not define is refused
//      (STS-REG-0090); gated, a person holding no role naming it is
//      refused; a native permission and an undefined one cannot be put on
//      an ordinary role; holding a role authorizing it, the person and the
//      client are issued it;
//   H. on client_credentials a permission the client holds only by
//      delegation is invalid_scope alone and left off beside another scope
//      (STS-OAUTH-0957), and issued once a role it holds authorizes it;
//   I. SSF_READ and SSF_MANAGE are native roles seeded with their groups
//      and no application; client_credentials carries ssf.read and
//      ssf.manage only while the client is in the role.
//
// What stays in process (its D12 note): held ∩ carried on a token already
// issued (E), the XACML PIP's role designator (F) and the per-scope
// policy's fallbacks (G), each a question asked of a module rather than of
// a request.
//
// OWNED HERE (local: true): this repository's own roles, management API and
// token endpoint.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const names = require("./random_username.js");
const authnSignin = require("./authn_signin.js");
const consoleSignIn = require("./console_signin.js");

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
var log = bunyan.createLogger({ name: "sts_role_permissions",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("rpm-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
  .slice(0, 31);
const RB = base + "/realm/" + REALM;
const API = RB + "/admin-api";
const CLIENT = "rp-client";
const MACHINE = "rp-machine";
const RESOURCE = "rp-api";
const RESOURCE_BASE = "https://rp-api-" + REALM + ".example/";
const PERMISSION = RESOURCE_BASE + "read";
const WRITE = RESOURCE_BASE + "write";
const ADMIN = "openid admin:read admin:write";
const SECRET = "rp-secret-" + STAMP.toLowerCase();
const PEOPLE = { nobody: "rp-nobody", reader: "rp-reader",
                 writer: "rp-writer" };

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
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

function postJson(url, payload) {
  log.debug("Entering postJson().");
  log.debug("Leaving postJson().");
  return send(url, { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}) });
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await postJson(url, payload);
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + String(r.raw).slice(0, 400));
  log.debug("Leaving ok().");
  return r.body;
}

async function codeCount(code) {
  log.debug("Entering codeCount(). " + code);
  const r = await send(API + "/audit?per=1&code=" + encodeURIComponent(code));
  assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
  log.debug("Leaving codeCount().");
  return Number(r.body.matched || 0);
}

// Runs `act` and answers it with how far the code's count on the realm's
// audit grew: a code is recorded, never sent.
async function coded(code, act) {
  log.debug("Entering coded(). " + code);
  const before = await codeCount(code);
  const answer = await act();
  let now = before;
  for (let i = 0; i < 20 && now <= before; i += 1) {
    now = await codeCount(code);
    if (now <= before) {
      await sleep(150);
    }
  }
  log.debug("Leaving coded(). " + before + " -> " + now);
  return { answer: answer, grew: now - before };
}

function token(form) {
  log.debug("Entering token().");
  log.debug("Leaving token().");
  return send(RB + "/oauth2/token", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(form).toString() });
}

// A person's token through the confidential client's password grant, which
// reaches the same issuance as every other grant does.
function personToken(who, scope, clientId) {
  log.debug("Entering personToken(). " + who);
  log.debug("Leaving personToken().");
  return token({ grant_type: "password", username: who,
    password: "anything", client_id: clientId || CLIENT,
    client_secret: SECRET, scope: scope });
}

function machineToken(clientId, scope) {
  log.debug("Entering machineToken(). " + clientId);
  log.debug("Leaving machineToken().");
  return token({ grant_type: "client_credentials", client_id: clientId,
    client_secret: SECRET, scope: scope });
}

// Whether an answer issued an application permission. OBSERVED: the
// answer's scope names it by its short name (`read`), the resource being
// the token's audience.
function issued(reply, permission) {
  log.debug("Entering issued().");
  const short = String(permission).slice(RESOURCE_BASE.length);
  log.debug("Leaving issued().");
  return scopesOf(reply).split(" ").some(function (one) {
    return one === permission || one === short;
  });
}

function scopesOf(reply) {
  log.debug("Entering scopesOf().");
  log.debug("Leaving scopesOf().");
  return String((reply.body && reply.body.scope) || "").split(" ")
    .filter(Boolean).sort().join(" ");
}

function claimsOf(jwt) {
  log.debug("Entering claimsOf().");
  let claims = {};
  try {
    claims = JSON.parse(Buffer.from(String(jwt).split(".")[1], "base64url")
      .toString("utf8"));
  } catch (e) {
    log.debug("Caught in claimsOf(): " + ((e && e.message) || e));
    // Not a JWT; the check that reads it fails on the empty object.
    claims = {};
  }
  log.debug("Leaving claimsOf().");
  return claims;
}

function role(body) {
  log.debug("Entering role(). " + body.action);
  log.debug("Leaving role().");
  return postJson(API + "/roles/" + body.action, Object.assign({}, body,
    { action: undefined }));
}

async function roleRow(name) {
  log.debug("Entering roleRow(). " + name);
  const r = await send(API + "/roles?role=" + encodeURIComponent(name));
  assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
  const rows = (r.body.roles || []).filter(function (one) {
    return one.name === name;
  });
  log.debug("Leaving roleRow().");
  return rows[0] || r.body.role || null;
}

function client(identifier, fields) {
  log.debug("Entering client(). " + identifier);
  log.debug("Leaving client().");
  return ok(API + "/applications/create", { identifier: identifier,
    kind: "oauth2-client", name: identifier, protocols: ["oauth2"],
    fields: Object.assign({ oauthClientId: [identifier],
      oauthClientSecret: SECRET,
      oauthTokenEndpointAuthMethod: "client_secret_post",
      oauthRedirectUri: ["https://" + identifier + ".example.net/cb"] },
      fields) }, "created " + identifier);
}

async function setUp() {
  log.debug("Entering setUp().");
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "Role permissions " + STAMP },
    "created the realm");
  await client(CLIENT, { oauthGrantType: ["password"],
    oauthAllowedScope: ["openid", PERMISSION, WRITE],
    oauthDelegatedPermission: ["urn:sts:admin-api:admin:read",
                               "urn:sts:admin-api:admin:write"] });
  await client(MACHINE, { oauthGrantType: ["client_credentials"],
    oauthAllowedScope: ["api", "device:compliance", PERMISSION],
    oauthDelegatedPermission: ["urn:sts:admin-api:admin:read",
                               "urn:sts:admin-api:admin:write"] });
  await ok(API + "/applications/create", { identifier: RESOURCE,
    kind: "oauth2-client", name: RESOURCE, protocols: ["oauth2"],
    fields: { oauthClientId: [RESOURCE],
              oauthPermissionBaseUri: RESOURCE_BASE,
              oauthPermission: ["read", "write"] } },
    "created the resource");
  for (const who of Object.keys(PEOPLE)) {
    await ok(API + "/users/create", { username: PEOPLE[who], invent: false,
      attributes: { cn: "Person " + who, sn: who, givenName: "Person" } },
      "created " + PEOPLE[who]);
  }
  log.debug("Leaving setUp().");
}

async function consoleRoles() {
  log.debug("Entering consoleRoles().");
  log.info("=== A. the console roles ===");
  const own = { ADMIN_READ: "admin:read", ADMIN_WRITE: "admin:write",
                SECURITY_ADMIN: "admin:security" };
  for (const name of Object.keys(own)) {
    const row = await roleRow(name);
    check(name + " is seeded, held by sts-api-client, authorizing " +
          own[name], function () {
      assert.ok(row, "no row for " + name);
      assert.strictEqual(row.console, true, JSON.stringify(row));
      assert.ok((row.applications || []).indexOf("sts-api-client") >= 0,
                JSON.stringify(row.applications));
      assert.deepStrictEqual(row.permissions, [own[name]]);
    });
  }
  const person = await role({ action: "add-member", role: "ADMIN_WRITE",
                              kind: "user", member: PEOPLE.nobody });
  check("a person cannot be written onto a console role here", function () {
    assert.strictEqual(person.status, 400, person.raw.slice(0, 300));
    assert.ok(/roster/.test(person.raw), person.raw.slice(0, 300));
  });
  const removed = await role({ action: "delete-role", role: "ADMIN_READ" });
  check("a console role cannot be deleted", function () {
    assert.strictEqual(removed.status, 400, removed.raw.slice(0, 300));
  });
  const repermitted = await role({ action: "add-permission",
                                   role: "ADMIN_READ",
                                   permission: PERMISSION });
  check("and its permission cannot be changed", function () {
    assert.strictEqual(repermitted.status, 400,
                       repermitted.raw.slice(0, 300));
  });
  log.debug("Leaving consoleRoles().");
}

// THE REALM'S CONSOLE CLAIMED, as development claims it: the bootstrap
// administrator signs in through the console's own client (`admin-ui/
// CLAUDE.md` 8a). Until then development's window gives every signed-in
// person both console roles, so B could not tell a role from the window.
async function claimConsole() {
  log.debug("Entering claimConsole().");
  const cookies = consoleSignIn.jar();
  const hop = async function (url) {
    const r = await fetch(new URL(url, RB).toString(), { redirect: "manual",
      headers: { cookie: cookies.header() } });
    cookies.keep(r);
    return r;
  };
  await hop(RB + "/admin");
  const verifier = crypto.randomBytes(32).toString("base64url");
  const authorize = RB + "/oauth2/authorize?" + new URLSearchParams({
    response_type: "code", client_id: "sts-admin-console",
    redirect_uri: RB + "/admin/callback", scope: "openid admin:read",
    state: "claim-" + STAMP, code_challenge_method: "S256",
    code_challenge: crypto.createHash("sha256").update(verifier)
      .digest("base64url"), resource: API }).toString();
  const toScreen = await hop(authorize);
  const where = new URL(toScreen.headers.get("location") || "", RB)
    .toString();
  const newPassword = "Claimed-Console-" + STAMP + "-9!";
  let answered = await authnSignin.signIn(RB, where, { action: "login",
    username: "admin", password: "anything-at-all" },
    { cookie: cookies.header() });
  cookies.keep(answered);
  for (let step = 0; step < 2 && answered.next === "password-change";
       step += 1) {
    answered = await authnSignin.changePassword(RB, answered.location,
      { new_password: newPassword, confirm_password: newPassword },
      { cookie: cookies.header() });
    cookies.keep(answered);
    answered = await authnSignin.ignoreOffer(RB, answered);
    cookies.keep(answered);
  }
  let at = await hop(answered.location || authorize);
  for (let i = 0; i < 5 && (at.status === 302 || at.status === 303) &&
       !/\/admin\/callback\?/.test(at.headers.get("location") || ""); i++) {
    at = await hop(at.headers.get("location"));
  }
  const roster = await send(API + "/rbac");
  assert.ok(roster.body.bootstrap.claimedAt, "signing in as admin did not " +
            "claim the realm's console: " + JSON.stringify(roster.body
              .bootstrap) + " " + at.status + " " +
            (at.headers.get("location") || ""));
  log.debug("Leaving claimConsole().");
}

async function people() {
  log.debug("Entering people().");
  log.info("=== B. a person and admin:* ===");
  await claimConsole();
  await ok(API + "/rbac/grant", { username: PEOPLE.writer, role: "write" },
           "granted Admin Write");
  await ok(API + "/rbac/grant", { username: PEOPLE.reader, role: "read" },
           "granted Admin Read");
  const nobody = await coded("STS-ADMIN-0821", function () {
    return personToken(PEOPLE.nobody, ADMIN);
  });
  check("once the roster names somebody, a person with no role is issued " +
        "neither admin scope, and one STS-ADMIN-0821 row records it",
        function () {
    assert.strictEqual(nobody.answer.status, 200, nobody.answer.raw
      .slice(0, 300));
    assert.strictEqual(scopesOf(nobody.answer), "openid");
    assert.strictEqual(nobody.grew, 1, "STS-ADMIN-0821 rows grew by " +
                       nobody.grew);
  });
  check("and the access token does not carry them", function () {
    assert.strictEqual(claimsOf(nobody.answer.body.access_token).scope,
                       "openid");
  });
  const reader = await personToken(PEOPLE.reader, ADMIN);
  check("Admin Read is issued admin:read and not admin:write", function () {
    assert.strictEqual(scopesOf(reader), "admin:read openid",
                       reader.raw.slice(0, 300));
  });
  const writer = await personToken(PEOPLE.writer, ADMIN);
  check("Admin Write, which implies Admin Read, is issued both",
        function () {
    assert.strictEqual(scopesOf(writer), "admin:read admin:write openid",
                       writer.raw.slice(0, 300));
  });
  const only = await personToken(PEOPLE.reader, "admin:write");
  check("only admin:write, for a holder of Admin Read, is invalid_scope",
        function () {
    assert.strictEqual(only.status, 400, only.raw.slice(0, 300));
    assert.strictEqual(only.body.error, "invalid_scope");
  });
  log.debug("Leaving people().");
}

async function machines() {
  log.debug("Entering machines().");
  log.info("=== C. an application and admin:* ===");
  const bare = await machineToken(MACHINE, "admin:read admin:write");
  check("a client declaring both admin scopes but holding no role is " +
        "issued neither", function () {
    assert.strictEqual(bare.status, 400, bare.raw.slice(0, 300));
    assert.strictEqual(bare.body.error, "invalid_scope");
  });
  await ok(API + "/roles/add-member", { role: "ADMIN_READ",
    kind: "application", member: MACHINE }, "added the client to ADMIN_READ");
  const read = await machineToken(MACHINE, "admin:read admin:write");
  check("in ADMIN_READ it is issued admin:read and not admin:write",
        function () {
    assert.strictEqual(scopesOf(read), "admin:read", read.raw.slice(0, 300));
  });
  const feed = await roleRow("DEVICE_COMPLIANCE");
  check("DEVICE_COMPLIANCE is a native role with no member, authorizing " +
        "device:compliance", function () {
    assert.ok(feed && feed.native === true && feed.console !== true,
              JSON.stringify(feed));
    assert.deepStrictEqual(feed.applications || [], []);
    assert.deepStrictEqual(feed.permissions, ["device:compliance"]);
  });
  const notIn = await machineToken(MACHINE, "device:compliance");
  check("a client declaring device:compliance but not in the role is not " +
        "issued it", function () {
    assert.strictEqual(notIn.status, 400, notIn.raw.slice(0, 300));
    assert.strictEqual(notIn.body.error, "invalid_scope");
  });
  await ok(API + "/roles/add-member", { role: "DEVICE_COMPLIANCE",
    kind: "application", member: MACHINE },
    "added the client to DEVICE_COMPLIANCE");
  const inRole = await machineToken(MACHINE, "device:compliance");
  check("in the role, it is issued the scope", function () {
    assert.strictEqual(scopesOf(inRole), "device:compliance",
                       inRole.raw.slice(0, 300));
  });
  const gone = await role({ action: "delete-role",
                            role: "DEVICE_COMPLIANCE" });
  check("and the role cannot be deleted", function () {
    assert.strictEqual(gone.status, 400, gone.raw.slice(0, 300));
  });
  log.debug("Leaving machines().");
}

async function gatedPermission() {
  log.debug("Entering gatedPermission().");
  log.info("=== D. a gated application permission ===");
  const ungated = await personToken(PEOPLE.nobody, "openid " + PERMISSION);
  check("ungated, it is issued as it always was", function () {
    assert.ok(issued(ungated, PERMISSION),
              "scope: " + scopesOf(ungated));
  });
  const badGate = await coded("STS-REG-0090", function () {
    return postJson(API + "/applications/add", { application: RESOURCE,
      attribute: "oauthRoleGatedPermission", value: "delete" });
  });
  check("gating a name the resource does not define is refused, " +
        "recorded as STS-REG-0090", function () {
    assert.strictEqual(badGate.answer.status, 400,
                       badGate.answer.raw.slice(0, 300));
    assert.strictEqual(badGate.grew, 1);
  });
  await ok(API + "/applications/add", { application: RESOURCE,
    attribute: "oauthRoleGatedPermission", value: "read" },
    "gated read");
  const refused = await personToken(PEOPLE.nobody, PERMISSION);
  check("gated, a person holding no role naming it is refused", function () {
    assert.strictEqual(refused.status, 400, refused.raw.slice(0, 300));
    assert.strictEqual(refused.body.error, "invalid_scope");
  });
  const readers = "rp-readers";
  await ok(API + "/roles/create-role", { role: readers }, "made a role");
  await ok(API + "/roles/add-member", { role: readers, kind: "user",
    member: PEOPLE.nobody }, "put the person in it");
  await ok(API + "/roles/add-member", { role: readers, kind: "application",
    member: MACHINE }, "put the client in it");
  const native = await role({ action: "add-permission", role: readers,
                              permission: "admin:read" });
  check("a native permission cannot be put on an ordinary role",
        function () {
    assert.strictEqual(native.status, 400, native.raw.slice(0, 300));
  });
  const nobodyDefines = await role({ action: "add-permission", role: readers,
                                     permission: RESOURCE_BASE + "delete" });
  check("nor a permission nobody defines", function () {
    assert.strictEqual(nobodyDefines.status, 400,
                       nobodyDefines.raw.slice(0, 300));
  });
  const added = await ok(API + "/roles/add-permission", { role: readers,
    permission: PERMISSION }, "authorized the gated permission");
  check("a defined, gated permission is authorized", function () {
    assert.strictEqual(added.gated, true, JSON.stringify(added));
  });
  await ok(API + "/roles/describe-role", { role: readers,
    description: "readers" }, "described the role");
  const described = await roleRow(readers);
  check("and editing the role's description keeps it", function () {
    assert.deepStrictEqual(described.permissions, [PERMISSION]);
  });
  const person = await personToken(PEOPLE.nobody, "openid " + PERMISSION);
  check("holding the role, the person is issued it", function () {
    assert.ok(issued(person, PERMISSION),
              "scope: " + scopesOf(person));
  });
  const machine = await machineToken(MACHINE, PERMISSION);
  check("and so is the client, on client_credentials", function () {
    assert.ok(issued(machine, PERMISSION),
              "scope: " + scopesOf(machine));
  });
  log.debug("Leaving gatedPermission().");
}

async function applicationPermission() {
  log.debug("Entering applicationPermission().");
  log.info("=== H. an application permission comes from a role ===");
  await ok(API + "/applications/add", { application: MACHINE,
    attribute: "oauthDelegatedPermission", value: WRITE },
    "gave the client write by delegation");
  const alone = await machineToken(MACHINE, WRITE);
  check("client_credentials asking only for a permission held by " +
        "delegation alone is invalid_scope", function () {
    assert.strictEqual(alone.status, 400, alone.raw.slice(0, 300));
    assert.strictEqual(alone.body.error, "invalid_scope");
  });
  const beside = await coded("STS-OAUTH-0957", function () {
    return machineToken(MACHINE, "api " + WRITE);
  });
  check("beside another scope the permission is left off, recorded as " +
        "STS-OAUTH-0957", function () {
    const got = scopesOf(beside.answer).split(" ");
    assert.ok(!issued(beside.answer, WRITE) && got.indexOf("api") >= 0,
              beside.answer.raw.slice(0, 300));
    assert.ok(beside.grew >= 1, "STS-OAUTH-0957 rows grew by " + beside.grew);
  });
  const writers = "rp-writers";
  await ok(API + "/roles/create-role", { role: writers }, "made a role");
  await ok(API + "/roles/add-member", { role: writers, kind: "application",
    member: MACHINE }, "put the client in it");
  await ok(API + "/roles/add-permission", { role: writers,
    permission: WRITE }, "authorized write");
  const held = await machineToken(MACHINE, WRITE);
  check("holding the role, the client is issued it", function () {
    assert.ok(issued(held, WRITE),
              "scope: " + scopesOf(held));
  });
  const person = await personToken(PEOPLE.nobody, "openid " + WRITE);
  check("a person's ungated permission is issued as before", function () {
    assert.ok(issued(person, WRITE),
              "scope: " + scopesOf(person));
  });
  log.debug("Leaving applicationPermission().");
}

async function sharedSignals() {
  log.debug("Entering sharedSignals().");
  log.info("=== I. Shared Signals roles ===");
  const app = "rp-ssf-app";
  await client(app, { oauthGrantType: ["client_credentials"],
                      oauthAllowedScope: ["ssf.read", "ssf.manage"] });
  for (const pair of [["SSF_READ", "ssf-read", "ssf.read"],
                      ["SSF_MANAGE", "ssf-manage", "ssf.manage"]]) {
    const row = await roleRow(pair[0]);
    check(pair[0] + " is a native role, seeded with " + pair[1] + " and no " +
          "application, authorizing " + pair[2], function () {
      assert.ok(row && row.native === true && row.console !== true,
                JSON.stringify(row));
      assert.deepStrictEqual(row.applications || [], []);
      assert.ok((row.groups || []).some(function (g) {
        return String(g.name || g.cn || g).indexOf(pair[1]) >= 0;
      }), JSON.stringify(row.groups));
      assert.deepStrictEqual(row.permissions, [pair[2]]);
    });
  }
  const bare = await machineToken(app, "ssf.read ssf.manage");
  check("client_credentials without membership is issued neither",
        function () {
    assert.strictEqual(bare.status, 400, bare.raw.slice(0, 300));
    assert.strictEqual(bare.body.error, "invalid_scope");
  });
  await ok(API + "/roles/add-member", { role: "SSF_READ",
    kind: "application", member: app }, "added the client to SSF_READ");
  const read = await machineToken(app, "ssf.read ssf.manage");
  check("in SSF_READ it is issued ssf.read and not ssf.manage", function () {
    assert.strictEqual(scopesOf(read), "ssf.read", read.raw.slice(0, 300));
  });
  await ok(API + "/roles/add-member", { role: "SSF_MANAGE",
    kind: "application", member: app }, "added the client to SSF_MANAGE");
  const both = await machineToken(app, "ssf.read ssf.manage");
  check("in both roles it is issued both", function () {
    assert.strictEqual(scopesOf(both), "ssf.manage ssf.read",
                       both.raw.slice(0, 300));
  });
  log.debug("Leaving sharedSignals().");
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. a throwaway realm " + REALM + " ===");
  await setUp();
  await consoleRoles();
  await people();
  await machines();
  await gatedPermission();
  await applicationPermission();
  await sharedSignals();
  log.info("Test completed successfully. " + checks + " check(s) passed.");
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error("sts_role_permissions FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
