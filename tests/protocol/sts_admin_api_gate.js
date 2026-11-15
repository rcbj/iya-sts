// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_admin_api_gate.js
//
// ===========================================================================
// THE MANAGEMENT API'S GATE, AS A CALLER MEETS IT (D12, #444).
//
// What `/admin-api` decides for each caller, and what it writes down about
// them, driven over HTTP with the tokens a caller really holds: people who
// signed in to the console as the console signs in (the public client
// `sts-admin-console`, PKCE, DPoP — `console_signin.js`) and the seeded
// `sts-api-client` by the client credentials grant. Everything happens in
// throwaway realms this job creates, A, B and F, so the default realm is
// only read.
//
//   A. THE AUDIT ACTOR IS THE TOKEN'S SUBJECT. A read and a group create
//      with a person's token name the person, on the HTTP row and on the
//      action's own; the same create with a body `actor` is refused 400
//      (STS-API-0009) and no row names the nominated name; the client's
//      token names the client; a role grant's row names the person.
//   B. A NAME THE BODY SUPPLIES IS NEVER THE ACTOR: `set-password` and a
//      passkey-policy save, with and without a body `actor`.
//   C. EVERY ACTION IS TOLD WHO IS ACTING: one act of each family that took
//      its actor from the body — roles, permissions, an application's
//      owner, global consent, SAML metadata — writes a row naming the
//      person; a back-channel retry of no delivery is refused in words.
//   D. `GET /admin-api/me`: Admin Write, Admin Read (held ∩ carried), a
//      role revoked after the token was minted, a client token, a realm's
//      own administrator (the `realm` authority, no service page) and the
//      realm's token under another realm's prefix.
//   E. THE OBJECT CHECK ON EVERY OPERATION (ASVS 5.0.0 8.2.2): the index
//      walked, every operation 401 with no token, 403 with a token without
//      its scope, refused at another realm and at the default realm with a
//      realm's token; a person made in A visible to A and not to B.
//   F. A TOKEN DIES WITH ITS SIGN-ON SESSION: two sessions of one person
//      in a third realm, the first ended by `/logout`'s selective sign-out
//      — its token 401 `invalid_token` recorded STS-API-0126, the second's
//      still 200, a client token unaffected.
//
// D12 (#444): carries over tests/admin_api_actor.js (1-4; 5, the gate off,
// is sts_admin_api_auth_required_mode.js's), tests/admin_api_nominated_
// actor.js, tests/admin_api_action_actor.js (1-6; 7's stand-in for a dead
// delivery has no wire form), tests/admin_api_me.js (1-5; 6 and 8 are
// sts_admin_api_auth_required_mode.js's, 7 is a cost), tests/admin_api_
// object_checks.js and tests/admin_api_session_bound.js, so they stay
// covered when Rust replaces Node.
//
// OWNED HERE (local: true): this repository's own management API and its
// gate.
// ===========================================================================

const assert = require("assert");
const names = require("./random_username.js");
const consoleSignIn = require("./console_signin.js");
const authnSignin = require("./authn_signin.js");

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
var log = bunyan.createLogger({ name: "sts_admin_api_gate",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const SECRET = process.env.STS_ADMIN_API_CLIENT_SECRET ||
               process.env.ADMIN_API_CLIENT_SECRET || "";
const STAMP = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "");

function realmId(prefix) {
  log.debug("Entering realmId().");
  log.debug("Leaving realmId().");
  return (prefix + STAMP).slice(0, 31);
}

const A = realmId("gatea");
const B = realmId("gateb");
// The session section's own realm, so the sessions it counts are its own.
const F = realmId("gatef");
const WRITER = ("gw" + STAMP).slice(0, 30);
const READER = ("gr" + STAMP).slice(0, 30);
const BWRITER = ("gb" + STAMP).slice(0, 30);
const SESSIONS = ("gs" + STAMP).slice(0, 30);
const VICTIM = ("gv" + STAMP).slice(0, 30);
const NOMINATED = "nominated-" + STAMP.slice(0, 12);

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

// One call. `token` undefined is the harness's own (the preload attaches
// it); null is NO credential at all — an empty Authorization header, which
// the preload leaves alone and the gate reads as none; a string is that
// bearer token.
async function call(method, url, token, payload) {
  log.debug("Entering call(). " + method + " " + url);
  const headers = { accept: "application/json" };
  if (token === null) {
    headers.authorization = "";
  } else if (typeof token === "string") {
    headers.authorization = "Bearer " + token;
  }
  const init = { method: method, headers: headers, redirect: "manual" };
  if (payload !== undefined) {
    headers["content-type"] = "application/json";
    init.body = JSON.stringify(payload);
  }
  const r = await fetch(url, init);
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
    // Not JSON: the caller reads `text`.
    json = null;
  }
  log.debug("Leaving call(). " + r.status);
  return { status: r.status, json: json, text: text, headers: r.headers };
}

// The sentences of a refusal, joined.
function errorsOf(reply) {
  log.debug("Entering errorsOf().");
  log.debug("Leaving errorsOf().");
  return [].concat((reply && reply.json && reply.json.errors) || []).join(" ");
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await call("POST", url, undefined, payload);
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + r.text.slice(0, 400));
  log.debug("Leaving ok().");
  return r.json;
}

// A client_credentials token for the seeded API client, audienced to a
// realm's management API, carrying `scope`.
async function clientToken(realmBase, scope) {
  log.debug("Entering clientToken().");
  const r = await fetch(realmBase + "/oauth2/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded",
               authorization: "Basic " + Buffer.from("sts-api-client:" +
                 SECRET).toString("base64") },
    body: new URLSearchParams({ grant_type: "client_credentials",
      scope: scope, resource: realmBase + "/admin-api" }).toString() });
  const text = await r.text();
  assert.strictEqual(r.status, 200, "the client credentials grant at " +
    realmBase + " answered " + r.status + " " + text.slice(0, 300));
  log.debug("Leaving clientToken().");
  return JSON.parse(text).access_token;
}

// The audit rows of a realm matching a filter, newest first.
async function rows(realmBase, query) {
  log.debug("Entering rows().");
  const r = await call("GET", realmBase + "/admin-api/audit?per=500&" +
                       new URLSearchParams(query).toString());
  assert.strictEqual(r.status, 200, "GET audit answered " + r.status);
  log.debug("Leaving rows().");
  return (r.json && r.json.events) || [];
}

// The rows recording `code`, waited for briefly.
async function codeRows(realmBase, code) {
  log.debug("Entering codeRows(). " + code);
  let found = [];
  for (let i = 0; i < 20 && !found.length; i += 1) {
    found = await rows(realmBase, { code: code });
    if (!found.length) {
      await sleep(150);
    }
  }
  log.debug("Leaving codeRows(). " + found.length);
  return found;
}

function newestSeq(list) {
  log.debug("Entering newestSeq().");
  let top = 0;
  list.forEach(function (row) {
    top = Math.max(top, Number(row.seq) || 0);
  });
  log.debug("Leaving newestSeq().");
  return top;
}

// The rows naming `actor` written after `since`, waited for briefly: the
// audit ring is read back through the API, which may answer before a row
// another worker wrote has been applied.
async function rowsSince(realmBase, actor, since, wanted) {
  log.debug("Entering rowsSince().");
  let found = [];
  for (let i = 0; i < 20; i += 1) {
    found = (await rows(realmBase, { actor: actor })).filter(function (row) {
      return (Number(row.seq) || 0) > since;
    });
    if (!wanted || found.some(wanted)) {
      break;
    }
    await sleep(150);
  }
  log.debug("Leaving rowsSince(). " + found.length);
  return found;
}

function brief(list) {
  log.debug("Entering brief().");
  log.debug("Leaving brief().");
  return JSON.stringify(list.map(function (row) {
    return row.action + " " + row.target + " " + row.errorCode;
  })).slice(0, 600);
}

// ---------------------------------------------------------------------------

async function sectionA(ctx) {
  log.debug("Entering sectionA().");
  log.info("=== A. the audit actor is the token's subject ===");
  const aBase = ctx.aBase;
  let since = newestSeq(await rows(aBase, {}));
  const read = await ctx.writer.api("GET", "/admin-api/config");
  assert.strictEqual(read.status, 200, "the writer's read answered " +
                     read.status);
  let named = await rowsSince(aBase, WRITER, since, function (row) {
    return row.action === "protocol.call" &&
      /\/admin-api\/config$/.test(row.target);
  });
  check("A1. a read with a person's token: the HTTP row names the person",
        function () {
    assert.ok(named.some(function (row) {
      return row.action === "protocol.call" &&
        /\/admin-api\/config$/.test(row.target);
    }), brief(named));
  });

  since = newestSeq(await rows(aBase, {}));
  const group = "gg-" + STAMP.slice(0, 20);
  const made = await ctx.writer.api("POST", "/admin-api/groups/create",
                                    { group: group });
  named = await rowsSince(aBase, WRITER, since, function (row) {
    return row.action === "group.create";
  });
  check("A2. a group create with the person's token: the HTTP row and the " +
        "directory's own row both name the person", function () {
    assert.strictEqual(made.status, 200, made.text.slice(0, 300));
    assert.ok(named.some(function (row) {
      return row.action === "group.create" &&
        row.target.indexOf("cn=" + group + ",") === 0;
    }), brief(named));
    assert.ok(named.some(function (row) {
      return row.action === "protocol.call" &&
        /\/admin-api\/groups\/create$/.test(row.target);
    }), brief(named));
  });

  const nominated = await ctx.writer.api("POST", "/admin-api/groups/create",
    { group: group + "-n", actor: NOMINATED });
  const refusedRows = await rows(aBase, { code: "STS-API-0009" });
  const nominatedRows = await rows(aBase, { actor: NOMINATED });
  check("A2. the same create naming an actor in its body is refused 400 by " +
        "the operation's schema, recorded STS-API-0009 against the person, " +
        "and no row names the nominated actor", function () {
    assert.strictEqual(nominated.status, 400, nominated.text.slice(0, 300));
    assert.ok(/"actor" is not a member of this request/
      .test(errorsOf(nominated)), nominated.text.slice(0, 300));
    assert.ok(nominated.text.indexOf("STS-API-0009") < 0,
              "the code was sent");
    assert.ok(refusedRows.some(function (row) {
      return row.actor === WRITER &&
        /\/admin-api\/groups\/create$/.test(row.target);
    }), brief(refusedRows));
    assert.strictEqual(nominatedRows.length, 0, brief(nominatedRows));
  });

  since = newestSeq(await rows(aBase, {}));
  const clientGroup = group + "-c";
  const byClient = await call("POST", aBase + "/admin-api/groups/create",
                              ctx.clientA, { group: clientGroup });
  named = await rowsSince(aBase, "sts-api-client", since, function (row) {
    return row.action === "group.create";
  });
  check("A3. the same write with the client's token names the client",
        function () {
    assert.strictEqual(byClient.status, 200, byClient.text.slice(0, 300));
    assert.ok(named.some(function (row) {
      return row.action === "group.create" &&
        row.target.indexOf("cn=" + clientGroup + ",") === 0;
    }), brief(named));
  });

  since = newestSeq(await rows(aBase, {}));
  const granted = await ctx.writer.api("POST", "/admin-api/rbac/grant",
                                       { username: VICTIM, role: "read" });
  named = await rowsSince(aBase, WRITER, since, function (row) {
    return row.action === "admin.role.change";
  });
  check("A4. a role grant, whose action takes the actor as an argument: " +
        "its row names the person", function () {
    assert.strictEqual(granted.status, 200, granted.text.slice(0, 300));
    assert.ok(named.some(function (row) {
      return row.action === "admin.role.change" &&
        /^cn=admin-read,/.test(row.target);
    }), brief(named));
  });
  const back = await ctx.writer.api("POST", "/admin-api/rbac/revoke",
                                    { username: VICTIM, role: "read" });
  assert.strictEqual(back.status, 200, back.text.slice(0, 200));
  log.debug("Leaving sectionA().");
}

// One act by the writer; its own row (not the HTTP one) names the writer.
async function actNamed(ctx, label, path, payload, action, target) {
  log.debug("Entering actNamed(). " + label);
  const since = newestSeq(await rows(ctx.aBase, {}));
  const got = await ctx.writer.api("POST", path, payload);
  const named = await rowsSince(ctx.aBase, WRITER, since, function (row) {
    return row.action === action;
  });
  check(label + ": the act succeeds and its " + action + " row names the " +
        "token's subject", function () {
    assert.ok(got.status === 200 && got.json && got.json.ok === true,
              got.status + " " + got.text.slice(0, 300));
    assert.ok(named.some(function (row) {
      return row.action === action && (!target || row.target === target);
    }), brief(named));
  });
  log.debug("Leaving actNamed().");
  return got;
}

// The passkey policy's whole default profile, as the save wants it: every
// field the profile's `sources` names, from the answer of GET policies.
async function passkeyFields(ctx, profile) {
  log.debug("Entering passkeyFields().");
  const listed = await ctx.writer.api("GET", "/admin-api/policies");
  assert.strictEqual(listed.status, 200, listed.text.slice(0, 200));
  const current = listed.json.passkey.profile;
  const fields = { profile: profile };
  Object.keys(current.sources || {}).forEach(function (name) {
    fields[name] = current[name];
  });
  log.debug("Leaving passkeyFields().");
  return fields;
}

async function sectionB(ctx) {
  log.debug("Entering sectionB().");
  log.info("=== B. a name the body supplies is not the actor ===");
  const nominated = await ctx.writer.api("POST", "/admin-api/users/" +
    "set-password", { user: VICTIM, generate: true, actor: NOMINATED });
  check("B1. set-password with a body actor is refused 400, before the " +
        "action", function () {
    assert.strictEqual(nominated.status, 400, nominated.text.slice(0, 300));
  });
  await actNamed(ctx, "B2. set-password omitting the actor",
                 "/admin-api/users/set-password",
                 { user: VICTIM, generate: true }, "password.set", VICTIM);

  const profile = "gp" + STAMP.slice(0, 18);
  const fields = await passkeyFields(ctx, profile);
  fields.recoveryAssurance = "not-weaker";
  fields.adminEnrolment = "on";
  const withActor = await ctx.writer.api("POST", "/admin-api/policies/" +
    "save-passkey-policy", Object.assign({ actor: NOMINATED }, fields));
  check("B3. a passkey-policy save naming an actor in its body is refused " +
        "400", function () {
    assert.strictEqual(withActor.status, 400, withActor.text.slice(0, 300));
    assert.ok(/"actor" is not a member/.test(errorsOf(withActor)),
              withActor.text.slice(0, 300));
  });
  const since = newestSeq(await rows(ctx.aBase, {}));
  const saved = await ctx.writer.api("POST", "/admin-api/policies/" +
                                     "save-passkey-policy", fields);
  const named = await rowsSince(ctx.aBase, WRITER, since, function (row) {
    return row.category === "admin" &&
      String(row.summary || "").indexOf(profile) >= 0;
  });
  check("B4. the save omitting it records the token's subject, and no row " +
        "names the nominated actor", function () {
    assert.ok(saved.status === 200 && saved.json && saved.json.ok === true,
              saved.status + " " + saved.text.slice(0, 400));
    assert.ok(named.some(function (row) {
      return String(row.summary || "").indexOf(profile) >= 0;
    }), brief(named));
  });
  const nominatedRows = await rows(ctx.aBase, { actor: NOMINATED });
  check("B5. nothing in the realm's audit log names the nominated actor",
        function () {
    assert.strictEqual(nominatedRows.length, 0, brief(nominatedRows));
  });
  const reset = await ctx.writer.api("POST", "/admin-api/policies/" +
                                     "reset-passkey-policy",
                                     { profile: profile });
  assert.strictEqual(reset.status, 200, reset.text.slice(0, 200));
  log.debug("Leaving sectionB().");
}

function samlEntity(entityId) {
  log.debug("Entering samlEntity().");
  const md = "urn:oasis:names:tc:SAML:2.0:metadata";
  log.debug("Leaving samlEntity().");
  return "<md:EntityDescriptor xmlns:md=\"" + md + "\" entityID=\"" +
    entityId + "\"><md:SPSSODescriptor protocolSupportEnumeration=\"" +
    "urn:oasis:names:tc:SAML:2.0:protocol\"><md:AssertionConsumerService " +
    "Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" " +
    "Location=\"https://gate-sp.test/acs\" index=\"0\"/>" +
    "</md:SPSSODescriptor></md:EntityDescriptor>";
}

async function sectionC(ctx) {
  log.debug("Entering sectionC().");
  log.info("=== C. every action is told who is acting ===");
  const app = "gate-app-" + STAMP.slice(0, 20);
  await ok(ctx.aBase + "/admin-api/applications/create", { identifier: app,
    kind: "oauth2-client", name: app, protocols: ["oauth2"],
    fields: { oauthClientId: [app] } }, "created the application");
  await actNamed(ctx, "C1. roles create-role", "/admin-api/roles/" +
                 "create-role", { role: "gr-" + STAMP.slice(0, 16) },
                 "roles.create");
  await actNamed(ctx, "C2. permissions set-permission-base",
                 "/admin-api/permissions/set-permission-base",
                 { resource: app, baseUri: "https://gate.test/" },
                 "application.update", app);
  await actNamed(ctx, "C3. permissions define-permission",
                 "/admin-api/permissions/define-permission",
                 { resource: app, name: "read", description: "Read it" },
                 "application.update", app);
  await actNamed(ctx, "C4. applications add-owner",
                 "/admin-api/applications/add-owner",
                 { application: app, owner: VICTIM },
                 "application.add-owner", app);
  await actNamed(ctx, "C5. consent grant-global-consent",
                 "/admin-api/consent/grant-global-consent",
                 { client: app, scope: "profile" }, "application.update",
                 app);
  const sp = "https://gate-sp-" + STAMP.slice(0, 16) + ".test/sp";
  const registered = await ctx.writer.api("POST", "/admin-api/saml2/register",
                                          { sp: sp });
  assert.strictEqual(registered.status, 200, registered.text.slice(0, 300));
  await actNamed(ctx, "C6. saml2 upload-metadata",
                 "/admin-api/saml2/upload-metadata",
                 { sp: sp, document: samlEntity(sp) }, "application.update",
                 sp);
  const retry = await ctx.writer.api("POST", "/admin-api/logout/" +
    "retry-backchannel", { delivery: "gate-none-" + STAMP.slice(0, 10) });
  check("C7. logout retry-backchannel of no delivery is refused 400 in a " +
        "sentence naming it", function () {
    assert.strictEqual(retry.status, 400, retry.text.slice(0, 300));
    assert.ok(/There is no back-channel delivery/.test(errorsOf(retry)),
              retry.text.slice(0, 300));
  });
  log.debug("Leaving sectionC().");
}

async function sectionD(ctx) {
  log.debug("Entering sectionD().");
  log.info("=== D. GET /admin-api/me ===");
  const w = await ctx.writer.api("GET", "/admin-api/me");
  check("D1. Admin Write in its own realm: a person, the realm authority, " +
        "that realm, both roles, read and write", function () {
    assert.strictEqual(w.status, 200, w.text.slice(0, 300));
    assert.strictEqual(w.json.caller.kind, "person");
    assert.strictEqual(w.json.caller.name, WRITER);
    assert.strictEqual(w.json.caller.clientId, "sts-admin-console");
    assert.strictEqual(w.json.authority, "realm");
    assert.strictEqual(w.json.realm, A);
    assert.strictEqual(w.json.read, true);
    assert.strictEqual(w.json.write, true);
    assert.ok(w.json.roles.indexOf("ADMIN_READ") >= 0 &&
              w.json.roles.indexOf("ADMIN_WRITE") >= 0,
              JSON.stringify(w.json.roles));
    assert.ok(w.json.tokenRequired === true);
  });
  check("D2. a realm administrator's pages hold its realm's pages and no " +
        "service page (/admin/persistence)", function () {
    const pages = w.json.pages || [];
    assert.ok(pages.indexOf("/admin/users") >= 0, JSON.stringify(pages));
    assert.ok(pages.indexOf("/admin/persistence") < 0,
              JSON.stringify(pages));
  });

  const r = await ctx.reader.api("GET", "/admin-api/me");
  check("D3. Admin Read reads and does not write; the console's token was " +
        "narrowed at issuance to what the person holds", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.ok(r.json.scopes.indexOf("admin:read") >= 0 &&
              r.json.scopes.indexOf("admin:write") < 0,
              JSON.stringify(r.json.scopes));
    assert.strictEqual(r.json.read, true);
    assert.strictEqual(r.json.write, false);
    assert.ok(r.json.roles.indexOf("ADMIN_WRITE") < 0,
              JSON.stringify(r.json.roles));
  });
  const write = await ctx.reader.api("POST", "/admin-api/groups/create",
    { group: "gr-refused-" + STAMP.slice(0, 12) });
  check("D3. and its write is refused 403", function () {
    assert.strictEqual(write.status, 403, write.text.slice(0, 300));
  });

  const demoted = await consoleSignIn.signInToTheConsole(ctx.aBase,
    ("gd" + STAMP).slice(0, 30), log, { grant: "write" });
  const before = await demoted.api("GET", "/admin-api/me");
  assert.ok(before.status === 200 && before.json.write === true,
            "precondition: " + before.text.slice(0, 300));
  const revoked = await call("POST", ctx.aBase + "/admin-api/rbac/revoke",
    undefined, { username: ("gd" + STAMP).slice(0, 30), role: "write" });
  assert.strictEqual(revoked.status, 200, revoked.text.slice(0, 200));
  const after = await demoted.api("GET", "/admin-api/me");
  const afterWrite = await demoted.api("POST", "/admin-api/groups/create",
    { group: "gd-refused-" + STAMP.slice(0, 12) });
  check("D4. Admin Write revoked after the token was minted shows on the " +
        "next call: the same token still reads and no longer writes",
        function () {
    assert.strictEqual(after.status, 200, after.text.slice(0, 300));
    assert.strictEqual(after.json.read, true);
    assert.strictEqual(after.json.write, false);
    assert.ok(after.json.scopes.indexOf("admin:write") >= 0,
              "the token itself still carries admin:write");
    assert.strictEqual(afterWrite.status, 403, afterWrite.text.slice(0, 300));
  });

  const c = await call("GET", ctx.aBase + "/admin-api/me", ctx.clientA);
  check("D5. a client_credentials token: an application, and no person",
        function () {
    assert.strictEqual(c.status, 200, c.text.slice(0, 300));
    assert.strictEqual(c.json.caller.kind, "application");
    assert.strictEqual(c.json.caller.name, "sts-api-client");
  });
  const s = await call("GET", base + "/admin-api/me");
  check("D5. the harness's service client in the default realm: the " +
        "service authority, with the service pages among its pages",
        function () {
    assert.strictEqual(s.status, 200, s.text.slice(0, 300));
    assert.strictEqual(s.json.authority, "service");
    assert.ok((s.json.pages || []).indexOf("/admin/persistence") >= 0 &&
              (s.json.pages || []).indexOf("/admin/users") >= 0,
              JSON.stringify(s.json.pages).slice(0, 300));
  });

  const cross = await call("GET", ctx.bBase + "/admin-api/me",
                           ctx.writer.token);
  check("D6. a realm's token under another realm's prefix is refused",
        function () {
    assert.ok(cross.status === 401 || cross.status === 403,
              cross.status + " " + cross.text.slice(0, 300));
  });
  log.debug("Leaving sectionD().");
}

// Every operation the index lists, with its parameters filled. A path
// parameter becomes `probe`; a POST gets an empty object.
async function operations(aBase) {
  log.debug("Entering operations().");
  const index = await call("GET", aBase + "/admin-api");
  assert.strictEqual(index.status, 200, index.text.slice(0, 200));
  const out = index.json.operations.map(function (op) {
    return { method: op.method, path: String(op.path)
      .replace(/\{[^}]+\}/g, "probe").replace(/:[A-Za-z_]+/g, "probe") };
  });
  log.debug("Leaving operations(). " + out.length);
  return out;
}

async function sectionE(ctx) {
  log.debug("Entering sectionE().");
  log.info("=== E. the object check, on every operation ===");
  const list = await operations(ctx.aBase);
  const noScope = await clientToken(ctx.aBase, "report:use");
  const open = [];
  const lacking = [];
  const crossed = [];
  const crossedDefault = [];
  let gated = 0;
  for (const one of list) {
    const body = one.method === "POST" ? {} : undefined;
    const anonymous = await call(one.method, ctx.aBase + one.path, null,
                                 body);
    if (anonymous.status !== 401) {
      open.push(one.method + " " + one.path + " " + anonymous.status);
      continue;
    }
    gated += 1;
    const narrow = await call(one.method, ctx.aBase + one.path, noScope,
                              body);
    if (narrow.status !== 403) {
      lacking.push(one.method + " " + one.path + " " + narrow.status);
    }
    const foreign = await call(one.method, ctx.bBase + one.path,
                               ctx.clientA, body);
    if (foreign.status !== 401 && foreign.status !== 403) {
      crossed.push(one.method + " " + one.path + " " + foreign.status);
    }
    const dflt = await call(one.method, base + one.path, ctx.clientA, body);
    if (dflt.status !== 401 && dflt.status !== 403) {
      crossedDefault.push(one.method + " " + one.path + " " + dflt.status);
    }
  }
  check("E1. the index was walked, and every operation it lists (" + gated +
        ") refuses a call with no token, 401", function () {
    assert.ok(list.length > 200, String(list.length));
    assert.strictEqual(open.length, 0, open.slice(0, 12).join(", "));
  });
  check("E2. a token without the operation's scope is refused 403, on " +
        "every operation", function () {
    assert.strictEqual(lacking.length, 0, lacking.slice(0, 12).join(", "));
  });
  check("E3. a realm's token is refused at another realm, on every " +
        "operation", function () {
    assert.strictEqual(crossed.length, 0, crossed.slice(0, 12).join(", "));
  });
  check("E4. and at the default realm, on every operation", function () {
    assert.strictEqual(crossedDefault.length, 0,
                       crossedDefault.slice(0, 12).join(", "));
  });

  const person = ("go" + STAMP).slice(0, 30);
  await ok(ctx.aBase + "/admin-api/users/create", { username: person,
    invent: false, attributes: { cn: "Only In A", sn: "A" } },
    "created a person in realm A");
  const inA = await ctx.writer.api("GET", "/admin-api/users?user=" + person);
  const inB = await ctx.bWriter.api("GET", "/admin-api/users?user=" + person);
  const listB = await ctx.bWriter.api("GET", "/admin-api/users");
  check("E5. an object in realm A is visible to A's administrator and " +
        "absent from B's", function () {
    assert.strictEqual(inA.status, 200, inA.text.slice(0, 200));
    assert.ok(inA.json.known !== false && inA.text.indexOf(person) >= 0,
              inA.text.slice(0, 300));
    assert.strictEqual(inB.status, 200, inB.text.slice(0, 200));
    assert.ok(inB.json.known === false || !inB.json.entry,
              inB.text.slice(0, 300));
    assert.strictEqual(listB.status, 200);
    assert.ok(listB.text.indexOf(person) < 0, "B's list names A's person");
  });
  log.debug("Leaving sectionE().");
}

// The ids of the sign-on sessions a realm holds now.
async function sessionIds(realmBase) {
  log.debug("Entering sessionIds().");
  const r = await call("GET", realmBase + "/admin-api/sessions");
  assert.strictEqual(r.status, 200, r.text.slice(0, 200));
  log.debug("Leaving sessionIds().");
  return (r.json.sessions || []).map(function (row) {
    return row.sid || row.id;
  });
}

async function sectionF(ctx) {
  log.debug("Entering sectionF().");
  log.info("=== F. a token dies with its sign-on session ===");
  const fBase = ctx.fBase;
  const first = await consoleSignIn.signInToTheConsole(fBase, SESSIONS,
                                                       log, { grant: "write" });
  const firstIds = await sessionIds(fBase);
  const second = await consoleSignIn.signInToTheConsole(fBase, SESSIONS,
                                                        log);
  const live = await first.api("GET", "/admin-api/me");
  check("F1. a token issued on a live session is accepted, and the realm " +
        "held that one session before the second sign-in", function () {
    assert.strictEqual(live.status, 200, live.text.slice(0, 300));
    assert.strictEqual(firstIds.length, 1, JSON.stringify(firstIds));
  });
  // /logout's selective sign-out of the FIRST session alone: a sign-out
  // with no selection ends every session the person holds and disowns
  // their tokens, which is a different refusal (STS-API-0122).
  const out = await authnSignin.signOut(fBase, { select: firstIds },
                                        { cookie: first.cookie });
  const left = await sessionIds(fBase);
  check("F2. the selective sign-out ends that session and only it",
        function () {
    assert.strictEqual(out.status, 200, String(out.text || "").slice(0, 300));
    assert.ok(out.json && out.json.ok === true &&
              out.json.scope === "selected",
              JSON.stringify(out.json || {}).slice(0, 300));
    assert.strictEqual(left.length, 1, JSON.stringify(left));
    assert.ok(left[0] !== firstIds[0], JSON.stringify(left));
  });
  const dead = await first.api("GET", "/admin-api/me");
  const coded = await codeRows(fBase, "STS-API-0126");
  check("F3. the same token is now refused 401 invalid_token, in words " +
        "naming the ended sign-on session, recorded STS-API-0126 and never " +
        "sent", function () {
    assert.strictEqual(dead.status, 401, dead.text.slice(0, 300));
    assert.ok(/invalid_token/.test(String(dead.headers
      .get("www-authenticate") || "")), dead.text.slice(0, 300));
    assert.ok(/sign-on session that has since ended/.test(errorsOf(dead)),
              errorsOf(dead));
    assert.ok(dead.text.indexOf("STS-API-0126") < 0, "the code was sent");
    assert.ok(coded.some(function (row) {
      return /\/admin-api\/me$/.test(row.target);
    }), brief(coded));
  });
  const other = await second.api("GET", "/admin-api/me");
  check("F4. a token issued on the SECOND, still live, session of the " +
        "same person goes on working: it is the session that ended, not " +
        "the person", function () {
    assert.strictEqual(other.status, 200, other.text.slice(0, 300));
  });
  const client = await call("GET", fBase + "/admin-api/me",
                            await clientToken(fBase, "admin:read"));
  check("F5. a client_credentials token, issued on no session, is not " +
        "affected", function () {
    assert.strictEqual(client.status, 200, client.text.slice(0, 300));
  });
  log.debug("Leaving sectionF().");
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. throwaway realms " + [A, B, F].join(", ") + " ===");
  for (const id of [A, B, F]) {
    await ok(base + "/admin-api/realms/create", { id: id,
      domain: id + ".example.net", name: "Management API gate " + STAMP },
      "created the realm " + id);
  }
  const ctx = { aBase: base + "/realm/" + A, bBase: base + "/realm/" + B,
                fBase: base + "/realm/" + F };
  await ok(ctx.aBase + "/admin-api/users/create", { username: VICTIM,
    invent: false, attributes: { cn: "Gate Victim", sn: "Victim" } },
    "created the person the acts name");
  ctx.writer = await consoleSignIn.signInToTheConsole(ctx.aBase, WRITER, log,
    { grant: ["write", "security"] });
  ctx.reader = await consoleSignIn.signInToTheConsole(ctx.aBase, READER, log,
    { grant: "read" });
  ctx.bWriter = await consoleSignIn.signInToTheConsole(ctx.bBase, BWRITER,
    log, { grant: "write" });
  ctx.clientA = await clientToken(ctx.aBase,
                                  "admin:read admin:write");
  await sectionA(ctx);
  await sectionB(ctx);
  await sectionC(ctx);
  await sectionD(ctx);
  await sectionE(ctx);
  await sectionF(ctx);
  assert.ok(checks >= 30, "only " + checks + " checks ran");
  log.info(checks + " checks passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
