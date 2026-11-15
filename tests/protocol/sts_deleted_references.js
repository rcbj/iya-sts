// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_deleted_references.js
//
// ---------------------------------------------------------------------------
// A DELETED CLIENT CONFERS NOTHING, AND A DELETED OWNER OWNS NOTHING, OVER
// THE WIRE.
//
// D12 (#444): carries over tests/deleted_references.js (#1612's review). In
// a throwaway development realm, every write through `/admin-api` or the
// directory's own socket and every read back off `/admin-api`:
//
//   A. an application conferring a role, forgotten (`applications/forget`),
//      is off the role's `conferredBy`; another client conferring it keeps
//      it; one made again under the identifier confers nothing; a
//      `roles.unconfer` row names it; an ldapdelete of the entry, the other
//      door, takes it off too;
//   B. a person owning a group, a role, an application and a service
//      account, deleted over LDAP, owns none of them; a co-owner is kept;
//      somebody made again at the same DN owns none; a remove-owner row of
//      each of the four kinds says so;
//   C. a group owning a group and a role, deleted over LDAP and made again
//      under its cn, owns neither;
//   D. a person renamed by an LDAP modifyDN owns the four under the new DN,
//      and nothing names the old one;
//   F. an application owning two roles (one held by a person, one by an
//      application), deleted through `applications/forget` and through an
//      ldapdelete, leaves neither; another application's role and its
//      member are untouched; one `roles.delete` row per role; registered
//      again it owns none, and a role made again under the old name starts
//      empty.
//
// NOT CARRIED: E (the four codes are in the table — tests/error_codes.js
// owns that); F's third door, `applications.deleteApplication()` called by
// the outbound SCIM client, has no HTTP door of its own (class (d)).
//
// Development mode, where every LDAP write is authorized (the root
// CLAUDE.md's index), is what lets the binder delete entries.
//
// OWNED HERE (local: true): this repository's own management API and
// directory.
// ---------------------------------------------------------------------------

const ldapjs = require("ldapjs");
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
var log = bunyan.createLogger({ name: "sts_deleted_references",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "")
  .slice(-10);
const REALM = "delref-" + STAMP;
const R = "/realm/" + REALM;
const RB = base + R;
const API = RB + "/admin-api";
const SUFFIX = (REALM + ".example.net").split(".").map(function (label) {
  return "dc=" + label;
}).join(",");
const USERS = "ou=users," + SUFFIX;
const GROUPS = "ou=groups," + SUFFIX;
const APPS = "ou=applications," + SUFFIX;
const LDAP_URL = "ldap://" + new URL(base).hostname + ":" +
                 (process.env.STS_LDAP_PORT || "389");
const BINDER = "dr-binder";

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

function form(o) {
  log.debug("Entering form().");
  log.debug("Leaving form().");
  return new URLSearchParams(o).toString();
}

function absolute(location) {
  log.debug("Entering absolute().");
  log.debug("Leaving absolute().");
  return /^https?:\/\//i.test(String(location || ""))
    ? String(location) : base + String(location || "");
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
    // Not JSON — a page or a JWT; the caller reads `raw`.
    body = null;
  }
  log.debug("Leaving send(). status=" + r.status);
  return { status: r.status, body: body, raw: raw, headers: r.headers,
           location: r.headers.get("location") || "" };
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

// A refusal: a 400 whose answer names no code.
async function refused(url, payload, what) {
  log.debug("Entering refused().");
  const r = await postJson(url, payload);
  assert.ok(r.status === 400 && r.body && r.body.ok === false,
    "POST " + url + " should have refused " + what + "; it answered " +
    r.status + " " + String(r.raw).slice(0, 400));
  assert.ok(!/STS-[A-Z]+-\d{4}/.test(r.raw), "no code is sent: " + r.raw);
  log.debug("Leaving refused().");
  return r.body;
}

async function codeCount(api, code) {
  log.debug("Entering codeCount(). " + code);
  const r = await send(api + "/audit?per=500&code=" +
                       encodeURIComponent(code));
  log.debug("Leaving codeCount().");
  return Number((r.body && r.body.matched) || 0);
}

async function codesSettle(api, code, atLeast) {
  log.debug("Entering codesSettle(). " + code);
  let n = await codeCount(api, code);
  for (let i = 0; i < 20 && n < atLeast; i += 1) {
    await sleep(150);
    n = await codeCount(api, code);
  }
  log.debug("Leaving codesSettle(). " + n);
  return n;
}

function key(dn) {
  log.debug("Entering key().");
  log.debug("Leaving key().");
  return String(dn || "").trim().toLowerCase().replace(/\s*,\s*/g, ",");
}

// Whether a list of owner DNs (strings or `{ dn }`) names `dn`.
function namesDn(list, dn) {
  log.debug("Entering namesDn().");
  const wanted = key(dn);
  log.debug("Leaving namesDn().");
  return (list || []).some(function (one) {
    return key(typeof one === "string" ? one : one && one.dn) === wanted;
  });
}

function ldapOp(kind, args) {
  log.debug("Entering ldapOp(). " + kind);
  log.debug("Leaving ldapOp().");
  return new Promise(function (resolve) {
    const client = ldapjs.createClient({ url: LDAP_URL });
    function done(error) {
      client.unbind();
      resolve(error ? { ok: false, code: error.code, message: error.message }
                    : { ok: true });
    }
    client.on("error", function (e) {
      log.debug("Caught in ldapOp(): " + ((e && e.message) || e));
      resolve({ ok: false, code: -1, message: String(e && e.message) });
    });
    client.bind("uid=" + BINDER + "," + USERS, "x-" + STAMP,
                function (bindError) {
      if (bindError) {
        done(bindError);
        return;
      }
      if (kind === "del") {
        client.del(args.dn, done);
      } else {
        client.modifyDN(args.dn, args.newDn, done);
      }
    });
  });
}

function person(username) {
  log.debug("Entering person(). " + username);
  log.debug("Leaving person().");
  return ok(API + "/users/create", { username: username, invent: false,
    attributes: { cn: username, givenName: "Dr", sn: username,
                  mail: username + "@delref.example.test" } },
    "created " + username);
}

function makeApplication(id) {
  log.debug("Entering makeApplication(). " + id);
  log.debug("Leaving makeApplication().");
  return ok(API + "/applications/create", { identifier: id, name: id,
    kind: "oauth2-client", protocols: ["oauth2"],
    fields: { oauthClientId: [id] } }, "registered " + id);
}

async function role(name) {
  log.debug("Entering role(). " + name);
  const r = await send(API + "/roles?role=" + encodeURIComponent(name));
  assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
  const found = (r.body && r.body.role) || null;
  log.debug("Leaving role().");
  return found && found.found !== false ? found : null;
}

async function groupOwners(cn) {
  log.debug("Entering groupOwners(). " + cn);
  const r = await send(API + "/groups?group=" +
                       encodeURIComponent("cn=" + cn + "," + GROUPS));
  assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
  log.debug("Leaving groupOwners().");
  return (r.body.group && r.body.group.owners) || [];
}

async function appOwners(id) {
  log.debug("Entering appOwners(). " + id);
  const r = await send(API + "/applications?application=" +
                       encodeURIComponent(id));
  assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
  log.debug("Leaving appOwners().");
  return (r.body.page && r.body.page.owners) || [];
}

async function accountOwners(who) {
  log.debug("Entering accountOwners(). " + who);
  const r = await send(API + "/users?user=" + encodeURIComponent(who));
  assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
  log.debug("Leaving accountOwners().");
  return (r.body.serviceAccount && r.body.serviceAccount.owners) || [];
}

async function ownersNow(things) {
  log.debug("Entering ownersNow().");
  const out = { group: await groupOwners(things.group),
                role: ((await role(things.role)) || {}).owners || [],
                app: await appOwners(things.app),
                account: await accountOwners(things.account) };
  log.debug("Leaving ownersNow().");
  return out;
}

// The audit rows of one action, by target, from the realm's log.
async function rowsOf(action) {
  log.debug("Entering rowsOf(). " + action);
  const r = await send(API + "/audit?per=500&action=" +
                       encodeURIComponent(action));
  log.debug("Leaving rowsOf().");
  return ((r.body && r.body.events) || []).map(function (one) {
    return String(one.target);
  });
}

// A group, a role, an application and a service account, each owned by
// `ownerDn` (and the group, the role and the account by `coDn` too).
async function ownedThings(label, ownerDn, coDn) {
  log.debug("Entering ownedThings(). " + label);
  const things = { group: "dr-" + label + "-group", role: "dr-" + label +
                   "-role", app: "dr-" + label + "-app",
                   account: "dr-" + label + "-sa" };
  await ok(API + "/groups/create", { group: things.group },
           "created " + things.group);
  await ok(API + "/roles/create-role", { role: things.role },
           "created " + things.role);
  await makeApplication(things.app);
  await person(things.account);
  const owners = [ownerDn].concat(coDn ? [coDn] : []);
  for (const dn of owners) {
    await ok(API + "/groups/add-owner", { group: things.group, owner: dn },
             "an owner of the group");
    await ok(API + "/roles/add-owner", { role: things.role, owner: dn },
             "an owner of the role");
  }
  await ok(API + "/applications/add-owner", { application: things.app,
    owner: ownerDn }, "an owner of the application");
  await ok(API + "/users/set-service-account", { user: things.account,
    owners: owners }, "made " + things.account + " a service account");
  const now = await ownersNow(things);
  assert.ok(namesDn(now.group, ownerDn) && namesDn(now.role, ownerDn) &&
            namesDn(now.app, ownerDn) && namesDn(now.account, ownerDn),
            "precondition (" + label + "): " + JSON.stringify(now));
  log.debug("Leaving ownedThings().");
  return things;
}

async function conferral() {
  log.debug("Entering conferral().");
  log.info("=== A. a deleted client confers nothing ===");
  await makeApplication("dr-confers");
  await makeApplication("dr-confers-too");
  await ok(API + "/roles/create-role", { role: "dr-conferred" },
           "created the conferred role");
  for (const client of ["dr-confers", "dr-confers-too"]) {
    await ok(API + "/roles/add-conferring-client", { role: "dr-conferred",
      client: client }, client + " confers it");
  }
  await ok(API + "/applications/forget", { application: "dr-confers" },
           "forgot dr-confers");
  let row = await role("dr-conferred");
  check("A1. the forgotten application is off the role's conferring clients",
        function () {
    assert.ok((row.conferredBy || []).indexOf("dr-confers") < 0,
              JSON.stringify(row.conferredBy));
  });
  check("A2. the other client conferring the role keeps it", function () {
    assert.ok((row.conferredBy || []).indexOf("dr-confers-too") >= 0,
              JSON.stringify(row.conferredBy));
  });
  await makeApplication("dr-confers");
  row = await role("dr-conferred");
  check("A3. an application made again under its identifier confers " +
        "nothing", function () {
    assert.ok((row.conferredBy || []).indexOf("dr-confers") < 0,
              JSON.stringify(row.conferredBy));
  });
  const unconfer = (await rowsOf("roles.unconfer")).filter(function (t) {
    return t === "dr-confers";
  });
  check("A4. one roles.unconfer row names the deleted application",
        function () {
    assert.strictEqual(unconfer.length, 1, JSON.stringify(unconfer));
  });
  await ok(API + "/roles/add-conferring-client", { role: "dr-conferred",
    client: "dr-confers" }, "dr-confers confers it again");
  const del = await ldapOp("del", { dn: "cn=dr-confers," + APPS });
  row = await role("dr-conferred");
  check("A5. an ldapdelete of the entry takes it off as well", function () {
    assert.ok(del.ok, JSON.stringify(del));
    assert.ok((row.conferredBy || []).indexOf("dr-confers") < 0,
              JSON.stringify(row.conferredBy));
  });
  log.debug("Leaving conferral().");
}

async function aPerson() {
  log.debug("Entering aPerson().");
  log.info("=== B. a deleted person owns nothing ===");
  await person("dr-owner");
  await person("dr-co-owner");
  const ownerDn = "uid=dr-owner," + USERS;
  const coDn = "uid=dr-co-owner," + USERS;
  const things = await ownedThings("person", ownerDn, coDn);
  const counts = {};
  const ACTIONS = ["roles.remove-owner", "group.remove-owner",
                   "application.remove-owner",
                   "admin.service-account.owner-removed"];
  for (const one of ACTIONS) {
    counts[one] = (await rowsOf(one)).length;
  }
  const gone = await ldapOp("del", { dn: ownerDn });
  const after = await ownersNow(things);
  check("B1. the deleted person is off the owners of the group, the role, " +
        "the application and the service account", function () {
    assert.ok(gone.ok, JSON.stringify(gone));
    assert.ok(!namesDn(after.group, ownerDn) && !namesDn(after.role, ownerDn) &&
              !namesDn(after.app, ownerDn) && !namesDn(after.account, ownerDn),
              JSON.stringify(after));
  });
  check("B2. the co-owner is kept on each", function () {
    assert.ok(namesDn(after.group, coDn) && namesDn(after.role, coDn) &&
              namesDn(after.account, coDn), JSON.stringify(after));
  });
  await person("dr-owner");
  const now = await ownersNow(things);
  check("B3. somebody made again at the same DN owns none of them",
        function () {
    assert.ok(!namesDn(now.group, ownerDn) && !namesDn(now.role, ownerDn) &&
              !namesDn(now.app, ownerDn) && !namesDn(now.account, ownerDn),
              JSON.stringify(now));
  });
  const grown = {};
  for (const one of ACTIONS) {
    grown[one] = (await rowsOf(one)).length - counts[one];
  }
  check("B4. each removal is audited under its remove-owner action",
        function () {
    assert.ok(ACTIONS.every(function (one) {
      return grown[one] >= 1;
    }), JSON.stringify(grown));
  });
  log.debug("Leaving aPerson().");
}

async function aGroup() {
  log.debug("Entering aGroup().");
  log.info("=== C. a deleted group owns nothing ===");
  await ok(API + "/groups/create", { group: "dr-owner-group" },
           "created the owning group");
  await ok(API + "/groups/create", { group: "dr-owned-group" },
           "created the owned group");
  await ok(API + "/roles/create-role", { role: "dr-owned-role" },
           "created the owned role");
  const groupDn = "cn=dr-owner-group," + GROUPS;
  await ok(API + "/groups/add-owner", { group: "dr-owned-group",
    owner: groupDn }, "the group owns a group");
  await ok(API + "/roles/add-owner", { role: "dr-owned-role",
    owner: groupDn }, "the group owns a role");
  const gone = await ldapOp("del", { dn: groupDn });
  await ok(API + "/groups/create", { group: "dr-owner-group" },
           "made the group again");
  const groups = await groupOwners("dr-owned-group");
  const roles = ((await role("dr-owned-role")) || {}).owners || [];
  check("C1. the deleted group, made again under its cn, owns neither",
        function () {
    assert.ok(gone.ok, JSON.stringify(gone));
    assert.ok(!namesDn(groups, groupDn) && !namesDn(roles, groupDn),
              JSON.stringify([groups, roles]));
  });
  log.debug("Leaving aGroup().");
}

async function aRename() {
  log.debug("Entering aRename().");
  log.info("=== D. a rename carries ownership ===");
  await person("dr-before");
  const oldDn = "uid=dr-before," + USERS;
  const newDn = "uid=dr-after," + USERS;
  const things = await ownedThings("renamed", oldDn, "");
  const renamed = await ldapOp("modifyDN", { dn: oldDn, newDn: newDn });
  const now = await ownersNow(things);
  check("D1. the renamed person owns all four under the new DN",
        function () {
    assert.ok(renamed.ok, JSON.stringify(renamed));
    assert.ok(namesDn(now.group, newDn) && namesDn(now.role, newDn) &&
              namesDn(now.app, newDn) && namesDn(now.account, newDn),
              JSON.stringify(now));
  });
  check("D2. and nothing names the old DN", function () {
    assert.ok(!namesDn(now.group, oldDn) && !namesDn(now.role, oldDn) &&
              !namesDn(now.app, oldDn) && !namesDn(now.account, oldDn),
              JSON.stringify(now));
  });
  log.debug("Leaving aRename().");
}

async function ownedRolesByDoor(door, remove) {
  log.debug("Entering ownedRolesByDoor(). " + door);
  const app = "dr-roles-" + door;
  const other = "dr-roles-other-" + door;
  const holder = "dr-holder-" + door;
  await makeApplication(app);
  await makeApplication(other);
  await person(holder);
  for (const one of [["reader", app], ["writer", app], ["reader", other]]) {
    await ok(API + "/roles/create-role", { role: one[0],
      application: one[1] }, "created " + one[0] + "@" + one[1]);
  }
  const reader = "reader@" + app;
  const writer = "writer@" + app;
  const kept = "reader@" + other;
  await ok(API + "/roles/add-member", { role: reader, kind: "user",
    member: holder }, "a person holds " + reader);
  await ok(API + "/roles/add-member", { role: writer, kind: "application",
    member: other }, "an application holds " + writer);
  await ok(API + "/roles/add-member", { role: kept, kind: "user",
    member: holder }, "a person holds " + kept);
  const before = (await rowsOf("roles.delete")).length;
  const gone = await remove(app);
  check("F1 (" + door + "). the application is deleted", function () {
    assert.ok(gone, "the door answered " + gone);
  });
  const readerNow = await role(reader);
  const writerNow = await role(writer);
  check("F2 (" + door + "). neither of its roles is left", function () {
    assert.ok(!readerNow && !writerNow,
              JSON.stringify([readerNow, writerNow]).slice(0, 300));
  });
  const keptRow = (await role(kept)) || {};
  check("F3 (" + door + "). another application's role is untouched, its " +
        "member kept", function () {
    assert.strictEqual(keptRow.application, other, JSON.stringify(keptRow)
      .slice(0, 300));
    assert.ok((keptRow.users || []).indexOf(holder) >= 0,
              JSON.stringify(keptRow.users));
  });
  const deleted = (await rowsOf("roles.delete")).slice(0);
  check("F4 (" + door + "). one roles.delete row per role, and none for the " +
        "other application's", function () {
    assert.strictEqual(deleted.length - before, 2, JSON.stringify(deleted));
    assert.ok(deleted.indexOf(reader) >= 0 && deleted.indexOf(writer) >= 0);
    assert.ok(deleted.indexOf(kept) < 0);
  });
  await makeApplication(app);
  const again = await role(reader);
  check("F5 (" + door + "). registered again under the same identifier, it " +
        "owns no role", function () {
    assert.ok(!again, JSON.stringify(again).slice(0, 300));
  });
  await ok(API + "/roles/create-role", { role: "reader", application: app },
           "made reader@" + app + " again");
  const fresh = (await role(reader)) || {};
  check("F6 (" + door + "). a role made again under the old name starts " +
        "empty", function () {
    assert.strictEqual((fresh.users || []).length, 0, JSON.stringify(fresh)
      .slice(0, 300));
    assert.strictEqual((fresh.applications || []).length, 0);
  });
  log.debug("Leaving ownedRolesByDoor().");
}

async function ownedRoles() {
  log.debug("Entering ownedRoles().");
  log.info("=== F. a deleted application's own roles go with it ===");
  await ownedRolesByDoor("console", async function (id) {
    log.debug("Entering the console door.");
    const r = await postJson(API + "/applications/forget",
                             { application: id });
    log.debug("Leaving the console door.");
    return r.status === 200 && r.body && r.body.ok !== false;
  });
  await ownedRolesByDoor("ldap", async function (id) {
    log.debug("Entering the LDAP door.");
    const r = await ldapOp("del", { dn: "cn=" + id + "," + APPS });
    log.debug("Leaving the LDAP door.");
    return r.ok;
  });
  log.debug("Leaving ownedRoles().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving deleted references at " + RB);
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "Deleted references " + STAMP },
    "created the realm");
  await person(BINDER);
  await conferral();
  await aPerson();
  await aGroup();
  await aRename();
  await ownedRoles();
  assert.ok(checks >= 24, "only " + checks + " checks ran; a section has " +
                          "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

// REMOVAL IS OPT-IN: with STS_TEST_REMOVE_REALMS=1 (a private probe that
// would otherwise fill its directory) every realm this run made — each id
// carries the run's STAMP — is removed at the end, pass or fail. A suite run
// leaves them standing (tests/CLAUDE.md, *No job removes a realm*).
async function removeRealms() {
  log.debug("Entering removeRealms().");
  if (process.env.STS_TEST_REMOVE_REALMS !== "1") {
    log.debug("Leaving removeRealms(). Not asked to.");
    return;
  }
  for (const id of [REALM]) {
    const r = await postJson(base + "/admin-api/realms/remove", { id: id });
    log.info("removed the realm " + id + " (" + r.status + ")");
  }
  log.debug("Leaving removeRealms().");
}

async function main() {
  log.debug("Entering main().");
  let failure = null;
  try {
    await test();
  } catch (e) {
    log.debug("Caught in main(): " + ((e && e.message) || e));
    // Reported below, after the realms are removed.
    failure = e;
  }
  try {
    await removeRealms();
  } catch (e) {
    log.debug("Caught in main() removing realms: " + ((e && e.message) || e));
    log.warn("could not remove the realms: " + e.message);
  }
  if (failure) {
    log.error(failure.stack || failure.message);
    log.debug("Leaving main(). Failed.");
    process.exit(1);
  }
  log.debug("Leaving main().");
}

main();
