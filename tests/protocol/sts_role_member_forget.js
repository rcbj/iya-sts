// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_role_member_forget.js
//
// ---------------------------------------------------------------------------
// A DELETED MEMBER HOLDS NOTHING, AND NEITHER DOES ITS NAMESAKE, OVER THE
// WIRE (D12, #444: carries over tests/role_member_forget.js).
//
// In one throwaway realm it leaves behind, through `/admin-api` and the
// directory's own LDAP socket:
//
//   A. an application forgotten through `POST /admin-api/applications/forget`
//      leaves its configured role and ADMIN_READ; one made again under its
//      identifier holds neither; another application on the role keeps it;
//   B. an application entry removed by an `ldapdelete`, the other door to
//      the same entry, does the same;
//   C. a person deleted over LDAP leaves the role, and somebody made again
//      under the username does not hold it;
//   D. a group deleted over LDAP leaves the role;
//   F. a deleted person leaves every group that listed them and somebody
//      made again under the username is in none; a deleted group leaves the
//      group it was nested in; a forgotten application leaves a group that
//      listed its entry;
//   G. over LDAP a group lists only what is there: an add of a group naming
//      a member nobody stored, and a modify adding one, are refused with
//      constraintViolation (19) and change nothing;
//   H. a person renamed by modifyDN is listed by the new DN in their group
//      and by the new username in their role, and nothing names the old.
//
// NOT CARRIED: E (STS-ADMIN-0919 is in the code table) is a fact about the
// table, which `tests/error_codes.js` owns; no request can make the forget
// itself fail.
//
// Development mode, where every LDAP write is authorized (the root
// CLAUDE.md's index), is what lets the binder below delete entries.
//
// ITS REALMS ARE REMOVED AT THE END ONLY WHEN ASKED
// (`STS_TEST_REMOVE_REALMS=1`, which a hand run against a long-lived probe
// sets so that its directory does not fill): tests/CLAUDE.md's *No job
// removes a realm* is the rule for a shared run, so by default they stay.
//
// OWNED HERE (local: true): this repository's own management API and
// directory.
// ---------------------------------------------------------------------------

const assert = require("assert");
const ldapjs = require("ldapjs");
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
var log = bunyan.createLogger({ name: "sts_role_member_forget",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("rmf-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
  .slice(0, 31);
const DOMAIN = REALM + ".example.net";
const api = base + "/realm/" + REALM + "/admin-api";
const SUFFIX = DOMAIN.split(".").map(function (label) {
  return "dc=" + label;
}).join(",");
const USERS = "ou=users," + SUFFIX;
const GROUPS = "ou=groups," + SUFFIX;
const APPS = "ou=applications," + SUFFIX;
const LDAP_URL = "ldap://" + new URL(base).hostname + ":" +
                 (process.env.STS_LDAP_PORT || "389");
const ROLE = "rmf-role";

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

async function ok(path, payload, what) {
  log.debug("Entering ok().");
  const r = await send(api + path, { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}) });
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST " + path + " should have " + what + "; it answered " + r.status +
    " " + String(r.raw).slice(0, 400));
  log.debug("Leaving ok().");
  return r.body;
}

function person(username) {
  log.debug("Entering person().");
  log.debug("Leaving person().");
  return { username: username, invent: false, credential: "none",
           attributes: { cn: username, sn: "Member", givenName: "Person",
                         mail: username + "@" + DOMAIN } };
}

function app(identifier) {
  log.debug("Entering app().");
  log.debug("Leaving app().");
  return { identifier: identifier, protocols: ["oauth2"],
           fields: { oauthClientId: [identifier] } };
}

// A role's members by kind, as GET /admin-api/roles?role= answers them.
async function members(role) {
  log.debug("Entering members().");
  const r = await send(api + "/roles?role=" + encodeURIComponent(role));
  assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
  const row = r.body.role || {};
  log.debug("Leaving members().");
  return { users: row.users || [], groups: row.groups || [],
           applications: row.applications || [] };
}

// The `member` values of a group, lower-cased.
async function listedBy(group) {
  log.debug("Entering listedBy().");
  const r = await send(api + "/groups?group=" +
                       encodeURIComponent("cn=" + group + "," + GROUPS));
  assert.ok(r.status === 200 && r.body.found, r.raw.slice(0, 300));
  log.debug("Leaving listedBy().");
  return ((r.body.group.attributes || {}).member || []).map(function (dn) {
    return String(dn).toLowerCase();
  });
}

// One LDAP operation, bound as a person of the realm, answering
// { ok, code, message } rather than throwing.
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
    client.bind("uid=rmf-binder," + USERS, "x-" + STAMP,
                function (bindError) {
      if (bindError) {
        done(bindError);
        return;
      }
      if (kind === "del") {
        client.del(args.dn, done);
      } else if (kind === "add") {
        client.add(args.dn, args.entry, done);
      } else if (kind === "modify") {
        client.modify(args.dn, new ldapjs.Change({ operation: "add",
          modification: new ldapjs.Attribute({ type: args.type,
                                               values: [args.value] }) }),
        done);
      } else {
        client.modifyDN(args.dn, args.newDn, done);
      }
    });
  });
}

async function applications() {
  log.debug("Entering applications().");
  log.info("=== A. an application forgotten through the API ===");
  await ok("/roles/create-role", { role: ROLE }, "created the role");
  for (const id of ["rmf-app", "rmf-other", "rmf-direct"]) {
    await ok("/applications/create", app(id), "created " + id);
    await ok("/roles/add-member", { role: ROLE, kind: "application",
                                    member: id }, id + " holds the role");
  }
  await ok("/roles/add-member", { role: "ADMIN_READ", kind: "application",
                                  member: "rmf-app" },
           "rmf-app holds ADMIN_READ");
  const before = await members(ROLE);
  const consoleBefore = await members("ADMIN_READ");
  check("three applications hold the role and the first ADMIN_READ too",
        function () {
    assert.deepStrictEqual(before.applications.slice().sort(),
                           ["rmf-app", "rmf-direct", "rmf-other"]);
    assert.ok(consoleBefore.applications.indexOf("rmf-app") >= 0,
              JSON.stringify(consoleBefore));
  });
  await ok("/applications/forget", { application: "rmf-app" },
           "forgot rmf-app");
  const forgot = await members(ROLE);
  const consoleForgot = await members("ADMIN_READ");
  check("it is out of its configured role and out of ADMIN_READ, and the " +
        "other application keeps the role", function () {
    assert.ok(forgot.applications.indexOf("rmf-app") < 0);
    assert.ok(consoleForgot.applications.indexOf("rmf-app") < 0);
    assert.ok(forgot.applications.indexOf("rmf-other") >= 0);
  });
  await ok("/applications/create", app("rmf-app"),
           "made rmf-app again");
  const remade = await members(ROLE);
  const consoleRemade = await members("ADMIN_READ");
  check("one made again under the identifier holds neither", function () {
    assert.ok(remade.applications.indexOf("rmf-app") < 0);
    assert.ok(consoleRemade.applications.indexOf("rmf-app") < 0);
  });

  log.info("=== B. an application entry removed over LDAP ===");
  const del = await ldapOp("del", { dn: "cn=rmf-direct," + APPS });
  const direct = await members(ROLE);
  check("an ldapdelete of the entry leaves the role too", function () {
    assert.ok(del.ok, JSON.stringify(del));
    assert.ok(direct.applications.indexOf("rmf-direct") < 0,
              JSON.stringify(direct));
  });
  log.debug("Leaving applications().");
}

async function peopleAndGroups() {
  log.debug("Entering peopleAndGroups().");
  log.info("=== C, D. a person and a group deleted over LDAP ===");
  await ok("/users/create", person("rmf-alice"), "created Alice");
  await ok("/groups/create", { group: "rmf-team" }, "created a group");
  await ok("/roles/add-member", { role: ROLE, kind: "user",
                                  member: "rmf-alice" }, "Alice holds it");
  await ok("/roles/add-member", { role: ROLE, kind: "group",
                                  member: "rmf-team" }, "the group holds it");
  const goneAlice = await ldapOp("del", { dn: "uid=rmf-alice," + USERS });
  const noAlice = await members(ROLE);
  check("a person deleted leaves the role", function () {
    assert.ok(goneAlice.ok, JSON.stringify(goneAlice));
    assert.ok(noAlice.users.indexOf("rmf-alice") < 0,
              JSON.stringify(noAlice));
  });
  await ok("/users/create", person("rmf-alice"), "made Alice again");
  const againAlice = await members(ROLE);
  check("somebody made again under the username does not hold it",
        function () {
    assert.ok(againAlice.users.indexOf("rmf-alice") < 0);
  });
  const goneTeam = await ldapOp("del", { dn: "cn=rmf-team," + GROUPS });
  const noTeam = await members(ROLE);
  check("a group deleted leaves the role", function () {
    assert.ok(goneTeam.ok, JSON.stringify(goneTeam));
    assert.ok(noTeam.groups.indexOf("rmf-team") < 0, JSON.stringify(noTeam));
  });

  log.info("=== F. groups too ===");
  await ok("/users/create", person("rmf-bob"), "created Bob");
  await ok("/groups/create", { group: "rmf-outer" }, "the outer group");
  await ok("/groups/create", { group: "rmf-inner" }, "the inner group");
  await ok("/groups/create", { group: "rmf-second" }, "a second group");
  await ok("/applications/create", app("rmf-listed"), "an application");
  const bobDn = ("uid=rmf-bob," + USERS).toLowerCase();
  const innerDn = ("cn=rmf-inner," + GROUPS).toLowerCase();
  const appDn = ("cn=rmf-listed," + APPS).toLowerCase();
  for (const member of [bobDn, innerDn, appDn]) {
    await ok("/groups/add-member", { group: "rmf-outer", member: member },
             "listed " + member);
  }
  await ok("/groups/add-member", { group: "rmf-second", member: bobDn },
           "listed Bob in the second group");
  const listed = await listedBy("rmf-outer");
  check("the outer group lists a person, a group and an application",
        function () {
    assert.deepStrictEqual(listed.slice().sort(),
                           [appDn, bobDn, innerDn].sort());
  });
  await ldapOp("del", { dn: "uid=rmf-bob," + USERS });
  const afterBob = { outer: await listedBy("rmf-outer"),
                     second: await listedBy("rmf-second") };
  check("a deleted person leaves every group that listed them", function () {
    assert.ok(afterBob.outer.indexOf(bobDn) < 0, afterBob.outer.join());
    assert.ok(afterBob.second.indexOf(bobDn) < 0, afterBob.second.join());
  });
  await ok("/users/create", person("rmf-bob"), "made Bob again");
  const afterRemade = { outer: await listedBy("rmf-outer"),
                        second: await listedBy("rmf-second") };
  check("and somebody made again under the username is in none of them",
        function () {
    assert.ok(afterRemade.outer.indexOf(bobDn) < 0);
    assert.ok(afterRemade.second.indexOf(bobDn) < 0);
  });
  await ldapOp("del", { dn: "cn=rmf-inner," + GROUPS });
  const afterInner = await listedBy("rmf-outer");
  check("a deleted group leaves the group it was nested in", function () {
    assert.deepStrictEqual(afterInner, [appDn]);
  });
  await ok("/applications/forget", { application: "rmf-listed" },
           "forgot the application");
  const afterApp = await listedBy("rmf-outer");
  check("a forgotten application leaves a group that listed its entry",
        function () {
    assert.deepStrictEqual(afterApp, []);
  });
  log.debug("Leaving peopleAndGroups().");
}

async function ldapIntegrity() {
  log.debug("Entering ldapIntegrity().");
  log.info("=== G. a group lists only what is there ===");
  const ghost = "uid=rmf-ghost," + USERS;
  const added = await ldapOp("add", { dn: "cn=rmf-ghosts," + GROUPS,
    entry: { objectClass: ["top", "groupOfNames"], cn: "rmf-ghosts",
             member: [ghost] } });
  const lookup = await send(api + "/groups?group=" +
                            encodeURIComponent("cn=rmf-ghosts," + GROUPS));
  check("an add of a group naming a member nobody stored is refused with " +
        "constraintViolation (19), and nothing is stored", function () {
    assert.strictEqual(added.ok, false, JSON.stringify(added));
    assert.strictEqual(added.code, 19, JSON.stringify(added));
    assert.ok(!(lookup.body && lookup.body.found), lookup.raw.slice(0, 200));
  });
  await ok("/groups/create", { group: "rmf-real" }, "a real group");
  const modified = await ldapOp("modify", { dn: "cn=rmf-real," + GROUPS,
    type: "member", value: ghost });
  const real = await listedBy("rmf-real");
  check("a modify adding one is refused the same way and changes nothing",
        function () {
    assert.strictEqual(modified.ok, false, JSON.stringify(modified));
    assert.strictEqual(modified.code, 19, JSON.stringify(modified));
    assert.deepStrictEqual(real, []);
  });

  log.info("=== H. a rename carries the memberships ===");
  await ok("/users/create", person("rmf-carol"), "created Carol");
  await ok("/groups/add-member", { group: "rmf-real",
    member: "uid=rmf-carol," + USERS }, "listed Carol");
  await ok("/roles/add-member", { role: ROLE, kind: "user",
                                  member: "rmf-carol" }, "Carol holds it");
  const renamed = await ldapOp("modifyDN", { dn: "uid=rmf-carol," + USERS,
    newDn: "uid=rmf-caroline," + USERS });
  const group = await listedBy("rmf-real");
  const role = await members(ROLE);
  check("the renamed person is listed by the new DN and the new username, " +
        "and nothing names the old", function () {
    assert.ok(renamed.ok, JSON.stringify(renamed));
    assert.deepStrictEqual(group,
                           [("uid=rmf-caroline," + USERS).toLowerCase()]);
    assert.ok(role.users.indexOf("rmf-caroline") >= 0, role.users.join());
    assert.ok(role.users.indexOf("rmf-carol") < 0, role.users.join());
  });
  log.debug("Leaving ldapIntegrity().");
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. the throwaway realm " + REALM + " ===");
  const made = await send(base + "/admin-api/realms/create", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id: REALM, domain: DOMAIN,
                           name: "Role member forget " + STAMP }) });
  assert.strictEqual(made.status, 200, made.raw.slice(0, 300));
  await ok("/users/create", person("rmf-binder"), "a binder");
  await applications();
  await peopleAndGroups();
  await ldapIntegrity();
  log.info("Test completed successfully. " + checks + " check(s) passed.");
  log.debug("Leaving test().");
}

// The realms this job made, removed from the default realm only when
// STS_TEST_REMOVE_REALMS is "1" (the header says why).
async function removeRealms() {
  log.debug("Entering removeRealms().");
  if (process.env.STS_TEST_REMOVE_REALMS !== "1") {
    log.debug("Leaving removeRealms(). Kept.");
    return;
  }
  for (const id of [REALM]) {
    try {
      const r = await fetch(base + "/admin-api/realms/remove", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: id }) });
      log.info("removed the realm " + id + ": " + r.status);
    } catch (e) {
      log.debug("Caught in removeRealms(): " + ((e && e.message) || e));
      // A removal that fails leaves a realm behind, which is what a run
      // without the switch does anyway; the job's verdict stands.
      log.info("could not remove the realm " + id);
    }
  }
  log.debug("Leaving removeRealms().");
}

test().then(function () {
  return true;
}, function (e) {
  log.error("sts_role_member_forget FAILED: " + ((e && e.stack) || e));
  return false;
}).then(async function (passed) {
  await removeRealms();
  if (!passed) {
    process.exit(1);
  }
});
