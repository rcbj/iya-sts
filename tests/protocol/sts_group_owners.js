// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_group_owners.js
//
// ---------------------------------------------------------------------------
// A GROUP'S OWNERS, OVER THE WIRE (#603).
//
// D12 (#444): carries over tests/group_owners.js's A and B, which it held
// through `ldap.addGroupOwner()`, `ldap.removeGroupOwner()` and
// `adminActions.groupsAction()`, as answers of
// `POST /admin-api/groups/add-owner` and `/remove-owner`, the group's
// `GET /admin-api/groups?group=`, the list, the directory socket and the
// realm's audit log:
//
//   A1. a person and a group added as owners by any name they answer to,
//       each once (a second add of the same DN, in another case, changes
//       nothing);
//   A2. an owner naming nobody (STS-LDAP-0135), the group itself
//       (STS-LDAP-0136), no owner (STS-LDAP-0134) and no group
//       (STS-LDAP-0050) refused, writing nothing;
//   A3. a remove of a value not listed refused (STS-LDAP-0138); a remove
//       keeps the other owners and the members;
//   A4. the last owner may go;
//   A5. the group's answer carries `owners` and `maxOwners`, the list
//       `ownerCount`;
//   A6. an owner deleted (an LDAP delete) is taken off the group;
//   A7. one past the most owners a group may name is refused
//       (STS-LDAP-0137);
//   B1. the two acts answer the owners as they now stand, and the
//       unknown-action sentence names all six actions.
//
// Its C and D — the console's helpers (`WebAnswers.redraw()`) and the
// Owners tab's markup — run in the browser over these answers and stay in
// process (class (d)).
//
// In a throwaway development realm this job creates, removed at the end
// only when STS_TEST_REMOVE_REALMS=1 (removeRealms() says why). OWNED HERE
// (local: true).
// ---------------------------------------------------------------------------

const assert = require("assert");
const ldapjs = require("ldapjs");
const serviceTrust = require("../tools/service_trust.js");
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
var log = bunyan.createLogger({ name: "sts_group_owners",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "");
const REALM = ("grpown-" + STAMP).slice(0, 31);
const API = base + "/realm/" + REALM + "/admin-api";
const TAG = STAMP.slice(-6);
const MAX_OWNERS = 25;

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function hostOf(url) {
  log.debug("Entering hostOf().");
  log.debug("Leaving hostOf().");
  return new URL(url).hostname;
}

function ldapsUrl() {
  log.debug("Entering ldapsUrl().");
  log.debug("Leaving ldapsUrl().");
  return process.env.STS_LDAPS_URL ||
    ("ldaps://" + hostOf(base) + ":" + (process.env.STS_LDAPS_PORT || 636));
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

function post(path, payload) {
  log.debug("Entering post(). " + path);
  log.debug("Leaving post().");
  return send(API + path, { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}) });
}

async function ok(promise, what) {
  log.debug("Entering ok().");
  const r = await promise;
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    what + ": answered " + r.status + " " + String(r.raw).slice(0, 400));
  log.debug("Leaving ok().");
  return r.body;
}

function errorsOf(r) {
  log.debug("Entering errorsOf().");
  log.debug("Leaving errorsOf().");
  return ((r.body && r.body.errors) || []).join(" ");
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

// Runs `fn` and answers its result and whether the realm's audit log gained
// a row carrying `code`. A code is never sent.
async function recording(code, fn) {
  log.debug("Entering recording(). " + code);
  const before = await codeCount(code);
  const out = await fn();
  let after = before;
  for (let i = 0; i < 20 && after <= before; i += 1) {
    await sleep(100);
    after = await codeCount(code);
  }
  log.debug("Leaving recording(). " + before + " -> " + after);
  return { out: out, recorded: after > before };
}

async function group(dn) {
  log.debug("Entering group().");
  const r = await send(API + "/groups?group=" + encodeURIComponent(dn));
  assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
  log.debug("Leaving group().");
  return r.body.group;
}

async function personDn(name) {
  log.debug("Entering personDn(). " + name);
  const r = await send(API + "/users?user=" + encodeURIComponent(name));
  log.debug("Leaving personDn().");
  return r.body.ldap.entry.dn;
}

function makePerson(name) {
  log.debug("Entering makePerson(). " + name);
  log.debug("Leaving makePerson().");
  return ok(post("/users/create", { username: name, invent: false,
    attributes: { cn: name, sn: "Owner" } }), "created " + name);
}

// An LDAP delete of `dn` over LDAPS, anonymously: a development realm
// authorizes no directory write.
function ldapDelete(dn) {
  log.debug("Entering ldapDelete(). " + dn);
  return new Promise(function (resolve) {
    const client = ldapjs.createClient({ url: ldapsUrl(),
      // Verified against the service's chain (tools/service_trust.js):
      // LDAPS presents the shared listener certificate.
      tlsOptions: { ca: serviceTrust.trustedCa() } });
    client.on("error", function (e) {
      log.debug("Caught in ldapDelete(): " + ((e && e.message) || e));
      resolve({ ok: false, name: e && e.name });
    });
    client.del(dn, function (e) {
      client.unbind();
      log.debug("Leaving ldapDelete(). " + (e ? e.name : "ok"));
      resolve(e ? { ok: false, name: e.name } : { ok: true });
    });
  });
}

async function theDirectory() {
  log.debug("Entering theDirectory().");
  log.info("=== A. the directory ===");
  const ANN = "go-ann-" + TAG;
  const BO = "go-bo-" + TAG;
  await makePerson(ANN);
  await makePerson(BO);
  const made = await ok(post("/groups/create", { group: "go-team-" + TAG,
    members: [ANN] }), "made the team");
  const ops = await ok(post("/groups/create", { group: "go-ops-" + TAG }),
                       "made ops");
  const TEAM = made.dn;
  const OPS = ops.dn;
  const annDn = await personDn(ANN);
  const ann = await ok(post("/groups/add-owner", { group: "go-team-" + TAG,
                                                   owner: ANN }),
                       "added ann");
  const again = await ok(post("/groups/add-owner", { group: TEAM,
                                                     owner: annDn
                                                       .toUpperCase() }),
                         "added ann again by DN");
  const both = await ok(post("/groups/add-owner", { group: "go-team-" + TAG,
                                                    owner: "go-ops-" + TAG }),
                        "added ops");
  check("A1. a person and a group are added by any name they answer to, " +
        "each once", function () {
    assert.strictEqual(ann.changed, true);
    assert.strictEqual(again.changed, false);
    assert.strictEqual(both.owners.length, 2, JSON.stringify(both.owners));
    assert.strictEqual(both.owners[0].kind, "person");
    assert.strictEqual(both.owners[1].kind, "group");
    assert.strictEqual(both.owners[1].name, "go-ops-" + TAG);
  });
  const refusals = [
    ["STS-LDAP-0135", "an owner naming nobody",
     { group: "go-team-" + TAG, owner: "go-no-such-" + TAG }],
    ["STS-LDAP-0136", "the group itself", { group: "go-team-" + TAG,
                                            owner: TEAM }],
    ["STS-LDAP-0134", "no owner", { group: "go-team-" + TAG, owner: "" }],
    ["STS-LDAP-0050", "no group", { group: "go-nothing-" + TAG,
                                    owner: ANN }]];
  for (const one of refusals) {
    const r = await recording(one[0], function () {
      return post("/groups/add-owner", one[2]);
    });
    check("A2. " + one[1] + " is refused (" + one[0] + ")", function () {
      assert.ok(r.out.status === 400 && r.recorded, r.out.raw.slice(0, 300));
    });
  }
  const held = await group(TEAM);
  check("A2. and none of them wrote anything", function () {
    assert.strictEqual(held.owners.length, 2, JSON.stringify(held.owners));
  });
  const boDn = await personDn(BO);
  const stranger = await recording("STS-LDAP-0138", function () {
    return post("/groups/remove-owner", { group: "go-team-" + TAG,
                                          owner: boDn });
  });
  const off = await ok(post("/groups/remove-owner", { group: "go-team-" + TAG,
                                                      owner: annDn }),
                       "removed ann");
  const afterOff = await group(TEAM);
  check("A3. a remove of a value not listed is refused (STS-LDAP-0138); a " +
        "remove keeps the other owners and the members", function () {
    assert.ok(stranger.out.status === 400 && stranger.recorded,
              stranger.out.raw.slice(0, 300));
    assert.strictEqual(off.owners.length, 1);
    assert.strictEqual(off.owners[0].name, "go-ops-" + TAG);
    assert.strictEqual(afterOff.members.length, 1,
                       JSON.stringify(afterOff.members));
  });
  const last = await ok(post("/groups/remove-owner", { group: TEAM,
                                                       owner: OPS }),
                        "removed the last owner");
  check("A4. the last owner may go: a group needs none", function () {
    assert.strictEqual(last.owners.length, 0);
  });
  await ok(post("/groups/add-owner", { group: TEAM, owner: BO }),
           "added bo");
  const view = await group(TEAM);
  const list = await send(API + "/groups?q=" +
                          encodeURIComponent("go-team-" + TAG));
  const row = (list.body.groups || []).filter(function (one) {
    return one.dn === TEAM;
  })[0];
  check("A5. the group's answer carries owners and maxOwners, the list " +
        "ownerCount", function () {
    assert.ok(Array.isArray(view.owners));
    assert.strictEqual(view.maxOwners, MAX_OWNERS);
    assert.ok(row && row.ownerCount === 1, JSON.stringify(row));
  });
  const deleted = await ldapDelete(boDn);
  const afterDelete = await group(TEAM);
  check("A6. an owner deleted is taken off the group", function () {
    assert.ok(deleted.ok, JSON.stringify(deleted));
    assert.strictEqual(afterDelete.owners.length, 0,
                       JSON.stringify(afterDelete.owners));
  });
  for (let i = 0; i < MAX_OWNERS; i += 1) {
    const name = "go-p" + i + "-" + TAG;
    await makePerson(name);
    await ok(post("/groups/add-owner", { group: OPS, owner: name }),
             "added owner " + i);
  }
  await makePerson("go-one-more-" + TAG);
  const over = await recording("STS-LDAP-0137", function () {
    return post("/groups/add-owner", { group: OPS,
                                       owner: "go-one-more-" + TAG });
  });
  const full = await group(OPS);
  check("A7. one past the most owners a group may name is refused " +
        "(STS-LDAP-0137)", function () {
    assert.ok(over.out.status === 400 && over.recorded,
              over.out.raw.slice(0, 300));
    assert.strictEqual(full.owners.length, MAX_OWNERS);
  });
  log.debug("Leaving theDirectory().");
}

async function theActs() {
  log.debug("Entering theActs().");
  log.info("=== B. the acts ===");
  const ANN = "ga-ann-" + TAG;
  await makePerson(ANN);
  const made = await ok(post("/groups/create", { group: "ga-team-" + TAG }),
                        "made the group");
  const added = await ok(post("/groups/add-owner", { group: made.dn,
                                                     owner: ANN }), "added");
  const removed = await ok(post("/groups/remove-owner", { group: made.dn,
    owner: await personDn(ANN) }), "removed");
  const unknown = await post("/groups/no-such", {});
  check("B1. the two acts answer the owners as they now stand", function () {
    assert.strictEqual(added.owners.length, 1);
    assert.ok(/is now an owner of/.test(added.message), added.message);
    assert.strictEqual(removed.owners.length, 0);
  });
  check("B1. the unknown-action sentence names all six actions",
        function () {
    assert.strictEqual(unknown.status, 400, unknown.raw.slice(0, 300));
    assert.ok(/create, add-member, set-mail, set-policy, add-owner, /
      .test(errorsOf(unknown)) && /remove-owner/.test(errorsOf(unknown)),
      errorsOf(unknown));
  });
  log.debug("Leaving theActs().");
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. a throwaway realm " + REALM + " ===");
  const made = await send(base + "/admin-api/realms/create", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id: REALM, domain: REALM + ".example.net",
                           name: "Group owners " + STAMP }) });
  assert.strictEqual(made.status, 200, made.raw.slice(0, 300));
  await theDirectory();
  await theActs();
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
