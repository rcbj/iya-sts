// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_directory_writes.js
//
// ---------------------------------------------------------------------------
// WHAT THE DIRECTORY'S WRITE DOORS REFUSE, WHAT A BULK OF DELETES DOES, AND
// WHAT A PRODUCT DIRECTORY IS SEEDED WITH, OVER THE WIRE (D12, #444).
//
// Each section is a file of `tests/` that held its claims only in process,
// asked here of a running service through `/admin-api`, `/scim/v2`, LDAP and
// LDAPS, with every refusal's code read back off the realm's audit log (a
// code is never sent):
//
//   A. GROUPS (tests/directory_group_writes.js): what a group may be called
//      (the same name twice, a seeded name, a DN, an RFC 4514 character and
//      an empty name refused); an empty group created as a groupOfNames; a
//      NUL in its note refused (STS-LDAP-0008) and nothing stored; a member
//      added by name written as their own entry DN, by the group's DN too;
//      a member naming nothing refused (STS-LDAP-0212), at the add and at
//      the create; SCIM's door refusing a dangling member as well; the add
//      idempotent (`changed: false`, one value); no group made as a side
//      effect, no member added to a person, an empty name refused; the
//      person never given memberOf; and the group's own mail — set at the
//      create, refused when not an address (STS-LDAP-0177), set, replaced
//      and cleared by cn or DN, idempotent, and refused for a group that is
//      not there (STS-LDAP-0050).
//   B. A SCIM BULK OF DELETES (tests/directory_bulk_delete.js): every
//      operation's own status in order (a missing id 404, a person the same
//      Bulk already deleted 404); the holder of a sign-on session signed
//      out; a person holding nothing deleted with no selective sign-out at
//      all, so no STS-LOGOUT-0007; a DELETE then a POST of the same name
//      making a NEW person whom a later `bulkId:` reference resolves to;
//      more than one chunk (520 deletes) each answered; the deleted name
//      answering nobody and a re-made one its new id; and a person with an
//      entry beneath them refused (not a leaf) until it is gone.
//   C. A PRODUCT DIRECTORY (tests/ldap_tls_product_mode.js): a realm created
//      in product is seeded with no demonstration people, groups, bind
//      account or privileged XACML identity, the role groups empty, the
//      containers there and a base entry that does not describe development
//      mode; a person created with `invent` defaulted is given no invented
//      attribute; the credential-attribute sweep does not run, saying why;
//      a verified bind's audit row says the password was verified. In
//      development the persona is still invented and a bind still audited
//      as unchecked. POST /tls/trust and /tls/trust/clear are unrouted in
//      both modes, and a TLS 1.2 client is refused on LDAPS by default
//      where TLS 1.3 is served.
//   D. A DN THE STORE CANNOT HOLD (tests/directory_long_dn.js): on MariaDB a
//      username whose DN key crosses 352 characters is refused at the door
//      (STS-LDAP-0204, saying to choose a shorter one) with nothing written,
//      and so is an LDAP add of such a DN; on every other store the same
//      name is accepted.
//
// What stays in process (class d): the batch being handed to the account
// observers once and at the chunk boundary, the event loop turning inside a
// Bulk, and the UUID index's misses (directory_bulk_delete.js B2, B3, D2,
// D3, E1); the role groups following renamed settings and the listeners'
// bind address (ldap_tls_product_mode.js 2 and 4, restart-only, process
// settings); the source-reading halves of directory_long_dn.js (C).
//
// OWNED HERE (local: true): this repository's own directory, through its own
// management API, SCIM and sockets. Every write is in a throwaway realm it
// creates, left behind unless STS_TEST_REMOVE_REALMS=1 asks for removal.
// ---------------------------------------------------------------------------
const assert = require("assert");
const crypto = require("crypto");
const tls = require("tls");
const { Command, Option } = require("commander");
const ldapjs = require("ldapjs");
const names = require("./random_username.js");
const facts = require("./service_facts.js");
const serviceTrust = require("../tools/service_trust.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // No appconfig file: the log level falls back to info, and the reason is
  // reported once the logger exists.
  appconfigProblem = e.message;
  appconfig = {};
}
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_directory_writes",
  level: appconfig.logLevel || appconfig.LOG_LEVEL ||
         process.env.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("No appconfig file was read: " + appconfigProblem);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");

const STAMP = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "")
  .slice(-12);
const PASSWORD = "Dw-" + crypto.randomBytes(9).toString("base64url") +
                 "-Correct.Horse-42";
// REMOVAL IS OPT-IN (STS_TEST_REMOVE_REALMS=1). tests/CLAUDE.md's *No job
// removes a realm* is the rule for a shared run, where what a job leaves is
// there to be read afterwards; a hand run against a private service sets the
// variable, and the realms this job made are removed at its end, pass or
// fail, so a long series of runs does not fill the directory's ceiling.
const MADE_REALMS = [];

async function removeRealms() {
  log.debug("Entering removeRealms().");
  if (process.env.STS_TEST_REMOVE_REALMS !== "1") {
    log.debug("Leaving removeRealms(). Not asked to.");
    return;
  }
  for (const id of MADE_REALMS) {
    try {
      const r = await fetch(base + "/admin-api/realms/remove", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: id }) });
      log.info("  (removed the realm " + id + ": " + r.status + ")");
    } catch (e) {
      log.debug("Caught in removeRealms(): " + ((e && e.message) || e));
      // A realm that cannot be removed is left, as a shared run leaves it.
    }
  }
  log.debug("Leaving removeRealms().");
}
const FLOOR = 70;

let checks = 0;
function check(what, fn) {
  log.debug("Entering check(). " + what);
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

function hostOf(url) {
  log.debug("Entering hostOf().");
  log.debug("Leaving hostOf().");
  return new URL(url).hostname;
}

function realmBase(id) {
  log.debug("Entering realmBase().");
  log.debug("Leaving realmBase().");
  return base + "/realm/" + id;
}

async function call(method, url, body, headers) {
  log.debug("Entering call(). " + method + " " + url);
  const r = await fetch(url, { method: method, redirect: "manual",
    headers: Object.assign({ "Content-Type": "application/json" },
                           headers || {}),
    body: body === undefined ? undefined
                             : (typeof body === "string" ? body
                                                         : JSON.stringify(body))
  });
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
    // Not JSON; `text` carries it into the message.
    json = null;
  }
  log.debug("Leaving call(). " + r.status);
  return { status: r.status, json: json, text: text };
}

async function ok(url, body, what) {
  log.debug("Entering ok().");
  const r = await call("POST", url, body);
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
            what + ": " + r.status + " " + r.text.slice(0, 400));
  log.debug("Leaving ok().");
  return r.json;
}

async function codeCount(realm, code) {
  log.debug("Entering codeCount(). " + code);
  const r = await call("GET", realmBase(realm) +
                       "/admin-api/audit?per=500&code=" +
                       encodeURIComponent(code));
  assert.strictEqual(r.status, 200, "GET audit answered " + r.status);
  log.debug("Leaving codeCount().");
  return ((r.json && r.json.events) || []).length;
}

async function codeAdded(realm, code, before) {
  log.debug("Entering codeAdded(). " + code);
  let now = before;
  for (let i = 0; i < 25 && now <= before; i += 1) {
    now = await codeCount(realm, code);
    if (now <= before) {
      await sleep(150);
    }
  }
  log.debug("Leaving codeAdded().");
  return now > before;
}

// POST and assert a 400, the errors' text matching `pattern` when one is
// given and `code` recorded when one is given.
async function refused(realm, path, body, code, pattern, what) {
  log.debug("Entering refused(). " + what);
  const before = code ? await codeCount(realm, code) : 0;
  const r = await call("POST", realmBase(realm) + "/admin-api" + path, body);
  const seen = code ? await codeAdded(realm, code, before) : true;
  check(what + " — 400" + (code ? ", recorded " + code : ""), function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 400));
    assert.ok(r.json && r.json.ok === false, r.text.slice(0, 400));
    if (pattern) {
      assert.ok(pattern.test((r.json.errors || []).join(" ")),
                JSON.stringify(r.json.errors));
    }
    assert.ok(seen, "no new " + code + " row");
  });
  log.debug("Leaving refused().");
  return r;
}

// One group's drill-down: `?group=` takes the group's DN, so a cn is put
// under the realm's ou=groups.
async function groupOf(r0, group) {
  log.debug("Entering groupOf(). " + group);
  const dn = /=/.test(group) ? group : "cn=" + group + "," + r0.groupsDn;
  const r = await call("GET", realmBase(r0.id) + "/admin-api/groups?group=" +
                       encodeURIComponent(dn));
  assert.strictEqual(r.status, 200, r.text.slice(0, 300));
  log.debug("Leaving groupOf().");
  return r.json;
}

async function realm(id, mode, extra) {
  log.debug("Entering realm(). " + id);
  await ok(base + "/admin-api/realms/create",
           { id: id, domain: id + ".example.net",
             name: "D12 directory writes " + mode,
             overrides: Object.assign({ "global.mode": mode },
                                      extra || {}) },
           "created the " + mode + " realm " + id);
  MADE_REALMS.push(id);
  const where = await call("GET", realmBase(id) + "/admin-api/groups");
  log.debug("Leaving realm().");
  return { id: id, baseDn: String(where.json.baseDn),
           usersDn: String(where.json.usersDn),
           groupsDn: String(where.json.groupsDn) };
}

async function person(r, username, password) {
  log.debug("Entering person(). " + username);
  const body = { username: username, invent: false,
    attributes: { cn: "DW " + username, givenName: "DW", sn: username,
                  mail: username + "@dw.test" } };
  if (password) {
    body.credential = "password";
    body.password = password;
  }
  const made = await ok(realmBase(r.id) + "/admin-api/users/create", body,
                        "created " + username + " in " + r.id);
  log.debug("Leaving person().");
  return String(made.dn);
}

// ---------------------------------------------------------------- LDAP ----
function ldapsUrl() {
  log.debug("Entering ldapsUrl().");
  log.debug("Leaving ldapsUrl().");
  return process.env.STS_LDAPS_URL ||
    ("ldaps://" + hostOf(base) + ":" + (process.env.STS_LDAPS_PORT || 636));
}

function connect() {
  log.debug("Entering connect().");
  const url = ldapsUrl();
  const client = ldapjs.createClient({
    url: url, reconnect: false, timeout: 20000, connectTimeout: 15000,
    tlsOptions: { rejectUnauthorized: true, servername: hostOf(url) }
  });
  client.on("error", function (e) {
    // ldapjs emits on the client as well as calling back; the operation in
    // flight reports it.
    log.debug("The LDAP client emitted an error: " + e.message);
  });
  log.debug("Leaving connect().");
  return client;
}

function settle(fn) {
  log.debug("Entering settle().");
  log.debug("Leaving settle().");
  return new Promise(function (resolve) {
    fn(function (e) {
      resolve({ code: e ? e.code : 0, message: e ? String(e.message) : "" });
    });
  });
}

function unbind(client) {
  log.debug("Entering unbind().");
  log.debug("Leaving unbind().");
  return new Promise(function (resolve) {
    try {
      client.unbind(function () {
        resolve(true);
      });
    } catch (e) {
      log.debug("Caught in unbind(): " + ((e && e.message) || e));
      // A connection the server already closed cannot be unbound.
      resolve(false);
    }
  });
}

// One LDAP operation on a connection of its own, bound when `dn` is given.
async function ldapOnce(dn, password, fn) {
  log.debug("Entering ldapOnce().");
  const client = connect();
  try {
    if (dn) {
      const b = await settle(function (done) {
        client.bind(dn, password, done);
      });
      assert.strictEqual(b.code, 0, "binding as " + dn + ": " + b.code + " " +
                         b.message);
    }
    log.debug("Leaving ldapOnce().");
    return await fn(client);
  } finally {
    await unbind(client);
  }
}

function search(client, dn, options) {
  log.debug("Entering search(). " + dn);
  log.debug("Leaving search().");
  return new Promise(function (resolve) {
    const entries = [];
    let settled = false;
    const done = function (outcome) {
      log.debug("Entering done().");
      if (!settled) {
        settled = true;
        clearTimeout(deadline);
        resolve(outcome);
      }
      log.debug("Leaving done().");
    };
    const deadline = setTimeout(function () {
      done({ code: -1, entries: [] });
    }, 20000);
    client.search(dn, Object.assign({ filter: "(objectClass=*)",
                                      scope: "base", attributes: ["*"] },
                                    options || {}), function (e, res) {
      if (e) {
        done({ code: e.code, entries: [] });
        return;
      }
      res.on("searchEntry", function (entry) {
        const pojo = entry.pojo || entry;
        const attrs = {};
        (pojo.attributes || []).forEach(function (a) {
          attrs[String(a.type).toLowerCase()] = [].concat(a.values || [])
            .map(String);
        });
        entries.push({ dn: String(pojo.objectName).toLowerCase()
                             .replace(/,\s+/g, ","), attributes: attrs });
      });
      res.on("error", function (err) {
        done({ code: err.code, entries: entries });
      });
      res.on("end", function (result) {
        done({ code: result ? result.status : 0, entries: entries });
      });
    });
  });
}

// An entry's attributes, read over LDAPS with no bind (a development realm
// reads anything) or as `dn`.
async function read(entryDn, bindDn, password) {
  log.debug("Entering read(). " + entryDn);
  const r = await ldapOnce(bindDn, password, function (c) {
    return search(c, entryDn, {});
  });
  log.debug("Leaving read().");
  return r.entries[0] ? r.entries[0].attributes : null;
}

// ---------------------------------------------------------------- SCIM ----
function scim(r, method, path, body) {
  log.debug("Entering scim(). " + method + " " + path);
  log.debug("Leaving scim().");
  // A development realm verifies no SCIM credential, but one is REQUIRED in
  // every mode; Basic is the scheme with nothing to mint.
  return call(method, realmBase(r.id) + "/scim/v2" + path, body,
              { "Content-Type": "application/scim+json",
                Accept: "application/scim+json",
                Authorization: "Basic " +
                  Buffer.from("dw-provisioner:anything").toString("base64") });
}

// What SCIM answers a PATCH adding a member that names nothing (observed).
const GHOST_STATUS = 400;
const USER = "urn:ietf:params:scim:schemas:core:2.0:User";
const GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group";

function scimUser(username) {
  log.debug("Entering scimUser().");
  log.debug("Leaving scimUser().");
  return { schemas: [USER], userName: username,
           name: { givenName: "DW", familyName: username },
           emails: [{ value: username + "@dw.test", primary: true }] };
}

async function bulk(r, operations) {
  log.debug("Entering bulk(). " + operations.length);
  const answer = await scim(r, "POST", "/Bulk", {
    schemas: ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
    Operations: operations });
  log.debug("Leaving bulk(). " + answer.status);
  return answer;
}

function statusesOf(answer) {
  log.debug("Entering statusesOf().");
  log.debug("Leaving statusesOf().");
  return ((answer.json && answer.json.Operations) || []).map(function (o) {
    return String(o.status);
  });
}

// Many people in as few Bulks as the service allows, their ids answered.
async function scimPeople(r, prefix, count) {
  log.debug("Entering scimPeople(). " + count);
  const ids = [];
  for (let start = 0; start < count; start += 100) {
    const ops = [];
    for (let i = start; i < Math.min(count, start + 100); i += 1) {
      ops.push({ method: "POST", path: "/Users", bulkId: "p" + i,
                 data: scimUser(prefix + i) });
    }
    const answer = await bulk(r, ops);
    assert.strictEqual(answer.status, 200, answer.text.slice(0, 400));
    (answer.json.Operations || []).forEach(function (o) {
      assert.strictEqual(String(o.status), "201", JSON.stringify(o));
      ids.push(String(o.location).split("/").pop());
    });
  }
  log.debug("Leaving scimPeople().");
  return ids;
}

// ------------------------------------------------------------ sections ----
async function groupNames(r) {
  log.debug("Entering groupNames().");
  log.info("=== A1. what a group may be called (" + r.id + ") ===");
  const made = await ok(realmBase(r.id) + "/admin-api/groups/create",
                        { group: "dgw-developers" }, "created dgw-developers");
  check("an ordinary name is accepted, at cn=<name>,ou=groups", function () {
    assert.ok(String(made.dn).toLowerCase().indexOf(
      "cn=dgw-developers,ou=groups") === 0, made.dn);
  });
  await refused(r.id, "/groups/create", { group: "dgw-developers" }, null,
                new RegExp(String(made.dn).replace(/[.*+?^${}()|[\]\\]/g,
                                                   "\\$&"), "i"),
                "the same name twice, the refusal NAMING the entry there");
  await refused(r.id, "/groups/create", { group: "developers" }, null, null,
                "a group the realm SEEDS (development seeds cn=developers)");
  await refused(r.id, "/groups/create",
                { group: "cn=developers,ou=groups," + r.baseDn }, null, null,
                "a DN, refused rather than escaped into a name");
  await refused(r.id, "/groups/create", { group: "two,parts" }, null, /4514/,
                "a name carrying a character RFC 4514 reserves, saying which " +
                "rule");
  await refused(r.id, "/groups/create", { group: "   " }, null, null,
                "an empty name");

  log.info("=== A2. an empty group ===");
  const empty = await ok(realmBase(r.id) + "/admin-api/groups/create",
                         { group: "dgw-nobody-in-here" },
                         "created an empty group");
  const emptyRead = await groupOf(r, "dgw-nobody-in-here");
  check("a group with no members is created, holds no membership value, " +
        "and is a groupOfNames", function () {
    assert.deepStrictEqual(empty.members, []);
    assert.ok(emptyRead.found && emptyRead.group, JSON.stringify(emptyRead)
      .slice(0, 300));
    assert.strictEqual((emptyRead.group.members || []).length, 0);
    assert.ok(JSON.stringify(emptyRead.group.objectClass ||
                             emptyRead.group.attributes || "")
      .toLowerCase().indexOf("groupofnames") >= 0,
              JSON.stringify(emptyRead.group).slice(0, 400));
  });

  log.info("=== A3. a value carrying a NUL ===");
  await refused(r.id, "/groups/create",
                { group: "dgw-nul-note", note: "hello\u0000there" },
                "STS-LDAP-0008", /NUL/, "a note carrying a NUL");
  const nul = await groupOf(r, "dgw-nul-note");
  check("and nothing was stored under that name", function () {
    assert.strictEqual(nul.found, false, JSON.stringify(nul).slice(0, 200));
  });
  log.debug("Leaving groupNames().");
}

async function groupMembers(r) {
  log.debug("Entering groupMembers().");
  log.info("=== A4. where a membership value points ===");
  const api = realmBase(r.id) + "/admin-api";
  const alice = await person(r, "dgw-alice-" + STAMP);
  const bob = await person(r, "dgw-bob-" + STAMP);
  const group = await ok(api + "/groups/create", { group: "dgw-team" },
                         "created dgw-team");
  const added = await ok(api + "/groups/add-member",
                         { group: "dgw-team", member: "dgw-alice-" + STAMP },
                         "added alice by name");
  check("adding by NAME writes their own entry DN onto `member`, and it " +
        "resolves", function () {
    assert.strictEqual(added.changed, true);
    assert.strictEqual(String(added.member).toLowerCase(),
                       alice.toLowerCase());
    assert.strictEqual(added.present, true);
    assert.strictEqual(added.attribute, "member");
  });
  const byDn = await ok(api + "/groups/add-member",
                        { group: group.dn, member: "dgw-bob-" + STAMP },
                        "added bob naming the group by DN");
  check("the group may be named by its whole DN too", function () {
    assert.strictEqual(byDn.changed, true);
  });
  await refused(r.id, "/groups/add-member",
                { group: group.dn, member: "dgw-nobody-" + STAMP },
                "STS-LDAP-0212", /Nothing is stored at/,
                "somebody with no entry, by name");
  const team = await groupOf(r, "dgw-team");
  check("the group holds the two people and both resolve", function () {
    const members = team.group.members || [];
    assert.strictEqual(members.length, 2, JSON.stringify(members));
    assert.strictEqual(members.filter(function (m) {
      return m.present;
    }).length, 2, JSON.stringify(members));
  });
  await refused(r.id, "/groups/create",
                { group: "dgw-with-nobody",
                  members: ["dgw-nobody-" + STAMP] },
                "STS-LDAP-0212", null,
                "a group created listing somebody who is not there");
  const notMade = await groupOf(r, "dgw-with-nobody");
  check("and nothing is stored", function () {
    assert.strictEqual(notMade.found, false);
  });
  // THE ONE DOOR SCIM WRITES THROUGH asks the same question of a value it
  // adds.
  const listed = await scim(r, "GET", "/Groups?filter=" +
                            encodeURIComponent('displayName eq "dgw-team"'));
  const scimId = ((listed.json && listed.json.Resources) || [])[0];
  check("precondition: SCIM lists the group", function () {
    assert.ok(scimId && scimId.id, listed.text.slice(0, 300));
  });
  const ghost = await scim(r, "PATCH", "/Groups/" + scimId.id, {
    schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    Operations: [{ op: "add", path: "members",
                   value: [{ value: crypto.randomUUID() }] }] });
  const afterGhost = await groupOf(r, "dgw-team");
  check("SCIM adding a member that names nothing is refused, and the " +
        "group is unchanged", function () {
    assert.strictEqual(ghost.status, GHOST_STATUS, ghost.text.slice(0, 300));
    assert.strictEqual((afterGhost.group.members || []).length, 2);
  });

  log.info("=== A5. idempotence, and what it refuses ===");
  const again = await ok(api + "/groups/add-member",
                         { group: "dgw-team", member: "dgw-alice-" + STAMP },
                         "added alice again");
  const once = await groupOf(r, "dgw-team");
  check("adding somebody already in it is NOT an error, changes nothing, " +
        "and leaves ONE value", function () {
    assert.strictEqual(again.changed, false);
    assert.strictEqual((once.group.members || []).length, 2);
  });
  await refused(r.id, "/groups/add-member",
                { group: "dgw-no-such-group", member: "dgw-alice-" + STAMP },
                null, /Create it first/,
                "adding to a group that does not exist");
  const sideEffect = await groupOf(r, "dgw-no-such-group");
  check("and it did NOT create the group on the way past", function () {
    assert.strictEqual(sideEffect.found, false);
  });
  await refused(r.id, "/groups/add-member",
                { group: bob, member: "dgw-alice-" + STAMP }, null, null,
                "adding a member to something that is not a group (a person)");
  await refused(r.id, "/groups/add-member", { group: "dgw-team", member: "" },
                null, null, "naming no member");
  await refused(r.id, "/groups/add-member",
                { group: "", member: "dgw-alice-" + STAMP }, null, null,
                "naming no group");

  log.info("=== A6. nothing is written onto the person ===");
  const held = await read(alice);
  const stored = await read(group.dn);
  check("the PERSON gained no memberOf", function () {
    assert.ok(held, "alice's entry did not read back");
    assert.ok(!held.memberof, JSON.stringify(Object.keys(held)));
  });
  check("and the group carries one entryDN at most — never a stored copy " +
        "beside the synthesised one", function () {
    assert.ok(!stored.entrydn || stored.entrydn.length === 1,
              JSON.stringify(stored.entrydn));
  });
  log.debug("Leaving groupMembers().");
}

async function groupMail(r) {
  log.debug("Entering groupMail().");
  log.info("=== A7. a group's own email address ===");
  const api = realmBase(r.id) + "/admin-api";
  const made = await ok(api + "/groups/create",
                        { group: "dgw-reporters", mail: "reporters@dw.test" },
                        "created a group with an address");
  const readBack = await read(made.dn);
  check("a create may give the address, and the entry carries it as mail",
        function () {
    assert.deepStrictEqual(readBack.mail, ["reporters@dw.test"]);
  });
  await refused(r.id, "/groups/create",
                { group: "dgw-bad-mail", mail: "not an address" },
                "STS-LDAP-0177", null, "a value that is not an address");
  const bad = await groupOf(r, "dgw-bad-mail");
  check("and nothing was created", function () {
    assert.strictEqual(bad.found, false);
  });
  const plain = await ok(api + "/groups/create", { group: "dgw-plain" },
                         "created dgw-plain");
  const set = await ok(api + "/groups/set-mail",
                       { group: "dgw-plain", mail: "plain@dw.test" },
                       "set its address by cn");
  const after = await read(plain.dn);
  check("set-mail writes the address by cn, and it reads back", function () {
    assert.strictEqual(set.changed, true);
    assert.deepStrictEqual(after.mail, ["plain@dw.test"]);
  });
  const same = await ok(api + "/groups/set-mail",
                        { group: plain.dn, mail: "plain@dw.test" },
                        "the same address by DN");
  check("the same address again changes nothing, by DN", function () {
    assert.strictEqual(same.changed, false);
  });
  const replaced = await ok(api + "/groups/set-mail",
                            { group: plain.dn, mail: "other@dw.test" },
                            "another address");
  const one = await read(plain.dn);
  check("another address replaces it: one value, the new one, the rest of " +
        "the entry untouched", function () {
    assert.strictEqual(replaced.changed, true);
    assert.deepStrictEqual(one.mail, ["other@dw.test"]);
    assert.ok((one.objectclass || []).length > 0 &&
              (one.description || []).length > 0, JSON.stringify(one));
  });
  const cleared = await ok(api + "/groups/set-mail",
                           { group: plain.dn, mail: "" }, "cleared it");
  const gone = await read(plain.dn);
  check("an empty value clears it, and the attribute is gone", function () {
    assert.strictEqual(cleared.changed, true);
    assert.ok(!gone.mail, JSON.stringify(gone.mail));
  });
  await refused(r.id, "/groups/set-mail",
                { group: "dgw-plain", mail: "nope" }, "STS-LDAP-0177", null,
                "a bad address at the setter too");
  await refused(r.id, "/groups/set-mail",
                { group: "dgw-no-such-" + STAMP, mail: "x@dw.test" },
                "STS-LDAP-0050", null, "a group that is not there");
  log.debug("Leaving groupMail().");
}

// Live sign-on sessions whose row names `username`.
async function sessionsOf(r, username) {
  log.debug("Entering sessionsOf(). " + username);
  const answer = await call("GET", realmBase(r.id) +
                            "/admin-api/sessions?per=300&q=" +
                            encodeURIComponent(username));
  assert.strictEqual(answer.status, 200, answer.text.slice(0, 300));
  const rows = (answer.json && (answer.json.sessions ||
                                answer.json.live || answer.json.rows)) || [];
  log.debug("Leaving sessionsOf().");
  return rows.filter(function (row) {
    return JSON.stringify(row).indexOf(username) >= 0;
  });
}

// A sign-on session for `username`, started the way WS-Trust starts one:
// an Issue with their UsernameToken (development checks no password).
async function signIn(r, username) {
  log.debug("Entering signIn(). " + username);
  const rst = '<?xml version="1.0" encoding="UTF-8"?>' +
    '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">' +
    '<soap:Header><wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/' +
    '2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">' +
    '<wsse:UsernameToken><wsse:Username>' + username + '</wsse:Username>' +
    '<wsse:Password>anything</wsse:Password></wsse:UsernameToken>' +
    '</wsse:Security></soap:Header><soap:Body><wst:RequestSecurityToken ' +
    'xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">' +
    '<wst:RequestType>' +
    'http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType>' +
    '<wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">' +
    '<wsa:EndpointReference ' +
    'xmlns:wsa="http://www.w3.org/2005/08/addressing"><wsa:Address>' +
    'urn:dw:' + STAMP + '</wsa:Address></wsa:EndpointReference>' +
    '</wsp:AppliesTo></wst:RequestSecurityToken></soap:Body></soap:Envelope>';
  const answer = await call("POST", realmBase(r.id) + "/sts", rst,
                            { "Content-Type": "application/soap+xml" });
  log.debug("Leaving signIn(). " + answer.status);
  return answer.status === 200;
}

async function bulkDeletes(r) {
  log.debug("Entering bulkDeletes().");
  log.info("=== B. a SCIM Bulk of deletes (" + r.id + ") ===");
  const prefix = "dbd-" + STAMP + "-";
  // A. A PERSON HOLDING NOTHING.
  const idleBefore = await codeCount(r.id, "STS-LOGOUT-0007");
  const idle = await scimPeople(r, prefix + "idle", 1);
  const idleGone = await scim(r, "DELETE", "/Users/" + idle[0]);
  await sleep(300);
  const selective = await call("GET", realmBase(r.id) +
                               "/admin-api/audit?per=500&action=" +
                               "logout.selective");
  const idleAfter = await codeCount(r.id, "STS-LOGOUT-0007");
  check("a person holding nothing is deleted (204) with no selective " +
        "sign-out at all — so no STS-LOGOUT-0007", function () {
    assert.strictEqual(idleGone.status, 204, idleGone.text.slice(0, 300));
    assert.strictEqual(((selective.json && selective.json.events) || [])
      .filter(function (row) {
        return JSON.stringify(row).indexOf(prefix + "idle") >= 0;
      }).length, 0, selective.text.slice(0, 400));
    assert.strictEqual(idleAfter, idleBefore);
  });

  // B. ONE BULK, EACH OPERATION ITS OWN STATUS.
  const people = await scimPeople(r, prefix + "b", 12);
  const signedIn = [];
  for (let i = 0; i < 3; i += 1) {
    signedIn.push(await signIn(r, prefix + "b" + i));
  }
  const live = await sessionsOf(r, prefix + "b0");
  check("three of them hold a sign-on session", function () {
    assert.deepStrictEqual(signedIn, [true, true, true]);
    assert.ok(live.length >= 1, "no live session named " + prefix + "b0");
  });
  const ops = people.slice(0, 6).map(function (id) {
    return { method: "DELETE", path: "/Users/" + id };
  }).concat([
    { method: "DELETE", path: "/Users/00000000-0000-4000-8000-00000000dead" },
    { method: "DELETE", path: "/Users/" + people[0] }
  ]).concat(people.slice(6).map(function (id) {
    return { method: "DELETE", path: "/Users/" + id };
  }));
  const b = await bulk(r, ops);
  await sleep(500);
  check("every operation has its own status, in order: six 204s, a missing " +
        "id 404, the person this Bulk already deleted 404, six 204s",
        function () {
    assert.strictEqual(b.status, 200, b.text.slice(0, 300));
    assert.strictEqual(statusesOf(b).join(","),
      "204,204,204,204,204,204,404,404,204,204,204,204,204,204");
  });
  const stillLive = [];
  for (let i = 0; i < 3; i += 1) {
    stillLive.push((await sessionsOf(r, prefix + "b" + i)).length);
  }
  check("every holder's sign-on session was ended", function () {
    assert.deepStrictEqual(stillLive, [0, 0, 0]);
  });
  let gone = 0;
  for (const id of people) {
    if ((await scim(r, "GET", "/Users/" + id)).status === 404) {
      gone += 1;
    }
  }
  const refusedSignOuts = ((await call("GET", realmBase(r.id) +
    "/admin-api/audit?per=500&action=logout.selective&outcome=refused"))
    .json.events || []).filter(function (row) {
    return JSON.stringify(row).indexOf(prefix) >= 0;
  });
  check("every one of them is gone, and nobody's sign-out was refused",
        function () {
    assert.strictEqual(gone, 12);
    assert.strictEqual(refusedSignOuts.length, 0,
                       JSON.stringify(refusedSignOuts).slice(0, 400));
  });

  // C. ORDER ACROSS THE BATCH, AND bulkId REFERENCES.
  const carol = (await scimPeople(r, prefix + "carol", 1))[0];
  await signIn(r, prefix + "carol0");
  const c = await bulk(r, [
    { method: "DELETE", path: "/Users/" + carol },
    { method: "POST", path: "/Users", bulkId: "again",
      data: scimUser(prefix + "carol0") },
    { method: "POST", path: "/Groups", bulkId: "grp",
      data: { schemas: [GROUP], displayName: prefix + "carols",
              members: [{ value: "bulkId:again" }] } }
  ]);
  const newCarol = String(((c.json.Operations || [])[1] || {}).location || "")
    .split("/").pop();
  const groupId = String(((c.json.Operations || [])[2] || {}).location || "")
    .split("/").pop();
  check("DELETE then POST of the same name, in order: 204, 201, 201, and a " +
        "NEW person (another id)", function () {
    assert.strictEqual(statusesOf(c).join(","), "204,201,201");
    assert.ok(newCarol && newCarol !== carol, newCarol + " / " + carol);
  });
  const groupRead = await scim(r, "GET", "/Groups/" + groupId);
  check("and the Group's `bulkId:again` reference resolved to the new person",
        function () {
    assert.ok(((groupRead.json && groupRead.json.members) || [])
      .some(function (m) {
        return m.value === newCarol;
      }), groupRead.text.slice(0, 400));
  });
  await signIn(r, prefix + "carol0");
  await sleep(500);
  const carolLive = await sessionsOf(r, prefix + "carol0");
  check("the new person's session, made after the Bulk, is not ended by " +
        "the delete of the person before them", function () {
    assert.ok(carolLive.length >= 1, "no live session for the new carol");
  });

  // D. MORE THAN ONE CHUNK.
  const many = await scimPeople(r, prefix + "m", 520);
  const d = await bulk(r, many.map(function (id) {
    return { method: "DELETE", path: "/Users/" + id };
  }));
  check("520 deletes in one Bulk, each answered 204", function () {
    assert.strictEqual(d.status, 200, d.text.slice(0, 300));
    assert.strictEqual(statusesOf(d).filter(function (s) {
      return s === "204";
    }).length, 520);
  });

  // E. THE NAME AND THE ID FOLLOW THE DELETE.
  const erin = (await scimPeople(r, prefix + "erin", 1))[0];
  await scim(r, "DELETE", "/Users/" + erin);
  const byName = await scim(r, "GET", "/Users?filter=" +
    encodeURIComponent('userName eq "' + prefix + 'erin0"'));
  const byId = await scim(r, "GET", "/Users/" + erin);
  check("the deleted person's id answers 404 and their name nobody",
        function () {
    assert.strictEqual(byId.status, 404);
    assert.strictEqual((byName.json && byName.json.totalResults), 0,
                       byName.text.slice(0, 300));
  });
  const erin2 = (await scimPeople(r, prefix + "erin", 1))[0];
  const byName2 = await scim(r, "GET", "/Users?filter=" +
    encodeURIComponent('userName eq "' + prefix + 'erin0"'));
  check("a person made again under the name is found by name, with their " +
        "new id", function () {
    assert.ok(erin2 !== erin);
    assert.strictEqual(((byName2.json && byName2.json.Resources) || [])
      .map(function (u) {
        return u.id;
      }).join(), erin2);
    assert.strictEqual((byName2.json && byName2.json.totalResults), 1);
  });

  // F. NOT A LEAF. A development realm lets an unbound connection add.
  const frank = (await scimPeople(r, prefix + "frank", 1))[0];
  const frankUser = await scim(r, "GET", "/Users/" + frank);
  const frankDn = "uid=" + prefix + "frank0," + r.usersDn;
  const childDn = "cn=dbd-child," + frankDn;
  const child = await ldapOnce(null, null, function (cl) {
    return settle(function (done) {
      cl.add(childDn, { objectClass: ["device"], cn: "dbd-child" }, done);
    });
  });
  check("precondition: an entry placed beneath a person over LDAP",
        function () {
    assert.strictEqual(frankUser.status, 200, frankUser.text.slice(0, 200));
    assert.strictEqual(child.code, 0, child.message);
  });
  const f = await bulk(r, [{ method: "DELETE", path: "/Users/" + frank }]);
  const fStatus = statusesOf(f)[0];
  const stillThere = await scim(r, "GET", "/Users/" + frank);
  check("a person with an entry beneath them is refused in a batch (not a " +
        "leaf), and is still there", function () {
    assert.ok(/^4\d\d$/.test(fStatus) && fStatus !== "404",
              f.text.slice(0, 400));
    assert.strictEqual(stillThere.status, 200);
  });
  const childGone = await ldapOnce(null, null, function (cl) {
    return settle(function (done) {
      cl.del(childDn, done);
    });
  });
  const g = await bulk(r, [{ method: "DELETE", path: "/Users/" + frank }]);
  check("and once the entry beneath is gone, deleted (204)", function () {
    assert.strictEqual(childGone.code, 0, childGone.message);
    assert.strictEqual(statusesOf(g)[0], "204", g.text.slice(0, 300));
  });
  log.debug("Leaving bulkDeletes().");
}

async function productDirectory(prod, dev) {
  log.debug("Entering productDirectory().");
  log.info("=== C1. a product directory: containers, no invented people ===");
  const admin = "dw-admin-" + STAMP;
  const adminDn = await person(prod, admin, PASSWORD);
  await ok(realmBase(prod.id) + "/admin-api/rbac/grant",
           { username: admin, role: "read" }, "granted Admin Read");
  const subtree = await ldapOnce(adminDn, PASSWORD, function (c) {
    return search(c, prod.baseDn, { scope: "sub", attributes: ["*"] });
  });
  const byDn = {};
  subtree.entries.forEach(function (e) {
    byDn[e.dn] = e.attributes;
  });
  const at = function (rdn) {
    log.debug("Entering at().");
    log.debug("Leaving at().");
    return (rdn + "," + prod.baseDn).toLowerCase();
  };
  check("the administrator reads the realm's subtree", function () {
    assert.ok(subtree.code === 0 && subtree.entries.length > 3,
              subtree.code + " " + subtree.entries.length);
  });
  ["uid=alice,ou=users", "uid=bob,ou=users", "uid=carol,ou=users",
   "cn=admin", "cn=developers,ou=groups",
   "cn=directory-admins,ou=groups"].forEach(function (rdn) {
    check("PRODUCT: no demonstration entry " + rdn, function () {
      assert.ok(!byDn[at(rdn)], at(rdn));
    });
  });
  check("PRODUCT: NEITHER privileged XACML identity is seeded", function () {
    assert.ok(!byDn[at("cn=remote-pep-1,ou=users")] &&
              !byDn[at("cn=xacml-user-1,ou=users")]);
  });
  const empty = function (rdn) {
    log.debug("Entering empty().");
    const e = byDn[at(rdn)];
    log.debug("Leaving empty().");
    return !!e && !(e.member || []).length;
  };
  check("PRODUCT: the two XACML role groups and the two Shared Signals " +
        "role groups ARE seeded, EMPTY", function () {
    assert.ok(empty("cn=remote-peps,ou=groups") &&
              empty("cn=xacml-users,ou=groups") &&
              empty("cn=ssf-read,ou=groups") &&
              empty("cn=ssf-manage,ou=groups"),
              Object.keys(byDn).filter(function (dn) {
                return /ou=groups/.test(dn);
              }).join(", "));
  });
  ["ou=users", "ou=groups", "ou=applications"].forEach(function (rdn) {
    check("PRODUCT: the structural container " + rdn + " is there",
          function () {
      assert.ok(byDn[at(rdn)], at(rdn));
    });
  });
  check("PRODUCT: and the base entry does not describe development mode",
        function () {
    const baseEntry = byDn[prod.baseDn.toLowerCase()];
    assert.ok(baseEntry, prod.baseDn);
    assert.ok(!/Every bind succeeds/.test(JSON.stringify(
      baseEntry.description || [])), JSON.stringify(baseEntry.description));
  });
  const devAlice = await read("uid=alice," + dev.usersDn);
  const devPep = await read("cn=remote-pep-1," + dev.usersDn);
  check("development still seeds alice and the PEP identity", function () {
    assert.ok(devAlice && devPep);
  });

  log.info("=== C2. nothing invented, a bind audited truthfully ===");
  const probe = "dw-probe-" + STAMP;
  const made = await ok(realmBase(prod.id) + "/admin-api/users/create",
    { username: probe, credential: "password", password: PASSWORD,
      attributes: { givenName: "Probe", sn: "Person",
                    mail: probe + "@dw.test" } },
    "created a person with invent defaulted");
  const entry = await read(String(made.dn), adminDn, PASSWORD);
  check("PRODUCT: a create with invent defaulted invents NONE of the " +
        "persona attributes — no displayName, the names and mail supplied, " +
        "cn made of the names", function () {
    assert.ok(entry, "the entry did not read back");
    assert.ok(!entry.displayname, JSON.stringify(entry.displayname));
    assert.deepStrictEqual(entry.givenname, ["Probe"]);
    assert.deepStrictEqual(entry.sn, ["Person"]);
    assert.deepStrictEqual(entry.mail, [probe + "@dw.test"]);
    assert.deepStrictEqual(entry.cn, ["Probe Person"]);
  });
  const devProbe = await ok(realmBase(dev.id) + "/admin-api/users/create",
    { username: probe, attributes: {} }, "created one in development");
  const devEntry = await read(String(devProbe.dn));
  check("development still invents a persona, \"(mock)\" and all",
        function () {
    assert.ok(devEntry && / \(mock\)$/.test((devEntry.displayname || [])[0]),
              JSON.stringify(devEntry && devEntry.displayname));
  });
  const populate = await call("POST", realmBase(prod.id) +
                              "/admin-api/credential-claims/populate", {});
  check("PRODUCT: the credential-attribute sweep does not run, saying why",
        function () {
    assert.strictEqual(populate.status, 200, populate.text.slice(0, 300));
    assert.ok(/product mode/.test(JSON.stringify(populate.json)),
              populate.text.slice(0, 400));
  });
  const bindRows = async function (r, dn) {
    log.debug("Entering bindRows().");
    const a = await call("GET", realmBase(r.id) +
                         "/admin-api/audit?per=500&action=directory.bind");
    log.debug("Leaving bindRows().");
    return ((a.json && a.json.events) || []).filter(function (row) {
      return String(row.target).toLowerCase() === String(dn).toLowerCase() &&
             row.outcome === "success";
    });
  };
  await ldapOnce(String(made.dn), PASSWORD, async function () {
    return true;
  });
  await sleep(300);
  const prodRow = (await bindRows(prod, made.dn))[0];
  check("PRODUCT: THE AUDIT ROW SAYS THE PASSWORD WAS VERIFIED", function () {
    assert.ok(prodRow && prodRow.detail &&
              prodRow.detail.passwordVerified === true &&
              !/no password was checked/.test(String(prodRow.detail.note)),
              JSON.stringify(prodRow && prodRow.detail));
  });
  await ldapOnce(String(devProbe.dn), "x", async function () {
    return true;
  });
  await sleep(300);
  const devRow = (await bindRows(dev, devProbe.dn))[0];
  check("development still audits a bind as unchecked, which is what " +
        "happened", function () {
    assert.ok(devRow && devRow.detail &&
              devRow.detail.passwordVerified === false &&
              /no password was checked/.test(String(devRow.detail.note)),
              JSON.stringify(devRow && devRow.detail));
  });

  log.info("=== C3. no open door for a trust anchor, and the TLS floor ===");
  for (const path of ["/tls/trust", "/tls/trust/clear"]) {
    for (const r of [prod, dev]) {
      const answer = await call("POST", realmBase(r.id) + path, "x",
                                { "Content-Type": "text/plain" });
      check("POST " + path + " in " + r.id + " answers as an unrouted path",
            function () {
        assert.strictEqual(answer.status, 404);
        assert.ok(/Cannot POST/.test(answer.text), answer.text.slice(0, 200));
      });
    }
  }
  const versionOf = function (maxVersion) {
    log.debug("Entering versionOf(). " + maxVersion);
    log.debug("Leaving versionOf().");
    return new Promise(function (resolve) {
      const url = new URL(ldapsUrl());
      const s = tls.connect({ host: url.hostname, port: Number(url.port),
                              servername: url.hostname, maxVersion: maxVersion,
                              ca: serviceTrust.trustedCa() }, function () {
        const v = s.getProtocol();
        s.destroy();
        resolve(v);
      });
      s.on("error", function (e) {
        resolve("refused: " + (e.code || e.message));
      });
    });
  };
  const twelve = await versionOf("TLSv1.2");
  const thirteen = await versionOf("TLSv1.3");
  check("by default a TLS 1.2 client is REFUSED on LDAPS and a 1.3 client " +
        "is served — the listeners' floor reaches the handshake", function () {
    assert.ok(/^refused/.test(twelve), twelve);
    assert.strictEqual(thirteen, "TLSv1.3");
  });
  log.debug("Leaving productDirectory().");
}

async function longDn(dev) {
  log.debug("Entering longDn().");
  log.info("=== D. a DN the store cannot hold ===");
  const store = String(await facts.setting(base + "/admin-api",
                                           "persistence.mode"));
  const longName = "longdn-" + STAMP + "-" + "n".repeat(400);
  const before = await codeCount(dev.id, "STS-LDAP-0204");
  const made = await call("POST", realmBase(dev.id) + "/admin-api/users/create",
    { username: longName, invent: false,
      attributes: { cn: "x", sn: "x", givenName: "x", mail: "x@dw.test" } });
  const longDnText = "uid=" + longName + "-ldap," + dev.usersDn;
  const added = await ldapOnce(null, null, function (c) {
    return settle(function (done) {
      c.add(longDnText, { objectClass: ["top", "person", "inetOrgPerson"],
                          sn: "x", cn: "x" }, done);
    });
  });
  if (store === "mariadb") {
    const seen = await codeAdded(dev.id, "STS-LDAP-0204", before);
    check("MariaDB: a username too long for the store's DN key is refused " +
          "STS-LDAP-0204, saying to choose a shorter one", function () {
      assert.strictEqual(made.status, 400, made.text.slice(0, 300));
      assert.ok(/shorter username/.test(JSON.stringify(made.json)),
                made.text.slice(0, 300));
      assert.ok(seen, "no STS-LDAP-0204 row");
    });
    const there = await call("GET", realmBase(dev.id) + "/admin-api/users?" +
                             "user=" + encodeURIComponent(longName));
    check("MariaDB: and nothing was written", function () {
      assert.ok(there.json && there.json.known === false,
                there.text.slice(0, 200));
    });
    check("MariaDB: and an LDAP add of such a DN is refused too", function () {
      assert.notStrictEqual(added.code, 0, added.message);
    });
  } else {
    check(store + ": the store holds any DN, so the same username is " +
          "accepted, over the API and over LDAP", function () {
      assert.strictEqual(made.status, 200, made.text.slice(0, 300));
      assert.strictEqual(added.code, 0, added.message);
    });
  }
  log.debug("Leaving longDn().");
}

async function test() {
  log.debug("Entering test().");
  // A Bulk of more than one sign-out chunk (500) needs a realm whose Bulk
  // limit is above it; the shipped limit is 100.
  const dev = await realm("dwd" + STAMP, "development",
                          { "scim.bulkMaxOperations": "600" });
  const prod = await realm("dwp" + STAMP, "product",
                           { "authn.allowOptionalSecondFactor": "true" });
  log.info("Realms " + dev.id + " (development) and " + prod.id +
           " (product).");
  await groupNames(dev);
  await groupMembers(dev);
  await groupMail(dev);
  await bulkDeletes(dev);
  await productDirectory(prod, dev);
  await longDn(dev);
  // A FLOOR on the count: a section that stops running must fail the job.
  assert.ok(checks >= FLOOR,
    "only " + checks + " checks ran; a section stopped running.");
  log.info(checks + " checks passed.");
  log.debug("Leaving test().");
}

const program = new Command();
program.addOption(new Option("-u, --url <url>",
                  "ignored; kept for a uniform CLI across the suite"));
program.parse(process.argv);

test().then(async function () {
  await removeRealms();
  log.info("Test completed successfully.");
}).catch(async function (e) {
  log.error(e.stack || e.message);
  await removeRealms();
  process.exit(1);
});
