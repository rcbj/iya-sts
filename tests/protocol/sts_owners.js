// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_owners.js
//
// ---------------------------------------------------------------------------
// OWNERS OF ROLES, GROUPS AND APPLICATIONS, AND WHAT IS CLOSED TO THEM, OVER
// THE WIRE (D12, #444).
//
// In one throwaway realm it leaves behind, through `/admin-api`, LDAP and
// the token endpoint:
//
//   A. A ROLE'S OWNERS (D12: carries over tests/role_owners.js A, B, F).
//      `add-owner` takes a person and a group by any name they answer to,
//      each once; nobody (STS-XACML-0174), no owner (0173), no role (0057)
//      and a stranger removed (0176) are refused and write nothing, each
//      code read off `/admin-api/audit`; a describe-role and an add-member
//      keep the owners; a remove keeps the members and the last owner may
//      go; an owner deleted over LDAP is taken off the role (#1612); the
//      unknown-action sentence names both acts. An application's owners
//      the same way (STS-REG-0355, STS-REG-0357).
//   B. WHAT IS CLOSED TO OWNERS (D12: carries over the over-the-wire half of
//      tests/owner_administration.js C, D and E; the owner rule end to end
//      is `sts_portal_owner_edits.js`'s). `GET /admin-api/ownership` gives
//      the reason a native role, a group this service grants through, this
//      service's own application and one declaring a protected scope are
//      closed, and none for an ordinary role; `set-protected` marks and
//      unmarks (the mark is then a reason), an unknown action is
//      STS-API-0134; OWNER_READ and OWNER_WRITE are built-in roles.
//   C. AN OWN MEMBER, NEVER AN INHERITED ONE (D12: carries over
//      tests/own_members.js O): an RFC 9396 detail whose type is
//      `constructor`, `toString` or `__proto__` is refused at the token
//      endpoint as an unknown type, STS-OAUTH-0453 on the audit row.
//
// NOT CARRIED, and why: owner_administration.js A and B decide questions
// against a stubbed register, every combination built by hand (the rule
// over the wire is sts_portal_owner_edits.js); role_owners.js C-E and
// owner_administration.js E's markup are the console's browser-drawn
// pages; own_members.js H, R, J, E, P, S, A, G and Z are library lookups
// whose doors (the XACML PDP and AuthZEN over mutual TLS, the policy
// editor, GNAP) belong to the phase-8 jobs.
//
// ITS REALMS ARE REMOVED AT THE END ONLY WHEN ASKED
// (`STS_TEST_REMOVE_REALMS=1`, which a hand run against a long-lived probe
// sets so that its directory does not fill): tests/CLAUDE.md's *No job
// removes a realm* is the rule for a shared run, so by default they stay.
//
// OWNED HERE (local: true): this repository's own management API.
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
var log = bunyan.createLogger({ name: "sts_owners",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("owners-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
  .slice(0, 31);
const DOMAIN = REALM + ".example.net";
const realmBase = base + "/realm/" + REALM;
const api = realmBase + "/admin-api";
const SUFFIX = DOMAIN.split(".").map(function (label) {
  return "dc=" + label;
}).join(",");
const LDAP_URL = "ldap://" + new URL(base).hostname + ":" +
                 (process.env.STS_LDAP_PORT || "389");

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

async function newestSeq() {
  log.debug("Entering newestSeq().");
  const r = await send(api + "/audit?per=1");
  log.debug("Leaving newestSeq().");
  return (r.body && r.body.newestSeq) || 0;
}

// The codes recorded in this realm after `since`; a response carries none.
async function codesSince(since, wanted) {
  log.debug("Entering codesSince().");
  let found = [];
  for (let i = 0; i < 20; i += 1) {
    const r = await send(api + "/audit?per=200");
    found = ((r.body && r.body.events) || []).filter(function (row) {
      return row.seq > since && row.errorCode;
    }).map(function (row) {
      return row.errorCode;
    });
    if (!wanted || found.indexOf(wanted) >= 0) {
      break;
    }
    await sleep(150);
  }
  log.debug("Leaving codesSince(). " + found.join(","));
  return found;
}

async function refused(url, payload, code, what) {
  log.debug("Entering refused().");
  const since = await newestSeq();
  const r = await postJson(url, payload);
  const codes = await codesSince(since, code);
  check(what + " (400, " + code + " on the audit row)", function () {
    assert.strictEqual(r.status, 400, r.raw.slice(0, 400));
    assert.ok(r.body && r.body.ok === false, r.raw.slice(0, 400));
    assert.ok(codes.indexOf(code) >= 0, "recorded: " + codes.join(","));
    assert.ok(r.raw.indexOf(code) < 0, "the code was sent");
  });
  log.debug("Leaving refused().");
  return r;
}

function person(username) {
  log.debug("Entering person().");
  log.debug("Leaving person().");
  return { username: username, invent: false, credential: "none",
           attributes: { cn: username, sn: "Owner", givenName: "Person",
                         mail: username + "@" + DOMAIN } };
}

async function roleOf(role) {
  log.debug("Entering roleOf().");
  const r = await send(api + "/roles?role=" + encodeURIComponent(role));
  assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
  log.debug("Leaving roleOf().");
  return r.body.role || {};
}

// One LDAP operation bound as the realm's directory; development authorizes
// every write (the root CLAUDE.md's index), which is the mode this runs in.
function ldapDelete(dn) {
  log.debug("Entering ldapDelete().");
  log.debug("Leaving ldapDelete().");
  return new Promise(function (resolve, reject) {
    const client = ldapjs.createClient({ url: LDAP_URL });
    client.on("error", function (e) {
      log.debug("Caught in ldapDelete(): " + ((e && e.message) || e));
      reject(e);
    });
    client.bind("uid=owners-binder,ou=users," + SUFFIX, "x-" + STAMP,
                function (bindError) {
      if (bindError) {
        client.destroy();
        reject(bindError);
        return;
      }
      client.del(dn, function (error) {
        client.unbind();
        if (error) {
          reject(error);
        } else {
          resolve();
        }
      });
    });
  });
}

async function roleOwners() {
  log.debug("Entering roleOwners().");
  const roles = api + "/roles/";
  log.info("=== A. a role's owners ===");
  await ok(api + "/users/create", person("ro-ann"), "created Ann");
  await ok(api + "/users/create", person("ro-bo"), "created Bo");
  await ok(api + "/users/create", person("owners-binder"), "a binder");
  const ops = await ok(api + "/groups/create", { group: "ro-ops" },
                       "created a group");
  await ok(roles + "create-role", { role: "ro-staff", description: "Staff" },
           "created a role");
  await ok(roles + "add-member", { role: "ro-staff", kind: "user",
                                   member: "ro-bo" }, "added a member");
  const ann = await ok(roles + "add-owner", { role: "ro-staff",
                                              owner: "ro-ann" }, "Ann");
  const again = await ok(roles + "add-owner", { role: "ro-staff",
    owner: ann.owner.toUpperCase() }, "Ann again, by her DN upper-cased");
  const group = await ok(roles + "add-owner", { role: "ro-staff",
                                                owner: "ro-ops" }, "a group");
  const held = await roleOf("ro-staff");
  check("a person and a group are added by any name they answer to, each " +
        "once", function () {
    assert.strictEqual(ann.changed, true);
    assert.strictEqual(again.changed, false, JSON.stringify(again));
    assert.strictEqual(group.owners.length, 2, JSON.stringify(group));
    assert.strictEqual(group.owners[0].kind, "person");
    assert.strictEqual(group.owners[1].kind, "group");
    assert.strictEqual(group.owners[1].name, "ro-ops");
    assert.ok(/is now an owner of/.test(ann.message), ann.message);
    assert.strictEqual((held.owners || []).length, 2, JSON.stringify(held));
  });
  await refused(roles + "add-owner", { role: "ro-staff",
                                       owner: "ro-no-such-one" },
                "STS-XACML-0174", "an owner who names nobody");
  await refused(roles + "add-owner", { role: "ro-staff", owner: "" },
                "STS-XACML-0173", "no owner");
  await refused(roles + "add-owner", { role: "ro-nothing-here",
                                       owner: "ro-ann" },
                "STS-XACML-0057", "a role that is not there");
  await refused(roles + "remove-owner", { role: "ro-staff",
    owner: "uid=ro-bo,ou=users," + SUFFIX }, "STS-XACML-0176",
    "a stranger removed");
  const afterRefusals = await roleOf("ro-staff");
  check("and none of them wrote anything", function () {
    assert.strictEqual(afterRefusals.owners.length, 2);
  });
  await ok(roles + "describe-role", { role: "ro-staff",
                                      description: "Staff, described" },
           "described the role");
  await ok(roles + "add-member", { role: "ro-staff", kind: "user",
                                   member: "ro-ann" }, "added Ann");
  const described = await roleOf("ro-staff");
  check("a describe-role and an add-member keep the owners", function () {
    assert.strictEqual(described.owners.length, 2, JSON.stringify(described));
    assert.strictEqual(described.description, "Staff, described");
    assert.strictEqual((described.users || []).length, 2,
                       JSON.stringify(described.users));
  });
  const off = await ok(roles + "remove-owner", { role: "ro-staff",
                                                 owner: ann.owner },
                       "took Ann off");
  const last = await ok(roles + "remove-owner", { role: "ro-staff",
                                                  owner: ops.dn },
                        "took the group off");
  const bare = await roleOf("ro-staff");
  check("a remove keeps the members, and the last owner may go", function () {
    assert.strictEqual(off.owners.length, 1);
    assert.strictEqual(last.owners.length, 0);
    assert.strictEqual(bare.users.length, 2);
  });
  await ok(roles + "add-owner", { role: "ro-staff", owner: "ro-bo" },
           "Bo owns it");
  await ldapDelete("uid=ro-bo,ou=users," + SUFFIX);
  const gone = await roleOf("ro-staff");
  check("an owner deleted over LDAP is taken off the role, which is kept " +
        "(#1612)", function () {
    assert.strictEqual((gone.owners || []).length, 0, JSON.stringify(gone));
    assert.ok(gone.dn || gone.name, JSON.stringify(gone).slice(0, 200));
  });
  const unknown = await postJson(roles + "no-such", {});
  check("the unknown-action sentence names both acts", function () {
    assert.strictEqual(unknown.status, 400);
    assert.ok(/add-owner, remove-owner/.test(
      (unknown.body.errors || []).join(" ")), unknown.raw.slice(0, 300));
  });

  log.info("=== A-F. an application's owners ===");
  const apps = api + "/applications/";
  await ok(apps + "create", { identifier: "ao-app", protocols: ["oauth2"],
                              fields: { oauthClientId: ["ao-app"] } },
           "created an application");
  await ok(apps + "add-owner", { application: "ao-app", owner: "ro-ann" },
           "Ann owns it");
  const appGroup = await ok(apps + "add-owner", { application: "ao-app",
                                                  owner: "ro-ops" },
                            "the group owns it");
  const appAgain = await ok(apps + "add-owner", { application: "ao-app",
                                                  owner: "ro-ann" },
                            "Ann again");
  check("a person and a group are added to an application, each once",
        function () {
    assert.strictEqual(appAgain.changed, false, JSON.stringify(appAgain));
    assert.strictEqual(appGroup.owners.length, 2);
    assert.strictEqual(appGroup.owners[1].kind, "group");
  });
  await refused(apps + "add-owner", { application: "ao-app",
                                      owner: "ao-no-such" },
                "STS-REG-0355", "an application owner who names nobody");
  await refused(apps + "remove-owner", { application: "ao-app",
                                         owner: "uid=x,dc=y" },
                "STS-REG-0357", "a stranger removed from an application");
  const noApp = await postJson(apps + "add-owner",
                               { application: "ao-nothing", owner: "ro-ann" });
  check("an owner for no application is refused", function () {
    assert.strictEqual(noApp.status, 400, noApp.raw.slice(0, 200));
  });
  const appOff = await ok(apps + "remove-owner", { application: "ao-app",
    owner: "uid=ro-ann,ou=users," + SUFFIX }, "took Ann off");
  check("a remove keeps the other owner", function () {
    assert.strictEqual(appOff.owners.length, 1, JSON.stringify(appOff));
  });
  log.debug("Leaving roleOwners().");
}

async function protectionOf(kind, name) {
  log.debug("Entering protectionOf().");
  const r = await send(api + "/ownership?kind=" + kind + "&name=" +
                       encodeURIComponent(name));
  assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
  log.debug("Leaving protectionOf().");
  return r.body;
}

async function closedToOwners() {
  log.debug("Entering closedToOwners().");
  log.info("=== B. what is closed to owners ===");
  await ok(api + "/roles/create-role", { role: "ob-plain" }, "a plain role");
  await ok(api + "/roles/add-owner", { role: "ob-plain", owner: "ro-ann" },
           "Ann owns it");
  await ok(api + "/applications/create", { identifier: "ob-scim",
    protocols: ["oauth2"], fields: { oauthClientId: ["ob-scim"],
      oauthAllowedScope: ["scim:read"] } }, "an application with scim:read");
  const native = await protectionOf("role", "ADMIN_WRITE");
  const roster = await protectionOf("group", "admin-write");
  const own = await protectionOf("application", "sts-user-portal");
  const scim = await protectionOf("application", "ob-scim");
  const plain = await protectionOf("role", "ob-plain");
  check("a native role is closed, and says it is native", function () {
    assert.strictEqual(native.protected, true);
    assert.ok(native.reasons.indexOf("it is a native role of this " +
                                     "service") >= 0, native.reasons);
  });
  check("the group the console roster is granted through is closed",
        function () {
    assert.strictEqual(roster.protected, true);
    assert.ok(roster.reasons.some(function (one) {
      return /grants a role or the console roster through/.test(one);
    }), JSON.stringify(roster.reasons));
  });
  check("this service's own application is closed", function () {
    assert.strictEqual(own.protected, true);
    assert.ok(own.reasons.indexOf("it is one of this service's own " +
                                  "applications") >= 0, own.reasons);
  });
  check("an application declaring a protected scope is closed, naming it",
        function () {
    assert.strictEqual(scim.protected, true);
    assert.ok(scim.reasons.some(function (one) {
      return /declares scim:read/.test(one);
    }), JSON.stringify(scim.reasons));
  });
  check("an ordinary role is open, and lists its owner", function () {
    assert.strictEqual(plain.protected, false, JSON.stringify(plain));
    assert.deepStrictEqual(plain.reasons, []);
    assert.strictEqual(plain.owners.length, 1);
    assert.strictEqual(plain.marked, false);
  });
  const marked = await ok(api + "/ownership/set-protected",
    { kind: "role", name: "ob-plain", protected: true }, "marked it");
  const nowMarked = await protectionOf("role", "ob-plain");
  check("set-protected closes it, and the mark is the reason", function () {
    assert.strictEqual(marked.ownerProtected, true);
    assert.strictEqual(nowMarked.marked, true);
    assert.strictEqual(nowMarked.protected, true);
    assert.deepStrictEqual(nowMarked.reasons,
                           ["an administrator closed it to its owners"]);
  });
  await ok(api + "/ownership/set-protected",
           { kind: "role", name: "ob-plain", protected: false },
           "unmarked it");
  const reopened = await protectionOf("role", "ob-plain");
  check("and unmarking opens it again", function () {
    assert.strictEqual(reopened.protected, false);
    assert.strictEqual(reopened.marked, false);
  });
  await refused(api + "/ownership/no-such", {}, "STS-API-0134",
                "an unknown ownership action");
  const register = await send(api + "/roles");
  check("OWNER_READ and OWNER_WRITE are built-in roles", function () {
    const builtIn = (register.body.builtIn || []).map(function (one) {
      return one.name;
    });
    assert.ok(builtIn.indexOf("OWNER_READ") >= 0 &&
              builtIn.indexOf("OWNER_WRITE") >= 0, builtIn.join());
  });
  log.debug("Leaving closedToOwners().");
}

async function ownMembers() {
  log.debug("Entering ownMembers().");
  log.info("=== C. an RFC 9396 type named after an inherited member ===");
  const CLIENT = "om-client";
  const SECRET = "om-" + STAMP + "-secret-value";
  await ok(api + "/applications/create", { identifier: CLIENT,
    protocols: ["oauth2"], fields: { oauthClientId: [CLIENT],
      oauthClientSecret: SECRET,
      oauthTokenEndpointAuthMethod: "client_secret_post",
      oauthGrantType: ["client_credentials"] } }, "a client");
  for (const type of ["constructor", "toString", "__proto__"]) {
    const since = await newestSeq();
    const r = await send(realmBase + "/oauth2/token", { method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "client_credentials",
        client_id: CLIENT, client_secret: SECRET,
        authorization_details: JSON.stringify([{ type: type }]) })
        .toString() });
    const codes = await codesSince(since, "STS-OAUTH-0453");
    check("a detail of type \"" + type + "\" is an unknown type (400 " +
          "invalid_authorization_details, STS-OAUTH-0453)", function () {
      assert.strictEqual(r.status, 400, r.raw.slice(0, 300));
      assert.strictEqual(r.body.error, "invalid_authorization_details");
      assert.ok(r.body.error_description.indexOf("'" + type + "'") >= 0,
                r.body.error_description);
      assert.ok(codes.indexOf("STS-OAUTH-0453") >= 0, codes.join(","));
    });
  }
  log.debug("Leaving ownMembers().");
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. the throwaway realm " + REALM + " ===");
  await ok(base + "/admin-api/realms/create", { id: REALM, domain: DOMAIN,
    name: "Owners " + STAMP }, "created the realm");
  await roleOwners();
  await closedToOwners();
  await ownMembers();
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
  log.error("sts_owners FAILED: " + ((e && e.stack) || e));
  return false;
}).then(async function (passed) {
  await removeRealms();
  if (!passed) {
    process.exit(1);
  }
});
