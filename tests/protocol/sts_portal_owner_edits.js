// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
// File: sts_portal_owner_edits.js
// ===========================================================================
// AN OWNER ADMINISTERS WHAT THEY OWN, FROM THE PORTAL, THROUGH /admin-api
// (#607, 2026-10-13). OURS (`local: true`).
//
// rcbj: a person updates the roles, groups, service accounts and
// applications they own from the user portal; the portal reaches the
// management API with `owner:read` and `owner:write`; and whether they may is
// the access-control policy's owner rule, in one place. This job signs a
// person in AS THE PORTAL — both resources, the owner scopes, the owner token
// refreshed from the same grant for `/admin-api` — and asks what the portal's
// owner pages ask:
//
//   a. the owner token carries owner:read and owner:write;
//   b. a role they own: read (the one role, not the register), described,
//      a member added; a list, add-permission and a role they do not own
//      refused; never the last owner, one of two;
//   c. a group they own: read (the one group), a member added;
//   d. an application they own: read (its owner fields only), its redirect
//      URIs written; its scopes and its grant types refused;
//   e. a service account they own: read;
//   f. an administrator's mark closes the role to them, GET /ownership says
//      why, and the portal's list says it is closed;
//   g. taken off everything, the token stops working at once;
//   h. a person who owns nothing is issued no owner scope.
//
// The default realm, with names stamped for the run; what it makes is left
// standing, as the other portal jobs leave theirs.
// ===========================================================================

const assert = require("assert");
const names = require("./random_username.js");
const portal = require("./portal_signin.js");
const consoleSignin = require("./console_signin.js");

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
var log = bunyan.createLogger({ name: "sts_portal_owner_edits",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp().toLowerCase().replace(/[^a-z0-9-]/g, "");
const OWNER = "po607-owner-" + STAMP;
const OTHER = "po607-other-" + STAMP;
const NOBODY = "po607-nobody-" + STAMP;
const ROLE = "po607-role-" + STAMP;
const FOREIGN_ROLE = "po607-foreign-" + STAMP;
const GROUP = "po607-group-" + STAMP;
const APP = "urn:example:po607:" + STAMP;
const SVC = "po607-svc-" + STAMP;

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

// The management API as an administrator: the run's preloaded credential.
async function admin(method, path, payload) {
  log.debug("Entering admin(). " + method + " " + path);
  const r = await fetch(base + "/admin-api" + path, {
    method: method,
    headers: payload === undefined ? {}
      : { "Content-Type": "application/json" },
    body: payload === undefined ? undefined : JSON.stringify(payload) });
  const raw = await r.text();
  let body = null;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in admin(): " + ((e && e.message) || e));
    // Not JSON: the caller reads `raw`.
    body = null;
  }
  log.debug("Leaving admin(). status=" + r.status);
  return { status: r.status, body: body, raw: raw };
}

async function adminOk(path, payload, what) {
  log.debug("Entering adminOk().");
  const r = await admin("POST", path, payload);
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST /admin-api" + path + " should have " + what + "; it answered " +
    r.status + " " + String(r.raw).slice(0, 400));
  log.debug("Leaving adminOk().");
  return r.body;
}

function refused(answer, what) {
  log.debug("Entering refused().");
  assert.strictEqual(answer.status, 403, what + ": " + answer.status + " " +
                     String(answer.text || "").slice(0, 400));
  log.debug("Leaving refused().");
}

function answered(answer, what) {
  log.debug("Entering answered().");
  assert.ok(answer.status === 200 && answer.json && answer.json.ok !== false,
            what + ": " + answer.status + " " +
            String(answer.text || "").slice(0, 400));
  log.debug("Leaving answered().");
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. two people, and what one of them owns ===");
  const say = log.info.bind(log);
  const password = await consoleSignin.ensureConsoleAccount(base, OWNER, say);
  await consoleSignin.ensureConsoleAccount(base, OTHER, say);
  await adminOk("/roles/create-role", { role: ROLE,
    description: "owned by " + OWNER }, "made the role");
  // The owner's DN, as the role now lists it: what a remove names.
  const ownerDn = String((await adminOk("/roles/add-owner", { role: ROLE,
    owner: OWNER }, "made the person its owner")).owner || "");
  await adminOk("/roles/create-role", { role: FOREIGN_ROLE }, "made another");
  await adminOk("/roles/add-owner", { role: FOREIGN_ROLE, owner: OTHER },
                "owned by somebody else");
  const group = await adminOk("/groups/create", { group: GROUP,
    members: [OTHER] }, "made the group");
  const groupDn = String(group.dn || "");
  await adminOk("/groups/add-owner", { group: GROUP, owner: OWNER },
                "made the person its owner");
  await adminOk("/applications/create", { identifier: APP,
    name: "Owner edits " + STAMP }, "made the application");
  await adminOk("/applications/add-owner", { application: APP,
    owner: OWNER }, "made the person its owner");
  await adminOk("/users/create", { username: SVC, invent: false,
    credential: "none", serviceAccount: true, owners: [OWNER] },
    "made the service account");

  log.info("=== a. the owner signs in as the portal ===");
  const p = await portal.signInToThePortal(base, OWNER, null,
    { password: password, owner: true });
  await p.ownerRefresh();
  check("the owner token carries owner:read and owner:write", function () {
    const scope = p.ownerScope().split(/\s+/);
    assert.ok(scope.indexOf("owner:read") >= 0 &&
              scope.indexOf("owner:write") >= 0, p.ownerScope());
  });

  log.info("=== b. a role they own ===");
  const role = await p.ownerApi("GET", "/admin-api/roles?role=" +
                                encodeURIComponent(ROLE));
  check("they read it, and only it", function () {
    assert.strictEqual(role.status, 200, role.text.slice(0, 400));
    assert.ok(role.json.role && role.json.role.name === ROLE,
              role.text.slice(0, 300));
    assert.strictEqual(role.json.roles, undefined,
                       "the register around it is not answered");
  });
  refused(await p.ownerApi("GET", "/admin-api/roles"),
          "the role register, a list, is refused to an owner's token");
  check("a list is refused", function () {});
  answered(await p.ownerApi("POST", "/admin-api/roles/describe-role",
    { role: ROLE, description: "described by its owner" }),
    "describe-role on a role they own");
  answered(await p.ownerApi("POST", "/admin-api/roles/add-member",
    { role: ROLE, kind: "user", member: OTHER }),
    "add-member on a role they own");
  const described = await admin("GET", "/roles?role=" +
                                encodeURIComponent(ROLE));
  check("the description and the member are written", function () {
    const r = described.body.role;
    assert.strictEqual(r.description, "described by its owner");
    assert.ok((r.users || []).indexOf(OTHER) >= 0, JSON.stringify(r.users));
  });
  refused(await p.ownerApi("POST", "/admin-api/roles/add-permission",
    { role: ROLE, permission: "admin:write" }),
    "add-permission is not an owner's");
  check("add-permission is refused", function () {});
  refused(await p.ownerApi("GET", "/admin-api/roles?role=" +
                           encodeURIComponent(FOREIGN_ROLE)),
          "a role somebody else owns");
  check("a role they do not own is refused", function () {});
  refused(await p.ownerApi("POST", "/admin-api/roles/remove-owner",
    { role: ROLE, owner: ownerDn }), "the last owner");
  check("the last owner cannot be taken off by an owner", function () {});
  const added = await p.ownerApi("POST", "/admin-api/roles/add-owner",
    { role: ROLE, owner: OTHER });
  answered(added, "add-owner");
  const otherDn = String(added.json.owner || "");
  answered(await p.ownerApi("POST", "/admin-api/roles/remove-owner",
    { role: ROLE, owner: otherDn }), "remove-owner, one of two");
  check("one of two owners can be", function () {});

  log.info("=== c. a group they own ===");
  const g = await p.ownerApi("GET", "/admin-api/groups?group=" +
                             encodeURIComponent(groupDn));
  check("they read it, and only it", function () {
    assert.strictEqual(g.status, 200, g.text.slice(0, 400));
    assert.ok(g.json.group && g.json.group.dn, g.text.slice(0, 300));
    assert.strictEqual(g.json.groups, undefined,
                       "the realm's other groups are not answered");
  });
  answered(await p.ownerApi("POST", "/admin-api/groups/add-member",
    { group: groupDn, member: OWNER }), "add-member on a group they own");
  check("a member is added", function () {});

  log.info("=== d. an application they own ===");
  const a = await p.ownerApi("GET", "/admin-api/applications?application=" +
                             encodeURIComponent(APP));
  check("they read its owner fields, and not the console's tabs", function () {
    assert.strictEqual(a.status, 200, a.text.slice(0, 400));
    assert.strictEqual(a.json.identifier, APP);
    assert.strictEqual(a.json.page, undefined);
    assert.ok(Array.isArray(a.json.owners) && a.json.owners.length === 1,
              JSON.stringify(a.json.owners));
  });
  answered(await p.ownerApi("POST", "/admin-api/applications/update-fields",
    { application: APP,
      fields: { oauthRedirectUri: ["https://po607.example/cb"] } }),
    "update-fields on its redirect URIs");
  check("its redirect URIs are written", function () {});
  refused(await p.ownerApi("POST", "/admin-api/applications/update-fields",
    { application: APP, fields: { oauthAllowedScope: ["admin:write"] } }),
    "its scopes");
  refused(await p.ownerApi("POST", "/admin-api/applications/set",
    { application: APP, attribute: "oauthGrantType",
      value: "client_credentials" }), "its grant types");
  check("its scopes and grant types are refused", function () {});

  log.info("=== e. a service account they own ===");
  const s = await p.ownerApi("GET", "/admin-api/service-accounts?account=" +
                             encodeURIComponent(SVC));
  check("they read it", function () {
    assert.strictEqual(s.status, 200, s.text.slice(0, 400));
    assert.ok(s.json.found && s.json.account.username === SVC,
              s.text.slice(0, 300));
  });

  log.info("=== f. an administrator closes the role to its owners ===");
  await adminOk("/ownership/set-protected", { kind: "role", name: ROLE,
    protected: true }, "marked the role");
  refused(await p.ownerApi("GET", "/admin-api/roles?role=" +
                           encodeURIComponent(ROLE)), "a marked role");
  const facts = await admin("GET", "/ownership?kind=role&name=" +
                            encodeURIComponent(ROLE));
  check("a marked role is refused to its owner, and says why", function () {
    assert.ok(facts.body && facts.body.protected === true &&
              facts.body.marked === true, facts.raw.slice(0, 300));
  });
  const owned = await p.api("GET", "/account-api/owned/roles");
  check("the portal's list says it is closed", function () {
    const row = ((owned.json || {}).rows || []).filter(function (one) {
      return one.id === ROLE;
    })[0];
    assert.ok(row && row.closed === true, JSON.stringify(owned.json));
  });

  log.info("=== g. taken off everything ===");
  await adminOk("/roles/remove-owner", { role: ROLE, owner: ownerDn },
                "took them off the role");
  await adminOk("/groups/remove-owner", { group: GROUP, owner: ownerDn },
                "the group");
  await adminOk("/applications/remove-owner", { application: APP,
    owner: ownerDn }, "the application");
  await adminOk("/users/set-service-account", { user: SVC,
    owners: [OTHER] }, "the service account");
  refused(await p.ownerApi("GET", "/admin-api/groups?group=" +
                           encodeURIComponent(groupDn)),
          "a token whose subject owns nothing now");
  check("the same token stops working at once", function () {});

  log.info("=== h. a person who owns nothing ===");
  const nobodyPassword = await consoleSignin.ensureConsoleAccount(base,
    NOBODY, say);
  const n = await portal.signInToThePortal(base, NOBODY, null,
    { password: nobodyPassword, owner: true });
  await n.ownerRefresh();
  check("is issued no owner scope", function () {
    assert.ok(n.ownerScope().split(/\s+/).indexOf("owner:read") < 0,
              n.ownerScope());
  });

  log.info("Test completed successfully. " + checks + " check(s) passed.");
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error("sts_portal_owner_edits FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
