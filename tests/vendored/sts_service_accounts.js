// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_service_accounts.js
//
// ---------------------------------------------------------------------------
// SERVICE ACCOUNTS OVER THE WIRE (#221 P1, P2, P4, 2026-10-06).
//
// In a throwaway realm it leaves behind, through /admin-api alone:
//
//   a. a create naming a service account with an owner who is nobody is
//      REFUSED, and nobody is left behind as an ordinary person;
//   b. a create naming a real owner makes one, and /admin-api/users tags it
//      and filters it with ?kind=service and ?kind=person;
//   c. its person page describes it — owner, and the policy's defaults: no
//      browser sign-in, no exemption, no rotation;
//   d. the service-account policy is the third kind on /admin-api/policies,
//      and a save of it is read back, inherited by nothing else;
//   e. Rotate now is REFUSED for an account that names no destination, and
//      for a person;
//   f. GET /admin-api/service-accounts lists it with the realm's rotation
//      settings;
//   g. set-service-account false makes them an ordinary person again.
//
// What a door does with a service account — the password doors, the
// browser, the KDC, the second-factor exemption — and the rotation's push
// and commit are held in process by `tests/service_accounts.js`, which can
// stand in a fake push destination; this job holds the surface a client of
// the management API sees.
//
// `local: true` in MANIFEST.js: this repository's own /admin-api.
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
var log = bunyan.createLogger({ name: "sts_service_accounts",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("svc221-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                               .slice(0, 31);
const realmApi = base + "/realm/" + REALM + "/admin-api";
const OWNER = "svc221-owner-" + STAMP.toLowerCase();
const ACCOUNT = "svc221-acct-" + STAMP.toLowerCase();
const REFUSED = "svc221-refused-" + STAMP.toLowerCase();

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

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. a throwaway realm " + REALM + " ===");
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "Service accounts " + STAMP },
    "created the realm");
  await ok(realmApi + "/users/create", { username: OWNER, invent: "no",
    credential: "none" }, "created the owner");

  log.info("=== a. a refused owner creates nobody ===");
  const refused = await postJson(realmApi + "/users/create", {
    username: REFUSED, invent: "no", credential: "none",
    serviceAccount: true, owner: "nobody-" + STAMP.toLowerCase() });
  check("a service account whose owner is nobody is refused", function () {
    assert.ok(refused.status >= 400 && refused.status < 500,
              refused.status + " " + refused.raw.slice(0, 400));
  });
  const ghost = await send(realmApi + "/users?q=" +
                           encodeURIComponent(REFUSED));
  check("and nobody was left behind as an ordinary person", function () {
    assert.strictEqual(ghost.status, 200, ghost.raw.slice(0, 300));
    assert.ok(!(ghost.body.users || []).some(function (row) {
      return row.key === REFUSED;
    }), JSON.stringify(ghost.body.users));
  });

  log.info("=== b. a service account, tagged and filtered ===");
  const made = await ok(realmApi + "/users/create", { username: ACCOUNT,
    invent: "no", credential: "none", serviceAccount: true, owner: OWNER },
    "created the service account");
  check("the create says it made a service account", function () {
    assert.strictEqual(made.serviceAccount, true, JSON.stringify(made));
  });
  const services = await send(realmApi + "/users?kind=service");
  check("?kind=service lists it, tagged, and only service accounts",
        function () {
    const rows = services.body.users || [];
    assert.ok(rows.some(function (row) {
      return row.key === ACCOUNT && row.serviceAccount === true;
    }), JSON.stringify(rows));
    assert.ok(rows.every(function (row) {
      return row.serviceAccount === true;
    }), JSON.stringify(rows));
    assert.ok(services.body.serviceAccounts >= 1);
  });
  const people = await send(realmApi + "/users?kind=person");
  check("?kind=person leaves it out", function () {
    assert.ok(!(people.body.users || []).some(function (row) {
      return row.key === ACCOUNT;
    }));
  });

  log.info("=== c. its page ===");
  const page = await send(realmApi + "/users?user=" +
                          encodeURIComponent(ACCOUNT));
  check("its page describes it, with the policy's secure defaults",
        function () {
    const sa = page.body && page.body.serviceAccount;
    assert.ok(sa && /svc221-owner-/.test(sa.owner) &&
              sa.ownerKind === "person", JSON.stringify(sa));
    assert.strictEqual(sa.policy.allowBrowserSignIn, false);
    assert.strictEqual(sa.policy.exemptFromSecondFactor, false);
    assert.strictEqual(sa.rotation.enabled, false);
  });

  log.info("=== d. the third kind of policy ===");
  const policies = await send(realmApi + "/policies");
  check("/admin-api/policies holds the service-account policy", function () {
    assert.ok((policies.body.kinds || []).some(function (kind) {
      return kind.id === "serviceAccount";
    }), JSON.stringify(policies.body.kinds));
    assert.ok(policies.body.actions.indexOf(
      "save-serviceAccount-policy") >= 0);
  });
  const profile = Object.assign({}, policies.body.serviceAccount.profile);
  const fields = {};
  Object.keys(profile).forEach(function (key) {
    if (typeof profile[key] === "boolean" ||
        typeof profile[key] === "number") {
      fields[key] = profile[key];
    }
  });
  delete fields.stored;
  delete fields.inherited;
  delete fields.enforced;
  fields.allowWsTrust = false;
  await ok(realmApi + "/policies/save-serviceAccount-policy", fields,
           "saved the realm's service-account policy");
  const after = await send(realmApi + "/policies");
  check("the save is read back, stored in this realm", function () {
    const p = after.body.serviceAccount.profile;
    assert.strictEqual(p.allowWsTrust, false, JSON.stringify(p));
    assert.strictEqual(p.stored, true);
  });

  log.info("=== e. Rotate now, refused where it cannot push ===");
  const noDest = await postJson(realmApi + "/users/rotate-password",
                                { user: ACCOUNT });
  check("an account naming no destination is refused", function () {
    assert.ok(noDest.status >= 400 && noDest.status < 500,
              noDest.status + " " + noDest.raw.slice(0, 300));
  });
  const person = await postJson(realmApi + "/users/rotate-password",
                                { user: OWNER });
  check("and so is a person", function () {
    assert.ok(person.status >= 400 && person.status < 500,
              person.status + " " + person.raw.slice(0, 300));
  });

  log.info("=== f. Monitoring → Service accounts ===");
  const monitor = await send(realmApi + "/service-accounts");
  check("GET /admin-api/service-accounts lists it, with the rotation's " +
        "settings", function () {
    assert.strictEqual(monitor.status, 200, monitor.raw.slice(0, 300));
    assert.ok((monitor.body.accounts || []).some(function (row) {
      return row.username === ACCOUNT;
    }), JSON.stringify(monitor.body.accounts));
    assert.strictEqual(monitor.body.policy.rotationEnabled, false);
    assert.ok(monitor.body.paging, JSON.stringify(monitor.body));
  });

  log.info("=== g. an ordinary person again ===");
  await ok(realmApi + "/users/set-service-account", { user: ACCOUNT,
    serviceAccount: false }, "cleared the flag");
  const cleared = await send(realmApi + "/users?user=" +
                             encodeURIComponent(ACCOUNT));
  check("their page no longer describes a service account", function () {
    assert.strictEqual(cleared.body.serviceAccount, null,
                       JSON.stringify(cleared.body.serviceAccount));
  });

  log.info("Test completed successfully. " + checks + " check(s) passed.");
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error("sts_service_accounts FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
