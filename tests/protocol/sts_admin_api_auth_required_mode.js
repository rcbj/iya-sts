// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_admin_api_auth_required_mode.js
//
// ===========================================================================
// `adminApi.authRequired=false` IS DEVELOPMENT MODE'S ALONE, AND THE
// DEFAULT REALM'S SERVICE TOKEN UNDER A REALM'S PREFIX IN PRODUCT (D12,
// #444), OVER HTTP.
//
// `adminApi.authRequired` is process-wide and `global.mode` of the DEFAULT
// realm is the service's, so this job changes both for a while and puts
// both back with `config/reset` in a `finally` — which is why it is
// `exclusive: true` in MANIFEST.js: every job running beside it would meet
// an open management API, or a service in product mode.
//
//   1. THE CONTROL: development with the setting off answers a caller with
//      no credential; `GET /admin-api/me` says nobody is calling, with
//      read and write; and an act then names nobody, on the HTTP row or on
//      the action's own (a group create).
//   2. A PRODUCT REALM, the `false` still stored process-wide: no credential
//      is 401, recorded STS-API-0001, the token gate's own refusal.
//   3. IN PRODUCT a console session is not this API's credential: an Admin
//      Write person's sign-on cookie, with no token, is 401 for a read and
//      a write (signed in while a fourth realm was in development, and the
//      realm switched to product behind them).
//   4. THERE, the row says `false` is stored, and `/admin-api/mode` lists
//      the management API's requirement, whose product reading says it is
//      ignored.
//   5. THERE, storing `false` is refused in a sentence naming product mode;
//      the default may still be written.
//   6. Back in a development realm, the stored `false` still opens the API,
//      so the product reading changed nothing.
//   7. THE DEFAULT REALM IN PRODUCT: a token the console holds for a
//      default-realm Admin Read person, whose `sub` is a `urn:uuid:` of the
//      default realm's directory, is still that person under a realm's
//      prefix (`/admin-api/me` answers them, not 403 STS-API-0125).
//
// D12 (#444): carries over tests/admin_api_auth_required_mode.js (1-6),
// tests/admin_api_actor.js (5, the control) and tests/admin_api_me.js (6
// and 8), so they stay covered when Rust replaces Node.
//
// OWNED HERE (local: true): this repository's own management API.
// ===========================================================================

const assert = require("assert");
const names = require("./random_username.js");
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
var log = bunyan.createLogger({ name: "sts_admin_api_auth_required_mode",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "");

function realmId(prefix) {
  log.debug("Entering realmId().");
  log.debug("Leaving realmId().");
  return (prefix + STAMP).slice(0, 31);
}

const DEV = realmId("arqd");
const PROD = realmId("arqp");
const OTHER = realmId("arqo");
const SWITCHED = realmId("arqs");
const WRITER = ("aw" + STAMP).slice(0, 30);
const READER = ("ar" + STAMP).slice(0, 30);

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
// bearer token. `cookie` is sent as it is.
async function call(method, url, token, payload, cookie) {
  log.debug("Entering call(). " + method + " " + url);
  const headers = { accept: "application/json" };
  if (token === null) {
    headers.authorization = "";
  } else if (typeof token === "string") {
    headers.authorization = "Bearer " + token;
  }
  if (cookie) {
    headers.cookie = cookie;
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

async function rows(realmBase, query) {
  log.debug("Entering rows().");
  const r = await call("GET", realmBase + "/admin-api/audit?per=500&" +
                       new URLSearchParams(query).toString());
  assert.strictEqual(r.status, 200, "GET audit answered " + r.status);
  log.debug("Leaving rows().");
  return (r.json && r.json.events) || [];
}

async function waitRows(realmBase, query, wanted) {
  log.debug("Entering waitRows().");
  let found = [];
  for (let i = 0; i < 20; i += 1) {
    found = (await rows(realmBase, query)).filter(wanted);
    if (found.length) {
      break;
    }
    await sleep(150);
  }
  log.debug("Leaving waitRows(). " + found.length);
  return found;
}

// The setting's row as a realm's `GET /admin-api/config` answers it.
async function settingRow(realmBase, key) {
  log.debug("Entering settingRow().");
  const r = await call("GET", realmBase + "/admin-api/config");
  assert.strictEqual(r.status, 200, r.text.slice(0, 200));
  let found = null;
  (function walk(x) {
    if (found || !x || typeof x !== "object") {
      return;
    }
    if (!Array.isArray(x) && x.key === key && "value" in x) {
      found = x;
      return;
    }
    Object.keys(x).forEach(function (k) {
      walk(x[k]);
    });
  })(r.json);
  log.debug("Leaving settingRow().");
  return found;
}

async function sections(ctx) {
  log.debug("Entering sections().");
  const devBase = ctx.devBase;
  const prodBase = ctx.prodBase;

  log.info("=== 1. the control: development with the setting off ===");
  await ok(base + "/admin-api/config/set",
           { key: "adminApi.authRequired", value: "false" },
           "turned the token requirement off");
  ctx.turnedOff = true;
  const open = await call("GET", devBase + "/admin-api/config", null);
  const me = await call("GET", devBase + "/admin-api/me", null);
  check("1a. a caller with no credential is answered 200", function () {
    assert.strictEqual(open.status, 200, open.text.slice(0, 300));
  });
  check("1b. /admin-api/me: no token required, no caller, read and write",
        function () {
    assert.strictEqual(me.status, 200, me.text.slice(0, 300));
    assert.strictEqual(me.json.tokenRequired, false);
    assert.ok(!me.json.caller, JSON.stringify(me.json.caller));
    assert.strictEqual(me.json.read, true);
    assert.strictEqual(me.json.write, true);
  });
  const group = "aq-" + STAMP.slice(0, 20);
  const made = await call("POST", devBase + "/admin-api/groups/create", null,
                          { group: group });
  const groupRows = await waitRows(devBase, { action: "group.create" },
    function (row) {
      return row.target.indexOf("cn=" + group + ",") === 0;
    });
  const httpRows = await waitRows(devBase, { action: "protocol.call" },
    function (row) {
      return /\/admin-api\/groups\/create$/.test(row.target);
    });
  check("1c. an act with no token names nobody, on the HTTP row or on the " +
        "action's own", function () {
    assert.strictEqual(made.status, 200, made.text.slice(0, 300));
    assert.ok(groupRows.length && groupRows[0].actor === "",
              JSON.stringify(groupRows[0] || {}).slice(0, 300));
    assert.ok(httpRows.length && httpRows.every(function (row) {
      return row.actor === "";
    }), JSON.stringify(httpRows.map(function (row) {
      return row.actor;
    })));
  });

  log.info("=== 2-5. a product realm, `false` still stored ===");
  const anonymous = await call("GET", prodBase + "/admin-api/config", null);
  const refused = await waitRows(prodBase, { code: "STS-API-0001" },
    function (row) {
      return /\/admin-api\/config$/.test(row.target);
    });
  check("2. no credential is 401, recorded STS-API-0001 and never sent",
        function () {
    assert.strictEqual(anonymous.status, 401, anonymous.text.slice(0, 300));
    assert.ok(/requires an OAuth 2\.0 access token/.test(errorsOf(anonymous)),
              errorsOf(anonymous));
    assert.ok(anonymous.text.indexOf("STS-API-0001") < 0, "the code was sent");
    assert.ok(refused.length > 0, "no STS-API-0001 row");
  });

  // The person signs in while their realm is still in development (product
  // requires a second factor of everybody, which a scripted sign-in does
  // not hold), and the realm is switched to product behind them.
  const switchBase = ctx.switchBase;
  const writer = await consoleSignIn.signInToTheConsole(switchBase, WRITER,
    log, { grant: "write" });
  await ok(switchBase + "/admin-api/config/set",
           { key: "global.mode", value: "product" },
           "switched " + SWITCHED + " to product behind the session");
  const byToken = await writer.api("GET", "/admin-api/config");
  const cookieRead = await call("GET", switchBase + "/admin-api/config", null,
                                undefined, writer.cookie);
  const cookieWrite = await call("POST", switchBase + "/admin-api/groups/" +
    "create", null, { group: group + "-c" }, writer.cookie);
  check("3. the Admin Write person's token reads; their sign-on session " +
        "alone is 401 for a read and for a write", function () {
    assert.strictEqual(byToken.status, 200, byToken.text.slice(0, 300));
    assert.ok(/sts_session=/.test(writer.cookie), writer.cookie);
    assert.strictEqual(cookieRead.status, 401, cookieRead.text.slice(0, 300));
    assert.strictEqual(cookieWrite.status, 401,
                       cookieWrite.text.slice(0, 300));
  });

  const row = await settingRow(prodBase, "adminApi.authRequired");
  const mode = await call("GET", prodBase + "/admin-api/mode");
  const requirement = ((mode.json && mode.json.requirements) || [])
    .filter(function (one) {
      return one.id === "management-api";
    })[0];
  check("4. the row says `false` is stored, and /admin-api/mode's " +
        "management API requirement says product ignores it", function () {
    assert.ok(row && row.value === false && row.default === true,
              JSON.stringify(row));
    assert.strictEqual(mode.status, 200, mode.text.slice(0, 200));
    assert.strictEqual(mode.json.isProduct, true);
    assert.ok(requirement && /ignored where it is stored/
      .test(requirement.inForce), JSON.stringify(requirement));
  });

  const store = await call("POST", prodBase + "/admin-api/config/set",
    undefined, { key: "adminApi.authRequired", value: "false" });
  check("5a. storing `false` in the product realm is refused, in a " +
        "sentence naming product mode", function () {
    assert.strictEqual(store.status, 400, store.text.slice(0, 300));
    assert.ok(/cannot be turned off here: this realm is in product mode/
      .test(errorsOf(store)), errorsOf(store));
  });
  const dflt = await call("POST", base + "/admin-api/config/set", undefined,
    { key: "adminApi.authRequired", value: "true" });
  check("5b. the default may still be written", function () {
    assert.ok(dflt.status === 200 && dflt.json.ok === true,
              dflt.text.slice(0, 300));
  });
  await ok(base + "/admin-api/config/set",
           { key: "adminApi.authRequired", value: "false" },
           "turned the token requirement off again");

  log.info("=== 6. back in development ===");
  const again = await call("GET", devBase + "/admin-api/config", null);
  check("6. the stored `false` still opens a development realm's API",
        function () {
    assert.strictEqual(again.status, 200, again.text.slice(0, 300));
  });
  await call("POST", base + "/admin-api/config/reset", undefined,
             { key: "adminApi.authRequired" });
  ctx.turnedOff = false;
  const closed = await call("GET", devBase + "/admin-api/config", null);
  assert.strictEqual(closed.status, 401, "after the reset the API should " +
                     "require a token again; it answered " + closed.status);
  log.debug("Leaving sections().");
}

async function serviceTokenInRealm(ctx) {
  log.debug("Entering serviceTokenInRealm().");
  log.info("=== 7. the default realm in product: its token under a realm ===");
  const reader = await consoleSignIn.signInToTheConsole(base, READER, log,
    { grant: "read" });
  const claims = JSON.parse(Buffer.from(String(reader.token).split(".")[1],
                                        "base64url").toString("utf8"));
  check("7a. precondition: the console's token names the default-realm " +
        "person by a urn:uuid subject", function () {
    assert.ok(/^urn:uuid:/.test(String(claims.sub)), JSON.stringify(claims));
  });
  await ok(base + "/admin-api/config/set",
           { key: "global.mode", value: "product" },
           "switched the default realm to product");
  ctx.productDefault = true;
  const there = await reader.api("GET", ctx.otherBase + "/admin-api/me");
  check("7b. under another realm's prefix it is still that person, the " +
        "service authority, reading", function () {
    assert.strictEqual(there.status, 200, there.text.slice(0, 300));
    assert.strictEqual(there.json.caller.kind, "person");
    assert.strictEqual(there.json.caller.name, READER);
    assert.strictEqual(there.json.authority, "service");
    assert.strictEqual(there.json.read, true);
  });
  log.debug("Leaving serviceTokenInRealm().");
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. throwaway realms " +
           [DEV, PROD, OTHER, SWITCHED].join(", ") + " ===");
  for (const id of [DEV, PROD, OTHER, SWITCHED]) {
    await ok(base + "/admin-api/realms/create", { id: id,
      domain: id + ".example.net", name: "authRequired " + STAMP },
      "created the realm " + id);
  }
  const ctx = { devBase: base + "/realm/" + DEV,
                prodBase: base + "/realm/" + PROD,
                otherBase: base + "/realm/" + OTHER,
                switchBase: base + "/realm/" + SWITCHED,
                turnedOff: false, productDefault: false };
  await ok(ctx.prodBase + "/admin-api/config/set",
           { key: "global.mode", value: "product" },
           "switched " + PROD + " to product");
  try {
    await sections(ctx);
    await serviceTokenInRealm(ctx);
  } finally {
    // RESTORED WITH `reset`, never by writing the old value back
    // (tests/CLAUDE.md), whatever happened above.
    if (ctx.productDefault) {
      await call("POST", base + "/admin-api/config/reset", undefined,
                 { key: "global.mode" });
    }
    if (ctx.turnedOff) {
      await call("POST", base + "/admin-api/config/reset", undefined,
                 { key: "adminApi.authRequired" });
    }
  }
  const mode = await call("GET", base + "/admin-api/mode");
  assert.ok(mode.status === 200 && mode.json.isProduct === false,
            "the default realm should be back in development: " +
            mode.text.slice(0, 200));
  assert.ok(checks >= 11, "only " + checks + " checks ran");
  log.info(checks + " checks passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
