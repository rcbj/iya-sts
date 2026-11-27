// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_admin_device_requirement.js
//
// ===========================================================================
// THE ADMINISTRATIVE SURFACE NEEDS A COMPLIANT REGISTERED DEVICE (#2179,
// ASVS 5.0.0 8.4.2), END TO END OVER HTTP.
//
// Every suite stack runs with `devices.requireCompliantDeviceForAdmin=off`
// (docker-compose-run-tests.yml, rcbj's decision of 2026-11-24): on, the
// first console sign-in from a compliant device would arm the realm and
// refuse every browser-driven console job after it. THIS is the one job that
// turns it on, in a throwaway realm of its own, and signs in as the console
// does — the HTTP helper (`console_signin.js`), whose DPoP key is registered
// as the account's device and marked compliant by the deployment's
// management credential (this run's program token), never a browser.
//
// THE REALM IS IN DEVELOPMENT MODE WITH THE SETTING `on`, not in product
// with `auto`: product requires a second factor of every sign-in, which a
// scripted sign-in does not hold (sts_admin_api_auth_required_mode.js's
// reason), and `on` is the same rule `auto` resolves to in product — what
// `auto` resolves to in each mode is held in process
// (tests/admin_device_requirement.js A1).
//
//   1. IN FORCE, NOT ARMED: Directory → Devices says so; an administrator
//      with NO device is admitted to the console — a realm with no
//      compliant device is never locked out — and that does not arm it.
//   2. ARMING: a roster member signing in from their own compliant device
//      is admitted, and the realm is armed.
//   3. ARMED REFUSALS: an administrator with no device, and one whose
//      device was reported non-compliant, are refused at the token endpoint
//      with access_denied and the sentence; each is recorded STS-DEVICE-0054
//      and the code is never sent.
//   4. ADMISSION: the compliant administrator reads /admin-api with the
//      console's token, and the refresh grant renews it.
//   5. PROGRAMS: the management credential is not asked — its calls into the
//      armed realm are answered, and a client-credentials token for the
//      management API is issued where the realm's client secret is the
//      run's.
//   6. RECOVERY BY A PROGRAM: the program marks the device compliant again
//      and that administrator signs in; the program sets the requirement
//      `off` and the administrator with no device signs in.
//
// Its realm is REMOVED WHEN THE JOB PASSES and left standing when it fails,
// so a failure can be read (rcbj, 2026-11-18).
//
// OWNED HERE (local: true): this repository's policy, console and API.
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
var log = bunyan.createLogger({ name: "sts_admin_device_requirement",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "");
const REALM = ("adrq" + STAMP).slice(0, 31);
const REALM_BASE = base + "/realm/" + REALM;
const SETTING = "devices.requireCompliantDeviceForAdmin";
// The four administrators, each a console Admin Write member of the realm's
// roster: one signs in with no device before the realm is armed, one arms
// it, one has no device once it is, and one has a device reported
// non-compliant.
const EARLY = ("ade" + STAMP).slice(0, 30);
const ARMER = ("ada" + STAMP).slice(0, 30);
const BARE = ("adb" + STAMP).slice(0, 30);
const LAPSED = ("adl" + STAMP).slice(0, 30);
const SENTENCE = "The admin console requires a compliant registered device.";

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

// One call as the run's management credential (the preload attaches the
// program token to every request that names none).
async function call(method, url, payload) {
  log.debug("Entering call(). " + method + " " + url);
  const headers = { accept: "application/json" };
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
  return { status: r.status, json: json, text: text };
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await call("POST", url, payload);
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + r.text.slice(0, 400));
  log.debug("Leaving ok().");
  return r.json;
}

// The realm's state as Directory → Devices draws it.
async function adminDevice() {
  log.debug("Entering adminDevice().");
  const r = await call("GET", REALM_BASE + "/admin-api/device-registration");
  assert.strictEqual(r.status, 200, r.text.slice(0, 300));
  const state = r.json && r.json.decisions && r.json.decisions.adminDevice;
  assert.ok(state, "GET /admin-api/device-registration carries no " +
            "decisions.adminDevice: " + r.text.slice(0, 300));
  log.debug("Leaving adminDevice().");
  return state;
}

// A console sign-in that is EXPECTED to be refused at the token endpoint:
// the helper asserts the token, so its assertion carries the endpoint's
// answer (status and body), which is what is read here.
async function refusedSignIn(user, options) {
  log.debug("Entering refusedSignIn(). " + user);
  let refusal = null;
  try {
    await consoleSignIn.signInToTheConsole(REALM_BASE, user, log,
      Object.assign({ grant: "write" }, options || {}));
  } catch (e) {
    log.debug("Caught in refusedSignIn(): " + ((e && e.message) || e));
    refusal = String((e && e.message) || e);
  }
  log.debug("Leaving refusedSignIn(). " + (refusal ? "Refused." : "Admitted."));
  return refusal;
}

async function codeRows() {
  log.debug("Entering codeRows().");
  let found = [];
  for (let i = 0; i < 20; i += 1) {
    const r = await call("GET", REALM_BASE + "/admin-api/audit?per=500&" +
                         "code=STS-DEVICE-0054");
    assert.strictEqual(r.status, 200, "GET audit answered " + r.status);
    found = (r.json && r.json.events) || [];
    if (found.length >= 2) {
      break;
    }
    await sleep(150);
  }
  log.debug("Leaving codeRows(). " + found.length);
  return found;
}

// The management API's client, for a client-credentials token in the realm:
// the run's pinned secret, where the launcher handed it over.
function programSecret() {
  log.debug("Entering programSecret().");
  log.debug("Leaving programSecret().");
  return process.env.STS_ADMIN_API_CLIENT_SECRET ||
    process.env.ADMIN_API_CLIENT_SECRET || "";
}

async function unarmed() {
  log.debug("Entering unarmed().");
  log.info("=== 1. in force, not armed ===");
  const before = await adminDevice();
  check("1a. Directory → Devices: the requirement is in force in this " +
        "realm and not yet armed", function () {
    assert.strictEqual(before.setting, SETTING);
    assert.strictEqual(before.value, "on", JSON.stringify(before));
    assert.strictEqual(before.inForce, true, JSON.stringify(before));
    assert.strictEqual(before.armed, false, JSON.stringify(before));
  });
  const early = await consoleSignIn.signInToTheConsole(REALM_BASE, EARLY,
    log, { grant: "write", noDevice: true });
  const me = await early.api("GET", "/admin-api/me");
  const after = await adminDevice();
  check("1b. an administrator with NO registered device is admitted to " +
        "the console, and that does not arm the realm", function () {
    assert.strictEqual(me.status, 200, me.text.slice(0, 300));
    assert.strictEqual(after.armed, false, JSON.stringify(after));
  });
  log.debug("Leaving unarmed().");
}

async function arming() {
  log.debug("Entering arming().");
  log.info("=== 2. arming on first proof ===");
  const armer = await consoleSignIn.signInToTheConsole(REALM_BASE, ARMER,
    log, { grant: "write" });
  const state = await adminDevice();
  check("2. a roster member signing in from their own compliant device is " +
        "admitted, and arms the realm", function () {
    assert.ok(consoleSignIn.deviceOf(ARMER), "no device was registered");
    assert.ok(armer.token, "no token");
    assert.strictEqual(state.armed, true, JSON.stringify(state));
    assert.ok(/^\d{4}-\d\d-\d\dT/.test(String(state.armedAt)),
              JSON.stringify(state));
  });
  log.debug("Leaving arming().");
  return armer;
}

async function refusals() {
  log.debug("Entering refusals().");
  log.info("=== 3. armed refusals ===");
  const bare = await refusedSignIn(BARE, { noDevice: true });
  check("3a. an administrator with no registered device is refused at the " +
        "token endpoint: access_denied, and the sentence", function () {
    assert.ok(bare, "the sign-in was admitted");
    assert.ok(/access_denied/.test(bare), bare);
    assert.ok(bare.indexOf(SENTENCE) >= 0, bare);
  });
  // LAPSED signs in first, from a compliant device, and is admitted; the
  // device management then reports it non-compliant.
  const lapsed = await consoleSignIn.signInToTheConsole(REALM_BASE, LAPSED,
    log, { grant: "write" });
  assert.ok(lapsed.token, "LAPSED should have signed in first");
  const device = consoleSignIn.deviceOf(LAPSED);
  await ok(REALM_BASE + "/admin-api/devices/set-compliance",
           { id: device, status: "not-compliant",
             reason: "sts_admin_device_requirement: the MDM's report" },
           "reported " + LAPSED + "'s device non-compliant");
  const renewed = await lapsed.refresh();
  const again = await refusedSignIn(LAPSED);
  check("3b. once the device is reported non-compliant, the refresh grant " +
        "and a new sign-in are both refused, with the sentence", function () {
    assert.strictEqual(renewed.status, 400,
                       JSON.stringify(renewed.json || {}).slice(0, 300));
    assert.strictEqual((renewed.json || {}).error, "access_denied",
                       JSON.stringify(renewed.json));
    assert.ok(String((renewed.json || {}).error_description || "")
      .indexOf(SENTENCE) === 0, JSON.stringify(renewed.json));
    assert.ok(again && /access_denied/.test(again) &&
              again.indexOf(SENTENCE) >= 0, again);
  });
  const rows = await codeRows();
  check("3c. each refusal is recorded STS-DEVICE-0054, and the code is " +
        "never sent", function () {
    assert.ok(rows.length >= 2, rows.length + " rows");
    assert.ok(bare.indexOf("STS-DEVICE-0054") < 0, "the code was sent");
    assert.ok(JSON.stringify(renewed.json || {})
      .indexOf("STS-DEVICE-0054") < 0, "the code was sent");
  });
  log.debug("Leaving refusals().");
}

async function admitted(armer) {
  log.debug("Entering admitted().");
  log.info("=== 4. the compliant administrator ===");
  const me = await armer.api("GET", "/admin-api/me");
  const renewed = await armer.refresh();
  const after = await armer.api("GET", "/admin-api/me");
  check("4. the compliant administrator reads /admin-api with the " +
        "console's token, and the refresh grant renews it", function () {
    assert.strictEqual(me.status, 200, me.text.slice(0, 300));
    assert.strictEqual(renewed.status, 200,
                       JSON.stringify(renewed.json || {}).slice(0, 300));
    assert.strictEqual(after.status, 200, after.text.slice(0, 300));
  });
  log.debug("Leaving admitted().");
}

async function programs() {
  log.debug("Entering programs().");
  log.info("=== 5. programs ===");
  const listed = await call("GET", REALM_BASE + "/admin-api/devices?per=10");
  check("5a. the management credential's calls into the armed realm are " +
        "answered", function () {
    assert.strictEqual(listed.status, 200, listed.text.slice(0, 300));
  });
  const secret = programSecret();
  if (!secret) {
    log.info("  no management client secret was handed to this job; 5b " +
             "is not asked.");
    log.debug("Leaving programs(). No secret.");
    return;
  }
  const tokenUrl = REALM_BASE + "/oauth2/token";
  const r = await fetch(tokenUrl, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded",
               authorization: "Basic " + Buffer.from("sts-api-client:" +
                 secret).toString("base64") },
    body: new URLSearchParams({ grant_type: "client_credentials",
      scope: "admin:read", resource: REALM_BASE + "/admin-api" }).toString()
  });
  const answer = await r.json().catch(function () {
    return {};
  });
  if (r.status === 401) {
    // The realm's own management client holds a secret other than the run's;
    // 5a is the evidence that the program is not asked.
    log.info("  the realm's sts-api-client does not hold the run's secret " +
             "(401); 5b is not asked.");
    log.debug("Leaving programs(). Another secret.");
    return;
  }
  check("5b. a client-credentials token for the management API is issued " +
        "in the armed realm: a program is never asked about a device",
        function () {
    assert.strictEqual(r.status, 200, JSON.stringify(answer).slice(0, 300));
    assert.ok(answer.access_token, JSON.stringify(answer).slice(0, 300));
  });
  log.debug("Leaving programs().");
}

async function recovery() {
  log.debug("Entering recovery().");
  log.info("=== 6. recovery by a program ===");
  await ok(REALM_BASE + "/admin-api/devices/set-compliance",
           { id: consoleSignIn.deviceOf(LAPSED), status: "compliant",
             reason: "sts_admin_device_requirement: recovered" },
           "marked " + LAPSED + "'s device compliant again");
  const back = await consoleSignIn.signInToTheConsole(REALM_BASE, LAPSED,
    log, { grant: "write" });
  const me = await back.api("GET", "/admin-api/me");
  check("6a. the program marks the device compliant again, and that " +
        "administrator signs in", function () {
    assert.strictEqual(me.status, 200, me.text.slice(0, 300));
  });
  await ok(REALM_BASE + "/admin-api/config/set",
           { key: SETTING, value: "off" },
           "set the requirement off in " + REALM);
  const bare = await consoleSignIn.signInToTheConsole(REALM_BASE, BARE, log,
    { grant: "write", noDevice: true });
  const bareMe = await bare.api("GET", "/admin-api/me");
  const state = await adminDevice();
  check("6b. the program sets the requirement off, and the administrator " +
        "with no device signs in; the realm stays armed", function () {
    assert.strictEqual(bareMe.status, 200, bareMe.text.slice(0, 300));
    assert.strictEqual(state.inForce, false, JSON.stringify(state));
    assert.strictEqual(state.armed, true, JSON.stringify(state));
  });
  log.debug("Leaving recovery().");
}

// THE REALM IS REMOVED WHEN THE JOB PASSED, and left standing when it failed
// so whoever reads the failure can look at it.
async function removeRealm() {
  log.debug("Entering removeRealm().");
  try {
    const r = await call("POST", base + "/admin-api/realms/remove",
                         { id: REALM });
    log.info("removed the realm " + REALM + ": " + r.status);
  } catch (e) {
    log.debug("Caught in removeRealm(): " + ((e && e.message) || e));
    // A realm left behind is litter, not a failure of what was tested.
    log.info("could not remove the realm " + REALM);
  }
  log.debug("Leaving removeRealm().");
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. the throwaway realm " + REALM + " ===");
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "Admin device " + STAMP,
    overrides: { "global.mode": "development" } },
    "created the realm " + REALM);
  await ok(REALM_BASE + "/admin-api/config/set",
           { key: SETTING, value: "on" },
           "turned the requirement on in " + REALM + " only");
  await unarmed();
  const armer = await arming();
  await refusals();
  await admitted(armer);
  await programs();
  await recovery();
  assert.ok(checks >= 10, "only " + checks + " checks ran");
  log.info(checks + " checks passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

test().then(function () {
  return removeRealm();
}, function (e) {
  log.error(e.stack || e.message);
  log.info("the realm " + REALM + " is left standing for the failure.");
  process.exit(1);
});
