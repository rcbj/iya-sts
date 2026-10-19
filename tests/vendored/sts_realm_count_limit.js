// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// ===========================================================================
// sts_realm_count_limit.js — HOW MANY REALMS ONE CLUSTER MAY HOLD, OVER HTTP.
//
// realms.maxCount (#368) caps create. The default is 10, counting the
// built-in default realm, and a service administrator changes it only while
// the default realm is ambient.
//
// EXCLUSIVE (tests/vendored/MANIFEST.js). The job holds the cap at the live
// count, so a parallel lane's realm create would be refused STS-CORE-0161
// for a reason that is not its own; and the count it reads must still be
// the count when the cap is set, which only an exclusive job can promise.
// The count is read again after every cap write and the job fails loudly if
// it moved.
//
// NO REALM IS REMOVED (tests/CLAUDE.md: no job removes a realm). The job
// raises the cap by one and creates ONE realm, which it LEAVES STANDING like
// every other job's realm — it is the realm the in-realm lock is asked
// under, and the successful create under the cap. Then it sets the cap to
// the new live count and proves the refusal twice, through `/admin-api` and
// through the console's own form (rule 7's parity), each recorded as
// STS-CORE-0161 and adding no realm. Lowering the cap removes nothing. A
// write of the cap under that realm's prefix is refused; the default realm's
// own row stays editable.
//
// The code is recorded and is not in the body. The refusal sentence is.
// The cap is ALWAYS put back (finally): left at the live count it would
// refuse every later job's create.
// ===========================================================================

"use strict";

const assert = require("assert");
const { Command, Option } = require("commander");
const { runStamp } = require("./random_username.js");
const consoleSignIn = require("./console_signin.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason tests/vendored/wait_for.js gives.
  appconfigProblem = e;
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_realm_count_limit",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");

const STAMP = runStamp();
const REALM = "rcl-" + STAMP;
// The console account this job signs in as; console_signin.js grants it
// both console roles, under a password only this process holds.
const CONSOLE_USER = "realm-count-test";

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

async function call(method, url, options) {
  log.debug("Entering call(). " + method + " " + url);
  const opts = Object.assign({ method: method, redirect: "manual" },
                             options || {});
  const r = await fetch(url, opts);
  const text = await r.text();
  let body = null;
  try {
    body = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
    // Not JSON — a page or an empty body. The text is kept; body stays null.
    body = null;
  }
  log.debug("Leaving call(). status=" + r.status);
  return { status: r.status, body: body, text: text };
}

async function api(method, path, payload) {
  log.debug("Entering api(). " + method + " " + path);
  const options = payload === undefined ? {}
    : { headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload) };
  const reply = await call(method, base + path, options);
  log.debug("Leaving api().");
  return reply;
}

function findSetting(body, key) {
  log.debug("Entering findSetting().");
  const groups = (body && body.groups) || [];
  let found = null;
  groups.forEach(function (group) {
    (group.settings || []).forEach(function (row) {
      if (row.key === key) {
        found = row;
      }
    });
  });
  log.debug("Leaving findSetting().");
  return found;
}

async function codeCount(code) {
  log.debug("Entering codeCount(). " + code);
  const reply = await api("GET", "/admin-api/audit?per=500&code=" +
                           encodeURIComponent(code));
  const body = reply.body && typeof reply.body === "object" ? reply.body
                                                             : {};
  const rows = body.events || body.rows || [];
  log.debug("Leaving codeCount(). " + rows.length);
  return rows.length;
}

async function sawCode(code, before) {
  log.debug("Entering sawCode(). " + code);
  let after = before;
  for (let i = 0; i < 20 && after <= before; i += 1) {
    await sleep(150);
    after = await codeCount(code);
  }
  log.debug("Leaving sawCode(). " + before + " -> " + after);
  return after > before;
}

// The live count, which must be a number that includes the default realm.
async function liveCount() {
  log.debug("Entering liveCount().");
  const listed = await api("GET", "/admin-api/realms");
  assert.strictEqual(listed.status, 200, "GET /admin-api/realms answered " +
                     listed.status + " " + listed.text.slice(0, 300));
  const held = listed.body && listed.body.count;
  assert.ok(typeof held === "number" && held >= 1,
            "the realm count includes the default realm. Got " +
            JSON.stringify(listed.body && listed.body.count));
  log.debug("Leaving liveCount(). " + held);
  return held;
}

// Sets the cap and reads the count again: nothing else runs while this job
// does (it is exclusive), so a count that moved is a broken manifest, and
// every assertion after it would be about somebody else's create.
async function capAt(value, expectedCount) {
  log.debug("Entering capAt(). " + value);
  const set = await api("POST", "/admin-api/config/set",
                        { key: "realms.maxCount", value: value });
  assert.strictEqual(set.status, 200, "setting realms.maxCount to " + value +
                     " answered " + set.status + " " +
                     set.text.slice(0, 300));
  const now = await liveCount();
  assert.strictEqual(now, expectedCount, "the realm count moved while the " +
                     "cap was being set (" + expectedCount + " -> " + now +
                     "): is this job still exclusive in MANIFEST.js?");
  log.debug("Leaving capAt().");
}

function refusalSentence(body) {
  log.debug("Entering refusalSentence().");
  const out = ((body && body.errors) || []).join(" ");
  log.debug("Leaving refusalSentence().");
  return out;
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving the realm cap at " + base + ".");
  const held = await liveCount();

  const configBefore = await api("GET", "/admin-api/config");
  assert.strictEqual(configBefore.status, 200,
                     "GET /admin-api/config answered " + configBefore.status);
  const before = findSetting(configBefore.body, "realms.maxCount");
  assert.ok(before, "GET /admin-api/config lists realms.maxCount");
  assert.strictEqual(before.default, 10, "the documented default is 10. " +
                     "Got " + JSON.stringify(before.default));
  assert.strictEqual(before.editable, true,
                     "the default realm offers the control");
  assert.strictEqual(before.editRefusal, undefined,
                     "the default realm has no edit refusal");

  const consoleClient = await consoleSignIn.signInToTheConsole(base,
    CONSOLE_USER, log, { grant: "write" });

  try {
    // ONE CREATE UNDER THE CAP, and the realm is left standing.
    await capAt(held + 1, held);
    const made = await api("POST", "/admin-api/realms/create",
                           { id: REALM, name: "Under the cap",
                             domain: REALM + ".example.net" });
    assert.strictEqual(made.status, 200,
                       "a create under the cap answered " + made.status +
                       " " + made.text.slice(0, 400));
    const atCap = await liveCount();
    assert.strictEqual(atCap, held + 1, "the create is in the count");

    // AT THE CAP: the next create is refused, through /admin-api ...
    await capAt(atCap, atCap);
    let codes = await codeCount("STS-CORE-0161");
    const refused = await api("POST", "/admin-api/realms/create",
                              { id: REALM + "-x", name: "Over the cap",
                                domain: REALM + "-x.example.net" });
    assert.strictEqual(refused.status, 400,
                       "a create at the cap should be refused. Got " +
                       refused.status + " " + refused.text.slice(0, 400));
    const sentence = refusalSentence(refused.body);
    assert.ok(sentence.indexOf("realms.maxCount") >= 0 &&
              sentence.indexOf(String(atCap)) >= 0,
              "the refusal names the limit and the live count. Got: " +
              sentence);
    assert.ok(!/STS-CORE-0161/.test(refused.text),
              "the code is recorded and is not in the body. Got: " +
              refused.text.slice(0, 400));
    assert.strictEqual(await liveCount(), atCap,
                       "a refused create adds no realm");
    assert.ok(await sawCode("STS-CORE-0161", codes),
              "the /admin-api refusal is recorded as STS-CORE-0161");

    // ... and through the console's own form (rule 7).
    codes = await codeCount("STS-CORE-0161");
    const fromConsole = await consoleClient.act("/admin/realms",
      { action: "create", id: REALM + "-c", name: "Over the cap",
        domain: REALM + "-c.example.net" });
    assert.strictEqual(fromConsole.status, 400,
                       "the console's create at the cap should be refused. " +
                       "Got " + fromConsole.status + " " +
                       String(fromConsole.text).slice(0, 400));
    const consoleSentence = refusalSentence(fromConsole.json);
    assert.ok(consoleSentence.indexOf("realms.maxCount") >= 0,
              "the console's refusal names the limit. Got: " +
              consoleSentence);
    assert.strictEqual(await liveCount(), atCap,
                       "a refused console create adds no realm");
    assert.ok(await sawCode("STS-CORE-0161", codes),
              "the console refusal is recorded as STS-CORE-0161");

    // LOWERING THE CAP REMOVES NOTHING, and still refuses.
    await capAt(1, atCap);
    const stillRefused = await api("POST", "/admin-api/realms/create",
                                   { id: REALM + "-y", name: "Still over",
                                     domain: REALM + "-y.example.net" });
    assert.strictEqual(stillRefused.status, 400,
                       "a create under the lowered cap is still refused");
    assert.strictEqual(await liveCount(), atCap,
                       "lowering the cap removes nothing");

    // THE CAP IS SET IN THE DEFAULT REALM ONLY.
    await capAt(atCap, atCap);
    const inside = await api("GET", "/realm/" + REALM + "/admin-api/config");
    assert.strictEqual(inside.status, 200,
                       "GET the cap from inside the realm answered " +
                       inside.status + " " + inside.text.slice(0, 300));
    const locked = findSetting(inside.body, "realms.maxCount");
    assert.ok(locked, "the realm's configuration lists the cap");
    assert.strictEqual(locked.editable, false,
                       "the control is disabled inside the realm");
    assert.ok(locked.editRefusal &&
              locked.editRefusal.indexOf("default realm") >= 0,
              "the row says the cap is set in the default realm. Got: " +
              JSON.stringify(locked.editRefusal));
    assert.strictEqual(locked.restartReason, undefined,
                       "the lock is not reported as a restart");

    const fromRealm = await api("POST", "/realm/" + REALM +
                                "/admin-api/config/set",
                                { key: "realms.maxCount", value: atCap + 5 });
    assert.strictEqual(fromRealm.status, 400,
                       "setting the cap from inside the realm answered " +
                       fromRealm.status + " " + fromRealm.text.slice(0, 400));
    assert.ok(refusalSentence(fromRealm.body).indexOf("default realm") >= 0,
              "the refusal says the default realm. Got: " +
              refusalSentence(fromRealm.body));
    const unchanged = await api("GET", "/admin-api/config");
    const now = findSetting(unchanged.body, "realms.maxCount");
    assert.strictEqual(now && now.value, atCap,
                       "the write from inside the realm did not change the " +
                       "cap");
    assert.strictEqual(now.editable, true,
                       "the default realm still offers the control");
    assert.strictEqual(now.editRefusal, undefined,
                       "the default realm still has no edit refusal");
  } finally {
    // ALWAYS put the cap back, whatever failed above. The realm this job
    // created stays: no job removes a realm (tests/CLAUDE.md).
    let restored;
    if (before && before.overridden) {
      restored = await api("POST", "/admin-api/config/set",
                           { key: "realms.maxCount", value: before.value });
    } else {
      restored = await api("POST", "/admin-api/config/reset",
                           { key: "realms.maxCount" });
    }
    if (restored.status !== 200) {
      log.error("realms.maxCount was not put back: " + restored.status +
                " " + restored.text.slice(0, 300));
      process.exitCode = 1;
    }
  }
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_realm_count_limit")
  .description("Drive the trust-realm cap: a create past realms.maxCount " +
      "is refused, lowering the cap removes nothing, and the cap can be " +
      "changed only in the default realm.")
  .addOption(new Option("-u, --url <url>", "base url of the STS under test")
      .default(base))
  .parse(process.argv);
base = String(program.opts().url || base).replace(/\/+$/, "");

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
