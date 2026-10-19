// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// ===========================================================================
// sts_realm_count_limit.js — HOW MANY REALMS ONE CLUSTER MAY HOLD, OVER HTTP.
//
// realms.maxCount (#368) caps create. The default is 10, counting the
// built-in default realm, and a service administrator changes it only while
// the default realm is ambient. This job sets the cap to the live count, so
// the next create is refused whatever the stack already holds, then raises it
// by one and creates one realm. Lowering the cap does not remove realms. A
// POST of the cap under another realm's prefix is refused; the default
// realm's own row stays editable.
//
// The code is recorded and is not in the body. The refusal sentence is.
// The override is put back and the realm this job created is removed: a cap
// left at the accumulated count would refuse every later job's create.
// ===========================================================================

"use strict";

const assert = require("assert");
const { Command, Option } = require("commander");
const { runStamp } = require("./random_username.js");

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

const REALM = "rcl-" + runStamp();

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

async function test() {
  log.debug("Entering test().");
  log.info("Driving the realm cap at " + base + ".");
  const listed = await api("GET", "/admin-api/realms");
  assert.strictEqual(listed.status, 200, "GET /admin-api/realms answered " +
                     listed.status + " " + listed.text.slice(0, 300));
  const held = listed.body && listed.body.count;
  assert.ok(typeof held === "number" && held >= 1,
            "the realm count includes the default realm. Got " +
            JSON.stringify(listed.body && listed.body.count));

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

  let created = false;
  try {
    const capped = await api("POST", "/admin-api/config/set",
                             { key: "realms.maxCount", value: held });
    assert.strictEqual(capped.status, 200,
                       "setting the cap to the live count answered " +
                       capped.status + " " + capped.text.slice(0, 300));

    const beforeCode = await codeCount("STS-CORE-0161");
    const refused = await api("POST", "/admin-api/realms/create",
                              { id: REALM, name: "Over the cap" });
    assert.strictEqual(refused.status, 400,
                       "a create at the cap should be refused. Got " +
                       refused.status + " " + refused.text.slice(0, 400));
    const sentence = ((refused.body && refused.body.errors) || []).join(" ");
    assert.ok(sentence.indexOf("realms.maxCount") >= 0 &&
              sentence.indexOf(String(held)) >= 0,
              "the refusal names the limit and the live count. Got: " +
              sentence);
    assert.ok(!/STS-CORE-0161/.test(refused.text),
              "the code is recorded and is not in the body. Got: " +
              refused.text.slice(0, 400));
    const still = await api("GET", "/admin-api/realms");
    assert.strictEqual(still.body && still.body.count, held,
                       "a refused create adds no realm");
    assert.ok(await sawCode("STS-CORE-0161", beforeCode),
              "the refusal is recorded as STS-CORE-0161");

    const lowered = await api("POST", "/admin-api/config/set",
                              { key: "realms.maxCount", value: 1 });
    assert.strictEqual(lowered.status, 200,
                       "lowering the cap answered " + lowered.status + " " +
                       lowered.text.slice(0, 300));
    const afterLower = await api("GET", "/admin-api/realms");
    assert.strictEqual(afterLower.body && afterLower.body.count, held,
                       "lowering the cap removes nothing");
    const stillRefused = await api("POST", "/admin-api/realms/create",
                                   { id: REALM + "b", name: "Still over" });
    assert.strictEqual(stillRefused.status, 400,
                       "a create under the lowered cap is still refused");

    const raised = await api("POST", "/admin-api/config/set",
                             { key: "realms.maxCount", value: held + 1 });
    assert.strictEqual(raised.status, 200,
                       "raising the cap by one answered " + raised.status +
                       " " + raised.text.slice(0, 300));
    const made = await api("POST", "/admin-api/realms/create",
                           { id: REALM, name: "Under the cap",
                             domain: REALM + ".example.net" });
    assert.strictEqual(made.status, 200,
                       "a create under the new cap answered " + made.status +
                       " " + made.text.slice(0, 400));
    created = true;
    const after = await api("GET", "/admin-api/realms");
    assert.strictEqual(after.body && after.body.count, held + 1,
                       "the create is in the count");

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
                                { key: "realms.maxCount", value: held + 2 });
    assert.strictEqual(fromRealm.status, 400,
                       "setting the cap from inside the realm answered " +
                       fromRealm.status + " " + fromRealm.text.slice(0, 400));
    const lockedSentence = ((fromRealm.body && fromRealm.body.errors) || [])
      .join(" ");
    assert.ok(lockedSentence.indexOf("default realm") >= 0,
              "the refusal says the default realm. Got: " + lockedSentence);
    const unchanged = await api("GET", "/admin-api/config");
    const now = findSetting(unchanged.body, "realms.maxCount");
    assert.strictEqual(now && now.value, held + 1,
                       "the write from inside the realm did not change the " +
                       "cap");
    assert.strictEqual(now.editable, true,
                       "the default realm still offers the control");
    assert.strictEqual(now.editRefusal, undefined,
                       "the default realm still has no edit refusal");
  } finally {
    if (created) {
      const gone = await api("POST", "/admin-api/realms/remove",
                             { id: REALM });
      if (gone.status !== 200) {
        log.error("the realm " + REALM + " was not removed: " +
                  gone.status + " " + gone.text.slice(0, 300));
      }
    }
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
