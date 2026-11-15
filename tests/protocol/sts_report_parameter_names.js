// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_report_parameter_names.js
//
// ---------------------------------------------------------------------------
// A SAVED PARAMETER'S NAME IS 1 TO 64 CHARACTERS, OVER THE WIRE (#1579).
//
// D12 (#444): carries over `tests/report_parameter_names.js`. In a throwaway
// realm, a person in `report-users` signs in as the reporting application's
// public client (`report_signin.js`: PKCE, a DPoP-bound `report:use` token
// for the realm's `/report-api`), and every call below is that token with a
// fresh proof:
//
//   A. a definition whose parameters name a 65-character name, or an empty
//      one, is refused 400 invalid_query "Parameters are names and
//      values." (STS-REPORT-0004 off the audit log); 64 characters is kept;
//      changing a definition that way is refused and the stored one keeps
//      what it had;
//   B. WHERE IN THE ORDER IT IS ASKED: a definition that does not exist is
//      404 first, a schedule that is not cron and a document naming no
//      source are answered for themselves, a nested value is refused for
//      the parameters;
//   C. a run's parameters are held to the same bound (65 and empty
//      refused, 64 accepted 202), a filter's `param` of 65 characters is
//      refused when saved (STS-REPORT-0030) and 64 is saved and runs, and
//      33 parameters are still refused.
//
// NOT carried, and why: D, a definition STORED before the bound whose
// filter names 65 characters — no door writes one, so it exists only where
// a test edits the definition store (class (d)).
//
// OWNED HERE (local: true): this repository's own reports API.
// ---------------------------------------------------------------------------

const assert = require("assert");
const names = require("./random_username.js");
const reportSignin = require("./report_signin.js");

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
var log = bunyan.createLogger({ name: "sts_report_parameter_names",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "")
  .slice(-10);
const REALM = "rpn-" + STAMP;
const RB = base + "/realm/" + REALM;
const OWNER = "rpn-owner-" + STAMP;
const PASSWORD = "Rpn-" + STAMP + "-Aa1!-pass";

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
  return { status: r.status, body: body, raw: raw, headers: r.headers };
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

// One call to the realm's /report-api with the session's DPoP-bound token
// and a fresh proof, retried once on a nonce the resource server asks for.
async function api(session, method, path, body) {
  log.debug("Entering api(). " + method + " " + path);
  const url = RB + "/report-api" + path;
  let r = null;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const headers = { Accept: "application/json",
      Authorization: "DPoP " + session.token,
      DPoP: session.key.proof(method, url, session.token) };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
    }
    const raw = await fetch(url, { method: method, headers: headers,
      body: body === undefined ? undefined : JSON.stringify(body) });
    session.key.keepNonce(raw);
    const text = await raw.text();
    let json = null;
    try {
      json = JSON.parse(text);
    } catch (e) {
      log.debug("Caught in api(): " + ((e && e.message) || e));
      // Not JSON; the caller reads `text`.
      json = null;
    }
    r = { status: raw.status, text: text, json: json };
    if (!(raw.status === 401 && /use_dpop_nonce/.test(
      String(raw.headers.get("www-authenticate") || "") + text))) {
      break;
    }
  }
  log.debug("Leaving api(). " + r.status);
  return r;
}

function brief(r) {
  log.debug("Entering brief().");
  log.debug("Leaving brief().");
  return r.status + " " + String(r.text || r.raw || "").slice(0, 300);
}

async function codeCount(code) {
  log.debug("Entering codeCount(). " + code);
  const r = await send(RB + "/admin-api/audit?per=500&code=" +
                       encodeURIComponent(code));
  log.debug("Leaving codeCount().");
  return Number((r.body && r.body.matched) || 0);
}

async function codesSettle(code, atLeast) {
  log.debug("Entering codesSettle(). " + code);
  let n = await codeCount(code);
  for (let i = 0; i < 20 && n < atLeast; i += 1) {
    await sleep(150);
    n = await codeCount(code);
  }
  log.debug("Leaving codesSettle(). " + n);
  return n;
}

async function test() {
  log.debug("Entering test().");
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "Report parameters " + STAMP },
    "created the realm");
  await ok(RB + "/admin-api/users/create", { username: OWNER, invent: false,
    attributes: { cn: "Owner " + STAMP, givenName: "Owner", sn: STAMP,
                  mail: OWNER + "@" + REALM + ".example.net" },
    credential: "password", password: PASSWORD }, "created the owner");
  await ok(RB + "/admin-api/groups/add-member", { group: "report-users",
    member: OWNER }, "put the owner in report-users");
  const session = await reportSignin.signInToReport(RB, OWNER, null,
    { password: PASSWORD });

  const NAMES = JSON.stringify({ error: "invalid_query",
    error_description: "Parameters are names and values." });
  const PARAM = JSON.stringify({ error: "invalid_query",
    error_description: "A parameter name is a string of 1 to 64 " +
      "characters." });
  const N64 = "p".repeat(64);
  const N65 = "p".repeat(65);
  const document = { source: "users", select: ["username"], limit: 3 };
  const define = function (payload) {
    return api(session, "POST", "/definitions", payload);
  };
  const run = function (id, payload) {
    return api(session, "POST", "/definitions/" + id + "/run", payload);
  };
  const before0004 = await codeCount("STS-REPORT-0004");
  const before0030 = await codeCount("STS-REPORT-0030");

  log.info("=== A. the bound ===");
  const a1 = await define({ name: "sixty-five", document: document,
                            parameters: { [N65]: 1 } });
  const a2 = await define({ name: "empty", document: document,
                            parameters: { "": 1 } });
  const a3 = await define({ name: "sixty-four", document: document,
                            parameters: { [N64]: 1, b: "x" } });
  check("A1. a 65-character parameter name is refused 400 invalid_query, " +
        "\"Parameters are names and values.\"", function () {
    assert.strictEqual(a1.text, NAMES, brief(a1));
    assert.strictEqual(a1.status, 400);
  });
  check("A2. an empty parameter name is refused the same way", function () {
    assert.strictEqual(a2.status, 400, brief(a2));
    assert.strictEqual(a2.text, NAMES);
  });
  const kept = a3.json && a3.json.definition;
  check("A3. a 64-character parameter name is kept", function () {
    assert.strictEqual(a3.status, 200, brief(a3));
    assert.strictEqual(kept.parameters[N64], 1);
    assert.strictEqual(kept.parameters.b, "x");
  });
  const id = kept.id;
  const a4 = await api(session, "POST", "/definitions/" + id,
    { name: "sixty-four", document: document, parameters: { [N65]: 1 } });
  check("A4. changing a definition to a 65-character name is refused the " +
        "same way", function () {
    assert.strictEqual(a4.status, 400, brief(a4));
    assert.strictEqual(a4.text, NAMES);
  });
  const a5 = await api(session, "GET", "/definitions/" + id);
  check("A5. and the stored definition keeps what it had", function () {
    assert.strictEqual(a5.status, 200, brief(a5));
    assert.strictEqual(a5.json.definition.parameters[N64], 1);
    assert.ok(!(N65 in a5.json.definition.parameters), brief(a5));
  });

  log.info("=== B. where in the order ===");
  const b1 = await api(session, "POST", "/definitions/nope",
    { name: "x", document: document, parameters: { [N65]: 1 } });
  check("B1. a definition that does not exist is 404 first", function () {
    assert.strictEqual(b1.status, 404, brief(b1));
    assert.strictEqual(b1.text, JSON.stringify({ error: "not_found",
      error_description: "No such definition." }));
  });
  const b2 = await define({ name: "cron", document: document,
                            schedule: "not cron", parameters: { [N65]: 1 } });
  check("B2. a schedule that is not cron is answered for the schedule",
        function () {
    assert.strictEqual(b2.status, 400, brief(b2));
    assert.strictEqual(b2.text, JSON.stringify({ error: "invalid_query",
      error_description: "The schedule is not a UTC cron expression." }));
  });
  const b3 = await define({ name: "source", document: { source: "nope" },
                            parameters: { [N65]: 1 } });
  check("B3. a document naming no source is answered for the document",
        function () {
    assert.strictEqual(b3.status, 400, brief(b3));
    assert.strictEqual(b3.text, JSON.stringify({ error: "unknown_source",
      error_description: "No such source." }));
  });
  const b4 = await define({ name: "value", document: document,
                            parameters: { [N65]: { nested: true } } });
  check("B4. a value the bag cannot hold beside the name is refused for " +
        "the parameters", function () {
    assert.strictEqual(b4.status, 400, brief(b4));
    assert.strictEqual(b4.text, NAMES);
  });

  log.info("=== C. a run, and a filter's param ===");
  const c1 = await run(id, { [N65]: 1 });
  const c2 = await run(id, { "": 1 });
  const c2a = await run(id, { [N64]: 2 });
  check("C1. a run naming a 65-character parameter is refused 400 " +
        "invalid_query, \"Parameters are names and values.\"", function () {
    assert.strictEqual(c1.status, 400, brief(c1));
    assert.strictEqual(c1.text, NAMES);
  });
  check("C2. and so is one naming an empty one", function () {
    assert.strictEqual(c2.status, 400, brief(c2));
    assert.strictEqual(c2.text, NAMES);
  });
  check("C2a. a run naming a 64-character parameter is accepted 202",
        function () {
    assert.strictEqual(c2a.status, 202, brief(c2a));
  });
  const c3 = await define({ name: "filtered", document: Object.assign({},
    document, { where: { op: "eq", field: "username", param: N65 } }) });
  check("C3. a filter naming a 65-character parameter is refused when " +
        "saved, \"A parameter name is a string of 1 to 64 characters.\"",
        function () {
    assert.strictEqual(c3.status, 400, brief(c3));
    assert.strictEqual(c3.text, PARAM);
  });
  const c3a = await define({ name: "filtered64", document: Object.assign({},
    document, { where: { op: "eq", field: "username", param: N64 } }) });
  check("C3a. a filter naming a 64-character parameter is saved",
        function () {
    assert.strictEqual(c3a.status, 200, brief(c3a));
    assert.ok(c3a.json.definition && c3a.json.definition.id, brief(c3a));
  });
  const c4 = await run(c3a.json.definition.id, { [N64]: OWNER });
  check("C4. and the definition runs with it", function () {
    assert.strictEqual(c4.status, 202, brief(c4));
  });
  const many = {};
  for (let i = 0; i < 33; i += 1) {
    many["p" + i] = i;
  }
  const c5 = await run(id, many);
  check("C5. a run naming 33 parameters is still refused", function () {
    assert.strictEqual(c5.status, 400, brief(c5));
    assert.strictEqual(c5.text, NAMES);
  });

  log.info("=== the codes, off the audit log ===");
  const after0004 = await codesSettle("STS-REPORT-0004", before0004 + 3);
  const after0030 = await codesSettle("STS-REPORT-0030", before0030 + 5);
  check("a refused RUN is recorded STS-REPORT-0004 (C1, C2, C5) and a " +
        "refused SAVE STS-REPORT-0030 (A1, A2, A4, B4, C3), and no answer " +
        "names a code", function () {
    assert.ok(after0004 - before0004 >= 3, "0004: " + before0004 + " -> " +
              after0004);
    assert.ok(after0030 - before0030 >= 5, "0030: " + before0030 + " -> " +
              after0030);
    [a1, a2, a4, b1, b2, b3, b4, c1, c2, c3, c5].forEach(function (r) {
      assert.ok(!/STS-[A-Z]+-\d{4}/.test(r.text), brief(r));
    });
  });
  log.debug("Leaving test().");
}

// REMOVAL IS OPT-IN: with STS_TEST_REMOVE_REALMS=1 (a private probe that
// would otherwise fill its directory) every realm this run made — each id
// carries the run's STAMP — is removed at the end, pass or fail. A suite run
// leaves them standing (tests/CLAUDE.md, *No job removes a realm*).
async function removeRealms() {
  log.debug("Entering removeRealms().");
  if (process.env.STS_TEST_REMOVE_REALMS !== "1") {
    log.debug("Leaving removeRealms(). Not asked to.");
    return;
  }
  const listed = await send(base + "/admin-api/realms?per=500");
  const mine = ((listed.body && listed.body.realms) || []).filter(
    function (one) {
      return one.id !== "default" && one.id.indexOf(STAMP) >= 0;
    });
  for (const one of mine) {
    const r = await postJson(base + "/admin-api/realms/remove",
                             { id: one.id });
    log.info("removed the realm " + one.id + " (" + r.status + ")");
  }
  log.debug("Leaving removeRealms().");
}

async function main() {
  log.debug("Entering main().");
  let failure = null;
  try {
    await test();
  } catch (e) {
    log.debug("Caught in main(): " + ((e && e.message) || e));
    // Reported below, after the realms are removed.
    failure = e;
  }
  try {
    await removeRealms();
  } catch (e) {
    log.debug("Caught in main() removing realms: " +
              ((e && e.message) || e));
    // A removal that fails leaves a realm on a private probe; not a test
    // failure.
    log.info("could not remove the realms: " + ((e && e.message) || e));
  }
  if (failure) {
    log.error("FAILED after " + checks + " check(s): " +
              ((failure && failure.stack) || failure));
    log.debug("Leaving main().");
    process.exit(1);
  }
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving main().");
}

main();
