// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_realm_retiring.js
//
// ---------------------------------------------------------------------------
// A REALM BEING REMOVED STARTS NOTHING NEW, OVER THE WIRE (#262).
//
// D12 (#444): carries over `tests/realm_retiring.js`'s part A. That file
// holds `realms.retire()` open with a hook of its own; here the removal is
// held open the way a deployment holds it — by a Shared Signals receiver
// that does not answer. The realm gets a push stream to a listener this job
// runs, which accepts the connection and never replies, so the removal's
// deliver phase waits on it (bounded by `realms.removalDeliveryTimeoutS`),
// and while it waits:
//
//   1. `GET /admin-api/realms` reports the realm retiring — in progress, not
//      interrupted, with what it refuses and when it finishes;
//   2. the token endpoint answers `invalid_grant` for a client_credentials
//      grant there, saying the realm is being removed, and records
//      STS-CORE-0121 on the realm's audit log — while a control realm still
//      issues;
//   3. a second removal is refused 400 with the `retiring` state, and
//      STS-CORE-0122 recorded where it arrived;
//   4. when the receiver has been waited for, the removal answers 200 with
//      its retirement report — the bound, and the SETs that went undelivered
//      — the realm is gone, its paths answer nothing, and no realm is
//      retiring any more;
//   and, beside it, a realm may not remove ITSELF (STS-ADMIN-0563).
//
// NOT carried: the issuance gate's other kinds (OpenID4VCI's credential
// endpoint, certificate enrollment's funnel, the SPIFFE authority) — each is
// one more door asked the same `retiringRefusal()`, owed by those families'
// jobs; B (the mark replicated and one-way between processes) and C (the
// mark written to PostgreSQL before the row is deleted) are about the
// store and the change log, class (d); D (a removal INTERRUPTED by a
// restart) needs the process restarted mid-removal, class (d).
//
// IT CHANGES ONE PROCESS-WIDE SETTING, `realms.removalDeliveryTimeoutS`
// (20 seconds, so the hold is short and bounded), and resets it in a
// `finally`. The stalling listener is on `OUTBOUND_TEST_HOST` (or
// `GNAP_PUSH_HOST`), the name the service reaches this job by — the
// arrangement `sts_outbound_tls.js` uses.
//
// OWNED HERE (local: true): this repository's own management API.
// ---------------------------------------------------------------------------

const assert = require("assert");
const http = require("http");
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
var log = bunyan.createLogger({ name: "sts_realm_retiring",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const HOST = process.env.OUTBOUND_TEST_HOST || process.env.GNAP_PUSH_HOST ||
             "localhost";
const STAMP = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "")
  .slice(-10);
const GOING = "rtg-" + STAMP;
const CONTROL = "rtc-" + STAMP;
const PUSH = "urn:ietf:rfc:8935";
const REVOKED =
  "https://schemas.openid.net/secevent/caep/event-type/session-revoked";
const BOUND_S = 20;

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

function postJson(url, payload, headers) {
  log.debug("Entering postJson().");
  log.debug("Leaving postJson().");
  return send(url, { method: "POST",
    headers: Object.assign({ "Content-Type": "application/json" },
                           headers || {}),
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

function token(realm, fields) {
  log.debug("Entering token().");
  log.debug("Leaving token().");
  return send(base + "/realm/" + realm + "/oauth2/token", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(fields).toString() });
}

async function codeCount(realm, code) {
  log.debug("Entering codeCount(). " + code);
  const r = await send(base + (realm ? "/realm/" + realm : "") +
                       "/admin-api/audit?per=500&code=" +
                       encodeURIComponent(code));
  log.debug("Leaving codeCount().");
  return Number((r.body && r.body.matched) || 0);
}

async function realmRow(id) {
  log.debug("Entering realmRow().");
  const r = await send(base + "/admin-api/realms?per=500");
  assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
  log.debug("Leaving realmRow().");
  return { row: (r.body.realms || []).filter(function (one) {
    return one.id === id;
  })[0] || null, all: r.body.realms || [] };
}

// A receiver that takes the connection and never answers it.
function stallingListener() {
  log.debug("Entering stallingListener().");
  const held = [];
  const server = http.createServer(function (req) {
    held.push({ at: Date.now(), url: req.url });
  });
  log.debug("Leaving stallingListener().");
  return new Promise(function (resolve) {
    server.listen(0, "0.0.0.0", function () {
      resolve({ server: server, held: held,
                url: "http://" + HOST + ":" + server.address().port +
                     "/events" });
    });
  });
}

async function receiver(realm) {
  log.debug("Entering receiver(). " + realm);
  const api = base + "/realm/" + realm + "/admin-api";
  await ok(api + "/applications/create", { identifier: "rcv",
    kind: "oauth2-client", name: "rcv", protocols: ["oauth2", "ssf"],
    fields: { oauthClientId: ["rcv"],
              oauthAllowedScope: ["ssf.read", "ssf.manage"],
              oauthGrantType: ["client_credentials"] } },
    "registered the receiver in " + realm);
  for (const role of ["SSF_READ", "SSF_MANAGE"]) {
    await ok(api + "/roles/add-member", { role: role, kind: "application",
      member: "rcv" }, "mapped the receiver onto " + role);
  }
  log.debug("Leaving receiver().");
}

async function theWindow(stall) {
  log.debug("Entering theWindow().");
  await ok(base + "/admin-api/realms/set", { id: GOING,
    key: "ssf.pushAllowHttp", value: "true" },
    "allowed a plain-HTTP push receiver in the realm");
  const minted = await token(GOING, { grant_type: "client_credentials",
    client_id: "rcv", client_secret: "dev", scope: "ssf.read ssf.manage" });
  assert.strictEqual(minted.status, 200, minted.raw.slice(0, 300));
  const stream = await postJson(base + "/realm/" + GOING + "/ssf/stream",
    { delivery: { method: PUSH, endpoint_url: stall.url },
      events_requested: [REVOKED] },
    { Authorization: "Bearer " + minted.body.access_token });
  assert.strictEqual(stream.status, 201, stream.raw.slice(0, 300));

  log.info("=== the removal, held open by a receiver that never answers ===");
  const started = Date.now();
  let answered = null;
  const removal = postJson(base + "/admin-api/realms/remove",
                           { id: GOING }).then(function (r) {
    answered = { r: r, ms: Date.now() - started };
    return answered;
  });
  let row = null;
  for (let i = 0; i < 40 && !(row && row.retiring); i += 1) {
    await sleep(150);
    row = (await realmRow(GOING)).row;
  }
  check("1. GET /admin-api/realms reports the realm retiring: in progress, " +
        "not interrupted, saying what it refuses", function () {
    assert.ok(row && row.retiring, JSON.stringify(row).slice(0, 300));
    assert.strictEqual(row.retiring.inProgress, true);
    assert.strictEqual(row.retiring.interrupted, false);
    assert.ok(/STS-CORE-0121/.test(row.retiring.refusing) &&
              /every new sign-in/.test(row.retiring.refusing),
              JSON.stringify(row.retiring));
    assert.ok(Number(row.retiring.finishesBy) > Number(row.retiring.since));
  });
  const before0121 = await codeCount(GOING, "STS-CORE-0121");
  const refused = await token(GOING, { grant_type: "client_credentials",
    client_id: "rcv", client_secret: "dev" });
  const control = await token(CONTROL, { grant_type: "client_credentials",
    client_id: "rcv", client_secret: "dev" });
  const after0121 = await codeCount(GOING, "STS-CORE-0121");
  check("2. the token endpoint answers invalid_grant there, saying the " +
        "realm is being removed", function () {
    assert.strictEqual(refused.status, 400, refused.raw.slice(0, 300));
    assert.strictEqual(refused.body.error, "invalid_grant");
    assert.ok(/is being removed/.test(refused.body.error_description),
              refused.raw.slice(0, 300));
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(refused.raw), "a code was sent");
  });
  check("2. and records STS-CORE-0121 on the realm's audit log", function () {
    assert.ok(after0121 > before0121, before0121 + " -> " + after0121);
  });
  check("2. while the control realm still issues", function () {
    assert.strictEqual(control.status, 200, control.raw.slice(0, 300));
  });
  const before0122 = await codeCount("", "STS-CORE-0122");
  const second = await postJson(base + "/admin-api/realms/remove",
                                { id: GOING });
  const after0122 = await codeCount("", "STS-CORE-0122");
  check("3. a second removal is refused while the first is running, with " +
        "its retiring state, and STS-CORE-0122 recorded", function () {
    assert.strictEqual(second.status, 400, second.raw.slice(0, 300));
    assert.ok(second.body.retiring && second.body.retiring.inProgress,
              second.raw.slice(0, 300));
    assert.ok(/already being removed/.test((second.body.errors || [])
      .join(" ")), second.raw.slice(0, 300));
    assert.ok(after0122 > before0122, before0122 + " -> " + after0122);
  });
  check("the receiver was really being waited for: the removal had not " +
        "answered while all that was asked", function () {
    assert.ok(stall.held.length >= 1, "nothing reached the receiver");
    assert.strictEqual(answered, null, JSON.stringify(answered &&
      answered.r.status));
  });

  const done = await removal;
  const gone = await realmRow(GOING);
  const path = await send(base + "/realm/" + GOING +
                          "/.well-known/openid-configuration");
  check("4. the removal then answers 200 with its retirement report: the " +
        "bound and what went undelivered", function () {
    assert.strictEqual(done.r.status, 200, done.r.raw.slice(0, 300));
    const r = done.r.body.retirement;
    assert.strictEqual(r.boundSeconds, BOUND_S, JSON.stringify(r));
    assert.ok((r.undelivered || []).some(function (one) {
      return one.count > 0 && /SET/.test(one.what);
    }), JSON.stringify(r));
    assert.ok(/not everything was delivered within/.test(
      done.r.body.message), done.r.body.message);
  });
  check("4. the realm is gone, its paths answer nothing, and no realm is " +
        "retiring any more", function () {
    assert.strictEqual(gone.row, null);
    assert.strictEqual(path.status, 404, String(path.status));
    assert.ok(!gone.all.some(function (one) {
      return one.retiring;
    }), JSON.stringify(gone.all.filter(function (one) {
      return one.retiring;
    }).map(function (one) {
      return one.id;
    })));
  });
  log.debug("Leaving theWindow().");
}

async function test() {
  log.debug("Entering test().");
  for (const id of [GOING, CONTROL]) {
    await ok(base + "/admin-api/realms/create", { id: id,
      domain: id + ".example.net", name: "Retiring " + STAMP },
      "created the realm " + id);
    await receiver(id);
  }
  const self = await postJson(base + "/realm/" + CONTROL +
                              "/admin-api/realms/remove", { id: CONTROL });
  const self0563 = await codeCount(CONTROL, "STS-ADMIN-0563");
  check("a realm may not remove ITSELF (STS-ADMIN-0563): the caller would " +
        "be left on a path that no longer exists", function () {
    assert.strictEqual(self.status, 400, self.raw.slice(0, 300));
    assert.ok(/removing it would leave the caller on a path/.test(
      (self.body.errors || []).join(" ")), self.raw.slice(0, 300));
    assert.ok(self0563 >= 1, String(self0563));
  });
  const stall = await stallingListener();
  log.info("the stalling receiver is " + stall.url);
  await ok(base + "/admin-api/config/set", {
    key: "realms.removalDeliveryTimeoutS", value: String(BOUND_S) },
    "bounded a removal's wait");
  try {
    await theWindow(stall);
  } finally {
    const reset = await postJson(base + "/admin-api/config/reset",
                                 { key: "realms.removalDeliveryTimeoutS" });
    log.info("reset realms.removalDeliveryTimeoutS (" + reset.status + ")");
    stall.server.closeAllConnections();
    stall.server.close();
  }
  log.info("Test completed successfully. " + checks + " check(s) passed.");
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error("sts_realm_retiring FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
