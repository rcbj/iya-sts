// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_rate_limits.js
//
// ---------------------------------------------------------------------------
// THE RATE LIMITER SAYS NO, AT THE LIMIT IT IS CONFIGURED WITH, OVER THE
// WIRE.
//
// D12 (#444): carries over `tests/rate_limiter.js` and the part of
// `tests/scan_and_rate_limits.js` a client can see. The door is the one a
// client reaches most simply — a client secret at `/oauth2/token`, checked
// in a PRODUCT realm (development checks no client secret) — and every
// limit is the realm's own setting, written through the root API's
// `realms/set`, so the job asserts the same thing whatever the stack's
// appconfig raised the shipped limits to:
//
//   1. THE BOUNDARY: with `security.rateLimitPerIdentity` 3, three wrong
//      secrets are refused `invalid_client` 401 and the FOURTH is refused
//      429, with a Retry-After in (0, window], and STS-OAUTH-0284 recorded
//      against STS-OAUTH-0020's plain failures; it stays refused, and the
//      RIGHT secret is refused too while the window holds;
//   2. ONE BUCKET PER IDENTITY: another client from the same address is
//      unaffected;
//   3. WHAT A SUCCESS FORGETS: two failures, a success, and the next three
//      failures are still plain 401s;
//   4. THE WINDOW EXPIRES: with `security.rateLimitWindowS` 2, a locked
//      client's Retry-After is at most 2 and its right secret is answered
//      200 once the window has passed;
//   5. IT READS THE SETTING: lowered to 2, the third attempt is refused;
//   6. `credentials.factorScanLimit` (scan_and_rate_limits.js part 2): the
//      second-factor roster's cap, `GET /admin-api/mfa`'s `scanLimit`, is
//      the realm's setting (3 against the shipped 5000, each in a fresh
//      realm because the roster is built once and kept), and a realm
//      holding more people than that says the roster is `capped`.
//
// NOT carried, and why: the ADDRESS bucket's counts — the bucket is per
// process and keyed by the caller's address (deliberately not per realm),
// so on a stack every job shares the runner's address and a count asserted
// over the wire races every concurrent job (class (d)); the portal's
// signing-key limiter per identity and per address, the applications page's
// cap and the PIP query's cap (scan_and_rate_limits.js parts 1, 3 and 4)
// are reached only by exceeding them, through the portal's DPoP-bound token
// or a remote PEP's client certificate, and are owed by those families'
// jobs rather than this one.
//
// OWNED HERE (local: true): this repository's own management API.
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
var log = bunyan.createLogger({ name: "sts_rate_limits",
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
const REALM = "rlim-" + STAMP;
const RB = base + "/realm/" + REALM;
const SECRET = "rate-limits-" + STAMP + "-" + String(Date.now()).slice(-8) +
               "-secret";

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
  return { status: r.status, body: body, raw: raw,
           retryAfter: r.headers.get("retry-after") };
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

function setting(key, value) {
  log.debug("Entering setting(). " + key + "=" + value);
  log.debug("Leaving setting().");
  return ok(base + "/admin-api/realms/set", { id: REALM, key: key,
    value: String(value) }, "set " + key + " on the realm");
}

async function client(id) {
  log.debug("Entering client(). " + id);
  await ok(RB + "/admin-api/applications/create", { identifier: id, name: id,
    protocols: ["oauth2"],
    fields: { oauthClientId: [id], oauthClientSecret: SECRET,
              oauthTokenEndpointAuthMethod: "client_secret_post",
              oauthGrantType: ["client_credentials"] } },
    "registered the client " + id);
  log.debug("Leaving client().");
}

function attempt(id, secret) {
  log.debug("Entering attempt(). " + id);
  log.debug("Leaving attempt().");
  return send(RB + "/oauth2/token", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "client_credentials",
                                client_id: id,
                                client_secret: secret }).toString() });
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
    domain: REALM + ".example.net", name: "Rate limits " + STAMP },
    "created the realm");
  await setting("global.mode", "product");
  await setting("security.rateLimitPerIdentity", 3);
  // The address bucket is shared with every job on the runner's address, so
  // it is raised out of the way and never asserted here (see the header).
  await setting("security.rateLimitPerAddress", 10000);
  await setting("security.rateLimitWindowS", 60);
  for (const id of ["c1", "c2", "c3"]) {
    await client(id);
  }

  log.info("=== 1. where the limit falls ===");
  const wrong = [];
  for (let i = 0; i < 5; i += 1) {
    wrong.push(await attempt("c1", "wrong-" + i));
  }
  const right = await attempt("c1", SECRET);
  check("1. three wrong secrets are refused invalid_client 401", function () {
    wrong.slice(0, 3).forEach(function (r) {
      assert.strictEqual(r.status, 401, r.raw.slice(0, 300));
      assert.strictEqual(r.body.error, "invalid_client");
    });
  });
  check("1. the FOURTH is refused 429 — not the third, and not later",
        function () {
    assert.strictEqual(wrong[3].status, 429, wrong[3].raw.slice(0, 300));
    assert.ok(/Too many failed client authentications/.test(
      wrong[3].body.error_description), wrong[3].raw.slice(0, 300));
  });
  check("1. with a Retry-After inside the 60-second window", function () {
    const s = Number(wrong[3].retryAfter);
    assert.ok(s > 0 && s <= 60, String(wrong[3].retryAfter));
  });
  check("1. it stays refused, and the RIGHT secret is refused too while the " +
        "window holds", function () {
    assert.strictEqual(wrong[4].status, 429, wrong[4].raw.slice(0, 300));
    assert.strictEqual(right.status, 429, right.raw.slice(0, 300));
  });
  const limited = await codesSettle("STS-OAUTH-0284", 3);
  const failed = await codesSettle("STS-OAUTH-0020", 3);
  check("1. the refusals are recorded STS-OAUTH-0284 and the plain " +
        "failures STS-OAUTH-0020, and no code is sent", function () {
    assert.ok(limited >= 3, "STS-OAUTH-0284 rows: " + limited);
    assert.ok(failed >= 3, "STS-OAUTH-0020 rows: " + failed);
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(wrong[3].raw + wrong[0].raw));
  });

  log.info("=== 2. one bucket per identity ===");
  const other = await attempt("c2", SECRET);
  check("2. another client from the same address is unaffected", function () {
    assert.strictEqual(other.status, 200, other.raw.slice(0, 300));
  });

  log.info("=== 3. what a success forgets ===");
  const forgets = [];
  forgets.push(await attempt("c3", "wrong-a"));
  forgets.push(await attempt("c3", "wrong-b"));
  forgets.push(await attempt("c3", SECRET));
  for (let i = 0; i < 3; i += 1) {
    forgets.push(await attempt("c3", "wrong-again-" + i));
  }
  check("3. a success clears the failures: two failures, a success, and " +
        "three more failures are all still plain 401s", function () {
    assert.strictEqual(forgets[2].status, 200, forgets[2].raw.slice(0, 300));
    [0, 1, 3, 4, 5].forEach(function (i) {
      assert.strictEqual(forgets[i].status, 401, i + ": " +
                         forgets[i].raw.slice(0, 200));
    });
  });

  log.info("=== 4. the window expires ===");
  await setting("security.rateLimitWindowS", 2);
  await client("c4");
  const short = [];
  for (let i = 0; i < 4; i += 1) {
    short.push(await attempt("c4", "wrong-" + i));
  }
  check("4. a two-second window locks after the same three failures, with " +
        "a Retry-After of at most two seconds", function () {
    assert.strictEqual(short[3].status, 429, short[3].raw.slice(0, 300));
    const s = Number(short[3].retryAfter);
    assert.ok(s > 0 && s <= 2, String(short[3].retryAfter));
  });
  await sleep(2600);
  const later = await attempt("c4", SECRET);
  check("4. and once the window has passed the right secret is answered 200",
        function () {
    assert.strictEqual(later.status, 200, later.raw.slice(0, 300));
  });

  log.info("=== 5. it reads the setting ===");
  await setting("security.rateLimitWindowS", 60);
  await setting("security.rateLimitPerIdentity", 2);
  await client("c5");
  const two = [];
  for (let i = 0; i < 3; i += 1) {
    two.push(await attempt("c5", "wrong-" + i));
  }
  check("5. lowered to 2, the THIRD attempt is refused", function () {
    assert.strictEqual(two[0].status, 401, two[0].raw.slice(0, 200));
    assert.strictEqual(two[1].status, 401, two[1].raw.slice(0, 200));
    assert.strictEqual(two[2].status, 429, two[2].raw.slice(0, 200));
  });

  log.info("=== 6. the second-factor roster's cap ===");
  // Two fresh realms, because the roster's population is built once and
  // kept (`rebuildPopulation()`): the cap is read when it is built, so each
  // realm is asked for the first time with its setting already in place.
  const capped = REALM + "-c";
  const plain = REALM + "-p";
  await ok(base + "/admin-api/realms/create", { id: capped,
    overrides: { "credentials.factorScanLimit": 3 } },
    "created a realm whose cap is 3");
  await ok(base + "/admin-api/realms/create", { id: plain },
    "created a realm with the shipped cap");
  const three = await send(base + "/realm/" + capped + "/admin-api/mfa");
  const shipped = await send(base + "/realm/" + plain + "/admin-api/mfa");
  check("6. GET /admin-api/mfa's scanLimit is the realm's setting: 3 there, " +
        "the shipped 5000 beside it", function () {
    assert.strictEqual(three.status, 200, three.raw.slice(0, 300));
    assert.strictEqual(three.body.scanLimit, 3);
    assert.strictEqual(shipped.body.scanLimit, 5000);
  });
  check("6. and a realm holding more people than its cap says the roster " +
        "is capped", function () {
    assert.ok(Number(three.body.directoryPeople) > 3,
              "the seeded realm holds " + three.body.directoryPeople);
    assert.strictEqual(three.body.capped, true);
    assert.ok(Number(three.body.scanned) <= 3, String(three.body.scanned));
    assert.strictEqual(shipped.body.capped, false);
  });

  log.info("Test completed successfully. " + checks + " check(s) passed.");
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error("sts_rate_limits FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
