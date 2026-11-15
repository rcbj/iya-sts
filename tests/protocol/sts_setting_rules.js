// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_setting_rules.js
//
// ---------------------------------------------------------------------------
// WHAT THE SETTING DOORS REFUSE, WHAT A WRITE SAYS ABOUT A RESTART, AND THE
// AGE OF THE USERS PAGE'S COUNT, OVER THE WIRE.
//
// D12 (#444): carries over, as observed through `/admin-api` in a throwaway
// realm this job creates and leaves behind:
//
//   A. tests/setting_absolute_uri.js's write door: `saml2.nameIdFormat` and
//      `saml11.nameIdFormat` refuse text that is not an absolute URI (400,
//      "absolute URI", STS-CORE-0006 on the realm's audit) and take the
//      URNs and URLs a format is; a row without the rule takes `,]`.
//   B. tests/unstorable_text.js's doors (#1463): a NUL, a lone high and a
//      lone low surrogate refused at `config/set` (STS-CORE-0171), the
//      refusal naming the setting and never quoting the value, a whole
//      surrogate pair taken; a realm created with a NUL in its name, a
//      realm override holding one and a description holding a lone
//      surrogate each refused, and nothing made or changed.
//   C. tests/settings_restart_wording.js's memory half: with no persistent
//      store a `set`, a `set-many` and a token-lifetimes `set` inside a
//      realm each say the override is in memory and gone on restart, and
//      name `persistence.realms`; a `set-many` that changed nothing says
//      nothing about a restart.
//   D. tests/users_page_count_age.js's view (#684): `GET /admin-api/users`
//      answers `directoryCountedAt` and `directoryCountsKeptFor` (null in
//      memory), `directoryCounts` stays the tiles alone, a repeat is the
//      kept count, a person created ends it, `/admin-api/mfa` carries the
//      same two members, and past `credentials.factorScanLimit` the list is
//      capped while `directoryPeople` is the directory's whole count.
//
// What stays in process is said in each file's own D12 note: the startup
// warning (STS-CORE-0176), the store's backstop for a value the door
// refuses, the persisting store's sentences and the pages the console's
// bundle draws from these answers.
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
var log = bunyan.createLogger({ name: "sts_setting_rules",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("setr-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
  .slice(0, 31);
const API = base + "/realm/" + REALM + "/admin-api";
const NUL = "a\u0000b";
const LONE = "a\ud800b";
const LOW = "\udc00";
const GOOD = [
  "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
  "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
  "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
  "https://example.com/formats/one"
];
const BAD = [",]", "", "no scheme", "urn:", "urn:a b", "x:\u0007y", "1urn:x"];
const PEOPLE = 12;
const SCAN_LIMIT = 10;

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

async function getJson(url) {
  log.debug("Entering getJson().");
  const r = await send(url);
  assert.strictEqual(r.status, 200, "GET " + url + " answered " + r.status +
                     " " + String(r.raw).slice(0, 300));
  log.debug("Leaving getJson().");
  return r.body;
}

// How many audit rows of one code the realm whose API this is holds. The
// code is recorded, never sent, so this is the only place a job sees it.
async function codeCount(api, code) {
  log.debug("Entering codeCount(). " + code);
  const body = await getJson(api + "/audit?per=1&code=" +
                             encodeURIComponent(code));
  log.debug("Leaving codeCount().");
  return Number(body.matched || 0);
}

// Waits for the count to pass `before`: the row is written as the answer
// leaves, and a poll costs nothing when it is already there.
async function codeGrew(api, code, before) {
  log.debug("Entering codeGrew(). " + code);
  let now = before;
  for (let i = 0; i < 20 && now <= before; i += 1) {
    now = await codeCount(api, code);
    if (now <= before) {
      await sleep(150);
    }
  }
  log.debug("Leaving codeGrew(). " + before + " -> " + now);
  return now - before;
}

async function absoluteUri() {
  log.debug("Entering absoluteUri().");
  log.info("=== A. a NameID format is an absolute URI ===");
  for (const key of ["saml2.nameIdFormat", "saml11.nameIdFormat"]) {
    for (const value of BAD) {
      const before = await codeCount(API, "STS-CORE-0006");
      const r = await postJson(API + "/config/set", { key: key,
                                                      value: value });
      const grew = await codeGrew(API, "STS-CORE-0006", before);
      check(key + " refuses " + JSON.stringify(value) + " as not an " +
            "absolute URI, recorded as STS-CORE-0006", function () {
        assert.strictEqual(r.status, 400, r.raw.slice(0, 300));
        assert.ok(r.body && r.body.ok === false &&
                  /absolute URI/.test((r.body.errors || []).join(" ")),
                  r.raw.slice(0, 300));
        assert.strictEqual(grew, 1, "audit rows of STS-CORE-0006 grew by " +
                           grew);
      });
    }
    for (const value of GOOD) {
      const r = await postJson(API + "/config/set", { key: key,
                                                      value: value });
      check(key + " takes " + value, function () {
        assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
        assert.strictEqual(r.body.setting.value, value);
      });
    }
    await ok(API + "/config/reset", { key: key }, "reset " + key);
  }
  const plain = await postJson(API + "/config/set",
                               { key: "branding.displayName", value: ",]" });
  check("a text row without the rule takes ,]", function () {
    assert.strictEqual(plain.status, 200, plain.raw.slice(0, 300));
  });
  await ok(API + "/config/reset", { key: "branding.displayName" },
           "reset branding.displayName");
  log.debug("Leaving absoluteUri().");
}

async function unstorable() {
  log.debug("Entering unstorable().");
  log.info("=== B. a value the store can never hold ===");
  const key = "saml11.nameIdFormat";
  for (const value of [NUL, LONE, LOW]) {
    const before = await codeCount(API, "STS-CORE-0171");
    const r = await postJson(API + "/config/set", { key: key, value: value });
    const grew = await codeGrew(API, "STS-CORE-0171", before);
    check("config/set refuses " + JSON.stringify(value) + ", naming the " +
          "setting and not the value, as STS-CORE-0171", function () {
      assert.strictEqual(r.status, 400, r.raw.slice(0, 300));
      const said = (r.body.errors || []).join(" ");
      assert.ok(said.indexOf(key) >= 0 && /NUL|surrogate/.test(said), said);
      assert.ok(said.indexOf(value) < 0, "the refusal quoted the value");
      assert.strictEqual(grew, 1, "STS-CORE-0171 rows grew by " + grew);
    });
  }
  const pair = await postJson(API + "/config/set",
                              { key: key, value: "urn:x:a\ud83d\ude00b" });
  check("a whole surrogate pair is still taken", function () {
    assert.strictEqual(pair.status, 200, pair.raw.slice(0, 300));
  });
  await ok(API + "/config/reset", { key: key }, "reset " + key);

  const root = base + "/admin-api";
  const badId = (REALM + "-x").slice(0, 31);
  const before = await codeCount(root, "STS-CORE-0171");
  const named = await postJson(root + "/realms/create", { id: badId,
    domain: badId + ".example.net", name: NUL });
  const grew = await codeGrew(root, "STS-CORE-0171", before);
  const listed = await getJson(root + "/realms");
  check("a realm named with a NUL is refused as STS-CORE-0171 and not made",
        function () {
    assert.strictEqual(named.status, 400, named.raw.slice(0, 300));
    assert.ok(/NUL/.test((named.body.errors || []).join(" ")),
              named.raw.slice(0, 300));
    assert.strictEqual(grew, 1, "STS-CORE-0171 rows grew by " + grew);
    const ids = (listed.realms || []).map(function (one) {
      return one.id;
    });
    assert.ok(ids.indexOf(REALM) >= 0 && ids.indexOf(badId) < 0,
              JSON.stringify(ids).slice(0, 400));
  });
  const override = await postJson(root + "/realms/set", { id: REALM,
    key: key, value: NUL });
  check("a realm override holding a NUL is refused", function () {
    assert.strictEqual(override.status, 400, override.raw.slice(0, 300));
    assert.ok(/NUL|surrogate/.test((override.body.errors || []).join(" ")),
              override.raw.slice(0, 300));
  });
  const described = await postJson(root + "/realms/update",
                                   { id: REALM, description: LONE });
  const after = await getJson(root + "/realms");
  check("a description holding a lone surrogate is refused and nothing " +
        "changes", function () {
    assert.strictEqual(described.status, 400, described.raw.slice(0, 300));
    assert.ok(/description/.test((described.body.errors || []).join(" ")),
              described.raw.slice(0, 300));
    const mine = (after.realms || []).filter(function (one) {
      return one.id === REALM;
    })[0];
    assert.ok(mine && String(mine.description || "").indexOf("\ud800") < 0,
              JSON.stringify(mine));
  });
  log.debug("Leaving unstorable().");
}

async function restartWording() {
  log.debug("Entering restartWording().");
  log.info("=== C. a write says it is gone on restart, with no store ===");
  const set = await ok(API + "/config/set", { key: "groups.claimName",
    value: "roles-" + STAMP }, "set groups.claimName");
  const many = await ok(API + "/config/set-many",
                        { "groups.claimName": "many-" + STAMP },
                        "set-many groups.claimName");
  const life = await ok(API + "/token-lifetimes/set",
                        { "oauth2.accessTokenTtlS": "600" },
                        "set a token lifetime");
  [["set", set], ["set-many", many], ["token-lifetimes set", life]]
    .forEach(function (pair) {
      check("a realm's " + pair[0] + " says it is in memory and gone on " +
            "restart, and how to keep it", function () {
        const message = String(pair[1].message || "");
        assert.ok(/in memory and gone on restart/.test(message), message);
        assert.ok(/appconfig file/.test(message) &&
                  /persistence\.realms/.test(message), message);
        assert.ok(!/kept across restarts/.test(message), message);
      });
    });
  const again = await ok(API + "/config/set-many",
                         { "groups.claimName": "many-" + STAMP },
                         "set-many the same value");
  check("a set-many that changed nothing says nothing about a restart",
        function () {
    assert.ok(/Nothing changed/.test(again.message) &&
              !/restart/.test(again.message), again.message);
  });
  await ok(API + "/config/reset", { key: "groups.claimName" }, "reset");
  await ok(API + "/config/reset", { key: "oauth2.accessTokenTtlS" }, "reset");
  log.debug("Leaving restartWording().");
}

async function countAge() {
  log.debug("Entering countAge().");
  log.info("=== D. the users view says how old its count is ===");
  await ok(API + "/config/set", { key: "credentials.factorScanLimit",
    value: String(SCAN_LIMIT) }, "lowered the scan limit");
  for (let i = 0; i < PEOPLE; i += 1) {
    await ok(API + "/users/create", { username: "upca-" + i, invent: false,
      attributes: { cn: "Count " + i, sn: "Count", givenName: "Upca" } },
      "created person " + i);
  }
  const first = await getJson(API + "/users");
  const at = Date.parse(first.directoryCountedAt);
  check("the view says when the directory counted, with no bound in memory",
        function () {
    assert.ok(typeof first.directoryCountedAt === "string" &&
              Number.isFinite(at) && at <= Date.now(),
              String(first.directoryCountedAt));
    assert.strictEqual(first.directoryCountsKeptFor, null);
    assert.ok(first.directoryPeople >= PEOPLE, String(first.directoryPeople));
  });
  check("directoryCounts stays the tiles alone", function () {
    const tiles = first.directoryCounts;
    assert.ok(tiles && !("countedAt" in tiles) &&
              !("keptForSeconds" in tiles),
              Object.keys(tiles || {}).join(","));
    assert.strictEqual(first.directoryCounts.people, first.directoryPeople);
  });
  check("past the scan limit the list is capped, and the directory's " +
        "count is the whole directory", function () {
    assert.strictEqual(first.capped, true);
    assert.strictEqual(first.scanLimit, SCAN_LIMIT);
    assert.ok(first.directoryPeople > first.scanned ||
              first.directoryPeople > SCAN_LIMIT,
              JSON.stringify({ people: first.directoryPeople,
                               scanned: first.scanned }));
  });
  const again = await getJson(API + "/users");
  check("a repeat answers the kept count, counted at the same time",
        function () {
    assert.strictEqual(again.directoryCountedAt, first.directoryCountedAt);
  });
  await ok(API + "/users/create", { username: "upca-extra", invent: false,
    attributes: { cn: "Count extra", sn: "Count", givenName: "Upca" } },
    "created one more person");
  const after = await getJson(API + "/users");
  check("a person created ends the kept count: one more, counted no earlier",
        function () {
    assert.strictEqual(after.directoryPeople, first.directoryPeople + 1);
    assert.ok(Date.parse(after.directoryCountedAt) >= at,
              after.directoryCountedAt);
  });
  const roster = await getJson(API + "/mfa");
  check("/admin-api/mfa carries the same two members", function () {
    assert.strictEqual(roster.directoryCountedAt, after.directoryCountedAt);
    assert.strictEqual(roster.directoryCountsKeptFor, null);
  });
  await ok(API + "/config/reset", { key: "credentials.factorScanLimit" },
           "reset the scan limit");
  log.debug("Leaving countAge().");
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. a throwaway realm " + REALM + " ===");
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "Setting rules " + STAMP },
    "created the realm");
  await absoluteUri();
  await unstorable();
  await restartWording();
  await countAge();
  log.info("Test completed successfully. " + checks + " check(s) passed.");
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error("sts_setting_rules FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
