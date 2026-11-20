// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_signing_history.js
//
// ---------------------------------------------------------------------------
// EVERY SIGNING KEY A REALM HAS EVER HELD, OVER THE WIRE (#42's follow-up).
//
// D12 (#444): carries over `tests/signing_history.js` — section F's real
// generations, and the claims of A–E a caller can see — through
// `/admin-api/keys/history`, its certificate download and the rotation
// doors, in a throwaway realm:
//
//   1. the index names every signing unit of the realm, each with a live
//      generation and nothing dropped; one unit's rows name its current key;
//   2. NO PRIVATE MATERIAL REACHES A ROW: no PEM private key, no `d`, no
//      `privateKeyPem`, at every stage below;
//   3. observing twice records nothing;
//   4. an unknown unit is refused, naming the units the realm has, rather
//      than answered as an empty history;
//   5. a rotation (POST /admin-api/keys/rotate) moves the old key to
//      `retired` and a new one to `current`; the old row keeps its first
//      timestamps and its certificate (captured once, never replaced);
//   6. an emergency rotation (`confirm: "compromised"`) marks the keys it
//      throws away DROPPED, with a reason, their certificate KEPT; the
//      dropped key is gone from the JWK Set and its certificate still
//      downloads, no-store; a kid the realm never held is 404, recorded
//      STS-KEYS-0068;
//   7. newest first, by when each key last moved;
//   8. the history is the realm's: another realm's index names none of its
//      keys.
//
// NOT carried, and why (class (d)): the injected-dependency sections' hand
// states (a process holding no key set, a re-certification over the same key
// while it is live, a fake that throws), and the BBS secret key search (no
// door reports a BBS key's row with material to search beyond 2).
//
// OWNED HERE (local: true): this repository's own management API.
// ---------------------------------------------------------------------------

const assert = require("assert");
const nodeCrypto = require("crypto");
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
var log = bunyan.createLogger({ name: "sts_signing_history",
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
    // Not JSON — a PEM chain or an empty answer; the caller reads `raw`.
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

function setting(realm, key, value) {
  log.debug("Entering setting(). " + realm + " " + key + "=" + value);
  log.debug("Leaving setting().");
  return ok(base + "/admin-api/realms/set", { id: realm, key: key,
    value: String(value) }, "set " + key + " on " + realm);
}

function headerOf(token) {
  log.debug("Entering headerOf().");
  const h = JSON.parse(Buffer.from(String(token).split(".")[0], "base64url")
    .toString("utf8"));
  log.debug("Leaving headerOf().");
  return h;
}

function pemsIn(text) {
  log.debug("Entering pemsIn().");
  const found = String(text).match(
    /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || [];
  log.debug("Leaving pemsIn().");
  return found;
}

function b64Of(pem) {
  log.debug("Entering b64Of().");
  log.debug("Leaving b64Of().");
  return String(pem).replace(/-----[^-]+-----|\s/g, "");
}

function pemOfB64(b64) {
  log.debug("Entering pemOfB64().");
  log.debug("Leaving pemOfB64().");
  return "-----BEGIN CERTIFICATE-----\n" +
         String(b64).match(/.{1,64}/g).join("\n") +
         "\n-----END CERTIFICATE-----\n";
}

const REALM = "skh-" + STAMP;
const OTHER = "skho-" + STAMP;
const CREATED = [];
const UNIT = "jose:RS256";

async function realm(id) {
  log.debug("Entering realm(). " + id);
  await ok(base + "/admin-api/realms/create", { id: id,
    domain: id + ".example.net", name: "Key history " + STAMP },
    "created the realm " + id);
  CREATED.push(id);
  // Development is what this job asserts; a product stack's realms would
  // otherwise inherit the process's mode.
  await setting(id, "global.mode", "development");
  log.debug("Leaving realm().");
}

async function history(realmId, unit) {
  log.debug("Entering history(). " + unit);
  const r = await send(base + "/realm/" + realmId +
                       "/admin-api/keys/history" +
                       (unit ? "?unit=" + encodeURIComponent(unit) : ""));
  log.debug("Leaving history(). " + r.status);
  return r;
}

function noPrivate(raw, what) {
  log.debug("Entering noPrivate().");
  check("2. no private material in " + what, function () {
    assert.ok(!/PRIVATE KEY/.test(raw), "a PEM private key");
    assert.ok(!/"d"\s*:/.test(raw), "a JWK private member");
    assert.ok(!/privateKey/i.test(raw), "a private key member");
  });
  log.debug("Leaving noPrivate().");
}

async function until(realmId, what, fn) {
  log.debug("Entering until(). " + what);
  let r = await history(realmId, UNIT);
  for (let i = 0; i < 90 && !fn(r.body); i += 1) {
    await sleep(1000);
    r = await history(realmId, UNIT);
  }
  assert.ok(fn(r.body), what + " never came: " + r.raw.slice(0, 600));
  log.debug("Leaving until().");
  return r;
}

function rowFor(body, kid) {
  log.debug("Entering rowFor().");
  log.debug("Leaving rowFor().");
  return (body.rows || []).filter(function (row) {
    return row.kid === kid;
  })[0];
}

async function test() {
  log.debug("Entering test().");
  await realm(REALM);
  // The history is a projection of the key set, taken as the set is used.
  await send(base + "/realm/" + REALM + "/oauth2/jwks");

  log.info("=== 1. the index and one unit ===");
  const index = await history(REALM);
  check("1a. the index names the realm's signing units, each live and " +
        "none dropped", function () {
    assert.strictEqual(index.status, 200, index.raw.slice(0, 300));
    const one = index.body.units.filter(function (u) {
      return u.unit === UNIT;
    })[0];
    assert.ok(one, "no " + UNIT + " in " + JSON.stringify(
      index.body.units.map(function (u) {
        return u.unit;
      })));
    index.body.units.forEach(function (u) {
      assert.ok(u.live >= 1 && u.dropped === 0, JSON.stringify(u));
    });
  });
  noPrivate(index.raw, "the index");
  const first = await until(REALM, "a current RS256 row", function (body) {
    return (body.rows || []).some(function (row) {
      return row.role === "current" && row.certificate;
    });
  });
  const current = first.body.rows.filter(function (row) {
    return row.role === "current";
  })[0];
  const jwks = (await send(base + "/realm/" + REALM + "/oauth2/jwks")).body;
  check("1b. its rows name the current key, the JWK Set's RS256 key, with " +
        "its certificate", function () {
    assert.strictEqual(current.kid, jwks.keys[0].kid);
    assert.ok(/BEGIN CERTIFICATE/.test(current.certificate.certificatePem));
    assert.ok(current.promotedAt && !current.droppedAt);
  });
  noPrivate(first.raw, "a unit's rows");

  log.info("=== 3. observing twice ===");
  const again = await history(REALM, UNIT);
  check("3. observing twice records nothing", function () {
    assert.strictEqual(again.body.total, first.body.total);
    assert.strictEqual(JSON.stringify(rowFor(again.body, current.kid)),
                       JSON.stringify(current));
  });

  log.info("=== 4. an unknown unit ===");
  const unknown = await history(REALM, "jose:no-such-unit");
  check("4. an unknown unit is refused, naming the units the realm has",
        function () {
    assert.strictEqual(unknown.status, 400, unknown.raw.slice(0, 300));
    assert.ok(unknown.body.units.indexOf(UNIT) >= 0);
  });

  log.info("=== 5. a rotation ===");
  const rot = await postJson(base + "/realm/" + REALM +
                             "/admin-api/keys/rotate", { units: [UNIT] });
  check("5a. a rotation is accepted and queued", function () {
    assert.strictEqual(rot.status, 202, rot.raw.slice(0, 300));
    assert.deepStrictEqual(rot.body.units, [UNIT]);
  });
  const rotated = await until(REALM, "the old key retired", function (body) {
    const old = rowFor(body, current.kid);
    return old && old.role !== "current";
  });
  const old = rowFor(rotated.body, current.kid);
  const now = rotated.body.rows.filter(function (row) {
    return row.role === "current";
  })[0];
  check("5b. the old key is retired and a new key is current", function () {
    assert.strictEqual(old.role, "retired", JSON.stringify(old).slice(0, 300));
    assert.ok(old.retiredAt, "no retiredAt");
    assert.ok(now && now.kid !== current.kid, JSON.stringify(now));
  });
  check("5c. the old row keeps its first timestamps and its certificate",
        function () {
    assert.strictEqual(old.firstSeenAt, current.firstSeenAt);
    assert.strictEqual(old.promotedAt, current.promotedAt);
    assert.strictEqual(old.certificate.thumbprint,
                       current.certificate.thumbprint);
  });
  noPrivate(rotated.raw, "the rows after a rotation");

  log.info("=== 6. an emergency ===");
  const unconfirmed = await postJson(base + "/realm/" + REALM +
                                     "/admin-api/keys/emergency",
                                     { units: [UNIT] });
  check("6a. an emergency rotation asks to be confirmed", function () {
    assert.strictEqual(unconfirmed.status, 400, unconfirmed.raw.slice(0, 300));
  });
  const emergency = await postJson(base + "/realm/" + REALM +
                                   "/admin-api/keys/emergency",
                                   { units: [UNIT], confirm: "compromised" });
  check("6b. confirmed, it is accepted", function () {
    assert.strictEqual(emergency.status, 202, emergency.raw.slice(0, 300));
    assert.strictEqual(emergency.body.emergency, true);
  });
  const dropped = await until(REALM, "a dropped key", function (body) {
    const one = rowFor(body, now.kid);
    return one && one.role === "dropped";
  });
  const gone = rowFor(dropped.body, now.kid);
  check("6c. the key it threw away is DROPPED, with a reason, and its " +
        "certificate KEPT", function () {
    assert.ok(gone.droppedAt, "no droppedAt");
    assert.ok(/emergency/.test(gone.reason), gone.reason);
    assert.strictEqual(gone.certificate.thumbprint,
                       now.certificate.thumbprint);
  });
  const after = (await send(base + "/realm/" + REALM + "/oauth2/jwks")).body;
  check("6d. and it is gone from the JWK Set", function () {
    assert.ok(!after.keys.some(function (k) {
      return k.kid === now.kid;
    }));
  });
  const cert = await send(base + "/realm/" + REALM +
                          "/admin-api/keys/history/certificate?unit=" +
                          encodeURIComponent(UNIT) + "&kid=" +
                          encodeURIComponent(now.kid));
  check("6e. its certificate still downloads, no-store", function () {
    assert.strictEqual(cert.status, 200, cert.raw.slice(0, 300));
    assert.ok(/application\/pem-certificate-chain/.test(
      cert.headers.get("content-type")));
    assert.strictEqual(cert.headers.get("cache-control"), "no-store");
    assert.strictEqual(b64Of(pemsIn(cert.raw)[0]),
                       b64Of(now.certificate.certificatePem));
  });
  noPrivate(dropped.raw + cert.raw, "a dropped row and its certificate");
  const codesBefore = Number((await send(base + "/realm/" + REALM +
    "/admin-api/audit?per=500&code=STS-KEYS-0068")).body.matched || 0);
  const never = await send(base + "/realm/" + REALM +
                           "/admin-api/keys/history/certificate?unit=" +
                           encodeURIComponent(UNIT) + "&kid=no-such-kid");
  let codesAfter = codesBefore;
  for (let i = 0; i < 20 && codesAfter <= codesBefore; i += 1) {
    await sleep(150);
    codesAfter = Number((await send(base + "/realm/" + REALM +
      "/admin-api/audit?per=500&code=STS-KEYS-0068")).body.matched || 0);
  }
  check("6f. a kid the realm never held is 404, recorded STS-KEYS-0068",
        function () {
    assert.strictEqual(never.status, 404, never.raw.slice(0, 300));
    assert.ok(codesAfter > codesBefore, codesBefore + " -> " + codesAfter);
  });

  log.info("=== 7. newest first ===");
  check("7. the rows are newest first, by when each key last moved (its " +
        "drop, its retirement, its promotion, its minting)", function () {
    const stamps = dropped.body.rows.map(function (row) {
      return Date.parse(row.droppedAt || row.retiredAt || row.promotedAt ||
                        row.createdAt || row.firstSeenAt);
    });
    for (let i = 1; i < stamps.length; i += 1) {
      assert.ok(stamps[i - 1] >= stamps[i], JSON.stringify(
        dropped.body.rows.map(function (row) {
          return [row.kid, row.role, row.droppedAt, row.retiredAt,
                  row.promotedAt];
        })));
    }
  });

  log.info("=== 8. per realm ===");
  await realm(OTHER);
  await send(base + "/realm/" + OTHER + "/oauth2/jwks");
  const theirs = await history(OTHER, UNIT);
  check("8. another realm's history names none of this realm's keys",
        function () {
    assert.strictEqual(theirs.status, 200, theirs.raw.slice(0, 300));
    [current.kid, now.kid].forEach(function (kid) {
      assert.ok(!rowFor(theirs.body, kid), kid);
    });
  });

  assert.ok(checks >= 19, "only " + checks + " checks ran; a section has " +
                          "stopped being called.");
  log.info(checks + " check(s) passed.");
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
  for (const id of CREATED) {
    const r = await postJson(base + "/admin-api/realms/remove", { id: id });
    log.info("removed the realm " + id + " (" + r.status + ")");
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
    log.debug("Caught in main(): " + ((e && e.message) || e));
    log.warn("could not remove the realms: " + e.message);
  }
  if (failure) {
    log.error(failure.stack || failure.message);
    log.debug("Leaving main(). failed");
    process.exit(1);
  }
  log.info("Test completed successfully.");
  log.debug("Leaving main().");
}

main();
