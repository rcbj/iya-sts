// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_asvs_identity_and_session.js
//
// ---------------------------------------------------------------------------
// PROVING WHO SOMEBODY IS, WHAT A SIGN-OUT ENDS AND WHAT SLOWS A GUESSER,
// OVER THE WIRE (#1448, #1449, #1504, #1505, #1520; ASVS 5.0.0 6.3.1,
// 7.4.1).
//
// D12 (#444): carries over `tests/asvs_identity_rules.js` and the part of
// `tests/asvs_session_limits.js` a client can see. In a development realm
// and a product realm of its own:
//
//   A. clearing a second factor (`clear-totp`, `clear-key`,
//      `clear-backup-codes`, `clear-email-factor`) is refused in product
//      without a statement of how the person was verified, or with one too
//      short, and goes on with one; development asks for none;
//   B. a password may not contain a word the organization or service is
//      known by (`security.passwordContextWords`), whatever its case,
//      punctuation or letter swaps; a word under four letters is not looked
//      for; the service's own name is always refused, with or without its
//      punctuation (product, through `users/set-password`);
//   C. `authn.sessionsEndedBefore` ends every session started before the
//      instant, and one started after is live;
//   D. THE DELAY after a wrong password at the sign-in screen grows (none,
//      then 250 ms, 500 ms, 1 s, 2 s) and never refuses, and a success
//      forgets it;
//   E. A SIGN-OUT in product revokes the access tokens issued on that
//      session (introspection says inactive) and leaves another session's
//      alone, and the ID Token stays usable as an `id_token_hint`; in
//      development the access token is left as it was; the signed-out
//      answer clears the origin's storage (`Clear-Site-Data: "storage"`).
//
// NOT carried, and why: the delay's cap at 4 s and its quiet-period
// forgetting are a clock (class (d)); the door counters' sharing across a
// cluster, the source reads (`doorBlocked`, `waitAfterFailures`) and the
// Clear-Site-Data decision for a browser holding another realm's account
// are the process's own (d); STS-OAUTH-1000 (an x5c certificate issued to
// ANOTHER application presented at private_key_jwt) needs two applications'
// certificates from the realm's CA — owed with the client-authentication
// family.
//
// OWNED HERE (local: true): this repository's credential and session rules.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const names = require("./random_username.js");
const authnSignin = require("./authn_signin");

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
var log = bunyan.createLogger({ name: "sts_asvs_identity_and_session",
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
    // Not JSON — an empty answer or a page; the caller reads `raw`.
    body = null;
  }
  log.debug("Leaving send(). status=" + r.status);
  return { status: r.status, body: body, raw: raw, headers: r.headers };
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
  assert.ok(r.status >= 200 && r.status < 300 && r.body &&
            r.body.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + String(r.raw).slice(0, 400));
  log.debug("Leaving ok().");
  return r.body;
}

function codeFree(text) {
  log.debug("Entering codeFree().");
  log.debug("Leaving codeFree().");
  return !/STS-[A-Z0-9]+-\d{4}/.test(String(text || ""));
}

async function makeRealm(id, mode) {
  log.debug("Entering makeRealm(). " + id);
  await ok(base + "/admin-api/realms/create", { id: id,
    domain: id + ".example.net", name: "D12 " + id }, "created " + id);
  if (mode) {
    await ok(base + "/admin-api/realms/set", { id: id, key: "global.mode",
      value: mode }, "set the mode of " + id);
  }
  log.debug("Leaving makeRealm().");
  return base + "/realm/" + id;
}

function realmSet(id, key, value) {
  log.debug("Entering realmSet(). " + key + "=" + value);
  log.debug("Leaving realmSet().");
  return ok(base + "/admin-api/realms/set", { id: id, key: key,
    value: String(value) }, "set " + key + " on " + id);
}

async function codeCount(rb, code) {
  log.debug("Entering codeCount(). " + code);
  const r = await send(rb + "/admin-api/audit?per=500&code=" +
                       encodeURIComponent(code));
  log.debug("Leaving codeCount().");
  return Number((r.body && r.body.matched) || 0);
}

async function codesSettle(rb, code, atLeast) {
  log.debug("Entering codesSettle(). " + code);
  let n = await codeCount(rb, code);
  for (let i = 0; i < 20 && n < atLeast; i += 1) {
    await sleep(150);
    n = await codeCount(rb, code);
  }
  log.debug("Leaving codesSettle(). " + n);
  return n;
}

// RFC 6238 with HMAC-SHA-1, six digits, thirty seconds.
function totp(secret, offset) {
  log.debug("Entering totp().");
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = String(secret).replace(/[\s=]/g, "").toUpperCase();
  let bits = "";
  for (const ch of clean) {
    bits += alphabet.indexOf(ch).toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  const counter = Math.floor(Date.now() / 30000) + (offset || 0);
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const mac = crypto.createHmac("sha1", Buffer.from(bytes)).update(message)
    .digest();
  const at = mac[mac.length - 1] & 0xf;
  const value = ((mac[at] & 0x7f) << 24) | (mac[at + 1] << 16) |
    (mac[at + 2] << 8) | mac[at + 3];
  log.debug("Leaving totp().");
  return String(value % 1000000).padStart(6, "0");
}

function sessionCookieIn(setCookies) {
  log.debug("Entering sessionCookieIn().");
  log.debug("Leaving sessionCookieIn().");
  return (setCookies || []).some(function (one) {
    return /^(__Host-)?sts_session=[^;]+/.test(String(one));
  });
}

// A public OAuth client of the realm, with PKCE, whose redirect URI is never
// dialled: the job reads the authorization endpoint's Location instead.
async function oauthClient(rb, id, extra) {
  log.debug("Entering oauthClient(). " + id);
  await ok(rb + "/admin-api/applications/create", { identifier: id,
    name: id, protocols: ["oauth2", "oidc"],
    fields: Object.assign({ oauthClientId: [id],
      oauthRedirectUri: ["https://rp.example/" + id + "/cb"],
      oauthTokenEndpointAuthMethod: "none",
      oauthGrantType: ["authorization_code", "refresh_token"],
      oauthAllowedScope: ["openid", "profile"] }, extra || {}) },
    "registered the client " + id);
  log.debug("Leaving oauthClient().");
}

// An authorization request; answers `{ status, location, verifier }` with
// the location absolute.
async function authorize(rb, clientId, cookie, extra) {
  log.debug("Entering authorize(). " + clientId);
  const verifier = crypto.randomBytes(32).toString("base64url");
  const r = await fetch(rb + "/oauth2/authorize?" + new URLSearchParams(
    Object.assign({ response_type: "code", client_id: clientId,
      redirect_uri: "https://rp.example/" + clientId + "/cb",
      scope: "openid", state: "s" + STAMP,
      nonce: "n" + crypto.randomBytes(4).toString("hex"),
      code_challenge: crypto.createHash("sha256").update(verifier)
        .digest("base64url"),
      code_challenge_method: "S256" }, extra || {})).toString(),
    { redirect: "manual", headers: cookie ? { cookie: cookie } : {} });
  await r.text();
  const where = r.headers.get("location") || "";
  log.debug("Leaving authorize(). " + r.status);
  return { status: r.status, verifier: verifier,
           location: where ? new URL(where, rb).toString() : "" };
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
    log.debug("Caught in main() removing realms: " + ((e && e.message) || e));
    // A removal that fails does not hide the test's own verdict.
    log.info("could not remove the realms: " + e.message);
  }
  if (failure) {
    log.error("FAILED after " + checks + " check(s): " +
              (failure.stack || failure));
    log.debug("Leaving main(). Failed.");
    process.exit(1);
  }
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving main().");
}

const DEV = "asvd-" + STAMP;
const PROD = "asvp-" + STAMP;
const APP = "asv-app-" + STAMP;
const SECRET = "asv-" + STAMP + "-" + crypto.randomBytes(8).toString("hex");
const PW = "Asv-" + STAMP + "-Violet.Tractor.Maple.42";

function user(tag) {
  log.debug("Entering user(). " + tag);
  log.debug("Leaving user().");
  return ("av" + tag + STAMP).slice(0, 30);
}

async function person(rb, name) {
  log.debug("Entering person(). " + name);
  await ok(rb + "/admin-api/users/create", { username: name, invent: false,
    attributes: { cn: "Asv " + name, sn: name, givenName: ["Asv"],
                  mail: [name + "@example.test"] },
    credential: "password", password: PW }, "created " + name);
  log.debug("Leaving person().");
}

async function setUp(id, mode) {
  log.debug("Entering setUp(). " + id);
  const rb = await makeRealm(id, mode);
  if (mode === "product") {
    await realmSet(id, "authn.allowOptionalSecondFactor", true);
  }
  await realmSet(id, "risk.assessSignIns", false);
  await realmSet(id, "security.rateLimitPerAddress", 10000);
  await realmSet(id, "security.rateLimitPerIdentity", 100);
  await ok(rb + "/admin-api/applications/create", { identifier: APP,
    name: APP, protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: [APP], oauthClientSecret: SECRET,
      oauthRedirectUri: ["https://rp.example/" + APP + "/cb"],
      oauthTokenEndpointAuthMethod: "client_secret_basic",
      oauthGrantType: ["authorization_code"],
      oauthAllowedScope: ["openid"] } }, "registered " + APP);
  await ok(rb + "/admin-api/consent/grant-global-consent",
           { client: APP, scope: "openid" }, "consented openid");
  log.debug("Leaving setUp().");
  return rb;
}

function basic() {
  log.debug("Entering basic().");
  log.debug("Leaving basic().");
  return "Basic " + Buffer.from(APP + ":" + SECRET).toString("base64");
}

// A code-flow sign-in in a fresh browser: `{ cookie, tokens }`.
async function signIn(rb, who) {
  log.debug("Entering signIn(). " + who);
  const start = await authorize(rb, APP);
  const a = await authnSignin.signIn(rb, start.location,
    { action: "login", username: who, password: PW }, {});
  assert.strictEqual(a.next, "redirect", "signed in " + who + ": " +
                     String(a.text).slice(0, 300));
  const r = await fetch(a.location, { redirect: "manual",
                                      headers: { cookie: a.cookie } });
  await r.text();
  const code = new URL(String(r.headers.get("location")), rb)
    .searchParams.get("code");
  const t = await send(rb + "/oauth2/token", { method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded",
               authorization: basic() },
    body: new URLSearchParams({ grant_type: "authorization_code",
      code: String(code), code_verifier: start.verifier,
      redirect_uri: "https://rp.example/" + APP + "/cb" }).toString() });
  assert.strictEqual(t.status, 200, "tokens: " + t.raw.slice(0, 300));
  log.debug("Leaving signIn().");
  return { cookie: a.cookie, tokens: t.body };
}

async function active(rb, token) {
  log.debug("Entering active().");
  const r = await send(rb + "/oauth2/introspect", { method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded",
               authorization: basic() },
    body: new URLSearchParams({ token: token }).toString() });
  log.debug("Leaving active(). " + r.status);
  return !!(r.body && r.body.active);
}

async function sectionA(dev, prod) {
  log.debug("Entering sectionA().");
  log.info("=== A. evidence to clear a second factor ===");
  const actions = ["clear-totp", "clear-key", "clear-backup-codes",
                   "clear-email-factor"];
  const nobody = user("nb");
  await person(prod, nobody);
  await person(dev, nobody);
  for (const action of actions) {
    const none = await postJson(prod + "/admin-api/users/" + action,
                                { user: nobody });
    const short = await postJson(prod + "/admin-api/users/" + action,
                                 { user: nobody, evidence: "short" });
    const said = await postJson(prod + "/admin-api/users/" + action,
      { user: nobody, evidence: "video call, passport checked" });
    const devNone = await postJson(dev + "/admin-api/users/" + action,
                                   { user: nobody });
    check("A. product: " + action + " is refused with no evidence and with " +
          "too little, and goes on with a statement; development asks for " +
          "none", function () {
      assert.ok(none.raw.indexOf("`evidence`") >= 0, none.raw.slice(0, 200));
      assert.ok(short.raw.indexOf("`evidence`") >= 0,
                short.raw.slice(0, 200));
      assert.ok(said.raw.indexOf("`evidence`") < 0, said.raw.slice(0, 200));
      assert.ok(devNone.raw.indexOf("`evidence`") < 0,
                devNone.raw.slice(0, 200));
    });
  }
  log.debug("Leaving sectionA().");
}

async function sectionB(prod) {
  log.debug("Entering sectionB().");
  log.info("=== B. context-specific words ===");
  await realmSet(PROD, "security.passwordContextWords", "Acme,xy");
  const who = user("pw");
  await person(prod, who);
  const rows = [
    ["violet tractor maple honest river " + STAMP, true,
     "an ordinary passphrase passes"],
    ["my-acme-password-long", false, "a listed word is refused"],
    ["MY ACME PASSWORD LONG", false, "whatever its case"],
    ["a-c-m-e-password-long", false, "or its punctuation"],
    ["@cm3 password long enough", false, "or its letter swaps"],
    ["oxygen xylophone xy words " + STAMP, true,
     "a word under four letters is not looked for"],
    ["the iya-sts service password", false,
     "the service's own name is always refused"],
    ["iyasts-service-password", false, "with or without its punctuation"]
  ];
  for (const row of rows) {
    const r = await postJson(prod + "/admin-api/users/set-password",
                             { user: who, password: row[0] });
    check("B. " + row[2], function () {
      if (row[1]) {
        assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
      } else {
        assert.ok(r.status >= 400, r.raw.slice(0, 200));
        assert.ok(/known by/.test(JSON.stringify(r.body.problems || [])),
                  r.raw.slice(0, 300));
      }
    });
  }
  log.debug("Leaving sectionB().");
}

async function sectionC(dev) {
  log.debug("Entering sectionC().");
  log.info("=== C. ending every session at one instant ===");
  const who = user("se");
  await person(dev, who);
  const before = await signIn(dev, who);
  const live = await authorize(dev, APP, before.cookie);
  await sleep(1100);
  await realmSet(DEV, "authn.sessionsEndedBefore", String(Date.now()));
  await sleep(1100);
  const ended = await authorize(dev, APP, before.cookie);
  const after = await signIn(dev, who);
  const stillLive = await authorize(dev, APP, after.cookie);
  check("C1. a live session is live", function () {
    assert.ok(/[?&]code=/.test(live.location), live.location);
  });
  check("C2. a session from before authn.sessionsEndedBefore has ended",
        function () {
    assert.ok(/\/authn\/login(\?[^#]*)?[?&#]authn=/.test(ended.location),
              ended.location);
  });
  check("C3. one started after it has not", function () {
    assert.ok(/[?&]code=/.test(stillLive.location), stillLive.location);
  });
  log.debug("Leaving sectionC().");
}

async function wrongAt(rb, who) {
  log.debug("Entering wrongAt().");
  const start = await authorize(rb, APP);
  const opened = await authnSignin.screen(rb, start.location);
  const t0 = Date.now();
  const r = await authnSignin.submit(rb, start.location,
    { action: "login", username: who, password: "Wrong-" + STAMP + "-pw!" },
    { screen: opened });
  const took = Date.now() - t0;
  log.debug("Leaving wrongAt(). " + took + " ms");
  return { answer: r, ms: took };
}

async function sectionD(prod) {
  log.debug("Entering sectionD().");
  log.info("=== D. the delay after a wrong password ===");
  const who = user("dl");
  await person(prod, who);
  const tries = [];
  for (let i = 0; i < 5; i += 1) {
    tries.push(await wrongAt(prod, who));
  }
  log.info("the five wrong passwords took " + tries.map(function (one) {
    return one.ms;
  }).join(", ") + " ms");
  check("D1. each wrong password is refused, never rate limited", function () {
    tries.forEach(function (one) {
      assert.strictEqual(one.answer.next, "refused", one.answer.text);
      assert.notStrictEqual(one.answer.status, 429);
    });
  });
  // The wait comes before the comparison and is for the failures already
  // noted: none before the first, then 250 ms doubling.
  check("D2. and each answer after the first waits longer: at least 250, " +
        "500, 1000 and 2000 ms", function () {
    [250, 500, 1000, 2000].forEach(function (floor, i) {
      assert.ok(tries[i + 1].ms >= floor, (i + 1) + ": " + tries[i + 1].ms +
                " ms");
    });
  });
  const good = await signIn(prod, who);
  void good;
  const afterSuccess = await wrongAt(prod, who);
  check("D3. a success forgets it: the next wrong password waits as the " +
        "first did, not as the fifth would", function () {
    assert.ok(afterSuccess.ms < tries[4].ms - 1000,
              afterSuccess.ms + " ms against " + tries[4].ms + " ms");
  });
  log.debug("Leaving sectionD().");
}

async function sectionE(rb, mode) {
  log.debug("Entering sectionE(). " + mode);
  const P = mode === "product";
  log.info("=== E. what a sign-out ends (" + mode + ") ===");
  const who = user("so" + (P ? "p" : "d"));
  await person(rb, who);
  const one = await signIn(rb, who);
  const two = await signIn(rb, who);
  const beforeOut = [await active(rb, one.tokens.access_token),
                     await active(rb, two.tokens.access_token)];
  // "Sign out" of THIS session alone: the page's own selection. With
  // nothing selected the act signs the person out everywhere.
  const sid = JSON.parse(Buffer.from(one.tokens.id_token.split(".")[1],
                                     "base64url").toString()).sid;
  const out = await authnSignin.signOut(rb, { scope: "selected",
    select: ["session:" + sid] }, { cookie: one.cookie });
  await sleep(300);
  const firstActive = await active(rb, one.tokens.access_token);
  const secondActive = await active(rb, two.tokens.access_token);
  check("E1. " + (P ? "product revokes the access token issued on the " +
                      "session signed out of" :
                      "development leaves the signed-out session's access " +
                      "token as it was"), function () {
    assert.strictEqual(firstActive, !P);
  });
  check("E2. and another session's access token is left alone", function () {
    assert.deepStrictEqual(beforeOut, [true, true]);
    assert.strictEqual(secondActive, true, JSON.stringify(out.json ||
      out.text || "").slice(0, 400));
  });
  const hinted = await send(rb + "/oauth2/logout?" + new URLSearchParams({
    id_token_hint: one.tokens.id_token, client_id: APP }).toString());
  check("E3. the signed-out session's ID Token is still usable as an " +
        "id_token_hint", function () {
    assert.ok(hinted.status < 400, hinted.status + " " +
              hinted.raw.slice(0, 200));
  });
  const cleared = out.headers && out.headers.get
    ? out.headers.get("clear-site-data") : null;
  check("E4. the sign-out clears this origin's storage when it was the " +
        "browser's last account", function () {
    assert.strictEqual(String(cleared), "\"storage\"",
                       String(cleared) + " " + String(out.status));
  });
  log.debug("Leaving sectionE().");
}

async function test() {
  log.debug("Entering test().");
  const dev = await setUp(DEV, null);
  const prod = await setUp(PROD, "product");
  await sectionA(dev, prod);
  await sectionB(prod);
  await sectionC(dev);
  await sectionD(prod);
  await sectionE(prod, "product");
  await sectionE(dev, "development");
  log.debug("Leaving test().");
}

main();
