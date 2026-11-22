// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_credential_removal_sessions.js
//
// ---------------------------------------------------------------------------
// REMOVING A CREDENTIAL ENDS THE SESSIONS IT SIGNED IN, AND NO OTHER, OVER
// THE WIRE (#722).
//
// D12 (#444): carries over `tests/credential_removal_sessions.js`. In a
// development realm of its own, with REAL ceremonies — passkeys from this
// job's software authenticator (`passkey_wire_kit.js`) registered at the
// portal, an RFC 6238 code computed from the secret the portal shows,
// recovery codes the portal generated — and real code and refresh grants:
//
//   1. THE PORTAL'S REMOVE (`POST /account-api/keys/remove`): a person signs
//      in with key A in one browser and key B in another, each holding a
//      refresh token. Removing A answers 200 with `sessionsEnded` 1 and a
//      sentence saying so; A's browser is no longer signed in and its
//      refresh token is invalid_grant; B's session and refresh token work.
//   2. THE API'S `clear-key`, the same for another person.
//   3. `clear-totp`: the session the authenticator app completed ends; a
//      password-only session of the same person, made before the app was
//      set up, stays.
//   4. `clear-backup-codes`: the session a recovery code completed ends;
//      the one the app completed stays.
//   6. a removal that signed in none of a person's sessions answers 0.
//
// NOT carried, and why: 1b, 2b and 1g (the audit row's count, the logout
// model's own record) are the store's (class (d)); 5 (the emailed second
// factor and an emailed sign-in link) needs a realm that can send mail and
// a catcher to read the code from, which no stack here provides (owed with
// the mail family); the portal's TOTP `remove` and the console's form are
// the same door as `clear-totp` behind another surface.
//
// OWNED HERE (local: true): this repository's own sign-in and portal.
// ---------------------------------------------------------------------------

// An address compared by parsing it, not searched for as text
// (`url_match.js`).
const urls = require("./url_match.js");
// The sign-in screen over `/authn-api` (#571).
const authnSignin = require("./authn_signin");
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
var log = bunyan.createLogger({ name: "sts_credential_removal_sessions",
                                level: appconfig.LOG_LEVEL ||
                                       process.env.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "")
  .slice(-10);
// A password this process made: product checks it.
const PASSWORD = "CredRm-" + nodeCrypto.randomBytes(9).toString("base64url") +
  "-9a!";
// A desktop browser's User-Agent with this job's name on the end: risk
// scoring reads a bare job name as an automated client, and product refuses
// a first sign-in from one (#62).
const AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 " +
  "sts_credential_removal_sessions/1.0 (" + STAMP + ")";

let checks = 0;
const failures = [];

// ONE CHECK. A failure is recorded and the run carries on; setup that later
// sections depend on uses `must()`, which throws.
async function check(what, fn) {
  log.debug("Entering check(). " + what);
  try {
    await fn();
    checks += 1;
    log.info("  [ok] " + what);
  } catch (e) {
    log.debug("Caught in check(): " + ((e && e.message) || e));
    failures.push(what + " — " + ((e && e.message) || e));
    log.error("  [FAILED] " + what + "  — " + ((e && e.message) || e));
  }
  log.debug("Leaving check().");
}

function must(condition, message) {
  log.debug("Entering must().");
  if (!condition) {
    log.debug("Leaving must(). Refused.");
    throw new Error("SETUP: " + message);
  }
  log.debug("Leaving must().");
}

function expect(condition, message) {
  log.debug("Entering expect().");
  if (!condition) {
    log.debug("Leaving expect(). Refused.");
    throw new Error(String(message));
  }
  log.debug("Leaving expect().");
}

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

function form(o) {
  log.debug("Entering form().");
  log.debug("Leaving form().");
  return new URLSearchParams(o).toString();
}

function realmBase(realm) {
  log.debug("Entering realmBase().");
  log.debug("Leaving realmBase().");
  return base + "/realm/" + realm;
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
           location: r.headers.get("location") || "", headers: r.headers };
}

function postJson(url, payload) {
  log.debug("Entering postJson().");
  log.debug("Leaving postJson().");
  return send(url, { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}) });
}

// The management API of a realm (`realm` null: the root's). The run's admin
// token is attached by the preload (`tools/attach-admin-token.js`).
function api(realm, method, p, payload) {
  log.debug("Entering api(). " + method + " " + p);
  const url = (realm ? realmBase(realm) : base) + "/admin-api" + p;
  log.debug("Leaving api().");
  if (method === "GET") {
    return send(url);
  }
  return postJson(url, payload);
}

async function apiOk(realm, p, payload, what) {
  log.debug("Entering apiOk(). " + p);
  const r = await api(realm, "POST", p, payload);
  must(r.status === 200 && r.body && r.body.ok !== false,
       (what || p) + " answered " + r.status + " " + r.raw.slice(0, 400));
  log.debug("Leaving apiOk().");
  return r.body;
}

const MADE = [];
async function makeRealm(stem, mode) {
  log.debug("Entering makeRealm(). " + stem);
  const id = (stem + "-" + STAMP).slice(0, 31);
  await apiOk(null, "/realms/create", { id: id, domain: id + ".example.net",
    name: stem + " " + STAMP }, "created the realm " + id);
  MADE.push(id);
  await apiOk(null, "/realms/set", { id: id, key: "global.mode",
    value: mode }, "set " + id + " to " + mode);
  log.debug("Leaving makeRealm(). " + id);
  return id;
}

function setting(realm, key, value) {
  log.debug("Entering setting(). " + key + "=" + value);
  log.debug("Leaving setting().");
  return apiOk(null, "/realms/set", { id: realm, key: key,
    value: String(value) }, "set " + key + " on " + realm);
}

async function createPerson(realm, username, extra) {
  log.debug("Entering createPerson(). " + username);
  const body = await apiOk(realm, "/users/create", Object.assign({
    username: username, invent: false,
    attributes: { cn: "Probe " + username, givenName: "Probe",
                  sn: username, mail: username + "@" + realm + ".example" },
    credential: "password", password: PASSWORD }, extra || {}),
  "created " + username);
  log.debug("Leaving createPerson().");
  return body;
}

// How many of a realm's audit rows carry `code`.
async function codeCount(realm, code) {
  log.debug("Entering codeCount(). " + code);
  const r = await api(realm, "GET", "/audit?per=500&code=" +
                      encodeURIComponent(code));
  const b = r.body && typeof r.body === "object" ? r.body : {};
  const rows = b.rows || b.events || [];
  const n = typeof b.matched === "number" ? b.matched : rows.length;
  log.debug("Leaving codeCount(). " + n);
  return n;
}

// Whether a new row with `code` arrived since `before`: the row is written
// as the response finishes, so the read after it may need a moment.
async function newRowWith(realm, code, before) {
  log.debug("Entering newRowWith(). " + code);
  let after = await codeCount(realm, code);
  for (let i = 0; i < 30 && after <= before; i += 1) {
    await sleep(200);
    after = await codeCount(realm, code);
  }
  log.debug("Leaving newRowWith(). " + before + " -> " + after);
  return after > before;
}

// A browser: a cookie jar (a plain object, which `authn_signin.js` writes
// back into) and redirects left to the caller.
function browser() {
  log.debug("Entering browser().");
  const jar = {};
  const self = {
    jar: jar,
    cookie: function cookieOf() {
      log.debug("Entering cookieOf().");
      log.debug("Leaving cookieOf().");
      return Object.keys(jar).map(function (k) {
        return k + "=" + jar[k];
      }).join("; ");
    },
    go: async function go(method, url, body, extra) {
      log.debug("Entering go(). " + method + " " + url);
      const headers = Object.assign({ "User-Agent": AGENT }, extra || {});
      const cookie = self.cookie();
      if (cookie) {
        headers.cookie = cookie;
      }
      if (body !== undefined) {
        headers["Content-Type"] = "application/x-www-form-urlencoded";
      }
      const absolute = /^https?:\/\//i.test(url) ? url : base + url;
      const r = await fetch(absolute, { method: method, redirect: "manual",
                                        headers: headers, body: body });
      const set = r.headers.getSetCookie ? r.headers.getSetCookie() : [];
      set.forEach(function (one) {
        const pair = String(one).split(";")[0];
        const at = pair.indexOf("=");
        if (at <= 0) {
          return;
        }
        const value = pair.slice(at + 1);
        if (value === "" || /Expires=Thu, 01 Jan 1970/i.test(String(one))) {
          delete jar[pair.slice(0, at)];
        } else {
          jar[pair.slice(0, at)] = value;
        }
      });
      const text = await r.text();
      log.debug("Leaving go(). status=" + r.status);
      return { status: r.status, location: r.headers.get("location") || "",
               text: text, url: absolute };
    }
  };
  log.debug("Leaving browser().");
  return self;
}

function sentToSignIn(r) {
  log.debug("Entering sentToSignIn().");
  log.debug("Leaving sentToSignIn().");
  return (r.status === 302 || r.status === 303) &&
    /\/authn\/login(?:\?app=[^#]*)?[?#]authn=/.test(r.location);
}

function decode(token) {
  log.debug("Entering decode().");
  const parts = String(token || "").split(".");
  log.debug("Leaving decode().");
  return JSON.parse(Buffer.from(parts[1] || "", "base64url")
    .toString("utf8") || "{}");
}

function pkce() {
  log.debug("Entering pkce().");
  const verifier = nodeCrypto.randomBytes(32).toString("base64url");
  log.debug("Leaving pkce().");
  return { verifier: verifier,
           challenge: nodeCrypto.createHash("sha256").update(verifier)
             .digest("base64url") };
}

// REMOVAL IS OPT-IN: with STS_TEST_REMOVE_REALMS=1 (a private probe that
// would otherwise fill its directory) every realm this run made is removed
// at the end, pass or fail. A suite run leaves them standing
// (tests/CLAUDE.md, *No job removes a realm*).
async function removeRealms() {
  log.debug("Entering removeRealms().");
  if (process.env.STS_TEST_REMOVE_REALMS !== "1") {
    log.debug("Leaving removeRealms(). Not asked to.");
    return;
  }
  for (const id of MADE) {
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
    // A failed removal leaves a realm on a private probe; it is not the
    // job's verdict.
    log.warn("removing the realms failed: " + ((e && e.message) || e));
  }
  if (failure) {
    log.error("Test failed: " + ((failure && failure.stack) || failure));
    log.debug("Leaving main(). Failed.");
    process.exit(1);
  }
  if (failures.length) {
    log.error(failures.length + " check(s) FAILED:\n  " +
              failures.join("\n  "));
    log.debug("Leaving main(). Failed.");
    process.exit(1);
  }
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving main().");
}


const wire = require("./passkey_wire_kit.js");
const portalSignin = require("./portal_signin.js");

const k = wire.kit("sts_credential_removal_sessions", { log: log });
const RP = "crs-rp-" + STAMP;
const REDIRECT = "https://rp-" + STAMP + ".crs.example/cb";
const HEADERS = { "User-Agent": AGENT };
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
let REALM = "";

function base32(text) {
  log.debug("Entering base32().");
  const cleaned = String(text).toUpperCase().replace(/[\s=-]/g, "");
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of cleaned) {
    value = (value << 5) | B32.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  log.debug("Leaving base32().");
  return Buffer.from(out);
}

// RFC 6238 with SHA-1, six digits, thirty seconds, `step` periods ahead.
function totp(secret, step) {
  log.debug("Entering totp().");
  const counter = Math.floor(Date.now() / 30000) + (step || 0);
  const msg = Buffer.alloc(8);
  msg.writeUInt32BE(Math.floor(counter / 4294967296), 0);
  msg.writeUInt32BE(counter % 4294967296, 4);
  const mac = nodeCrypto.createHmac("sha1", base32(secret)).update(msg)
    .digest();
  const off = mac[mac.length - 1] & 15;
  const n = (mac.readUInt32BE(off) & 0x7fffffff) % 1000000;
  log.debug("Leaving totp().");
  return String(n).padStart(6, "0");
}

function jarFrom(b, cookieHeader) {
  log.debug("Entering jarFrom().");
  String(cookieHeader || "").split(/;\s*/).forEach(function (pair) {
    const at = pair.indexOf("=");
    if (at > 0) {
      b.jar[pair.slice(0, at)] = pair.slice(at + 1);
    }
  });
  log.debug("Leaving jarFrom().");
}

function authorizeUrl(p) {
  log.debug("Entering authorizeUrl().");
  log.debug("Leaving authorizeUrl().");
  return realmBase(REALM) + "/oauth2/authorize?" + form({ client_id: RP,
    response_type: "code", redirect_uri: REDIRECT,
    scope: "openid offline_access", state: "s",
    nonce: "n" + nodeCrypto.randomBytes(8).toString("hex"),
    code_challenge: p.challenge, code_challenge_method: "S256" });
}

// A sign-in in a browser of its own: `how` is "passkey" (`key` the
// authenticator), "password", "totp" (`secret`) or "code" (`code`, a
// recovery code). `{ b, refresh, shown }`.
async function signIn(who, how, given) {
  log.debug("Entering signIn(). " + who + " " + how);
  const g = given || {};
  const b = browser();
  const p = pkce();
  const first = await b.go("GET", authorizeUrl(p));
  must(sentToSignIn(first), "no screen: " + first.status + " " +
       first.location);
  const at = new URL(first.location, realmBase(REALM) + "/").toString();
  const page = await authnSignin.screen(realmBase(REALM), at,
    { cookie: b.cookie(), headers: HEADERS });
  let answer = await authnSignin.submit(realmBase(REALM), at,
    { action: "login", username: who,
      password: how === "passkey" ? "" : PASSWORD,
      webauthn_only: how === "passkey" ? "1" : "" },
    { screen: page, cookie: page.cookie, headers: HEADERS });
  if (answer.next === "mfa" && answer.location) {
    const pageName = how === "code" ? "backup-code" : undefined;
    const st = await authnSignin.step(answer.location,
      { cookie: answer.cookie, headers: HEADERS, page: pageName });
    if (how === "passkey") {
      answer = await authnSignin.passkeyStep(st, function (c) {
        return g.key.assert(c.challenge);
      }, { headers: HEADERS });
    } else if (how === "totp") {
      answer = await authnSignin.stepAct(st, "totp",
        { code: totp(g.secret, g.step || 0) }, { headers: HEADERS });
    } else if (how === "code") {
      answer = await authnSignin.stepAct(st, "backup-code",
        { code: g.code }, { headers: HEADERS });
    }
  }
  jarFrom(b, answer.cookie);
  let final = { status: answer.status, location: "" };
  if (answer.next === "redirect" && answer.location) {
    final = await b.go("GET", answer.location);
    if (/\/oauth2\/authorize\?/.test(final.location)) {
      final = await b.go("GET", new URL(final.location,
        realmBase(REALM) + "/").toString());
    }
  }
  must(urls.isAt(final.location, REDIRECT), who + " " + how +
       " did not come back with a code: " + answer.status + " " +
       answer.next + " " + JSON.stringify(answer.errors || []) + " " +
       final.status + " " + final.location);
  const t = await send(realmBase(REALM) + "/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form({ grant_type: "authorization_code",
      code: new URL(final.location).searchParams.get("code"),
      redirect_uri: REDIRECT, client_id: RP, code_verifier: p.verifier }) });
  must(t.body && t.body.refresh_token, "no refresh token: " +
       t.raw.slice(0, 300));
  log.debug("Leaving signIn().");
  return { b: b, refresh: t.body.refresh_token };
}

async function signedIn(s) {
  log.debug("Entering signedIn().");
  const r = await s.b.go("GET", authorizeUrl(pkce()));
  log.debug("Leaving signedIn(). " + r.status);
  return urls.isAt(r.location, REDIRECT) && /[?&]code=/.test(r.location);
}

async function refreshes(s) {
  log.debug("Entering refreshes().");
  const r = await send(realmBase(REALM) + "/oauth2/token", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form({ grant_type: "refresh_token", refresh_token: s.refresh,
                 client_id: RP }) });
  if (r.status === 200 && r.body && r.body.refresh_token) {
    s.refresh = r.body.refresh_token;
  }
  log.debug("Leaving refreshes(). " + r.status);
  return { ok: r.status === 200,
           error: (r.body && r.body.error) || "", status: r.status };
}

async function portalOf(who) {
  log.debug("Entering portalOf(). " + who);
  log.debug("Leaving portalOf().");
  return portalSignin.signInToThePortal(realmBase(REALM), who, null,
                                        { password: PASSWORD });
}

async function keySections() {
  log.debug("Entering keySections().");
  log.info("=== 1. the portal's remove ===");
  const alice = names.usernameFor("crsa");
  await createPerson(REALM, alice);
  const alicePortal = await portalOf(alice);
  const keyA = k.authenticator({});
  const keyB = k.authenticator({});
  for (const key of [keyA, keyB]) {
    const e = await k.enrol(alicePortal, key, {});
    must(e.done && e.done.status === 200, "enrolling: " +
         JSON.stringify(e.done && e.done.json).slice(0, 300));
  }
  const inA = await signIn(alice, "passkey", { key: keyA });
  const inB = await signIn(alice, "passkey", { key: keyB });
  await check("1. (precondition) both sessions sign their browser in",
              async function () {
    expect(await signedIn(inA) && await signedIn(inB), "not both");
  });
  const removed = await alicePortal.api("POST", "/account-api/keys/remove",
    { credentialId: keyA.credentialId });
  await check("1a. removing key A at the portal answers 200, sessionsEnded " +
              "1, and says so", async function () {
    expect(removed.status === 200 && removed.json &&
           Number(removed.json.sessionsEnded) === 1,
           removed.status + " " + JSON.stringify(removed.json)
             .slice(0, 300));
    expect(/session/i.test(String(removed.json.message || "")),
           JSON.stringify(removed.json).slice(0, 300));
  });
  await check("1c. key A's browser is no longer signed in",
              async function () {
    expect(!(await signedIn(inA)), "still signed in");
  });
  const aRefresh = await refreshes(inA);
  await check("1d. and the refresh token issued on it is refused " +
              "(invalid_grant)", async function () {
    expect(!aRefresh.ok && aRefresh.error === "invalid_grant",
           JSON.stringify(aRefresh));
  });
  const bRefresh = await refreshes(inB);
  await check("1e, 1f. key B's session still signs its browser in, and its " +
              "refresh token still works", async function () {
    expect(await signedIn(inB), "B's browser is not signed in");
    expect(bRefresh.ok, JSON.stringify(bRefresh));
  });

  log.info("=== 2. the API's clear-key ===");
  const bob = names.usernameFor("crsb");
  await createPerson(REALM, bob);
  const bobPortal = await portalOf(bob);
  const keyC = k.authenticator({});
  const keyD = k.authenticator({});
  for (const key of [keyC, keyD]) {
    const e = await k.enrol(bobPortal, key, {});
    must(e.done && e.done.status === 200, "enrolling: " +
         JSON.stringify(e.done && e.done.json).slice(0, 300));
  }
  const inC = await signIn(bob, "passkey", { key: keyC });
  const inD = await signIn(bob, "passkey", { key: keyD });
  const cleared = await api(REALM, "POST", "/users/clear-key",
    { user: bob, credentialId: keyC.credentialId });
  await check("2a. clear-key answers ok with sessionsEnded 1",
              async function () {
    expect(cleared.status === 200 && cleared.body &&
           Number(cleared.body.sessionsEnded) === 1,
           cleared.status + " " + cleared.raw.slice(0, 300));
  });
  const cRefresh = await refreshes(inC);
  await check("2c. key C's session and refresh token end",
              async function () {
    expect(!(await signedIn(inC)), "C's browser is still signed in");
    expect(!cRefresh.ok, JSON.stringify(cRefresh));
  });
  await check("2d. key D's session stays", async function () {
    expect(await signedIn(inD), "D's browser is not signed in");
  });

  log.info("=== 6. a removal that signed nobody in ===");
  const erin = names.usernameFor("crse");
  await createPerson(REALM, erin);
  const erinPortal = await portalOf(erin);
  const keyE = k.authenticator({});
  const e = await k.enrol(erinPortal, keyE, {});
  must(e.done && e.done.status === 200, "enrolling erin's key");
  const none = await erinPortal.api("POST", "/account-api/keys/remove",
    { credentialId: keyE.credentialId });
  await check("6. removing a key that signed in none of a person's " +
              "sessions answers 0, and the portal's session stays",
              async function () {
    expect(none.status === 200 && none.json &&
           Number(none.json.sessionsEnded) === 0,
           none.status + " " + JSON.stringify(none.json).slice(0, 300));
    const still = await erinPortal.api("GET", "/account-api/keys");
    expect(still.status === 200, "the portal's own session ended: " +
           still.status);
  });
  log.debug("Leaving keySections().");
}

async function factorSections() {
  log.debug("Entering factorSections().");
  log.info("=== 3, 4. the authenticator app and the recovery codes ===");
  const carol = names.usernameFor("crsc");
  await createPerson(REALM, carol);
  const plain = await signIn(carol, "password");
  const portal = await portalOf(carol);
  const started = await portal.api("POST", "/account-api/mfa",
                                   { action: "start" });
  must(started.status === 200, "start: " + started.status);
  const viewed = await portal.api("GET", "/account-api/mfa");
  const secret = String((viewed.json && viewed.json.setup &&
                         viewed.json.setup.grouped) || "");
  must(secret.length >= 16, "no secret: " + JSON.stringify(viewed.json)
    .slice(0, 300));
  const confirmed = await portal.api("POST", "/account-api/mfa",
    { action: "confirm", code: totp(secret, 0) });
  must(confirmed.status === 200 && confirmed.json && confirmed.json.ok,
       "confirm: " + confirmed.status + " " +
       JSON.stringify(confirmed.json).slice(0, 300));
  const generated = await portal.api("POST", "/account-api/mfa",
                                     { action: "generate-codes" });
  const g = generated.json || {};
  const fresh = (g.view && g.view.fresh) || {};
  const codes = fresh.codes || [];
  const handle = fresh.handle || "";
  must(codes.length && handle, "generate-codes: " +
       JSON.stringify(g).slice(0, 300));
  const kept = await portal.api("POST", "/account-api/mfa",
    { action: "confirm-codes", handle: handle });
  must(kept.status === 200, "confirm-codes: " + kept.status + " " +
       JSON.stringify(kept.json).slice(0, 300));
  // The next period's code: the one the confirm spent is not taken twice.
  const byApp = await signIn(carol, "totp", { secret: secret, step: 1 });
  const byCode = await signIn(carol, "code", { code: String(codes[0]) });

  const clearCodes = await api(REALM, "POST", "/users/clear-backup-codes",
                               { user: carol });
  await check("4. clear-backup-codes answers sessionsEnded 1",
              async function () {
    expect(clearCodes.status === 200 && clearCodes.body &&
           Number(clearCodes.body.sessionsEnded) === 1,
           clearCodes.status + " " + clearCodes.raw.slice(0, 300));
  });
  await check("4. the session a recovery code completed ends; the one the " +
              "app completed stays", async function () {
    expect(!(await signedIn(byCode)), "the recovery code's session stays");
    expect(await signedIn(byApp), "the app's session ended");
  });
  const clearApp = await api(REALM, "POST", "/users/clear-totp",
                             { user: carol });
  await check("3a. clear-totp answers sessionsEnded 1, and ends the session " +
              "the app completed", async function () {
    expect(clearApp.status === 200 && clearApp.body &&
           Number(clearApp.body.sessionsEnded) === 1,
           clearApp.status + " " + clearApp.raw.slice(0, 300));
    expect(!(await signedIn(byApp)), "the app's session stays");
  });
  await check("3. a password-only session of the same person stays",
              async function () {
    expect(await signedIn(plain), "the password session ended");
  });
  log.debug("Leaving factorSections().");
}

async function test() {
  log.debug("Entering test().");
  REALM = await makeRealm("crs", "development");
  await apiOk(REALM, "/applications/create", { identifier: RP, name: RP,
    kind: "oauth2-client", protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: [RP], oauthRedirectUri: [REDIRECT],
              oauthGrantType: ["authorization_code", "refresh_token"],
              oauthResponseType: ["code"],
              oauthAllowedScope: ["openid", "offline_access"],
              oauthTokenEndpointAuthMethod: "none" } }, "the client");
  for (const one of ["openid", "offline_access"]) {
    await apiOk(REALM, "/consent/grant-global-consent",
                { client: RP, scope: one }, "consented " + one);
  }
  await keySections();
  await factorSections();
  log.debug("Leaving test().");
}

main();
