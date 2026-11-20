// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_authn_mechanism_enforcement.js
//
// ---------------------------------------------------------------------------
// THE SIGN-IN MECHANISMS AND SECOND FACTORS AN APPLICATION ALLOWS, ENFORCED
// AT EVERY BROWSER SIGN-IN, OVER THE WIRE (#457, #475, #1148).
//
// D12 (#444): carries over `tests/authn_mechanism_enforcement.js` and
// `tests/mfa_mechanism_enforcement.js`. Both lists are those of the named
// authentication policy an application names (`appAuthnPolicy`), written
// here through `/admin-api/policies/save-named-authn-policy` and the
// application's create, in a throwaway development realm with the wallet
// and SPNEGO sign-ins switched on:
//
//   B. a policy listing a value that is not a mechanism, or not a second
//      factor, is refused (STS-AUTHN-0533); an application naming no policy
//      of the realm is refused at the write;
//   D. one mechanism routes as the one value did (SPNEGO straight to
//      `/authn/spnego`); several draw the screen with only those offered;
//   E. a screen with nothing on it allowed draws no username or password,
//      and a password posted anyway is refused at the door, saying what it
//      allows (STS-AUTHN-0298), with no session;
//   F. OAuth: a password session for a client allowing a key or a wallet is
//      sent to sign in again (STS-OAUTH-0945), and prompt=none is
//      login_required at the client (STS-OAUTH-0946); an authenticator-app
//      session for a client allowing only a security key likewise
//      (STS-OAUTH-0952, STS-OAUTH-0953), while a password-alone session is
//      issued to;
//   G. WS-Federation: re-prompted once (STS-WSFED-0017, STS-WSFED-0022) and
//      refused when it comes back still unmet (STS-WSFED-0018,
//      STS-WSFED-0023);
//   H. (mfa D, E) somebody holding only an authenticator app, signing in to
//      an application that allows only a security key, is asked for the
//      app's code FIRST, then offered a passkey to set up and nothing else,
//      with no session in between, and let through to the registration; a
//      second factor required of somebody holding none is offered only what
//      the application allows.
//
// NOT carried, and why: sections A and C of both files (which mechanism an
// event satisfies, and `issuance_gate.check()` asked directly) are the
// process's own functions (class (d)); the SAML profiles take G's shape and
// their drivers need a signed AuthnRequest (owed with the SAML phase).
//
// OWNED HERE (local: true): this repository's authentication policy.
// ---------------------------------------------------------------------------

// An address compared by parsing it, not searched for as text
// (`url_match.js`).
const urls = require("./url_match.js");
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
var log = bunyan.createLogger({ name: "sts_authn_mechanism_enforcement",
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

const REALM = "amec-" + STAMP;
const PW = "Amec-" + STAMP + "-Correct.Horse.Battery.42";
const RP = "https://rp.amec.example";

function user(tag) {
  log.debug("Entering user(). " + tag);
  log.debug("Leaving user().");
  return ("am" + tag + STAMP).slice(0, 30);
}

async function person(rb, name) {
  log.debug("Entering person(). " + name);
  await ok(rb + "/admin-api/users/create", { username: name, invent: false,
    attributes: { cn: "Amec " + name, sn: name },
    credential: "password", password: PW }, "created " + name);
  log.debug("Leaving person().");
}

async function policy(rb, name, mechanisms, secondFactors) {
  log.debug("Entering policy(). " + name);
  const r = await postJson(rb + "/admin-api/policies/save-named-authn-policy",
    { name: name, mechanisms: mechanisms || [],
      secondFactors: secondFactors || [] });
  log.debug("Leaving policy(). " + r.status);
  return r;
}

// An OAuth client of the realm naming `policyName` (none when empty).
async function client(rb, id, policyName) {
  log.debug("Entering client(). " + id);
  const fields = { oauthClientId: [id], oauthRedirectUri: [RP + "/" + id],
    oauthTokenEndpointAuthMethod: "none",
    oauthGrantType: ["authorization_code"],
    oauthAllowedScope: ["openid"] };
  if (policyName) {
    fields.appAuthnPolicy = policyName;
  }
  const r = await postJson(rb + "/admin-api/applications/create",
    { identifier: id, name: id, protocols: ["oauth2", "oidc"],
      fields: fields });
  log.debug("Leaving client(). " + r.status);
  return r;
}

async function authz(rb, id, cookie, extra) {
  log.debug("Entering authz(). " + id);
  const verifier = crypto.randomBytes(32).toString("base64url");
  const r = await fetch(rb + "/oauth2/authorize?" + new URLSearchParams(
    Object.assign({ response_type: "code", client_id: id,
      redirect_uri: RP + "/" + id, scope: "openid", state: "s1",
      nonce: "n" + crypto.randomBytes(3).toString("hex"),
      code_challenge: crypto.createHash("sha256").update(verifier)
        .digest("base64url"),
      code_challenge_method: "S256" }, extra || {})).toString(),
    { redirect: "manual", headers: cookie ? { cookie: cookie } : {} });
  await r.text();
  log.debug("Leaving authz(). " + r.status);
  return { status: r.status, location: new URL(String(
    r.headers.get("location") || ""), rb).toString() };
}

const SCREEN = /\/authn\/login(\?[^#]*)?[?&#]authn=/;

// A browser signed in with a password (and a TOTP code where `secret` is
// given) at a client that names no policy: its cookie header.
async function session(rb, plain, name, secret) {
  log.debug("Entering session(). " + name);
  const start = await authz(rb, plain);
  let a = await authnSignin.submit(rb, start.location,
    { action: "login", username: name, password: PW }, {});
  if (a.next === "mfa" && secret) {
    const opened = await authnSignin.step(a.location, { cookie: a.cookie });
    a = await authnSignin.stepAct(opened, "totp", { code: totp(secret, 1) });
  }
  assert.strictEqual(a.next, "redirect", "a session for " + name + ": " +
                     a.text.slice(0, 300));
  log.debug("Leaving session().");
  return a.cookie;
}

async function enrolTotp(rb, plain, name) {
  log.debug("Entering enrolTotp(). " + name);
  await ok(rb + "/admin-api/users/require-mfa", { user: name },
           "required a second factor of " + name);
  const start = await authz(rb, plain);
  const a = await authnSignin.submit(rb, start.location,
    { action: "login", username: name, password: PW }, {});
  const opened = await authnSignin.step(a.location, { cookie: a.cookie });
  const begun = await authnSignin.stepAct(opened, "setup/totp", {});
  const shown = await authnSignin.step(begun.location,
                                       { cookie: opened.cookie });
  const secret = ((shown.view.setup || {}).totp || {}).secret || "";
  const done = await authnSignin.stepAct(shown, "setup/confirm",
                                         { code: totp(secret, 0) });
  assert.strictEqual(done.next, "redirect", done.text.slice(0, 300));
  await ok(rb + "/admin-api/users/stop-requiring-mfa", { user: name },
           "stopped requiring a second factor of " + name);
  log.debug("Leaving enrolTotp().");
  return secret;
}

async function sectionB(rb) {
  log.debug("Entering sectionB().");
  log.info("=== B. the field and the policy ===");
  const before = await codeCount(rb, "STS-AUTHN-0533");
  const bad = await policy(rb, "amec-bad", ["smoke-signals"]);
  const badSecond = await policy(rb, "amec-bad2", ["password"],
                                 ["carrier-pigeon"]);
  const after = await codesSettle(rb, "STS-AUTHN-0533", before + 2);
  check("B1. a policy listing a value that is not a mechanism is refused, " +
        "naming it", function () {
    assert.strictEqual(bad.status, 400, bad.raw.slice(0, 300));
    assert.ok(/smoke-signals/.test(bad.raw), bad.raw.slice(0, 300));
  });
  check("B2. and one listing a value that is not a second factor", function () {
    assert.strictEqual(badSecond.status, 400, badSecond.raw.slice(0, 300));
    assert.ok(/carrier-pigeon/.test(badSecond.raw),
              badSecond.raw.slice(0, 300));
  });
  check("B3. both recorded STS-AUTHN-0533", function () {
    assert.ok(after >= before + 2, before + " -> " + after);
  });
  const dangling = await client(rb, "amec-dangling-" + STAMP,
                                "no-such-policy");
  check("B4. an application naming no policy of the realm is refused at " +
        "the write", function () {
    assert.ok(dangling.status >= 400 || (dangling.body &&
              dangling.body.ok === false), dangling.raw.slice(0, 300));
    assert.ok(/no-such-policy/.test(dangling.raw),
              dangling.raw.slice(0, 300));
  });
  log.debug("Leaving sectionB().");
}

async function sectionDE(rb) {
  log.debug("Entering sectionDE().");
  log.info("=== D, E. where the sign-in goes, and the door ===");
  assert.strictEqual((await policy(rb, "amec-spnego", ["spnego"])).status,
                     200, "saved amec-spnego");
  const one = "amec-one-" + STAMP;
  await client(rb, one, "amec-spnego");
  const straight = await authz(rb, one);
  check("D1. one mechanism allowed routes as the one value did — SPNEGO " +
        "straight to /authn/spnego", function () {
    assert.strictEqual(straight.status, 302, straight.location);
    assert.ok(/\/authn\/spnego/.test(straight.location), straight.location);
  });
  assert.strictEqual((await policy(rb, "amec-keywallet",
                                   ["webauthn", "wallet"])).status, 200);
  const door = "amec-door-" + STAMP;
  await client(rb, door, "amec-keywallet");
  const at = await authz(rb, door);
  const screen = await authnSignin.screen(rb, at.location);
  const sv = screen.view || {};
  check("D2. several allowed draw the screen with only those: a key and " +
        "the wallet, no password, no emailed code, no Kerberos", function () {
    assert.ok(SCREEN.test(at.location), at.location);
    assert.strictEqual(screen.status, 200);
    assert.strictEqual(sv.screen, true);
    assert.strictEqual(sv.password, false);
    assert.ok(!(sv.email && (sv.email.code || sv.email.link)),
              JSON.stringify(sv.email));
    assert.ok(!sv.kerberos, JSON.stringify(sv.kerberos));
    assert.ok(sv.wallet && /\/authn\/wallet/.test(sv.wallet.href),
              JSON.stringify(sv.wallet));
    assert.strictEqual(sv.keys.primaryAllowed, true);
  });
  assert.strictEqual((await policy(rb, "amec-elsewhere",
                                   ["wallet", "spnego"])).status, 200);
  const elsewhere = "amec-else-" + STAMP;
  await client(rb, elsewhere, "amec-elsewhere");
  const bareAt = await authz(rb, elsewhere);
  const bare = await authnSignin.screen(rb, bareAt.location);
  check("E1. nothing on the screen allowed: no username or password, only " +
        "the doors it allows", function () {
    assert.strictEqual(bare.status, 200);
    assert.strictEqual(bare.view.screen, false);
    assert.ok(bare.view.wallet && /\/authn\/wallet/.test(
      bare.view.wallet.href));
  });
  const alice = user("al");
  await person(rb, alice);
  const before = await codeCount(rb, "STS-AUTHN-0298");
  const refused = await authnSignin.act(rb, "/authn-api/pending/" +
    encodeURIComponent(bare.id) + "/password",
    { username: alice, password: PW },
    { cookie: bare.cookie, csrf: bare.csrf });
  const after = await codesSettle(rb, "STS-AUTHN-0298", before + 1);
  check("E2. a password posted anyway is refused at the door, saying what " +
        "it allows, with no session, STS-AUTHN-0298", function () {
    assert.strictEqual(refused.status, 400, refused.text);
    assert.ok(/requires signing in with/.test(refused.text), refused.text);
    assert.ok(!sessionCookieIn(refused.headers.getSetCookie().filter(
      function (one) {
        return bare.setCookies.indexOf(one) < 0;
      })));
    assert.ok(after > before, before + " -> " + after);
  });
  log.debug("Leaving sectionDE().");
}

async function sectionFG(rb, plain) {
  log.debug("Entering sectionFG().");
  log.info("=== F, G. OAuth and WS-Federation re-prompt ===");
  const alice = user("fa");
  await person(rb, alice);
  const cookie = await session(rb, plain, alice);
  const oauth = "amec-oauth-" + STAMP;
  await client(rb, oauth, "amec-keywallet");
  let before = await codeCount(rb, "STS-OAUTH-0945");
  const reprompt = await authz(rb, oauth, cookie);
  let after = await codesSettle(rb, "STS-OAUTH-0945", before + 1);
  check("F1. an authorization request on a password session, for a client " +
        "allowing a key or a wallet, is sent to sign in again, " +
        "STS-OAUTH-0945", function () {
    assert.strictEqual(reprompt.status, 302);
    assert.ok(SCREEN.test(reprompt.location), reprompt.location);
    assert.ok(after > before, before + " -> " + after);
  });
  before = await codeCount(rb, "STS-OAUTH-0946");
  const passive = await authz(rb, oauth, cookie, { prompt: "none" });
  after = await codesSettle(rb, "STS-OAUTH-0946", before + 1);
  check("F2. with prompt=none it is login_required at the client instead, " +
        "STS-OAUTH-0946", function () {
    assert.strictEqual(passive.status, 302);
    assert.ok(urls.isAt(passive.location, RP + "/" + oauth) &&
              /error=login_required/.test(passive.location),
              passive.location);
    assert.ok(after > before, before + " -> " + after);
  });

  const wsrealm = "urn:amec:wsfed:" + STAMP;
  const reply = RP + "/wsfed";
  const created = await postJson(rb + "/admin-api/applications/create",
    { identifier: wsrealm, name: "amec wsfed " + STAMP,
      protocols: ["wsfed"],
      fields: { wsfedReplyUrl: [reply], appAuthnPolicy: "amec-keywallet" } });
  assert.ok(created.status < 300, "the WS-Federation application: " +
            created.raw.slice(0, 300));
  const signIn = rb + "/wsfed?wa=wsignin1.0&wtrealm=" +
    encodeURIComponent(wsrealm) + "&wreply=" + encodeURIComponent(reply);
  before = await codeCount(rb, "STS-WSFED-0017");
  const wsfed = await send(signIn, { headers: { cookie: cookie } });
  after = await codesSettle(rb, "STS-WSFED-0017", before + 1);
  check("G1. a WS-Federation sign-in on a password session is sent to sign " +
        "in again, STS-WSFED-0017", function () {
    assert.strictEqual(wsfed.status, 303, wsfed.raw.slice(0, 200));
    assert.ok(SCREEN.test(String(wsfed.headers.get("location"))),
              wsfed.headers.get("location"));
    assert.ok(after > before, before + " -> " + after);
  });
  before = await codeCount(rb, "STS-WSFED-0018");
  const back = await send(signIn + "&sts_mechanism_retry=1",
                          { headers: { cookie: cookie } });
  after = await codesSettle(rb, "STS-WSFED-0018", before + 1);
  check("G2. and refused when it comes back from that trip still unmet, " +
        "STS-WSFED-0018", function () {
    assert.strictEqual(back.status, 403, back.raw.slice(0, 200));
    assert.ok(after > before, before + " -> " + after);
  });

  log.info("=== F, G. second factors ===");
  assert.strictEqual((await policy(rb, "amec-keys-only",
    ["password", "password-mfa", "webauthn"], ["securityKey"])).status, 200);
  const fay = user("fy");
  await person(rb, fay);
  const faySecret = await enrolTotp(rb, plain, fay);
  const fayCookie = await session(rb, plain, fay, faySecret);
  const keys = "amec-keys-" + STAMP;
  await client(rb, keys, "amec-keys-only");
  before = await codeCount(rb, "STS-OAUTH-0952");
  const second = await authz(rb, keys, fayCookie);
  after = await codesSettle(rb, "STS-OAUTH-0952", before + 1);
  check("F3. an authorization request on an authenticator-app session, for " +
        "a client allowing only a security key, is sent to sign in again, " +
        "STS-OAUTH-0952", function () {
    assert.strictEqual(second.status, 302);
    assert.ok(SCREEN.test(second.location), second.location);
    assert.ok(after > before, before + " -> " + after);
  });
  before = await codeCount(rb, "STS-OAUTH-0953");
  const secondPassive = await authz(rb, keys, fayCookie, { prompt: "none" });
  after = await codesSettle(rb, "STS-OAUTH-0953", before + 1);
  check("F4. with prompt=none it is login_required, STS-OAUTH-0953",
        function () {
    assert.ok(/error=login_required/.test(secondPassive.location),
              secondPassive.location);
    assert.ok(after > before, before + " -> " + after);
  });
  const oneFactor = await authz(rb, keys, cookie);
  check("F5. a session on a password alone is issued to: the list says " +
        "which second factor, never whether one is needed", function () {
    assert.ok(urls.isAt(oneFactor.location, RP + "/" + keys) &&
              /^\?code=/.test(new URL(oneFactor.location).search),
              oneFactor.location);
  });
  const wsKeys = "urn:amec:wsfed-keys:" + STAMP;
  const made = await postJson(rb + "/admin-api/applications/create",
    { identifier: wsKeys, name: "amec wsfed keys " + STAMP,
      protocols: ["wsfed"],
      fields: { wsfedReplyUrl: [reply], appAuthnPolicy: "amec-keys-only" } });
  assert.ok(made.status < 300, made.raw.slice(0, 300));
  const keysSignIn = rb + "/wsfed?wa=wsignin1.0&wtrealm=" +
    encodeURIComponent(wsKeys) + "&wreply=" + encodeURIComponent(reply);
  before = await codeCount(rb, "STS-WSFED-0022");
  const ws2 = await send(keysSignIn, { headers: { cookie: fayCookie } });
  after = await codesSettle(rb, "STS-WSFED-0022", before + 1);
  check("G3. a WS-Federation sign-in on an authenticator-app session is " +
        "sent to sign in again, STS-WSFED-0022", function () {
    assert.strictEqual(ws2.status, 303, ws2.raw.slice(0, 200));
    assert.ok(SCREEN.test(String(ws2.headers.get("location"))));
    assert.ok(after > before, before + " -> " + after);
  });
  before = await codeCount(rb, "STS-WSFED-0023");
  const ws2back = await send(keysSignIn + "&sts_mechanism_retry=1",
                             { headers: { cookie: fayCookie } });
  after = await codesSettle(rb, "STS-WSFED-0023", before + 1);
  check("G4. and refused when it comes back still unmet, STS-WSFED-0023",
        function () {
    assert.strictEqual(ws2back.status, 403, ws2back.raw.slice(0, 200));
    assert.ok(after > before, before + " -> " + after);
  });
  log.debug("Leaving sectionFG().");
}

async function sectionH(rb, plain) {
  log.debug("Entering sectionH().");
  log.info("=== H. the proof before an enrolment, and enrolment narrowed ===");
  const dana = user("dn");
  await person(rb, dana);
  const secret = await enrolTotp(rb, plain, dana);
  const keys = "amec-keys2-" + STAMP;
  await client(rb, keys, "amec-keys-only");
  const start = await authz(rb, keys);
  const asked = await authnSignin.submit(rb, start.location,
    { action: "login", username: dana, password: PW }, {});
  const askedPage = await authnSignin.step(asked.location,
                                           { cookie: asked.cookie });
  check("H1. somebody who holds only an authenticator app is asked for ITS " +
        "code first, though the application does not allow it", function () {
    assert.strictEqual(asked.next, "mfa", asked.text);
    assert.strictEqual(askedPage.view.page, "totp");
  });
  const proved = await authnSignin.stepAct(askedPage, "totp",
                                           { code: totp(secret, 1) });
  const setupPage = proved.next === "mfa"
    ? await authnSignin.step(proved.location, { cookie: proved.cookie })
    : null;
  const setup = (setupPage && setupPage.view && setupPage.view.setup) || {};
  check("H2. and then offered a passkey to set up — only what the " +
        "application allows — and still no session", function () {
    assert.strictEqual(proved.step, "enrol", proved.text);
    assert.ok(setup.offered && setup.offered.webauthn &&
              !setup.offered.totp, JSON.stringify(setup.offered));
    assert.strictEqual(setup.proved, true);
    const values = proved.headers.getSetCookie().filter(function (one) {
      return /^(__Host-)?sts_session=[^;]+/.test(one);
    }).map(function (one) {
      return one.split(";")[0];
    });
    assert.ok(new Set(values).size <= 1, JSON.stringify(values));
  });
  const chosen = await authnSignin.stepAct(setupPage, "setup/webauthn", {});
  const chosenPage = chosen.next === "mfa"
    ? await authnSignin.step(chosen.location, { cookie: chosen.cookie })
    : null;
  check("H3. the set-up screen lets the proved person through to the " +
        "passkey registration, though they hold a factor", function () {
    assert.strictEqual(chosen.step, "webauthn", chosen.text);
    assert.strictEqual(chosenPage.status, 200);
    assert.strictEqual(chosenPage.view.webauthn.mode, "create");
  });
  assert.strictEqual((await policy(rb, "amec-apps-only",
    ["password", "password-mfa"], ["totp"])).status, 200);
  const apps = "amec-apps-" + STAMP;
  await client(rb, apps, "amec-apps-only");
  const erin = user("er");
  await person(rb, erin);
  await ok(rb + "/admin-api/users/require-mfa", { user: erin },
           "required a second factor of " + erin);
  const eStart = await authz(rb, apps);
  const e = await authnSignin.submit(rb, eStart.location,
    { action: "login", username: erin, password: PW }, {});
  const ePage = await authnSignin.step(e.location, { cookie: e.cookie });
  const offered = (ePage.view && ePage.view.setup &&
                   ePage.view.setup.offered) || {};
  check("H4. a second factor required of somebody who holds none offers " +
        "only what the application allows: an authenticator app, no passkey",
        function () {
    assert.strictEqual(ePage.status, 200, ePage.text);
    assert.strictEqual(offered.totp, true, JSON.stringify(offered));
    assert.strictEqual(offered.webauthn, false, JSON.stringify(offered));
  });
  log.debug("Leaving sectionH().");
}

async function test() {
  log.debug("Entering test().");
  const rb = await makeRealm(REALM, null);
  await realmSet(REALM, "risk.assessSignIns", false);
  await realmSet(REALM, "oid4vp.signIn", true);
  await realmSet(REALM, "krb5.spnegoAuthentication", true);
  await realmSet(REALM, "oauth2.consentRequired", false);
  await realmSet(REALM, "security.rateLimitPerAddress", 10000);
  const plain = "amec-plain-" + STAMP;
  await client(rb, plain, "");
  await sectionB(rb);
  await sectionDE(rb);
  await sectionFG(rb, plain);
  await sectionH(rb, plain);
  log.debug("Leaving test().");
}

main();
