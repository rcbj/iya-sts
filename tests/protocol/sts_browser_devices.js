// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_browser_devices.js
//
// ---------------------------------------------------------------------------
// #265: A REMEMBERED BROWSER — A DEVICE KNOWN BY A SIGNED AND ENCRYPTED
// COOKIE — OVER THE WIRE.
//
// D12 (#444): carries over `tests/browser_devices.js`, which loaded the
// whole stack in a child and read the device register and the cookie's
// claims in process. Here a person enrols an authenticator app at the
// sign-in's required set-up step (RFC 6238, computed by this file) and then
// signs in as a browser does; the device is read off `/admin-api/devices`,
// the codes off the realm's audit log. In a throwaway development realm,
// with `totp.window` 4 so each sign-in can spend a later step than the
// last (RFC 6238 section 5.2's accept-once rule):
//
//   A. the dedicated keys are published nowhere: no `sts-bd-` key in the
//      realm's JWK Set.
//   B. "Remember this browser" is offered; the person is asked for the
//      code; the finished sign-in registers a `bearer` device (method
//      `browser`, no keys) and sets the cookie, HttpOnly, SameSite=Lax,
//      Path=/; the audit log says the person asked for it.
//   C. the cookie is a compact JWE (five parts); a tampered one is not read:
//      with the skip on (F) its sign-in is asked for the code as from a
//      browser nobody remembered (STS-DEVICE-0040 is a log line only).
//   D. a bearer device cannot be marked compliant (STS-DEVICE-0039).
//   E. with the skip off, a remembered browser is still asked for the
//      second factor, and the sign-in reissues the cookie onto the same
//      device.
//   F. with the skip on (the authentication policy's
//      rememberedBrowserSkipsSecondFactor), the password alone signs in on
//      the remembered browser and the audit log says the factor was
//      skipped; the realm's console still asks.
//   G. the current cookie in ANOTHER browser is still asked, and the device
//      is not marked compromised.
//   H. a COPY — the first cookie presented after two reissues — marks the
//      device compromised (STS-DEVICE-0041, a log line only), the sign-in
//      does not reach the client, and the cookie is cleared.
//
// NOT carried (class (d)): the keys' kids and curves and the signer group
// (A1's and A2's `helpers.browserDeviceKeysFor()` and `signerGroups`: no
// answer names a key that is published nowhere), the claims the cookie
// carries (C1's `browserDevices.read()` opens a JWE only this service can
// open), the device's generation counter and recorded context (no API
// answer carries `browser`), and part I's pure halves (`browserOf()`,
// `hasSecondFactor()`).
//
// REALMS ARE LEFT STANDING (tests/CLAUDE.md, *No job removes a realm*)
// unless STS_TEST_REMOVE_REALMS=1, a private probe's switch.
//
// OWNED HERE (local: true): this repository's sign-in service and device
// register.
// ---------------------------------------------------------------------------

// An address compared by parsing it, not searched for as text
// (`url_match.js`).
const urls = require("./url_match.js");
const assert = require("assert");
const nodeCrypto = require("crypto");
const names = require("./random_username.js");
const registry = require("./sts_applications.js");
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
var log = bunyan.createLogger({ name: "sts_browser_devices",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const ORIGIN = new URL(base).origin;
const STAMP = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "")
  .slice(-10);
const REALM = "bdev-" + STAMP;
const RB = base + "/realm/" + REALM;
const API = RB + "/admin-api";
const PASSWORD = "Bdev-" + nodeCrypto.randomBytes(9).toString("base64url") +
  "-Aa1!";
const PERSON = names.usernameFor("bdev-alice");
const APP = "bdev-app-" + STAMP;
const SECRET = "bdev-secret-" + STAMP + "-" +
  nodeCrypto.randomBytes(16).toString("hex");
const REDIRECT = "https://" + APP + ".example.test/cb";
const CHROME = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36";
const FIREFOX = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) " +
  "Gecko/20100101 Firefox/132.0";
const FLOOR = 15;

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

async function call(method, url, body) {
  log.debug("Entering call(). " + method + " " + url);
  const r = await fetch(url, { method: method, redirect: "manual",
    headers: { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
    // Not JSON; `text` carries it into the message.
    json = null;
  }
  log.debug("Leaving call(). status=" + r.status);
  return { status: r.status, json: json, text: text };
}

async function ok(url, body, what) {
  log.debug("Entering ok().");
  const r = await call("POST", url, body);
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
            what + ": " + r.status + " " + r.text.slice(0, 400));
  log.debug("Leaving ok().");
  return r.json;
}

function setting(key, value) {
  log.debug("Entering setting(). " + key);
  log.debug("Leaving setting().");
  return ok(base + "/admin-api/realms/set", { id: REALM, key: key,
    value: String(value) }, "set " + key + " on " + REALM);
}

// THE CODES ARE RECORDED, NEVER SENT: read off this realm's audit log.
async function codeCount(code) {
  log.debug("Entering codeCount(). " + code);
  const r = await call("GET", API + "/audit?per=500&code=" +
                       encodeURIComponent(code));
  log.debug("Leaving codeCount().");
  return Number((r.json && r.json.matched) || 0);
}

async function codesSettle(code, atLeast) {
  log.debug("Entering codesSettle(). " + code);
  let n = await codeCount(code);
  for (let i = 0; i < 40 && n < atLeast; i += 1) {
    await sleep(150);
    n = await codeCount(code);
  }
  log.debug("Leaving codesSettle(). " + n);
  return n;
}

// The audit rows of one action by one actor.
async function actions(action, actor) {
  log.debug("Entering actions(). " + action);
  const r = await call("GET", API + "/audit?per=500&q=" +
                       encodeURIComponent(action));
  const rows = ((r.json && (r.json.events || r.json.rows)) || [])
    .filter(function (row) {
      return row.action === action && row.actor === actor;
    });
  log.debug("Leaving actions(). " + rows.length);
  return rows;
}

// RFC 6238 with HMAC-SHA-1, six digits, thirty seconds: the parameters the
// set-up step's own answer names.
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
  const mac = nodeCrypto.createHmac("sha1", Buffer.from(bytes))
    .update(message).digest();
  const at = mac[mac.length - 1] & 0xf;
  const value = ((mac[at] & 0x7f) << 24) | (mac[at + 1] << 16) |
    (mac[at + 2] << 8) | mac[at + 3];
  log.debug("Leaving totp().");
  return String(value % 1000000).padStart(6, "0");
}

// ---------------------------------------------------------------------------
// ONE BROWSER: a cookie jar, name to value, and a User-Agent.
// ---------------------------------------------------------------------------
function keepCookies(jar, lines) {
  log.debug("Entering keepCookies().");
  (lines || []).forEach(function (one) {
    const pair = String(one).split(";")[0];
    const at = pair.indexOf("=");
    if (at <= 0) {
      return;
    }
    const value = pair.slice(at + 1);
    if (value === "" || /Max-Age=0/i.test(String(one)) ||
        /Expires=Thu, 01 Jan 1970/i.test(String(one))) {
      delete jar[pair.slice(0, at)];
    } else {
      jar[pair.slice(0, at)] = value;
    }
  });
  log.debug("Leaving keepCookies().");
}

function cookieOf(jar) {
  log.debug("Entering cookieOf().");
  log.debug("Leaving cookieOf().");
  return Object.keys(jar).map(function (k) {
    return k + "=" + jar[k];
  }).join("; ");
}

function browser(ua, jar) {
  log.debug("Entering browser().");
  log.debug("Leaving browser().");
  return { ua: ua, jar: jar || {}, lines: [] };
}

async function go(b, url) {
  log.debug("Entering go().");
  const headers = { "user-agent": b.ua };
  const cookie = cookieOf(b.jar);
  if (cookie) {
    headers.cookie = cookie;
  }
  const absolute = new URL(String(url), base + "/").toString();
  const r = await fetch(absolute, { redirect: "manual", headers: headers });
  const lines = r.headers.getSetCookie ? r.headers.getSetCookie() : [];
  b.lines = b.lines.concat(lines);
  keepCookies(b.jar, lines);
  const text = await r.text();
  const location = r.headers.get("location")
    ? new URL(r.headers.get("location"), absolute).toString() : "";
  log.debug("Leaving go(). status=" + r.status);
  return { status: r.status, location: location, text: text };
}

// Follows redirects on this service; stops at the sign-in screen, at a
// step, or off the service.
async function follow(b, url) {
  log.debug("Entering follow().");
  let r = await go(b, url);
  for (let hops = 0; hops < 12; hops += 1) {
    if (r.status < 300 || r.status >= 400 || !r.location ||
        /\/authn\/login\?/.test(r.location) ||
        new URL(r.location).origin !== ORIGIN) {
      break;
    }
    r = await go(b, r.location);
  }
  log.debug("Leaving follow(). " + r.status);
  return r;
}

function authorizeUrl() {
  log.debug("Entering authorizeUrl().");
  log.debug("Leaving authorizeUrl().");
  return RB + "/oauth2/authorize?" + new URLSearchParams({
    response_type: "code", client_id: APP, redirect_uri: REDIRECT,
    scope: "openid", prompt: "login",
    state: "st-" + nodeCrypto.randomBytes(6).toString("hex"),
    nonce: "n-" + nodeCrypto.randomBytes(9).toString("base64url")
  }).toString();
}

function take(b, answer) {
  log.debug("Entering take().");
  const lines = (answer && answer.setCookies) || [];
  b.lines = b.lines.concat(lines);
  keepCookies(b.jar, lines);
  log.debug("Leaving take().");
}

// THE PASSWORD STEP of a sign-in to `start`, with "Remember this browser"
// ticked or not. Answers the screen's view, the act's answer and, where the
// act named a step, that step opened.
async function passwordStep(b, start, remember) {
  log.debug("Entering passwordStep().");
  const r = await follow(b, start);
  assert.ok(/\/authn\/login\?/.test(r.location),
            "the sign-in screen: " + r.status + " " + r.location);
  const screen = await authnSignin.screen(RB, r.location,
    { cookie: cookieOf(b.jar), headers: { "user-agent": b.ua } });
  take(b, screen);
  const fields = { action: "login", username: PERSON, password: PASSWORD };
  if (remember) {
    fields.remember_browser = "1";
  }
  const answer = await authnSignin.submit(RB, r.location, fields,
    { cookie: cookieOf(b.jar), headers: { "user-agent": b.ua },
      screen: screen });
  take(b, answer);
  let opened = null;
  if (answer.next === "mfa" && answer.location) {
    opened = await authnSignin.step(answer.location,
      { cookie: cookieOf(b.jar), headers: { "user-agent": b.ua } });
    take(b, opened);
  }
  log.debug("Leaving passwordStep(). " + answer.next);
  return { view: screen.view, answer: answer, opened: opened };
}

function asksCode(step) {
  log.debug("Entering asksCode().");
  log.debug("Leaving asksCode().");
  return !!(step.opened && step.opened.view &&
            step.opened.view.page === "totp");
}

// The one-time code, then on to wherever the sign-in goes.
async function codeStep(b, step, offset) {
  log.debug("Entering codeStep().");
  const done = await authnSignin.stepAct(step.opened, "totp",
    { code: totp(state.secret, offset) },
    { cookie: cookieOf(b.jar), headers: { "user-agent": b.ua } });
  take(b, done);
  const landed = done.next === "redirect" && done.location
    ? await follow(b, done.location) : null;
  log.debug("Leaving codeStep(). " + done.next);
  return { done: done, landed: landed };
}

function atClient(r) {
  log.debug("Entering atClient().");
  log.debug("Leaving atClient().");
  return !!(r && urls.isAt(r.location, REDIRECT) &&
            /^\?code=/.test(new URL(r.location).search));
}

const state = { secret: "", cookieName: "" };

async function devicesOfPerson() {
  log.debug("Entering devicesOfPerson().");
  const r = await call("GET", API + "/devices?per=50&owner=" +
                       encodeURIComponent(PERSON));
  log.debug("Leaving devicesOfPerson().");
  return ((r.json && r.json.devices) || []).filter(function (d) {
    return d.enrolment && d.enrolment.method === "browser";
  });
}

async function deviceById(id) {
  log.debug("Entering deviceById().");
  const r = await call("GET", API + "/devices?device=" +
                       encodeURIComponent(id));
  log.debug("Leaving deviceById().");
  return (r.json && r.json.device) || null;
}

// THE AUTHENTICATION POLICY saved whole (every row at its default, read off
// GET /admin-api/policies), with `fields` over it.
async function saveAuthnPolicy(fields) {
  log.debug("Entering saveAuthnPolicy().");
  const page = await call("GET", API + "/policies");
  const rows = (page.json && page.json.authn && page.json.authn.fields) ||
    [];
  assert.ok(rows.length, "GET /admin-api/policies answered no " +
            "authentication policy fields: " + page.text.slice(0, 200));
  const body = { profile: "default" };
  rows.forEach(function (row) {
    body[row.key] = row.default;
  });
  Object.assign(body, fields || {});
  const saved = await ok(API + "/policies/save-authn-policy", body,
                         "saved the authentication policy");
  log.debug("Leaving saveAuthnPolicy().");
  return saved;
}

async function setUp() {
  log.debug("Entering setUp().");
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "Remembered browsers " + STAMP,
    overrides: { "global.mode": "development" } }, "created the realm");
  await setting("risk.assessSignIns", false);
  await setting("authn.multipleAccounts", false);
  await setting("totp.window", 4);
  await ok(API + "/applications/create", {
    identifier: APP, name: "Remembered browsers " + STAMP,
    protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: [APP], oauthRedirectUri: [REDIRECT],
              oauthClientSecret: SECRET,
              oauthTokenEndpointAuthMethod: "client_secret_basic",
              oauthAllowedScope: ["openid"] } },
    "created the relying party");
  await ok(API + "/consent/grant-global-consent",
           { client: APP, scope: "openid" }, "consented openid");
  await registry.ensurePerson(RB, PERSON, PASSWORD);
  await ok(API + "/users/require-mfa", { user: PERSON },
           "required a second factor of the person");
  // THE AUTHENTICATOR APP, enrolled at the required set-up step.
  const b = browser(CHROME);
  const r = await follow(b, authorizeUrl());
  const login = await authnSignin.submit(RB, r.location,
    { action: "login", username: PERSON, password: PASSWORD },
    { cookie: cookieOf(b.jar), headers: { "user-agent": b.ua } });
  take(b, login);
  assert.ok(login.next === "mfa" && login.step === "enrol",
            "the required set-up step: " + JSON.stringify(login.json));
  const opened = await authnSignin.step(login.location,
    { cookie: cookieOf(b.jar) });
  const begun = await authnSignin.stepAct(opened, "setup/totp", {});
  const shown = await authnSignin.step(begun.location || login.location,
                                       { cookie: login.cookie });
  state.secret = ((shown.view.setup || {}).totp || {}).secret || "";
  const confirmed = await authnSignin.stepAct(shown, "setup/confirm",
    { code: totp(state.secret, -4) });
  assert.ok(confirmed.next === "redirect",
            "enrolling the authenticator app: " +
            JSON.stringify(confirmed.json));
  log.debug("Leaving setUp().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Remembered browsers at " + base + ", realm " + REALM);
  await setUp();

  log.info("=== A. the dedicated keys ===");
  const jwks = await call("GET", RB + "/oauth2/jwks");
  check("A. no key of the remembered browsers is in the realm's JWK Set",
        function () {
    assert.strictEqual(jwks.status, 200);
    assert.ok(jwks.text.indexOf("sts-bd-") < 0, jwks.text.slice(0, 300));
  });

  log.info("=== B. remembered at sign-in ===");
  const b1 = browser(CHROME);
  const first = await passwordStep(b1, authorizeUrl(), true);
  check("B1-2. the screen offers Remember this browser, and a person with " +
        "an authenticator app is asked for the code", function () {
    assert.ok(first.view && first.view.remember,
              JSON.stringify(first.view).slice(0, 300));
    assert.ok(asksCode(first), JSON.stringify(first.answer.json));
  });
  const firstDone = await codeStep(b1, first, -3);
  const linesFirst = b1.lines.slice();
  const remembered = await devicesOfPerson();
  const d1 = remembered[0] || {};
  state.cookieName = Object.keys(b1.jar).filter(function (k) {
    return /sts_browser/.test(k);
  })[0] || "";
  check("B3. the finished sign-in reaches the client, registers a bearer " +
        "device (method browser, no keys) and sets the cookie", function () {
    assert.ok(atClient(firstDone.landed), JSON.stringify(firstDone.done
      .json));
    assert.strictEqual(remembered.length, 1, JSON.stringify(remembered));
    assert.strictEqual(d1.attestation.level || d1.attestation, "bearer",
                       JSON.stringify(d1.attestation));
    assert.strictEqual(d1.keys.length, 0);
    assert.ok(state.cookieName, JSON.stringify(Object.keys(b1.jar)));
  });
  const askedFor = await actions("device.browser.remembered", PERSON);
  const setLine = linesFirst.filter(function (l) {
    return l.indexOf(state.cookieName + "=") === 0 &&
           !/Max-Age=0/.test(l);
  }).pop() || "";
  check("B4-5. the audit log says the person asked for it; the cookie is " +
        "HttpOnly, SameSite=Lax, Path=/", function () {
    assert.strictEqual(askedFor.length, 1, String(askedFor.length));
    assert.ok(/HttpOnly/.test(setLine) && /SameSite=Lax/.test(setLine) &&
              /Path=\//.test(setLine), setLine);
  });

  log.info("=== C. the token ===");
  const gen1 = b1.jar[state.cookieName];
  const parts = String(gen1).split(".");
  check("C1. the cookie is a compact JWE: five parts", function () {
    assert.strictEqual(parts.length, 5, String(gen1).slice(0, 80));
  });
  log.info("=== D. never compliant ===");
  const notCompliant = await codeCount("STS-DEVICE-0039");
  const compliant = await call("POST", API + "/devices/set-compliance",
    { id: d1.id, status: "compliant", reason: "D12" });
  const notCompliantAfter = await codesSettle("STS-DEVICE-0039",
                                              notCompliant + 1);
  check("D. a bearer device cannot be marked compliant (STS-DEVICE-0039)",
        function () {
    assert.strictEqual(compliant.status, 400, compliant.text.slice(0, 300));
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(compliant.text), compliant.text);
    assert.ok(notCompliantAfter > notCompliant,
              notCompliant + " -> " + notCompliantAfter);
  });

  log.info("=== E. skip off: still asked ===");
  const b1e = browser(CHROME, {});
  b1e.jar[state.cookieName] = gen1;
  const second = await passwordStep(b1e, authorizeUrl(), false);
  check("E1. with the skip off, a remembered browser is still asked for " +
        "the second factor", function () {
    assert.ok(asksCode(second), JSON.stringify(second.answer.json));
  });
  await codeStep(b1e, second, -2);
  const gen2 = b1e.jar[state.cookieName];
  const stillOne = await devicesOfPerson();
  check("E2. the sign-in reissued the cookie, onto the same device",
        function () {
    assert.ok(gen2 && gen2 !== gen1, "no new cookie");
    assert.strictEqual(stillOne.length, 1, JSON.stringify(stillOne));
    assert.strictEqual(stillOne[0].id, d1.id);
  });

  log.info("=== F. skip on ===");
  await saveAuthnPolicy({ rememberedBrowserSkipsSecondFactor: true });
  const b1f = browser(CHROME, {});
  b1f.jar[state.cookieName] = gen2;
  const third = await passwordStep(b1f, authorizeUrl(), false);
  const landed = third.answer.next === "redirect"
    ? await follow(b1f, third.answer.location) : null;
  const skipped = await actions("authn.second-factor.skipped", PERSON);
  check("F1. with the skip on, the password alone signs in on the " +
        "remembered browser, and the audit log says the factor was skipped",
        function () {
    assert.ok(atClient(landed), third.answer.next + " " +
              JSON.stringify(third.answer.json).slice(0, 300));
    assert.strictEqual(skipped.length, 1, String(skipped.length));
  });
  const gen3 = b1f.jar[state.cookieName];
  check("F2. and the cookie was issued again", function () {
    assert.ok(gen3 && gen3 !== gen2, "no third cookie");
  });
  // C2 is asked HERE, with the skip on, so that being asked for the code
  // says the tampered cookie was not read.
  const tamperedParts = parts.slice();
  tamperedParts[3] = tamperedParts[3].slice(0, -2) +
    (tamperedParts[3].slice(-2) === "AA" ? "BB" : "AA");
  // STS-DEVICE-0040 is a log line only, with no audit row: what a client
  // sees is the cookie cleared and the browser treated as unrecognised.
  const bt = browser(CHROME, {});
  bt.jar[state.cookieName] = tamperedParts.join(".");
  const tampered = await passwordStep(bt, authorizeUrl(), false);
  check("C2. with the skip on, a tampered cookie is not read: the " +
        "sign-in is asked for the code, as from a browser nobody remembered",
        function () {
    assert.ok(asksCode(tampered), JSON.stringify(tampered.answer.json));
  });

  const consoleBrowser = browser(CHROME, {});
  consoleBrowser.jar[state.cookieName] = gen3;
  await go(consoleBrowser, RB + "/admin");
  const verifier = nodeCrypto.randomBytes(32).toString("base64url");
  const consoleAuthorize = RB + "/oauth2/authorize?" + new URLSearchParams({
    client_id: "sts-admin-console", response_type: "code",
    redirect_uri: RB + "/admin/callback",
    scope: "openid admin:read admin:write", state: "s",
    code_challenge: nodeCrypto.createHash("sha256").update(verifier)
      .digest("base64url"),
    code_challenge_method: "S256" }).toString();
  const atConsole = await passwordStep(consoleBrowser, consoleAuthorize,
                                       false);
  check("F3. the realm's console still asks, remembered browser or not",
        function () {
    assert.ok(asksCode(atConsole), JSON.stringify(atConsole.answer.json)
      .slice(0, 300));
  });

  log.info("=== G. another browser ===");
  const b2 = browser(FIREFOX, {});
  b2.jar[state.cookieName] = gen3;
  const moved = await passwordStep(b2, authorizeUrl(), false);
  const afterMove = await deviceById(d1.id);
  check("G. the current cookie in another browser is still asked, and is " +
        "not taken for a copy", function () {
    assert.ok(asksCode(moved), JSON.stringify(moved.answer.json));
    assert.strictEqual(afterMove.status, "active");
  });

  log.info("=== H. a copy ===");
  const b3 = browser(CHROME, {});
  b3.jar[state.cookieName] = gen1;
  const copy = await passwordStep(b3, authorizeUrl(), false);
  const copyDone = asksCode(copy) ? await codeStep(b3, copy, -1) : null;
  const compromised = await deviceById(d1.id);
  const cleared = b3.lines.some(function (l) {
    return l.indexOf(state.cookieName + "=") === 0 &&
           (/Max-Age=0/i.test(l) || /=;/.test(l));
  });
  // STS-DEVICE-0041 is a log line only; the device's status is the
  // observable.
  check("H1. the first cookie presented after two reissues is a copy: the " +
        "device is compromised", function () {
    assert.strictEqual(compromised.status, "compromised");
  });
  check("H2. the sign-in does not reach the client, and the cookie is " +
        "cleared", function () {
    assert.ok(!atClient(copyDone && copyDone.landed),
              "the copy reached the client");
    assert.ok(cleared, JSON.stringify(b3.lines));
    assert.ok(!b3.jar[state.cookieName], "the cookie is still held");
  });

  await saveAuthnPolicy({});
  assert.ok(checks >= FLOOR, "only " + checks + " checks ran");
  log.info(checks + " check(s) passed.");
  log.debug("Leaving test().");
}

// REMOVAL IS OPT-IN: with STS_TEST_REMOVE_REALMS=1 (a private probe that
// would otherwise fill its directory) the realm is removed at the end, pass
// or fail. A suite run leaves it standing (tests/CLAUDE.md, *No job removes
// a realm*).
async function removeRealms() {
  log.debug("Entering removeRealms().");
  if (process.env.STS_TEST_REMOVE_REALMS !== "1") {
    log.debug("Leaving removeRealms(). Not asked to.");
    return;
  }
  const r = await call("POST", base + "/admin-api/realms/remove",
                       { id: REALM });
  log.info("removed the realm " + REALM + " (" + r.status + ")");
  log.debug("Leaving removeRealms().");
}

async function main() {
  log.debug("Entering main().");
  let failure = null;
  try {
    await test();
  } catch (e) {
    log.debug("Caught in main(): " + ((e && e.message) || e));
    // Reported below, after the realm is removed.
    failure = e;
  }
  try {
    await removeRealms();
  } catch (e) {
    log.debug("Caught in main(): " + ((e && e.message) || e));
    log.info("could not remove the realm: " + ((e && e.message) || e));
  }
  if (failure) {
    log.error(failure.stack || failure.message);
    log.debug("Leaving main(). Failed.");
    process.exit(1);
  }
  log.info("Test completed successfully.");
  log.debug("Leaving main().");
}

main();
