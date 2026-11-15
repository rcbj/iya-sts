// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_consent_rules.js
//
// ---------------------------------------------------------------------------
// TWO RULES OF THE CONSENT SCREEN, AS A BROWSER MEETS THEM.
//
// D12 (#444): carries over tests/consent_public_client_once.js and
// tests/consent_claim_by_owner.js.
//
//   1. A PUBLIC CLIENT IS ASKED EVERY TIME (ASVS 5.0.0 10.7.1), in a
//      development realm with `oauth2.consentAlwaysForPublicClients` on and
//      one account per browser: the sign-in, the screen, Allow, and the pass
//      that follows issues a code with no second ask (the loop the file
//      exists for); a NEW request by the same client is asked again and its
//      own Allow issues a code; the pass an answer named, replayed, is asked
//      again — the answer counted once; a confidential client is asked once
//      and a later request issues a code at once.
//   2. A PENDING CONSENT IS CLAIMED ONLY BY THE PERSON IT WAS ASKED OF, in
//      a PRODUCT realm (where a consent is tied to the browser that first
//      opens it, #1454): another person's session is refused (STS-AUTHN-0552
//      off the audit log) and claims nothing; the person's own session
//      claims it and is answered again after; once claimed another session
//      of the same person is refused, and so is the other person; the
//      person's Allow then issues a code.
//
// NOT CARRIED: consent_public_client_once 3a/3c (the answer digest and the
// one-time store as functions) and consent_claim_by_owner D (a caller that
// names no request — no HTTP caller can be one) — class (d).
//
// OWNED HERE (local: true): this repository's own sign-in surface.
// ---------------------------------------------------------------------------

const authnSignin = require("./authn_signin");
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
var log = bunyan.createLogger({ name: "sts_consent_rules",
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
const DEV = "cons-" + STAMP;
const PROD = "consp-" + STAMP;
const SECRET = "consent-rules-" + STAMP + "-" + String(Date.now()).slice(-8) +
               "-0123456789abcdef0123456789abcdef";
const PASSWORD = "Consent-Rules-Passw0rd!-" + String(Date.now()).slice(-6);
const ALICE = "alice-" + STAMP;
const BOB = "bob-" + STAMP;
const REDIRECT = "https://rp.consent.example.test/cb";
const AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 " +
  "sts_consent_rules/1.0 (" + STAMP + ")";

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

function form(o) {
  log.debug("Entering form().");
  log.debug("Leaving form().");
  return new URLSearchParams(o).toString();
}

function absolute(location) {
  log.debug("Entering absolute().");
  log.debug("Leaving absolute().");
  return /^https?:\/\//i.test(String(location || ""))
    ? String(location) : base + String(location || "");
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
    // Not JSON — a page or a JWT; the caller reads `raw`.
    body = null;
  }
  log.debug("Leaving send(). status=" + r.status);
  return { status: r.status, body: body, raw: raw, headers: r.headers,
           location: r.headers.get("location") || "" };
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

// A refusal: a 400 whose answer names no code.
async function refused(url, payload, what) {
  log.debug("Entering refused().");
  const r = await postJson(url, payload);
  assert.ok(r.status === 400 && r.body && r.body.ok === false,
    "POST " + url + " should have refused " + what + "; it answered " +
    r.status + " " + String(r.raw).slice(0, 400));
  assert.ok(!/STS-[A-Z]+-\d{4}/.test(r.raw), "no code is sent: " + r.raw);
  log.debug("Leaving refused().");
  return r.body;
}

async function codeCount(api, code) {
  log.debug("Entering codeCount(). " + code);
  const r = await send(api + "/audit?per=500&code=" +
                       encodeURIComponent(code));
  log.debug("Leaving codeCount().");
  return Number((r.body && r.body.matched) || 0);
}

async function codesSettle(api, code, atLeast) {
  log.debug("Entering codesSettle(). " + code);
  let n = await codeCount(api, code);
  for (let i = 0; i < 20 && n < atLeast; i += 1) {
    await sleep(150);
    n = await codeCount(api, code);
  }
  log.debug("Leaving codesSettle(). " + n);
  return n;
}

// One browser, with a cookie jar, signed in once and kept.
function browser(realm) {
  log.debug("Entering browser().");
  const jar = {};
  const self = {
    jar: jar,
    realm: realm,
    header() {
      log.debug("Entering header().");
      log.debug("Leaving header().");
      return Object.keys(jar).map(function (k) {
        return k + "=" + jar[k];
      }).join("; ");
    },
    keep(headers) {
      log.debug("Entering keep().");
      const set = headers.getSetCookie ? headers.getSetCookie() : [];
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
      log.debug("Leaving keep().");
    },
    async go(method, path) {
      log.debug("Entering go(). " + method + " " + path);
      const headers = { "User-Agent": AGENT };
      const cookie = self.header();
      if (cookie) {
        headers.cookie = cookie;
      }
      const r = await fetch(absolute(path), { method: method,
        redirect: "manual", headers: headers });
      self.keep(r.headers);
      const text = await r.text();
      log.debug("Leaving go(). status=" + r.status);
      return { status: r.status, location: r.headers.get("location") || "",
               text: text, headers: r.headers };
    }
  };
  log.debug("Leaving browser().");
  return self;
}

async function signIn(b, location, who) {
  log.debug("Entering signIn(). who=" + who);
  const answer = await authnSignin.submit(base + "/realm/" + b.realm,
    location,
    { action: "login", username: who, password: PASSWORD },
    { cookie: b.header(), headers: { "User-Agent": AGENT } });
  assert.ok(answer.view, "the sign-in screen: " + answer.status + " " +
            JSON.stringify(answer.errors));
  b.keep(answer.headers);
  const posted = await authnSignin.asFormAnswer(answer, function (m, u) {
    return b.go(m, u);
  });
  log.debug("Leaving signIn().");
  return posted;
}


function codeOf(r, state) {
  log.debug("Entering codeOf().");
  const at = String(r.location || "");
  if (at.indexOf(REDIRECT) !== 0) {
    log.debug("Leaving codeOf(). Not the client.");
    return "";
  }
  const q = new URL(at).searchParams;
  log.debug("Leaving codeOf().");
  return q.get("state") === state ? String(q.get("code") || "") : "";
}

// An authorization request in `b`'s realm; signs `who` in if asked to.
async function authorize(b, client, state, who) {
  log.debug("Entering authorize(). " + client + " " + state);
  let r = await b.go("GET", "/realm/" + b.realm + "/oauth2/authorize?" +
    form({ client_id: client, response_type: "code", redirect_uri: REDIRECT,
           scope: "openid profile", state: state, nonce: "n-" + state,
           code_challenge: nodeCrypto.createHash("sha256")
             .update("v".repeat(43)).digest("base64url"),
           code_challenge_method: "S256" }));
  if ((r.status === 302 || r.status === 303) &&
      /\/authn\/login(?:\?app=[^#]*)?[?#]authn=/.test(r.location) && who) {
    const signed = await signIn(b, r.location, who);
    r = await b.go("GET", signed.location);
  }
  log.debug("Leaving authorize(). " + r.status + " " + r.location);
  return r;
}

async function allow(b, r) {
  log.debug("Entering allow().");
  const answered = await authnSignin.consentWithJar(absolute(r.location),
    "allow", b.jar, { headers: { "User-Agent": AGENT } });
  if (answered.status !== 303) {
    log.debug("Leaving allow(). Not answered: " + answered.status);
    return { status: answered.status, location: "", text: answered.text };
  }
  const pass = await b.go("GET", answered.location);
  pass.answeredAt = answered.location;
  log.debug("Leaving allow().");
  return pass;
}

async function realm(id, mode, settings) {
  log.debug("Entering realm(). " + id);
  await ok(base + "/admin-api/realms/create", { id: id,
    domain: id + ".example.net", name: "Consent rules " + id },
    "created the realm " + id);
  if (mode) {
    await ok(base + "/admin-api/realms/set", { id: id, key: "global.mode",
      value: mode }, "put " + id + " in " + mode + " mode");
  }
  for (const key of Object.keys(settings || {})) {
    await ok(base + "/admin-api/realms/set", { id: id, key: key,
      value: String(settings[key]) }, "set " + key + " on " + id);
  }
  const api = base + "/realm/" + id + "/admin-api";
  for (const who of [ALICE, BOB]) {
    await ok(api + "/users/create", { username: who, invent: false,
      credential: "password", password: PASSWORD,
      attributes: { cn: who, givenName: who.split("-")[0], sn: "Consent",
                    mail: who + "@consent.example.test" } },
      "created " + who + " in " + id);
  }
  log.debug("Leaving realm().");
  return api;
}

async function registerClient(api, id, isPublic) {
  log.debug("Entering registerClient(). " + id);
  const fields = { oauthClientId: [id], oauthRedirectUri: [REDIRECT],
    oauthAllowedScope: ["openid", "profile"],
    oauthGrantType: ["authorization_code"], oauthResponseType: ["code"],
    oauthTokenEndpointAuthMethod: isPublic ? "none" : "client_secret_basic" };
  if (!isPublic) {
    fields.oauthClientSecret = SECRET;
  }
  await ok(api + "/applications/create", { identifier: id, name: id,
    kind: "oauth2-client", protocols: ["oauth2", "oidc"], fields: fields },
    "registered " + id);
  log.debug("Leaving registerClient().");
}

// =========================================================================
// 1. consent_public_client_once.js
// =========================================================================
async function publicClientOnce() {
  log.debug("Entering publicClientOnce().");
  log.info("=== 1. a public client is asked every time ===");
  const api = await realm(DEV, "", {
    "oauth2.consentAlwaysForPublicClients": true,
    "authn.multipleAccounts": false });
  await registerClient(api, "cpo-public", true);
  await registerClient(api, "cpo-confidential", false);
  const b = browser(DEV);
  let r = await authorize(b, "cpo-public", "p1", ALICE);
  check("1a. the public client's request meets the consent screen",
        function () {
    assert.ok(authnSignin.isConsent(r.location), r.status + " " + r.location);
  });
  r = await allow(b, r);
  const passAt = r.answeredAt;
  check("1b. after Allow, the pass that follows issues a code and does not " +
        "ask again", function () {
    assert.ok(codeOf(r, "p1"), r.status + " " + r.location);
  });
  const replay = await b.go("GET", passAt);
  check("1c. the same pass replayed is asked again: the answer counted " +
        "once", function () {
    assert.ok(authnSignin.isConsent(replay.location),
              replay.status + " " + replay.location);
  });
  r = await authorize(b, "cpo-public", "p2");
  check("1d. a NEW request by the same public client is asked again, with " +
        "the earlier consent on file", function () {
    assert.ok(authnSignin.isConsent(r.location), r.status + " " + r.location);
  });
  r = await allow(b, r);
  check("1e. and its own Allow issues a code", function () {
    assert.ok(codeOf(r, "p2"), r.status + " " + r.location);
  });
  r = await authorize(b, "cpo-confidential", "c1");
  check("1f. a confidential client is asked the first time", function () {
    assert.ok(authnSignin.isConsent(r.location), r.status + " " + r.location);
  });
  r = await allow(b, r);
  check("1g. and its Allow issues a code", function () {
    assert.ok(codeOf(r, "c1"), r.status + " " + r.location);
  });
  r = await authorize(b, "cpo-confidential", "c2");
  check("1h. a later request by it issues a code at once: the recorded " +
        "consent counts", function () {
    assert.ok(codeOf(r, "c2"), r.status + " " + r.location);
  });
  log.debug("Leaving publicClientOnce().");
}

// =========================================================================
// 2. consent_claim_by_owner.js
// =========================================================================
async function claimByOwner() {
  log.debug("Entering claimByOwner().");
  log.info("=== 2. a pending consent is claimed only by its person ===");
  const api = await realm(PROD, "product", {
    "authn.allowOptionalSecondFactor": true });
  await registerClient(api, "cbo-client", false);
  const alice = browser(PROD);
  const asked = await authorize(alice, "cbo-client", "a1", ALICE);
  check("2a. alice's request meets the consent screen", function () {
    assert.ok(authnSignin.isConsent(asked.location),
              asked.status + " " + asked.location);
  });
  const where = absolute(asked.location);
  const bob = browser(PROD);
  const bobFirst = await authorize(bob, "cbo-client", "b1", BOB);
  assert.ok(authnSignin.isConsent(bobFirst.location),
            "bob signed in: " + bobFirst.status + " " + bobFirst.location);
  const alice2 = browser(PROD);
  const alice2First = await authorize(alice2, "cbo-client", "a2", ALICE);
  assert.ok(authnSignin.isConsent(alice2First.location),
            "alice's second session: " + alice2First.status);

  const before = await codeCount(api, "STS-AUTHN-0552");
  const byBob = await authnSignin.consentPage(where, {
    cookie: bob.header(), headers: { "User-Agent": AGENT } });
  check("2b. another person's session is refused, and is shown nothing",
        function () {
    assert.ok(!byBob.view, byBob.status + " " + byBob.text.slice(0, 200));
    assert.strictEqual(byBob.status, 400, byBob.text.slice(0, 200));
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(byBob.text), byBob.text);
  });
  const own = await authnSignin.consentPage(where, {
    cookie: alice.header(), headers: { "User-Agent": AGENT } });
  check("2c. that refusal claimed nothing: the person's own session claims " +
        "it", function () {
    assert.ok(own.view, own.status + " " + own.text.slice(0, 300));
  });
  const again = await authnSignin.consentPage(where, {
    cookie: alice.header(), headers: { "User-Agent": AGENT } });
  check("2d. and is answered again after", function () {
    assert.ok(again.view, again.status + " " + again.text.slice(0, 200));
  });
  const byAlice2 = await authnSignin.consentPage(where, {
    cookie: alice2.header(), headers: { "User-Agent": AGENT } });
  const byBobAgain = await authnSignin.consentPage(where, {
    cookie: bob.header(), headers: { "User-Agent": AGENT } });
  check("2e. once claimed, another session of the same person is refused, " +
        "and so is the other person", function () {
    assert.ok(!byAlice2.view && byAlice2.status === 400,
              byAlice2.status + " " + byAlice2.text.slice(0, 200));
    assert.ok(!byBobAgain.view && byBobAgain.status === 400,
              byBobAgain.status + " " + byBobAgain.text.slice(0, 200));
  });
  const n = await codesSettle(api, "STS-AUTHN-0552", before + 3);
  check("2f. each of the three refusals is recorded STS-AUTHN-0552",
        function () {
    assert.ok(n - before >= 3, "rows added: " + (n - before));
  });
  const answered = await authnSignin.answerConsent(again, "allow",
    { headers: { "User-Agent": AGENT } });
  alice.keep({ getSetCookie: function () {
    return answered.setCookies || [];
  } });
  const pass = await alice.go("GET", answered.location);
  check("2g. the person's own Allow issues the code", function () {
    assert.strictEqual(answered.next, "redirect", JSON.stringify(
      answered.json).slice(0, 300));
    assert.ok(codeOf(pass, "a1"), pass.status + " " + pass.location);
  });
  log.debug("Leaving claimByOwner().");
}

async function test() {
  log.debug("Entering test().");
  await publicClientOnce();
  await claimByOwner();
  assert.ok(checks >= 15, "only " + checks + " checks ran; a section has " +
                          "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
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
  for (const id of [DEV, PROD]) {
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
    log.debug("Caught in main() removing realms: " + ((e && e.message) || e));
    log.warn("could not remove the realms: " + e.message);
  }
  if (failure) {
    log.error(failure.stack || failure.message);
    log.debug("Leaving main(). Failed.");
    process.exit(1);
  }
  log.debug("Leaving main().");
}

main();
