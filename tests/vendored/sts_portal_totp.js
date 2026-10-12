// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_portal_totp.js
//
// ===========================================================================
// AN AUTHENTICATOR APP IS ENROLLED IN THE PORTAL, AND THE SIGN-IN SCREEN THEN
// DEMANDS A CODE — ALL OF IT OVER HTTP, WITH THE CODE COMPUTED HERE.
//
// Five claims, driven through the real doors.
//
// **SINCE #568 THE PORTAL IS A STATIC APPLICATION** over `/account-api`, so
// the doors are its operations: the sign-in is still walked by hand — that is
// where a second factor is demanded — and the portal's own token is then
// taken through the same sign-on session (`portal_signin.js`, single sign-on);
// `/portal/mfa` is `GET` and `POST /account-api/mfa`, drawn by the portal's
// own renderers where an assertion is about what the page SHOWS. A secret
// shown, a code refused, a write attributed: the claims are unchanged.
//
//   1. a signed-in person enrols an authenticator at `/portal/mfa`: a secret
//      is SHOWN, nothing is stored until a code confirms it, and a wrong code
//      leaves the enrolment unfinished;
//   2. once enrolled, **A PASSWORD ALONE STOPS SIGNING THEM IN** — the sign-in
//      screen asks for a code without being told to, and the session that
//      comes out says `amr ["pwd","otp"]` and `acr "mfa"`;
//   3. RFC 6238 section 5.2 is enforced end to end: the code that confirmed
//      the enrolment cannot also sign them in;
//   4. one person cannot enrol an authenticator on somebody else's account,
//      whatever they put in the body;
//   5. an operator's clear at `/admin-api/mfa/clear-totp` really does drop the
//      account back to one factor.
//
// ---------------------------------------------------------------------------
// THE CODE IS COMPUTED BY AN IMPLEMENTATION WRITTEN FOR THIS FILE, AND THAT IS
// THE WHOLE VALUE OF THE JOB.
//
// `tests/totp.js` asserts `common/totp.ts` against RFC 4226's and RFC 6238's
// own published vectors, so the SERVICE's arithmetic is known to be right. What
// that cannot show is that a THIRD PARTY holding the secret this service handed
// out can produce a code this service accepts — which is the only thing an
// authenticator app ever does, and the only claim a person cares about.
//
// So the thirty lines below are deliberately not `require`d from
// `common/totp.ts`. They are the same shape a client author would write, and
// they are checked against RFC 6238's Appendix B before they are trusted (see
// `theGeneratorIsRight()`) — because a test-side generator that agreed with a
// broken service would be worse than no test at all. It is the arrangement
// the parent project's `tests/webauthn_cross_impl.js` describes: two
// implementations written apart,
// each checked against the specification, then checked against each other.
//
// ---------------------------------------------------------------------------
// WHY IT IS HERE, WHICH IS THE FIRST QUESTION tests/CLAUDE.md ASKS.
//
// `local: true`. It drives this service's own `/portal`, its own `/admin` and
// its `/admin-api` — the OWNERSHIP argument rather than a capability one: the
// tree that adds a control to those surfaces is the tree that should go red
// when the control loses its endpoint.
//
// **AND IT IS NOT COVERED BY `tests/totp.js` NEXT DOOR**, which is the trap
// this feature invites: that file proves the algorithm and touches no route.
// Every defect this job exists to catch — a screen that never asks for the
// code, a step id that is not spent, a body parameter that lets somebody enrol
// for another person — is invisible to it and passes it perfectly.
// ===========================================================================

const assert = require("assert");
const nodeCrypto = require("crypto");
const { usernameFor } = require("./random_username.js");
const portal = require("./portal_signin.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason tests/vendored/wait_for.js gives.
  appconfigProblem = e;
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_portal_totp",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug('CONFIG_FILE could not be read, so the configuration is empty: ' +
            appconfigProblem.message);
}
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");
var api = base + "/admin-api";

// Suffixed per run, because the directory is append-only in practice and two
// runs against one long-lived mock must not see each other's people.
var OWNER = usernameFor("totp-owner");
var INTRUDER = usernameFor("totp-intruder");
var NEWCOMER = usernameFor("totp-newcomer");
// SECTION 5'S OWN PERSON (#311): the owner has a TOTP replay on record from
// section 2 by then, which a deployment's risk engine scores (`totp-replay`)
// into a step-up the owner — their factor just cleared — cannot answer. A
// local stack sets the MEDIUM threshold out of reach; a deployment does not.
var CLEARED = usernameFor("totp-cleared");

var checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

// ---------------------------------------------------------------------------
// THE INDEPENDENT RFC 6238 IMPLEMENTATION. Thirty lines, written from the
// specification rather than taken from the service under test. See the header.
// ---------------------------------------------------------------------------
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32ToBytes(text) {
  log.debug("Entering base32ToBytes().");
  const cleaned = String(text).toUpperCase().replace(/[\s=-]/g, "");
  let bits = 0;
  let value = 0;
  const out = [];
  for (let i = 0; i < cleaned.length; i++) {
    const index = B32.indexOf(cleaned[i]);
    assert.ok(index >= 0,
      "the secret this service showed is not base32: " + cleaned[i]);
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  log.debug("Leaving base32ToBytes().");
  return Buffer.from(out);
}

// RFC 4226 section 5.3 over RFC 6238 section 4.2.
function codeFor(secret, atMs, opts) {
  log.debug("Entering codeFor().");
  const options = opts || {};
  const digits = Number(options.digits || 6);
  const period = Number(options.period || 30);
  const alg = String(options.algorithm || "SHA1").toLowerCase();
  const counter = Math.floor(Number(atMs || Date.now()) / 1000 / period);
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const digest = nodeCrypto.createHmac(alg, base32ToBytes(secret))
                           .update(message).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = ((digest[offset] & 0x7f) << 24) |
                 ((digest[offset + 1] & 0xff) << 16) |
                 ((digest[offset + 2] & 0xff) << 8) |
                 (digest[offset + 3] & 0xff);
  log.debug("Leaving codeFor().");
  return String(binary % Math.pow(10, digits)).padStart(digits, "0");
}

// ---------------------------------------------------------------------------
// ONE BROWSER. Manual redirects and a cookie jar of our own, because every
// assertion here is about WHICH screen came back — a fetch that followed the
// redirects would answer the question by hiding it.
// ---------------------------------------------------------------------------
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

function browser(name) {
  log.debug("Entering browser().");
  const self = {
    name: name,
    cookie: "",
    jar: {},
    cookieHeader: function () {
      log.debug("Entering cookieHeader().");
      log.debug("Leaving cookieHeader().");
      return Object.keys(self.jar).map(function (k) {
        return k + "=" + self.jar[k];
      }).join("; ");
    },
    async go(method, path, body) {
      log.debug("Entering go().");
      const headers = {};
      if (self.cookie) headers.cookie = self.cookie;
      if (body !== undefined) {
        headers["Content-Type"] = "application/x-www-form-urlencoded";
      }
      const r = await fetch(absolute(path),
                            { method: method, redirect: "manual",
                                              headers: headers, body: body });
      // KEYED BY NAME: a browser signing in to a hosted surface holds TWO
      // cookies — the sign-on session and the surface's own — and keeping only
      // the last one seen drops whichever arrived first.
      const set = r.headers.getSetCookie ? r.headers.getSetCookie() : [];
      set.forEach(function (one) {
        const pair = String(one).split(";")[0];
        const name = pair.split("=")[0];
        const value = pair.slice(name.length + 1);
        if (value === "" || /Expires=Thu, 01 Jan 1970/i.test(String(one))) {
          delete self.jar[name];
        } else {
          self.jar[name] = value;
        }
        self.cookie = self.cookieHeader();
      });
      log.debug("Leaving go().");
      return { status: r.status, location: r.headers.get("location") || "",
               text: await r.text() };
    }
  };
  log.debug("Leaving browser().");
  return self;
}

// A BARE `/portal` OR `/admin` DRAWS THE REALM CHOOSER once a service has
// trust realms (2026-09-14, #32), and the suite nearly always has some. The
// chooser's own `?realm=default` is what a script names to skip it, so every
// door this file signs in through, or asks whether a browser is anybody, names
// it. `sts_realm_administrators.js` asserts the chooser itself.
const PORTAL_DOOR = "/portal?realm=default";

async function apiGet(path) {
  log.debug("Entering apiGet().");
  const r = await fetch(api + path);
  const raw = await r.text();
  let body;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in apiGet(): " + ((e && e.message) || e));
    // An HTML error page from a door that answers JSON is worth quoting whole
    // rather than reporting as a parse failure.
    body = raw;
  }
  log.debug("Leaving apiGet().");
  return { status: r.status, body: body, raw: raw };
}

async function apiPost(path, body) {
  log.debug("Entering apiPost().");
  const r = await fetch(api + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  const raw = await r.text();
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in apiPost(): " + ((e && e.message) || e));
    parsed = raw;
  }
  log.debug("Leaving apiPost().");
  return { status: r.status, body: parsed, raw: raw };
}

function csrfOf(text) {
  log.debug("Entering csrfOf().");
  log.debug("Leaving csrfOf().");
  return (String(text).match(/name="csrf_token" value="([^"]+)"/) ||
          [])[1] || "";
}

// ---------------------------------------------------------------------------
// EVERY PERSON THIS JOB SIGNS IN IS CREATED FIRST, WITH A PASSWORD AND THE
// ATTRIBUTES A REAL ACCOUNT CARRIES (2026-09-12).
//
// In product mode this service invents no persona for a name that signs in,
// creates nobody because a sign-in named them, and verifies the password
// against the person's own entry. The suite runs in development, where none of
// that is enforced — which is why a job leaning on it would go on passing
// while testing the invention. So `ensurePerson()` makes each account through
// `/admin-api/users/create` with `invent: false`, its own `cn`, `sn`,
// `givenName`, `displayName` and `mail`, and a password of at least twelve
// characters, and that password is what the sign-in screen is sent.
// ---------------------------------------------------------------------------
var PASSWORD = "portal-totp-Passw0rd!-" + String(Date.now()).slice(-6);
var MAIL_DOMAIN = "portal-totp.test";

function personAttributes(who) {
  log.debug("Entering personAttributes().");
  log.debug("Leaving personAttributes().");
  return { cn: "TOTP Person " + who, givenName: "TOTP", sn: who,
           displayName: "TOTP Person " + who, mail: who + "@" + MAIL_DOMAIN };
}

// Create `who` with a password and real attributes, once per run.
var createdPeople = {};
async function ensurePerson(who) {
  log.debug("Entering ensurePerson(). who=" + who);
  if (createdPeople[who]) {
    log.debug("Leaving ensurePerson(). Already created by this run.");
    return;
  }
  const r = await apiPost("/users/create", {
    username: who, invent: false, attributes: personAttributes(who),
    credential: "password", password: PASSWORD
  });
  assert.ok(r.status === 200 && r.body && r.body.ok && r.body.passwordSet,
    "POST /admin-api/users/create should create " + who + " with a password " +
    "before they sign in; it answered " + r.status + " " +
    String(r.raw).slice(0, 300));
  createdPeople[who] = true;
  log.debug("Leaving ensurePerson(). Created " + who + ".");
}

// The secret as the page prints it for manual entry — groups of four inside a
// <code>. Read off the PAGE and not out of the otpauth URI, deliberately: the
// transcribable form is what somebody without a camera uses, and a page whose
// QR code and printed secret disagreed would pass an assertion that read only
// one of them.
function secretShownOn(text) {
  log.debug("Entering secretShownOn().");
  const cell = String(text).match(/<th>Secret<\/th><td><code>([^<]+)<\/code>/);
  log.debug("Leaving secretShownOn().");
  return cell ? cell[1].replace(/\s+/g, "") : "";
}

function qrShownOn(text) {
  log.debug("Entering qrShownOn().");
  log.debug("Leaving qrShownOn().");
  return /<img src="data:image\/svg\+xml;base64,[A-Za-z0-9+/=]+"/.test(
      String(text));
}

// ---------------------------------------------------------------------------
// SIGN IN, AS THE STATIC PORTAL DOES (#568). The portal is a public client of
// this service's own authorization server, so a sign-in is a code flow: the
// browser asks `/oauth2/authorize` as `sts-user-portal` with PKCE, meets the
// sign-in screen because the AUTHORIZATION ENDPOINT decides it needs one, and
// comes back to `/portal/callback` with a code. The walk is done here by hand
// to the callback — the sign-in screen is where a second factor is demanded,
// which is what this job is about — and the portal's DPoP-bound token is then
// taken through the sign-on session it set (`portal_signin.js`, which signs
// in again with nothing typed). `door` is kept for a reader: the page the
// person came for.
//
// `onSecondFactor` is handed the 200 the password POST answered with when the
// screen asks for something more.
// ---------------------------------------------------------------------------
function b64u(buffer) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(buffer).toString("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// The authorization request the portal's runtime sends.
function portalAuthorizeUrl() {
  log.debug("Entering portalAuthorizeUrl().");
  const verifier = b64u(nodeCrypto.randomBytes(32));
  const url = base + "/oauth2/authorize?" + new URLSearchParams({
    response_type: "code", client_id: "sts-user-portal",
    redirect_uri: base + "/portal/callback", scope: "openid account:manage",
    state: b64u(nodeCrypto.randomBytes(16)),
    code_challenge: b64u(nodeCrypto.createHash("sha256").update(verifier)
      .digest()),
    code_challenge_method: "S256", resource: base + "/account-api" })
    .toString();
  log.debug("Leaving portalAuthorizeUrl().");
  return url;
}

async function signIn(door, who, onSecondFactor) {
  log.debug("Entering signIn(). door=" + door + " who=" + who);
  await ensurePerson(who);
  const b = browser(who);
  let r = await b.go("GET", PORTAL_DOOR);
  assert.strictEqual(r.status, 200,
    "the portal's shell should answer " + PORTAL_DOOR + "; it answered " +
    r.status + " -> " + r.location);
  r = await b.go("GET", portalAuthorizeUrl());
  assert.ok(/\/authn\/login\?authn=/.test(r.location),
    "the authorization endpoint should send a browser with no sign-on " +
    "session to the sign-in screen; it answered " + r.status + " -> " +
    r.location);
  r = await b.go("GET", r.location);
  const authnId = (r.text.match(/name="authn_id" value="([^"]+)"/) || [])[1];
  assert.ok(authnId, "the sign-in screen carries no authn_id to post back.");
  r = await b.go("POST", "/authn/login",
                 form({ authn_id: authnId, username: who,
                        password: PASSWORD, action: "login",
                        csrf_token: csrfOf(r.text) }));
  if (r.status === 200) {
    assert.ok(onSecondFactor,
      "the sign-in screen asked for something more and this call was not " +
      "expecting it: " + String(r.text).slice(0, 300));
    r = await onSecondFactor(b, r);
  } else {
    assert.ok(!onSecondFactor,
      "a second factor was expected and the password alone was enough — " +
      "which is the defect this job exists to catch. It answered " + r.status +
      " -> " + r.location);
  }
  assert.ok(r.status === 303 || r.status === 302,
    "the sign-in should end in a redirect; got " + r.status + " " +
    String(r.text).slice(0, 300));
  r = await b.go("GET", r.location);   // the authorization endpoint
  assert.ok(/\/portal\/callback\?/.test(r.location),
    "the authorization endpoint should answer the portal's callback with a " +
    "code; it answered " + r.status + " -> " + r.location);
  assert.ok(b.cookie, "completing the flow should establish a session cookie.");
  b.portal = await portal.signInToThePortal(base, who, null,
                                            { cookie: b.cookieHeader() });
  log.debug("Leaving signIn().");
  return b;
}

// THE PAGE AS THE PORTAL DRAWS IT for `b`'s person: `{ status, json, text }`,
// `text` the cards the portal's own renderers draw from the operation's view.
// The operation is the one the portal's page table names for the path — what
// the runtime asks — rather than one found by `mirrors`, which `/portal` shares
// between the Overview and `GET /account-api/me`.
async function pageOf(b, path) {
  log.debug("Entering pageOf(). " + path);
  const table = portal.portalBundle();
  const row = table.PAGES.filter(function (one) {
    return one.path === path;
  })[0];
  assert.ok(row, "the portal draws no page at " + path);
  if (!b.me) {
    b.me = (await b.portal.api("GET", "/account-api/me")).json;
  }
  const answer = await b.portal.api("GET", row.operation);
  const t = table.messages.WebTranslator.fromData(b.me && b.me.locale);
  const text = answer.status === 200 && answer.json
    ? row.render(answer.json, { t: t, query: {}, prefix: "", origin: base,
                                me: b.me, locale: b.me && b.me.locale,
                                version: b.me && b.me.version, here: path })
    : "";
  log.debug("Leaving pageOf().");
  return { status: answer.status, json: answer.json, text: text };
}

// A PAGE FOR NOBODY — the activation link's — drawn from its view by the
// portal's own renderers, in the language a browser with no preference gets.
let nobodyLocale = null;
async function drawForNobody(path, view) {
  log.debug("Entering drawForNobody(). " + path);
  if (!nobodyLocale) {
    nobodyLocale = (await portal.nobody(base, "GET", "/account-api/locale"))
      .json;
  }
  const table = portal.portalBundle();
  const row = table.PAGES.filter(function (one) {
    return one.path === path;
  })[0];
  const t = table.messages.WebTranslator.fromData(nobodyLocale.locale);
  log.debug("Leaving drawForNobody().");
  return row.render(view, { t: t, query: {}, prefix: "", origin: base,
                            me: null, locale: nobodyLocale.locale,
                            version: nobodyLocale.version, here: path });
}

// ===========================================================================
// 0. THE GENERATOR ITSELF, BEFORE ANYTHING IS ASSERTED WITH IT.
//
// **A TEST-SIDE IMPLEMENTATION THAT AGREED WITH A BROKEN SERVICE WOULD BE
// WORSE THAN NO TEST**, so the thirty lines above are checked against RFC
// 6238's Appendix B first. This is the only section here that sends no
// request.
// ===========================================================================
function theGeneratorIsRight() {
  log.debug("Entering theGeneratorIsRight().");
  log.info("=== 0. the job's own RFC 6238 implementation ===");
  // The seeds are the RFC's, with errata 2866 applied: the prose says one
  // twenty-byte ASCII seed for all three modes and the published values are
  // only reproducible with a seed as long as the digest.
  const seed = function (bytes) {
    log.debug("Entering seed().");
    let s = "";
    while (s.length < bytes) { s += "1234567890"; }
    log.debug("Leaving seed().");
    return s.slice(0, bytes);
  };

  const toBase32 = function (ascii) {
    log.debug("Entering toBase32().");
    const bytes = Buffer.from(ascii, "utf8");
    let bits = 0;
    let value = 0;
    let out = "";
    for (let i = 0; i < bytes.length; i++) {
      value = (value << 8) | bytes[i];
      bits += 8;
      while (bits >= 5) {
        out += B32[(value >>> (bits - 5)) & 31];
        bits -= 5;
      }
    }
    if (bits > 0) { out += B32[(value << (5 - bits)) & 31]; }
    log.debug("Leaving toBase32().");
    return out;
  };
  const vectors = [
    [59, "SHA1", 20, "94287082"],
    [1111111109, "SHA1", 20, "07081804"],
    [1234567890, "SHA256", 32, "91819424"],
    [2000000000, "SHA512", 64, "38618901"]
  ];
  vectors.forEach(function (row) {
    const got = codeFor(toBase32(seed(row[2])), row[0] * 1000,
                        { digits: 8, period: 30, algorithm: row[1] });
    assert.strictEqual(got, row[3],
      "this job's own TOTP generator disagrees with RFC 6238 Appendix B at " +
      "t=" + row[0] + " " + row[1] + ": got " + got + ", expected " + row[3] +
      ". Nothing below this line means anything until that is fixed.");
  });
  check("the generator this job checks the SERVICE with is itself checked " +
        "against RFC 6238 Appendix B — four vectors across all three digests",
        function () { assert.ok(true); });
  log.debug("Leaving theGeneratorIsRight().");
}

// ===========================================================================
// 1. ENROLMENT: A SECRET IS SHOWN AND NOTHING IS STORED UNTIL A CODE PROVES IT.
// ===========================================================================
async function enrolling() {
  log.debug("Entering enrolling().");
  log.info("=== 1. enrolling an authenticator app at /portal/mfa ===");
  const b = await signIn("/portal/mfa", OWNER);

  let page = await pageOf(b, "/portal/mfa");
  check("the portal offers to set one up, and reports none enrolled",
        function () {
    assert.strictEqual(page.status, 200,
      "/portal/mfa answered " + page.status);
    assert.ok(/No authenticator app is set up/.test(page.text),
      "the page should say none is set up; it said " +
      String(page.text).slice(0, 400));
    assert.ok(/Set up an authenticator app/.test(page.text),
      "and it should offer the control.");
  });

  check("it names the apps a person might already have, rather than one",
        function () {
    ["Google Authenticator", "Authy", "FreeOTP"].forEach(function (app) {
      assert.ok(page.text.indexOf(app) >= 0,
        "the page should encourage any RFC 6238 app; it does not mention " +
        app);
    });
  });

  let r = await b.portal.act("/portal/mfa", { action: "start" });
  check("starting the setup answers NO SECRET OF ITS OWN — the page asks " +
        "its view again, which re-derives the one pending, so a reload " +
        "cannot mint a second secret and invalidate the one just scanned " +
        "(it was a 303 until #568)", function () {
    assert.ok(r.status === 200 && r.json && r.json.ok === true &&
              !r.json.view,
      "POST start answered " + r.status + " " + String(r.text).slice(0, 200));
  });

  page = await pageOf(b, "/portal/mfa");
  const secret = secretShownOn(page.text);
  const reread = secretShownOn((await pageOf(b, "/portal/mfa")).text);
  check("and asking the page again shows the SAME secret", function () {
    assert.strictEqual(reread, secret,
      "a second read of /portal/mfa minted another secret.");
  });
  check("the secret is shown BOTH ways: a QR code drawn on the server, and " +
        "the base32 in groups of four for a phone that cannot scan it",
        function () {
    assert.ok(qrShownOn(page.text),
      "no QR code data: URI on the page: the image arrives rendered by the " +
      "server, in the view.");
    assert.ok(secret.length >= 32,
      "no transcribable secret on the page; got '" + secret + "'");
  });

  check("and the account, issuer and parameters are printed beside it, so " +
        "an app with no camera can be configured by hand", function () {
    assert.ok(page.text.indexOf(OWNER) >= 0, "the account is not named.");
    assert.ok(/HMAC-SHA-1/.test(page.text),
      "the algorithm is not printed: " + String(page.text).slice(0, 200));
  });

  // **NOTHING IS STORED YET**, which is the half of the two-step design that
  // matters: an unconfirmed secret on somebody's entry is a second factor they
  // cannot produce, which is a lockout rather than a control.
  let seen = await apiGet("/mfa?q=" + encodeURIComponent(OWNER));
  check("NOTHING IS ENROLLED YET — the secret has been shown and the " +
        "directory knows nothing about it, so a person who walks away from " +
        "this page is not locked out of their own account", function () {
    assert.strictEqual(seen.status, 200,
      "GET /admin-api/mfa answered " + seen.status + " " +
      String(seen.raw).slice(0, 200));
    const row = (seen.body.people || []).filter(function (one) {
      return one.username === OWNER;
    })[0];
    assert.ok(row, "the person is not on /admin-api/mfa at all.");
    assert.strictEqual(row.totp, false,
      "an unconfirmed enrolment reached the store.");
    assert.strictEqual(row.mfaRequired, false,
      "and it is already being demanded of them.");
  });

  r = await b.portal.act("/portal/mfa", { action: "confirm",
                                          code: "000000" });
  check("a wrong code is refused and the SAME secret is redrawn — mistyping " +
        "six digits must not mean scanning again", function () {
    assert.strictEqual(r.status, 400, "a wrong code answered " + r.status);
    const view = (r.json && r.json.view) || {};
    assert.strictEqual(
      String((view.setup || {}).grouped || "").replace(/\s+/g, ""), secret,
      "the refusal's view carries a different secret, so a typo costs a " +
      "rescan.");
  });

  const code = codeFor(secret);
  r = await b.portal.act("/portal/mfa", { action: "confirm", code: code });
  check("A CODE THIS JOB COMPUTED FROM THE SECRET IS ACCEPTED — which is the " +
        "only thing an authenticator app ever does, and the claim tests/" +
        "totp.js cannot make", function () {
    // **THE 200 IS AS RIGHT AS THE 303 AND THIS ASSERTION TOOK BOTH ON
    // 2026-09-10**, when a first enrolment started issuing RECOVERY CODES and
    // answered with the page, because a 303 cannot carry a list of
    // credentials. Since 2026-09-11 an enrolment issues no codes (a set is
    // generated on request instead), and both answers are still accepted.
    //
    // What is asserted here is that the confirmation SUCCEEDED, which both
    // answers say. `tests/vendored/sts_portal_backup_codes.js` is where the
    // recovery codes' own render is pinned, including that an enrolment
    // shows none.
    // Since #568 the answer is `{ ok: true, message }`.
    assert.ok(r.status === 200 && r.json && r.json.ok === true,
      "the confirmation answered " + r.status + " " +
      String(r.text).slice(0, 300));
  });

  seen = await apiGet("/mfa?q=" + encodeURIComponent(OWNER));
  check("and NOW it is enrolled, readable, and a second factor is required " +
        "of them", function () {
    const row = (seen.body.people || []).filter(function (one) {
      return one.username === OWNER;
    })[0];
    assert.ok(row, "the person left /admin-api/mfa.");
    assert.strictEqual(row.totp, true,
                       "the enrolment did not reach the store.");
    assert.strictEqual(row.totpUsable, true,
      "the stored enrolment cannot be read back: " +
      JSON.stringify(row.totpDetail));
    assert.strictEqual(row.mfaRequired, true,
      "a second factor is not being required of them.");
    assert.strictEqual(row.secondFactor, "totp",
      "the wrong factor will be asked for: " + row.secondFactor);
  });

  const rows = await apiGet("/audit?per=200");
  check("the enrolment is in the audit log AS THEM, and so is the moment a " +
        "secret was SHOWN — the row somebody investigating a compromised " +
        "account goes looking for, and the one a log of successes only would " +
        "not have", function () {
    const events = (rows.body.events || rows.body.rows || []);
    const mine = events.filter(function (e) {
      return String(e.actor || "") === OWNER;
    });
    assert.ok(mine.some(function (e) {
      return e.action === "portal.mfa.started";
    }),
      "no portal.mfa.started row for " + OWNER + ".");
    assert.ok(mine.some(function (e) {
      return e.action === "portal.mfa.enrolled";
    }),
      "no portal.mfa.enrolled row for " + OWNER + ".");
  });

  log.debug("Leaving enrolling().");
  return { browser: b, secret: secret, confirmationCode: code };
}

// ===========================================================================
// 2. THE SIGN-IN SCREEN DEMANDS IT, WITHOUT BEING ASKED TO.
//
// **THIS IS THE ASSERTION THE WHOLE FEATURE RESTS ON.** `mfaRequired` had been
// on `credentials.mechanismsFor()` since the portal was written and NOTHING
// READ IT at the sign-in door, so it was a sentence on a page rather than a
// rule. The check is not "a code screen can be reached" — it is that the
// password alone STOPS WORKING, which is what a person means by having turned
// MFA on.
// ===========================================================================
async function theSignInDemandsIt(enrolment) {
  log.debug("Entering theSignInDemandsIt().");
  log.info("=== 2. the sign-in screen asks for a code, unprompted ===");
  let sawTheCodeScreen = false;
  let replayRefused = false;
  let amr = "";

  const b = await signIn(PORTAL_DOOR, OWNER, async function (bb, r) {
    sawTheCodeScreen = /One-time code|one-time code|authenticator app/i.test(
        r.text) &&
                       /name="mfa_id"/.test(r.text);
    assert.ok(sawTheCodeScreen,
      "the password alone got through, or some other screen was drawn: " +
      String(r.text).slice(0, 400));
    const mfaId = (r.text.match(/name="mfa_id" value="([^"]+)"/) || [])[1];

    // RFC 6238 SECTION 5.2, END TO END. The code that CONFIRMED the enrolment
    // is a code, and a code is accepted once.
    let x = await bb.go("POST", "/authn/totp",
                        form({ mfa_id: mfaId,
                               code: enrolment.confirmationCode }));
    replayRefused = x.status === 200 && /already been used/.test(x.text);
    assert.ok(replayRefused,
      "the code that confirmed the enrolment was accepted a second time, or " +
      "was refused with the wrong reason: " + x.status + " " +
      String(x.text).slice(0, 300));

    // THE NEXT STEP. Computed thirty seconds ahead rather than waiting: the
    // window forgives a step either side, so a code from the next step is
    // accepted now — which is the whole point of the window and lets this run
    // in milliseconds instead of half a minute.
    const next = codeFor(enrolment.secret, Date.now() + 30000);
    x = await bb.go("POST", "/authn/totp", form({ mfa_id: mfaId, code: next }));
    return x;
  });

  check("the sign-in screen asked for a code WITHOUT the person ticking " +
        "anything — which is what 'configured to use it' has to mean",
        function () { assert.ok(sawTheCodeScreen); });
  check("and the code that confirmed the enrolment could NOT sign them in — " +
        "RFC 6238 section 5.2, and it is refused as a REPLAY rather than as " +
        "a wrong code, because those are different things to be told",
        function () { assert.ok(replayRefused); });

  const page = await pageOf(b, "/portal");
  amr = (page.text.match(/<tr><th>How<\/th><td>([^<]*)/) || [])[1] || "";
  check("the session says two factors were presented: amr pwd and otp, acr " +
        "mfa — RFC 8176's value, whose registry entry names RFC 4226 and RFC " +
        "6238 by number", function () {
    assert.ok(/pwd/.test(amr) && /otp/.test(amr),
      "the session's amr is '" + amr + "'");
    assert.ok(/acr mfa/.test(amr),
      "the session's acr is not mfa: '" + amr + "'");
  });

  log.debug("Leaving theSignInDemandsIt().");
  return b;
}

// ===========================================================================
// 3. ONE PERSON CANNOT ENROL ON ANOTHER'S ACCOUNT.
//
// The rule the whole portal is built on — no route takes an identity from the
// request — and it matters MORE on this endpoint than on any other there. A
// `username` read from this body would not be an information leak: it would let
// anybody signed in enrol THEIR OWN authenticator app as somebody else's second
// factor, and then hold a factor for an account they do not own.
//
// **THE PAGE PROVES THE PAGE AND ONLY THE STORE PROVES THE WRITE**, which is
// the lesson `sts_portal_sessions.js` records: an earlier defect in this portal
// rendered the caller's own account while the write went to the person they had
// named, and every page-level assertion passed.
// ===========================================================================
async function oneUserCannotEnrolForAnother() {
  log.debug("Entering oneUserCannotEnrolForAnother().");
  log.info("=== 3. A01: enrolling for somebody else ===");
  const b = await signIn("/portal/mfa", INTRUDER);
  let page = await pageOf(b, "/portal/mfa");

  const beforeRows = await apiGet("/mfa?q=" + encodeURIComponent(OWNER));
  const before = (beforeRows.body.people || []).filter(function (one) {
    return one.username === OWNER;
  })[0];

  // Every parameter a future author might plausibly have read.
  const r = await b.portal.act("/portal/mfa",
                               { action: "start", user: OWNER,
                                 username: OWNER, subject: OWNER,
                                 uid: OWNER });
  check("the POST is answered rather than erroring — the parameters are " +
        "simply not read (the account is the token's, #568)", function () {
    assert.ok(r.status === 200 || r.status === 400,
      "it answered " + r.status);
  });

  page = await pageOf(b, "/portal/mfa");
  check("and the page that comes back is the INTRUDER'S OWN — their name on " +
        "it, and not the person they named", function () {
    assert.ok(page.text.indexOf(INTRUDER) >= 0,
      "the page does not name the caller.");
    assert.ok(page.text.indexOf(OWNER) < 0,
      "the page names " + OWNER + ", whom the caller only asked about.");
  });

  const afterRows = await apiGet("/mfa?q=" + encodeURIComponent(OWNER));
  const after = (afterRows.body.people || []).filter(function (one) {
    return one.username === OWNER;
  })[0];
  check("AND THE STORE IS UNCHANGED — the owner's enrolment is the one they " +
        "made, with the same enrolment instant. This is the assertion that " +
        "means something: a handler reading a username from the body renders " +
        "the caller's own page perfectly and writes to somebody else",
        function () {
    assert.ok(before && after, "the owner left /admin-api/mfa.");
    assert.strictEqual(after.totp, true, "the owner's enrolment was removed.");
    assert.strictEqual(after.totpDetail.enrolledAt,
      before.totpDetail.enrolledAt,
      "the owner's enrolment was REPLACED by the intruder's — the exact " +
      "takeover this rule exists to prevent.");
  });

  // And a hand-made confirm naming the owner cannot finish the OWNER's
  // enrolment either: the pending record is keyed by the session's person.
  const confirm = await b.portal.act("/portal/mfa",
                                     { action: "confirm", user: OWNER,
                                       username: OWNER, code: "123456" });
  check("and a confirmation naming somebody else confirms nothing of theirs " +
        "— the pending enrolment is keyed by the TOKEN'S person",
        function () {
    assert.strictEqual(confirm.status, 400, "it answered " + confirm.status);
  });
  log.debug("Leaving oneUserCannotEnrolForAnother().");
}

// ===========================================================================
// 4. AN ACTIVATION LINK CAN SET ONE UP, AND IS NOT SPENT UNTIL IT DOES.
//
// The other enrolment door, and the one for somebody who has never signed in:
// provisioned through the management API with no credential at all, they set up
// a password AND an authenticator in one flow.
//
// **THE LINK IS SPENT WHEN THE SETUP FINISHES AND NOT WHEN THE PASSWORD IS
// SET**, which is this directory's existing rule reaching a case it did not
// have before — somebody who ticks the box and then cannot find their phone
// must still hold a usable link.
// ===========================================================================
async function anActivationLinkCanSetOneUp() {
  log.debug("Entering anActivationLinkCanSetOneUp().");
  log.info("=== 4. setting one up while spending an activation link ===");
  // Created with the attributes a real account carries and `invent: false`,
  // so nothing on the entry is a persona this service made up; the password
  // and the authenticator arrive through the activation link below — which is
  // why `credential: "none"` is said: a create naming no credential GENERATES a
  // password since 2026-09-12, and the person this section provisions is one
  // who holds nothing until the link is spent.
  const created = await apiPost("/users/create",
    { username: NEWCOMER, invent: false, credential: "none",
      attributes: personAttributes(NEWCOMER) });
  assert.ok(created.status === 200 || created.status === 201,
    "creating " + NEWCOMER + " answered " + created.status + " " +
    String(created.raw).slice(0, 300));

  const issued = await apiPost("/users/issue-activation",
                               { username: NEWCOMER });
  assert.ok(issued.status === 200,
    "issuing an activation link answered " + issued.status + " " +
    String(issued.raw).slice(0, 300));
  const url = issued.body.activationUrl || issued.body.url || "";
  assert.ok(url,
            "no activation URL came back: " + String(issued.raw).slice(0, 300));

  // THE LINK IS THE PORTAL'S PAGE; WHAT IT DRAWS IS `GET /account-api/
  // activation` with the link's `user` and `token`, which takes no access
  // token (#568). Opening the link is asking that.
  const linked = new URL(url, base);
  const linkQuery = "?user=" +
    encodeURIComponent(linked.searchParams.get("user") || "") + "&token=" +
    encodeURIComponent(linked.searchParams.get("token") || "");
  const opened = await portal.nobody(base, "GET",
                                     "/account-api/activation" + linkQuery);
  let page = { status: opened.status,
               text: opened.json
                 ? await drawForNobody("/portal/activate", opened.json) : "" };
  const token = (page.text.match(/name="token" value="([^"]+)"/) || [])[1];
  check("the setup form offers an authenticator app as an independent " +
        "CHECKBOX beside the password — it is a second factor, not one of " +
        "the answers to 'what signs you in'", function () {
    assert.strictEqual(page.status, 200, "the link answered " + page.status);
    assert.ok(/name="totp" value="1"/.test(page.text),
      "no authenticator checkbox on the setup form.");
    assert.ok(/type="checkbox"[^>]*name="totp"/.test(page.text) ||
              /name="totp"[^>]*type="checkbox"/.test(page.text),
      "the authenticator control is not a checkbox.");
  });

  let r = await portal.nobody(base, "POST", "/account-api/activation",
                              { user: NEWCOMER, token: token,
                                password: "First-Passw0rd!",
                                confirm: "First-Passw0rd!",
                                key_role: "none", totp: "1" });
  const enrolment = ((r.json && r.json.view) || {}).enrolment || {};
  const secret = String(enrolment.grouped || "").replace(/\s+/g, "");
  check("setting a password with the box ticked shows the secret rather than " +
        "finishing", function () {
    assert.strictEqual(r.status, 200, "it answered " + r.status);
    assert.strictEqual((r.json.view || {}).step, "totp",
      "the answer is not the authenticator's step: " +
      String(r.text).slice(0, 400));
    assert.ok(secret.length >= 32,
      "no secret in the step: " + String(r.text).slice(0, 400));
    assert.ok(/^data:image\/svg\+xml;base64,/.test(String(enrolment.qr || "")),
      "no QR code in the step.");
  });

  // **THE LINK IS NOT SPENT.** Asserted by USING it again rather than by
  // reading a flag: what somebody who abandons this step actually does is open
  // the link a second time.
  const reopened = await portal.nobody(base, "GET",
                                      "/account-api/activation" + linkQuery);
  check("AND THE ACTIVATION LINK IS STILL LIVE — somebody who ticks the box " +
        "and then cannot find their phone is not stranded with a spent link " +
        "and half an account", function () {
    assert.strictEqual(reopened.status, 200,
      "reopening the link answered " + reopened.status + ", so it was spent " +
      "before the setup finished.");
  });

  r = await portal.nobody(base, "POST", "/account-api/activation",
                          { user: NEWCOMER, token: token, step: "totp",
                            code: codeFor(secret) });
  const ready = r.json && r.json.view
    ? await drawForNobody("/portal/activate", r.json.view) : "";
  check("a code from the secret finishes the setup", function () {
    assert.strictEqual(r.status, 200, "it answered " + r.status);
    assert.ok(/Your account is ready/.test(ready),
      "the account-ready page was not drawn: " + String(r.text).slice(0, 400));
    assert.ok(/authenticator app is set up/i.test(ready),
      "and it does not say the authenticator was set up.");
  });

  const spent = await portal.nobody(base, "GET",
                                    "/account-api/activation" + linkQuery);
  check("and NOW the link is spent", function () {
    assert.strictEqual(spent.status, 400,
      "the link still works after the setup finished; it answered " +
      spent.status);
  });

  const seen = await apiGet("/mfa?q=" + encodeURIComponent(NEWCOMER));
  check("the newcomer holds a password AND an authenticator, having never " +
        "signed in", function () {
    const row = (seen.body.people || []).filter(function (one) {
      return one.username === NEWCOMER;
    })[0];
    assert.ok(row, NEWCOMER + " is not on /admin-api/mfa.");
    assert.strictEqual(row.totp, true, "no authenticator was stored.");
    assert.strictEqual(row.mfaRequired, true,
      "a second factor is not required of them.");
  });
  log.debug("Leaving anActivationLinkCanSetOneUp().");
}

// ===========================================================================
// 5. AN OPERATOR CAN CLEAR IT, AND THAT IS THE ONLY WAY BACK.
//
// The shared secret lives on a device this service cannot reach and there is
// deliberately no self-service reset — one anybody can use is no second factor
// — so a service that enforces a factor it cannot clear has a support queue
// rather than a security control.
//
// The assertion that means something is the TRANSITION: clearing it and then
// signing in with a password ALONE. A read-back saying `totp: false` would pass
// on a service that had stopped asking for the code for some other reason.
// ===========================================================================
// An authenticator app enrolled for `who` at /portal/mfa, with no wrong code
// and no replay on their record. Section 1 argues each step; this only does
// them.
async function enrolledPerson(who) {
  log.debug("Entering enrolledPerson(). who=" + who);
  const b = await signIn("/portal/mfa", who);
  let r = await b.portal.act("/portal/mfa", { action: "start" });
  // The start answers no secret (section 1 says why); it is on the page.
  assert.ok(r.status === 200, "starting " + who + "'s enrolment answered " +
            r.status);
  const page = await pageOf(b, "/portal/mfa");
  const secret = secretShownOn(page.text);
  assert.ok(secret, "no secret was shown when enrolling " + who);
  r = await b.portal.act("/portal/mfa", { action: "confirm",
                                          code: codeFor(secret) });
  assert.ok(r.status < 400, "confirming " + who + "'s enrolment answered " +
            r.status);
  log.debug("Leaving enrolledPerson().");
}

async function anOperatorCanClearIt() {
  log.debug("Entering anOperatorCanClearIt().");
  log.info("=== 5. clearing an authenticator through /admin-api ===");
  await enrolledPerson(CLEARED);
  const cleared = await apiPost("/mfa/clear-totp", { username: CLEARED });
  check("POST /admin-api/mfa/clear-totp accepts it", function () {
    assert.strictEqual(cleared.status, 200,
      "it answered " + cleared.status + " " +
      String(cleared.raw).slice(0, 300));
    assert.strictEqual(cleared.body.ok, true,
                       String(cleared.raw).slice(0, 200));
  });

  const again = await apiPost("/mfa/clear-totp", { username: CLEARED });
  check("and clearing one nobody holds is a 400 rather than a silent 200 — " +
        "the caller asked to clear a specific thing and it was not there",
        function () {
    assert.strictEqual(again.status, 400, "it answered " + again.status);
  });

  // THE TRANSITION. `signIn` with no handler ASSERTS that the password alone
  // was enough, so this one call is the whole claim.
  const b = await signIn(PORTAL_DOOR, CLEARED);
  const page = await pageOf(b, "/portal");
  check("AND THE PASSWORD ALONE SIGNS THEM IN AGAIN — the transition, which " +
        "is the only shape of assertion that can tell 'the factor was " +
        "cleared' from 'the factor was never being asked for'", function () {
    assert.strictEqual(page.status, 200, "/portal answered " + page.status);
    const amr = (page.text.match(/<tr><th>How<\/th><td>([^<]*)/) ||
                 [])[1] || "";
    assert.ok(!/otp/.test(amr),
      "the session still claims a one-time code: '" + amr + "'");
  });

  const rows = await apiGet("/audit?per=200");
  check("and the clear is in the audit log as an ADMIN act — a security " +
        "downgrade performed by a third party, which is the one shape of act " +
        "an audit log exists for", function () {
    const events = (rows.body.events || rows.body.rows || []);
    assert.ok(events.some(function (e) {
      return e.action === "admin.mfa.totp.cleared" &&
             JSON.stringify(e.detail || {}).indexOf(CLEARED) >= 0;
    }), "no admin.mfa.totp.cleared row naming " + CLEARED + ".");
  });
  log.debug("Leaving anOperatorCanClearIt().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Running the /portal/mfa and RFC 6238 checks against " + base);
  theGeneratorIsRight();
  const enrolment = await enrolling();
  await theSignInDemandsIt(enrolment);
  await oneUserCannotEnrolForAnother();
  await anActivationLinkCanSetOneUp();
  await anOperatorCanClearIt();
  log.info(checks + " assertion(s).");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error(e);
  process.exit(1);
});
