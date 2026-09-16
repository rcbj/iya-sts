"use strict";
//
// File: sts_portal_totp.js
//
// ===========================================================================
// AN AUTHENTICATOR APP IS ENROLLED IN THE PORTAL, AND THE SIGN-IN SCREEN THEN
// DEMANDS A CODE — ALL OF IT OVER HTTP, WITH THE CODE COMPUTED HERE.
//
// Five claims, driven through the real doors:
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
// `tests/totp.js` asserts `common/totp.js` against RFC 4226's and RFC 6238's
// own published vectors, so the SERVICE's arithmetic is known to be right. What
// that cannot show is that a THIRD PARTY holding the secret this service handed
// out can produce a code this service accepts — which is the only thing an
// authenticator app ever does, and the only claim a person cares about.
//
// So the thirty lines below are deliberately not `require`d from
// `common/totp.js`. They are the same shape a client author would write, and
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
// SIGN IN AT A DOOR. `/portal` is an OpenID Connect relying party of this
// service's own authorization server, so this is a code flow: the browser goes
// to `/oauth2/authorize`, meets the sign-in screen because the AUTHORIZATION
// ENDPOINT decides it needs one, and comes back with a code.
//
// `onSecondFactor` is handed the 200 the password POST answered with when the
// screen asks for something more, which is exactly what this job is about.
// ---------------------------------------------------------------------------
async function signIn(door, who, onSecondFactor) {
  log.debug("Entering signIn(). door=" + door + " who=" + who);
  await ensurePerson(who);
  const b = browser(who);
  let r = await b.go("GET", door);
  assert.ok(/\/oauth2\/authorize\?/.test(r.location),
    door + " should send an unauthenticated browser to the authorization " +
    "endpoint; it answered " + r.status + " -> " + r.location);
  r = await b.go("GET", r.location);
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
  r = await b.go("GET",
                 r.location);   // the authorization endpoint, with a code
  r = await b.go("GET", r.location);   // the callback, which mints the session
  assert.ok(b.cookie, "completing the flow should establish a session cookie.");
  log.debug("Leaving signIn().");
  return b;
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

  let page = await b.go("GET", "/portal/mfa");
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

  let r = await b.go("POST", "/portal/mfa",
                     form({ action: "start", csrf_token: csrfOf(page.text) }));
  check("starting the setup REDIRECTS rather than rendering — so a reload " +
        "cannot mint a second secret and invalidate the one just scanned",
        function () {
    assert.ok(r.status === 303 || r.status === 302,
      "POST start answered " + r.status);
  });

  page = await b.go("GET", "/portal/mfa");
  const secret = secretShownOn(page.text);
  check("the secret is shown BOTH ways: a QR code drawn on the server, and " +
        "the base32 in groups of four for a phone that cannot scan it",
        function () {
    assert.ok(qrShownOn(page.text),
      "no QR code data: URI on the page. Every page of this portal is " +
      "script-src 'none', so the image has to arrive rendered.");
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

  r = await b.go("POST", "/portal/mfa",
                 form({ action: "confirm", code: "000000",
                        csrf_token: csrfOf(page.text) }));
  check("a wrong code is refused and the SAME secret is redrawn — mistyping " +
        "six digits must not mean scanning again", function () {
    assert.strictEqual(r.status, 400, "a wrong code answered " + r.status);
    assert.strictEqual(secretShownOn(r.text), secret,
      "the page came back with a different secret, so a typo costs a rescan.");
  });

  const code = codeFor(secret);
  r = await b.go("POST", "/portal/mfa",
                 form({ action: "confirm", code: code,
                        csrf_token: csrfOf(r.text) }));
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
    assert.ok(r.status === 303 || r.status === 302 || r.status === 200,
      "the confirmation answered " + r.status + " " +
      String(r.text).slice(0, 300));
    if (r.status === 200) {
      assert.ok(!/class="err"/.test(r.text),
        "the confirmation answered 200 with an error on the page: " +
        String(r.text).slice(0, 300));
    }
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

  const page = await b.go("GET", "/portal");
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
  let page = await b.go("GET", "/portal/mfa");

  const beforeRows = await apiGet("/mfa?q=" + encodeURIComponent(OWNER));
  const before = (beforeRows.body.people || []).filter(function (one) {
    return one.username === OWNER;
  })[0];

  // Every parameter a future author might plausibly have read.
  const r = await b.go("POST", "/portal/mfa",
                       form({ action: "start", user: OWNER, username: OWNER,
                              subject: OWNER, uid: OWNER,
                              csrf_token: csrfOf(page.text) }));
  check("the POST is answered rather than erroring — the parameters are " +
        "simply not read", function () {
    assert.ok(r.status === 303 || r.status === 302 || r.status === 400,
      "it answered " + r.status);
  });

  page = await b.go("GET", "/portal/mfa");
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
  const confirm = await b.go("POST", "/portal/mfa",
                             form({ action: "confirm", user: OWNER,
                                    username: OWNER, code: "123456",
                                    csrf_token: csrfOf(page.text) }));
  check("and a confirmation naming somebody else confirms nothing of theirs " +
        "— the pending enrolment is keyed by the SESSION'S person",
        function () {
    assert.ok(confirm.status === 400 || confirm.status === 303,
      "it answered " + confirm.status);
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

  const b = browser(NEWCOMER);
  let page = await b.go("GET", url);
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

  let r = await b.go("POST", "/portal/activate",
                     form({ user: NEWCOMER, token: token,
                            password: "First-Passw0rd!",
                            confirm: "First-Passw0rd!",
                            key_role: "none", totp: "1" }));
  const secret = secretShownOn(r.text);
  check("setting a password with the box ticked shows the secret rather than " +
        "finishing", function () {
    assert.strictEqual(r.status, 200, "it answered " + r.status);
    assert.ok(secret.length >= 32,
      "no secret on the page: " + String(r.text).slice(0, 400));
    assert.ok(qrShownOn(r.text), "no QR code on the page.");
  });

  // **THE LINK IS NOT SPENT.** Asserted by USING it again rather than by
  // reading a flag: what somebody who abandons this step actually does is open
  // the link a second time.
  const reopened = await browser(NEWCOMER).go("GET", url);
  check("AND THE ACTIVATION LINK IS STILL LIVE — somebody who ticks the box " +
        "and then cannot find their phone is not stranded with a spent link " +
        "and half an account", function () {
    assert.strictEqual(reopened.status, 200,
      "reopening the link answered " + reopened.status + ", so it was spent " +
      "before the setup finished.");
  });

  r = await b.go("POST", "/portal/activate",
                 form({ user: NEWCOMER, token: token, step: "totp",
                        code: codeFor(secret) }));
  check("a code from the secret finishes the setup", function () {
    assert.strictEqual(r.status, 200, "it answered " + r.status);
    assert.ok(/Your account is ready/.test(r.text),
      "the account-ready page was not drawn: " + String(r.text).slice(0, 400));
    assert.ok(/authenticator app is set up/i.test(r.text),
      "and it does not say the authenticator was set up.");
  });

  const spent = await browser(NEWCOMER).go("GET", url);
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
async function anOperatorCanClearIt() {
  log.debug("Entering anOperatorCanClearIt().");
  log.info("=== 5. clearing an authenticator through /admin-api ===");
  const cleared = await apiPost("/mfa/clear-totp", { username: OWNER });
  check("POST /admin-api/mfa/clear-totp accepts it", function () {
    assert.strictEqual(cleared.status, 200,
      "it answered " + cleared.status + " " +
      String(cleared.raw).slice(0, 300));
    assert.strictEqual(cleared.body.ok, true,
                       String(cleared.raw).slice(0, 200));
  });

  const again = await apiPost("/mfa/clear-totp", { username: OWNER });
  check("and clearing one nobody holds is a 400 rather than a silent 200 — " +
        "the caller asked to clear a specific thing and it was not there",
        function () {
    assert.strictEqual(again.status, 400, "it answered " + again.status);
  });

  // THE TRANSITION. `signIn` with no handler ASSERTS that the password alone
  // was enough, so this one call is the whole claim.
  const b = await signIn(PORTAL_DOOR, OWNER);
  const page = await b.go("GET", "/portal");
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
             JSON.stringify(e.detail || {}).indexOf(OWNER) >= 0;
    }), "no admin.mfa.totp.cleared row naming " + OWNER + ".");
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
