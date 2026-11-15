// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_authn_api_surface.js
//
// ---------------------------------------------------------------------------
// THE SIGN-IN SURFACE OVER `/authn-api`, AS A BROWSER MEETS IT, OVER THE WIRE.
//
// D12 (#444): carries over `tests/authn_api.js` (#571),
// `tests/authn_mfa_api.js` (#572, #573) and `tests/authn_consent_api.js` (#576), which drove the
// stack in a child process and minted their pending sign-ins with
// `authn.beginAuthentication()`. Here every pending sign-in comes from a
// real authorization request of a public client of a throwaway realm, so a
// signed-in answer goes back to `/oauth2/authorize` and on to the client:
//
//   A. THE SCREEN'S SHELL: the bundle, the card, the `<noscript>`, no form,
//      no-store, a policy keeping `frame-ancestors` and allowing script and
//      API from 'self' only; the arrival cookie; an unknown id refused
//      `invalid_request`; the bundle served.
//   B. THE INDEX AND THE OPENAPI DOCUMENT: every page and control's
//      operation, the step operations, the consent view and answer.
//   C. THE VIEW: facts and no markup, a CSRF token per session.
//   D. THE BINDING of an act: JSON (415), an Origin of this service (403),
//      the token of the cookie's session (403), a malformed id, an unknown
//      id and an unknown field (400), every refusal code-free.
//   E. THE ACTS: a refused password keeps the pending sign-in and sets no
//      session cookie; a password signs in (the cookie on THAT answer,
//      `next: redirect`), the record spent; Cancel answers access_denied;
//      Continue without signing in off and on; the identity rate limit
//      (429); the forced password change (the realm's seeded `admin`); a
//      ticked passkey box answering the enrolment ceremony.
//   F. THE STEPS: an authenticator app's code page (the shell, a page it
//      cannot be drawn on refused, the old POST and `/authn/webauthn.js`
//      gone); the step's binding; a wrong code, the right one, the step
//      spent; a required set-up step (Ignore refused, the otpauth: URI and
//      no picture, a wrong first code, the right one enrolling and signing
//      in); the passkey step's ceremony and its two refusals; a session
//      refused at the end of a step drawn on the screen with its sentence;
//      Start over from a code step, a set-up step and the forced password
//      change, the original request completed, and its audit row.
//   G. THE CONSENT SCREEN: its shell and policy, its four refusals, its
//      view and token, its binding, Deny and Allow, a replay, and who is
//      asking (`logo_uri`, `policy_uri`, `tos_uri`) with the page's
//      `img-src` naming the logo's origin and nothing wider.
//   H. NO BEARER ID IN AN AUDIT ROW, and the old form POSTs gone.
//   I. THE PASSKEY CEREMONY'S ARMING is limited per address (429 with a
//      Retry-After), last, in a realm of its own, because the address
//      bucket is the runner's.
//
// NOT carried, and why: the comparisons with `websecurity.tokenFor()` and
// the module checks (`authnApi.operations`, `Authn.prototype.loginPage`) are
// the process's own (class (d)); the bundle's renderers drawing each view
// (`authn_mfa_api` 11k, `authn_consent_api` 8f–8h) are browser code (d);
// the recovery-code way round (`authn_mfa_api` 6) needs recovery codes no
// door this job can reach issues before a sign-in (owed, with the portal's
// recovery-code family); the RFC 9396 limit controls on the consent screen
// (`authn_consent_api` 3a, 4h, 5a, 5b) need a realm access type with limits
// (owed, with the authorization-details family); the emailed factor's view
// (`authn_mfa_api` 3e) needs a mail catcher (owed, with the mail family).
//
// OWNED HERE (local: true): this repository's sign-in surface and its API.
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
var log = bunyan.createLogger({ name: "sts_authn_api_surface",
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

const REALM = "aas-" + STAMP;
const LIMITS = "aasl-" + STAMP;
const PW = "Aas-" + STAMP + "-Correct.Horse.Battery.42";

function user(tag) {
  log.debug("Entering user(). " + tag);
  log.debug("Leaving user().");
  return ("as" + tag + STAMP).slice(0, 30);
}

async function person(rb, name) {
  log.debug("Entering person(). " + name);
  await ok(rb + "/admin-api/users/create", { username: name, invent: false,
    attributes: { cn: "Aas " + name, sn: name, givenName: ["Aas"],
                  mail: [name + "@example.test"] },
    credential: "password", password: PW }, "created " + name);
  log.debug("Leaving person().");
}

// A pending sign-in of the realm's client: the screen's absolute address.
async function pending(rb, app, extra) {
  log.debug("Entering pending().");
  const r = await authorize(rb, app, null, extra);
  assert.ok(/\/authn\/login\?authn=/.test(r.location),
            "the authorization request should send the browser to the " +
            "sign-in screen; it answered " + r.status + " " + r.location);
  log.debug("Leaving pending().");
  return r.location;
}

// Signs `name` in up to their step: `{ answer, opened }`.
async function toStep(rb, app, name, fields) {
  log.debug("Entering toStep(). " + name);
  const answer = await authnSignin.submit(rb, await pending(rb, app),
    Object.assign({ action: "login", username: name, password: PW },
                  fields || {}), {});
  let opened = null;
  if (answer.next === "mfa") {
    opened = await authnSignin.step(answer.location,
                                    { cookie: answer.cookie });
  }
  log.debug("Leaving toStep(). " + answer.next);
  return { answer: answer, opened: opened };
}

// Enrols an authenticator app through the required set-up step and
// answers its secret; the person's requirement is taken away after.
async function enrolTotp(rb, app, name) {
  log.debug("Entering enrolTotp(). " + name);
  await ok(rb + "/admin-api/users/require-mfa", { user: name },
           "required a second factor of " + name);
  const s = await toStep(rb, app, name);
  const begun = await authnSignin.stepAct(s.opened, "setup/totp", {});
  const shown = await authnSignin.step(begun.location,
                                       { cookie: s.opened.cookie });
  const secret = ((shown.view.setup || {}).totp || {}).secret || "";
  const done = await authnSignin.stepAct(shown, "setup/confirm",
                                         { code: totp(secret, 0) });
  assert.strictEqual(done.next, "redirect", done.text.slice(0, 300));
  await ok(rb + "/admin-api/users/stop-requiring-mfa", { user: name },
           "stopped requiring a second factor of " + name);
  log.debug("Leaving enrolTotp().");
  return secret;
}

const seenIds = [];

async function sectionScreen(rb, app) {
  log.debug("Entering sectionScreen().");
  log.info("=== A–E. the screen ===");
  const at = await pending(rb, app);
  const id = authnSignin.pendingIdOf(at);
  seenIds.push(id);
  const shell = await fetch(at, { redirect: "manual" });
  const text = await shell.text();
  const csp = String(shell.headers.get("content-security-policy") || "");
  const cookies = shell.headers.getSetCookie();
  check("A1. /authn/login answers the shell: the bundle, the card, the " +
        "notice, no form, no-store", function () {
    assert.strictEqual(shell.status, 200);
    assert.ok(/no-store/.test(String(shell.headers.get("cache-control"))));
    assert.ok(/<script src="(\/realm\/[^/"]+)?\/authn\/signin\.js" defer>/
      .test(text), text.slice(0, 600));
    assert.ok(/<link rel="stylesheet" href="(\/realm\/[^/"]+)?\/web\/card\.css">/
      .test(text), text.slice(0, 600));
    assert.ok(text.indexOf("<noscript>") > 0);
    assert.ok(!/<form/.test(text) && !/name="password"/.test(text));
  });
  check("A2. its policy keeps frame-ancestors and allows script and API " +
        "from 'self' only", function () {
    assert.ok(/frame-ancestors 'none'/.test(csp), csp);
    assert.ok(/script-src 'self'(;|$)/.test(csp), csp);
    assert.ok(/connect-src 'self'/.test(csp), csp);
    assert.ok(!/unsafe-inline/.test(csp), csp);
  });
  check("A3. and it mints the arrival cookie for a browser without one",
        function () {
    assert.ok(sessionCookieIn(cookies), JSON.stringify(cookies));
  });
  const unknown = await send(rb + "/authn/login?authn=nosuchsignin");
  check("A4. an unknown id is refused invalid_request, code-free",
        function () {
    assert.strictEqual(unknown.status, 400, unknown.raw.slice(0, 200));
    assert.strictEqual(unknown.body && unknown.body.error,
                       "invalid_request");
    assert.ok(codeFree(unknown.raw));
  });
  const bundle = await send(base + "/authn/signin.js");
  check("A5. the bundle is served, built", function () {
    assert.strictEqual(bundle.status, 200);
    assert.ok(/javascript/.test(bundle.headers.get("content-type")));
    assert.ok(bundle.raw.length > 1000 &&
              bundle.raw.indexOf("was not built") < 0);
  });

  const index = await send(rb + "/authn-api");
  const ops = (index.body && index.body.operations) || [];
  function mirror(m, action) {
    log.debug("Entering mirror(). " + m);
    log.debug("Leaving mirror().");
    return ops.filter(function (op) {
      return op.mirrors === m && (!action || op.action === action);
    }).length === 1;
  }
  check("B1. the index names the operation each page and control is",
        function () {
    assert.strictEqual(index.status, 200);
    ["GET /authn/login", "GET /authn/select-idp",
     "GET /authn/password-change"].forEach(function (m) {
      assert.ok(mirror(m), m);
    });
    assert.ok(mirror("POST /authn/password-change", "password-change"));
    assert.ok(mirror("POST /authn/password-change", "start-over"));
    ["login", "cancel", "anonymous", "email", "passkey-options",
     "passkey"].forEach(function (a) {
      assert.ok(mirror("POST /authn/login", a), a);
    });
  });
  const paths = ops.map(function (op) {
    return op.method + " " + op.path;
  });
  check("B2. and every step's operation", function () {
    ["POST /authn-api/mfa/{id}/totp", "POST /authn-api/mfa/{id}/setup/totp",
     "POST /authn-api/mfa/{id}/setup/confirm",
     "POST /authn-api/mfa/{id}/setup/webauthn",
     "POST /authn-api/mfa/{id}/start-over",
     "GET /authn-api/mfa/{id}"].forEach(function (p) {
      assert.ok(paths.indexOf(p) >= 0, p + " in " + paths.join(", "));
    });
  });
  check("B3. and the consent screen's view and answer", function () {
    assert.ok(paths.indexOf("GET /authn-api/consent/{id}") >= 0,
              paths.join(", "));
    assert.ok(paths.indexOf("POST /authn-api/consent/{id}") >= 0,
              paths.join(", "));
  });
  const doc = await send(rb + "/authn-api/openapi.json");
  check("B4. the OpenAPI document is 3.1.0 and carries the bodies",
        function () {
    assert.strictEqual(doc.status, 200);
    assert.strictEqual(doc.body.openapi, "3.1.0");
    const pw = doc.body.paths["/authn-api/pending/{id}/password"];
    assert.ok(pw && pw.post && pw.post.requestBody);
    const totpOp = doc.body.paths["/authn-api/mfa/{id}/totp"];
    assert.ok(totpOp && totpOp.post && totpOp.post.requestBody);
    const consent = doc.body.paths["/authn-api/consent/{id}"];
    assert.ok(consent && consent.get && consent.post &&
              consent.post.requestBody);
  });

  const opened = await authnSignin.screen(rb, at,
    { cookie: cookies.map(function (c) {
      return c.split(";")[0];
    }).join("; ") });
  const v = opened.view || {};
  check("C1. the view is facts and no markup", function () {
    assert.strictEqual(opened.status, 200);
    assert.strictEqual(v.screen, true);
    assert.strictEqual(typeof v.password, "boolean");
    assert.ok(v.keys && v.demands && Array.isArray(v.details));
    assert.ok(!/<[a-z]/.test(JSON.stringify(v)), JSON.stringify(v));
  });
  const again = await authnSignin.screen(rb, at, { cookie: opened.cookie });
  const other = await authnSignin.screen(rb, await pending(rb, app));
  check("C2. csrf is the cookie's session's: the same twice, another " +
        "browser's differs", function () {
    assert.ok(opened.csrf && opened.csrf === again.csrf);
    assert.ok(other.csrf && other.csrf !== opened.csrf);
  });

  const pwPath = "/authn-api/pending/" + encodeURIComponent(opened.id) +
                 "/password";
  function tryAct(o) {
    log.debug("Entering tryAct().");
    log.debug("Leaving tryAct().");
    return authnSignin.act(rb, o.path || pwPath,
      o.body || { username: user("x"), password: "p" },
      Object.assign({ cookie: opened.cookie, csrf: opened.csrf }, o.opts));
  }
  const refusals = {};
  refusals.form = await tryAct({ body: "username=x",
    opts: { contentType: "application/x-www-form-urlencoded" } });
  refusals.noOrigin = await tryAct({ opts: { origin: null } });
  refusals.evil = await tryAct({ opts: { origin: "https://evil.example" } });
  refusals.noToken = await tryAct({ opts: { csrf: "" } });
  refusals.otherToken = await tryAct({ opts: { csrf: other.csrf } });
  refusals.noSession = await tryAct({ opts: { cookie: "" } });
  refusals.malformed = await tryAct({
    path: "/authn-api/pending/not*an*id/password" });
  refusals.unknown = await tryAct({
    path: "/authn-api/pending/AAAAAAAAAAAAAAAAAAAAAAAA/password" });
  refusals.field = await tryAct({ body: { username: user("x"),
                                          password: "p", admin: "1" } });
  check("D1. a body that is not JSON is refused 415", function () {
    assert.strictEqual(refusals.form.status, 415);
  });
  check("D2. no Origin, another origin, no token, another session's token " +
        "and no session are each refused 403", function () {
    ["noOrigin", "evil", "noToken", "otherToken", "noSession"].forEach(
      function (k) {
        assert.strictEqual(refusals[k].status, 403, k + " " +
                           refusals[k].text.slice(0, 200));
      });
  });
  check("D3. a malformed id, an unknown id (no sign-in waiting) and a " +
        "field the operation does not take are refused 400", function () {
    assert.strictEqual(refusals.malformed.status, 400);
    assert.strictEqual(refusals.unknown.status, 400);
    assert.ok(/no sign-in waiting/i.test(refusals.unknown.text),
              refusals.unknown.text);
    assert.strictEqual(refusals.field.status, 400,
                       refusals.field.text.slice(0, 200));
  });
  check("D4. no refusal carries an error code", function () {
    Object.keys(refusals).forEach(function (k) {
      assert.ok(codeFree(refusals[k].text), k + " " + refusals[k].text);
    });
  });

  const ann = user("ann");
  const wrong = await authnSignin.submit(rb, at, { action: "login",
    username: ann, password: "invalid" }, { screen: opened });
  check("E1. a refused password answers next: refused, English and " +
        "code-free, and sets no session cookie", function () {
    assert.strictEqual(wrong.status, 400, wrong.text);
    assert.strictEqual(wrong.next, "refused");
    assert.ok(new RegExp("Authentication failed for " + ann)
      .test(wrong.errors.join(" ")), wrong.text);
    assert.ok(codeFree(wrong.text));
    assert.ok(!sessionCookieIn(wrong.headers.getSetCookie().filter(
      function (c) {
        return opened.setCookies.indexOf(c) < 0;
      })), JSON.stringify(wrong.headers.getSetCookie()));
  });
  const right = await authnSignin.submit(rb, at, { action: "login",
    username: ann, password: "right" }, { screen: opened });
  check("E2. the pending sign-in survives a refusal, and a password signs " +
        "in: next: redirect back to the authorization request, the " +
        "session cookie set on that answer", function () {
    assert.strictEqual(right.next, "redirect", right.text);
    assert.ok(/\/oauth2\/authorize\?/.test(right.location), right.location);
    assert.ok(sessionCookieIn(right.headers.getSetCookie().filter(
      function (c) {
        return opened.setCookies.indexOf(c) < 0;
      })), JSON.stringify(right.headers.getSetCookie()));
  });
  const back = await fetch(right.location, { redirect: "manual",
    headers: { cookie: right.cookie } });
  await back.text();
  check("E3. and the authorization request answers its client a code",
        function () {
    assert.strictEqual(back.status, 302);
    assert.ok(/^https:\/\/rp\.example\/[^?]+\/cb\?code=/.test(
      String(back.headers.get("location"))) ||
      /\/oauth2\/consent/.test(String(back.headers.get("location"))),
      String(back.headers.get("location")));
  });
  const spent = await authnSignin.act(rb, pwPath, { username: ann,
    password: "right" }, { cookie: right.cookie, csrf: opened.csrf });
  const spentView = await authnSignin.screen(rb, at, { cookie: right.cookie });
  check("E4. and the pending sign-in is spent: its act and its view are " +
        "refused 400 to the browser now signed in", function () {
    assert.strictEqual(spent.status, 400, spent.text);
    assert.strictEqual(spentView.status, 400, JSON.stringify(spentView.json));
  });

  const cancelled = await authnSignin.submit(rb, await pending(rb, app),
    { action: "cancel" }, {});
  check("E5. Cancel answers the caller access_denied", function () {
    assert.strictEqual(cancelled.next, "redirect", cancelled.text);
    assert.ok(/access_denied/.test(cancelled.location), cancelled.location);
  });

  await realmSet(REALM, "authn.unauthenticatedSessions", false);
  const anonOff = await authnSignin.submit(rb, await pending(rb, app),
    { action: "anonymous" }, {});
  await realmSet(REALM, "authn.unauthenticatedSessions", true);
  const anonAt = await pending(rb, app);
  const anonOpen = await authnSignin.screen(rb, anonAt);
  const anonOn = await authnSignin.submit(rb, anonAt, { action: "anonymous" },
                                          { screen: anonOpen });
  await realmSet(REALM, "authn.unauthenticatedSessions", false);
  check("E6. Continue without signing in is no session with the setting " +
        "off", function () {
    assert.strictEqual(anonOff.next, "refused", anonOff.text);
  });
  check("E7. with it on, the view offers it and it starts an " +
        "unauthenticated session", function () {
    assert.strictEqual(anonOpen.view && anonOpen.view.anonymous, true);
    assert.strictEqual(anonOn.next, "redirect", anonOn.text);
    assert.ok(sessionCookieIn(anonOn.headers.getSetCookie()));
  });

  await realmSet(REALM, "security.rateLimitPerIdentity", 2);
  await realmSet(REALM, "security.rateLimitPerAddress", 10000);
  const rlAt = await pending(rb, app);
  const rlOpen = await authnSignin.screen(rb, rlAt);
  let last = null;
  for (let i = 0; i < 4; i += 1) {
    last = await authnSignin.submit(rb, rlAt, { action: "login",
      username: user("rl"), password: "invalid" }, { screen: rlOpen });
  }
  await realmSet(REALM, "security.rateLimitPerIdentity", 50);
  check("E8. the sign-in rate limit answers 429, code-free", function () {
    assert.strictEqual(last.status, 429, last.text);
    assert.strictEqual(last.next, "refused");
    assert.ok(codeFree(last.text));
  });

  // The forced password change: the realm's seeded administrator carries
  // pwdReset (rb's bootstrap answer said so).
  const pc = await authnSignin.submit(rb, await pending(rb, app),
    { action: "login", username: "admin", password: "x" }, {});
  check("E9. pwdReset answers next: password-change", function () {
    assert.strictEqual(pc.next, "password-change", pc.text);
    assert.ok(/\/authn\/password-change\?change=|#change=/.test(pc.location),
              pc.location);
  });
  const pcView = await authnSignin.screen(rb, pc.location,
    { cookie: pc.cookie, page: "password-change" });
  check("E10. its view names the person", function () {
    assert.strictEqual(pcView.status, 200);
    assert.strictEqual(pcView.view && pcView.view.username, "admin");
  });
  const pcBad = await authnSignin.changePassword(rb, pc.location,
    { new_password: "One-New-Pass-" + STAMP + "!",
      confirm_password: "Another-" + STAMP + "!" }, { cookie: pc.cookie });
  check("E11. a mismatch is refused, the step kept", function () {
    assert.strictEqual(pcBad.status, 400, pcBad.text);
    assert.ok(/not the same/.test(pcBad.errors.join(" ")), pcBad.text);
  });
  const fresh = "One-New-Pass-" + STAMP + "-Long.Enough!";
  const pcGood = await authnSignin.changePassword(rb, pc.location,
    { new_password: fresh, confirm_password: fresh }, { cookie: pc.cookie });
  check("E12. a good change continues the sign-in", function () {
    assert.ok(pcGood.next === "redirect" || pcGood.next === "mfa",
              pcGood.text);
  });
  const again2 = await authnSignin.submit(rb, await pending(rb, app),
    { action: "login", username: "admin", password: fresh }, {});
  check("E13. and pwdReset is cleared: the next sign-in is no change",
        function () {
    assert.notStrictEqual(again2.next, "password-change", again2.text);
  });

  const kim = user("kim");
  await person(rb, kim);
  const pk = await toStep(rb, app, kim, { use_webauthn: "1" });
  check("E14. ticking the passkey box answers the ceremony's step, whose " +
        "view is its enrolment ceremony", function () {
    assert.strictEqual(pk.answer.next, "mfa", pk.answer.text);
    assert.strictEqual(pk.answer.step, "webauthn");
    assert.strictEqual(pk.opened.status, 200, pk.opened.text);
    assert.strictEqual(pk.opened.view.webauthn.mode, "create");
  });
  const armed = await authnSignin.stepAct(pk.opened, "webauthn/options", {});
  const c = armed.json || {};
  check("F1. its ceremony is armed: challenge, RP ID, user and its handle",
        function () {
    assert.strictEqual(armed.status, 200, armed.text);
    assert.strictEqual(c.mode, "create");
    assert.ok(c.challenge && c.rpId && c.user && c.user.id && c.options);
    assert.strictEqual(c.user.name, kim);
    assert.ok(Array.isArray(c.exclude));
  });
  const noCeremony = await authnSignin.stepAct(pk.opened, "webauthn", {});
  const declined = await authnSignin.stepAct(pk.opened, "webauthn",
    { credential: "{\"error\":\"NotAllowedError\",\"message\":\"declined\"}" });
  check("F2. a result with no ceremony in it is refused, and the browser's " +
        "refusal is said as given, the step kept", function () {
    assert.strictEqual(noCeremony.status, 400, noCeremony.text);
    assert.ok(/did not run the ceremony/.test(noCeremony.errors.join(" ")),
              noCeremony.text);
    assert.strictEqual(declined.status, 400, declined.text);
    assert.ok(/NotAllowedError/.test(declined.errors.join(" ")),
              declined.text);
  });
  log.debug("Leaving sectionScreen().");
}

async function sectionSteps(rb, app) {
  log.debug("Entering sectionSteps().");
  log.info("=== F. the steps after the screen ===");
  const sue = user("sue");
  await person(rb, sue);
  await ok(rb + "/admin-api/users/require-mfa", { user: sue },
           "required a second factor of " + sue);
  const s = await toStep(rb, app, sue);
  seenIds.push(s.opened.id);
  check("F3. a required second factor answers the set-up step's choice",
        function () {
    assert.strictEqual(s.answer.next, "mfa", s.answer.text);
    assert.strictEqual(s.answer.step, "enrol");
    assert.strictEqual(s.opened.view.page, "setup");
    assert.strictEqual(s.opened.view.setup.state, "choose");
    assert.strictEqual(s.opened.view.setup.optional, false);
  });
  const skip = await authnSignin.stepAct(s.opened, "skip", {});
  check("F4. Ignore is refused on a required step", function () {
    assert.strictEqual(skip.status, 400, skip.text);
    assert.ok(/cannot be ignored/.test(skip.errors.join(" ")), skip.text);
  });
  const begun = await authnSignin.stepAct(s.opened, "setup/totp", {});
  check("F5. an authenticator app begun answers the set-up page again",
        function () {
    assert.strictEqual(begun.next, "mfa", begun.text);
    assert.strictEqual(begun.step, "enrol-totp");
    assert.ok(/\/authn\/mfa-setup[?#]/.test(begun.location), begun.location);
  });
  const shown = await authnSignin.step(begun.location,
                                       { cookie: s.opened.cookie });
  const k = (shown.view && shown.view.setup && shown.view.setup.totp) || {};
  check("F6. its view carries the otpauth: URI the browser draws, and no " +
        "picture", function () {
    assert.strictEqual(shown.view.setup.state, "totp");
    assert.ok(/^otpauth:\/\/totp\//.test(String(k.uri)), String(k.uri));
    assert.ok(k.secret);
    assert.ok(!/<svg|data:image/.test(shown.text));
  });
  const secret = new URL(String(k.uri)).searchParams.get("secret");
  const good = totp(secret, 0);
  const bad = await authnSignin.stepAct(shown, "setup/confirm",
    { code: good === "000000" ? "111111" : "000000" });
  const enrolled = await authnSignin.stepAct(shown, "setup/confirm",
                                             { code: good });
  check("F7. a wrong first code is refused, the secret kept; the right one " +
        "enrols the app and signs in", function () {
    assert.strictEqual(bad.status, 400, bad.text);
    assert.strictEqual(bad.next, "refused");
    assert.strictEqual(enrolled.next, "redirect", enrolled.text);
    assert.ok(/\/oauth2\/authorize\?/.test(enrolled.location));
    assert.ok(sessionCookieIn(enrolled.headers.getSetCookie()));
  });
  await ok(rb + "/admin-api/users/stop-requiring-mfa", { user: sue },
           "stopped requiring a second factor of " + sue);

  const tom = user("tom");
  await person(rb, tom);
  const tomSecret = await enrolTotp(rb, app, tom);
  const t = await toStep(rb, app, tom);
  seenIds.push(t.opened.id);
  check("F8. a person holding an authenticator app is answered next: mfa, " +
        "the code page's address, and no session cookie", function () {
    assert.strictEqual(t.answer.next, "mfa", t.answer.text);
    assert.strictEqual(t.answer.step, "totp");
    assert.ok(/\/authn\/totp[?#]/.test(t.answer.location));
    // The shell's arrival cookie is the only session cookie on the walk.
    const values = t.answer.headers.getSetCookie().filter(function (one) {
      return /^(__Host-)?sts_session=[^;]+/.test(one);
    }).map(function (one) {
      return one.split(";")[0];
    });
    assert.ok(new Set(values).size <= 1, JSON.stringify(values));
  });
  check("F9. and that page is the surface's shell, drawn from its step's " +
        "view", function () {
    assert.strictEqual(t.opened.shellStatus, 200);
    assert.strictEqual(t.opened.status, 200, t.opened.text);
    assert.strictEqual(t.opened.view.page, "totp");
    assert.strictEqual(t.opened.view.username, tom);
  });
  const stepBase = t.opened.base;
  const wrongPage = await send(stepBase + "/authn-api/mfa/" +
    encodeURIComponent(t.opened.id) + "?page=webauthn",
    { headers: { cookie: t.opened.cookie, accept: "application/json" } });
  const noPage = await send(stepBase + "/authn-api/mfa/" +
    encodeURIComponent(t.opened.id) + "?page=nonsense",
    { headers: { cookie: t.opened.cookie, accept: "application/json" } });
  const wrongShell = await send(stepBase + "/authn/webauthn?mfa=" +
    encodeURIComponent(t.opened.id), { headers: { cookie: t.opened.cookie } });
  check("F10. a page its step cannot be drawn on is refused code-free, at " +
        "the view and at the shell, and a page that is not one is refused",
        function () {
    assert.ok(wrongPage.status >= 400 && wrongPage.status < 500,
              wrongPage.status + " " + wrongPage.raw.slice(0, 200));
    assert.ok(codeFree(wrongPage.raw));
    assert.strictEqual(noPage.status, 400, noPage.raw.slice(0, 200));
    assert.strictEqual(wrongShell.status, 400,
                       wrongShell.status + " " + wrongShell.raw.slice(0, 200));
  });
  const oldPost = await send(stepBase + "/authn/totp", { method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded",
               cookie: t.opened.cookie },
    body: "mfa=" + encodeURIComponent(t.opened.id) + "&code=000000" });
  const oldScript = await send(base + "/authn/webauthn.js");
  check("F11. the old step form POST and /authn/webauthn.js are gone",
        function () {
    assert.strictEqual(oldPost.status, 404, String(oldPost.status));
    assert.strictEqual(oldScript.status, 404, String(oldScript.status));
  });
  const totpPath = "/authn-api/mfa/" + encodeURIComponent(t.opened.id) +
                   "/totp";
  const other = await authnSignin.screen(rb, await pending(rb, app));
  const b = {};
  b.form = await authnSignin.stepAct(t.opened, "totp", "code=1",
    { contentType: "application/x-www-form-urlencoded" });
  b.noOrigin = await authnSignin.stepAct(t.opened, "totp", { code: "1" },
                                         { origin: null });
  b.evil = await authnSignin.stepAct(t.opened, "totp", { code: "1" },
                                     { origin: "https://evil.example" });
  b.otherToken = await authnSignin.stepAct(t.opened, "totp", { code: "1" },
                                           { csrf: other.csrf });
  b.malformed = await authnSignin.act(stepBase, "/authn-api/mfa/not*an*id/" +
    "totp", { code: "1" }, { cookie: t.opened.cookie, csrf: t.opened.csrf });
  b.unknown = await authnSignin.act(stepBase, "/authn-api/mfa/" +
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/totp", { code: "1" },
    { cookie: t.opened.cookie, csrf: t.opened.csrf });
  b.field = await authnSignin.stepAct(t.opened, "totp",
                                      { code: "1", admin: "1" });
  check("F12. a step's act is bound as the screen's: 415, 403, 403, 403, " +
        "400, 400, 400, all code-free", function () {
    assert.strictEqual(b.form.status, 415, b.form.text);
    assert.strictEqual(b.noOrigin.status, 403);
    assert.strictEqual(b.evil.status, 403);
    assert.strictEqual(b.otherToken.status, 403);
    assert.strictEqual(b.malformed.status, 400);
    assert.strictEqual(b.unknown.status, 400);
    assert.strictEqual(b.field.status, 400, b.field.text);
    Object.keys(b).forEach(function (one) {
      assert.ok(codeFree(b[one].text), one + " " + b[one].text);
    });
  });
  void totpPath;
  const nextCode = totp(tomSecret, 1);
  const wrongCode = await authnSignin.stepAct(t.opened, "totp",
    { code: nextCode === "000000" ? "111111" : "000000" });
  check("F13. a wrong code is refused, English and code-free, with no " +
        "session cookie", function () {
    assert.strictEqual(wrongCode.status, 400, wrongCode.text);
    assert.strictEqual(wrongCode.next, "refused");
    assert.ok(codeFree(wrongCode.text));
    assert.ok(!sessionCookieIn(wrongCode.headers.getSetCookie().filter(
      function (one) {
        return t.opened.setCookies.indexOf(one) < 0;
      })));
  });
  const rightCode = await authnSignin.stepAct(t.opened, "totp",
                                              { code: nextCode });
  const spentStep = await authnSignin.stepAct(t.opened, "totp",
    { code: nextCode }, { cookie: rightCode.cookie });
  check("F14. the step survives a wrong code, and the right one signs in: " +
        "next: redirect, the session cookie on that answer; then the step " +
        "is spent", function () {
    assert.strictEqual(rightCode.next, "redirect", rightCode.text);
    assert.ok(/\/oauth2\/authorize\?/.test(rightCode.location));
    assert.ok(sessionCookieIn(rightCode.headers.getSetCookie()));
    assert.strictEqual(spentStep.status, 400, spentStep.text);
  });

  // A session refused at the end of a step: disabled in between.
  const dan = user("dan");
  await person(rb, dan);
  const danSecret = await enrolTotp(rb, app, dan);
  const d = await toStep(rb, app, dan);
  await ok(rb + "/admin-api/users/disable", { user: dan, reason: "d12" },
           "disabled " + dan);
  const refusedAtEnd = await authnSignin.stepAct(d.opened, "totp",
    { code: totp(danSecret, 1) });
  await ok(rb + "/admin-api/users/enable", { user: dan },
           "enabled " + dan);
  check("F15. a session refused at the end of the step answers the " +
        "sign-in screen's address", function () {
    assert.strictEqual(refusedAtEnd.status, 400, refusedAtEnd.text);
    assert.strictEqual(refusedAtEnd.next, "refused");
    assert.ok(/\/authn\/login[?#]authn=/.test(
      String(refusedAtEnd.json && refusedAtEnd.json.location)),
      refusedAtEnd.text);
  });
  const drawnBack = await authnSignin.screen(rb, new URL(
    String(refusedAtEnd.json.location), rb).toString(),
    { cookie: d.opened.cookie });
  check("F16. and the screen's view says why", function () {
    assert.strictEqual(drawnBack.status, 200);
    assert.ok(/Authentication failed/.test(String(drawnBack.view &&
      drawnBack.view.error)), JSON.stringify(drawnBack.view));
  });

  // Start over.
  const sam = user("sam");
  await person(rb, sam);
  const samSecret = await enrolTotp(rb, app, sam);
  const soAt = await pending(rb, app);
  const soId = authnSignin.pendingIdOf(soAt);
  const soAnswer = await authnSignin.submit(rb, soAt, { action: "login",
    username: sam, password: PW }, {});
  const soOpened = await authnSignin.step(soAnswer.location,
                                          { cookie: soAnswer.cookie });
  const whileOpen = await authnSignin.screen(rb, soAt,
                                             { cookie: soAnswer.cookie });
  const so = await authnSignin.stepAct(soOpened, "start-over", {});
  check("F17. while the step is open the pending sign-in is the step's; " +
        "Start over answers the sign-in screen for the SAME request and " +
        "starts no session", function () {
    assert.ok(whileOpen.status >= 400, String(whileOpen.status));
    assert.strictEqual(so.next, "redirect", so.text);
    assert.ok(new RegExp("/authn/login\\?authn=" + soId.replace(
      /[-_]/g, "[-_]") + "$").test(so.location), so.location);
    assert.ok(!sessionCookieIn(so.headers.getSetCookie()));
    assert.ok(codeFree(so.text));
  });
  const soScreen = await authnSignin.screen(rb, so.location,
                                            { cookie: soAnswer.cookie });
  check("F18. the pending sign-in is back under its id, and the screen " +
        "draws for it with no sentence on it", function () {
    assert.strictEqual(soScreen.status, 200);
    assert.ok(soScreen.view && !soScreen.view.error,
              JSON.stringify(soScreen.view && soScreen.view.error));
  });
  const so2 = await authnSignin.stepAct(soOpened, "start-over", {});
  const oldStep = await authnSignin.stepAct(soOpened, "totp",
                                            { code: totp(samSecret, 1) });
  check("F19. a second Start over from the ended step is refused, and the " +
        "old step takes no code", function () {
    assert.strictEqual(so2.status, 400, so2.text);
    assert.strictEqual(so2.next, "refused");
    assert.ok(codeFree(so2.text));
    assert.strictEqual(oldStep.status, 400, oldStep.text);
  });
  const re = await authnSignin.submit(rb, so.location, { action: "login",
    username: sam, password: PW }, { screen: soScreen });
  const reStep = await authnSignin.step(re.location, { cookie: re.cookie });
  const reDone = await authnSignin.stepAct(reStep, "totp",
                                           { code: totp(samSecret, 1) });
  check("F20. signing in again completes the ORIGINAL request", function () {
    assert.strictEqual(re.next, "mfa", re.text);
    assert.strictEqual(reDone.next, "redirect", reDone.text);
    assert.ok(/\/oauth2\/authorize\?/.test(reDone.location));
    assert.ok(sessionCookieIn(reDone.headers.getSetCookie()));
  });
  const audit = await send(rb + "/admin-api/audit?per=500&action=" +
                           "authn.sign-in.started-over");
  check("F21. the audit log records the start over, by the person",
        function () {
    const rows = (audit.body && (audit.body.rows || audit.body.entries ||
                                 audit.body.events)) || [];
    assert.ok(rows.some(function (row) {
      return row.action === "authn.sign-in.started-over" &&
             row.actor === sam;
    }), audit.raw.slice(0, 600));
  });
  const sid = user("sid");
  await person(rb, sid);
  await ok(rb + "/admin-api/users/require-mfa", { user: sid },
           "required a second factor of " + sid);
  const setupStep = await toStep(rb, app, sid);
  const setupOver = await authnSignin.stepAct(setupStep.opened, "start-over",
                                              {});
  check("F22. the set-up step starts over too", function () {
    assert.strictEqual(setupStep.answer.step, "enrol");
    assert.strictEqual(setupOver.next, "redirect", setupOver.text);
    assert.ok(/\/authn\/login[?#]authn=/.test(setupOver.location));
  });
  log.debug("Leaving sectionSteps().");
}

async function sectionPasswordChangeStartOver(rb, app) {
  log.debug("Entering sectionPasswordChangeStartOver().");
  // A second realm's seeded administrator, still holding pwdReset.
  const rb2 = await makeRealm("aasp-" + STAMP, null);
  await oauthClient(rb2, app);
  const at = await pending(rb2, app);
  const id = authnSignin.pendingIdOf(at);
  const pc = await authnSignin.submit(rb2, at, { action: "login",
    username: "admin", password: "x" }, {});
  const pcOpened = await authnSignin.screen(rb2, pc.location,
    { cookie: pc.cookie, page: "password-change" });
  const over = await authnSignin.act(rb2, "/authn-api/password-change/" +
    encodeURIComponent(pcOpened.id) + "/start-over", {},
    { cookie: pcOpened.cookie, csrf: pcOpened.csrf });
  const still = await authnSignin.submit(rb2, await pending(rb2, app),
    { action: "login", username: "admin", password: "x" }, {});
  check("F23. the forced password change starts over to the same request, " +
        "changing nothing", function () {
    assert.strictEqual(pc.next, "password-change", pc.text);
    assert.strictEqual(over.next, "redirect", over.text);
    assert.ok(new RegExp("/authn/login\\?authn=" + id.replace(/[-_]/g,
      "[-_]") + "$").test(over.location), over.location);
    assert.strictEqual(still.next, "password-change", still.text);
  });
  log.debug("Leaving sectionPasswordChangeStartOver().");
}

async function sectionConsent(rb) {
  log.debug("Entering sectionConsent().");
  log.info("=== G. the consent screen ===");
  const app = "aasc-" + STAMP;
  const plain = "aasn-" + STAMP;
  await oauthClient(rb, app, {
    oauthLogoUri: "https://logo.example/" + app + ".png",
    oauthPolicyUri: "https://rp.example/policy",
    oauthTosUri: "https://rp.example/tos" });
  await oauthClient(rb, plain);
  const amy = user("amy");
  const bea = user("bea");
  await person(rb, amy);
  await person(rb, bea);
  async function signedIn(who, client) {
    log.debug("Entering signedIn(). " + who);
    const s = await authnSignin.submit(rb, await pending(rb, client,
      { scope: "openid profile" }),
      { action: "login", username: who, password: PW }, {});
    const r = await fetch(s.location, { redirect: "manual",
                                        headers: { cookie: s.cookie } });
    await r.text();
    log.debug("Leaving signedIn().");
    return { cookie: s.cookie, location: new URL(
      String(r.headers.get("location") || ""), rb).toString(),
             status: r.status, screenView: s.view };
  }
  const a = await signedIn(amy, app);
  assert.ok(authnSignin.isConsent(a.location),
            "the realm should ask for consent; the authorization request " +
            "answered " + a.status + " " + a.location);
  const opened = await authnSignin.consentPage(a.location,
                                               { cookie: a.cookie });
  seenIds.push(opened.id);
  const shell = await fetch(a.location, { redirect: "manual",
    headers: { cookie: a.cookie } });
  const shellText = await shell.text();
  const csp = String(shell.headers.get("content-security-policy") || "");
  check("G1. /oauth2/consent answers the shell: its script, the card, the " +
        "notice, no form, with frame-ancestors kept", function () {
    assert.strictEqual(shell.status, 200);
    assert.ok(/<script src="(\/realm\/[^/"]+)?\/oauth2\/consent\.js"/.test(
      shellText), shellText.slice(0, 500));
    assert.ok(shellText.indexOf("<noscript>") > 0);
    assert.ok(!/<form/.test(shellText));
    assert.ok(/frame-ancestors 'none'/.test(csp), csp);
    assert.ok(/script-src 'self'/.test(csp) && !/unsafe-inline/.test(csp));
  });
  check("G2. its img-src names the registered logo's origin and nothing " +
        "wider", function () {
    const img = (csp.match(/img-src ([^;]*)/) || [])[1] || "";
    assert.ok(/https:\/\/logo\.example/.test(img), csp);
    assert.ok(!/\*|https:(\s|$)/.test(img), img);
  });
  const script = await send(base + "/oauth2/consent.js");
  check("G3. the script is served", function () {
    assert.strictEqual(script.status, 200);
    assert.ok(/javascript/.test(script.headers.get("content-type")));
  });
  const cBase = opened.base;
  const malformed = await send(cBase + "/oauth2/consent?consent=not*an*id",
    { headers: { cookie: a.cookie } });
  const unknown = await send(cBase + "/oauth2/consent?consent=" +
    "AAAAAAAAAAAAAAAAAAAAAAAA", { headers: { cookie: a.cookie } });
  const noSession = await send(a.location);
  const b = await signedIn(bea, plain);
  const anothers = await send(a.location, { headers: { cookie: b.cookie } });
  check("G4. a malformed id, an unknown one, no session and another " +
        "person's session are refused 400 invalid_request", function () {
    [malformed, unknown, noSession, anothers].forEach(function (r, i) {
      assert.strictEqual(r.status, 400, i + " " + r.raw.slice(0, 200));
      assert.ok(/invalid_request/.test(r.raw), i + " " + r.raw.slice(0, 200));
    });
  });
  const v = opened.view || {};
  check("G5. the view is facts and no markup, with a CSRF token",
        function () {
    assert.strictEqual(opened.status, 200, opened.text);
    assert.ok(opened.csrf);
    assert.ok(!/<[a-z]/.test(JSON.stringify(v)), JSON.stringify(v));
    assert.ok(JSON.stringify(v).indexOf(app) >= 0, JSON.stringify(v));
  });
  check("G6. who is asking: the view's clientDisplay carries the logo and " +
        "the two links", function () {
    const shown = JSON.stringify(v.clientDisplay || {});
    assert.ok(/logo\.example/.test(shown), shown);
    assert.ok(/rp\.example\/policy/.test(shown), shown);
    assert.ok(/rp\.example\/tos/.test(shown), shown);
  });
  const viewToOther = await send(cBase + "/authn-api/consent/" +
    encodeURIComponent(opened.id), { headers: { cookie: b.cookie,
                                                accept: "application/json" } });
  check("G7. the view is refused to another person's session", function () {
    assert.ok(viewToOther.status >= 400 && viewToOther.status < 500,
              viewToOther.status + " " + viewToOther.raw.slice(0, 200));
  });
  const plainAuth = await fetch(new URL(b.location).toString(),
    { redirect: "manual", headers: { cookie: b.cookie } });
  const plainText = await plainAuth.text();
  const plainCsp = String(plainAuth.headers.get("content-security-policy") ||
                          "");
  const plainOpen = authnSignin.isConsent(b.location)
    ? await authnSignin.consentPage(b.location, { cookie: b.cookie }) : null;
  check("G8. a client with none of the three shows nothing and adds no " +
        "image origin", function () {
    assert.ok(plainOpen, "no consent screen: " + b.location + " " +
              plainText.slice(0, 100));
    assert.ok(!plainOpen.view.clientDisplay ||
              !/https?:/.test(JSON.stringify(plainOpen.view.clientDisplay)),
              JSON.stringify(plainOpen.view.clientDisplay));
    const img = (plainCsp.match(/img-src ([^;]*)/) || [])[1] || "";
    assert.ok(!/https:\/\//.test(img), plainCsp);
  });
  check("G9. and its sign-in screen shows nothing of the other client",
        function () {
    assert.ok(!b.screenView || !b.screenView.clientDisplay ||
              !/logo\.example/.test(JSON.stringify(
                b.screenView.clientDisplay)));
  });
  const other = await authnSignin.screen(rb, await pending(rb, plain));
  const r = {};
  r.form = await authnSignin.answerConsent(opened, "allow",
    { contentType: "application/x-www-form-urlencoded" });
  r.noOrigin = await authnSignin.answerConsent(opened, "allow",
                                               { origin: null });
  r.evil = await authnSignin.answerConsent(opened, "allow",
                                           { origin: "https://evil.example" });
  r.noToken = await authnSignin.answerConsent(opened, "allow", { csrf: "" });
  r.otherToken = await authnSignin.answerConsent(opened, "allow",
                                                 { csrf: other.csrf });
  r.malformed = await authnSignin.act(cBase, "/authn-api/consent/not*an*id",
    { action: "allow" }, { cookie: opened.cookie, csrf: opened.csrf });
  r.field = await authnSignin.act(cBase, "/authn-api/consent/" +
    encodeURIComponent(opened.id), { action: "allow", admin: "1" },
    { cookie: opened.cookie, csrf: opened.csrf });
  r.neither = await authnSignin.act(cBase, "/authn-api/consent/" +
    encodeURIComponent(opened.id), { action: "maybe" },
    { cookie: opened.cookie, csrf: opened.csrf });
  r.anothers = await authnSignin.act(cBase, "/authn-api/consent/" +
    encodeURIComponent(opened.id), { action: "allow" },
    { cookie: b.cookie, csrf: other.csrf });
  check("G10. an answer is bound: 415, 403 ×4, and a malformed id, an " +
        "unknown field, an action neither allow nor deny and another " +
        "person's answer refused 400, all code-free", function () {
    assert.strictEqual(r.form.status, 415, r.form.text);
    ["noOrigin", "evil", "noToken", "otherToken"].forEach(function (k) {
      assert.strictEqual(r[k].status, 403, k + " " + r[k].text);
    });
    ["malformed", "field", "neither"].forEach(function (k) {
      assert.strictEqual(r[k].status, 400, k + " " + r[k].text);
    });
    assert.ok(r.anothers.status >= 400 && r.anothers.status < 500,
              r.anothers.text);
    Object.keys(r).forEach(function (k) {
      assert.ok(codeFree(r[k].text), k + " " + r[k].text);
    });
  });
  const allowed = await authnSignin.answerConsent(opened, "allow");
  const replay = await authnSignin.answerConsent(opened, "allow");
  check("G11. Allow names the authorization request to go back to, and a " +
        "replay is refused", function () {
    assert.strictEqual(allowed.next, "redirect", allowed.text);
    assert.ok(/\/oauth2\/authorize\?/.test(allowed.location),
              allowed.location);
    assert.ok(replay.status >= 400, replay.text);
  });
  const denyOpen = await authnSignin.consentPage(b.location,
                                                 { cookie: b.cookie });
  const denied = await authnSignin.answerConsent(denyOpen, "deny");
  check("G12. Deny names the request with consent_error=access_denied",
        function () {
    assert.strictEqual(denied.next, "redirect", denied.text);
    assert.ok(/consent_error=access_denied/.test(denied.location),
              denied.location);
  });
  const oldPost = await send(cBase + "/oauth2/consent", { method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded",
               cookie: b.cookie },
    body: "consent=" + encodeURIComponent(denyOpen.id) + "&action=allow" });
  check("G13. POST /oauth2/consent is gone", function () {
    assert.strictEqual(oldPost.status, 404, String(oldPost.status));
  });
  log.debug("Leaving sectionConsent().");
}

async function sectionAudit(rb, app) {
  log.debug("Entering sectionAudit().");
  log.info("=== H. no bearer id in an audit row; the old screen POST ===");
  const at = await pending(rb, app);
  const old = await send(rb + "/authn/login", { method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: "authn_id=" + encodeURIComponent(authnSignin.pendingIdOf(at)) +
          "&username=" + user("old") + "&password=x&action=login" });
  check("H1. POST /authn/login is gone", function () {
    assert.strictEqual(old.status, 404, String(old.status));
  });
  const rows = await send(rb + "/admin-api/audit?per=500");
  const text = rows.raw;
  check("H2. the audit log names the operations and never a pending, step " +
        "or consent id (" + seenIds.length + " ids looked for)", function () {
    assert.strictEqual(rows.status, 200);
    assert.ok(/\/authn-api\//.test(text), "no /authn-api row at all");
    seenIds.forEach(function (id) {
      assert.ok(text.indexOf(id) < 0, "the id " + id.slice(0, 6) +
                "… is in an audit row");
    });
  });
  log.debug("Leaving sectionAudit().");
}

async function sectionArming(app) {
  log.debug("Entering sectionArming().");
  log.info("=== I. arming the usernameless ceremony, per address ===");
  const rb = await makeRealm(LIMITS, null);
  await oauthClient(rb, app);
  await realmSet(LIMITS, "security.rateLimitPerAddress", 2);
  const at = await pending(rb, app);
  const opened = await authnSignin.screen(rb, at);
  // The address bucket is the process's: a run just before this one may
  // have left it full, so wait out what it says first.
  const first = await authnSignin.passkeyOptions(rb, opened);
  if (first.status === 429) {
    const wait = Number(first.headers.get("retry-after") || 60);
    log.info("the address bucket is still full; waiting " + wait + " s");
    await sleep((wait + 1) * 1000);
  }
  const arms = [];
  for (let i = 0; i < 4; i += 1) {
    arms.push(await authnSignin.passkeyOptions(rb, opened));
  }
  await realmSet(LIMITS, "security.rateLimitPerAddress", 10000);
  const last = arms[arms.length - 1];
  check("I1. arming the passkey ceremony is rate limited per address: 429 " +
        "with a Retry-After, code-free", function () {
    assert.strictEqual(arms[0].status, 200, arms[0].text);
    assert.strictEqual(last.status, 429, arms.map(function (one) {
      return one.status;
    }).join(","));
    assert.strictEqual(last.next, "refused");
    assert.ok(codeFree(last.text));
    assert.ok(/^\d+$/.test(String(last.headers.get("retry-after") || "")));
  });
  log.debug("Leaving sectionArming().");
}

async function test() {
  log.debug("Entering test().");
  const rb = await makeRealm(REALM, null);
  const app = "aas-" + STAMP;
  await oauthClient(rb, app);
  await realmSet(REALM, "security.rateLimitPerAddress", 10000);
  await sectionScreen(rb, app);
  await sectionSteps(rb, app);
  await sectionPasswordChangeStartOver(rb, app);
  await sectionConsent(rb);
  await sectionAudit(rb, app);
  await sectionArming(app);
  log.debug("Leaving test().");
}

main();
