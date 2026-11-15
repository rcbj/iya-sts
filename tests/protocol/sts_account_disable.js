// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_account_disable.js
//
// ---------------------------------------------------------------------------
// A DISABLED ACCOUNT, AND A DELETED ONE, AT EVERY DOOR A CLIENT REACHES.
//
// D12 (#444): carries over `tests/account_disable.js` (the #36 follow-up,
// #413) and the half of `tests/account_delete.js` (#241) that
// `sts_account_delete_sessions.js` does not hold. The point of the first is
// the LIST OF DOORS: a refusal at the sign-in screen alone would look
// exactly like the feature working. In a development realm and a product
// realm of its own (product with a real password, so every refusal is the
// disable and not a wrong password):
//
//   A. the controls before the disable: a code-flow sign-in, single sign-on
//      from that session, the password grant (development) or its refusal
//      (product, STS-OAUTH-0197), a refresh token in hand;
//   B. `POST /admin-api/users/disable`: changed, disabled, the sessions it
//      ended said in the reply, one `account.disable` audit row naming the
//      caller; the relying party on the session sent its back-channel
//      Logout Token (development, through the test peer);
//   C. the doors: the old cookie no longer signs in, the sign-in screen
//      refuses the password with the sentence a wrong one gets and
//      STS-AUTHN-0200 on the audit log, a passwordless security-key sign-in
//      refused before any ceremony;
//   E. the token endpoint: the password grant `invalid_grant` (development)
//      or still `unsupported_grant_type` (product), and the refresh token
//      issued before the disable `invalid_grant`;
//   G. the management API refuses a disabled person's token (development:
//      its token comes from the password grant);
//   H. enable clears it and they sign in again; enabling twice changes
//      nothing and says so; the anonymous principal cannot be disabled;
//   I. SCIM `active: false` is the same act (the sessions end), `active:
//      true` the enable, and a PATCH with the string "False" never answers
//      2xx with the account left enabled (development);
//   J. `GET /admin-api/users?user=` says the account is disabled (the
//      person's view; `/admin-api/mfa`'s rows do not say it);
//   K. product refuses a passwordless sign-in for somebody who holds no
//      passkey before it asks anything else (STS-AUTHN-0206);
//   L. account_delete A6: a SCIM DELETE sends the relying party on the
//      deleted person's session its Logout Token (development, the peer).
//
// NOT carried, and why: `authn.startSession()` called with each other
// door's shape, `credentials.verify()` and `issuance_gate.check()` (C3, C2,
// F) are the process's own choke points (class (d)); the doors that reach
// them — federation, SPNEGO, the wallet, WS-Trust, the SAML profiles, GNAP,
// an LDAP bind — are each their family's (owed with those phases); the
// Kerberos AS-REQ's KDC_ERR_CLIENT_REVOKED (D) is owed with the Kerberos
// phase; SCIM's "a resource that does not say `active`" (I5) is a mapping
// function (d); account_delete B and C (a delete reaching this node as an
// entry going away, a person made again before the deferred consequence
// runs) need a second node or a stalled consequence (d).
//
// Needs the test peer for B4 and L (`testPeer: true`); those two checks are
// skipped with the reason without it.
//
// OWNED HERE (local: true): this repository's directory, sessions and
// management API.
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
var log = bunyan.createLogger({ name: "sts_account_disable",
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

const testPeer = require("./test_peer.js");

const DEV = "adis-" + STAMP;
const PROD = "adip-" + STAMP;
const APP = "adis-app-" + STAMP;
const SECRET = "adis-" + STAMP + "-" + crypto.randomBytes(8).toString("hex");
const PW = "Adis-" + STAMP + "-Correct.Horse.Battery.42";

function user(tag) {
  log.debug("Entering user(). " + tag);
  log.debug("Leaving user().");
  return ("ad" + tag + STAMP).slice(0, 30);
}

function basic() {
  log.debug("Entering basic().");
  log.debug("Leaving basic().");
  return "Basic " + Buffer.from(APP + ":" + SECRET).toString("base64");
}

async function person(rb, name) {
  log.debug("Entering person(). " + name);
  await ok(rb + "/admin-api/users/create", { username: name, invent: false,
    attributes: { cn: "Adis " + name, sn: name, givenName: ["Adis"],
                  mail: [name + "@example.test"] },
    credential: "password", password: PW }, "created " + name);
  log.debug("Leaving person().");
}

async function setUp(id, mode, bcl) {
  log.debug("Entering setUp(). " + id);
  const rb = await makeRealm(id, mode);
  if (mode === "product") {
    await realmSet(id, "authn.allowOptionalSecondFactor", true);
  }
  await realmSet(id, "risk.assessSignIns", false);
  await realmSet(id, "security.rateLimitPerAddress", 10000);
  if (bcl) {
    await realmSet(id, "federation.outboundSkipTlsVerification", true);
  }
  const fields = { oauthClientId: [APP], oauthClientSecret: SECRET,
    oauthRedirectUri: ["https://rp.example/" + APP + "/cb"],
    oauthTokenEndpointAuthMethod: "client_secret_basic",
    oauthGrantType: ["authorization_code", "refresh_token", "password",
                     "client_credentials"],
    oauthAllowedScope: ["openid", "profile", "scim:read", "scim:write"],
    oauthDelegatedPermission: ["urn:sts:admin-api:admin:read"] };
  if (bcl) {
    fields.oauthBackchannelLogoutUri = bcl.endpoint;
    fields.oauthBackchannelLogoutSessionRequired = "TRUE";
  }
  await ok(rb + "/admin-api/applications/create", { identifier: APP,
    name: APP, protocols: ["oauth2", "oidc", "scim"], fields: fields },
    "registered " + APP);
  for (const one of ["openid", "profile"]) {
    await ok(rb + "/admin-api/consent/grant-global-consent",
             { client: APP, scope: one }, "consented " + one);
  }
  log.debug("Leaving setUp().");
  return rb;
}

function form(rb, body) {
  log.debug("Entering form().");
  log.debug("Leaving form().");
  return send(rb + "/oauth2/token", { method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded",
               authorization: basic() },
    body: new URLSearchParams(body).toString() });
}

// A code-flow sign-in: `{ answer, cookie, tokens, claims }`; `answer` the
// screen's, `tokens` absent when it did not sign in.
async function signIn(rb, who, password, cookie) {
  log.debug("Entering signIn(). " + who);
  const start = await authorize(rb, APP, cookie);
  let at = start;
  let answer = null;
  let jar = cookie || "";
  if (/\/authn\/login(\?[^#]*)?[?&#]authn=/.test(start.location)) {
    answer = await authnSignin.signIn(rb, start.location,
      { action: "login", username: who, password: password },
      { cookie: jar });
    if (answer.next !== "redirect") {
      log.debug("Leaving signIn(). Refused: " + answer.next);
      return { answer: answer, cookie: answer.cookie, start: start };
    }
    jar = answer.cookie;
    const r = await fetch(answer.location, { redirect: "manual",
                                             headers: { cookie: jar } });
    await r.text();
    at = { location: new URL(String(r.headers.get("location") || ""),
                             rb).toString(), verifier: start.verifier };
  }
  const code = new URL(at.location).searchParams.get("code");
  if (!code) {
    log.debug("Leaving signIn(). No code: " + at.location);
    return { answer: answer, cookie: jar, start: start, at: at };
  }
  const t = await form(rb, { grant_type: "authorization_code", code: code,
    redirect_uri: "https://rp.example/" + APP + "/cb",
    code_verifier: start.verifier });
  const claims = t.body && t.body.id_token
    ? JSON.parse(Buffer.from(t.body.id_token.split(".")[1], "base64url")
      .toString()) : {};
  log.debug("Leaving signIn(). " + t.status);
  return { answer: answer, cookie: jar, tokens: t, claims: claims,
           start: start, sso: !answer };
}

async function auditRows(rb, query) {
  log.debug("Entering auditRows().");
  const r = await send(rb + "/admin-api/audit?per=500&" + query);
  log.debug("Leaving auditRows().");
  return (r.body && (r.body.rows || r.body.entries || r.body.events)) || [];
}

async function doors(rb, mode, view, tenantId) {
  log.debug("Entering doors(). " + mode);
  const P = mode === "product";
  const tag = "[" + mode + "] ";
  const alice = user("al" + (P ? "p" : "d"));
  const other = user("ot" + (P ? "p" : "d"));
  await person(rb, alice);
  await person(rb, other);
  log.info("=== " + tag + "A. the controls ===");
  const first = await signIn(rb, alice, PW);
  check(tag + "A1. the person signs in through the code flow, with a sid " +
        "and a refresh token", function () {
    assert.strictEqual(first.tokens && first.tokens.status, 200,
                       JSON.stringify(first.answer && first.answer.json));
    assert.ok(first.claims.sid, JSON.stringify(first.claims));
    assert.ok(first.tokens.body.refresh_token);
  });
  const sso = await signIn(rb, alice, PW, first.cookie);
  check(tag + "A2. and a second authorization request is answered from the " +
        "session", function () {
    assert.strictEqual(sso.sso, true, JSON.stringify(sso.start));
    assert.strictEqual(sso.tokens.status, 200);
  });
  const grantBefore = await form(rb, { grant_type: "password",
    username: alice, password: PW, scope: "openid" });
  check(tag + (P ? "A3. product has no password grant (RFC 9700)"
                 : "A3. the password grant issues"), function () {
    if (P) {
      assert.strictEqual(grantBefore.status, 400, grantBefore.raw);
      assert.strictEqual(grantBefore.body.error, "unsupported_grant_type");
    } else {
      assert.strictEqual(grantBefore.status, 200, grantBefore.raw);
    }
  });
  if (P) {
    const n = await codesSettle(rb, "STS-OAUTH-0197", 1);
    const codesSeen = (await auditRows(rb, "")).filter(function (row) {
      return row.errorCode;
    }).map(function (row) {
      return row.action + ":" + row.errorCode + ":" + row.target;
    });
    // The in-process child recorded STS-OAUTH-0131 (RFC 9700's refusal);
    // over the wire a product realm's profile does not advertise the grant
    // at all, and the refusal is the one that says so.
    check(tag + "A4. and that refusal is recorded STS-OAUTH-0197 (a grant " +
          "the profile does not advertise)",
          function () {
      assert.ok(n >= 1, "rows: " + n + " " + JSON.stringify(codesSeen));
    });
  }

  log.info("=== " + tag + "B. the disable ===");
  const since = view ? await testPeer.mark(tenantId) : null;
  const acted = await postJson(rb + "/admin-api/users/disable",
                               { user: alice, reason: "d12" });
  check(tag + "B1. POST /admin-api/users/disable writes the lock and says " +
        "what it ended", function () {
    assert.strictEqual(acted.status, 200, acted.raw.slice(0, 300));
    assert.strictEqual(acted.body.changed, true, acted.raw.slice(0, 300));
    assert.strictEqual(acted.body.disabled, true);
    assert.ok(acted.body.ended && acted.body.ended.terminated > 0,
              acted.raw.slice(0, 300));
    assert.ok(/disabled/.test(String(acted.body.message)));
  });
  const rows = await auditRows(rb, "q=" + encodeURIComponent(alice));
  check(tag + "B2. one disable audit row names the person and who did it",
        function () {
    const mine = rows.filter(function (row) {
      return /disable/.test(String(row.action)) && row.target === alice;
    });
    assert.strictEqual(mine.length, 1, JSON.stringify(rows).slice(0, 500));
    assert.ok(mine[0].actor, JSON.stringify(mine[0]));
  });
  if (view) {
    const got = await testPeer.waitFor(tenantId, "bcl", since, null, 15000);
    check(tag + "B3. the relying party on the session is sent its " +
          "back-channel Logout Token, naming the sid", function () {
      assert.ok(got, "nothing reached the peer");
      assert.strictEqual(got.ok, true, JSON.stringify(got).slice(0, 400));
      assert.strictEqual(got.claims.sid, first.claims.sid);
    });
  } else if (!P) {
    log.info(testPeer.skipReason("B3, the Logout Token at a disable"));
  }

  log.info("=== " + tag + "C. the doors ===");
  const oldCookie = await authorize(rb, APP, first.cookie);
  check(tag + "C1. the old session no longer signs in: the browser is sent " +
        "to the sign-in screen", function () {
    assert.ok(/\/authn\/login(\?[^#]*)?[?&#]authn=/.test(oldCookie.location),
              oldCookie.status + " " + oldCookie.location);
  });
  const before0200 = await codeCount(rb, "STS-AUTHN-0200");
  const screen = await signIn(rb, alice, PW);
  const wrongPw = await signIn(rb, other, "invalid");
  check(tag + "C2. the sign-in screen refuses their password with the " +
        "sentence a wrong one gets", function () {
    assert.ok(!screen.tokens, "it signed in");
    assert.strictEqual(screen.answer.next, "refused",
                       screen.answer.text.slice(0, 300));
    assert.ok(/Authentication failed/.test(screen.answer.errors.join(" ")),
              screen.answer.text);
    if (!P) {
      assert.strictEqual(wrongPw.answer.next, "refused");
      assert.ok(/Authentication failed/.test(
        wrongPw.answer.errors.join(" ")));
    }
    assert.ok(codeFree(screen.answer.text));
  });
  const after0200 = await codesSettle(rb, "STS-AUTHN-0200", before0200 + 1);
  check(tag + "C3. and the refusal is recorded STS-AUTHN-0200 (a password " +
        "for a disabled account, refused before it is compared)", function () {
    assert.ok(after0200 > before0200, before0200 + " -> " + after0200);
  });
  const pending = await authorize(rb, APP);
  const passwordless = await authnSignin.submit(rb, pending.location,
    { action: "login", username: alice, password: "", webauthn_only: "1" },
    {});
  check(tag + "C4. a passwordless security-key sign-in is refused BEFORE " +
        "the ceremony", function () {
    assert.strictEqual(passwordless.next, "refused", passwordless.text);
    // Development answers the wrong-password sentence; product asks first
    // whether the account holds a passkey at all (it does not: no door
    // here enrols one before a sign-in), and says so (see K).
    assert.ok(P ? /no passkey registered/.test(passwordless.errors.join(" "))
                : /Authentication failed/.test(passwordless.errors.join(" ")),
              passwordless.text);
    assert.ok(!(passwordless.json && passwordless.json.step === "webauthn"));
  });

  log.info("=== " + tag + "E. the token endpoint ===");
  const grantAfter = await form(rb, { grant_type: "password",
    username: alice, password: PW, scope: "openid" });
  check(tag + (P ? "E1. the password grant is still refused, as for " +
                   "everybody" : "E1. the password grant is invalid_grant"),
        function () {
    assert.strictEqual(grantAfter.status, 400, grantAfter.raw);
    assert.strictEqual(grantAfter.body.error,
                       P ? "unsupported_grant_type" : "invalid_grant");
  });
  const refreshed = await form(rb, { grant_type: "refresh_token",
    refresh_token: first.tokens.body.refresh_token });
  check(tag + "E2. the refresh token issued before the disable is " +
        "invalid_grant", function () {
    assert.strictEqual(refreshed.status, 400, refreshed.raw);
    assert.strictEqual(refreshed.body.error, "invalid_grant");
  });

  if (!P) {
    log.info("=== " + tag + "G. the management API ===");
    const apiUser = user("api");
    await person(rb, apiUser);
    const apiToken = await form(rb, { grant_type: "password",
      username: apiUser, password: PW, scope: "admin:read",
      resource: rb + "/admin-api" });
    const call = function () {
      return send(rb + "/admin-api/logout", { headers: {
        authorization: "Bearer " + String(apiToken.body &&
                                          apiToken.body.access_token) } });
    };
    const apiBefore = await call();
    await ok(rb + "/admin-api/users/disable", { user: apiUser, reason: "d12" },
             "disabled " + apiUser);
    const apiAfter = await call();
    await ok(rb + "/admin-api/users/enable", { user: apiUser },
             "enabled " + apiUser);
    check(tag + "G1. the management API refuses a token issued to a person " +
          "whose account is disabled", function () {
      assert.strictEqual(apiToken.status, 200, apiToken.raw.slice(0, 300));
      assert.strictEqual(apiBefore.status, 200, apiBefore.raw.slice(0, 200));
      assert.strictEqual(apiAfter.status, 401, apiAfter.raw.slice(0, 200));
      assert.strictEqual(apiAfter.body.error, "invalid_token");
    });
  }

  log.info("=== " + tag + "J. what the API shows ===");
  const shown = await send(rb + "/admin-api/users?user=" +
                           encodeURIComponent(alice));
  check(tag + "J1. GET /admin-api/users?user= says the account is disabled",
        function () {
    assert.strictEqual(shown.status, 200, shown.raw.slice(0, 200));
    assert.strictEqual(shown.body.factors.disabled, true,
                       JSON.stringify(shown.body.factors).slice(0, 300));
  });

  log.info("=== " + tag + "H. enabling ===");
  const enabled = await postJson(rb + "/admin-api/users/enable",
                                 { user: alice });
  const back = await signIn(rb, alice, PW);
  const twice = await postJson(rb + "/admin-api/users/enable",
                               { user: alice });
  const nobody = await postJson(rb + "/admin-api/users/disable",
                                { user: "anonymous", reason: "d12" });
  check(tag + "H1. enable clears the lock, and they sign in again",
        function () {
    assert.strictEqual(enabled.status, 200, enabled.raw.slice(0, 200));
    assert.strictEqual(enabled.body.changed, true);
    assert.strictEqual(back.tokens && back.tokens.status, 200,
                       JSON.stringify(back.answer && back.answer.json));
  });
  check(tag + "H2. enabling an enabled account changes nothing and says so",
        function () {
    assert.strictEqual(twice.status, 200, twice.raw.slice(0, 200));
    assert.strictEqual(twice.body.changed, false);
    assert.ok(twice.body.message, twice.raw.slice(0, 200));
  });
  check(tag + "H3. and the anonymous principal cannot be disabled",
        function () {
    assert.ok(nobody.status >= 400 || (nobody.body && nobody.body.ok ===
                                       false), nobody.raw.slice(0, 200));
  });
  log.debug("Leaving doors().");
}

async function scimToken(rb) {
  log.debug("Entering scimToken().");
  const t = await form(rb, { grant_type: "client_credentials",
                             scope: "scim:read scim:write" });
  assert.strictEqual(t.status, 200, "a SCIM token: " + t.raw.slice(0, 300));
  log.debug("Leaving scimToken().");
  return { Authorization: "Bearer " + t.body.access_token };
}

async function scimIdOf(rb, auth, name) {
  log.debug("Entering scimIdOf(). " + name);
  const r = await send(rb + "/scim/v2/Users?filter=" +
    encodeURIComponent("userName eq \"" + name + "\""), { headers: auth });
  const id = r.body && r.body.Resources && r.body.Resources[0] &&
             r.body.Resources[0].id;
  assert.ok(id, "no SCIM id for " + name + ": " + r.raw.slice(0, 200));
  log.debug("Leaving scimIdOf().");
  return id;
}

function scimPatch(rb, auth, id, value) {
  log.debug("Entering scimPatch().");
  log.debug("Leaving scimPatch().");
  return send(rb + "/scim/v2/Users/" + id, { method: "PATCH",
    headers: Object.assign({ "content-type": "application/scim+json" }, auth),
    body: JSON.stringify({
      schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
      Operations: [{ op: "replace", path: "active", value: value }] }) });
}

async function scim(rb, view, tenantId) {
  log.debug("Entering scim().");
  log.info("=== [development] I. SCIM's active ===");
  const who = user("sc");
  await person(rb, who);
  const auth = await scimToken(rb);
  const id = await scimIdOf(rb, auth, who);
  const s = await signIn(rb, who, PW);
  const off = await scimPatch(rb, auth, id, false);
  await sleep(300);
  const ended = await authorize(rb, APP, s.cookie);
  const refused = await signIn(rb, who, PW);
  check("[development] I1. SCIM active: false disables the account: the " +
        "session ends and the screen refuses them", function () {
    assert.strictEqual(off.status, 200, off.raw.slice(0, 300));
    assert.strictEqual(off.body.active, false);
    assert.ok(/\/authn\/login(\?[^#]*)?[?&#]authn=/.test(ended.location),
              ended.location);
    assert.ok(!refused.tokens);
  });
  const on = await scimPatch(rb, auth, id, true);
  const again = await signIn(rb, who, PW);
  check("[development] I2. and active: true is the enable", function () {
    assert.strictEqual(on.status, 200, on.raw.slice(0, 300));
    assert.strictEqual(on.body.active, true);
    assert.strictEqual(again.tokens && again.tokens.status, 200);
  });
  const str = await scimPatch(rb, auth, id, "False");
  await sleep(300);
  const read = await send(rb + "/scim/v2/Users/" + id, { headers: auth });
  check("[development] I3. a PATCH with the string \"False\" either " +
        "disables the account or is refused — never 2xx with it enabled",
        function () {
    assert.ok(str.status >= 400 || (read.body && read.body.active === false),
              str.status + " " + read.raw.slice(0, 200));
  });
  await scimPatch(rb, auth, id, true);

  log.info("=== [development] L. a SCIM DELETE and the relying party ===");
  const gone = user("gn");
  await person(rb, gone);
  const g = await signIn(rb, gone, PW);
  const since = view ? await testPeer.mark(tenantId) : null;
  const deleted = await send(rb + "/scim/v2/Users/" +
                             await scimIdOf(rb, auth, gone),
                             { method: "DELETE", headers: auth });
  const after = await authorize(rb, APP, g.cookie);
  check("[development] L1. SCIM DELETE answers 204 and the old session no " +
        "longer signs in", function () {
    assert.strictEqual(deleted.status, 204, deleted.raw.slice(0, 200));
    assert.ok(/\/authn\/login(\?[^#]*)?[?&#]authn=/.test(after.location),
              after.status + " " + after.location);
  });
  if (view) {
    const got = await testPeer.waitFor(tenantId, "bcl", since,
      function (one) {
        return one.claims && one.claims.sid === g.claims.sid;
      }, 15000);
    check("[development] L2. the relying party on the deleted person's " +
          "session is sent its Logout Token", function () {
      assert.ok(got, "nothing reached the peer");
      assert.strictEqual(got.ok, true, JSON.stringify(got).slice(0, 400));
    });
  } else {
    log.info(testPeer.skipReason("L2, the Logout Token at a delete"));
  }
  log.debug("Leaving scim().");
}

async function passwordlessWithoutKey(rb) {
  log.debug("Entering passwordlessWithoutKey().");
  log.info("=== [product] K. passwordless for somebody holding no passkey ===");
  const who = user("nk");
  await person(rb, who);
  const before = await codeCount(rb, "STS-AUTHN-0206");
  const pending = await authorize(rb, APP);
  const r = await authnSignin.submit(rb, pending.location,
    { action: "login", username: who, password: "", webauthn_only: "1" }, {});
  const after = await codesSettle(rb, "STS-AUTHN-0206", before + 1);
  check("[product] K1. a passwordless sign-in for somebody holding no " +
        "passkey is refused before the ceremony, STS-AUTHN-0206", function () {
    assert.strictEqual(r.next, "refused", r.text);
    assert.ok(after > before, before + " -> " + after);
    assert.ok(codeFree(r.text));
  });
  log.debug("Leaving passwordlessWithoutKey().");
}

async function test() {
  log.debug("Entering test().");
  let view = null;
  let tenantId = null;
  if (testPeer.available()) {
    tenantId = testPeer.tenantId("adis");
    view = await testPeer.tenant(tenantId, base + "/realm/" + DEV, base,
                                 { bcl: { clientId: APP } });
  }
  const dev = await setUp(DEV, null, view && view.bcl);
  await doors(dev, "development", view, tenantId);
  await scim(dev, view, tenantId);
  const prod = await setUp(PROD, "product", null);
  await doors(prod, "product", null, null);
  await passwordlessWithoutKey(prod);
  log.debug("Leaving test().");
}

main();
