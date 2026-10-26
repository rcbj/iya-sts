// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_hosted_surface_renewal.js
//
// ===========================================================================
// THE ADMIN CONSOLE AND THE USER PORTAL RENEW THEIR TOKENS, AND THE TOKENS DIE
// WITH THE SIGN-ON SESSION, OVER HTTP (2026-09-12; both static since #568).
//
// An operator watched their console session expire an hour after signing in
// and was sent back through the sign-in screen — off the page they were on.
// The fix then was `common/oidc_rp.ts` renewing a relying-party session's
// tokens in place. **Neither surface has such a session any more**: the
// console became a static page holding a DPoP-bound token on #446, and the
// portal on #568, both public clients that renew with the refresh grant. So
// this job asserts what a person would notice, in those terms:
//
//   1. THE PORTAL RENEWS. The refresh grant answers a new DPoP-bound access
//      token, rotates the refresh token, and the new token reads the
//      person's own account — with no second sign-on session.
//   2. A SIGN-OUT ENDS IT. Revoking the sign-on session makes every token
//      issued on it a refusal at `/account-api` (STS-ACCOUNT-0008).
//   3. A REVOCATION ENDS IT, AND THE NEXT SIGN-IN NEEDS NO SCREEN. Revoking the
//      person's tokens refuses the refresh grant and the access token; the
//      sign-on session is still live, so the portal's next authorization
//      request is answered with a code and no sign-in.
//   4. THE CONSOLE RENEWS TOO, the same grant with the same key.
//   5. THE SIGN-ON SESSION RUNNING OUT ENDS THE PORTAL'S TOKENS. The reverse
//      of what the relying-party portal did (it outlived its sign-on session
//      by renewing): a token now dies with the session it was issued on, and
//      a renewal does not revive it.
//
// `local: true`, for tests/CLAUDE.md's ownership reason: it drives this
// service's own `/admin` and `/portal` and reads `/admin-api`. It runs in a
// throwaway realm it creates and leaves standing, for "No job removes a realm".
// `tests/oidc_rp_renewal.js` is the in-process half of the relying-party
// renewal the embedded debugger still uses.
// ===========================================================================

const assert = require("assert");
const { runStamp, usernameFor } = require("./random_username.js");
const signin = require("./console_signin.js");
const portalSignin = require("./portal_signin.js");

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
var log = bunyan.createLogger({ name: "sts_hosted_surface_renewal",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, ""))
  .replace(/\/+$/, "");
var api = base + "/admin-api";
var REALM = ("renew-" + runStamp()).toLowerCase()
                                   .replace(/[^a-z0-9-]/g, "")
                                   .slice(0, 31);
var R = "/realm/" + REALM;
var realmApi = base + R + "/admin-api";
var PASSWORD = "renewal-Passw0rd!-" + String(Date.now()).slice(-6);
// The realm's token lifetime, and the lead time that renews on every request.
var TOKEN_TTL_S = 300;
// `authn.sessionLifetimeS`'s floor, which section 5 waits out.
var SIGN_ON_LIFETIME_S = 60;

var checks = 0;
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
  return new Promise(function (resolve) { setTimeout(resolve, ms); });
}

async function call(method, url, body) {
  log.debug("Entering call().");
  const r = await fetch(url, body === undefined ? { method: method } : {
    method: method, headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  const raw = await r.text();
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
    // An HTML error page from a door that answers JSON; `raw` carries it.
    parsed = raw;
  }
  log.debug("Leaving call().");
  return { status: r.status, body: parsed, raw: raw };
}

async function ok(url, body, what) {
  log.debug("Entering ok().");
  const r = await call("POST", url, body);
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    what + ": " + url + " answered " + r.status + " " +
    String(r.raw).slice(0, 400));
  log.debug("Leaving ok().");
  return r.body;
}

async function sessionsIn(apiBase) {
  log.debug("Entering sessionsIn().");
  const r = await call("GET", apiBase + "/sessions?per=200");
  assert.ok(r.status === 200 && Array.isArray(r.body.sessions),
    "GET " + apiBase + "/sessions answered " + r.status + " " +
    String(r.raw).slice(0, 200));
  log.debug("Leaving sessionsIn().");
  return r.body.sessions;
}

// A session cookie is `<sid>.<handle>` since 2026-09-14 (`authn/CLAUDE.md`):
// the handle rotates on a re-authentication and the sid never does. A session
// row, its `derivedFrom` and an audit row's target name the SID, so a match
// takes the part before the first dot. The "same session" checks keep
// comparing the WHOLE cookie, which is the stronger claim: a renewal must not
// rotate the handle either.
function sidOf(cookie) {
  log.debug("Entering sidOf().");
  const text = String(cookie || "");
  const dot = text.indexOf(".");
  log.debug("Leaving sidOf().");
  return dot > 0 ? text.slice(0, dot) : text;
}

async function auditRows(apiBase, action, target) {
  log.debug("Entering auditRows().");
  const r = await call("GET",
                       apiBase + "/audit?action=" + encodeURIComponent(action) +
                              "&per=200");
  assert.ok(r.status === 200 && Array.isArray(r.body.events),
    "GET " + apiBase + "/audit answered " + r.status + " " +
    String(r.raw).slice(0, 200));
  log.debug("Leaving auditRows().");
  return r.body.events.filter(function (row) {
    return !target || row.target === target;
  });
}

// ---------------------------------------------------------------------------
// SETUP: a realm, a person, short tokens on both clients, and a lead time that
// renews on every request.
// ---------------------------------------------------------------------------
async function setUp() {
  log.debug("Entering setUp().");
  log.info("=== a throwaway realm " + REALM + " with short tokens ===");
  await ok(api + "/realms/create", { id: REALM,
                                     domain: REALM + ".example.net",
                                     name: REALM },
           "created the realm");
  for (const client of ["sts-user-portal", "sts-admin-console"]) {
    for (const attribute of ["oauthAccessTokenTtlS", "oauthIdTokenTtlS"]) {
      await ok(realmApi + "/applications/set",
               { application: client, attribute: attribute,
                 value: String(TOKEN_TTL_S) },
               "set " + attribute + " on " + client);
    }
  }
  await ok(realmApi + "/config/set", { key: "oidcRp.renewBeforeExpiryS",
                                       value: String(TOKEN_TTL_S) },
           "set the lead time");
  await ok(realmApi + "/config/set", { key: "authn.sessionLifetimeS",
                                       value: String(SIGN_ON_LIFETIME_S) },
           "set the sign-on session lifetime");
  log.debug("Leaving setUp().");
}

async function ensurePerson(who) {
  log.debug("Entering ensurePerson(). who=" + who);
  const r = await call("POST", realmApi + "/users/create", {
    username: who, invent: false, credential: "password", password: PASSWORD,
    attributes: { cn: "Renewal " + who, sn: who, givenName: "Renewal",
                  displayName: "Renewal " + who,
                  mail: who + "@renewal.test" } });
  assert.ok(r.status === 200 && r.body.ok,
            "created " + who + ": " + r.raw.slice(0, 300));
  log.debug("Leaving ensurePerson().");
}

// ---------------------------------------------------------------------------
// THE PORTAL'S CLIENT, signed in as the static portal signs in
// (`portal_signin.js`), and the sign-on session id its walk left in the jar.
// ---------------------------------------------------------------------------
async function portalAs(who) {
  log.debug("Entering portalAs(). who=" + who);
  await ensurePerson(who);
  const client = await portalSignin.signInToThePortal(base + R, who, log,
    { password: PASSWORD });
  const cookie = (String(client.cookie).match(/sts_session=([^;]+)/) ||
                  [])[1] || "";
  log.debug("Leaving portalAs().");
  return { client: client, who: who, signOnCookie: cookie };
}

// What `/account-api` says to a token: the status and the challenge.
async function asked(client) {
  log.debug("Entering asked().");
  const r = await client.api("GET", "/account-api/me");
  log.debug("Leaving asked().");
  return { status: r.status, json: r.json,
           challenge: String(r.headers.get("www-authenticate") || "") };
}

// ---------------------------------------------------------------------------
// 1. THE PORTAL RENEWS.
// ---------------------------------------------------------------------------
async function thePortalRenewsInPlace() {
  log.debug("Entering thePortalRenewsInPlace().");
  log.info("=== 1. the portal renews its token with the refresh grant ===");
  const held = await portalAs(usernameFor("renew-portal"));
  const client = held.client;
  check("the sign-in left the portal holding a refresh token and the " +
        "browser a sign-on session", function () {
    assert.ok(client.refreshToken, "no refresh token was issued");
    assert.ok(held.signOnCookie, "no sts_session cookie: " + client.cookie);
  });
  const firstToken = client.token;
  const firstRefresh = client.refreshToken;
  await sleep(1100);
  const renewed = await client.refresh();
  check("the refresh grant answers a new DPoP-bound access token and " +
        "rotates the refresh token", function () {
    assert.strictEqual(renewed.status, 200,
                       JSON.stringify(renewed.json).slice(0, 300));
    assert.ok(/^dpop$/i.test(String(renewed.json.token_type || "")),
              JSON.stringify(renewed.json).slice(0, 200));
    assert.notStrictEqual(client.token, firstToken);
    assert.ok(client.refreshToken && client.refreshToken !== firstRefresh,
              "the refresh token was not rotated");
  });
  const me = await asked(client);
  check("AND THE NEW TOKEN READS THEIR OWN ACCOUNT — no sign-in, no page " +
        "left", function () {
    assert.strictEqual(me.status, 200, JSON.stringify(me.json));
    assert.strictEqual(me.json.user.username, held.who);
  });
  const starts = (await auditRows(realmApi, "session.start")).filter(
      function (row) {
    return row.actor === held.who;
  });
  check("AND NO NEW SESSION: one session.start row for this person — the " +
        "sign-on session; the portal holds a token and no session of its " +
        "own (#568)", function () {
    assert.strictEqual(starts.length, 1,
                       JSON.stringify(starts.map(function (row) {
      return row.summary;
    })));
  });
  const row = (await sessionsIn(realmApi)).filter(function (s) {
    return s.sessionId === sidOf(held.signOnCookie);
  })[0];
  check("the sign-on session is listed, and nothing on its row is a token",
        function () {
    assert.ok(row, "no row for " + held.signOnCookie);
    assert.ok(!/eyJ[A-Za-z0-9_-]{10,}/.test(JSON.stringify(row)),
              JSON.stringify(row));
  });
  log.debug("Leaving thePortalRenewsInPlace().");
  return held;
}

// ---------------------------------------------------------------------------
// 2. A SIGN-OUT ENDS IT.
// ---------------------------------------------------------------------------
async function aSignOutStillEndsIt() {
  log.debug("Entering aSignOutStillEndsIt().");
  log.info("=== 2. revoking the sign-on session ends the portal's token ===");
  const held = await portalAs(usernameFor("renew-signout"));
  const before = await asked(held.client);
  check("before: the token reads the account", function () {
    assert.strictEqual(before.status, 200, JSON.stringify(before.json));
  });
  const signOn = (await sessionsIn(realmApi)).filter(function (s) {
    return s.sessionId === sidOf(held.signOnCookie);
  })[0];
  assert.ok(signOn, "no row for the sign-on session " + held.signOnCookie);
  await ok(realmApi + "/sessions/revoke",
           { key: signOn.key, select: signOn.id },
           "revoked the sign-on session");
  const after = await asked(held.client);
  check("THE TOKEN IS REFUSED: 401 invalid_token, because the sign-on " +
        "session it was issued on has ended", function () {
    assert.strictEqual(after.status, 401, JSON.stringify(after.json));
    assert.ok(/invalid_token/.test(after.challenge), after.challenge);
  });
  const rows = await sessionsIn(realmApi);
  check("and the sign-on session is gone from the list", function () {
    assert.ok(!rows.some(function (s) {
      return s.sessionId === sidOf(held.signOnCookie);
    }), held.signOnCookie);
  });
  log.debug("Leaving aSignOutStillEndsIt().");
}

// ---------------------------------------------------------------------------
// 3. A REVOCATION ENDS IT, AND THE NEXT SIGN-IN NEEDS NO SCREEN.
// ---------------------------------------------------------------------------
async function aRefusedRenewalReturnsToThePage() {
  log.debug("Entering aRefusedRenewalReturnsToThePage().");
  log.info("=== 3. the person's tokens revoked ===");
  const held = await portalAs(usernameFor("renew-refused"));
  // The person's own subject (`urn:uuid:<entryUUID>` since 2026-09-14), read
  // off the realm's /admin-api/users rather than built from the name.
  const subjectAnswer = await call("GET", realmApi + "/users?user=" +
                                   encodeURIComponent(held.who));
  const sub = String((subjectAnswer.body && subjectAnswer.body.subject) || "");
  check("the person has a urn:uuid: subject to revoke by", function () {
    assert.ok(/^urn:uuid:/.test(sub), subjectAnswer.raw.slice(0, 200));
  });
  const revoked = await ok(realmApi + "/tokens/revoke-subject",
                           { subject: sub },
                           "revoked every token for " + held.who);
  check("the refresh token (and the rest) were revoked", function () {
    assert.ok(Number(revoked.revoked) >= 1, JSON.stringify(revoked));
  });
  const page = await asked(held.client);
  check("THE ACCESS TOKEN IS REFUSED: 401 invalid_token", function () {
    assert.strictEqual(page.status, 401, JSON.stringify(page.json));
    assert.ok(/invalid_token/.test(page.challenge), page.challenge);
  });
  const renewed = await held.client.refresh();
  check("and so is the refresh grant", function () {
    assert.strictEqual(renewed.status, 400,
                       JSON.stringify(renewed.json).slice(0, 300));
    assert.strictEqual(renewed.json.error, "invalid_grant");
  });
  // The helper refuses to type a password here: a sign-in screen would fail
  // it, so a client coming back IS the code answered with no screen.
  const again = await portalSignin.signInToThePortal(base + R, held.who, log,
    { cookie: held.client.cookie });
  const keys = await again.page("/portal/keys");
  check("THE SIGN-ON SESSION IS STILL LIVE: the portal's next authorization " +
        "request is answered with a code and no sign-in screen, and the new " +
        "token draws the page", function () {
    assert.strictEqual(keys.status, 200, keys.text.slice(0, 300));
  });
  log.debug("Leaving aRefusedRenewalReturnsToThePage().");
}

// ---------------------------------------------------------------------------
// 4. THE CONSOLE.
// ---------------------------------------------------------------------------
async function theConsoleRenewsToo() {
  log.debug("Entering theConsoleRenewsToo().");
  log.info("=== 4. the admin console renews inside the same session ===");
  // THE CONSOLE IS A STATIC PAGE SINCE #446, signed in in the browser as a
  // public client with a DPoP-bound token; there is no console session to
  // keep. What renews is the TOKEN: the refresh grant, with the same key,
  // the refresh token rotated. `console_signin.js` does what the page does.
  const consoleClient = await signin.signInToTheConsole(base + R,
    usernameFor("renew-console"), log);
  const firstToken = consoleClient.token;
  const firstRefresh = consoleClient.refreshToken;
  check("the sign-in left the console holding a refresh token", function () {
    assert.ok(firstRefresh, "no refresh token was issued");
  });
  await sleep(1100);
  const renewed = await consoleClient.refresh();
  check("the refresh grant answers a new DPoP-bound access token and " +
        "rotates the refresh token", function () {
    assert.strictEqual(renewed.status, 200,
                       JSON.stringify(renewed.json).slice(0, 300));
    assert.ok(/^dpop$/i.test(String(renewed.json.token_type || "")),
              JSON.stringify(renewed.json).slice(0, 200));
    assert.notStrictEqual(consoleClient.token, firstToken);
    assert.ok(consoleClient.refreshToken &&
              consoleClient.refreshToken !== firstRefresh,
              "the refresh token was not rotated");
  });
  const page = await consoleClient.api("GET", "/admin-api/sessions");
  check("and the console reads with it (200, or 403 where the role roster " +
        "names others), with no new sign-in", function () {
    assert.ok(page.status === 200 || page.status === 403,
              page.status + " " + String(page.text).slice(0, 200));
  });
  log.debug("Leaving theConsoleRenewsToo().");
}

// ---------------------------------------------------------------------------
// 5. THE SIGN-ON SESSION RUNNING OUT ENDS THE PORTAL'S TOKENS.
// ---------------------------------------------------------------------------
async function theSignOnSessionRunningOut(held) {
  log.debug("Entering theSignOnSessionRunningOut().");
  log.info("=== 5. the sign-on session runs out, and the portal's token " +
           "with it ===");
  const signOn = (await sessionsIn(realmApi)).filter(function (s) {
    return s.sessionId === sidOf(held.signOnCookie);
  })[0];
  const waitMs = signOn ?
                 Math.max(0, Number(signOn.expiresAt) - Date.now()) + 1500
                        : 0;
  log.info("waiting " + Math.round(waitMs / 1000) +
           "s for the sign-on session to run out");
  await sleep(waitMs);
  // Presenting the expired sign-on cookie where it is read ends it through the
  // lookup — the authorization endpoint — rather than waiting on the sweep.
  await fetch(base + R + "/oauth2/authorize?client_id=sts-user-portal&" +
              "response_type=code&scope=openid&redirect_uri=" +
              encodeURIComponent(base + R + "/portal/callback"),
              { redirect: "manual",
                headers: { cookie: "sts_session=" + held.signOnCookie } });
  const rows = await sessionsIn(realmApi);
  check("the sign-on session has ended", function () {
    assert.ok(!rows.some(function (s) {
      return s.sessionId === sidOf(held.signOnCookie);
    }), held.signOnCookie);
  });
  const page = await asked(held.client);
  check("AND THE PORTAL'S TOKEN DIES WITH IT: 401 invalid_token — the " +
        "relying-party portal outlived its sign-on session by renewing, and " +
        "the static one does not (#568)", function () {
    assert.strictEqual(page.status, 401, JSON.stringify(page.json));
    assert.ok(/invalid_token/.test(page.challenge), page.challenge);
  });
  const renewed = await held.client.refresh();
  const after = await asked(held.client);
  check("and a renewal does not revive it: whatever the refresh grant " +
        "answers, the account is not read with what it gave", function () {
    assert.ok(renewed.status !== 200 || after.status === 401,
              renewed.status + " then " + after.status);
  });
  log.debug("Leaving theSignOnSessionRunningOut().");
}

async function test() {
  log.debug("Entering test().");
  await setUp();
  const held = await thePortalRenewsInPlace();
  await aSignOutStillEndsIt();
  await aRefusedRenewalReturnsToThePage();
  await theConsoleRenewsToo();
  await theSignOnSessionRunningOut(held);
  // A FLOOR on the check count, for sts_admin_console.js's reason: a section
  // that stops being called takes its assertions with it and the run still
  // says passed.
  assert.ok(checks >= 19, "only " + checks + " checks ran");
  log.info("sts_hosted_surface_renewal: " + checks + " checks passed.");
  log.debug("Leaving test().");
}

test().then(function () {
  process.exit(0);
}, function (e) {
  log.error("sts_hosted_surface_renewal FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
