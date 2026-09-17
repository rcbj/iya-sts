"use strict";
//
// File: sts_hosted_surface_renewal.js
//
// ===========================================================================
// THE ADMIN CONSOLE AND THE USER PORTAL RENEW THEIR TOKENS INSIDE THE SAME
// SESSION, OVER HTTP (2026-09-12).
//
// An operator watched their console session expire an hour after signing in,
// with its ID Token and access token, and was sent back through the sign-in
// screen — off the page they were on. `common/oidc_rp.ts` now keeps the tokens
// a sign-in was issued and, when they run out, redeems the refresh token over
// the loopback back channel and writes the new tokens onto the SAME session.
// This job drives both surfaces through a real browser-shaped cookie jar and
// asserts what a person would notice:
//
//   1. THE PORTAL RENEWS AND STAYS ON THE PAGE. The page answers 200, the
//      session id and the CSRF token on it are the ones it had, no second
//      session appears, and exactly the audit row a renewal writes is there.
//   2. A SIGN-OUT STILL ENDS A RENEWABLE SESSION. Revoking the sign-on session
//      cascades, and the next page is the authorization code flow.
//   3. A RENEWAL THE TOKEN ENDPOINT REFUSES ENDS THE SESSION AND COMES BACK TO
//      THE SAME PAGE. The refresh token is revoked; the next page runs the code
//      flow, the sign-on session answers it without a sign-in, and the browser
//      lands on the page it asked for.
//   4. THE CONSOLE RENEWS TOO, and its session — which lives in the default
//      realm's partition while its sign-in ran here — writes its renewal there.
//   5. THE SIGN-ON SESSION RUNNING OUT DOES NOT END IT. With the realm's
//      session lifetime at its sixty-second floor, the portal session outlives
//      its sign-on session and goes on renewing.
//
// `oidcRp.renewBeforeExpiryS` is set at the TOKEN LIFETIME in the realm, which
// renews on every request: that is how a renewal is watched without waiting an
// hour, and the setting's own description names it for exactly this.
//
// `local: true`, for tests/CLAUDE.md's ownership reason: it drives this
// service's own `/admin` and `/portal` and reads `/admin-api`. It runs in a
// throwaway realm it creates and leaves standing, for "No job removes a realm".
// `tests/oidc_rp_renewal.js` is the in-process half — the decision table, a
// parent that vanished early, and the same-sign-in check.
// ===========================================================================

const assert = require("assert");
const { runStamp, usernameFor } = require("./random_username.js");

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

function absolute(location) {
  log.debug("Entering absolute().");
  log.debug("Leaving absolute().");
  return /^https?:\/\//i.test(String(location || "")) ? String(location)
                                                       : base +
                                                           String(
                                                               location || "");
}

// A cookie jar kept BY NAME and manual redirects — sts_portal_sessions.js's
// browser, because every assertion here is about which cookie and which hop.
function browser() {
  log.debug("Entering browser().");
  const self = {
    jar: {},
    async go(method, path, body) {
      log.debug("Entering go().");
      const headers = {};
      const cookie = Object.keys(self.jar)
                           .map(function (k) { return k + "=" + self.jar[k]; })
                           .join("; ");
      if (cookie) headers.cookie = cookie;
      if (body !== undefined) headers["Content-Type"] =
          "application/x-www-form-urlencoded";
      const r = await fetch(absolute(path),
                            { method: method, redirect: "manual",
                                              headers: headers, body: body });
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
      });
      log.debug("Leaving go().");
      return { status: r.status, location: r.headers.get("location") || "",
               text: await r.text(), setCookies: set };
    }
  };
  log.debug("Leaving browser().");
  return self;
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

function csrfOf(text) {
  log.debug("Entering csrfOf().");
  log.debug("Leaving csrfOf().");
  return (String(text).match(/name="csrf_token" value="([^"]+)"/) ||
          [])[1] || "";
}

// Through the authorization code flow at `door`, signing in when the
// authorization endpoint asks. Answers the browser and the page landed on.
async function signInAt(b, door, who) {
  log.debug("Entering signInAt(). door=" + door);
  let r = await b.go("GET", door);
  assert.ok(/\/oauth2\/authorize\?/.test(r.location),
    door + " should send an unauthenticated browser to the authorization " +
    "endpoint; it answered " + r.status + " -> " + r.location);
  r = await b.go("GET", r.location);
  if (/\/authn\/login\?authn=/.test(r.location)) {
    r = await b.go("GET", r.location);
    const authnId = (r.text.match(/name="authn_id" value="([^"]+)"/) || [])[1];
    assert.ok(authnId,
              "the sign-in screen carries an authn_id: " +
              r.text.slice(0, 200));
    r = await b.go("POST", R + "/authn/login", new URLSearchParams({
      authn_id: authnId, username: who, password: PASSWORD, action: "login",
      csrf_token: csrfOf(r.text) }).toString());
    assert.ok(r.status === 303 || r.status === 302,
      "the sign-in form should redirect; it answered " + r.status + " " +
      r.text.slice(0, 200));
    r = await b.go("GET", r.location);
  }
  assert.ok(/\/(admin|portal)\/callback\?/.test(r.location),
    "the authorization endpoint should come back to the callback with a " +
    "code; it answered " +
    r.status + " -> " + r.location);
  r = await b.go("GET", r.location);
  assert.ok(r.status === 303 || r.status === 302,
    "the callback should redirect to the page asked for; it answered " +
    r.status + " " +
    r.text.slice(0, 300));
  const landed = r.location;
  log.debug("Leaving signInAt(). landed on " + landed);
  return landed;
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
  await ok(api + "/realms/create", { id: REALM, name: REALM },
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
// 1. THE PORTAL RENEWS AND STAYS ON THE PAGE.
// ---------------------------------------------------------------------------
async function thePortalRenewsInPlace() {
  log.debug("Entering thePortalRenewsInPlace().");
  log.info("=== 1. the portal renews its tokens inside the same session ===");
  const who = usernameFor("renew-portal");
  await ensurePerson(who);
  const b = browser();
  const landed = await signInAt(b, R + "/portal/mfa", who);
  const portalId = b.jar.sts_portal;
  const signOnId = b.jar.sts_session;
  check("the sign-in left the browser holding a portal session and a sign-on " +
        "session",
    function () {
      assert.ok(portalId && signOnId, JSON.stringify(Object.keys(b.jar)));
    });
  check("and came back to the page it asked for", function () {
    assert.ok(/\/portal\/mfa$/.test(landed), landed);
  });

  const first = await b.go("GET", R + "/portal/mfa");
  const csrfBefore = csrfOf(first.text);
  const renewalsBefore = (await auditRows(realmApi, "session.renew",
                                          sidOf(portalId))).length;
  await sleep(1100);
  const page = await b.go("GET", R + "/portal/mfa");
  check("THE PAGE IS DRAWN — 200, not a redirect to the authorization " +
        "endpoint — with the tokens due for renewal on every " +
        "request", function () {
    assert.strictEqual(page.status, 200, page.status + " -> " + page.location);
  });
  check("THE SAME SESSION: the browser still holds the same portal session " +
        "id and was sent no new one", function () {
    assert.strictEqual(b.jar.sts_portal, portalId);
    assert.ok(!page.setCookies.some(function (c) {
      return /^sts_portal=/.test(c);
    }),
              page.setCookies.join(" | "));
  });
  check("the CSRF token on the page is the one a form already open carries, " +
        "which is what keeps a half-filled form working across a " +
        "renewal", function () {
    assert.ok(csrfBefore, "the page before the renewal carried no CSRF token");
    assert.strictEqual(csrfOf(page.text), csrfBefore);
  });
  check("and it shows THEIR account", function () {
    assert.ok(page.text.indexOf(who) >= 0, "the page does not name " + who);
  });

  const renewals = await auditRows(realmApi, "session.renew",
                                  sidOf(portalId));
  check("A RENEWAL HAPPENED: `session.renew` rows for this session, outcome " +
        "success",
    function () {
      assert.ok(renewals.length > renewalsBefore,
                renewals.length + " row(s), " + renewalsBefore + " before");
      assert.ok(renewals.every(function (row) {
        return row.outcome === "success";
      }),
                JSON.stringify(renewals.map(function (row) {
                  return row.outcome;
                })));
    });
  const starts = (await auditRows(realmApi, "session.start")).filter(
      function (row) {
    return row.actor === who;
  });
  check("AND NO NEW SESSION: two session.start rows for this person — the " +
        "sign-on session and the portal's — however many renewals there " +
        "were", function () {
    assert.strictEqual(starts.length, 2,
                       JSON.stringify(starts.map(function (row) {
      return row.summary;
    })));
  });
  const row = (await sessionsIn(realmApi)).filter(function (s) {
    return s.sessionId === sidOf(portalId);
  })[0];
  check("the sessions list names the renewals on the portal session's row, " +
        "and its expiry rule says it renews rather than dying with its " +
        "sign-on session", function () {
    assert.ok(row, "no row for " + portalId);
    assert.ok(/tokens renewed [0-9]+ time/.test(row.detail), row.detail);
    assert.ok(/^Renewed, not extended/.test(row.expiryRule), row.expiryRule);
  });
  check("and nothing on that row is a token", function () {
    assert.ok(!/eyJ[A-Za-z0-9_-]{10,}/.test(JSON.stringify(row)),
              JSON.stringify(row));
  });
  log.debug("Leaving thePortalRenewsInPlace().");
  return { b: b, who: who, portalId: portalId, signOnId: signOnId };
}

// ---------------------------------------------------------------------------
// 2. A SIGN-OUT STILL ENDS A RENEWABLE SESSION.
// ---------------------------------------------------------------------------
async function aSignOutStillEndsIt() {
  log.debug("Entering aSignOutStillEndsIt().");
  log.info("=== 2. revoking the sign-on session still ends the portal " +
           "session ===");
  const who = usernameFor("renew-signout");
  await ensurePerson(who);
  const b = browser();
  await signInAt(b, R + "/portal", who);
  const portalId = b.jar.sts_portal;
  const signOn = (await sessionsIn(realmApi)).filter(function (s) {
    return s.sessionId === sidOf(b.jar.sts_session);
  })[0];
  assert.ok(signOn, "no row for the sign-on session " + b.jar.sts_session);
  await ok(realmApi + "/sessions/revoke",
           { key: signOn.key, select: signOn.id },
           "revoked the sign-on session");
  const page = await b.go("GET", R + "/portal");
  check("the portal answers with the authorization code flow, not the page — " +
        "renewal did not turn the cascade off", function () {
    assert.ok(page.status === 303 &&
              /\/oauth2\/authorize\?/.test(page.location),
              page.status + " -> " + page.location);
  });
  const rows = await sessionsIn(realmApi);
  check("and the portal session is gone from the list", function () {
    assert.ok(!rows.some(function (s) {
      return s.sessionId === sidOf(portalId);
    }),
              portalId);
  });
  log.debug("Leaving aSignOutStillEndsIt().");
}

// ---------------------------------------------------------------------------
// 3. A REFUSED RENEWAL ENDS THE SESSION AND COMES BACK TO THE SAME PAGE.
// ---------------------------------------------------------------------------
async function aRefusedRenewalReturnsToThePage() {
  log.debug("Entering aRefusedRenewalReturnsToThePage().");
  log.info("=== 3. a refresh token the token endpoint refuses ===");
  const who = usernameFor("renew-refused");
  await ensurePerson(who);
  const b = browser();
  await signInAt(b, R + "/portal/keys", who);
  const portalId = b.jar.sts_portal;
  // The person's own subject (`urn:uuid:<entryUUID>` since 2026-09-14), read
  // off the realm's /admin-api/users rather than built from the name.
  const subjectAnswer = await call("GET", realmApi + "/users?user=" +
                                   encodeURIComponent(who));
  const sub = String((subjectAnswer.body && subjectAnswer.body.subject) || "");
  check("the person has a urn:uuid: subject to revoke by", function () {
    assert.ok(/^urn:uuid:/.test(sub), subjectAnswer.raw.slice(0, 200));
  });
  const revoked = await ok(realmApi + "/tokens/revoke-subject",
                           { subject: sub },
                           "revoked every token for " + who);
  check("the refresh token (and the rest) were revoked", function () {
    assert.ok(Number(revoked.revoked) >= 1, JSON.stringify(revoked));
  });
  const page = await b.go("GET", R + "/portal/keys");
  check("THE SESSION IS ENDED: the page answers with the authorization code " +
        "flow",
    function () {
      assert.ok(page.status === 303 &&
                /\/oauth2\/authorize\?/.test(page.location),
                page.status + " -> " + page.location);
    });
  const refused = (await auditRows(realmApi, "session.renew",
                                   sidOf(portalId))).filter(
      function (row) {
    return row.outcome === "refused";
  });
  check("and it says why: a refused `session.renew` row coded STS-AUTHN-0137",
        function () {
    assert.ok(refused.length >= 1, "no refused row");
    assert.strictEqual(refused[0].errorCode, "STS-AUTHN-0137");
  });
  let r = await b.go("GET", page.location);
  check("the sign-on session is still live, so the authorization endpoint " +
        "answers with a code and no sign-in screen", function () {
    assert.ok(/\/portal\/callback\?/.test(r.location),
              r.status + " -> " + r.location);
  });
  r = await b.go("GET", r.location);
  check("AND THE BROWSER LANDS BACK ON THE PAGE IT WAS ON", function () {
    assert.ok((r.status === 303 || r.status === 302) && /\/portal\/keys$/.test(
        r.location),
              r.status + " -> " + r.location);
  });
  log.debug("Leaving aRefusedRenewalReturnsToThePage().");
}

// ---------------------------------------------------------------------------
// 4. THE CONSOLE.
// ---------------------------------------------------------------------------
async function theConsoleRenewsToo() {
  log.debug("Entering theConsoleRenewsToo().");
  log.info("=== 4. the admin console renews inside the same session ===");
  const who = usernameFor("renew-console");
  await ensurePerson(who);
  const b = browser();
  await signInAt(b, R + "/admin/sessions", who);
  const adminId = b.jar.sts_admin;
  check("the sign-in left the browser holding a console session", function () {
    assert.ok(adminId, JSON.stringify(Object.keys(b.jar)));
  });
  await sleep(1100);
  const page = await b.go("GET", R + "/admin/sessions");
  check("the console answers the page (200, or 403 where the role roster " +
        "names others) and does NOT send the browser to the authorization " +
        "endpoint", function () {
    assert.ok(page.status === 200 || page.status === 403,
              page.status + " -> " + page.location);
  });
  check("with the same console session", function () {
    assert.strictEqual(b.jar.sts_admin, adminId);
  });
  const rows = await auditRows(api, "session.renew", sidOf(adminId));
  check("THE RENEWAL IS RECORDED IN THE DEFAULT REALM, where the console " +
        "session lives, although the sign-in ran in " + REALM, function () {
    assert.ok(rows.some(function (row) { return row.outcome === "success"; }),
              JSON.stringify(rows));
  });
  log.debug("Leaving theConsoleRenewsToo().");
}

// ---------------------------------------------------------------------------
// 5. THE SIGN-ON SESSION RUNNING OUT DOES NOT END IT.
// ---------------------------------------------------------------------------
async function theSignOnSessionRunningOut(held) {
  log.debug("Entering theSignOnSessionRunningOut().");
  log.info("=== 5. the sign-on session runs out; the portal session does not " +
           "===");
  const signOn = (await sessionsIn(realmApi)).filter(function (s) {
    return s.sessionId === sidOf(held.signOnId);
  })[0];
  const waitMs = signOn ?
                 Math.max(0, Number(signOn.expiresAt) - Date.now()) + 1500
                        : 0;
  log.info("waiting " + Math.round(waitMs / 1000) +
           "s for the sign-on session to run out");
  await sleep(waitMs);
  // Presenting the expired sign-on cookie where it is read ends it through the
  // lookup — the authorization endpoint — rather than waiting on the sweep.
  await held.b.go("GET",
                  R +
                  "/oauth2/authorize?client_id=sts-user-portal&response_type=code&scope=openid&redirect_uri=" + encodeURIComponent(base + R +
                                                                          "/portal/callback"));
  const rows = await sessionsIn(realmApi);
  check("the sign-on session has ended", function () {
    assert.ok(!rows.some(function (s) {
      return s.sessionId === sidOf(held.signOnId);
    }),
              held.signOnId);
  });
  const page = await held.b.go("GET", R + "/portal/mfa");
  check("AND THE PORTAL PAGE IS STILL DRAWN for the person who signed in " +
        "more than a minute ago — the same portal session, renewing its own " +
        "tokens", function () {
    assert.strictEqual(page.status, 200, page.status + " -> " + page.location);
    assert.strictEqual(held.b.jar.sts_portal, held.portalId);
    assert.ok(page.text.indexOf(held.who) >= 0);
  });
  const after = (await sessionsIn(realmApi)).filter(function (s) {
    return s.sessionId === sidOf(held.portalId);
  })[0];
  check("and it is still listed, derived from a sign-on session that no " +
        "longer exists",
    function () {
      assert.ok(after, "no row for " + held.portalId);
      assert.strictEqual(after.derivedFrom, sidOf(held.signOnId));
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
  assert.ok(checks >= 24, "only " + checks + " checks ran");
  log.info("sts_hosted_surface_renewal: " + checks + " checks passed.");
  log.debug("Leaving test().");
}

test().then(function () {
  process.exit(0);
}, function (e) {
  log.error("sts_hosted_surface_renewal FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
