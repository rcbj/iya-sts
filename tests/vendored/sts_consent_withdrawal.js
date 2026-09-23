"use strict";
//
// File: sts_consent_withdrawal.js
//
// ---------------------------------------------------------------------------
// WITHDRAWN MEANS WITHDRAWN, OVER THE WIRE (#172, 2026-09-23).
//
// Until #172 withdrawing a consent edited the record and nothing else: the
// application kept refreshing for the refresh token's whole lifetime, and the
// refresh grant never asked. Now (the argument is above `withdrawnStamp()` in
// common/consent.ts), asserted over HTTP in a throwaway trust realm that is
// left behind, in whichever mode the service runs:
//
//   a. A GRANT UNDER CONSENT REFRESHES, and withdrawing one of its scopes
//      through `/admin-api` revoke-consent makes the refresh `invalid_grant`
//      and its access token inactive at introspection.
//   b. RE-CONSENTING REVIVES NOTHING: a new code works, the old refresh token
//      is still refused.
//   c. AN `offline_access` GRANT — the one that runs while the person is away
//      — is ended by withdrawing `offline_access` alone.
//   d. `revoke-application-consent` and `forget-user-consent` do the same,
//      and each refuses a second time with nothing held.
//   e. A GLOBAL CONSENT: the generic application edit refuses to remove it;
//      `revoke-global-consent` revokes the grant it covered; re-adding it
//      revives nothing, and a new sign-in works without being asked.
//   f. THE PERSON THEMSELVES, on `/portal/consents`: the page lists what they
//      agreed, the Withdraw form revokes the grant, and the page refuses a
//      post without its CSRF token and one naming nothing of theirs.
//   g. `oauth2.refreshRequiresConsent`: a grant made while consent was off is
//      refused once consent is on, and renewed with the setting off.
//
// OWNED HERE (local: true): this repository's consent register, console
// operations and portal.
// ---------------------------------------------------------------------------

const assert = require("assert");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const registry = require("./sts_applications.js");

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
var log = bunyan.createLogger({ name: "sts_consent_withdrawal",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("withdraw-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                                 .slice(0, 31);
const realmBase = base + "/realm/" + REALM;
const realmApi = realmBase + "/admin-api";
const REDIRECT = "https://rp.withdraw.example.test/cb";
const PASSWORD = "Withdraw-Passw0rd!-" + String(Date.now()).slice(-6);
const ALICE = names.usernameFor("wd-alice");
const SECRET = "withdraw-" + String(Date.now()).slice(-8) + "-client-secret";
const A = { client_id: "wd-a-" + REALM, client_secret: SECRET };
const B = { client_id: "wd-b-" + REALM, client_secret: SECRET };
const SCOPES = ["openid", "profile", "email", "offline_access"];
let PRODUCT = false;
let cookie = "";

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
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
    // Not JSON — an HTML page or an empty 200; the caller reads `raw`.
    body = null;
  }
  log.debug("Leaving send(). status=" + r.status);
  return { status: r.status, body: body, raw: raw, headers: r.headers };
}

function apiPost(url, payload) {
  log.debug("Entering apiPost().");
  log.debug("Leaving apiPost().");
  return send(url, { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}) });
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await apiPost(url, payload);
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + String(r.raw).slice(0, 400));
  log.debug("Leaving ok().");
  return r.body;
}

function basicFor(client) {
  log.debug("Entering basicFor().");
  log.debug("Leaving basicFor().");
  return "Basic " + Buffer.from(encodeURIComponent(client.client_id) + ":" +
                                encodeURIComponent(client.client_secret))
    .toString("base64");
}

// A form POST to the realm with client_secret_basic.
function post(path, form, client) {
  log.debug("Entering post(). " + path);
  log.debug("Leaving post().");
  return send(realmBase + path, { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded",
               Authorization: basicFor(client) },
    body: new URLSearchParams(form).toString() });
}

// Introspection as the token's own client (RFC 9701 section 5's rule).
async function active(token, client) {
  log.debug("Entering active().");
  const r = await post("/oauth2/introspect", { token: token }, client);
  assert.strictEqual(r.status, 200, "introspection: " + r.raw.slice(0, 300));
  log.debug("Leaving active(). " + r.body.active);
  return r.body.active === true;
}

// A code the way a browser gets one — the consent screen answered Allow if it
// is drawn — and the tokens for it.
async function tokens(client, scope) {
  log.debug("Entering tokens(). " + client.client_id + " " + scope);
  const got = await registry.authorizationCode(realmBase, {
    clientId: client.client_id, redirectUri: REDIRECT, username: ALICE,
    password: PASSWORD, scope: scope, cookie: cookie || undefined });
  cookie = got.cookie;
  const r = await post("/oauth2/token", { grant_type: "authorization_code",
    code: got.code, redirect_uri: REDIRECT, code_verifier: got.verifier },
    client);
  assert.strictEqual(r.status, 200, "the token request for " +
                     client.client_id + ": " + r.raw.slice(0, 400));
  assert.ok(r.body.access_token && r.body.refresh_token,
            "an access token and a refresh token: " +
            Object.keys(r.body).join(", "));
  log.debug("Leaving tokens().");
  return r.body;
}

function refresh(token, client) {
  log.debug("Entering refresh().");
  log.debug("Leaving refresh().");
  return post("/oauth2/token", { grant_type: "refresh_token",
                                 refresh_token: token }, client);
}

// A refresh that must succeed; answers the new token set (the rotated
// refresh token in product, where RFC 9700 mode rotates).
async function renewed(token, client, what) {
  log.debug("Entering renewed().");
  const r = await refresh(token, client);
  assert.strictEqual(r.status, 200, what + ": " + r.raw.slice(0, 400));
  log.debug("Leaving renewed().");
  return { access_token: r.body.access_token,
           refresh_token: r.body.refresh_token || token };
}

function refused(r, status, error) {
  log.debug("Entering refused().");
  assert.strictEqual(r.status, status, r.raw.slice(0, 400));
  assert.strictEqual(r.body && r.body.error, error, r.raw.slice(0, 400));
  log.debug("Leaving refused().");
}

function application(client) {
  log.debug("Entering application().");
  log.debug("Leaving application().");
  return { identifier: client.client_id, kind: "oauth2-client",
           name: client.client_id, protocols: ["oauth2", "oidc"],
           fields: { oauthClientId: [client.client_id],
                     oauthRedirectUri: [REDIRECT],
                     oauthGrantType: ["authorization_code", "refresh_token"],
                     oauthAllowedScope: SCOPES,
                     oauthTokenEndpointAuthMethod: "client_secret_basic",
                     oauthClientSecret: client.client_secret } };
}

async function setUp() {
  log.debug("Entering setUp().");
  log.info("=== 0. a throwaway realm " + REALM + " ===");
  PRODUCT = await registry.isProduct(base);
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "Consent withdrawal " + STAMP },
    "created the realm");
  await ok(realmApi + "/users/create", {
    username: ALICE, invent: false, credential: "password",
    password: PASSWORD,
    attributes: { cn: "Withdraw " + ALICE, givenName: "Withdraw", sn: ALICE,
                  mail: ALICE + "@withdraw.test" } }, "created " + ALICE);
  await ok(realmApi + "/applications/create", application(A), "client A");
  await ok(realmApi + "/applications/create", application(B), "client B");
  log.debug("Leaving setUp().");
}

// ---------------------------------------------------------------------------
// a–d. THE PERSON'S OWN CONSENT, WITHDRAWN THROUGH /admin-api.
// ---------------------------------------------------------------------------
async function personalConsent() {
  log.debug("Entering personalConsent().");
  log.info("=== a. revoke-consent ends the grant ===");
  const first = await tokens(A, "openid profile");
  const again = await renewed(first.refresh_token, A,
                              "a grant under consent refreshes");
  check("a grant under consent refreshes", function () {
    assert.ok(again.access_token);
  });
  const answer = await ok(realmApi + "/consent/revoke-consent",
    { username: ALICE, client: A.client_id, scope: "profile" },
    "withdrew profile");
  let r = await refresh(again.refresh_token, A);
  const accessAfter = await active(again.access_token, A);
  check("withdrawing ONE scope makes the refresh invalid_grant, the whole " +
        "token and not a narrowed one", function () {
    refused(r, 400, "invalid_grant");
  });
  check("and the access token of the grant is inactive at introspection",
        function () {
    assert.strictEqual(accessAfter, false);
  });
  check("the reply says how many tokens it revoked", function () {
    assert.ok(answer.revoked >= 1, JSON.stringify(answer).slice(0, 300));
    assert.ok(/\d{14}\.\d{3}Z/.test(String(answer.withdrawnAt)),
              "withdrawnAt: " + answer.withdrawnAt);
  });

  log.info("=== b. re-consenting revives nothing ===");
  const fresh = await tokens(A, "openid profile");
  r = await refresh(again.refresh_token, A);
  check("after consenting again, the refresh token granted before the " +
        "withdrawal is still refused", function () {
    refused(r, 400, "invalid_grant");
  });
  const freshAgain = await renewed(fresh.refresh_token, A,
                                   "the new grant refreshes");
  check("and the new grant refreshes", function () {
    assert.ok(freshAgain.access_token);
  });

  log.info("=== c. withdrawing offline_access ends an offline grant ===");
  const offline = await tokens(A, "openid offline_access");
  check("offline_access was granted", function () {
    assert.ok(/offline_access/.test(String(offline.scope || "")),
              "scope: " + offline.scope);
  });
  await ok(realmApi + "/consent/revoke-consent",
    { username: ALICE, client: A.client_id, scope: "offline_access" },
    "withdrew offline_access");
  r = await refresh(offline.refresh_token, A);
  check("the offline grant — the one that runs while the person is away — " +
        "is refused", function () {
    refused(r, 400, "invalid_grant");
  });

  log.info("=== d. revoke-application-consent and forget-user-consent ===");
  const whole = await ok(realmApi + "/consent/revoke-application-consent",
    { username: ALICE, client: A.client_id }, "withdrew everything for A");
  r = await refresh(freshAgain.refresh_token, A);
  const wholeAgain = await apiPost(realmApi +
    "/consent/revoke-application-consent",
    { username: ALICE, client: A.client_id });
  check("revoke-application-consent withdraws every scope and refuses the " +
        "grant, and refuses a second time with nothing held", function () {
    assert.ok(whole.removed >= 2, JSON.stringify(whole).slice(0, 300));
    refused(r, 400, "invalid_grant");
    assert.strictEqual(wholeAgain.status, 400, wholeAgain.raw.slice(0, 300));
  });
  const beforeForget = await tokens(A, "openid email");
  await ok(realmApi + "/consent/forget-user-consent", { username: ALICE },
           "forgot everything");
  r = await refresh(beforeForget.refresh_token, A);
  check("forget-user-consent refuses the grant too", function () {
    refused(r, 400, "invalid_grant");
  });
  log.debug("Leaving personalConsent().");
}

// ---------------------------------------------------------------------------
// e. A GLOBAL CONSENT.
// ---------------------------------------------------------------------------
async function globalConsent() {
  log.debug("Entering globalConsent().");
  log.info("=== e. a global consent, withdrawn ===");
  await ok(realmApi + "/consent/grant-global-consent",
           { client: B.client_id, scope: "openid" }, "consented openid");
  await ok(realmApi + "/consent/grant-global-consent",
           { client: B.client_id, scope: "profile" }, "consented profile");
  const covered = await tokens(B, "openid profile");
  const covered2 = await renewed(covered.refresh_token, B,
                                 "a grant the override covered refreshes");
  const generic = await apiPost(realmApi + "/applications/remove",
    { application: B.client_id, attribute: "oauthGlobalConsent",
      value: "profile" });
  check("the generic application edit refuses to remove a global consent",
        function () {
    assert.strictEqual(generic.status, 400, generic.raw.slice(0, 300));
    assert.ok(/revoke-global-consent/.test(generic.raw),
              generic.raw.slice(0, 300));
  });
  const withdrawn = await ok(realmApi + "/consent/revoke-global-consent",
    { client: B.client_id, scope: "profile" }, "withdrew profile globally");
  let r = await refresh(covered2.refresh_token, B);
  const accessAfter = await active(covered2.access_token, B);
  check("revoke-global-consent refuses the grant it covered and its access " +
        "token is inactive", function () {
    refused(r, 400, "invalid_grant");
    assert.strictEqual(accessAfter, false);
    assert.ok(withdrawn.revoked >= 1, JSON.stringify(withdrawn).slice(0, 300));
  });
  await ok(realmApi + "/consent/grant-global-consent",
           { client: B.client_id, scope: "profile" }, "consented it again");
  r = await refresh(covered2.refresh_token, B);
  check("re-adding the override revives nothing", function () {
    refused(r, 400, "invalid_grant");
  });
  const next = await tokens(B, "openid profile");
  const nextAgain = await renewed(next.refresh_token, B,
                                  "a new grant under the override refreshes");
  check("and a new grant under the re-added override refreshes", function () {
    assert.ok(nextAgain.access_token);
  });
  log.debug("Leaving globalConsent().");
}

// ---------------------------------------------------------------------------
// f. THE PORTAL.
// ---------------------------------------------------------------------------
function jarFrom(header) {
  log.debug("Entering jarFrom().");
  const jar = {};
  String(header || "").split(/;\s*/).forEach(function (pair) {
    const name = pair.split("=")[0];
    if (name) {
      jar[name] = pair.slice(name.length + 1);
    }
  });
  log.debug("Leaving jarFrom().");
  return jar;
}

async function browse(jar, method, url, body) {
  log.debug("Entering browse(). " + method + " " + url);
  const headers = { cookie: Object.keys(jar).map(function (k) {
    return k + "=" + jar[k];
  }).join("; ") };
  if (body !== undefined) {
    headers["Content-Type"] = "application/x-www-form-urlencoded";
  }
  const r = await fetch(url, { method: method, redirect: "manual",
                               headers: headers, body: body });
  (r.headers.getSetCookie ? r.headers.getSetCookie() : [])
    .forEach(function (one) {
      const pair = String(one).split(";")[0];
      const name = pair.split("=")[0];
      const value = pair.slice(name.length + 1);
      if (value === "") {
        delete jar[name];
      } else {
        jar[name] = value;
      }
    });
  const location = r.headers.get("location") || "";
  log.debug("Leaving browse(). " + r.status);
  return { status: r.status, text: await r.text(),
           location: location ? new URL(location, url).toString() : "" };
}

// GET a portal page, following the portal's own code flow on the sign-on
// session the jar holds.
async function portalPage(jar, path) {
  log.debug("Entering portalPage().");
  let r = await browse(jar, "GET", realmBase + path);
  for (let hop = 0; hop < 8 && (r.status === 302 || r.status === 303);
       hop++) {
    r = await browse(jar, "GET", r.location);
  }
  assert.strictEqual(r.status, 200, path + " should draw; it answered " +
                     r.status + " " + r.text.slice(0, 300));
  log.debug("Leaving portalPage().");
  return r;
}

async function portal() {
  log.debug("Entering portal().");
  log.info("=== f. the person withdraws on /portal/consents ===");
  const grant = await tokens(A, "openid profile");
  const jar = jarFrom(cookie);
  let page = await portalPage(jar, "/portal/consents");
  check("the page lists the person's own consent to A, with a Withdraw form",
        function () {
    assert.ok(page.text.indexOf(A.client_id) >= 0, "client not listed");
    assert.ok(/name="action" value="scope"/.test(page.text),
              "no Withdraw form");
    assert.ok(!/<script/i.test(page.text), "a script on the page");
  });
  const csrf = (page.text.match(/name="csrf_token" value="([^"]+)"/) ||
                [])[1] || "";
  let r = await browse(jar, "POST", realmBase + "/portal/consents",
    new URLSearchParams({ action: "scope", client: A.client_id,
                          scope: "profile" }).toString());
  check("a post without its CSRF token is refused 403", function () {
    assert.strictEqual(r.status, 403, r.text.slice(0, 200));
  });
  r = await browse(jar, "POST", realmBase + "/portal/consents",
    new URLSearchParams({ action: "scope", client: B.client_id,
                          scope: "profile", csrf_token: csrf }).toString());
  check("a post naming nothing of the person's own is refused 400 — B's " +
        "profile is under GLOBAL consent, not theirs", function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 200));
  });
  const renewedBefore = await renewed(grant.refresh_token, A,
                                      "the grant refreshes before");
  r = await browse(jar, "POST", realmBase + "/portal/consents",
    new URLSearchParams({ action: "scope", client: A.client_id,
                          scope: "profile", csrf_token: csrf }).toString());
  check("the Withdraw form answers 303 back to the page", function () {
    assert.strictEqual(r.status, 303, r.text.slice(0, 200));
    assert.ok(/\/portal\/consents\?/.test(r.location), r.location);
  });
  r = await refresh(renewedBefore.refresh_token, A);
  const accessAfter = await active(renewedBefore.access_token, A);
  check("and the grant is refused and its access token inactive", function () {
    refused(r, 400, "invalid_grant");
    assert.strictEqual(accessAfter, false);
  });
  page = await portalPage(jar, "/portal/consents");
  check("and profile is no longer listed for A", function () {
    assert.ok(!/<code>profile<\/code>/.test(page.text),
              "profile still listed");
  });
  log.debug("Leaving portal().");
}

// ---------------------------------------------------------------------------
// g. oauth2.refreshRequiresConsent.
// ---------------------------------------------------------------------------
async function refreshRequiresConsent() {
  log.debug("Entering refreshRequiresConsent().");
  log.info("=== g. a grant nobody consented to ===");
  // Whatever is left, gone first; nothing held is a 400, which is fine here.
  const cleared = await apiPost(realmApi + "/consent/forget-user-consent",
                                { username: ALICE });
  log.debug("forget-user-consent answered " + cleared.status);
  await ok(realmApi + "/config/set", { key: "oauth2.consentRequired",
                                       value: false }, "consent off");
  let unasked;
  try {
    unasked = await tokens(A, "openid email");
  } finally {
    await ok(realmApi + "/config/set", { key: "oauth2.consentRequired",
                                         value: true }, "consent on again");
  }
  let r = await refresh(unasked.refresh_token, A);
  check("with consent turned on, a grant made while it was off is refused",
        function () {
    refused(r, 400, "invalid_grant");
  });
  const second = await tokens(A, "openid");
  await ok(realmApi + "/config/set", { key: "oauth2.consentRequired",
                                       value: false }, "consent off");
  let third;
  try {
    third = await tokens(A, "openid email");
  } finally {
    await ok(realmApi + "/config/set", { key: "oauth2.consentRequired",
                                         value: true }, "consent on again");
  }
  await ok(realmApi + "/config/set", { key: "oauth2.refreshRequiresConsent",
                                       value: false },
           "refreshRequiresConsent off");
  try {
    r = await refresh(third.refresh_token, A);
    check("with oauth2.refreshRequiresConsent off it is renewed (the weaker " +
          "option)", function () {
      assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
    });
  } finally {
    await ok(realmApi + "/config/set", { key: "oauth2.refreshRequiresConsent",
                                         value: true },
             "refreshRequiresConsent on again");
  }
  const secondAgain = await renewed(second.refresh_token, A,
                                    "a consented grant");
  check("and a grant that WAS consented is renewed with the setting on",
        function () {
    assert.ok(secondAgain.access_token);
  });
  log.debug("Leaving refreshRequiresConsent().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving consent withdrawal at " + realmBase + " (" +
           (PRODUCT ? "product" : "development") + ")");
  await setUp();
  await personalConsent();
  await globalConsent();
  await portal();
  await refreshRequiresConsent();
  assert.ok(checks >= 23, "only " + checks + " checks ran; a section has " +
                                             "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_consent_withdrawal")
  .description("#172: withdrawing a consent — through /admin-api, globally " +
    "and on /portal/consents — ends the grant it covered, a re-consent " +
    "revives nothing, and oauth2.refreshRequiresConsent refuses a grant " +
    "nobody consented to.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
