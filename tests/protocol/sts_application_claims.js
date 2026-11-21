// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_application_claims.js
//
// ---------------------------------------------------------------------------
// WHAT AN APPLICATION'S OWN CLAIM SETTINGS PUT IN A REAL TOKEN, OVER THE
// WIRE.
//
// D12 (#444): carries over the parts a client can see of five in-process
// files, each of which asserted through `admin_stats.jwtClaims()` or
// `oauth2.tokenSet()` in a child process. Here the settings go in through
// `/admin-api` and the claims come out of tokens this job obtains from the
// realm's own authorization endpoint (a person signed in at the screen over
// `/authn-api`, the code redeemed at `/oauth2/token`), decoded here:
//
//   A. application_claims.js — an application's custom claim rows win by
//      name over the realm's, add their own, another client keeps the
//      realm's, removing one brings the realm's back; the refusals
//      (STS-REG-0206 off the audit log: a reserved name, a name it does not
//      hold, an unknown set, an OAuth set on a SAML-only application, and
//      the GNAP set's reserved names and the GNAP set on an OAuth client);
//      `GET /admin-api/applications?application=` marking rows by source;
//      its access-token lifetime as the token's `expires_in` and `exp`.
//   B. application_claim_selections.js — the realm ticks `mail` for the ID
//      Token; an application's own selection REPLACES it, an empty one
//      carries nothing, inheriting brings it back, another client keeps the
//      realm's; STS-REG-0215 for an unknown attribute, an unknown set, an
//      undeclared family and a value that is not a list; the OAuth table's
//      `set-claim-selections` writing only the changed column, refusing the
//      whole Save on one bad attribute.
//   C. custom_attribute_claims.js — three custom attributes (an integer, a
//      multi-valued string, a date) in the catalogue, marked custom and
//      last; ticked for the access token, carried typed; a person without
//      a value carries none; an unknown name refuses the whole selection;
//      another realm offers none and refuses the name; a claims request
//      for one at UserInfo.
//   D. permission_claims.js — STS-REG-0344's refusals; a granted
//      permission of a resource server carries the claims mapped to it
//      (email without the email scope), one mapping nothing carries none,
//      a cleared mapping none, and a mapping for a permission no longer
//      exposed is listed stale.
//   E. scope_claims.js — a resource server declaring nothing gets no
//      section 5.4 claim; declared and granted it gets them, declared and
//      not granted it does not; the refusals (STS-REG-0203); and a
//      configured ID Token claim that a scope covers only with that scope.
//
// NOT CARRIED, and why: the SAML 2.0 and 1.1 halves (an assertion to a
// service provider is phase 7's flow, owed there); GNAP issuance of the
// application's rows (phase 8's flow; the refusals are here); the view
// models' markup and the libraries' pure functions (scope_claims A, the
// tabs' HTML — class (d)); a stored value the rules refuse being ignored at
// issuance (no door writes one: the write is refused first); the Kerberos
// PAC half (sts_kerberos_pac_claims) and CAEP's claims change
// (sts_caep_claims_doors).
//
// OWNED HERE (local: true): this repository's own management API.
// ---------------------------------------------------------------------------

// An address compared by parsing it, not searched for as text
// (`url_match.js`).
const urls = require("./url_match.js");
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
var log = bunyan.createLogger({ name: "sts_application_claims",
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
const REALM = "appcl-" + STAMP;
const OTHER_REALM = "appcl2-" + STAMP;
const R = "/realm/" + REALM;
const RB = base + R;
const API = RB + "/admin-api";
const SECRET = "app-claims-" + STAMP + "-" + String(Date.now()).slice(-8) +
               "-0123456789abcdef0123456789abcdef";
const PASSWORD = "App-Claims-Passw0rd!-" + String(Date.now()).slice(-6);
const ALICE = "alice-" + STAMP;
const BARE = "bare-" + STAMP;
const REDIRECT = "https://rp.appclaims.example.test/cb";
const HR = "https://hr.appclaims.example.test/";
const RS = "https://api.appclaims.example.test";
const AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 " +
  "sts_application_claims/1.0 (" + STAMP + ")";

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

function decode(token) {
  log.debug("Entering decode().");
  const parts = String(token).split(".");
  log.debug("Leaving decode().");
  return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
}

// One browser, with a cookie jar, signed in once and kept.
function browser() {
  log.debug("Entering browser().");
  const jar = {};
  const self = {
    jar: jar,
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
  const answer = await authnSignin.submit(base + R, location,
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

const browsers = {};

// A code flow for `who` at `client`, answering the token response.
async function tokensFor(client, scope, who, extra) {
  log.debug("Entering tokensFor(). " + client + " " + scope);
  const b = browsers[who] || (browsers[who] = browser());
  const verifier = nodeCrypto.randomBytes(32).toString("base64url");
  const params = Object.assign({ response_type: "code", client_id: client,
    redirect_uri: REDIRECT, scope: scope, state: "st",
    nonce: "n-" + STAMP,
    code_challenge: nodeCrypto.createHash("sha256").update(verifier)
      .digest("base64url"), code_challenge_method: "S256" }, extra || {});
  let r = await b.go("GET", R + "/oauth2/authorize?" + form(params));
  if ((r.status === 302 || r.status === 303) &&
      /\/authn\/login(?:\?app=[^#]*)?[?#]authn=/.test(r.location)) {
    const signed = await signIn(b, r.location, who);
    r = await b.go("GET", signed.location);
  }
  const code = r.location && urls.isAt(r.location, REDIRECT)
    ? new URL(r.location).searchParams.get("code") : "";
  assert.ok(code, "a code for " + client + " (" + scope + "): " + r.status +
            " " + r.location + " " + String(r.text).slice(0, 300));
  const body = { grant_type: "authorization_code", code: code,
    redirect_uri: REDIRECT, client_id: client, client_secret: SECRET,
    code_verifier: verifier };
  if (extra && extra.resource) {
    body.resource = extra.resource;
  }
  const t = await send(RB + "/oauth2/token", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form(body) });
  assert.strictEqual(t.status, 200, "the code redeemed: " +
                     t.raw.slice(0, 400));
  log.debug("Leaving tokensFor().");
  return t.body;
}

async function accessFor(client, scope, who, extra) {
  log.debug("Entering accessFor().");
  const t = await tokensFor(client, scope, who || ALICE, extra);
  log.debug("Leaving accessFor().");
  return decode(t.access_token);
}

async function idFor(client, scope, who) {
  log.debug("Entering idFor().");
  const t = await tokensFor(client, scope, who || ALICE);
  log.debug("Leaving idFor().");
  return decode(t.id_token);
}

async function client(id, protocols, fields) {
  log.debug("Entering client(). " + id);
  await ok(API + "/applications/create", { identifier: id, name: id,
    kind: "oauth2-client", protocols: protocols || ["oauth2", "oidc"],
    fields: Object.assign({ oauthClientId: [id], oauthClientSecret: SECRET,
      oauthTokenEndpointAuthMethod: "client_secret_post",
      oauthRedirectUri: [REDIRECT],
      oauthAllowedScope: ["openid", "profile", "email"],
      oauthGrantType: ["authorization_code", "client_credentials"],
      oauthResponseType: ["code"] }, fields || {}) },
    "registered " + id);
  for (const one of ["openid", "profile", "email"]) {
    await ok(API + "/consent/grant-global-consent",
             { client: id, scope: one }, "consented " + one + " for " + id);
  }
  log.debug("Leaving client().");
}

async function application(id) {
  log.debug("Entering application(). " + id);
  const r = await send(API + "/applications?application=" +
                       encodeURIComponent(id));
  assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
  log.debug("Leaving application().");
  return r.body;
}

// The application page's custom-claim sets, as GET answers them.
function setsOf(detail) {
  log.debug("Entering setsOf().");
  const c = detail && detail.customClaims;
  log.debug("Leaving setsOf().");
  return Array.isArray(c) ? c : ((c && c.sets) || []);
}

async function setup() {
  log.debug("Entering setup().");
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "Application claims " + STAMP },
    "created the realm");
  await ok(base + "/admin-api/realms/create", { id: OTHER_REALM,
    domain: OTHER_REALM + ".example.net",
    name: "Application claims, other " + STAMP },
    "created the other realm");
  const defined = [
    { name: "costCentreCode", label: "Cost centre", syntax: "integer" },
    { name: "badgeIds", label: "Badges", syntax: "string",
      multiValued: true },
    { name: "hiredOn", label: "Hired on", syntax: "date" }];
  for (const one of defined) {
    await ok(API + "/policies/define-person-attribute", one,
             "defined the custom attribute " + one.name);
  }
  await ok(API + "/users/create", { username: ALICE, invent: false,
    credential: "password", password: PASSWORD,
    attributes: { cn: "Alice " + STAMP, givenName: "Alice", sn: "Person",
                  mail: ALICE + "@appclaims.example.test",
                  departmentNumber: "D-7", costCentreCode: "42",
                  badgeIds: ["b-1", "b-2"], hiredOn: "20260131" } },
    "created " + ALICE);
  await ok(API + "/users/create", { username: BARE, invent: false,
    credential: "password", password: PASSWORD,
    attributes: { cn: "Bare " + STAMP, givenName: "Bare", sn: "Person",
                  mail: BARE + "@appclaims.example.test" } },
    "created " + BARE);
  await client("ac-web");
  await client("ac-other");
  await ok(API + "/applications/create", { identifier: "ac-sp",
    name: "ac-sp", kind: "saml2-service-provider",
    protocols: ["saml2", "saml11"],
    fields: {} }, "registered a SAML-only service provider");
  await ok(API + "/applications/create", { identifier: "ac-gnap",
    name: "ac-gnap", protocols: ["gnap"], fields: {} },
    "registered a GNAP client");
  log.debug("Leaving setup().");
}

// =========================================================================
// A. application_claims.js
// =========================================================================
async function sectionA() {
  log.debug("Entering sectionA().");
  log.info("=== A. an application's own custom claims ===");
  await ok(API + "/claims/replace", { set: "access_token", claims: [
    { name: "tenant", value: "realm" }, { name: "region", value: "us" }] },
    "set the realm's access-token claims");
  await ok(API + "/applications/set-custom-claim", { application: "ac-web",
    set: "access_token", name: "tenant", value: "app" },
    "set ac-web's tenant");
  await ok(API + "/applications/set-custom-claim", { application: "ac-web",
    set: "access_token", name: "plan", value: "gold" },
    "set ac-web's plan");
  await ok(API + "/applications/set-custom-claim", { application: "ac-web",
    set: "id_token", name: "department", attribute: "departmentNumber",
    type: "string" }, "set ac-web's department from the directory");
  const web = await accessFor("ac-web", "openid");
  const other = await accessFor("ac-other", "openid");
  check("A1. its own row wins by name, the realm's other row stays, its " +
        "extra row is added", function () {
    assert.strictEqual(web.tenant, "app", JSON.stringify(web));
    assert.strictEqual(web.region, "us");
    assert.strictEqual(web.plan, "gold");
  });
  check("A2. another client gets the realm's set", function () {
    assert.strictEqual(other.tenant, "realm", JSON.stringify(other));
    assert.strictEqual(other.plan, undefined);
  });
  const id = await idFor("ac-web", "openid");
  check("A3. a directory-attribute row carries the person's value",
        function () {
    assert.strictEqual(id.department, "D-7", JSON.stringify(id));
  });
  const detail = await application("ac-web");
  check("A4. the application's page marks each row by source, and a " +
        "replaced realm row so", function () {
    const sets = setsOf(detail);
    const access = sets.filter(function (one) {
      return one.id === "access_token";
    })[0] || { effective: [] };
    const tenant = access.effective.filter(function (one) {
      return one.name === "tenant";
    });
    assert.deepStrictEqual(sets.map(function (one) {
      return one.id;
    }), ["access_token", "id_token", "userinfo"],
                           JSON.stringify(detail.customClaims).slice(0, 600));
    assert.strictEqual(tenant.length, 1, JSON.stringify(access.effective));
    assert.strictEqual(tenant[0].source, "application");
    assert.strictEqual(tenant[0].replacesRealm, true);
    assert.ok(access.effective.some(function (one) {
      return one.name === "region" && one.source === "realm";
    }), JSON.stringify(access.effective));
  });
  await ok(API + "/applications/remove-custom-claim", {
    application: "ac-web", set: "access_token", name: "tenant" },
    "removed ac-web's tenant");
  const back = await accessFor("ac-web", "openid");
  check("A5. removing its row brings the realm's value back", function () {
    assert.strictEqual(back.tenant, "realm", JSON.stringify(back));
    assert.strictEqual(back.plan, "gold");
  });

  const before = await codeCount(API, "STS-REG-0206");
  const schemaBefore = await codeCount(API, "STS-API-0009");
  await refused(API + "/applications/set-custom-claim", {
    application: "ac-web", set: "access_token", name: "sub", value: "x" },
    "a reserved name");
  await refused(API + "/applications/remove-custom-claim", {
    application: "ac-web", set: "access_token", name: "nobody" },
    "a name it does not hold");
  await refused(API + "/applications/set-custom-claim", {
    application: "ac-web", set: "nope", name: "a", value: "b" },
    "an unknown set");
  await refused(API + "/applications/set-custom-claim", {
    application: "ac-sp", set: "access_token", name: "a", value: "b" },
    "an OAuth set on a SAML-only application");
  for (const reserved of ["access", "grant_id", "username"]) {
    await refused(API + "/applications/set-custom-claim", {
      application: "ac-gnap", set: "gnap_access_token", name: reserved,
      value: "nope" }, "GNAP's reserved " + reserved);
  }
  await refused(API + "/applications/set-custom-claim", {
    application: "ac-web", set: "gnap_access_token", name: "tenant",
    value: "nope" }, "the GNAP set on an OAuth client");
  const after = await codesSettle(API, "STS-REG-0206", before + 7);
  const schemaAfter = await codesSettle(API, "STS-API-0009",
                                        schemaBefore + 1);
  check("A6. an unknown set is refused by the request schema (STS-API-0009) " +
        "before the action looks", function () {
    assert.ok(schemaAfter - schemaBefore >= 1, "STS-API-0009 rows added: " +
              (schemaAfter - schemaBefore));
  });
  check("A6. a reserved name, a name not held, an OAuth set " +
        "on a SAML-only application, GNAP's three reserved names and the " +
        "GNAP set on an OAuth client are refused 400, recorded STS-REG-0206",
        function () {
    assert.ok(after - before >= 7, "STS-REG-0206 rows added: " +
              (after - before));
  });
  const gnapAttr = await postJson(API + "/applications/set-custom-claim", {
    application: "ac-gnap", set: "gnap_access_token", name: "department",
    attribute: "uid", type: "string" });
  const gnapDetail = await application("ac-gnap");
  check("A7. a directory-attribute row is accepted on the GNAP set, and the " +
        "GNAP client's page offers that set and not the OAuth ones",
        function () {
    assert.strictEqual(gnapAttr.status, 200, gnapAttr.raw.slice(0, 300));
    assert.deepStrictEqual(setsOf(gnapDetail).map(
      function (one) {
        return one.id;
      }), ["gnap_access_token"]);
  });

  await ok(API + "/applications/set", { application: "ac-web",
    attribute: "oauthAccessTokenTtlS", value: "120" },
    "set ac-web's access-token lifetime");
  const timed = await tokensFor("ac-web", "openid", ALICE);
  const timedClaims = decode(timed.access_token);
  const lifetimes = (await application("ac-web")).tokenLifetimes || {};
  check("A8. its access-token lifetime is the token's: expires_in 120 and " +
        "exp - iat 120, and the page says it is the application's",
        function () {
    assert.strictEqual(timed.expires_in, 120, JSON.stringify(timed));
    assert.strictEqual(timedClaims.exp - timedClaims.iat, 120);
    const rows = lifetimes.lifetimes || lifetimes.rows || [];
    const access = rows.filter(function (one) {
      return one.setting === "oauth2.accessTokenTtlS";
    })[0];
    const idTtl = rows.filter(function (one) {
      return one.setting === "oauth2.idTokenTtlS";
    })[0];
    assert.ok(access && access.value === 120 &&
              access.source === "application", JSON.stringify(rows));
    assert.ok(idTtl && idTtl.source === "realm" &&
              idTtl.value === idTtl.realmValue, JSON.stringify(rows));
  });
  await ok(API + "/claims/replace", { set: "access_token", claims: [] },
           "emptied the realm's access-token claims");
  log.debug("Leaving sectionA().");
}

// =========================================================================
// B. application_claim_selections.js
// =========================================================================
async function sectionB() {
  log.debug("Entering sectionB().");
  log.info("=== B. an application's own directory-attribute selection ===");
  await ok(API + "/claims/attributes", { set: "id_token",
    attributes: ["mail"] }, "ticked mail for the realm's ID Tokens");
  const first = await idFor("ac-web", "openid email profile");
  await ok(API + "/applications/set-claim-attributes", {
    application: "ac-web", set: "id_token", attributes: ["givenName"] },
    "ac-web selects givenName");
  const own = await idFor("ac-web", "openid email profile");
  const other = await idFor("ac-other", "openid email profile");
  check("B1. the realm's selection reaches the client first", function () {
    assert.strictEqual(first.email, ALICE + "@appclaims.example.test",
                       JSON.stringify(first));
  });
  check("B2. its own selection REPLACES the realm's: givenName in, mail out",
        function () {
    assert.strictEqual(own.given_name, "Alice", JSON.stringify(own));
    assert.strictEqual(own.email, undefined);
  });
  check("B3. another client still gets the realm's selection", function () {
    assert.ok(other.email && other.given_name === undefined,
              JSON.stringify(other));
  });
  await ok(API + "/applications/set-claim-attributes", {
    application: "ac-web", set: "id_token", attributes: [""] },
    "ac-web selects nothing");
  const none = await idFor("ac-web", "openid email profile");
  check("B4. an empty selection carries no attribute", function () {
    assert.ok(none.email === undefined && none.given_name === undefined,
              JSON.stringify(none));
  });
  const back = await ok(API + "/applications/inherit-claim-attributes", {
    application: "ac-web", set: "id_token" }, "ac-web inherits again");
  const inherited = await idFor("ac-web", "openid email profile");
  check("B5. inheriting brings the realm's selection back", function () {
    assert.strictEqual(back.inherited, true, JSON.stringify(back));
    assert.ok(inherited.email, JSON.stringify(inherited));
  });

  const before = await codeCount(API, "STS-REG-0215");
  const schemaBefore = await codeCount(API, "STS-API-0009");
  await refused(API + "/applications/set-claim-attributes", {
    application: "ac-web", set: "id_token", attributes: ["nope"] },
    "an unknown attribute");
  await refused(API + "/applications/set-claim-attributes", {
    application: "ac-web", set: "nope", attributes: [] }, "an unknown set");
  await refused(API + "/applications/set-claim-attributes", {
    application: "ac-sp", set: "id_token", attributes: ["mail"] },
    "a family the application is not declared for");
  await refused(API + "/applications/set", { application: "ac-web",
    attribute: "oauthClaimAttributesIdToken", value: "\"mail\"" },
    "a stored value that is not a list");
  const after = await codesSettle(API, "STS-REG-0215", before + 3);
  const schemaAfter = await codesSettle(API, "STS-API-0009",
                                        schemaBefore + 1);
  check("B6. an unknown attribute, an undeclared family and a value that " +
        "is not a list are refused, recorded STS-REG-0215; an unknown set " +
        "is the request schema's (STS-API-0009)", function () {
    assert.ok(after - before >= 3, "STS-REG-0215 rows added: " +
              (after - before));
    assert.ok(schemaAfter - schemaBefore >= 1, "STS-API-0009 rows added: " +
              (schemaAfter - schemaBefore));
  });

  await ok(API + "/applications/set-claim-attributes", {
    application: "ac-web", set: "access_token", attributes: ["sn"] },
    "ac-web selects sn for its access tokens");
  const together = await ok(API + "/applications/set-claim-selections", {
    application: "ac-web", access_token: ["sn"], id_token: ["mail"],
    userinfo: ["givenName"] }, "saved the OAuth table");
  const bySet = {};
  (together.sets || []).forEach(function (one) {
    bySet[one.set] = one;
  });
  check("B7. one Save writes only the changed column: an untouched " +
        "inherited column keeps inheriting, an untouched own one is left, a " +
        "changed one becomes the application's own", function () {
    assert.ok(bySet.access_token && bySet.access_token.changed === false &&
              bySet.access_token.inherited === false,
              JSON.stringify(together));
    assert.ok(bySet.id_token && bySet.id_token.changed === false &&
              bySet.id_token.inherited === true);
    assert.ok(bySet.userinfo && bySet.userinfo.changed === true);
  });
  const emptied = await ok(API + "/applications/set-claim-selections", {
    application: "ac-web", userinfo: [""] }, "emptied the userinfo column");
  check("B8. a column with nothing ticked holds an empty selection; a " +
        "column not sent is not touched", function () {
    assert.strictEqual(emptied.sets.length, 1, JSON.stringify(emptied));
    assert.strictEqual(emptied.sets[0].changed, true);
  });
  const bad = await refused(API + "/applications/set-claim-selections", {
    application: "ac-web", id_token: ["givenName"],
    access_token: ["no-such-attribute"] }, "one bad attribute");
  const still = await idFor("ac-web", "openid email profile");
  check("B9. an attribute the catalogue does not hold refuses the whole " +
        "Save, and no column is written", function () {
    assert.ok(bad.ok === false);
    assert.ok(still.email && still.given_name === undefined,
              JSON.stringify(still));
  });
  await refused(API + "/applications/set-claim-selections", {
    application: "ac-sp", id_token: ["mail"] },
    "an application not declared for OAuth");
  const last = await codesSettle(API, "STS-REG-0215", after + 2);
  check("B10. both table refusals are recorded STS-REG-0215", function () {
    assert.ok(last - after >= 2, "rows added: " + (last - after));
  });
  await ok(API + "/claims/attributes", { set: "id_token", attributes: [] },
           "unticked the realm's ID Token attributes");
  log.debug("Leaving sectionB().");
}

// =========================================================================
// C. custom_attribute_claims.js
// =========================================================================
async function sectionC() {
  log.debug("Entering sectionC().");
  log.info("=== C. the realm's custom attributes as claims ===");
  const catalogue = ((await send(API + "/claims")).body || {})
    .attributeCatalogue || [];
  const custom = catalogue.filter(function (row) {
    return row.custom;
  });
  check("C1. the catalogue carries the three, marked custom, last, never " +
        "generated", function () {
    assert.deepStrictEqual(custom.map(function (row) {
      return row.ldap + "=" + row.claim;
    }).sort(), ["badgeIds=badgeIds", "costCentreCode=costCentreCode",
                "hiredOn=hiredOn"]);
    assert.strictEqual(catalogue.indexOf(custom[0]), catalogue.length - 3);
    assert.ok(custom.every(function (row) {
      return row.generated === false;
    }));
  });
  const elsewhere = ((await send(base + "/realm/" + OTHER_REALM +
                                 "/admin-api/claims")).body || {})
    .attributeCatalogue || [];
  check("C2. another realm's catalogue offers none of them", function () {
    assert.ok(elsewhere.length > 5);
    assert.ok(elsewhere.every(function (row) {
      return !row.custom;
    }));
  });
  await refused(base + "/realm/" + OTHER_REALM +
                "/admin-api/claims/attributes", { set: "access_token",
    attributes: ["costCentreCode"] }, "this realm's name in another");
  await ok(API + "/claims/attributes", { set: "access_token",
    attributes: ["costCentreCode", "badgeIds", "hiredOn", "mail"] },
    "ticked the three and mail for access tokens");
  await refused(API + "/claims/attributes", { set: "access_token",
    attributes: ["costCentreCode", "nope"] }, "an unknown name");
  const ticked = ((await send(API + "/claims")).body || {})
    .attributeCatalogue || [];
  check("C3. an unknown name refuses the whole selection: the one before " +
        "it stands", function () {
    const row = ticked.filter(function (one) {
      return one.ldap === "hiredOn";
    })[0];
    assert.ok(row && row.sets.access_token === true, JSON.stringify(row));
  });
  const token = await accessFor("ac-other", "openid");
  check("C4. an access token carries each under its name, typed by its " +
        "syntax: a number, every value, a date as YYYY-MM-DD", function () {
    assert.strictEqual(token.costCentreCode, 42, JSON.stringify(token));
    assert.deepStrictEqual(token.badgeIds, ["b-1", "b-2"]);
    assert.strictEqual(token.hiredOn, "2026-01-31");
  });
  const bare = await accessFor("ac-other", "openid", BARE);
  check("C5. a person without a value carries no claim, and nothing is " +
        "invented", function () {
    assert.ok(!("costCentreCode" in bare) && !("badgeIds" in bare) &&
              !("hiredOn" in bare), JSON.stringify(bare));
  });
  const t = await tokensFor("ac-other", "openid", ALICE, {
    claims: JSON.stringify({ userinfo: { hiredOn: null } }) });
  const info = await send(RB + "/oauth2/userinfo", { headers: {
    Authorization: "Bearer " + t.access_token } });
  check("C6. OpenID Connect Core 5.5: a client may ask for one by name at " +
        "UserInfo", function () {
    assert.strictEqual(info.status, 200, info.raw.slice(0, 300));
    assert.strictEqual(info.body.hiredOn, "2026-01-31", info.raw);
  });
  await ok(API + "/claims/attributes", { set: "access_token",
    attributes: [] }, "unticked the realm's access-token attributes");
  log.debug("Leaving sectionC().");
}

// =========================================================================
// D. permission_claims.js
// =========================================================================
async function sectionD() {
  log.debug("Entering sectionD().");
  log.info("=== D. claims mapped to a resource server's own scopes ===");
  await ok(API + "/applications/create", { identifier: "pc-api",
    name: "pc-api", kind: "oauth2-resource-server", protocols: ["oauth2"],
    fields: { oauthPermissionBaseUri: HR,
              oauthPermission: ["hr.read|Read HR data", "hr.admin"] } },
    "registered the resource server");
  await client("pc-web", ["oauth2", "oidc"], {
    oauthAllowedScope: ["openid", "profile", "email", HR + "hr.read",
                        HR + "hr.admin"],
    oauthDelegatedPermission: [HR + "hr.read", HR + "hr.admin"] });
  for (const one of [HR + "hr.read", HR + "hr.admin"]) {
    await ok(API + "/consent/grant-global-consent",
             { client: "pc-web", scope: one }, "consented " + one);
  }
  const before = await codeCount(API, "STS-REG-0344");
  await refused(API + "/applications/set-permission-claims", {
    application: "pc-api", permission: "hr.write", attributes: ["mail"] },
    "a permission it does not expose");
  await refused(API + "/applications/set-permission-claims", {
    application: "pc-api", permission: "hr.read", attributes: ["nope"] },
    "an unknown attribute");
  await refused(API + "/applications/set-permission-claims", {
    application: "ac-sp", permission: "hr.read", attributes: [] },
    "an application not declared for OAuth");
  await refused(API + "/applications/set", { application: "pc-api",
    attribute: "oauthPermissionClaims", value: "[\"mail\"]" },
    "a value that is not an object");
  await refused(API + "/applications/set", { application: "pc-api",
    attribute: "oauthPermissionClaims", value: "{\"hr.write\":[\"mail\"]}" },
    "an object naming another permission");
  const after = await codesSettle(API, "STS-REG-0344", before + 5);
  check("D1. a permission it does not expose, an unknown attribute, an " +
        "application not declared for OAuth, a value that is not an object " +
        "and one naming another permission are refused, STS-REG-0344",
        function () {
    assert.ok(after - before >= 5, "rows added: " + (after - before));
  });
  await ok(API + "/applications/set-permission-claims", {
    application: "pc-api", permission: "hr.read",
    attributes: ["mail", "givenName"] }, "mapped hr.read");
  const granted = await accessFor("pc-web", "openid " + HR + "hr.read");
  check("D2. hr.read granted: its email and given_name are in — without " +
        "the email or profile scope — and nothing it does not map",
        function () {
    // An element of aud EQUAL to the audience, not a string search.
    assert.ok([].concat(granted.aud).some(function (one) {
      return one === HR;
    }), JSON.stringify(granted));
    assert.strictEqual(granted.email, ALICE + "@appclaims.example.test");
    assert.strictEqual(granted.given_name, "Alice");
    assert.strictEqual(granted.name, undefined);
  });
  const adminTok = await accessFor("pc-web", "openid " + HR + "hr.admin");
  check("D3. hr.admin granted, which maps nothing: none", function () {
    assert.ok(adminTok.email === undefined &&
              adminTok.given_name === undefined, JSON.stringify(adminTok));
  });
  await ok(API + "/applications/clear-permission-claims", {
    application: "pc-api", permission: "hr.read" }, "cleared hr.read");
  const cleared = await accessFor("pc-web", "openid " + HR + "hr.read");
  check("D4. a cleared mapping carries none", function () {
    assert.strictEqual(cleared.email, undefined, JSON.stringify(cleared));
  });
  await ok(API + "/applications/set-permission-claims", {
    application: "pc-api", permission: "hr.admin", attributes: ["mail"] },
    "mapped hr.admin");
  await ok(API + "/applications/remove", { application: "pc-api",
    attribute: "oauthPermission", value: "hr.admin" },
    "stopped exposing hr.admin");
  const state = ((await application("pc-api")).page || {})
    .permissionClaims || {};
  check("D5. a mapping for a permission it no longer exposes is listed " +
        "stale", function () {
    assert.deepStrictEqual(state.stale, ["hr.admin"],
                           JSON.stringify(state).slice(0, 400));
    assert.deepStrictEqual((state.permissions || []).map(function (p) {
      return p.name;
    }), ["hr.read"]);
  });
  log.debug("Leaving sectionD().");
}

// =========================================================================
// E. scope_claims.js
// =========================================================================
async function sectionE() {
  log.debug("Entering sectionE().");
  log.info("=== E. which claims a scope covers ===");
  await ok(API + "/applications/create", { identifier: "sc-api",
    name: "sc-api", kind: "oauth2-resource-server", protocols: ["oauth2"],
    fields: { oauthAudience: [RS] } }, "registered a resource server");
  const nothing = await accessFor("ac-other", "openid profile email",
                                  ALICE, { resource: RS });
  check("E1. a resource server that declares nothing gets no section 5.4 " +
        "claim, preferred_username included; username stays", function () {
    assert.ok([].concat(nothing.aud).some(function (one) {
      return one === RS;
    }), JSON.stringify(nothing));
    assert.ok(nothing.preferred_username === undefined &&
              nothing.name === undefined && nothing.email === undefined,
              JSON.stringify(nothing));
    assert.strictEqual(nothing.username, ALICE);
  });
  for (const claim of ["email", "name", "preferred_username"]) {
    await ok(API + "/applications/add", { application: "sc-api",
      attribute: "oauthAccessTokenClaim", value: claim },
      "declared " + claim);
  }
  const profileOnly = await accessFor("ac-other", "openid profile", ALICE,
                                      { resource: RS });
  check("E2. declared and granted: name and preferred_username in; email " +
        "declared but not granted, out", function () {
    assert.ok(profileOnly.name && profileOnly.preferred_username === ALICE,
              JSON.stringify(profileOnly));
    assert.strictEqual(profileOnly.email, undefined);
  });
  const withEmail = await accessFor("ac-other", "openid profile email",
                                    ALICE, { resource: RS });
  check("E3. email granted: in, though the OpenID Connect scopes are not on " +
        "the token's scope claim", function () {
    // A resource server's declared section 5.4 claims carry the entry's
    // own values, even in development (until fix/node-defects-1114 they
    // carried the invented persona: `name` "<user> (mock)", an `email` at
    // the realm's domain).
    assert.strictEqual(withEmail.email, ALICE + "@appclaims.example.test",
                       JSON.stringify(withEmail));
    assert.ok(!/\(mock\)/.test(String(withEmail.name)),
              JSON.stringify(withEmail));
    assert.ok(String(withEmail.scope || "").indexOf("email") < 0,
              String(withEmail.scope));
  });
  const before = await codeCount(API, "STS-REG-0203");
  await refused(API + "/applications/add", { application: "sc-api",
    attribute: "oauthAccessTokenClaim", value: "groups" },
    "a claim outside section 5.4");
  await refused(API + "/applications/set", { application: "sc-api",
    attribute: "oauthAccessTokenClaimsCombine", value: "everything" },
    "an unknown combining mode");
  const after = await codesSettle(API, "STS-REG-0203", before + 2);
  check("E4. a claim outside section 5.4 and an unknown mode are refused, " +
        "STS-REG-0203", function () {
    assert.ok(after - before >= 2, "rows added: " + (after - before));
  });
  await ok(API + "/claims/replace", { set: "id_token", claims: [
    { name: "email", value: "set@appclaims.example.test" },
    { name: "site", value: "sc" }] }, "set the realm's ID Token claims");
  const noEmail = await idFor("ac-other", "openid");
  const yesEmail = await idFor("ac-other", "openid email");
  check("E5. a configured email reaches the ID Token only with email " +
        "granted; a claim no scope covers always", function () {
    assert.strictEqual(noEmail.email, undefined, JSON.stringify(noEmail));
    assert.strictEqual(noEmail.site, "sc");
    assert.strictEqual(yesEmail.email, "set@appclaims.example.test",
                       JSON.stringify(yesEmail));
  });
  await ok(API + "/claims/replace", { set: "id_token", claims: [] },
           "emptied the realm's ID Token claims");
  log.debug("Leaving sectionE().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving application claims at " + RB);
  await setup();
  await sectionA();
  await sectionB();
  await sectionC();
  await sectionD();
  await sectionE();
  assert.ok(checks >= 35, "only " + checks + " checks ran; a section has " +
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
  for (const id of [REALM, OTHER_REALM]) {
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
