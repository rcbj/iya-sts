// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_admin_client_policies.js
//
// ---------------------------------------------------------------------------
// CLIENTS AN ADMINISTRATOR MADE, AND WHAT THEIR ENTRIES DECIDE AT THE
// PROTOCOL DOORS (#293, WP1, 2026-10-13).
//
// `docs/configure-oauth2-grants.md` and `docs/configure-oidc-flows.md` give
// recipes for clients written through `/admin-api`, and three of them had no
// over-HTTP job: every job that ran the device flow registered its client by
// DCR, nothing set `oauthRequirePushedAuthorizationRequests` and then sent an
// authorization request, and nothing observed the product refusal of a
// response type that issues an access token from the authorization endpoint.
// This job does all three, in two throwaway realms it creates and leaves
// standing — one development, one product — so both halves are asserted
// whatever mode the service itself was started in:
//
//   1. THE DEVICE GRANT (RFC 8628) for a public client created through
//      `/admin-api/applications/create` with the grant in `oauthGrantType`:
//      codes issued, polling pending, the person approving on the static
//      portal, tokens issued to that client. A client whose declared grants
//      leave the device grant out is refused at the device endpoint,
//      unauthorized_client (STS-OAUTH-0692).
//   2. PAR REQUIRED PER CLIENT (RFC 9126 section 6): with
//      `oauthRequirePushedAuthorizationRequests` written TRUE through
//      `/admin-api/applications/set`, a plain authorization request is
//      refused here, never redirected (STS-OAUTH-0419); a pushed one signs
//      the person in and ends in a code the token endpoint redeems; written
//      FALSE again, the plain request reaches the sign-in screen.
//   3. `id_token token` AND `code token` (RFC 9700 section 2.1.2): the
//      product realm advertises neither, and refuses each as
//      unsupported_response_type (STS-OAUTH-0163, not the 0126 the docs
//      inferred — section 3 says why): on a page with a link to the client
//      when nobody is signed in, redirected to the client when somebody is.
//      In the development realm, with RFC 9700 mode off there, the same
//      request reaches the sign-in screen.
//
// Every refusal's code is read back from the realm's `/admin-api/audit` — a
// code is recorded and never sent.
//
// RISK SCORING (#62) IS OFF IN BOTH REALMS: this job's HTTP client is an
// automated one on a TLS stack the realm has never seen, which product's
// issuance policy answers by asking for a security key. What is asserted here
// is the client's entry, not the risk policy
// (`sts_development_only_settings.js` makes the same choice).
//
// OWNED HERE (local: true).
// ---------------------------------------------------------------------------

const assert = require("assert");
const nodeCrypto = require("crypto");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const registry = require("./sts_applications.js");
const authnSignin = require("./authn_signin");
const PORTAL_SIGNIN = require("./portal_signin.js");

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
var log = bunyan.createLogger({ name: "sts_admin_client_policies",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const TAG = STAMP.toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 12);
const DEV = "acp-d-" + TAG;
const PROD = "acp-p-" + TAG;
const PERSON = names.usernameFor("acp-person");
const PASSWORD = "Acp-" + nodeCrypto.randomBytes(9).toString("base64url") +
  "-Aa1!";
const SECRET = "acp-secret-" + TAG + "-0123456789abcdef";
const REDIRECT = "https://rp.acp.example.test/cb";
const DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";
const DEVICE_APP = "acp-device-" + TAG;
const NO_DEVICE_APP = "acp-nodevice-" + TAG;
const PAR_APP = "acp-par-" + TAG;
const TOKEN_TYPES_APP = "acp-types-" + TAG;
const FLOOR = 25;

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function realmBase(id) {
  log.debug("Entering realmBase().");
  log.debug("Leaving realmBase().");
  return base + "/realm/" + id;
}

function form(o) {
  log.debug("Entering form().");
  log.debug("Leaving form().");
  return new URLSearchParams(o).toString();
}

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

function claimsOf(jwt) {
  log.debug("Entering claimsOf().");
  const claims = JSON.parse(Buffer.from(String(jwt).split(".")[1],
                                        "base64url").toString("utf8"));
  log.debug("Leaving claimsOf().");
  return claims;
}

async function call(method, url, body, headers) {
  log.debug("Entering call(). " + method + " " + url);
  const r = await fetch(url, { method: method, redirect: "manual",
    headers: Object.assign({ "Content-Type": "application/json" },
                           headers || {}),
    body: body === undefined ? undefined :
          (typeof body === "string" ? body : JSON.stringify(body)) });
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
  return { status: r.status, json: json, text: text,
           location: r.headers.get("location") || "" };
}

async function formPost(url, fields, headers) {
  log.debug("Entering formPost().");
  log.debug("Leaving formPost().");
  return call("POST", url, form(fields), Object.assign(
    { "Content-Type": "application/x-www-form-urlencoded" }, headers || {}));
}

async function ok(url, body, what) {
  log.debug("Entering ok().");
  const r = await call("POST", url, body);
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
            what + ": " + r.status + " " + r.text.slice(0, 400));
  log.debug("Leaving ok().");
  return r.json;
}

async function setting(realm, key, value) {
  log.debug("Entering setting(). " + key);
  log.debug("Leaving setting().");
  return ok(realmBase(realm) + "/admin-api/config/set",
            { key: key, value: value }, "set " + key + " in " + realm);
}

function basicFor(clientId) {
  log.debug("Entering basicFor().");
  log.debug("Leaving basicFor().");
  return { Authorization: "Basic " + Buffer.from(
    encodeURIComponent(clientId) + ":" + encodeURIComponent(SECRET))
    .toString("base64") };
}

// How many of the realm's audit rows carry `code`.
async function codeCount(realm, code) {
  log.debug("Entering codeCount(). " + code);
  const r = await call("GET", realmBase(realm) +
                       "/admin-api/audit?per=500&code=" +
                       encodeURIComponent(code));
  const body = r.json && typeof r.json === "object" ? r.json : {};
  const rows = body.rows || body.events || [];
  log.debug("Leaving codeCount(). " + rows.length);
  return rows.length;
}

// Waits for a new audit row with `code` in `realm`: the row is written as the
// response finishes, so the read after it may need a moment.
async function newRowWith(realm, code, before) {
  log.debug("Entering newRowWith(). " + code);
  let after = before;
  for (let i = 0; i < 20 && after <= before; i += 1) {
    await sleep(150);
    after = await codeCount(realm, code);
  }
  log.debug("Leaving newRowWith(). " + before + " -> " + after);
  return after > before;
}

// The parameters of a redirect back to the client, from the query or, for a
// fragment response mode, the fragment.
function returnedParams(location) {
  log.debug("Entering returnedParams().");
  const u = new URL(location);
  const out = new URLSearchParams(u.search);
  new URLSearchParams(u.hash.replace(/^#/, "")).forEach(function (v, k) {
    out.set(k, v);
  });
  log.debug("Leaving returnedParams().");
  return out;
}

// One browser: a cookie jar and redirects left to the caller.
function browser() {
  log.debug("Entering browser().");
  const jar = {};
  const self = {
    jar: jar,
    async go(method, url) {
      log.debug("Entering go(). " + method + " " + url);
      const headers = {};
      const cookie = Object.keys(jar).map(function (k) {
        return k + "=" + jar[k];
      }).join("; ");
      if (cookie) {
        headers.cookie = cookie;
      }
      const absolute = /^https?:\/\//i.test(url) ? url : base + url;
      const r = await fetch(absolute, { method: method, redirect: "manual",
                                        headers: headers });
      const set = r.headers.getSetCookie ? r.headers.getSetCookie() : [];
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
      const text = await r.text();
      log.debug("Leaving go(). status=" + r.status);
      return { status: r.status, location: r.headers.get("location") || "",
               text: text };
    }
  };
  log.debug("Leaving browser().");
  return self;
}

function sentToSignIn(r) {
  log.debug("Entering sentToSignIn().");
  log.debug("Leaving sentToSignIn().");
  return (r.status === 302 || r.status === 303) &&
    /\/authn\/login\?authn=/.test(r.location);
}

// RFC 9700 section 2.1.1: a nonce is transaction-specific, and product
// refuses one an earlier redeemed code used.
function freshNonce() {
  log.debug("Entering freshNonce().");
  log.debug("Leaving freshNonce().");
  return "n-" + nodeCrypto.randomBytes(9).toString("base64url");
}

function pkce() {
  log.debug("Entering pkce().");
  const verifier = nodeCrypto.randomBytes(32).toString("base64url");
  const challenge = nodeCrypto.createHash("sha256").update(verifier)
    .digest("base64url");
  log.debug("Leaving pkce().");
  return { verifier: verifier, challenge: challenge };
}

async function setUp() {
  log.debug("Entering setUp().");
  log.info("=== 0. two throwaway realms: " + DEV + " and " + PROD + " ===");
  await ok(base + "/admin-api/realms/create",
           { id: PROD, domain: PROD + ".example.net", name: "#293 product",
             overrides: { "global.mode": "product" } },
           "created the product realm");
  await ok(base + "/admin-api/realms/create",
           { id: DEV, domain: DEV + ".example.net",
             name: "#293 development",
             overrides: { "global.mode": "development" } },
           "created the development realm");
  for (const realm of [PROD, DEV]) {
    const api = realmBase(realm) + "/admin-api";
    await setting(realm, "risk.assessSignIns", false);
    await setting(realm, "oauth2.deviceAuthorization", true);
    await setting(realm, "oauth2.deviceCodeIntervalS", 1);
    await registry.ensurePerson(realmBase(realm), PERSON, PASSWORD);
    // A realm's portal is reached at an address its seeded client does not
    // hold, and product teaches an entry none, so it is registered here as an
    // operator standing a realm up would (`sts_email_factor.js`'s reason).
    await ok(api + "/applications/add",
             { application: "sts-user-portal", attribute: "oauthRedirectUri",
               value: realmBase(realm) + "/portal/callback" },
             realm + ": registered the realm portal's callback");
    await ok(api + "/applications/create", {
      identifier: DEVICE_APP, name: "#293 device " + TAG,
      protocols: ["oauth2", "oidc"],
      fields: { oauthClientId: DEVICE_APP,
                oauthTokenEndpointAuthMethod: "none",
                oauthGrantType: [DEVICE_GRANT, "refresh_token"] } },
      realm + ": created the public device client");
    await ok(api + "/applications/create", {
      identifier: NO_DEVICE_APP, name: "#293 no device " + TAG,
      protocols: ["oauth2", "oidc"],
      fields: { oauthClientId: NO_DEVICE_APP, oauthRedirectUri: [REDIRECT],
                oauthClientSecret: SECRET,
                oauthTokenEndpointAuthMethod: "client_secret_post",
                oauthGrantType: ["authorization_code"] } },
      realm + ": created a client declaring only the code grant");
    for (const app of [PAR_APP, TOKEN_TYPES_APP]) {
      await ok(api + "/applications/create", {
        identifier: app, name: "#293 " + app,
        protocols: ["oauth2", "oidc"],
        fields: { oauthClientId: app, oauthRedirectUri: [REDIRECT],
                  oauthClientSecret: SECRET,
                  oauthTokenEndpointAuthMethod: "client_secret_basic" } },
        realm + ": created " + app);
      await ok(api + "/consent/grant-global-consent",
               { client: app, scope: "openid" },
               realm + ": consented openid on " + app);
    }
    await ok(api + "/consent/grant-global-consent",
             { client: DEVICE_APP, scope: "openid" },
             realm + ": consented openid on the device client");
  }
  log.debug("Leaving setUp().");
}

// RFC 8628 for a public client an administrator created.
async function theDeviceGrant(realm) {
  log.debug("Entering theDeviceGrant(). " + realm);
  log.info("=== 1. " + realm + ": the device grant ===");
  const rb = realmBase(realm);
  const started = await formPost(rb + "/oauth2/device_authorization",
                                 { client_id: DEVICE_APP, scope: "openid" });
  const codes = started.json || {};
  check(realm + ": the device endpoint issues codes to the client created " +
        "through /admin-api", function () {
    assert.strictEqual(started.status, 200, started.text.slice(0, 300));
    assert.ok(codes.device_code && codes.user_code, started.text);
    assert.strictEqual(codes.verification_uri, rb + "/portal/device");
  });
  const pending = await formPost(rb + "/oauth2/token", {
    grant_type: DEVICE_GRANT, client_id: DEVICE_APP,
    device_code: codes.device_code });
  check(realm + ": before approval the token endpoint answers " +
        "authorization_pending", function () {
    assert.strictEqual(pending.status, 400, pending.text.slice(0, 300));
    assert.strictEqual(pending.json && pending.json.error,
                       "authorization_pending", pending.text.slice(0, 300));
  });
  const portal = await PORTAL_SIGNIN.signInToThePortal(rb, PERSON, null,
                                                       { password: PASSWORD });
  const approved = await portal.act("/portal/device",
    { action: "approve", user_code: codes.user_code });
  check(realm + ": the person approves on the portal", function () {
    assert.ok(approved.status === 200 && approved.json && approved.json.ok,
              String(approved.text).slice(0, 300));
  });
  let t = null;
  for (let i = 0; i < 10; i += 1) {
    await sleep(1200);
    t = await formPost(rb + "/oauth2/token", {
      grant_type: DEVICE_GRANT, client_id: DEVICE_APP,
      device_code: codes.device_code });
    if (t.status === 200 || !(t.json && /pending|slow_down/.test(
      String(t.json.error)))) {
      break;
    }
  }
  check(realm + ": the device is issued tokens for that client", function () {
    assert.strictEqual(t.status, 200, t.text.slice(0, 300));
    assert.ok(t.json.access_token, t.text.slice(0, 300));
    assert.strictEqual(claimsOf(t.json.access_token).client_id, DEVICE_APP);
  });
  const before = await codeCount(realm, "STS-OAUTH-0692");
  const refused = await formPost(rb + "/oauth2/device_authorization",
    { client_id: NO_DEVICE_APP, client_secret: SECRET, scope: "openid" });
  const recorded = await newRowWith(realm, "STS-OAUTH-0692", before);
  check(realm + ": a client whose oauthGrantType leaves the device grant " +
        "out is refused unauthorized_client (STS-OAUTH-0692)", function () {
    assert.strictEqual(refused.status, 400, refused.text.slice(0, 300));
    assert.strictEqual(refused.json && refused.json.error,
                       "unauthorized_client", refused.text.slice(0, 300));
    assert.ok(recorded, "no audit row carries STS-OAUTH-0692");
  });
  log.debug("Leaving theDeviceGrant().");
}

// Signs PERSON in on a browser already sent to the sign-in screen and
// follows the flow to the client; answers the code.
async function signInToCode(realm, b, r) {
  log.debug("Entering signInToCode().");
  r = await authnSignin.signInWithJar(realmBase(realm), r.location,
    { action: "login", username: PERSON, password: PASSWORD }, b.jar);
  assert.ok(r.answer.view, "the sign-in screen: " + r.answer.status + " " +
            JSON.stringify(r.answer.json));
  for (let hops = 0; hops < 6 && (r.status === 302 || r.status === 303) &&
       String(r.location).indexOf(REDIRECT) !== 0; hops++) {
    r = await b.go("GET", r.location);
  }
  assert.ok(String(r.location).indexOf(REDIRECT) === 0,
            "the flow should end at the client; it answered " + r.status +
            " " + r.location + " " + String(r.text).slice(0, 300));
  const code = returnedParams(r.location).get("code");
  assert.ok(code, "no code at the client: " + r.location);
  log.debug("Leaving signInToCode().");
  return code;
}

// RFC 9126 section 6, set on one client's entry through /admin-api.
async function parPerClient(realm) {
  log.debug("Entering parPerClient(). " + realm);
  log.info("=== 2. " + realm + ": PAR required per client ===");
  const rb = realmBase(realm);
  const R = "/realm/" + realm;
  await ok(rb + "/admin-api/applications/set",
           { application: PAR_APP,
             attribute: "oauthRequirePushedAuthorizationRequests",
             value: "TRUE" }, realm + ": required PAR of " + PAR_APP);
  const plainParams = function (p) {
    return { response_type: "code", client_id: PAR_APP,
             redirect_uri: REDIRECT, scope: "openid", state: "st-" + TAG,
             nonce: freshNonce(), code_challenge: p.challenge,
             code_challenge_method: "S256" };
  };
  let p = pkce();
  const before = await codeCount(realm, "STS-OAUTH-0419");
  let b = browser();
  let r = await b.go("GET", R + "/oauth2/authorize?" +
                     form(plainParams(p)));
  const recorded = await newRowWith(realm, "STS-OAUTH-0419", before);
  check(realm + ": with the attribute TRUE a plain authorization request " +
        "is refused here, invalid_request, never redirected (STS-OAUTH-0419)",
        function () {
    assert.strictEqual(r.status, 400, r.status + " " + r.location);
    assert.ok(/invalid_request/.test(r.text), r.text.slice(0, 300));
    assert.ok(recorded, "no audit row carries STS-OAUTH-0419");
  });
  p = pkce();
  const pushed = await formPost(rb + "/oauth2/par", plainParams(p),
                                basicFor(PAR_APP));
  check(realm + ": the same request pushed to /oauth2/par is accepted",
        function () {
    assert.strictEqual(pushed.status, 201, pushed.text.slice(0, 300));
    assert.ok(/^urn:ietf:params:oauth:request_uri:/.test(
      pushed.json.request_uri), pushed.text.slice(0, 300));
  });
  b = browser();
  r = await b.go("GET", R + "/oauth2/authorize?" + form({
    client_id: PAR_APP, request_uri: pushed.json.request_uri }));
  check(realm + ": its request_uri sends the person to sign in",
        function () {
    assert.ok(sentToSignIn(r), r.status + " " + r.location + " " +
              r.text.slice(0, 300));
  });
  const code = await signInToCode(realm, b, r);
  const token = await formPost(rb + "/oauth2/token", {
    grant_type: "authorization_code", code: code, redirect_uri: REDIRECT,
    code_verifier: p.verifier }, basicFor(PAR_APP));
  check(realm + ": and the code is redeemed", function () {
    assert.strictEqual(token.status, 200, token.text.slice(0, 300));
    assert.ok(token.json.access_token && token.json.id_token,
              token.text.slice(0, 300));
  });
  await ok(rb + "/admin-api/applications/set",
           { application: PAR_APP,
             attribute: "oauthRequirePushedAuthorizationRequests",
             value: "FALSE" }, realm + ": stopped requiring PAR");
  b = browser();
  r = await b.go("GET", R + "/oauth2/authorize?" +
                 form(plainParams(pkce())));
  check(realm + ": written FALSE again, the plain request reaches the " +
        "sign-in screen", function () {
    assert.ok(sentToSignIn(r), r.status + " " + r.location + " " +
              r.text.slice(0, 300));
  });
  log.debug("Leaving parPerClient().");
}

// RFC 9700 section 2.1.2: no access token from the authorization endpoint.
//
// WHAT REFUSES IT IN PRODUCT IS THE METADATA, NOT THE BCP CHECK (found by
// this job's first run). RFC 9700 mode takes every token-bearing type out
// of `response_types_supported`, and the authorization endpoint refuses a
// type its own metadata does not advertise (STS-OAUTH-0163) before
// `oauth2_bcp.js`'s section 2.1.2 check (STS-OAUTH-0126) is reached. The
// error the client is owed is the same, unsupported_response_type; how it
// is delivered depends on the browser: with nobody signed in it is SHOWN
// on a page carrying a link to the client (RFC 9700 section 4.11.2: no
// redirect before the user is authenticated), and on a signed-in browser
// it is redirected.
function authorizeTokenType(type) {
  log.debug("Entering authorizeTokenType().");
  log.debug("Leaving authorizeTokenType().");
  return "/realm/" + PROD + "/oauth2/authorize?" +
    form({ response_type: type, client_id: TOKEN_TYPES_APP,
           redirect_uri: REDIRECT, scope: "openid", state: "st-" + TAG,
           nonce: freshNonce() });
}

function assertRefusalAtClient(location) {
  log.debug("Entering assertRefusalAtClient().");
  assert.ok(location.indexOf(REDIRECT) === 0, location);
  const back = returnedParams(location);
  assert.strictEqual(back.get("error"), "unsupported_response_type",
                     location);
  assert.strictEqual(back.get("state"), "st-" + TAG, location);
  assert.ok(!back.get("access_token") && !back.get("code") &&
            !back.get("id_token"), location);
  log.debug("Leaving assertRefusalAtClient().");
}

async function tokenBearingTypes() {
  log.debug("Entering tokenBearingTypes().");
  log.info("=== 3. id_token token and code token ===");
  const metadata = await call("GET", realmBase(PROD) +
                              "/.well-known/openid-configuration");
  check("product: the realm's metadata advertises no response type that " +
        "issues an access token", function () {
    assert.strictEqual(metadata.status, 200, metadata.text.slice(0, 200));
    const types = metadata.json.response_types_supported || [];
    assert.ok(types.length > 0, JSON.stringify(types));
    types.forEach(function (one) {
      assert.ok(String(one).split(" ").indexOf("token") < 0,
                "advertised: " + JSON.stringify(types));
    });
  });
  // A browser signed in to the product realm, for the redirected half.
  const signedIn = browser();
  const p = pkce();
  let r = await signedIn.go("GET", "/realm/" + PROD + "/oauth2/authorize?" +
    form({ response_type: "code", client_id: PAR_APP,
           redirect_uri: REDIRECT, scope: "openid", state: "st-" + TAG,
           nonce: freshNonce(), code_challenge: p.challenge,
           code_challenge_method: "S256" }));
  assert.ok(sentToSignIn(r), "signing in for section 3: " + r.status + " " +
            r.location);
  await signInToCode(PROD, signedIn, r);
  for (const type of ["id_token token", "code token"]) {
    let before = await codeCount(PROD, "STS-OAUTH-0163");
    r = await browser().go("GET", authorizeTokenType(type));
    let recorded = await newRowWith(PROD, "STS-OAUTH-0163", before);
    const found = r.text.match(
      /href="(https:\/\/rp\.acp\.example\.test\/cb[^"]*)"/);
    const link = found ? found[1] : "";
    check("product, nobody signed in: response_type=" + type + " is " +
          "refused on a page, unsupported_response_type, its link to the " +
          "client carrying the error (STS-OAUTH-0163)", function () {
      assert.strictEqual(r.status, 400, r.status + " " + r.location);
      assert.ok(/unsupported_response_type/.test(r.text),
                r.text.slice(0, 300));
      assertRefusalAtClient(link.replace(/&amp;/g, "&"));
      assert.ok(recorded, "no audit row carries STS-OAUTH-0163");
    });
    before = await codeCount(PROD, "STS-OAUTH-0163");
    r = await signedIn.go("GET", authorizeTokenType(type));
    recorded = await newRowWith(PROD, "STS-OAUTH-0163", before);
    check("product, signed in: response_type=" + type + " is redirected " +
          "to the client as unsupported_response_type, with no token",
          function () {
      assert.ok(r.status === 302 || r.status === 303,
                r.status + " " + r.text.slice(0, 300));
      assertRefusalAtClient(r.location);
      assert.ok(recorded, "no audit row carries STS-OAUTH-0163");
    });
  }
  const report = await call("GET", realmBase(DEV) + "/oauth2/rfc9700");
  const devStrict = !!(report.json && report.json.enabled);
  check("development: the realm reports RFC 9700 mode " +
        (devStrict ? "ON (set for the whole service)" : "off"), function () {
    assert.strictEqual(report.status, 200, report.text.slice(0, 200));
  });
  r = await browser().go("GET", "/realm/" + DEV + "/oauth2/authorize?" +
    form({ response_type: "id_token token", client_id: TOKEN_TYPES_APP,
           redirect_uri: REDIRECT, scope: "openid", state: "st-" + TAG,
           nonce: freshNonce() }));
  if (devStrict) {
    // A stack that turns RFC 9700 mode on for the whole service turns it on
    // in this realm too; then the refusal is what holds.
    check("development, RFC 9700 mode on: the same refusal", function () {
      assert.ok(/unsupported_response_type/.test(r.text + r.location),
                r.status + " " + r.location);
    });
  } else {
    check("development: response_type=id_token token reaches the sign-in " +
          "screen", function () {
      assert.ok(sentToSignIn(r), r.status + " " + r.location + " " +
                r.text.slice(0, 300));
    });
  }
  log.debug("Leaving tokenBearingTypes().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving clients created through /admin-api at " + base);
  await setUp();
  for (const realm of [PROD, DEV]) {
    await theDeviceGrant(realm);
    await parPerClient(realm);
  }
  await tokenBearingTypes();
  assert.ok(checks >= FLOOR, "only " + checks + " checks ran; a section has " +
            "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_admin_client_policies")
  .description("#293: the device grant, PAR required per client and the " +
    "token-bearing response types, for clients created through /admin-api, " +
    "in a development and a product realm.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
