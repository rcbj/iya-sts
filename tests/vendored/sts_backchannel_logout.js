// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_backchannel_logout.js
//
// ---------------------------------------------------------------------------
// OPENID CONNECT BACK-CHANNEL LOGOUT 1.0, DELIVERED TO A RELYING PARTY THAT
// IS NOT THIS JOB (#293, WP3, 2026-10-13).
//
// `docs/configure-oidc-flows.md` gives the recipe for a client registered
// with `oauthBackchannelLogoutUri`, and no job received the Logout Token
// over the wire: `tests/backchannel_logout.js` drives it in process, and the
// OpenID conformance plan's own client in its lane. The relying party here
// is the test peer's `bcl` role (`tests/peer/peer_bcl.js`), which verifies
// the token as section 2.6 says a relying party must — the signature under
// the realm's published keys, `typ: logout+jwt`, `iss`, `aud`, `iat`, `jti`,
// the event, `sub` or `sid`, no `nonce`, no replay — and reports what it got.
//
//   1. THE DEVELOPMENT REALM: a person signs in through the code flow at a
//      client created through `/admin-api` with the peer's endpoint as its
//      `oauthBackchannelLogoutUri`; RP-initiated logout with the ID Token as
//      `id_token_hint` sends ONE Logout Token, which the peer accepts, naming
//      the ID Token's `sub` and `sid`; a second sign-in ended by the console's
//      global logout (`POST /admin-api/logout/global`) sends another, with a
//      new `sid`.
//   2. THE PRODUCT REALM: the same registration, the same sign-in and the
//      same sign-out — and NO token reaches the peer, because product mode
//      does not dial a back-channel address that resolves to a private
//      network (`mode.dialsInternalAddresses()`), which is where every test
//      stack keeps the peer. What is asserted is that refusal: the
//      `logout.backchannel` audit row carrying STS-OAUTH-0534, and nothing
//      recorded at the peer.
//
// THE PEER'S TLS IS VERIFIED where a directory is shared with the service:
// its CA is the realm's `federation.outboundCaFile` (TEST_PEER_CA_FILE, as
// `sts_provider_commands.js` names it). Where none is shared — a hand run
// against a service started elsewhere — the development realm turns
// `federation.outboundSkipTlsVerification` on instead, which development
// allows and logs on every request, and this job says so.
//
// Needs the test peer (`testPeer: true`); skipped with the reason without it.
//
// OWNED HERE (local: true).
// ---------------------------------------------------------------------------

const assert = require("assert");
const nodeCrypto = require("crypto");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const registry = require("./sts_applications.js");
const authnSignin = require("./authn_signin");
const testPeer = require("./test_peer.js");

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
var log = bunyan.createLogger({ name: "sts_backchannel_logout",
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
const DEV = "bcl-d-" + TAG;
const PROD = "bcl-p-" + TAG;
const PERSON = names.usernameFor("bcl-person");
const PASSWORD = "Bcl-" + nodeCrypto.randomBytes(9).toString("base64url") +
  "-Aa1!";
const SECRET = "bcl-secret-" + TAG + "-" +
  nodeCrypto.randomBytes(16).toString("hex");
const REDIRECT = "https://rp.bcl.example.test/cb";
const APP = "bcl-client-" + TAG;
const FLOOR = 7;

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

// The person signed in at APP through the code flow: the browser holding the
// sign-on session, and the ID Token.
async function signIn(realm) {
  log.debug("Entering signIn(). " + realm);
  const rb = realmBase(realm);
  const verifier = nodeCrypto.randomBytes(32).toString("base64url");
  const b = browser();
  let r = await b.go("GET", "/realm/" + realm + "/oauth2/authorize?" + form({
    response_type: "code", client_id: APP, redirect_uri: REDIRECT,
    scope: "openid", state: "st-" + TAG,
    nonce: "n-" + nodeCrypto.randomBytes(9).toString("base64url"),
    code_challenge: nodeCrypto.createHash("sha256").update(verifier)
      .digest("base64url"),
    code_challenge_method: "S256" }));
  assert.ok((r.status === 302 || r.status === 303) &&
            /\/authn\/login\?authn=/.test(r.location),
            "the authorization endpoint should send the browser to sign in; " +
            "it answered " + r.status + " " + r.location);
  r = await authnSignin.signInWithJar(rb, r.location,
    { action: "login", username: PERSON, password: PASSWORD }, b.jar);
  for (let hops = 0; hops < 6 && (r.status === 302 || r.status === 303) &&
       String(r.location).indexOf(REDIRECT) !== 0; hops++) {
    r = await b.go("GET", r.location);
  }
  const code = String(r.location).indexOf(REDIRECT) === 0
    ? new URL(r.location).searchParams.get("code") : "";
  assert.ok(code, "no code at the client: " + r.status + " " + r.location);
  const t = await call("POST", rb + "/oauth2/token",
    form({ grant_type: "authorization_code", code: code,
           redirect_uri: REDIRECT, code_verifier: verifier }),
    { "Content-Type": "application/x-www-form-urlencoded",
      Authorization: "Basic " + Buffer.from(APP + ":" + SECRET)
        .toString("base64") });
  assert.ok(t.status === 200 && t.json.id_token,
            "the token endpoint: " + t.status + " " + t.text.slice(0, 300));
  log.debug("Leaving signIn().");
  return { browser: b, idToken: t.json.id_token,
           claims: claimsOf(t.json.id_token) };
}

// RP-initiated logout with the ID Token as its hint, on the browser that
// signed in.
async function rpLogout(realm, session) {
  log.debug("Entering rpLogout(). " + realm);
  const r = await session.browser.go("GET", "/realm/" + realm +
    "/oauth2/logout?" + form({ id_token_hint: session.idToken,
                               client_id: APP }));
  log.debug("Leaving rpLogout(). " + r.status);
  return r;
}

async function setUpRealm(realm, view) {
  log.debug("Entering setUpRealm(). " + realm);
  const api = realmBase(realm) + "/admin-api";
  // RISK SCORING (#62) is off for sts_admin_client_policies.js's reason.
  await setting(realm, "risk.assessSignIns", false);
  await registry.ensurePerson(realmBase(realm), PERSON, PASSWORD);
  if (process.env.TEST_PEER_CA_FILE) {
    await setting(realm, "federation.outboundCaFile",
                  process.env.TEST_PEER_CA_FILE);
  } else if (realm === DEV) {
    log.info(DEV + ": no directory is shared with the service, so the " +
             "peer's certificate is NOT verified here " +
             "(federation.outboundSkipTlsVerification, development only).");
    await setting(realm, "federation.outboundSkipTlsVerification", true);
  }
  await ok(api + "/applications/create", {
    identifier: APP, name: "#293 back-channel logout " + TAG,
    protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: APP, oauthRedirectUri: [REDIRECT],
              oauthClientSecret: SECRET,
              oauthTokenEndpointAuthMethod: "client_secret_basic",
              oauthBackchannelLogoutUri: view.bcl.endpoint,
              oauthBackchannelLogoutSessionRequired: "TRUE" } },
    realm + ": created the client with the peer as its " +
    "backchannel_logout_uri");
  await ok(api + "/consent/grant-global-consent",
           { client: APP, scope: "openid" }, realm + ": consented openid");
  log.debug("Leaving setUpRealm().");
}

async function development() {
  log.debug("Entering development().");
  log.info("=== 1. " + DEV + ": Logout Tokens at the relying party ===");
  const tenantId = testPeer.tenantId("bcl-d");
  const view = await testPeer.tenant(tenantId, realmBase(DEV), base,
                                     { bcl: { clientId: APP } });
  await setUpRealm(DEV, view);
  const discovery = await call("GET", realmBase(DEV) +
                               "/.well-known/openid-configuration");
  check(DEV + ": discovery says back-channel logout is supported, with " +
        "sessions", function () {
    assert.strictEqual(discovery.json.backchannel_logout_supported, true);
    assert.strictEqual(discovery.json.backchannel_logout_session_supported,
                       true);
  });
  const first = await signIn(DEV);
  check(DEV + ": the ID Token carries a sid", function () {
    assert.ok(first.claims.sid, JSON.stringify(first.claims));
  });
  let since = await testPeer.mark(tenantId);
  await rpLogout(DEV, first);
  let got = await testPeer.waitFor(tenantId, "bcl", since, null, 15000);
  check(DEV + ": RP-initiated logout sends a Logout Token the relying " +
        "party ACCEPTS (signature, typ, iss, aud, iat, jti, the event, no " +
        "nonce)", function () {
    assert.ok(got, "nothing reached the peer");
    assert.strictEqual(got.ok, true, JSON.stringify(got).slice(0, 600));
    assert.strictEqual(got.signatureValid, true);
    assert.strictEqual(String(got.header.typ).toLowerCase(), "logout+jwt");
  });
  check(DEV + ": and it names the ID Token's sub and sid", function () {
    assert.strictEqual(got.claims.sub, first.claims.sub);
    assert.strictEqual(got.claims.sid, first.claims.sid);
  });
  await sleep(1500);
  const exactlyOne = await testPeer.received(tenantId, "bcl", since);
  check(DEV + ": exactly one token was sent for that sign-out", function () {
    assert.strictEqual(exactlyOne.events.length, 1,
                       JSON.stringify(exactlyOne.events).slice(0, 400));
  });
  const second = await signIn(DEV);
  since = await testPeer.mark(tenantId);
  await ok(realmBase(DEV) + "/admin-api/logout/global", { user: PERSON },
           DEV + ": the console's global logout of " + PERSON);
  got = await testPeer.waitFor(tenantId, "bcl", since, null, 15000);
  check(DEV + ": the console's global logout sends another, accepted, for " +
        "the new session", function () {
    assert.ok(got && got.ok === true, JSON.stringify(got).slice(0, 600));
    assert.strictEqual(got.claims.sid, second.claims.sid);
    assert.notStrictEqual(got.claims.sid, first.claims.sid);
  });
  log.debug("Leaving development().");
}

async function product() {
  log.debug("Entering product().");
  log.info("=== 2. " + PROD + ": product does not dial a private address ===");
  const tenantId = testPeer.tenantId("bcl-p");
  const view = await testPeer.tenant(tenantId, realmBase(PROD), base,
                                     { bcl: { clientId: APP } });
  await setUpRealm(PROD, view);
  const session = await signIn(PROD);
  const since = await testPeer.mark(tenantId);
  const before = await codeCount(PROD, "STS-OAUTH-0534");
  await rpLogout(PROD, session);
  let after = before;
  for (let i = 0; i < 40 && after <= before; i += 1) {
    await sleep(250);
    after = await codeCount(PROD, "STS-OAUTH-0534");
  }
  const got = await testPeer.received(tenantId, "bcl", since);
  check(PROD + ": the sign-out's Logout Token is not sent to the peer's " +
        "private address — the logout.backchannel row carries " +
        "STS-OAUTH-0534 — and nothing reaches the peer", function () {
    assert.ok(after > before, "no audit row carries STS-OAUTH-0534");
    assert.strictEqual(got.events.length, 0,
                       JSON.stringify(got.events).slice(0, 400));
  });
  log.debug("Leaving product().");
}

async function test() {
  log.debug("Entering test().");
  if (!testPeer.available()) {
    log.info(testPeer.skipReason("the relying party that receives Logout " +
                                 "Tokens"));
    log.info("Test completed successfully.");
    log.debug("Leaving test(). No peer.");
    return;
  }
  log.info("Driving back-channel logout at " + base);
  await ok(base + "/admin-api/realms/create",
           { id: PROD, domain: PROD + ".example.net", name: "#293 product",
             overrides: { "global.mode": "product" } },
           "created the product realm");
  await ok(base + "/admin-api/realms/create",
           { id: DEV, domain: DEV + ".example.net",
             name: "#293 development",
             overrides: { "global.mode": "development" } },
           "created the development realm");
  await development();
  await product();
  assert.ok(checks >= FLOOR, "only " + checks + " checks ran; a section has " +
            "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_backchannel_logout")
  .description("#293: OpenID Connect Back-Channel Logout delivered to the " +
    "test peer and verified there, in a development realm, and refused to " +
    "a private address in a product one.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
