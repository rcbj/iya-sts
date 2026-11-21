// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_account_api.js
//
// ---------------------------------------------------------------------------
// `/account-api`, THE USER PORTAL'S ONLY DOOR, OVER THE WIRE (#568).
//
// D12 (#444): carries over `tests/account_api.js`, which ran the stack in a
// child process and signed somebody in as the static portal does. Here the
// person is signed in the same way (`portal_signin.js`: the public client
// `sts-user-portal`, PKCE, a DPoP-bound token for the realm's
// `/account-api`) in a throwaway realm, and then:
//
//   1. THE TABLE: `GET /account-api` with no token lists the operations,
//      each id unique; the public OpenAPI document documents exactly them;
//   2. THE TOKEN'S PERSON: `GET /account-api/me` names who signed in;
//   3. THE GATE: no token (401 with a DPoP challenge), the token as Bearer,
//      the token with no proof and a token this realm did not sign are each
//      refused 401, STS-ACCOUNT-0001, 0010 and 0002 recorded, none sent;
//   4. THE BODY: a field the operation does not take is refused 400 and
//      changes nothing; the same body without it changes the language;
//      `text/plain; x=json` and a form body are refused 415 at an operation
//      that takes no token; `application/json; charset=utf-8` is JSON.
//   5. A DEVICE-GRANT CLI: the person approves the requested Account API
//      resource on the portal; its DPoP-bound token names that audience and
//      issues an SSH certificate through the same API.
//
// NOT carried, and why: every page the portal bundle draws having the GET
// that mirrors it, every page drawing in the person's language and every
// form field being one its operation takes (1d, 2b–2d) read the browser
// bundle's tables and renderers (class (d)); "a passkey another person holds
// cannot be removed by naming its id" (4) needs a passkey enrolled for the
// other person, which only a console administrator's person-bound token can
// do over the wire (`sts_passkey_bulk_enrolment.js`'s arrangement) — owed,
// with the passkey family; the codes being registered (3e) is the table's
// (d).
//
// OWNED HERE (local: true): this repository's account API.
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
var log = bunyan.createLogger({ name: "sts_account_api",
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

function sshPublicKey() {
  log.debug("Entering sshPublicKey().");
  const pair = crypto.generateKeyPairSync("ed25519");
  const algorithm = Buffer.from("ssh-ed25519");
  const publicBytes = pair.publicKey.export({
    format: "der", type: "spki"
  }).subarray(-32);
  const algorithmLength = Buffer.alloc(4);
  const keyLength = Buffer.alloc(4);
  algorithmLength.writeUInt32BE(algorithm.length);
  keyLength.writeUInt32BE(publicBytes.length);
  const blob = Buffer.concat([
    algorithmLength, algorithm, keyLength, publicBytes
  ]).toString("base64");
  log.debug("Leaving sshPublicKey().");
  return "ssh-ed25519 " + blob + " account-api-test";
}

function deviceDpopKey() {
  log.debug("Entering deviceDpopKey().");
  const pair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = pair.publicKey.export({ format: "jwk" });
  const publicJwk = { kty: "EC", crv: jwk.crv, x: jwk.x, y: jwk.y };
  const thumbprint = JSON.stringify({ crv: publicJwk.crv,
    kty: publicJwk.kty, x: publicJwk.x, y: publicJwk.y });
  log.debug("Leaving deviceDpopKey().");
  return { privateKey: pair.privateKey, jwk: publicJwk,
    jkt: crypto.createHash("sha256").update(thumbprint)
      .digest("base64url") };
}

function deviceDpopProof(key, method, url, extra) {
  log.debug("Entering deviceDpopProof(). " + method + " " + url);
  const header = { typ: "dpop+jwt", alg: "ES256", jwk: key.jwk };
  const claims = Object.assign({ jti: crypto.randomBytes(16)
    .toString("base64url"), htm: method.toUpperCase(), htu: url,
    iat: Math.floor(Date.now() / 1000) }, extra || {});
  const input = Buffer.from(JSON.stringify(header)).toString("base64url") +
    "." + Buffer.from(JSON.stringify(claims)).toString("base64url");
  const signature = crypto.sign("sha256", Buffer.from(input, "ascii"),
    { key: key.privateKey, dsaEncoding: "ieee-p1363" });
  log.debug("Leaving deviceDpopProof().");
  return input + "." + signature.toString("base64url");
}

function jwtPayload(token) {
  log.debug("Entering jwtPayload().");
  const payload = JSON.parse(Buffer.from(String(token).split(".")[1],
    "base64url").toString("utf8"));
  log.debug("Leaving jwtPayload().");
  return payload;
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

const portal = require("./portal_signin.js");

const REALM = "aapi-" + STAMP;
const PW = "Q7v#2mL9@xB4sZ";

async function test() {
  log.debug("Entering test().");
  const rb = await makeRealm(REALM, null);
  await realmSet(REALM, "risk.assessSignIns", false);
  const mallory = ("aam" + STAMP).slice(0, 30);
  await ok(rb + "/admin-api/users/create", { username: mallory,
    invent: false, attributes: { cn: "Aapi " + mallory, sn: mallory,
      givenName: "Aapi", mail: mallory + "@example.test" },
    credential: "password", password: PW }, "created " + mallory);
  const m = await portal.signInToThePortal(rb, mallory, log,
                                           { password: PW });
  check("0. the person signs in as the static portal does", function () {
    assert.ok(m && m.token, "no token");
  });

  log.info("=== 1. the table ===");
  const index = await portal.nobody(rb, "GET", "/account-api");
  const ops = (index.json && index.json.operations) || [];
  const ids = ops.map(function (op) {
    return op.operationId;
  });
  check("1a. GET /account-api, with no token, lists the operations",
        function () {
    assert.strictEqual(index.status, 200, index.text.slice(0, 200));
    assert.ok(ops.length > 40, String(ops.length));
  });
  check("1b. every operation id is unique", function () {
    assert.strictEqual(ids.length, new Set(ids).size, ids.join(","));
  });
  const doc = await portal.nobody(rb, "GET", "/account-api/openapi.json");
  let documented = 0;
  Object.keys((doc.json && doc.json.paths) || {}).forEach(function (p) {
    documented += Object.keys(doc.json.paths[p]).filter(function (verb) {
      return /^(get|post|put|patch|delete)$/.test(verb);
    }).length;
  });
  check("1c. the OpenAPI document, public, documents exactly the table's " +
        "operations", function () {
    assert.strictEqual(doc.status, 200);
    assert.strictEqual(documented, ops.length,
                       documented + " vs " + ops.length);
  });

  log.info("=== 2. the token's person ===");
  const me = await m.api("GET", "/account-api/me");
  check("2a. GET /account-api/me names the token's person", function () {
    assert.strictEqual(me.status, 200, String(me.text).slice(0, 200));
    assert.strictEqual(me.json.user.username, mallory);
  });

  log.info("=== 3. the gate ===");
  const codes = ["STS-ACCOUNT-0001", "STS-ACCOUNT-0002", "STS-ACCOUNT-0010"];
  const before = {};
  for (const code of codes) {
    before[code] = await codeCount(rb, code);
  }
  const bare = await send(rb + "/account-api/me");
  const asBearer = await send(rb + "/account-api/me",
    { headers: { authorization: "Bearer " + m.token } });
  const noProof = await send(rb + "/account-api/me",
    { headers: { authorization: "DPoP " + m.token } });
  const forged = await send(rb + "/account-api/me", { headers: {
    authorization: "DPoP eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0." } });
  check("3a. no token: 401 with a DPoP challenge", function () {
    assert.strictEqual(bare.status, 401);
    assert.ok(/^DPoP /.test(String(bare.headers.get("www-authenticate") ||
                                   "")), bare.headers.get("www-authenticate"));
  });
  check("3b–3d. the token presented as Bearer, the token with no proof and " +
        "a token this realm did not sign are each refused 401, code-free",
        function () {
    [asBearer, noProof, forged].forEach(function (r, i) {
      assert.strictEqual(r.status, 401, i + " " + r.raw.slice(0, 200));
      assert.ok(codeFree(r.raw), r.raw);
    });
  });
  const after = {};
  for (const code of codes) {
    after[code] = await codesSettle(rb, code, before[code] + 1);
  }
  check("3e. the refusals are recorded STS-ACCOUNT-0001 (no token), " +
        "STS-ACCOUNT-0010 (DPoP-bound as Bearer) and STS-ACCOUNT-0002 (not " +
        "this realm's)", function () {
    codes.forEach(function (code) {
      assert.ok(after[code] > before[code], code + " " +
                JSON.stringify({ before: before, after: after }));
    });
  });

  log.info("=== 4. the body ===");
  const locale = async function () {
    log.debug("Entering locale().");
    const r = await m.api("GET", "/account-api/me");
    log.debug("Leaving locale().");
    return JSON.stringify((r.json && r.json.locale) || null);
  };
  const was = await locale();
  const extra = await m.api("POST", "/account-api/language",
                            { lang: "fr", bogus: "x" });
  const still = await locale();
  check("4a. a body field the operation does not take is refused 400, and " +
        "nothing is changed", function () {
    assert.strictEqual(extra.status, 400, String(extra.text).slice(0, 200));
    assert.ok(/bogus\W+is not a field/.test(JSON.stringify(extra.json)),
              JSON.stringify(extra.json));
    assert.strictEqual(still, was);
  });
  const plain = await m.api("POST", "/account-api/language", { lang: "fr" });
  const now = await locale();
  check("4b. the same body without it is accepted, and changes the language",
        function () {
    assert.strictEqual(plain.status, 200, String(plain.text).slice(0, 200));
    assert.notStrictEqual(now, was);
  });
  const notJson = await send(rb + "/account-api/forgot-password",
    { method: "POST", headers: { "content-type": "text/plain; x=json" },
      body: JSON.stringify({ account: mallory }) });
  const asForm = await send(rb + "/account-api/forgot-password",
    { method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "account=" + encodeURIComponent(mallory) });
  const exact = await send(rb + "/account-api/forgot-password",
    { method: "POST",
      headers: { "content-type": "application/json; charset=utf-8" },
      body: JSON.stringify({ account: mallory }) });
  check("4c. text/plain; x=json is refused 415 at an operation that takes " +
        "no token", function () {
    assert.strictEqual(notJson.status, 415, notJson.raw.slice(0, 200));
  });
  check("4d. a form-encoded body is refused 415", function () {
    assert.strictEqual(asForm.status, 415, asForm.raw.slice(0, 200));
  });
  check("4e. application/json with a parameter is accepted as JSON",
        function () {
    assert.notStrictEqual(exact.status, 415, exact.raw.slice(0, 200));
  });

  log.info("=== 5. SSH user certificates ===");
  const publicKey = sshPublicKey();
  const noToken = await portal.nobody(rb, "POST",
    "/account-api/ssh/certificates",
    { publicKey: publicKey, principals: [mallory] });
  check("5a. certificate issuance still requires the Account API token",
        function () {
    assert.strictEqual(noToken.status, 401, noToken.text.slice(0, 200));
  });
  await realmSet(REALM, "pki.personSelfService", false);
  const disabled = await m.api("POST", "/account-api/ssh/certificates",
    { publicKey: publicKey, principals: [mallory] });
  check("5b. pki.personSelfService refuses SSH certificate issuance",
        function () {
    assert.strictEqual(disabled.status, 403, disabled.text.slice(0, 200));
    assert.ok(codeFree(disabled.text), disabled.text);
  });
  await realmSet(REALM, "pki.personSelfService", true);
  const unowned = await m.api("POST", "/account-api/ssh/certificates",
    { publicKey: publicKey, principals: ["not-" + mallory] });
  check("5c. a person cannot request an unrelated SSH principal",
        function () {
    assert.strictEqual(unowned.status, 403, unowned.text.slice(0, 200));
    assert.ok(codeFree(unowned.text), unowned.text);
  });
  log.info("=== 5d. a device-grant CLI uses its Account API token ===");
  await realmSet(REALM, "oauth2.deviceAuthorization", true);
  const deviceClient = ("aacli" + STAMP).slice(0, 30);
  await oauthClient(rb, deviceClient, {
    oauthGrantType: ["urn:ietf:params:oauth:grant-type:device_code"],
    oauthAllowedScope: ["openid"]
  });
  await ok(rb + "/admin-api/permissions/grant-permission", {
    client: deviceClient,
    permission: "urn:sts:account-api:account:manage"
  }, "granted the CLI access to the caller's own account");
  const deviceKey = deviceDpopKey();
  const deviceAuthorizationUrl = rb + "/oauth2/device_authorization";
  const accountResource = rb + "/account-api";
  const deviceForm = new URLSearchParams({ client_id: deviceClient,
    scope: "openid", resource: "https://unknown.example/api" });
  const unknownResource = await send(deviceAuthorizationUrl, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: deviceForm.toString() });
  check("device authorization refuses an unregistered resource", function () {
    assert.strictEqual(unknownResource.status, 400,
      unknownResource.raw.slice(0, 200));
    assert.strictEqual(unknownResource.body.error, "invalid_target");
    assert.ok(codeFree(unknownResource.raw), unknownResource.raw);
  });
  const startForm = new URLSearchParams({ client_id: deviceClient,
    scope: "openid account:manage", resource: accountResource });
  const started = await send(deviceAuthorizationUrl, { method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded",
      dpop: deviceDpopProof(deviceKey, "POST", deviceAuthorizationUrl) },
    body: startForm.toString() });
  const deviceCodes = started.body || {};
  const shown = await m.draw("/portal/device",
    { user_code: deviceCodes.user_code });
  check("the portal shows the requested Account API resource before " +
        "approval", function () {
    assert.strictEqual(started.status, 200, started.raw.slice(0, 300));
    assert.strictEqual(shown.status, 200,
      JSON.stringify(shown.json).slice(0, 300));
    assert.ok(shown.html.indexOf("id=\"device-resources\"") >= 0);
    assert.ok(shown.html.indexOf(accountResource) >= 0);
  });
  const deviceApproval = await m.act("/portal/device",
    { action: "approve", user_code: deviceCodes.user_code });
  check("the portal approves the device authorization", function () {
    assert.strictEqual(deviceApproval.status, 200,
      deviceApproval.text.slice(0, 200));
    assert.ok(deviceApproval.json && deviceApproval.json.ok);
  });
  const tokenUrl = rb + "/oauth2/token";
  const widenedForm = new URLSearchParams({
    grant_type: "urn:ietf:params:oauth:grant-type:device_code",
    client_id: deviceClient, device_code: deviceCodes.device_code,
    resource: rb + "/admin-api" });
  const widened = await send(tokenUrl, { method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded",
      dpop: deviceDpopProof(deviceKey, "POST", tokenUrl, {
        c_s256: crypto.createHash("sha256").update(deviceCodes.device_code,
          "ascii").digest("base64url") }) },
    body: widenedForm.toString() });
  check("the token request cannot widen the approved resources", function () {
    assert.strictEqual(widened.status, 400, widened.raw.slice(0, 200));
    assert.strictEqual(widened.body.error, "invalid_target");
    assert.ok(codeFree(widened.raw), widened.raw);
  });
  const tokenForm = new URLSearchParams({
    grant_type: "urn:ietf:params:oauth:grant-type:device_code",
    client_id: deviceClient, device_code: deviceCodes.device_code });
  const tokenAnswer = await send(tokenUrl, { method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded",
      dpop: deviceDpopProof(deviceKey, "POST", tokenUrl, {
        c_s256: crypto.createHash("sha256").update(deviceCodes.device_code,
          "ascii").digest("base64url") }) },
    body: tokenForm.toString() });
  const deviceToken = tokenAnswer.body && tokenAnswer.body.access_token;
  const deviceClaims = deviceToken ? jwtPayload(deviceToken) : {};
  check("the device grant returns a DPoP-bound token for /account-api",
        function () {
    assert.strictEqual(tokenAnswer.status, 200,
      tokenAnswer.raw.slice(0, 300));
    assert.strictEqual(tokenAnswer.body.token_type, "DPoP");
    assert.strictEqual(deviceClaims.aud, accountResource);
    assert.strictEqual(deviceClaims.cnf.jkt, deviceKey.jkt);
  });
  const devicePublicKey = sshPublicKey();
  const sshUrl = rb + "/account-api/ssh/certificates";
  const deviceIssued = await send(sshUrl, { method: "POST",
    headers: { "content-type": "application/json",
      authorization: "DPoP " + deviceToken,
      dpop: deviceDpopProof(deviceKey, "POST", sshUrl, {
        ath: crypto.createHash("sha256").update(deviceToken)
          .digest("base64url") }) },
    body: JSON.stringify({ publicKey: devicePublicKey,
      principals: [mallory] }) });
  check("the device token can issue the caller's SSH certificate",
        function () {
    assert.strictEqual(deviceIssued.status, 200,
      deviceIssued.raw.slice(0, 300));
    assert.match(deviceIssued.body.certificate,
      /^ssh-ed25519-cert-v01@openssh\.com /);
  });
  const issued = await m.api("POST", "/account-api/ssh/certificates",
    { publicKey: publicKey, principals: [mallory] });
  check("5e. the caller can obtain a certificate for their own UID",
        function () {
    assert.strictEqual(issued.status, 200, issued.text.slice(0, 300));
    assert.match(issued.json.certificate,
      /^ssh-ed25519-cert-v01@openssh\.com /);
    assert.match(issued.json.serialHex, /^[0-9a-f]+$/);
    assert.strictEqual(issued.json.hardwareBound, false);
  });
  const otherName = ("aao" + STAMP).slice(0, 30);
  await ok(rb + "/admin-api/users/create", { username: otherName,
    invent: false, attributes: { cn: "Aapi " + otherName, sn: otherName,
      givenName: "Aapi", mail: otherName + "@example.test" },
    credential: "password", password: PW }, "created " + otherName);
  const other = await portal.signInToThePortal(rb, otherName, log,
                                               { password: PW });
  const foreignRevoke = await other.api("POST",
    "/account-api/ssh/certificates/revoke",
    { serialHex: issued.json.serialHex });
  check("5f. another token subject cannot revoke the certificate",
        function () {
    assert.strictEqual(foreignRevoke.status, 404,
                       foreignRevoke.text.slice(0, 200));
    assert.ok(codeFree(foreignRevoke.text), foreignRevoke.text);
  });
  const publicCa = await portal.nobody(rb, "GET",
    "/pki/ssh-user-ca/" + REALM);
  const revoked = await m.api("POST",
    "/account-api/ssh/certificates/revoke",
    { serialHex: issued.json.serialHex });
  const publicKrl = await portal.nobody(rb, "GET",
    "/pki/ssh-user-krl/" + REALM);
  check("5g. the realm CA and KRL are public, uncached, and the owner can " +
        "revoke their certificate", function () {
    assert.strictEqual(publicCa.status, 200, publicCa.text.slice(0, 200));
    assert.strictEqual(publicCa.headers.get("cache-control"), "no-store");
    assert.strictEqual(revoked.status, 200, revoked.text.slice(0, 200));
    assert.strictEqual(revoked.json.revoked, true);
    assert.strictEqual(publicKrl.status, 200, publicKrl.text.slice(0, 200));
    assert.strictEqual(publicKrl.headers.get("cache-control"), "no-store");
  });
  log.debug("Leaving test().");
}

main();
