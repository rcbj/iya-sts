// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_authn_certificate_signin.js
//
// ---------------------------------------------------------------------------
// THE SIGN-IN SCREEN CONTINUES WITH THE TLS CLIENT CERTIFICATE ON THE
// CONNECTION, OVER A REAL HANDSHAKE ON THE MAIN PORT (#1051).
//
// D12 (#444): carries over `tests/authn_certificate_signin.js`, which built a
// listener with the main port's posture in a child process. Here the main
// port itself is dialled with a certificate the person enrolled over EST
// (`/.well-known/est/tls-client/simpleenroll`, their password) in a
// throwaway development realm:
//
//   A. no offer on a connection that presents nothing; the offer naming the
//      holder (`certificate: { name }`) on one that presents theirs; the act
//      starting their session, and the authorization endpoint answering the
//      client a code whose ID Token says `amr ["swk"]` and `acr "1"`;
//   B. the refusals, each with no session and its code: no certificate on
//      the act's connection (STS-AUTHN-0463); a person's certificate from
//      ANOTHER realm's authority (STS-AUTHN-0465); an application whose
//      named authentication policy does not take a certificate
//      (STS-AUTHN-0467); an application's certificate, issued through
//      `/admin-api/applications/issue-tls-client-certificate`
//      (STS-AUTHN-0466); the certificate once its holder revoked it at the
//      portal (STS-AUTHN-0464).
//
// NOT carried, and why: the renderer drawing the button (A) is browser code
// (class (d)).
//
// OWNED HERE (local: true): this repository's sign-in screen.
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
var log = bunyan.createLogger({ name: "sts_authn_certificate_signin",
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

const path = require("path");
const https = require("https");
const est = require("./est_client.js");
const portal = require("./portal_signin.js");

const REPO = process.env.MOCK_STS_DIR || path.join(__dirname, "..", "..");
const x509 = require(path.join(REPO, "common", "crypto_impl", "x509.js"));
const keyMaterial = require(path.join(REPO, "common", "crypto_impl",
                                      "key_material.js"));

const REALM = "acrt-" + STAMP;
const OTHER = "acro-" + STAMP;
const PW = "Acrt-" + STAMP + "-Violet.Tractor.Maple.42";
const RP = "https://rp.acrt.example";

function user(tag) {
  log.debug("Entering user(). " + tag);
  log.debug("Leaving user().");
  return ("ac" + tag + STAMP).slice(0, 30);
}

async function person(rb, name) {
  log.debug("Entering person(). " + name);
  await ok(rb + "/admin-api/users/create", { username: name, invent: false,
    attributes: { cn: "Acrt " + name, sn: name, givenName: ["Acrt"],
                  mail: [name + "@example.test"] },
    credential: "password", password: PW }, "created " + name);
  log.debug("Leaving person().");
}

// A TLS client certificate for `who`, enrolled over EST in `rb`.
async function enrol(rb, who) {
  log.debug("Entering enrol(). " + who);
  const pair = await keyMaterial.generateKeyPair("ec-p256");
  const csr = await x509.certificationRequest({ subject: "CN=" + who,
    publicKeyPem: pair.publicPem, privateKeyPem: pair.privatePem });
  const r = await est.send({ method: "POST",
    url: rb + "/.well-known/est/tls-client/simpleenroll",
    headers: { "Content-Type": "application/pkcs10",
               "Content-Transfer-Encoding": "base64" },
    body: est.requestBody(csr.der), basic: [who, PW] });
  assert.strictEqual(r.status, 200, "EST enrolment for " + who + ": " +
                     r.status + " " + String(r.body).slice(0, 200));
  const der = Buffer.from(String(r.body).replace(/\s+/g, ""), "base64");
  const pem = est.parseCertsOnly(der).certificates[0];
  // The leaf alone does not verify at the handshake: the EST Issuing CA is
  // not an anchor, so the chain the realm publishes is presented with it.
  const ca = await est.send({ method: "GET",
    url: rb + "/.well-known/est/tls-client/cacerts" });
  const chain = est.parseCertsOnly(Buffer.from(String(ca.body)
    .replace(/\s+/g, ""), "base64")).certificates;
  log.debug("Leaving enrol().");
  return { cert: pem + chain.join(""), key: pair.privatePem,
           serial: new crypto.X509Certificate(pem).serialNumber
             .toLowerCase() };
}

// One request on a connection of its own, presenting `tls` (cert, key)
// where given.
function tlsCall(method, url, o) {
  log.debug("Entering tlsCall(). " + method);
  const opts = o || {};
  return new Promise(function (resolve, reject) {
    const u = new URL(url);
    const body = opts.body === undefined ? "" : JSON.stringify(opts.body);
    const headers = Object.assign({ accept: "application/json" },
                                  opts.headers || {});
    if (method !== "GET") {
      headers["content-type"] = "application/json";
      headers["content-length"] = Buffer.byteLength(body);
    }
    const req = https.request({ host: u.hostname, port: u.port,
      path: u.pathname + u.search, method: method, headers: headers,
      agent: false, cert: opts.tls ? opts.tls.cert : undefined,
      key: opts.tls ? opts.tls.key : undefined,
      passphrase: opts.tls ? opts.tls.passphrase : undefined },
    function (res) {
      let text = "";
      res.setEncoding("utf8");
      res.on("data", function (chunk) {
        text += chunk;
      });
      res.on("end", function () {
        let json = null;
        try {
          json = JSON.parse(text);
        } catch (e) {
          log.debug("Caught in tlsCall(): " + ((e && e.message) || e));
          // Not JSON: the caller reads the text.
          json = null;
        }
        log.debug("Leaving tlsCall(). " + res.statusCode);
        resolve({ status: res.statusCode, json: json, text: text,
                  setCookies: [].concat(res.headers["set-cookie"] || []) });
      });
    });
    req.on("error", function (e) {
      log.debug("Caught in tlsCall(): " + e.message);
      reject(e);
    });
    req.end(body || undefined);
  });
}

async function client(rb, id, policyName) {
  log.debug("Entering client(). " + id);
  const fields = { oauthClientId: [id], oauthRedirectUri: [RP + "/" + id],
    oauthTokenEndpointAuthMethod: "none",
    oauthGrantType: ["authorization_code"], oauthAllowedScope: ["openid"] };
  if (policyName) {
    fields.appAuthnPolicy = policyName;
  }
  await ok(rb + "/admin-api/applications/create", { identifier: id,
    name: id, protocols: ["oauth2", "oidc"], fields: fields },
    "registered " + id);
  log.debug("Leaving client().");
}

async function authz(rb, id) {
  log.debug("Entering authz(). " + id);
  const verifier = crypto.randomBytes(32).toString("base64url");
  const r = await fetch(rb + "/oauth2/authorize?" + new URLSearchParams({
    response_type: "code", client_id: id, redirect_uri: RP + "/" + id,
    scope: "openid", state: "s1", nonce: "n1",
    code_challenge: crypto.createHash("sha256").update(verifier)
      .digest("base64url"),
    code_challenge_method: "S256" }).toString(), { redirect: "manual" });
  await r.text();
  const location = new URL(String(r.headers.get("location")), rb).toString();
  log.debug("Leaving authz().");
  return { verifier: verifier, location: location,
           id: authnSignin.pendingIdOf(location) };
}

// The screen's view on a connection presenting `tls`, after its shell:
// `{ view, csrf, cookie }`.
async function viewWith(rb, at, tls) {
  log.debug("Entering viewWith().");
  const shell = await tlsCall("GET", at.location, { tls: tls });
  const cookie = shell.setCookies.map(function (one) {
    return one.split(";")[0];
  }).join("; ");
  const v = await tlsCall("GET", rb + "/authn-api/pending/" +
    encodeURIComponent(at.id), { tls: tls, headers: { cookie: cookie } });
  log.debug("Leaving viewWith().");
  return { status: v.status, view: v.json && v.json.view,
           csrf: (v.json && v.json.csrf) || "", cookie: cookie };
}

function certificateAct(rb, at, opened, tls) {
  log.debug("Entering certificateAct().");
  log.debug("Leaving certificateAct().");
  return tlsCall("POST", rb + "/authn-api/pending/" +
    encodeURIComponent(at.id) + "/certificate", { tls: tls, body: {},
    headers: { cookie: opened.cookie, origin: new URL(rb).origin,
               "x-csrf-token": opened.csrf } });
}

async function refusedWith(rb, code, run) {
  log.debug("Entering refusedWith(). " + code);
  const before = await codeCount(rb, code);
  const r = await run();
  const after = await codesSettle(rb, code, before + 1);
  log.debug("Leaving refusedWith().");
  return { r: r, rose: after > before, counts: before + " -> " + after };
}

async function test() {
  log.debug("Entering test().");
  const rb = await makeRealm(REALM, null);
  const ob = await makeRealm(OTHER, null);
  for (const id of [REALM, OTHER]) {
    await realmSet(id, "risk.assessSignIns", false);
    await realmSet(id, "security.rateLimitPerAddress", 10000);
    await realmSet(id, "oauth2.consentRequired", false);
  }
  const app = "acrt-" + STAMP;
  await client(rb, app, "");
  const alice = user("al");
  await person(rb, alice);
  await person(ob, alice);
  const mine = await enrol(rb, alice);
  const foreign = await enrol(ob, alice);

  log.info("=== A. the offer and the sign-in ===");
  const at = await authz(rb, app);
  const bare = await viewWith(rb, at, null);
  check("A1. no offer on a connection that presents nothing", function () {
    assert.strictEqual(bare.status, 200);
    assert.ok(!bare.view.certificate, JSON.stringify(bare.view.certificate));
  });
  const offered = await viewWith(rb, at, mine);
  check("A2. the offer names the holder on a connection presenting their " +
        "certificate", function () {
    assert.strictEqual(offered.status, 200);
    assert.ok(offered.view.certificate, JSON.stringify(offered.view));
    assert.strictEqual(offered.view.certificate.name, alice);
  });
  const done = await certificateAct(rb, at, offered, mine);
  check("A3. the act starts their session: next: redirect, the session " +
        "cookie on that answer", function () {
    assert.strictEqual(done.status, 200, done.text);
    assert.strictEqual(done.json.next, "redirect", done.text);
    assert.ok(sessionCookieIn(done.setCookies), JSON.stringify(
      done.setCookies));
  });
  const sessionCookie = authnSignin.foldCookies(offered.cookie,
                                                done.setCookies);
  const back = await fetch(new URL(done.json.location, rb).toString(),
    { redirect: "manual", headers: { cookie: sessionCookie } });
  await back.text();
  const code = new URL(String(back.headers.get("location") || ""), rb)
    .searchParams.get("code");
  const t = await send(rb + "/oauth2/token", { method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "authorization_code",
      code: String(code), code_verifier: at.verifier, client_id: app,
      redirect_uri: RP + "/" + app }).toString() });
  const claims = t.body && t.body.id_token ? JSON.parse(Buffer.from(
    t.body.id_token.split(".")[1], "base64url").toString()) : {};
  check("A4. and the authorization endpoint answers the client a code " +
        "whose ID Token says amr [\"swk\"] and acr \"1\"", function () {
    assert.ok(code, String(back.headers.get("location")));
    assert.strictEqual(t.status, 200, t.raw.slice(0, 200));
    assert.deepStrictEqual(claims.amr, ["swk"]);
    assert.strictEqual(String(claims.acr), "1");
  });

  log.info("=== B. the refusals ===");
  const at1 = await authz(rb, app);
  const opened1 = await viewWith(rb, at1, mine);
  const noCert = await refusedWith(rb, "STS-AUTHN-0463", function () {
    return certificateAct(rb, at1, opened1, null);
  });
  check("B1. no certificate on the act's connection is refused, no " +
        "session, STS-AUTHN-0463", function () {
    assert.strictEqual(noCert.r.status, 400, noCert.r.text);
    assert.strictEqual(noCert.r.json.next, "refused");
    assert.ok(!sessionCookieIn(noCert.r.setCookies));
    assert.ok(codeFree(noCert.r.text));
    assert.ok(noCert.rose, noCert.counts);
  });
  const at2 = await authz(rb, app);
  const opened2 = await viewWith(rb, at2, foreign);
  const other = await refusedWith(rb, "STS-AUTHN-0465", function () {
    return certificateAct(rb, at2, opened2, foreign);
  });
  check("B2. a person's certificate from ANOTHER realm's authority is not " +
        "offered and is refused, STS-AUTHN-0465", function () {
    assert.ok(!opened2.view.certificate, JSON.stringify(opened2.view));
    assert.strictEqual(other.r.status, 400, other.r.text);
    assert.ok(!sessionCookieIn(other.r.setCookies));
    assert.ok(other.rose, other.counts);
  });
  const saved = await postJson(rb +
    "/admin-api/policies/save-named-authn-policy",
    { name: "acrt-password-only", mechanisms: ["password"] });
  assert.strictEqual(saved.status, 200, saved.raw.slice(0, 200));
  const narrow = "acrt-narrow-" + STAMP;
  await client(rb, narrow, "acrt-password-only");
  const at3 = await authz(rb, narrow);
  const opened3 = await viewWith(rb, at3, mine);
  const notTaken = await refusedWith(rb, "STS-AUTHN-0467", function () {
    return certificateAct(rb, at3, opened3, mine);
  });
  check("B3. an application whose authentication policy does not take a " +
        "certificate refuses it, STS-AUTHN-0467", function () {
    assert.strictEqual(notTaken.r.status, 400, notTaken.r.text);
    assert.ok(!sessionCookieIn(notTaken.r.setCookies));
    assert.ok(notTaken.rose, notTaken.counts);
  });
  const p12 = "Acrt-p12-" + STAMP;
  const issued = await ok(rb + "/admin-api/applications/" +
    "issue-tls-client-certificate", { application: app, password: p12,
    keyAlg: "ec-p256" }, "issued " + app + " a TLS client certificate");
  const appTls = { cert: issued.files.chain.text,
                   key: issued.files.key.text, passphrase: p12 };
  const at5 = await authz(rb, app);
  const opened5 = await viewWith(rb, at5, appTls);
  const asApp = await refusedWith(rb, "STS-AUTHN-0466", function () {
    return certificateAct(rb, at5, opened5, appTls);
  });
  check("B4. an application's certificate is not offered and is refused, " +
        "STS-AUTHN-0466", function () {
    assert.ok(!opened5.view.certificate, JSON.stringify(opened5.view));
    assert.strictEqual(asApp.r.status, 400, asApp.r.text);
    assert.ok(!sessionCookieIn(asApp.r.setCookies));
    assert.ok(asApp.rose, asApp.counts);
  });
  const p = await portal.signInToThePortal(rb, alice, log, { password: PW });
  const revoked = await p.act("/portal/certificates", { action: "revoke",
    serial: mine.serial, reason: "keyCompromise" });
  assert.strictEqual(revoked.status, 200, "revoked at the portal: " +
                     revoked.status + " " + JSON.stringify(revoked.json)
                       .slice(0, 300));
  const at4 = await authz(rb, app);
  const opened4 = await viewWith(rb, at4, mine);
  const gone = await refusedWith(rb, "STS-AUTHN-0464", function () {
    return certificateAct(rb, at4, opened4, mine);
  });
  check("B5. the certificate once its holder revoked it is refused, " +
        "STS-AUTHN-0464", function () {
    assert.strictEqual(gone.r.status, 400, gone.r.text);
    assert.ok(!sessionCookieIn(gone.r.setCookies));
    assert.ok(gone.rose, gone.counts);
  });
  log.debug("Leaving test().");
}

main();
