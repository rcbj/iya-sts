// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_client_authentication.js
//
// ---------------------------------------------------------------------------
// CLIENT AUTHENTICATION AT THE TOKEN ENDPOINT, OVER THE WIRE (#293, WP4,
// 2026-10-13).
//
// Three methods `docs/configure-oauth2-grants.md` documents had no over-HTTP
// job outside the OpenID conformance lane: a SUCCESSFUL `client_secret_jwt`
// (only its refusal was driven, and one success in an OAuth 2.1 realm), and
// RFC 8705's `tls_client_auth` and `self_signed_tls_client_auth`, which only
// `tests/rfc8705_mtls.js` drove, in process. This job drives all three
// against the running service, for clients created through `/admin-api`, in
// two throwaway realms it creates and leaves standing — one development, one
// product — so both halves are asserted whatever mode the service runs in:
//
//   1. client_secret_jwt (RFC 7523 section 2.2 with an HMAC, OIDC Core 9):
//      `client_credentials` with the assertion addressed to the issuer and to
//      the token endpoint; the same assertion again refused as a replay; one
//      MACed with another secret refused; a client pinned to HS512 issued a
//      token for an HS512 assertion and refused an HS256 one; and the
//      authorization code grant redeemed with an assertion.
//   2. tls_client_auth (RFC 8705 section 2.1), by a certificate the realm's
//      Credentials door issued to the application: a token bound to the
//      certificate (`cnf.x5t#S256`), introspection showing the binding; no
//      certificate (STS-OAUTH-0014) and another application's certificate
//      (STS-OAUTH-0484) refused; a revoked certificate refused while the
//      application's other certificate still authenticates it.
//   3. self_signed_tls_client_auth (section 2.2), by a self-signed
//      certificate `openssl` makes at run time and the application's jwks
//      names as an `x5c`: a bound token; another self-signed certificate
//      refused (STS-OAUTH-0016); a client with nothing registered refused
//      (STS-OAUTH-0015).
//
// WHAT THE FIRST RUN FOUND, AND WHAT IS THEREFORE ASSERTED (2026-10-13):
//   * Development mode with RFC 9700 mode off OBSERVES a client_secret_jwt
//     assertion and verifies nothing about its MAC or its jti — a replay, a
//     wrong secret and a key too short for HS512 are all issued tokens there,
//     which is the documented non-goal, and asserted as such; product refuses
//     each.
//   * The registered `token_endpoint_auth_signing_alg` is held in EVERY mode.
//   * An HS512 assertion under a 448-bit secret is refused in product (RFC
//     7518 section 3.2: the key must be at least as long as the hash), so the
//     HS512 client holds a 512-bit secret.
//   * Both RFC 8705 methods are verified in EVERY mode — no certificate,
//     another application's, a revoked one and an unregistered self-signed
//     one are refused in development too.
//
// THE CERTIFICATE IS PRESENTED ON THE MAIN PORT, which asks every connection
// for one and requires none, so the client is `https.request` with `cert` and
// `key` — fetch() cannot present one. Every refusal's code is read back from
// the realm's `/admin-api/audit`. Nothing here is committed key material:
// every key is made at run time.
//
// OWNED HERE (local: true).
// ---------------------------------------------------------------------------

const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const https = require("https");
const nodeCrypto = require("crypto");
const childProcess = require("child_process");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const registry = require("./sts_applications.js");
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
var log = bunyan.createLogger({ name: "sts_client_authentication",
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
const DEV = "cau-d-" + TAG;
const PROD = "cau-p-" + TAG;
const PERSON = names.usernameFor("cau-person");
const PASSWORD = "Cau-" + nodeCrypto.randomBytes(9).toString("base64url") +
  "-Aa1!";
const SECRET = "cau-secret-" + TAG + "-" +
  nodeCrypto.randomBytes(16).toString("hex");
// RFC 7518 section 3.2: an HS512 key is at least 512 bits, so the HS512
// client's secret is 64 random bytes and SECRET (448 bits) is too short.
const LONG_SECRET = nodeCrypto.randomBytes(64).toString("hex");
const OTHER_SECRET = "cau-other-" + TAG + "-" +
  nodeCrypto.randomBytes(16).toString("hex");
const REDIRECT = "https://rp.cau.example.test/cb";
const CSJ_APP = "cau-csj-" + TAG;
const HS512_APP = "cau-hs512-" + TAG;
const MTLS_APP = "cau-mtls-" + TAG;
const MTLS_OTHER = "cau-mtls2-" + TAG;
const SELF_APP = "cau-self-" + TAG;
const SELF_EMPTY = "cau-selfnone-" + TAG;
const ASSERTION_TYPE =
  "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const FLOOR = 36;

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

// RFC 8705 section 3.1: the base64url SHA-256 of the certificate's DER.
function thumbprintOf(pem) {
  log.debug("Entering thumbprintOf().");
  const der = new nodeCrypto.X509Certificate(pem).raw;
  log.debug("Leaving thumbprintOf().");
  return nodeCrypto.createHash("sha256").update(der).digest("base64url");
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

// A form POST over TLS presenting `tls` ({ cert, key }) as the client
// certificate, or none. The anchor is the one the runner hands every job
// (NODE_EXTRA_CA_CERTS), so the service's certificate is still verified.
function tlsPost(url, fields, tls) {
  log.debug("Entering tlsPost(). " + url + " cert=" + !!tls);
  const body = form(fields);
  const u = new URL(url);
  return new Promise(function (resolve, reject) {
    const req = https.request({
      method: "POST", hostname: u.hostname, port: u.port || 443,
      path: u.pathname + u.search, servername: u.hostname,
      // A fresh connection, so one request's certificate never rides on
      // another's resumed session.
      agent: false,
      cert: tls ? tls.cert : undefined, key: tls ? tls.key : undefined,
      headers: { "Content-Type": "application/x-www-form-urlencoded",
                 "Content-Length": Buffer.byteLength(body) }
    }, function (res) {
      const chunks = [];
      res.on("data", function (c) {
        chunks.push(c);
      });
      res.on("end", function () {
        const text = Buffer.concat(chunks).toString("utf8");
        let json = null;
        try {
          json = JSON.parse(text);
        } catch (e) {
          log.debug("Caught in tlsPost(): " + ((e && e.message) || e));
          // Not JSON; `text` carries it into the message.
          json = null;
        }
        log.debug("Leaving tlsPost(). status=" + res.statusCode);
        resolve({ status: res.statusCode, json: json, text: text });
      });
    });
    req.on("error", function (e) {
      log.debug("Caught in tlsPost(): " + ((e && e.message) || e));
      reject(e);
    });
    req.end(body);
  });
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

// Runs `fn`, then waits for a new audit row with `code` in `realm`.
async function recording(realm, code, fn) {
  log.debug("Entering recording(). " + code);
  const before = await codeCount(realm, code);
  const r = await fn();
  let after = before;
  for (let i = 0; i < 20 && after <= before; i += 1) {
    await sleep(150);
    after = await codeCount(realm, code);
  }
  r.recorded = after > before;
  log.debug("Leaving recording(). " + before + " -> " + after);
  return r;
}

function refusedClient(r) {
  log.debug("Entering refusedClient().");
  log.debug("Leaving refusedClient().");
  return r.status === 401 && r.json && r.json.error === "invalid_client";
}

// Is RFC 9700 mode on in `realm`? Outside it, development mode OBSERVES a
// client's credential and does not verify it (CLAUDE.md, "Things this
// service deliberately does not do"), so a refusal below is asserted where
// the mode is on and the issued token where it is off.
async function strictIn(realm) {
  log.debug("Entering strictIn(). " + realm);
  const r = await call("GET", realmBase(realm) + "/oauth2/rfc9700");
  assert.strictEqual(r.status, 200, r.text.slice(0, 200));
  log.debug("Leaving strictIn(). " + !!r.json.enabled);
  return !!r.json.enabled;
}

// A refusal where the realm verifies client credentials, and an issued token
// where it only observes them.
function refusedOrObserved(r, strict) {
  log.debug("Entering refusedOrObserved(). strict=" + strict);
  if (strict) {
    assert.ok(refusedClient(r), r.status + " " + r.text.slice(0, 300));
  } else {
    assert.strictEqual(r.status, 200, "development mode observes the " +
                       "credential and should issue: " + r.text.slice(0, 300));
  }
  log.debug("Leaving refusedOrObserved().");
}

// An RFC 7523 client assertion MACed with `secret` (client_secret_jwt).
function hmacAssertion(clientId, secret, aud, alg, jti) {
  log.debug("Entering hmacAssertion(). " + alg);
  const now = Math.floor(Date.now() / 1000);
  const head = Buffer.from(JSON.stringify({ alg: alg, typ: "JWT" }))
    .toString("base64url");
  const body = Buffer.from(JSON.stringify({
    iss: clientId, sub: clientId, aud: aud, iat: now, exp: now + 60,
    jti: jti || nodeCrypto.randomBytes(12).toString("hex") }))
    .toString("base64url");
  const mac = nodeCrypto.createHmac(alg === "HS512" ? "sha512" : "sha256",
                                    secret).update(head + "." + body)
    .digest("base64url");
  log.debug("Leaving hmacAssertion().");
  return head + "." + body + "." + mac;
}

// A self-signed EC certificate and its key, made by openssl in a temporary
// directory that is removed again.
function selfSigned(cn) {
  log.debug("Entering selfSigned(). " + cn);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cau-"));
  try {
    childProcess.execFileSync("openssl", ["req", "-x509", "-newkey", "ec",
      "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "2",
      "-subj", "/CN=" + cn, "-keyout", path.join(dir, "k.pem"),
      "-out", path.join(dir, "c.pem")], { stdio: "pipe" });
    const out = { cert: fs.readFileSync(path.join(dir, "c.pem"), "utf8"),
                  key: fs.readFileSync(path.join(dir, "k.pem"), "utf8") };
    log.debug("Leaving selfSigned().");
    return out;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// A TLS client certificate the realm's Credentials door issues to `app`.
async function issuedTo(realm, app, label) {
  log.debug("Entering issuedTo(). " + app);
  const password = nodeCrypto.randomBytes(18).toString("base64url");
  const r = await ok(realmBase(realm) +
                     "/admin-api/applications/issue-tls-client-certificate",
                     { application: app, password: password,
                       keyAlg: "ec-p256", label: label },
                     realm + ": issued " + app + " a TLS client certificate");
  const key = nodeCrypto.createPrivateKey({ key: r.files.key.text,
                                           format: "pem",
                                           passphrase: password })
    .export({ format: "pem", type: "pkcs8" });
  const pem = r.certificate.certificatePem;
  log.debug("Leaving issuedTo().");
  return { tls: { cert: [pem].concat(r.certificate.chainPem || [])
                    .join("\n"), key: String(key) },
           pem: pem,
           serialHex: r.certificate.serialHex || r.serialHex ||
             new nodeCrypto.X509Certificate(pem).serialNumber.toLowerCase() };
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

// A code for `clientId`, the person signed in with their password.
async function codeFor(realm, clientId) {
  log.debug("Entering codeFor(). " + clientId);
  const verifier = nodeCrypto.randomBytes(32).toString("base64url");
  const challenge = nodeCrypto.createHash("sha256").update(verifier)
    .digest("base64url");
  const b = browser();
  let r = await b.go("GET", "/realm/" + realm + "/oauth2/authorize?" + form({
    response_type: "code", client_id: clientId, redirect_uri: REDIRECT,
    scope: "openid", state: "st-" + TAG,
    nonce: "n-" + nodeCrypto.randomBytes(9).toString("base64url"),
    code_challenge: challenge, code_challenge_method: "S256" }));
  assert.ok((r.status === 302 || r.status === 303) &&
            /\/authn\/login\?authn=/.test(r.location),
            "the authorization endpoint should send the browser to sign in; " +
            "it answered " + r.status + " " + r.location + " " +
            r.text.slice(0, 300));
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
  const code = new URL(r.location).searchParams.get("code");
  assert.ok(code, "no code at the client: " + r.location);
  log.debug("Leaving codeFor().");
  return { code: code, verifier: verifier };
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
    // RISK SCORING (#62) is off for sts_admin_client_policies.js's reason:
    // this client is automated, and what is asserted is authentication.
    await setting(realm, "risk.assessSignIns", false);
    await registry.ensurePerson(realmBase(realm), PERSON, PASSWORD);
    const make = async function (identifier, fields) {
      await ok(api + "/applications/create", {
        identifier: identifier, name: "#293 " + identifier,
        protocols: ["oauth2", "oidc"],
        fields: Object.assign({ oauthClientId: identifier }, fields) },
        realm + ": created " + identifier);
    };
    await make(CSJ_APP, { oauthRedirectUri: [REDIRECT],
                          oauthClientSecret: SECRET,
                          oauthTokenEndpointAuthMethod: "client_secret_jwt" });
    await make(HS512_APP, { oauthClientSecret: LONG_SECRET,
                            oauthTokenEndpointAuthMethod: "client_secret_jwt",
                            oauthTokenEndpointAuthSigningAlg: "HS512" });
    await make(MTLS_APP, { oauthTokenEndpointAuthMethod: "tls_client_auth" });
    await make(MTLS_OTHER, { oauthTokenEndpointAuthMethod:
                               "tls_client_auth" });
    await make(SELF_EMPTY, { oauthTokenEndpointAuthMethod:
                               "self_signed_tls_client_auth" });
    await ok(api + "/consent/grant-global-consent",
             { client: CSJ_APP, scope: "openid" },
             realm + ": consented openid on " + CSJ_APP);
  }
  log.debug("Leaving setUp().");
}

// RFC 7523 section 2.2 with an HMAC.
async function clientSecretJwt(realm) {
  log.debug("Entering clientSecretJwt(). " + realm);
  log.info("=== 1. " + realm + ": client_secret_jwt ===");
  const rb = realmBase(realm);
  const strict = await strictIn(realm);
  const how = strict ? " is refused" :
    " is issued all the same (RFC 9700 mode off: observed, not verified)";
  check(realm + ": RFC 9700 mode is " + (strict ? "on" : "off") +
        (strict === (realm === PROD) ? ", as the realm's mode implies" :
         " for the whole service"), function () {
    assert.ok(true);
  });
  const tokenUrl = rb + "/oauth2/token";
  const issuer = (await call("GET", rb +
    "/.well-known/oauth-authorization-server")).json.issuer;
  const asked = function (assertion, extra) {
    return formPost(tokenUrl, Object.assign({
      grant_type: "client_credentials", client_id: CSJ_APP,
      client_assertion_type: ASSERTION_TYPE,
      client_assertion: assertion }, extra || {}));
  };
  const jti = "csj-" + nodeCrypto.randomBytes(8).toString("hex");
  const toIssuer = hmacAssertion(CSJ_APP, SECRET, issuer, "HS256", jti);
  let r = await asked(toIssuer);
  check(realm + ": an HS256 assertion addressed to the issuer is issued a " +
        "token for the client", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.strictEqual(claimsOf(r.json.access_token).client_id, CSJ_APP);
  });
  r = await asked(hmacAssertion(CSJ_APP, SECRET, tokenUrl, "HS256"));
  check(realm + ": one addressed to the token endpoint is issued too " +
        "(the sole-issuer audience is OAuth 2.1 mode's rule)", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
  });
  r = await asked(toIssuer);
  check(realm + ": the same assertion again" + how, function () {
    refusedOrObserved(r, strict);
  });
  r = await asked(hmacAssertion(CSJ_APP, OTHER_SECRET, issuer, "HS256"));
  check(realm + ": one MACed with another secret" + how, function () {
    refusedOrObserved(r, strict);
  });
  r = await formPost(tokenUrl, { grant_type: "client_credentials",
    client_id: HS512_APP, client_assertion_type: ASSERTION_TYPE,
    client_assertion: hmacAssertion(HS512_APP, LONG_SECRET, issuer,
                                    "HS512") });
  check(realm + ": a client pinned to HS512 is issued a token for an HS512 " +
        "assertion", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
  });
  r = await formPost(tokenUrl, { grant_type: "client_credentials",
    client_id: HS512_APP, client_assertion_type: ASSERTION_TYPE,
    client_assertion: hmacAssertion(HS512_APP, LONG_SECRET, issuer,
                                    "HS256") });
  // THE REGISTERED ALGORITHM IS HELD IN EVERY MODE (found by this job's
  // first run): development observes the MAC but still compares the
  // assertion's `alg` with what the client registered.
  check(realm + ": an HS256 one is refused in every mode (OIDC Core 9's " +
        "token_endpoint_auth_signing_alg)", function () {
    assert.ok(refusedClient(r), r.status + " " + r.text.slice(0, 300));
    assert.ok(/OIDC Core section 9/.test(r.json.error_description || ""),
              r.json.error_description);
  });
  r = await asked(hmacAssertion(CSJ_APP, SECRET, issuer, "HS512"));
  check(realm + ": an HS512 assertion under a 448-bit secret (RFC 7518 " +
        "section 3.2: the key is shorter than the hash)" + how, function () {
    refusedOrObserved(r, strict);
    if (strict) {
      assert.ok(/448-bit/.test(r.json.error_description || ""),
                r.json.error_description);
    }
  });
  const got = await codeFor(realm, CSJ_APP);
  r = await formPost(tokenUrl, { grant_type: "authorization_code",
    code: got.code, redirect_uri: REDIRECT, code_verifier: got.verifier,
    client_id: CSJ_APP, client_assertion_type: ASSERTION_TYPE,
    client_assertion: hmacAssertion(CSJ_APP, SECRET, issuer, "HS256") });
  check(realm + ": the authorization code grant is redeemed with an " +
        "assertion, and the ID Token names the client", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.ok(r.json.id_token, r.text.slice(0, 300));
    const aud = claimsOf(r.json.id_token).aud;
    assert.ok(aud === CSJ_APP ||
              (Array.isArray(aud) && aud.indexOf(CSJ_APP) >= 0),
              JSON.stringify(aud));
  });
  log.debug("Leaving clientSecretJwt().");
}

// RFC 8705 section 2.1, by certificates the realm issued.
async function tlsClientAuth(realm) {
  log.debug("Entering tlsClientAuth(). " + realm);
  log.info("=== 2. " + realm + ": tls_client_auth ===");
  const rb = realmBase(realm);
  const tokenUrl = rb + "/oauth2/token";
  const first = await issuedTo(realm, MTLS_APP, "first");
  const second = await issuedTo(realm, MTLS_APP, "second");
  const others = await issuedTo(realm, MTLS_OTHER, "other");
  const grant = { grant_type: "client_credentials", client_id: MTLS_APP };
  let r = await tlsPost(tokenUrl, grant, first.tls);
  check(realm + ": the certificate the Credentials door issued " +
        "authenticates the application, and the token is bound to it " +
        "(cnf.x5t#S256)", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    const claims = claimsOf(r.json.access_token);
    assert.strictEqual(claims.client_id, MTLS_APP);
    assert.strictEqual(claims.cnf && claims.cnf["x5t#S256"],
                       thumbprintOf(first.pem), JSON.stringify(claims.cnf));
  });
  const accessToken = r.json.access_token;
  r = await tlsPost(rb + "/oauth2/introspect",
                    { token: accessToken, client_id: MTLS_APP }, first.tls);
  check(realm + ": introspection, authenticated the same way, shows it " +
        "active and bound", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.strictEqual(r.json.active, true, r.text.slice(0, 300));
    assert.strictEqual(r.json.cnf && r.json.cnf["x5t#S256"],
                       thumbprintOf(first.pem), r.text.slice(0, 300));
  });
  r = await recording(realm, "STS-OAUTH-0014", function () {
    return tlsPost(tokenUrl, grant, null);
  });
  check(realm + ": no certificate is refused invalid_client " +
        "(STS-OAUTH-0014)", function () {
    assert.ok(refusedClient(r), r.status + " " + r.text.slice(0, 300));
    assert.ok(r.recorded, "no audit row carries STS-OAUTH-0014");
  });
  r = await recording(realm, "STS-OAUTH-0484", function () {
    return tlsPost(tokenUrl, grant, others.tls);
  });
  check(realm + ": another application's certificate is refused " +
        "invalid_client (STS-OAUTH-0484)", function () {
    assert.ok(refusedClient(r), r.status + " " + r.text.slice(0, 300));
    assert.ok(r.recorded, "no audit row carries STS-OAUTH-0484");
  });
  await ok(rb + "/admin-api/applications/revoke-tls-client-certificate",
           { application: MTLS_APP, serialHex: first.serialHex,
             reason: "keyCompromise" },
           realm + ": revoked the first certificate");
  r = await tlsPost(tokenUrl, grant, first.tls);
  check(realm + ": the revoked certificate no longer authenticates it",
        function () {
    assert.ok(refusedClient(r), r.status + " " + r.text.slice(0, 300));
  });
  r = await tlsPost(tokenUrl, grant, second.tls);
  check(realm + ": its other certificate still does", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.strictEqual(claimsOf(r.json.access_token).cnf["x5t#S256"],
                       thumbprintOf(second.pem));
  });
  log.debug("Leaving tlsClientAuth().");
}

// RFC 8705 section 2.2, by a certificate nobody issued.
async function selfSignedTlsClientAuth(realm) {
  log.debug("Entering selfSignedTlsClientAuth(). " + realm);
  log.info("=== 3. " + realm + ": self_signed_tls_client_auth ===");
  const rb = realmBase(realm);
  const tokenUrl = rb + "/oauth2/token";
  const mine = selfSigned(SELF_APP);
  const stranger = selfSigned(SELF_APP);
  const der = new nodeCrypto.X509Certificate(mine.cert).raw
    .toString("base64");
  const jwk = Object.assign(nodeCrypto.createPublicKey(mine.cert)
    .export({ format: "jwk" }), { kid: "self", x5c: [der] });
  await ok(rb + "/admin-api/applications/create", {
    identifier: SELF_APP, name: "#293 " + SELF_APP,
    protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: SELF_APP,
              oauthTokenEndpointAuthMethod: "self_signed_tls_client_auth",
              oauthJwks: JSON.stringify({ keys: [jwk] }) } },
    realm + ": created " + SELF_APP + " with the certificate in its jwks");
  const grant = { grant_type: "client_credentials", client_id: SELF_APP };
  let r = await tlsPost(tokenUrl, grant, mine);
  check(realm + ": the self-signed certificate its jwks names as an x5c " +
        "authenticates it, and the token is bound to it", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    const claims = claimsOf(r.json.access_token);
    assert.strictEqual(claims.client_id, SELF_APP);
    assert.strictEqual(claims.cnf && claims.cnf["x5t#S256"],
                       thumbprintOf(mine.cert), JSON.stringify(claims.cnf));
  });
  r = await recording(realm, "STS-OAUTH-0016", function () {
    return tlsPost(tokenUrl, grant, stranger);
  });
  check(realm + ": another self-signed certificate is refused " +
        "invalid_client (STS-OAUTH-0016)", function () {
    assert.ok(refusedClient(r), r.status + " " + r.text.slice(0, 300));
    assert.ok(r.recorded, "no audit row carries STS-OAUTH-0016");
  });
  r = await recording(realm, "STS-OAUTH-0015", function () {
    return tlsPost(tokenUrl, { grant_type: "client_credentials",
                               client_id: SELF_EMPTY }, mine);
  });
  check(realm + ": a client with nothing registered is refused " +
        "invalid_client (STS-OAUTH-0015)", function () {
    assert.ok(refusedClient(r), r.status + " " + r.text.slice(0, 300));
    assert.ok(r.recorded, "no audit row carries STS-OAUTH-0015");
  });
  log.debug("Leaving selfSignedTlsClientAuth().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving client authentication at " + base);
  await setUp();
  for (const realm of [PROD, DEV]) {
    await clientSecretJwt(realm);
    await tlsClientAuth(realm);
    await selfSignedTlsClientAuth(realm);
  }
  assert.ok(checks >= FLOOR, "only " + checks + " checks ran; a section has " +
            "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_client_authentication")
  .description("#293: client_secret_jwt, tls_client_auth and " +
    "self_signed_tls_client_auth at the token endpoint, for clients created " +
    "through /admin-api, in a development and a product realm.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
