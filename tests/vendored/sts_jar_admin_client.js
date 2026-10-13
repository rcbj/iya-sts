// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_jar_admin_client.js
//
// ---------------------------------------------------------------------------
// A JWT-SECURED AUTHORIZATION REQUEST CLIENT AN ADMINISTRATOR CREATED
// (RFC 9101), OVER THE WIRE (#293, WP2, 2026-10-13).
//
// `docs/configure-oidc-flows.md` gives the recipe for a JAR client written
// through `/admin-api` with `oauthRequestUri`, `oauthRequestObjectSigningAlg`,
// `oauthJwksUri` and `oauthRequireSignedRequestObject`, and no over-HTTP job
// set any of the four: `tests/rfc9101_request_objects.js` drives them in
// process, and `sts_fapi_advanced.js` sends objects by value. This job creates
// such a client and serves its request objects and its key set from a
// listener of its own, which the SERVICE dials:
//
//   1. THE DEVELOPMENT REALM, over plain http (which development allows,
//      `federation.outboundAllowHttp` on in the realm for the jwks_uri):
//      a signed object fetched from the registered request_uri, verified
//      with the key fetched from the registered jwks_uri, signs the person
//      in and ends at the client with the OBJECT's state; then the refusals
//      — a request_uri nobody registered (and the listener asserting it was
//      never asked for), an object signed with another algorithm than the
//      registered one, one signed by a key the jwks does not hold, and an
//      unsigned one by value while a signed one is required.
//   2. THE PRODUCT REALM: a client registering a plain-http request_uri is
//      refused at the create (RFC 9101 section 5.2), and the listener
//      asserts nothing was dialled. Where a directory is shared
//      with the service (`outbound_test_ca.js`) the positive runs again over
//      https, under a CA made at run time that the realm trusts through
//      `federation.outboundCaFile`; where none is (a hand run against a
//      service started elsewhere) that half SKIPS, saying so.
//
// THE LISTENER runs in this job on OUTBOUND_TEST_HOST (or GNAP_PUSH_HOST),
// the address the service reaches the runner at, bound on every interface.
//
// OWNED HERE (local: true).
// ---------------------------------------------------------------------------

const assert = require("assert");
const http = require("http");
const https = require("https");
const nodeCrypto = require("crypto");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const registry = require("./sts_applications.js");
const authnSignin = require("./authn_signin");
const testCa = require("./outbound_test_ca.js");

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
var log = bunyan.createLogger({ name: "sts_jar_admin_client",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const HOST = process.env.OUTBOUND_TEST_HOST || process.env.GNAP_PUSH_HOST ||
             "localhost";
const STAMP = names.runStamp();
const TAG = STAMP.toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 12);
const DEV = "jar-d-" + TAG;
const PROD = "jar-p-" + TAG;
const PERSON = names.usernameFor("jar-person");
const PASSWORD = "Jar-" + nodeCrypto.randomBytes(9).toString("base64url") +
  "-Aa1!";
const SECRET = "jar-secret-" + TAG + "-" +
  nodeCrypto.randomBytes(16).toString("hex");
const REDIRECT = "https://rp.jar.example.test/cb";
const APP = "jar-client-" + TAG;
// Eight checks with no directory shared with the service; the product https
// half adds three.
const FLOOR = testCa.caLocation() ? 11 : 8;

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

function b64u(value) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(typeof value === "string" ? value :
                     JSON.stringify(value)).toString("base64url");
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

// THE CLIENT'S KEYS: ES256 (the registered algorithm, published at the
// jwks_uri), and two that must not verify — an RS256 key in the same set,
// for the wrong-algorithm case, and an ES256 key in no set at all.
function keyPair(type, kid) {
  log.debug("Entering keyPair(). " + kid);
  const pair = type === "ec"
    ? nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" })
    : nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = Object.assign(pair.publicKey.export({ format: "jwk" }),
    { kid: kid, use: "sig", alg: type === "ec" ? "ES256" : "RS256" });
  log.debug("Leaving keyPair().");
  return { privateKey: pair.privateKey, jwk: jwk, kid: kid,
           alg: jwk.alg };
}
const ES = keyPair("ec", "jar-es-" + TAG);
const RS = keyPair("rsa", "jar-rs-" + TAG);
const STRANGER = keyPair("ec", "jar-es-" + TAG);

function signed(key, claims) {
  log.debug("Entering signed(). " + key.alg);
  const input = b64u({ alg: key.alg, kid: key.kid,
                       typ: "oauth-authz-req+jwt" }) + "." + b64u(claims);
  const signature = key.alg === "ES256"
    ? nodeCrypto.sign("sha256", Buffer.from(input),
                      { key: key.privateKey, dsaEncoding: "ieee-p1363" })
    : nodeCrypto.sign("sha256", Buffer.from(input), key.privateKey);
  log.debug("Leaving signed().");
  return input + "." + signature.toString("base64url");
}

function unsigned(claims) {
  log.debug("Entering unsigned().");
  log.debug("Leaving unsigned().");
  return b64u({ alg: "none", typ: "oauth-authz-req+jwt" }) + "." +
    b64u(claims) + ".";
}

// The claims of a request object for APP at `realm`, and what the flow
// needs to finish it.
function requestClaims(issuer) {
  log.debug("Entering requestClaims().");
  const verifier = nodeCrypto.randomBytes(32).toString("base64url");
  const now = Math.floor(Date.now() / 1000);
  const state = "obj-" + nodeCrypto.randomBytes(6).toString("hex");
  const claims = {
    iss: APP, aud: issuer, client_id: APP, response_type: "code",
    redirect_uri: REDIRECT, scope: "openid", state: state,
    nonce: "n-" + nodeCrypto.randomBytes(9).toString("base64url"),
    code_challenge: nodeCrypto.createHash("sha256").update(verifier)
      .digest("base64url"),
    code_challenge_method: "S256", iat: now, nbf: now, exp: now + 300,
    jti: nodeCrypto.randomBytes(12).toString("hex") };
  log.debug("Leaving requestClaims().");
  return { claims: claims, verifier: verifier, state: state };
}

// THE CLIENT'S HOST: serves /req/<name> (a request object) and /jwks, over
// http or, given `tls`, https; remembers every path asked for.
async function clientHost(tls) {
  log.debug("Entering clientHost(). tls=" + !!tls);
  const objects = {};
  const hits = [];
  const handler = function (req, res) {
    const path = String(req.url || "").split("?")[0];
    hits.push(path);
    if (path === "/jwks") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ keys: [ES.jwk, RS.jwk] }));
      return;
    }
    const name = path.replace(/^\/req\//, "");
    if (objects[name]) {
      res.writeHead(200,
        { "Content-Type": "application/oauth-authz-req+jwt" });
      res.end(objects[name]);
      return;
    }
    res.writeHead(404);
    res.end();
  };
  const server = tls ? https.createServer(tls, handler)
                     : http.createServer(handler);
  await new Promise(function (resolve) {
    server.listen(0, "0.0.0.0", resolve);
  });
  const origin = (tls ? "https://" : "http://") + HOST + ":" +
    server.address().port;
  log.debug("Leaving clientHost(). " + origin);
  return { origin: origin, objects: objects, hits: hits,
           close: function () {
             server.close();
           } };
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

// The error a refused authorization request carries, wherever it is: a
// redirect to the client, or a page shown in its place.
function refusalOf(r) {
  log.debug("Entering refusalOf().");
  let error = "";
  if (r.location && r.location.indexOf(REDIRECT) === 0) {
    error = new URL(r.location).searchParams.get("error") || "";
  } else {
    const found = new RegExp("\\b(invalid_request_uri|" +
      "invalid_request_object|invalid_request)\\b").exec(r.text || "");
    error = found ? found[1] : "";
  }
  log.debug("Leaving refusalOf(). " + error);
  return error;
}

function shown(r) {
  log.debug("Entering shown().");
  log.debug("Leaving shown().");
  return r.status + " " + (r.location || "") + " " +
    String(r.text || "").replace(/<style[\s\S]*?<\/style>/, "")
      .replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").slice(0, 400);
}

function clientBody(host) {
  log.debug("Entering clientBody().");
  log.debug("Leaving clientBody().");
  return {
    identifier: APP, name: "#293 JAR client " + TAG,
    protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: APP, oauthRedirectUri: [REDIRECT],
              oauthClientSecret: SECRET,
              oauthTokenEndpointAuthMethod: "client_secret_basic",
              oauthRequestUri: [host.origin + "/req/good"],
              oauthRequestObjectSigningAlg: "ES256",
              oauthJwksUri: host.origin + "/jwks",
              oauthRequireSignedRequestObject: "TRUE" } };
}

async function makeClient(realm, host) {
  log.debug("Entering makeClient(). " + realm);
  const api = realmBase(realm) + "/admin-api";
  await ok(api + "/applications/create", clientBody(host),
           realm + ": created the JAR client with its four attributes");
  await ok(api + "/consent/grant-global-consent",
           { client: APP, scope: "openid" }, realm + ": consented openid");
  log.debug("Leaving makeClient().");
}

// The positive: a registered request_uri, a signed object, the person signed
// in, and the OBJECT's state at the client.
async function goodRequest(realm, host) {
  log.debug("Entering goodRequest(). " + realm);
  const rb = realmBase(realm);
  const issuer = (await call("GET", rb +
    "/.well-known/oauth-authorization-server")).json.issuer;
  const asked = requestClaims(issuer);
  host.objects.good = signed(ES, asked.claims);
  const before = host.hits.length;
  const b = browser();
  // The query names another state; RFC 9101 section 6.3 says the object's
  // is the one in force.
  let r = await b.go("GET", "/realm/" + realm + "/oauth2/authorize?" + form({
    client_id: APP, request_uri: host.origin + "/req/good",
    state: "from-the-query" }));
  const fetched = host.hits.slice(before);
  check(realm + ": a request_uri the client registered is fetched, its " +
        "object verified with the key at the registered jwks_uri, and the " +
        "person sent to sign in", function () {
    assert.ok(sentToSignIn(r), shown(r));
    assert.ok(fetched.indexOf("/req/good") >= 0, JSON.stringify(fetched));
  });
  r = await authnSignin.signInWithJar(rb, r.location,
    { action: "login", username: PERSON, password: PASSWORD }, b.jar);
  for (let hops = 0; hops < 6 && (r.status === 302 || r.status === 303) &&
       String(r.location).indexOf(REDIRECT) !== 0; hops++) {
    r = await b.go("GET", r.location);
  }
  const back = String(r.location).indexOf(REDIRECT) === 0
    ? new URL(r.location).searchParams : new URLSearchParams();
  check(realm + ": the flow ends at the client with a code and the " +
        "OBJECT's state, not the query's", function () {
    assert.ok(back.get("code"), shown(r));
    assert.strictEqual(back.get("state"), asked.state, r.location);
  });
  const token = await call("POST", rb + "/oauth2/token",
    form({ grant_type: "authorization_code", code: back.get("code"),
           redirect_uri: REDIRECT, code_verifier: asked.verifier }),
    { "Content-Type": "application/x-www-form-urlencoded",
      Authorization: "Basic " + Buffer.from(APP + ":" + SECRET)
        .toString("base64") });
  check(realm + ": and the code is redeemed with the object's PKCE " +
        "verifier", function () {
    assert.strictEqual(token.status, 200, token.text.slice(0, 300));
  });
  log.debug("Leaving goodRequest().");
}

async function development(host) {
  log.debug("Entering development().");
  log.info("=== 1. " + DEV + ": the JAR client over the wire ===");
  const rb = realmBase(DEV);
  const issuer = (await call("GET", rb +
    "/.well-known/oauth-authorization-server")).json.issuer;
  await goodRequest(DEV, host);
  const nobody = "/req/unregistered-" + TAG;
  host.objects["unregistered-" + TAG] =
    signed(ES, requestClaims(issuer).claims);
  let r = await browser().go("GET", "/realm/" + DEV +
    "/oauth2/authorize?" + form({ client_id: APP,
                                  request_uri: host.origin + nobody }));
  check(DEV + ": a request_uri the client did not register is refused, " +
        "and never dialled", function () {
    assert.ok(!sentToSignIn(r), shown(r));
    assert.ok(/^invalid_request/.test(refusalOf(r)), shown(r));
    assert.ok(host.hits.indexOf(nobody) < 0, JSON.stringify(host.hits));
  });
  host.objects.good = signed(RS, requestClaims(issuer).claims);
  r = await browser().go("GET", "/realm/" + DEV + "/oauth2/authorize?" +
    form({ client_id: APP, request_uri: host.origin + "/req/good" }));
  check(DEV + ": an object signed RS256 by a key in the client's own set " +
        "is refused — the registered algorithm is ES256", function () {
    assert.ok(!sentToSignIn(r), shown(r));
    assert.ok(/^invalid_request/.test(refusalOf(r)), shown(r));
  });
  host.objects.good = signed(STRANGER, requestClaims(issuer).claims);
  r = await browser().go("GET", "/realm/" + DEV + "/oauth2/authorize?" +
    form({ client_id: APP, request_uri: host.origin + "/req/good" }));
  check(DEV + ": an object signed by a key the jwks_uri does not hold is " +
        "refused", function () {
    assert.ok(!sentToSignIn(r), shown(r));
    assert.ok(/^invalid_request/.test(refusalOf(r)), shown(r));
  });
  r = await browser().go("GET", "/realm/" + DEV + "/oauth2/authorize?" +
    form({ client_id: APP,
           request: unsigned(requestClaims(issuer).claims) }));
  check(DEV + ": an unsigned object by value is refused while " +
        "oauthRequireSignedRequestObject is TRUE", function () {
    assert.ok(!sentToSignIn(r), shown(r));
    assert.ok(/^invalid_request/.test(refusalOf(r)), shown(r));
  });
  log.debug("Leaving development().");
}

async function product(plainHost) {
  log.debug("Entering product().");
  log.info("=== 2. " + PROD + ": product ===");
  const rb = realmBase(PROD);
  const before = plainHost.hits.length;
  // RFC 9101 SECTION 5.2, AT THE DOOR (found by this job's first run):
  // product refuses a plain-http request_uri when it is REGISTERED, so the
  // authorization endpoint never meets one.
  const refused = await call("POST", rb + "/admin-api/applications/create",
                             clientBody(plainHost));
  const listed = await call("GET", rb + "/admin-api/applications?" +
                            form({ application: APP }));
  check(PROD + ": a client registering a plain-http request_uri is refused " +
        "at the create, and nothing is dialled", function () {
    assert.strictEqual(refused.status, 400, refused.text.slice(0, 300));
    assert.ok(/RFC 9101 section 5\.2/.test(refused.text),
              refused.text.slice(0, 300));
    assert.ok(!(listed.json && listed.json.found), listed.text.slice(0, 200));
    assert.strictEqual(plainHost.hits.length, before,
                       JSON.stringify(plainHost.hits.slice(before)));
  });
  const where = testCa.caLocation();
  if (!where) {
    log.info(PROD + ": the https half is skipped. " + testCa.skipReason());
    log.debug("Leaving product(). No shared directory.");
    return;
  }
  const ca = await testCa.makeCa();
  const caFile = testCa.publishCa(ca);
  await setting(PROD, "federation.outboundCaFile", caFile);
  const secure = await clientHost(await testCa.listenerCertificate(ca, HOST));
  try {
    await makeClient(PROD, secure);
    await goodRequest(PROD, secure);
  } finally {
    secure.close();
  }
  log.debug("Leaving product().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving a JAR client created through /admin-api at " + base +
           "; the client's host is " + HOST);
  await ok(base + "/admin-api/realms/create",
           { id: PROD, domain: PROD + ".example.net", name: "#293 product",
             overrides: { "global.mode": "product" } },
           "created the product realm");
  await ok(base + "/admin-api/realms/create",
           { id: DEV, domain: DEV + ".example.net",
             name: "#293 development",
             overrides: { "global.mode": "development" } },
           "created the development realm");
  const host = await clientHost(null);
  try {
    for (const realm of [PROD, DEV]) {
      // RISK SCORING (#62) is off for sts_admin_client_policies.js's reason.
      await setting(realm, "risk.assessSignIns", false);
      await registry.ensurePerson(realmBase(realm), PERSON, PASSWORD);
    }
    await makeClient(DEV, host);
    // The jwks_uri goes through the federation outbound policy, which admits
    // plain http in development only and only with this setting.
    await setting(DEV, "federation.outboundAllowHttp", true);
    await development(host);
    await product(host);
  } finally {
    host.close();
  }
  assert.ok(checks >= FLOOR, "only " + checks + " checks ran; a section has " +
            "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_jar_admin_client")
  .description("#293: a JAR client created through /admin-api — request_uri " +
    "and jwks_uri fetched from this job's own host, the registered " +
    "algorithm and the signed-object requirement — in a development and a " +
    "product realm.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
