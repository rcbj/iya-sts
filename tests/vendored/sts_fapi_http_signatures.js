// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_fapi_http_signatures.js
//
// ===========================================================================
// FAPI 2.0 HTTP SIGNATURES AT THE RESOURCE SERVERS, OVER HTTP, IN A
// THROWAWAY TRUST REALM (#178, the draft of 26 June 2026).
//
// A client with an ES256 key in its registered jwks gets a client-credentials
// token for `scim:read`, and calls `GET /scim/v2/Users` in the realm, which
// goes through the same access-token door as every resource server here:
//
//   a. off (the default): an unsigned request is answered and the answer is
//      NOT signed;
//   b. a signed request (tag "fapi-2-request", @method, @target-uri,
//      authorization, created, keyid) is answered 200, and the answer IS
//      signed, because the request was. The answer carries a Content-Digest
//      of its body, a "fapi-2-response" signature by the realm key its JWKS
//      publishes under the keyid, covering @status and content-digest, the
//      request's @method and @target-uri by ;req, every component the
//      request signature covered, and the request's Signature and
//      Signature-Input members by ;key. The job verifies all of it with its
//      own code and the realm's published key;
//   c. what a signed request is refused for, each 401 invalid_request:
//      authorization not covered, created 2 minutes old, a keyid the client
//      never registered, the wrong key, a target URI other than the one
//      signed;
//   d. `oauth2.httpSignatures=require-requests` in the realm: an unsigned
//      request is 401, a signed one 200;
//   e. `sign-responses`: an unsigned request's answer is signed;
//   f. the client flag: `oauthHttpSignedRequests=TRUE` through /admin-api
//      makes an unsigned request from THAT client 401 with the setting off,
//      and a value other than TRUE or FALSE is refused and does not land.
//
// THE SIGNER AND VERIFIER HERE ARE THIS FILE'S OWN, for `sts_step_up.js`'s
// TOTP reason: a signature base built by the service's own module at both
// ends would prove only that one function agrees with itself. They cover the
// handful of component kinds this job uses, plain fields and the derived
// components, and nothing else.
//
// ---------------------------------------------------------------------------
// WHY IT IS THIS REPOSITORY'S OWN (`local: true`). tests/CLAUDE.md's second
// question: it is asserted over HTTP against a running service, and the
// setting and the client flag are written through `/admin-api`.
//
// WHAT IT LEAVES BEHIND: its realm, left STANDING (tests/CLAUDE.md, *NO JOB
// REMOVES A REALM*), with the one application. The setting it changes in
// that realm is put back with `/admin-api/config/reset` in a `finally`.
// ===========================================================================

const assert = require("assert");
const nodeCrypto = require("crypto");
const { Command, Option } = require("commander");
const names = require("./random_username.js");

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
var log = bunyan.createLogger({ name: "sts_fapi_http_signatures",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");
var api = base + "/admin-api";

const STAMP = names.runStamp();
const REALM = ("fapihs-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                               .slice(0, 31);
const R = "/realm/" + REALM;
const realmBase = base + R;
const realmApi = realmBase + "/admin-api";
const CLIENT = "fapihs-client-" + STAMP;
const SECRET = "fapihs-secret-" + STAMP + "-0123456789abcdef";
const RESOURCE = realmBase + "/scim/v2/Users?count=1";

// The client's key, made here and never written down (rcbj's rule on key
// material), and a second key it never registered.
const CLIENT_KEY = nodeCrypto.generateKeyPairSync("ec",
                                                  { namedCurve: "P-256" });
const STRANGER_KEY = nodeCrypto.generateKeyPairSync("ec",
                                                    { namedCurve: "P-256" });
const KID = "fapihs-" + STAMP;

const FLOOR = 25;
var checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  ✓ " + what);
  log.debug("Leaving check().");
}

function form(o) {
  log.debug("Entering form().");
  log.debug("Leaving form().");
  return new URLSearchParams(o).toString();
}

async function send(url, options) {
  log.debug("Entering send(). url=" + url);
  const r = await fetch(url, Object.assign({ redirect: "manual" },
                                           options || {}));
  const bytes = Buffer.from(await r.arrayBuffer());
  const raw = bytes.toString("utf8");
  let body = null;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in send(): " + ((e && e.message) || e));
    // Not JSON. The caller reads `raw`.
    body = null;
  }
  log.debug("Leaving send(). status=" + r.status);
  return { status: r.status, body: body, raw: raw, bytes: bytes,
           headers: r.headers };
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

// ---------------------------------------------------------------------------
// THE JOB'S OWN RFC 9421: the base for derived components and plain fields
// (sections 2.1, 2.2, 2.4 and 2.5), ES256 as r||s (section 3.3.7 with RFC
// 7518 section 3.4).
// ---------------------------------------------------------------------------
function componentLine(id, message) {
  log.debug("Entering componentLine(). " + id);
  const m = /^"([^"]+)"((?:;[a-z-]+(?:="[^"]*")?)*)$/.exec(id);
  assert.ok(m, "a component identifier this job cannot read: " + id);
  const name = m[1];
  const params = m[2];
  const from = /;req(;|$)/.test(params) ? message.request : message;
  const key = /;key="([^"]*)"/.exec(params);
  let value;
  if (name === "@status") {
    value = String(from.status);
  } else if (name === "@method") {
    value = from.method;
  } else if (name === "@target-uri") {
    value = from.targetUri;
  } else if (key) {
    // A Dictionary member: in this job, the request's one signature, so the
    // member's value is the field's text after "<label>=".
    const text = String(from.headers[name] || "");
    assert.ok(text.indexOf(key[1] + "=") === 0,
              name + " has no member " + key[1] + ": " + text);
    value = text.slice(key[1].length + 1);
  } else {
    value = String(from.headers[name] === undefined ? "" :
                   from.headers[name]).trim();
    assert.ok(from.headers[name] !== undefined,
              "the covered field " + name + " is absent");
  }
  log.debug("Leaving componentLine().");
  return id + ": " + value;
}

function baseOf(components, paramsText, message) {
  log.debug("Entering baseOf().");
  const lines = components.map(function (id) {
    return componentLine(id, message);
  });
  lines.push('"@signature-params": (' + components.join(" ") + ")" +
             paramsText);
  log.debug("Leaving baseOf().");
  return lines.join("\n");
}

function signRequest(url, token, options) {
  log.debug("Entering signRequest().");
  const o = options || {};
  const components = o.components ||
    ['"@method"', '"@target-uri"', '"authorization"'];
  const created = Math.floor(Date.now() / 1000) - (o.age || 0);
  const paramsText = ";created=" + created + ';keyid="' + (o.kid || KID) +
                     '";tag="fapi-2-request"';
  const headers = { authorization: "Bearer " + token };
  const message = { method: "GET", targetUri: o.signedUrl || url,
                    headers: headers };
  const signature = nodeCrypto.sign("sha256",
    Buffer.from(baseOf(components, paramsText, message), "ascii"),
    { key: (o.key || CLIENT_KEY).privateKey, dsaEncoding: "ieee-p1363" });
  headers["signature-input"] = "sig1=(" + components.join(" ") + ")" +
                               paramsText;
  headers.signature = "sig1=:" + signature.toString("base64") + ":";
  log.debug("Leaving signRequest().");
  return { method: "GET", targetUri: url, headers: headers };
}

async function call(request) {
  log.debug("Entering call().");
  const r = await send(request.targetUri, { headers: request.headers });
  log.debug("Leaving call().");
  return r;
}

// The response signature, verified with the realm's published key: the
// components it covers, its parameters, and the bytes.
async function verifyResponse(r, request) {
  log.debug("Entering verifyResponse().");
  const input = r.headers.get("signature-input") || "";
  const sig = r.headers.get("signature") || "";
  const m = /^([a-zA-Z0-9_*.-]+)=\(([^)]*)\)(.*)$/.exec(input);
  assert.ok(m, "no response Signature-Input: " + JSON.stringify(input));
  const label = m[1];
  const components = m[2].split(" ").filter(Boolean);
  const paramsText = m[3];
  const sm = new RegExp("^" + label + "=:([A-Za-z0-9+/=]+):$").exec(sig);
  assert.ok(sm, "no Signature member " + label + ": " + sig);
  const kid = /;keyid="([^"]*)"/.exec(paramsText);
  assert.ok(kid, "the response signature names no keyid: " + paramsText);
  const jwks = await send(realmBase + "/oauth2/jwks");
  const jwk = ((jwks.body && jwks.body.keys) || []).filter(function (k) {
    return k.kid === kid[1];
  })[0];
  assert.ok(jwk, "the realm's JWKS has no key " + kid[1]);
  assert.strictEqual(jwk.alg, "ES256", JSON.stringify(jwk));
  const headers = {};
  r.headers.forEach(function (value, name) {
    headers[name] = value;
  });
  const message = { status: r.status, headers: headers, request: request };
  const verified = nodeCrypto.verify("sha256",
    Buffer.from(baseOf(components, paramsText, message), "ascii"),
    { key: nodeCrypto.createPublicKey({ key: jwk, format: "jwk" }),
      dsaEncoding: "ieee-p1363" },
    Buffer.from(sm[1], "base64"));
  log.debug("Leaving verifyResponse(). " + verified);
  return { verified: verified, components: components,
           params: paramsText };
}

function refusedAs401(r, what) {
  log.debug("Entering refusedAs401().");
  check(what + " — 401 invalid_request", function () {
    assert.strictEqual(r.status, 401, r.status + " " + r.raw.slice(0, 300));
    assert.ok(/error="invalid_request"/.test(
      r.headers.get("www-authenticate") || ""),
      r.headers.get("www-authenticate"));
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(r.raw),
              "an error code reached the client: " + r.raw);
  });
  log.debug("Leaving refusedAs401().");
}

async function resetQuietly(key) {
  log.debug("Entering resetQuietly(). key=" + key);
  try {
    const r = await postJson(realmApi + "/config/reset", { key: key });
    if (r.status !== 200) {
      log.warn("resetting " + key + " in " + REALM + " answered " + r.status +
               " " + r.raw.slice(0, 200));
    }
  } catch (e) {
    // A `finally` that throws replaces the failure that got there
    // (tests/CLAUDE.md), so the reset reports and does not throw.
    log.debug("Caught in resetQuietly(): " + ((e && e.message) || e));
    log.warn("resetting " + key + " in " + REALM + " failed: " +
             ((e && e.message) || e));
  }
  log.debug("Leaving resetQuietly().");
}

async function setUp() {
  log.debug("Entering setUp().");
  log.info("=== 0. a throwaway realm " + REALM + " and a client ===");
  await ok(api + "/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "FAPI HTTP Signatures " + STAMP },
    "created the realm");
  const jwk = Object.assign(CLIENT_KEY.publicKey.export({ format: "jwk" }),
                            { kid: KID, alg: "ES256", use: "sig" });
  await ok(realmApi + "/applications/create", { identifier: CLIENT,
    kind: "oauth2-client", name: CLIENT, protocols: ["oauth2"],
    // SCIM's scopes are issued only to a client that declares them (#110).
    fields: { oauthClientId: [CLIENT], oauthClientSecret: SECRET,
              oauthTokenEndpointAuthMethod: "client_secret_post",
              oauthAllowedScope: ["scim:read"],
              oauthGrantType: ["client_credentials"],
              oauthJwks: JSON.stringify({ keys: [jwk] }) } },
    "created the client with its key in oauthJwks");
  const r = await send(realmBase + "/oauth2/token", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form({ grant_type: "client_credentials", client_id: CLIENT,
                 client_secret: SECRET, scope: "scim:read" }) });
  assert.ok(r.body && r.body.access_token,
            "a scim:read token: " + r.raw.slice(0, 300));
  log.debug("Leaving setUp().");
  return r.body.access_token;
}

async function offByDefault(token) {
  log.debug("Entering offByDefault().");
  log.info("=== a. off: an unsigned request, an unsigned answer ===");
  const request = { method: "GET", targetUri: RESOURCE,
                    headers: { authorization: "Bearer " + token } };
  const r = await call(request);
  check("an unsigned request is answered 200, and the answer carries no " +
        "Signature", function () {
    assert.strictEqual(r.status, 200, r.status + " " + r.raw.slice(0, 300));
    assert.strictEqual(r.headers.get("signature"), null);
  });
  log.debug("Leaving offByDefault().");
}

async function aSignedRequest(token) {
  log.debug("Entering aSignedRequest().");
  log.info("=== b. a signed request, and its signed answer ===");
  const request = signRequest(RESOURCE, token);
  const r = await call(request);
  check("a signed request is answered 200", function () {
    assert.strictEqual(r.status, 200, r.status + " " + r.raw.slice(0, 300));
  });
  check("the answer carries a sha-256 Content-Digest of its body (RFC 9530)",
        function () {
    const expected = "sha-256=:" + nodeCrypto.createHash("sha256")
      .update(r.bytes).digest("base64") + ":";
    assert.strictEqual(r.headers.get("content-digest"), expected);
  });
  const v = await verifyResponse(r, request);
  check("the answer's fapi-2-response signature verifies with the realm " +
        "key the JWKS publishes under its keyid", function () {
    assert.ok(v.verified, JSON.stringify(v));
    assert.ok(/;tag="fapi-2-response"/.test(v.params), v.params);
    assert.ok(/;created=\d+/.test(v.params), v.params);
  });
  check("it covers @status and content-digest, the request's @method, " +
        "@target-uri and authorization by ;req, and the request's " +
        "Signature and Signature-Input members by ;key (draft 5.3.2.1)",
        function () {
    ['"@status"', '"content-digest"', '"@method";req',
     '"@target-uri";req', '"authorization";req',
     '"signature";req;key="sig1"', '"signature-input";req;key="sig1"']
      .forEach(function (id) {
        assert.ok(v.components.indexOf(id) >= 0,
                  id + " is not covered: " + v.components.join(" "));
      });
  });
  const other = await verifyResponse(r, signRequest(RESOURCE, token));
  check("the same answer does not verify against a different request",
        function () {
    assert.ok(!other.verified);
  });
  log.debug("Leaving aSignedRequest().");
}

async function theRefusals(token) {
  log.debug("Entering theRefusals().");
  log.info("=== c. what a signed request is refused for ===");
  refusedAs401(await call(signRequest(RESOURCE, token,
    { components: ['"@method"', '"@target-uri"'] })),
    "a signature that does not cover authorization");
  refusedAs401(await call(signRequest(RESOURCE, token, { age: 120 })),
    "a signature created two minutes ago");
  refusedAs401(await call(signRequest(RESOURCE, token, { kid: "nobody" })),
    "a keyid the client never registered");
  refusedAs401(await call(signRequest(RESOURCE, token,
    { key: STRANGER_KEY })), "a signature by a key the client did not " +
    "register, under its keyid");
  refusedAs401(await call(signRequest(RESOURCE, token,
    { signedUrl: realmBase + "/scim/v2/Users?count=2" })),
    "a request whose target URI is not the one signed");
  log.debug("Leaving theRefusals().");
}

async function theSetting(token) {
  log.debug("Entering theSetting().");
  log.info("=== d, e. oauth2.httpSignatures in the realm ===");
  try {
    await ok(realmApi + "/config/set",
             { key: "oauth2.httpSignatures", value: "require-requests" },
             "required signed requests in the realm");
    refusedAs401(await call({ method: "GET", targetUri: RESOURCE,
      headers: { authorization: "Bearer " + token } }),
      "require-requests: an unsigned request");
    const signed = await call(signRequest(RESOURCE, token));
    check("require-requests: a signed request is answered 200", function () {
      assert.strictEqual(signed.status, 200,
                         signed.status + " " + signed.raw.slice(0, 300));
    });
    await ok(realmApi + "/config/set",
             { key: "oauth2.httpSignatures", value: "sign-responses" },
             "signed responses in the realm");
    const request = { method: "GET", targetUri: RESOURCE,
                      headers: { authorization: "Bearer " + token } };
    const r = await call(request);
    const v = await verifyResponse(r, request);
    check("sign-responses: an unsigned request's answer is signed, covering " +
          "@status and the request's @method and @target-uri", function () {
      assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
      assert.ok(v.verified, JSON.stringify(v));
      assert.ok(v.components.indexOf('"@method";req') >= 0 &&
                v.components.indexOf('"@target-uri";req') >= 0,
                v.components.join(" "));
    });
  } finally {
    await resetQuietly("oauth2.httpSignatures");
  }
  log.debug("Leaving theSetting().");
}

async function theClientFlag(token) {
  log.debug("Entering theClientFlag().");
  log.info("=== f. oauthHttpSignedRequests on the client ===");
  const refused = await postJson(realmApi + "/applications/set",
    { application: CLIENT, attribute: "oauthHttpSignedRequests",
      value: "yes" });
  check("a value other than TRUE or FALSE is refused", function () {
    assert.strictEqual(refused.status, 400,
                       refused.status + " " + refused.raw);
    assert.strictEqual(refused.body.ok, false, refused.raw);
  });
  const unsigned = { method: "GET", targetUri: RESOURCE,
                     headers: { authorization: "Bearer " + token } };
  const still = await call(unsigned);
  check("and it did not land: an unsigned request is still answered",
        function () {
    assert.strictEqual(still.status, 200, still.raw.slice(0, 300));
  });
  await ok(realmApi + "/applications/set",
           { application: CLIENT, attribute: "oauthHttpSignedRequests",
             value: "TRUE" }, "set oauthHttpSignedRequests=TRUE");
  refusedAs401(await call(unsigned),
               "the client's flag: its unsigned request, with the setting " +
               "off");
  const signed = await call(signRequest(RESOURCE, token));
  check("the client's flag: its signed request is answered 200", function () {
    assert.strictEqual(signed.status, 200, signed.raw.slice(0, 300));
  });
  await ok(realmApi + "/applications/set",
           { application: CLIENT, attribute: "oauthHttpSignedRequests",
             value: "FALSE" }, "set oauthHttpSignedRequests=FALSE");
  log.debug("Leaving theClientFlag().");
}

async function test() {
  log.debug("Entering test().");
  log.info("FAPI 2.0 HTTP Signatures against " + base + " in the realm " +
           REALM + ", client " + CLIENT);
  const token = await setUp();
  await offByDefault(token);
  await aSignedRequest(token);
  await theRefusals(token);
  await theSetting(token);
  await theClientFlag(token);
  assert.ok(checks >= FLOOR,
    "only " + checks + " checks ran, against a floor of " + FLOOR + ".");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_fapi_http_signatures")
  .description("FAPI 2.0 HTTP Signatures (draft of 26 June 2026) over HTTP " +
      "in a throwaway realm: signed requests verified at /scim/v2, signed " +
      "responses verified with the realm's published key, the refusals, " +
      "oauth2.httpSignatures and the client's oauthHttpSignedRequests.")
  // Accepted and ignored: the parent project's run-report.js passes --url to
  // every job; this repository's (tests/tools/run-report.js) passes none.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
