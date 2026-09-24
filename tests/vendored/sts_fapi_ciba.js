"use strict";
//
// File: sts_fapi_ciba.js
//
// ---------------------------------------------------------------------------
// FAPI-CIBA (#142, 2026-09-24), over HTTP: a throwaway realm (left behind)
// with CIBA on and then `oauth2.fapi=1-baseline` — FAPI-CIBA has no setting of
// its own; it is what CIBA becomes under any FAPI profile.
//
//   a. DISCOVERY: poll and ping, and push no longer.
//   b. REGISTRATION: a push client is refused under the profile; a poll
//      client with private_key_jwt is registered.
//   c. THE ENDPOINT: a push client registered before the profile was turned
//      on is refused (unauthorized_client); a request with no binding_message
//      is invalid_request; a request_context that is not a JSON object is
//      invalid_request; a conforming request with a request_context is
//      acknowledged.
//
// OWNED HERE (local: true): this repository's authorization server.
// ---------------------------------------------------------------------------

const assert = require("assert");
const nodeCrypto = require("crypto");
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
var log = bunyan.createLogger({ name: "sts_fapi_ciba",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var root = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("fciba-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                              .slice(0, 31);
const base = root + "/realm/" + REALM;
const api = base + "/admin-api";
const GRANT = "urn:openid:params:grant-type:ciba";
const HOLDER = names.usernameFor("fciba");
const PASSWORD = "Fciba-Passw0rd!-" + String(Date.now()).slice(-6);
const NOTIFY = "https://rp.fciba.example.test/notify";

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
    // Not JSON; the caller reads `raw`.
    body = null;
  }
  log.debug("Leaving send(). status=" + r.status);
  return { status: r.status, body: body, raw: raw };
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

function clientKey(kid) {
  log.debug("Entering clientKey().");
  const pair = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = pair.publicKey.export({ format: "jwk" });
  jwk.kid = kid;
  jwk.use = "sig";
  jwk.alg = "ES256";
  log.debug("Leaving clientKey().");
  return { privateKey: pair.privateKey, jwk: jwk };
}

// RFC 7523 section 3's client assertion, signed ES256, audienced to `aud`.
function assertion(clientId, key, aud) {
  log.debug("Entering assertion().");
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "ES256", typ: "JWT", kid: key.jwk.kid };
  const claims = { iss: clientId, sub: clientId, aud: aud,
                   jti: nodeCrypto.randomBytes(12).toString("base64url"),
                   iat: now, exp: now + 60 };
  const input = Buffer.from(JSON.stringify(header)).toString("base64url") +
                "." + Buffer.from(JSON.stringify(claims))
                  .toString("base64url");
  const sig = nodeCrypto.sign("sha256", Buffer.from(input),
    { key: key.privateKey, dsaEncoding: "ieee-p1363" });
  log.debug("Leaving assertion().");
  return input + "." + sig.toString("base64url");
}

function registration(key, mode) {
  log.debug("Entering registration(). " + mode);
  const out = { redirect_uris: ["https://rp.fciba.example.test/cb"],
                token_endpoint_auth_method: "private_key_jwt",
                token_endpoint_auth_signing_alg: "ES256",
                jwks: { keys: [key.jwk] },
                grant_types: [GRANT, "authorization_code"],
                response_types: ["code"], scope: "openid profile",
                backchannel_token_delivery_mode: mode };
  if (mode !== "poll") {
    out.backchannel_client_notification_endpoint = NOTIFY;
  }
  log.debug("Leaving registration().");
  return out;
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. a throwaway realm " + REALM + " ===");
  await ok(root + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "FAPI-CIBA " + STAMP },
    "created the realm");
  await ok(api + "/config/set", { key: "oauth2.ciba", value: true },
           "turned CIBA on");
  await ok(api + "/config/set", { key: "oauth2.openRegistration",
                                  value: true }, "opened registration");
  await registry.ensurePerson(base, HOLDER, PASSWORD);
  // A push client, registered while the realm is not yet under a profile.
  const pushKey = clientKey("push-" + STAMP);
  const pushed = await postJson(base + "/oauth2/register",
                                registration(pushKey, "push"));
  assert.strictEqual(pushed.status, 201, "the push client before FAPI: " +
                     pushed.raw.slice(0, 300));
  await ok(api + "/config/set", { key: "oauth2.fapi",
                                  value: "1-baseline" },
           "put the realm under FAPI 1.0 Baseline");

  log.info("=== a. discovery ===");
  const discovery = await send(base + "/.well-known/openid-configuration");
  const issuer = discovery.body.issuer;
  check("poll and ping are published, and push is not", function () {
    assert.deepStrictEqual(
      discovery.body.backchannel_token_delivery_modes_supported,
      ["poll", "ping"]);
  });

  log.info("=== b. registration ===");
  const refusedPush = await postJson(base + "/oauth2/register",
    registration(clientKey("push2-" + STAMP), "push"));
  const pollKey = clientKey("poll-" + STAMP);
  const poll = await postJson(base + "/oauth2/register",
                              registration(pollKey, "poll"));
  check("a push client is refused under the profile, a poll client " +
        "registered", function () {
    assert.strictEqual(refusedPush.status, 400, refusedPush.raw.slice(0, 300));
    assert.strictEqual(refusedPush.body.error, "invalid_client_metadata");
    assert.strictEqual(poll.status, 201, poll.raw.slice(0, 300));
  });

  log.info("=== c. the endpoint ===");
  const authorize = function (clientId, key, extra) {
    log.debug("Entering authorize().");
    log.debug("Leaving authorize().");
    return send(base + "/oauth2/bc-authorize", { method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(Object.assign({
        client_id: clientId, scope: "openid",
        client_assertion_type:
          "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        client_assertion: assertion(clientId, key, issuer),
        login_hint: HOLDER }, extra)).toString() });
  };
  const pushNow = await authorize(pushed.body.client_id, pushKey,
                                  { binding_message: "PUSH-1",
                                    client_notification_token: "t-" +
                                      STAMP });
  const noBinding = await authorize(poll.body.client_id, pollKey, {});
  const badContext = await authorize(poll.body.client_id, pollKey,
    { binding_message: "BIND-2", request_context: "[1, 2]" });
  const good = await authorize(poll.body.client_id, pollKey,
    { binding_message: "BIND-3",
      request_context: JSON.stringify({ device: "till 4",
                                        geolocation: "51.5,-0.1" }) });
  check("push refused (unauthorized_client), no binding_message and a " +
        "request_context that is not an object refused (invalid_request), " +
        "a conforming request acknowledged", function () {
    assert.strictEqual(pushNow.status, 400, pushNow.raw.slice(0, 300));
    assert.strictEqual(pushNow.body.error, "unauthorized_client");
    assert.strictEqual(noBinding.status, 400, noBinding.raw.slice(0, 300));
    assert.strictEqual(noBinding.body.error, "invalid_request");
    assert.strictEqual(badContext.status, 400, badContext.raw.slice(0, 300));
    assert.strictEqual(badContext.body.error, "invalid_request");
    assert.strictEqual(good.status, 200, good.raw.slice(0, 300));
    assert.ok(good.body.auth_req_id && good.body.interval > 0);
  });

  assert.ok(checks >= 3, "only " + checks + " checks ran");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

new Command()
  .description("FAPI-CIBA (#142): CIBA under a FAPI profile — poll and ping " +
    "only, a binding message required, request_context accepted.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
