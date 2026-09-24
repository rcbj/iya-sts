"use strict";
//
// File: sts_token_revocation.js
//
// ---------------------------------------------------------------------------
// RFC 7009 TOKEN REVOCATION, OVER THE WIRE (#102, 2026-09-22).
//
// Until that day `/oauth2/revoke` authenticated no client and revoked the jti
// of any JWS this realm had signed, in every mode. Now (the argument is above
// `revokeEndpoint()` in oauth-oidc/oauth2.ts), asserted over HTTP in a
// throwaway trust realm that is left behind, in whichever mode the service
// runs:
//
//   a. DISCOVERY: `revocation_endpoint_auth_methods_supported` is exactly
//      introspection's list, with `none` for a public client.
//   b. NO CREDENTIAL: product refuses 401 `invalid_client` and revokes
//      nothing; development revokes.
//   c. A BAD CREDENTIAL: 401 `invalid_client` in both modes, with the Basic
//      challenge, and nothing revoked.
//   d. ANOTHER CLIENT'S TOKEN: `invalid_grant`, and it stays active.
//   e. AN ID TOKEN: `unsupported_token_type`.
//   f. NO TOKEN: `invalid_request`.
//   g. AN UNKNOWN `token_type_hint`: ignored, and the token is revoked.
//   h. A REFRESH TOKEN TAKES ITS GRANT WITH IT: refreshed once, the second
//      refresh token revoked, and every access token of the grant is
//      inactive at introspection — and the refresh token no longer refreshes.
//   i. A PUBLIC CLIENT revokes its own token with its client_id alone and, in
//      product, is refused another client's.
//
// OWNED HERE (local: true): this repository's own authorization server.
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
var log = bunyan.createLogger({ name: "sts_token_revocation",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("revoke-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                               .slice(0, 31);
const realmBase = base + "/realm/" + REALM;
const realmApi = realmBase + "/admin-api";
const REDIRECT = "https://rp.revoke.example.test/cb";
const PASSWORD = "Revoke-Passw0rd!-" + String(Date.now()).slice(-6);
const ALICE = names.usernameFor("rv-alice");
const SECRET = "revoke-" + String(Date.now()).slice(-8) + "-client-secret";
const A = { client_id: "rv-a-" + REALM, client_secret: SECRET };
const B = { client_id: "rv-b-" + REALM, client_secret: SECRET };
const PUB = { client_id: "rv-pub-" + REALM };
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
    // Not JSON — an empty 200, for one; the caller reads `raw`.
    body = null;
  }
  log.debug("Leaving send(). status=" + r.status);
  return { status: r.status, body: body, raw: raw, headers: r.headers };
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await send(url, { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}) });
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

// A form POST to the realm, with the client's credential as client_secret_basic
// where it has a secret and as a bare client_id where it has none.
function post(path, form, client, headers) {
  log.debug("Entering post(). " + path);
  const h = Object.assign({ "Content-Type":
                              "application/x-www-form-urlencoded" },
                          headers || {});
  const body = Object.assign({}, form);
  if (client && client.client_secret) {
    h.Authorization = basicFor(client);
  } else if (client) {
    body.client_id = client.client_id;
  }
  log.debug("Leaving post().");
  return send(realmBase + path, { method: "POST", headers: h,
    body: new URLSearchParams(body).toString() });
}

function revoke(form, client, headers) {
  log.debug("Entering revoke().");
  log.debug("Leaving revoke().");
  return post("/oauth2/revoke", form, client, headers);
}

// Introspection as client A, which product requires and RFC 9701 section 5's
// intended-for rule allows for A's own tokens.
async function active(token) {
  log.debug("Entering active().");
  const r = await post("/oauth2/introspect", { token: token }, A);
  assert.strictEqual(r.status, 200, "introspection: " + r.raw.slice(0, 300));
  log.debug("Leaving active(). " + r.body.active);
  return r.body.active === true;
}

// The public client cannot introspect (it has no credential), so its access
// token is tried where it is USED: UserInfo refuses a revoked one.
async function userinfoAccepts(token) {
  log.debug("Entering userinfoAccepts().");
  const r = await send(realmBase + "/oauth2/userinfo",
                       { headers: { Authorization: "Bearer " + token } });
  log.debug("Leaving userinfoAccepts(). " + r.status);
  return r.status === 200;
}

async function tokens(client) {
  log.debug("Entering tokens(). " + client.client_id);
  const got = await registry.authorizationCode(realmBase, {
    clientId: client.client_id, redirectUri: REDIRECT, username: ALICE,
    password: PASSWORD, scope: "openid", cookie: cookie || undefined });
  cookie = got.cookie;
  const r = await post("/oauth2/token", { grant_type: "authorization_code",
    code: got.code, redirect_uri: REDIRECT, code_verifier: got.verifier },
    client);
  assert.strictEqual(r.status, 200, "the token request for " +
                     client.client_id + ": " + r.raw.slice(0, 400));
  assert.ok(r.body.access_token && r.body.refresh_token && r.body.id_token,
            "an access token, a refresh token and an ID Token: " +
            Object.keys(r.body).join(", "));
  log.debug("Leaving tokens().");
  return r.body;
}

function refused(r, status, error) {
  log.debug("Entering refused().");
  assert.strictEqual(r.status, status, r.raw.slice(0, 400));
  assert.strictEqual(r.body && r.body.error, error, r.raw.slice(0, 400));
  log.debug("Leaving refused().");
}

function application(client, method) {
  log.debug("Entering application().");
  const fields = { oauthClientId: [client.client_id],
                   oauthRedirectUri: [REDIRECT],
                   oauthGrantType: ["authorization_code", "refresh_token"],
                   oauthAllowedScope: ["openid"],
                   oauthTokenEndpointAuthMethod: method };
  if (client.client_secret) {
    fields.oauthClientSecret = client.client_secret;
  }
  log.debug("Leaving application().");
  return { identifier: client.client_id, kind: "oauth2-client",
           name: client.client_id, protocols: ["oauth2"], fields: fields };
}

async function setUp() {
  log.debug("Entering setUp().");
  log.info("=== 0. a throwaway realm " + REALM + " ===");
  PRODUCT = await registry.isProduct(base);
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "RFC 7009 " + STAMP },
    "created the realm");
  await ok(realmApi + "/users/create", {
    username: ALICE, invent: false, credential: "password",
    password: PASSWORD,
    attributes: { cn: "Revoke " + ALICE, givenName: "Revoke", sn: ALICE,
                  mail: ALICE + "@revoke.test" } }, "created " + ALICE);
  await ok(realmApi + "/applications/create",
           application(A, "client_secret_basic"), "client A");
  await ok(realmApi + "/applications/create",
           application(B, "client_secret_basic"), "client B");
  await ok(realmApi + "/applications/create", application(PUB, "none"),
           "a public client");
  log.debug("Leaving setUp().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving RFC 7009 at " + realmBase + " (" +
           (PRODUCT ? "product" : "development") + ")");
  await setUp();

  log.info("=== a. discovery ===");
  const meta = (await send(realmBase +
                           "/.well-known/oauth-authorization-server")).body;
  check("revocation_endpoint_auth_methods_supported is introspection's list, " +
        "none included", function () {
    assert.deepStrictEqual(meta.revocation_endpoint_auth_methods_supported,
                           meta.introspection_endpoint_auth_methods_supported);
    ["none", "client_secret_basic", "client_secret_post",
     "private_key_jwt"].forEach(function (one) {
      assert.ok(meta.revocation_endpoint_auth_methods_supported
        .indexOf(one) >= 0, one);
    });
  });

  const one = await tokens(A);
  log.info("=== b. no credential ===");
  let r = await revoke({ token: one.access_token });
  const afterAnonymous = await active(one.access_token);
  if (PRODUCT) {
    check("product: no credential is 401 invalid_client and revokes nothing",
          function () {
      refused(r, 401, "invalid_client");
      assert.strictEqual(afterAnonymous, true);
    });
  } else {
    check("development: an anonymous caller still revokes", function () {
      assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
      assert.strictEqual(afterAnonymous, false);
    });
  }

  const two = await tokens(A);
  log.info("=== c. a bad credential ===");
  r = await revoke({ token: two.access_token },
                   { client_id: A.client_id, client_secret: "wrong" });
  const afterWrong = await active(two.access_token);
  check("a secret that does not verify is 401 invalid_client with the Basic " +
        "challenge, in both modes, and nothing is revoked", function () {
    refused(r, 401, "invalid_client");
    assert.ok(/^Basic realm=/.test(String(r.headers.get("www-authenticate") ||
                                          "")),
              String(r.headers.get("www-authenticate")));
    assert.strictEqual(afterWrong, true);
  });

  log.info("=== d. another client's token ===");
  r = await revoke({ token: two.access_token }, B);
  const afterOther = await active(two.access_token);
  check("client B revoking client A's token is invalid_grant, and it stays " +
        "active", function () {
    refused(r, 400, "invalid_grant");
    assert.strictEqual(afterOther, true);
  });

  log.info("=== e. an ID Token ===");
  r = await revoke({ token: two.id_token }, A);
  check("an ID Token is unsupported_token_type (RFC 7009 section 2.2.1)",
        function () {
    refused(r, 400, "unsupported_token_type");
  });

  log.info("=== f. no token ===");
  r = await revoke({}, A);
  check("a request with no token is invalid_request (section 2.1)",
        function () {
    refused(r, 400, "invalid_request");
  });

  log.info("=== g. an unknown hint ===");
  r = await revoke({ token: two.access_token,
                     token_type_hint: "urn:example:no-such-hint" }, A);
  const afterHint = await active(two.access_token);
  const refreshAfterHint = await active(two.refresh_token);
  check("an unknown token_type_hint is ignored and the token revoked — and " +
        "only that token: its refresh token stays active", function () {
    assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
    assert.strictEqual(afterHint, false);
    assert.strictEqual(refreshAfterHint, true);
  });

  log.info("=== h. a refresh token takes its grant with it ===");
  const first = await tokens(A);
  r = await post("/oauth2/token", { grant_type: "refresh_token",
                                    refresh_token: first.refresh_token }, A);
  assert.strictEqual(r.status, 200, "the refresh: " + r.raw.slice(0, 300));
  const second = r.body;
  r = await revoke({ token: second.refresh_token,
                     token_type_hint: "refresh_token" }, A);
  const states = [await active(first.access_token),
                  await active(second.access_token),
                  await active(second.refresh_token),
                  await active(first.refresh_token)];
  check("revoking the refreshed refresh token leaves every token of the " +
        "grant inactive at introspection — both access tokens included",
        function () {
    assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
    assert.deepStrictEqual(states, [false, false, false, false]);
  });
  r = await post("/oauth2/token", { grant_type: "refresh_token",
                                    refresh_token: second.refresh_token }, A);
  check("and the refresh token no longer refreshes", function () {
    refused(r, 400, "invalid_grant");
  });

  log.info("=== i. a public client ===");
  const pub = await tokens(PUB);
  if (PRODUCT) {
    // In development a bare client_id is no credential, so the request is
    // the anonymous one of section b and revokes; product identifies a
    // public client by it.
    const three = await tokens(A);
    r = await revoke({ token: three.access_token }, PUB);
    const afterPubOther = await active(three.access_token);
    check("product: a public client is refused another client's token",
          function () {
      refused(r, 400, "invalid_grant");
      assert.strictEqual(afterPubOther, true);
    });
  }
  assert.strictEqual(await userinfoAccepts(pub.access_token), true,
                     "precondition: UserInfo accepts the public client's " +
                     "token");
  r = await revoke({ token: pub.access_token }, PUB);
  const pubAfter = await userinfoAccepts(pub.access_token);
  check("a public client revokes its own token with its client_id alone",
        function () {
    assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
    assert.strictEqual(pubAfter, false);
  });

  assert.ok(checks >= 10, "only " + checks + " checks ran; a section has " +
                                             "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_token_revocation")
  .description("RFC 7009: client authentication at the revocation endpoint " +
    "by mode, another client's token refused, the token types, the hint, " +
    "and a refresh token taking its grant with it.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
