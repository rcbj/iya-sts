// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_token_exchange_response.js
//
// ---------------------------------------------------------------------------
// WHAT AN RFC 8693 EXCHANGE ANSWERS, MEMBER BY MEMBER (iya-sts #156).
//
// An exchange of a person's `openid profile` access token for another
// resource server, with no `scope` on the request, answered
// `"scope": ""` — not a value under RFC 6749 section 3.3 — and an `id_token`
// beside an access token whose scope named no `openid`. The rule since:
//
//   * no `scope` on the exchange carries the subject_token's forward, then
//     narrowed as every grant is — RFC 9068's plan takes the OpenID Connect
//     scopes off a token for another resource server;
//   * the response's `scope` names what the access token carries, and is
//     LEFT OUT when it carries nothing;
//   * an `id_token` comes back only when the issued token's scope carries
//     `openid`.
//
// In a throwaway realm left standing, in whichever mode the service is in
// (the subject token comes from the code flow, which product allows):
//
//   E1. no scope, an audience that is another resource server: an access
//       token for it, no `scope` member, no `scope` claim, no `id_token`,
//       `issued_token_type` an access token.
//   E2. `scope=openid` asked for that audience: the same — asking for
//       `openid` does not put it on a token for another resource server.
//   E3. no scope and no audience — a SELF exchange, for the subject token's
//       own audience: the subject's `openid profile` carried forward, on
//       the token and in the response, and the `id_token` with it.
//
// OWNED HERE (local: true): the response is this repository's own.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");
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
var log = bunyan.createLogger({ name: "sts_token_exchange_response",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug('CONFIG_FILE could not be read, so the configuration is empty: ' +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const REALM = usernameFor("txresp").replace(/[^a-z0-9-]/g, "").slice(0, 30);
const realmBase = base + "/realm/" + REALM;
const realmApi = realmBase + "/admin-api";
const PASSWORD = "Tx!" + crypto.randomBytes(12).toString("base64url") + "9z";
const SECRET = "exchange-response-" + crypto.randomBytes(8).toString("hex");
const ALICE = "tx-alice";
// The client: it signs Alice in, then exchanges her token. S, so it may
// delegate to API.
const CLIENT = "tx-client";
const REDIRECT = "https://" + CLIENT + ".example/callback";
// R: another resource server, registered so product's policy knows it.
const API = "tx-api";
const API_URL = "https://" + API + ".example";
const EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS = "urn:ietf:params:oauth:token-type:access_token";

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

async function call(method, target, body, headers) {
  log.debug("Entering call().");
  const r = await fetch(target, { method: method, redirect: "manual",
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
  log.debug("Leaving call().");
  return { status: r.status, json: json, text: text };
}

async function ok(target, body, what) {
  log.debug("Entering ok().");
  const r = await call("POST", target, body);
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
            what + ": " + r.status + " " + r.text.slice(0, 400));
  log.debug("Leaving ok().");
  return r.json;
}

function claimsOf(jwt) {
  log.debug("Entering claimsOf().");
  const part = String(jwt || "").split(".")[1] || "";
  log.debug("Leaving claimsOf().");
  return JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
}

async function token(form) {
  log.debug("Entering token().");
  const params = new URLSearchParams();
  Object.keys(form).forEach(function (k) {
    if (form[k] !== null && form[k] !== undefined) {
      params.append(k, form[k]);
    }
  });
  const r = await call("POST", realmBase + "/oauth2/token", params.toString(),
    { "Content-Type": "application/x-www-form-urlencoded" });
  log.debug("Leaving token(). " + r.status);
  return r;
}

// Alice's access token, through the code flow, for `openid profile`.
async function aliceToken() {
  log.debug("Entering aliceToken().");
  const granted = await registry.authorizationCode(realmBase, {
    clientId: CLIENT, redirectUri: REDIRECT, username: ALICE,
    password: PASSWORD, scope: "openid profile" });
  const r = await token({ grant_type: "authorization_code",
    code: granted.code, redirect_uri: REDIRECT,
    code_verifier: granted.verifier, client_id: CLIENT,
    client_secret: SECRET });
  assert.strictEqual(r.status, 200, "Alice's code redeemed: " +
                     r.text.slice(0, 400));
  const claims = claimsOf(r.json.access_token);
  assert.deepStrictEqual(String(claims.scope || "").split(" ").sort(),
                         ["openid", "profile"],
                         "the subject token carries openid profile: " +
                         JSON.stringify(claims));
  log.debug("Leaving aliceToken().");
  return r.json.access_token;
}

// An exchange by CLIENT of `subjectToken`, with `extra` on top (a null
// value sends no parameter).
function exchange(subjectToken, extra) {
  log.debug("Entering exchange().");
  log.debug("Leaving exchange().");
  return token(Object.assign({ grant_type: EXCHANGE, client_id: CLIENT,
    client_secret: SECRET, subject_token: subjectToken,
    subject_token_type: ACCESS }, extra || {}));
}

// The members every answer here must have right, whatever the scope.
function assertIssued(r, what) {
  log.debug("Entering assertIssued().");
  assert.strictEqual(r.status, 200, what + ": " + r.text.slice(0, 400));
  assert.strictEqual(r.json.issued_token_type, ACCESS, r.text.slice(0, 400));
  assert.ok(r.json.access_token, r.text.slice(0, 400));
  assert.ok(/^(Bearer|DPoP)$/.test(r.json.token_type), r.text.slice(0, 400));
  assert.notStrictEqual(r.json.scope, "",
    "\"scope\": \"\" is not a scope (RFC 6749 section 3.3): " +
    r.text.slice(0, 400));
  log.debug("Leaving assertIssued().");
}

async function exchanges() {
  log.debug("Entering exchanges().");
  log.info("=== E. RFC 8693 token exchange responses ===");
  const subjectToken = await aliceToken();

  let r = await exchange(subjectToken, { audience: API_URL });
  check("E1. no scope, an audience that is another resource server: no " +
        "`scope` member, no `scope` claim, no `id_token`", function () {
    assertIssued(r, "E1");
    assert.ok(!Object.prototype.hasOwnProperty.call(r.json, "scope"),
              "no scope member: " + r.text.slice(0, 400));
    assert.ok(!r.json.id_token, "no id_token: " + r.text.slice(0, 400));
    const claims = claimsOf(r.json.access_token);
    assert.ok(!("scope" in claims), JSON.stringify(claims));
    assert.ok([].concat(claims.aud).indexOf(API_URL) >= 0,
              JSON.stringify(claims.aud));
  });

  r = await exchange(subjectToken, { audience: API_URL, scope: "openid" });
  check("E2. scope=openid for that audience: the same — openid is not put " +
        "on a token for another resource server, so no id_token",
        function () {
          assertIssued(r, "E2");
          assert.ok(!/\bopenid\b/.test(String(r.json.scope || "")),
                    r.text.slice(0, 400));
          assert.ok(!r.json.id_token, "no id_token: " +
                    r.text.slice(0, 400));
        });

  r = await exchange(subjectToken, {});
  check("E3. no scope and no audience (a self exchange): the subject's " +
        "openid profile carried forward, in the response and on the " +
        "token, and the id_token with it", function () {
    assertIssued(r, "E3");
    assert.deepStrictEqual(String(r.json.scope || "").split(" ").sort(),
                           ["openid", "profile"], r.text.slice(0, 400));
    const claims = claimsOf(r.json.access_token);
    assert.deepStrictEqual(String(claims.scope || "").split(" ").sort(),
                           ["openid", "profile"], JSON.stringify(claims));
    assert.ok(r.json.id_token, "an id_token: " + r.text.slice(0, 400));
  });
  log.debug("Leaving exchanges().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving token exchange responses at " + realmBase);
  await ok(base + "/admin-api/realms/create",
           { id: REALM, domain: REALM + ".example.net",
             name: "Token exchange responses" }, "created the realm");
  await ok(realmApi + "/users/create",
           { username: ALICE, invent: false, credential: "password",
             password: PASSWORD,
             attributes: { cn: "Exchange " + ALICE, givenName: "Exchange",
                           sn: "Alice" } }, "created " + ALICE);
  await ok(realmApi + "/applications/create", { identifier: API,
    protocols: ["oauth2"],
    fields: { oauthClientId: [API], oauthClientSecret: SECRET,
              oauthTokenEndpointAuthMethod: "client_secret_post",
              oauthGrantType: ["client_credentials"],
              oauthAudience: [API_URL] } }, "the resource server " + API);
  await ok(realmApi + "/applications/create", { identifier: CLIENT,
    protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: [CLIENT], oauthClientSecret: SECRET,
              oauthTokenEndpointAuthMethod: "client_secret_post",
              oauthAllowedScope: ["openid", "profile"],
              oauthRedirectUri: [REDIRECT],
              oauthResponseType: ["code"],
              oauthGrantType: ["authorization_code", EXCHANGE],
              oauthAudience: ["https://" + CLIENT + ".example"],
              appAllowedToDelegateTo: [API] } }, "the client " + CLIENT);
  for (const one of ["openid", "profile"]) {
    await ok(realmApi + "/consent/grant-global-consent",
             { client: CLIENT, scope: one }, "consented " + one);
  }
  await exchanges();
  assert.ok(checks >= 3, "only " + checks + " of 3 checks ran; a section " +
            "has stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_token_exchange_response")
  .description("What an RFC 8693 token exchange answers: no empty scope, " +
    "no id_token beside a token without openid, and the subject's scope " +
    "carried forward when none is asked for.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
