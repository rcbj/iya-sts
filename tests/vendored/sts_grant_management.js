"use strict";
//
// File: sts_grant_management.js
//
// ---------------------------------------------------------------------------
// GRANT MANAGEMENT FOR OAUTH 2.0 (#142, 2026-09-24), over HTTP, in a
// throwaway trust realm that is left behind, in whichever mode the service
// runs:
//
//   1. PUBLISHED: grant_management_actions_supported and
//      grant_management_endpoint in the discovery document.
//   2. CREATE: an authorization request with grant_management_action=create
//      is answered with a grant_id in the token response, and the grant is
//      readable at /oauth2/grants/{grant_id} with an access token carrying
//      grant_management_query — no-store.
//   3. MERGE: the same grant, more scope; the refresh token issued before is
//      refused (invalid_grant) and the new one refreshes; the grant says
//      updated_by client.
//   4. REPLACE: the grant holds only the new request's scope.
//   5. THE AUTHORIZATION REFUSALS: grant_id with no action, create with a
//      grant_id, merge naming a grant nobody holds (invalid_grant_id), and a
//      public client (invalid_request) — each redirected to the client.
//   6. THE API'S REFUSALS: no token (401), a token without the scope (403),
//      another client's grant (403), an unknown grant (404).
//   7. DELETE: 204; the grant is gone (404), its refresh token refused and
//      its access token inactive at introspection.
//   8. THE CONSOLE'S TWIN: /admin-api/grants lists a grant, revoke-grant
//      revokes it, and a second time is refused.
//   9. (#176) A client revoking with a token minted under the grant, then
//      asking again with it: 404 for that grant, 401 for any other; a
//      client_assertion naming no client, or two, is invalid_client; and
//      the grants endpoint echoes or mints x-fapi-interaction-id.
//
// OWNED HERE (local: true): this repository's authorization server and its
// management API.
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
var log = bunyan.createLogger({ name: "sts_grant_management",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("grants-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                               .slice(0, 31);
const realmBase = base + "/realm/" + REALM;
const realmApi = realmBase + "/admin-api";
const REDIRECT = "https://rp.grants.example.test/cb";
const PASSWORD = "Grants-Passw0rd!-" + String(Date.now()).slice(-6);
const ALICE = names.usernameFor("gm-alice");
const SECRET = "grants-" + String(Date.now()).slice(-8) + "-client-secret";
const A = { client_id: "gm-a-" + REALM, client_secret: SECRET };
const B = { client_id: "gm-b-" + REALM, client_secret: SECRET };
const PUBLIC = { client_id: "gm-p-" + REALM };
const SCOPES = ["openid", "profile", "email", "offline_access",
                "grant_management_query", "grant_management_revoke"];
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
    // Not JSON — an HTML page or an empty body; the caller reads `raw`.
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

function post(path, form, client) {
  log.debug("Entering post(). " + path);
  log.debug("Leaving post().");
  return send(realmBase + path, { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded",
               Authorization: basicFor(client) },
    body: new URLSearchParams(form).toString() });
}

async function active(token, client) {
  log.debug("Entering active().");
  const r = await post("/oauth2/introspect", { token: token }, client);
  assert.strictEqual(r.status, 200, "introspection: " + r.raw.slice(0, 300));
  log.debug("Leaving active(). " + r.body.active);
  return r.body.active === true;
}

// The tokens for a code the way a browser gets one, with `extra` on the
// authorization request.
async function tokens(client, scope, extra) {
  log.debug("Entering tokens(). " + scope);
  const got = await registry.authorizationCode(realmBase, {
    clientId: client.client_id, redirectUri: REDIRECT, username: ALICE,
    password: PASSWORD, scope: scope, cookie: cookie || undefined,
    extra: extra });
  cookie = got.cookie;
  const r = await post("/oauth2/token", { grant_type: "authorization_code",
    code: got.code, redirect_uri: REDIRECT, code_verifier: got.verifier },
    client);
  assert.strictEqual(r.status, 200, "the token request: " +
                     r.raw.slice(0, 400));
  log.debug("Leaving tokens().");
  return r.body;
}

// An access token for the grant management API, by client_credentials.
async function apiToken(client, scope) {
  log.debug("Entering apiToken(). " + scope);
  const r = await post("/oauth2/token", { grant_type: "client_credentials",
                                          scope: scope }, client);
  assert.strictEqual(r.status, 200, "client_credentials for " + scope +
                     ": " + r.raw.slice(0, 400));
  log.debug("Leaving apiToken().");
  return r.body.access_token;
}

function grantCall(method, grantId, token) {
  log.debug("Entering grantCall(). " + method);
  log.debug("Leaving grantCall().");
  return send(realmBase + "/oauth2/grants/" + encodeURIComponent(grantId),
              { method: method,
                headers: token ? { Authorization: "Bearer " + token } : {} });
}

// Where an authorization request with `params` is sent back to, and the
// error it carries there.
async function authorizeError(clientId, params) {
  log.debug("Entering authorizeError().");
  const pair = registry.pkce();
  const url = realmBase + "/oauth2/authorize?" + new URLSearchParams(
    Object.assign({ response_type: "code", client_id: clientId,
                    redirect_uri: REDIRECT, scope: "openid",
                    state: "gm", code_challenge: pair.challenge,
                    code_challenge_method: pair.method }, params))
    .toString();
  const r = await fetch(url, { redirect: "manual" });
  let location = r.headers.get("location") || "";
  // RFC 9700 MODE (and so product mode) SHOWS THE ERROR RATHER THAN
  // REDIRECTING IT while nobody is signed in (section 4.11.2): a page whose
  // link carries the same error to the client's redirect URI. That link is
  // what the client would be sent to, so it is read as the Location.
  if (!location) {
    const page = await r.text();
    const links = page.match(/href="([^"]+)"/g) || [];
    for (let i = 0; i < links.length && !location; i++) {
      const href = links[i].slice(6, -1).replace(/&amp;/g, "&");
      if (href.indexOf(REDIRECT) === 0) {
        location = href;
      }
    }
  }
  const error = new URL(location || "https://none.invalid/")
    .searchParams.get("error") || "";
  log.debug("Leaving authorizeError(). " + error);
  return { status: r.status, location: location, error: error };
}

function application(client, method) {
  log.debug("Entering application().");
  const fields = { oauthClientId: [client.client_id],
                   oauthRedirectUri: [REDIRECT],
                   oauthGrantType: ["authorization_code", "refresh_token",
                                    "client_credentials"],
                   oauthAllowedScope: SCOPES,
                   oauthTokenEndpointAuthMethod: method };
  if (client.client_secret) {
    fields.oauthClientSecret = client.client_secret;
  }
  log.debug("Leaving application().");
  return { identifier: client.client_id, kind: "oauth2-client",
           name: client.client_id, protocols: ["oauth2", "oidc"],
           fields: fields };
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. a throwaway realm " + REALM + " ===");
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "Grant management " + STAMP },
    "created the realm");
  await ok(realmApi + "/users/create", {
    username: ALICE, invent: false, credential: "password",
    password: PASSWORD,
    attributes: { cn: "Grants " + ALICE, givenName: "Grants", sn: ALICE,
                  mail: ALICE + "@grants.test" } }, "created " + ALICE);
  await ok(realmApi + "/applications/create",
           application(A, "client_secret_basic"), "client A");
  await ok(realmApi + "/applications/create",
           application(B, "client_secret_basic"), "client B");
  await ok(realmApi + "/applications/create",
           application(PUBLIC, "none"), "the public client");

  log.info("=== 1. published ===");
  const discovery = await send(realmBase +
                               "/.well-known/openid-configuration");
  check("grant_management_actions_supported and grant_management_endpoint",
        function () {
    assert.deepStrictEqual(discovery.body.grant_management_actions_supported,
                           ["create", "merge", "replace", "query", "revoke"]);
    assert.strictEqual(discovery.body.grant_management_endpoint,
                       realmBase + "/oauth2/grants");
  });

  log.info("=== 2. create ===");
  const created = await tokens(A, "openid profile offline_access",
                               { grant_management_action: "create" });
  const grantId = created.grant_id;
  const query = await apiToken(A, "grant_management_query");
  const read = await grantCall("GET", grantId, query);
  check("the token response carries a grant_id, and the grant is readable, " +
        "no-store", function () {
    assert.ok(grantId && /^[A-Za-z0-9_-]{20,}$/.test(grantId),
              JSON.stringify(created));
    assert.strictEqual(read.status, 200, read.raw.slice(0, 300));
    assert.ok(/no-store/.test(read.headers.get("cache-control") || ""));
    assert.strictEqual(read.body.scopes[0].scope,
                       "openid profile offline_access");
    assert.ok(Number.isInteger(read.body.created_at));
    assert.ok(Number.isInteger(read.body.expires_at));
    assert.ok(!read.body.updated_by);
  });

  log.info("=== 3. merge ===");
  const merged = await tokens(A, "openid email", {
    grant_management_action: "merge", grant_id: grantId });
  const oldRefresh = await post("/oauth2/token", {
    grant_type: "refresh_token", refresh_token: created.refresh_token }, A);
  const newRefresh = await post("/oauth2/token", {
    grant_type: "refresh_token", refresh_token: merged.refresh_token }, A);
  const afterMerge = await grantCall("GET", grantId, query);
  check("the same grant, its scope merged; the earlier refresh token " +
        "refused, the new one refreshing; updated_by client", function () {
    assert.strictEqual(merged.grant_id, grantId);
    ["openid", "profile", "offline_access", "email"].forEach(function (s) {
      assert.ok(merged.scope.split(" ").indexOf(s) >= 0, merged.scope);
    });
    assert.strictEqual(oldRefresh.status, 400, oldRefresh.raw.slice(0, 300));
    assert.strictEqual(oldRefresh.body.error, "invalid_grant");
    assert.strictEqual(newRefresh.status, 200, newRefresh.raw.slice(0, 300));
    assert.strictEqual(newRefresh.body.grant_id, grantId);
    assert.strictEqual(afterMerge.body.updated_by, "client");
    assert.ok(afterMerge.body.scopes[0].scope.split(" ").indexOf("email") >=
              0);
  });

  log.info("=== 4. replace ===");
  const replaced = await tokens(A, "openid email offline_access", {
    grant_management_action: "replace", grant_id: grantId });
  const afterReplace = await grantCall("GET", grantId, query);
  check("the grant holds only the new request's scope", function () {
    assert.strictEqual(replaced.grant_id, grantId);
    assert.strictEqual(afterReplace.body.scopes[0].scope,
                       "openid email offline_access");
  });

  log.info("=== 5. the authorization refusals ===");
  const noAction = await authorizeError(A.client_id, { grant_id: grantId });
  const createWithId = await authorizeError(A.client_id, {
    grant_management_action: "create", grant_id: grantId });
  const unknown = await authorizeError(A.client_id, {
    grant_management_action: "merge", grant_id: "nobody-holds-this" });
  const otherClients = await authorizeError(B.client_id, {
    grant_management_action: "merge", grant_id: grantId });
  const publicClient = await authorizeError(PUBLIC.client_id, {
    grant_management_action: "create" });
  check("grant_id alone and create with an id are invalid_request; an " +
        "unknown grant and another client's are invalid_grant_id; a public " +
        "client is invalid_request — each sent back to the client",
        function () {
    [noAction, createWithId, unknown, otherClients, publicClient]
      .forEach(function (r) {
        assert.ok(r.location.indexOf(REDIRECT) === 0, r.location);
      });
    assert.strictEqual(noAction.error, "invalid_request");
    assert.strictEqual(createWithId.error, "invalid_request");
    assert.strictEqual(unknown.error, "invalid_grant_id");
    assert.strictEqual(otherClients.error, "invalid_grant_id");
    assert.strictEqual(publicClient.error, "invalid_request");
  });

  log.info("=== 6. the API's refusals ===");
  const noToken = await grantCall("GET", grantId, "");
  const noScope = await grantCall("GET", grantId,
                                  await apiToken(A, "profile"));
  const otherClient = await grantCall("GET", grantId,
    await apiToken(B, "grant_management_query"));
  const nobody = await grantCall("GET", "nobody-holds-this", query);
  const deleteWithQuery = await grantCall("DELETE", grantId, query);
  check("no token 401, no scope 403 insufficient_scope, another client's " +
        "grant 403, an unknown one 404, and DELETE needs the revoke scope",
        function () {
    assert.strictEqual(noToken.status, 401);
    assert.strictEqual(noScope.status, 403);
    assert.strictEqual(noScope.body.error, "insufficient_scope");
    assert.ok(/insufficient_scope/.test(
      noScope.headers.get("www-authenticate") || ""));
    assert.strictEqual(otherClient.status, 403);
    assert.strictEqual(nobody.status, 404);
    assert.strictEqual(deleteWithQuery.status, 403);
  });

  log.info("=== 7. delete ===");
  const revokeToken = await apiToken(A, "grant_management_revoke");
  const deleted = await grantCall("DELETE", grantId, revokeToken);
  const gone = await grantCall("GET", grantId, query);
  const refreshAfter = await post("/oauth2/token", {
    grant_type: "refresh_token", refresh_token: replaced.refresh_token }, A);
  const accessAfter = await active(replaced.access_token, A);
  check("204; the grant is gone, its refresh token refused and its access " +
        "token inactive", function () {
    assert.strictEqual(deleted.status, 204, deleted.raw.slice(0, 300));
    assert.strictEqual(gone.status, 404);
    assert.strictEqual(refreshAfter.status, 400);
    assert.strictEqual(refreshAfter.body.error, "invalid_grant");
    assert.strictEqual(accessAfter, false);
  });

  log.info("=== 8. the console's twin ===");
  const second = await tokens(A, "openid profile", {
    grant_management_action: "create" });
  const listed = await send(realmApi + "/grants?client_id=" +
                            encodeURIComponent(A.client_id));
  const byConsole = await send(realmApi + "/grants/revoke-grant", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ grantId: second.grant_id }) });
  const again = await send(realmApi + "/grants/revoke-grant", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ grantId: second.grant_id }) });
  check("/admin-api/grants lists the grant; revoke-grant revokes it, and " +
        "refuses a second time", function () {
    assert.strictEqual(listed.status, 200, listed.raw.slice(0, 300));
    assert.ok(listed.body.grants.some(function (g) {
      return g.grantId === second.grant_id && g.clientId === A.client_id;
    }), listed.raw.slice(0, 400));
    assert.strictEqual(byConsole.status, 200, byConsole.raw.slice(0, 300));
    assert.ok(byConsole.body.revoked >= 1, byConsole.raw);
    assert.strictEqual(again.status, 400);
  });

  log.info("=== 9. what the OpenID conformance suite found (#176) ===");
  // The OpenID conformance suite's query-and-revoke: the client revokes with
  // a token minted UNDER the grant, then asks about it with the same token.
  const own = await tokens(A, "openid grant_management_query " +
    "grant_management_revoke", { grant_management_action: "create" });
  const ownDeleted = await grantCall("DELETE", own.grant_id,
                                     own.access_token);
  const ownGone = await grantCall("GET", own.grant_id, own.access_token);
  const ownElsewhere = await grantCall("GET", grantId, own.access_token);
  // RFC 7523 section 3 item B: an assertion with no sub, and no client_id
  // beside it, names no client to authenticate.
  const nameless = [{ alg: "ES256", typ: "JWT" },
    { iss: "nobody", aud: realmBase, exp: Math.floor(Date.now() / 1000) + 60,
      jti: "nameless-" + STAMP }].map(function (part) {
    return Buffer.from(JSON.stringify(part)).toString("base64url");
  }).join(".") + ".c2ln";
  const namelessAnswer = await send(realmBase + "/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "client_credentials",
      client_assertion_type:
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      client_assertion: nameless }).toString() });
  // RFC 7523 section 3 item B and OpenID Connect Core section 9: iss and sub
  // are both the client_id, so an assertion naming two clients is refused
  // before any grant is looked at (the suite's FAPI 1.0 wrong-sub module).
  const twoNamed = [{ alg: "ES256", typ: "JWT" },
    { iss: A.client_id, sub: "wrong-sub-" + STAMP, aud: realmBase,
      exp: Math.floor(Date.now() / 1000) + 60,
      jti: "two-named-" + STAMP }].map(function (part) {
    return Buffer.from(JSON.stringify(part)).toString("base64url");
  }).join(".") + ".c2ln";
  const twoNamedAnswer = await send(realmBase + "/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "client_credentials",
      client_assertion_type:
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      client_assertion: twoNamed }).toString() });
  // FAPI 1.0 Baseline section 6.2.1 item 13: a protected resource echoes
  // the client's x-fapi-interaction-id, and mints a UUID when none came.
  // The header is set before the route answers, so a refused call shows it
  // as well as a served one.
  const interaction = "3b2f6a5e-1c4d-4e8f-9a0b-" +
    String(Date.now()).slice(-12).padStart(12, "0");
  const echoed = await send(realmBase + "/oauth2/grants/" + grantId, {
    headers: { "x-fapi-interaction-id": interaction } });
  const minted = await send(realmBase + "/oauth2/grants/" + grantId);
  check("an assertion whose iss and sub differ is invalid_client; a " +
        "resource echoes x-fapi-interaction-id or mints one", function () {
    assert.strictEqual(twoNamedAnswer.status, 401,
                       twoNamedAnswer.raw.slice(0, 300));
    assert.strictEqual(twoNamedAnswer.body.error, "invalid_client");
    assert.strictEqual(echoed.headers.get("x-fapi-interaction-id"),
                       interaction);
    assert.match(String(minted.headers.get("x-fapi-interaction-id") || ""),
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  });
  check("a token revoked with its grant is told that grant is gone (404) " +
        "and refused elsewhere (401); a nameless assertion is " +
        "invalid_client", function () {
    assert.strictEqual(ownDeleted.status, 204, ownDeleted.raw.slice(0, 300));
    assert.strictEqual(ownGone.status, 404, ownGone.raw.slice(0, 300));
    assert.strictEqual(ownElsewhere.status, 401,
                       ownElsewhere.raw.slice(0, 300));
    assert.strictEqual(namelessAnswer.status, 401,
                       namelessAnswer.raw.slice(0, 300));
    assert.strictEqual(namelessAnswer.body.error, "invalid_client");
  });

  assert.ok(checks >= 10, "only " + checks + " checks ran");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

new Command()
  .description("Grant Management for OAuth 2.0 (#142): create, merge, " +
    "replace, the grant management API and its refusals, and the console's " +
    "twin.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
