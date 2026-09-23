"use strict";
//
// File: sts_scope_policy.js
//
// ---------------------------------------------------------------------------
// A SCOPE IS TIED TO THE CLIENT THAT ASKS FOR IT (#110, 2026-09-22).
//
// Until that day the token endpoint issued any scope a request named, to any
// client, in every mode — so any client that could use client_credentials
// could mint `admin:write` for /admin-api, `scim:write` or `ssf:write`. Now a
// client may be issued only what its `oauthAllowedScope` declares, and the
// three resource servers behind this service's own protected scopes ask again
// on every call. Asserted over HTTP, in a throwaway trust realm that is left
// behind, in both modes:
//
//   1. SCIM. A client that does not declare `scim:write` is refused
//      `invalid_scope` for it; declared through /admin-api it is issued the
//      scope and SCIM accepts the token; the declaration withdrawn, SCIM
//      refuses THAT SAME TOKEN (403).
//   2. SHARED SIGNALS, the same three steps.
//   3. /admin-api. A client that is not the management client is refused
//      `admin:read` at issuance; declared, its token reaches the API;
//      withdrawn, the token it holds is refused 403 — in the DEFAULT realm,
//      where until #110 any client's token carrying the scope was accepted.
//   4. REGISTRATION. RFC 7591's `scope` is the declaration, returned by the
//      registration and by RFC 7592's read; a protected scope in it is
//      `invalid_client_metadata`.
//   5. EVERY OTHER SCOPE. In development an undeclared scope is issued; in
//      product it is `invalid_scope`, a declared one is issued with `scope`
//      echoed, and a client declaring nothing still has OpenID Connect's.
//
// OWNED HERE (local: true): the policy is this repository's own.
// ---------------------------------------------------------------------------

const assert = require("assert");
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
var log = bunyan.createLogger({ name: "sts_scope_policy",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug('CONFIG_FILE could not be read, so the configuration is empty: ' +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const REALM = usernameFor("scopepol").replace(/[^a-z0-9-]/g, "").slice(0, 30);
const realmBase = base + "/realm/" + REALM;
const realmApi = realmBase + "/admin-api";
const SECRET = "scope-policy-" + String(Date.now()).slice(-8) + "-secret";
const SCIM_CLIENT = "sp-scim-" + REALM;
const SSF_CLIENT = "sp-ssf-" + REALM;
const BARE_CLIENT = "sp-bare-" + REALM;
const LISTED_CLIENT = "sp-listed-" + REALM;
const ADMIN_CLIENT = "sp-admin-" + REALM;
const CUSTOM = "sp:custom";
let PRODUCT = false;

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

async function call(method, url, body, headers) {
  log.debug("Entering call().");
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
  log.debug("Leaving call().");
  return { status: r.status, json: json, text: text };
}

async function ok(url, body, what) {
  log.debug("Entering ok().");
  const r = await call("POST", url, body);
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
            what + ": " + r.status + " " + r.text.slice(0, 400));
  log.debug("Leaving ok().");
  return r.json;
}

function application(identifier, protocols, fields) {
  log.debug("Entering application().");
  log.debug("Leaving application().");
  return { identifier: identifier, kind: "oauth2-client", name: identifier,
           protocols: protocols,
           fields: Object.assign({ oauthClientId: [identifier],
                                   oauthClientSecret: SECRET,
                                   oauthGrantType: ["client_credentials"],
                                   oauthTokenEndpointAuthMethod:
                                     "client_secret_post" }, fields || {}) };
}

// A client_credentials request, answered whole: the refusals are asserted.
async function token(at, identifier, scope, resource) {
  log.debug("Entering token().");
  const form = new URLSearchParams({ grant_type: "client_credentials",
    client_id: identifier, client_secret: SECRET, scope: scope });
  if (resource) {
    form.set("resource", resource);
  }
  const r = await call("POST", at + "/oauth2/token", form.toString(),
    { "Content-Type": "application/x-www-form-urlencoded" });
  log.debug("Leaving token(). status=" + r.status);
  return r;
}

async function declare(api, identifier, scope, mode) {
  log.debug("Entering declare().");
  await ok(api + "/applications/" + (mode || "add"),
           { application: identifier, attribute: "oauthAllowedScope",
             value: scope },
           (mode || "add") + " " + scope + " on " + identifier);
  log.debug("Leaving declare().");
}

function refusedInvalidScope(r) {
  log.debug("Entering refusedInvalidScope().");
  assert.strictEqual(r.status, 400, r.text.slice(0, 300));
  assert.strictEqual(r.json && r.json.error, "invalid_scope", r.text);
  assert.ok(/oauthAllowedScope/.test(r.text), r.text);
  log.debug("Leaving refusedInvalidScope().");
}

async function scim() {
  log.debug("Entering scim().");
  log.info("=== 1. SCIM ===");
  let r = await token(realmBase, SCIM_CLIENT, "scim:read scim:write");
  check("a client that does not declare the SCIM scopes is refused " +
        "invalid_scope for them", function () {
    refusedInvalidScope(r);
  });
  await declare(realmApi, SCIM_CLIENT, "scim:read");
  await declare(realmApi, SCIM_CLIENT, "scim:write");
  r = await token(realmBase, SCIM_CLIENT, "scim:read scim:write");
  check("declared through /admin-api, it is issued them", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.strictEqual(r.json.scope, "scim:read scim:write", r.text);
  });
  const held = r.json.access_token;
  const auth = { Authorization: "Bearer " + held };
  r = await call("GET", realmBase + "/scim/v2/Users?count=1", undefined, auth);
  check("and SCIM accepts the token", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
  });
  await declare(realmApi, SCIM_CLIENT, "scim:read", "remove");
  r = await call("GET", realmBase + "/scim/v2/Users?count=1", undefined, auth);
  check("withdrawing scim:read cuts off THE SAME TOKEN: 403 naming the " +
        "attribute", function () {
    assert.strictEqual(r.status, 403, r.text.slice(0, 300));
    assert.ok(/oauthAllowedScope/.test(r.text), r.text);
  });
  log.debug("Leaving scim().");
}

async function sharedSignals() {
  log.debug("Entering sharedSignals().");
  log.info("=== 2. Shared Signals ===");
  let r = await token(realmBase, SSF_CLIENT, "ssf:read ssf:write");
  check("a client that does not declare the SSF scopes is refused " +
        "invalid_scope for them", function () {
    refusedInvalidScope(r);
  });
  await declare(realmApi, SSF_CLIENT, "ssf:read");
  await declare(realmApi, SSF_CLIENT, "ssf:write");
  r = await token(realmBase, SSF_CLIENT, "ssf:read ssf:write");
  check("declared, it is issued them", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.strictEqual(r.json.scope, "ssf:read ssf:write", r.text);
  });
  const auth = { Authorization: "Bearer " + r.json.access_token };
  r = await call("GET", realmBase + "/ssf/stream", undefined, auth);
  check("and the transmitter accepts the token", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
  });
  await declare(realmApi, SSF_CLIENT, "ssf:read", "remove");
  r = await call("GET", realmBase + "/ssf/stream", undefined, auth);
  check("withdrawing ssf:read cuts off the same token: 403", function () {
    assert.strictEqual(r.status, 403, r.text.slice(0, 300));
    assert.ok(/oauthAllowedScope/.test(r.text), r.text);
  });
  log.debug("Leaving sharedSignals().");
}

async function managementApi() {
  log.debug("Entering managementApi().");
  log.info("=== 3. /admin-api, in the default realm ===");
  const api = base + "/admin-api";
  const audience = base + "/admin-api";
  await ok(api + "/applications/create",
           application(ADMIN_CLIENT, ["oauth2"]),
           "created a client in the default realm");
  try {
    let r = await token(base, ADMIN_CLIENT, "admin:read", audience);
    check("a client that is not the management client is refused " +
          "admin:read at issuance", function () {
      refusedInvalidScope(r);
    });
    await declare(api, ADMIN_CLIENT, "admin:read");
    r = await token(base, ADMIN_CLIENT, "admin:read", audience);
    assert.ok(r.status === 200 && r.json.access_token,
              "precondition: declared, the token is issued: " + r.status +
              " " + r.text.slice(0, 300));
    const auth = { Authorization: "Bearer " + r.json.access_token };
    r = await call("GET", api + "/status", undefined, auth);
    check("declared by an administrator, its token reaches the API",
          function () {
      assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    });
    await declare(api, ADMIN_CLIENT, "admin:read", "remove");
    r = await call("GET", api + "/status", undefined, auth);
    check("withdrawn, the token it already holds is refused 403 — the " +
          "default realm no longer accepts the scope from any client",
          function () {
      assert.strictEqual(r.status, 403, r.text.slice(0, 300));
      assert.ok(/oauthAllowedScope/.test(r.text), r.text);
    });
  } finally {
    // An administrative client is not left behind in the default realm.
    await call("POST", api + "/applications/forget",
               { application: ADMIN_CLIENT });
  }
  log.debug("Leaving managementApi().");
}

async function registration() {
  log.debug("Entering registration().");
  log.info("=== 4. RFC 7591 registration ===");
  await ok(realmApi + "/config/set",
           { key: "oauth2.openRegistration", value: "true" },
           "opened registration in the throwaway realm");
  const endpoint = realmBase + "/oauth2/register";
  const redirect = "https://scope-policy.example/cb";
  let r = await call("POST", endpoint, { redirect_uris: [redirect],
    scope: "openid admin:write" });
  check("a registration declaring a protected scope is " +
        "invalid_client_metadata", function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 300));
    assert.strictEqual(r.json && r.json.error, "invalid_client_metadata",
                       r.text);
  });
  r = await call("POST", endpoint, { redirect_uris: [redirect],
    scope: "openid " + CUSTOM });
  check("an ordinary registration's scope is returned as registered",
        function () {
    assert.strictEqual(r.status, 201, r.text.slice(0, 300));
    assert.strictEqual(r.json.scope, "openid " + CUSTOM, r.text);
  });
  const read = await call("GET", r.json.registration_client_uri, undefined,
    { Authorization: "Bearer " + r.json.registration_access_token });
  check("and RFC 7592's read returns it from the declaration", function () {
    assert.strictEqual(read.status, 200, read.text.slice(0, 300));
    assert.strictEqual(read.json.scope, "openid " + CUSTOM, read.text);
  });
  log.debug("Leaving registration().");
}

async function everyOtherScope() {
  log.debug("Entering everyOtherScope().");
  log.info("=== 5. every other scope, in " +
           (PRODUCT ? "product" : "development") + " mode ===");
  let r = await token(realmBase, BARE_CLIENT, CUSTOM);
  if (PRODUCT) {
    check("product: a client declaring nothing is refused an undeclared " +
          "scope", function () {
      refusedInvalidScope(r);
    });
  } else {
    check("development: an undeclared scope is issued", function () {
      assert.strictEqual(r.status, 200, r.text.slice(0, 300));
      assert.strictEqual(r.json.scope, CUSTOM, r.text);
    });
  }
  r = await token(realmBase, BARE_CLIENT, "openid");
  check("a client declaring nothing still has the default set (openid)",
        function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
  });
  r = await token(realmBase, LISTED_CLIENT, CUSTOM);
  check("a declared scope is issued, and `scope` echoes it", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.strictEqual(r.json.scope, CUSTOM, r.text);
  });
  r = await token(realmBase, LISTED_CLIENT, "sp:other");
  if (PRODUCT) {
    check("product: a scope outside a client's list is refused", function () {
      refusedInvalidScope(r);
    });
  }
  log.debug("Leaving everyOtherScope().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving the scope policy at " + realmBase);
  PRODUCT = await registry.isProduct(base);
  await ok(base + "/admin-api/realms/create",
           { id: REALM, domain: REALM + ".example.net",
             name: "Scope policy" }, "created the realm");
  await ok(realmApi + "/applications/create",
           application(SCIM_CLIENT, ["oauth2", "scim"]), "a SCIM client");
  await ok(realmApi + "/applications/create",
           application(SSF_CLIENT, ["oauth2", "ssf"]), "an SSF client");
  await ok(realmApi + "/applications/create",
           application(BARE_CLIENT, ["oauth2"]), "a client declaring nothing");
  await ok(realmApi + "/applications/create",
           application(LISTED_CLIENT, ["oauth2"],
                       { oauthAllowedScope: [CUSTOM] }),
           "a client declaring one scope");
  await scim();
  await sharedSignals();
  await managementApi();
  await registration();
  await everyOtherScope();
  assert.ok(checks >= 17, "only " + checks + " checks ran; a section has " +
                                             "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_scope_policy")
  .description("A scope is tied to the client: this service's protected " +
    "scopes are issued only to a client that declares them and honoured " +
    "only while it does; registration declares; product holds every other " +
    "scope to the declaration.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
