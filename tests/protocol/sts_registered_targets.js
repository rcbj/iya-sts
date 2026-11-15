// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_registered_targets.js
//
// ---------------------------------------------------------------------------
// A RESOURCE, A GNAP RIGHT'S LOCATIONS AND EVERY AUDIENCE A TOKEN CARRIES
// NAME A REGISTERED TARGET, IN EVERY MODE, OVER THE WIRE (#505, #1140).
//
// D12 (#444): carries over `tests/registered_targets.js`. In a development
// realm and a product realm of its own, each holding the same registered
// applications (an API by its oauthAudience and client_id, one by its
// permission base URI, a public OAuth client, a GNAP resource server):
//
//   T1. GET /admin-api/mode lists no `unregistered-resource-targets` row:
//       the modes no longer differ (#1140);
//   T3. THE AUTHORIZATION ENDPOINT: a resource naming nobody, or one
//       nobody-address beside a registered one, is refused STS-OAUTH-0950
//       in both modes — a REDIRECTED invalid_target in development, but
//       this service's own 400 page in product (pinned; the units file has
//       product redirect too); a registered
//       application by its audience and permission base URI (a client_id or
//       identifier is no absolute URI, refused 400 by the request schema
//       first, its sentence naming `resource`), the default resource
//       indicator, a named authorization
//       server's, /admin-api, /account-api and /report-api pass;
//       /gnap/rs/resource (the deleted demonstration resource server) and a
//       path of this service that is no resource server do not;
//   T4. THE TOKEN ENDPOINT: an unregistered resource is a 400
//       invalid_target (STS-OAUTH-0951) before the grant is looked at; a
//       registered and an own one fail for the grant instead; a token
//       exchange is not asked;
//   T5. GNAP (development, whose first presentation registers the key): a
//       right whose location names nobody, or one of two, is refused
//       invalid_request (STS-GNAP-0903); one at or under a registered GNAP
//       resource server's address passes, and a registered application's
//       audience passes the target check only to be refused as naming no
//       resource server (STS-GNAP-0904);
//   T6. GNAP: a request naming no resource server — an unknown reference,
//       an uncatalogued type with no location — is refused invalid_request
//       (STS-GNAP-0904), the second of two tokens by its index; one naming
//       the registered resource server or the Shared Signals transmitter
//       (its scope or the `ssf` type) is not;
//   T7. THE PLAN: a client-credentials token with no resource is planned
//       for the client's own client_id, and /report-api and the default
//       resource while their objects exist; once `sts-resource` and
//       `sts-report-api` are deleted from the development realm, both are
//       refused invalid_target (STS-OAUTH-0951: the token endpoint's own
//       check answers before the plan's 0986).
//
// OWED: STS-OAUTH-0986 itself — the plan refusing the DEFAULT audience of
// an authorization-code token once `sts-resource` is gone (a sign-in flow
// with no resource); every request naming a resource meets 0951 first.
//
// NOT carried (class (d)): a seen-only target — a development SIGHTING with
// an audience and no appRegisteredBy is filed by the register's own
// `seen()`, which no request reaches with an audience; the GNAP rules in
// the product realm (#1140 made the modes alike; a product GNAP client
// needs its key provisioned first, the GNAP jobs' registrar, phase 8).
//
// OWNED HERE (local: true): this repository's own authorization server.
// ---------------------------------------------------------------------------

const gnap = require("./gnap_client.js");
const assert = require("assert");
const nodeCrypto = require("crypto");
const names = require("./random_username.js");

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
var log = bunyan.createLogger({ name: "sts_registered_targets",
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

function form(o) {
  log.debug("Entering form().");
  log.debug("Leaving form().");
  return new URLSearchParams(o).toString();
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
  return { status: r.status, body: body, raw: raw, headers: r.headers,
           location: r.headers.get("location") || "" };
}

function postJson(url, payload) {
  log.debug("Entering postJson().");
  log.debug("Leaving postJson().");
  return send(url, { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}) });
}

function postForm(url, fields, headers) {
  log.debug("Entering postForm().");
  log.debug("Leaving postForm().");
  return send(url, { method: "POST",
    headers: Object.assign({ "Content-Type":
                               "application/x-www-form-urlencoded" },
                           headers || {}),
    body: form(fields) });
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

// How many rows of a realm's audit log carry `code`, waited for until there
// are more than `above` (default 0): the row is written as the refusal is
// sent, and a code is recorded, never sent.
async function codeCount(realm, code, above) {
  log.debug("Entering codeCount(). " + code);
  const floor = Number(above || 0);
  let n = 0;
  for (let i = 0; i < 20; i += 1) {
    const r = await send(base + "/realm/" + realm + "/admin-api/audit" +
                         "?per=500&code=" + encodeURIComponent(code));
    n = Number((r.body && r.body.matched) || 0);
    if (n > floor) {
      break;
    }
    await sleep(150);
  }
  log.debug("Leaving codeCount(). " + n);
  return n;
}

async function createRealm(id, mode, what) {
  log.debug("Entering createRealm(). " + id);
  await ok(base + "/admin-api/realms/create", { id: id,
    domain: id + ".example.net", name: what + " " + STAMP },
    "created the realm " + id);
  if (mode) {
    await ok(base + "/admin-api/realms/set", { id: id, key: "global.mode",
                                               value: mode },
             "put " + id + " in " + mode + " mode");
  }
  log.debug("Leaving createRealm().");
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
    log.debug("Caught in main(): " + ((e && e.message) || e));
    // A failed removal is not the job's verdict.
    log.info("could not remove the realms: " + ((e && e.message) || e));
  }
  if (failure) {
    log.error(failure.stack || failure.message);
    log.debug("Leaving main(). Failed.");
    process.exit(1);
  }
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving main().");
}

const DEV = "rt-" + STAMP;
const PROD = "rtp-" + STAMP;
const API_AUD = "https://api-" + STAMP + ".rt.example/v1";
const BASE_URI = "https://perm-" + STAMP + ".rt.example/";
const GNAP_RS = "https://rs-" + STAMP + ".rt.example/gnap";
const NOBODY = "https://nobody-" + STAMP + ".rt.example/api";
const REDIRECT = "https://rp.rt.example/cb";
const SECRET = "rt-secret-" + nodeCrypto.randomBytes(10).toString("hex");

async function fixtures(realm) {
  log.debug("Entering fixtures(). " + realm);
  const API = base + "/realm/" + realm + "/admin-api";
  await ok(API + "/applications/create", { identifier: "rt-api",
    protocols: ["oauth2"],
    fields: { oauthAudience: [API_AUD], oauthClientId: "rt-api-client" } },
    "registered rt-api");
  await ok(API + "/applications/create", { identifier: "rt-perm",
    protocols: ["oauth2"],
    fields: { oauthPermissionBaseUri: BASE_URI,
              oauthPermission: ["read|Read it"] } }, "registered rt-perm");
  await ok(API + "/applications/create", { identifier: "rt-oauth",
    protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: "rt-oauth", oauthRedirectUri: [REDIRECT],
              oauthTokenEndpointAuthMethod: "none",
              oauthGrantType: ["authorization_code",
                "urn:ietf:params:oauth:grant-type:token-exchange"] } },
    "registered rt-oauth");
  await ok(API + "/applications/create", { identifier: "rt-cc",
    protocols: ["oauth2"],
    fields: { oauthClientId: "rt-cc", oauthClientSecret: SECRET,
              oauthTokenEndpointAuthMethod: "client_secret_post",
              oauthGrantType: ["client_credentials"] } },
    "registered rt-cc");
  await ok(API + "/applications/create", { identifier: "rt-gnap-rs",
    kind: "gnap-resource-server", protocols: ["gnap"],
    fields: { gnapResourceServerUri: GNAP_RS } }, "registered rt-gnap-rs");
  await ok(API + "/authorization-servers/create", { id: "as1",
    label: "Named" }, "created a named authorization server");
  log.debug("Leaving fixtures().");
}

async function authorize(realm, resource) {
  log.debug("Entering authorize().");
  const query = new URLSearchParams({ response_type: "code",
    scope: "openid", client_id: "rt-oauth", redirect_uri: REDIRECT,
    state: "s-" + nodeCrypto.randomBytes(6).toString("hex"),
    nonce: "n-" + nodeCrypto.randomBytes(6).toString("hex"),
    code_challenge: nodeCrypto.randomBytes(32).toString("base64url"),
    code_challenge_method: "S256" });
  [].concat(resource === undefined ? [] : resource).forEach(function (one) {
    query.append("resource", one);
  });
  const r = await send(base + "/realm/" + realm + "/oauth2/authorize?" +
                       query.toString());
  let error = "";
  if (String(r.location).indexOf(REDIRECT) === 0) {
    error = new URL(r.location).searchParams.get("error") || "";
  }
  log.debug("Leaving authorize().");
  return { status: r.status, error: error,
           location: r.location || String(r.raw).slice(0, 300) };
}

async function authorizationEndpoint(realm) {
  log.debug("Entering authorizationEndpoint(). " + realm);
  const RB = base + "/realm/" + realm;
  const before = await codeCount(realm, "STS-OAUTH-0950");
  const refused = [NOBODY, [API_AUD, NOBODY], RB + "/gnap/rs/resource",
                   RB + "/resource/x", RB + "/other"];
  // ON THE WIRE A PRODUCT REALM DOES NOT REDIRECT IT: the development
  // realm sends invalid_target back to the registered redirect URI, as the
  // units file has both modes do, but the product realm answers this
  // service's own 400 page (the code is recorded all the same). Pinned, and
  // listed in the D12 notes: RFC 6749 section 4.1.2.1 redirects an error
  // once the client and its redirect URI are good.
  const product = realm === PROD;
  for (const one of refused) {
    const r = await authorize(realm, one);
    check("T3. " + realm + ": resource " + JSON.stringify(one) + " is " +
          (product ? "refused on this service's 400 page (pinned)"
                   : "a redirected invalid_target"), function () {
      if (product) {
        assert.strictEqual(r.status, 400, r.status + " " + r.location);
      } else {
        assert.ok(r.status === 302 || r.status === 303, r.status + " " +
                  r.location);
        assert.strictEqual(r.error, "invalid_target", r.location);
      }
    });
  }
  const after = await codeCount(realm, "STS-OAUTH-0950",
                                before + refused.length - 1);
  check("T3. " + realm + ": each recorded STS-OAUTH-0950", function () {
    assert.ok(after >= before + refused.length, before + " -> " + after);
  });
  // A CLIENT ID OR AN IDENTIFIER IS NO RESOURCE AT THIS DOOR: RFC 8707
  // section 2 asks for an absolute URI, and the request's schema refuses
  // one that is not before the target check (the units file asked the
  // definition, which knows the four names). The sentence names
  // `resource` (it named "the query parameter '0'" until
  // fix/node-defects-1114).
  for (const one of ["rt-api-client", "rt-api"]) {
    const r = await send(RB + "/oauth2/authorize?" + new URLSearchParams({
      response_type: "code", client_id: "rt-oauth", resource: one }));
    check("T3c. " + realm + ": the bare name " + one + " is refused 400 " +
          "invalid_request as no absolute URI, the sentence naming " +
          "resource", function () {
      assert.strictEqual(r.status, 400, r.raw.slice(0, 300));
      assert.strictEqual(r.body.error, "invalid_request");
      assert.ok(/resource/.test(r.body.error_description),
                r.raw.slice(0, 300));
      assert.ok(!/'0'/.test(r.body.error_description), r.raw.slice(0, 300));
    });
  }
  const passing = [API_AUD, BASE_URI,
                   BASE_URI.slice(0, -1), RB + "/resource",
                   RB + "/as1/resource", RB + "/admin-api",
                   RB + "/account-api", RB + "/report-api", undefined];
  for (const one of passing) {
    const r = await authorize(realm, one);
    check("T3b. " + realm + ": resource " + JSON.stringify(one) +
          " passes the target check", function () {
      assert.notStrictEqual(r.error, "invalid_target", r.location);
      assert.ok(r.status === 302 || r.status === 303, r.status + " " +
                r.location);
    });
  }
  log.debug("Leaving authorizationEndpoint().");
}

async function tokenEndpoint(realm) {
  log.debug("Entering tokenEndpoint(). " + realm);
  const RB = base + "/realm/" + realm;
  const ask = function (resource) {
    return postForm(RB + "/oauth2/token", { grant_type: "authorization_code",
      client_id: "rt-oauth", code: "not-a-code-" + STAMP,
      redirect_uri: REDIRECT, code_verifier: "v".repeat(43),
      resource: resource });
  };
  const c951 = await codeCount(realm, "STS-OAUTH-0951");
  const refused = await ask(NOBODY);
  const c951after = await codeCount(realm, "STS-OAUTH-0951", c951);
  check("T4. " + realm + ": a token request for an unregistered resource is " +
        "400 invalid_target before the grant is looked at, STS-OAUTH-0951",
        function () {
    assert.strictEqual(refused.status, 400, refused.raw.slice(0, 300));
    assert.strictEqual(refused.body.error, "invalid_target");
    assert.ok(c951after > c951, c951 + " -> " + c951after);
  });
  for (const one of [API_AUD, RB + "/admin-api", RB + "/account-api",
                     RB + "/report-api"]) {
    const r = await ask(one);
    check("T4b. " + realm + ": " + one + " passes the check and fails for " +
          "the made-up code instead", function () {
      assert.strictEqual(r.status, 400, r.raw.slice(0, 300));
      assert.notStrictEqual(r.body.error, "invalid_target",
                            r.raw.slice(0, 300));
    });
  }
  const exchange = await postForm(RB + "/oauth2/token", {
    grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
    client_id: "rt-oauth", subject_token: "x.y.z",
    subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
    resource: NOBODY });
  const c951x = await codeCount(realm, "STS-OAUTH-0951");
  check("T4c. " + realm + ": a token exchange is not asked: its targets " +
        "are RFC 8693's", function () {
    assert.ok(exchange.status >= 400, exchange.raw.slice(0, 300));
    assert.strictEqual(c951x, c951after, c951after + " -> " + c951x);
  });
  log.debug("Leaving tokenEndpoint().");
}

async function gnapRights() {
  log.debug("Entering gnapRights().");
  const GRANT = base + "/realm/" + DEV + "/gnap";
  const client = new gnap.Client({ key: gnap.newKey("ES256") });
  // `access` is one token's rights; `tokens`, when given, is several
  // tokens' requests as they stand.
  const asks = function (access, tokens) {
    const body = { client: { key: client.keyObject(),
                             display: { name: "registered targets " +
                                              STAMP } },
                   interact: { start: ["redirect"] },
                   access_token: tokens || { access: access } };
    return client.send("POST", GRANT, { json: body });
  };
  const right = function (locations) {
    const one = { type: "https://rt.example/photos", actions: ["read"] };
    if (locations) {
      one.locations = locations;
    }
    return one;
  };
  const c903 = await codeCount(DEV, "STS-GNAP-0903");
  for (const locations of [[NOBODY], [GNAP_RS, NOBODY]]) {
    const r = await asks([right(locations)]);
    check("T5. a GNAP right located at " + JSON.stringify(locations) +
          " is refused invalid_request", function () {
      assert.strictEqual(r.status, 400, r.status + " " + r.text.slice(0, 300));
      const error = (r.json || {}).error || {};
      assert.strictEqual(error.code || error, "invalid_request",
                         r.text.slice(0, 300));
    });
  }
  const c903after = await codeCount(DEV, "STS-GNAP-0903", c903 + 1);
  check("T5. both recorded STS-GNAP-0903", function () {
    assert.ok(c903after >= c903 + 2, c903 + " -> " + c903after);
  });
  // A REGISTERED APPLICATION'S AUDIENCE passes the target check (no
  // STS-GNAP-0903) and is then refused for naming no GNAP resource server
  // (STS-GNAP-0904): the units file asked only the first question of it.
  const c903b = await codeCount(DEV, "STS-GNAP-0903");
  const c904a = await codeCount(DEV, "STS-GNAP-0904");
  const audience = await asks([right([API_AUD])]);
  const c903c = await codeCount(DEV, "STS-GNAP-0903");
  const c904b = await codeCount(DEV, "STS-GNAP-0904", c904a);
  check("T5b. a right located at a registered application's audience " +
        "passes the target check and is refused as naming no resource " +
        "server (STS-GNAP-0904, not 0903)", function () {
    assert.strictEqual(audience.status, 400, audience.text.slice(0, 300));
    assert.strictEqual(c903c, c903b, c903b + " -> " + c903c);
    assert.ok(c904b > c904a, c904a + " -> " + c904b);
  });
  for (const access of [[right([GNAP_RS])], [right([GNAP_RS + "/photos/1"])],
                        ["ssf.read"], [{ type: "ssf", actions: ["read"] }]]) {
    // "Not refused for its target" is what is asked: Shared Signals' scope
    // is then refused 403 request_denied for a scope rule (#110), which
    // is another question, so the two target codes are what is counted.
    const n903 = await codeCount(DEV, "STS-GNAP-0903");
    const n904 = await codeCount(DEV, "STS-GNAP-0904");
    const r = await asks(access);
    const m903 = await codeCount(DEV, "STS-GNAP-0903");
    const m904 = await codeCount(DEV, "STS-GNAP-0904");
    check("T5b/T6c. " + JSON.stringify(access) + " is not refused for its " +
          "target (" + r.status + ")", function () {
      assert.ok(!/names no resource server|no registered/.test(r.text),
                r.status + " " + r.text.slice(0, 300));
      assert.strictEqual(m903 + m904, n903 + n904,
                         [n903, n904, m903, m904].join(" "));
    });
  }
  const c904 = await codeCount(DEV, "STS-GNAP-0904");
  for (const access of [["rt-unknown-reference"], [right(null)]]) {
    const r = await asks(access);
    check("T6. a token naming no resource server " + JSON.stringify(access) +
          " is refused invalid_request", function () {
      assert.strictEqual(r.status, 400, r.status + " " + r.text.slice(0, 300));
    });
  }
  const second = await asks(null, [
    { label: "a", access: [right([GNAP_RS])] },
    { label: "b", access: ["rt-unknown-reference"] }]);
  const c904after = await codeCount(DEV, "STS-GNAP-0904", c904 + 2);
  check("T6b. of two tokens, the one naming nobody is refused by its index, " +
        "and the three are recorded STS-GNAP-0904", function () {
    assert.strictEqual(second.status, 400, second.text.slice(0, 300));
    assert.ok(/access_token\[1\]/.test(second.text), second.text
      .slice(0, 300));
    assert.ok(c904after >= c904 + 3, c904 + " -> " + c904after);
  });
  log.debug("Leaving gnapRights().");
}

async function thePlan() {
  log.debug("Entering thePlan().");
  const RB = base + "/realm/" + DEV;
  const cc = function (resource) {
    const fields = { grant_type: "client_credentials", client_id: "rt-cc",
                     client_secret: SECRET };
    if (resource) {
      fields.resource = resource;
    }
    return postForm(RB + "/oauth2/token", fields);
  };
  let r = await cc();
  check("T7b. a client-credentials token with no resource is planned for " +
        "the client's own client_id", function () {
    assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
    const aud = JSON.parse(Buffer.from(r.body.access_token.split(".")[1],
                                       "base64url").toString()).aud;
    assert.deepStrictEqual([].concat(aud), ["rt-cc"]);
  });
  for (const one of [RB + "/report-api", RB + "/resource"]) {
    r = await cc(one);
    check("T7b. and one for " + one + " while its object exists",
          function () {
      assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
    });
  }
  for (const id of ["sts-report-api", "sts-resource"]) {
    await ok(RB + "/admin-api/applications/forget", { application: id },
             "deleted " + id + " from the realm");
  }
  // The token endpoint's own registered-target check answers first
  // (STS-OAUTH-0951), so the plan's STS-OAUTH-0986 is not what these
  // record.
  const before = await codeCount(DEV, "STS-OAUTH-0951");
  const noReport = await cc(RB + "/report-api");
  const noDefault = await cc(RB + "/resource");
  const after = await codeCount(DEV, "STS-OAUTH-0951", before + 1);
  check("T7c. with their objects deleted, /report-api and the default " +
        "resource are refused invalid_target, both recorded STS-OAUTH-0951",
        function () {
    assert.strictEqual(noReport.status, 400, noReport.raw.slice(0, 300));
    assert.strictEqual(noReport.body.error, "invalid_target");
    assert.strictEqual(noDefault.status, 400, noDefault.raw.slice(0, 300));
    assert.strictEqual(noDefault.body.error, "invalid_target");
    assert.ok(after >= before + 2, before + " -> " + after);
  });
  log.debug("Leaving thePlan().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Registered targets at " + base);
  const report = await send(base + "/admin-api/mode");
  check("T1. the mode report lists no unregistered-resource-targets row " +
        "(#1140)", function () {
    assert.strictEqual(report.status, 200, report.raw.slice(0, 200));
    assert.ok(report.raw.indexOf("unregistered-resource-targets") < 0);
  });
  await createRealm(DEV, "development", "Registered targets");
  await createRealm(PROD, "product", "Registered targets (product)");
  for (const realm of [DEV, PROD]) {
    await fixtures(realm);
    await authorizationEndpoint(realm);
    await tokenEndpoint(realm);
  }
  await gnapRights();
  await thePlan();
  assert.ok(checks >= 60, "only " + checks + " checks ran; a section has " +
                          "stopped being called.");
  log.debug("Leaving test().");
}

main();
