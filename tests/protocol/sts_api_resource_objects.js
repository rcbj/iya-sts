// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_api_resource_objects.js
//
// ---------------------------------------------------------------------------
// THIS SERVICE'S OWN APIS ARE APPLICATION OBJECTS, AND A RESOURCE IS NEVER A
// CLIENT (#1139), OVER THE WIRE.
//
// D12 (#444): carries over tests/api_resource_objects.js. In a throwaway
// realm, in development (the mode that verifies no client credential, so
// the one where a resource could most easily pass for a client):
//
//   A. sts-management-api, sts-account-api, sts-report-api,
//      sts-authzen-api and sts-resource are seeded as
//      `oauth2-resource-server` alone, each holding its API's audience under
//      the realm's prefix, with no grant type;
//   B. sts-api-client is a confidential client_credentials client, a member
//      of ADMIN_READ, ADMIN_WRITE and REPORT_USE and not of REPORT_ADMIN —
//      read off `GET /admin-api/applications` and `GET /admin-api/roles`;
//   C. every resource object's client_id is refused 401 invalid_client at
//      the token, PAR, introspection, revocation, device authorization and
//      CIBA endpoints, as the Basic user with a Basic challenge, and 400
//      with no redirect at the authorization endpoint — each recorded
//      STS-OAUTH-0985 off the realm's audit log, no code sent;
//   D. the default realm's sts-api-client (the suite's own secret) is
//      issued an /admin-api token and a /report-api token, one per
//      resource, each accepted where it is addressed.
//
// NOT CARRIED: `applications.clientConfigOf()`'s absent secret on a
// resource (an internal record; the wire shows no grant type and the
// refusals) — class (d).
//
// OWNED HERE (local: true): this repository's own management API.
// ---------------------------------------------------------------------------

const assert = require("assert");
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
var log = bunyan.createLogger({ name: "sts_api_resource_objects",
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
const REALM = "apiobj-" + STAMP;
const R = "/realm/" + REALM;
const RB = base + R;
const API = RB + "/admin-api";

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

function absolute(location) {
  log.debug("Entering absolute().");
  log.debug("Leaving absolute().");
  return /^https?:\/\//i.test(String(location || ""))
    ? String(location) : base + String(location || "");
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
    // Not JSON — a page or a JWT; the caller reads `raw`.
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

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await postJson(url, payload);
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + String(r.raw).slice(0, 400));
  log.debug("Leaving ok().");
  return r.body;
}

// A refusal: a 400 whose answer names no code.
async function refused(url, payload, what) {
  log.debug("Entering refused().");
  const r = await postJson(url, payload);
  assert.ok(r.status === 400 && r.body && r.body.ok === false,
    "POST " + url + " should have refused " + what + "; it answered " +
    r.status + " " + String(r.raw).slice(0, 400));
  assert.ok(!/STS-[A-Z]+-\d{4}/.test(r.raw), "no code is sent: " + r.raw);
  log.debug("Leaving refused().");
  return r.body;
}

async function codeCount(api, code) {
  log.debug("Entering codeCount(). " + code);
  const r = await send(api + "/audit?per=500&code=" +
                       encodeURIComponent(code));
  log.debug("Leaving codeCount().");
  return Number((r.body && r.body.matched) || 0);
}

async function codesSettle(api, code, atLeast) {
  log.debug("Entering codesSettle(). " + code);
  let n = await codeCount(api, code);
  for (let i = 0; i < 20 && n < atLeast; i += 1) {
    await sleep(150);
    n = await codeCount(api, code);
  }
  log.debug("Leaving codesSettle(). " + n);
  return n;
}

const RESOURCES = [
  ["sts-management-api", "/admin-api"],
  ["sts-account-api", "/account-api"],
  ["sts-report-api", "/report-api"],
  ["sts-authzen-api", "/access/v1"],
  ["sts-resource", "/resource"]
];
const ENDPOINTS = ["/oauth2/token", "/oauth2/par", "/oauth2/introspect",
                   "/oauth2/revoke", "/oauth2/device_authorization",
                   "/oauth2/bc-authorize"];

async function application(id) {
  log.debug("Entering application(). " + id);
  const r = await send(API + "/applications?application=" +
                       encodeURIComponent(id));
  assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
  log.debug("Leaving application().");
  return r.body;
}

async function roleMembers(role) {
  log.debug("Entering roleMembers(). " + role);
  const r = await send(API + "/roles?role=" + encodeURIComponent(role));
  assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
  log.debug("Leaving roleMembers().");
  return (r.body.role && r.body.role.applications) || [];
}

function formPost(url, fields, headers) {
  log.debug("Entering formPost(). " + url);
  log.debug("Leaving formPost().");
  return send(url, { method: "POST", headers: Object.assign({
    "Content-Type": "application/x-www-form-urlencoded",
    Accept: "application/json" }, headers || {}),
    body: new URLSearchParams(fields).toString() });
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving the API resource objects at " + RB);
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "API objects " + STAMP },
    "created the realm");

  log.info("=== A. the resource objects ===");
  for (const pair of RESOURCES) {
    const app = await application(pair[0]);
    check("A. " + pair[0] + " is a resource object alone, holding " + R +
          pair[1] + ", with no grant type", function () {
      assert.strictEqual(app.found !== false, true, JSON.stringify(app)
        .slice(0, 300));
      assert.deepStrictEqual(app.kinds, ["oauth2-resource-server"]);
      const audiences = [].concat(app.fields.oauthAudience || []);
      assert.ok(audiences.some(function (one) {
        return one.replace(/^https?:\/\/[^/]+/, "") === R + pair[1];
      }), JSON.stringify(audiences));
      assert.strictEqual(app.fields.oauthGrantType, undefined,
                         JSON.stringify(app.fields.oauthGrantType));
    });
  }

  log.info("=== B. the bootstrap client ===");
  const client = await application("sts-api-client");
  check("B1. sts-api-client is a confidential client_credentials client",
        function () {
    assert.ok(client.kinds.indexOf("oauth2-client") >= 0,
              JSON.stringify(client.kinds));
    assert.ok(client.kinds.indexOf("oauth2-resource-server") < 0);
    assert.deepStrictEqual([].concat(client.fields.oauthGrantType),
                           ["client_credentials"]);
    assert.deepStrictEqual([].concat(
      client.fields.oauthTokenEndpointAuthMethod), ["client_secret_basic"]);
  });
  const held = {};
  for (const role of ["ADMIN_READ", "ADMIN_WRITE", "REPORT_USE",
                      "REPORT_ADMIN"]) {
    held[role] = (await roleMembers(role)).indexOf("sts-api-client") >= 0;
  }
  check("B2. it is a member of ADMIN_READ, ADMIN_WRITE and REPORT_USE, and " +
        "not of REPORT_ADMIN", function () {
    assert.deepStrictEqual(held, { ADMIN_READ: true, ADMIN_WRITE: true,
                                   REPORT_USE: true, REPORT_ADMIN: false });
  });

  log.info("=== C. a resource is never a client ===");
  const start = await codeCount(API, "STS-OAUTH-0985");
  let refusals = 0;
  for (const pair of RESOURCES) {
    for (const endpoint of ENDPOINTS) {
      const r = await formPost(RB + endpoint, {
        grant_type: "client_credentials", client_id: pair[0],
        token: "x", scope: "openid", login_hint: "nobody",
        response_type: "code", redirect_uri: "https://rp.example/cb" });
      refusals += 1;
      check("C. " + endpoint + " refuses " + pair[0] + " as a client, 401 " +
            "invalid_client", function () {
        assert.strictEqual(r.status, 401, r.raw.slice(0, 300));
        assert.strictEqual(r.body && r.body.error, "invalid_client");
        assert.ok(!/STS-[A-Z]+-\d{4}/.test(r.raw), r.raw);
      });
    }
  }
  const basic = await formPost(RB + "/oauth2/token", {
    grant_type: "client_credentials", scope: "admin:read" },
    { Authorization: "Basic " + Buffer.from("sts-management-api:anything")
      .toString("base64") });
  refusals += 1;
  check("C. named as the Basic user, the resource is refused with a Basic " +
        "challenge", function () {
    assert.strictEqual(basic.status, 401, basic.raw.slice(0, 300));
    assert.strictEqual(basic.body.error, "invalid_client");
    assert.ok(/^Basic/i.test(String(basic.headers.get("www-authenticate"))),
              String(basic.headers.get("www-authenticate")));
  });
  const authz = await send(RB + "/oauth2/authorize?" + new URLSearchParams({
    client_id: "sts-report-api", response_type: "code", scope: "openid",
    redirect_uri: "https://rp.example/cb", state: "s" }).toString(),
    { headers: { Accept: "application/json" } });
  refusals += 1;
  check("C. the authorization endpoint answers 400 for a resource and does " +
        "not redirect", function () {
    assert.strictEqual(authz.status, 400, authz.raw.slice(0, 300));
    assert.strictEqual(authz.location, "");
  });
  const counted = await codesSettle(API, "STS-OAUTH-0985", start + refusals);
  check("C. every one of the " + refusals + " refusals is recorded " +
        "STS-OAUTH-0985", function () {
    assert.ok(counted - start >= refusals, "rows added: " +
              (counted - start) + " of " + refusals);
  });

  log.info("=== D. the client at work, in the default realm ===");
  const secret = process.env.STS_ADMIN_API_CLIENT_SECRET ||
                 process.env.ADMIN_API_CLIENT_SECRET || "";
  const auth = { Authorization: "Basic " + Buffer.from("sts-api-client:" +
                 secret).toString("base64") };
  const admin = await formPost(base + "/oauth2/token", {
    grant_type: "client_credentials", scope: "admin:read admin:write",
    resource: base + "/admin-api" }, auth);
  check("D1. sts-api-client is issued an /admin-api token", function () {
    assert.strictEqual(admin.status, 200, admin.raw.slice(0, 300));
    assert.strictEqual(String(admin.body.scope), "admin:read admin:write");
  });
  const me = await fetch(base + "/admin-api/me", { headers: {
    Authorization: "Bearer " + admin.body.access_token } });
  check("D2. and /admin-api accepts it", function () {
    assert.strictEqual(me.status, 200);
  });
  const report = await formPost(base + "/oauth2/token", {
    grant_type: "client_credentials", scope: "report:use",
    resource: base + "/report-api" }, auth);
  check("D3. it is issued a /report-api token with report:use", function () {
    assert.strictEqual(report.status, 200, report.raw.slice(0, 300));
    assert.strictEqual(String(report.body.scope), "report:use");
  });
  const reportApi = await fetch(base + "/report-api", { headers: {
    Authorization: "Bearer " + report.body.access_token } });
  check("D4. and /report-api accepts it", function () {
    assert.strictEqual(reportApi.status, 200);
  });

  assert.ok(checks >= 40, "only " + checks + " checks ran; a section has " +
                          "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
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
  for (const id of [REALM]) {
    const r = await postJson(base + "/admin-api/realms/remove", { id: id });
    log.info("removed the realm " + id + " (" + r.status + ")");
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
    log.warn("could not remove the realms: " + e.message);
  }
  if (failure) {
    log.error(failure.stack || failure.message);
    log.debug("Leaving main(). Failed.");
    process.exit(1);
  }
  log.debug("Leaving main().");
}

main();
