// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_cors.js
//
// ---------------------------------------------------------------------------
// THE CORS ALLOWLIST, ASKED OF A RUNNING SERVICE (2026-09-13).
//
// D12 (#444): carries over `tests/cors.js`, which holds the rule on a small
// express app built around the real middlewares; here it is the service
// itself, in a throwaway realm this job leaves behind:
//
//   A. WHAT AN ORIGIN IS, through the register: each spelling a browser
//      might send held in the one serialisation it sends (case, the default
//      port, IDN, IPv6), and each value that is not an origin (`*`, a
//      wildcard host, `null`, a path, a query, a fragment, a user name, no
//      scheme, no host, a bad port) refusing the create whole, with
//      STS-REG-0150 on the audit and nothing written; an empty value in the
//      list dropped as no value;
//   B. THE REGISTER'S WRITES: two spellings of one origin held once, an add
//      of `null` refused, an add stored normalised, the same origin in the
//      other spelling changing nothing, and a remove finding it by either;
//   C. THE DECISION over the realm's own endpoints: no Origin is no header
//      and `Vary: Origin`; discovery names no client, so the realm's union
//      is allowed (with the DPoP nonce exposed) and a stranger is not; a
//      token request is judged by the client it names — its own list, an
//      unknown client refused, an empty list refusing, a Basic credential
//      naming its client and two names both having to allow it, a client
//      assertion naming its `sub`; an access token names its client and
//      `azp` stands in for one; off an OAuth path a Basic user name that is
//      no application is a person; a preflight answered with what it asked
//      for and never credentials, and a refused one a 204 with no headers;
//      this service's own origin and `global.corsOrigins` always allowed; a
//      cross-origin navigation never decided; RFC 9700 mode withholding CORS
//      from the authorization endpoint; nothing anywhere answering `*`;
//   D. GNAP: its OPTIONS discovery reaches its route from a refused origin
//      and an allowed one, a published API's page ending in `gnap` is a
//      preflight that never reaches a route (#1503), and GNAP's preflight
//      lists OPTIONS (#1214) where another path's does not.
//
// Which code a withheld header is LOGGED under (STS-HTTP-0019..0022) is a
// log line and no audit row, so no client can read it; `tests/cors.js`
// keeps that half.
//
// Its realms are left standing, as every job's are, unless
// STS_TEST_REMOVE_REALMS=1 asks for them to be removed at the end: a hand
// run against a private probe would otherwise fill its directory.
//
// OWNED HERE (local: true): this repository's own HTTP spine.
// ---------------------------------------------------------------------------

const assert = require("assert");
const https = require("https");
const names = require("./random_username.js");
const serviceTrust = require("../tools/service_trust.js");

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
var log = bunyan.createLogger({ name: "sts_cors",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const SUFFIX = STAMP.toLowerCase().replace(/[^a-z0-9]/g, "");
const REALM = ("cors-" + SUFFIX).slice(0, 31);
const BSP = ("corsbcp-" + SUFFIX).slice(0, 31);
const ORIGIN_A = "https://a-" + SUFFIX + ".example";
const ORIGIN_B = "https://b-" + SUFFIX + ".example";
const STRANGER = "https://stranger-" + SUFFIX + ".example";
const LISTED = "https://listed-" + SUFFIX + ".example";
const A = "cors-a-" + SUFFIX;
const B = "cors-b-" + SUFFIX;
const EMPTY = "cors-empty-" + SUFFIX;
const FORM = { "Content-Type": "application/x-www-form-urlencoded" };

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
    // Not JSON — a page or an empty answer; the caller reads `raw`.
    body = null;
  }
  log.debug("Leaving send(). status=" + r.status);
  return { status: r.status, headers: r.headers, body: body, raw: raw };
}

// fetch() sets `Sec-Fetch-Mode: cors` itself and a caller cannot replace
// it, so a navigation is asked with https.request, which sends what it is
// given.
function rawRequest(url, method, headers, body) {
  log.debug("Entering rawRequest(). url=" + url);
  log.debug("Leaving rawRequest().");
  return new Promise(function (resolve, reject) {
    const req = https.request(url, { method: method, headers: headers,
                                     ca: serviceTrust.trustedCa() },
                              function (res) {
      let raw = "";
      res.on("data", function (c) {
        raw += c;
      });
      res.on("end", function () {
        resolve({ status: res.statusCode, raw: raw, headers: {
          get: function (name) {
            const v = res.headers[String(name).toLowerCase()];
            return v === undefined ? null : v;
          } } });
      });
    });
    req.on("error", reject);
    req.end(body || undefined);
  });
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

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

function api(realm) {
  log.debug("Entering api().");
  log.debug("Leaving api().");
  return base + "/realm/" + realm + "/admin-api";
}

async function codeCount(code) {
  log.debug("Entering codeCount(). " + code);
  const r = await send(api(REALM) + "/audit?per=500&code=" +
                       encodeURIComponent(code));
  const rows = (r.body && (r.body.events || r.body.rows)) || [];
  log.debug("Leaving codeCount(). " + rows.length);
  return rows.length;
}

async function sawCode(code, before) {
  log.debug("Entering sawCode(). " + code);
  let after = await codeCount(code);
  for (let i = 0; i < 20 && after <= before; i += 1) {
    await sleep(150);
    after = await codeCount(code);
  }
  log.debug("Leaving sawCode(). " + before + " -> " + after);
  return after > before;
}

async function corsOf(id) {
  log.debug("Entering corsOf(). " + id);
  const r = await send(api(REALM) + "/applications?application=" +
                       encodeURIComponent(id));
  log.debug("Leaving corsOf().");
  return r.body && r.body.found !== false ?
    [].concat((r.body.fields || {}).appCorsOrigin || []) : null;
}

function create(realm, id, origins, extra) {
  log.debug("Entering create(). " + id);
  const fields = Object.assign({ oauthClientId: [id],
                                 oauthGrantType: ["client_credentials"] },
                               extra || {});
  if (origins) {
    fields.appCorsOrigin = origins;
  }
  log.debug("Leaving create().");
  return postJson(api(realm) + "/applications/create", { identifier: id,
    kind: "oauth2-client", name: id, protocols: ["oauth2"],
    fields: fields });
}

const NORMALISED = [
  ["https://app.example.com", "https://app.example.com"],
  ["HTTPS://App.Example.COM:443/", "https://app.example.com"],
  ["http://localhost:3000", "http://localhost:3000"],
  ["http://LOCALHOST:80", "http://localhost"],
  ["http://[::1]:5173", "http://[::1]:5173"],
  ["https://bücher.example", "https://xn--bcher-kva.example"],
  ["chrome-extension://abcdefghijklmnop",
   "chrome-extension://abcdefghijklmnop"]
];

const REFUSED = [
  ["*", "the wildcard this rule replaces"],
  ["https://*.example.com", "a wildcard host no browser sends"],
  ["null", "the opaque origin every sandboxed frame shares"],
  ["https://app.example.com/spa", "a path the comparison would drop"],
  ["https://app.example.com?x=1", "a query"],
  ["https://app.example.com#x", "a fragment"],
  ["https://user@app.example.com", "a user name"],
  ["app.example.com", "no scheme"],
  ["file:///tmp/x", "no host"],
  ["https://app.example.com:99999", "a port that does not parse"]
];

async function sectionGrammar() {
  log.debug("Entering sectionGrammar().");
  log.info("=== A. what an origin is ===");
  for (let i = 0; i < NORMALISED.length; i += 1) {
    const id = "cors-n" + i + "-" + SUFFIX;
    const r = await create(REALM, id, [NORMALISED[i][0]]);
    const held = await corsOf(id);
    check("held as the origin a browser sends: " + NORMALISED[i][0],
          function () {
      assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
      assert.deepStrictEqual(held, [NORMALISED[i][1]]);
    });
  }
  for (let i = 0; i < REFUSED.length; i += 1) {
    const id = "cors-r" + i + "-" + SUFFIX;
    const before = await codeCount("STS-REG-0150");
    const r = await create(REALM, id, ["https://ok.example",
                                       REFUSED[i][0]]);
    const seen = await sawCode("STS-REG-0150", before);
    const held = await corsOf(id);
    check("refused as an origin, the create whole: " +
          JSON.stringify(REFUSED[i][0]) + " (" + REFUSED[i][1] + ")",
          function () {
      assert.strictEqual(r.status, 400, r.raw.slice(0, 300));
      assert.ok(seen, "no STS-REG-0150 on the audit log");
      assert.ok(!/STS-[A-Z]+-\d{4}/.test(r.raw), r.raw.slice(0, 200));
      assert.strictEqual(held, null, "something was written");
    });
  }
  const blank = "cors-blank-" + SUFFIX;
  const r = await create(REALM, blank, ["https://ok.example", ""]);
  const held = await corsOf(blank);
  check("an empty value in the list is no value: it is dropped and the " +
        "rest is kept", function () {
    assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
    assert.deepStrictEqual(held, ["https://ok.example"]);
  });
  log.debug("Leaving sectionGrammar().");
}

function update(action, id, value) {
  log.debug("Entering update(). " + action);
  log.debug("Leaving update().");
  return postJson(api(REALM) + "/applications/" + action, {
    application: id, attribute: "appCorsOrigin", value: value });
}

async function sectionWrites() {
  log.debug("Entering sectionWrites().");
  log.info("=== B. what the register stores ===");
  const id = "cors-w-" + SUFFIX;
  const made = await create(REALM, id, ["HTTPS://Spa.Example:443/",
                                        "https://spa.example"]);
  const held = await corsOf(id);
  check("two spellings of one origin are held ONCE, as a browser sends it",
        function () {
    assert.strictEqual(made.status, 200, made.raw.slice(0, 300));
    assert.deepStrictEqual(held, ["https://spa.example"]);
  });
  const before = await codeCount("STS-REG-0150");
  const bad = await update("add", id, "null");
  const seen = await sawCode("STS-REG-0150", before);
  check("an add of `null` is refused with STS-REG-0150", function () {
    assert.strictEqual(bad.status, 400, bad.raw.slice(0, 300));
    assert.ok(seen);
  });
  const added = await update("add", id, "HTTP://LocalHost:5173/");
  const afterAdd = await corsOf(id);
  check("an add is accepted and stored normalised", function () {
    assert.strictEqual(added.status, 200, added.raw.slice(0, 300));
    assert.ok(afterAdd.indexOf("http://localhost:5173") >= 0 &&
              afterAdd.indexOf("HTTP://LocalHost:5173/") < 0,
              JSON.stringify(afterAdd));
  });
  const again = await update("add", id, "http://localhost:5173");
  const afterAgain = await corsOf(id);
  check("the same origin in the other spelling changes nothing", function () {
    assert.strictEqual(again.status, 200, again.raw.slice(0, 300));
    assert.deepStrictEqual(afterAgain, afterAdd);
  });
  const removed = await update("remove", id, "HTTP://LOCALHOST:5173");
  const afterRemove = await corsOf(id);
  check("a remove finds the value by its normalised spelling", function () {
    assert.strictEqual(removed.status, 200, removed.raw.slice(0, 300));
    assert.deepStrictEqual(afterRemove, ["https://spa.example"]);
  });
  log.debug("Leaving sectionWrites().");
}

function acao(r) {
  log.debug("Entering acao().");
  log.debug("Leaving acao().");
  return String(r.headers.get("access-control-allow-origin") || "");
}

// A JWT nobody signed: the CORS decision reads who a credential names,
// never whether it verifies.
function unsignedJwt(claims) {
  log.debug("Entering unsignedJwt().");
  const part = function (o) {
    return Buffer.from(JSON.stringify(o)).toString("base64url");
  };
  log.debug("Leaving unsignedJwt().");
  return part({ alg: "none", typ: "JWT" }) + "." + part(claims) + ".";
}

function basic(user) {
  log.debug("Entering basic().");
  log.debug("Leaving basic().");
  return "Basic " + Buffer.from(user + ":secret").toString("base64");
}

function token(realm, origin, body, headers) {
  log.debug("Entering token().");
  log.debug("Leaving token().");
  return send(base + "/realm/" + realm + "/oauth2/token", { method: "POST",
    headers: Object.assign({ Origin: origin }, FORM, headers || {}),
    body: body });
}

async function sectionDecision() {
  log.debug("Entering sectionDecision().");
  log.info("=== C. the decision ===");
  const R = base + "/realm/" + REALM;
  let r = await send(R + "/.well-known/openid-configuration");
  check("a request with no Origin gets no CORS header, and Vary: Origin",
        function () {
    assert.strictEqual(acao(r), "");
    assert.ok(/Origin/.test(r.headers.get("vary") || ""),
              r.headers.get("vary"));
  });
  r = await send(R + "/.well-known/openid-configuration",
                 { headers: { Origin: ORIGIN_A } });
  check("discovery names no client, so an origin any application in the " +
        "realm lists is allowed, and the DPoP nonce is exposed to it",
        function () {
    assert.strictEqual(acao(r), ORIGIN_A);
    assert.ok(/DPoP-Nonce/i.test(r.headers.get(
      "access-control-expose-headers") || ""));
  });
  r = await send(R + "/.well-known/openid-configuration",
                 { headers: { Origin: STRANGER } });
  check("and an origin no application lists is not, and nothing answers *",
        function () {
    assert.strictEqual(acao(r), "");
  });
  r = await token(REALM, ORIGIN_A, "grant_type=client_credentials" +
                  "&client_id=" + A);
  check("a token request naming client A from A's origin is allowed",
        function () {
    assert.strictEqual(acao(r), ORIGIN_A);
  });
  r = await token(REALM, ORIGIN_B, "grant_type=client_credentials" +
                  "&client_id=" + A);
  check("PER CLIENT: naming A from B's origin is not, though B's origin is " +
        "in the realm's union", function () {
    assert.strictEqual(acao(r), "");
  });
  r = await token(REALM, ORIGIN_A, "grant_type=client_credentials" +
                  "&client_id=no-such-" + SUFFIX);
  check("an unknown client_id gets no CORS header even from a listed origin",
        function () {
    assert.strictEqual(acao(r), "");
  });
  r = await token(REALM, ORIGIN_A, "grant_type=client_credentials" +
                  "&client_id=" + EMPTY);
  check("a client with an empty appCorsOrigin allows no third-party origin",
        function () {
    assert.strictEqual(acao(r), "");
  });
  r = await token(REALM, ORIGIN_A, "grant_type=client_credentials" +
                  "&client_id=" + A, { Authorization: basic(B) });
  check("two names on one request must both allow the origin", function () {
    assert.strictEqual(acao(r), "");
  });
  r = await token(REALM, ORIGIN_B, "grant_type=client_credentials",
                  { Authorization: basic(B) });
  check("a Basic credential names its client", function () {
    assert.strictEqual(acao(r), ORIGIN_B);
  });
  r = await token(REALM, ORIGIN_A, "grant_type=client_credentials" +
                  "&client_assertion=" + unsignedJwt({ iss: B, sub: B }));
  check("a client assertion names its sub: B from A's origin is refused",
        function () {
    assert.strictEqual(acao(r), "");
  });
  r = await send(R + "/oauth2/userinfo", { headers: { Origin: ORIGIN_B,
    Authorization: "Bearer " + unsignedJwt({ client_id: B }) } });
  check("an access token names the client it was issued to", function () {
    assert.strictEqual(acao(r), ORIGIN_B);
  });
  r = await send(R + "/oauth2/userinfo", { headers: { Origin: ORIGIN_A,
    Authorization: "DPoP " + unsignedJwt({ azp: B }) } });
  check("and azp stands in for client_id, under DPoP too", function () {
    assert.strictEqual(acao(r), "");
  });
  r = await send(R + "/scim/v2/Users", { headers: { Origin: ORIGIN_A,
    Authorization: basic("alice-" + SUFFIX) } });
  check("off an OAuth path a Basic user name that is no application is a " +
        "person, and the request names no client", function () {
    assert.strictEqual(acao(r), ORIGIN_A);
  });
  r = await send(R + "/scim/v2/Users", { headers: { Origin: ORIGIN_A,
    Authorization: basic("scim-" + B) } });
  check("while one that is an application's scimClientId is judged against " +
        "that application", function () {
    assert.strictEqual(acao(r), "");
  });
  r = await send(R + "/oauth2/token", { method: "OPTIONS", headers: {
    Origin: ORIGIN_A, "Access-Control-Request-Method": "POST",
    "Access-Control-Request-Headers": "authorization,dpop" } });
  check("a preflight from a listed origin is answered with the method and " +
        "headers it asked for, and never credentials", function () {
    assert.strictEqual(r.status, 204);
    assert.strictEqual(acao(r), ORIGIN_A);
    assert.ok(/POST/.test(r.headers.get("access-control-allow-methods") ||
                          ""));
    assert.ok(/dpop/i.test(r.headers.get("access-control-allow-headers") ||
                           ""));
    assert.strictEqual(r.headers.get("access-control-allow-credentials"),
                       null);
    assert.ok(String(r.headers.get("access-control-allow-methods") || "")
      .split(",").indexOf("OPTIONS") < 0, "OPTIONS listed off GNAP");
  });
  r = await send(R + "/oauth2/token", { method: "OPTIONS", headers: {
    Origin: STRANGER, "Access-Control-Request-Method": "POST" } });
  check("and one from an origin nobody lists is a 204 with no CORS headers",
        function () {
    assert.strictEqual(r.status, 204);
    assert.strictEqual(acao(r), "");
  });
  const own = new URL(base).origin;
  r = await send(R + "/oauth2/userinfo", { headers: { Origin: own,
    Authorization: "Bearer " + unsignedJwt({ client_id: "no-such-" +
                                                         SUFFIX }) } });
  check("this service's own origin is allowed whatever the request names",
        function () {
    assert.strictEqual(acao(r), own);
  });
  await ok(api(REALM) + "/config/set", { key: "global.corsOrigins",
    value: LISTED + ",not an origin" }, "listed an origin of the service's");
  r = await token(REALM, LISTED, "client_id=" + A);
  check("and so is an origin global.corsOrigins names, beside a value there " +
        "that is ignored", function () {
    assert.strictEqual(acao(r), LISTED);
  });
  r = await rawRequest(R + "/saml2/sso", "POST",
    Object.assign({ Origin: ORIGIN_A, "Sec-Fetch-Mode": "navigate" }, FORM),
    "SAMLRequest=x");
  const fetched = await rawRequest(R + "/saml2/sso", "POST",
    Object.assign({ Origin: ORIGIN_A, "Sec-Fetch-Mode": "cors" }, FORM),
    "SAMLRequest=x");
  check("a cross-origin navigation is answered and not decided at all, " +
        "where the same request as a fetch from that origin is",
        function () {
    assert.strictEqual(acao(r), "");
    assert.ok(r.status < 500, String(r.status));
    assert.strictEqual(acao(fetched), ORIGIN_A);
  });
  r = await send(R + "/oauth2/authorize?client_id=" + A,
                 { headers: { Origin: ORIGIN_A } });
  check("outside RFC 9700 mode the authorization endpoint is judged by the " +
        "client it names", function () {
    assert.strictEqual(acao(r), ORIGIN_A);
  });
  const bcpA = "cors-bcp-" + SUFFIX;
  await create(BSP, bcpA, [ORIGIN_A]);
  await ok(api(BSP) + "/config/set", { key: "oauth2.rfc9700", value: "true" },
           "put the realm in RFC 9700 mode");
  r = await send(base + "/realm/" + BSP + "/oauth2/authorize?client_id=" +
                 bcpA, { headers: { Origin: ORIGIN_A } });
  const tokenBcp = await token(BSP, ORIGIN_A, "grant_type=client_credentials" +
                               "&client_id=" + bcpA);
  check("RFC 9700 section 2.6 withholds CORS from the authorization " +
        "endpoint, for a client that lists the origin, and not from the " +
        "token endpoint", function () {
    assert.strictEqual(acao(r), "");
    assert.strictEqual(acao(tokenBcp), ORIGIN_A);
  });
  log.debug("Leaving sectionDecision().");
}

async function sectionGnap() {
  log.debug("Entering sectionGnap().");
  log.info("=== D. GNAP's OPTIONS discovery ===");
  const R = base + "/realm/" + REALM;
  let r = await send(R + "/gnap", { method: "OPTIONS",
                                    headers: { Origin: STRANGER } });
  check("GNAP's OPTIONS discovery reaches its route from a refused origin",
        function () {
    assert.strictEqual(r.status, 200, r.raw.slice(0, 200));
    assert.ok(/grant_request_endpoint/.test(r.raw));
    assert.strictEqual(acao(r), "");
  });
  r = await send(R + "/gnap", { method: "OPTIONS", headers: {
    Origin: ORIGIN_A, "Access-Control-Request-Method": "POST" } });
  check("and from an allowed one, with the CORS headers on it", function () {
    assert.strictEqual(r.status, 200);
    assert.ok(/grant_request_endpoint/.test(r.raw));
    assert.strictEqual(acao(r), ORIGIN_A);
  });
  r = await send(R + "/account-api/gnap", { method: "OPTIONS", headers: {
    Origin: ORIGIN_A, "Access-Control-Request-Method": "GET" } });
  check("a published API's page ending in gnap is a preflight and never " +
        "reaches a route (#1503)", function () {
    assert.ok(!/grant_request_endpoint/.test(r.raw), r.raw.slice(0, 200));
  });
  r = await send(R + "/gnap", { method: "OPTIONS", headers: {
    Origin: ORIGIN_A, "Access-Control-Request-Method": "OPTIONS" } });
  const methods = String(r.headers.get("access-control-allow-methods") || "")
    .split(",");
  check("GNAP's preflight lists OPTIONS, and still POST (#1214)",
        function () {
    assert.strictEqual(acao(r), ORIGIN_A);
    assert.ok(methods.indexOf("OPTIONS") >= 0 &&
              methods.indexOf("POST") >= 0, methods.join(","));
  });
  log.debug("Leaving sectionGnap().");
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. throwaway realms " + REALM + " and " + BSP + " ===");
  for (const id of [REALM, BSP]) {
    await ok(base + "/admin-api/realms/create", { id: id,
      domain: id + ".example.net", name: "CORS " + STAMP },
      "created the realm " + id);
  }
  await sectionGrammar();
  await sectionWrites();
  for (const one of [[A, [ORIGIN_A]],
                     [B, [ORIGIN_B], { scimClientId: ["scim-" + B] }],
                     [EMPTY, null]]) {
    const r = await create(REALM, one[0], one[1], one[2]);
    assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
  }
  await sectionDecision();
  await sectionGnap();
  log.info(checks + " checks passed.");
  log.debug("Leaving test().");
}

// THE REALMS ARE LEFT STANDING, as every job leaves its own (tests/CLAUDE.md,
// "No job removes a realm"), unless STS_TEST_REMOVE_REALMS is "1": a hand
// run against a private probe that hundreds of realms would otherwise fill
// asks for them to be removed, and so for everything made in them.
async function removeRealms() {
  log.debug("Entering removeRealms().");
  if (process.env.STS_TEST_REMOVE_REALMS !== "1") {
    log.debug("Leaving removeRealms(). Left standing.");
    return;
  }
  for (const id of [REALM, BSP]) {
    try {
      const r = await fetch(base + "/admin-api/realms/remove", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: id }) });
      log.info("removed the realm " + id + ": " + r.status);
    } catch (e) {
      log.debug("Caught in removeRealms(): " + ((e && e.message) || e));
      // A removal that fails leaves a realm behind, which is the default.
      log.info("could not remove the realm " + id);
    }
  }
  log.debug("Leaving removeRealms().");
}

async function main() {
  log.debug("Entering main().");
  try {
    try {
      await test();
    } finally {
      await removeRealms();
    }
    log.info("Test completed successfully.");
    log.debug("Leaving main().");
    process.exit(0);
  } catch (e) {
    log.debug("Caught in main(): " + ((e && e.message) || e));
    log.error("Test failed: " + ((e && e.stack) || e));
    log.debug("Leaving main().");
    process.exit(1);
  }
}

main();
