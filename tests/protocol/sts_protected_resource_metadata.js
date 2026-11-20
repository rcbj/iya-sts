// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_protected_resource_metadata.js
//
// ---------------------------------------------------------------------------
// RFC 9728 AS AN IMPORT, OVER THE WIRE: WHAT A DOCUMENT IS READ AS, WHAT IS
// REFUSED, AND WHAT IS DIALLED.
//
// D12 (#444): carries over `tests/protected_resource_metadata.js`. Its
// reading — `POST /admin-api/applications/load-resource-metadata` — answers
// the whole analysis (members, extensions, signed_metadata, the section 3.3
// check, the authorization-server comparison, the plan), so every section
// that file asked of the library is asked here of the operation, and every
// refusal's code is read off `/admin-api/audit` (a code is recorded, never
// sent). In throwaway realms, one per mode:
//
//   A. THE SECTION 2 MEMBERS: a document with every kind of member parses;
//      an extension member is listed AND kept in what the entry would
//      store; a language-tagged member is read as the member it tags;
//      signed_metadata decoded, neither verified nor applied; an unknown
//      bearer method warned about; eleven malformed documents refused by
//      code (STS-REG-0076, 0077), and one over federation.maxResponseBytes.
//   B. SECTION 3.1 AND 3.3: the well-known URL for a resource with no path,
//      a terminating slash, a path and a query; a pasted document is not
//      checked and says why; a fetched one matching its URL matches, and one
//      describing another resource on the same host does not.
//   C. INTERNAL ADDRESSES, in a PRODUCT realm: a fetch from an internal
//      literal — loopback, the private ranges, link-local, the metadata
//      address, both IPv4-mapped spellings, NAT64 — is refused STS-REG-0080
//      before a socket opens, and this job's listener saw none of them.
//   D. THE AUTHORIZATION SERVERS: an issuer differing only by a trailing
//      slash is the realm's; a foreign one is not and the comparison says
//      so; a document naming none compares nothing; the realm's list carries
//      the issuer the request arrived on.
//   E. THE PLAN: name, base URI and audience from the resource; the client
//      id random and different each time; a scope under the resource losing
//      its prefix, one that is not keeping it, one with a space and a repeat
//      left out of the lines; OAuth 2.0 ticked.
//   F. THE MODE-GATED MUSTs: a non-https resource imported with a warning in
//      development and refused in product (STS-REG-0088); a pasted
//      conforming document fine in product.
//   G. THE FETCH: no source (0074), two sources (0075), an upload, a
//      document sent as an object; a fetch that matches; a redirect not
//      followed (0082); a 404 (0083); a body over the cap (0084);
//      federation.outbound off (0078) and plain http with
//      federation.outboundAllowHttp off (0079), neither dialled; in product
//      plain http refused whatever that setting says, and an https URL on a
//      private address or a name resolving to loopback refused (0080) with
//      nothing reaching this job's listener.
//   J. THE CREATE-TIME CHECKS: a create refusing a permission that is not a
//      scope token (STS-REG-0013), a repeat (0014), permissions with no base
//      URI (0015), a base URI that is not absolute (0012), an operator error
//      code in a permission's name or description (0367), a stored document
//      with no resource or a stored URL that is not http(s) (0089) — each
//      writing nothing; a create carrying everything an import proposes
//      accepted and read back; the same refusals on an update, and the
//      refused values never written.
//
// NOT carried, and why: the `internalAddressProblem()` rows that are NOT
// internal (8.8.8.8, 172.32.0.1, 2606:4700:...) — over the wire the only
// evidence is that the service DIALS them, and a test stack has no egress
// (class (d)); a section 3.3 mismatch REFUSED in product (STS-REG-0087) —
// product dials no address a test stack can reach, so no fetched document
// arrives to be compared (class (d)); H, the form the console's third tab posts
// (`documentFromForm()`), and I, multipart/form-data parsing for the
// console's CSRF check — the console is a static application over
// `/admin-api` since #446, which takes JSON, so neither is a request any
// client can make now (class (d)).
//
// THE LISTENER: section G's documents are served by this job on
// OUTBOUND_TEST_HOST (or GNAP_PUSH_HOST, the name the service reaches this
// runner by; 127.0.0.1 when the two share a host).
//
// OWNED HERE (local: true): this repository's own management API.
// ---------------------------------------------------------------------------

const assert = require("assert");
const http = require("http");
const names = require("./random_username.js");
// An address named in an answer, parsed rather than searched for as
// text (`url_match.js`).
const urls = require("./url_match.js");

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
var log = bunyan.createLogger({ name: "sts_protected_resource_metadata",
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
const DEV = "prm-d-" + STAMP;
const PROD = "prm-p-" + STAMP;
const HOST = process.env.OUTBOUND_TEST_HOST || process.env.GNAP_PUSH_HOST ||
             "127.0.0.1";
const FLOOR = 80;

const GOOD = {
  resource: "https://api.example.com",
  authorization_servers: ["https://sts.example.com/",
                          "https://other.example.org"],
  scopes_supported: ["https://api.example.com/read", "write", "bad scope",
                     "write"],
  bearer_methods_supported: ["header", "carrier-pigeon"],
  resource_name: "Widgets",
  "resource_name#fr": "Gadgets",
  dpop_bound_access_tokens_required: true,
  x_vendor_extension: { anything: [1, 2] },
  signed_metadata: Buffer.from('{"alg":"RS256"}').toString("base64url") +
                   "." + Buffer.from('{"resource":"https://evil.example"}')
                     .toString("base64url") + ".c2ln"
};

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function rb(realm) {
  log.debug("Entering rb().");
  log.debug("Leaving rb().");
  return base + "/realm/" + realm;
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

function setting(realm, key, value) {
  log.debug("Entering setting(). " + key + "=" + value);
  log.debug("Leaving setting().");
  return ok(base + "/admin-api/realms/set", { id: realm, key: key,
    value: String(value) }, "set " + key + " on " + realm);
}

function reset(realm, key) {
  log.debug("Entering reset(). " + key);
  log.debug("Leaving reset().");
  return ok(rb(realm) + "/admin-api/config/reset", { key: key },
            "reset " + key + " on " + realm);
}

// The code the LAST refused call at `path` was recorded under, read off the
// realm's audit log: the newest `protocol.call` row whose target is that
// path. Nothing else writes to this job's realms, so the newest is ours.
async function lastCode(realm, path) {
  log.debug("Entering lastCode(). " + path);
  const want = "/realm/" + realm + path;
  for (let i = 0; i < 20; i += 1) {
    const r = await send(rb(realm) + "/admin-api/audit?per=20&action=" +
                         "protocol.call");
    const rows = ((r.body && (r.body.events || r.body.rows)) || [])
      .filter(function (row) {
        return row.target === want;
      });
    if (rows.length && rows[0].outcome !== "success") {
      log.debug("Leaving lastCode(). " + rows[0].errorCode);
      return String(rows[0].errorCode || "");
    }
    await new Promise(function (resolve) {
      setTimeout(resolve, 100);
    });
  }
  log.debug("Leaving lastCode(). none");
  return "";
}

const LOAD = "/admin-api/applications/load-resource-metadata";

async function load(realm, body) {
  log.debug("Entering load().");
  const r = await postJson(rb(realm) + LOAD, body);
  r.code = "";
  if (r.status !== 200) {
    r.code = await lastCode(realm, LOAD);
  }
  log.debug("Leaving load(). " + r.status + " " + r.code);
  return r;
}

function warned(r, re) {
  log.debug("Entering warned().");
  const list = (r.body && r.body.warnings) || [];
  log.debug("Leaving warned().");
  return list.some(function (w) {
    return re.test(String(w));
  });
}

// One listener this job owns: each path answers what the current section
// asks, and every request is counted.
function listener() {
  log.debug("Entering listener().");
  const state = { hits: 0, handler: null };
  const server = http.createServer(function (req, res) {
    state.hits += 1;
    if (state.handler) {
      state.handler(req, res);
    } else {
      res.writeHead(404);
      res.end();
    }
  });
  log.debug("Leaving listener().");
  return new Promise(function (resolve) {
    server.listen(Number(process.env.PRM_LISTENER_PORT || 0), "0.0.0.0",
                  function () {
      state.port = server.address().port;
      state.server = server;
      resolve(state);
    });
  });
}

async function membersSection() {
  log.debug("Entering membersSection().");
  log.info("=== A. the section 2 members ===");
  const good = await load(DEV, { document: JSON.stringify(GOOD) });
  check("A. a document with every kind of member parses", function () {
    assert.strictEqual(good.status, 200, good.raw.slice(0, 400));
    assert.strictEqual(good.body.ok, true);
  });
  check("A. a member RFC 9728 does not define is listed as an extension, " +
        "AND KEPT in what the entry would store", function () {
    assert.ok(good.body.extensions.indexOf("x_vendor_extension") >= 0,
              JSON.stringify(good.body.extensions));
    assert.deepStrictEqual(JSON.parse(good.body.compact).x_vendor_extension,
                           GOOD.x_vendor_extension);
    assert.deepStrictEqual(good.body.document.x_vendor_extension,
                           GOOD.x_vendor_extension);
  });
  check("A. a language-tagged member (section 2.1) is read as the member " +
        "it tags", function () {
    const tagged = good.body.members.filter(function (m) {
      return m.member === "resource_name#fr";
    });
    assert.strictEqual(tagged.length, 1);
    assert.strictEqual(tagged[0].type, "string");
  });
  check("A. signed_metadata is DECODED and neither verified nor applied",
        function () {
    const s = good.body.signedMetadata;
    assert.ok(s, JSON.stringify(good.body).slice(0, 300));
    assert.strictEqual(s.verified, false);
    assert.strictEqual(s.applied, false);
    assert.strictEqual(s.claims.resource, "https://evil.example");
    assert.strictEqual(good.body.document.resource,
                       "https://api.example.com");
  });
  check("A. a bearer method RFC 6750 does not define is warned about",
        function () {
    assert.ok(warned(good, /carrier-pigeon/),
              JSON.stringify(good.body.warnings));
  });
  const refusals = [
    // An EMPTY document is no source at the operation (STS-REG-0074, as in
    // section G), where the library called it a malformed one (0076).
    ["", "STS-REG-0074", "an empty document, which is no source at all"],
    ["not json", "STS-REG-0076", "a document that is not JSON"],
    ["[1,2]", "STS-REG-0076", "a JSON array"],
    ['{"__proto__":{"x":1},"resource":"https://a.example"}', "STS-REG-0076",
     "a polluting key"],
    ['{"scopes_supported":["read"]}', "STS-REG-0077", "no resource"],
    ['{"resource":"api.example.com"}', "STS-REG-0077",
     "a resource that is not a URL"],
    ['{"resource":"https://a.example#frag"}', "STS-REG-0077",
     "a resource with a fragment"],
    ['{"resource":"https://a.example","scopes_supported":"read"}',
     "STS-REG-0077", "a list member given as a string"],
    ['{"resource":"https://a.example","authorization_servers":["x"]}',
     "STS-REG-0077", "an authorization server that is not a URL"],
    ['{"resource":"https://a.example",' +
     '"dpop_bound_access_tokens_required":"true"}', "STS-REG-0077",
     "a boolean given as a string"],
    ['{"resource":"https://a.example","signed_metadata":"abc"}',
     "STS-REG-0077", "signed_metadata that is not a JWT"]
  ];
  for (const row of refusals) {
    const body = { document: row[0] };
    const r = await load(DEV, body);
    check("A. REFUSED: " + row[2] + " (" + row[1] + "), 400 with a sentence " +
          "and no code in it", function () {
      assert.strictEqual(r.status, 400, r.raw.slice(0, 300));
      assert.strictEqual(r.body.ok, false);
      assert.ok((r.body.errors || []).length >= 1, r.raw.slice(0, 300));
      assert.ok(!/STS-[A-Z]+-\d{4}/.test(r.raw), r.raw.slice(0, 300));
      assert.strictEqual(r.code, row[1], "recorded " + r.code);
    });
  }
  await setting(DEV, "federation.maxResponseBytes", 1024);
  const big = await load(DEV, { document: JSON.stringify({
    resource: "https://a.example", resource_name: "x".repeat(2000) }) });
  await reset(DEV, "federation.maxResponseBytes");
  check("A. a document over federation.maxResponseBytes is refused " +
        "(STS-REG-0076)", function () {
    assert.strictEqual(big.status, 400, big.raw.slice(0, 300));
    assert.strictEqual(big.code, "STS-REG-0076");
  });
  log.debug("Leaving membersSection().");
  return good;
}

async function wellKnownSection(server) {
  log.debug("Entering wellKnownSection().");
  log.info("=== B. section 3.1 and section 3.3 ===");
  const cases = [
    ["https://api.example.com",
     "https://api.example.com/.well-known/oauth-protected-resource",
     "a resource with no path"],
    ["https://api.example.com/",
     "https://api.example.com/.well-known/oauth-protected-resource",
     "the terminating slash after the host is removed first"],
    ["https://api.example.com/v1/x?q=1",
     "https://api.example.com/.well-known/oauth-protected-resource" +
     "/v1/x?q=1", "a path and a query go after the suffix"]
  ];
  for (const c of cases) {
    const r = await load(DEV, { document: JSON.stringify({ resource: c[0] }) });
    check("B. section 3.1's well-known URL: " + c[2], function () {
      assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
      assert.strictEqual(r.body.resourceCheck.wellKnownUrl, c[1]);
    });
  }
  const pasted = await load(DEV, { document: JSON.stringify(GOOD) });
  check("B. a pasted document is NOT checked, and says why", function () {
    assert.strictEqual(pasted.body.resourceCheck.checked, false);
    assert.strictEqual(pasted.body.resourceCheck.matches, null);
    assert.ok(/pasted or uploaded/.test(pasted.body.resourceCheck.why),
              pasted.body.resourceCheck.why);
  });
  const origin = "http://" + HOST + ":" + server.port;
  server.handler = function (req, res) {
    log.debug("Entering B handler(). " + req.url);
    if (req.url === "/.well-known/oauth-protected-resource/api" ||
        req.url === "/.well-known/oauth-protected-resource/other") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ resource: origin + "/api" }));
    } else {
      res.writeHead(404);
      res.end();
    }
    log.debug("Leaving B handler().");
  };
  await setting(DEV, "federation.outboundAllowHttp", true);
  const matched = await load(DEV, { url: origin +
    "/.well-known/oauth-protected-resource/api" });
  const other = await load(DEV, { url: origin +
    "/.well-known/oauth-protected-resource/other" });
  check("B. a FETCHED document matching its well-known URL matches",
        function () {
    assert.strictEqual(matched.status, 200, matched.raw.slice(0, 300));
    assert.strictEqual(matched.body.source, "url");
    assert.strictEqual(matched.body.resourceCheck.checked, true);
    assert.strictEqual(matched.body.resourceCheck.matches, true);
  });
  check("B. one describing ANOTHER resource on the same host does not — the " +
        "attack section 3.3 exists for (development imports it, warned)",
        function () {
    assert.strictEqual(other.status, 200, other.raw.slice(0, 300));
    assert.strictEqual(other.body.resourceCheck.checked, true);
    assert.strictEqual(other.body.resourceCheck.matches, false);
    assert.ok(warned(other, /section 3\.3/), JSON.stringify(
      other.body.warnings));
  });
  log.debug("Leaving wellKnownSection().");
}

async function internalSection(server) {
  log.debug("Entering internalSection().");
  log.info("=== C. internal addresses (product) ===");
  const internal = ["127.0.0.1", "10.1.2.3", "172.31.255.255", "192.168.0.1",
                    "169.254.169.254", "100.64.0.1", "0.0.0.0", "[::1]",
                    "[fe80::1]", "[fd12:3456::1]", "[::ffff:127.0.0.1]",
                    "[::ffff:7f00:1]", "[::ffff:a00:1]", "[64:ff9b::a00:1]"];
  const before = server.hits;
  for (const host of internal) {
    const r = await load(PROD, { url: "https://" + host + ":" + server.port +
      "/.well-known/oauth-protected-resource" });
    check("C. product: a fetch from " + host + " is refused as internal " +
          "(STS-REG-0080)", function () {
      assert.strictEqual(r.status, 400, r.raw.slice(0, 300));
      assert.strictEqual(r.code, "STS-REG-0080", r.raw.slice(0, 300));
    });
  }
  check("C. and not one of those requests reached this job's listener",
        function () {
    assert.strictEqual(server.hits - before, 0);
  });
  log.debug("Leaving internalSection().");
}

async function serversSection() {
  log.debug("Entering serversSection().");
  log.info("=== D. the authorization servers ===");
  const issuer = rb(DEV);
  const doc = Object.assign({}, GOOD, {
    authorization_servers: [issuer + "/", "https://other.example.org"] });
  const r = await load(DEV, { document: JSON.stringify(doc) });
  const a = r.body.authorizationServers;
  check("D. both listed issuers are compared", function () {
    assert.strictEqual(a.listed, 2, JSON.stringify(a));
  });
  check("D. an issuer differing only by a trailing slash is this realm's",
        function () {
    assert.strictEqual(a.rows[0].matched, true, JSON.stringify(a.rows));
    assert.strictEqual(a.matched, 1);
  });
  check("D. a foreign issuer is not, and the whole comparison says so",
        function () {
    assert.strictEqual(a.rows[1].matched, false);
    assert.strictEqual(a.anyUnmatched, true);
    assert.strictEqual(a.allMatched, false);
  });
  const none = await load(DEV, { document: JSON.stringify({
    resource: "https://a.example" }) });
  check("D. a document naming none compares nothing rather than matching " +
        "nothing", function () {
    assert.strictEqual(none.body.authorizationServers.listed, 0);
    assert.strictEqual(none.body.authorizationServers.allMatched, false);
  });
  check("D. the realm's list is built from the address the request arrived " +
        "on — this realm's issuer", function () {
    const issuers = none.body.authorizationServers.realm.map(function (x) {
      return x.issuer;
    });
    assert.ok(issuers.indexOf(issuer) >= 0, JSON.stringify(issuers));
  });
  log.debug("Leaving serversSection().");
}

async function planSection(good) {
  log.debug("Entering planSection().");
  log.info("=== E. the plan ===");
  const plan = good.body.plan;
  check("E. the resource is the default name, the permission base URI and " +
        "the audience", function () {
    assert.strictEqual(plan.name, GOOD.resource);
    assert.strictEqual(plan.baseUri, GOOD.resource);
    assert.strictEqual(plan.audience, GOOD.resource);
  });
  const again = await load(DEV, { document: JSON.stringify(GOOD) });
  check("E. the identifier defaults to the client_id, random base64url, " +
        "and a second plan gets a different one", function () {
    assert.strictEqual(plan.identifier, plan.clientId);
    assert.ok(/^[A-Za-z0-9_-]+$/.test(plan.clientId), plan.clientId);
    assert.notStrictEqual(again.body.plan.clientId, plan.clientId);
  });
  check("E. a scope under the resource loses the prefix, its identifier the " +
        "scope as advertised", function () {
    const read = plan.permissions[0];
    assert.strictEqual(read.name, "read");
    assert.strictEqual(read.stripped, true);
    assert.strictEqual(read.sameAsAdvertised, true);
  });
  check("E. a scope that is not under it keeps its name, its identifier the " +
        "base URI and the name", function () {
    const write = plan.permissions[1];
    assert.strictEqual(write.name, "write");
    assert.strictEqual(write.stripped, false);
    assert.strictEqual(write.id, "https://api.example.com/write");
  });
  check("E. a scope with a space cannot be a permission, a repeated scope " +
        "is a duplicate, and the form's lines leave both out", function () {
    assert.ok(!!plan.permissions[2].problem, JSON.stringify(plan.permissions));
    assert.strictEqual(plan.permissions[3].duplicate, true);
    assert.strictEqual(plan.permissionLines.join(","), "read,write");
  });
  check("E. the base-with-a-slash against the audience-without-one is " +
        "warned, and OAuth 2.0 is ticked", function () {
    assert.ok(plan.warnings.some(function (w) {
      return /trailing `\/`/.test(w);
    }), JSON.stringify(plan.warnings));
    assert.strictEqual(plan.protocols.join(","), "oauth2");
  });
  log.debug("Leaving planSection().");
}

async function modeSection(server) {
  log.debug("Entering modeSection().");
  log.info("=== F. the two mode-gated MUSTs ===");
  const httpDoc = JSON.stringify({ resource: "http://api.example.com" });
  const devHttp = await load(DEV, { document: httpDoc });
  check("F. development: a non-https resource is imported with a warning",
        function () {
    assert.strictEqual(devHttp.status, 200, devHttp.raw.slice(0, 300));
    assert.ok(warned(devHttp, /https scheme/),
              JSON.stringify(devHttp.body.warnings));
  });
  const prodHttp = await load(PROD, { document: httpDoc });
  check("F. product: a non-https resource is REFUSED (STS-REG-0088)",
        function () {
    assert.strictEqual(prodHttp.status, 400, prodHttp.raw.slice(0, 300));
    assert.strictEqual(prodHttp.code, "STS-REG-0088");
  });
  const prodGood = await load(PROD, { document: JSON.stringify(GOOD) });
  check("F. product: a pasted conforming document is fine", function () {
    assert.strictEqual(prodGood.status, 200, prodGood.raw.slice(0, 300));
  });
  // The section 3.3 mismatch's development half is section B's "another
  // resource". Its product half needs a fetch product will make, and product
  // dials no address a test stack can reach (section G), so STS-REG-0087 is
  // not asked here (the header's NOT carried).
  log.debug("Leaving modeSection(). " + server.hits);
}

async function fetchSection(server) {
  log.debug("Entering fetchSection().");
  log.info("=== G. the fetch ===");
  const none = await load(DEV, {});
  check("G. no source is refused (STS-REG-0074)", function () {
    assert.strictEqual(none.status, 400, none.raw.slice(0, 300));
    assert.strictEqual(none.code, "STS-REG-0074");
  });
  const two = await load(DEV, { document: "{}", url: "https://x.example" });
  check("G. two sources are refused rather than one being chosen " +
        "(STS-REG-0075)", function () {
    assert.strictEqual(two.status, 400, two.raw.slice(0, 300));
    assert.strictEqual(two.code, "STS-REG-0075");
  });
  const uploaded = await load(DEV, { file: { name: "prm.json",
    text: JSON.stringify(GOOD) } });
  check("G. an upload loads and is named", function () {
    assert.strictEqual(uploaded.status, 200, uploaded.raw.slice(0, 300));
    assert.strictEqual(uploaded.body.source, "upload");
    assert.strictEqual(uploaded.body.filename, "prm.json");
  });
  const asObject = await load(DEV, { document: GOOD });
  check("G. a JSON caller may send the document as an object", function () {
    assert.strictEqual(asObject.status, 200, asObject.raw.slice(0, 300));
    assert.strictEqual(asObject.body.source, "pasted");
  });

  const origin = "http://" + HOST + ":" + server.port;
  const local = JSON.stringify({ resource: origin + "/api",
                                 scopes_supported: ["read"] });
  server.handler = function (req, res) {
    log.debug("Entering G handler(). " + req.url);
    if (req.url === "/.well-known/oauth-protected-resource/api") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(local);
    } else if (req.url === "/moved") {
      res.writeHead(302, { location: "/.well-known/" +
                                     "oauth-protected-resource/api" });
      res.end();
    } else if (req.url === "/big") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ resource: origin + "/api",
                               resource_name: "x".repeat(5000) }));
    } else {
      res.writeHead(404);
      res.end();
    }
    log.debug("Leaving G handler().");
  };
  const wellKnown = origin + "/.well-known/oauth-protected-resource/api";
  await setting(DEV, "federation.outboundAllowHttp", true);
  let before = server.hits;
  const fetched = await load(DEV, { url: wellKnown });
  check("G. development: a document is fetched from this job's listener and " +
        "matches its well-known URL", function () {
    assert.strictEqual(fetched.status, 200, fetched.raw.slice(0, 300));
    assert.strictEqual(fetched.body.source, "url");
    assert.strictEqual(fetched.body.url, wellKnown);
    assert.strictEqual(fetched.body.resourceCheck.matches, true);
    assert.strictEqual(server.hits - before, 1);
  });
  const moved = await load(DEV, { url: origin + "/moved" });
  check("G. a redirect is not followed (STS-REG-0082)", function () {
    assert.strictEqual(moved.status, 400, moved.raw.slice(0, 300));
    assert.strictEqual(moved.code, "STS-REG-0082");
  });
  const missing = await load(DEV, { url: origin + "/nothing" });
  check("G. a 404 is refused (STS-REG-0083)", function () {
    assert.strictEqual(missing.status, 400, missing.raw.slice(0, 300));
    assert.strictEqual(missing.code, "STS-REG-0083");
  });
  await setting(DEV, "federation.maxResponseBytes", 1024);
  const big = await load(DEV, { url: origin + "/big" });
  await reset(DEV, "federation.maxResponseBytes");
  check("G. a body over the cap is refused while it is read (STS-REG-0084)",
        function () {
    assert.strictEqual(big.status, 400, big.raw.slice(0, 300));
    assert.strictEqual(big.code, "STS-REG-0084");
  });
  await setting(DEV, "federation.outbound", false);
  before = server.hits;
  const off = await load(DEV, { url: wellKnown });
  await reset(DEV, "federation.outbound");
  check("G. federation.outbound off: refused (STS-REG-0078), and nothing " +
        "was dialled", function () {
    assert.strictEqual(off.status, 400, off.raw.slice(0, 300));
    assert.strictEqual(off.code, "STS-REG-0078");
    assert.strictEqual(server.hits - before, 0);
  });
  await reset(DEV, "federation.outboundAllowHttp");
  before = server.hits;
  const insecureOff = await load(DEV, { url: wellKnown });
  check("G. plain http with federation.outboundAllowHttp off is refused " +
        "before anything is dialled (STS-REG-0079)", function () {
    assert.strictEqual(insecureOff.status, 400,
                       insecureOff.raw.slice(0, 300));
    assert.strictEqual(insecureOff.code, "STS-REG-0079");
    assert.strictEqual(server.hits - before, 0);
  });

  await setting(PROD, "federation.outboundAllowHttp", true);
  before = server.hits;
  const plain = await load(PROD, { url: wellKnown });
  check("G. PRODUCT: plain http is refused whatever " +
        "federation.outboundAllowHttp says (STS-REG-0079, naming product " +
        "mode), and nothing is dialled", function () {
    assert.strictEqual(plain.status, 400, plain.raw.slice(0, 300));
    assert.strictEqual(plain.code, "STS-REG-0079");
    assert.ok(/product mode/.test(plain.raw), plain.raw.slice(0, 300));
  });
  const secure = await load(PROD, { url: wellKnown.replace(/^http:/,
                                                           "https:") });
  check("G. PRODUCT: the same listener over https is refused as an " +
        "internal address (STS-REG-0080)", function () {
    assert.strictEqual(secure.status, 400, secure.raw.slice(0, 300));
    assert.strictEqual(secure.code, "STS-REG-0080");
  });
  const byName = await load(PROD, { url: "https://localhost:" + server.port +
                                         "/x" });
  check("G. PRODUCT: and a NAME resolving to loopback is refused the same " +
        "way", function () {
    assert.strictEqual(byName.status, 400, byName.raw.slice(0, 300));
    assert.strictEqual(byName.code, "STS-REG-0080");
  });
  check("G. PRODUCT: NO REQUEST REACHED THIS JOB'S LISTENER, which is the " +
        "assertion the pinning is for", function () {
    assert.strictEqual(server.hits - before, 0);
  });
  log.debug("Leaving fetchSection().");
}

async function createSection() {
  log.debug("Entering createSection().");
  log.info("=== J. the create-time checks ===");
  const api = rb(DEV) + "/admin-api/applications";
  const cases = [
    [{ oauthPermissionBaseUri: "https://a.example",
       oauthPermission: ["bad scope"] }, "STS-REG-0013",
     "a permission name that is not a scope token"],
    [{ oauthPermissionBaseUri: "https://a.example",
       oauthPermission: ["read", "read|again"] }, "STS-REG-0014",
     "the same permission twice"],
    [{ oauthPermission: ["read"] }, "STS-REG-0015",
     "permissions with no base URI"],
    [{ oauthPermissionBaseUri: "https://a.example",
       oauthPermission: ["read|kept off the token (STS-AUTHN-0294)"] },
     "STS-REG-0367",
     "a permission description that contains an operator error code"],
    [{ oauthPermissionBaseUri: "https://a.example",
       oauthPermission: ["STS-AUTHN-0294"] }, "STS-REG-0367",
     "a permission name that is an operator error code"],
    [{ oauthPermissionBaseUri: "not a uri" }, "STS-REG-0012",
     "a base URI that is not absolute"],
    [{ oauthResourceMetadata: "[1]" }, "STS-REG-0089",
     "a stored document that is not an object with a resource"],
    [{ oauthResourceMetadataUrl: "ftp://a.example/x" }, "STS-REG-0089",
     "a stored URL that is not http or https"]
  ];
  for (let i = 0; i < cases.length; i += 1) {
    const id = "prm-refused-" + i;
    const r = await postJson(api + "/create", { identifier: id, name: id,
      protocols: ["oauth2"], fields: cases[i][0] });
    const code = r.status === 200 ? "" :
      await lastCode(DEV, "/admin-api/applications/create");
    const read = await send(api + "?application=" + id);
    check("J. a CREATE refuses " + cases[i][2] + " (" + cases[i][1] + ") " +
          "and writes nothing", function () {
      assert.strictEqual(r.status, 400, r.raw.slice(0, 300));
      assert.strictEqual(code, cases[i][1], r.raw.slice(0, 300));
      assert.ok(!/STS-[A-Z]+-\d{4}/.test(r.raw), r.raw.slice(0, 300));
      // `?application=` answers the one application's view, `found` false
      // for an identifier nobody wrote.
      assert.ok(!(read.body && read.body.found), read.raw.slice(0, 300));
    });
  }
  const made = await postJson(api + "/create", { identifier: "prm-created",
    name: "prm-created", protocols: ["oauth2"],
    fields: { oauthClientId: ["prm-created"],
              oauthPermissionBaseUri: "https://api.example.com",
              oauthAudience: ["https://api.example.com"],
              oauthPermission: ["read", "write|Change widgets"],
              oauthResourceMetadata: JSON.stringify(GOOD),
              oauthResourceMetadataUrl: "https://api.example.com/" +
                ".well-known/oauth-protected-resource" } });
  check("J. a create carrying everything an import proposes is accepted",
        function () {
    assert.strictEqual(made.status, 200, made.raw.slice(0, 400));
  });
  const read = await send(api + "?application=prm-created");
  check("J. the document and the permissions are on the entry", function () {
    assert.ok(urls.namesOrigin(read.raw, "https://api.example.com") &&
              /Change widgets/.test(read.raw), read.raw.slice(0, 400));
  });
  const badUpdate = await postJson(api + "/set", {
    application: "prm-created", attribute: "oauthResourceMetadata",
    value: '{"a":1}' });
  const badCode = await lastCode(DEV, "/admin-api/applications/set");
  check("J. an UPDATE refuses a document with no resource too " +
        "(STS-REG-0089)", function () {
    assert.strictEqual(badUpdate.status, 400, badUpdate.raw.slice(0, 300));
    assert.strictEqual(badCode, "STS-REG-0089");
  });
  const coded = await postJson(api + "/add", { application: "prm-created",
    attribute: "oauthPermission", value: "admin|refused (STS-AUTHN-0294)" });
  const codedCode = await lastCode(DEV, "/admin-api/applications/add");
  check("J. an UPDATE refuses a permission description that contains an " +
        "operator error code (STS-REG-0367), without repeating the code",
        function () {
    assert.strictEqual(coded.status, 400, coded.raw.slice(0, 300));
    assert.strictEqual(codedCode, "STS-REG-0367");
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(coded.raw), coded.raw.slice(0, 300));
  });
  const codedName = await postJson(api + "/add", {
    application: "prm-created", attribute: "oauthPermission",
    value: "STS-AUTHN-0294" });
  const nameCode = await lastCode(DEV, "/admin-api/applications/add");
  check("J. an UPDATE refuses a permission name that is an operator error " +
        "code (STS-REG-0367)", function () {
    assert.strictEqual(codedName.status, 400, codedName.raw.slice(0, 300));
    assert.strictEqual(nameCode, "STS-REG-0367");
  });
  const after = await send(api + "?application=prm-created");
  check("J. and neither refused value was written", function () {
    assert.ok(after.raw.indexOf("STS-AUTHN-0294") < 0,
              after.raw.slice(0, 300));
  });
  log.debug("Leaving createSection().");
}

async function test() {
  log.debug("Entering test().");
  for (const id of [DEV, PROD]) {
    await ok(base + "/admin-api/realms/create", { id: id,
      domain: id + ".example.net", name: "RFC 9728 import " + STAMP },
      "created the realm " + id);
  }
  await setting(DEV, "global.mode", "development");
  await setting(PROD, "global.mode", "product");
  const server = await listener();
  try {
    const good = await membersSection();
    await wellKnownSection(server);
    await internalSection(server);
    await serversSection();
    await planSection(good);
    await modeSection(server);
    await fetchSection(server);
    await createSection();
  } finally {
    server.server.close();
  }
  assert.ok(checks >= FLOOR, "only " + checks + " checks ran; the floor is " +
            FLOOR);
  log.info(checks + " check(s) passed.");
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
  for (const id of [DEV, PROD]) {
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
    log.debug("Caught in main(): " + ((e && e.message) || e));
    // A removal that fails is logged; the job's verdict is the test's.
    log.warn("could not remove the realms: " + ((e && e.message) || e));
  }
  if (failure) {
    log.error("FAILED after " + checks + " check(s): " +
              ((failure && failure.stack) || failure));
    log.debug("Leaving main(). Failed.");
    process.exit(1);
  }
  log.info("Test completed successfully.");
  log.debug("Leaving main().");
  process.exit(0);
}

main();
