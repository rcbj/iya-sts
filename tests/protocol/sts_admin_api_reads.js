// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_admin_api_reads.js
//
// ===========================================================================
// THREE READS OF THE MANAGEMENT API AND THE CONSOLE, OVER HTTP (D12, #444).
//
// In throwaway realms this job creates:
//
//   A. `GET /admin-api/console/delegation/map`, the delegation picture as
//      one answer: an RFC 8693 delegation recorded by a real token exchange
//      (a person's token, the client's own as `actor_token`), read with an
//      Admin Read person's console token — the graph of the act, a look
//      with a label for every node, the counts, the SVG and its layout;
//      `format=svg` the SVG document alone with no links; text matching
//      nobody leaving no act; a mechanism outside its closed set refused;
//      the console's operation list naming it and the management index not.
//   B. VERIFICATIONS: `POST /admin-api/verifications/start` by value (its
//      state, wallet URL and openid4vp:// URI), with a completion page and
//      with one that is not an http(s) URL, by reference (the Request Object
//      served at the `request_uri`), in a product realm only a registered
//      redirect URI; `GET /admin-api/verifications` by state (found, not yet
//      received), the open list, an unknown state 404; a response_type
//      outside its closed set; Admin Read refused a start; the Verifier
//      request tab's operation answering the open list; and
//      `GET /admin-api/kerberos/principals`'s account policy and database by
//      public fields, `/krb5/principals` gone.
//   C. THE LISTS #313'S SWEEP PAGED: `/admin-api/roles`' narrowed
//      applications on `requiringPage` with the whole count, the two pagers
//      not moving each other, a page past the end clamped, every page
//      walked; `/admin-api/sessions`' unauthenticated sessions on
//      `anonymousPage`.
//
// D12 (#444): carries over tests/admin_api_delegation_map.js,
// tests/admin_api_verifications.js (all but 3b and 4a's decided row, which
// write a verdict onto a transaction directly — a wallet's answer is
// `sts_oid4vp_wallet.js`'s — and 6's drawing, the console bundle's) and
// tests/admin_lists_paging.js (1-4; 5 draws pagers from views built in
// process over registers that need a database, a secret store or a profile
// store), so they stay covered when Rust replaces Node.
//
// OWNED HERE (local: true): this repository's own console operations and
// management API.
// ===========================================================================

const assert = require("assert");
const names = require("./random_username.js");
const consoleSignIn = require("./console_signin.js");

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
var log = bunyan.createLogger({ name: "sts_admin_api_reads",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "");
const REALM = ("rds" + STAMP).slice(0, 31);
const PRODUCT = ("rdp" + STAMP).slice(0, 31);
const READER = ("rr" + STAMP).slice(0, 30);
const TX = "urn:ietf:params:oauth:grant-type:token-exchange";
const AT = "urn:ietf:params:oauth:token-type:access_token";
const MAP = "/admin-api/console/delegation/map";

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

// A call; the preload attaches the harness's token to /admin-api.
async function call(method, url, payload, headers) {
  log.debug("Entering call(). " + method + " " + url);
  const sent = Object.assign({ accept: "application/json" }, headers || {});
  const init = { method: method, headers: sent, redirect: "manual" };
  if (payload !== undefined) {
    sent["content-type"] = "application/json";
    init.body = JSON.stringify(payload);
  }
  const r = await fetch(url, init);
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
    // Not JSON: the caller reads the text.
    json = null;
  }
  log.debug("Leaving call(). " + r.status);
  return { status: r.status, text: text, json: json, headers: r.headers };
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await call("POST", url, payload);
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + r.text.slice(0, 400));
  log.debug("Leaving ok().");
  return r.json;
}

async function token(realmBase, params) {
  log.debug("Entering token().");
  const r = await fetch(realmBase + "/oauth2/token", { method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(params).toString() });
  const text = await r.text();
  assert.strictEqual(r.status, 200, params.grant_type + " answered " +
                     r.status + " " + text.slice(0, 300));
  log.debug("Leaving token().");
  return JSON.parse(text).access_token;
}

async function delegationMap(ctx) {
  log.debug("Entering delegationMap().");
  log.info("=== A. the delegation picture as one answer ===");
  const rb = ctx.realmBase;
  const audience = "https://api-" + STAMP.slice(0, 16) + ".example.com";
  const person = ("dm" + STAMP).slice(0, 30);
  await ok(rb + "/admin-api/applications/create", { identifier: "dmapi",
    kind: "oauth2-client", name: "dmapi", protocols: ["oauth2"],
    fields: { oauthClientId: ["dmapi-client"], oauthAudience: [audience] } },
    "created the target application");
  await ok(rb + "/admin-api/applications/create", { identifier: "dmfront",
    kind: "oauth2-client", name: "dmfront", protocols: ["oauth2"],
    fields: { oauthClientId: ["dmfront"],
              oauthGrantType: ["client_credentials", "password", TX] } },
    "created the acting application");
  const subject = await token(rb, { grant_type: "password",
    client_id: "dmfront", client_secret: "dev", username: person,
    password: "dev" });
  const actor = await token(rb, { grant_type: "client_credentials",
    client_id: "dmfront", client_secret: "dev" });
  await token(rb, { grant_type: TX, client_id: "dmfront",
    client_secret: "dev", subject_token: subject, subject_token_type: AT,
    actor_token: actor, actor_token_type: AT, audience: audience });

  const r = await ctx.reader.api("GET", MAP);
  const j = r.json || {};
  const nodes = Array.isArray(j.nodes) ? j.nodes : [];
  check("A1. the answer is the graph of the act: its parties and the line " +
        "between them", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.ok(nodes.length >= 3, JSON.stringify(nodes).slice(0, 300));
    assert.ok(JSON.stringify(nodes).indexOf(person) >= 0,
              JSON.stringify(nodes).slice(0, 400));
    assert.ok(Array.isArray(j.edges) && j.edges.length >= 1,
              JSON.stringify(j.edges));
  });
  check("A2. every node has a look, with a label", function () {
    const looks = j.looks || {};
    assert.ok(nodes.every(function (node) {
      return looks[node.id] && typeof looks[node.id].label === "string" &&
        looks[node.id].label !== "";
    }), JSON.stringify(Object.keys(looks)));
  });
  check("A3. the drawing is SVG, and it laid out", function () {
    assert.strictEqual(String(j.svg || "").indexOf("<svg"), 0,
                       String(j.svg || "").slice(0, 80));
    assert.ok(j.drawing && j.drawing.width > 0 && j.drawing.height > 0 &&
              j.drawing.failed === null, JSON.stringify(j.drawing));
  });
  check("A4. the counts the filter shows are in it", function () {
    assert.ok(j.matched >= 1 && j.held >= 1, JSON.stringify({
      matched: j.matched, held: j.held }));
    assert.strictEqual(typeof (j.summary || {}).byType, "object");
  });
  const svg = await ctx.reader.api("GET", MAP + "?format=svg");
  check("A5. format=svg answers the SVG document alone, with no links in " +
        "it", function () {
    assert.strictEqual(svg.status, 200, svg.text.slice(0, 200));
    assert.strictEqual(svg.text.indexOf("<svg"), 0, svg.text.slice(0, 80));
    assert.ok(svg.text.indexOf("<a ") < 0 && svg.text.indexOf("href=") < 0,
              "the document carries a link");
  });
  const svgType = await call("GET", rb + MAP + "?format=svg", undefined,
    { authorization: "DPoP " + ctx.reader.token,
      dpop: ctx.reader.key.proof("GET", rb + MAP, ctx.reader.token) });
  check("A5. as image/svg+xml", function () {
    assert.strictEqual(svgType.status, 200, svgType.text.slice(0, 200));
    assert.ok(/^image\/svg\+xml/.test(String(svgType.headers
      .get("content-type"))), svgType.headers.get("content-type"));
  });
  const none = await ctx.reader.api("GET", MAP + "?q=" +
    encodeURIComponent("dm-nobody-" + STAMP));
  check("A6. text matching nobody leaves no act in the picture",
        function () {
    assert.strictEqual(none.status, 200, none.text.slice(0, 200));
    assert.strictEqual(none.json.matched, 0);
    assert.ok(JSON.stringify(none.json.nodes || []).indexOf(person) < 0);
  });
  const closed = await ctx.reader.api("GET", MAP + "?type=not-a-mechanism");
  check("A7. a mechanism outside its closed set is refused 400",
        function () {
    assert.strictEqual(closed.status, 400, closed.text.slice(0, 200));
  });
  const ops = await ctx.reader.api("GET", "/admin-api/console/operations");
  const listed = ((ops.json || {}).operations || []).filter(function (one) {
    return one.path === MAP;
  })[0] || null;
  const index = await call("GET", rb + "/admin-api");
  check("A8. the console's operation list names it, a console operation " +
        "mirroring the page; the management API's index does not",
        function () {
    assert.ok(listed && listed.method === "GET" && listed.kind === "console" &&
              listed.mirrors === "GET /admin/delegation/map",
              JSON.stringify(listed));
    assert.strictEqual(index.status, 200);
    assert.ok(!(index.json.operations || []).some(function (one) {
      return one.path === MAP;
    }), "the index lists the console's operation");
  });
  log.debug("Leaving delegationMap().");
}

function paramsOf(url) {
  log.debug("Entering paramsOf().");
  const out = {};
  new URL(url).searchParams.forEach(function (value, name) {
    out[name] = value;
  });
  log.debug("Leaving paramsOf().");
  return out;
}

async function verifications(ctx) {
  log.debug("Entering verifications().");
  log.info("=== B. verifications, and the Kerberos account policy ===");
  const api = ctx.realmBase + "/admin-api";
  let r = await call("POST", api + "/verifications/start",
                     { format: "dc+sd-jwt" });
  let j = r.json || {};
  check("B1. a start by value answers its state, the wallet URL (the " +
        "wallet and the query), the openid4vp:// URI a QR code carries, " +
        "and no completion page", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.ok(j.ok === true && typeof j.state === "string" &&
              j.state.length > 10, r.text.slice(0, 300));
    assert.strictEqual(j.walletUrl, j.wallet + "?" + j.query);
    assert.ok(/^openid4vp:\/\/\?/.test(j.requestUri), j.requestUri);
    assert.strictEqual(j.requestUri.slice("openid4vp://?".length), j.query);
    assert.strictEqual(j.byReference, false);
    assert.ok(!j.request_uri);
    assert.strictEqual(j.redirectUri, "");
  });
  const byValueState = j.state;
  const DONE = "https://rp.example/verified";
  r = await call("POST", api + "/verifications/start",
                 { mode: "same-device", redirect_uri: DONE });
  check("B2. a start may name the page its wallet is sent to afterwards",
        function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.strictEqual(r.json.redirectUri, DONE);
  });
  r = await call("POST", api + "/verifications/start",
                 { redirect_uri: "javascript:alert(1)" });
  check("B3. a redirect_uri that is not an absolute http(s) URL is refused",
        function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 300));
    assert.strictEqual(r.json.ok, false);
  });
  const prodApi = ctx.productBase + "/admin-api";
  const other = await call("POST", prodApi + "/verifications/start",
                           { redirect_uri: DONE });
  check("B4. in a product realm, a completion page the calling client never " +
        "registered is refused", function () {
    assert.strictEqual(other.status, 400, other.text.slice(0, 300));
    assert.strictEqual(other.json.ok, false);
  });

  r = await call("POST", api + "/verifications/start",
                 { format: "dc+sd-jwt", by: "reference",
                   mode: "cross-device" });
  j = r.json || {};
  const asked = j.walletUrl ? paramsOf(j.walletUrl) : {};
  check("B5. by reference: the wallet URL carries client_id and the " +
        "request_uri the answer names", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.strictEqual(j.byReference, true);
    assert.ok(j.request_uri && asked.request_uri === j.request_uri,
              JSON.stringify(asked));
    assert.ok(asked.client_id && asked.client_id === j.clientId,
              JSON.stringify(asked));
    assert.strictEqual(j.mode, "cross-device");
  });
  const object = await fetch(j.request_uri);
  const objectText = await object.text();
  check("B6. and the signed Request Object is served there", function () {
    assert.strictEqual(object.status, 200, objectText.slice(0, 200));
    assert.strictEqual(objectText.split(".").length, 3,
                       objectText.slice(0, 80));
  });
  const byReferenceState = j.state;

  r = await ctx.reader.api("GET", "/admin-api/verifications?state=" +
                           encodeURIComponent(byValueState));
  check("B7. Admin Read reads the outcome by state: found and not yet " +
        "received", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.strictEqual(r.json.found, true);
    assert.strictEqual(r.json.received, false);
    assert.strictEqual(r.json.verdict, null);
  });
  r = await ctx.reader.api("GET", "/admin-api/verifications");
  const rows = (r.json && r.json.verifications) || [];
  const waiting = rows.filter(function (row) {
    return row.state === byReferenceState;
  })[0];
  check("B8. without state: the open verifications, the waiting one among " +
        "them", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.ok(typeof r.json.total === "number" && r.json.total >= 2,
              String(r.json.total));
    assert.ok(waiting && waiting.received === false &&
              waiting.byReference === true, JSON.stringify(waiting));
  });
  r = await ctx.reader.api("GET", "/admin-api/verifications?state=nope-" +
                           STAMP);
  check("B9. a state with no record is 404, found false, one sentence",
        function () {
    assert.strictEqual(r.status, 404, r.text.slice(0, 300));
    assert.strictEqual(r.json.found, false);
    assert.ok(Array.isArray(r.json.errors) && r.json.errors.length === 1);
  });
  r = await call("POST", api + "/verifications/start",
                 { response_type: "code" });
  check("B10. a response_type outside the closed set is refused",
        function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 300));
    assert.ok(Array.isArray(r.json.errors));
  });
  r = await ctx.reader.api("POST", "/admin-api/verifications/start",
                           { format: "dc+sd-jwt" });
  check("B11. Admin Read may not start a verification (403)", function () {
    assert.strictEqual(r.status, 403, r.text.slice(0, 300));
  });
  r = await ctx.reader.api("GET", "/admin-api/verifier-request");
  check("B12. the Verifier request tab's operation answers the open list " +
        "and the start choices", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 200));
    assert.ok(r.json.recentVerifications && r.json.startChoices,
              Object.keys(r.json).join(","));
    assert.ok(JSON.stringify(r.json.recentVerifications)
      .indexOf(byValueState) >= 0, "the started one is not in the list");
  });
  const ops = await call("GET", ctx.realmBase + "/admin-api");
  const start = (ops.json.operations || []).filter(function (one) {
    return one.path === "/admin-api/verifications/start";
  })[0];
  check("B12. and its form resolves to POST /admin-api/verifications/start " +
        "through `mirrors`", function () {
    assert.ok(start && start.method === "POST" &&
              /POST \/admin\/vc#vc-tab-verifier-request/.test(start.mirrors),
              JSON.stringify(start));
  });

  // The DEFAULT realm's KDC, read only: a fresh realm's has no service
  // hosts yet, and the default realm's always has the seeded ones.
  r = await call("GET", base + "/admin-api/kerberos/principals?per=500");
  const gone = await fetch(base + "/krb5/principals");
  const goneText = await gone.text();
  const policy = (r.json && r.json.accountPolicy) || {};
  const krbtgt = ((r.json && r.json.database) || []).filter(function (row) {
    return /^krbtgt\//.test(row.principal);
  })[0];
  check("B13. GET /admin-api/kerberos/principals answers the account " +
        "policy, without either shared password", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 200));
    assert.strictEqual(policy.anyUsernameAuthenticates, true);
    assert.ok(Array.isArray(policy.neverCreated));
    assert.ok(Array.isArray(policy.serviceHosts) &&
              policy.serviceHosts.length > 0, JSON.stringify(policy));
    assert.ok(!("userPassword" in policy) &&
              !("autoServicePassword" in policy), JSON.stringify(policy));
  });
  check("B14. and the KDC's database by its public fields: the krbtgt with " +
        "its salt and enctypes, no password", function () {
    assert.ok(krbtgt && typeof krbtgt.salt === "string" &&
              krbtgt.salt.length > 0, JSON.stringify(krbtgt));
    assert.ok(Array.isArray(krbtgt.etypes) && krbtgt.etypes.length > 0);
    assert.ok(!("password" in krbtgt), JSON.stringify(krbtgt));
    assert.ok(r.json.databaseTotal >= r.json.database.length);
    assert.ok((r.json.realmsServed || []).length > 0);
  });
  check("B15. /krb5/principals itself is gone (#595)", function () {
    assert.strictEqual(gone.status, 404, goneText.slice(0, 200));
    assert.ok(/Cannot GET/.test(goneText), goneText.slice(0, 200));
  });
  log.debug("Leaving verifications().");
}

async function listsPaging(ctx) {
  log.debug("Entering listsPaging().");
  log.info("=== C. the lists #313's sweep paged ===");
  const rb = ctx.realmBase;
  const tag = "lp" + STAMP.slice(0, 12);
  const APPS = 7;
  for (let i = 0; i < APPS; i += 1) {
    await ok(rb + "/admin-api/applications/create", { identifier: tag + i,
      kind: "oauth2-client", name: tag + i, protocols: ["oauth2"],
      fields: { oauthClientId: [tag + i], appRequiredRole: [tag + "-role"] } },
      "created narrowed application " + i);
  }
  const whole = await call("GET", rb + "/admin-api/roles?per=500");
  const total = whole.json.counts.requiring;
  const mine = (whole.json.requiring || []).filter(function (row) {
    return String(row.application).indexOf(tag) === 0;
  });
  check("C0. precondition: the register lists the " + APPS + " narrowed " +
        "applications", function () {
    assert.strictEqual(mine.length, APPS, JSON.stringify(mine));
  });
  const first = await call("GET", rb + "/admin-api/roles?per=3");
  check("C1. the narrowed applications are one page, on requiringPage, and " +
        "counts.requiring is the whole count", function () {
    assert.strictEqual(first.json.requiring.length, Math.min(3, total));
    assert.strictEqual(first.json.requiringPaging.total, total);
    assert.strictEqual(first.json.requiringPaging.param, "requiringPage");
    assert.strictEqual(first.json.counts.requiring, total);
  });
  const moved = await call("GET", rb + "/admin-api/roles?per=3&" +
                           "requiringPage=2");
  const rolesMoved = await call("GET", rb + "/admin-api/roles?per=3&" +
                                "rolesPage=2");
  check("C2. requiringPage moves the applications and not the roles; " +
        "rolesPage leaves the applications on page 1", function () {
    assert.strictEqual(moved.json.requiringPaging.page, 2);
    assert.strictEqual(moved.json.paging.page, 1);
    assert.strictEqual(rolesMoved.json.requiringPaging.page, 1);
  });
  const past = await call("GET", rb + "/admin-api/roles?per=3&" +
                          "requiringPage=999");
  check("C3. a page past the end is the last page", function () {
    assert.strictEqual(past.json.requiringPaging.page,
                       past.json.requiringPaging.pages);
  });
  const seen = [];
  for (let page = 1; page <= 100; page += 1) {
    const one = await call("GET", rb + "/admin-api/roles?per=3&" +
                           "requiringPage=" + page);
    one.json.requiring.forEach(function (row) {
      seen.push(row.application);
    });
    if (page >= one.json.requiringPaging.pages) {
      break;
    }
  }
  const distinct = seen.filter(function (id, i) {
    return seen.indexOf(id) === i;
  });
  check("C4. walking every page reads every narrowed application once",
        function () {
    assert.strictEqual(seen.length, total, JSON.stringify(seen));
    assert.strictEqual(distinct.length, total);
  });
  // Two arrivals with no session: the sign-in screen's shell mints one
  // each (an unauthenticated session the logout reader holds).
  for (let i = 0; i < 3; i += 1) {
    await fetch(rb + "/authn/login", { redirect: "manual" });
  }
  const sessions = await call("GET", rb + "/admin-api/sessions?per=2");
  check("C5. the unauthenticated sessions are paged on anonymousPage, and " +
        "unauthenticatedHeld counts them all", function () {
    assert.strictEqual(sessions.status, 200, sessions.text.slice(0, 200));
    const paging = sessions.json.unauthenticatedPaging;
    assert.ok(paging && paging.param === "anonymousPage",
              JSON.stringify(paging));
    assert.ok(sessions.json.unauthenticatedSessions.length <=
              paging.perPage);
    assert.strictEqual(paging.total, sessions.json.unauthenticatedHeld);
  });
  log.debug("Leaving listsPaging().");
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. throwaway realms " + REALM + " and " + PRODUCT + " ===");
  for (const id of [REALM, PRODUCT]) {
    await ok(base + "/admin-api/realms/create", { id: id,
      domain: id + ".example.net", name: "Management API reads " + STAMP },
      "created the realm " + id);
  }
  await ok(base + "/realm/" + PRODUCT + "/admin-api/config/set",
           { key: "global.mode", value: "product" },
           "switched " + PRODUCT + " to product");
  const ctx = { realmBase: base + "/realm/" + REALM,
                productBase: base + "/realm/" + PRODUCT };
  ctx.reader = await consoleSignIn.signInToTheConsole(ctx.realmBase, READER,
    log, { grant: "read" });
  await delegationMap(ctx);
  await verifications(ctx);
  await listsPaging(ctx);
  assert.ok(checks >= 25, "only " + checks + " checks ran");
  log.info(checks + " checks passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
