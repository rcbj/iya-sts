// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_api_request_names.js
//
// ===========================================================================
// WHAT THE FOUR APIS REFUSE BY NAME, OVER HTTP (D12, #444; #1476, #1483).
//
// A query parameter an operation does not declare, a declared parameter
// whose value its type does not hold and a custom header no specification
// defines are each a 400, with a code RECORDED (read back off the realm's
// `/admin-api/audit`) and never sent, in a sentence naming the parameter or
// header and never its value; everything declared or standard still reaches
// the operation. In one throwaway realm, with the credential each API takes:
//
//   A. /admin-api (the harness's token): an unknown parameter on an
//      operation with none and on one with some (STS-API-0142), a word in
//      an integer (STS-API-0143), a declared and an empty value, `cell`,
//      `format=svg` at a management address told where the drawing is, an
//      unknown header (STS-API-0144) on both kinds and on a POST, every
//      group of standard and provider header and this service's own
//      internal ones accepted, and the names nobody defined refused.
//   B. /account-api (the portal's DPoP-bound token): STS-ACCOUNT-0020 on
//      operations with and without parameters and on a POST, a word in an
//      integer and a nested value (STS-ACCOUNT-0021), an unknown header
//      (STS-ACCOUNT-0022), a declared and an empty value, a browser's own
//      headers.
//   C. /authn-api (a real pending sign-in): STS-AUTHN-0553, -0554, -0555;
//      a declared query, a WebView's headers, the sign-in pages' X-Step-Id
//      and X-Step-Query, X-CSRF-Token on a POST and not on a GET, the
//      wallet start's names, the sign-out view's names, the account list's
//      none.
//   D. /report-api (`sts-report`'s DPoP-bound token): STS-REPORT-0056,
//      -0057, -0058, on the index and a POST too; the jobs list's four
//      names, the definitions list's older `limit`, DPoP and
//      X-Requested-With, a path parameter, and a path no operation is left
//      to the router.
//
// D12 (#444): carries over tests/admin_api_request_names.js (A-C; D and E
// read the source and the console's bundle) and tests/api_request_names.js
// (B-D; A, E and F are the shared library, the documents' examples and the
// portal's bundle), so they stay covered when Rust replaces Node.
//
// OWNED HERE (local: true): this repository's own four APIs.
// ===========================================================================

const assert = require("assert");
const crypto = require("crypto");
const names = require("./random_username.js");
const portalSignIn = require("./portal_signin.js");
const reportSignIn = require("./report_signin.js");
const authnSignin = require("./authn_signin.js");

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
var log = bunyan.createLogger({ name: "sts_api_request_names",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "");
const REALM = ("reqn" + STAMP).slice(0, 31);
const PERSON = ("rn" + STAMP).slice(0, 30);
const PASSWORD = "Req-Names-" + crypto.randomBytes(9).toString("base64url") +
                 "-Aa1!";
// A value a refusal must never echo.
const SECRET = "SECRETv" + crypto.randomBytes(4).toString("hex");

// One header from each group /admin-api accepts whatever an operation
// declares (common/request_headers.ts); `Host` and `:authority` are left
// out because a client cannot send them as data.
const ACCEPTED_HEADERS = [
  "Accept-Language", "If-None-Match", "Sec-CH-UA-Brand-New",
  "Sec-Fetch-Site", "X-Forwarded-Client-Cert", "Forwarded", "X-Real-IP",
  "X-Request-Id", "Via", "traceparent", "tracestate",
  "X-Client-Cert", "X-SSL-Client-Verify",
  "CloudFront-Viewer-Country", "X-Amz-Cf-Id", "X-Amzn-Trace-Id",
  "X-Origin-Verify",
  "X-Cloud-Trace-Context", "X-Goog-Request-Id",
  "X-Azure-FDID", "X-ARR-LOG-ID", "X-MS-Request-Id", "X-Original-Host",
  "x-sts-pool-protocol-worker", "x-sts-ldap-drop", "x-sts-listener",
  "x-sts-peer-certificate", "x-sts-cell-from"
];
const REFUSED_HEADERS = ["X-Requested-With", "X-Sts-Garbage", "X-Foo",
                         "X-Csrf-Token", "Sts-Whatever"];

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

function parse(text) {
  log.debug("Entering parse().");
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in parse(): " + ((e && e.message) || e));
    // Not JSON: the caller reads the text.
    json = null;
  }
  log.debug("Leaving parse().");
  return json;
}

// A plain call: the preload attaches the harness's token to /admin-api.
async function call(method, url, headers, payload) {
  log.debug("Entering call(). " + method + " " + url);
  const sent = Object.assign({ accept: "application/json" }, headers || {});
  const init = { method: method, headers: sent, redirect: "manual" };
  if (payload !== undefined) {
    sent["content-type"] = "application/json";
    init.body = JSON.stringify(payload);
  }
  const r = await fetch(url, init);
  const text = await r.text();
  log.debug("Leaving call(). " + r.status);
  return { status: r.status, text: text, json: parse(text) };
}

// A call carrying a DPoP-bound token and a fresh proof, retried once with
// the server's nonce (RFC 9449 section 8).
async function dpopCall(client, method, url, headers, payload) {
  log.debug("Entering dpopCall(). " + method + " " + url);
  let answer = null;
  const target = url.split("?")[0];
  for (let i = 0; i < 2; i += 1) {
    const sent = Object.assign({ accept: "application/json",
      authorization: "DPoP " + client.token,
      dpop: client.key.proof(method, target, client.token) }, headers || {});
    const init = { method: method, headers: sent, redirect: "manual" };
    if (payload !== undefined) {
      sent["content-type"] = "application/json";
      init.body = JSON.stringify(payload);
    }
    const r = await fetch(url, init);
    client.key.keepNonce(r);
    const text = await r.text();
    answer = { status: r.status, text: text, json: parse(text),
               challenge: String(r.headers.get("www-authenticate") || "") };
    if (!(r.status === 401 && /use_dpop_nonce/.test(answer.challenge))) {
      break;
    }
  }
  log.debug("Leaving dpopCall(). " + answer.status);
  return answer;
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await call("POST", url, {}, payload);
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + r.text.slice(0, 400));
  log.debug("Leaving ok().");
  return r.json;
}

// The realm's audit rows recording `code`, waited for until one names
// `pathPart`.
async function codeRows(realmBase, code, pathPart) {
  log.debug("Entering codeRows(). " + code);
  let found = [];
  for (let i = 0; i < 20; i += 1) {
    const r = await call("GET", realmBase + "/admin-api/audit?per=500&code=" +
                         encodeURIComponent(code));
    found = ((r.json && r.json.events) || []).filter(function (row) {
      return String(row.target).indexOf(pathPart) >= 0;
    });
    if (found.length) {
      break;
    }
    await sleep(150);
  }
  log.debug("Leaving codeRows(). " + found.length);
  return found;
}

// A shape refusal: 400, naming `name`, echoing neither the secret nor a
// code, and the code recorded against `pathPart`.
async function refusedBy(realmBase, reply, name, code, pathPart) {
  log.debug("Entering refusedBy().");
  const recorded = await codeRows(realmBase, code, pathPart);
  log.debug("Leaving refusedBy().");
  return function () {
    assert.strictEqual(reply.status, 400, reply.text.slice(0, 300));
    assert.ok(reply.text.indexOf(name) >= 0, "the refusal does not name " +
              name + ": " + reply.text.slice(0, 300));
    assert.ok(reply.text.indexOf(SECRET) < 0, "the value was echoed");
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(reply.text), "a code was sent");
    assert.ok(recorded.length > 0, "no " + code + " row for " + pathPart);
  };
}

async function adminApi(ctx) {
  log.debug("Entering adminApi().");
  log.info("=== A. /admin-api ===");
  const api = ctx.realmBase + "/admin-api";
  let r = await call("GET", api + "/crypto?sts_garbage=" + SECRET);
  check("A1. an unknown parameter on an operation that declares none is " +
        "refused, STS-API-0142", await refusedBy(ctx.realmBase, r,
          "sts_garbage", "STS-API-0142", "/admin-api/crypto"));
  r = await call("GET", api + "/audit?sts_garbage=" + SECRET);
  check("A2. and on one that declares some", await refusedBy(ctx.realmBase,
        r, "sts_garbage", "STS-API-0142", "/admin-api/audit"));
  r = await call("GET", api + "/audit?page=abc" + SECRET);
  check("A3. a word in an integer parameter is refused, STS-API-0143, and " +
        "not echoed", await refusedBy(ctx.realmBase, r, "page",
          "STS-API-0143", "/admin-api/audit"));
  const declared = await call("GET", api + "/audit?page=2&per=50");
  const empty = await call("GET", api + "/audit?page=");
  const bare = await call("GET", api + "/crypto");
  const cell = await call("GET", api + "/crypto?cell=cac1");
  check("A4. a declared value, an empty value, no query and `cell` all " +
        "reach the operation", function () {
    assert.strictEqual(declared.status, 200, declared.text.slice(0, 200));
    assert.strictEqual(empty.status, 200, empty.text.slice(0, 200));
    assert.strictEqual(bare.status, 200, bare.text.slice(0, 200));
    assert.strictEqual(cell.status, 200, cell.text.slice(0, 200));
  });
  const svg = await call("GET", api + "/delegation/user?format=svg");
  check("A5. format=svg at a management address is still told where the " +
        "drawing is", function () {
    assert.strictEqual(svg.status, 400, svg.text.slice(0, 300));
    assert.ok(/the admin console's/.test(svg.text), svg.text.slice(0, 300));
  });
  r = await call("GET", api + "/crypto", { "x-sts-garbage": SECRET });
  check("A6. an unknown header is refused, STS-API-0144, its value not " +
        "echoed", await refusedBy(ctx.realmBase, r, "x-sts-garbage",
          "STS-API-0144", "/admin-api/crypto"));
  r = await call("GET", api + "/audit?page=1", { "x-sts-garbage": SECRET });
  check("A7. and on an operation with parameters",
        await refusedBy(ctx.realmBase, r, "x-sts-garbage", "STS-API-0144",
                        "/admin-api/audit"));
  const postUnknown = await call("POST", api + "/encryption/rotate?" +
                                 "sts_garbage=1", {}, {});
  const postHeader = await call("POST", api + "/encryption/rotate",
                                { "x-sts-garbage": "1" }, {});
  check("A8. a POST refuses both, before the action", function () {
    assert.strictEqual(postUnknown.status, 400, postUnknown.text.slice(0, 300));
    assert.ok(/sts_garbage/.test(postUnknown.text));
    assert.strictEqual(postHeader.status, 400, postHeader.text.slice(0, 300));
    assert.ok(/x-sts-garbage/.test(postHeader.text));
  });
  const internal = await call("GET", api + "/crypto", {
    "x-sts-pool-protocol-worker": "1", "x-sts-ldap-drop": "a",
    "sec-ch-ua-new-hint": "?1" });
  check("A9. an internal pool header and a Sec-* hint still pass",
        function () {
    assert.strictEqual(internal.status, 200, internal.text.slice(0, 300));
  });
  const refusedAccepted = [];
  for (const name of ACCEPTED_HEADERS) {
    const one = await call("GET", api + "/crypto", { [name]: "1" });
    if (one.status !== 200) {
      refusedAccepted.push(name + " " + one.status + " " +
                           one.text.slice(0, 120));
    }
  }
  check("A10. one header of every standard, provider and internal group is " +
        "accepted (" + ACCEPTED_HEADERS.length + ")", function () {
    assert.strictEqual(refusedAccepted.length, 0, refusedAccepted.join("; "));
  });
  const passed = [];
  for (const name of REFUSED_HEADERS) {
    const one = await call("GET", api + "/crypto", { [name]: SECRET });
    if (one.status !== 400 || one.text.indexOf(name.toLowerCase()) < 0 ||
        one.text.indexOf(SECRET) >= 0) {
      passed.push(name + " " + one.status);
    }
  }
  check("A11. the names nobody defined (" + REFUSED_HEADERS.join(", ") +
        ") are each refused 400, naming the header and not its value",
        function () {
    assert.strictEqual(passed.length, 0, passed.join("; "));
  });
  log.debug("Leaving adminApi().");
}

async function accountApi(ctx) {
  log.debug("Entering accountApi().");
  log.info("=== B. /account-api ===");
  const api = ctx.realmBase + "/account-api";
  const p = ctx.portal;
  let r = await dpopCall(p, "GET", api + "/overview?sts_garbage=" + SECRET);
  check("B1. an unknown parameter on an operation with parameters is " +
        "STS-ACCOUNT-0020", await refusedBy(ctx.realmBase, r, "sts_garbage",
          "STS-ACCOUNT-0020", "/account-api/overview"));
  r = await dpopCall(p, "GET", api + "/me?sts_garbage=" + SECRET);
  check("B2. and on one with none", await refusedBy(ctx.realmBase, r,
        "sts_garbage", "STS-ACCOUNT-0020", "/account-api/me"));
  r = await dpopCall(p, "GET", api + "/applications?page=abc" + SECRET);
  const wrongRows = (await codeRows(ctx.realmBase, "STS-ACCOUNT-0021",
                                    "/account-api/applications"))
    .concat(await codeRows(ctx.realmBase, "STS-ACCOUNT-0016",
                           "/account-api/applications"));
  check("B3. a word in an integer is refused, naming the parameter and not " +
        "its value", function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 300));
    assert.ok(r.text.indexOf("page") >= 0 && r.text.indexOf(SECRET) < 0,
              r.text.slice(0, 300));
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(r.text), "a code was sent");
    assert.ok(wrongRows.length > 0, "no STS-ACCOUNT-0021 or -0016 row");
  });
  r = await dpopCall(p, "GET", api + "/overview?done[a]=" + SECRET);
  check("B4. a nested value is STS-ACCOUNT-0021",
        await refusedBy(ctx.realmBase, r, "done", "STS-ACCOUNT-0021",
                        "/account-api/overview"));
  r = await dpopCall(p, "GET", api + "/me", { "x-sts-garbage": SECRET });
  check("B5. an unknown header is STS-ACCOUNT-0022",
        await refusedBy(ctx.realmBase, r, "x-sts-garbage", "STS-ACCOUNT-0022",
                        "/account-api/me"));
  const declared = await dpopCall(p, "GET", api + "/applications?page=1&" +
                                  "done=ok");
  const empty = await dpopCall(p, "GET", api + "/applications?page=");
  const browser = await dpopCall(p, "GET", api + "/me", {
    "x-requested-with": "com.app", "sec-fetch-site": "same-origin",
    "x-forwarded-for": "192.0.2.4" });
  check("B6. a declared query, an empty value, and a browser's own headers " +
        "(X-Requested-With, Sec-*, a proxy's) reach the operation",
        function () {
    assert.strictEqual(declared.status, 200, declared.text.slice(0, 300));
    assert.strictEqual(empty.status, 200, empty.text.slice(0, 300));
    assert.strictEqual(browser.status, 200, browser.text.slice(0, 300));
  });
  r = await dpopCall(p, "POST", api + "/language?sts_garbage=1", {},
                     { language: "en" });
  check("B7. a POST refuses an unknown query parameter, STS-ACCOUNT-0020",
        function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 300));
    assert.ok(/sts_garbage/.test(r.text), r.text.slice(0, 300));
  });
  log.debug("Leaving accountApi().");
}

// A real pending sign-in: the console's authorization request, which sends
// a browser with no session to the sign-in screen with the id.
async function pendingSignIn(realmBase) {
  log.debug("Entering pendingSignIn().");
  await fetch(realmBase + "/admin", { redirect: "manual" });
  const verifier = crypto.randomBytes(32).toString("base64url");
  const r = await fetch(realmBase + "/oauth2/authorize?" +
    new URLSearchParams({ response_type: "code",
      client_id: "sts-admin-console",
      redirect_uri: realmBase + "/admin/callback",
      scope: "openid admin:read", state: "s" + STAMP.slice(0, 8),
      code_challenge: crypto.createHash("sha256").update(verifier)
        .digest("base64url"),
      code_challenge_method: "S256",
      resource: realmBase + "/admin-api" }).toString(),
    { redirect: "manual" });
  const where = r.headers.get("location") || "";
  const id = (where.match(/[?&#]authn=([^&]+)/) || [])[1];
  assert.ok(id, "the authorization request should name a pending sign-in; " +
            "it answered " + r.status + " " + where);
  log.debug("Leaving pendingSignIn().");
  return decodeURIComponent(id);
}

async function authnApi(ctx) {
  log.debug("Entering authnApi().");
  log.info("=== C. /authn-api ===");
  const api = ctx.realmBase + "/authn-api";
  const id = await pendingSignIn(ctx.realmBase);
  const pending = api + "/pending/" + encodeURIComponent(id);
  let r = await call("GET", pending + "?sts_garbage=" + SECRET);
  check("C1. an unknown parameter is STS-AUTHN-0553",
        await refusedBy(ctx.realmBase, r, "sts_garbage", "STS-AUTHN-0553",
                        "/authn-api/pending/"));
  r = await call("GET", pending, { "x-sts-garbage": SECRET });
  check("C2. an unknown header is STS-AUTHN-0555",
        await refusedBy(ctx.realmBase, r, "x-sts-garbage", "STS-AUTHN-0555",
                        "/authn-api/pending/"));
  r = await call("GET", api + "/mfa/" + encodeURIComponent(id) +
                 "?page[a]=" + SECRET);
  check("C3. a nested value is STS-AUTHN-0554",
        await refusedBy(ctx.realmBase, r, "page", "STS-AUTHN-0554",
                        "/authn-api/mfa/"));
  const view = await call("GET", pending);
  const webView = await call("GET", pending, {
    "x-requested-with": "com.vendor.app", "sec-fetch-mode": "cors",
    origin: new URL(base).origin });
  // As a product sign-in page asks (#1454): `-` in the path, the id in
  // X-Step-Id, and X-Step-Query carrying the page's own query (whose
  // `authn`, `mfa` and `enrol` are merged into the request's; nothing else).
  const step = await call("GET", api + "/pending/-", { "x-step-id": id,
                                                       "x-step-query": "x=1" });
  check("C4. the pending sign-in's view answers, and so it does with a " +
        "WebView's X-Requested-With and a browser's headers, and with the " +
        "sign-in pages' X-Step-Id and X-Step-Query", function () {
    assert.strictEqual(view.status, 200, view.text.slice(0, 300));
    assert.strictEqual(webView.status, 200, webView.text.slice(0, 300));
    assert.strictEqual(step.status, 200, step.text.slice(0, 300));
  });
  r = await call("GET", pending, { "x-csrf-token": "t" + SECRET });
  check("C5. a GET does not take X-CSRF-Token, STS-AUTHN-0555",
        await refusedBy(ctx.realmBase, r, "x-csrf-token", "STS-AUTHN-0555",
                        "/authn-api/pending/"));
  const csrf = (view.json && view.json.csrf) || "";
  const post = await call("POST", pending + "/password", {
    "x-csrf-token": csrf, origin: new URL(base).origin }, {
    username: PERSON, password: "not-the-password" });
  check("C6. a POST does take X-CSRF-Token: it is not a shape refusal",
        function () {
    assert.ok(!/is not one this operation takes|header/i.test(
      (post.json && post.json.error_description) || ""),
      post.status + " " + post.text.slice(0, 300));
  });
  r = await call("POST", pending + "/password?sts_garbage=1", {
    "x-csrf-token": csrf }, { username: PERSON, password: "x" });
  check("C7. and a POST refuses an unknown query parameter",
        function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 300));
    assert.ok(/sts_garbage/.test(r.text), r.text.slice(0, 300));
  });
  const wallet = await call("GET", api + "/wallet?" + new URLSearchParams({
    authn: id, siop: "1", login_hint: "h", did_act: "publish" }));
  r = await call("GET", api + "/wallet?state=s");
  const walletState = r;
  check("C8. the wallet start takes every name its runtime sends, and " +
        "refuses a name its view does not take (`state`)", function () {
    assert.ok(!/is not one this operation takes/.test(wallet.text),
              wallet.status + " " + wallet.text.slice(0, 300));
    assert.strictEqual(walletState.status, 400,
                       walletState.text.slice(0, 300));
    assert.ok(/"state"/.test(walletState.text) ||
              /\\"state\\"/.test(walletState.text),
              walletState.text.slice(0, 300));
    assert.ok(walletState.json && "error_description" in walletState.json,
              "the 400 is the model's shape refusal");
  });
  const logout = await call("GET", api + "/logout?" + new URLSearchParams({
    username: "u", account: "a", login_hint: "h" }));
  const accounts = await call("GET", api + "/accounts");
  r = await call("GET", api + "/accounts?username=u");
  check("C9. the sign-out view takes username, account and login_hint; the " +
        "browser's account list takes none", function () {
    assert.strictEqual(logout.status, 200, logout.text.slice(0, 300));
    assert.strictEqual(accounts.status, 200, accounts.text.slice(0, 300));
  });
  check("C9. and the account list refuses `username`, STS-AUTHN-0553",
        await refusedBy(ctx.realmBase, r, "username", "STS-AUTHN-0553",
                        "/authn-api/accounts"));
  log.debug("Leaving authnApi().");
}

async function reportApi(ctx) {
  log.debug("Entering reportApi().");
  log.info("=== D. /report-api ===");
  const api = ctx.realmBase + "/report-api";
  const rep = ctx.report;
  let r = await dpopCall(rep, "GET", api + "/groups?sts_garbage=" + SECRET);
  check("D1. an unknown parameter is STS-REPORT-0056",
        await refusedBy(ctx.realmBase, r, "sts_garbage", "STS-REPORT-0056",
                        "/report-api/groups"));
  r = await dpopCall(rep, "GET", api + "/groups?page=abc" + SECRET);
  check("D2. a word in an integer is STS-REPORT-0057",
        await refusedBy(ctx.realmBase, r, "page", "STS-REPORT-0057",
                        "/report-api/groups"));
  r = await dpopCall(rep, "GET", api + "/catalog", { "x-sts-garbage": SECRET });
  check("D3. an unknown header is STS-REPORT-0058",
        await refusedBy(ctx.realmBase, r, "x-sts-garbage", "STS-REPORT-0058",
                        "/report-api/catalog"));
  r = await dpopCall(rep, "GET", api + "?sts_garbage=1");
  const index = r;
  r = await dpopCall(rep, "POST", api + "/definitions?sts_garbage=1", {}, {});
  const postRows = await codeRows(ctx.realmBase, "STS-REPORT-0056",
                                  "/report-api/definitions");
  check("D4. on the index too, and a POST refuses too", function () {
    assert.strictEqual(index.status, 400, index.text.slice(0, 300));
    assert.strictEqual(r.status, 400, r.text.slice(0, 300));
    assert.ok(/sts_garbage/.test(r.text), r.text.slice(0, 300));
    assert.ok(postRows.length > 0, "no STS-REPORT-0056 row for the POST");
  });
  const jobs = await dpopCall(rep, "GET", api + "/jobs?page=2&per=20&" +
                              "after=x&limit=5");
  const limit = await dpopCall(rep, "GET", api + "/definitions?limit=9");
  const me = await dpopCall(rep, "GET", api + "/me",
                            { "x-requested-with": "com.app" });
  const pathOp = await dpopCall(rep, "GET", api + "/jobs/id1/result");
  const unrouted = await dpopCall(rep, "GET", api + "/no/such/path?" +
                                  "sts_garbage=1");
  const shape = /is not one this operation takes|header .* is not/;
  check("D5. the jobs list takes page, per, after and limit; the " +
        "definitions list the older `limit`; DPoP and X-Requested-With pass",
        function () {
    assert.ok(!shape.test(jobs.text) && jobs.status !== 400,
              jobs.status + " " + jobs.text.slice(0, 300));
    assert.ok(!shape.test(limit.text) && limit.status === 200,
              limit.status + " " + limit.text.slice(0, 300));
    assert.strictEqual(me.status, 200, me.text.slice(0, 300));
  });
  check("D6. a route with a path parameter is found, and a path no " +
        "operation is is left to the router", function () {
    assert.ok(!shape.test(pathOp.text), pathOp.status + " " +
              pathOp.text.slice(0, 300));
    assert.ok(!/sts_garbage/.test(unrouted.text), unrouted.status + " " +
              unrouted.text.slice(0, 300));
  });
  log.debug("Leaving reportApi().");
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. a throwaway realm " + REALM + " ===");
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "Request names " + STAMP },
    "created the realm");
  const ctx = { realmBase: base + "/realm/" + REALM };
  await ok(ctx.realmBase + "/admin-api/users/create", { username: PERSON,
    invent: false, attributes: { cn: "Request Names", sn: "Names",
      givenName: "Request", mail: PERSON + "@example.net" },
    credential: "password", password: PASSWORD }, "created the person");
  for (const role of ["REPORT_USE", "REPORT_ADMIN"]) {
    await ok(ctx.realmBase + "/admin-api/roles/add-member",
             { role: role, kind: "user", member: PERSON },
             "granted " + role);
  }
  ctx.portal = await portalSignIn.signInToThePortal(ctx.realmBase, PERSON,
    log, { password: PASSWORD });
  ctx.report = await reportSignIn.signInToReport(ctx.realmBase, PERSON,
    function (line) {
      log.info(line);
    }, { password: PASSWORD });
  await adminApi(ctx);
  await accountApi(ctx);
  await authnApi(ctx);
  await reportApi(ctx);
  assert.ok(authnSignin && checks >= 30, "only " + checks + " checks ran");
  log.info(checks + " checks passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
