// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_authn_api_wallet.js
//
// ---------------------------------------------------------------------------
// THE WALLET SIGN-IN'S PAGES AND `/authn-api/wallet`, OVER THE WIRE (#574).
//
// D12 (#444): carries over `tests/authn_api_wallet.js`, which ran on
// `wallet_kit.js`'s in-process server. In a throwaway development realm with
// `oid4vp.signIn` on, every pending sign-in from a real authorization
// request, through `wallet_signin.js` as the pages do:
//
//   1. THE INDEX AND THE OPENAPI DOCUMENT list the five wallet operations,
//      the page each is the door of, the state a path parameter and each
//      act's body a schema;
//   2. THE SHELLS: `/authn/wallet` and `/authn/wallet/wait` answer the
//      sign-in surface's document (its one script, the `<noscript>`, no
//      form, `frame-ancestors` kept), the first minting the arrival cookie
//      and starting nothing; `/authn/wallet.js` and the form POST
//      `/authn/wallet/dc-api` are gone;
//   3. THE START VIEW creates nothing (no binding cookie) and answers the
//      CSRF token; a start naming nothing pending is refused with a view,
//      STS-VC-0053, code-free;
//   4. THE BINDING: a form body (415, STS-AUTHN-0325), no Origin or another
//      site's (403, STS-AUTHN-0326), no CSRF token or another browser's
//      (403, STS-AUTHN-0327) with nothing started, a field the operation
//      does not take (400, STS-VC-0069);
//   5. THE START sets the binding cookie and no session cookie, and names
//      the wait page; the wait view carries the request, the same-device
//      link and the poll's interval; the poll answers `wait` while the
//      wallet has not answered, changing no session;
//   6. NO AUDIT ROW names the state or the pending id;
//   7. an enrolment from a browser holding no sign-on session is refused
//      back to the portal (STS-VC-0093), a start carrying `login_hint` meets
//      that refusal and not the field's, and a start naming a second-factor
//      step nobody holds is refused (STS-VC-0053).
//
// NOT carried, and why: the sign-in the poll finishes once a wallet has
// presented a credential (5a, 5e) is `sts_oid4vp_wallet.js`'s; the second
// collection's refusal after it (5f, STS-VC-0062) is owed with that job,
// which holds a wallet; `audit.redactedPath()` and `redactedQuery()` asked
// directly (6b) are the process's (class (d)).
//
// OWNED HERE (local: true): this repository's sign-in surface.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const names = require("./random_username.js");
const authnSignin = require("./authn_signin");

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
var log = bunyan.createLogger({ name: "sts_authn_api_wallet",
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
  return { status: r.status, body: body, raw: raw, headers: r.headers };
}

function postJson(url, payload, headers) {
  log.debug("Entering postJson().");
  log.debug("Leaving postJson().");
  return send(url, { method: "POST",
    headers: Object.assign({ "Content-Type": "application/json" },
                           headers || {}),
    body: JSON.stringify(payload || {}) });
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await postJson(url, payload);
  assert.ok(r.status >= 200 && r.status < 300 && r.body &&
            r.body.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + String(r.raw).slice(0, 400));
  log.debug("Leaving ok().");
  return r.body;
}

function codeFree(text) {
  log.debug("Entering codeFree().");
  log.debug("Leaving codeFree().");
  return !/STS-[A-Z0-9]+-\d{4}/.test(String(text || ""));
}

async function makeRealm(id, mode) {
  log.debug("Entering makeRealm(). " + id);
  await ok(base + "/admin-api/realms/create", { id: id,
    domain: id + ".example.net", name: "D12 " + id }, "created " + id);
  if (mode) {
    await ok(base + "/admin-api/realms/set", { id: id, key: "global.mode",
      value: mode }, "set the mode of " + id);
  }
  log.debug("Leaving makeRealm().");
  return base + "/realm/" + id;
}

function realmSet(id, key, value) {
  log.debug("Entering realmSet(). " + key + "=" + value);
  log.debug("Leaving realmSet().");
  return ok(base + "/admin-api/realms/set", { id: id, key: key,
    value: String(value) }, "set " + key + " on " + id);
}

async function codeCount(rb, code) {
  log.debug("Entering codeCount(). " + code);
  const r = await send(rb + "/admin-api/audit?per=500&code=" +
                       encodeURIComponent(code));
  log.debug("Leaving codeCount().");
  return Number((r.body && r.body.matched) || 0);
}

async function codesSettle(rb, code, atLeast) {
  log.debug("Entering codesSettle(). " + code);
  let n = await codeCount(rb, code);
  for (let i = 0; i < 20 && n < atLeast; i += 1) {
    await sleep(150);
    n = await codeCount(rb, code);
  }
  log.debug("Leaving codesSettle(). " + n);
  return n;
}

// RFC 6238 with HMAC-SHA-1, six digits, thirty seconds.
function totp(secret, offset) {
  log.debug("Entering totp().");
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = String(secret).replace(/[\s=]/g, "").toUpperCase();
  let bits = "";
  for (const ch of clean) {
    bits += alphabet.indexOf(ch).toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  const counter = Math.floor(Date.now() / 30000) + (offset || 0);
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const mac = crypto.createHmac("sha1", Buffer.from(bytes)).update(message)
    .digest();
  const at = mac[mac.length - 1] & 0xf;
  const value = ((mac[at] & 0x7f) << 24) | (mac[at + 1] << 16) |
    (mac[at + 2] << 8) | mac[at + 3];
  log.debug("Leaving totp().");
  return String(value % 1000000).padStart(6, "0");
}

function sessionCookieIn(setCookies) {
  log.debug("Entering sessionCookieIn().");
  log.debug("Leaving sessionCookieIn().");
  return (setCookies || []).some(function (one) {
    return /^(__Host-)?sts_session=[^;]+/.test(String(one));
  });
}

// A public OAuth client of the realm, with PKCE, whose redirect URI is never
// dialled: the job reads the authorization endpoint's Location instead.
async function oauthClient(rb, id, extra) {
  log.debug("Entering oauthClient(). " + id);
  await ok(rb + "/admin-api/applications/create", { identifier: id,
    name: id, protocols: ["oauth2", "oidc"],
    fields: Object.assign({ oauthClientId: [id],
      oauthRedirectUri: ["https://rp.example/" + id + "/cb"],
      oauthTokenEndpointAuthMethod: "none",
      oauthGrantType: ["authorization_code", "refresh_token"],
      oauthAllowedScope: ["openid", "profile"] }, extra || {}) },
    "registered the client " + id);
  log.debug("Leaving oauthClient().");
}

// An authorization request; answers `{ status, location, verifier }` with
// the location absolute.
async function authorize(rb, clientId, cookie, extra) {
  log.debug("Entering authorize(). " + clientId);
  const verifier = crypto.randomBytes(32).toString("base64url");
  const r = await fetch(rb + "/oauth2/authorize?" + new URLSearchParams(
    Object.assign({ response_type: "code", client_id: clientId,
      redirect_uri: "https://rp.example/" + clientId + "/cb",
      scope: "openid", state: "s" + STAMP,
      nonce: "n" + crypto.randomBytes(4).toString("hex"),
      code_challenge: crypto.createHash("sha256").update(verifier)
        .digest("base64url"),
      code_challenge_method: "S256" }, extra || {})).toString(),
    { redirect: "manual", headers: cookie ? { cookie: cookie } : {} });
  await r.text();
  const where = r.headers.get("location") || "";
  log.debug("Leaving authorize(). " + r.status);
  return { status: r.status, verifier: verifier,
           location: where ? new URL(where, rb).toString() : "" };
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
    log.debug("Caught in main() removing realms: " + ((e && e.message) || e));
    // A removal that fails does not hide the test's own verdict.
    log.info("could not remove the realms: " + e.message);
  }
  if (failure) {
    log.error("FAILED after " + checks + " check(s): " +
              (failure.stack || failure));
    log.debug("Leaving main(). Failed.");
    process.exit(1);
  }
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving main().");
}

const wallet = require("./wallet_signin.js");

const REALM = "awal-" + STAMP;

// A job's browser: a cookie jar with `header()` and `take()`.
function browser() {
  log.debug("Entering browser().");
  const jar = {};
  const who = {
    cookies: jar,
    csrf: "",
    header: function () {
      return Object.keys(jar).map(function (k) {
        return k + "=" + jar[k];
      }).join("; ");
    },
    take: function (res) {
      const lines = typeof res.headers.getSetCookie === "function"
        ? res.headers.getSetCookie() : [];
      lines.forEach(function (line) {
        const pair = String(line).split(";")[0];
        const at = pair.indexOf("=");
        const name = pair.slice(0, at).trim().replace(/^__Host-/, "");
        const value = pair.slice(at + 1);
        if (value === "") {
          delete jar[name];
        } else {
          jar[name] = value;
        }
      });
      return lines;
    }
  };
  log.debug("Leaving browser().");
  return who;
}

async function pendingId(rb, app) {
  log.debug("Entering pendingId().");
  const r = await authorize(rb, app);
  const id = authnSignin.pendingIdOf(r.location);
  assert.ok(id && id !== r.location, "no pending sign-in: " + r.location);
  log.debug("Leaving pendingId().");
  return id;
}

async function test() {
  log.debug("Entering test().");
  const rb = await makeRealm(REALM, null);
  await realmSet(REALM, "oid4vp.signIn", true);
  await realmSet(REALM, "risk.assessSignIns", false);
  const app = "awal-" + STAMP;
  await oauthClient(rb, app);
  const ids = [];

  log.info("=== 1. the index and the document ===");
  const index = await send(rb + "/authn-api");
  const ops = ((index.body || {}).operations || []).filter(function (op) {
    return /^\/authn-api\/wallet/.test(op.path);
  });
  const byId = {};
  ops.forEach(function (op) {
    byId[op.operationId] = op;
  });
  check("1a. the index lists the five wallet operations and the page each " +
        "is the door of", function () {
    assert.strictEqual(ops.length, 5, JSON.stringify(ops));
    assert.strictEqual(byId.getWalletStart.method, "GET");
    assert.strictEqual(byId.getWalletStart.mirrors, "GET /authn/wallet");
    assert.strictEqual(byId.startWalletSignIn.method, "POST");
    assert.strictEqual(byId.getWalletWait.path, "/authn-api/wallet/{state}");
    assert.strictEqual(byId.getWalletWait.mirrors, "GET /authn/wallet/wait");
    assert.strictEqual(byId.walletStatus.path,
                       "/authn-api/wallet/{state}/status");
    assert.strictEqual(byId.answerWalletDcApi.path,
                       "/authn-api/wallet/{state}/dc-api");
  });
  const doc = (await send(rb + "/authn-api/openapi.json")).body || {};
  const statusOp = ((doc.paths || {})["/authn-api/wallet/{state}/status"] ||
                    {}).post || {};
  check("1b. the OpenAPI document has them, the state a path parameter and " +
        "each act's body a schema", function () {
    assert.strictEqual(statusOp.operationId, "walletStatus");
    assert.ok((statusOp.parameters || []).some(function (p) {
      return p.name === "state" && p.in === "path";
    }), JSON.stringify(statusOp.parameters));
    assert.ok(statusOp.requestBody);
    assert.ok(doc.paths["/authn-api/wallet"].get &&
              doc.paths["/authn-api/wallet"].post);
  });

  log.info("=== 2. the shells ===");
  const shellWho = browser();
  const shellId = await pendingId(rb, app);
  ids.push(shellId);
  const shell = await wallet.call(shellWho, "GET", rb + "/authn/wallet?" +
    new URLSearchParams({ authn: shellId }).toString());
  const csp = String(shell.headers.get("content-security-policy") || "");
  check("2a. /authn/wallet answers the sign-in surface's shell, mints the " +
        "arrival cookie and starts nothing", function () {
    assert.strictEqual(shell.status, 200, shell.text.slice(0, 200));
    assert.ok(/<script src="(\/realm\/[^/"]+)?\/authn\/signin\.js"/.test(
      shell.text), shell.text.slice(0, 400));
    assert.ok(/<noscript>/.test(shell.text) && !/<form/.test(shell.text));
    assert.ok(/script-src 'self'/.test(csp) &&
              /frame-ancestors 'none'/.test(csp), csp);
    assert.ok(shellWho.cookies.sts_session, JSON.stringify(shellWho.cookies));
    assert.ok(!shellWho.cookies.sts_wallet_binding);
  });
  const waitShell = await wallet.call(browser(), "GET", rb +
                                      "/authn/wallet/wait?authn=x&state=y");
  check("2b. /authn/wallet/wait answers the same shell", function () {
    assert.strictEqual(waitShell.status, 200);
    assert.ok(/<script src="(\/realm\/[^/"]+)?\/authn\/signin\.js"/.test(
      waitShell.text));
  });
  const oldScript = await send(base + "/authn/wallet.js");
  const oldForm = await send(rb + "/authn/wallet/dc-api", { method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: "authn=x&state=y" });
  check("2c. /authn/wallet.js and the form POST /authn/wallet/dc-api are " +
        "gone", function () {
    assert.strictEqual(oldScript.status, 404);
    assert.strictEqual(oldForm.status, 404);
  });

  log.info("=== 3. the start view creates nothing ===");
  const viewWho = browser();
  const viewId = await pendingId(rb, app);
  ids.push(viewId);
  const first = await wallet.open(rb, viewWho, { authn: viewId });
  const opened = first.opened;
  check("3a. the start view answers what is being started and the CSRF " +
        "token, and sets no binding cookie", function () {
    assert.strictEqual(opened.status, 200, opened.text.slice(0, 200));
    assert.strictEqual(opened.json.view.wallet, "start");
    assert.strictEqual(opened.json.view.kind, "wallet");
    assert.ok(opened.json.csrf);
    assert.ok(!viewWho.cookies.sts_wallet_binding);
    assert.ok(!opened.setCookie.some(function (c) {
      return /^(__Host-)?sts_wallet_binding=/.test(c);
    }));
  });
  let before = await codeCount(rb, "STS-VC-0053");
  const nothing = await wallet.call(viewWho, "GET", rb +
                                    "/authn-api/wallet?authn=nothing-pending");
  let after = await codesSettle(rb, "STS-VC-0053", before + 1);
  check("3b. a start naming nothing pending is refused with a view, " +
        "STS-VC-0053, and no code in the answer", function () {
    assert.strictEqual(nothing.status, 400, nothing.text);
    assert.strictEqual(nothing.json.next, "refused");
    assert.strictEqual(nothing.json.view.wallet, "refused");
    assert.ok(codeFree(nothing.text));
    assert.ok(after > before, before + " -> " + after);
  });

  log.info("=== 4. the binding of an act ===");
  const csrf = opened.json.csrf;
  const codes = ["STS-AUTHN-0325", "STS-AUTHN-0326", "STS-AUTHN-0327",
                 "STS-VC-0069"];
  const was = {};
  for (const code of codes) {
    was[code] = await codeCount(rb, code);
  }
  const asForm = await send(rb + "/authn-api/wallet", { method: "POST",
    headers: { cookie: viewWho.header(), origin: new URL(rb).origin,
               "x-csrf-token": csrf,
               "content-type": "application/x-www-form-urlencoded" },
    body: "authn=" + encodeURIComponent(viewId) });
  const noOrigin = await wallet.act(rb, viewWho, "/authn-api/wallet",
    { authn: viewId }, { origin: null, csrf: csrf });
  const foreign = await wallet.act(rb, viewWho, "/authn-api/wallet",
    { authn: viewId }, { origin: "https://attacker.example", csrf: csrf });
  const noToken = await wallet.act(rb, viewWho, "/authn-api/wallet",
    { authn: viewId }, { csrf: "" });
  const wrongToken = await wallet.act(rb, viewWho, "/authn-api/wallet",
    { authn: viewId }, { csrf: "x" + csrf });
  const extra = await wallet.act(rb, viewWho, "/authn-api/wallet",
    { authn: viewId, returnTo: "/elsewhere" }, { csrf: csrf });
  const now = {};
  for (const code of codes) {
    now[code] = await codesSettle(rb, code, was[code] + 1);
  }
  check("4a. a form body is refused 415, STS-AUTHN-0325", function () {
    assert.strictEqual(asForm.status, 415, asForm.raw.slice(0, 200));
    assert.ok(now["STS-AUTHN-0325"] > was["STS-AUTHN-0325"]);
  });
  check("4b. no Origin, or another site's, is refused 403, STS-AUTHN-0326",
        function () {
    assert.strictEqual(noOrigin.status, 403);
    assert.strictEqual(foreign.status, 403);
    assert.ok(now["STS-AUTHN-0326"] >= was["STS-AUTHN-0326"] + 1);
  });
  check("4c. no CSRF token, or another browser's, is refused 403, " +
        "STS-AUTHN-0327, and nothing is started", function () {
    assert.strictEqual(noToken.status, 403);
    assert.strictEqual(wrongToken.status, 403);
    assert.ok(!viewWho.cookies.sts_wallet_binding);
    assert.ok(now["STS-AUTHN-0327"] >= was["STS-AUTHN-0327"] + 1);
  });
  check("4d. a field the operation does not take — a returnTo — is " +
        "refused 400, STS-VC-0069", function () {
    assert.strictEqual(extra.status, 400, extra.text);
    assert.ok(now["STS-VC-0069"] > was["STS-VC-0069"]);
  });
  check("4e. no refusal carries an error code", function () {
    [asForm.raw, noOrigin.text, foreign.text, noToken.text, wrongToken.text,
     extra.text].forEach(function (text) {
      assert.ok(codeFree(text), text);
    });
  });

  log.info("=== 5. the start, the wait page and the poll ===");
  const who = browser();
  const sId = await pendingId(rb, app);
  ids.push(sId);
  const s = await wallet.start(rb, who, { authn: sId });
  const arrival = who.cookies.sts_session;
  check("5a. the start sets the binding cookie, names the wait page, and " +
        "sets no session cookie", function () {
    assert.strictEqual(s.door.status, 303, s.door.text);
    assert.ok(who.cookies.sts_wallet_binding,
              JSON.stringify(Object.keys(who.cookies)));
    assert.ok(/\/authn\/wallet\/wait(\?[^#]*)?[?#&]authn=[^&]+&state=/.test(
      s.waitUrl), s.waitUrl);
    assert.ok(!s.door.answer.setCookie.some(function (c) {
      return /^(__Host-)?sts_session=/.test(c);
    }));
  });
  ids.push(s.state);
  check("5b. the wait view carries the request, the same-device link and " +
        "the poll's interval", function () {
    assert.strictEqual(s.waiting.status, 200, s.waiting.text);
    assert.strictEqual(s.view.wallet, "wait");
    assert.strictEqual(s.view.state, s.state);
    assert.ok(s.walletUrl, JSON.stringify(s.view));
    assert.ok(s.view.pollSeconds > 0);
    assert.ok(codeFree(s.waiting.text));
  });
  const early = await wallet.collect(rb, who, s);
  check("5c. the poll answers wait while the wallet has not answered, and " +
        "changes no session", function () {
    assert.strictEqual(early.status, 200, early.text);
    assert.strictEqual(early.json.next, "wait");
    assert.ok(early.json.expiresIn > 0);
    assert.strictEqual(who.cookies.sts_session, arrival);
  });

  log.info("=== 6. the bearer ids are never recorded ===");
  const audit = await send(rb + "/admin-api/audit?per=500");
  check("6. no audit row names a wallet state or a pending id (" +
        ids.length + " looked for)", function () {
    assert.ok(/\/authn(-api)?\/wallet/.test(audit.raw), "no wallet row");
    ids.forEach(function (id) {
      assert.ok(audit.raw.indexOf(id) < 0, id.slice(0, 6) + "… is recorded");
    });
  });

  log.info("=== 7. the enrolment and the second factor ===");
  await realmSet(REALM, "oid4vp.signInSelfIssued", true);
  const enrolWho = browser();
  before = await codeCount(rb, "STS-VC-0093");
  await wallet.call(enrolWho, "GET", rb + "/authn/wallet?siop=1&enrol=1");
  const enrol = await wallet.call(enrolWho, "GET", rb +
                                  "/authn-api/wallet?siop=1&enrol=1");
  after = await codesSettle(rb, "STS-VC-0093", before + 1);
  check("7a. an enrolment from a browser holding no sign-on session is " +
        "refused 403 back to the portal, STS-VC-0093", function () {
    assert.strictEqual(enrol.status, 403, enrol.text);
    assert.strictEqual(enrol.json.view.backKind, "portal");
    assert.ok(after > before, before + " -> " + after);
  });
  // The refused view carries no token; the browser takes one as the page
  // does after a refusal, from a start view of its session.
  await wallet.refreshCsrf(rb, enrolWho, await pendingId(rb, app));
  before = after;
  const hinted = await wallet.act(rb, enrolWho, "/authn-api/wallet",
    { siop: "1", enrol: "1", login_hint: "aw-nobody" });
  after = await codesSettle(rb, "STS-VC-0093", before + 1);
  check("7b. a start carrying login_hint is not refused for the field; " +
        "naming nobody signed in it meets the enrolment's refusal",
        function () {
    assert.strictEqual(hinted.status, 403, hinted.text);
    assert.ok(after > before, before + " -> " + after);
  });
  before = await codeCount(rb, "STS-VC-0053");
  const step = await wallet.start(rb, browser(), { mfa: "no-such-step" });
  after = await codesSettle(rb, "STS-VC-0053", before + 1);
  check("7c. a start naming a second-factor step nobody holds is refused " +
        "400, STS-VC-0053", function () {
    assert.strictEqual(step.door.status, 400, step.door.text);
    assert.ok(after > before, before + " -> " + after);
  });
  log.debug("Leaving test().");
}

main();
