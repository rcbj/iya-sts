"use strict";
//
// File: sts_session_management.js
//
// ---------------------------------------------------------------------------
// OPENID CONNECT SESSION MANAGEMENT 1.0 OVER THE WIRE (#121, 2026-09-23).
//
// In a throwaway realm, with no sign-in (runnable in product mode):
//
//   a. OFF (the default): the OP iframe and its script are 404s naming
//      oauth2.sessionManagement, and discovery names no check_session_iframe.
//   b. ON: discovery names the realm's OP iframe; the iframe page is framable
//      by the registered relying party's origin and nobody else (no `*`, no
//      X-Frame-Options), runs one 'self' script, and that script is served.
//   c. prompt=none with no session: login_required carrying a session_state
//      that verifies, by section 3's formula computed HERE, over the empty
//      OP browser state — and an OAuth request without openid carries none.
//
// The iframe's script itself is exercised in tests/session_management.js
// (a node vm), and a signed-in flow there too.
//
// OWNED HERE (local: true): this repository's own OpenID Provider.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const { Command, Option } = require("commander");
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
var log = bunyan.createLogger({ name: "sts_session_management",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("sessmgmt-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                                 .slice(0, 31);
const R = "/realm/" + REALM;
const realmApi = base + R + "/admin-api";
const RP = "https://rp.sessmgmt.example";
const REDIRECT = RP + "/cb";

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
    // Not JSON — an HTML page, a text refusal; the caller reads `raw`.
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

// Section 3's formula, written here rather than read from the service, so
// the check is a second opinion.
function holds(clientId, sessionState, browserState) {
  log.debug("Entering holds().");
  const text = String(sessionState || "");
  const salt = text.slice(text.lastIndexOf(".") + 1);
  const digest = crypto.createHash("sha256")
    .update(clientId + " " + RP + " " + browserState + " " + salt, "utf8")
    .digest("base64url");
  log.debug("Leaving holds().");
  return text === digest + "." + salt;
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving Session Management at " + base + R);

  log.info("=== 0. a throwaway realm " + REALM + " and a relying party ===");
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "Session Mgmt " + STAMP },
    "created the realm");
  await ok(realmApi + "/config/set", { key: "oauth2.openRegistration",
                                       value: true },
           "opened dynamic registration in the realm");
  const reg = await send(base + R + "/oauth2/register", { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ redirect_uris: [REDIRECT],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "client_secret_basic" }) });
  assert.strictEqual(reg.status, 201, reg.raw.slice(0, 300));
  const clientId = reg.body.client_id;

  log.info("=== a. off, by default ===");
  let r = await send(base + R + "/oauth2/check_session");
  check("the OP iframe is a 404 naming the setting, not Express's",
        function () {
    assert.strictEqual(r.status, 404, r.raw.slice(0, 200));
    assert.ok(/oauth2\.sessionManagement/.test(r.raw), r.raw.slice(0, 200));
    assert.ok(!/Cannot GET/.test(r.raw), r.raw.slice(0, 200));
  });
  r = await send(base + R + "/oauth2/check_session.js");
  check("and so is its script", function () {
    assert.strictEqual(r.status, 404, r.raw.slice(0, 200));
  });
  r = await send(base + R + "/.well-known/openid-configuration");
  check("and discovery names no check_session_iframe", function () {
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.body.check_session_iframe, undefined);
  });

  log.info("=== b. on ===");
  await ok(realmApi + "/config/set", { key: "oauth2.sessionManagement",
                                       value: true },
           "turned Session Management on in the realm");
  r = await send(base + R + "/.well-known/openid-configuration");
  const iframeUrl = r.body && r.body.check_session_iframe;
  check("discovery names the realm's OP iframe", function () {
    assert.ok(/\/realm\/[^/]+\/oauth2\/check_session$/.test(
      String(iframeUrl)), String(iframeUrl));
  });
  r = await send(base + R + "/oauth2/check_session");
  const csp = String(r.headers.get("content-security-policy") || "");
  const ancestors = ((/frame-ancestors ([^;]*)/.exec(csp) || [])[1] || "")
    .split(" ");
  check("the OP iframe is framable by the registered relying party and " +
        "nobody else", function () {
    assert.strictEqual(r.status, 200, r.raw.slice(0, 200));
    assert.ok(ancestors.indexOf(RP) >= 0, csp);
    assert.ok(ancestors.indexOf("*") < 0 &&
              ancestors.indexOf("'none'") < 0, csp);
    assert.strictEqual(r.headers.get("x-frame-options"), null);
  });
  check("and runs one 'self' script, no inline one", function () {
    assert.ok(/script-src 'self'/.test(csp), csp);
    assert.ok(/<script src="check_session\.js"><\/script>/.test(r.raw),
              r.raw.slice(0, 300));
  });
  r = await send(base + R + "/oauth2/check_session.js");
  check("and the script is served as JavaScript", function () {
    assert.strictEqual(r.status, 200);
    assert.ok(/javascript/.test(r.headers.get("content-type") || ""));
    assert.ok(/postMessage/.test(r.raw) && /sts_op_browser_state/.test(r.raw));
  });

  log.info("=== c. prompt=none with no session ===");
  const verifier = crypto.randomBytes(32).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier)
    .digest("base64url");
  const ask = function (scope) {
    return send(base + R + "/oauth2/authorize?" + new URLSearchParams({
      client_id: clientId, response_type: "code", redirect_uri: REDIRECT,
      scope: scope, state: "s-" + STAMP, nonce: "n-" + STAMP,
      prompt: "none", code_challenge: challenge,
      code_challenge_method: "S256" }).toString());
  };
  r = await ask("openid");
  const location = String(r.headers.get("location") || "");
  const params = new URLSearchParams(location.slice(location.indexOf("?") +
                                                    1));
  check("login_required, carrying a session_state over the empty browser " +
        "state (section 3, computed here)", function () {
    assert.strictEqual(r.status, 302, r.raw.slice(0, 300));
    assert.ok(location.indexOf(REDIRECT) === 0, location);
    assert.strictEqual(params.get("error"), "login_required", location);
    assert.ok(holds(clientId, params.get("session_state"), ""), location);
  });
  r = await ask("profile");
  const other = String(r.headers.get("location") || "");
  check("an OAuth request without openid carries no session_state",
        function () {
    assert.ok(other.indexOf(REDIRECT) === 0, other);
    assert.ok(!/session_state=/.test(other), other);
  });

  assert.ok(checks >= 9, "only " + checks + " checks ran; a section has " +
                                             "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_session_management")
  .description("OpenID Connect Session Management 1.0 (#121).")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
