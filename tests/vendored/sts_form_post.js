"use strict";
//
// File: sts_form_post.js
//
// ---------------------------------------------------------------------------
// OAUTH 2.0 FORM POST RESPONSE MODE: THE INTERSTITIAL (#126, 2026-09-23).
// With nobody signed in, RFC 9700 section 4.11.2 has an error shown rather
// than redirected, with the person offered the way on. For a client that asked
// for form_post that way on is a FORM — a button POSTing the error, state and
// iss to the redirect URI — never a GET link carrying them in the URL; and for
// form_post.jwt, the one `response` field. In a throwaway realm with RFC 9700
// mode on, with no sign-in, so it runs in every mode. The successful form_post
// response is tests/vendored/sts_oidc_core.js section o.
//
// OWNED HERE (local: true): this repository's own OpenID Provider.
// ---------------------------------------------------------------------------

const assert = require("assert");
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
var log = bunyan.createLogger({ name: "sts_form_post",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("formpost-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                                 .slice(0, 31);
const R = "/realm/" + REALM;
const realmApi = base + R + "/admin-api";
const RP = "https://rp.formpost.example";
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
    // Not JSON — a page; the caller reads `raw`.
    body = null;
  }
  log.debug("Leaving send(). status=" + r.status);
  return { status: r.status, body: body, raw: raw, headers: r.headers,
           location: r.headers.get("location") || "" };
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

async function register(members) {
  log.debug("Entering register().");
  const r = await send(base + R + "/oauth2/register", { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(Object.assign({ redirect_uris: [REDIRECT],
      grant_types: ["authorization_code"], response_types: ["code"],
      token_endpoint_auth_method: "client_secret_basic" }, members || {})) });
  assert.strictEqual(r.status, 201, r.raw.slice(0, 300));
  log.debug("Leaving register().");
  return r.body.client_id;
}

function authorize(params) {
  log.debug("Entering authorize().");
  log.debug("Leaving authorize().");
  return send(base + R + "/oauth2/authorize?" +
              new URLSearchParams(params).toString());
}

function field(raw, name) {
  log.debug("Entering field().");
  const m = new RegExp('<input type="hidden" name="' + name +
                       '" value="([^"]*)"').exec(raw);
  log.debug("Leaving field().");
  return m ? m[1].replace(/&amp;/g, "&") : null;
}

async function test() {
  log.debug("Entering test().");
  log.info("Form post interstitials at " + base + R);
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "Form post " + STAMP },
    "created the realm");
  await ok(realmApi + "/config/set", { key: "oauth2.openRegistration",
                                       value: true },
           "opened dynamic registration in the realm");
  await ok(realmApi + "/config/set", { key: "oauth2.rfc9700", value: true },
           "turned RFC 9700 mode on in the realm");
  const clientId = await register({});
  const action = new RegExp('<form method="post" action="' +
    REDIRECT.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + '">');

  log.info("=== a. form_post ===");
  let r = await authorize({ client_id: clientId, response_type: "bogus",
    redirect_uri: REDIRECT, scope: "openid", state: "st-" + STAMP,
    response_mode: "form_post" });
  check("with nobody signed in the error is shown, not redirected",
        function () {
    assert.strictEqual(r.status, 400, r.status + " " + r.location);
    assert.strictEqual(r.location, "");
  });
  check("and the way on is a FORM POSTing error, state and iss to the " +
        "redirect URI — not a link carrying them in the URL", function () {
    assert.ok(action.test(r.raw), r.raw.slice(0, 600));
    assert.strictEqual(field(r.raw, "error"), "unsupported_response_type");
    assert.strictEqual(field(r.raw, "state"), "st-" + STAMP);
    assert.ok(field(r.raw, "iss"), "no iss field");
    assert.ok(!/href="[^"]*[?#&]error=/.test(r.raw), "a link carries the " +
              "error");
  });
  check("with a button and no script — the page is a decision", function () {
    assert.ok(/<button type="submit">/.test(r.raw));
    assert.ok(!/<script/i.test(r.raw));
  });

  log.info("=== b. form_post.jwt ===");
  r = await authorize({ client_id: clientId, response_type: "bogus",
    redirect_uri: REDIRECT, scope: "openid", state: "s",
    response_mode: "form_post.jwt" });
  check("form_post.jwt's way on POSTs the one response field", function () {
    assert.strictEqual(r.status, 400, r.status + " " + r.location);
    assert.ok(action.test(r.raw), r.raw.slice(0, 600));
    const jwt = field(r.raw, "response");
    assert.ok(jwt && jwt.split(".").length === 3, String(jwt));
    assert.strictEqual(field(r.raw, "error"), null);
  });

  log.info("=== c. a mode that is not form_post keeps its link ===");
  r = await authorize({ client_id: clientId, response_type: "bogus",
    redirect_uri: REDIRECT, scope: "openid", state: "s" });
  check("the query mode's way on is still a link", function () {
    assert.strictEqual(r.status, 400, r.status + " " + r.location);
    assert.ok(/href="https:\/\/rp\.formpost\.example\/cb[?#][^"]*error=/
      .test(r.raw), r.raw.slice(0, 600));
  });

  assert.ok(checks >= 5, "only " + checks + " checks ran; a section has " +
                                           "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_form_post")
  .description("Form Post Response Mode's interstitial (#126).")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
