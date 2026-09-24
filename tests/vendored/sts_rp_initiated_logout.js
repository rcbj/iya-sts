"use strict";
//
// File: sts_rp_initiated_logout.js
//
// ---------------------------------------------------------------------------
// OPENID CONNECT RP-INITIATED LOGOUT 1.0 OVER THE WIRE (#124, with #115,
// 2026-09-23). In a throwaway realm, with no sign-in, so it runs in product
// mode as well:
//
//   a. a malformed request, and a POST that is not a form, are 400 PAGES;
//   b. a client's registered post_logout_redirect_uri is followed with state,
//      by GET and by POST; one it did not register is not followed;
//   c. a client that registered none: development follows an http(s)
//      address, product does not; a private-use one is never followed;
//   d. a hint that is not an ID Token this server issued is refused;
//   e. with nowhere to return, a page, and no "mock" in it.
//
// The confirmation page, the verified hint and "validate before ending" with
// a live session are in tests/rp_initiated_logout.js (a child process).
//
// OWNED HERE (local: true): this repository's own OpenID Provider.
// ---------------------------------------------------------------------------

const assert = require("assert");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
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
var log = bunyan.createLogger({ name: "sts_rp_initiated_logout",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("rplogout-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                                 .slice(0, 31);
const R = "/realm/" + REALM;
const realmApi = base + R + "/admin-api";
const RP = "https://rp.rplogout.example";
const BACK = RP + "/signed-out";

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

function logout(params) {
  log.debug("Entering logout().");
  log.debug("Leaving logout().");
  return send(base + R + "/oauth2/logout?" +
              new URLSearchParams(params || {}).toString());
}

async function register(members) {
  log.debug("Entering register().");
  const r = await send(base + R + "/oauth2/register", { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(Object.assign({ redirect_uris: [RP + "/cb"],
      grant_types: ["authorization_code"], response_types: ["code"],
      token_endpoint_auth_method: "client_secret_basic" }, members || {})) });
  assert.strictEqual(r.status, 201, r.raw.slice(0, 300));
  log.debug("Leaving register().");
  return r.body.client_id;
}

async function test() {
  log.debug("Entering test().");
  const product = await registry.isProduct(registry.baseOf(base));
  log.info("RP-Initiated Logout at " + base + R + " (" +
           (product ? "product" : "development") + " mode)");
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "RP logout " + STAMP },
    "created the realm");
  await ok(realmApi + "/config/set", { key: "oauth2.openRegistration",
                                       value: true },
           "opened dynamic registration in the realm");
  const listed = await register({ post_logout_redirect_uris: [BACK] });
  const bare = await register({});

  log.info("=== a. refusals are pages ===");
  let r = await logout({ post_logout_redirect_uri: "javascript:alert(1)" });
  check("a malformed sign-out is a 400 page", function () {
    assert.strictEqual(r.status, 400, r.raw.slice(0, 200));
    assert.ok(/text\/html/.test(r.headers.get("content-type") || ""));
  });
  r = await send(base + R + "/oauth2/logout", { method: "POST",
    headers: { "Content-Type": "application/json" }, body: "{}" });
  check("a POST that is not a form is a 400 page", function () {
    assert.strictEqual(r.status, 400, r.raw.slice(0, 200));
    assert.ok(/text\/html/.test(r.headers.get("content-type") || ""));
  });

  log.info("=== b. the registered return, with state ===");
  r = await logout({ client_id: listed, post_logout_redirect_uri: BACK,
                     state: "st-" + STAMP });
  check("GET: the registered address, followed, with state", function () {
    assert.strictEqual(r.status, 302, r.raw.slice(0, 200));
    assert.strictEqual(r.location, BACK + "?state=st-" + STAMP);
  });
  r = await send(base + R + "/oauth2/logout", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ client_id: listed,
                                post_logout_redirect_uri: BACK,
                                state: "p" }).toString() });
  check("POST (section 2) with no session cookie is ASKED — a cross-site POST " +
        "looks exactly like this", function () {
    assert.strictEqual(r.status, 200, r.raw.slice(0, 200));
    assert.ok(/name="confirm_for"/.test(r.raw), r.raw.slice(0, 300));
  });
  const fields = {};
  (r.raw.match(/<input type="hidden"[^>]*>/g) || []).forEach(function (tag) {
    const name = /name="([^"]+)"/.exec(tag);
    const value = /value="([^"]*)"/.exec(tag);
    if (name) {
      fields[name[1]] = value ? value[1].replace(/&amp;/g, "&") : "";
    }
  });
  fields.confirm = "yes";
  r = await send(base + R + "/oauth2/logout", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(fields).toString() });
  check("and the page's own form returns to the registered address with " +
        "state", function () {
    assert.strictEqual(r.status, 302, r.raw.slice(0, 200));
    assert.strictEqual(r.location, BACK + "?state=p");
  });
  r = await logout({ client_id: listed,
                     post_logout_redirect_uri: RP + "/elsewhere" });
  check("an address the client did not register is not followed, and the " +
        "page says so", function () {
    assert.strictEqual(r.status, 200, r.raw.slice(0, 200));
    assert.strictEqual(r.location, "");
    assert.ok(/not returned/.test(r.raw), r.raw.slice(0, 300));
  });

  log.info("=== c. a client that registered none ===");
  r = await logout({ client_id: bare, post_logout_redirect_uri: BACK });
  check(product ? "product does not follow an address nobody registered"
                : "development follows it (#118's rule)", function () {
    if (product) {
      assert.strictEqual(r.location, "", r.raw.slice(0, 200));
    } else {
      assert.strictEqual(r.status, 302, r.raw.slice(0, 200));
      assert.strictEqual(r.location, BACK);
    }
  });
  r = await logout({ client_id: bare,
                     post_logout_redirect_uri: "com.example.rplogout:/out" });
  check("a private-use address nobody registered is never followed",
        function () {
    assert.strictEqual(r.location, "", r.raw.slice(0, 200));
  });

  log.info("=== d. a hint that is not this server's ID Token ===");
  r = await logout({ id_token_hint: "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ4In0." +
                                    "c2lnbmF0dXJl" });
  check("is refused, as a page", function () {
    assert.strictEqual(r.status, 400, r.raw.slice(0, 200));
    assert.ok(/text\/html/.test(r.headers.get("content-type") || ""));
  });

  log.info("=== e. nowhere to return ===");
  r = await logout({});
  check("a page saying so, and no \"mock\" in it", function () {
    assert.strictEqual(r.status, 200, r.raw.slice(0, 200));
    assert.ok(/text\/html/.test(r.headers.get("content-type") || ""));
    assert.ok(!/mock/i.test(r.raw), r.raw.slice(0, 200));
  });

  assert.ok(checks >= 10, "only " + checks + " checks ran; a section has " +
                                            "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_rp_initiated_logout")
  .description("OpenID Connect RP-Initiated Logout 1.0 (#124).")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
