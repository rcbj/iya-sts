"use strict";
//
// File: sts_frontchannel_logout.js
//
// ---------------------------------------------------------------------------
// OPENID CONNECT FRONT-CHANNEL LOGOUT 1.0, OVER THE WIRE (#122, 2026-09-22).
//
// What the #45 review found, held from where a relying party meets it, in a
// throwaway realm it leaves behind with dynamic registration opened:
//
//   a. DISCOVERY (section 3): frontchannel_logout_session_supported — the
//      provider member — and not the registration member it used to publish
//      in its place; `sid` in claims_supported.
//   b. THE ORIGIN RULE (section 2) at registration: a frontchannel_logout_uri
//      whose scheme, host and port match no redirect_uri is refused; one that
//      matches is accepted.
//   c. THE SAME RULE at /admin-api's attribute write.
//   d. THE SIGN-OUT PAGE after signing in through a NAMED authorization
//      server and signing out at the realm's own /oauth2/logout: the iframe
//      carries the named server's `iss` (the one the ID Token named, not the
//      sign-out's) and the session's `sid`; frame-src names the relying
//      party's origin and frame-ancestors survives; and section 4's return
//      is a <meta> refresh to the post_logout_redirect_uri, with the link.
//   e. oauth2.frontchannelLogoutWaitS=0 keeps the link and draws no refresh.
//   f. A STORED URI THAT NO LONGER MATCHES — the redirect URI it shared an
//      origin with removed — is reported on /logout's inventory and not
//      framed by /oauth2/logout.
//
// OWNED HERE (local: true): this repository's own authorization server.
// ---------------------------------------------------------------------------

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
var log = bunyan.createLogger({ name: "sts_frontchannel_logout",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("fclogout-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                                  .slice(0, 31);
const R = "/realm/" + REALM;
const realmApi = base + R + "/admin-api";
const RP = "https://rp.fclogout.example.test";
const REDIRECT = RP + "/cb";
const FRONTCHANNEL = RP + "/fc";
const POST_LOGOUT = RP + "/signed-out";
// A named authorization server inside the realm. Unconfigured, it publishes
// this service's defaults under an issuer of its own, which is all d needs.
const AS = "fcx";
const PASSWORD = "Fc-Logout-Passw0rd!-" + String(Date.now()).slice(-6);
const ALICE = names.usernameFor("fc-alice");

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
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
    // Not JSON — a page; the caller reads `raw`.
    body = null;
  }
  log.debug("Leaving send(). status=" + r.status);
  return { status: r.status, body: body, raw: raw,
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

// One browser, with a cookie jar.
function browser(name) {
  log.debug("Entering browser(). " + name);
  const jar = {};
  const self = {
    async go(method, path, body) {
      log.debug("Entering go(). " + method + " " + path);
      const headers = {};
      const cookie = Object.keys(jar).map(function (k) {
        return k + "=" + jar[k];
      }).join("; ");
      if (cookie) {
        headers.cookie = cookie;
      }
      if (body !== undefined) {
        headers["Content-Type"] = "application/x-www-form-urlencoded";
      }
      const r = await fetch(absolute(path), { method: method,
        redirect: "manual", headers: headers, body: body });
      const set = r.headers.getSetCookie ? r.headers.getSetCookie() : [];
      set.forEach(function (one) {
        const pair = String(one).split(";")[0];
        const at = pair.indexOf("=");
        if (at <= 0) {
          return;
        }
        const value = pair.slice(at + 1);
        if (value === "" || /Expires=Thu, 01 Jan 1970/i.test(String(one))) {
          delete jar[pair.slice(0, at)];
        } else {
          jar[pair.slice(0, at)] = value;
        }
      });
      const text = await r.text();
      log.debug("Leaving go(). status=" + r.status);
      return { status: r.status, location: r.headers.get("location") || "",
               text: text, headers: r.headers };
    }
  };
  log.debug("Leaving browser().");
  return self;
}

function hiddenFields(html) {
  log.debug("Entering hiddenFields().");
  const out = {};
  (String(html).match(/<input type="hidden"[^>]*>/g) || [])
    .forEach(function (tag) {
      const name = /name="([^"]+)"/.exec(tag);
      const value = /value="([^"]*)"/.exec(tag);
      if (name) {
        out[name[1]] = value ? value[1].replace(/&amp;/g, "&") : "";
      }
    });
  log.debug("Leaving hiddenFields().");
  return out;
}

function pkce() {
  log.debug("Entering pkce().");
  const verifier = nodeCrypto.randomBytes(32).toString("base64url");
  log.debug("Leaving pkce().");
  return { verifier: verifier,
           challenge: nodeCrypto.createHash("sha256").update(verifier)
             .digest("base64url") };
}

// Where a redirect to REDIRECT put its parameters: `{ where, params }`, or
// null when it went anywhere else.
function atClient(r, redirect) {
  log.debug("Entering atClient().");
  const target = redirect || REDIRECT;
  if (!(r.status === 302 || r.status === 303) ||
      String(r.location).indexOf(target) !== 0) {
    log.debug("Leaving atClient(). Not at the client.");
    return null;
  }
  const url = new URL(r.location);
  const fragment = url.hash ? new URLSearchParams(url.hash.slice(1)) : null;
  log.debug("Leaving atClient().");
  return fragment && Array.from(fragment.keys()).length
    ? { where: "fragment", params: fragment }
    : { where: "query", params: url.searchParams };
}

async function signIn(b, location, who) {
  log.debug("Entering signIn(). who=" + who);
  const page = await b.go("GET", location);
  assert.strictEqual(page.status, 200, "the sign-in screen: " + page.status +
                     " " + page.text.slice(0, 300));
  const fields = hiddenFields(page.text);
  fields.username = who;
  fields.password = PASSWORD;
  fields.action = "login";
  const posted = await b.go("POST", R + "/authn/login", form(fields));
  log.debug("Leaving signIn().");
  return posted;
}

// An authorization request; follows a sign-in when there is no session.
async function authorize(b, params, who) {
  log.debug("Entering authorize().");
  let r = await b.go("GET", R + "/oauth2/authorize?" + form(params));
  if ((r.status === 302 || r.status === 303) &&
      /\/authn\/login\?authn=/.test(r.location) && who) {
    const signed = await signIn(b, r.location, who);
    r = await b.go("GET", signed.location);
  }
  log.debug("Leaving authorize(). " + r.status);
  return r;
}

async function register(metadata) {
  log.debug("Entering register().");
  const r = await postJson(base + R + "/oauth2/register", Object.assign({
    redirect_uris: [REDIRECT], token_endpoint_auth_method:
      "client_secret_basic", grant_types: ["authorization_code"],
    response_types: ["code"], post_logout_redirect_uris: [POST_LOGOUT]
  }, metadata || {}));
  log.debug("Leaving register(). " + r.status);
  return r;
}

async function setUp() {
  log.debug("Entering setUp().");
  log.info("=== 0. a throwaway realm " + REALM + " ===");
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "Front-channel " + STAMP },
    "created the realm");
  await ok(realmApi + "/config/set", { key: "oauth2.openRegistration",
                                       value: true },
           "opened dynamic registration in the realm");
  await ok(realmApi + "/users/create", {
    username: ALICE, invent: false, credential: "password",
    password: PASSWORD,
    attributes: { cn: "Front " + ALICE, givenName: "Front", sn: ALICE,
                  mail: ALICE + "@fclogout.test" } },
    "created " + ALICE);
  log.debug("Leaving setUp().");
}

// Signs ALICE in to `client` through the named authorization server, and
// answers the browser holding the session.
async function signedInThroughNamedServer(client) {
  log.debug("Entering signedInThroughNamedServer().");
  const b = browser("alice");
  const p = nodeCrypto.randomBytes(32).toString("base64url");
  const params = { response_type: "code", client_id: client.client_id,
    redirect_uri: REDIRECT, scope: "openid", state: "st-" + STAMP,
    nonce: "n-" + STAMP,
    code_challenge: nodeCrypto.createHash("sha256").update(p)
      .digest("base64url"),
    code_challenge_method: "S256" };
  let r = await b.go("GET", R + "/" + AS + "/oauth2/authorize?" +
                     form(params));
  if ((r.status === 302 || r.status === 303) &&
      /\/authn\/login\?authn=/.test(r.location)) {
    const page = await b.go("GET", r.location);
    const fields = hiddenFields(page.text);
    fields.username = ALICE;
    fields.password = PASSWORD;
    fields.action = "login";
    const posted = await b.go("POST", R + "/authn/login", form(fields));
    r = await b.go("GET", posted.location);
  }
  assert.ok((r.status === 302 || r.status === 303) &&
            r.location.indexOf(REDIRECT) === 0 &&
            new URL(r.location).searchParams.get("code"),
    "a code from the named authorization server: " + r.status + " " +
    r.location + " " + String(r.text).slice(0, 300));
  log.debug("Leaving signedInThroughNamedServer().");
  return b;
}

function signOutUrl(client) {
  log.debug("Entering signOutUrl().");
  log.debug("Leaving signOutUrl().");
  return R + "/oauth2/logout?" + form({ client_id: client.client_id,
    post_logout_redirect_uri: POST_LOGOUT });
}

async function test() {
  log.debug("Entering test().");
  await setUp();

  log.info("=== a. discovery ===");
  const discovery = (await send(base + R +
                                "/.well-known/openid-configuration")).body;
  check("frontchannel_logout_session_supported is published, and the " +
        "registration member frontchannel_logout_session_required is not",
    function () {
      assert.strictEqual(discovery.frontchannel_logout_supported, true);
      assert.strictEqual(discovery.frontchannel_logout_session_supported,
                         true, JSON.stringify(discovery));
      assert.ok(!("frontchannel_logout_session_required" in discovery));
    });
  check("sid is in claims_supported", function () {
    assert.ok((discovery.claims_supported || []).indexOf("sid") >= 0);
  });

  log.info("=== b. the origin rule at registration ===");
  const elsewhere = await register({
    frontchannel_logout_uri: "https://elsewhere.example.test/fc" });
  check("a frontchannel_logout_uri on another host is refused", function () {
    assert.strictEqual(elsewhere.status, 400, elsewhere.raw);
    assert.strictEqual(elsewhere.body.error, "invalid_client_metadata");
    assert.ok(/frontchannel_logout_uri/.test(
      elsewhere.body.error_description), elsewhere.raw);
  });
  const otherPort = await register({
    frontchannel_logout_uri: RP + ":8443/fc" });
  check("and one on the same host at another port", function () {
    assert.strictEqual(otherPort.status, 400, otherPort.raw);
  });
  const good = await register({ frontchannel_logout_uri: FRONTCHANNEL,
    frontchannel_logout_session_required: true });
  check("one on the redirect URI's origin is accepted", function () {
    assert.strictEqual(good.status, 201, good.raw);
  });
  const client = good.body;
  await ok(realmApi + "/consent/grant-global-consent",
           { client: client.client_id, scope: "openid" },
           "consented openid for everybody on " + client.client_id);

  log.info("=== c. the origin rule at /admin-api ===");
  const written = await postJson(realmApi + "/applications/set",
    { application: client.client_id,
      attribute: "oauthFrontchannelLogoutUri",
      value: "https://elsewhere.example.test/fc" });
  check("a write of an off-origin frontchannel URI is refused", function () {
    assert.strictEqual(written.status, 400, written.raw);
  });

  log.info("=== d. the sign-out page ===");
  const named = (await send(base + R + "/" + AS +
                            "/.well-known/openid-configuration")).body;
  const realmIssuer = discovery.issuer;
  check("the named server has an issuer of its own", function () {
    assert.ok(named && named.issuer && named.issuer !== realmIssuer,
              JSON.stringify(named && named.issuer));
  });
  let b = await signedInThroughNamedServer(client);
  let out = await b.go("GET", signOutUrl(client));
  let page = out.text;
  const csp = String(out.headers.get("content-security-policy") || "");
  const frame = /<iframe src="([^"]+)"/.exec(page);
  check("the sign-out renders the notification", function () {
    assert.strictEqual(out.status, 200, page.slice(0, 400));
    assert.ok(frame, page.slice(0, 800));
  });
  const framed = new URL(frame[1].replace(/&amp;/g, "&"));
  check("the iframe carries the NAMED server's iss, not the sign-out's",
    function () {
      assert.strictEqual(framed.origin + framed.pathname, FRONTCHANNEL);
      assert.strictEqual(framed.searchParams.get("iss"), named.issuer,
                         framed.toString());
      assert.ok(framed.searchParams.get("sid"), framed.toString());
    });
  check("frame-src names the relying party and frame-ancestors survives",
    function () {
      assert.ok(/frame-src [^;]*https:\/\/rp\.fclogout\.example\.test/
        .test(csp), csp);
      assert.ok(/frame-ancestors/.test(csp), csp);
    });
  check("section 4's return: a <meta> refresh to post_logout_redirect_uri " +
        "after 3 seconds, and the link", function () {
    assert.ok(page.indexOf('<meta http-equiv="refresh" content="3;url=' +
                           POST_LOGOUT + '">') >= 0, page.slice(0, 1200));
    assert.ok(page.indexOf('<a href="' + POST_LOGOUT + '">') >= 0);
  });

  log.info("=== e. oauth2.frontchannelLogoutWaitS=0 ===");
  await ok(realmApi + "/config/set",
           { key: "oauth2.frontchannelLogoutWaitS", value: 0 },
           "set the wait to 0 in the realm");
  b = await signedInThroughNamedServer(client);
  out = await b.go("GET", signOutUrl(client));
  page = out.text;
  check("no refresh, and the link is still drawn", function () {
    assert.ok(page.indexOf('http-equiv="refresh"') < 0, page.slice(0, 800));
    assert.ok(page.indexOf('<a href="' + POST_LOGOUT + '">') >= 0);
  });
  await ok(realmApi + "/config/reset",
           { key: "oauth2.frontchannelLogoutWaitS" }, "cleared the wait");

  log.info("=== f. a stored URI that no longer matches ===");
  b = await signedInThroughNamedServer(client);
  await ok(realmApi + "/applications/add",
    { application: client.client_id, attribute: "oauthRedirectUri",
      value: "https://moved.fclogout.example.test/cb" },
    "added a redirect URI on another host");
  await ok(realmApi + "/applications/remove",
    { application: client.client_id, attribute: "oauthRedirectUri",
      value: REDIRECT }, "removed the one the frontchannel URI matched");
  // The inventory first: /logout lists every relying party the session
  // holds, and says why one will not be notified.
  const inventory = await b.go("GET", R + "/logout");
  check("/logout lists the client as not to be notified, with section 2's " +
        "reason", function () {
    assert.strictEqual(inventory.status, 200, inventory.text.slice(0, 400));
    assert.ok(/Front-Channel Logout 1\.0 section 2/.test(inventory.text),
              inventory.text.slice(0, 2000));
  });
  out = await b.go("GET", signOutUrl(client));
  check("and /oauth2/logout frames nothing: with nobody left to notify it " +
        "answers the plain redirect", function () {
    assert.ok(out.status === 302 || out.status === 303,
              out.status + " " + out.text.slice(0, 400));
    assert.strictEqual(out.location, POST_LOGOUT);
  });

  log.info("Test completed successfully. " + checks + " check(s) passed.");
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error("sts_frontchannel_logout FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
