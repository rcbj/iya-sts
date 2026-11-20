// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_backchannel_logout_deliveries.js
//
// ---------------------------------------------------------------------------
// OPENID CONNECT BACK-CHANNEL LOGOUT 1.0: THE REGISTRATION RULES, EVERY
// DELIVERY'S FATE, AND WHAT A SIGN-OUT REVOKES — OVER THE WIRE.
//
// D12 (#444): carries over `tests/backchannel_logout.js` (#36) and
// `tests/backchannel_logout_gaps.js` (#123). `sts_backchannel_logout.js`
// holds one delivery to the test peer's relying party and product mode's
// refusal; this job runs relying parties of its OWN, each answering a script
// of statuses, so the retry, the dead letters and the audit are observable.
// In one throwaway DEVELOPMENT realm:
//
//   1. THE REGISTRATION MEMBERS: at RFC 7591 registration a javascript: or
//      fragment-carrying backchannel_logout_uri is refused
//      invalid_client_metadata (STS-REG-0070) and an https one with a query
//      is accepted, its session_required read back FALSE by default; a
//      console write of an ftp: address is refused (STS-REG-0071). SECTION
//      2.2's SCHEME RULE (#123): an http address refused for a public client
//      (STS-REG-0189) and for a confidential one while the outbound policy
//      would not dial it (STS-REG-0190), at registration, at a create and at
//      an attribute write; https untouched; http for a confidential client
//      accepted where the policy sends over http, a public one's still not.
//   2. THE DELIVERIES:
//        a. discovery's two members follow `oauth2.backchannelLogout`;
//        b. an ID Token issued on a session carries `sid`;
//        c. RP-initiated logout: the relying party receives ONE form POST
//           whose logout_token is a logout+jwt, RS256, verified against the
//           realm's JWKS, naming the ID Token's iss, sub and sid, aud the
//           client, exp two minutes on, a jti, the one event, no nonce; the
//           delivery ends `sent` on GET /admin-api/logout, with ONE
//           `logout.backchannel` audit row;
//        d. the console's global logout (`POST /admin-api/logout/global`)
//           lists three deliveries PENDING and says so; then 503, 503, 204 is
//           sent on the third attempt, 400 is dead after one POST
//           (STS-OAUTH-0536) and 500 dead after three (STS-OAUTH-0537), one
//           audit row each with its code, the list showing where each got;
//        e. WS-Federation's wsignout1.0 sends one too;
//        f. forgetting one relying party at `/authn-api/logout` sends it one
//           and leaves the session alive, and ending the session afterwards
//           does not tell it twice;
//        g. with the setting off the ID Token still carries sid (front-channel
//           logout needs it) and a sign-out sends nothing; with both off, no
//           sid.
//   3. SECTION 2.7 AT SIGN-OUT, IN DEVELOPMENT (#123): an online refresh
//      token is revoked, an offline_access one survives, and an entry with
//      `oauthRevokeRefreshOnLogout: FALSE` keeps its online one.
//
// NOT carried, and why: `plan()`'s derived row id and a session that
// recorded no issuer (STS-OAUTH-0542) or a hand-written unusable address
// (STS-OAUTH-0544) — internal planning state no door produces (class (d));
// the Logout Token's claims asked of `claimsFor()` (asserted on the token
// received instead); product mode's refusal of an internal address
// (STS-OAUTH-0534, already `sts_backchannel_logout.js` section 2); a
// registration the register refused answered 201 (a stubbed register,
// class (d)).
//
// THE RELYING PARTIES run in this job on OUTBOUND_TEST_HOST (or
// GNAP_PUSH_HOST, the name the service reaches this runner by).
//
// OWNED HERE (local: true): this repository's own OpenID Provider.
// ---------------------------------------------------------------------------

// An address compared by parsing it, not searched for as text
// (`url_match.js`).
const urls = require("./url_match.js");
const assert = require("assert");
const http = require("http");
const nodeCrypto = require("crypto");
const names = require("./random_username.js");
const registry = require("./sts_applications.js");
const authnSignin = require("./authn_signin");
const navigation = require("./navigation.js");

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
var log = bunyan.createLogger({ name: "sts_backchannel_logout_deliveries",
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
const REALM = "bcd-" + STAMP;
const RB = base + "/realm/" + REALM;
const ORIGIN = new URL(base).origin;
const HOST = process.env.OUTBOUND_TEST_HOST || process.env.GNAP_PUSH_HOST ||
             "127.0.0.1";
const PASSWORD = "Bcd-" + nodeCrypto.randomBytes(9).toString("base64url") +
  "-Aa1!";
const SECRET = "bcd-secret-" + nodeCrypto.randomBytes(16).toString("hex");
const REDIRECT = "https://rp.bcd.example.test/cb";
const EVENT = "http://schemas.openid.net/event/backchannel-logout";
const FLOOR = 41;

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

function partOf(jwt, n) {
  log.debug("Entering partOf().");
  const part = JSON.parse(Buffer.from(String(jwt).split(".")[n],
                                      "base64url").toString("utf8"));
  log.debug("Leaving partOf().");
  return part;
}

function form(o) {
  log.debug("Entering form().");
  log.debug("Leaving form().");
  return new URLSearchParams(o).toString();
}

async function call(method, url, body, headers, jar) {
  log.debug("Entering call(). " + method + " " + url);
  const h = Object.assign({}, headers || {});
  if (jar && Object.keys(jar).length) {
    h.cookie = Object.keys(jar).map(function (k) {
      return k + "=" + jar[k];
    }).join("; ");
  }
  const r = await fetch(/^https?:/.test(url) ? url : RB + url,
    { method: method, redirect: "manual", headers: h, body: body });
  if (jar) {
    (r.headers.getSetCookie ? r.headers.getSetCookie() : [])
      .forEach(function (one) {
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
  }
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
    // Not JSON; `text` carries it.
    json = null;
  }
  log.debug("Leaving call(). " + r.status);
  return { status: r.status, text: text, json: json,
           location: r.headers.get("location") || "" };
}

// A GET as a browser's top-level navigation sends it (`navigation.js`):
// `/oauth2/logout` asks rather than signs out when a GET says it is not one
// (#1443).
async function navigate(url, jar) {
  log.debug("Entering navigate(). " + url);
  const headers = {};
  if (jar && Object.keys(jar).length) {
    headers.cookie = Object.keys(jar).map(function (k) {
      return k + "=" + jar[k];
    }).join("; ");
  }
  const r = await navigation.navigate(/^https?:/.test(url) ? url : RB + url,
                                      headers);
  (r.headers.getSetCookie ? r.headers.getSetCookie() : [])
    .forEach(function (one) {
      const pair = String(one).split(";")[0];
      const at = pair.indexOf("=");
      if (at <= 0 || !jar) {
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
  log.debug("Leaving navigate(). " + r.status);
  return { status: r.status, text: text, json: null,
           location: r.headers.get("location") || "" };
}

function postJson(url, payload) {
  log.debug("Entering postJson().");
  log.debug("Leaving postJson().");
  return call("POST", url, JSON.stringify(payload || {}),
              { "Content-Type": "application/json" });
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await postJson(url, payload);
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
            what + ": " + r.status + " " + r.text.slice(0, 400));
  log.debug("Leaving ok().");
  return r.json;
}

function setting(key, value) {
  log.debug("Entering setting(). " + key);
  log.debug("Leaving setting().");
  return ok(base + "/admin-api/realms/set", { id: REALM, key: key,
    value: String(value) }, "set " + key);
}

function reset(key) {
  log.debug("Entering reset(). " + key);
  log.debug("Leaving reset().");
  return ok(RB + "/admin-api/config/reset", { key: key }, "reset " + key);
}

// The newest refused `protocol.call` row at `path`: its code.
async function lastCode(path) {
  log.debug("Entering lastCode(). " + path);
  for (let i = 0; i < 20; i += 1) {
    const r = await call("GET", "/admin-api/audit?per=30&action=" +
                         "protocol.call");
    const rows = ((r.json && (r.json.events || r.json.rows)) || [])
      .filter(function (row) {
        return String(row.target || "") === "/realm/" + REALM + path &&
               row.outcome !== "success";
      });
    if (rows.length && rows[0].errorCode) {
      log.debug("Leaving lastCode(). " + rows[0].errorCode);
      return String(rows[0].errorCode);
    }
    await sleep(100);
  }
  log.debug("Leaving lastCode(). none");
  return "";
}

// Every `logout.backchannel` audit row for a client.
async function auditRows(clientId) {
  log.debug("Entering auditRows(). " + clientId);
  const r = await call("GET", "/admin-api/audit?per=500&action=" +
                       "logout.backchannel");
  const rows = ((r.json && (r.json.events || r.json.rows)) || [])
    .filter(function (row) {
      return row.target === clientId;
    });
  log.debug("Leaving auditRows(). " + rows.length);
  return rows;
}

// The deliveries GET /admin-api/logout lists for a client.
async function deliveries(clientId) {
  log.debug("Entering deliveries(). " + clientId);
  const r = await call("GET", "/admin-api/logout?per=200");
  const rows = ((r.json && r.json.backchannelDeliveries) || [])
    .filter(function (row) {
      return row.clientId === clientId;
    });
  log.debug("Leaving deliveries(). " + rows.length);
  return rows;
}

async function settled(clientId, count) {
  log.debug("Entering settled(). " + clientId);
  let rows = [];
  for (let i = 0; i < 150; i += 1) {
    rows = await deliveries(clientId);
    if (rows.length >= count && rows.every(function (row) {
      return row.state !== "pending";
    })) {
      break;
    }
    await sleep(100);
  }
  log.debug("Leaving settled(). " + rows.length);
  return rows;
}

// THE RELYING PARTIES: every POST recorded, each path answering from a
// script of statuses whose last one repeats.
function relyingParties() {
  log.debug("Entering relyingParties().");
  const state = { received: [], scripts: {} };
  const server = http.createServer(function (req, res) {
    let text = "";
    req.on("data", function (c) {
      text += c;
    });
    req.on("end", function () {
      state.received.push({ path: req.url, method: req.method,
                            type: String(req.headers["content-type"] || ""),
                            body: text });
      const script = state.scripts[req.url] || [404];
      const status = script.length > 1 ? script.shift() : script[0];
      res.writeHead(status, { "cache-control": "no-store" });
      res.end();
    });
  });
  state.postsTo = function (p) {
    return state.received.filter(function (one) {
      return one.path === p;
    });
  };
  log.debug("Leaving relyingParties().");
  return new Promise(function (resolve) {
    server.listen(Number(process.env.BCD_LISTENER_PORT || 0), "0.0.0.0",
                  function () {
      state.server = server;
      state.origin = "http://" + HOST + ":" + server.address().port;
      resolve(state);
    });
  });
}

async function client(id, extra) {
  log.debug("Entering client(). " + id);
  await ok(RB + "/admin-api/applications/create", {
    identifier: id, name: id, protocols: ["oauth2", "oidc"],
    fields: Object.assign({ oauthClientId: [id], oauthClientSecret: SECRET,
      oauthTokenEndpointAuthMethod: "client_secret_post",
      oauthGrantType: ["authorization_code", "refresh_token"],
      oauthRedirectUri: [REDIRECT],
      oauthGlobalConsent: ["openid", "offline_access"] }, extra || {}) },
    "created the client " + id);
  log.debug("Leaving client().");
}

// The code flow for `clientId` in `jar`, signing `username` in first when
// the browser has no session. Answers the token response.
async function authorize(jar, clientId, username, scope) {
  log.debug("Entering authorize(). " + clientId);
  let r = await call("GET", "/oauth2/authorize?" + form({
    response_type: "code", client_id: clientId, redirect_uri: REDIRECT,
    scope: scope || "openid", state: "st",
    nonce: "n-" + nodeCrypto.randomBytes(6).toString("hex") }),
    undefined, {}, jar);
  if ((r.status === 302 || r.status === 303) &&
      /\/authn\/login/.test(r.location)) {
    r = await authnSignin.signInWithJar(RB, r.location,
      { action: "login", username: username, password: PASSWORD }, jar);
  }
  for (let hops = 0; hops < 6 && (r.status === 302 || r.status === 303) &&
       !urls.isAt(r.location, REDIRECT); hops += 1) {
    r = await call("GET", /^https?:/.test(r.location) ? r.location
      : ORIGIN + r.location, undefined, {}, jar);
  }
  const code = urls.isAt(r.location, REDIRECT)
    ? new URL(r.location).searchParams.get("code") : "";
  assert.ok(code, "no code for " + clientId + ": " + r.status + " " +
            r.location + " " + String(r.text).slice(0, 300));
  const t = await call("POST", "/oauth2/token", form({
    grant_type: "authorization_code", code: code, redirect_uri: REDIRECT,
    client_id: clientId, client_secret: SECRET }),
    { "Content-Type": "application/x-www-form-urlencoded" });
  assert.ok(t.status === 200 && t.json.id_token,
            "the token endpoint: " + t.status + " " + t.text.slice(0, 300));
  log.debug("Leaving authorize().");
  return t.json;
}

// The sign-out page's own confirmation (RP-initiated logout with no hint
// asks), answered yes.
async function signOut(jar, query) {
  log.debug("Entering signOut().");
  let r = await navigate("/oauth2/logout" + (query ? "?" + form(query)
                                                     : ""), jar);
  if (/name="confirm_for"/.test(r.text)) {
    const fields = {};
    (r.text.match(/<input type="hidden"[^>]*>/g) || []).forEach(
      function (tag) {
        const name = /name="([^"]+)"/.exec(tag);
        const value = /value="([^"]*)"/.exec(tag);
        if (name) {
          fields[name[1]] = value ? value[1].replace(/&amp;/g, "&") : "";
        }
      });
    fields.confirm = "yes";
    r = await call("POST", "/oauth2/logout", form(fields),
      { "Content-Type": "application/x-www-form-urlencoded",
        Origin: ORIGIN }, jar);
  }
  log.debug("Leaving signOut(). " + r.status);
  return r;
}

async function registrationSection(rps) {
  log.debug("Entering registrationSection().");
  log.info("=== 1. the registration members ===");
  const json = { "Content-Type": "application/json" };
  const register = function (members) {
    return call("POST", "/oauth2/register", JSON.stringify(Object.assign({
      redirect_uris: [REDIRECT] }, members)), json);
  };
  let r = await register({ backchannel_logout_uri: "javascript:alert(1)" });
  let code = await lastCode("/oauth2/register");
  check("1a1. a registration naming a javascript: backchannel_logout_uri is " +
        "refused invalid_client_metadata (STS-REG-0070)", function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 300));
    assert.strictEqual(r.json.error, "invalid_client_metadata");
    assert.strictEqual(code, "STS-REG-0070");
  });
  r = await register({ backchannel_logout_uri:
                         "https://rp.bcd.example/bc#frag" });
  check("1a2. and so is one with a fragment — section 2.2", function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 300));
    assert.strictEqual(r.json.error, "invalid_client_metadata");
  });
  r = await register({ backchannel_logout_uri:
                         "https://rp.bcd.example/bc?x=1" });
  // The registration response echoes the address and leaves the
  // unrequested session_required out (no true is invented for it).
  check("1a3. an https address with a query component is accepted, and " +
        "session_required is not claimed true when nobody asked",
        function () {
    assert.strictEqual(r.status, 201, r.text.slice(0, 300));
    assert.strictEqual(r.json.backchannel_logout_uri,
                       "https://rp.bcd.example/bc?x=1");
    assert.notStrictEqual(r.json.backchannel_logout_session_required, true);
  });
  await client("bcd-lib");
  r = await postJson(RB + "/admin-api/applications/set", {
    application: "bcd-lib", attribute: "oauthBackchannelLogoutUri",
    value: "ftp://rp.bcd.example/bc" });
  code = await lastCode("/admin-api/applications/set");
  check("1a5. a console write of an ftp: address is refused " +
        "(STS-REG-0071)", function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 300));
    assert.strictEqual(code, "STS-REG-0071");
  });

  log.info("--- section 2.2's scheme rule (#123) ---");
  const HTTP_URI = "http://rp.bcd.example/bc";
  const HTTPS_URI = "https://rp.bcd.example/bc";
  await setting("federation.outboundAllowHttp", false);
  r = await register({ backchannel_logout_uri: HTTP_URI,
                       token_endpoint_auth_method: "none" });
  code = await lastCode("/oauth2/register");
  check("1b. registration: a public client's http URI is refused, saying it " +
        "needs a confidential client (STS-REG-0189)", function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 300));
    assert.strictEqual(r.json.error, "invalid_client_metadata");
    assert.ok(/confidential/.test(r.json.error_description),
              r.json.error_description);
    assert.strictEqual(code, "STS-REG-0189");
  });
  r = await register({ backchannel_logout_uri: HTTP_URI });
  code = await lastCode("/oauth2/register");
  check("1c. registration: a confidential client's http URI is refused " +
        "while the outbound policy would not dial it, with its reason " +
        "(STS-REG-0190)", function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 300));
    assert.ok(/dead-lettered/.test(r.json.error_description),
              r.json.error_description);
    assert.strictEqual(code, "STS-REG-0190");
  });
  r = await register({ backchannel_logout_uri: HTTPS_URI });
  check("1d. registration: https is accepted", function () {
    assert.strictEqual(r.status, 201, r.text.slice(0, 300));
  });
  await setting("federation.outboundAllowHttp", true);
  r = await register({ backchannel_logout_uri: HTTP_URI });
  check("1e. registration: a confidential client's http URI is accepted " +
        "where the policy sends over http", function () {
    assert.strictEqual(r.status, 201, r.text.slice(0, 300));
  });
  r = await register({ backchannel_logout_uri: HTTP_URI,
                       token_endpoint_auth_method: "none" });
  check("1f. and a public client's still is not", function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 300));
  });
  await setting("federation.outboundAllowHttp", false);
  r = await postJson(RB + "/admin-api/applications/create", {
    identifier: "bcd-public", name: "bcd-public", protocols: ["oauth2"],
    fields: { oauthClientId: ["bcd-public"],
              oauthRedirectUri: [REDIRECT],
              oauthBackchannelLogoutUri: HTTP_URI } });
  code = await lastCode("/admin-api/applications/create");
  check("1g. a create with no credential (a public client) and an http URI " +
        "is refused (STS-REG-0189)", function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 300));
    assert.strictEqual(code, "STS-REG-0189");
  });
  r = await postJson(RB + "/admin-api/applications/set", {
    application: "bcd-lib", attribute: "oauthBackchannelLogoutUri",
    value: HTTP_URI });
  code = await lastCode("/admin-api/applications/set");
  check("1h. an attribute write of an http URI on a confidential entry is " +
        "refused while the policy would not dial it (STS-REG-0190)",
        function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 300));
    assert.strictEqual(code, "STS-REG-0190");
  });
  r = await postJson(RB + "/admin-api/applications/set", {
    application: "bcd-lib", attribute: "oauthBackchannelLogoutUri",
    value: HTTPS_URI });
  check("1i. and an https one is written", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
  });
  // Every later section sends over http to this job's listeners.
  await setting("federation.outboundAllowHttp", true);
  log.debug("Leaving registrationSection(). " + rps.origin);
}

async function verifiedBy(jwt) {
  log.debug("Entering verifiedBy().");
  const header = partOf(jwt, 0);
  const jwks = await call("GET", "/oauth2/jwks");
  const jwk = (jwks.json.keys || []).filter(function (k) {
    return k.kid === header.kid;
  })[0];
  if (!jwk) {
    log.debug("Leaving verifiedBy(). No such key.");
    return false;
  }
  const parts = String(jwt).split(".");
  const key = nodeCrypto.createPublicKey({ key: jwk, format: "jwk" });
  const good = nodeCrypto.verify("sha256",
    Buffer.from(parts[0] + "." + parts[1]), key,
    Buffer.from(parts[2], "base64url"));
  log.debug("Leaving verifiedBy(). " + good);
  return good;
}

async function deliverySection(rps) {
  log.debug("Entering deliverySection().");
  log.info("=== 2a. discovery ===");
  let d = await call("GET", "/.well-known/openid-configuration");
  check("2a1. discovery advertises backchannel_logout_supported and " +
        "backchannel_logout_session_supported", function () {
    assert.strictEqual(d.json.backchannel_logout_supported, true);
    assert.strictEqual(d.json.backchannel_logout_session_supported, true);
  });
  await setting("oauth2.backchannelLogout", false);
  d = await call("GET", "/.well-known/openid-configuration");
  await reset("oauth2.backchannelLogout");
  check("2a2. and both read false with oauth2.backchannelLogout off",
        function () {
    assert.strictEqual(d.json.backchannel_logout_supported, false);
    assert.strictEqual(d.json.backchannel_logout_session_supported, false);
  });

  log.info("=== 2b, 2c. an RP-initiated logout ===");
  const alice = {};
  const t = await authorize(alice, "bcd-ok", "bcd-alice-" + STAMP);
  const idToken = partOf(t.id_token, 1);
  check("2b1. the ID Token issued on the session carries sid", function () {
    assert.ok(idToken.sid, JSON.stringify(idToken));
  });
  const r = await navigate("/oauth2/logout?" + form({
    id_token_hint: t.id_token, client_id: "bcd-ok" }), alice);
  check("2c0. /oauth2/logout answers at once", function () {
    assert.ok(r.status === 200 || r.status === 302 || r.status === 303,
              r.status + " " + r.text.slice(0, 200));
  });
  const rows = await settled("bcd-ok", 1);
  const posts = rps.postsTo("/bc/ok");
  check("2c1. the relying party received ONE form POST (section 2.5)",
        function () {
    assert.strictEqual(posts.length, 1, "deliveries: " +
                       JSON.stringify(rows) + " received: " +
                       JSON.stringify(rps.received).slice(0, 300) + " " +
                       r.status + " " + r.location + " " +
                       r.text.replace(/<[^>]*>/g, " ").replace(/\s+/g, " ")
                         .slice(0, 600));
    assert.strictEqual(posts[0].method, "POST");
    assert.ok(/application\/x-www-form-urlencoded/.test(posts[0].type),
              posts[0].type);
  });
  const token = new URLSearchParams(posts[0].body).get("logout_token");
  const head = partOf(token, 0);
  const body = partOf(token, 1);
  check("2c2. the logout_token is typed logout+jwt and signed RS256, with " +
        "the kid of the realm key", function () {
    assert.strictEqual(head.typ, "logout+jwt");
    assert.strictEqual(head.alg, "RS256");
    assert.ok(head.kid);
  });
  check("2c3. it names the ID Token's iss, sub and sid, is addressed to the " +
        "client, lives two minutes, carries a jti and the one event, and no " +
        "nonce (section 2.4)", function () {
    assert.strictEqual(body.iss, idToken.iss);
    assert.strictEqual(body.sub, idToken.sub);
    assert.strictEqual(body.sid, idToken.sid);
    assert.strictEqual(body.aud, "bcd-ok");
    assert.strictEqual(body.exp - body.iat, 120);
    assert.ok(typeof body.jti === "string" && body.jti.length >= 16);
    assert.deepStrictEqual(body.events, { [EVENT]: {} });
    assert.ok(!("nonce" in body));
  });
  const verified = await verifiedBy(token);
  check("2c4. its signature verifies against the realm's JWKS", function () {
    assert.ok(verified);
  });
  const audited = await auditRows("bcd-ok");
  check("2c5. the delivery ends sent, after one attempt, on GET " +
        "/admin-api/logout", function () {
    assert.strictEqual(rows.length, 1, JSON.stringify(rows));
    assert.strictEqual(rows[0].state, "sent");
    assert.strictEqual(rows[0].attempts, 1);
  });
  check("2c6. ONE logout.backchannel audit row records it", function () {
    assert.strictEqual(audited.length, 1);
    assert.strictEqual(audited[0].outcome, "success");
  });
  const gone = await call("GET", "/oauth2/authorize?" + form({
    response_type: "code", client_id: "bcd-ok", redirect_uri: REDIRECT,
    scope: "openid", state: "st", nonce: "n" }), undefined, {}, alice);
  check("2c7. and the session is gone", function () {
    assert.ok(/\/authn\/login/.test(gone.location), gone.status + " " +
              gone.location);
  });
  log.debug("Leaving deliverySection().");
}

async function globalSection(rps) {
  log.debug("Entering globalSection().");
  log.info("=== 2d. the console's global logout: retry, 400, 5xx ===");
  const bob = {};
  const who = "bcd-bob-" + STAMP;
  await authorize(bob, "bcd-flaky", who);
  await authorize(bob, "bcd-refuse", who);
  await authorize(bob, "bcd-down", who);
  const acted = await ok(RB + "/admin-api/logout/global", { user: who },
                         "the console's global logout");
  const listedNow = (acted.result && acted.result.backchannel) || [];
  check("2d1. the console's global logout lists three deliveries, each " +
        "PENDING — they are sent after the answer", function () {
    assert.strictEqual(listedNow.length, 3, JSON.stringify(listedNow)
      .slice(0, 400));
    assert.ok(listedNow.every(function (row) {
      return row.state === "pending";
    }));
  });
  check("2d2. and its message says so", function () {
    assert.ok(/3 back-channel Logout Tokens \(3 pending\)/.test(
      acted.message), acted.message);
    assert.ok(/BACK-CHANNEL Logout Tokens need no browser/.test(
      acted.message), acted.message);
  });
  const flaky = (await settled("bcd-flaky", 1))[0] || {};
  const refuse = (await settled("bcd-refuse", 1))[0] || {};
  const down = (await settled("bcd-down", 1))[0] || {};
  check("2d3. 503, 503, 204: retried and SENT on the third attempt (204 is " +
        "success, section 2.8)", function () {
    assert.strictEqual(flaky.state, "sent", JSON.stringify(flaky));
    assert.strictEqual(flaky.attempts, 3);
    assert.strictEqual(rps.postsTo("/bc/flaky").length, 3);
  });
  check("2d4. 400 is FINAL — one POST, a dead letter", function () {
    assert.strictEqual(refuse.state, "dead", JSON.stringify(refuse));
    assert.strictEqual(refuse.attempts, 1);
    assert.strictEqual(rps.postsTo("/bc/refuse").length, 1);
  });
  check("2d5. 500 every time: three POSTs (the attempts setting), then a " +
        "dead letter", function () {
    assert.strictEqual(down.state, "dead", JSON.stringify(down));
    assert.strictEqual(down.attempts, 3);
    assert.strictEqual(rps.postsTo("/bc/down").length, 3);
  });
  const fRows = await auditRows("bcd-flaky");
  const rRows = await auditRows("bcd-refuse");
  const dRows = await auditRows("bcd-down");
  check("2d6. ONE audit row per delivery, not one per attempt, each failure " +
        "with its code (STS-OAUTH-0536, STS-OAUTH-0537)", function () {
    assert.strictEqual(fRows.length, 1);
    assert.strictEqual(rRows.length, 1);
    assert.strictEqual(dRows.length, 1);
    assert.strictEqual(rRows[0].errorCode, "STS-OAUTH-0536");
    assert.strictEqual(dRows[0].errorCode, "STS-OAUTH-0537");
  });
  // A dead delivery's code is drawn on Monitoring -> Sessions for an
  // administrator diagnosing it (#1355; `getLiveSessions` in
  // tests/openapi_response_models.js's DRAWN_CODE_OPERATIONS).
  check("2d7. GET /admin-api/logout lists where each delivery got to, the " +
        "dead ones with their codes for the console to draw", function () {
    assert.strictEqual(down.state, "dead");
    assert.strictEqual(flaky.state, "sent");
    assert.strictEqual(refuse.errorCode, "STS-OAUTH-0536",
                       JSON.stringify(refuse));
    assert.strictEqual(down.errorCode, "STS-OAUTH-0537");
    assert.ok(!flaky.errorCode, JSON.stringify(flaky));
  });
  log.debug("Leaving globalSection().");
}

async function wsfedSection(rps) {
  log.debug("Entering wsfedSection().");
  log.info("=== 2e. WS-Federation's sign-out ===");
  const carol = {};
  await authorize(carol, "bcd-wsfed", "bcd-carol-" + STAMP);
  const r = await navigate("/wsfed?wa=wsignout1.0", carol);
  const rows = await settled("bcd-wsfed", 1);
  check("2e1. wsignout1.0 ends the session and the OIDC relying party is " +
        "sent its Logout Token — a door front-channel never reached",
        function () {
    assert.ok(r.status < 500, r.status + " " + r.text.slice(0, 200));
    assert.strictEqual(rows.length, 1, JSON.stringify(rows));
    assert.strictEqual(rows[0].state, "sent");
    assert.strictEqual(rps.postsTo("/bc/wsfed").length, 1);
  });
  log.debug("Leaving wsfedSection().");
}

async function forgetSection(rps) {
  log.debug("Entering forgetSection().");
  log.info("=== 2f. forgetting one relying party ===");
  const dave = {};
  await authorize(dave, "bcd-one", "bcd-dave-" + STAMP);
  const seen = await call("GET", "/authn-api/logout", undefined,
                          { accept: "application/json" }, dave);
  const rpRow = [];
  ((seen.json && seen.json.view && seen.json.view.families) || [])
    .forEach(function (family) {
      (family.rows || []).forEach(function (row) {
        if (/^oidc-rp:/.test(String(row.id)) &&
            String(row.id).indexOf("bcd-one") >= 0) {
          rpRow.push(row.id);
        }
      });
    });
  assert.strictEqual(rpRow.length, 1, "the relying party's row: " +
                     seen.text.slice(0, 600));
  const act = await call("POST", "/authn-api/logout",
    JSON.stringify({ scope: "selected", select: rpRow }),
    { "content-type": "application/json", accept: "application/json",
      origin: ORIGIN, "x-csrf-token": seen.json.csrf }, dave);
  const rows = await settled("bcd-one", 1);
  check("2f1. a selective \"forget this relying party\" sends it a Logout " +
        "Token", function () {
    assert.strictEqual(act.status, 200, act.text.slice(0, 300));
    assert.strictEqual(rows.length, 1);
    assert.strictEqual(rows[0].state, "sent");
    assert.strictEqual(rps.postsTo("/bc/one").length, 1);
  });
  const still = await call("GET", "/authn-api/logout", undefined,
                           { accept: "application/json" }, dave);
  check("2f2. and the session itself stays", function () {
    assert.strictEqual(still.status, 200, still.text.slice(0, 200));
    assert.ok(!!dave.sts_session);
  });
  await signOut(dave);
  await sleep(500);
  check("2f3. ending the session afterwards does not tell the forgotten " +
        "client twice", function () {
    assert.strictEqual(rps.postsTo("/bc/one").length, 1);
  });
  log.debug("Leaving forgetSection().");
}

async function offSection(rps) {
  log.debug("Entering offSection().");
  log.info("=== 2g. the setting off ===");
  await setting("oauth2.backchannelLogout", false);
  const erin = {};
  const t = await authorize(erin, "bcd-off", "bcd-erin-" + STAMP);
  check("2g1. with it off the ID Token still carries sid, because " +
        "front-channel logout is on and needs it", function () {
    assert.ok(partOf(t.id_token, 1).sid);
  });
  await signOut(erin);
  await sleep(600);
  const rows = await deliveries("bcd-off");
  check("2g2. and a sign-out sends nothing and plans nothing", function () {
    assert.strictEqual(rps.postsTo("/bc/off").length, 0);
    assert.strictEqual(rows.length, 0, JSON.stringify(rows));
  });
  await setting("oauth2.frontchannelLogout", false);
  const frank = {};
  const f = await authorize(frank, "bcd-off", "bcd-frank-" + STAMP);
  await reset("oauth2.frontchannelLogout");
  await reset("oauth2.backchannelLogout");
  check("2g3. with BOTH off the ID Token carries no sid", function () {
    assert.ok(!("sid" in partOf(f.id_token, 1)));
  });
  log.debug("Leaving offSection().");
}

async function revokedSection() {
  log.debug("Entering revokedSection().");
  log.info("=== 3. section 2.7 at sign-out, in development ===");
  const gina = {};
  const who = "bcd-gina-" + STAMP;
  const offline = (await authorize(gina, "bcd-rt", who,
                                   "openid offline_access")).refresh_token;
  const online = (await authorize(gina, "bcd-rt", who, "openid"))
    .refresh_token;
  const kept = (await authorize(gina, "bcd-keeps", who, "openid"))
    .refresh_token;
  const active = async function (tokenValue, id) {
    const r = await call("POST", "/oauth2/introspect", form({
      token: tokenValue, client_id: id, client_secret: SECRET }),
      { "Content-Type": "application/x-www-form-urlencoded" });
    return !!(r.json && r.json.active);
  };
  const before = [await active(offline, "bcd-rt"),
                  await active(online, "bcd-rt"),
                  await active(kept, "bcd-keeps")];
  check("3a. three refresh tokens on one session, all active before the " +
        "sign-out (RFC 9700 mode is off)", function () {
    assert.ok(offline && online && kept, "a refresh token is missing");
    assert.deepStrictEqual(before, [true, true, true]);
  });
  await signOut(gina);
  const onlineAfter = await active(online, "bcd-rt");
  const offlineAfter = await active(offline, "bcd-rt");
  const keptAfter = await active(kept, "bcd-keeps");
  check("3b. after the sign-out the online token is revoked, in development " +
        "mode (section 2.7)", function () {
    assert.strictEqual(onlineAfter, false);
  });
  check("3c. the offline_access token survives (OIDC Core section 11)",
        function () {
    assert.strictEqual(offlineAfter, true);
  });
  check("3d. and oauthRevokeRefreshOnLogout: FALSE on an entry keeps its " +
        "online token", function () {
    assert.strictEqual(keptAfter, true);
  });
  log.debug("Leaving revokedSection().");
}

async function setUp(rps) {
  log.debug("Entering setUp().");
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "Back-channel deliveries " + STAMP },
    "created the realm");
  await setting("global.mode", "development");
  // RISK SCORING (#62) is off for sts_admin_client_policies.js's reason.
  await setting("risk.assessSignIns", false);
  await setting("oauth2.backchannelLogoutBackoffMs", 0);
  await setting("oauth2.backchannelLogoutTimeoutMs", 2000);
  for (const who of ["alice", "bob", "carol", "dave", "erin", "frank",
                     "gina"]) {
    await registry.ensurePerson(RB, "bcd-" + who + "-" + STAMP, PASSWORD);
  }
  rps.scripts = { "/bc/ok": [200], "/bc/flaky": [503, 503, 204],
                  "/bc/refuse": [400], "/bc/down": [500],
                  "/bc/wsfed": [200], "/bc/one": [200], "/bc/off": [200] };
  log.debug("Leaving setUp().");
}

async function clients(rps) {
  log.debug("Entering clients().");
  for (const name of ["ok", "flaky", "refuse", "down", "wsfed", "one",
                      "off"]) {
    await client("bcd-" + name, {
      oauthBackchannelLogoutUri: rps.origin + "/bc/" + name,
      oauthBackchannelLogoutSessionRequired: "TRUE" });
  }
  await client("bcd-rt");
  await client("bcd-keeps", { oauthRevokeRefreshOnLogout: "FALSE" });
  log.debug("Leaving clients().");
}

async function test() {
  log.debug("Entering test().");
  const rps = await relyingParties();
  try {
    await setUp(rps);
    await registrationSection(rps);
    await clients(rps);
    await deliverySection(rps);
    await globalSection(rps);
    await wsfedSection(rps);
    await forgetSection(rps);
    await offSection(rps);
    await revokedSection();
  } finally {
    rps.server.close();
  }
  assert.ok(checks >= FLOOR, "only " + checks + " checks ran; the floor is " +
            FLOOR);
  log.info(checks + " check(s) passed.");
  log.debug("Leaving test().");
}

// REMOVAL IS OPT-IN: with STS_TEST_REMOVE_REALMS=1 (a private probe that
// would otherwise fill its directory) the realm this run made is removed at
// the end, pass or fail. A suite run leaves it standing (tests/CLAUDE.md,
// *No job removes a realm*).
async function removeRealms() {
  log.debug("Entering removeRealms().");
  if (process.env.STS_TEST_REMOVE_REALMS !== "1") {
    log.debug("Leaving removeRealms(). Not asked to.");
    return;
  }
  const r = await postJson(base + "/admin-api/realms/remove", { id: REALM });
  log.info("removed the realm " + REALM + " (" + r.status + ")");
  log.debug("Leaving removeRealms().");
}

async function main() {
  log.debug("Entering main().");
  let failure = null;
  try {
    await test();
  } catch (e) {
    log.debug("Caught in main(): " + ((e && e.message) || e));
    // Reported below, after the realm is removed.
    failure = e;
  }
  try {
    await removeRealms();
  } catch (e) {
    log.debug("Caught in main(): " + ((e && e.message) || e));
    // A removal that fails is logged; the job's verdict is the test's.
    log.warn("could not remove the realm: " + ((e && e.message) || e));
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
