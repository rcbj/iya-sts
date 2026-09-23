"use strict";
//
// File: sts_native_sso.js
//
// ---------------------------------------------------------------------------
// OPENID CONNECT NATIVE SSO FOR MOBILE APPS 1.0, AND THE DEVICE REGISTER
// (#130, 2026-09-23), over HTTP, in a throwaway realm.
//
//   1. DISCOVERY: native_sso_supported, and device_sso among the scopes.
//   2. THE FIRST APP: an authorization-code grant for `openid device_sso`
//      returns a device_secret, and its ID Token carries `ds_hash` and `sid`.
//      The device is an entry in ou=devices, owned by the person and linked to
//      the first app (/admin-api/users/devices).
//   3. THE SECOND APP, in the same Native SSO group, exchanges the ID Token
//      and the device secret (section 4) for tokens of its own in the SAME
//      session; the device now names both apps.
//   4. THE REFUSALS: a client not enabled asking for device_sso
//      (invalid_scope); a client of another group exchanging
//      (unauthorized_client); the wrong audience, a wrong secret, and RFC
//      8693's token types — none declared, and an ID Token declared an
//      access token (invalid_request).
//   5. THE SAME DEVICE AGAIN: a new sign-in whose code grant presents the
//      secret is bound to the same device and handed the same secret.
//   6. THE SESSION ENDS: once it is revoked, the exchange is refused.
//   7. REVOCATION: /oauth2/revoke takes the device secret away; the device
//      stays, and is removed through /admin-api.
//
// OWNED HERE (local: true): this repository's authorization server and its
// management API.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const registry = require("./sts_applications.js");
const consentScreen = require("./consent_screen.js");

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
var log = bunyan.createLogger({ name: "sts_native_sso",
                                level: appconfig.LOG_LEVEL ||
                                       process.env.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var root = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("nsso-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                             .slice(0, 31);
const base = root + "/realm/" + REALM;
const api = base + "/admin-api";
const HOLDER = names.usernameFor("nsso-holder");
const PASSWORD = "Nsso-holder-" + crypto.randomBytes(9).toString("base64url") +
                 "-Aa1!";
const EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
const ID_TOKEN = "urn:ietf:params:oauth:token-type:id_token";
const ACCESS = "urn:ietf:params:oauth:token-type:access_token";
const DEVICE = "urn:openid:params:token-type:device-secret";

// Four public clients: two in one group, one in another, one not enabled.
const APPS = {
  first: { id: "nsso-first", group: "vendor.one" },
  second: { id: "nsso-second", group: "vendor.one" },
  other: { id: "nsso-other", group: "vendor.two" },
  plain: { id: "nsso-plain", group: "" }
};
function redirectOf(app) {
  log.debug("Entering redirectOf().");
  log.debug("Leaving redirectOf().");
  return "https://" + app.id + ".example.test/cb";
}

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function payloadOf(jwt) {
  log.debug("Entering payloadOf().");
  log.debug("Leaving payloadOf().");
  return JSON.parse(Buffer.from(String(jwt).split(".")[1], "base64url")
    .toString("utf8"));
}

function jar() {
  log.debug("Entering jar().");
  const cookies = {};
  log.debug("Leaving jar().");
  return {
    header: function header() {
      log.debug("Entering header().");
      log.debug("Leaving header().");
      return Object.keys(cookies).map(function (k) {
        return k + "=" + cookies[k];
      }).join("; ");
    },
    take: function take(response) {
      log.debug("Entering take().");
      const set = typeof response.headers.getSetCookie === "function"
        ? response.headers.getSetCookie() : [];
      set.forEach(function (line) {
        const pair = line.split(";")[0];
        const eq = pair.indexOf("=");
        const name = pair.slice(0, eq).trim();
        const value = pair.slice(eq + 1).trim();
        if (/Max-Age=0/i.test(line) || value === "") {
          delete cookies[name];
        } else {
          cookies[name] = value;
        }
      });
      log.debug("Leaving take().");
      return set;
    }
  };
}

async function hop(who, method, url, opts) {
  log.debug("Entering hop(). " + method + " " + url);
  const o = opts || {};
  const headers = Object.assign({}, o.headers || {});
  let body;
  if (o.form) {
    body = new URLSearchParams(o.form).toString();
    headers["content-type"] = "application/x-www-form-urlencoded";
  } else if (o.json !== undefined) {
    body = JSON.stringify(o.json);
    headers["content-type"] = "application/json";
  }
  if (who && who.header()) {
    headers.cookie = who.header();
  }
  const absolute = new URL(url, base).toString();
  const r = await fetch(absolute, { method: method, headers: headers,
                                    body: body, redirect: "manual" });
  if (who) {
    who.take(r);
  }
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in hop(): " + ((e && e.message) || e));
    json = null;
  }
  const location = r.headers.get("location") || "";
  log.debug("Leaving hop(). " + r.status);
  return { status: r.status, text: text, json: json,
           location: location ? new URL(location, absolute).toString() :
                                "" };
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
  const verifier = crypto.randomBytes(32).toString("base64url");
  log.debug("Leaving pkce().");
  return { verifier: verifier,
           challenge: crypto.createHash("sha256").update(verifier)
             .digest("base64url") };
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await hop(null, "POST", url, { json: payload || {} });
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + r.text.slice(0, 400));
  log.debug("Leaving ok().");
  return r.json;
}

// An authorization-code grant for `app`, signing in with the password where
// the browser has no session, and redeeming the code. `extra` goes on the
// token request (a presented device_secret). Answers { authorized, tokens }.
async function codeGrant(who, app, scope, extra) {
  log.debug("Entering codeGrant(). " + app.id);
  const pair = pkce();
  let r = await hop(who, "GET", base + "/oauth2/authorize?" +
    new URLSearchParams({ response_type: "code", client_id: app.id,
      redirect_uri: redirectOf(app), scope: scope, state: "s-" + STAMP,
      nonce: "n-" + crypto.randomBytes(4).toString("hex"),
      code_challenge: pair.challenge, code_challenge_method: "S256" })
      .toString());
  const authorized = r;
  for (let n = 0; n < 8 && r.location && r.location.indexOf(root) === 0 &&
                  !consentScreen.isConsentScreen(r.location); n += 1) {
    if (/\/authn\/login\?/.test(r.location)) {
      const page = await hop(who, "GET", r.location);
      const fields = hiddenFields(page.text);
      fields.username = HOLDER;
      fields.password = PASSWORD;
      fields.action = "login";
      r = await hop(who, "POST", base + "/authn/login", { form: fields });
    } else {
      r = await hop(who, "GET", r.location);
    }
  }
  const settled = await consentScreen.settleAuthorization({
    base: base, location: r.location, cookie: who.header() });
  const landed = settled.location || r.location || "";
  const url = landed ? new URL(landed) : null;
  const code = url ? url.searchParams.get("code") : null;
  const tokens = code ? await hop(null, "POST", base + "/oauth2/token",
    { form: Object.assign({ grant_type: "authorization_code", code: code,
                            redirect_uri: redirectOf(app), client_id: app.id,
                            code_verifier: pair.verifier }, extra || {}) })
    : null;
  log.debug("Leaving codeGrant(). code=" + !!code);
  return { authorized: authorized, landed: landed,
           error: url ? url.searchParams.get("error") : null,
           tokens: tokens };
}

async function exchange(app, fields) {
  log.debug("Entering exchange(). " + app.id);
  const r = await hop(null, "POST", base + "/oauth2/token", { form:
    Object.assign({ grant_type: EXCHANGE, client_id: app.id }, fields) });
  log.debug("Leaving exchange(). " + r.status);
  return r;
}

async function devicesOf() {
  log.debug("Entering devicesOf().");
  const r = await hop(null, "GET", api + "/users/devices?user=" +
                      encodeURIComponent(HOLDER));
  log.debug("Leaving devicesOf().");
  return (r.json && r.json.devices) || [];
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. a throwaway realm " + REALM + " ===");
  await ok(root + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "Native SSO " + STAMP },
    "created the realm");
  for (const key of Object.keys(APPS)) {
    const app = APPS[key];
    await registry.provision(base, {
      identifier: app.id, name: "Native SSO job " + key,
      protocols: ["oauth2", "oidc"],
      fields: Object.assign({ oauthClientId: app.id,
        oauthGrantType: ["authorization_code", "refresh_token", EXCHANGE],
        oauthTokenEndpointAuthMethod: "none", oauthConfidential: "FALSE",
        oauthRedirectUri: [redirectOf(app)], oauthResponseType: ["code"],
        oauthScope: ["openid", "device_sso"] },
        app.group ? { oauthNativeSso: "TRUE",
                      oauthNativeSsoGroup: app.group } : {}),
      why: "the " + key + " app sts_native_sso.js shares a sign-in through"
    });
  }
  await registry.ensurePerson(base, HOLDER, PASSWORD);

  log.info("=== 1. discovery ===");
  let r = await hop(null, "GET", base + "/.well-known/openid-configuration");
  check("native_sso_supported, and device_sso among the scopes", function () {
    assert.strictEqual(r.json.native_sso_supported, true);
    assert.ok(r.json.scopes_supported.indexOf("device_sso") >= 0);
  });
  const issuer = r.json.issuer;

  log.info("=== 2. the first app ===");
  const browser = jar();
  const firstGrant = await codeGrant(browser, APPS.first,
                                     "openid device_sso");
  const firstTokens = firstGrant.tokens && firstGrant.tokens.json || {};
  const idToken = firstTokens.id_token || "";
  const claims = idToken ? payloadOf(idToken) : {};
  const secret = firstTokens.device_secret || "";
  check("the code grant returns a device_secret, and the ID Token its " +
        "ds_hash and sid", function () {
    assert.ok(firstGrant.tokens, "no code: " + firstGrant.landed);
    assert.strictEqual(firstGrant.tokens.status, 200,
                       firstGrant.tokens.text.slice(0, 300));
    assert.ok(/^[A-Za-z0-9_-]{43}$/.test(secret), firstGrant.tokens.text);
    const expected = crypto.createHash("sha256").update(secret).digest()
      .subarray(0, 16).toString("base64url");
    assert.strictEqual(claims.ds_hash, expected);
    assert.ok(claims.sid, JSON.stringify(claims));
  });
  let held = await devicesOf();
  check("the device is an entry in ou=devices, owned by the person, " +
        "linked to the first app, its session live", function () {
    assert.strictEqual(held.length, 1, JSON.stringify(held));
    assert.ok(/,ou=devices,/.test(held[0].dn), held[0].dn);
    assert.ok(/^uid=/i.test(held[0].owner), held[0].owner);
    assert.strictEqual(held[0].applications.length, 1);
    assert.strictEqual(held[0].nativeSso, true);
    assert.strictEqual(held[0].sessionLive, true);
  });

  log.info("=== 3. the second app ===");
  const exchanged = await exchange(APPS.second, { subject_token: idToken,
    subject_token_type: ID_TOKEN, actor_token: secret,
    actor_token_type: DEVICE, audience: issuer, scope: "openid" });
  const secondId = exchanged.json && exchanged.json.id_token ?
    payloadOf(exchanged.json.id_token) : {};
  check("the second app exchanges the ID Token and the device secret for " +
        "tokens of its own, in the same session", function () {
    assert.strictEqual(exchanged.status, 200, exchanged.text.slice(0, 400));
    assert.ok(exchanged.json.access_token && exchanged.json.id_token);
    assert.strictEqual(exchanged.json.issued_token_type, ACCESS);
    assert.strictEqual(exchanged.json.device_secret, secret);
    assert.strictEqual(secondId.sid, claims.sid);
    assert.strictEqual(secondId.aud, APPS.second.id);
    assert.strictEqual(secondId.sub, claims.sub);
  });
  held = await devicesOf();
  check("the device now names both applications", function () {
    assert.strictEqual(held.length, 1);
    assert.strictEqual(held[0].applications.length, 2,
                       JSON.stringify(held[0]));
  });

  log.info("=== 4. the refusals ===");
  const plain = await codeGrant(jar(), APPS.plain, "openid device_sso");
  check("a client not enabled for Native SSO is refused device_sso " +
        "(invalid_scope)", function () {
    assert.strictEqual(plain.error, "invalid_scope", plain.landed);
  });
  const refusals = [
    ["a client of another group (unauthorized_client)", APPS.other,
     { subject_token: idToken, subject_token_type: ID_TOKEN,
       actor_token: secret, actor_token_type: DEVICE, audience: issuer },
     "unauthorized_client"],
    ["the wrong audience", APPS.second,
     { subject_token: idToken, subject_token_type: ID_TOKEN,
       actor_token: secret, actor_token_type: DEVICE,
       audience: "https://elsewhere.example" }, "invalid_request"],
    ["a device secret that is not the ID Token's", APPS.second,
     { subject_token: idToken, subject_token_type: ID_TOKEN,
       actor_token: crypto.randomBytes(32).toString("base64url"),
       actor_token_type: DEVICE, audience: issuer }, "invalid_request"],
    ["no subject_token_type (RFC 8693 section 2.1)", APPS.second,
     { subject_token: idToken, actor_token: secret,
       actor_token_type: DEVICE, audience: issuer }, "invalid_request"],
    ["an ID Token declared an access token", APPS.second,
     { subject_token: idToken, subject_token_type: ACCESS },
     "invalid_request"]
  ];
  for (const one of refusals) {
    const got = await exchange(one[1], one[2]);
    check("refused: " + one[0], function () {
      assert.strictEqual(got.status, 400, got.text.slice(0, 300));
      assert.strictEqual(got.json.error, one[3], got.text.slice(0, 300));
    });
  }

  log.info("=== 5. the same device again ===");
  const again = await codeGrant(jar(), APPS.first, "openid device_sso",
                                { device_secret: secret });
  const againTokens = (again.tokens && again.tokens.json) || {};
  held = await devicesOf();
  check("a new sign-in presenting the secret keeps the same device and the " +
        "same secret, bound to the new session", function () {
    assert.strictEqual(againTokens.device_secret, secret,
                       again.tokens && again.tokens.text);
    assert.strictEqual(held.length, 1, JSON.stringify(held));
    assert.notStrictEqual(payloadOf(againTokens.id_token).sid, claims.sid);
  });
  const newSid = payloadOf(againTokens.id_token).sid;

  log.info("=== 6. the session ends ===");
  await ok(api + "/sessions/revoke", { key: HOLDER,
    select: "session:" + newSid }, "ended the session");
  const after = await exchange(APPS.second, {
    subject_token: againTokens.id_token, subject_token_type: ID_TOKEN,
    actor_token: secret, actor_token_type: DEVICE, audience: issuer });
  check("once the session has ended, the device secret exchanges nothing",
        function () {
    assert.strictEqual(after.status, 400, after.text.slice(0, 300));
    assert.strictEqual(after.json.error, "invalid_request");
  });

  log.info("=== 7. revocation and removal ===");
  const fresh = await codeGrant(jar(), APPS.first, "openid device_sso",
                                { device_secret: secret });
  const freshTokens = (fresh.tokens && fresh.tokens.json) || {};
  const revoked = await hop(null, "POST", base + "/oauth2/revoke", { form: {
    token: secret, client_id: APPS.first.id } });
  const afterRevoke = await exchange(APPS.second, {
    subject_token: freshTokens.id_token, subject_token_type: ID_TOKEN,
    actor_token: secret, actor_token_type: DEVICE, audience: issuer });
  held = await devicesOf();
  check("/oauth2/revoke takes the secret away and the device stays",
        function () {
    assert.strictEqual(fresh.tokens.status, 200, fresh.tokens.text);
    assert.strictEqual(revoked.status, 200, revoked.text.slice(0, 300));
    assert.strictEqual(afterRevoke.status, 400,
                       afterRevoke.text.slice(0, 300));
    assert.strictEqual(held.length, 1);
    assert.strictEqual(held[0].nativeSso, false);
  });
  // The person's own page, in the browser section 2 signed in: the portal's
  // code flow rides on that sign-on session.
  let page = await hop(browser, "GET", base + "/portal/devices");
  for (let n = 0; n < 12 && (page.status === 302 || page.status === 303);
       n += 1) {
    page = await hop(browser, "GET", page.location);
  }
  check("/portal/devices lists the device, with a Remove", function () {
    assert.strictEqual(page.status, 200, page.text.slice(0, 300));
    assert.ok(page.text.indexOf(held[0].id) >= 0, "the device is listed");
    assert.ok(/value="remove"/.test(page.text), "no Remove form");
  });
  await ok(api + "/users/remove-device", { user: HOLDER, id: held[0].id },
           "removed the device");
  held = await devicesOf();
  check("an administrator removes the device", function () {
    assert.strictEqual(held.length, 0, JSON.stringify(held));
  });

  assert.ok(checks >= 15, "only " + checks + " checks ran");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

new Command()
  .description("OpenID Connect Native SSO (#130): the device secret, the " +
    "ou=devices entry, the section 4 exchange and its refusals, RFC 8693's " +
    "token types, the same device again, a session ending, revocation.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
