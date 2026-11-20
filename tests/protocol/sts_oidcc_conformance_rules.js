// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_oidcc_conformance_rules.js
//
// ---------------------------------------------------------------------------
// WHAT THE OPENID CONFORMANCE SUITE ASKED OF THIS PROVIDER, ASKED DIRECTLY
// OVER THE WIRE, WITHOUT THE SUITE'S CONTAINERS.
//
// D12 (#444): carries over `tests/oidcc_conformance_defaults.js` (#1292) and
// `tests/oidcc_conformance_findings.js` (#187). `sts_oidcc_conformance.js`
// and its siblings run the plans themselves, in their own lanes with the
// suite's three containers; this job is the regression check for each fix
// they led to, asked of a running service in throwaway realms:
//
//   E. `keys.eddsaSigning`, OFF by default: a fresh realm's JWKS carries no
//      OKP signing key (its RSA key first) and its discovery offers no
//      EdDSA for what it signs while still accepting EdDSA client
//      assertions; a realm that turned it on publishes OKP keys and lists
//      EdDSA for ID Tokens; a registration naming EdDSA for its ID Tokens
//      is refused (invalid_client_metadata) in the one and accepted in the
//      other.
//   T. Enterprise Extensions' `tenant` and `session_expiry`: absent from an
//      ID Token by default; `tenant` (the realm's id) when the claims
//      request names it; in every ID Token with
//      `oauth2.enterpriseClaimsAlways`.
//   P. THE `profile` SCOPE: an implicit ID Token for a person with nothing
//      typed carries all fourteen claims in development; a person whose
//      entry holds middleName, schacGender, timeZone, pictureUrl and
//      profileUrl is answered from them (schacGender 1 as `male`); none of
//      them without the scope.
//   1. RFC 6749 SECTION 6 IN EVERY MODE: a refresh token presented by
//      another client is invalid_grant citing RFC 6749 (STS-OAUTH-0141);
//      its own client redeems it; a refresh asking for more than its grant
//      is invalid_scope (0142), a narrower one is not.
//   2. RFC 6749 SECTION 4.1.2 IN EVERY MODE: a code presented twice is
//      invalid_grant (0143) and the access token the first redemption
//      bought is revoked (introspection inactive); with
//      `oauth2.codeReplayIdempotent` the second answers as the first did;
//      RFC 9700 mode ignores that setting.
//   3. OPENID CONNECT CORE 6.2's FRAGMENT: a request_uri whose fragment is
//      the SHA-256 of other content is refused by default and taken with
//      `oauth2.requestUriFragmentCheck` off — the request object served by
//      this job's own listener.
//   7. A REQUEST NAMING NO response_type (missing or empty) is told it
//      names none, quoting no ""; an unknown one is quoted
//      (STS-OAUTH-0162).
//   8. RFC 9700 MODE: an unregistered redirect_uri is refused in one
//      sentence naming only the address sent, for a client that registered
//      one address and one that registered two (#1331); an unregistered
//      post_logout_redirect_uri's page names no registered address either.
//
// NOT carried, and why: E1–E9 (the setting row's shape, the helper
// functions, `signJwtAs()` refused STS-KEYS-0165 — library calls; no request
// reaches a signer naming EdDSA while the realm offers none, because every
// door that names an algorithm refuses it first, class (d)); 4, OpenID
// Federation 1.1 section 12.1.1.1's request-object claims for an
// automatically registered relying party (OWED to phase 7, OpenID
// Federation: it needs a federation entity this job cannot stand up); 5,
// ECDH-ES's Concat KDF with apu/apv, and 6, OpenID4VCI credential-response
// encryption to an EC key (OWED to phase 9, OpenID4VC: each needs a wallet's
// flow); 1g, a refresh naming no client outside RFC 9700 mode (over the wire
// a token request always names its client, by authentication or by
// client_id, class (d)); 1h, a refresh widening a grant that carried NO
// scope (every grant issued over the wire carries one — a request naming
// none is given the client's default — so no such refresh token exists,
// class (d)); 8b's `checkPostLogoutRedirectUri()` reason fields
// (a library answer; the page is asserted instead).
//
// THE LISTENER (section 3) runs on OUTBOUND_TEST_HOST (or GNAP_PUSH_HOST,
// the name the service reaches this runner by).
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
var log = bunyan.createLogger({ name: "sts_oidcc_conformance_rules",
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
const OFF = "occ-off-" + STAMP;
const ON = "occ-on-" + STAMP;
const BCP = "occ-bcp-" + STAMP;
const HOST = process.env.OUTBOUND_TEST_HOST || process.env.GNAP_PUSH_HOST ||
             "127.0.0.1";
const PASSWORD = "Occ-" + nodeCrypto.randomBytes(9).toString("base64url") +
  "-Aa1!";
const SECRET = "occ-secret-" + nodeCrypto.randomBytes(16).toString("hex");
const REDIRECT = "https://rp.occ.example.test/cb";
const PLAIN = "occ-plain-" + STAMP;
const TYPED = "occ-typed-" + STAMP;
const FLOOR = 25;

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

function claimsOf(jwt) {
  log.debug("Entering claimsOf().");
  const claims = JSON.parse(Buffer.from(String(jwt).split(".")[1],
                                        "base64url").toString("utf8"));
  log.debug("Leaving claimsOf().");
  return claims;
}

async function call(method, url, body, headers, jar) {
  log.debug("Entering call(). " + method + " " + url);
  const h = Object.assign({}, headers || {});
  if (jar && Object.keys(jar).length) {
    h.cookie = Object.keys(jar).map(function (k) {
      return k + "=" + jar[k];
    }).join("; ");
  }
  const r = await fetch(url, { method: method, redirect: "manual",
    headers: h, body: body });
  if (jar) {
    (r.headers.getSetCookie ? r.headers.getSetCookie() : [])
      .forEach(function (one) {
        const pair = String(one).split(";")[0];
        const at = pair.indexOf("=");
        if (at > 0) {
          jar[pair.slice(0, at)] = pair.slice(at + 1);
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

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await call("POST", url, JSON.stringify(payload || {}),
                       { "Content-Type": "application/json" });
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
            what + ": " + r.status + " " + r.text.slice(0, 400));
  log.debug("Leaving ok().");
  return r.json;
}

function setting(realm, key, value) {
  log.debug("Entering setting(). " + realm + " " + key);
  log.debug("Leaving setting().");
  return ok(base + "/admin-api/realms/set", { id: realm, key: key,
    value: String(value) }, "set " + key + " on " + realm);
}

function form(o) {
  log.debug("Entering form().");
  log.debug("Leaving form().");
  return new URLSearchParams(o).toString();
}

function token(realm, fields) {
  log.debug("Entering token().");
  log.debug("Leaving token().");
  return call("POST", rb(realm) + "/oauth2/token", form(fields),
              { "Content-Type": "application/x-www-form-urlencoded" });
}

function withClient(id, fields) {
  log.debug("Entering withClient().");
  log.debug("Leaving withClient().");
  return Object.assign({ client_id: id, client_secret: SECRET }, fields);
}

// The newest refused `protocol.call` row at `path` in the realm: its code.
async function lastCode(realm, path) {
  log.debug("Entering lastCode(). " + path);
  for (let i = 0; i < 20; i += 1) {
    const r = await call("GET", rb(realm) +
                         "/admin-api/audit?per=30&action=protocol.call");
    const rows = ((r.json && (r.json.events || r.json.rows)) || [])
      .filter(function (row) {
        return String(row.target || "").indexOf(path) >= 0 &&
               row.outcome !== "success";
      });
    if (rows.length && rows[0].errorCode) {
      log.debug("Leaving lastCode(). " + rows[0].errorCode);
      return String(rows[0].errorCode);
    }
    await new Promise(function (resolve) {
      setTimeout(resolve, 100);
    });
  }
  log.debug("Leaving lastCode(). none");
  return "";
}

async function client(realm, id, extra) {
  log.debug("Entering client(). " + realm + " " + id);
  await ok(rb(realm) + "/admin-api/applications/create", {
    identifier: id, name: id, protocols: ["oauth2", "oidc"],
    fields: Object.assign({ oauthClientId: [id], oauthClientSecret: SECRET,
      oauthTokenEndpointAuthMethod: "client_secret_post",
      oauthGrantType: ["password", "refresh_token", "authorization_code",
                       "implicit"],
      oauthResponseType: ["code", "id_token", "id_token token"],
      oauthRedirectUri: [REDIRECT],
      oauthGlobalConsent: ["openid", "profile", "offline_access"] },
      extra || {}) }, "created the client " + id + " in " + realm);
  log.debug("Leaving client().");
}

// A browser signed in to `realm` at the screen, after the authorization
// request `query` sent it there. Answers where the browser landed and its
// jar.
async function authorize(realm, query, username, jarIn) {
  log.debug("Entering authorize(). " + realm);
  const jar = jarIn || {};
  let r = await call("GET", rb(realm) + "/oauth2/authorize?" + form(query),
                     undefined, {}, jar);
  if ((r.status === 302 || r.status === 303) &&
      /\/authn\/login/.test(r.location)) {
    r = await authnSignin.signInWithJar(rb(realm), r.location,
      { action: "login", username: username, password: PASSWORD }, jar);
  }
  for (let hops = 0; hops < 6 && (r.status === 302 || r.status === 303) &&
       !urls.isAt(r.location, REDIRECT); hops += 1) {
    const next = /^https?:/.test(r.location) ? r.location
      : new URL(base).origin + r.location;
    r = await call("GET", next, undefined, {}, jar);
  }
  log.debug("Leaving authorize(). " + r.status);
  return { landed: String(r.location || ""), jar: jar, last: r };
}

function fragmentOf(url) {
  log.debug("Entering fragmentOf().");
  const at = String(url).indexOf("#");
  log.debug("Leaving fragmentOf().");
  return new URLSearchParams(at >= 0 ? String(url).slice(at + 1) : "");
}

async function idTokenFor(realm, clientId, username, extra) {
  log.debug("Entering idTokenFor().");
  const got = await authorize(realm, Object.assign({
    response_type: "id_token", client_id: clientId, redirect_uri: REDIRECT,
    scope: "openid", state: "st",
    nonce: "n-" + nodeCrypto.randomBytes(6).toString("hex") }, extra || {}),
    username);
  const idToken = fragmentOf(got.landed).get("id_token");
  assert.ok(idToken, "no ID Token at the client: " + got.landed + " " +
            got.last.status + " " + String(got.last.text).slice(0, 300));
  log.debug("Leaving idTokenFor().");
  return claimsOf(idToken);
}

async function eddsaSection() {
  log.debug("Entering eddsaSection().");
  log.info("=== E. keys.eddsaSigning, off by default ===");
  const okpSigning = function (list) {
    return (list || []).filter(function (k) {
      return k.kty === "OKP" && k.use !== "enc";
    });
  };
  const offJwks = await call("GET", rb(OFF) + "/oauth2/jwks");
  const onJwks = await call("GET", rb(ON) + "/oauth2/jwks");
  check("E10. a fresh realm's JWKS carries no OKP signing key, its RSA key " +
        "still first", function () {
    assert.strictEqual(offJwks.status, 200);
    assert.strictEqual(okpSigning(offJwks.json.keys).length, 0);
    assert.strictEqual(offJwks.json.keys[0].kty, "RSA");
  });
  check("E11. a realm with keys.eddsaSigning on publishes its OKP keys",
        function () {
    assert.ok(okpSigning(onJwks.json.keys).length > 0,
              JSON.stringify(onJwks.json.keys.map(function (k) {
                return k.kty + "/" + (k.crv || "");
              })));
  });
  const off = (await call("GET", rb(OFF) +
                          "/.well-known/openid-configuration")).json;
  const on = (await call("GET", rb(ON) +
                         "/.well-known/openid-configuration")).json;
  check("E12. the off realm's discovery: no EdDSA among what it signs, " +
        "EdDSA still among the client assertions it accepts", function () {
    assert.ok(off.id_token_signing_alg_values_supported.indexOf("EdDSA") < 0);
    assert.ok(off.userinfo_signing_alg_values_supported.indexOf("EdDSA") < 0);
    assert.ok(off.token_endpoint_auth_signing_alg_values_supported
      .indexOf("EdDSA") >= 0);
  });
  check("E13. and the realm with it on lists EdDSA for its ID Tokens",
        function () {
    assert.ok(on.id_token_signing_alg_values_supported.indexOf("EdDSA") >= 0,
              JSON.stringify(on.id_token_signing_alg_values_supported));
  });
  const asked = JSON.stringify({ redirect_uris: [REDIRECT],
    id_token_signed_response_alg: "EdDSA" });
  const json = { "Content-Type": "application/json" };
  const refused = await call("POST", rb(OFF) + "/oauth2/register", asked,
                             json);
  const accepted = await call("POST", rb(ON) + "/oauth2/register", asked,
                              json);
  check("E14. a registration naming EdDSA for its ID Tokens is refused by " +
        "default and accepted with the switch on", function () {
    assert.strictEqual(refused.status, 400, refused.text.slice(0, 300));
    assert.strictEqual(refused.json.error, "invalid_client_metadata");
    assert.strictEqual(accepted.status, 201, accepted.text.slice(0, 300));
    assert.strictEqual(accepted.json.id_token_signed_response_alg, "EdDSA");
  });
  log.debug("Leaving eddsaSection().");
}

async function enterpriseSection() {
  log.debug("Entering enterpriseSection().");
  log.info("=== T. tenant and session_expiry ===");
  const plain = await idTokenFor(OFF, "occ-web", PLAIN);
  check("T1. by default an ID Token carries neither tenant nor " +
        "session_expiry", function () {
    assert.ok(plain.sub);
    assert.strictEqual(plain.tenant, undefined);
    assert.strictEqual(plain.session_expiry, undefined);
  });
  const named = await idTokenFor(OFF, "occ-web", PLAIN, {
    claims: JSON.stringify({ id_token: { tenant: null } }) });
  check("T2. a claims request naming tenant puts the realm's id there, and " +
        "nothing else", function () {
    assert.strictEqual(named.tenant, OFF, JSON.stringify(named));
    assert.strictEqual(named.session_expiry, undefined);
  });
  await setting(OFF, "oauth2.enterpriseClaimsAlways", true);
  const always = await idTokenFor(OFF, "occ-web", PLAIN);
  await ok(rb(OFF) + "/admin-api/config/reset",
           { key: "oauth2.enterpriseClaimsAlways" }, "reset the setting");
  check("T3. oauth2.enterpriseClaimsAlways puts tenant in every ID Token",
        function () {
    assert.strictEqual(always.tenant, OFF, JSON.stringify(always));
  });
  log.debug("Leaving enterpriseSection().");
}

async function profileSection() {
  log.debug("Entering profileSection().");
  log.info("=== P. the profile scope ===");
  const PROFILE = ["name", "family_name", "given_name", "middle_name",
                   "nickname", "preferred_username", "profile", "picture",
                   "website", "gender", "birthdate", "zoneinfo", "locale",
                   "updated_at"];
  const invented = await idTokenFor(OFF, "occ-web", PLAIN,
                                    { scope: "openid profile" });
  const missing = PROFILE.filter(function (c) {
    return invented[c] === undefined;
  });
  check("P1. an implicit ID Token for a person with nothing typed carries " +
        "all fourteen profile claims in development", function () {
    assert.strictEqual(missing.join(", "), "");
  });
  const typed = await idTokenFor(OFF, "occ-web", TYPED,
                                 { scope: "openid profile" });
  check("P2. a person's own five attributes answer the five claims, " +
        "schacGender 1 as male", function () {
    assert.strictEqual(typed.middle_name, "Quincy", JSON.stringify(typed));
    assert.strictEqual(typed.gender, "male");
    assert.strictEqual(typed.zoneinfo, "Europe/Stockholm");
    assert.strictEqual(typed.picture, "https://bob.example/photo.jpg");
    assert.strictEqual(typed.profile, "https://bob.example/");
  });
  const scopeless = await idTokenFor(OFF, "occ-web", TYPED);
  check("P3. and none of them without the profile scope", function () {
    assert.strictEqual(scopeless.middle_name, undefined);
    assert.strictEqual(scopeless.gender, undefined);
  });
  log.debug("Leaving profileSection().");
}

async function refresh(scope, clientId) {
  log.debug("Entering refresh().");
  const fields = { grant_type: "password", username: PLAIN,
                   password: PASSWORD };
  if (scope) {
    fields.scope = scope;
  }
  const r = await token(OFF, withClient(clientId || "occ-one", fields));
  assert.ok(r.status === 200 && r.json.refresh_token,
            "the password grant: " + r.status + " " + r.text.slice(0, 300));
  log.debug("Leaving refresh().");
  return r.json.refresh_token;
}

async function refreshSection() {
  log.debug("Entering refreshSection().");
  log.info("=== 1. a refresh token is its own client's, in every mode ===");
  let rt = await refresh("openid offline_access");
  let r = await token(OFF, withClient("occ-two", {
    grant_type: "refresh_token", refresh_token: rt }));
  const crossCode = await lastCode(OFF, "/oauth2/token");
  check("1a–c. a refresh token issued to one client and presented by " +
        "another is refused invalid_grant with RFC 9700 mode off, citing " +
        "RFC 6749 (STS-OAUTH-0141)", function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 300));
    assert.strictEqual(r.json.error, "invalid_grant");
    assert.ok(/RFC 6749 section 6/.test(r.json.error_description),
              r.json.error_description);
    assert.strictEqual(crossCode, "STS-OAUTH-0141");
  });
  r = await token(OFF, withClient("occ-one", {
    grant_type: "refresh_token", refresh_token: rt }));
  check("1d. its own client redeems it", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
  });
  rt = await refresh("openid offline_access");
  r = await token(OFF, withClient("occ-one", {
    grant_type: "refresh_token", refresh_token: rt,
    scope: "openid offline_access profile" }));
  const widerCode = await lastCode(OFF, "/oauth2/token");
  check("1e. a refresh asking for more than its grant is refused " +
        "invalid_scope, in every mode (STS-OAUTH-0142)", function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 300));
    assert.strictEqual(r.json.error, "invalid_scope");
    assert.strictEqual(widerCode, "STS-OAUTH-0142");
  });
  rt = await refresh("openid offline_access profile");
  r = await token(OFF, withClient("occ-one", {
    grant_type: "refresh_token", refresh_token: rt,
    scope: "openid offline_access" }));
  check("1f. and a narrower one is not", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
  });
  log.debug("Leaving refreshSection().");
}

async function codeTwice(realm) {
  log.debug("Entering codeTwice(). " + realm);
  // PKCE in every realm: RFC 9700 mode requires it.
  const verifier = nodeCrypto.randomBytes(32).toString("base64url");
  const got = await authorize(realm, { response_type: "code",
    client_id: "occ-one", redirect_uri: REDIRECT, scope: "openid",
    state: "st", nonce: "n-" + nodeCrypto.randomBytes(6).toString("hex"),
    code_challenge: nodeCrypto.createHash("sha256").update(verifier)
      .digest("base64url"),
    code_challenge_method: "S256" }, PLAIN);
  const code = new URL(got.landed).searchParams.get("code");
  assert.ok(code, "no code: " + got.landed + " " + got.last.status + " " +
            String(got.last.text).slice(0, 300));
  const redeem = function () {
    return token(realm, withClient("occ-one", {
      grant_type: "authorization_code", code: code,
      redirect_uri: REDIRECT, code_verifier: verifier }));
  };
  const first = await redeem();
  assert.strictEqual(first.status, 200, first.text.slice(0, 300));
  const second = await redeem();
  const code2 = second.status === 200 ? "" :
    await lastCode(realm, "/oauth2/token");
  const intro = await call("POST", rb(realm) + "/oauth2/introspect",
    form(withClient("occ-one", { token: first.json.access_token })),
    { "Content-Type": "application/x-www-form-urlencoded" });
  log.debug("Leaving codeTwice().");
  return { first: first, second: second, code: code2,
           active: !!(intro.json && intro.json.active) };
}

async function codeSection() {
  log.debug("Entering codeSection().");
  log.info("=== 2. a code is single use, in every mode ===");
  const plain = await codeTwice(OFF);
  check("2a–b. a code presented twice is refused invalid_grant with RFC " +
        "9700 mode off (STS-OAUTH-0143)", function () {
    assert.strictEqual(plain.second.status, 400,
                       plain.second.text.slice(0, 300));
    assert.strictEqual(plain.second.json.error, "invalid_grant");
    assert.strictEqual(plain.code, "STS-OAUTH-0143");
  });
  check("2c. and the access token the first redemption bought is revoked",
        function () {
    assert.strictEqual(plain.active, false);
  });
  await setting(OFF, "oauth2.codeReplayIdempotent", true);
  const courtesy = await codeTwice(OFF);
  await ok(rb(OFF) + "/admin-api/config/reset",
           { key: "oauth2.codeReplayIdempotent" }, "reset the setting");
  check("2d. oauth2.codeReplayIdempotent restores the old courtesy",
        function () {
    assert.strictEqual(courtesy.second.status, 200,
                       courtesy.second.text.slice(0, 300));
  });
  await setting(BCP, "oauth2.codeReplayIdempotent", true);
  const strict = await codeTwice(BCP);
  check("2e. and RFC 9700 mode ignores it (STS-OAUTH-0143)", function () {
    assert.strictEqual(strict.second.status, 400,
                       strict.second.text.slice(0, 300));
    assert.strictEqual(strict.code, "STS-OAUTH-0143");
  });
  log.debug("Leaving codeSection().");
}

async function fragmentSection() {
  log.debug("Entering fragmentSection().");
  log.info("=== 3. a request_uri fragment is checked while the realm says " +
           "so ===");
  const object = Buffer.from('{"alg":"none"}').toString("base64url") + "." +
    Buffer.from(JSON.stringify({ client_id: "occ-one",
      response_type: "code", redirect_uri: REDIRECT, scope: "openid",
      state: "st", nonce: "n-ro" })).toString("base64url") + ".";
  let hits = 0;
  const server = http.createServer(function (req, res) {
    hits += 1;
    res.writeHead(200, { "content-type": "application/oauth-authz-req+jwt" });
    res.end(object);
  });
  await new Promise(function (resolve) {
    server.listen(Number(process.env.OCC_LISTENER_PORT || 0), "0.0.0.0",
                  resolve);
  });
  try {
    await setting(OFF, "federation.outboundAllowHttp", true);
    const other = nodeCrypto.createHash("sha256").update("random bytes")
      .digest("base64url");
    const at = "http://" + HOST + ":" + server.address().port + "/ro";
    const uri = at + "#" + other;
    // RFC 9101 section 10.4: a request_uri is fetched only when the client
    // registered it (the fragment is no part of the comparison).
    await ok(rb(OFF) + "/admin-api/applications/add", {
      application: "occ-one", attribute: "oauthRequestUri", value: at },
      "registered the request_uri");
    const ask = function () {
      return authorize(OFF, { client_id: "occ-one", response_type: "code",
                              request_uri: uri, scope: "openid" }, PLAIN);
    };
    const refused = await ask();
    check("3a. by default a digest fragment of other content is refused",
          function () {
      assert.ok(hits >= 1, "the request object was never fetched: " +
                refused.landed + " " + String(refused.last.text)
                  .slice(0, 400));
      assert.ok(/SHA-256 of a different/.test(decodeURIComponent(
        refused.landed + " " + refused.last.text)),
                refused.landed + " " + String(refused.last.text)
                  .slice(0, 400));
    });
    await setting(OFF, "oauth2.requestUriFragmentCheck", false);
    const taken = await ask();
    await ok(rb(OFF) + "/admin-api/config/reset",
             { key: "oauth2.requestUriFragmentCheck" }, "reset the setting");
    check("3b. with oauth2.requestUriFragmentCheck off it is only a version " +
          "name: the code is issued", function () {
      assert.ok(new URL(taken.landed).searchParams.get("code"),
                taken.landed + " " + String(taken.last.text).slice(0, 400));
    });
  } finally {
    server.close();
  }
  log.debug("Leaving fragmentSection().");
}

async function responseTypeSection() {
  log.debug("Entering responseTypeSection().");
  log.info("=== 7. a request naming no response_type says so ===");
  const SAYS = "This request names no response_type, and every " +
    "authorization request must name one (RFC 6749 section 3.1.1).";
  const vet = async function (responseType) {
    const q = { client_id: "occ-one", redirect_uri: REDIRECT,
                scope: "openid", state: "s", nonce: "n",
                code_challenge: "x".repeat(43),
                code_challenge_method: "S256" };
    if (responseType !== undefined) {
      q.response_type = responseType;
    }
    const r = await call("GET", rb(OFF) + "/oauth2/authorize?" + form(q));
    // An unknown response type has no response mode of its own, so its
    // error is answered in the FRAGMENT (OAuth 2.0 Multiple Response Types
    // section 5's default for anything but `code`); a missing one in the
    // query.
    const back = !urls.isAt(r.location, REDIRECT) ? new URLSearchParams()
      : (/#/.test(r.location) ? fragmentOf(r.location)
                              : new URL(r.location).searchParams);
    return { error: back.get("error"), description:
               back.get("error_description"),
             code: await lastCode(OFF, "/oauth2/authorize") };
  };
  const missing = await vet(undefined);
  const empty = await vet("");
  const unknown = await vet("banana");
  check("7a. a request with no response_type, or an empty one, is told it " +
        "names none, quoting no \"\" (STS-OAUTH-0162)", function () {
    [missing, empty].forEach(function (r) {
      assert.strictEqual(r.error, "unsupported_response_type",
                         JSON.stringify(r));
      assert.strictEqual(r.description, SAYS);
      assert.strictEqual(r.code, "STS-OAUTH-0162");
    });
  });
  check("7b. one naming a response type this server does not know still " +
        "quotes it (in single quotes, at the endpoint)", function () {
    assert.strictEqual(unknown.error, "unsupported_response_type");
    assert.strictEqual(unknown.description,
                       "response_type 'banana' is not supported.");
    assert.strictEqual(unknown.code, "STS-OAUTH-0162");
  });
  log.debug("Leaving responseTypeSection().");
}

async function registeredListSection() {
  log.debug("Entering registeredListSection().");
  log.info("=== 8. a registered-list refusal names only what was sent ===");
  // Single quotes on the wire: RFC 6749 section 5.2 leaves '"' out of the
  // characters an error_description may carry.
  const SAYS = "RFC 9700 section 2.1: 'https://c.example/cb' is not a " +
    "redirect URI registered for this client, and a redirect_uri must " +
    "match a registered one by exact string comparison (RFC 3986 section " +
    "6.2.1).";
  const discloses = function (text) {
    return /a\.example|b\.example|\bthe 2\b|\b2 (?:redirect|post-logout)/
      .test(String(text));
  };
  const asks = async function (id) {
    const r = await call("GET", rb(BCP) + "/oauth2/authorize?" + form({
      response_type: "code", client_id: id,
      redirect_uri: "https://c.example/cb", scope: "openid", state: "s",
      code_challenge: "x".repeat(43), code_challenge_method: "S256" }),
      undefined, { accept: "application/json" });
    return r;
  };
  const single = await asks("occ-reg-one");
  const plural = await asks("occ-reg-two");
  check("8a. RFC 9700 mode: an unregistered redirect_uri is refused in one " +
        "sentence that names only the address sent, never the registered " +
        "ones or their number, for one address and for two (#1331)",
        function () {
    [single, plural].forEach(function (r) {
      assert.strictEqual(r.status, 400, r.text.slice(0, 300));
      assert.strictEqual(r.json.error_description, SAYS);
      assert.ok(!discloses(r.text), r.text.slice(0, 300));
    });
  });
  const out = await call("GET", rb(BCP) + "/oauth2/logout?" + form({
    client_id: "occ-reg-two",
    post_logout_redirect_uri: "https://c.example/out" }));
  check("8b. an unregistered post_logout_redirect_uri is not followed, and " +
        "the page names no registered address", function () {
    assert.ok(out.status === 200 || out.status === 400,
              out.status + " " + out.location);
    assert.ok(out.location.indexOf("https://c.example/out") !== 0);
    assert.ok(!discloses(out.text), out.text.slice(0, 600));
  });
  log.debug("Leaving registeredListSection().");
}

async function setUp() {
  log.debug("Entering setUp().");
  for (const id of [OFF, ON, BCP]) {
    await ok(base + "/admin-api/realms/create", { id: id,
      domain: id + ".example.net", name: "Conformance rules " + STAMP },
      "created the realm " + id);
    await setting(id, "global.mode", "development");
    // RISK SCORING (#62) is off for sts_admin_client_policies.js's reason.
    await setting(id, "risk.assessSignIns", false);
    await registry.ensurePerson(rb(id), PLAIN, PASSWORD);
  }
  await setting(ON, "keys.eddsaSigning", true);
  await setting(BCP, "oauth2.rfc9700", true);
  await ok(rb(OFF) + "/admin-api/users/create", { username: TYPED,
    invent: false, credential: "password", password: PASSWORD,
    attributes: { cn: "Bob Typed", sn: "Typed", givenName: "Bob",
                  middleName: "Quincy", schacGender: "1",
                  timeZone: "Europe/Stockholm",
                  pictureUrl: "https://bob.example/photo.jpg",
                  profileUrl: "https://bob.example/",
                  mail: TYPED + "@suite.example.test" } },
    "created the typed person");
  await client(OFF, "occ-web");
  await client(OFF, "occ-one");
  await client(OFF, "occ-two");
  await client(BCP, "occ-one");
  await client(BCP, "occ-reg-one", {
    oauthRedirectUri: ["https://a.example/cb"],
    oauthPostLogoutRedirectUri: ["https://a.example/out"] });
  await client(BCP, "occ-reg-two", {
    oauthRedirectUri: ["https://a.example/cb", "https://b.example/cb"],
    oauthPostLogoutRedirectUri: ["https://a.example/out",
                                 "https://b.example/out"] });
  log.debug("Leaving setUp().");
}

async function test() {
  log.debug("Entering test().");
  await setUp();
  await eddsaSection();
  await enterpriseSection();
  await profileSection();
  await refreshSection();
  await codeSection();
  await fragmentSection();
  await responseTypeSection();
  await registeredListSection();
  assert.ok(checks >= FLOOR, "only " + checks + " checks ran; the floor is " +
            FLOOR);
  log.info(checks + " check(s) passed.");
  log.debug("Leaving test().");
}

// REMOVAL IS OPT-IN: with STS_TEST_REMOVE_REALMS=1 (a private probe that
// would otherwise fill its directory) every realm this run made is removed
// at the end, pass or fail. A suite run leaves them standing
// (tests/CLAUDE.md, *No job removes a realm*).
async function removeRealms() {
  log.debug("Entering removeRealms().");
  if (process.env.STS_TEST_REMOVE_REALMS !== "1") {
    log.debug("Leaving removeRealms(). Not asked to.");
    return;
  }
  for (const id of [OFF, ON, BCP]) {
    const r = await call("POST", base + "/admin-api/realms/remove",
                         JSON.stringify({ id: id }),
                         { "Content-Type": "application/json" });
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
