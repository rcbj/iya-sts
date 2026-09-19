"use strict";
//
// File: sts_oauth21.js
//
// ===========================================================================
// OAUTH 2.1 MODE (draft-ietf-oauth-v2-1-16) AT THE REAL ENDPOINTS (2026-09-13).
//
// `tests/oauth21_mode.js` holds every DECISION `oauth-oidc/oauth21.js` makes,
// in process. What is here is the half a request can see — the endpoints
// answering those decisions, in the shape a client meets them: the status, the
// OAuth error code, whether anything was redirected, and a real authorization
// code flow driven by a cookie-jar browser against the real sign-in screen.
//
// Most of it is NEGATIVES, for `sts_dpop.js`'s reason. But the section to read
// first is a POSITIVE one, because it is why this mode is a mode of its own:
// a public client following OAuth 2.1 to the letter — PKCE, and NO redirect_uri
// at the token endpoint — gets a token here, where RFC 9700 mode refuses it.
// The same request is asserted refused in an RFC 9700 realm beside it, so the
// acceptance cannot be a service that has stopped checking.
//
// `local: true`, on `tests/CLAUDE.md`'s third reason: a console control with a
// protocol consequence. The mode is a realm setting written through
// `/admin-api/realms/create`, the clients are declared through
// `/admin-api/applications`, and every assertion is made at `/oauth2/*`.
//
// It works in two throwaway trust realms, which it leaves standing — see *No
// job removes a realm* in `tests/CLAUDE.md`.
// ===========================================================================

const assert = require("assert");
const nodeCrypto = require("crypto");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");
const fixtures = require("./oauth_fixtures.js");
const facts = require("./service_facts.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason tests/vendored/wait_for.js gives.
  appconfigProblem = e;
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_oauth21",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");
var api = base + "/admin-api";

var REALM = usernameFor("oauth21").replace(/[^a-z0-9-]/g, "").slice(0, 30);
var BCP_REALM = usernameFor("o21bcp").replace(/[^a-z0-9-]/g, "").slice(0, 30);
var PREFIX = "/realm/" + REALM;
var BCP_PREFIX = "/realm/" + BCP_REALM;

var REDIRECT = "http://127.0.0.1:9999/oauth21-callback";
var OTHER_REDIRECT = "http://127.0.0.1:9999/oauth21-other";
var PUBLIC = "o21-public";
var CONFIDENTIAL = "o21-confidential";
var TWO_URIS = "o21-two-uris";
var DECLARES_NOTHING = "o21-declares-nothing";
var LOCKED = "o21-locked";
var ASSERTING = "o21-asserting";
var SAML_CLIENT = "o21-saml";
var SECRET = "o21-secret-" + String(Date.now()).slice(-8);
var PERSON = usernameFor("o21person");
var PASSWORD = "o21-Passw0rd!-" + String(Date.now()).slice(-8);

var checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  ✓ " + what);
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
  log.debug("Entering send().");
  const r = await fetch(url, Object.assign({ redirect: "manual" },
                                           options || {}));
  const raw = await r.text();
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in send(): " + ((e && e.message) || e));
    // Not JSON — a page. Quoting it whole says more than a parse failure.
    parsed = raw;
  }
  log.debug("Leaving send().");
  return { status: r.status, body: parsed, raw: raw,
           location: r.headers.get("location") || "",
           retryAfter: r.headers.get("retry-after") || "" };
}

async function ok(url, body, what) {
  log.debug("Entering ok().");
  const r = await send(url, { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}) });
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + JSON.stringify((r.body && (r.body.errors || r.body.why)) || r.body)
      .slice(0, 500));
  log.debug("Leaving ok().");
  return r.body;
}

async function token(prefix, fields, headers) {
  log.debug("Entering token().");
  const r = await send(base + prefix + "/oauth2/token", { method: "POST",
    headers: Object.assign({ "Content-Type":
                             "application/x-www-form-urlencoded" },
                           headers || {}),
    body: typeof fields === "string" ? fields : form(fields) });
  log.debug("Leaving token().");
  return r;
}

function pkce() {
  log.debug("Entering pkce().");
  const verifier = nodeCrypto.randomBytes(32).toString("base64url");
  const challenge = nodeCrypto.createHash("sha256").update(verifier)
    .digest("base64url");
  log.debug("Leaving pkce().");
  return { verifier: verifier, challenge: challenge };
}

// The error_description grammar the mode promises (section 3.2.4).
function asciiDescription(body) {
  log.debug("Entering asciiDescription().");
  log.debug("Leaving asciiDescription().");
  return /^[\x20\x21\x23-\x5B\x5D-\x7E]*$/.test(
    String((body && body.error_description) || ""));
}

// One browser, manual redirects and a cookie jar of its own, for
// `sts_consent.js`'s reason: which redirect comes back IS the assertion.
function browser() {
  log.debug("Entering browser().");
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
        if (at > 0) {
          jar[pair.slice(0, at)] = pair.slice(at + 1);
        }
      });
      const text = await r.text();
      log.debug("Leaving go(). status=" + r.status);
      return { status: r.status, location: r.headers.get("location") || "",
               text: text };
    }
  };
  log.debug("Leaving browser().");
  return self;
}

// Sign in at the realm's sign-in screen and follow the authorization request
// to whatever it answers afterwards. Returns that answer.
async function authorizeSignedIn(prefix, query) {
  log.debug("Entering authorizeSignedIn().");
  const b = browser();
  let r = await b.go("GET", prefix + "/oauth2/authorize?" + form(query));
  assert.ok(/\/authn\/login\?authn=/.test(r.location),
    "an unauthenticated authorization request should go to the sign-in " +
    "screen; it answered " + r.status + " " + r.location + " " +
    r.text.slice(0, 300));
  r = await b.go("GET", r.location);
  const authnId = (r.text.match(/name="authn_id" value="([^"]+)"/) || [])[1];
  assert.ok(authnId, "the sign-in screen carries no authn_id to post back.");
  r = await b.go("POST", prefix + "/authn/login",
                 form({ authn_id: authnId, username: PERSON,
                        password: PASSWORD, action: "login" }));
  assert.ok(r.status === 303 || r.status === 302,
    "the sign-in form should redirect, got " + r.status);
  r = await b.go("GET", r.location);
  log.debug("Leaving authorizeSignedIn(). " + r.status + " " + r.location);
  return r;
}

function codeFrom(location) {
  log.debug("Entering codeFrom().");
  const url = new URL(location);
  log.debug("Leaving codeFrom().");
  return { code: url.searchParams.get("code"),
           error: url.searchParams.get("error"),
           description: url.searchParams.get("error_description"),
           iss: url.searchParams.get("iss"),
           origin: url.origin + url.pathname };
}

async function setUp() {
  log.debug("Entering setUp().");
  log.info("=== 0. two realms, the clients, a person ===");
  await ok(api + "/realms/create", { id: REALM, name: "OAuth 2.1 mode",
    overrides: { "oauth2.oauth21": true, "oauth2.consentRequired": false,
                 "security.rateLimitPerIdentity": 3 } },
    "created the OAuth 2.1 realm");
  await ok(api + "/realms/create", { id: BCP_REALM, name: "RFC 9700 mode",
    overrides: { "oauth2.rfc9700": true, "oauth2.consentRequired": false } },
    "created the RFC 9700 realm beside it");
  const clients = [
    [PUBLIC, { oauthRedirectUri: [REDIRECT],
               oauthTokenEndpointAuthMethod: "none" }],
    [CONFIDENTIAL, { oauthRedirectUri: [REDIRECT], oauthClientSecret: SECRET,
                     oauthTokenEndpointAuthMethod: "client_secret_post" }],
    [TWO_URIS, { oauthRedirectUri: [REDIRECT, OTHER_REDIRECT],
                 oauthTokenEndpointAuthMethod: "none" }],
    [LOCKED, { oauthClientSecret: SECRET,
               oauthTokenEndpointAuthMethod: "client_secret_post" }],
    [ASSERTING, { oauthClientSecret: SECRET,
                  oauthTokenEndpointAuthMethod: "client_secret_jwt" }],
    [SAML_CLIENT, { oauthTokenEndpointAuthMethod: "saml2_bearer" }]
  ];
  for (const prefix of [PREFIX, BCP_PREFIX]) {
    for (const pair of clients) {
      await ok(base + prefix + "/admin-api/applications/create",
               { identifier: pair[0], protocols: ["oauth2", "oidc"],
                 fields: Object.assign({ oauthClientId: pair[0] }, pair[1]) },
               "created " + pair[0] + " in " + prefix);
    }
    await ok(base + prefix + "/admin-api/users/create",
             { username: PERSON, invent: false, credential: "password",
               password: PASSWORD,
               attributes: { cn: "OAuth 2.1 Person", sn: PERSON,
                             mail: PERSON + "@oauth21.test" } },
             "created the person who signs in, in " + prefix);
  }
  // DECLARES NOTHING: an entry with a client_id and no protocol family, no
  // redirect URI, no method and no credential — what a sighting leaves.
  await ok(base + PREFIX + "/admin-api/applications/create",
           { identifier: DECLARES_NOTHING, protocols: [],
             fields: { oauthClientId: DECLARES_NOTHING } },
           "created an entry that declares nothing");
  log.debug("Leaving setUp().");
}

async function theReports() {
  log.debug("Entering theReports().");
  log.info("=== 1. the reports and the metadata ===");
  const report = await send(base + PREFIX + "/oauth2/oauth21");
  check("GET /oauth2/oauth21 reports the mode on in the realm, naming the " +
        "draft", function () {
          assert.strictEqual(report.status, 200);
          assert.strictEqual(report.body.enabled, true);
          assert.strictEqual(report.body.draft, "draft-ietf-oauth-v2-1-16");
        });
  const bcp = await send(base + PREFIX + "/oauth2/rfc9700");
  check("and /oauth2/rfc9700 says RFC 9700 mode is on BECAUSE of it",
        function () {
          assert.strictEqual(bcp.body.enabled, true);
          assert.strictEqual(bcp.body.enabled_by, "oauth2.oauth21");
        });
  const outside = await send(base + "/oauth2/oauth21");
  check("the default realm is not in the mode", function () {
    assert.strictEqual(outside.body.enabled, false);
  });
  const metadata = await send(base + PREFIX +
                              "/.well-known/oauth-authorization-server");
  check("the realm's metadata stops advertising saml2_bearer client " +
        "authentication", function () {
          assert.strictEqual(metadata.status, 200);
          const methods = metadata.body.token_endpoint_auth_methods_supported;
          assert.ok(Array.isArray(methods) && methods.length);
          assert.strictEqual(methods.indexOf("saml2_bearer"), -1,
                             JSON.stringify(methods));
        });
  log.debug("Leaving theReports().");
  return metadata.body.issuer;
}

async function theAuthorizationEndpoint() {
  log.debug("Entering theAuthorizationEndpoint().");
  log.info("=== 2. the authorization endpoint ===");
  const p = pkce();
  const unregistered = await send(base + PREFIX + "/oauth2/authorize?" + form({
    response_type: "code", client_id: "o21-never-" + REALM,
    redirect_uri: REDIRECT, code_challenge: p.challenge,
    code_challenge_method: "S256" }));
  check("A CLIENT WITH NO REDIRECT URI OF ITS OWN IS REFUSED ON THIS " +
        "SERVER — " +
        "400, nothing redirected", function () {
          assert.strictEqual(unregistered.status, 400,
                             unregistered.raw.slice(0, 300));
          assert.strictEqual(unregistered.location, "");
          assert.strictEqual(unregistered.body.error, "invalid_request");
          assert.ok(/2\.3\.1/.test(unregistered.body.error_description),
                    unregistered.body.error_description);
          assert.ok(asciiDescription(unregistered.body),
                    "the error_description is within section 3.2.4's " +
                    "grammar: " + unregistered.body.error_description);
        });
  const ambiguous = await send(base + PREFIX + "/oauth2/authorize?" + form({
    response_type: "code", client_id: TWO_URIS, code_challenge: p.challenge,
    code_challenge_method: "S256" }));
  check("no redirect_uri from a client with TWO registered is refused",
        function () {
          assert.strictEqual(ambiguous.status, 400,
                             ambiguous.raw.slice(0, 300));
          assert.strictEqual(ambiguous.location, "");
        });
  const repeated = await send(base + PREFIX + "/oauth2/authorize?" +
    form({ response_type: "code", client_id: PUBLIC, redirect_uri: REDIRECT,
           code_challenge: p.challenge, code_challenge_method: "S256" }) +
    "&state=a&state=b");
  check("a repeated authorization parameter is refused", function () {
    assert.strictEqual(repeated.status, 400, repeated.raw.slice(0, 300));
    assert.ok(/state/.test(repeated.body.error_description || ""),
              repeated.body.error_description);
  });
  log.debug("Leaving theAuthorizationEndpoint().");
}

async function theCodeFlowWithoutRedirectUri(issuer) {
  log.debug("Entering theCodeFlowWithoutRedirectUri().");
  log.info("=== 3. OAuth 2.1's code flow: no redirect_uri, twice ===");
  const p = pkce();
  const answered = await authorizeSignedIn(PREFIX, {
    response_type: "code", client_id: PUBLIC, scope: "openid",
    nonce: "n-" + REALM, state: "s", code_challenge: p.challenge,
    code_challenge_method: "S256" });
  const got = codeFrom(answered.location);
  check("AN AUTHORIZATION REQUEST WITH NO redirect_uri IS ANSWERED AT " +
        "THE ONE " +
        "THE CLIENT REGISTERED, with the iss", function () {
          assert.strictEqual(got.origin, REDIRECT, answered.location);
          assert.ok(got.code, answered.location);
          assert.strictEqual(got.iss, issuer);
        });
  const redeemed = await token(PREFIX, { grant_type: "authorization_code",
    code: got.code, code_verifier: p.verifier, client_id: PUBLIC });
  check("AND THE TOKEN REQUEST WITH NO redirect_uri GETS A TOKEN — section " +
        "10.2, the row that makes this a mode of its own", function () {
          assert.strictEqual(redeemed.status, 200, redeemed.raw.slice(0, 400));
          assert.ok(redeemed.body.access_token);
        });

  const q = pkce();
  const bcpAnswered = await authorizeSignedIn(BCP_PREFIX, {
    response_type: "code", client_id: PUBLIC, redirect_uri: REDIRECT,
    scope: "openid", nonce: "n-" + BCP_REALM, code_challenge: q.challenge,
    code_challenge_method: "S256" });
  const bcpCode = codeFrom(bcpAnswered.location);
  const bcpRefused = await token(BCP_PREFIX, { grant_type:
    "authorization_code", code: bcpCode.code, code_verifier: q.verifier,
    client_id: PUBLIC });
  check("the SAME token request in an RFC 9700 realm is refused — so the " +
        "acceptance above is the mode and not a service that stopped checking",
        function () {
          assert.strictEqual(bcpRefused.status, 400,
                             bcpRefused.raw.slice(0, 300));
          assert.strictEqual(bcpRefused.body.error, "invalid_grant");
        });

  const r = pkce();
  const again = await authorizeSignedIn(PREFIX, {
    response_type: "code", client_id: PUBLIC, redirect_uri: REDIRECT,
    scope: "openid", nonce: "n2-" + REALM, code_challenge: r.challenge,
    code_challenge_method: "S256" });
  const mismatch = await token(PREFIX, { grant_type: "authorization_code",
    code: codeFrom(again.location).code, code_verifier: r.verifier,
    client_id: PUBLIC, redirect_uri: OTHER_REDIRECT });
  check("a redirect_uri that IS sent must still be identical", function () {
    assert.strictEqual(mismatch.status, 400, mismatch.raw.slice(0, 300));
    assert.strictEqual(mismatch.body.error, "invalid_grant");
  });
  log.debug("Leaving theCodeFlowWithoutRedirectUri().");
}

async function pkceForEveryClient() {
  log.debug("Entering pkceForEveryClient().");
  log.info("=== 4. PKCE for confidential clients, and the nonce exemption ===");
  // BEFORE ANYBODY SIGNS IN, and so answered as a page rather than redirected:
  // RFC 9700 section 4.11.2, which this mode inherits, will not bounce an error
  // to a client's registered redirect_uri for a browser nobody has
  // authenticated. The refusal is the same one either way; the page is what
  // carries it here.
  const refused = await send(base + PREFIX + "/oauth2/authorize?" + form({
    response_type: "code", client_id: CONFIDENTIAL, redirect_uri: REDIRECT,
    scope: "openid" }));
  check("a CONFIDENTIAL client with no PKCE and no nonce is refused " +
        "(section 7.5.1.1) — RFC 9700 mode only logs it", function () {
          assert.strictEqual(refused.location, "", "nothing is redirected");
          assert.ok(/7\.5\.1\.1/.test(refused.raw), refused.raw.slice(0, 400));
          assert.ok(/invalid_request/.test(refused.raw));
        });
  const noMethod = await send(base + PREFIX + "/oauth2/authorize?" + form({
    response_type: "code", client_id: PUBLIC, redirect_uri: REDIRECT,
    code_challenge: pkce().challenge }));
  check("a code_challenge with no code_challenge_method is refused as " +
        "missing the method", function () {
          assert.strictEqual(noMethod.location, "");
          assert.ok(/code_challenge_method is REQUIRED/.test(noMethod.raw),
                    noMethod.raw.slice(0, 400));
        });
  const exempt = await authorizeSignedIn(PREFIX, {
    response_type: "code", client_id: CONFIDENTIAL, redirect_uri: REDIRECT,
    scope: "openid", nonce: "exempt-" + REALM });
  const exemptCode = codeFrom(exempt.location).code;
  check("the exemption — confidential, a secret on file, openid and a nonce " +
        "— issues a code without PKCE", function () {
          assert.ok(exemptCode, exempt.location);
        });
  const unauthenticated = await token(PREFIX, { grant_type:
    "authorization_code", code: exemptCode, redirect_uri: REDIRECT,
    client_id: CONFIDENTIAL });
  check("which the client cannot redeem without authenticating", function () {
    assert.ok(unauthenticated.status === 400 || unauthenticated.status === 401,
              unauthenticated.raw.slice(0, 300));
  });
  const exempt2 = await authorizeSignedIn(PREFIX, {
    response_type: "code", client_id: CONFIDENTIAL, redirect_uri: REDIRECT,
    scope: "openid", nonce: "exempt2-" + REALM });
  const withoutRedirect = await token(PREFIX, { grant_type:
    "authorization_code", code: codeFrom(exempt2.location).code,
    client_id: CONFIDENTIAL, client_secret: SECRET });
  check("NOR WITHOUT redirect_uri: a code with no PKCE keeps RFC 6749's " +
        "binding", function () {
          assert.strictEqual(withoutRedirect.status, 400,
                             withoutRedirect.raw.slice(0, 300));
          assert.strictEqual(withoutRedirect.body.error, "invalid_grant");
        });
  const exempt3 = await authorizeSignedIn(PREFIX, {
    response_type: "code", client_id: CONFIDENTIAL, redirect_uri: REDIRECT,
    scope: "openid", nonce: "exempt3-" + REALM });
  const redeemed = await token(PREFIX, { grant_type: "authorization_code",
    code: codeFrom(exempt3.location).code, redirect_uri: REDIRECT,
    client_id: CONFIDENTIAL, client_secret: SECRET });
  check("and with both, it is redeemed", function () {
    assert.strictEqual(redeemed.status, 200, redeemed.raw.slice(0, 300));
    assert.ok(redeemed.body.id_token);
  });
  log.debug("Leaving pkceForEveryClient().");
}

async function theTokenEndpointsClients(issuer) {
  log.debug("Entering theTokenEndpointsClients().");
  log.info("=== 5. the client at the token endpoint ===");
  const nothing = await token(PREFIX, { grant_type: "client_credentials",
    client_id: DECLARES_NOTHING });
  check("a token request naming a client that declares nothing is refused " +
        "invalid_client", function () {
          assert.strictEqual(nothing.status, 401, nothing.raw.slice(0, 300));
          assert.strictEqual(nothing.body.error, "invalid_client");
        });
  // THE SAME REFUSAL ON A GRANT NO OTHER RULE REFUSES FIRST. For
  // client_credentials above, section 4.2's "authenticate the client" would
  // refuse this client too, so that request cannot show WHICH rule answered —
  // a refresh token is refused invalid_grant (400) once the client is past the
  // declaration check, and invalid_client (401) only by it.
  const nothingRefresh = await token(PREFIX, { grant_type: "refresh_token",
    client_id: DECLARES_NOTHING, refresh_token: "not-a-refresh-token" });
  check("and a refresh naming that client is refused AS A CLIENT, before the " +
        "refresh token is looked at", function () {
          assert.strictEqual(nothingRefresh.status, 401,
                             nothingRefresh.raw.slice(0, 300));
          assert.strictEqual(nothingRefresh.body.error, "invalid_client");
        });
  const publicCc = await token(PREFIX, { grant_type: "client_credentials",
    client_id: PUBLIC });
  check("the client credentials grant from a public client is refused " +
        "(section 4.2)", function () {
          assert.strictEqual(publicCc.status, 401, publicCc.raw.slice(0, 300));
          assert.strictEqual(publicCc.body.error, "invalid_client");
        });
  const publicSecret = await token(PREFIX, { grant_type:
    "client_credentials", client_id: PUBLIC, client_secret: "anything" });
  check("a secret presented by a public client, which nothing can verify, " +
        "is refused rather than ignored (section 3.2.2)", function () {
          assert.strictEqual(publicSecret.status, 401,
                             publicSecret.raw.slice(0, 300));
        });
  const two = await token(PREFIX, { grant_type: "client_credentials",
      client_id: CONFIDENTIAL, client_secret: SECRET },
    { Authorization: "Basic " + Buffer.from(CONFIDENTIAL + ":" + SECRET)
                                      .toString("base64") });
  check("two client authentication methods in one request are refused " +
        "(section 2.4)", function () {
          assert.strictEqual(two.status, 400, two.raw.slice(0, 300));
          assert.strictEqual(two.body.error, "invalid_request");
        });
  const repeated = await token(PREFIX, "grant_type=client_credentials" +
    "&grant_type=client_credentials&client_id=" + CONFIDENTIAL +
    "&client_secret=" + encodeURIComponent(SECRET));
  check("a repeated token request parameter is refused", function () {
    assert.strictEqual(repeated.status, 400, repeated.raw.slice(0, 300));
    assert.ok(/grant_type/.test(repeated.body.error_description || ""));
  });
  const good = await token(PREFIX, { grant_type: "client_credentials",
    client_id: CONFIDENTIAL, client_secret: SECRET });
  check("and one authentication method from a declared confidential client " +
        "gets a token", function () {
          assert.strictEqual(good.status, 200, good.raw.slice(0, 300));
        });
  const saml = await token(PREFIX, { grant_type: "client_credentials",
    client_id: SAML_CLIENT });
  // TWO REFUSALS CAN ANSWER THIS AND EITHER IS RIGHT. The mode drops
  // saml2_bearer from the realm's metadata, and the token endpoint refuses a
  // method its own metadata does not advertise (400) before the mode's own
  // refusal is reached (401) — the document IS the server. What must hold is
  // that the client is refused, as a client.
  check("SAML bearer client authentication is refused invalid_client — by " +
        "the metadata that no longer advertises it", function () {
          assert.ok(saml.status === 400 || saml.status === 401,
                    saml.raw.slice(0, 300));
          assert.strictEqual(saml.body.error, "invalid_client");
          assert.ok(/saml2_bearer|SAML/.test(saml.body.error_description ||
                                             ""),
                    saml.body.error_description);
        });

  const now = Math.floor(Date.now() / 1000);
  const assertionFor = function (aud) {
    const b64u = function (v) {
      return Buffer.from(JSON.stringify(v)).toString("base64url");
    };
    const signing = b64u({ alg: "HS256", typ: "JWT" }) + "." + b64u({
      iss: ASSERTING, sub: ASSERTING, aud: aud, iat: now, exp: now + 60,
      jti: nodeCrypto.randomUUID() });
    return signing + "." + nodeCrypto.createHmac("sha256", SECRET)
      .update(signing).digest("base64url");
  };
  const toEndpoint = await token(PREFIX, { grant_type: "client_credentials",
    client_id: ASSERTING, client_assertion_type:
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    client_assertion: assertionFor(base + PREFIX + "/oauth2/token") });
  check("A CLIENT ASSERTION ADDRESSED TO THE TOKEN ENDPOINT URL IS REFUSED — " +
        "rfc7523bis requires the issuer as the sole audience", function () {
          assert.strictEqual(toEndpoint.status, 401,
                             toEndpoint.raw.slice(0, 300));
          assert.ok(/SOLE audience/.test(toEndpoint.body.error_description ||
                                         ""),
                    toEndpoint.body.error_description);
        });
  const toIssuer = await token(PREFIX, { grant_type: "client_credentials",
    client_id: ASSERTING, client_assertion_type:
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    client_assertion: assertionFor(issuer) });
  check("and one addressed to the issuer alone is accepted", function () {
    assert.strictEqual(toIssuer.status, 200, toIssuer.raw.slice(0, 300));
  });
  log.debug("Leaving theTokenEndpointsClients().");
}

// ---------------------------------------------------------------------------
// #34 (2026-09-15). Section 4.3.1's rotation is bookkeeping about a chain
// belonging to a CLIENT, so this mode refuses a grant a client makes in its
// own name with no client_id at all — which, before this, skipped the
// registered-client check entirely and was rotated as if it belonged to
// somebody.
//
// The control is the refusal in the OTHER realm: the same request there is
// refused for the token being nonsense, which is a different answer and proves
// this one is the mode and not the token.
// ---------------------------------------------------------------------------
async function theUnnamedClient() {
  log.debug("Entering theUnnamedClient().");
  log.info("=== 7. a grant made in no client's name ===");
  const unnamed = await token(PREFIX, { grant_type: "refresh_token",
    refresh_token: "not-a-refresh-token" });
  check("A REFRESH REQUEST NAMING NO CLIENT IS REFUSED invalid_client in " +
        "OAuth 2.1 mode, before the token is looked at", function () {
          assert.strictEqual(unnamed.status, 401, unnamed.raw.slice(0, 300));
          assert.strictEqual(unnamed.body && unnamed.body.error,
                             "invalid_client", unnamed.raw.slice(0, 300));
        });
  check("and the refusal names no error code — those are recorded, never sent",
        function () {
          assert.ok(unnamed.raw.indexOf("STS-OAUTH-") < 0,
                    unnamed.raw.slice(0, 300));
        });
  // A PRODUCT-mode default realm also refuses a grant naming no client, so
  // there the control names a public client of its own: the one request that
  // realm answers by looking at the token.
  const outsideFields = { grant_type: "refresh_token",
    refresh_token: "not-a-refresh-token" };
  if (await facts.isProduct(base + "/admin-api")) {
    const control = "oauth21-control-" + usernameFor("c");
    await fixtures.publicClient(base + "/admin-api", control,
                                ["https://example.test/oauth21-control"],
                                { oauthGrantType: ["authorization_code",
                                                   "refresh_token"] });
    outsideFields.client_id = control;
  }
  const outside = await token("", outsideFields);
  check("while the default realm refuses the same request for the TOKEN " +
        "instead — invalid_grant, which is the control on the check above",
        function () {
          assert.strictEqual(outside.status, 400, outside.raw.slice(0, 300));
          assert.strictEqual(outside.body && outside.body.error,
                             "invalid_grant", outside.raw.slice(0, 300));
        });
  log.debug("Leaving theUnnamedClient().");
}

async function theSecretLimit() {
  log.debug("Entering theSecretLimit().");
  log.info("=== 6. a client secret that keeps failing ===");
  const answers = [];
  for (let i = 0; i < 4; i++) {
    answers.push(await token(PREFIX, { grant_type: "client_credentials",
      client_id: LOCKED, client_secret: "wrong-" + i }));
  }
  check("three wrong secrets are refused invalid_client", function () {
    answers.slice(0, 3).forEach(function (r) {
      assert.strictEqual(r.status, 401, r.raw.slice(0, 300));
    });
  });
  check("and the fourth is answered 429 with Retry-After before the secret " +
        "is looked at", function () {
          assert.strictEqual(answers[3].status, 429, answers[3].raw.slice(0,
                                                                          300));
          assert.ok(Number(answers[3].retryAfter) > 0, answers[3].retryAfter);
        });
  const right = await token(PREFIX, { grant_type: "client_credentials",
    client_id: LOCKED, client_secret: SECRET });
  check("the right secret is refused too while the lock holds — a lock a " +
        "correct guess opened would be no lock", function () {
          assert.strictEqual(right.status, 429, right.raw.slice(0, 300));
        });
  const other = await token(PREFIX, { grant_type: "client_credentials",
    client_id: CONFIDENTIAL, client_secret: SECRET });
  check("and another client from the same address is unaffected", function () {
    assert.strictEqual(other.status, 200, other.raw.slice(0, 300));
  });
  log.debug("Leaving theSecretLimit().");
}

async function registration() {
  log.debug("Entering registration().");
  log.info("=== 7. registration mirrors the endpoints ===");
  // A PRODUCT-mode realm keeps registration closed to anybody without a
  // trusted software statement, so both registrations carry one this realm
  // signs for a publisher registered through the management API — the door
  // that is open in every mode. What is refused below is the metadata.
  const json = { "Content-Type": "application/json" };
  const publisher = "oauth21-publisher";
  await send(base + PREFIX + "/admin-api/applications/create", {
    method: "POST", headers: json,
    body: JSON.stringify({ identifier: publisher, name: publisher,
                           protocols: ["oauth2"],
                           fields: { oauthClientId: publisher } }) });
  const issued = await send(base + PREFIX +
      "/admin-api/applications/issue-software-statement", {
    method: "POST", headers: json,
    body: JSON.stringify({ application: publisher, metadata: "{}" }) });
  const statement = issued.body && issued.body.softwareStatement;
  assert.ok(statement, "the realm would not issue a software statement: " +
            issued.raw.slice(0, 300));
  const saml = await send(base + PREFIX + "/oauth2/register", { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ software_statement: statement,
                           redirect_uris: [REDIRECT],
                           token_endpoint_auth_method: "saml2_bearer" }) });
  check("a registration asking for saml2_bearer client authentication is " +
        "refused", function () {
          assert.strictEqual(saml.status, 400, saml.raw.slice(0, 300));
          assert.strictEqual(saml.body.error, "invalid_client_metadata");
        });
  const publicCc = await send(base + PREFIX + "/oauth2/register", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ software_statement: statement,
                           grant_types: ["client_credentials"],
                           token_endpoint_auth_method: "none" }) });
  check("and one asking for client_credentials as a public client",
        function () {
          assert.strictEqual(publicCc.status, 400, publicCc.raw.slice(0, 300));
        });
  log.debug("Leaving registration().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving " + base + " in the realms \"" + REALM + "\" and \"" +
           BCP_REALM + "\".");
  await setUp();
  const issuer = await theReports();
  await theAuthorizationEndpoint();
  await theCodeFlowWithoutRedirectUri(issuer);
  await pkceForEveryClient();
  await theTokenEndpointsClients(issuer);
  await theUnnamedClient();
  await theSecretLimit();
  await registration();
  assert.ok(checks >= 30,
    "only " + checks + " checks ran; a section has stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_oauth21")
  .description("OAuth 2.1 mode (draft-ietf-oauth-v2-1-16) at the real " +
      "endpoints: a public client with PKCE and no redirect_uri getting a " +
      "token where RFC 9700 mode refuses it, the redirect_uri default, an " +
      "unregistered client refused on this server, PKCE for confidential " +
      "clients and the nonce exemption, the token endpoint's client " +
      "refusals, the sole-issuer client assertion audience, the client " +
      "secret rate limit, the grant made in no client's name, and " +
      "registration's mirrors.")
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
