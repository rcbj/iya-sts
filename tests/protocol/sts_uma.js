// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_uma.js
//
// ---------------------------------------------------------------------------
// USER-MANAGED ACCESS 2.0 OVER HTTP (#1168 phase 7, #1196), in whichever mode
// the service is in, in a throwaway trust realm.
//
// THIS JOB IS BOTH THE RESOURCE SERVER AND THE CLIENT. The ticket asked for
// Keycloak as the independent peer (rcbj's decision 8); Keycloak's
// authorization services are themselves a UMA authorization server, and its
// UMA client library dials Keycloak-shaped addresses built from a realm name,
// so it cannot be pointed at this service as it stands. That is put to rcbj
// on #1196; until it is answered this job drives both sides over the wire.
//
//   1. SETUP: a realm with uma.enabled; an owner, a requesting party and a
//      stranger; a resource server made one through POST
//      /admin-api/uma/enable-resource-server, allowed to own resources; a
//      client registering the uma-ticket grant and a claims redirect URI; a
//      second client and a second resource server.
//   2. DISCOVERY: every URL of /.well-known/uma2-configuration is a
//      registered route; the token endpoint advertises the uma-ticket grant.
//   3. THE PAT, BOTH GRANTS: client_credentials as the application itself,
//      and the authorization code flow as the owner; a resource registered
//      with each; none without a PAT.
//   4. THE PERMISSION TICKET, need_info, THE CLAIMS INTERACTION: an unknown
//      requesting party is need_info with a rotated ticket and
//      redirect_user; the party signs in at the claims interaction
//      endpoint and comes back claims_submitted with a new ticket; nothing
//      is shared, so request_denied.
//   5. A SHARE ON THE PORTAL, THE RPT, INTROSPECTION: the owner shares view;
//      the RPT carries it, a PCT comes with it; the resource server's PAT
//      introspects it with its permissions; another resource server sees it
//      inactive.
//   6. request_submitted, THE PORTAL'S APPROVAL, UPGRADE: a share that asks
//      the owner each time; the client told request_submitted; the owner
//      approves on the portal; the next try, with the PCT and the old RPT,
//      is granted both scopes and the old RPT is inactive.
//   7. REVOCATION ON THE PORTAL: removing the share ends the RPT.
//   8. AN APPLICATION AS OWNER (decision 5): its document shared through
//      POST /admin-api/uma/owner-share; the party's RPT over its resource.
//   9. NEGATIVES: a ticket presented by a second client, a spent ticket, a
//      scope the ticket does not carry, a stranger.
//  10. THE CONSOLE'S OPERATIONS: GET /admin-api/uma and its monitor.
//  11. uma.enabled OFF: the grant is no longer advertised or performed.
//
// The in-process halves are tests/uma_*.js. The realm is left behind
// (tests/CLAUDE.md, *No job removes a realm*).
//
// OWNED HERE (local: true): UMA exists in this repository and nowhere else.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const authnSignin = require("./authn_signin");
const consentScreen = require("./consent_screen.js");
const portalSignin = require("./portal_signin.js");

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
var log = bunyan.createLogger({ name: "sts_uma",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");

const STAMP = names.runStamp().toLowerCase().replace(/[^a-z0-9-]/g, "");
const REALM = ("uma-" + STAMP).slice(0, 40);
const PREFIX = "/realm/" + REALM;
const REALM_BASE = base + PREFIX;
const GRANT = "urn:ietf:params:oauth:grant-type:uma-ticket";
const PROTECTION = "urn:sts:uma-protection-api:uma_protection";
const OWNER = "uma-owner";
const PARTY = "uma-party";
const STRANGER = "uma-stranger";
const PASSWORD = "Uma-" + STAMP + "-9a!";
const RS = "uma-rs-" + STAMP;
const RS2 = "uma-rs2-" + STAMP;
const CLIENT = "uma-client-" + STAMP;
const CLIENT2 = "uma-client2-" + STAMP;
const RS_REDIRECT = "https://" + RS + ".example.com/callback";
const CLAIMS_REDIRECT = "https://" + CLIENT + ".example.com/claims";
const SECRETS = {};
const DESKTOP_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) " +
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const AGENT = { "User-Agent": DESKTOP_USER_AGENT };

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

async function fetchJson(url, options) {
  log.debug("Entering fetchJson(). url=" + url);
  const r = await fetch(url, Object.assign({ redirect: "manual" },
                                           options || {}));
  const text = await r.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in fetchJson(): " + ((e && e.message) || e));
    // Not JSON; the caller reports the status and the text.
    body = null;
  }
  log.debug("Leaving fetchJson(). status=" + r.status);
  return { status: r.status, body: body, text: text, headers: r.headers };
}

function api(path) {
  log.debug("Entering api().");
  log.debug("Leaving api().");
  return REALM_BASE + "/admin-api" + path;
}

async function must(path, payload, what) {
  log.debug("Entering must(). " + path);
  const r = await fetchJson(api(path), { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload) });
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST " + PREFIX + "/admin-api" + path + " should have " + what +
    "; it answered " + r.status + " " + String(r.text).slice(0, 400));
  log.debug("Leaving must().");
  return r.body;
}

async function mustRead(path, what) {
  log.debug("Entering mustRead(). " + path);
  const r = await fetchJson(api(path));
  assert.ok(r.status === 200 && r.body,
    "GET " + PREFIX + "/admin-api" + path + " (" + what + ") answered " +
    r.status + " " + String(r.text).slice(0, 300));
  log.debug("Leaving mustRead().");
  return r.body;
}

function basic(id) {
  log.debug("Entering basic().");
  log.debug("Leaving basic().");
  return "Basic " + Buffer.from(encodeURIComponent(id) + ":" +
    encodeURIComponent(SECRETS[id])).toString("base64");
}

async function token(id, fields) {
  log.debug("Entering token(). " + id);
  const form = new URLSearchParams();
  Object.keys(fields).forEach(function (k) {
    if (fields[k] !== undefined && fields[k] !== null) {
      form.set(k, String(fields[k]));
    }
  });
  const r = await fetchJson(REALM_BASE + "/oauth2/token", { method: "POST",
    headers: Object.assign({ "Content-Type":
      "application/x-www-form-urlencoded", Authorization: basic(id) }, AGENT),
    body: form.toString() });
  log.debug("Leaving token(). " + r.status);
  return r;
}

async function withPat(pat, method, path, payload) {
  log.debug("Entering withPat(). " + method + " " + path);
  const headers = { Authorization: "Bearer " + pat };
  if (payload !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  const r = await fetchJson(REALM_BASE + path, { method: method,
    headers: headers,
    body: payload === undefined ? undefined : JSON.stringify(payload) });
  log.debug("Leaving withPat(). " + r.status);
  return r;
}

async function introspect(pat, value) {
  log.debug("Entering introspect().");
  const r = await fetchJson(REALM_BASE + "/oauth2/introspect", {
    method: "POST", headers: { Authorization: "Bearer " + pat,
      "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ token: value }).toString() });
  log.debug("Leaving introspect(). " + r.status);
  return r;
}

function brief(r) {
  log.debug("Entering brief().");
  log.debug("Leaving brief().");
  return r.status + " " + String(r.text || "").slice(0, 400);
}

// A browser's walk through the one sign-in screen: from a URL that sends
// a person there, signed in as `who`, to wherever the service sends them
// last (a consent screen settled on the way). Answers the last location.
async function signInThrough(startUrl, who) {
  log.debug("Entering signInThrough(). " + who);
  const first = await fetch(startUrl, { redirect: "manual", headers: AGENT });
  const screenAt = first.headers.get("location") || "";
  assert.ok(/\/authn\/login\?authn=/.test(screenAt), "the request should " +
    "reach the sign-in screen; it answered " + first.status + " " + screenAt +
    " " + String(await first.text()).slice(0, 300));
  const screenUrl = new URL(screenAt, base);
  const signedIn = await authnSignin.submit(screenUrl.origin +
    screenUrl.pathname.replace(/\/authn\/login$/, ""), screenUrl.toString(),
    { action: "login", username: who, password: PASSWORD },
    { headers: AGENT });
  if (signedIn.next !== "redirect" || !signedIn.cookie ||
      !signedIn.location) {
    assert.fail("signing " + who + " in should redirect with a session; " +
      "the screen answered " + signedIn.status + " " + signedIn.next + ": " +
      JSON.stringify(signedIn.errors));
  }
  const back = await fetch(new URL(signedIn.location, base).toString(),
    { redirect: "manual",
      headers: Object.assign({ Cookie: signedIn.cookie }, AGENT) });
  const after = back.headers.get("location") || "";
  const settled = await consentScreen.settleAuthorization({
    base: base, location: after, cookie: signedIn.cookie, headers: AGENT });
  log.debug("Leaving signInThrough().");
  return settled.location || after;
}

function queryOf(location) {
  log.debug("Entering queryOf().");
  log.debug("Leaving queryOf().");
  return location.indexOf("?") >= 0
    ? new URLSearchParams(location.split("?")[1].split("#")[0])
    : new URLSearchParams();
}

// THE PERSON'S PORTAL, one per person, kept.
const portals = {};
async function portalOf(who) {
  log.debug("Entering portalOf().");
  if (!portals[who]) {
    portals[who] = await portalSignin.signInToThePortal(REALM_BASE, who,
      null, { password: PASSWORD });
  }
  log.debug("Leaving portalOf().");
  return portals[who];
}

async function sharedView(who) {
  log.debug("Entering sharedView().");
  const r = await (await portalOf(who)).api("GET", "/account-api/shared");
  assert.strictEqual(r.status, 200, "the owner's /account-api/shared: " +
    r.status + " " + JSON.stringify(r.json).slice(0, 300));
  log.debug("Leaving sharedView().");
  return (r.json && r.json.view) || r.json || {};
}

async function onPortal(who, fields, what) {
  log.debug("Entering onPortal(). " + fields.action);
  const r = await (await portalOf(who)).act("/portal/shared", fields);
  assert.ok(r.status === 200, what + ": the portal answered " + r.status +
    " " + JSON.stringify(r.json).slice(0, 400));
  log.debug("Leaving onPortal().");
  return r.json;
}

// The share of `resource` with `who` in the owner's view, by recipient.
function shareOf(view, resource, who) {
  log.debug("Entering shareOf().");
  const row = (view.resources || []).filter(function (one) {
    return one.id === resource;
  })[0] || { shares: [] };
  log.debug("Leaving shareOf().");
  return (row.shares || []).filter(function (s) {
    const r = s.recipient || {};
    return r.label === who || r.value === who;
  })[0] || null;
}

// The permission endpoint's ticket for one resource and scopes.
async function ticketFor(pat, resource, scopes) {
  log.debug("Entering ticketFor().");
  const r = await withPat(pat, "POST", "/uma/perm",
                          [{ resource_id: resource, resource_scopes: scopes }]);
  assert.ok(r.status === 201 && r.body && r.body.ticket,
            "a permission ticket: " + brief(r));
  log.debug("Leaving ticketFor().");
  return r.body.ticket;
}

// The claims interaction endpoint, walked by `who`: answers the new ticket.
async function interact(ticket, who) {
  log.debug("Entering interact(). " + who);
  const state = "st-" + crypto.randomBytes(6).toString("hex");
  const url = REALM_BASE + "/uma/claims?" + new URLSearchParams({
    client_id: CLIENT, ticket: ticket, claims_redirect_uri: CLAIMS_REDIRECT,
    state: state }).toString();
  const location = await signInThrough(url, who);
  const q = queryOf(location);
  log.debug("Leaving interact().");
  return { location: location, ticket: q.get("ticket") || "",
           state: q.get("state") || "",
           authorizationState: q.get("authorization_state") || "",
           sentState: state };
}

async function setUp() {
  log.debug("Entering setUp().");
  log.info("=== 1. setup ===");
  const made = await fetchJson(base + "/admin-api/realms/create", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id: REALM, domain: REALM + ".example.net",
                           name: "UMA 2.0 protocol job" }) });
  assert.ok(made.status === 200 && made.body && made.body.ok !== false,
            "created the realm: " + brief(made));
  await must("/config/set", { key: "uma.enabled", value: "true" },
             "turned UMA on");
  for (const who of [OWNER, PARTY, STRANGER]) {
    await must("/users/create", { username: who, invent: false,
      credential: "password", password: PASSWORD,
      attributes: { cn: "UMA " + who, sn: who, givenName: "UMA",
                    displayName: "UMA " + who,
                    mail: who + "@" + REALM + ".example.net" } },
      "created " + who);
  }
  const apps = [
    { id: RS, fields: { oauthGrantType: ["client_credentials",
        "authorization_code"], oauthRedirectUri: [RS_REDIRECT],
        oauthTokenEndpointAuthMethod: ["client_secret_basic"] } },
    { id: RS2, fields: { oauthGrantType: ["client_credentials"],
        oauthTokenEndpointAuthMethod: ["client_secret_basic"] } },
    { id: CLIENT, fields: { oauthGrantType: [GRANT],
        oauthClaimsRedirectUri: [CLAIMS_REDIRECT],
        oauthTokenEndpointAuthMethod: ["client_secret_basic"] } },
    { id: CLIENT2, fields: { oauthGrantType: [GRANT],
        oauthTokenEndpointAuthMethod: ["client_secret_basic"] } }
  ];
  for (const one of apps) {
    await must("/applications/create", { identifier: one.id,
      protocols: ["oauth2"],
      fields: Object.assign({ oauthClientId: one.id }, one.fields) },
      "created " + one.id);
    SECRETS[one.id] = crypto.randomBytes(48).toString("base64url");
    await must("/applications/set", { application: one.id,
      attribute: "oauthClientSecret", value: SECRETS[one.id] },
      "set " + one.id + "'s client secret");
  }
  for (const rs of [RS, RS2]) {
    await must("/uma/enable-resource-server", { application: rs },
               "made " + rs + " a resource server");
    await must("/uma/set-owns-resources", { application: rs, value: "TRUE" },
               "let " + rs + " own resources");
  }
  const view = await mustRead("/uma", "the UMA page");
  check("1. the resource servers are on /admin-api/uma, each holding " +
        "uma_protection", function () {
    const rows = (view.resourceServers || []).filter(function (row) {
      return row.identifier === RS || row.identifier === RS2;
    });
    assert.strictEqual(rows.length, 2, JSON.stringify(view.resourceServers));
    assert.ok(rows.every(function (row) {
      return row.protectionGranted && row.ownsResources;
    }), JSON.stringify(rows));
  });
  log.debug("Leaving setUp().");
}

async function discovery() {
  log.debug("Entering discovery().");
  log.info("=== 2. discovery ===");
  const r = await fetchJson(REALM_BASE + "/.well-known/uma2-configuration");
  check("2a. the UMA discovery document is served", function () {
    assert.strictEqual(r.status, 200, brief(r));
    assert.ok(r.body.issuer && r.body.token_endpoint &&
              r.body.resource_registration_endpoint &&
              r.body.permission_endpoint, r.text);
    assert.ok((r.body.grant_types_supported || []).indexOf(GRANT) >= 0,
              r.text);
  });
  // Every URL a registered route: an unrouted path is express's own
  // "Cannot <METHOD>", which a route never answers.
  const methods = { token_endpoint: "POST",
    resource_registration_endpoint: "POST", permission_endpoint: "POST",
    introspection_endpoint: "POST", claims_interaction_endpoint: "GET",
    authorization_endpoint: "GET", jwks_uri: "GET",
    registration_endpoint: "POST", revocation_endpoint: "POST" };
  const unrouted = [];
  for (const name of Object.keys(r.body)) {
    const value = r.body[name];
    if (typeof value !== "string" || !/^https?:\/\//.test(value) ||
        name === "issuer") {
      continue;
    }
    const method = methods[name] || "GET";
    const got = await fetchJson(value, { method: method,
      headers: method === "POST" ? { "Content-Type":
        "application/x-www-form-urlencoded" } : {},
      body: method === "POST" ? "" : undefined });
    if (/^Cannot (GET|POST) /.test(String(got.text || "")) ||
        /<pre>Cannot (GET|POST) /.test(String(got.text || ""))) {
      unrouted.push(name + " " + value);
    }
  }
  check("2b. every URL of the discovery document is a registered route",
        function () {
    assert.deepStrictEqual(unrouted, []);
  });
  const meta = await fetchJson(REALM_BASE +
                               "/.well-known/openid-configuration");
  check("2c. the token endpoint advertises the uma-ticket grant while " +
        "uma.enabled", function () {
    assert.ok((meta.body.grant_types_supported || []).indexOf(GRANT) >= 0,
              meta.text.slice(0, 300));
  });
  log.debug("Leaving discovery().");
}

async function patByCode(who) {
  log.debug("Entering patByCode(). " + who);
  const verifier = crypto.randomBytes(32).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier)
    .digest("base64url");
  const url = REALM_BASE + "/oauth2/authorize?" + new URLSearchParams({
    response_type: "code", client_id: RS, redirect_uri: RS_REDIRECT,
    scope: "uma_protection", resource: REALM_BASE + "/uma",
    state: "s-" + crypto.randomBytes(6).toString("hex"),
    code_challenge: challenge, code_challenge_method: "S256" }).toString();
  const location = await signInThrough(url, who);
  const code = queryOf(location).get("code");
  assert.ok(code, "the authorization code for the PAT: " + location);
  const r = await token(RS, { grant_type: "authorization_code", code: code,
    redirect_uri: RS_REDIRECT, code_verifier: verifier,
    resource: REALM_BASE + "/uma" });
  assert.ok(r.status === 200 && r.body.access_token,
            "the PAT by the code flow: " + brief(r));
  log.debug("Leaving patByCode().");
  return r.body.access_token;
}

async function patByClient(id) {
  log.debug("Entering patByClient(). " + id);
  const r = await token(id, { grant_type: "client_credentials",
    scope: "uma_protection", resource: REALM_BASE + "/uma" });
  assert.ok(r.status === 200 && r.body.access_token,
            "the PAT by client_credentials: " + brief(r));
  log.debug("Leaving patByClient().");
  return r.body.access_token;
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving UMA 2.0 at " + REALM_BASE);
  await setUp();
  await discovery();

  // =========================================================================
  // 3. THE PAT, BOTH GRANTS.
  // =========================================================================
  log.info("=== 3. the PAT ===");
  const ownerPat = await patByCode(OWNER);
  const appPat = await patByClient(RS);
  const otherPat = await patByClient(RS2);
  let r = await withPat(ownerPat, "POST", "/uma/rreg",
    { name: "Holiday photos", resource_scopes: ["view", "print"] });
  check("3a. the owner's PAT (code flow) registers the owner's resource",
        function () {
    assert.strictEqual(r.status, 201, brief(r));
    assert.ok(r.body._id, r.text);
  });
  const photos = r.body._id;
  r = await withPat(appPat, "POST", "/uma/rreg",
    { name: "Service manual", resource_scopes: ["read"] });
  check("3b. the application's PAT (client_credentials) registers its own " +
        "resource", function () {
    assert.strictEqual(r.status, 201, brief(r));
    assert.ok(r.body._id, r.text);
  });
  const manual = r.body._id;
  r = await fetchJson(REALM_BASE + "/uma/rreg", { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name: "x", resource_scopes: ["a"] }) });
  check("3c. no PAT, no registration: 401", function () {
    assert.strictEqual(r.status, 401, brief(r));
  });
  r = await withPat(ownerPat, "GET", "/uma/rreg");
  check("3d. the owner's PAT lists the owner's resource", function () {
    assert.strictEqual(r.status, 200, brief(r));
    assert.ok(Array.isArray(r.body) && r.body.indexOf(photos) >= 0, r.text);
  });

  // =========================================================================
  // 4. need_info, THE CLAIMS INTERACTION, request_denied.
  // =========================================================================
  log.info("=== 4. need_info and the claims interaction ===");
  let ticket = await ticketFor(ownerPat, photos, ["view"]);
  r = await token(CLIENT, { grant_type: GRANT, ticket: ticket });
  check("4a. nobody known is need_info, with a rotated ticket and " +
        "redirect_user", function () {
    assert.strictEqual(r.status, 403, brief(r));
    assert.strictEqual(r.body.error, "need_info", r.text);
    assert.ok(r.body.ticket && r.body.ticket !== ticket, r.text);
    assert.ok(r.body.redirect_user === true ||
              (r.body.required_claims || []).length > 0, r.text);
  });
  let walked = await interact(r.body.ticket, PARTY);
  check("4b. the claims interaction signs the party in and returns " +
        "claims_submitted, a new ticket and the state", function () {
    assert.strictEqual(walked.authorizationState, "claims_submitted",
                       walked.location);
    assert.ok(walked.ticket, walked.location);
    assert.strictEqual(walked.state, walked.sentState, walked.location);
    assert.ok(walked.location.indexOf(CLAIMS_REDIRECT) === 0,
              walked.location);
  });
  r = await token(CLIENT, { grant_type: GRANT, ticket: walked.ticket });
  check("4c. known, and nothing shared: request_denied", function () {
    assert.strictEqual(r.status, 403, brief(r));
    assert.strictEqual(r.body.error, "request_denied", r.text);
  });

  // =========================================================================
  // 5. A SHARE, THE RPT, INTROSPECTION.
  // =========================================================================
  log.info("=== 5. a share, the RPT and introspection ===");
  await onPortal(OWNER, { action: "share", resource: photos, scope: ["view"],
    recipientKind: "person", recipient: PARTY }, "shared view");
  let view = await sharedView(OWNER);
  const viewShare = shareOf(view, photos, PARTY);
  check("5a. the share is on the owner's Sharing page", function () {
    assert.ok(viewShare && viewShare.id, JSON.stringify(view).slice(0, 600));
  });
  ticket = await ticketFor(ownerPat, photos, ["view"]);
  r = await token(CLIENT, { grant_type: GRANT, ticket: ticket });
  assert.strictEqual(r.body && r.body.error, "need_info", brief(r));
  walked = await interact(r.body.ticket, PARTY);
  r = await token(CLIENT, { grant_type: GRANT, ticket: walked.ticket });
  check("5b. shared, the party's client is issued an RPT and a PCT",
        function () {
    assert.strictEqual(r.status, 200, brief(r));
    assert.ok(r.body.access_token, r.text);
    assert.ok(r.body.pct, "a PCT with the claims gathered: " + r.text);
  });
  const rpt = r.body.access_token;
  const pct = r.body.pct;
  r = await introspect(ownerPat, rpt);
  check("5c. the resource server's PAT introspects the RPT: its " +
        "permissions, no scope", function () {
    assert.strictEqual(r.status, 200, brief(r));
    assert.strictEqual(r.body.active, true, r.text);
    assert.ok(Array.isArray(r.body.permissions) &&
              r.body.permissions.some(function (p) {
                return p.resource_id === photos &&
                       p.resource_scopes.indexOf("view") >= 0;
              }), r.text);
    assert.strictEqual(r.body.scope, undefined, r.text);
  });
  r = await introspect(otherPat, rpt);
  check("5d. another resource server's PAT sees it inactive", function () {
    assert.strictEqual(r.status, 200, brief(r));
    assert.strictEqual(r.body.active, false, r.text);
  });

  // =========================================================================
  // 6. request_submitted, THE PORTAL'S APPROVAL, UPGRADE.
  // =========================================================================
  log.info("=== 6. request_submitted, approval and upgrade ===");
  await onPortal(OWNER, { action: "share", resource: photos,
    scope: ["print"], recipientKind: "person", recipient: PARTY,
    askMe: "on" }, "shared print, asking each time");
  ticket = await ticketFor(ownerPat, photos, ["print"]);
  r = await token(CLIENT, { grant_type: GRANT, ticket: ticket, pct: pct,
                            rpt: rpt });
  check("6a. a share that asks the owner is request_submitted, with a " +
        "rotated ticket", function () {
    assert.strictEqual(r.status, 403, brief(r));
    assert.strictEqual(r.body.error, "request_submitted", r.text);
    assert.ok(r.body.ticket && r.body.ticket !== ticket, r.text);
  });
  const pollTicket = r.body.ticket;
  view = await sharedView(OWNER);
  const waiting = (view.pending || []).filter(function (one) {
    return one.client === CLIENT;
  })[0];
  check("6b. the request waits on the owner's Sharing page", function () {
    assert.ok(waiting && waiting.id, JSON.stringify(view.pending));
  });
  await onPortal(OWNER, { action: "approve", pending: waiting.id },
                 "approved the request");
  r = await token(CLIENT, { grant_type: GRANT, ticket: pollTicket, pct: pct,
                            rpt: rpt });
  check("6c. the next try is granted, upgrading the RPT", function () {
    assert.strictEqual(r.status, 200, brief(r));
    assert.ok(r.body.access_token && r.body.access_token !== rpt, r.text);
  });
  const upgraded = r.body.access_token;
  r = await introspect(ownerPat, upgraded);
  const old = await introspect(ownerPat, rpt);
  check("6d. the upgraded RPT carries view and print; the old one is " +
        "inactive", function () {
    const scopes = [];
    (r.body.permissions || []).forEach(function (p) {
      if (p.resource_id === photos) {
        Array.prototype.push.apply(scopes, p.resource_scopes);
      }
    });
    assert.ok(scopes.indexOf("view") >= 0 && scopes.indexOf("print") >= 0,
              r.text);
    assert.strictEqual(old.body.active, false, old.text);
  });

  // =========================================================================
  // 7. REVOCATION ON THE PORTAL.
  // =========================================================================
  log.info("=== 7. revocation on the portal ===");
  await onPortal(OWNER, { action: "unshare", share: viewShare.id },
                 "removed the view share");
  r = await introspect(ownerPat, upgraded);
  check("7. removing the share ends the RPT that carried it: active false",
        function () {
    assert.strictEqual(r.status, 200, brief(r));
    assert.strictEqual(r.body.active, false, r.text);
  });

  // =========================================================================
  // 8. AN APPLICATION AS OWNER (decision 5).
  // =========================================================================
  log.info("=== 8. an application as owner ===");
  await must("/uma/owner-share", { owner: RS, resource: manual,
    scope: "read", recipientKind: "person", recipient: PARTY },
    "shared the application's manual");
  const owned = await mustRead("/uma?owner=" + encodeURIComponent(RS),
                               "the application's owner tab");
  check("8a. the application's document carries the share", function () {
    assert.ok(owned.owner && owned.owner.editable &&
              owned.owner.document.shares.length === 1,
              JSON.stringify(owned.owner).slice(0, 500));
  });
  ticket = await ticketFor(appPat, manual, ["read"]);
  r = await token(CLIENT, { grant_type: GRANT, ticket: ticket, pct: pct });
  check("8b. the party's client, with its PCT, is issued an RPT over the " +
        "application's resource", function () {
    assert.strictEqual(r.status, 200, brief(r));
    assert.ok(r.body.access_token, r.text);
  });

  // =========================================================================
  // 9. NEGATIVES.
  // =========================================================================
  log.info("=== 9. negatives ===");
  ticket = await ticketFor(appPat, manual, ["read"]);
  r = await token(CLIENT, { grant_type: GRANT, ticket: ticket });
  const rotated = r.body && r.body.ticket;
  r = await token(CLIENT2, { grant_type: GRANT, ticket: rotated });
  check("9a. a ticket another client presented first is invalid_grant",
        function () {
    assert.strictEqual(r.status, 400, brief(r));
    assert.strictEqual(r.body.error, "invalid_grant", r.text);
  });
  r = await token(CLIENT, { grant_type: GRANT, ticket: ticket, pct: pct });
  check("9b. a spent ticket is invalid_grant", function () {
    assert.strictEqual(r.status, 400, brief(r));
    assert.strictEqual(r.body.error, "invalid_grant", r.text);
  });
  ticket = await ticketFor(appPat, manual, ["read"]);
  r = await token(CLIENT, { grant_type: GRANT, ticket: ticket, pct: pct,
                            scope: "delete" });
  check("9c. a scope the resource does not carry is invalid_scope",
        function () {
    assert.strictEqual(r.status, 400, brief(r));
    assert.strictEqual(r.body.error, "invalid_scope", r.text);
  });
  ticket = await ticketFor(ownerPat, photos, ["print"]);
  r = await token(CLIENT, { grant_type: GRANT, ticket: ticket });
  walked = await interact(r.body.ticket, STRANGER);
  r = await token(CLIENT, { grant_type: GRANT, ticket: walked.ticket });
  check("9d. a stranger, signed in, is request_denied", function () {
    assert.strictEqual(r.status, 403, brief(r));
    assert.strictEqual(r.body.error, "request_denied", r.text);
  });

  // =========================================================================
  // 10. THE CONSOLE'S OPERATIONS.
  // =========================================================================
  log.info("=== 10. the console's operations ===");
  const page = await mustRead("/uma", "the UMA page");
  const monitor = await mustRead("/uma/monitor", "the UMA monitor");
  check("10. /admin-api/uma lists the resources and live RPTs, and the " +
        "monitor counts the realm's", function () {
    assert.ok(page.resources.total >= 2, JSON.stringify(page.resources));
    assert.ok(page.rpts.total >= 1, JSON.stringify(page.rpts));
    assert.ok(monitor.totals && monitor.totals.resources >= 2,
              JSON.stringify(monitor.totals));
  });

  // =========================================================================
  // 11. uma.enabled OFF.
  // =========================================================================
  log.info("=== 11. uma.enabled off ===");
  await must("/config/set", { key: "uma.enabled", value: "false" },
             "turned UMA off");
  const meta = await fetchJson(REALM_BASE +
                               "/.well-known/openid-configuration");
  ticket = "anything";
  r = await token(CLIENT, { grant_type: GRANT, ticket: ticket });
  check("11. off, the grant is neither advertised nor performed",
        function () {
    assert.ok((meta.body.grant_types_supported || []).indexOf(GRANT) < 0,
              meta.text.slice(0, 300));
    assert.strictEqual(r.body && r.body.error, "unsupported_grant_type",
                       brief(r));
  });

  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_uma")
  .description("User-Managed Access 2.0 over HTTP (#1168 phase 7): the " +
    "PAT, resource registration, need_info, the claims interaction, the " +
    "RPT, introspection, request_submitted and the portal's approval, " +
    "upgrade, revocation, an application as owner and the negatives, in " +
    "whichever mode the service is in.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
