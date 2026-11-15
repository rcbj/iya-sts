// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_report_access_policy.js
//
// ---------------------------------------------------------------------------
// THE REPORTS API IS DECIDED BY ROLES AND THE PDP, AS A CALLER MEETS IT
// (#1030, #1038, #1141).
//
// D12 (#444): carries over `tests/report_access_policy.js`. In a throwaway
// realm whose console is claimed first (claimConsole(): in development
// every signed-in person is a console, and so a report, administrator
// until then), with people in report-users and report-admins, a direct
// member of REPORT_USE, Admin Write and Admin Read on the realm's roster,
// and three applications (one in REPORT_USE, one in REPORT_ADMIN, one in
// neither, each holding the two delegated permission grants):
//
//   A. THE ROLES: REPORT_USE and REPORT_ADMIN seeded with their groups and
//      permissions, both groups present, sts-report-api's permission base;
//   B. ISSUANCE through the reporting application's own code flow (the
//      scope asked chosen here): what each person and each application is
//      ISSUED, report:use alone invalid_scope for an outsider, a client
//      holding neither role refused invalid_scope;
//   C. THE POLICY OVER HTTP: who sees, changes, runs, lists and deletes
//      which definition and job — the owner, the shared group's member, an
//      outsider, a report administrator, each application confined to its
//      own; no report scope is insufficient_scope (0017); a role taken away
//      after the token was minted is refused on the next call (0018); a
//      definition that is not the caller's is 404, never 403; the reports
//      application's Shared Signals inbox per caller;
//   E. `permitReportSharing: no` built from the access-control template
//      over /admin-api/xacml: the shared member and the report
//      administrator lose the definition, the owner and an application keep
//      theirs, and deleting the override puts the built-in rule back;
//   F. a realm's own Admin Write sees every definition, Admin Read its own,
//      and the realm's token is believed in no other realm (401).
//
// NOT carried, and why: STS-REPORT-0044, the policy refusing the API to a
// caller who holds a report role — the built-in document permits every
// holder, so only a hand-written access-control override denying its first
// rule reaches it (owed with the XACML family's jobs, phase 8); taking a
// person out of report-users — /admin-api has no remove-member for a group
// (an ldapmodify or a SCIM PATCH, phase 4 and 9), so the role-taken-away
// case is a direct REPORT_USE member's; D, the schedule's question for an
// owner whose role went (STS-REPORT-0028) — a scheduled definition never
// runs on a running service (see sts_report_query.js, section 4b, a Node
// defect); F2-F10, a default-realm service administrator reaching
// another realm's report API and a default-realm report user refused
// there (STS-REPORT-0045) — they need the DEFAULT realm's console claimed
// and its roster changed, which is process-wide state every job shares
// (owed: an exclusive job, or a stack whose default console is claimed).
//
// OWNED HERE (local: true): this repository's own reports API.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const names = require("./random_username.js");
const consoleSignin = require("./console_signin.js");
const authnSignin = require("./authn_signin.js");
const fixtures = require("./oauth_fixtures.js");

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
var log = bunyan.createLogger({ name: "sts_report_access_policy",
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
const REALM = "rap-" + STAMP;
const RB = base + "/realm/" + REALM;
const PASSWORD = "Rap-" + STAMP + "-Aa1!-pass";
const SECRET = "rap-" + STAMP + "-" + String(Date.now()).slice(-8) +
               "-client-secret";
// A desktop browser's User-Agent, as report_signin.js sends.
const AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";
const OWNER = "rap-owner-" + STAMP;
const SHARED = "rap-shared-" + STAMP;
const OUTSIDER = "rap-out-" + STAMP;
const ADMIN = "rap-admin-" + STAMP;
const NOBODY = "rap-nobody-" + STAMP;
const LATER = "rap-later-" + STAMP;
const CONSOLE_W = "rap-cw-" + STAMP;
const CONSOLE_R = "rap-cr-" + STAMP;
const GROUP = "rap-share-" + STAMP;
const APP = "rap-app-" + STAMP;
const APP2 = "rap-app2-" + STAMP;
const CLIENT = "rap-client-" + STAMP;

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

// One call to the realm's /report-api with the session's DPoP-bound token
// and a fresh proof, retried once on a nonce the resource server asks for.
async function api(session, method, path, body) {
  log.debug("Entering api(). " + method + " " + path);
  const url = (session.rb || RB) + "/report-api" + path;
  let r = null;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const headers = { Accept: "application/json",
      Authorization: "DPoP " + session.token,
      DPoP: session.key.proof(method, url, session.token) };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
    }
    const raw = await fetch(url, { method: method, headers: headers,
      body: body === undefined ? undefined : JSON.stringify(body) });
    session.key.keepNonce(raw);
    const text = await raw.text();
    let json = null;
    try {
      json = JSON.parse(text);
    } catch (e) {
      log.debug("Caught in api(): " + ((e && e.message) || e));
      // Not JSON; the caller reads `text`.
      json = null;
    }
    r = { status: raw.status, text: text, json: json };
    if (!(raw.status === 401 && /use_dpop_nonce/.test(
      String(raw.headers.get("www-authenticate") || "") + text))) {
      break;
    }
  }
  log.debug("Leaving api(). " + r.status);
  return r;
}

function brief(r) {
  log.debug("Entering brief().");
  log.debug("Leaving brief().");
  return r.status + " " + String(r.text || r.raw || "").slice(0, 300);
}

async function codeCount(code) {
  log.debug("Entering codeCount(). " + code);
  const r = await send(RB + "/admin-api/audit?per=500&code=" +
                       encodeURIComponent(code));
  log.debug("Leaving codeCount().");
  return Number((r.body && r.body.matched) || 0);
}

async function codesSettle(code, atLeast) {
  log.debug("Entering codesSettle(). " + code);
  let n = await codeCount(code);
  for (let i = 0; i < 20 && n < atLeast; i += 1) {
    await sleep(150);
    n = await codeCount(code);
  }
  log.debug("Leaving codesSettle(). " + n);
  return n;
}

// A person with a password, in the groups given.
async function person(name, groups, cn) {
  log.debug("Entering person(). " + name);
  await ok(RB + "/admin-api/users/create", { username: name, invent: false,
    attributes: { cn: cn || ("Person " + name), givenName: "Report",
                  sn: name, mail: name + "@" + REALM + ".example.net" },
    credential: "password", password: PASSWORD }, "created " + name);
  for (const group of groups || []) {
    await ok(RB + "/admin-api/groups/add-member", { group: group,
      member: name }, "put " + name + " in " + group);
  }
  log.debug("Leaving person().");
}

// THE CONSOLE IS CLOSED FIRST. In development a realm's console is open to
// every signed-in person until its bootstrap administrator first signs in
// to it (admin.openWhenEmpty), and since #1038 a console administrator is a
// report administrator — so until then EVERY person holds REPORT_ADMIN and
// no report-users member is confined to their own rows. The bootstrap
// administrator `admin` signs in once here: the forced password change at
// the sign-in screen, then the console's own sign-in, which claims the
// window. The roster is enforced from then on, as in product.
async function claimConsole() {
  log.debug("Entering claimConsole().");
  const pkce = fixtures.pkce();
  const query = new URLSearchParams({ response_type: "code",
    client_id: "sts-report", redirect_uri: RB + "/report/callback",
    scope: "openid", code_challenge: pkce.challenge,
    code_challenge_method: "S256", state: "claim-" + STAMP });
  const at = await fetch(RB + "/oauth2/authorize?" + query.toString(),
                         { redirect: "manual" });
  const where = new URL(String(at.headers.get("location") || ""),
                        RB + "/").toString();
  const NEW = "Claim-" + STAMP + "-Aa1!-console";
  let answer = await authnSignin.signIn(RB, where,
    { action: "login", username: "admin", password: "anything" }, {});
  if (answer.next === "password-change") {
    answer = await authnSignin.changePassword(RB, answer.location,
      { new_password: NEW, confirm_password: NEW },
      { cookie: answer.cookie });
  }
  await consoleSignin.signInToTheConsole(RB, "admin", null,
                                         { password: NEW });
  const roster = await send(RB + "/admin-api/rbac");
  assert.ok(roster.body && roster.body.openToAnyone === false &&
            roster.body.bootstrap && roster.body.bootstrap.claimedAt,
    "precondition: the realm's console is claimed and closed; the roster " +
    "reads " + JSON.stringify(roster.body && {
      open: roster.body.openToAnyone, bootstrap: roster.body.bootstrap }));
  log.debug("Leaving claimConsole().");
}

function b64u(buffer) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(buffer).toString("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// A P-256 DPoP key of report_signin.js's shape: `proof(method, url,
// token)` and `keepNonce(response)`.
function dpopKey() {
  log.debug("Entering dpopKey().");
  const pair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = pair.publicKey.export({ format: "jwk" });
  const state = { nonce: "" };
  log.debug("Leaving dpopKey().");
  return {
    keepNonce: function (response) {
      const nonce = response.headers.get("dpop-nonce");
      if (nonce) {
        state.nonce = nonce;
      }
    },
    proof: function (method, url, accessToken) {
      const header = { typ: "dpop+jwt", alg: "ES256",
        jwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } };
      const claims = { jti: b64u(crypto.randomBytes(16)),
                       htm: String(method).toUpperCase(),
                       htu: String(url).replace(/[?#].*$/, ""),
                       iat: Math.floor(Date.now() / 1000) };
      if (accessToken) {
        claims.ath = b64u(crypto.createHash("sha256").update(accessToken)
          .digest());
      }
      if (state.nonce) {
        claims.nonce = state.nonce;
      }
      const input = b64u(JSON.stringify(header)) + "." +
                    b64u(JSON.stringify(claims));
      const signature = crypto.sign("sha256", Buffer.from(input),
        { key: pair.privateKey, dsaEncoding: "ieee-p1363" });
      return input + "." + b64u(signature);
    }
  };
}

// THE REPORTING APPLICATION'S CODE FLOW WITH A SCOPE OF THE CALLER'S
// CHOOSING: what report_signin.js does with its fixed scope, answering what
// was ISSUED — `{ error }` where the authorization endpoint refused, else
// `{ scope, token, key }` with the token DPoP-bound to `key`. `rb` is the
// realm's base (the default realm's is `base`). A development realm needs
// no pushed request and no JARM, so neither is made.
async function signInScoped(rb, user, scope) {
  log.debug("Entering signInScoped(). " + user + " " + scope);
  const cookies = consoleSignin.jar();
  const key = dpopKey();
  const pkce = fixtures.pkce();
  const redirectUri = rb + "/report/callback";
  const state = b64u(crypto.randomBytes(12));
  const params = new URLSearchParams({ response_type: "code",
    client_id: "sts-report", redirect_uri: redirectUri, scope: scope,
    code_challenge: pkce.challenge, code_challenge_method: "S256",
    resource: rb + "/report-api", state: state,
    nonce: b64u(crypto.randomBytes(12)) });
  const hop = async function (url) {
    const r = await fetch(url, { redirect: "manual",
      headers: { cookie: cookies.header(), "User-Agent": AGENT } });
    cookies.keep(r);
    return r;
  };
  let at = await hop(rb + "/oauth2/authorize?" + params.toString());
  let location = String(at.headers.get("location") || "");
  if (/[?&#]authn=/.test(location)) {
    const signed = await authnSignin.signIn(rb,
      new URL(location, rb + "/").toString(),
      { action: "login", username: user, password: PASSWORD },
      { cookie: cookies.header() });
    cookies.keep(signed);
    at = authnSignin.responseLike(signed);
    location = String(at.headers.get("location") || "");
  }
  for (let guard = 0; guard < 8 && !/\/report\/callback\?/.test(location);
       guard += 1) {
    if (authnSignin.isConsent(location)) {
      const answered = await authnSignin.consentFor(
        new URL(location, rb + "/").toString(), cookies.header());
      cookies.keep(answered);
      at = authnSignin.responseLike(answered);
    } else if (at.status === 302 || at.status === 303) {
      at = await hop(new URL(location, rb + "/").toString());
    } else {
      break;
    }
    location = String(at.headers.get("location") || "");
  }
  const back = new URL(location, rb + "/");
  if (back.searchParams.get("error")) {
    log.debug("Leaving signInScoped(). Refused.");
    return { error: back.searchParams.get("error") };
  }
  const code = back.searchParams.get("code");
  assert.ok(code, "the report sign-in of " + user + " reached no code: " +
            at.status + " " + location);
  const tokenUrl = rb + "/oauth2/token";
  let issued = null;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const r = await fetch(tokenUrl, { method: "POST", headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      DPoP: key.proof("POST", tokenUrl, "") },
      body: new URLSearchParams({ grant_type: "authorization_code",
        code: code, redirect_uri: redirectUri, client_id: "sts-report",
        code_verifier: pkce.verifier, resource: rb + "/report-api" })
        .toString() });
    key.keepNonce(r);
    issued = { status: r.status, json: await r.json() };
    if (!(r.status === 400 && issued.json.error === "use_dpop_nonce")) {
      break;
    }
  }
  assert.strictEqual(issued.status, 200, "the report code of " + user +
    " should redeem; it answered " + JSON.stringify(issued.json));
  log.debug("Leaving signInScoped().");
  return { scope: String(issued.json.scope || ""),
           token: issued.json.access_token, key: key, rb: rb };
}

// An application's own token, on client_credentials at the realm's token
// endpoint, audienced to its /report-api and DPoP-bound to a key of its own.
async function machineToken(rb, id, scope) {
  log.debug("Entering machineToken(). " + id);
  const key = dpopKey();
  const tokenUrl = rb + "/oauth2/token";
  let issued = null;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const r = await fetch(tokenUrl, { method: "POST", headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      DPoP: key.proof("POST", tokenUrl, "") },
      body: new URLSearchParams({ grant_type: "client_credentials",
        client_id: id, client_secret: SECRET, scope: scope,
        resource: rb + "/report-api" }).toString() });
    key.keepNonce(r);
    issued = { status: r.status, json: await r.json() };
    if (!(r.status === 400 && issued.json.error === "use_dpop_nonce")) {
      break;
    }
  }
  log.debug("Leaving machineToken(). " + issued.status);
  return issued.status === 200
    ? { scope: String(issued.json.scope || ""),
        token: issued.json.access_token, key: key, rb: rb }
    : { error: issued.json.error, status: issued.status };
}

// The report scopes a token response names, sorted. `openid` is left out:
// a token audienced to /report-api by `resource` names only the scopes that
// resource defines (the in-process file read tokenSet()'s whole string).
function words(scope) {
  log.debug("Entering words().");
  log.debug("Leaving words().");
  return String(scope || "").split(/\s+/).filter(function (one) {
    return one && one !== "openid";
  }).sort().join(" ");
}

async function application(id, role) {
  log.debug("Entering application(). " + id);
  await ok(RB + "/admin-api/applications/create", { identifier: id,
    name: id, protocols: ["oauth2"],
    fields: { oauthClientId: [id], oauthClientSecret: SECRET,
              oauthTokenEndpointAuthMethod: "client_secret_post",
              oauthGrantType: ["client_credentials"],
              // The report scopes are delegated permission grants (#1141).
              oauthDelegatedPermission: ["urn:sts:report-api:report:use",
                                         "urn:sts:report-api:report:admin"] } },
    "registered " + id);
  if (role) {
    await ok(RB + "/admin-api/roles/add-member", { role: role,
      kind: "application", member: id }, "put " + id + " in " + role);
  }
  log.debug("Leaving application().");
}

async function test() {
  log.debug("Entering test().");
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "Report access " + STAMP },
    "created the realm");
  await claimConsole();
  await person(OWNER, ["report-users"]);
  await person(SHARED, ["report-users"]);
  await person(OUTSIDER, ["report-users"]);
  await person(ADMIN, ["report-admins"]);
  await person(NOBODY, []);
  await person(LATER, []);
  await person(CONSOLE_W, []);
  await person(CONSOLE_R, []);
  await ok(RB + "/admin-api/roles/add-member", { role: "REPORT_USE",
    kind: "user", member: LATER }, "made " + LATER + " a direct member");
  await ok(RB + "/admin-api/rbac/grant", { username: CONSOLE_W,
    role: "write" }, "granted Admin Write");
  await ok(RB + "/admin-api/rbac/grant", { username: CONSOLE_R,
    role: "read" }, "granted Admin Read");
  await ok(RB + "/admin-api/groups/create", { group: GROUP },
           "created the share group");
  await ok(RB + "/admin-api/groups/add-member", { group: GROUP,
    member: SHARED }, "put the shared member in it");
  await application(APP, "REPORT_USE");
  await application(APP2, "REPORT_ADMIN");
  await application(CLIENT, null);
  const before = {};
  for (const code of ["STS-REPORT-0017", "STS-REPORT-0018"]) {
    before[code] = await codeCount(code);
  }

  log.info("=== A. the roles ===");
  const useRole = await send(RB + "/admin-api/roles?role=REPORT_USE");
  const adminRole = await send(RB + "/admin-api/roles?role=REPORT_ADMIN");
  check("A1. REPORT_USE is seeded with the group report-users and " +
        "authorizes report:use", function () {
    const role = useRole.body && useRole.body.role;
    assert.ok(role && role.groups.indexOf("report-users") >= 0,
              useRole.raw.slice(0, 400));
    assert.deepStrictEqual(role.permissions, ["report:use"]);
  });
  check("A2. REPORT_ADMIN is seeded with report-admins and authorizes " +
        "report:admin", function () {
    const role = adminRole.body && adminRole.body.role;
    assert.ok(role && role.groups.indexOf("report-admins") >= 0,
              adminRole.raw.slice(0, 400));
    assert.deepStrictEqual(role.permissions, ["report:admin"]);
  });
  const reportGroups = await send(RB + "/admin-api/groups?q=report-");
  check("A3. both groups exist in the directory", function () {
    assert.ok(/report-users/.test(reportGroups.raw) &&
              /report-admins/.test(reportGroups.raw),
              reportGroups.raw.slice(0, 300));
  });
  const api2 = await send(RB + "/admin-api/applications?q=sts-report-api");
  check("A4. sts-report-api, the reports API's resource object (#1139), " +
        "defines the report permissions under urn:sts:report-api:",
        function () {
    assert.ok(/urn:sts:report-api:/.test(api2.raw), api2.raw.slice(0, 400));
  });

  log.info("=== B. issuance ===");
  const asked = "openid report:use report:admin";
  const tOwner = await signInScoped(RB, OWNER, asked);
  const tShared = await signInScoped(RB, SHARED, asked);
  const tOut = await signInScoped(RB, OUTSIDER, asked);
  const tAdmin = await signInScoped(RB, ADMIN, asked);
  const tNobody = await signInScoped(RB, NOBODY, asked);
  const alone = await signInScoped(RB, NOBODY, "report:use");
  const tLater = await signInScoped(RB, LATER, asked);
  const tCw = await signInScoped(RB, CONSOLE_W, asked);
  const tCr = await signInScoped(RB, CONSOLE_R, asked);
  const tNone = await signInScoped(RB, OWNER, "openid");
  const tApp = await machineToken(RB, APP, "report:use report:admin");
  const tApp2 = await machineToken(RB, APP2, "report:use report:admin");
  const bare = await machineToken(RB, CLIENT, "report:use");
  check("B1. a member of report-users is issued report:use and not " +
        "report:admin", function () {
    assert.strictEqual(words(tOwner.scope), "report:use",
                       tOwner.scope);
  });
  check("B2. a member of report-admins is issued report:admin and not " +
        "report:use", function () {
    assert.strictEqual(words(tAdmin.scope), "report:admin",
                       tAdmin.scope);
  });
  check("B3. an outsider is issued neither", function () {
    assert.strictEqual(words(tNobody.scope), "", tNobody.scope);
  });
  check("B4. report:use alone is invalid_scope for an outsider",
        function () {
    assert.strictEqual(alone.error, "invalid_scope", JSON.stringify(alone));
  });
  check("B5. a direct user member of REPORT_USE is issued report:use",
        function () {
    assert.strictEqual(words(tLater.scope), "report:use",
                       tLater.scope);
  });
  check("B6. an application in REPORT_USE is issued report:use on " +
        "client_credentials, and not report:admin", function () {
    assert.strictEqual(words(tApp.scope), "report:use",
                       JSON.stringify(tApp));
  });
  check("B7. an application in REPORT_ADMIN is issued report:admin",
        function () {
    assert.strictEqual(words(tApp2.scope), "report:admin",
                       JSON.stringify(tApp2));
  });
  check("B8. an application that is no member is refused invalid_scope " +
        "though it declares the scope", function () {
    assert.strictEqual(bare.error, "invalid_scope", JSON.stringify(bare));
  });
  check("B9. Admin Write on the realm's console roster is issued both, in " +
        "no report group (#1038)", function () {
    assert.strictEqual(words(tCw.scope), "report:admin report:use",
                       tCw.scope);
  });
  check("B10. Admin Read is issued report:use and not report:admin",
        function () {
    assert.strictEqual(words(tCr.scope), "report:use", tCr.scope);
  });

  log.info("=== C. the policy, over HTTP ===");
  const at = async function (session, method, path, body) {
    return api(session, method, path, body);
  };
  let r = await at(tOwner, "GET", "");
  check("C1. a report user reaches the API", function () {
    assert.strictEqual(r.status, 200, brief(r));
  });
  r = await at(tNone, "GET", "");
  check("C3. a token with no report scope is 403 insufficient_scope",
        function () {
    assert.strictEqual(r.status, 403, brief(r));
    assert.strictEqual(r.json.error, "insufficient_scope");
  });
  r = await at(tApp, "GET", "");
  check("C4. an application's own token reaches the API (STS-REPORT-0016 " +
        "is retired)", function () {
    assert.strictEqual(r.status, 200, brief(r));
  });
  const document = { source: "users", select: ["username"], limit: 3 };
  const define = async function (session, name) {
    const made = await at(session, "POST", "/definitions",
                          { name: name, document: document });
    return made.json && made.json.definition ? made.json.definition : null;
  };
  const d1 = await define(tOwner, "the owner's");
  const d2 = await define(tApp, "the application's");
  const d3 = await define(tApp2, "the admin application's");
  check("C5. a person and two applications each saved a definition, each " +
        "recording its owner", function () {
    assert.ok(d1 && d2 && d3, JSON.stringify([d1, d2, d3]));
    assert.ok(/^urn:uuid:/.test(d1.owner), d1.owner);
    assert.strictEqual(d2.owner, APP, JSON.stringify(d2));
  });
  const D1 = d1.id;
  const D2 = d2.id;
  const D3 = d3.id;
  const groups = await at(tOwner, "GET", "/groups?q=" +
                          encodeURIComponent(GROUP));
  const groupDn = ((groups.json && groups.json.groups) || [])
    .filter(function (one) {
      return one.name === GROUP;
    }).map(function (one) {
      return one.dn;
    })[0];
  r = await at(tOwner, "POST", "/definitions/" + D1 + "/share",
               { groups: [groupDn] });
  check("C7. the owner shares it with the group (found through " +
        "/report-api/groups)", function () {
    assert.ok(groupDn, brief(groups));
    assert.strictEqual(r.status, 200, brief(r));
  });
  const get = async function (session, id) {
    return (await at(session, "GET", "/definitions/" + id)).status;
  };
  const seen = {
    owner: await get(tOwner, D1), shared: await get(tShared, D1),
    out: await get(tOut, D1), admin: await get(tAdmin, D1),
    app: await get(tApp, D1), app2: await get(tApp2, D1)
  };
  check("C8-C11. the owner, the shared group's member and a report " +
        "administrator see it; a report user outside the group is answered " +
        "404", function () {
    assert.deepStrictEqual([seen.owner, seen.shared, seen.out, seen.admin],
                           [200, 200, 404, 200],
                           JSON.stringify(seen));
  });
  check("C12-C13. no application sees a person's definition, whichever " +
        "role it holds", function () {
    assert.deepStrictEqual([seen.app, seen.app2], [404, 404],
                           JSON.stringify(seen));
  });
  const appSees = [await get(tApp, D2), await get(tOwner, D2),
                   await get(tAdmin, D2)];
  check("C14. the application sees its own, a report user does not, a " +
        "report administrator does", function () {
    assert.deepStrictEqual(appSees, [200, 404, 200]);
  });
  const update = function (session, id) {
    return at(session, "POST", "/definitions/" + id,
              { name: "renamed " + STAMP, document: document });
  };
  const u = [await update(tShared, D1), await update(tAdmin, D1),
             await update(tOwner, D1), await update(tApp2, D2)];
  check("C15-C18. a share does not let its member change the definition; " +
        "a report administrator and the owner may; an administrator " +
        "application may not change another application's", function () {
    assert.deepStrictEqual(u.map(function (one) {
      return one.status;
    }), [404, 200, 200, 404], u.map(brief).join(" | "));
  });
  const run = function (session, id) {
    return at(session, "POST", "/definitions/" + id + "/run", {});
  };
  const runs = [await run(tShared, D1), await run(tOut, D1),
                await run(tApp, D2)];
  check("C19-C21. the shared member runs it, an outsider may not, an " +
        "application runs its own", function () {
    assert.deepStrictEqual(runs.map(function (one) {
      return one.status;
    }), [202, 404, 202], runs.map(brief).join(" | "));
  });
  const ids = async function (session) {
    const listed = await at(session, "GET", "/definitions");
    return ((listed.json || {}).definitions || []).map(function (one) {
      return one.id;
    }).sort().join(",");
  };
  const lists = { owner: await ids(tOwner), shared: await ids(tShared),
                  out: await ids(tOut), admin: await ids(tAdmin),
                  app: await ids(tApp), app2: await ids(tApp2) };
  check("C22-C26. a report user lists their own, the shared member the " +
        "one shared, an outsider nothing, a report administrator every " +
        "one, each application only what it defined", function () {
    assert.strictEqual(lists.owner, D1, JSON.stringify(lists));
    assert.strictEqual(lists.shared, D1);
    assert.strictEqual(lists.out, "");
    assert.strictEqual(lists.admin, [D1, D2, D3].sort().join(","));
    assert.strictEqual(lists.app, D2);
    assert.strictEqual(lists.app2, D3);
  });
  const jobCount = async function (session) {
    const listed = await at(session, "GET", "/jobs");
    return ((listed.json || {}).jobs || []).length;
  };
  const counts = [await jobCount(tShared), await jobCount(tOut),
                  await jobCount(tAdmin)];
  check("C27. a job is its runner's, a report administrator sees every " +
        "job, an outsider none", function () {
    assert.ok(counts[0] >= 1 && counts[1] === 0 && counts[2] >= 2,
              counts.join(","));
  });
  const del = [await at(tApp2, "DELETE", "/definitions/" + D2),
               await at(tApp, "DELETE", "/definitions/" + D2)];
  check("C28-C29. an application may not delete another application's " +
        "definition, and deletes its own", function () {
    assert.deepStrictEqual([del[0].status, del[1].status], [404, 200],
                           del.map(brief).join(" | "));
  });

  log.info("=== C. a role taken away after the token was minted ===");
  r = await at(tLater, "GET", "");
  const d4 = await define(tLater, "before the role went");
  await ok(RB + "/admin-api/roles/remove-member", { role: "REPORT_USE",
    kind: "user", member: LATER }, "took the direct member off REPORT_USE");
  const afterRole = await at(tLater, "GET", "");
  check("C30-C31. a direct member reaches the API, and the same token is " +
        "refused 403 on the next call once the role is gone: held and " +
        "carried (STS-REPORT-0018)", function () {
    assert.strictEqual(r.status, 200, brief(r));
    assert.ok(d4, "the definition before the role went");
    assert.strictEqual(afterRole.status, 403, brief(afterRole));
    assert.ok(/holds no role/.test(afterRole.text), brief(afterRole));
  });
  log.info("=== C. the reports application's Shared Signals inbox ===");
  const ownerSub = d1.owner;
  const signals = { admin: await at(tAdmin, "GET", "/signals"),
                    owner: await at(tOwner, "GET", "/signals"),
                    shared: await at(tShared, "GET", "/signals"),
                    app: await at(tApp, "GET", "/signals") };
  check("C32. a report administrator sees every signal the reports " +
        "application received in the realm", function () {
    assert.strictEqual(signals.admin.json.scope, "realm",
                       brief(signals.admin));
    assert.ok(signals.admin.json.total >= 2, brief(signals.admin));
  });
  check("C33. a report user sees the signals about themselves (their " +
        "sign-in's session-established)", function () {
    assert.strictEqual(signals.owner.json.scope, "own",
                       brief(signals.owner));
    assert.ok(signals.owner.json.total >= 1, brief(signals.owner));
    assert.ok(signals.owner.json.rows.every(function (row) {
      return String(row.subject).indexOf(ownerSub) >= 0;
    }), brief(signals.owner));
    assert.ok(signals.owner.json.rows.some(function (row) {
      return /session-established$/.test(String(row.type));
    }), brief(signals.owner));
  });
  check("C34. another report user sees none of the owner's, and an " +
        "application sees none", function () {
    assert.strictEqual(signals.shared.json.scope, "own",
                       brief(signals.shared));
    assert.ok(!signals.shared.text.includes(ownerSub), brief(signals.shared));
    assert.strictEqual(signals.app.status, 200, brief(signals.app));
    assert.strictEqual(signals.app.json.total, 0, brief(signals.app));
  });

  log.info("=== E. the access-control policy without its sharing rule ===");
  const built = await postJson(RB + "/admin-api/xacml/create-from-template", {
    template: "access-control", name: "access-control",
    p_permitReportSharing: "no" });
  check("precondition: an access-control override built with " +
        "permitReportSharing no is in force", function () {
    assert.strictEqual(built.status, 200, brief(built));
  });
  const without = [await get(tOwner, D1), await get(tShared, D1),
                   await get(tAdmin, D1), await get(tApp2, D3)];
  check("E1-E4. the owner and an application still reach their own; the " +
        "shared member and the report administrator, whose access was the " +
        "third rule's, do not", function () {
    assert.deepStrictEqual(without, [200, 404, 404, 200],
                           JSON.stringify(without));
  });
  const removed = await postJson(RB + "/admin-api/xacml/delete",
                                 { name: "access-control" });
  const restored = [await get(tShared, D1), await get(tAdmin, D1)];
  check("E5. with the override gone the built-in document decides again",
        function () {
    assert.strictEqual(removed.status, 200, brief(removed));
    assert.deepStrictEqual(restored, [200, 200], JSON.stringify(restored));
  });

  log.info("=== F. a realm's administrator is believed only there ===");
  const elsewhere = await api(Object.assign({}, tCw, { rb: base }), "GET",
                              "");
  check("F12-F13. Admin Write's token reaches the realm's report API and " +
        "is believed in no other realm (401 at the default realm's)",
        function () {
    assert.strictEqual(elsewhere.status, 401, brief(elsewhere));
  });
  const cwHere = await api(tCw, "GET", "/definitions");
  const crHere = await api(tCr, "GET", "/definitions");
  check("F1. Admin Write lists every definition as a report administrator; " +
        "Admin Read only its own", function () {
    assert.strictEqual(cwHere.status, 200, brief(cwHere));
    assert.ok(cwHere.json.total >= 2, brief(cwHere));
    assert.strictEqual(crHere.json.total, 0, brief(crHere));
  });

  log.info("=== the codes, off the audit log ===");
  const after = {};
  for (const code of Object.keys(before)) {
    after[code] = await codesSettle(code, before[code] + 1) - before[code];
  }
  check("the refusals are recorded: 0017 no report scope, 0018 a role " +
        "taken away; no answer names a code",
        function () {
    assert.ok(after["STS-REPORT-0017"] >= 1, JSON.stringify(after));
    assert.ok(after["STS-REPORT-0018"] >= 1, JSON.stringify(after));
    [afterRole].forEach(function (one) {
      assert.ok(!/STS-[A-Z]+-\d{4}/.test(one.text), brief(one));
    });
  });
  log.debug("Leaving test().");
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
    log.debug("Caught in main() removing realms: " +
              ((e && e.message) || e));
    // A removal that fails leaves a realm on a private probe; not a test
    // failure.
    log.info("could not remove the realms: " + ((e && e.message) || e));
  }
  if (failure) {
    log.error("FAILED after " + checks + " check(s): " +
              ((failure && failure.stack) || failure));
    log.debug("Leaving main().");
    process.exit(1);
  }
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving main().");
}

main();
