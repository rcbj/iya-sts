// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_device_bound_sessions.js
//
// ---------------------------------------------------------------------------
// DEVICE BOUND SESSION CREDENTIALS (#725), OVER THE WIRE.
//
// D12 (#444): carries over `tests/device_bound_sessions.js`, which played
// the browser against the whole stack in a child process and read the
// session store beside each answer. Here the browser is this file — an
// ES256 key made here, DBSC proofs (`dbsc+jwt`, the challenge as `jti`)
// signed with it as the W3C draft's section 9.10 writes them — and what the
// store held is asked the way a client or an operator can ask it: whether
// the session is HONOURED is a `prompt=none` authorization request in that
// browser (a code, or `login_required`), whether it was ENDED is
// `GET /admin-api/sessions`, and every code is read off the realm's audit
// log. In a throwaway development realm:
//
//   1. OFF, THE DEFAULT: a sign-in's answer carries no
//      Secure-Session-Registration, and both endpoints answer 404.
//   2. ON: the answer that sets the session cookie offers ES256 and RS256,
//      the registration path and a challenge.
//   3. REGISTRATION with an ES256 key: 200, the instructions (refresh URL,
//      include_site false, the bound cookie, HttpOnly SameSite=Lax), the
//      next challenge, no-store; the session row says it is bound; the
//      session is honoured beside the bound cookie, NOT without it, and not
//      ended; a second registration is refused (409).
//   4. THE COOKIE LAPSES: a refresh with no proof is a 403 with a
//      challenge for this session; the challenge signed with the bound key
//      renews the cookie and the session is honoured again.
//   5. A REPLAYED PROOF is refused (401), with no code in the answer, and
//      ends the session.
//   6. A REFRESH SIGNED BY ANOTHER KEY is refused (401), the session ended
//      and both cookies cleared.
//   7. AN UNKNOWN DBSC SESSION ID is refused (401) and the sign-on session
//      is left as it was.
//   8. A browser that never registers keeps an ordinary session.
//   9. SEVERAL ACCOUNTS IN ONE BROWSER (#561): two people sign in in one
//      jar and each registers with its own challenge, under a bound cookie
//      named for its binding; each account chosen by login_hint is honoured
//      beside ITS cookie only — never the other account in its place.
//  10. A refresh naming none of the browser's bindings is refused (401)
//      and ends nothing.
//  11. A refresh of one account signed by another key ends that account
//      alone: the other is still honoured and the default cookie kept.
//  13. Secure-Session-Skipped (#743): a well-formed list is recorded on the
//      session's row and the session stays honoured; a malformed one is
//      STS-AUTHN-0460.
//  14. include_site (#742): on, an address host keeps include_site and adds
//      no Domain.
//  15. deviceBoundRequired (#740) cannot be saved while the feature is off
//      (STS-AUTHN-0461); off saves; on saves once the feature is on.
//  16. While required: a session that SKIPPED is refused an authorization
//      code (STS-AUTHN-0462), a bound one is issued, and with the
//      requirement off again the skipped session is issued too.
//
// NOT carried (class (d)): part 12 (a second sign-in of one person in a
// browser that cannot prove the key replaces the bound session — the store
// is what says "never two of one person in the set", and the wire cannot
// tell a replaced session from a second one without the set's insides);
// 13b and 13d (the reasons not appended twice, a skip after binding not
// unbinding — fields of the binding record no answer carries); 14b
// (Domain=example.com for a DNS host: the request's Host would have to be
// another name than the one this service answers at); 16a, 16c and 16f
// (a pending session inside the issuance wait, a timed-out one and one
// never offered — asked of `issuanceGate.check()` with hand-built session
// records; over the wire the wait is a clock).
//
// REALMS ARE LEFT STANDING (tests/CLAUDE.md, *No job removes a realm*)
// unless STS_TEST_REMOVE_REALMS=1, a private probe's switch.
//
// OWNED HERE (local: true): this repository's sign-in service.
// ---------------------------------------------------------------------------

// An address compared by parsing it, not searched for as text
// (`url_match.js`).
const urls = require("./url_match.js");
const assert = require("assert");
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
var log = bunyan.createLogger({ name: "sts_device_bound_sessions",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const ORIGIN = new URL(base).origin;
const STAMP = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "")
  .slice(-10);
const REALM = "dbsc-" + STAMP;
const RB = base + "/realm/" + REALM;
const API = RB + "/admin-api";
const PASSWORD = "Dbsc-" + nodeCrypto.randomBytes(9).toString("base64url") +
  "-Aa1!";
const APP = "dbsc-app-" + STAMP;
const SECRET = "dbsc-secret-" + STAMP + "-" +
  nodeCrypto.randomBytes(16).toString("hex");
const REDIRECT = "https://" + APP + ".example.test/cb";
const FLOOR = 24;

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

function who(name) {
  log.debug("Entering who().");
  log.debug("Leaving who().");
  return names.usernameFor("dbsc-" + name);
}

async function call(method, url, body, headers) {
  log.debug("Entering call(). " + method + " " + url);
  const r = await fetch(url, { method: method, redirect: "manual",
    headers: Object.assign({ "Content-Type": "application/json" },
                           headers || {}),
    body: body === undefined ? undefined :
          (typeof body === "string" ? body : JSON.stringify(body)) });
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
    // Not JSON; `text` carries it into the message.
    json = null;
  }
  log.debug("Leaving call(). status=" + r.status);
  return { status: r.status, json: json, text: text };
}

async function ok(url, body, what) {
  log.debug("Entering ok().");
  const r = await call("POST", url, body);
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
            what + ": " + r.status + " " + r.text.slice(0, 400));
  log.debug("Leaving ok().");
  return r.json;
}

function setting(key, value) {
  log.debug("Entering setting(). " + key);
  log.debug("Leaving setting().");
  return ok(base + "/admin-api/realms/set", { id: REALM, key: key,
    value: String(value) }, "set " + key + " on " + REALM);
}

// THE CODES ARE RECORDED, NEVER SENT: read off this realm's audit log.
async function codeCount(code) {
  log.debug("Entering codeCount(). " + code);
  const r = await call("GET", API + "/audit?per=500&code=" +
                       encodeURIComponent(code));
  log.debug("Leaving codeCount().");
  return Number((r.json && r.json.matched) || 0);
}

async function codesSettle(code, atLeast) {
  log.debug("Entering codesSettle(). " + code);
  let n = await codeCount(code);
  for (let i = 0; i < 40 && n < atLeast; i += 1) {
    await sleep(150);
    n = await codeCount(code);
  }
  log.debug("Leaving codesSettle(). " + n);
  return n;
}

// THE SESSION ROWS of one person, as /admin-api/sessions lists them.
async function rowsOf(username) {
  log.debug("Entering rowsOf(). " + username);
  const r = await call("GET", API + "/sessions?per=100&q=" +
                       encodeURIComponent(username));
  const rows = ((r.json && r.json.sessions) || []).filter(function (row) {
    return row.username === username && row.sessionId;
  });
  log.debug("Leaving rowsOf(). " + rows.length);
  return rows;
}

async function live(sid, username) {
  log.debug("Entering live().");
  const rows = await rowsOf(username);
  log.debug("Leaving live().");
  return rows.filter(function (row) {
    return row.sessionId === sid;
  })[0] || null;
}

// ---------------------------------------------------------------------------
// THE BROWSER'S KEY, AND A PROOF MADE WITH IT.
// ---------------------------------------------------------------------------
function keyPair() {
  log.debug("Entering keyPair().");
  const pair = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = pair.publicKey.export({ format: "jwk" });
  log.debug("Leaving keyPair().");
  return { privateKey: pair.privateKey,
           jwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } };
}

function b64(obj) {
  log.debug("Entering b64().");
  log.debug("Leaving b64().");
  return Buffer.from(JSON.stringify(obj)).toString("base64url");
}

function proof(key, challenge, withJwk) {
  log.debug("Entering proof().");
  const header = { alg: "ES256", typ: "dbsc+jwt" };
  if (withJwk) {
    header.jwk = key.jwk;
  }
  const input = b64(header) + "." + b64({ jti: challenge });
  const sig = nodeCrypto.sign("sha256", Buffer.from(input),
    { key: key.privateKey, dsaEncoding: "ieee-p1363" });
  log.debug("Leaving proof().");
  return input + "." + sig.toString("base64url");
}

function quoted(text) {
  log.debug("Entering quoted().");
  log.debug("Leaving quoted().");
  return '"' + text + '"';
}

// Secure-Session-Registration: `(ES256 RS256);path="…";challenge="…"`.
function offerOf(raw) {
  log.debug("Entering offerOf().");
  if (!raw) {
    log.debug("Leaving offerOf(). None.");
    return null;
  }
  const algs = (/\(([^)]*)\)/.exec(raw) || [])[1] || "";
  const pathOf = (/;\s*path="([^"]*)"/.exec(raw) || [])[1] || "";
  const challenge = (/;\s*challenge="([^"]*)"/.exec(raw) || [])[1] || "";
  log.debug("Leaving offerOf().");
  return { algs: algs.trim().split(/\s+/), path: pathOf,
           challenge: challenge };
}

// Secure-Session-Challenge: `"challenge";id="…"`.
function challengeOf(raw) {
  log.debug("Entering challengeOf().");
  if (!raw) {
    log.debug("Leaving challengeOf(). None.");
    return null;
  }
  const challenge = (/^\s*"([^"]*)"/.exec(raw) || [])[1] || "";
  const id = (/;\s*id="([^"]*)"/.exec(raw) || [])[1] || "";
  log.debug("Leaving challengeOf().");
  return { challenge: challenge, id: id };
}

// ---------------------------------------------------------------------------
// ONE BROWSER: a cookie jar, name to value.
// ---------------------------------------------------------------------------
function keepCookies(jar, lines) {
  log.debug("Entering keepCookies().");
  (lines || []).forEach(function (one) {
    const pair = String(one).split(";")[0];
    const at = pair.indexOf("=");
    if (at <= 0) {
      return;
    }
    const value = pair.slice(at + 1);
    if (value === "" || /Max-Age=0/i.test(String(one)) ||
        /Expires=Thu, 01 Jan 1970/i.test(String(one))) {
      delete jar[pair.slice(0, at)];
    } else {
      jar[pair.slice(0, at)] = value;
    }
  });
  log.debug("Leaving keepCookies().");
}

function cookieOf(jar) {
  log.debug("Entering cookieOf().");
  log.debug("Leaving cookieOf().");
  return Object.keys(jar).map(function (k) {
    return k + "=" + jar[k];
  }).join("; ");
}

async function go(jar, method, url, headers, body) {
  log.debug("Entering go(). " + method);
  const h = Object.assign({}, headers || {});
  const cookie = cookieOf(jar);
  if (cookie) {
    h.cookie = cookie;
  }
  const absolute = new URL(String(url), base + "/").toString();
  const r = await fetch(absolute, { method: method, redirect: "manual",
                                    headers: h, body: body });
  const setCookies = r.headers.getSetCookie ? r.headers.getSetCookie() : [];
  keepCookies(jar, setCookies);
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in go(): " + ((e && e.message) || e));
    // Not JSON: a page, read as text.
    json = null;
  }
  const location = r.headers.get("location")
    ? new URL(r.headers.get("location"), absolute).toString() : "";
  log.debug("Leaving go(). status=" + r.status);
  return { status: r.status, location: location, text: text, json: json,
           setCookies: setCookies,
           header: function (name) {
             return r.headers.get(name) || "";
           } };
}

// A DBSC request: a POST with no body, the headers given.
function dbsc(jar, path, headers) {
  log.debug("Entering dbsc().");
  log.debug("Leaving dbsc().");
  return go(jar, "POST", new URL(path, ORIGIN).toString(), headers, "");
}

function authorizeUrl(extra) {
  log.debug("Entering authorizeUrl().");
  const url = RB + "/oauth2/authorize?" + new URLSearchParams(Object.assign({
    response_type: "code", client_id: APP, redirect_uri: REDIRECT,
    scope: "openid", state: "st-" + nodeCrypto.randomBytes(6)
      .toString("hex"),
    nonce: "n-" + nodeCrypto.randomBytes(9).toString("base64url") },
    extra || {})).toString();
  log.debug("Leaving authorizeUrl().");
  return url;
}

// Follows redirects on this service; stops at the sign-in screen, at the
// client's redirect URI, or at a page.
async function follow(jar, url, headers) {
  log.debug("Entering follow().");
  let r = await go(jar, "GET", url, headers);
  for (let hops = 0; hops < 12; hops += 1) {
    if (r.status < 300 || r.status >= 400 || !r.location) {
      break;
    }
    if (/\/authn\/(login|accounts)\?/.test(r.location) ||
        new URL(r.location).origin !== ORIGIN) {
      break;
    }
    r = await go(jar, "GET", r.location, headers);
  }
  log.debug("Leaving follow(). " + r.status);
  return r;
}

// HONOURED: a prompt=none request in this browser is answered a code.
async function honoured(jar, hint, headers) {
  log.debug("Entering honoured().");
  const extra = { prompt: "none" };
  if (hint) {
    extra.login_hint = hint;
  }
  const r = await follow(jar, authorizeUrl(extra), headers);
  const at = r.location && urls.isAt(r.location, REDIRECT)
    ? new URL(r.location).searchParams : null;
  log.debug("Leaving honoured().");
  return { code: at ? at.get("code") || "" : "",
           error: at ? at.get("error") || "" : "(stopped at " + r.status +
             " " + r.location + ")" };
}

// A SIGN-IN in `jar`: the authorization request to the screen, the
// password, and an optional set-up offer ignored. Answers the session id
// and the Secure-Session-Registration the answer that set the cookie
// carried.
async function signIn(username, given) {
  log.debug("Entering signIn(). " + username);
  const jar = given || {};
  const r = await follow(jar, authorizeUrl({ prompt: "login" }));
  assert.ok(/\/authn\/login\?/.test(r.location),
            "the sign-in screen for " + username + ": " + r.status + " " +
            r.location);
  const answer = await authnSignin.submit(RB, r.location,
    { action: "login", username: username, password: PASSWORD },
    { cookie: cookieOf(jar) });
  keepCookies(jar, answer.setCookies);
  let offer = answer.headers.get("secure-session-registration") || "";
  const after = await authnSignin.ignoreOffer(RB, answer);
  if (after !== answer) {
    keepCookies(jar, after.setCookies);
    offer = offer || (after.headers && after.headers
      .get("secure-session-registration")) || "";
  }
  assert.ok(after.next === "redirect",
            "signing in as " + username + " should answer a redirect: " +
            after.status + " " + after.next + " " +
            String(after.text).slice(0, 300));
  log.debug("Leaving signIn().");
  return { jar: jar, sid: String(jar.sts_session || "").split(".")[0],
           offer: offerOf(offer), raw: offer };
}

async function register(username, key, given) {
  log.debug("Entering register(). " + username);
  const s = await signIn(username, given);
  assert.ok(s.offer && s.offer.path, "an offer for " + username + ": " +
            s.raw);
  const r = await dbsc(s.jar, s.offer.path, {
    "secure-session-response": quoted(proof(key, s.offer.challenge, true))
  });
  log.debug("Leaving register().");
  return { s: s, r: r, instr: r.json || {},
           cookie: (((r.json || {}).credentials || [])[0] || {}).name };
}

// A REFRESH: asked for a challenge, then answered signed with `key`.
async function refresh(jar, id, key) {
  log.debug("Entering refresh().");
  const asked = await dbsc(jar, "/realm/" + REALM + "/authn/dbsc/refresh",
                           { "sec-secure-session-id": quoted(id) });
  const next = challengeOf(asked.header("secure-session-challenge"));
  if (!next) {
    log.debug("Leaving refresh(). No challenge.");
    return { asked: asked, answered: null };
  }
  const answered = await dbsc(jar, "/realm/" + REALM +
    "/authn/dbsc/refresh", { "sec-secure-session-id": quoted(id),
      "secure-session-response": quoted(proof(key, next.challenge,
                                              false)) });
  log.debug("Leaving refresh().");
  return { asked: asked, next: next, answered: answered };
}

// THE PASSKEY POLICY'S deviceBoundRequired (#740), saved whole through the
// door the console's page uses: every row at its default (GET
// /admin-api/policies), this one member set.
async function savePolicy(required) {
  log.debug("Entering savePolicy(). " + required);
  const page = await call("GET", API + "/policies");
  const fields = (page.json && page.json.passkey &&
                  page.json.passkey.fields) || [];
  assert.ok(fields.length, "GET /admin-api/policies answered no passkey " +
            "fields: " + page.status + " " + page.text.slice(0, 200));
  const body = { profile: "default" };
  fields.forEach(function (field) {
    body[field.key] = field.default;
  });
  body.deviceBoundRequired = required;
  const r = await call("POST", API + "/policies/save-passkey-policy", body);
  log.debug("Leaving savePolicy(). " + r.status);
  return r;
}

async function setUp() {
  log.debug("Entering setUp().");
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "DBSC " + STAMP,
    overrides: { "global.mode": "development" } }, "created the realm");
  // One address signing many people in, in seconds, is what risk scoring
  // counts (sts_admin_client_policies.js's reason).
  await setting("risk.assessSignIns", false);
  // Parts 1 to 8 are one session per browser, as the in-process file has
  // it; part 9 turns several accounts on.
  await setting("authn.multipleAccounts", false);
  await ok(API + "/applications/create", {
    identifier: APP, name: "DBSC " + STAMP, protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: [APP], oauthRedirectUri: [REDIRECT],
              oauthClientSecret: SECRET,
              oauthTokenEndpointAuthMethod: "client_secret_basic",
              oauthAllowedScope: ["openid"] } },
    "created the relying party");
  await ok(API + "/consent/grant-global-consent",
           { client: APP, scope: "openid" }, "consented openid");
  log.debug("Leaving setUp().");
}

async function people(list) {
  log.debug("Entering people().");
  for (const one of list) {
    await registry.ensurePerson(RB, who(one), PASSWORD);
  }
  log.debug("Leaving people().");
}

// ---------------------------------------------------------------------------
// THE SECTIONS.
// ---------------------------------------------------------------------------
async function partsOneToEight() {
  log.debug("Entering partsOneToEight().");
  log.info("=== 1. off, the default ===");
  let s = await signIn(who("off"));
  const off1 = await dbsc(s.jar, "/realm/" + REALM + "/authn/dbsc/register",
                          {});
  const off2 = await dbsc(s.jar, "/realm/" + REALM + "/authn/dbsc/refresh",
                          { "sec-secure-session-id": '"x"' });
  check("1. off: the sign-in sets the session cookie and offers no " +
        "registration, and both endpoints answer 404", function () {
    assert.ok(s.sid, JSON.stringify(Object.keys(s.jar)));
    assert.strictEqual(s.offer, null, s.raw);
    assert.strictEqual(off1.status, 404, off1.text.slice(0, 200));
    assert.strictEqual(off2.status, 404, off2.text.slice(0, 200));
  });

  await setting("authn.deviceBoundSessions", true);

  log.info("=== 2. the offer ===");
  s = await signIn(who("ann"));
  check("2. on: the answer that sets the session cookie offers (ES256 " +
        "RS256), the registration path and a challenge", function () {
    assert.ok(s.offer, "no Secure-Session-Registration");
    assert.strictEqual(s.offer.algs.join(" "), "ES256 RS256", s.raw);
    assert.ok(/\/authn\/dbsc\/register$/.test(s.offer.path), s.raw);
    assert.ok(s.offer.challenge, s.raw);
  });

  log.info("=== 3. registration ===");
  const key = keyPair();
  const reg = await dbsc(s.jar, s.offer.path, {
    "secure-session-response": quoted(proof(key, s.offer.challenge, true))
  });
  const instr = reg.json || {};
  const cred = (instr.credentials || [])[0] || {};
  const first = challengeOf(reg.header("secure-session-challenge"));
  check("3a. registration with an ES256 key answers the instructions, the " +
        "bound cookie and the next challenge, no-store", function () {
    assert.strictEqual(reg.status, 200, reg.text.slice(0, 400));
    assert.ok(instr.session_identifier, reg.text.slice(0, 400));
    assert.ok(/\/authn\/dbsc\/refresh$/.test(instr.refresh_url),
              instr.refresh_url);
    assert.strictEqual(instr.scope && instr.scope.include_site, false);
    assert.strictEqual(cred.type, "cookie");
    assert.ok(/^sts_session_bound/.test(cred.name), cred.name);
    assert.ok(/HttpOnly/.test(cred.attributes) &&
              /SameSite=Lax/.test(cred.attributes), cred.attributes);
    assert.ok(s.jar[cred.name], JSON.stringify(Object.keys(s.jar)));
    assert.ok(first && first.id === instr.session_identifier,
              reg.header("secure-session-challenge"));
    assert.ok(/no-store/.test(reg.header("cache-control")),
              reg.header("cache-control"));
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(reg.text));
  });
  const dbscId = instr.session_identifier;
  const row = await live(s.sid, who("ann"));
  check("3b. the session's row says it is bound, by ES256", function () {
    assert.ok(row, "no row for the session");
    assert.ok(row.deviceBound && row.deviceBound.bound === true &&
              row.deviceBound.alg === "ES256",
              JSON.stringify(row && row.deviceBound));
  });
  const withCookie = await honoured(s.jar);
  const lapsed = Object.assign({}, s.jar);
  delete lapsed[cred.name];
  const without = await honoured(lapsed);
  const stillThere = await live(s.sid, who("ann"));
  check("3c-d. honoured beside its bound cookie; without it not honoured, " +
        "and not ended", function () {
    assert.ok(withCookie.code, withCookie.error);
    assert.ok(!without.code, "a code without the bound cookie");
    assert.ok(stillThere, "the session was ended");
  });
  const second = await dbsc(s.jar, s.offer.path, {
    "secure-session-response": quoted(proof(keyPair(), s.offer.challenge,
                                            true)) });
  check("3e. a second registration is refused (409)", function () {
    assert.strictEqual(second.status, 409, second.text.slice(0, 200));
  });

  log.info("=== 4. the cookie lapses; refresh ===");
  delete s.jar[cred.name];
  const asked = await dbsc(s.jar, "/realm/" + REALM + "/authn/dbsc/refresh",
                           { "sec-secure-session-id": quoted(dbscId) });
  const next = challengeOf(asked.header("secure-session-challenge"));
  check("4a. a refresh with no proof is a 403 carrying a challenge for " +
        "this session", function () {
    assert.strictEqual(asked.status, 403, asked.text.slice(0, 200));
    assert.ok(next && next.id === dbscId && next.challenge,
              asked.header("secure-session-challenge"));
  });
  const signed = proof(key, next.challenge, false);
  const renewed = await dbsc(s.jar, "/realm/" + REALM +
    "/authn/dbsc/refresh", { "sec-secure-session-id": quoted(dbscId),
      "secure-session-response": quoted(signed) });
  const again = await honoured(s.jar);
  const counted = await live(s.sid, who("ann"));
  check("4b-c. the challenge signed with the bound key renews the bound " +
        "cookie; the session is honoured again and the refresh counted",
        function () {
    assert.strictEqual(renewed.status, 200, renewed.text.slice(0, 300));
    assert.ok(s.jar[cred.name], "no bound cookie after the refresh");
    assert.strictEqual(renewed.json.session_identifier, dbscId);
    assert.ok(again.code, again.error);
    assert.strictEqual(counted && counted.deviceBound.refreshes, 1,
                       JSON.stringify(counted && counted.deviceBound));
  });

  log.info("=== 5. a replayed proof ===");
  const replay = await dbsc(s.jar, "/realm/" + REALM +
    "/authn/dbsc/refresh", { "sec-secure-session-id": quoted(dbscId),
      "secure-session-response": quoted(signed) });
  const afterReplay = await live(s.sid, who("ann"));
  check("5. the same proof again is refused (401), no code sent, and the " +
        "session ended", function () {
    assert.strictEqual(replay.status, 401, replay.text.slice(0, 200));
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(replay.text), replay.text);
    assert.strictEqual(afterReplay, null);
  });

  log.info("=== 6. another key ===");
  const bob = await register(who("bob"), keyPair());
  const stolen = await refresh(bob.s.jar, bob.instr.session_identifier,
                               keyPair());
  const bobRow = await live(bob.s.sid, who("bob"));
  check("6. a refresh signed by another key is refused (401), the session " +
        "ended and both cookies cleared", function () {
    assert.strictEqual(bob.r.status, 200, bob.r.text.slice(0, 200));
    assert.ok(stolen.answered, "no challenge to answer");
    assert.strictEqual(stolen.answered.status, 401,
                       stolen.answered.text.slice(0, 200));
    assert.strictEqual(bobRow, null);
    assert.ok(!bob.s.jar.sts_session && !bob.s.jar[bob.cookie],
              JSON.stringify(Object.keys(bob.s.jar)));
  });

  log.info("=== 7. an unknown DBSC session ===");
  const cy = await register(who("cy"), keyPair());
  const unknown = await dbsc(cy.s.jar, "/realm/" + REALM +
    "/authn/dbsc/refresh", { "sec-secure-session-id":
      quoted("not-this-one") });
  const cyRow = await live(cy.s.sid, who("cy"));
  check("7. a refresh naming another DBSC session is refused (401) and the " +
        "sign-on session is left as it was", function () {
    assert.strictEqual(unknown.status, 401, unknown.text.slice(0, 200));
    assert.ok(cyRow, "the session was ended");
  });

  log.info("=== 8. a browser without DBSC ===");
  const dan = await signIn(who("dan"));
  const danHonoured = await honoured(dan.jar);
  check("8. a browser that never registers keeps an ordinary session, " +
        "honoured with no bound cookie", function () {
    assert.ok(dan.offer, dan.raw);
    assert.ok(danHonoured.code, danHonoured.error);
    assert.ok(!Object.keys(dan.jar).some(function (k) {
      return /^sts_session_bound/.test(k);
    }));
  });
  log.debug("Leaving partsOneToEight().");
}

async function severalAccounts() {
  log.debug("Entering severalAccounts().");
  log.info("=== 9. several accounts in one browser (#561) ===");
  await setting("authn.multipleAccounts", true);
  const jar = {};
  const aliceKey = keyPair();
  const bobbyKey = keyPair();
  const alice = await signIn(who("alice"), jar);
  const bobby = await signIn(who("bobby"), jar);
  check("9a. two people sign in in one browser and both stay signed in",
        function () {
    assert.ok(alice.sid && bobby.sid && alice.sid !== bobby.sid,
              alice.sid + " " + bobby.sid);
    assert.ok(alice.offer && bobby.offer, alice.raw + " / " + bobby.raw);
  });
  const bobReg = await dbsc(jar, bobby.offer.path, {
    "secure-session-response": quoted(proof(bobbyKey, bobby.offer.challenge,
                                            true)) });
  const bobInstr = bobReg.json || {};
  const bobCookie = ((bobInstr.credentials || [])[0] || {}).name;
  const aliceReg = await dbsc(jar, alice.offer.path, {
    "secure-session-response": quoted(proof(aliceKey, alice.offer.challenge,
                                            true)) });
  const aliceInstr = aliceReg.json || {};
  const aliceCookie = ((aliceInstr.credentials || [])[0] || {}).name;
  const aliceRow = await live(alice.sid, who("alice"));
  const bobbyRow = await live(bobby.sid, who("bobby"));
  check("9b-c. each account's challenge binds that account, under a bound " +
        "cookie named for its binding, both held at once", function () {
    assert.strictEqual(bobReg.status, 200, bobReg.text.slice(0, 300));
    assert.strictEqual(aliceReg.status, 200, aliceReg.text.slice(0, 300));
    assert.ok(new RegExp(bobInstr.session_identifier + "$").test(bobCookie),
              bobCookie + " " + bobInstr.session_identifier);
    assert.notStrictEqual(aliceCookie, bobCookie);
    assert.ok(jar[aliceCookie] && jar[bobCookie],
              JSON.stringify(Object.keys(jar)));
    assert.ok(aliceRow.deviceBound.bound && bobbyRow.deviceBound.bound);
  });
  const a1 = await honoured(jar, who("alice"));
  const b1 = await honoured(jar, who("bobby"));
  const noAlice = Object.assign({}, jar);
  delete noAlice[aliceCookie];
  const a2 = await honoured(noAlice, who("alice"));
  const b2 = await honoured(noAlice, who("bobby"));
  const crossed = Object.assign({}, noAlice);
  crossed[aliceCookie] = jar[bobCookie];
  const a3 = await honoured(crossed, who("alice"));
  check("9d-f. each account chosen by login_hint is honoured beside its " +
        "own bound cookie; without it, not honoured and NOT replaced by " +
        "the other; another binding's cookie does not stand in",
        function () {
    assert.ok(a1.code && b1.code, a1.error + " " + b1.error);
    assert.ok(!a2.code, "alice honoured without her bound cookie");
    assert.ok(b2.code, b2.error);
    assert.ok(!a3.code, "another binding's cookie stood in for alice's");
  });

  log.info("=== 10. a refresh naming none of the bindings ===");
  const none = await dbsc(jar, "/realm/" + REALM + "/authn/dbsc/refresh",
                          { "sec-secure-session-id":
                              quoted("none-of-these") });
  const aliceStill = await live(alice.sid, who("alice"));
  const bobbyStill = await live(bobby.sid, who("bobby"));
  check("10b. a refresh naming no account's binding is refused (401) and " +
        "ends nothing", function () {
    assert.strictEqual(none.status, 401, none.text.slice(0, 200));
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(none.text), none.text);
    assert.ok(aliceStill && bobbyStill);
  });

  log.info("=== 11. another key ends that account only ===");
  const defaultBefore = jar.sts_session;
  const stolen = await refresh(jar, aliceInstr.session_identifier,
                               keyPair());
  const aliceGone = await live(alice.sid, who("alice"));
  const bobbyLeft = await honoured(jar, who("bobby"));
  check("11. a refresh of one account signed by another key ends that " +
        "account alone; its bound cookie is cleared, the other's and the " +
        "default cookie kept, and the other is still honoured", function () {
    assert.ok(stolen.answered, "no challenge to answer");
    assert.strictEqual(stolen.answered.status, 401,
                       stolen.answered.text.slice(0, 200));
    assert.strictEqual(aliceGone, null);
    assert.ok(!jar[aliceCookie] && jar[bobCookie],
              JSON.stringify(Object.keys(jar)));
    assert.strictEqual(jar.sts_session, defaultBefore);
    assert.strictEqual(String(defaultBefore).split(".")[0], bobby.sid);
    assert.ok(bobbyLeft.code, bobbyLeft.error);
  });
  await setting("authn.multipleAccounts", false);
  log.debug("Leaving severalAccounts().");
}

async function skippedAndSite() {
  log.debug("Entering skippedAndSite().");
  log.info("=== 13. Secure-Session-Skipped (#743) ===");
  const skip = await signIn(who("skip"));
  const seen = await honoured(skip.jar, "", {
    "secure-session-skipped":
      'unreachable;session_identifier="abc", quota_exceeded' });
  const skipRow = await live(skip.sid, who("skip"));
  check("13a. a well-formed Secure-Session-Skipped is recorded on the " +
        "session's row, and the session stays honoured", function () {
    assert.ok(seen.code, seen.error);
    const b = (skipRow && skipRow.deviceBound) || {};
    assert.ok(!b.bound, JSON.stringify(b));
    assert.ok(JSON.stringify(b).indexOf("skipped") >= 0 ||
              JSON.stringify(b).indexOf("unreachable") >= 0,
              JSON.stringify(b));
  });
  const mal = await signIn(who("mal"));
  const malBefore = await codeCount("STS-AUTHN-0460");
  await honoured(mal.jar, "", { "secure-session-skipped": '"not-a-token"' });
  const malAfter = await codesSettle("STS-AUTHN-0460", malBefore + 1);
  check("13c. a malformed skip is recorded STS-AUTHN-0460", function () {
    assert.ok(malAfter > malBefore, malBefore + " -> " + malAfter);
  });

  log.info("=== 14. include_site (#742) ===");
  await setting("authn.deviceBoundIncludeSite", true);
  try {
    const loop = await register(who("loop"), keyPair());
    const scope = loop.instr.scope || {};
    const attrs = String((((loop.instr.credentials || [])[0]) || {})
      .attributes || "");
    check("14c. on, a host that is an address keeps include_site and adds " +
          "no Domain", function () {
      assert.strictEqual(loop.r.status, 200, loop.r.text.slice(0, 200));
      assert.strictEqual(scope.include_site, true, JSON.stringify(scope));
      assert.ok(!/Domain=/.test(attrs), attrs);
    });
  } finally {
    await setting("authn.deviceBoundIncludeSite", false);
  }
  log.debug("Leaving skippedAndSite().");
}

async function required() {
  log.debug("Entering required().");
  log.info("=== 15. requiring a bound session (#740) ===");
  await setting("authn.deviceBoundSessions", false);
  const before = await codeCount("STS-AUTHN-0461");
  const refusedOn = await savePolicy(true);
  const after = await codesSettle("STS-AUTHN-0461", before + 1);
  const savedOff = await savePolicy(false);
  check("15a-b. deviceBoundRequired cannot be saved while the feature is " +
        "off (STS-AUTHN-0461); saving it off succeeds", function () {
    assert.strictEqual(refusedOn.status, 400, refusedOn.text.slice(0, 300));
    assert.ok(after > before, before + " -> " + after + " " +
              refusedOn.text.slice(0, 300));
    assert.strictEqual(savedOff.status, 200, savedOff.text.slice(0, 300));
  });
  await setting("authn.deviceBoundSessions", true);
  const savedOn = await savePolicy(true);
  check("15c. the requirement saves while device-bound sessions are on",
        function () {
    assert.strictEqual(savedOn.status, 200, savedOn.text.slice(0, 300));
  });

  log.info("=== 16. issuance refuses a skipped session, allows a bound " +
           "one ===");
  const skipped = await signIn(who("req-skip"));
  // The browser says it will not bind: the skip is recorded, and the
  // session is then one a bound session was required of and did not get.
  await honoured(skipped.jar, "", { "secure-session-skipped":
                                      "unreachable" });
  const r0462 = await codeCount("STS-AUTHN-0462");
  const refusedCode = await honoured(skipped.jar);
  const r0462After = await codesSettle("STS-AUTHN-0462", r0462 + 1);
  const bound = await register(who("req-bound"), keyPair());
  const boundCode = await honoured(bound.s.jar);
  check("16b, 16d. while required, a skipped session is refused a code " +
        "(STS-AUTHN-0462) and a bound one is issued", function () {
    assert.ok(!refusedCode.code, "a code for a skipped session");
    assert.ok(r0462After > r0462, r0462 + " -> " + r0462After);
    assert.ok(boundCode.code, boundCode.error);
  });
  const offAgain = await savePolicy(false);
  const open = await honoured(skipped.jar);
  check("16e. with the requirement off again, the skipped session is " +
        "issued", function () {
    assert.strictEqual(offAgain.status, 200, offAgain.text.slice(0, 300));
    assert.ok(open.code, open.error);
  });
  await setting("authn.deviceBoundSessions", false);
  log.debug("Leaving required().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Device Bound Session Credentials at " + base + ", realm " +
           REALM);
  await setUp();
  await people(["off", "ann", "bob", "cy", "dan", "alice", "bobby", "skip",
                "mal", "loop", "req-skip", "req-bound"]);
  await partsOneToEight();
  await severalAccounts();
  await skippedAndSite();
  await required();
  assert.ok(checks >= FLOOR, "only " + checks + " checks ran");
  log.info(checks + " check(s) passed.");
  log.debug("Leaving test().");
}

// REMOVAL IS OPT-IN: with STS_TEST_REMOVE_REALMS=1 (a private probe that
// would otherwise fill its directory) the realm is removed at the end, pass
// or fail. A suite run leaves it standing (tests/CLAUDE.md, *No job removes
// a realm*).
async function removeRealms() {
  log.debug("Entering removeRealms().");
  if (process.env.STS_TEST_REMOVE_REALMS !== "1") {
    log.debug("Leaving removeRealms(). Not asked to.");
    return;
  }
  const r = await call("POST", base + "/admin-api/realms/remove",
                       { id: REALM });
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
    log.info("could not remove the realm: " + ((e && e.message) || e));
  }
  if (failure) {
    log.error(failure.stack || failure.message);
    log.debug("Leaving main(). Failed.");
    process.exit(1);
  }
  log.info("Test completed successfully.");
  log.debug("Leaving main().");
}

main();
