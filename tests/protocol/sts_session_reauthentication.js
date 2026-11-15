// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_session_reauthentication.js
//
// ---------------------------------------------------------------------------
// THE SAME PERSON SIGNING IN AGAIN IS A RE-AUTHENTICATION, AND A SESSION
// COOKIE IS `<sid>.<handle>`, OVER THE WIRE (2026-09-14).
//
// D12 (#444): carries over the part of `tests/session_reauthentication.js`
// a browser, a relying party and a Shared Signals receiver see. In a
// development realm of its own with `oauth2.rfc9700` on for the realm (the
// half the in-process file ran in a child process for) and
// `authn.multipleAccounts` off (one session per browser, the arrangement
// the in-process file asserts; with it on, section 7's other person ADDS
// an account, which the multi-account jobs hold), a person signs in
// through the code flow and then proves themselves again in the same
// browser with `prompt=login`:
//
//   1. the cookie is `<sid>.<handle>`, the sid the one the ID Token names;
//   2. after the re-authentication the ID Token's `sid` is UNCHANGED and
//      its `auth_time` is the new sign-in's;
//   3. the cookie is ROTATED: the same sid, a new handle; the OLD cookie no
//      longer opens the session in a browser of its own, the new one does,
//      and a BARE sid is not a cookie at all;
//   4. the realm holds ONE session for the person, not a copy;
//   5. RFC 9700 MODE: the refresh token issued before the re-authentication
//      still refreshes — a re-authentication revokes nothing;
//   6. a re-authentication that leaves `acr` where it was tells a CAEP
//      receiver NOTHING about that session — no session-revoked, no
//      assurance-level-change;
//   7. somebody else signing in on that browser gets a session of their own
//      and the first person's ENDS: their cookie opens nothing, and CAEP
//      is told session-revoked.
//
// NOT carried, and why: that the record is the same object and not a copy
// put back under the same key, its two authentication events, when it
// BEGAN against its absolute expiry, the relying parties kept on it, the
// portal session derived from it, the observer's `reauthenticated` notice
// and a keyed API session's extension are facts of the session store no
// answer states (class (d)); the step-DOWN case (a weaker re-authentication
// lowering `acr`, the CAEP assurance-level-change saying `decrease`) needs a
// second factor at the first sign-in and is owed with the TOTP doors'
// jobs (`sts_second_factor_doors`).
//
// OWNED HERE (local: true): this repository's own sessions.
// ---------------------------------------------------------------------------

// The sign-in screen over `/authn-api` (#571).
const authnSignin = require("./authn_signin");
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
var log = bunyan.createLogger({ name: "sts_session_reauthentication",
                                level: appconfig.LOG_LEVEL ||
                                       process.env.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "")
  .slice(-10);
// A password this process made: product checks it.
const PASSWORD = "Reauth-" + nodeCrypto.randomBytes(9).toString("base64url") +
  "-9a!";
// A desktop browser's User-Agent with this job's name on the end: risk
// scoring reads a bare job name as an automated client, and product refuses
// a first sign-in from one (#62).
const AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 " +
  "sts_session_reauthentication/1.0 (" + STAMP + ")";

let checks = 0;
const failures = [];

// ONE CHECK. A failure is recorded and the run carries on; setup that later
// sections depend on uses `must()`, which throws.
async function check(what, fn) {
  log.debug("Entering check(). " + what);
  try {
    await fn();
    checks += 1;
    log.info("  [ok] " + what);
  } catch (e) {
    log.debug("Caught in check(): " + ((e && e.message) || e));
    failures.push(what + " — " + ((e && e.message) || e));
    log.error("  [FAILED] " + what + "  — " + ((e && e.message) || e));
  }
  log.debug("Leaving check().");
}

function must(condition, message) {
  log.debug("Entering must().");
  if (!condition) {
    log.debug("Leaving must(). Refused.");
    throw new Error("SETUP: " + message);
  }
  log.debug("Leaving must().");
}

function expect(condition, message) {
  log.debug("Entering expect().");
  if (!condition) {
    log.debug("Leaving expect(). Refused.");
    throw new Error(String(message));
  }
  log.debug("Leaving expect().");
}

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

function form(o) {
  log.debug("Entering form().");
  log.debug("Leaving form().");
  return new URLSearchParams(o).toString();
}

function realmBase(realm) {
  log.debug("Entering realmBase().");
  log.debug("Leaving realmBase().");
  return base + "/realm/" + realm;
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
  return { status: r.status, body: body, raw: raw,
           location: r.headers.get("location") || "", headers: r.headers };
}

function postJson(url, payload) {
  log.debug("Entering postJson().");
  log.debug("Leaving postJson().");
  return send(url, { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}) });
}

// The management API of a realm (`realm` null: the root's). The run's admin
// token is attached by the preload (`tools/attach-admin-token.js`).
function api(realm, method, p, payload) {
  log.debug("Entering api(). " + method + " " + p);
  const url = (realm ? realmBase(realm) : base) + "/admin-api" + p;
  log.debug("Leaving api().");
  if (method === "GET") {
    return send(url);
  }
  return postJson(url, payload);
}

async function apiOk(realm, p, payload, what) {
  log.debug("Entering apiOk(). " + p);
  const r = await api(realm, "POST", p, payload);
  must(r.status === 200 && r.body && r.body.ok !== false,
       (what || p) + " answered " + r.status + " " + r.raw.slice(0, 400));
  log.debug("Leaving apiOk().");
  return r.body;
}

const MADE = [];
async function makeRealm(stem, mode) {
  log.debug("Entering makeRealm(). " + stem);
  const id = (stem + "-" + STAMP).slice(0, 31);
  await apiOk(null, "/realms/create", { id: id, domain: id + ".example.net",
    name: stem + " " + STAMP }, "created the realm " + id);
  MADE.push(id);
  await apiOk(null, "/realms/set", { id: id, key: "global.mode",
    value: mode }, "set " + id + " to " + mode);
  log.debug("Leaving makeRealm(). " + id);
  return id;
}

function setting(realm, key, value) {
  log.debug("Entering setting(). " + key + "=" + value);
  log.debug("Leaving setting().");
  return apiOk(null, "/realms/set", { id: realm, key: key,
    value: String(value) }, "set " + key + " on " + realm);
}

async function createPerson(realm, username, extra) {
  log.debug("Entering createPerson(). " + username);
  const body = await apiOk(realm, "/users/create", Object.assign({
    username: username, invent: false,
    attributes: { cn: "Probe " + username, givenName: "Probe",
                  sn: username, mail: username + "@" + realm + ".example" },
    credential: "password", password: PASSWORD }, extra || {}),
  "created " + username);
  log.debug("Leaving createPerson().");
  return body;
}

// How many of a realm's audit rows carry `code`.
async function codeCount(realm, code) {
  log.debug("Entering codeCount(). " + code);
  const r = await api(realm, "GET", "/audit?per=500&code=" +
                      encodeURIComponent(code));
  const b = r.body && typeof r.body === "object" ? r.body : {};
  const rows = b.rows || b.events || [];
  const n = typeof b.matched === "number" ? b.matched : rows.length;
  log.debug("Leaving codeCount(). " + n);
  return n;
}

// Whether a new row with `code` arrived since `before`: the row is written
// as the response finishes, so the read after it may need a moment.
async function newRowWith(realm, code, before) {
  log.debug("Entering newRowWith(). " + code);
  let after = await codeCount(realm, code);
  for (let i = 0; i < 30 && after <= before; i += 1) {
    await sleep(200);
    after = await codeCount(realm, code);
  }
  log.debug("Leaving newRowWith(). " + before + " -> " + after);
  return after > before;
}

// A browser: a cookie jar (a plain object, which `authn_signin.js` writes
// back into) and redirects left to the caller.
function browser() {
  log.debug("Entering browser().");
  const jar = {};
  const self = {
    jar: jar,
    cookie: function cookieOf() {
      log.debug("Entering cookieOf().");
      log.debug("Leaving cookieOf().");
      return Object.keys(jar).map(function (k) {
        return k + "=" + jar[k];
      }).join("; ");
    },
    go: async function go(method, url, body, extra) {
      log.debug("Entering go(). " + method + " " + url);
      const headers = Object.assign({ "User-Agent": AGENT }, extra || {});
      const cookie = self.cookie();
      if (cookie) {
        headers.cookie = cookie;
      }
      if (body !== undefined) {
        headers["Content-Type"] = "application/x-www-form-urlencoded";
      }
      const absolute = /^https?:\/\//i.test(url) ? url : base + url;
      const r = await fetch(absolute, { method: method, redirect: "manual",
                                        headers: headers, body: body });
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
               text: text, url: absolute };
    }
  };
  log.debug("Leaving browser().");
  return self;
}

function sentToSignIn(r) {
  log.debug("Entering sentToSignIn().");
  log.debug("Leaving sentToSignIn().");
  return (r.status === 302 || r.status === 303) &&
    /\/authn\/login(?:\?app=[^#]*)?[?#]authn=/.test(r.location);
}

function decode(token) {
  log.debug("Entering decode().");
  const parts = String(token || "").split(".");
  log.debug("Leaving decode().");
  return JSON.parse(Buffer.from(parts[1] || "", "base64url")
    .toString("utf8") || "{}");
}

function pkce() {
  log.debug("Entering pkce().");
  const verifier = nodeCrypto.randomBytes(32).toString("base64url");
  log.debug("Leaving pkce().");
  return { verifier: verifier,
           challenge: nodeCrypto.createHash("sha256").update(verifier)
             .digest("base64url") };
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
  for (const id of MADE) {
    const r = await postJson(base + "/admin-api/realms/remove", { id: id });
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
    // A failed removal leaves a realm on a private probe; it is not the
    // job's verdict.
    log.warn("removing the realms failed: " + ((e && e.message) || e));
  }
  if (failure) {
    log.error("Test failed: " + ((failure && failure.stack) || failure));
    log.debug("Leaving main(). Failed.");
    process.exit(1);
  }
  if (failures.length) {
    log.error(failures.length + " check(s) FAILED:\n  " +
              failures.join("\n  "));
    log.debug("Leaving main(). Failed.");
    process.exit(1);
  }
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving main().");
}


const ssfRoles = require("./ssf_roles.js");

const APP = "reauth-" + STAMP;
const REDIRECT = "https://rp-" + STAMP + ".reauth.example/cb";
const RECEIVER = "reauth-rx-" + STAMP;
const SECRET = "reauth-" + nodeCrypto.randomBytes(12).toString("hex");
const CAEP = "https://schemas.openid.net/secevent/caep/event-type/";
const ALICE = names.usernameFor("rea");
const BOB = names.usernameFor("reb");
let REALM = "";

// The code flow in browser `b` for `who`; with `prompt`, asked again.
async function codeFlow(b, who, prompt) {
  log.debug("Entering codeFlow(). " + who);
  const p = pkce();
  const query = { client_id: APP, response_type: "code",
    redirect_uri: REDIRECT, scope: "openid offline_access", state: "s",
    nonce: "n" + Date.now(), code_challenge: p.challenge,
    code_challenge_method: "S256" };
  if (prompt) {
    query.prompt = prompt;
  }
  let r = await b.go("GET", realmBase(REALM) + "/oauth2/authorize?" +
                     form(query));
  if (sentToSignIn(r)) {
    const sent = await authnSignin.signInWithJar(realmBase(REALM),
      new URL(r.location, realmBase(REALM) + "/").toString(),
      { action: "login", username: who, password: PASSWORD }, b.jar,
      { ignoreOffer: true, headers: { "User-Agent": AGENT } });
    must(sent.status === 303 && sent.location, "the sign-in: " +
         sent.status + " " + String(sent.text || "").slice(0, 300));
    r = await b.go("GET", new URL(sent.location,
                                  realmBase(REALM) + "/").toString());
  }
  must(r.location.indexOf(REDIRECT) === 0, "no code: " + r.status + " " +
       r.location);
  const code = new URL(r.location).searchParams.get("code");
  const t = await send(realmBase(REALM) + "/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form({ grant_type: "authorization_code", code: code,
                 redirect_uri: REDIRECT, client_id: APP,
                 code_verifier: p.verifier }) });
  must(t.status === 200 && t.body && t.body.id_token, "the token: " +
       t.status + " " + t.raw.slice(0, 300));
  log.debug("Leaving codeFlow().");
  return { idToken: decode(t.body.id_token), refresh: t.body.refresh_token,
           cookie: b.jar.sts_session || "" };
}

// Whether a browser holding only `cookie` is signed in.
async function opens(cookie) {
  log.debug("Entering opens().");
  const b = browser();
  b.jar.sts_session = cookie;
  const p = pkce();
  const r = await b.go("GET", realmBase(REALM) + "/oauth2/authorize?" +
    form({ client_id: APP, response_type: "code", redirect_uri: REDIRECT,
           scope: "openid", state: "s", nonce: "n" + Date.now(),
           code_challenge: p.challenge, code_challenge_method: "S256" }));
  log.debug("Leaving opens(). " + r.status);
  return r.location.indexOf(REDIRECT) === 0 && /[?&]code=/.test(r.location);
}

function refresh(token) {
  log.debug("Entering refresh().");
  log.debug("Leaving refresh().");
  return send(realmBase(REALM) + "/oauth2/token", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form({ grant_type: "refresh_token", refresh_token: token,
                 client_id: APP }) });
}

async function receiverToken() {
  log.debug("Entering receiverToken().");
  await ssfRoles.mapApplication(ssfRoles.sendPost(send),
    realmBase(REALM) + "/admin-api", RECEIVER, "ssf.read ssf.manage");
  const r = await send(realmBase(REALM) + "/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form({ grant_type: "client_credentials", client_id: RECEIVER,
                 client_secret: SECRET, scope: "ssf.read ssf.manage" }) });
  must(r.body && r.body.access_token, "a receiver token: " +
       r.raw.slice(0, 300));
  log.debug("Leaving receiverToken().");
  return r.body.access_token;
}

// Every SET waiting on the stream, decoded, and acknowledged.
async function drain(token, streamId) {
  log.debug("Entering drain().");
  const auth = { "Content-Type": "application/json",
                 Authorization: "Bearer " + token };
  const r = await send(realmBase(REALM) + "/ssf/poll", { method: "POST",
    headers: auth, body: JSON.stringify({ stream_id: streamId,
      returnImmediately: true, maxEvents: 100 }) });
  must(r.status === 200, "poll: " + r.raw.slice(0, 300));
  const sets = (r.body && r.body.sets) || {};
  const jtis = Object.keys(sets);
  if (jtis.length) {
    await send(realmBase(REALM) + "/ssf/poll", { method: "POST",
      headers: auth, body: JSON.stringify({ stream_id: streamId, ack: jtis,
        returnImmediately: true, maxEvents: 0 }) });
  }
  log.debug("Leaving drain(). " + jtis.length);
  return jtis.map(function (jti) {
    return decode(sets[jti]);
  });
}

function typesOf(sets) {
  log.debug("Entering typesOf().");
  const out = [];
  sets.forEach(function (one) {
    Object.keys(one.events || {}).forEach(function (t) {
      out.push(t.replace(CAEP, ""));
    });
  });
  log.debug("Leaving typesOf().");
  return out;
}

async function aliceRows() {
  log.debug("Entering aliceRows().");
  const r = await api(REALM, "GET", "/sessions?per=300&q=" +
                      encodeURIComponent(ALICE));
  log.debug("Leaving aliceRows().");
  return ((r.body && r.body.sessions) || []).filter(function (one) {
    return JSON.stringify(one).indexOf(ALICE) >= 0 &&
      String(one.kind || one.protocol || "session") !== "relyingParty";
  });
}

async function test() {
  log.debug("Entering test().");
  REALM = await makeRealm("reau", "development");
  await setting(REALM, "oauth2.rfc9700", "true");
  // ONE SESSION PER BROWSER, the arrangement the in-process file asserts:
  // with `authn.multipleAccounts` on (the default since #561) another
  // person signing in ADDS an account instead (the multi-account jobs').
  await setting(REALM, "authn.multipleAccounts", "false");
  await createPerson(REALM, ALICE);
  await createPerson(REALM, BOB);
  await apiOk(REALM, "/applications/create", { identifier: APP, name: APP,
    kind: "oauth2-client", protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: [APP], oauthRedirectUri: [REDIRECT],
              oauthGrantType: ["authorization_code", "refresh_token"],
              oauthResponseType: ["code"],
              oauthAllowedScope: ["openid", "offline_access"],
              oauthTokenEndpointAuthMethod: "none" } }, "the client");
  for (const one of ["openid", "offline_access"]) {
    await apiOk(REALM, "/consent/grant-global-consent",
                { client: APP, scope: one }, "consented " + one);
  }
  await apiOk(REALM, "/applications/create", { identifier: RECEIVER,
    name: RECEIVER, kind: "oauth2-client", protocols: ["oauth2", "ssf"],
    fields: { oauthClientId: [RECEIVER], oauthClientSecret: SECRET,
              oauthTokenEndpointAuthMethod: "client_secret_post",
              oauthAllowedScope: ["ssf.read", "ssf.manage"],
              oauthGrantType: ["client_credentials"] } }, "the receiver");
  const rx = await receiverToken();
  const stream = await send(realmBase(REALM) + "/ssf/stream", {
    method: "POST", headers: { "Content-Type": "application/json",
                               Authorization: "Bearer " + rx },
    body: JSON.stringify({ delivery: { method: "urn:ietf:rfc:8936" },
      events_requested: [CAEP + "session-revoked",
                         CAEP + "assurance-level-change",
                         CAEP + "session-established"] }) });
  must(stream.status === 201, "the stream: " + stream.raw.slice(0, 300));
  const streamId = stream.body.stream_id;

  log.info("=== 1. the first sign-in ===");
  const b = browser();
  const first = await codeFlow(b, ALICE);
  const sid = String(first.idToken.sid || "");
  await check("1. the session cookie is <sid>.<handle>, the sid the one " +
              "the ID Token names", async function () {
    expect(sid && first.cookie.indexOf(sid + ".") === 0 &&
           first.cookie.length > sid.length + 8,
           JSON.stringify({ sid: sid, cookie: first.cookie.slice(0, 80) }));
  });
  await sleep(1500);
  await drain(rx, streamId);

  log.info("=== 2, 3. the same person, again ===");
  const again = await codeFlow(b, ALICE, "login");
  await check("2. after a re-authentication the ID Token's sid is " +
              "UNCHANGED", async function () {
    expect(again.idToken.sid === sid, sid + " -> " + again.idToken.sid);
  });
  await check("2. and auth_time is the new sign-in's", async function () {
    expect(Number(again.idToken.auth_time) > Number(first.idToken.auth_time),
           first.idToken.auth_time + " -> " + again.idToken.auth_time);
  });
  await check("3. the cookie is ROTATED: the same sid, a new handle",
              async function () {
    expect(again.cookie.indexOf(sid + ".") === 0 &&
           again.cookie !== first.cookie,
           first.cookie.slice(0, 60) + " -> " + again.cookie.slice(0, 60));
  });
  const oldOpens = await opens(first.cookie);
  const newOpens = await opens(again.cookie);
  const bareOpens = await opens(sid);
  await check("3. the OLD cookie no longer opens the session, the new one " +
              "does", async function () {
    expect(!oldOpens && newOpens, "old " + oldOpens + ", new " + newOpens);
  });
  await check("3. a BARE sid is not a cookie: it opens nothing",
              async function () {
    expect(!bareOpens, "the bare sid opened the session");
  });
  const rows = await aliceRows();
  await check("4. the realm holds ONE session for the person, not a copy",
              async function () {
    expect(rows.length === 1, JSON.stringify(rows).slice(0, 600));
  });
  const renewed = await refresh(first.refresh);
  await check("5. RFC 9700 mode: the refresh token issued before the " +
              "re-authentication still refreshes", async function () {
    expect(renewed.status === 200 && renewed.body &&
           renewed.body.access_token,
           renewed.status + " " + renewed.raw.slice(0, 300));
  });
  await sleep(1000);
  const quiet = typesOf(await drain(rx, streamId));
  await check("6. a re-authentication that leaves acr where it was tells " +
              "the receiver nothing: no session-revoked, no " +
              "assurance-level-change", async function () {
    expect(quiet.indexOf("session-revoked") < 0 &&
           quiet.indexOf("assurance-level-change") < 0,
           quiet.join(","));
  });

  log.info("=== 7. somebody else on that browser ===");
  const bob = await codeFlow(b, BOB, "login");
  let seen = [];
  for (let i = 0; i < 20 && seen.indexOf("session-revoked") < 0; i += 1) {
    seen = seen.concat(typesOf(await drain(rx, streamId)));
    if (seen.indexOf("session-revoked") < 0) {
      await sleep(250);
    }
  }
  const aliceAfter = await opens(again.cookie);
  await check("7. somebody else signing in on that browser gets a session " +
              "of their own", async function () {
    expect(bob.idToken.sid && bob.idToken.sid !== sid,
           sid + " / " + bob.idToken.sid);
  });
  await check("7. and the first person's session ENDS: their cookie opens " +
              "nothing, and CAEP is told session-revoked", async function () {
    expect(!aliceAfter, "the first person's cookie still opens");
    expect(seen.indexOf("session-revoked") >= 0, seen.join(","));
  });
  log.debug("Leaving test().");
}

main();
