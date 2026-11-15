// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_session_cap.js
//
// ---------------------------------------------------------------------------
// A REALM HOLDS AT MOST `authn.maxSessions` SESSIONS, AND A SUBJECT AT MOST
// `authn.maxSessionsPerSubject`, OVER THE WIRE (#345, #350).
//
// D12 (#444): carries over the part of `tests/session_cap.js` a browser
// sees. In a development realm of its own (the cap is the same in both
// modes; development lets a job sign people in without a second factor),
// every cap written with `/admin-api/realms/set`, people signed in at the
// sign-in screen in browsers of their own, the realm's sessions read off
// `/admin-api/sessions` and the codes off its audit log:
//
//   A. at the realm cap a NEW person's sign-in is refused and the sessions
//      already held all still sign their browsers in (nobody was ended to
//      make room). The screen answers 403 saying the realm is full, and the
//      refusal is recorded STS-AUTHN-0337;
//   B. a person signing in AGAIN in their own browser at the cap is not an
//      insert: it is answered;
//   C. lowering the cap below what is held ends nobody; a new person is
//      still refused;
//   L. a refused sign-in leaves the browser's own session: in a browser
//      signed in as one person, a new person refused at the cap leaves the
//      first still signed in, and that refusal is a `session.refuse` row
//      carrying STS-AUTHN-0337;
//   F. a subject's own cap: with `authn.maxSessionsPerSubject` 2, a person's
//      third browser ends THEIR oldest session (STS-AUTHN-0292 on a
//      `session.end` row) and nobody else's.
//
// NOT carried, and why: D, E, G, I, J, K and M choose a victim by
// `lastSeenAt`, merge two copies of a row or split one realm's shed budget
// from another's, which are facts of the store no answer states (class
// (d)); C's "the sweep's budget" needs the scheduler's
// `authn.session-expiry` run, a clock (class (d)); H (a relying-party row is
// stored chosen) and the CAEP notice are store fields and an observer
// (class (d)).
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
var log = bunyan.createLogger({ name: "sts_session_cap",
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
const PASSWORD = "SessCap-" + nodeCrypto.randomBytes(9).toString("base64url") +
  "-9a!";
// A desktop browser's User-Agent with this job's name on the end: risk
// scoring reads a bare job name as an automated client, and product refuses
// a first sign-in from one (#62).
const AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 " +
  "sts_session_cap/1.0 (" + STAMP + ")";

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


const APP = "cap-" + STAMP;
const REDIRECT = "https://rp-" + STAMP + ".cap.example/cb";
const PEOPLE = ["ca", "cb", "cc", "cd", "ce"].map(function (stem) {
  return names.usernameFor(stem);
});
let REALM = "";

function authorizeUrl(extra) {
  log.debug("Entering authorizeUrl().");
  const p = pkce();
  log.debug("Leaving authorizeUrl().");
  return realmBase(REALM) + "/oauth2/authorize?" + form(Object.assign({
    client_id: APP, response_type: "code", redirect_uri: REDIRECT,
    scope: "openid", state: "s", nonce: "n" + Date.now() +
    nodeCrypto.randomBytes(8).toString("hex"), code_challenge: p.challenge,
    code_challenge_method: "S256" }, extra || {}));
}

function gotCode(r) {
  log.debug("Entering gotCode().");
  log.debug("Leaving gotCode().");
  return (r.status === 302 || r.status === 303) &&
    r.location.indexOf(REDIRECT) === 0 && /[?&]code=/.test(r.location);
}

// Signs `who` in in browser `b` (a fresh one when omitted): `{ b, ok,
// shown }`, ok when the browser came back to the client with a code.
async function signIn(who, b, extra) {
  log.debug("Entering signIn(). " + who);
  const br = b || browser();
  const start = await br.go("GET", authorizeUrl(extra));
  if (!sentToSignIn(start)) {
    log.debug("Leaving signIn(). No screen.");
    return { b: br, ok: gotCode(start), screen: false,
             shown: start.status + " " + start.location };
  }
  const sent = await authnSignin.signInWithJar(realmBase(REALM),
    new URL(start.location, realmBase(REALM) + "/").toString(),
    { action: "login", username: who, password: PASSWORD }, br.jar,
    { ignoreOffer: true, headers: { "User-Agent": AGENT } });
  let landed = null;
  if (sent.status === 303 && sent.location) {
    landed = await br.go("GET", new URL(sent.location,
                                        realmBase(REALM) + "/").toString());
  }
  const out = { b: br, ok: !!landed && gotCode(landed), screen: true,
    next: sent.answer.next,
    shown: sent.status + " " + sent.answer.next + " " +
           JSON.stringify(sent.answer.errors || []).slice(0, 200) + " " +
           (landed ? landed.status + " " + landed.location : "") };
  log.debug("Leaving signIn(). " + out.shown);
  return out;
}

// Whether the browser's session still answers the client with no screen.
async function stillSignedIn(b) {
  log.debug("Entering stillSignedIn().");
  const r = await b.go("GET", authorizeUrl());
  log.debug("Leaving stillSignedIn(). " + r.status);
  return gotCode(r);
}

async function held() {
  log.debug("Entering held().");
  const r = await api(REALM, "GET", "/sessions?per=300");
  must(r.status === 200 && r.body, "sessions: " + r.status);
  log.debug("Leaving held(). " + r.body.held);
  return Number(r.body.held || 0);
}

async function auditRows(action, code) {
  log.debug("Entering auditRows(). " + action);
  const r = await api(REALM, "GET", "/audit?per=500&code=" +
                      encodeURIComponent(code));
  const rows = ((r.body && (r.body.rows || r.body.events)) || [])
    .filter(function (one) {
      return !action || one.action === action;
    });
  log.debug("Leaving auditRows(). " + rows.length);
  return rows;
}

async function test() {
  log.debug("Entering test().");
  REALM = await makeRealm("scap", "development");
  for (const who of PEOPLE) {
    await createPerson(REALM, who);
  }
  await apiOk(REALM, "/applications/create", { identifier: APP, name: APP,
    kind: "oauth2-client", protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: [APP], oauthRedirectUri: [REDIRECT],
              oauthGrantType: ["authorization_code"],
              oauthResponseType: ["code"], oauthAllowedScope: ["openid"],
              oauthTokenEndpointAuthMethod: "none" } }, "the client");
  await apiOk(REALM, "/consent/grant-global-consent",
              { client: APP, scope: "openid" }, "consented openid");

  log.info("=== A. the realm cap ===");
  const a = await signIn(PEOPLE[0]);
  must(a.ok, "the first sign-in: " + a.shown);
  const base0 = await held();
  // Room for exactly one more: whatever the realm holds now (the first
  // person's session, and any the management API's own calls keep) and
  // one.
  await setting(REALM, "authn.maxSessions", base0 + 1);
  const b = await signIn(PEOPLE[1]);
  must(b.ok, "the second sign-in, into the last place: " + b.shown);
  const atCap = await held();
  const fullBefore = await codeCount(REALM, "STS-AUTHN-0337");
  const c = await signIn(PEOPLE[2]);
  const fullAfter = await newRowWith(REALM, "STS-AUTHN-0337", fullBefore);
  await check("A. at the realm cap a new person's sign-in is refused — " +
              "the browser does not come back to the client with a code",
              async function () {
    expect(!c.ok, c.shown);
  });
  // A NEW browser at the cap is told the realm is full, 403, and the
  // refusal is recorded STS-AUTHN-0337 (until fix/node-defects-1114 it was
  // given no arrival session and asked to reload, with no code recorded).
  await check("A. the screen answers 403 saying the realm is full, and " +
              "records STS-AUTHN-0337 with no code in the answer",
              async function () {
    expect(/^403 /.test(c.shown) &&
           /as many sign-in sessions as it allows/.test(c.shown), c.shown);
    expect(!/holds no session/.test(c.shown), c.shown);
    expect(!/STS-[A-Z]+-\d{4}/.test(c.shown), c.shown);
    expect(fullAfter, "no new STS-AUTHN-0337 row after " + fullBefore);
  });
  await check("A. the store stays at the cap, and nobody was ended to make " +
              "room: both sessions still sign their browsers in",
              async function () {
    expect((await held()) <= atCap, "held grew past " + atCap);
    expect(await stillSignedIn(a.b), "the first person's session ended");
    expect(await stillSignedIn(b.b), "the second person's session ended");
  });

  log.info("=== B. signing in again is not an insert ===");
  const again = await signIn(PEOPLE[0], a.b, { prompt: "login" });
  await check("B. the same person signing in again in their own browser " +
              "at the cap is answered", async function () {
    expect(again.ok, again.shown);
  });

  log.info("=== L. a refused sign-in leaves the browser's session ===");
  const refusedBefore = await codeCount(REALM, "STS-AUTHN-0337");
  const switched = await signIn(PEOPLE[3], b.b, { prompt: "login" });
  await newRowWith(REALM, "STS-AUTHN-0337", refusedBefore);
  const refusals = await auditRows("session.refuse", "STS-AUTHN-0337");
  await check("L. in a browser signed in as one person, a NEW person " +
              "refused at the cap leaves the first one signed in",
              async function () {
    expect(!switched.ok, switched.shown);
    expect(await stillSignedIn(b.b), "the browser's own session ended");
  });
  await check("A, L. the refusal is a session.refuse row carrying " +
              "STS-AUTHN-0337, and the answer carries no code",
              async function () {
    expect(refusals.length > 0, "no session.refuse row with STS-AUTHN-0337");
    expect(!/STS-[A-Z]+-\d{4}/.test(switched.shown), switched.shown);
  });

  log.info("=== C. lowering the cap ends nobody ===");
  await setting(REALM, "authn.maxSessions", 1);
  await check("C. lowered below what is held, the cap ends nobody: both " +
              "sessions still sign their browsers in", async function () {
    expect(await stillSignedIn(a.b), "the first person's session ended");
    expect(await stillSignedIn(b.b), "the second person's session ended");
  });
  const late = await signIn(PEOPLE[4]);
  await check("C. and a new person is still refused while the realm is " +
              "over it", async function () {
    expect(!late.ok, late.shown);
  });

  log.info("=== F. a subject's own cap ===");
  await setting(REALM, "authn.maxSessions", 1000);
  await setting(REALM, "authn.maxSessionsPerSubject", 2);
  const endedBefore = (await auditRows("session.end",
                                       "STS-AUTHN-0292")).length;
  const second = await signIn(PEOPLE[0]);
  must(second.ok, "the first person's second browser: " + second.shown);
  await check("F. at their own cap of two, both of the person's browsers " +
              "are signed in", async function () {
    expect(await stillSignedIn(a.b), "the oldest ended early");
    expect(await stillSignedIn(second.b), "the second is not signed in");
  });
  const third = await signIn(PEOPLE[0]);
  must(third.ok, "the first person's third browser: " + third.shown);
  let endedAfter = (await auditRows("session.end", "STS-AUTHN-0292")).length;
  for (let i = 0; i < 20 && endedAfter <= endedBefore; i += 1) {
    await sleep(200);
    endedAfter = (await auditRows("session.end", "STS-AUTHN-0292")).length;
  }
  await check("F. the third browser ends the person's OWN oldest session " +
              "— its browser is sent to the sign-in screen", async function () {
    expect(!(await stillSignedIn(a.b)), "the oldest still signs in");
    expect(await stillSignedIn(second.b), "the second ended");
    expect(await stillSignedIn(third.b), "the third is not signed in");
  });
  await check("F. and nobody else's, and the end is a session.end row " +
              "carrying STS-AUTHN-0292", async function () {
    expect(await stillSignedIn(b.b), "the other person's session ended");
    expect(endedAfter > endedBefore, endedBefore + " -> " + endedAfter);
  });
  log.debug("Leaving test().");
}

main();
