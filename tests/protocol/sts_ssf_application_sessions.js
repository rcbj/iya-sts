// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_ssf_application_sessions.js
//
// ---------------------------------------------------------------------------
// AN APPLICATION'S STREAM CARRIES EVENTS ONLY ABOUT PEOPLE WITH AN ACTIVE
// SESSION ON THAT APPLICATION, OVER THE WIRE (#2234, 2026-11-25).
//
// In a throwaway realm it leaves behind, two OpenID Connect applications, A
// and B, each with a poll stream of its own made with its client
// credentials, and three people: alice signs in to A, bob to B, carol to
// nothing.
//
//   a. Add Subject on A's stream: alice (signed in to A) is accepted, 200;
//      bob (signed in to B only) is refused 403 access_denied;
//   b. a verification event (no subject) reaches A's stream;
//   c. bob signs himself out (POST /logout, global): B's stream is sent
//      session-revoked about bob; A's stream is sent nothing about him;
//   d. alice's account is disabled by an administrator, which ends her
//      session: A's stream is sent session-revoked AND RISC account-disabled
//      about her — the event that ends a session reaches the application
//      whose session it ended — and B's nothing about her;
//   e. carol, signed in nowhere, is disabled: neither stream hears of it;
//   f. with ssf.applicationStreamScope `all` in this realm, bob (signed in
//      nowhere now) disabled reaches A's stream, the behaviour before #2234;
//   g. A's own client secret rotated: the credential-change about the
//      APPLICATION (no person, nobody signed in) reaches A's stream — the
//      scope is about people, and an event about the application itself
//      (#2028's pep-policies-changed has the same subject) is not filtered.
//
// OWNED HERE (local: true): this repository's sessions and transmitter.
// ---------------------------------------------------------------------------

const urls = require("./url_match.js");
// The sign-in screen over `/authn-api` (#571).
const authnSignin = require("./authn_signin");
const assert = require("assert");
const nodeCrypto = require("crypto");
const names = require("./random_username.js");
const ssfRoles = require("./ssf_roles.js");

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
var log = bunyan.createLogger({ name: "sts_ssf_application_sessions",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("appses2234-" + STAMP).toLowerCase()
  .replace(/[^a-z0-9-]/g, "").slice(0, 31);
const R = "/realm/" + REALM;
const realmBase = base + R;
const realmApi = realmBase + "/admin-api";
const CAEP = "https://schemas.openid.net/secevent/caep/event-type/";
const RISC = "https://schemas.openid.net/secevent/risc/event-type/";
const SSF = "https://schemas.openid.net/secevent/ssf/event-type/";
const POLL = "urn:ietf:rfc:8936";
const PASSWORD = "App-2234-Passw0rd!-" + String(Date.now()).slice(-6);
const VERIFIER = "v".repeat(43);
const APPS = {
  A: { id: "as2234-a-" + STAMP.toLowerCase(),
       secret: "as-2234-a-" + String(Date.now()).slice(-8),
       redirect: "https://a.as2234.example.test/cb" },
  B: { id: "as2234-b-" + STAMP.toLowerCase(),
       secret: "as-2234-b-" + String(Date.now()).slice(-8),
       redirect: "https://b.as2234.example.test/cb" }
};
const ALICE = names.usernameFor("as-alice");
const BOB = names.usernameFor("as-bob");
const CAROL = names.usernameFor("as-carol");
// A desktop Chrome string with this job's name on the end: isbot reads a bare
// job name as an automated client, and product mode refuses a first sign-in
// from one on risk (#62).
const AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 " +
  "sts_ssf_application_sessions/1.0 (" + STAMP + ")";

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

function postJson(url, payload, headers) {
  log.debug("Entering postJson().");
  log.debug("Leaving postJson().");
  return send(url, { method: "POST",
    headers: Object.assign({ "Content-Type": "application/json" },
                           headers || {}),
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
    jar: jar,
    async go(method, path, body, extra) {
      log.debug("Entering go(). " + method + " " + path);
      const headers = Object.assign({ "User-Agent": AGENT }, extra || {});
      const cookie = Object.keys(jar).map(function (k) {
        return k + "=" + jar[k];
      }).join("; ");
      if (cookie) {
        headers.cookie = cookie;
      }
      if (body !== undefined && !headers["Content-Type"]) {
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
               text: text };
    }
  };
  log.debug("Leaving browser().");
  return self;
}

function decode(token) {
  log.debug("Entering decode().");
  const parts = String(token).split(".");
  log.debug("Leaving decode().");
  return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
}

// Signs `who` in to an application with the code flow and answers the
// `sub` its ID Token names.
async function signInTo(app, who) {
  log.debug("Entering signInTo(). " + who + " -> " + app.id);
  const b = browser(who);
  const challenge = nodeCrypto.createHash("sha256").update(VERIFIER)
    .digest("base64url");
  const params = { response_type: "code", client_id: app.id,
    redirect_uri: app.redirect, scope: "openid profile", state: "st",
    nonce: "n-" + nodeCrypto.randomBytes(4).toString("hex"),
    code_challenge: challenge, code_challenge_method: "S256" };
  let r = await b.go("GET", R + "/oauth2/authorize?" + form(params));
  if ((r.status === 302 || r.status === 303) &&
      /\/authn\/login(?:\?app=[^#]*)?[?#]authn=/.test(r.location)) {
    const posted = await authnSignin.signInWithJar(base + R, r.location,
      { action: "login", username: who, password: PASSWORD }, b.jar,
      { headers: { "User-Agent": AGENT } });
    assert.ok(posted.answer.view, "the sign-in screen: " +
              posted.answer.status + " " + JSON.stringify(posted.answer.json));
    r = await b.go("GET", posted.location);
  }
  assert.ok((r.status === 302 || r.status === 303) &&
            urls.isAt(r.location, app.redirect),
            who + " reaches " + app.id + ": " + r.status + " " + r.location);
  const code = new URL(r.location).searchParams.get("code");
  assert.ok(code, "a code for " + who + ": " + r.location);
  const t = await send(realmBase + "/oauth2/token", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form({ grant_type: "authorization_code", code: code,
                 redirect_uri: app.redirect, client_id: app.id,
                 client_secret: app.secret, code_verifier: VERIFIER }) });
  assert.ok(t.body && t.body.id_token, "an ID Token for " + who + ": " +
            t.raw.slice(0, 300));
  log.debug("Leaving signInTo().");
  return { browser: b, sub: String(decode(t.body.id_token).sub) };
}

async function tokenFor(app) {
  log.debug("Entering tokenFor(). " + app.id);
  const scope = "ssf.read ssf.manage";
  await ssfRoles.mapApplication(ssfRoles.sendPost(send), realmApi, app.id,
                                scope);
  const r = await send(realmBase + "/oauth2/token", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form({ grant_type: "client_credentials", client_id: app.id,
                 client_secret: app.secret, scope: scope }) });
  assert.ok(r.body && r.body.access_token,
            "a token for " + app.id + ": " + r.raw.slice(0, 300));
  log.debug("Leaving tokenFor().");
  return r.body.access_token;
}

// Every SET waiting on a stream, decoded, and acknowledged.
async function drain(app) {
  log.debug("Entering drain(). " + app.id);
  const auth = { "Content-Type": "application/json",
                 Authorization: "Bearer " + app.token };
  const r = await send(realmBase + "/ssf/poll", { method: "POST",
    headers: auth, body: JSON.stringify({ stream_id: app.stream,
      returnImmediately: true, maxEvents: 100 }) });
  assert.strictEqual(r.status, 200, "poll: " + r.raw.slice(0, 300));
  const sets = r.body.sets || {};
  const jtis = Object.keys(sets);
  if (jtis.length) {
    await send(realmBase + "/ssf/poll", { method: "POST", headers: auth,
      body: JSON.stringify({ stream_id: app.stream, ack: jtis,
                             returnImmediately: true, maxEvents: 0 }) });
  }
  log.debug("Leaving drain(). " + jtis.length + " SET(s).");
  return jtis.map(function (jti) {
    return decode(sets[jti]);
  });
}

// Everything a stream is sent, kept as it is drained, so a later check can
// look at what an earlier wait collected.
const SEEN = { A: [], B: [] };

// Waits for a stream to hold a SET the predicate accepts; `tries` polls a
// quarter of a second apart. Delivery is on a promise after the act answers.
async function waitFor(which, predicate, tries) {
  log.debug("Entering waitFor(). " + which);
  for (let i = 0; i < (tries || 24); i++) {
    (await drain(APPS[which])).forEach(function (one) {
      SEEN[which].push(one);
    });
    const hit = SEEN[which].filter(predicate)[0];
    if (hit) {
      log.debug("Leaving waitFor(). Found.");
      return hit;
    }
    await new Promise(function (r) { setTimeout(r, 250); });
  }
  log.debug("Leaving waitFor(). Not found.");
  return null;
}

function eventOf(set, uri) {
  log.debug("Entering eventOf().");
  log.debug("Leaving eventOf().");
  return ((set && set.events) || {})[uri] || null;
}

// Whether a SET's subject is this person, by the `sub` their ID Token named.
function about(set, sub) {
  log.debug("Entering about().");
  const s = set && set.sub_id;
  const user = s && (s.format === "complex" ? s.user : s);
  log.debug("Leaving about().");
  return !!user && user.format === "iss_sub" && String(user.sub) === sub;
}

function anyAbout(which, sub) {
  log.debug("Entering anyAbout().");
  log.debug("Leaving anyAbout().");
  return SEEN[which].filter(function (set) {
    return about(set, sub);
  });
}

async function makeApplication(app) {
  log.debug("Entering makeApplication(). " + app.id);
  await ok(realmApi + "/applications/create", { identifier: app.id,
    kind: "oauth2-client", name: app.id, protocols: ["oauth2", "ssf"],
    fields: { oauthClientId: [app.id], oauthClientSecret: app.secret,
              oauthTokenEndpointAuthMethod: "client_secret_post",
              oauthAllowedScope: ["openid", "profile", "ssf.read",
                                  "ssf.manage"],
              oauthRedirectUri: [app.redirect],
              oauthGrantType: ["authorization_code", "client_credentials"],
              oauthResponseType: ["code"] } },
    "created " + app.id);
  for (const one of ["openid", "profile"]) {
    await ok(realmApi + "/consent/grant-global-consent",
             { client: app.id, scope: one }, "consented " + one);
  }
  app.token = await tokenFor(app);
  const created = await postJson(realmBase + "/ssf/stream",
    { delivery: { method: POLL },
      events_requested: [CAEP + "session-revoked", CAEP + "credential-change",
                         RISC + "account-disabled"] },
    { Authorization: "Bearer " + app.token });
  assert.strictEqual(created.status, 201, created.raw.slice(0, 400));
  app.stream = created.body.stream_id;
  log.debug("Leaving makeApplication().");
}

async function subjects(app, action, subject) {
  log.debug("Entering subjects(). " + action);
  const r = await postJson(realmBase + "/ssf/subjects/" + action,
    { stream_id: app.stream, subject: subject },
    { Authorization: "Bearer " + app.token });
  log.debug("Leaving subjects(). " + r.status);
  return r;
}

function issSub(sub) {
  log.debug("Entering issSub().");
  log.debug("Leaving issSub().");
  return { format: "iss_sub", iss: realmBase, sub: sub };
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. a throwaway realm " + REALM + ", two applications, " +
           "three people ===");
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "App sessions 2234 " + STAMP },
    "created the realm");
  await makeApplication(APPS.A);
  await makeApplication(APPS.B);
  for (const who of [ALICE, BOB, CAROL]) {
    await ok(realmApi + "/users/create", { username: who, invent: false,
      credential: "password", password: PASSWORD,
      attributes: { cn: "AS " + who, givenName: "AS", sn: who,
                    mail: who + "@as2234.test" } }, "created " + who);
  }
  const alice = await signInTo(APPS.A, ALICE);
  const bob = await signInTo(APPS.B, BOB);
  check("alice is signed in to A and bob to B", function () {
    assert.ok(alice.sub && bob.sub && alice.sub !== bob.sub,
              alice.sub + " " + bob.sub);
  });

  log.info("=== a. Add Subject ===");
  let r = await subjects(APPS.A, "add", issSub(alice.sub));
  check("A may add alice, who has an active session on A (200)", function () {
    assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
  });
  r = await subjects(APPS.A, "add", issSub(bob.sub));
  check("A may not add bob, signed in to B only (403 access_denied)",
    function () {
      assert.strictEqual(r.status, 403, r.raw.slice(0, 300));
      assert.strictEqual(r.body && r.body.err, "access_denied", r.raw);
    });
  r = await subjects(APPS.A, "remove", issSub(alice.sub));
  check("and removing alice again answers 204", function () {
    assert.strictEqual(r.status, 204, r.raw.slice(0, 300));
  });

  log.info("=== b. an event with no subject ===");
  r = await postJson(realmBase + "/ssf/verify",
    { stream_id: APPS.A.stream, state: "as2234-" + STAMP },
    { Authorization: "Bearer " + APPS.A.token });
  const verified = await waitFor("A", function (set) {
    return !!eventOf(set, SSF + "verification");
  });
  check("a verification event (no subject) reaches A's stream", function () {
    assert.ok(r.status === 204, r.status + " " + r.raw.slice(0, 200));
    assert.ok(verified, JSON.stringify(SEEN.A).slice(0, 800));
  });

  log.info("=== c. bob signs himself out ===");
  r = await bob.browser.go("POST", R + "/logout",
    JSON.stringify({ scope: "global" }),
    { "Content-Type": "application/json", Accept: "application/json" });
  check("POST /logout signs bob out", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
  });
  const bobRevoked = await waitFor("B", function (set) {
    return !!eventOf(set, CAEP + "session-revoked") && about(set, bob.sub);
  });
  check("B's stream is sent session-revoked about bob: the sign-out reaches " +
        "the application whose session it ended", function () {
    assert.ok(bobRevoked, JSON.stringify(SEEN.B).slice(0, 1200));
  });
  await waitFor("A", function () { return false; }, 6);
  check("A's stream is sent nothing about bob", function () {
    assert.strictEqual(anyAbout("A", bob.sub).length, 0,
                       JSON.stringify(anyAbout("A", bob.sub)).slice(0, 800));
  });

  log.info("=== d. alice's account disabled, which ends her session ===");
  await ok(realmApi + "/users/disable", { user: ALICE },
           "disabled " + ALICE);
  const aliceRevoked = await waitFor("A", function (set) {
    return !!eventOf(set, CAEP + "session-revoked") && about(set, alice.sub);
  });
  const aliceDisabled = await waitFor("A", function (set) {
    return !!eventOf(set, RISC + "account-disabled") && about(set, alice.sub);
  });
  check("A's stream is sent session-revoked about alice", function () {
    assert.ok(aliceRevoked, JSON.stringify(SEEN.A).slice(0, 1200));
  });
  check("and RISC account-disabled about her: the event that ended her " +
        "session on A still reaches A", function () {
    assert.ok(aliceDisabled, JSON.stringify(SEEN.A).slice(0, 1200));
  });
  await waitFor("B", function () { return false; }, 6);
  check("B's stream is sent nothing about alice", function () {
    assert.strictEqual(anyAbout("B", alice.sub).length, 0,
                       JSON.stringify(anyAbout("B", alice.sub)).slice(0, 800));
  });

  log.info("=== e. carol, signed in nowhere, disabled ===");
  const carolDisabled = await postJson(realmApi + "/users/disable",
                                       { user: CAROL });
  await waitFor("A", function () { return false; }, 8);
  await waitFor("B", function () { return false; }, 2);
  check("neither stream hears of carol's account-disabled", function () {
    assert.strictEqual(carolDisabled.status, 200,
                       carolDisabled.raw.slice(0, 300));
    const named = SEEN.A.concat(SEEN.B).filter(function (set) {
      return !!eventOf(set, RISC + "account-disabled") &&
             !about(set, alice.sub) && !about(set, bob.sub);
    });
    assert.strictEqual(named.length, 0, JSON.stringify(named).slice(0, 800));
  });

  log.info("=== f. ssf.applicationStreamScope all ===");
  await ok(realmApi + "/config/set", { key: "ssf.applicationStreamScope",
    value: "all" }, "set the scope to all in " + REALM);
  try {
    await ok(realmApi + "/users/disable", { user: BOB }, "disabled " + BOB);
    const old = await waitFor("A", function (set) {
      return !!eventOf(set, RISC + "account-disabled") && about(set, bob.sub);
    });
    check("with all, A's stream hears of bob, signed in nowhere: the " +
          "behaviour before #2234", function () {
      assert.ok(old, JSON.stringify(SEEN.A).slice(0, 1200));
    });
  } finally {
    await ok(realmApi + "/config/reset", { key: "ssf.applicationStreamScope" },
             "put the scope back");
  }

  log.info("=== g. an event about the application itself ===");
  await ok(realmApi + "/applications/rotate-secret",
           { application: APPS.A.id }, "rotated " + APPS.A.id + "'s secret");
  const own = await waitFor("A", function (set) {
    const change = eventOf(set, CAEP + "credential-change");
    const s = set && set.sub_id;
    return !!change && !!s && s.format === "complex" && !s.user &&
           !!s.application && String(s.application.id) === APPS.A.id;
  });
  check("A's own credential-change, about the application and nobody, " +
        "reaches A's stream with no person signed in", function () {
    assert.ok(own, JSON.stringify(SEEN.A).slice(-1500));
  });

  log.info("Test completed successfully. " + checks + " check(s) passed.");
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error("sts_ssf_application_sessions FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
