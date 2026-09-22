"use strict";
//
// File: sts_risc_acts.js
//
// ---------------------------------------------------------------------------
// RISC ON ITS OWN, OVER THE WIRE (#146, 2026-09-22).
//
// In a throwaway realm it leaves behind, with a poll stream taking every RISC
// type and covering everybody:
//
//   a. an administrator's reset link marked "the credential was compromised"
//      sends account-credential-change-required, recovery-activated and
//      credential-compromise (credential_type password), each with an
//      iss_sub subject — the RFC 9493 name, never issuer_subject_id;
//   b. a disable carrying a RISC reason sends account-disabled with it, and
//      one without sends none — the reason is never invented;
//   c. an address a deleted account held, given to a new account, sends
//      identifier-recycled with the address as the subject;
//   d. the account holder's section 2.8 choice on /portal/signals:
//      opt-out-initiated, opt-out-cancelled, opt-out-initiated again, then
//      opt-out-effective from the risc.opt-out-effective scheduler job once
//      risc.optOutDelayHours (set to 0 here) has passed, and opt-in;
//   e. a move the state diagram does not allow is refused (409).
//
// OWNED HERE (local: true): this repository's own transmitter and portal.
// ---------------------------------------------------------------------------

const assert = require("assert");
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
var log = bunyan.createLogger({ name: "sts_risc_acts",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("risc146-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                               .slice(0, 31);
const R = "/realm/" + REALM;
const realmBase = base + R;
const realmApi = realmBase + "/admin-api";
const RISC = "https://schemas.openid.net/secevent/risc/event-type/";
const POLL = "urn:ietf:rfc:8936";
const SECRET = "risc-146-" + String(Date.now()).slice(-8);
const RECEIVER = "risc146-rx-" + STAMP.toLowerCase();
const PASSWORD = "Risc-146-Passw0rd!-" + String(Date.now()).slice(-6);
const ALICE = names.usernameFor("r146-alice");
const CAROL = names.usernameFor("r146-carol");
const BOB = names.usernameFor("r146-bob");
const DAVE = names.usernameFor("r146-dave");
const EVE = names.usernameFor("r146-eve");
const SHARED = "recycled-" + STAMP.toLowerCase() + "@risc146.test";
const AGENT = "sts_risc_acts/1.0";

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

// One browser, with a cookie jar.
function browser(name) {
  log.debug("Entering browser(). " + name);
  const jar = {};
  const self = {
    async go(method, path, body) {
      log.debug("Entering go(). " + method + " " + path);
      const headers = { "User-Agent": AGENT };
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
               text: text, headers: r.headers };
    }
  };
  log.debug("Leaving browser().");
  return self;
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

function decode(token) {
  log.debug("Entering decode().");
  const parts = String(token).split(".");
  log.debug("Leaving decode().");
  return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
}

async function tokenFor(scope) {
  log.debug("Entering tokenFor().");
  const r = await send(realmBase + "/oauth2/token", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form({ grant_type: "client_credentials", client_id: RECEIVER,
                 client_secret: SECRET, scope: scope }) });
  assert.ok(r.body && r.body.access_token,
            "a token for " + scope + ": " + r.raw.slice(0, 300));
  log.debug("Leaving tokenFor().");
  return r.body.access_token;
}

// Every SET waiting on the stream, decoded, and acknowledged.
async function drain(token, streamId) {
  log.debug("Entering drain().");
  const auth = { "Content-Type": "application/json",
                 Authorization: "Bearer " + token };
  const r = await send(realmBase + "/ssf/poll", { method: "POST",
    headers: auth, body: JSON.stringify({ stream_id: streamId,
      returnImmediately: true, maxEvents: 100 }) });
  assert.strictEqual(r.status, 200, "poll: " + r.raw.slice(0, 300));
  const sets = r.body.sets || {};
  const jtis = Object.keys(sets);
  if (jtis.length) {
    await send(realmBase + "/ssf/poll", { method: "POST", headers: auth,
      body: JSON.stringify({ stream_id: streamId, ack: jtis,
                             returnImmediately: true, maxEvents: 0 }) });
  }
  log.debug("Leaving drain(). " + jtis.length + " SET(s).");
  return jtis.map(function (jti) {
    return decode(sets[jti]);
  });
}

// Waits for the stream to hold a SET the predicate accepts. Delivery is on a
// promise after the write answers, so a first poll may be early.
// Everything drained and not yet matched. A drain acknowledges every SET it
// reads, so events that arrive together (a reset link sends three) must be
// kept for the waits that follow, and a matched one is taken out so that two
// waits for the same type find two events.
const POOL = [];
async function waitFor(token, streamId, what, predicate, tries) {
  log.debug("Entering waitFor(). " + what);
  for (let i = 0; i < (tries || 20); i++) {
    (await drain(token, streamId)).forEach(function (one) {
      POOL.push(one);
    });
    const at = POOL.findIndex(predicate);
    if (at >= 0) {
      const hit = POOL.splice(at, 1)[0];
      log.debug("Leaving waitFor(). Found.");
      return { hit: hit, seen: POOL.slice() };
    }
    await new Promise(function (r) { setTimeout(r, 250); });
  }
  log.debug("Leaving waitFor(). Not found.");
  return { hit: null, seen: POOL.slice() };
}

function riscEvent(set, type) {
  log.debug("Entering riscEvent().");
  log.debug("Leaving riscEvent().");
  return ((set && set.events) || {})[RISC + type] || null;
}

function userOf(set) {
  log.debug("Entering userOf().");
  const sub = set && set.sub_id;
  log.debug("Leaving userOf().");
  return sub && sub.format === "complex" ? sub.user : sub;
}

async function signInToPortal(who) {
  log.debug("Entering signInToPortal().");
  const b = browser(who);
  let r = await b.go("GET", R + "/portal");
  for (let i = 0; i < 8 && (r.status === 302 || r.status === 303); i++) {
    if (/\/authn\/login\?authn=/.test(r.location)) {
      const page = await b.go("GET", r.location);
      const fields = hiddenFields(page.text);
      fields.username = who;
      fields.password = PASSWORD;
      fields.action = "login";
      r = await b.go("POST", R + "/authn/login", form(fields));
      continue;
    }
    r = await b.go("GET", r.location);
  }
  assert.strictEqual(r.status, 200, "the portal after sign-in: " + r.status +
                     " " + r.location + " " + String(r.text).slice(0, 300));
  log.debug("Leaving signInToPortal().");
  return b;
}

// POST one opt-out move from the page's own form (and its CSRF token).
async function move(b, which) {
  log.debug("Entering move(). " + which);
  const page = await b.go("GET", R + "/portal/signals");
  const csrf = (String(page.text)
    .match(/name="csrf_token" value="([^"]+)"/) || [])[1] || "";
  const r = await b.go("POST", R + "/portal/signals",
                       form({ move: which, csrf_token: csrf }));
  log.debug("Leaving move(). " + r.status);
  return r;
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. a throwaway realm " + REALM + " and a poll stream ===");
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "RISC 146 " + STAMP },
    "created the realm");
  await ok(realmApi + "/applications/create", { identifier: RECEIVER,
    kind: "oauth2-client", name: RECEIVER, protocols: ["oauth2", "ssf"],
    // The Shared Signals and SCIM scopes are issued only to a client that
    // declares them (#110).
    fields: { oauthClientId: [RECEIVER], oauthClientSecret: SECRET,
              oauthTokenEndpointAuthMethod: "client_secret_post",
              oauthAllowedScope: ["ssf:read", "ssf:write", "scim:read",
                                  "scim:write"],
              oauthGrantType: ["client_credentials"] } },
    "created the receiver's application");
  const token = await tokenFor("ssf:read ssf:write");
  const types = ["account-credential-change-required", "recovery-activated",
    "credential-compromise", "account-disabled", "account-enabled",
    "identifier-recycled", "opt-out-initiated", "opt-out-cancelled",
    "opt-out-effective", "opt-in"].map(function (t) { return RISC + t; });
  const created = await send(realmBase + "/ssf/stream", { method: "POST",
    headers: { "Content-Type": "application/json",
               Authorization: "Bearer " + token },
    body: JSON.stringify({ delivery: { method: POLL },
                           events_requested: types }) });
  check("a poll stream takes the RISC types under test", function () {
    assert.strictEqual(created.status, 201, created.raw.slice(0, 400));
  });
  const streamId = created.body.stream_id;
  for (const who of [ALICE, CAROL, BOB, EVE]) {
    await ok(realmApi + "/users/create", { username: who, invent: false,
      credential: "password", password: PASSWORD,
      attributes: { cn: "RISC " + who, givenName: "RISC", sn: who,
                    mail: who === BOB ? SHARED : who + "@risc146.test" } },
      "created " + who);
  }
  await drain(token, streamId);
  POOL.length = 0;

  log.info("=== a. a reset link marked compromised ===");
  await ok(realmApi + "/users/issue-password-reset",
           { user: ALICE, compromised: true }, "issued a reset link");
  const wanted = ["account-credential-change-required", "recovery-activated",
                  "credential-compromise"];
  const seen = [];
  for (const one of wanted) {
    const found = await waitFor(token, streamId, one, function (set) {
      return !!riscEvent(set, one);
    });
    seen.push(found.hit);
    check(one + " is sent, about alice, with an iss_sub subject",
      function () {
        assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 1200));
        const user = userOf(found.hit);
        assert.strictEqual(user && user.format, "iss_sub",
                           JSON.stringify(found.hit.sub_id));
      });
  }
  check("credential-compromise carries credential_type password",
    function () {
      assert.strictEqual(riscEvent(seen[2], "credential-compromise")
        .credential_type, "password");
    });

  log.info("=== b. a disable, with and without a RISC reason ===");
  await ok(realmApi + "/users/disable", { user: CAROL,
    riscReason: "hijacking" }, "disabled carol, reason hijacking");
  let found = await waitFor(token, streamId, "disabled", function (set) {
    return !!riscEvent(set, "account-disabled");
  });
  check("account-disabled carries the reason the administrator gave",
    function () {
      assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 800));
      assert.strictEqual(riscEvent(found.hit, "account-disabled").reason,
                         "hijacking");
    });
  await ok(realmApi + "/users/enable", { user: CAROL }, "enabled carol");
  await ok(realmApi + "/users/disable", { user: CAROL },
           "disabled carol again, no reason");
  found = await waitFor(token, streamId, "disabled again", function (set) {
    return !!riscEvent(set, "account-disabled");
  });
  check("and one without a reason carries none", function () {
    assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 800));
    assert.ok(!("reason" in riscEvent(found.hit, "account-disabled")),
              JSON.stringify(riscEvent(found.hit, "account-disabled")));
  });
  const badReason = await postJson(realmApi + "/users/disable",
    { user: EVE, riscReason: "left the company" });
  check("a reason RISC does not define is refused", function () {
    assert.strictEqual(badReason.status, 400, badReason.raw.slice(0, 300));
  });

  log.info("=== c. an address recycled ===");
  const scimToken = await tokenFor("scim:read scim:write");
  const scimAuth = { Authorization: "Bearer " + scimToken };
  const listed = await send(realmBase + "/scim/v2/Users?filter=" +
    encodeURIComponent("userName eq \"" + BOB + "\""), { headers: scimAuth });
  const bobId = listed.body && listed.body.Resources &&
                listed.body.Resources[0] && listed.body.Resources[0].id;
  const deleted = await send(realmBase + "/scim/v2/Users/" + bobId,
                             { method: "DELETE", headers: scimAuth });
  check("bob, who held the address, is deleted", function () {
    assert.ok(deleted.status === 204 || deleted.status === 200,
              deleted.status + " " + deleted.raw.slice(0, 200));
  });
  await ok(realmApi + "/users/create", { username: DAVE, invent: false,
    credential: "password", password: PASSWORD,
    attributes: { cn: "RISC " + DAVE, givenName: "RISC", sn: DAVE,
                  mail: SHARED } }, "created dave with bob's address");
  found = await waitFor(token, streamId, "recycled", function (set) {
    return !!riscEvent(set, "identifier-recycled");
  });
  check("identifier-recycled is sent, its subject the address", function () {
    assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 800));
    const user = userOf(found.hit);
    assert.strictEqual(user && user.email, SHARED,
                       JSON.stringify(found.hit.sub_id));
  });

  log.info("=== d. the account holder's opt-out on the portal ===");
  const b = await signInToPortal(EVE);
  const page = await b.go("GET", R + "/portal/signals");
  check("the portal offers eve the choice", function () {
    assert.ok(/Stop sharing security events/.test(page.text),
              page.text.slice(0, 600));
  });
  let r = await move(b, "optOutInitiated");
  found = await waitFor(token, streamId, "initiated", function (set) {
    return !!riscEvent(set, "opt-out-initiated");
  });
  check("opting out sends opt-out-initiated", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 800));
  });
  r = await move(b, "optIn");
  check("e. opting straight back in from opt-out-initiated is refused " +
        "(409)", function () {
    assert.strictEqual(r.status, 409, r.text.slice(0, 300));
  });
  r = await move(b, "optOutCancelled");
  found = await waitFor(token, streamId, "cancelled", function (set) {
    return !!riscEvent(set, "opt-out-cancelled");
  });
  check("cancelling sends opt-out-cancelled", function () {
    assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 800));
  });
  await move(b, "optOutInitiated");
  await drain(token, streamId);
  POOL.length = 0;
  await ok(realmApi + "/config/set", { key: "risc.optOutDelayHours",
                                       value: 0 }, "set the delay to 0");
  const queued = await postJson(realmApi + "/scheduler/run",
                                { job: "risc.opt-out-effective" });
  check("the risc.opt-out-effective job is queued to run now (202)",
    function () {
      assert.strictEqual(queued.status, 202, queued.raw.slice(0, 300));
    });
  // A queued run is picked up on the scheduler's own tick: up to 30 s.
  found = await waitFor(token, streamId, "effective", function (set) {
    return !!riscEvent(set, "opt-out-effective");
  }, 120);
  check("the scheduler job sends opt-out-effective once the delay has " +
        "passed", function () {
    assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 800));
  });
  const again = await waitFor(token, streamId, "a second effective",
    function (set) {
      return !!riscEvent(set, "opt-out-effective");
    }, 8);
  check("and sends it ONCE", function () {
    assert.strictEqual(again.hit, null, JSON.stringify(again.hit));
  });
  r = await move(b, "optIn");
  found = await waitFor(token, streamId, "opt-in", function (set) {
    return !!riscEvent(set, "opt-in");
  });
  check("opting back in sends opt-in", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 800));
  });
  await ok(realmApi + "/config/reset", { key: "risc.optOutDelayHours" },
           "put the delay back");

  log.info("Test completed successfully. " + checks + " check(s) passed.");
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error("sts_risc_acts FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
