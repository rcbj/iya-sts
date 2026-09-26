"use strict";
//
// File: sts_ca_hierarchy_signals.js
//
// ---------------------------------------------------------------------------
// AN ACT ON THE CERTIFICATE HIERARCHY TELLS THE PEOPLE UNDER IT, OVER THE
// WIRE (#244, 2026-09-26).
//
// In a throwaway realm it leaves behind, with a poll stream that takes CAEP
// credential-change and RISC credential-compromise and covers everybody:
//
//   a. a person is issued a signing key pair on /admin-api/pki — a
//      certificate in the realm's "assertions" Issuing CA's issued register,
//      which this service holds no key to re-certify;
//   b. `reissue-use-case` on that Issuing CA orphans it: credential-change
//      (x509, revoke) naming the OLD serial, about the person, and the answer
//      says people were affected;
//   c. a second key pair, then the NEW Issuing CA revoked on its
//      Intermediate's list for keyCompromise: credential-change (x509,
//      revoke) naming the second serial AND RISC credential-compromise
//      (x509), both about the person — the revocation walks down the tier.
//
// Only this realm's authorities are touched: a revoked Issuing CA in the
// default realm would refuse other jobs' certificates.
//
// OWNED HERE (local: true): this repository's certificate authority and
// transmitter.
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
var log = bunyan.createLogger({ name: "sts_ca_hierarchy_signals",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("ca244-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                              .slice(0, 31);
const realmBase = base + "/realm/" + REALM;
const realmApi = realmBase + "/admin-api";
const CAEP = "https://schemas.openid.net/secevent/caep/event-type/";
const RISC = "https://schemas.openid.net/secevent/risc/event-type/";
const POLL = "urn:ietf:rfc:8936";
const SECRET = "ca-244-" + String(Date.now()).slice(-8);
const RECEIVER = "ca244-rx-" + STAMP.toLowerCase();
const ALICE = names.usernameFor("c244-alice");
const PASSWORD = "Ca-244-Passw0rd!-" + String(Date.now()).slice(-6);

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
  return { status: r.status, body: body, raw: raw };
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

// Waits for the stream to have held a SET the predicate accepts, keeping
// every SET seen so a later wait can find one an earlier poll collected.
const POOL = [];
async function waitFor(token, streamId, what, predicate) {
  log.debug("Entering waitFor(). " + what);
  for (let i = 0; i < 40; i++) {
    const sets = await drain(token, streamId);
    sets.forEach(function (one) {
      POOL.push(one);
    });
    const hit = POOL.filter(predicate)[0];
    if (hit) {
      log.debug("Leaving waitFor(). Found.");
      return { hit: hit, seen: POOL.slice() };
    }
    await new Promise(function (r) { setTimeout(r, 250); });
  }
  log.debug("Leaving waitFor(). Not found.");
  return { hit: null, seen: POOL.slice() };
}

function eventOf(set, uri) {
  log.debug("Entering eventOf().");
  log.debug("Leaving eventOf().");
  return ((set && set.events) || {})[uri] || null;
}

function userOf(set) {
  log.debug("Entering userOf().");
  const sub = set && set.sub_id;
  log.debug("Leaving userOf().");
  return sub && sub.format === "complex" ? sub.user : sub;
}

function normal(serial) {
  log.debug("Entering normal().");
  log.debug("Leaving normal().");
  return String(serial || "").toLowerCase().replace(/[^0-9a-f]/g, "")
    .replace(/^0+/, "");
}

// A certificate change about the x509 serial asked for.
function certificateChange(changeType, serial) {
  log.debug("Entering certificateChange().");
  log.debug("Leaving certificateChange().");
  return function (set) {
    const ev = eventOf(set, CAEP + "credential-change");
    return !!ev && ev.credential_type === "x509" &&
           ev.change_type === changeType &&
           normal(ev.x509_serial) === normal(serial);
  };
}

// Issues the person a key pair and answers its serial, which the issue's
// answer does not carry: the credential-change (x509) it sends
// does, and is the first such event naming a serial not seen before.
const SERIALS = [];
async function issueTo(who, token, streamId) {
  log.debug("Entering issueTo().");
  const issued = await postJson(realmApi + "/pki/issue", { target: "person",
    identifier: who });
  assert.strictEqual(issued.status, 200, issued.raw.slice(0, 400));
  const found = await waitFor(token, streamId, "x509 create",
    function (set) {
      const ev = eventOf(set, CAEP + "credential-change");
      // A second key pair REPLACES the first: `update` then.
      return !!ev && ev.credential_type === "x509" &&
             (ev.change_type === "create" || ev.change_type === "update") &&
             SERIALS.indexOf(normal(ev.x509_serial)) < 0;
    });
  assert.ok(found.hit, "no credential-change (x509, create) for the key " +
            "pair: " + JSON.stringify(found.seen).slice(0, 1200));
  const serial = normal(eventOf(found.hit, CAEP + "credential-change")
    .x509_serial);
  SERIALS.push(serial);
  log.debug("Leaving issueTo(). " + serial);
  return { serial: serial, set: found.hit };
}

// The realm's "assertions" Issuing CA, as its Intermediate's register lists
// it on GET /admin-api/pki.
async function assertionsCa() {
  log.debug("Entering assertionsCa().");
  const view = await send(realmApi + "/pki");
  assert.strictEqual(view.status, 200, view.raw.slice(0, 300));
  const authorities = (view.body.revocation &&
                       view.body.revocation.authorities) || [];
  const intermediate = authorities.filter(function (one) {
    return one.ca === "intermediate" && String(one.scope) === REALM;
  })[0];
  assert.ok(intermediate, "no Intermediate for " + REALM + " among " +
            JSON.stringify(authorities.map(function (one) {
              return one.scope + "/" + one.ca;
            })));
  const tier = (intermediate.issued || []).filter(function (one) {
    return one.kind === "issuing-ca" && !one.revoked &&
           /assertions/i.test(String(one.label));
  })[0];
  assert.ok(tier, "no assertions Issuing CA under " + REALM + ": " +
            JSON.stringify(intermediate.issued).slice(0, 600));
  log.debug("Leaving assertionsCa().");
  return tier;
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. a throwaway realm " + REALM + " and a poll stream ===");
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "CA 244 " + STAMP },
    "created the realm");
  await ok(realmApi + "/pki/build", {}, "built the realm's authority");
  await ok(realmApi + "/applications/create", { identifier: RECEIVER,
    kind: "oauth2-client", name: RECEIVER, protocols: ["oauth2", "ssf"],
    fields: { oauthClientId: [RECEIVER], oauthClientSecret: SECRET,
              oauthTokenEndpointAuthMethod: "client_secret_post",
              oauthAllowedScope: ["ssf:read", "ssf:write"],
              oauthGrantType: ["client_credentials"] } },
    "created the receiver's application");
  const token = await tokenFor("ssf:read ssf:write");
  const created = await send(realmBase + "/ssf/stream", { method: "POST",
    headers: { "Content-Type": "application/json",
               Authorization: "Bearer " + token },
    body: JSON.stringify({ delivery: { method: POLL },
      events_requested: [CAEP + "credential-change",
                         RISC + "credential-compromise"] }) });
  check("a poll stream takes credential-change and credential-compromise",
    function () {
      assert.strictEqual(created.status, 201, created.raw.slice(0, 400));
      const delivered = created.body.events_delivered || [];
      assert.ok(delivered.indexOf(CAEP + "credential-change") >= 0 &&
                delivered.indexOf(RISC + "credential-compromise") >= 0,
                JSON.stringify(delivered));
    });
  const streamId = created.body.stream_id;
  await ok(realmApi + "/users/create", { username: ALICE, invent: false,
    credential: "password", password: PASSWORD,
    attributes: { cn: "CA " + ALICE, givenName: "CA", sn: ALICE,
                  mail: ALICE + "@ca244.test" } }, "created " + ALICE);

  log.info("=== a. a key pair for the person ===");
  const issuedFirst = await issueTo(ALICE, token, streamId);
  const first = issuedFirst.serial;
  let found = { hit: issuedFirst.set, seen: [] };
  check("the key pair is announced (credential-change x509 create), which " +
        "names the person's subject", function () {
    assert.ok(first && userOf(found.hit), JSON.stringify(found.hit));
  });
  const alice = JSON.stringify(userOf(found.hit));
  const aliceSub = String((userOf(found.hit) || {}).sub || ALICE);

  log.info("=== b. its Issuing CA reissued ===");
  const reissued = await postJson(realmApi + "/pki/reissue-use-case",
                                  { useCase: "assertions" });
  check("reissue-use-case answers, and says certificates held by people " +
        "were affected", function () {
    assert.strictEqual(reissued.status, 200, reissued.raw.slice(0, 400));
    assert.ok(/held by people were affected/.test(String(reissued.body.why)),
              String(reissued.body.why));
  });
  found = await waitFor(token, streamId, "x509 revoke (orphaned)",
                        certificateChange("revoke", first));
  check("THE KEY PAIR IS ORPHANED, NOT RE-MINTED: credential-change (x509, " +
        "revoke) naming its serial, about the same person", function () {
    assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 1200));
    assert.strictEqual(JSON.stringify(userOf(found.hit)), alice);
    const ev = eventOf(found.hit, CAEP + "credential-change");
    assert.ok(/CN=/.test(String(ev.x509_issuer)), JSON.stringify(ev));
  });

  log.info("=== c. the new Issuing CA revoked for keyCompromise ===");
  const second = (await issueTo(ALICE, token, streamId)).serial;
  const tier = await assertionsCa();
  const revoked = await postJson(realmApi + "/pki/revoke-certificate", {
    scope: REALM, ca: "intermediate", serialHex: tier.serialHex,
    reason: "keyCompromise", note: "driven by sts_ca_hierarchy_signals" });
  check("the Issuing CA goes on its Intermediate's list, and the answer " +
        "says the people beneath it are told", function () {
    assert.strictEqual(revoked.status, 200, revoked.raw.slice(0, 400));
    assert.ok(/Issuing CA/.test(String(revoked.body.why)) &&
              /credential-compromise/.test(String(revoked.body.why)),
              String(revoked.body.why));
  });
  found = await waitFor(token, streamId, "x509 revoke (tier)",
                        certificateChange("revoke", second));
  check("A REVOKED ISSUING CA WALKS DOWN TO ITS LEAVES: credential-change " +
        "(x509, revoke) naming the second key pair's serial", function () {
    assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 1200));
    assert.strictEqual(JSON.stringify(userOf(found.hit)), alice);
  });
  found = await waitFor(token, streamId, "credential-compromise",
    function (set) {
      const ev = eventOf(set, RISC + "credential-compromise");
      // RISC names an account, and may name it in another format than
      // CAEP's session subject; the person's `sub` is in it either way.
      return !!ev && ev.credential_type === "x509" &&
             JSON.stringify(set.sub_id || {}).indexOf(aliceSub) >= 0;
    });
  check("AND, FOR keyCompromise, RISC credential-compromise (x509) about " +
        "the person", function () {
    assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 1200));
  });

  log.info("Test completed successfully. " + checks + " check(s) passed.");
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error("sts_ca_hierarchy_signals FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
