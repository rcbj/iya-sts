"use strict";
//
// File: sts_service_key_signals.js
//
// ---------------------------------------------------------------------------
// THE OTHER KEYS A RELYING PARTY PINS ARE ANNOUNCED, OVER THE WIRE (#245,
// 2026-09-26).
//
// In a throwaway realm it leaves behind — Kerberos on, with its own Kerberos
// realm, and `krb5.retainedKeyVersions` 0 — with a poll stream that takes
// this service's own key events:
//
//   a. `POST /admin-api/oidfed/rotate-key` queues a rotation of the realm's
//      Federation Entity Key; once it has run, `federation-key-rotated`
//      arrives naming the realm, the key that stopped signing and the one
//      that signs now, reason "requested", and the Entity Configuration to
//      fetch again;
//   b. an EMERGENCY rotation arrives as reason "emergency", naming the next
//      key it revoked as well;
//   c. `POST /admin-api/spiffe/rotate` for the JWT authority sends
//      `spiffe-authority-rotated`, the bundle changed, with the realm's trust
//      domain and bundle address;
//   d. `rotate-krbtgt` — an ORDINARY rotation — keeps nothing with
//      `krb5.retainedKeyVersions` 0, so every TGT in the realm is refused:
//      `kerberos-tickets-invalidated` arrives with reason
//      "nothing-retained", where it used to arrive for "rotate and
//      invalidate" alone.
//
// The listener certificate's event (`tls-certificate-changed`) is not driven
// here: replacing it means rebuilding the process branch or the Root, which
// every other job in the run shares; `tests/service_key_signals.js` holds it
// in a process of its own, with the deletion notice of a stream (a poll
// receiver cannot read a SET from a stream that no longer exists).
//
// OWNED HERE (local: true): this repository's transmitter, OpenID
// Federation, SPIFFE and KDC.
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
var log = bunyan.createLogger({ name: "sts_service_key_signals",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("keys245-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                               .slice(0, 31);
const DOMAIN = REALM + ".example.net";
const KREALM = DOMAIN.toUpperCase();
const realmBase = base + "/realm/" + REALM;
const realmApi = realmBase + "/admin-api";
const OWN = "urn:iya:sts:secevent:event-type:";
const POLL = "urn:ietf:rfc:8936";
const SECRET = "keys-245-" + String(Date.now()).slice(-8);
const RECEIVER = "keys245-rx-" + STAMP.toLowerCase();

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
async function waitFor(token, streamId, what, predicate, rounds) {
  log.debug("Entering waitFor(). " + what);
  for (let i = 0; i < (rounds || 240); i++) {
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

function own(set, name) {
  log.debug("Entering own().");
  log.debug("Leaving own().");
  return ((set && set.events) || {})[OWN + name] || null;
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. a throwaway realm " + REALM + " and a poll stream ===");
  await ok(base + "/admin-api/realms/create", { id: REALM, domain: DOMAIN,
    name: "Keys 245 " + STAMP,
    overrides: { "krb5.enabled": true, "krb5.realm": KREALM,
                 "krb5.retainedKeyVersions": 0 } },
    "created the realm with Kerberos on and no krbtgt version kept");
  await ok(realmApi + "/applications/create", { identifier: RECEIVER,
    kind: "oauth2-client", name: RECEIVER, protocols: ["oauth2", "ssf"],
    fields: { oauthClientId: [RECEIVER], oauthClientSecret: SECRET,
              oauthTokenEndpointAuthMethod: "client_secret_post",
              oauthAllowedScope: ["ssf:read", "ssf:write"],
              oauthGrantType: ["client_credentials"] } },
    "created the receiver's application");
  const token = await tokenFor("ssf:read ssf:write");
  const wanted = ["federation-key-rotated", "spiffe-authority-rotated",
                  "tls-certificate-changed", "kerberos-tickets-invalidated"]
    .map(function (name) {
      return OWN + name;
    });
  const created = await send(realmBase + "/ssf/stream", { method: "POST",
    headers: { "Content-Type": "application/json",
               Authorization: "Bearer " + token },
    body: JSON.stringify({ delivery: { method: POLL },
                           events_requested: wanted }) });
  check("a poll stream takes the four key events, which this service " +
        "offers", function () {
      assert.strictEqual(created.status, 201, created.raw.slice(0, 400));
      const delivered = created.body.events_delivered || [];
      wanted.forEach(function (uri) {
        assert.ok(delivered.indexOf(uri) >= 0, uri + " not in " +
                  JSON.stringify(delivered));
      });
    });
  const streamId = created.body.stream_id;

  log.info("=== a. the Federation Entity Key rotated by hand ===");
  await ok(realmApi + "/oidfed/rotate-key", {}, "queued a rotation");
  let found = await waitFor(token, streamId, "federation-key-rotated",
    function (set) {
      const ev = own(set, "federation-key-rotated");
      return !!ev && ev.reason === "requested";
    });
  check("federation-key-rotated arrives: the realm, the key that stopped " +
        "signing and the one that signs now, reason requested, and the " +
        "Entity Configuration's address", function () {
      assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 1200));
      const ev = own(found.hit, "federation-key-rotated");
      assert.strictEqual(ev.realm, REALM);
      assert.ok(/^federation-entity-key \S+ -> \S+$/.test(ev.rotated),
                ev.rotated);
      assert.ok(!ev.entity_configuration_uri ||
                /\/\.well-known\/openid-federation$/.test(
                  ev.entity_configuration_uri), JSON.stringify(ev));
    });

  log.info("=== b. an emergency ===");
  await ok(realmApi + "/oidfed/rotate-key", { emergency: true,
    confirm: "compromised" }, "queued an emergency rotation");
  found = await waitFor(token, streamId, "federation-key-rotated emergency",
    function (set) {
      const ev = own(set, "federation-key-rotated");
      return !!ev && ev.reason === "emergency";
    });
  check("an EMERGENCY arrives as one, naming the next key revoked with the " +
        "current one", function () {
      assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 1200));
      const ev = own(found.hit, "federation-key-rotated");
      assert.ok(/-> revoked/.test(ev.rotated), ev.rotated);
    });

  log.info("=== c. the SPIFFE JWT authority rotated ===");
  const spiffe = await postJson(realmApi + "/spiffe/rotate", { which: "jwt" });
  check("the rotation is accepted", function () {
    assert.strictEqual(spiffe.status, 200, spiffe.raw.slice(0, 400));
  });
  found = await waitFor(token, streamId, "spiffe-authority-rotated",
    function (set) {
      const ev = own(set, "spiffe-authority-rotated");
      return !!ev && /^jwt-authority /.test(String(ev.rotated));
    });
  check("spiffe-authority-rotated arrives, the bundle changed, with the " +
        "realm's trust domain", function () {
      assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 1200));
      const ev = own(found.hit, "spiffe-authority-rotated");
      assert.strictEqual(ev.realm, REALM);
      assert.strictEqual(ev.bundle_changed, true, JSON.stringify(ev));
      assert.ok(ev.trust_domain, JSON.stringify(ev));
      assert.strictEqual(ev.reason, "requested");
    });

  log.info("=== d. an ordinary krbtgt rotation that keeps nothing ===");
  await ok(realmApi + "/kerberos/principals/rotate-krbtgt", {},
           "queued an ordinary krbtgt rotation");
  found = await waitFor(token, streamId, "kerberos-tickets-invalidated",
    function (set) {
      const ev = own(set, "kerberos-tickets-invalidated");
      return !!ev && ev.reason === "nothing-retained";
    }, 480);
  check("WITH NO VERSION KEPT, AN ORDINARY ROTATION ENDS EVERY TGT AND SAYS " +
        "SO: kerberos-tickets-invalidated, reason nothing-retained, naming " +
        "the realm's Kerberos realm", function () {
      assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 1200));
      const ev = own(found.hit, "kerberos-tickets-invalidated");
      assert.strictEqual(ev.kerberos_realm, KREALM, JSON.stringify(ev));
      assert.ok(ev.kvno > 0, JSON.stringify(ev));
    });

  log.info("Test completed successfully. " + checks + " check(s) passed.");
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error("sts_service_key_signals FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
