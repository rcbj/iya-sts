// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_application_signals.js
//
// ---------------------------------------------------------------------------
// SHARED SIGNALS ABOUT AN APPLICATION, OVER THE WIRE (#221 P5, 2026-10-06).
//
// In a throwaway realm it leaves behind:
//
//   a. a receiver's poll stream that takes CAEP credential-change ADDS an
//      application as its subject — SSF 1.0's complex subject with an
//      `application` member, format `opaque`, the application's client_id —
//      and is answered 200;
//   b. the application's client secret is ROTATED through /admin-api
//      (`POST /admin-api/applications/rotate-secret`), and the stream is
//      sent ONE credential-change about the application: credential_type
//      `urn:iya:sts:credential-type:client-secret`, change_type `update`,
//      initiated by `admin`, and a subject with no `user` member;
//   c. a second application's secret rotated is NOT sent to the stream,
//      which names only the first;
//   d. the subject is removed again, 204.
//
// OWNED HERE (local: true): this repository's own transmitter and
// management API.
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
var log = bunyan.createLogger({ name: "sts_application_signals",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("app221-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                               .slice(0, 31);
const R = "/realm/" + REALM;
const realmBase = base + R;
const realmApi = realmBase + "/admin-api";
const CAEP = "https://schemas.openid.net/secevent/caep/event-type/";
const POLL = "urn:ietf:rfc:8936";
const SECRET = "app-221-" + String(Date.now()).slice(-8);
const RECEIVER = "app221-rx-" + STAMP.toLowerCase();
const TARGET = "app221-svc-" + STAMP.toLowerCase();
const OTHER = "app221-other-" + STAMP.toLowerCase();
const CLIENT_SECRET_TYPE = "urn:iya:sts:credential-type:client-secret";

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
    // Not JSON — an empty answer or a page; the caller reads `raw`.
    body = null;
  }
  log.debug("Leaving send(). status=" + r.status);
  return { status: r.status, body: body, raw: raw };
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
  const auth = { Authorization: "Bearer " + token };
  const r = await postJson(realmBase + "/ssf/poll", { stream_id: streamId,
    returnImmediately: true, maxEvents: 100 }, auth);
  assert.strictEqual(r.status, 200, "poll: " + r.raw.slice(0, 300));
  const sets = r.body.sets || {};
  const jtis = Object.keys(sets);
  if (jtis.length) {
    await postJson(realmBase + "/ssf/poll", { stream_id: streamId,
      ack: jtis, returnImmediately: true, maxEvents: 0 }, auth);
  }
  log.debug("Leaving drain(). " + jtis.length + " SET(s).");
  return jtis.map(function (jti) {
    return decode(sets[jti]);
  });
}

// Polls until a SET the predicate accepts arrives, keeping every SET seen.
const received = [];
async function waitFor(token, streamId, predicate, tries) {
  log.debug("Entering waitFor().");
  for (let i = 0; i < (tries || 20); i++) {
    const at = received.findIndex(predicate);
    if (at >= 0) {
      log.debug("Leaving waitFor(). Found.");
      return received.splice(at, 1)[0];
    }
    (await drain(token, streamId)).forEach(function (one) {
      received.push(one);
    });
    if (received.findIndex(predicate) < 0) {
      await new Promise(function (r) { setTimeout(r, 250); });
    }
  }
  log.debug("Leaving waitFor(). Not found.");
  return null;
}

function applicationOf(set) {
  log.debug("Entering applicationOf().");
  const sub = set && set.sub_id;
  const member = sub && sub.format === "complex" ? sub.application : null;
  log.debug("Leaving applicationOf().");
  return member && member.format === "opaque" ? String(member.id) : "";
}

function secretChange(set, who) {
  log.debug("Entering secretChange().");
  const ev = ((set && set.events) || {})[CAEP + "credential-change"];
  log.debug("Leaving secretChange().");
  return !!ev && applicationOf(set) === who &&
         ev.credential_type === CLIENT_SECRET_TYPE;
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. a throwaway realm " + REALM + " ===");
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "Application signals " + STAMP },
    "created the realm");
  await ok(realmApi + "/applications/create", { identifier: RECEIVER,
    kind: "oauth2-client", name: RECEIVER, protocols: ["oauth2", "ssf"],
    fields: { oauthClientId: [RECEIVER], oauthClientSecret: SECRET,
              oauthTokenEndpointAuthMethod: "client_secret_post",
              oauthAllowedScope: ["ssf:read", "ssf:write"],
              oauthGrantType: ["client_credentials"] } },
    "created the receiver's application");
  for (const who of [TARGET, OTHER]) {
    await ok(realmApi + "/applications/create", { identifier: who,
      kind: "oauth2-client", name: who, protocols: ["oauth2"],
      fields: { oauthClientId: [who],
                oauthTokenEndpointAuthMethod: "client_secret_basic",
                oauthGrantType: ["client_credentials"] } },
      "created the application " + who);
    await ok(realmApi + "/applications/add-secret", { application: who },
             "gave " + who + " a client secret");
  }

  log.info("=== a. a stream that adds the application as its subject ===");
  const token = await tokenFor("ssf:read ssf:write");
  const auth = { Authorization: "Bearer " + token };
  const created = await postJson(realmBase + "/ssf/stream", {
    delivery: { method: POLL },
    events_requested: [CAEP + "credential-change"] }, auth);
  check("a poll stream takes credential-change", function () {
    assert.strictEqual(created.status, 201, created.raw.slice(0, 400));
    assert.ok((created.body.events_delivered || [])
      .indexOf(CAEP + "credential-change") >= 0,
              JSON.stringify(created.body.events_delivered));
  });
  const streamId = created.body.stream_id;
  const subject = { format: "complex",
                    application: { format: "opaque", id: TARGET } };
  const added = await postJson(realmBase + "/ssf/subjects/add",
    { stream_id: streamId, subject: subject }, auth);
  check("Add Subject takes the application subject (SSF 1.0 section " +
        "8.1.3.2: 200)", function () {
    assert.strictEqual(added.status, 200, added.raw.slice(0, 400));
  });
  await drain(token, streamId);
  received.length = 0;

  log.info("=== b. the application's secret rotated ===");
  await ok(realmApi + "/applications/rotate-secret", { application: TARGET },
           "rotated " + TARGET + "'s client secret");
  const hit = await waitFor(token, streamId, function (set) {
    return secretChange(set, TARGET);
  });
  check("credential-change about the APPLICATION: client-secret, update, " +
        "by admin, and no user member", function () {
    assert.ok(hit, JSON.stringify(received).slice(0, 1200));
    const ev = hit.events[CAEP + "credential-change"];
    assert.strictEqual(ev.change_type, "update", JSON.stringify(ev));
    assert.strictEqual(ev.initiating_entity, "admin", JSON.stringify(ev));
    assert.ok(!hit.sub_id.user, JSON.stringify(hit.sub_id));
  });

  log.info("=== c. another application's rotation is not this stream's ===");
  await ok(realmApi + "/applications/rotate-secret", { application: OTHER },
           "rotated " + OTHER + "'s client secret");
  const stray = await waitFor(token, streamId, function (set) {
    return secretChange(set, OTHER);
  }, 6);
  check("a stream naming one application is not sent another's", function () {
    assert.strictEqual(stray, null, JSON.stringify(stray));
  });

  log.info("=== d. the subject removed ===");
  const removed = await postJson(realmBase + "/ssf/subjects/remove",
    { stream_id: streamId, subject: subject }, auth);
  check("Remove Subject answers 204", function () {
    assert.strictEqual(removed.status, 204, removed.raw.slice(0, 400));
  });

  log.info("Test completed successfully. " + checks + " check(s) passed.");
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error("sts_application_signals FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
