// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_ssf_conformance.js
//
// ---------------------------------------------------------------------------
// THE SHARED SIGNALS FRAMEWORK 1.0 FINAL TEXT, OVER THE WIRE (#144,
// 2026-09-22).
//
// What a read of SSF 1.0 final and RFC 9493 against the code found, held from
// the outside, where a receiver meets it — and where `product` mode and the
// AWS targets can run it:
//
//   1. OWNERSHIP (section 8). Two receivers in one realm. Every endpoint that
//      takes a stream_id answers 404 for the other one's stream, exactly as
//      for a stream that does not exist; a list is the caller's own; this
//      service's own receiver stream cannot be read; nothing leaves the
//      other's stream changed.
//   2. `aud` IS TRANSMITTER-SUPPLIED (section 8.1.1): the receiver's
//      client_id when it names none, an ssfReceiverId of its application when
//      it names that, refused when it names somebody else, and not changeable
//      by a PATCH.
//   3. THE SUBJECT GRAMMAR: iss_sub accepted and the drafts' issuer_subject_id
//      refused; a complex subject needs "format": "complex" and may carry
//      `application`; section 3.5's ip-addresses format.
//   4. DISCOVERY (section 7.2): the inserted-path form for a realm issuer,
//      the issuer it names, and spec_version "1_0".
//   5. VERIFICATION: 204, and a SET that is explicitly typed and carries a
//      txn.
//   6. STATUS (section 8.1.5): a paused poll stream hands out its
//      stream-updated event and holds a RISC event until it is enabled.
//   7. WHAT A RECEIVER CHECKS: in every mode, a real RFC 8935 PUSH to the
//      test peer's receiver (#586), which verifies what arrived the way any
//      receiver must and is read back by this job. With no peer (an AWS
//      target) it skips, saying so. (7a asserted the service's own
//      `/ssf/receive` refusing a wrong typ, iss and aud; #593 deleted that
//      endpoint, and the section with it.)
//
// OWNED HERE (local: true): this repository's transmitter, in a THROWAWAY
// TRUST REALM that is left behind.
// ---------------------------------------------------------------------------

const assert = require("assert");
const { Command, Option } = require("commander");
const nodeCrypto = require("crypto");
const { usernameFor } = require("./random_username.js");
const testPeer = require("./test_peer.js");
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
var log = bunyan.createLogger({ name: "sts_ssf_conformance",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug('CONFIG_FILE could not be read, so the configuration is empty: ' +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const REALM = usernameFor("ssfconf").replace(/[^a-z0-9-]/g, "").slice(0, 30);
const realmBase = base + "/realm/" + REALM;
const realmApi = realmBase + "/admin-api";
const RISC = "https://schemas.openid.net/secevent/risc/event-type/";
const ACCOUNT_DISABLED = RISC + "account-disabled";
const SSF = "https://schemas.openid.net/secevent/ssf/event-type/";
const VERIFICATION = SSF + "verification";
const UPDATED = SSF + "stream-updated";
const POLL = "urn:ietf:rfc:8936";
const PUSH = "urn:ietf:rfc:8935";
const SECRET = "ssf-conf-" + String(Date.now()).slice(-8);
const ALICE = "ssf-conf-a-" + REALM;
const BOB = "ssf-conf-b-" + REALM;
const ALICE_WEB = "https://" + REALM + ".example/web";

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

async function call(method, url, body, headers) {
  log.debug("Entering call().");
  const r = await fetch(url, { method: method,
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
  log.debug("Leaving call().");
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

function application(identifier, fields) {
  log.debug("Entering application().");
  log.debug("Leaving application().");
  return { identifier: identifier, kind: "oauth2-client", name: identifier,
           protocols: ["oauth2", "ssf"],
           // The Shared Signals scopes are issued only to a client that
           // declares them (#110).
           fields: Object.assign({ oauthClientId: [identifier],
                                   oauthAllowedScope: ["ssf.read",
                                                       "ssf.manage"],
                                   oauthClientSecret: SECRET,
                                   oauthTokenEndpointAuthMethod:
                                     "client_secret_post" }, fields || {}) };
}

async function tokenFor(identifier) {
  log.debug("Entering tokenFor().");
  await ssfRoles.mapApplication(ssfRoles.callPost(call), realmApi, identifier, "ssf.read ssf.manage");
  const r = await fetch(realmBase + "/oauth2/token", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "grant_type=client_credentials&client_id=" +
          encodeURIComponent(identifier) +
          "&client_secret=" + encodeURIComponent(SECRET) + "&scope=" +
          encodeURIComponent("ssf.read ssf.manage") });
  const json = await r.json();
  assert.ok(json.access_token,
            "a token for " + identifier + ": " + JSON.stringify(json));
  log.debug("Leaving tokenFor().");
  return json.access_token;
}

function decode(token) {
  log.debug("Entering decode().");
  const parts = String(token).split(".");
  log.debug("Leaving decode().");
  return { header: JSON.parse(Buffer.from(parts[0], "base64url")
                                .toString("utf8")),
           claims: JSON.parse(Buffer.from(parts[1], "base64url")
                                .toString("utf8")) };
}

function receiver(token) {
  log.debug("Entering receiver().");
  const auth = { Authorization: "Bearer " + token };
  const send = function (method, path, body) {
    log.debug("Entering send().");
    log.debug("Leaving send().");
    return call(method, realmBase + path, body, auth);
  };
  log.debug("Leaving receiver().");
  return {
    send: send,
    // Every SET waiting, decoded, and acknowledged so the next read is fresh.
    async drain(id) {
      log.debug("Entering drain().");
      const r = await send("POST", "/ssf/poll",
                           { stream_id: id, returnImmediately: true,
                             maxEvents: 100 });
      assert.strictEqual(r.status, 200, "poll: " + r.text.slice(0, 300));
      const sets = r.json.sets || {};
      const jtis = Object.keys(sets);
      if (jtis.length) {
        await send("POST", "/ssf/poll", { stream_id: id, ack: jtis,
                                          returnImmediately: true,
                                          maxEvents: 0 });
      }
      log.debug("Leaving drain().");
      return jtis.map(function (jti) {
        return decode(sets[jti]);
      });
    }
  };
}

// DRAINED UNTIL WHAT IS AWAITED HAS ARRIVED, or five seconds have passed.
// Delivery is asynchronous by specification — SSF 1.0 section 8.1.4.2 says a
// receiver "MUST NOT depend on the Verification Event being transmitted
// synchronously", and a stream-updated event is queued the same way — so one
// drain straight after the request asks too early wherever the poll can be
// answered by another node (`cluster` mode found it: the verify answered on
// one node, the drain on the other, and it was empty). Everything drained is
// kept, so a check on the whole list sees every SET that arrived.
async function drainUntil(receiver, id, arrived) {
  log.debug("Entering drainUntil().");
  const deadline = Date.now() + 5000;
  let got = [];
  for (;;) {
    got = got.concat(await receiver.drain(id));
    if (arrived(got) || Date.now() >= deadline) {
      log.debug("Leaving drainUntil().");
      return got;
    }
    await new Promise(function (resolve) {
      setTimeout(resolve, 150);
    });
  }
}

function hasType(list, type) {
  log.debug("Entering hasType().");
  log.debug("Leaving hasType().");
  return list.some(function (one) {
    return typeOf(one) === type;
  });
}

function typeOf(set) {
  log.debug("Entering typeOf().");
  log.debug("Leaving typeOf().");
  return Object.keys(set.claims.events || {})[0];
}

// ---------------------------------------------------------------------------
// 7b. A PUSH TO A RECEIVER THAT IS NOT THIS SERVICE (#586): the test peer's
// SSF receiver (tests/peer/peer_ssf.js), in every mode. A third receiver
// application asks for an RFC 8935 push stream to the peer's TLS listener
// with an authorization_header of its own; the realm trusts the peer's CA
// through `ssf.pushCaFile` — product mode verifies every push's certificate
// (#171) — and a verification request makes the transmitter push. What the
// peer received is read back from it: explicitly typed, signed by a key at
// the realm's jwks_uri (the peer fetched it and checked), from the realm's
// issuer, addressed to the stream's aud, with the state and a txn — and the
// header the receiver asked for, which the peer refuses a push without.
// Answers how many checks ran; none, saying so, in a run with no peer.
// ---------------------------------------------------------------------------
async function pushToTheTestPeer(issuer) {
  log.debug("Entering pushToTheTestPeer().");
  log.info("=== 7b. a push to the test peer's receiver ===");
  if (!testPeer.available()) {
    log.info(testPeer.skipReason("7b, the push to a receiver that is not " +
                                 "this service"));
    log.debug("Leaving pushToTheTestPeer(). No peer.");
    return 0;
  }
  const CAROL = "ssf-conf-c-" + REALM;
  const header = "Bearer push-" + nodeCrypto.randomBytes(12).toString("hex");
  await ok(realmApi + "/applications/create", application(CAROL),
           "created carol's application");
  const carol = receiver(await tokenFor(CAROL));
  const view = await testPeer.tenant(testPeer.tenantId("ssf-" + REALM),
                                     realmBase, base,
                                     { ssf: { authorizationHeader: header,
                                              audience: CAROL } });
  const caFile = process.env.TEST_PEER_CA_FILE || view.caFile;
  await ok(realmApi + "/config/set", { key: "ssf.pushCaFile",
                                       value: caFile },
           "named the test peer's CA in ssf.pushCaFile");
  let r = await carol.send("POST", "/ssf/stream", {
    delivery: { method: PUSH, endpoint_url: view.ssf.pushUrl,
                authorization_header: header },
    events_requested: [VERIFICATION, ACCOUNT_DISABLED] });
  const stream = r.json && r.json.stream_id;
  check("7b. a push stream to the test peer's https endpoint is created, " +
        "addressed to the receiver", function () {
    assert.ok(r.status === 200 || r.status === 201, r.text.slice(0, 300));
    assert.strictEqual(r.json.delivery.method, PUSH, r.text.slice(0, 300));
    assert.strictEqual(r.json.aud, CAROL, r.text.slice(0, 300));
  });
  const since = await testPeer.mark(view.tenant);
  r = await carol.send("POST", "/ssf/verify", { stream_id: stream,
                                                state: "push-state" });
  check("7b. a verification request answers 204", function () {
    assert.strictEqual(r.status, 204, r.text);
  });
  const seen = {};
  const arrived = await testPeer.waitFor(view.tenant, "ssf", since,
    function (one) {
      return (one.eventTypes || []).indexOf(VERIFICATION) >= 0;
    }, 15000, seen);
  check("7b. THE TRANSMITTER PUSHED IT to the peer over TLS it verified " +
        "against ssf.pushCaFile, with the receiver's authorization_header, " +
        "and the peer accepted it (202)", function () {
    assert.ok(arrived, "nothing reached the peer; it saw " +
              JSON.stringify(seen.seen || []).slice(0, 600));
    assert.strictEqual(arrived.ok, true, JSON.stringify(arrived));
    assert.strictEqual(arrived.status, 202, JSON.stringify(arrived));
  });
  check("7b. what arrived is explicitly typed secevent+jwt, signed by a key " +
        "at the realm's jwks_uri, from the realm's issuer, to the stream's " +
        "aud, echoing the state and carrying a txn", function () {
    assert.strictEqual(arrived.header.typ, "secevent+jwt");
    assert.strictEqual(arrived.signatureValid, true);
    assert.strictEqual(arrived.claims.iss, issuer);
    assert.deepStrictEqual([].concat(arrived.claims.aud), [CAROL]);
    assert.strictEqual(arrived.claims.events[VERIFICATION].state,
                       "push-state");
    assert.ok(arrived.claims.txn, JSON.stringify(arrived.claims));
  });
  r = await carol.send("DELETE", "/ssf/stream?stream_id=" +
                                 encodeURIComponent(stream));
  check("7b. carol deletes her push stream", function () {
    assert.strictEqual(r.status, 204, r.text);
  });
  // RESTORED WITH `reset` (tests/CLAUDE.md), though the realm is this
  // job's own: a setting left overridden is another job's starting state.
  await ok(realmApi + "/config/reset", { key: "ssf.pushCaFile" },
           "reset ssf.pushCaFile");
  log.debug("Leaving pushToTheTestPeer().");
  return 5;
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving SSF 1.0 conformance at " + realmBase);

  log.info("=== 0. the realm and two receivers ===");
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "SSF conformance" },
    "created the realm");
  await ok(realmApi + "/applications/create",
           application(ALICE, { ssfReceiverId: [ALICE_WEB] }),
           "created alice's application");
  await ok(realmApi + "/applications/create", application(BOB),
           "created bob's application");
  const alice = receiver(await tokenFor(ALICE));
  const bob = receiver(await tokenFor(BOB));

  log.info("=== 4. discovery ===");
  let r = await call("GET", base + "/.well-known/ssf-configuration/realm/" +
                            REALM);
  check("THE INSERTED-PATH FORM (section 7.2) answers for a realm's issuer, " +
        "and the document names exactly that issuer", function () {
          assert.strictEqual(r.status, 200, r.text.slice(0, 300));
          assert.ok(/\/realm\/[^/]+$/.test(r.json.issuer) &&
                    r.json.issuer.slice(-REALM.length) === REALM, r.text);
        });
  const issuer = r.json.issuer;
  check("an OPTIONAL array with nothing in it is left out rather than sent " +
        "empty — critical_subject_members with ssf.criticalSubjectMembers " +
        "unset (#187, the OpenID conformance suite)", function () {
          assert.ok(!Object.prototype.hasOwnProperty.call(
            r.json, "critical_subject_members"), r.text.slice(0, 400));
        });
  check("spec_version is \"1_0\", section 7.1's value for the final " +
        "specification", function () {
          assert.strictEqual(r.json.spec_version, "1_0");
        });
  r = await call("GET", realmBase + "/.well-known/ssf-configuration");
  check("and the realm's own copy agrees on the issuer", function () {
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.json.issuer, issuer);
  });
  r = await call("GET", base + "/.well-known/ssf-configuration/realm/" +
                        "no-such-" + REALM);
  check("a path no transmitter's issuer has is a 404", function () {
    assert.strictEqual(r.status, 404, r.text.slice(0, 200));
  });

  log.info("=== 2. aud is Transmitter-Supplied ===");
  r = await alice.send("POST", "/ssf/stream", { delivery: { method: POLL },
    events_requested: [ACCOUNT_DISABLED, VERIFICATION, UPDATED] });
  check("a stream created with no aud is addressed to the receiver's own " +
        "client_id", function () {
          assert.strictEqual(r.status, 201, r.text);
          assert.strictEqual(r.json.aud, ALICE);
          assert.strictEqual(r.json.iss, issuer);
        });
  const aliceStream = r.json.stream_id;
  const pollAt = String((r.json.delivery || {}).endpoint_url || "");
  check("a poll stream's delivery.endpoint_url names the stream (RFC 8936's " +
        "poll endpoint is per stream; #187)", function () {
          assert.ok(new URL(pollAt).searchParams.get("stream_id") ===
                    aliceStream, pollAt);
        });
  r = await call("POST", pollAt, { returnImmediately: true, maxEvents: 0 },
                 { Authorization: "Bearer " + (await tokenFor(ALICE)) });
  check("and a poll of exactly that URL, with no stream_id in the body, is " +
        "answered", function () {
          assert.strictEqual(r.status, 200, r.text.slice(0, 300));
        });
  r = await alice.send("POST", "/ssf/stream", { delivery: { method: POLL },
                                                aud: [ALICE_WEB] });
  check("one naming an ssfReceiverId of the receiver's application is " +
        "accepted as named", function () {
          assert.strictEqual(r.status, 201, r.text);
          assert.deepStrictEqual(r.json.aud, [ALICE_WEB]);
        });
  const aliceSecond = r.json.stream_id;
  r = await alice.send("POST", "/ssf/stream", { delivery: { method: POLL },
                                                aud: BOB });
  check("ONE NAMING ANOTHER RECEIVER IS REFUSED — it was taken as sent " +
        "until #144", function () {
          assert.strictEqual(r.status, 400, r.text);
          assert.ok(/not associated/.test(r.text), r.text);
        });
  r = await alice.send("PATCH", "/ssf/stream", { stream_id: aliceStream,
                                                 aud: ALICE_WEB });
  check("a PATCH changing aud is refused (section 8.1.1.3)", function () {
    assert.strictEqual(r.status, 400, r.text);
  });

  log.info("=== 1. ownership ===");
  r = await bob.send("POST", "/ssf/stream", { delivery: { method: POLL } });
  assert.strictEqual(r.status, 201, r.text);
  const bobStream = r.json.stream_id;
  const q = "?stream_id=" + encodeURIComponent(aliceStream);
  const attempts = [
    ["GET", "/ssf/stream" + q, undefined],
    ["PATCH", "/ssf/stream", { stream_id: aliceStream, description: "x" }],
    ["PUT", "/ssf/stream", { stream_id: aliceStream,
                             delivery: { method: POLL } }],
    ["GET", "/ssf/status" + q, undefined],
    ["POST", "/ssf/status", { stream_id: aliceStream, status: "disabled" }],
    ["POST", "/ssf/subjects/add", { stream_id: aliceStream,
      subject: { format: "opaque", id: "x" } }],
    ["POST", "/ssf/subjects/remove", { stream_id: aliceStream,
      subject: { format: "opaque", id: "x" } }],
    ["POST", "/ssf/verify", { stream_id: aliceStream }],
    ["POST", "/ssf/poll", { stream_id: aliceStream }],
    ["DELETE", "/ssf/stream" + q, undefined]
  ];
  const answers = [];
  for (const one of attempts) {
    const got = await bob.send(one[0], one[1], one[2]);
    answers.push(one[0] + " " + one[1].split("?")[0] + " " + got.status);
  }
  const missing = await bob.send("GET", "/ssf/stream?stream_id=ssf-nope" +
                                        REALM);
  check("EVERY ENDPOINT ANSWERS 404 FOR ANOTHER RECEIVER'S STREAM (section " +
        "8: \"for this Event Receiver\") — all ten, each of which read, " +
        "changed or deleted it until #144", function () {
          assert.ok(answers.every(function (line) {
            return / 404$/.test(line);
          }), JSON.stringify(answers));
        });
  const theirs = await bob.send("GET", "/ssf/stream" + q);
  check("and the 404 says exactly what a stream that does not exist says, " +
        "so a caller learns nothing about which ids exist", function () {
          assert.strictEqual(theirs.json.description.replace(aliceStream, "X"),
                             missing.json.description.replace(
                               "ssf-nope" + REALM, "X"));
        });
  r = await alice.send("GET", "/ssf/stream" + q);
  check("the stream is untouched: alice still reads it, enabled, as it was",
        function () {
          assert.strictEqual(r.status, 200, r.text);
          assert.strictEqual(r.json.aud, ALICE);
        });
  r = await alice.send("GET", "/ssf/status" + q);
  check("and its status was not changed by bob's attempt", function () {
    assert.strictEqual(r.json.status, "enabled");
  });
  r = await bob.send("GET", "/ssf/stream");
  check("A LIST IS THE CALLER'S OWN STREAMS — every stream in the realm, " +
        "this service's own included, until #144", function () {
          assert.strictEqual(r.status, 200, r.text);
          assert.deepStrictEqual(r.json.map(function (one) {
            return one.stream_id;
          }), [bobStream]);
        });
  r = await alice.send("GET", "/ssf/stream");
  check("alice's list is her two", function () {
    assert.deepStrictEqual(r.json.map(function (one) {
      return one.stream_id;
    }).sort(), [aliceStream, aliceSecond].sort());
    assert.ok(r.text.indexOf("authorization_header") < 0, r.text);
  });
  r = await alice.send("GET", "/ssf/stream?stream_id=ssf-internal-" + REALM +
                              "-admin-console");
  check("THIS SERVICE'S OWN RECEIVER STREAM CANNOT BE READ over " +
        "/ssf/stream — its authorization_header was readable by any ssf.read " +
        "token", function () {
          assert.strictEqual(r.status, 404, r.text.slice(0, 200));
        });

  log.info("=== 3. the subject grammar ===");
  const add = function (subject) {
    log.debug("Entering add().");
    log.debug("Leaving add().");
    return alice.send("POST", "/ssf/subjects/add",
                      { stream_id: aliceSecond, subject: subject });
  };
  // An empty 200 (SSF 1.0 section 8.1.3.2; it was 204 until #187).
  r = await add({ format: "iss_sub", iss: issuer, sub: "someone" });
  check("an iss_sub subject is added (RFC 9493's registered name)",
        function () {
          assert.strictEqual(r.status, 200, r.text);
        });
  r = await add({ format: "issuer_subject_id", iss: issuer, sub: "someone" });
  check("the drafts' issuer_subject_id is refused", function () {
    assert.strictEqual(r.status, 400, r.text);
  });
  r = await add({ user: { format: "iss_sub", iss: issuer, sub: "someone" },
                  session: { format: "opaque", id: "s" } });
  check("a complex subject without \"format\": \"complex\" is refused",
        function () {
          assert.strictEqual(r.status, 400, r.text);
        });
  r = await add({ format: "complex",
    user: { format: "iss_sub", iss: issuer, sub: "someone" },
    application: { format: "opaque", id: "app" } });
  check("one with it, carrying the seventh member (application), is added",
        function () {
          assert.strictEqual(r.status, 200, r.text);
        });
  r = await add({ format: "ip-addresses", "ip-addresses": ["192.0.2.1"] });
  check("section 3.5's ip-addresses format is added", function () {
    assert.strictEqual(r.status, 200, r.text);
  });

  log.info("=== 5. verification ===");
  await alice.drain(aliceStream);
  r = await alice.send("POST", "/ssf/verify", { stream_id: aliceStream,
                                                state: "conf-state" });
  check("a verification request answers 204 (section 8.1.4.2)", function () {
    assert.strictEqual(r.status, 204, r.text);
  });
  let got = await drainUntil(alice, aliceStream, function (list) {
    return hasType(list, VERIFICATION);
  });
  const verification = got.filter(function (one) {
    return typeOf(one) === VERIFICATION;
  })[0];
  check("the verification event is explicitly typed, echoes the state, and " +
        "carries a txn", function () {
          assert.ok(verification, JSON.stringify(got));
          assert.strictEqual(verification.header.typ, "secevent+jwt");
          assert.strictEqual(verification.claims.events[VERIFICATION].state,
                             "conf-state");
          assert.ok(verification.claims.txn, JSON.stringify(
            verification.claims));
          assert.strictEqual(verification.claims.aud, ALICE);
        });

  log.info("=== 6. status, in section 8.1.5's order ===");
  r = await alice.send("POST", "/ssf/status", { stream_id: aliceStream,
                                                status: "paused",
                                                reason: "conformance" });
  check("the stream is paused", function () {
    assert.strictEqual(r.status, 200, r.text);
    assert.strictEqual(r.json.status, "paused");
  });
  await ok(realmApi + "/risc/emit", { type: "account-disabled",
    account_id: usernameFor("ssf-conf-person"),
    reason_admin: "sts_ssf_conformance" }, "emitted account-disabled");
  got = await drainUntil(alice, aliceStream, function (list) {
    return hasType(list, UPDATED);
  });
  check("A PAUSED POLL STREAM HANDS OUT ITS stream-updated EVENT (status " +
        "paused) AND NOTHING ELSE — the account-disabled waits", function () {
          assert.deepStrictEqual(got.map(typeOf), [UPDATED],
                                 JSON.stringify(got.map(typeOf)));
          assert.strictEqual(got[0].claims.events[UPDATED].status, "paused");
          assert.deepStrictEqual(got[0].claims.sub_id,
                                 { format: "opaque", id: aliceStream });
        });
  r = await alice.send("POST", "/ssf/status", { stream_id: aliceStream,
                                                status: "enabled" });
  got = await drainUntil(alice, aliceStream, function (list) {
    return hasType(list, UPDATED) && hasType(list, ACCOUNT_DISABLED);
  });
  check("enabling it hands out stream-updated (status enabled) and then the " +
        "account-disabled held while it was paused", function () {
          assert.strictEqual(r.status, 200, r.text);
          const types = got.map(typeOf);
          assert.ok(types.indexOf(UPDATED) >= 0 &&
                    types.indexOf(ACCOUNT_DISABLED) >= 0,
                    JSON.stringify(types));
        });

  // =========================================================================
  // 7. WHAT A RECEIVER CHECKS — at the TEST PEER's, in every mode (#586).
  // The service's own `/ssf/receive` (7a) was deleted by #593.
  // =========================================================================
  const pushChecks = await pushToTheTestPeer(issuer);

  r = await alice.send("DELETE", "/ssf/stream" + q);
  check("alice deletes her own stream", function () {
    assert.strictEqual(r.status, 204, r.text);
  });

  // The floor: the 29 checks every run makes, and whatever section 7 said it
  // made — 7b only with a peer.
  const floor = 29 + pushChecks;
  assert.ok(checks >= floor, "only " + checks + " of " + floor + " checks " +
                             "ran; a section has stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_ssf_conformance")
  .description("SSF 1.0 final over the wire (#144): stream ownership, a " +
    "Transmitter-Supplied aud, the RFC 9493 names and the final complex " +
    "subject, the inserted-path discovery form, verification, status in " +
    "section 8.1.5's order, and a push to the test peer's receiver " +
    "(#586).")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
