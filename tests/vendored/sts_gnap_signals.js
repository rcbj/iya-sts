"use strict";
//
// File: sts_gnap_signals.js
//
// ---------------------------------------------------------------------------
// GNAP AND SHARED SIGNALS AGAINST A RUNNING SERVICE: A GNAP WEB APPLICATION
// OWNS A STREAM WITH ITS OWN ACCESS TOKEN, HEARS A CAEP EVENT WHEN A GRANT OR A
// TOKEN IS REVOKED OR A GRANT MODIFIED — AND HEARS NOTHING ABOUT PEOPLE WHO
// NEVER APPROVED IT.
//
// Three things were asked for on 2026-09-12 and this job holds each:
//
//   1. a GNAP web application is a Shared Signals RECEIVER in its own right: it
//      creates and polls a stream with a GNAP access token (the `gnap` scheme
//      in `ssf/ssf_auth.ts`), so the stream's owner is the APPLICATION;
//   2. that stream is SCOPED: an event about a person who never approved a
//      grant to that application does not reach it, while an unscoped stream
//      beside it does receive the same event — the control that proves the
//      silence is the scope and not a broken pipe;
//   3. revoking a grant or a token emits CAEP session-revoked, whose session is
//      the grant or the token, and modifying a grant emits token-claims-change.
//
// Every SET read here is verified against the realm's /oauth2/jwks with node's
// crypto before its contents are believed.
//
// Everything runs in a THROWAWAY TRUST REALM that is left behind.
//
// OWNED HERE (local: true): GNAP exists in this repository and nowhere else.
// ---------------------------------------------------------------------------

const assert = require("assert");
const nodeCrypto = require("crypto");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");
const gnap = require("./gnap_client.js");
const flowLib = require("./gnap_flow.js");

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
var log = bunyan.createLogger({ name: "sts_gnap_signals",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug('CONFIG_FILE could not be read, so the configuration is empty: ' +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const h = flowLib.harness({
  base: base,
  realm: usernameFor("gnapsig").replace(/[^a-z0-9-]/g, "").slice(0, 30),
  password: "gnap-signals-Passw0rd!-" + String(Date.now()).slice(-6),
  log: log
});
const check = h.check;
const OWNER = usernameFor("gnap-sig-owner");
const STRANGER = usernameFor("gnap-sig-stranger");
const CAEP = "https://schemas.openid.net/secevent/caep/event-type/";
const REVOKED = CAEP + "session-revoked";
const CLAIMS = CAEP + "token-claims-change";
const POLL = "urn:ietf:rfc:8936";
const BASIC = "Basic " +
              Buffer.from("gnap-signals-probe:any-password").toString("base64");

let jwks = null;

function verifySet(compact) {
  log.debug("Entering verifySet().");
  const parts = String(compact).split(".");
  const header = JSON.parse(Buffer.from(parts[0], "base64url")
                                  .toString("utf8"));
  const jwk =
      jwks.keys.filter(function (k) { return k.kid === header.kid; })[0];
  assert.ok(jwk, "the SET kid " + header.kid + " is in the realm JWKS");
  assert.strictEqual(header.alg, "RS256", "SETs are signed with " +
                                          "ssf.signingAlgorithm's default");
  assert.ok(nodeCrypto.verify("sha256", Buffer.from(parts[0] + "." + parts[1]),
                              nodeCrypto.createPublicKey(
                                  { key: jwk, format: "jwk" }),
                              Buffer.from(parts[2], "base64url")), "the SET " +
                                  "signature verifies");
  log.debug("Leaving verifySet().");
  return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
}

// Collect every SET on a poll stream, verified, and acknowledge them.
async function drain(send, streamId) {
  log.debug("Entering drain().");
  const r = await send({ stream_id: streamId, returnImmediately: true,
                         maxEvents: 100 });
  assert.strictEqual(r.status, 200,
                     "the poll answers: " + r.text.slice(0, 300));
  const sets = r.json.sets || {};
  const jtis = Object.keys(sets);
  if (jtis.length) {
    const acked = await send({ stream_id: streamId, returnImmediately: true,
                               ack: jtis, maxEvents: 0 });
    assert.strictEqual(acked.status, 200,
                       "the acknowledgement is accepted: " +
                       acked.text.slice(0, 300));
    const after = await send({ stream_id: streamId, returnImmediately: true,
                               maxEvents: 100 });
    const left = Object.keys((after.json && after.json.sets) || {})
                       .filter(function (jti) {
      return jtis.indexOf(jti) >= 0;
    });
    assert.deepStrictEqual(left, [], "an acknowledged SET is not delivered " +
                                     "again (RFC 8936 section 2.4)");
  }
  log.debug("drained " + streamId + ": " + jtis.join(", "));
  log.debug("Leaving drain().");
  return jtis.map(function (jti) { return verifySet(sets[jti]); });
}

// ---------------------------------------------------------------------------
// DRAIN UNTIL WHAT WAS CAUSED HAS ARRIVED, OR A BOUND HAS PASSED (2026-09-12).
//
// DELIVERY IS NOT AWAITED BY THE REQUEST THAT CAUSES IT, which section 6 has
// always said and sections 2 to 5 did not act on. In one process that costs
// nothing — the SET is queued before the next request is read. In the
// `dispatch` mode the revoking request and the poll are two requests with no
// cookie, answered by whichever worker the pool picks, and the queued SET
// reaches the other worker through replication half a second to a second
// later. So a single `returnImmediately` poll straight after the 204 found an
// empty queue, in that mode only, about a service that delivered correctly.
//
// `wanted` decides when to stop; each round's SETs are acknowledged by drain()
// and kept here. A `wanted` that is never true is a SETTLE WINDOW, which is how
// a NEGATIVE is asserted: "nothing arrived" means nothing arrived in the time a
// positive on the control stream was allowed.
// ---------------------------------------------------------------------------
const DELIVERY_WAIT_MS = Number(process.env.GNAP_SIGNALS_WAIT_MS || 15000);
const SETTLE_MS = Number(process.env.GNAP_SIGNALS_SETTLE_MS || 2000);

async function drainUntil(send, streamId, wanted, boundMs) {
  log.debug("Entering drainUntil().");
  const deadline = Date.now() +
                   (boundMs === undefined ? DELIVERY_WAIT_MS : boundMs);
  let all = [];
  for (;;) {
    all = all.concat(await drain(send, streamId));
    if ((wanted && wanted(all)) || Date.now() >= deadline) {
      log.debug("Leaving drainUntil().");
      return all;
    }
    await new Promise(function (resolve) { setTimeout(resolve, 250); });
  }
}

function hears(uri, who, prefix) {
  log.debug("Entering hears().");
  log.debug("Leaving hears().");
  return function (sets) { return about(sets, uri, who, prefix).length > 0; };
}

// A person's `urn:uuid:<entryUUID>`, by name, filled once they are created.
const SUBJECTS = {};

function about(sets, uri, who, prefix) {
  log.debug("Entering about().");
  log.debug("Leaving about().");
  return sets.filter(function (set) {
    const event = set.events && set.events[uri];
    const subject = set.sub_id || (event && event.subject) || {};
    const user = subject.user || {};
    const session = subject.session || {};
    return event && !!SUBJECTS[who] && String(user.sub) === SUBJECTS[who] &&
           String(session.id || "").indexOf(prefix) === 0;
  });
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving GNAP + Shared Signals at " + h.realmBase);

  // =========================================================================
  // 0. THE REALM, TWO PEOPLE, TWO GNAP WEB APPLICATIONS.
  // =========================================================================
  log.info("=== 0. the realm and two web applications ===");
  await h.createRealm("GNAP signals");
  await h.setting("gnap.continueWaitS", 0);
  await h.ensurePerson(OWNER);
  await h.ensurePerson(STRANGER);
  // Their subjects, which a SET's `user.sub` carries (2026-09-14).
  SUBJECTS[OWNER] = await h.subjectOf(OWNER);
  SUBJECTS[STRANGER] = await h.subjectOf(STRANGER);
  jwks = await (await fetch(h.realmBase + "/oauth2/jwks")).json();
  const web = new gnap.Client({ key: gnap.newKey("ES256") });
  const other = new gnap.Client({ key: gnap.newKey("ES256") });
  const WEB_ID = "gnap-web-" + h.realm;
  const OTHER_ID = "gnap-other-" + h.realm;
  await h.ok(h.realmApi + "/applications/create", {
    identifier: WEB_ID, kind: "gnap-client", protocols: ["gnap"],
    fields: { gnapKey: JSON.stringify(web.keyObject()),
              gnapFinishUri: h.FINISH } },
    "registered the web application that will own a stream");
  await h.ok(h.realmApi + "/applications/create", {
    identifier: OTHER_ID, kind: "gnap-client", protocols: ["gnap"],
    fields: { gnapKey: JSON.stringify(other.keyObject()),
              gnapFinishUri: h.FINISH } },
    "registered a second web application");

  // =========================================================================
  // 1. A GNAP ACCESS TOKEN OWNS A STREAM (ssf/ssf_auth.ts, the gnap scheme).
  // =========================================================================
  log.info("=== 1. a stream owned with a GNAP token ===");
  const ssfGrant = await h.redirectGrant(web, OWNER,
    { access_token: { access: ["ssf:read", "ssf:write"] } });
  const ssfToken = ssfGrant.released.access_token.value;
  const streamBody = { delivery: { method: POLL },
                       events_requested: [REVOKED, CLAIMS],
                       aud: "https://web.gnap.test/signals" };
  let r = await web.send("POST", h.realmBase + "/ssf/stream",
                         { token: ssfToken, json: streamBody });
  check("POST /ssf/stream with the GNAP scheme and an HTTP signature creates " +
        "a stream", function () {
    assert.strictEqual(r.status, 201, r.text);
    assert.ok(r.json.stream_id);
    assert.deepStrictEqual(r.json.events_delivered.slice().sort(),
                           [REVOKED, CLAIMS].sort());
  });
  const webStream = r.json.stream_id;
  const readOnly = await h.redirectGrant(web, OWNER,
                                         { access_token: {
                                           access: ["ssf:read"] } });
  r = await web.send("POST", h.realmBase + "/ssf/stream",
                     { token: readOnly.released.access_token.value,
                                                             json:
                                                               streamBody });
  check("a GNAP token carrying only ssf:read cannot create a stream (403 " +
        "access_denied)", function () {
    assert.strictEqual(r.status, 403, r.text);
    assert.ok(/ssf:write/.test(r.text), r.text);
  });
  r = await web.send("POST", h.realmBase + "/ssf/stream",
                     { token: ssfToken, json: streamBody, sign: false });
  check("the GNAP token without its key proof is refused (401)", function () {
    assert.strictEqual(r.status, 401, r.text);
  });
  r = await other.send("POST", h.realmBase + "/ssf/stream",
                       { token: ssfToken, json: streamBody });
  check("the GNAP token proved by ANOTHER application's key is refused (401)",
        function () {
    assert.strictEqual(r.status, 401, r.text);
  });
  r = await gnap.rawRequest("GET", h.realmBase + "/ssf/stream", {});
  check("a 401 from the SSF endpoints offers the GNAP scheme with as_uri",
        function () {
    assert.strictEqual(r.status, 401, r.text);
    const challenge = [].concat(r.headers["www-authenticate"] || []).join(", ");
    assert.ok(challenge.indexOf("GNAP as_uri=\"" + h.GRANT + "\"") >= 0,
              challenge);
  });
  r = await gnap.rawRequest("GET",
                            h.realmBase + "/.well-known/ssf-configuration", {});
  check("the transmitter metadata lists urn:ietf:rfc:9635 among its " +
        "authorization schemes", function () {
    assert.ok(r.json.authorization_schemes.some(function (
        one) { return one.spec_urn === "urn:ietf:rfc:9635"; }),
              JSON.stringify(r.json.authorization_schemes));
  });
  const pollWeb = function (body) {
    log.debug("Entering pollWeb().");
    log.debug("Leaving pollWeb().");
    return web.send("POST", h.realmBase + "/ssf/poll",
                    { token: ssfToken, json: body });
  };
  // THE CONTROL: an unscoped stream owned by a Basic principal, which is not a
  // GNAP application and so is covered by no GNAP scope.
  r = await gnap.rawRequest("POST", h.realmBase + "/ssf/stream",
    { Authorization: BASIC, "Content-Type": "application/json" },
    Buffer.from(JSON.stringify(streamBody)));
  check("an unscoped control stream is created with Basic", function () {
    assert.strictEqual(r.status, 201, r.text);
  });
  const controlStream = r.json.stream_id;
  const pollControl = async function (body) {
    log.debug("Entering pollControl().");
    const buf = Buffer.from(JSON.stringify(body));
    log.debug("Leaving pollControl().");
    return gnap.rawRequest("POST", h.realmBase + "/ssf/poll",
      { Authorization: BASIC, "Content-Type": "application/json" }, buf);
  };
  await drain(pollWeb, webStream);
  await drain(pollControl, controlStream);

  // =========================================================================
  // 2. REVOKING A GRANT EMITS session-revoked FOR THE GRANT.
  // =========================================================================
  log.info("=== 2. grant revocation ===");
  const doomed = await h.redirectGrant(web, OWNER);
  r = await web.send("DELETE", doomed.released.continue.uri,
                     { token: doomed.released.continue.access_token.value });
  assert.strictEqual(r.status, 204, r.text);
  let webSets = await drainUntil(pollWeb, webStream,
                                 hears(REVOKED, OWNER, "gnap-grant:"));
  let controlSets = await drainUntil(pollControl, controlStream,
                                     hears(REVOKED, OWNER, "gnap-grant:"));
  check("the owning application's stream receives a signed session-revoked " +
        "whose session is the grant",
        function () {
          const hits = about(webSets, REVOKED, OWNER, "gnap-grant:");
          assert.strictEqual(hits.length, 1, JSON.stringify(webSets));
          const event = hits[0].events[REVOKED];
          assert.strictEqual(event.initiating_entity, "system");
          assert.ok(event.event_timestamp > 0);
        });
  check("…and so does the unscoped control stream", function () {
    assert.strictEqual(about(controlSets, REVOKED, OWNER, "gnap-grant:").length,
                       1, JSON.stringify(controlSets));
  });

  // =========================================================================
  // 3. THE SCOPE: A PERSON WHO NEVER APPROVED THIS APPLICATION.
  // =========================================================================
  log.info("=== 3. the stream is scoped to the application's own users ===");
  const strangers = await h.redirectGrant(other, STRANGER);
  r = await other.send("DELETE", strangers.released.continue.uri,
                       { token:
                           strangers.released.continue.access_token.value });
  assert.strictEqual(r.status, 204, r.text);
  // THE CONTROL FIRST, and until it hears: once the event about the stranger
  // has reached a poll, the web application's stream is given the settle
  // window to receive it too — so its silence below is silence and not an
  // event still in flight.
  controlSets = await drainUntil(pollControl, controlStream,
                                 hears(REVOKED, STRANGER, "gnap-grant:"));
  webSets = await drainUntil(pollWeb, webStream, null, SETTLE_MS);
  check("the control stream receives the event about the stranger — the pipe " +
        "works", function () {
    assert.strictEqual(about(controlSets, REVOKED, STRANGER,
                             "gnap-grant:").length, 1,
                       JSON.stringify(controlSets));
  });
  check("…and the web application's stream does NOT: the stranger never " +
        "approved a grant to it", function () {
    assert.strictEqual(about(webSets, REVOKED, STRANGER, "gnap-grant:").length,
                       0, JSON.stringify(webSets));
  });
  await h.ok(h.realmApi + "/applications/set",
             { application: WEB_ID, attribute: "gnapScopedSignals",
                                                 value: "FALSE" }, "unscoped " +
                                                     "the web application");
  const again = await h.redirectGrant(other, STRANGER);
  r = await other.send("DELETE", again.released.continue.uri,
                       { token: again.released.continue.access_token.value });
  webSets = await drainUntil(pollWeb, webStream,
                             hears(REVOKED, STRANGER, "gnap-grant:"));
  await drainUntil(pollControl, controlStream,
                   hears(REVOKED, STRANGER, "gnap-grant:"));
  check("with gnapScopedSignals FALSE on the application its stream hears " +
        "about the stranger too", function () {
    assert.strictEqual(about(webSets, REVOKED, STRANGER, "gnap-grant:").length,
                       1, JSON.stringify(webSets));
  });
  await h.ok(h.realmApi + "/applications/set",
             { application: WEB_ID, attribute: "gnapScopedSignals",
                                                 value: "TRUE" }, "put the " +
                                                     "scope back");

  // =========================================================================
  // 4. REVOKING A TOKEN, AND MODIFYING A GRANT.
  // =========================================================================
  log.info("=== 4. token revocation and grant modification ===");
  const managed = await h.redirectGrant(web, OWNER);
  const token = managed.released.access_token;
  const jti = JSON.parse(Buffer.from(token.value.split(".")[1], "base64url")
                               .toString("utf8")).jti;
  r = await web.send("DELETE", token.manage.uri,
                     { token: token.manage.access_token.value });
  assert.strictEqual(r.status, 204, r.text);
  webSets = await drainUntil(pollWeb, webStream,
                             hears(REVOKED, OWNER, "gnap-token:"));
  check("revoking a token at its manage URI emits session-revoked whose " +
        "session is that token", function () {
    const hits = about(webSets, REVOKED, OWNER, "gnap-token:");
    assert.strictEqual(hits.length, 1, JSON.stringify(webSets));
    assert.strictEqual(hits[0].sub_id.session.id, "gnap-token:" + jti);
  });
  const modifying = await h.redirectGrant(web, OWNER);
  const narrowed = [{ type: h.DEMO, actions: ["read"] }];
  r = await web.send("PATCH", modifying.released.continue.uri, {
    token: modifying.released.continue.access_token.value,
    json: { access_token: { access: narrowed } } });
  assert.strictEqual(r.status, 200, r.text);
  webSets = await drainUntil(pollWeb, webStream,
                             hears(CLAIMS, OWNER, "gnap-grant:"));
  check("modifying a grant emits token-claims-change carrying the new access",
        function () {
    const hits = about(webSets, CLAIMS, OWNER, "gnap-grant:");
    assert.strictEqual(hits.length, 1, JSON.stringify(webSets));
    assert.deepStrictEqual(hits[0].events[CLAIMS].claims.access, narrowed);
  });

  // =========================================================================
  // 5. THE ADMINISTRATOR'S REVOKE IS THE SAME EVENT.
  // =========================================================================
  log.info("=== 5. revoked by an administrator ===");
  const byAdmin = await h.redirectGrant(web, OWNER);
  const view = await h.apiGet(h.realmApi + "/gnap?state=approved&per=200");
  // The continuation URI's last segment is the grant id (RFC 9635 leaves its
  // shape to the AS; this one names the grant), so the row is found exactly.
  const byAdminId = byAdmin.released.continue.uri.split("/").pop();
  const row = (view.body.grants.rows || []).filter(function (one) {
    return one.id === byAdminId;
  })[0];
  check("the console's grant list shows the approved grant", function () {
    assert.ok(row, JSON.stringify(view.body.grants).slice(0, 600));
  });
  await h.ok(h.realmApi + "/gnap/revoke-grant", { grant: row.id }, "revoked " +
      "the grant from the console API");
  webSets = await drainUntil(pollWeb, webStream,
                             hears(REVOKED, OWNER, "gnap-grant:" + row.id));
  check("POST /admin-api/gnap/revoke-grant emits the same session-revoked",
        function () {
    const hits = about(webSets, REVOKED, OWNER, "gnap-grant:" + row.id);
    assert.strictEqual(hits.length, 1, JSON.stringify(webSets));
  });
  r = await web.send("GET", h.RS,
                     { token: byAdmin.released.access_token.value });
  check("…and the grant's token stops working", function () {
    assert.strictEqual(r.status, 401, r.text);
  });

  // =========================================================================
  // 6. gnap.caepEvents OFF.
  // =========================================================================
  log.info("=== 6. switched off ===");
  await h.setting("gnap.caepEvents", false);
  const quiet = await h.redirectGrant(web, OWNER);
  r = await web.send("DELETE", quiet.released.continue.uri,
                     { token: quiet.released.continue.access_token.value });
  assert.strictEqual(r.status, 204, r.text);
  await h.setting("gnap.caepEvents", true);
  // A SECOND revocation with the setting back on, drained together with the
  // first: delivery is not awaited by the revoking request, so "nothing
  // arrived" is only an assertion once something revoked AFTER it has.
  const loud = await h.redirectGrant(web, OWNER);
  r = await web.send("DELETE", loud.released.continue.uri,
                     { token: loud.released.continue.access_token.value });
  assert.strictEqual(r.status, 204, r.text);
  const quietId = "gnap-grant:" + quiet.released.continue.uri.split("/").pop();
  const loudId = "gnap-grant:" + loud.released.continue.uri.split("/").pop();
  webSets = await drainUntil(pollWeb, webStream, hears(REVOKED, OWNER, loudId));
  check("with gnap.caepEvents off a grant revocation emits nothing, while " +
        "one revoked after it with the setting back on does", function () {
          assert.strictEqual(about(webSets, REVOKED, OWNER, quietId).length, 0,
                             JSON.stringify(webSets));
          assert.strictEqual(about(webSets, REVOKED, OWNER, loudId).length, 1,
                             JSON.stringify(webSets));
        });

  assert.ok(h.checks >= 17, "only " + h.checks + " checks ran; a section has " +
                                                 "stopped being called.");
  log.info(h.checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_gnap_signals")
  .description("GNAP and Shared Signals: a GNAP web application owns an SSF " +
    "stream with its own access token, receives CAEP session-revoked for " +
    "revoked grants and tokens and token-claims-change for a modified grant, " +
    "and hears nothing about people who never approved it.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
