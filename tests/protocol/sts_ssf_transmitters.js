// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_ssf_transmitters.js
//
// ===========================================================================
// A FEDERATION PARTNER'S SHARED SIGNALS, OVER THE WIRE (#153, #373, #374;
// #444 D12, phase 7).
//
// `tests/ssf_transmitters.js` drives `ssf/ssf_transmitters.ts` in a child
// process with a fake partner, a fake session list and a fake sign-out. Here
// the partner is a stand-in SSF TRANSMITTER in THIS process — its discovery
// document at the inserted path, its keys, its token endpoint, a stream
// endpoint and a poll endpoint — dialled at OUTBOUND_TEST_HOST from a
// development realm with `federation.outboundAllowHttp` and
// `ssf.actOnSignalsInDevelopment` on; the same partner signs its people in
// by an ID Token by form_post (its signing key pasted), so the sessions a
// signal ends are real ones, read back through `/logout`'s JSON answer:
//
//   B. discovery at `/.well-known/ssf-configuration/<fedPeer's path>`; a
//      document naming another issuer refused; the client secret held and
//      never shown; a relationship whose signals are off refused;
//   C. the stream created with the relationship's own signals client; a
//      polled session-revoked naming one session the partner started ends
//      that one and not the other;
//   D. a polled account-disabled blocks the partner's sign-ins of the person
//      and ends the rest of its sessions, the account left enabled, and it
//      is acknowledged on the next poll;
//   E. the block refuses the person's federated sign-in (STS-FED-0156); the
//      partner's account-enabled lifts it;
//   F. a SET signed by another key, or naming another issuer or audience,
//      acts on nothing;
//   G. an email subject names nobody until the relationship allows it;
//   I. the push endpoint refuses an Authorization header it did not give.
//
// NOT HERE: A (`xacml_signal_pep.decide()`'s reaction table as a function;
// C–E are its outcomes for a sign-in partner), H (an `ssf` signals-only
// relationship; its device compliance is the device register's), J
// (deleting a relationship: no `/admin-api` door removes one), K (the grant
// revocation's reaction rows, `ssf.signalsRevokeGrants`) and L (the
// conformance suite's receiver plans, which `sts_ssf_receiver_conformance.js`
// drives).
//
// OWNED HERE (local: true). Its realms are removed only on a private probe.
// ===========================================================================

const assert = require("assert");
const http = require("http");
const nodeCrypto = require("crypto");
const K = require("./oauth_wire_kit.js").kit("sts_ssf_transmitters");

const log = K.log;
const RISC = "https://schemas.openid.net/secevent/risc/event-type/";
const CAEP = "https://schemas.openid.net/secevent/caep/event-type/";
const TX_KEY = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const TX_JWK = Object.assign(TX_KEY.publicKey.export({ format: "jwk" }),
                             { kid: "tx-1", alg: "ES256", use: "sig" });
const ID_KEY = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const ROGUE = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const CLIENT = "ssft-client-" + K.STAMP;
let SP = null;
let ROOT = "";
let ISS = "";
const tx = { docIssuer: "", requests: [], polls: [] };

// THE TRANSMITTER. A hot path: every request is in `tx.requests`.
function transmitter(req, res) {
  const url = new URL(req.url, "http://x");
  let body = "";
  req.on("data", function (c) {
    body += c;
  });
  req.on("end", function () {
    tx.requests.push({ path: url.pathname, method: req.method, body: body,
                       auth: String(req.headers.authorization || "") });
    const json = function (status, value) {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(value === null ? "" : JSON.stringify(value));
    };
    if (/^\/\.well-known\/ssf-configuration/.test(url.pathname)) {
      json(200, { issuer: tx.docIssuer, jwks_uri: ROOT + "/jwks",
        configuration_endpoint: ROOT + "/stream",
        status_endpoint: ROOT + "/status",
        verification_endpoint: ROOT + "/verify",
        delivery_methods_supported: ["urn:ietf:rfc:8935",
                                     "urn:ietf:rfc:8936"] });
      return;
    }
    if (url.pathname === "/jwks") {
      json(200, { keys: [TX_JWK] });
      return;
    }
    if (url.pathname === "/token") {
      json(200, { access_token: "tx-token", token_type: "Bearer",
                  expires_in: 300 });
      return;
    }
    if (url.pathname === "/stream" && req.method === "POST") {
      json(201, { stream_id: "s-1", aud: "realm-receiver",
        delivery: { method: "urn:ietf:rfc:8936",
                    endpoint_url: ROOT + "/poll" } });
      return;
    }
    if (url.pathname === "/poll") {
      json(200, tx.polls.shift() || { sets: {}, moreAvailable: false });
      return;
    }
    json(404, { error: "not here" });
  });
}

function signSet(claims, key) {
  log.debug("Entering signSet().");
  const input = Buffer.from(JSON.stringify({ alg: "ES256", kid: "tx-1",
    typ: "secevent+jwt" })).toString("base64url") + "." +
    Buffer.from(JSON.stringify(claims)).toString("base64url");
  const sig = nodeCrypto.sign("sha256", Buffer.from(input),
    { key: (key || TX_KEY).privateKey, dsaEncoding: "ieee-p1363" });
  log.debug("Leaving signSet().");
  return input + "." + sig.toString("base64url");
}

function setOf(event, subject, over, payload) {
  log.debug("Entering setOf(). " + event);
  const claims = Object.assign({ iss: ISS, aud: "realm-receiver",
    jti: nodeCrypto.randomBytes(8).toString("hex"),
    iat: Math.floor(Date.now() / 1000), sub_id: subject, events: {} },
  over || {});
  claims.events[(/^(session-revoked|device-)/.test(event) ? CAEP : RISC) +
                event] = payload || {};
  log.debug("Leaving setOf().");
  return claims;
}

function api(path, body) {
  log.debug("Entering api(). " + path);
  log.debug("Leaving api().");
  return K.send(K.rb(SP) + "/admin-api" + path,
                body === undefined ? {} : { json: body });
}

async function relationship(id, settings) {
  log.debug("Entering relationship(). " + id);
  await K.ok(K.rb(SP) + "/admin-api/federation/create", { id: id,
    role: "service-provider", protocol: "oidc", peer: ISS },
  "created " + id);
  for (const field of Object.keys(settings)) {
    await K.ok(K.rb(SP) + "/admin-api/federation/set", { id: id,
      field: field, value: settings[field] }, "set " + field);
  }
  await K.ok(K.rb(SP) + "/admin-api/federation/enable", { id: id },
             "enabled " + id);
  log.debug("Leaving relationship().");
}

async function signIn(sid) {
  log.debug("Entering signIn(). " + sid);
  const b = K.browser();
  const begun = await b.go(K.rb(SP) + "/federation/login/partner");
  const asked = new URL(begun.location);
  const now = Math.floor(Date.now() / 1000);
  const input = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT",
    kid: "id-1" })).toString("base64url") + "." +
    Buffer.from(JSON.stringify({ iss: ISS, aud: CLIENT, sub: "ext-alice",
      sid: sid, iat: now, exp: now + 300,
      nonce: asked.searchParams.get("nonce") })).toString("base64url");
  const token = input + "." + nodeCrypto.sign("sha256", Buffer.from(input),
    ID_KEY.privateKey).toString("base64url");
  let r = await b.go(K.rb(SP) + "/federation/acs/partner", { form: {
    id_token: token, state: asked.searchParams.get("state") } });
  for (let i = 0; i < 4 && r.status >= 300 && r.status < 400 && r.location;
       i += 1) {
    r = await b.go(new URL(r.location, K.base).toString());
  }
  log.debug("Leaving signIn(). " + r.status);
  return { b: b, r: r };
}

async function live(b) {
  log.debug("Entering live().");
  const r = await b.go(K.rb(SP) + "/logout",
                       { headers: { accept: "application/json" } });
  log.debug("Leaving live(). " + r.status);
  return r.status === 200;
}

async function pollNow(sets) {
  log.debug("Entering pollNow().");
  const map = {};
  sets.forEach(function (one) {
    map[one.jti] = one.jwt;
  });
  tx.polls.push({ sets: map, moreAvailable: false });
  const r = await api("/federation/signals-poll-now", { id: "partner" });
  log.debug("Leaving pollNow(). " + r.status);
  return r;
}

function signed(claims, key) {
  log.debug("Entering signed().");
  log.debug("Leaving signed().");
  return { jti: claims.jti, jwt: signSet(claims, key) };
}

async function person() {
  log.debug("Entering person().");
  const r = await api("/users?user=ssft-alice");
  log.debug("Leaving person().");
  return r.json || {};
}

// ------------------------------------------------------------------- B, C
async function discoveryAndStream() {
  log.debug("Entering discoveryAndStream().");
  log.info("=== B. discovery; C. a session-revoked ===");
  tx.docIssuer = "https://someone-else.test";
  const wrong = await api("/federation/signals-discover", { id: "partner" });
  tx.docIssuer = ISS;
  tx.requests = [];
  const found = await api("/federation/signals-discover", { id: "partner" });
  await relationship("quiet", { fedSsoUrl: ISS + "/authorize",
                                fedClientId: "q", fedResponseType: "id_token",
                                fedJwks: JSON.stringify({ keys: [] }) });
  const off = await api("/federation/signals-discover", { id: "quiet" });
  K.check("B1. discovery at the inserted path from fedPeer; a document " +
          "naming another issuer is refused; the secret is never shown; a " +
          "relationship whose signals are off is refused", function () {
    assert.strictEqual(wrong.status, 400, wrong.text.slice(0, 200));
    assert.strictEqual(found.status, 200, found.text.slice(0, 300));
    assert.strictEqual((tx.requests[0] || {}).path,
                       "/.well-known/ssf-configuration/realm/partner");
    assert.ok(found.text.indexOf("tx-secret-" + K.STAMP) < 0);
    assert.strictEqual(off.status, 400, off.text.slice(0, 200));
    assert.ok(/fedSignalsEnabled/.test(off.text), off.text.slice(0, 300));
  });
  tx.requests = [];
  const stream = await api("/federation/signals-create-stream",
                           { id: "partner" });
  const tokenCall = tx.requests.filter(function (r) {
    return r.path === "/token";
  })[0] || { body: "" };
  K.check("C0. the stream is created with the relationship's own signals " +
          "client", function () {
    assert.strictEqual(stream.status, 200, stream.text.slice(0, 300));
    assert.ok(new RegExp("client_secret=tx-secret-" + K.STAMP)
      .test(tokenCall.body) || /^Basic /.test(tokenCall.auth || ""),
              tokenCall.body.slice(0, 200));
  });
  const one = await signIn("sid-1");
  const two = await signIn("sid-2");
  assert.ok(await live(one.b) && await live(two.b), "no partner sessions: " +
            K.shown(one.r));
  const polled = await pollNow([signed(setOf("session-revoked",
    { format: "complex",
      user: { format: "iss_sub", iss: ISS, sub: "ext-alice" },
      session: { format: "opaque", id: "sid-1" } }, {},
    { initiating_entity: "user" }))]);
  const oneLive = await live(one.b);
  const twoLive = await live(two.b);
  K.check("C1. a polled session-revoked naming one session the partner " +
          "started ends that one and nothing else", function () {
    assert.strictEqual(polled.status, 200, polled.text.slice(0, 300));
    assert.ok(!oneLive, "sid-1's session is still live");
    assert.ok(twoLive, "sid-2's session ended");
  });
  log.debug("Leaving discoveryAndStream().");
  return two;
}

// ------------------------------------------------------------------- D, E
async function blockAndLift(two) {
  log.debug("Entering blockAndLift().");
  log.info("=== D. account-disabled; E. the block ===");
  const disabled = signed(setOf("account-disabled",
    { format: "iss_sub", iss: ISS, sub: "ext-alice" }));
  tx.requests = [];
  const polled = await pollNow([disabled]);
  const twoLive = await live(two.b);
  const p = await person();
  const polls = tx.requests.filter(function (r) {
    return r.path === "/poll";
  });
  const acked = polls.some(function (c) {
    return c.body.indexOf(disabled.jti) >= 0 && /"ack"/.test(c.body);
  });
  K.check("D1. a polled account-disabled ends the rest of the sessions the " +
          "partner started, leaves the account enabled, and is " +
          "acknowledged on the next poll", function () {
    assert.strictEqual(polled.status, 200, polled.text.slice(0, 300));
    assert.ok(!twoLive, "sid-2's session is still live");
    assert.ok(!/pwdAccountLockedTime|"stsAccountDisabled":\s*\[?"TRUE"/i
      .test(JSON.stringify(p.ldap || {})), JSON.stringify(p.ldap || {})
      .slice(0, 300));
    assert.ok(acked, JSON.stringify(polls.map(function (c) {
      return c.body;
    })));
  });
  const blocked = await K.coded(SP, "STS-FED-0156", function () {
    return signIn("sid-3");
  });
  K.check("E1. the block refuses the person's sign-in through that " +
          "relationship (STS-FED-0156)", function () {
    assert.ok(blocked.answer.r.status >= 400, K.shown(blocked.answer.r));
    assert.ok(blocked.rose >= 1);
  });
  await pollNow([signed(setOf("account-enabled",
    { format: "iss_sub", iss: ISS, sub: "ext-alice" }))]);
  const lifted = await signIn("sid-4");
  const liftedLive = await live(lifted.b);
  K.check("E2. the partner's account-enabled lifts it", function () {
    assert.strictEqual(lifted.r.status, 200, K.shown(lifted.r));
    assert.ok(liftedLive);
  });
  log.debug("Leaving blockAndLift().");
  return lifted;
}

// ------------------------------------------------------------------- F, G
async function refusals(lifted) {
  log.debug("Entering refusals().");
  log.info("=== F. what acts on nothing; G. an email subject ===");
  const subject = { format: "iss_sub", iss: ISS, sub: "ext-alice" };
  await pollNow([
    signed(setOf("account-disabled", subject), ROGUE),
    signed(setOf("account-disabled", subject, { iss: "https://evil.test" })),
    signed(setOf("account-disabled", subject, { aud: "somebody-else" }))]);
  const still = await live(lifted.b);
  const again = await signIn("sid-5");
  K.check("F1. a SET signed by another key, or naming another issuer or " +
          "audience, acts on nothing: the session lives and the next " +
          "sign-in is not blocked", function () {
    assert.ok(still, "the session ended");
    assert.strictEqual(again.r.status, 200, K.shown(again.r));
  });
  const byMail = { format: "email", email: "alice@ssft.example" };
  await pollNow([signed(setOf("account-disabled", byMail))]);
  const notNamed = await signIn("sid-6");
  await K.ok(K.rb(SP) + "/admin-api/federation/set", { id: "partner",
    field: "fedSignalEmailMatch", value: "TRUE" }, "email match on");
  await pollNow([signed(setOf("account-disabled", byMail))]);
  const named = await K.coded(SP, "STS-FED-0156", function () {
    return signIn("sid-7");
  });
  K.check("G1. an email subject names nobody unless the relationship " +
          "allows it", function () {
    assert.strictEqual(notNamed.r.status, 200, K.shown(notNamed.r));
    assert.ok(named.answer.r.status >= 400, K.shown(named.answer.r));
    assert.ok(named.rose >= 1);
  });
  log.debug("Leaving refusals().");
}

// ------------------------------------------------------------------- I
async function pushDoor() {
  log.debug("Entering pushDoor().");
  log.info("=== I. the push endpoint ===");
  const r = await K.send(K.rb(SP) + "/federation/signals/partner",
    { method: "POST", raw: "x", headers: { authorization: "Bearer wrong",
      "content-type": "application/secevent+jwt" } });
  // A poll stream holds no push header, so any header is one it did not
  // give; the in-process file's 401 is for a push stream's wrong header.
  K.check("I1. the push endpoint refuses an Authorization header it did " +
          "not give", function () {
    assert.ok(r.status === 401 || r.status === 403 || r.status === 404,
              K.shown(r));
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(r.text));
  });
  log.debug("Leaving pushDoor().");
}

async function test() {
  log.debug("Entering test().");
  const server = http.createServer(transmitter);
  await new Promise(function (resolve) {
    server.listen(0, "0.0.0.0", resolve);
  });
  ROOT = "http://" + K.HOST + ":" + server.address().port;
  ISS = ROOT + "/realm/partner";
  try {
    SP = await K.realm("ssft", "development", {
      "federation.outboundAllowHttp": "true",
      "ssf.actOnSignalsInDevelopment": "true" });
    await K.ok(K.rb(SP) + "/admin-api/users/create", {
      username: "ssft-alice", invent: false, credential: "none",
      attributes: { cn: "Alice", givenName: "Alice", sn: "Ssft",
                    mail: "alice@ssft.example" } }, "created alice");
    const idJwk = Object.assign(ID_KEY.publicKey.export({ format: "jwk" }),
                                { kid: "id-1", alg: "RS256", use: "sig" });
    await relationship("partner", { fedSsoUrl: ISS + "/authorize",
      fedClientId: CLIENT, fedResponseType: "id_token", fedScope: "openid",
      fedJwks: JSON.stringify({ keys: [idJwk] }),
      fedSubjectPolicy: "pre-linked", fedSignalsEnabled: "TRUE",
      fedSignalsTokenUrl: ROOT + "/token",
      fedSignalsClientId: "realm-receiver",
      fedSignalsClientSecret: "tx-secret-" + K.STAMP });
    await K.ok(K.rb(SP) + "/admin-api/users/federation-link", {
      user: "ssft-alice", relationship: "partner", subject: "ext-alice" },
    "linked alice");
    const two = await discoveryAndStream();
    const lifted = await blockAndLift(two);
    await refusals(lifted);
    await pushDoor();
  } finally {
    server.close();
  }
  log.debug("Leaving test().");
}

K.main(test, 9);
