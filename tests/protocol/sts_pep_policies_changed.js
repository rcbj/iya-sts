// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_pep_policies_changed.js
//
// ===========================================================================
// AN EMBEDDED PEP HEARS OF A POLICY CHANGE OVER SHARED SIGNALS, OVER THE WIRE
// (#2028, work item 5 of #1206).
//
// `tests/pep_policies_changed.js` holds the decision in process. This job
// drives it as a deployment meets it, in a realm of its own: two
// applications, each owning an RFC 8936 poll stream that asked for
// `urn:iya:sts:secevent:event-type:pep-policies-changed`, and a PEP embedded
// in the first in `local` mode, registered and pulling on its own
// DPoP-bound tokens as the `iya-pep` package does.
//
//   D. A DEPLOY: a change to the realm root its application is decided by
//      puts exactly one SET on the bound application's stream — subject the
//      application, `pep` the PEP, `changed` policies, `sync_token` the
//      scope's new token (what a scoped pull then answers) — and none on
//      the other application's stream.
//   X. THE EXCLUSION: with the application's `ssfAllowedEvents` naming only
//      `caep`, the stream is no longer delivered the type, the next deploy
//      puts nothing on it, and the application's page lists the PEP in
//      `pepEventsExcluded` (the console's warning).
//
// OWNED HERE (local: true): the event is this service's own, and the
// console's warning is drawn from /admin-api.
// ===========================================================================

const assert = require("assert");
const K = require("./oauth_wire_kit.js").kit("sts_pep_policies_changed");
const credentials = require("../tools/pep-credential.js");
const ssfRoles = require("./ssf_roles.js");

const log = K.log;
const check = K.check;

const URI = "urn:iya:sts:secevent:event-type:pep-policies-changed";
const POLL = "urn:ietf:rfc:8936";
const S = K.STAMP.slice(-7).toLowerCase();
const APP = "ppc-app-" + S;
const OTHER = "ppc-oth-" + S;
const PEP = "ppc-pep-" + S;
const SECRET = "ppc-secret-" + K.rand(12);
let realm = null;
let key = null;
let pepToken = "";
const streams = {};

function api(path) {
  log.debug("Entering api().");
  log.debug("Leaving api().");
  return K.rb(realm) + "/admin-api" + path;
}

async function post(url, body) {
  log.debug("Entering post().");
  const r = await K.send(url, { json: body });
  log.debug("Leaving post().");
  return { status: r.status, text: r.text, json: r.json, body: r.json };
}

async function asPep(method, path, body) {
  log.debug("Entering asPep(). " + method + " " + path);
  const url = K.rb(realm) + path;
  const headers = credentials.dpopHeaders(key.privateKeyPem, method,
                                          url.split("?")[0], pepToken);
  const r = await K.send(url, body === undefined
    ? { method: method, headers: headers }
    : { method: method, headers: headers, json: body });
  log.debug("Leaving asPep(). " + r.status);
  return r;
}

async function receiverToken(identifier) {
  log.debug("Entering receiverToken(). " + identifier);
  await ssfRoles.mapApplication(post, api(""), identifier,
                                "ssf.read ssf.manage");
  const r = await K.send(K.rb(realm) + "/oauth2/token", { form: {
    grant_type: "client_credentials", client_id: identifier,
    client_secret: SECRET, scope: "ssf.read ssf.manage" } });
  assert.ok(r.json && r.json.access_token, K.shown(r));
  log.debug("Leaving receiverToken().");
  return r.json.access_token;
}

// Every SET waiting on a stream, acknowledged, as { type, payload, sub_id }.
async function drain(owner) {
  log.debug("Entering drain(). " + owner);
  const one = streams[owner];
  const auth = { Authorization: "Bearer " + one.token };
  const out = [];
  for (let i = 0; i < 3; i += 1) {
    const r = await K.send(K.rb(realm) + "/ssf/poll", { headers: auth,
      json: { stream_id: one.id, returnImmediately: true, maxEvents: 100 } });
    assert.strictEqual(r.status, 200, K.shown(r));
    const sets = (r.json && r.json.sets) || {};
    const jtis = Object.keys(sets);
    if (!jtis.length) {
      break;
    }
    jtis.forEach(function (jti) {
      const claims = JSON.parse(Buffer.from(sets[jti].split(".")[1],
                                            "base64url").toString("utf8"));
      Object.keys(claims.events || {}).forEach(function (type) {
        out.push({ type: type, payload: claims.events[type],
                   subject: claims.sub_id || claims.events[type].subject });
      });
    });
    await K.send(K.rb(realm) + "/ssf/poll", { headers: auth,
      json: { stream_id: one.id, ack: jtis, returnImmediately: true,
              maxEvents: 0 } });
  }
  log.debug("Leaving drain(). " + out.length);
  return out;
}

async function setUp() {
  log.debug("Entering setUp().");
  realm = await K.realm("pepsignal", "development");
  for (const id of [APP, OTHER]) {
    await K.ok(api("/applications/create"), { identifier: id, name: id,
      kind: "oauth2-client", protocols: ["oauth2", "ssf"],
      fields: { oauthClientId: [id],
                oauthAllowedScope: ["ssf.read", "ssf.manage"],
                oauthClientSecret: SECRET,
                oauthTokenEndpointAuthMethod: "client_secret_post" } },
      "created " + id);
  }
  // THE ROOT the application is decided by (it enforces nothing).
  await K.ok(api("/xacml/create-from-template"), { template: "blank",
    name: "ppc-root" }, "the root policy");
  await K.ok(api("/xacml/set-root"), { name: "ppc-root" }, "made it the root");
  // THE PEP: its account, key, binding, registration and first pull.
  await K.ok(api("/users/create"), { username: PEP, invent: false,
    attributes: { cn: PEP, sn: "Signal PEP", givenName: "Signal",
                  mail: PEP + "@pep-signal.test" } }, "created " + PEP);
  await K.ok(api("/groups/add-member"), { group: "remote-peps", member: PEP },
             "put " + PEP + " in remote-peps");
  key = await credentials.assertionRequest({ keyAlg: "ec-p256", name: PEP });
  await credentials.issueAssertionCredential({ post: post }, K.base,
    "/realm/" + realm, PEP, key.csrPem);
  const got = await credentials.pepAccessToken(K.rb(realm), PEP,
    key.privateKeyPem, "xacml:pep", "/xacml/pep");
  assert.ok(got.status === 200 && got.token, String(got.text).slice(0, 300));
  pepToken = got.token;
  await K.ok(api("/xacml/set-pep-application"),
             { name: PEP, application: APP }, "bound " + PEP);
  const registered = await asPep("POST", "/xacml/pep/register",
    { name: PEP, kind: "embedded", application: APP, mode: "local",
      protocolVersion: 1, version: "iya-pep-rust/0.1.0" });
  assert.ok(registered.status === 201 || registered.status === 200,
            K.shown(registered));
  const pulled = await asPep("GET", "/xacml/pep/policies?scope=" +
                             "bound-application&pep=" + PEP);
  assert.strictEqual(pulled.status, 200, K.shown(pulled));
  // THE TWO RECEIVERS' STREAMS.
  for (const owner of [APP, OTHER]) {
    const token = await receiverToken(owner);
    const made = await K.send(K.rb(realm) + "/ssf/stream", {
      headers: { Authorization: "Bearer " + token },
      json: { delivery: { method: POLL }, events_requested: [URI] } });
    assert.strictEqual(made.status, 201, K.shown(made));
    assert.ok(made.json.events_delivered.indexOf(URI) >= 0, K.shown(made));
    streams[owner] = { id: made.json.stream_id, token: token };
    await drain(owner);
  }
  log.debug("Leaving setUp().");
}

async function deploy() {
  log.debug("Entering deploy().");
  log.info("=== D. a deploy ===");
  await K.ok(api("/xacml/add-rule"), { policy: "ppc-root", path: "",
                                        effect: "Permit" }, "changed the root");
  let mine = [];
  for (let i = 0; i < 20 && !mine.length; i += 1) {
    mine = (await drain(APP)).filter(function (one) {
      return one.type === URI;
    });
    if (!mine.length) {
      await K.sleep(250);
    }
  }
  const others = (await drain(OTHER)).filter(function (one) {
    return one.type === URI;
  });
  const pulled = await asPep("GET", "/xacml/pep/policies?scope=" +
                             "bound-application&pep=" + PEP);
  check("D1. the deploy put exactly one pep-policies-changed on the bound " +
        "application's stream, naming the PEP, policies and the scope's " +
        "new token", function () {
    assert.strictEqual(mine.length, 1, JSON.stringify(mine));
    assert.strictEqual(mine[0].payload.pep, PEP);
    assert.deepStrictEqual(mine[0].payload.changed, ["policies"]);
    assert.strictEqual(mine[0].payload.sync_token, pulled.json.syncToken,
                       JSON.stringify(mine[0].payload));
    assert.strictEqual(mine[0].payload.policy, undefined);
  });
  check("D2. its subject is the application", function () {
    assert.deepStrictEqual(mine[0].subject, { format: "complex",
      application: { format: "opaque", id: APP } },
      JSON.stringify(mine[0].subject));
  });
  check("D3. and nothing reached the other application's stream",
        function () {
    assert.strictEqual(others.length, 0, JSON.stringify(others));
  });
  log.debug("Leaving deploy().");
}

async function excluded() {
  log.debug("Entering excluded().");
  log.info("=== X. the exclusion ===");
  await K.ok(api("/applications/add"), { application: APP,
    attribute: "ssfAllowedEvents", value: "caep" },
    "limited " + APP + " to caep");
  const read = await K.send(K.rb(realm) + "/ssf/stream?stream_id=" +
    encodeURIComponent(streams[APP].id),
    { headers: { Authorization: "Bearer " + streams[APP].token } });
  const config = Array.isArray(read.json) ? read.json[0] : read.json;
  await K.ok(api("/xacml/add-rule"), { policy: "ppc-root", path: "",
                                        effect: "Deny" }, "changed the root");
  await K.sleep(1500);
  const got = (await drain(APP)).filter(function (one) {
    return one.type === URI;
  });
  const page = await K.send(api("/applications?application=" +
                                encodeURIComponent(APP)));
  check("X1. ssfAllowedEvents naming only caep withholds the type: the " +
        "stream no longer delivers it and the next deploy sends nothing",
        function () {
    assert.ok(config && config.events_delivered.indexOf(URI) < 0,
              K.shown(read));
    assert.strictEqual(got.length, 0, JSON.stringify(got));
  });
  check("X2. the application's page lists the PEP that will not hear of a " +
        "change", function () {
    assert.strictEqual(page.status, 200, K.shown(page));
    assert.deepStrictEqual((page.json.page || {}).pepEventsExcluded, [PEP],
                           K.shown(page));
  });
  log.debug("Leaving excluded().");
}

async function test() {
  log.debug("Entering test().");
  await setUp();
  await deploy();
  await excluded();
  log.debug("Leaving test().");
}

K.main(test, 5);
