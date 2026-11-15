// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_issued_sets_and_delegation_map.js
//
// ---------------------------------------------------------------------------
// ONE ISSUANCE IS ONE SET, AND ONE APPLICATION IS ONE BOX, OVER THE WIRE.
//
// D12 (#444): carries over three in-process files, each driven here through
// real protocol requests in a throwaway development realm and read back from
// `/admin-api`:
//
//   * `tests/issued_sets.js` — a row of /admin/tokens is one issuance:
//       1. a password grant asking `openid offline_access` is ONE set of
//          three, `grouped`, every member carrying the issuer's set id, in
//          issuance order `access_token+refresh_token+id_token`;
//       2. the set's expiry is its EARLIEST member's, `lastExpiresAtMs` the
//          latest (the refresh token's);
//       3. one member revoked makes the set `mixed`, with the breakdown
//          (`valid: 2, revoked: 1`) and `revokedCount: 1`;
//       4. a SAML assertion (a WS-Trust RST) is a set of its OWN — not
//          grouped, size 1, no set id, one revocable member whose reach is
//          `record-only`;
//       5. a set key nothing holds answers `found: false`.
//     NOT carried, and why: "two replies that agree on every recorded field
//     are still two replies" needs two token responses minted in the same
//     millisecond, which a client cannot arrange on purpose (class (d)).
//   * `tests/delegation_map_audience.js` — an application named by its
//     registered audience, by its identifier or by its client_id is ONE box
//     on the delegation picture (`GET /admin-api/delegation`'s `graph`),
//     keyed by the identifier with the client_id kept as an alias; and a
//     configured pair (`appAllowedToDelegateTo`) naming the audience draws
//     its `may-delegate` line to that same box. An audience no application
//     registered cannot reach the register over the wire — the token
//     endpoint refuses it (`invalid_target`), which is asserted instead.
//   * `tests/delegation_map_client_subject.js` — a client acting as itself:
//     in development the actor's `sub` is the bare client_id, and where that
//     client_id is NOT the identifier the box is still the application's;
//     a person is still keyed as an identity. Product's form
//     (`urn:sts:client:<id>`, #468) is asserted by
//     `sts_token_exchange_chain_delegation.js`'s `assertGraphIsAChain()` in
//     both modes; and an actor_token naming ANOTHER client cannot be sent —
//     the token endpoint refuses it (RFC 8693 section 2.1), which is
//     asserted here in its place.
//
// OWNED HERE (local: true): this repository's own management API.
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
var log = bunyan.createLogger({ name: "sts_issued_sets_and_delegation_map",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "")
  .slice(-10);
const REALM = "isd-" + STAMP;
const RB = base + "/realm/" + REALM;
const TX = "urn:ietf:params:oauth:grant-type:token-exchange";
const AT = "urn:ietf:params:oauth:token-type:access_token";

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
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

function token(fields) {
  log.debug("Entering token().");
  log.debug("Leaving token().");
  return send(RB + "/oauth2/token", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(fields).toString() });
}

async function app(identifier, fields, protocols) {
  log.debug("Entering app(). " + identifier);
  await ok(RB + "/admin-api/applications/create", { identifier: identifier,
    name: identifier, protocols: protocols || ["oauth2"], fields: fields },
    "registered " + identifier);
  log.debug("Leaving app().");
}

function jtiOf(jwt) {
  log.debug("Entering jtiOf().");
  const payload = JSON.parse(Buffer.from(String(jwt).split(".")[1],
                                         "base64url").toString("utf8"));
  log.debug("Leaving jtiOf().");
  return payload.jti;
}

// ---------------------------------------------------------------------------
// issued_sets.js
// ---------------------------------------------------------------------------
async function theIssuedSets() {
  log.debug("Entering theIssuedSets().");
  log.info("=== 1. one issuance is one set (issued_sets) ===");
  await app("web", { oauthClientId: ["web"],
    oauthGrantType: ["password", "refresh_token", "client_credentials"] });
  const minted = await token({ grant_type: "password", client_id: "web",
    client_secret: "dev", username: "sets-" + STAMP, password: "dev",
    scope: "openid offline_access" });
  assert.strictEqual(minted.status, 200, minted.raw.slice(0, 300));
  const jti = jtiOf(minted.body.access_token);
  const listed = await send(RB + "/admin-api/tokens?per=200");
  const set = ((listed.body && listed.body.sets) || []).filter(function (s) {
    return s.members.some(function (m) {
      return m.jti === jti;
    });
  })[0];
  check("1. the reply is ONE set of three, grouped, every member carrying " +
        "the issuer's own set id", function () {
    assert.ok(set, "no set holds jti " + jti);
    assert.strictEqual(set.grouped, true);
    assert.strictEqual(set.size, 3);
    assert.ok(set.setId, JSON.stringify(set).slice(0, 300));
    assert.ok(set.members.every(function (m) {
      return m.setId === set.setId;
    }));
    assert.strictEqual(set.setKey, "set:" + set.setId);
  });
  check("1. members in issuance order: access_token+refresh_token+id_token",
        function () {
    assert.strictEqual(set.kinds.join("+"),
                       "access_token+refresh_token+id_token");
    assert.deepStrictEqual(set.members.map(function (m) {
      return m.kind;
    }), ["access_token", "refresh_token", "id_token"]);
  });
  check("2. the set's expiry is its earliest member's, and lastExpiresAtMs " +
        "the refresh token's", function () {
    const exps = set.members.map(function (m) {
      return m.expiresAtMs;
    });
    assert.strictEqual(set.expiresAtMs, Math.min.apply(null, exps));
    assert.strictEqual(set.lastExpiresAtMs, Math.max.apply(null, exps));
    assert.ok(set.expiresAtMs < set.lastExpiresAtMs);
    assert.strictEqual(set.members[1].expiresAtMs, set.lastExpiresAtMs);
  });
  check("the set starts valid, three revocable and none revoked", function () {
    assert.strictEqual(set.state, "valid");
    assert.strictEqual(set.revocableCount, 3);
    assert.strictEqual(set.revokedCount, 0);
  });

  await ok(RB + "/admin-api/tokens/revoke", { jti: jti },
           "revoked the access token alone");
  const opened = await send(RB + "/admin-api/tokens/set?id=" +
                            encodeURIComponent(set.setKey));
  check("3. one member revoked makes the set MIXED, with the breakdown",
        function () {
    assert.strictEqual(opened.status, 200, opened.raw.slice(0, 300));
    assert.strictEqual(opened.body.found, true);
    assert.strictEqual(opened.body.set.state, "mixed");
    assert.deepStrictEqual(opened.body.set.states, { valid: 2, revoked: 1 });
    assert.strictEqual(opened.body.set.revokedCount, 1);
  });

  await app("sets-rp", { wstrustAppliesTo: ["https://sets-rp-" + STAMP +
                                            ".example"] }, ["wstrust"]);
  const rst = '<?xml version="1.0" encoding="UTF-8"?>' +
    '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">' +
    '<soap:Header><wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/' +
    '2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">' +
    '<wsse:UsernameToken><wsse:Username>sets-' + STAMP + '</wsse:Username>' +
    '<wsse:Password>dev</wsse:Password></wsse:UsernameToken>' +
    '</wsse:Security></soap:Header>' +
    '<soap:Body><wst:RequestSecurityToken ' +
    'xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">' +
    '<wst:RequestType>' +
    'http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType>' +
    '<wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/' +
    'policy"><wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/' +
    'addressing"><wsa:Address>https://sets-rp-' + STAMP + '.example' +
    '</wsa:Address></wsa:EndpointReference></wsp:AppliesTo>' +
    '</wst:RequestSecurityToken></soap:Body></soap:Envelope>';
  const issued = await send(RB + "/sts", { method: "POST",
    headers: { "Content-Type": "application/soap+xml" }, body: rst });
  assert.strictEqual(issued.status, 200, issued.raw.slice(0, 300));
  const after = await send(RB + "/admin-api/tokens?per=200");
  const assertion = ((after.body && after.body.sets) || []).filter(
    function (s) {
      return s.members.some(function (m) {
        return m.revocationReach === "record-only";
      });
    })[0];
  check("4. a SAML assertion is a set of its OWN: not grouped, one member, " +
        "no set id", function () {
    assert.ok(assertion, JSON.stringify((after.body.sets || []).map(
      function (s) {
        return s.kinds;
      })));
    assert.strictEqual(assertion.grouped, false);
    assert.strictEqual(assertion.size, 1);
    assert.strictEqual(assertion.setId, "");
  });
  check("4. its one member is revocable, and its reach is the record only",
        function () {
    assert.strictEqual(assertion.revocableCount, 1);
    assert.strictEqual(assertion.members[0].revocationReach, "record-only");
  });
  const absent = await send(RB + "/admin-api/tokens/set?id=" +
                            encodeURIComponent("set:never-" + STAMP));
  check("5. a set key nothing holds answers found: false", function () {
    assert.strictEqual(absent.status, 200, absent.raw.slice(0, 300));
    assert.strictEqual(absent.body.found, false);
  });
  log.debug("Leaving theIssuedSets().");
}

// ---------------------------------------------------------------------------
// delegation_map_audience.js and delegation_map_client_subject.js
// ---------------------------------------------------------------------------
async function graph() {
  log.debug("Entering graph().");
  const r = await send(RB + "/admin-api/delegation?per=200");
  assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
  log.debug("Leaving graph().");
  return r.body.graph || { nodes: [], edges: [] };
}

function describe(g) {
  log.debug("Entering describe().");
  log.debug("Leaving describe().");
  return JSON.stringify({
    nodes: (g.nodes || []).map(function (n) {
      return [n.id, n.application, n.aliases, n.roles];
    }),
    edges: (g.edges || []).map(function (e) {
      return [e.from, e.relation, e.to];
    }) });
}

async function theBoxes() {
  log.debug("Entering theBoxes().");
  log.info("=== 2. one application is one box (delegation_map_*) ===");
  const audience = "https://api-" + STAMP + ".example.com";
  await app("api1", { oauthAudience: [audience],
                      oauthClientId: ["api1-client"] });
  await app("front", { oauthClientId: ["front"],
    oauthGrantType: ["client_credentials", "password", TX],
    appAllowedToDelegateTo: [audience] });
  await app("svc", { oauthClientId: ["svc-client"],
                     oauthGrantType: ["client_credentials", TX] });

  const own = await token({ grant_type: "client_credentials",
    client_id: "front", client_secret: "dev" });
  assert.strictEqual(own.status, 200, own.raw.slice(0, 300));
  for (const name of [audience, "api1", "api1-client"]) {
    const ex = await token({ grant_type: TX, client_id: "front",
      client_secret: "dev", subject_token: own.body.access_token,
      subject_token_type: AT, audience: name });
    assert.strictEqual(ex.status, 200, name + ": " + ex.raw.slice(0, 300));
  }
  const stranger = await token({ grant_type: TX, client_id: "front",
    client_secret: "dev", subject_token: own.body.access_token,
    subject_token_type: AT,
    audience: "https://nobody-" + STAMP + ".example.com" });
  check("an audience no application registered is refused invalid_target, " +
        "so it never reaches the register", function () {
    assert.strictEqual(stranger.status, 400, stranger.raw.slice(0, 300));
    assert.strictEqual(stranger.body.error, "invalid_target");
  });

  let g = await graph();
  const apiBoxes = g.nodes.filter(function (n) {
    return n.id === "api1";
  });
  check("the audience, the identifier and the client_id are ONE box, keyed " +
        "by the identifier, the client_id kept as an alias", function () {
    assert.strictEqual(apiBoxes.length, 1, describe(g));
    assert.strictEqual(apiBoxes[0].application, "api1");
    assert.ok((apiBoxes[0].aliases || []).indexOf("api1-client") >= 0,
              describe(g));
    assert.strictEqual(apiBoxes[0].roles.target, 3, describe(g));
    assert.ok(!g.nodes.some(function (n) {
      return n.id === audience || n.id === "api1-client";
    }), describe(g));
  });
  check("every act's line reaches that box", function () {
    const reaching = g.edges.filter(function (e) {
      return e.to === "api1" && e.relation === "reaches";
    }).reduce(function (n, e) {
      return n + Number(e.acts || 0);
    }, 0);
    assert.strictEqual(reaching, 3, describe(g));
  });
  check("a configured pair naming the AUDIENCE draws its may-delegate line " +
        "to that same box", function () {
    const configured = g.edges.filter(function (e) {
      return e.relation === "may-delegate";
    });
    assert.strictEqual(configured.length, 1, describe(g));
    assert.strictEqual(configured[0].from, "front");
    assert.strictEqual(configured[0].to, "api1");
  });

  const person = "dmc-" + STAMP;
  const signedIn = await token({ grant_type: "password", client_id: "front",
    client_secret: "dev", username: person, password: "dev" });
  assert.strictEqual(signedIn.status, 200, signedIn.raw.slice(0, 300));
  const svcOwn = await token({ grant_type: "client_credentials",
    client_id: "svc-client", client_secret: "dev" });
  assert.strictEqual(svcOwn.status, 200, svcOwn.raw.slice(0, 300));
  const foreign = await token({ grant_type: TX, client_id: "front",
    client_secret: "dev", subject_token: signedIn.body.access_token,
    subject_token_type: AT, actor_token: svcOwn.body.access_token,
    actor_token_type: AT, audience: audience });
  check("an actor_token issued to ANOTHER client is refused (RFC 8693 " +
        "section 2.1), so that act cannot be recorded", function () {
    assert.strictEqual(foreign.status, 400, foreign.raw.slice(0, 300));
    assert.strictEqual(foreign.body.error, "invalid_request");
    assert.ok(/not issued to this client/.test(
      foreign.body.error_description), foreign.raw.slice(0, 300));
  });
  const delegated = await token({ grant_type: TX, client_id: "svc-client",
    client_secret: "dev", subject_token: signedIn.body.access_token,
    subject_token_type: AT, actor_token: svcOwn.body.access_token,
    actor_token_type: AT, audience: audience });
  assert.strictEqual(delegated.status, 200, delegated.raw.slice(0, 300));
  g = await graph();
  const svcBoxes = g.nodes.filter(function (n) {
    return n.id === "svc";
  });
  check("DEVELOPMENT'S FORM: an actor whose sub is a REGISTERED client_id " +
        "is that application's box, though the client_id is not the " +
        "identifier", function () {
    assert.strictEqual(svcBoxes.length, 1, describe(g));
    assert.ok(svcBoxes[0].roles.intermediary >= 1, describe(g));
    assert.ok(!g.nodes.some(function (n) {
      return n.id === "svc-client";
    }), describe(g));
  });
  check("a person is still keyed as an identity (no application), and " +
        "the service acts for them on to the API", function () {
    const boxes = g.nodes.filter(function (n) {
      return n.id === person;
    });
    assert.strictEqual(boxes.length, 1, describe(g));
    assert.strictEqual(boxes[0].application, "");
    assert.ok(boxes[0].roles.initial >= 1, describe(g));
    assert.ok(g.edges.some(function (e) {
      return e.from === person && e.relation === "acts-for" &&
             e.mode === "delegation" && e.to === "svc";
    }), describe(g));
    assert.ok(g.edges.some(function (e) {
      return e.from === "svc" && e.relation === "reaches" && e.to === "api1";
    }), describe(g));
  });
  log.debug("Leaving theBoxes().");
}

async function test() {
  log.debug("Entering test().");
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "Issued sets " + STAMP },
    "created the realm");
  await theIssuedSets();
  await theBoxes();
  log.info("Test completed successfully. " + checks + " check(s) passed.");
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error("sts_issued_sets_and_delegation_map FAILED: " +
            ((e && e.stack) || e));
  process.exit(1);
});
