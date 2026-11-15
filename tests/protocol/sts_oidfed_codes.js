// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_oidfed_codes.js
//
// ===========================================================================
// OPENID FEDERATION'S REFUSALS BY CODE, OVER THE WIRE (#132-#137; #444 D12,
// phase 7).
//
// `tests/oidfed_entity.js`, `tests/oidfed_extensions.js` and
// `tests/oidfed_registration.js` call `oidfed/*` in process and read each
// refusal's code off the result; `sts_oidfed.js` and
// `sts_oidfed_extensions.js` drive the same endpoints over HTTP and read
// statuses. This job carries the codes, the default realm the Trust Anchor
// and a throwaway realm its Subordinate (an OP), as those jobs arrange it:
//
//   E. an unauthenticated resolve naming an entity this realm has not
//      resolved does not start a resolution (STS-OIDFED-0036); the current
//      Federation Entity Key cannot be revoked by hand (STS-OIDFED-0042);
//   X. no Subordinate Statement about a suspended subordinate
//      (STS-OIDFED-0057); an Extended Subordinate Listing with a limit that
//      is not a positive integer (STS-OIDFED-0060); Subordinate Events with
//      no sub (STS-OIDFED-0063) or a stranger's (STS-OIDFED-0064);
//   R. automatic registration at the realm's authorization endpoint,
//      refused 400 and never redirected, the RP not registered: no proof,
//      aud another OP, two audiences, a sub, no jti, another key, a
//      symmetric alg (STS-OIDFED-0054), a secret-based method
//      (STS-OIDFED-0055), somebody else's chain (STS-OIDFED-0053); the
//      good request registers; explicit registration with the wrong media
//      type (STS-OIDFED-0056), a configuration naming no OP or another one,
//      and a realm that does not offer it (404); and (oidcc conformance
//      finding 4) every later request object of the registered RP held to
//      section 12.1.1.1's claims — a sub, no jti, no exp, no iss, no aud,
//      another aud (STS-OIDFED-0067) — the good one still accepted.
//
// NOT HERE: oidfed_registration 3a (a registration made with a clock two
// hours behind, so that it lands already expired — no request moves the
// service's clock) and oidfed_entity's resolution "nothing fetched" (the
// trust chain of a local realm is built in process).
//
// OWNED HERE (local: true). Its realm is removed only on a private probe;
// the subordinates it registers under the default realm carry the STAMP.
// ===========================================================================

const assert = require("assert");
const nodeCrypto = require("crypto");
const K = require("./oauth_wire_kit.js").kit("sts_oidfed_codes");

const log = K.log;
let REALM = null;

function partsOf(jwt) {
  log.debug("Entering partsOf().");
  const p = String(jwt || "").split(".");
  if (p.length !== 3) {
    log.debug("Leaving partsOf(). Not a JWS.");
    return null;
  }
  log.debug("Leaving partsOf().");
  return { header: JSON.parse(Buffer.from(p[0], "base64url").toString()),
           claims: JSON.parse(Buffer.from(p[1], "base64url").toString()) };
}

function jws(header, payload, privateKey, alg) {
  log.debug("Entering jws().");
  const b64 = function (o) {
    log.debug("Entering b64().");
    log.debug("Leaving b64().");
    return Buffer.from(JSON.stringify(o)).toString("base64url");
  };
  const input = b64(Object.assign({ alg: alg || "ES256" }, header)) + "." +
                b64(payload);
  const sig = alg === "HS256"
    ? nodeCrypto.createHmac("sha256", "a-shared-secret").update(input)
      .digest("base64url")
    : nodeCrypto.sign("sha256", Buffer.from(input),
      { key: privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url");
  log.debug("Leaving jws().");
  return input + "." + sig;
}

function ecKey(kid) {
  log.debug("Entering ecKey().");
  const pair = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = Object.assign(pair.publicKey.export({ format: "jwk" }),
                            { kid: kid, alg: "ES256", use: "sig" });
  log.debug("Leaving ecKey().");
  return { privateKey: pair.privateKey, jwk: jwk };
}

async function configurationOf(at) {
  log.debug("Entering configurationOf(). " + at);
  const r = await K.send(at + "/.well-known/openid-federation");
  log.debug("Leaving configurationOf(). " + r.status);
  return { jwt: r.text, parts: r.status === 200 ? partsOf(r.text) : null };
}

// A RELYING PARTY the default realm vouches for, and makers of its Entity
// Configuration, Trust Chain and request objects (sts_oidfed.js's shape).
async function federatedRp(tag, anchor, fetchAt) {
  log.debug("Entering federatedRp(). " + tag);
  const id = "https://" + tag + "-" + K.STAMP + ".example.test";
  const fed = ecKey("fed-" + tag);
  const proto = ecKey("rp-" + tag);
  await K.ok(K.base + "/admin-api/oidfed/add-subordinate",
             { entityId: id, jwks: { keys: [fed.jwk] },
               entityTypes: "openid_relying_party" }, "registered " + id);
  const ss = await K.send(fetchAt + "?sub=" + encodeURIComponent(id));
  assert.strictEqual(ss.status, 200, ss.text.slice(0, 300));
  const now = Math.floor(Date.now() / 1000);
  const rp = { id: id, proto: proto };
  rp.configuration = function (extra, claims) {
    log.debug("Entering configuration().");
    log.debug("Leaving configuration().");
    return jws({ typ: "entity-statement+jwt", kid: fed.jwk.kid },
      Object.assign({ iss: id, sub: id, iat: now, exp: now + 3600,
        jwks: { keys: [fed.jwk] }, authority_hints: [anchor.parts.claims.iss],
        metadata: { openid_relying_party: Object.assign({
          redirect_uris: [id + "/cb"], response_types: ["code"],
          grant_types: ["authorization_code"], client_name: "RP " + tag,
          jwks: { keys: [proto.jwk] } }, extra || {}) } }, claims || {}),
      fed.privateKey);
  };
  rp.chain = function (ec) {
    log.debug("Entering chain().");
    log.debug("Leaving chain().");
    return [ec || rp.configuration(), ss.text, anchor.jwt];
  };
  rp.request = function (opId, claims, header, key, alg) {
    log.debug("Entering request().");
    const payload = Object.assign({ iss: id, client_id: id, aud: opId,
      jti: nodeCrypto.randomUUID(), iat: now, exp: now + 300,
      response_type: "code", redirect_uri: id + "/cb", scope: "openid",
      state: "s-" + tag, nonce: "n-" + tag,
      code_challenge: nodeCrypto.createHash("sha256").update("v".repeat(43))
        .digest("base64url"), code_challenge_method: "S256" }, claims || {});
    Object.keys(payload).forEach(function (k) {
      if (payload[k] === undefined) {
        delete payload[k];
      }
    });
    log.debug("Leaving request().");
    return jws(Object.assign({ typ: "oauth-authz-req+jwt",
                               kid: proto.jwk.kid, trust_chain: rp.chain() },
                             header || {}),
               payload, key || proto.privateKey, alg);
  };
  log.debug("Leaving federatedRp().");
  return rp;
}

// Whether the realm holds a client for `id`: the applications list, searched
// for it.
async function known(realm, id) {
  log.debug("Entering known(). " + id);
  const r = await K.send(K.rb(realm) + "/admin-api/applications?q=" +
                         encodeURIComponent(id.replace(/^https:\/\//, "")));
  log.debug("Leaving known(). " + r.status);
  return r.status === 200 && r.text.indexOf("\"" + id + "\"") >= 0;
}

// ------------------------------------------------------------------- E
async function entity(anchor) {
  log.debug("Entering entity().");
  log.info("=== E. the entity: resolve and its keys ===");
  const resolveAt = anchor.parts.claims.metadata.federation_entity
    .federation_resolve_endpoint || K.base + "/oidfed/resolve";
  const got = await K.coded(null, "STS-OIDFED-0036", function () {
    return K.send(resolveAt + "?sub=" + encodeURIComponent(
      "https://elsewhere-" + K.STAMP + ".example.test") + "&trust_anchor=" +
      encodeURIComponent(anchor.parts.claims.iss));
  });
  K.check("E1. an unauthenticated resolve naming an entity nobody resolved " +
          "starts no resolution (STS-OIDFED-0036)", function () {
    assert.ok(got.answer.status >= 400, got.answer.text.slice(0, 200));
    assert.ok(got.rose >= 1);
  });
  const view = await K.send(K.rb(REALM) + "/admin-api/oidfed");
  const current = ((view.json || {}).keys || []).filter(function (k) {
    return k.state === "current";
  })[0] || {};
  const refused = await K.coded(REALM, "STS-OIDFED-0042", function () {
    return K.send(K.rb(REALM) + "/admin-api/oidfed/revoke-key",
                  { json: { kid: current.kid, reason: "compromised" } });
  });
  K.check("E2. the current Federation Entity Key cannot be revoked by hand " +
          "(400, STS-OIDFED-0042)", function () {
    assert.ok(current.kid, JSON.stringify((view.json || {}).keys)
      .slice(0, 300));
    assert.strictEqual(refused.answer.status, 400,
                       refused.answer.text.slice(0, 200));
    assert.ok(refused.rose >= 1);
  });
  log.debug("Leaving entity().");
}

// ------------------------------------------------------------------- X
async function extensions(anchor) {
  log.debug("Entering extensions().");
  log.info("=== X. the extensions ===");
  const fe = anchor.parts.claims.metadata.federation_entity;
  const sub = "https://suspended-" + K.STAMP + ".example.test";
  const key = ecKey("sus");
  await K.ok(K.base + "/admin-api/oidfed/add-subordinate", { entityId: sub,
    jwks: { keys: [key.jwk] }, entityTypes: "openid_relying_party" },
  "registered " + sub);
  await K.ok(K.base + "/admin-api/oidfed/suspend-subordinate",
             { entityId: sub, reason: "under review" }, "suspended");
  let got = await K.coded(null, "STS-OIDFED-0057", function () {
    return K.send(fe.federation_fetch_endpoint + "?sub=" +
                  encodeURIComponent(sub));
  });
  K.check("X1. no Subordinate Statement about a suspended subordinate " +
          "(404 not_found, STS-OIDFED-0057)", function () {
    assert.strictEqual(got.answer.status, 404, got.answer.text.slice(0, 200));
    assert.strictEqual((got.answer.json || {}).error, "not_found");
    assert.ok(got.rose >= 1);
  });
  await K.ok(K.base + "/admin-api/oidfed/remove-subordinate",
             { entityId: sub, reason: "done" }, "removed");
  got = await K.coded(null, "STS-OIDFED-0060", function () {
    return K.send(K.base + "/oidfed/extended-list?limit=0");
  });
  K.check("X2. an Extended Subordinate Listing with a limit of 0 is 400 " +
          "invalid_request (STS-OIDFED-0060)", function () {
    assert.strictEqual(got.answer.status, 400);
    assert.strictEqual((got.answer.json || {}).error, "invalid_request");
    assert.ok(got.rose >= 1);
  });
  const noSub = await K.coded(null, "STS-OIDFED-0063", function () {
    return K.send(K.base + "/oidfed/subordinate-events");
  });
  const stranger = await K.coded(null, "STS-OIDFED-0064", function () {
    return K.send(K.base + "/oidfed/subordinate-events?sub=" +
      encodeURIComponent("https://stranger-" + K.STAMP + ".example.test"));
  });
  K.check("X3. Subordinate Events with no sub is 400 (STS-OIDFED-0063), " +
          "and for an entity that never was a subordinate 404 " +
          "(STS-OIDFED-0064)", function () {
    assert.strictEqual(noSub.answer.status, 400);
    assert.ok(noSub.rose >= 1);
    assert.strictEqual(stranger.answer.status, 404);
    assert.ok(stranger.rose >= 1);
  });
  log.debug("Leaving extensions().");
}

// ------------------------------------------------------------------- R
async function registration(anchor) {
  log.debug("Entering registration().");
  log.info("=== R. registration through the federation ===");
  const fetchAt = anchor.parts.claims.metadata.federation_entity
    .federation_fetch_endpoint;
  const anchorId = anchor.parts.claims.iss;
  const op = await configurationOf(K.rb(REALM));
  const opId = op.parts.claims.iss;
  const rp = await federatedRp("reg", anchor, fetchAt);
  const other = ecKey("other");
  const at = K.rb(REALM) + "/oauth2/authorize";
  const cases = [
    ["no proof", null, "STS-OIDFED-0054"],
    ["aud another OP", rp.request(anchorId), "STS-OIDFED-0054"],
    ["two audiences", rp.request(opId, { aud: [opId, anchorId] }),
     "STS-OIDFED-0054"],
    ["a sub", rp.request(opId, { sub: rp.id }), "STS-OIDFED-0054"],
    ["no jti", rp.request(opId, { jti: undefined }), "STS-OIDFED-0054"],
    ["another key", rp.request(opId, {}, { kid: other.jwk.kid },
                               other.privateKey), "STS-OIDFED-0054"],
    ["a symmetric alg", rp.request(opId, {}, {}, null, "HS256"),
     "STS-OIDFED-0054"],
    ["a secret method", rp.request(opId, {}, { trust_chain: rp.chain(
      rp.configuration({ token_endpoint_auth_method:
                         "client_secret_basic" })) }), "STS-OIDFED-0055"],
    ["somebody else's chain", rp.request(opId, {},
      { trust_chain: [anchor.jwt] }), "STS-OIDFED-0053"]
  ];
  for (const c of cases) {
    const form = { client_id: rp.id, response_type: "code", scope: "openid" };
    if (c[1]) {
      form.request = c[1];
    } else {
      form.redirect_uri = rp.id + "/cb";
    }
    const got = await K.coded(REALM, c[2], function () {
      return K.send(at, { form: form });
    });
    const registered = await known(REALM, rp.id);
    K.check("R. refused: " + c[0] + " (400, never redirected, " + c[2] +
            "), and nothing registered", function () {
      assert.strictEqual(got.answer.status, 400,
                         got.answer.status + " " + got.answer.location + " " +
                         got.answer.text.slice(0, 200));
      assert.ok(!got.answer.location);
      assert.ok(got.rose >= 1, "no " + c[2] + " row");
      assert.ok(!registered);
    });
  }
  const good = await K.send(at, { form: { client_id: rp.id,
    response_type: "code", scope: "openid", request: rp.request(opId) } });
  const nowKnown = await known(REALM, rp.id);
  K.check("R. the good request object registers the RP (now known to " +
          "/admin-api/applications) and goes on to sign-in", function () {
    assert.strictEqual(good.status, 302, good.text.slice(0, 300));
    assert.ok(nowKnown, "the registered RP is not listed");
    assert.ok(!/\/cb/.test(good.location), good.location);
  });
  // oidcc_conformance_findings 4: section 12.1.1.1's claims are asked of
  // EVERY request object from an RP registered automatically, not only the
  // one that registered it.
  const again = [
    ["a sub", { sub: rp.id }], ["no jti", { jti: undefined }],
    ["no exp", { exp: undefined }], ["no iss", { iss: undefined }],
    ["no aud", { aud: undefined }], ["another aud", { aud: [opId, rp.id] }]];
  for (const c of again) {
    const got = await K.coded(REALM, "STS-OIDFED-0067", function () {
      return K.send(at, { form: { client_id: rp.id, response_type: "code",
        scope: "openid", request: rp.request(opId, c[1]) } });
    });
    K.check("R. the registered RP's next request object with " + c[0] +
            " is refused too (400, STS-OIDFED-0067; " +
            "openid-federation-automatic-client-registration-invalid-*)",
    function () {
      assert.strictEqual(got.answer.status, 400,
                         got.answer.status + " " + got.answer.location);
      assert.ok(got.rose >= 1);
    });
  }
  const still = await K.send(at, { form: { client_id: rp.id,
    response_type: "code", scope: "openid", request: rp.request(opId) } });
  K.check("R. and its next good request object still goes on to sign-in",
          function () {
            assert.strictEqual(still.status, 302, still.text.slice(0, 200));
          });
  const ex = await federatedRp("explicit", anchor, fetchAt);
  const reg = K.rb(REALM) + "/oidfed/register";
  const chain = ex.chain(ex.configuration({ token_endpoint_auth_method:
                                            "private_key_jwt" },
                                          { aud: opId }));
  const wrongType = await K.coded(REALM, "STS-OIDFED-0056", function () {
    return K.send(reg, { json: chain });
  });
  const noOp = await K.send(reg, { raw: ex.configuration(),
    headers: { "Content-Type": "application/entity-statement+jwt" } });
  const otherOp = await K.send(reg, { raw: ex.configuration({},
    { aud: anchorId }), headers: { "Content-Type":
                                   "application/entity-statement+jwt" } });
  await K.set(REALM, "oidfed.clientRegistrationTypes", "automatic");
  const off = await K.send(reg, { raw: JSON.stringify(chain),
    headers: { "Content-Type": "application/trust-chain+json" } });
  await K.unset(REALM, "oidfed.clientRegistrationTypes");
  K.check("R. explicit registration refused: the wrong media type (400, " +
          "STS-OIDFED-0056), a configuration naming no OP or another one, " +
          "and a realm that does not offer it (404)", function () {
    assert.strictEqual(wrongType.answer.status, 400);
    assert.ok(wrongType.rose >= 1);
    assert.ok(noOp.status >= 400, noOp.text.slice(0, 200));
    assert.ok(otherOp.status >= 400, otherOp.text.slice(0, 200));
    assert.strictEqual(off.status, 404, off.text.slice(0, 200));
  });
  log.debug("Leaving registration().");
}

async function test() {
  log.debug("Entering test().");
  REALM = await K.realm("ofc", "development");
  const anchor = await configurationOf(K.base);
  assert.ok(anchor.parts, "no Entity Configuration at the default realm");
  await entity(anchor);
  await extensions(anchor);
  await registration(anchor);
  log.debug("Leaving test().");
}

K.main(test, 23);
