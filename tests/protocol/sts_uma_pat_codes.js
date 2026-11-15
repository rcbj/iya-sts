// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_uma_pat_codes.js
//
// ===========================================================================
// USER-MANAGED ACCESS 2.0: THE PAT REFUSALS AND THE CLAIMS INTERACTION
// ENDPOINT, BY CODE, OVER THE WIRE (#444 D12 phase 8; #1168, #1194).
//
// `sts_uma_codes.js` carries `uma_protection`'s, `uma_grant`'s and
// `uma_admin`'s refusals by code, less these, in a development realm with
// `uma.enabled`, the job as resource server:
//
//   P. THE PAT: a token audienced to `/uma` without `uma_protection`
//      (STS-UMA-0103); a PAT a resource server took as ITSELF while its
//      application does not own resources (0105); a PAT revoked through
//      `/oauth2/revoke` (0106); a DPoP-bound PAT sent as Bearer (0107);
//   C. THE CLAIMS INTERACTION ENDPOINT (`uma_claims`): a client it does not
//      know, or a claims_redirect_uri the client did not register (0400, a
//      400 that sends nobody anywhere); a ticket that is unknown (0407,
//      back to the registered address with `not_authorized`).
//
// OWNED HERE (local: true): UMA and the API are ours.
// ===========================================================================

const assert = require("assert");
const nodeCrypto = require("crypto");
const K = require("./oauth_wire_kit.js").kit("sts_uma_pat_codes");

const log = K.log;
const check = K.check;
const GRANT = "urn:ietf:params:oauth:grant-type:uma-ticket";
const BACK = "https://umpc-client.example/claims-back";

let realm = null;
const SECRETS = {};
let RS = "";
let RS2 = "";
let CLIENT = "";

function api(path) {
  log.debug("Entering api().");
  log.debug("Leaving api().");
  return K.rb(realm) + "/admin-api" + path;
}

async function coded(code, what, act, verdict) {
  log.debug("Entering coded(). " + code);
  const c = await K.coded(realm, code, act);
  check(what + " (" + code + ")", function () {
    (verdict || function (r) {
      assert.ok(r.status >= 400, K.shown(r));
    })(c.answer);
    assert.ok(c.rose >= 1, code + " rose " + c.rose + " " +
              K.shown(c.answer));
  });
  log.debug("Leaving coded().");
  return c.answer;
}

function tokenAs(id, form, headers) {
  log.debug("Entering tokenAs(). " + id);
  log.debug("Leaving tokenAs().");
  return K.send(K.rb(realm) + "/oauth2/token", {
    headers: Object.assign({ Authorization: K.basic(id, SECRETS[id]) },
                           headers || {}), form: form });
}

function withPat(pat, scheme) {
  log.debug("Entering withPat().");
  log.debug("Leaving withPat().");
  return K.send(K.rb(realm) + "/uma/rreg", { headers: {
    Authorization: (scheme || "Bearer") + " " + pat } });
}

function patForm() {
  log.debug("Entering patForm().");
  log.debug("Leaving patForm().");
  return { grant_type: "client_credentials", scope: "uma_protection",
           resource: K.rb(realm) + "/uma" };
}

async function setUp() {
  log.debug("Entering setUp().");
  realm = await K.realm("umpc", "development");
  await K.set(realm, "uma.enabled", true);
  RS = "umpc-rs-" + K.STAMP;
  RS2 = "umpc-rs2-" + K.STAMP;
  CLIENT = "umpc-client-" + K.STAMP;
  for (const one of [[RS, ["client_credentials"]],
                     [RS2, ["client_credentials"]], [CLIENT, [GRANT]]]) {
    SECRETS[one[0]] = "umpc-" + nodeCrypto.randomBytes(24)
      .toString("base64url");
    await K.app(realm, one[0], Object.assign({ oauthClientId: [one[0]],
      oauthClientSecret: SECRETS[one[0]], oauthGrantType: one[1],
      oauthTokenEndpointAuthMethod: "client_secret_basic" },
      one[0] === CLIENT ? { oauthClaimsRedirectUri: [BACK] } : {}),
      { protocols: ["oauth2"] });
  }
  for (const rs of [RS, RS2]) {
    await K.ok(api("/uma/enable-resource-server"), { application: rs },
               "made " + rs + " a resource server");
  }
  await K.ok(api("/uma/set-owns-resources"), { application: RS,
                                               value: "TRUE" },
             "let " + RS + " own resources");
  log.debug("Leaving setUp().");
}

async function pats() {
  log.debug("Entering pats().");
  log.info("=== P. the PAT ===");
  const unscoped = await tokenAs(RS, { grant_type: "client_credentials",
                                       resource: K.rb(realm) + "/uma" });
  assert.strictEqual(unscoped.status, 200, K.shown(unscoped));
  await coded("STS-UMA-0103", "P1. a token audienced to /uma without " +
              "uma_protection is refused", function () {
    return withPat(unscoped.json.access_token);
  });
  const itself = await tokenAs(RS2, patForm());
  log.info("the PAT of a resource server owning nothing answered " +
           itself.status);
  if (itself.status === 200) {
    await coded("STS-UMA-0105", "P2. a PAT taken as ITSELF by a resource " +
                "server whose application does not own resources is refused",
                function () {
      return withPat(itself.json.access_token);
    });
  }
  const pat = await tokenAs(RS, patForm());
  assert.strictEqual(pat.status, 200, K.shown(pat));
  const live = await withPat(pat.json.access_token);
  check("P3. the PAT is accepted before it is revoked", function () {
    assert.strictEqual(live.status, 200, K.shown(live));
  });
  const revoked = await K.send(K.rb(realm) + "/oauth2/revoke", {
    headers: { Authorization: K.basic(RS, SECRETS[RS]) },
    form: { token: pat.json.access_token } });
  assert.strictEqual(revoked.status, 200, K.shown(revoked));
  await coded("STS-UMA-0106", "P4. a revoked PAT is refused", function () {
    return withPat(pat.json.access_token);
  });
  const key = K.keyPair("ES256");
  const htu = K.rb(realm) + "/oauth2/token";
  const bound = await tokenAs(RS, patForm(),
                              { DPoP: K.dpop(key, "POST", htu) });
  check("P5. a PAT asked with a DPoP proof is DPoP-bound", function () {
    assert.strictEqual(bound.status, 200, K.shown(bound));
    assert.strictEqual(String(bound.json.token_type).toLowerCase(), "dpop",
                       K.shown(bound));
  });
  await coded("STS-UMA-0107", "P6. a DPoP-bound PAT sent as Bearer is " +
              "refused", function () {
    return withPat(bound.json.access_token);
  });
  log.debug("Leaving pats().");
}

async function claims() {
  log.debug("Entering claims().");
  log.info("=== C. the claims interaction endpoint ===");
  const at = function (query) {
    return K.send(K.rb(realm) + "/uma/claims?" +
                  new URLSearchParams(query).toString());
  };
  await coded("STS-UMA-0400", "C1. a client it does not know is a 400 " +
              "that sends nobody anywhere", function () {
    return at({ client_id: "umpc-nobody", claims_redirect_uri: BACK,
                ticket: "x", state: "s" });
  }, function (r) {
    assert.strictEqual(r.status, 400, K.shown(r));
    assert.strictEqual(r.location, "");
  });
  await coded("STS-UMA-0400", "C2. and so is an address the client did " +
              "not register", function () {
    return at({ client_id: CLIENT,
                claims_redirect_uri: "https://elsewhere.example/cb",
                ticket: "x", state: "s" });
  }, function (r) {
    assert.strictEqual(r.status, 400, K.shown(r));
  });
  await coded("STS-UMA-0407", "C3. an unknown ticket goes back to the " +
              "registered address, not_authorized", function () {
    return at({ client_id: CLIENT, claims_redirect_uri: BACK,
                ticket: "umpc-no-such-ticket", state: "s-1" });
  }, function (r) {
    assert.strictEqual(r.status, 302, K.shown(r));
    assert.ok(r.location.indexOf(BACK) === 0 &&
              /authorization_state=not_authorized/.test(r.location) &&
              /state=s-1/.test(r.location), r.location);
  });
  log.debug("Leaving claims().");
}

async function test() {
  log.debug("Entering test().");
  await setUp();
  await pats();
  await claims();
  log.debug("Leaving test().");
}

K.main(test, 9);
