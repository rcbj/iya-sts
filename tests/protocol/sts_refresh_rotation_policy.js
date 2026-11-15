// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_refresh_rotation_policy.js
//
// ---------------------------------------------------------------------------
// WHAT MAKES A REFRESH TOKEN ROTATE, AND WHOSE CHAIN IT IS (#34), OVER THE
// WIRE.
//
// D12 (#444): carries `tests/refresh_rotation_policy.js` to a running
// service, in throwaway realms of this job's own (each realm one switch), at
// `/oauth2/token`, `/oauth2/introspect` and `/oauth2/oauth21`, every code read
// off `/admin-api/audit`:
//
//   1. with neither rotation nor a mode, a refresh token is spent and still
//      works, and works again (the state OAuth 2.1 section 4.3.1 is about);
//   2. `oauth2.refreshTokenRotation` alone: a refresh hands back a NEW
//      refresh token, the one it replaced introspects inactive at once,
//      presenting it again is refused invalid_grant as a detected replay
//      (STS-OAUTH-0138) with no code on the wire, and the replay revoked the
//      whole family, so the sibling is refused too;
//   3. what does NOT come with rotation: a refresh naming no client is still
//      answered there, and in a realm with neither; in RFC 9700 mode the same
//      request is refused (STS-OAUTH-0140) — a split, not a move;
//   4. RFC 6749 section 6 in every mode: a refresh WIDENING the scope is
//      refused invalid_scope (STS-OAUTH-0142) with no mode on (#187);
//   5. OAuth 2.1 mode: a refresh naming no client at all is refused
//      invalid_client (STS-OAUTH-0297); a JWT bearer grant naming an
//      undeclared client is refused (STS-OAUTH-0299); and `/oauth2/oauth21`
//      has section 4.3.1's row, citing the draft and saying it is a choice
//      of two.
//
// NOT carried, and why: 2g–2j, the clientless SAML / JWT bearer grant
// answered with an access token and NO refresh token, need a valid
// assertion from a declared issuer — owed to the assertion-grant jobs
// (`sts_jwt_bearer_grant`, `sts_saml2_bearer_grant`, phase 5's G02 group);
// 1a/1b (`rotationRequired()` and `enabled()` as predicates) and 2c/2d are
// observed only as the answers above.
//
// OWNED HERE (local: true): realm settings of this service's own management
// API.
// ---------------------------------------------------------------------------

const assert = require("assert");
const K = require("./oauth_wire_kit.js").kit("sts_refresh_rotation_policy");
const log = K.log;

const ID = "rrp-client";
const SECRET = "rrp-secret-" + K.rand(16) + "-0123456789abcdef";
const PERSON = "rrp-alice-" + K.STAMP;
const PASSWORD = "Rrp-" + K.rand(9) + "-pw!";
const REDIRECT = "https://rp.rrp.example/cb";
const FLOOR = 15;

function check(what, fn) {
  K.check(what, fn);
}

function noCode(r) {
  log.debug("Entering noCode().");
  log.debug("Leaving noCode().");
  return !/STS-[A-Z]+-\d{4}/.test(String(r.text));
}

async function setUp(realm) {
  log.debug("Entering setUp().");
  await K.app(realm, ID, { oauthClientId: [ID], oauthClientSecret: SECRET,
    oauthTokenEndpointAuthMethod: "client_secret_post",
    oauthRedirectUri: [REDIRECT],
    oauthGrantType: ["password", "authorization_code", "refresh_token"],
    oauthAllowedScope: ["openid", "offline_access", "profile"] });
  await K.person(realm, PERSON, PASSWORD);
  log.debug("Leaving setUp().");
}

// A refresh token: by the password grant where the realm allows it, and by
// the code flow (PKCE, the sign-in screen) in the two modes, which refuse
// the password grant.
async function issue(realm, scope, byCode) {
  log.debug("Entering issue().");
  let r;
  if (byCode) {
    const b = K.browser();
    const pk = K.pkce();
    const first = await b.go(K.rb(realm) + "/oauth2/authorize?" +
      new URLSearchParams({ client_id: ID, response_type: "code",
        redirect_uri: REDIRECT, scope: scope || "openid offline_access",
        state: "s" + K.rand(3), nonce: "n" + K.rand(3),
        code_challenge: pk.challenge, code_challenge_method: "S256" }));
    const p = K.answerAt(await K.signIn(realm, b, first, PERSON, PASSWORD),
                         REDIRECT);
    r = await K.send(K.rb(realm) + "/oauth2/token", { form: {
      grant_type: "authorization_code", code: (p && p.get("code")) || "",
      redirect_uri: REDIRECT, code_verifier: pk.verifier, client_id: ID,
      client_secret: SECRET } });
  } else {
    r = await K.send(K.rb(realm) + "/oauth2/token", { form: {
      grant_type: "password", username: PERSON, password: PASSWORD,
      scope: scope || "openid offline_access", client_id: ID,
      client_secret: SECRET } });
  }
  assert.ok(r.status === 200 && r.json.refresh_token,
            realm + ": no refresh token issued: " + K.shown(r));
  log.debug("Leaving issue().");
  return r.json.refresh_token;
}

function refresh(realm, token, o) {
  log.debug("Entering refresh().");
  const opts = o || {};
  const form = { grant_type: "refresh_token", refresh_token: token,
                 scope: opts.scope };
  if (!opts.anonymous) {
    form.client_id = ID;
    form.client_secret = SECRET;
  }
  log.debug("Leaving refresh().");
  return K.send(K.rb(realm) + "/oauth2/token", { form: form });
}

async function plain(P) {
  log.debug("Entering plain().");
  log.info("=== 1. rotation off and no mode ===");
  const t = await issue(P);
  const a = await refresh(P, t);
  const b = await refresh(P, t);
  check("1a. with rotation off a refresh token is spent and still works",
        function () {
    assert.strictEqual(a.status, 200, K.shown(a));
  });
  check("1b. and works AGAIN: the state OAuth 2.1 section 4.3.1 is about",
        function () {
    assert.strictEqual(b.status, 200, K.shown(b));
  });
  const anon = await refresh(P, await issue(P), { anonymous: true });
  check("3c. a realm with neither switch refuses a refresh naming no " +
        "client nothing", function () {
    assert.strictEqual(anon.status, 200, K.shown(anon));
  });
  const wide = await K.coded(P, "STS-OAUTH-0142", async function () {
    return refresh(P, await issue(P, "openid offline_access"),
                   { scope: "openid offline_access profile" });
  });
  check("4. a refresh widening the scope is refused invalid_scope " +
        "(STS-OAUTH-0142) with no mode on — RFC 6749 section 6 (#187)",
        function () {
    assert.strictEqual(wide.answer.status, 400, K.shown(wide.answer));
    assert.strictEqual(wide.answer.json.error, "invalid_scope");
    assert.strictEqual(wide.rose, 1, "STS-OAUTH-0142 rows: " + wide.rose);
    assert.ok(noCode(wide.answer));
  });
  log.debug("Leaving plain().");
}

async function rotation(R) {
  log.debug("Entering rotation().");
  log.info("=== 2. oauth2.refreshTokenRotation alone ===");
  const first = await issue(R);
  const r = await refresh(R, first);
  const second = String((r.json && r.json.refresh_token) || "");
  check("2a. a refresh hands back a NEW refresh token", function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.ok(second && second !== first, K.shown(r));
  });
  const intro = await K.send(K.rb(R) + "/oauth2/introspect", { form: {
    token: first, token_type_hint: "refresh_token", client_id: ID,
    client_secret: SECRET } });
  check("2b. the one it replaced introspects inactive at once",
        function () {
    assert.strictEqual(intro.status, 200, K.shown(intro));
    assert.strictEqual(intro.json.active, false, intro.text);
  });
  const replay = await K.coded(R, "STS-OAUTH-0138", function () {
    return refresh(R, first);
  });
  check("2c. presenting the spent one again is refused invalid_grant, as a " +
        "detected replay (STS-OAUTH-0138), with no code on the wire",
        function () {
    assert.strictEqual(replay.answer.status, 400, K.shown(replay.answer));
    assert.strictEqual(replay.answer.json.error, "invalid_grant");
    assert.strictEqual(replay.rose, 1, "STS-OAUTH-0138 rows: " +
                       replay.rose);
    assert.ok(noCode(replay.answer));
  });
  const sibling = await refresh(R, second);
  check("2d. the replay revoked the whole family: the sibling is refused",
        function () {
    assert.strictEqual(sibling.status, 400, K.shown(sibling));
  });
  const anon = await refresh(R, await issue(R), { anonymous: true });
  check("3a. the client binding stays behind the mode: rotation alone " +
        "answers a refresh naming no client", function () {
    assert.strictEqual(anon.status, 200, K.shown(anon));
  });
  log.debug("Leaving rotation().");
}

async function mode9700(M) {
  log.debug("Entering mode9700().");
  log.info("=== 3. RFC 9700 mode ===");
  const t = await issue(M, null, true);
  const seen = await K.coded(M, "STS-OAUTH-0140", function () {
    return refresh(M, t, { anonymous: true });
  });
  check("3b. in RFC 9700 mode the same request IS refused " +
        "(STS-OAUTH-0140): a split, not a move", function () {
    assert.ok(seen.answer.status >= 400, K.shown(seen.answer));
    assert.strictEqual(seen.rose, 1, "STS-OAUTH-0140 rows: " + seen.rose +
                       " " + K.shown(seen.answer));
    assert.ok(noCode(seen.answer));
  });
  log.debug("Leaving mode9700().");
}

async function oauth21(O) {
  log.debug("Entering oauth21().");
  log.info("=== 5. OAuth 2.1 mode ===");
  const t = await issue(O, null, true);
  const seen = await K.coded(O, "STS-OAUTH-0297", function () {
    return refresh(O, t, { anonymous: true });
  });
  check("5a. a refresh naming no client at all is refused invalid_client " +
        "(STS-OAUTH-0297)", function () {
    assert.ok(seen.answer.status === 400 || seen.answer.status === 401,
              K.shown(seen.answer));
    assert.strictEqual(seen.answer.json.error, "invalid_client");
    assert.strictEqual(seen.rose, 1, "STS-OAUTH-0297 rows: " + seen.rose);
    assert.ok(noCode(seen.answer));
  });
  const now = Math.floor(Date.now() / 1000);
  const key = K.keyPair("ES256", "rrp-assert");
  const assertion = K.jws("ES256", { kid: "rrp-assert" }, {
    iss: "https://issuer.rrp.example", sub: PERSON,
    aud: K.rb(O) + "/oauth2/token", iat: now, exp: now + 120,
    jti: K.rand(8) }, key);
  const stranger = await K.coded(O, "STS-OAUTH-0299", function () {
    return K.send(K.rb(O) + "/oauth2/token", { form: {
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: assertion, client_id: "rrp-stranger-" + K.rand(3) } });
  });
  check("5b. a JWT bearer grant naming an undeclared client is refused " +
        "(STS-OAUTH-0299)", function () {
    assert.ok(stranger.answer.status >= 400, K.shown(stranger.answer));
    assert.strictEqual(stranger.rose, 1, "STS-OAUTH-0299 rows: " +
                       stranger.rose + " " + K.shown(stranger.answer));
    assert.ok(noCode(stranger.answer));
  });
  const report = await K.send(K.rb(O) + "/oauth2/oauth21");
  const row = ((report.json && report.json.requirements) || [])
    .find(function (one) {
      return one.id === "refresh-public-rotation";
    });
  check("5c. /oauth2/oauth21 has a row of its own for section 4.3.1",
        function () {
    assert.ok(row, K.shown(report));
  });
  check("5d. citing the section and the draft it is a section of",
        function () {
    assert.strictEqual(row.section, report.json.draft + " 4.3.1");
    assert.strictEqual(report.json.draft, "draft-ietf-oauth-v2-1-16");
  });
  check("5e. and saying it is a choice of two rather than a DPoP " +
        "requirement", function () {
    assert.ok(/CHOICE OF TWO/.test(row.note), row.note);
  });
  log.debug("Leaving oauth21().");
}

async function test() {
  log.debug("Entering test().");
  const P = await K.realm("rrpplain", "development");
  const R = await K.realm("rrprot", "development",
                          { "oauth2.refreshTokenRotation": true });
  const M = await K.realm("rrp9700", "development",
                          { "oauth2.rfc9700": true });
  const O = await K.realm("rrp21", "development", { "oauth2.oauth21": true });
  for (const one of [P, R, M, O]) {
    await setUp(one);
  }
  await plain(P);
  await rotation(R);
  await mode9700(M);
  await oauth21(O);
  log.debug("Leaving test().");
}

K.main(test, FLOOR);
