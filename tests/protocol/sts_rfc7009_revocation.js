// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_rfc7009_revocation.js
//
// ===========================================================================
// RFC 7009 TOKEN REVOCATION IN BOTH MODES, OVER THE WIRE (#102; D12, #444).
//
// `sts_token_revocation.js` asserts the endpoint in whichever mode the
// service runs. This job carries `tests/rfc7009_revocation.js` — which held
// BOTH modes in one child process — onto a running service: one throwaway
// realm, every token minted while it is in development (the password grant
// is development's), then the realm switched to product through the root
// API's `realms/set`, exactly as the child switched `global.mode`:
//
//   1. `/admin-api/mode`'s `revocation` row describes both modes, the
//      refusals and where the rule lives;
//   2. development: an anonymous caller revokes; a presented secret that
//      fails is 401 invalid_client and revokes nothing, with the Basic
//      challenge for a Basic credential; another client's token is
//      invalid_grant and stays active; an unregistered client_id with a
//      secret goes on unidentified and revokes; an ID Token is
//      unsupported_token_type; no token is invalid_request; an unknown hint
//      is ignored; an invalid token is 200; and a refresh token in a chain
//      that does not rotate takes the refresh token it came from and both
//      access tokens with it;
//   3. discovery: revocation's auth methods are introspection's, `none` and
//      `client_secret_jwt` included;
//   4. product: no credential and a wrong secret are 401 and revoke
//      nothing; another client's token is invalid_grant with an audit row
//      STS-OAUTH-0612 naming the caller and the owner; an access token is
//      revoked alone (its refresh token stays); a public client revokes its
//      own with its client_id alone and is refused another's; an unknown
//      client_id is 401 with or without a secret; the token-type,
//      missing-token and hint rows; a ROTATING chain's refresh token takes
//      every access token of the grant; and a named authorization server
//      advertising only private_key_jwt refuses a client_secret_post client
//      before its secret is read, and its document says so.
//
// NOT CARRIED: `mode.opensRevocation()` as a function (class (d); the row
// in section 1 is what a caller can read). Codes come off `/admin-api/audit`.
//
// OWNED HERE (local: true): this repository's own authorization server.
// ===========================================================================

const assert = require("assert");
const K = require("./oauth_wire_kit.js").kit("sts_rfc7009_revocation");
const log = K.log;

const SECRET_A = "r79-client-a-secret-" + K.rand(8);
const SECRET_B = "r79-client-b-secret-" + K.rand(8);
const ALICE = "r79-alice-" + K.STAMP;

async function test() {
  log.debug("Entering test().");
  const id = await K.realm("r79", "development");
  const R = K.rb(id);

  log.info("=== 1. /admin-api/mode ===");
  const mode = await K.send(R + "/admin-api/mode");
  const row = ((mode.json && mode.json.requirements) || []).filter(
    function (one) {
      return one.id === "revocation";
    })[0];
  K.check("1. the mode page's revocation row describes both modes, the " +
          "refusals and where", function () {
    assert.ok(row, mode.text.slice(0, 300));
    assert.ok(/invalid_grant/.test(row.product), JSON.stringify(row));
    assert.ok(/401 invalid_client/.test(row.development),
              JSON.stringify(row));
    assert.ok(/oauth2\.ts/.test(row.where), JSON.stringify(row));
  });

  const confidential = function (client, secret) {
    log.debug("Entering confidential().");
    log.debug("Leaving confidential().");
    return K.app(id, client, { oauthClientId: [client],
      oauthClientSecret: secret,
      oauthTokenEndpointAuthMethod: "client_secret_post",
      oauthAllowedScope: ["openid", "offline_access"],
      oauthGrantType: ["password", "refresh_token",
                       "client_credentials"] });
  };
  await confidential("r79-a", SECRET_A);
  await confidential("r79-b", SECRET_B);
  await K.app(id, "r79-pub", { oauthClientId: ["r79-pub"],
    oauthTokenEndpointAuthMethod: "none",
    oauthAllowedScope: ["openid", "offline_access"],
    oauthGrantType: ["password", "refresh_token"] });
  await K.person(id, ALICE, "Alice-" + K.rand(6) + "-pw!");

  const A = { client_id: "r79-a", client_secret: SECRET_A };
  const B = { client_id: "r79-b", client_secret: SECRET_B };
  const PUB = { client_id: "r79-pub" };
  const WRONG_A = { client_id: "r79-a", client_secret: "not-the-secret" };
  const basicWrong = K.basic("r79-a", "not-the-secret");

  const grant = async function (client) {
    log.debug("Entering grant().");
    const got = await K.send(R + "/oauth2/token", { form: Object.assign({
      grant_type: "password", username: ALICE, password: "anything",
      scope: "openid offline_access" }, client) });
    log.debug("Leaving grant(). " + got.status);
    return got.json || {};
  };
  const refresh = function (client, token) {
    log.debug("Entering refresh().");
    log.debug("Leaving refresh().");
    return K.send(R + "/oauth2/token", { form: Object.assign({
      grant_type: "refresh_token", refresh_token: token }, client) });
  };
  const revoke = function (form, headers, path) {
    log.debug("Entering revoke().");
    log.debug("Leaving revoke().");
    return K.send(R + (path || "/oauth2/revoke"),
                  { form: form, headers: headers || {} });
  };
  const active = async function (token, client) {
    log.debug("Entering active().");
    const r = await K.send(R + "/oauth2/introspect", {
      form: Object.assign({ token: token }, client || A) });
    log.debug("Leaving active().");
    return r.status === 200 && r.json && r.json.active === true;
  };
  const usable = async function (token) {
    log.debug("Entering usable().");
    const r = await K.send(R + "/oauth2/userinfo",
                           { headers: { authorization: "Bearer " + token } });
    log.debug("Leaving usable().");
    return r.status === 200;
  };

  log.info("=== 2. development ===");
  const d1 = await grant(A);
  K.check("2a. (a control: the password grant issues an access token, a " +
          "refresh token and an ID Token)", function () {
    assert.ok(d1.access_token && d1.refresh_token && d1.id_token,
              JSON.stringify(Object.keys(d1)));
  });
  const d2 = await grant(A);
  const d3 = await grant(A);
  const p1 = await grant(A);
  const p2 = await grant(A);
  const p3 = await grant(A);
  const pPub = await grant(PUB);
  const pPub2 = await grant(PUB);
  K.check("2a. (a control: every set was issued)", function () {
    [d2, d3, p1, p2, p3, pPub, pPub2].forEach(function (one) {
      assert.ok(one.access_token && one.refresh_token,
                JSON.stringify(one).slice(0, 200));
    });
  });

  let r = await revoke({ token: d1.access_token });
  const d1Gone = !(await active(d1.access_token));
  K.check("2b. development: an anonymous caller still revokes an access " +
          "token", function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.ok(d1Gone);
  });
  r = await revoke(Object.assign({ token: d2.access_token }, WRONG_A));
  let still = await active(d2.access_token);
  K.check("2c. development: a presented secret that does not verify is " +
          "401 invalid_client, and nothing is revoked", function () {
    assert.strictEqual(r.status, 401, K.shown(r));
    assert.strictEqual(r.json.error, "invalid_client");
    assert.ok(still);
  });
  r = await revoke({ token: d2.access_token },
                   { authorization: basicWrong });
  K.check("2d. and a wrong Basic credential gets the challenge", function () {
    assert.strictEqual(r.status, 401, K.shown(r));
    assert.ok(/^Basic realm=/.test(String(r.headers.get("www-authenticate")
                                          || "")),
              String(r.headers.get("www-authenticate")));
  });
  r = await revoke(Object.assign({ token: d2.access_token }, B));
  still = await active(d2.access_token);
  K.check("2e. development: an authenticated client revoking another " +
          "client's token is refused invalid_grant, and it stays active",
          function () {
    assert.strictEqual(r.status, 400, K.shown(r));
    assert.strictEqual(r.json.error, "invalid_grant");
    assert.ok(still);
  });
  r = await revoke({ token: d2.access_token, client_id: "r79-nobody",
                     client_secret: "whatever" });
  still = await active(d2.access_token);
  K.check("2f. development: an unregistered client_id has nothing to fail " +
          "against, so it goes on unidentified and revokes", function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.ok(!still);
  });
  r = await revoke({ token: d1.id_token });
  K.check("2g. development: an ID Token is unsupported_token_type",
          function () {
    assert.strictEqual(r.status, 400, K.shown(r));
    assert.strictEqual(r.json.error, "unsupported_token_type");
  });
  r = await revoke({});
  K.check("2h. development: a request with no token is invalid_request",
          function () {
    assert.strictEqual(r.status, 400, K.shown(r));
    assert.strictEqual(r.json.error, "invalid_request");
    assert.ok(/REQUIRED/.test(r.json.error_description || ""), K.shown(r));
  });
  r = await revoke(Object.assign({ token: d3.access_token,
                                   token_type_hint: "no_such_hint" }, A));
  still = await active(d3.access_token);
  K.check("2i. development: an unknown token_type_hint is ignored, not " +
          "refused (RFC 7009 section 2.1)", function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.ok(!still);
  });
  r = await revoke({ token: "not-a-token" });
  K.check("2j. an invalid token is still 200 (section 2.2)", function () {
    assert.strictEqual(r.status, 200, K.shown(r));
  });

  const chain = await grant(A);
  const second = await refresh(A, chain.refresh_token);
  const next = second.json || {};
  still = await active(chain.refresh_token);
  K.check("2k. (a control: a refresh outside RFC 9700 mode leaves the " +
          "first refresh token working)", function () {
    assert.strictEqual(second.status, 200, K.shown(second));
    assert.ok(next.access_token && next.refresh_token && still);
  });
  r = await revoke(Object.assign({ token: next.refresh_token,
                                   token_type_hint: "refresh_token" }, A));
  const gone = [await active(chain.access_token),
                await active(chain.refresh_token),
                await active(next.access_token),
                await active(next.refresh_token)];
  K.check("2l. revoking a refresh token revokes its grant: the refresh " +
          "token it came from and both access tokens (section 2.1)",
          function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.strictEqual(gone.join(","), "false,false,false,false");
  });
  const redeemed = await refresh(A, chain.refresh_token);
  K.check("2m. and the first refresh token no longer refreshes", function () {
    assert.strictEqual(redeemed.status, 400, K.shown(redeemed));
    assert.strictEqual(redeemed.json.error, "invalid_grant");
  });

  log.info("=== 3. discovery ===");
  const meta = (await K.send(R + "/.well-known/oauth-authorization-server"))
    .json || {};
  K.check("3a. revocation_endpoint_auth_methods_supported is " +
          "introspection's list, none and client_secret_jwt included",
          function () {
    const listed = meta.revocation_endpoint_auth_methods_supported || [];
    assert.deepStrictEqual(listed,
      meta.introspection_endpoint_auth_methods_supported);
    assert.ok(listed.indexOf("none") >= 0, JSON.stringify(listed));
    assert.ok(listed.indexOf("client_secret_jwt") >= 0,
              JSON.stringify(listed));
  });

  log.info("=== 4. product ===");
  await K.set(id, "global.mode", "product");
  r = await revoke({ token: p1.access_token });
  still = await active(p1.access_token);
  K.check("4a. product: no credential is 401 invalid_client and revokes " +
          "nothing", function () {
    assert.strictEqual(r.status, 401, K.shown(r));
    assert.strictEqual(r.json.error, "invalid_client");
    assert.ok(still);
  });
  r = await revoke({ token: p1.access_token },
                   { authorization: basicWrong });
  still = await active(p1.access_token);
  K.check("4b. product: a wrong secret is 401 with the Basic challenge",
          function () {
    assert.strictEqual(r.status, 401, K.shown(r));
    assert.strictEqual(r.json.error, "invalid_client");
    assert.ok(/^Basic realm=/.test(String(r.headers.get("www-authenticate")
                                          || "")));
    assert.ok(still);
  });
  const before0612 = await K.codeCount(id, "STS-OAUTH-0612");
  r = await revoke(Object.assign({ token: p1.access_token }, B));
  still = await active(p1.access_token);
  K.check("4c. product: another client's token is invalid_grant and stays " +
          "active", function () {
    assert.strictEqual(r.status, 400, K.shown(r));
    assert.strictEqual(r.json.error, "invalid_grant");
    assert.ok(still);
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(r.text), r.text);
  });
  await K.codeAfter(id, "STS-OAUTH-0612", before0612);
  const rows = await K.send(R + "/admin-api/audit?per=50&code=" +
                            "STS-OAUTH-0612");
  const listedRows = (rows.json && (rows.json.rows || rows.json.entries ||
                                    rows.json.events)) || [];
  // The request's own protocol.call row carries the code too; the
  // revocation's row is the one that names the two clients.
  const recorded = listedRows.filter(function (one) {
    return one.action === "oauth.token.revoke";
  })[0];
  K.check("4d. the audit row STS-OAUTH-0612 names the caller and the owner",
          function () {
    assert.ok(Number(rows.json && rows.json.matched) > before0612,
              rows.text.slice(0, 300));
    assert.ok(recorded, JSON.stringify(listedRows).slice(0, 600));
    const text = JSON.stringify(recorded);
    assert.strictEqual(recorded.actor, "r79-b", text.slice(0, 600));
    assert.ok(/r79-a/.test(text), text.slice(0, 600));
  });
  r = await revoke(Object.assign({ token: p1.access_token }, A));
  const p1Access = await active(p1.access_token);
  const p1Refresh = await active(p1.refresh_token);
  K.check("4e. product: a client revokes its own access token — and only " +
          "that token, its refresh token stays", function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.ok(!p1Access && p1Refresh, p1Access + " " + p1Refresh);
  });
  const usableBefore = await usable(pPub.access_token);
  r = await revoke(Object.assign({ token: pPub.access_token }, PUB));
  const usableAfter = await usable(pPub.access_token);
  K.check("4f. product: a PUBLIC client revokes its own token with its " +
          "client_id alone", function () {
    assert.ok(usableBefore, "the public client's token was not usable");
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.ok(!usableAfter);
  });
  r = await revoke(Object.assign({ token: p2.access_token }, PUB));
  still = await active(p2.access_token);
  K.check("4g. and is refused another client's", function () {
    assert.strictEqual(r.status, 400, K.shown(r));
    assert.strictEqual(r.json.error, "invalid_grant");
    assert.ok(still);
  });
  r = await revoke({ token: p2.access_token, client_id: "r79-nobody" });
  K.check("4h. product: a client_id nobody registered is 401", function () {
    assert.strictEqual(r.status, 401, K.shown(r));
    assert.strictEqual(r.json.error, "invalid_client");
  });
  r = await revoke({ token: pPub2.access_token, client_id: "r79-nobody",
                     client_secret: "whatever" });
  still = await usable(pPub2.access_token);
  K.check("4i. and so is one presenting a secret, which development let " +
          "through unidentified", function () {
    assert.strictEqual(r.status, 401, K.shown(r));
    assert.ok(still);
  });
  r = await revoke(Object.assign({ token: p2.id_token }, A));
  K.check("4j. product: an ID Token is unsupported_token_type", function () {
    assert.strictEqual(r.status, 400, K.shown(r));
    assert.strictEqual(r.json.error, "unsupported_token_type");
  });
  r = await revoke(Object.assign({}, A));
  K.check("4k. product: no token is invalid_request", function () {
    assert.strictEqual(r.status, 400, K.shown(r));
    assert.strictEqual(r.json.error, "invalid_request");
  });
  r = await revoke(Object.assign({ token: p2.access_token,
                                   token_type_hint: "urn:example:x" }, A));
  still = await active(p2.access_token);
  K.check("4l. product: an unknown hint is ignored", function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.ok(!still);
  });

  const rotated = await refresh(A, p3.refresh_token);
  const q = rotated.json || {};
  still = await active(p3.refresh_token);
  K.check("4m. (a control: in product the refresh rotates, retiring the " +
          "presented token)", function () {
    assert.strictEqual(rotated.status, 200, K.shown(rotated));
    assert.ok(q.refresh_token && !still);
  });
  r = await revoke(Object.assign({ token: q.refresh_token }, A));
  const after = [await active(p3.access_token),
                 await active(q.access_token),
                 await active(q.refresh_token)];
  K.check("4n. product: revoking the rotated chain's refresh token revokes " +
          "every access token of the grant", function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.strictEqual(after.join(","), "false,false,false");
  });
  const again = await refresh(A, q.refresh_token);
  K.check("4o. and the refresh token is refused at the token endpoint",
          function () {
    assert.strictEqual(again.status, 400, K.shown(again));
    assert.strictEqual(again.json.error, "invalid_grant");
  });

  await K.ok(R + "/admin-api/authorization-servers/create",
             { id: "r79narrow", label: "Narrow revocation" },
             "created a named authorization server");
  await K.ok(R + "/admin-api/authorization-servers/set",
             { id: "r79narrow",
               member: "revocation_endpoint_auth_methods_supported",
               value: "[\"private_key_jwt\"]" },
             "narrowed its revocation auth methods");
  r = await revoke(Object.assign({ token: p2.refresh_token }, A), {},
                   "/r79narrow/oauth2/revoke");
  still = await active(p2.refresh_token);
  K.check("4p. a profile advertising only private_key_jwt refuses a " +
          "client_secret_post client before its secret is read",
          function () {
    assert.strictEqual(r.status, 401, K.shown(r));
    assert.strictEqual(r.json.error, "invalid_client");
    assert.ok(/private_key_jwt/.test(r.json.error_description || ""),
              K.shown(r));
    assert.ok(still);
  });
  const narrowed = (await K.send(R +
    "/.well-known/oauth-authorization-server/r79narrow")).json || {};
  K.check("4q. and its document says so", function () {
    assert.deepStrictEqual(
      narrowed.revocation_endpoint_auth_methods_supported,
      ["private_key_jwt"]);
  });
  K.check("4r. (a control: the tokens name their client)", function () {
    assert.strictEqual(K.decode(p2.access_token).payload.client_id, "r79-a");
  });
  log.debug("Leaving test().");
}

K.main(test, 34);
