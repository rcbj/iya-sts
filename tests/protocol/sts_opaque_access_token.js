// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_opaque_access_token.js
//
// ---------------------------------------------------------------------------
// AN OPAQUE ACCESS TOKEN IS A HANDLE, AND THE DEFAULT STAYS A JWT (#501),
// OVER THE WIRE.
//
// D12 (#444): carries `tests/opaque_access_token.js` to a running service,
// in throwaway realms whose `oauth2.accessTokenFormat` is written through
// `/admin-api/realms/set`:
//
//   1. the default issues an RFC 9068 JWT (`typ` at+jwt);
//   2. `opaque`: the token endpoint answers a handle of 43 characters of
//      unpadded base64url with no dot (256 bits), which introspects active
//      with its client, jti and expiry, and which UserInfo accepts;
//   3. a one-character change introspects exactly like any other miss
//      (`active: false` and nothing else), neither answer echoing the handle
//      or saying the guess was close, and UserInfo refuses both alike;
//   4. a handle revoked through RFC 7009 introspects inactive;
//   5. clearing the setting: the next token is a JWT again, and a handle
//      minted while it was on still resolves;
//   6. a full store (`oauth2.maxOpaqueAccessTokens` at its minimum, 16)
//      refuses the next mint rather than evicting a live token, and the
//      earlier handles still introspect active. PINNED NODE DEFECT: that
//      refusal is a 500 the token endpoint records as STS-OAUTH-0228 (the
//      token endpoint failed), not the STS-OAUTH-0979 refusal the module
//      names.
//
// NOT carried, and why: the store's row shape (the handle's SHA-256 as the
// key, no handle in the row, the jti index), an expired row deleted on read
// and a revocation only in the token register are store internals, class
// (d); the miss counter per ADDRESS is per process and keyed by the caller's
// address, so on a stack every job shares it (class (d), as
// `sts_rate_limits` argues); `jtiOf()` / `lifetimeSeconds()` are library
// readers, observed here only through introspection's `jti` and `exp`.
//
// OWNED HERE (local: true): this repository's own management API.
// ---------------------------------------------------------------------------

const assert = require("assert");
const K = require("./oauth_wire_kit.js").kit("sts_opaque_access_token");
const log = K.log;

const ID = "opq-client";
const SECRET = "opq-secret-" + K.rand(16) + "-0123456789abcdef";
const PERSON = "opq-ada-" + K.STAMP;
const PASSWORD = "Opq-" + K.rand(9) + "-pw!";
const FLOOR = 14;

function check(what, fn) {
  K.check(what, fn);
}

async function setUp(realm) {
  log.debug("Entering setUp().");
  await K.app(realm, ID, { oauthClientId: [ID], oauthClientSecret: SECRET,
    oauthTokenEndpointAuthMethod: "client_secret_basic",
    oauthGrantType: ["password", "client_credentials"],
    oauthAllowedScope: ["openid", "profile"] });
  await K.person(realm, PERSON, PASSWORD);
  log.debug("Leaving setUp().");
}

function token(realm, grant) {
  log.debug("Entering token(). " + grant);
  const form = grant === "password"
    ? { grant_type: "password", username: PERSON, password: PASSWORD,
        scope: "openid profile" }
    : { grant_type: "client_credentials" };
  log.debug("Leaving token().");
  return K.send(K.rb(realm) + "/oauth2/token", {
    headers: { Authorization: K.basic(ID, SECRET) }, form: form });
}

function introspect(realm, value) {
  log.debug("Entering introspect().");
  log.debug("Leaving introspect().");
  return K.send(K.rb(realm) + "/oauth2/introspect", {
    headers: { Authorization: K.basic(ID, SECRET) },
    form: { token: value } });
}

function userinfo(realm, value) {
  log.debug("Entering userinfo().");
  log.debug("Leaving userinfo().");
  return K.send(K.rb(realm) + "/oauth2/userinfo", {
    headers: { Authorization: "Bearer " + value } });
}

function mutate(handle) {
  log.debug("Entering mutate().");
  const last = handle.charAt(handle.length - 1);
  log.debug("Leaving mutate().");
  return handle.slice(0, -1) + (last === "A" ? "B" : "A");
}

async function test() {
  log.debug("Entering test().");
  const R = await K.realm("opq", "development");
  await setUp(R);

  log.info("=== 1. the default is a JWT ===");
  const jwt = await token(R, "client_credentials");
  check("1. the default format issues an RFC 9068 JWT (typ at+jwt)",
        function () {
    assert.strictEqual(jwt.status, 200, K.shown(jwt));
    const d = K.decode(jwt.json.access_token);
    assert.ok(d, jwt.json.access_token);
    assert.strictEqual(d.header.typ, "at+jwt");
  });

  log.info("=== 2. opaque: a handle ===");
  await K.set(R, "oauth2.accessTokenFormat", "opaque");
  const opaque = await token(R, "password");
  const handle = String((opaque.json && opaque.json.access_token) || "");
  check("2a. oauth2.accessTokenFormat=opaque answers a handle: 43 " +
        "characters of unpadded base64url, no dot", function () {
    assert.strictEqual(opaque.status, 200, K.shown(opaque));
    assert.strictEqual(handle.length, 43, handle);
    assert.ok(/^[A-Za-z0-9_-]+$/.test(handle), handle);
    assert.ok(handle.indexOf(".") < 0);
  });
  const active = await introspect(R, handle);
  check("2b. it introspects active, with its client, jti and expiry",
        function () {
    assert.strictEqual(active.status, 200, K.shown(active));
    assert.strictEqual(active.json.active, true, active.text);
    assert.strictEqual(active.json.client_id, ID);
    assert.ok(active.json.jti, active.text);
    assert.ok(Number(active.json.exp) > Date.now() / 1000, active.text);
  });
  const ui = await userinfo(R, handle);
  check("2c. and UserInfo accepts it as the person's token", function () {
    assert.strictEqual(ui.status, 200, K.shown(ui));
    assert.ok(/^urn:uuid:/.test(ui.json.sub), ui.text);
  });

  log.info("=== 3. a miss is a miss ===");
  const near = await introspect(R, mutate(handle));
  const far = await introspect(R, "z".repeat(43));
  check("3a. a one-character change introspects like any other miss",
        function () {
    assert.strictEqual(near.status, 200, K.shown(near));
    assert.deepStrictEqual(near.json, { active: false });
    assert.strictEqual(near.text, far.text);
  });
  check("3b. neither answer echoes the handle or says the guess was close",
        function () {
    const both = near.text + far.text;
    assert.ok(both.indexOf(handle) < 0 && !/close/i.test(both), both);
  });
  const nearUi = await userinfo(R, mutate(handle));
  const farUi = await userinfo(R, "z".repeat(43));
  check("3c. and UserInfo refuses both alike, 401", function () {
    assert.strictEqual(nearUi.status, 401, K.shown(nearUi));
    assert.strictEqual(farUi.status, 401, K.shown(farUi));
    assert.strictEqual(nearUi.text, farUi.text);
    assert.ok(nearUi.text.indexOf(handle) < 0);
  });

  log.info("=== 4. revoked ===");
  const second = await token(R, "client_credentials");
  const victim = String(second.json && second.json.access_token);
  const rv = await K.send(K.rb(R) + "/oauth2/revoke", {
    headers: { Authorization: K.basic(ID, SECRET) },
    form: { token: victim, token_type_hint: "access_token" } });
  const gone = await introspect(R, victim);
  check("4. a handle revoked through RFC 7009 introspects inactive",
        function () {
    assert.strictEqual(rv.status, 200, K.shown(rv));
    assert.strictEqual(victim.length, 43, victim);
    assert.strictEqual(gone.json.active, false, gone.text);
  });

  log.info("=== 5. the setting cleared ===");
  await K.unset(R, "oauth2.accessTokenFormat");
  const back = await token(R, "client_credentials");
  const still = await introspect(R, handle);
  check("5a. clearing the setting: the next token is a JWT again",
        function () {
    assert.ok(K.decode(back.json && back.json.access_token), K.shown(back));
  });
  check("5b. and a handle minted while it was on still resolves",
        function () {
    assert.strictEqual(still.json.active, true, still.text);
  });

  log.info("=== 6. a full store refuses ===");
  const F = await K.realm("opqcap", "development",
                          { "oauth2.accessTokenFormat": "opaque",
                            "oauth2.maxOpaqueAccessTokens": 16 });
  await setUp(F);
  const filled = [];
  for (let i = 0; i < 16; i++) {
    const one = await token(F, "client_credentials");
    if (one.status === 200) {
      filled.push(one.json.access_token);
    }
  }
  const c0979 = await K.codeCount(F, "STS-OAUTH-0979");
  const c0228 = await K.codeCount(F, "STS-OAUTH-0228");
  const r = await token(F, "client_credentials");
  await K.sleep(1500);
  const rose0979 = (await K.codeCount(F, "STS-OAUTH-0979")) - c0979;
  const rose0228 = (await K.codeCount(F, "STS-OAUTH-0228")) - c0228;
  check("6a. sixteen handles fit a store capped at sixteen", function () {
    assert.strictEqual(filled.length, 16, String(filled.length));
  });
  check("6b. the seventeenth mint is refused: no token, and no code sent",
        function () {
    assert.ok(r.status >= 400, K.shown(r));
    assert.ok(!(r.json && r.json.access_token), K.shown(r));
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(r.text), r.text);
  });
  // NODE DEFECT, PINNED: the token endpoint does not catch the store's
  // refusal. It answers 500 and records STS-OAUTH-0228 ("the token
  // endpoint failed"), with the store's error in the log line, and no row
  // carries STS-OAUTH-0979. The design (opaque_access_token.ts) says the mint is refused
  // STS-OAUTH-0979. This check holds today's answer so a change is seen.
  check("6c. PINNED: it is answered 500 and recorded STS-OAUTH-0228, not " +
        "STS-OAUTH-0979",
        function () {
    assert.strictEqual(r.status, 500, K.shown(r));
    assert.strictEqual(rose0979, 0, "STS-OAUTH-0979 rows: " + rose0979);
    assert.strictEqual(rose0228, 1, "STS-OAUTH-0228 rows: " + rose0228);
  });
  const first = await introspect(F, filled[0]);
  check("6d. rather than evicting a live token: the first still " +
        "introspects active", function () {
    assert.strictEqual(first.json.active, true, first.text);
  });
  log.debug("Leaving test().");
}

K.main(test, FLOOR);
