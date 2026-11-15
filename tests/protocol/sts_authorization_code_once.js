// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_authorization_code_once.js
//
// ---------------------------------------------------------------------------
// AN AUTHORIZATION CODE IS PRESENTED ONCE, WHATEVER THE OUTCOME, AND LIVES AT
// MOST FIVE MINUTES (#424), OVER THE WIRE.
//
// D12 (#444): carries `tests/authorization_code_once.js` to a running
// service. Codes come from real authorization requests by a confidential
// client, signed in through the sign-in screen (`authn_signin.js`), in
// throwaway realms of this job's own; every code is read off
// `/admin-api/audit` (a code is recorded, never sent):
//
//   1. a failed client authentication — in an RFC 9700 realm, which verifies
//      a confidential client's secret — then the CORRECT second
//      presentation refused invalid_grant "already presented"
//      (STS-OAUTH-0789);
//   2.–4. the same after a redirect_uri mismatch, a wrong PKCE verifier and
//      a body that fails validation (a verifier too short);
//   5. a code past its lifetime: the realm's `oauth2.authorizationCodeTtlS`
//      lowered to its floor (30 s) and waited out — refused as expired, then
//      as presented;
//   6. a successful redemption whose identical repeat is refused as single
//      use and revokes the access token it bought (RFC 6749 section 10.5);
//      a DIFFERING repeat the same; and an access token refreshed from a
//      replayed code revoked too (#1489);
//   7. two presentations at the same moment: exactly one is answered 200;
//   8. the lifetime's row: 300 by default, 300 accepted, 301 refused;
//   9. `oauth2.codeReplayIdempotent` on in a realm: a refused presentation
//      leaves the code redeemable, an identical repeat gets the same tokens,
//      and a code redeemed while it was off has nothing to replay
//      (STS-OAUTH-0958).
//
// NOT carried, and why: 6f (the revocation observer's `replay` reason — what
// sends the grant's CAEP signals) is an in-process slot, owed to the Shared
// Signals family's jobs, which see the SET; 10 (the two code stores keyed by
// the code's digest, the jtis kept and the tokens not) is the store's shape,
// class (d). The moved clock of 5 is replaced by the setting's floor.
//
// OWNED HERE (local: true): codes, settings and realms of this service's own
// management API.
// ---------------------------------------------------------------------------

const assert = require("assert");
const K = require("./oauth_wire_kit.js").kit("sts_authorization_code_once");
const log = K.log;

const ID = "aco-rp";
const SECRET = "aco-secret-" + K.rand(16) + "-0123456789abcdef";
const REDIRECT = "https://rp.aco.example/cb";
const PERSON = "aco-alice-" + K.STAMP;
const PASSWORD = "Aco-" + K.rand(9) + "-pw!";
const FLOOR = 24;

function check(what, fn) {
  K.check(what, fn);
}

async function client(realm) {
  log.debug("Entering client().");
  await K.app(realm, ID, { oauthClientId: [ID], oauthClientSecret: SECRET,
    oauthRedirectUri: [REDIRECT],
    oauthTokenEndpointAuthMethod: "client_secret_basic",
    oauthGrantType: ["authorization_code", "refresh_token"],
    oauthAllowedScope: ["openid", "offline_access"] });
  await K.person(realm, PERSON, PASSWORD);
  log.debug("Leaving client().");
}

// A FRESH CODE from a real authorization request; the first signs in through
// the screen and the rest ride that browser's session.
async function newCode(realm, b, verifier) {
  log.debug("Entering newCode().");
  const q = { client_id: ID, response_type: "code", redirect_uri: REDIRECT,
              scope: "openid offline_access", state: "st-" + K.rand(3),
              nonce: "n-" + K.rand(4) };
  if (verifier) {
    q.code_challenge = require("crypto").createHash("sha256")
      .update(verifier).digest("base64url");
    q.code_challenge_method = "S256";
  }
  const first = await b.go(K.rb(realm) + "/oauth2/authorize?" +
                           new URLSearchParams(q));
  const r = await K.signIn(realm, b, first, PERSON, PASSWORD);
  const p = K.answerAt(r, REDIRECT);
  const code = (p && p.get("code")) || "";
  assert.ok(code, "no code from the authorization request: " + K.shown(r));
  log.debug("Leaving newCode().");
  return code;
}

function redeem(realm, code, o) {
  log.debug("Entering redeem().");
  const opts = o || {};
  log.debug("Leaving redeem().");
  return K.send(K.rb(realm) + "/oauth2/token", {
    headers: { Authorization: K.basic(ID, opts.secret || SECRET) },
    form: Object.assign({ grant_type: "authorization_code", code: code,
                          redirect_uri: REDIRECT }, opts.form || {}) });
}

function introspect(realm, token) {
  log.debug("Entering introspect().");
  log.debug("Leaving introspect().");
  return K.send(K.rb(realm) + "/oauth2/introspect", {
    headers: { Authorization: K.basic(ID, SECRET) },
    form: { token: token || "" } });
}

// The second presentation, correct this time, after a failed first.
async function refusedAfter(realm, label, code, first, extra) {
  log.debug("Entering refusedAfter(). " + label);
  const seen = await K.coded(realm, "STS-OAUTH-0789", function () {
    return redeem(realm, code, extra);
  });
  const second = seen.answer;
  check(label + ": the first presentation is refused", function () {
    assert.ok(first.status >= 400, K.shown(first));
  });
  check(label + ": the correct second presentation is refused " +
        "invalid_grant, already presented (STS-OAUTH-0789) — the flow " +
        "must start over", function () {
    assert.strictEqual(second.status, 400, K.shown(second));
    assert.strictEqual(second.json.error, "invalid_grant");
    assert.ok(/already presented/.test(second.json.error_description),
              second.text);
    assert.strictEqual(seen.rose, 1, "STS-OAUTH-0789 rows: " + seen.rose);
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(second.text), second.text);
  });
  log.debug("Leaving refusedAfter().");
}

async function failures(D, R9700) {
  log.debug("Entering failures().");
  log.info("=== 1. a failed client authentication (RFC 9700 realm) ===");
  const b9 = K.browser();
  const v1 = K.pkce().verifier;
  let code = await newCode(R9700, b9, v1);
  const wrong = await redeem(R9700, code, { secret: "wrong-secret-" +
    K.rand(8), form: { code_verifier: v1 } });
  check("1. the wrong secret is refused invalid_client — the mode verifies " +
        "it", function () {
    assert.strictEqual(wrong.json && wrong.json.error, "invalid_client",
                       K.shown(wrong));
  });
  await refusedAfter(R9700, "1. failed client authentication", code, wrong,
    { form: { code_verifier: v1 } });

  const b = K.browser();
  log.info("=== 2. a redirect_uri that does not match ===");
  code = await newCode(D, b);
  await refusedAfter(D, "2. redirect_uri mismatch", code,
    await redeem(D, code, { form: { redirect_uri:
                                    "https://rp.aco.example/x" } }));

  log.info("=== 3. a wrong PKCE code_verifier ===");
  const verifier = K.pkce().verifier;
  code = await newCode(D, b, verifier);
  await refusedAfter(D, "3. wrong code_verifier", code,
    await redeem(D, code, { form: { code_verifier: K.pkce().verifier } }),
    { form: { code_verifier: verifier } });

  log.info("=== 4. a body that fails validation ===");
  code = await newCode(D, b, verifier);
  await refusedAfter(D, "4. malformed body (a verifier too short)", code,
    await redeem(D, code, { form: { code_verifier: "short" } }),
    { form: { code_verifier: verifier } });
  log.debug("Leaving failures().");
}

async function lifetime(E) {
  log.debug("Entering lifetime().");
  log.info("=== 5. past its lifetime (30 s, waited out) ===");
  await K.set(E, "oauth2.authorizationCodeTtlS", 30);
  const b = K.browser();
  const code = await newCode(E, b);
  await K.sleep(31500);
  const r = await redeem(E, code);
  check("5a. a code presented after its lifetime is refused as expired",
        function () {
    assert.strictEqual(r.status, 400, K.shown(r));
    assert.strictEqual(r.json.error, "invalid_grant");
    assert.ok(/expired/.test(r.text), r.text);
  });
  await refusedAfter(E, "5b. after the expired presentation", code, r);
  log.debug("Leaving lifetime().");
}

async function redeemed(D) {
  log.debug("Entering redeemed().");
  log.info("=== 6. a successful redemption, then a repeat ===");
  const b = K.browser();
  let code = await newCode(D, b);
  const ok = await redeem(D, code);
  check("6a. a correct first presentation is redeemed", function () {
    assert.strictEqual(ok.status, 200, K.shown(ok));
    assert.ok(ok.json.access_token);
  });
  const replay = await redeem(D, code);
  check("6b. its identical repeat is refused invalid_grant (single use)",
        function () {
    assert.strictEqual(replay.status, 400, K.shown(replay));
    assert.strictEqual(replay.json.error, "invalid_grant");
    assert.ok(/single use/.test(replay.json.error_description),
              replay.text);
  });
  const intro = await introspect(D, ok.json.access_token);
  check("6c. and the access token the first bought is revoked (RFC 6749 " +
        "section 10.5)", function () {
    assert.strictEqual(intro.status, 200, K.shown(intro));
    assert.strictEqual(intro.json.active, false, intro.text);
  });

  code = await newCode(D, b);
  const ok2 = await redeem(D, code);
  const differing = await redeem(D, code, { form: { redirect_uri:
                                            "https://rp.aco.example/x" } });
  const intro2 = await introspect(D, ok2.json && ok2.json.access_token);
  check("6d. a repeat that DIFFERS is refused as single use and revokes " +
        "what the first bought", function () {
    assert.strictEqual(ok2.status, 200, K.shown(ok2));
    assert.strictEqual(differing.status, 400, K.shown(differing));
    assert.ok(/single use/.test(differing.text), differing.text);
    assert.strictEqual(intro2.json.active, false, intro2.text);
  });

  code = await newCode(D, b);
  const firstSet = await redeem(D, code);
  const refreshed = await K.send(K.rb(D) + "/oauth2/token", {
    headers: { Authorization: K.basic(ID, SECRET) },
    form: { grant_type: "refresh_token",
            refresh_token: (firstSet.json && firstSet.json.refresh_token) ||
                           "" } });
  await redeem(D, code);
  const intro3 = await introspect(D, refreshed.json &&
                                     refreshed.json.access_token);
  check("6e. an access token REFRESHED from a replayed code is revoked " +
        "too (#1489)", function () {
    assert.ok(firstSet.json && firstSet.json.refresh_token,
              K.shown(firstSet));
    assert.strictEqual(refreshed.status, 200, K.shown(refreshed));
    assert.strictEqual(intro3.json.active, false, intro3.text);
  });
  const replays = await K.codeCount(D, "STS-OAUTH-0143");
  check("6f. the single-use refusals are on the audit log (STS-OAUTH-0143)",
        function () {
    assert.ok(replays >= 3, "STS-OAUTH-0143 rows: " + replays);
  });

  log.info("=== 7. two presentations at once ===");
  code = await newCode(D, b);
  const both = await Promise.all([redeem(D, code), redeem(D, code)]);
  check("7. two presentations at the same moment: exactly one is " +
        "redeemed and the other refused", function () {
    const wins = both.filter(function (one) {
      return one.status === 200;
    });
    const lost = both.filter(function (one) {
      return one.status === 400;
    });
    assert.ok(wins.length === 1 && lost.length === 1,
              both.map(K.shown).join(" | "));
  });
  log.debug("Leaving redeemed().");
}

async function setting(D) {
  log.debug("Entering setting().");
  log.info("=== 8. the lifetime ===");
  const cfg = await K.send(K.rb(D) + "/admin-api/config");
  let row = null;
  ((cfg.json && cfg.json.groups) || []).forEach(function (g) {
    (g.settings || []).forEach(function (one) {
      if (one.key === "oauth2.authorizationCodeTtlS") {
        row = one;
      }
    });
  });
  check("8a. the default lifetime is 300 seconds", function () {
    assert.ok(row, "no oauth2.authorizationCodeTtlS row");
    assert.strictEqual(Number(row.value), 300, JSON.stringify(row));
  });
  const at = await K.send(K.base + "/admin-api/realms/set", { json: {
    id: D, key: "oauth2.authorizationCodeTtlS", value: "300" } });
  const over = await K.send(K.base + "/admin-api/realms/set", { json: {
    id: D, key: "oauth2.authorizationCodeTtlS", value: "301" } });
  check("8b. 300 may be set", function () {
    assert.ok(at.status === 200 && at.json.ok !== false, K.shown(at));
  });
  check("8c. 301 is refused: at most five minutes", function () {
    assert.ok(over.status >= 400 || (over.json && over.json.ok === false),
              K.shown(over));
  });
  await K.unset(D, "oauth2.authorizationCodeTtlS");
  log.debug("Leaving setting().");
}

async function idempotent(I) {
  log.debug("Entering idempotent().");
  log.info("=== 9. oauth2.codeReplayIdempotent: the control ===");
  const b = K.browser();
  const before = await newCode(I, b);
  const spent = await redeem(I, before);
  await K.set(I, "oauth2.codeReplayIdempotent", true);
  const code = await newCode(I, b);
  const bad = await redeem(I, code, { form: { redirect_uri:
                                      "https://rp.aco.example/x" } });
  const then = await redeem(I, code);
  check("9a. on: a refused presentation leaves the code redeemable",
        function () {
    assert.strictEqual(bad.status, 400, K.shown(bad));
    assert.strictEqual(then.status, 200, K.shown(then));
  });
  const again = await redeem(I, code);
  check("9b. and an identical repeat gets the same tokens", function () {
    assert.strictEqual(again.status, 200, K.shown(again));
    assert.strictEqual(again.json.access_token, then.json.access_token);
  });
  const seen = await K.coded(I, "STS-OAUTH-0958", function () {
    return redeem(I, before);
  });
  check("9c. a code redeemed while the setting was off has nothing to " +
        "replay, and is refused (STS-OAUTH-0958)", function () {
    assert.strictEqual(spent.status, 200, K.shown(spent));
    const r = seen.answer;
    assert.strictEqual(r.status, 400, K.shown(r));
    assert.strictEqual(r.json.error, "invalid_grant");
    assert.ok(/no token response was kept/.test(r.text), r.text);
    assert.strictEqual(seen.rose, 1, "STS-OAUTH-0958 rows: " + seen.rose);
  });
  await K.unset(I, "oauth2.codeReplayIdempotent");
  log.debug("Leaving idempotent().");
}

async function test() {
  log.debug("Entering test().");
  const D = await K.realm("aco", "development");
  const R9700 = await K.realm("aco9700", "development",
                              { "oauth2.rfc9700": true });
  const E = await K.realm("acottl", "development");
  const I = await K.realm("acoidem", "development");
  for (const one of [D, R9700, E, I]) {
    await client(one);
  }
  await failures(D, R9700);
  await lifetime(E);
  await redeemed(D);
  await setting(D);
  await idempotent(I);
  log.debug("Leaving test().");
}

K.main(test, FLOOR);
