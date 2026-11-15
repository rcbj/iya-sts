// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_sender_constraints.js
//
// ---------------------------------------------------------------------------
// ASKING FOR MORE THAN EITHER SPECIFICATION REQUIRES (#34), OVER THE WIRE.
//
// D12 (#444): carries over `tests/sender_constraints.js` — the five
// settings' decisions (its section 1, asked of the token endpoint and
// UserInfo in a realm per setting rather than of the module) and its child
// process's doors (3a–3l) — against a running service. Each realm turns on
// one setting, so one realm requiring a constraint is seen not to make the
// next require it:
//
//   R. ROTATION: with neither mode nor `oauth2.refreshTokenRotation` a
//      refresh token is kept; the setting alone rotates (the old token then
//      refused); RFC 9700 mode rotates whatever the setting says;
//   D. `oauth2.refreshTokenRequireDpop`: a token request with no proof
//      refused WHOLE, invalid_dpop_proof (STS-OAUTH-0521), no code on the
//      wire; with a proof a DPoP token set; a bound refresh token without a
//      proof refused by RFC 9449 section 5's own check first
//      (STS-OAUTH-0215); an UNBOUND refresh token refused rather than bound
//      (STS-OAUTH-0523), and one with no proof at all (STS-OAUTH-0524); the
//      bound one with its proof redeemed; with the setting off, a
//      confidential client rotating its key at a refresh (#176);
//   M. `oauth2.refreshTokenRequireMtls`: a token request with no client
//      certificate refused (the code the realm records is read off the
//      audit log and named);
//   A. `oauth2.accessTokenRequireDpop`: UserInfo refusing a bearer token
//      with a DPoP challenge (STS-OAUTH-0528), a bound token with no proof
//      (STS-OAUTH-0529), a proved bound token answered, the realm's own
//      /admin-api refusing this job's bearer token meanwhile (so the codes
//      are read once the setting is off), and with the setting off the same
//      bearer token accepted;
//   T. `oauth2.accessTokenRequireMtls`: a token carrying no thumbprint
//      refused at UserInfo (STS-OAUTH-0530);
//   G. `/admin-api` refusing a DPoP-bound token presented as Bearer.
//
// NOT CARRIED, and why: `MTLS_EXEMPT_CLIENTS` and
// `DPOP_BOUND_PUBLIC_CLIENTS` as lists, and the debugger's client NOT
// being on the first (2a–2e-vi), are module constants — (d); the public
// console's DPoP binding at issuance (2e-vii, STS-OAUTH-0943) is
// `sts_console_client.js`'s; an unbound token of the public console at a
// resource (2e-xi, STS-OAUTH-0944) cannot be minted by any endpoint, which
// is what the rule ensures — (d); the exempt client still asked for DPoP
// under both settings (2f) needs the hosted console signing in to a realm
// requiring a client certificate it is exempt from, and the certificate
// rows that need one presented (1n, 1s, 1z, STS-OAUTH-0525, 0531) are
// `sts_rfc8705_mtls.js`'s, which builds the client certificate.
//
// OWNED HERE (local: true).
// ---------------------------------------------------------------------------

const assert = require("assert");
const nodeCrypto = require("crypto");
const K = require("./oauth_wire_kit.js").kit("sts_sender_constraints");
const log = K.log;

const SECRET = "sc-client-secret-" + K.rand(12);
const PERSON = "sc-alice-" + K.STAMP;
const PASSWORD = "Sc-" + K.rand(9) + "-pw!";
const KEY = K.keyPair("ES256", "sc-dpop");
const REDIRECT = "https://rp.sc.example/cb";
const FLOOR = 21;

const R = {};

function check(what, fn) {
  K.check(what, fn);
}

function tokenUrl(realm) {
  log.debug("Entering tokenUrl().");
  log.debug("Leaving tokenUrl().");
  return K.rb(realm) + "/oauth2/token";
}

function issue(realm, headers) {
  log.debug("Entering issue().");
  log.debug("Leaving issue().");
  return K.send(tokenUrl(realm), { headers: headers || {}, form: {
    grant_type: "password", username: PERSON, password: PASSWORD,
    scope: "openid offline_access", client_id: "sc-client",
    client_secret: SECRET } });
}

function refresh(realm, token, headers) {
  log.debug("Entering refresh().");
  log.debug("Leaving refresh().");
  return K.send(tokenUrl(realm), { headers: headers || {}, form: {
    grant_type: "refresh_token", refresh_token: token,
    client_id: "sc-client", client_secret: SECRET } });
}

function proof(realm, key, method, url, token) {
  log.debug("Entering proof().");
  const extra = token ? { ath: nodeCrypto.createHash("sha256")
    .update(token).digest("base64url") } : {};
  log.debug("Leaving proof().");
  return K.dpop(key || KEY, method || "POST", url || tokenUrl(realm), extra);
}

function userinfo(realm, scheme, token, dpopProof) {
  log.debug("Entering userinfo().");
  const headers = { Authorization: scheme + " " + token };
  if (dpopProof) {
    headers.DPoP = dpopProof;
  }
  log.debug("Leaving userinfo().");
  return K.send(K.rb(realm) + "/oauth2/userinfo", { headers: headers });
}

// RFC 9700 mode refuses the password grant (its section 2.4), so its realm
// buys its first refresh token with the code flow.
async function viaCode(realm) {
  log.debug("Entering viaCode().");
  const p = K.pkce();
  const b = K.browser();
  const first = await b.go(K.rb(realm) + "/oauth2/authorize?" +
    new URLSearchParams({ client_id: "sc-client", response_type: "code",
      redirect_uri: REDIRECT, scope: "openid offline_access",
      state: "s-" + K.rand(4), nonce: "n-" + K.rand(4),
      code_challenge: p.challenge, code_challenge_method: "S256" }));
  const back = await K.signIn(realm, b, first, PERSON, PASSWORD);
  const q = K.answerAt(back, REDIRECT);
  assert.ok(q && q.get("code"), K.shown(back));
  const r = await K.send(tokenUrl(realm), { form: {
    grant_type: "authorization_code", code: q.get("code"),
    redirect_uri: REDIRECT, code_verifier: p.verifier,
    client_id: "sc-client", client_secret: SECRET } });
  log.debug("Leaving viaCode(). " + r.status);
  return r;
}

async function rotation() {
  log.debug("Entering rotation().");
  log.info("=== R. rotation ===");
  for (const one of [["off", false], ["rotation", true], ["mode", true]]) {
    const realm = R[one[0]];
    const first = one[0] === "mode" ? await viaCode(realm)
                                     : await issue(realm);
    const rt = first.json && first.json.refresh_token;
    const next = await refresh(realm, rt);
    const old = await refresh(realm, rt);
    if (one[1]) {
      check("R. " + one[0] + ": the refresh rotates — a new refresh token " +
            "is issued and the old one is refused", function () {
        assert.strictEqual(next.status, 200, K.shown(next));
        assert.ok(next.json.refresh_token &&
                  next.json.refresh_token !== rt, K.shown(next));
        assert.strictEqual(old.status, 400, K.shown(old));
        assert.strictEqual(old.json.error, "invalid_grant");
      });
    } else {
      check("R. with neither mode nor the setting, nothing rotates: the " +
            "same refresh token is redeemed again", function () {
        assert.strictEqual(first.status, 200, K.shown(first));
        assert.strictEqual(next.status, 200, K.shown(next));
        assert.strictEqual(old.status, 200, K.shown(old));
      });
    }
  }
  log.debug("Leaving rotation().");
}

async function refreshDpop() {
  log.debug("Entering refreshDpop().");
  log.info("=== D. oauth2.refreshTokenRequireDpop ===");
  const off = await issue(R.off);
  const unboundRefresh = off.json.refresh_token;
  check("D1. with the settings off a plain token request still gets a " +
        "refresh token", function () {
    assert.strictEqual(off.status, 200, K.shown(off));
    assert.ok(unboundRefresh);
  });
  // The same realm's unbound refresh token is presented in the DPoP realm
  // by issuing one there before the setting goes on.
  const early = await issue(R.dpop);
  const earlyRefresh = early.json && early.json.refresh_token;
  await K.set(R.dpop, "oauth2.refreshTokenRequireDpop", true);
  let c = await K.coded(R.dpop, "STS-OAUTH-0521", function () {
    return issue(R.dpop);
  });
  check("D2. with the setting on, a token request carrying no proof is " +
        "refused WHOLE — no access token either (STS-OAUTH-0521)",
        function () {
    assert.strictEqual(c.answer.status, 400, K.shown(c.answer));
    assert.strictEqual(c.answer.json.error, "invalid_dpop_proof");
    assert.ok(!c.answer.json.access_token);
    assert.ok(c.rose >= 1);
  });
  check("D3. and the refusal carries no error code on the wire",
        function () {
    assert.ok(c.answer.text.indexOf("STS-OAUTH-") < 0);
  });
  const bound = await issue(R.dpop, { DPoP: proof(R.dpop) });
  check("D4. the same request with a proof is issued, as a DPoP token set",
        function () {
    assert.strictEqual(bound.status, 200, K.shown(bound));
    assert.ok(bound.json.refresh_token && bound.json.access_token);
    assert.strictEqual(String(bound.json.token_type).toLowerCase(), "dpop");
  });
  c = await K.coded(R.dpop, "STS-OAUTH-0215", function () {
    return refresh(R.dpop, bound.json.refresh_token);
  });
  check("D5. redeeming a bound refresh token without a proof is refused " +
        "invalid_grant by the binding check that was already there " +
        "(STS-OAUTH-0215)", function () {
    assert.strictEqual(c.answer.status, 400, K.shown(c.answer));
    assert.strictEqual(c.answer.json.error, "invalid_grant");
    assert.ok(c.rose >= 1);
  });
  c = await K.coded(R.dpop, "STS-OAUTH-0523", function () {
    return refresh(R.dpop, earlyRefresh, { DPoP: proof(R.dpop) });
  });
  check("D6. AN UNBOUND REFRESH TOKEN IS REFUSED RATHER THAN BOUND to the " +
        "key presenting it, invalid_grant (STS-OAUTH-0523)", function () {
    assert.ok(earlyRefresh, K.shown(early));
    assert.strictEqual(c.answer.status, 400, K.shown(c.answer));
    assert.strictEqual(c.answer.json.error, "invalid_grant");
    assert.ok(c.rose >= 1);
  });
  c = await K.coded(R.dpop, "STS-OAUTH-0524", function () {
    return refresh(R.dpop, earlyRefresh);
  });
  check("D7. and an unbound one with no proof at all is its own refusal " +
        "(STS-OAUTH-0524)", function () {
    assert.strictEqual(c.answer.status, 400, K.shown(c.answer));
    assert.ok(c.rose >= 1);
  });
  let r = await refresh(R.dpop, bound.json.refresh_token,
                        { DPoP: proof(R.dpop) });
  check("D8. and the bound one with its own proof is redeemed", function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.ok(r.json.access_token);
  });
  r = await issue(R.off, { DPoP: proof(R.off) });
  const rotated = K.keyPair("ES256", "sc-rotated");
  const next = await refresh(R.off, r.json.refresh_token,
                             { DPoP: proof(R.off, rotated) });
  check("D9. setting off: an authenticated client refreshing with a NEW " +
        "key is issued a DPoP token set (RFC 9449 section 5)", function () {
    assert.strictEqual(next.status, 200, K.shown(next));
    assert.strictEqual(String(next.json.token_type).toLowerCase(), "dpop");
  });
  r = await issue(R.off);
  check("D10. and the realm next door is untouched: a token request with " +
        "no proof is issued there", function () {
    assert.strictEqual(r.status, 200, K.shown(r));
  });
  log.debug("Leaving refreshDpop().");
  return bound.json.access_token;
}

async function refreshMtls() {
  log.debug("Entering refreshMtls().");
  log.info("=== M. oauth2.refreshTokenRequireMtls ===");
  await K.set(R.mtls, "oauth2.refreshTokenRequireMtls", true);
  const before = {
    "STS-OAUTH-0522": await K.codeCount(R.mtls, "STS-OAUTH-0522"),
    "STS-OAUTH-0527": await K.codeCount(R.mtls, "STS-OAUTH-0527") };
  const r = await issue(R.mtls);
  // Either code may be the one; the audit row is waited for briefly.
  let after = {};
  for (let i = 0; i < 20; i++) {
    after = {
      "STS-OAUTH-0522": await K.codeCount(R.mtls, "STS-OAUTH-0522"),
      "STS-OAUTH-0527": await K.codeCount(R.mtls, "STS-OAUTH-0527") };
    if (after["STS-OAUTH-0522"] > before["STS-OAUTH-0522"] ||
        after["STS-OAUTH-0527"] > before["STS-OAUTH-0527"]) {
      break;
    }
    await K.sleep(150);
  }
  const rose = Object.keys(before).filter(function (code) {
    return after[code] > before[code];
  });
  K.log.info("the mutual TLS refusal recorded " + rose.join(", "));
  check("M1. a token request with no client certificate is refused " +
        "invalid_client 401, recorded STS-OAUTH-0522 (no certificate) or " +
        "STS-OAUTH-0527 (a port that cannot ask for one)", function () {
    assert.strictEqual(r.status, 401, K.shown(r));
    assert.strictEqual(r.json.error, "invalid_client");
    assert.strictEqual(rose.length, 1, JSON.stringify([before, after]));
  });
  log.debug("Leaving refreshMtls().");
}

async function resources(boundAccess) {
  log.debug("Entering resources().");
  log.info("=== A. oauth2.accessTokenRequireDpop ===");
  // WHILE A REALM REQUIRES DPoP OF EVERY ACCESS TOKEN, ITS OWN /admin-api
  // REFUSES THIS JOB'S BEARER TOKEN TOO (it is a resource of the realm), so
  // the codes are read after the setting is off again.
  const plain = await issue(R.atDpop);
  const bearer = plain.json.access_token;
  const boundSet = await issue(R.atDpop, { DPoP: proof(R.atDpop) });
  const bound = boundSet.json.access_token;
  const url = K.rb(R.atDpop) + "/oauth2/userinfo";
  const n0528 = await K.codeCount(R.atDpop, "STS-OAUTH-0528");
  const n0529 = await K.codeCount(R.atDpop, "STS-OAUTH-0529");
  await K.set(R.atDpop, "oauth2.accessTokenRequireDpop", true);
  let refusedBearer;
  let refusedUnproved;
  let proved;
  let ownApi;
  try {
    refusedBearer = await userinfo(R.atDpop, "Bearer", bearer);
    refusedUnproved = await userinfo(R.atDpop, "DPoP", bound);
    proved = await userinfo(R.atDpop, "DPoP", bound,
                            proof(R.atDpop, KEY, "GET", url, bound));
    ownApi = await K.send(K.rb(R.atDpop) + "/admin-api/audit?per=1");
  } finally {
    await K.unset(R.atDpop, "oauth2.accessTokenRequireDpop");
  }
  const rose0528 = await K.codeAfter(R.atDpop, "STS-OAUTH-0528", n0528);
  const rose0529 = await K.codeAfter(R.atDpop, "STS-OAUTH-0529", n0529);
  check("A1. with oauth2.accessTokenRequireDpop on, UserInfo refuses a " +
        "bearer token 401 with a DPoP challenge (STS-OAUTH-0528)",
        function () {
    assert.strictEqual(refusedBearer.status, 401, K.shown(refusedBearer));
    assert.ok(String(refusedBearer.headers.get("www-authenticate") || "")
      .indexOf("DPoP") === 0,
      refusedBearer.headers.get("www-authenticate"));
    assert.ok(rose0528 > n0528);
  });
  check("A2. and a bound token with no proof beside it is refused too " +
        "(STS-OAUTH-0529)", function () {
    assert.strictEqual(refusedUnproved.status, 401,
                       K.shown(refusedUnproved));
    assert.ok(rose0529 > n0529);
  });
  check("A3. a proved bound token is answered", function () {
    assert.strictEqual(proved.status, 200, K.shown(proved));
  });
  check("A4. and the realm's own /admin-api refuses a bearer access token " +
        "while the setting is on", function () {
    assert.strictEqual(ownApi.status, 401, K.shown(ownApi));
  });
  let r = await userinfo(R.atDpop, "Bearer", bearer);
  check("A5. with the setting off the same bearer token is accepted — the " +
        "refusal is the setting and nothing else", function () {
    assert.strictEqual(r.status, 200, K.shown(r));
  });

  log.info("=== T. oauth2.accessTokenRequireMtls ===");
  const tToken = (await issue(R.atMtls)).json.access_token;
  const n0530 = await K.codeCount(R.atMtls, "STS-OAUTH-0530");
  await K.set(R.atMtls, "oauth2.accessTokenRequireMtls", true);
  let unbound;
  try {
    unbound = await userinfo(R.atMtls, "Bearer", tToken);
  } finally {
    await K.unset(R.atMtls, "oauth2.accessTokenRequireMtls");
  }
  const rose0530 = await K.codeAfter(R.atMtls, "STS-OAUTH-0530", n0530);
  const next = await userinfo(R.off, "Bearer", (await issue(R.off)).json
    .access_token);
  check("T1. the mutual TLS row refuses a token carrying no thumbprint " +
        "(STS-OAUTH-0530), and the realm next door does not", function () {
    assert.strictEqual(unbound.status, 401, K.shown(unbound));
    assert.ok(rose0530 > n0530);
    assert.strictEqual(next.status, 200, K.shown(next));
  });

  log.info("=== G. /admin-api ===");
  r = await K.send(K.rb(R.dpop) + "/admin-api/health", {
    headers: { Authorization: "Bearer " + boundAccess } });
  check("G1. a DPoP-bound token presented to /admin-api as Bearer is not " +
        "accepted", function () {
    assert.ok(r.status === 401 || r.status === 403, K.shown(r));
  });
  log.debug("Leaving resources().");
}

async function test() {
  log.debug("Entering test().");
  R.off = await K.realm("sc-off", "development");
  R.rotation = await K.realm("sc-rot", "development",
                             { "oauth2.refreshTokenRotation": true });
  R.mode = await K.realm("sc-mode", "development",
                         { "oauth2.rfc9700": true,
                           "oauth2.refreshTokenRotation": false });
  R.dpop = await K.realm("sc-dpop", "development");
  R.mtls = await K.realm("sc-mtls", "development");
  R.atDpop = await K.realm("sc-atdpop", "development");
  R.atMtls = await K.realm("sc-atmtls", "development");
  for (const realm of Object.keys(R)) {
    await K.person(R[realm], PERSON, PASSWORD);
    await K.app(R[realm], "sc-client", { oauthClientId: "sc-client",
      oauthClientSecret: SECRET,
      oauthTokenEndpointAuthMethod: "client_secret_post",
      oauthRedirectUri: [REDIRECT],
      oauthGrantType: ["password", "refresh_token", "authorization_code"] });
  }
  await rotation();
  const boundAccess = await refreshDpop();
  await refreshMtls();
  await resources(boundAccess);
  log.debug("Leaving test().");
}

K.main(test, FLOOR);
