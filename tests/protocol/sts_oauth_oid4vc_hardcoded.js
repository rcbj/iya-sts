// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_oauth_oid4vc_hardcoded.js
//
// ===========================================================================
// THE 2026-09-12 HARD-CODED-VALUE SWEEP OF oauth-oidc/ AND oid4vc/, OVER
// THE WIRE (D12, #444).
//
// Carries the endpoint half of `tests/oauth_oid4vc_hardcoded.js` — which
// ran in a child process on a loopback port — onto a running service, in a
// development and a product realm of its own (the product realm lets a
// person sign in without a second factor, `authn.allowOptionalSecondFactor`,
// because what is asserted is not the second factor):
//
//   1. THE PASSWORD GRANT: development takes any password and refuses the
//      reserved `invalid`; product refuses the grant outright
//      (unsupported_grant_type), the right and a wrong password with the
//      IDENTICAL answer, naming nobody;
//   2. `/dpop/nonce-mode` IS NOT A ROUTE in either mode (#597); the nonce
//      is `oauth2.dpopNonceRequired`, written through the realm's own
//      `/admin-api/config/set`, and it reaches that realm's token endpoint
//      and not another realm's;
//   3. RFC 7591 REGISTRATION: development's is open, the client_id takes
//      `oauth2.registeredClientIdPrefix` and `client_secret_expires_at`
//      follows `oauth2.clientSecretLifetimeDays`; an RFC 7592 read with no
//      registration access token is 401; product refuses it 403 naming
//      `oauth2.openRegistration` and does not advertise the endpoint, and
//      with the setting on answers and advertises it;
//   4. THE TRANSACTION CODE of an offer the person makes on the portal:
//      `oid4vci.txCodeLength` digits and no leading zero; development's six
//      wrong codes spend nothing; product says how many attempts remain and
//      the attempt reaching `oid4vci.txCodeMaxAttempts` spends the code;
//   5. THE DEMONSTRATION'S PAGES AND READBACKS ARE NOT ROUTES (#594) in
//      either mode;
//   6. THE OpenID4VCI ENDPOINTS IN PRODUCT accept only a token this realm
//      can verify: a made-up bearer and a foreign JWT refused invalid_token
//      at all three (with the challenge), a live token of this realm let
//      past the token check, an anonymous wallet redeeming with no
//      client_id, and a token this realm revoked refused at all three and
//      recorded STS-VC-0086; development lets both through;
//   7. did:web FOLLOWS THE REALM: the default realm's DID is the Host form,
//      a realm's carries `:realm:<id>`, resolves at `<realm>/did.json`, and
//      `/did.json` is not served;
//   8. A DAY-LONG RFC 7523 GRANT ASSERTION WITH NO `iat` is refused by the
//      lifetime ceiling, a short one with none is accepted.
//
// NOT CARRIED (class (d)): the library half (the replay cache refusing
// rather than forgetting, a client assertion's `exp`, the persona gate, the
// DPoP windows), and `vpWalletFor()` asked as a function (its wire door is
// the wallet sign-in's start, `POST /authn-api/wallet`, STS-VC-0033, the
// wallet sign-in family's job); and STS-OAUTH-0938, a pre-authorized code
// for a person with no entry: every offer is made on a signed-in session
// now (#589, #594) and carries that session's subject, which the grant
// keeps even after the entry is deleted (oauth2.ts, "THE PERSON, RESOLVED
// NOW"), so no door mints the offer the refusal is for.
//
// OWNED HERE (local: true): this repository's authorization server and
// credential issuer.
// ===========================================================================

const assert = require("assert");
const nodeCrypto = require("crypto");
const portal = require("./portal_signin.js");
const K = require("./oauth_wire_kit.js").kit("sts_oauth_oid4vc_hardcoded");
const log = K.log;

const SECRET = "hc-client-secret-" + K.rand(8);
const PASSWORD = "Hc-" + K.rand(6) + "-correct-horse!";
const PRE_AUTH = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
const IDENTITY = { credential_configuration_id: "IdentityCredential" };
const ENDPOINTS = ["/oid4vci/credential", "/oid4vci/deferred_credential",
                   "/oid4vci/notification"];

function hcClient(id) {
  log.debug("Entering hcClient().");
  log.debug("Leaving hcClient().");
  return K.app(id, "hc-client", { oauthClientId: ["hc-client"],
    oauthClientSecret: SECRET,
    oauthTokenEndpointAuthMethod: "client_secret_post",
    oauthAllowedScope: ["openid", "profile", "email"],
    oauthGrantType: ["password", "client_credentials", PRE_AUTH] });
}

function token(id, form) {
  log.debug("Entering token().");
  log.debug("Leaving token().");
  return K.send(K.rb(id) + "/oauth2/token", { form: form });
}

// An offer the person makes for their own wallet on the portal (#589).
async function offerFor(id, user) {
  log.debug("Entering offerFor(). " + user);
  const client = await portal.signInToThePortal(K.rb(id), user, null,
                                                { password: PASSWORD });
  const made = await client.act("/portal/wallet",
    { configuration: "IdentityCredential", mode: "cross-device" });
  assert.ok(made.status === 200 && made.json && made.json.offer,
            "the portal's offer: " + made.status + " " +
            String(made.text).slice(0, 300));
  const offer = made.json.offer;
  const grant = ((offer.credentialOffer || {}).grants || {})[PRE_AUTH] || {};
  assert.ok(grant["pre-authorized_code"] && offer.txCode,
            JSON.stringify(offer).slice(0, 400));
  log.debug("Leaving offerFor().");
  return { code: grant["pre-authorized_code"], txCode: String(offer.txCode) };
}

function redeem(id, offer, txCode, withClient) {
  log.debug("Entering redeem().");
  const form = { grant_type: PRE_AUTH,
                 "pre-authorized_code": offer.code, tx_code: txCode };
  if (withClient !== false) {
    form.client_id = "hc-client";
    form.client_secret = SECRET;
  }
  log.debug("Leaving redeem().");
  return token(id, form);
}

function issuerCall(id, where, bearer, json) {
  log.debug("Entering issuerCall(). " + where);
  log.debug("Leaving issuerCall().");
  return K.send(K.rb(id) + where, { json: json || {},
    headers: { authorization: "Bearer " + bearer } });
}

function foreignJwt(id) {
  log.debug("Entering foreignJwt().");
  const key = K.keyPair("RS256", "foreign");
  const out = K.jws("RS256", { typ: "at+jwt" }, { sub: "hc-alice",
    iss: K.rb(id), aud: K.rb(id), jti: "hc-foreign-" + K.rand(4),
    exp: Math.floor(Date.now() / 1000) + 600 }, key);
  log.debug("Leaving foreignJwt().");
  return out;
}

async function passwordGrant(dev, prod, user) {
  log.debug("Entering passwordGrant().");
  log.info("=== 1. the password grant ===");
  let r = await token(dev, { grant_type: "password", username: user,
    password: "not-the-password", client_id: "hc-client",
    client_secret: SECRET });
  K.check("1a. development: the password grant still accepts ANY password",
          function () {
    assert.strictEqual(r.status, 200, K.shown(r));
  });
  r = await token(dev, { grant_type: "password", username: user,
    password: "invalid", client_id: "hc-client", client_secret: SECRET });
  K.check("1b. development: the reserved password \"invalid\" is still " +
          "refused", function () {
    assert.strictEqual(r.status, 400, K.shown(r));
    assert.strictEqual(r.json.error, "invalid_grant");
  });
  const right = await token(prod, { grant_type: "password", username: user,
    password: PASSWORD, scope: "openid profile email",
    client_id: "hc-client", client_secret: SECRET });
  const wrong = await token(prod, { grant_type: "password", username: user,
    password: "not-the-password", client_id: "hc-client",
    client_secret: SECRET });
  K.check("1c. product: the password grant is refused outright " +
          "(unsupported_grant_type, RFC 9700 section 2.4)", function () {
    assert.strictEqual(right.status, 400, K.shown(right));
    assert.strictEqual(right.json.error, "unsupported_grant_type");
  });
  K.check("1d. and a WRONG password is refused the same way, the IDENTICAL " +
          "answer, naming nobody", function () {
    assert.strictEqual(wrong.status, 400, K.shown(wrong));
    assert.strictEqual(wrong.json.error, "unsupported_grant_type");
    assert.strictEqual(right.json.error_description,
                       wrong.json.error_description);
    assert.ok(String(right.json.error_description).indexOf(user) < 0,
              right.json.error_description);
  });
  log.debug("Leaving passwordGrant().");
}

async function dpopNonce(dev, prod, other) {
  log.debug("Entering dpopNonce().");
  log.info("=== 2. the DPoP nonce is a per-realm setting ===");
  for (const id of [prod, dev]) {
    const post = await K.send(K.rb(id) + "/dpop/nonce-mode",
                              { json: { required: true } });
    const get = await K.send(K.rb(id) + "/dpop/nonce-mode");
    K.check("2a. " + (id === prod ? "product" : "development") +
            ": /dpop/nonce-mode is not a route, by either method",
            function () {
      assert.strictEqual(post.status, 404, K.shown(post));
      assert.ok(/Cannot POST/.test(post.text), post.text.slice(0, 160));
      assert.strictEqual(get.status, 404, K.shown(get));
      assert.ok(/Cannot GET/.test(get.text), get.text.slice(0, 160));
    });
  }
  const set = await K.send(K.rb(dev) + "/admin-api/config/set", { json: {
    key: "oauth2.dpopNonceRequired", value: "true" } });
  const key = K.keyPair("ES256", "dp");
  const ask = function (id) {
    log.debug("Entering ask().");
    log.debug("Leaving ask().");
    return K.send(K.rb(id) + "/oauth2/token", {
      headers: { DPoP: K.dpop(key, "POST", K.rb(id) + "/oauth2/token") },
      form: { grant_type: "client_credentials", client_id: "hc-client",
              client_secret: SECRET } });
  };
  const here = await ask(dev);
  const there = await ask(other);
  K.check("2b. the realm's own /admin-api/config/set turns nonces on in the " +
          "realm it was reached in: its token endpoint asks for one",
          function () {
    assert.strictEqual(set.status, 200, K.shown(set));
    assert.strictEqual(here.status, 400, K.shown(here));
    assert.strictEqual(here.json.error, "use_dpop_nonce");
    assert.ok(here.headers.get("dpop-nonce"), "no DPoP-Nonce header");
  });
  K.check("2c. and NOT in another realm — it was one switch for the whole " +
          "process until 2026-09-12", function () {
    assert.strictEqual(there.status, 200, K.shown(there));
  });
  await K.send(K.rb(dev) + "/admin-api/config/reset",
               { json: { key: "oauth2.dpopNonceRequired" } });
  log.debug("Leaving dpopNonce().");
}

async function registration(dev, prod) {
  log.debug("Entering registration().");
  log.info("=== 3. RFC 7591 registration ===");
  await K.set(dev, "oauth2.registeredClientIdPrefix", "hc-dyn-");
  await K.set(dev, "oauth2.clientSecretLifetimeDays", 1);
  const r = await K.send(K.rb(dev) + "/oauth2/register",
    { json: { redirect_uris: ["https://rp.hc.example/cb"] } });
  const dayFromNow = Math.floor(Date.now() / 1000) + 86400;
  K.check("3a. development: registration is open and the client_id takes " +
          "the configured prefix", function () {
    assert.strictEqual(r.status, 201, K.shown(r));
    assert.ok(/^hc-dyn-/.test(r.json.client_id), r.json.client_id);
  });
  K.check("3b. and client_secret_expires_at follows " +
          "oauth2.clientSecretLifetimeDays, in days", function () {
    assert.ok(Math.abs(r.json.client_secret_expires_at - dayFromNow) <= 120,
              String(r.json.client_secret_expires_at));
  });
  await K.unset(dev, "oauth2.registeredClientIdPrefix");
  await K.unset(dev, "oauth2.clientSecretLifetimeDays");
  const read = await K.send(K.rb(dev) + "/oauth2/register/" +
                            encodeURIComponent(r.json.client_id));
  K.check("3c. an RFC 7592 read with no registration access token is " +
          "refused 401", function () {
    assert.strictEqual(read.status, 401, K.shown(read));
  });
  await K.set(prod, "oauth2.softwareStatementOpensRegistration", false);
  const closed = await K.send(K.rb(prod) + "/oauth2/register",
    { json: { redirect_uris: ["https://rp.hc.example/cb"] } });
  let meta = await K.send(K.rb(prod) +
                          "/.well-known/oauth-authorization-server");
  K.check("3d. product: registration is refused 403 and names " +
          "oauth2.openRegistration", function () {
    assert.strictEqual(closed.status, 403, K.shown(closed));
    assert.ok(/oauth2\.openRegistration/.test(closed.text), closed.text);
  });
  K.check("3e. product: and registration_endpoint is not advertised",
          function () {
    assert.ok(meta.json && !("registration_endpoint" in meta.json),
              String(meta.json && meta.json.registration_endpoint));
  });
  await K.set(prod, "oauth2.openRegistration", true);
  const open = await K.send(K.rb(prod) + "/oauth2/register",
    { json: { redirect_uris: ["https://rp.hc.example/cb"],
              token_endpoint_auth_method: "client_secret_basic" } });
  meta = await K.send(K.rb(prod) + "/.well-known/oauth-authorization-server");
  K.check("3f. product with oauth2.openRegistration on: registration " +
          "answers and is advertised", function () {
    assert.strictEqual(open.status, 201, K.shown(open));
    assert.ok(meta.json.registration_endpoint, JSON.stringify(meta.json)
      .slice(0, 200));
  });
  await K.unset(prod, "oauth2.openRegistration");
  await K.unset(prod, "oauth2.softwareStatementOpensRegistration");
  log.debug("Leaving registration().");
}

async function transactionCode(dev, prod, user) {
  log.debug("Entering transactionCode().");
  log.info("=== 4. the Transaction Code ===");
  await K.set(dev, "oid4vci.txCodeLength", 8);
  const devOffer = await offerFor(dev, user);
  await K.unset(dev, "oid4vci.txCodeLength");
  K.check("4a. the Transaction Code has oid4vci.txCodeLength digits and no " +
          "leading zero", function () {
    assert.ok(/^[1-9][0-9]{7}$/.test(devOffer.txCode), devOffer.txCode);
  });
  for (let i = 0; i < 6; i++) {
    await redeem(dev, devOffer, "00000000");
  }
  const kept = await redeem(dev, devOffer, devOffer.txCode);
  K.check("4b. development: six wrong codes do NOT spend the pre-authorized " +
          "code — the right one still redeems", function () {
    assert.strictEqual(kept.status, 200, K.shown(kept));
    assert.ok(kept.json.access_token);
  });
  await K.set(prod, "oid4vci.txCodeMaxAttempts", 3);
  const offer = await offerFor(prod, user);
  const wrong = offer.txCode === "000000" ? "111111" : "000000";
  const first = await redeem(prod, offer, wrong);
  K.check("4c. product: a wrong code says how many attempts remain",
          function () {
    assert.strictEqual(first.status, 400, K.shown(first));
    assert.ok(/2 attempt\(s\) remain/.test(first.text), first.text);
  });
  await redeem(prod, offer, wrong);
  const third = await redeem(prod, offer, wrong);
  K.check("4d. product: the wrong code that reaches " +
          "oid4vci.txCodeMaxAttempts SPENDS the code", function () {
    assert.ok(/has been spent/.test(third.text), third.text);
  });
  const after = await redeem(prod, offer, offer.txCode);
  K.check("4e. and the RIGHT code afterwards is refused, because the code " +
          "no longer exists", function () {
    assert.strictEqual(after.status, 400, K.shown(after));
  });
  await K.unset(prod, "oid4vci.txCodeMaxAttempts");
  log.debug("Leaving transactionCode().");
}

async function demonstrationGone(dev, prod) {
  log.debug("Entering demonstrationGone().");
  log.info("=== 5. the demonstration's routes are gone ===");
  for (const id of [prod, dev]) {
    const still = [];
    for (const where of ["/issuer", "/issuer/offer?mode=cross-device",
                         "/vc-demo-api/offer", "/oid4vci/last_request",
                         "/oid4vci/notification/x", "/did/generate",
                         "/oid4vp/start", "/oid4vp/result/x"]) {
      const r = await K.send(K.rb(id) + where);
      if (!(r.status === 404 && /Cannot GET/.test(r.text))) {
        still.push(where + " " + r.status);
      }
    }
    K.check("5. " + (id === prod ? "product" : "development") + ": the " +
            "demonstration's pages and readbacks are not routes (#594)",
            function () {
      assert.strictEqual(still.join(", "), "");
    });
  }
  log.debug("Leaving demonstrationGone().");
}

async function issuerTokens(dev, prod, user) {
  log.debug("Entering issuerTokens().");
  log.info("=== 6. the OpenID4VCI endpoints' tokens ===");
  let r = await issuerCall(dev, "/oid4vci/credential", "made-up-token",
                           IDENTITY);
  K.check("6a. development: a made-up bearer still reaches the credential " +
          "request", function () {
    assert.notStrictEqual(r.status, 401, K.shown(r));
  });
  r = await issuerCall(dev, "/oid4vci/credential", foreignJwt(dev),
                       IDENTITY);
  K.check("6b. development: a foreign JWT still reaches the request",
          function () {
    assert.notStrictEqual(r.status, 401, K.shown(r));
  });
  for (const where of ENDPOINTS) {
    r = await issuerCall(prod, where, "made-up-token", IDENTITY);
    K.check("6c. product: " + where + " refuses a made-up bearer " +
            "invalid_token, with the challenge", function () {
      assert.strictEqual(r.status, 401, K.shown(r));
      assert.strictEqual(r.json.error, "invalid_token");
      assert.ok(/invalid_token/.test(String(
        r.headers.get("www-authenticate") || "")));
    });
  }
  r = await issuerCall(prod, "/oid4vci/credential", foreignJwt(prod),
                       IDENTITY);
  K.check("6d. product: and a JWT signed by a key that is not this realm's",
          function () {
    assert.strictEqual(r.status, 401, K.shown(r));
    assert.strictEqual(r.json.error, "invalid_token");
  });
  const offer = await offerFor(prod, user);
  const minted = await redeem(prod, offer, offer.txCode);
  const live = minted.json && minted.json.access_token;
  K.check("6e. product: this realm issues a token for the person's offer",
          function () {
    assert.strictEqual(minted.status, 200, K.shown(minted));
    assert.ok(live);
  });
  const anonOffer = await offerFor(prod, user);
  const anon = await redeem(prod, anonOffer, anonOffer.txCode, false);
  K.check("6f. product: an anonymous wallet redeems a pre-authorized code " +
          "with no client_id (OpenID4VCI section 6.1)", function () {
    assert.strictEqual(anon.status, 200, K.shown(anon));
    assert.ok(anon.json.access_token);
  });
  r = await issuerCall(prod, "/oid4vci/credential", live, IDENTITY);
  K.check("6g. product: a token this realm issued reaches the request " +
          "(refused for the missing proof — the control)", function () {
    assert.strictEqual(r.status, 400, K.shown(r));
    assert.notStrictEqual(r.json.error, "invalid_token");
  });
  for (const where of ENDPOINTS.slice(1)) {
    r = await issuerCall(prod, where, live, {});
    K.check("6g. product: " + where + " lets the live token past the token " +
            "check (the control)", function () {
      assert.ok(!(r.status === 401 && r.json &&
                  r.json.error === "invalid_token"), K.shown(r));
    });
  }
  const before = await K.codeCount(prod, "STS-VC-0086");
  const revoked = await K.send(K.rb(prod) + "/oauth2/revoke", { form: {
    token: live, client_id: "hc-client", client_secret: SECRET } });
  K.check("6h. (a control: the live token is revoked)", function () {
    assert.strictEqual(revoked.status, 200, K.shown(revoked));
  });
  for (const where of ENDPOINTS) {
    r = await issuerCall(prod, where, live, where === ENDPOINTS[0]
      ? IDENTITY : {});
    K.check("6i. product: " + where + " refuses the REVOKED token " +
            "invalid_token", function () {
      assert.strictEqual(r.status, 401, K.shown(r));
      assert.strictEqual(r.json.error, "invalid_token");
      assert.ok(/revoked/.test(String(r.json.error_description)),
                K.shown(r));
    });
  }
  const after = await K.codeAfter(prod, "STS-VC-0086", before + 2);
  K.check("6j. product: each of the three refusals is recorded under " +
          "STS-VC-0086", function () {
    assert.ok(after - before >= 3, String(after - before));
  });
  log.debug("Leaving issuerTokens().");
}

async function didWeb(dev) {
  log.debug("Entering didWeb().");
  log.info("=== 7. did:web follows the realm ===");
  const host = new URL(K.base).host.replace(":", "%3A");
  const plain = await K.send(K.base + "/.well-known/did.json");
  const realmDoc = await K.send(K.rb(dev) + "/.well-known/did.json");
  const pathForm = await K.send(K.rb(dev) + "/did.json");
  const bare = await K.send(K.base + "/did.json");
  K.check("7a. the default realm's DID is the Host-header form",
          function () {
    assert.strictEqual(plain.json && plain.json.id, "did:web:" + host);
  });
  K.check("7b. a realm's DID carries the realm path as did:web components",
          function () {
    assert.strictEqual(realmDoc.json && realmDoc.json.id,
                       "did:web:" + host + ":realm:" + dev);
  });
  K.check("7c. and resolves at <realm>/did.json, where the did:web method " +
          "looks for it", function () {
    assert.strictEqual(pathForm.status, 200, K.shown(pathForm));
    assert.strictEqual(pathForm.json.id, realmDoc.json.id);
  });
  K.check("7d. a DID with no path is NOT also served at /did.json",
          function () {
    assert.strictEqual(bare.status, 404, K.shown(bare));
  });
  log.debug("Leaving didWeb().");
}

async function assertionIat(dev) {
  log.debug("Entering assertionIat().");
  log.info("=== 8. an RFC 7523 grant assertion with no iat ===");
  const ISS = "https://hc-broker-" + K.STAMP + ".example/iss";
  const AUD = K.rb(dev) + "/oauth2/token";
  await K.ok(K.rb(dev) + "/admin-api/pki/build",
             { organisation: "Hard-coded sweep", country: "US" },
             "built the realm's CA");
  await K.app(dev, "hc-broker", { oauthClientId: ["hc-broker"],
    oauthClientSecret: SECRET,
    oauthTokenEndpointAuthMethod: "client_secret_post" });
  const issued = await K.ok(K.rb(dev) + "/admin-api/pki/issue",
                            { identifier: "hc-broker" },
                            "issued the broker's signing key pair");
  await K.ok(K.rb(dev) + "/admin-api/applications/add",
             { application: "hc-broker", attribute: "oauthAssertionIssuer",
               value: ISS }, "declared the assertion issuer");
  const pem = (await K.ok(K.rb(dev) + "/admin-api/applications/reveal-secret",
    { application: "hc-broker", secret: "oauthAssertionPrivateKey" },
    "revealed the broker's key")).value;
  const user = "hc-someone-" + K.STAMP;
  await K.person(dev, user, PASSWORD);
  const sign = function (claims) {
    log.debug("Entering sign().");
    const input = K.b64u({ alg: issued.jwsAlg, typ: "JWT",
                           kid: issued.kid }) + "." + K.b64u(claims);
    const sig = nodeCrypto.sign("sha256", Buffer.from(input), pem)
      .toString("base64url");
    log.debug("Leaving sign().");
    return input + "." + sig;
  };
  const now = Math.floor(Date.now() / 1000);
  const grant = function (claims) {
    log.debug("Entering grant().");
    log.debug("Leaving grant().");
    return token(dev, {
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: sign(claims), client_id: "hc-broker",
      client_secret: SECRET });
  };
  const long = await grant({ iss: ISS, sub: user, aud: AUD,
    exp: now + 86000, jti: "hc-noiat-" + K.rand(4) });
  K.check("8a. a day-long grant assertion with NO iat is refused by the " +
          "ceiling, which names oauth2.jwtBearerMaxLifetimeS", function () {
    assert.strictEqual(long.status, 400, K.shown(long));
    assert.strictEqual(long.json.error, "invalid_grant");
    assert.ok(/oauth2\.jwtBearerMaxLifetimeS/.test(
      long.json.error_description || ""), K.shown(long));
  });
  const short = await grant({ iss: ISS, sub: user, aud: AUD,
    exp: now + 60, jti: "hc-short-" + K.rand(4) });
  K.check("8b. while a short one with no iat is accepted — the control",
          function () {
    assert.strictEqual(short.status, 200, K.shown(short));
  });
  log.debug("Leaving assertionIat().");
}

async function test() {
  log.debug("Entering test().");
  const dev = await K.realm("hcd", "development");
  const other = await K.realm("hco", "development");
  const prod = await K.realm("hcp", "product",
    { "authn.allowOptionalSecondFactor": "true" });
  const user = "hc-alice-" + K.STAMP;
  for (const id of [dev, other, prod]) {
    await hcClient(id);
    await K.person(id, user, PASSWORD);
  }
  await passwordGrant(dev, prod, user);
  await dpopNonce(dev, prod, other);
  await registration(dev, prod);
  await transactionCode(dev, prod, user);
  await demonstrationGone(dev, prod);
  await issuerTokens(dev, prod, user);
  await didWeb(dev);
  await assertionIat(dev);
  log.debug("Leaving test().");
}

K.main(test, 43);
