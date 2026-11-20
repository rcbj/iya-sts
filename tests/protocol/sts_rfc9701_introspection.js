// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_rfc9701_introspection.js
//
// ---------------------------------------------------------------------------
// RFC 9701, THE JWT INTROSPECTION RESPONSE, OVER THE WIRE.
//
// D12 (#444): carries over `tests/rfc9701_introspection.js`'s child process
// (3a–3ah, 4a–4p, 5a–5e, 6a–6c, 7a) against a running service, in a
// development realm of its own (switched to product for 3af–3ah and back)
// and an OAuth 2.1 one. Every signature is verified, and the Nested JWT
// decrypted, by THIS FILE's own code over node's crypto:
//
//   3. anonymous JSON unchanged in development and varying on Accept; an
//      unauthenticated JWT request refused 400 invalid_client
//      (STS-OAUTH-0291); the media type, typ, alg, iss/aud/iat, no sub or
//      exp, the inner RFC 7662 answer; an inactive token as
//      `{"active":false}` alone; JSON preferred in Accept; the token
//      endpoint's methods; ES256 and HS256 registered; `none` and a lone
//      `enc` refused at the registry (STS-REG-0073); an RSA-OAEP-256 /
//      A128CBC-HS256 Nested JWT; a lone `enc` left behind answered 500
//      (STS-OAUTH-0293); RFC 7591 refusing `none` (STS-REG-0072) and
//      honouring PS384; the three discovery members and the auth methods;
//      a named server's issuer; product's 401 for anonymous JSON and its
//      restricted JSON;
//   4. section 5's intended-for rule: another resource server's token
//      `{"active":false}`, the API itself, its own client, development's
//      unchecked JSON unrestricted, an `oauthAudience` match and not
//      another, a permission base with and without its slash, a refresh
//      token its client's alone, and an RFC 8693 token's `act` carried to
//      the resource server it is for and to nobody else;
//   5. a named server's profile refusing the RS256 default (STS-OAUTH-0296)
//      and an unlisted auth method (STS-OAUTH-0295), a removed member not
//      checking, the document matching;
//   6. OAuth 2.1's two-method refusal in its realm and not outside it;
//   7. `/admin-api/crypto`'s introspection rows against the discovery
//      document.
//
// NOT CARRIED, and why: the Accept table, section 6's defaults, the
// inactive claim's rebuild and the recipient-key parsing (1a–1z) and the
// registry's checker called directly (2a–2f) are library — (d); what they
// decide is what the sections above observe. 4m's nested `act` chain and
// `may_act` were a token signed in process with the realm's key; here the
// `act` is the one a real RFC 8693 exchange issues, which carries no
// `may_act`, so the nesting two levels deep and `may_act` stay (d).
//
// OWNED HERE (local: true).
// ---------------------------------------------------------------------------

const assert = require("assert");
const nodeCrypto = require("crypto");
const K = require("./oauth_wire_kit.js").kit("sts_rfc9701_introspection");
const log = K.log;

const JWT = "application/token-introspection+jwt";
const CLIENT_SECRET = "r97-client-secret-" + K.rand(12);
const RS_SECRET = "r97-rs-secret-" + K.rand(12);
const API_SECRET = "r97-api-secret-" + K.rand(12);
const AUD_SECRET = "r97-aud-secret-" + K.rand(12);
const PERM_SECRET = "r97-perm-secret-" + K.rand(12);
const PERSON = "r97-alice-" + K.STAMP;
const PASSWORD = "R97-" + K.rand(9) + "-pw!";
const FLOOR = 45;

let D;
let O21;
let ISS;
let JWKS;
let TOKEN;

function check(what, fn) {
  K.check(what, fn);
}

function part(token, i) {
  log.debug("Entering part().");
  let out = {};
  try {
    out = JSON.parse(Buffer.from(String(token).split(".")[i], "base64url")
      .toString("utf8"));
  } catch (e) {
    log.debug("Caught in part(): " + ((e && e.message) || e));
    // Not a JWT; the caller's assertion fails on the empty object.
    out = {};
  }
  log.debug("Leaving part().");
  return out;
}

// THIS FILE'S OWN JWS CHECK — node's crypto and nothing from the service.
function verifies(token, jwks, secret) {
  log.debug("Entering verifies().");
  const pieces = String(token).split(".");
  const head = part(token, 0);
  const data = Buffer.from(pieces[0] + "." + pieces[1]);
  const signature = Buffer.from(pieces[2] || "", "base64url");
  const digest = "sha" + String(head.alg).slice(2);
  let ok = false;
  if (/^HS/.test(head.alg)) {
    const mac = nodeCrypto.createHmac(digest, secret).update(data).digest();
    ok = mac.length === signature.length &&
         nodeCrypto.timingSafeEqual(mac, signature);
  } else {
    const key = ((jwks && jwks.keys) || []).filter(function (one) {
      return one.kid === head.kid;
    })[0];
    if (key) {
      const publicKey = nodeCrypto.createPublicKey({ key: key,
                                                     format: "jwk" });
      const opts = /^ES/.test(head.alg)
        ? { key: publicKey, dsaEncoding: "ieee-p1363" }
        : (/^PS/.test(head.alg)
          ? { key: publicKey,
              padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
              saltLength: Number(head.alg.slice(2)) / 8 }
          : publicKey);
      ok = nodeCrypto.verify(digest, data, opts, signature);
    }
  }
  log.debug("Leaving verifies(). " + ok);
  return ok;
}

// THIS FILE'S OWN JWE — RSA-OAEP-256 and A128CBC-HS256 (RFC 7518 5.2.2.1).
function decrypts(compact, privateKey) {
  log.debug("Entering decrypts().");
  const pieces = String(compact).split(".");
  const cek = nodeCrypto.privateDecrypt({ key: privateKey, oaepHash: "sha256",
    padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING },
    Buffer.from(pieces[1], "base64url"));
  const iv = Buffer.from(pieces[2], "base64url");
  const ciphertext = Buffer.from(pieces[3], "base64url");
  const aad = Buffer.from(pieces[0], "ascii");
  const al = Buffer.alloc(8);
  al.writeBigUInt64BE(BigInt(aad.length * 8));
  const tag = nodeCrypto.createHmac("sha256", cek.subarray(0, 16))
    .update(Buffer.concat([aad, iv, ciphertext, al])).digest()
    .subarray(0, 16);
  if (!nodeCrypto.timingSafeEqual(tag, Buffer.from(pieces[4], "base64url"))) {
    log.debug("Leaving decrypts(). The tag did not verify.");
    throw new Error("the authentication tag did not verify");
  }
  const decipher = nodeCrypto.createDecipheriv("aes-128-cbc",
                                               cek.subarray(16), iv);
  log.debug("Leaving decrypts().");
  return Buffer.concat([decipher.update(ciphertext), decipher.final()])
    .toString("utf8");
}

function introspect(realm, headers, form, prefix) {
  log.debug("Entering introspect().");
  log.debug("Leaving introspect().");
  return K.send(K.rb(realm) + (prefix || "") + "/oauth2/introspect", {
    headers: headers || {}, form: Object.assign({ token: TOKEN },
                                                form || {}) });
}

function rsBasic() {
  log.debug("Entering rsBasic().");
  log.debug("Leaving rsBasic().");
  return K.basic("r97-rs", RS_SECRET);
}

function asJwt(token, id, secret, prefix) {
  log.debug("Entering asJwt().");
  log.debug("Leaving asJwt().");
  return K.send(K.rb(D) + (prefix || "") + "/oauth2/introspect", {
    headers: { Accept: JWT },
    form: { token: token, client_id: id, client_secret: secret } });
}

function activeIn(r) {
  log.debug("Entering activeIn().");
  log.debug("Leaving activeIn().");
  return r.status === 200 &&
    (part(r.text, 1).token_introspection || {}).active === true;
}

function inactiveAlone(r) {
  log.debug("Entering inactiveAlone().");
  log.debug("Leaving inactiveAlone().");
  return r.status === 200 && JSON.stringify(part(r.text, 1)
    .token_introspection) === "{\"active\":false}";
}

async function tokenFor(form) {
  log.debug("Entering tokenFor().");
  const r = await K.send(K.rb(D) + "/oauth2/token", { form: Object.assign({
    client_id: "r97-client", client_secret: CLIENT_SECRET }, form) });
  log.debug("Leaving tokenFor(). " + r.status);
  return r.json || {};
}

function rsSet(attribute, value) {
  log.debug("Entering rsSet(). " + attribute);
  log.debug("Leaving rsSet().");
  return K.send(K.rb(D) + "/admin-api/applications/set", { json: {
    application: "r97-rs", attribute: attribute, value: value } });
}

// ----------------------------------------------------------------- 3: JWT
async function theJwt() {
  log.debug("Entering theJwt().");
  log.info("=== 3. RFC 7662 and the JWT ===");
  let r = await introspect(D, {});
  check("3b. development: anonymous JSON introspection is unchanged, and " +
        "varies on Accept", function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.strictEqual(r.json.active, true);
    assert.strictEqual(r.json.client_id, "r97-client");
    assert.ok(/^application\/json/.test(r.headers.get("content-type")));
    assert.ok(/Accept/.test(r.headers.get("vary") || ""));
  });
  let c = await K.coded(D, "STS-OAUTH-0291", function () {
    return introspect(D, { Accept: JWT });
  });
  check("3d. section 5: an anonymous JWT request is refused 400 " +
        "invalid_client (STS-OAUTH-0291)", function () {
    assert.strictEqual(c.answer.status, 400, K.shown(c.answer));
    assert.strictEqual(c.answer.json.error, "invalid_client");
    assert.ok(/RFC 9701 section 5/.test(c.answer.json.error_description));
    assert.ok(c.rose >= 1);
  });
  r = await introspect(D, { Accept: JWT,
                            Authorization: K.basic("r97-rs", "wrong") });
  const noCredential = await introspect(D, { Accept: JWT },
                                        { client_id: "r97-client" });
  check("3e. a wrong secret, and a client_id with no credential, are " +
        "refused the same way", function () {
    assert.ok(r.status === 400 && r.json.error === "invalid_client",
              K.shown(r));
    assert.strictEqual(noCredential.status, 400, K.shown(noCredential));
  });
  r = await introspect(D, { Accept: JWT, Authorization: rsBasic() });
  const head = part(r.text, 0);
  const claims = part(r.text, 1);
  const inner = claims.token_introspection || {};
  check("3g. section 5: 200 with Content-Type exactly " + JWT, function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.strictEqual(r.headers.get("content-type"), JWT);
  });
  check("3h. header typ token-introspection+jwt, alg RS256 by default, " +
        "verified against /oauth2/jwks by this file's own verifier",
        function () {
    assert.strictEqual(head.typ, "token-introspection+jwt");
    assert.strictEqual(head.alg, "RS256");
    assert.ok(verifies(r.text, JWKS));
  });
  check("3j. iss is this authorization server, aud the resource server, " +
        "iat now; no sub and no exp at the top", function () {
    assert.strictEqual(claims.iss, ISS);
    assert.strictEqual(claims.aud, "r97-rs");
    assert.ok(Math.abs(claims.iat - Date.now() / 1000) < 60);
    assert.ok(!("sub" in claims) && !("exp" in claims));
  });
  check("3l. token_introspection is the RFC 7662 answer", function () {
    assert.strictEqual(inner.active, true);
    assert.strictEqual(inner.client_id, "r97-client");
    assert.ok(inner.jti);
    assert.strictEqual(inner.token_type, "Bearer");
  });
  r = await introspect(D, { Accept: JWT, Authorization: rsBasic() },
                       { token: "not-a-token" });
  check("3m. an inactive token: token_introspection is {\"active\":false} " +
        "alone", function () {
    assert.ok(inactiveAlone(r), K.shown(r));
  });
  r = await introspect(D, { Accept: "application/json, " + JWT + ";q=0.2",
                            Authorization: rsBasic() });
  check("3n. JSON preferred in Accept is answered as JSON", function () {
    assert.ok(r.status === 200 && r.json && r.json.active === true,
              K.shown(r));
  });
  r = await introspect(D, { Accept: JWT }, { client_id: "r97-rs",
                                             client_secret: RS_SECRET });
  check("3o. client_secret_post authenticates too", function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.strictEqual(part(r.text, 1).aud, "r97-rs");
  });

  log.info("=== 3. what the resource server registers ===");
  let w = await rsSet("oauthIntrospectionSignedResponseAlg", "ES256");
  r = await introspect(D, { Accept: JWT, Authorization: rsBasic() });
  check("3q. ES256 set through the registry: the response is ES256 and " +
        "verifies with the published EC key", function () {
    assert.strictEqual(w.status, 200, K.shown(w));
    assert.strictEqual(part(r.text, 0).alg, "ES256");
    assert.ok(verifies(r.text, JWKS));
  });
  await rsSet("oauthIntrospectionSignedResponseAlg", "HS256");
  r = await introspect(D, { Accept: JWT, Authorization: rsBasic() });
  check("3r. HS256 is keyed by the client secret and names no kid",
        function () {
    assert.strictEqual(part(r.text, 0).alg, "HS256", K.shown(r));
    assert.ok(verifies(r.text, null, RS_SECRET));
    assert.ok(!part(r.text, 0).kid);
  });
  c = await K.coded(D, "STS-REG-0073", function () {
    return rsSet("oauthIntrospectionSignedResponseAlg", "none");
  });
  check("3s. `none` is refused at the registry (STS-REG-0073)", function () {
    assert.ok(c.answer.status >= 400 || c.answer.json.ok === false,
              K.shown(c.answer));
    assert.ok(c.rose >= 1);
  });
  w = await rsSet("oauthIntrospectionEncryptedResponseEnc", "A128CBC-HS256");
  check("3t. an enc onto an entry with no alg is refused", function () {
    assert.ok(w.status >= 400 || w.json.ok === false, K.shown(w));
  });
  const pair = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const encJwk = Object.assign(pair.publicKey.export({ format: "jwk" }),
                               { kid: "r97-enc", use: "enc" });
  await rsSet("oauthJwks", JSON.stringify({ keys: [encJwk] }));
  await rsSet("oauthIntrospectionSignedResponseAlg", "");
  w = await rsSet("oauthIntrospectionEncryptedResponseAlg", "RSA-OAEP-256");
  r = await introspect(D, { Accept: JWT, Authorization: rsBasic() });
  const outer = part(r.text, 0);
  check("3v. a Nested JWT: RSA-OAEP-256, the default enc, cty JWT, the " +
        "typ, and the registered key's kid", function () {
    assert.strictEqual(w.status, 200, K.shown(w));
    assert.strictEqual(r.text.split(".").length, 5, K.shown(r));
    assert.strictEqual(outer.alg, "RSA-OAEP-256");
    assert.strictEqual(outer.enc, "A128CBC-HS256");
    assert.strictEqual(outer.cty, "JWT");
    assert.strictEqual(outer.typ, "token-introspection+jwt");
    assert.strictEqual(outer.kid, "r97-enc");
  });
  const opened = decrypts(r.text, pair.privateKey);
  check("3w. this file decrypts it to a signed JWT that verifies",
        function () {
    assert.strictEqual(opened.split(".").length, 3);
    assert.strictEqual(part(opened, 0).typ, "token-introspection+jwt");
    assert.ok(verifies(opened, JWKS));
    assert.strictEqual(part(opened, 1).aud, "r97-rs");
  });
  // A REGISTRATION NOTHING CAN HONOUR: the registry refuses an enc without
  // an alg (3t), so the lone enc is left behind by setting the enc while
  // the alg is there and then clearing the alg, as an ldapmodify would.
  await rsSet("oauthIntrospectionEncryptedResponseEnc", "A256GCM");
  await rsSet("oauthIntrospectionEncryptedResponseAlg", "");
  c = await K.coded(D, "STS-OAUTH-0293", function () {
    return introspect(D, { Accept: JWT, Authorization: rsBasic() });
  });
  await rsSet("oauthIntrospectionEncryptedResponseEnc", "");
  check("3x. an enc left without an alg: 500 with the reason, never an " +
        "unencrypted response (STS-OAUTH-0293)", function () {
    assert.strictEqual(c.answer.status, 500, K.shown(c.answer));
    assert.strictEqual(c.answer.json.error, "server_error");
    assert.ok(/MUST NOT/.test(c.answer.json.error_description));
    assert.ok(c.rose >= 1);
  });
  await rsSet("oauthJwks", "");

  log.info("=== 3. RFC 7591 and the metadata ===");
  c = await K.coded(D, "STS-REG-0072", function () {
    return K.send(K.rb(D) + "/oauth2/register", { json: {
      client_name: "r97 bad", grant_types: ["client_credentials"],
      introspection_signed_response_alg: "none" } });
  });
  check("3y. registration naming `none` is invalid_client_metadata " +
        "(STS-REG-0072)", function () {
    assert.strictEqual(c.answer.status, 400, K.shown(c.answer));
    assert.strictEqual(c.answer.json.error, "invalid_client_metadata");
    assert.ok(c.rose >= 1);
  });
  r = await K.send(K.rb(D) + "/oauth2/register", { json: {
    client_name: "r97 registered " + K.STAMP,
    grant_types: ["client_credentials"],
    token_endpoint_auth_method: "client_secret_post",
    introspection_signed_response_alg: "PS384" } });
  const registered = r.json || {};
  const asRegistered = await K.send(K.rb(D) + "/oauth2/introspect", {
    headers: { Accept: JWT }, form: { token: TOKEN,
      client_id: registered.client_id,
      client_secret: registered.client_secret } });
  check("3z. a registration naming PS384 is accepted and echoes it",
        function () {
    assert.ok(r.status === 201 || r.status === 200, K.shown(r));
    assert.strictEqual(registered.introspection_signed_response_alg,
                       "PS384");
  });
  check("3ab. and the registered client's response is PS384, verifying",
        function () {
    assert.strictEqual(asRegistered.status, 200, K.shown(asRegistered));
    assert.strictEqual(part(asRegistered.text, 0).alg, "PS384");
    assert.strictEqual(part(asRegistered.text, 1).aud,
                       registered.client_id);
    assert.ok(verifies(asRegistered.text, JWKS));
  });
  const meta = (await K.send(K.rb(D) +
    "/.well-known/oauth-authorization-server")).json;
  check("3ac. section 7: the three members are published, none excluded",
        function () {
    const s = meta.introspection_signing_alg_values_supported;
    assert.ok(Array.isArray(s) && s.indexOf("RS256") >= 0 &&
              s.indexOf("none") < 0, JSON.stringify(s));
    assert.ok(Array.isArray(
      meta.introspection_encryption_alg_values_supported));
    assert.ok(meta.introspection_encryption_enc_values_supported
      .indexOf("A128CBC-HS256") >= 0);
  });
  check("3ad. the introspection auth methods are the verifiable ones",
        function () {
    assert.ok(meta.introspection_endpoint_auth_methods_supported
      .indexOf("client_secret_jwt") >= 0);
  });
  r = await introspect(D, { Accept: JWT, Authorization: rsBasic() }, {},
                       "/tenant9701");
  check("3ae. a named authorization server signs as its own issuer",
        function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.strictEqual(part(r.text, 1).iss, ISS + "/tenant9701");
  });
  log.debug("Leaving theJwt().");
  return meta;
}

// -------------------------------------------------------- 4: intended for
async function intendedFor() {
  log.debug("Entering intendedFor().");
  log.info("=== 4. section 5's intended-for rule ===");
  const apiToken = (await tokenFor({ grant_type: "client_credentials",
                                     scope: "r97-api" })).access_token;
  check("4a. a token addressed to r97-api by its scope", function () {
    assert.ok(apiToken && part(apiToken, 1).aud === "r97-api",
              JSON.stringify(part(apiToken, 1).aud));
  });
  let r = await asJwt(apiToken, "r97-rs", RS_SECRET);
  check("4b. r97-rs asking about r97-api's token is told " +
        "{\"active\":false} and nothing else", function () {
    assert.ok(inactiveAlone(r), K.shown(r));
  });
  r = await asJwt(apiToken, "r97-api", API_SECRET);
  const own = await asJwt(apiToken, "r97-client", CLIENT_SECRET);
  check("4c. r97-api, named in aud, is told it is active; and so is the " +
        "client holding the token", function () {
    assert.ok(activeIn(r), K.shown(r));
    assert.ok(activeIn(own), K.shown(own));
  });
  r = await K.send(K.rb(D) + "/oauth2/introspect",
                   { form: { token: apiToken } });
  const unchecked = await K.send(K.rb(D) + "/oauth2/introspect",
    { form: { token: apiToken, client_id: "r97-rs",
              client_secret: RS_SECRET } });
  check("4e. an anonymous development JSON caller, and one whose " +
        "credential nothing checked, are NOT restricted", function () {
    assert.ok(r.status === 200 && r.json.active === true, K.shown(r));
    assert.ok(unchecked.status === 200 && unchecked.json.active === true,
              K.shown(unchecked));
  });
  const audToken = (await tokenFor({ grant_type: "client_credentials",
    resource: "https://api.r97.example/" })).access_token;
  r = await asJwt(audToken, "r97-aud", AUD_SECRET);
  const notApi = await asJwt(audToken, "r97-api", API_SECRET);
  check("4g. an RFC 8707 resource matching the caller's oauthAudience is " +
        "intended for it, and not for another resource server",
        function () {
    assert.ok(activeIn(r), K.shown(r));
    assert.ok(notApi.status === 200 && !activeIn(notApi), K.shown(notApi));
  });
  const permToken = (await tokenFor({ grant_type: "password",
    username: PERSON, password: PASSWORD,
    scope: "https://perm.r97.example/read" })).access_token;
  r = await asJwt(permToken, "r97-perm", PERM_SECRET);
  check("4i. a delegated permission's base URI names the resource that " +
        "defines it", function () {
    assert.ok(permToken, "no permission token");
    assert.ok(activeIn(r), K.shown(r));
  });
  const bareToken = (await tokenFor({ grant_type: "client_credentials",
    resource: "https://perm.r97.example" })).access_token;
  r = await asJwt(bareToken, "r97-perm", PERM_SECRET);
  check("4i2. and a resource naming that base without its trailing slash " +
        "still names it", function () {
    assert.ok(activeIn(r), K.shown(r));
    assert.strictEqual(part(bareToken, 1).aud, "https://perm.r97.example");
  });
  const grant = await tokenFor({ grant_type: "password", username: PERSON,
    password: PASSWORD, scope: "openid offline_access" });
  const refresh = grant.refresh_token;
  r = await asJwt(refresh, "r97-rs", RS_SECRET);
  const ownRefresh = await asJwt(refresh, "r97-client", CLIENT_SECRET);
  check("4k. a refresh token is not a resource server's to ask about, but " +
        "its own client may", function () {
    assert.ok(refresh, JSON.stringify(Object.keys(grant)));
    assert.ok(r.status === 200 && !activeIn(r), K.shown(r));
    assert.ok(activeIn(ownRefresh), K.shown(ownRefresh));
    assert.strictEqual(part(ownRefresh.text, 1).token_introspection
      .token_type, "refresh_token");
  });

  // 4m-4p: an RFC 8693 delegation's `act`, introspected.
  const subject = (await tokenFor({ grant_type: "password",
    username: PERSON, password: PASSWORD, scope: "r97-api" })).access_token;
  // The actor is the client itself: a client_credentials token asking for
  // nothing else is addressed to it.
  const actor = (await tokenFor({ grant_type: "client_credentials" }))
    .access_token;
  const ex = await K.send(K.rb(D) + "/oauth2/token", { form: {
    client_id: "r97-client", client_secret: CLIENT_SECRET,
    grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
    subject_token: subject,
    subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
    actor_token: actor,
    actor_token_type: "urn:ietf:params:oauth:token-type:access_token",
    scope: "r97-api" } });
  const delegated = ex.json && ex.json.access_token;
  const act = part(delegated, 1).act;
  r = await K.send(K.rb(D) + "/oauth2/introspect",
                   { form: { token: delegated } });
  check("4m. RFC 7662 JSON carries an exchanged token's act as in the " +
        "token", function () {
    assert.strictEqual(ex.status, 200, K.shown(ex));
    assert.ok(act && act.sub, JSON.stringify(part(delegated, 1)));
    assert.ok(r.status === 200 && r.json.active === true, K.shown(r));
    assert.deepStrictEqual(r.json.act, act);
  });
  r = await asJwt(delegated, "r97-api", API_SECRET);
  const elsewhere = await asJwt(delegated, "r97-rs", RS_SECRET);
  const plain = await K.send(K.rb(D) + "/oauth2/introspect",
                             { form: { token: apiToken } });
  check("4n. and so does RFC 9701's JWT, to the resource server it is for",
        function () {
    assert.ok(activeIn(r), K.shown(r));
    assert.deepStrictEqual(part(r.text, 1).token_introspection.act, act);
  });
  check("4o. a resource server the token is not for learns nothing of its " +
        "actors; a token carrying none has none", function () {
    assert.ok(inactiveAlone(elsewhere), K.shown(elsewhere));
    assert.ok(plain.status === 200 && !("act" in plain.json) &&
              !("may_act" in plain.json), K.shown(plain));
  });
  log.debug("Leaving intendedFor().");
  return apiToken;
}

// ---------------------------------------------------------- 5, 6, 7, prod
async function profilesModes(meta, apiToken) {
  log.debug("Entering profilesModes().");
  log.info("=== 5. a named authorization server narrows ===");
  const api = K.rb(D) + "/admin-api/authorization-servers";
  await K.ok(api + "/create", { id: "r97narrow" }, "created r97narrow");
  await K.ok(api + "/set", { profile: "r97narrow",
    member: "introspection_signing_alg_values_supported",
    value: "[\"PS256\"]" }, "narrowed the signing list");
  let c = await K.coded(D, "STS-OAUTH-0296", function () {
    return introspect(D, { Accept: JWT, Authorization: rsBasic() }, {},
                      "/r97narrow");
  });
  let r = await introspect(D, { Accept: JWT, Authorization: rsBasic() });
  check("5a. a profile advertising only PS256 refuses a resource server " +
        "on the RS256 default, 400, naming the list (STS-OAUTH-0296)",
        function () {
    assert.strictEqual(c.answer.status, 400, K.shown(c.answer));
    assert.strictEqual(c.answer.json.error, "invalid_client");
    assert.ok(/PS256/.test(c.answer.json.error_description) &&
              /default/.test(c.answer.json.error_description));
    assert.ok(c.rose >= 1);
  });
  check("5b. the default authorization server is unaffected", function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.strictEqual(part(r.text, 0).alg, "RS256");
  });
  await K.ok(api + "/set", { profile: "r97narrow",
    member: "introspection_signing_alg_values_supported",
    value: "[\"RS256\",\"PS256\"]" }, "widened the signing list");
  await K.ok(api + "/set", { profile: "r97narrow",
    member: "introspection_endpoint_auth_methods_supported",
    value: "[\"private_key_jwt\"]" }, "narrowed the auth methods");
  c = await K.coded(D, "STS-OAUTH-0295", function () {
    return introspect(D, { Accept: JWT, Authorization: rsBasic() }, {},
                      "/r97narrow");
  });
  check("5c. a profile not advertising client_secret_basic refuses that " +
        "client before its secret is read (STS-OAUTH-0295)", function () {
    assert.strictEqual(c.answer.status, 400, K.shown(c.answer));
    assert.ok(/private_key_jwt/.test(c.answer.json.error_description));
    assert.ok(c.rose >= 1);
  });
  await K.ok(api + "/remove", { profile: "r97narrow",
    member: "introspection_endpoint_auth_methods_supported" },
    "removed the auth methods member");
  r = await introspect(D, { Accept: JWT, Authorization: rsBasic() }, {},
                       "/r97narrow");
  const narrowed = (await K.send(K.rb(D) +
    "/.well-known/oauth-authorization-server/r97narrow")).json;
  check("5d. a REMOVED member means the check does not run", function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.strictEqual(part(r.text, 1).iss, ISS + "/r97narrow");
  });
  check("5e. and the document says exactly what the endpoint did",
        function () {
    assert.deepStrictEqual(
      narrowed.introspection_signing_alg_values_supported,
      ["RS256", "PS256"]);
    assert.ok(!("introspection_endpoint_auth_methods_supported" in
                narrowed));
  });

  log.info("=== 6. OAuth 2.1 section 2.4 at introspection ===");
  r = await K.send(K.rb(O21) + "/oauth2/introspect", {
    form: { token: TOKEN, client_secret: RS_SECRET },
    headers: { Authorization: rsBasic() } });
  const outside = await K.send(K.rb(D) + "/oauth2/introspect", {
    form: { token: TOKEN, client_secret: RS_SECRET },
    headers: { Authorization: rsBasic() } });
  check("6b. OAuth 2.1: Basic AND a body secret on one introspection " +
        "request is refused, even for JSON; outside the mode it is " +
        "answered", function () {
    assert.strictEqual(r.status, 400, K.shown(r));
    assert.strictEqual(r.json.error, "invalid_request");
    assert.ok(/2\.4/.test(r.json.error_description));
    assert.strictEqual(outside.status, 200, K.shown(outside));
  });

  log.info("=== 7. the crypto-metadata page ===");
  const cm = await K.send(K.rb(D) + "/admin-api/crypto");
  const rowOf = function (label) {
    log.debug("Entering rowOf().");
    let found = null;
    ((cm.json && cm.json.families) || []).forEach(function (family) {
      (family.algorithms || []).forEach(function (row) {
        if (row.what === label) {
          found = row.values;
        }
      });
    });
    log.debug("Leaving rowOf().");
    return found;
  };
  check("7a. /admin-api/crypto lists the introspection algorithms the " +
        "discovery document advertises", function () {
    assert.deepStrictEqual(rowOf("JWT introspection response (RFC 9701)"),
      meta.introspection_signing_alg_values_supported);
    assert.deepStrictEqual(
      rowOf("JWT introspection response encryption (RFC 9701)"),
      meta.introspection_encryption_alg_values_supported);
  });

  log.info("=== 3af. product mode ===");
  await K.set(D, "global.mode", "product");
  let anon;
  let authed;
  let restricted;
  try {
    anon = await K.coded(D, "STS-OAUTH-0292", function () {
      return introspect(D, {});
    });
    authed = await introspect(D, { Authorization: rsBasic() });
    restricted = await K.send(K.rb(D) + "/oauth2/introspect", {
      form: { token: apiToken }, headers: { Authorization: rsBasic() } });
  } finally {
    await K.set(D, "global.mode", "development");
  }
  check("3af. product: anonymous JSON introspection is refused 401 " +
        "(STS-OAUTH-0292)", function () {
    assert.strictEqual(anon.answer.status, 401, K.shown(anon.answer));
    assert.strictEqual(anon.answer.json.error, "invalid_client");
    assert.ok(anon.rose >= 1);
  });
  check("3ag. product: an authenticated JSON request is answered",
        function () {
    assert.ok(authed.status === 200 && authed.json.active === true,
              K.shown(authed));
  });
  check("3ah. product: the JSON answer is restricted like the JWT — " +
        "r97-api's token is {\"active\":false} to r97-rs", function () {
    assert.strictEqual(restricted.status, 200, K.shown(restricted));
    assert.strictEqual(JSON.stringify(restricted.json),
                       "{\"active\":false}");
  });
  log.debug("Leaving profilesModes().");
}

async function test() {
  log.debug("Entering test().");
  D = await K.realm("r97", "development");
  O21 = await K.realm("r97o21", "development", { "oauth2.oauth21": true });
  ISS = (await K.send(K.rb(D) + "/.well-known/oauth-authorization-server"))
    .json.issuer;
  await K.person(D, PERSON, PASSWORD);
  const post = function (id, secret, extra) {
    log.debug("Entering post().");
    log.debug("Leaving post().");
    return Object.assign({ oauthClientId: id, oauthClientSecret: secret,
      oauthTokenEndpointAuthMethod: "client_secret_post" }, extra || {});
  };
  await K.app(D, "r97-client", post("r97-client", CLIENT_SECRET, {
    oauthGrantType: ["client_credentials", "password", "refresh_token",
                     "urn:ietf:params:oauth:grant-type:token-exchange"] }));
  for (const realm of [D, O21]) {
    await K.app(realm, "r97-rs", { oauthClientId: "r97-rs",
      oauthClientSecret: RS_SECRET,
      oauthTokenEndpointAuthMethod: "client_secret_basic" });
  }
  await K.app(D, "r97-api", post("r97-api", API_SECRET));
  await K.app(D, "r97-aud", post("r97-aud", AUD_SECRET,
    { oauthAudience: ["https://api.r97.example/"] }));
  await K.app(D, "r97-perm", post("r97-perm", PERM_SECRET,
    { oauthPermissionBaseUri: "https://perm.r97.example",
      oauthPermission: ["read|reads things"] }));
  const issued = await tokenFor({ grant_type: "client_credentials",
                                  scope: "r97-rs" });
  TOKEN = issued.access_token;
  check("3a. a token to introspect was issued, addressed to r97-rs",
        function () {
    assert.ok(TOKEN, JSON.stringify(issued));
  });
  JWKS = (await K.send(K.rb(D) + "/oauth2/jwks")).json;
  const meta = await theJwt();
  const apiToken = await intendedFor();
  await profilesModes(meta, apiToken);
  log.debug("Leaving test().");
}

K.main(test, FLOOR);
