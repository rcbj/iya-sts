// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_pki_codes.js
//
// ---------------------------------------------------------------------------
// THE CERTIFICATE AUTHORITY'S BUILD REFUSALS, THE PIN SLOTS, AND A PINNED
// KEY THAT SIGNS, OVER THE WIRE.
//
// D12 (#444): what `sts_pki_rules.js` and `sts_signer_trust.js` left owed of
// `tests/pki_defaults.js`, `tests/pki_hybrid.js`,
// `tests/pki_rebuild_recertifies.js` and `tests/pinned_signers.js`, each
// refusal's code read off the realm's audit log:
//
//   A. THE BUILD: an alternative key algorithm that is no pure post-quantum
//      signature algorithm (the request schema's STS-API-0009 before
//      STS-PKI-0200); a composite ML-DSA key asked of
//      the build itself (STS-PKI-0274, where the setting falls back); a
//      signature algorithm the key cannot produce (STS-PKI-0004);
//   B. THE PIN SLOTS: an xml slot other than RS256 (STS-PKI-0208); the xml
//      RS256 slot with a certificate whose keyUsage lacks keyEncipherment
//      (STS-PKI-0217);
//   C. A PINNED KEY SIGNS: with `pki.pinnedSignerLeadMinutes` 0 a pinned
//      RS256 key signs the realm's next access token at once — the token's
//      `kid` is the pinned key's, and it verifies under the published JWK.
//
// OWNED HERE (local: true): this repository's own certificate authority.
// ---------------------------------------------------------------------------

const assert = require("assert");
const nodeCrypto = require("crypto");
const forge = require("node-forge");
const K = require("./oauth_wire_kit.js").kit("sts_pki_codes");
const log = K.log;

const FLOOR = 8;

function check(what, fn) {
  log.debug("Entering check().");
  K.check(what, fn);
  log.debug("Leaving check().");
}

function refused(what, out, code) {
  log.debug("Entering refused(). " + code);
  check(what + " (" + code + ")", function () {
    assert.ok(out.answer.status >= 400, K.shown(out.answer));
    assert.ok(out.rose >= 1, code + " rows: " + out.rose + "; " +
              K.shown(out.answer));
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(out.answer.text), "a code was sent");
  });
  log.debug("Leaving refused().");
}

function post(realm, path, body, code) {
  log.debug("Entering post(). " + path);
  log.debug("Leaving post().");
  return K.coded(realm, code, function () {
    return K.send(K.rb(realm) + "/admin-api" + path, { json: body });
  });
}

// A self-signed certificate over an RSA key, with the keyUsage given.
function rsaWithCertificate(keyUsage) {
  log.debug("Entering rsaWithCertificate().");
  const pair = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const privatePem = pair.privateKey.export({ type: "pkcs8", format: "pem" });
  const c = forge.pki.createCertificate();
  c.publicKey = forge.pki.publicKeyFromPem(pair.publicKey.export({
    type: "spki", format: "pem" }));
  c.serialNumber = "01" + nodeCrypto.randomBytes(8).toString("hex");
  c.validity.notBefore = new Date(Date.now() - 60000);
  c.validity.notAfter = new Date(Date.now() + 30 * 86400000);
  const subject = [{ name: "commonName", value: "pinned " + K.STAMP }];
  c.setSubject(subject);
  c.setIssuer(subject);
  c.setExtensions([Object.assign({ name: "keyUsage", critical: true },
                                 keyUsage)]);
  c.sign(forge.pki.privateKeyFromPem(privatePem), forge.md.sha256.create());
  log.debug("Leaving rsaWithCertificate().");
  return { privatePem: privatePem,
           certificatePem: forge.pki.certificateToPem(c) };
}

async function build() {
  log.debug("Entering build().");
  log.info("=== A. the build's refusals ===");
  const realm = await K.realm("pkicodes");
  // The request schema refuses an unknown altKeyAlg first (STS-API-0009),
  // naming the values it takes, so STS-PKI-0200 is not reached here.
  const alt = await post(realm, "/pki/build", { organisation: "Codes",
    altKeyAlg: "ml-kem-768" }, "STS-API-0009");
  check("A1. an alternative key algorithm that is no post-quantum " +
        "signature algorithm is refused, the values it takes named",
        function () {
    assert.strictEqual(alt.answer.status, 400, K.shown(alt.answer));
    assert.ok(/ml-dsa-65/.test(alt.answer.text), K.shown(alt.answer));
    assert.ok(alt.rose >= 1, "STS-API-0009 rows: " + alt.rose);
  });
  refused("A2. a composite ML-DSA key asked of the build is refused",
    await post(realm, "/pki/build", { organisation: "Codes",
      keyAlg: "mldsa44-rsa2048-pss-sha256" }, "STS-PKI-0274"),
    "STS-PKI-0274");
  refused("A3. a signature algorithm the key cannot produce is refused",
    await post(realm, "/pki/build", { organisation: "Codes",
      keyAlg: "rsa-2048", signatureAlg: "sha256-ecdsa" }, "STS-PKI-0004"),
    "STS-PKI-0004");
  log.debug("Leaving build().");
}

function kidOf(token) {
  log.debug("Entering kidOf().");
  log.debug("Leaving kidOf().");
  return JSON.parse(Buffer.from(String(token).split(".")[0], "base64url")
    .toString()).kid;
}

async function pins() {
  log.debug("Entering pins().");
  log.info("=== B. the pin slots, and C. a pinned key signing ===");
  const realm = await K.realm("pkipins");
  await K.ok(K.rb(realm) + "/admin-api/pki/build", { organisation: "Pins" },
             "built the CA");
  await K.set(realm, "pki.pinnedSigners", true);
  const signer = rsaWithCertificate({ digitalSignature: true,
                                      keyEncipherment: true });
  refused("B1. an xml slot other than RS256 is no slot a pinned key signs " +
          "from",
    await post(realm, "/pki/pin-key", { useCase: "xml", slot: "ES256",
      privateKeyPem: nodeCrypto.generateKeyPairSync("ec", {
        namedCurve: "P-256" }).privateKey.export({ type: "pkcs8",
                                                   format: "pem" }) },
      "STS-PKI-0208"), "STS-PKI-0208");
  const noEncipher = rsaWithCertificate({ digitalSignature: true });
  refused("B2. the xml RS256 slot refuses a certificate whose keyUsage " +
          "lacks keyEncipherment",
    await post(realm, "/pki/pin-key", { useCase: "xml", slot: "RS256",
      privateKeyPem: noEncipher.privatePem,
      certificatePem: noEncipher.certificatePem }, "STS-PKI-0217"),
    "STS-PKI-0217");
  await K.set(realm, "pki.pinnedSignerLeadMinutes", 0);
  await K.set(realm, "oauth2.accessTokenSigningAlg", "RS256");
  const pinned = await K.send(K.rb(realm) + "/admin-api/pki/pin-key",
    { json: { useCase: "jose", slot: "RS256",
              privateKeyPem: signer.privatePem } });
  const kid = String((pinned.json && pinned.json.kid) || "");
  check("C1. the RS256 key is pinned", function () {
    assert.strictEqual(pinned.status, 200, K.shown(pinned));
    assert.ok(/^sts-pinned-/.test(kid), kid);
  });
  const id = "pkc-" + K.STAMP;
  const secret = "Pkc-" + nodeCrypto.randomBytes(15).toString("base64url");
  await K.app(realm, id, { oauthClientId: [id], oauthClientSecret: secret,
    oauthTokenEndpointAuthMethod: "client_secret_post",
    oauthGrantType: ["client_credentials"] });
  const token = await K.send(K.rb(realm) + "/oauth2/token", { form: {
    grant_type: "client_credentials", client_id: id,
    client_secret: secret } });
  const at = String((token.json && token.json.access_token) || "");
  const jwks = await K.send(K.rb(realm) + "/oauth2/jwks");
  const jwk = ((jwks.json && jwks.json.keys) || []).filter(function (k) {
    return k.kid === kid;
  })[0];
  check("C2. with pki.pinnedSignerLeadMinutes 0 the next access token is " +
        "signed by the pinned key at once", function () {
    assert.strictEqual(token.status, 200, K.shown(token));
    assert.strictEqual(kidOf(at), kid, "signed by " + kidOf(at));
  });
  check("C3. and it verifies under the published JWK", function () {
    assert.ok(jwk, "the pinned kid is not published");
    const parts = at.split(".");
    assert.ok(nodeCrypto.verify("sha256", Buffer.from(parts[0] + "." +
      parts[1]), nodeCrypto.createPublicKey({ key: jwk, format: "jwk" }),
      Buffer.from(parts[2], "base64url")), "the signature does not verify");
  });
  await K.ok(K.rb(realm) + "/admin-api/pki/unpin-key",
             { useCase: "jose", slot: "RS256" }, "unpinned it");
  log.debug("Leaving pins().");
}

async function test() {
  log.debug("Entering test().");
  await build();
  await pins();
  log.debug("Leaving test().");
}

K.main(test, FLOOR);
