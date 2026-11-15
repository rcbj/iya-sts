// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_saml_encrypted_logout.js
//
// ===========================================================================
// AN ENCRYPTED NameID IN A SERVICE PROVIDER'S LogoutRequest, AND THE KEY
// TRANSPORT PRODUCT NEVER UNWRAPS, OVER THE WIRE (#181, #192; #444 D12,
// phase 7).
//
// The SAML 2.0 identity provider decrypts a LogoutRequest's
// `<saml:EncryptedID>` with any of the realm's own RSA keys
// (`saml2_sso.ts`'s singleLogout(), through `helpers.decryptOwnElement()`).
// XML Encryption 1.1 section 6.1.2 forbids RSAES-PKCS1-v1_5 key transport
// for new use, and product mode refuses it before any key operation: the
// LogoutRequest is answered 400 and recorded STS-KEYS-0070, the operator's
// fix being the service provider's algorithm, not its certificate. Here, in
// a development and a product realm, a service provider written here signs
// a LogoutRequest on the Redirect binding whose NameID is encrypted to the
// realm's published encryption certificate (its metadata's
// `KeyDescriptor use="encryption"`) by this file's own XML Encryption:
//
//   K1. product, rsa-1_5: refused 400, STS-KEYS-0070, and not the generic
//       STS-SAML-0020;
//   K2. product, rsa-oaep (SHA-256, MGF1-SHA-256): decrypted and answered
//       with a LogoutResponse, no refusal;
//   K3. development, rsa-1_5: unwrapped, no STS-KEYS-0070 (the mode
//       predicate's other half);
//   K4. an EncryptedID that decrypts under no key of the realm is
//       STS-SAML-0020 in both modes.
//
// OWNED HERE (local: true). Its realms are removed only on a private probe.
// ===========================================================================

const assert = require("assert");
const nodeCrypto = require("crypto");
const K = require("./oauth_wire_kit.js").kit("sts_saml_encrypted_logout");
const S = require("./saml_wire_kit.js").samlKit(K);

const log = K.log;
const XENC = "http://www.w3.org/2001/04/xmlenc#";
const XENC11 = "http://www.w3.org/2009/xmlenc11#";
const DS = "http://www.w3.org/2000/09/xmldsig#";
const NS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol";
const NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion";
const SP = "https://sel-" + K.STAMP + ".example.test/sp";
const SP_SLO = "https://sel-" + K.STAMP + ".example.test/slo";
const SP_ACS = "https://sel-" + K.STAMP + ".example.test/acs";

function el(name, attrs, inner) {
  log.debug("Entering el().");
  log.debug("Leaving el().");
  return "<" + name + (attrs || "") + ">" + (inner || "") + "</" + name + ">";
}

// The NameID encrypted to `certPem`: aes256-gcm content, the key wrapped
// with rsa-1_5 or rsa-oaep (SHA-256, MGF1-SHA-256).
function encryptedId(nameId, certPem, transport) {
  log.debug("Entering encryptedId(). " + transport);
  const recipient = new nodeCrypto.X509Certificate(certPem).publicKey;
  const xml = el("saml:NameID", " xmlns:saml=\"" + NS_SAML + "\" Format=\"" +
                 "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\"",
                 nameId);
  const key = nodeCrypto.randomBytes(32);
  const iv = nodeCrypto.randomBytes(12);
  const c = nodeCrypto.createCipheriv("aes-256-gcm", key, iv);
  const body = Buffer.concat([iv, c.update(Buffer.from(xml, "utf8")),
                              c.final(), c.getAuthTag()]);
  let wrapped;
  let method;
  if (transport === "rsa-1_5") {
    wrapped = nodeCrypto.publicEncrypt({ key: recipient,
      padding: nodeCrypto.constants.RSA_PKCS1_PADDING }, key);
    method = el("xenc:EncryptionMethod", " Algorithm=\"" + XENC +
                "rsa-1_5\"");
  } else {
    wrapped = nodeCrypto.publicEncrypt({ key: recipient,
      padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256" }, key);
    method = el("xenc:EncryptionMethod", " Algorithm=\"" + XENC11 +
                "rsa-oaep\"",
      el("ds:DigestMethod", " Algorithm=\"" + XENC + "sha256\"") +
      el("xenc11:MGF", " xmlns:xenc11=\"" + XENC11 + "\" Algorithm=\"" +
         XENC11 + "mgf1sha256\""));
  }
  log.debug("Leaving encryptedId().");
  return el("saml:EncryptedID", "", el("xenc:EncryptedData",
    " xmlns:xenc=\"" + XENC + "\" Type=\"" + XENC + "Element\"",
    el("xenc:EncryptionMethod", " Algorithm=\"" + XENC11 + "aes256-gcm\"") +
    el("ds:KeyInfo", " xmlns:ds=\"" + DS + "\"", el("xenc:EncryptedKey", "",
      method + el("xenc:CipherData", "", el("xenc:CipherValue", "",
        wrapped.toString("base64"))))) +
    el("xenc:CipherData", "", el("xenc:CipherValue", "",
      body.toString("base64")))));
}

function logoutRequest(realm, inner) {
  log.debug("Entering logoutRequest().");
  log.debug("Leaving logoutRequest().");
  return "<samlp:LogoutRequest xmlns:samlp=\"" + NS_SAMLP +
    "\" xmlns:saml=\"" + NS_SAML + "\" ID=\"_sel-" + K.rand(8) +
    "\" Version=\"2.0\" IssueInstant=\"" + new Date().toISOString() +
    "\" Destination=\"" + K.rb(realm) + "/saml2/slo\"><saml:Issuer>" + SP +
    "</saml:Issuer>" + inner + "</samlp:LogoutRequest>";
}

async function world(mode) {
  log.debug("Entering world(). " + mode);
  const realm = await K.realm("sel-" + mode.slice(0, 1), mode);
  const spKey = await S.credential("sel sp " + K.STAMP);
  await K.ok(K.rb(realm) + "/admin-api/applications/create", {
    identifier: SP, name: SP, protocols: ["saml2"],
    fields: { samlEntityId: [SP], samlAssertionConsumerService: [SP_ACS],
              samlSingleLogoutService: [SP_SLO],
              samlSigningCertificate: [spKey.certificatePem] } },
  "created the SP");
  const md = await K.send(K.rb(realm) + "/saml2/metadata");
  const desc = (/<md:KeyDescriptor use="encryption">[\s\S]*?<\/md:KeyDescriptor>/
    .exec(md.text) || [])[0] || "";
  const der = ((/X509Certificate>([^<]+)</.exec(desc) || [])[1] || "")
    .replace(/\s+/g, "");
  assert.ok(der, "no encryption certificate in " + realm + "'s metadata");
  log.debug("Leaving world().");
  return { realm: realm, spKey: spKey, certPem: "-----BEGIN CERTIFICATE-----" +
    "\n" + (der.match(/.{1,64}/g) || []).join("\n") +
    "\n-----END CERTIFICATE-----\n" };
}

async function send(w, inner, code) {
  log.debug("Entering send().");
  const url = S.redirect(K.rb(w.realm) + "/saml2/slo",
    logoutRequest(w.realm, inner), { sign: w.spKey, relayState: "sel" });
  const got = await K.coded(w.realm, code, function () {
    return K.send(url);
  });
  log.debug("Leaving send(). " + got.answer.status);
  return got;
}

async function test() {
  log.debug("Entering test().");
  const p = await world("product");
  const d = await world("development");
  const stranger = await S.credential("sel stranger " + K.STAMP);
  let got = await send(p, encryptedId("sel-alice", p.certPem, "rsa-1_5"),
                       "STS-KEYS-0070");
  const generic = await K.codeCount(p.realm, "STS-SAML-0020");
  K.check("K1. product: an EncryptedID whose key is wrapped with rsa-1_5 is " +
          "refused 400 (STS-KEYS-0070), not the generic STS-SAML-0020",
  function () {
    assert.strictEqual(got.answer.status, 400, K.shown(got.answer));
    assert.ok(got.rose >= 1, "no STS-KEYS-0070 row");
    assert.strictEqual(generic, 0);
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(got.answer.text));
  });
  got = await send(p, encryptedId("sel-alice", p.certPem, "rsa-oaep"),
                   "STS-KEYS-0070");
  K.check("K2. product: the same NameID under rsa-oaep is decrypted and " +
          "answered with a LogoutResponse", function () {
    assert.ok(got.answer.status === 303 || got.answer.status === 302 ||
              got.answer.status === 200, K.shown(got.answer));
    assert.strictEqual(got.rose, 0);
  });
  got = await send(d, encryptedId("sel-alice", d.certPem, "rsa-1_5"),
                   "STS-KEYS-0070");
  K.check("K3. development: rsa-1_5 is unwrapped, no STS-KEYS-0070",
          function () {
            assert.ok(got.answer.status < 400, K.shown(got.answer));
            assert.strictEqual(got.rose, 0);
          });
  for (const w of [d, p]) {
    got = await send(w, encryptedId("sel-alice", stranger.certificatePem,
                                    "rsa-oaep"), "STS-SAML-0020");
    K.check("K4 (" + (w === p ? "product" : "development") + "). an " +
            "EncryptedID that decrypts under no key of the realm is 400, " +
            "STS-SAML-0020", function () {
      assert.strictEqual(got.answer.status, 400, K.shown(got.answer));
      assert.ok(got.rose >= 1);
    });
  }
  log.debug("Leaving test().");
}

K.main(test, 5);
