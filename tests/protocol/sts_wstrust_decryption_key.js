// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_wstrust_decryption_key.js
//
// ---------------------------------------------------------------------------
// AN APPLICATION'S OWN WS-TRUST DECRYPTION KEY PAIR, OVER THE WIRE (#1668,
// rcbj's request of 2026-11-19).
//
// What a WS-Trust client and an operator do with it, through `/admin-api`
// and `/sts` alone, in a throwaway realm:
//
//   A. ISSUE: `POST /admin-api/applications/issue-wstrust-decryption-key`
//      gives the application a key pair from the realm's CA; the answer and
//      `credentials.wstrustDecryption` of `GET /admin-api/applications
//      ?application=` carry its certificate (CN=<application>-encrypt,
//      keyEncipherment) and never its private key.
//   B. USE: a client that DOWNLOADED that certificate encrypts the whole
//      RequestSecurityToken to it (the AppliesTo inside the ciphertext) and
//      is issued a token; the same request encrypted to the realm's XML
//      Encryption certificate (`/saml2/metadata`) is wsse:FailedCheck,
//      STS-WSTRUST-0083.
//   C. UPLOAD: a certificate and private key the client made itself are
//      stored, and a request encrypted to that certificate is answered; a
//      private key that is not the certificate's is refused (STS-ADMIN-0947).
//   D. REMOVE: the key pair is taken off, and a request encrypted to the
//      realm's certificate is answered again.
//
// Every refusal's code is read off the realm's audit log; none is sent.
// The realm is removed when the job passes (`K.main`).
//
// OWNED HERE (local: true): this repository's own management API and
// WS-Trust endpoint.
// ---------------------------------------------------------------------------

const assert = require("assert");
const nodeCrypto = require("crypto");
const forge = require("node-forge");
const xmldom = require("@xmldom/xmldom");
if (!global.DOMParser) {
  global.DOMParser = xmldom.DOMParser;
}
if (!global.XMLSerializer) {
  global.XMLSerializer = xmldom.XMLSerializer;
}
const xmldsig = require("../../common/crypto_impl/xmldsig.js");
const K = require("./oauth_wire_kit.js").kit("sts_wstrust_decryption_key");
const W = require("./wstrust_wire_kit.js").wsKit(K);

const log = K.log;
const FLOOR = 11;
const APP = "wdk-back";
const PERSON = "wdk-alice";
const PASSWORD = "Wdk-Passw0rd!-" + String(Date.now()).slice(-6);
const BACK = "https://wdk-back-" + K.STAMP + ".example";
const XENC = "http://www.w3.org/2001/04/xmlenc#";
const SOAP12 = "http://www.w3.org/2003/05/soap-envelope";
// A PEM private key's armour followed by its base64, raw or in JSON.
const KEY_MATERIAL = /PRIVATE KEY-----(?:\\n|\s)*[A-Za-z0-9+/]{16}/;

function check(what, fn) {
  log.debug("Entering check().");
  K.check(what, fn);
  log.debug("Leaving check().");
}

// The whole RequestSecurityToken, the Body's content, encrypted to
// `certPem` as a WS-Trust client of this service would: AES-256-GCM, the
// key transported with RSA-OAEP to the certificate it carries.
function sealedRst(certPem) {
  log.debug("Entering sealedRst().");
  const clear = W.rst({ security: W.usernameToken(PERSON, PASSWORD),
                        appliesTo: BACK });
  const doc = new xmldom.DOMParser().parseFromString(clear, "text/xml");
  const body = doc.getElementsByTagNameNS(SOAP12, "Body")[0];
  const serializer = new xmldom.XMLSerializer();
  let plain = "";
  for (let i = 0; i < body.childNodes.length; i++) {
    plain += serializer.serializeToString(body.childNodes[i]);
  }
  const data = xmldsig.encryptXml(plain, { certPem: certPem,
                                           type: XENC + "Content" });
  const start = clear.indexOf("<s:Body>") + "<s:Body>".length;
  const end = clear.indexOf("</s:Body>");
  log.debug("Leaving sealedRst().");
  return clear.slice(0, start) + data + clear.slice(end);
}

function post(realm, raw) {
  log.debug("Entering post().");
  log.debug("Leaving post().");
  return W.post(realm, { raw: raw });
}

// A self-signed RSA leaf and its key, made by the client.
function clientPair(commonName) {
  log.debug("Entering clientPair(). " + commonName);
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = "01" + nodeCrypto.randomBytes(8).toString("hex");
  cert.validity.notBefore = new Date(Date.now() - 60000);
  cert.validity.notAfter = new Date(Date.now() + 86400000);
  const attrs = [{ name: "commonName", value: commonName }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([{ name: "keyUsage", keyEncipherment: true }]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  log.debug("Leaving clientPair().");
  return { certificate: forge.pki.certificateToPem(cert),
           privateKey: forge.pki.privateKeyToPem(keys.privateKey) };
}

async function decryptionState(realm) {
  log.debug("Entering decryptionState().");
  const view = await K.send(K.rb(realm) + "/admin-api/applications" +
                            "?application=" + encodeURIComponent(APP));
  assert.strictEqual(view.status, 200, K.shown(view));
  assert.ok(!KEY_MATERIAL.test(view.text), "the view carries a private key");
  log.debug("Leaving decryptionState().");
  return ((view.json || {}).credentials || {}).wstrustDecryption || {};
}

async function issued(realm) {
  log.debug("Entering issued().");
  log.info("=== A. issue a key pair from the realm's CA ===");
  const r = await K.send(K.rb(realm) +
    "/admin-api/applications/issue-wstrust-decryption-key",
  { json: { application: APP, keyAlg: "rsa-3072" } });
  const state = (r.json || {}).wstrustDecryption || {};
  check("A1. issue-wstrust-decryption-key answers the certificate and no " +
        "private key", function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.ok(state.held && state.source === "issued", K.shown(r));
    assert.ok(/BEGIN CERTIFICATE/.test(state.certificatePem || ""),
              K.shown(r));
    assert.ok(!KEY_MATERIAL.test(r.text), "the answer carries a private key");
  });
  const listed = await decryptionState(realm);
  const leaf = new nodeCrypto.X509Certificate(listed.certificatePem);
  check("A2. the downloaded certificate is the one issued: CN=" + APP +
        "-encrypt, issued by the realm's CA, keyEncipherment", function () {
    assert.strictEqual(listed.certificatePem, state.certificatePem);
    assert.strictEqual(leaf.subject.split("\n")[0], "CN=" + APP + "-encrypt",
                       leaf.subject);
    assert.notStrictEqual(leaf.issuer, leaf.subject);
    assert.deepStrictEqual(listed.certificate.keyUsage,
                           ["keyEncipherment"]);
    assert.ok(listed.sealedAtRest === true || listed.sealedAtRest === false);
  });
  log.debug("Leaving issued().");
  return listed.certificatePem;
}

// The realm's XML Encryption certificate, as `/saml2/metadata` publishes it.
async function realmCertificate(realm) {
  log.debug("Entering realmCertificate().");
  const r = await K.send(K.rb(realm) + "/saml2/metadata");
  const block = (/<md:KeyDescriptor use="encryption">[\s\S]*?<\/md:KeyDescriptor>/
    .exec(r.text) || [""])[0];
  const b64 = ((/X509Certificate>([^<]+)</.exec(block) || [])[1] || "")
    .replace(/\s+/g, "");
  assert.ok(b64, "no encryption certificate in /saml2/metadata: " +
            r.text.slice(0, 300));
  log.debug("Leaving realmCertificate().");
  return "-----BEGIN CERTIFICATE-----\n" + b64.match(/.{1,64}/g).join("\n") +
    "\n-----END CERTIFICATE-----\n";
}

async function used(realm, appPem, realmPem) {
  log.debug("Entering used().");
  log.info("=== B. a request encrypted to it ===");
  const answered = await post(realm, sealedRst(appPem));
  check("B1. a wholly encrypted request, encrypted to the downloaded " +
        "certificate, is issued a token", function () {
    const token = W.tokenOf(answered, "the encrypted request");
    assert.ok(token.assertion || token.jwt, K.shown(answered));
  });
  const refused = await K.coded(realm, "STS-WSTRUST-0083", function () {
    return post(realm, sealedRst(realmPem));
  });
  check("B2. the same request encrypted to the realm's certificate is " +
        "wsse:FailedCheck (STS-WSTRUST-0083), and no code is sent",
        function () {
          assert.strictEqual(refused.answer.status, 500,
                             K.shown(refused.answer));
          assert.ok(/wsse:FailedCheck/.test(refused.answer.text),
                    refused.answer.text.slice(0, 400));
          assert.ok(refused.rose >= 1, "0083 rows: " + refused.rose);
          assert.ok(!/STS-[A-Z]+-\d{4}/.test(refused.answer.text));
        });
  log.debug("Leaving used().");
}

async function uploaded(realm) {
  log.debug("Entering uploaded().");
  log.info("=== C. a key pair the client made, uploaded ===");
  const mine = clientPair(APP + "-client-made");
  const other = clientPair(APP + "-other");
  const mismatch = await K.coded(realm, "STS-ADMIN-0947", function () {
    return K.send(K.rb(realm) +
      "/admin-api/applications/upload-wstrust-decryption-key",
    { json: { application: APP, certificate: mine.certificate,
              privateKey: other.privateKey } });
  });
  check("C1. a private key that is not the certificate's is refused " +
        "(STS-ADMIN-0947)", function () {
    assert.strictEqual(mismatch.answer.status, 400, K.shown(mismatch.answer));
    assert.ok(mismatch.rose >= 1, "0947 rows: " + mismatch.rose);
    assert.ok(!KEY_MATERIAL.test(mismatch.answer.text));
  });
  const r = await K.send(K.rb(realm) +
    "/admin-api/applications/upload-wstrust-decryption-key",
  { json: { application: APP, certificate: mine.certificate,
            privateKey: mine.privateKey } });
  check("C2. the client's certificate and key are stored, source " +
        "uploaded, and the answer carries no private key", function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.strictEqual(r.json.wstrustDecryption.source, "uploaded");
    assert.ok(!KEY_MATERIAL.test(r.text));
  });
  const answered = await post(realm, sealedRst(mine.certificate));
  check("C3. a request encrypted to the uploaded certificate is issued a " +
        "token", function () {
    const token = W.tokenOf(answered, "the request to the uploaded key");
    assert.ok(token.assertion || token.jwt, K.shown(answered));
  });
  log.debug("Leaving uploaded().");
}

async function removed(realm, realmPem) {
  log.debug("Entering removed().");
  log.info("=== D. the key pair removed ===");
  const r = await K.send(K.rb(realm) +
    "/admin-api/applications/remove-wstrust-decryption-key",
  { json: { application: APP } });
  check("D1. remove-wstrust-decryption-key takes it off", function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.strictEqual(r.json.wstrustDecryption.held, false, K.shown(r));
  });
  const state = await decryptionState(realm);
  check("D2. the application's view holds no key pair now", function () {
    assert.strictEqual(state.held, false, JSON.stringify(state));
  });
  const again = await K.coded(realm, "STS-ADMIN-0950", function () {
    return K.send(K.rb(realm) +
      "/admin-api/applications/remove-wstrust-decryption-key",
    { json: { application: APP } });
  });
  check("D3. removing it again is refused (STS-ADMIN-0950)", function () {
    assert.strictEqual(again.answer.status, 400, K.shown(again.answer));
    assert.ok(again.rose >= 1, "0950 rows: " + again.rose);
  });
  const answered = await post(realm, sealedRst(realmPem));
  check("D4. a request encrypted to the realm's certificate is answered " +
        "again", function () {
    const token = W.tokenOf(answered, "the request to the realm's key");
    assert.ok(token.assertion || token.jwt, K.shown(answered));
  });
  log.debug("Leaving removed().");
}

async function test() {
  log.debug("Entering test().");
  const realm = await K.realm("wdk", "development");
  await K.ok(K.rb(realm) + "/admin-api/pki/build", { organisation: "Wdk" },
             "built the realm's CA");
  await K.app(realm, APP, { oauthClientId: [APP], wstrustAppliesTo: [BACK],
                            wstrustAcceptEncryptedElements: "TRUE" },
              { protocols: ["wstrust"] });
  await K.person(realm, PERSON, PASSWORD);
  const appPem = await issued(realm);
  const realmPem = await realmCertificate(realm);
  await used(realm, appPem, realmPem);
  await uploaded(realm);
  await removed(realm, realmPem);
  log.debug("Leaving test().");
}

K.main(test, FLOOR);
