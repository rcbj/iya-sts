// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_pki_rules.js
//
// ---------------------------------------------------------------------------
// WHAT A REALM'S CERTIFICATE AUTHORITY IS BUILT FROM, OVER THE WIRE.
//
// D12 (#444): carries over what a client can see of `tests/pki_defaults.js`,
// `tests/pki_hybrid.js` and `tests/pki_rebuild_recertifies.js`, in throwaway
// realms, each built through `/admin-api/pki/build` and read back as the
// certificates `/pki/ca/{realm}/intermediate.cer` and the realm's JWK Set
// publish — DER read by node, and by OID where node reads no field:
//
//   A. THE SETTINGS ARE THE BUILD'S DEFAULTS (pki_defaults): with
//      `pki.keyAlgorithm` ec-p384 and `pki.signatureAlgorithm` sha384-ecdsa
//      on the realm, its Intermediate holds a P-384 key and is signed
//      ecdsa-with-SHA384 in what it signs; `pki.intermediateLifetimeYears`
//      3 is its lifetime; a composite ML-DSA key algorithm, which the
//      listeners cannot load, falls back (STS-PKI-0275 is logged only);
//   B. THE ALTERNATIVE KEY (pki_hybrid, #68): with
//      `pki.alternativeKeyAlgorithm` ml-dsa-65 what the realm's Intermediate
//      signs carries ITU-T X.509 clause 9.8's three extensions
//      (subjectAltPublicKeyInfo, altSignatureAlgorithm, altSignatureValue),
//      and without it the Intermediate carries none;
//   C. A REBUILD RECERTIFIES THE SIGNING KEYS (pki_rebuild_recertifies, #46):
//      after a second build the realm's JWK Set publishes every key's
//      certificate chain from the NEW Intermediate, never the old.
//
// NOT carried, and why: a full workbench store refusing rather than
// discarding (PKI-0268's neighbour) and `certify()` re-signing when the
// Issuing CA is replaced between its signature and its record (PKI-0186)
// need a wrapped x509 module (class (d)); the probe leaves with only a
// classical signature or a stranger's alternative signature (PKI-0201,
// 0202) need the Issuing CA's private keys; the process-scope branch and the
// service Root (0270, 0272) are process-wide and owed to an exclusive job;
// OpenSSL path-building is `sts_pki_distribution_points.js`'s.
//
// OWNED HERE (local: true): this repository's own certificate authority.
// ---------------------------------------------------------------------------

const assert = require("assert");
const nodeCrypto = require("crypto");
const K = require("./oauth_wire_kit.js").kit("sts_pki_rules");
const log = K.log;

const FLOOR = 9;
const OID = {
  ecdsaSha384: Buffer.from("06082a8648ce3d040303", "hex"),
  altPublicKey: Buffer.from("0603551d48", "hex"),
  altSigAlg: Buffer.from("0603551d49", "hex"),
  altSigValue: Buffer.from("0603551d4a", "hex")
};

function check(what, fn) {
  log.debug("Entering check().");
  K.check(what, fn);
  log.debug("Leaving check().");
}

async function intermediate(realm) {
  log.debug("Entering intermediate(). " + realm);
  const r = await fetch(K.base + "/pki/ca/" + realm + "/intermediate.cer");
  assert.strictEqual(r.status, 200, "the Intermediate of " + realm + ": " +
                     r.status);
  const raw = Buffer.from(await r.arrayBuffer());
  const text = raw.toString("latin1");
  const der = /-----BEGIN/.test(text)
    ? Buffer.from(text.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""),
                  "base64") : raw;
  log.debug("Leaving intermediate().");
  return { der: der, x: new nodeCrypto.X509Certificate(der) };
}

// The certificate the realm's Intermediate signed for its JOSE signing
// keys: the second of a JWK's x5c (the Intermediate itself is signed by the
// service Root, whose own settings are the process's).
async function issuingCa(realm) {
  log.debug("Entering issuingCa(). " + realm);
  const keys = chainsIn((await K.send(K.rb(realm) + "/oauth2/jwks")).json);
  assert.ok(keys.length >= 1, "no key of " + realm + " carries an x5c chain");
  const der = Buffer.from(keys[0].x5c[1], "base64");
  log.debug("Leaving issuingCa().");
  return { der: der, x: new nodeCrypto.X509Certificate(der) };
}

async function build(realm) {
  log.debug("Entering build(). " + realm);
  log.debug("Leaving build().");
  return K.send(K.rb(realm) + "/admin-api/pki/build",
                { json: { organisation: "PKI rules" } });
}

async function settings(realm) {
  log.debug("Entering settings().");
  log.info("=== A. the settings are the build's defaults ===");
  await K.set(realm, "pki.keyAlgorithm", "ec-p384");
  await K.set(realm, "pki.signatureAlgorithm", "sha384-ecdsa");
  await K.set(realm, "pki.intermediateLifetimeYears", 3);
  const built = await build(realm);
  check("A1. the realm's CA is built with its settings", function () {
    assert.strictEqual(built.status, 200, K.shown(built));
  });
  const ca = await intermediate(realm);
  check("A2. its Intermediate holds a P-384 key", function () {
    const details = ca.x.publicKey.asymmetricKeyDetails || {};
    assert.strictEqual(ca.x.publicKey.asymmetricKeyType, "ec");
    assert.strictEqual(details.namedCurve, "secp384r1",
                       JSON.stringify(details));
  });
  const signed = await issuingCa(realm);
  check("A3. and what it signs is signed ecdsa-with-SHA384: the JOSE " +
        "signing CA under it", function () {
    assert.ok(signed.x.verify(ca.x.publicKey), "not signed by the " +
              "Intermediate");
    assert.ok(signed.der.indexOf(OID.ecdsaSha384) >= 0,
              "no ecdsa-with-SHA384 OID in the certificate");
  });
  check("A4. pki.intermediateLifetimeYears 3 is its lifetime", function () {
    const years = (Date.parse(ca.x.validTo) - Date.parse(ca.x.validFrom)) /
                  (365.25 * 86400000);
    assert.ok(years > 2.9 && years < 3.1, String(years));
  });
  await K.unset(realm, "pki.intermediateLifetimeYears");
  await K.set(realm, "pki.keyAlgorithm", "mldsa44-rsa2048-pss-sha256");
  await K.unset(realm, "pki.signatureAlgorithm");
  const out = await K.coded(realm, "STS-PKI-0275", function () {
    return build(realm);
  });
  const after = await intermediate(realm);
  check("A5. a composite ML-DSA key algorithm, which the listeners cannot " +
        "load, falls back: the build is answered and the new " +
        "Intermediate's key is one node reads (STS-PKI-0275 is a log line, " +
        "with no audit row)", function () {
    assert.strictEqual(out.answer.status, 200, K.shown(out.answer));
    log.info("A5. STS-PKI-0275 audit rows: " + out.rose);
    assert.ok(!after.der.equals(ca.der), "the Intermediate is the old one");
    assert.ok(after.x.publicKey.asymmetricKeyType,
              "a key node cannot read");
  });
  log.debug("Leaving settings().");
}

async function hybrid() {
  log.debug("Entering hybrid().");
  log.info("=== B. the alternative key ===");
  const plain = await K.realm("pkiplain");
  assert.strictEqual((await build(plain)).status, 200);
  const classical = await intermediate(plain);
  check("B1. with no alternative key algorithm the Intermediate carries no " +
        "clause 9.8 extension", function () {
    assert.ok(classical.der.indexOf(OID.altPublicKey) < 0);
    assert.ok(classical.der.indexOf(OID.altSigValue) < 0);
  });
  const alt = await K.realm("pkialt");
  await K.set(alt, "pki.alternativeKeyAlgorithm", "ml-dsa-65");
  const built = await build(alt);
  assert.strictEqual(built.status, 200, K.shown(built));
  const hybridCa = await issuingCa(alt);
  check("B2. with ml-dsa-65 what the realm's Intermediate signs carries " +
        "subjectAltPublicKeyInfo, altSignatureAlgorithm and " +
        "altSignatureValue", function () {
    assert.ok(hybridCa.der.indexOf(OID.altPublicKey) >= 0, "no 2.5.29.72");
    assert.ok(hybridCa.der.indexOf(OID.altSigAlg) >= 0, "no 2.5.29.73");
    assert.ok(hybridCa.der.indexOf(OID.altSigValue) >= 0, "no 2.5.29.74");
  });
  log.debug("Leaving hybrid().");
}

function chainsIn(jwks) {
  log.debug("Entering chainsIn().");
  log.debug("Leaving chainsIn().");
  return ((jwks && jwks.keys) || []).filter(function (k) {
    return Array.isArray(k.x5c) && k.x5c.length >= 2;
  });
}

async function rebuild() {
  log.debug("Entering rebuild().");
  log.info("=== C. a rebuild recertifies the signing keys ===");
  const realm = await K.realm("pkirebuild");
  assert.strictEqual((await build(realm)).status, 200);
  const first = await intermediate(realm);
  const before = chainsIn((await K.send(K.rb(realm) + "/oauth2/jwks")).json);
  check("C1. the JWK Set publishes certificate chains from the first " +
        "Intermediate", function () {
    assert.ok(before.length >= 1, "no key carries an x5c chain");
    before.forEach(function (k) {
      assert.ok(k.x5c.indexOf(first.der.toString("base64")) > 0, k.kid);
    });
  });
  assert.strictEqual((await build(realm)).status, 200);
  const second = await intermediate(realm);
  const after = chainsIn((await K.send(K.rb(realm) + "/oauth2/jwks")).json);
  check("C2. a second build makes a new Intermediate", function () {
    assert.ok(!second.der.equals(first.der));
  });
  check("C3. and every key's chain is from the NEW Intermediate, never the " +
        "old", function () {
    assert.ok(after.length >= 1, "no key carries an x5c chain");
    after.forEach(function (k) {
      assert.ok(k.x5c.indexOf(second.der.toString("base64")) > 0, k.kid);
      assert.ok(k.x5c.indexOf(first.der.toString("base64")) < 0, k.kid);
    });
  });
  log.debug("Leaving rebuild().");
}

async function test() {
  log.debug("Entering test().");
  const realm = await K.realm("pkidefaults");
  await settings(realm);
  await hybrid();
  await rebuild();
  log.debug("Leaving test().");
}

K.main(test, FLOOR);
