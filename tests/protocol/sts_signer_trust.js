// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_signer_trust.js
//
// ---------------------------------------------------------------------------
// A REALM'S SIGNER TRUSTSTORE AND ITS PINNED SIGNING KEYS, OVER THE WIRE.
//
// D12 (#444): carries over what a client can see of
// `tests/signer_truststore.js` (#1360) and `tests/pinned_signers.js` (#263),
// in throwaway realms through `/admin-api/pki/trust` and
// `/admin-api/pki/pin-key`, every certificate minted here at run time
// (node-forge) and every refusal's code read off the realm's audit log:
//
//   A. THE SIGNER TRUSTSTORE: a self-signed CA is admitted as an anchor and
//      an intermediate it issued as an intermediate; refused: a leaf
//      (STS-PKI-0234), a CA whose keyUsage lacks keyCertSign (0230), an
//      expired CA (0231), an RSA-1024 CA (0232), an intermediate under no
//      anchor held (0233), a CA certificate offered as an anchor whose
//      self-signature does not verify (0228), and what is no certificate
//      (0238); `purposes` kept as given; another realm holds none of it; a
//      remove under the colon spelling of the fingerprint takes it off;
//   B. PINNED SIGNERS: with `pki.pinnedSigners` off a pin into a slot the
//      realm signs from is refused (STS-PKI-0206); with it on, a key of the
//      wrong type for the slot (an EC key, an RSA key under 2048 bits) is
//      refused (0207), a certificate that is not over the key, a chain
//      whose first certificate did not issue it (0209) and an expired
//      certificate (0210); an unpin of an empty slot (0211); an RS256 key
//      pinned is published at once in the JWK Set under an `sts-pinned-`
//      kid; turning the setting off while it is held is refused (0215);
//      unpinned, the kid is gone.
//
// NOT carried, and why: the truststore's file layer and the directory slot
// validated whole (0235) and its caps (0236, 32 anchors per realm) are class
// (d) (a child's fatal start-up, a store fault, a count too costly to fill
// on a shared service); a pinned key SIGNING after
// `pki.pinnedSignerLeadMinutes`, the composite slot (0208), the xml slot's
// keyUsage (0217), the expiry warning (0212) and the start-up check (0216)
// need a moved clock, a key no forge builds or a restart, and are owed or
// (d) as each says; `tests/truststore_admin.js` (the client-certificate
// truststore) is process-wide and its doors are
// `sts_admin_api_operations.js`'s truststore section; and
// `tests/tls_presented_root.js` is the listener's handshake, owed with
// phase 3's TLS jobs.
//
// OWNED HERE (local: true): this repository's own certificate authority.
// ---------------------------------------------------------------------------

const assert = require("assert");
const nodeCrypto = require("crypto");
const forge = require("node-forge");
const K = require("./oauth_wire_kit.js").kit("sts_signer_trust");
const log = K.log;

const FLOOR = 21;
const DAY = 86400000;

function check(what, fn) {
  log.debug("Entering check().");
  K.check(what, fn);
  log.debug("Leaving check().");
}

// A certificate: `signer` is { key, cert } (absent: self-signed), `ca` makes
// it a CA, `keyUsage` overrides, `from`/`to` move its validity.
function cert(spec) {
  log.debug("Entering cert(). " + spec.cn);
  const keys = spec.keys || forge.pki.rsa.generateKeyPair(spec.bits || 2048);
  const c = forge.pki.createCertificate();
  c.publicKey = keys.publicKey;
  c.serialNumber = "01" + nodeCrypto.randomBytes(8).toString("hex");
  c.validity.notBefore = new Date(Date.now() + (spec.from || -DAY));
  c.validity.notAfter = new Date(Date.now() + (spec.to || 30 * DAY));
  const subject = [{ name: "commonName", value: spec.cn }];
  c.setSubject(subject);
  c.setIssuer(spec.signer ? spec.signer.cert.subject.attributes : subject);
  const exts = [{ name: "basicConstraints", cA: !!spec.ca, critical: true }];
  exts.push(Object.assign({ name: "keyUsage", critical: true },
    spec.keyUsage || (spec.ca ? { keyCertSign: true, cRLSign: true }
                              : { digitalSignature: true })));
  exts.push({ name: "subjectKeyIdentifier" });
  c.setExtensions(exts);
  c.sign(spec.signer ? spec.signer.keys.privateKey : keys.privateKey,
         forge.md.sha256.create());
  const pem = forge.pki.certificateToPem(c);
  log.debug("Leaving cert().");
  return { keys: keys, cert: c, pem: pem,
           fingerprint: new nodeCrypto.X509Certificate(pem).fingerprint256 };
}

async function coded(realm, code, path, body) {
  log.debug("Entering coded(). " + code);
  const out = await K.coded(realm, code, function () {
    return K.send(K.rb(realm) + "/admin-api" + path, { json: body });
  });
  log.debug("Leaving coded(). " + out.rose);
  return out;
}

function refused(what, out, code) {
  log.debug("Entering refused(). " + code);
  check(what + " (" + code + ")", function () {
    assert.strictEqual(out.answer.status, 400, K.shown(out.answer));
    assert.ok(out.rose >= 1, code + " rows: " + out.rose + "; " +
              K.shown(out.answer));
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(out.answer.text), "a code was sent");
  });
  log.debug("Leaving refused().");
}

async function listed(realm) {
  log.debug("Entering listed().");
  const r = await K.send(K.rb(realm) + "/admin-api/pki/trust");
  const text = JSON.stringify(r.json || {}).toLowerCase();
  log.debug("Leaving listed().");
  return text;
}

function plain(fp) {
  log.debug("Entering plain().");
  log.debug("Leaving plain().");
  return fp.replace(/:/g, "").toLowerCase();
}

async function truststore() {
  log.debug("Entering truststore().");
  log.info("=== A. the signer truststore ===");
  const realm = await K.realm("signtrust");
  const other = await K.realm("signtrust2");
  const anchor = cert({ cn: "Signer Root " + K.STAMP, ca: true });
  const inter = cert({ cn: "Signer Intermediate " + K.STAMP, ca: true,
                       signer: anchor });
  const added = await K.send(K.rb(realm) + "/admin-api/pki/trust/add",
    { json: { certificates: anchor.pem, purposes: ["saml-signer"] } });
  check("A1. a self-signed CA is admitted as an anchor, with the purposes " +
        "given", function () {
    assert.strictEqual(added.status, 200, K.shown(added));
    const text = JSON.stringify(added.json);
    assert.ok(/anchor/.test(text) && /saml-signer/.test(text), text);
  });
  const under = await K.send(K.rb(realm) + "/admin-api/pki/trust/add",
    { json: { certificates: inter.pem } });
  check("A2. a CA it issued is admitted as an intermediate", function () {
    assert.strictEqual(under.status, 200, K.shown(under));
    assert.ok(/intermediate/.test(JSON.stringify(under.json)));
  });
  const leaf = cert({ cn: "a leaf " + K.STAMP, signer: anchor });
  refused("A3. a leaf is refused: it goes on the entry that uses it",
    await coded(realm, "STS-PKI-0234", "/pki/trust/add",
                { certificates: leaf.pem }), "STS-PKI-0234");
  refused("A4. a CA whose keyUsage lacks keyCertSign is refused",
    await coded(realm, "STS-PKI-0230", "/pki/trust/add", {
      certificates: cert({ cn: "no keyCertSign " + K.STAMP, ca: true,
        keyUsage: { digitalSignature: true } }).pem }), "STS-PKI-0230");
  refused("A5. an expired CA is refused",
    await coded(realm, "STS-PKI-0231", "/pki/trust/add", {
      certificates: cert({ cn: "expired " + K.STAMP, ca: true,
        from: -30 * DAY, to: -DAY }).pem }), "STS-PKI-0231");
  refused("A6. an RSA-1024 CA is refused as weak",
    await coded(realm, "STS-PKI-0232", "/pki/trust/add", {
      certificates: cert({ cn: "weak " + K.STAMP, ca: true,
        bits: 1024 }).pem }), "STS-PKI-0232");
  const stranger = cert({ cn: "Stranger Root " + K.STAMP, ca: true });
  refused("A7. an intermediate under no anchor held is refused",
    await coded(realm, "STS-PKI-0233", "/pki/trust/add", {
      certificates: cert({ cn: "orphan " + K.STAMP, ca: true,
        signer: stranger }).pem }), "STS-PKI-0233");
  refused("A8. a CA offered as an anchor that is not self-signed is refused",
    await coded(realm, "STS-PKI-0228", "/pki/trust/add", {
      kind: "anchor", certificates: cert({ cn: "not self " + K.STAMP,
        ca: true, signer: stranger }).pem }), "STS-PKI-0228");
  refused("A9. what is no certificate is refused",
    await coded(realm, "STS-PKI-0238", "/pki/trust/add", { certificates:
      "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n" }),
    "STS-PKI-0238");
  const here = await listed(realm);
  const there = await listed(other);
  check("A10. the realm lists both; another realm holds neither", function () {
    assert.ok(here.indexOf(plain(anchor.fingerprint)) >= 0 ||
              here.indexOf(anchor.fingerprint.toLowerCase()) >= 0, here);
    assert.ok(there.indexOf(plain(anchor.fingerprint)) < 0 &&
              there.indexOf(anchor.fingerprint.toLowerCase()) < 0);
  });
  const removed = await K.send(K.rb(realm) + "/admin-api/pki/trust/remove",
    { json: { fingerprint: inter.fingerprint } });
  const afterRemove = await listed(realm);
  check("A11. a remove under the colon spelling takes the intermediate off",
        function () {
    assert.strictEqual(removed.status, 200, K.shown(removed));
    assert.ok(afterRemove.indexOf(plain(inter.fingerprint)) < 0 &&
              afterRemove.indexOf(inter.fingerprint.toLowerCase()) < 0);
  });
  log.debug("Leaving truststore().");
}

function keyPem(kind) {
  log.debug("Entering keyPem(). " + kind);
  const pair = kind === "ec"
    ? nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" })
    : nodeCrypto.generateKeyPairSync("rsa", { modulusLength: Number(kind) });
  log.debug("Leaving keyPem().");
  return { privatePem: pair.privateKey.export({ type: "pkcs8",
                                                format: "pem" }),
           publicPem: pair.publicKey.export({ type: "spki", format: "pem" }) };
}

// A self-signed certificate over a node key, through forge.
function certOver(pair, from, to) {
  log.debug("Entering certOver().");
  const keys = { publicKey: forge.pki.publicKeyFromPem(pair.publicPem),
                 privateKey: forge.pki.privateKeyFromPem(pair.privatePem) };
  log.debug("Leaving certOver().");
  return cert({ cn: "pinned " + K.STAMP, keys: keys, from: from, to: to })
    .pem;
}

async function kids(realm) {
  log.debug("Entering kids().");
  const r = await K.send(K.rb(realm) + "/oauth2/jwks");
  log.debug("Leaving kids().");
  return ((r.json && r.json.keys) || []).map(function (k) {
    return k.kid;
  });
}

async function pinned() {
  log.debug("Entering pinned().");
  log.info("=== B. pinned signers ===");
  const off = await K.realm("pinoff");
  await K.ok(K.rb(off) + "/admin-api/pki/build", { organisation: "Pin" },
             "built the CA");
  const rsa = keyPem(2048);
  refused("B1. with pki.pinnedSigners off a pin into a slot the realm signs " +
          "from is refused",
    await coded(off, "STS-PKI-0206", "/pki/pin-key", { useCase: "jose",
      slot: "RS256", privateKeyPem: rsa.privatePem }), "STS-PKI-0206");
  const on = await K.realm("pinon");
  await K.ok(K.rb(on) + "/admin-api/pki/build", { organisation: "Pin" },
             "built the CA");
  await K.set(on, "pki.pinnedSigners", true);
  refused("B2. an EC key in the RS256 slot is refused",
    await coded(on, "STS-PKI-0207", "/pki/pin-key", { useCase: "jose",
      slot: "RS256", privateKeyPem: keyPem("ec").privatePem }),
    "STS-PKI-0207");
  refused("B3. an RSA key under 2048 bits is refused",
    await coded(on, "STS-PKI-0207", "/pki/pin-key", { useCase: "jose",
      slot: "RS256", privateKeyPem: keyPem(1024).privatePem }),
    "STS-PKI-0207");
  const foreign = await K.send(K.rb(on) + "/admin-api/pki/pin-key", { json: {
    useCase: "jose", slot: "RS256", privateKeyPem: rsa.privatePem,
    certificatePem: certOver(keyPem(2048)) } });
  check("B4. a certificate that is not over the key is refused, and says " +
        "so", function () {
    assert.strictEqual(foreign.status, 400, K.shown(foreign));
    assert.ok(/does not belong to that certificate/.test(foreign.text),
              K.shown(foreign));
  });
  // The chain supplied beside the certificate must issue it: a CA that did
  // not is refused (#263).
  const unrelated = cert({ cn: "Unrelated CA " + K.STAMP, ca: true });
  refused("B4b. a chain whose first certificate did not issue the key's " +
          "certificate is refused",
    await coded(on, "STS-PKI-0209", "/pki/pin-key", { useCase: "jose",
      slot: "RS256", privateKeyPem: rsa.privatePem,
      certificatePem: certOver(rsa), chainPem: unrelated.pem }),
    "STS-PKI-0209");
  refused("B5. an expired certificate is refused",
    await coded(on, "STS-PKI-0210", "/pki/pin-key", { useCase: "jose",
      slot: "RS256", privateKeyPem: rsa.privatePem,
      certificatePem: certOver(rsa, -30 * DAY, -DAY) }), "STS-PKI-0210");
  refused("B6. unpinning a slot that holds no pinned key is refused",
    await coded(on, "STS-PKI-0211", "/pki/unpin-key",
                { useCase: "jose", slot: "ES256" }), "STS-PKI-0211");
  const pin = await K.send(K.rb(on) + "/admin-api/pki/pin-key", { json: {
    useCase: "jose", slot: "RS256", privateKeyPem: rsa.privatePem } });
  const kid = String((pin.json && pin.json.kid) || "");
  const published = await kids(on);
  check("B7. an RS256 key is pinned under an sts-pinned- kid, published at " +
        "once in the JWK Set", function () {
    assert.strictEqual(pin.status, 200, K.shown(pin));
    assert.ok(/^sts-pinned-/.test(kid), kid);
    assert.ok(published.indexOf(kid) >= 0, JSON.stringify(published));
  });
  // Through the realm's own config/set, whose audit log is the realm's.
  const offWhileHeld = await K.coded(on, "STS-PKI-0215", function () {
    return K.send(K.rb(on) + "/admin-api/config/set", { json: {
      key: "pki.pinnedSigners", value: "false" } });
  });
  check("B8. turning pki.pinnedSigners off while a pinned key is held is " +
        "refused (STS-PKI-0215)", function () {
    assert.strictEqual(offWhileHeld.answer.status, 400,
                       K.shown(offWhileHeld.answer));
    assert.ok(offWhileHeld.rose >= 1, "rows: " + offWhileHeld.rose);
  });
  const unpin = await K.send(K.rb(on) + "/admin-api/pki/unpin-key",
    { json: { useCase: "jose", slot: "RS256" } });
  const after = await kids(on);
  check("B9. unpinned, the kid is gone from the JWK Set", function () {
    assert.strictEqual(unpin.status, 200, K.shown(unpin));
    assert.ok(after.indexOf(kid) < 0, JSON.stringify(after));
  });
  log.debug("Leaving pinned().");
}

async function test() {
  log.debug("Entering test().");
  await truststore();
  await pinned();
  log.debug("Leaving test().");
}

K.main(test, FLOOR);
