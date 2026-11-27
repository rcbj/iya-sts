// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_truststores.js
//
// ---------------------------------------------------------------------------
// NAMED TRUSTSTORES AND THE USE CASES THAT TRUST THEM, OVER THE WIRE (#2118
// phase 4).
//
// `GET /admin-api/truststores` and its seven actions, in throwaway realms,
// every certificate minted here at run time (node-forge) and every refusal's
// code read off the realm's audit log, never off the answer:
//
//   A. THE VIEW: every kind of truststore a realm can name is listed (the
//      built-ins, the two views, the legacy settings), node's own store is
//      described certificate by certificate WITHOUT PEM, and every use case
//      says what it trusts now and its default.
//   B. A NAMED TRUSTSTORE'S LIFE: created; a second of the name refused
//      (STS-PKI-0305); an anchor and the intermediate it issued admitted and
//      a leaf refused by name in the same bundle; a truststore that does not
//      exist takes nothing (0301); `show` answers PEM, and none with
//      `withPem: false`; a remove under the colon spelling; a delete.
//   C. ASSIGNMENT: a realm use case assigned the truststore and the realm's
//      signers, read back on the view; a delete refused while it is trusted
//      (0307); a service-wide inbound use case refused from a realm (0302)
//      — an outbound one may be overridden there (#2148); a fixed
//      use case (0303) and a SPIFFE use case given an X.509 store (0304)
//      refused; unassign back to the default.
//   D. REALM CONFINEMENT: another realm neither lists the truststore nor can
//      delete it (0301).
//   E. AN UNKNOWN ACTION is refused (STS-ADMIN-0956).
//
// NOT carried, and why: a service-wide truststore and a service-wide use
// case's assignment are written in the DEFAULT realm, which every other job
// reads, so this job leaves them to `tests/truststores_api.js` (in process,
// put back in a `finally`); what a use case then TRUSTS at a handshake or a
// signature is phases 2 and 3's, held in process by `tests/truststores.js`.
//
// OWNED HERE (local: true): this repository's own management API.
// ---------------------------------------------------------------------------

const assert = require("assert");
const nodeCrypto = require("crypto");
const forge = require("node-forge");
const K = require("./oauth_wire_kit.js").kit("sts_truststores");
const log = K.log;

const FLOOR = 25;
const DAY = 86400000;

function check(what, fn) {
  log.debug("Entering check().");
  K.check(what, fn);
  log.debug("Leaving check().");
}

// A certificate: `signer` is { keys, cert } (absent: self-signed), `ca`
// makes it a CA.
function cert(spec) {
  log.debug("Entering cert(). " + spec.cn);
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const c = forge.pki.createCertificate();
  c.publicKey = keys.publicKey;
  c.serialNumber = "01" + nodeCrypto.randomBytes(8).toString("hex");
  c.validity.notBefore = new Date(Date.now() - DAY);
  c.validity.notAfter = new Date(Date.now() + 30 * DAY);
  const subject = [{ name: "commonName", value: spec.cn }];
  c.setSubject(subject);
  c.setIssuer(spec.signer ? spec.signer.cert.subject.attributes : subject);
  c.setExtensions([
    { name: "basicConstraints", cA: !!spec.ca, critical: true },
    Object.assign({ name: "keyUsage", critical: true },
      spec.ca ? { keyCertSign: true, cRLSign: true }
              : { digitalSignature: true }),
    { name: "subjectKeyIdentifier" }
  ]);
  c.sign(spec.signer ? spec.signer.keys.privateKey : keys.privateKey,
         forge.md.sha256.create());
  const pem = forge.pki.certificateToPem(c);
  log.debug("Leaving cert().");
  return { keys: keys, cert: c, pem: pem,
           fingerprint: new nodeCrypto.X509Certificate(pem).fingerprint256 };
}

// One action in a realm.
function act(realm, action, body) {
  log.debug("Entering act(). " + action);
  log.debug("Leaving act().");
  return K.send(K.rb(realm) + "/admin-api/truststores/" + action,
                { json: body });
}

// One action in a realm whose refusal's code is counted on its audit log.
async function coded(realm, code, action, body) {
  log.debug("Entering coded(). " + code);
  const out = await K.coded(realm, code, function () {
    return act(realm, action, body);
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

// The realm's view.
async function view(realm) {
  log.debug("Entering view().");
  const r = await K.send(K.rb(realm) + "/admin-api/truststores");
  assert.strictEqual(r.status, 200, K.shown(r));
  log.debug("Leaving view().");
  return r.json || {};
}

function storeIn(json, name) {
  log.debug("Entering storeIn(). " + name);
  log.debug("Leaving storeIn().");
  return (json.stores || []).filter(function (one) {
    return one.name === name;
  })[0] || null;
}

function useCaseIn(json, id) {
  log.debug("Entering useCaseIn(). " + id);
  log.debug("Leaving useCaseIn().");
  return (json.useCases || []).filter(function (one) {
    return one.id === id;
  })[0] || null;
}

function plain(fp) {
  log.debug("Entering plain().");
  log.debug("Leaving plain().");
  return fp.replace(/:/g, "").toUpperCase();
}

async function test() {
  log.debug("Entering test().");
  const realm = await K.realm("tstores");
  const other = await K.realm("tstores2");

  log.info("=== A. the view ===");
  const first = await view(realm);
  check("A1. every kind of truststore a realm can name is listed",
        function () {
    ["system", "service-root", "signers", "client-certificates",
     "setting:federation.outboundCaFile"].forEach(function (name) {
      assert.ok(storeIn(first, name), name + " is missing");
    });
  });
  check("A2. node's store is described certificate by certificate, " +
        "without PEM", function () {
    const system = first.system || {};
    assert.ok(system.count > 0, JSON.stringify(system).slice(0, 200));
    assert.strictEqual(system.count, (system.certificates || []).length);
    assert.ok(!/BEGIN CERTIFICATE/.test(JSON.stringify(first)),
              "PEM was sent");
  });
  check("A3. every use case says what it trusts now and its default",
        function () {
    const saml = useCaseIn(first, "saml-signer");
    assert.ok(saml && saml.assignable && !saml.assigned &&
              saml.names.join(",") === saml.defaults.join(","),
              JSON.stringify(saml));
  });

  log.info("=== B. a named truststore ===");
  const anchor = cert({ cn: "Truststore Root " + K.STAMP, ca: true });
  const inter = cert({ cn: "Truststore Intermediate " + K.STAMP, ca: true,
                       signer: anchor });
  const leaf = cert({ cn: "a leaf " + K.STAMP, signer: anchor });
  const made = await act(realm, "create", { name: "partners",
                                            description: "our partners" });
  check("B1. a truststore is created", function () {
    assert.strictEqual(made.status, 200, K.shown(made));
  });
  refused("B2. a second of the name is refused",
          await coded(realm, "STS-PKI-0305", "create", { name: "partners" }),
          "STS-PKI-0305");
  const added = await act(realm, "add", { name: "partners",
    certificates: leaf.pem + anchor.pem + inter.pem });
  check("B3. the anchor and its intermediate are admitted, the leaf " +
        "refused by name", function () {
    assert.strictEqual(added.status, 200, K.shown(added));
    assert.strictEqual(added.json.added.length, 2, K.shown(added));
    assert.strictEqual(added.json.refused.length, 1, K.shown(added));
  });
  refused("B4. a truststore that does not exist takes nothing",
          await coded(realm, "STS-PKI-0301", "add",
                      { name: "nowhere", certificates: anchor.pem }),
          "STS-PKI-0301");
  const listed = storeIn(await view(realm), "partners");
  check("B5. the view lists it with what it holds", function () {
    assert.ok(listed && listed.kind === "named" && listed.anchors === 1 &&
              listed.intermediates === 1, JSON.stringify(listed));
    assert.ok(listed.certificates.some(function (one) {
      return one.fingerprint256 === plain(inter.fingerprint);
    }), JSON.stringify(listed.certificates));
  });
  const withPem = await act(realm, "show", { name: "partners" });
  const bare = await act(realm, "show", { name: "partners",
                                          withPem: false });
  check("B6. show answers PEM, and none with withPem false", function () {
    assert.strictEqual(withPem.status, 200, K.shown(withPem));
    assert.ok(/BEGIN CERTIFICATE/.test(withPem.text));
    assert.strictEqual(bare.status, 200, K.shown(bare));
    assert.ok(!/BEGIN CERTIFICATE/.test(bare.text));
  });

  log.info("=== C. assignment ===");
  const assigned = await act(realm, "assign", { useCase: "saml-signer",
    truststores: ["partners", "signers"] });
  const after = await view(realm);
  check("C1. a realm use case is assigned the truststore, read back",
        function () {
    assert.strictEqual(assigned.status, 200, K.shown(assigned));
    const saml = useCaseIn(after, "saml-signer");
    assert.ok(saml.assigned && saml.names.join(",") === "partners,signers",
              JSON.stringify(saml));
    assert.ok(storeIn(after, "partners").usedBy.indexOf("saml-signer") >= 0);
  });
  refused("C2. a truststore a use case trusts is not deleted",
          await coded(realm, "STS-PKI-0307", "delete", { name: "partners" }),
          "STS-PKI-0307");
  refused("C3. a service-wide inbound use case is not assigned from a realm",
          await coded(realm, "STS-PKI-0302", "assign",
                      { useCase: "tls-client", truststores: ["system"] }),
          "STS-PKI-0302");
  refused("C4. a fixed use case is not assigned",
          await coded(realm, "STS-PKI-0303", "assign",
                      { useCase: "cell-peer", truststores: ["partners"] }),
          "STS-PKI-0303");
  refused("C5. a SPIFFE use case names SPIFFE bundles only",
          await coded(realm, "STS-PKI-0304", "assign",
                      { useCase: "spiffe-svid", truststores: ["partners"] }),
          "STS-PKI-0304");

  log.info("=== D. realm confinement ===");
  const elsewhere = await view(other);
  check("D1. another realm does not list it", function () {
    assert.ok(!storeIn(elsewhere, "partners"));
  });
  refused("D2. nor can another realm delete it",
          await coded(other, "STS-PKI-0301", "delete", { name: "partners" }),
          "STS-PKI-0301");

  const unassigned = await act(realm, "unassign", { useCase: "saml-signer" });
  const removed = await act(realm, "remove", {
    name: "partners", fingerprint: inter.fingerprint });
  const held = storeIn(await view(realm), "partners");
  check("C6. unassigned, and a remove under the colon spelling takes the " +
        "intermediate off", function () {
    assert.strictEqual(unassigned.status, 200, K.shown(unassigned));
    assert.strictEqual(removed.status, 200, K.shown(removed));
    assert.ok(held && held.intermediates === 0, JSON.stringify(held));
  });
  const deleted = await act(realm, "delete", { name: "partners" });
  const gone = await view(realm);
  check("C7. unassigned, the truststore is deleted", function () {
    assert.strictEqual(deleted.status, 200, K.shown(deleted));
    assert.ok(!storeIn(gone, "partners"));
  });

  log.info("=== K. a key set bound to one party (#2149) ===");
  const jwk = Object.assign({ kid: "ks-" + K.STAMP, alg: "ES256" },
    nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" })
      .publicKey.export({ format: "jwk" }));
  const keyMade = await act(realm, "create", { name: "partner-keys",
    kind: "jwks", party: "client:partner-" + K.STAMP,
    jwks: { keys: [jwk] } });
  check("K1. a key set bound to one client is created", function () {
    assert.strictEqual(keyMade.status, 200, K.shown(keyMade));
  });
  const keyRow = storeIn(await view(realm), "partner-keys");
  check("K2. the view says it is a key set, whose, and its keys",
        function () {
    assert.ok(keyRow && keyRow.storeKind === "jwks" &&
              keyRow.party === "client:partner-" + K.STAMP &&
              keyRow.keys === 1, JSON.stringify(keyRow));
  });
  refused("K3. a key set refuses a private key",
          await coded(realm, "STS-PKI-0308", "create", { name: "bad-keys",
            kind: "jwks", party: "client:x", jwks: { keys: [{ kty: "EC",
              crv: "P-256", x: jwk.x, y: jwk.y, d: "AAAA" }] } }),
          "STS-PKI-0308");
  refused("K4. a certificate use case does not name a key set",
          await coded(realm, "STS-PKI-0309", "assign",
                      { useCase: "saml-signer",
                        truststores: ["partner-keys"] }),
          "STS-PKI-0309");
  const keyAssigned = await act(realm, "assign", { useCase: "client-jws",
    truststores: ["registered-keys", "partner-keys"] });
  const keyUri = await act(realm, "set-keys", { name: "partner-keys",
    jwksUri: "https://keys.example.net/" + K.STAMP + "/jwks" });
  const afterKeys = await view(realm);
  check("K5. client-jws is assigned the key set, and its keys replaced by " +
        "a jwks_uri, read back", function () {
    assert.strictEqual(keyAssigned.status, 200, K.shown(keyAssigned));
    assert.strictEqual(keyUri.status, 200, K.shown(keyUri));
    const row = storeIn(afterKeys, "partner-keys");
    assert.ok(row.jwksUri === "https://keys.example.net/" + K.STAMP +
              "/jwks" && row.usedBy.indexOf("client-jws") >= 0,
              JSON.stringify(row));
  });
  const keyCleared = await act(realm, "unassign", { useCase: "client-jws" });
  const keyGone = await act(realm, "delete", { name: "partner-keys" });
  check("K6. unassigned, the key set is deleted", function () {
    assert.strictEqual(keyCleared.status, 200, K.shown(keyCleared));
    assert.strictEqual(keyGone.status, 200, K.shown(keyGone));
  });

  log.info("=== E. an unknown action ===");
  refused("E1. an unknown action is refused",
          await coded(realm, "STS-ADMIN-0956", "frobnicate", {}),
          "STS-ADMIN-0956");
  log.debug("Leaving test().");
}

K.main(test, FLOOR);
