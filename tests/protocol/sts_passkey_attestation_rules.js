// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: sts_passkey_attestation_rules.js
//
// ===========================================================================
// WHAT A PASSKEY'S ATTESTATION IS HELD TO, OVER THE WIRE (#530, #532, #941,
// #1114).
//
// D12 (#444): carries over the part a client can see of three in-process
// files deleted at the cutover, with real registrations at the portal's
// `/account-api/keys` and real sign-ins at the screen:
//
//   A. `passkey_attestation_algorithm.js` — an ML-DSA-65 packed attestation
//      under an ML-DSA-87 root recorded on the key's row as ML-DSA-65, its
//      certificate and anchor ML-DSA-87, post-quantum; a classical one as
//      ES256 and sha256-ecdsa; the policy's `attestationAlgorithms` refusing
//      a classical attestation under `post-quantum`, an ML-DSA-87 signature
//      under `ml-dsa-65` alone and no attestation at all (STS-AUTHN-0411),
//      and taking the post-quantum one; the recorded algorithms held to the
//      list at sign-in only while `enforceAttestationAtSignIn` is on
//      (STS-AUTHN-0412); the API's key row carrying the reading; and the
//      credential's algorithm and the attestation's recorded independently
//      (an ML-DSA-65 credential under a classical leaf refused under
//      `post-quantum`, an ES256 credential under the ML-DSA chain taken);
//   B. `passkey_attestation_signin.js` — a key registered with `none` signs
//      in; a rule demanding trust (an AAGUID list) is a registration rule
//      while the switch is off; on, the key is refused at the typed passkey
//      step and with no username, saying why (STS-AUTHN-0316), its row on
//      the portal marked and one CAEP credential change sent, the refusal
//      again marking nothing new; a key registered under a wide AAGUID list
//      refused once the list is narrowed; the switch off, it signs in;
//   C. `passkey_enterprise_serial.js` — with the attribute empty nothing is
//      checked; set, an untrusted statement is refused; a trusted packed
//      attestation from an enterprise request records the serial its
//      certificate names, from the subject's serialNumber and from Yubico's
//      extension, and registers where it is one of the person's values
//      (case and spaces aside); one that is not refused (STS-AUTHN-0320),
//      one that names none refused (STS-AUTHN-0321).
//
// NOT CARRIED (class (d)): `pki.attestationSignatureAlgorithm()` and
// `pki.attestationDeviceSerial()` over certificates (a library, asserted
// here by what the key row records); `passkey_rules.js`'s strict reading
// (a library); the sign-in verdict over a STUBBED FIDO Metadata Service — a
// model reported compromised, a certification level no longer met, a lookup
// that throws (STS-AUTHN-0317) — since no stack here serves a metadata
// service a job can make lie; and the directory hook refusing a secret
// attribute (a module call; no door asks it for one).
//
// THE CERTIFICATES ARE MADE AT RUN TIME with the service's own X.509 and
// post-quantum encoders (`common/crypto_impl/x509.js`, `pqc_x509.js`, as
// `sts_webauthn_attestation.js` does). NO REAL POST-QUANTUM AUTHENTICATOR'S
// ATTESTATION IS TESTED: the chain is shaped as WebAuthn Level 3 section
// 8.2 and RFC 9881 describe one. No key material is in this repository.
//
// EVERY REALM IS THE JOB'S OWN: each section writes `webauthn.*` trust
// settings and the passkey policy. `local: true`: written here.
// ===========================================================================

const assert = require("assert");
const nodeCrypto = require("crypto");
const { Command, Option } = require("commander");
const asn1js = require("asn1js");
const keyMaterial = require("../../common/crypto_impl/key_material");
const x509 = require("../../common/crypto_impl/x509");
const pqx = require("../../common/crypto_impl/pqc_x509");
const portalSignin = require("./portal_signin.js");
const wire = require("./passkey_wire_kit.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand run without one still loads.
  appconfigProblem = e;
  appconfig = {};
}
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_passkey_attestation_rules",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const k = wire.kit("sts_passkey_attestation_rules", { log: log });
const check = k.check;
const PASSWORD = "Pk-Attest-" + k.STAMP + "-correct-9!";
const AAGUID_OID = "1.3.6.1.4.1.45724.1.1.4";
const YUBICO_SERIAL_OID = "1.3.6.1.4.1.41482.13.1";

function who(name) {
  log.debug("Entering who().");
  log.debug("Leaving who().");
  return name + "-" + k.STAMP;
}

function hours(n) {
  log.debug("Entering hours().");
  log.debug("Leaving hours().");
  return new Date(Date.now() + n * 3600000).toISOString();
}

// The AAGUID as the certificate extension carries it: an OCTET STRING.
function aaguidExtension(aaguid) {
  log.debug("Entering aaguidExtension().");
  const der = Buffer.from(new asn1js.OctetString({
    valueHex: new Uint8Array(aaguid).buffer }).toBER(false));
  log.debug("Leaving aaguidExtension().");
  return { oid: AAGUID_OID, critical: false, value: der.toString("base64") };
}

function aaguidText(aaguid) {
  log.debug("Entering aaguidText().");
  const h = Buffer.from(aaguid).toString("hex");
  log.debug("Leaving aaguidText().");
  return h.slice(0, 8) + "-" + h.slice(8, 12) + "-" + h.slice(12, 16) + "-" +
         h.slice(16, 20) + "-" + h.slice(20);
}

// A CLASSICAL ROOT and, under it, packed attestation certificates.
async function ecRoot(name) {
  log.debug("Entering ecRoot(). " + name);
  const pair = await keyMaterial.generateKeyPair("ec-p256");
  const root = await x509.issueCertificate({
    subject: [{ name: "CN", value: name + " Root" }],
    subjectPublicKey: pair.publicPem, signatureAlg: "sha256-ecdsa",
    profile: "root-ca",
    issuer: { privateKeyPem: pair.privatePem, keyAlg: "ec-p256" },
    notBefore: hours(-1), notAfter: hours(24),
    extensions: {
      basicConstraints: { present: true, critical: true, ca: true,
                          pathLen: null },
      keyUsage: { present: true, critical: true,
                  usages: ["keyCertSign", "cRLSign"] } } });
  log.debug("Leaving ecRoot().");
  return {
    pem: root.pem,
    // `serial`: `{ subject }` as the subject's serialNumber, `{ yubico }` as
    // Yubico's serial extension (an INTEGER) — where an enterprise
    // attestation puts a device's serial.
    leaf: async function (aaguid, serial) {
      log.debug("Entering leaf().");
      const leafPair = await keyMaterial.generateKeyPair("ec-p256");
      const custom = [aaguidExtension(aaguid)];
      if (serial && serial.yubico !== undefined) {
        custom.push({ oid: YUBICO_SERIAL_OID, critical: false,
          value: Buffer.from(new asn1js.Integer({
            value: Number(serial.yubico) }).toBER(false))
            .toString("base64") });
      }
      const subject = [{ name: "C", value: "US" },
                       { name: "O", value: name },
                       { name: "OU", value: "Authenticator Attestation" },
                       { name: "CN", value: name + " Attestation" }];
      if (serial && serial.subject) {
        subject.push({ name: "serialNumber", value: serial.subject });
      }
      const cert = await x509.issueCertificate({
        subject: subject, subjectPublicKey: leafPair.publicPem,
        signatureAlg: "sha256-ecdsa", profile: "digital-signature",
        issuer: { certificatePem: root.pem, privateKeyPem: pair.privatePem,
                  keyAlg: "ec-p256" },
        notBefore: hours(-1), notAfter: hours(24),
        extensions: {
          basicConstraints: { present: true, critical: true, ca: false },
          keyUsage: { present: true, critical: true,
                      usages: ["digitalSignature"] },
          custom: custom } });
      log.debug("Leaving leaf().");
      return {
        der: Buffer.from(String(cert.pem).replace(/-----[^-]+-----/g, "")
          .replace(/\s+/g, ""), "base64"),
        alg: -7,
        sign: function (data) {
          log.debug("Entering sign() (ES256 attestation).");
          log.debug("Leaving sign() (ES256 attestation).");
          return nodeCrypto.sign("sha256", data, leafPair.privatePem);
        }
      };
    }
  };
}

// AN ML-DSA-87 ROOT AND AN ML-DSA-65 ATTESTATION CERTIFICATE UNDER IT,
// carrying what section 8.2.1 requires of a packed one.
async function mldsaChain(aaguid) {
  log.debug("Entering mldsaChain().");
  const rootPair = await pqx.generateKeyPair("ML-DSA-87");
  const rootPriv = pqx.privatePem("ML-DSA-87", rootPair.priv);
  const root = await x509.issueCertificate({
    subject: [{ name: "CN", value: "Synthetic PQ Attestation Root" }],
    subjectPublicKey: pqx.publicPem("ML-DSA-87", rootPair.pub),
    issuerPrivateKey: rootPriv, signatureAlg: "ml-dsa-87",
    notBefore: hours(-1), notAfter: hours(24),
    extensions: {
      basicConstraints: { present: true, critical: true, ca: true },
      keyUsage: { present: true, critical: true,
                  usages: ["keyCertSign", "cRLSign"] },
      subjectKeyIdentifier: { present: true } } });
  const leafPair = await pqx.generateKeyPair("ML-DSA-65");
  const leaf = await x509.issueCertificate({
    subject: [{ name: "C", value: "US" },
              { name: "O", value: "Synthetic PQ Vendor" },
              { name: "OU", value: "Authenticator Attestation" },
              { name: "CN", value: "Synthetic PQ Attestation" }],
    subjectPublicKey: pqx.publicPem("ML-DSA-65", leafPair.pub),
    signatureAlg: "ml-dsa-87",
    issuer: { certificatePem: root.pem, privateKeyPem: rootPriv,
              keyAlg: "ml-dsa-87" },
    notBefore: hours(-1), notAfter: hours(24),
    extensions: {
      basicConstraints: { present: true, critical: true, ca: false },
      keyUsage: { present: true, critical: true,
                  usages: ["digitalSignature"] },
      subjectKeyIdentifier: { present: true },
      authorityKeyIdentifier: { present: true },
      custom: [aaguidExtension(aaguid)] } });
  log.debug("Leaving mldsaChain().");
  return {
    pem: root.pem,
    der: Buffer.from(leaf.der),
    alg: -49,
    sign: async function (data) {
      log.debug("Entering sign() (ML-DSA-65 attestation).");
      const sig = await pqx.sign("ML-DSA-65", new Uint8Array(data),
                                 leafPair.priv);
      log.debug("Leaving sign() (ML-DSA-65 attestation).");
      return Buffer.from(sig);
    }
  };
}

// A packed Basic statement over the ceremony, by `leaf`. The ML-DSA
// signature is async, so the statement is signed before the credential is
// made: `packedBy()` answers an authenticator whose `register()` is async.
function packedBy(leaf, options) {
  log.debug("Entering packedBy().");
  const holder = {};
  const auth = k.authenticator(Object.assign({}, options, {
    attest: function (c) {
      log.debug("Entering attest().");
      holder.pending = c;
      log.debug("Leaving attest().");
      return { fmt: "packed", attStmt: { alg: leaf.alg, sig: holder.sig,
                                         x5c: [leaf.der] } };
    } }));
  const register = auth.register;
  auth.register = async function (challenge, handle, rpId) {
    log.debug("Entering register() (packed).");
    // A first pass learns the bytes signed over (the authenticator data
    // does not change between passes: the same key, id and counter).
    holder.sig = Buffer.alloc(0);
    register(challenge, handle, rpId);
    holder.sig = await leaf.sign(Buffer.concat([holder.pending.authData,
      holder.pending.clientDataHash]));
    const out = register(challenge, handle, rpId);
    log.debug("Leaving register() (packed).");
    return out;
  };
  log.debug("Leaving packedBy().");
  return auth;
}

// `/account-api/keys` with an authenticator whose register() may be async.
async function enrolWith(client, auth) {
  log.debug("Entering enrolWith().");
  const begun = await k.enrol(client, null, {});
  assert.ok(begun.pending && begun.pending.id, "no enrolment was begun: " +
    JSON.stringify(begun.begun && begun.begun.json).slice(0, 300));
  const p = begun.pending;
  const credential = await auth.register(p.challenge, p.userHandle, p.rpId);
  const done = await client.api("POST", "/account-api/keys", {
    action: "finish", enrolment_id: p.id,
    credential: JSON.stringify(credential) });
  log.debug("Leaving enrolWith(). " + done.status);
  return { done: done, pending: p, auth: auth,
           said: String(done.text || "") };
}

async function rowOf(realm, name, credentialId) {
  log.debug("Entering rowOf().");
  const keys = await k.keysOf(realm, name);
  log.debug("Leaving rowOf().");
  return keys.filter(function (one) {
    return one.credentialId === credentialId;
  })[0] || null;
}

async function withCode(realm, code, fn) {
  log.debug("Entering withCode(). " + code);
  const before = await k.codeCount(realm, code);
  const out = await fn();
  out.recorded = await k.newCodes(realm, code, before);
  log.debug("Leaving withCode(). " + out.recorded);
  return out;
}

async function portalOf(realm, name, attributes) {
  log.debug("Entering portalOf(). " + name);
  await k.person(realm, name, PASSWORD, attributes);
  const client = await portalSignin.signInToThePortal(realm.base, name, null,
    { password: PASSWORD });
  log.debug("Leaving portalOf().");
  return client;
}

// A typed passwordless sign-in with `auth`'s key.
async function signIn(realm, name, auth) {
  log.debug("Entering signIn(). " + name);
  const t = await k.typed(realm, name, {});
  if (!t.step) {
    log.debug("Leaving signIn(). No step.");
    return t.answer;
  }
  const done = await k.ceremony(t.step, function (c) {
    return auth.assert(c.challenge);
  });
  log.debug("Leaving signIn(). " + done.next);
  return done;
}

// ---------------------------------------------------------------------------
// A. WHAT AN ATTESTATION IS SIGNED WITH (#941, #1114).
// ---------------------------------------------------------------------------
async function algorithms() {
  log.debug("Entering algorithms().");
  log.info("=== A. what an attestation is signed with ===");
  const realm = await k.realm("pkat-a", "development");
  await k.client(realm);
  const aaguid = nodeCrypto.randomBytes(16);
  const pq = await mldsaChain(aaguid);
  const ec = await ecRoot("Classical Vendor " + k.STAMP);
  const ecLeaf = await ec.leaf(aaguid);
  await k.mustSet(realm, "webauthn.attestationPolicy", "verify-if-present");
  await k.mustSet(realm, "webauthn.attestationTrustAnchors",
                  pq.pem.trim() + "\n" + ec.pem.trim());
  const name = who("alg");
  const portal = await portalOf(realm, name);

  const pqKey = await enrolWith(portal, packedBy(pq, { aaguid: aaguid,
                                                       alg: -49 }));
  const ecKey = await enrolWith(portal, packedBy(ecLeaf, { aaguid: aaguid }));
  const pqRow = await rowOf(realm, name, pqKey.auth.credentialId) || {};
  const ecRow = await rowOf(realm, name, ecKey.auth.credentialId) || {};
  const pa = ((pqRow.attestation || {}).algorithms) || {};
  const ea = ((ecRow.attestation || {}).algorithms) || {};
  check("A1. an ML-DSA packed attestation under an ML-DSA root is recorded " +
        "on the key's row: its statement ML-DSA-65 (-49), its certificate " +
        "and anchor ML-DSA-87, all post-quantum, trusted", function () {
    assert.strictEqual(pqKey.done.status, 200, pqKey.said.slice(0, 300));
    assert.strictEqual(pqRow.attestation.trusted, true,
                       JSON.stringify(pqRow.attestation).slice(0, 400));
    assert.strictEqual(pa.statement, "ML-DSA-65", JSON.stringify(pa));
    assert.strictEqual(pa.statementCoseAlg, -49);
    assert.strictEqual(pa.certificates.length, 1);
    assert.strictEqual(pa.certificates[0].algorithm, "ML-DSA-87");
    assert.strictEqual(pa.anchor && pa.anchor.algorithm, "ML-DSA-87");
    assert.strictEqual(pa.postQuantum, true);
  });
  check("A2. a classical one is recorded as ES256 under sha256-ecdsa, not " +
        "post-quantum, and the API's key row carries each reading",
        function () {
    assert.strictEqual(ecKey.done.status, 200, ecKey.said.slice(0, 300));
    assert.strictEqual(ea.statement, "ES256", JSON.stringify(ea));
    assert.strictEqual(ea.certificates[0].algorithm, "sha256-ecdsa");
    assert.strictEqual(ea.anchor && ea.anchor.algorithm, "sha256-ecdsa");
    assert.strictEqual(ea.postQuantum, false);
    assert.strictEqual((pqRow.attestationAlgorithms || {}).postQuantum, true,
                       JSON.stringify(pqRow.attestationAlgorithms));
    assert.strictEqual((ecRow.attestationAlgorithms || {}).postQuantum, false,
                       JSON.stringify(ecRow.attestationAlgorithms));
  });

  await k.mustSavePolicy(realm, { attestationAlgorithms: "post-quantum" });
  const classical = await withCode(realm, "STS-AUTHN-0411", function () {
    return ec.leaf(aaguid).then(function (leaf) {
      return enrolWith(portal, packedBy(leaf, { aaguid: aaguid }));
    });
  });
  // NO ATTESTATION is refused before the algorithms are read: the list
  // demands a trusted statement, and `none` proves nothing (STS-AUTHN-0240).
  const unattested = await withCode(realm, "STS-AUTHN-0240", function () {
    return enrolWith(portal, k.authenticator({ aaguid: aaguid }));
  });
  const taken = await enrolWith(portal, packedBy(pq, { aaguid: aaguid,
                                                       alg: -49 }));
  await k.mustSavePolicy(realm, { attestationAlgorithms: "ml-dsa-65" });
  const narrow = await withCode(realm, "STS-AUTHN-0411", function () {
    return enrolWith(portal, packedBy(pq, { aaguid: aaguid, alg: -49 }));
  });
  check("A3. attestationAlgorithms refuses a classical attestation under " +
        "post-quantum and an ML-DSA-87 signature under ml-dsa-65 alone " +
        "(STS-AUTHN-0411), no attestation at all as untrusted " +
        "(STS-AUTHN-0240), and takes the post-quantum one", function () {
    assert.strictEqual(classical.done.status, 400,
                       classical.said.slice(0, 300));
    assert.ok(classical.recorded > 0, "no STS-AUTHN-0411 row (classical)");
    assert.strictEqual(unattested.done.status, 400,
                       unattested.said.slice(0, 300));
    assert.ok(unattested.recorded > 0, "no STS-AUTHN-0240 row (none)");
    assert.strictEqual(narrow.done.status, 400, narrow.said.slice(0, 300));
    assert.ok(narrow.recorded > 0, "no STS-AUTHN-0411 row (ml-dsa-65)");
    assert.strictEqual(taken.done.status, 200, taken.said.slice(0, 300));
  });

  await k.mustSavePolicy(realm, { attestationAlgorithms: "post-quantum" });
  const mixedPq = await withCode(realm, "STS-AUTHN-0411", function () {
    return enrolWith(portal, packedBy(ecLeaf, { aaguid: aaguid, alg: -49 }));
  });
  const mixedEc = await enrolWith(portal, packedBy(pq, { aaguid: aaguid }));
  const mixedRow = await rowOf(realm, name, mixedEc.auth.credentialId) || {};
  check("A4. THE CREDENTIAL'S ALGORITHM AND THE ATTESTATION'S ARE RECORDED " +
        "INDEPENDENTLY: an ML-DSA-65 credential under a classical leaf is " +
        "refused under post-quantum, and an ES256 credential under the " +
        "ML-DSA chain is taken, its row saying ES256 for the credential and " +
        "ML-DSA-65 for the statement", function () {
    assert.strictEqual(mixedPq.done.status, 400, mixedPq.said.slice(0, 300));
    assert.ok(mixedPq.recorded > 0, "no STS-AUTHN-0411 row (mixed)");
    assert.strictEqual(mixedEc.done.status, 200, mixedEc.said.slice(0, 300));
    assert.strictEqual((mixedRow.algorithm || {}).name, "ES256");
    assert.strictEqual(((mixedRow.attestation || {}).algorithms || {})
      .statement, "ML-DSA-65");
  });

  // D. At sign-in, only while enforceAttestationAtSignIn is on.
  await k.mustSavePolicy(realm, {});
  const held = await signIn(realm, name, ecKey.auth);
  await k.mustSavePolicy(realm, { attestationAlgorithms: "post-quantum" });
  const listOnly = await signIn(realm, name, ecKey.auth);
  const enforced = await withCode(realm, "STS-AUTHN-0412", async function () {
    await k.mustSavePolicy(realm, { attestationAlgorithms: "post-quantum",
                                    enforceAttestationAtSignIn: true });
    return { answer: await signIn(realm, name, ecKey.auth) };
  });
  const pqStill = await signIn(realm, name, pqKey.auth);
  await k.mustSavePolicy(realm, { attestationAlgorithms: "post-quantum" });
  const again = await signIn(realm, name, ecKey.auth);
  check("A5. at sign-in the recorded algorithms are held to the list only " +
        "while enforceAttestationAtSignIn is on: the classical key signs in " +
        "under post-quantum with the switch off, is refused with it on " +
        "(STS-AUTHN-0412) while the post-quantum key signs in, and signs in " +
        "again with it off", function () {
    assert.strictEqual(held.next, "redirect", k.said(held).slice(0, 300));
    assert.strictEqual(listOnly.next, "redirect",
                       k.said(listOnly).slice(0, 300));
    assert.notStrictEqual(enforced.answer.next, "redirect",
                          k.said(enforced.answer).slice(0, 300));
    assert.ok(enforced.recorded > 0, "no STS-AUTHN-0412 row");
    assert.strictEqual(pqStill.next, "redirect", k.said(pqStill).slice(0, 300));
    assert.strictEqual(again.next, "redirect", k.said(again).slice(0, 300));
  });
  log.debug("Leaving algorithms().");
}

// ---------------------------------------------------------------------------
// B. THE ATTESTATION RULES AT SIGN-IN (#530).
// ---------------------------------------------------------------------------
// Every CAEP row the realm's audit log holds, by action.
async function caepCount(realm, atLeast) {
  log.debug("Entering caepCount().");
  let n = 0;
  for (let i = 0; i < 20; i += 1) {
    const r = await k.call(realm, "GET", "/audit?per=1");
    const by = (r.body && r.body.byAction) || {};
    n = Object.keys(by).filter(function (one) {
      return /^caep\./.test(one);
    }).reduce(function (sum, one) {
      return sum + Number(by[one] || 0);
    }, 0);
    if (!atLeast || n >= atLeast) {
      break;
    }
    await k.sleep(150);
  }
  log.debug("Leaving caepCount(). " + n);
  return n;
}

async function atSignIn() {
  log.debug("Entering atSignIn().");
  log.info("=== B. the attestation rules at sign-in ===");
  const realm = await k.realm("pkat-b", "development");
  await k.client(realm);
  const name = who("alice");
  const portal = await portalOf(realm, name);
  const alice = k.authenticator({});
  const plain = await k.enrol(portal, alice, {});
  const row = async function () {
    log.debug("Entering row().");
    log.debug("Leaving row().");
    return await rowOf(realm, name, alice.credentialId) || {};
  };
  const first = await row();
  let r = await signIn(realm, name, alice);
  check("B1. a key registered with `none` attestation — nothing trusted — " +
        "signs in", function () {
    assert.strictEqual(plain.done.status, 200);
    assert.strictEqual((first.attestation || {}).trusted, false);
    assert.strictEqual(r.next, "redirect", k.said(r).slice(0, 300));
  });
  const listed = nodeCrypto.randomBytes(16);
  await k.mustSet(realm, "webauthn.attestationAllowedAaguids",
                  aaguidText(listed));
  r = await signIn(realm, name, alice);
  check("B2. a rule demanding trust (an AAGUID list) is still a " +
        "REGISTRATION rule while the switch is off", function () {
    assert.strictEqual(r.next, "redirect", k.said(r).slice(0, 300));
  });

  await k.mustSavePolicy(realm, { enforceAttestationAtSignIn: true });
  const caepBefore = await caepCount(realm);
  const typed = await withCode(realm, "STS-AUTHN-0316", async function () {
    return { answer: await signIn(realm, name, alice) };
  });
  // THE MARK IS THE PORTAL'S TO SHOW: `/account-api/keys` carries the
  // sentence on the key's row (the management API's row does not).
  const portalRow = async function () {
    log.debug("Entering portalRow().");
    const page = await portal.api("GET", "/account-api/keys");
    log.debug("Leaving portalRow().");
    return (((page.json && page.json.keys) || []).filter(function (one) {
      return one.credentialId === alice.credentialId;
    })[0]) || {};
  };
  const marked = await portalRow();
  const caepAfter = await caepCount(realm, caepBefore + 1);
  const noName = await k.usernameless(realm, function (challenge) {
    return alice.assert(challenge);
  });
  const markedAgain = await portalRow();
  const caepAgain = await caepCount(realm);
  check("B3. the switch on: the key is refused at the passkey step, saying " +
        "it requires a trusted attestation (STS-AUTHN-0316), its row marked " +
        "and one CAEP credential change sent", function () {
    assert.notStrictEqual(typed.answer.next, "redirect",
                          k.said(typed.answer).slice(0, 300));
    assert.ok(/requires a trusted one/.test(k.said(typed.answer)),
              k.said(typed.answer).slice(0, 300));
    assert.ok(typed.recorded > 0, "no STS-AUTHN-0316 row");
    assert.ok(typeof marked.attestationRefused === "string" &&
              marked.attestationRefused.length > 0,
              JSON.stringify(marked).slice(0, 400));
    assert.strictEqual(caepAfter - caepBefore, 1,
                       caepBefore + " then " + caepAfter);
  });
  check("B4. and with no username, saying why — the same refusal again " +
        "marks nothing new and sends no second signal", function () {
    assert.strictEqual(noName.next, "refused", k.said(noName).slice(0, 300));
    assert.ok(/requires a trusted one/.test(k.said(noName)),
              k.said(noName).slice(0, 300));
    assert.strictEqual(markedAgain.attestationRefused,
                       marked.attestationRefused);
    assert.strictEqual(caepAgain, caepAfter);
  });
  await k.mustSavePolicy(realm, {});
  r = await signIn(realm, name, alice);
  check("B5. the switch off again, it signs in", function () {
    assert.strictEqual(r.next, "redirect", k.said(r).slice(0, 300));
  });

  // A key registered under a wide AAGUID list, then the list narrowed.
  const wide = nodeCrypto.randomBytes(16);
  const ec = await ecRoot("Wide Vendor " + k.STAMP);
  await k.mustSet(realm, "webauthn.attestationPolicy", "verify-if-present");
  await k.mustSet(realm, "webauthn.attestationTrustAnchors", ec.pem);
  await k.mustSet(realm, "webauthn.attestationAllowedAaguids",
                  aaguidText(wide) + "," + aaguidText(listed));
  const bob = who("bob");
  const bobPortal = await portalOf(realm, bob);
  const bobKey = await enrolWith(bobPortal,
                                 packedBy(await ec.leaf(wide),
                                          { aaguid: wide }));
  await k.mustSavePolicy(realm, { enforceAttestationAtSignIn: true });
  const wideIn = await signIn(realm, bob, bobKey.auth);
  await k.mustSet(realm, "webauthn.attestationAllowedAaguids",
                  aaguidText(listed));
  const narrowed = await withCode(realm, "STS-AUTHN-0316", async function () {
    return { answer: await signIn(realm, bob, bobKey.auth) };
  });
  check("B6. a key registered under a wide AAGUID list signs in under it, " +
        "and is refused once the list is narrowed (STS-AUTHN-0316)",
        function () {
    assert.strictEqual(bobKey.done.status, 200, bobKey.said.slice(0, 300));
    assert.strictEqual(wideIn.next, "redirect", k.said(wideIn).slice(0, 300));
    assert.notStrictEqual(narrowed.answer.next, "redirect",
                          k.said(narrowed.answer).slice(0, 300));
    assert.ok(narrowed.recorded > 0, "no STS-AUTHN-0316 row (narrowed)");
  });
  log.debug("Leaving atSignIn().");
}

// ---------------------------------------------------------------------------
// C. A SECURITY KEY'S SERIAL BOUND TO ITS PERSON (#532).
// ---------------------------------------------------------------------------
async function serials() {
  log.debug("Entering serials().");
  log.info("=== C. a security key's serial ===");
  const realm = await k.realm("pkat-c", "development");
  const aaguid = nodeCrypto.randomBytes(16);
  const ec = await ecRoot("Enterprise Vendor " + k.STAMP);
  await k.mustSet(realm, "webauthn.attestationPolicy", "verify-if-present");
  await k.mustSet(realm, "webauthn.attestationTrustAnchors", ec.pem);
  // AN ENTERPRISE REQUEST AT THIS RP ID (#1114): a serial is read only
  // from a statement one produced. The list first, so the write rule holds.
  await k.mustSet(realm, "webauthn.attestationEnterpriseRpIds", k.RP_ID);
  await k.mustSet(realm, "webauthn.attestation", "enterprise");
  const name = who("ser");
  const portal = await portalOf(realm, name,
                                { departmentNumber: ["5550001", " sn-abc "] });
  const unbound = await enrolWith(portal, k.authenticator({}));
  check("C1. with the attribute empty nothing is checked: a key with no " +
        "serial registers", function () {
    assert.strictEqual(unbound.done.status, 200, unbound.said.slice(0, 300));
  });

  // The person's serials in a multi-valued attribute a create may write
  // (`serialNumber` is not in a person's catalogue here).
  await k.mustSavePolicy(realm,
                         { enterpriseSerialAttribute: "departmentNumber" });
  const untrusted = await withCode(realm, "STS-AUTHN-0240", function () {
    return enrolWith(portal, k.authenticator({}));
  });
  const cased = await enrolWith(portal, packedBy(await ec.leaf(aaguid,
    { subject: "SN-ABC" }), { aaguid: aaguid, attachment: "cross-platform",
                              transports: ["usb"] }));
  const yubico = await enrolWith(portal, packedBy(await ec.leaf(aaguid,
    { yubico: 5550001 }), { aaguid: aaguid, attachment: "cross-platform",
                            transports: ["usb"] }));
  const casedRow = await rowOf(realm, name, cased.auth.credentialId) || {};
  const yubicoRow = await rowOf(realm, name, yubico.auth.credentialId) || {};
  check("C2. set, it demands a trusted statement — an unattested key is " +
        "refused — and a trusted packed attestation from an enterprise " +
        "request records the serial its certificate names, from the " +
        "subject's serialNumber and from Yubico's extension, and registers " +
        "where it is one of the person's values (case and spaces aside)",
        function () {
    assert.strictEqual(untrusted.done.status, 400,
                       untrusted.said.slice(0, 300));
    assert.ok(untrusted.recorded > 0, "no STS-AUTHN-0240 row");
    assert.ok(/binds security-key serials/.test(untrusted.said),
              untrusted.said.slice(0, 300));
    assert.strictEqual(cased.done.status, 200, cased.said.slice(0, 300));
    assert.strictEqual(yubico.done.status, 200, yubico.said.slice(0, 300));
    assert.strictEqual(casedRow.deviceSerial, "SN-ABC",
                       JSON.stringify(casedRow).slice(0, 300));
    assert.strictEqual(yubicoRow.deviceSerial, "5550001",
                       JSON.stringify(yubicoRow).slice(0, 300));
  });
  const other = await withCode(realm, "STS-AUTHN-0320", async function () {
    return enrolWith(portal, packedBy(await ec.leaf(aaguid,
      { subject: "9990009" }), { aaguid: aaguid }));
  });
  const none = await withCode(realm, "STS-AUTHN-0321", async function () {
    return enrolWith(portal, packedBy(await ec.leaf(aaguid),
                                      { aaguid: aaguid }));
  });
  check("C3. a serial that is not the person's is refused (STS-AUTHN-0320), " +
        "saying it is not one issued to them, and one that names none is " +
        "refused (STS-AUTHN-0321)", function () {
    assert.strictEqual(other.done.status, 400, other.said.slice(0, 300));
    assert.ok(/not one issued to you/.test(other.said),
              other.said.slice(0, 300));
    assert.ok(other.recorded > 0, "no STS-AUTHN-0320 row");
    assert.strictEqual(none.done.status, 400, none.said.slice(0, 300));
    assert.ok(none.recorded > 0, "no STS-AUTHN-0321 row");
  });
  log.debug("Leaving serials().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving the passkey attestation rules at " + k.root);
  await algorithms();
  await atSignIn();
  await serials();
  assert.ok(k.checks() >= 14, "only " + k.checks() + " checks ran; a " +
            "section has stopped being called.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_passkey_attestation_rules")
  .description("What a passkey's attestation is held to over the wire: its " +
      "algorithms recorded and enforced, the rules at sign-in, and a " +
      "security key's serial bound to its person (D12, #444).")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

k.main(test);
