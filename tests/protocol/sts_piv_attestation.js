// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_piv_attestation.js
//
// ---------------------------------------------------------------------------
// A YUBIKEY PIV KEY ATTESTATION OVER EST, AND THE ENROLMENT FORM'S API
// (#1955 P2), over HTTP, in a throwaway realm.
//
//   0. A realm of its own, a person with a password and a mail address, EST
//      allowed the four PIV slot profiles, and the job's own Yubico-shaped
//      PIV root as the realm's piv.attestationAnchors.
//   1. EST /piv-auth/simpleenroll with a request carrying
//      draft-ietf-lamps-csr-attestation's id-aa-attestation attribute (the
//      slot attestation certificate as the statement, the f9 certificate in
//      `certs`): issued, and the YubiKey is in /admin-api/hardware-tokens
//      under its serial, its evidence `piv-attestation`, the certificate on
//      it.
//   2. The same request whose attestation certifies another key: refused
//      400, and the answer names no error code.
//   3. A 9a attestation offered for piv-sign: refused.
//   4. POST /admin-api/hardware-tokens/enrol-piv with the form's three PEM
//      texts: issued, attested, on the token. An unknown action names the
//      three acts.
//   5. ESCROW: /piv-key-management/serverkeygen refused while
//      piv.keyEscrow is off (501); with it on, either issued and listed in
//      /admin-api/hardware-tokens/escrowed (where this stack holds a
//      key-encryption key) or refused 503; recovery by a caller without
//      PIV_KEY_RECOVERY is 403.
//
// EVERY KEY AND CERTIFICATE IS MADE HERE, AT RUN TIME (rcbj: no key
// material in git), with Yubico's extensions as its PIV attestation page
// defines them. With STS_TEST_REMOVE_REALMS=1 the realm is removed at the
// end, pass or fail (tests/CLAUDE.md).
//
// OWNED HERE (local: true): this repository's EST server, hardware token
// register and management API.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const asn1js = require("asn1js");
const pkijs = require("pkijs");
const est = require("./est_client.js");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const registry = require("./sts_applications.js");

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
var log = bunyan.createLogger({ name: "sts_piv_attestation",
                                level: appconfig.LOG_LEVEL ||
                                       process.env.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var root = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("piv-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                            .slice(0, 31);
const base = root + "/realm/" + REALM;
const api = base + "/admin-api";
const OWNER = names.usernameFor("piv-owner");
const PASSWORD = "Piv-owner-" + crypto.randomBytes(9).toString("base64url") +
                 "-Aa1!";
const EST = base + "/.well-known/est";
const YUBICO = "1.3.6.1.4.1.41482.3.";
const STATEMENT = "1.3.6.1.4.1.41482.3.2";
const ID_AA_ATTESTATION = "1.2.840.113549.1.9.16.2.59";
const EC = { name: "ECDSA", namedCurve: "P-256" };

pkijs.setEngine("node", new pkijs.CryptoEngine({ name: "node",
  crypto: crypto.webcrypto }));

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

async function post(url, payload) {
  log.debug("Entering post(). " + url);
  const r = await fetch(url, { method: "POST",
    headers: { "content-type": "application/json",
               accept: "application/json" },
    body: JSON.stringify(payload || {}) });
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in post(): " + ((e && e.message) || e));
    json = null;
  }
  log.debug("Leaving post(). " + r.status);
  return { status: r.status, text: text, json: json };
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await post(url, payload);
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + r.text.slice(0, 400));
  log.debug("Leaving ok().");
  return r.json;
}

async function read(where) {
  log.debug("Entering read(). " + where);
  const r = await fetch(api + where, { headers: {
    accept: "application/json" } });
  const text = await r.text();
  assert.strictEqual(r.status, 200, "GET " + where + " answered " + r.status +
                     " " + text.slice(0, 300));
  log.debug("Leaving read().");
  return JSON.parse(text);
}

// ---------------------------------------------------------------------------
// A YUBICO-SHAPED DEVICE: a root, an f9 certificate under it (a CA), and a
// slot attestation certificate with Yubico's four extensions.
// ---------------------------------------------------------------------------
function pemOf(der, label) {
  log.debug("Entering pemOf().");
  log.debug("Leaving pemOf().");
  return "-----BEGIN " + label + "-----\n" +
    Buffer.from(der).toString("base64").replace(/(.{64})/g, "$1\n") +
    "\n-----END " + label + "-----\n";
}

function ext(oid, critical, bytes) {
  log.debug("Entering ext().");
  log.debug("Leaving ext().");
  return new pkijs.Extension({ extnID: oid, critical: !!critical,
    extnValue: bytes instanceof ArrayBuffer ? bytes
      : new Uint8Array(Buffer.from(bytes)).buffer });
}

async function certificate(o) {
  log.debug("Entering certificate().");
  const cert = new pkijs.Certificate();
  cert.version = 2;
  cert.serialNumber = new asn1js.Integer({ valueHex: new Uint8Array(
    Buffer.concat([Buffer.from([1]), crypto.randomBytes(8)])).buffer });
  const dn = new pkijs.RelativeDistinguishedNames();
  dn.typesAndValues.push(new pkijs.AttributeTypeAndValue({ type: "2.5.4.3",
    value: new asn1js.Utf8String({ value: o.cn }) }));
  cert.subject = dn;
  cert.issuer = o.issuer ? o.issuer.cert.subject : dn;
  cert.notBefore.value = new Date(Date.now() - 3600 * 1000);
  cert.notAfter.value = new Date(Date.now() + 365 * 86400000);
  cert.extensions = [];
  if (o.ca) {
    cert.extensions.push(ext("2.5.29.19", true, new pkijs.BasicConstraints({
      cA: true }).toSchema().toBER(false)));
    cert.extensions.push(ext("2.5.29.15", true, new asn1js.BitString({
      valueHex: new Uint8Array([0x06]).buffer, unusedBits: 1 })
      .toBER(false)));
  }
  (o.extensions || []).forEach(function (one) {
    cert.extensions.push(one);
  });
  await cert.subjectPublicKeyInfo.importKey(o.publicKey);
  await cert.sign(o.issuer ? o.issuer.key : o.signingKey, "SHA-256");
  const der = Buffer.from(cert.toSchema(true).toBER(false));
  log.debug("Leaving certificate().");
  return { cert: cert, der: der, pem: pemOf(der, "CERTIFICATE") };
}

async function pair() {
  log.debug("Entering pair().");
  log.debug("Leaving pair().");
  return crypto.webcrypto.subtle.generateKey(EC, true, ["sign", "verify"]);
}

async function device() {
  log.debug("Entering device().");
  const rootKeys = await pair();
  const rootCert = await certificate({ cn: "PIV job root " + STAMP,
    publicKey: rootKeys.publicKey, signingKey: rootKeys.privateKey,
    ca: true });
  const f9Keys = await pair();
  const f9 = await certificate({ cn: "Yubico PIV Attestation",
    publicKey: f9Keys.publicKey, ca: true,
    issuer: { cert: rootCert.cert, key: rootKeys.privateKey } });
  log.debug("Leaving device().");
  return { root: rootCert, f9: f9, f9Key: f9Keys.privateKey };
}

// A key in `slot`, its attestation (of another key with `other`), and a
// request over the key carrying the attestation when `inRequest`.
async function slotKey(dev, slot, o) {
  log.debug("Entering slotKey(). " + slot);
  const opts = o || {};
  const keys = await pair();
  const attested = opts.other ? await pair() : keys;
  const serial = 20000000 + crypto.randomInt(70000000);
  const hex = serial.toString(16).padStart(8, "0");
  const slotCert = await certificate({ cn: "YubiKey PIV Attestation " + slot,
    publicKey: attested.publicKey,
    issuer: { cert: dev.f9.cert, key: dev.f9Key },
    extensions: [ext(YUBICO + "3", false, [5, 4, 3]),
                 ext(YUBICO + "7", false, Buffer.concat([
                   Buffer.from([0x02, 4]), Buffer.from(hex, "hex")])),
                 ext(YUBICO + "8", false, [2, 2]),
                 ext(YUBICO + "9", false, [3])] });
  const csr = new pkijs.CertificationRequest();
  csr.subject.typesAndValues.push(new pkijs.AttributeTypeAndValue({
    type: "2.5.4.3", value: new asn1js.Utf8String({ value: OWNER }) }));
  await csr.subjectPublicKeyInfo.importKey(keys.publicKey);
  if (opts.inRequest !== false) {
    const bundle = new asn1js.Sequence({ value: [
      new asn1js.Sequence({ value: [new asn1js.Sequence({ value: [
        new asn1js.ObjectIdentifier({ value: STATEMENT }),
        asn1js.fromBER(new Uint8Array(slotCert.der).buffer).result] })] }),
      new asn1js.Sequence({ value: [
        asn1js.fromBER(new Uint8Array(dev.f9.der).buffer).result] })] });
    csr.attributes = [new pkijs.Attribute({ type: ID_AA_ATTESTATION,
                                            values: [bundle] })];
  }
  await csr.sign(keys.privateKey, "SHA-256");
  const der = Buffer.from(csr.toSchema().toBER(false));
  log.debug("Leaving slotKey().");
  return { csrDer: der, csrPem: pemOf(der, "CERTIFICATE REQUEST"),
           slotPem: slotCert.pem, f9Pem: dev.f9.pem, serial: String(serial) };
}

async function enroll(label, der, kind) {
  log.debug("Entering enroll(). " + label);
  const r = await est.send({ method: "POST",
    url: EST + "/" + label + "/" + (kind || "simpleenroll"),
    body: est.requestBody(der), basic: [OWNER, PASSWORD],
    headers: { "Content-Type": "application/pkcs10" } });
  log.debug("Leaving enroll(). " + r.status);
  return { status: r.status, body: String(r.body) };
}

async function tokenOf(serial) {
  log.debug("Entering tokenOf(). " + serial);
  const v = await read("/hardware-tokens?q=" + encodeURIComponent(serial));
  log.debug("Leaving tokenOf().");
  return (v.tokens || []).filter(function (one) {
    return one.serial === serial;
  })[0] || null;
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. a throwaway realm " + REALM + " ===");
  await ok(root + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "PIV " + STAMP,
    overrides: { "global.mode": "development" } }, "created the realm");
  await registry.ensurePerson(base, OWNER, PASSWORD);
  const dev = await device();
  await ok(api + "/config/set", { key: "est.allowedProfiles",
    value: "tls-client,piv-auth,piv-sign,piv-key-management,piv-card-auth" },
           "let EST issue the PIV profiles");
  await ok(api + "/config/set", { key: "piv.attestationAnchors",
                                  value: dev.root.pem },
           "trusted the job's PIV root");

  log.info("=== 1. an attested request over EST ===");
  const good = await slotKey(dev, "9a", {});
  const issued = await enroll("piv-auth", good.csrDer);
  const token = issued.status === 200 ? await tokenOf(good.serial) : null;
  check("issued, and the YubiKey is recorded under its serial from " +
        "piv-attestation, the certificate on it", function () {
    assert.strictEqual(issued.status, 200, issued.body.slice(0, 300));
    assert.ok(token, "no token " + good.serial);
    assert.ok(token.evidenceSources.indexOf("piv-attestation") >= 0,
              JSON.stringify(token));
    assert.strictEqual(token.holder, OWNER, JSON.stringify(token));
    assert.ok(token.credentials.some(function (c) {
      return c.kind === "x509" && c.smartCard === true;
    }), JSON.stringify(token.credentials));
  });

  log.info("=== 2. an attestation of another key ===");
  const other = await enroll("piv-auth",
    (await slotKey(dev, "9a", { other: true })).csrDer);
  check("refused 400, naming no error code", function () {
    assert.strictEqual(other.status, 400, other.body.slice(0, 300));
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(other.body), other.body);
  });

  log.info("=== 3. a 9a attestation for piv-sign ===");
  const wrongSlot = await enroll("piv-sign",
                                 (await slotKey(dev, "9a", {})).csrDer);
  check("refused: the attestation is for another slot", function () {
    assert.strictEqual(wrongSlot.status, 400, wrongSlot.body.slice(0, 300));
  });

  log.info("=== 4. the enrolment form's API ===");
  const form = await slotKey(dev, "9c", { inRequest: false });
  const viaApi = await post(api + "/hardware-tokens/enrol-piv", {
    username: OWNER, profile: "piv-sign", csr: form.csrPem,
    attestationCertificate: form.slotPem, attestationIssuer: form.f9Pem });
  const unknown = await post(api + "/hardware-tokens/misplaced", {});
  check("enrol-piv issues an attested piv-sign certificate on the token, " +
        "and an unknown action names the three acts", function () {
    assert.strictEqual(viaApi.status, 200, viaApi.text.slice(0, 300));
    assert.strictEqual(viaApi.json.attested, true, viaApi.text.slice(0, 300));
    assert.strictEqual(viaApi.json.token, "yubico/" + form.serial);
    assert.ok(/BEGIN CERTIFICATE/.test(viaApi.json.certificatePem));
    assert.strictEqual(unknown.status, 400, unknown.text.slice(0, 300));
    assert.ok(/lost, enrol-piv, recover-key/.test(unknown.text),
              unknown.text.slice(0, 300));
  });

  log.info("=== 5. escrow ===");
  const template = (await slotKey(dev, "9d", { inRequest: false })).csrDer;
  await ok(api + "/config/set", { key: "est.serverKeyGeneration",
                                  value: true }, "turned server keys on");
  const off = await enroll("piv-key-management", template, "serverkeygen");
  await ok(api + "/config/set", { key: "piv.keyEscrow", value: true },
           "turned escrow on");
  const on = await enroll("piv-key-management", template, "serverkeygen");
  const listed = await read("/hardware-tokens/escrowed?username=" +
                            encodeURIComponent(OWNER));
  const serial = (listed.escrowed[0] || {}).serialHex || "00";
  const recovery = await post(api + "/hardware-tokens/recover-key",
                              { username: OWNER, serial: serial });
  check("escrow off refuses a 9d server key (501); on, it is issued and " +
        "listed (or 503 with no key-encryption key); a caller without " +
        "PIV_KEY_RECOVERY cannot recover it (403)", function () {
    assert.strictEqual(off.status, 501, off.body.slice(0, 300));
    assert.ok(on.status === 200 || on.status === 503, on.body.slice(0, 300));
    assert.strictEqual(listed.escrowed.length, on.status === 200 ? 1 : 0,
                       JSON.stringify(listed));
    // The policy is asked BEFORE the key is looked for, so a caller without
    // the role learns nothing about whether one is held.
    assert.strictEqual(recovery.status, 403, recovery.text.slice(0, 300));
    assert.ok(/PIV_KEY_RECOVERY/.test(recovery.text),
              recovery.text.slice(0, 300));
    assert.ok(!/PRIVATE KEY/.test(recovery.text), "no key was handed over");
  });

  assert.ok(checks >= 5, "only " + checks + " checks ran");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

// REMOVAL IS OPT-IN (tests/CLAUDE.md): with STS_TEST_REMOVE_REALMS=1 the
// realm this run made is removed at the end, pass or fail.
async function removeRealm() {
  log.debug("Entering removeRealm().");
  if (process.env.STS_TEST_REMOVE_REALMS !== "1") {
    log.debug("Leaving removeRealm(). Not asked to.");
    return;
  }
  const r = await post(root + "/admin-api/realms/remove", { id: REALM });
  log.info("removed the realm " + REALM + " (" + r.status + ")");
  log.debug("Leaving removeRealm().");
}

new Command()
  .description("A YubiKey PIV key attestation over EST and the PIV " +
    "enrolment form's API (#1955 P2): an attested request recorded as a " +
    "hardware token, the refusals, enrol-piv, and escrow.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().then(function () {
  return removeRealm().then(function () {
    process.exit(0);
  });
}, function (e) {
  log.error(e.stack || e.message);
  return removeRealm().then(function () {
    process.exit(1);
  }, function (e2) {
    log.debug("Caught in the job's exit: " + ((e2 && e2.message) || e2));
    process.exit(1);
  });
});
