// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_est_attestation_freshness.js
//
// ---------------------------------------------------------------------------
// A TPM KEY ATTESTATION'S FRESHNESS OVER EST (#257, 2026-10-06), over HTTP,
// in a throwaway realm.
//
// draft-ietf-lamps-csr-attestation section 6.2 defers freshness to
// draft-ietf-lamps-attestation-freshness, whose section 5.1 is EST's
// `/nonce`. This job is an EST client doing what that section says, with a
// TPM it builds itself: the TPM2_Certify statement's extraData is the nonce.
//
//   1. /nonce is authenticated: no credential, 401.
//   2. GET /.well-known/est/device/nonce: 200, the draft's media type, a
//      32-octet unpadded base64url nonce, an expiry, and the sts_est_nonce
//      cookie.
//   3. A device simpleenroll whose TPM statement carries that nonce, sent
//      with the cookie: issued, the key attested and its freshness FRESH.
//   4. THE REPLAY the ticket is about: the same statement again, in a new
//      request for the same key — in development certified with freshness
//      UNPROVEN.
//   5. POST { len: 48 }: 48 octets; another media type, a member the CDDL
//      does not define and a reqTypeInfo refused (400, 400, 503); a label
//      that reads no attestation answers the empty nonce.
//   6. PRODUCT MODE on the realm: the replay is REFUSED 403, and a fresh
//      statement is issued.
//
// EVERY KEY AND CERTIFICATE IS MADE HERE, AT RUN TIME (rcbj: no key
// material in git): a test TPM manufacturer root, configured as the realm's
// devices.tpmTrustAnchors, and an Attestation Key certified under it.
//
// OWNED HERE (local: true): this repository's EST server and device
// register.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const path = require("path");
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
var log = bunyan.createLogger({ name: "sts_est_attestation_freshness",
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
const REALM = ("fresh-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                              .slice(0, 31);
const base = root + "/realm/" + REALM;
const api = base + "/admin-api";
const OWNER = names.usernameFor("fresh-owner");
const PASSWORD = "Fresh-owner-" + crypto.randomBytes(9).toString("base64url") +
                 "-Aa1!";
const REPO = process.env.MOCK_STS_DIR || path.join(__dirname, "..", "..");
const x509 = require(path.join(REPO, "common", "vendored", "x509.js"));
const FRESH = "application/est-attestation-freshness+json";
const EST = base + "/.well-known/est";

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

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await fetch(url, { method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload || {}) });
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in ok(): " + ((e && e.message) || e));
    json = null;
  }
  assert.ok(r.status === 200 && json && json.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + text.slice(0, 400));
  log.debug("Leaving ok().");
  return json;
}

async function read(where) {
  log.debug("Entering read(). " + where);
  const r = await fetch(api + where);
  const text = await r.text();
  assert.strictEqual(r.status, 200, "GET " + where + " answered " + r.status +
                     " " + text.slice(0, 300));
  log.debug("Leaving read().");
  return JSON.parse(text);
}

// ---------------------------------------------------------------------------
// AN EST CLIENT WITH A COOKIE JAR: section 5.1's binding is a cookie, and a
// client that drops it is a client whose nonce counts for nothing.
// ---------------------------------------------------------------------------
function client() {
  log.debug("Entering client().");
  const jar = {};
  const self = {
    jar: jar,
    async send(opts) {
      log.debug("Entering send(). " + opts.method + " " + opts.url);
      const headers = Object.assign({}, opts.headers || {});
      const cookie = Object.keys(jar).map(function (k) {
        return k + "=" + jar[k];
      }).join("; ");
      if (cookie && opts.cookies !== false) {
        headers.Cookie = cookie;
      }
      const r = await est.send(Object.assign({}, opts, { headers: headers,
        basic: opts.basic === undefined ? [OWNER, PASSWORD] : opts.basic }));
      [].concat(r.headers["set-cookie"] || []).forEach(function (one) {
        const pair = String(one).split(";")[0];
        const at = pair.indexOf("=");
        if (at > 0) {
          jar[pair.slice(0, at)] = pair.slice(at + 1);
        }
      });
      log.debug("Leaving send(). " + r.status);
      return r;
    }
  };
  log.debug("Leaving client().");
  return self;
}

function json(r) {
  log.debug("Entering json().");
  let out = null;
  try {
    out = JSON.parse(String(r.body));
  } catch (e) {
    log.debug("Caught in json(): " + ((e && e.message) || e));
    out = null;
  }
  log.debug("Leaving json().");
  return out;
}

// ---------------------------------------------------------------------------
// A TPM, AS FAR AS TPM2_Certify GOES: a manufacturer root, an Attestation
// Key certified under it with tcg-kp-AIKCertificate, and the statement over
// a P-256 key — TPMS_ATTEST with `extraData`, TPMT_PUBLIC with fixedTPM,
// fixedParent and sensitiveDataOrigin, the AK's RSASSA signature — as
// draft-ietf-lamps-csr-attestation revision 20's Tcg-csr-tpm-certify in an
// AttestationBundle (common/crypto.js says why revision 20).
// ---------------------------------------------------------------------------
function u16(n) {
  log.debug("Entering u16().");
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n, 0);
  log.debug("Leaving u16().");
  return b;
}

function u32(n) {
  log.debug("Entering u32().");
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0, 0);
  log.debug("Leaving u32().");
  return b;
}

function tpm2b(bytes) {
  log.debug("Entering tpm2b().");
  log.debug("Leaving tpm2b().");
  return Buffer.concat([u16(bytes.length), Buffer.from(bytes)]);
}

function pem(key, type) {
  log.debug("Entering pem().");
  log.debug("Leaving pem().");
  return key.export({ type: type, format: "pem" });
}

async function manufacturer() {
  log.debug("Entering manufacturer().");
  const rootKey = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const rootPem = await x509.issueCertificate({
    subject: "CN=Freshness job TPM manufacturer " + STAMP,
    subjectPublicKey: pem(rootKey.publicKey, "spki"), issuer: null,
    issuerPrivateKey: pem(rootKey.privateKey, "pkcs8"),
    signatureAlg: "sha256-ecdsa",
    profile: "root-ca", extensions: x509.defaultExtensions("root-ca") });
  const akKey = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const ak = x509.defaultExtensions("tls-client");
  ak.extKeyUsage = { present: true, usages: ["2.23.133.8.3"],
                     critical: false };
  ak.keyUsage = { present: true, usages: ["digitalSignature"],
                  critical: true };
  const akPem = await x509.issueCertificate({
    subject: "CN=Freshness job AK " + STAMP,
    subjectPublicKey: pem(akKey.publicKey, "spki"),
    issuer: { certificatePem: certPemOf(rootPem), privateKeyPem:
              pem(rootKey.privateKey, "pkcs8"), keyAlg: "ec-p256" },
    signatureAlg: "sha256-ecdsa", extensions: ak });
  log.debug("Leaving manufacturer().");
  return { rootPem: certPemOf(rootPem), akPem: certPemOf(akPem),
           akPrivate: akKey.privateKey };
}

// `issueCertificate()` answers `{ der, pem, … }`.
function certPemOf(issued) {
  log.debug("Entering certPemOf().");
  log.debug("Leaving certPemOf().");
  return String(issued.pem);
}

function tpmBundle(tpm, jwk, extraData) {
  log.debug("Entering tpmBundle().");
  const pubArea = Buffer.concat([
    u16(0x0023), u16(0x000b), u32(0x00060472), tpm2b(Buffer.alloc(0)),
    u16(0x0010), u16(0x0010), u16(0x0003), u16(0x0010),
    tpm2b(Buffer.from(jwk.x, "base64url")),
    tpm2b(Buffer.from(jwk.y, "base64url"))]);
  const name = Buffer.concat([u16(0x000b), crypto.createHash("sha256")
    .update(pubArea).digest()]);
  const certInfo = Buffer.concat([
    u32(0xff544347), u16(0x8017),
    tpm2b(Buffer.concat([u16(0x000b), crypto.randomBytes(32)])),
    tpm2b(extraData), Buffer.alloc(17), Buffer.alloc(8), tpm2b(name),
    tpm2b(Buffer.concat([u16(0x000b), crypto.randomBytes(32)]))]);
  const raw = crypto.sign("sha256", certInfo, tpm.akPrivate);
  const signature = Buffer.concat([u16(0x0014), u16(0x000b), tpm2b(raw)]);
  const octets = function (b) {
    log.debug("Entering octets().");
    log.debug("Leaving octets().");
    return new asn1js.OctetString({ valueHex: new Uint8Array(b).buffer });
  };
  const akDer = Buffer.from(String(tpm.akPem)
    .replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""), "base64");
  log.debug("Leaving tpmBundle().");
  return new asn1js.Sequence({ value: [
    new asn1js.Sequence({ value: [new asn1js.Sequence({ value: [
      new asn1js.ObjectIdentifier({ value: "2.23.133.20.1" }),
      new asn1js.Sequence({ value: [octets(tpm2b(certInfo)),
                                    octets(signature),
                                    octets(tpm2b(pubArea))] })] })] }),
    new asn1js.Sequence({ value: [asn1js.fromBER(new Uint8Array(akDer)
      .buffer).result] })] });
}

// A PKCS#10 request over `pair`, carrying `bundle` as its one
// id-aa-attestation attribute and `uris` as its subjectAltName.
async function deviceCsr(pair, bundle, uris) {
  log.debug("Entering deviceCsr().");
  const csr = new pkijs.CertificationRequest();
  csr.subject.typesAndValues.push(new pkijs.AttributeTypeAndValue({
    type: "2.5.4.3", value: new asn1js.Utf8String({ value: "a device" }) }));
  csr.attributes = [new pkijs.Attribute({
    type: "1.2.840.113549.1.9.16.2.59", values: [bundle] })];
  if ((uris || []).length) {
    csr.attributes.push(new pkijs.Attribute({
      type: "1.2.840.113549.1.9.14",
      values: [new pkijs.Extensions({ extensions: [new pkijs.Extension({
        extnID: "2.5.29.17", critical: false,
        extnValue: new pkijs.GeneralNames({ names: uris.map(function (u) {
          return new pkijs.GeneralName({ type: 6, value: u });
        }) }).toSchema().toBER(false) })] }).toSchema()] }));
  }
  const publicKey = await crypto.webcrypto.subtle.importKey("spki",
    pair.publicKey.export({ type: "spki", format: "der" }),
    { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
  const privateKey = await crypto.webcrypto.subtle.importKey("pkcs8",
    pair.privateKey.export({ type: "pkcs8", format: "der" }),
    { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  await csr.subjectPublicKeyInfo.importKey(publicKey);
  await csr.sign(privateKey, "SHA-256");
  log.debug("Leaving deviceCsr().");
  return Buffer.from(csr.toSchema().toBER(false));
}

async function enroll(c, der) {
  log.debug("Entering enroll().");
  const r = await c.send({ method: "POST", url: EST + "/device/simpleenroll",
    body: est.requestBody(der),
    headers: { "Content-Type": "application/pkcs10" } });
  let deviceId = "";
  if (r.status === 200) {
    const certificate = new crypto.X509Certificate(est.parseCertsOnly(
      est.base64Body(r.body)).certificates[0]);
    deviceId = String(certificate.subjectAltName)
      .replace(/^URI:urn:sts:device:/, "");
  }
  log.debug("Leaving enroll(). " + r.status);
  return { status: r.status, body: String(r.body), deviceId: deviceId };
}

async function keyOf(deviceId, thumbprintOf) {
  log.debug("Entering keyOf(). " + deviceId);
  const one = await read("/devices?device=" + encodeURIComponent(deviceId));
  const keys = (one.device || {}).keys || [];
  log.debug("Leaving keyOf().");
  return thumbprintOf ? keys.filter(thumbprintOf)[0] || null
                      : keys[keys.length - 1] || null;
}

async function nonceOf(c, label) {
  log.debug("Entering nonceOf().");
  const r = await c.send({ method: "GET", url: EST + "/" + label + "/nonce" });
  log.debug("Leaving nonceOf(). " + r.status);
  return { status: r.status, headers: r.headers, body: json(r) };
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. a throwaway realm " + REALM + ", a TPM manufacturer ===");
  await ok(root + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "Freshness " + STAMP,
    overrides: { "global.mode": "development" } },
    "created the realm");
  await registry.ensurePerson(base, OWNER, PASSWORD);
  const tpm = await manufacturer();
  await ok(api + "/config/set", { key: "devices.tpmTrustAnchors",
                                  value: tpm.rootPem },
           "trusted the job's TPM manufacturer root");
  const c = client();

  log.info("=== 1. /nonce is authenticated ===");
  const anonymous = await c.send({ method: "GET", url: EST + "/device/nonce",
                                   basic: null });
  check("no credential: 401 with the Basic challenge", function () {
    assert.strictEqual(anonymous.status, 401, String(anonymous.body));
    assert.ok(/^Basic/.test(String(anonymous.headers["www-authenticate"])));
  });

  log.info("=== 2. GET /device/nonce ===");
  const first = await nonceOf(c, "device");
  const setCookie = String([].concat(first.headers["set-cookie"] || [])[0]);
  check("200, " + FRESH + ", a 32-octet nonce, an expiry and the " +
        "sts_est_nonce cookie", function () {
    assert.strictEqual(first.status, 200, JSON.stringify(first.body));
    assert.strictEqual(String(first.headers["content-type"]), FRESH);
    assert.ok(/^[A-Za-z0-9_-]{43}$/.test(first.body.nonce), first.body.nonce);
    assert.strictEqual(Buffer.from(first.body.nonce, "base64url").length, 32);
    assert.ok(Number.isInteger(first.body.expiry) && first.body.expiry > 0);
    assert.ok(/^sts_est_nonce=est\.[A-Za-z0-9_-]{43};/.test(setCookie),
              setCookie);
    assert.ok(/HttpOnly/.test(setCookie) && /Secure/.test(setCookie),
              setCookie);
    assert.ok(setCookie.indexOf(first.body.nonce) < 0,
              "the cookie carries a handle, never the nonce");
  });

  log.info("=== 3. a device simpleenroll over a FRESH TPM statement ===");
  const pair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = pair.publicKey.export({ format: "jwk" });
  const freshStatement = tpmBundle(tpm, jwk,
                                   Buffer.from(first.body.nonce, "base64url"));
  const issued = await enroll(c, await deviceCsr(pair, freshStatement));
  const freshKey = issued.deviceId ? await keyOf(issued.deviceId) : null;
  check("issued, the key attested and its freshness FRESH", function () {
    assert.strictEqual(issued.status, 200, issued.body.slice(0, 300));
    assert.ok(freshKey, "no key on device " + issued.deviceId);
    assert.strictEqual(freshKey.attestation.level, "attested",
                       JSON.stringify(freshKey.attestation));
    assert.strictEqual(freshKey.attestation.freshness.status, "fresh",
                       JSON.stringify(freshKey.attestation));
  });

  log.info("=== 4. the same statement replayed for the same key ===");
  const urn = "urn:sts:device:" + issued.deviceId;
  const replay = await enroll(c, await deviceCsr(pair, freshStatement,
                                                 [urn]));
  const replayedKey = replay.status === 200
    ? await keyOf(issued.deviceId) : null;
  check("development certifies the replay with freshness UNPROVEN",
        function () {
    assert.strictEqual(replay.status, 200, replay.body.slice(0, 300));
    assert.strictEqual(replayedKey.attestation.freshness.status, "unproven",
                       JSON.stringify(replayedKey.attestation));
    assert.ok(/no such challenge/.test(replayedKey.attestation.freshness
      .detail), replayedKey.attestation.freshness.detail);
  });

  log.info("=== 5. POST /nonce, and its refusals ===");
  const posted = await c.send({ method: "POST", url: EST + "/device/nonce",
    headers: { "Content-Type": FRESH }, body: JSON.stringify({ len: 48 }) });
  const wrongType = await c.send({ method: "POST",
    url: EST + "/device/nonce", headers: { "Content-Type":
      "application/json" }, body: "{}" });
  const extraMember = await c.send({ method: "POST",
    url: EST + "/device/nonce", headers: { "Content-Type": FRESH },
    body: JSON.stringify({ len: 32, colour: "blue" }) });
  const typed = await c.send({ method: "POST", url: EST + "/device/nonce",
    headers: { "Content-Type": FRESH },
    body: JSON.stringify({ reqTypeInfo: { type: "1.2.3.4.5" } }) });
  const notNeeded = await nonceOf(c, "tls-client");
  check("len 48 is honoured; another media type 400, an undefined member " +
        "400, a reqTypeInfo 503; a label that reads no attestation answers " +
        "the empty nonce", function () {
    assert.strictEqual(posted.status, 200, String(posted.body));
    assert.strictEqual(Buffer.from(json(posted).nonce, "base64url").length,
                       48);
    assert.strictEqual(wrongType.status, 400, String(wrongType.body));
    assert.strictEqual(extraMember.status, 400, String(extraMember.body));
    assert.strictEqual(typed.status, 503, String(typed.body));
    assert.strictEqual(notNeeded.status, 200);
    assert.strictEqual(notNeeded.body.nonce, "");
  });

  log.info("=== 6. product mode on the realm ===");
  await ok(api + "/config/set", { key: "global.mode", value: "product" },
           "put this realm in product mode");
  let refused = null;
  let accepted = null;
  let acceptedKey = null;
  try {
    refused = await enroll(c, await deviceCsr(pair, freshStatement, [urn]));
    const second = await nonceOf(c, "device");
    const pair2 = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    accepted = await enroll(c, await deviceCsr(pair2, tpmBundle(tpm,
      pair2.publicKey.export({ format: "jwk" }),
      Buffer.from(String(second.body && second.body.nonce), "base64url"))));
    acceptedKey = accepted.deviceId ? await keyOf(accepted.deviceId) : null;
  } finally {
    await ok(api + "/config/set", { key: "global.mode",
                                    value: "development" },
             "put this realm back in development mode");
  }
  check("product refuses the replayed statement (403) and issues over a " +
        "fresh one", function () {
    assert.strictEqual(refused.status, 403, refused.body.slice(0, 300));
    assert.ok(/made for this request/.test(refused.body),
              refused.body.slice(0, 300));
    assert.strictEqual(accepted.status, 200, accepted.body.slice(0, 300));
    assert.strictEqual(acceptedKey.attestation.freshness.status, "fresh",
                       JSON.stringify(acceptedKey && acceptedKey.attestation));
  });

  assert.ok(checks >= 6, "only " + checks + " checks ran");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

new Command()
  .description("A TPM key attestation's freshness over EST (#257): " +
    "/nonce (draft-ietf-lamps-attestation-freshness section 5.1), a device " +
    "enrolment over a fresh TPM2_Certify statement, the same statement " +
    "replayed (unproven in development, refused in product), and the " +
    "nonce request's refusals.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
