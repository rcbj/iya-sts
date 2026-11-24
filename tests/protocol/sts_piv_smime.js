// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_piv_smime.js
//
// ---------------------------------------------------------------------------
// S/MIME MAIL DECRYPTED WITH THE KEY ON A PIV CARD (#2058, umbrella #2055):
// the service's own mail, encrypted to a certificate whose key was generated
// on the client lab's PIV card, delivered to a real mail server, and opened
// by `openssl cms` through OpenSC's PKCS#11 module — the card decrypting.
// The lab is tests/client-lab/ (tests/CLAUDE.md, *THE CLIENT LAB*).
//
//   0. A throwaway realm (development), a person with an address at the
//      realm's domain; a factory-fresh `yubikey` PIV card; an attestation
//      root made in the lab at run time, the f9 key generated on the card
//      and certified by it; a KEY MANAGEMENT key (slot 9d, RSA-2048)
//      generated on the card and attested; that root the realm's only
//      piv.attestationAnchors.
//   1. THE PORTAL: a 9d request signed on the card (its raw RSA operation
//      through pkcs11-tool: OpenSC gives a key management key no signing
//      mechanism), `enrol-piv` for piv-key-management with the attestation: an
//      attested certificate over the card's key, naming the person's
//      address, imported to slot 9d.
//   2. THE PORTAL: that certificate registered as the person's S/MIME
//      certificate (/account-api openpgp `smime`) and S/MIME chosen for
//      their mail (`mail-encryption`).
//   3. THE MAIL SERVER: postfix in the lab, receiving for the realm's
//      domain over STARTTLS under a CA made there now, its CA certificate on
//      the shared volume (bin/lab-mail-start); the realm's SMTP transport
//      pointed at it, `mail.smtpCaFile` that certificate.
//   4. THE SERVICE'S MAIL: an administrator's test message to the person
//      (/admin-api/mail/test). It arrives in the lab's mailbox as S/MIME
//      enveloped data (application/pkcs7-mime), and the test message's text
//      is not in it.
//   5. DECRYPTED ON THE CARD: `openssl cms -decrypt` with `-engine pkcs11
//      -keyform engine -inkey pkcs11:id=%03` gives back the test message.
//   6. WITHOUT THE CARD'S KEY IT CANNOT BE READ: with a factory-fresh card
//      in the reader (slot 9d empty) the same command fails, and so does a
//      key the job makes in software.
//
// EVERY KEY AND CERTIFICATE IS MADE AT RUN TIME. Nothing is read from the
// repository.
//
// OWNED HERE (local: true): this repository's portal, account API, PIV
// enrolment, OpenPGP and S/MIME register and mail channel. `clientLab:
// true`: without CLIENT_LAB_URL (an AWS target, coverage) the runner skips
// it. It also needs the lab and the service to share /run/sts-test (the
// compose stacks mount `sts-test-shared` in both), for the mail server's CA.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const asn1js = require("asn1js");
const pkijs = require("pkijs");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const portal = require("./portal_signin.js");
const lab = require("./client_lab.js");

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
var log = bunyan.createLogger({ name: "sts_piv_smime",
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
const REALM = ("pivmail-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                                .slice(0, 31);
const DOMAIN = REALM + ".example.net";
const base = root + "/realm/" + REALM;
const api = base + "/admin-api";
const OWNER = names.usernameFor("piv-mail");
const ADDRESS = OWNER + "@" + DOMAIN;
const PASSWORD = "Piv-mail-" + crypto.randomBytes(9).toString("base64url") +
                 "-Aa1!";
const PIN = "123456";
// The mail server's CA certificate, where the lab writes it and the service
// reads it (bin/lab-mail-start; the shared volume is at the same path in
// both).
const MAIL_CA = "/run/sts-test/client-lab/mail-ca.crt";
// What the PIV clients in the lab are told (tests/client-lab/piv/).
const PIV_ENV = { OPENSC_CONF: "/opt/client-lab/piv/opensc.conf",
                  OPENSSL_CONF: "/opt/client-lab/piv/openssl.cnf" };
// The key management key, as OpenSC's PKCS#11 module numbers it.
const KEY_9D = "pkcs11:id=%03;type=private;pin-value=" + PIN;
const SHA256_WITH_RSA = "1.2.840.113549.1.1.11";
// DigestInfo's prefix for SHA-256 (RFC 8017 section 9.2, note 1).
const SHA256_DIGEST_INFO = Buffer.from("3031300d060960864801650304020105000420",
                                       "hex");

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

async function call(method, url, payload) {
  log.debug("Entering call(). " + method + " " + url);
  const options = { method: method, headers: { accept: "application/json" } };
  if (payload !== undefined) {
    options.headers["content-type"] = "application/json";
    options.body = JSON.stringify(payload);
  }
  const r = await fetch(url, options);
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
    // Not JSON; the caller reads `text`.
    json = null;
  }
  log.debug("Leaving call(). " + r.status);
  return { status: r.status, text: text, json: json };
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await call("POST", url, payload);
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + r.text.slice(0, 400));
  log.debug("Leaving ok().");
  return r.json;
}

async function settings(values) {
  log.debug("Entering settings().");
  for (const key of Object.keys(values)) {
    await ok(api + "/config/set", { key: key, value: values[key] },
             "set " + key);
  }
  log.debug("Leaving settings().");
}

// A request for the 9d key, SIGNED ON THE CARD. OpenSC gives a PIV key
// management key decrypt and unwrap only, never sign (the engine answers
// CKR_KEY_TYPE_INCONSISTENT), so proof of possession is the card's own raw
// RSA operation: the request's PKCS#1 v1.5 signature block (RFC 8017
// section 9.2) is built here and `pkcs11-tool --decrypt --mechanism
// RSA-X-509` raises it to the key's private exponent — which is what a
// signature is. The certificate request is put together around the result.
async function keyManagementRequest(publicKey) {
  log.debug("Entering keyManagementRequest().");
  const csr = new pkijs.CertificationRequest();
  csr.version = 0;
  csr.subject.typesAndValues.push(new pkijs.AttributeTypeAndValue({
    type: "2.5.4.3", value: new asn1js.Utf8String({ value: OWNER }) }));
  const spki = crypto.createPublicKey(publicKey)
    .export({ type: "spki", format: "der" });
  csr.subjectPublicKeyInfo = new pkijs.PublicKeyInfo({ schema:
    asn1js.fromBER(new Uint8Array(spki).buffer).result });
  csr.attributes = [];
  const tbs = Buffer.from(csr.encodeTBS().toBER(false));
  const digestInfo = Buffer.concat([SHA256_DIGEST_INFO,
    crypto.createHash("sha256").update(tbs).digest()]);
  const k = 256;
  const block = Buffer.concat([Buffer.from([0x00, 0x01]),
    Buffer.alloc(k - 3 - digestInfo.length, 0xff), Buffer.from([0x00]),
    digestInfo]);
  await lab.put("card/9d.block", block);
  await lab.must("pkcs11-tool", ["--module", lab.PKCS11_MODULE,
    "--slot-description", lab.PIV_READER, "--login", "--pin", PIN,
    "--decrypt", "--mechanism", "RSA-X-509", "--id", "03",
    "-i", lab.work("card/9d.block"), "-o", lab.work("card/9d.sig")],
    { env: PIV_ENV });
  const sig = await lab.get("card/9d.sig");
  assert.ok(crypto.verify("sha256", tbs, crypto.createPublicKey(publicKey),
                          sig), "the card's raw RSA over the request does " +
            "not verify as a PKCS#1 v1.5 signature under the 9d key");
  const der = Buffer.from(new asn1js.Sequence({ value: [
    asn1js.fromBER(new Uint8Array(tbs).buffer).result,
    new asn1js.Sequence({ value: [
      new asn1js.ObjectIdentifier({ value: SHA256_WITH_RSA }),
      new asn1js.Null()] }),
    new asn1js.BitString({ valueHex: new Uint8Array(sig).buffer })] })
    .toBER(false));
  log.debug("Leaving keyManagementRequest().");
  return "-----BEGIN CERTIFICATE REQUEST-----\n" +
    der.toString("base64").replace(/(.{64})/g, "$1\n").replace(/\n$/, "") +
    "\n-----END CERTIFICATE REQUEST-----\n";
}

// `openssl cms -decrypt` of the message in the lab, through the engine.
async function decrypt(message, recipient, inkey, engine) {
  log.debug("Entering decrypt().");
  const args = ["cms", "-decrypt", "-in", lab.work(message),
                "-recip", lab.work(recipient), "-inkey", inkey];
  if (engine) {
    args.splice(2, 0, "-engine", "pkcs11", "-keyform", "engine");
  }
  const r = await lab.run("openssl", args, { env: PIV_ENV });
  log.debug("Leaving decrypt(). " + r.code);
  return r;
}

async function test() {
  log.debug("Entering test().");
  assert.ok(lab.available(), "no CLIENT_LAB_URL: this job needs the client " +
            "lab (the runner skips it without one, `clientLab: true`)");
  await lab.ready();

  log.info("=== 0. a realm " + REALM + ", a person, a card ===");
  await ok(root + "/admin-api/realms/create", { id: REALM, domain: DOMAIN,
    name: "PIV mail " + STAMP, overrides: { "global.mode": "development" } },
           "created the realm");
  await ok(api + "/users/create", { username: OWNER, invent: false,
    credential: "password", password: PASSWORD,
    attributes: { cn: "PIV mail " + OWNER, givenName: "PIV", sn: OWNER,
                  displayName: "PIV mail " + OWNER, mail: ADDRESS } },
           "created " + OWNER);
  await settings({ "est.allowedProfiles":
    "tls-client,piv-auth,piv-sign,piv-key-management,piv-card-auth" });
  const serial = await lab.newPivCard("yubikey");
  await lab.must("lab-piv-attest", [lab.work("card"), "9d:RSA2048"]);
  const rootPem = (await lab.get("card/root.pem")).toString();
  const f9 = (await lab.get("card/f9.pem")).toString();
  const attestation = (await lab.get("card/attestation-9d.pem")).toString();
  const publicKey = (await lab.get("card/slot-9d.pub")).toString();
  await settings({ "piv.attestationAnchors": rootPem });
  check("a factory-fresh yubikey card, its serial " + serial + ", a key " +
        "management key generated in 9d and attested", function () {
    assert.ok(/^\d{8}$/.test(serial), "serial " + serial);
    assert.ok(/BEGIN CERTIFICATE/.test(attestation), attestation);
  });

  log.info("=== 1. the portal: the 9d certificate ===");
  const person = await portal.signInToThePortal(base, OWNER, null,
                                                { password: PASSWORD });
  // OpenSC lists the key only beside a certificate in its slot.
  await lab.must("lab-piv-placeholder", [lab.work("card"), "9d"]);
  const csr = await keyManagementRequest(publicKey);
  const enrolled = await person.act("/portal/tokens", {
    action: "enrol-piv", profile: "piv-key-management", csr: csr,
    attestationCertificate: attestation, attestationIssuer: f9 });
  const issued = ((enrolled.json || {}).view || {}).issued || {};
  let cert = null;
  check("enrol-piv issues an ATTESTED piv-key-management certificate over " +
        "the card's 9d key, naming " + ADDRESS, function () {
    assert.strictEqual(enrolled.status, 200,
                       String(enrolled.text).slice(0, 400));
    assert.strictEqual(issued.attested, true, JSON.stringify(issued));
    cert = new crypto.X509Certificate(issued.certificatePem);
    assert.ok(cert.publicKey.export({ type: "spki", format: "der" }).equals(
      crypto.createPublicKey(publicKey).export({ type: "spki",
                                                 format: "der" })),
      "the certificate is not over the card's 9d key");
    assert.ok(String(cert.subjectAltName).indexOf(ADDRESS) >= 0,
              String(cert.subjectAltName));
  });
  const recipient = "card/issued-9d.pem";
  await lab.put(recipient, issued.certificatePem);
  await lab.must("yubico-piv-tool", ["-r", lab.PIV_READER, "-a",
    "import-certificate", "-s", "9d", "-i", lab.work(recipient)]);

  log.info("=== 2. the portal: S/MIME for the person's mail ===");
  const registered = await person.act("/portal/openpgp",
    { action: "smime", certificate: issued.certificatePem });
  const chosen = await person.act("/portal/openpgp",
    { action: "mail-encryption", choice: "smime" });
  check("the certificate is the person's S/MIME certificate, and S/MIME " +
        "is chosen for their mail", function () {
    assert.strictEqual(registered.status, 200,
                       String(registered.text).slice(0, 400));
    assert.strictEqual(chosen.status, 200, String(chosen.text).slice(0, 400));
    const mailView = ((chosen.json || {}).view || {}).mailEncryption || {};
    assert.strictEqual(mailView.choice, "smime", JSON.stringify(mailView));
  });

  log.info("=== 3. the mail server: postfix in the lab ===");
  await lab.must("lab-mail-start", [DOMAIN]);
  await settings({ "mail.transport": "smtp", "mail.smtpHost": "client-lab",
                   "mail.smtpPort": "25", "mail.smtpTls": "starttls",
                   "mail.smtpCaFile": MAIL_CA, "mail.smtpAuth": "none",
                   "mail.attempts": "1" });

  log.info("=== 4. the service's mail ===");
  const sent = await ok(api + "/mail/test", { user: OWNER },
                        "queued a test message to " + OWNER);
  const fetched = await lab.run("lab-mail-fetch", [lab.work("mail"), "90",
                                                   ADDRESS]);
  const count = Number(String(fetched.stdout).trim() || 0);
  const message = "mail/msg-" + count + ".eml";
  const raw = count ? (await lab.get(message)).toString() : "";
  check("the test message reaches the lab's mailbox over STARTTLS as " +
        "S/MIME enveloped data, its text not in it", function () {
    assert.ok(count >= 1, "nothing arrived: " + JSON.stringify(sent) +
              fetched.stderr);
    assert.ok(/^To:.*/im.test(raw) && raw.indexOf(ADDRESS) >= 0,
              raw.slice(0, 600));
    // RFC 3848: postfix's Received line says ESMTPS for a message that
    // came in over TLS (and lab-mail-start refuses any other).
    assert.ok(/^Received:[^\n]*(\n\s[^\n]*)*with ESMTPS/im.test(raw),
              raw.slice(0, 800));
    assert.ok(/Content-Type:\s*application\/(x-)?pkcs7-mime/i.test(raw),
              raw.slice(0, 800));
    assert.ok(/enveloped-data/i.test(raw), raw.slice(0, 800));
    assert.ok(raw.indexOf("This is a test message") < 0,
              "the test message's text is in the clear");
  });

  log.info("=== 5. decrypted on the card ===");
  const opened = await decrypt(message, recipient, KEY_9D, true);
  check("openssl cms -decrypt through the PKCS#11 engine (the card's 9d " +
        "key) gives back the test message", function () {
    assert.strictEqual(opened.code, 0, opened.stderr.slice(-800));
    assert.ok(opened.stdout.indexOf("This is a test message") >= 0,
              opened.stdout.slice(0, 800));
  });

  log.info("=== 6. without the card's key ===");
  await lab.newPivCard("yubikey");
  const noCard = await decrypt(message, recipient, KEY_9D, true);
  check("with a factory-fresh card in the reader the same command fails",
        function () {
    assert.notStrictEqual(noCard.code, 0, noCard.stdout.slice(0, 300));
    assert.ok(noCard.stdout.indexOf("This is a test message") < 0);
  });
  const other = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  await lab.put("mail/other.key",
                other.privateKey.export({ type: "pkcs8", format: "pem" }));
  const wrongKey = await decrypt(message, recipient,
                                 lab.work("mail/other.key"), false);
  check("and so does a key that is not the card's", function () {
    assert.notStrictEqual(wrongKey.code, 0, wrongKey.stdout.slice(0, 300));
    assert.ok(wrongKey.stdout.indexOf("This is a test message") < 0);
  });

  assert.ok(checks >= 7, "only " + checks + " checks ran");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

new Command()
  .description("S/MIME mail decrypted with the key on a PIV card in the " +
    "client lab (#2058): the key management certificate enrolled and " +
    "registered on the portal, the service's mail delivered to the lab's " +
    "postfix and decrypted by openssl cms through OpenSC.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().then(function () {
  process.exit(0);
}, function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
