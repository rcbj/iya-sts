// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_piv_card.js
//
// ---------------------------------------------------------------------------
// PIV ON A CARD, WITH THE CLIENTS A PERSON USES (#2059, umbrella #2055):
// attested enrolment through the portal and EST, mutual-TLS and PKINIT
// sign-in, and a lost token refused. The realistic half of
// `sts_piv_attestation.js`, whose attestations are made in node: here the
// key is GENERATED ON A CARD and never leaves it, and every operation on it
// is a real client's — yubico-piv-tool, OpenSC's PKCS#11 module, OpenSSL's
// PKCS#11 engine, curl and MIT kinit — in the client lab
// (tests/client-lab/, tests/CLAUDE.md *THE CLIENT LAB*).
//
//   0. A throwaway realm (development), a person with a password, EST
//      allowed the PIV profiles; a factory-fresh `yubikey` PIV card (PivApplet
//      attesting as a YubiKey 5); a PIV attestation root made in the lab at
//      run time, the f9 attestation key generated on the card and certified
//      by it; keys generated on the card in 9a (RSA-2048: MIT kinit's
//      PKINIT signs through PKCS#11 with RSA only) and 9c (P-256) and
//      attested; that
//      root the realm's only piv.attestationAnchors.
//   1. THE PORTAL, the way a person enrols: a request signed on the card for
//      9a (OpenSSL's engine over OpenSC), and /account-api's `enrol-piv`
//      with it and the two attestation certificates: an attested piv-auth
//      certificate, imported to the card's slot 9a.
//   2. EST, the enrolment client's way: a request for 9c carrying
//      draft-ietf-lamps-csr-attestation's id-aa-attestation attribute (the
//      9c attestation, the f9 certificate), signed on the card with
//      pkcs11-tool; /piv-sign/simpleenroll with the person's password: an
//      attested certificate, imported to slot 9c.
//   3. THE REGISTER: GET /admin-api/hardware-tokens finds the card under its
//      serial (the one `yubico-piv-tool -a status` reads), evidence
//      piv-attestation, the person its holder, both certificates on it as
//      smart-card credentials.
//   4. MUTUAL TLS: curl with the key on the card (`--engine pkcs11`, a
//      pkcs11: URI) and the issued certificate signs the person in at
//      /tls/sign-in.
//   5. PKINIT: MIT kinit with `X509_user_identity=PKCS11:` over OpenSC gets a
//      TGT for the person, and `klist -f` shows it pre-authenticated and
//      HARDWARE authenticated (H).
//   6. LOST: the person reports the card lost on the portal; the same curl
//      starts no session and the same kinit gets no ticket.
//   7. A STOCK PivApplet card (no Yubico serial, a fixed issuer) is refused
//      at the portal: STS-PIV-0006 under a YubiKey-named f9 certificate,
//      STS-PIV-0007 (no serial) under one named as its fixed issuer; no
//      token is recorded for it.
//
// EVERY KEY AND CERTIFICATE IS MADE AT RUN TIME: the cards are new at every
// lab start and every key on them is generated there. Nothing is read from
// the repository.
//
// TODO(#2066): once the person entry holds the hardware tokens
// (`stsHardwareToken`), assert section 3's token on the entry as well.
//
// OWNED HERE (local: true): this repository's portal, account API, EST
// server, hardware token register, main port and KDC. `clientLab: true`:
// without CLIENT_LAB_URL (an AWS target, coverage) the runner skips it.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const fs = require("fs");
const asn1js = require("asn1js");
const pkijs = require("pkijs");
const { Command, Option } = require("commander");
const est = require("./est_client.js");
const names = require("./random_username.js");
const facts = require("./service_facts.js");
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
var log = bunyan.createLogger({ name: "sts_piv_card",
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
const REALM = ("pivcard-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                                .slice(0, 31);
const base = root + "/realm/" + REALM;
const api = base + "/admin-api";
const EST = base + "/.well-known/est";
const OWNER = names.usernameFor("piv-card");
const PASSWORD = "Piv-card-" + crypto.randomBytes(9).toString("base64url") +
                 "-Aa1!";
const PIN = "123456";
const STATEMENT = "1.3.6.1.4.1.41482.3.2";
const ID_AA_ATTESTATION = "1.2.840.113549.1.9.16.2.59";
const ECDSA_SHA256 = "1.2.840.10045.4.3.2";
// What the PIV clients in the lab are told (tests/client-lab/piv/).
const PIV_ENV = { OPENSC_CONF: "/opt/client-lab/piv/opensc.conf",
                  OPENSSL_CONF: "/opt/client-lab/piv/openssl.cnf" };
// The card's keys by slot, as OpenSC's PKCS#11 module numbers them.
const KEY_ID = { "9a": "01", "9c": "02" };

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

function pause(ms) {
  log.debug("Entering pause().");
  log.debug("Leaving pause().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
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

async function tokenOf(serial) {
  log.debug("Entering tokenOf(). " + serial);
  const r = await call("GET", api + "/hardware-tokens?q=" +
                       encodeURIComponent(serial));
  assert.strictEqual(r.status, 200, r.text.slice(0, 300));
  log.debug("Leaving tokenOf().");
  return (r.json.tokens || []).filter(function (one) {
    return String(one.serial) === String(serial);
  })[0] || null;
}

async function codeCount(code) {
  log.debug("Entering codeCount(). " + code);
  const r = await call("GET", api + "/audit?per=500&code=" +
                       encodeURIComponent(code));
  const rows = (r.json && (r.json.events || r.json.rows)) || [];
  log.debug("Leaving codeCount(). " + rows.length);
  return rows.length;
}

async function sawCode(code, before) {
  log.debug("Entering sawCode(). " + code);
  for (let i = 0; i < 30; i += 1) {
    if (await codeCount(code) > before) {
      log.debug("Leaving sawCode(). Seen.");
      return true;
    }
    await pause(200);
  }
  log.debug("Leaving sawCode(). Not seen.");
  return false;
}

function pemOf(der, label) {
  log.debug("Entering pemOf().");
  log.debug("Leaving pemOf().");
  return "-----BEGIN " + label + "-----\n" +
    Buffer.from(der).toString("base64").replace(/(.{64})/g, "$1\n")
      .replace(/\n$/, "") + "\n-----END " + label + "-----\n";
}

// Every PEM certificate in a text, each ending in a newline.
function pemBlocks(text) {
  log.debug("Entering pemBlocks().");
  log.debug("Leaving pemBlocks().");
  return (String(text).match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || [])
    .map(function (one) {
      return one + "\n";
    });
}

function derOfPem(pem) {
  log.debug("Entering derOfPem().");
  log.debug("Leaving derOfPem().");
  return Buffer.from(String(pem).replace(/-----[^-]+-----/g, "")
    .replace(/\s+/g, ""), "base64");
}

// ---------------------------------------------------------------------------
// THE CARD.
// ---------------------------------------------------------------------------

// A factory-fresh card, an attestation root made now, the f9 key generated
// on the card and certified by it, and keys generated in `slots` and
// attested (bin/lab-piv-attest). Answers the PEM texts the lab wrote.
async function attestedCard(dir, variant, slots, f9Subject) {
  log.debug("Entering attestedCard(). " + variant);
  const serial = await lab.newPivCard(variant);
  const args = [lab.work(dir), slots.join(",")];
  if (f9Subject) {
    args.push(f9Subject);
  }
  await lab.must("lab-piv-attest", args);
  const out = { serial: serial, dir: dir,
                root: (await lab.get(dir + "/root.pem")).toString(),
                f9: (await lab.get(dir + "/f9.pem")).toString(),
                slots: {} };
  for (const spec of slots) {
    const s = spec.split(":")[0];
    out.slots[s] = {
      attestation: (await lab.get(dir + "/attestation-" + s + ".pem"))
        .toString(),
      publicKey: (await lab.get(dir + "/slot-" + s + ".pub")).toString() };
  }
  log.debug("Leaving attestedCard(). Serial " + serial + ".");
  return out;
}

// A request for `slot`, signed on the card through OpenSSL's PKCS#11 engine
// (bin/lab-piv-request).
async function engineRequest(card, slot) {
  log.debug("Entering engineRequest(). " + slot);
  await lab.must("lab-piv-request", [lab.work(card.dir), slot,
                                     "/CN=" + OWNER]);
  log.debug("Leaving engineRequest().");
  return (await lab.get(card.dir + "/" + slot + ".csr")).toString();
}

// A request carrying the id-aa-attestation attribute, built here and SIGNED
// ON THE CARD: its to-be-signed bytes go to the lab, pkcs11-tool signs them
// with the slot's key (ECDSA with SHA-256, DER), and the request is put
// together around that signature.
async function attestedRequest(card, slot) {
  log.debug("Entering attestedRequest(). " + slot);
  const s = card.slots[slot];
  const csr = new pkijs.CertificationRequest();
  csr.version = 0;
  csr.subject.typesAndValues.push(new pkijs.AttributeTypeAndValue({
    type: "2.5.4.3", value: new asn1js.Utf8String({ value: OWNER }) }));
  const spki = crypto.createPublicKey(s.publicKey)
    .export({ type: "spki", format: "der" });
  csr.subjectPublicKeyInfo = new pkijs.PublicKeyInfo({ schema:
    asn1js.fromBER(new Uint8Array(spki).buffer).result });
  const bundle = new asn1js.Sequence({ value: [
    new asn1js.Sequence({ value: [new asn1js.Sequence({ value: [
      new asn1js.ObjectIdentifier({ value: STATEMENT }),
      asn1js.fromBER(new Uint8Array(derOfPem(s.attestation)).buffer)
        .result] })] }),
    new asn1js.Sequence({ value: [
      asn1js.fromBER(new Uint8Array(derOfPem(card.f9)).buffer).result] })] });
  csr.attributes = [new pkijs.Attribute({ type: ID_AA_ATTESTATION,
                                          values: [bundle] })];
  const tbs = Buffer.from(csr.encodeTBS().toBER(false));
  // OpenSC lists the key only beside a certificate in its slot.
  await lab.must("lab-piv-placeholder", [lab.work(card.dir), slot]);
  await lab.put(card.dir + "/" + slot + ".tbs", tbs);
  await lab.must("pkcs11-tool", ["--module", lab.PKCS11_MODULE,
    "--slot-description", lab.PIV_READER, "--login", "--pin", PIN, "--sign",
    "--mechanism", "ECDSA-SHA256", "--id", KEY_ID[slot],
    "--signature-format", "openssl",
    "-i", lab.work(card.dir + "/" + slot + ".tbs"),
    "-o", lab.work(card.dir + "/" + slot + ".sig")], { env: PIV_ENV });
  const sig = await lab.get(card.dir + "/" + slot + ".sig");
  const der = Buffer.from(new asn1js.Sequence({ value: [
    asn1js.fromBER(new Uint8Array(tbs).buffer).result,
    new asn1js.Sequence({ value: [
      new asn1js.ObjectIdentifier({ value: ECDSA_SHA256 })] }),
    new asn1js.BitString({ valueHex: new Uint8Array(sig).buffer })] })
    .toBER(false));
  assert.ok(crypto.verify("sha256", tbs, crypto.createPublicKey(s.publicKey),
                          sig), "the card's signature over the request " +
            "does not verify under the slot's public key");
  log.debug("Leaving attestedRequest().");
  return der;
}

async function importCertificate(card, slot, pem) {
  log.debug("Entering importCertificate(). " + slot);
  const file = await lab.put(card.dir + "/issued-" + slot + ".pem", pem);
  await lab.must("yubico-piv-tool", ["-r", lab.PIV_READER, "-a",
    "import-certificate", "-s", slot, "-i", file]);
  log.debug("Leaving importCertificate().");
}

// ---------------------------------------------------------------------------
// THE SIGN-INS, FROM THE LAB.
// ---------------------------------------------------------------------------

// curl's `GET /tls/sign-in` with the key on the card and the certificate
// (and its chain) from `chainFile`.
async function curlSignIn(chainFile) {
  log.debug("Entering curlSignIn().");
  const r = await lab.run("curl", ["-sS", "--max-time", "60",
    "--cacert", lab.work("anchors.pem"),
    "--engine", "pkcs11", "--key-type", "ENG",
    "--key", "pkcs11:id=%01;type=private;pin-value=" + PIN,
    "--cert", chainFile, "-H", "Accept: application/json",
    base + "/tls/sign-in"], { env: PIV_ENV });
  let json = null;
  try {
    json = JSON.parse(r.stdout);
  } catch (e) {
    log.debug("Caught in curlSignIn(): " + ((e && e.message) || e));
    // Not JSON: no answer (the caller reads stderr).
    json = null;
  }
  log.debug("Leaving curlSignIn(). " + r.code);
  return { code: r.code, json: json, raw: r.stdout, stderr: r.stderr };
}

const K = { realm: "", kdcHost: "", kdcPort: 88, n: 0 };

async function kerberosSetup() {
  log.debug("Entering kerberosSetup().");
  K.realm = String(await facts.setting(api, "krb5.realm") || "");
  K.kdcHost = process.env.STS_KDC_HOST || new URL(root).hostname;
  K.kdcPort = Number(process.env.STS_KDC_PORT ||
                     await facts.setting(api, "krb5.kdcPort") || 88);
  const ca = await est.send({ method: "GET", url: EST + "/cacerts" });
  assert.strictEqual(ca.status, 200, "EST /cacerts answered " + ca.status);
  const chain = est.parseCertsOnly(est.base64Body(ca.body)).certificates;
  await lab.put("krb/root.pem", chain[chain.length - 1]);
  await lab.put("krb/pool.pem", chain.slice(0, -1).join(""));
  await lab.put("krb/krb5.conf", "[libdefaults]\n default_realm = " +
    K.realm + "\n dns_lookup_kdc = false\n dns_lookup_realm = false\n" +
    " udp_preference_limit = 1\n rdns = false\n\n[realms]\n " + K.realm +
    " = {\n  kdc = " + K.kdcHost + ":" + K.kdcPort +
    "\n  pkinit_anchors = FILE:" + lab.work("krb/root.pem") +
    "\n  pkinit_pool = FILE:" + lab.work("krb/pool.pem") + "\n }\n");
  log.info("Kerberos realm " + K.realm + ", KDC " + K.kdcHost + ":" +
           K.kdcPort);
  log.debug("Leaving kerberosSetup().");
}

// kinit with the key on the card (PIN on stdin), then `klist -f`.
async function kinitWithCard() {
  log.debug("Entering kinitWithCard().");
  K.n += 1;
  const cache = lab.work("krb/cc-" + K.n);
  const env = Object.assign({ KRB5_CONFIG: lab.work("krb/krb5.conf"),
                              KRB5CCNAME: "FILE:" + cache,
                              KRB5_TRACE: lab.work("krb/trace-" + K.n) },
                            PIV_ENV);
  const kinit = await lab.run("kinit", ["-X",
    "X509_user_identity=PKCS11:module_name=" + lab.PKCS11_MODULE +
    ":certid=" + KEY_ID["9a"], OWNER + "@" + K.realm],
    { env: env, stdin: PIN + "\n", timeoutMs: 60000 });
  const klist = kinit.code === 0
    ? await lab.run("klist", ["-f", "-c", cache], { env: env })
    : { code: -1, stdout: "", stderr: "" };
  let flags = "";
  const lines = klist.stdout.split("\n");
  for (let i = 0; i < lines.length; i += 1) {
    if (/\skrbtgt\//.test(lines[i]) && !flags) {
      const m = /Flags:\s*(\S+)/.exec(lines[i + 1] || "");
      flags = m ? m[1] : "";
    }
  }
  log.debug("Leaving kinitWithCard(). " + kinit.code + " " + flags);
  return { code: kinit.code, out: kinit.stdout + kinit.stderr,
           klist: klist.stdout, flags: flags };
}

// ---------------------------------------------------------------------------
// THE JOB.
// ---------------------------------------------------------------------------
async function test() {
  log.debug("Entering test().");
  assert.ok(lab.available(), "no CLIENT_LAB_URL: this job needs the client " +
            "lab (the runner skips it without one, `clientLab: true`)");
  await lab.ready();
  const anchors = process.env.NODE_EXTRA_CA_CERTS
    ? fs.readFileSync(process.env.NODE_EXTRA_CA_CERTS) : null;
  assert.ok(anchors, "no NODE_EXTRA_CA_CERTS: the lab's curl needs the " +
            "service's TLS anchor");
  await lab.put("anchors.pem", anchors);

  log.info("=== 0. a realm " + REALM + ", a person, a card ===");
  await ok(root + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "PIV card " + STAMP,
    // Its own KDC on the shared port 88, named for its domain (section 5).
    overrides: { "global.mode": "development", "krb5.enabled": true } },
    "created the realm");
  await ok(api + "/users/create", { username: OWNER, invent: false,
    credential: "password", password: PASSWORD,
    attributes: { cn: "PIV " + OWNER, givenName: "PIV", sn: OWNER,
                  displayName: "PIV " + OWNER,
                  mail: OWNER + "@" + REALM + ".example.net" } },
           "created " + OWNER);
  await ok(api + "/config/set", { key: "est.allowedProfiles",
    value: "tls-client,smartcard-logon,piv-auth,piv-sign," +
           "piv-key-management,piv-card-auth" },
           "let EST issue the PIV profiles");
  // 9a RSA-2048, because MIT kinit's PKINIT signs through PKCS#11 with
  // CKM_RSA_PKCS only (krb5 1.20); 9c P-256.
  const card = await attestedCard("card", "yubikey", ["9a:RSA2048", "9c"]);
  await ok(api + "/config/set", { key: "piv.attestationAnchors",
                                  value: card.root },
           "trusted the lab's attestation root");
  check("a factory-fresh yubikey card in the lab, its serial " +
        card.serial + ", 9a and 9c generated on it and attested", function () {
    assert.ok(/^\d{8}$/.test(card.serial), "serial " + card.serial);
    assert.ok(/BEGIN CERTIFICATE/.test(card.slots["9a"].attestation) &&
              /BEGIN CERTIFICATE/.test(card.slots["9c"].attestation));
  });

  log.info("=== 1. the portal: enrol-piv with a request signed on the " +
           "card ===");
  const person = await portal.signInToThePortal(base, OWNER, null,
                                                { password: PASSWORD });
  const csr9a = await engineRequest(card, "9a");
  const enrolled = await person.act("/portal/tokens", {
    action: "enrol-piv", profile: "piv-auth", csr: csr9a,
    attestationCertificate: card.slots["9a"].attestation,
    attestationIssuer: card.f9 });
  const issued = ((enrolled.json || {}).view || {}).issued || {};
  check("the portal's enrol-piv issues an ATTESTED piv-auth certificate on " +
        "the card's key, for the token yubico/" + card.serial, function () {
    assert.strictEqual(enrolled.status, 200,
                       String(enrolled.text).slice(0, 400));
    assert.strictEqual(issued.attested, true, JSON.stringify(issued));
    assert.strictEqual(issued.token, "yubico/" + card.serial);
    const cert = new crypto.X509Certificate(issued.certificatePem);
    assert.ok(cert.publicKey.export({ type: "spki", format: "der" }).equals(
      crypto.createPublicKey(card.slots["9a"].publicKey)
        .export({ type: "spki", format: "der" })),
      "the certificate is not over the card's 9a key");
  });
  await importCertificate(card, "9a", issued.certificatePem);
  // The leaf and its chain, one PEM block a line apart: the listener
  // anchors at the service Root, so curl sends the issuing CAs too.
  const chain9a = await lab.put("card/chain-9a.pem",
    pemBlocks(issued.certificatePem + "\n" + String(issued.chainPem || ""))
      .join(""));

  log.info("=== 2. EST: an attested request signed on the card ===");
  const der9c = await attestedRequest(card, "9c");
  const viaEst = await est.send({ method: "POST",
    url: EST + "/piv-sign/simpleenroll", body: est.requestBody(der9c),
    basic: [OWNER, PASSWORD],
    headers: { "Content-Type": "application/pkcs10" } });
  let pem9c = "";
  check("EST /piv-sign/simpleenroll issues a certificate on the card's 9c " +
        "key, from the attestation in the request", function () {
    assert.strictEqual(viaEst.status, 200,
                       Buffer.from(viaEst.body || "").toString().slice(0, 300));
    pem9c = est.parseCertsOnly(est.base64Body(viaEst.body)).certificates[0];
    const cert = new crypto.X509Certificate(pem9c);
    assert.ok(cert.publicKey.export({ type: "spki", format: "der" }).equals(
      crypto.createPublicKey(card.slots["9c"].publicKey)
        .export({ type: "spki", format: "der" })),
      "the certificate is not over the card's 9c key");
  });
  await importCertificate(card, "9c", pem9c);

  log.info("=== 3. the register ===");
  const token = await tokenOf(card.serial);
  check("GET /admin-api/hardware-tokens: the card under its serial, " +
        "evidence piv-attestation, " + OWNER + " its holder, both " +
        "certificates on it as smart-card credentials", function () {
    assert.ok(token, "no token " + card.serial);
    assert.ok((token.evidenceSources || []).indexOf("piv-attestation") >= 0,
              JSON.stringify(token));
    assert.strictEqual(token.holder, OWNER, JSON.stringify(token));
    const certs = (token.credentials || []).filter(function (c) {
      return c.kind === "x509" && c.smartCard === true;
    });
    assert.strictEqual(certs.length, 2, JSON.stringify(token.credentials));
  });
  // TODO(#2066): the same token in the person entry's stsHardwareToken.

  log.info("=== 4. mutual TLS: curl with the key on the card ===");
  const signedIn = await curlSignIn(chain9a);
  check("curl (--engine pkcs11, a pkcs11: URI) signs " + OWNER + " in at " +
        "/tls/sign-in in " + REALM, function () {
    assert.strictEqual(signedIn.code, 0, signedIn.stderr.slice(-600));
    assert.ok(signedIn.json, signedIn.raw.slice(0, 400));
    assert.strictEqual(signedIn.json.signedIn, true,
                       signedIn.raw.slice(0, 600));
    assert.strictEqual((signedIn.json.session || {}).username, OWNER,
                       signedIn.raw.slice(0, 600));
    assert.strictEqual((signedIn.json.session || {}).realm, REALM,
                       signedIn.raw.slice(0, 600));
  });

  log.info("=== 5. PKINIT: kinit with the key on the card ===");
  await kerberosSetup();
  const tgt = await kinitWithCard();
  check("kinit -X X509_user_identity=PKCS11:… gets " + OWNER + "@" +
        K.realm + " a TGT, and klist -f shows it pre-authenticated (A) and " +
        "HARDWARE authenticated (H)", function () {
    assert.strictEqual(tgt.code, 0, tgt.out.slice(-1200));
    assert.ok(new RegExp(OWNER + "@" + K.realm).test(tgt.klist), tgt.klist);
    assert.ok(/A/.test(tgt.flags) && /H/.test(tgt.flags),
              "flags " + tgt.flags + "\n" + tgt.klist);
  });

  log.info("=== 6. the card reported lost ===");
  const lost = await person.act("/portal/tokens",
                                { action: "lost", key: token.key });
  const after = await tokenOf(card.serial);
  check("the person reports the card lost on the portal, and the register " +
        "says so", function () {
    assert.strictEqual(lost.status, 200, String(lost.text).slice(0, 400));
    assert.strictEqual(after.status, "lost", JSON.stringify(after));
  });
  const refusedTls = await curlSignIn(chain9a);
  log.info("    /tls/sign-in answered: " +
           JSON.stringify((refusedTls.json || {}).session || refusedTls.raw)
             .slice(0, 400));
  check("the same curl, over a handshake that completes, starts no " +
        "session: the lost-token act revoked the certificate " +
        "(keyCompromise), and the sign-in is refused on revocation",
        function () {
    assert.strictEqual(refusedTls.code, 0, refusedTls.stderr.slice(-600));
    assert.ok(refusedTls.json, refusedTls.raw.slice(0, 400));
    assert.notStrictEqual(refusedTls.json.signedIn, true,
                          refusedTls.raw.slice(0, 600));
    const why = (refusedTls.json.session || {});
    assert.strictEqual(why.refusedOnRevocation, true,
                       refusedTls.raw.slice(0, 600));
    assert.ok(/keyCompromise/.test(String(why.why)), String(why.why));
  });
  const refusedKdc = await kinitWithCard();
  // The KDC's own answer, from the trace (sts_kerberos_pkinit.js's reason:
  // kinit's message is its LAST error, after a password fallback).
  const trace = (await lab.get("krb/trace-" + K.n)).toString();
  const kdcError = { stdout: trace.split("\n").filter(function (line) {
    return /Received error from KDC/.test(line);
  }).join("\n") };
  log.info("    kinit: " + refusedKdc.out.trim().split("\n").pop() +
           " | " + kdcError.stdout.trim().split("\n").pop());
  check("the same kinit gets no ticket: the KDC answers the PKINIT " +
        "request KDC_ERR_REVOKED_CERTIFICATE", function () {
    assert.notStrictEqual(refusedKdc.code, 0, refusedKdc.klist);
    assert.ok(/Received error from KDC: -?\d+\/Revoked certificate/
                .test(kdcError.stdout), kdcError.stdout +
              refusedKdc.out.slice(-800));
  });

  log.info("=== 7. a stock PivApplet card ===");
  for (const [f9, code] of [["/CN=Yubico PIV Attestation", "STS-PIV-0006"],
                            ["/CN=PIVApplet Attestation", "STS-PIV-0007"]]) {
    const stock = await attestedCard("stock-" + code, "stock", ["9a"], f9);
    // The realm trusts THIS card's root, so what is refused is the card.
    await ok(api + "/config/set", { key: "piv.attestationAnchors",
                                    value: stock.root },
             "trusted the stock card's attestation root");
    const before = await codeCount(code);
    const refused = await person.act("/portal/tokens", {
      action: "enrol-piv", profile: "piv-auth",
      csr: await engineRequest(stock, "9a"),
      attestationCertificate: stock.slots["9a"].attestation,
      attestationIssuer: stock.f9 });
    const seen = await sawCode(code, before);
    const tokens = await call("GET", api + "/hardware-tokens?q=" +
                              encodeURIComponent(OWNER));
    check("a stock card's attestation (f9 " + f9 + ") is refused at the " +
          "portal, " + code + " on the realm's audit, and no token is " +
          "recorded for it", function () {
      assert.strictEqual(refused.status, 400,
                         String(refused.text).slice(0, 400));
      assert.ok(seen, "no " + code + " row");
      assert.ok(!/STS-[A-Z]+-\d{4}/.test(String(refused.text)),
                "the answer names an error code");
      assert.strictEqual(((tokens.json || {}).tokens || []).length, 1,
                         tokens.text.slice(0, 400));
    });
  }

  assert.ok(checks >= 11, "only " + checks + " checks ran");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

new Command()
  .description("PIV on a card in the client lab (#2059): attested " +
    "enrolment through the portal and EST, mutual-TLS and PKINIT sign-in " +
    "with the key on the card, a lost card refused, a stock card refused.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().then(function () {
  process.exit(0);
}, function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
