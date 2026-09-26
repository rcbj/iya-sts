"use strict";
//
// File: sts_est_libest.js
//
// ===========================================================================
// CISCO'S libest estclient AGAINST THE EST SERVER (#209, 2026-09-26).
//
// No official EST conformance suite exists. libest (BSD-3-Clause) is the
// reference implementation of RFC 7030, and its `estclient` is what an
// operator bootstraps a device with. At the commit tests/Dockerfile pins
// (a464ba8, statically linked against OpenSSL 1.1.1w — it does not build on
// OpenSSL 3), this job drives every operation and every authentication EST
// allows that this service accepts:
//
//   * BOOTSTRAP (section 4.1.1): `-g` against the service Root alone, then
//     the /cacerts answer — the EST Issuing CA, the realm Intermediate and
//     the Root — becomes the explicit trust anchor database for everything
//     after it, as the RFC has a client do. With the Root alone estclient
//     warns on every re-enrollment ("unable to get local issuer") because
//     it verifies what it was issued against that database.
//   * `-a` /csrattrs under a label (`--path-seg tls-server`): serverAuth and
//     a dNSName hint.
//   * `-e` /simpleenroll with HTTP Basic, the CSR estclient makes itself;
//     under `tls-server` with an `openssl req` CSR (`-y`) naming a host
//     registered on the entry: CN = the host, UID = the entry (#207's fix).
//   * `-r` /simplereenroll with the TLS client certificate; the one it
//     renewed is then refused as a credential (superseded, STS-ENROLL-0018).
//   * `-e` with a TLS client certificate instead of a password.
//   * `-q` /serverkeygen: a certificate and the key the server made, which
//     match (the multipart response failed "OSSL error" until #209's fix).
//   * `-z`, which puts a challengePassword in the CSR — enrolled; the
//     service does not read it (tls-unique does not exist in TLS 1.3,
//     `est/CLAUDE.md` section 3.5).
//   * REFUSALS: no credential (401), a wrong password (refused in product;
//     development checks no password, the root CLAUDE.md non-goal), an
//     unknown label (404), a refused profile (`root-ca`, 403), a host not
//     registered on the entry, a self-signed client certificate, an
//     `--auth-token` (Bearer is not an EST credential here), and `--srp`
//     (no TLS-SRP: TLS 1.3 has none; the handshake is refused).
//   * estclient's own output for every successful command: no `[WARNING]`
//     and no `[ERROR]` line beyond the three recorded below.
//
// **THE DEFAULT REALM, NOT A THROWAWAY ONE — A DOCUMENTED EXCEPTION.**
// estclient builds its URL as https://host:port/.well-known/est[/label]/op
// and can be told nothing else; a realm's EST is at /realm/<id>/.well-known/
// est, which no RFC 7030 client can name, because the well-known URI is at
// the root (RFC 8615). So the job runs in the default realm, with people of
// its own names, and changes no default-realm setting. Recorded on #209.
//
// THREE LINES estclient PRINTS THAT ARE NOT THE SERVER'S, accepted by name:
//   * `[WARNING]… Not using client certificate for TLS session, HTTP basic
//     or digest auth will be used.` — its note that it has no certificate.
//   * `[WARNING]… HTTP auth failure` — the 401 that asks for Basic: estclient
//     never sends credentials pre-emptively, and HTTP authentication is a
//     challenge first (RFC 9110 section 11.6.1).
//   * `OSSL error: (null)` after every successful /serverkeygen — libest's
//     est_client_verify_key_and_cert() dumps the OpenSSL error queue at its
//     `end:` label on success too, and the queue is empty.
// ===========================================================================

const assert = require("assert");
const fs = require("fs");
const nodeCrypto = require("crypto");
const path = require("path");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");
const K = require("./enroll_clients_kit.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason tests/vendored/wait_for.js gives.
  appconfigProblem = e;
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_est_libest",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const STAMP = usernameFor("le").replace(/[^a-z0-9-]/g, "").slice(0, 24);
const PERSON = "estlib-" + STAMP;
const HOST = "dev." + PERSON + ".test";
const EKU = { serverAuth: "1.3.6.1.5.5.7.3.1",
              clientAuth: "1.3.6.1.5.5.7.3.2" };
const ACCEPTED = [
  /Not using client certificate for TLS session/,
  /\[WARNING\]\[est_client_send_enroll_request_internal:\d+\]--> HTTP auth failure/
];
const C = K.checker(log);

var work = "";
var anchors = "";
var host = "";
var port = "";

async function est(args, options) {
  log.debug("Entering est().");
  const opts = options || {};
  const out = path.join(work, "out-" + opts.name);
  fs.mkdirSync(out, { recursive: true });
  const r = await K.run("estclient", ["-s", host, "-p", port, "-o", out,
                                      "-w", "30"].concat(args), {
    env: { EST_OPENSSL_CACERT: opts.anchors || anchors },
    secrets: opts.secrets, timeoutMs: 120000 });
  r.dir = out;
  r.files = fs.readdirSync(out);
  log.debug("Leaving est(). files=" + r.files.join(","));
  return r;
}

// estclient exits 0 on every failure, so success is the file it wrote and
// the absence of any warning or error line it was not expected to print.
function wrote(r, file, what, extra) {
  log.debug("Entering wrote().");
  assert.ok(r.files.indexOf(file) >= 0, what + ": estclient wrote no " +
            file + " (it wrote " + r.files.join(",") + "):\n" + r.shown);
  const bad = K.problemLines(r.output, /\[(WARNING|ERROR)\]|OSSL error/,
                             ACCEPTED.concat(extra || []));
  assert.deepStrictEqual(bad, [], what + ": estclient reported:\n" +
                         bad.join("\n"));
  log.debug("Leaving wrote().");
  return path.join(r.dir, file);
}

function refused(r, pattern, what) {
  log.debug("Entering refused().");
  assert.ok(!r.files.some(function (f) {
    return /^cert-/.test(f);
  }), what + ": a certificate was written:\n" + r.shown);
  assert.ok(pattern.test(r.output), what + ": " + r.shown);
  log.debug("Leaving refused().");
}

// A certs-only PKCS#7, base64 as estclient saves it, read with OpenSSL.
async function certsOf(file) {
  log.debug("Entering certsOf().");
  const der = path.join(work, path.basename(file) + ".der");
  fs.writeFileSync(der, Buffer.from(fs.readFileSync(file, "utf8"),
                                    "base64"));
  const r = await K.run("openssl", ["pkcs7", "-inform", "der", "-in", der,
                                    "-print_certs"]);
  assert.strictEqual(r.status, 0, r.shown);
  log.debug("Leaving certsOf().");
  return K.pemChain(r.stdout);
}

function leafOf(file) {
  log.debug("Entering leafOf().");
  const chain = K.pemChain(fs.readFileSync(file, "utf8"));
  log.debug("Leaving leafOf().");
  return chain[0];
}

function assertLeaf(leaf, cacerts, ekus, what) {
  log.debug("Entering assertLeaf().");
  K.chainsTo([leaf].concat(cacerts.slice(0, 2)), cacerts[2]);
  assert.ok(String(leaf.subjectAltName)
              .indexOf("URI:urn:sts:person:" + PERSON) >= 0,
            what + ": the SAN names the entry: " + leaf.subjectAltName);
  assert.deepStrictEqual((leaf.keyUsage || []).slice().sort(),
                         ekus.slice().sort(), what + ": EKU");
  log.debug("Leaving assertLeaf().");
}

async function test() {
  log.debug("Entering test().");
  const url = new URL(K.base);
  host = url.hostname;
  port = url.port || "443";
  log.info("Driving " + K.base + " with libest's estclient in the default " +
           "realm (the only realm an EST client can name).");
  work = K.scratch("estclient");
  const bundle = await K.trustBundle(work);
  const product = await K.isProduct(null);

  // -------------------------------------------------------------------------
  log.info("=== 0. a person and a host name, in the default realm ===");
  const password = await K.makePerson(null, PERSON, PERSON + "@example.test");
  await K.ok(K.realmApi(null) + "/est/add-host-name",
             { kind: "person", identifier: PERSON, hostName: HOST },
             "registered " + HOST);
  const basic = ["-u", PERSON, "-h", password];
  const secrets = [password];

  // -------------------------------------------------------------------------
  log.info("=== 1. /cacerts, the bootstrap ===");
  const g = await est(["-g"], { name: "cacerts", anchors: bundle.file });
  const cacerts = await certsOf(wrote(g, "cacert-0-0.pkcs7", "-g"));
  C.check("-g fetches the EST Issuing CA, the Intermediate and the Root, " +
          "which chain", function () {
    assert.strictEqual(cacerts.length, 3);
    assert.ok(/EST/.test(cacerts[0].subject), cacerts[0].subject);
    K.chainsTo(cacerts, bundle.root);
    assert.ok(Buffer.from(cacerts[2].raw).equals(Buffer.from(bundle.root.raw)),
              "the third is the service Root");
  });
  anchors = path.join(work, "cacerts.pem");
  fs.writeFileSync(anchors, cacerts.map(function (x) {
    return x.toString();
  }).join("\n"));

  // -------------------------------------------------------------------------
  log.info("=== 2. /csrattrs ===");
  const a = await est(["-a", "--path-seg", "tls-server"], { name: "attrs" });
  const attrsFile = wrote(a, "csr-0-0.base64", "-a");
  const der = path.join(work, "attrs.der");
  fs.writeFileSync(der, Buffer.from(fs.readFileSync(attrsFile, "utf8"),
                                    "base64"));
  const parsed = await K.run("openssl", ["asn1parse", "-inform", "der",
                                         "-in", der]);
  C.check("-a under tls-server names serverAuth and a dNSName hint",
          function () {
    assert.strictEqual(parsed.status, 0, parsed.shown);
    assert.ok(/TLS Web Server Authentication/.test(parsed.output),
              parsed.shown);
    assert.ok(/dNSName/.test(parsed.output), parsed.shown);
  });

  // -------------------------------------------------------------------------
  log.info("=== 3. /simpleenroll ===");
  const e1 = await est(["-e"].concat(basic, ["--common-name", PERSON,
                                             "--pem-output"]),
                       { name: "enroll", secrets: secrets });
  const leaf1 = leafOf(wrote(e1, "cert-0-0.pem", "-e"));
  const key1 = path.join(e1.dir, "key-x-x.pem");
  C.check("-e with HTTP Basic is issued the default profile (tls-client) " +
          "for the entry, CN the entry", function () {
    assertLeaf(leaf1, cacerts, [EKU.clientAuth], "-e");
    assert.ok(/(^|\n)CN=/.test(leaf1.subject) &&
              leaf1.subject.indexOf("CN=" + PERSON) >= 0, leaf1.subject);
    assert.ok(fs.existsSync(key1));
  });
  const serverReq = await K.opensslRequest(work, "server", {
    subject: "/CN=" + HOST, sans: "DNS:" + HOST, newkey: "rsa:2048" });
  const e2 = await est(["-e", "--path-seg", "tls-server",
                        "-y", serverReq.csr, "--pem-output"]
                         .concat(basic), { name: "server", secrets: secrets });
  const leaf2 = leafOf(wrote(e2, "cert-0-0.pem", "-e tls-server"));
  C.check("-e under tls-server with an openssl CSR is issued serverAuth, " +
          "CN the host and UID the entry", function () {
    assertLeaf(leaf2, cacerts, [EKU.serverAuth], "tls-server");
    assert.ok(leaf2.subject.indexOf("CN=" + HOST) >= 0, leaf2.subject);
    assert.ok(leaf2.subject.indexOf("UID=" + PERSON) >= 0, leaf2.subject);
    assert.ok(String(leaf2.subjectAltName).indexOf("DNS:" + HOST) >= 0);
  });
  const z = await est(["-e", "-z", "--common-name", PERSON, "--pem-output"]
                        .concat(basic), { name: "pop", secrets: secrets });
  C.check("-z (a challengePassword in the CSR) enrolls; the service reads " +
          "no tls-unique, which TLS 1.3 does not have", function () {
    assertLeaf(leafOf(wrote(z, "cert-0-0.pem", "-z")), cacerts,
               [EKU.clientAuth], "-z");
  });

  // -------------------------------------------------------------------------
  log.info("=== 4. /simplereenroll and a certificate as the credential ===");
  const r1 = await est(["-r", "-c", path.join(e1.dir, "cert-0-0.pem"),
                        "-k", key1, "--pem-output"], { name: "reenroll" });
  const leaf3 = leafOf(wrote(r1, "cert-0-0.pem", "-r"));
  C.check("-r with the TLS client certificate re-enrolls the same entry " +
          "under a new serial", function () {
    assertLeaf(leaf3, cacerts, [EKU.clientAuth], "-r");
    assert.notStrictEqual(K.serialOf(leaf3), K.serialOf(leaf1));
    assert.strictEqual(leaf3.subject, leaf1.subject);
  });
  const crl = await K.crlSerials("default", "est");
  C.check("the renewed certificate is on the EST CRL (superseded)",
          function () {
    assert.ok(crl.indexOf(K.serialOf(leaf1)) >= 0, crl.join(","));
  });
  const stale = await est(["-e", "-c", path.join(e1.dir, "cert-0-0.pem"),
                           "-k", key1, "--common-name", PERSON],
                          { name: "stale" });
  C.check("the superseded certificate is refused as a credential",
          function () {
    refused(stale, /EST_ERR_AUTH_FAIL/, "superseded certificate");
  });
  const byCert = await est(["-e", "-c", path.join(r1.dir, "cert-0-0.pem"),
                            "-k", key1, "--common-name", PERSON,
                            "--pem-output"], { name: "bycert" });
  C.check("-e with a current TLS client certificate and no password " +
          "enrolls", function () {
    assertLeaf(leafOf(wrote(byCert, "cert-0-0.pem", "-e by certificate")),
               cacerts, [EKU.clientAuth], "by certificate");
  });

  // -------------------------------------------------------------------------
  log.info("=== 5. /serverkeygen ===");
  const qReq = await K.opensslRequest(work, "keygen", {
    subject: "/CN=" + PERSON, newkey: "rsa:2048" });
  const q = await est(["-q", "-x", qReq.key, "--common-name", PERSON,
                       "--pem-output"].concat(basic),
                      { name: "keygen", secrets: secrets });
  const qLeaf = leafOf(wrote(q, "cert-0-0.pem", "-q", [/^OSSL error: \(null\)$/]));
  const qKeyText = fs.readFileSync(wrote(q, "key-0-0.key", "-q",
                                         [/^OSSL error: \(null\)$/]),
                                   "utf8").replace(/\s+/g, "");
  C.check("-q is issued a certificate and the key the server made, and " +
          "they match", function () {
    assertLeaf(qLeaf, cacerts, [EKU.clientAuth], "-q");
    const key = nodeCrypto.createPrivateKey({
      key: Buffer.from(qKeyText, "base64"), format: "der", type: "pkcs8" });
    const pub = nodeCrypto.createPublicKey(key).export({ type: "spki",
                                                         format: "der" });
    assert.ok(Buffer.from(pub).equals(Buffer.from(qLeaf.publicKey.export({
      type: "spki", format: "der" }))), "the key is not the certificate's");
  });

  // -------------------------------------------------------------------------
  log.info("=== 6. refusals ===");
  const none = await est(["-e", "--common-name", PERSON], { name: "none" });
  C.check("no credential is refused (401)", function () {
    refused(none, /EST_ERR_AUTH_FAIL/, "no credential");
  });
  const wrong = await est(["-e", "-u", PERSON, "-h", "not-" + password,
                           "--common-name", PERSON],
                          { name: "wrong", secrets: [password] });
  if (product) {
    C.check("a wrong password is refused (product mode)", function () {
      refused(wrong, /EST_ERR_AUTH_FAIL/, "wrong password");
    });
  } else {
    C.check("a wrong password enrolls in development mode, which checks " +
            "no password", function () {
      wrote(wrong, "cert-0-0.pkcs7", "wrong password (development)");
    });
  }
  const label = await est(["-e", "--path-seg", "nosuch", "--common-name",
                           PERSON].concat(basic),
                          { name: "label", secrets: secrets });
  C.check("an unknown label is 404", function () {
    refused(label, /EST_ERR_HTTP_NOT_FOUND/, "unknown label");
  });
  const rootCa = await est(["-e", "--path-seg", "root-ca", "--common-name",
                            PERSON].concat(basic),
                           { name: "rootca", secrets: secrets });
  C.check("a refused profile (root-ca) is refused", function () {
    refused(rootCa, /failed with code/, "root-ca");
  });
  const strangerReq = await K.opensslRequest(work, "stranger", {
    subject: "/CN=nobody-" + STAMP + ".example.org",
    sans: "DNS:nobody-" + STAMP + ".example.org", newkey: "rsa:2048" });
  const stranger = await est(["-e", "--path-seg", "tls-server",
                              "-y", strangerReq.csr]
                               .concat(basic),
                             { name: "stranger", secrets: secrets });
  C.check("a host not registered on the entry is refused", function () {
    refused(stranger, /failed with code/, "unregistered host");
  });
  const selfKey = path.join(work, "self.key");
  const selfCert = path.join(work, "self.pem");
  const self = await K.run("openssl", ["req", "-x509", "-newkey", "ec",
    "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", selfKey,
    "-out", selfCert, "-days", "1", "-subj", "/CN=" + PERSON]);
  assert.strictEqual(self.status, 0, self.shown);
  const selfSigned = await est(["-e", "-c", selfCert, "-k", selfKey,
                                "--common-name", PERSON], { name: "self" });
  C.check("a self-signed client certificate is refused", function () {
    refused(selfSigned, /EST_ERR_AUTH_FAIL|failed with code/,
            "self-signed certificate");
  });
  const token = await est(["-e", "--auth-token", "not-an-est-credential",
                           "--common-name", PERSON], { name: "token" });
  C.check("a Bearer token (--auth-token) is refused", function () {
    refused(token, /EST_ERR_AUTH_FAIL/, "--auth-token");
  });
  const srp = await est(["-e", "--srp", "--srp-user", PERSON,
                         "--srp-password", password, "--common-name",
                         PERSON], { name: "srp", secrets: secrets });
  C.check("TLS-SRP is refused at the handshake (the service offers none)",
          function () {
    refused(srp, /EST_ERR_SSL_CONNECT|SSL/, "--srp");
  });

  assert.ok(C.count >= 17,
    "only " + C.count + " checks ran; a section has stopped being called.");
  log.info(C.count + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_est_libest")
  .description("Cisco's libest estclient, at a pinned commit, against the " +
      "EST server: bootstrap, csrattrs, simpleenroll with Basic and with a " +
      "certificate, simplereenroll, serverkeygen, and the refusals.")
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error((e.stack || e.message) +
            (e.cause ? "\ncaused by: " + (e.cause.stack || e.cause) : ""));
  process.exit(1);
});
