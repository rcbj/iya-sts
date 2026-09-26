"use strict";
//
// File: sts_scep_micromdm.js
//
// ===========================================================================
// micromdm's scepclient AGAINST THE SCEP SERVER (#211, 2026-09-26).
//
// micromdm/scep (Go, MIT) is the SCEP client of the Apple MDM ecosystem, a
// separate lineage from sscep. At the version tests/Dockerfile pins (v2.3.0,
// `go install` against the checksum database) — and at its `main` head
// (9902c1a, 2026-01-22), which changes nothing here — it CANNOT BE ISSUED A
// CERTIFICATE BY THIS SERVICE, and that is the service being right:
//
//   scepclient builds every pkiMessage with smallstep/scep and
//   smallstep/pkcs7 v0.1.1, whose package defaults are SINGLE DES-CBC for the
//   envelope (`ContentEncryptionAlgorithm = EncryptionAlgorithmDESCBC`) and
//   SHA-1 for the signature (`NewSignedData` sets OIDDigestAlgorithmSHA1).
//   It reads GetCACaps only to choose POST over GET, never to choose an
//   algorithm, and has no flag for either. This service offers AES and
//   SHA-256 in GetCACaps and refuses SHA-1, MD5, DES and 3DES `badAlg` in
//   both modes (docs/scep.md) — RFC 8894 section 3.5.2 has a client use
//   what the capabilities offer. So every PKCSReq scepclient sends is a
//   CertRep FAILURE badAlg (STS-SCEP-0020, the SHA-1 signature, is the first
//   check it fails). Recorded on #211 as a documented exception, with the
//   question to the owner of whether a legacy-algorithm setting should exist.
//
// What the job holds, in a throwaway realm it builds and leaves standing:
//
//   * THE TRANSPORT scepclient does use correctly, over HTTPS (the service
//     Root in SSL_CERT_FILE) and over the plain-HTTP listener: GetCACert (the
//     RA, the Issuing CA, the Intermediate and the Root), GetCACaps and a
//     POSTed PKIOperation — counted on /admin-api/scep/monitor. Every
//     PKIOperation was refused 415 STS-SCEP-0007 before #211's fix, because
//     scepclient POSTs `application/octet-stream`; it now reaches the CMS
//     checks and is answered a signed CertRep that scepclient parses.
//   * THE RECIPIENT CHOSEN THREE WAYS — every certificate GetCACert answered
//     (its default), `-key-encipherment-selector`, `-ca-fingerprint` naming
//     the RA — each reaching the server; and a fingerprint naming nothing,
//     refused by the client itself.
//   * THE REFUSAL IS badAlg, reported by scepclient as `failInfo: badAlg`,
//     and it SPENDS NOTHING: the single-use challenge it carried then
//     enrolls through sscep with SHA-256 and AES.
//   * scepclient's log: no `level=warn` and no `level=error` on the way to
//     the CertRep.
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
var log = bunyan.createLogger({ name: "sts_scep_micromdm",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const STAMP = usernameFor("mm").replace(/[^a-z0-9-]/g, "").slice(0, 22);
const REALM = ("mdm-" + STAMP).slice(0, 30);
const DAVE = "dave-" + STAMP;
const EKU = { clientAuth: "1.3.6.1.5.5.7.3.2" };
const C = K.checker(log);

var bundle = null;
var intermediate = null;

// One scepclient run in a directory of its own: it keeps its key, its CSR
// and its certificate beside each other, and a second run in the same
// directory is a renewal.
async function scepclient(dir, args, what) {
  log.debug("Entering scepclient().");
  fs.mkdirSync(dir, { recursive: true });
  const r = await K.run("scepclient", ["-private-key",
                                       path.join(dir, "key.pem"),
                                       "-certificate",
                                       path.join(dir, "cert.pem"),
                                       "-debug"].concat(args), {
    env: { SSL_CERT_FILE: bundle.file },
    secrets: [args[args.indexOf("-challenge") + 1]].filter(function (x) {
      return args.indexOf("-challenge") >= 0 && x;
    }),
    timeoutMs: 120000 });
  r.what = what;
  r.dir = dir;
  log.debug("Leaving scepclient(). status=" + r.status);
  return r;
}

function failed(r, pattern) {
  log.debug("Entering failed().");
  assert.notStrictEqual(r.status, 0, r.what + " succeeded:\n" + r.shown);
  assert.ok(pattern.test(r.output), r.what + ": " + r.shown);
  log.debug("Leaving failed().");
}

// A CertRep FAILURE badAlg, parsed by scepclient (it verified the RA's
// signature to read it), with no warning or error logged on the way.
function badAlg(r) {
  log.debug("Entering badAlg().");
  failed(r, /PKCSReq \(19\) request failed, failInfo: badAlg/);
  assert.ok(/msg="parsed scep pkiMessage" scep_message_type="CertRep/
              .test(r.output), r.what + ": no CertRep parsed: " + r.shown);
  const bad = K.problemLines(r.output, /level=(warn|error)/i);
  assert.deepStrictEqual(bad, [], r.what + " logged:\n" + bad.join("\n"));
  log.debug("Leaving badAlg().");
}

async function challenge(realm, profile) {
  log.debug("Entering challenge().");
  const made = await K.ok(K.realmApi(realm) + "/scep/create-challenge",
                          { kind: "person", identifier: DAVE,
                            profile: profile || "tls-client" },
                          "made a challenge");
  log.debug("Leaving challenge().");
  return made;
}

async function monitorCounts() {
  log.debug("Entering monitorCounts().");
  const r = await K.send(K.realmApi(REALM) + "/scep/monitor");
  log.debug("Leaving monitorCounts().");
  return Object.assign({}, (r.body && r.body.operations) || {});
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving " + K.base + " with micromdm's scepclient in the trust " +
           "realm \"" + REALM + "\".");
  const work = K.scratch("scepclient");
  bundle = await K.trustBundle(work);
  // `-version` answers "unknown": `go install` stamps no version, which
  // is why tests/Dockerfile names v2.3.0 where it installs it.
  log.info("scepclient -version: " +
           (await K.run("scepclient", ["-version"])).output.trim() +
           " (v2.3.0, pinned in tests/Dockerfile)");

  // -------------------------------------------------------------------------
  log.info("=== 0. a realm and a person ===");
  await K.makeRealm(REALM, "scepclient job");
  await K.makePerson(REALM, DAVE, DAVE + "@example.test");
  await K.setting(REALM, "scep.attemptsPerAddress", 100000);
  intermediate = await K.realmIntermediate(REALM);
  const before = await monitorCounts();

  // -------------------------------------------------------------------------
  log.info("=== 1. over HTTPS: the transport, and badAlg ===");
  const one = await challenge(REALM);
  const https = await scepclient(path.join(work, "https"), [
    "-server-url", one.url, "-challenge", one.challenge, "-cn", DAVE],
    "scepclient over https");
  const after = await monitorCounts();
  C.check("GetCACert lists the RA, the Issuing CA, the Intermediate and " +
          "the Root", function () {
    assert.ok(/msg=cacertlist count=4/.test(https.output), https.shown);
    assert.ok(/number=0 rdn="CN=SCEP RA/.test(https.output), https.shown);
  });
  C.check("GetCACaps and the POSTed PKIOperation reach the server and are " +
          "counted (the POST was 415 before #211)", function () {
    ["GetCACaps", "GetCACert", "PKIOperation"].forEach(function (op) {
      const name = Object.keys(after).filter(function (k) {
        return k.toLowerCase().indexOf(op.toLowerCase()) >= 0;
      })[0];
      assert.ok(name && after[name] > (before[name] || 0),
                op + " was not counted: " + JSON.stringify(after));
    });
    assert.ok(/op=PKIOperation error=null/.test(https.output), https.shown);
  });
  C.check("the PKCSReq, signed over SHA-1 and enveloped with DES (the " +
          "client's fixed defaults), is a signed CertRep FAILURE badAlg",
          function () {
    badAlg(https);
  });

  // -------------------------------------------------------------------------
  log.info("=== 2. over plain HTTP, the recipient chosen three ways ===");
  const getca = await K.run("sscep", ["getca", "-u", one.plainUrl, "-c",
                                      path.join(work, "ca.crt")]);
  assert.strictEqual(getca.status, 0, getca.shown);
  const ra = K.pemChain(fs.readFileSync(path.join(work, "ca.crt-0"),
                                        "utf8"))[0];
  const selected = await scepclient(path.join(work, "selected"), [
    "-server-url", one.plainUrl, "-challenge", one.challenge, "-cn", DAVE,
    "-key-encipherment-selector"], "scepclient -key-encipherment-selector");
  C.check("over plain HTTP with -key-encipherment-selector: badAlg",
          function () {
    badAlg(selected);
  });
  const pinned = await scepclient(path.join(work, "pinned"), [
    "-server-url", one.plainUrl, "-challenge", one.challenge,
    "-cn", DAVE, "-ca-fingerprint",
    nodeCrypto.createHash("sha256").update(ra.raw).digest("hex")],
    "scepclient -ca-fingerprint");
  C.check("-ca-fingerprint naming the RA: badAlg", function () {
    badAlg(pinned);
  });
  const wrongPin = await scepclient(path.join(work, "wrongpin"), [
    "-server-url", one.plainUrl, "-challenge", one.challenge,
    "-cn", DAVE, "-ca-fingerprint", "00".repeat(32)],
    "scepclient -ca-fingerprint (nothing matches)");
  C.check("-ca-fingerprint naming nothing the server sent is refused by " +
          "the client before it sends anything", function () {
    failed(wrongPin, /no selected CA\/RA recipients/);
  });

  // -------------------------------------------------------------------------
  log.info("=== 3. the refusal spent nothing ===");
  const req = await K.opensslRequest(work, "dave", {
    subject: "/CN=" + DAVE, challenge: one.challenge,
    sans: "URI:urn:sts:person:" + DAVE });
  const sscep = await K.run("sscep", ["enroll", "-u", one.plainUrl,
    "-c", path.join(work, "ca.crt-0"), "-e", path.join(work, "ca.crt-0"),
    "-k", req.key, "-r", req.csr, "-S", "sha256", "-E", "aes",
    "-l", path.join(work, "dave.pem")], { secrets: [one.challenge] });
  C.check("the challenge scepclient carried three times still enrolls " +
          "with SHA-256 and AES", function () {
    assert.strictEqual(sscep.status, 0, sscep.shown);
    const leaf = K.pemChain(fs.readFileSync(path.join(work, "dave.pem"),
                                            "utf8"))[0];
    assert.ok(String(leaf.subjectAltName)
                .indexOf("URI:urn:sts:person:" + DAVE) >= 0);
    assert.deepStrictEqual(leaf.keyUsage, [EKU.clientAuth]);
    K.chainsTo([leaf, K.pemChain(fs.readFileSync(
      path.join(work, "ca.crt-1"), "utf8"))[0], intermediate], bundle.root);
  });

  assert.ok(C.count >= 7,
    "only " + C.count + " checks ran; a section has stopped being called.");
  log.info(C.count + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_scep_micromdm")
  .description("micromdm's scepclient, at a pinned version, against the " +
      "SCEP server over HTTPS and plain HTTP: GetCACert, GetCACaps and a " +
      "POSTed PKIOperation, three ways of choosing the recipient, and the " +
      "badAlg its fixed SHA-1 and DES draw, which spends no challenge.")
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error((e.stack || e.message) +
            (e.cause ? "\ncaused by: " + (e.cause.stack || e.cause) : ""));
  process.exit(1);
});
