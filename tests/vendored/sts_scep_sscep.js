"use strict";
//
// File: sts_scep_sscep.js
//
// ===========================================================================
// sscep AGAINST THE SCEP SERVER (#210, 2026-09-26).
//
// No official SCEP conformance suite exists. sscep (certnanny, BSD-style) is
// the long-standing independent SCEP client, a C program with no TLS at all,
// and speaks RFC 8894's GetCACaps, GetCACert, PKCSReq, GetCertInitial /
// CertPoll, GetCert and GetCRL with the challenge-password flow. At the
// commit tests/Dockerfile pins (cb3e539 — v0.10.0 cannot GetCert from a CA
// with a separate RA), in two throwaway realms it builds and leaves standing,
// over the PLAIN-HTTP listener (`pki.httpPort`, which answers SCEP since
// #210 because sscep refuses an https URL):
//
//   * GetCACaps and GetCACert: the RA first (it signs every CertRep and
//     decrypts every request), then the Issuing CA.
//   * THE HINT, RUN LITERALLY: the three lines /admin-api/scep/create-challenge
//     answers (the same hint /admin/scep draws) are run by bash as they are
//     written and enroll — until #210 they could not (https URL, no
//     challengePassword, the wrong certificate to verify with).
//   * A CHALLENGE THE PERSON MADE on /portal/certificates, signed in through
//     the realm's own authorization server, spent by an sscep enrollment
//     whose request carries the subject the certificate will — so sscep
//     prints no warning. The certificate chains to the realm and the Root.
//   * `-R`, resuming the same transaction (GetCertInitial): the same
//     certificate back, not a second one.
//   * GetCert by serial and GetCRL, signed with the enrolled certificate.
//   * RENEWAL the way sscep does it — a PKCSReq signed by the old
//     certificate (`-K -O`; sscep has no RenewalReq), which RFC 8894 section
//     2.3 notes most clients keep and which was refused STS-SCEP-0034 until
//     #210 — and the old serial then on the SCEP CRL.
//   * REFUSALS, each a CertRep FAILURE: the challenge reused, a challenge
//     nobody issued, a request enveloped to ANOTHER realm's RA, and 3DES and
//     SHA-1.
//   * sscep's output for every successful command: no warning and no error.
// ===========================================================================

const assert = require("assert");
const fs = require("fs");
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
var log = bunyan.createLogger({ name: "sts_scep_sscep",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const STAMP = usernameFor("ss").replace(/[^a-z0-9-]/g, "").slice(0, 22);
const REALM = ("sscep-" + STAMP).slice(0, 30);
const REALM_B = ("sscepb-" + STAMP).slice(0, 30);
const CAROL = "carol-" + STAMP;
const EKU = { clientAuth: "1.3.6.1.5.5.7.3.2" };
const C = K.checker(log);

var work = "";

async function sscep(op, args, what) {
  log.debug("Entering sscep(). op=" + op);
  const r = await K.run("sscep", [op].concat(args), { cwd: work,
                                                      timeoutMs: 120000 });
  r.what = what;
  log.debug("Leaving sscep(). status=" + r.status);
  return r;
}

function succeeded(r) {
  log.debug("Entering succeeded().");
  assert.strictEqual(r.status, 0, r.what + " exited " + r.status + ":\n" +
                     r.shown);
  const bad = K.problemLines(r.output, /warning|error|fail/i);
  assert.deepStrictEqual(bad, [], r.what + " printed:\n" + bad.join("\n"));
  log.debug("Leaving succeeded().");
}

function failed(r, pattern) {
  log.debug("Entering failed().");
  assert.notStrictEqual(r.status, 0, r.what + " succeeded:\n" + r.shown);
  assert.ok(/FAILURE/i.test(r.output) && pattern.test(r.output),
            r.what + ": " + r.shown);
  log.debug("Leaving failed().");
}

function file(name) {
  log.debug("Entering file().");
  log.debug("Leaving file().");
  return path.join(work, name);
}

function certIn(name) {
  log.debug("Entering certIn().");
  log.debug("Leaving certIn().");
  return K.pemChain(fs.readFileSync(file(name), "utf8"))[0];
}

async function challengeFromApi(realm, who) {
  log.debug("Entering challengeFromApi().");
  const made = await K.ok(K.realmApi(realm) + "/scep/create-challenge",
                          { kind: "person", identifier: who,
                            profile: "tls-client" },
                          "made a challenge for " + who);
  log.debug("Leaving challengeFromApi().");
  return made;
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving " + K.base + " with sscep in the trust realm \"" +
           REALM + "\".");
  work = K.scratch("sscep");
  const bundle = await K.trustBundle(work);

  // -------------------------------------------------------------------------
  log.info("=== 0. two realms, a person with a password ===");
  await K.makeRealm(REALM, "sscep job");
  await K.makeRealm(REALM_B, "sscep job B");
  const password = await K.makePerson(REALM, CAROL, CAROL + "@example.test");
  await K.setting(REALM, "scep.attemptsPerAddress", 100000);
  const first = await challengeFromApi(REALM, CAROL);
  const url = first.plainUrl;
  C.check("create-challenge answers a plain-HTTP URL for sscep", function () {
    assert.ok(/^http:\/\/[^/]+\/realm\/[^/]+\/enroll\/scep\/tls-client$/
                .test(url), url);
  });
  // The subject the certificate will carry, read from the hint: sscep
  // warns when the request's differs.
  const org = (first.hint.match(/\\nO=([^\\]+)\\n/) || [])[1];
  const country = (first.hint.match(/\\nC=([A-Z]{2})\\n/) || [])[1];
  assert.ok(org, "the hint names no organisation: " + first.hint);
  const intermediate = await K.realmIntermediate(REALM);

  // -------------------------------------------------------------------------
  log.info("=== 1. GetCACaps and GetCACert ===");
  const caps = await sscep("getcaps", ["-u", url], "getcaps");
  C.check("GetCACaps offers POST, SHA-256, AES and Renewal", function () {
    succeeded(caps);
    ["POSTPKIOperation", "SHA-256", "AES", "Renewal"].forEach(function (c) {
      assert.ok(caps.output.indexOf(c) >= 0, c + " not in " + caps.shown);
    });
  });
  const getca = await sscep("getca", ["-u", url, "-c", "ca.crt"], "getca");
  C.check("GetCACert answers the RA and then the Issuing CA, chaining to " +
          "the Root", function () {
    succeeded(getca);
    const ra = certIn("ca.crt-0");
    const issuing = certIn("ca.crt-1");
    assert.ok(/SCEP/.test(issuing.subject), issuing.subject);
    assert.ok(ra.checkIssued(issuing) && ra.verify(issuing.publicKey),
              "the RA is issued by the SCEP Issuing CA");
    K.chainsTo([issuing, intermediate], bundle.root);
  });

  // -------------------------------------------------------------------------
  log.info("=== 2. the hint, run as it is written ===");
  const hintDir = K.scratch("sscep-hint");
  const hint = await K.run("bash", ["-e", "-c", first.hint],
                           { cwd: hintDir, secrets: [first.challenge],
                             timeoutMs: 120000 });
  C.check("the three lines of the hint enroll, with no warning", function () {
    assert.strictEqual(hint.status, 0, hint.shown);
    const bad = K.problemLines(hint.output, /warning|error|fail/i);
    assert.deepStrictEqual(bad, [], bad.join("\n"));
    const leaf = K.pemChain(fs.readFileSync(path.join(hintDir, "cert.pem"),
                                            "utf8"))[0];
    assert.ok(leaf.subject.indexOf("CN=" + CAROL) >= 0, leaf.subject);
  });

  // -------------------------------------------------------------------------
  log.info("=== 3. a challenge the person made on the portal ===");
  const portal = await K.portalSignIn(REALM, CAROL, password);
  const made = await portal.post({ action: "create-challenge",
                                   profile: "tls-client" });
  const challenge = (made.text.match(
    /Challenge password<\/th><td><code>([^<]+)<\/code>/) || [])[1];
  const portalUrl = (made.text.match(
    /Plain-HTTP SCEP URL<\/th><td><code>([^<]+)<\/code>/) || [])[1];
  C.check("/portal/certificates makes a challenge and names the " +
          "plain-HTTP URL", function () {
    assert.strictEqual(made.status, 200, made.text.slice(0, 400));
    assert.ok(challenge, "no challenge on the page");
    assert.strictEqual(portalUrl, url);
  });
  const subject = "/CN=" + CAROL + "/O=" + org +
    (country ? "/C=" + country : "");
  const req = await K.opensslRequest(work, "carol", {
    subject: subject, challenge: challenge,
    sans: "URI:urn:sts:person:" + CAROL });
  const enroll = ["-u", url, "-c", "ca.crt-0", "-e", "ca.crt-0",
                  "-k", req.key, "-r", req.csr, "-S", "sha256", "-E", "aes"];
  const enrolled = await sscep("enroll", enroll.concat(["-l", "carol.pem"]),
                               "enroll");
  const leaf = fs.existsSync(file("carol.pem")) ? certIn("carol.pem") : null;
  C.check("sscep enrolls with the person's challenge: the realm's " +
          "certificate for the entry, chained to the Root", function () {
    succeeded(enrolled);
    K.chainsTo([leaf, certIn("ca.crt-1"), intermediate], bundle.root);
    assert.ok(String(leaf.subjectAltName)
                .indexOf("URI:urn:sts:person:" + CAROL) >= 0);
    assert.deepStrictEqual(leaf.keyUsage, [EKU.clientAuth]);
  });
  const resumed = await sscep("enroll", enroll.concat(["-l", "again.pem",
                                                       "-R"]),
                              "enroll -R");
  C.check("-R resumes the same transaction and gets the same certificate",
          function () {
    succeeded(resumed);
    assert.strictEqual(K.serialOf(certIn("again.pem")), K.serialOf(leaf));
  });
  const reuseReq = await K.opensslRequest(work, "reuse", {
    subject: subject, challenge: challenge });
  const reused = await sscep("enroll", ["-u", url, "-c", "ca.crt-0",
    "-e", "ca.crt-0", "-k", reuseReq.key, "-r", reuseReq.csr,
    "-S", "sha256", "-E", "aes", "-l", "reuse.pem"], "enroll (reused)");
  C.check("the spent challenge on a new key is a FAILURE", function () {
    failed(reused, /badRequest|failInfo|FAILURE/);
  });

  // -------------------------------------------------------------------------
  log.info("=== 4. GetCert and GetCRL ===");
  const serialDecimal = BigInt("0x" + K.serialOf(leaf)).toString(10);
  const gotCert = await sscep("getcert", ["-u", url, "-c", "ca.crt-0",
    "-k", req.key, "-l", "carol.pem", "-O", "ca.crt-1",
    "-s", serialDecimal, "-w", "got.pem"], "getcert");
  C.check("GetCert by serial answers the enrolled certificate", function () {
    succeeded(gotCert);
    assert.strictEqual(K.serialOf(certIn("got.pem")), K.serialOf(leaf));
  });
  const gotCrl = await sscep("getcrl", ["-u", url, "-c", "ca.crt-0",
    "-k", req.key, "-l", "carol.pem", "-O", "carol.pem",
    "-w", "scep.crl"], "getcrl");
  C.check("GetCRL answers the Issuing CA's CRL", function () {
    succeeded(gotCrl);
    assert.ok(fs.statSync(file("scep.crl")).size > 0);
  });

  // -------------------------------------------------------------------------
  log.info("=== 5. renewal, the way sscep does it ===");
  const renewReq = await K.opensslRequest(work, "renew", {
    subject: subject, sans: "URI:urn:sts:person:" + CAROL });
  const renewed = await sscep("enroll", ["-u", url, "-c", "ca.crt-0",
    "-e", "ca.crt-0", "-k", renewReq.key, "-r", renewReq.csr,
    "-K", req.key, "-O", "carol.pem", "-S", "sha256", "-E", "aes",
    "-l", "renewed.pem"], "enroll (renewal)");
  C.check("a PKCSReq signed by the old certificate renews it (refused " +
          "STS-SCEP-0034 before #210)", function () {
    succeeded(renewed);
    const fresh = certIn("renewed.pem");
    assert.notStrictEqual(K.serialOf(fresh), K.serialOf(leaf));
    assert.strictEqual(fresh.subject, leaf.subject);
  });
  const crl = await K.crlSerials(REALM, "scep");
  C.check("the renewed certificate is on the SCEP CRL", function () {
    assert.ok(crl.indexOf(K.serialOf(leaf)) >= 0, crl.join(","));
  });

  // -------------------------------------------------------------------------
  log.info("=== 6. refusals ===");
  const nobody = await K.opensslRequest(work, "nobody", {
    subject: subject, challenge: "scep-p-nobody-0123456789abcdef.nope" });
  const unknown = await sscep("enroll", ["-u", url, "-c", "ca.crt-0",
    "-e", "ca.crt-0", "-k", nobody.key, "-r", nobody.csr, "-S", "sha256",
    "-E", "aes", "-l", "nobody.pem"], "enroll (unknown challenge)");
  C.check("a challenge nobody issued is a FAILURE", function () {
    failed(unknown, /FAILURE/);
  });
  const urlB = url.replace("/realm/" + REALM + "/", "/realm/" + REALM_B + "/");
  const getcaB = await sscep("getca", ["-u", urlB, "-c", "b.crt"],
                             "getca (realm B)");
  succeeded(getcaB);
  const other = await challengeFromApi(REALM, CAROL);
  const otherReq = await K.opensslRequest(work, "other", {
    subject: subject, challenge: other.challenge });
  const wrongRa = await sscep("enroll", ["-u", url, "-c", "ca.crt-0",
    "-e", "b.crt-0", "-k", otherReq.key, "-r", otherReq.csr,
    "-S", "sha256", "-E", "aes", "-l", "wrongra.pem"],
    "enroll (another realm's RA)");
  C.check("a request enveloped to another realm's RA is a FAILURE",
          function () {
    failed(wrongRa, /badMessageCheck|FAILURE/);
  });
  const des = await sscep("enroll", ["-u", url, "-c", "ca.crt-0",
    "-e", "ca.crt-0", "-k", otherReq.key, "-r", otherReq.csr,
    "-S", "sha256", "-E", "3des", "-l", "des.pem"], "enroll (3DES)");
  C.check("3DES is a FAILURE (badAlg)", function () {
    failed(des, /badAlg|FAILURE/);
  });
  const sha1 = await sscep("enroll", ["-u", url, "-c", "ca.crt-0",
    "-e", "ca.crt-0", "-k", otherReq.key, "-r", otherReq.csr,
    "-S", "sha1", "-E", "aes", "-l", "sha1.pem"], "enroll (SHA-1)");
  C.check("SHA-1 is a FAILURE (badAlg)", function () {
    failed(sha1, /badAlg|FAILURE/);
  });
  const stillGood = await sscep("enroll", ["-u", url, "-c", "ca.crt-0",
    "-e", "ca.crt-0", "-k", otherReq.key, "-r", otherReq.csr,
    "-S", "sha256", "-E", "aes", "-l", "other.pem"], "enroll (after)");
  C.check("and the challenge those refusals carried is still good for a " +
          "proper request", function () {
    succeeded(stillGood);
  });

  assert.ok(C.count >= 15,
    "only " + C.count + " checks ran; a section has stopped being called.");
  log.info(C.count + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_scep_sscep")
  .description("certnanny's sscep, at a pinned commit, against the SCEP " +
      "server over the plain-HTTP listener: capabilities, CA certificates, " +
      "the hint run literally, a portal challenge, resume, GetCert, " +
      "GetCRL, renewal and the refusals.")
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error((e.stack || e.message) +
            (e.cause ? "\ncaused by: " + (e.cause.stack || e.cause) : ""));
  process.exit(1);
});
