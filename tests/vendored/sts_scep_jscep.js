"use strict";
//
// File: sts_scep_jscep.js
//
// ===========================================================================
// jscep AGAINST THE SCEP SERVER (#250, 2026-09-26).
//
// jscep (MIT) is the maintained Java SCEP client library, on Bouncy Castle —
// a fourth SCEP lineage beside sscep, micromdm's scepclient and certmonger.
// It is a LIBRARY, so tests/tools/jscep-driver is the thinnest program that
// calls it (its header says exactly what it adds); jscep 3.0.1, built into
// the tests image by tests/Dockerfile's `enroll-java` stage with every jar
// held to a sha256. In two throwaway realms, over the plain-HTTP listener
// and then the main port's HTTPS:
//
//   * GetCACaps: what jscep NEGOTIATES from it — AES, SHA-512, POST.
//   * GetCACert: the RA as recipient and signer, the SCEP Issuing CA as the
//     issuer — checked by the driver against the realm Intermediate and the
//     Root, the out-of-band check jscep leaves to its application.
//   * GetNextCACert: not offered, so jscep itself refuses to ask; and the
//     server answers 501 to a client that asks anyway.
//   * PKCSReq with a challenge the PERSON made on /portal/certificates,
//     negotiated algorithms; CertPoll (GetCertInitial) for that transaction;
//     the same request again → the same certificate.
//   * EVERY COMBINATION of the ciphers and digests jscep can choose from the
//     server's capabilities — AES-128, AES-192, AES-256 × SHA-256, SHA-512 —
//     each through jscep's own encoder with that one argument named.
//   * GetCert by serial, and GetCRL.
//   * RENEWAL as jscep does it — a PKCSReq signed by the certificate being
//     renewed — keeping the key (refused STS-SCEP-0037 before #250: jscep's
//     transactionID is its public key's SHA-1, so it repeats) and with a new
//     key; both old serials then on the SCEP CRL.
//   * REFUSALS, each a CertRep FAILURE jscep reads: DES-EDE3, DES and SHA-1
//     (algorithms the server does not advertise) badAlg, after which the
//     challenge they carried still enrolls; the challenge reused, and one
//     nobody issued, badRequest; a request enveloped to ANOTHER realm's RA,
//     badMessageCheck.
//   * HTTPS on the main port: capabilities, CA and an enrollment.
//   * jscep's log (slf4j-simple, stderr): no WARN and no ERROR on any
//     success.
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
var log = bunyan.createLogger({ name: "sts_scep_jscep",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const STAMP = usernameFor("js").replace(/[^a-z0-9-]/g, "").slice(0, 22);
const REALM = ("jscep-" + STAMP).slice(0, 30);
const REALM_B = ("jscepb-" + STAMP).slice(0, 30);
const FRAN = "fran-" + STAMP;
const EKU = { clientAuth: "1.3.6.1.5.5.7.3.2" };
const C = K.checker(log);

var work = "";
var common = [];
const secrets = [];

// One driver command: its JSON answer, and jscep's own log lines.
async function jscep(command, args, what) {
  log.debug("Entering jscep(). " + command);
  const r = await K.run("jscep-driver", [command].concat(common, args),
                        { cwd: work, secrets: secrets, timeoutMs: 120000 });
  let answer = null;
  const last = r.stdout.trim().split("\n").pop();
  try {
    answer = JSON.parse(last);
  } catch (e) {
    log.debug("Caught in jscep(): " + ((e && e.message) || e));
    // No JSON: the driver itself failed; the assertion shows its output.
    answer = null;
  }
  log.debug("Leaving jscep().");
  return { run: r, answer: answer || {}, what: what,
           problems: K.problemLines(r.stderr, / (WARN|ERROR) /) };
}

function succeeded(j) {
  log.debug("Entering succeeded().");
  assert.ok(j.answer.ok === true && j.run.status === 0,
            j.what + ": " + j.run.shown);
  assert.deepStrictEqual(j.problems, [], j.what + " logged:\n" +
                         j.problems.join("\n"));
  log.debug("Leaving succeeded().");
}

function failedWith(j, failInfo) {
  log.debug("Entering failedWith().");
  assert.strictEqual(j.answer.status, "FAILURE", j.what + ": " + j.run.shown);
  assert.strictEqual(j.answer.failInfo, failInfo,
                     j.what + ": " + j.run.shown);
  log.debug("Leaving failedWith().");
}

async function challenge(realm, who) {
  log.debug("Entering challenge().");
  const made = await K.ok(K.realmApi(realm) + "/scep/create-challenge",
                          { kind: "person", identifier: who,
                            profile: "tls-client" },
                          "made a challenge for " + who);
  secrets.push(made.challenge);
  log.debug("Leaving challenge().");
  return made;
}

// A serial as hex with no leading zeros: Java's BigInteger.toString(16)
// drops them and K.serialOf() keeps an odd one.
function norm(serial) {
  log.debug("Entering norm().");
  log.debug("Leaving norm().");
  return String(serial || "").toLowerCase().replace(/^0+/, "");
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

async function test() {
  log.debug("Entering test().");
  log.info("Driving " + K.base + " with jscep in the trust realm \"" +
           REALM + "\".");
  work = K.scratch("jscep");
  const bundle = await K.trustBundle(work);

  // -------------------------------------------------------------------------
  log.info("=== 0. two realms, a person with a password ===");
  await K.makeRealm(REALM, "jscep job");
  await K.makeRealm(REALM_B, "jscep job B");
  const password = await K.makePerson(REALM, FRAN, FRAN + "@example.test");
  await K.setting(REALM, "scep.attemptsPerAddress", 100000);
  const first = await challenge(REALM, FRAN);
  const url = first.plainUrl;
  const org = (first.hint.match(/\\nO=([^\\]+)\\n/) || [])[1];
  const country = (first.hint.match(/\\nC=([A-Z]{2})\\n/) || [])[1];
  assert.ok(org, "the hint names no organisation: " + first.hint);
  const subject = "/CN=" + FRAN + "/O=" + org +
    (country ? "/C=" + country : "");
  const intermediate = await K.realmIntermediate(REALM);
  fs.writeFileSync(file("root.pem"), bundle.root.toString());
  fs.writeFileSync(file("intermediate.pem"), intermediate.toString());
  common = ["--anchor=" + file("root.pem"),
            "--intermediate=" + file("intermediate.pem")];
  const U = "--url=" + url;

  // -------------------------------------------------------------------------
  log.info("=== 1. GetCACaps, GetCACert, GetNextCACert ===");
  const caps = await jscep("caps", [U], "caps");
  C.check("GetCACaps: jscep negotiates AES, SHA-512 and POST, and sees " +
          "Renewal and no GetNextCACert", function () {
    succeeded(caps);
    assert.strictEqual(caps.answer.cipher, "AES");
    assert.strictEqual(caps.answer.digest, "SHA-512");
    assert.strictEqual(caps.answer.signature, "SHA512withRSA");
    assert.strictEqual(caps.answer.post, true);
    assert.strictEqual(caps.answer.renewal, true);
    assert.strictEqual(caps.answer.rollover, false);
  });
  const getca = await jscep("getca", [U, "--out=" + file("ca")], "getca");
  C.check("GetCACert: the RA is recipient and signer, the SCEP Issuing CA " +
          "the issuer, and it chains to the Root", function () {
    succeeded(getca);
    assert.ok(/CN=SCEP RA/.test(getca.answer.recipient));
    assert.strictEqual(getca.answer.signer, getca.answer.recipient);
    assert.ok(/SCEP Issuing CA/.test(getca.answer.issuer));
    assert.ok(/chains to/.test(getca.run.stderr), getca.run.stderr);
    const ra = certIn("ca/recipient.pem");
    const issuing = certIn("ca/issuer.pem");
    assert.ok(ra.checkIssued(issuing) && ra.verify(issuing.publicKey));
    K.chainsTo([issuing, intermediate], bundle.root);
  });
  const next = await jscep("nextca", [U], "nextca");
  const raw = await fetch(url + "?operation=GetNextCACert");
  C.check("GetNextCACert: jscep will not ask (not advertised), and the " +
          "server answers 501", function () {
    assert.strictEqual(next.answer.ok, false);
    assert.strictEqual(next.answer.exception,
                       "java.lang.UnsupportedOperationException");
    assert.strictEqual(raw.status, 501);
  });

  // -------------------------------------------------------------------------
  log.info("=== 2. enrol, poll, retry ===");
  const portal = await K.portalSignIn(REALM, FRAN, password);
  const made = await portal.post({ action: "create-challenge",
                                   profile: "tls-client" });
  const own = (made.text.match(
    /Challenge password<\/th><td><code>([^<]+)<\/code>/) || [])[1];
  assert.ok(own, "/portal/certificates made no challenge");
  secrets.push(own);
  const req = await K.opensslRequest(work, "fran",
                                     { subject: subject, challenge: own });
  const enrolled = await jscep("enroll", [U, "--csr=" + req.csr,
    "--key=" + req.key, "--out=" + file("fran.pem")], "enroll");
  const leaf = fs.existsSync(file("fran.pem")) ? certIn("fran.pem") : null;
  C.check("jscep enrols with the person's challenge: the realm's " +
          "certificate for the entry, chained to the Root", function () {
    succeeded(enrolled);
    K.chainsTo([leaf, certIn("ca/issuer.pem"), intermediate], bundle.root);
    assert.ok(String(leaf.subjectAltName)
                .indexOf("URI:urn:sts:person:" + FRAN) >= 0);
    assert.deepStrictEqual(leaf.keyUsage, [EKU.clientAuth]);
  });
  const polled = await jscep("poll", [U, "--csr=" + req.csr,
                                      "--key=" + req.key], "poll");
  C.check("CertPoll for that transaction answers the same certificate",
          function () {
    succeeded(polled);
    assert.strictEqual(polled.answer.transactionId,
                       enrolled.answer.transactionId);
    assert.strictEqual(norm(polled.answer.serial), norm(K.serialOf(leaf)));
  });
  const again = await jscep("enroll", [U, "--csr=" + req.csr,
    "--key=" + req.key, "--out=" + file("again.pem")], "enroll (retry)");
  C.check("the same request again is the same certificate, and spends " +
          "nothing", function () {
    succeeded(again);
    assert.strictEqual(norm(again.answer.serial), norm(K.serialOf(leaf)));
  });

  // -------------------------------------------------------------------------
  log.info("=== 3. every cipher and digest jscep can choose ===");
  const ciphers = ["AES_128", "AES_192", "AES_256"];
  const sigs = ["SHA256withRSA", "SHA512withRSA"];
  for (let i = 0; i < ciphers.length; i += 1) {
    for (let j = 0; j < sigs.length; j += 1) {
      const name = "combo-" + i + "-" + j;
      const made2 = await challenge(REALM, FRAN);
      const r = await K.opensslRequest(work, name,
        { subject: subject, challenge: made2.challenge });
      const got = await jscep("enroll", [U, "--csr=" + r.csr,
        "--key=" + r.key, "--cipher=" + ciphers[i], "--sig=" + sigs[j],
        "--out=" + file(name + ".pem")], ciphers[i] + " + " + sigs[j]);
      C.check(ciphers[i] + " with " + sigs[j] + " enrols", function () {
        succeeded(got);
        assert.strictEqual(got.answer.cipher, ciphers[i]);
        assert.strictEqual(got.answer.signature, sigs[j]);
      });
    }
  }

  // -------------------------------------------------------------------------
  log.info("=== 4. GetCert and GetCRL ===");
  const gotCert = await jscep("getcert", [U, "--identity=" + file("fran.pem"),
    "--key=" + req.key, "--serial=" + K.serialOf(leaf),
    "--out=" + file("got.pem")], "getcert");
  C.check("GetCert by serial answers the enrolled certificate", function () {
    succeeded(gotCert);
    assert.strictEqual(K.serialOf(certIn("got.pem")), K.serialOf(leaf));
  });
  const gotCrl = await jscep("getcrl", [U, "--identity=" + file("fran.pem"),
    "--key=" + req.key, "--serial=" + K.serialOf(leaf),
    "--out=" + file("scep.crl")], "getcrl");
  C.check("GetCRL answers the SCEP Issuing CA's CRL", function () {
    succeeded(gotCrl);
    assert.ok(/SCEP Issuing CA/.test(gotCrl.answer.issuer));
    assert.ok(fs.statSync(file("scep.crl")).size > 0);
  });

  // -------------------------------------------------------------------------
  log.info("=== 5. renewal ===");
  const sameKey = await K.run("openssl", ["req", "-new", "-key", req.key,
    "-subj", subject, "-out", file("renew.csr")], { cwd: work });
  assert.strictEqual(sameKey.status, 0, sameKey.shown);
  const renewed = await jscep("enroll", [U, "--csr=" + file("renew.csr"),
    "--key=" + req.key, "--identity=" + file("fran.pem"),
    "--identity-key=" + req.key, "--out=" + file("renewed.pem")],
    "renewal (same key)");
  C.check("a renewal that keeps the key — the same transactionID — is a " +
          "new certificate (STS-SCEP-0037 before #250)", function () {
    succeeded(renewed);
    assert.strictEqual(renewed.answer.transactionId,
                       enrolled.answer.transactionId);
    assert.notStrictEqual(norm(renewed.answer.serial),
                          norm(K.serialOf(leaf)));
  });
  const fresh = await K.opensslRequest(work, "rekey", { subject: subject });
  const rekeyed = await jscep("enroll", [U, "--csr=" + fresh.csr,
    "--key=" + fresh.key, "--identity=" + file("renewed.pem"),
    "--identity-key=" + req.key, "--out=" + file("rekeyed.pem")],
    "renewal (new key)");
  C.check("a renewal with a new key, signed by the certificate it renews",
          function () {
    succeeded(rekeyed);
    assert.notStrictEqual(rekeyed.answer.serial, renewed.answer.serial);
  });
  const crl = (await K.crlSerials(REALM, "scep")).map(norm);
  C.check("both renewed certificates are on the SCEP CRL", function () {
    assert.ok(crl.indexOf(norm(K.serialOf(leaf))) >= 0, crl.join(","));
    assert.ok(crl.indexOf(norm(renewed.answer.serial)) >= 0,
              crl.join(","));
  });

  // -------------------------------------------------------------------------
  log.info("=== 6. refusals ===");
  const held = await challenge(REALM, FRAN);
  const weak = await K.opensslRequest(work, "weak",
    { subject: subject, challenge: held.challenge });
  const algs = [["--cipher=DESede", "DES-EDE3"], ["--cipher=DES", "DES"],
                ["--sig=SHA1withRSA", "SHA-1"]];
  for (let i = 0; i < algs.length; i += 1) {
    const r = await jscep("enroll", [U, "--csr=" + weak.csr,
      "--key=" + weak.key, algs[i][0]], "enroll (" + algs[i][1] + ")");
    C.check(algs[i][1] + ", which the server does not advertise, is a " +
            "FAILURE badAlg", function () {
      failedWith(r, "badAlg");
    });
  }
  const after = await jscep("enroll", [U, "--csr=" + weak.csr,
    "--key=" + weak.key, "--out=" + file("weak.pem")], "enroll (after)");
  C.check("and the challenge those refusals carried still enrols",
          function () {
    succeeded(after);
  });
  const reuse = await K.opensslRequest(work, "reuse",
                                       { subject: subject, challenge: own });
  const reused = await jscep("enroll", [U, "--csr=" + reuse.csr,
    "--key=" + reuse.key], "enroll (reused)");
  C.check("the person's spent challenge is a FAILURE badRequest",
          function () {
    failedWith(reused, "badRequest");
  });
  const nobody = await K.opensslRequest(work, "nobody", { subject: subject,
    challenge: "scep-p-nobody-0123456789abcdef.nope" });
  const unknown = await jscep("enroll", [U, "--csr=" + nobody.csr,
    "--key=" + nobody.key], "enroll (unknown)");
  C.check("a challenge nobody issued is a FAILURE badRequest", function () {
    failedWith(unknown, "badRequest");
  });
  const urlB = url.replace("/realm/" + REALM + "/", "/realm/" + REALM_B + "/");
  const getcaB = await jscep("getca", ["--url=" + urlB,
    "--out=" + file("ca-b")], "getca (realm B)");
  assert.ok(getcaB.answer.ok, getcaB.run.shown);
  const other = await challenge(REALM, FRAN);
  const otherReq = await K.opensslRequest(work, "other",
    { subject: subject, challenge: other.challenge });
  const wrongRa = await jscep("enroll", [U, "--csr=" + otherReq.csr,
    "--key=" + otherReq.key, "--recipient=" + file("ca-b/recipient.pem")],
    "enroll (another realm's RA)");
  C.check("a request enveloped to another realm's RA is a FAILURE " +
          "badMessageCheck", function () {
    failedWith(wrongRa, "badMessageCheck");
  });

  // -------------------------------------------------------------------------
  log.info("=== 7. HTTPS on the main port ===");
  const T = ["--url=" + first.url, "--trust=" + bundle.file];
  const tlsCaps = await jscep("caps", T, "caps (https)");
  const tlsReq = await K.opensslRequest(work, "tls",
    { subject: subject, challenge: other.challenge });
  const tlsEnrol = await jscep("enroll", T.concat(["--csr=" + tlsReq.csr,
    "--key=" + tlsReq.key, "--out=" + file("tls.pem")]), "enroll (https)");
  C.check("over HTTPS: the capabilities, and an enrolment with the " +
          "challenge the wrong-RA refusal left unspent", function () {
    succeeded(tlsCaps);
    assert.ok(/https:/.test(first.url), first.url);
    succeeded(tlsEnrol);
    assert.ok(certIn("tls.pem"));
  });

  assert.ok(C.count >= 25,
    "only " + C.count + " checks ran; a section has stopped being called.");
  log.info(C.count + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_scep_jscep")
  .description("jscep, through tests/tools/jscep-driver, against the SCEP " +
      "server: capabilities, CA certificates, enrolment, polling, every " +
      "negotiable algorithm, GetCert, GetCRL, renewal, the refusals and " +
      "HTTPS.")
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error((e.stack || e.message) +
            (e.cause ? "\ncaused by: " + (e.cause.stack || e.cause) : ""));
  process.exit(1);
});
