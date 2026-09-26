"use strict";
//
// File: sts_tlsfuzzer.js
//
// ===========================================================================
// TLSFUZZER AGAINST THE MAIN HTTPS PORT AND LDAPS 636 (#212, 2026-09-26).
//
// tlsfuzzer is the TLS protocol conformance and robustness suite: some 170
// scripts covering version negotiation, extension handling, record-layer
// limits, renegotiation, certificate requests and known attacks. This job
// runs every script that applies — tests/vendored/tlsfuzzer_kit.js holds the
// PLAN, what is not applicable and why, and every expected failure with its
// reason — against the two TLS listeners a test stack publishes. The third,
// the embedded debugger's, is bound by no stack and is driven in process
// (tests/tlsfuzzer_debugger.js) from the same plan.
//
// THE CLIENT CERTIFICATES ARE MADE HERE, AT RUN TIME. The main port asks
// every connection for one, so the scripts that present one — CertificateVerify
// in both versions, malformed certificates, post-handshake authentication —
// need a key and a certificate. RSA and EC P-256 come from a throwaway
// realm's own CA (`issue-tls-client-certificate` on an application, as the
// FAPI conformance job gets its mTLS certificates): those verify against the
// service Root on the main port. Ed25519, RSA-PSS and ML-DSA-65 are key types
// the realm's CA does not issue for TLS clients, so they are self-signed with
// `openssl` (3.5, the tests image's) — the port asks for a certificate and
// requires none, so a certificate that chains to nothing still completes the
// handshake, which is all a CertificateVerify probe needs. Nothing is
// committed and nothing outlives the job's scratch directory.
//
// The job passes when every script passes: exit 0, FAIL 0, XPASS 0. Each
// failure is printed with the probes that failed and the command that
// reproduces it.
// ===========================================================================

const assert = require("assert");
const childProcess = require("child_process");
const fs = require("fs");
const nodeCrypto = require("crypto");
const path = require("path");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const kit = require("./enroll_clients_kit.js");
const fuzzer = require("./tlsfuzzer_kit.js");

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
var log = bunyan.createLogger({ name: "sts_tlsfuzzer",
                                level: appconfig.LOG_LEVEL ||
                                       process.env.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const TAG = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "")
  .slice(0, 12);
const REALM = "tlsf-" + TAG;
const APP = "tlsfuzzer-" + TAG;

// Where the two listeners are: the host of the service URL, its port, and
// 636 unless the runner says otherwise (sts_ldaps.js's reading).
function targets() {
  log.debug("Entering targets().");
  const url = new URL(kit.base);
  const port = Number(url.port || 443);
  log.debug("Leaving targets().");
  return {
    host: url.hostname,
    main: port,
    ldaps: Number(process.env.STS_LDAPS_PORT || 636)
  };
}

// `openssl`, bounded, its output logged when it fails.
function openssl(args) {
  log.debug("Entering openssl().");
  const r = childProcess.spawnSync("openssl", args,
                                   { encoding: "utf8", timeout: 120000 });
  assert.strictEqual(r.status, 0, "openssl " + args.join(" ") + " failed: " +
                     (r.stderr || r.error || ""));
  log.debug("Leaving openssl().");
  return r.stdout;
}

// A client certificate from the realm's CA, as tlsfuzzer reads one: the key
// as unencrypted PKCS #8, the certificate followed by its chain.
async function realmCertificate(dir, kind, keyAlg) {
  log.debug("Entering realmCertificate(). " + kind);
  const password = nodeCrypto.randomBytes(18).toString("base64url");
  const r = await kit.ok(kit.realmApi(REALM) +
                         "/applications/issue-tls-client-certificate",
                         { application: APP, password: password,
                           keyAlg: keyAlg, label: "tlsfuzzer " + kind },
                         "issued a " + keyAlg + " TLS client certificate");
  const key = nodeCrypto.createPrivateKey({ key: r.files.key.text,
                                           format: "pem",
                                           passphrase: password })
    .export({ format: "pem", type: "pkcs8" });
  const pair = { key: path.join(dir, kind + ".key"),
                 cert: path.join(dir, kind + ".crt") };
  fs.writeFileSync(pair.key, String(key), { mode: 0o600 });
  fs.writeFileSync(pair.cert, [r.certificate.certificatePem]
    .concat(r.certificate.chainPem || []).join("\n"));
  log.debug("Leaving realmCertificate().");
  return pair;
}

// A self-signed one, for a key type the realm's CA does not issue.
function selfSigned(dir, kind, keyArgs) {
  log.debug("Entering selfSigned(). " + kind);
  const pair = { key: path.join(dir, kind + ".key"),
                 cert: path.join(dir, kind + ".crt") };
  openssl(["req", "-x509", "-nodes", "-days", "1", "-subj",
           "/CN=tlsfuzzer-" + kind + "-" + TAG, "-keyout", pair.key,
           "-out", pair.cert].concat(keyArgs));
  log.debug("Leaving selfSigned().");
  return pair;
}

async function clientCertificates() {
  log.debug("Entering clientCertificates().");
  const dir = kit.scratch("tlsfuzzer-certs");
  await kit.makeRealm(REALM, "tlsfuzzer " + TAG);
  await kit.ok(kit.realmApi(REALM) + "/applications/create",
               { identifier: APP, protocols: ["oauth2"],
                 fields: { oauthClientId: APP } }, "created an application");
  const certificates = {
    rsa: await realmCertificate(dir, "rsa", "rsa-2048"),
    ec: await realmCertificate(dir, "ec", "ec-p256"),
    ed25519: selfSigned(dir, "ed25519", ["-newkey", "ed25519"]),
    rsapss: selfSigned(dir, "rsapss", ["-newkey", "rsa-pss", "-pkeyopt",
                                       "rsa_keygen_bits:2048"]),
    mldsa: selfSigned(dir, "mldsa", ["-newkey", "ml-dsa-65"]),
    brainpool: selfSigned(dir, "brainpool", ["-newkey", "ec", "-pkeyopt",
                                             "ec_paramgen_curve:" +
                                             "brainpoolP256r1"])
  };
  // tlslite reads a brainpool key only in the traditional SEC 1 form: its
  // PKCS #8 parser knows the NIST curves alone ("Unknown curve").
  openssl(["ec", "-in", certificates.brainpool.key, "-out",
           certificates.brainpool.key]);
  log.debug("Leaving clientCertificates().");
  return { dir: dir, certificates: certificates };
}

async function test() {
  log.debug("Entering test().");
  const where = targets();
  log.info("tlsfuzzer " + fs.readFileSync(path.join(fuzzer.TLSFUZZER_DIR,
    "tlsfuzzer", "COMMIT"), "utf8").trim() + ", tlslite-ng " +
    fs.readFileSync(path.join(fuzzer.TLSFUZZER_DIR, "tlslite-ng", "COMMIT"),
                    "utf8").trim() + ", against " + where.host + ":" +
    where.main + " and :" + where.ldaps);
  fuzzer.notApplicable().forEach(function (entry) {
    log.info("  [not applicable] " + entry.script + ": " + entry.skip);
  });
  const made = await clientCertificates();
  const concurrency = Number(process.env.STS_TLSFUZZER_CONCURRENCY || 4);
  const report = function (r) {
    log.debug("Entering report(). " + r.script);
    log.debug("Leaving report().");
    if (r.ok) {
      log.info("  " + fuzzer.line(r));
    } else {
      log.error("  " + fuzzer.line(r) + "\n    reproduce: " + r.command +
                "\n" + r.output.split("\n").slice(-60).join("\n"));
    }
  };
  const [main, ldaps] = await Promise.all([
    fuzzer.runPlan({ host: where.host, port: where.main,
                     certificates: made.certificates }, "main",
                   { concurrency: concurrency, onResult: report }),
    fuzzer.runPlan({ host: where.host, port: where.ldaps,
                     certificates: made.certificates }, "ldaps",
                   { concurrency: concurrency, onResult: report })
  ]);
  fs.rmSync(made.dir, { recursive: true, force: true });
  const all = main.concat(ldaps);
  const probes = all.reduce(function (sum, r) {
    return sum + (r.counts.total || 0);
  }, 0);
  const bad = all.filter(function (r) {
    return !r.ok;
  });
  log.info(all.length + " script runs, " + probes + " probes, " + bad.length +
           " failed.");
  assert.ok(main.length > 0 && ldaps.length > 0,
            "the plan ran on both listeners");
  assert.strictEqual(bad.length, 0, bad.length + " tlsfuzzer script(s) " +
    "failed: " + bad.map(function (r) {
      return r.listener + " " + r.script;
    }).join(", "));
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

new Command()
  .description("tlsfuzzer (#212) against the main HTTPS port and LDAPS 636, " +
    "every applicable script, with client certificates made at run time.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
