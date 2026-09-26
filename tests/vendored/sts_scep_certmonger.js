"use strict";
//
// File: sts_scep_certmonger.js
//
// ===========================================================================
// certmonger AGAINST THE SCEP SERVER (#249, 2026-09-26).
//
// certmonger (Red Hat, GPL-2.0+) is the certificate-tracking daemon most
// Linux hosts enrol and renew with; `getcert add-scep-ca` and `getcert
// request` drive its `scep-submit` helper, a third SCEP lineage beside sscep
// (#210) and micromdm's scepclient (#211), and the second that can complete
// an enrollment here. Ubuntu 26.04's package (0.79.21), installed in the
// tests image (tests/Dockerfile). THE JOB STARTS THE DAEMON ITSELF, on a
// private socket (`certmonger -n -L -P`, which getcert reaches through
// CERTMONGER_PVT_ADDRESS — no D-Bus), with its state in a scratch directory
// and `-d 0`: the log it writes is exactly what the daemon would send to
// syslog, and it is the job's error-and-warning source together with
// `getcert list`'s status and ca-error. In two throwaway realms, over the
// PLAIN-HTTP listener (RFC 8894 section 2.1; why not HTTPS is the last
// scenario):
//
//   * add-scep-ca: certmonger fetches GetCACaps and GetCACert itself; its CA
//     record holds the capabilities, the RA and the Issuing CA.
//   * getcert request with a challenge the PERSON made on
//     /portal/certificates: MONITORING, the realm's certificate for the entry,
//     chained to the Root — refused STS-SCEP-0011 before #249, because
//     certmonger signs with a version 1 self-signed certificate.
//   * CertPoll: certmonger's own scep-submit, run as the daemon runs it, with
//     the GetCertInitial message the daemon generated and stored for that
//     request: the same certificate, encrypted to the request's key.
//   * getcert resubmit (the same key) and getcert rekey (a new one): each a
//     new certificate, the one before superseded on the SCEP CRL. The
//     resubmit was refused STS-SCEP-0037 before #249 — certmonger's
//     transactionID is its public key's digest, so it repeats.
//   * REFUSALS: the challenge reused, the envelope to ANOTHER realm's RA,
//     and — certmonger's CA record told to use them — DES-EDE3 and SHA-1.
//     Each is on the SCEP monitor with its code. certmonger reports each as
//     CA_UNREACHABLE, "no content": it cannot read a FAILURE CertRep, which
//     RFC 8894 section 3.2 sends without signed content (scep/CLAUDE.md,
//     *What the real clients found*). The challenge the algorithm refusals
//     carried then enrolls.
//   * HTTPS: certmonger fetches the CA over TLS with `-R`, and its
//     PKIOperation request then fails curl error 60, because scep-submit
//     passes the CA file to the first two requests only — asserted, so a
//     certmonger that fixes it is noticed.
//   * The daemon's log: nothing but the documented line after a refusal.
// ===========================================================================

const assert = require("assert");
const childProcess = require("child_process");
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
var log = bunyan.createLogger({ name: "sts_scep_certmonger",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const STAMP = usernameFor("cm").replace(/[^a-z0-9-]/g, "").slice(0, 22);
const REALM = ("cmgr-" + STAMP).slice(0, 30);
const REALM_B = ("cmgrb-" + STAMP).slice(0, 30);
const ERIN = "erin-" + STAMP;
const EKU = { clientAuth: "1.3.6.1.5.5.7.3.2" };
const SCEP_SUBMIT = "/usr/lib/certmonger/scep-submit";
const C = K.checker(log);

// The one line certmonger logs for a refusal it could not read — the
// documented exception, and the only problem line a refusal may leave.
const NO_CONTENT = /failed to verify signature on server response\. .*no content/;

var work = "";
var state = null;
var daemon = null;
const secrets = [];

// ---------------------------------------------------------------------------
// THE DAEMON: started, stopped and restarted by the job, its state in the
// scratch directory.
// ---------------------------------------------------------------------------
function stateEnv() {
  log.debug("Entering stateEnv().");
  log.debug("Leaving stateEnv().");
  return {
    CERTMONGER_CONFIG_DIR: state.dir,
    CERTMONGER_REQUESTS_DIR: path.join(state.dir, "requests"),
    CERTMONGER_CAS_DIR: path.join(state.dir, "cas"),
    CERTMONGER_LOCAL_CA_DIR: path.join(state.dir, "local"),
    CERTMONGER_TMPDIR: path.join(state.dir, "tmp")
  };
}

async function startDaemon() {
  log.debug("Entering startDaemon().");
  const env = stateEnv();
  Object.keys(env).forEach(function (k) {
    fs.mkdirSync(env[k], { recursive: true });
  });
  try {
    fs.unlinkSync(state.sock);
  } catch (e) {
    log.debug("Caught in startDaemon(): " + ((e && e.message) || e));
    // No socket left from a previous run of the daemon: nothing to remove.
  }
  const out = fs.openSync(state.log, "a");
  daemon = childProcess.spawn("certmonger",
    ["-n", "-L", "-P", state.sock, "-d", "0", "-p", state.pid],
    { env: Object.assign({}, process.env, env),
      stdio: ["ignore", out, out] });
  fs.closeSync(out);
  daemon.on("error", function (e) {
    log.info("certmonger could not be started: " + e.message);
  });
  for (let i = 0; i < 100 && !fs.existsSync(state.sock); i += 1) {
    await new Promise(function (resolve) {
      setTimeout(resolve, 100);
    });
  }
  assert.ok(fs.existsSync(state.sock),
            "certmonger did not open its socket " + state.sock);
  log.debug("Leaving startDaemon().");
}

async function stopDaemon() {
  log.debug("Entering stopDaemon().");
  if (!daemon || daemon.exitCode !== null) {
    log.debug("Leaving stopDaemon(). Not running.");
    return;
  }
  const exited = new Promise(function (resolve) {
    daemon.on("exit", resolve);
  });
  daemon.kill("SIGTERM");
  await Promise.race([exited, new Promise(function (resolve) {
    setTimeout(resolve, 10000);
  })]);
  if (daemon.exitCode === null) {
    daemon.kill("SIGKILL");
  }
  daemon = null;
  log.debug("Leaving stopDaemon().");
}

async function getcert(args, what) {
  log.debug("Entering getcert(). " + args[0]);
  const r = await K.run("getcert", args, {
    cwd: work, secrets: secrets, timeoutMs: 180000,
    env: { CERTMONGER_PVT_ADDRESS: "unix:path=" + state.sock } });
  r.what = what;
  log.debug("Leaving getcert(). status=" + r.status);
  return r;
}

// certmonger's own record files: `key=value`, a value continued on lines
// that start with a space.
function records(dir) {
  log.debug("Entering records().");
  const out = [];
  fs.readdirSync(dir).forEach(function (name) {
    const rec = {};
    let last = null;
    let text = "";
    try {
      // certmonger writes a record to `<name>.tmp` and renames it; one
      // listed and gone by the time it is read is that, mid-write.
      text = name.endsWith(".tmp") ? ""
                                   : fs.readFileSync(path.join(dir, name),
                                                     "utf8");
    } catch (e) {
      log.debug("Caught in records(): " + ((e && e.message) || e));
      text = "";
    }
    text.split("\n")
      .forEach(function (line) {
        if (line.startsWith(" ") && last) {
          rec[last] += "\n" + line.slice(1);
        } else if (line.indexOf("=") > 0) {
          last = line.slice(0, line.indexOf("="));
          rec[last] = line.slice(line.indexOf("=") + 1);
        }
      });
    rec.file = path.join(dir, name);
    out.push(rec);
  });
  log.debug("Leaving records().");
  return out;
}

function recordOf(kind, id) {
  log.debug("Entering recordOf(). " + kind + " " + id);
  const found = records(stateEnv()[kind === "ca" ? "CERTMONGER_CAS_DIR"
                                                 : "CERTMONGER_REQUESTS_DIR"])
    .filter(function (r) {
      return r.id === id;
    });
  log.debug("Leaving recordOf().");
  return found[0] || null;
}

// The SCEP Issuing CA among the certificates certmonger kept for its CA:
// `ca_encryption_issuer_cert` is the top of what GetCACert answered (the
// Root), and the rest is `ca_encryption_cert_pool`.
function issuingOf(ca) {
  log.debug("Entering issuingOf().");
  const found = K.pemChain((ca.ca_encryption_issuer_cert || "") + "\n" +
                           (ca.ca_encryption_cert_pool || ""))
    .filter(function (x) {
      return /SCEP Issuing CA/.test(x.subject);
    });
  assert.ok(found.length > 0, "certmonger kept no SCEP Issuing CA");
  log.debug("Leaving issuingOf().");
  return found[0];
}

async function waitForCa(id) {
  log.debug("Entering waitForCa(). " + id);
  let ca = null;
  for (let i = 0; i < 150; i += 1) {
    ca = recordOf("ca", id);
    if (ca && ca.ca_capabilities && ca.ca_encryption_cert) {
      break;
    }
    await new Promise(function (resolve) {
      setTimeout(resolve, 200);
    });
  }
  log.debug("Leaving waitForCa().");
  return ca;
}

// What `getcert list -i` says, as fields.
async function listed(id) {
  log.debug("Entering listed(). " + id);
  const r = await getcert(["list", "-i", id], "getcert list -i " + id);
  const fields = {};
  r.output.split("\n").forEach(function (line) {
    const m = line.match(/^\s+([a-z][a-z -]*):\s?(.*)$/);
    if (m && !(m[1] in fields)) {
      fields[m[1]] = m[2];
    }
  });
  log.debug("Leaving listed(). status=" + fields.status);
  return fields;
}

// The daemon's log from `from` on, and the problem lines in it.
function logSince(from) {
  log.debug("Entering logSince().");
  const text = fs.readFileSync(state.log, "utf8").slice(from);
  log.debug("Leaving logSince().");
  return text;
}

function logSize() {
  log.debug("Entering logSize().");
  log.debug("Leaving logSize().");
  return fs.existsSync(state.log) ? fs.statSync(state.log).size : 0;
}

// The problem lines of the daemon's log. The documented "no content" line
// is left out everywhere: it belongs to a refusal, and certmonger re-sends
// a refused request on its own schedule, so one can land in a later step's
// slice of the log; a SUCCESS can never produce it (it has content), and
// every refusal asserts it through `getcert list`'s ca-error instead.
function problems(text) {
  log.debug("Entering problems().");
  log.debug("Leaving problems().");
  return K.problemLines(text, /error|warn|fail|crit/i, [NO_CONTENT]);
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

async function monitorRows(realm) {
  log.debug("Entering monitorRows().");
  const r = await K.send(K.realmApi(realm) + "/scep/monitor");
  assert.strictEqual(r.status, 200, "the SCEP monitor: " + r.status);
  log.debug("Leaving monitorRows().");
  return r.body.recent || [];
}

// A refusal: certmonger's status, its one documented log line, and the
// code the server recorded for it.
async function refused(id, since, logFrom, codes, what) {
  log.debug("Entering refused(). " + id);
  const f = await listed(id);
  const rows = (await monitorRows(REALM)).filter(function (row) {
    return row.at >= since && row.operation === "PKIOperation:PKCSReq";
  });
  C.check(what + ": certmonger reports CA_UNREACHABLE (it cannot read a " +
          "FAILURE CertRep) and the server recorded " + codes.join(" or "),
          function () {
    assert.strictEqual(f.status, "CA_UNREACHABLE", JSON.stringify(f));
    assert.ok(NO_CONTENT.test(f["ca-error"] || ""), f["ca-error"]);
    const bad = problems(logSince(logFrom));
    assert.deepStrictEqual(bad, [], bad.join("\n"));
    assert.ok(rows.some(function (row) {
      return codes.indexOf(row.errorCode) >= 0;
    }), "no monitor row with " + codes.join("/") + ": " +
        JSON.stringify(rows.map(function (row) {
          return [row.errorCode, row.failInfo];
        })));
  });
  await getcert(["stop-tracking", "-i", id], "stop-tracking " + id);
  log.debug("Leaving refused().");
}

function certAt(file) {
  log.debug("Entering certAt().");
  log.debug("Leaving certAt().");
  return K.pemChain(fs.readFileSync(file, "utf8"))[0];
}

function sha256Of(file) {
  log.debug("Entering sha256Of().");
  log.debug("Leaving sha256Of().");
  return nodeCrypto.createHash("sha256").update(fs.readFileSync(file))
    .digest("hex");
}

function pemBody(pem, label) {
  log.debug("Entering pemBody().");
  const m = String(pem).match(new RegExp("-----BEGIN " + label +
    "-----([\\s\\S]+?)-----END " + label + "-----"));
  log.debug("Leaving pemBody().");
  return m ? Buffer.from(m[1].replace(/\s+/g, ""), "base64") : null;
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving " + K.base + " with certmonger in the trust realm \"" +
           REALM + "\".");
  work = K.scratch("certmonger");
  state = { dir: path.join(work, "state"), sock: path.join(work, "cm.sock"),
            pid: path.join(work, "cm.pid"), log: path.join(work, "cm.log") };
  const bundle = await K.trustBundle(work);

  // -------------------------------------------------------------------------
  log.info("=== 0. two realms, a person with a password, the daemon ===");
  await K.makeRealm(REALM, "certmonger job");
  await K.makeRealm(REALM_B, "certmonger job B");
  const password = await K.makePerson(REALM, ERIN, ERIN + "@example.test");
  await K.setting(REALM, "scep.attemptsPerAddress", 100000);
  // Every job of the suite reaches the portal from ONE address, and the
  // portal's challenge form counts successes too (five a minute by
  // default): run after the sscep and certmonger jobs it met 429,
  // STS-HTTP-0018. The limit is this realm's to raise.
  await K.setting(REALM, "pki.personSelfServicePerAddress", 10000);
  const first = await challenge(REALM, ERIN);
  const url = first.plainUrl;
  const org = (first.hint.match(/\\nO=([^\\]+)\\n/) || [])[1];
  const country = (first.hint.match(/\\nC=([A-Z]{2})\\n/) || [])[1];
  assert.ok(org, "the hint names no organisation: " + first.hint);
  const subject = "CN=" + ERIN + ",O=" + org + (country ? ",C=" + country : "");
  const intermediate = await K.realmIntermediate(REALM);
  await startDaemon();
  const version = await K.run("certmonger", ["-v"], {});
  log.info("  " + version.output.trim());

  // -------------------------------------------------------------------------
  log.info("=== 1. add-scep-ca: GetCACaps and GetCACert ===");
  let mark = logSize();
  const added = await getcert(["add-scep-ca", "-c", "STS", "-u", url],
                              "add-scep-ca");
  const ca = await waitForCa("STS");
  C.check("add-scep-ca fetches the capabilities, the RA and the Issuing CA",
          function () {
    assert.strictEqual(added.status, 0, added.shown);
    assert.ok(ca, "certmonger kept no CA record for STS");
    ["POSTPKIOperation", "SHA-256", "AES", "Renewal"].forEach(function (c) {
      assert.ok(ca.ca_capabilities.split(",").indexOf(c) >= 0,
                c + " not in " + ca.ca_capabilities);
    });
    const ra = K.pemChain(ca.ca_encryption_cert)[0];
    const issuing = issuingOf(ca);
    assert.ok(/SCEP RA/.test(ra.subject), ra.subject);
    assert.ok(ra.checkIssued(issuing) && ra.verify(issuing.publicKey));
    K.chainsTo([issuing, intermediate], bundle.root);
    assert.deepStrictEqual(problems(logSince(mark)), []);
  });

  // -------------------------------------------------------------------------
  log.info("=== 2. a request with the person's own challenge ===");
  const portal = await K.portalSignIn(REALM, ERIN, password);
  const made = await portal.post({ action: "create-challenge",
                                   profile: "tls-client" });
  const own = (made.text.match(
    /Challenge password<\/th><td><code>([^<]+)<\/code>/) || [])[1];
  assert.ok(own, "/portal/certificates made no challenge");
  secrets.push(own);
  const key = path.join(work, "erin.key");
  const cert = path.join(work, "erin.pem");
  mark = logSize();
  const requested = await getcert(["request", "-c", "STS", "-k", key,
    "-f", cert, "-N", subject, "-L", own, "-I", "erin", "-w",
    "--wait-timeout", "120"], "getcert request");
  const erin = await listed("erin");
  const leaf = fs.existsSync(cert) ? certAt(cert) : null;
  C.check("getcert request enrolls: MONITORING, the realm's certificate " +
          "for the entry, chained to the Root (STS-SCEP-0011 before #249)",
          function () {
    assert.strictEqual(requested.status, 0, requested.shown);
    assert.strictEqual(erin.status, "MONITORING", JSON.stringify(erin));
    assert.ok(leaf, "no certificate was written");
    K.chainsTo([leaf, issuingOf(ca), intermediate], bundle.root);
    assert.ok(String(leaf.subjectAltName)
                .indexOf("URI:urn:sts:person:" + ERIN) >= 0,
              leaf.subjectAltName);
    assert.deepStrictEqual(leaf.keyUsage, [EKU.clientAuth]);
    assert.ok(leaf.subject.indexOf("CN=" + ERIN) >= 0, leaf.subject);
    assert.deepStrictEqual(problems(logSince(mark)), []);
  });

  // -------------------------------------------------------------------------
  log.info("=== 3. CertPoll, with the message the daemon stored ===");
  const req = recordOf("request", "erin");
  assert.ok(req && req.scep_gic, "the request record holds no " +
            "GetCertInitial message");
  const issuingPem = issuingOf(ca).toString();
  const polled = await K.run(SCEP_SUBMIT, ["-u", url], {
    cwd: work, timeoutMs: 60000,
    env: { CERTMONGER_OPERATION: "POLL",
           CERTMONGER_PKCSREQ: req.scep_gic,
           CERTMONGER_SCEP_RA_CERTIFICATE: ca.ca_encryption_cert,
           CERTMONGER_SCEP_CA_CERTIFICATE: bundle.root.toString(),
           CERTMONGER_SCEP_CERTIFICATES: issuingPem +
             intermediate.toString() } });
  const enveloped = pemBody(polled.stdout, "PKCS7");
  let pollSerial = null;
  if (enveloped) {
    fs.writeFileSync(path.join(work, "poll.der"), enveloped);
    const opened = await K.run("openssl", ["cms", "-decrypt", "-inform",
      "DER", "-in", "poll.der", "-inkey", key, "-binary", "-out",
      "poll.p7"], { cwd: work });
    const certs = await K.run("openssl", ["pkcs7", "-inform", "DER", "-in",
      "poll.p7", "-print_certs"], { cwd: work });
    const got = K.pemChain(certs.stdout);
    pollSerial = got.length && opened.status === 0 ? K.serialOf(got[0])
                                                   : null;
  }
  C.check("scep-submit's CertPoll for that transaction answers the same " +
          "certificate, encrypted to the request's key", function () {
    assert.strictEqual(polled.status, 0, polled.shown);
    assert.strictEqual(pollSerial, K.serialOf(leaf));
  });

  // -------------------------------------------------------------------------
  log.info("=== 4. resubmit (the same key) and rekey (a new one) ===");
  const keyBefore = sha256Of(key);
  mark = logSize();
  const resubmitted = await getcert(["resubmit", "-i", "erin", "-w",
                                     "--wait-timeout", "120"],
                                    "getcert resubmit");
  const second = certAt(cert);
  C.check("getcert resubmit renews with the same key — its transactionID " +
          "repeats, refused STS-SCEP-0037 before #249", function () {
    assert.strictEqual(resubmitted.status, 0, resubmitted.shown);
    assert.notStrictEqual(K.serialOf(second), K.serialOf(leaf));
    assert.strictEqual(sha256Of(key), keyBefore);
    assert.deepStrictEqual(problems(logSince(mark)), []);
  });
  mark = logSize();
  const rekeyed = await getcert(["rekey", "-i", "erin", "-w",
                                 "--wait-timeout", "120"], "getcert rekey");
  const third = certAt(cert);
  C.check("getcert rekey renews with a new key", function () {
    assert.strictEqual(rekeyed.status, 0, rekeyed.shown);
    assert.notStrictEqual(K.serialOf(third), K.serialOf(second));
    assert.notStrictEqual(sha256Of(key), keyBefore);
    assert.strictEqual(third.subject, leaf.subject);
    assert.deepStrictEqual(problems(logSince(mark)), []);
  });
  const crl = await K.crlSerials(REALM, "scep");
  C.check("both renewed certificates are on the SCEP CRL", function () {
    assert.ok(crl.indexOf(K.serialOf(leaf)) >= 0, crl.join(","));
    assert.ok(crl.indexOf(K.serialOf(second)) >= 0, crl.join(","));
    assert.ok(crl.indexOf(K.serialOf(third)) < 0);
  });

  // -------------------------------------------------------------------------
  log.info("=== 5. refusals ===");
  let since = new Date().toISOString();
  mark = logSize();
  await getcert(["request", "-c", "STS", "-k", path.join(work, "r1.key"),
    "-f", path.join(work, "r1.pem"), "-N", subject, "-L", own, "-I",
    "reused", "-w", "--wait-timeout", "60"], "request (reused)");
  await refused("reused", since, mark,
                ["STS-ENROLL-0083", "STS-ENROLL-0084"],
                "the person's spent challenge");

  const raB = (await K.run("sh", ["-c", "curl -s '" +
    url.replace("/realm/" + REALM + "/", "/realm/" + REALM_B + "/") +
    "?operation=GetCACert' | openssl pkcs7 -inform DER -print_certs"],
    { cwd: work })).stdout;
  fs.writeFileSync(path.join(work, "ra-b.pem"),
                   K.pemChain(raB)[0].toString());
  assert.ok(/SCEP RA/.test(K.pemChain(raB)[0].subject));
  const wrong = await challenge(REALM, ERIN);
  await getcert(["add-scep-ca", "-c", "WRONG", "-u", url, "-r",
                 path.join(work, "ra-b.pem")], "add-scep-ca (WRONG)");
  await waitForCa("WRONG");
  since = new Date().toISOString();
  mark = logSize();
  await getcert(["request", "-c", "WRONG", "-k", path.join(work, "r2.key"),
    "-f", path.join(work, "r2.pem"), "-N", subject, "-L", wrong.challenge,
    "-I", "wrong", "-w", "--wait-timeout", "60"], "request (wrong RA)");
  await refused("wrong", since, mark, ["STS-SCEP-0027"],
                "a request enveloped to another realm's RA");

  // The CA record told to use the two algorithms this server refuses:
  // `scep_cipher` and `scep_digest` are certmonger's own fields, read when
  // the daemon starts, which is the one way to make it send them.
  const weak = await challenge(REALM, ERIN);
  const caFile = recordOf("ca", "STS").file;
  const pristine = fs.readFileSync(caFile, "utf8");
  const cases = [["scep_cipher=DES3", "STS-SCEP-0029", "DES-EDE3"],
                 ["scep_digest=SHA1", "STS-SCEP-0020", "SHA-1"]];
  for (let i = 0; i < cases.length; i += 1) {
    await stopDaemon();
    fs.writeFileSync(caFile, pristine.replace(/\n?$/, "\n") +
                     cases[i][0] + "\n");
    await startDaemon();
    since = new Date().toISOString();
    mark = logSize();
    const id = "weak" + i;
    await getcert(["request", "-c", "STS", "-k",
      path.join(work, id + ".key"), "-f", path.join(work, id + ".pem"),
      "-N", subject, "-L", weak.challenge, "-I", id, "-w",
      "--wait-timeout", "60"], "request (" + cases[i][2] + ")");
    await refused(id, since, mark, [cases[i][1]],
                  cases[i][2] + " (badAlg)");
  }
  await stopDaemon();
  fs.writeFileSync(caFile, pristine);
  await startDaemon();
  mark = logSize();
  const after = await getcert(["request", "-c", "STS", "-k",
    path.join(work, "after.key"), "-f", path.join(work, "after.pem"),
    "-N", subject, "-L", weak.challenge, "-I", "after", "-w",
    "--wait-timeout", "120"], "request (after)");
  C.check("the challenge the algorithm refusals carried still enrolls",
          function () {
    assert.strictEqual(after.status, 0, after.shown);
    assert.ok(certAt(path.join(work, "after.pem")));
    assert.deepStrictEqual(problems(logSince(mark)), []);
  });

  // -------------------------------------------------------------------------
  log.info("=== 6. HTTPS ===");
  const tls = await challenge(REALM, ERIN);
  await getcert(["add-scep-ca", "-c", "TLS", "-u", tls.url, "-R",
                 bundle.file], "add-scep-ca (https)");
  const tlsCa = await waitForCa("TLS");
  mark = logSize();
  await getcert(["request", "-c", "TLS", "-k", path.join(work, "t.key"),
    "-f", path.join(work, "t.pem"), "-N", subject, "-L", tls.challenge,
    "-I", "tls", "-w", "--wait-timeout", "60"], "request (https)");
  const overTls = await listed("tls");
  C.check("over HTTPS certmonger fetches the CA with -R, and its " +
          "PKIOperation fails curl error 60: scep-submit sends that " +
          "request with no CA file (the documented exception)", function () {
    assert.ok(tlsCa && /AES/.test(tlsCa.ca_capabilities || ""),
              "the CA was not fetched over TLS");
    assert.strictEqual(overTls.status, "CA_UNREACHABLE",
                       JSON.stringify(overTls));
    assert.ok(/^Error 60 connecting to https:/.test(overTls["ca-error"]),
              overTls["ca-error"]);
    const bad = problems(logSince(mark)).filter(function (line) {
      return !/Error 60 connecting to https:/.test(line);
    });
    assert.deepStrictEqual(bad, [], bad.join("\n"));
  });
  await getcert(["stop-tracking", "-i", "tls"], "stop-tracking tls");
  await stopDaemon();

  assert.ok(C.count >= 12,
    "only " + C.count + " checks ran; a section has stopped being called.");
  log.info(C.count + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_scep_certmonger")
  .description("certmonger's daemon and scep-submit against the SCEP " +
      "server over the plain-HTTP listener: add-scep-ca, request, CertPoll, " +
      "resubmit, rekey, the refusals, and HTTPS.")
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(async function (e) {
  log.error((e.stack || e.message) +
            (e.cause ? "\ncaused by: " + (e.cause.stack || e.cause) : ""));
  if (state && fs.existsSync(state.log)) {
    log.error("certmonger's log:\n" + logSince(0).slice(-4000));
  }
  await stopDaemon();
  process.exit(1);
});
