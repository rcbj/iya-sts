// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_kerberos_pkinit.js
//
// ---------------------------------------------------------------------------
// A CERTIFICATE AS THE KERBEROS PRE-AUTHENTICATION, OVER TCP 88, WITH REAL
// MIT KINIT (#179, 2026-10-05).
//
// #173 refuses, in product, an AS-REQ that proved only a password for a
// person who holds or owes a second factor. A person with an authenticator
// app has FAST and OTP; a person whose second factor is a SMART CARD had no
// way to a ticket at all until PKINIT. This job is the protocol half of
// `tests/kerberos_pkinit.js` (which holds the KDF vectors, the codec, what
// the KDC writes INTO a TGT and every refusal with a client of its own) and
// asserts, against the service's published KDC, in order:
//
//   1. GET /admin-api/kerberos says PKINIT is on, anonymous PKINIT is on and
//      the RFC 8070 freshness token is required (rule 7: the console's
//      status block is the API's `status`);
//   2. two people made through /admin-api, P and Q, each ENROL a smart-card
//      logon certificate over EST (RFC 7030) with their own password — the
//      key and the PKCS#10 request made here with `openssl` at run time —
//      and the EST /cacerts chain gives the service Root (MIT's
//      pkinit_anchors) and the issuing chain (its pkinit_pool);
//   3. with `krb5_wire.js`: the bare AS-REQ offers PA-PK-AS-REQ and
//      PA-PKINIT-KX; a second factor is then REQUIRED of P (require-mfa),
//      after which P's right password alone is KDC_ERR_POLICY in product and
//      a TGT in development, and Q's password is a TGT in both;
//   4. and, where MIT Kerberos and its PKINIT plugin are installed on the
//      machine running the job:
//        * `kinit -X X509_user_identity=FILE:cert,key` for P gets a TGT, and
//          `klist -f` shows it initial, pre-authenticated and HARDWARE
//          authenticated (H): a smart-card logon certificate over a key this
//          service never held is what `pkinit-hardware` means;
//        * P's password alone with `kinit` — refused in product with
//          KDC_ERR_POLICY as the first error the KDC sent after the method
//          list (read from KRB5_TRACE), a TGT in development. THIS PAIR IS
//          THE POINT OF #179: the certificate gets the person whom the
//          password cannot;
//        * Q's certificate offered for P is KDC_ERR_CLIENT_NAME_MISMATCH,
//          and the same certificate for Q is a TGT — the refusal is the
//          binding, not the certificate;
//        * `kinit -n` gets an anonymous TGT
//          (WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS, flag a), and
//          `kinit -T <that ccache>` gets Q a TGT on the password INSIDE FAST
//          armored by it (RFC 8062's reason for existing).
//      Without MIT Kerberos, or without its PKINIT plugin, that section says
//      so and is skipped.
//
// WHY MIT READS THE TRACE: `kinit`'s own message is the LAST error, after
// whatever fallback it tried (a password prompt on a closed stdin, for one),
// and the decision this job asserts is the KDC's FIRST answer to the
// pre-authentication. KRB5_TRACE goes to a real FILE per command, because
// the trace on stderr interleaves with kinit's own lines.
//
// WHAT IT CHANGES: two people, a second-factor requirement on one of them,
// and two certificates recorded on their entries. No setting is read and
// changed. KEY MATERIAL is made at run time in a temporary directory removed
// in a `finally`; nothing is read from the repository.
//
// WHERE IT DIALS: the KDC at the service URL's host and `krb5.kdcPort`, or
// STS_KDC_HOST / STS_KDC_PORT (sts_kerberos_spnego.js's convention).
//
// OWNED HERE (local: true): this repository's KDC, EST server and API.
// ---------------------------------------------------------------------------

const assert = require("assert");
const childProcess = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");
const nodeCrypto = require("crypto");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");
const facts = require("./service_facts.js");
const wire = require("./krb5_wire.js");
const est = require("./est_client.js");
const { declineToRun } = require("./expectation.js");

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
var log = bunyan.createLogger({ name: "sts_kerberos_pkinit",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const apiBase = base + "/admin-api";
const EST = base + "/.well-known/est";

const P = usernameFor("krb5-pkinit");
const Q = usernameFor("krb5-pkother");
const PASSWORD = "Krb5-Pkinit-Passw0rd!-" + String(Date.now()).slice(-6);

// PADATA types (RFC 4556 section 3.2.1, RFC 8062 section 7).
const PA_PK_AS_REQ = 16;
const PA_PKINIT_KX = 147;

// MIT's com_err numbers for the KDC errors this job reads out of a trace:
// KRB5KDC_ERR_NONE (-1765328384) plus the RFC 4120 / RFC 4556 code.
const MIT_ERR = {
  PREAUTH_REQUIRED: -1765328384 + 25,
  POLICY: -1765328384 + 12,
  CLIENT_NAME_MISMATCH: -1765328384 + 75
};

// Where Debian and Ubuntu's krb5-pkinit puts the plugin, by architecture.
const PKINIT_PLUGIN_DIRS = ["/usr/lib/x86_64-linux-gnu",
                            "/usr/lib/aarch64-linux-gnu", "/usr/lib64",
                            "/usr/lib"];

const K = { product: false, realm: "", kdcHost: "", kdcPort: 88,
            password: "" };

// How long a product person's keys may take to appear after the password is
// set (sts_kerberos_spnego.js argues the number).
const KEYS_WAIT_MS = 20000;

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

// ---------------------------------------------------------------------------
// THE ADMIN API.
// ---------------------------------------------------------------------------
async function apiCall(method, pathName, body) {
  log.debug("Entering apiCall(). " + method + " " + pathName);
  const options = { method: method,
                    headers: { Accept: "application/json" } };
  if (body !== undefined) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }
  const r = await fetch(apiBase + pathName, options);
  const raw = await r.text();
  let parsed = null;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in apiCall(): " + ((e && e.message) || e));
    parsed = raw;
  }
  log.debug("Leaving apiCall(). " + r.status);
  return { status: r.status, body: parsed, raw: raw };
}

async function apiOk(pathName, body, what) {
  log.debug("Entering apiOk(). " + pathName);
  const r = await apiCall("POST", pathName, body);
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
            "POST /admin-api" + pathName + " should have " + what + "; it " +
            "answered " + r.status + " " + String(r.raw).slice(0, 300));
  log.debug("Leaving apiOk().");
  return r.body;
}

async function ensurePerson(who) {
  log.debug("Entering ensurePerson(). " + who);
  // The mail is what the smart-card logon profile writes as the UPN.
  await apiOk("/users/create", {
    username: who, invent: false, credential: "password", password: PASSWORD,
    attributes: { cn: "PKINIT " + who, givenName: "PKINIT", sn: who,
                  displayName: "PKINIT " + who,
                  mail: who + "@pkinit.test" } }, "created " + who);
  log.debug("Leaving ensurePerson().");
}

// ---------------------------------------------------------------------------
// WHAT THE SERVICE IS.
// ---------------------------------------------------------------------------
async function learnTheService() {
  log.debug("Entering learnTheService().");
  K.product = await facts.isProduct(apiBase);
  K.realm = String(process.env.KRB5_REALM ||
                   await facts.setting(apiBase, "krb5.realm") || "");
  K.kdcHost = process.env.STS_KDC_HOST || new URL(base).hostname;
  K.kdcPort = Number(process.env.STS_KDC_PORT ||
                     await facts.setting(apiBase, "krb5.kdcPort") || 88);
  // Product keys a person from their own password; development keys every
  // user account from one shared password (kerberos/CLAUDE.md).
  K.password = K.product ? PASSWORD
    : String(await facts.setting(apiBase, "krb5.userPassword") ||
             "password!");
  log.info("mode " + (K.product ? "product" : "development") + ", realm " +
           K.realm + ", KDC " + K.kdcHost + ":" + K.kdcPort);
  log.debug("Leaving learnTheService().");
}

async function theStatusSaysSo() {
  log.debug("Entering theStatusSaysSo().");
  log.info("=== 1. GET /admin-api/kerberos: the PKINIT status ===");
  const r = await apiCall("GET", "/kerberos");
  const pkinit = r.body && r.body.status && r.body.status.pkinit;
  check("GET /admin-api/kerberos carries status.pkinit: PKINIT on, " +
        "anonymous PKINIT on, the freshness token required", function () {
          assert.strictEqual(r.status, 200, String(r.raw).slice(0, 300));
          assert.ok(pkinit, "no status.pkinit: " +
                    JSON.stringify(r.body && r.body.status).slice(0, 400));
          assert.strictEqual(pkinit.pkinit, true, JSON.stringify(pkinit));
          assert.strictEqual(pkinit.anonymousPkinit, true,
                             JSON.stringify(pkinit));
          assert.strictEqual(pkinit.freshnessRequired, true,
                             JSON.stringify(pkinit));
        });
  check("and names the two indicators and no RSA key transport",
        function () {
          assert.deepStrictEqual(pkinit.indicators,
                                 ["pkinit", "pkinit-hardware"]);
          assert.ok(/not implemented/.test(String(pkinit.rsaKeyTransport)),
                    pkinit.rsaKeyTransport);
        });
  log.debug("Leaving theStatusSaysSo().");
}

// ---------------------------------------------------------------------------
// A CHILD PROCESS, ASYNCHRONOUSLY (sts_kerberos_heimdal.js's lesson: a
// synchronous spawn blocks the loop while the service closes keep-alives),
// with its stdin CLOSED so a `kinit` that falls back to a password prompt
// fails rather than waits.
// ---------------------------------------------------------------------------
function run(tool, args, opts) {
  log.debug("Entering run(). " + tool + " " + args.join(" "));
  const options = opts || {};
  return new Promise(function (resolve, reject) {
    const child = childProcess.spawn(tool, args, {
      env: Object.assign({}, process.env, options.env || {}) });
    let out = "";
    const timer = setTimeout(function () {
      child.kill("SIGKILL");
    }, 60000);
    child.stdout.on("data", function (b) {
      out += b.toString();
    });
    child.stderr.on("data", function (b) {
      out += b.toString();
    });
    child.on("error", function (e) {
      clearTimeout(timer);
      reject(new Error(tool + " could not be run: " + e.message));
    });
    child.on("close", function (code) {
      clearTimeout(timer);
      log.debug("Leaving run(). " + tool + " exit " + code);
      resolve({ status: code, out: out });
    });
    // A tool that exits without reading its input makes this write EPIPE;
    // what it did is judged by its exit code and output, not by that.
    child.stdin.on("error", function (e) {
      log.debug("Caught in run(): " + tool + "'s stdin: " +
                ((e && e.message) || e));
    });
    child.stdin.end(options.input || "");
  });
}

function onPath(tool) {
  log.debug("Entering onPath(). " + tool);
  const r = childProcess.spawnSync("sh", ["-c", "command -v " + tool],
                                   { encoding: "utf8" });
  log.debug("Leaving onPath().");
  return r.status === 0 && (r.stdout || "").indexOf(tool) !== -1;
}

function pkinitPlugin() {
  log.debug("Entering pkinitPlugin().");
  const found = PKINIT_PLUGIN_DIRS.map(function (dir) {
    return path.join(dir, "krb5", "plugins", "preauth", "pkinit.so");
  }).filter(function (file) {
    return fs.existsSync(file);
  })[0] || "";
  log.debug("Leaving pkinitPlugin(). " + (found || "none"));
  return found;
}

// ---------------------------------------------------------------------------
// 2. THE CERTIFICATES, OVER EST.
// ---------------------------------------------------------------------------

// A P-256 key and a PKCS#10 request over it, made by `openssl` in `dir`.
// The subject is only a label: EST builds the certificate's names from the
// ENTRY (common/cert_enrollment.ts), never from the request.
async function keyAndRequest(dir, who) {
  log.debug("Entering keyAndRequest(). " + who);
  const keyFile = path.join(dir, who + ".key.pem");
  const csrFile = path.join(dir, who + ".csr.der");
  const r = await run("openssl", ["req", "-new", "-newkey", "ec",
    "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
    "-keyout", keyFile, "-outform", "DER", "-out", csrFile,
    "-subj", "/CN=" + who]);
  assert.strictEqual(r.status, 0, "openssl req for " + who + ": " + r.out);
  fs.chmodSync(keyFile, 0o600);
  log.debug("Leaving keyAndRequest().");
  return { keyFile: keyFile, csr: fs.readFileSync(csrFile) };
}

async function theChain(dir) {
  log.debug("Entering theChain().");
  const ca = await est.send({ method: "GET", url: EST + "/cacerts" });
  let chain = [];
  check("EST /cacerts answers the issuing chain: the EST Issuing CA, the " +
        "realm Intermediate and the self-signed service Root", function () {
          assert.strictEqual(ca.status, 200,
                             Buffer.from(ca.body || "").toString().slice(0,
                                                                         300));
          chain = est.parseCertsOnly(est.base64Body(ca.body)).certificates;
          assert.strictEqual(chain.length, 3, "certificates: " + chain.length);
          const x = chain.map(function (pem) {
            return new nodeCrypto.X509Certificate(pem);
          });
          assert.ok(x[0].verify(x[1].publicKey) &&
                    x[1].verify(x[2].publicKey) &&
                    x[2].verify(x[2].publicKey), "not a path to a Root");
        });
  const anchors = path.join(dir, "root.pem");
  const pool = path.join(dir, "pool.pem");
  fs.writeFileSync(anchors, chain[2]);
  fs.writeFileSync(pool, chain[0] + chain[1]);
  log.debug("Leaving theChain().");
  return { anchors: anchors, pool: pool,
           issuing: new nodeCrypto.X509Certificate(chain[0]) };
}

async function enrol(dir, who, chain) {
  log.debug("Entering enrol(). " + who);
  const made = await keyAndRequest(dir, who);
  const r = await est.send({
    method: "POST", url: EST + "/smartcard-logon/simpleenroll",
    body: est.requestBody(made.csr),
    headers: { "Content-Type": "application/pkcs10" },
    basic: [who, PASSWORD] });
  let pem = "";
  check(who + " enrols a SMART-CARD LOGON certificate over EST with their " +
        "own password: issued by the EST Issuing CA, naming them, with " +
        "id-ms-kp-sc-logon, over the key made here", function () {
          assert.strictEqual(r.status, 200, "simpleenroll answered " +
                             r.status + " " + Buffer.from(r.body || "")
                               .toString().slice(0, 300));
          pem = est.parseCertsOnly(est.base64Body(r.body)).certificates[0];
          const cert = new nodeCrypto.X509Certificate(pem);
          assert.ok(cert.verify(chain.issuing.publicKey),
                    "not signed by the EST Issuing CA");
          assert.ok(String(cert.subjectAltName)
                      .indexOf("urn:sts:person:" + who) !== -1,
                    cert.subjectAltName);
          assert.ok((cert.keyUsage || []).indexOf("1.3.6.1.4.1.311.20.2.2") !==
                    -1, JSON.stringify(cert.keyUsage));
          const mine = nodeCrypto.createPublicKey(
            nodeCrypto.createPrivateKey(fs.readFileSync(made.keyFile)));
          assert.ok(cert.publicKey.export({ type: "spki", format: "der" })
                      .equals(mine.export({ type: "spki", format: "der" })),
                    "the certificate is not over the key sent");
        });
  const certFile = path.join(dir, who + ".cert.pem");
  fs.writeFileSync(certFile, pem);
  log.debug("Leaving enrol().");
  return { certFile: certFile, keyFile: made.keyFile };
}

// ---------------------------------------------------------------------------
// 3. THE PASSWORD, WITH THIS SUITE'S OWN CLIENT.
// ---------------------------------------------------------------------------

// The AS exchange for a person, waiting out product mode's derivation window
// (only the refusals that window produces are retried) — fast_otp's.
async function asForPerson(tcp, who, password) {
  log.debug("Entering asForPerson(). " + who);
  const started = Date.now();
  for (;;) {
    const r = await wire.asExchange(tcp, K.realm, who,
                                    { password: password });
    const e = (r.second && r.second.error) || (r.first && r.first.error);
    if (!(K.product && !r.tgt && e &&
          /no Kerberos keys yet|sign in once|nobody by that name/i
            .test(e.eText) && Date.now() - started < KEYS_WAIT_MS)) {
      log.debug("Leaving asForPerson().");
      return r;
    }
    await pause(500);
  }
}

async function passwordAlone(tcp) {
  log.debug("Entering passwordAlone().");
  log.info("=== 3. the password, before and after a second factor is " +
           "required ===");
  const before = await asForPerson(tcp, P, K.password);
  check("the bare AS-REQ's method list offers PA-PK-AS-REQ and " +
        "PA-PKINIT-KX", function () {
          assert.ok(before.offered.indexOf(PA_PK_AS_REQ) !== -1 &&
                    before.offered.indexOf(PA_PKINIT_KX) !== -1,
                    "offered " + before.offered);
        });
  check(P + "'s password gets a TGT while nothing more is required of them",
        function () {
          assert.ok(before.tgt, JSON.stringify(before.second ||
                                               before.first).slice(0, 300));
        });
  await apiOk("/users/require-mfa", { user: P },
              "required a second factor of " + P);
  const after = await asForPerson(tcp, P, K.password);
  if (K.product) {
    check("PRODUCT: with a second factor required, " + P + "'s right " +
          "password alone is KDC_ERR_POLICY (12)", function () {
            assert.ok(!after.tgt, "a TGT was issued on a password alone");
            const e = (after.second || after.first).error;
            assert.strictEqual(e.code, 12, e.toString());
          });
  } else {
    check("DEVELOPMENT: " + P + "'s password alone still gets a TGT, as " +
          "every password does", function () {
            assert.ok(after.tgt, JSON.stringify(after.second ||
                                                after.first).slice(0, 300));
          });
  }
  const q = await asForPerson(tcp, Q, K.password);
  check(Q + ", of whom nothing more is required, gets a TGT on the " +
        "password", function () {
          assert.ok(q.tgt, JSON.stringify(q.second || q.first).slice(0, 300));
        });
  log.debug("Leaving passwordAlone().");
}

// ---------------------------------------------------------------------------
// 4. REAL MIT KERBEROS, WHERE IT AND ITS PKINIT PLUGIN ARE INSTALLED.
// ---------------------------------------------------------------------------
const M = { dir: "", conf: "", n: 0 };

function writeConf(chain) {
  log.debug("Entering writeConf().");
  M.conf = path.join(M.dir, "krb5.conf");
  fs.writeFileSync(M.conf, "[libdefaults]\n default_realm = " + K.realm +
    "\n dns_lookup_kdc = false\n dns_lookup_realm = false\n" +
    " udp_preference_limit = 1\n rdns = false\n\n[realms]\n " + K.realm +
    " = {\n  kdc = " + K.kdcHost + ":" + K.kdcPort +
    "\n  pkinit_anchors = FILE:" + chain.anchors +
    "\n  pkinit_pool = FILE:" + chain.pool + "\n }\n");
  log.debug("Leaving writeConf().");
}

// One MIT command with this run's krb5.conf, its own ccache and its own
// trace file. Answers the result and the trace's text.
async function mit(tool, args, opts) {
  log.debug("Entering mit(). " + tool);
  const options = opts || {};
  M.n += 1;
  const trace = path.join(M.dir, "trace-" + M.n + ".log");
  const r = await run(tool, args, { input: options.input, env: {
    KRB5_CONFIG: M.conf, KRB5_TRACE: trace,
    KRB5CCNAME: options.cache || "FILE:" + path.join(M.dir, "cc") } });
  let traced = "";
  try {
    traced = fs.readFileSync(trace, "utf8");
  } catch (e) {
    // A tool that failed before initialising the library writes no trace;
    // the assertion that reads it then says what was missing.
    log.debug("Caught in mit(): " + ((e && e.message) || e));
    traced = "";
  }
  log.debug("Leaving mit(). exit " + r.status);
  return { status: r.status, out: r.out, trace: traced };
}

// Every KDC error in a trace, in order, as { code, text }.
function kdcErrors(trace) {
  log.debug("Entering kdcErrors().");
  const out = [];
  const re = /Received error from KDC: (-?\d+)\/([^\n]*)/g;
  let m = re.exec(trace);
  while (m) {
    out.push({ code: Number(m[1]), text: m[2].trim() });
    m = re.exec(trace);
  }
  log.debug("Leaving kdcErrors(). " + out.length);
  return out;
}

// The first error after the method list: the KDC's answer to what the
// client actually proved.
function firstDecision(result) {
  log.debug("Entering firstDecision().");
  const found = kdcErrors(result.trace).filter(function (one) {
    return one.code !== MIT_ERR.PREAUTH_REQUIRED;
  })[0] || null;
  log.debug("Leaving firstDecision().");
  return found;
}

// `klist -f` of a ccache: the default principal and the krbtgt's flags.
async function listed(cache) {
  log.debug("Entering listed().");
  const r = await mit("klist", ["-f", "-c", cache]);
  const lines = r.out.split("\n");
  let flags = "";
  lines.forEach(function (line, i) {
    if (/\skrbtgt\//.test(line) && !flags) {
      const next = String(lines[i + 1] || "").match(/Flags:\s*(\S*)/);
      flags = next ? next[1] : "";
    }
  });
  const principal = (r.out.match(/Default principal:\s*(\S+)/) || [])[1] ||
                    "";
  log.debug("Leaving listed(). " + principal + " " + flags);
  return { status: r.status, out: r.out, principal: principal,
           flags: flags };
}

function shown(result) {
  log.debug("Entering shown().");
  log.debug("Leaving shown().");
  return result.out.slice(0, 400) + "\n--- first KDC errors: " +
         JSON.stringify(kdcErrors(result.trace).slice(0, 4));
}

async function withMitKinit(certs, chain) {
  log.debug("Entering withMitKinit().");
  log.info("=== 4. MIT kinit: PKINIT, the password, anonymous armor ===");
  const plugin = pkinitPlugin();
  if (process.env.STS_KRB5_MIT === "off" || !onPath("kinit") ||
      !onPath("klist") || !plugin) {
    log.info("  MIT Kerberos (kinit, klist) or its PKINIT plugin " +
             "(krb5-pkinit: krb5/plugins/preauth/pkinit.so) is not " +
             "installed on this machine, so this section is SKIPPED; " +
             "tests/kerberos_pkinit.js drives PKINIT in process with a " +
             "client of its own.");
    log.debug("Leaving withMitKinit(). Skipped.");
    return false;
  }
  log.info("  MIT's PKINIT plugin: " + plugin);
  writeConf(chain);
  const principalP = P + "@" + K.realm;
  const principalQ = Q + "@" + K.realm;
  const identity = function (who) {
    log.debug("Entering identity().");
    log.debug("Leaving identity().");
    return "X509_user_identity=FILE:" + certs[who].certFile + "," +
           certs[who].keyFile;
  };

  const ccP = "FILE:" + path.join(M.dir, "cc-p");
  const pk = await mit("kinit", ["-X", identity(P), "-c", ccP, principalP]);
  check("MIT: kinit -X X509_user_identity=FILE:<cert>,<key> " + principalP +
        " gets a TGT", function () {
          assert.strictEqual(pk.status, 0, shown(pk));
        });
  const pkList = await listed(ccP);
  check("klist -f: the TGT is " + principalP + "'s, flags I (initial), " +
        "A (pre-authenticated) and H (hardware-authenticated: a smart-card " +
        "logon certificate over a key this service never held)",
        function () {
          assert.strictEqual(pkList.principal, principalP, pkList.out);
          ["I", "A", "H"].forEach(function (flag) {
            assert.ok(pkList.flags.indexOf(flag) !== -1,
                      "flag " + flag + " missing: " + pkList.out);
          });
        });

  const pw = await mit("kinit", ["-c", "FILE:" + path.join(M.dir, "cc-pw"),
                                 principalP], { input: K.password + "\n" });
  if (K.product) {
    const decided = firstDecision(pw);
    check("MIT, PRODUCT: kinit " + principalP + " with the password alone " +
          "is refused, the KDC's first decision KDC_ERR_POLICY (" +
          MIT_ERR.POLICY + "/KDC policy rejects request) — the certificate " +
          "above got the person the password cannot", function () {
            assert.notStrictEqual(pw.status, 0, shown(pw));
            assert.ok(decided, "no KDC error in the trace: " + shown(pw));
            assert.strictEqual(decided.code, MIT_ERR.POLICY, shown(pw));
            assert.ok(/KDC policy rejects request/.test(decided.text),
                      decided.text);
          });
  } else {
    check("MIT, DEVELOPMENT: kinit " + principalP + " with the password " +
          "alone succeeds", function () {
            assert.strictEqual(pw.status, 0, shown(pw));
          });
  }

  const wrong = await mit("kinit", ["-X", identity(Q), "-c",
                                    "FILE:" + path.join(M.dir, "cc-wrong"),
                                    principalP]);
  const mismatch = firstDecision(wrong);
  check("MIT: " + Q + "'s certificate offered for " + principalP + " is " +
        "refused, the KDC's first decision KDC_ERR_CLIENT_NAME_MISMATCH (" +
        MIT_ERR.CLIENT_NAME_MISMATCH + "/Client name mismatch)",
        function () {
          assert.notStrictEqual(wrong.status, 0, shown(wrong));
          assert.ok(mismatch, "no KDC error in the trace: " + shown(wrong));
          assert.strictEqual(mismatch.code, MIT_ERR.CLIENT_NAME_MISMATCH,
                             shown(wrong));
          assert.ok(/Client name mismatch/.test(mismatch.text),
                    mismatch.text);
        });
  const ccQ = "FILE:" + path.join(M.dir, "cc-q");
  const own = await mit("kinit", ["-X", identity(Q), "-c", ccQ, principalQ]);
  const ownList = own.status === 0 ? await listed(ccQ) : null;
  check("and the same certificate for " + principalQ + " is a TGT — the " +
        "refusal was the binding, not the certificate", function () {
          assert.strictEqual(own.status, 0, shown(own));
          assert.strictEqual(ownList.principal, principalQ, ownList.out);
        });

  const armor = "FILE:" + path.join(M.dir, "armor");
  const anon = await mit("kinit", ["-n", "-c", armor, "@" + K.realm]);
  const anonList = anon.status === 0 ? await listed(armor) : null;
  check("MIT: kinit -n @" + K.realm + " gets an anonymous TGT " +
        "(WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS, flag a) — RFC 8062",
        function () {
          assert.strictEqual(anon.status, 0, shown(anon));
          assert.strictEqual(anonList.principal,
                             "WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS",
                             anonList.out);
          assert.ok(anonList.flags.indexOf("a") !== -1, anonList.out);
        });
  const ccFast = "FILE:" + path.join(M.dir, "cc-fast");
  const fast = await mit("kinit", ["-T", armor, "-c", ccFast, principalQ],
                         { input: K.password + "\n" });
  const fastList = fast.status === 0 ? await listed(ccFast) : null;
  check("MIT: kinit -T <the anonymous ccache> " + principalQ + " gets a TGT " +
        "on the password INSIDE FAST armored by it", function () {
          assert.strictEqual(fast.status, 0, shown(fast));
          assert.strictEqual(fastList.principal, principalQ, fastList.out);
          assert.ok(/FAST|armor/i.test(fast.trace),
                    "the trace shows no FAST armor: " + shown(fast));
        });
  log.debug("Leaving withMitKinit().");
  return true;
}

async function test() {
  log.debug("Entering test().");
  if (String(process.env.STS_TEST_UNPUBLISHED || "").split(",")
        .indexOf("kerberos") >= 0) {
    declineToRun(log, "this environment does not publish the KDC's TCP 88 " +
                      "(STS_TEST_UNPUBLISHED names kerberos).");
    log.debug("Leaving test(). Skipped.");
    return;
  }
  if (!onPath("openssl")) {
    declineToRun(log, "openssl is not installed here, and this job makes " +
                      "its keys and certificate requests with it.");
    log.debug("Leaving test(). Skipped.");
    return;
  }
  log.info("Driving Kerberos PKINIT at " + base);
  await learnTheService();
  await theStatusSaysSo();
  M.dir = fs.mkdtempSync(path.join(os.tmpdir(), "krb5-pkinit-"));
  let mitRan = false;
  try {
    log.info("=== 2. two people, and a smart-card logon certificate each " +
             "over EST ===");
    await ensurePerson(P);
    await ensurePerson(Q);
    const chain = await theChain(M.dir);
    // BEFORE require-mfa: in product a second-factor person's own password
    // is refused at EST's Basic door (#101), so the enrolment comes first,
    // as a person enrolling their card before the requirement would.
    const certs = {};
    certs[P] = await enrol(M.dir, P, chain);
    certs[Q] = await enrol(M.dir, Q, chain);
    const tcp = wire.tcpTransport(K.kdcHost, K.kdcPort);
    await passwordAlone(tcp);
    mitRan = await withMitKinit(certs, chain);
  } finally {
    try {
      fs.rmSync(M.dir, { recursive: true, force: true });
    } catch (e) {
      log.debug("Caught in test(): " + ((e && e.message) || e));
    }
  }
  const floor = mitRan ? 16 : 9;
  assert.ok(checks >= floor, "only " + checks + " checks ran (floor " +
            floor + "); a section has stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_kerberos_pkinit")
  .description("Kerberos PKINIT (RFC 4556, RFC 8070, RFC 8636) over TCP 88 " +
    "with MIT kinit: a smart-card logon certificate enrolled over EST gets " +
    "a hardware-authenticated TGT for a person whose password alone is " +
    "refused in product, another person's certificate is a client name " +
    "mismatch, and anonymous PKINIT (RFC 8062) armors FAST.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
