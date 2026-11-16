// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_listener_tls_policy.js
//
// ---------------------------------------------------------------------------
// THE LISTENERS' TLS POLICY AND CLIENT AUTHENTICATION, READ OFF REAL
// HANDSHAKES WITH THE RUNNING SERVICE (#423, #429, #507).
//
// D12 (#444): carries over tests/listener_tls_policy.js's claims about the
// main port and a realm's own listener. Every claim is a handshake made by
// node's TLS client (OpenSSL 3.5, so the ML-KEM groups are offered) and an
// HTTP request over it, after a setting changed at runtime through
// `POST /admin-api/config/set` — the door the console writes through:
//
//   A. the defaults: TLS 1.2 refused (on by default since #429), TLS 1.3
//      with each of the three default suites accepted, CCM refused; a
//      CertificateRequest sent (a certificate the client offers arrives,
//      `GET /admin-api/tls-connection` reports it presented) and a client
//      with none admitted;
//   B. tls.disableTls12 off: TLS 1.2 accepted; on again, refused;
//   C. tls.tls13CipherSuites: a suite not chosen refused, a chosen one —
//      CCM included — accepted; an empty list refused (400, STS-TLS-0043 on
//      the audit);
//   D. tls.pqcOnly: TLS 1.2, AES-128 and a classical group refused, AES-256
//      with X25519MLKEM768 accepted; on with no 256-bit suite chosen
//      refused (STS-TLS-0043);
//   E. the main port's two toggles: no CertificateRequest (an offered
//      certificate never arrives), and a certificate required — refused
//      without one and with a stranger's, admitted with one chaining to a
//      Root added through `POST /admin-api/tls/trust/add`;
//   F. a realm's own listener (`listeners.realm`, port
//      STS_TEST_REALM_LISTENER_PORT, mapped to nothing, so a handshake is
//      "admitted" when the listener answers HTTP at all): its own
//      tls.disableTls12 `off` admitting TLS 1.2 there while the main port
//      refuses it, and
//      `inherit` refusing it again; its own pqcOnly with no 256-bit suite
//      refused at the write (STS-TLS-0043);
//   L. RFC 6066 section 3: a TLS 1.2 session ID made under `localhost` is
//      not resumed under another name or no name, and still is under its
//      own (L5c); a TLS 1.2 ticket resumed under another name is closed
//      unanswered (L5d, #507); a TLS 1.3 ticket is resumed under another
//      name (L5e).
//
// What stays in process (class (d)): a TLS 1.3 name in tls.ciphers and an
// unreadable anchors file stopping the service (I, STS-TLS-0042 and -0045:
// start-up refusals no running service can be asked for), the applier
// handed each new policy (H, an in-process hook), and the per-listener
// session cache sizes and lifetimes (L1-L6 but L5c-e), which no client can
// read off a handshake. LDAPS's CertificateRequest (G) is the directory's,
// in its own job. Section L needs `openssl` on the PATH (the tests image
// has it): node's client never offers a session under another name.
//
// Every setting here is process-wide, so each is put back with `reset` in a
// `finally`, pass or fail, and the Root E adds is removed by fingerprint
// (#335). The realm and its listener are the job's own; the listener is
// removed again so the port is free for the next job.
//
// Its realms are removed at the end only under STS_TEST_REMOVE_REALMS=1
// (a hand run on a shared probe); the suite leaves them standing.
//
// OWNED HERE (local: true): this repository's own listeners and management
// API.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const tls = require("tls");
const forge = require("node-forge");
const names = require("./random_username.js");
const credentials = require("../tools/pep-credential.js");

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
var log = bunyan.createLogger({ name: "sts_listener_tls_policy",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const TARGET = new URL(base);
const HOST = TARGET.hostname;
const MAIN_PORT = Number(TARGET.port || 443);
const REALM_PORT = Number(process.env.STS_TEST_REALM_LISTENER_PORT || 8099);
const STAMP = names.runStamp();
const REALM = ("tlsp-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
  .slice(0, 31);
const LISTENER = "tlsp" + STAMP.toLowerCase().replace(/[^a-z0-9]/g, "")
  .slice(-8);
const DEFAULT_SUITES = ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256",
                        "TLS_CHACHA20_POLY1305_SHA256"];
const TOUCHED = ["tls.disableTls12", "tls.tls13CipherSuites", "tls.pqcOnly",
                 "tls.mainPortDisableOptionalClientCertificate",
                 "tls.mainPortRequireClientCertificate"];

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

// A self-signed client certificate nothing trusts: a "stranger's".
function stranger() {
  log.debug("Entering stranger().");
  const pair = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = pair.publicKey;
  cert.serialNumber = "0" + crypto.randomBytes(8).toString("hex");
  cert.validity.notBefore = new Date(Date.now() - 60000);
  cert.validity.notAfter = new Date(Date.now() + 3600000);
  const subject = [{ name: "commonName", value: "stranger-" + STAMP }];
  cert.setSubject(subject);
  cert.setIssuer(subject);
  cert.setExtensions([{ name: "extKeyUsage", clientAuth: true }]);
  cert.sign(pair.privateKey, forge.md.sha256.create());
  log.debug("Leaving stranger().");
  return { cert: forge.pki.certificateToPem(cert),
           key: forge.pki.privateKeyToPem(pair.privateKey) };
}

// ONE HANDSHAKE AND ONE HTTP/1.1 REQUEST OVER IT. `o`: port, version
// ('1.2' or '1.3'), ciphers (node's list, TLS 1.3 suite names included),
// groups, cert and key, servername ('' for none), session (to resume),
// noTicket, path and token. Resolves { accepted, status, body, protocol,
// cipher, reused, session, error } and never rejects.
function probe(o) {
  log.debug("Entering probe().");
  log.debug("Leaving probe().");
  return new Promise(function (resolve) {
    const options = {
      host: HOST, port: o.port || MAIN_PORT, rejectUnauthorized: false,
      ALPNProtocols: ["http/1.1"], cert: o.cert, key: o.key,
      session: o.session
    };
    if (o.servername !== "") {
      options.servername = o.servername || HOST;
    }
    if (o.version === "1.2") {
      options.minVersion = "TLSv1.2";
      options.maxVersion = "TLSv1.2";
    } else if (o.version === "1.3") {
      options.minVersion = "TLSv1.3";
      options.maxVersion = "TLSv1.3";
    }
    if (o.ciphers) {
      options.ciphers = o.ciphers;
    }
    if (o.groups) {
      options.ecdhCurve = o.groups;
    }
    if (o.noTicket) {
      options.secureOptions = crypto.constants.SSL_OP_NO_TICKET;
    }
    const out = { accepted: false, status: 0, body: "", session: null };
    let socket;
    let text = "";
    let settled = false;
    const finish = function () {
      if (settled) {
        return;
      }
      settled = true;
      const m = /^HTTP\/1\.1 (\d{3})/.exec(text);
      out.status = m ? Number(m[1]) : 0;
      out.accepted = out.status === 200;
      // Any HTTP answer at all: the handshake completed and the listener
      // read a request, whatever its router made of the path.
      out.answered = out.status > 0;
      out.body = text.split("\r\n\r\n").slice(1).join("\r\n\r\n");
      resolve(out);
    };
    try {
      socket = tls.connect(options, function () {
        out.protocol = socket.getProtocol();
        out.cipher = (socket.getCipher() || {}).standardName;
        out.reused = socket.isSessionReused();
        const headers = "Host: " + TARGET.host + "\r\nConnection: close\r\n" +
          "Accept: application/json\r\n" +
          (o.token ? "Authorization: Bearer " + o.token + "\r\n" : "");
        socket.write("GET " + (o.path || "/.well-known/openid-configuration") +
                     " HTTP/1.1\r\n" + headers + "\r\n");
      });
    } catch (e) {
      log.debug("Caught in probe(): " + ((e && e.message) || e));
      // An option this client cannot offer at all is a refused probe.
      out.error = e;
      finish();
      return;
    }
    socket.on("session", function (s) {
      out.session = s;
    });
    socket.on("data", function (c) {
      text += c.toString("utf8");
    });
    socket.setTimeout(15000, function () {
      socket.destroy();
    });
    socket.on("error", function (e) {
      log.debug("probe socket error: " + ((e && e.message) || e));
      out.error = e;
    });
    socket.on("close", finish);
  });
}

async function api(method, path, payload, tlsOptions) {
  log.debug("Entering api(). " + method + " " + path);
  const body = payload === undefined ? "" : JSON.stringify(payload);
  const out = await new Promise(function (resolve, reject) {
    const req = require("https").request({
      method: method, hostname: HOST, port: MAIN_PORT, path: path,
      agent: false, rejectUnauthorized: false,
      cert: tlsOptions && tlsOptions.cert, key: tlsOptions && tlsOptions.key,
      headers: { "content-type": "application/json",
                 accept: "application/json",
                 "content-length": Buffer.byteLength(body) }
    }, function (res) {
      const chunks = [];
      res.on("data", function (c) {
        chunks.push(c);
      });
      res.on("end", function () {
        const raw = Buffer.concat(chunks).toString("utf8");
        let json = null;
        try {
          json = JSON.parse(raw);
        } catch (e) {
          log.debug("Caught in api(): " + ((e && e.message) || e));
          // Not JSON; the caller reads `raw`.
          json = null;
        }
        resolve({ status: res.statusCode, body: json, raw: raw });
      });
    });
    req.on("error", reject);
    req.end(body);
  });
  log.debug("Leaving api(). " + out.status);
  return out;
}

async function setSetting(key, value, tlsOptions) {
  log.debug("Entering setSetting(). " + key);
  const r = await api("POST", "/admin-api/config/set",
                      { key: key, value: value }, tlsOptions);
  log.debug("Leaving setSetting(). " + r.status);
  return r;
}

async function mustSet(key, value) {
  log.debug("Entering mustSet(). " + key);
  const r = await setSetting(key, value);
  assert.strictEqual(r.status, 200, "config/set " + key + "=" +
                     JSON.stringify(value) + ": " + r.raw.slice(0, 300));
  // Applied at the next handshake; the applier runs on the write's turn.
  await sleep(200);
  log.debug("Leaving mustSet().");
}

async function resetSetting(key, tlsOptions) {
  log.debug("Entering resetSetting(). " + key);
  const r = await api("POST", "/admin-api/config/reset", { key: key },
                      tlsOptions);
  if (r.status !== 200 && !/no runtime override/.test(r.raw)) {
    log.warn("config/reset " + key + " answered " + r.status + " " +
             r.raw.slice(0, 200));
  }
  await sleep(100);
  log.debug("Leaving resetSetting().");
  return r;
}

async function auditCount(prefix, code) {
  log.debug("Entering auditCount(). " + code);
  const r = await api("GET", prefix + "/admin-api/audit?per=500&code=" +
                      encodeURIComponent(code));
  const rows = (r.body && (r.body.events || r.body.rows)) || [];
  log.debug("Leaving auditCount(). " + rows.length);
  return rows.length;
}

async function sawCode(prefix, code, before) {
  log.debug("Entering sawCode(). " + code);
  for (let i = 0; i < 30; i += 1) {
    if (await auditCount(prefix, code) > before) {
      log.debug("Leaving sawCode(). Seen.");
      return true;
    }
    await sleep(200);
  }
  log.debug("Leaving sawCode(). Not seen.");
  return false;
}

// Whether a certificate the client offered arrived: the management API's
// description of this very connection, asked over it.
async function presented(cert) {
  log.debug("Entering presented().");
  const r = await probe({ path: "/admin-api/tls-connection",
                          cert: cert.cert, key: cert.key,
                          token: process.env.STS_ADMIN_API_TOKEN });
  assert.strictEqual(r.status, 200, "GET /admin-api/tls-connection: " +
                     r.status + " " + r.body.slice(0, 200));
  const view = JSON.parse(r.body);
  log.debug("Leaving presented().");
  return view.clientCertificate || {};
}

function why(r) {
  log.debug("Entering why().");
  log.debug("Leaving why().");
  return "status " + r.status + " " + (r.protocol || "") + " " +
    (r.cipher || "") + " " + String((r.error && r.error.message) || "");
}

async function sectionsAtoD() {
  log.debug("Entering sectionsAtoD().");
  log.info("=== A. the defaults ===");
  for (const key of TOUCHED) {
    await resetSetting(key);
  }
  const t12 = await probe({ version: "1.2" });
  check("A1. TLS 1.2 is refused untouched (tls.disableTls12 is on by " +
        "default)", function () {
    assert.strictEqual(t12.accepted, false, why(t12));
  });
  for (const suite of DEFAULT_SUITES) {
    const r = await probe({ version: "1.3", ciphers: suite });
    check("A2. TLS 1.3 with " + suite + " is accepted", function () {
      assert.ok(r.accepted, why(r));
      assert.strictEqual(r.cipher, suite);
    });
  }
  const ccm = await probe({ version: "1.3",
                           ciphers: "TLS_AES_128_CCM_SHA256" });
  check("A3. CCM is refused by default", function () {
    assert.strictEqual(ccm.accepted, false, why(ccm));
  });
  const bare = await probe({});
  const offered = await presented(stranger());
  check("A4. a client with no certificate is admitted, and one offered is " +
        "presented: the main port sends a CertificateRequest", function () {
    assert.ok(bare.accepted, why(bare));
    assert.strictEqual(offered.presented, true, JSON.stringify(offered));
    // The handshake's own verdict (#37): `verified` also holds revocation.
    assert.strictEqual(offered.handshakeVerified, false,
                       JSON.stringify(offered));
  });

  log.info("=== B. tls.disableTls12 ===");
  await mustSet("tls.disableTls12", false);
  const t12on = await probe({ version: "1.2" });
  const t13still = await probe({ version: "1.3" });
  await mustSet("tls.disableTls12", true);
  const t12off = await probe({ version: "1.2" });
  check("B. off, TLS 1.2 is accepted (and TLS 1.3 still); on again, " +
        "refused", function () {
    assert.ok(t12on.accepted && t12on.protocol === "TLSv1.2", why(t12on));
    assert.ok(t13still.accepted, why(t13still));
    assert.strictEqual(t12off.accepted, false, why(t12off));
  });

  log.info("=== C. tls.tls13CipherSuites ===");
  await mustSet("tls.tls13CipherSuites",
                "TLS_AES_256_GCM_SHA384,TLS_AES_128_CCM_SHA256");
  const notChosen = await probe({ version: "1.3",
                                  ciphers: "TLS_AES_128_GCM_SHA256" });
  const chosen = await probe({ version: "1.3",
                               ciphers: "TLS_AES_256_GCM_SHA384" });
  const ccmChosen = await probe({ version: "1.3",
                                  ciphers: "TLS_AES_128_CCM_SHA256" });
  check("C. a suite not chosen is refused, and the chosen ones — CCM " +
        "included — are accepted", function () {
    assert.strictEqual(notChosen.accepted, false, why(notChosen));
    assert.ok(chosen.accepted, why(chosen));
    assert.ok(ccmChosen.accepted &&
              ccmChosen.cipher === "TLS_AES_128_CCM_SHA256", why(ccmChosen));
  });
  const before43 = await auditCount("", "STS-TLS-0043");
  const empty = await setSetting("tls.tls13CipherSuites", "");
  const saw43 = await sawCode("", "STS-TLS-0043", before43);
  check("C. an empty list is refused at the write, recorded STS-TLS-0043",
        function () {
    assert.strictEqual(empty.status, 400, empty.raw.slice(0, 300));
    assert.ok(saw43, "no STS-TLS-0043 row after an empty suite list");
  });
  const afterEmpty = await probe({ version: "1.3",
                                   ciphers: "TLS_AES_256_GCM_SHA384" });
  check("C. and the listener still holds the list before it", function () {
    assert.ok(afterEmpty.accepted, why(afterEmpty));
  });
  await resetSetting("tls.tls13CipherSuites");

  log.info("=== D. tls.pqcOnly ===");
  await mustSet("tls.disableTls12", false);
  await mustSet("tls.pqcOnly", true);
  const pq12 = await probe({ version: "1.2" });
  const pq128 = await probe({ version: "1.3",
                              ciphers: "TLS_AES_128_GCM_SHA256",
                              groups: "X25519MLKEM768" });
  const pqClassical = await probe({ version: "1.3",
                                    ciphers: "TLS_AES_256_GCM_SHA384",
                                    groups: "X25519:P-256" });
  const pqGood = await probe({ version: "1.3",
                               ciphers: "TLS_AES_256_GCM_SHA384",
                               groups: "X25519MLKEM768" });
  check("D. post-quantum only refuses TLS 1.2, AES-128 and a classical " +
        "group, and accepts AES-256 with X25519MLKEM768", function () {
    assert.strictEqual(pq12.accepted, false, why(pq12));
    assert.strictEqual(pq128.accepted, false, why(pq128));
    assert.strictEqual(pqClassical.accepted, false, why(pqClassical));
    assert.ok(pqGood.accepted, why(pqGood));
  });
  await resetSetting("tls.pqcOnly");
  await resetSetting("tls.disableTls12");
  await mustSet("tls.tls13CipherSuites", "TLS_AES_128_GCM_SHA256");
  const before43b = await auditCount("", "STS-TLS-0043");
  const pqNoSuite = await setSetting("tls.pqcOnly", true);
  const saw43b = await sawCode("", "STS-TLS-0043", before43b);
  check("D. post-quantum only with no 256-bit suite chosen is refused at " +
        "the write, STS-TLS-0043", function () {
    assert.strictEqual(pqNoSuite.status, 400, pqNoSuite.raw.slice(0, 300));
    assert.ok(saw43b, "no STS-TLS-0043 row for pqcOnly without a suite");
  });
  await resetSetting("tls.pqcOnly");
  await resetSetting("tls.tls13CipherSuites");
  log.debug("Leaving sectionsAtoD().");
}

async function sectionE() {
  log.debug("Entering sectionE().");
  log.info("=== E. the main port's client certificate toggles ===");
  await mustSet("tls.mainPortDisableOptionalClientCertificate", true);
  const notAsked = await presented(stranger());
  check("E1. with no CertificateRequest an offered certificate never " +
        "arrives", function () {
    assert.strictEqual(notAsked.presented, false, JSON.stringify(notAsked));
  });
  await resetSetting("tls.mainPortDisableOptionalClientCertificate");

  const cred = await credentials.mint({
    subject: "CN=tls-policy-" + STAMP + ",O=iya-sts tests" });
  const own = { cert: cred.certPem, key: cred.keyPem };
  try {
    const added = await credentials.trustRecorded(base, cred.anchorPem, []);
    assert.ok(added && added.ok !== false, "tls/trust/add refused the " +
              "job's Root: " + JSON.stringify(added).slice(0, 300));
    // The anchor reaches the handshake truststore on the node's next pull.
    // What is asked is the HANDSHAKE's verdict, `handshakeVerified` (#37,
    // 2026-11-15): `verified` also holds the revocation verdict since then,
    // which a stack consulting revocation can refuse for this job's leaf.
    let verified = {};
    for (let i = 0; i < 40 && verified.handshakeVerified !== true; i += 1) {
      verified = await presented(own);
      if (verified.handshakeVerified !== true) {
        await sleep(500);
      }
    }
    assert.strictEqual(verified.handshakeVerified, true,
                       JSON.stringify(verified));
    await mustSet("tls.mainPortRequireClientCertificate", true);
    const none = await probe({});
    const strangers = await probe(stranger());
    const mine = await probe(own);
    check("E2. a certificate required: refused without one and with a " +
          "stranger's, admitted with one chaining to the truststore",
          function () {
      assert.strictEqual(none.accepted, false, why(none));
      assert.strictEqual(strangers.accepted, false, why(strangers));
      assert.ok(mine.accepted, why(mine));
    });
  } finally {
    // The reset needs the certificate the port now requires.
    await resetSetting("tls.mainPortRequireClientCertificate", own);
    await credentials.removeAnchor(base, cred.anchorPem);
  }
  log.debug("Leaving sectionE().");
}

async function sectionF() {
  log.debug("Entering sectionF().");
  log.info("=== F. a realm's own listener on " + REALM_PORT + " ===");
  const made = await api("POST", "/admin-api/realms/create",
    { id: REALM, domain: REALM + ".example.net", name: "TLS policy " + STAMP });
  assert.strictEqual(made.status, 200, made.raw.slice(0, 300));
  const realmApi = "/realm/" + REALM + "/admin-api";
  const ownBase = "https://" + HOST + ":" + REALM_PORT;
  const define = function (tlsBlock) {
    return api("POST", realmApi + "/listeners/set-listeners",
      { value: [{ id: LISTENER, port: REALM_PORT, publicBaseUrl: ownBase,
                  tls: tlsBlock }] });
  };
  try {
    const set = await define({ disableTls12: "off" });
    assert.strictEqual(set.status, 200, set.raw.slice(0, 400));
    let there = { answered: false };
    const path = "/realm/" + REALM + "/.well-known/openid-configuration";
    for (let i = 0; i < 40 && !there.answered; i += 1) {
      there = await probe({ port: REALM_PORT, version: "1.2", path: path });
      if (!there.answered) {
        await sleep(500);
      }
    }
    const mainStill = await probe({ version: "1.2" });
    check("F. the realm listener's own tls.disableTls12 off admits TLS " +
          "1.2 there while the main port, inheriting, refuses it",
          function () {
      assert.ok(there.answered && there.protocol === "TLSv1.2", why(there));
      assert.strictEqual(mainStill.accepted, false, why(mainStill));
    });
    const inherit = await define({ disableTls12: "inherit" });
    assert.strictEqual(inherit.status, 200, inherit.raw.slice(0, 400));
    let back = { answered: true };
    for (let i = 0; i < 40 && back.answered; i += 1) {
      await sleep(250);
      back = await probe({ port: REALM_PORT, version: "1.2", path: path });
    }
    const t13 = await probe({ port: REALM_PORT, version: "1.3", path: path });
    check("F. `inherit` takes the service's again: TLS 1.2 refused there, " +
          "TLS 1.3 answered", function () {
      assert.strictEqual(back.answered, false, why(back));
      assert.ok(t13.answered, why(t13));
    });
    const before43 = await auditCount("/realm/" + REALM, "STS-TLS-0043");
    const pqBad = await define({ pqcOnly: "on",
                                 tls13CipherSuites: "TLS_AES_128_GCM_SHA256" });
    const saw = await sawCode("/realm/" + REALM, "STS-TLS-0043", before43);
    check("F. the listener's own pqcOnly with no 256-bit suite is refused " +
          "at the write, STS-TLS-0043", function () {
      assert.strictEqual(pqBad.status, 400, pqBad.raw.slice(0, 300));
      assert.ok(saw, "no STS-TLS-0043 row on the realm's audit");
    });
  } finally {
    const cleared = await api("POST", realmApi + "/listeners/set-listeners",
                              { value: [] });
    if (cleared.status !== 200) {
      log.warn("Could not remove the realm listener: " +
               cleared.raw.slice(0, 200));
    }
  }
  log.debug("Leaving sectionF().");
}

// ONE HANDSHAKE BY OPENSSL'S OWN CLIENT, for section L: node's client will
// not offer a session under a server name other than the one it was made
// under (measured against a server that ignores the name), so only
// `s_client -sess_in` can ask the service whether IT refuses one. `o`:
// version, servername ('' for none), sessIn, sessOut, noTicket.
function sClient(o) {
  log.debug("Entering sClient().");
  const args = ["s_client", "-connect", HOST + ":" + MAIN_PORT, "-ign_eof"];
  if (o.servername === "") {
    args.push("-noservername");
  } else {
    args.push("-servername", o.servername || HOST);
  }
  args.push(o.version === "1.2" ? "-tls1_2" : "-tls1_3");
  if (o.sessOut) {
    args.push("-sess_out", o.sessOut);
  }
  if (o.sessIn) {
    args.push("-sess_in", o.sessIn);
  }
  if (o.noTicket) {
    args.push("-no_ticket");
  }
  log.debug("Leaving sClient().");
  return new Promise(function (resolve) {
    const proc = require("child_process").spawn("openssl", args);
    let text = "";
    proc.stdout.on("data", function (d) {
      text += d;
    });
    proc.stderr.on("data", function (d) {
      text += d;
    });
    proc.on("error", function (e) {
      text += "spawn failed: " + e.message;
    });
    const timer = setTimeout(function () {
      proc.kill("SIGKILL");
    }, 20000);
    proc.on("close", function () {
      clearTimeout(timer);
      resolve({ text: text, accepted: /HTTP\/1\.1 200/.test(text),
                reused: /^Reused,/m.test(text) });
    });
    // A TLS 1.3 ticket arrives after the handshake: give it a moment
    // before the request, so -sess_out writes the session with it.
    setTimeout(function () {
      proc.stdin.write("GET /.well-known/openid-configuration HTTP/1.0" +
                       "\r\nHost: " + TARGET.host + "\r\n\r\n");
      proc.stdin.end();
    }, 500);
  });
}

function tail(r) {
  log.debug("Entering tail().");
  log.debug("Leaving tail().");
  return r.text.replace(/\s+/g, " ").slice(-240);
}

async function sectionL() {
  log.debug("Entering sectionL().");
  log.info("=== L. a session resumed only under its own name ===");
  const dir = require("fs").mkdtempSync(require("path").join(
    require("os").tmpdir(), "tls-policy-"));
  const file = function (name) {
    return require("path").join(dir, name + ".pem");
  };
  await mustSet("tls.disableTls12", false);
  try {
    const made = await sClient({ version: "1.2", noTicket: true,
                                 sessOut: file("l5c") });
    const other = await sClient({ version: "1.2", noTicket: true,
                                  sessIn: file("l5c"),
                                  servername: "other.localhost" });
    const none = await sClient({ version: "1.2", noTicket: true,
                                 sessIn: file("l5c"), servername: "" });
    const own = await sClient({ version: "1.2", noTicket: true,
                                sessIn: file("l5c") });
    check("L5c. a TLS 1.2 session ID made under one name is not resumed " +
          "under another or under none (RFC 6066 section 3: a full " +
          "handshake each time), and still is under its own", function () {
      assert.ok(made.accepted, tail(made));
      assert.ok(other.accepted && !other.reused, tail(other));
      assert.ok(none.accepted && !none.reused, tail(none));
      assert.ok(own.accepted && own.reused, tail(own));
    });
    const tkMade = await sClient({ version: "1.2", sessOut: file("l5d") });
    const tkOther = await sClient({ version: "1.2", sessIn: file("l5d"),
                                    servername: "other.localhost" });
    const tkOwn = await sClient({ version: "1.2", sessIn: file("l5d") });
    check("L5d. a TLS 1.2 ticket made under one name and resumed under " +
          "another is closed unanswered (#507), and resumed and answered " +
          "under its own", function () {
      assert.ok(tkMade.accepted && !tkMade.reused, tail(tkMade));
      assert.ok(tkOther.reused && !tkOther.accepted, tail(tkOther));
      assert.ok(tkOwn.reused && tkOwn.accepted, tail(tkOwn));
    });
  } finally {
    await resetSetting("tls.disableTls12");
  }
  await sClient({ version: "1.3", sessOut: file("l5e") });
  const t13Other = await sClient({ version: "1.3", sessIn: file("l5e"),
                                   servername: "other.localhost" });
  check("L5e. a TLS 1.3 ticket is resumed and answered under another name " +
        "(RFC 8446 section 4.2.11 leaves that to the client)", function () {
    assert.ok(t13Other.reused && t13Other.accepted, tail(t13Other));
  });
  require("fs").rmSync(dir, { recursive: true, force: true });
  log.debug("Leaving sectionL().");
}

async function test() {
  log.debug("Entering test().");
  assert.ok(base.indexOf("https:") === 0,
            "the main port is HTTPS in every appconfig; " + base + " is not");
  try {
    await sectionsAtoD();
    await sectionE();
    await sectionL();
    await sectionF();
  } finally {
    for (const key of TOUCHED) {
      await resetSetting(key);
    }
  }
  log.info("sts_listener_tls_policy: " + checks + " checks passed.");
  log.debug("Leaving test().");
}

// THE REALMS THIS JOB MADE, REMOVED AT ITS END ONLY WHEN ASKED
// (STS_TEST_REMOVE_REALMS=1, a hand run against a probe that many jobs
// share and whose directory would otherwise fill). The suite does not ask:
// no job removes a realm on a shared run (tests/CLAUDE.md).
async function removeRealms() {
  log.debug("Entering removeRealms().");
  if (process.env.STS_TEST_REMOVE_REALMS !== "1") {
    log.debug("Leaving removeRealms(). Not asked.");
    return;
  }
  for (const id of [REALM]) {
    try {
      const r = await fetch(base + "/admin-api/realms/remove", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: id }) });
      log.info("removed the realm " + id + ": " + r.status);
    } catch (e) {
      log.debug("Caught in removeRealms(): " + ((e && e.message) || e));
      // A realm left behind is litter, not a failure of what was tested.
      log.warn("could not remove the realm " + id);
    }
  }
  log.debug("Leaving removeRealms().");
}

test().finally(removeRealms).then(function () {
  log.info("Test completed successfully.");
}).catch(function (e) {
  log.error("sts_listener_tls_policy FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
