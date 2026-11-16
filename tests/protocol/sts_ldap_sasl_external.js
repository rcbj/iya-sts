// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_ldap_sasl_external.js
//
// ---------------------------------------------------------------------------
// SASL EXTERNAL OVER LDAPS, AGAINST A RUNNING SERVICE (D12, #444; #1047).
//
// A SASL EXTERNAL bind (RFC 4513 section 5.2.1.2) binds the connection as
// the person entry named by the `urn:sts:person:` subjectAltName of a TLS
// client certificate this realm issued, and it is available exactly when
// 636 asks for a certificate. `tests/ldap_sasl_external.js` holds it in
// child processes of its own; this asks the service's real listener, with
// certificates the people issued themselves on the portal
// (`generate-tls-client`), and reads each refusal's code off the realm's
// audit log. ldapjs's client sends only simple binds, so the SASL bind is
// written as BER by hand and every answer read with node-ldapjs's own
// parser, as the in-process file does.
//
//   C. THE DEFAULTS: 636 asks for nothing, so a certificate the client holds
//      is never sent, and EXTERNAL is 48 (STS-LDAP-0179).
//   A. OPTIONAL (`ldap.ldapsDisableOptionalClientCertificate` off):
//      A1 alice's certificate binds her with an empty name, with her own
//         `dn:` and `u:` authzId and with her DN as the bind name; a search
//         of her entry answers bound and is refused unbound once the realm
//         is in product mode;
//      A2 refusals, each with its result code and its STS-LDAP code: an
//         authzId naming bob (50, 0189) or in neither form (50, 0189), a
//         bind name naming bob (49, 0190), no certificate (48, 0179), a
//         mechanism other than EXTERNAL (7, 0178), EXTERNAL on 389 (48,
//         0180), an outside authority's certificate trusted through the
//         truststore and stored on no entry (49, 0192), another realm's
//         certificate held to this realm's DN (49, 0184) while it binds in
//         its own, a person with no entry (49, 0187), a disabled person (49,
//         0188), a revoked certificate (49, 0181);
//      A2b the outside certificate STORED on frank's entry binds as frank,
//         with his `u:` authzId and not alice's (50, 0189); a renewed one
//         with the same subject is refused until stored (49, 0192), and one
//         stored on two entries is refused (49, 0193).
//   B. REQUIRED (`ldap.ldapsRequireClientCertificate` on): a handshake
//      without a certificate is refused, and alice's binds.
//
// What stays in process (class d): which connection `boundConnections()`
// lists (A1's second check; a search of the entry stands in for it), an
// application's certificate (A2's 0185: no door issues an application a TLS
// client certificate), and A3, the dispatched-operation shape.
//
// TWO SETTINGS OF THE PROCESS ARE CHANGED AND PUT BACK, IN A finally: the
// two LDAPS client-certificate toggles are per-process, and so is the
// client truststore the two outside authorities are added to and removed
// from by fingerprint (tests/CLAUDE.md's anchor rule). While the job runs,
// 636 asks every handshake for a certificate; `sts_ldaps.js` asserts it
// does not, so the two must not run at once (the main lane is serial).
//
// OWNED HERE (local: true). The realms are left behind unless
// STS_TEST_REMOVE_REALMS=1 asks for removal.
// ---------------------------------------------------------------------------
const assert = require("assert");
const crypto = require("crypto");
const childProcess = require("child_process");
const fs = require("fs");
const net = require("net");
const os = require("os");
const path = require("path");
const tls = require("tls");
const { Command, Option } = require("commander");
const { BerWriter } = require("@ldapjs/asn1");
const ldapMessages = require("@ldapjs/messages");
const ldapFilters = require("@ldapjs/filter");
const { Parser } = require("ldapjs/lib/messages");
const names = require("./random_username.js");
const portal = require("./portal_signin.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // No appconfig file: the log level falls back to info, and the reason is
  // reported once the logger exists.
  appconfigProblem = e.message;
  appconfig = {};
}
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_ldap_sasl_external",
  level: appconfig.logLevel || appconfig.LOG_LEVEL ||
         process.env.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("No appconfig file was read: " + appconfigProblem);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");
const HOST = new URL(base).hostname;
const LDAPS_PORT = Number(process.env.STS_LDAPS_URL
  ? new URL(process.env.STS_LDAPS_URL).port
  : (process.env.STS_LDAPS_PORT || 636));
const LDAP_PORT = Number(process.env.STS_LDAP_URL
  ? new URL(process.env.STS_LDAP_URL).port
  : (process.env.STS_LDAP_PORT || 389));

const STAMP = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "")
  .slice(-12);
const REALM = "lse" + STAMP;
const OTHER_REALM = "lso" + STAMP;
const PASSWORD = "Lse-" + crypto.randomBytes(9).toString("base64url") +
                 "-Aa1!";
const WHO = { alice: "lse-alice-" + STAMP, bob: "lse-bob-" + STAMP,
              carol: "lse-carol-" + STAMP, dave: "lse-dave-" + STAMP,
              frank: "lse-frank-" + STAMP };
const FLOOR = 30;

// REMOVAL IS OPT-IN (STS_TEST_REMOVE_REALMS=1): tests/CLAUDE.md's *No job
// removes a realm* is the rule for a shared run; a hand run against a
// private service asks for its realms to go.
const MADE_REALMS = [];

let checks = 0;
function check(what, fn) {
  log.debug("Entering check(). " + what);
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

async function call(method, url, body) {
  log.debug("Entering call(). " + method + " " + url);
  const r = await fetch(url, { method: method, redirect: "manual",
    headers: { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
    // Not JSON; `text` carries it into the message.
    json = null;
  }
  log.debug("Leaving call(). " + r.status);
  return { status: r.status, json: json, text: text };
}

async function ok(url, body, what) {
  log.debug("Entering ok().");
  const r = await call("POST", url, body);
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
            what + ": " + r.status + " " + r.text.slice(0, 400));
  log.debug("Leaving ok().");
  return r.json;
}

function api(realm) {
  log.debug("Entering api().");
  log.debug("Leaving api().");
  return base + (realm ? "/realm/" + realm : "") + "/admin-api";
}

async function codeCount(realm, code) {
  log.debug("Entering codeCount(). " + code);
  const r = await call("GET", api(realm) + "/audit?per=500&code=" +
                       encodeURIComponent(code));
  assert.strictEqual(r.status, 200, "GET audit answered " + r.status);
  log.debug("Leaving codeCount().");
  return ((r.json && r.json.events) || []).length;
}

async function codeAdded(realm, code, before) {
  log.debug("Entering codeAdded(). " + code);
  let now = before;
  for (let i = 0; i < 25 && now <= before; i += 1) {
    now = await codeCount(realm, code);
    if (now <= before) {
      await sleep(150);
    }
  }
  log.debug("Leaving codeAdded().");
  return now > before;
}

// ------------------------------------------------- the hand-written client --
// One connection; requests written as BER, answers read with node-ldapjs's
// own Parser and matched by message id.
function connection(socket) {
  log.debug("Entering connection().");
  const parser = new Parser({ log: log });
  const waiting = {};
  const entries = {};
  let closed = null;
  parser.on("message", function (message) {
    const id = message.messageId;
    if (message.type === "SearchResultEntry") {
      (entries[id] = entries[id] || []).push(String(message.objectName));
      return;
    }
    const done = waiting[id];
    delete waiting[id];
    if (done) {
      done({ status: message.status,
             diagnosticMessage: String(message.diagnosticMessage || ""),
             entries: entries[id] || [] });
    }
  });
  parser.on("error", function (e) {
    log.debug("Caught in the client parser: " + ((e && e.message) || e));
  });
  socket.on("data", function (data) {
    parser.write(data);
  });
  const fail = function (why) {
    log.debug("Entering fail(). " + why);
    closed = closed || why;
    Object.keys(waiting).forEach(function (id) {
      const done = waiting[id];
      delete waiting[id];
      done({ closed: closed });
    });
    log.debug("Leaving fail().");
  };
  socket.on("error", function (e) {
    fail("error: " + ((e && e.message) || e));
  });
  socket.on("close", function () {
    fail("closed");
  });
  let next = 1;
  log.debug("Leaving connection().");
  return {
    send: function (build) {
      log.debug("Entering send().");
      const id = next++;
      log.debug("Leaving send().");
      return new Promise(function (resolve) {
        if (closed) {
          resolve({ closed: closed });
          return;
        }
        waiting[id] = resolve;
        const timer = setTimeout(function () {
          if (waiting[id]) {
            delete waiting[id];
            resolve({ closed: "timeout" });
          }
        }, 15000);
        timer.unref();
        socket.write(build(id));
      });
    },
    end: function () {
      log.debug("Entering end().");
      socket.destroy();
      log.debug("Leaving end().");
    }
  };
}

function saslBind(mechanism, credentials, name) {
  log.debug("Entering saslBind(). " + mechanism);
  log.debug("Leaving saslBind().");
  return function (id) {
    const ber = new BerWriter();
    ber.startSequence();
    ber.writeInt(id);
    ber.startSequence(0x60);
    ber.writeInt(3);
    ber.writeString(name || "");
    ber.startSequence(0xa3);
    ber.writeString(mechanism);
    if (credentials !== undefined) {
      ber.writeBuffer(Buffer.from(credentials, "utf8"), 0x04);
    }
    ber.endSequence();
    ber.endSequence();
    ber.endSequence();
    return ber.buffer;
  };
}

function baseSearch(dn) {
  log.debug("Entering baseSearch().");
  log.debug("Leaving baseSearch().");
  return function (id) {
    return new ldapMessages.SearchRequest({
      messageId: id, baseObject: dn, scope: "base",
      filter: new ldapFilters.PresenceFilter({ attribute: "objectClass" }),
      attributes: ["uid"]
    }).toBer().buffer;
  };
}

function ldaps(credential) {
  log.debug("Entering ldaps().");
  const socket = tls.connect(Object.assign({
    host: HOST, port: LDAPS_PORT, servername: HOST,
    // The listener's own certificate is not what any check here is about,
    // and sts_ldaps.js verifies it.
    rejectUnauthorized: false
  }, credential ? { cert: credential.cert, key: credential.key } : {}));
  log.debug("Leaving ldaps().");
  return new Promise(function (resolve) {
    const conn = connection(socket);
    socket.once("secureConnect", function () {
      resolve(conn);
    });
    socket.once("error", function () {
      resolve(conn);
    });
  });
}

function plain() {
  log.debug("Entering plain().");
  const socket = net.connect(LDAP_PORT, HOST);
  log.debug("Leaving plain().");
  return new Promise(function (resolve) {
    const conn = connection(socket);
    socket.once("connect", function () {
      resolve(conn);
    });
    socket.once("error", function () {
      resolve(conn);
    });
  });
}

async function bindOnce(credential, mechanism, authzId, name) {
  log.debug("Entering bindOnce().");
  const conn = await ldaps(credential);
  const answer = await conn.send(saslBind(mechanism, authzId, name));
  log.debug("Leaving bindOnce().");
  return { conn: conn, answer: answer };
}

function brief(answer) {
  log.debug("Entering brief().");
  log.debug("Leaving brief().");
  return JSON.stringify(answer).slice(0, 300);
}

// A refused SASL bind: its result code, and `code` recorded in `realm`.
async function refused(realm, label, credential, status, code, opts) {
  log.debug("Entering refused(). " + label);
  const o = opts || {};
  const before = await codeCount(realm, code);
  const got = await bindOnce(credential, o.mechanism || "EXTERNAL",
                             o.authzId, o.name);
  got.conn.end();
  const seen = await codeAdded(realm, code, before);
  check(label + " is refused with " + status + ", recorded " + code,
        function () {
    assert.strictEqual(got.answer.status, status, brief(got.answer));
    assert.ok(seen, "no new " + code + " row in " + realm);
  });
  log.debug("Leaving refused().");
}

// ------------------------------------------------------------ fixtures ----
async function makeRealm(id) {
  log.debug("Entering makeRealm(). " + id);
  await ok(api("") + "/realms/create",
           { id: id, domain: id + ".example.net",
             name: "D12 SASL EXTERNAL " + STAMP },
           "created the realm " + id);
  MADE_REALMS.push(id);
  // A self-issued certificate per check below, against a limit of five per
  // window.
  await ok(api(id) + "/config/set",
           { key: "pki.personSelfServicePerIdentity", value: 100 },
           "raised the per-identity limit in " + id);
  await ok(api(id) + "/config/set",
           { key: "pki.personSelfServicePerAddress", value: 100 },
           "raised the per-address limit in " + id);
  log.debug("Leaving makeRealm().");
}

async function makePerson(realm, username) {
  log.debug("Entering makePerson(). " + username);
  const made = await ok(api(realm) + "/users/create", {
    username: username, invent: false, credential: "password",
    password: PASSWORD,
    attributes: { cn: "LSE " + username, givenName: "Lse", sn: username,
                  mail: username + "@" + realm + ".example.net" } },
    "created " + username + " in " + realm);
  log.debug("Leaving makePerson().");
  return String(made.dn);
}

function fileText(file) {
  log.debug("Entering fileText().");
  log.debug("Leaving fileText().");
  return Buffer.from(String(file.base64), "base64").toString("utf8");
}

// The person signs in to the portal and issues themselves a TLS client
// certificate: { cert (the chain), key, serial }.
async function selfIssued(realm, username, label) {
  log.debug("Entering selfIssued(). " + username);
  const browser = await portal.signInToThePortal(base + "/realm/" + realm,
    username, null, { password: PASSWORD });
  const r = await browser.act("/portal/signing-key",
    { action: "generate-tls-client", label: label, key_alg: "ec-p256" });
  assert.strictEqual(r.status, 200, String(r.text).slice(0, 400));
  const fresh = r.json.view.fresh;
  log.debug("Leaving selfIssued().");
  return { cert: fileText(fresh.files.chain), key: fileText(fresh.files.key),
           serial: fresh.issued.serialHex, browser: browser };
}

// An outside certificate authority and a leaf it issued, with clientAuth
// and a urn:sts:person: name — everything this service's own would carry
// except the issuer.
function outsideCertificate(dir, person) {
  log.debug("Entering outsideCertificate().");
  const run = function (args) {
    log.debug("Entering run(). " + args[0]);
    const r = childProcess.spawnSync("openssl", args, { cwd: dir,
                                                        encoding: "utf8" });
    if (r.status !== 0) {
      throw new Error("openssl " + args[0] + ": " + r.stderr);
    }
    log.debug("Leaving run().");
  };
  fs.writeFileSync(path.join(dir, "ext.cnf"),
    "[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=keyCertSign,cRLSign\n" +
    "[leaf]\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\n" +
    "extendedKeyUsage=clientAuth\nsubjectAltName=URI:urn:sts:person:" +
    person + "\n");
  run(["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out",
       "ca.key"]);
  run(["req", "-new", "-x509", "-key", "ca.key", "-subj",
       "/CN=Outside Test CA " + STAMP, "-days", "2", "-out", "ca.pem",
       "-extensions", "ca", "-config", "ext.cnf"]);
  run(["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out",
       "leaf.key"]);
  run(["req", "-new", "-key", "leaf.key", "-subj", "/CN=" + person, "-out",
       "leaf.csr", "-config", "ext.cnf"]);
  run(["x509", "-req", "-in", "leaf.csr", "-CA", "ca.pem", "-CAkey",
       "ca.key", "-CAcreateserial", "-days", "1", "-out", "leaf.pem",
       "-extfile", "ext.cnf", "-extensions", "leaf"]);
  log.debug("Leaving outsideCertificate().");
  return {
    caPem: fs.readFileSync(path.join(dir, "ca.pem"), "utf8"),
    cert: fs.readFileSync(path.join(dir, "leaf.pem"), "utf8"),
    key: fs.readFileSync(path.join(dir, "leaf.key"), "utf8")
  };
}

// A person deleted through SCIM, the realm's deprovisioning door. A
// development realm verifies no SCIM credential, but one is required.
async function deletePerson(realm, username) {
  log.debug("Entering deletePerson(). " + username);
  const headers = { Accept: "application/scim+json",
                    Authorization: "Basic " +
                      Buffer.from("lse:anything").toString("base64") };
  const found = await fetch(base + "/realm/" + realm + "/scim/v2/Users?" +
    "filter=" + encodeURIComponent('userName eq "' + username + '"'),
    { headers: headers });
  const body = await found.json();
  const id = ((body && body.Resources) || [])[0] &&
             body.Resources[0].id;
  assert.ok(id, "SCIM found no " + username + ": " +
            JSON.stringify(body).slice(0, 300));
  const gone = await fetch(base + "/realm/" + realm + "/scim/v2/Users/" + id,
                           { method: "DELETE", headers: headers });
  assert.strictEqual(gone.status, 204, "deleting " + username + " answered " +
                     gone.status);
  log.debug("Leaving deletePerson().");
}

// An unbound LDAP modify adding one binary value: development authorizes
// any write. Its result code.
function ldapModifyBinary(dn, type, value) {
  log.debug("Entering ldapModifyBinary(). " + dn);
  const ldapjs = require("ldapjs");
  const client = ldapjs.createClient({
    url: "ldaps://" + HOST + ":" + LDAPS_PORT, reconnect: false,
    timeout: 20000, connectTimeout: 15000,
    tlsOptions: { rejectUnauthorized: false, servername: HOST } });
  client.on("error", function (e) {
    // The modify's callback reports it.
    log.debug("The LDAP client emitted an error: " + e.message);
  });
  log.debug("Leaving ldapModifyBinary().");
  return new Promise(function (resolve) {
    client.modify(dn, new ldapjs.Change({ operation: "add",
      modification: new ldapjs.Attribute({ type: type, values: [value] }) }),
    function (e) {
      const code = e ? e.code : 0;
      client.destroy();
      resolve(code);
    });
  });
}

// ------------------------------------------------------------ settings ----
const TOUCHED = [];

async function setProcess(key, value) {
  log.debug("Entering setProcess(). " + key);
  TOUCHED.push(key);
  await ok(api("") + "/config/set", { key: key, value: value },
           "set " + key + " = " + value);
  // The listener takes a per-process toggle when it is written; a
  // handshake shortly after is the first to see it.
  await sleep(500);
  log.debug("Leaving setProcess().");
}

async function restore() {
  log.debug("Entering restore().");
  for (const key of TOUCHED) {
    const r = await call("POST", api("") + "/config/reset", { key: key });
    log.info("  (reset " + key + ": " + r.status + ")");
  }
  log.debug("Leaving restore().");
}

const ANCHORS = [];

async function addAnchor(pem) {
  log.debug("Entering addAnchor().");
  const fingerprint = new crypto.X509Certificate(pem).fingerprint256;
  ANCHORS.push(fingerprint);
  const r = await call("POST", api("") + "/tls/trust/add",
                       { certificates: pem });
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
            "adding an outside authority answered " + r.status + " " +
            r.text.slice(0, 300));
  log.debug("Leaving addAnchor().");
}

async function removeAnchors() {
  log.debug("Entering removeAnchors().");
  for (const fingerprint of ANCHORS) {
    const r = await call("POST", api("") + "/tls/trust/remove",
                         { fingerprint: fingerprint });
    log.info("  (removed anchor " + fingerprint.slice(0, 11) + ": " +
             r.status + ")");
  }
  log.debug("Leaving removeAnchors().");
}

async function removeRealms() {
  log.debug("Entering removeRealms().");
  if (process.env.STS_TEST_REMOVE_REALMS !== "1") {
    log.debug("Leaving removeRealms(). Not asked to.");
    return;
  }
  for (const id of MADE_REALMS) {
    const r = await call("POST", api("") + "/realms/remove", { id: id });
    log.info("  (removed the realm " + id + ": " + r.status + ")");
  }
  log.debug("Leaving removeRealms().");
}

// ------------------------------------------------------------ sections ----
async function optional(dns, issued) {
  log.debug("Entering optional().");
  log.info("=== A1. the certificate binds its person ===");
  let got = await bindOnce(issued.alice, "EXTERNAL");
  check("alice's certificate binds with SASL EXTERNAL and an empty name",
        function () {
    assert.strictEqual(got.answer.status, 0, brief(got.answer));
  });
  await ok(api(REALM) + "/config/set",
           { key: "global.mode", value: "product" }, "PRODUCT for a moment");
  try {
    const read = await got.conn.send(baseSearch(dns.alice));
    check("PRODUCT: bound, a search of her own entry answers it",
          function () {
      assert.ok(read.status === 0 && read.entries.length === 1 &&
                read.entries[0].toLowerCase() === dns.alice.toLowerCase(),
                brief(read));
    });
    const anon = await ldaps(issued.alice);
    const unbound = await anon.send(baseSearch(dns.alice));
    anon.end();
    check("PRODUCT: the same search unbound is refused (50)", function () {
      assert.strictEqual(unbound.status, 50, brief(unbound));
    });
  } finally {
    await call("POST", api(REALM) + "/config/reset", { key: "global.mode" });
  }
  got.conn.end();
  for (const one of [["with her own dn: authzId", "dn:" + dns.alice],
                     ["with her own u: authzId", "u:" + WHO.alice]]) {
    got = await bindOnce(issued.alice, "EXTERNAL", one[1]);
    got.conn.end();
    check(one[0], function () {
      assert.strictEqual(got.answer.status, 0, brief(got.answer));
    });
  }
  got = await bindOnce(issued.alice, "EXTERNAL", undefined, dns.alice);
  got.conn.end();
  check("with her own DN as the bind name", function () {
    assert.strictEqual(got.answer.status, 0, brief(got.answer));
  });

  log.info("=== A2. refusals ===");
  await refused(REALM, "an authzId naming bob (dn:)", issued.alice, 50,
                "STS-LDAP-0189", { authzId: "dn:" + dns.bob });
  await refused(REALM, "an authzId naming bob (u:)", issued.alice, 50,
                "STS-LDAP-0189", { authzId: "u:" + WHO.bob });
  await refused(REALM, "an authzId in neither form", issued.alice, 50,
                "STS-LDAP-0189", { authzId: WHO.alice });
  await refused(REALM, "a bind name naming bob", issued.alice, 49,
                "STS-LDAP-0190", { name: dns.bob });
  await refused("", "EXTERNAL with no certificate", null, 48,
                "STS-LDAP-0179");
  // Refused before the certificate is read, so before a realm is known: the
  // row is the default realm's.
  await refused("", "a mechanism other than EXTERNAL", issued.alice, 7,
                "STS-LDAP-0178", { mechanism: "PLAIN",
                                   authzId: "\u0000" + WHO.alice + "\u0000x" });
  const before = await codeCount("", "STS-LDAP-0180");
  const onPlain = await plain();
  const plainAnswer = await onPlain.send(saslBind("EXTERNAL"));
  onPlain.end();
  const plainSeen = await codeAdded("", "STS-LDAP-0180", before);
  check("EXTERNAL on the plain listener (389) is refused with 48, recorded " +
        "STS-LDAP-0180", function () {
    assert.strictEqual(plainAnswer.status, 48, brief(plainAnswer));
    assert.ok(plainSeen, "no new STS-LDAP-0180 row");
  });

  log.info("=== A2b. an outside authority's certificate (#1061) ===");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "lse-"));
  const dir2 = fs.mkdtempSync(path.join(os.tmpdir(), "lse-"));
  try {
    const outside = outsideCertificate(dir, WHO.alice);
    const renewed = outsideCertificate(dir2, WHO.alice);
    await addAnchor(outside.caPem);
    await addAnchor(renewed.caPem);
    await sleep(500);
    // AN OUTSIDE CERTIFICATE NAMES NO REALM — its issuer is no realm's
    // authority — so with no name it is looked for in the DEFAULT realm,
    // where it is stored on nobody. Named by a DN, it is asked about in the
    // realm that DN is in.
    await refused("", "a certificate from an outside authority, naming " +
                  "alice and stored on no entry (with no name: the default " +
                  "realm)", outside, 49, "STS-LDAP-0192");
    await refused(REALM, "the same certificate held to frank's DN before it " +
                  "is stored on him", outside, 49, "STS-LDAP-0192",
                  { name: dns.frank });
    await ok(api(REALM) + "/users/add-certificate",
             { user: WHO.frank, certificate: outside.cert },
             "stored the outside certificate on frank");
    let viaStored = await bindOnce(outside, "EXTERNAL", undefined, dns.frank);
    const read = await viaStored.conn.send(baseSearch(dns.frank));
    viaStored.conn.end();
    check("stored on frank's entry, it binds — as frank, whose entry it " +
          "then reads", function () {
      assert.strictEqual(viaStored.answer.status, 0, brief(viaStored.answer));
      assert.ok(read.status === 0 && read.entries.length === 1, brief(read));
    });
    viaStored = await bindOnce(outside, "EXTERNAL", "dn:" + dns.frank);
    viaStored.conn.end();
    check("with frank's own dn: authzId and no name", function () {
      assert.strictEqual(viaStored.answer.status, 0, brief(viaStored.answer));
    });
    await refused(REALM, "the stored certificate with an authzId naming " +
                  "alice, whom it names", outside, 50, "STS-LDAP-0189",
                  { authzId: "dn:" + dns.alice });
    await refused(REALM, "a renewed certificate with the same subject, not " +
                  "stored", renewed, 49, "STS-LDAP-0192", { name: dns.frank });
    // A SECOND ENTRY CANNOT BE GIVEN IT AT THE MANAGEMENT API, which refuses
    // a certificate already stored elsewhere; an LDAP modify of the
    // development realm's directory is the door left.
    const twice = await call("POST", api(REALM) + "/users/add-certificate",
                             { user: WHO.bob, certificate: outside.cert });
    check("the management API refuses to store it on a second entry",
          function () {
      assert.strictEqual(twice.status, 400, twice.text.slice(0, 300));
      assert.ok(/already stored on/.test(twice.text), twice.text.slice(0, 300));
    });
    const der = new crypto.X509Certificate(outside.cert).raw;
    const onBob = await ldapModifyBinary(dns.bob, "userCertificate;binary",
                                         der);
    check("but a development realm's unbound LDAP modify stores it on bob " +
          "too", function () {
      assert.strictEqual(onBob, 0);
    });
    await refused(REALM, "the certificate stored on two entries", outside,
                  49, "STS-LDAP-0193", { name: dns.frank });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(dir2, { recursive: true, force: true });
  }

  log.info("=== A2. the realm, the entry, the account, the certificate ===");
  // Recorded in the realm whose DN it was held to.
  await refused(REALM, "another realm's certificate held to this " +
                "realm's DN", issued.other, 49, "STS-LDAP-0184",
                { authzId: "dn:" + dns.alice });
  got = await bindOnce(issued.other, "EXTERNAL");
  got.conn.end();
  check("the same certificate with no name binds in its own realm",
        function () {
    assert.strictEqual(got.answer.status, 0, brief(got.answer));
  });
  await deletePerson(REALM, WHO.dave);
  // With no entry there is no realm to record it in but the default one.
  await refused("", "a person with no entry", issued.dave, 49,
                "STS-LDAP-0187");
  await ok(api(REALM) + "/users/disable", { user: WHO.carol },
           "disabled carol");
  await refused(REALM, "a disabled person", issued.carol, 49,
                "STS-LDAP-0188");
  const revoked = await issued.alice2.browser.act("/portal/signing-key",
    { action: "revoke-tls-client", serial: issued.alice2.serial,
      reason: "keyCompromise" });
  check("precondition: alice's second certificate is revoked", function () {
    assert.strictEqual(revoked.status, 200, String(revoked.text).slice(0, 300));
  });
  await refused(REALM, "a revoked certificate", issued.alice2, 49,
                "STS-LDAP-0181");
  log.debug("Leaving optional().");
}

async function test() {
  log.debug("Entering test().");
  log.info("LDAPS at " + HOST + ":" + LDAPS_PORT + "; realms " + REALM +
           " and " + OTHER_REALM + ".");
  await makeRealm(REALM);
  await makeRealm(OTHER_REALM);
  const dns = {};
  for (const key of Object.keys(WHO)) {
    dns[key] = await makePerson(REALM, WHO[key]);
  }
  await makePerson(OTHER_REALM, WHO.alice);
  const issued = {
    alice: await selfIssued(REALM, WHO.alice, "laptop"),
    alice2: await selfIssued(REALM, WHO.alice, "phone"),
    carol: await selfIssued(REALM, WHO.carol, "laptop"),
    dave: await selfIssued(REALM, WHO.dave, "laptop"),
    other: await selfIssued(OTHER_REALM, WHO.alice, "laptop")
  };
  try {
    log.info("=== C. the defaults: 636 asks for nothing ===");
    await refused("", "at the defaults EXTERNAL, with a certificate in hand " +
                  "that is never sent,", issued.alice, 48, "STS-LDAP-0179");

    await setProcess("ldap.ldapsDisableOptionalClientCertificate", "false");
    await optional(dns, issued);

    log.info("=== B. required ===");
    await setProcess("ldap.ldapsRequireClientCertificate", "true");
    const without = await bindOnce(null, "EXTERNAL");
    without.conn.end();
    check("required: a connection without a certificate is refused at the " +
          "handshake", function () {
      assert.ok(!!without.answer.closed, brief(without.answer));
    });
    const got = await bindOnce(issued.alice, "EXTERNAL");
    got.conn.end();
    check("required: alice's certificate binds with SASL EXTERNAL",
          function () {
      assert.strictEqual(got.answer.status, 0, brief(got.answer));
    });
  } finally {
    await restore();
    await removeAnchors();
  }
  // A FLOOR on the count: a section that stops running must fail the job.
  assert.ok(checks >= FLOOR,
    "only " + checks + " checks ran; a section stopped running.");
  log.info(checks + " checks passed.");
  log.debug("Leaving test().");
}

const program = new Command();
program.addOption(new Option("-u, --url <url>",
                  "ignored; kept for a uniform CLI across the suite"));
program.parse(process.argv);

test().then(async function () {
  await removeRealms();
  log.info("Test completed successfully.");
}).catch(async function (e) {
  log.error(e.stack || e.message);
  await removeRealms();
  process.exit(1);
});
