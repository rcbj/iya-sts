// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: sts_ssh_user_ca.js
//
// ---------------------------------------------------------------------------
// SSH USER CERTIFICATES OVER HTTP (#1955 P3). A key made in this run is
// issued and revoked through /account-api. The certificate and the KRL are
// read back and checked here with node:crypto — the signature, the
// principal, the lifetime, the key id, the CA key and the revoked serial.
// Nothing in this file calls the service's own SSH parser.
//
//   a. this client can verify a certificate and a KRL it built itself;
//   b. the two operations are on the account API index;
//   c. no token is 401, self-service off is 403, and an unrelated
//      principal is 403;
//   d. the owner's certificate verifies under the realm CA's public key,
//      and the KRL does not yet name its serial;
//   e. a zero serial is 400, another subject is 404, and the owner's
//      revoke puts that serial on the KRL.
//
// pki.personSelfService is turned off only in a realm this run creates,
// and put back. `local: true`: this repository's account API and PKI
// documents. What the issuer decides in process is tests/ssh_user_ca.js.
// The same issuance inside tests/protocol/sts_account_api.js is opt-in
// and checks only the certificate's prefix.
// ---------------------------------------------------------------------------

"use strict";

const assert = require("assert");
const nodeCrypto = require("crypto");
const names = require("./random_username.js");
const portal = require("./portal_signin.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand run without one still
  // loads.
  appconfigProblem = e;
  appconfig = {};
}
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_ssh_user_ca",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "")
  .slice(-12);
const REALM = "ssh" + STAMP;
const DOMAIN = REALM + ".example.net";
const OWNER = ("own" + STAMP).slice(0, 24);
const OTHER = ("oth" + STAMP).slice(0, 24);
const PASSWORD = "Ssh-Cert-Key9!xQ";
const CERT_TYPE = "ssh-ed25519-cert-v01@openssh.com";
const KRL_MAGIC = BigInt("0x5353484b524c0a00");
const KRL_COMMENT = "Iya STS SSH user CA";

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

// A HOT PATH, as common/pki.js's sshUint32(): one certificate calls this
// per field. No Entering/Leaving pair.
function u32(n) {
  const out = Buffer.alloc(4);
  out.writeUInt32BE(Number(n) >>> 0, 0);
  return out;
}

// A HOT PATH, as u32(). No Entering/Leaving pair.
function u64(n) {
  const out = Buffer.alloc(8);
  out.writeBigUInt64BE(BigInt(n), 0);
  return out;
}

// A HOT PATH, as u32(). No Entering/Leaving pair.
function sshStr(bytes) {
  const b = Buffer.isBuffer(bytes) ? bytes
    : Buffer.from(String(bytes), "utf8");
  return Buffer.concat([u32(b.length), b]);
}

// A HOT PATH, as common/pki.js's sshReader(): the methods carry no
// Entering/Leaving pair. A short buffer throws; the caller reports it.
function sshReader(bytes) {
  const buf = Buffer.from(bytes || []);
  let at = 0;
  const reader = {
    take: function (n) {
      if (n < 0 || at + n > buf.length) {
        throw new Error("the SSH structure is truncated");
      }
      const out = buf.subarray(at, at + n);
      at += n;
      return out;
    },
    uint32: function () {
      return reader.take(4).readUInt32BE(0);
    },
    uint64: function () {
      return reader.take(8).readBigUInt64BE(0);
    },
    string: function () {
      return reader.take(reader.uint32());
    },
    text: function () {
      return reader.string().toString("utf8");
    },
    position: function () {
      return at;
    },
    done: function () {
      return at === buf.length;
    }
  };
  return reader;
}

function readStrings(buf) {
  log.debug("Entering readStrings().");
  const reader = sshReader(buf);
  const out = [];
  while (!reader.done()) {
    out.push(reader.text());
  }
  log.debug("Leaving readStrings(). " + out.length);
  return out;
}

function ed25519Material() {
  log.debug("Entering ed25519Material().");
  const pair = nodeCrypto.generateKeyPairSync("ed25519");
  const raw = pair.publicKey.export({ format: "der", type: "spki" })
    .subarray(-32);
  const blob = Buffer.concat([
    sshStr(Buffer.from("ssh-ed25519")), sshStr(raw)]);
  log.debug("Leaving ed25519Material().");
  return { raw: raw, privateKey: pair.privateKey, blob: blob,
           line: "ssh-ed25519 " + blob.toString("base64") };
}

function ed25519Raw(blob) {
  log.debug("Entering ed25519Raw().");
  const reader = sshReader(blob);
  const type = reader.text();
  const raw = reader.string();
  if (type !== "ssh-ed25519" || raw.length !== 32 || !reader.done()) {
    log.debug("Leaving ed25519Raw(). Not an Ed25519 key.");
    throw new Error("not an ssh-ed25519 public key");
  }
  log.debug("Leaving ed25519Raw().");
  return raw;
}

function parseCert(line) {
  log.debug("Entering parseCert().");
  const parts = String(line || "").trim().split(/\s+/);
  if (parts.length < 2) {
    log.debug("Leaving parseCert(). No blob.");
    throw new Error("the certificate line has no blob");
  }
  const blob = Buffer.from(parts[1], "base64");
  const reader = sshReader(blob);
  const certType = reader.text();
  const nonce = reader.string();
  const userRaw = reader.string();
  const serial = reader.uint64();
  const kind = reader.uint32();
  const keyId = reader.text();
  const principals = readStrings(reader.string());
  const validAfter = reader.uint64();
  const validBefore = reader.uint64();
  const critical = reader.string();
  const extensions = reader.string();
  const reserved = reader.string();
  const caBlob = reader.string();
  const signed = blob.subarray(0, reader.position());
  const wrapped = sshReader(reader.string());
  const sigFormat = wrapped.text();
  const signature = Buffer.from(wrapped.string());
  if (!reader.done() || !wrapped.done()) {
    log.debug("Leaving parseCert(). Trailing bytes.");
    throw new Error("the certificate has trailing bytes");
  }
  log.debug("Leaving parseCert().");
  return { lineType: parts[0], certType: certType, nonce: nonce,
           userRaw: userRaw, serial: serial, kind: kind, keyId: keyId,
           principals: principals, validAfter: validAfter,
           validBefore: validBefore, critical: critical,
           extensions: extensions, reserved: reserved, caBlob: caBlob,
           signed: signed, sigFormat: sigFormat, signature: signature };
}

function verifySignature(signed, caRaw, signature) {
  log.debug("Entering verifySignature().");
  const key = nodeCrypto.createPublicKey({
    key: { kty: "OKP", crv: "Ed25519", x: caRaw.toString("base64url") },
    format: "jwk" });
  const ok = nodeCrypto.verify(null, signed, key, signature) === true;
  log.debug("Leaving verifySignature(). " + ok);
  return ok;
}

function parseKrl(bytes) {
  log.debug("Entering parseKrl().");
  const reader = sshReader(bytes);
  if (reader.uint64() !== KRL_MAGIC || reader.uint32() !== 1) {
    log.debug("Leaving parseKrl(). Not a KRL.");
    throw new Error("not an OpenSSH KRL");
  }
  const out = { version: reader.uint64(), generatedAt: reader.uint64(),
                flags: reader.uint64(), comment: "", authorities: [] };
  reader.string();
  out.comment = reader.text();
  while (!reader.done()) {
    const type = reader.take(1)[0];
    const data = sshReader(reader.string());
    if (type === 1) {
      const caBlob = Buffer.from(data.string());
      data.string();
      const serials = [];
      while (!data.done()) {
        const sub = data.take(1)[0];
        const body = sshReader(data.string());
        if (sub === 0x20) {
          while (!body.done()) {
            serials.push(body.uint64());
          }
        }
      }
      out.authorities.push({ caBlob: caBlob, serials: serials });
    }
  }
  log.debug("Leaving parseKrl(). " + out.authorities.length);
  return out;
}

// The same layout PROTOCOL.certkeys uses for an Ed25519 user certificate,
// so a bug in the reader fails before any request is sent.
function localCertificate(user, ca, serial, principal) {
  log.debug("Entering localCertificate().");
  const signed = Buffer.concat([
    sshStr(Buffer.from(CERT_TYPE)),
    sshStr(nodeCrypto.randomBytes(32)),
    sshStr(user.raw),
    u64(serial),
    u32(1),
    sshStr(Buffer.from("sts:" + serial.toString(16))),
    sshStr(sshStr(Buffer.from(principal))),
    u64(1n),
    u64(400n),
    sshStr(Buffer.alloc(0)),
    sshStr(Buffer.alloc(0)),
    sshStr(Buffer.alloc(0)),
    sshStr(ca.blob)
  ]);
  const rawSig = nodeCrypto.sign(null, signed, ca.privateKey);
  const wrap = Buffer.concat([
    sshStr(Buffer.from("ssh-ed25519")), sshStr(rawSig)]);
  const blob = Buffer.concat([signed, sshStr(wrap)]);
  log.debug("Leaving localCertificate().");
  return CERT_TYPE + " " + blob.toString("base64");
}

function localKrl(caBlob, serials) {
  log.debug("Entering localKrl().");
  const parts = [u64(KRL_MAGIC), u32(1), u64(7n), u64(9n), u64(0n),
    sshStr(Buffer.alloc(0)), sshStr(Buffer.from(KRL_COMMENT))];
  if (serials.length) {
    const list = Buffer.concat(serials.map(function (n) {
      return u64(n);
    }));
    const sub = Buffer.concat([Buffer.from([0x20]), sshStr(list)]);
    const body = Buffer.concat([
      sshStr(caBlob), sshStr(Buffer.alloc(0)), sub]);
    parts.push(Buffer.from([1]), sshStr(body));
  }
  log.debug("Leaving localKrl().");
  return Buffer.concat(parts);
}

function selfCheck() {
  log.debug("Entering selfCheck().");
  const user = ed25519Material();
  const ca = ed25519Material();
  const serial = 0x1fn;
  const parsed = parseCert(localCertificate(user, ca, serial, "ada"));
  assert.strictEqual(parsed.certType, CERT_TYPE);
  assert.strictEqual(parsed.lineType, CERT_TYPE);
  assert.strictEqual(parsed.userRaw.length, 32);
  assert.ok(parsed.userRaw.equals(user.raw));
  assert.strictEqual(parsed.serial, serial);
  assert.deepStrictEqual(parsed.principals, ["ada"]);
  assert.strictEqual(parsed.keyId, "sts:1f");
  assert.strictEqual(parsed.sigFormat, "ssh-ed25519");
  assert.strictEqual(parsed.signature.length, 64);
  assert.ok(verifySignature(parsed.signed, ca.raw, parsed.signature));
  const flipped = Buffer.from(parsed.signed);
  flipped[0] ^= 0xff;
  assert.ok(!verifySignature(flipped, ca.raw, parsed.signature));
  const empty = parseKrl(localKrl(ca.blob, []));
  assert.strictEqual(empty.comment, KRL_COMMENT);
  assert.strictEqual(empty.authorities.length, 0);
  const listed = parseKrl(localKrl(ca.blob, [serial]));
  assert.strictEqual(listed.authorities.length, 1);
  assert.ok(listed.authorities[0].caBlob.equals(ca.blob));
  assert.strictEqual(listed.authorities[0].serials[0], serial);
  log.debug("Leaving selfCheck().");
}

async function send(url, options) {
  log.debug("Entering send().");
  const response = await fetch(url, Object.assign({ redirect: "manual" },
                                                   options || {}));
  const raw = await response.text();
  let body = null;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in send(): " + ((e && e.message) || e));
    // Not JSON. The caller reads raw.
    body = null;
  }
  log.debug("Leaving send(). " + response.status);
  return { status: response.status, body: body, raw: raw,
           headers: response.headers };
}

function postJson(url, payload) {
  log.debug("Entering postJson().");
  log.debug("Leaving postJson().");
  return send(url, { method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload || {}) });
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const response = await postJson(url, payload);
  assert.ok(response.status >= 200 && response.status < 300 &&
            response.body && response.body.ok !== false,
            "POST " + url + " should have " + what + "; it answered " +
            response.status + " " + String(response.raw).slice(0, 300));
  log.debug("Leaving ok().");
  return response.body;
}

function codeFree(text) {
  log.debug("Entering codeFree().");
  const okText = !/STS-[A-Z0-9]+-\d{4}/.test(String(text || ""));
  log.debug("Leaving codeFree().");
  return okText;
}

async function makeRealm(id) {
  log.debug("Entering makeRealm(). " + id);
  await ok(base + "/admin-api/realms/create", { id: id,
    domain: id + ".example.net", name: "SSH user CA " + id },
    "created " + id);
  log.debug("Leaving makeRealm().");
  return base + "/realm/" + id;
}

function realmSet(id, key, value) {
  log.debug("Entering realmSet(). " + key);
  log.debug("Leaving realmSet().");
  return ok(base + "/admin-api/realms/set", { id: id, key: key,
    value: String(value) }, "set " + key + " on " + id);
}

async function getBytes(url) {
  log.debug("Entering getBytes().");
  const response = await fetch(url);
  const bytes = Buffer.from(await response.arrayBuffer());
  log.debug("Leaving getBytes(). " + response.status);
  return { status: response.status, bytes: bytes,
           headers: response.headers };
}

function userBody(username) {
  log.debug("Entering userBody().");
  log.debug("Leaving userBody().");
  return { username: username, invent: false, credential: "password",
    password: PASSWORD,
    attributes: { cn: "Ssh " + username, sn: username, givenName: "Ssh",
                  mail: username + "@" + DOMAIN } };
}

async function removeRealm() {
  log.debug("Entering removeRealm().");
  if (process.env.STS_TEST_REMOVE_REALMS !== "1") {
    log.debug("Leaving removeRealm(). Not asked to.");
    return;
  }
  const response = await postJson(base + "/admin-api/realms/remove",
                                  { id: REALM });
  log.info("removed the realm " + REALM + " (" + response.status + ")");
  log.debug("Leaving removeRealm().");
}

function operationIds(index) {
  log.debug("Entering operationIds().");
  const ids = ((index.json && index.json.operations) || []).map(
    function (op) {
      return op.operationId;
    });
  log.debug("Leaving operationIds().");
  return ids;
}

async function test() {
  log.debug("Entering test().");
  log.info("SSH user certificates at " + base + "/realm/" + REALM);
  check("this client verifies an Ed25519 certificate and a KRL it built",
        function () {
    selfCheck();
  });

  const rb = await makeRealm(REALM);
  await realmSet(REALM, "risk.assessSignIns", false);
  await ok(rb + "/admin-api/users/create", userBody(OWNER),
           "created " + OWNER);
  await ok(rb + "/admin-api/users/create", userBody(OTHER),
           "created " + OTHER);
  const owner = await portal.signInToThePortal(rb, OWNER, log,
                                               { password: PASSWORD });
  const material = ed25519Material();
  check("the owner signs in as the portal does", function () {
    assert.ok(owner && owner.token, "no token");
  });

  log.info("=== b. the account API index ===");
  const index = await portal.nobody(rb, "GET", "/account-api");
  check("issue and revoke are listed with no token", function () {
    assert.strictEqual(index.status, 200, index.text.slice(0, 200));
    const ids = operationIds(index);
    assert.ok(ids.indexOf("issueSshCertificate") >= 0, ids.join(","));
    assert.ok(ids.indexOf("revokeSshCertificate") >= 0, ids.join(","));
  });

  log.info("=== c. what is refused ===");
  const noToken = await portal.nobody(rb, "POST",
    "/account-api/ssh/certificates",
    { publicKey: material.line, principals: [OWNER] });
  let tightened = false;
  try {
    await realmSet(REALM, "pki.personSelfService", false);
    tightened = true;
    const disabled = await owner.api("POST",
      "/account-api/ssh/certificates",
      { publicKey: material.line, principals: [OWNER] });
    check("no token is 401 and self-service off is 403, with no error " +
          "code in either body", function () {
      assert.strictEqual(noToken.status, 401, noToken.text.slice(0, 200));
      assert.ok(codeFree(noToken.text), noToken.text.slice(0, 200));
      assert.strictEqual(disabled.status, 403,
                         disabled.text.slice(0, 200));
      assert.ok(codeFree(disabled.text), disabled.text.slice(0, 200));
    });
    await realmSet(REALM, "pki.personSelfService", true);
    tightened = false;
    const unowned = await owner.api("POST",
      "/account-api/ssh/certificates",
      { publicKey: material.line, principals: ["not-" + OWNER] });
    check("an unrelated principal is refused 403, with no error code",
          function () {
      assert.strictEqual(unowned.status, 403, unowned.text.slice(0, 200));
      assert.ok(codeFree(unowned.text), unowned.text.slice(0, 200));
    });

    log.info("=== d. a certificate this client verifies ===");
    const issued = await owner.api("POST",
      "/account-api/ssh/certificates",
      { publicKey: material.line, principals: [OWNER] });
    const caDoc = await portal.nobody(rb, "GET",
      "/pki/ssh-user-ca/" + REALM);
    const krlBefore = await getBytes(rb + "/pki/ssh-user-krl/" + REALM);
    check("the certificate verifies under the published CA key, names " +
          "only the owner, and is not on the KRL yet", function () {
      assert.strictEqual(issued.status, 200, issued.text.slice(0, 300));
      assert.strictEqual(issued.json.hardwareBound, false);
      assert.match(issued.json.serialHex, /^[0-9a-f]+$/);
      assert.ok(codeFree(issued.text), issued.text.slice(0, 300));
      const cert = parseCert(issued.json.certificate);
      const serial = BigInt("0x" + issued.json.serialHex);
      assert.strictEqual(cert.lineType, CERT_TYPE);
      assert.strictEqual(cert.certType, CERT_TYPE);
      assert.strictEqual(cert.nonce.length, 32);
      assert.ok(cert.userRaw.equals(material.raw));
      assert.strictEqual(cert.kind, 1);
      assert.strictEqual(cert.serial, serial);
      assert.strictEqual(cert.keyId, "sts:" + issued.json.serialHex);
      assert.deepStrictEqual(cert.principals, [OWNER]);
      assert.strictEqual(cert.critical.length, 0);
      // ssh-keygen's default extensions (pki.sshUserCertificateExtensions,
      // the #1955 review), each with empty data, in lexical order.
      const ext = sshReader(cert.extensions);
      const names = [];
      while (!ext.done()) {
        names.push(ext.text());
        assert.strictEqual(ext.string().length, 0);
      }
      assert.deepStrictEqual(names, ["permit-X11-forwarding",
        "permit-agent-forwarding", "permit-port-forwarding", "permit-pty",
        "permit-user-rc"]);
      assert.strictEqual(cert.reserved.length, 0);
      assert.strictEqual(cert.validAfter,
                         BigInt(issued.json.validAfter));
      assert.strictEqual(cert.validBefore,
                         BigInt(issued.json.validBefore));
      assert.strictEqual(cert.validBefore - cert.validAfter, 330n);
      const now = BigInt(Math.floor(Date.now() / 1000));
      const skew = cert.validAfter - (now - 30n);
      assert.ok(skew >= -120n && skew <= 120n, String(skew));
      assert.strictEqual(cert.sigFormat, "ssh-ed25519");
      assert.strictEqual(cert.signature.length, 64);
      assert.strictEqual(caDoc.status, 200, caDoc.text.slice(0, 200));
      assert.ok(/^text\/plain/.test(
        String(caDoc.headers.get("content-type") || "")));
      assert.strictEqual(caDoc.headers.get("cache-control"), "no-store");
      assert.ok(codeFree(caDoc.text), caDoc.text.slice(0, 200));
      const caParts = caDoc.text.trim().split(/\s+/);
      assert.strictEqual(caParts[0], "ssh-ed25519");
      const caBlob = Buffer.from(caParts[1], "base64");
      assert.ok(cert.caBlob.equals(caBlob));
      const caRaw = ed25519Raw(caBlob);
      assert.ok(verifySignature(cert.signed, caRaw, cert.signature));
      const flipped = Buffer.from(cert.signed);
      flipped[0] ^= 0xff;
      assert.ok(!verifySignature(flipped, caRaw, cert.signature));
      assert.strictEqual(krlBefore.status, 200);
      assert.ok(/^application\/octet-stream/.test(
        String(krlBefore.headers.get("content-type") || "")));
      assert.strictEqual(krlBefore.headers.get("cache-control"),
                         "no-store");
      const before = parseKrl(krlBefore.bytes);
      assert.strictEqual(before.comment, KRL_COMMENT);
      assert.ok(!before.authorities.some(function (one) {
        return one.serials.some(function (n) {
          return n === serial;
        });
      }));
    });

    log.info("=== e. revoke ===");
    const badSerial = await owner.api("POST",
      "/account-api/ssh/certificates/revoke", { serialHex: "0" });
    const other = await portal.signInToThePortal(rb, OTHER, log,
                                                 { password: PASSWORD });
    const foreign = await other.api("POST",
      "/account-api/ssh/certificates/revoke",
      { serialHex: issued.json.serialHex });
    const revoked = await owner.api("POST",
      "/account-api/ssh/certificates/revoke",
      { serialHex: issued.json.serialHex });
    const krlAfter = await getBytes(rb + "/pki/ssh-user-krl/" + REALM);
    check("a zero serial is 400, another subject is 404, and the owner's " +
          "revoke puts the serial on the KRL", function () {
      assert.strictEqual(badSerial.status, 400,
                         badSerial.text.slice(0, 200));
      assert.ok(codeFree(badSerial.text), badSerial.text.slice(0, 200));
      assert.strictEqual(foreign.status, 404, foreign.text.slice(0, 200));
      assert.ok(codeFree(foreign.text), foreign.text.slice(0, 200));
      assert.strictEqual(revoked.status, 200, revoked.text.slice(0, 200));
      assert.strictEqual(revoked.json.revoked, true);
      assert.ok(codeFree(revoked.text), revoked.text.slice(0, 200));
      assert.strictEqual(krlAfter.status, 200);
      assert.ok(/^application\/octet-stream/.test(
        String(krlAfter.headers.get("content-type") || "")));
      assert.strictEqual(krlAfter.headers.get("cache-control"),
                         "no-store");
      const after = parseKrl(krlAfter.bytes);
      const serial = BigInt("0x" + issued.json.serialHex);
      const hit = after.authorities.filter(function (one) {
        return one.serials.some(function (n) {
          return n === serial;
        });
      });
      assert.strictEqual(hit.length, 1);
      assert.ok(hit[0].caBlob.equals(
        Buffer.from(caDoc.text.trim().split(/\s+/)[1], "base64")));
    });
  } finally {
    if (tightened) {
      try {
        await realmSet(REALM, "pki.personSelfService", true);
      } catch (e) {
        log.debug("Caught in test(): " + ((e && e.message) || e));
        // The original failure is still the one that leaves test().
        log.error("pki.personSelfService could not be put back: " +
                  ((e && e.message) || e));
      }
    }
  }
  log.debug("Leaving test().");
}

async function main() {
  log.debug("Entering main().");
  let failure = null;
  try {
    await test();
  } catch (e) {
    log.debug("Caught in main(): " + ((e && e.message) || e));
    // Reported below, after the realm is removed.
    failure = e;
  }
  try {
    await removeRealm();
  } catch (e) {
    log.debug("Caught in main() removing the realm: " +
              ((e && e.message) || e));
    // A removal that fails does not hide the test's own verdict.
    log.info("could not remove the realm: " + ((e && e.message) || e));
  }
  if (failure) {
    log.error("FAILED after " + checks + " check(s): " +
              (failure.stack || failure));
    log.debug("Leaving main(). Failed.");
    process.exit(1);
  }
  log.info(checks + " check(s) passed.");
  log.debug("Leaving main().");
}

main();
