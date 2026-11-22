// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: sts_yubiotp.js
//
// ---------------------------------------------------------------------------
// YUBICO OTP AND YK-VAL 2.0 OVER HTTP (#1955 P5). A client made in this
// run — modhex, CRC-16 residual 0xf0b8, AES-128-ECB, HMAC-SHA1 — imports a
// CSV, assigns the token by spending one OTP, and then speaks
// GET and POST /wsapi/2.0/verify. Nothing here calls the service's own
// OTP or HMAC code: those bytes are produced with node:crypto.
//
//   a. while yubiotp.ykval is off, both methods answer
//      OPERATION_NOT_ALLOWED, unsigned, no-store, with no error code;
//   b. the five management operations are in the document, and an import
//      with no token is refused;
//   c. a CSV made in the run is imported and assigned; the confirmation
//      OTP is spent; no answer carries the AES key, the private id or an
//      error code;
//   d. a YK-VAL client created here: a missing parameter, an unknown
//      client and a bad HMAC; a fresh OTP is OK with sl=100 and a
//      signature this client checks; the same OTP is REPLAYED_OTP; the
//      same nonce is REPLAYED_REQUEST; POST works the same way; a zero
//      counter is BAD_OTP; removing the client makes the next request
//      NO_SUCH_CLIENT.
//
// The three settings are turned on only in a realm this run creates, and
// put back. The keys are drawn here and never written down. What the
// policy row does to enrolment is tests/yubiotp.js, in process.
// `local: true`: this repository's management API and YK-VAL endpoint.
// ---------------------------------------------------------------------------

"use strict";

const assert = require("assert");
const https = require("https");
const nodeCrypto = require("crypto");
const querystring = require("querystring");
const { Command, Option } = require("commander");

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
var log = bunyan.createLogger({ name: "sts_yubiotp",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const OPERATION = "/admin-api/hardware-tokens";
const MODHEX = "cbdefghijklnrtuv";
const SETTINGS = ["yubiotp.offered", "yubiotp.ykval",
                  "yubiotp.allowPlaintextImport"];
const STAMP = Date.now().toString(36).toLowerCase() +
  nodeCrypto.randomBytes(2).toString("hex");
const REALM = ("y5" + STAMP).slice(0, 31);
const DOMAIN = REALM + ".example.net";
const PERSON = ("otp" + STAMP).slice(0, 24);
const PASSWORD = "Yubi-Otp-Key9!xQ";

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

// One request. The management API's token is attached by the launcher's
// preload unless `bare` sends `Authorization: none`. `form` is
// application/x-www-form-urlencoded, which is how YK-VAL's POST is signed.
function send(method, path, options) {
  log.debug("Entering send(). " + method + " " + path);
  const o = options || {};
  const target = new URL(base + path);
  const headers = Object.assign({ accept: o.accept || "application/json" },
                                o.headers || {});
  let body = "";
  if (o.form) {
    body = querystring.stringify(o.form);
    headers["content-type"] = "application/x-www-form-urlencoded";
    headers["content-length"] = Buffer.byteLength(body);
  } else if (o.json !== undefined) {
    body = JSON.stringify(o.json);
    headers["content-type"] = "application/json";
    headers["content-length"] = Buffer.byteLength(body);
  }
  if (o.bare) {
    // `tests/tools/attach-admin-token.js` leaves this alone, and the
    // service reads it as a malformed credential: a caller with no token.
    headers.authorization = "none";
  }
  log.debug("Leaving send().");
  return new Promise(function (resolve, reject) {
    const transport = target.protocol === "http:" ? require("http") : https;
    const req = transport.request({
      method: method, hostname: target.hostname, port: target.port,
      path: target.pathname + target.search, headers: headers
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
          log.debug("Caught in send(): " + ((e && e.message) || e));
          // Not JSON: YK-VAL's text/plain, or Express's own 404. The
          // caller reads `raw`.
          json = null;
        }
        resolve({ status: res.statusCode, headers: res.headers, raw: raw,
                  json: json });
      });
    });
    req.on("error", reject);
    req.end(body);
  });
}

function realmPath(path) {
  log.debug("Entering realmPath().");
  log.debug("Leaving realmPath().");
  return "/realm/" + REALM + path;
}

function modhexEncode(buf) {
  log.debug("Entering modhexEncode().");
  let out = "";
  for (let i = 0; i < buf.length; i++) {
    out += MODHEX.charAt((buf[i] >> 4) & 0x0f);
    out += MODHEX.charAt(buf[i] & 0x0f);
  }
  log.debug("Leaving modhexEncode().");
  return out;
}

function modhexDecode(text) {
  log.debug("Entering modhexDecode().");
  const s = String(text || "");
  if (!s.length || (s.length % 2) !== 0) {
    log.debug("Leaving modhexDecode(). Not even.");
    return null;
  }
  const out = Buffer.alloc(s.length / 2);
  for (let i = 0; i < s.length; i += 2) {
    const hi = MODHEX.indexOf(s.charAt(i));
    const lo = MODHEX.indexOf(s.charAt(i + 1));
    if (hi < 0 || lo < 0) {
      log.debug("Leaving modhexDecode(). Not modhex.");
      return null;
    }
    out[i / 2] = (hi << 4) | lo;
  }
  log.debug("Leaving modhexDecode().");
  return out;
}

// CRC-16, polynomial 0x8408, initialised to 0xffff. A genuine 16-byte
// block, CRC included, leaves residual 0xf0b8.
function crc16(bytes) {
  log.debug("Entering crc16().");
  let crc = 0xffff;
  for (let i = 0; i < bytes.length; i++) {
    crc ^= bytes[i];
    for (let b = 0; b < 8; b++) {
      const lsb = crc & 1;
      crc >>>= 1;
      if (lsb) {
        crc ^= 0x8408;
      }
    }
  }
  log.debug("Leaving crc16().");
  return crc & 0xffff;
}

// One OTP. The public id is 6 random bytes of modhex; the private id is
// 6 bytes of hex; the AES key is 16 bytes. use 0 and session 0 together
// are the counter this service refuses.
function makeSecret(serial) {
  log.debug("Entering makeSecret().");
  const secret = {
    serial: serial,
    publicId: modhexEncode(nodeCrypto.randomBytes(6)),
    p: nodeCrypto.randomBytes(6).toString("hex"),
    k: nodeCrypto.randomBytes(16).toString("hex")
  };
  log.debug("Leaving makeSecret().");
  return secret;
}

function otpFor(secret, use, session) {
  log.debug("Entering otpFor().");
  const plain = Buffer.alloc(16);
  Buffer.from(secret.p, "hex").copy(plain, 0);
  plain.writeUInt16LE(Math.floor(use) & 0xffff, 6);
  plain[11] = Math.floor(session) & 0xff;
  const crc = crc16(plain.subarray(0, 14));
  plain.writeUInt16LE((~crc) & 0xffff, 14);
  const cipher = nodeCrypto.createCipheriv("aes-128-ecb",
    Buffer.from(secret.k, "hex"), null);
  cipher.setAutoPadding(false);
  const block = Buffer.concat([cipher.update(plain), cipher.final()]);
  const otp = secret.publicId + modhexEncode(block);
  log.debug("Leaving otpFor().");
  return otp;
}

// YK-VAL's parameter string: keys sorted, `h` and empty values omitted.
function paramString(params) {
  log.debug("Entering paramString().");
  const src = params || {};
  const keys = Object.keys(src).filter(function (k) {
    return k !== "h" && src[k] !== undefined && src[k] !== null &&
           String(src[k]) !== "";
  }).sort();
  const out = keys.map(function (k) {
    return k + "=" + String(src[k]);
  }).join("&");
  log.debug("Leaving paramString().");
  return out;
}

function sign(secret, params) {
  log.debug("Entering sign().");
  const digest = nodeCrypto.createHmac("sha1",
    Buffer.from(String(secret || ""), "base64"))
    .update(paramString(params), "utf8").digest("base64");
  log.debug("Leaving sign().");
  return digest;
}

function nonce() {
  log.debug("Entering nonce().");
  const out = nodeCrypto.randomBytes(16).toString("hex");
  log.debug("Leaving nonce().");
  return out;
}

function clientId() {
  log.debug("Entering clientId().");
  const bytes = nodeCrypto.randomBytes(12);
  let id = "";
  for (let i = 0; i < bytes.length; i++) {
    id += String(bytes[i] % 10);
  }
  if (id.charAt(0) === "0") {
    id = "1" + id.slice(1);
  }
  log.debug("Leaving clientId().");
  return id;
}

// `name=value` lines, CR LF, and a trailing CR LF. `h` is base64, so the
// value is everything after the first `=`.
function ykvalFields(raw) {
  log.debug("Entering ykvalFields().");
  const fields = {};
  String(raw || "").split(/\r\n/).forEach(function (line) {
    if (!line) {
      return;
    }
    const at = line.indexOf("=");
    if (at < 1) {
      return;
    }
    fields[line.slice(0, at)] = line.slice(at + 1);
  });
  log.debug("Leaving ykvalFields().");
  return fields;
}

function codeFree(text) {
  log.debug("Entering codeFree().");
  const ok = !/STS-[A-Z0-9]+-\d{4}/.test(String(text || ""));
  log.debug("Leaving codeFree().");
  return ok;
}

function assertAnswer(res, status) {
  log.debug("Entering assertAnswer().");
  // YK-VAL's status is a body field. The HTTP status stays 200, including
  // a refusal: express's send() is what writes the text.
  assert.strictEqual(res.status, 200, String(res.raw).slice(0, 300));
  const fields = ykvalFields(res.raw);
  assert.strictEqual(fields.status, status, res.raw.slice(0, 300));
  assert.strictEqual(res.headers["cache-control"], "no-store",
                     JSON.stringify(res.headers["cache-control"]));
  assert.ok(/^text\/plain/.test(String(res.headers["content-type"] || "")),
            String(res.headers["content-type"]));
  assert.ok(codeFree(res.raw), res.raw.slice(0, 300));
  assert.ok(res.raw.endsWith("\r\n"), "the body does not end CR LF");
  log.debug("Leaving assertAnswer().");
  return fields;
}

async function verify(params, method) {
  log.debug("Entering verify().");
  const path = realmPath("/wsapi/2.0/verify");
  let res;
  if (method === "POST") {
    res = await send("POST", path, { form: params, accept: "text/plain" });
  } else {
    const qs = querystring.stringify(params || {});
    res = await send("GET", path + (qs ? "?" + qs : ""),
                     { accept: "text/plain" });
  }
  log.debug("Leaving verify().");
  return res;
}

async function setFlags(on) {
  log.debug("Entering setFlags().");
  const body = {};
  SETTINGS.forEach(function (key) {
    body[key] = on;
  });
  const res = await send("POST", realmPath("/admin-api/config/set-many"),
                         { json: body });
  assert.ok(res.status >= 200 && res.status < 300 && res.json &&
            res.json.ok !== false,
            "the YubiKey OTP settings could not be " +
            (on ? "turned on" : "put back") + ": " + res.status + " " +
            String(res.raw).slice(0, 300));
  log.debug("Leaving setFlags().");
}

async function test() {
  log.debug("Entering test().");
  log.info("YubiKey OTP and YK-VAL at " + base + "/realm/" + REALM);
  const secret = makeSecret("Y5-" + STAMP);
  const sample = otpFor(secret, 1, 1);
  const opened = modhexDecode(sample.slice(-32));
  check("this client mints an OTP whose CRC residual is 0xf0b8",
        function () {
    assert.strictEqual(sample.length, 44, "a 6-byte public id is 44 " +
                       "modhex characters with its ciphertext");
    assert.ok(opened && opened.length === 16, "the ciphertext is not " +
              "16 bytes of modhex");
    const decipher = nodeCrypto.createDecipheriv("aes-128-ecb",
      Buffer.from(secret.k, "hex"), null);
    decipher.setAutoPadding(false);
    const plain = Buffer.concat([decipher.update(opened),
                                 decipher.final()]);
    assert.strictEqual(crc16(plain), 0xf0b8);
  });

  log.info("=== a. YK-VAL while it is off ===");
  const created = await send("POST", "/admin-api/realms/create", { json: {
    id: REALM, domain: DOMAIN, name: "YubiKey OTP " + STAMP } });
  assert.ok(created.status >= 200 && created.status < 300 &&
            created.json && created.json.ok !== false,
            "the realm was not created: " + created.status + " " +
            String(created.raw).slice(0, 300));
  let armed = false;
  try {
    const offGet = await verify({});
    const offPost = await verify({ id: "1", otp: sample, nonce: nonce(),
                                   h: "not-a-signature" }, "POST");
    check("GET and POST /wsapi/2.0/verify answer OPERATION_NOT_ALLOWED, " +
          "unsigned, while yubiotp.ykval is off", function () {
      [offGet, offPost].forEach(function (res) {
        const fields = assertAnswer(res, "OPERATION_NOT_ALLOWED");
        assert.ok(!fields.h, "an answer was signed while YK-VAL is off");
        assert.strictEqual(Object.keys(fields).join(","), "status");
      });
    });

    log.info("=== b. the document and the gate ===");
    const doc = await send("GET", "/admin-api/openapi.json");
    const anonymous = await send("POST",
      realmPath(OPERATION + "/import-yubiotp"),
      { bare: true, json: { csv: "serial,public id,private id,aes key" } });
    check("the five YubiKey OTP operations are published and an import " +
          "refuses a caller with no token", function () {
      const paths = Object.keys((doc.json && doc.json.paths) || {});
      ["/import-yubiotp", "/assign-yubiotp", "/remove-yubiotp",
       "/ykval-client-add", "/ykval-client-remove"].forEach(function (p) {
        assert.ok(paths.indexOf(OPERATION + p) >= 0,
                  OPERATION + p + " is not in the document");
      });
      assert.strictEqual(anonymous.status, 401,
                         anonymous.raw.slice(0, 200));
    });

    log.info("=== c. import and assignment ===");
    await setFlags(true);
    armed = true;
    const csv = "serial,public id,private id,aes key\n" +
      [secret.serial, secret.publicId, secret.p, secret.k].join(",");
    const imported = await send("POST",
      realmPath(OPERATION + "/import-yubiotp"), { json: { csv: csv } });
    const person = await send("POST", realmPath("/admin-api/users/create"),
      { json: {
        username: PERSON, invent: false, credential: "password",
        password: PASSWORD,
        attributes: { cn: "Yubi " + PERSON, sn: PERSON, givenName: "Yubi",
                      mail: PERSON + "@" + DOMAIN } } });
    const confirming = otpFor(secret, 1, 1);
    const assigned = await send("POST",
      realmPath(OPERATION + "/assign-yubiotp"), { json: {
        serial: secret.serial, username: PERSON, otp: confirming } });
    const again = await send("POST",
      realmPath(OPERATION + "/assign-yubiotp"), { json: {
        serial: secret.serial, username: PERSON,
        otp: otpFor(secret, 9, 1) } });
    const unknown = await send("POST",
      realmPath(OPERATION + "/assign-yubiotp"), { json: {
        serial: "no-such-" + STAMP, username: PERSON,
        otp: otpFor(secret, 9, 2) } });
    check("the CSV is imported and assigned, the second assignment and " +
          "an unknown serial are refused, and no answer carries the " +
          "secret or an error code", function () {
      assert.strictEqual(person.status, 200, person.raw.slice(0, 400));
      assert.strictEqual(imported.status, 200, imported.raw.slice(0, 400));
      assert.strictEqual(imported.json.imported.length, 1, imported.raw);
      assert.strictEqual(imported.json.imported[0].publicId,
                         secret.publicId);
      assert.strictEqual(assigned.status, 200, assigned.raw.slice(0, 400));
      assert.strictEqual(assigned.json.token.holder, PERSON);
      assert.strictEqual(assigned.json.token.status, "assigned");
      assert.strictEqual(again.status, 409, again.raw.slice(0, 300));
      assert.strictEqual(unknown.status, 404, unknown.raw.slice(0, 300));
      const text = imported.raw + assigned.raw + again.raw + unknown.raw +
        person.raw;
      [secret.k, secret.p].forEach(function (needle) {
        assert.ok(text.indexOf(needle) < 0,
                  "an answer carried a secret");
      });
      assert.ok(codeFree(text), text.slice(0, 400));
    });

    log.info("=== d. YK-VAL 2.0 ===");
    const id = clientId();
    const missing = await verify({ otp: confirming, nonce: nonce(),
                                   h: "not-a-signature" });
    const unknownClient = await verify({
      id: id === "9999999999999999" ? "9999999999999998" : "9999999999999999",
      otp: confirming, nonce: nonce(), h: "not-a-signature" });
    const added = await send("POST",
      realmPath(OPERATION + "/ykval-client-add"), { json: { id: id } });
    assert.strictEqual(added.status, 200, added.raw.slice(0, 300));
    const key = added.json && added.json.key;
    assert.ok(key && added.json.id === id, "the client key was not " +
              "answered once");
    const missingSigned = await verify({ id: id });
    const bad = await verify({ id: id, otp: confirming, nonce: nonce(),
                               h: "not-a-signature" });
    const spentNonce = nonce();
    const spentParams = { id: id, otp: confirming, nonce: spentNonce };
    spentParams.h = sign(key, spentParams);
    const spentRes = await verify(spentParams);
    const freshNonce = nonce();
    const freshOtp = otpFor(secret, 1, 2);
    const fresh = { id: id, otp: freshOtp, nonce: freshNonce };
    fresh.h = sign(key, fresh);
    const okRes = await verify(fresh);
    const replayNonce = nonce();
    const replay = { id: id, otp: freshOtp, nonce: replayNonce };
    replay.h = sign(key, replay);
    const replayRes = await verify(replay);
    const reused = { id: id, otp: otpFor(secret, 2, 1),
                     nonce: freshNonce };
    reused.h = sign(key, reused);
    const reusedRes = await verify(reused);
    const postedNonce = nonce();
    const posted = { id: id, otp: otpFor(secret, 2, 2),
                     nonce: postedNonce };
    posted.h = sign(key, posted);
    const postedRes = await verify(posted, "POST");
    const zeroNonce = nonce();
    const zero = { id: id, otp: otpFor(secret, 0, 0), nonce: zeroNonce };
    zero.h = sign(key, zero);
    const zeroRes = await verify(zero);
    check("a missing parameter, an unknown client and a bad HMAC are " +
          "the unsigned refusals, and a parameter for a known client " +
          "is signed", function () {
      const missed = assertAnswer(missing, "MISSING_PARAMETER");
      assert.ok(!missed.h, "a request with no client id was signed");
      const noClient = assertAnswer(unknownClient, "NO_SUCH_CLIENT");
      assert.ok(!noClient.h, "an unknown client was signed");
      const wrong = assertAnswer(bad, "BAD_SIGNATURE");
      assert.ok(!wrong.h, "a bad HMAC was answered with a signature");
      const partial = assertAnswer(missingSigned, "MISSING_PARAMETER");
      assert.strictEqual(partial.h, sign(key, partial),
                         "the signed refusal does not verify");
    });
    check("the OTP that assigned the token is REPLAYED_OTP, and a fresh " +
          "one is OK with sl=100 and a signature this client checks",
          function () {
      const used = assertAnswer(spentRes, "REPLAYED_OTP");
      assert.strictEqual(used.h, sign(key, used));
      assert.strictEqual(used.otp, confirming);
      const good = assertAnswer(okRes, "OK");
      assert.strictEqual(good.sl, "100");
      assert.strictEqual(good.otp, freshOtp);
      assert.strictEqual(good.nonce, freshNonce);
      assert.ok(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(good.t),
                good.t);
      assert.strictEqual(good.h, sign(key, good));
    });
    check("the same OTP with a new nonce is REPLAYED_OTP, the same " +
          "nonce with a new OTP is REPLAYED_REQUEST, POST accepts " +
          "another OTP, and a zero counter is BAD_OTP", function () {
      const againOtp = assertAnswer(replayRes, "REPLAYED_OTP");
      assert.strictEqual(againOtp.h, sign(key, againOtp));
      const againNonce = assertAnswer(reusedRes, "REPLAYED_REQUEST");
      assert.strictEqual(againNonce.h, sign(key, againNonce));
      const postedFields = assertAnswer(postedRes, "OK");
      assert.strictEqual(postedFields.sl, "100");
      assert.strictEqual(postedFields.h, sign(key, postedFields));
      const refused = assertAnswer(zeroRes, "BAD_OTP");
      assert.strictEqual(refused.h, sign(key, refused));
    });
    const removed = await send("POST",
      realmPath(OPERATION + "/ykval-client-remove"), { json: { id: id } });
    const goneNonce = nonce();
    const gone = { id: id, otp: otpFor(secret, 3, 1), nonce: goneNonce };
    gone.h = sign(key, gone);
    const goneRes = await verify(gone);
    check("removing the client makes the next signed OTP NO_SUCH_CLIENT, " +
          "unsigned, and the key is not in that answer", function () {
      assert.strictEqual(removed.status, 200, removed.raw.slice(0, 300));
      assert.ok(removed.raw.indexOf(key) < 0,
                "the removal answer repeated the client key");
      const fields = assertAnswer(goneRes, "NO_SUCH_CLIENT");
      assert.ok(!fields.h, "a removed client was still signed");
      assert.ok(goneRes.raw.indexOf(key) < 0,
                "the verify answer carried the client key");
    });
    await setFlags(false);
    armed = false;
    const restored = await verify({});
    check("with the setting put back, YK-VAL is OPERATION_NOT_ALLOWED " +
          "again", function () {
      const fields = assertAnswer(restored, "OPERATION_NOT_ALLOWED");
      assert.ok(!fields.h);
      assert.strictEqual(Object.keys(fields).join(","), "status");
    });
  } finally {
    if (armed) {
      try {
        await setFlags(false);
      } catch (e) {
        log.debug("Caught in test(): " + ((e && e.message) || e));
        // The original failure is still the one that leaves test(). A
        // second throw here would hide it.
        log.error("the YubiKey OTP settings could not be put back: " +
                  ((e && e.message) || e));
      }
    }
    if (process.env.STS_TEST_REMOVE_REALMS === "1") {
      const removedRealm = await send("POST", "/admin-api/realms/remove",
                                      { json: { id: REALM } });
      log.info("removed the realm " + REALM + " (" +
               removedRealm.status + ")");
    }
  }

  log.info(checks + " checks passed.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_yubiotp")
  .description("YubiKey OTP and YK-VAL 2.0 over HTTP (#1955 P5).")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().then(function () {
  process.exit(0);
}, function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
