// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: sts_oath_tokens.js
//
// ---------------------------------------------------------------------------
// IMPORTED OATH TOKENS OVER HTTP (#1955 P4): a vendor's PSKC seed file
// (RFC 6030) imported through `/admin-api/hardware-tokens/import-pskc`,
// listed, assigned to a person and retired.
//
//   a. the four operations are in the management API's document, and the
//      inventory refuses a caller with no token;
//   b. a container made in the run (AES-128-CBC under a pre-shared key,
//      HMAC-SHA1 over each value, RFC 6030 section 6.1) is refused under the
//      wrong key and imported under the right one, and NO ANSWER CARRIES THE
//      SECRET, THE KEY OR AN ERROR CODE;
//   c. the inventory lists it unassigned by its serial; it is assigned to a
//      person made here, listed assigned, and refused a second assignment
//      (409) and a removal while assigned (409); an unknown token is 404;
//   d. reporting its hardware token lost retires it, and the retired row is
//      then removed.
//
// The keys of the seed file are drawn in the run and never written down.
// What a code from the token does at a sign-in is `tests/oath_tokens.js`'s
// and `tests/hotp.js`', in process. The authentication policy's hotp row
// is off by default; this run turns it on for the assignment and puts the
// default realm's profile back. `local: true`: this repository's
// console and management API.
// ---------------------------------------------------------------------------

"use strict";

const assert = require("assert");
const https = require("https");
const nodeCrypto = require("crypto");
const { Command, Option } = require("commander");

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
var log = bunyan.createLogger({ name: "sts_oath_tokens",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const OPERATION = "/admin-api/hardware-tokens";
const RUN = Date.now().toString(36) + "-" +
  require("crypto").randomBytes(2).toString("hex");

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

// One request over node's own https. The management API's token is attached
// by the launcher's preload (`tests/tools/attach-admin-token.js`) unless
// `bare` sends `Authorization: none`.
function send(method, path, options) {
  log.debug("Entering send(). " + method + " " + path);
  const o = options || {};
  const target = new URL(base + path);
  const headers = Object.assign({ accept: "application/json" },
                                o.headers || {});
  const body = o.json === undefined ? "" : JSON.stringify(o.json);
  if (body) {
    headers["content-type"] = "application/json";
    headers["content-length"] = Buffer.byteLength(body);
  }
  if (o.bare) {
    // `tests/tools/attach-admin-token.js` leaves this alone, and the service
    // reads it as a malformed credential: a caller with no token.
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
          // Not JSON: a page, a CSV, or Express's own 404; the caller reads
          // `raw`.
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

// XML Encryption's CBC, the IV first; PKCS #7 padding is a valid case of
// its padding (the last octet counts it).
function cbc(key, plain) {
  log.debug("Entering cbc().");
  const iv = nodeCrypto.randomBytes(16);
  const c = nodeCrypto.createCipheriv("aes-128-cbc", key, iv);
  const out = Buffer.concat([iv, c.update(plain), c.final()]);
  log.debug("Leaving cbc().");
  return out;
}

// One HOTP key in an RFC 6030 section 6.1 container, made in the run.
function container(serial, key) {
  log.debug("Entering container().");
  const macKey = nodeCrypto.randomBytes(20);
  const secret = nodeCrypto.randomBytes(20);
  const enc = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
  const sealedMac = cbc(key, macKey);
  const sealedSecret = cbc(key, secret);
  const valueMac = nodeCrypto.createHmac("sha1", macKey)
    .update(sealedSecret).digest("base64");
  const xml = [
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
    "<KeyContainer Version=\"1.0\" " +
      "xmlns=\"urn:ietf:params:xml:ns:keyprov:pskc\" " +
      "xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" " +
      "xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\">",
    "<EncryptionKey><ds:KeyName>run-key</ds:KeyName></EncryptionKey>",
    "<MACMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#hmac-sha1\">" +
      "<MACKey><xenc:EncryptionMethod Algorithm=\"" + enc + "\"/>" +
      "<xenc:CipherData><xenc:CipherValue>" + sealedMac.toString("base64") +
      "</xenc:CipherValue></xenc:CipherData></MACKey></MACMethod>",
    "<KeyPackage><DeviceInfo><Manufacturer>Run Vendor</Manufacturer>" +
      "<SerialNo>" + serial + "</SerialNo></DeviceInfo>",
    "<Key Id=\"1\" Algorithm=\"urn:ietf:params:xml:ns:keyprov:pskc:hotp\">",
    "<AlgorithmParameters><ResponseFormat Length=\"6\" " +
      "Encoding=\"DECIMAL\"/></AlgorithmParameters>",
    "<Data><Secret><EncryptedValue><xenc:EncryptionMethod Algorithm=\"" +
      enc + "\"/><xenc:CipherData><xenc:CipherValue>" +
      sealedSecret.toString("base64") + "</xenc:CipherValue>" +
      "</xenc:CipherData></EncryptedValue><ValueMAC>" + valueMac +
      "</ValueMAC></Secret><Counter><PlainValue>0</PlainValue></Counter>" +
      "</Data></Key></KeyPackage></KeyContainer>"
  ].join("\n");
  log.debug("Leaving container().");
  return { xml: xml, secret: secret };
}

// The hotp row is off by default. Assignment asks it. The returned record
// is what puts the default realm's profile back: a reset when nothing was
// stored, the previous field values when a profile already was.
async function allowHotp() {
  log.debug("Entering allowHotp().");
  const got = await send("GET", "/admin-api/policies");
  assert.strictEqual(got.status, 200, String(got.raw).slice(0, 300));
  const authn = got.json && got.json.authn;
  assert.ok(authn && authn.defaults, "the policies answer had no defaults");
  const wasStored = !!(authn.profile && authn.profile.stored);
  const previous = Object.assign({ profile: "default" }, authn.defaults);
  Object.keys(authn.defaults).forEach(function (key) {
    if (authn.profile && authn.profile[key] !== undefined) {
      previous[key] = authn.profile[key];
    }
  });
  if (authn.profile && authn.profile.description !== undefined) {
    previous.description = authn.profile.description;
  }
  const saved = await send("POST", "/admin-api/policies/save-authn-policy",
    { json: Object.assign({}, previous, { hotpSecondFactor: true }) });
  const ok = saved.status >= 200 && saved.status < 300 && saved.json &&
             saved.json.ok !== false;
  log.debug("Leaving allowHotp().");
  return {
    ok: ok, wasStored: wasStored, previous: previous,
    detail: saved.status + " " + String(saved.raw).slice(0, 300)
  };
}

async function restoreHotp(saved) {
  log.debug("Entering restoreHotp().");
  let res;
  if (!saved.wasStored) {
    res = await send("POST", "/admin-api/policies/reset-authn-policy",
                     { json: { profile: "default" } });
  } else {
    res = await send("POST", "/admin-api/policies/save-authn-policy",
                     { json: saved.previous });
  }
  assert.ok(res.status >= 200 && res.status < 300 && res.json &&
            res.json.ok !== false,
            "the authentication policy could not be put back: " +
            res.status + " " + String(res.raw).slice(0, 300));
  log.debug("Leaving restoreHotp().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Imported OATH tokens at " + base);
  const serial = "P4-" + RUN;
  const person = "oath-" + RUN;
  const key = nodeCrypto.randomBytes(16);
  const made = container(serial, key);

  log.info("=== a. the document and the gate ===");
  const doc = await send("GET", "/admin-api/openapi.json");
  const anonymous = await send("GET", OPERATION + "/oath", { bare: true });
  check("the four OATH operations are published and the inventory refuses " +
        "a caller with no token", function () {
    const paths = Object.keys((doc.json && doc.json.paths) || {});
    ["/oath", "/import-pskc", "/assign-oath", "/remove-oath"]
      .forEach(function (p) {
        assert.ok(paths.indexOf(OPERATION + p) >= 0,
                  OPERATION + p + " is not in the document");
      });
    assert.strictEqual(anonymous.status, 401, anonymous.raw.slice(0, 200));
  });

  log.info("=== b. the import ===");
  const wrong = await send("POST", OPERATION + "/import-pskc",
    { json: { pskc: made.xml,
              preSharedKey: nodeCrypto.randomBytes(16).toString("hex") } });
  const right = await send("POST", OPERATION + "/import-pskc",
    { json: { pskc: made.xml, preSharedKey: key.toString("hex") } });
  check("the wrong key imports nothing, the right one imports the token, " +
        "and no answer carries the secret, the key or an error code",
        function () {
    assert.strictEqual(wrong.status, 400, wrong.raw.slice(0, 300));
    assert.strictEqual(wrong.json.ok, false);
    assert.strictEqual(right.status, 200, right.raw.slice(0, 400));
    assert.strictEqual(right.json.imported.length, 1, right.raw);
    assert.strictEqual(right.json.imported[0].status, "unassigned");
    assert.strictEqual(right.json.protection, "pre-shared");
    const text = wrong.raw + right.raw;
    [made.secret.toString("hex"), made.secret.toString("base64"),
     key.toString("hex")].forEach(function (needle) {
      assert.ok(text.indexOf(needle) < 0, "an answer carried " + needle);
    });
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(text), text.slice(0, 400));
  });
  const tokenKey = right.json && right.json.imported[0]
    ? right.json.imported[0].key : "";

  let hotpPolicy = null;
  let hotpRestored = false;
  try {
    log.info("=== c. listing and assignment ===");
    hotpPolicy = await allowHotp();
    assert.ok(hotpPolicy.ok, "the hotp row could not be turned on: " +
              hotpPolicy.detail);
    const listed = await send("GET", OPERATION + "/oath?q=" +
                              encodeURIComponent(serial));
    await send("POST", "/admin-api/users/create", { json: {
      username: person, invent: false,
      attributes: { cn: "OATH " + person, sn: person } } });
    const assigned = await send("POST", OPERATION + "/assign-oath",
      { json: { key: tokenKey, username: person } });
    const again = await send("POST", OPERATION + "/assign-oath",
      { json: { key: tokenKey, username: person } });
    const removeAssigned = await send("POST", OPERATION + "/remove-oath",
      { json: { key: tokenKey } });
    const unknown = await send("POST", OPERATION + "/assign-oath",
      { json: { key: "run-vendor/no-such-" + RUN + "/1", username: person } });
    const after = await send("GET", OPERATION + "/oath?q=" +
                             encodeURIComponent(serial));
    check("the token is listed unassigned, assigned to the person, and " +
          "refused a second assignment and a removal while assigned; an " +
          "unknown token is 404", function () {
      assert.strictEqual(listed.status, 200, listed.raw.slice(0, 300));
      assert.ok(listed.json.tokens.some(function (r) {
        return r.key === tokenKey && r.status === "unassigned";
      }), listed.raw.slice(0, 400));
      assert.strictEqual(assigned.status, 200, assigned.raw.slice(0, 400));
      assert.strictEqual(assigned.json.token.holder, person);
      assert.strictEqual(again.status, 409, again.raw.slice(0, 300));
      assert.strictEqual(removeAssigned.status, 409,
                         removeAssigned.raw.slice(0, 300));
      assert.strictEqual(unknown.status, 404, unknown.raw.slice(0, 300));
      assert.ok(after.json.tokens.some(function (r) {
        return r.key === tokenKey && r.status === "assigned" &&
               r.holder === person;
      }), after.raw.slice(0, 400));
    });

    log.info("=== d. lost, retired and removed ===");
    const lost = await send("POST", OPERATION + "/lost",
      { json: { key: "run-vendor/" + serial } });
    const retired = await send("GET", OPERATION + "/oath?status=retired&q=" +
                               encodeURIComponent(serial));
    const removed = await send("POST", OPERATION + "/remove-oath",
      { json: { key: tokenKey } });
    check("reporting its hardware token lost retires it, and the retired " +
          "row is removed", function () {
      assert.strictEqual(lost.status, 200, lost.raw.slice(0, 400));
      assert.ok((lost.json.retired || []).some(function (r) {
        return r.kind === "hotp" && r.ref === tokenKey;
      }), lost.raw.slice(0, 400));
      assert.ok(retired.json.tokens.some(function (r) {
        return r.key === tokenKey;
      }), retired.raw.slice(0, 400));
      assert.strictEqual(removed.status, 200, removed.raw.slice(0, 300));
    });
    if (hotpPolicy && hotpPolicy.ok) {
      await restoreHotp(hotpPolicy);
      hotpRestored = true;
    }
  } finally {
    if (hotpPolicy && hotpPolicy.ok && !hotpRestored) {
      try {
        await restoreHotp(hotpPolicy);
      } catch (e) {
        log.debug("Caught in test(): " + ((e && e.message) || e));
        // The original failure is still the one that leaves test(). A
        // second throw here would hide it.
        log.error("the authentication policy could not be put back: " +
                  ((e && e.message) || e));
      }
    }
  }

  log.info(checks + " checks passed.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_oath_tokens")
  .description("Imported OATH tokens over HTTP (#1955 P4).")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().then(function () {
  process.exit(0);
}, function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
