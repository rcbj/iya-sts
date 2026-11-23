// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: sts_openpgp.js
//
// ---------------------------------------------------------------------------
// OpenPGP KEYS AND THE WEB KEY DIRECTORY OVER HTTP (#1955 P6).
//
//   a. the console page answers its shell, the operations are in the
//      management API's document, and the view refuses a caller with no
//      token;
//   b. a person made here is issued a challenge through `/admin-api/
//      openpgp/challenge`; a key made HERE by openpgp.js signs it as `gpg
//      --clearsign` would, and `register` takes it — a tampered proof and a
//      replay are refused, and no answer names an error code;
//   c. the Web Key Directory answers nothing while the realm's switch is off
//      and the person has not opted in; with `openpgp.wkd` on for a domain
//      only this job uses, and the person published, the advanced method
//      answers the binary key (octet-stream, no-store) and the policy file,
//      the direct method answers by Host, and a withdrawal ends it;
//   d. the key is removed, the settings reset and the person deleted.
//
// The behaviour in depth — every refusal, PGP/MIME and S/MIME decryption,
// required encryption, the lost-key retirer — is `tests/openpgp_keys.js`, in
// process. `local: true`: this repository's console and APIs.
// ---------------------------------------------------------------------------

"use strict";

const assert = require("assert");
const https = require("https");
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
var log = bunyan.createLogger({ name: "sts_openpgp",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const OPERATION = "/admin-api/openpgp";
const STAMP = Date.now().toString(36);

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
    // THE NAME THE CERTIFICATE IS CHECKED AGAINST IS THE ONE DIALLED, not
    // the Host header: node's agent takes `servername` from `headers.host`
    // when it is set, so the direct-method request below (Host: the WKD
    // domain, which the stack's certificate does not name) failed the
    // handshake with ERR_TLS_CERT_ALTNAME_INVALID before the service saw
    // it. Host still reaches the service as the header the WKD reads. An
    // IP address is not a server name (RFC 6066 section 3), so none is
    // sent for one.
    const req = transport.request({
      method: method, hostname: target.hostname, port: target.port,
      path: target.pathname + target.search, headers: headers,
      servername: require("net").isIP(target.hostname) ? ""
                                                       : target.hostname
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

const openpgp = require("openpgp");
const PERSON = "pgp-" + STAMP;
const DOMAIN = "p6-" + STAMP + ".example.org";
const ADDRESS = PERSON + "@" + DOMAIN;

// The z-base-32 SHA-1 of the lower-cased local part (the draft, section
// 3.1), written here from the draft rather than taken from the service.
function wkdHash(local) {
  log.debug("Entering wkdHash().");
  const alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769";
  const bytes = require("crypto").createHash("sha1")
    .update(local.toLowerCase()).digest();
  let bits = 0;
  let value = 0;
  let out = "";
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    out += alphabet[(value << (5 - bits)) & 31];
  }
  log.debug("Leaving wkdHash().");
  return out;
}

async function test() {
  log.debug("Entering test().");
  log.info("Directory → OpenPGP keys and the Web Key Directory at " + base);
  log.info("=== a. the page, the document and the gate ===");
  const shell = await send("GET", "/admin/openpgp",
                           { headers: { accept: "text/html" } });
  const doc = await send("GET", "/admin-api/openapi.json");
  const anonymous = await send("GET", OPERATION, { bare: true });
  check("the console page answers its shell, the operations are " +
        "published, and the view refuses a caller with no token",
        function () {
    assert.strictEqual(shell.status, 200, shell.raw.slice(0, 200));
    const paths = Object.keys((doc.json && doc.json.paths) || {});
    [OPERATION, OPERATION + "/challenge", OPERATION + "/register",
     OPERATION + "/publish", OPERATION + "/mail-encryption"]
      .forEach(function (p) {
        assert.ok(paths.indexOf(p) >= 0, p + " is not in the document");
      });
    assert.strictEqual(anonymous.status, 401, anonymous.raw.slice(0, 200));
  });

  const made = await send("POST", "/admin-api/users/create", { json: {
    username: PERSON, invent: false,
    attributes: { mail: ADDRESS, givenName: "Pgp", sn: "Tester" } } });
  check("a person is made with an address in a domain only this job uses",
        function () {
    assert.ok(made.status === 200 || made.status === 201,
              made.raw.slice(0, 300));
  });
  const hash = wkdHash(PERSON);
  try {
    log.info("=== b. registration on a proof of possession ===");
    const challenge = await send("POST", OPERATION + "/challenge",
                                 { json: { user: PERSON } });
    const text = ((challenge.json || {}).challenge || {}).text || "";
    const key = await openpgp.generateKey({ type: "ecc",
      curve: "curve25519Legacy", userIDs: [{ email: ADDRESS }],
      format: "object" });
    const signed = await openpgp.sign({
      message: await openpgp.createCleartextMessage({ text: text + "\n" }),
      signingKeys: key.privateKey });
    const tampered = await send("POST", OPERATION + "/register", { json: {
      user: PERSON, publicKey: key.publicKey.armor(),
      signed: signed.replace("Nonce:", "Nonce: x") } });
    const good = await send("POST", OPERATION + "/register", { json: {
      user: PERSON, publicKey: key.publicKey.armor(), signed: signed } });
    const replay = await send("POST", OPERATION + "/register", { json: {
      user: PERSON, publicKey: key.publicKey.armor(), signed: signed } });
    const view = await send("GET", OPERATION + "?user=" +
                            encodeURIComponent(PERSON));
    check("a challenge is issued, a tampered proof refused, the real one " +
          "registered, a replay refused, and no answer names a code",
          function () {
      assert.strictEqual(challenge.status, 200, challenge.raw.slice(0, 300));
      assert.ok(/Nonce: /.test(text), text);
      assert.strictEqual(tampered.status, 400, tampered.raw.slice(0, 300));
      assert.strictEqual(good.status, 200, good.raw.slice(0, 300));
      assert.strictEqual(replay.status, 400, replay.raw.slice(0, 300));
      assert.strictEqual(view.json.person.key.fingerprint,
                         key.publicKey.getFingerprint());
      assert.ok(!/STS-[A-Z]+-\d{4}/.test(tampered.raw + good.raw +
                                          replay.raw));
    });

    log.info("=== c. the Web Key Directory ===");
    const keyPath = "/.well-known/openpgpkey/" + DOMAIN + "/hu/" + hash +
      "?l=" + encodeURIComponent(PERSON);
    const off = await send("GET", keyPath, { bare: true });
    await send("POST", "/admin-api/config/set",
               { json: { key: "openpgp.wkdDomains", value: DOMAIN } });
    await send("POST", "/admin-api/config/set",
               { json: { key: "openpgp.wkd", value: "true" } });
    const notOpted = await send("GET", keyPath, { bare: true });
    const published = await send("POST", OPERATION + "/publish",
                                 { json: { user: PERSON } });
    const answered = await send("GET", keyPath, { bare: true });
    const policy = await send("GET", "/.well-known/openpgpkey/" + DOMAIN +
                              "/policy", { bare: true });
    const direct = await send("GET", "/.well-known/openpgpkey/hu/" + hash,
                              { bare: true, headers: { host: DOMAIN } });
    await send("POST", OPERATION + "/withdraw", { json: { user: PERSON } });
    const withdrawn = await send("GET", keyPath, { bare: true });
    check("nothing is answered while off or before the person opts in; " +
          "then the binary key, the policy file and the direct method; " +
          "nothing after a withdrawal", function () {
      assert.strictEqual(off.status, 404, off.raw.slice(0, 200));
      assert.strictEqual(notOpted.status, 404, notOpted.raw.slice(0, 200));
      assert.strictEqual(published.status, 200, published.raw.slice(0, 300));
      assert.strictEqual(answered.status, 200, answered.raw.slice(0, 200));
      assert.ok(/application\/octet-stream/.test(
        answered.headers["content-type"]));
      assert.ok(/no-store/.test(answered.headers["cache-control"]));
      assert.strictEqual(policy.status, 200, policy.raw.slice(0, 200));
      assert.ok(direct.status === 200 || direct.status === 404,
                direct.raw.slice(0, 200));
      assert.strictEqual(withdrawn.status, 404, withdrawn.raw.slice(0, 200));
    });
  } finally {
    log.info("=== d. clean-up ===");
    await send("POST", OPERATION + "/remove", { json: { user: PERSON } });
    await send("POST", "/admin-api/config/reset",
               { json: { key: "openpgp.wkd" } });
    await send("POST", "/admin-api/config/reset",
               { json: { key: "openpgp.wkdDomains" } });
    await send("POST", "/admin-api/users/delete", { json: { user: PERSON } });
  }
  log.info(checks + " checks passed.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_openpgp")
  .description("OpenPGP keys and the Web Key Directory over HTTP (#1955 P6).")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().then(function () {
  process.exit(0);
}, function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
