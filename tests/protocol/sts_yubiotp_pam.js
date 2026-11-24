// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: sts_yubiotp_pam.js
//
// ---------------------------------------------------------------------------
// YUBIKEY OTP THROUGH pam_yubico (#2061, umbrella #2055). rcbj's
// "realistic tests": Yubico's own PAM module, in the client lab
// (tests/CLAUDE.md, *THE CLIENT LAB*), asks this service's YK-VAL 2.0
// endpoint about OTPs a YubiKey would type. sts_yubiotp.js speaks the same
// protocol with bytes made in node; here every request and every check of
// the answer's signature is pam_yubico's (libykclient's).
//
// THE OTPs come from `ykgenerate`, the reference generator in Yubico's own
// OTP library (libyubikey, yubico-c): the same AES-128 block a YubiKey's
// keyboard emulation types, from a key, a private id and counters this job
// draws and hands it. That is the faithful stand-in for a key nobody can
// press here; nothing in this file or in the lab calls the service's OTP
// code. `ykparse` decrypts the first one and checks its CRC, so the
// generator is known to say what it is asked.
//
//   a. the administrator imports the token (a CSV made at run time) and
//      assigns it with one OTP, and creates a YK-VAL client through
//      /admin-api; the person's entry carries it in stsYubiOtpToken,
//      read with ldapsearch over LDAPS (no AES key, no private id);
//   b. a PAM service (`lab-pam-service`) runs pam_yubico with that
//      client's id and key, the realm's /wsapi/2.0/verify as its URL, the
//      service's TLS anchor as its CA, and an authfile mapping the person
//      to the token's public id; `pamtester … authenticate` with a fresh
//      OTP succeeds;
//   c. the same OTP again is refused (REPLAYED_OTP, in pam_yubico's own
//      debug log), and so are an OTP the token's key did not make
//      (BAD_OTP) and, with the right OTP, a PAM service holding a wrong
//      client key (BAD_SIGNATURE);
//   d. the person reports the token lost on the portal's operation
//      (POST /account-api/tokens, `lost`): the next OTP the key makes is
//      refused, and the value on the entry, the master, says retired.
//
// The realm runs in the stack's mode, with the YubiKey OTP settings and the
// authentication policy's yubico-otp row on in it alone. `local: true`,
// `clientLab: true`: SKIPPED by the runner where there is no CLIENT_LAB_URL.
// ---------------------------------------------------------------------------

"use strict";

const assert = require("assert");
const nodeCrypto = require("crypto");
const fs = require("fs");
const lab = require("./client_lab.js");
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
var log = bunyan.createLogger({ name: "sts_yubiotp_pam",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
// The service as the lab reaches it: the same URL by default, the lab being
// on the stack's network.
const LAB_BASE = String(process.env.CLIENT_LAB_STS_URL || base)
  .replace(/\/+$/, "");
const STAMP = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "")
  .slice(-10);
const REALM = "ykpam" + STAMP;
const DOMAIN = REALM + ".example.net";
const PERSON = ("yk" + STAMP).slice(0, 24);
const ADMIN = ("yka" + STAMP).slice(0, 24);
const PASSWORD = "YubiKey-Pam-Otp9!x";
const DIR = "yk-" + STAMP;
const SERVICE = "lab-yk-" + STAMP;
const WRONG_SERVICE = "lab-ykbad-" + STAMP;
const MODHEX = "cbdefghijklnrtuv";

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
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
  return { status: response.status, body: body, raw: raw };
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

// A public id is any six bytes in modhex; YubiKeys' own start `cc`, and
// this one is drawn at random so no other run's token can answer for it.
function modhexOf(bytes) {
  log.debug("Entering modhexOf().");
  let out = "";
  for (const b of bytes) {
    out += MODHEX.charAt(b >> 4) + MODHEX.charAt(b & 0x0f);
  }
  log.debug("Leaving modhexOf().");
  return out;
}

function hex(n, width) {
  log.debug("Entering hex().");
  log.debug("Leaving hex().");
  return Number(n).toString(16).padStart(width, "0");
}

// ONE OTP AS THE KEY WOULD TYPE IT: the public id, then ykgenerate's
// 32-character token for this use counter and session counter, with a
// timestamp that advances as a key's does.
async function otp(token, use, session, aesKey) {
  log.debug("Entering otp().");
  token.clock += 8;
  const made = await lab.must("ykgenerate", [aesKey || token.aesKey,
    token.privateId, hex(use, 4), hex(token.clock & 0xffff, 4),
    hex((token.clock >> 16) & 0xff, 2), hex(session, 2)]);
  const text = token.publicId + String(made.stdout).trim();
  assert.match(text, /^[cbdefghijklnrtuv]{44}$/, text);
  log.debug("Leaving otp().");
  return text;
}

function pamConfig(id, key, url, dir) {
  log.debug("Entering pamConfig().");
  log.debug("Leaving pamConfig().");
  return "# " + SERVICE + ": pam_yubico against " + url + " (#2061)\n" +
    "auth required pam_yubico.so id=" + id + " key=" + key +
    " urllist=" + url + " authfile=" + lab.work(dir + "/authfile") +
    " cainfo=" + lab.work(dir + "/anchor.pem") +
    " debug debug_file=" + lab.work(dir + "/pam_yubico.log") + "\n" +
    "account required pam_permit.so\n";
}

async function pamtester(service, typed) {
  log.debug("Entering pamtester(). " + service);
  const answer = await lab.run("pamtester", ["-v", service, PERSON,
                                             "authenticate"],
                               { stdin: typed + "\n", timeoutMs: 60000 });
  log.debug("Leaving pamtester(). " + answer.code);
  return answer;
}

function authenticated(answer) {
  log.debug("Entering authenticated().");
  const text = String(answer.stdout) + String(answer.stderr);
  const yes = answer.code === 0 && /successfully authenticated/.test(text);
  log.debug("Leaving authenticated(). " + yes);
  return yes;
}

// A REFUSAL IS EITHER OF pam_yubico'S TWO: PAM_AUTH_ERR ("Authentication
// failure") for an answer it trusts that says no, and PAM_AUTHINFO_UNAVAIL
// ("cannot retrieve authentication info") for one it cannot trust, such as
// an answer whose signature does not verify under its key.
function refused(answer) {
  log.debug("Entering refused().");
  const text = String(answer.stdout) + String(answer.stderr);
  const yes = answer.code !== 0 &&
    /Authentication failure|cannot retrieve authentication info/i
      .test(text) && !/successfully authenticated/.test(text);
  log.debug("Leaving refused(). " + yes);
  return yes;
}

// The service's own record of each YK-VAL request (ykval.verify), newest
// first: its summary names the status it answered.
async function verifyRows(rb) {
  log.debug("Entering verifyRows().");
  const r = await send(rb + "/admin-api/audit?" + new URLSearchParams({
    action: "ykval.verify", per: "300" }).toString());
  assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
  log.debug("Leaving verifyRows().");
  return (r.body.events || []).map(function (one) {
    return String(one.summary || "");
  });
}

// What pam_yubico's own debug log says since `from` (its length before):
// the YK-VAL status it read out of the answer.
async function pamLogSince(from) {
  log.debug("Entering pamLogSince().");
  const text = (await lab.get(DIR + "/pam_yubico.log")).toString("utf8");
  log.debug("Leaving pamLogSince().");
  return text.slice(from);
}

async function pamLogLength() {
  log.debug("Entering pamLogLength().");
  const text = (await lab.get(DIR + "/pam_yubico.log")).toString("utf8");
  log.debug("Leaving pamLogLength().");
  return text.length;
}

function ldapsUrl() {
  log.debug("Entering ldapsUrl().");
  log.debug("Leaving ldapsUrl().");
  return process.env.CLIENT_LAB_LDAPS_URL ||
    ("ldaps://" + new URL(LAB_BASE).hostname + ":" +
     (process.env.STS_LDAPS_PORT || 636));
}

// stsYubiOtpToken on the person's entry, read with ldapsearch over LDAPS as
// the realm's administrator: each value the JSON it is.
async function entryTokens(adminDn, dn) {
  log.debug("Entering entryTokens().");
  const answer = await lab.must("ldapsearch", ["-LLL", "-o", "ldif-wrap=no",
    "-H", ldapsUrl(), "-D", adminDn, "-w", PASSWORD, "-b", dn, "-s", "base",
    "(objectClass=*)", "stsYubiOtpToken"],
    { env: { LDAPTLS_CACERT: lab.work(DIR + "/anchor.pem"),
             LDAPTLS_REQCERT: "demand" } });
  const values = [];
  String(answer.stdout).split("\n").forEach(function (line) {
    const plain = /^stsYubiOtpToken: (.*)$/i.exec(line);
    const coded = /^stsYubiOtpToken:: (.*)$/i.exec(line);
    if (plain) {
      values.push(plain[1]);
    } else if (coded) {
      values.push(Buffer.from(coded[1], "base64").toString("utf8"));
    }
  });
  log.debug("Leaving entryTokens(). " + values.length);
  return values;
}

async function setUp() {
  log.debug("Entering setUp().");
  await ok(base + "/admin-api/realms/create", { id: REALM, domain: DOMAIN,
    name: "YubiKey OTP through PAM " + STAMP, overrides: {
      // A product realm requires a second factor of everybody; an LDAP
      // simple bind and the portal's password sign-in here cannot give one.
      "authn.allowOptionalSecondFactor": "true",
      "risk.assessSignIns": "false",
      "yubiotp.offered": "true",
      "yubiotp.ykval": "true",
      // The CSV holds the AES key in the clear, as Yubico's personalization
      // tool writes it; the setting is what admits such a file.
      "yubiotp.allowPlaintextImport": "true" } },
    "created the realm " + REALM);
  const rb = base + "/realm/" + REALM;
  const dns = {};
  for (const who of [PERSON, ADMIN]) {
    dns[who] = String((await ok(rb + "/admin-api/users/create", {
      username: who, invent: false, credential: "password",
      password: PASSWORD,
      attributes: { cn: "YubiKey " + who, sn: who, givenName: "YubiKey",
                    mail: who + "@" + DOMAIN } }, "created " + who)).dn);
  }
  await ok(rb + "/admin-api/rbac/grant", { username: ADMIN, role: "read" },
           "granted " + ADMIN + " Admin Read on the realm's roster");
  // The yubico-otp row of the authentication policy is off by default; a
  // token is assigned only where it is on.
  const policies = await send(rb + "/admin-api/policies");
  assert.strictEqual(policies.status, 200, policies.raw.slice(0, 300));
  await ok(rb + "/admin-api/policies/save-authn-policy",
           Object.assign({ profile: "default" }, policies.body.authn.defaults,
                         { yubicoOtpSecondFactor: true }),
           "turned the yubico-otp row on");
  log.debug("Leaving setUp().");
  return { rb: rb, personDn: dns[PERSON], adminDn: dns[ADMIN] };
}

async function test() {
  log.debug("Entering test().");
  log.info("YubiKey OTP through pam_yubico, realm " + REALM);
  await lab.ready(180000);
  const anchorFile = process.env.NODE_EXTRA_CA_CERTS || "";
  assert.ok(anchorFile && fs.existsSync(anchorFile), "the job needs the " +
            "service's TLS anchor in NODE_EXTRA_CA_CERTS");
  await lab.put(DIR + "/anchor.pem", fs.readFileSync(anchorFile));
  await lab.put(DIR + "/pam_yubico.log", "");
  const s = await setUp();
  const rb = s.rb;

  // THE PERSON IS ON THE PORTAL BEFORE THE TOKEN IS THEIRS: once it is,
  // the sign-in asks for it as a second factor, which portal_signin.js's
  // password walk does not answer. Reporting it lost asks for a recent
  // sign-in, and this one is seconds old by then.
  const person = await portal.signInToThePortal(rb, PERSON, log,
                                                { password: PASSWORD });

  log.info("=== a. the token, imported and assigned; the YK-VAL client ===");
  const token = {
    serial: String(nodeCrypto.randomInt(10000000, 99999999)),
    publicId: modhexOf(nodeCrypto.randomBytes(6)),
    privateId: nodeCrypto.randomBytes(6).toString("hex"),
    aesKey: nodeCrypto.randomBytes(16).toString("hex"),
    clock: nodeCrypto.randomInt(0, 0x100000)
  };
  const first = await otp(token, 1, 0);
  const parsed = await lab.must("ykparse", [token.aesKey, first.slice(12)]);
  check("ykparse decrypts the first OTP ykgenerate made: this token's " +
        "private id, counter 1, a good CRC", function () {
    const text = String(parsed.stdout);
    assert.match(text, /crc check: ok/, text);
    assert.match(text, /counter: 1 \(0x0001\)/, text);
    assert.ok(text.replace(/\s+/g, "").indexOf("uid:" +
      token.privateId) >= 0, text);
  });
  const csv = "serial,public id,private id,aes key\n" +
    [token.serial, token.publicId, token.privateId, token.aesKey].join(",") +
    "\n";
  const imported = await ok(rb + "/admin-api/hardware-tokens/import-yubiotp",
                            { csv: csv }, "imported the token");
  const assigned = await ok(rb + "/admin-api/hardware-tokens/assign-yubiotp",
    { serial: token.serial, username: PERSON, otp: first },
    "assigned the token with one OTP");
  const client = await ok(rb + "/admin-api/hardware-tokens/ykval-client-add",
    { id: String(nodeCrypto.randomInt(100000, 999999)) },
    "created a YK-VAL client");
  const onEntry = await entryTokens(s.adminDn, s.personDn);
  check("the administrator imports the CSV, assigns the token to the " +
        "person and creates a YK-VAL client; the entry carries the token " +
        "in stsYubiOtpToken, read over LDAPS, with no secret", function () {
    assert.strictEqual(imported.imported.length, 1);
    assert.strictEqual(assigned.token.holder, PERSON);
    assert.strictEqual(assigned.token.status, "assigned");
    assert.ok(client.id && client.key, JSON.stringify(Object.keys(client)));
    assert.strictEqual(onEntry.length, 1, JSON.stringify(onEntry));
    const value = JSON.parse(onEntry[0]);
    assert.strictEqual(value.publicId, token.publicId, onEntry[0]);
    assert.strictEqual(String(value.serial), token.serial, onEntry[0]);
    assert.ok(onEntry[0].indexOf(token.aesKey) < 0 &&
              onEntry[0].indexOf(token.privateId) < 0, onEntry[0]);
  });

  log.info("=== b. pam_yubico signs the person in ===");
  const url = LAB_BASE + "/realm/" + REALM + "/wsapi/2.0/verify";
  await lab.put(DIR + "/authfile", PERSON + ":" + token.publicId + "\n");
  await lab.put(DIR + "/" + SERVICE, pamConfig(client.id, client.key, url,
                                                 DIR));
  await lab.must("lab-pam-service", ["install", SERVICE,
                                     lab.work(DIR + "/" + SERVICE)]);
  const typed = await otp(token, 1, 1);
  let mark = await pamLogLength();
  const login = await pamtester(SERVICE, typed);
  const loginLog = await pamLogSince(mark);
  check("pamtester authenticates the person with a fresh OTP; " +
        "pam_yubico's log has the service's OK", function () {
    assert.ok(authenticated(login), JSON.stringify(login).slice(0, 900) +
              "\n" + loginLog.slice(-1500));
    assert.match(loginLog, /ykclient return value \(0\): Success/,
                 loginLog.slice(-1500));
  });

  log.info("=== c. what pam_yubico is refused ===");
  mark = await pamLogLength();
  const replay = await pamtester(SERVICE, typed);
  const replayLog = await pamLogSince(mark);
  check("the same OTP again is refused: REPLAYED_OTP", function () {
    assert.ok(refused(replay), JSON.stringify(replay).slice(0, 900));
    assert.match(replayLog, /REPLAYED_OTP/, replayLog.slice(-1500));
  });
  mark = await pamLogLength();
  const forged = await pamtester(SERVICE, await otp(token, 2, 0,
    nodeCrypto.randomBytes(16).toString("hex")));
  const forgedLog = await pamLogSince(mark);
  check("an OTP with the token's public id that its key did not make is " +
        "refused: BAD_OTP", function () {
    assert.ok(refused(forged), JSON.stringify(forged).slice(0, 900));
    assert.match(forgedLog, /BAD_OTP/, forgedLog.slice(-1500));
  });
  const wrongKey = nodeCrypto.randomBytes(20).toString("base64");
  await lab.put(DIR + "/" + WRONG_SERVICE, pamConfig(client.id, wrongKey,
                                                       url, DIR));
  await lab.must("lab-pam-service", ["install", WRONG_SERVICE,
                                     lab.work(DIR + "/" + WRONG_SERVICE)]);
  mark = await pamLogLength();
  const unsigned = await pamtester(WRONG_SERVICE, await otp(token, 2, 1));
  const unsignedLog = await pamLogSince(mark);
  check("a PAM service holding the wrong client key is refused, the " +
        "right OTP notwithstanding: its request is BAD_SIGNATURE, and " +
        "pam_yubico will not trust the unsigned answer", function () {
    assert.ok(refused(unsigned), JSON.stringify(unsigned).slice(0, 900));
    assert.match(unsignedLog, /BAD_SERVER_SIGNATURE/,
                 unsignedLog.slice(-1500));
  });
  mark = await pamLogLength();
  const later = await pamtester(SERVICE, await otp(token, 3, 0));
  check("the next OTP the key makes still signs the person in", function () {
    assert.ok(authenticated(later), JSON.stringify(later).slice(0, 900));
  });

  const rows = await verifyRows(rb);
  check("the service's own audit rows say the same: OK, REPLAYED_OTP, " +
        "BAD_OTP, BAD_SIGNATURE, OK", function () {
    const said = rows.slice().reverse().map(function (summary) {
      const m = /: ([A-Z_]+)/.exec(summary);
      return m ? m[1] : summary;
    });
    assert.deepStrictEqual(said.slice(-5), ["OK", "REPLAYED_OTP", "BAD_OTP",
                                            "BAD_SIGNATURE", "OK"],
                           JSON.stringify(rows.slice(0, 8)));
  });

  log.info("=== d. the person reports the token lost ===");
  const listed = await person.api("GET", "/account-api/tokens");
  const held = ((listed.json && listed.json.tokens) || []).filter(
    function (one) {
      return String(one.key || "").indexOf(token.serial) >= 0;
    })[0];
  assert.ok(held, "the person's token list does not name the token: " +
            String(listed.text).slice(0, 400));
  const lost = await person.api("POST", "/account-api/tokens",
                                { action: "lost", key: held.key });
  mark = await pamLogLength();
  const afterLost = await pamtester(SERVICE, await otp(token, 4, 0));
  const lostLog = await pamLogSince(mark);
  const retired = await entryTokens(s.adminDn, s.personDn);
  check("the portal's lost report retires it: the next OTP the key makes " +
        "is refused, and the entry, the master, records it retired",
        function () {
    assert.strictEqual(lost.status, 200, String(lost.text).slice(0, 300));
    assert.ok(refused(afterLost), JSON.stringify(afterLost).slice(0, 900));
    // Its public identity is dropped, so the service knows no key that
    // made it: BAD_OTP.
    assert.match(lostLog, /\(BAD_OTP\)/, lostLog.slice(-1500));
    // The value stays, as the record of a token never to be assigned
    // again (docs/v1.2.0/hardware-tokens.md); the inventory's retired row
    // is rebuilt from it.
    assert.strictEqual(retired.length, 1, JSON.stringify(retired));
    const value = JSON.parse(retired[0]);
    assert.strictEqual(value.status, "retired", retired[0]);
    assert.ok(value.retiredAt, retired[0]);
    assert.strictEqual(value.publicId, token.publicId, retired[0]);
  });
  log.debug("Leaving test().");
}

async function cleanUp() {
  log.debug("Entering cleanUp().");
  for (const name of [SERVICE, WRONG_SERVICE]) {
    try {
      await lab.run("lab-pam-service", ["remove", name]);
    } catch (e) {
      log.debug("Caught in cleanUp(): " + ((e && e.message) || e));
      // The lab's own restart clears it; the verdict is the test's.
      log.info("could not remove the PAM service " + name);
    }
  }
  if (process.env.STS_TEST_REMOVE_REALMS === "1") {
    const response = await postJson(base + "/admin-api/realms/remove",
                                    { id: REALM });
    log.info("removed the realm " + REALM + " (" + response.status + ")");
  }
  log.debug("Leaving cleanUp().");
}

async function main() {
  log.debug("Entering main().");
  if (!lab.available()) {
    log.info("SKIPPED: no CLIENT_LAB_URL, so there is no client lab " +
             "(an AWS target, or ./run-coverage.sh).");
    log.debug("Leaving main(). No lab.");
    return;
  }
  let failure = null;
  try {
    await test();
  } catch (e) {
    log.debug("Caught in main(): " + ((e && e.message) || e));
    // Reported below, after the lab and the realm are tidied.
    failure = e;
  }
  try {
    await cleanUp();
  } catch (e) {
    log.debug("Caught in main() tidying up: " + ((e && e.message) || e));
    // A tidy-up that fails does not hide the test's own verdict.
    log.info("could not tidy up: " + ((e && e.message) || e));
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
