// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: sts_openpgp_card_mail.js
//
// ---------------------------------------------------------------------------
// OpenPGP MAIL BETWEEN TWO PEOPLE, THE KEY ON A CARD (#2057, umbrella
// #2055). rcbj's "realistic tests": GnuPG, postfix and the virtual OpenPGP
// card in the client lab (tests/CLAUDE.md, *THE CLIENT LAB*), against a
// running service. sts_openpgp.js registers keys and reads the Web Key
// Directory with bytes made in node; here a person and their
// correspondent use the programs they would.
//
//   a. THE RECIPIENT'S KEY IS GENERATED ON THE CARD (`gpg --card-edit`:
//      the PIN changed from the factory's, key-attr NIST P-384, generate),
//      the portal's challenge (/account-api/openpgp) is signed with
//      `gpg --clearsign` ON THE CARD, and the key is registered and
//      published, and mail to them set to be encrypted with it;
//   b. THE SENDER, a second GnuPG home with no card, finds the key BY NAME:
//      `gpg --auto-key-locate clear,wkd,nodefault --locate-keys`, dirmngr
//      fetching https://openpgpkey.<domain>/.well-known/openpgpkey/... The
//      domain is one only this job uses; in the lab openpgpkey.<domain>
//      resolves to the service (bin/lab-hosts), and the service answers it
//      on a custom listener (port 443, the name in its certificate, issued
//      by the service's own CA, whose Root is in the lab's trust store,
//      bin/lab-trust-anchor), with the Certificate authority application
//      (where the Web Key Directory is) mapped onto it. The listener and the
//      mapping are the service's; both are put back as they were;
//   c. the sender encrypts (gpg) and sends a PGP/MIME message (RFC 3156)
//      with sendmail; postfix in the lab delivers it to the recipient's
//      mailbox (bin/lab-postfix); the recipient decrypts it ON THE CARD;
//   d. THIS SERVICE'S OWN MAIL: the realm's SMTP transport points at the
//      lab's postfix (STARTTLS, its CA on the volume both share); the
//      recipient asks for an emailed sign-in code; the message arrives
//      PGP/MIME, multipart/encrypted under a neutral subject, is decrypted
//      ON THE CARD, and the code in it signs them in;
//   e. with the card taken out of its reader (bin/lab-openpgp-card) the
//      same message no longer decrypts;
//   f. the recipient withdraws the key from the directory: the Web Key
//      Directory URL answers 404 and a fresh sender cannot find the key.
//
// The realm runs in the stack's mode. Every key, PIN change and
// certificate is made in the run; the card is replaced by a factory-fresh
// one at the end. `local: true`, `clientLab: true`: SKIPPED by the runner
// where there is no CLIENT_LAB_URL. Port 443 is taken on the service for
// the job's length, so a second copy of this job cannot run beside it.
// ---------------------------------------------------------------------------

"use strict";

const assert = require("assert");
const nodeCrypto = require("crypto");
const fs = require("fs");
const lab = require("./client_lab.js");
const names = require("./random_username.js");
const portal = require("./portal_signin.js");
const authnSignin = require("./authn_signin.js");
const ownPassword = require("./own_password");

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
var log = bunyan.createLogger({ name: "sts_openpgp_card_mail",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const LAB_BASE = String(process.env.CLIENT_LAB_STS_URL || base)
  .replace(/\/+$/, "");
// The lab's postfix, as the service reaches it, and the shared volume both
// mount (docker-compose-run-tests.yml's sts-test-shared).
const LAB_SMTP_HOST = process.env.CLIENT_LAB_SMTP_HOST || "client-lab";
const SHARED = process.env.CLIENT_LAB_SHARED_DIR || "/run/sts-test";
const STAMP = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "")
  .slice(-10);
const REALM = "pgpmail" + STAMP;
const DOMAIN = REALM + ".example.net";
const WKD_HOST = "openpgpkey." + DOMAIN;
const RECIPIENT = ("pr" + STAMP).slice(0, 24);
const ADDRESS = RECIPIENT + "@" + DOMAIN;
const SENDER = "Sender " + STAMP + " <ps" + STAMP + "@client-lab>";
const PASSWORD = "OpenPgp-Card-Mail9!x";
// The card's PINs: the factory's, and the one the person sets. The user PIN
// is set to the Admin PIN's value so that whichever of the two gpg asks for
// at a step (it depends on what scdaemon already holds), the answer is the
// same; a person who did the same would still be asked for each.
const FACTORY_PIN = "123456";
const PIN = "12345678";
const LISTENER = "wkd" + STAMP.slice(-8);
const DIR = "pgp-" + STAMP;
const RECIPIENT_HOME = DIR + "/recipient-gnupg";
const SENDER_HOME = DIR + "/sender-gnupg";
const LATE_HOME = DIR + "/late-sender-gnupg";
const MAIL_CA = SHARED + "/client-lab/" + STAMP + "/mail-ca.pem";

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

// ---------------------------------------------------------------------------
// GnuPG in the lab. A card step goes through bin/lab-gpg-answer, which
// answers gpg's prompts by the keyword gpg names.
// ---------------------------------------------------------------------------
function gpgEnv(home) {
  log.debug("Entering gpgEnv().");
  log.debug("Leaving gpgEnv().");
  return { GNUPGHOME: lab.work(home) };
}

function answered(home, lines, hidden, gpgArgs, extra) {
  log.debug("Entering answered().");
  let args = [];
  Object.keys(lines).forEach(function (k) {
    args = args.concat(["--line", k + "=" + lines[k]]);
  });
  if (hidden) {
    args = args.concat(["--hidden", hidden]);
  }
  log.debug("Leaving answered().");
  return lab.run("lab-gpg-answer", args.concat(["--"]).concat(gpgArgs),
    Object.assign({ env: gpgEnv(home), timeoutMs: 300000 }, extra || {}));
}

async function cardKeyOnTheCard() {
  log.debug("Entering cardKeyOnTheCard().");
  await lab.must("lab-gnupg-home", [lab.work(RECIPIENT_HOME)]);
  const pin = await answered(RECIPIENT_HOME,
    { "cardedit.prompt": "admin,passwd,quit",
      "cardutil.change_pin.menu": "1,q" },
    [FACTORY_PIN, PIN, PIN].join(","), ["--card-edit"]);
  assert.strictEqual(pin.code, 0, pin.stdout.slice(-1200));
  const attr = await answered(RECIPIENT_HOME,
    { "cardedit.prompt": "admin,key-attr,quit",
      "cardedit.genkeys.algo": "2", "keygen.curve": "4" },
    PIN, ["--card-edit"]);
  assert.strictEqual(attr.code, 0, attr.stdout.slice(-1200));
  const made = await answered(RECIPIENT_HOME,
    { "cardedit.prompt": "admin,generate,quit",
      "cardedit.genkeys.backup_enc": "n", "keygen.valid": "0",
      "keygen.name": "Recipient " + STAMP, "keygen.email": ADDRESS,
      "keygen.comment": "" },
    PIN, ["--card-edit"]);
  const status = await lab.must("gpg", ["--card-status", "--with-colons"],
                                { env: gpgEnv(RECIPIENT_HOME) });
  const created = /\[GNUPG:\] KEY_CREATED \S+ ([0-9A-F]{40})/
    .exec(made.stdout);
  log.debug("Leaving cardKeyOnTheCard().");
  return { made: made, status: status.stdout,
           fingerprint: created ? created[1] : "" };
}

// The armored PGP message in a text, or "".
function armoredIn(text) {
  log.debug("Entering armoredIn().");
  const m = /-----BEGIN PGP MESSAGE-----[\s\S]*?-----END PGP MESSAGE-----/
    .exec(String(text || ""));
  log.debug("Leaving armoredIn().");
  return m ? m[0].replace(/\r\n/g, "\n") + "\n" : "";
}

async function decryptOnTheCard(name, armored) {
  log.debug("Entering decryptOnTheCard(). " + name);
  await lab.put(DIR + "/" + name + ".asc", armored);
  const out = lab.work(DIR + "/" + name + ".out");
  const answer = await answered(RECIPIENT_HOME, {}, PIN, ["--yes",
    "--output", out, "--decrypt", lab.work(DIR + "/" + name + ".asc")],
    { timeoutMs: 120000 });
  let plain = "";
  if (/\[GNUPG:\] DECRYPTION_OKAY/.test(answer.stdout)) {
    plain = (await lab.get(DIR + "/" + name + ".out")).toString("utf8");
  }
  log.debug("Leaving decryptOnTheCard(). " + answer.code);
  return { answer: answer, plain: plain,
           okay: /\[GNUPG:\] DECRYPTION_OKAY/.test(answer.stdout) };
}

// The messages in an mbox, oldest first.
async function mailbox() {
  log.debug("Entering mailbox().");
  let text = "";
  try {
    text = (await lab.get(DIR + "/postfix/mail/" + RECIPIENT))
      .toString("utf8");
  } catch (e) {
    log.debug("Caught in mailbox(): " + ((e && e.message) || e));
    // Nothing delivered yet: no mbox file.
    text = "";
  }
  log.debug("Leaving mailbox().");
  return text ? text.split(/\n(?=From \S+ )/) : [];
}

async function arrived(what, test) {
  log.debug("Entering arrived(). " + what);
  const until = Date.now() + 60000;
  while (Date.now() < until) {
    const hit = (await mailbox()).filter(test)[0];
    if (hit) {
      log.debug("Leaving arrived().");
      return hit;
    }
    await pause(1000);
  }
  const log2 = await lab.run("curl", ["-s", "file://" +
    lab.work(DIR + "/postfix/maillog")]);
  log.debug("Leaving arrived(). Never.");
  throw new Error(what + " never reached the recipient's mailbox; " +
                  "postfix's log ends: " + String(log2.stdout).slice(-1500));
}

function headerOf(message, name) {
  log.debug("Entering headerOf(). " + name);
  const head = String(message).split(/\r?\n\r?\n/)[0].replace(/\r?\n[ \t]+/g,
                                                                " ");
  const m = new RegExp("^" + name + ":\\s*(.*)$", "im").exec(head);
  log.debug("Leaving headerOf().");
  return m ? m[1].trim() : "";
}

// A decrypted MIME entity's text: base64 and quoted-printable parts decoded.
function textOf(entity) {
  log.debug("Entering textOf().");
  const out = [String(entity)];
  const parts = String(entity).split(/\r?\n--[^\r\n]+\r?\n/);
  parts.forEach(function (part) {
    const cte = /content-transfer-encoding:\s*(\S+)/i.exec(part);
    const body = part.split(/\r?\n\r?\n/).slice(1).join("\n\n");
    if (cte && /base64/i.test(cte[1])) {
      out.push(Buffer.from(body.replace(/[^A-Za-z0-9+/=]/g, ""), "base64")
        .toString("utf8"));
    } else if (cte && /quoted-printable/i.test(cte[1])) {
      out.push(body.replace(/=\r?\n/g, "").replace(/=([0-9A-F]{2})/g,
        function (all, h) {
          return String.fromCharCode(parseInt(h, 16));
        }));
    }
  });
  log.debug("Leaving textOf().");
  return out.join("\n");
}

// ---------------------------------------------------------------------------
// The service's custom listener for openpgpkey.<domain>, and the mapping of
// the Certificate authority application (which holds the Web Key
// Directory) onto it. Both put back exactly as they were found.
// ---------------------------------------------------------------------------
let restore = null;

async function wkdListener() {
  log.debug("Entering wkdListener().");
  const got = await send(base + "/admin-api/listeners");
  assert.strictEqual(got.status, 200, got.raw.slice(0, 300));
  const defs = got.body.definitions || {};
  const before = { listeners: String(defs.listeners || ""),
                   applications: String(defs.applications || "") };
  const listeners = before.listeners ? JSON.parse(before.listeners) : [];
  const applications = before.applications
    ? JSON.parse(before.applications) : {};
  const pki = applications.pki || { listeners: ["main"],
                                    advertised: "main" };
  listeners.push({ id: LISTENER, port: 443,
                   publicBaseUrl: "https://" + WKD_HOST,
                   hostnames: [WKD_HOST] });
  applications.pki = { listeners: pki.listeners.concat([LISTENER]),
                       advertised: pki.advertised || "main" };
  const set = await postJson(base + "/admin-api/listeners/set-listeners",
                             { value: listeners });
  if (set.status !== 200) {
    log.debug("Leaving wkdListener(). Refused.");
    return { ok: false, why: set.raw.slice(0, 400) };
  }
  restore = before;
  await ok(base + "/admin-api/listeners/set-applications",
           { value: applications },
           "mapped the Certificate authority onto " + LISTENER);
  log.debug("Leaving wkdListener().");
  return { ok: true };
}

async function restoreListener() {
  log.debug("Entering restoreListener().");
  if (!restore) {
    log.debug("Leaving restoreListener(). Nothing to put back.");
    return;
  }
  await ok(base + "/admin-api/listeners/set-applications",
           { value: restore.applications }, "put the mapping back");
  await ok(base + "/admin-api/listeners/set-listeners",
           { value: restore.listeners }, "put the listeners back");
  restore = null;
  log.debug("Leaving restoreListener().");
}

async function setUp() {
  log.debug("Entering setUp().");
  await ok(base + "/admin-api/realms/create", { id: REALM, domain: DOMAIN,
    name: "OpenPGP card mail " + STAMP, overrides: {
      "authn.allowOptionalSecondFactor": "true",
      "risk.assessSignIns": "false",
      "openpgp.wkd": "true" } },
    "created the realm " + REALM);
  const rb = base + "/realm/" + REALM;
  await ok(rb + "/admin-api/users/create", { username: RECIPIENT,
    invent: false, credential: "password",
    password: ownPassword.temporaryFor(PASSWORD),
    attributes: { cn: "Recipient " + STAMP, sn: RECIPIENT,
                  givenName: "Recipient", mail: ADDRESS } },
    "created " + RECIPIENT);
  // THE PASSWORD IS THE PERSON'S OWN (#2160): a typed one is temporary in
  // product, so they choose PASSWORD at the sign-in screen
  // (`own_password.js`; in development it is simply set).
  await ownPassword.ownPassword(rb, RECIPIENT, PASSWORD,
    function (who, value) {
      return postJson(rb + "/admin-api/users/set-password",
                      { user: who, password: value });
    });
  log.debug("Leaving setUp().");
  return rb;
}

async function openpgp(person, body) {
  log.debug("Entering openpgp(). " + (body ? body.action : "GET"));
  const r = body ? await person.api("POST", "/account-api/openpgp", body)
                 : await person.api("GET", "/account-api/openpgp");
  log.debug("Leaving openpgp(). " + r.status);
  return r;
}

async function locate(home) {
  log.debug("Entering locate().");
  await lab.must("lab-gnupg-home", [lab.work(home)]);
  // dirmngr asks the system's resolver, which reads /etc/hosts, where
  // openpgpkey.<domain> is.
  await lab.put(home + "/dirmngr.conf", "standard-resolver\n");
  const found = await lab.run("gpg", ["--batch", "--with-colons",
    "--auto-key-locate", "clear,wkd,nodefault", "--locate-keys", ADDRESS],
    { env: gpgEnv(home), timeoutMs: 120000 });
  log.debug("Leaving locate(). " + found.code);
  return found;
}

function fingerprintsOf(colons) {
  log.debug("Entering fingerprintsOf().");
  const out = [];
  String(colons || "").split("\n").forEach(function (line) {
    const f = line.split(":");
    if (f[0] === "fpr") {
      out.push(f[9]);
    }
  });
  log.debug("Leaving fingerprintsOf().");
  return out;
}

async function test() {
  log.debug("Entering test().");
  log.info("OpenPGP mail with the key on the card, realm " + REALM +
           ", Web Key Directory at " + WKD_HOST);
  await lab.ready(180000);
  const anchorFile = process.env.NODE_EXTRA_CA_CERTS || "";
  assert.ok(anchorFile && fs.existsSync(anchorFile), "the job needs the " +
            "service's TLS anchor in NODE_EXTRA_CA_CERTS");
  await lab.put(DIR + "/anchor.pem", fs.readFileSync(anchorFile));
  const rb = await setUp();
  const person = await portal.signInToThePortal(rb, RECIPIENT, log,
                                                { password: PASSWORD });

  log.info("=== the lab: the listener, the name, the anchor, postfix ===");
  const listener = await wkdListener();
  if (!listener.ok) {
    assert.match(listener.why, /cell/i, "the custom listener for " +
                 WKD_HOST + " was refused: " + listener.why);
    log.info("SKIPPED: this service runs as several cells, where no " +
             "custom listener may exist, so openpgpkey." + DOMAIN +
             " cannot be served by name (" + listener.why.slice(0, 160) +
             ")");
    log.debug("Leaving test(). Cells.");
    return;
  }
  await lab.must("lab-hosts", ["add", WKD_HOST,
                               new URL(LAB_BASE).hostname]);
  await lab.must("lab-trust-anchor", ["add", "sts-" + STAMP,
                                      lab.work(DIR + "/anchor.pem")]);
  await lab.must("lab-postfix", ["start", lab.work(DIR + "/postfix"),
                                 DOMAIN, MAIL_CA, RECIPIENT]);

  log.info("=== a. the key, generated on the card, registered ===");
  const card = await cardKeyOnTheCard();
  check("gpg --card-edit changes the PIN, sets NIST P-384 and generates " +
        "the key on the card; gpg --card-status shows it there",
        function () {
    assert.strictEqual(card.made.code, 0, card.made.stdout.slice(-1500));
    assert.match(card.fingerprint, /^[0-9A-F]{40}$/,
                 card.made.stdout.slice(-1500));
    // --card-status's `fpr:` row: the signature, decryption and
    // authentication keys' fingerprints, the first this primary key.
    assert.ok(card.status.toUpperCase().indexOf(card.fingerprint) >= 0,
              card.status);
    assert.match(card.status, /^keyattr:2:18:NIST P-384:/m, card.status);
  });
  const exported = await lab.must("gpg", ["--armor", "--export", ADDRESS],
                                  { env: gpgEnv(RECIPIENT_HOME) });
  const challenge = await openpgp(person, { action: "challenge" });
  const text = String((challenge.json && challenge.json.view &&
    challenge.json.view.challenge && challenge.json.view.challenge.text) ||
    "");
  const asked = text || String(((await openpgp(person)).json.challenge ||
                                {}).text || "");
  await lab.put(DIR + "/challenge.txt", asked);
  const signed = await answered(RECIPIENT_HOME, {}, PIN, ["--yes",
    "--local-user", ADDRESS, "--output", lab.work(DIR + "/signed.asc"),
    "--clearsign", lab.work(DIR + "/challenge.txt")]);
  const signedText = signed.code === 0
    ? (await lab.get(DIR + "/signed.asc")).toString("utf8") : "";
  const registered = await openpgp(person, { action: "register",
    publicKey: exported.stdout, signed: signedText });
  const published = await openpgp(person, { action: "publish" });
  const encrypted = await openpgp(person, { action: "mail-encryption",
                                            choice: "openpgp" });
  const view = (await openpgp(person)).json;
  check("the challenge is signed with gpg --clearsign on the card, and the " +
        "key is registered, published and chosen for mail", function () {
    assert.ok(asked.indexOf(ADDRESS) >= 0, asked);
    assert.strictEqual(signed.code, 0, signed.stdout.slice(-1200));
    assert.match(signedText, /BEGIN PGP SIGNED MESSAGE/);
    assert.strictEqual(registered.status, 200,
                       String(registered.text).slice(0, 400));
    assert.strictEqual(published.status, 200,
                       String(published.text).slice(0, 300));
    assert.strictEqual(encrypted.status, 200,
                       String(encrypted.text).slice(0, 300));
    assert.strictEqual(view.key.fingerprint, card.fingerprint.toLowerCase());
    assert.strictEqual(view.wkd.published, true, JSON.stringify(view.wkd));
    assert.strictEqual(view.mailEncryption.choice, "openpgp");
    assert.ok(String(view.wkd.url).indexOf("https://" + WKD_HOST + "/") === 0,
              view.wkd.url);
  });

  log.info("=== b. the sender finds it by name ===");
  const found = await locate(SENDER_HOME);
  check("gpg --auto-key-locate clear,wkd finds the recipient's key at " +
        WKD_HOST + ", over TLS the lab trusts, by name", function () {
    assert.strictEqual(found.code, 0, found.stderr.slice(-1500));
    assert.ok(fingerprintsOf(found.stdout).indexOf(card.fingerprint) >= 0,
              found.stdout.slice(0, 800) + found.stderr.slice(-600));
    // `clear,wkd,nodefault`: the keyring was empty and no other method was
    // allowed, so the directory is where it came from.
    assert.match(found.stderr, /imported: 1/, found.stderr.slice(-600));
  });

  log.info("=== c. encrypted, sent with sendmail, decrypted on the card ===");
  const secret = "A sealed note " + nodeCrypto.randomBytes(8)
    .toString("hex");
  await lab.put(DIR + "/note.txt", "Content-Type: text/plain; " +
                "charset=utf-8\n\n" + secret + "\n");
  await lab.must("gpg", ["--batch", "--yes", "--trust-model", "always",
    "--armor", "--recipient", ADDRESS, "--output",
    lab.work(DIR + "/note.asc"), "--encrypt", lab.work(DIR + "/note.txt")],
    { env: gpgEnv(SENDER_HOME) });
  const sealed = (await lab.get(DIR + "/note.asc")).toString("utf8");
  const boundary = "pgp-" + nodeCrypto.randomBytes(6).toString("hex");
  const subject = "A note " + STAMP;
  const message = "From: " + SENDER + "\nTo: " + ADDRESS +
    "\nSubject: " + subject + "\nMIME-Version: 1.0\n" +
    "Content-Type: multipart/encrypted; " +
    "protocol=\"application/pgp-encrypted\"; boundary=\"" + boundary +
    "\"\n\nThis is an OpenPGP/MIME encrypted message (RFC 3156).\n--" +
    boundary + "\nContent-Type: application/pgp-encrypted\n" +
    "Content-Description: PGP/MIME version identification\n\nVersion: 1\n" +
    "\n--" + boundary + "\nContent-Type: application/octet-stream; " +
    "name=\"encrypted.asc\"\nContent-Disposition: inline; " +
    "filename=\"encrypted.asc\"\n\n" + sealed + "\n--" + boundary + "--\n";
  const sent = await lab.run("sendmail", ["-t", "-i"], { stdin: message });
  const delivered = await arrived("the sender's note", function (m) {
    return headerOf(m, "Subject") === subject;
  });
  const opened = await decryptOnTheCard("note", armoredIn(delivered));
  check("sendmail hands it to postfix, which delivers it to the " +
        "recipient's mailbox, PGP/MIME, and the card decrypts it",
        function () {
    assert.strictEqual(sent.code, 0, sent.stderr);
    assert.match(headerOf(delivered, "Content-Type"),
                 /multipart\/encrypted/i);
    assert.ok(delivered.indexOf(secret) < 0, "the note is in the clear");
    assert.ok(opened.okay, opened.answer.stdout.slice(-1500));
    assert.ok(opened.plain.indexOf(secret) >= 0, opened.plain);
  });

  log.info("=== d. this service's own mail, an emailed sign-in code ===");
  await ok(rb + "/admin-api/config/set-many", {
    "mail.transport": "smtp", "mail.smtpHost": LAB_SMTP_HOST,
    "mail.smtpPort": "25", "mail.smtpTls": "starttls",
    "mail.smtpCaFile": MAIL_CA, "mail.smtpAuth": "none",
    "mail.ratePerCategory": "30", "mail.ratePerRecipient": "30" },
    "pointed the realm's SMTP transport at the lab's postfix");
  const policies = await send(rb + "/admin-api/policies");
  assert.strictEqual(policies.status, 200, policies.raw.slice(0, 300));
  await ok(rb + "/admin-api/policies/save-authn-policy",
           Object.assign({ profile: "default" }, policies.body.authn.defaults,
                         { emailCodePrimary: true }),
           "offered an emailed sign-in code");
  const screen = await fetch(rb + "/portal", { redirect: "manual" });
  await screen.text();
  const verifier = nodeCrypto.randomBytes(32).toString("base64url");
  const authorize = await fetch(rb + "/oauth2/authorize?" +
    new URLSearchParams({ response_type: "code",
      client_id: "sts-user-portal", redirect_uri: rb + "/portal/callback",
      scope: "openid account:manage",
      state: nodeCrypto.randomBytes(16).toString("base64url"),
      code_challenge: nodeCrypto.createHash("sha256").update(verifier)
        .digest("base64url"),
      code_challenge_method: "S256", resource: rb + "/account-api" })
      .toString(), { redirect: "manual" });
  await authorize.text();
  const login = new URL(String(authorize.headers.get("location") || ""), rb)
    .toString();
  const asking = await authnSignin.signIn(rb, login,
    { action: "email-code", username: RECIPIENT }, {});
  const coded = await arrived("this service's sign-in code", function (m) {
    return /multipart\/encrypted/i.test(headerOf(m, "Content-Type")) &&
      headerOf(m, "Subject") !== subject;
  });
  const codeOpened = await decryptOnTheCard("code", armoredIn(coded));
  const code = (/\b(\d{6})\b/.exec(textOf(codeOpened.plain)) || [])[1] || "";
  let done = null;
  if (asking.next === "mfa" && code) {
    const step = await authnSignin.step(asking.location,
                                        { cookie: asking.cookie });
    done = await authnSignin.stepAct(step, "email/code", { code: code });
  }
  check("the emailed code arrives PGP/MIME, under a neutral subject, " +
        "decrypts on the card, and signs the recipient in", function () {
    assert.strictEqual(asking.next, "mfa", JSON.stringify(asking)
      .slice(0, 400));
    assert.match(headerOf(coded, "Content-Type"),
                 /protocol="?application\/pgp-encrypted"?/i);
    assert.ok(!/code/i.test(headerOf(coded, "Subject")),
              "the subject says what is inside: " + headerOf(coded,
                                                              "Subject"));
    assert.ok(codeOpened.okay, codeOpened.answer.stdout.slice(-1500));
    assert.match(code, /^\d{6}$/, textOf(codeOpened.plain).slice(0, 600));
    assert.ok(done && done.next === "redirect",
              JSON.stringify(done || {}).slice(0, 400));
  });

  log.info("=== e. the card taken out ===");
  await lab.must("lab-openpgp-card", ["remove"]);
  const without = await decryptOnTheCard("note-again", armoredIn(delivered));
  check("with the card out of its reader the same message does not " +
        "decrypt", function () {
    assert.ok(!without.okay, without.answer.stdout.slice(-1200));
    assert.notStrictEqual(without.answer.code, 0);
    assert.ok(without.plain.indexOf(secret) < 0);
  });

  log.info("=== f. withdrawn from the directory ===");
  const withdrawn = await openpgp(person, { action: "withdraw" });
  const direct = await lab.run("curl", ["-s", "-o", "/dev/null", "-w",
    "%{http_code}", view.wkd.url]);
  const late = await locate(LATE_HOME);
  check("once withdrawn the directory answers 404 for the address, and a " +
        "sender who never saw the key cannot find it", function () {
    assert.strictEqual(withdrawn.status, 200,
                       String(withdrawn.text).slice(0, 300));
    assert.strictEqual(String(direct.stdout).trim(), "404", direct.stderr);
    assert.ok(!/^pub:/m.test(late.stdout) &&
              fingerprintsOf(late.stdout).indexOf(card.fingerprint) < 0,
              late.stdout.slice(0, 400));
    assert.match(late.stderr, /No (public key|data)|not found/i,
                 late.stderr.slice(-600));
  });
  log.info("    the late sender's gpg said: " +
           String(late.stderr).trim().split("\n").slice(-2).join(" / "));
  log.debug("Leaving test().");
}

async function cleanUp() {
  log.debug("Entering cleanUp().");
  const steps = [
    ["the listener", function () {
      return restoreListener();
    }],
    ["the name", function () {
      return lab.run("lab-hosts", ["remove", WKD_HOST]);
    }],
    ["the anchor", function () {
      return lab.run("lab-trust-anchor", ["remove", "sts-" + STAMP]);
    }],
    ["postfix", function () {
      return lab.run("lab-postfix", ["stop"]);
    }],
    ["the card", function () {
      return lab.run("lab-openpgp-card", ["fresh"]);
    }]
  ];
  for (const one of steps) {
    try {
      await one[1]();
    } catch (e) {
      log.debug("Caught in cleanUp(): " + ((e && e.message) || e));
      // Each is tidied on its own; the verdict is the test's.
      log.info("could not put back " + one[0] + ": " +
               ((e && e.message) || e));
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
    // Reported below, after the service and the lab are put back.
    failure = e;
  }
  await cleanUp();
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
