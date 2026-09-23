"use strict";
//
// File: sts_mail.js
//
// ===========================================================================
// THE MAIL CHANNEL OVER HTTP, DELIVERING TO A REAL SMTP SERVER (#63,
// 2026-09-22). `local: true` — written here, owned here (tests/CLAUDE.md).
//
// The stack runs Mailpit (MIT) beside the service, requiring STARTTLS with a
// certificate minted at run time into the directory the service shares with
// this runner; the service is told to trust it as `mail.smtpCaFile`. This job
// works in a PRODUCT-mode realm of its own, whatever mode the stack is in,
// because that is where every rule the channel has is in force, and it reads
// what arrived through Mailpit's HTTP API.
//
//   0. The realm: product mode, global.publicBaseUrl pinned to this service,
//      the SMTP transport pointed at the catcher. `capture` is refused there
//      (STS-MAIL-0003). A person with an address and a password.
//   1. A test message — delivered over STARTTLS (the catcher accepts nothing
//      else), From no-reply@ the realm's domain, Auto-Submitted, no image.
//   2. An address an ADMINISTRATOR provided is already verified (#64: an
//      administrator is a trusted source), so the verification an
//      administrator asks for sends nothing. The link flow — the pinned
//      origin, a GET that spends nothing, a form that spends it once — is
//      `sts_email_verification.js`'s now, through a person's own change of
//      address, which is where an unverified address comes from.
//   3. Forgot password: an unknown account and a known one get the SAME
//      page; only the known one is mailed; the link sets a new password; the
//      person is then told their password changed.
//   4. An administrator's reset link with `deliver: "mail"`: not returned,
//      mailed.
//   5. A dead letter: a transport that cannot talk to the catcher (implicit
//      TLS against its STARTTLS port) dead-letters with one attempt; fixed,
//      the retry is delivered.
//   6. The outbox lists what was sent, with no body.
//
// WHERE THERE IS NO CATCHER — an AWS target, the coverage run — the sections
// that need it SKIP and say so (`MAILPIT_API_URL` unset); section 0's refusal
// runs everywhere.
// ===========================================================================

const assert = require("assert");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");

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
var log = bunyan.createLogger({ name: "sts_mail",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const MAILPIT = String(process.env.MAILPIT_API_URL || "").replace(/\/+$/, "");
const SMTP_HOST = process.env.MAILPIT_SMTP_HOST || "mailpit";
const SMTP_PORT = process.env.MAILPIT_SMTP_PORT || "1025";
const CA_FILE = process.env.MAILPIT_CA_FILE ||
                "/run/sts-test/mailpit/server.crt";
const REALM = usernameFor("mail").replace(/[^a-z0-9-]/g, "").slice(0, 30);
const DOMAIN = REALM + ".example.net";
const PERSON = usernameFor("mailp").replace(/[^a-z0-9]/g, "").slice(0, 20);
const ADDRESS = PERSON + "@" + DOMAIN;
const PASSWORD = "Mail-" + String(Date.now()).slice(-8) + "-xQ9!pZ";
const NEW_PASSWORD = "Reset-" + String(Date.now()).slice(-8) + "-kW4#tR";

let checks = 0;
let skipped = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function skip(what, why) {
  log.debug("Entering skip().");
  skipped += 1;
  log.info("  [skip] " + what + " — " + why);
  log.debug("Leaving skip().");
}

function realmBase() {
  log.debug("Entering realmBase().");
  log.debug("Leaving realmBase().");
  return base + "/realm/" + REALM;
}

async function call(method, url, body, headers, form) {
  log.debug("Entering call().");
  const r = await fetch(url, { method: method, redirect: "manual",
    headers: Object.assign({ "Content-Type": form
      ? "application/x-www-form-urlencoded" : "application/json" },
                           headers || {}),
    body: body === undefined ? undefined : (form
      ? new URLSearchParams(body).toString()
      : (typeof body === "string" ? body : JSON.stringify(body))) });
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
    // Not JSON; `text` carries it into the message.
    json = null;
  }
  log.debug("Leaving call().");
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

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) { setTimeout(resolve, ms); });
}

async function until(what, fn, ms) {
  log.debug("Entering until().");
  const deadline = Date.now() + (ms || 30000);
  while (Date.now() < deadline) {
    const got = await fn();
    if (got) {
      log.debug("Leaving until(). Yes.");
      return got;
    }
    await sleep(500);
  }
  log.debug("Leaving until(). Timed out waiting for " + what + ".");
  return null;
}

// Every message the catcher holds for one address, newest first.
async function inbox(address) {
  log.debug("Entering inbox().");
  const r = await fetch(MAILPIT + "/api/v1/search?query=" +
                        encodeURIComponent("to:" + address));
  const json = await r.json();
  log.debug("Leaving inbox().");
  return (json && json.messages) || [];
}

// Waits for a message to `address` whose subject matches, and answers it
// whole (text, HTML, headers).
async function arrived(address, subject, seen) {
  log.debug("Entering arrived().");
  const summary = await until("a message \"" + subject + "\" to " + address,
    async function () {
      const all = await inbox(address);
      return all.filter(function (m) {
        return subject.test(m.Subject) && (seen || []).indexOf(m.ID) < 0;
      })[0] || null;
    });
  assert.ok(summary, "no message matching " + subject + " reached " +
            address + " in the catcher");
  const whole = await (await fetch(MAILPIT + "/api/v1/message/" +
                                   summary.ID)).json();
  const headers = await (await fetch(MAILPIT + "/api/v1/message/" +
                                     summary.ID + "/headers")).json();
  log.debug("Leaving arrived().");
  return { id: summary.ID, message: whole, headers: headers };
}

// The first link to this service's own origin in a message's text part.
function linkIn(message) {
  log.debug("Entering linkIn().");
  const found = new RegExp("(" + base.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") +
                           "/realm/" + REALM + "/portal/[^\\s]+)")
    .exec(String(message.Text || ""));
  log.debug("Leaving linkIn().");
  return found ? found[1] : "";
}

function hiddenValue(html, name) {
  log.debug("Entering hiddenValue().");
  const m = new RegExp('name="' + name + '" value="([^"]*)"').exec(html);
  log.debug("Leaving hiddenValue().");
  return m ? m[1].replace(/&amp;/g, "&") : "";
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving the mail channel at " + base + " in the realm " + REALM +
           (MAILPIT ? ", delivering to the catcher at " + MAILPIT
                    : "; there is no catcher (MAILPIT_API_URL is unset)"));

  // =========================================================================
  // 0. THE REALM
  // =========================================================================
  await ok(base + "/admin-api/realms/create",
           { id: REALM, domain: DOMAIN, name: "mail (#63)",
             overrides: { "global.mode": "product" } },
           "created the product realm");
  let r = await call("POST", realmBase() + "/admin-api/config/set",
                     { key: "mail.transport", value: "capture" });
  check("product: the capture transport is refused on write " +
        "(STS-MAIL-0003)", function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 300));
    assert.ok(/capture/.test(r.text), r.text.slice(0, 300));
  });
  // WHETHER THE STACK PINS THE BASE (2026-09-23). The single-node and cluster
  // stacks set global.publicBaseUrl (both nodes sit behind one balancer), and
  // a pinned base is exactly what product mails links under; only an
  // UNPINNED product realm has no link base at all.
  const settings = await call("GET", realmBase() + "/admin-api/config");
  const pinnedRow = ((settings.json && settings.json.groups) || [])
    .reduce(function (all, g) {
      return all.concat(g.settings || []);
    }, ((settings.json && settings.json.settings) || []))
    .filter(function (row) {
      return row.key === "global.publicBaseUrl";
    })[0];
  const pinned = String((pinnedRow && pinnedRow.value) || "").trim()
    .replace(/\/+$/, "");
  r = await call("GET", realmBase() + "/admin-api/mail");
  check("product: with nothing configured the transport is off, and a " +
        "link is mailed only under a pinned base", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.strictEqual(r.json.transport, "off");
    assert.strictEqual(r.json.linkBase, pinned
      ? pinned + "/realm/" + REALM : "",
      pinned ? "the pinned base and the realm's prefix"
             : "no unpinned link in product");
  });
  if (!MAILPIT) {
    skip("sections 1-6", "MAILPIT_API_URL is not set, so there is no mail " +
         "catcher to deliver to (an AWS target or the coverage run)");
    assert.ok(checks + skipped >= 3, "only " + checks + " checks ran");
    log.info("Test completed successfully.");
    log.debug("Leaving test().");
    return;
  }
  await ok(realmBase() + "/admin-api/config/set-many",
           { "mail.transport": "smtp", "mail.smtpHost": SMTP_HOST,
             "mail.smtpPort": SMTP_PORT, "mail.smtpTls": "starttls",
             "mail.smtpCaFile": CA_FILE, "mail.smtpAuth": "none",
             "mail.attempts": "1", "mail.ratePerCategory": "20",
             // THE ONE-FIELD FORM, which section 3 drives: the recovery
             // code form (#64, D4) is `sts_email_verification.js`'s.
             "mail.resetRequiresBackupCode": "false",
             "global.publicBaseUrl": base },
           "pointed the realm's SMTP transport at the catcher");
  r = await call("GET", realmBase() + "/admin-api/mail");
  check("the realm sends through smtp, links on the pinned origin",
        function () {
    assert.strictEqual(r.json.transport, "smtp", r.text.slice(0, 300));
    assert.strictEqual(r.json.linkBase, base + "/realm/" + REALM);
    assert.strictEqual(r.json.from, "no-reply@" + DOMAIN);
  });
  await ok(realmBase() + "/admin-api/users/create",
           { username: PERSON, invent: false,
             attributes: { mail: ADDRESS, givenName: "Mail", sn: "Tester" },
             credential: "password", password: PASSWORD,
             passwordConfirm: PASSWORD },
           "created " + PERSON + " with an address");

  // =========================================================================
  // 1. A TEST MESSAGE
  // =========================================================================
  await ok(realmBase() + "/admin-api/mail/test", { user: PERSON },
           "queued a test message");
  let got = await arrived(ADDRESS, /test message/);
  check("1. the test message was delivered to the entry's address — over " +
        "STARTTLS, which the catcher requires", function () {
    assert.strictEqual(got.message.To[0].Address, ADDRESS);
  });
  check("1. From is no-reply@ the realm's domain, and it says it was " +
        "sent automatically", function () {
    assert.strictEqual(got.message.From.Address, "no-reply@" + DOMAIN);
    assert.deepStrictEqual(got.headers["Auto-Submitted"],
                           ["auto-generated"]);
  });
  check("1. the HTML part loads nothing", function () {
    assert.ok(!/<img|<script|src=/i.test(String(got.message.HTML || "")),
              String(got.message.HTML || "").slice(0, 300));
  });
  const seen = [got.id];

  // =========================================================================
  // 2. ADDRESS VERIFICATION
  // =========================================================================
  r = await call("POST", realmBase() + "/admin-api/mail/verify",
                 { user: PERSON });
  check("2. the address an administrator created the account with is " +
        "already VERIFIED — an administrator is a trusted source (#64) — " +
        "so asking to verify it sends nothing", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.strictEqual(r.json.verified, true, r.text.slice(0, 300));
  });

  // =========================================================================
  // 3. FORGOT PASSWORD
  // =========================================================================
  r = await call("GET", realmBase() + "/portal/forgot-password");
  check("3. the forgot-password page is offered (product, a transport)",
        function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
  });
  const unknown = await call("POST", realmBase() + "/portal/forgot-password",
                             { account: "nobody-" + PERSON }, {}, true);
  const known = await call("POST", realmBase() + "/portal/forgot-password",
                           { account: ADDRESS }, {}, true);
  check("3. an unknown account and a known one get the same page",
        function () {
    assert.strictEqual(unknown.status, 200);
    assert.strictEqual(known.status, 200);
    const sentence = function (html) {
      log.debug("Entering sentence().");
      log.debug("Leaving sentence().");
      return (/<div class="ok">([^<]*)<\/div>/.exec(html) || [])[1];
    };
    assert.ok(sentence(known.text), known.text.slice(0, 400));
    assert.strictEqual(sentence(unknown.text), sentence(known.text));
  });
  got = await arrived(ADDRESS, /Reset your/, seen);
  seen.push(got.id);
  const resetLink = linkIn(got.message);
  check("3. the known account's verified address was sent a reset link",
        function () {
    assert.ok(resetLink.indexOf(base + "/realm/" + REALM +
                                "/portal/reset-password?") === 0, resetLink);
  });
  r = await call("GET", resetLink);
  check("3. the link opens the form", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
  });
  r = await call("POST", realmBase() + "/portal/reset-password",
                 { user: hiddenValue(r.text, "user"),
                   token: hiddenValue(r.text, "token"),
                   password: NEW_PASSWORD, confirm: NEW_PASSWORD }, {}, true);
  check("3. and sets a new password", function () {
    assert.ok(r.status === 200 || r.status === 303,
              r.status + " " + r.text.slice(0, 300));
  });
  got = await arrived(ADDRESS, /password was changed/, seen);
  seen.push(got.id);
  check("3. the person is told their password changed (a security notice)",
        function () {
    assert.strictEqual(got.message.To[0].Address, ADDRESS);
  });

  // =========================================================================
  // 4. AN ADMINISTRATOR'S RESET LINK, MAILED
  // =========================================================================
  r = await call("POST", realmBase() + "/admin-api/users/issue-password-reset",
                 { user: PERSON, deliver: "mail" });
  check("4. with deliver: mail the reset link is NOT returned", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.strictEqual(r.json.mailedTo, ADDRESS);
    assert.ok(!r.json.resetUrl, "resetUrl was returned");
  });
  got = await arrived(ADDRESS, /Reset your/, seen);
  seen.push(got.id);
  check("4. it was mailed, naming an administrator", function () {
    assert.ok(/an administrator/.test(String(got.message.Text)),
              String(got.message.Text).slice(0, 300));
  });

  // =========================================================================
  // 5. A DEAD LETTER, AND ITS RETRY
  // =========================================================================
  await ok(realmBase() + "/admin-api/config/set",
           { key: "mail.smtpTls", value: "implicit" },
           "broke the transport (implicit TLS on a STARTTLS port)");
  const queued = await ok(realmBase() + "/admin-api/mail/test",
                          { user: PERSON }, "queued a test message");
  const dead = await until("the message to be a dead letter",
    async function () {
      const o = await call("GET", realmBase() +
                           "/admin-api/mail/outbox?state=dead");
      return ((o.json && o.json.rows) || []).filter(function (row) {
        return row.id === queued.message_id;
      })[0] || null;
    }, 45000);
  check("5. a transport that cannot talk to the relay dead-letters the " +
        "message after mail.attempts (1)", function () {
    assert.ok(dead, "no dead letter " + queued.message_id);
    assert.ok(/^STS-MAIL-00(09|14)$/.test(dead.errorCode), dead.errorCode);
  });
  await ok(realmBase() + "/admin-api/config/set",
           { key: "mail.smtpTls", value: "starttls" }, "mended the transport");
  await ok(realmBase() + "/admin-api/mail/outbox/retry",
           { message: queued.message_id }, "retried the dead letter");
  got = await arrived(ADDRESS, /test message/, seen);
  seen.push(got.id);
  check("5. the retry was delivered", function () {
    assert.strictEqual(got.message.To[0].Address, ADDRESS);
  });

  // =========================================================================
  // 6. THE OUTBOX
  // =========================================================================
  r = await call("GET", realmBase() + "/admin-api/mail/outbox?q=" +
                 encodeURIComponent(PERSON));
  check("6. the outbox lists what was sent to the person, and no body",
        function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    const rows = r.json.rows || [];
    assert.ok(rows.filter(function (row) {
      return row.state === "sent";
    }).length >= 5, JSON.stringify(rows.map(function (row) {
      return row.template + ":" + row.state;
    })));
    rows.forEach(function (row) {
      assert.ok(row.text === undefined && row.html === undefined,
                "a row carried a body");
    });
  });
  r = await call("GET", realmBase() + "/admin-api/mail/outbox?message=" +
                 encodeURIComponent(queued.message_id));
  check("6. a SENT message's own view carries no body either", function () {
    assert.ok(r.json.message && r.json.message.text === undefined,
              r.text.slice(0, 300));
  });

  assert.ok(checks + skipped >= 17, "only " + checks + " checks ran and " +
            skipped + " were skipped; a section has stopped being called.");
  log.info(checks + " check(s) passed, " + skipped + " skipped.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_mail")
  .description("#63: the mail channel delivering to a real SMTP server — " +
    "a test message, address verification, a self-service reset, an " +
    "administrator's link mailed, a dead letter and its retry.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
