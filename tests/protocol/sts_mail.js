// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

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
//      person is then told their password changed. Since #568 the portal is a
//      static application, so the form and the link are the operations the
//      portal's pages are drawn from and post to: `/account-api/forgot-
//      password` and `/account-api/reset-password`, which take no token —
//      the reset link's secret is what authorises the reset. The link in the
//      mail still names the portal page, `/portal/reset-password?...`.
//   4. An administrator's reset link with `deliver: "mail"`: not returned,
//      mailed.
//   5. A dead letter: a transport that cannot talk to the catcher (implicit
//      TLS against its STARTTLS port) dead-letters with one attempt; fixed,
//      the retry is delivered.
//   6. The outbox lists what was sent, with no body.
//
//   7. THE CHANNEL'S REFUSALS AND DEAD LETTERS, WITH THEIR CODES (D12, #444:
//      carries over the over-the-wire half of tests/mail.js), in a
//      development realm of its own and needing no catcher: no transport
//      (STS-MAIL-0001), a recipient past mail.ratePerRecipient (0010) and a
//      From that is not one mailbox (0023) are refused 400 and recorded on
//      the audit log; an SMTP relay that refuses the connection (0009), an
//      smtp transport with no host (0004) and DKIM required with no key
//      (0022) are each a dead letter whose outbox row carries its code and
//      sentence; an administrator's reset link to be mailed to a person with
//      no address, and in product with global.publicBaseUrl empty, is
//      answered with the link and a `mailError` saying why nothing was
//      mailed. Its realm is removed at the end only when
//      STS_TEST_REMOVE_REALMS is "1" (a hand run against a long-lived
//      probe), for tests/CLAUDE.md's *No job removes a realm*.
//
// WHERE THERE IS NO CATCHER — an AWS target, the coverage run — the sections
// that need it SKIP and say so (`MAILPIT_API_URL` unset); section 0's refusal
// and section 7 run everywhere.
// ===========================================================================

// An address compared by parsing it, not searched for as text
// (`url_match.js`).
const urls = require("./url_match.js");
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

// The `user` and `token` a mailed link carries in its query.
function linkParam(link, name) {
  log.debug("Entering linkParam().");
  let value = "";
  try {
    // The query, or the fragment, where a link's token travels (#1454).
    const url = new URL(link);
    value = url.searchParams.get(name) ||
      new URLSearchParams(url.hash.slice(1)).get(name) || "";
  } catch (e) {
    log.debug("Caught in linkParam(): " + ((e && e.message) || e));
    // Not a URL: no parameter, which the assertion that reads it says.
    value = "";
  }
  log.debug("Leaving linkParam().");
  return value;
}

// SECTION 7's own realm, and the codes recorded there after a point; a
// response never carries one.
const REFUSALS = usernameFor("mailr").replace(/[^a-z0-9-]/g, "").slice(0, 30);

function refusalsApi(path) {
  log.debug("Entering refusalsApi().");
  log.debug("Leaving refusalsApi().");
  return base + "/realm/" + REFUSALS + "/admin-api" + path;
}

async function newestAt() {
  log.debug("Entering newestAt().");
  const r = await call("GET", refusalsApi("/audit?per=1"));
  log.debug("Leaving newestAt().");
  // BY TIME (#465): `seq` is unique across processes and rises within
  // each, but it is not one order across them, so a row a request worker
  // numbered from a lower block than the newest row here would be missed.
  // A reader resumes by `at`, as the audit API says.
  const newest = (r.json && r.json.events && r.json.events[0]) || {};
  return newest.at || 0;
}

async function codesSince(since, wanted) {
  log.debug("Entering codesSince().");
  let found = [];
  for (let i = 0; i < 20 && found.indexOf(wanted) < 0; i += 1) {
    const r = await call("GET", refusalsApi("/audit?per=200"));
    found = ((r.json && r.json.events) || []).filter(function (row) {
      return row.at > since && row.errorCode;
    }).map(function (row) {
      return row.errorCode;
    });
    if (found.indexOf(wanted) < 0) {
      await sleep(150);
    }
  }
  log.debug("Leaving codesSince(). " + found.join(","));
  return found;
}

async function settings(values) {
  log.debug("Entering settings().");
  await ok(refusalsApi("/config/set-many"), values,
           "set " + Object.keys(values).join(", "));
  log.debug("Leaving settings().");
}

async function refusedTest(code, what) {
  log.debug("Entering refusedTest().");
  const since = await newestAt();
  const r = await call("POST", refusalsApi("/mail/test"), { user: "mr-one" });
  const codes = await codesSince(since, code);
  check("7. " + what + " (400, " + code + " on the audit row)", function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 300));
    assert.ok(codes.indexOf(code) >= 0, "recorded: " + codes.join(","));
    assert.ok(r.text.indexOf("STS-") < 0, "a code was sent");
  });
  log.debug("Leaving refusedTest().");
  return r;
}

// A test message queued, and the outbox row it became once it settled.
async function deadLetter(code, what, pattern) {
  log.debug("Entering deadLetter().");
  const queued = await ok(refusalsApi("/mail/test"), { user: "mr-one" },
                          "queued a test message");
  const row = await until("the message settled", async function () {
    const r = await call("GET", refusalsApi("/mail/outbox?message=" +
                         encodeURIComponent(queued.message_id)));
    const one = ((r.json && r.json.rows) || [])[0];
    return one && one.state !== "pending" ? one : null;
  }, 15000);
  check("7. " + what + ": a dead letter after one attempt, its row " +
        "carrying " + code, function () {
    assert.strictEqual(row.state, "dead", JSON.stringify(row).slice(0, 300));
    assert.strictEqual(row.attempts, 1);
    assert.strictEqual(row.errorCode, code, JSON.stringify(row));
    assert.ok(pattern.test(row.why), row.why);
  });
  log.debug("Leaving deadLetter().");
}

async function refusals() {
  log.debug("Entering refusals().");
  log.info("=== 7. the channel's refusals and dead letters ===");
  // THE REALM STARTS IN DEVELOPMENT, SAID SO (run #300): the section
  // creates a person with no address, captures messages and only at its
  // end puts the realm in product itself; in a product process a realm made
  // without the override would refuse the first two from the start.
  await ok(base + "/admin-api/realms/create", { id: REFUSALS,
    domain: REFUSALS + ".example.net", name: "Mail refusals",
    overrides: { "global.mode": "development" } },
    "created the realm " + REFUSALS);
  await ok(refusalsApi("/users/create"), { username: "mr-one",
    invent: false, credential: "none", attributes: { cn: "Mail One",
      sn: "One", givenName: "Mail", mail: "mr-one@" + REFUSALS +
      ".example.net" } }, "created a person with an address");
  await ok(refusalsApi("/users/create"), { username: "mr-none",
    invent: false, credential: "none", attributes: { cn: "Mail None",
      sn: "None", givenName: "Mail" } }, "created a person with none");
  await settings({ "mail.transport": "off" });
  await refusedTest("STS-MAIL-0001", "no transport configured");
  await settings({ "mail.transport": "capture", "mail.ratePerRecipient": "1",
                   "mail.ratePerCategory": "100" });
  await ok(refusalsApi("/mail/test"), { user: "mr-one" },
           "sent the one message the ceiling allows");
  await refusedTest("STS-MAIL-0010", "a recipient past mail.ratePerRecipient");
  await settings({ "mail.ratePerRecipient": "100",
                   "mail.from": "a@b.example, c@d.example" });
  await refusedTest("STS-MAIL-0023", "a From that is not one plain mailbox");
  await call("POST", refusalsApi("/config/reset"), { key: "mail.from" });

  await settings({ "mail.transport": "smtp", "mail.smtpHost": "127.0.0.1",
                   "mail.smtpPort": "1", "mail.smtpTls": "starttls",
                   "mail.smtpAuth": "none", "mail.attempts": "1" });
  await deadLetter("STS-MAIL-0009", "a relay that refuses the connection",
                   /ECONNREFUSED/);
  await settings({ "mail.dkimDomain": REFUSALS + ".example.net",
                   "mail.dkimSelector": "s1" });
  await deadLetter("STS-MAIL-0022", "DKIM required and no key",
                   /no DKIM key is configured/);
  await call("POST", refusalsApi("/config/reset"), { key: "mail.dkimDomain" });
  await call("POST", refusalsApi("/config/set"), { key: "mail.smtpHost",
                                                   value: "" });
  await deadLetter("STS-MAIL-0004", "an smtp transport with no host",
                   /has no host/);

  const noAddress = await ok(refusalsApi("/users/issue-password-reset"),
    { user: "mr-none", deliver: "mail" }, "asked to mail a reset link");
  check("7. a reset link to be mailed to a person with no address is " +
        "answered with the link and why nothing was mailed", function () {
    assert.ok(/#token=/.test(noAddress.resetUrl || ""),
              JSON.stringify(noAddress).slice(0, 300));
    assert.ok(/no mail attribute/.test(noAddress.mailError || ""),
              String(noAddress.mailError));
  });
  await settings({ "global.publicBaseUrl": "" });
  await call("POST", refusalsApi("/config/set"), { key: "global.mode",
                                                   value: "product" });
  const noBase = await ok(refusalsApi("/users/issue-password-reset"),
    { user: "mr-one", deliver: "mail" }, "asked to mail a reset link");
  check("7. in product with global.publicBaseUrl empty no link is mailed, " +
        "and the answer says so", function () {
    assert.ok(/global\.publicBaseUrl is not set/
                .test(noBase.mailError || ""), String(noBase.mailError));
  });
  log.debug("Leaving refusals().");
}

async function sections() {
  log.debug("Entering sections().");
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
    }, (settings.json && Array.isArray(settings.json.settings) ?
        settings.json.settings : []))
    .filter(function (row) {
      return row.key === "global.publicBaseUrl";
    })[0];
  const pinned = String((pinnedRow && pinnedRow.value) || "").trim()
    .replace(/\/+$/, "");
  // WHAT THE DEPLOYMENT CONFIGURED (#311): testidp sets `ses` for the whole
  // service, and a new realm inherits it. Only `default` is product's `off`.
  const transportRow = ((settings.json && settings.json.groups) || [])
    .reduce(function (all, g) {
      return all.concat(g.settings || []);
    }, (settings.json && Array.isArray(settings.json.settings) ?
        settings.json.settings : []))
    .filter(function (row) {
      return row.key === "mail.transport";
    })[0];
  const configured = String((transportRow && transportRow.value) ||
                            "default");
  const expected = configured === "default" ? "off" : configured;
  r = await call("GET", realmBase() + "/admin-api/mail");
  check("product: the transport is the one configured (" + expected +
        "; off when nothing is), and a link is mailed only under a " +
        "pinned base", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.strictEqual(r.json.transport, expected);
    assert.strictEqual(r.json.linkBase, pinned
      ? pinned + "/realm/" + REALM : "",
      pinned ? "the pinned base and the realm's prefix"
             : "no unpinned link in product");
  });
  if (!MAILPIT) {
    skip("sections 1-6", "MAILPIT_API_URL is not set, so there is no mail " +
         "catcher to deliver to (an AWS target or the coverage run)");
    assert.ok(checks + skipped >= 3, "only " + checks + " checks ran");
    log.debug("Leaving sections(). No catcher.");
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
  r = await call("GET", realmBase() + "/account-api/forgot-password");
  check("3. the forgot-password page is offered (product, a transport)",
        function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
  });
  const unknown = await call("POST", realmBase() +
                             "/account-api/forgot-password",
                             { account: "nobody-" + PERSON });
  const known = await call("POST", realmBase() +
                           "/account-api/forgot-password",
                           { account: ADDRESS });
  check("3. an unknown account and a known one get the same page",
        function () {
    assert.strictEqual(unknown.status, 200);
    assert.strictEqual(known.status, 200);
    const sentence = function (answer) {
      log.debug("Entering sentence().");
      log.debug("Leaving sentence().");
      return answer.json && answer.json.view ? answer.json.view.note : "";
    };
    assert.ok(sentence(known), known.text.slice(0, 400));
    assert.strictEqual(sentence(unknown), sentence(known));
    assert.strictEqual(JSON.stringify(unknown.json),
                       JSON.stringify(known.json),
                       "the two answers differ");
  });
  got = await arrived(ADDRESS, /Reset your/, seen);
  seen.push(got.id);
  const resetLink = linkIn(got.message);
  check("3. the known account's verified address was sent a reset link",
        function () {
    assert.ok(urls.isAt(resetLink, base + "/realm/" + REALM +
                        "/portal/reset-password") &&
              new URL(resetLink).search !== "", resetLink);
  });
  const linkUser = linkParam(resetLink, "user");
  const linkToken = linkParam(resetLink, "token");
  r = await call("GET", realmBase() + "/account-api/reset-password?" +
                 new URLSearchParams({ user: linkUser }).toString(),
                 undefined, { "X-Link-Token": linkToken });
  check("3. the link opens the form", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
  });
  r = await call("POST", realmBase() + "/account-api/reset-password",
                 { user: linkUser, token: linkToken,
                   password: NEW_PASSWORD, confirm: NEW_PASSWORD });
  check("3. and sets a new password", function () {
    assert.ok(r.status === 200 && r.json && r.json.ok &&
              r.json.view && r.json.view.done,
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
  log.debug("Leaving sections().");
}

// Sections 0-6, then 7, which needs no catcher and so runs everywhere.
async function test() {
  log.debug("Entering test().");
  await sections();
  try {
    await refusals();
  } finally {
    if (process.env.STS_TEST_REMOVE_REALMS === "1") {
      await call("POST", base + "/admin-api/realms/remove",
                 { id: REFUSALS });
    }
  }
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
  // THE CAUSE TOO (2026-09-29): undici's `fetch failed` says nothing
  // about which request or why; its `cause` does (ECONNRESET, other side
  // closed, a timeout). CI run 36553670107 logged only the first.
  const cause = e && e.cause
    ? " — cause: " + ((e.cause.code ? e.cause.code + " " : "") +
                      (e.cause.message || String(e.cause)))
    : "";
  log.error((e.stack || e.message) + cause);
  process.exit(1);
});
