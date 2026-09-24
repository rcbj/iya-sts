"use strict";
//
// File: sts_email_verification.js
//
// ===========================================================================
// WHICH ADDRESSES ARE VERIFIED, A PERSON'S OWN CHANGE OF ADDRESS, AND THE
// RECOVERY-CODE RESET, OVER HTTP (#64, 2026-09-23). `local: true`.
//
// A realm of its own, delivering to the Mailpit catcher. It starts in
// DEVELOPMENT mode, because what a person does on their portal here needs the
// portal, and a product realm's portal cannot sign anybody in on a service
// that is not itself in product mode (its client's signing key cannot be
// sealed there); it is switched to PRODUCT for section 3, because a
// self-service reset is offered only where passwords are checked.
//
//   1. TRUSTED SOURCES: an address an administrator creates the account with
//      is already verified, so asking to verify it sends nothing; set-mail
//      writes a new one, verified, and the FORMER address is told.
//   2. A PERSON'S OWN CHANGE (D5): the new address is mailed a link and is
//      not the account's until it is followed; opening the link spends
//      nothing; the form spends it, once; the account's address is then the
//      new one, verified, and the former address is told.
//   3. THE RECOVERY-CODE RESET (D4): three fields; a wrong recovery code is
//      answered like everything else, sends no link and tells the address
//      owner; the right one sends the link, which sets a password.
//
// WHERE THERE IS NO CATCHER the job SKIPS: every section needs a transport.
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
var log = bunyan.createLogger({ name: "sts_email_verification",
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
const REALM = usernameFor("emv").replace(/[^a-z0-9-]/g, "").slice(0, 30);
const DOMAIN = REALM + ".example.net";
const PASSWORD = "Emv-" + String(Date.now()).slice(-8) + "-xQ9!pZ";
const NEW_PASSWORD = "Emv2-" + String(Date.now()).slice(-8) + "-kW4#tR";

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

async function call(method, url, body) {
  log.debug("Entering call().");
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

async function inbox(address) {
  log.debug("Entering inbox().");
  const r = await fetch(MAILPIT + "/api/v1/search?query=" +
                        encodeURIComponent("to:" + address));
  const json = await r.json();
  log.debug("Leaving inbox().");
  return (json && json.messages) || [];
}

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
  log.debug("Leaving arrived().");
  return { id: summary.ID, message: whole };
}

function codeIn(message) {
  log.debug("Entering codeIn().");
  log.debug("Leaving codeIn().");
  return (String(message.Text || "").match(/\b(\d{6})\b/) || [])[1] || "";
}

function form(o) {
  log.debug("Entering form().");
  log.debug("Leaving form().");
  return new URLSearchParams(o).toString();
}

function absolute(location) {
  log.debug("Entering absolute().");
  log.debug("Leaving absolute().");
  return /^https?:\/\//i.test(String(location || ""))
    ? String(location) : base + String(location || "");
}

// A BROWSER'S USER-AGENT, for `sts_caep_credential_changes.js`'s reason:
// isbot reads a bare script name as an automated client, and product mode
// refuses a first sign-in from one on risk (#62).
const AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 sts_email_verification/1.0";

// ONE BROWSER: manual redirects and a cookie jar keyed by name, because
// every assertion here is about which screen came back and which cookies
// the browser holds — the binding cookie a link depends on among them.
function browser(name) {
  log.debug("Entering browser().");
  const self = {
    name: name,
    jar: {},
    cookieHeader: function () {
      log.debug("Entering cookieHeader().");
      log.debug("Leaving cookieHeader().");
      return Object.keys(self.jar).map(function (k) {
        return k + "=" + self.jar[k];
      }).join("; ");
    },
    async go(method, path, body) {
      log.debug("Entering go().");
      const headers = { "User-Agent": AGENT };
      const cookie = self.cookieHeader();
      if (cookie) {
        headers.cookie = cookie;
      }
      if (body !== undefined) {
        headers["Content-Type"] = "application/x-www-form-urlencoded";
      }
      const r = await fetch(absolute(path), { method: method,
        redirect: "manual", headers: headers, body: body });
      const set = r.headers.getSetCookie ? r.headers.getSetCookie() : [];
      set.forEach(function (one) {
        const pair = String(one).split(";")[0];
        const key = pair.split("=")[0];
        const value = pair.slice(key.length + 1);
        if (value === "" || /Expires=Thu, 01 Jan 1970/i.test(String(one))) {
          delete self.jar[key];
        } else {
          self.jar[key] = value;
        }
      });
      log.debug("Leaving go().");
      return { status: r.status, location: r.headers.get("location") || "",
               text: await r.text() };
    }
  };
  log.debug("Leaving browser().");
  return self;
}

function csrfOf(text) {
  log.debug("Entering csrfOf().");
  log.debug("Leaving csrfOf().");
  return (String(text).match(/name="csrf_token" value="([^"]+)"/) ||
          [])[1] || "";
}

function hiddenValue(html, name) {
  log.debug("Entering hiddenValue().");
  const m = new RegExp('name="' + name + '" value="([^"]*)"').exec(html);
  log.debug("Leaving hiddenValue().");
  return m ? m[1].replace(/&amp;/g, "&") : "";
}

async function person(who, withAddress) {
  log.debug("Entering person().");
  await ok(realmBase() + "/admin-api/users/create",
           { username: who, invent: false,
             attributes: Object.assign({ givenName: "Emv", sn: who,
                                         cn: "Emv " + who },
               withAddress === false ? {} : { mail: who + "@" + DOMAIN }),
             credential: "password", password: PASSWORD,
             passwordConfirm: PASSWORD },
           "created " + who);
  log.debug("Leaving person().");
  return who + "@" + DOMAIN;
}

async function signIn(who, password) {
  log.debug("Entering signIn().");
  const b = browser(who);
  let r = await b.go("GET", realmBase() + "/portal");
  for (let hop = 0; hop < 4 && r.location &&
       !/\/authn\/login\?authn=/.test(r.location); hop++) {
    r = await b.go("GET", r.location);
  }
  r = await b.go("GET", r.location);
  r = await b.go("POST", realmBase() + "/authn/login",
    form({ authn_id: hiddenValue(r.text, "authn_id"), username: who,
           password: password || PASSWORD, action: "login" }));
  for (let hop = 0; hop < 6 && (r.status === 302 || r.status === 303); hop++) {
    r = await b.go("GET", r.location);
  }
  assert.ok(b.jar.sts_session, "no session for " + who + ": " + r.status +
            " " + r.text.slice(0, 200));
  log.debug("Leaving signIn().");
  return b;
}

async function ids(address) {
  log.debug("Entering ids().");
  const all = await inbox(address);
  log.debug("Leaving ids().");
  return all.map(function (m) {
    return m.ID;
  });
}

// A PRODUCT REALM'S PORTAL IS REACHED AT ADDRESSES ITS CLIENT DOES NOT HOLD
// (its seeded redirect URI is the default origin's), and product teaches an
// entry no address a request arrives at — so an administrator registers the
// two, as an operator standing a realm up would.
async function openThePortal() {
  log.debug("Entering openThePortal().");
  await ok(realmBase() + "/admin-api/applications/add",
           { application: "sts-user-portal", attribute: "oauthRedirectUri",
             value: realmBase() + "/portal/callback" },
           "registered the realm portal's callback");
  await ok(realmBase() + "/admin-api/applications/add",
           { application: "sts-user-portal",
             attribute: "oauthPostLogoutRedirectUri",
             value: realmBase() + "/portal" },
           "registered the realm portal's sign-out address");
  log.debug("Leaving openThePortal().");
}

async function trustedSources() {
  log.debug("Entering trustedSources().");
  log.info("=== 1. an administrator is a trusted source ===");
  const who = usernameFor("emva").replace(/[^a-z0-9]/g, "").slice(0, 20);
  const address = await person(who);
  let r = await call("POST", realmBase() + "/admin-api/mail/verify",
                     { user: who });
  check("1. an address an administrator created the account with is " +
        "already verified — nothing is sent", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.strictEqual(r.json.verified, true, r.text.slice(0, 300));
  });
  const seen = await ids(address);
  const next = who + ".set@" + DOMAIN;
  r = await call("POST", realmBase() + "/admin-api/users/set-mail",
                 { user: who, mail: next });
  check("1. set-mail writes a new address, verified", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.strictEqual(r.json.verified, true);
  });
  const told = await arrived(address, /address of your/, seen);
  check("1. and the FORMER address is told it changed", function () {
    assert.ok(String(told.message.Text).indexOf(next) >= 0,
              String(told.message.Text).slice(0, 300));
  });
  r = await call("POST", realmBase() + "/admin-api/mail/verify",
                 { user: who });
  check("1. the new one needs no link either", function () {
    assert.strictEqual(r.json.verified, true, r.text.slice(0, 300));
  });
  log.debug("Leaving trustedSources().");
}

async function aPersonsOwnChange() {
  log.debug("Entering aPersonsOwnChange().");
  log.info("=== 2. a person changes their own address ===");
  const who = usernameFor("emvb").replace(/[^a-z0-9]/g, "").slice(0, 20);
  const address = await person(who);
  const next = who + ".new@" + DOMAIN;
  const b = await signIn(who);
  let r = await b.go("GET", realmBase() + "/portal/email");
  const seenOld = await ids(address);
  r = await b.go("POST", realmBase() + "/portal/email",
    form({ action: "change", address: next, csrf_token: csrfOf(r.text) }));
  check("2. the change is asked for", function () {
    assert.strictEqual(r.status, 303, r.text.slice(0, 300));
  });
  r = await b.go("GET", realmBase() + "/portal/email");
  check("2. and is PENDING: the address is still the old one, and the page " +
        "says what it is changing to", function () {
    assert.ok(r.text.indexOf("<code>" + address + "</code>") >= 0,
              r.text.slice(0, 400));
    assert.ok(/Changing to/.test(r.text) && r.text.indexOf(next) >= 0);
  });
  const got = await arrived(next, /Confirm your address/);
  const link = (String(got.message.Text).match(
    /(https?:\/\/\S+\/portal\/verify-email\?\S+)/) || [])[1] || "";
  check("2. the link went to the NEW address, on the pinned origin",
        function () {
    assert.ok(link.indexOf(base + "/realm/" + REALM +
                           "/portal/verify-email?") === 0, link);
  });
  r = await call("GET", link);
  check("2. opening it spends nothing: it draws a button", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.ok(/Verify this address/.test(r.text));
  });
  const fields = { user: hiddenValue(r.text, "user"),
                   token: hiddenValue(r.text, "token") };
  const post = await fetch(realmBase() + "/portal/verify-email", {
    method: "POST", redirect: "manual",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form(fields) });
  const posted = await post.text();
  check("2. the form makes it the account's address", function () {
    assert.strictEqual(post.status, 200, posted.slice(0, 300));
    assert.ok(/Address verified/.test(posted), posted.slice(0, 300));
  });
  const again = await fetch(realmBase() + "/portal/verify-email", {
    method: "POST", redirect: "manual",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form(fields) });
  check("2. once", function () {
    assert.strictEqual(again.status, 400);
  });
  const told = await arrived(address, /address of your/, seenOld);
  check("2. and the FORMER address is told it changed", function () {
    assert.ok(String(told.message.Text).indexOf(next) >= 0);
  });
  r = await call("POST", realmBase() + "/admin-api/mail/verify",
                 { user: who });
  check("2. the new address is verified", function () {
    assert.strictEqual(r.json.verified, true, r.text.slice(0, 300));
  });
  log.debug("Leaving aPersonsOwnChange().");
}

async function theRecoveryCodeReset() {
  log.debug("Entering theRecoveryCodeReset().");
  log.info("=== 3. the recovery-code reset ===");
  const who = usernameFor("emvc").replace(/[^a-z0-9]/g, "").slice(0, 20);
  const address = await person(who);
  const b = await signIn(who);
  let r = await b.go("GET", realmBase() + "/portal/mfa");
  r = await b.go("POST", realmBase() + "/portal/mfa",
    form({ action: "generate-codes", csrf_token: csrfOf(r.text) }));
  const list = String(r.text).match(/<ul class="codes">([\s\S]*?)<\/ul>/);
  const codes = [];
  const re = /<code(?: class="[^"]*")?>([^<]+)<\/code>/g;
  let m;
  while (list && (m = re.exec(list[1])) !== null) {
    codes.push(m[1]);
  }
  r = await b.go("POST", realmBase() + "/portal/mfa",
    form({ action: "confirm-codes", handle: hiddenValue(r.text, "handle"),
           csrf_token: csrfOf(r.text) }));
  check("3. the person holds a set of recovery codes", function () {
    assert.ok(codes.length >= 8, "only " + codes.length + " codes");
  });
  await ok(realmBase() + "/admin-api/config/set",
           { key: "global.mode", value: "product" },
           "switched the realm to product, where a reset is offered");
  r = await call("GET", realmBase() + "/portal/forgot-password");
  check("3. the forgot-password form asks for the username, the address " +
        "and a recovery code", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.ok(/name="account"/.test(r.text) && /name="address"/.test(r.text) &&
              /name="code"/.test(r.text), r.text.slice(0, 400));
  });
  const ask = async function (fields) {
    const res = await fetch(realmBase() + "/portal/forgot-password", {
      method: "POST", redirect: "manual",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form(fields) });
    const text = await res.text();
    return (/<div class="ok">([^<]*)<\/div>/.exec(text) || [])[1] || text;
  };
  const seen = await ids(address);
  const wrongAddress = await ask({ account: who, address: "x@" + DOMAIN,
                                   code: codes[0] });
  const wrongCode = await ask({ account: who, address: address,
                                code: "AAAAA-AAAAA" });
  const notice = await arrived(address, /tried to reset/, seen);
  check("3. a wrong recovery code with the right name and address tells " +
        "the address owner", function () {
    assert.ok(notice.id, "no notice");
  });
  const right = await ask({ account: who, address: address,
                           code: codes[0] });
  check("3. every combination is answered with the same sentence",
        function () {
    assert.strictEqual(wrongAddress, wrongCode);
    assert.strictEqual(wrongCode, right);
  });
  const reset = await arrived(address, /Reset your/, seen);
  const resetLink = (String(reset.message.Text).match(
    /(https?:\/\/\S+\/portal\/reset-password\?\S+)/) || [])[1] || "";
  check("3. all three right: the reset link is mailed, naming the recovery " +
        "code as what was presented", function () {
    assert.ok(resetLink, String(reset.message.Text).slice(0, 300));
    assert.ok(/recovery codes/.test(String(reset.message.Text)));
  });
  const replay = await ask({ account: who, address: address,
                            code: codes[0] });
  void replay;
  r = await call("GET", resetLink);
  const done = await fetch(realmBase() + "/portal/reset-password", {
    method: "POST", redirect: "manual",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form({ user: hiddenValue(r.text, "user"),
                 token: hiddenValue(r.text, "token"),
                 password: NEW_PASSWORD, confirm: NEW_PASSWORD }) });
  check("3. and the link sets a new password", function () {
    assert.ok(done.status === 200 || done.status === 303, done.status);
  });
  const resets = (await inbox(address)).filter(function (x) {
    return /Reset your/.test(x.Subject);
  });
  check("3. the SAME code a second time mailed nothing: it was spent",
        function () {
    assert.strictEqual(resets.length, 1, JSON.stringify(resets.map(
      function (x) { return x.Subject; })));
  });
  log.debug("Leaving theRecoveryCodeReset().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving address verification and the recovery-code reset at " +
           base + " in the realm " + REALM);
  if (!MAILPIT) {
    skip("everything", "MAILPIT_API_URL is not set, so there is no mail " +
         "catcher to deliver to (an AWS target or the coverage run)");
    log.info("Test completed successfully.");
    log.debug("Leaving test().");
    return;
  }
  await ok(base + "/admin-api/realms/create",
           { id: REALM, domain: DOMAIN, name: "email verification (#64)" },
           "created the realm");
  await openThePortal();
  await ok(realmBase() + "/admin-api/config/set-many",
           { "mail.transport": "smtp", "mail.smtpHost": SMTP_HOST,
             "mail.smtpPort": SMTP_PORT, "mail.smtpTls": "starttls",
             "mail.smtpCaFile": CA_FILE, "mail.smtpAuth": "none",
             "mail.ratePerCategory": "30", "mail.ratePerRecipient": "30",
             "global.publicBaseUrl": base },
           "pointed the realm's SMTP transport at the catcher");
  await trustedSources();
  await aPersonsOwnChange();
  await theRecoveryCodeReset();
  assert.ok(checks >= 19, "only " + checks + " checks ran; a section has " +
            "stopped being called.");
  log.info(checks + " check(s) passed, " + skipped + " skipped.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_email_verification")
  .description("#64: which addresses are verified, a person's own change of " +
    "address, and the self-service reset with a recovery code, delivered to " +
    "a real SMTP server.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
