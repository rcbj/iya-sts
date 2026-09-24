"use strict";
//
// File: sts_email_factor.js
//
// ===========================================================================
// THE EMAILED CODE AND THE EMAILED SIGN-IN LINK, OVER HTTP (#64, 2026-09-23).
// `local: true` — written here, owned here (tests/CLAUDE.md).
//
// Works in a realm of its own, delivering to the Mailpit catcher `sts_mail.js`
// uses and reading what arrived through its HTTP API. A DEVELOPMENT realm:
// the codes and links are checked for real in both modes, and a product
// realm's portal cannot sign anybody in on a service that is not itself in
// product mode (its client's signing key cannot be sealed there), which the
// opt-in on /portal/mfa needs. Its mail transport starts OFF, which is what
// section 0 is about.
//
//   0. THE POLICIES PAGE: both policies on one resource; a realm with no
//      authentication policy of its own follows the default realm's; in a
//      realm that cannot send mail the email rows are DISABLED and a save
//      turning one on is refused (STS-AUTHN-0244).
//   1. A CODE AS THE SECOND FACTOR: a person opts in on /portal/mfa; their
//      next sign-in mails a code; a wrong one counts down; the right one
//      signs in with amr ["pwd","otp"] and acr "mfa".
//   2. A CODE AS THE FIRST FACTOR: "Email me a sign-in code" with a username
//      alone signs in with amr ["otp"] and acr "1"; an unknown name gets the
//      SAME page and nothing is mailed.
//   3. A LINK: it lands on a page that spends nothing; opened in a browser
//      that did not start the sign-in it signs nobody in; in the one that
//      did, Continue signs in.
//
// WHERE THERE IS NO CATCHER — an AWS target, the coverage run — sections
// 1–3 SKIP and say so; section 0 runs everywhere.
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
var log = bunyan.createLogger({ name: "sts_email_factor",
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
const REALM = usernameFor("emf").replace(/[^a-z0-9-]/g, "").slice(0, 30);
const DOMAIN = REALM + ".example.net";
const PASSWORD = "Emf-" + String(Date.now()).slice(-8) + "-xQ9!pZ";

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
  "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 sts_email_factor/1.0";

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

async function person(who) {
  log.debug("Entering person().");
  await ok(realmBase() + "/admin-api/users/create",
           { username: who, invent: false,
             attributes: { mail: who + "@" + DOMAIN, givenName: "Emf",
                           sn: who, cn: "Emf " + who },
             credential: "password", password: PASSWORD,
             passwordConfirm: PASSWORD },
           "created " + who);
  log.debug("Leaving person().");
  return who + "@" + DOMAIN;
}

// To the realm's sign-in screen through its portal, as a browser arrives:
// answers the browser and the screen.
async function toSignIn(b) {
  log.debug("Entering toSignIn().");
  let r = await b.go("GET", realmBase() + "/portal");
  for (let hop = 0; hop < 4 && r.location &&
       !/\/authn\/login\?authn=/.test(r.location); hop++) {
    r = await b.go("GET", r.location);
  }
  assert.ok(/\/authn\/login\?authn=/.test(r.location),
            "the portal did not lead to the sign-in screen: " + r.status +
            " -> " + r.location);
  r = await b.go("GET", r.location);
  assert.ok(hiddenValue(r.text, "authn_id"), "no authn_id on the screen");
  log.debug("Leaving toSignIn().");
  return r;
}

// Follows a finished sign-in's redirects back into the portal.
async function finish(b, r) {
  log.debug("Entering finish().");
  for (let hop = 0; hop < 6 && (r.status === 302 || r.status === 303); hop++) {
    r = await b.go("GET", r.location);
  }
  log.debug("Leaving finish().");
  return r;
}

async function sessionOf(who) {
  log.debug("Entering sessionOf().");
  const r = await call("GET", realmBase() + "/admin-api/sessions?q=" +
                       encodeURIComponent(who));
  const rows = (r.json && (r.json.rows || r.json.sessions)) || [];
  const found = rows.filter(function (row) {
    return String(row.username || row.who || row.user || "") === who ||
           JSON.stringify(row).indexOf('"' + who + '"') >= 0;
  }).filter(function (row) {
    return Array.isArray(row.amr) && row.amr.length;
  })[0] || null;
  log.debug("Leaving sessionOf().");
  return found;
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

async function thePoliciesPage() {
  log.debug("Entering thePoliciesPage().");
  log.info("=== 0. the Policies page, in a realm that cannot send mail ===");
  let r = await call("GET", realmBase() + "/admin-api/policies");
  check("0. both policies are on one resource, as kinds", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.deepStrictEqual(r.json.kinds.map(function (k) {
      return k.id;
    }), ["password", "authn"]);
    assert.ok(r.json.actions.indexOf("save-authn-policy") >= 0);
  });
  check("0. both email mechanisms are OFF by default", function () {
    const p = r.json.authn.profile;
    assert.strictEqual(p.emailCodePrimary, false);
    assert.strictEqual(p.emailLinkSecondFactor, false);
  });
  check("0. with no transport the email rows are DISABLED, with the reason",
        function () {
    assert.strictEqual(r.json.authn.mail.usable, false);
    const row = r.json.authn.fields.filter(function (f) {
      return f.key === "emailCodePrimary";
    })[0];
    assert.ok(row && row.disabled === true && /cannot send mail/.test(
      row.disabledWhy), JSON.stringify(row));
  });
  const fields = Object.assign({ profile: "default" }, r.json.authn.defaults);
  const refused = await call("POST", realmBase() +
    "/admin-api/policies/save-authn-policy",
    Object.assign({}, fields, { emailCodePrimary: true }));
  check("0. a save turning one on is REFUSED while the realm cannot send " +
        "mail", function () {
    assert.strictEqual(refused.status, 400, refused.text.slice(0, 300));
    assert.ok(/cannot send mail/.test(refused.text), refused.text);
  });
  // INHERITANCE: the default realm's profile, then this realm's own.
  const defaultSaved = await call("POST", base +
    "/admin-api/policies/save-authn-policy",
    Object.assign({}, fields, { emailCodeTtlS: 240,
                                description: "sts_email_factor.js" }));
  try {
    r = await call("GET", realmBase() + "/admin-api/policies");
    check("0. a realm with no profile of its own FOLLOWS the default realm's",
          function () {
      assert.strictEqual(defaultSaved.status, 200,
                         defaultSaved.text.slice(0, 300));
      assert.strictEqual(r.json.authn.profile.from, "default-realm");
      assert.strictEqual(r.json.authn.profile.emailCodeTtlS, 240);
    });
  } finally {
    await call("POST", base + "/admin-api/policies/reset-authn-policy",
               { profile: "default" });
  }
  r = await call("GET", realmBase() + "/admin-api/policies");
  check("0. and the built-in defaults once that is removed", function () {
    assert.strictEqual(r.json.authn.profile.from, "built-in");
  });
  log.debug("Leaving thePoliciesPage().");
  return fields;
}

async function aCodeAsTheSecondFactor(fields) {
  log.debug("Entering aCodeAsTheSecondFactor().");
  log.info("=== 1. an emailed code as the second factor ===");
  const who = usernameFor("emfa").replace(/[^a-z0-9]/g, "").slice(0, 20);
  const address = await person(who);
  // Opted in from the portal, signed in on a password alone the first time.
  const b = browser(who);
  let r = await toSignIn(b);
  r = await b.go("POST", realmBase() + "/authn/login",
    form({ authn_id: hiddenValue(r.text, "authn_id"), username: who,
           password: PASSWORD, action: "login" }));
  r = await finish(b, r);
  r = await b.go("GET", realmBase() + "/portal/mfa");
  check("1. /portal/mfa offers email as a second factor", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 200));
    assert.ok(/id="email-factor-code"/.test(r.text), "no email option");
  });
  r = await b.go("POST", realmBase() + "/portal/mfa",
    form({ action: "email-factor-on", kind: "code",
           csrf_token: csrfOf(r.text) }));
  check("1. and the person turns it on", function () {
    assert.strictEqual(r.status, 303, r.text.slice(0, 300));
  });
  const seen = (await inbox(address)).map(function (m) {
    return m.ID;
  });
  const c = browser(who + "-2");
  r = await toSignIn(c);
  r = await c.go("POST", realmBase() + "/authn/login",
    form({ authn_id: hiddenValue(r.text, "authn_id"), username: who,
           password: PASSWORD, action: "login" }));
  const mfaId = hiddenValue(r.text, "mfa_id");
  check("1. the next sign-in mails a code and asks for it", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.ok(/Check your email/.test(r.text) && mfaId, r.text.slice(0, 300));
  });
  const got = await arrived(address, /sign-in code/, seen);
  const code = codeIn(got.message);
  check("1. the code arrived at the verified address, in the layout",
        function () {
    assert.ok(/^\d{6}$/.test(code), String(got.message.Text).slice(0, 200));
    assert.ok(/You received this because/.test(String(got.message.Text)));
  });
  r = await c.go("POST", realmBase() + "/authn/email-code",
    form({ mfa_id: mfaId, action: "verify",
           code: code === "000000" ? "111111" : "000000" }));
  check("1. a wrong code keeps the step and counts down", function () {
    assert.strictEqual(r.status, 200);
    assert.ok(/more attempt/.test(r.text), r.text.slice(0, 300));
  });
  r = await c.go("POST", realmBase() + "/authn/email-code",
    form({ mfa_id: mfaId, action: "verify", code: code }));
  check("1. the right code signs in", function () {
    assert.ok(r.status === 302 || r.status === 303,
              r.status + " " + r.text.slice(0, 300));
  });
  await finish(c, r);
  const session = await until("the session", function () {
    return sessionOf(who);
  }, 10000);
  check("1. the session says amr [\"pwd\",\"otp\"] and acr \"mfa\"",
        function () {
    assert.ok(session, "no session for " + who);
    assert.ok(session.amr.indexOf("otp") >= 0 &&
              session.amr.indexOf("pwd") >= 0, JSON.stringify(session.amr));
    assert.strictEqual(session.acr, "mfa");
  });
  void fields;
  log.debug("Leaving aCodeAsTheSecondFactor().");
}

async function aCodeAsTheFirstFactor() {
  log.debug("Entering aCodeAsTheFirstFactor().");
  log.info("=== 2. an emailed code as the first factor ===");
  const who = usernameFor("emfb").replace(/[^a-z0-9]/g, "").slice(0, 20);
  const address = await person(who);
  const b = browser(who);
  let r = await toSignIn(b);
  check("2. the sign-in screen offers \"Email me a sign-in code\"",
        function () {
    assert.ok(/id="kc-email-code"/.test(r.text), r.text.slice(0, 300));
  });
  const seen = (await inbox(address)).map(function (m) {
    return m.ID;
  });
  r = await b.go("POST", realmBase() + "/authn/login",
    form({ authn_id: hiddenValue(r.text, "authn_id"), username: who,
           action: "email-code" }));
  const page = r.text.replace(/value="[A-Za-z0-9_-]{20,}"/g, "ID")
    .replace(new RegExp(who, "g"), "WHO");
  const mfaId = hiddenValue(r.text, "mfa_id");
  const got = await arrived(address, /sign-in code/, seen);
  r = await b.go("POST", realmBase() + "/authn/email-code",
    form({ mfa_id: mfaId, action: "verify", code: codeIn(got.message) }));
  await finish(b, r);
  const session = await until("the session", function () {
    return sessionOf(who);
  }, 10000);
  check("2. a username and the mailed code sign in: amr [\"otp\"], acr \"1\"",
        function () {
    assert.ok(session, "no session for " + who);
    assert.deepStrictEqual(session.amr, ["otp"]);
    assert.strictEqual(session.acr, "1");
  });
  const nobody = "nobody" + who;
  const d = browser(nobody);
  r = await toSignIn(d);
  r = await d.go("POST", realmBase() + "/authn/login",
    form({ authn_id: hiddenValue(r.text, "authn_id"), username: nobody,
           action: "email-code" }));
  check("2. an unknown name gets the SAME page — no enumeration", function () {
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.text.replace(/value="[A-Za-z0-9_-]{20,}"/g, "ID")
      .replace(new RegExp(nobody, "g"), "WHO"), page);
  });
  log.debug("Leaving aCodeAsTheFirstFactor().");
}

async function aLink() {
  log.debug("Entering aLink().");
  log.info("=== 3. an emailed sign-in link ===");
  const who = usernameFor("emfc").replace(/[^a-z0-9]/g, "").slice(0, 20);
  const address = await person(who);
  const b = browser(who);
  let r = await toSignIn(b);
  const seen = (await inbox(address)).map(function (m) {
    return m.ID;
  });
  r = await b.go("POST", realmBase() + "/authn/login",
    form({ authn_id: hiddenValue(r.text, "authn_id"), username: who,
           action: "email-link" }));
  const mfaId = hiddenValue(r.text, "mfa_id");
  check("3. the waiting page, which refreshes itself", function () {
    assert.strictEqual(r.status, 200);
    assert.ok(/Open it in this browser/.test(r.text) &&
              /http-equiv="refresh"/.test(r.text), r.text.slice(0, 300));
    assert.ok(b.jar.sts_email_binding, "no binding cookie");
  });
  const got = await arrived(address, /sign-in link/, seen);
  const link = (String(got.message.Text).match(
    /(https?:\/\/\S+\/authn\/email-link\/open\S+)/) || [])[1] || "";
  check("3. the link is mailed, on this service's pinned origin", function () {
    assert.ok(link.indexOf(base + "/realm/" + REALM +
                           "/authn/email-link/open?") === 0, link);
  });
  const other = browser("elsewhere");
  r = await other.go("GET", link);
  check("3. opened in ANOTHER browser it signs nobody in", function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 300));
    assert.ok(/where you started/.test(r.text));
  });
  // The browser already holds the portal's ARRIVAL session, so what the
  // GET must not do is CHANGE it — and the waiting step must still be there.
  const before = b.jar.sts_session || "";
  r = await b.go("GET", link);
  const t = hiddenValue(r.text, "t");
  const waiting = await b.go("GET", realmBase() + "/authn/email-link?mfa=" +
                             encodeURIComponent(mfaId));
  check("3. in the browser that started it the GET draws Continue and " +
        "spends nothing", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.ok(/Continue/.test(r.text) && t);
    assert.strictEqual(b.jar.sts_session || "", before,
                       "the GET changed the session");
    assert.ok(/Open it in this browser/.test(waiting.text),
              "the step is gone after a GET: " + waiting.text.slice(0, 200));
  });
  r = await b.go("POST", realmBase() + "/authn/email-link/open",
    form({ mfa_id: mfaId, t: t }));
  check("3. and Continue signs in", function () {
    assert.ok(r.status === 302 || r.status === 303,
              r.status + " " + r.text.slice(0, 300));
    assert.ok(b.jar.sts_session && b.jar.sts_session !== before,
              "no new session cookie");
  });
  log.debug("Leaving aLink().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving the emailed code and link at " + base + " in the realm " +
           REALM + (MAILPIT ? ", delivering to " + MAILPIT
                            : "; there is no catcher"));
  await ok(base + "/admin-api/realms/create",
           { id: REALM, domain: DOMAIN, name: "email factor (#64)",
             overrides: { "mail.transport": "off" } },
           "created the realm, with no mail transport");
  await openThePortal();
  const fields = await thePoliciesPage();
  if (!MAILPIT) {
    skip("sections 1-3", "MAILPIT_API_URL is not set, so there is no mail " +
         "catcher to deliver to (an AWS target or the coverage run)");
    assert.ok(checks >= 7, "only " + checks + " checks ran");
    log.info("Test completed successfully.");
    log.debug("Leaving test().");
    return;
  }
  await ok(realmBase() + "/admin-api/config/set-many",
           { "mail.transport": "smtp", "mail.smtpHost": SMTP_HOST,
             "mail.smtpPort": SMTP_PORT, "mail.smtpTls": "starttls",
             "mail.smtpCaFile": CA_FILE, "mail.smtpAuth": "none",
             "mail.ratePerCategory": "30", "mail.ratePerRecipient": "30",
             "global.publicBaseUrl": base },
           "pointed the realm's SMTP transport at the catcher");
  await ok(realmBase() + "/admin-api/policies/save-authn-policy",
           Object.assign({}, fields, { emailCodePrimary: true,
             emailCodeSecondFactor: true, emailLinkPrimary: true,
             emailLinkSecondFactor: true }),
           "turned the four email rows on");
  await aCodeAsTheSecondFactor(fields);
  await aCodeAsTheFirstFactor();
  await aLink();
  assert.ok(checks + skipped >= 21, "only " + checks + " checks ran and " +
            skipped + " were skipped; a section has stopped being called.");
  log.info(checks + " check(s) passed, " + skipped + " skipped.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_email_factor")
  .description("#64: the authentication policy on the Policies resource, " +
    "and the emailed code and sign-in link as first and second factors, " +
    "delivered to a real SMTP server.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
