// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_pseudonyms.js
//
// ===========================================================================
// SIGN-IN NAMES, OVER HTTP (#644). `local: true`.
//
// A realm of its own. An administrator's set-pseudonyms stores a name at
// once. Signing in with it issues the filing person's subject and the
// filing username. The whole address wins over the local-part fold. The
// portal edits the token's own subject. Another realm's token is refused.
//
// The mailed-link section runs only where MAILPIT_API_URL is set. Before
// the link is spent the address is the other person. After it, the owner.
// After the name is removed, the other person again. The other sections
// run without a catcher.
// ===========================================================================

const assert = require("assert");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");
const portal = require("./portal_signin.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  appconfigProblem = e;
  appconfig = {};
}
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_pseudonyms",
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

function stamp(prefix) {
  log.debug("Entering stamp().");
  log.debug("Leaving stamp().");
  return usernameFor(prefix).replace(/[^a-z0-9-]/g, "").slice(0, 24);
}

const REALM = stamp("p644");
const OTHER = stamp("p644b");
const DOMAIN = REALM + ".example.net";
const ALICE = stamp("p644a");
const BOB = stamp("p644u");
const CARA = stamp("p644c");
const PASSWORD = "P644-" + String(Date.now()).slice(-8) + "-xQ9!pZ";
const ALIAS = ALICE + ".other";
const SECOND = ALICE + ".second";
const CARA_ADDRESS = ALICE + "@alias.example";
const FOLD = BOB + "@fold.example";
const CANCEL_ADDRESS = "wait." + BOB + "@fold.example";

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

async function call(method, url, body, headers) {
  log.debug("Entering call().");
  const sent = Object.assign({}, headers || {});
  if (body !== undefined && !sent["Content-Type"]) {
    sent["Content-Type"] = "application/json";
  }
  const r = await fetch(url, { method: method, redirect: "manual",
    headers: sent,
    body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
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

function errorsOf(r) {
  log.debug("Entering errorsOf().");
  log.debug("Leaving errorsOf().");
  return ((r.json && r.json.errors) || []).join(" ");
}

function payloadOf(token) {
  log.debug("Entering payloadOf().");
  const part = String(token || "").split(".")[1] || "";
  const json = JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
  log.debug("Leaving payloadOf().");
  return json;
}

async function person(who, mail) {
  log.debug("Entering person().");
  await ok(realmBase() + "/admin-api/users/create",
           { username: who, invent: false,
             attributes: { givenName: "P", sn: who, cn: "P " + who,
                           mail: mail },
             credential: "password", password: PASSWORD,
             passwordConfirm: PASSWORD },
           "created " + who);
  const read = await call("GET", realmBase() + "/admin-api/users?user=" +
                          encodeURIComponent(who));
  const subject = String((read.json && read.json.subject) || "");
  assert.ok(/^urn:uuid:/.test(subject),
            "no subject for " + who + ": " + read.text.slice(0, 300));
  log.debug("Leaving person().");
  return subject;
}

async function signIn(who) {
  log.debug("Entering signIn().");
  const c = await portal.signInToThePortal(realmBase(), who, null,
                                           { password: PASSWORD });
  assert.ok(c.token, "no token for " + who);
  log.debug("Leaving signIn().");
  return c;
}

// A SIGN-IN THAT MAY BE REFUSED: the token's payload, or null when the
// portal's sign-in did not end in a token.
async function signInOrRefused(who) {
  log.debug("Entering signInOrRefused().");
  try {
    const c = await signIn(who);
    log.debug("Leaving signInOrRefused(). Signed in.");
    return payloadOf(c.token);
  } catch (e) {
    log.debug("Caught in signInOrRefused(): " + ((e && e.message) || e));
    log.debug("Leaving signInOrRefused(). Refused.");
    return null;
  }
}

// The realm's mode, from GET /admin-api/mode.
async function realmMode() {
  log.debug("Entering realmMode().");
  const r = await call("GET", realmBase() + "/admin-api/mode");
  assert.strictEqual(r.status, 200, "GET /admin-api/mode: " + r.status +
                     " " + r.text.slice(0, 300));
  log.debug("Leaving realmMode().");
  return String(r.json && r.json.mode);
}

// WHAT AN ADDRESS NOBODY HOLDS SIGNS IN AS (step 9). Development checks no
// password and files a whole address under its local part, so FOLD is Bob.
// Product checks the password of the entry the WHOLE name finds — a uid or
// a live pseudonym — and folds nothing, so with no live holder FOLD is
// refused. Either way it is not Alice while her address is pending, which is
// what step 9 is about. (First run in product mode: 2026-11-02.)
function assertNotYetAlice(payload, mode, aliceSubject, bobSubject, when) {
  log.debug("Entering assertNotYetAlice().");
  if (mode === "product") {
    assert.strictEqual(payload, null, when + ": product mode signed in " +
      "an address no uid or live pseudonym holds: " +
      JSON.stringify(payload));
  } else {
    assert.ok(payload, when + ": development mode refused the address");
    assert.strictEqual(payload.sub, bobSubject);
    assert.strictEqual(payload.username, BOB);
    assert.notStrictEqual(payload.sub, aliceSubject);
  }
  log.debug("Leaving assertNotYetAlice().");
}

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

async function arrived(address) {
  log.debug("Entering arrived().");
  const summary = await until("a sign-in-name message to " + address,
    async function () {
      const all = await inbox(address);
      return all.filter(function (m) {
        return /Confirm a name/.test(m.Subject);
      })[0] || null;
    });
  assert.ok(summary, "no sign-in-name message reached " + address);
  const whole = await (await fetch(MAILPIT + "/api/v1/message/" +
                                   summary.ID)).json();
  log.debug("Leaving arrived().");
  return whole;
}

function linkIn(message) {
  log.debug("Entering linkIn().");
  const text = String(message.Text || "") + "\n" + String(message.HTML || "");
  const found = text.match(
    /https?:\/\/\S+\/portal\/verify-pseudonym\?\S+/);
  log.debug("Leaving linkIn().");
  return found ? found[0].replace(/[)>.,]+$/, "") : "";
}

function linkParams(link) {
  log.debug("Entering linkParams().");
  let out = { user: "", token: "" };
  try {
    const u = new URL(link);
    out = { user: u.searchParams.get("user") || "",
            token: new URLSearchParams(u.hash.slice(1)).get("token") || "" };
  } catch (e) {
    log.debug("Caught in linkParams(): " + ((e && e.message) || e));
    out = { user: "", token: "" };
  }
  log.debug("Leaving linkParams().");
  return out;
}

async function listed(c) {
  log.debug("Entering listed().");
  const r = await c.api("GET", "/account-api/pseudonyms");
  assert.strictEqual(r.status, 200, r.text.slice(0, 300));
  log.debug("Leaving listed().");
  return r.json || {};
}

function hasName(view, name) {
  log.debug("Entering hasName().");
  const fold = String(name).toLowerCase();
  log.debug("Leaving hasName().");
  return (view.pseudonyms || []).some(function (one) {
    return String(one).toLowerCase() === fold;
  });
}

async function theAliasSignsInAsTheOwner(aliceSubject) {
  log.debug("Entering theAliasSignsInAsTheOwner().");
  const added = await ok(realmBase() + "/admin-api/users/set-pseudonyms",
                         { user: ALICE, add: ALIAS },
                         "added " + ALIAS);
  check("1. an administrator's name is live, with nothing pending",
        function () {
    assert.ok((added.pseudonyms || []).some(function (one) {
      return String(one).toLowerCase() === ALIAS;
    }), JSON.stringify(added.pseudonyms));
    assert.strictEqual(added.pending, null);
  });
  const signed = await signIn(ALIAS);
  const payload = payloadOf(signed.token);
  check("1. signing in with the alias issues the filing subject and " +
        "the filing username", function () {
    assert.strictEqual(payload.sub, aliceSubject);
    assert.strictEqual(payload.username, ALICE);
    assert.strictEqual(payload.preferred_username, undefined);
  });
  const view = await listed(signed);
  check("2. the portal lists the name for the token's own subject",
        function () {
    assert.ok(hasName(view, ALIAS), JSON.stringify(view.pseudonyms));
  });
  const second = await signed.api("POST", "/account-api/pseudonyms",
                                  { action: "add", value: SECOND });
  const afterAdd = await listed(signed);
  check("2. the person adds another name", function () {
    assert.strictEqual(second.status, 200, second.text.slice(0, 300));
    assert.ok(second.json && second.json.ok === true, second.text);
    assert.ok(!second.json.token, "the answer carried a token");
    assert.ok(hasName(afterAdd, SECOND), JSON.stringify(afterAdd));
  });
  const removed = await signed.api("POST", "/account-api/pseudonyms",
                                   { action: "remove", value: SECOND });
  const afterRemove = await listed(signed);
  check("2. and removes it", function () {
    assert.strictEqual(removed.status, 200, removed.text.slice(0, 300));
    assert.ok(!hasName(afterRemove, SECOND) && hasName(afterRemove, ALIAS),
              JSON.stringify(afterRemove.pseudonyms));
  });
  const extra = await signed.api("POST", "/account-api/pseudonyms",
                                 { action: "add", value: ALIAS + "x",
                                   user: BOB });
  check("3. a user field is refused", function () {
    assert.strictEqual(extra.status, 400, extra.text.slice(0, 300));
    assert.ok(errorsOf(extra).indexOf(
      'body: "user" is not a field this operation takes.') >= 0,
      extra.text.slice(0, 400));
  });
  const own = await signed.api("POST", "/account-api/pseudonyms",
                               { action: "add", value: ALICE });
  check("3. the person's own uid is refused", function () {
    assert.strictEqual(own.status, 400, own.text.slice(0, 300));
    assert.ok(errorsOf(own).indexOf(
      "That name is already this person's uid.") >= 0,
      own.text.slice(0, 400));
  });
  const bad = await signed.api("POST", "/account-api/pseudonyms",
                               { action: "add", value: "bad,name" });
  check("3. a reserved character is refused", function () {
    assert.strictEqual(bad.status, 400, bad.text.slice(0, 300));
    assert.ok(/distinguished name/.test(errorsOf(bad)),
              bad.text.slice(0, 400));
  });
  const taken = await signed.api("POST", "/account-api/pseudonyms",
                                 { action: "add", value: BOB });
  check("3. somebody else's uid is refused", function () {
    assert.strictEqual(taken.status, 400, taken.text.slice(0, 300));
    assert.ok(errorsOf(taken).indexOf(
      "Somebody else in this realm already answers to that name.") >= 0,
      taken.text.slice(0, 400));
  });
  log.debug("Leaving theAliasSignsInAsTheOwner().");
  return signed;
}

async function theWholeAddressWins(aliceSubject, caraSubject) {
  log.debug("Entering theWholeAddressWins().");
  await ok(realmBase() + "/admin-api/users/set-pseudonyms",
           { user: CARA, add: CARA_ADDRESS },
           "added " + CARA_ADDRESS + " to " + CARA);
  const signed = await signIn(CARA_ADDRESS);
  const payload = payloadOf(signed.token);
  check("4. the whole address is its owner, ahead of the local-part fold",
        function () {
    assert.strictEqual(payload.sub, caraSubject);
    assert.strictEqual(payload.username, CARA);
    assert.notStrictEqual(payload.sub, aliceSubject);
  });
  log.debug("Leaving theWholeAddressWins().");
}

async function theAdministratorRefusals() {
  log.debug("Entering theAdministratorRefusals().");
  const both = await call("POST",
    realmBase() + "/admin-api/users/set-pseudonyms",
    { user: ALICE, add: ALIAS + "z", remove: ALIAS });
  check("5. a body naming two changes is refused", function () {
    assert.strictEqual(both.status, 400, both.text.slice(0, 300));
    assert.ok(/exactly one of add, remove or cancelPending/
      .test(errorsOf(both)), both.text.slice(0, 400));
  });
  const collided = await call("POST",
    realmBase() + "/admin-api/users/set-pseudonyms",
    { user: ALICE, add: BOB });
  check("5. a name the directory refuses stays the administrator's " +
        "sentence", function () {
    assert.strictEqual(collided.status, 400, collided.text.slice(0, 300));
    assert.ok(/would not write the name/.test(errorsOf(collided)),
              collided.text.slice(0, 400));
    assert.ok(errorsOf(collided).indexOf(BOB) < 0,
              "the refused name was repeated: " + collided.text.slice(0, 400));
  });
  log.debug("Leaving theAdministratorRefusals().");
}

async function anotherRealmIsRefused() {
  log.debug("Entering anotherRealmIsRefused().");
  await ok(base + "/admin-api/realms/create",
           { id: OTHER, domain: OTHER + ".example.net",
             name: "pseudonyms other (#644)" },
           "created the other realm");
  const secretReply = await call("POST", base + "/realm/" + OTHER +
    "/admin-api/applications/regenerate-secret",
    { application: "sts-api-client" });
  const secret = secretReply.json && secretReply.json.clientSecret;
  assert.ok(secret, "regenerating the other realm's secret answered " +
            secretReply.status + " " + secretReply.text.slice(0, 200));
  const form = await fetch(base + "/realm/" + OTHER + "/oauth2/token", {
    method: "POST", redirect: "manual",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: "Basic " +
        Buffer.from("sts-api-client:" + secret).toString("base64")
    },
    body: new URLSearchParams({
      grant_type: "client_credentials",
      scope: "admin:read admin:write",
      resource: base + "/realm/" + OTHER + "/admin-api"
    }).toString()
  });
  const mintedJson = await form.json();
  const token = mintedJson && mintedJson.access_token;
  assert.ok(token, "the other realm's token endpoint answered " +
            form.status + " " + JSON.stringify(mintedJson).slice(0, 200));
  const crossed = await call("POST",
    realmBase() + "/admin-api/users/set-pseudonyms",
    { user: ALICE, add: ALIAS + "q" },
    { Authorization: "Bearer " + token });
  check("6. another realm's administrator token is refused here",
        function () {
    assert.strictEqual(crossed.status, 401, crossed.text.slice(0, 300));
  });
  log.debug("Leaving anotherRealmIsRefused().");
}

async function theDocuments() {
  log.debug("Entering theDocuments().");
  const admin = await call("GET", base + "/admin-api/openapi.json");
  check("7. the management API document declares setUserPseudonyms",
        function () {
    const ids = [];
    Object.keys((admin.json && admin.json.paths) || {})
      .forEach(function (p) {
        Object.keys(admin.json.paths[p]).forEach(function (method) {
          ids.push(String((admin.json.paths[p][method] || {}).operationId));
        });
      });
    assert.ok(ids.indexOf("setUserPseudonyms") >= 0, ids.join(","));
  });
  const account = await call("GET", realmBase() + "/account-api/openapi.json");
  check("7. the account API document declares the four operations",
        function () {
    const ids = [];
    Object.keys((account.json && account.json.paths) || {})
      .forEach(function (p) {
        Object.keys(account.json.paths[p]).forEach(function (method) {
          ids.push(String((account.json.paths[p][method] || {})
            .operationId));
        });
      });
    ["getPseudonyms", "postPseudonyms", "getPseudonymVerification",
     "verifyPseudonym"].forEach(function (id) {
      assert.ok(ids.indexOf(id) >= 0, id + " is not declared");
    });
  });
  log.debug("Leaving theDocuments().");
}

async function theAliasIsGone(aliceSubject) {
  log.debug("Entering theAliasIsGone().");
  await ok(realmBase() + "/admin-api/users/set-pseudonyms",
           { user: ALICE, remove: ALIAS }, "removed " + ALIAS);
  const read = await call("GET", realmBase() + "/admin-api/users?user=" +
                          encodeURIComponent(ALIAS));
  check("8. after removal the alias does not resolve to the owner",
        function () {
    assert.notStrictEqual(String((read.json && read.json.subject) || ""),
                          aliceSubject);
  });
  log.debug("Leaving theAliasIsGone().");
}

async function theMailedLink(aliceSubject, bobSubject) {
  log.debug("Entering theMailedLink().");
  if (!MAILPIT) {
    skip("the mailed link", "MAILPIT_API_URL is not set");
    log.debug("Leaving theMailedLink(). No catcher.");
    return;
  }
  await ok(realmBase() + "/admin-api/config/set-many",
           { "mail.transport": "smtp", "mail.smtpHost": SMTP_HOST,
             "mail.smtpPort": SMTP_PORT, "mail.smtpTls": "starttls",
             "mail.smtpCaFile": CA_FILE, "mail.smtpAuth": "none",
             "mail.ratePerCategory": "30", "mail.ratePerRecipient": "30",
             "global.publicBaseUrl": base },
           "pointed the realm's SMTP transport at the catcher");
  const alice = await signIn(ALICE);
  const asked = await alice.api("POST", "/account-api/pseudonyms",
                                { action: "add", value: FOLD });
  check("9. adding an email answers without the link's secret", function () {
    assert.strictEqual(asked.status, 200, asked.text.slice(0, 400));
    assert.ok(asked.json && asked.json.ok === true, asked.text);
    assert.ok(!asked.json.token, asked.text.slice(0, 400));
  });
  const message = await arrived(FOLD);
  const link = linkIn(message);
  check("9. the message links to /portal/verify-pseudonym", function () {
    assert.ok(link, String(message.Text || "").slice(0, 400));
    assert.ok(link.indexOf("/portal/verify-email") < 0, link);
  });
  const mode = await realmMode();
  const beforePayload = await signInOrRefused(FOLD);
  check("9. before the link is spent the address is not its owner (" +
        mode + ")", function () {
    assertNotYetAlice(beforePayload, mode, aliceSubject, bobSubject,
                      "before the link is spent");
  });
  const params = linkParams(link);
  const looked = await call("GET", realmBase() +
    "/account-api/verify-pseudonym?user=" +
    encodeURIComponent(params.user), undefined,
    { "X-Link-Token": params.token });
  const still = await listed(alice);
  check("9. opening the link spends nothing", function () {
    assert.strictEqual(looked.status, 200, looked.text.slice(0, 300));
    assert.strictEqual(String((looked.json && looked.json.address) || "")
      .toLowerCase(), FOLD);
    assert.ok(!hasName(still, FOLD), JSON.stringify(still));
  });
  const spent = await call("POST",
    realmBase() + "/account-api/verify-pseudonym",
    { user: params.user, token: params.token });
  const after = await signIn(FOLD);
  const afterPayload = payloadOf(after.token);
  check("9. after the link is spent the address is the owner", function () {
    assert.strictEqual(spent.status, 200, spent.text.slice(0, 300));
    assert.ok(spent.json && spent.json.view && spent.json.view.verified,
              spent.text.slice(0, 300));
    assert.strictEqual(afterPayload.sub, aliceSubject);
    assert.strictEqual(afterPayload.username, ALICE);
  });
  const dropped = await alice.api("POST", "/account-api/pseudonyms",
                                  { action: "remove", value: FOLD });
  const backPayload = await signInOrRefused(FOLD);
  check("9. after removal the address is not its owner again (" + mode +
        ")", function () {
    assert.strictEqual(dropped.status, 200, dropped.text.slice(0, 300));
    assertNotYetAlice(backPayload, mode, aliceSubject, bobSubject,
                      "after removal");
  });
  const waiting = await alice.api("POST", "/account-api/pseudonyms",
                                  { action: "add", value: CANCEL_ADDRESS });
  assert.strictEqual(waiting.status, 200, waiting.text.slice(0, 400));
  const secondMessage = await arrived(CANCEL_ADDRESS);
  const secondLink = linkParams(linkIn(secondMessage));
  await ok(realmBase() + "/admin-api/users/set-pseudonyms",
           { user: ALICE, cancelPending: true }, "cancelled the pending link");
  const replay = await call("POST",
    realmBase() + "/account-api/verify-pseudonym",
    { user: secondLink.user, token: secondLink.token });
  check("9. a cancelled link does not spend", function () {
    assert.strictEqual(replay.status, 400, replay.text.slice(0, 300));
    assert.ok(/not valid/.test(errorsOf(replay) +
              String((replay.json && replay.json.view &&
                      replay.json.view.refused) || "")),
              replay.text.slice(0, 400));
  });
  log.debug("Leaving theMailedLink().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving sign-in names at " + base + " in the realm " + REALM);
  await ok(base + "/admin-api/realms/create",
           { id: REALM, domain: DOMAIN, name: "sign-in names (#644)" },
           "created the realm");
  await openThePortal();
  const bobSubject = await person(BOB, BOB + ".kept@" + DOMAIN);
  const aliceSubject = await person(ALICE, ALICE + "@" + DOMAIN);
  const caraSubject = await person(CARA, CARA + "@" + DOMAIN);
  await theAliasSignsInAsTheOwner(aliceSubject);
  await theWholeAddressWins(aliceSubject, caraSubject);
  await theAdministratorRefusals();
  await anotherRealmIsRefused();
  await theDocuments();
  await theAliasIsGone(aliceSubject);
  await theMailedLink(aliceSubject, bobSubject);
  assert.ok(checks >= 16, "only " + checks + " checks ran; a section has " +
            "stopped being called.");
  log.info(checks + " check(s) passed, " + skipped + " skipped.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_pseudonyms")
  .description("#644: a live stsPseudonym signs in as the filing person, " +
    "over HTTP, in a realm of its own.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
