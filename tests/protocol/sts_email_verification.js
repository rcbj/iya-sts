// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

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
// AND WHAT A RISC RECEIVER IS TOLD (#294, for #235), on a poll stream in the
// realm: following the verification link (section 2) is
// identifier-changed and recovery-information-changed — and ASKING for the
// change is neither; a recovery code spent on /portal/forgot-password
// (section 3) is recovery-information-changed and recovery-activated — and a
// wrong code is neither.
//
// WHERE THERE IS NO CATCHER the job SKIPS: every section needs a transport.
//
// SINCE #568 THE PORTAL IS A STATIC APPLICATION over `/account-api`: a
// person signs in as it does (`portal_signin.js`: PKCE, a DPoP-bound token),
// the email and authenticator pages' forms are their operations, and the
// links a person is mailed — still naming `/portal/verify-email` and
// `/portal/reset-password` — are spent through the operations those pages
// are drawn from and post to, which take no token: the link's secret is the
// credential. What a page shows is read from its view.
// ===========================================================================

const assert = require("assert");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");
const portal = require("./portal_signin.js");
const ssfRoles = require("./ssf_roles.js");

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
const RISC = "https://schemas.openid.net/secevent/risc/event-type/";
const POLL = "urn:ietf:rfc:8936";
// The realm's SSF receiver: a confidential client of its own.
const RECEIVER = "emv-receiver";
const RECEIVER_SECRET = "emv-" + String(Date.now()).slice(-8) + "-rx";

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

// The `user` and `token` a mailed link carries in its query.
function linkParams(link) {
  log.debug("Entering linkParams().");
  let out = { user: "", token: "" };
  try {
    const u = new URL(link);
    out = { user: u.searchParams.get("user") || "",
            token: u.searchParams.get("token") || "" };
  } catch (e) {
    log.debug("Caught in linkParams(): " + ((e && e.message) || e));
    // Not a URL: nothing to spend, which the assertion reading it says.
    out = { user: "", token: "" };
  }
  log.debug("Leaving linkParams().");
  return out;
}

// A PAGE DRAWN FOR NOBODY — the forgot-password form — as the portal draws
// it: its own renderer, the language data for nobody.
async function drawnForNobody(path, view) {
  log.debug("Entering drawnForNobody().");
  const table = portal.portalBundle();
  const data = (await call("GET", realmBase() + "/account-api/locale")).json ||
               {};
  const t = table.messages.WebTranslator.fromData(data.locale);
  const html = table.render(path, view, { t: t, query: {}, prefix: "",
    origin: base, me: null, locale: data.locale, version: data.version,
    here: path });
  log.debug("Leaving drawnForNobody().");
  return html;
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
  const read = await call("GET", realmBase() + "/admin-api/users?user=" +
                          encodeURIComponent(who));
  SUBJECTS[who] = String((read.json && read.json.subject) || "");
  assert.ok(/^urn:uuid:/.test(SUBJECTS[who]),
            "no subject for " + who + ": " + read.text.slice(0, 300));
  log.debug("Leaving person().");
  return who + "@" + DOMAIN;
}

// SIGNED IN AS THE STATIC PORTAL SIGNS IN (#568), in the realm.
async function signIn(who, password) {
  log.debug("Entering signIn().");
  const c = await portal.signInToThePortal(realmBase(), who, null,
                                           { password: password || PASSWORD });
  assert.ok(c.token, "no token for " + who);
  log.debug("Leaving signIn().");
  return c;
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

// ---------------------------------------------------------------------------
// THE RISC RECEIVER (#294): a stream in the realm, and what it was sent.
// ---------------------------------------------------------------------------
const stream = { id: "", seen: [] };
// Each person's `sub` (urn:uuid:<entryUUID>), read after they are created:
// RISC names a person by address where the event is about one, and by
// issuer and subject otherwise (recovery-information-changed).
const SUBJECTS = {};

async function receiverToken() {
  log.debug("Entering receiverToken().");
  await ssfRoles.mapApplication(ssfRoles.callPost(call), realmBase() + "/admin-api", RECEIVER, "ssf.read ssf.manage");
  const r = await fetch(realmBase() + "/oauth2/token", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form({ grant_type: "client_credentials", client_id: RECEIVER,
                 client_secret: RECEIVER_SECRET,
                 scope: "ssf.read ssf.manage" }) });
  const json = await r.json();
  assert.ok(json && json.access_token,
            "a receiver token: " + JSON.stringify(json).slice(0, 300));
  log.debug("Leaving receiverToken().");
  return json.access_token;
}

async function openTheStream() {
  log.debug("Entering openTheStream().");
  await ok(realmBase() + "/admin-api/applications/create", {
    identifier: RECEIVER, kind: "oauth2-client", name: RECEIVER,
    protocols: ["oauth2", "ssf"],
    fields: { oauthClientId: [RECEIVER], oauthClientSecret: RECEIVER_SECRET,
              oauthTokenEndpointAuthMethod: "client_secret_post",
              oauthAllowedScope: ["ssf.read", "ssf.manage"],
              oauthGrantType: ["client_credentials"] } },
    "created the RISC receiver's application");
  const r = await fetch(realmBase() + "/ssf/stream", { method: "POST",
    headers: { "Content-Type": "application/json",
               Authorization: "Bearer " + (await receiverToken()) },
    body: JSON.stringify({ delivery: { method: POLL },
      events_requested: ["recovery-information-changed",
                         "recovery-activated", "identifier-changed"]
        .map(function (t) { return RISC + t; }) }) });
  const json = await r.json();
  check("0. a RISC poll stream takes recovery-information-changed, " +
        "recovery-activated and identifier-changed", function () {
    assert.strictEqual(r.status, 201, JSON.stringify(json).slice(0, 400));
  });
  stream.id = json.stream_id;
  log.debug("Leaving openTheStream().");
}

// Every SET waiting on the stream, decoded, acknowledged and kept. A fresh
// token each time: section 3 moves the realm to product mode mid-job.
async function drainTheStream() {
  log.debug("Entering drainTheStream().");
  const auth = { "Content-Type": "application/json",
                 Authorization: "Bearer " + (await receiverToken()) };
  const r = await fetch(realmBase() + "/ssf/poll", { method: "POST",
    headers: auth, body: JSON.stringify({ stream_id: stream.id,
      returnImmediately: true, maxEvents: 100 }) });
  const json = await r.json();
  assert.strictEqual(r.status, 200, "poll: " +
                     JSON.stringify(json).slice(0, 300));
  const sets = json.sets || {};
  const jtis = Object.keys(sets);
  if (jtis.length) {
    await fetch(realmBase() + "/ssf/poll", { method: "POST", headers: auth,
      body: JSON.stringify({ stream_id: stream.id, ack: jtis,
                             returnImmediately: true, maxEvents: 0 }) });
  }
  jtis.forEach(function (jti) {
    stream.seen.push(JSON.parse(Buffer.from(String(sets[jti]).split(".")[1],
                                            "base64url").toString("utf8")));
  });
  log.debug("Leaving drainTheStream(). " + jtis.length + " SET(s).");
}

// A RISC `type` about `who` — by an address (every one of theirs carries the
// name) or by their subject — among the SETs that arrived since `from`.
function riscAbout(type, who, from) {
  log.debug("Entering riscAbout(). " + type);
  log.debug("Leaving riscAbout().");
  return stream.seen.slice(from).filter(function (set) {
    const subject = JSON.stringify((set && set.sub_id) || {});
    return !!((set && set.events) || {})[RISC + type] &&
           (subject.indexOf(who) >= 0 ||
            (!!SUBJECTS[who] && subject.indexOf(SUBJECTS[who]) >= 0));
  });
}

// Waits until every type in `types` about `who` has arrived since `from`.
async function riscArrived(types, who, from) {
  log.debug("Entering riscArrived().");
  const got = await until(types.join(", ") + " about " + who,
    async function () {
      await drainTheStream();
      return types.every(function (type) {
        return riscAbout(type, who, from).length > 0;
      });
    }, 15000);
  log.debug("Leaving riscArrived(). " + !!got);
  return !!got;
}

// Lets what is in flight arrive, and reads it: for a check that something
// was NOT sent.
async function settle() {
  log.debug("Entering settle().");
  await sleep(1500);
  await drainTheStream();
  log.debug("Leaving settle().");
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
  const c = await signIn(who);
  const seenOld = await ids(address);
  let r = await c.act("/portal/email", { action: "change", address: next });
  check("2. the change is asked for", function () {
    assert.ok(r.status === 200 && r.json && r.json.ok, r.text.slice(0, 300));
  });
  r = await c.page("/portal/email");
  check("2. and is PENDING: the address is still the old one, and the page " +
        "says what it is changing to", function () {
    assert.strictEqual(r.json.address, address, r.text.slice(0, 400));
    assert.strictEqual(r.json.changing, next, r.text.slice(0, 400));
  });
  await settle();
  const asked = stream.seen.length;
  check("2. asking for the change tells RISC nothing yet (#235): the " +
        "address is not the account's", function () {
    assert.strictEqual(riscAbout("recovery-information-changed", who, 0)
      .length, 0, JSON.stringify(stream.seen).slice(0, 800));
  });
  const got = await arrived(next, /Confirm your address/);
  const link = (String(got.message.Text).match(
    /(https?:\/\/\S+\/portal\/verify-email\?\S+)/) || [])[1] || "";
  check("2. the link went to the NEW address, on the pinned origin",
        function () {
    assert.ok(link.indexOf(base + "/realm/" + REALM +
                           "/portal/verify-email?") === 0, link);
  });
  const fields = linkParams(link);
  r = await call("GET", realmBase() + "/account-api/verify-email?" +
                 form(fields));
  check("2. opening it spends nothing: it draws a button", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.ok(r.json && r.json.address === next && r.json.token,
              r.text.slice(0, 300));
  });
  const post = await call("POST", realmBase() + "/account-api/verify-email",
                          fields);
  check("2. the form makes it the account's address", function () {
    assert.strictEqual(post.status, 200, post.text.slice(0, 300));
    assert.ok(post.json && post.json.view && post.json.view.verified,
              post.text.slice(0, 300));
  });
  const again = await call("POST", realmBase() + "/account-api/verify-email",
                           fields);
  check("2. once", function () {
    assert.strictEqual(again.status, 400);
  });
  const verifiedSent = await riscArrived(["identifier-changed",
    "recovery-information-changed"], who, asked);
  check("2. following the link is RISC identifier-changed and " +
        "recovery-information-changed (#235)", function () {
    assert.ok(verifiedSent, JSON.stringify(stream.seen.slice(asked))
      .slice(0, 1500));
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
  const c = await signIn(who);
  let r = await c.act("/portal/mfa", { action: "generate-codes" });
  // The set is shown once, in the answer's `view.fresh` (#568).
  const fresh = (r.json && r.json.view && r.json.view.fresh) || {};
  const codes = (fresh.codes || []).slice(0);
  r = await c.act("/portal/mfa", { action: "confirm-codes",
                                   handle: fresh.handle });
  check("3. the person holds a set of recovery codes", function () {
    assert.ok(codes.length >= 8, "only " + codes.length + " codes");
    assert.ok(r.status === 200 && r.json && r.json.ok, r.text.slice(0, 300));
  });
  await ok(realmBase() + "/admin-api/config/set",
           { key: "global.mode", value: "product" },
           "switched the realm to product, where a reset is offered");
  r = await call("GET", realmBase() + "/account-api/forgot-password");
  const forgotForm = r.status === 200
    ? await drawnForNobody("/portal/forgot-password", r.json) : "";
  check("3. the forgot-password form asks for the username, the address " +
        "and a recovery code", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.ok(r.json.threeFields === true, r.text.slice(0, 300));
    assert.ok(/name="account"/.test(forgotForm) &&
              /name="address"/.test(forgotForm) &&
              /name="code"/.test(forgotForm), forgotForm.slice(0, 400));
  });
  // The form's answer: the one sentence, `view.note`, whatever was asked.
  const ask = async function (fields) {
    const res = await call("POST", realmBase() +
                           "/account-api/forgot-password", fields);
    return (res.json && res.json.view && res.json.view.note) || res.text;
  };
  const seen = await ids(address);
  await settle();
  const beforeWrong = stream.seen.length;
  const wrongAddress = await ask({ account: who, address: "x@" + DOMAIN,
                                   code: codes[0] });
  const wrongCode = await ask({ account: who, address: address,
                                code: "AAAAA-AAAAA" });
  const notice = await arrived(address, /tried to reset/, seen);
  check("3. a wrong recovery code with the right name and address tells " +
        "the address owner", function () {
    assert.ok(notice.id, "no notice");
  });
  await settle();
  check("3. and spends nothing: no recovery-information-changed",
        function () {
    assert.strictEqual(riscAbout("recovery-information-changed", who,
                                 beforeWrong).length, 0,
                       JSON.stringify(stream.seen.slice(beforeWrong))
                         .slice(0, 800));
  });
  const beforeRight = stream.seen.length;
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
  const spentSent = await riscArrived(["recovery-information-changed",
    "recovery-activated"], who, beforeRight);
  check("3. the recovery code spent on the form is RISC " +
        "recovery-information-changed (the set shrank) and " +
        "recovery-activated (#235)", function () {
    assert.ok(spentSent, JSON.stringify(stream.seen.slice(beforeRight))
      .slice(0, 1500));
  });
  const replay = await ask({ account: who, address: address,
                            code: codes[0] });
  void replay;
  const resetFields = linkParams(resetLink);
  r = await call("GET", realmBase() + "/account-api/reset-password?" +
                 form(resetFields));
  const done = await call("POST", realmBase() + "/account-api/reset-password",
    { user: resetFields.user, token: resetFields.token,
      password: NEW_PASSWORD, confirm: NEW_PASSWORD });
  check("3. and the link sets a new password", function () {
    assert.ok(r.status === 200 && done.status === 200 && done.json &&
              done.json.view && done.json.view.done,
              r.status + " " + done.status + " " + done.text.slice(0, 300));
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
  await openTheStream();
  await trustedSources();
  await aPersonsOwnChange();
  await theRecoveryCodeReset();
  assert.ok(checks >= 24, "only " + checks + " checks ran; a section has " +
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
