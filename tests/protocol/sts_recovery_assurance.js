// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_recovery_assurance.js
//
// ---------------------------------------------------------------------------
// ACCOUNT RECOVERY NO WEAKER THAN THE PASSKEY IT REPLACES (#724), OVER THE
// WIRE.
//
// D12 (#444): carries over `tests/recovery_assurance.js`. The passkey
// policy's `recoveryAssurance` row (`any`, `not-weaker`, `operator-only`)
// and the doors that ask it, driven through `/admin-api`, the reset link at
// `/account-api/reset-password`, the portal (`/account-api/keys`,
// `/portal/mfa`'s recovery codes) and the sign-in screen over
// `/authn-api`, in realms of this job's own. A pending recovery is read off
// the person's entry (`stsRecoveryPending`, in `GET /admin-api/users`), and
// codes off `/admin-api/audit`:
//
//   A. the row's built-in default is `any` in development and `not-weaker`
//      in product;
//   G. `save-passkey-policy` takes the row, refuses a value outside the
//      three, and a save that leaves it out keeps the value stored (#907);
//   C. UNDER `any`: an administrator's reset link, spent, records no
//      recovery, and a password sign-in of a person holding a passkey goes
//      on to the application;
//   D. UNDER `not-weaker`: the spent link leaves a pending recovery naming
//      its door (`admin-reset`); the password sign-in starts no session and
//      draws the set-up step, marked `recovery`, offering only a passkey,
//      whose ceremony is a REGISTRATION; a key registered in the act does
//      not complete the recovery (#901: STS-AUTHN-0381, still pending); a
//      sign-in with the passkey the person already held clears it, and the
//      password then signs in as before;
//   H. AN ADMINISTRATOR'S PASSWORD ON A PASSKEY HOLDER (#960): under
//      `not-weaker` `set-password` leaves a pending recovery naming
//      `admin-password`, and after the forced change the API's
//      set-password also sets, the sign-in draws the recovery set-up step;
//      under `any` it leaves nothing pending and the password signs in;
//      `reset-person-keytab` in a realm whose KDC is off is refused
//      (STS-KRB-0128) and leaves nothing pending;
//   E. A RECOVERY CODE AT THE SECOND-FACTOR STEP, for a person whose
//      passkey is their second factor: under `operator-only` the step
//      offers no recovery code and one spent anyway is refused
//      (STS-AUTHN-0380); under `not-weaker` a code spent there leads to the
//      recovery set-up step (a passkey's registration), not to the
//      application, and the recovery is written on the entry as pending
//      (#31);
//   F. UNDER `operator-only` an administrator's reset link is still spent.
//
// NOT carried, and why: B (the built-in rules document and
// `passkey_rules.js` answering alike over a grid of facts) is two library
// readings compared (class (d)); I (a recovery write that returns false,
// #962) needs the directory's write stubbed, which no door can do (d);
// `startSession()`'s own refusal detail beyond its code (d). OWED: F's
// self-service half — a reset link the PERSON asked for refused at its
// spend (STS-AUTHN-0380) and the forgot-password request mailing nothing
// to a passkey holder — needs a realm that sends mail and a catcher; J
// (an activation abandoned at the key or authenticator step, #927) needs
// an activation link, which is issued by mail; the LDAP `userPassword`
// notes of H (a non-self write) belong with the directory jobs.
//
// The realms turn `risk.assessSignIns` off (this job's client is scored
// `automated-client`) and, except for E, `webauthn.mfaAllowed` off: the
// realm in which a passkey signs in on its own and is never the second
// step, as the in-process file arranges, and the usernameless door off so
// the screen's own passkey button answers nothing here.
//
// OWNED HERE (local: true): this repository's own API, portal and screen.
// ---------------------------------------------------------------------------

const assert = require("assert");
const authnSignin = require("./authn_signin");
const portal = require("./portal_signin.js");
const passkeys = require("./passkey_wire_kit.js");

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
var log = bunyan.createLogger({ name: "sts_recovery_assurance",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const k = passkeys.kit("sts_recovery_assurance", { log: log });
const check = k.check;
const SEED = "Ra-" + k.STAMP + "-Seed-Passw0rd";

async function ok(realm, path, body, what) {
  log.debug("Entering ok(). " + path);
  const r = await k.call(realm, "POST", path, body);
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST " + path + " should have " + what + "; it answered " + r.status +
    " " + String(r.raw).slice(0, 400));
  log.debug("Leaving ok().");
  return r.body;
}

async function setting(realm, key, value) {
  log.debug("Entering setting(). " + key + "=" + value);
  const r = await k.send("POST", k.root + "/admin-api/realms/set",
                         { id: realm.id, key: key, value: String(value) });
  assert.ok(r.status === 200, "realms/set " + key + ": " + r.status + " " +
            r.raw.slice(0, 300));
  log.debug("Leaving setting().");
}

async function gained(realm, code, before) {
  log.debug("Entering gained(). " + code);
  let n = (await k.codeCount(realm, code)) - before;
  for (let i = 0; i < 20 && n < 1; i += 1) {
    await k.sleep(150);
    n = (await k.codeCount(realm, code)) - before;
  }
  log.debug("Leaving gained(). " + n);
  return n;
}

// What the person's entry says is pending: "" for nothing, else the door.
async function pendingOf(realm, who) {
  log.debug("Entering pendingOf(). " + who);
  const r = await k.call(realm, "GET", "/users?user=" +
                         encodeURIComponent(who));
  const attrs = (r.body && r.body.ldap && r.body.ldap.entry &&
                 r.body.ldap.entry.attributes) || {};
  const value = String(((attrs.stsRecoveryPending ||
                         attrs.stsrecoverypending) || [])[0] || "");
  log.debug("Leaving pendingOf(). " + value);
  return { door: value.split(" ")[0], raw: value,
           changeRequired: !!(r.body && r.body.factors &&
                              r.body.factors.passwordChangeRequired) };
}

async function recoveryRow(realm, value) {
  log.debug("Entering recoveryRow(). " + value);
  await k.mustSavePolicy(realm, { allowUsernameless: false,
                                  recoveryAssurance: value });
  log.debug("Leaving recoveryRow().");
}

// An administrator's reset link, spent with `password`.
async function spendLink(realm, who, password) {
  log.debug("Entering spendLink(). " + who);
  const issued = await ok(realm, "/users/issue-password-reset",
                          { user: who }, "issued a reset link");
  const token = new URLSearchParams(new URL(issued.resetUrl).hash.slice(1))
    .get("token");
  const r = await k.send("POST", realm.base + "/account-api/reset-password",
    { user: who, token: token, password: password, confirm: password },
    k.BROWSER);
  log.debug("Leaving spendLink(). " + r.status);
  return r;
}

// A password sign-in at the screen: the answer, and the step's view where
// it went to a step.
async function passwordSignIn(realm, who, password) {
  log.debug("Entering passwordSignIn(). " + who);
  const s = await k.screen(realm);
  const answer = await authnSignin.submit(realm.base, s.location,
    { action: "login", username: who, password: password },
    { cookie: s.cookie, screen: s.opened, headers: k.BROWSER });
  let step = null;
  if (answer.next === "mfa" && answer.location) {
    step = await authnSignin.step(answer.location,
      { cookie: answer.cookie, headers: k.BROWSER });
  }
  log.debug("Leaving passwordSignIn(). " + answer.next);
  return { answer: answer, step: step };
}

// Where an answer that names the authorization endpoint lands, followed
// with the cookies the sign-in set: "session" where a session answers it
// (a code at the client's redirect URI, or the consent screen, which only
// a signed-in person meets), "screen" back at the sign-in screen, or the
// status and location.
async function follow(realm, answer) {
  log.debug("Entering follow().");
  if (!answer || !answer.location) {
    log.debug("Leaving follow(). Nowhere.");
    return "nowhere";
  }
  const url = /^https?:/.test(answer.location) ? answer.location
    : new URL(realm.base).origin + answer.location;
  const r = await fetch(url, { redirect: "manual", headers: Object.assign(
    { cookie: authnSignin.foldCookies(answer.cookie || "",
                                      answer.setCookies || []) },
    k.BROWSER) });
  const to = r.headers.get("location") || "";
  log.debug("Leaving follow(). " + r.status + " " + to);
  if ((/[?&]code=/.test(to) && to.indexOf(k.REDIRECT) === 0) ||
      /\/oauth2\/consent\?/.test(to)) {
    return "session";
  }
  if (/\/authn\/login/.test(to)) {
    return "screen";
  }
  return r.status + " " + to.slice(0, 120);
}

// A sign-in that started a session: its redirect, followed, is answered by
// that session.
async function reached(realm, answer) {
  log.debug("Entering reached().");
  const where = answer && answer.next === "redirect"
    ? await follow(realm, answer) : String(answer && answer.next);
  log.debug("Leaving reached(). " + where);
  return where;
}

function wentOn(answer) {
  log.debug("Entering wentOn().");
  log.debug("Leaving wentOn().");
  return !!answer && (answer.next === "redirect" ||
                      answer.next === "consent");
}

function isRecoverySetup(step) {
  log.debug("Entering isRecoverySetup().");
  const v = (step && step.view) || {};
  const setup = v.setup || {};
  log.debug("Leaving isRecoverySetup().");
  return v.page === "setup" && setup.recovery === true &&
         !!setup.offered && setup.offered.webauthn === true &&
         setup.offered.totp === false;
}

// A person with a password and a passkey enrolled at /account-api/keys.
async function holder(realm, who) {
  log.debug("Entering holder(). " + who);
  await k.person(realm, who, SEED);
  const s = await portal.signInToThePortal(realm.base, who, null,
                                           { password: SEED });
  const key = k.authenticator({});
  const e = await k.enrol(s, key, {});
  assert.ok(e.done && e.done.status === 200, "the enrolment: " +
            JSON.stringify(e.done && e.done.json).slice(0, 300));
  log.debug("Leaving holder().");
  return { who: who, key: key, portal: s };
}

// The forced change a sign-in met, answered with `password`.
async function changeThrough(realm, answer, password) {
  log.debug("Entering changeThrough().");
  if (answer.next !== "password-change") {
    log.debug("Leaving changeThrough(). No change asked.");
    return answer;
  }
  const changed = await authnSignin.changePassword(realm.base,
    answer.location,
    { new_password: password, confirm_password: password },
    { cookie: answer.cookie });
  log.debug("Leaving changeThrough(). " + changed.next);
  return changed;
}

async function realmFor(prefix, mfaAllowed) {
  log.debug("Entering realmFor(). " + prefix);
  const realm = await k.realm(prefix, "development");
  await setting(realm, "risk.assessSignIns", "false");
  await setting(realm, "webauthn.mfaAllowed", mfaAllowed ? "true" : "false");
  await k.client(realm);
  log.debug("Leaving realmFor().");
  return realm;
}

// ---------------------------------------------------------------------------
async function defaultsAndSaves(realm) {
  log.debug("Entering defaultsAndSaves().");
  log.info("=== A. the row's default, and G. its save ===");
  const prod = await k.realm("rap", "product");
  const dev = await k.call(realm, "GET", "/policies");
  const pro = await k.call(prod, "GET", "/policies");
  check("A. the built-in recoveryAssurance is `any` in development and " +
        "`not-weaker` in product", function () {
    assert.strictEqual(dev.body.passkey.profile.recoveryAssurance, "any");
    assert.strictEqual(pro.body.passkey.profile.recoveryAssurance,
                       "not-weaker");
  });
  const bad = await k.savePolicy(realm, { recoveryAssurance: "sometimes" });
  check("G. a value outside the three is refused", function () {
    assert.strictEqual(bad.status, 400, bad.raw.slice(0, 300));
  });
  await recoveryRow(realm, "operator-only");
  const defaults = await k.policyDefaults(realm);
  delete defaults.recoveryAssurance;
  const left = await k.call(realm, "POST", "/policies/save-passkey-policy",
    Object.assign({ profile: "default" }, defaults,
                  { allowUsernameless: false }));
  const kept = await k.call(realm, "GET", "/policies");
  check("G. a save that leaves the row out is accepted and keeps the value " +
        "stored (#907)", function () {
    assert.strictEqual(left.status, 200, left.raw.slice(0, 300));
    assert.strictEqual(kept.body.passkey.profile.recoveryAssurance,
                       "operator-only");
  });
  log.debug("Leaving defaultsAndSaves().");
}

async function underAnyAndNotWeaker(realm) {
  log.debug("Entering underAnyAndNotWeaker().");
  const ann = await holder(realm, k.STAMP.slice(0, 4) + "-ra-ann");

  log.info("=== C. under any ===");
  await recoveryRow(realm, "any");
  const spentAny = await spendLink(realm, ann.who, "Ra-" + k.STAMP + "-One1");
  const nothing = await pendingOf(realm, ann.who);
  const signAny = await passwordSignIn(realm, ann.who,
                                       "Ra-" + k.STAMP + "-One1");
  const anyWhere = await reached(realm, signAny.answer);
  check("C. under any the administrator's link is spent and no recovery " +
        "is recorded", function () {
    assert.strictEqual(spentAny.status, 200, spentAny.raw.slice(0, 300));
    assert.strictEqual(nothing.raw, "");
  });
  check("C. and the password alone, for a person holding a passkey, goes " +
        "on to the application", function () {
    assert.strictEqual(anyWhere, "session", anyWhere + " " +
              JSON.stringify(signAny.answer.json).slice(0, 300));
  });

  log.info("=== D. under not-weaker ===");
  await recoveryRow(realm, "not-weaker");
  const pw2 = "Ra-" + k.STAMP + "-Two2";
  const spent = await spendLink(realm, ann.who, pw2);
  const pending = await pendingOf(realm, ann.who);
  check("D. the spent link leaves a pending recovery naming its door",
        function () {
    assert.strictEqual(spent.status, 200, spent.raw.slice(0, 300));
    assert.strictEqual(pending.door, "admin-reset", pending.raw);
  });
  const signed = await passwordSignIn(realm, ann.who, pw2);
  check("D. the password sign-in starts no session and draws the set-up " +
        "step, marked recovery, offering only a passkey", function () {
    assert.ok(!wentOn(signed.answer), "it went on: " + signed.answer.next);
    assert.ok(isRecoverySetup(signed.step),
              JSON.stringify(signed.step && signed.step.view).slice(0, 400));
  });
  const chosen = await authnSignin.stepAct(signed.step, "setup/webauthn", {},
                                           { headers: k.BROWSER });
  const ceremonyStep = chosen.next === "mfa" && chosen.location
    ? await authnSignin.step(chosen.location,
                             { cookie: chosen.cookie || signed.step.cookie,
                               headers: k.BROWSER })
    : signed.step;
  const fresh = k.authenticator({});
  const before81 = await k.codeCount(realm, "STS-AUTHN-0381");
  const registered = await k.ceremony(ceremonyStep, function (c) {
    return c.mode === "create" || !c.allow
      ? fresh.register(c.challenge, (c.user && c.user.id) || "", c.rpId)
      : fresh.register(c.challenge, "", c.rpId);
  });
  const got81 = await gained(realm, "STS-AUTHN-0381", before81);
  const stillPending = await pendingOf(realm, ann.who);
  const landed = await follow(realm, registered);
  check("D. choosing a passkey draws a REGISTRATION ceremony",
        function () {
    const mode = registered.armed && registered.armed.json &&
                 registered.armed.json.mode;
    assert.strictEqual(mode, "create",
      JSON.stringify(registered.armed && registered.armed.json)
        .slice(0, 300));
  });
  // The ceremony's act answers `redirect`, and the authorization request
  // it names sends the browser back to the sign-in screen — no session was
  // started — and the refusal is one STS-AUTHN-0381 row (until
  // fix/node-defects-1114 none was recorded).
  check("D. a key REGISTERED in the act does not complete the recovery: " +
        "its redirect lands back on the sign-in screen, the recovery is " +
        "still pending, and one STS-AUTHN-0381 row is recorded (#901)",
        function () {
    assert.strictEqual(landed, "screen", landed + " " +
                       JSON.stringify(registered.json).slice(0, 300));
    assert.strictEqual(stillPending.door, "admin-reset", stillPending.raw);
    assert.strictEqual(got81, 1, "STS-AUTHN-0381 rows gained: " + got81);
  });
  const typed = await k.typed(realm, ann.who);
  const byKey = await k.ceremony(typed.step, function (c) {
    return ann.key.assert(c.challenge, {});
  });
  const keyWhere = await reached(realm, byKey);
  const cleared = await pendingOf(realm, ann.who);
  const after = await passwordSignIn(realm, ann.who, pw2);
  const afterWhere = await reached(realm, after.answer);
  check("D. a sign-in with the passkey the person already held starts a " +
        "session and clears the recovery", function () {
    assert.strictEqual(keyWhere, "session", keyWhere + " " +
              JSON.stringify(byKey.json).slice(0, 300) + " " +
              JSON.stringify(typed.answer.json).slice(0, 300));
    assert.strictEqual(cleared.raw, "");
  });
  check("D. once completed, the password signs in as before", function () {
    assert.strictEqual(afterWhere, "session", afterWhere + " " +
              JSON.stringify(after.answer.json).slice(0, 300));
  });

  log.info("=== H. an administrator's password on a passkey holder ===");
  const before = await ok(realm, "/users/set-password",
                          { user: ann.who, generate: true },
                          "set a generated password");
  const held = await pendingOf(realm, ann.who);
  const heldSignIn = await passwordSignIn(realm, ann.who, before.password);
  const changedTo = "Ra-" + k.STAMP + "-Changed6";
  const heldChange = await changeThrough(realm, heldSignIn.answer, changedTo);
  const heldStep = heldChange.next === "mfa" && heldChange.location
    ? await authnSignin.step(heldChange.location,
                             { cookie: heldChange.cookie,
                               headers: k.BROWSER })
    : null;
  // OBSERVED: `/admin-api/users/set-password` also sets the forced change
  // (its answer says so), so the sign-in meets the change first; the
  // in-process file drove the console's action and read pwdReset clear.
  check("H. under not-weaker set-password leaves a pending recovery naming " +
        "admin-password; the sign-in meets the forced change, and after it " +
        "the recovery set-up step, with no session", function () {
    assert.strictEqual(held.door, "admin-password", held.raw);
    assert.strictEqual(held.changeRequired, true);
    assert.strictEqual(heldSignIn.answer.next, "password-change",
                       heldSignIn.answer.next);
    assert.ok(isRecoverySetup(heldStep), heldChange.next + " " +
              JSON.stringify(heldStep && heldStep.view).slice(0, 300));
  });
  const typed2 = await k.typed(realm, ann.who);
  await k.ceremony(typed2.step, function (c) {
    return ann.key.assert(c.challenge, {});
  });
  await recoveryRow(realm, "any");
  const typedPw = "Ra-" + k.STAMP + "-Typed3";
  await ok(realm, "/users/set-password", { user: ann.who, password: typedPw },
           "set a typed password");
  const free = await pendingOf(realm, ann.who);
  const freeSignIn = await passwordSignIn(realm, ann.who, typedPw);
  const freeChange = await changeThrough(realm, freeSignIn.answer,
                                         "Ra-" + k.STAMP + "-Changed7");
  const freeWhere = await reached(realm, freeChange);
  log.info("a typed set-password's sign-in went to " +
           freeSignIn.answer.next);
  check("H. under any the same act (a typed password) leaves nothing " +
        "pending, and the password signs in", function () {
    assert.strictEqual(free.raw, "");
    assert.strictEqual(freeWhere, "session", freeWhere + " " +
              JSON.stringify(freeChange.json).slice(0, 300));
  });
  await recoveryRow(realm, "not-weaker");
  const before128 = await k.codeCount(realm, "STS-KRB-0128");
  const keytab = await k.call(realm, "POST",
    "/kerberos/principals/reset-person-keytab",
    { username: ann.who, password: "Ra-" + k.STAMP + "-Keytab4" });
  const got128 = await gained(realm, "STS-KRB-0128", before128);
  const afterKeytab = await pendingOf(realm, ann.who);
  const stillWorks = await passwordSignIn(realm, ann.who,
                                          "Ra-" + k.STAMP + "-Changed7");
  const worksWhere = await reached(realm, stillWorks.answer);
  check("H. reset-person-keytab in a realm whose KDC is off is refused " +
        "(STS-KRB-0128), leaves nothing pending, and the stored password " +
        "still signs in", function () {
    assert.ok(keytab.status >= 400 && keytab.status < 500,
              keytab.status + " " + keytab.raw.slice(0, 300));
    assert.ok(got128 >= 1, "STS-KRB-0128 rows gained: " + got128);
    assert.strictEqual(afterKeytab.raw, "");
    assert.strictEqual(worksWhere, "session", worksWhere);
  });

  log.info("=== F. under operator-only, an administrator's link ===");
  await recoveryRow(realm, "operator-only");
  const opSpent = await spendLink(realm, ann.who, "Ra-" + k.STAMP + "-Op5");
  check("F. under operator-only an administrator's reset link is still " +
        "spent", function () {
    assert.strictEqual(opSpent.status, 200, opSpent.raw.slice(0, 300));
    assert.ok(opSpent.body && opSpent.body.ok === true,
              opSpent.raw.slice(0, 300));
  });
  log.debug("Leaving underAnyAndNotWeaker().");
}

// ---------------------------------------------------------------------------
// E. A recovery code at the second-factor step.
// ---------------------------------------------------------------------------
async function recoveryCodes() {
  log.debug("Entering recoveryCodes().");
  log.info("=== E. a recovery code at the second-factor step ===");
  const realm = await realmFor("rae", true);
  const bob = await holder(realm, k.STAMP.slice(0, 4) + "-ra-bob");
  const shown = await bob.portal.act("/portal/mfa",
                                     { action: "generate-codes" });
  const view = (shown.json && (shown.json.view || shown.json)) || {};
  const fresh = view.fresh || {};
  const codes = fresh.codes || [];
  const handle = fresh.handle || "";
  const confirmed = await bob.portal.act("/portal/mfa",
    { action: "confirm-codes", handle: handle });
  assert.ok(confirmed.status === 200 && codes.length > 2,
            "the recovery codes: " + confirmed.status + " " +
            JSON.stringify(shown.json).slice(0, 600));

  await recoveryRow(realm, "operator-only");
  let signed = await passwordSignIn(realm, bob.who, SEED);
  const before80 = await k.codeCount(realm, "STS-AUTHN-0380");
  const spentCode = await authnSignin.stepAct(signed.step, "backup-code",
    { code: codes[0] }, { headers: k.BROWSER });
  const got80 = await gained(realm, "STS-AUTHN-0380", before80);
  check("E. under operator-only the second-factor step offers no recovery " +
        "code, and one spent anyway is refused (STS-AUTHN-0380)",
        function () {
    assert.strictEqual(signed.answer.next, "mfa", signed.answer.next);
    assert.strictEqual(signed.step.view.links.backup, false,
                       JSON.stringify(signed.step.view.links));
    assert.ok(!wentOn(spentCode), spentCode.next + " " +
              JSON.stringify(spentCode.json).slice(0, 300));
    assert.ok(got80 >= 1, "STS-AUTHN-0380 rows gained: " + got80);
  });

  await recoveryRow(realm, "not-weaker");
  signed = await passwordSignIn(realm, bob.who, SEED);
  const viaCode = await authnSignin.stepAct(signed.step, "backup-code",
    { code: codes[1] }, { headers: k.BROWSER });
  const next = viaCode.next === "mfa" && viaCode.location
    ? await authnSignin.step(viaCode.location,
                             { cookie: viaCode.cookie || signed.step.cookie,
                               headers: k.BROWSER })
    : null;
  const pending = await pendingOf(realm, bob.who);
  check("E. under not-weaker the step offers the code, and spending it " +
        "leads to the registration of a passkey rather than the " +
        "application", function () {
    assert.strictEqual(signed.step.view.links.backup, true,
                       JSON.stringify(signed.step.view.links));
    assert.ok(!wentOn(viaCode), viaCode.next + " " +
              JSON.stringify(viaCode.json).slice(0, 300));
    assert.strictEqual(viaCode.next, "mfa", viaCode.next);
    assert.ok(isRecoverySetup(next),
              JSON.stringify(next && next.view).slice(0, 300));
  });
  // The recovery the code began is written on the entry, as an
  // administrator's is (#31; until fix/node-defects-1114 nothing was).
  check("E. and the recovery that code began is pending on the entry",
        function () {
    assert.ok(pending.raw !== "", "nothing pending: " +
              JSON.stringify(pending));
    log.info("E. pending: " + pending.raw);
  });
  log.debug("Leaving recoveryCodes().");
}

async function main() {
  log.debug("Entering main().");
  let failure = null;
  try {
    const realm = await realmFor("rad", false);
    await defaultsAndSaves(realm);
    await underAnyAndNotWeaker(realm);
    await recoveryCodes();
    log.info(k.checks() + " check(s) passed.");
  } catch (e) {
    log.debug("Caught in main(): " + ((e && e.message) || e));
    // Reported below, after the realms are removed.
    failure = e;
  }
  try {
    await k.removeRealms();
  } catch (e) {
    log.debug("Caught in main(): " + ((e && e.message) || e));
    log.warn("could not remove the realms: " + ((e && e.message) || e));
  }
  if (failure) {
    log.error("sts_recovery_assurance FAILED: " +
              ((failure && failure.stack) || failure));
    log.debug("Leaving main(). Failed.");
    process.exit(1);
  }
  log.info("Test completed successfully.");
  log.debug("Leaving main().");
}

main();
