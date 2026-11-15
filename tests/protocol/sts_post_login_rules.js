// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_post_login_rules.js
//
// ===========================================================================
// POST-LOGIN ACTIVITIES AT THE SIGN-IN, OVER THE WIRE: THE POST-QUANTUM
// PASSKEY MIGRATION, WHO IS ASKED, AND WHAT NAMES THE POLICY (#1096,
// #1100-#1105, #1126, #1239).
//
// D12 (#444): carries over the part a client can see of three in-process
// files deleted at the cutover — `post_login.js`, `post_login_started.js`
// and `post_login_references.js` — with real sign-ins at the screen over
// `/authn-api`, real passkeys from `passkey_wire_kit.js`'s software
// authenticator (registered at the portal's `/account-api/keys`), the
// policy and the references written through `/admin-api`, and every code
// read off `/admin-api/audit`. `sts_post_login_activity.js` holds the
// invitation, Skip and the snooze for a person with no passkey; this job
// holds the rest:
//
//   A. THE POLICY'S REFUSALS: a bad profile name (the request schema's,
//      STS-API-0009, before STS-AUTHN-0470), a number out of its range or
//      a precedence outside 1 to 1000 (0471), and a passkey policy with
//      both lanes beside classical-only (0476).
//   B. ON: a person holding a classical passkey signs in with password and
//      passkey and is held at `/authn/post-login` — the view names the
//      reason (`classical`), the method and Skip, and no role; another
//      step's act on that step is refused and starts nothing.
//   C. THE UPGRADE: Register asks first for the classical passkey ALONE
//      (the proof, an assertion naming only it) and refuses a classical
//      retry; then registers ML-DSA only, the classical passkey left out
//      of the exclude list; the ML-DSA passkey REPLACES the classical one
//      in place (one key, post-quantum, the classical one gone) and the
//      held session starts — and the next sign-in is not asked.
//   D. ALONGSIDE: the page says another authenticator, the classical
//      passkey is excluded, and both are kept.
//   E. A DEVICE THAT CANNOT MAKE IT: the browser's error goes back to the
//      step's page, which names it, and an `authn.post-login.unsupported`
//      row records it.
//   F. NO PASSKEY, THE CLASSICAL FALLBACK: offered where the profile allows
//      it, the retry asking for no ML-DSA.
//   G. EXCLUSION AND THE REFERENCES (`post_login_references.js`): a named
//      profile saves with a precedence; a group naming a disabled profile
//      excludes its member; `appPostLoginPolicy` takes `default` or a named
//      profile and refuses another (STS-REG-0203); a group's
//      `stsPostLoginPolicy` refused for a name the realm does not hold
//      (STS-LDAP-0195); a disabled profile the APPLICATION names excludes a
//      sign-in to it and not to another; a profile in use is not deleted
//      (STS-AUTHN-0543), and once nothing names it, it is.
//   H. A STARTED ACTIVITY ASKS ITS GROUPS (`post_login_started.js`): with
//      the policy OFF, a member of a running activity's group is asked at
//      sign-in and a non-member is not; paused it asks nobody, resumed it
//      asks again, ended it asks nobody; one started for the realm reaches
//      a person in no group.
//
// NOT CARRIED, and why. Class (d): the policy's selection over a directory
// double, `dueFor()`'s answers where no sign-in shows them (I: an ML-DSA
// passkey with no post-quantum attestation recorded — no door records one
// as post-quantum without a post-quantum chain, which `sts_passkey_
// attestation_rules` holds), the moved clock of G1 (past the allotted time
// is days away; nothing over the wire moves the clock), so Skip's refusal
// (STS-AUTHN-0474) and a door that cannot draw the step (STS-AUTHN-0473)
// are owed with a clock this suite cannot set; the row #1101 marks
// possibly replaced and its removal guard (K: a passwordless person's
// portal, which no door signs in without a passkey ceremony at the
// portal's own client); `askedBy` on a progress row (the reports
// family's, `/report-api`); the console's markup (F of the references
// file); the portal's Upgrade and `webauthn.pqcUpgrade` being gone (M: an
// absence asserted by `sts_api_request_names` refusing unknown names).
//
// OWNED HERE (local: true): this repository's own `/authn-api`,
// `/account-api` and `/admin-api`.
// ===========================================================================

const assert = require("assert");
const wire = require("./passkey_wire_kit.js");
const portalSignin = require("./portal_signin.js");
const authnSignin = require("./authn_signin");

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
var log = bunyan.createLogger({ name: "sts_post_login_rules",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const k = wire.kit("sts_post_login_rules", { log: log });
const check = k.check;
const PASSWORD = "Pl-Rules-Passw0rd!-" + String(Date.now()).slice(-6);
const DEFAULTS = { enabled: true, activity: "pqc-passkey-migration",
                   snoozeDays: 3, graceDays: 30, noPasskey: "leave",
                   method: "upgrade", attestation: "any",
                   noPasskeyFallback: "none" };

function who(name) {
  log.debug("Entering who(). " + name);
  log.debug("Leaving who().");
  return (name + "-" + k.STAMP).slice(0, 30);
}

function savePolicy(realm, fields, profile) {
  log.debug("Entering savePolicy(). " + (profile || "default"));
  log.debug("Leaving savePolicy().");
  return k.call(realm, "POST", "/policies/save-postLogin-policy",
    Object.assign({ profile: profile || "default" }, DEFAULTS,
                  fields || {}));
}

async function mustSavePolicy(realm, fields, profile) {
  log.debug("Entering mustSavePolicy().");
  const r = await savePolicy(realm, fields, profile);
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "saving the post-login policy " + JSON.stringify(fields) + " answered " +
    r.status + " " + r.raw.slice(0, 400));
  log.debug("Leaving mustSavePolicy().");
}

// A person with a password and, where `alg` is given, one passkey of that
// algorithm registered at the portal (the realm's one lane offers both).
// `{ name, key, portal }`.
async function holder(realm, name, alg) {
  log.debug("Entering holder(). " + name);
  await k.person(realm, name, PASSWORD);
  const portal = await portalSignin.signInToThePortal(realm.base, name, null,
    { password: PASSWORD });
  let key = null;
  if (alg) {
    key = k.authenticator({ alg: alg });
    const done = await k.enrol(portal, key, {});
    assert.ok(done.done && done.done.status === 200,
      "registering " + name + "'s passkey answered " +
      JSON.stringify((done.done || done.begun).json).slice(0, 400));
  }
  log.debug("Leaving holder().");
  return { name: name, key: key, portal: portal };
}

// A password sign-in, the passkey step answered by `p.key` where one is
// asked: `{ answer, cookie }` — `answer.next` `redirect` (signed in) or
// `mfa` at the post-login step.
async function signIn(realm, p, clientId) {
  log.debug("Entering signIn(). " + p.name);
  const s = await k.screen(realm, undefined, clientId);
  let answer = await authnSignin.submit(realm.base, s.opened.id,
    { action: "login", username: p.name, password: PASSWORD },
    { screen: s.opened, cookie: s.opened.cookie, headers: k.BROWSER });
  if (answer.next === "mfa" && answer.step === "webauthn" && p.key) {
    const step = await authnSignin.step(answer.location,
      { cookie: answer.cookie, headers: k.BROWSER });
    answer = await k.ceremony(step, function (c) {
      return p.key.assert(c.challenge, { rpId: c.rpId });
    });
  }
  log.debug("Leaving signIn(). " + answer.next + " " + answer.step);
  return answer;
}

function heldAtPostLogin(answer) {
  log.debug("Entering heldAtPostLogin().");
  log.debug("Leaving heldAtPostLogin().");
  return answer.next === "mfa" &&
         /\/authn\/post-login(?:\?app=[^#]*)?[?#]mfa=/.test(
           String(answer.location || ""));
}

function startsSession(answer) {
  log.debug("Entering startsSession().");
  log.debug("Leaving startsSession().");
  return answer.next === "redirect" &&
         !/\/authn\//.test(String(answer.location || ""));
}

async function openStep(answer) {
  log.debug("Entering openStep().");
  const opened = await authnSignin.step(answer.location,
    { cookie: answer.cookie, headers: k.BROWSER });
  log.debug("Leaving openStep(). " + opened.status);
  return opened;
}

function act(opened, op, body) {
  log.debug("Entering act(). " + op);
  log.debug("Leaving act().");
  return authnSignin.stepAct(opened, op, body || {}, { headers: k.BROWSER });
}

async function rowsOf(realm, action, actor) {
  log.debug("Entering rowsOf(). " + action);
  const r = await k.call(realm, "GET", "/audit?per=500&action=" +
                         encodeURIComponent(action));
  const rows = ((r.body && (r.body.rows || r.body.events)) || []).filter(
    function (one) {
      return one.action === action && (!actor || one.actor === actor);
    });
  log.debug("Leaving rowsOf(). " + rows.length);
  return rows;
}

async function refusedUnder(realm, code, fn) {
  log.debug("Entering refusedUnder(). " + code);
  const before = await k.codeCount(realm, code);
  const r = await fn();
  const n = await k.newCodes(realm, code, before);
  log.debug("Leaving refusedUnder(). " + n);
  return { r: r, n: n };
}

async function refusals(realm) {
  log.debug("Entering refusals().");
  log.info("=== A. the policy's refusals ===");
  // A NAME THE SCHEMA REFUSES FIRST: the request schema holds the
  // profile's pattern, so STS-AUTHN-0470 is never reached through
  // /admin-api — the refusal is the schema's (STS-API-0009).
  const badName = await refusedUnder(realm, "STS-API-0009", function () {
    return savePolicy(realm, {}, "Not A Name!");
  });
  // A number the schema takes as a string is the policy's to refuse.
  const range = await refusedUnder(realm, "STS-AUTHN-0471", function () {
    return savePolicy(realm, { snoozeDays: "500" });
  });
  const precedence = await refusedUnder(realm, "STS-AUTHN-0471",
    function () {
      return savePolicy(realm, { precedence: "0" }, "pl-named");
    });
  check("A1. a bad profile name is refused by the request schema " +
        "(STS-API-0009, before STS-AUTHN-0470), and a number out of its " +
        "range or a named profile's precedence outside 1 to 1000 by the " +
        "policy (STS-AUTHN-0471), 400 each, no code sent", function () {
    [badName, range, precedence].forEach(function (one) {
      assert.strictEqual(one.r.status, 400, one.r.raw.slice(0, 300));
      assert.ok(one.n >= 1, one.r.raw.slice(0, 300));
      assert.ok(!/STS-[A-Z]+-\d{4}/.test(one.r.raw), one.r.raw);
    });
    assert.ok(/from 1 to 90/.test(range.r.raw), range.r.raw);
    assert.ok(/from 1 to 1000/.test(precedence.r.raw), precedence.r.raw);
  });
  const lanes = await refusedUnder(realm, "STS-AUTHN-0476", function () {
    return k.savePolicy(realm, { lanes: "both",
                                 registrationMode: "classical-only" });
  });
  check("A2. a passkey policy with both lanes beside classical-only is " +
        "refused (STS-AUTHN-0476)", function () {
    assert.ok(lanes.r.status === 400 || (lanes.r.body &&
              lanes.r.body.ok === false), lanes.r.raw.slice(0, 300));
    assert.ok(lanes.n >= 1, lanes.r.raw.slice(0, 300));
  });
  log.debug("Leaving refusals().");
}

async function migration(realm) {
  log.debug("Entering migration().");
  log.info("=== B. on: a classical passkey's holder is held ===");
  const ann = await holder(realm, who("pla-ann"), -7);
  const off = await signIn(realm, ann);
  check("B0. off, a password and passkey sign-in goes straight on",
    function () {
      assert.ok(startsSession(off), k.said(off));
    });
  await mustSavePolicy(realm, { method: "upgrade" });
  const held = await signIn(realm, ann);
  const startsBefore = (await rowsOf(realm, "session.start", ann.name))
    .length;
  check("B1. on, the sign-in starts no session and lands on the post-login " +
        "step", function () {
    assert.ok(heldAtPostLogin(held), k.said(held) + " " + held.location);
  });
  let opened = await openStep(held);
  check("B2. its view names the reason, the method and Skip, and no role",
    function () {
      const v = (opened.view || {}).postLogin || {};
      assert.strictEqual(opened.status, 200, String(opened.text).slice(0,
                                                                  300));
      assert.ok(v.role === undefined && v.reason === "classical" &&
                v.canSkip === true && v.snoozeDays === 3 &&
                v.method === "upgrade", JSON.stringify(opened.view));
    });
  const roundAbout = await act(opened, "totp", { code: "000000" });
  const startsAfter = (await rowsOf(realm, "session.start", ann.name))
    .length;
  check("B3. another step's act on the post-login step is refused and " +
        "starts nothing", function () {
    assert.ok(!startsSession(roundAbout), k.said(roundAbout));
    assert.ok(roundAbout.apiStatus === 400 || roundAbout.status === 400,
              JSON.stringify([roundAbout.apiStatus, roundAbout.status]));
    assert.strictEqual(startsAfter, startsBefore);
  });

  log.info("=== C. the upgrade ===");
  const toProof = await act(opened, "post-login/register");
  const proofPage = await openStep(toProof);
  const pw = (proofPage.view || {}).webauthn || {};
  const retry = await act(proofPage, "webauthn/options",
                          { algorithms: "classical" });
  const proved = await k.ceremony(proofPage, function (c) {
    return ann.key.assert(c.challenge, { rpId: c.rpId });
  });
  check("C1. Register asks first for the classical passkey ALONE — the " +
        "proof — and a classical retry is refused", function () {
    assert.ok(toProof.next === "mfa" && toProof.step === "webauthn",
              k.said(toProof));
    assert.ok(pw.mode === "get" && pw.postLogin && pw.postLogin.upgrade &&
              pw.postLogin.upgrade.phase === "proof", JSON.stringify(pw));
    assert.deepStrictEqual(((proved.armed || {}).json || {}).ceremony
      ? proved.armed.json.ceremony.allow : proved.armed.json.allow,
      [ann.key.credentialId]);
    assert.ok(retry.apiStatus === 400 || retry.status === 400,
              JSON.stringify([retry.apiStatus, retry.status]));
    assert.ok(proved.next === "mfa" && proved.step === "webauthn",
              k.said(proved));
  });
  const createPage = await openStep(proved);
  const cw = (createPage.view || {}).webauthn || {};
  const pq = k.authenticator({ alg: -49 });
  const made = await k.ceremony(createPage, function (c) {
    return pq.register(c.challenge, c.user && c.user.id, c.rpId);
  });
  const keys = await k.keysOf(realm, ann.name);
  const armed = (made.armed && made.armed.json) || {};
  const exclude = (armed.ceremony && armed.ceremony.exclude) ||
                  armed.exclude || [];
  check("C2. the registration is ML-DSA only with the classical passkey " +
        "left out of the exclude list", function () {
    assert.ok(cw.mode === "create" && (cw.algorithms || []).length > 0 &&
              cw.algorithms.every(function (one) {
                return /^ML-DSA-/.test(one);
              }), JSON.stringify(cw.algorithms));
    assert.ok(exclude.indexOf(ann.key.credentialId) < 0,
              JSON.stringify(exclude));
  });
  check("C3. the ML-DSA passkey REPLACES the classical one in place — one " +
        "key, post-quantum, the classical one gone — and the held session " +
        "starts", function () {
    assert.ok(startsSession(made), k.said(made));
    assert.strictEqual(keys.length, 1, JSON.stringify(keys).slice(0, 500));
    assert.strictEqual(keys[0].credentialId, pq.credentialId);
    assert.ok(!keys[0].role, JSON.stringify(keys[0]));
    assert.ok(keys[0].algorithm && keys[0].algorithm.postQuantum === true,
              JSON.stringify(keys[0]).slice(0, 500));
  });
  const doneRows = await rowsOf(realm, "authn.post-login.done", ann.name);
  ann.key = pq;
  const after = await signIn(realm, ann);
  check("C4. one `authn.post-login.done` row, and the next sign-in is not " +
        "asked", function () {
    assert.strictEqual(doneRows.length, 1, JSON.stringify(doneRows));
    assert.ok(startsSession(after), k.said(after));
  });

  log.info("=== D. alongside ===");
  await mustSavePolicy(realm, { method: "alongside" });
  const fay = await holder(realm, who("pla-fay"), -7);
  const fayHeld = await signIn(realm, fay);
  const fayOpened = await openStep(fayHeld);
  const fv = (fayOpened.view || {}).postLogin || {};
  const toCreate = await act(fayOpened, "post-login/register");
  const fayPage = await openStep(toCreate);
  const fayPq = k.authenticator({ alg: -49 });
  const fayMade = await k.ceremony(fayPage, function (c) {
    return fayPq.register(c.challenge, c.user && c.user.id, c.rpId);
  });
  const fayArmed = (fayMade.armed && fayMade.armed.json) || {};
  const fayExclude = (fayArmed.ceremony && fayArmed.ceremony.exclude) ||
                     fayArmed.exclude || [];
  const fayKeys = await k.keysOf(realm, fay.name);
  check("D1. alongside: the page says another authenticator, the classical " +
        "passkey is excluded, and both passkeys are kept", function () {
    assert.ok(fv.method === "alongside" && fv.separate === true,
              JSON.stringify(fv));
    assert.strictEqual(((fayPage.view || {}).webauthn || {}).mode,
                       "create");
    assert.ok(fayExclude.indexOf(fay.key.credentialId) >= 0,
              JSON.stringify(fayExclude));
    assert.ok(startsSession(fayMade), k.said(fayMade));
    assert.strictEqual(fayKeys.length, 2, JSON.stringify(fayKeys));
  });

  log.info("=== E. a device that cannot make it ===");
  const dan = await holder(realm, who("pla-dan"), -7);
  const danHeld = await signIn(realm, dan);
  const danOpened = await openStep(danHeld);
  const toDan = await act(danOpened, "post-login/register");
  const danPage = await openStep(toDan);
  const failed = await act(danPage, "webauthn",
    { credential: JSON.stringify({ error: "NotSupportedError",
                                   message: "SECRET FREE TEXT" }) });
  const back = failed.next === "mfa" ? await openStep(failed) : {};
  const unsupported = await rowsOf(realm, "authn.post-login.unsupported",
                                   dan.name);
  check("E1. a ceremony the device did not complete goes back to the step " +
        "page, which names it, and leaves an audit row with the error " +
        "NAME", function () {
    assert.strictEqual(failed.step, "post-login", k.said(failed));
    assert.strictEqual(((back.view || {}).postLogin || {}).failed,
                       "NotSupportedError", JSON.stringify(back.view));
    assert.strictEqual(unsupported.length, 1, JSON.stringify(unsupported));
    assert.strictEqual(unsupported[0].detail.error, "NotSupportedError");
    assert.strictEqual(unsupported[0].errorCode, "STS-AUTHN-0022");
    assert.ok(JSON.stringify(unsupported).indexOf("SECRET FREE TEXT") < 0);
  });

  log.info("=== F. no passkey: the classical fallback ===");
  // Made BEFORE the save: the portal's own sign-in would otherwise be the
  // first one asked, and the helper presses Skip there.
  const ivy = await holder(realm, who("pla-ivy"), 0);
  await mustSavePolicy(realm, { noPasskey: "invite", method: "automatic",
                                noPasskeyFallback: "classical" });
  const ivyHeld = await signIn(realm, ivy);
  assert.ok(heldAtPostLogin(ivyHeld), "the sign-in of a person with no " +
    "passkey was not held: " + k.said(ivyHeld).slice(0, 400) + " " +
    ivyHeld.next + " " + ivyHeld.step + " " + ivyHeld.location);
  const ivyOpened = await openStep(ivyHeld);
  const toIvy = await act(ivyOpened, "post-login/register");
  const ivyPage = await openStep(toIvy);
  const ivyFacts = (ivyPage.view || {}).webauthn || {};
  const ivyRetry = await act(ivyPage, "webauthn/options",
                             { algorithms: "classical" });
  check("F1. a person with no passkey is offered the classical retry where " +
        "the profile allows it, and the retry asks for no ML-DSA",
    function () {
      assert.ok(heldAtPostLogin(ivyHeld), k.said(ivyHeld));
      assert.ok(ivyFacts.fallback && ivyFacts.fallback.classical === true,
                JSON.stringify(ivyFacts.fallback));
      const opts = (ivyRetry.json && (ivyRetry.json.options ||
        (ivyRetry.json.ceremony && ivyRetry.json.ceremony.options))) || {};
      assert.ok(ivyRetry.apiStatus === 200 || ivyRetry.status === 200,
                JSON.stringify(ivyRetry.json).slice(0, 300));
      assert.ok((opts.algorithms || []).length > 0 &&
                opts.algorithms.every(function (one) {
                  return [-48, -49, -50].indexOf(Number(one)) < 0;
                }), JSON.stringify(opts.algorithms));
    });
  await k.call(realm, "POST", "/policies/reset-postLogin-policy",
               { profile: "default" });
  log.debug("Leaving migration().");
}

async function references(realm) {
  log.debug("Entering references().");
  log.info("=== G. exclusion, and what names the policy ===");
  await mustSavePolicy(realm, { method: "alongside" });
  await mustSavePolicy(realm, { enabled: false, precedence: 10 },
                       "excluded");
  const group = who("pl-excl").toLowerCase();
  const made = await k.call(realm, "POST", "/groups/create",
                            { group: group });
  assert.strictEqual(made.status, 200, made.raw.slice(0, 300));
  const eve = await holder(realm, who("pla-eve"), -7);
  const bob = await holder(realm, who("pla-bob"), -7);
  await k.call(realm, "POST", "/groups/add-member",
               { group: group, member: eve.name });
  const unknown = await refusedUnder(realm, "STS-LDAP-0195", function () {
    return k.call(realm, "POST", "/groups/set-policy", { group: group,
      attribute: "stsPostLoginPolicy", policy: "nobody-holds-this" });
  });
  check("G1. a group's stsPostLoginPolicy naming a profile the realm does " +
        "not hold is refused (STS-LDAP-0195)", function () {
    assert.ok(refusedLike(unknown.r), unknown.r.raw.slice(0, 300));
    assert.ok(unknown.n >= 1, unknown.r.raw.slice(0, 300));
  });
  const named = await k.call(realm, "POST", "/groups/set-policy",
    { group: group, attribute: "stsPostLoginPolicy", policy: "excluded" });
  assert.strictEqual(named.status, 200, named.raw.slice(0, 300));
  const eveIn = await signIn(realm, eve);
  const bobIn = await signIn(realm, bob);
  check("G2. a disabled named profile a group names excludes its member; " +
        "a person it does not reach is asked", function () {
    assert.ok(startsSession(eveIn), k.said(eveIn));
    assert.ok(heldAtPostLogin(bobIn), k.said(bobIn));
  });
  const policies = await k.call(realm, "GET", "/policies");
  check("G3. the named profile reads back with its precedence and the " +
        "group naming it, and the kind's references", function () {
    const kind = (policies.body && policies.body.postLogin) || {};
    const row = (kind.named || []).filter(function (one) {
      return one.name === "excluded";
    })[0] || {};
    assert.strictEqual(row.precedence, 10, JSON.stringify(kind)
      .slice(0, 600));
    assert.ok(((row.namedBy || {}).groups || []).indexOf(group) >= 0,
              JSON.stringify(row));
  });

  // THE APPLICATION'S REFERENCE.
  const other = await k.client(realm, "pl-other-client");
  const bad = await refusedUnder(realm, "STS-REG-0203", function () {
    return k.call(realm, "POST", "/applications/set", {
      application: k.CLIENT, attribute: "appPostLoginPolicy",
      value: "nobody-holds-this" });
  });
  check("G4. appPostLoginPolicy refuses a name that is neither default " +
        "nor a named profile (STS-REG-0203)", function () {
    assert.ok(refusedLike(bad.r), bad.r.raw.slice(0, 300));
    assert.ok(bad.n >= 1, "STS-REG-0203 rows: " + bad.n + " " +
              bad.r.raw.slice(0, 300));
  });
  const appSet = await k.call(realm, "POST", "/applications/set", {
    application: k.CLIENT, attribute: "appPostLoginPolicy",
    value: "excluded" });
  assert.ok(appSet.status === 200 && appSet.body.ok !== false,
            appSet.raw.slice(0, 300));
  const bobHere = await signIn(realm, bob, k.CLIENT);
  const bobThere = await signIn(realm, bob, other);
  check("G5. a disabled profile the APPLICATION names excludes a sign-in " +
        "to it, and a sign-in to another application is asked", function () {
    assert.ok(startsSession(bobHere), k.said(bobHere));
    assert.ok(heldAtPostLogin(bobThere), k.said(bobThere));
  });
  const inUse = await refusedUnder(realm, "STS-AUTHN-0543", function () {
    return k.call(realm, "POST", "/policies/reset-postLogin-policy",
                  { profile: "excluded" });
  });
  check("G6. a profile an application or a group names is not deleted " +
        "(STS-AUTHN-0543)", function () {
    assert.ok(refusedLike(inUse.r), inUse.r.raw.slice(0, 300));
    assert.ok(inUse.n >= 1, inUse.r.raw.slice(0, 300));
  });
  await k.call(realm, "POST", "/applications/set", {
    application: k.CLIENT, attribute: "appPostLoginPolicy",
    value: "default" });
  await k.call(realm, "POST", "/groups/set-policy",
    { group: group, attribute: "stsPostLoginPolicy", policy: "" });
  const gone = await k.call(realm, "POST", "/policies/reset-postLogin-policy",
                            { profile: "excluded" });
  const after = await k.call(realm, "GET", "/policies");
  check("G7. once nothing names it, it is deleted", function () {
    assert.ok(gone.status === 200 && gone.body.ok !== false,
              gone.raw.slice(0, 300));
    const kind = (after.body && after.body.postLogin) || {};
    assert.ok(!(kind.named || []).some(function (one) {
      return one.name === "excluded";
    }), JSON.stringify(kind.named));
  });
  await k.call(realm, "POST", "/policies/reset-postLogin-policy",
               { profile: "default" });
  log.debug("Leaving references().");
}

function refusedLike(r) {
  log.debug("Entering refusedLike().");
  log.debug("Leaving refusedLike().");
  return r.status >= 400 || (r.body && r.body.ok === false);
}

async function started(realm) {
  log.debug("Entering started().");
  log.info("=== H. a started activity asks its groups ===");
  const staff = who("pl-staff").toLowerCase();
  const made = await k.call(realm, "POST", "/groups/create",
                            { group: staff });
  assert.strictEqual(made.status, 200, made.raw.slice(0, 300));
  const cat = await holder(realm, who("pla-cat"), -7);
  const hal = await holder(realm, who("pla-hal"), -7);
  await k.call(realm, "POST", "/groups/add-member",
               { group: staff, member: cat.name });
  const quiet = await signIn(realm, cat);
  check("H1. the policy off and nothing started: nobody is asked",
    function () {
      assert.ok(startsSession(quiet), k.said(quiet));
    });
  const start = await k.call(realm, "POST", "/post-login-activities/start",
    { activity: "pqc-passkey-migration", groups: [staff] });
  assert.ok(start.status === 200 && start.body.ok !== false,
            "starting the activity answered " + start.status + " " +
            start.raw.slice(0, 400));
  const id = start.body.started && start.body.started.id;
  const catAsked = await signIn(realm, cat);
  const halNot = await signIn(realm, hal);
  check("H2. with the policy off, a member of the started activity's group " +
        "is asked at sign-in, and a non-member is not", function () {
    assert.ok(heldAtPostLogin(catAsked), k.said(catAsked));
    assert.ok(startsSession(halNot), k.said(halNot));
  });
  await k.call(realm, "POST", "/post-login-activities/pause", { id: id });
  const paused = await signIn(realm, cat);
  await k.call(realm, "POST", "/post-login-activities/resume", { id: id });
  const resumed = await signIn(realm, cat);
  await k.call(realm, "POST", "/post-login-activities/end", { id: id });
  const ended = await signIn(realm, cat);
  check("H3. paused it asks nobody, resumed it asks again, ended it asks " +
        "nobody", function () {
    assert.ok(startsSession(paused), k.said(paused));
    assert.ok(heldAtPostLogin(resumed), k.said(resumed));
    assert.ok(startsSession(ended), k.said(ended));
  });
  const whole = await k.call(realm, "POST", "/post-login-activities/start",
    { activity: "pqc-passkey-migration" });
  assert.ok(whole.status === 200 && whole.body.ok !== false,
            "starting the realm's activity answered " + whole.status + " " +
            whole.raw.slice(0, 400));
  const halNow = await signIn(realm, hal);
  check("H4. one started for the realm reaches a person in no group",
    function () {
      assert.ok(heldAtPostLogin(halNow), k.said(halNow));
    });
  const wholeId = whole.body.started && whole.body.started.id;
  await k.call(realm, "POST", "/post-login-activities/end", { id: wholeId });
  log.debug("Leaving started().");
}

async function test() {
  log.debug("Entering test().");
  const realm = await k.realm("pl-rules", "development");
  await k.client(realm);
  await k.mustSet(realm, "oauth2.consentRequired", false);
  log.info("Driving " + realm.base);
  await refusals(realm);
  await migration(realm);
  const refs = await k.realm("pl-refs", "development");
  await k.client(refs);
  await k.mustSet(refs, "oauth2.consentRequired", false);
  await references(refs);
  const starts = await k.realm("pl-start", "development");
  await k.client(starts);
  await k.mustSet(starts, "oauth2.consentRequired", false);
  await started(starts);
  assert.ok(k.checks() >= 20, "only " + k.checks() + " checks ran; a " +
            "section has stopped being called.");
  log.debug("Leaving test().");
}

k.main(test);
