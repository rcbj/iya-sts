// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: sts_passkey_post_quantum_rules.js
//
// ===========================================================================
// THE CLASSICAL RETRY OF AN ML-DSA REGISTRATION, LIST-AND-REFUSE, AND A
// POST-QUANTUM PASSKEY REQUIRED FOR ONE APPLICATION, OVER THE WIRE (#718,
// #944, #946).
//
// D12 (#444): carries over what a client can see of
// `tests/passkey_post_quantum_fallback.js` and the parts of
// `tests/passkey_post_quantum_required.js` that
// `sts_passkey_post_quantum_required.js` does not already hold. Real
// ceremonies from the kit's software authenticators (ES256 and ML-DSA-65,
// keys made when the job runs), every setting a realm's own
// (`/admin-api/config/set` under its prefix), every code off the realm's
// `/admin-api/audit`:
//
//   F. THE RETRY AT THE PORTAL (`/account-api/keys`): a waiting
//      registration carries the fallback facts (asks ML-DSA, a retry
//      offered); a retry begun with `algorithms: classical` asks for no
//      ML-DSA, says it is the retry and registers an ES256 key; an ML-DSA
//      credential answering it is refused as not offered (STS-AUTHN-0228);
//      under `webauthn.pqcOnly` the retry is refused at the begin
//      (STS-AUTHN-0420) and a plain begin asks only ML-DSA and offers no
//      retry; under `registration-and-sign-in` it is refused too, and under
//      `sign-in` the portal still offers it;
//   S. THE RETRY AT THE SIGN-IN STEP: a person setting up a passkey at
//      sign-in arms it through `webauthn/options` with
//      `algorithms: classical`, asks for no ML-DSA, registers an ES256 key
//      and is signed in; under a profile requiring a post-quantum passkey
//      at sign-in the step offers none, and one asked for anyway is refused
//      400 (STS-AUTHN-0420);
//   L. #946: `narrow`, the default, names only the post-quantum key;
//      `webauthn.postQuantumAllowCredentials: list-and-refuse` names both,
//      the classical assertion is refused after the ceremony
//      (STS-AUTHN-0356) and the screen carries the panel's registration link
//      and no upgrade link, and the post-quantum key from the same list
//      signs in; the profile's row overrides the realm's setting both ways;
//      a person holding only a classical key is still told before the
//      ceremony, with the panel's link;
//   R. A NAMED PROFILE AN APPLICATION NAMES (`appPasskeyPolicy`) refuses a
//      classical passkey for that application only (STS-AUTHN-0356, saying
//      why) and the same key signs in to another; a person holding only a
//      classical key is told on the passwordless step and refused before
//      the ceremony is armed, and so is the step after a password, where an
//      assertion sent anyway is refused at the session's start;
//   P. with both lanes on (`webauthn.pqcAlongsideClassical`) and
//      `registration-and-sign-in`, only the post-quantum lane is offered and
//      a classical choice becomes it.
//
// NOT CARRIED: fallback A1-A4's library answers beyond what a begin shows
// (`classicalRetryLane()`, #939's `postQuantumUpgradeOffered()`), B1/B4's
// drawn guidance and E (the browser bundle's `failureKind()`,
// `offerFallback()` and the renderers) — class (d); D4's "the question
// carries the resolved value as a policy fact" (an internal question, (d));
// required 6 (the CAEP credential-change once per key and reason: owed by
// the Shared Signals family, phase 9, with a receiver) and 9 (the device
// link: owed by the devices family's job); required 8a's `addKey()`
// refusal STS-AUTHN-0355 is in process only — over the wire the ceremony
// refuses first (STS-AUTHN-0228, `sts_passkey_post_quantum_required.js`).
//
// OWNED HERE (local: true): the passkey policy is this repository's own.
// ===========================================================================

"use strict";

const assert = require("assert");
const wire = require("./passkey_wire_kit.js");
const portalSignin = require("./portal_signin.js");
const fixtures = require("./oauth_fixtures.js");
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
var log = bunyan.createLogger({ name: "sts_passkey_post_quantum_rules",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const K = wire.kit("sts_passkey_post_quantum_rules", { log: log });
const check = K.check;
const PASSWORD = "Pk-pq-rules-" + K.STAMP + "-Aa1!";
const ML_DSA = [-48, -49, -50];

function who(name) {
  log.debug("Entering who(). " + name);
  log.debug("Leaving who().");
  return ("pkq-" + name + "-" + K.STAMP).slice(0, 40);
}

function noPq(algorithms) {
  log.debug("Entering noPq().");
  log.debug("Leaving noPq().");
  return Array.isArray(algorithms) && algorithms.length > 0 &&
    algorithms.every(function (alg) {
      return ML_DSA.indexOf(alg) < 0 && !/^ML-DSA/.test(String(alg));
    });
}

function onlyPq(algorithms) {
  log.debug("Entering onlyPq().");
  log.debug("Leaving onlyPq().");
  return Array.isArray(algorithms) && algorithms.length > 0 &&
    algorithms.every(function (alg) {
      return ML_DSA.indexOf(alg) >= 0 || /^ML-DSA/.test(String(alg));
    });
}

async function refusedWith(realm, code, act) {
  log.debug("Entering refusedWith(). " + code);
  const before = await K.codeCount(realm, code);
  const r = await act();
  const recorded = await K.newCodes(realm, code, before);
  if (!recorded) {
    const last = await K.call(realm, "GET", "/audit?per=3&outcome=refused");
    log.info("no " + code + " row; the newest refusals: " +
             JSON.stringify(((last.body && last.body.events) || [])
               .map(function (row) {
                 return row.errorCode;
               })));
  }
  log.debug("Leaving refusedWith(). " + recorded);
  return { r: r, recorded: recorded };
}

async function setting(realm, key, value) {
  log.debug("Entering setting(). " + key);
  await K.mustSet(realm, key, value);
  log.debug("Leaving setting().");
}

async function portalFor(realm, name) {
  log.debug("Entering portalFor(). " + name);
  await K.person(realm, name, PASSWORD);
  const client = await portalSignin.signInToThePortal(realm.base, name, null,
    { password: PASSWORD });
  log.debug("Leaving portalFor().");
  return client;
}

// A begin at `/account-api/keys`, `algorithms: classical` where `retry`,
// and the waiting registration read back: `{ begun, pending }`.
async function begin(client, retry, lane) {
  log.debug("Entering begin(). " + retry);
  const body = { action: "begin", kind: "passkey" };
  if (retry) {
    body.algorithms = "classical";
  }
  if (lane) {
    body.lane = lane;
  }
  const begun = await client.api("POST", "/account-api/keys", body);
  const page = await client.api("GET", "/account-api/keys");
  const pending = (page.json && page.json.enrol &&
                   page.json.enrol.pending) || null;
  log.debug("Leaving begin(). " + begun.status);
  return { begun: begun, pending: pending, page: page };
}

async function finish(client, pending, auth) {
  log.debug("Entering finish().");
  const done = await client.api("POST", "/account-api/keys",
    { action: "finish", enrolment_id: pending.id,
      credential: JSON.stringify(auth.register(pending.challenge,
        pending.userHandle, pending.rpId)) });
  log.debug("Leaving finish(). " + done.status);
  return done;
}

async function cancel(client) {
  log.debug("Entering cancel().");
  await client.api("POST", "/account-api/keys", { action: "cancel" });
  log.debug("Leaving cancel().");
}

// A passwordless typed sign-in for `clientId` to its passkey step.
async function passkeyStepFor(realm, name, clientId, password) {
  log.debug("Entering passkeyStepFor(). " + name);
  const s = await K.screen(realm, K.BROWSER, clientId);
  const fields = password
    ? { action: "login", username: name, password: password,
        use_webauthn: "1" }
    : { action: "login", username: name, password: "", webauthn_only: "1" };
  const answer = await authnSignin.submit(realm.base, s.opened.id, fields,
    { screen: s.opened, cookie: s.opened.cookie, headers: K.BROWSER });
  assert.ok(answer.next === "mfa" && answer.location,
            name + " reached no passkey step: " + K.said(answer)
              .slice(0, 300));
  const step = await authnSignin.step(answer.location,
    { cookie: answer.cookie, headers: K.BROWSER });
  log.debug("Leaving passkeyStepFor().");
  return step;
}

function viewOf(step) {
  log.debug("Entering viewOf().");
  log.debug("Leaving viewOf().");
  return (step.json && step.json.view && step.json.view.webauthn) || {};
}

function arm(step, body) {
  log.debug("Entering arm().");
  log.debug("Leaving arm().");
  return authnSignin.stepAct(step, "webauthn/options", body || {},
                             { headers: K.BROWSER });
}

function answerStep(step, armed, credential) {
  log.debug("Entering answerStep().");
  log.debug("Leaving answerStep().");
  return authnSignin.stepAct(step, "webauthn",
    { credential: JSON.stringify(credential) },
    { cookie: armed.cookie, headers: K.BROWSER });
}

async function portalRetry() {
  log.debug("Entering portalRetry().");
  log.info("=== F. the classical retry at the portal ===");
  const realm = await K.realm("pkq-f", "development");
  const client = await portalFor(realm, who("ann"));
  const first = await begin(client, false);
  await cancel(client);
  check("F1. a waiting registration carries the fallback facts: it asks " +
        "for ML-DSA and a classical retry is offered", function () {
    assert.ok(first.pending, JSON.stringify(first.begun.json));
    assert.deepStrictEqual(first.pending.fallback,
      { asksPostQuantum: true, classical: true, retrying: false });
    assert.ok(!noPq(first.pending.options.algorithms),
              JSON.stringify(first.pending.options.algorithms));
  });
  const retried = await begin(client, true);
  const annKey = K.authenticator({});
  const done = await finish(client, retried.pending, annKey);
  check("F2. a retry begun with the classical algorithms only asks for no " +
        "ML-DSA, says it is the retry, and registers an ES256 key",
        function () {
    assert.ok(retried.pending, JSON.stringify(retried.begun.json));
    assert.ok(noPq(retried.pending.options.algorithms),
              JSON.stringify(retried.pending.options.algorithms));
    assert.strictEqual(retried.pending.fallback.retrying, true);
    assert.strictEqual(retried.pending.fallback.classical, false);
    assert.strictEqual(done.status, 200, JSON.stringify(done.json)
      .slice(0, 300));
  });
  const wrong = await refusedWith(realm, "STS-AUTHN-0228", async function () {
    const again = await begin(client, true);
    const r = await finish(client, again.pending,
                           K.authenticator({ alg: -49 }));
    return r;
  });
  check("F3. an ML-DSA credential answering the classical retry is refused " +
        "as an algorithm not offered (STS-AUTHN-0228)", function () {
    assert.strictEqual(wrong.r.status, 400, JSON.stringify(wrong.r.json)
      .slice(0, 300));
    assert.ok(wrong.recorded > 0, "no STS-AUTHN-0228 row");
  });
  await cancel(client);

  await setting(realm, "webauthn.pqcOnly", true);
  const onlyRetry = await refusedWith(realm, "STS-AUTHN-0420", function () {
    return begin(client, true).then(function (b) {
      return b.begun;
    });
  });
  await cancel(client);
  const onlyPlain = await begin(client, false);
  await cancel(client);
  await K.reset(realm, "webauthn.pqcOnly");
  check("F4. under webauthn.pqcOnly the retry is refused at the begin " +
        "(STS-AUTHN-0420), and a plain begin asks only ML-DSA and offers no " +
        "retry", function () {
    assert.ok(onlyRetry.r.status >= 400, JSON.stringify(onlyRetry.r.json));
    assert.ok(onlyRetry.recorded > 0, "no STS-AUTHN-0420 row");
    assert.ok(onlyPlain.pending, JSON.stringify(onlyPlain.begun.json));
    assert.ok(onlyPq(onlyPlain.pending.options.algorithms),
              JSON.stringify(onlyPlain.pending.options.algorithms));
    assert.strictEqual(onlyPlain.pending.fallback.classical, false);
  });

  await K.mustSavePolicy(realm,
                         { postQuantumRequired: "registration-and-sign-in" });
  const regRetry = await refusedWith(realm, "STS-AUTHN-0420", function () {
    return begin(client, true).then(function (b) {
      return b.begun;
    });
  });
  await cancel(client);
  await K.mustSavePolicy(realm, { postQuantumRequired: "sign-in" });
  const signInRetry = await begin(client, true);
  await cancel(client);
  check("F5. registration-and-sign-in refuses the retry too " +
        "(STS-AUTHN-0420); under sign-in the portal still offers it",
        function () {
    assert.ok(regRetry.r.status >= 400, JSON.stringify(regRetry.r.json));
    assert.ok(regRetry.recorded > 0, "no STS-AUTHN-0420 row");
    assert.strictEqual(signInRetry.begun.status, 200,
                       JSON.stringify(signInRetry.begun.json));
    assert.ok(signInRetry.pending &&
              noPq(signInRetry.pending.options.algorithms),
              JSON.stringify(signInRetry.pending));
  });
  log.debug("Leaving portalRetry().");
}

async function stepRetry() {
  log.debug("Entering stepRetry().");
  log.info("=== S. the classical retry at the sign-in step ===");
  const realm = await K.realm("pkq-s", "development");
  await K.client(realm);
  const ben = who("ben");
  await K.person(realm, ben, null);
  const step = await passkeyStepFor(realm, ben, K.CLIENT);
  const view = viewOf(step);
  const armed = await arm(step, { algorithms: "classical" });
  const benKey = K.authenticator({});
  const c = armed.json || {};
  const done = c.ok ? await answerStep(step, armed,
    benKey.register(c.challenge, (c.user || {}).id, c.rpId))
    : { next: "" };
  const keys = await K.keysOf(realm, ben);
  check("S1. at the sign-in step the classical retry is offered, armed " +
        "through the API, asks for no ML-DSA, registers an ES256 key and " +
        "signs the person in", function () {
    assert.strictEqual(view.mode, "create", JSON.stringify(view)
      .slice(0, 300));
    assert.strictEqual(view.fallback.classical, true,
                       JSON.stringify(view.fallback));
    assert.ok(c.ok && c.fallback && c.fallback.retrying === true,
              JSON.stringify(c).slice(0, 300));
    assert.ok(noPq((c.options || {}).algorithms),
              JSON.stringify(c.options || {}).slice(0, 300));
    assert.strictEqual(done.next, "redirect", K.said(done).slice(0, 300));
    assert.ok(keys.some(function (one) {
      return one.credentialId === benKey.credentialId;
    }), JSON.stringify(keys).slice(0, 300));
  });
  await K.mustSavePolicy(realm, { postQuantumRequired: "sign-in" });
  const dan = who("dan");
  await K.person(realm, dan, null);
  const danStep = await passkeyStepFor(realm, dan, K.CLIENT);
  const danView = viewOf(danStep);
  const danArmed = await refusedWith(realm, "STS-AUTHN-0420", function () {
    return arm(danStep, { algorithms: "classical" });
  });
  check("S2. under a profile requiring a post-quantum passkey at sign-in " +
        "the step offers no retry, and one asked for anyway is refused " +
        "400 (STS-AUTHN-0420)", function () {
    assert.strictEqual(danView.mode, "create");
    assert.strictEqual(danView.fallback.classical, false,
                       JSON.stringify(danView.fallback));
    assert.strictEqual(danArmed.r.status, 400, danArmed.r.text
      .slice(0, 300));
    assert.ok(/would not sign you in/.test(danArmed.r.text),
              danArmed.r.text.slice(0, 300));
    assert.ok(danArmed.recorded > 0, "no STS-AUTHN-0420 row");
  });
  log.debug("Leaving stepRetry().");
}

async function listAndRefuse() {
  log.debug("Entering listAndRefuse().");
  log.info("=== L. narrow, and list-and-refuse ===");
  const realm = await K.realm("pkq-l", "development");
  await K.client(realm);
  const cat = who("cat");
  const client = await portalFor(realm, cat);
  const catClassical = K.authenticator({});
  const catPq = K.authenticator({ alg: -49 });
  const e1 = await K.enrol(client, catClassical);
  const e2 = await K.enrol(client, catPq);
  assert.ok(e1.done.status === 200 && e2.done.status === 200,
            JSON.stringify([e1.done.json, e2.done.json]).slice(0, 300));
  const eve = who("eve");
  const eveClient = await portalFor(realm, eve);
  const e3 = await K.enrol(eveClient, K.authenticator({}));
  assert.strictEqual(e3.done.status, 200, JSON.stringify(e3.done.json));

  const allowOf = async function (name) {
    const step = await passkeyStepFor(realm, name, K.CLIENT);
    const armed = await arm(step, {});
    return { step: step, armed: armed,
             allow: ((armed.json || {}).allow || []).slice().sort() };
  };
  await K.mustSavePolicy(realm, { postQuantumRequired: "sign-in" });
  const narrowed = await allowOf(cat);
  check("L1. narrow, the default: the step names only the post-quantum key",
        function () {
    assert.deepStrictEqual(narrowed.allow, [catPq.credentialId]);
  });
  await setting(realm, "webauthn.postQuantumAllowCredentials",
                "list-and-refuse");
  const listed = await allowOf(cat);
  const refused = await refusedWith(realm, "STS-AUTHN-0356", function () {
    return answerStep(listed.step, listed.armed,
                      catClassical.assert(listed.armed.json.challenge));
  });
  const screen = refused.r.location
    ? await authnSignin.screen(realm.base, refused.r.location,
                               { cookie: refused.r.cookie,
                                 headers: K.BROWSER })
    : { view: {} };
  const panel = (screen.view || {}).postQuantumRequired;
  check("L2. list-and-refuse names both keys; the classical assertion is " +
        "refused after the ceremony (STS-AUTHN-0356), and the screen " +
        "carries the panel: registration, and no upgrade link (#1100)",
        function () {
    assert.strictEqual(listed.allow.length, 2, JSON.stringify(listed.allow));
    assert.strictEqual(refused.r.next, "refused", K.said(refused.r)
      .slice(0, 300));
    assert.ok(refused.recorded > 0, "no STS-AUTHN-0356 row");
    assert.ok(panel && panel.register === "/portal/keys",
              JSON.stringify(screen.view || {}).slice(0, 400));
    assert.strictEqual(panel.upgrade, undefined, JSON.stringify(panel));
  });
  const again = await allowOf(cat);
  const pqAnswer = await answerStep(again.step, again.armed,
                                    catPq.assert(again.armed.json.challenge));
  check("L3. and the post-quantum key, picked from the same list, signs in",
        function () {
    assert.strictEqual(pqAnswer.next, "redirect", K.said(pqAnswer)
      .slice(0, 300));
  });
  await K.mustSavePolicy(realm, { postQuantumRequired: "sign-in",
                                  postQuantumAllowCredentials: "narrow" });
  const rowNarrow = await allowOf(cat);
  await K.reset(realm, "webauthn.postQuantumAllowCredentials");
  await K.mustSavePolicy(realm, { postQuantumRequired: "sign-in",
    postQuantumAllowCredentials: "list-and-refuse" });
  const rowList = await allowOf(cat);
  check("L4. the profile's row overrides the realm's setting both ways",
        function () {
    assert.strictEqual(rowNarrow.allow.length, 1,
                       JSON.stringify(rowNarrow.allow));
    assert.strictEqual(rowList.allow.length, 2,
                       JSON.stringify(rowList.allow));
  });
  const eveStep = await passkeyStepFor(realm, eve, K.CLIENT);
  const eveView = viewOf(eveStep);
  const eveArmed = await arm(eveStep, {});
  check("L5. under list-and-refuse a person holding only a classical key " +
        "is still told before the ceremony, with the panel's link",
        function () {
    assert.ok(/requires a post-quantum passkey/.test(
      String(eveView.problem)), JSON.stringify(eveView).slice(0, 300));
    assert.ok(eveView.postQuantumHelp &&
              eveView.postQuantumHelp.register === "/portal/keys",
              JSON.stringify(eveView.postQuantumHelp));
    assert.strictEqual(eveView.postQuantumAllowCredentials,
                       "list-and-refuse");
    assert.strictEqual(eveArmed.status, 400, eveArmed.text.slice(0, 300));
  });
  log.debug("Leaving listAndRefuse().");
}

async function forOneApplication() {
  log.debug("Entering forOneApplication().");
  log.info("=== R. required for one application ===");
  const realm = await K.realm("pkq-r", "development");
  const STRICT = "pkq-strict";
  const LOOSE = "pkq-loose";
  await fixtures.publicClient(realm.api, STRICT, [K.REDIRECT]);
  await fixtures.publicClient(realm.api, LOOSE, [K.REDIRECT]);
  const alice = who("alice");
  const client = await portalFor(realm, alice);
  const aliceKey = K.authenticator({});
  const enrolled = await K.enrol(client, aliceKey);
  assert.strictEqual(enrolled.done.status, 200,
                     JSON.stringify(enrolled.done.json));
  const dave = who("dave");
  const daveClient = await portalFor(realm, dave);
  const daveKey = K.authenticator({});
  const daveEnrolled = await K.enrol(daveClient, daveKey);
  assert.strictEqual(daveEnrolled.done.status, 200,
                     JSON.stringify(daveEnrolled.done.json));
  const strict = "pq-strict-" + K.STAMP.slice(-6);
  await K.mustSavePolicy(realm, { postQuantumRequired: "sign-in" }, strict,
                         { precedence: 10 });
  const pointed = await K.call(realm, "POST", "/applications/set",
    { application: STRICT, attribute: "appPasskeyPolicy", value: strict });
  assert.strictEqual(pointed.status, 200, pointed.raw.slice(0, 300));

  const toStrict = await refusedWith(realm, "STS-AUTHN-0356",
                                     async function () {
    const screen = await K.screen(realm, K.BROWSER, STRICT);
    return K.usernameless(realm, function (challenge) {
      return aliceKey.assert(challenge);
    }, screen);
  });
  const looseScreen = await K.screen(realm, K.BROWSER, LOOSE);
  const toLoose = await K.usernameless(realm, function (challenge) {
    return aliceKey.assert(challenge);
  }, looseScreen);
  check("R1. a usernameless sign-in, with an ES256 passkey, to the " +
        "application the profile selects is refused after the ceremony " +
        "(STS-AUTHN-0356) and says why; the same key signs in to an " +
        "application the profile does not select", function () {
    assert.strictEqual(toStrict.r.next, "refused", K.said(toStrict.r)
      .slice(0, 300));
    assert.ok(/requires a post-quantum passkey/.test(K.said(toStrict.r)),
              K.said(toStrict.r).slice(0, 300));
    assert.ok(toStrict.recorded > 0, "no STS-AUTHN-0356 row");
    assert.ok(K.redirected(toLoose), K.said(toLoose).slice(0, 300));
  });

  const primary = await passkeyStepFor(realm, dave, STRICT);
  const daveView = viewOf(primary);
  const daveArmed = await refusedWith(realm, "STS-AUTHN-0356", function () {
    return arm(primary, {});
  });
  check("R2. PRIMARY: a person holding only a classical passkey is told on " +
        "the passwordless step's page, and the ceremony is refused before " +
        "it is armed (STS-AUTHN-0356, recorded)", function () {
    assert.strictEqual(daveView.mode, "get", JSON.stringify(daveView)
      .slice(0, 300));
    assert.ok(/requires a post-quantum passkey/.test(
      String(daveView.problem)), JSON.stringify(daveView).slice(0, 300));
    assert.ok(daveArmed.r.status >= 400, daveArmed.r.text.slice(0, 300));
    assert.ok(/requires a post-quantum passkey/.test(daveArmed.r.text),
              daveArmed.r.text.slice(0, 300));
    assert.ok(daveArmed.recorded > 0, "no STS-AUTHN-0356 row");
  });
  const second = await passkeyStepFor(realm, alice, STRICT, PASSWORD);
  const aliceView = viewOf(second);
  const aliceArmed = await refusedWith(realm, "STS-AUTHN-0356", function () {
    return arm(second, {});
  });
  const anyway = await refusedWith(realm, "STS-AUTHN-0356", function () {
    return authnSignin.stepAct(second, "webauthn",
      { credential: JSON.stringify(aliceKey.assert(
        String(aliceView.challenge || ""))) }, { headers: K.BROWSER });
  });
  check("R3. SECOND FACTOR: the step after a password is held to it too, " +
        "told and refused before the ceremony; an assertion sent anyway is " +
        "refused at the session's start (STS-AUTHN-0356)", function () {
    assert.ok(/requires a post-quantum passkey/.test(
      String(aliceView.problem)), JSON.stringify(aliceView).slice(0, 300));
    assert.ok(aliceArmed.r.status >= 400, aliceArmed.r.text.slice(0, 300));
    assert.ok(aliceArmed.recorded > 0, "no STS-AUTHN-0356 row at arming");
    assert.notStrictEqual(anyway.r.next, "redirect",
                          K.said(anyway.r).slice(0, 300));
    assert.ok(anyway.recorded > 0, "no STS-AUTHN-0356 row for the answer");
  });
  log.debug("Leaving forOneApplication().");
}

async function bothLanes() {
  log.debug("Entering bothLanes().");
  log.info("=== P. both lanes on ===");
  const realm = await K.realm("pkq-p", "development");
  const client = await portalFor(realm, who("erin"));
  await setting(realm, "webauthn.pqcAlongsideClassical", true);
  const before = await client.api("GET", "/account-api/keys");
  await K.mustSavePolicy(realm,
                         { postQuantumRequired: "registration-and-sign-in" });
  const page = await client.api("GET", "/account-api/keys");
  const chosen = await begin(client, false, "classical");
  await cancel(client);
  check("P1. with both lanes on, registration-and-sign-in offers only the " +
        "post-quantum lane, and a classical choice becomes it", function () {
    assert.deepStrictEqual(before.json.enrol.lanes, ["classical", "pqc"]);
    assert.deepStrictEqual(page.json.enrol.lanes, ["pqc"]);
    assert.strictEqual(chosen.begun.status, 200,
                       JSON.stringify(chosen.begun.json));
    assert.strictEqual(chosen.pending.lane, "pqc",
                       JSON.stringify(chosen.pending).slice(0, 300));
    assert.ok(onlyPq(chosen.pending.options.algorithms),
              JSON.stringify(chosen.pending.options.algorithms));
  });
  log.debug("Leaving bothLanes().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving the post-quantum passkey rules at " + K.root);
  await portalRetry();
  await stepRetry();
  await listAndRefuse();
  await forOneApplication();
  await bothLanes();
  log.debug("Leaving test().");
}

K.main(test);
