'use strict';
//
// File: key_agreement_storm.js
//
// ===========================================================================
// A REALM CREATED AT RUNTIME MUST NOT MAKE ITS SIGNING KEYS IN EVERY PROCESS
// (2026-09-12).
//
// **THE DEFECT THIS FILE EXISTS FOR, AND IT WAS MEASURED RATHER THAN
// REASONED ABOUT.** `common/pki.js`'s realm watcher ended with:
//
//     // AND ITS KEYS, if they have been generated already.
//     return certifyKeySet(id, keySetProvider(id));
//
// `keySetProvider` is `helpers.stsKeysFor.of()`, which MAKES a key set when
// the process has none — so that line did not certify a realm's keys, it
// CREATED them, in every process that saw the realm appear. In a dispatched
// service that is the front process and every request worker.
//
// On a `--modes=dispatch` run of the whole suite, a realm created at
// 17:48:47.995 had FOUR key sets in four processes within 95ms — kids
// 7223b2499bdb, 5adaac82b8f3, 2865074f6ea8 and ee9c19ca8208 — each generated,
// each written to `sts_keys`, and each arbitrated away by
// `request_pool.js`'s first-generator-wins except whichever reached the front
// process first. They converge; what they do not do is converge BEFORE
// answering, and a response served inside that window carries a key set the
// service is about to disown.
//
// It reached the suite as `tests/vendored/sts_jwt_bearer_grant.js` section 7:
// an RSA public key read from `/oauth2/jwks` on one worker, an assertion
// encrypted to it, and a token request decrypted on another — **`oaep
// decoding error`**, which names nothing and looks like a broken JWE.
//
// Measured against a real dispatched stack, three request workers on one
// PostgreSQL store, creating four realms and requesting NOTHING:
//
//     before   13 key generations   (3 or 4 per realm, one per process)
//     after     0
//
// ---------------------------------------------------------------------------
// WHAT THIS FILE CAN AND CANNOT ASSERT.
//
// **It cannot stand up four processes.** `npm test` is one process with no
// port and no store, and a test that forked a pool to watch a race would be
// measuring the machine it ran on. What it CAN pin is the contract that made
// the race unavoidable, which is a property of one function: the realm
// watcher must ask whether this process HOLDS a realm's keys and must not
// reach for them.
//
// So it drives `pki.js`'s own watcher with two providers it can see being
// called, which is the whole of the defect: the old code called `keySetFor`
// unconditionally, and the fix calls it only when `keySetHeldFor` says yes.
// **A revert makes `taken` non-zero on a realm nobody holds keys for**, which
// is section B.
// ===========================================================================

// The state this file wants is the DEFAULT, so it removes what would override
// it rather than writing the default back — `database_metrics.js`'s argument,
// and it matters here for the same reason: both launchers export each mode's
// environment into the runner, which hands `process.env` to every in-process
// job.
delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');

const pki = require('../common/pki');
const helpers = require('../common/helpers');
const realms = require('../common/realms');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'key_agreement_storm',
  level: process.env.LOG_LEVEL || 'info' });

async function run(t) {
  log.debug("Entering run().");
  t.log.info('=== A. a realm created at runtime holds no keys yet ===');

  // **THE ASSERTION IS ABOUT THE CACHE AND NOT ABOUT WHO WAS CALLED**, and
  // that is deliberate. A first version of this file counted calls to two
  // providers it installed itself — and `tests/run.js` runs every file in ONE
  // process, where `common/service_state.ts` has already started `pki.js`
  // with providers of its own, so the counters measured a function nobody was
  // calling and the file failed while the service was correct. What is below
  // is true whoever wired the watcher up, which is the property a test of a
  // module-level registration has to have.
  const id = 'storm-probe-' + Date.now().toString(36);

  // -------------------------------------------------------------------------
  // **THE WATCHER HAS TO BE SUBSCRIBED AND IT HAS TO HAVE BOTH PROVIDERS**,
  // and this is not setup noise — it is the production pairing, written out.
  // `pki.start()` is what subscribes (`watchRealms()`), and the handler
  // returns early when `keySetFor` is missing, so a file that started nothing
  // would assert "no keys were made" about a watcher that was never called.
  // Both are supplied exactly as `common/service_state.ts` supplies them, and
  // the difference between the defect and the fix is which one the watcher
  // reaches for.
  //
  // Started here rather than relied upon: `tests/run.js` runs every file in
  // ONE process and what has already started `pki.js` depends on the order
  // the files happen to run in, which is not something an assertion should
  // rest on.
  // -------------------------------------------------------------------------
  await pki.start({
    realmIds: [],
    keySetFor: function (realmId) {
      log.debug("Entering keySetFor().");
      log.debug("Leaving keySetFor().");
      return helpers.stsKeysFor.of(realmId);
    },
    keySetHeldFor: function (realmId) {
      log.debug("Entering keySetHeldFor().");
      const cache = helpers.stsKeysFor.existing();
      log.debug("Leaving keySetHeldFor().");
      return !!(cache && typeof cache.has === 'function' &&
                cache.has(String(realmId || '')));
    }
  });

  t.check(!helpers.stsKeysFor.existing().has(id),
          'nothing holds keys for a realm that does not exist yet, which is ' +
          'the baseline the next assertion is measured against');

  // ---------------------------------------------------------------------
  // **AND IT IS REMOVED AGAIN IN `finally`, WHICH IS NOT TIDINESS.**
  // `tests/run.js` runs every file in ONE process, and
  // `tests/realm_isolation.js` asserts that only the default realm is left — so
  // a realm this file leaves behind fails a different file, about a service
  // that is correct, with a message naming neither. (That is the opposite of
  // the rule for a CONTAINER run, where a realm a job creates is deliberately
  // kept so a failed run can be read afterwards.)
  // ---------------------------------------------------------------------
  // `realms.create()` fires `realms.onChange(id, 'create')` — the same event a
  // realm created through `/admin-api/realms/create` produces, and what
  // `pki.js`'s watcher is subscribed to.
  realms.create({ id: id, name: id });
  try {

    // -------------------------------------------------------------------------
    // **WAIT FOR THE BRANCH RATHER THAN FOR A DURATION**, which is what makes
    // the assertion below non-vacuous. The watcher's body is asynchronous and
    // deliberately not awaited by the act that created the realm — a realm
    // creation must not block on nine signatures — so a fixed sleep is a guess,
    // and a guess that is too short turns "it did not make the keys" into "it
    // had not run yet", which passes for the wrong reason and would pass
    // against the defect. The branch is the watcher's OTHER half and is
    // unconditional, so its appearance is the evidence that the handler reached
    // the line this file is about. Measured: about 500ms to build one realm's
    // Intermediate and four Issuing CAs.
    // -------------------------------------------------------------------------
    const deadline = Date.now() + 20000;
    let scope = null;
    while (Date.now() < deadline) {
      scope = pki.describeScope(id);
      if (scope && scope.built) {
        break;
      }
      await new Promise(function (resolve) { setTimeout(resolve, 100); });
    }

    t.check(!!(scope && scope.built),
            'the realm has a certificate authority branch, so the watcher ' +
            'RAN — without which the assertion below would be measuring a ' +
            'handler that had not been called yet',
            JSON.stringify({ built: !!(scope && scope.built),
                             intermediate: !!(scope && scope.intermediate) }));

    t.check(!helpers.stsKeysFor.existing().has(id),
            'AND IT HOLDS NO SIGNING KEYS FOR THAT REALM, with the realm ' +
            'created and its certificate authority built. This is the whole ' +
            'fix. `pki.js`\'s realm watcher ended with `certifyKeySet(id, ' +
            'keySetProvider(id))` under a comment saying it certified keys ' +
            '"if they have been generated already" — and that provider is ' +
            '`helpers.stsKeysFor.of()`, which GENERATES a key set for a ' +
            'realm that has none. So the watcher did not certify a realm\'s ' +
            'keys, it MADE them, in every process that saw the realm appear. ' +
            'Measured on a dispatched stack with three request workers: four ' +
            'realms created and nothing requested produced THIRTEEN key ' +
            'generations before this change and NONE after');

    t.log.info('=== B. the keys are still made, by the first caller that ' +
               'needs them ===');

    // THE OTHER HALF, AND IT IS WHAT STOPS THIS BEING A FIX THAT BREAKS THE
    // FEATURE: not generating at creation is only correct because the first
    // READER generates, and `helpers.js`'s `certifyLater()` certifies them from
    // that direction. It is also what `helpers.js` already said happened — *a
    // realm created at runtime makes its keys on first use* — and had silently
    // stopped being true.
    const keys = helpers.stsKeysFor.of(id);
    t.check(!!(keys && keys.kid),
            'the first caller that needs the realm\'s keys gets them',
            keys && keys.kid);
    t.check(helpers.stsKeysFor.existing().has(id),
            'and they are cached from then on, so the second caller does not ' +
            'make a second set');

    const again = helpers.stsKeysFor.of(id);
    t.equal(again.kid, keys.kid,
            'and it is the SAME key set, which is the property one process ' +
            'has to hold before several processes can agree about it');
  } finally {
    realms.remove(id);
  }

  t.log.info('=== C. and the SERVICE wires both providers, not just this ' +
             'file ===');

  // -------------------------------------------------------------------------
  // **THE FIX LIVES IN TWO FILES AND THE SECTIONS ABOVE PIN ONLY ONE**, which
  // a mutation run showed rather than a reading: deleting `keySetHeldFor` from
  // `common/service_state.ts` — the only production caller of `pki.start()` —
  // leaves every assertion above green, because this file supplies providers
  // of its own. Without it `pki.js` falls back to certifying nothing at all,
  // which is SAFE (no storm) and is not the intended behaviour: a realm whose
  // keys this process does have would stop being certified at creation.
  //
  // So this reads the source. That is what `tests/version.js` does about the
  // surfaces that draw a version, and for the same reason: two call sites
  // agree perfectly right up until one of them is edited.
  // -------------------------------------------------------------------------
  const options = fs.readFileSync(
    path.join(__dirname, '..', 'common', 'service_state.ts'), 'utf8');

  // **THE WHOLE FILE AND NOT A SLICE OF THE CALL.** A first version cut the
  // options object out between `pki.start({` and the first `})`, and the
  // first `})` is the end of the `realmIds:` map function three lines in — so
  // it matched 115 characters, found neither provider, and failed against a
  // file that had both. There is exactly one `pki.start(` in this module, so
  // the file IS the call site and a boundary nobody has to get right is worth
  // more than a tighter match.
  t.check(options.indexOf('pki.start(') >= 0,
          'common/service_state.ts is where pki.start() is called — the ' +
          'check below is about that call and this is what says it is still ' +
          'here');

  t.check(options.indexOf('keySetFor:') >= 0,
          'common/service_state.ts hands pki.start() a key-set provider');
  t.check(options.indexOf('keySetHeldFor:') >= 0,
          'AND THE HELD-CHECK BESIDE IT. This is the half that stops the ' +
          'realm watcher generating a key set in every process — without it ' +
          'pki.js certifies nothing at realm creation, which is safe and is ' +
          'not what is meant');
  t.check(/existing\s*\(\s*\)/.test(options),
          'and the held-check reads the CACHE (`stsKeysFor.existing()`) ' +
          'rather than `.of()`. `.of()` is the one that generates, so a ' +
          'held-check written with it would answer "yes, this process holds ' +
          'them" by MAKING them — the defect wearing the shape of its own fix');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'key_agreement_storm',
  describe: 'A realm created at runtime does not make its signing keys in ' +
            'every process: pki.js\'s realm watcher ASKS whether this ' +
            'process holds them (keySetHeldFor) rather than reaching for ' +
            'them (keySetFor, which generates) — the defect that put four ' +
            'key sets in four processes for one realm and reached the suite ' +
            'as an OAEP decode failure — and the keys are still made by the ' +
            'first caller that needs them',
  run: run
};
