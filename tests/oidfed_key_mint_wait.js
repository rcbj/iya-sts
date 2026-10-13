// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: oidfed_key_mint_wait.js
//
// ===========================================================================
// A REQUEST THAT MEETS ANOTHER PROCESS'S FEDERATION KEY MINT WAITS FOR IT
// (2026-09-28). A realm's first Federation Entity Key is minted on first use
// under a cluster claim, and the process that lost the claim answered at once
// with no key — so its request was a 503 a moment before the key existed
// everywhere. CI run 36415737694: `sts_siop` in single-node, the Entity
// Configuration of a realm created 1.4 s earlier. `ensure()` now waits,
// bounded, for the winner's row to arrive in the register.
//
// In process, over stub dependencies: the claim is always held elsewhere and
// the register gains the other process's current key 300 ms after the call.
// `ensure()` must resolve holding it, and must not have minted one itself.
// ===========================================================================

const keysModule = require('../oidfed/federation_keys');

const log = require('bunyan').createLogger({ name: 'oidfed_key_mint_wait',
  level: process.env.LOG_LEVEL || 'info' });

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

async function run(t) {
  log.debug("Entering run().");
  let rows = [];
  let minted = 0;
  const deps = {
    log: log,
    config: { value: function () {
      log.debug("Entering value().");
      log.debug("Leaving value().");
      return 'ES256';
    } },
    realms: { current: function () {
      log.debug("Entering current().");
      log.debug("Leaving current().");
      return { id: 'mintwait' };
    } },
    keystore: {},
    errorCodes: {},
    store: { keyRows: function () {
      log.debug("Entering keyRows().");
      log.debug("Leaving keyRows().");
      return rows;
    }, writeKeyRows: function () {
      log.debug("Entering writeKeyRows().");
      log.debug("Leaving writeKeyRows().");
    } },
    makeKey: async function () {
      log.debug("Entering makeKey().");
      minted += 1;
      log.debug("Leaving makeKey().");
      return { publicJwk: { kid: 'mine' }, privateKey: 'x' };
    },
    scheduler: function () { log.debug("scheduler()"); return {}; },
    mode: function () { log.debug("mode()"); return {}; },
    audit: function () { log.debug("audit()"); return {}; },
    // THE CLAIM IS ALWAYS HELD BY ANOTHER PROCESS.
    claims: function () {
      log.debug("Entering claims().");
      log.debug("Leaving claims().");
      return { claim: async function () {
        log.debug("Entering claim().");
        log.debug("Leaving claim().");
        return { ok: false, reason: 'held' };
      } };
    },
    events: function () { log.debug("events()"); return {}; },
    signals: function () { log.debug("signals()"); return {}; },
    now: function () { log.debug("now()"); return Date.now(); }
  };
  const keys = new keysModule.FederationKeys(deps);
  // The other process's row lands in the register 300 ms after the call.
  const winner = { v: 1, kid: 'winner', alg: 'ES256', state: 'current',
                   publicJwk: { kid: 'winner' }, privateKey: 'y',
                   sealed: false, createdAt: Date.now() };
  sleep(300).then(function () {
    rows = [winner];
  });
  const started = Date.now();
  const answered = await keys.ensure();
  const tookMs = Date.now() - started;
  t.check(answered.some(function (row) {
    return row.state === 'current' && row.kid === 'winner';
  }), 'A REQUEST THAT MEETS ANOTHER PROCESS\'S MINT WAITS FOR ITS KEY and ' +
      'answers with it, rather than with no key (a 503 at the Entity ' +
      'Configuration)', { answered: answered, tookMs: tookMs });
  t.check(minted === 0, 'and mints no key of its own', minted);
  t.check(tookMs >= 250 && tookMs < 5000,
          'and it waited only until the row arrived', tookMs);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'oidfed_key_mint_wait',
  describe: 'OpenID Federation: a request meeting another process\'s ' +
            'Federation Entity Key mint waits for the key, bounded',
  run: run
};
