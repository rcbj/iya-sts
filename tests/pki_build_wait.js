// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: pki_build_wait.js
//
// ===========================================================================
// A CERTIFICATE AUTHORITY BUILD IS WAITED FOR A BOUNDED TIME (CI run #250,
// 2026-11-15).
//
// The fuzz mode's schemathesis waited 300 s for `POST /admin-api/pki/
// build-scope`, `policies/transfer/export`, `scep/reissue-ra` and
// `scim/clients/issue-certificate`, and none was ever answered: each ends in
// `common/pki.js`'s per-scope build queue, which had no bound, behind builds
// that each waited out a held `pki.build` claim with a bound of their own.
// What this holds (`common/CLAUDE.md`, *One deadline per caller*):
//
//   W1. a build whose claim another node holds is refused STS-PKI-0184 once
//       the caller's deadline passes, and that refusal is a busy one
//       (`isBusyRefusal()`, which `/admin-api/pki/*` answers 503 with
//       Retry-After);
//   W2. a caller QUEUED behind such a build — an issuer's `ensureScope()` —
//       shares no wait with it: its own deadline, counted from when it
//       joined the queue, ends its wait, so it is refused at about the same
//       moment rather than after the first caller's wait and then its own;
//   W3. a body refused for what it asks for (an unknown key algorithm) is
//       answered at once, not after the queue and the claim;
//   W4. only those two codes are busy;
//   W5. a build started BY a build shares its caller's deadline: a build
//       that spends most of the bound and then asks for another scope's
//       branch, whose claim is held, is refused at the first caller's
//       deadline and not one bound later.
//
// A "node" holding the claim is this process's own claims store
// (`cluster/cluster_claims.js`, in memory with no persistence store), and
// `keystore.mergesPkiRows()` is stubbed true for the run so the module
// coordinates its builds as it does on a merging store. The bound is
// shortened with `pki.setBuildWaitMs()` and put back afterwards.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');

const pki = require('../common/pki');
const keystore = require('../common/keystore');
const claims = require('../cluster/cluster_claims');
const errorCodes = require('../common/error_codes');

const log = require('bunyan').createLogger({
  name: 'pki_build_wait', level: process.env.LOG_LEVEL || 'info' });

// The bound for the run, and how far past it a refusal may come: one poll,
// the store reads around it, and a loaded test runner.
const WAIT_MS = 1500;
const SLACK_MS = 1200;

async function timed(fn) {
  log.debug("Entering timed().");
  const began = Date.now();
  const answer = await fn();
  log.debug("Leaving timed().");
  return { answer: answer, ms: Date.now() - began };
}

async function heldClaim(t, scope) {
  log.debug("Entering heldClaim().");
  const held = await claims.claim({ scope: 'pki.build',
                                    value: 'scope:' + scope,
                                    ttlMs: 60000, realm: '' });
  t.check(held.ok, 'W0. another "node" holds the pki.build claim of ' +
          scope, JSON.stringify(held));
  log.debug("Leaving heldClaim().");
  return held;
}

async function refusedAtTheDeadline(t, scope) {
  log.debug("Entering refusedAtTheDeadline().");
  const one = await timed(function () {
    return pki.buildScope(scope, {});
  });
  t.check(!one.answer.ok &&
          errorCodes.codeOf(one.answer) === 'STS-PKI-0184' &&
          one.ms >= WAIT_MS - 100 && one.ms < WAIT_MS + SLACK_MS,
          'W1. a build whose claim is held is refused STS-PKI-0184 at the ' +
          'caller\'s deadline (' + one.ms + ' ms, bound ' + WAIT_MS + ')',
          JSON.stringify({ answer: one.answer,
                           code: errorCodes.codeOf(one.answer) }));
  t.check(pki.isBusyRefusal(one.answer),
          'W1. and it is a busy refusal, answered 503 with Retry-After');
  log.debug("Leaving refusedAtTheDeadline().");
}

async function queuedCallerOwnDeadline(t, scope) {
  log.debug("Entering queuedCallerOwnDeadline().");
  const began = Date.now();
  const first = pki.buildScope(scope, {}).then(function (answer) {
    return { answer: answer, ms: Date.now() - began };
  });
  // An issuer arriving while that build waits: queued behind it.
  const second = pki.ensureScope(scope).then(function (answer) {
    return { answer: answer, ms: Date.now() - began };
  });
  const both = await Promise.all([first, second]);
  t.check(both.every(function (one) {
    return !one.answer.ok &&
           errorCodes.codeOf(one.answer) === 'STS-PKI-0184';
  }), 'W2. a build and an issuer queued behind it are both refused ' +
      'STS-PKI-0184', JSON.stringify(both));
  t.check(both[0].ms >= WAIT_MS - 100,
          'W2. a caller after an earlier refusal starts a deadline of its ' +
          'own, not the ended one (' + both[0].ms + ' ms)');
  t.check(both[1].ms < WAIT_MS + SLACK_MS,
          'W2. the queued issuer\'s wait ends at ITS deadline, not after ' +
          'the build ahead\'s wait and then its own (' + both[1].ms +
          ' ms, bound ' + WAIT_MS + ')');
  log.debug("Leaving queuedCallerOwnDeadline().");
}

async function refusedAtOnce(t, scope) {
  log.debug("Entering refusedAtOnce().");
  const waiting = pki.buildScope(scope, {});
  const bad = await timed(function () {
    return pki.buildScope(scope, { keyAlg: 'no-such-key-algorithm' });
  });
  t.check(!bad.answer.ok &&
          errorCodes.codeOf(bad.answer) === 'STS-PKI-0002' && bad.ms < 500,
          'W3. a build asking for a key algorithm this service lacks is ' +
          'refused at once, while another build of the scope waits (' +
          bad.ms + ' ms)', JSON.stringify({ answer: bad.answer,
                                            code: errorCodes.codeOf(
                                              bad.answer) }));
  await waiting;
  log.debug("Leaving refusedAtOnce().");
}

function onlyBusyCodes(t) {
  log.debug("Entering onlyBusyCodes().");
  const other = errorCodes.mark({ ok: false, errors: ['x'] }, 'STS-PKI-0002');
  const store = errorCodes.mark({ ok: false, errors: ['x'] }, 'STS-PKI-0183');
  t.check(pki.isBusyRefusal(store) && !pki.isBusyRefusal(other) &&
          !pki.isBusyRefusal({ ok: true }) && !pki.isBusyRefusal(null),
          'W4. STS-PKI-0183 and 0184 are busy; another refusal and a ' +
          'success are not');
  log.debug("Leaving onlyBusyCodes().");
}

async function nestedSharesDeadline(t, scope) {
  log.debug("Entering nestedSharesDeadline().");
  const outer = scope + '-outer';
  const began = Date.now();
  // The outer build takes its own (free) claim, spends most of the bound,
  // then asks for the held scope's branch — as `buildScopeNow()` asks for
  // the Root.
  const answer = await pki.oneBuildInTheCluster(outer, 'issuing', null,
    async function () {
      await new Promise(function (resolve) {
        setTimeout(resolve, WAIT_MS - 100);
      });
      return pki.buildScope(scope, {});
    });
  const ms = Date.now() - began;
  t.check(!answer.ok && errorCodes.codeOf(answer) === 'STS-PKI-0184' &&
          ms < WAIT_MS + SLACK_MS,
          'W5. a build started by a build is refused at the first caller\'s ' +
          'deadline, not a whole bound later (' + ms + ' ms, bound ' +
          WAIT_MS + ')', JSON.stringify(answer));
  log.debug("Leaving nestedSharesDeadline().");
}

async function run(t) {
  log.debug("Entering run().");
  const scope = 'bwait-' + nodeCrypto.randomBytes(4).toString('hex');
  const merges = keystore.mergesPkiRows;
  keystore.mergesPkiRows = function () {
    return true;
  };
  pki.setBuildWaitMs(WAIT_MS);
  let held = null;
  try {
    held = await heldClaim(t, scope);
    await refusedAtTheDeadline(t, scope);
    await queuedCallerOwnDeadline(t, scope);
    await refusedAtOnce(t, scope);
    onlyBusyCodes(t);
    await nestedSharesDeadline(t, scope);
  } finally {
    if (held && held.ok) {
      await claims.release(held.handle);
    }
    keystore.mergesPkiRows = merges;
    pki.setBuildWaitMs();
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'pki_build_wait',
  describe: 'A certificate authority build is waited for a bounded time ' +
            '(CI run #250): a held pki.build claim refuses the caller ' +
            'STS-PKI-0184 at its deadline, a caller queued behind such a ' +
            'build has a deadline of its own counted from the queue, a ' +
            'body refused for what it asks is answered before the queue, ' +
            'only 0183 and 0184 are busy (503 with Retry-After), and a build ' +
            'started by a build shares its caller\'s deadline',
  run: run
};
