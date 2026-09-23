'use strict';
//
// File: tests/spiffe_rekey_waits_for_branch.js
//
// ===========================================================================
// THE SPIRE SERVER API RE-KEYS ONLY ONCE ITS REALM'S BRANCH IS UNDER THE NEW
// ROOT (2026-09-21).
//
// A replaced Root reaches the front process before the realm branches the
// replacing process rebuilds after it. The listener certificate is re-issued
// at once, which re-keys every realm's SPIRE Server API — and re-keying issued
// from a branch still under the OLD Root, so `pki.issueUnder()` repaired the
// branch in the front process while the replacing worker rebuilt it too: two
// "Intermediate CA (default)" certificates, found by
// `sts_pki_distribution_points` in `single-node`, where no cluster claim
// serialises the two processes. `SpiffeServer.awaitRealmBranch()` is the wait.
//
// In process with `pki.scopeChainsToRoot` replaced for the file and put back
// in a `finally`: the ORDER of two processes' work is what no single request
// can show, and the wait is a comparison polled on a timer.
//
//   1. a branch that already chains to the Root is not waited for;
//   2. a branch that arrives later is waited for, and the wait ends when it
//      does — not before;
//   3. as source: refreshServerCredentials() waits before it re-keys.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'spiffe_rekey_waits',
  level: process.env.LOG_LEVEL || 'info' });

const pki = require('../common/pki');
const spiffeServer = require('../spiffe/spiffe_server');

async function run(t) {
  log.debug("Entering run().");
  const real = pki.scopeChainsToRoot;
  const server = new spiffeServer.SpiffeServer(
    spiffeServer.SpiffeServer.defaultDeps());
  // THE WAIT'S TIMERS ARE unref()'d, correctly for a service whose listeners
  // hold the event loop open — and in this process nothing else does, so
  // without this the process simply ended mid-wait, reporting nothing.
  const keepAlive = setInterval(function () {}, 1000);
  try {
    // 1. ALREADY CURRENT.
    pki.scopeChainsToRoot = function () {
      return true;
    };
    let began = Date.now();
    t.equal(await server.awaitRealmBranch(''), true,
            'a branch already under the Root is ready');
    t.check(Date.now() - began < 200,
            'and is not waited for', (Date.now() - began) + 'ms');

    // 2. ARRIVING LATER.
    let arrived = false;
    pki.scopeChainsToRoot = function () {
      return arrived;
    };
    setTimeout(function () {
      arrived = true;
    }, 700).unref();
    began = Date.now();
    const settled = await server.awaitRealmBranch('');
    const waited = Date.now() - began;
    t.equal(settled, true, 'a branch that arrives later is waited for');
    t.check(waited >= 650 && waited < 5000,
            'and the wait ends when it arrives — not before, and not at the ' +
            'thirty-second bound', waited + 'ms');
  } finally {
    pki.scopeChainsToRoot = real;
    clearInterval(keepAlive);
  }

  // 3. THE RE-KEY WAITS.
  const source = fs.readFileSync(path.join(__dirname, '..', 'spiffe',
                                           'spiffe_server.ts'), 'utf8');
  const body = /  refreshServerCredentials\(\) \{([\s\S]*?)\n  \}\n/
    .exec(source);
  t.check(!!body && /awaitRealmBranch\(realmId\)[\s\S]*refreshServerApiCredentials/
            .test(body[1]),
          'refreshServerCredentials() waits for the realm\'s branch BEFORE it ' +
          're-keys the SPIRE Server API');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'spiffe_rekey_waits_for_branch',
  describe: 'the SPIRE Server API re-keys only once its realm\'s branch is ' +
            'under the new Root, so a replaced Root never gets a second ' +
            'Intermediate built beside the one the replacing process builds',
  run: run
};
