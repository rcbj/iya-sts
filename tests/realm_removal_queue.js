// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: realm_removal_queue.js
//
// ===========================================================================
// NO REALM IS REMOVED WHILE AN EXCLUSIVE JOB RUNS (2026-11-18, GitHub
// Actions run #493).
//
// The runner removes a passed job's realms in a queue beside the jobs
// (`tools/realm-ledger.js`, `RemovalQueue`). Beside an EXCLUSIVE job that
// was wrong: `sts_realm_count_limit` failed in every mode with "the realm
// count moved while the cap was being set (5 -> 4)". So:
//
//   A. `hold()` waits for every removal queued before it to land;
//   B. a removal queued while held does not start until the release;
//   C. `drain()` waits for everything queued, the held ones included once
//      released, and a removal that throws does not stop the queue;
//   D. `run-report.js` takes the hold around an exclusive job and around a
//      cluster restart, and drains before it reports — read from the source,
//      because the runner's job loop is not something a test can drive
//      without a service.
// ===========================================================================

const fs = require('fs');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'realm_removal_queue',
  level: process.env.LOG_LEVEL || 'info' });

const realmLedger = require('./tools/realm-ledger');

function later(ms) {
  log.debug("Entering later().");
  log.debug("Leaving later().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

async function run(t) {
  log.debug("Entering run().");
  const queue = new realmLedger.RemovalQueue();
  const events = [];
  let exclusive = false;
  const removal = function (name, ms) {
    log.debug("Entering removal().");
    log.debug("Leaving removal().");
    return function () {
      events.push({ name: name, during: exclusive, at: 'start' });
      return later(ms).then(function () {
        events.push({ name: name, during: exclusive, at: 'end' });
      });
    };
  };
  queue.enqueue(removal('before-1', 30));
  queue.enqueue(removal('before-2', 30));
  const release = await queue.hold();
  t.check(events.filter(function (e) {
    return e.at === 'end';
  }).length === 2, 'A. the hold waited for the two removals queued before ' +
          'it', JSON.stringify(events));

  exclusive = true;
  queue.enqueue(removal('during', 10));
  queue.enqueue(function () {
    throw new Error('a removal that throws');
  });
  await later(80);
  t.check(!events.some(function (e) {
    return e.name === 'during';
  }), 'B. a removal queued during the hold has not started while the ' +
          'exclusive job runs', JSON.stringify(events));
  exclusive = false;
  release();
  await queue.drain();
  t.check(events.some(function (e) {
    return e.name === 'during' && e.at === 'end' && !e.during;
  }) && !events.some(function (e) {
    return e.during;
  }), 'C. after the release it runs, a throwing removal does not stop the ' +
          'queue, and none ran during the hold', JSON.stringify(events));
  queue.enqueue(removal('after', 5));
  await queue.drain();
  t.check(events.some(function (e) {
    return e.name === 'after' && e.at === 'end';
  }), 'C. and the queue still runs what is queued after', '');

  const source = fs.readFileSync(path.join(__dirname, 'tools',
                                           'run-report.js'), 'utf8');
  t.check(/job\.exclusive \? await removals\.hold\(\)/.test(source),
          'D. run-report.js holds the queue around an exclusive job', '');
  t.check(/const releaseRemovals = await removals\.hold\(\)/.test(source) &&
          /await removals\.drain\(\)/.test(source),
          'D. and around a cluster restart, and drains it before reporting',
          '');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'realm_removal_queue',
  describe: 'The runner\'s realm-removal queue is drained and held around ' +
            'an exclusive job and a cluster restart: no realm is removed ' +
            'while one runs (run #493)',
  run: run
};
