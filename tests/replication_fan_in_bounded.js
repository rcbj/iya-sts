// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: replication_fan_in_bounded.js
//
// ===========================================================================
// THE FAN-IN HOLDS WHAT THE OTHER PROCESSES HOLD, NOT WHAT THEY EVER HELD
// (#618, 2026-10-14).
//
// `persistence/persistence_replication.js`'s `contribute()` keeps what every
// other process wrote to a `merge: 'own'` store, as handle -> realm -> key ->
// origin -> value. A removal deleted the ORIGIN and left the key's Map behind,
// empty, for ever. `admin_stats.users` notes every replicated create in every
// process and journals the eviction of a note past its MAX_USERS cap, so a
// bulk load left one empty Map per person ever added in every process: a heap
// snapshot of a request worker on 8081 at about 974K people held 798,858 keys
// under `admin_stats.users`, 796,728 of them empty — about 300 bytes a person
// per isolate, the whole of the live-heap growth #618 measured — and
// `everyUserRecord()` walked all of them on every read of the users register.
//
// Asserted, counting ENTRIES (`contributionCounts()`), never the heap:
//   1. thirty thousand people through the note-then-evict pattern of three
//      processes with a cap of 100 leave at most 3 x 100 values and as many
//      keys, and `remoteKeys()` lists only those;
//   2. a removal of something never held (an eviction whose row was gone
//      before this process read the note) makes nothing;
//   3. removing the last value under a realm and handle removes those levels
//      too;
//   4. a removal takes only its own origin's value: another process's value
//      under the same key stays, and is still answered;
//   5. the module's own fan-in (the one `admin_stats` reads) returns to where
//      it was after five thousand `admin_stats.users` notes are removed, and
//      the users register lists none of them.
//
// WHY IN PROCESS: the fan-in needs a second origin, which is a second process
// or a restart, and how much it holds is visible to nothing outside it.
// ===========================================================================

delete process.env.CONFIG_FILE;

const realms = require('../common/realms');
const replication = require('../persistence/persistence_replication');
const stats = require('../common/admin_stats');

const log = require('bunyan').createLogger({
  name: 'replication_fan_in_bounded',
  level: process.env.LOG_LEVEL || 'info' });

const DEFAULT = realms.DEFAULT_REALM.id;
const STAMP = Date.now().toString(36);
const HANDLE = 'admin_stats.users';

// A users-register record as another process would have written it.
function theirRecord(key) {
  log.debug("Entering theirRecord().");
  log.debug("Leaving theirRecord().");
  return { key: key, name: key, forms: {}, realms: {}, protocols: {},
           events: [], eventsForgotten: 0, authentications: 0, firstAt: 0,
           lastAt: 0, isClient: false, knownBy: 'created' };
}

module.exports = {
  name: 'replication_fan_in_bounded',
  describe: 'the replication fan-in of merge: \'own\' stores holds what the ' +
            'other processes hold now: a removal takes its empty levels ' +
            'with it, so thirty thousand noted-and-evicted people leave a ' +
            'bounded number of entries (#618)',
  run: async function run(t) {
    log.debug("Entering run().");
    // An instance of its own, so the counts are this test's and nothing
    // else in the process can add to them.
    const fanIn = replication.createReplication('fan-in-bound-' + STAMP);
    const ORIGINS = ['node-b', 'node-c', 'node-d'];
    const CAP = 100;
    const PEOPLE = 30000;

    // --- 1. note, then evict past the cap, in every other process -------
    let peak = 0;
    for (let i = 0; i < PEOPLE; i++) {
      const key = 'bound-' + STAMP + '-' + i;
      ORIGINS.forEach(function (o) {
        fanIn.contribute(HANDLE, DEFAULT, key, o, theirRecord(key));
      });
      if (i >= CAP) {
        const evicted = 'bound-' + STAMP + '-' + (i - CAP);
        ORIGINS.forEach(function (o) {
          fanIn.contribute(HANDLE, DEFAULT, evicted, o, null);
        });
      }
      if (i % 1000 === 999) {
        peak = Math.max(peak, fanIn.contributionCounts().keys);
      }
    }
    const after = fanIn.contributionCounts();
    t.check(after.keys <= CAP && after.values <= CAP * ORIGINS.length &&
            peak <= CAP,
            '1. thirty thousand people noted and evicted by three ' +
            'processes with a cap of 100 leave at most 100 keys and 300 ' +
            'values, and never held more',
            JSON.stringify({ after: after, peak: peak }));
    t.check(fanIn.remoteKeys(HANDLE, DEFAULT).length === after.keys,
            '1b. and remoteKeys() — what everyUserRecord() walks — lists ' +
            'exactly those keys', String(fanIn.remoteKeys(HANDLE,
                                                           DEFAULT).length));

    // --- 2. a removal of something never held makes nothing ------------
    const before = fanIn.contributionCounts();
    for (let i = 0; i < 1000; i++) {
      fanIn.contribute(HANDLE, DEFAULT, 'never-' + STAMP + '-' + i,
                       'node-e', null);
      fanIn.contribute('test.never.held', 'some-realm', 'k' + i, 'node-e',
                       null);
    }
    t.check(JSON.stringify(fanIn.contributionCounts()) ===
            JSON.stringify(before),
            '2. a thousand removals of rows never held — an eviction that ' +
            'overtook its note — add no handle, realm or key',
            JSON.stringify({ before: before,
                             after: fanIn.contributionCounts() }));

    // --- 3. the last value takes its realm and handle with it ----------
    for (let i = PEOPLE - CAP; i < PEOPLE; i++) {
      ORIGINS.forEach(function (o) {
        fanIn.contribute(HANDLE, DEFAULT, 'bound-' + STAMP + '-' + i, o,
                         null);
      });
    }
    const empty = fanIn.contributionCounts();
    t.check(empty.handles === 0 && empty.realms === 0 && empty.keys === 0 &&
            empty.values === 0,
            '3. removing every value leaves no handle, realm or key behind',
            JSON.stringify(empty));

    // --- 4. a removal takes only its own origin -------------------------
    const shared = 'shared-' + STAMP;
    fanIn.contribute(HANDLE, DEFAULT, shared, 'node-b', theirRecord(shared));
    fanIn.contribute(HANDLE, DEFAULT, shared, 'node-c', theirRecord(shared));
    fanIn.contribute(HANDLE, DEFAULT, shared, 'node-b', null);
    const left = fanIn.remoteRows(HANDLE, DEFAULT, shared);
    t.check(left.length === 1 && left[0].key === shared &&
            fanIn.contributionCounts().keys === 1,
            '4. removing one process\'s value leaves another\'s under the ' +
            'same key, still answered', JSON.stringify(left));
    fanIn.contribute(HANDLE, DEFAULT, shared, 'node-c', null);

    // --- 5. the module's own fan-in, which admin_stats reads ------------
    const baseline = replication.contributionCounts();
    const NOTED = 5000;
    for (let i = 0; i < NOTED; i++) {
      const key = 'stats-' + STAMP + '-' + i;
      replication.contribute(HANDLE, DEFAULT, key, 'node-x',
                             theirRecord(key));
    }
    const grown = replication.contributionCounts();
    for (let i = 0; i < NOTED; i++) {
      replication.contribute(HANDLE, DEFAULT, 'stats-' + STAMP + '-' + i,
                             'node-x', null);
    }
    const back = replication.contributionCounts();
    const listed = stats.userRows().filter(function (r) {
      return String(r.key).indexOf('stats-' + STAMP + '-') === 0;
    }).length;
    t.check(grown.keys - baseline.keys === NOTED &&
            back.keys === baseline.keys && back.values === baseline.values &&
            listed === 0,
            '5. five thousand admin_stats.users notes removed leave the ' +
            'module\'s fan-in where it was, and the users register lists ' +
            'none of them',
            JSON.stringify({ baseline: baseline, grown: grown, back: back,
                             listed: listed }));
    log.debug("Leaving run().");
  }
};
