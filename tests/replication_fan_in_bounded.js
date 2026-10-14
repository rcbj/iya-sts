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
//      the users register lists none of them;
//   6. A DEAD PROCESS'S CONTRIBUTIONS GO (#618 phase 2): an origin that is
//      not a live reader of the change log is dropped from the fan-in once it
//      has been absent for the grace period, and not before; a live one, and
//      one that turns live inside the grace, is kept; the levels a dropped
//      origin empties go with it; a failed read of the readers drops
//      nothing; the change-log pull's own scheduler job does it, at most once
//      a minute, with no timer of its own.
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

// A coordinating driver whose live readers the test says (#618 phase 2).
function readersDriver(live) {
  log.debug("Entering readersDriver().");
  const d = {
    asked: 0,
    fail: false,
    origin: function () {
      log.debug("Entering origin().");
      log.debug("Leaving origin().");
      return 'node-self';
    },
    latestChangeSeq: function () {
      log.debug("Entering latestChangeSeq().");
      log.debug("Leaving latestChangeSeq().");
      return Promise.resolve(0);
    },
    changeCeiling: function () {
      log.debug("Entering changeCeiling().");
      log.debug("Leaving changeCeiling().");
      return Promise.resolve(0);
    },
    changesSince: function () {
      log.debug("Entering changesSince().");
      log.debug("Leaving changesSince().");
      return Promise.resolve([]);
    },
    reportChangeReader: function () {
      log.debug("Entering reportChangeReader().");
      log.debug("Leaving reportChangeReader().");
      return Promise.resolve({ inserted: true });
    },
    liveChangeReaders: function () {
      log.debug("Entering liveChangeReaders().");
      d.asked += 1;
      log.debug("Leaving liveChangeReaders().");
      return d.fail ? Promise.reject(new Error('the readers are unreadable'))
        : Promise.resolve(Array.from(live));
    }
  };
  log.debug("Leaving readersDriver().");
  return d;
}

// Section 6: a dead process's contributions go.
async function deadOrigins(t) {
  log.debug("Entering deadOrigins().");
  // `persistence.coordinate` is restart-only: varied through the
  // environment, as tests/replication.js does.
  const before = process.env.STS_PERSISTENCE_COORDINATE;
  process.env.STS_PERSISTENCE_COORDINATE = 'true';
  replication.reset();
  const live = new Set(['node-live']);
  const driver = readersDriver(live);
  await replication.start(driver, {});
  const OTHER = 'audit.events';
  const fill = function () {
    ['node-live', 'node-dead', 'node-new'].forEach(function (o) {
      replication.contribute(HANDLE, DEFAULT, 'both-' + STAMP, o,
                             theirRecord('both-' + STAMP + '-' + o));
    });
    replication.contribute(HANDLE, DEFAULT, 'dead-only-' + STAMP, 'node-dead',
                           theirRecord('dead-only-' + STAMP));
    replication.contribute(OTHER, 'acme', '', 'node-dead', [{ n: 1 }]);
    replication.contribute(OTHER, DEFAULT, '', 'node-live', [{ n: 2 }]);
  };
  fill();
  const held = replication.contributionCounts();
  const graceMs = replication.status().retention.fanInGraceS * 1000;
  t.check(graceMs >= 15 * 60 * 1000 &&
          graceMs >= replication.status().retention.readerTtlS * 1000,
          '6. the grace is the reader TTL and never less than fifteen ' +
          'minutes: a restart under a stable origin is not a death',
          String(graceMs));
  const t0 = Date.now();
  const first = await replication.pruneFanIn(true, t0);
  t.check(first && first.dropped.length === 0 &&
          JSON.stringify(replication.contributionCounts()) ===
            JSON.stringify(held),
          '6a. an origin first seen not live is only noted: nothing is ' +
          'dropped at once', JSON.stringify(first));
  const early = await replication.pruneFanIn(true, t0 + graceMs - 1);
  t.check(early && early.dropped.length === 0 &&
          JSON.stringify(replication.contributionCounts()) ===
            JSON.stringify(held),
          '6b. nor before the grace period (' + graceMs + ' ms) has passed',
          JSON.stringify(early));
  live.add('node-new');
  const late = await replication.pruneFanIn(true, t0 + graceMs);
  const both = replication.remoteRows(HANDLE, DEFAULT, 'both-' + STAMP)
    .map(function (r) {
      return r.key;
    }).sort();
  const after = replication.contributionCounts();
  t.check(late && JSON.stringify(late.dropped) === '["node-dead"]' &&
          late.values === 3 &&
          JSON.stringify(both) === JSON.stringify(
            ['both-' + STAMP + '-node-live', 'both-' + STAMP + '-node-new']),
          '6c. after the grace the dead origin is dropped, and the live one ' +
          'and the one that turned live inside the grace are kept',
          JSON.stringify({ late: late, both: both }));
  t.check(replication.remoteRows(HANDLE, DEFAULT,
                                 'dead-only-' + STAMP).length === 0 &&
          replication.remoteKeys(HANDLE, DEFAULT)
            .indexOf('dead-only-' + STAMP) < 0 &&
          replication.remoteRows(OTHER, 'acme', '').length === 0 &&
          replication.remoteRows(OTHER, DEFAULT, '').length === 1 &&
          after.values === held.values - 3 && after.keys === held.keys - 2 &&
          after.realms === held.realms - 1,
          '6d. the levels only the dead origin held go with it: its key, ' +
          'and its realm under a handle another origin still holds',
          JSON.stringify({ held: held, after: after }));
  t.check(replication.origins().sort().join(',') === 'node-live,node-new',
          '6e. and it is no longer among the other processes',
          replication.origins().join(','));

  // A failed read of the readers drops nothing.
  replication.contribute(HANDLE, DEFAULT, 'gone-' + STAMP, 'node-gone',
                         theirRecord('gone-' + STAMP));
  await replication.pruneFanIn(true, t0 + graceMs + 1);
  driver.fail = true;
  const failed = await replication.pruneFanIn(true, t0 + 3 * graceMs);
  t.check(failed === null &&
          replication.remoteRows(HANDLE, DEFAULT, 'gone-' + STAMP).length ===
            1,
          '6f. a failed read of the live readers drops nothing — an origin ' +
          'is dropped on the readers\' evidence, never on its absence');
  driver.fail = false;

  // The change-log pull's own job does it, at most once a minute.
  replication.reset();
  await replication.start(driver, {});
  fill();
  const job = require('../cluster/scheduler').job(
    'persistence.change-log-pull');
  const asked = driver.asked;
  await job.run();
  await job.run();
  t.check(!!job && job.kind === 'per-process' && driver.asked === asked + 1,
          '6g. the change-log pull\'s per-process job asks who is live, and ' +
          'twice in a minute asks once', String(driver.asked - asked));
  replication.reset();
  if (before === undefined) {
    delete process.env.STS_PERSISTENCE_COORDINATE;
  } else {
    process.env.STS_PERSISTENCE_COORDINATE = before;
  }
  log.debug("Leaving deadOrigins().");
}

module.exports = {
  name: 'replication_fan_in_bounded',
  describe: 'the replication fan-in of merge: \'own\' stores holds what the ' +
            'other processes hold now: a removal takes its empty levels ' +
            'with it, so thirty thousand noted-and-evicted people leave a ' +
            'bounded number of entries, and a dead process\'s ' +
            'contributions go after a grace period (#618)',
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

    // --- 6. a dead process's contributions go ----------------------------
    await deadOrigins(t);
    log.debug("Leaving run().");
  }
};
