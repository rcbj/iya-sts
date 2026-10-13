// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/seq_allocator.js
//
// ---------------------------------------------------------------------------
// A SEQUENCE NUMBER UNIQUE ACROSS EVERY PROCESS OF ONE SERVICE (#465).
//
// The audit log and the delegation register numbered rows with a counter per
// process, and `/admin-api` published it as "monotonic and never reused" —
// so two request workers both numbered their rows 1, 2, … and a reader
// walking by `seq` missed them. `common/seq_allocator.ts` leases blocks from
// one shared counter. Held here, with two allocators standing for two
// processes over one counter (the table's upsert, simulated):
//
//   1. without a shared store the caller's own counter is used, unchanged;
//   2. with one, two processes' numbers never collide and each process's
//      rise — across many blocks, so the background lease is exercised;
//   3. a stream that spends both blocks with no lease falls back to its own
//      range, unique per process, and keeps rising there;
//   4. a lease that fails at start leaves the caller's own counter in use;
//   5. the audit log and the delegation register stamp `seq` and `origin`
//      on every row (one process, no shared store, as `npm test` runs).
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const SeqAllocatorModule = require('../common/seq_allocator');
const { SeqAllocator } = SeqAllocatorModule;

const log = require('bunyan').createLogger({ name: 'seq_allocator',
  level: process.env.LOG_LEVEL || 'info' });

// One shared counter, as `sts_cluster_windows` is: a distinct, rising count
// per call and per (scope, key). `fail` makes every call refuse; `hold`
// leaves calls unanswered until released.
function sharedCounter() {
  log.debug("Entering sharedCounter().");
  const counts = {};
  const state = { fail: false, held: [], hold: false };
  const counters = {
    sharesWindows: function () {
      return true;
    },
    countInWindow: function (opts) {
      const answer = function () {
        if (state.fail) {
          return { ok: false, reason: 'store', why: 'refused by the test' };
        }
        const key = opts.scope + '|' + opts.key;
        counts[key] = (counts[key] || 0) + 1;
        return { ok: true, count: counts[key], remainingMs: 1 };
      };
      if (state.hold) {
        return new Promise(function (resolve) {
          state.held.push(function () {
            resolve(answer());
          });
        });
      }
      return Promise.resolve(answer());
    }
  };
  log.debug("Leaving sharedCounter().");
  return { counters: counters, state: state };
}

// Lets the background leases of a few next() calls settle.
function settle() {
  log.debug("Entering settle().");
  log.debug("Leaving settle().");
  return new Promise(function (resolve) {
    setImmediate(resolve);
  });
}

async function run(t) {
  log.debug("Entering run().");
  const BLOCK = SeqAllocatorModule.BLOCK;

  // --- 1. No shared store -------------------------------------------------
  const lonely = new SeqAllocator({ counters: function () {
    return { sharesWindows: function () {
      return false;
    } };
  } });
  await lonely.start();
  let own = 0;
  const local = function () {
    own++;
    return own;
  };
  t.check(lonely.next('audit', local) === 1 &&
          lonely.next('audit', local) === 2 && !lonely.status().shared,
          '1. without a shared store the caller\'s own counter numbers ' +
          'the rows, as it always did');

  // --- 2. Two processes, one counter --------------------------------------
  const shared = sharedCounter();
  const a = new SeqAllocator({ counters: function () {
    return shared.counters;
  } });
  const b = new SeqAllocator({ counters: function () {
    return shared.counters;
  } });
  await a.start();
  await b.start();
  t.check(a.status().shared && b.status().shared &&
          a.status().originIndex !== b.status().originIndex,
          '2. both processes leased from the store, with distinct origin ' +
          'indexes', JSON.stringify([a.status(), b.status()]));
  const seen = {};
  const fromA = [];
  const fromB = [];
  let duplicate = 0;
  const unused = function () {
    return -1;
  };
  for (let i = 0; i < 3 * BLOCK; i++) {
    const x = a.next('delegation', unused);
    const y = b.next('delegation', unused);
    [x, y].forEach(function (one) {
      if (seen[one]) {
        duplicate++;
      }
      seen[one] = true;
    });
    fromA.push(x);
    fromB.push(y);
    if (i % 100 === 0) {
      await settle();
    }
  }
  const rising = function (list) {
    return list.every(function (one, i) {
      return i === 0 || one > list[i - 1];
    });
  };
  t.check(duplicate === 0 && rising(fromA) && rising(fromB) &&
          fromA.every(function (one) {
            return one > 0 && one < SeqAllocatorModule.FALLBACK_BASE;
          }),
          '2. across three blocks each, the two processes\' numbers never ' +
          'collide, each process\'s rise, and every one is a leased number',
          JSON.stringify({ duplicate: duplicate,
                           a: [fromA[0], fromA[fromA.length - 1]],
                           b: [fromB[0], fromB[fromB.length - 1]] }));
  const auditA = a.next('audit', unused);
  const auditB = b.next('audit', unused);
  t.check(auditA !== auditB && auditA > 0 && auditB > 0,
          '2. a second stream is leased on its own', auditA + ' ' + auditB);

  // --- 3. The store goes away ---------------------------------------------
  shared.state.hold = true;
  const left = a.status().streams.delegation;
  const toSpend = (left.current ? left.current.end - left.current.next + 1
                                : 0) +
                  (left.spare ? left.spare.end - left.spare.next + 1 : 0);
  for (let i = 0; i < toSpend; i++) {
    a.next('delegation', unused);
  }
  const fallbackA1 = a.next('delegation', unused);
  const fallbackA2 = a.next('delegation', unused);
  const bLeft = b.status().streams.delegation;
  const bSpend = (bLeft.current ? bLeft.current.end - bLeft.current.next + 1
                                : 0) +
                 (bLeft.spare ? bLeft.spare.end - bLeft.spare.next + 1 : 0);
  for (let i = 0; i < bSpend; i++) {
    b.next('delegation', unused);
  }
  const fallbackB1 = b.next('delegation', unused);
  t.check(fallbackA1 >= SeqAllocatorModule.FALLBACK_BASE &&
          fallbackA2 === fallbackA1 + 1 &&
          fallbackB1 >= SeqAllocatorModule.FALLBACK_BASE &&
          fallbackB1 !== fallbackA1 && fallbackB1 !== fallbackA2 &&
          a.status().streams.delegation.fallback,
          '3. with both blocks spent and no lease, each process numbers ' +
          'from a range of its own, rising, and the two never meet',
          JSON.stringify([fallbackA1, fallbackA2, fallbackB1]));
  shared.state.hold = false;
  shared.state.held.forEach(function (release) {
    release();
  });
  await settle();
  await settle();
  const afterReturn = a.next('delegation', unused);
  t.check(afterReturn === fallbackA2 + 1,
          '3. and stays in its range when the store returns, so its ' +
          'numbers keep rising', afterReturn);

  // --- 4. A lease that fails at start -------------------------------------
  const broken = sharedCounter();
  broken.state.fail = true;
  const c = new SeqAllocator({ counters: function () {
    return broken.counters;
  } });
  await c.start();
  let mine = 100;
  t.check(!c.status().shared &&
          c.next('audit', function () {
            mine++;
            return mine;
          }) === 101,
          '4. a lease refused at start leaves the caller\'s own counter in ' +
          'use, and nothing waits or throws');

  // --- 5. The two registers stamp their rows ------------------------------
  const audit = require('../common/audit');
  const delegation = require('../common/delegation');
  const realms = require('../common/realms');
  realms.run(realms.DEFAULT_REALM, function () {
    const before = audit.list().length;
    audit.audit({ category: 'admin', action: 'admin.test',
                  summary: 'seq_allocator test' });
    const event = audit.list()[0];
    const act = delegation.record({
      protocol: delegation.TYPES[0].protocol, type: delegation.TYPES[0].type,
      outcome: delegation.OUTCOMES[0], initial: { presented: 'sa-alice' },
      intermediary: { presented: 'sa-front', application: 'sa-front' },
      target: { application: 'sa-back' }, authorizedBy: 'a test' });
    t.check(audit.list().length === before + 1 &&
            typeof event.seq === 'number' && event.seq > 0 &&
            Object.prototype.hasOwnProperty.call(event, 'origin') &&
            act && typeof act.seq === 'number' && act.seq > 0 &&
            Object.prototype.hasOwnProperty.call(act, 'origin'),
            '5. every audit event and delegation act carries a seq and its ' +
            'origin', JSON.stringify({ event: event && [event.seq,
              event.origin], act: act && [act.seq, act.origin] }));
    const summary = delegation.summary();
    t.check(summary.newestSeq === act.seq,
            '5. the register\'s newestSeq names the newest act it holds',
            summary.newestSeq + ' ' + act.seq);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'seq allocator',
  describe: 'audit and delegation sequence numbers unique across every ' +
            'process of one service (#465)',
  run: run
};
