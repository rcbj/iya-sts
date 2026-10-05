// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: bounded_lru.js
//
// ===========================================================================
// `common/bounded_lru.ts`: THE BOUNDED LEAST-RECENTLY-USED CACHE (#349
// phase 1, 2026-09-29).
//
// The class a request worker's directory window will be built on. Nothing in
// the service constructs one yet, so everything it promises is held here:
//
//   A. RECENCY IS USE. `get()` moves a key to the young end, so the key
//      evicted is the one least recently READ, not the one inserted first —
//      the difference from `cacheRegistry.makeRoom()`, and the reason the
//      class exists. `peek()` and `has()` are not a use.
//   B. THE BOUND IS A FUNCTION, asked at every insert; lowering it takes
//      effect at the next insert, and an unreadable bound is one.
//   C. A PINNED KEY IS NEVER EVICTED; pins are counted; with every key
//      pinned the cache stays over its bound and `stats()` says by how much,
//      and the last unpin brings it back within it.
//   D. THE REGISTRY: described once at construction; hits, misses and
//      evictions reach the registry's counter; a row carries the key as
//      `rowOf` shows it and never the value.
//   E. `onEvict` is told after the fact, and a listener that throws changes
//      nothing.
// ===========================================================================

const BoundedLru = require('../common/bounded_lru');
const cacheRegistry = require('../common/cache_registry');

const log = require('bunyan').createLogger({ name: 'bounded_lru',
  level: process.env.LOG_LEVEL || 'info' });

// A marker no registry row may carry.
const SECRET = 'bounded-lru-VALUE-must-not-appear';

function recency(t) {
  log.debug("Entering recency().");
  let max = 3;
  const lru = new BoundedLru({ name: 'test.lru-recency',
    maxEntries: function () { return max; } });
  lru.set('a', 1).set('b', 2).set('c', 3);
  t.equal(lru.get('a'), 1, 'A1. a held value is read back');
  lru.set('d', 4);
  t.check(!lru.has('b') && lru.has('a') && lru.has('c') && lru.has('d'),
          'A2. past the bound, the least recently READ key goes (b), not ' +
          'the first inserted (a, read since)', JSON.stringify(lru.keys()));
  lru.peek('c');
  lru.has('c');
  lru.set('e', 5);
  t.check(!lru.has('c') && lru.has('a'),
          'A3. peek() and has() are not a use: c, only peeked, is the ' +
          'next to go', JSON.stringify(lru.keys()));
  lru.set('a', 10);
  t.equal(lru.size, 3, 'A4. setting a held key replaces it and grows nothing');
  t.equal(lru.keys()[2], 'a', 'A5. and makes it the most recently used');
  t.equal(lru.get('zz'), undefined, 'A6. a key never held reads as undefined');
  const s = lru.stats();
  t.check(s.hits === 1 && s.misses === 1 && s.evictions === 2,
          'A7. stats() counts the hit, the miss and both evictions',
          JSON.stringify(s));

  // --- B. the bound -------------------------------------------------------
  max = 1;
  t.equal(lru.size, 3, 'B1. lowering the bound evicts nothing by itself');
  lru.set('f', 6);
  t.check(lru.size === 1 && lru.has('f'),
          'B2. and takes effect at the next insert',
          JSON.stringify(lru.keys()));
  [NaN, 0, -5, Infinity].forEach(function (bad) {
    max = bad;
    t.equal(lru.limit(), 1, 'B3. an unusable bound (' + String(bad) +
            ') is read as one, never as unbounded');
  });
  const throwing = new BoundedLru({ name: 'test.lru-throws',
    maxEntries: function () { throw new Error('unreadable'); } });
  throwing.set('x', 1).set('y', 2);
  t.check(throwing.size === 1 && throwing.has('y'),
          'B4. a bound that throws is one too',
          JSON.stringify(throwing.keys()));
  log.debug("Leaving recency().");
}

function pinning(t) {
  log.debug("Entering pinning().");
  const lru = new BoundedLru({ name: 'test.lru-pins',
    maxEntries: function () { return 2; } });
  lru.set('a', 1);
  lru.pin('a');
  lru.set('b', 2).set('c', 3);
  t.check(lru.has('a') && !lru.has('b') && lru.has('c'),
          'C1. a pinned key is skipped by the eviction; the oldest unpinned ' +
          'goes instead', JSON.stringify(lru.keys()));
  lru.pin('c');
  lru.pin('c');
  lru.pin('d');
  lru.set('d', 4);
  t.check(lru.has('a') && lru.has('c') && lru.has('d'),
          'C2. with every key pinned the cache stays over its bound rather ' +
          'than drop one', JSON.stringify(lru.keys()));
  t.equal(lru.stats().overBound, 1, 'C3. and stats() reports the overrun');
  t.equal(lru.stats().pinned, 3, 'C4. and the pinned keys held');
  lru.unpin('c');
  t.check(lru.isPinned('c'),
          'C5. pins are counted: one unpin of a twice-pinned key keeps it ' +
          'pinned');
  lru.unpin('a');
  t.check(!lru.has('a') && lru.size === 2,
          'C6. the unpin that frees a key brings the cache back within its ' +
          'bound at once', JSON.stringify(lru.keys()));
  lru.pin('later');
  lru.set('later', 9);
  lru.set('e', 5);
  t.check(lru.has('later'),
          'C7. a key pinned before it is held is protected from the moment ' +
          'it arrives', JSON.stringify(lru.keys()));
  lru.delete('later');
  t.check(!lru.isPinned('later'), 'C8. delete() drops the pins with the key');
  lru.clear();
  t.check(lru.size === 0 && !lru.isPinned('c'),
          'C9. clear() drops every key and every pin');
  log.debug("Leaving pinning().");
}

function registry(t) {
  log.debug("Entering registry().");
  const registered = [];
  const counted = { hit: 0, miss: 0, evicted: 0 };
  const double = {
    register: function (d) {
      registered.push(d);
      return {
        hit: function () { counted.hit += 1; },
        miss: function () { counted.miss += 1; },
        evicted: function (n) { counted.evicted += n; },
        refused: function () {}
      };
    }
  };
  const lru = new BoundedLru({ name: 'test.lru-described',
    maxEntries: function () { return 2; }, registry: double,
    title: 'Test window', owner: 'tests/bounded_lru.js',
    settings: ['test.setting'],
    rowOf: function (key) {
      const cut = key.indexOf('\n');
      return { realm: key.slice(0, cut), key: key.slice(cut + 1) };
    } });
  t.equal(registered.length, 1, 'D1. a cache given a registry registers once');
  lru.set('acme\ncn=a', { secret: SECRET });
  lru.set('acme\ncn=b', { secret: SECRET });
  lru.get('acme\ncn=a');
  lru.get('acme\ncn=zz');
  lru.set('\ncn=c', { secret: SECRET });
  t.check(counted.hit === 1 && counted.miss === 1 && counted.evicted === 1,
          'D2. hits, misses and evictions reach the registry\'s counter',
          JSON.stringify(counted));
  const d = registered[0];
  const rows = d.entries();
  t.check(rows.length === 2 && rows[0].realm === 'acme' &&
          rows[0].key === 'cn=a' && rows[1].realm === '',
          'D3. a row is the key as rowOf shows it, in its realm',
          JSON.stringify(rows));
  t.check(JSON.stringify(rows).indexOf(SECRET) < 0,
          'D4. and never carries the value');
  t.equal(d.maxEntries(), 2, 'D5. the descriptor\'s bound is the cache\'s');
  const plain = new BoundedLru({ name: 'test.lru-undescribed',
    maxEntries: function () { return 1; } });
  plain.set('x', 1);
  t.equal(registered.length, 1,
          'D6. a cache given no registry describes itself nowhere');

  // Against the real registry: the page's summary of it is well-formed.
  const real = new BoundedLru({ name: 'test.lru-real-registry',
    maxEntries: function () { return 5; }, registry: cacheRegistry,
    owner: 'tests/bounded_lru.js' });
  real.set('k', SECRET);
  real.get('k');
  const row = cacheRegistry.report().filter(function (r) {
    return r.name === 'test.lru-real-registry';
  })[0];
  t.check(row && row.size === 1 && row.maxEntries === 5 && row.hits === 1 &&
          !row.problem && JSON.stringify(row).indexOf(SECRET) < 0,
          'D7. the real registry reports it: size, bound, hits, no problem, ' +
          'no value', JSON.stringify(row));
  cacheRegistry.forget('test.lru-real-registry');
  log.debug("Leaving registry().");
}

function evictionListener(t) {
  log.debug("Entering evictionListener().");
  const told = [];
  const lru = new BoundedLru({ name: 'test.lru-evict',
    maxEntries: function () { return 1; },
    onEvict: function (key, value) {
      told.push(key + '=' + value);
      throw new Error('a listener that throws');
    } });
  lru.set('a', 1).set('b', 2);
  t.check(told.length === 1 && told[0] === 'a=1' && !lru.has('a') &&
          lru.has('b'),
          'E1. onEvict is told the key and value after it has gone, and a ' +
          'listener that throws changes nothing', JSON.stringify(told));
  t.check((function () {
    try {
      new BoundedLru({ name: 'test.lru-bad' });
      return false;
    } catch (e) {
      log.debug("Caught in evictionListener(): " + e.message);
      return true;
    }
  })(), 'E2. a cache with no bound function is refused at construction');
  log.debug("Leaving evictionListener().");
}

function run(t) {
  log.debug("Entering run().");
  recency(t);
  pinning(t);
  registry(t);
  evictionListener(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'bounded_lru',
  describe: 'common/bounded_lru.ts: recency of use, a bound read at every ' +
            'insert, pins that outrank the bound, and the registry row',
  run: run
};
