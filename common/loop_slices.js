// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: loop_slices.js
//
// ===========================================================================
// A WALK IN SLICES, WITH A TURN OF THE EVENT LOOP BETWEEN THEM (#704).
//
// A scheduler job's body runs on a request worker since #408, or on the
// front process, and either way on a loop that is also answering requests.
// A body that walks a whole store in one turn — every session, every token
// record, every expired row of a register — holds that loop for the whole
// walk, however nicely the scheduler deferred the run. This is the one
// shape the walks take instead: `walkInSlices()` visits a Map `slice`
// entries at a time and awaits `nextTurn()` between slices, so a request on
// that process waits for one slice, never for the store.
//
// **A Map's iterator survives what other code does between slices**: an
// entry deleted before it is reached is not visited, one added is visited
// at the end, and deleting the entry just visited is safe. A walk that must
// not see its own deletions collects keys and deletes after it, as every
// caller did before; `visit` answering `true` deletes the entry visited,
// through the Map handed in, which for a `realms.map()` view is the
// journalling one, so a persisted store records the delete.
//
// **THE REALM DOES NOT NEED RE-ENTERING**: the ambient realm is an
// `AsyncLocalStorage` (`common/realms.js`), carried across `setImmediate()`
// and the await. `options.within(fn)` is for a walk over a NAMED realm's
// partition from outside it — `realms.run(realm, fn)` — so each slice's
// settings and writes are that realm's.
//
// A LEAF: it requires nothing of this service but `config`, for the logger.
// `common/cache_registry.js` has a walk of its own over ejector plans, for
// its counting; the rule it follows is this one.
// ===========================================================================

const bunyan = require('bunyan');
const config = require('./config');

const log = bunyan.createLogger({ name: 'sts-loop-slices' });
config.registerLogger(log);

/** Entries visited between two turns of the event loop, by default. */
const SLICE = 500;

/**
 * A promise that resolves at the next turn of the event loop, after the I/O
 * that is waiting.
 *
 * @returns the promise
 */
function nextTurn() {
  log.debug("Entering nextTurn().");
  log.debug("Leaving nextTurn().");
  return new Promise(function (resolve) {
    setImmediate(resolve);
  });
}

/**
 * Visits every entry of a Map a slice at a time, a turn of the event loop
 * between slices.
 *
 * @param {Map<any, any>} map - the Map, or a `realms.map()` view of one
 * @param {(value: any, key: any) => any} visit - called per entry; answering
 *   `true` deletes that entry through `map`
 * @param {{ slice?: number, within?: (fn: () => void) => void }} [options] -
 *   `slice`, the entries per turn (SLICE when omitted), and `within`, which
 *   runs each slice (inside a realm, say)
 * @returns {Promise<number>} how many entries `visit` deleted
 */
async function walkInSlices(map, visit, options) {
  log.debug("Entering walkInSlices().");
  const o = options || {};
  const slice = Math.max(1, Number(o.slice) || SLICE);
  const within = typeof o.within === 'function' ? o.within
    : function (fn) {
      fn();
    };
  const it = map.entries();
  let deleted = 0;
  let done = false;
  while (!done) {
    within(function () {
      for (let i = 0; i < slice; i++) {
        const step = it.next();
        if (step.done) {
          done = true;
          return;
        }
        if (visit(step.value[1], step.value[0]) === true) {
          map.delete(step.value[0]);
          deleted += 1;
        }
      }
    });
    if (!done) {
      await nextTurn();
    }
  }
  log.debug("Leaving walkInSlices(). " + deleted + " deleted.");
  return deleted;
}

/**
 * Calls `fn` on every item of an array a slice at a time, a turn of the event
 * loop between slices.
 *
 * @param {any[]} items - the items
 * @param {(item: any, index: number) => void} fn - called per item
 * @param {number} [slice] - the items per turn; SLICE when omitted
 * @returns {Promise<void>} resolved once every item has been seen
 */
async function eachInSlices(items, fn, slice) {
  log.debug("Entering eachInSlices().");
  const size = Math.max(1, Number(slice) || SLICE);
  for (let i = 0; i < items.length; i++) {
    if (i > 0 && i % size === 0) {
      await nextTurn();
    }
    fn(items[i], i);
  }
  log.debug("Leaving eachInSlices(). " + items.length + ".");
}

/**
 * A walk in slices, with a turn of the event loop between them (#704): what a
 * scheduler job's body walks a store with, so its process keeps answering.
 *
 * @namespace
 */
module.exports = {
  SLICE: SLICE,
  nextTurn: nextTurn,
  walkInSlices: walkInSlices,
  eachInSlices: eachInSlices
};
