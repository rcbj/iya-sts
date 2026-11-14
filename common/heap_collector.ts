// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: heap_collector.ts
//
// ---------------------------------------------------------------------------
// A FULL GARBAGE COLLECTION OF THE V8 ISOLATE THAT ASKS, ON DEMAND (#611,
// 2026-10-13).
//
// Monitoring → Node Health's Collect buttons (`admin-ui/node_health_admin.ts`)
// run one in the front process's main thread and, over the request pool's
// channel, in each request and hosted-surface worker thread
// (`common/request_worker.ts`). Each worker thread is an isolate of its own,
// so each collects itself: nothing here reaches another thread's heap.
//
// **`gc` WITHOUT A STARTUP FLAG.** `global.gc` exists only under
// `--expose-gc`, and rcbj's decision was not to touch the command line —
// `common/process_memory.ts`'s re-exec and the pool's `Worker` flags stay as
// they are. V8 reads `--expose-gc` when it makes a CONTEXT, so the flag is
// set for as long as it takes `vm.runInNewContext('gc')` to make one and hand
// its `gc` back, and then CLEARED: left set, every context made afterwards —
// every `vm` sandbox, every worker thread a pool starts — would carry a
// global `gc` nobody asked for. The function handed back keeps working after
// the flag is cleared (it is bound to the isolate, not to the flag), and is
// kept, one per isolate, since a static field is per isolate too. A process
// that WAS started with `--expose-gc` already has `global.gc`; that one is
// used and the flag is left alone, because clearing it would take `gc` from
// the contexts that process's operator meant to have it.
//
// **THE FIGURES ARE THE ISOLATE'S OWN**: `v8.getHeapStatistics()`'s
// `used_heap_size` and `total_heap_size` before and after, and the time the
// call took, which is the pause — the collection is synchronous and stops
// this thread until it finishes. `process.memoryUsage()` would add a read of
// `/proc` for the resident size, which in a worker thread is the whole
// process's anyway.
//
// **A STATIC UTILITY CLASS** (#50, `common/html.ts`'s shape) holding one
// cached function. It requires only node's own modules and takes its logger
// as an argument, so it can be required from a worker thread before the
// service's logger is the one it should use, and it can close no cycle.
// ---------------------------------------------------------------------------

import v8 = require('v8');
import vm = require('vm');

// What `collect()` logs through: `helpers.log`, or a worker's own.
interface CollectorLog {
  debug(message: string): void;
}

// What one collection answers.
interface Collection {
  ok: boolean;
  heapUsedBeforeBytes: number | null;
  heapTotalBeforeBytes: number | null;
  heapUsedAfterBytes: number | null;
  heapTotalAfterBytes: number | null;
  freedBytes: number | null;
  durationMs: number | null;
  error: string | null;
}

/**
 * Runs a full garbage collection of the calling V8 isolate and reports its
 * heap before and after: the on-demand control of Monitoring → Node Health.
 *
 * A static utility class; its one piece of state is the cached `gc`.
 */
class HeapCollector {
  // `gc`, once obtained in this isolate.
  private static gcFn: (() => void) | null = null;

  /**
   * Answers V8's `gc` for this isolate, obtaining it the first time without
   * a startup flag: `--expose-gc` set while one context is made, then
   * cleared. A process started with the flag has it already.
   *
   * @param log - the logger
   * @returns the function
   * @throws Error when V8 hands back no function
   */
  static gcFunction(log: CollectorLog): () => void {
    log.debug("Entering HeapCollector.gcFunction().");
    if (HeapCollector.gcFn) {
      log.debug("Leaving HeapCollector.gcFunction(). Cached.");
      return HeapCollector.gcFn;
    }
    const exposed = (globalThis as any).gc;
    if (typeof exposed === 'function') {
      HeapCollector.gcFn = exposed;
      log.debug("Leaving HeapCollector.gcFunction(). Started with it.");
      return exposed;
    }
    let found: unknown = null;
    v8.setFlagsFromString('--expose-gc');
    try {
      found = vm.runInNewContext('gc');
    } finally {
      // CLEARED WHATEVER HAPPENED, for the reason the header gives: a flag
      // left set puts `gc` in every context made from now on.
      v8.setFlagsFromString('--no-expose-gc');
    }
    if (typeof found !== 'function') {
      log.debug("Leaving HeapCollector.gcFunction(). V8 gave no gc.");
      throw new Error('V8 did not expose gc to a new context');
    }
    HeapCollector.gcFn = found as () => void;
    log.debug("Leaving HeapCollector.gcFunction(). Obtained.");
    return HeapCollector.gcFn;
  }

  /**
   * Runs one full garbage collection of this isolate, synchronously.
   *
   * Never throws: a `gc` that cannot be obtained, or that throws, is an
   * answer with `ok: false` and the reason, and the figures it could not
   * read null.
   *
   * @param log - the logger
   * @returns the heap before and after, the bytes freed and the pause
   */
  static collect(log: CollectorLog): Collection {
    log.debug("Entering HeapCollector.collect().");
    let gc: () => void;
    try {
      gc = HeapCollector.gcFunction(log);
    } catch (e) {
      log.debug("Caught in HeapCollector.collect(): " +
                ((e && e.message) || e));
      // Nothing was collected, so there is no figure to give; the caller
      // records the reason under its error code.
      log.debug("Leaving HeapCollector.collect(). No gc.");
      return { ok: false, heapUsedBeforeBytes: null,
               heapTotalBeforeBytes: null, heapUsedAfterBytes: null,
               heapTotalAfterBytes: null, freedBytes: null,
               durationMs: null,
               error: 'gc could not be obtained: ' +
                      String((e && e.message) || e) };
    }
    const before = v8.getHeapStatistics();
    const started = process.hrtime.bigint();
    try {
      gc();
    } catch (e) {
      log.debug("Caught in HeapCollector.collect(): " +
                ((e && e.message) || e));
      // V8's gc does not throw in practice; if it did, the heap is as it
      // was and the answer says why.
      log.debug("Leaving HeapCollector.collect(). gc threw.");
      return { ok: false, heapUsedBeforeBytes: before.used_heap_size,
               heapTotalBeforeBytes: before.total_heap_size,
               heapUsedAfterBytes: null, heapTotalAfterBytes: null,
               freedBytes: null, durationMs: null,
               error: 'gc threw: ' + String((e && e.message) || e) };
    }
    const took = Number(process.hrtime.bigint() - started) / 1e6;
    const after = v8.getHeapStatistics();
    log.debug("Leaving HeapCollector.collect().");
    return {
      ok: true,
      heapUsedBeforeBytes: before.used_heap_size,
      heapTotalBeforeBytes: before.total_heap_size,
      heapUsedAfterBytes: after.used_heap_size,
      heapTotalAfterBytes: after.total_heap_size,
      freedBytes: before.used_heap_size - after.used_heap_size,
      durationMs: Math.round(took * 1000) / 1000,
      error: null
    };
  }
}

export = HeapCollector;
