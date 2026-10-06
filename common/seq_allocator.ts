// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: seq_allocator.ts
//
// ---------------------------------------------------------------------------
// A SEQUENCE NUMBER UNIQUE ACROSS EVERY PROCESS OF ONE SERVICE (#465).
//
// The audit log (`common/audit.js`) and the delegation register
// (`common/delegation.js`) number every row with `seq`, and `/admin-api`
// published it as "monotonic and never reused". It was a counter in each
// process: a request worker is a thread with a heap of its own, a cluster node
// is another container, and each numbered its rows from 1 — so two workers on
// one node both handed out 1 and 2, and a reader walking by `seq` saw nothing
// new. The delegation counter was not even persisted, so a restarted process
// reused the numbers of the rows it had restored.
//
// rcbj's decision (2026-10-06): UNIQUE ACROSS PROCESSES, AND RISING WITHIN
// EACH ONE — not a strict global order, which only a write serialised across
// the cluster could give. So:
//
//   * **BLOCKS LEASED FROM THE STORE.** A process leases a block of BLOCK
//     numbers at a time from one shared counter in postgres and hands them out
//     itself. Block k is ((k - 1) * BLOCK, k * BLOCK]; k comes from one atomic
//     conditional upsert, so no two processes ever hold the same block.
//   * **NEVER WAITING.** `audit.record()` and `delegation.record()` are
//     synchronous and must not fail, so the numbers are leased AHEAD: two
//     blocks at the process's start, and the next one fetched in the
//     background once the current block is half spent.
//   * **A FALLBACK THAT IS STILL UNIQUE.** If the store cannot be reached for
//     long enough that both blocks are spent, numbers come from a range of
//     this process's own: at its start it also leased an ORIGIN INDEX, unique
//     to this process run, and its fallback range is FALLBACK_BASE + index *
//     ORIGIN_SPAN. A stream that has fallen back stays there until the process
//     restarts, so its numbers keep rising rather than dropping back below
//     the fallback range when the store returns.
//   * **ONE SINGLE-WRITER SHAPE KEEPS ITS OWN COUNTER.** Without a shared
//     store (memory, ldif) there is exactly one writing process — request
//     workers and clustering both require postgres — and the caller's own
//     counter is used, as it always was.
//
// What it does NOT give is one order across processes: process A may hold
// block 3 while B holds block 4, and an event A records after one B recorded
// has the smaller number. A reader resumes by time (`at`), with `seq` as the
// tie-break and as the row's name, and the published texts say so.
//
// THE COUNTER IS A ROW OF `sts_cluster_windows`, the table the rate limiter
// counts in (`cluster/cluster_counters.js`'s countInWindow()), with a window
// that never ends. Its upsert already gives every caller a distinct, rising
// count (measured: cluster/CLAUDE.md, "count inside a window"), and reusing it
// needs no schema change — the DDL is applied by somebody else, and a new
// table would leave every existing database short of it. Its scopes are this
// module's own (`seq.block`, `seq.origin`), and the window purge never
// reaches a row whose window ends a thousand years from now.
//
// A LEAF: bunyan and nothing of this service at load. The counters are
// required LAZILY, when the store is known to be open.
// ---------------------------------------------------------------------------

// This module's own logger, for `common/mode.js`'s reason: a leaf cannot
// require the shared one in helpers.js. The level is STS_LOG_LEVEL, then
// CONFIG_FILE's logLevel, then info.
let logLevelProblem: any = null;
const log = require('bunyan').createLogger({
  name: 'sts-seq-allocator',
  level: (function () {
    if (process.env.STS_LOG_LEVEL) {
      return process.env.STS_LOG_LEVEL;
    }
    try {
      return require(process.env.CONFIG_FILE as string).logLevel || 'info';
    } catch (e) {
      logLevelProblem = e;
      return 'info';
    }
  })()
});
// The error-code table, a leaf: requiring it moves nothing.
const errorCodes = require('./error_codes');
if (logLevelProblem) {
  log.debug('No log level from CONFIG_FILE, so info: ' +
            ((logLevelProblem && logLevelProblem.message) || logLevelProblem));
}

// How many numbers one lease holds. Large enough that a busy process leases
// rarely; small enough that a process that dies wastes little of the space.
const BLOCK = 1000;
// The start of the fallback space, and how much of it one process run owns.
// Leased numbers stay far below FALLBACK_BASE (2^52 is 4.5 * 10^15), and the
// whole fallback space ends below Number.MAX_SAFE_INTEGER (2^53 - 1).
const FALLBACK_BASE = Math.pow(2, 52);
const ORIGIN_SPAN = Math.pow(2, 31);
const ORIGIN_SLOTS = Math.pow(2, 20);
// A window that never ends: a thousand years, in milliseconds.
const FOREVER_MS = 1000 * 365 * 24 * 60 * 60 * 1000;
// The scopes of the two counters, in `sts_cluster_windows`.
const BLOCK_SCOPE = 'seq.block';
const ORIGIN_SCOPE = 'seq.origin';
// The streams leased at a process's start.
const STREAMS = ['audit', 'delegation'];

interface Range {
  next: number;
  end: number;
}

interface Stream {
  name: string;
  current: Range | null;
  spare: Range | null;
  leasing: boolean;
  fallback: boolean;
  fallbackNext: number;
}

/**
 * Hands out sequence numbers unique across every process of one service:
 * blocks leased ahead from a shared counter, a per-process fallback range,
 * and the caller's own counter where there is one writer (#465).
 */
class SeqAllocator {
  // The shared counters (`cluster/cluster_counters.js`), through a loader so
  // that a test can hand two allocators — two processes — one counter.
  private countersOf: () => any;
  private streams: Map<string, Stream> = new Map();
  private originIndex: number | null = null;
  private shared = false;
  private starting: Promise<any> | null = null;

  /**
   * @param opts - `counters`, a loader for the shared counters; the
   *   service's own, required lazily, when omitted
   */
  constructor(opts?: { counters?: () => any }) {
    this.countersOf = (opts && opts.counters) || function () {
      return require('../cluster/cluster_counters');
    };
  }

  /**
   * The next number of a stream: from this process's leased block where the
   * store is shared, from the caller's own counter otherwise. Never waits and
   * never throws.
   *
   * @param name - the stream, e.g. `audit` or `delegation`
   * @param local - the caller's own counter, for a single-writer store
   * @returns the number
   */
  next(name: string, local: () => number): number {
    log.debug('Entering SeqAllocator.next(). ' + name);
    if (!this.shared) {
      this.startLater();
      log.debug('Leaving SeqAllocator.next(). The caller\'s own counter.');
      return local();
    }
    const stream = this.streamOf(name);
    if (!stream.fallback) {
      if (!stream.current || stream.current.next > stream.current.end) {
        stream.current = stream.spare;
        stream.spare = null;
      }
      if (stream.current && stream.current.next <= stream.current.end) {
        const value = stream.current.next++;
        this.prefetch(stream);
        log.debug('Leaving SeqAllocator.next(). ' + value);
        return value;
      }
      // BOTH BLOCKS SPENT AND NO LEASE ARRIVED: the store has been out of
      // reach for BLOCK numbers or more. From here this stream numbers from
      // its own range until the process restarts.
      stream.fallback = true;
      log.error(errorCodes.tag('STS-STORE-0076') + 'seq_allocator: the "' +
                name + '" ' +
                'stream spent its leased numbers and no lease arrived from ' +
                'the store; it numbers from this process\'s own range ' +
                '(origin index ' + this.originIndex + ') until restart.');
    }
    const value = FALLBACK_BASE +
      ((this.originIndex as number) % ORIGIN_SLOTS) * ORIGIN_SPAN +
      (stream.fallbackNext++ % ORIGIN_SPAN);
    log.debug('Leaving SeqAllocator.next(). From the fallback range.');
    return value;
  }

  /**
   * Leases this process's origin index and the first two blocks of every
   * stream, where a shared store is open. Resolves either way: without a
   * shared store, or when the lease fails, the callers' own counters are
   * used and that is reported.
   *
   * @returns a promise of `{ shared, originIndex }`
   */
  start(): Promise<any> {
    log.debug('Entering SeqAllocator.start().');
    const self = this;
    if (this.shared) {
      log.debug('Leaving SeqAllocator.start(). Already leased.');
      return Promise.resolve(this.status());
    }
    if (this.starting) {
      log.debug('Leaving SeqAllocator.start(). Already starting.');
      return this.starting;
    }
    let counters: any = null;
    try {
      counters = this.countersOf();
    } catch (e) {
      log.debug('Caught in SeqAllocator.start(): ' +
                ((e && e.message) || e));
      counters = null;
    }
    if (!counters || !counters.sharesWindows()) {
      log.debug('Leaving SeqAllocator.start(). No shared store; each ' +
                'caller keeps its own counter.');
      return Promise.resolve(this.status());
    }
    this.starting = counters.countInWindow({
      scope: ORIGIN_SCOPE, key: 'index', windowMs: FOREVER_MS
    }).then(function (answer: any) {
      if (!answer || !answer.ok) {
        throw new Error((answer && answer.why) || 'no origin index');
      }
      const index = Number(answer.count) || 0;
      return STREAMS.reduce(function (chain: Promise<any>, name: string) {
        return chain.then(function () {
          return self.lease(self.streamOf(name));
        }).then(function () {
          return self.lease(self.streamOf(name));
        });
      }, Promise.resolve()).then(function () {
        self.originIndex = index;
        self.shared = STREAMS.every(function (name) {
          const stream = self.streamOf(name);
          return !!stream.current;
        });
        if (!self.shared) {
          throw new Error('a first block could not be leased');
        }
        log.info('seq_allocator: numbers are leased from the store in ' +
                 'blocks of ' + BLOCK + ' (origin index ' + index + ').');
        return self.status();
      });
    }).catch(function (e: any) {
      log.error(errorCodes.tag('STS-STORE-0075') + 'seq_allocator: the ' +
                'sequence numbers could ' +
                'not be leased from the store, so this process numbers its ' +
                'audit and delegation rows with its own counter, which is ' +
                'unique only within this process: ' +
                ((e && e.message) || e));
      self.streams = new Map();
      return self.status();
    }).then(function (status: any) {
      self.starting = null;
      return status;
    });
    log.debug('Leaving SeqAllocator.start(). Leasing.');
    return this.starting;
  }

  /**
   * What the allocator holds, for a status page or a test.
   *
   * @returns `{ shared, originIndex, block, streams }`
   */
  status(): any {
    log.debug('Entering SeqAllocator.status().');
    const streams: Record<string, any> = {};
    this.streams.forEach(function (stream, name) {
      streams[name] = {
        current: stream.current ? { next: stream.current.next,
                                    end: stream.current.end } : null,
        spare: stream.spare ? { next: stream.spare.next,
                                end: stream.spare.end } : null,
        fallback: stream.fallback
      };
    });
    log.debug('Leaving SeqAllocator.status().');
    return { shared: this.shared, originIndex: this.originIndex,
             block: BLOCK, streams: streams };
  }

  // A process that began without a shared store, and has one now, leases on
  // its next number rather than never: start() is idempotent and resolves.
  private startLater(): void {
    log.debug('Entering SeqAllocator.startLater().');
    if (!this.starting) {
      let shares = false;
      try {
        shares = this.countersOf().sharesWindows();
      } catch (e) {
        log.debug('Caught in SeqAllocator.startLater(): ' +
                  ((e && e.message) || e));
        shares = false;
      }
      if (shares) {
        this.start();
      }
    }
    log.debug('Leaving SeqAllocator.startLater().');
  }

  private streamOf(name: string): Stream {
    log.debug('Entering SeqAllocator.streamOf().');
    let stream = this.streams.get(name);
    if (!stream) {
      stream = { name: name, current: null, spare: null, leasing: false,
                 fallback: false, fallbackNext: 0 };
      this.streams.set(name, stream);
    }
    log.debug('Leaving SeqAllocator.streamOf().');
    return stream;
  }

  // The next block, fetched in the background once the current one is half
  // spent and none is waiting.
  private prefetch(stream: Stream): void {
    log.debug('Entering SeqAllocator.prefetch().');
    const left = stream.current ? stream.current.end - stream.current.next + 1
                                : 0;
    if (!stream.spare && !stream.leasing && !stream.fallback &&
        left < BLOCK / 2) {
      this.lease(stream);
    }
    log.debug('Leaving SeqAllocator.prefetch().');
  }

  // One block from the shared counter, placed as the current block or the
  // spare. Resolves either way; a failure is logged and retried at the next
  // prefetch.
  private lease(stream: Stream): Promise<void> {
    log.debug('Entering SeqAllocator.lease(). ' + stream.name);
    stream.leasing = true;
    let counters: any = null;
    try {
      counters = this.countersOf();
    } catch (e) {
      log.debug('Caught in SeqAllocator.lease(): ' + ((e && e.message) || e));
      stream.leasing = false;
      log.debug('Leaving SeqAllocator.lease(). No counters.');
      return Promise.resolve();
    }
    log.debug('Leaving SeqAllocator.lease(). Asking the store.');
    return counters.countInWindow({
      scope: BLOCK_SCOPE, key: stream.name, windowMs: FOREVER_MS
    }).then(function (answer: any) {
      if (!answer || !answer.ok) {
        log.warn(errorCodes.tag('STS-STORE-0077') +
                 'seq_allocator: a block of "' +
                 stream.name + '" numbers could not be leased: ' +
                 ((answer && answer.why) || 'no answer') + '.');
        return;
      }
      const k = Number(answer.count) || 0;
      const range = { next: (k - 1) * BLOCK + 1, end: k * BLOCK };
      if (!stream.current) {
        stream.current = range;
      } else {
        stream.spare = range;
      }
    }, function (e: any) {
      log.debug('Caught in SeqAllocator.lease(): ' + ((e && e.message) || e));
      log.warn(errorCodes.tag('STS-STORE-0077') +
               'seq_allocator: a block of "' + stream.name +
               '" numbers could not be leased: ' + ((e && e.message) || e) +
               '.');
    }).then(function () {
      stream.leasing = false;
    });
  }
}

// THE PROCESS'S ONE ALLOCATOR. Each process — the front and every request
// worker thread — has its own module state and therefore its own instance,
// which is exactly the unit a lease belongs to.
const allocator = new SeqAllocator();

export = {
  SeqAllocator: SeqAllocator,
  next: function (name: string, local: () => number): number {
    return allocator.next(name, local);
  },
  start: function (): Promise<any> {
    return allocator.start();
  },
  status: function (): any {
    return allocator.status();
  },
  BLOCK: BLOCK,
  FALLBACK_BASE: FALLBACK_BASE
};
