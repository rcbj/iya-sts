// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: sync_query.ts
//
// ---------------------------------------------------------------------------
// A SYNCHRONOUS QUESTION TO THE STORE, FROM A PROCESS WHOSE DIRECTORY API IS
// SYNCHRONOUS (#349 phase 3, 2026-09-29).
//
// rcbj's decision on #349: a request or surface worker holds the people and
// devices as a bounded window, and asks postgres for what the window does not
// hold — WITHOUT the directory API becoming asynchronous. That API is
// synchronous at about a thousand call sites (#349's design comment counted
// them), some in the Kerberos files the parent's tests image copies, and a
// postgres read is not. So a miss crosses a thread boundary and WAITS:
//
//   * a `worker_thread` (`sync_query_thread.ts`) owns a connection of its
//     own, and runs the named query from `persistence/directory_queries.js`;
//   * this side posts the question on a `MessageChannel`, then blocks on
//     `Atomics.wait()` over a shared counter the thread bumps after posting
//     its answer, and takes the answer with `receiveMessageOnPort()` — the
//     pattern the `synckit` package uses. Node allows `Atomics.wait()` on its
//     main thread; a browser does not, and this never runs in one.
//
// **WHAT IT COSTS IS THE WHOLE EVENT LOOP FOR ONE ROUND TRIP.** Nothing else
// in this process runs while it waits: about a millisecond to a database in
// the same zone, which is the price of a CPU-bound millisecond and is why
// only a MISS pays it. The wait is BOUNDED — `ldap.workerDirectoryTimeoutMs`
// — and a question that is not answered in time throws a coded error
// (`STS-LDAP-0130`), which the request it belonged to is refused with
// (rcbj: a worker whose miss finds the database down refuses; nothing is
// answered out of a window that cannot say what it is missing).
//
// **A CONSOLE REQUEST ALSO HAS A BUDGET (#359).** One question under its
// own bound still summed, across a page, to 17 s on a surface worker.
// `runWithBudget()` enters an `AsyncLocalStorage` slot; each `query()`
// waits only for the room that is left and, once the budget is spent,
// throws `STS-LDAP-0175` without posting another question. No slot means
// no budget. The API stays synchronous.
//
// **THE BUDGET IS THE REQUEST'S, AND ENDS WITH IT.** An `AsyncLocalStorage`
// store follows everything started inside it — a timer, a debounced flush,
// a scheduler job armed lazily by the first request that needed it — and is
// never cleared there. Left at that, a job armed from a console request
// carried that request's spent budget for the life of the process and every
// synchronous read it made failed as `STS-LDAP-0175` (the review of #692).
// So the slot is CLOSED when the request's response finishes or its
// connection closes, and a closed slot is no budget; and the background
// entry points that arm a timer (`cluster/scheduler.ts`'s `setTimer`,
// `persistence.js`'s flush and retry) arm it through `outsideBudget()`, so
// what they run never sees a request's slot even while that request is
// still open.
//
// **THE COUNTER, NOT A FLAG.** A flag set to 0 before each question and to 1
// by the thread loses a wake when a LATE answer to a question that already
// timed out lands between the reset and the wait. The thread adds one per
// answer; this side reads the counter BEFORE it looks for its answer and
// waits only while the counter has not moved, so a bump it did not see ends
// the wait at once rather than at the bound. Answers carry the question's id
// and a stale one is discarded.
//
// **A THREAD THAT DIES IS REPLACED ON THE NEXT QUESTION**, not from its
// `exit` event: that event is delivered by the event loop this class blocks,
// so a question in flight would never see it. A dead thread is seen as a
// timeout, and the next question starts a new one.
//
// A CLASS WHOSE DEPENDENCIES ARRIVE THROUGH ITS CONSTRUCTOR (#50): the
// connection options (the driver's `bridgeConnection()`), the bound, and —
// for `tests/sync_query.js` — the module the thread runs its questions
// through instead of the database, so the whole mechanism is exercised in process
// with no database.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import path = require('path');
import workerThreads = require('worker_threads');
import asyncHooks = require('async_hooks');
import errorCodes = require('./error_codes');

const log = bunyan.createLogger({ name: 'sts-sync-query' });

// One console request's remaining synchronous wait (#359). Module-level,
// so a question asked from any bridge in the request shares it. No store
// means no budget: startup, the scheduler, SCIM and an LDAP operation.
interface BudgetSlot {
  ms: number;
  waited: number;
  // false once the request the budget belongs to has finished or closed.
  open: boolean;
}

// What `runWithBudget()` may be handed to end the budget with: the
// request's response (an `http.ServerResponse` is one).
interface BudgetLifetime {
  once(event: string, listener: () => void): unknown;
}

const directoryBudget = new asyncHooks.AsyncLocalStorage<BudgetSlot>();

// What the constructor takes.
interface SyncQueryOptions {
  // The connection options (`knex_store.js`'s, #326): the driver's
  // `bridgeConnection()`.
  connection?: Record<string, unknown> | null;
  // The bound on one question, in milliseconds, asked per question.
  timeoutMs: () => number;
  // A module path the thread runs questions through instead of the
  // database: it exports `run(name, args)`, which answers or rejects. For
  // tests.
  backend?: string | null;
  // The thread's script; the compiled `sync_query_thread.js` beside this.
  threadFile?: string | null;
  // Named statements the thread builds instead of directory_queries.js.
  // Absent on the directory bridge, whose workerData stays what it was.
  queries?: string | null;
  // Codes for a bridge that is not the directory's. Absent, the three
  // directory sentences and STS-LDAP-0130/0131/0132 stay byte for byte.
  timeoutCode?: string | null;
  refusedCode?: string | null;
  threadErrorCode?: string | null;
}

// One answer from the thread.
interface Answer {
  id: number;
  ok: boolean;
  value?: unknown;
  error?: { message: string; code?: string };
}

// The figures `stats()` reports.
interface SyncQueryStats {
  started: number;
  questions: number;
  timedOut: number;
  failed: number;
  waitedMs: number;
  longestMs: number;
  budgetRefused: number;
}

/**
 * Asks the store a question synchronously, through a worker thread with a
 * connection of its own (#349).
 */
class SyncQuery {
  private worker: workerThreads.Worker | null = null;
  private port: workerThreads.MessagePort | null = null;
  private counter: Int32Array | null = null;
  private nextId = 1;
  // The statement_timeout the running thread was started with. A session
  // bridge replaces the thread when the configured wait changes; the
  // directory bridge keeps the thread it started.
  private startedBound: number | null = null;
  private readonly figures: SyncQueryStats = {
    started: 0, questions: 0, timedOut: 0, failed: 0, waitedMs: 0,
    longestMs: 0, budgetRefused: 0
  };

  /**
   * Keeps the options; the thread starts at the first question.
   *
   * @param options - the connection, the bound, and a test backend
   * @throws an Error when the bound is not a function
   */
  constructor(private readonly options: SyncQueryOptions) {
    log.debug("Entering SyncQuery.constructor().");
    if (!options || typeof options.timeoutMs !== 'function') {
      log.debug("Leaving SyncQuery.constructor(). Incomplete.");
      throw new Error('SyncQuery needs a timeoutMs() function.');
    }
    log.debug("Leaving SyncQuery.constructor().");
  }

  // The bound as a usable number, at most a minute. The directory bridge
  // floors anything below 10 ms, including an unusable number, at 2000,
  // which is what ldap.workerDirectoryTimeoutMs's minimum matches. A
  // session bridge honors the configured wait, including 0: that wait
  // does not block, and it is not replaced with 2000.
  private bound(): number {
    log.debug("Entering SyncQuery.bound().");
    let n = NaN;
    try {
      n = Number(this.options.timeoutMs());
    } catch (e) {
      log.debug("Caught in SyncQuery.bound(): " +
                ((e && (e as Error).message) || e));
      n = NaN;
    }
    let out = 2000;
    if (isFinite(n)) {
      const floor = this.options.timeoutCode ? 0 : 10;
      if (n >= floor) {
        out = Math.min(n, 60000);
      }
    }
    log.debug("Leaving SyncQuery.bound().");
    return out;
  }

  // STARTS THE THREAD when there is none. Unref'd both ways, so a process
  // with nothing else to do can still exit.
  private ensureThread(): void {
    log.debug("Entering SyncQuery.ensureThread().");
    const bound = this.bound();
    // A session bridge's statement_timeout is copied into the thread once.
    // When the configured wait changes, that copy would keep cancelling at
    // the old bound, so the thread is replaced. The directory bridge does
    // not: its tests change the bound on a live thread and still read the
    // late answer from it.
    if (this.worker && this.port && this.counter &&
        (!this.options.timeoutCode || this.startedBound === bound)) {
      log.debug("Leaving SyncQuery.ensureThread(). Running.");
      return;
    }
    if (this.worker) {
      const old = this.worker;
      this.forget(old);
      const gone = old.terminate();
      Promise.resolve(gone).catch(function (e: any) {
        log.debug("Caught in SyncQuery.ensureThread(): " +
                  ((e && e.message) || e));
      });
    }
    const shared = new SharedArrayBuffer(4);
    const channel = new workerThreads.MessageChannel();
    const file = this.options.threadFile ||
      path.join(__dirname, 'sync_query_thread.js');
    // `queries` is added only when this bridge names its own module. The
    // directory bridge's workerData is the four fields it has always posted.
    // statement_timeout matches this call's bound, including 0. PostgreSQL
    // treats 0 as no server cancel; the client has already returned.
    const workerData: Record<string, unknown> = {
      counter: shared, port: channel.port2,
      connection: this.options.connection
        ? Object.assign({}, this.options.connection,
                        { statement_timeout: bound })
        : null,
      backend: this.options.backend || null
    };
    if (this.options.queries) {
      workerData.queries = this.options.queries;
    }
    const worker = new workerThreads.Worker(file, {
      // THE STATEMENT TIMEOUT IS THE BOUND, so a query this side has given
      // up on does not go on running in the database.
      workerData: workerData,
      transferList: [channel.port2]
    });
    worker.unref();
    channel.port1.unref();
    worker.on('error', (err: Error) => {
      // Delivered by the event loop, so after the question it broke has
      // already timed out; the next question starts a new thread.
      const threadCode = this.options.threadErrorCode || 'STS-LDAP-0132';
      const bridgeName = this.options.threadErrorCode
        ? 'session bridge\'s' : 'directory bridge\'s';
      log.error(errorCodes.tag(threadCode) + 'sync_query: the ' +
                bridgeName + ' thread failed: ' + err.message +
                '. The next question starts a new one.');
      this.forget(worker);
    });
    worker.on('exit', (code: number) => {
      log.debug('sync_query: the bridge thread exited (' + code + ').');
      this.forget(worker);
    });
    this.worker = worker;
    this.port = channel.port1;
    this.counter = new Int32Array(shared);
    this.startedBound = bound;
    this.figures.started += 1;
    log.debug("Leaving SyncQuery.ensureThread(). Started.");
  }

  // Drops a thread that is gone, if it is still the current one.
  private forget(worker: workerThreads.Worker): void {
    log.debug("Entering SyncQuery.forget().");
    if (this.worker === worker) {
      this.worker = null;
      if (this.port) {
        this.port.close();
      }
      this.port = null;
      this.counter = null;
    }
    log.debug("Leaving SyncQuery.forget().");
  }

  /**
   * Asks a named question and waits for the answer.
   *
   * @param name - one of `persistence/directory_queries.js`'s queries (or
   *   whatever a test backend answers)
   * @param args - its arguments
   * @returns the answer
   * @throws an Error marked `STS-LDAP-0130` when no answer came within the
   *   bound, `STS-LDAP-0131` when the store refused the question, or
   *   `STS-LDAP-0175` when this request's budget is already spent
   */
  query(name: string, args: unknown[]): unknown {
    log.debug("Entering SyncQuery.query(). " + name);
    // A SESSION BRIDGE (#350) IS OUTSIDE THE DIRECTORY BUDGET. The budget
    // is a console request's wait on the DIRECTORY (#359); a session read
    // is the cookie middleware's, ahead of every page, and a spent
    // directory budget refusing it would turn a slow console page into
    // STS-LDAP-0175 on the sign-on itself. Its own bound is
    // authn.sessionWindowTimeoutMs, and it neither reads nor adds to the
    // slot.
    const held = this.options.timeoutCode
      ? undefined : directoryBudget.getStore();
    // A closed slot belongs to a request that has finished: whatever is
    // asking now was started by it and outlived it, and has no budget.
    const slot = held && held.open ? held : undefined;
    if (slot && slot.waited >= slot.ms) {
      this.figures.budgetRefused += 1;
      log.debug("Leaving SyncQuery.query(). The request's budget is spent.");
      throw errorCodes.mark(new Error(errorCodes.tag('STS-LDAP-0175') +
        'The directory could not be read: this request has already ' +
        'waited ' + slot.waited + ' ms for the store, and its budget ' +
        'is ' + slot.ms + ' ms.'), 'STS-LDAP-0175');
    }
    this.ensureThread();
    const port = this.port as workerThreads.MessagePort;
    const counter = this.counter as Int32Array;
    const id = this.nextId++;
    // THE QUESTION'S OWN BOUND, cut by whatever of the request's budget
    // is left. The cut is not raised back to 10 ms: a few milliseconds
    // of room is a few milliseconds of waiting, and the question that
    // does not finish in them is the same timeout as one that used its
    // whole bound.
    const questionBound = this.bound();
    const bound = slot
      ? Math.min(questionBound, Math.max(0, slot.ms - slot.waited))
      : questionBound;
    const started = Date.now();
    this.figures.questions += 1;
    port.postMessage({ id: id, name: String(name),
                       args: Array.isArray(args) ? args : [] });
    let answer: Answer | null = null;
    for (;;) {
      const seen = Atomics.load(counter, 0);
      answer = this.take(port, id);
      if (answer) {
        break;
      }
      const left = bound - (Date.now() - started);
      if (left <= 0) {
        break;
      }
      Atomics.wait(counter, 0, seen, left);
    }
    const waited = Date.now() - started;
    this.figures.waitedMs += waited;
    this.figures.longestMs = Math.max(this.figures.longestMs, waited);
    if (slot) {
      slot.waited += waited;
    }
    const timeoutCode = this.options.timeoutCode || 'STS-LDAP-0130';
    const refusedCode = this.options.refusedCode || 'STS-LDAP-0131';
    const kind = this.options.timeoutCode ? 'session store' : 'directory';
    if (!answer) {
      this.figures.timedOut += 1;
      log.debug("Leaving SyncQuery.query(). Timed out.");
      throw errorCodes.mark(new Error(errorCodes.tag(timeoutCode) +
        'The ' + kind + ' could not be read: the store did not answer "' +
        name + '" within ' + bound + ' ms.'), timeoutCode);
    }
    if (!answer.ok) {
      this.figures.failed += 1;
      const why = (answer.error && answer.error.message) || 'no reason given';
      log.debug("Leaving SyncQuery.query(). Refused.");
      throw errorCodes.mark(new Error(errorCodes.tag(refusedCode) +
        'The ' + kind + ' could not be read: the store refused "' + name +
        '": ' + why), refusedCode);
    }
    log.debug("Leaving SyncQuery.query().");
    return answer.value;
  }

  // Every message waiting on the port: the one for `id` is returned, a
  // stale one (a question that already timed out) is dropped.
  private take(port: workerThreads.MessagePort, id: number): Answer | null {
    log.debug("Entering SyncQuery.take().");
    for (;;) {
      const got = workerThreads.receiveMessageOnPort(port);
      if (!got) {
        log.debug("Leaving SyncQuery.take(). Nothing yet.");
        return null;
      }
      const message = got.message as Answer;
      if (message && message.id === id) {
        log.debug("Leaving SyncQuery.take().");
        return message;
      }
      log.debug('sync_query: dropped a late answer to question ' +
                (message && message.id) + '.');
    }
  }

  /**
   * Ends the thread, for a clean stop and for tests.
   *
   * @returns a promise that settles when the thread has gone
   */
  stop(): Promise<void> {
    log.debug("Entering SyncQuery.stop().");
    const worker = this.worker;
    if (!worker) {
      log.debug("Leaving SyncQuery.stop(). Nothing running.");
      return Promise.resolve();
    }
    this.forget(worker);
    log.debug("Leaving SyncQuery.stop().");
    return worker.terminate().then(function () {
      return undefined;
    });
  }

  /**
   * The bridge's figures since the process started.
   *
   * @returns started threads, questions, timeouts, failures and wait times
   */
  stats(): SyncQueryStats {
    log.debug("Entering SyncQuery.stats().");
    log.debug("Leaving SyncQuery.stats().");
    return Object.assign({}, this.figures);
  }

  /**
   * Runs `fn` with a budget on the synchronous waits `query()` does
   * inside it (#359). A non-positive or non-finite budget runs `fn`
   * with none. The wait is cumulative across every question in the
   * call, including one a timeout cut short. When `lifetime` is given
   * (the request's response), the budget ends at its `finish` or
   * `close`: anything `fn` started that is still running afterwards
   * asks with no budget.
   *
   * @param ms - the budget, in milliseconds
   * @param fn - the work
   * @param lifetime - what ends the budget, or none
   * @returns whatever `fn` returns
   */
  static runWithBudget(ms: number, fn: () => unknown,
                       lifetime?: BudgetLifetime): unknown {
    log.debug("Entering SyncQuery.runWithBudget().");
    const n = Number(ms);
    let answer: unknown;
    if (!isFinite(n) || n <= 0) {
      try {
        answer = fn();
      } catch (e) {
        // `fn` refused. The code is the caller's to map, so it propagates
        // after this function has recorded it and left out loud.
        log.debug("Caught in SyncQuery.runWithBudget(): " +
                  ((e && (e as Error).message) || e));
        log.debug("Leaving SyncQuery.runWithBudget(). No budget.");
        throw e;
      }
      log.debug("Leaving SyncQuery.runWithBudget(). No budget.");
      return answer;
    }
    const slot: BudgetSlot = { ms: n, waited: 0, open: true };
    if (lifetime && typeof lifetime.once === 'function') {
      const close = function (): void {
        slot.open = false;
      };
      lifetime.once('finish', close);
      lifetime.once('close', close);
    }
    try {
      answer = directoryBudget.run(slot, fn);
    } catch (e) {
      // The same refusal, now from a question that ran under the budget.
      log.debug("Caught in SyncQuery.runWithBudget(): " +
                ((e && (e as Error).message) || e));
      log.debug("Leaving SyncQuery.runWithBudget().");
      throw e;
    }
    log.debug("Leaving SyncQuery.runWithBudget().");
    return answer;
  }

  /**
   * Runs `fn` with no request's budget, whatever context it was called
   * from: a background entry point arms its timer through this, so the
   * work the timer runs never inherits a console request's slot.
   *
   * @param fn - the work
   * @returns whatever `fn` returns
   */
  static outsideBudget<T>(fn: () => T): T {
    log.debug("Entering SyncQuery.outsideBudget().");
    const answer = directoryBudget.exit(fn);
    log.debug("Leaving SyncQuery.outsideBudget().");
    return answer;
  }

  /**
   * Whether a budget is in force here: an open slot (for tests and for
   * a reader of the logs).
   *
   * @returns true inside a request's open budget
   */
  static budgetInForce(): boolean {
    log.debug("Entering SyncQuery.budgetInForce().");
    const held = directoryBudget.getStore();
    const inForce = Boolean(held && held.open);
    log.debug("Leaving SyncQuery.budgetInForce().");
    return inForce;
  }
}

export = SyncQuery;
