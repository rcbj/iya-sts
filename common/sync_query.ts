// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

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
// them), some in the parent project's locked Kerberos files, and a postgres
// read is not. So a miss crosses a thread boundary and WAITS:
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
// through instead of `pg`, so the whole mechanism is exercised in process
// with no database.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import path = require('path');
import workerThreads = require('worker_threads');
import errorCodes = require('./error_codes');

const log = bunyan.createLogger({ name: 'sts-sync-query' });

// What the constructor takes.
interface SyncQueryOptions {
  // `pg` client options: the driver's `bridgeConnection()`.
  connection?: Record<string, unknown> | null;
  // The bound on one question, in milliseconds, asked per question.
  timeoutMs: () => number;
  // A module path the thread runs questions through instead of `pg`: it
  // exports `run(name, args)`, which answers or rejects. For tests.
  backend?: string | null;
  // The thread's script; the compiled `sync_query_thread.js` beside this.
  threadFile?: string | null;
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
  private readonly figures: SyncQueryStats = {
    started: 0, questions: 0, timedOut: 0, failed: 0, waitedMs: 0,
    longestMs: 0
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

  // The bound as a usable number: at least 10 ms, at most a minute.
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
    log.debug("Leaving SyncQuery.bound().");
    return isFinite(n) && n >= 10 ? Math.min(n, 60000) : 2000;
  }

  // STARTS THE THREAD when there is none. Unref'd both ways, so a process
  // with nothing else to do can still exit.
  private ensureThread(): void {
    log.debug("Entering SyncQuery.ensureThread().");
    if (this.worker && this.port && this.counter) {
      log.debug("Leaving SyncQuery.ensureThread(). Running.");
      return;
    }
    const shared = new SharedArrayBuffer(4);
    const channel = new workerThreads.MessageChannel();
    const file = this.options.threadFile ||
      path.join(__dirname, 'sync_query_thread.js');
    const worker = new workerThreads.Worker(file, {
      // THE STATEMENT TIMEOUT IS THE BOUND, so a query this side has given
      // up on does not go on running in the database.
      workerData: { counter: shared, port: channel.port2,
                    connection: this.options.connection
                      ? Object.assign({}, this.options.connection,
                                      { statement_timeout: this.bound() })
                      : null,
                    backend: this.options.backend || null },
      transferList: [channel.port2]
    });
    worker.unref();
    channel.port1.unref();
    worker.on('error', (err: Error) => {
      // Delivered by the event loop, so after the question it broke has
      // already timed out; the next question starts a new thread.
      log.error(errorCodes.tag('STS-LDAP-0132') + 'sync_query: the ' +
                'directory bridge\'s thread failed: ' + err.message +
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
   *   bound, or `STS-LDAP-0131` when the store refused the question
   */
  query(name: string, args: unknown[]): unknown {
    log.debug("Entering SyncQuery.query(). " + name);
    this.ensureThread();
    const port = this.port as workerThreads.MessagePort;
    const counter = this.counter as Int32Array;
    const id = this.nextId++;
    const bound = this.bound();
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
    if (!answer) {
      this.figures.timedOut += 1;
      log.debug("Leaving SyncQuery.query(). Timed out.");
      throw errorCodes.mark(new Error(errorCodes.tag('STS-LDAP-0130') +
        'The directory could not be read: the store did not answer "' +
        name + '" within ' + bound + ' ms.'), 'STS-LDAP-0130');
    }
    if (!answer.ok) {
      this.figures.failed += 1;
      const why = (answer.error && answer.error.message) || 'no reason given';
      log.debug("Leaving SyncQuery.query(). Refused.");
      throw errorCodes.mark(new Error(errorCodes.tag('STS-LDAP-0131') +
        'The directory could not be read: the store refused "' + name +
        '": ' + why), 'STS-LDAP-0131');
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
}

export = SyncQuery;
