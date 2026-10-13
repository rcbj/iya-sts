// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: fault_boundary.ts
//
// ---------------------------------------------------------------------------
// AN UNEXPECTED ERROR IS WRITTEN DOWN AND CONTAINED, AND NO PROCESS EXITS
// OVER ONE (2026-09-29).
//
// rcbj: "it severely impacts availability of the cluster for a worker or
// leader node.js process to exit. It needs to recover gracefully." Until
// this file, nothing in the service listened for `uncaughtException` or
// `unhandledRejection`, so on node 22 and 24 ONE of either — a bug in a
// timer callback, an `'error'` event nobody listened for, a promise chain
// with no `.catch()`, an `async` Express handler that threw — ended the
// process that met it: the front process (and with it the scheduler's
// leadership, every listener and every open connection) or a request
// worker. The cluster recovered, eventually; the requests
// in flight did not.
//
// So there are two boundaries here, and they are the only places an error
// can escape every `try` this service has:
//
//   * **THE PROCESS.** `installProcessHandlers()` listens for both events,
//     logs what arrived — with its STACK, because an error nobody caught is
//     by definition one nobody wrote a sentence for — and lets the process
//     carry on. It is installed only once the process has STARTED (the
//     front process in `announce()`, a request worker once its state is
//     up — a worker thread's `process` events are its own, #364): a
//     failure while starting is still fatal, exactly as it was, because a process that
//     could not come up must not present itself as one that did. Node's
//     documentation warns that carrying on after `uncaughtException` can
//     leave a module half-updated; the owner's decision is that a node
//     answering is worth more than that risk, and the record in the log is
//     what makes the risk visible.
//
//   * **EXPRESS 4.** Express catches a handler that THROWS and routes it to
//     `next(err)`, but a handler that returns a REJECTED promise — every
//     `async` handler that fails — is invisible to it, and became the
//     process-level rejection above. `guardExpress()` extends Express's own
//     `try` to the promise: the rejection is logged and handed to `next()`
//     as a plain 500, the same road a thrown error has always taken. It
//     does nothing when the handler has already answered or already called
//     `next()` — calling `next()` a second time would run the rest of the
//     chain twice — and only logs.
//
// **WHAT DOES NOT CHANGE.** No error that is caught today is caught
// differently: every existing `catch`, its log line and its code stay as
// they are, and an error Express already handled still reaches the same
// handler. What changes is only what used to be a CRASH.
//
// **ONE LINE PER DISTINCT FAULT, NOT ONE PER OCCURRENCE.** A fault in a
// request path repeats on every request, and a log line per occurrence is
// the flood rcbj has refused before (SSF, 2026-09-14). The first three
// occurrences of each fault (its name, message and first frame) are logged
// in full, then the 10th, 100th, 1000th… with the running count — so
// nothing is silent, and nothing drowns the log. No timer summarises the
// rest: a repeating timer is a scheduler job (#49), and a count carried on
// the next line needs none.
//
// A LIBRARY (rule 3): it registers no route and requires only the
// error-code table, a leaf; its logger is handed in, as `lazy_module.ts`'s
// is, so a process with a logger of its own can use it without the stack.
// ---------------------------------------------------------------------------

import errorCodes = require('./error_codes');

interface FaultLog {
  debug(message: string): void;
  error(message: string): void;
}

// Distinct faults remembered for the throttle. A bound, not a cache: past
// it the oldest is forgotten, and a forgotten fault that recurs is simply
// logged in full again.
const MAX_SIGNATURES = 500;
const FULL_LINES = 3;

/**
 * Where unexpected errors are contained: the process handlers and the
 * Express guard.
 *
 * A static utility class; its state is the throttle and the counts.
 */
class FaultBoundary {
  private static seen: Map<string, number> = new Map();
  private static installed: boolean = false;
  private static guarded: boolean = false;
  private static lastUnlogged: string = '';
  private static totals: { [kind: string]: number } = {
    uncaughtException: 0, unhandledRejection: 0, expressHandler: 0
  };

  /**
   * Listens for `uncaughtException` and `unhandledRejection` on this
   * process, logs each (throttled) and lets the process carry on. Call it
   * once the process has started; a second call does nothing.
   *
   * @param role - what this process is, for the log line ("front process",
   *   "request worker")
   * @param log - the process's logger
   * @returns whether this call installed them
   */
  static installProcessHandlers(role: string, log: FaultLog): boolean {
    log.debug("Entering FaultBoundary.installProcessHandlers(). " + role);
    if (FaultBoundary.installed) {
      log.debug("Leaving FaultBoundary.installProcessHandlers(). Already.");
      return false;
    }
    FaultBoundary.installed = true;
    process.on('uncaughtException', function (err: unknown, origin: string) {
      FaultBoundary.contain('uncaughtException', 'STS-CORE-0141', err,
                            role + ' ' + process.pid + ' (' +
                            (origin || 'uncaughtException') + ')', log);
    });
    process.on('unhandledRejection', function (reason: unknown) {
      FaultBoundary.contain('unhandledRejection', 'STS-CORE-0142', reason,
                            role + ' ' + process.pid, log);
    });
    log.debug("Leaving FaultBoundary.installProcessHandlers(). Installed.");
    return true;
  }

  /**
   * Extends Express 4's own `try` around a handler to the promise the
   * handler returns, so that a rejected `async` handler reaches `next()`
   * as a 500 rather than becoming an unhandled rejection. Patches the one
   * prototype every router's layers share, so it covers every express app
   * in the process; a second call does nothing.
   *
   * @param log - the logger for the faults it contains
   * @returns whether the guard is in place
   */
  static guardExpress(log: FaultLog): boolean {
    log.debug("Entering FaultBoundary.guardExpress().");
    if (FaultBoundary.guarded) {
      log.debug("Leaving FaultBoundary.guardExpress(). Already.");
      return true;
    }
    let Layer: any = null;
    try {
      // Express's internal module, required by path because it is the one
      // place both handler kinds are called. express 4 has no `exports`
      // map, so the path resolves; the shape is checked below rather than
      // trusted, since a major version would move it.
      Layer = require('express/lib/router/layer');
    } catch (e) {
      log.debug("Caught in FaultBoundary.guardExpress(): " +
                ((e && e.message) || e));
      Layer = null;
    }
    const proto = Layer && Layer.prototype;
    if (!proto || typeof proto.handle_request !== 'function' ||
        typeof proto.handle_error !== 'function') {
      log.error(errorCodes.tag('STS-CORE-0144') + 'fault_boundary: ' +
                'express/lib/router/layer is not the shape this guard ' +
                'knows, so a rejected async handler is NOT contained and ' +
                'reaches the process handlers instead.');
      log.debug("Leaving FaultBoundary.guardExpress(). Unknown shape.");
      return false;
    }
    // Express 4.22's two methods, with the returned promise observed. Called
    // for every layer a request passes through, so no Entering/Leaving
    // pair — the hot-path exception the code style allows, stated here as
    // it requires.
    proto.handle_request = function handle(req: any, res: any, next: any) {
      const fn = this.handle;
      if (fn.length > 3) {
        return next();
      }
      const watched = FaultBoundary.watchNext(next);
      let result: any;
      try {
        result = fn(req, res, watched.next);
      } catch (err) {
        next(err);
        return undefined;
      }
      FaultBoundary.observe(result, req, res, next, watched, log);
      return undefined;
    };
    proto.handle_error = function handle_error(error: any, req: any,
                                               res: any, next: any) {
      const fn = this.handle;
      if (fn.length !== 4) {
        return next(error);
      }
      const watched = FaultBoundary.watchNext(next);
      let result: any;
      try {
        result = fn(error, req, res, watched.next);
      } catch (err) {
        next(err);
        return undefined;
      }
      FaultBoundary.observe(result, req, res, next, watched, log);
      return undefined;
    };
    FaultBoundary.guarded = true;
    log.debug("Leaving FaultBoundary.guardExpress(). Guarded.");
    return true;
  }

  /**
   * How many faults of each kind this process has contained.
   *
   * @returns a copy of the counts, and the last reason a fault could
   *   not be logged
   */
  static figures(): { [kind: string]: number | string } {
    return Object.assign({ lastUnlogged: FaultBoundary.lastUnlogged },
                         FaultBoundary.totals);
  }

  // A `next` that remembers it was called, so that a rejection arriving
  // after the handler moved on is logged rather than routed a second time.
  // Per layer per request: the hot-path exception, as above.
  private static watchNext(next: any): { next: any, called: boolean } {
    const watched = { next: null as any, called: false };
    watched.next = function (this: any) {
      watched.called = true;
      return next.apply(this, arguments);
    };
    return watched;
  }

  // What a handler returned: nothing to do unless it is a promise, and then
  // only if it rejects. Per layer per request: the hot-path exception.
  private static observe(result: any, req: any, res: any, next: any,
                         watched: { called: boolean },
                         log: FaultLog): void {
    if (!result || typeof result.then !== 'function') {
      return;
    }
    result.then(undefined, function (err: unknown) {
      const where = 'an Express handler for ' + String(req && req.method) +
        ' ' + String(req && (req.originalUrl || req.url) || '')
        .split('?')[0];
      FaultBoundary.contain('expressHandler', 'STS-CORE-0143', err,
                            where, log);
      if (watched.called || (res && res.headersSent)) {
        return;
      }
      // A PLAIN 500 AND NOT THE ERROR: Express's final handler writes an
      // error's stack into the page outside NODE_ENV=production, and what
      // failed is the operator's to read in the log above, not a caller's.
      const plain: any = new Error('Internal Server Error');
      plain.stack = plain.message;
      plain.status = 500;
      next(plain);
    });
  }

  // THE ONE PLACE A CONTAINED FAULT IS WRITTEN DOWN, and it may not throw:
  // it runs inside the process's last handler, where a throw would be the
  // crash this file exists to prevent. Its own failure goes to stderr.
  private static contain(kind: string, code: string, err: unknown,
                         where: string, log: FaultLog): void {
    try {
      log.debug("Entering FaultBoundary.contain(). " + kind);
      FaultBoundary.totals[kind] = (FaultBoundary.totals[kind] || 0) + 1;
      const e: any = err;
      const name = (e && e.name) || typeof err;
      const message = String((e && e.message) || err);
      const stack = String((e && e.stack) || message);
      const frame = (stack.split('\n')[1] || '').trim();
      const signature = kind + '|' + name + '|' +
        message.slice(0, 200) + '|' + frame;
      const count = (FaultBoundary.seen.get(signature) || 0) + 1;
      FaultBoundary.seen.delete(signature);
      FaultBoundary.seen.set(signature, count);
      if (FaultBoundary.seen.size > MAX_SIGNATURES) {
        FaultBoundary.seen.delete(FaultBoundary.seen.keys().next().value as
                                  string);
      }
      if (count > FULL_LINES && !FaultBoundary.isPowerOfTen(count)) {
        log.debug("Leaving FaultBoundary.contain(). Throttled: " + count);
        return;
      }
      // error-code: none — `code` is the caller's STS-CORE-0141/0142/0143
      log.error(errorCodes.tag(code) + 'fault_boundary: an unexpected ' +
                'error (' + kind + ') reached ' + where + ' and was ' +
                'contained; the process carries on. Seen ' + count +
                ' time(s)' + (count > FULL_LINES ? ' — logged at 1, 2, 3 ' +
                'and each power of ten' : '') + '. ' + stack);
      log.debug("Leaving FaultBoundary.contain(). Logged.");
    } catch (e) {
      try {
        process.stderr.write('fault_boundary: could not log a contained ' +
                             'fault: ' + ((e && e.message) || e) + '\n');
      } catch (e2) {
        // stderr itself is gone; there is nowhere left to write to, and
        // throwing here would end the process this file keeps alive. It is
        // counted, and the last reason kept, for figures().
        FaultBoundary.totals.unlogged =
          (FaultBoundary.totals.unlogged || 0) + 1;
        FaultBoundary.lastUnlogged = String((e2 && e2.message) || e2);
      }
    }
  }

  // Only reached while a fault is being contained, and only past its third
  // occurrence: called from contain(), whose own pair brackets it, so no
  // Entering/Leaving pair of its own — a one-expression helper.
  private static isPowerOfTen(n: number): boolean {
    let v = n;
    while (v >= 10 && v % 10 === 0) {
      v = v / 10;
    }
    return v === 1;
  }
}

/**
 * The fault boundary: process handlers and the Express guard.
 * @namespace
 */
export = FaultBoundary;
