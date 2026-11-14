// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: job_log.ts
//
// ---------------------------------------------------------------------------
// A SCHEDULER JOB'S BODY LOGS ONLY WHEN SOMETHING IS WRONG.
//
// A job's successful work is already the run row on /admin/scheduler. At the
// default info level, the same work was also a log line — a tally, a purge
// count, a memory report — on every tick, in every process, and an operator
// reading the container log could not see a failure in it.
// `cluster/scheduler.ts` calls `during()` around each of the three
// `job.run()` sites. For that call, and for everything it awaits, bunyan's
// `info` is written at debug.
//
// What stays at the level the caller asked for:
//
//   * a warning, an error or a fatal line — those emitters are not touched;
//   * an info line that carries an `STS-` code, which is how a recorded
//     failure is written, including `audit.js`'s refusal line (`tag()` puts
//     `[STS-…]` at the front, and a field may carry `errorCode`).
//
// `STS_LOG_LEVEL=debug` still shows the routine lines: they are rewritten,
// not dropped. A call outside `during()` is unchanged, so the same function
// logs at info on a request and at debug when the scheduler called it.
//
// A LEAF. It requires `async_hooks` and bunyan and nothing of this service,
// because the scheduler requires it and a require back would be a cycle.
// The patch is on `Logger.prototype`, so a logger created before this module
// loaded is covered, and a `child()` is too. It is idempotent.
// ---------------------------------------------------------------------------

import asyncHooks = require('async_hooks');
import bunyan = require('bunyan');

const storage = new asyncHooks.AsyncLocalStorage<boolean>();

const log = bunyan.createLogger({
  name: 'sts-job-log',
  level: process.env.STS_LOG_LEVEL || 'info'
});

interface JobLogger {
  debug: (...args: unknown[]) => unknown;
}

type JobInfo = ((this: JobLogger, ...args: unknown[]) => unknown) & {
  __stsJobLog?: boolean;
};

interface BunyanCtor {
  prototype: { info: JobInfo };
}

/**
 * Writes a scheduler job's routine info lines at debug.
 */
class JobLog {
  /**
   * Runs `body` while routine info lines are written at debug.
   *
   * A promise `body` returns keeps that context for its own awaits. This
   * returns when `body` returns, which for an async job is the promise,
   * not the settlement.
   *
   * @param body - the job's `run`
   * @returns whatever `body` returns
   */
  static during<T>(body: () => T): T {
    log.debug('Entering JobLog.during().');
    try {
      const result = storage.run(true, body);
      log.debug('Leaving JobLog.during().');
      return result;
    } catch (e) {
      log.debug('Caught in JobLog.during(): ' +
                ((e && (e as Error).message) || e));
      log.debug('Leaving JobLog.during().');
      throw e;
    }
  }

  /**
   * Patches bunyan so info inside `during()` is debug unless the line names
   * a recorded failure. Idempotent.
   */
  static install(): void {
    log.debug('Entering JobLog.install().');
    const proto = (bunyan as unknown as BunyanCtor).prototype;
    if (proto.info && proto.info.__stsJobLog) {
      log.debug('Leaving JobLog.install(). Already installed.');
      return;
    }
    const orig = proto.info;
    // No Entering/Leaving pair: jobInfo() replaces bunyan's info emitter and
    // runs on every info line in the process. A line here would recurse.
    const jobInfo = function (this: JobLogger): unknown {
      if (arguments.length === 0) {
        return orig.call(this);
      }
      if (storage.getStore() === true &&
          typeof this.debug === 'function' &&
          !JobLog.namesProblem(arguments)) {
        return this.debug.apply(this, arguments as unknown as unknown[]);
      }
      return orig.apply(this, arguments as unknown as unknown[]);
    } as JobInfo;
    jobInfo.__stsJobLog = true;
    proto.info = jobInfo;
    log.debug('Leaving JobLog.install().');
  }

  // No Entering/Leaving pair: namesProblem() runs on every info line a job
  // writes, and a debug line here would be the noise this module exists to
  // stop. One level only: a string, an Error's message, or errorCode, msg
  // or message on a fields object. A line that names none of those is
  // debug. A field the scan cannot read stays at info.
  private static namesProblem(args: IArguments): boolean {
    for (let i = 0; i < args.length; i++) {
      const value = args[i];
      if (typeof value === 'string') {
        if (value.indexOf('STS-') >= 0) {
          return true;
        }
        continue;
      }
      if (value instanceof Error) {
        if (typeof value.message === 'string' &&
            value.message.indexOf('STS-') >= 0) {
          return true;
        }
        continue;
      }
      if (!value || typeof value !== 'object') {
        continue;
      }
      try {
        const fields = value as { errorCode?: unknown; msg?: unknown;
                                  message?: unknown };
        if (JobLog.textNamesProblem(fields.errorCode) ||
            JobLog.textNamesProblem(fields.msg) ||
            JobLog.textNamesProblem(fields.message)) {
          return true;
        }
      } catch (e) {
        // A getter that throws cannot be read. The line stays at info.
        log.debug('Caught in JobLog.namesProblem(): ' +
                  ((e && (e as Error).message) || e));
        return true;
      }
    }
    return false;
  }

  // No Entering/Leaving pair: textNamesProblem() is namesProblem()'s, above.
  private static textNamesProblem(value: unknown): boolean {
    return typeof value === 'string' && value.indexOf('STS-') >= 0;
  }
}

JobLog.install();

export = JobLog;
