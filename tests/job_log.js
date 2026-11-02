// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: job_log.js
//
// ===========================================================================
// A SCHEDULER JOB'S BODY LOGS ONLY WHEN SOMETHING IS WRONG.
//
// `common/job_log.ts` rewrites bunyan's `info` to `debug` for the call to
// `job.run()` and for everything that call awaits. Held here, with a real
// bunyan logger (the scheduler kit's log is not one):
//
//   A. outside `during()`, an info line is info;
//   B. inside it, a routine info line is absent at the info level and
//      present at debug, including after an await, a timer and `child()`;
//   C. an info line that names an `STS-` code stays at info: a string, an
//      `errorCodes.tag()`, a fields object's `errorCode`, and an Error;
//   D. a nested `err` is one level down and is rewritten; a field the scan
//      cannot read stays at info;
//   E. `log.info()` with no arguments still answers whether info is enabled;
//   F. a warning and an error stay where they were asked;
//   G. a body that throws is rethrown;
//   H. the three `job.run()` sites — inline, delegated and per-process —
//      each do this, and a service-scoped job runs in the default realm.
// ===========================================================================

delete process.env.CONFIG_FILE;

const bunyan = require('bunyan');
const JobLog = require('../common/job_log');
const errorCodes = require('../common/error_codes');
const kit = require('./scheduler_kit');

const log = bunyan.createLogger({ name: 'job_log',
  level: process.env.LOG_LEVEL || 'info' });

const INFO = 30;
const DEBUG = 20;
const WARN = 40;
const ERROR = 50;

/**
 * A bunyan logger at `level` whose raw records this test can read.
 *
 * @param {string} level - the logger's level
 * @returns {{ logger: any, records: any[] }} it
 */
function captured(level) {
  log.debug('Entering captured().');
  const records = [];
  const logger = bunyan.createLogger({
    name: 'job-body',
    streams: [{ type: 'raw', level: 'trace', stream: {
      write: function (rec) {
        records.push(rec);
      } } }]
  });
  // A stream at trace would lower the logger; set the level back.
  logger.level(level);
  log.debug('Leaving captured().');
  return { logger: logger, records: records };
}

/**
 * The messages recorded at `level`, or at every level when `level` is null.
 *
 * @param {any[]} records - raw bunyan records
 * @param {number|null} level - a bunyan level, or null
 * @returns {string[]} the messages
 */
function messages(records, level) {
  log.debug('Entering messages().');
  const out = records.filter(function (rec) {
    return level === null || rec.level === level;
  }).map(function (rec) {
    return String(rec.msg);
  });
  log.debug('Leaving messages().');
  return out;
}

/**
 * True when `records` holds `text` at `level`.
 *
 * @param {any[]} records - raw bunyan records
 * @param {number} level - a bunyan level
 * @param {string} text - the message
 * @returns {boolean} whether it was recorded there
 */
function has(records, level, text) {
  log.debug('Entering has().');
  const found = messages(records, level).indexOf(text) >= 0;
  log.debug('Leaving has().');
  return found;
}

/**
 * The three scheduler sites, each with its own pair of loggers.
 *
 * @param {object} t - the harness
 * @returns {Promise<void>} when the runs have been checked
 */
async function schedulerSites(t) {
  log.debug('Entering schedulerSites().');
  const w = kit.world({ clustered: false });
  const node = w.node('front');
  const realmsSeen = [];

  function jobRun(label, bag) {
    log.debug('Entering jobRun().');
    log.debug('Leaving jobRun().');
    return async function (ctx) {
      realmsSeen.push(label + ':' + ctx.realm);
      bag.info.logger.info(label + ' routine');
      await Promise.resolve();
      bag.info.logger.info(label + ' after await');
      bag.debug.logger.info(label + ' routine');
      bag.info.logger.info(errorCodes.tag('STS-SCHED-0017') + label);
      bag.info.logger.warn(label + ' warning');
      return { ok: true };
    };
  }

  function spec(id, kind, bag, off) {
    log.debug('Entering spec().');
    const job = {
      id: id, title: 'A job-log test', describe: 'For the test.',
      owner: 'tests/job_log.js', kind: kind,
      everyMs: function () { return 60000; },
      run: jobRun(id, bag)
    };
    if (off) {
      job.off = function () { return 'called directly'; };
    }
    log.debug('Leaving spec().');
    return job;
  }

  const per = { info: captured('info'), debug: captured('debug') };
  const inline = { info: captured('info'), debug: captured('debug') };
  const delegated = { info: captured('info'), debug: captured('debug') };
  node.scheduler.register(spec('test.joblog.process', 'per-process', per));
  node.scheduler.register(spec('test.joblog.inline', 'cluster', inline));
  node.scheduler.register(spec('test.joblog.delegated', 'cluster',
                               delegated, true));
  node.scheduler.register({
    id: 'test.joblog.fails', title: 'A job-log test',
    describe: 'For the test.', owner: 'tests/job_log.js',
    kind: 'cluster',
    everyMs: function () { return 60000; },
    run: function failRun() {
      log.debug('Entering failRun().');
      const error = new Error('job failed');
      log.debug('Leaving failRun().');
      throw error;
    }
  });
  const answer = await node.scheduler.runDelegated({
    jobId: 'test.joblog.delegated', realm: 'default',
    runId: 'run-delegated', trigger: 'schedule', params: null,
    clockOffsetMs: 0
  });
  t.check(answer && answer.ok === true,
          'a delegated run answers ok', JSON.stringify(answer));
  node.scheduler.start('front');
  await w.advance(3 * 60000);

  function quiet(bag, label) {
    log.debug('Entering quiet().');
    t.check(!has(bag.info.records, INFO, label + ' routine') &&
            !has(bag.info.records, INFO, label + ' after await'),
            label + ': a routine info line is not written at info',
            JSON.stringify(messages(bag.info.records, null)));
    t.check(has(bag.debug.records, DEBUG, label + ' routine') &&
            !has(bag.debug.records, INFO, label + ' routine'),
            label + ': the same line is a debug record',
            JSON.stringify(messages(bag.debug.records, null)));
    t.check(bag.info.records.some(function (rec) {
      return rec.level === INFO &&
             String(rec.msg).indexOf('[STS-SCHED-0017]') >= 0 &&
             String(rec.msg).indexOf(label) >= 0;
    }), label + ': an STS- line stays at info',
    JSON.stringify(messages(bag.info.records, INFO)));
    t.check(has(bag.info.records, WARN, label + ' warning'),
            label + ': a warning stays a warning',
            JSON.stringify(messages(bag.info.records, null)));
    log.debug('Leaving quiet().');
  }
  quiet(per, 'test.joblog.process');
  quiet(inline, 'test.joblog.inline');
  quiet(delegated, 'test.joblog.delegated');
  t.check(realmsSeen.length >= 3 && realmsSeen.every(function (one) {
    return one.endsWith(':default');
  }), 'a service-scoped job runs in the default realm',
  JSON.stringify(realmsSeen));
  const runs = w.audits.filter(function (row) {
    return row.action === 'scheduler.run';
  });
  t.check(!runs.some(function (row) {
    return row.outcome === 'success' ||
           String(row.summary || '').indexOf('succeeded') >= 0;
  }), 'a successful run writes no audit row',
  JSON.stringify(runs.map(function (row) { return row.summary; })));
  t.check(runs.some(function (row) {
    return row.outcome === 'failure' && row.errorCode === 'STS-SCHED-0001';
  }), 'a failed run is still an audit row', JSON.stringify(runs));
  log.debug('Leaving schedulerSites().');
}

module.exports = {
  name: 'job_log',
  describe: 'A scheduler job writes routine info at debug, and keeps a ' +
            'warning, an error and an info line that carries an STS- code',
  run: async function (t) {
    log.debug('Entering run().');

    // A. Outside during(), info is info.
    const outside = captured('info');
    outside.logger.info('outside');
    t.check(has(outside.records, INFO, 'outside'),
            'outside a job, an info line is info',
            JSON.stringify(messages(outside.records, null)));

    // B, C, D, E, F. Inside during().
    const quiet = captured('info');
    const shown = captured('debug');
    const boom = {};
    let reads = 0;
    Object.defineProperty(boom, 'errorCode', {
      enumerable: true,
      get: function () {
        reads += 1;
        if (reads === 1) {
          throw new Error('unreadable');
        }
        return 'ok';
      }
    });
    let probe = null;
    await JobLog.during(async function () {
      probe = quiet.logger.info();
      quiet.logger.info('routine');
      shown.logger.info('routine');
      await Promise.resolve();
      quiet.logger.info('after await');
      shown.logger.info('after await');
      await new Promise(function (resolve) {
        setTimeout(function () {
          quiet.logger.info('after timer');
          shown.logger.info('after timer');
          resolve();
        }, 20);
      });
      quiet.logger.child({ component: 'c' }).info('child routine');
      shown.logger.child({ component: 'c' }).info('child routine');
      quiet.logger.info('failed STS-SCHED-0017');
      quiet.logger.info(errorCodes.tag('STS-SCHED-0017') + 'tagged');
      quiet.logger.info({ errorCode: 'STS-SCHED-0017' }, 'fields');
      quiet.logger.info(new Error('boom STS-SCHED-0017'), 'as error');
      quiet.logger.info({ err: new Error('nested STS-SCHED-0017') },
                         'nested');
      shown.logger.info({ err: new Error('nested STS-SCHED-0017') },
                         'nested');
      quiet.logger.info(boom, 'getter stayed');
      quiet.logger.warn('a warning');
      quiet.logger.error('an error');
    });
    t.check(probe === true && quiet.logger.debug() === false,
            'log.info() with no arguments stays enabled at info',
            String(probe));
    ['routine', 'after await', 'after timer', 'child routine',
     'nested'].forEach(function (text) {
      t.check(!has(quiet.records, INFO, text),
              'inside a job, "' + text + '" is not an info line',
              JSON.stringify(messages(quiet.records, null)));
      t.check(has(shown.records, DEBUG, text) &&
              !has(shown.records, INFO, text),
              'inside a job, "' + text + '" is a debug record',
              JSON.stringify(messages(shown.records, null)));
    });
    t.check(has(quiet.records, INFO, 'failed STS-SCHED-0017') &&
            has(quiet.records, INFO, '[STS-SCHED-0017] tagged') &&
            has(quiet.records, INFO, 'fields') &&
            has(quiet.records, INFO, 'as error') &&
            has(quiet.records, INFO, 'getter stayed'),
            'an info line that names STS-, and one whose field cannot be ' +
            'read, stays at info',
            JSON.stringify(messages(quiet.records, INFO)));
    t.check(has(quiet.records, WARN, 'a warning') &&
            has(quiet.records, ERROR, 'an error'),
            'a warning and an error stay where they were asked',
            JSON.stringify(messages(quiet.records, null)));
    quiet.logger.info('after the job');
    t.check(has(quiet.records, INFO, 'after the job'),
            'after the job, info is info again',
            JSON.stringify(messages(quiet.records, INFO)));

    // G. A thrown body is rethrown.
    let thrown = '';
    try {
      JobLog.during(function () {
        throw new Error('job blew up');
      });
    } catch (e) {
      // The body failed. during() records it at debug and rethrows it.
      log.debug('Caught in run(): ' + ((e && e.message) || e));
      thrown = (e && e.message) || '';
    }
    t.check(thrown === 'job blew up',
            'a body that throws is rethrown', thrown);

    // H. The three run() sites, and the audit row a success used to be.
    await schedulerSites(t);

    // I. The job's own successful call is not an audit event. A failure is.
    const audit = require('../common/audit');
    const before = audit.localEvents().length;
    const quietReq = { method: 'POST', originalUrl: '/ssf/poll',
                        headers: {}, query: {} };
    const quietWrote = audit.recordHttp(quietReq,
      { statusCode: 200, locals: { auditQuietWhenOk: true } },
      { matched: true });
    t.check(quietWrote === null && audit.localEvents().length === before,
            'a scheduler job\'s own successful call is not an audit event');
    const failed = audit.recordHttp(quietReq,
      { statusCode: 500, locals: { auditQuietWhenOk: true } },
      { matched: true });
    t.check(!!failed && failed.outcome === 'error',
            'a failed call from that job is still recorded',
            JSON.stringify(failed));
    log.debug('Leaving run().');
  }
};
