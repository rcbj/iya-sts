// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: debug_level_cost.js
// ===========================================================================
// A DISABLED DEBUG LINE COSTS ONE COMPARISON (#627), in process.
// `common/config.js` wraps bunyan's `debug` and `trace` on the shared
// prototype so that a call below the logger's level returns before bunyan
// does any work. What is held here:
//   A. BELOW THE LEVEL, BUNYAN IS NOT ENTERED: its emitter's first act is to
//      read `this._emit`, so a counting getter on a logger's `_emit` counts
//      entries into it — none for a thousand `debug` and `trace` lines at
//      info, and some for `info` (the control: the spy works). Nothing is
//      written.
//   B. AT THE LEVEL, THE LINE IS WRITTEN, with its message, as before.
//   C. A RUNTIME CHANGE TAKES EFFECT BOTH WAYS: through `logger.level()`, and
//      through `global.logLevel` for a logger registered with config.js.
//   D. `log.debug()` WITH NO ARGUMENTS still answers bunyan's boolean, at
//      both levels, for `trace` too.
//   E. CHILD LOGGERS: a child of an info logger is quiet; a child bunyan
//      gave `debug` of its own writes under an info parent.
//   F. INSTALLED ONCE: loading config.js again over the same bunyan does not
//      wrap the wrapper; the wrapped method holds bunyan's own emitter.
//   G. AN UNBOUND CALL is still bunyan's (its warning), not a TypeError.
// ===========================================================================

const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'debug_level_cost',
  level: process.env.LOG_LEVEL || 'info' });

/**
 * A logger at `level` writing raw records into `records`, with a counting
 * getter on `_emit` so entries into bunyan's emitter are visible.
 *
 * @param {string} level - the logger's level
 * @returns {{logger: any, records: any[], entries: function(): number}} it
 */
function spiedLogger(level) {
  log.debug('Entering spiedLogger().');
  const records = [];
  const logger = bunyan.createLogger({
    name: 'spied',
    level: level,
    streams: [{ type: 'raw', level: 'trace', stream: {
      write: function (rec) {
        records.push(rec);
      } } }]
  });
  // Every logger's own level is the minimum of its streams' (bunyan), so the
  // stream's `trace` would lower it; set it back.
  logger.level(level);
  let reads = 0;
  const realEmit = bunyan.prototype._emit;
  Object.defineProperty(logger, '_emit', {
    configurable: true,
    get: function () {
      reads++;
      return realEmit;
    }
  });
  log.debug('Leaving spiedLogger().');
  return {
    logger: logger,
    records: records,
    entries: function () {
      return reads;
    }
  };
}

module.exports = {
  name: 'debug level cost',
  describe: 'A debug or trace line below the logger\'s level returns before ' +
            'bunyan does any work (#627); at the level it is written; a ' +
            'runtime change takes effect both ways; log.debug() still ' +
            'answers whether the level is enabled',
  run: function (t) {
    log.debug('Entering run().');
    const config = require('../common/config');

    // A. Below the level, bunyan is not entered and nothing is written.
    const a = spiedLogger('info');
    let built = 0;
    const costly = {
      toString: function () {
        built++;
        return 'costly';
      }
    };
    for (let i = 0; i < 1000; i++) {
      a.logger.debug('Entering x(). %s', costly);
      a.logger.trace('Leaving x().', { n: i });
    }
    t.equal(a.entries(), 0,
            'A: 2000 debug/trace lines at info enter bunyan\'s emitter 0 ' +
            'times');
    t.equal(a.records.length, 0, 'A: and write nothing');
    t.equal(built, 0, 'A: and format no argument');
    a.logger.info('an info line');
    t.check(a.entries() > 0,
            'A (control): an info line does enter bunyan\'s emitter',
            String(a.entries()));
    t.equal(a.records.length, 1, 'A (control): and is written');

    // B. At the level, the line is written as before.
    const b = spiedLogger('debug');
    b.logger.debug('Entering y(). %d names.', 3);
    t.equal(b.records.length, 1, 'B: a debug line at debug is written');
    t.equal(b.records.length && b.records[0].msg, 'Entering y(). 3 names.',
            'B: with its formatted message');
    t.equal(b.records.length && b.records[0].level, bunyan.DEBUG,
            'B: at level debug');
    b.logger.trace('a trace line');
    t.equal(b.records.length, 1, 'B: a trace line at debug is not');
    b.logger.level('trace');
    b.logger.trace('a trace line');
    t.equal(b.records.length, 2, 'B: and at trace it is');

    // C. A runtime change takes effect both ways.
    const c = spiedLogger('info');
    c.logger.debug('one');
    c.logger.level('debug');
    c.logger.debug('two');
    c.logger.level('info');
    c.logger.debug('three');
    t.equal(c.records.map(function (r) {
      return r.msg;
    }).join(','), 'two',
            'C: logger.level() down to debug and back up to info');
    const before = config.value('global.logLevel');
    const r = spiedLogger(before);
    config.registerLogger(r.logger);
    try {
      config.setOverride('global.logLevel', 'debug');
      r.logger.debug('through the setting');
      t.equal(r.records.filter(function (x) {
        return x.msg === 'through the setting';
      }).length, 1, 'C: global.logLevel=debug at runtime writes the line');
      config.setOverride('global.logLevel', 'info');
      const n = r.entries();
      r.logger.debug('after the setting');
      t.equal(r.entries() - n, 0,
              'C: global.logLevel=info at runtime quiets it again, before ' +
              'bunyan');
    } finally {
      config.clearOverride('global.logLevel');
    }

    // D. No arguments: bunyan's boolean.
    const d = spiedLogger('info');
    t.equal(d.logger.debug(), false, 'D: debug() at info is false');
    t.equal(d.logger.trace(), false, 'D: trace() at info is false');
    t.equal(d.logger.info(), true, 'D: info() at info is true');
    d.logger.level('debug');
    t.equal(d.logger.debug(), true, 'D: debug() at debug is true');
    t.equal(d.logger.trace(), false, 'D: trace() at debug is false');
    d.logger.level('trace');
    t.equal(d.logger.trace(), true, 'D: trace() at trace is true');
    t.equal(d.records.length, 0, 'D: and none of them writes a line');

    // E. Child loggers.
    const e = spiedLogger('info');
    const child = e.logger.child({ part: 'child' });
    child.debug('quiet child');
    const loud = e.logger.child({ part: 'loud', level: 'debug' });
    loud.debug('loud child');
    t.equal(e.records.map(function (x) {
      return x.msg;
    }).join(','), 'loud child',
            'E: an info child is quiet, a debug child of an info parent ' +
            'writes');

    // F. Installed once, over bunyan's own emitter.
    const wrapped = bunyan.prototype.debug;
    t.check(wrapped.quietBelowLevel === true,
            'F: bunyan.prototype.debug is the wrapper');
    t.check(typeof wrapped.bunyanEmitter === 'function' &&
            wrapped.bunyanEmitter.quietBelowLevel !== true,
            'F: and it wraps bunyan\'s own emitter, not another wrapper');
    const configPath = require.resolve('../common/config');
    const cached = require.cache[configPath];
    delete require.cache[configPath];
    try {
      require('../common/config');
    } finally {
      require.cache[configPath] = cached;
    }
    const trace = bunyan.prototype.trace;
    t.check(bunyan.prototype.debug === wrapped &&
            trace.quietBelowLevel === true &&
            typeof trace.bunyanEmitter === 'function' &&
            trace.bunyanEmitter.quietBelowLevel !== true,
            'F: loading config.js again leaves the one wrapper in place');

    // G. An unbound call is bunyan's business.
    const g = spiedLogger('info');
    const unbound = g.logger.debug;
    let threw = null;
    try {
      unbound('unbound');
    } catch (err) {
      log.debug('Caught in run(): ' + ((err && err.message) || err));
      threw = err;
    }
    t.equal(threw, null, 'G: an unbound debug call does not throw');
    log.debug('Leaving run().');
  }
};
