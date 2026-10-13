// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: fault_boundary.js
//
// ---------------------------------------------------------------------------
// AN UNEXPECTED ERROR IS LOGGED AND CONTAINED, AND NOTHING ELSE CHANGES
// (#355).
//
// `common/fault_boundary.ts` has two halves, and each is held here to what it
// promises and to what it promises NOT to do:
//
//   * THE EXPRESS GUARD: a rejected `async` handler is answered with a plain
//     500 whose body names nothing of the error; a handler that already
//     answered keeps its answer; a handler that called `next()` and then
//     rejected does not run the chain a second time; a thrown error still
//     takes Express's own road; a 4-argument error handler is guarded too.
//   * THE PROCESS HANDLERS: before they are installed an uncaught exception
//     still ends the process (a startup failure stays fatal); after, an
//     uncaught exception and an unhandled rejection are logged under
//     STS-CORE-0141 / 0142 and the process carries on; and a fault that
//     repeats is logged at 1, 2, 3, 10 — not fifteen times.
//
// **EVERY SCENARIO RUNS IN A CHILD PROCESS** — this file, forked with
// `--child <scenario>` — because both halves change PROCESS-WIDE state (a
// prototype every express app shares, and `process.on()` listeners), and
// `run.js` runs every in-process test in one process.
// ---------------------------------------------------------------------------

const childProcess = require('child_process');
const http = require('http');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'fault_boundary',
  level: process.env.LOG_LEVEL || 'info' });

// A logger of the shape fault_boundary.ts takes, keeping every error line so
// the child can report them.
function capturingLog(lines) {
  log.debug("Entering capturingLog().");
  log.debug("Leaving capturingLog().");
  return {
    debug: function () {
      return undefined;
    },
    error: function (message) {
      lines.push(String(message));
    }
  };
}

// One GET against the child's own server, answered as { status, body }.
function get(port, path) {
  log.debug("Entering get(). " + path);
  return new Promise(function (resolve, reject) {
    http.get({ host: '127.0.0.1', port: port, path: path }, function (res) {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', function (chunk) {
        body += chunk;
      });
      res.on('end', function () {
        resolve({ status: res.statusCode, body: body });
      });
    }).on('error', function (e) {
      log.debug("Caught in get(): " + ((e && e.message) || e));
      reject(e);
    });
    log.debug("Leaving get().");
  });
}

function wait(ms) {
  log.debug("Entering wait().");
  log.debug("Leaving wait().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

// THE CHILD'S HALF: the express scenario.
async function childExpress() {
  log.debug("Entering childExpress().");
  const express = require('express');
  const faultBoundary = require('../common/fault_boundary');
  const lines = [];
  const guarded = faultBoundary.guardExpress(capturingLog(lines));
  const app = express();
  let secondRuns = 0;
  app.get('/rejects', async function () {
    throw new Error('the secret detail');
  });
  app.get('/answered-then-rejects', async function (req, res) {
    res.send('kept');
    throw new Error('after the answer');
  });
  app.get('/next-then-rejects', async function (req, res, next) {
    next();
    await Promise.resolve();
    throw new Error('after next');
  });
  app.get('/next-then-rejects', function (req, res) {
    secondRuns += 1;
    res.send('second');
  });
  app.get('/throws', function () {
    throw new Error('thrown the old way');
  });
  app.get('/to-error-handler', function (req, res, next) {
    next(new Error('first'));
  });
  app.use(async function (err, req, res, next) {
    if (err && err.message === 'first') {
      throw new Error('the error handler failed');
    }
    next(err);
  });
  const server = await new Promise(function (resolve) {
    const s = app.listen(0, '127.0.0.1', function () {
      resolve(s);
    });
  });
  const port = server.address().port;
  const results = {
    guarded: guarded,
    rejects: await get(port, '/rejects'),
    answered: await get(port, '/answered-then-rejects'),
    nextThen: await get(port, '/next-then-rejects'),
    throws: await get(port, '/throws'),
    errorHandler: await get(port, '/to-error-handler')
  };
  await wait(50);
  results.secondRuns = secondRuns;
  results.lines = lines;
  results.figures = faultBoundary.figures();
  server.close();
  log.debug("Leaving childExpress().");
  return results;
}

// THE CHILD'S HALF: the process scenario. Each fault is raised from a timer
// or a bare rejected promise — places no `try` of the caller's reaches.
async function childProcessHandlers() {
  log.debug("Entering childProcessHandlers().");
  const faultBoundary = require('../common/fault_boundary');
  const lines = [];
  const first = faultBoundary.installProcessHandlers('test child',
                                                     capturingLog(lines));
  const second = faultBoundary.installProcessHandlers('test child',
                                                      capturingLog(lines));
  setTimeout(function () {
    throw new Error('from a timer');
  }, 0);
  Promise.reject(new Error('nobody handled this'));
  for (let i = 0; i < 15; i++) {
    setImmediate(function repeated() {
      throw new Error('the same fault');
    });
  }
  await wait(200);
  log.debug("Leaving childProcessHandlers().");
  return { first: first, second: second, lines: lines,
           figures: faultBoundary.figures(), alive: true };
}

// Runs one scenario in a forked copy of this file and answers what it
// reported on its channel, with its exit code.
function inChild(scenario) {
  log.debug("Entering inChild(). " + scenario);
  return new Promise(function (resolve) {
    const child = childProcess.fork(__filename, ['--child', scenario], {
      stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
      env: Object.assign({}, process.env, { NODE_ENV: 'development' })
    });
    let stderr = '';
    let report = null;
    child.stderr.on('data', function (chunk) {
      stderr += chunk;
    });
    child.on('message', function (message) {
      report = message;
    });
    child.on('exit', function (code) {
      resolve({ code: code, report: report, stderr: stderr });
    });
    log.debug("Leaving inChild().");
  });
}

async function run(t) {
  log.debug("Entering run().");
  const ex = await inChild('express');
  const r = ex.report || {};
  t.check(ex.code === 0 && !!ex.report, 'the express child ran to the end',
          'exit ' + ex.code + ' ' + ex.stderr.slice(0, 400));
  t.check(r.guarded === true, 'the guard recognised express\'s Layer');
  t.check(r.rejects && r.rejects.status === 500,
          'a rejected async handler is answered 500',
          JSON.stringify(r.rejects));
  t.check(r.rejects && r.rejects.body.indexOf('secret detail') < 0 &&
          r.rejects.body.indexOf('Error: ') < 0,
          'and the 500 names nothing of the error, not even its stack',
          r.rejects && r.rejects.body);
  t.check(r.answered && r.answered.status === 200 &&
          r.answered.body === 'kept',
          'a handler that answered and then rejected keeps its answer',
          JSON.stringify(r.answered));
  t.check(r.nextThen && r.nextThen.body === 'second' && r.secondRuns === 1,
          'a handler that called next() and then rejected does not run ' +
          'the chain twice',
          JSON.stringify(r.nextThen) + ' runs=' + r.secondRuns);
  t.check(r.throws && r.throws.status === 500,
          'a thrown error still takes express\'s own road to a 500');
  t.check(r.errorHandler && r.errorHandler.status === 500,
          'a rejected 4-argument error handler is answered 500');
  const exLines = r.lines || [];
  t.check(exLines.filter(function (l) {
    return l.indexOf('STS-CORE-0143') >= 0;
  }).length === 4,
          'each of the four rejections is logged under STS-CORE-0143',
          exLines.join('\n').slice(0, 800));
  t.check(exLines.some(function (l) {
    return l.indexOf('the secret detail') >= 0 &&
           l.indexOf('GET /rejects') >= 0;
  }), 'the log line names the route and carries the error');

  const bare = await new Promise(function (resolve) {
    const child = childProcess.spawn(process.execPath,
      ['-e', 'setTimeout(function () { throw new Error("boom"); }, 0);'],
      { stdio: 'ignore' });
    child.on('exit', function (code) {
      resolve(code);
    });
  });
  t.check(bare !== 0, 'without the handlers an uncaught exception still ' +
                      'ends the process (a startup failure stays fatal)',
          'exit ' + bare);

  const ph = await inChild('process');
  const p = ph.report || {};
  t.check(ph.code === 0 && p.alive === true,
          'with the handlers installed the process survives an uncaught ' +
          'exception, an unhandled rejection and fifteen repeats',
          'exit ' + ph.code + ' ' + ph.stderr.slice(0, 400));
  t.check(p.first === true && p.second === false,
          'installProcessHandlers() installs once');
  const lines = p.lines || [];
  t.check(lines.some(function (l) {
    return l.indexOf('STS-CORE-0141') >= 0 &&
           l.indexOf('from a timer') >= 0;
  }), 'the uncaught exception is logged under STS-CORE-0141 with its error');
  t.check(lines.some(function (l) {
    return l.indexOf('STS-CORE-0142') >= 0 &&
           l.indexOf('nobody handled this') >= 0;
  }), 'the unhandled rejection is logged under STS-CORE-0142');
  const repeats = lines.filter(function (l) {
    return l.indexOf('the same fault') >= 0;
  });
  t.check(repeats.length === 4,
          'a fault seen fifteen times is logged at 1, 2, 3 and 10',
          repeats.length + ' line(s)');
  t.check(p.figures && p.figures.uncaughtException === 16,
          'and every occurrence is still counted',
          JSON.stringify(p.figures));
  log.debug("Leaving run().");
}

// THE CHILD'S ENTRY: runs the scenario it was forked for and reports on the
// channel. Anything that escapes is reported as a failure, not a crash.
if (require.main === module && process.argv[2] === '--child') {
  const scenario = process.argv[3];
  const body = scenario === 'express' ? childExpress() :
               childProcessHandlers();
  body.then(function (report) {
    process.send(report, function () {
      process.exit(0);
    });
  }, function (e) {
    log.debug("Caught in the child: " + ((e && e.message) || e));
    process.exit(3);
  });
}

module.exports = {
  name: 'fault_boundary',
  describe: 'an unexpected error is logged and contained — a rejected async ' +
            'Express handler is a plain 500, a started process survives an ' +
            'uncaught exception or unhandled rejection — and nothing else ' +
            'changes (#355)',
  run: run
};
