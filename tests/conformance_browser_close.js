// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/conformance_browser_close.js
//
// ===========================================================================
// A CONFORMANCE JOB'S BROWSER CANNOT OUTLIVE THE JOB (#2258).
//
// `tests/protocol/conformance_browser.js` throws a browser away when a visit
// runs past its deadline, and closes the one it holds at the end of a job.
// Both used to ASK: `WebDriver.quit()` sends QUIT and ends the chromedriver
// it started only once QUIT has settled, so a chromedriver that had stopped
// answering was never ended — and a child process with a request open on
// its socket keeps node's event loop alive. In run 45608374617
// sts_oidcc_conformance logged "Test completed successfully." at 13:30 and
// was killed at its 16200 s watchdog: one visit had been abandoned at 12:57.
//
// Here, in a child process, the chromedriver is a fake
// (`CONFORMANCE_CHROMEDRIVER`) that answers `/status` and a new session and
// then NEVER answers again, so every WebDriver call and QUIT hangs, as the
// stuck one did:
//
//   A. a visit runs past its deadline (CONFORMANCE_BROWSER_VISIT_MS), its
//      browser is thrown away, the job's `quit()` runs and the child process
//      EXITS on its own — no `process.exit()` — within the bound;
//   B. a visit hangs and the job's own `quit()` closes the browser under it:
//      `quit()` returns at its bound (CONFORMANCE_BROWSER_QUIT_MS), the
//      hung visit settles rather than waiting for ever, and the child
//      exits.
//
// Before #2258 both children ran until the parent's timeout killed them.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'conformance_browser_close',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// The fake chromedriver: started by selenium as `<exe> --port=N ...`.
// A program written to a file at run time; exempt from the Entering/Leaving
// rule as code that runs in a child (root CLAUDE.md, Code style).
const FAKE_DRIVER = [
  '#!/usr/bin/env node',
  "'use strict';",
  "const http = require('http');",
  'const arg = process.argv.find(function (a) {',
  "  return a.indexOf('--port=') === 0;",
  '});',
  "const port = Number(String(arg || '').split('=')[1]);",
  'http.createServer(function (req, res) {',
  "  req.on('data', function () {});",
  "  req.on('end', function () {",
  "    if (req.method === 'GET' && /\\/status$/.test(req.url)) {",
  "      res.setHeader('content-type', 'application/json');",
  "      res.end(JSON.stringify({ value: { ready: true, message: '' } }));",
  '      return;',
  '    }',
  "    if (req.method === 'POST' && /\\/session$/.test(req.url)) {",
  "      res.setHeader('content-type', 'application/json');",
  '      res.end(JSON.stringify({ value: { sessionId: "fake",',
  '        capabilities: { browserName: "chrome" } } }));',
  '      return;',
  '    }',
  '    // Everything else, QUIT included, is never answered.',
  '  });',
  "}).listen(port, '0.0.0.0');",
  '// Gone with the process that started it, so a failing run (whose child',
  '// the parent kills) leaves no fake behind.',
  'const parent = process.ppid;',
  'setInterval(function () {',
  '  if (process.ppid !== parent) {',
  '    process.exit(0);',
  '  }',
  '}, 500);',
  ''
].join('\n');

// The child's program (`node -e`): it may use nothing from this file's scope.
function childMain() {
  /* eslint-disable no-console */
  const cb = require(process.env.CBC_MODULE);
  const person = cb.person({
    suite: function () {
      return Promise.resolve({ status: 200, body: {} });
    },
    suiteBase: 'http://127.0.0.1:9/',
    serviceBase: 'http://127.0.0.1:9',
    username: 'nobody', password: 'nothing', actions: {}
  });
  const started = Date.now();
  const visit = person.start('m1', { testName: 'fake-module' },
                             'http://127.0.0.1:9/nowhere')
    .then(function () {
      return 'resolved';
    }, function (e) {
      return 'rejected: ' + ((e && e.message) || e);
    });
  let job;
  if (process.env.CBC_SCENARIO === 'A') {
    // The deadline throws the browser away; then the job ends.
    job = visit.then(function (how) {
      return cb.quit().then(function () {
        return how;
      });
    });
  } else {
    // The job ends while the visit hangs.
    job = new Promise(function (resolve) {
      setTimeout(resolve, 2500);
    }).then(function () {
      const quitting = Date.now();
      return cb.quit().then(function () {
        const quitMs = Date.now() - quitting;
        return visit.then(function (how) {
          return how + ' quitMs=' + quitMs;
        });
      });
    });
  }
  job.then(function (how) {
    console.log('CBC-DONE ' + (Date.now() - started) + 'ms ' + how);
  }, function (e) {
    console.log('CBC-FAILED ' + ((e && e.stack) || e));
  });
}

function scenario(name, driverPath, extraEnv) {
  log.debug("Entering scenario(). " + name);
  const env = Object.assign({}, process.env, {
    CONFORMANCE_CHROMEDRIVER: driverPath,
    CBC_MODULE: path.join(ROOT, 'tests', 'protocol',
                          'conformance_browser.js'),
    CBC_SCENARIO: name,
    CONFORMANCE_BROWSER_QUIT_MS: '1500',
    LOG_LEVEL: 'fatal'
  }, extraEnv);
  delete env.CONFIG_FILE;
  const started = Date.now();
  const child = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')();'],
    { cwd: path.join(ROOT, 'tests'), env: env, encoding: 'utf8',
      timeout: 45000, killSignal: 'SIGKILL' });
  const out = { status: child.status, signal: child.signal,
                ms: Date.now() - started,
                stdout: String(child.stdout || ''),
                stderr: String(child.stderr || '') };
  log.debug("Leaving scenario(). " + name + " " + out.status + " " +
            out.signal + " " + out.ms + "ms");
  return out;
}

function run(t) {
  log.debug("Entering run().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-cb-close-'));
  const driverPath = path.join(dir, 'chromedriver');
  try {
    fs.writeFileSync(driverPath, FAKE_DRIVER, { mode: 0o755 });

    const a = scenario('A', driverPath,
                       { CONFORMANCE_BROWSER_VISIT_MS: '1500' });
    t.check(a.signal === null && a.status === 0,
            'A. after a visit was abandoned at its deadline, the job\'s ' +
            'process exits on its own once its work is done',
            'status ' + a.status + ', signal ' + a.signal + ' after ' +
            a.ms + ' ms (a signal is the parent\'s 45 s timeout: something ' +
            'still holds the event loop). ' + a.stdout.slice(-500) +
            a.stderr.slice(-1500));
    t.check(/CBC-DONE/.test(a.stdout),
            'A. the abandoned visit and the job\'s quit() both settled',
            a.stdout.slice(-500));

    const b = scenario('B', driverPath,
                       { CONFORMANCE_BROWSER_VISIT_MS: '600000' });
    t.check(b.signal === null && b.status === 0,
            'B. a job that quits while a visit hangs exits on its own',
            'status ' + b.status + ', signal ' + b.signal + ' after ' +
            b.ms + ' ms. ' + b.stdout.slice(-500) + b.stderr.slice(-1500));
    const quitMs = Number((/quitMs=(\d+)/.exec(b.stdout) || [])[1]);
    t.check(quitMs >= 1000 && quitMs < 10000,
            'B. quit() returns at its bound rather than waiting for a QUIT ' +
            'that never comes back',
            'quit() took ' + quitMs + ' ms; ' + b.stdout.slice(-300));
    t.check(/CBC-DONE/.test(b.stdout),
            'B. the hung visit settles once its chromedriver is ended, ' +
            'rather than waiting for ever',
            b.stdout.slice(-300));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'conformance_browser_close',
  describe: 'issue #2258: a conformance job\'s browser is ended, not just ' +
            'asked to quit — a visit abandoned at its deadline, or a ' +
            'browser closed at the end of the job, cannot keep the job\'s ' +
            'process alive when its chromedriver has stopped answering',
  run: run
};
