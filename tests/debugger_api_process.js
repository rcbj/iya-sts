'use strict';
//
// File: debugger_api_process.js
//
// ===========================================================================
// THE EMBEDDED DEBUGGER'S API CHILD, SUPERVISED (2026-09-13).
//
// `debugger/debugger_api_process.ts` forks the debugger's api and keeps it
// running. This file forks a STAND-IN api — thirty lines written here that bind
// the socket, say they are listening and report what they were given — and
// asserts the five things the supervisor exists for:
//
//   A. the child is started with a BUILT environment: the contract's variables
//      and PATH, HOME, LANG, TZ — and not a variable of this process's own,
//      which is where a deployment's secrets are;
//   B. it is only READY once the child says it is listening, and the socket's
//      directory is owner-only;
//   C. A NEW TRUST ANCHOR REPLACES THE CHILD: the same anchor does nothing, a
//      new one makes the child not-ready at once, forks a successor that reads
//      the NEW anchor, and is not counted as a failure;
//   D. a child that keeps dying is restarted with backoff and GIVEN UP ON at
//      `debugger.restartLimit`;
//   E. `stop()` removes the socket directory.
//
// WHY IN PROCESS: every claim is about a process this service forks and the
// environment it hands down, which no request can see — the real api answers
// the same over its socket whether or not it was handed a secret.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-dbg-proc-test-'));
const apiDir = path.join(scratch, 'api');
fs.mkdirSync(path.join(apiDir, 'env'), { recursive: true });
fs.writeFileSync(path.join(apiDir, 'env', 'embedded.js'),
                 'module.exports = {};\n');
// The stand-in. It is data, a program for a child process, and is exempt from
// the code style for that reason. A `crash` file beside it makes it exit at
// once, which is how section D makes a child that keeps dying.
fs.writeFileSync(path.join(apiDir, 'server.js'), [
  "'use strict';",
  "const fs = require('fs');",
  "const http = require('http');",
  "const path = require('path');",
  "if (fs.existsSync(path.join(__dirname, 'crash'))) { process.exit(3); }",
  "const sock = process.env.DEBUGGER_LISTEN_SOCKET;",
  "const server = http.createServer(function (req, res) {",
  "  const anchorFile = process.env.NODE_EXTRA_CA_CERTS || '';",
  "  res.setHeader('content-type', 'application/json');",
  "  res.end(JSON.stringify({ pid: process.pid,",
  "    env: Object.keys(process.env).sort(),",
  "    ui: process.env.DEBUGGER_UI_URL,",
  "    config: process.env.CONFIG_FILE,",
  "    anchor: anchorFile ? fs.readFileSync(anchorFile, 'utf8') : '' }));",
  "});",
  "server.listen(sock, function () {",
  "  if (process.send) {",
  "    process.send({ type: 'debugger-api-listening', socket: sock });",
  "  }",
  "});",
  "process.on('SIGTERM', function () {",
  "  server.close(function () { process.exit(0); });",
  "});",
  "process.on('disconnect', function () { process.exit(0); });",
  ''
].join('\n'));
process.env.STS_DEBUGGER_API_DIRECTORY = apiDir;
// A variable only THIS process holds. The child must not see it.
process.env.STS_DEBUGGER_TEST_SECRET = 'not-for-the-child';

const config = require('../common/config');
const apiProcess = require('../debugger/debugger_api_process');

const log = require('bunyan').createLogger({ name: 'debugger_api_process',
  level: process.env.LOG_LEVEL || 'info' });

const ANCHOR_ONE = '-----BEGIN CERTIFICATE-----\nb25l\n' +
                   '-----END CERTIFICATE-----\n';
const ANCHOR_TWO = '-----BEGIN CERTIFICATE-----\ndHdv\n' +
                   '-----END CERTIFICATE-----\n';

// Poll until `test()` answers true, or give up after `ms`.
async function until(test, ms) {
  log.debug("Entering until().");
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (test()) {
      log.debug("Leaving until(). Met.");
      return true;
    }
    await new Promise(function (resolve) {
      setTimeout(resolve, 50);
    });
  }
  log.debug("Leaving until(). Timed out.");
  return test();
}

function ask() {
  log.debug("Entering ask().");
  log.debug("Leaving ask().");
  return new Promise(function (resolve, reject) {
    const req = http.request({ socketPath: apiProcess.socketPath(),
                               path: '/', method: 'GET' }, function (res) {
      let text = '';
      res.on('data', function (chunk) {
        text += chunk;
      });
      res.on('end', function () {
        try {
          resolve(JSON.parse(text));
        } catch (e) {
          log.debug("Caught in a callback in ask(): " + e.message);
          reject(e);
        }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

async function run(t) {
  log.debug("Entering run().");
  const allowed = ['CONFIG_FILE', 'DEBUGGER_ALLOWED_ADDRESS_RANGES',
                   'DEBUGGER_BLOCK_PRIVATE_NETWORK_CALLS',
                   'DEBUGGER_LISTEN_SOCKET', 'DEBUGGER_LOG_LEVEL',
                   'DEBUGGER_UI_URL', 'HOME', 'LANG', 'NODE_EXTRA_CA_CERTS',
                   'PATH', 'TZ'];
  let socketDir = '';
  try {
    // -----------------------------------------------------------------------
    t.log.info('=== A and B. started, ready, and what it was handed ===');
    const started = await apiProcess.start({ uiUrl: 'https://dbg.test:8444',
                                             anchorPem: ANCHOR_ONE });
    t.check(started.started, 'the stand-in api is forked',
            JSON.stringify(started));
    t.check(await until(apiProcess.ready, 15000),
            'and becomes READY once it reports listening',
            JSON.stringify(apiProcess.status()));
    socketDir = path.dirname(apiProcess.socketPath());
    t.equal((fs.statSync(socketDir).mode & 0o777).toString(8), '700',
            'the socket\'s directory is owner-only');
    const first = await ask();
    // Node adds a few of its own on start (NODE_CHANNEL_FD and the like), so
    // what is asserted is that nothing of THIS process's crossed.
    //
    // NODE_V8_COVERAGE is one of node's own too, and it failed the coverage
    // job until 2026-09-15: a process collecting coverage copies it into
    // every child it spawns, even one handed an explicit `env` with nothing
    // in it — node does that so a child's coverage is collected as well, and
    // the service cannot prevent it. It only appears when the test itself is
    // instrumented, which is why no plain run ever saw it.
    const leaked = first.env.filter(function (name) {
      return allowed.indexOf(name) < 0 &&
             !/^NODE_(CHANNEL|UNIQUE|V8_COVERAGE$)/.test(name);
    });
    t.equal(JSON.stringify(leaked), '[]',
            'the child holds only the contract\'s variables and PATH, HOME, ' +
            'LANG, TZ — none of this process\'s environment',
            JSON.stringify(first.env));
    t.check(first.env.indexOf('STS_DEBUGGER_TEST_SECRET') < 0,
            'in particular not a variable only this process holds');
    t.equal(first.ui, 'https://dbg.test:8444',
            'it is told the debugger origin');
    t.equal(first.config, path.join(apiDir, 'env', 'embedded.js'),
            'and its own embedded configuration, not this service\'s');
    t.equal(first.anchor, ANCHOR_ONE,
            'and reads this service\'s trust anchor from the file it was ' +
            'given');

    // -----------------------------------------------------------------------
    t.log.info('=== C. a new trust anchor replaces the child ===');
    t.equal(apiProcess.updateAnchor(ANCHOR_ONE), false,
            'the same anchor replaces nothing');
    t.equal(apiProcess.status().pid, first.pid,
            'and the child is the same one');
    t.equal(apiProcess.updateAnchor(ANCHOR_TWO), true,
            'a new anchor starts a replacement');
    t.check(!apiProcess.ready(),
            'and the child is NOT READY from that moment, so no call is sent ' +
            'to a process that has been told to exit');
    t.check(await until(function () {
      const now = apiProcess.status();
      return apiProcess.ready() && now.pid && now.pid !== first.pid;
    }, 15000), 'a successor is forked and becomes ready',
            JSON.stringify(apiProcess.status()));
    const second = await ask();
    t.equal(second.anchor, ANCHOR_TWO, 'and it reads the NEW anchor');
    t.equal(apiProcess.status().consecutiveFailures, 0,
            'and the hand-over is not counted as a failure');
    t.equal(apiProcess.status().anchorReplacements, 1,
            'and is reported as a replacement');

    // -----------------------------------------------------------------------
    t.log.info('=== D. a child that keeps dying is given up on ===');
    const startsBefore = apiProcess.status().starts;
    config.setOverride('debugger.restartLimit', '2');
    fs.writeFileSync(path.join(apiDir, 'crash'), '');
    process.kill(second.pid, 'SIGKILL');
    t.check(await until(function () {
      return apiProcess.status().state === 'given-up';
    }, 20000), 'after debugger.restartLimit exits in a row it stays stopped',
            JSON.stringify(apiProcess.status()));
    // The killed child is the first failure; the one restart after it dies
    // at once and is the second, which reaches the limit of two.
    t.equal(apiProcess.status().starts - startsBefore, 1,
            'having restarted exactly once in between');
    t.equal(apiProcess.status().consecutiveFailures, 2,
            'with both deaths counted');
    t.check(!apiProcess.ready(), 'and it is not ready');
  } finally {
    config.clearOverride('debugger.restartLimit');
    // -----------------------------------------------------------------------
    t.log.info('=== E. stop ===');
    await apiProcess.stop();
    t.check(!socketDir || !fs.existsSync(socketDir),
            'stop() removes the socket directory', socketDir);
    delete process.env.STS_DEBUGGER_TEST_SECRET;
    fs.rmSync(scratch, { recursive: true, force: true });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'debugger_api_process',
  describe: 'the embedded debugger\'s api child: a built environment, ready ' +
            'only when listening, replaced on a new trust anchor, given up ' +
            'on after repeated deaths, and cleaned up on stop',
  run: run
};
