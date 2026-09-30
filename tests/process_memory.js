// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: process_memory.js
//
// ===========================================================================
// EVERY PROCESS HAS A HEAP LIMIT DERIVED FROM THE CONTAINER, AND A WORKER'S
// DEATH BY MEMORY SAYS SO (#341, 2026-09-29).
//
// `common/process_memory.ts` reads the container's memory limit (cgroup v2,
// cgroup v1 and its hierarchical limit, the ECS task), derives one heap budget
// for every V8 isolate, re-executes the front process with it, and reports
// each isolate's memory. `common/request_pool.js` starts each worker THREAD
// (#364; a forked process until then) with the budget as its
// `resourceLimits`, and names a thread whose heap reached it
// (ERR_WORKER_OUT_OF_MEMORY) as STS-WORKER-0046. The kernel's OOM killer has
// no worker to pick any more — a thread is not a process — so it ends the
// whole process and STS-WORKER-0047 is retired; nothing here asserts it.
//
// 1–5 assert the decisions over fake files and arguments, and 3 the worker
// count's default (`requestWorkers()`, #364). 6 re-executes a real child
// through `process.execve()` and reads its V8 heap limit. 7 and 8 drive the
// pool's REAL fork() and reap() with stub worker threads: one that fills its
// heap and is ended by V8 at the limit it was started with, and one started
// with the limit off and terminated from outside, which claims nothing.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const config = require('../common/config');
const pm = require('../common/process_memory');
const pool = require('../common/request_pool');

const log = require('bunyan').createLogger({ name: 'process_memory_test',
  level: process.env.LOG_LEVEL || 'info' });

const MIB = 1024 * 1024;

function reader(files) {
  log.debug("Entering reader().");
  log.debug("Leaving reader().");
  return function (file) {
    if (Object.prototype.hasOwnProperty.call(files, file)) {
      return files[file];
    }
    const e = new Error('ENOENT: ' + file);
    throw e;
  };
}

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) { setTimeout(resolve, ms); });
}

async function waitFor(test, ms) {
  log.debug("Entering waitFor().");
  const until = Date.now() + ms;
  while (Date.now() < until) {
    if (test()) {
      log.debug("Leaving waitFor(). Met.");
      return true;
    }
    await sleep(50);
  }
  log.debug("Leaving waitFor(). Timed out.");
  return !!test();
}

// ---------------------------------------------------------------------------
// 1. THE CONTAINER'S LIMIT, FROM EACH CGROUP LAYOUT.
// ---------------------------------------------------------------------------
function checkTheCgroup(t) {
  log.debug("Entering checkTheCgroup().");
  t.log.info('=== the container limit, from cgroup v2 and v1 ===');
  let got = pm.cgroupLimit(reader({
    '/sys/fs/cgroup/memory.max': '8589934592\n' }));
  t.equal(got.bytes, 8589934592, 'cgroup v2: memory.max is the limit');
  got = pm.cgroupLimit(reader({ '/sys/fs/cgroup/memory.max': 'max\n' }));
  t.equal(got.bytes, null, 'cgroup v2: "max" is no limit');
  got = pm.cgroupLimit(reader({
    '/sys/fs/cgroup/memory/memory.limit_in_bytes': '3221225472\n' }));
  t.equal(got.bytes, 3221225472, 'cgroup v1: memory.limit_in_bytes');
  got = pm.cgroupLimit(reader({
    '/sys/fs/cgroup/memory/memory.limit_in_bytes': '9223372036854771712\n',
    '/sys/fs/cgroup/memory/memory.stat':
      'cache 0\nrss 1\nhierarchical_memory_limit 8589934592\n' }));
  t.equal(got.bytes, 8589934592,
          'cgroup v1 unlimited: an ancestor\'s hierarchical_memory_limit ' +
          '(a Fargate task\'s) is the limit');
  got = pm.cgroupLimit(reader({
    '/sys/fs/cgroup/memory/memory.limit_in_bytes': '9223372036854771712\n',
    '/sys/fs/cgroup/memory/memory.stat':
      'hierarchical_memory_limit 9223372036854771712\n' }));
  t.equal(got.bytes, null, 'cgroup v1 unlimited all the way up: no limit');
  got = pm.cgroupLimit(reader({}));
  t.equal(got.bytes, null, 'no memory cgroup at all: no limit');
  log.debug("Leaving checkTheCgroup().");
}

// ---------------------------------------------------------------------------
// 2. THE BUDGET.
// ---------------------------------------------------------------------------
function checkTheBudget(t) {
  log.debug("Entering checkTheBudget().");
  t.log.info('=== the budget: (limit − headroom) ÷ processes ===');
  let b = pm.derive({ configuredMb: 0, limitBytes: 8192 * MIB,
                      requestCount: 3, surfaceCount: 1 });
  // 15 % of 8192 is 1228.8 MiB of headroom; five processes (front, three
  // protocol, one surface).
  t.equal(b.processes, 5, 'front + 3 + 1');
  t.equal(b.mb, Math.floor((8192 - 1228.8) / 5),
          'testidp\'s 8 GiB node: 1392 MiB per process');
  b = pm.derive({ configuredMb: 0, limitBytes: 1024 * MIB,
                  requestCount: 0, surfaceCount: 0 });
  t.equal(b.mb, 768, 'a 1 GiB single process: (1024 − 256) ÷ 1');
  b = pm.derive({ configuredMb: 0, limitBytes: 512 * MIB,
                  requestCount: 4, surfaceCount: 2 });
  t.equal(b.mb, 256, 'never below the 256 MiB floor');
  b = pm.derive({ configuredMb: 0, limitBytes: null,
                  requestCount: 3, surfaceCount: 1 });
  t.equal(b.mb, 0, 'no visible limit: nothing is set');
  b = pm.derive({ configuredMb: 700, limitBytes: 8192 * MIB,
                  requestCount: 3, surfaceCount: 1 });
  t.equal(b.mb, 700, 'workers.heapLimitMb wins when it is set');
  b = pm.derive({ configuredMb: -1, limitBytes: 8192 * MIB,
                  requestCount: 3, surfaceCount: 1 });
  t.check(b.mb === 0 && b.off === true,
          '-1 is OFF: no limit, whatever the container says',
          JSON.stringify(b));
  log.debug("Leaving checkTheBudget().");
}

// ---------------------------------------------------------------------------
// 3. THE FLAG, AN OPERATOR'S, IS READ — AND THE WORKER COUNT'S DEFAULT.
//
// A worker had the flag replaced in its execArgv (`workerExecArgv()`) until
// #364; a worker thread takes the budget as `resourceLimits` (7 below) and
// has no argv of node options, so only the operator's flag is left to read.
// ---------------------------------------------------------------------------
function checkTheFlag(t) {
  log.debug("Entering checkTheFlag().");
  t.log.info('=== the flag, read ===');
  t.equal(pm.explicitFlag(['--max-old-space-size=900'], ''), 900,
          'on the command line');
  t.equal(pm.explicitFlag([], '--enable-source-maps --max-old-space-size 700'),
          700, 'in NODE_OPTIONS, in the two-word form');
  t.equal(pm.explicitFlag(['--inspect'], ''), 0, 'none set');
  t.check(typeof pm.workerExecArgv !== 'function',
          'and there is no worker argv to rewrite: a worker thread takes ' +
          'its budget as resourceLimits (#364)', '');
  log.debug("Leaving checkTheFlag().");
}

// Sets `vars` (a value of undefined unsets one) for the length of `fn`, and
// puts every one back whatever happens. Synchronous: requestWorkers() reads
// the settings when it is called.
function withVars(vars, fn) {
  log.debug("Entering withVars().");
  const had = {};
  Object.keys(vars).forEach(function (name) {
    had[name] = process.env[name];
    if (vars[name] === undefined) {
      delete process.env[name];
    } else {
      process.env[name] = vars[name];
    }
  });
  try {
    return fn();
  } finally {
    Object.keys(had).forEach(function (name) {
      if (had[name] === undefined) {
        delete process.env[name];
      } else {
        process.env[name] = had[name];
      }
    });
    log.debug("Leaving withVars().");
  }
}

// ONE REQUEST WORKER BY DEFAULT, WHERE THE STORE CAN COORDINATE (#364).
// `workers.requestCount` defaults to 1, and that default means NONE on a
// store that cannot coordinate — memory, ldif, or postgres with
// `persistence.coordinate` off — because a worker holds its own copy of
// every store and learns the others' writes only from the change log. An
// operator's own value is theirs (the pool's start() refuses it without
// coordination, STS-WORKER-0024, which is not this function's to say).
function checkTheWorkerCount(t) {
  log.debug("Entering checkTheWorkerCount().");
  t.log.info('=== the request worker count: its default, and an ' +
             'operator\'s ===');
  const unset = { STS_WORKERS_REQUEST_COUNT: undefined };
  withVars(unset, function () {
    t.check(/^defaults?$/.test(config.sourceOf('workers.requestCount')) &&
            Number(config.value('workers.requestCount')) === 1,
            'workers.requestCount is 1 by default',
            config.sourceOf('workers.requestCount') + ' ' +
            config.value('workers.requestCount'));
  });
  withVars(Object.assign({ STS_PERSISTENCE_MODE: 'memory' }, unset),
    function () {
      t.equal(pm.requestWorkers(), 0,
              'the default on the memory store is no worker at all');
      t.equal(pm.settings().requestCount, 0,
              'and the heap budget is divided by the front process alone');
    });
  withVars(Object.assign({ STS_PERSISTENCE_MODE: 'ldif' }, unset),
    function () {
      t.equal(pm.requestWorkers(), 0, 'nor on the ldif store');
    });
  withVars(Object.assign({ STS_PERSISTENCE_MODE: 'postgres',
                           STS_PERSISTENCE_COORDINATE: 'true' }, unset),
    function () {
      t.equal(pm.requestWorkers(), 1,
              'on postgres with coordination the default is one worker');
      t.equal(pm.settings().requestCount, 1,
              'and the budget counts it');
    });
  withVars(Object.assign({ STS_PERSISTENCE_MODE: 'postgres',
                           STS_PERSISTENCE_COORDINATE: 'false' }, unset),
    function () {
      t.equal(pm.requestWorkers(), 0,
              'on postgres with persistence.coordinate off it is none again');
    });
  withVars({ STS_PERSISTENCE_MODE: 'memory', STS_WORKERS_REQUEST_COUNT: '2' },
    function () {
      t.equal(pm.requestWorkers(), 2,
              'an operator\'s explicit value is honoured whatever the store ' +
              '— refusing it without coordination is start()\'s');
    });
  withVars({ STS_PERSISTENCE_MODE: 'postgres',
             STS_PERSISTENCE_COORDINATE: 'true',
             STS_WORKERS_REQUEST_COUNT: '0' },
  function () {
    t.equal(pm.requestWorkers(), 0,
            'and an explicit 0 is none, on a store that could coordinate');
  });
  log.debug("Leaving checkTheWorkerCount().");
}

// ---------------------------------------------------------------------------
// 4. THE OOM-KILL COUNTER.
// ---------------------------------------------------------------------------
function checkTheCounter(t) {
  log.debug("Entering checkTheCounter().");
  t.log.info('=== the cgroup\'s oom_kill count ===');
  t.equal(pm.oomKillCount(reader({ '/sys/fs/cgroup/memory.events':
    'low 0\nhigh 0\nmax 12\noom 3\noom_kill 2\noom_group_kill 0\n' })), 2,
  'cgroup v2 memory.events');
  t.equal(pm.oomKillCount(reader({
    '/sys/fs/cgroup/memory/memory.oom_control':
      'oom_kill_disable 0\nunder_oom 0\noom_kill 5\n' })), 5,
  'cgroup v1 memory.oom_control');
  t.equal(pm.oomKillCount(reader({})), null, 'no counter visible: null');
  log.debug("Leaving checkTheCounter().");
}

// ---------------------------------------------------------------------------
// 5. WHY A WORKER DIED.
// ---------------------------------------------------------------------------
function checkTheCause(t) {
  log.debug("Entering checkTheCause().");
  t.log.info('=== an exit\'s cause ===');
  t.equal(pool.exitCause('ERR_WORKER_OUT_OF_MEMORY'), 'STS-WORKER-0046',
          'ERR_WORKER_OUT_OF_MEMORY is a thread\'s heap at its limit');
  t.equal(pool.exitCause(null), '',
          'a thread that ended any other way claims nothing');
  t.equal(pool.exitCause('SIGABRT'), '',
          'and a signal is no cause any more: a thread receives none, and ' +
          'SIGABRT was a forked process\'s way of running out of heap');
  t.equal(pool.exitCause('SIGKILL'), '',
          'nor is SIGKILL — the kernel\'s OOM killer ends the whole process ' +
          'now, and STS-WORKER-0047 is retired');
  log.debug("Leaving checkTheCause().");
}

// ---------------------------------------------------------------------------
// 6. THE FRONT PROCESS RE-EXECUTES ITSELF WITH THE FLAG.
// ---------------------------------------------------------------------------
function checkTheReexec(t, dir) {
  log.debug("Entering checkTheReexec().");
  t.log.info('=== the front process restarts itself with the flag ===');
  if (typeof process.execve !== 'function') {
    t.check(false, 'this node (' + process.version + ') has process.execve, ' +
            'which the image\'s does', '');
    log.debug("Leaving checkTheReexec(). No execve.");
    return;
  }
  const script = path.join(dir, 'reexec-child.js');
  fs.writeFileSync(script, [
    "'use strict';",
    "if (!process.env.STS_HEAP_REEXEC) {",
    "  process.stdout.write('before ' + process.pid + '\\n');",
    "}",
    "const pm = require(" + JSON.stringify(
      path.join(__dirname, '..', 'common', 'process_memory')) + ");",
    "pm.reexecWithHeapLimit();",
    "process.stdout.write('after ' + JSON.stringify({ pid: process.pid,",
    "  limit: pm.heapLimitMb(), budget: pm.budget().mb,",
    "  argv: process.execArgv }) + '\\n');",
    ""].join('\n'));
  const env = Object.assign({}, process.env,
                            { STS_WORKERS_HEAP_LIMIT_MB: '300',
                              LOG_LEVEL: 'fatal' });
  delete env.STS_HEAP_REEXEC;
  delete env.STS_HEAP_BUDGET;
  delete env.NODE_OPTIONS;
  const out = childProcess.execFileSync(process.execPath, [script],
    { env: env, encoding: 'utf8', timeout: 30000 });
  const lines = out.split('\n').filter(function (line) {
    return /^(before|after) /.test(line);
  });
  const before = /^before (\d+)/.exec(lines[0] || '');
  const after = /^after (.*)$/.exec(lines[1] || '');
  t.check(!!before && !!after, 'the child ran twice: before and after',
          JSON.stringify(lines));
  if (!before || !after) {
    log.debug("Leaving checkTheReexec(). No output.");
    return;
  }
  const got = JSON.parse(after[1]);
  t.equal(got.pid, Number(before[1]),
          'the same pid: the process replaced itself rather than spawn a ' +
          'second');
  t.check(got.argv.indexOf('--max-old-space-size=300') >= 0,
          'it was started again with --max-old-space-size=300',
          JSON.stringify(got.argv));
  // V8'S heap_size_limit IS THE OLD SPACE PLUS THE YOUNG GENERATION'S
  // CEILING, which node 24 puts at 192 MiB whatever the old space is: 492
  // for 300, measured. Bounded below by the flag and far below V8's default
  // for this machine.
  t.check(got.limit >= 300 && got.limit < 600,
          'and V8\'s heap limit is 300 MiB plus the young generation',
          String(got.limit));
  t.equal(got.budget, 300, 'the budget came across the re-exec');

  // AND WITH THE LIMIT OFF (-1): no re-exec and no flag.
  env.STS_WORKERS_HEAP_LIMIT_MB = '-1';
  const offOut = childProcess.execFileSync(process.execPath, [script],
    { env: env, encoding: 'utf8', timeout: 30000 });
  const offLines = offOut.split('\n').filter(function (line) {
    return /^(before|after) /.test(line);
  });
  const offAfter = /^after (.*)$/.exec(offLines[1] || '');
  const off = offAfter ? JSON.parse(offAfter[1]) : null;
  t.check(!!off && off.budget === 0 &&
          off.argv.join(' ').indexOf('--max-old-space-size') < 0,
          'workers.heapLimitMb -1: the child ran once more without the flag ' +
          'and was not re-executed', JSON.stringify(offLines));
  log.debug("Leaving checkTheReexec().");
}

// ---------------------------------------------------------------------------
// 7 and 8. THE POOL: A WORKER THREAD STARTED WITH THE BUDGET AND ENDED BY V8
// AT IT, AND ONE STARTED WITH THE LIMIT OFF AND TERMINATED FROM OUTSIDE.
//
// The stub is a thread, as the real worker is since #364: it reads its own
// V8 heap limit — which `resourceLimits` sets per isolate — and sends it in
// a memory report over `parentPort`, then either fills its heap or listens
// and says ready. Its `pid` is its threadId, the pool's id for it.
// ---------------------------------------------------------------------------
const STUB = [
  "'use strict';",
  "const http = require('http');",
  "const v8 = require('v8');",
  "const wt = require('worker_threads');",
  "wt.parentPort.on('message', function (m) {",
  "  if (m && m.stop) { process.exit(0); }",
  "  if (!m || !m.begin) { return; }",
  "  const limit = Math.round(v8.getHeapStatistics().heap_size_limit /",
  "                          1048576);",
  "  wt.parentPort.postMessage({ memoryReport: {",
  "    role: 'protocol worker thread', pid: wt.threadId, rssMb: 1,",
  "    heapUsedMb: 1, heapTotalMb: 1, externalMb: 0, arrayBuffersMb: 0,",
  "    heapLimitMb: limit, at: Date.now() } });",
  "  if (process.env.STUB_MODE === 'fill') {",
  "    setTimeout(function () {",
  "      const hold = [];",
  "      for (;;) { hold.push(new Array(100000).fill(Math.random())); }",
  "    }, 200);",
  "    return;",
  "  }",
  "  const server = http.createServer(function (req, res) {",
  "    res.end(String(wt.threadId));",
  "  });",
  "  server.listen(m.socket, function () {",
  "    wt.parentPort.postMessage({ ready: true });",
  "  });",
  "});",
  ""
].join('\n');

async function withEnv(vars, fn) {
  log.debug("Entering withEnv().");
  const had = {};
  Object.keys(vars).forEach(function (name) {
    had[name] = process.env[name];
    process.env[name] = vars[name];
  });
  pool.reset();
  try {
    await fn();
  } finally {
    await pool.stop(3000);
    Object.keys(had).forEach(function (name) {
      if (had[name] === undefined) {
        delete process.env[name];
      } else {
        process.env[name] = had[name];
      }
    });
    pool.reset();
  }
  log.debug("Leaving withEnv().");
}

function lastExit() {
  log.debug("Entering lastExit().");
  const exits = pool.stats().memory.exits;
  log.debug("Leaving lastExit().");
  return exits[exits.length - 1] || null;
}

async function checkTheHeapExit(t, stub) {
  log.debug("Entering checkTheHeapExit().");
  t.log.info('=== a worker thread started with the budget is ended at ' +
             'it, and the process carries on ===');
  await withEnv({ STS_WORKERS_REQUEST_COUNT: '0', STUB_MODE: 'fill',
                  STS_WORKERS_HEAP_LIMIT_MB: '64' }, async function () {
    pool.useWorkerModule(stub);
    t.equal(pool.stats().memory.heapLimitMb, 64,
            'the pool reads the budget from workers.heapLimitMb');
    const entry = pool.fork(pool.PROTOCOL_POOL, 0);
    const limits = entry.child.worker && entry.child.worker.resourceLimits;
    t.check(!!limits && limits.maxOldGenerationSizeMb === 64,
            'the thread was started with the budget as its resourceLimits',
            JSON.stringify(limits));
    t.check(await waitFor(function () {
      return !!lastExit();
    }, 30000), 'the worker thread that filled its heap exited', '');
    const exit = lastExit() || {};
    t.equal(exit.pid, entry.pid, 'it is that worker\'s exit, by threadId');
    t.equal(exit.cause, 'STS-WORKER-0046',
            'reported as the heap (ERR_WORKER_OUT_OF_MEMORY)');
    t.check(exit.code !== 0 && exit.code !== null,
            'with the non-zero code a thread V8 ended exits with',
            JSON.stringify(exit.code));
    t.check(exit.memory && exit.memory.heapLimitMb >= 64 &&
            exit.memory.heapLimitMb < 300,
            'its own heap limit was the 64 MiB it was given, and its report ' +
            'reached the front process', JSON.stringify(exit.memory));
    t.check(process.memoryUsage().rss > 0,
            'and this process — the front, whose thread it was — is still ' +
            'here to say so', '');
  });
  log.debug("Leaving checkTheHeapExit().");
}

async function checkTheLimitOff(t, stub) {
  log.debug("Entering checkTheLimitOff().");
  t.log.info('=== with the limit off a thread keeps V8\'s own, and a ' +
             'thread terminated from outside claims nothing ===');
  await withEnv({ STS_WORKERS_REQUEST_COUNT: '0', STUB_MODE: 'ok',
                  STS_WORKERS_HEAP_LIMIT_MB: '-1' }, async function () {
    pool.useWorkerModule(stub);
    t.check(pool.stats().memory.heapLimitMb === 0,
            'with the limit OFF the pool starts its threads with no budget',
            JSON.stringify(pool.stats().memory));
    const entry = pool.fork(pool.PROTOCOL_POOL, 0);
    await entry.settled;
    t.check(!!entry.memory && entry.memory.heapLimitMb >= 300,
            'the thread\'s memory report reaches the front process, and ' +
            'its heap limit is V8\'s own rather than a budget',
            JSON.stringify(entry.memory));
    entry.child.kill();
    t.check(await waitFor(function () {
      return !!lastExit();
    }, 10000), 'the terminated thread was reaped', '');
    const exit = lastExit() || {};
    t.equal(exit.cause, null,
            'a thread ended from outside is not the heap, and nothing more ' +
            'is claimed');
    t.equal(exit.pid, entry.pid, 'it is that worker\'s exit');
  });
  log.debug("Leaving checkTheLimitOff().");
}

async function run(t) {
  log.debug("Entering run().");
  checkTheCgroup(t);
  checkTheBudget(t);
  checkTheFlag(t);
  checkTheWorkerCount(t);
  checkTheCounter(t);
  checkTheCause(t);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-process-memory-'));
  const stub = path.join(dir, 'stub-worker.js');
  fs.writeFileSync(stub, STUB);
  try {
    checkTheReexec(t, dir);
    await checkTheHeapExit(t, stub);
    await checkTheLimitOff(t, stub);
  } finally {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch (e) {
      log.debug("Caught in run(): " + ((e && e.message) || e));
    }
    pool.reset();
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'process_memory',
  describe: 'that every isolate gets a heap limit derived from the ' +
            'container (cgroup v2, v1, the ECS task), that the front ' +
            'process re-executes itself with it, that a worker thread is ' +
            'started with it as resourceLimits and a thread whose heap ' +
            'reaches it is reported as STS-WORKER-0046 (#341, #364), and ' +
            'that one request worker is the default only where the store ' +
            'coordinates (#364)',
  run: run
};
