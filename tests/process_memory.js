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
// for every process, re-executes the front process with it, and reports each
// process's memory. `common/request_pool.js` forks each worker with the
// budget and tells a heap exhaustion (SIGABRT, STS-WORKER-0046) from the
// kernel's OOM killer (SIGKILL with the cgroup's oom_kill count risen,
// STS-WORKER-0047).
//
// 1–5 assert the decisions over fake files and arguments. 6 re-executes a
// real child through `process.execve()` and reads its V8 heap limit. 7 and 8
// drive the pool's REAL fork() and reap() with stub workers: one that fills
// its heap (and is aborted by V8 at the limit it was forked with) and one
// that is SIGKILLed while a fake OOM counter rises.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
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
  // 15 % of 8192 is 1228.8 MiB of headroom; six processes (front, three
  // protocol, one surface, the crypto allowance).
  t.equal(b.processes, 6, 'front + 3 + 1 + the crypto allowance');
  t.equal(b.mb, Math.floor((8192 - 1228.8) / 6),
          'testidp\'s 8 GiB node: 1160 MiB per process');
  b = pm.derive({ configuredMb: 0, limitBytes: 1024 * MIB,
                  requestCount: 0, surfaceCount: 0 });
  t.equal(b.mb, 384, 'a 1 GiB single process: (1024 − 256) ÷ 2');
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
// 3. THE FLAG: AN OPERATOR'S IS READ, A WORKER'S IS REPLACED.
// ---------------------------------------------------------------------------
function checkTheFlag(t) {
  log.debug("Entering checkTheFlag().");
  t.log.info('=== the flag, read and replaced ===');
  t.equal(pm.explicitFlag(['--max-old-space-size=900'], ''), 900,
          'on the command line');
  t.equal(pm.explicitFlag([], '--enable-source-maps --max-old-space-size 700'),
          700, 'in NODE_OPTIONS, in the two-word form');
  t.equal(pm.explicitFlag(['--inspect'], ''), 0, 'none set');
  t.equal(pm.workerExecArgv(['--inspect=0', '--max-old-space-size=900',
                             '--max-old-space-size', '800'], 512).join(' '),
          '--inspect=0 --max-old-space-size=512',
          'a worker keeps the other options and gets the budget alone');
  t.equal(pm.workerExecArgv(['--max-old-space-size=900'], 0).join(' '), '',
          'no budget: no flag, and the front process\'s is not passed on');
  log.debug("Leaving checkTheFlag().");
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
  t.equal(pool.exitCause('SIGABRT', null, null), 'STS-WORKER-0046',
          'SIGABRT is V8 at the heap limit');
  t.equal(pool.exitCause('SIGKILL', 2, 3), 'STS-WORKER-0047',
          'SIGKILL with the oom_kill count risen is the kernel');
  t.equal(pool.exitCause('SIGKILL', 3, 3), '',
          'SIGKILL with the count unchanged was somebody\'s kill');
  t.equal(pool.exitCause('SIGKILL', null, null), '',
          'and with no counter nothing is claimed');
  t.equal(pool.exitCause(null, 1, 2), '', 'an exit code is not a kill');
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
// 7 and 8. THE POOL: A WORKER FORKED WITH THE BUDGET AND ABORTED AT IT, AND A
// SIGKILL WHILE THE OOM COUNTER ROSE.
// ---------------------------------------------------------------------------
const STUB = [
  "'use strict';",
  "const http = require('http');",
  "const v8 = require('v8');",
  "process.on('message', function (m) {",
  "  if (!m || !m.begin) { return; }",
  "  const limit = Math.round(v8.getHeapStatistics().heap_size_limit /",
  "                          1048576);",
  "  process.send({ memoryReport: { role: 'protocol worker',",
  "    pid: process.pid, rssMb: 1, heapUsedMb: 1, heapTotalMb: 1,",
  "    externalMb: 0, arrayBuffersMb: 0, heapLimitMb: limit,",
  "    at: Date.now() } });",
  "  if (process.env.STUB_MODE === 'fill') {",
  "    setTimeout(function () {",
  "      const hold = [];",
  "      for (;;) { hold.push(new Array(100000).fill(Math.random())); }",
  "    }, 200);",
  "    return;",
  "  }",
  "  const server = http.createServer(function (req, res) {",
  "    res.end(String(process.pid));",
  "  });",
  "  server.listen(m.socket, function () { process.send({ ready: true }); });",
  "});",
  "process.on('disconnect', function () { process.exit(0); });",
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
  t.log.info('=== a worker forked with the budget is aborted at it ===');
  await withEnv({ STS_WORKERS_REQUEST_COUNT: '0', STUB_MODE: 'fill',
                  STS_WORKERS_HEAP_LIMIT_MB: '64' }, async function () {
    pool.useWorkerModule(stub);
    t.equal(pool.stats().memory.heapLimitMb, 64,
            'the pool reads the budget from workers.heapLimitMb');
    const entry = pool.fork(pool.PROTOCOL_POOL, 0);
    t.check(await waitFor(function () {
      return !!lastExit();
    }, 30000), 'the worker that filled its heap exited', '');
    const exit = lastExit() || {};
    t.equal(exit.pid, entry.pid, 'it is that worker\'s exit');
    t.equal(exit.signal, 'SIGABRT', 'V8 aborted it');
    t.equal(exit.cause, 'STS-WORKER-0046', 'reported as the heap');
    t.check(exit.memory && exit.memory.heapLimitMb >= 64 &&
            exit.memory.heapLimitMb < 300,
            'it had been forked with the 64 MiB limit, and its report ' +
            'reached the front process', JSON.stringify(exit.memory));
  });
  log.debug("Leaving checkTheHeapExit().");
}

async function checkTheKernelKill(t, stub) {
  log.debug("Entering checkTheKernelKill().");
  t.log.info('=== a SIGKILL while the OOM count rises is the kernel ===');
  await withEnv({ STS_WORKERS_REQUEST_COUNT: '0', STUB_MODE: 'ok',
                  STS_WORKERS_HEAP_LIMIT_MB: '-1' }, async function () {
    pool.useWorkerModule(stub);
    let kills = 7;
    pool.useOomCounter(function () {
      return kills;
    });
    t.check(pool.stats().memory.heapLimitMb === 0,
            'with the limit OFF the pool forks with no budget', '');
    let entry = pool.fork(pool.PROTOCOL_POOL, 0);
    await entry.settled;
    t.check(entry.child.spawnargs.join(' ')
      .indexOf('--max-old-space-size') < 0,
    'and the worker was forked without the flag',
    entry.child.spawnargs.join(' '));
    t.check(!!entry.memory,
            'its memory report still reaches the front process', '');
    kills = 8;
    entry.child.kill('SIGKILL');
    t.check(await waitFor(function () {
      return !!lastExit();
    }, 10000), 'the killed worker was reaped', '');
    t.equal((lastExit() || {}).cause, 'STS-WORKER-0047',
            'a SIGKILL with the count risen is the OOM killer, with the ' +
            'limit off too');
    entry = pool.fork(pool.PROTOCOL_POOL, 0);
    await entry.settled;
    entry.child.kill('SIGKILL');
    t.check(await waitFor(function () {
      return pool.stats().memory.exits.length === 2;
    }, 10000), 'the second was reaped too', '');
    t.equal((lastExit() || {}).cause, null,
            'with the count unchanged it was somebody\'s kill, and nothing ' +
            'more is claimed');
  });
  log.debug("Leaving checkTheKernelKill().");
}

async function run(t) {
  log.debug("Entering run().");
  checkTheCgroup(t);
  checkTheBudget(t);
  checkTheFlag(t);
  checkTheCounter(t);
  checkTheCause(t);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-process-memory-'));
  const stub = path.join(dir, 'stub-worker.js');
  fs.writeFileSync(stub, STUB);
  try {
    checkTheReexec(t, dir);
    await checkTheHeapExit(t, stub);
    await checkTheKernelKill(t, stub);
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
  describe: 'that every process gets a heap limit derived from the ' +
            'container (cgroup v2, v1, the ECS task), that the front ' +
            'process re-executes itself with it, that a worker is forked ' +
            'with it, and ' +
            'that a heap exhaustion and a kernel OOM kill are each reported ' +
            'under a code of their own (#341)',
  run: run
};
