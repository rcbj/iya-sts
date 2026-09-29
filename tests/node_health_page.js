// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: node_health_page.js
//
// ===========================================================================
// MONITORING → NODE HEALTH (#329): THE ARITHMETIC, THE SOURCES THAT ARE NOT
// THERE, AND EVERY PROCESS COUNTED.
//
// `admin-ui/node_health_admin.ts` reads a cgroup, `/proc`, every worker over
// the channel and the ECS task metadata endpoint. Its constructor takes each
// of those as a dependency, so this file hands it a cgroup of its own — a
// temporary directory of cgroup v2 files it rewrites between samples — a
// clock it moves, and pools that answer what it says. Nine claims:
//
//   1. CPU UTILISATION is CPU time over wall time against `cpu.max`'s
//      quota: two samples taken for a first page, the kept sample used by a
//      page a second later, and a fresh pair again for a sample over a minute
//      old or a counter that went backwards; throttling as a share of the
//      periods.
//   2. NO QUOTA, NO LIMIT: `cpu.max` of `max` is a share of
//      `os.availableParallelism()` and says so; `memory.max` of `max` gives
//      no percentage and says so.
//   3. A SOURCE THAT IS NOT THERE IS A SENTENCE — no cgroup, a v1 host
//      without a cpuacct controller,
//      not Linux, no ECS endpoint, an ECS endpoint that does not answer —
//      and never a zero.
//   4. THE PROCESS'S OWN CGROUP is found through `/proc/self/cgroup` when the
//      root is a host's.
//   5. EVERY PROCESS IS COUNTED: the front process, each worker that
//      answered and its post-quantum children from `/proc`, a worker that did
//      not answer listed as such, the debugger's api child, and the totals.
//   6. THE ECS FIGURES are the container's own stats in `/task/stats`,
//      against `/task`'s limits.
//   7. THE REAL CHANNEL carries a worker's `process.memoryUsage()` back
//      (`request_pool.askWorkerPoolStatus()` over a stub worker), the REAL
//      `request_worker.ts` sends it, and the page is drawn, pinned to the
//      front process and refused to a realm's own administrator.
//   8. A REAL POST-QUANTUM CHILD answers `worker_pool.askMemoryStatus()`
//      with its own figures, the question is not counted as a job, a child
//      computing a job is absent from a bounded answer, and the page draws
//      the child from its answer.
//   9. CGROUP V1 (Fargate's): cpuacct.usage against cfs_quota_us /
//      cfs_period_us, usage_in_bytes against limit_in_bytes and the rest,
//      found through controller-named hierarchies; v1's "no limit" sentinel
//      and a quota of -1 falling back to the ECS TASK's limits, said; no
//      cgroup at all on ECS drawn from the agent's figures, labelled; and
//      the cluster totals adding whichever each node reported.
//
// Section 5 also holds the children's rows: one that answered with its own
// five figures, the debugger's api child likewise, a busy one kept as a
// /proc row saying why. `tests/debugger_api_process.js` holds the preload
// that makes the debugger's api child answer.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const config = require('../common/config');
const requestPool = require('../common/request_pool');
const workerPool = require('../common/worker_pool');
const app = require('../common/app');
// Loading a module registers nothing since #50's R1, so the page's route is
// registered here. The console shell comes first, as in the composition root.
require('../admin-ui/admin').registerRoutes(app);
const nodeHealthAdmin = require('../admin-ui/node_health_admin');
nodeHealthAdmin.registerRoutes(app);
const adminScope = require('../admin-ui/admin_scope');

const NodeHealthAdmin = nodeHealthAdmin.NodeHealthAdmin;
const PROTO = requestPool.PROTOCOL_POOL;
const MIB = 1024 * 1024;

const log = require('bunyan').createLogger({
  name: 'node_health_page',
  level: process.env.LOG_LEVEL || 'info' });

// The stub request worker: `begin` in, `ready` out; `{ poolStatus }` answered
// with a post-quantum pool of one child and a memory of its own.
const STUB = [
  "'use strict';",
  "const http = require('http');",
  "process.on('message', function (m) {",
  "  if (m && m.poolStatus) {",
  "    process.send({ poolStatus: true, id: m.id, pid: process.pid,",
  "      pq: { configured: 1, running: 0, workers: [] },",
  "      memory: process.memoryUsage(), cpu: process.cpuUsage(),",
  "      uptimeS: 1 });",
  "    return;",
  "  }",
  "  if (m && m.stop) { process.exit(0); }",
  "  if (!m || !m.begin) { return; }",
  "  const server = http.createServer(function (req, res) { res.end(''); });",
  "  server.listen(m.socket, function () { process.send({ ready: true }); });",
  "});",
  "process.on('disconnect', function () { process.exit(0); });",
  ""
].join('\n');

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
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

// Every temporary directory made, removed when the file ends.
const tempDirs = [];

// A temporary directory holding `files` ({ relative path: text }).
function tree(files) {
  log.debug("Entering tree().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-node-health-'));
  tempDirs.push(dir);
  Object.keys(files).forEach(function (name) {
    const file = path.join(dir, name);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, files[name]);
  });
  log.debug("Leaving tree().");
  return dir;
}

function cpuStat(usageUsec) {
  log.debug("Entering cpuStat().");
  log.debug("Leaving cpuStat().");
  return 'usage_usec ' + usageUsec + '\nuser_usec ' + (usageUsec * 0.75) +
    '\nsystem_usec ' + (usageUsec * 0.25) + '\nnr_periods 200\n' +
    'nr_throttled 10\nthrottled_usec 3000000\n';
}

// A cgroup v2 directory of a container with two vCPUs and 1 GiB.
function aCgroup(overrides) {
  log.debug("Entering aCgroup().");
  const files = Object.assign({
    'cgroup.controllers': 'cpuset cpu io memory pids\n',
    'cpu.stat': cpuStat(10000000),
    'cpu.max': '200000 100000\n',
    'memory.current': String(512 * MIB) + '\n',
    'memory.max': String(1024 * MIB) + '\n',
    'memory.peak': String(600 * MIB) + '\n',
    'memory.stat': 'anon ' + (300 * MIB) + '\nfile ' + (200 * MIB) +
                   '\nkernel ' + (12 * MIB) + '\nsock 0\n',
    'memory.events': 'low 0\nhigh 0\nmax 0\noom 0\noom_kill 2\n'
  }, overrides || {});
  Object.keys(files).forEach(function (name) {
    if (files[name] === null) {
      delete files[name];
    }
  });
  log.debug("Leaving aCgroup().");
  return tree(files);
}

// Pools that answer nothing: no request worker, no post-quantum child.
function quietPools() {
  log.debug("Entering quietPools().");
  log.debug("Leaving quietPools().");
  return {
    requestPool: function () {
      return { stats: function () {
        return { workers: [] };
      }, askWorkerPoolStatus: function () {
        return Promise.resolve({});
      } };
    },
    workerPool: function () {
      return { stats: function () {
        return { workers: [] };
      } };
    },
    debuggerProcess: function () {
      return { status: function () {
        return { pid: null };
      } };
    }
  };
}

// An instance over `cgroupRoot`, a clock this file moves (and `onSleep` run
// while it "sleeps"), and whatever else `extra` replaces.
function anInstance(cgroupRoot, extra) {
  log.debug("Entering anInstance().");
  const clock = { us: 1000000000 };
  const deps = Object.assign(NodeHealthAdmin.defaultDeps(), quietPools(), {
    cgroupRoot: cgroupRoot,
    procRoot: tree({ 'self/cgroup': '0::/\n' }),
    platform: 'linux',
    ecsUri: function () {
      return '';
    },
    clockUs: function () {
      return clock.us;
    },
    sleep: function (ms) {
      clock.us += ms * 1000;
      if (clock.onSleep) {
        clock.onSleep();
      }
      return Promise.resolve();
    },
    availableParallelism: function () {
      return 4;
    }
  }, extra || {});
  const instance = new NodeHealthAdmin(deps);
  log.debug("Leaving anInstance().");
  return { instance: instance, clock: clock };
}

// ---------------------------------------------------------------------------
// 1. CPU UTILISATION, AND THE MEMORY FIGURES.
// ---------------------------------------------------------------------------
async function checkTheArithmetic(t) {
  log.debug("Entering checkTheArithmetic().");
  t.log.info('=== 1. CPU time over wall time against the quota; memory ' +
             'against the limit ===');
  const dir = aCgroup();
  const made = anInstance(dir);
  const clock = made.clock;
  // The first page: two samples 500 ms apart, between which the container
  // used 500 ms of CPU — one CPU of two.
  clock.onSleep = function () {
    fs.writeFileSync(path.join(dir, 'cpu.stat'), cpuStat(10500000));
  };
  let view = await made.instance.nodeHealthView();
  let cpu = view.cpu;
  t.equal(cpu.available, true, 'the CPU is read');
  t.equal(cpu.sampled, 'fresh-sample', 'the first page samples twice');
  t.equal(cpu.windowSeconds, 0.5, 'half a second apart');
  t.equal(cpu.limitVcpus, 2, 'cpu.max 200000/100000 is two vCPUs');
  t.equal(cpu.coresUsed, 1, 'one CPU was used');
  t.equal(cpu.utilisationPercent, 50, 'which is 50 % of the quota');
  t.equal(cpu.usageSeconds, 10.5, 'the cumulative CPU time in seconds');
  t.check(!!cpu.throttling && cpu.throttling.throttledPercentOfPeriods === 5 &&
          cpu.throttling.throttledSeconds === 3,
          'throttling is 10 of 200 periods, 3 s', JSON.stringify(cpu));
  // A second page a second later: the kept sample is used, and 1.5 s of CPU
  // in that second is 75 %.
  clock.onSleep = null;
  clock.us += 1000000;
  fs.writeFileSync(path.join(dir, 'cpu.stat'), cpuStat(12000000));
  view = await made.instance.nodeHealthView();
  cpu = view.cpu;
  t.equal(cpu.sampled, 'since-previous-sample',
          'a page a second later uses the kept sample');
  t.equal(cpu.windowSeconds, 1, 'over the second since');
  t.equal(cpu.utilisationPercent, 75, '1.5 CPUs of two is 75 %');
  // Over a minute later: a fresh pair, not an average over the minute.
  clock.us += 120 * 1000000;
  clock.onSleep = function () {
    fs.writeFileSync(path.join(dir, 'cpu.stat'), cpuStat(12100000));
  };
  view = await made.instance.nodeHealthView();
  t.check(view.cpu.sampled === 'fresh-sample' &&
          view.cpu.utilisationPercent === 10,
          'a sample over a minute old is not used; a fresh pair is (0.1 s ' +
          'in 0.5 s of two vCPUs is 10 %)', JSON.stringify(view.cpu));
  // A counter that went backwards (a new cgroup): a fresh pair again.
  clock.us += 1000000;
  fs.writeFileSync(path.join(dir, 'cpu.stat'), cpuStat(100));
  clock.onSleep = function () {
    fs.writeFileSync(path.join(dir, 'cpu.stat'), cpuStat(250100));
  };
  view = await made.instance.nodeHealthView();
  t.check(view.cpu.sampled === 'fresh-sample' &&
          view.cpu.utilisationPercent === 25,
          'a counter that went backwards is sampled afresh, not drawn as a ' +
          'negative', JSON.stringify(view.cpu));
  const mem = view.memory;
  t.equal(mem.available, true, 'the memory is read');
  t.equal(mem.currentBytes, 512 * MIB, 'memory.current');
  t.equal(mem.limitBytes, 1024 * MIB, 'memory.max');
  t.equal(mem.utilisationPercent, 50, '512 MiB of 1 GiB is 50 %');
  t.check(mem.anonBytes === 300 * MIB && mem.fileBytes === 200 * MIB &&
          mem.kernelBytes === 12 * MIB && mem.peakBytes === 600 * MIB &&
          mem.oomKills === 2,
          'anon, file, kernel, peak and oom_kill from their files',
          JSON.stringify(mem));
  t.check(view.cgroup === dir, 'the cgroup root is the container\'s when ' +
          '/proc/self/cgroup says 0::/', view.cgroup);
  log.debug("Leaving checkTheArithmetic().");
}

// ---------------------------------------------------------------------------
// 2. NO QUOTA AND NO LIMIT.
// ---------------------------------------------------------------------------
async function checkNoLimits(t) {
  log.debug("Entering checkNoLimits().");
  t.log.info('=== 2. no quota and no limit are said, not guessed ===');
  const dir = aCgroup({ 'cpu.max': 'max 100000\n', 'memory.max': 'max\n' });
  const made = anInstance(dir);
  made.clock.onSleep = function () {
    fs.writeFileSync(path.join(dir, 'cpu.stat'), cpuStat(11000000));
  };
  const view = await made.instance.nodeHealthView();
  t.check(view.cpu.limitVcpus === null &&
          view.cpu.limitSource === 'unlimited' &&
          view.cpu.percentOfVcpus === 4 &&
          view.cpu.utilisationPercent === 50 &&
          /os\.availableParallelism\(\)/.test(view.cpu.limitText),
          'cpu.max "max": the share is of the 4 CPUs node reports, and it ' +
          'says so (2 CPUs of 4 is 50 %)', JSON.stringify(view.cpu));
  t.check(view.memory.limitBytes === null &&
          view.memory.utilisationPercent === null &&
          /No memory limit/.test(view.memory.limitText),
          'memory.max "max": no percentage, and a sentence',
          JSON.stringify(view.memory));
  const bare = aCgroup({ 'cpu.max': null, 'memory.max': null });
  const again = anInstance(bare);
  const noFiles = await again.instance.nodeHealthView();
  t.check(noFiles.cpu.limitSource === 'no-cpu.max' &&
          /no cpu\.max/.test(noFiles.cpu.limitText) &&
          /no memory\.max/.test(noFiles.memory.limitText),
          'a cgroup with no cpu.max or memory.max says it has none',
          noFiles.cpu.limitText + ' / ' + noFiles.memory.limitText);
  log.debug("Leaving checkNoLimits().");
}

// ---------------------------------------------------------------------------
// 3. SOURCES THAT ARE NOT THERE.
// ---------------------------------------------------------------------------
async function checkUnavailable(t) {
  log.debug("Entering checkUnavailable().");
  t.log.info('=== 3. a source that is not there is a sentence, never a ' +
             'zero ===');
  const empty = tree({ 'nothing': '' });
  let view = await anInstance(empty).instance.nodeHealthView();
  t.check(view.cpu.available === false && view.memory.available === false &&
          /no cgroup v2/.test(view.cpu.unavailableText) &&
          !('utilisationPercent' in view.cpu) &&
          !('currentBytes' in view.memory),
          'no cgroup v2: both unavailable, with a sentence and no figure',
          JSON.stringify([view.cpu, view.memory]));
  // A cgroup v1 host with a memory controller and no cpuacct: its memory
  // is read (section 9 has the rest), and the CPU says what is missing.
  const v1 = tree({ 'memory/memory.usage_in_bytes': '1000\n' });
  view = await anInstance(v1).instance.nodeHealthView();
  t.check(view.memory.available === true && view.memory.cgroupVersion === 1 &&
          view.cpu.available === false &&
          /cpuacct/.test(view.cpu.unavailableText),
          'a cgroup v1 host is read as one, and a missing controller is said',
          JSON.stringify([view.memory.cgroupVersion,
                          view.cpu.unavailableText]));
  view = await anInstance(aCgroup(), { platform: 'darwin' }).instance
    .nodeHealthView();
  t.check(view.cpu.available === false && /not running on Linux/.test(
    view.cpu.unavailableText), 'not Linux says so', view.cpu.unavailableText);
  const noCurrent = aCgroup({ 'memory.current': null });
  view = await anInstance(noCurrent).instance.nodeHealthView();
  t.check(view.memory.available === false &&
          /memory\.current/.test(view.memory.unavailableText),
          'a cgroup without memory.current says which file is missing',
          view.memory.unavailableText);
  t.check(view.ecs.available === false &&
          /ECS_CONTAINER_METADATA_URI_V4 is not set/.test(
            view.ecs.unavailableText),
          'no ECS endpoint is said in words', view.ecs.unavailableText);
  view = await anInstance(aCgroup(), {
    ecsUri: function () {
      return 'http://169.254.170.2/v4/abc';
    },
    fetchJson: function () {
      return Promise.reject(new Error('The operation was aborted due to ' +
                                      'timeout'));
    } }).instance.nodeHealthView();
  t.check(view.ecs.available === false &&
          view.ecs.errorCode === 'STS-CORE-0125' &&
          /did not answer/.test(view.ecs.unavailableText),
          'an ECS endpoint that does not answer is said, with its code',
          JSON.stringify(view.ecs));
  t.check(view.machine && /NOT the container/.test(view.machine.text),
          'the machine\'s own figures are labelled as not the container\'s',
          view.machine && view.machine.text);
  log.debug("Leaving checkUnavailable().");
}

// ---------------------------------------------------------------------------
// 4. THE PROCESS'S OWN CGROUP ON A HOST.
// ---------------------------------------------------------------------------
async function checkOwnCgroup(t) {
  log.debug("Entering checkOwnCgroup().");
  t.log.info('=== 4. the process\'s own cgroup, found through ' +
             '/proc/self/cgroup ===');
  const root = tree({
    'cgroup.controllers': 'cpu memory\n',
    'system.slice/sts.scope/cpu.stat': cpuStat(1000),
    'system.slice/sts.scope/cpu.max': '100000 100000\n',
    'system.slice/sts.scope/memory.current': String(64 * MIB) + '\n',
    'system.slice/sts.scope/memory.max': String(256 * MIB) + '\n'
  });
  const made = anInstance(root, {
    procRoot: tree({ 'self/cgroup': '0::/system.slice/sts.scope\n' }) });
  const view = await made.instance.nodeHealthView();
  t.check(view.cgroup === path.join(root, 'system.slice/sts.scope') &&
          view.memory.utilisationPercent === 25 &&
          view.cpu.limitVcpus === 1,
          'the directory /proc/self/cgroup names is read, not the host\'s ' +
          'root', JSON.stringify({ cgroup: view.cgroup,
                                   memory: view.memory.utilisationPercent }));
  log.debug("Leaving checkOwnCgroup().");
}

// ---------------------------------------------------------------------------
// 5. EVERY PROCESS OF THE NODE.
// ---------------------------------------------------------------------------
function memoryOf(rss, heap) {
  log.debug("Entering memoryOf().");
  log.debug("Leaving memoryOf().");
  return { rss: rss, heapUsed: heap, heapTotal: heap * 2, external: 1024,
           arrayBuffers: 512 };
}

async function checkEveryProcess(t) {
  log.debug("Entering checkEveryProcess().");
  t.log.info('=== 5. the front process, every worker, every child, and ' +
             'the totals ===');
  const status = function (kb) {
    return 'Name:\tnode\nVmHWM:\t' + (kb * 2) + ' kB\nVmRSS:\t' + kb +
      ' kB\n';
  };
  const proc = tree({ 'self/cgroup': '0::/\n',
                      '9000/status': status(10 * 1024),
                      '9001/status': status(20 * 1024) });
  const asked = {};
  const made = anInstance(aCgroup(), {
    procRoot: proc,
    pid: 4242,
    memoryUsage: function () {
      return memoryOf(100 * MIB, 40 * MIB);
    },
    cpuUsage: function () {
      return { user: 2000000, system: 500000 };
    },
    requestPool: function () {
      return {
        stats: function () {
          return { workers: [
            { pid: 5001, pool: 'protocol', ready: true },
            { pid: 5002, pool: 'protocol', ready: true },
            { pid: 5003, pool: 'surfaces', ready: true },
            { pid: 5004, pool: 'protocol', ready: false }] };
        },
        askWorkerPoolStatus: function (ms, options) {
          asked.workers = ms;
          asked.childMemory = options && options.childMemory;
          return Promise.resolve({
            // Asked its children, and the one it has was busy.
            5001: { pq: { workers: [{ pid: 9001, inFlight: 1 }] },
                    pqMemory: {},
                    memory: memoryOf(80 * MIB, 30 * MIB),
                    cpu: { user: 1000000, system: 0 }, uptimeS: 60 },
            // Answered without asking its child (an older worker).
            5003: { pq: { workers: [{ pid: 9003, inFlight: 0 }] },
                    memory: memoryOf(70 * MIB, 20 * MIB),
                    cpu: null, uptimeS: 60 }
          });
        }
      };
    },
    workerPool: function () {
      return {
        stats: function () {
          return { workers: [{ pid: 9000, inFlight: 0 }] };
        },
        askMemoryStatus: function (ms) {
          asked.ownChildren = ms;
          return Promise.resolve({
            9000: { memory: memoryOf(15 * MIB, 5 * MIB),
                    cpu: { user: 300000, system: 100000 }, uptimeS: 30 } });
        }
      };
    },
    debuggerProcess: function () {
      return {
        status: function () {
          return { pid: 9002 };
        },
        askMemory: function (ms) {
          asked.debugger = ms;
          return Promise.resolve({ pid: 9002,
                                   memory: memoryOf(50 * MIB, 25 * MIB),
                                   cpu: { user: 0, system: 0 },
                                   uptimeS: 90 });
        }
      };
    }
  });
  const view = await made.instance.nodeHealthView();
  const p = view.processes;
  const byPid = function (pid) {
    return p.rows.filter(function (r) {
      return r.pid === pid;
    })[0];
  };
  const roles = p.rows.map(function (r) {
    return r.pid + ':' + r.role;
  });
  t.check(asked.workers === 1000 && asked.childMemory === 500 &&
          asked.ownChildren === 500 && asked.debugger === 500,
          'the workers are asked within a second, and told to ask their ' +
          'children within half of one; the front process\'s children and ' +
          'the debugger within half a second', JSON.stringify(asked));
  t.check(p.rows[0].pid === 4242 && p.rows[0].role === 'front process' &&
          p.rows[0].heapUsedBytes === 40 * MIB &&
          p.rows[0].cpuUserSeconds === 2,
          'the front process is first, with its own memoryUsage() and CPU',
          JSON.stringify(p.rows[0]));
  t.check(roles.indexOf('5001:request worker') >= 0 &&
          roles.indexOf('5003:hosted-surface worker') >= 0,
          'each worker that answered is a row, by its pool', roles.join());
  t.check(roles.indexOf('9000:post-quantum worker of pid 4242') >= 0 &&
          roles.indexOf('9001:post-quantum worker of pid 5001') >= 0 &&
          roles.indexOf('9003:post-quantum worker of pid 5003') >= 0 &&
          roles.indexOf('9002:protocol debugger api') >= 0,
          'the post-quantum children of the front process and of each ' +
          'worker, and the debugger\'s api, are rows', roles.join());
  const own = byPid(9000);
  t.check(own.source === 'process.memoryUsage()' &&
          own.rssBytes === 15 * MIB && own.heapUsedBytes === 5 * MIB &&
          own.heapTotalBytes === 10 * MIB && own.externalBytes === 1024 &&
          own.arrayBuffersBytes === 512 && own.cpuUserSeconds === 0.3 &&
          own.uptimeSeconds === 30,
          'a post-quantum child that answered reports its own five figures, ' +
          'CPU time and uptime', JSON.stringify(own));
  const dbg = byPid(9002);
  t.check(dbg.source === 'process.memoryUsage()' &&
          dbg.heapUsedBytes === 25 * MIB && dbg.rssBytes === 50 * MIB,
          'so does the debugger\'s api child', JSON.stringify(dbg));
  const busy = byPid(9001);
  t.check(busy.rssBytes === 20 * MIB && busy.peakRssBytes === 40 * MIB &&
          busy.heapUsedBytes === null &&
          busy.source === '/proc/9001/status' &&
          /computing a job/.test(busy.notReported) &&
          /did not answer within 500ms/.test(busy.notReported),
          'a child that was busy keeps its /proc row, heap null not zero, ' +
          'and says why', JSON.stringify(busy));
  const unasked = byPid(9003);
  t.check(unasked.rssBytes === null &&
          /could not be read/.test(unasked.unreadable) &&
          /its parent did not ask it/.test(unasked.notReported),
          'a child its worker did not ask, whose /proc entry cannot be ' +
          'read, says both', JSON.stringify(unasked));
  t.check(p.unanswered.length === 1 && p.unanswered[0].pid === 5002 &&
          /did not answer within 1000ms/.test(p.unanswered[0].why),
          'the worker that did not answer is listed as unanswered, and one ' +
          'not yet ready is not asked', JSON.stringify(p.unanswered));
  t.equal(p.totals.processes, 7, 'seven processes in all');
  t.equal(p.totals.rssBytes, (100 + 80 + 70 + 15 + 20 + 50) * MIB,
          'the resident total is the sum of every size that was read');
  t.equal(p.totals.processesWithRss, 6, 'six of them had a size');
  t.equal(p.totals.heapUsedBytes, (40 + 30 + 20 + 5 + 25) * MIB,
          'the heap total is the five processes that reported one');
  t.equal(p.totals.processesWithHeap, 5, 'five reported a heap');
  t.check(/counted once for each/.test(p.totalsText),
          'and the page says shared pages are counted more than once', '');
  log.debug("Leaving checkEveryProcess().");
}

// ---------------------------------------------------------------------------
// 6. THE ECS TASK METADATA ENDPOINT.
// ---------------------------------------------------------------------------
async function checkEcs(t) {
  log.debug("Entering checkEcs().");
  t.log.info('=== 6. the ECS endpoint\'s own figures, as a cross-check ===');
  const asked = [];
  const answers = {
    '': { DockerId: 'abc123', Limits: { CPU: 1024, Memory: 2048 } },
    '/task': { Limits: { CPU: 1, Memory: 2048 } },
    '/task/stats': { abc123: {
      read: '2026-09-28T12:00:00Z',
      memory_stats: { usage: 700 * MIB, limit: 2048 * MIB },
      cpu_stats: { cpu_usage: { total_usage: 3000000000 },
                   system_cpu_usage: 20000000000, online_cpus: 2 },
      precpu_stats: { cpu_usage: { total_usage: 2500000000 },
                      system_cpu_usage: 18000000000 } },
      other: {} }
  };
  const made = anInstance(aCgroup(), {
    ecsUri: function () {
      return 'http://169.254.170.2/v4/abc123/';
    },
    fetchJson: function (url, ms) {
      asked.push(url + ' ' + ms);
      const suffix = url.replace('http://169.254.170.2/v4/abc123', '');
      return Promise.resolve(answers[suffix]);
    } });
  const view = await made.instance.nodeHealthView();
  const e = view.ecs;
  t.check(asked.length === 3 && asked.every(function (one) {
    return / 1000$/.test(one);
  }), 'the container, /task and /task/stats are each asked with a ' +
      'one-second bound', asked.join(', '));
  t.check(e.available === true && e.dockerId === 'abc123' &&
          e.taskLimits.cpuVcpus === 1 && e.taskLimits.memoryMiB === 2048,
          'the task\'s limits', JSON.stringify(e));
  t.check(e.stats.memoryUsageBytes === 700 * MIB &&
          e.stats.memoryLimitBytes === 2048 * MIB &&
          e.stats.cpuCoresUsed === 0.5 &&
          e.stats.cpuPercentOfTaskLimit === 50,
          'this container\'s stats: memory, and 0.5 CPUs of a one-vCPU task ' +
          'from the two samples docker keeps', JSON.stringify(e.stats));
  t.equal(e.unavailableText, null, 'and nothing said missing');
  log.debug("Leaving checkEcs().");
}

// ---------------------------------------------------------------------------
// 7. THE REAL CHANNEL, THE REAL WORKER, AND THE PAGE.
// ---------------------------------------------------------------------------
function draw(query) {
  log.debug("Entering draw().");
  const layer = (app._router.stack || []).filter(function (one) {
    return one.route && one.route.path === '/admin/node-health' &&
           one.route.methods.get;
  })[0];
  if (!layer) {
    log.debug("Leaving draw(). No route.");
    return Promise.resolve(null);
  }
  return new Promise(function (resolve) {
    const res = {
      statusCode: 200,
      set: function () {
        return this;
      },
      status: function (code) {
        this.statusCode = code;
        return this;
      },
      type: function () {
        return this;
      },
      send: function (text) {
        resolve({ status: this.statusCode, body: String(text) });
        return this;
      },
      json: function (value) {
        resolve({ status: this.statusCode, body: JSON.stringify(value) });
        return this;
      },
      get: function () {
        return undefined;
      },
      getHeader: function () {
        return undefined;
      },
      setHeader: function () {
        return undefined;
      },
      locals: {}
    };
    const req = { query: query, headers: {}, method: 'GET', cookies: {},
                  url: '/admin/node-health',
                  originalUrl: '/admin/node-health',
                  path: '/admin/node-health',
                  get: function () {
                    return '';
                  } };
    layer.route.stack[0].handle(req, res, function (e) {
      log.debug("The page's handler called next(): " +
                ((e && e.message) || e));
      resolve(null);
    });
    log.debug("Leaving draw().");
  });
}

async function checkTheChannelAndThePage(t) {
  log.debug("Entering checkTheChannelAndThePage().");
  t.log.info('=== 7. the channel carries a worker\'s memory; the page is ' +
             'drawn, pinned and a service page ===');
  const stubPath = path.join(os.tmpdir(), 'sts-stub-health-' + process.pid +
                             '.js');
  fs.writeFileSync(stubPath, STUB);
  const had = process.env.STS_WORKERS_REQUEST_COUNT;
  process.env.STS_WORKERS_REQUEST_COUNT = '1';
  requestPool.reset();
  requestPool.useWorkerModule(stubPath);
  try {
    requestPool.fork(PROTO, 0);
    t.check(await waitFor(function () {
      return requestPool.workerTable().some(function (one) {
        return one.ready;
      });
    }, 10000), 'a stub worker comes up', '');
    const answers = await requestPool.askWorkerPoolStatus(1000);
    const pids = Object.keys(answers);
    const one = pids.length === 1 ? answers[pids[0]] : null;
    t.check(!!one && one.memory && one.memory.rss > 0 &&
            one.memory.heapUsed > 0 && !!one.cpu && one.uptimeS === 1,
            'askWorkerPoolStatus() hands back the worker\'s memory, CPU ' +
            'time and uptime', JSON.stringify(answers));
    const view = await nodeHealthAdmin.nodeHealthView();
    t.check(view.processes.rows.some(function (r) {
      return r.role === 'request worker' && r.rssBytes > 0;
    }), 'the real page lists that worker with its memory',
    JSON.stringify(view.processes.rows));
  } finally {
    await requestPool.stop(3000);
    requestPool.reset();
    if (had === undefined) {
      delete process.env.STS_WORKERS_REQUEST_COUNT;
    } else {
      process.env.STS_WORKERS_REQUEST_COUNT = had;
    }
    try {
      fs.unlinkSync(stubPath);
    } catch (e) {
      log.debug("Caught in checkTheChannelAndThePage(): " +
                ((e && e.message) || e));
    }
  }
  // The real worker sends what the stub sends: its compiled source, read as
  // a statement (the tests image compiled request_worker.ts beside it).
  const compiled = path.join(__dirname, '..', 'common', 'request_worker.js');
  const source = fs.readFileSync(fs.existsSync(compiled)
    ? compiled : compiled.replace(/\.js$/, '.ts'), 'utf8');
  // The method's definition, not the call to it in the message handler.
  const at = source.search(/reportPoolStatus\(message[^)]*\)[^{;]*\{/);
  const body = at < 0 ? '' : source.slice(at);
  t.check(/process\.memoryUsage\(\)/.test(body.slice(0, 3000)) &&
          /memory:\s*memory,\s*cpu:\s*cpu/.test(body.slice(0, 3000)),
          'request_worker.ts answers { poolStatus } with its memoryUsage() ' +
          'and cpuUsage()', '');

  const page = await draw({});
  t.check(!!page && page.status === 200 && /id="cpu"/.test(page.body) &&
          /id="memory"/.test(page.body) && /id="processes"/.test(page.body) &&
          /id="ecs"/.test(page.body) && /id="machine"/.test(page.body),
          'the page draws its five sections', page ? page.body.slice(0, 300)
                                                    : 'no page');
  t.check(!!page && /ECS_CONTAINER_METADATA_URI_V4 is not set/.test(
    page.body) === !process.env.ECS_CONTAINER_METADATA_URI_V4,
  'here, with no ECS endpoint, the page says so in words', '');
  const asJson = await draw({ format: 'json' });
  const parsed = asJson ? JSON.parse(asJson.body) : {};
  t.check(parsed.scope === 'node' && parsed.pid === process.pid &&
          parsed.processes.rows[0].role === 'front process' &&
          (parsed.cpu.available || !!parsed.cpu.unavailableText) &&
          (parsed.memory.available || !!parsed.memory.unavailableText),
          '?format=json answers the view, naming the node\'s front process',
          JSON.stringify({ cpu: parsed.cpu, memory: parsed.memory }));
  const had2 = process.env.STS_WORKERS_DISPATCH;
  process.env.STS_WORKERS_DISPATCH = '*';
  try {
    t.check(requestPool.dispatched('/admin/caches') === true &&
            requestPool.dispatched('/admin/node-health') === false &&
            requestPool.dispatched('/realm/acme/admin/node-health') ===
              false &&
            requestPool.dispatched('/admin-api/node-health') === false,
            'with workers.dispatch=* the page and its API are still ' +
            'answered by the front process', '');
  } finally {
    if (had2 === undefined) {
      delete process.env.STS_WORKERS_DISPATCH;
    } else {
      process.env.STS_WORKERS_DISPATCH = had2;
    }
  }
  t.check(adminScope.pageIsService('/admin/node-health'),
          '/admin/node-health is a service page', '');
  const refusal = adminScope.refusalFor(
    { authority: 'realm', identityRealm: 'acme' }, '/admin/node-health',
    null, {});
  t.check(!!refusal && refusal.reason === 'service_page',
          'a realm administrator is refused it', JSON.stringify(refusal));
  log.debug("Leaving checkTheChannelAndThePage().");
}

// ---------------------------------------------------------------------------
// 8. A REAL POST-QUANTUM CHILD ANSWERS ITS MEMORY — AND A BUSY ONE DOES NOT.
// ---------------------------------------------------------------------------
function scryptJob(n) {
  log.debug("Entering scryptJob().");
  log.debug("Leaving scryptJob().");
  return { plaintext: 'node-health', salt: Buffer.from('0123456789abcdef'),
           keylen: 16, N: n, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };
}

async function checkRealPqChild(t) {
  log.debug("Entering checkRealPqChild().");
  t.log.info('=== 8. a real post-quantum child answers its memory status, ' +
             'which is not a job; a busy one does not ===');
  await workerPool.stop(3000);
  workerPool.reset();
  config.setOverride('workers.count', '1');
  try {
    await workerPool.run('scrypt.derive', scryptJob(1024));
    const before = workerPool.stats();
    const child = before.workers[0].pid;
    const answers = await workerPool.askMemoryStatus(2000);
    const one = answers[child];
    t.check(!!one && one.memory && one.memory.rss > 0 &&
            one.memory.heapUsed > 0 && one.memory.heapTotal > 0 &&
            typeof one.memory.external === 'number' &&
            typeof one.memory.arrayBuffers === 'number' && !!one.cpu &&
            typeof one.uptimeS === 'number',
            'the child answers with its own memoryUsage(), cpuUsage() and ' +
            'uptime', JSON.stringify(answers));
    const after = workerPool.stats();
    t.check(after.counts.jobs === before.counts.jobs &&
            after.counts.inProcess === before.counts.inProcess,
            'and the question is not counted as a job',
            JSON.stringify(after.counts));
    // A job of about 64 MiB of scrypt keeps the child computing well past a
    // 20 ms bound; the question sent after it is read only when it returns.
    const job = workerPool.run('scrypt.derive', scryptJob(65536));
    const busy = await workerPool.askMemoryStatus(20);
    t.check(!busy[child], 'a child computing a job is absent from an ' +
            'answer bounded shorter than the job', JSON.stringify(busy));
    await job;
    const view = await nodeHealthAdmin.nodeHealthView();
    const row = view.processes.rows.filter(function (r) {
      return r.pid === child;
    })[0];
    t.check(!!row && row.source === 'process.memoryUsage()' &&
            row.heapUsedBytes > 0 &&
            row.role === 'post-quantum worker of pid ' + process.pid,
            'the page draws it with its own figures, not /proc\'s',
            JSON.stringify(row));
  } finally {
    config.clearOverride('workers.count');
    await workerPool.stop(3000);
    workerPool.reset();
  }
  log.debug("Leaving checkRealPqChild().");
}

// ---------------------------------------------------------------------------
// 9. CGROUP V1, AND THE ECS TASK'S FIGURES (#329, as Fargate has it).
// ---------------------------------------------------------------------------
// A cgroup v1 container: a hierarchy per controller, `cpu,cpuacct` shared,
// each mounted at the container's own cgroup, and `/proc/self/cgroup`
// naming paths under them that do not exist inside it.
function aV1Cgroup(overrides) {
  log.debug("Entering aV1Cgroup().");
  const files = Object.assign({
    'memory/memory.usage_in_bytes': String(512 * MIB) + '\n',
    'memory/memory.limit_in_bytes': String(1024 * MIB) + '\n',
    'memory/memory.max_usage_in_bytes': String(700 * MIB) + '\n',
    'memory/memory.stat': 'cache ' + (90 * MIB) + '\nrss ' + (290 * MIB) +
      '\ntotal_cache ' + (100 * MIB) + '\ntotal_rss ' + (300 * MIB) + '\n',
    'memory/memory.oom_control': 'oom_kill_disable 0\nunder_oom 0\n' +
      'oom_kill 1\n',
    'memory/memory.kmem.usage_in_bytes': String(10 * MIB) + '\n',
    'cpu,cpuacct/cpuacct.usage': '10000000000\n',
    'cpu,cpuacct/cpu.cfs_quota_us': '200000\n',
    'cpu,cpuacct/cpu.cfs_period_us': '100000\n',
    'cpu,cpuacct/cpu.stat': 'nr_periods 100\nnr_throttled 4\n' +
      'throttled_time 2000000000\n'
  }, overrides || {});
  Object.keys(files).forEach(function (name) {
    if (files[name] === null) {
      delete files[name];
    }
  });
  log.debug("Leaving aV1Cgroup().");
  return tree(files);
}

const V1_SELF = '12:memory:/ecs/task/container\n' +
                '4:cpu,cpuacct:/ecs/task/container\n' +
                '1:name=systemd:/ecs/task/container\n';

// The ECS agent as Fargate answers: a two-vCPU, 8 GiB task whose container
// has no memory limit of its own (the agent's number near 2^63).
function anEcs(opts) {
  log.debug("Entering anEcs().");
  const o = opts || {};
  const answers = {
    '': { DockerId: 'c1', Limits: { CPU: 2 } },
    '/task': { Limits: { CPU: 2, Memory: 8192 } },
    '/task/stats': { c1: {
      memory_stats: { usage: 3019096064, limit: 9223372036854772000 },
      cpu_stats: { cpu_usage: { total_usage: 1112000000 },
                   system_cpu_usage: 40000000000, online_cpus: 2 },
      precpu_stats: { cpu_usage: { total_usage: 1000000000 },
                      system_cpu_usage: 36000000000 } } }
  };
  log.debug("Leaving anEcs().");
  return {
    ecsUri: function () {
      return 'http://169.254.170.2/v4/c1';
    },
    fetchJson: function (url) {
      if (o.fails) {
        return Promise.reject(new Error('timeout'));
      }
      return Promise.resolve(answers[url.replace(
        'http://169.254.170.2/v4/c1', '')]);
    }
  };
}

async function checkV1AndEcs(t) {
  log.debug("Entering checkV1AndEcs().");
  t.log.info('=== 9. cgroup v1, the task\'s limits where the cgroup has ' +
             'none, and the ECS agent\'s figures where there is no cgroup ===');
  // (a) cgroup v1 arithmetic.
  let dir = aV1Cgroup();
  let made = anInstance(dir, { procRoot: tree({ 'self/cgroup': V1_SELF }) });
  made.clock.onSleep = function () {
    fs.writeFileSync(path.join(dir, 'cpu,cpuacct', 'cpuacct.usage'),
                     '10500000000\n');
  };
  let view = await made.instance.nodeHealthView();
  t.check(view.cgroupVersion === 1 && view.cpu.cgroupVersion === 1 &&
          view.memory.cgroupVersion === 1 &&
          view.cgroup === path.join(dir, 'memory'),
          'a cgroup v1 container is found through its controller-named ' +
          'hierarchies, and says it is v1', JSON.stringify({
            v: view.cgroupVersion, cgroup: view.cgroup }));
  t.check(view.cpu.available && view.cpu.limitVcpus === 2 &&
          view.cpu.coresUsed === 1 && view.cpu.utilisationPercent === 50 &&
          view.cpu.usageSeconds === 10.5 &&
          view.cpu.throttling.throttledPercentOfPeriods === 4 &&
          view.cpu.throttling.throttledSeconds === 2 &&
          /cgroup v1, cpu\.cfs_quota_us \/ cpu\.cfs_period_us/.test(
            view.cpu.limitText),
          'v1 CPU: cpuacct.usage in nanoseconds over the window against ' +
          'cfs_quota_us / cfs_period_us (1 CPU of 2 is 50 %), throttled_time ' +
          'in nanoseconds', JSON.stringify(view.cpu));
  t.check(view.memory.available && view.memory.currentBytes === 512 * MIB &&
          view.memory.limitBytes === 1024 * MIB &&
          view.memory.utilisationPercent === 50 &&
          view.memory.anonBytes === 300 * MIB &&
          view.memory.fileBytes === 100 * MIB &&
          view.memory.peakBytes === 700 * MIB &&
          view.memory.kernelBytes === 10 * MIB &&
          view.memory.oomKills === 1 &&
          /memory\.limit_in_bytes/.test(view.memory.limitText),
          'v1 memory: usage_in_bytes against limit_in_bytes, total_rss and ' +
          'total_cache, max_usage_in_bytes as the peak, oom_control\'s ' +
          'oom_kill', JSON.stringify(view.memory));
  // (b) v1 with no limit and no quota, on ECS: the task's limits.
  dir = aV1Cgroup({ 'memory/memory.limit_in_bytes': '9223372036854771712\n',
                    'cpu,cpuacct/cpu.cfs_quota_us': '-1\n' });
  made = anInstance(dir, Object.assign({
    procRoot: tree({ 'self/cgroup': V1_SELF }) }, anEcs()));
  made.clock.onSleep = function () {
    fs.writeFileSync(path.join(dir, 'cpu,cpuacct', 'cpuacct.usage'),
                     '10500000000\n');
  };
  view = await made.instance.nodeHealthView();
  t.check(view.memory.limitBytes === 8192 * MIB &&
          view.memory.limitSource === 'ecs-task' &&
          view.memory.utilisationPercent === 6.3 &&
          /ECS TASK's, 8192 MiB/.test(view.memory.limitText),
          'v1\'s "no limit" sentinel falls back to the ECS task\'s 8 GiB, ' +
          'and says so (512 MiB is 6.3 %)', JSON.stringify(view.memory));
  t.check(view.cpu.limitVcpus === null && view.cpu.percentOfVcpus === 2 &&
          view.cpu.limitSource === 'ecs-task' &&
          view.cpu.utilisationPercent === 50 &&
          /ECS TASK's 2 vCPU/.test(view.cpu.limitText),
          'a quota of -1 falls back to the ECS task\'s 2 vCPU',
          JSON.stringify(view.cpu));
  t.check(view.ecs.stats.memoryLimitBytes === null &&
          view.ecs.stats.memoryLimitUnlimited === true,
          'the agent\'s own "no limit" number is said as none, not drawn',
          JSON.stringify(view.ecs.stats));
  const v1Node = view;
  // (c) No cgroup at all, on ECS: the agent's figures, labelled as its.
  made = anInstance(tree({ 'nothing': '' }), anEcs());
  view = await made.instance.nodeHealthView();
  t.check(view.memory.available && view.memory.fromEcs === true &&
          view.memory.currentBytes === 3019096064 &&
          view.memory.limitBytes === 8192 * MIB &&
          view.memory.utilisationPercent === 35.1 &&
          /ECS agent/.test(view.memory.limitText) &&
          /no cgroup/.test(view.memory.cgroupUnavailableText),
          'no cgroup: memory from the ECS agent, against the task\'s ' +
          'limit, labelled as ECS\'s', JSON.stringify(view.memory));
  t.check(view.cpu.available && view.cpu.fromEcs === true &&
          view.cpu.coresUsed === 0.056 && view.cpu.percentOfVcpus === 2 &&
          view.cpu.utilisationPercent === 2.8 && view.cpu.sampled === 'ecs',
          'and CPU from the agent\'s two samples, against the task\'s ' +
          '2 vCPU (0.056 of 2 is 2.8 %)', JSON.stringify(view.cpu));
  const page = await (async function () {
    return made.instance.html(view);
  })();
  t.check(/ECS agent/.test(page) && !/Not available/.test(
    page.slice(page.indexOf('id="cpu"'), page.indexOf('id="processes"'))),
          'the page draws both from the agent, not as unavailable', '');
  // (d) The cluster's totals use whichever each node reported.
  const totals = NodeHealthAdmin.totalsOf([
    { name: 'a', state: 'live', view: v1Node },
    { name: 'b', state: 'live', view: view }]);
  t.check(totals.memoryNodes === 2 &&
          totals.memoryUsedBytes === 512 * MIB + 3019096064 &&
          totals.memoryLimitBytes === 16384 * MIB &&
          totals.cpuNodes === 2 && totals.cpuOf === 4 &&
          totals.cpuCoresUsed === 1.056,
          'the cluster totals add a v1 node with the task\'s limit and an ' +
          'ECS-only node', JSON.stringify(totals));
  // (e) No cgroup and no ECS: still unavailable, in words.
  made = anInstance(tree({ 'nothing': '' }), anEcs({ fails: true }));
  view = await made.instance.nodeHealthView();
  t.check(!view.memory.available && !view.cpu.available &&
          /no cgroup/.test(view.memory.unavailableText),
          'no cgroup and an ECS endpoint that does not answer: unavailable, ' +
          'said', view.memory.unavailableText);
  log.debug("Leaving checkV1AndEcs().");
}

async function run(t) {
  log.debug("Entering run().");
  await checkTheArithmetic(t);
  await checkNoLimits(t);
  await checkUnavailable(t);
  await checkOwnCgroup(t);
  await checkEveryProcess(t);
  await checkEcs(t);
  await checkV1AndEcs(t);
  try {
    await checkTheChannelAndThePage(t);
    await checkRealPqChild(t);
  } finally {
    tempDirs.forEach(function (dir) {
      fs.rmSync(dir, { recursive: true, force: true });
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'node_health_page',
  describe: 'Monitoring → Node Health (#329): CPU utilisation from cpu.stat ' +
            'against cpu.max, memory against memory.max, a source that is ' +
            'not there said in words, every process of the node counted ' +
            'with its memory, the ECS cross-check, the channel, and the page ' +
            'pinned to the front process and refused to a realm ' +
            'administrator',
  run: run
};
