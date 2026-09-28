// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: node_health_admin.ts
//
// ===========================================================================
// MONITORING → NODE HEALTH (#329, 2026-09-28): THE CONTAINER'S CPU AND
// MEMORY, AND THE MEMORY OF EVERY NODE.JS PROCESS IN IT.
//
// `GET /admin/node-health` draws four things, each from the one source that
// actually describes it:
//
//   * CPU UTILISATION OF THE CONTAINER — cgroup v2's `cpu.stat`
//     (`usage_usec`, the CPU time every process of the cgroup has used)
//     sampled over an interval, against the quota in `cpu.max` (quota /
//     period is the vCPUs the container may use). Throttling
//     (`nr_throttled`, `throttled_usec`) beside it where the file has it.
//   * MEMORY OF THE CONTAINER — `memory.current` against `memory.max`, and
//     `memory.stat`'s `anon`, `file` and `kernel`, which say whether what is
//     in use is the processes' own or page cache the kernel will give back.
//   * THE NODE.JS MEMORY OF EVERY PROCESS — `process.memoryUsage()` of the
//     front process and of each request and hosted-surface worker, which
//     answer over the channel #327 added (`{ poolStatus }`, bounded at a
//     second, a silent worker listed as unanswered); and the same figures
//     from every post-quantum child and the debugger's api child, each asked
//     over its own channel (`worker_pool.askMemoryStatus()` — a control
//     message, not a job — and `debugger_api_process.askMemory()`, answered
//     by a preload), bounded at half a second. A child that does not answer
//     in time — a post-quantum worker computing a job cannot — is drawn with
//     its resident size from `/proc/<pid>/status` and the reason. The totals
//     across them.
//   * THE ECS TASK METADATA ENDPOINT, where the platform sets
//     `ECS_CONTAINER_METADATA_URI_V4` — its `/task/stats` and `/task`, as a
//     cross-check of the cgroup figures from the agent's side. It needs no
//     IAM; locally it is absent and the page says so.
//
// **NOT `os.totalmem()`, `os.freemem()` OR `os.loadavg()` AS THE
// CONTAINER'S.** On Fargate they describe the micro-VM the task runs in, and
// on a workstation the whole machine: a container at its memory limit can
// read as a machine with gigabytes free. They are drawn in a section of their
// own labelled as the machine's, and never beside a container figure.
//
// **A SOURCE THAT IS NOT THERE IS SAID IN A SENTENCE, NEVER DRAWN AS ZERO.**
// No cgroup v2 (a cgroup v1 host, or not Linux at all), no `cpu.max` (no
// quota — then the vCPUs are `os.availableParallelism()`, and the page says
// that is what the percentage is of), `memory.max` of `max` (no limit, so no
// percentage), no ECS endpoint, a worker that did not answer, a child whose
// `/proc` entry could not be read: each is `available: false` or `null` and
// a sentence, because a zero would read as an idle container rather than an
// unmeasured one.
//
// **CPU UTILISATION NEEDS TWO SAMPLES, AND THE PAGE NEVER WAITS LONG FOR
// THEM.** This instance keeps the previous sample; a page drawn between a
// quarter of a second and a minute after it reports the utilisation since
// then. Otherwise — the first load, a reload within 250 ms, a sample older
// than a minute (an average over an hour is not what an operator looking at
// a slow node wants) or a counter that went backwards — it samples twice,
// `SAMPLE_MS` apart, while the workers and the ECS endpoint are being asked,
// so the page is bounded by the slowest of the three and by a second.
//
// **THE NUMBERS ARE THIS NODE'S.** Each node of a cluster is a container of
// its own; the page names the host and the front process that drew it, and
// it is ALWAYS the front process: both paths are in `request_pool.js`'s
// `NEVER_DISPATCHED` beside Worker Pools', because only the front process
// knows the workers and can ask them. A request worker asks its OWN
// post-quantum children when the front process asks it (`childMemory`),
// within ASK_CHILDREN_MS, which is under the front process's bound.
//
// **A SERVICE PAGE** (`admin_scope.ts`): the container is the process's, so a
// realm's own administrator is refused it. No control and no POST.
//
// **THE ECS ENDPOINT IS DIALLED DIRECTLY, not through
// `common/outbound_tls.ts`.** That module decides the transport of requests
// to an address somebody else answers — a registered or configured peer. This
// is the platform's own agent on the task's link-local address, named by an
// environment variable the platform sets and no request or setting can
// change, it offers no TLS, and nothing is sent to it but a GET. It is not a
// URL a caller supplied (root `CLAUDE.md`, *Things this service deliberately
// does not do*).
//
// Rule 7: `GET /admin-api/node-health` answers `nodeHealthView()`, the
// function the page's `?format=json` answers.
//
// TYPESCRIPT, AS A CLASS (#50): `worker_pools_admin.ts`'s shape —
// dependencies through the constructor, `registerRoutes(app)` called by
// `common/protocol_stack.ts` (18s), facades for the JavaScript callers. The
// file locations and the clock are dependencies so that
// `tests/node_health_page.js` can hand it a cgroup of its own.
// ===========================================================================

import os = require('os');
import fs = require('fs');
import path = require('path');
import admin = require('./admin');
import helpers = require('../common/helpers');
import errorCodes = require('../common/error_codes');
import InstanceSlot = require('../common/instance_slot');

type Req = any;
type Res = any;
type Json = any;

/**
 * The console path of Monitoring → Node Health.
 */
const PAGE = '/admin/node-health';

// How long the page waits for the request workers, and for each request to
// the ECS task metadata endpoint.
const ASK_WORKERS_MS = 1000;
// How long a post-quantum child or the debugger's api child is waited for,
// by the front process and by each request worker for its own children —
// under ASK_WORKERS_MS, so a worker's answer can include its children's.
const ASK_CHILDREN_MS = 500;
const ECS_TIMEOUT_MS = 1000;
// The interval between two CPU samples taken for one page, and the ages
// between which a kept sample is used instead.
const SAMPLE_MS = 500;
const MIN_WINDOW_US = 250 * 1000;
const MAX_WINDOW_US = 60 * 1000 * 1000;

const MIB = 1024 * 1024;

interface NodeHealthAdminDeps {
  log: typeof helpers.log;
  admin: typeof admin;
  errorCodes: typeof errorCodes;
  // LAZY, all three, as in `worker_pools_admin.ts`: by the time a page is
  // drawn each is in node's module cache.
  requestPool: () => any;
  workerPool: () => any;
  debuggerProcess: () => any;
  // A file's text, or a rejection (ENOENT for a file that is not there).
  readFile: (file: string) => Promise<string>;
  cgroupRoot: string;
  procRoot: string;
  // Read when a page is drawn, so the environment is the process's now.
  ecsUri: () => string;
  fetchJson: (url: string, timeoutMs: number) => Promise<any>;
  sleep: (ms: number) => Promise<void>;
  // Microseconds on a monotonic clock, for the CPU window.
  clockUs: () => number;
  now: () => number;
  pid: number;
  host: string;
  platform: string;
  memoryUsage: () => Json;
  cpuUsage: () => Json;
  uptimeS: () => number;
  availableParallelism: () => number;
  machine: () => Json;
  sampleMs: number;
}

/**
 * Monitoring → Node Health: the container's CPU and memory from its cgroup,
 * the Node.js memory of every process of the node, and the ECS task
 * metadata endpoint's figures as a cross-check.
 */
class NodeHealthAdmin {
  /**
   * See the module's `PAGE`.
   */
  static readonly PAGE = PAGE;

  // The previous CPU sample, and the cgroup it was read from.
  private lastCpu: { dir: string; usageUsec: number; atUs: number } | null =
    null;

  // Whether the ECS endpoint failed the last time it was asked, so that a
  // failure is logged when it starts rather than on every page.
  private ecsFailing = false;

  /**
   * Builds an instance over the modules it depends on.
   *
   * @param deps - the logger, the console, the pools, the files and clocks
   */
  constructor(private readonly deps: NodeHealthAdminDeps) {
    deps.log.debug("Entering NodeHealthAdmin.constructor().");
    deps.log.debug("Leaving NodeHealthAdmin.constructor().");
  }

  /**
   * Answers the real modules and locations the composition root passes to
   * the constructor.
   *
   * @returns the dependencies of a default instance
   */
  static defaultDeps(): NodeHealthAdminDeps {
    helpers.log.debug("Entering NodeHealthAdmin.defaultDeps().");
    const log = helpers.log;
    const deps: NodeHealthAdminDeps = {
      log: log,
      admin: admin,
      errorCodes: errorCodes,
      requestPool: function requestPool(): any {
        log.debug("Entering requestPool().");
        log.debug("Leaving requestPool().");
        return require('../common/request_pool');
      },
      workerPool: function workerPool(): any {
        log.debug("Entering workerPool().");
        log.debug("Leaving workerPool().");
        return require('../common/worker_pool');
      },
      debuggerProcess: function debuggerProcess(): any {
        log.debug("Entering debuggerProcess().");
        log.debug("Leaving debuggerProcess().");
        return require('../debugger/debugger_api_process');
      },
      readFile: function readFile(file: string): Promise<string> {
        log.debug("Entering readFile().");
        log.debug("Leaving readFile().");
        return fs.promises.readFile(file, 'utf8');
      },
      cgroupRoot: '/sys/fs/cgroup',
      procRoot: '/proc',
      ecsUri: function ecsUri(): string {
        log.debug("Entering ecsUri().");
        log.debug("Leaving ecsUri().");
        return String(process.env.ECS_CONTAINER_METADATA_URI_V4 || '');
      },
      fetchJson: function fetchJson(url: string, timeoutMs: number):
        Promise<any> {
        log.debug("Entering fetchJson().");
        log.debug("Leaving fetchJson().");
        return fetch(url, { signal: AbortSignal.timeout(timeoutMs) })
          .then(function (r: any): any {
            if (!r.ok) {
              throw new Error('it answered HTTP ' + r.status);
            }
            return r.json();
          });
      },
      sleep: function sleep(ms: number): Promise<void> {
        log.debug("Entering sleep().");
        log.debug("Leaving sleep().");
        return new Promise(function (resolve: () => void): void {
          setTimeout(resolve, ms);
        });
      },
      clockUs: function clockUs(): number {
        log.debug("Entering clockUs().");
        log.debug("Leaving clockUs().");
        return Number(process.hrtime.bigint() / BigInt(1000));
      },
      now: Date.now,
      pid: process.pid,
      host: os.hostname(),
      platform: process.platform,
      memoryUsage: function memoryUsage(): Json {
        log.debug("Entering memoryUsage().");
        log.debug("Leaving memoryUsage().");
        return process.memoryUsage();
      },
      cpuUsage: function cpuUsage(): Json {
        log.debug("Entering cpuUsage().");
        log.debug("Leaving cpuUsage().");
        return process.cpuUsage();
      },
      uptimeS: function uptimeS(): number {
        log.debug("Entering uptimeS().");
        log.debug("Leaving uptimeS().");
        return Math.round(process.uptime());
      },
      availableParallelism: function availableParallelism(): number {
        log.debug("Entering availableParallelism().");
        const fn = (os as any).availableParallelism;
        log.debug("Leaving availableParallelism().");
        return typeof fn === 'function' ? fn() : os.cpus().length;
      },
      machine: function machine(): Json {
        log.debug("Entering machine().");
        log.debug("Leaving machine().");
        return { loadavg: os.loadavg(), totalmemBytes: os.totalmem(),
                 freememBytes: os.freemem(), cpus: os.cpus().length };
      },
      sampleMs: SAMPLE_MS
    };
    helpers.log.debug("Leaving NodeHealthAdmin.defaultDeps().");
    return deps;
  }

  // A file's text, or null when it cannot be read — the reason kept.
  private read(file: string): Promise<{ text: string | null; why: string }> {
    const { log, readFile } = this.deps;
    log.debug("Entering NodeHealthAdmin.read(). " + file);
    log.debug("Leaving NodeHealthAdmin.read().");
    return readFile(file).then(function (text: string): Json {
      return { text: String(text), why: '' };
    }, function (e: any): Json {
      log.debug("Caught in NodeHealthAdmin.read(): " +
                ((e && e.message) || e));
      // Not there, or not readable: the caller says which source is
      // missing, in words.
      return { text: null,
               why: e && e.code === 'ENOENT' ? 'it is not there'
                                             : String((e && e.message) || e) };
    });
  }

  /**
   * Parses a cgroup file of `key value` lines (`cpu.stat`, `memory.stat`,
   * `memory.events`) into numbers.
   *
   * @param text - the file's text
   * @returns each key's value
   */
  static keyed(text: string): { [key: string]: number } {
    helpers.log.debug("Entering NodeHealthAdmin.keyed().");
    const out: { [key: string]: number } = {};
    String(text || '').split('\n').forEach(function (line: string): void {
      const parts = line.trim().split(/\s+/);
      if (parts.length === 2 && /^\d+$/.test(parts[1])) {
        out[parts[0]] = Number(parts[1]);
      }
    });
    helpers.log.debug("Leaving NodeHealthAdmin.keyed().");
    return out;
  }

  /**
   * Reads `cpu.max`: `max 100000` is no quota, `200000 100000` two vCPUs.
   *
   * @param text - the file's text
   * @returns the vCPUs, or null for no quota
   */
  static vcpusOf(text: string): number | null {
    helpers.log.debug("Entering NodeHealthAdmin.vcpusOf().");
    const parts = String(text || '').trim().split(/\s+/);
    const quota = Number(parts[0]);
    const period = Number(parts[1]);
    if (parts[0] === 'max' || !(quota > 0) || !(period > 0)) {
      helpers.log.debug("Leaving NodeHealthAdmin.vcpusOf(). No quota.");
      return null;
    }
    helpers.log.debug("Leaving NodeHealthAdmin.vcpusOf().");
    return quota / period;
  }

  // One decimal place, as a number.
  private static round1(n: number): number {
    helpers.log.debug("Entering NodeHealthAdmin.round1().");
    helpers.log.debug("Leaving NodeHealthAdmin.round1().");
    return Math.round(n * 10) / 10;
  }

  /**
   * Finds the directory of this process's cgroup v2: the one
   * `/proc/self/cgroup` names under the cgroup root when that directory has
   * the files (a host, or a container sharing the host's cgroup namespace),
   * and otherwise the root itself (a container with a cgroup namespace of
   * its own, where the root is the container).
   *
   * @returns `{ dir }`, or `{ dir: null, why }` when there is no cgroup v2
   */
  async cgroupDir(): Promise<{ dir: string | null; why: string }> {
    const { log, cgroupRoot, procRoot, platform } = this.deps;
    log.debug("Entering NodeHealthAdmin.cgroupDir().");
    if (platform !== 'linux') {
      log.debug("Leaving NodeHealthAdmin.cgroupDir(). Not Linux.");
      return { dir: null, why: 'This node is not running on Linux (' +
        platform + '), so there are no cgroup files to read.' };
    }
    const controllers = await this.read(path.join(cgroupRoot,
                                                  'cgroup.controllers'));
    if (controllers.text === null) {
      const v1 = await this.read(path.join(cgroupRoot, 'memory',
                                           'memory.usage_in_bytes'));
      log.debug("Leaving NodeHealthAdmin.cgroupDir(). No cgroup v2.");
      return { dir: null, why: v1.text !== null
        ? 'This host mounts cgroup v1 at ' + cgroupRoot + ', not cgroup ' +
          'v2, and this page reads only cgroup v2.'
        : 'There is no cgroup v2 at ' + cgroupRoot + ' (' +
          controllers.why + ').' };
    }
    const self = await this.read(path.join(procRoot, 'self', 'cgroup'));
    const line = String(self.text || '').split('\n').filter(
      function (one: string): boolean {
        return one.indexOf('0::') === 0;
      })[0];
    const rel = line ? line.slice(3).trim() : '/';
    if (rel && rel !== '/') {
      const candidate = path.join(cgroupRoot, rel);
      const has = await this.read(path.join(candidate, 'memory.current'));
      if (has.text !== null) {
        log.debug("Leaving NodeHealthAdmin.cgroupDir(). " + candidate);
        return { dir: candidate, why: '' };
      }
    }
    log.debug("Leaving NodeHealthAdmin.cgroupDir(). The root.");
    return { dir: cgroupRoot, why: '' };
  }

  // `cpu.stat`'s cumulative usage, and when it was read.
  private async cpuSample(dir: string):
    Promise<{ stat: Json | null; atUs: number; why: string }> {
    const { log, clockUs } = this.deps;
    log.debug("Entering NodeHealthAdmin.cpuSample().");
    const read = await this.read(path.join(dir, 'cpu.stat'));
    const atUs = clockUs();
    if (read.text === null) {
      log.debug("Leaving NodeHealthAdmin.cpuSample(). Unreadable.");
      return { stat: null, atUs: atUs, why: read.why };
    }
    const stat = NodeHealthAdmin.keyed(read.text);
    log.debug("Leaving NodeHealthAdmin.cpuSample().");
    return { stat: 'usage_usec' in stat ? stat : null, atUs: atUs,
             why: 'usage_usec' in stat ? '' : 'it has no usage_usec' };
  }

  /**
   * The container's CPU: utilisation over a window, against the quota.
   *
   * @param dir - the cgroup directory, or null when there is none
   * @param why - the sentence for no cgroup
   * @returns the CPU view
   */
  async cpuView(dir: string | null, why: string): Promise<Json> {
    const { log, sleep, sampleMs, availableParallelism } = this.deps;
    log.debug("Entering NodeHealthAdmin.cpuView().");
    if (!dir) {
      log.debug("Leaving NodeHealthAdmin.cpuView(). No cgroup.");
      return { available: false, unavailableText: why };
    }
    let current = await this.cpuSample(dir);
    if (!current.stat) {
      log.debug("Leaving NodeHealthAdmin.cpuView(). No cpu.stat.");
      return { available: false, source: path.join(dir, 'cpu.stat'),
               unavailableText: 'The container\'s CPU time cannot be read: ' +
                 path.join(dir, 'cpu.stat') + ' — ' + current.why + '.' };
    }
    const kept = this.lastCpu;
    let previous: { usageUsec: number; atUs: number };
    let how: string;
    const age = kept && kept.dir === dir ? current.atUs - kept.atUs : -1;
    if (kept && kept.dir === dir && age >= MIN_WINDOW_US &&
        age <= MAX_WINDOW_US &&
        current.stat.usage_usec >= kept.usageUsec) {
      previous = kept;
      how = 'since-previous-sample';
    } else {
      previous = { usageUsec: current.stat.usage_usec,
                   atUs: current.atUs };
      await sleep(sampleMs);
      const second = await this.cpuSample(dir);
      if (!second.stat) {
        log.debug("Leaving NodeHealthAdmin.cpuView(). Second read failed.");
        return { available: false, source: path.join(dir, 'cpu.stat'),
                 unavailableText: 'The container\'s CPU time could be read ' +
                   'once and not a second time: ' + second.why + '.' };
      }
      current = second;
      how = 'fresh-sample';
    }
    this.lastCpu = { dir: dir, usageUsec: current.stat.usage_usec,
                     atUs: current.atUs };
    const windowUs = Math.max(1, current.atUs - previous.atUs);
    const usedUs = Math.max(0, current.stat.usage_usec - previous.usageUsec);
    const cores = usedUs / windowUs;
    const max = await this.read(path.join(dir, 'cpu.max'));
    const quota = max.text === null ? null : NodeHealthAdmin.vcpusOf(max.text);
    const hostCpus = availableParallelism();
    const vcpus = quota === null ? hostCpus : quota;
    let limitText: string;
    if (quota !== null) {
      limitText = 'The container may use ' + NodeHealthAdmin.round1(quota) +
        ' vCPU (cpu.max), and the percentage is of that.';
    } else if (max.text === null) {
      limitText = 'This cgroup has no cpu.max, so it has no CPU quota of ' +
        'its own; the percentage is of the ' + hostCpus + ' CPU(s) node ' +
        'reports available (os.availableParallelism()).';
    } else {
      limitText = 'No CPU quota (cpu.max is "max"): the container may use ' +
        'every CPU the host gives it, and the percentage is of the ' +
        hostCpus + ' CPU(s) node reports available ' +
        '(os.availableParallelism()).';
    }
    const s = current.stat;
    const throttling = 'nr_periods' in s
      ? { periods: s.nr_periods, throttledPeriods: s.nr_throttled || 0,
          throttledSeconds: NodeHealthAdmin.round1(
            (s.throttled_usec || 0) / 1e6),
          throttledPercentOfPeriods: s.nr_periods
            ? NodeHealthAdmin.round1(100 * (s.nr_throttled || 0) /
                                     s.nr_periods)
            : null }
      : null;
    const view = {
      available: true,
      source: path.join(dir, 'cpu.stat'),
      limitVcpus: quota === null ? null : quota,
      limitSource: quota !== null ? 'cpu.max'
                                  : max.text === null ? 'no-cpu.max'
                                                      : 'unlimited',
      percentOfVcpus: vcpus,
      limitText: limitText,
      sampled: how,
      windowSeconds: Math.round(windowUs / 1000) / 1000,
      coresUsed: Math.round(cores * 1000) / 1000,
      utilisationPercent: NodeHealthAdmin.round1(100 * cores / vcpus),
      usageSeconds: NodeHealthAdmin.round1(s.usage_usec / 1e6),
      userSeconds: 'user_usec' in s
        ? NodeHealthAdmin.round1(s.user_usec / 1e6) : null,
      systemSeconds: 'system_usec' in s
        ? NodeHealthAdmin.round1(s.system_usec / 1e6) : null,
      throttling: throttling,
      throttlingText: throttling ? null
        : 'cpu.stat has no throttling counters: with no quota there is ' +
          'nothing to throttle against.'
    };
    log.debug("Leaving NodeHealthAdmin.cpuView().");
    return view;
  }

  /**
   * The container's memory: `memory.current` against `memory.max`, and what
   * `memory.stat` says it is made of.
   *
   * @param dir - the cgroup directory, or null when there is none
   * @param why - the sentence for no cgroup
   * @returns the memory view
   */
  async memoryView(dir: string | null, why: string): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering NodeHealthAdmin.memoryView().");
    if (!dir) {
      log.debug("Leaving NodeHealthAdmin.memoryView(). No cgroup.");
      return { available: false, unavailableText: why };
    }
    const files = await Promise.all(['memory.current', 'memory.max',
      'memory.stat', 'memory.peak', 'memory.events'].map((name: string) =>
      this.read(path.join(dir, name))));
    const current = files[0];
    if (current.text === null || !/^\d+/.test(current.text.trim())) {
      log.debug("Leaving NodeHealthAdmin.memoryView(). No memory.current.");
      return { available: false, source: path.join(dir, 'memory.current'),
               unavailableText: 'The container\'s memory cannot be read: ' +
                 path.join(dir, 'memory.current') + ' — ' +
                 (current.why || 'it is not a number') + '.' };
    }
    const used = Number(current.text.trim());
    const maxText = files[1].text === null ? null : files[1].text.trim();
    const limit = maxText !== null && /^\d+$/.test(maxText)
      ? Number(maxText) : null;
    const stat = files[2].text === null ? null
                                        : NodeHealthAdmin.keyed(files[2].text);
    const events = files[4].text === null
      ? null : NodeHealthAdmin.keyed(files[4].text);
    const peak = files[3].text !== null && /^\d+$/.test(files[3].text.trim())
      ? Number(files[3].text.trim()) : null;
    const view = {
      available: true,
      source: path.join(dir, 'memory.current'),
      currentBytes: used,
      limitBytes: limit,
      limitText: limit !== null
        ? 'The container may use ' + (limit / MIB).toFixed(0) + ' MiB ' +
          '(memory.max).'
        : maxText === null
          ? 'This cgroup has no memory.max, so it has no memory limit of ' +
            'its own and there is no percentage to give.'
          : 'No memory limit (memory.max is "max"), so there is no ' +
            'percentage to give.',
      utilisationPercent: limit ? NodeHealthAdmin.round1(100 * used / limit)
                                : null,
      peakBytes: peak,
      anonBytes: stat && 'anon' in stat ? stat.anon : null,
      fileBytes: stat && 'file' in stat ? stat.file : null,
      kernelBytes: stat && 'kernel' in stat ? stat.kernel : null,
      statText: stat ? 'anon is the processes\' own memory; file is page ' +
                       'cache the kernel reclaims under pressure before it ' +
                       'kills anything.'
                     : 'memory.stat cannot be read, so what the memory is ' +
                       'made of is not known.',
      oomKills: events && 'oom_kill' in events ? events.oom_kill : null
    };
    log.debug("Leaving NodeHealthAdmin.memoryView().");
    return view;
  }

  // `/proc/<pid>/status`'s resident size and its high-water mark.
  private async procMemory(pid: number):
    Promise<{ rss: number | null; hwm: number | null; why: string }> {
    const { log, procRoot } = this.deps;
    log.debug("Entering NodeHealthAdmin.procMemory(). " + pid);
    const read = await this.read(path.join(procRoot, String(pid), 'status'));
    if (read.text === null) {
      log.debug("Leaving NodeHealthAdmin.procMemory(). Unreadable.");
      return { rss: null, hwm: null,
               why: path.join(procRoot, String(pid), 'status') + ' could ' +
                 'not be read (' + read.why + ')' };
    }
    const kb = function (key: string): number | null {
      log.debug("Entering kb(). " + key);
      const m = new RegExp('^' + key + ':\\s*(\\d+)\\s*kB', 'm')
        .exec(read.text || '');
      log.debug("Leaving kb().");
      return m ? Number(m[1]) * 1024 : null;
    };
    const rss = kb('VmRSS');
    log.debug("Leaving NodeHealthAdmin.procMemory().");
    return { rss: rss, hwm: kb('VmHWM'),
             why: rss === null ? 'its status file has no VmRSS' : '' };
  }

  // A row for a process that reported `process.memoryUsage()` itself.
  private reportedRow(pid: number, role: string, memory: Json, cpu: Json,
                      uptimeS: number | null): Json {
    const { log } = this.deps;
    log.debug("Entering NodeHealthAdmin.reportedRow(). " + pid);
    log.debug("Leaving NodeHealthAdmin.reportedRow().");
    return {
      pid: pid, role: role, source: 'process.memoryUsage()',
      rssBytes: Number(memory.rss) || 0,
      heapUsedBytes: Number(memory.heapUsed) || 0,
      heapTotalBytes: Number(memory.heapTotal) || 0,
      externalBytes: Number(memory.external) || 0,
      arrayBuffersBytes: Number(memory.arrayBuffers) || 0,
      peakRssBytes: null,
      cpuUserSeconds: cpu ? NodeHealthAdmin.round1(cpu.user / 1e6) : null,
      cpuSystemSeconds: cpu ? NodeHealthAdmin.round1(cpu.system / 1e6)
                            : null,
      uptimeSeconds: uptimeS
    };
  }

  // A row for a child read from `/proc`, which has no heap to report.
  private async procRow(pid: number, role: string): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering NodeHealthAdmin.procRow(). " + pid);
    const m = await this.procMemory(pid);
    log.debug("Leaving NodeHealthAdmin.procRow().");
    return {
      pid: pid, role: role, source: '/proc/' + pid + '/status',
      rssBytes: m.rss, heapUsedBytes: null, heapTotalBytes: null,
      externalBytes: null, arrayBuffersBytes: null, peakRssBytes: m.hwm,
      cpuUserSeconds: null, cpuSystemSeconds: null, uptimeSeconds: null,
      unreadable: m.rss === null ? m.why : null
    };
  }

  // A child that answered its memory status: its own figures. One that did
  // not: its resident size from /proc, and why there is no heap.
  private async childRow(pid: number, role: string, answer: Json,
                         busy: boolean, noAnswer: string): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering NodeHealthAdmin.childRow(). " + pid);
    if (answer && answer.memory) {
      log.debug("Leaving NodeHealthAdmin.childRow(). Reported.");
      return this.reportedRow(pid, role, answer.memory, answer.cpu,
                              answer.uptimeS === undefined ? null
                                                           : answer.uptimeS);
    }
    const row = await this.procRow(pid, role);
    row.notReported = answer
      ? 'it answered without its memory, so only its resident size is ' +
        'shown, from /proc'
      : (busy ? 'it was computing a job, which reads no message until it ' +
                'returns, and '
              : '') + noAnswer + ', so only its resident size is shown, ' +
        'from /proc';
    log.debug("Leaving NodeHealthAdmin.childRow(). From /proc.");
    return row;
  }

  /**
   * Every process of the node and its memory: the front process, each
   * request and hosted-surface worker that answered, the post-quantum
   * children of each of them, and the debugger's api child — each child
   * with its own `process.memoryUsage()` when it answered its memory status
   * (#329), and its resident size from /proc when it did not.
   *
   * @param stats - `request_pool.stats()`
   * @param answers - `{ [pid]: { pq, memory, cpu, uptimeS, pqMemory } }`
   *   from the workers
   * @param ownChildren - `{ [pid]: { memory, cpu, uptimeS } }` from this
   *   process's post-quantum children
   * @param debuggerAnswer - the debugger's api child's answer, or null
   * @returns the processes view
   */
  async processesView(stats: Json, answers: Json, ownChildren?: Json,
                      debuggerAnswer?: Json): Promise<Json> {
    const { log, pid, memoryUsage, cpuUsage, uptimeS, workerPool,
            debuggerProcess } = this.deps;
    const self = this;
    log.debug("Entering NodeHealthAdmin.processesView().");
    const rows: Json[] = [];
    const unanswered: Json[] = [];
    const children: Promise<Json>[] = [];
    rows.push(this.reportedRow(pid, 'front process', memoryUsage(),
                               cpuUsage(), uptimeS()));
    const pqChildren = function (pq: Json, reported: Json,
                                 parent: number, parentAnswered: boolean):
      void {
      log.debug("Entering pqChildren(). " + parent);
      ((pq && pq.workers) || []).forEach(function (w: Json): void {
        children.push(self.childRow(w.pid, 'post-quantum worker of pid ' +
                                    parent, (reported || {})[w.pid],
                                    Number(w.inFlight) > 0,
                                    parentAnswered
                                      ? 'it did not answer within ' +
                                        ASK_CHILDREN_MS + 'ms'
                                      : 'its parent did not ask it'));
      });
      log.debug("Leaving pqChildren().");
    };
    pqChildren(workerPool().stats(), ownChildren, pid, true);
    (stats.workers || []).filter(function (one: Json): boolean {
      return one.ready;
    }).forEach(function (one: Json): void {
      const role = (one.pool || 'protocol') === 'surfaces'
        ? 'hosted-surface worker' : 'request worker';
      const answer = answers[one.pid];
      if (answer && answer.memory) {
        rows.push(self.reportedRow(one.pid, role, answer.memory, answer.cpu,
                                   answer.uptimeS));
        pqChildren(answer.pq, answer.pqMemory, one.pid, !!answer.pqMemory);
      } else {
        unanswered.push({ pid: one.pid, role: role,
                          why: answer
                            ? 'it answered without its memory'
                            : 'it did not answer within ' + ASK_WORKERS_MS +
                              'ms' });
      }
    });
    let debuggerNote: string | null = null;
    try {
      const status = debuggerProcess().status();
      if (status && status.pid) {
        children.push(this.childRow(status.pid, 'protocol debugger api',
          debuggerAnswer && debuggerAnswer.pid === status.pid
            ? debuggerAnswer : null, false,
          'it did not answer within ' + ASK_CHILDREN_MS + 'ms (its ' +
          'memory preload, debugger_api_status.js, answers when it is ' +
          'installed)'));
      }
    } catch (e) {
      log.debug("Caught in NodeHealthAdmin.processesView(): " +
                ((e && e.message) || e));
      // The debugger's api is a child only where the debugger runs; its row
      // is left out and the reason said.
      debuggerNote = 'The protocol debugger\'s api process could not be ' +
        'asked for its pid: ' + String((e && e.message) || e) + '.';
    }
    const read = await Promise.all(children);
    read.forEach(function (row: Json): void {
      rows.push(row);
    });
    const sum = function (key: string): number {
      log.debug("Entering sum(). " + key);
      log.debug("Leaving sum().");
      return rows.reduce(function (n: number, row: Json): number {
        return n + (typeof row[key] === 'number' ? row[key] : 0);
      }, 0);
    };
    const withRss = rows.filter(function (row: Json): boolean {
      return typeof row.rssBytes === 'number';
    }).length;
    const withHeap = rows.filter(function (row: Json): boolean {
      return typeof row.heapUsedBytes === 'number';
    }).length;
    const view = {
      rows: rows,
      unanswered: unanswered,
      debuggerNote: debuggerNote,
      totals: {
        processes: rows.length,
        rssBytes: sum('rssBytes'),
        processesWithRss: withRss,
        heapUsedBytes: sum('heapUsedBytes'),
        heapTotalBytes: sum('heapTotalBytes'),
        externalBytes: sum('externalBytes'),
        processesWithHeap: withHeap
      },
      totalsText: 'The resident total is the sum over the ' + withRss +
        ' process(es) whose size could be read, so pages shared between ' +
        'processes (node\'s own code among them) are counted once for each ' +
        'and it can exceed the container\'s memory.current. The heap ' +
        'figures are the ' + withHeap + ' process(es) that reported ' +
        'process.memoryUsage() themselves; a child that did not answer in ' +
        'time — a post-quantum worker computing a job cannot — is shown ' +
        'with its resident size from /proc and no heap, and says why.'
    };
    log.debug("Leaving NodeHealthAdmin.processesView(). " + rows.length +
              " process(es).");
    return view;
  }

  /**
   * The ECS task metadata endpoint's view of this container, where the
   * platform provides one.
   *
   * @returns the ECS view
   */
  async ecsView(): Promise<Json> {
    const { log, ecsUri, fetchJson, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering NodeHealthAdmin.ecsView().");
    const base = ecsUri().replace(/\/+$/, '');
    if (!base) {
      log.debug("Leaving NodeHealthAdmin.ecsView(). Not on ECS.");
      return { available: false,
               unavailableText: 'ECS_CONTAINER_METADATA_URI_V4 is not set: ' +
                 'this node is not an Amazon ECS task (it is not on Fargate ' +
                 'or an ECS container instance), so there is no task ' +
                 'metadata endpoint to cross-check the cgroup against.' };
    }
    const ask = function (suffix: string): Promise<Json> {
      log.debug("Entering ask(). " + (suffix || '/'));
      log.debug("Leaving ask().");
      return fetchJson(base + suffix, ECS_TIMEOUT_MS).then(
        function (body: Json): Json {
          return { body: body, why: '' };
        }, function (e: any): Json {
          log.debug("Caught in NodeHealthAdmin.ecsView(): " +
                    ((e && e.message) || e));
          // Said on the page, and logged once below.
          return { body: null, why: String((e && e.message) || e) };
        });
    };
    const got = await Promise.all([ask(''), ask('/task'),
                                   ask('/task/stats')]);
    const container = got[0].body;
    const task = got[1].body;
    const allStats = got[2].body;
    const failed = got.filter(function (one: Json): boolean {
      return !one.body;
    });
    if (failed.length && !self.ecsFailing) {
      log.warn(errorCodes.tag('STS-CORE-0125') + 'The ECS task metadata ' +
               'endpoint did not answer Monitoring → Node Health: ' +
               failed.map(function (one: Json): string {
                 return one.why;
               }).join('; '));
    }
    self.ecsFailing = failed.length > 0;
    if (!container && !task && !allStats) {
      log.debug("Leaving NodeHealthAdmin.ecsView(). Nothing answered.");
      return { available: false, errorCode: 'STS-CORE-0125',
               unavailableText: 'ECS_CONTAINER_METADATA_URI_V4 is set, but ' +
                 'the task metadata endpoint did not answer within ' +
                 ECS_TIMEOUT_MS + 'ms: ' + got[0].why + '.' };
    }
    const dockerId = container && container.DockerId
      ? String(container.DockerId) : null;
    const stats = allStats && dockerId ? allStats[dockerId] || null : null;
    let figures: Json = null;
    if (stats) {
      const ms = stats.memory_stats || {};
      const cs = stats.cpu_stats || {};
      const ps = stats.precpu_stats || {};
      const cpuDelta = ((cs.cpu_usage || {}).total_usage || 0) -
                       ((ps.cpu_usage || {}).total_usage || 0);
      const sysDelta = (cs.system_cpu_usage || 0) -
                       (ps.system_cpu_usage || 0);
      const online = cs.online_cpus ||
        ((cs.cpu_usage || {}).percpu_usage || []).length || 0;
      const cores = sysDelta > 0 && cpuDelta >= 0 && online
        ? cpuDelta / sysDelta * online : null;
      const taskCpu = task && task.Limits && Number(task.Limits.CPU) > 0
        ? Number(task.Limits.CPU) : null;
      figures = {
        read: stats.read || null,
        memoryUsageBytes: typeof ms.usage === 'number' ? ms.usage : null,
        memoryLimitBytes: typeof ms.limit === 'number' ? ms.limit : null,
        cpuCoresUsed: cores === null ? null : Math.round(cores * 1000) / 1000,
        cpuPercentOfTaskLimit: cores !== null && taskCpu
          ? NodeHealthAdmin.round1(100 * cores / taskCpu) : null
      };
    }
    const view = {
      available: true,
      endpoint: 'ECS_CONTAINER_METADATA_URI_V4',
      dockerId: dockerId,
      containerLimits: container && container.Limits ? container.Limits
                                                     : null,
      taskLimits: task && task.Limits
        ? { cpuVcpus: task.Limits.CPU === undefined ? null : task.Limits.CPU,
            memoryMiB: task.Limits.Memory === undefined ? null
                                                        : task.Limits.Memory }
        : null,
      stats: figures,
      unavailableText: failed.length || !figures
        ? (failed.length ? 'Part of the endpoint did not answer: ' +
            failed.map(function (one: Json): string {
              return one.why;
            }).join('; ') + '. ' : '') +
          (figures ? '' : 'There are no stats for this container in ' +
            '/task/stats' + (dockerId ? ' (' + dockerId + ')' : '') + '.')
        : null,
      text: 'The ECS agent\'s own figures for this container, as a cross-' +
        'check of the cgroup: the agent samples on its own schedule, so ' +
        'they will not agree to the byte or the percent.'
    };
    log.debug("Leaving NodeHealthAdmin.ecsView().");
    return view;
  }

  // This process's post-quantum children's memory, or none at all.
  private askOwnChildren(): Promise<Json> {
    const { log, workerPool } = this.deps;
    log.debug("Entering NodeHealthAdmin.askOwnChildren().");
    log.debug("Leaving NodeHealthAdmin.askOwnChildren().");
    return Promise.resolve().then(function (): Json {
      return workerPool().askMemoryStatus(ASK_CHILDREN_MS);
    }).catch(function (e: any): Json {
      log.debug("Caught in NodeHealthAdmin.askOwnChildren(): " +
                ((e && e.message) || e));
      // The children are then drawn from /proc, each saying why.
      return {};
    });
  }

  // The debugger's api child's memory, or null.
  private askDebugger(): Promise<Json> {
    const { log, debuggerProcess } = this.deps;
    log.debug("Entering NodeHealthAdmin.askDebugger().");
    log.debug("Leaving NodeHealthAdmin.askDebugger().");
    return Promise.resolve().then(function (): Json {
      return debuggerProcess().askMemory(ASK_CHILDREN_MS);
    }).catch(function (e: any): Json {
      log.debug("Caught in NodeHealthAdmin.askDebugger(): " +
                ((e && e.message) || e));
      // Its row, if it has one, is then drawn from /proc and says why.
      return null;
    });
  }

  // The page's JSON, and the management API's answer.
  /**
   * Answers the page's JSON and `GET /admin-api/node-health`: this node's
   * container and processes, read when called.
   *
   * @returns a promise of the view
   */
  async nodeHealthView(): Promise<Json> {
    const { log, requestPool, now, pid, host, machine } = this.deps;
    log.debug("Entering NodeHealthAdmin.nodeHealthView().");
    const pool = requestPool();
    const stats = pool.stats();
    const asking = (stats.workers || []).some(function (one: Json): boolean {
      return one.ready;
    });
    const where = await this.cgroupDir();
    const got = await Promise.all([
      this.cpuView(where.dir, where.why),
      this.memoryView(where.dir, where.why),
      asking ? pool.askWorkerPoolStatus(ASK_WORKERS_MS,
                                        { childMemory: ASK_CHILDREN_MS })
             : Promise.resolve({}),
      this.ecsView(),
      this.askOwnChildren(),
      this.askDebugger()
    ]);
    const processes = await this.processesView(stats, got[2] || {},
                                               got[4] || {}, got[5]);
    const view = {
      generatedAt: new Date(now()).toISOString(),
      host: host,
      pid: pid,
      scope: 'node',
      scopeText: 'These are the figures of this node — the container ' +
        host + ' — drawn by its front process, pid ' + pid + '. Every node ' +
        'of a cluster is a container of its own, with its own figures.',
      cgroup: where.dir,
      cpu: got[0],
      memory: got[1],
      processes: processes,
      ecs: got[3],
      machine: Object.assign({
        text: 'The machine this container runs on — on Fargate, the ' +
          'micro-VM; on a workstation, the whole workstation. NOT the ' +
          'container: its free memory and load say nothing about the ' +
          'container\'s limit.'
      }, machine())
    };
    log.debug("Leaving NodeHealthAdmin.nodeHealthView().");
    return view;
  }

  // Bytes as MiB, or a dash for a figure that is not there.
  private mib(value: unknown): string {
    const { log } = this.deps;
    log.debug("Entering NodeHealthAdmin.mib().");
    log.debug("Leaving NodeHealthAdmin.mib().");
    return typeof value === 'number' ? (value / MIB).toFixed(1) + ' MiB'
                                     : '—';
  }

  // A percentage, or a dash.
  private pct(value: unknown): string {
    const { log } = this.deps;
    log.debug("Entering NodeHealthAdmin.pct().");
    log.debug("Leaving NodeHealthAdmin.pct().");
    return typeof value === 'number' ? value.toFixed(1) + ' %' : '—';
  }

  // A table of three columns: label, value and why.
  private rows(items: [string, string, string][]): string {
    const { log, admin } = this.deps;
    log.debug("Entering NodeHealthAdmin.rows().");
    log.debug("Leaving NodeHealthAdmin.rows().");
    return '<table class="grid"><tbody>' +
      items.map(function (one: [string, string, string]): string {
        return '<tr><th>' + admin.esc(one[0]) + '</th><td>' + one[1] +
          '</td><td><small>' + one[2] + '</small></td></tr>';
      }).join('') + '</tbody></table>';
  }

  private cpuHtml(cpu: Json): string {
    const { log, admin } = this.deps;
    log.debug("Entering NodeHealthAdmin.cpuHtml().");
    const head = '<h2 id="cpu">Container CPU</h2>';
    if (!cpu.available) {
      log.debug("Leaving NodeHealthAdmin.cpuHtml(). Unavailable.");
      return head + '<p><strong>Not available:</strong> ' +
        admin.esc(cpu.unavailableText) + '</p>';
    }
    const t = cpu.throttling;
    const html = head + '<p>' + admin.esc(cpu.limitText) + '</p>' +
      this.rows([
        ['Utilisation', admin.esc(this.pct(cpu.utilisationPercent)),
         admin.esc(cpu.coresUsed) + ' of ' + admin.esc(cpu.percentOfVcpus) +
         ' CPU(s) over ' + admin.esc(cpu.windowSeconds) + ' s, ' +
         (cpu.sampled === 'fresh-sample' ? 'two samples taken for this page'
                                         : 'since the previous page')],
        ['CPU time used', admin.esc(cpu.usageSeconds) + ' s',
         'every process of the container since it started (user ' +
         admin.esc(cpu.userSeconds === null ? '—' : cpu.userSeconds) +
         ' s, system ' +
         admin.esc(cpu.systemSeconds === null ? '—' : cpu.systemSeconds) +
         ' s)'],
        ['Throttled', t ? admin.esc(t.throttledPeriods) + ' of ' +
           admin.esc(t.periods) + ' periods' : '—',
         t ? admin.esc(this.pct(t.throttledPercentOfPeriods)) + ' of ' +
             'periods, ' + admin.esc(t.throttledSeconds) + ' s held back ' +
             'by the quota'
           : admin.esc(cpu.throttlingText)]
      ]) + '<p><small>From <code>' + admin.esc(cpu.source) +
      '</code>.</small></p>';
    log.debug("Leaving NodeHealthAdmin.cpuHtml().");
    return html;
  }

  private memoryHtml(m: Json): string {
    const { log, admin } = this.deps;
    log.debug("Entering NodeHealthAdmin.memoryHtml().");
    const head = '<h2 id="memory">Container memory</h2>';
    if (!m.available) {
      log.debug("Leaving NodeHealthAdmin.memoryHtml(). Unavailable.");
      return head + '<p><strong>Not available:</strong> ' +
        admin.esc(m.unavailableText) + '</p>';
    }
    const html = head + '<p>' + admin.esc(m.limitText) + '</p>' +
      this.rows([
        ['In use', admin.esc(this.mib(m.currentBytes)),
         (m.utilisationPercent === null ? 'no limit to measure against'
            : admin.esc(this.pct(m.utilisationPercent)) + ' of ' +
              admin.esc(this.mib(m.limitBytes))) +
         (m.peakBytes === null ? ''
            : '; the most it has used is ' +
              admin.esc(this.mib(m.peakBytes)))],
        ['Anonymous', admin.esc(this.mib(m.anonBytes)),
         'the processes\' own memory: heaps, stacks, buffers'],
        ['Page cache', admin.esc(this.mib(m.fileBytes)),
         'files the kernel caches, and gives back under pressure'],
        ['Kernel', admin.esc(this.mib(m.kernelBytes)),
         'the kernel\'s own structures on the container\'s behalf'],
        ['Killed for memory', m.oomKills === null ? '—'
                                                  : admin.esc(m.oomKills),
         'processes the kernel killed at the limit (memory.events ' +
         'oom_kill)']
      ]) + '<p><small>' + admin.esc(m.statText) + ' From <code>' +
      admin.esc(m.source) + '</code>.</small></p>';
    log.debug("Leaving NodeHealthAdmin.memoryHtml().");
    return html;
  }

  private processesHtml(p: Json): string {
    const { log, admin } = this.deps;
    const self = this;
    log.debug("Entering NodeHealthAdmin.processesHtml().");
    const t = p.totals;
    const html = '<h2 id="processes">Node.js processes</h2>' +
      this.rows([
        ['Processes', admin.esc(t.processes), 'listed below'],
        ['Resident, in all', admin.esc(this.mib(t.rssBytes)),
         'across ' + admin.esc(t.processesWithRss) + ' process(es)'],
        ['Heap used, in all', admin.esc(this.mib(t.heapUsedBytes)),
         'of ' + admin.esc(this.mib(t.heapTotalBytes)) + ' allocated, ' +
         'across ' + admin.esc(t.processesWithHeap) + ' process(es)']
      ]) + admin.note(admin.esc(p.totalsText), 'How the totals add up') +
      '<table class="grid"><thead><tr><th>Process</th><th>Resident</th>' +
      '<th>Heap used</th><th>Heap total</th><th>External</th>' +
      '<th>Array buffers</th><th>CPU time</th></tr></thead><tbody>' +
      p.rows.map(function (r: Json): string {
        return '<tr><td>pid ' + admin.esc(r.pid) + '<br><small>' +
          admin.esc(r.role) + '</small></td><td>' +
          (r.unreadable ? '<small>' + admin.esc(r.unreadable) + '</small>'
                        : admin.esc(self.mib(r.rssBytes))) +
          (r.notReported ? '<br><small>' + admin.esc(r.notReported) +
                           '</small>' : '') +
          '</td><td>' + admin.esc(self.mib(r.heapUsedBytes)) + '</td><td>' +
          admin.esc(self.mib(r.heapTotalBytes)) + '</td><td>' +
          admin.esc(self.mib(r.externalBytes)) + '</td><td>' +
          admin.esc(self.mib(r.arrayBuffersBytes)) + '</td><td>' +
          (r.cpuUserSeconds === null ? '—'
             : admin.esc(NodeHealthAdmin.round1(r.cpuUserSeconds +
                                                r.cpuSystemSeconds)) +
               ' s') + '</td></tr>';
      }).join('') + '</tbody></table>' +
      (p.unanswered.length ? admin.warn(
        p.unanswered.length + ' worker(s) did not report: ' +
        p.unanswered.map(function (u: Json): string {
          return 'pid ' + admin.esc(u.pid) + ', ' + admin.esc(u.role) +
            ' (' + admin.esc(u.why) + ')';
        }).join('; ') + '.') : '') +
      (p.debuggerNote ? '<p><small>' + admin.esc(p.debuggerNote) +
                        '</small></p>' : '');
    log.debug("Leaving NodeHealthAdmin.processesHtml().");
    return html;
  }

  private ecsHtml(e: Json): string {
    const { log, admin } = this.deps;
    log.debug("Entering NodeHealthAdmin.ecsHtml().");
    const head = '<h2 id="ecs">ECS task metadata</h2>';
    if (!e.available) {
      log.debug("Leaving NodeHealthAdmin.ecsHtml(). Unavailable.");
      return head + '<p><strong>Not available:</strong> ' +
        admin.esc(e.unavailableText) + '</p>';
    }
    const s = e.stats || {};
    const limits = e.taskLimits || {};
    const html = head + '<p>' + admin.esc(e.text) + '</p>' +
      this.rows([
        ['Task limits', admin.esc(limits.cpuVcpus === undefined ||
                                  limits.cpuVcpus === null
                                    ? '—' : limits.cpuVcpus) + ' vCPU, ' +
           admin.esc(limits.memoryMiB === undefined ||
                     limits.memoryMiB === null
                       ? '—' : limits.memoryMiB) + ' MiB', '/task'],
        ['Memory', admin.esc(this.mib(s.memoryUsageBytes)),
         'of ' + admin.esc(this.mib(s.memoryLimitBytes)) + ', /task/stats'],
        ['CPU', s.cpuCoresUsed === null || s.cpuCoresUsed === undefined
           ? '—' : admin.esc(s.cpuCoresUsed) + ' CPU(s)',
         admin.esc(this.pct(s.cpuPercentOfTaskLimit)) + ' of the task\'s ' +
         'vCPUs, between the agent\'s last two samples']
      ]) + (e.unavailableText ? '<p><small>' + admin.esc(e.unavailableText) +
                                '</small></p>' : '');
    log.debug("Leaving NodeHealthAdmin.ecsHtml().");
    return html;
  }

  private html(json: Json): string {
    const { log, admin } = this.deps;
    log.debug("Entering NodeHealthAdmin.html().");
    const cpu = json.cpu;
    const mem = json.memory;
    const tiles = '<div class="tiles">' +
      admin.tile(cpu.available ? this.pct(cpu.utilisationPercent) : 'n/a',
                 'CPU') +
      admin.tile(!mem.available ? 'n/a'
                   : mem.utilisationPercent === null
                     ? this.mib(mem.currentBytes)
                     : this.pct(mem.utilisationPercent), 'Memory') +
      admin.tile(this.mib(json.processes.totals.rssBytes),
                 'Resident, all processes') +
      admin.tile(String(json.processes.totals.processes), 'Processes') +
      '</div>';
    const about = admin.note(
      '<p>' + admin.esc(json.scopeText) + '</p><p>The container\'s CPU and ' +
      'memory are read from its cgroup (v2), each process\'s from the ' +
      'process itself, when the page is drawn; nothing is kept but the ' +
      'previous CPU sample. This page changes nothing.</p>',
      'What this page is');
    const m = json.machine;
    const machine = '<h2 id="machine">The machine, not the container</h2>' +
      '<p>' + admin.esc(m.text) + '</p>' +
      this.rows([
        ['Load average', admin.esc((m.loadavg || []).map(
          function (n: number): string {
            return n.toFixed(2);
          }).join(' / ')), '1, 5 and 15 minutes (os.loadavg())'],
        ['Memory', admin.esc(this.mib(m.freememBytes)) + ' free of ' +
           admin.esc(this.mib(m.totalmemBytes)),
         'os.freemem() and os.totalmem()'],
        ['CPUs', admin.esc(m.cpus), 'os.cpus()']
      ]);
    const html = tiles + about + this.cpuHtml(cpu) + this.memoryHtml(mem) +
      this.processesHtml(json.processes) + this.ecsHtml(json.ecs) + machine;
    log.debug("Leaving NodeHealthAdmin.html().");
    return html;
  }

  /**
   * Registers `GET /admin/node-health`.
   *
   * @param app - the shared express app
   */
  registerRoutes(app: { get: Function }): void {
    const { log, admin, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering NodeHealthAdmin.registerRoutes().");
    app.get(PAGE, function (req: Req, res: Res): void {
      log.debug('Entering GET ' + PAGE + '.');
      self.nodeHealthView().then(function (json: Json): void {
        admin.respond(req, res, json, 'Node health', PAGE,
                      admin.messagesOf(req) + self.html(json));
      }).catch(function (e: any): void {
        log.debug("Caught in GET " + PAGE + ": " + ((e && e.message) || e));
        log.error(errorCodes.tag('STS-CORE-0124') + 'The node health ' +
                  'report could not be built: ' + ((e && e.message) || e));
        errorCodes.mark(res, 'STS-CORE-0124');
        res.status(500).type('text/plain')
          .send('The node health report could not be built.');
      });
      log.debug('Leaving GET ' + PAGE + '.');
    });
    log.debug("Leaving NodeHealthAdmin.registerRoutes().");
  }
}

const slot = new InstanceSlot<NodeHealthAdmin>(
  'admin-ui/node_health_admin',
  () => new NodeHealthAdmin(NodeHealthAdmin.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * Monitoring → Node Health, `/admin/node-health`: the container's CPU and
 * memory, and the memory of every Node.js process of this node. A service
 * page with no control and no POST.
 * @namespace
 */
export = {
  registerRoutes: slot.forward('registerRoutes'),
  NodeHealthAdmin: NodeHealthAdmin,
  /**
   * Installs the instance the composition root built and runs its
   * wire step; a second install is refused.
   */
  installInstance: (instance: NodeHealthAdmin): void =>
    slot.install(instance),
  /**
   * Says where the instance in use came from: `root`, `default` or
   * `none`.
   */
  instanceOrigin: (): string => slot.origin(),
  PAGE: PAGE,
  // For `mgmt-api/admin_api.ts` (rule 7).
  nodeHealthView: slot.forward('nodeHealthView')
};
