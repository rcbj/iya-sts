// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: node_health_admin.ts
//
// ===========================================================================
// MONITORING → NODE HEALTH (#329, 2026-09-28): THE CONTAINER'S CPU AND
// MEMORY, AND THE MEMORY OF EVERY NODE.JS PROCESS AND WORKER THREAD IN IT.
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
//   * THE NODE.JS MEMORY OF EVERY PROCESS AND WORKER THREAD —
//     `process.memoryUsage()` of the front process; the heap of each request
//     and hosted-surface worker THREAD, which answers over the channel #327
//     added (`{ poolStatus }`, bounded at a second, a silent worker listed
//     as unanswered); and the same figures from the debugger's api child,
//     asked over its own channel (`debugger_api_process.askMemory()`,
//     answered by a preload), bounded at half a second. A child PROCESS that
//     does not answer in time is drawn with its resident size from
//     `/proc/<pid>/status` and the reason. The totals across them. There
//     were post-quantum children too until #363 (2026-09-30); post-quantum
//     signing and scrypt now run on libuv's thread pool inside each process,
//     so their memory is that process's.
//
// **A WORKER IS A THREAD OF THE FRONT PROCESS SINCE #364 (2026-09-30), AND
// THAT DECIDES WHAT EACH ROW MAY SAY.** Until then each worker was a forked
// process with a resident size and a CPU time of its own. In a thread,
// `process.memoryUsage().rss` and `process.cpuUsage()` are the WHOLE
// PROCESS's — the same numbers in every thread — and `/proc/<pid>` is the
// whole process too; only the heap figures (`heapUsed`, `heapTotal`,
// `external`, `arrayBuffers`) are per V8 isolate. So:
//
//   - the front process's row carries the process's resident size and CPU
//     time, every worker thread's included, and its MAIN thread's heap;
//   - a worker thread's row carries its own heap and NOT a resident size or
//     a CPU time (`null`, with `processWide` saying where they are), because
//     repeating the process's figure per thread would count it N+1 times;
//   - the resident total adds processes only (the front and the debugger's
//     api child), and the heap total adds every isolate;
//   - a worker that did not answer is said to have not answered, and nothing
//     more: a thread has no `/proc` entry of its own to fall back on.
//   * THE ECS TASK METADATA ENDPOINT, where the platform sets
//     `ECS_CONTAINER_METADATA_URI_V4` — its `/task/stats` and `/task`, as a
//     cross-check of the cgroup figures from the agent's side. It needs no
//     IAM; locally it is absent and the page says so.
//
// **CGROUP V1 TOO, AND THE ECS TASK WHERE THE CGROUP IS SILENT (2026-09-28,
// found on Fargate).** Fargate's platform mounts cgroup v1, so the first
// deploy drew both container sections as unavailable while the ECS agent
// answered. v1 is read as v2 is — `cpuacct.usage` (nanoseconds) sampled the
// same way, against `cpu.cfs_quota_us` / `cpu.cfs_period_us` (-1 is none),
// `cpu.stat`'s `throttled_time`; `memory.usage_in_bytes` against
// `memory.limit_in_bytes`, `memory.stat`'s `total_rss` / `total_cache`,
// `memory.max_usage_in_bytes` as the peak, `memory.oom_control`'s
// `oom_kill` — each controller found through the hierarchy
// `/proc/self/cgroup` names it in, and every figure says which version it
// came from (`cgroupVersion`). A limit that means NONE (v2's `max`, v1's
// number near 2^63, the agent's own) falls back to the ECS TASK's limit
// (`/task` Limits), with `limitSource: 'ecs-task'` and a sentence; and where
// there is no cgroup at all but the agent answers, the container's figures
// are the agent's (`fromEcs`), labelled as such (`withEcs()`). The cluster
// totals add whichever each node reported.
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
// **EVERY NODE, BY NAME (#332, 2026-09-28).** In a cluster the page draws a
// section per node — this node's from its live view, every other's from the
// snapshot its front process writes every fifteen seconds
// (`cluster/node_snapshots.ts`), stamped with its age and marked stale or
// gone rather than dropped — and the cluster's totals above them. A node is
// named (`cluster.nodeName`) and never addressed: no host name or address is
// in the view. `?node=<name>` narrows the page and the API to one node.
//
// **THE LIVE FIGURES ARE THIS NODE'S.** Each node of a cluster is a container
// of its own; the page names the node and the front process that drew it, and
// it is ALWAYS the front process: both paths are in `request_pool.js`'s
// `NEVER_DISPATCHED` beside Worker Pools', because only the front process
// knows the workers and can ask them.
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
import nodeSnapshots = require('../cluster/node_snapshots');

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
// How long the debugger's api child is waited for.
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
  // LAZY, both, as in `worker_pools_admin.ts`: by the time a page is drawn
  // each is in node's module cache.
  requestPool: () => any;
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
  // This node's NAME, never its host or address (#332).
  nodeName: () => string;
  // Every other node's snapshot, and the job that writes this one's (#332).
  snapshots: () => typeof nodeSnapshots;
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
      nodeName: function nodeName(): string {
        log.debug("Entering nodeName().");
        log.debug("Leaving nodeName().");
        return nodeSnapshots.selfName();
      },
      snapshots: function snapshots(): typeof nodeSnapshots {
        log.debug("Entering snapshots().");
        log.debug("Leaving snapshots().");
        return nodeSnapshots;
      },
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

  // /proc/self/cgroup, as its lines: `{ controllers, hierarchy, rel }`.
  private async selfCgroups(): Promise<Json[]> {
    const { log, procRoot } = this.deps;
    log.debug("Entering NodeHealthAdmin.selfCgroups().");
    const self = await this.read(path.join(procRoot, 'self', 'cgroup'));
    const lines = String(self.text || '').split('\n').map(
      function (one: string): Json {
        const m = /^(\d+):([^:]*):(.*)$/.exec(one.trim());
        return m ? { hierarchy: m[2],
                     controllers: m[2] ? m[2].split(',') : [],
                     rel: m[3] || '/' } : null;
      }).filter(function (one: Json): boolean {
      return !!one;
    });
    log.debug("Leaving NodeHealthAdmin.selfCgroups(). " + lines.length);
    return lines;
  }

  // The first of `dirs` holding `file`, or null.
  private async firstWith(dirs: string[], file: string):
    Promise<string | null> {
    const { log } = this.deps;
    log.debug("Entering NodeHealthAdmin.firstWith(). " + file);
    const seen = new Set<string>();
    for (const dir of dirs) {
      if (seen.has(dir)) {
        continue;
      }
      seen.add(dir);
      const got = await this.read(path.join(dir, file));
      if (got.text !== null) {
        log.debug("Leaving NodeHealthAdmin.firstWith(). " + dir);
        return dir;
      }
    }
    log.debug("Leaving NodeHealthAdmin.firstWith(). None.");
    return null;
  }

  // A cgroup v1 controller's directory for this process: the hierarchy
  // `/proc/self/cgroup` names it in (`cpu,cpuacct`) or the controller's own
  // name, with the process's path under it (a host) or without (a container,
  // whose hierarchy is mounted at its own cgroup — Fargate's case).
  private async v1Dir(lines: Json[], controller: string, file: string):
    Promise<string | null> {
    const { log, cgroupRoot } = this.deps;
    log.debug("Entering NodeHealthAdmin.v1Dir(). " + controller);
    const line = lines.filter(function (one: Json): boolean {
      return one.controllers.indexOf(controller) >= 0;
    })[0];
    const dirs: string[] = [];
    if (line) {
      dirs.push(path.join(cgroupRoot, line.hierarchy, line.rel),
                path.join(cgroupRoot, controller, line.rel),
                path.join(cgroupRoot, line.hierarchy));
    }
    dirs.push(path.join(cgroupRoot, controller));
    if (controller === 'cpu' || controller === 'cpuacct') {
      dirs.push(path.join(cgroupRoot, 'cpu,cpuacct'),
                path.join(cgroupRoot, 'cpuacct,cpu'));
    }
    const found = await this.firstWith(dirs, file);
    log.debug("Leaving NodeHealthAdmin.v1Dir(). " + found);
    return found;
  }

  /**
   * Finds this process's cgroup, and which version it is.
   *
   * CGROUP V2: the directory `/proc/self/cgroup`'s `0::` line names under
   * the cgroup root when that directory has the files (a host, or a
   * container sharing the host's cgroup namespace), and otherwise the root
   * (a container with a namespace of its own, where the root is the
   * container). CGROUP V1 (#329, 2026-09-28 — Fargate's platform mounts it):
   * a directory per controller, `memory`, `cpu` and `cpuacct`, found through
   * the controller-named hierarchies of `/proc/self/cgroup`.
   *
   * @returns `{ version, dir }` for v2, `{ version: 1, memoryDir, cpuDir,
   *   cpuacctDir }` for v1, or `{ version: null, why }` when there is none
   */
  async cgroupDir(): Promise<Json> {
    const { log, cgroupRoot, platform } = this.deps;
    log.debug("Entering NodeHealthAdmin.cgroupDir().");
    const none = { version: null, dir: null, memoryDir: null, cpuDir: null,
                   cpuacctDir: null, why: '' };
    if (platform !== 'linux') {
      log.debug("Leaving NodeHealthAdmin.cgroupDir(). Not Linux.");
      return Object.assign(none, { why: 'This node is not running on ' +
        'Linux (' + platform + '), so there are no cgroup files to read.' });
    }
    const lines = await this.selfCgroups();
    const controllers = await this.read(path.join(cgroupRoot,
                                                  'cgroup.controllers'));
    if (controllers.text !== null) {
      const unified = lines.filter(function (one: Json): boolean {
        return !one.hierarchy;
      })[0];
      const rel = unified ? unified.rel : '/';
      let dir = cgroupRoot;
      if (rel && rel !== '/') {
        const candidate = path.join(cgroupRoot, rel);
        const has = await this.read(path.join(candidate, 'memory.current'));
        if (has.text !== null) {
          dir = candidate;
        }
      }
      log.debug("Leaving NodeHealthAdmin.cgroupDir(). v2 " + dir);
      return Object.assign(none, { version: 2, dir: dir });
    }
    const memoryDir = await this.v1Dir(lines, 'memory',
                                       'memory.usage_in_bytes');
    const cpuacctDir = await this.v1Dir(lines, 'cpuacct', 'cpuacct.usage');
    const cpuDir = await this.v1Dir(lines, 'cpu', 'cpu.cfs_period_us');
    if (memoryDir || cpuacctDir) {
      log.debug("Leaving NodeHealthAdmin.cgroupDir(). v1.");
      return Object.assign(none, { version: 1, memoryDir: memoryDir,
                                   cpuDir: cpuDir, cpuacctDir: cpuacctDir });
    }
    log.debug("Leaving NodeHealthAdmin.cgroupDir(). None.");
    return Object.assign(none, { why: 'There is no cgroup at ' + cgroupRoot +
      ': no cgroup v2 (' + controllers.why + ') and no cgroup v1 memory or ' +
      'cpuacct controller.' });
  }

  // The container's cumulative CPU time, as cgroup v2's `cpu.stat` names it
  // — v1's `cpuacct.usage` (nanoseconds) and `cpu.stat` (`throttled_time`,
  // nanoseconds) translated — and when it was read.
  private async cpuSample(where: Json):
    Promise<{ stat: Json | null; atUs: number; why: string;
              source: string }> {
    const { log, clockUs } = this.deps;
    log.debug("Entering NodeHealthAdmin.cpuSample(). v" + where.version);
    if (where.version === 2) {
      const file = path.join(where.dir, 'cpu.stat');
      const read = await this.read(file);
      const atUs = clockUs();
      if (read.text === null) {
        log.debug("Leaving NodeHealthAdmin.cpuSample(). Unreadable.");
        return { stat: null, atUs: atUs, why: read.why, source: file };
      }
      const stat = NodeHealthAdmin.keyed(read.text);
      log.debug("Leaving NodeHealthAdmin.cpuSample().");
      return { stat: 'usage_usec' in stat ? stat : null, atUs: atUs,
               why: 'usage_usec' in stat ? '' : 'it has no usage_usec',
               source: file };
    }
    if (!where.cpuacctDir) {
      log.debug("Leaving NodeHealthAdmin.cpuSample(). No cpuacct.");
      return { stat: null, atUs: clockUs(), source: 'cpuacct.usage',
               why: 'there is no cgroup v1 cpuacct controller' };
    }
    const file = path.join(where.cpuacctDir, 'cpuacct.usage');
    const usage = await this.read(file);
    const atUs = clockUs();
    const ns = usage.text === null ? NaN : Number(usage.text.trim());
    if (!(ns >= 0)) {
      log.debug("Leaving NodeHealthAdmin.cpuSample(). Unreadable v1.");
      return { stat: null, atUs: atUs, source: file,
               why: usage.text === null ? usage.why : 'it is not a number' };
    }
    const stat: Json = { usage_usec: ns / 1000 };
    if (where.cpuDir) {
      const cs = await this.read(path.join(where.cpuDir, 'cpu.stat'));
      const k = cs.text === null ? {} : NodeHealthAdmin.keyed(cs.text);
      if ('nr_periods' in k) {
        stat.nr_periods = k.nr_periods;
        stat.nr_throttled = k.nr_throttled || 0;
        stat.throttled_usec = (k.throttled_time || 0) / 1000;
      }
    }
    log.debug("Leaving NodeHealthAdmin.cpuSample(). v1.");
    return { stat: stat, atUs: atUs, why: '', source: file };
  }

  // The CPU quota in vCPUs: v2's `cpu.max`, v1's `cpu.cfs_quota_us` over
  // `cpu.cfs_period_us` (-1 is none). `kind`: `quota`, `unlimited` (the file
  // says none) or `no-file`.
  private async cpuQuota(where: Json):
    Promise<{ vcpus: number | null; kind: string; file: string }> {
    const { log } = this.deps;
    log.debug("Entering NodeHealthAdmin.cpuQuota().");
    if (where.version === 2) {
      const max = await this.read(path.join(where.dir, 'cpu.max'));
      const q = max.text === null ? null : NodeHealthAdmin.vcpusOf(max.text);
      log.debug("Leaving NodeHealthAdmin.cpuQuota(). v2.");
      return { vcpus: q, file: 'cpu.max',
               kind: q !== null ? 'quota'
                                : max.text === null ? 'no-file' : 'unlimited' };
    }
    if (!where.cpuDir) {
      log.debug("Leaving NodeHealthAdmin.cpuQuota(). No cpu controller.");
      return { vcpus: null, kind: 'no-file', file: 'cpu.cfs_quota_us' };
    }
    const got = await Promise.all([
      this.read(path.join(where.cpuDir, 'cpu.cfs_quota_us')),
      this.read(path.join(where.cpuDir, 'cpu.cfs_period_us'))]);
    const quota = got[0].text === null ? NaN : Number(got[0].text.trim());
    const period = got[1].text === null ? NaN : Number(got[1].text.trim());
    log.debug("Leaving NodeHealthAdmin.cpuQuota(). v1.");
    if (got[0].text === null) {
      return { vcpus: null, kind: 'no-file', file: 'cpu.cfs_quota_us' };
    }
    return quota > 0 && period > 0
      ? { vcpus: quota / period, kind: 'quota',
          file: 'cpu.cfs_quota_us / cpu.cfs_period_us' }
      : { vcpus: null, kind: 'unlimited', file: 'cpu.cfs_quota_us' };
  }

  /**
   * The container's CPU: utilisation over a window, against the quota — from
   * cgroup v2 or v1, whichever this node has.
   *
   * @param where - `cgroupDir()`'s answer
   * @returns the CPU view
   */
  async cpuView(where: Json): Promise<Json> {
    const { log, sleep, sampleMs, availableParallelism } = this.deps;
    log.debug("Entering NodeHealthAdmin.cpuView().");
    if (!where || !where.version) {
      log.debug("Leaving NodeHealthAdmin.cpuView(). No cgroup.");
      return { available: false, cgroupVersion: null,
               unavailableText: where ? where.why : 'No cgroup.' };
    }
    const key = where.version + ':' + (where.dir || where.cpuacctDir);
    let current = await this.cpuSample(where);
    if (!current.stat) {
      log.debug("Leaving NodeHealthAdmin.cpuView(). No CPU time.");
      return { available: false, cgroupVersion: where.version,
               source: current.source,
               unavailableText: 'The container\'s CPU time cannot be read: ' +
                 current.source + ' — ' + current.why + '.' };
    }
    const kept = this.lastCpu;
    let previous: { usageUsec: number; atUs: number };
    let how: string;
    const age = kept && kept.dir === key ? current.atUs - kept.atUs : -1;
    if (kept && kept.dir === key && age >= MIN_WINDOW_US &&
        age <= MAX_WINDOW_US &&
        current.stat.usage_usec >= kept.usageUsec) {
      previous = kept;
      how = 'since-previous-sample';
    } else {
      previous = { usageUsec: current.stat.usage_usec,
                   atUs: current.atUs };
      await sleep(sampleMs);
      const second = await this.cpuSample(where);
      if (!second.stat) {
        log.debug("Leaving NodeHealthAdmin.cpuView(). Second read failed.");
        return { available: false, cgroupVersion: where.version,
                 source: second.source,
                 unavailableText: 'The container\'s CPU time could be read ' +
                   'once and not a second time: ' + second.why + '.' };
      }
      current = second;
      how = 'fresh-sample';
    }
    this.lastCpu = { dir: key, usageUsec: current.stat.usage_usec,
                     atUs: current.atUs };
    const windowUs = Math.max(1, current.atUs - previous.atUs);
    const usedUs = Math.max(0, current.stat.usage_usec - previous.usageUsec);
    const cores = usedUs / windowUs;
    const q = await this.cpuQuota(where);
    const hostCpus = availableParallelism();
    const vcpus = q.vcpus === null ? hostCpus : q.vcpus;
    const version = 'cgroup v' + where.version;
    let limitText: string;
    if (q.kind === 'quota') {
      limitText = 'The container may use ' +
        NodeHealthAdmin.round1(q.vcpus as number) + ' vCPU (' + version +
        ', ' + q.file + '), and the percentage is of that.';
    } else if (q.kind === 'no-file') {
      limitText = 'This cgroup (' + version + ') has no ' + q.file + ', so ' +
        'it has no CPU quota of its own; the percentage is of the ' +
        hostCpus + ' CPU(s) node reports available ' +
        '(os.availableParallelism()).';
    } else {
      limitText = 'No CPU quota (' + version + ', ' + q.file + ' says ' +
        'none): the container may use every CPU the host gives it, and the ' +
        'percentage is of the ' + hostCpus + ' CPU(s) node reports ' +
        'available (os.availableParallelism()).';
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
      cgroupVersion: where.version,
      source: current.source,
      limitVcpus: q.vcpus,
      limitSource: q.kind === 'quota' ? (where.version === 2 ? 'cpu.max'
                                                             : 'cpu.cfs')
                   : q.kind === 'no-file' ? 'no-' + q.file.split(' ')[0]
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
        : 'The cgroup has no throttling counters: with no quota there is ' +
          'nothing to throttle against.'
    };
    log.debug("Leaving NodeHealthAdmin.cpuView().");
    return view;
  }

  /**
   * Whether a memory limit is one that means "none": v2's `max` is not a
   * number at all, but v1's `memory.limit_in_bytes` and the ECS agent's
   * container limit say none with a number near 2^63 (9223372036854771712).
   *
   * @param bytes - the limit
   * @returns true for no limit
   */
  static unlimitedBytes(bytes: number): boolean {
    helpers.log.debug("Entering NodeHealthAdmin.unlimitedBytes().");
    helpers.log.debug("Leaving NodeHealthAdmin.unlimitedBytes().");
    return !(bytes > 0) || bytes >= Math.pow(2, 60);
  }

  // A file's text as a whole number, or null.
  private static numberOf(got: { text: string | null }): number | null {
    helpers.log.debug("Entering NodeHealthAdmin.numberOf().");
    helpers.log.debug("Leaving NodeHealthAdmin.numberOf().");
    return got.text !== null && /^\d+$/.test(got.text.trim())
      ? Number(got.text.trim()) : null;
  }

  /**
   * The container's memory, from cgroup v2 (`memory.current` against
   * `memory.max`, `memory.stat`, `memory.peak`, `memory.events`) or v1
   * (`memory.usage_in_bytes` against `memory.limit_in_bytes`, `memory.stat`'s
   * rss and cache, `memory.max_usage_in_bytes`, `memory.oom_control`).
   *
   * @param where - `cgroupDir()`'s answer
   * @returns the memory view
   */
  async memoryView(where: Json): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering NodeHealthAdmin.memoryView().");
    if (!where || !where.version) {
      log.debug("Leaving NodeHealthAdmin.memoryView(). No cgroup.");
      return { available: false, cgroupVersion: null,
               unavailableText: where ? where.why : 'No cgroup.' };
    }
    const v2 = where.version === 2;
    const dir = v2 ? where.dir : where.memoryDir;
    if (!dir) {
      log.debug("Leaving NodeHealthAdmin.memoryView(). No v1 memory.");
      return { available: false, cgroupVersion: 1,
               unavailableText: 'This cgroup v1 host has no memory ' +
                 'controller for this process.' };
    }
    const names = v2
      ? ['memory.current', 'memory.max', 'memory.stat', 'memory.peak',
         'memory.events', '']
      : ['memory.usage_in_bytes', 'memory.limit_in_bytes', 'memory.stat',
         'memory.max_usage_in_bytes', 'memory.oom_control',
         'memory.kmem.usage_in_bytes'];
    const files = await Promise.all(names.map((name: string) =>
      name ? this.read(path.join(dir, name))
           : Promise.resolve({ text: null, why: '' })));
    const source = path.join(dir, names[0]);
    const used = NodeHealthAdmin.numberOf(files[0]);
    if (used === null) {
      log.debug("Leaving NodeHealthAdmin.memoryView(). No usage.");
      return { available: false, cgroupVersion: where.version,
               source: source,
               unavailableText: 'The container\'s memory cannot be read: ' +
                 source + ' — ' + (files[0].why || 'it is not a number') +
                 '.' };
    }
    const maxText = files[1].text === null ? null : files[1].text.trim();
    const raw = NodeHealthAdmin.numberOf(files[1]);
    const limit = raw !== null && !NodeHealthAdmin.unlimitedBytes(raw)
      ? raw : null;
    const stat = files[2].text === null ? null
                                        : NodeHealthAdmin.keyed(files[2].text);
    const events = files[4].text === null
      ? null : NodeHealthAdmin.keyed(files[4].text);
    const pick = function (keys: string[]): number | null {
      helpers.log.debug("Entering pick().");
      helpers.log.debug("Leaving pick().");
      const k = keys.filter(function (one: string): boolean {
        return !!stat && one in stat;
      })[0];
      return k ? (stat as Json)[k] : null;
    };
    const version = 'cgroup v' + where.version;
    const limitName = names[1];
    const view = {
      available: true,
      cgroupVersion: where.version,
      source: source,
      currentBytes: used,
      limitBytes: limit,
      limitSource: limit !== null ? limitName
                                  : maxText === null ? 'no-' + limitName
                                                     : 'unlimited',
      limitText: limit !== null
        ? 'The container may use ' + (limit / MIB).toFixed(0) + ' MiB (' +
          version + ', ' + limitName + ').'
        : maxText === null
          ? 'This cgroup (' + version + ') has no ' + limitName + ', so it ' +
            'has no memory limit of its own and there is no percentage to ' +
            'give.'
          : 'No memory limit (' + version + ', ' + limitName + ' says ' +
            'none), so there is no percentage to give.',
      utilisationPercent: limit ? NodeHealthAdmin.round1(100 * used / limit)
                                : null,
      peakBytes: NodeHealthAdmin.numberOf(files[3]),
      anonBytes: v2 ? pick(['anon']) : pick(['total_rss', 'rss']),
      fileBytes: v2 ? pick(['file']) : pick(['total_cache', 'cache']),
      kernelBytes: v2 ? pick(['kernel']) : NodeHealthAdmin.numberOf(files[5]),
      statText: stat ? (v2 ? 'anon' : 'rss') + ' is the processes\' own ' +
                       'memory; ' + (v2 ? 'file' : 'cache') + ' is page ' +
                       'cache the kernel reclaims under pressure before it ' +
                       'kills anything.'
                     : 'memory.stat cannot be read, so what the memory is ' +
                       'made of is not known.',
      oomKills: events && 'oom_kill' in events ? events.oom_kill : null
    };
    log.debug("Leaving NodeHealthAdmin.memoryView(). " + version);
    return view;
  }

  /**
   * Gives the container's figures what only the ECS agent knows (#329, on
   * Fargate): where the cgroup says there is no limit — v2's `max`, v1's
   * sentinel — the limit is the ECS TASK's (`/task` Limits), and the page
   * says so; and where there is no cgroup to read at all, the container's
   * memory and CPU are the agent's own (`/task/stats`), labelled as ECS's.
   *
   * @param cpu - the CPU view
   * @param memory - the memory view
   * @param ecs - the ECS view
   * @returns `{ cpu, memory }`, new objects
   */
  static withEcs(cpu: Json, memory: Json, ecs: Json): Json {
    helpers.log.debug("Entering NodeHealthAdmin.withEcs().");
    const round1 = NodeHealthAdmin.round1;
    const outCpu = Object.assign({}, cpu);
    const outMem = Object.assign({}, memory);
    const task = ecs && ecs.available && ecs.taskLimits ? ecs.taskLimits : {};
    const stats = ecs && ecs.available && ecs.stats ? ecs.stats : null;
    const taskCpu = Number(task.cpuVcpus) > 0 ? Number(task.cpuVcpus) : null;
    const taskMem = Number(task.memoryMiB) > 0
      ? Number(task.memoryMiB) * MIB : null;
    if (!outMem.available && stats && typeof stats.memoryUsageBytes ===
        'number') {
      const lim = typeof stats.memoryLimitBytes === 'number'
        ? stats.memoryLimitBytes : taskMem;
      Object.assign(outMem, {
        available: true, fromEcs: true, source: 'ECS /task/stats',
        cgroupUnavailableText: memory.unavailableText || null,
        unavailableText: undefined,
        currentBytes: stats.memoryUsageBytes, limitBytes: lim,
        limitSource: typeof stats.memoryLimitBytes === 'number'
          ? 'ecs-container' : lim ? 'ecs-task' : 'none',
        limitText: 'From the ECS agent (/task/stats), because the cgroup ' +
          'cannot be read here. ' + (typeof stats.memoryLimitBytes ===
          'number' ? 'The limit is the container\'s, as the agent reports it.'
          : lim ? 'The container has no limit of its own, so the limit is ' +
                  'the ECS TASK\'s, ' + (lim / MIB).toFixed(0) + ' MiB.'
                : 'There is no limit to measure against.'),
        utilisationPercent: lim ? round1(100 * stats.memoryUsageBytes / lim)
                                : null,
        peakBytes: null, anonBytes: null, fileBytes: null, kernelBytes: null,
        oomKills: null,
        statText: 'The ECS agent reports the total only.'
      });
    } else if (outMem.available && outMem.limitBytes === null && taskMem) {
      Object.assign(outMem, {
        limitBytes: taskMem, limitSource: 'ecs-task',
        limitText: 'The container has no memory limit of its own (cgroup ' +
          'v' + outMem.cgroupVersion + '), so the limit is the ECS TASK\'s, ' +
          (taskMem / MIB).toFixed(0) + ' MiB (/task Limits.Memory), and the ' +
          'percentage is of that.',
        utilisationPercent: round1(100 * outMem.currentBytes / taskMem)
      });
    }
    if (!outCpu.available && stats && typeof stats.cpuCoresUsed ===
        'number') {
      Object.assign(outCpu, {
        available: true, fromEcs: true, source: 'ECS /task/stats',
        cgroupUnavailableText: cpu.unavailableText || null,
        unavailableText: undefined,
        coresUsed: stats.cpuCoresUsed, limitVcpus: taskCpu,
        percentOfVcpus: taskCpu,
        limitSource: taskCpu ? 'ecs-task' : 'none',
        limitText: 'From the ECS agent (/task/stats), between its last two ' +
          'samples, because the cgroup cannot be read here' + (taskCpu
            ? '; the percentage is of the ECS TASK\'s ' + taskCpu + ' vCPU.'
            : '; the task names no CPU limit, so there is no percentage.'),
        utilisationPercent: taskCpu ? round1(100 * stats.cpuCoresUsed /
                                             taskCpu) : null,
        sampled: 'ecs', windowSeconds: null, usageSeconds: null,
        userSeconds: null, systemSeconds: null, throttling: null,
        throttlingText: 'The ECS agent does not report throttling.'
      });
    } else if (outCpu.available && outCpu.limitVcpus === null && taskCpu) {
      Object.assign(outCpu, {
        percentOfVcpus: taskCpu, limitSource: 'ecs-task',
        limitText: 'The container has no CPU quota of its own (cgroup v' +
          outCpu.cgroupVersion + '), so the percentage is of the ECS ' +
          'TASK\'s ' + taskCpu + ' vCPU (/task Limits.CPU).',
        utilisationPercent: round1(100 * outCpu.coresUsed / taskCpu)
      });
    }
    helpers.log.debug("Leaving NodeHealthAdmin.withEcs().");
    return { cpu: NodeHealthAdmin.scrubUndefined(outCpu),
             memory: NodeHealthAdmin.scrubUndefined(outMem) };
  }

  // A copy without the members set to undefined.
  private static scrubUndefined(o: Json): Json {
    helpers.log.debug("Entering NodeHealthAdmin.scrubUndefined().");
    const out: Json = {};
    Object.keys(o).forEach(function (k: string): void {
      if (o[k] !== undefined) {
        out[k] = o[k];
      }
    });
    helpers.log.debug("Leaving NodeHealthAdmin.scrubUndefined().");
    return out;
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

  // A row for a process that reported `process.memoryUsage()` itself: its
  // resident size and CPU time are its own, every thread's included.
  private reportedRow(pid: number, role: string, memory: Json, cpu: Json,
                      uptimeS: number | null): Json {
    const { log } = this.deps;
    log.debug("Entering NodeHealthAdmin.reportedRow(). " + pid);
    log.debug("Leaving NodeHealthAdmin.reportedRow().");
    return {
      pid: pid, threadId: null, kind: 'process', role: role,
      source: 'process.memoryUsage()',
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

  // A row for a worker THREAD of the front process (#364): its own isolate's
  // heap figures, and no resident size or CPU time — in a thread those are
  // the process's, the same numbers in every thread, and they are on the
  // front process's row already.
  private threadRow(pid: number, threadId: number, role: string,
                    memory: Json, uptimeS: number | null): Json {
    const { log } = this.deps;
    log.debug("Entering NodeHealthAdmin.threadRow(). " + threadId);
    log.debug("Leaving NodeHealthAdmin.threadRow().");
    return {
      pid: pid, threadId: threadId, kind: 'thread', role: role,
      source: 'process.memoryUsage(), in the thread (heap figures only)',
      rssBytes: null,
      heapUsedBytes: Number(memory.heapUsed) || 0,
      heapTotalBytes: Number(memory.heapTotal) || 0,
      externalBytes: Number(memory.external) || 0,
      arrayBuffersBytes: Number(memory.arrayBuffers) || 0,
      peakRssBytes: null,
      cpuUserSeconds: null,
      cpuSystemSeconds: null,
      processWide: 'a thread\'s resident size and CPU time are the whole ' +
        'process\'s, so they are on the front process\'s row (pid ' + pid +
        ') and not repeated here',
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
      pid: pid, threadId: null, kind: 'process', role: role,
      source: '/proc/' + pid + '/status',
      rssBytes: m.rss, heapUsedBytes: null, heapTotalBytes: null,
      externalBytes: null, arrayBuffersBytes: null, peakRssBytes: m.hwm,
      cpuUserSeconds: null, cpuSystemSeconds: null, uptimeSeconds: null,
      unreadable: m.rss === null ? m.why : null
    };
  }

  // A child that answered its memory status: its own figures. One that did
  // not: its resident size from /proc, and why there is no heap.
  private async childRow(pid: number, role: string, answer: Json,
                         noAnswer: string): Promise<Json> {
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
      : noAnswer + ', so only its resident size is shown, from /proc';
    log.debug("Leaving NodeHealthAdmin.childRow(). From /proc.");
    return row;
  }

  /**
   * Every process and worker thread of the node and its memory: the front
   * process, each request and hosted-surface worker thread that answered
   * (its heap only, since #364), and the debugger's api child — the child
   * with its own `process.memoryUsage()` when it answered its memory status
   * (#329), and its resident size from /proc when it did not.
   *
   * @param stats - `request_pool.stats()`, whose worker `pid` is a threadId
   * @param answers - `{ [threadId]: { memory, cpu, uptimeS, error } }` from
   *   the worker threads
   * @param debuggerAnswer - the debugger's api child's answer, or null
   * @returns the processes view
   */
  async processesView(stats: Json, answers: Json,
                      debuggerAnswer?: Json): Promise<Json> {
    const { log, pid, memoryUsage, cpuUsage, uptimeS,
            debuggerProcess } = this.deps;
    const self = this;
    log.debug("Entering NodeHealthAdmin.processesView().");
    const rows: Json[] = [];
    const unanswered: Json[] = [];
    const children: Promise<Json>[] = [];
    const front = this.reportedRow(pid, 'front process', memoryUsage(),
                                   cpuUsage(), uptimeS());
    front.processWide = 'its resident size and CPU time are the whole ' +
      'process\'s, every worker thread\'s included; its heap figures are ' +
      'its main thread\'s';
    rows.push(front);
    // EACH WORKER IS A THREAD OF THIS PROCESS (#364): the pool's `pid` for it
    // is its threadId, and its row is its isolate's heap alone.
    (stats.workers || []).filter(function (one: Json): boolean {
      return one.ready;
    }).forEach(function (one: Json): void {
      const role = ((one.pool || 'protocol') === 'surfaces'
        ? 'hosted-surface worker thread ' : 'protocol worker thread ') +
        one.pid;
      const answer = answers[one.pid];
      if (answer && answer.memory) {
        rows.push(self.threadRow(pid, one.pid, role, answer.memory,
                                 answer.uptimeS === undefined
                                   ? null : answer.uptimeS));
      } else {
        // NOTHING TO FALL BACK ON: a thread has no /proc entry of its own,
        // and /proc/<pid> is the whole process, already on the front row.
        unanswered.push({ pid: pid, threadId: one.pid, role: role,
                          why: (answer
                            ? 'it answered without its memory'
                            : 'it did not answer within ' + ASK_WORKERS_MS +
                              'ms') + '; a thread has no /proc entry of its ' +
                            'own, so its heap cannot be read from outside ' +
                            'it' });
      }
    });
    let debuggerNote: string | null = null;
    try {
      const status = debuggerProcess().status();
      if (status && status.pid) {
        children.push(this.childRow(status.pid, 'protocol debugger api',
          debuggerAnswer && debuggerAnswer.pid === status.pid
            ? debuggerAnswer : null,
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
    const count = function (test: (row: Json) => boolean): number {
      log.debug("Entering count().");
      log.debug("Leaving count().");
      return rows.filter(test).length;
    };
    // A THREAD'S rssBytes IS NULL, so the resident sum below adds processes
    // alone: summing the process's size once per thread would count it N+1
    // times.
    const withRss = count(function (row: Json): boolean {
      return typeof row.rssBytes === 'number';
    });
    const withHeap = count(function (row: Json): boolean {
      return typeof row.heapUsedBytes === 'number';
    });
    const threads = count(function (row: Json): boolean {
      return row.kind === 'thread';
    });
    const view = {
      rows: rows,
      unanswered: unanswered,
      debuggerNote: debuggerNote,
      totals: {
        rows: rows.length,
        processes: rows.length - threads,
        workerThreads: threads,
        rssBytes: sum('rssBytes'),
        processesWithRss: withRss,
        heapUsedBytes: sum('heapUsedBytes'),
        heapTotalBytes: sum('heapTotalBytes'),
        externalBytes: sum('externalBytes'),
        isolatesWithHeap: withHeap
      },
      totalsText: 'The request and hosted-surface workers are THREADS of ' +
        'the front process (#364), so their resident size and CPU time are ' +
        'the front process\'s own figures and are counted once, on its row. ' +
        'The resident total is the sum over the ' + withRss + ' process(es) ' +
        'whose size could be read — the front process and the debugger\'s ' +
        'api child — so pages the two share (node\'s own code among them) ' +
        'are counted once for each and it can exceed the container\'s ' +
        'memory.current. The heap figures are the ' + withHeap + ' V8 ' +
        'isolate(s) that reported process.memoryUsage() themselves: the ' +
        'front process\'s main thread, each worker thread, and the child; a ' +
        'child process that did not answer in time is shown with its ' +
        'resident size from /proc and no heap, and a worker thread that did ' +
        'not is listed as unanswered, since a thread has no /proc entry of ' +
        'its own. Post-quantum signing and scrypt have had no processes ' +
        'of their own since #363: they run on libuv\'s thread pool, and ' +
        'their memory is counted in the process that asked.'
    };
    log.debug("Leaving NodeHealthAdmin.processesView(). " + rows.length +
              " row(s), " + threads + " of them thread(s).");
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
        // The agent says "no limit" with a number near 2^63, as cgroup v1
        // does; that is not a limit, and is said as one here (#329).
        memoryLimitBytes: typeof ms.limit === 'number' &&
          !NodeHealthAdmin.unlimitedBytes(ms.limit) ? ms.limit : null,
        memoryLimitUnlimited: typeof ms.limit === 'number' &&
          NodeHealthAdmin.unlimitedBytes(ms.limit),
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
  async localView(): Promise<Json> {
    const { log, requestPool, now, pid, nodeName, machine } = this.deps;
    log.debug("Entering NodeHealthAdmin.localView().");
    const node = nodeName();
    const pool = requestPool();
    const stats = pool.stats();
    const asking = (stats.workers || []).some(function (one: Json): boolean {
      return one.ready;
    });
    const where = await this.cgroupDir();
    const got = await Promise.all([
      this.cpuView(where),
      this.memoryView(where),
      asking ? pool.askWorkerPoolStatus(ASK_WORKERS_MS)
             : Promise.resolve({}),
      this.ecsView(),
      this.askDebugger()
    ]);
    const processes = await this.processesView(stats, got[2] || {},
                                               got[4]);
    // The ECS task's limits where the cgroup has none, and the agent's own
    // figures where there is no cgroup to read (#329, Fargate).
    const container = NodeHealthAdmin.withEcs(got[0], got[1], got[3]);
    const view = {
      generatedAt: new Date(now()).toISOString(),
      node: node,
      pid: pid,
      scope: 'node',
      scopeText: 'These are the figures of the node ' + node + ' — its ' +
        'container — drawn by its front process, pid ' + pid + '. Every ' +
        'node of a cluster is a container of its own, with its own figures.',
      cgroup: where.dir || where.memoryDir || null,
      cgroupVersion: where.version,
      cpu: container.cpu,
      memory: container.memory,
      processes: processes,
      ecs: got[3],
      machine: Object.assign({
        text: 'The machine this container runs on — on Fargate, the ' +
          'micro-VM; on a workstation, the whole workstation. NOT the ' +
          'container: its free memory and load say nothing about the ' +
          'container\'s limit.'
      }, machine())
    };
    log.debug("Leaving NodeHealthAdmin.localView().");
    return view;
  }

  /**
   * The cluster's totals over the nodes that are not gone and have a view:
   * container memory used and its limit, CPU used against the CPUs each
   * node measures against, and the processes and their memory.
   *
   * @param nodes - the node sections
   * @returns the totals
   */
  static totalsOf(nodes: Json[]): Json {
    helpers.log.debug("Entering NodeHealthAdmin.totalsOf().");
    const counted = nodes.filter(function (n: Json): boolean {
      return n.state !== 'gone' && !!n.view;
    });
    let memUsed = 0;
    let memLimit: number | null = 0;
    let memNodes = 0;
    let cores = 0;
    let cpus = 0;
    let cpuNodes = 0;
    let processes = 0;
    let threads = 0;
    let rss = 0;
    let heap = 0;
    counted.forEach(function (n: Json): void {
      const v = n.view;
      if (v.memory && v.memory.available) {
        memNodes++;
        memUsed += Number(v.memory.currentBytes) || 0;
        memLimit = memLimit !== null && typeof v.memory.limitBytes === 'number'
          ? memLimit + v.memory.limitBytes : null;
      }
      if (v.cpu && v.cpu.available) {
        cpuNodes++;
        cores += Number(v.cpu.coresUsed) || 0;
        cpus += Number(v.cpu.percentOfVcpus) || 0;
      }
      const t = (v.processes && v.processes.totals) || {};
      processes += Number(t.processes) || 0;
      threads += Number(t.workerThreads) || 0;
      rss += Number(t.rssBytes) || 0;
      heap += Number(t.heapUsedBytes) || 0;
    });
    const limit = memNodes ? memLimit : null;
    helpers.log.debug("Leaving NodeHealthAdmin.totalsOf().");
    return {
      nodes: nodes.length,
      nodesCounted: counted.length,
      memoryNodes: memNodes,
      memoryUsedBytes: memNodes ? memUsed : null,
      memoryLimitBytes: limit,
      memoryPercent: limit ? Math.round(1000 * memUsed / limit) / 10 : null,
      cpuNodes: cpuNodes,
      cpuCoresUsed: cpuNodes ? Math.round(cores * 1000) / 1000 : null,
      cpuOf: cpuNodes ? cpus : null,
      cpuPercent: cpus ? Math.round(1000 * cores / cpus) / 10 : null,
      processes: processes,
      workerThreads: threads,
      rssBytes: rss,
      heapUsedBytes: heap,
      text: 'Over the ' + counted.length + ' node(s) that are not gone ' +
        'and have a snapshot, stale ones included and marked. The limits ' +
        'are summed only when every node has one.'
    };
  }

  /**
   * Answers the page's JSON and `GET /admin-api/node-health`: this node's
   * live view at the top, and a section per cluster node with the cluster's
   * totals (#332). With `node`, the answer is about that node alone.
   *
   * @param opts - `{ node }` to narrow to one node by name
   * @returns a promise of the view, or `{ notFound }` for an unknown name
   */
  async nodeHealthView(opts?: { node?: string }): Promise<Json> {
    const { log, now, pid, snapshots } = this.deps;
    log.debug("Entering NodeHealthAdmin.nodeHealthView().");
    const local = await this.localView();
    const read = await snapshots().read('nodeHealth', local);
    const want = opts && opts.node ? String(opts.node) : '';
    let nodes = read.nodes;
    let subject: Json = local;
    if (want) {
      const hit = nodes.filter(function (n: Json): boolean {
        return n.name === want;
      })[0];
      if (!hit) {
        log.debug("Leaving NodeHealthAdmin.nodeHealthView(). No such node.");
        return { notFound: want, nodeNames: nodes.map(function (n: Json):
          string {
          return n.name;
        }) };
      }
      nodes = [hit];
      subject = hit.view || { node: hit.name };
    }
    const answer = Object.assign({}, subject, {
      generatedAt: new Date(now()).toISOString(),
      answeredBy: { node: local.node, pid: pid },
      state: nodes.length === 1 && want ? nodes[0].state : 'live',
      cluster: read.cluster,
      nodes: nodes,
      totals: NodeHealthAdmin.totalsOf(nodes)
    });
    log.debug("Leaving NodeHealthAdmin.nodeHealthView(). " + nodes.length +
              " node(s).");
    return snapshots().scrub(answer);
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
    if (cpu.fromEcs) {
      const ecsHtml = head + '<p>' + admin.esc(cpu.limitText) + '</p>' +
        this.rows([
          ['Utilisation', admin.esc(this.pct(cpu.utilisationPercent)),
           admin.esc(cpu.coresUsed) + ' CPU(s)' + (cpu.percentOfVcpus
             ? ' of ' + admin.esc(cpu.percentOfVcpus) : '') +
           ', as the ECS agent measured it']
        ]) + '<p><small>The cgroup: ' +
        admin.esc(cpu.cgroupUnavailableText || '') + '</small></p>';
      log.debug("Leaving NodeHealthAdmin.cpuHtml(). From ECS.");
      return ecsHtml;
    }
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
      ]) + '<p><small>From cgroup v' + admin.esc(cpu.cgroupVersion) +
      ', <code>' + admin.esc(cpu.source) + '</code>.</small></p>';
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
         'processes the kernel killed at the limit (oom_kill, in ' +
         'memory.events or v1\'s memory.oom_control)']
      ]) + '<p><small>' + admin.esc(m.statText) + ' From ' +
      (m.fromEcs ? 'the ECS agent, because the cgroup cannot be read: ' +
                   admin.esc(m.cgroupUnavailableText || '')
                 : 'cgroup v' + admin.esc(m.cgroupVersion) + ', <code>' +
                   admin.esc(m.source) + '</code>') + '.</small></p>';
    log.debug("Leaving NodeHealthAdmin.memoryHtml().");
    return html;
  }

  private processesHtml(p: Json): string {
    const { log, admin } = this.deps;
    const self = this;
    log.debug("Entering NodeHealthAdmin.processesHtml().");
    const t = p.totals;
    const html = '<h2 id="processes">Node.js processes and worker threads' +
      '</h2>' +
      this.rows([
        ['Processes', admin.esc(t.processes), 'listed below'],
        ['Worker threads', admin.esc(t.workerThreads || 0),
         'request and hosted-surface workers, threads of the front process'],
        ['Resident, in all', admin.esc(this.mib(t.rssBytes)),
         'across ' + admin.esc(t.processesWithRss) + ' process(es); a ' +
         'thread\'s is its process\'s'],
        ['Heap used, in all', admin.esc(this.mib(t.heapUsedBytes)),
         'of ' + admin.esc(this.mib(t.heapTotalBytes)) + ' allocated, ' +
         'across ' + admin.esc(t.isolatesWithHeap) + ' V8 isolate(s)']
      ]) + admin.note(admin.esc(p.totalsText), 'How the totals add up') +
      '<table class="grid"><thead><tr><th>Process or thread</th>' +
      '<th>Resident</th><th>Heap used</th><th>Heap total</th>' +
      '<th>External</th><th>Array buffers</th><th>CPU time</th></tr>' +
      '</thead><tbody>' +
      p.rows.map(function (r: Json): string {
        const thread = r.kind === 'thread';
        return '<tr><td>' + (thread ? 'thread ' + admin.esc(r.threadId) +
                             ' of pid ' + admin.esc(r.pid)
                           : 'pid ' + admin.esc(r.pid)) + '<br><small>' +
          admin.esc(r.role) + '</small></td><td>' +
          (thread ? '<small>the process\'s</small>'
           : r.unreadable ? '<small>' + admin.esc(r.unreadable) + '</small>'
             : admin.esc(self.mib(r.rssBytes))) +
          (r.notReported ? '<br><small>' + admin.esc(r.notReported) +
                           '</small>' : '') +
          '</td><td>' + admin.esc(self.mib(r.heapUsedBytes)) + '</td><td>' +
          admin.esc(self.mib(r.heapTotalBytes)) + '</td><td>' +
          admin.esc(self.mib(r.externalBytes)) + '</td><td>' +
          admin.esc(self.mib(r.arrayBuffersBytes)) + '</td><td>' +
          (thread ? '<small>the process\'s</small>'
           : r.cpuUserSeconds === null ? '—'
             : admin.esc(NodeHealthAdmin.round1(r.cpuUserSeconds +
                                                r.cpuSystemSeconds)) +
               ' s' + (r.processWide ? '<br><small>every thread\'s' +
                                       '</small>' : '')) + '</td></tr>';
      }).join('') + '</tbody></table>' +
      (p.unanswered.length ? admin.warn(
        p.unanswered.length + ' worker thread(s) did not report: ' +
        p.unanswered.map(function (u: Json): string {
          return 'thread ' + admin.esc(u.threadId) + ', ' +
            admin.esc(u.role) + ' (' + admin.esc(u.why) + ')';
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
         (s.memoryLimitUnlimited ? 'no container limit (the agent\'s "none")'
            : 'of ' + admin.esc(this.mib(s.memoryLimitBytes))) +
         ', /task/stats'],
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
      admin.tile(String(json.processes.totals.workerThreads || 0),
                 'Worker threads') +
      '</div>';
    const about = admin.note(
      '<p>' + admin.esc(json.scopeText) + '</p><p>The container\'s CPU and ' +
      'memory are read from its cgroup (v2), each process\'s and worker ' +
      'thread\'s from the process or thread itself, when the page is ' +
      'drawn; nothing is kept but the ' +
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

  // The page for every node: the cluster's totals and a section per node,
  // this node's from its live view and every other's from its snapshot.
  private clusterHtml(json: Json): string {
    const { log, admin } = this.deps;
    const self = this;
    log.debug("Entering NodeHealthAdmin.clusterHtml().");
    const c = json.cluster || {};
    const nodes: Json[] = json.nodes || [];
    const own = nodes.filter(function (n: Json): boolean {
      return n.self;
    })[0];
    if (!c.clustered || nodes.length < 2) {
      const html = admin.note(admin.esc(c.text || ''), 'Cluster') +
        (c.readError ? admin.warn(admin.esc(c.readError)) : '') +
        (own && own.view ? this.html(own.view)
                         : nodes[0] && nodes[0].view
                           ? this.html(nodes[0].view) : '');
      log.debug("Leaving NodeHealthAdmin.clusterHtml(). One node.");
      return html;
    }
    const t = json.totals;
    const html = '<h2 id="cluster">Cluster</h2><p>' + admin.esc(c.text) +
      '</p>' + (c.readError ? admin.warn(admin.esc(c.readError)) : '') +
      this.rows([
        ['Container memory', admin.esc(this.mib(t.memoryUsedBytes)),
         t.memoryLimitBytes === null ? 'no total limit to measure against'
           : admin.esc(this.pct(t.memoryPercent)) + ' of ' +
             admin.esc(this.mib(t.memoryLimitBytes))],
        ['CPU', t.cpuCoresUsed === null ? '—'
           : admin.esc(t.cpuCoresUsed) + ' CPU(s)',
         t.cpuPercent === null ? 'not measured'
           : admin.esc(this.pct(t.cpuPercent)) + ' of ' +
             admin.esc(t.cpuOf) + ' CPU(s)'],
        ['Processes', admin.esc(t.processes) + ' and ' +
           admin.esc(t.workerThreads || 0) + ' worker thread(s)',
         admin.esc(this.mib(t.rssBytes)) + ' resident (processes only), ' +
         admin.esc(this.mib(t.heapUsedBytes)) + ' of heap used']
      ]) + '<p><small>' + admin.esc(t.text) + '</small></p>' +
      '<table class="grid"><thead><tr><th>Node</th><th>State</th>' +
      '<th>Age</th></tr></thead><tbody>' +
      nodes.map(function (n: Json): string {
        return '<tr><td><a href="#node-' + admin.esc(n.name) + '">' +
          admin.esc(n.name) + '</a>' + (n.self ? ' (this node)' : '') +
          '</td><td>' + admin.esc(n.state) + '</td><td>' +
          (n.ageSeconds === null ? '—' : admin.esc(n.ageSeconds) + ' s') +
          '</td></tr>';
      }).join('') + '</tbody></table>' +
      nodes.map(function (n: Json): string {
        const head = '<h2 id="node-' + admin.esc(n.name) + '">Node ' +
          admin.esc(n.name) + (n.self ? ' (this node)' : '') + '</h2><p>' +
          '<strong>' + admin.esc(n.state) + '</strong>: ' +
          admin.esc(n.stateText) + '</p>';
        if (!n.view) {
          return head;
        }
        let body = '';
        try {
          body = self.html(n.view);
        } catch (e) {
          log.debug("Caught in NodeHealthAdmin.clusterHtml(): " +
                    ((e && e.message) || e));
          // A snapshot from another version of this page may lack a figure
          // this one draws; the node is still listed, and says so.
          return head + admin.warn('This node\'s snapshot could not be ' +
                                   'drawn: ' + admin.esc((e && e.message) ||
                                                         e) + '.');
        }
        // Another node's sections carry its name in their anchors, so the
        // page's own `id="cpu"` and the rest stay this node's.
        return head + (n.self ? body
          : body.replace(/ id="/g, ' id="' + admin.esc(n.name) + '-'));
      }).join('');
    log.debug("Leaving NodeHealthAdmin.clusterHtml().");
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
    // THIS NODE'S VIEW FOR THE OTHER NODES (#332): the job that writes it
    // is registered by the hand-over, in every process that loads the page.
    this.deps.snapshots().provide('nodeHealth', function (): Promise<Json> {
      return self.localView();
    });
    app.get(PAGE, function (req: Req, res: Res): void {
      log.debug('Entering GET ' + PAGE + '.');
      self.nodeHealthView({ node: req.query && req.query.node
                                    ? String(req.query.node) : '' })
        .then(function (json: Json): void {
          if (json.notFound) {
            errorCodes.mark(res, 'STS-CORE-0126');
            res.status(404).type('text/plain')
              .send('There is no node named ' + json.notFound + '.');
            return;
          }
          admin.respond(req, res, json, 'Node health', PAGE,
                        admin.messagesOf(req) + self.clusterHtml(json));
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
