// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

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
// realm's own administrator is refused it.
//
// **ITS ONE CONTROL IS A FULL GARBAGE COLLECTION, ON DEMAND (#611,
// 2026-10-13).** rcbj's decisions: THIS NODE, every process — the front
// process's main thread and every request and hosted-surface worker thread
// of the node serving the console, never the cluster; a Collect all button
// and a Collect button on each of those rows; service administrators only,
// because it is about the process (a realm's own administrator is refused
// the page and the operation alike, `admin_scope.ts`); both modes; audited.
// `collectGarbage()` answers `POST /admin-api/node-health/collect-garbage`,
// the operation the page's buttons are sent to. Each worker thread is an
// isolate of its own, so the front process asks each over the pool's channel
// (`request_pool.collectWorkerGarbage()`, answered by `request_worker.ts`)
// and collects its own main thread with `common/heap_collector.ts` while
// they work — the workers are asked FIRST, so they collect in parallel with
// the front rather than after it. Each isolate reports its heap before and
// after and the pause. A full collection stops the thread it runs in; in the
// front process that is every listener of the node, which the page says
// beside the buttons. It is a diagnostic: V8 collects on its own schedule,
// and a heap that a forced collection does not shrink is held, not garbage.
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
// A leaf requiring only node's `v8` and `vm` (#611): the front process's own
// garbage collection.
import HeapCollector = require('../common/heap_collector');
// At the top rather than lazily (#543 phase 2c): `server_prose.ts` requires
// only what config.js's neighbours already loaded, and this module is built
// at 18s, long after them — `encryption_admin.ts`'s arrangement.
import serverProse = require('../common/server_prose');
// The page's renderer (#446): a `web_` module, loadable in a browser.
import NodeHealthPage = require('./web_node_health');

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
// How long a garbage collection in the worker threads is waited for (#611):
// a full collection of a large heap takes longer than a status answer, and
// a thread still collecting at the bound is listed as not having answered.
const ASK_GC_MS = 10000;
// The one action of `POST /admin-api/node-health/{action}` (#611).
const COLLECT_ACTION = 'collect-garbage';
const ECS_TIMEOUT_MS = 1000;
// The interval between two CPU samples taken for one page, and the ages
// between which a kept sample is used instead.
const SAMPLE_MS = 500;
const MIN_WINDOW_US = 250 * 1000;
const MAX_WINDOW_US = 60 * 1000 * 1000;

const MIB = 1024 * 1024;

// ---------------------------------------------------------------------------
// EVERY SENTENCE THIS PAGE'S VIEW CARRIES, as a table (#543 phase 2c), so
// that the nodehealth namespace can carry them and `common/server_prose.ts`
// refill an answer to `GET /admin-api/node-health` in a console reader's
// language. Each is what the code below wrote inline until #543, byte for
// byte; a `{{name}}` is a value filled in with `serverProse.fill()` — a
// number, a file, a node's name, a pid, an error's own text (carried over as
// data) — or another sentence of this table (translated in turn).
//
// **ANOTHER NODE'S SECTION IS ITS STORED SNAPSHOT** (`node_snapshots.ts`),
// written in English by that node's front process, so it is translated by
// matching too, and only while that node runs a build whose templates are
// these: a node on an older build whose sentence differs is drawn in the
// English it wrote.
// ---------------------------------------------------------------------------
const SENTENCES = Object.freeze({
  notLinux: 'This node is not running on Linux ({{platform}}), so there are ' +
    'no cgroup files to read.',
  noCgroup: 'There is no cgroup at {{root}}: no cgroup v2 ({{why}}) and no ' +
    'cgroup v1 memory or cpuacct controller.',
  noCgroupShort: 'No cgroup.',
  cpuUnreadable: 'The container\'s CPU time cannot be read: {{source}} — ' +
    '{{why}}.',
  cpuOnce: 'The container\'s CPU time could be read once and not a second ' +
    'time: {{why}}.',
  cpuQuota: 'The container may use {{vcpus}} vCPU ({{version}}, {{file}}), ' +
    'and the percentage is of that.',
  cpuNoFile: 'This cgroup ({{version}}) has no {{file}}, so it has no CPU ' +
    'quota of its own; the percentage is of the {{cpus}} CPU(s) node ' +
    'reports available (os.availableParallelism()).',
  cpuUnlimited: 'No CPU quota ({{version}}, {{file}} says none): the ' +
    'container may use every CPU the host gives it, and the percentage is ' +
    'of the {{cpus}} CPU(s) node reports available ' +
    '(os.availableParallelism()).',
  noThrottling: 'The cgroup has no throttling counters: with no quota ' +
    'there is nothing to throttle against.',
  noV1Memory: 'This cgroup v1 host has no memory controller for this ' +
    'process.',
  memoryUnreadable: 'The container\'s memory cannot be read: {{source}} — ' +
    '{{why}}.',
  memoryLimit: 'The container may use {{mib}} MiB ({{version}}, {{file}}).',
  memoryNoFile: 'This cgroup ({{version}}) has no {{file}}, so it has no ' +
    'memory limit of its own and there is no percentage to give.',
  memoryUnlimited: 'No memory limit ({{version}}, {{file}} says none), so ' +
    'there is no percentage to give.',
  // `anon` and `file` are `anon`/`file` on v2 and `rss`/`cache` on v1:
  // memory.stat's own key names, carried over.
  memoryStat: '{{anon}} is the processes\' own memory; {{file}} is page ' +
    'cache the kernel reclaims under pressure before it kills anything.',
  memoryNoStat: 'memory.stat cannot be read, so what the memory is made of ' +
    'is not known.',
  ecsMemoryContainer: 'From the ECS agent (/task/stats), because the ' +
    'cgroup cannot be read here. The limit is the container\'s, as the ' +
    'agent reports it.',
  ecsMemoryTask: 'From the ECS agent (/task/stats), because the cgroup ' +
    'cannot be read here. The container has no limit of its own, so the ' +
    'limit is the ECS TASK\'s, {{mib}} MiB.',
  ecsMemoryNone: 'From the ECS agent (/task/stats), because the cgroup ' +
    'cannot be read here. There is no limit to measure against.',
  ecsTotalOnly: 'The ECS agent reports the total only.',
  taskMemoryLimit: 'The container has no memory limit of its own (cgroup ' +
    'v{{version}}), so the limit is the ECS TASK\'s, {{mib}} MiB (/task ' +
    'Limits.Memory), and the percentage is of that.',
  ecsCpuTask: 'From the ECS agent (/task/stats), between its last two ' +
    'samples, because the cgroup cannot be read here; the percentage is of ' +
    'the ECS TASK\'s {{vcpus}} vCPU.',
  ecsCpuNone: 'From the ECS agent (/task/stats), between its last two ' +
    'samples, because the cgroup cannot be read here; the task names no ' +
    'CPU limit, so there is no percentage.',
  ecsNoThrottling: 'The ECS agent does not report throttling.',
  taskCpuLimit: 'The container has no CPU quota of its own (cgroup ' +
    'v{{version}}), so the percentage is of the ECS TASK\'s {{vcpus}} vCPU ' +
    '(/task Limits.CPU).',
  procUnreadable: '{{file}} could not be read ({{why}})',
  noVmRss: 'its status file has no VmRSS',
  threadProcessWide: 'a thread\'s resident size and CPU time are the whole ' +
    'process\'s, so they are on the front process\'s row (pid {{pid}}) and ' +
    'not repeated here',
  frontProcessWide: 'its resident size and CPU time are the whole ' +
    'process\'s, every worker thread\'s included; its heap figures are its ' +
    'main thread\'s',
  roleFront: 'front process',
  roleDebugger: 'protocol debugger api',
  roleSurface: 'hosted-surface worker thread {{thread}}',
  roleProtocol: 'protocol worker thread {{thread}}',
  childNoMemory: 'it answered without its memory, so only its resident ' +
    'size is shown, from /proc',
  childNoAnswer: '{{why}}, so only its resident size is shown, from /proc',
  debuggerSilent: 'it did not answer within {{ms}}ms (its memory preload, ' +
    'debugger_api_status.js, answers when it is installed)',
  threadSilent: 'it did not answer within {{ms}}ms',
  threadUnanswered: '{{why}}; a thread has no /proc entry of its own, so ' +
    'its heap cannot be read from outside it',
  debuggerNoPid: 'The protocol debugger\'s api process could not be asked ' +
    'for its pid: {{error}}.',
  totals: 'The request and hosted-surface workers are THREADS of ' +
    'the front process (#364), so their resident size and CPU time are ' +
    'the front process\'s own figures and are counted once, on its row. ' +
    'The resident total is the sum over the {{rss}} process(es) ' +
    'whose size could be read — the front process and the debugger\'s ' +
    'api child — so pages the two share (node\'s own code among them) ' +
    'are counted once for each and it can exceed the container\'s ' +
    'memory.current. The heap figures are the {{heap}} V8 ' +
    'isolate(s) that reported process.memoryUsage() themselves: the ' +
    'front process\'s main thread, each worker thread, and the child; a ' +
    'child process that did not answer in time is shown with its ' +
    'resident size from /proc and no heap, and a worker thread that did ' +
    'not is listed as unanswered, since a thread has no /proc entry of ' +
    'its own. Post-quantum signing and scrypt have had no processes ' +
    'of their own since #363: they run on libuv\'s thread pool, and ' +
    'their memory is counted in the process that asked.',
  ecsNotSet: 'ECS_CONTAINER_METADATA_URI_V4 is not set: this node is not ' +
    'an Amazon ECS task (it is not on Fargate or an ECS container ' +
    'instance), so there is no task metadata endpoint to cross-check the ' +
    'cgroup against.',
  ecsSilent: 'ECS_CONTAINER_METADATA_URI_V4 is set, but the task metadata ' +
    'endpoint did not answer within {{ms}}ms: {{why}}.',
  // The trailing space is the inline sentence's own: it stood before a
  // second sentence that is empty when the container has stats.
  ecsPartial: 'Part of the endpoint did not answer: {{whys}}. ',
  // Each with the second sentence written out, so that a reason holding a
  // full stop cannot be split at the wrong one when an answer is matched.
  ecsPartialNoStats: 'Part of the endpoint did not answer: {{whys}}. There ' +
    'are no stats for this container in /task/stats.',
  ecsPartialNoStatsId: 'Part of the endpoint did not answer: {{whys}}. ' +
    'There are no stats for this container in /task/stats ({{dockerId}}).',
  ecsNoStats: 'There are no stats for this container in /task/stats.',
  ecsNoStatsId: 'There are no stats for this container in /task/stats ' +
    '({{dockerId}}).',
  ecsText: 'The ECS agent\'s own figures for this container, as a cross-' +
    'check of the cgroup: the agent samples on its own schedule, so ' +
    'they will not agree to the byte or the percent.',
  scope: 'These are the figures of the node {{node}} — its container — ' +
    'drawn by its front process, pid {{pid}}. Every node of a cluster is a ' +
    'container of its own, with its own figures.',
  machine: 'The machine this container runs on — on Fargate, the ' +
    'micro-VM; on a workstation, the whole workstation. NOT the ' +
    'container: its free memory and load say nothing about the ' +
    'container\'s limit.',
  clusterTotals: 'Over the {{count}} node(s) that are not gone and have a ' +
    'snapshot, stale ones included and marked. The limits are summed only ' +
    'when every node has one.'
});

// The phrases that appear only INSIDE a sentence above — why a file could
// not be read, why a sample has no CPU time — keyed `.param.` so that they
// are never matched as a whole string.
const PARAMS = Object.freeze({
  notThere: 'it is not there',
  notANumber: 'it is not a number',
  noUsage: 'it has no usage_usec',
  noCpuacct: 'there is no cgroup v1 cpuacct controller',
  noMemory: 'it answered without its memory'
});

// The routes whose answers carry the nodehealth namespace's prose (#543).
const PROSE_ROUTES = ['/admin-api/node-health'];

// A sentence of the table, filled.
const say = function say(key: keyof typeof SENTENCES,
                         params?: Record<string, unknown>): string {
  helpers.log.debug("Entering say(). " + key);
  const out = serverProse.fill(SENTENCES[key], params || {});
  helpers.log.debug("Leaving say().");
  return out;
};

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
  // A full garbage collection of this thread's isolate (#611):
  // `HeapCollector.collect()`, a dependency so a test can hand it a result.
  collectHere: () => Json;
  // LAZY, `requestPool`'s way: the audit log the collection is recorded in.
  audit: () => any;
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

  /**
   * The routes whose answers carry this module's prose (#543).
   */
  static readonly PROSE_ROUTES = PROSE_ROUTES;

  /**
   * Extracts the nodehealth namespace (#543 phase 2c): every sentence of the
   * view, the computed ones as templates, and the phrases that appear only
   * inside them. A row's `source` is not harvested: it names a file or a
   * function call (`process.memoryUsage()`, `/proc/<pid>/status`).
   *
   * @returns key → English
   */
  static prose(): Record<string, string> {
    helpers.log.debug("Entering NodeHealthAdmin.prose().");
    const out: Record<string, string> = Object.assign({},
      serverProse.harvest('nodehealth.s', SENTENCES, Object.keys(SENTENCES)),
      serverProse.harvest('nodehealth.param', PARAMS, Object.keys(PARAMS)));
    helpers.log.debug("Leaving NodeHealthAdmin.prose(). " +
                      Object.keys(out).length);
    return out;
  }

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
      sampleMs: SAMPLE_MS,
      collectHere: function collectHere(): Json {
        log.debug("Entering collectHere().");
        log.debug("Leaving collectHere().");
        return HeapCollector.collect(log);
      },
      audit: function audit(): any {
        log.debug("Entering audit().");
        log.debug("Leaving audit().");
        return require('../common/audit');
      }
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
               why: e && e.code === 'ENOENT' ? PARAMS.notThere
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
      return Object.assign(none, { why: say('notLinux',
                                            { platform: platform }) });
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
    return Object.assign(none, { why: say('noCgroup',
      { root: cgroupRoot, why: controllers.why }) });
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
               why: 'usage_usec' in stat ? '' : PARAMS.noUsage,
               source: file };
    }
    if (!where.cpuacctDir) {
      log.debug("Leaving NodeHealthAdmin.cpuSample(). No cpuacct.");
      return { stat: null, atUs: clockUs(), source: 'cpuacct.usage',
               why: PARAMS.noCpuacct };
    }
    const file = path.join(where.cpuacctDir, 'cpuacct.usage');
    const usage = await this.read(file);
    const atUs = clockUs();
    const ns = usage.text === null ? NaN : Number(usage.text.trim());
    if (!(ns >= 0)) {
      log.debug("Leaving NodeHealthAdmin.cpuSample(). Unreadable v1.");
      return { stat: null, atUs: atUs, source: file,
               why: usage.text === null ? usage.why : PARAMS.notANumber };
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
               unavailableText: where ? where.why : say('noCgroupShort') };
    }
    const key = where.version + ':' + (where.dir || where.cpuacctDir);
    let current = await this.cpuSample(where);
    if (!current.stat) {
      log.debug("Leaving NodeHealthAdmin.cpuView(). No CPU time.");
      return { available: false, cgroupVersion: where.version,
               source: current.source,
               unavailableText: say('cpuUnreadable',
                 { source: current.source, why: current.why }) };
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
                 unavailableText: say('cpuOnce', { why: second.why }) };
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
      limitText = say('cpuQuota', {
        vcpus: NodeHealthAdmin.round1(q.vcpus as number), version: version,
        file: q.file });
    } else if (q.kind === 'no-file') {
      limitText = say('cpuNoFile', { version: version, file: q.file,
                                     cpus: hostCpus });
    } else {
      limitText = say('cpuUnlimited', { version: version, file: q.file,
                                        cpus: hostCpus });
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
      throttlingText: throttling ? null : say('noThrottling')
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
               unavailableText: where ? where.why : say('noCgroupShort') };
    }
    const v2 = where.version === 2;
    const dir = v2 ? where.dir : where.memoryDir;
    if (!dir) {
      log.debug("Leaving NodeHealthAdmin.memoryView(). No v1 memory.");
      return { available: false, cgroupVersion: 1,
               unavailableText: say('noV1Memory') };
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
               unavailableText: say('memoryUnreadable', {
                 source: source, why: files[0].why || PARAMS.notANumber }) };
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
        ? say('memoryLimit', { mib: (limit / MIB).toFixed(0),
                               version: version, file: limitName })
        : say(maxText === null ? 'memoryNoFile' : 'memoryUnlimited',
              { version: version, file: limitName }),
      utilisationPercent: limit ? NodeHealthAdmin.round1(100 * used / limit)
                                : null,
      peakBytes: NodeHealthAdmin.numberOf(files[3]),
      anonBytes: v2 ? pick(['anon']) : pick(['total_rss', 'rss']),
      fileBytes: v2 ? pick(['file']) : pick(['total_cache', 'cache']),
      kernelBytes: v2 ? pick(['kernel']) : NodeHealthAdmin.numberOf(files[5]),
      statText: stat ? say('memoryStat', { anon: v2 ? 'anon' : 'rss',
                                           file: v2 ? 'file' : 'cache' })
                     : say('memoryNoStat'),
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
        limitText: typeof stats.memoryLimitBytes === 'number'
          ? say('ecsMemoryContainer')
          : lim ? say('ecsMemoryTask', { mib: (lim / MIB).toFixed(0) })
                : say('ecsMemoryNone'),
        utilisationPercent: lim ? round1(100 * stats.memoryUsageBytes / lim)
                                : null,
        peakBytes: null, anonBytes: null, fileBytes: null, kernelBytes: null,
        oomKills: null,
        statText: say('ecsTotalOnly')
      });
    } else if (outMem.available && outMem.limitBytes === null && taskMem) {
      Object.assign(outMem, {
        limitBytes: taskMem, limitSource: 'ecs-task',
        limitText: say('taskMemoryLimit', {
          version: outMem.cgroupVersion, mib: (taskMem / MIB).toFixed(0) }),
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
        limitText: taskCpu ? say('ecsCpuTask', { vcpus: taskCpu })
                           : say('ecsCpuNone'),
        utilisationPercent: taskCpu ? round1(100 * stats.cpuCoresUsed /
                                             taskCpu) : null,
        sampled: 'ecs', windowSeconds: null, usageSeconds: null,
        userSeconds: null, systemSeconds: null, throttling: null,
        throttlingText: say('ecsNoThrottling')
      });
    } else if (outCpu.available && outCpu.limitVcpus === null && taskCpu) {
      Object.assign(outCpu, {
        percentOfVcpus: taskCpu, limitSource: 'ecs-task',
        limitText: say('taskCpuLimit', { version: outCpu.cgroupVersion,
                                         vcpus: taskCpu }),
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
               why: say('procUnreadable', {
                 file: path.join(procRoot, String(pid), 'status'),
                 why: read.why }) };
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
             why: rss === null ? say('noVmRss') : '' };
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
      processWide: say('threadProcessWide', { pid: pid }),
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
    row.notReported = answer ? say('childNoMemory')
                             : say('childNoAnswer', { why: noAnswer });
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
    const front = this.reportedRow(pid, say('roleFront'), memoryUsage(),
                                   cpuUsage(), uptimeS());
    front.processWide = say('frontProcessWide');
    rows.push(front);
    // EACH WORKER IS A THREAD OF THIS PROCESS (#364): the pool's `pid` for it
    // is its threadId, and its row is its isolate's heap alone.
    (stats.workers || []).filter(function (one: Json): boolean {
      return one.ready;
    }).forEach(function (one: Json): void {
      const role = say((one.pool || 'protocol') === 'surfaces'
        ? 'roleSurface' : 'roleProtocol', { thread: one.pid });
      const answer = answers[one.pid];
      if (answer && answer.memory) {
        rows.push(self.threadRow(pid, one.pid, role, answer.memory,
                                 answer.uptimeS === undefined
                                   ? null : answer.uptimeS));
      } else {
        // NOTHING TO FALL BACK ON: a thread has no /proc entry of its own,
        // and /proc/<pid> is the whole process, already on the front row.
        unanswered.push({ pid: pid, threadId: one.pid, role: role,
                          why: say('threadUnanswered', { why: answer
                            ? PARAMS.noMemory
                            : say('threadSilent', { ms: ASK_WORKERS_MS }) }) });
      }
    });
    let debuggerNote: string | null = null;
    try {
      const status = debuggerProcess().status();
      if (status && status.pid) {
        children.push(this.childRow(status.pid, say('roleDebugger'),
          debuggerAnswer && debuggerAnswer.pid === status.pid
            ? debuggerAnswer : null,
          say('debuggerSilent', { ms: ASK_CHILDREN_MS })));
      }
    } catch (e) {
      log.debug("Caught in NodeHealthAdmin.processesView(): " +
                ((e && e.message) || e));
      // The debugger's api is a child only where the debugger runs; its row
      // is left out and the reason said.
      debuggerNote = say('debuggerNoPid',
                         { error: String((e && e.message) || e) });
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
      totalsText: say('totals', { rss: withRss, heap: withHeap })
    };
    log.debug("Leaving NodeHealthAdmin.processesView(). " + rows.length +
              " row(s), " + threads + " of them thread(s).");
    return view;
  }

  /**
   * What is missing from the ECS endpoint's answer, as the sentence the view
   * carries: which requests failed, and whether this container has no stats.
   * Byte for byte the concatenation it replaced (#543 phase 2c).
   *
   * @param whys - each failed request's reason, data carried over
   * @param hasStats - whether `/task/stats` had this container's figures
   * @param dockerId - the container's id, or null
   * @returns the sentence, or '' when nothing is missing
   */
  static ecsGaps(whys: string[], hasStats: boolean,
                 dockerId: string | null): string {
    helpers.log.debug("Entering NodeHealthAdmin.ecsGaps().");
    const params = { whys: whys.join('; '), dockerId: dockerId };
    let out: string;
    if (hasStats) {
      out = whys.length ? say('ecsPartial', params) : '';
    } else if (whys.length) {
      out = say(dockerId ? 'ecsPartialNoStatsId' : 'ecsPartialNoStats',
                params);
    } else {
      out = say(dockerId ? 'ecsNoStatsId' : 'ecsNoStats', params);
    }
    helpers.log.debug("Leaving NodeHealthAdmin.ecsGaps().");
    return out;
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
               unavailableText: say('ecsNotSet') };
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
      // STS-CORE-0125 is recorded on the warning above, where the silence
      // was detected; a code is never sent, so it is not in the answer.
      log.debug("Leaving NodeHealthAdmin.ecsView(). Nothing answered.");
      return { available: false,
               unavailableText: say('ecsSilent', { ms: ECS_TIMEOUT_MS,
                                                   why: got[0].why }) };
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
        ? NodeHealthAdmin.ecsGaps(failed.map(function (one: Json): string {
          return one.why;
        }), !!figures, dockerId)
        : null,
      text: say('ecsText')
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
      scopeText: say('scope', { node: node, pid: pid }),
      cgroup: where.dir || where.memoryDir || null,
      cgroupVersion: where.version,
      cpu: container.cpu,
      memory: container.memory,
      processes: processes,
      ecs: got[3],
      machine: Object.assign({ text: say('machine') }, machine())
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
      text: say('clusterTotals', { count: counted.length })
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

  // -------------------------------------------------------------------------
  // A FULL GARBAGE COLLECTION, ON DEMAND (#611). The module header has rcbj's
  // decisions; this is the one function the operation calls (rule 7: the
  // page's buttons are sent to that operation and nothing else).
  //
  // `target` is `all` (the default), `front` (the front process's main
  // thread) or the threadId of a ready worker thread of THIS node — the
  // pool's `pid` for it, and the `threadId` of its row on the page. A worker
  // is named only by an id this node's pool has: anything else is refused
  // before anything is collected (`STS-CORE-0160`).
  //
  // ONE AUDIT ROW PER PRESS, with every isolate's figures summed in it and
  // the count of those that failed or did not answer, rather than a row per
  // isolate: a Collect all on a node of eight workers is one act. Its code is
  // `STS-CORE-0158` when an isolate could not collect, `STS-CORE-0159` when
  // a worker did not answer, and none otherwise; the other condition, when
  // both happened, is logged under its own code.
  // -------------------------------------------------------------------------
  /**
   * Runs a full garbage collection in the front process's main thread, in
   * one worker thread, or in all of them, and reports each isolate's heap
   * before and after: `POST /admin-api/node-health/collect-garbage`.
   *
   * @param body - `{ action, target }`; `target` is `all`, `front` or a
   *   worker thread's threadId, and `all` when absent
   * @param actor - who asked, for the audit row
   * @returns `{ ok, status, ... }`: the per-isolate `rows`, `unanswered`,
   *   `totals` and `message`, or a refusal with `errors` and `errorCode`
   */
  async collectGarbage(body: Json, actor?: string): Promise<Json> {
    const { log, requestPool, collectHere, audit, pid, nodeName, now,
            errorCodes } = this.deps;
    log.debug("Entering NodeHealthAdmin.collectGarbage().");
    const action = String((body && body.action) || '');
    if (action !== COLLECT_ACTION) {
      log.debug("Leaving NodeHealthAdmin.collectGarbage(). Unknown action.");
      return { ok: false, status: 400, errorCode: 'STS-CORE-0160',
               errors: ['Unknown action "' + action + '". There is one: ' +
                        COLLECT_ACTION + '.'] };
    }
    const given = body && body.target !== undefined && body.target !== null
      ? String(body.target).trim() : '';
    const target = given || 'all';
    if (target !== 'all' && target !== 'front' && !/^\d+$/.test(target)) {
      log.debug("Leaving NodeHealthAdmin.collectGarbage(). Bad target.");
      return { ok: false, status: 400, errorCode: 'STS-CORE-0160',
               errors: ['The target "' + target + '" is none of all, ' +
                        'front or a worker thread\'s threadId.'] };
    }
    const pool = requestPool();
    const ready = (pool.stats().workers || []).filter(function (one: Json):
      boolean {
      return one.ready;
    });
    const threadIds = ready.map(function (one: Json): string {
      return String(one.pid);
    });
    const roleOf = function (threadId: string): string {
      log.debug("Entering roleOf(). " + threadId);
      const one = ready.filter(function (w: Json): boolean {
        return String(w.pid) === threadId;
      })[0];
      log.debug("Leaving roleOf().");
      return say((one && one.pool) === 'surfaces' ? 'roleSurface'
                                                  : 'roleProtocol',
                 { thread: threadId });
    };
    if (/^\d+$/.test(target) && threadIds.indexOf(target) < 0) {
      log.debug("Leaving NodeHealthAdmin.collectGarbage(). No such thread.");
      return { ok: false, status: 404, errorCode: 'STS-CORE-0160',
               errors: ['This node has no ready worker thread ' + target +
                        '; it has ' + (threadIds.length
                          ? threadIds.join(', ') : 'none') + '.'],
               threadIds: threadIds };
    }
    const ask = target === 'all' ? threadIds
      : target === 'front' ? [] : [target];
    // THE WORKERS ARE ASKED FIRST, so each collects on its own thread while
    // this one collects its own; asked after, they would wait for the front
    // process's pause before they started.
    const asking: Promise<Json> = ask.length
      ? pool.collectWorkerGarbage(ask, ASK_GC_MS)
      : Promise.resolve({ asked: [], answers: {} });
    const rows: Json[] = [];
    if (target === 'all' || target === 'front') {
      rows.push(Object.assign({ kind: 'process', pid: pid, threadId: 0,
                                role: say('roleFront') }, collectHere()));
    }
    const got = await asking;
    const unanswered: Json[] = [];
    (got.asked || []).forEach(function (one: unknown): void {
      const threadId = String(one);
      const role = roleOf(threadId);
      const answer = (got.answers || {})[threadId];
      if (!answer) {
        unanswered.push({ pid: pid, threadId: Number(threadId), role: role,
                          why: say('threadSilent', { ms: ASK_GC_MS }) });
        return;
      }
      rows.push(Object.assign({ kind: 'thread', pid: pid,
                                threadId: Number(threadId), role: role },
                              answer));
    });
    const collected = rows.filter(function (r: Json): boolean {
      return r.ok;
    });
    const failed = rows.filter(function (r: Json): boolean {
      return !r.ok;
    });
    const freed = collected.reduce(function (n: number, r: Json): number {
      return n + (Number(r.freedBytes) || 0);
    }, 0);
    const longest = collected.reduce(function (n: number, r: Json): number {
      return Math.max(n, Number(r.durationMs) || 0);
    }, 0);
    const node = nodeName();
    const code = failed.length ? 'STS-CORE-0158'
      : (unanswered.length ? 'STS-CORE-0159' : '');
    if (failed.length && unanswered.length) {
      log.warn(errorCodes.tag('STS-CORE-0159') + 'node_health_admin: ' +
               unanswered.length + ' worker thread(s) did not answer a ' +
               'garbage collection within ' + ASK_GC_MS + 'ms: ' +
               unanswered.map(function (u: Json): string {
                 return String(u.threadId);
               }).join(', ') + '.');
    }
    const summary = 'A full garbage collection ran in ' + collected.length +
      ' isolate(s) of node ' + node + ' (target ' + target + '), freeing ' +
      NodeHealthAdmin.round1(freed / MIB) + ' MiB; the longest pause was ' +
      NodeHealthAdmin.round1(longest) + ' ms' +
      (failed.length ? '; ' + failed.length + ' could not collect (' +
        failed.map(function (r: Json): string {
          return r.role + ': ' + r.error;
        }).join('; ') + ')' : '') +
      (unanswered.length ? '; ' + unanswered.length + ' did not answer' : '') +
      '.';
    try {
      audit().record({
        action: 'node-health.collect-garbage', protocol: 'admin',
        channel: 'http', actor: String(actor || ''),
        target: node + ' ' + target,
        outcome: code ? 'error' : 'success',
        errorCode: code || undefined,
        summary: summary,
        detail: { node: node, target: target, isolates: rows.length,
                  collected: collected.length, failed: failed.length,
                  unanswered: unanswered.length, freedBytes: freed,
                  longestPauseMs: longest }
      });
    } catch (e) {
      log.debug("Caught in NodeHealthAdmin.collectGarbage(): " +
                ((e && e.message) || e));
      // Recording never fails an operation (`audit.js`): the collection has
      // run, and its answer still goes back.
    }
    const frontFailedAlone = rows.length === 1 && failed.length === 1 &&
                             !ask.length;
    log.debug("Leaving NodeHealthAdmin.collectGarbage(). " +
              collected.length + " collected.");
    return {
      ok: !frontFailedAlone,
      status: frontFailedAlone ? 500 : 200,
      errorCode: code || undefined,
      errors: frontFailedAlone ? [String(failed[0].error)] : undefined,
      generatedAt: new Date(now()).toISOString(),
      node: node,
      pid: pid,
      target: target,
      rows: rows,
      unanswered: unanswered,
      totals: { isolates: rows.length, collected: collected.length,
                failed: failed.length, unanswered: unanswered.length,
                freedBytes: freed, longestPauseMs: longest },
      message: summary
    };
  }

  // DRAWN BY `web_node_health.ts` (#446): this page is converted for the
  // static console, and its renderer is a module a browser can load. Until the
  // cutover this process still draws it, handing the renderer the view passed
  // THROUGH JSON, so it is held to what the API's caller receives.
  private clusterHtml(json: Json): string {
    const { log } = this.deps;
    log.debug("Entering NodeHealthAdmin.clusterHtml().");
    const drawn = NodeHealthPage.render(JSON.parse(JSON.stringify(json)));
    log.debug("Leaving NodeHealthAdmin.clusterHtml().");
    return drawn;
  }

  // ONE NODE'S SECTIONS, by the same renderer and through the same round
  // trip. Kept because `tests/node_health_page.js` draws a single node's view
  // with it; the page itself goes through `clusterHtml()` above.
  private html(json: Json): string {
    const { log } = this.deps;
    log.debug("Entering NodeHealthAdmin.html().");
    const drawn = NodeHealthPage.html(JSON.parse(JSON.stringify(json)));
    log.debug("Leaving NodeHealthAdmin.html().");
    return drawn;
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
 * memory, and the memory of every Node.js process of this node, and a full
 * garbage collection of any of them on demand (#611). A service page.
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
  // The nodehealth namespace's routes and English (#543 phase 2c).
  PROSE_ROUTES: NodeHealthAdmin.PROSE_ROUTES,
  prose: NodeHealthAdmin.prose,
  // For `mgmt-api/admin_api.ts` (rule 7).
  nodeHealthView: slot.forward('nodeHealthView'),
  // `POST /admin-api/node-health/collect-garbage` (#611).
  collectGarbage: slot.forward('collectGarbage'),
  COLLECT_ACTION: COLLECT_ACTION
};
