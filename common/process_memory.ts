// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: process_memory.ts
//
// ---------------------------------------------------------------------------
// A HEAP LIMIT FOR EVERY PROCESS, DERIVED FROM THE CONTAINER, AND A MEMORY
// REPORT PER PROCESS (#341, 2026-09-29).
//
// A node of this service is up to 1 + workers.requestCount +
// workers.surfaceCount processes, and each of them holds the whole store in
// its own heap. Until this module NOTHING set a V8 heap limit, in either
// image, in `ecs.tf` or in the request pool's fork(). V8's default is sized
// to the MACHINE and not to the container, so five processes could each grow
// towards it. When the task ran out, the kernel SIGKILLed whichever was
// biggest, and the log said `worker N was killed with SIGKILL` (testidp
// node-a, 2026-09-28 20:32 UTC) with no code, no heap figure and no hint of
// which store had grown.
//
// **THE BUDGET.** `workers.heapLimitMb`, when it is above 0, is every
// process's limit. At -1 it is OFF: this service applies no limit at all, so
// the front process is not re-executed and no worker is forked with the flag.
// That is rcbj's setting for testidp while its processes are larger than a
// derived budget would allow (2026-09-29); the memory report and the
// OOM-kill attribution (STS-WORKER-0047) work the same with it off. At 0, the
// default, the limit is DERIVED:
//
//     (container limit − headroom) ÷ (1 + requestCount + surfaceCount)
//       − 48 MiB of young generation
//
// — one share per ISOLATE, the front's and each worker thread's (#364),
// and each isolate's young generation set to 48 MiB and taken out of its
// share (#366; see YOUNG_MB). (Until #363 the divisor carried one more
// share, for the post-quantum computation children of `worker_pool.js`;
// that pool is gone.) The headroom is 15 % of the limit and at least 256
// MiB. It is what the process holds OUTSIDE the isolates' heaps: code,
// Buffers and native memory. The old space is floored at 192 MiB. With no
// visible limit (`max` on cgroup v2, the v1 "unlimited" value, no ECS task
// limit), NOTHING is set, which is how this service ran before.
//
// **THE FLAG BOUNDS THE OLD SPACE ONLY.** V8's `heap_size_limit`, which the
// report prints as the limit, is that plus the young generation's ceiling:
// 192 MiB in node 24 whatever the old space is (300 gives 492, measured in
// tests/process_memory.js). The young generation rarely grows to its
// ceiling, and the headroom is what it comes out of. On testidp's 8 GiB
// node with 3 + 1 workers the budget is 1392 MiB of old space per process.
//
// **WHERE THE CONTAINER LIMIT IS READ FROM, IN ORDER.** cgroup v2's
// `memory.max`; cgroup v1's `memory.limit_in_bytes`, then its `memory.stat`
// `hierarchical_memory_limit` (the limit an ancestor sets, which is where a
// Fargate task's is when the container has none of its own); and last the
// ECS task metadata endpoint's `Limits.Memory`, when
// `ECS_CONTAINER_METADATA_URI_V4` is set. On cgroup v2, a container sees its
// own cgroup and none of its ancestors, and `ecs.tf` sets `memory` on the
// TASK and not on the container. So on Fargate the task's own answer is the
// one that reaches the number.
//
// **THE FRONT PROCESS RE-EXECUTES ITSELF WITH THE FLAG.** This is the choice
// that had to be argued. `--max-old-space-size` is read when V8 starts, and
// the alternatives were:
//
//   * `v8.setFlagsFromString()` at run time. It is NOT reliable: the heap is
//     already configured by then, and V8's documentation says changing a
//     flag after start-up is undefined behaviour.
//   * NODE_OPTIONS set by an entrypoint script. Every child would inherit it
//     (the request workers, the crypto children, the debugger's api child
//     and every `node -e` of a compose command), and every way this image
//     is started would have to go through the script. The two compose
//     files and `docker run` override the command with `exec node
//     server.js`, and the AWS nodes use the image's own CMD. (The
//     `entrypoint.sh` in deploy/aws is the Terraform runner's, not the
//     service's.)
//   * A launcher that computes the flag and SPAWNS node. That is two
//     processes where there was one, with PID 1 forwarding signals.
//
// So `server.js` calls `reexecWithHeapLimit()` on its second line of work,
// and when a limit is due the process replaces itself through
// `process.execve()` (node ≥ 22.15 / 23.11; the image runs 24). It keeps the
// same pid and the same file descriptors, and nothing is lost that was not
// just computed. It works wherever `node server.js` runs: the image's CMD,
// both compose files, `docker run` and ECS. A marker in the environment
// (`STS_HEAP_REEXEC`) stops a second pass, and `STS_HEAP_BUDGET` carries the
// budget across, so it is computed once. A limit an OPERATOR set with the
// flag or in NODE_OPTIONS is left alone and becomes the budget. Where
// `process.execve` is missing, or it fails, the service starts without a
// limit and says so (`STS-WORKER-0048`); a heap limit is protection, and
// its absence was the state before.
//
// **THE WORKERS** are forked with `execArgv` carrying the same flag (the
// request pool's fork()). **THE BUDGET IS READ BEFORE THE STORE IS OPENED**,
// from the appconfig layers and the environment. A restart-only override
// saved in the store is not in it, and every process uses this one number.
//
// **THE REPORT** is the per-process scheduler job `process.memory-report`. It
// runs every five minutes in every process that runs the scheduler (the
// front and each request worker), and each run logs ONE line with the role,
// `process.memoryUsage()` and the heap limit. A request worker also sends
// its figures to the front process over the pool's channel, so that a later
// exit can be reported beside the last figures seen (`STS-WORKER-0046`,
// `0047`). The run's summary is recorded like any per-process run, so
// Monitoring → Scheduler shows each process's latest.
//
// A LEAF: it requires config, error_codes and node's own modules at load,
// and the scheduler only through the instance `protocol_stack.ts` hands it.
// ---------------------------------------------------------------------------

import fs = require('fs');
import v8 = require('v8');
import childProcess = require('child_process');
import bunyan = require('bunyan');
import config = require('./config');
import errorCodes = require('./error_codes');
import WorkerChannel = require('./worker_channel');

let logLevelProblem: any = null;
const log = bunyan.createLogger({
  name: 'process_memory',
  level: (function (): any {
    try {
      return config.value('global.logLevel') || 'info';
    } catch (e) {
      logLevelProblem = e;
      return 'info';
    }
  })()
});
if (logLevelProblem) {
  log.debug('No log level could be read, so info: ' +
            ((logLevelProblem && logLevelProblem.message) || logLevelProblem));
}

const MIB = 1024 * 1024;
// A cgroup v1 limit at or above this is v1's way of saying "none"
// (9223372036854771712 on a 4 KiB page).
const UNLIMITED = Math.pow(2, 60);
// See the header: 15 % of the limit and at least 256 MiB stays outside every
// isolate's heap, and no isolate is given less than MIN_MB of old space.
const HEADROOM_SHARE = 0.15;
const HEADROOM_MIN = 256 * MIB;
// 192 since #366, where it was 256: the floor on OLD space, and with the
// young generation now inside the share a 512 MiB container with one
// isolate derives 208 MiB, which a floor of 256 would have pushed past the
// container. A fresh isolate's live heap is about 100 MiB since #365.
const MIN_MB = 192;
// How long the ECS task metadata endpoint is given.
const ECS_TIMEOUT_MS = 3000;
const REEXEC_MARKER = 'STS_HEAP_REEXEC';
const BUDGET_ENV = 'STS_HEAP_BUDGET';
const FLAG = '--max-old-space-size';
// ---------------------------------------------------------------------------
// THE YOUNG GENERATION IS PART OF THE SHARE (#366, 2026-09-30).
//
// `--max-old-space-size` bounds the OLD space only, and V8's young
// generation comes on top of it: 192 MiB in node 24 whatever the old space
// is. That was tolerable at one isolate per process with 15 % headroom
// under it, and it is not at two isolates in a 1 GiB container (#364): two
// shares of 384 MiB of old space each carried 192 MiB of young ceiling on
// top, 1152 MiB of possible heap in a 1024 MiB container. So each isolate's
// young generation is set too — 48 MiB, V8's three semi-spaces of 16 MiB,
// `--max-semi-space-size` for the front and `maxYoungGenerationSizeMb` for a
// worker thread — and it comes OUT of the isolate's share: old space is the
// share less 48 MiB. A young generation of 48 MiB scavenges more often than
// one of 192 MiB, and each scavenge is shorter.
// ---------------------------------------------------------------------------
const YOUNG_MB = 48;
const SEMI_FLAG = '--max-semi-space-size';
const SEMI_MB = YOUNG_MB / 3;
const REPORT_JOB = 'process.memory-report';
const REPORT_EVERY_MS = 5 * 60 * 1000;

/**
 * Where a container memory limit was read, and what it was.
 */
interface ContainerLimit {
  bytes: number | null;
  source: string;
}

/**
 * Every process's heap budget: `mb` 0 means no limit is set.
 */
interface Budget {
  mb: number;
  // The young generation each isolate is given beside `mb` (#366); 0 when
  // no budget applies.
  youngMb?: number;
  // workers.heapLimitMb is -1: no limit is applied, and nothing is stripped.
  off?: boolean;
  source: string;
  limitBytes: number | null;
  processes: number;
}

/**
 * The figures one process reports.
 */
interface Snapshot {
  role: string;
  pid: number;
  rssMb: number;
  heapUsedMb: number;
  heapTotalMb: number;
  externalMb: number;
  arrayBuffersMb: number;
  heapLimitMb: number;
  at: number;
}

type Reader = (file: string) => string;

let cachedBudget: Budget | null = null;

/**
 * The heap limit of every process of a node, derived from the container,
 * and the per-process memory report. A static utility class.
 */
class ProcessMemory {
  /**
   * Reads a file as text; the default reader of every method below.
   *
   * @param file - the path
   * @returns its contents
   */
  static readText(file: string): string {
    log.debug("Entering ProcessMemory.readText().");
    log.debug("Leaving ProcessMemory.readText().");
    return fs.readFileSync(file, 'utf8');
  }

  /**
   * Reads the container's memory limit from its cgroup: v2 first, then v1
   * and v1's hierarchical limit.
   *
   * @param read - optional; reads a file, for tests
   * @returns `{ bytes, source }`, `bytes` null when there is no limit
   */
  static cgroupLimit(read?: Reader): ContainerLimit {
    log.debug("Entering ProcessMemory.cgroupLimit().");
    const readFile = read || ProcessMemory.readText;
    let v2: string | null = null;
    try {
      v2 = readFile('/sys/fs/cgroup/memory.max').trim();
    } catch (e) {
      log.debug("Caught in ProcessMemory.cgroupLimit(): " +
                ((e && e.message) || e));
      // Not cgroup v2, or no memory controller: v1 below.
      v2 = null;
    }
    if (v2 !== null) {
      const bytes = /^\d+$/.test(v2) ? Number(v2) : null;
      log.debug("Leaving ProcessMemory.cgroupLimit(). v2.");
      return { bytes: bytes && bytes < UNLIMITED ? bytes : null,
               source: 'cgroup v2 memory.max (' + v2 + ')' };
    }
    let v1: number | null = null;
    try {
      v1 = Number(readFile(
        '/sys/fs/cgroup/memory/memory.limit_in_bytes').trim());
    } catch (e) {
      log.debug("Caught in ProcessMemory.cgroupLimit(): " +
                ((e && e.message) || e));
      log.debug("Leaving ProcessMemory.cgroupLimit(). No cgroup.");
      return { bytes: null, source: 'no memory cgroup' };
    }
    if (v1 && v1 > 0 && v1 < UNLIMITED) {
      log.debug("Leaving ProcessMemory.cgroupLimit(). v1.");
      return { bytes: v1, source: 'cgroup v1 memory.limit_in_bytes' };
    }
    // THE LIMIT AN ANCESTOR SETS: a Fargate task's, when the container has
    // none of its own.
    let hierarchical: number | null = null;
    try {
      const stat = readFile('/sys/fs/cgroup/memory/memory.stat');
      const found = /^hierarchical_memory_limit\s+(\d+)\s*$/m.exec(stat);
      hierarchical = found ? Number(found[1]) : null;
    } catch (e) {
      log.debug("Caught in ProcessMemory.cgroupLimit(): " +
                ((e && e.message) || e));
      hierarchical = null;
    }
    if (hierarchical && hierarchical > 0 && hierarchical < UNLIMITED) {
      log.debug("Leaving ProcessMemory.cgroupLimit(). v1 hierarchical.");
      return { bytes: hierarchical,
               source: 'cgroup v1 hierarchical_memory_limit' };
    }
    log.debug("Leaving ProcessMemory.cgroupLimit(). v1 unlimited.");
    return { bytes: null, source: 'cgroup v1, unlimited' };
  }

  // THE ECS TASK'S OWN LIMIT, asked of the task metadata endpoint (v4) when
  // the cgroup shows none. Synchronous because it is asked once, before
  // anything else has started, and the answer decides whether this process
  // replaces itself. So it runs as a bounded child whose output is read, and
  // costs one short node start on ECS and nothing anywhere else.
  /**
   * Reads the ECS task's memory limit from the task metadata endpoint, when
   * `ECS_CONTAINER_METADATA_URI_V4` is set.
   *
   * @returns the limit in bytes, or null
   */
  static ecsTaskLimit(): number | null {
    log.debug("Entering ProcessMemory.ecsTaskLimit().");
    const uri = process.env.ECS_CONTAINER_METADATA_URI_V4;
    if (!uri) {
      log.debug("Leaving ProcessMemory.ecsTaskLimit(). Not on ECS.");
      return null;
    }
    const script =
      "fetch(process.env.U + '/task').then(function (r) { return r.json(); })" +
      ".then(function (j) { process.stdout.write(String((j && j.Limits && " +
      "j.Limits.Memory) || '')); }, function () {})";
    try {
      const env: any = Object.assign({}, process.env, { U: uri });
      delete env.NODE_OPTIONS;
      const out = childProcess.execFileSync(process.execPath, ['-e', script],
        { env: env, timeout: ECS_TIMEOUT_MS, encoding: 'utf8',
          stdio: ['ignore', 'pipe', 'ignore'] });
      const mib = Number(String(out).trim());
      log.debug("Leaving ProcessMemory.ecsTaskLimit().");
      return mib > 0 ? mib * MIB : null;
    } catch (e) {
      log.debug("Caught in ProcessMemory.ecsTaskLimit(): " +
                ((e && e.message) || e));
      // An endpoint that does not answer in time is a limit this process
      // cannot see, which is the same as none: no heap limit is set.
      log.debug("Leaving ProcessMemory.ecsTaskLimit(). No answer.");
      return null;
    }
  }

  /**
   * The container's memory limit: the cgroup's, else the ECS task's.
   *
   * @returns `{ bytes, source }`
   */
  static containerLimit(): ContainerLimit {
    log.debug("Entering ProcessMemory.containerLimit().");
    const cgroup = ProcessMemory.cgroupLimit();
    if (cgroup.bytes) {
      log.debug("Leaving ProcessMemory.containerLimit(). cgroup.");
      return cgroup;
    }
    const ecs = ProcessMemory.ecsTaskLimit();
    if (ecs) {
      log.debug("Leaving ProcessMemory.containerLimit(). ECS.");
      return { bytes: ecs, source: 'the ECS task metadata endpoint' };
    }
    log.debug("Leaving ProcessMemory.containerLimit(). None.");
    return cgroup;
  }

  /**
   * Derives every process's heap budget. A decision over its arguments.
   *
   * @param input - `configuredMb` (workers.heapLimitMb), `limitBytes` and
   *   its `source`, and the two pool sizes
   * @returns the budget; `mb` 0 when no limit is to be set
   */
  static derive(input: { configuredMb: number; limitBytes: number | null;
                         source?: string; requestCount: number;
                         surfaceCount: number }): Budget {
    log.debug("Entering ProcessMemory.derive().");
    const processes = 1 + Math.max(0, input.requestCount || 0) +
      Math.max(0, input.surfaceCount || 0);
    if (input.configuredMb < 0) {
      log.debug("Leaving ProcessMemory.derive(). Off.");
      return { mb: 0, off: true,
               source: 'workers.heapLimitMb is -1: no heap limit is applied',
               limitBytes: input.limitBytes, processes: processes };
    }
    if (input.configuredMb > 0) {
      log.debug("Leaving ProcessMemory.derive(). Configured.");
      return { mb: Math.floor(input.configuredMb), youngMb: YOUNG_MB,
               source: 'workers.heapLimitMb', limitBytes: input.limitBytes,
               processes: processes };
    }
    if (!input.limitBytes) {
      log.debug("Leaving ProcessMemory.derive(). No limit.");
      return { mb: 0, source: 'no container memory limit is visible (' +
                              (input.source || 'none') + ')',
               limitBytes: null, processes: processes };
    }
    const headroom = Math.max(HEADROOM_MIN,
                              input.limitBytes * HEADROOM_SHARE);
    const share = Math.floor((input.limitBytes - headroom) / processes / MIB);
    const old = share - YOUNG_MB;
    log.debug("Leaving ProcessMemory.derive(). Derived.");
    return { mb: Math.max(MIN_MB, old), youngMb: YOUNG_MB,
             source: 'derived: (' + Math.round(input.limitBytes / MIB) +
                     ' MiB from ' + (input.source || 'the container') +
                     ' − ' + Math.round(headroom / MIB) + ' MiB headroom) ÷ ' +
                     processes + ' isolates − ' + YOUNG_MB + ' MiB young ' +
                     'generation each' +
                     (old < MIN_MB ? ', raised to the ' + MIN_MB +
                                     ' MiB floor' : ''),
             limitBytes: input.limitBytes, processes: processes };
  }

  /**
   * Reads the three settings the budget depends on.
   *
   * @returns `{ configuredMb, requestCount, surfaceCount }`, all 0 with no
   *   configuration; `configuredMb` is -1 when the limit is off
   */
  // -------------------------------------------------------------------------
  // ONE REQUEST WORKER BY DEFAULT, WHERE THE STORE CAN COORDINATE (#364,
  // rcbj).
  //
  // `workers.requestCount` defaults to 1, `workers.dispatch` to `*` and
  // `workers.readYourWrite` to on. A worker needs a store that coordinates —
  // persistence.mode postgres with persistence.coordinate on — because it
  // holds its own copy of every store and learns the others' writes from the
  // change log. On the memory or ldif store the DEFAULT therefore means none:
  // a development service is one thread, as it always was, and says so once.
  // An OPERATOR's value is theirs: `workers.requestCount` set explicitly
  // without coordination is still refused at startup (STS-WORKER-0024,
  // `request_pool.js`'s start()).
  //
  // HERE rather than in `request_pool.js`, which asks it for its size:
  // this file divides the heap budget by the same count, and runs first of
  // all — before the store is opened and before the pool is loaded — so the
  // rule is decided from the settings alone and written once.
  // -------------------------------------------------------------------------
  /**
   * How many request worker threads this process runs: `workers.requestCount`,
   * except that its default of 1 is 0 where the store cannot coordinate.
   *
   * @returns the count, 0 or more
   */
  static requestWorkers(): number {
    log.debug("Entering ProcessMemory.requestWorkers().");
    let wanted = 0;
    let byDefault = false;
    let coordinates = false;
    let mode = '';
    try {
      wanted = parseInt(config.value('workers.requestCount'), 10);
      const source = config.sourceOf('workers.requestCount');
      byDefault = source === 'default' || source === 'defaults';
      mode = String(config.value('persistence.mode'));
      coordinates = mode === 'postgres' &&
        config.value('persistence.coordinate') !== false;
    } catch (e) {
      log.debug("Caught in ProcessMemory.requestWorkers(): " +
                ((e && e.message) || e));
      // No configuration at all (an in-process test): no worker, which is
      // the right answer for a module loaded on its own.
      log.debug("Leaving ProcessMemory.requestWorkers(). No settings; 0.");
      return 0;
    }
    if (!(wanted > 0)) {
      log.debug("Leaving ProcessMemory.requestWorkers(). 0.");
      return 0;
    }
    if (byDefault && !coordinates) {
      if (!ProcessMemory.noCoordinationNoted) {
        ProcessMemory.noCoordinationNoted = true;
        log.info('process_memory: no request worker — ' +
                 'workers.requestCount is at its default and the store ' +
                 '(persistence.mode "' + mode + '") does not coordinate, so ' +
                 'every request is handled in the front thread.');
      }
      log.debug("Leaving ProcessMemory.requestWorkers(). The default, " +
                "without coordination; 0.");
      return 0;
    }
    log.debug("Leaving ProcessMemory.requestWorkers(). " + wanted + ".");
    return wanted;
  }

  // Whether requestWorkers() has said once that the default means none.
  private static noCoordinationNoted = false;

  static settings(): { configuredMb: number; requestCount: number;
                       surfaceCount: number } {
    log.debug("Entering ProcessMemory.settings().");
    const read = function (key: string, allowOff?: boolean): number {
      try {
        const n = parseInt(config.value(key), 10);
        if (allowOff && n < 0) {
          return -1;
        }
        return n > 0 ? n : 0;
      } catch (e) {
        log.debug("Caught in ProcessMemory.settings(): " +
                  ((e && e.message) || e));
        // No configuration (an in-process test): nothing is sized.
        return 0;
      }
    };
    log.debug("Leaving ProcessMemory.settings().");
    return { configuredMb: read('workers.heapLimitMb', true),
             requestCount: ProcessMemory.requestWorkers(),
             surfaceCount: read('workers.surfaceCount') };
  }

  /**
   * The heap limit an operator set with the flag, on the command line or in
   * NODE_OPTIONS.
   *
   * @param argv - the node options to read (`process.execArgv`)
   * @param nodeOptions - NODE_OPTIONS
   * @returns the limit in MiB, or 0 when none was set
   */
  static explicitFlag(argv: string[], nodeOptions: string): number {
    log.debug("Entering ProcessMemory.explicitFlag().");
    const words = (argv || []).concat(String(nodeOptions || '').split(/\s+/));
    let mb = 0;
    for (let i = 0; i < words.length; i++) {
      const w = words[i];
      if (w.indexOf(FLAG + '=') === 0) {
        mb = Number(w.slice(FLAG.length + 1)) || mb;
      } else if (w === FLAG && i + 1 < words.length) {
        mb = Number(words[i + 1]) || mb;
      }
    }
    log.debug("Leaving ProcessMemory.explicitFlag().");
    return mb;
  }

  /**
   * Every process's heap budget, computed once per process: carried across
   * the front process's re-exec, taken from an operator's own flag, or
   * derived.
   *
   * @returns the budget
   */
  static budget(): Budget {
    log.debug("Entering ProcessMemory.budget().");
    if (cachedBudget) {
      log.debug("Leaving ProcessMemory.budget(). Cached.");
      return cachedBudget;
    }
    const carried = process.env[BUDGET_ENV];
    if (carried) {
      try {
        const parsed = JSON.parse(carried);
        if (parsed && typeof parsed.mb === 'number') {
          cachedBudget = parsed;
          log.debug("Leaving ProcessMemory.budget(). Carried.");
          return parsed;
        }
      } catch (e) {
        log.debug("Caught in ProcessMemory.budget(): " +
                  ((e && e.message) || e));
        // Not ours, or damaged: computed again below.
      }
    }
    const s = ProcessMemory.settings();
    // OFF COMES FIRST: -1 applies nothing, whatever the container or an
    // operator's flag says. An operator's own flag still reaches the front
    // process, and fork() passes the options on unchanged.
    if (s.configuredMb < 0) {
      cachedBudget = ProcessMemory.derive({ configuredMb: -1,
                                            limitBytes: null,
                                            requestCount: s.requestCount,
                                            surfaceCount: s.surfaceCount });
      log.debug("Leaving ProcessMemory.budget(). Off.");
      return cachedBudget;
    }
    const operator = ProcessMemory.explicitFlag(process.execArgv,
                                                process.env.NODE_OPTIONS || '');
    if (operator > 0) {
      cachedBudget = { mb: operator,
                       source: FLAG + ' set on the command line or in ' +
                               'NODE_OPTIONS',
                       limitBytes: null,
                       processes: 1 + s.requestCount + s.surfaceCount };
      log.debug("Leaving ProcessMemory.budget(). The operator's.");
      return cachedBudget;
    }
    const limit = s.configuredMb > 0 ? { bytes: null, source: '' }
                                     : ProcessMemory.containerLimit();
    cachedBudget = ProcessMemory.derive({ configuredMb: s.configuredMb,
                                          limitBytes: limit.bytes,
                                          source: limit.source,
                                          requestCount: s.requestCount,
                                          surfaceCount: s.surfaceCount });
    log.debug("Leaving ProcessMemory.budget().");
    return cachedBudget;
  }

  /**
   * Forgets the computed budget; for tests.
   */
  static resetBudget(): void {
    log.debug("Entering ProcessMemory.resetBudget().");
    cachedBudget = null;
    log.debug("Leaving ProcessMemory.resetBudget().");
  }

  /**
   * Replaces the front process with itself started with the heap flag, when
   * a limit is due and not yet in force. Called by `server.js` before it
   * loads the service; does not return when it re-executes.
   *
   * @returns what was done: `{ reexec: false, why }`
   */
  static reexecWithHeapLimit(): { reexec: boolean; why: string } {
    log.debug("Entering ProcessMemory.reexecWithHeapLimit().");
    const budget = ProcessMemory.budget();
    if (process.env[REEXEC_MARKER] === '1') {
      log.info('process_memory: the front process runs with a heap limit ' +
               'of ' + ProcessMemory.heapLimitMb() + ' MiB (' +
               budget.source + '); every request worker is given ' +
               budget.mb + ' MiB.');
      log.debug("Leaving ProcessMemory.reexecWithHeapLimit(). Done already.");
      return { reexec: false, why: 'already re-executed' };
    }
    if (budget.off || !budget.mb || budget.source.indexOf(FLAG) === 0) {
      log.info('process_memory: no heap limit is set by this service: ' +
               (budget.mb ? budget.source + ', ' + budget.mb + ' MiB'
                          : budget.source) + '.');
      log.debug("Leaving ProcessMemory.reexecWithHeapLimit(). Not needed.");
      return { reexec: false, why: budget.off ? 'off'
        : (budget.mb ? 'set by the operator' : 'no limit') };
    }
    const execve = (process as any).execve;
    if (typeof execve !== 'function') {
      log.warn(errorCodes.tag('STS-WORKER-0048') + 'process_memory: a heap ' +
               'limit of ' + budget.mb + ' MiB is due (' + budget.source +
               ') and this node (' + process.version + ') has no ' +
               'process.execve() to restart itself with it, so the front ' +
               'process runs without one. The request workers still get it.');
      log.debug("Leaving ProcessMemory.reexecWithHeapLimit(). No execve.");
      return { reexec: false, why: 'no process.execve' };
    }
    const env = Object.assign({}, process.env);
    env[REEXEC_MARKER] = '1';
    env[BUDGET_ENV] = JSON.stringify(budget);
    const args = [process.execPath, FLAG + '=' + budget.mb]
      .concat(budget.youngMb ? [SEMI_FLAG + '=' + SEMI_MB] : [],
              process.execArgv, process.argv.slice(1));
    log.info('process_memory: restarting the front process with ' + FLAG +
             '=' + budget.mb + ' (' + budget.source + ').');
    try {
      execve.call(process, process.execPath, args, env);
    } catch (e) {
      log.warn(errorCodes.tag('STS-WORKER-0048') + 'process_memory: the ' +
               'front process could not restart itself with a heap limit of ' +
               budget.mb + ' MiB (' + ((e && e.message) || e) + '), so it ' +
               'runs without one. The request workers still get it.');
    }
    log.debug("Leaving ProcessMemory.reexecWithHeapLimit(). Not replaced.");
    return { reexec: false, why: 'process.execve failed' };
  }


  /**
   * How many processes the kernel's OOM killer has killed in this
   * container's cgroup: v2 `memory.events`, else v1 `memory.oom_control`.
   *
   * @param read - optional; reads a file, for tests
   * @returns the count, or null when no counter is visible
   */
  static oomKillCount(read?: Reader): number | null {
    log.debug("Entering ProcessMemory.oomKillCount().");
    const readFile = read || ProcessMemory.readText;
    const files = ['/sys/fs/cgroup/memory.events',
                   '/sys/fs/cgroup/memory/memory.oom_control'];
    for (let i = 0; i < files.length; i++) {
      let text = '';
      try {
        text = readFile(files[i]);
      } catch (e) {
        log.debug("Caught in ProcessMemory.oomKillCount(): " +
                  ((e && e.message) || e));
        // This cgroup version's file is not here; the next one may be.
        continue;
      }
      const found = /^oom_kill\s+(\d+)\s*$/m.exec(text);
      if (found) {
        log.debug("Leaving ProcessMemory.oomKillCount().");
        return Number(found[1]);
      }
    }
    log.debug("Leaving ProcessMemory.oomKillCount(). No counter.");
    return null;
  }

  /**
   * This process's heap limit, as V8 has it.
   *
   * @returns MiB
   */
  static heapLimitMb(): number {
    log.debug("Entering ProcessMemory.heapLimitMb().");
    log.debug("Leaving ProcessMemory.heapLimitMb().");
    return Math.round(v8.getHeapStatistics().heap_size_limit / MIB);
  }

  /**
   * What this process is: `front`, `protocol worker` or `surface worker`.
   *
   * @returns the role
   */
  static role(): string {
    log.debug("Entering ProcessMemory.role().");
    if (!process.env.STS_REQUEST_WORKER) {
      log.debug("Leaving ProcessMemory.role(). Front.");
      return 'front';
    }
    log.debug("Leaving ProcessMemory.role(). A worker.");
    return process.env.STS_REQUEST_WORKER_POOL === 'surfaces'
      ? 'surface worker' : 'protocol worker';
  }

  /**
   * This process's memory figures, in MiB.
   *
   * @returns the snapshot
   */
  static snapshot(): Snapshot {
    log.debug("Entering ProcessMemory.snapshot().");
    const m = process.memoryUsage();
    const mb = function (n: number): number {
      return Math.round((n || 0) / MIB);
    };
    log.debug("Leaving ProcessMemory.snapshot().");
    // `pid` is the worker's THREAD id in a request worker (#364), and
    // `rssMb` the whole process's there: RSS is process-wide, and only the
    // heap figures are this isolate's own.
    return { role: ProcessMemory.role(), pid: WorkerChannel.id(),
             rssMb: mb(m.rss),
             heapUsedMb: mb(m.heapUsed), heapTotalMb: mb(m.heapTotal),
             externalMb: mb(m.external), arrayBuffersMb: mb(m.arrayBuffers),
             heapLimitMb: ProcessMemory.heapLimitMb(), at: Date.now() };
  }

  /**
   * One snapshot as the line the report logs.
   *
   * @param s - the snapshot
   * @returns the line
   */
  static describe(s: Snapshot): string {
    log.debug("Entering ProcessMemory.describe().");
    log.debug("Leaving ProcessMemory.describe().");
    return s.role + ' ' + s.pid + ': rss ' + s.rssMb + ' MiB, heap ' +
      s.heapUsedMb + ' of ' + s.heapTotalMb + ' MiB (limit ' + s.heapLimitMb +
      '), external ' + s.externalMb + ' MiB, array buffers ' +
      s.arrayBuffersMb + ' MiB';
  }

  /**
   * One run of `process.memory-report`: logs this process's line, sends a
   * request worker's figures to the front process, and answers the run's
   * summary.
   *
   * @returns the snapshot
   */
  static report(): Snapshot {
    log.debug("Entering ProcessMemory.report().");
    const s = ProcessMemory.snapshot();
    log.info('process_memory: ' + ProcessMemory.describe(s) + '.');
    if (process.env.STS_REQUEST_WORKER && WorkerChannel.inWorkerThread()) {
      try {
        WorkerChannel.send({ memoryReport: s });
      } catch (e) {
        log.debug("Caught in ProcessMemory.report(): " +
                  ((e && e.message) || e));
        // The channel is closing: this worker is going, and the front
        // process reports its exit without these figures.
      }
    }
    log.debug("Leaving ProcessMemory.report().");
    return s;
  }

  /**
   * Registers `process.memory-report` with the scheduler, once. Called by
   * `protocol_stack.ts` in every process that builds the stack.
   *
   * @param scheduler - the scheduler instance
   */
  static ensureReportJob(scheduler: any): void {
    log.debug("Entering ProcessMemory.ensureReportJob().");
    if (scheduler.job(REPORT_JOB)) {
      log.debug("Leaving ProcessMemory.ensureReportJob(). Registered.");
      return;
    }
    scheduler.register({
      id: REPORT_JOB,
      title: 'Memory report',
      describe: 'Logs, in this process, one line with its role and its ' +
                'memory: resident size, heap used and total, the heap ' +
                'limit, external memory and array buffers (#341).',
      owner: 'common/process_memory.ts',
      kind: 'per-process',
      everyMs: function (): number {
        return REPORT_EVERY_MS;
      },
      run: function (): any {
        return ProcessMemory.report();
      }
    });
    log.debug("Leaving ProcessMemory.ensureReportJob().");
  }
}

export = ProcessMemory;
