'use strict';
//
// File: cluster/scheduler.ts
//
// ===========================================================================
// ONE SCHEDULER FOR EVERY PERIODIC JOB IN THIS SERVICE, AND EACH JOB RUNS ON
// EXACTLY ONE NODE (2026-09-22, #49).
//
// rcbj's directive of 2026-09-21 (root CLAUDE.md, *Anything periodic is a
// scheduler job*): anything this service does periodically in the background
// is a job registered here, and no module starts a repeating timer of its own.
// Until this file every such job was a `setTimeout` chain or a `setInterval`
// in the module that owned it, each re-deriving "am I a worker", most of them
// running in EVERY process — request workers included — and one of them (the
// CRL directory refresh) with no coordination at all. The plan is on #49,
// with rcbj's answers D1 to D10; `cluster/CLAUDE.md`, *The scheduler*, is the
// short form.
//
// ---------------------------------------------------------------------------
// SIX THINGS ARE WORTH KNOWING BEFORE READING FURTHER.
//
// **1. TWO KINDS OF JOB.** A *cluster* job (the default) runs once for the
// whole service, on the scheduler's leader: a CRL refresh, the session-expiry
// sweep, a signer rotation. A *per-process* job runs in EVERY process that
// holds the state it cleans, because that state is reachable from no other —
// an in-memory cache's ejection, a process's own change-log pull. A
// per-process job takes no claim, and is still registered here, reported on
// /admin/scheduler (one row per node and process) and switched here.
//
// **2. THE LEADER IS A LEASE, AND A LEASE ALONE IS NOT ENOUGH.** One serving
// front process holds `ops.scheduler` (`cluster.lead()`), and only it looks
// for due cluster jobs. With clustering off it is this process at once. A
// lease can change hands while a run is in progress, so a run is ALSO claimed
// (`cluster_claims.claim()`, scope `scheduler.run`, value the run's id, for
// the run's time limit), and the claim's database time is written on the run
// row as its FENCE. An outcome is written only while the row still carries
// that fence: a node that paused past its claim and wakes to report loses to
// the attempt that took over. It is `oauth-oidc/backchannel_logout.ts`'s
// arrangement, and that file's header argues it; `cluster.withLease()` is not
// used because the runs are written through a coalesced `realms.map` flush,
// which the lease context does not reach.
//
// **3. A SLOT, NOT A TIMER.** An interval job's slots are the multiples of
// its interval on the DATABASE's clock, so every node computes the same slot
// and the same next time — which is what lets /admin/scheduler, drawn by any
// node, say when a job runs next — and a run's id is derived from (job,
// realm, slot), so two leaders reaching the same slot claim ONE row. A slot
// missed while nobody led runs ONCE when somebody does, because only the
// current slot is ever due. A cron job's slot is its most recent occurrence
// (croner computes it, D1, and nothing else). A job may say it runs only on
// demand.
//
// **4. NEVER AT REQUIRE TIME, NEVER IN A STANDBY, NEVER A CLUSTER JOB IN A
// WORKER.** Registering a job starts nothing. `start()` is called by
// `server.js` once the service's state is restored and before it binds — so
// an active-passive standby, which never gets that far, runs nothing — and by
// `common/request_worker.ts` in PER-PROCESS mode, which runs per-process jobs
// and nothing else.
//
// **5. EVERYTHING THE PAGE SAYS IS IN THE STORE.** Runs are rows of
// `scheduler.runs`, a persisted per-realm `realms.map` (a service-wide job's
// runs are the default realm's), so /admin/scheduler drawn by ANY process on
// ANY node shows what the leader did. So are the leader's own row (who leads,
// since when, when it last ticked), the per-process jobs' latest run in each
// process, and the queued commands — a manual run (#48's button) and a
// step-down — which are written by whichever process served the request and
// picked up by the leader at its next tick. Nothing here is answered out of
// this process's memory that another process would answer differently.
//
// **6. IT NEVER HOLDS THE THREAD.** A job's `run()` is asynchronous and is
// expected to yield: the cluster heartbeat is a JavaScript timer, and a job
// that blocks for a node's lifetime costs the node its membership
// (`STS-CLUSTER-0004`). A run past its time limit is recorded as failed and
// fenced out; the scheduler does not wait on it.
//
// A LIBRARY (rule 3): it registers no route. It requires `cluster.js`,
// `cluster_claims.js` and `common/` leaves, and every job's owner requires it
// in the ordinary direction to register — so no slot (rule 3e) is needed.
// `admin-ui/scheduler_admin.ts` draws it, and `mgmt-api/admin_api.ts`
// answers it as JSON.
// ===========================================================================

import nodeCrypto = require('crypto');
import os = require('os');
import helpers = require('../common/helpers');
import config = require('../common/config');
import realms = require('../common/realms');
import errorCodes = require('../common/error_codes');
import audit = require('../common/audit');
import cluster = require('./cluster');
import clusterClaims = require('./cluster_claims');

type Json = any;

// The lease the leader holds.
const LEADER_LEASE = 'ops.scheduler';

// The claim scope a run is taken under.
const RUN_SCOPE = 'scheduler.run';

// The store's keys that are not runs.
const LEADER_KEY = 'leader';
const PROCESS_PREFIX = 'process|';
const COMMAND_PREFIX = 'command|';

// The states a run passes through. `queued` is a manual run nobody has taken
// yet; the three after `running` are final.
const STATES = ['queued', 'running', 'succeeded', 'failed', 'abandoned'];
const FINAL = ['succeeded', 'failed', 'abandoned'];

// A job id: lower-case words joined by dots and hyphens, as the ones in the
// plan are (`authn.session-expiry`, `signing.rotate`).
const JOB_ID = /^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)+$/;

// How long past its slot a due job may wait before the page calls it overdue:
// never less than this, and never less than three ticks.
const OVERDUE_FLOOR_MS = 60 * 1000;

// The shape of a registered job. `cluster/CLAUDE.md` describes each member.
interface JobSpec {
  id: string;
  title: string;
  describe: string;
  owner: string;
  kind?: 'cluster' | 'per-process';
  scope?: 'service' | 'realm';
  // Exactly one of the three.
  everyMs?: () => number;
  everySetting?: string;
  everySettingUnit?: 's' | 'ms' | 'min' | 'h' | 'days';
  cron?: string;
  manualOnly?: boolean;
  // Why the job is off right now, or '' — asked per realm for a realm job.
  off?: (realmId: string) => string;
  // Whether an administrator may run it now.
  manual?: boolean;
  timeoutS?: number | (() => number);
  // Runs the job. Resolves a small JSON summary, which the run row keeps.
  run: (ctx: RunContext) => Promise<Json> | Json;
}

interface RunContext {
  realm: string;
  runId: string;
  trigger: string;
  params: Json;
  // True while this attempt still owns its run: this process still leads,
  // the run has not timed out, and the row still carries this attempt's
  // fence. A job asks before each step it cannot take back.
  stillOwner: () => boolean;
  // The database's clock, as of the tick that started the run, moved on by
  // this process's own clock since.
  nowMs: () => number;
  log: typeof helpers.log;
}

interface SchedulerDeps {
  log: typeof helpers.log;
  config: { value(key: string): any };
  realms: { list(): Json[]; run(realm: Json, fn: () => any): any;
            get(id: string): Json; DEFAULT_ID: string };
  errorCodes: typeof errorCodes;
  audit: { record(event: Json): any };
  cluster: {
    enabled(): boolean;
    lead(name: string, handlers: Json): void;
    holds(name: string): boolean;
    stepDown(name: string, holdOffMs?: number): Promise<Json>;
    nodeId(): string;
    nodeName(): string;
    state(): Promise<Json>;
  };
  claims: {
    claim(opts: Json): Promise<Json>;
    release(handle: Json): Promise<Json>;
  };
  // The runs: a `realms.map`, or a test's stand-in with the same two members.
  store: { realmMap(realmId: string): Map<string, Json> };
  // The database's clock, where there is one; this process's otherwise.
  dbNow: () => Promise<number>;
  now: () => number;
  setTimer: (fn: () => void, ms: number) => Json;
  clearTimer: (handle: Json) => void;
  // Cron: the most recent occurrence at or before `ms`, and the next after.
  cronPrev: (expr: string, ms: number) => number | null;
  cronNext: (expr: string, ms: number) => number | null;
  host: string;
  pid: number;
  isRequestWorker: () => boolean;
}

// ---------------------------------------------------------------------------
// WHICH OF TWO COPIES OF A ROW IS NEWER — the store's `mergeRow`, and the
// comparison every write here makes before it writes: (attempt, fence, final
// over running over queued, last update). A total order, so the merge
// converges; ties keep the stored copy. `backchannel_logout.ts`'s rank.
// ---------------------------------------------------------------------------
function stateRank(state: string): number {
  helpers.log.debug("Entering stateRank().");
  helpers.log.debug("Leaving stateRank().");
  return FINAL.indexOf(state) >= 0 ? 2 : (state === 'running' ? 1 : 0);
}

function rankOf(row: Json): number[] {
  helpers.log.debug("Entering rankOf().");
  const r = row || {};
  helpers.log.debug("Leaving rankOf().");
  return [Number(r.attempt) || 0, Number(r.fenceAt) || 0, stateRank(r.state),
          Number(r.updatedAt) || 0];
}

function compareRows(a: Json, b: Json): number {
  helpers.log.debug("Entering compareRows().");
  const x = rankOf(a);
  const y = rankOf(b);
  for (let i = 0; i < x.length; i++) {
    if (x[i] !== y[i]) {
      helpers.log.debug("Leaving compareRows().");
      return x[i] < y[i] ? -1 : 1;
    }
  }
  helpers.log.debug("Leaving compareRows(). Equal.");
  return 0;
}

// PER TRUST REALM, AT ITS DECLARATION (root CLAUDE.md, trust realms rule 2),
// PERSISTED where this service persists what it mints, TOMBSTONED — a
// removed run must not be brought back by a node holding an old copy — and
// MERGED by rank.
const runStore = realms.map({
  persist: 'scheduler.runs',
  tombstone: true,
  mergeRow: function (mine: Json, theirs: Json): Json {
    helpers.log.debug("Entering mergeRow().");
    helpers.log.debug("Leaving mergeRow().");
    return compareRows(mine, theirs) > 0 ? mine : theirs;
  }
});

class Scheduler {
  static readonly LEADER_LEASE = LEADER_LEASE;
  static readonly RUN_SCOPE = RUN_SCOPE;
  static readonly STATES = STATES;
  static readonly compareRows = compareRows;

  private readonly jobs = new Map<string, JobSpec>();
  private started = '';            // '' | 'front' | 'per-process'
  private leading = false;
  private leadingSince = 0;
  private leaderToken = 0;
  private timer: Json = null;
  private processTimer: Json = null;
  private ticking: Promise<void> | null = null;
  // Runs this process is running now: runId -> { fence, realm, timedOut }.
  private readonly inFlight = new Map<string, Json>();
  // Per-process jobs: `jobId|realm` -> the last slot this process ran.
  private readonly processSlots = new Map<string, number>();
  // The database clock's offset from this process's, at the last reading.
  private clockOffset = 0;
  private lastClockAt = 0;

  constructor(private readonly deps: SchedulerDeps) {
    deps.log.debug("Entering Scheduler.constructor().");
    deps.log.debug("Leaving Scheduler.constructor().");
  }

  static defaultDeps(): SchedulerDeps {
    helpers.log.debug("Entering Scheduler.defaultDeps().");
    helpers.log.debug("Leaving Scheduler.defaultDeps().");
    return {
      log: helpers.log,
      config: config,
      realms: realms,
      errorCodes: errorCodes,
      audit: audit,
      cluster: cluster,
      claims: clusterClaims,
      store: runStore,
      dbNow: Scheduler.databaseNow,
      now: function (): number {
        return Date.now();
      },
      setTimer: function (fn: () => void, ms: number): Json {
        const handle = setTimeout(fn, Math.max(0, ms));
        // Never the reason a process that is shutting down stays up.
        if (handle && typeof handle.unref === 'function') {
          handle.unref();
        }
        return handle;
      },
      clearTimer: function (handle: Json): void {
        clearTimeout(handle);
      },
      cronPrev: Scheduler.cronPrev,
      cronNext: Scheduler.cronNext,
      host: os.hostname(),
      pid: process.pid,
      isRequestWorker: function (): boolean {
        return !!process.env.STS_REQUEST_WORKER;
      }
    };
  }

  // The database's clock where the store has one (postgres), this process's
  // otherwise — which on a store nothing else shares is the same thing.
  // LAZY: `persistence.js` requires half the service.
  static databaseNow(): Promise<number> {
    helpers.log.debug("Entering Scheduler.databaseNow().");
    const persistence = require('../persistence/persistence');
    const store = persistence.clusterStore && persistence.clusterStore();
    if (!store || typeof store.clusterClock !== 'function') {
      helpers.log.debug("Leaving Scheduler.databaseNow(). Local clock.");
      return Promise.resolve(Date.now());
    }
    helpers.log.debug("Leaving Scheduler.databaseNow(). The store's.");
    return Promise.resolve().then(function (): Promise<number> {
      return store.clusterClock();
    }).then(function (ms: number): number {
      return Number(ms) || Date.now();
    }, function (e: Json): number {
      helpers.log.debug("Caught in Scheduler.databaseNow(): " +
                        ((e && e.message) || e));
      return Date.now();
    });
  }

  // CRON THROUGH CRONER, AND NOTHING ELSE THROUGH IT (D1). In UTC, so every
  // node reads an expression the same way whatever its container's zone.
  static cronPrev(expr: string, ms: number): number | null {
    helpers.log.debug("Entering Scheduler.cronPrev().");
    const { Cron } = require('croner');
    const job = new Cron(expr, { paused: true, timezone: 'UTC' });
    // croner counts in WHOLE SECONDS and leaves the reference second out, so
    // an occurrence at exactly 03:00:00 is found from 03:00:01 and not from
    // 03:00:00.999. The reference is therefore the start of the NEXT second.
    const runs = job.previousRuns(1, new Date(Math.floor(ms / 1000) * 1000 +
                                              1000));
    job.stop();
    helpers.log.debug("Leaving Scheduler.cronPrev().");
    return runs && runs[0] ? runs[0].getTime() : null;
  }

  static cronNext(expr: string, ms: number): number | null {
    helpers.log.debug("Entering Scheduler.cronNext().");
    const { Cron } = require('croner');
    const job = new Cron(expr, { paused: true, timezone: 'UTC' });
    const next = job.nextRun(new Date(ms));
    job.stop();
    helpers.log.debug("Leaving Scheduler.cronNext().");
    return next ? next.getTime() : null;
  }

  // -------------------------------------------------------------------------
  // REGISTRATION. Refused WHOLE when a member is missing or malformed
  // (STS-SCHED-0009), and thrown: a job registered half-way would be a row on
  // the page that never runs, and a registration happens at require time,
  // where a throw is a programming error the first test finds.
  // -------------------------------------------------------------------------
  register(spec: JobSpec): JobSpec {
    const { log, errorCodes, cronNext } = this.deps;
    log.debug("Entering Scheduler.register(). " + (spec && spec.id));
    const problems: string[] = [];
    const s: Json = spec || {};
    if (!JOB_ID.test(String(s.id || ''))) {
      problems.push('an id of dot- or hyphen-separated lower-case words');
    }
    ['title', 'describe', 'owner'].forEach(function (name: string): void {
      if (!String(s[name] || '').trim()) {
        problems.push('a ' + name);
      }
    });
    if (typeof s.run !== 'function') {
      problems.push('a run() function');
    }
    const schedules = ['everyMs', 'everySetting', 'cron', 'manualOnly']
      .filter(function (name: string): boolean {
        return !!s[name];
      });
    if (schedules.length !== 1) {
      problems.push('exactly one of everyMs, everySetting, cron and ' +
                    'manualOnly');
    }
    if (s.everyMs && typeof s.everyMs !== 'function') {
      problems.push('everyMs as a function');
    }
    if (s.cron) {
      try {
        cronNext(String(s.cron), 0);
      } catch (e) {
        log.debug("Caught in Scheduler.register(): " +
                  ((e && e.message) || e));
        problems.push('a cron expression croner can read (' +
                      ((e && e.message) || e) + ')');
      }
    }
    if (s.kind && ['cluster', 'per-process'].indexOf(s.kind) < 0) {
      problems.push('a kind of cluster or per-process');
    }
    if (s.scope && ['service', 'realm'].indexOf(s.scope) < 0) {
      problems.push('a scope of service or realm');
    }
    if (s.kind === 'per-process' && s.manualOnly) {
      problems.push('a schedule: a per-process job cannot be on demand ' +
                    'only, because nothing queues a run in every process');
    }
    if (this.jobs.has(String(s.id))) {
      problems.push('an id no other job has ("' + s.id + '" is registered)');
    }
    if (problems.length) {
      log.debug("Leaving Scheduler.register(). Refused.");
      throw new Error(errorCodes.tag('STS-SCHED-0009') + 'scheduler: the ' +
                      'job "' + String(s.id || '') + '" was not registered. ' +
                      'It needs ' + problems.join('; ') + '.');
    }
    const job: JobSpec = Object.assign({ kind: 'cluster', scope: 'service',
                                         manual: true }, s);
    this.jobs.set(job.id, job);
    log.debug("Leaving Scheduler.register(). " + this.jobs.size +
              " job(s).");
    return job;
  }

  job(id: string): JobSpec | null {
    const { log } = this.deps;
    log.debug("Entering Scheduler.job().");
    log.debug("Leaving Scheduler.job().");
    return this.jobs.get(String(id)) || null;
  }

  jobIds(): string[] {
    const { log } = this.deps;
    log.debug("Entering Scheduler.jobIds().");
    log.debug("Leaving Scheduler.jobIds().");
    return Array.from(this.jobs.keys()).sort();
  }

  // For tests: a registration forgotten, so a test can register its own.
  unregister(id: string): boolean {
    const { log } = this.deps;
    log.debug("Entering Scheduler.unregister().");
    log.debug("Leaving Scheduler.unregister().");
    return this.jobs.delete(String(id));
  }

  // -------------------------------------------------------------------------
  // THE CLOCK. Read from the database once a tick; between readings the
  // offset from this process's own clock carries it.
  // -------------------------------------------------------------------------
  private refreshClock(): Promise<number> {
    const { log, dbNow, now } = this.deps;
    const self = this;
    log.debug("Entering Scheduler.refreshClock().");
    log.debug("Leaving Scheduler.refreshClock().");
    return dbNow().then(function (db: number): number {
      const local = now();
      self.clockOffset = Number(db) - local;
      self.lastClockAt = local;
      return Number(db);
    });
  }

  nowMs(): number {
    const { log, now } = this.deps;
    log.debug("Entering Scheduler.nowMs().");
    log.debug("Leaving Scheduler.nowMs().");
    return now() + this.clockOffset;
  }

  private setting(key: string): number {
    const { log, config } = this.deps;
    log.debug("Entering Scheduler.setting(). " + key);
    log.debug("Leaving Scheduler.setting().");
    return Number(config.value(key));
  }

  private tickMs(): number {
    const { log } = this.deps;
    log.debug("Entering Scheduler.tickMs().");
    log.debug("Leaving Scheduler.tickMs().");
    return Math.max(1000, this.setting('scheduler.tickS') * 1000);
  }

  // -------------------------------------------------------------------------
  // A JOB'S SCHEDULE, IN MILLISECONDS — or 0 for a job with no interval.
  // Read directly from its setting: 0 is a legal value there and means OFF
  // (the root CLAUDE.md's `|| n` rule), which `offReason()` reports.
  // -------------------------------------------------------------------------
  intervalMs(job: JobSpec): number {
    const { log, config } = this.deps;
    log.debug("Entering Scheduler.intervalMs(). " + job.id);
    let ms = 0;
    if (typeof job.everyMs === 'function') {
      ms = Number(job.everyMs()) || 0;
    } else if (job.everySetting) {
      const value = Number(config.value(job.everySetting));
      const unit = job.everySettingUnit || 's';
      const factor = unit === 'ms' ? 1 : unit === 's' ? 1000
        : unit === 'min' ? 60000 : unit === 'h' ? 3600000 : 86400000;
      ms = value > 0 ? value * factor : 0;
    }
    log.debug("Leaving Scheduler.intervalMs(). " + ms);
    return ms;
  }

  // The slot a cluster job is due for at `at`, and when the next one starts:
  // `{ slot, startsAt, nextAt }`, or null when it has none (on demand only,
  // or an interval of 0).
  slotAt(job: JobSpec, at: number): Json {
    const { log, cronPrev, cronNext } = this.deps;
    log.debug("Entering Scheduler.slotAt(). " + job.id);
    if (job.manualOnly) {
      log.debug("Leaving Scheduler.slotAt(). On demand only.");
      return null;
    }
    if (job.cron) {
      const prev = cronPrev(job.cron, at);
      const next = cronNext(job.cron, at);
      log.debug("Leaving Scheduler.slotAt(). Cron.");
      return prev === null ? { slot: null, startsAt: null, nextAt: next }
        : { slot: prev, startsAt: prev, nextAt: next };
    }
    const every = this.intervalMs(job);
    if (!(every > 0)) {
      log.debug("Leaving Scheduler.slotAt(). No interval.");
      return null;
    }
    const slot = Math.floor(at / every);
    log.debug("Leaving Scheduler.slotAt(). Interval.");
    return { slot: slot, startsAt: slot * every, nextAt: (slot + 1) * every };
  }

  // In words, for the page and the API.
  scheduleText(job: JobSpec): string {
    const { log } = this.deps;
    log.debug("Entering Scheduler.scheduleText().");
    let text: string;
    if (job.manualOnly) {
      text = 'on demand only';
    } else if (job.cron) {
      text = 'cron ' + job.cron + ' (UTC)';
    } else {
      const every = this.intervalMs(job);
      text = every > 0 ? 'every ' + Scheduler.span(every) : 'no interval (0)';
      if (job.everySetting) {
        text += ', from ' + job.everySetting;
      }
    }
    log.debug("Leaving Scheduler.scheduleText().");
    return text;
  }

  // "4 min 12 s", "2 h 5 min", "90 d" — two units at most.
  static span(ms: number): string {
    helpers.log.debug("Entering Scheduler.span().");
    const s = Math.max(0, Math.round(ms / 1000));
    const units: Array<[number, string]> = [[86400, 'd'], [3600, 'h'],
                                             [60, 'min'], [1, 's']];
    const parts: string[] = [];
    let left = s;
    units.forEach(function (unit: [number, string]): void {
      if (parts.length < 2 && (left >= unit[0] ||
                               (unit[0] === 1 && !parts.length))) {
        const n = Math.floor(left / unit[0]);
        left -= n * unit[0];
        parts.push(n + ' ' + unit[1]);
      }
    });
    helpers.log.debug("Leaving Scheduler.span().");
    return parts.join(' ');
  }

  // -------------------------------------------------------------------------
  // WHY A JOB IS OFF, or ''. Three reasons, in the order the page names them:
  // the scheduler itself, the job's own id in `scheduler.disabledJobs`, and
  // whatever the job says (its interval setting at 0, a mode predicate).
  // -------------------------------------------------------------------------
  offReason(job: JobSpec, realmId?: string): string {
    const { log, config } = this.deps;
    log.debug("Entering Scheduler.offReason(). " + job.id);
    if (!config.value('scheduler.enabled')) {
      log.debug("Leaving Scheduler.offReason(). The scheduler is off.");
      return 'scheduler.enabled is off';
    }
    if (this.disabledIds().indexOf(job.id) >= 0) {
      log.debug("Leaving Scheduler.offReason(). Listed.");
      return 'named in scheduler.disabledJobs';
    }
    if (!job.manualOnly && !job.cron && !(this.intervalMs(job) > 0)) {
      log.debug("Leaving Scheduler.offReason(). No interval.");
      return (job.everySetting || 'its interval') + ' is 0';
    }
    let own = '';
    if (typeof job.off === 'function') {
      try {
        own = String(job.off(String(realmId || realms.DEFAULT_ID)) || '');
      } catch (e) {
        log.debug("Caught in Scheduler.offReason(): " +
                  ((e && e.message) || e));
        own = 'its own check failed: ' + ((e && e.message) || e);
      }
    }
    log.debug("Leaving Scheduler.offReason(). " + (own || 'on'));
    return own;
  }

  disabledIds(): string[] {
    const { log, config } = this.deps;
    log.debug("Entering Scheduler.disabledIds().");
    const raw = String(config.value('scheduler.disabledJobs') || '');
    log.debug("Leaving Scheduler.disabledIds().");
    return raw.split(',').map(function (one: string): string {
      return one.trim();
    }).filter(Boolean);
  }

  private timeoutMsOf(job: JobSpec): number {
    const { log } = this.deps;
    log.debug("Entering Scheduler.timeoutMsOf().");
    const own = typeof job.timeoutS === 'function' ? job.timeoutS()
      : job.timeoutS;
    const s = Number(own) > 0 ? Number(own)
      : this.setting('scheduler.runTimeoutS');
    log.debug("Leaving Scheduler.timeoutMsOf().");
    return Math.max(1000, s * 1000);
  }

  // The realms a job is due in: the default one for a service job, every one
  // for a realm job.
  private realmIdsFor(job: JobSpec): string[] {
    const { log, realms } = this.deps;
    log.debug("Entering Scheduler.realmIdsFor().");
    log.debug("Leaving Scheduler.realmIdsFor().");
    return job.scope === 'realm'
      ? realms.list().map(function (one: Json): string {
        return String(one.id);
      })
      : [realms.DEFAULT_ID];
  }

  private storeOf(realmId: string): Map<string, Json> {
    const { log, store } = this.deps;
    log.debug("Entering Scheduler.storeOf().");
    log.debug("Leaving Scheduler.storeOf().");
    return store.realmMap(String(realmId || realms.DEFAULT_ID));
  }

  // WRITE A ROW, unless the store already holds a newer copy — the merge's
  // comparison made here too, so this process's own copy never goes back.
  private writeRow(realmId: string, row: Json): Json {
    const { log } = this.deps;
    log.debug("Entering Scheduler.writeRow(). " + row.runId + " " + row.state);
    const map = this.storeOf(realmId);
    const held = map.get(row.runId);
    row.updatedAt = Math.max(this.nowMs(),
                             (held && Number(held.updatedAt) + 1) || 0);
    if (held && compareRows(row, held) < 0) {
      log.debug("Leaving Scheduler.writeRow(). A newer copy stands.");
      return Object.assign({}, held);
    }
    map.set(row.runId, Object.assign({}, row));
    log.debug("Leaving Scheduler.writeRow().");
    return row;
  }

  private runIdFor(job: JobSpec, realmId: string, slot: number): string {
    const { log } = this.deps;
    log.debug("Entering Scheduler.runIdFor().");
    const digest = nodeCrypto.createHash('sha256')
      .update(job.id + '\n' + realmId + '\n' + String(slot))
      .digest('base64url').slice(0, 22);
    log.debug("Leaving Scheduler.runIdFor().");
    return 's-' + digest;
  }

  private who(): Json {
    const { log, cluster, host, pid } = this.deps;
    log.debug("Entering Scheduler.who().");
    let nodeId = '';
    let nodeName = '';
    try {
      nodeId = String(cluster.nodeId() || '');
      nodeName = String(cluster.nodeName() || '');
    } catch (e) {
      log.debug("Caught in Scheduler.who(): " + ((e && e.message) || e));
    }
    log.debug("Leaving Scheduler.who().");
    return { node: nodeId, nodeName: nodeName || host, host: host, pid: pid };
  }

  // -------------------------------------------------------------------------
  // STARTING. `server.js` calls `start('front')` once the service's state is
  // restored; `common/request_worker.ts` calls `start('per-process')`. A
  // front process campaigns for the lease; with clustering off `lead()`
  // answers at once. Idempotent.
  // -------------------------------------------------------------------------
  start(role?: string): boolean {
    const { log, cluster, isRequestWorker } = this.deps;
    const self = this;
    log.debug("Entering Scheduler.start(). " + role);
    if (this.started) {
      log.debug("Leaving Scheduler.start(). Already started.");
      return false;
    }
    const perProcessOnly = role === 'per-process' || isRequestWorker();
    this.started = perProcessOnly ? 'per-process' : 'front';
    this.scheduleProcessTick(0);
    if (perProcessOnly) {
      log.info('scheduler: running ' + this.perProcessJobs().length +
               ' per-process job(s) in this process (' + process.pid +
               '). Cluster jobs run on the scheduler\'s leader, which a ' +
               'request worker never is.');
      log.debug("Leaving Scheduler.start(). Per-process only.");
      return true;
    }
    cluster.lead(LEADER_LEASE, {
      onGain: function (token: number): void {
        self.gainLeadership(token);
      },
      onLose: function (): void {
        self.loseLeadership();
      }
    });
    log.debug("Leaving Scheduler.start().");
    return true;
  }

  stop(): void {
    const { log, clearTimer } = this.deps;
    log.debug("Entering Scheduler.stop().");
    this.started = '';
    this.leading = false;
    if (this.timer) {
      clearTimer(this.timer);
      this.timer = null;
    }
    if (this.processTimer) {
      clearTimer(this.processTimer);
      this.processTimer = null;
    }
    log.debug("Leaving Scheduler.stop().");
  }

  isLeading(): boolean {
    const { log } = this.deps;
    log.debug("Entering Scheduler.isLeading().");
    log.debug("Leaving Scheduler.isLeading().");
    return this.leading;
  }

  private gainLeadership(token: number): void {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering Scheduler.gainLeadership(). token=" + token);
    if (!this.started || this.started !== 'front') {
      log.debug("Leaving Scheduler.gainLeadership(). Not started here.");
      return;
    }
    this.leading = true;
    this.leaderToken = Number(token) || 0;
    this.leadingSince = this.nowMs();
    log.info('scheduler: this process (' + process.pid + ') leads the ' +
             'scheduler' + (token ? ' (lease token ' + token + ')' : ', and ' +
             'nothing else could: this service is not clustered') + '. ' +
             this.clusterJobs().length + ' cluster job(s), ' +
             this.perProcessJobs().length + ' per-process.');
    // THE CATCH-UP IS THE FIRST TICK: runs that were claimed or running on a
    // node that went are re-claimed once their claims lapse, and every job
    // due in its current slot runs — once, whatever was missed.
    this.refreshClock().then(function (): void {
      self.writeLeaderRow('gained');
    }, function (e: Json): void {
      log.debug("Caught in Scheduler.gainLeadership(): " +
                ((e && e.message) || e));
    }).then(function (): void {
      self.scheduleTick(0);
    });
    log.debug("Leaving Scheduler.gainLeadership().");
  }

  private loseLeadership(): void {
    const { log, clearTimer } = this.deps;
    log.debug("Entering Scheduler.loseLeadership().");
    if (!this.leading) {
      log.debug("Leaving Scheduler.loseLeadership(). Was not leading.");
      return;
    }
    this.leading = false;
    if (this.timer) {
      clearTimer(this.timer);
      this.timer = null;
    }
    log.warn('scheduler: this process (' + process.pid + ') no longer leads ' +
             'the scheduler. ' + this.inFlight.size + ' run(s) still going ' +
             'here are fenced out from now on.');
    log.debug("Leaving Scheduler.loseLeadership().");
  }

  private writeLeaderRow(event: string): void {
    const { log } = this.deps;
    log.debug("Entering Scheduler.writeLeaderRow(). " + event);
    const me = this.who();
    this.writeRow(realms.DEFAULT_ID, {
      runId: LEADER_KEY, kind: 'leader', node: me.node,
      nodeName: me.nodeName, host: me.host, pid: me.pid,
      token: this.leaderToken, since: this.leadingSince,
      lastTickAt: this.nowMs(), event: event,
      clustered: this.clustered()
    });
    log.debug("Leaving Scheduler.writeLeaderRow().");
  }

  private clustered(): boolean {
    const { log, cluster } = this.deps;
    log.debug("Entering Scheduler.clustered().");
    let on = false;
    try {
      on = !!cluster.enabled();
    } catch (e) {
      log.debug("Caught in Scheduler.clustered(): " + ((e && e.message) || e));
    }
    log.debug("Leaving Scheduler.clustered().");
    return on;
  }

  private clusterJobs(): JobSpec[] {
    const { log } = this.deps;
    log.debug("Entering Scheduler.clusterJobs().");
    log.debug("Leaving Scheduler.clusterJobs().");
    return Array.from(this.jobs.values()).filter(function (job: JobSpec) {
      return job.kind !== 'per-process';
    });
  }

  private perProcessJobs(): JobSpec[] {
    const { log } = this.deps;
    log.debug("Entering Scheduler.perProcessJobs().");
    log.debug("Leaving Scheduler.perProcessJobs().");
    return Array.from(this.jobs.values()).filter(function (job: JobSpec) {
      return job.kind === 'per-process';
    });
  }

  // THE LEADER'S TIMER — the scheduler's own, and the one timer every
  // periodic job in the service now hangs off.
  private scheduleTick(delayMs: number): void {
    const { log, setTimer, clearTimer } = this.deps;
    const self = this;
    log.debug("Entering Scheduler.scheduleTick().");
    if (!this.leading) {
      log.debug("Leaving Scheduler.scheduleTick(). Not leading.");
      return;
    }
    if (this.timer) {
      clearTimer(this.timer);
    }
    this.timer = setTimer(function (): void {
      self.timer = null;
      self.tick().then(function (): void {
        self.scheduleTick(self.tickMs());
      }, function (e: Json): void {
        log.debug("Caught in Scheduler.scheduleTick(): " +
                  ((e && e.message) || e));
        self.scheduleTick(self.tickMs());
      });
    }, Math.max(0, delayMs));
    log.debug("Leaving Scheduler.scheduleTick().");
  }

  // -------------------------------------------------------------------------
  // ONE TICK OF THE LEADER. Serialised: a tick that is still going when the
  // next is asked for is the one that answers.
  // -------------------------------------------------------------------------
  tick(): Promise<void> {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering Scheduler.tick().");
    if (this.ticking) {
      log.debug("Leaving Scheduler.tick(). One is running.");
      return this.ticking;
    }
    this.ticking = this.tickOnce().catch(function (e: Json): void {
      log.error(errorCodes.tag('STS-SCHED-0013') + 'scheduler: a tick ' +
                'failed: ' + ((e && e.message) || e) + '. It is tried again ' +
                'at the next one.');
    }).then(function (): void {
      self.ticking = null;
    });
    log.debug("Leaving Scheduler.tick().");
    return this.ticking;
  }

  private async tickOnce(): Promise<void> {
    const { log } = this.deps;
    log.debug("Entering Scheduler.tickOnce().");
    if (!this.leading) {
      log.debug("Leaving Scheduler.tickOnce(). Not leading.");
      return;
    }
    await this.refreshClock();
    this.writeLeaderRow('tick');
    if (await this.obeyCommands()) {
      log.debug("Leaving Scheduler.tickOnce(). Stood down.");
      return;
    }
    const at = this.nowMs();
    const self = this;
    this.clusterJobs().forEach(function (job: JobSpec): void {
      self.realmIdsFor(job).forEach(function (realmId: string): void {
        if (self.offReason(job, realmId)) {
          return;
        }
        const slot = self.slotAt(job, at);
        if (!slot || slot.slot === null) {
          return;
        }
        const runId = self.runIdFor(job, realmId, slot.slot);
        const row = self.storeOf(realmId).get(runId);
        if (row && FINAL.indexOf(row.state) >= 0) {
          return;
        }
        self.attempt(job, realmId, row || {
          runId: runId, kind: 'run', jobId: job.id, realm: realmId,
          slot: slot.slot, dueAt: slot.startsAt, trigger: 'schedule',
          params: null, requestedBy: '', state: 'queued', attempt: 0,
          fenceAt: 0, queuedAt: at
        });
      });
    });
    this.queuedManualRuns().forEach(function (pair: Json): void {
      const job = self.job(pair.row.jobId);
      if (!job) {
        return;
      }
      self.attempt(job, pair.realm, pair.row);
    });
    log.debug("Leaving Scheduler.tickOnce().");
  }

  // Every queued manual run in every realm, oldest first.
  private queuedManualRuns(): Json[] {
    const { log, realms } = this.deps;
    const self = this;
    log.debug("Entering Scheduler.queuedManualRuns().");
    const out: Json[] = [];
    realms.list().forEach(function (realm: Json): void {
      self.storeOf(String(realm.id)).forEach(function (row: Json): void {
        if (row && row.kind === 'run' && row.trigger === 'manual' &&
            (row.state === 'queued' || row.state === 'running')) {
          out.push({ realm: String(realm.id), row: Object.assign({}, row) });
        }
      });
    });
    out.sort(function (a: Json, b: Json): number {
      return Number(a.row.queuedAt) - Number(b.row.queuedAt);
    });
    log.debug("Leaving Scheduler.queuedManualRuns(). " + out.length + ".");
    return out;
  }

  // -------------------------------------------------------------------------
  // ONE ATTEMPT AT ONE RUN: claim it, write it running with the claim's time
  // as its fence, run it with a time limit, and write the outcome only if
  // the fence still stands. Not awaited by the tick: a slow job does not
  // hold up the others.
  // -------------------------------------------------------------------------
  private attempt(job: JobSpec, realmId: string, row: Json): void {
    const { log, claims, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering Scheduler.attempt(). " + job.id + " " + row.runId);
    if (this.inFlight.has(row.runId)) {
      log.debug("Leaving Scheduler.attempt(). Running here already.");
      return;
    }
    const timeoutMs = this.timeoutMsOf(job);
    // Held while the claim is being asked, so the next tick does not ask too.
    this.inFlight.set(row.runId, { fence: 0, realm: realmId,
                                   timedOut: false, asking: true });
    claims.claim({ scope: RUN_SCOPE, value: row.runId, realm: realmId,
                   ttlMs: timeoutMs + 1000 }).then(function (answer: Json) {
      if (!answer.ok) {
        self.inFlight.delete(row.runId);
        if (answer.reason === 'store') {
          log.warn(errorCodes.tag('STS-SCHED-0008') + 'scheduler: the ' +
                   'claim store could not be asked about run ' + row.runId +
                   ' of ' + job.id + ' (' + (answer.why || '') + '). It is ' +
                   'not started until it can be.');
        }
        return;
      }
      return self.runClaimed(job, realmId, row, answer, timeoutMs);
    }).catch(function (e: Json): void {
      self.inFlight.delete(row.runId);
      log.error(errorCodes.tag('STS-SCHED-0013') + 'scheduler: run ' +
                row.runId + ' of ' + job.id + ' could not be started: ' +
                ((e && e.message) || e) + '.');
    });
    log.debug("Leaving Scheduler.attempt().");
  }

  private runClaimed(job: JobSpec, realmId: string, row: Json, answer: Json,
                     timeoutMs: number): Promise<void> {
    const { log, audit, realms, setTimer, clearTimer, claims } = this.deps;
    const self = this;
    log.debug("Entering Scheduler.runClaimed(). " + row.runId);
    const fence = Number(answer.claimedAt) || this.nowMs();
    const stored = this.storeOf(realmId).get(row.runId) || row;
    const me = this.who();
    // A ROW STILL MARKED RUNNING BY SOMEBODY ELSE whose claim this attempt has
    // just been able to take: that attempt lost its claim before it finished.
    // It is recorded as ABANDONED, under a row of its own, and this attempt
    // is the next one.
    if (stored.state === 'running' && Number(stored.fenceAt) &&
        Number(stored.fenceAt) !== fence) {
      this.writeRow(realmId, Object.assign({}, stored, {
        runId: stored.runId + ':' + (Number(stored.attempt) || 1),
        state: 'abandoned', endedAt: this.nowMs(),
        errorCode: 'STS-SCHED-0011',
        why: 'The attempt on ' + (stored.nodeName || stored.node || '?') +
             ' (pid ' + stored.pid + ') stopped holding its claim before it ' +
             'finished; attempt ' + ((Number(stored.attempt) || 1) + 1) +
             ' took it over.',
        abandonedOf: stored.runId }));
      audit.record({ action: 'scheduler.run', protocol: 'scheduler',
                     channel: 'internal', target: job.id,
                     errorCode: 'STS-SCHED-0011', outcome: 'failure',
                     summarised: true,
                     summary: 'Scheduler run ' + stored.runId + ' of ' +
                              job.id + ' was abandoned and taken over.',
                     detail: { runId: stored.runId, realm: realmId,
                               node: stored.node, pid: stored.pid } });
    }
    const running = Object.assign({}, stored, {
      state: 'running', fenceAt: fence,
      attempt: (Number(stored.attempt) || 0) + 1,
      node: me.node, nodeName: me.nodeName, host: me.host, pid: me.pid,
      startedAt: this.nowMs(), endedAt: 0, errorCode: '', why: '',
      result: null, takenOver: stored.state === 'running'
    });
    this.writeRow(realmId, running);
    const flight: Json = { fence: fence, realm: realmId, timedOut: false,
                           asking: false };
    this.inFlight.set(row.runId, flight);
    const startedLocal = this.deps.now();
    const ctx: RunContext = {
      realm: realmId, runId: row.runId, trigger: running.trigger,
      params: running.params || null,
      stillOwner: function (): boolean {
        const live = self.storeOf(realmId).get(row.runId);
        return self.leading && !flight.timedOut && !!live &&
               Number(live.fenceAt) === fence;
      },
      nowMs: function (): number {
        return self.nowMs();
      },
      log: log
    };
    let timeoutHandle: Json = null;
    const timedOut = new Promise(function (resolve: (v: Json) => void) {
      timeoutHandle = setTimer(function (): void {
        flight.timedOut = true;
        resolve({ timedOut: true });
      }, timeoutMs);
    });
    const realm = realms.get(realmId) || realms.get(realms.DEFAULT_ID);
    const work = Promise.resolve().then(function (): Json {
      return realms.run(realm, function (): Json {
        return job.run(ctx);
      });
    }).then(function (result: Json): Json {
      return { ok: true, result: result };
    }, function (e: Json): Json {
      return { ok: false, error: e };
    });
    log.debug("Leaving Scheduler.runClaimed(). Running.");
    return Promise.race([work, timedOut]).then(function (outcome: Json) {
      clearTimer(timeoutHandle);
      self.inFlight.delete(row.runId);
      const endedAt = self.nowMs();
      const live = self.storeOf(realmId).get(row.runId);
      if (!live || Number(live.fenceAt) !== fence) {
        log.warn(errorCodes.tag('STS-SCHED-0003') + 'scheduler: the ' +
                 'outcome of run ' + row.runId + ' of ' + job.id + ' was ' +
                 'fenced out — another attempt took it over — and is not ' +
                 'written.');
        return;
      }
      const final: Json = Object.assign({}, live, {
        endedAt: endedAt, durationMs: self.deps.now() - startedLocal });
      let errorCode = '';
      if (outcome.timedOut) {
        errorCode = 'STS-SCHED-0002';
        final.state = 'failed';
        final.why = 'It was still running after its time limit of ' +
                    Scheduler.span(timeoutMs) + '.';
        claims.release(answer.handle);
      } else if (!outcome.ok) {
        errorCode = 'STS-SCHED-0001';
        final.state = 'failed';
        final.why = String((outcome.error && outcome.error.message) ||
                           outcome.error || 'it failed');
      } else {
        final.state = 'succeeded';
        final.result = Scheduler.summaryOf(outcome.result);
      }
      final.errorCode = errorCode;
      self.writeRow(realmId, final);
      audit.record({
        action: 'scheduler.run', protocol: 'scheduler', channel: 'internal',
        target: job.id, errorCode: errorCode,
        outcome: errorCode ? 'failure' : 'success', summarised: !!errorCode,
        summary: 'Scheduler run ' + row.runId + ' of ' + job.id +
                 (realmId !== realms.DEFAULT_ID ? ' in "' + realmId + '"'
                   : '') + ' ' + final.state + ' (' + final.trigger +
                 ', attempt ' + final.attempt + ').',
        detail: { runId: row.runId, realm: realmId, trigger: final.trigger,
                  attempt: final.attempt, durationMs: final.durationMs,
                  why: final.why || '' }
      });
      if (errorCode) {
        log.warn(errorCodes.tag(errorCode) + 'scheduler: ' + job.id + ' ' +
                 'failed: ' + final.why);
      }
    });
  }

  // A job's answer, kept small: the row is replicated and drawn on a page.
  static summaryOf(result: Json): Json {
    helpers.log.debug("Entering Scheduler.summaryOf().");
    if (result === undefined || result === null) {
      helpers.log.debug("Leaving Scheduler.summaryOf(). None.");
      return null;
    }
    let text = '';
    try {
      text = typeof result === 'string' ? result : JSON.stringify(result);
    } catch (e) {
      helpers.log.debug("Caught in Scheduler.summaryOf(): " +
                        ((e && e.message) || e));
      text = String(result);
    }
    helpers.log.debug("Leaving Scheduler.summaryOf().");
    return text.length > 500 ? text.slice(0, 497) + '...' : text;
  }

  // -------------------------------------------------------------------------
  // PER-PROCESS JOBS: every process runs them itself, each process keeps the
  // last slot it ran, and its latest run is written to the store under a key
  // naming the node and the process — so the page drawn anywhere shows every
  // process's row.
  // -------------------------------------------------------------------------
  private scheduleProcessTick(delayMs: number): void {
    const { log, setTimer, clearTimer } = this.deps;
    const self = this;
    log.debug("Entering Scheduler.scheduleProcessTick().");
    if (!this.started || !this.perProcessJobs().length) {
      log.debug("Leaving Scheduler.scheduleProcessTick(). Nothing to run.");
      return;
    }
    if (this.processTimer) {
      clearTimer(this.processTimer);
    }
    this.processTimer = setTimer(function (): void {
      self.processTimer = null;
      self.processTick().then(function (): void {
        self.scheduleProcessTick(self.tickMs());
      }, function (e: Json): void {
        log.debug("Caught in Scheduler.scheduleProcessTick(): " +
                  ((e && e.message) || e));
        self.scheduleProcessTick(self.tickMs());
      });
    }, Math.max(0, delayMs));
    log.debug("Leaving Scheduler.scheduleProcessTick().");
  }

  async processTick(): Promise<void> {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering Scheduler.processTick().");
    await this.refreshClock().catch(function (e: Json): void {
      log.debug("Caught in Scheduler.processTick(): " +
                ((e && e.message) || e));
    });
    const at = this.nowMs();
    const jobs = this.perProcessJobs();
    for (let i = 0; i < jobs.length; i++) {
      const job = jobs[i];
      const realmIds = self.realmIdsFor(job);
      for (let j = 0; j < realmIds.length; j++) {
        const realmId = realmIds[j];
        if (self.offReason(job, realmId)) {
          continue;
        }
        const slot = self.slotAt(job, at);
        const key = job.id + '|' + realmId;
        if (!slot || slot.slot === null ||
            self.processSlots.get(key) === slot.slot) {
          continue;
        }
        self.processSlots.set(key, slot.slot);
        await self.runInThisProcess(job, realmId, slot);
      }
    }
    log.debug("Leaving Scheduler.processTick().");
  }

  private async runInThisProcess(job: JobSpec, realmId: string,
                                 slot: Json): Promise<void> {
    const { log, realms } = this.deps;
    const self = this;
    log.debug("Entering Scheduler.runInThisProcess(). " + job.id);
    const me = this.who();
    const key = PROCESS_PREFIX + job.id + '|' + realmId + '|' +
                (me.node || me.host) + '|' + me.pid;
    const startedAt = this.nowMs();
    const startedLocal = this.deps.now();
    const realm = realms.get(realmId) || realms.get(realms.DEFAULT_ID);
    let outcome: Json;
    try {
      const result = await realms.run(realm, function (): Json {
        return job.run({
          realm: realmId, runId: key, trigger: 'schedule', params: null,
          stillOwner: function (): boolean {
            return !!self.started;
          },
          nowMs: function (): number {
            return self.nowMs();
          },
          log: log
        });
      });
      outcome = { state: 'succeeded', errorCode: '', why: '',
                  result: Scheduler.summaryOf(result) };
    } catch (e) {
      log.warn(errorCodes.tag('STS-SCHED-0015') + 'scheduler: the ' +
               'per-process job ' + job.id + ' failed in this process: ' +
               ((e && e.message) || e) + '.');
      outcome = { state: 'failed', errorCode: 'STS-SCHED-0015',
                  why: String((e && e.message) || e), result: null };
    }
    this.writeRow(realms.DEFAULT_ID, Object.assign({
      runId: key, kind: 'process', jobId: job.id, realm: realmId,
      slot: slot.slot, dueAt: slot.startsAt, nextAt: slot.nextAt,
      trigger: 'schedule', node: me.node, nodeName: me.nodeName,
      host: me.host, pid: me.pid, worker: this.started === 'per-process',
      startedAt: startedAt, endedAt: this.nowMs(),
      durationMs: this.deps.now() - startedLocal, attempt: 0, fenceAt: 0
    }, outcome));
    log.debug("Leaving Scheduler.runInThisProcess().");
  }

  // -------------------------------------------------------------------------
  // MANUAL RUNS (#48's button, and every job's Run now). A queued row,
  // written by whichever process served the request, picked up by the leader
  // at its next tick — so it runs once, on the leader, wherever it was
  // asked. A second request for the same job and realm while one is queued
  // is the same run. Answers `{ ok, runId, run }` or `{ ok: false,
  // errorCode, why }`; the caller answers 202 or 400.
  // -------------------------------------------------------------------------
  requestRun(jobId: string, opts?: Json): Json {
    const { log, realms } = this.deps;
    log.debug("Entering Scheduler.requestRun(). " + jobId);
    const o = opts || {};
    const job = this.job(jobId);
    if (!job) {
      log.debug("Leaving Scheduler.requestRun(). Unknown job.");
      return { ok: false, errorCode: 'STS-SCHED-0004', status: 404,
               why: 'No job "' + String(jobId) + '" is registered. The ' +
                    'jobs are ' + this.jobIds().join(', ') + '.' };
    }
    if (job.manual === false || job.kind === 'per-process') {
      log.debug("Leaving Scheduler.requestRun(). Not by hand.");
      return { ok: false, errorCode: 'STS-SCHED-0005', status: 400,
               why: job.id + ' runs on its schedule only' +
                    (job.kind === 'per-process'
                      ? ': it is a per-process job, which every process ' +
                        'runs for itself.' : '.') };
    }
    const realmId = job.scope === 'realm'
      ? String(o.realm || realms.DEFAULT_ID) : realms.DEFAULT_ID;
    if (job.scope === 'realm' && !realms.get(realmId)) {
      log.debug("Leaving Scheduler.requestRun(). Unknown realm.");
      return { ok: false, errorCode: 'STS-SCHED-0012', status: 400,
               why: 'There is no realm "' + realmId + '".' };
    }
    const off = this.offReason(job, realmId);
    if (off) {
      log.debug("Leaving Scheduler.requestRun(). Off.");
      return { ok: false, errorCode: 'STS-SCHED-0006', status: 400,
               why: job.id + ' is off: ' + off + '.' };
    }
    const params = o.params && typeof o.params === 'object' ? o.params : null;
    const paramsText = JSON.stringify(params);
    let existing: Json = null;
    this.storeOf(realmId).forEach(function (row: Json): void {
      if (!existing && row && row.kind === 'run' && row.trigger === 'manual' &&
          row.jobId === job.id && row.state === 'queued' &&
          JSON.stringify(row.params || null) === paramsText) {
        existing = row;
      }
    });
    if (existing) {
      log.debug("Leaving Scheduler.requestRun(). Already queued.");
      return { ok: true, runId: existing.runId, alreadyQueued: true,
               run: this.runView(existing) };
    }
    const row = this.writeRow(realmId, {
      runId: 'm-' + nodeCrypto.randomBytes(12).toString('base64url'),
      kind: 'run', jobId: job.id, realm: realmId, slot: null,
      dueAt: this.nowMs(), trigger: 'manual', params: params,
      requestedBy: String(o.requestedBy || ''),
      requestedVia: String(o.via || ''), state: 'queued', attempt: 0,
      fenceAt: 0, queuedAt: this.nowMs()
    });
    this.deps.audit.record({
      action: 'scheduler.run', protocol: 'scheduler',
      channel: o.channel || 'console', actor: String(o.requestedBy || ''),
      target: job.id,
      summary: 'A run of ' + job.id + ' was queued by hand' +
               (o.via ? ' at ' + o.via : '') + '.',
      detail: { runId: row.runId, realm: realmId }
    });
    log.debug("Leaving Scheduler.requestRun(). Queued " + row.runId + ".");
    return { ok: true, runId: row.runId, run: this.runView(row) };
  }

  // -------------------------------------------------------------------------
  // STEPPING DOWN (D10): a command row the leader obeys at its next tick —
  // wherever the request was answered, which behind a balancer is any node.
  // -------------------------------------------------------------------------
  requestStepDown(opts?: Json): Json {
    const { log } = this.deps;
    log.debug("Entering Scheduler.requestStepDown().");
    const o = opts || {};
    if (!this.clustered()) {
      log.debug("Leaving Scheduler.requestStepDown(). Not clustered.");
      return { ok: false, errorCode: 'STS-SCHED-0010', status: 400,
               why: 'This service is not clustered, so there is no other ' +
                    'node to hand the scheduler to.' };
    }
    const leader = this.storeOf(realms.DEFAULT_ID).get(LEADER_KEY) || null;
    const row = this.writeRow(realms.DEFAULT_ID, {
      runId: COMMAND_PREFIX + nodeCrypto.randomBytes(9).toString('base64url'),
      kind: 'command', command: 'step-down', state: 'queued',
      requestedBy: String(o.requestedBy || ''),
      requestedVia: String(o.via || ''), queuedAt: this.nowMs(),
      leaderAtRequest: leader ? { node: leader.node, pid: leader.pid,
                                  token: leader.token } : null,
      attempt: 0, fenceAt: 0
    });
    this.deps.audit.record({
      action: 'scheduler.step-down', protocol: 'scheduler',
      channel: o.channel || 'console', actor: String(o.requestedBy || ''),
      target: LEADER_LEASE,
      summary: 'The scheduler\'s leader was asked to stand down' +
               (o.via ? ' at ' + o.via : '') + '.',
      detail: { command: row.runId }
    });
    log.debug("Leaving Scheduler.requestStepDown().");
    return { ok: true, command: row.runId, leaderAtRequest:
             row.leaderAtRequest };
  }

  // Answers true when this process stood down, so the tick stops there.
  private async obeyCommands(): Promise<boolean> {
    const { log, cluster } = this.deps;
    const self = this;
    log.debug("Entering Scheduler.obeyCommands().");
    const queued: Json[] = [];
    this.storeOf(realms.DEFAULT_ID).forEach(function (row: Json): void {
      if (row && row.kind === 'command' && row.state === 'queued') {
        queued.push(Object.assign({}, row));
      }
    });
    if (!queued.length) {
      log.debug("Leaving Scheduler.obeyCommands(). None.");
      return false;
    }
    queued.forEach(function (row: Json): void {
      self.writeRow(realms.DEFAULT_ID, Object.assign(row, {
        state: 'succeeded', endedAt: self.nowMs(),
        obeyedBy: self.who() }));
    });
    const answer = await cluster.stepDown(LEADER_LEASE);
    if (!answer || !answer.ok) {
      log.warn(errorCodes.tag('STS-SCHED-0014') + 'scheduler: asked to ' +
               'stand down, and could not (' +
               ((answer && (answer.why || answer.reason)) || 'no answer') +
               ').');
      log.debug("Leaving Scheduler.obeyCommands(). Could not.");
      return false;
    }
    log.info('scheduler: this process stood down as the scheduler\'s ' +
             'leader, as asked; another node takes it at its next heartbeat.');
    log.debug("Leaving Scheduler.obeyCommands(). Stood down.");
    return true;
  }

  // -------------------------------------------------------------------------
  // HISTORY. Finished runs older than `scheduler.historyDays` go, and past
  // `scheduler.maxRuns` per realm the oldest finished ones go first — never a
  // queued or running row, and never a job's latest run.
  // -------------------------------------------------------------------------
  prune(at?: number): number {
    const { log, realms } = this.deps;
    const self = this;
    log.debug("Entering Scheduler.prune().");
    const now = at || this.nowMs();
    const keepMs = Math.max(1, this.setting('scheduler.historyDays')) *
                   86400000;
    const cap = Math.max(100, this.setting('scheduler.maxRuns'));
    let removed = 0;
    realms.list().forEach(function (realm: Json): void {
      const map = self.storeOf(String(realm.id));
      const latest = new Map<string, Json>();
      const finished: Json[] = [];
      map.forEach(function (row: Json, key: string): void {
        if (!row || (row.kind !== 'run' && row.kind !== 'command' &&
                     row.kind !== 'process')) {
          return;
        }
        const job = row.jobId || row.command || '';
        const ended = Number(row.endedAt) || 0;
        const held = latest.get(job + '|' + row.realm);
        if (row.kind === 'run' && FINAL.indexOf(row.state) >= 0 &&
            (!held || ended > (Number(held.endedAt) || 0))) {
          latest.set(job + '|' + row.realm, row);
        }
        if (FINAL.indexOf(row.state) >= 0 || row.kind === 'process') {
          finished.push({ key: key, row: row, ended: ended ||
                          Number(row.updatedAt) || 0 });
        }
      });
      const protectedKeys = new Set<string>();
      latest.forEach(function (row: Json): void {
        protectedKeys.add(row.runId);
      });
      finished.sort(function (a: Json, b: Json): number {
        return a.ended - b.ended;
      });
      let over = map.size - cap;
      finished.forEach(function (one: Json): void {
        if (protectedKeys.has(one.key)) {
          return;
        }
        if (now - one.ended > keepMs || over > 0) {
          map.delete(one.key);
          removed += 1;
          over -= 1;
        }
      });
    });
    log.debug("Leaving Scheduler.prune(). " + removed + " removed.");
    return removed;
  }

  // -------------------------------------------------------------------------
  // THE REPORT, which /admin/scheduler draws and GET /admin-api/scheduler
  // answers field for field. Read from the STORE, with the next run worked
  // out from the DATABASE's clock, so every process on every node draws the
  // same figures. `realmId` confines it to one realm's realm-scoped rows (a
  // realm administrator's view), with the service jobs shown read-only.
  // -------------------------------------------------------------------------
  async status(opts?: Json): Promise<Json> {
    const { log, realms } = this.deps;
    const self = this;
    log.debug("Entering Scheduler.status().");
    const o = opts || {};
    await this.refreshClock().catch(function (e: Json): void {
      log.debug("Caught in Scheduler.status(): " + ((e && e.message) || e));
    });
    const at = this.nowMs();
    const onlyRealm = o.realm ? String(o.realm) : '';
    const leaderRow = this.storeOf(realms.DEFAULT_ID).get(LEADER_KEY) || null;
    const leader = await this.leaderView(leaderRow, at);
    const jobs: Json[] = [];
    this.jobIds().forEach(function (id: string): void {
      const job = self.jobs.get(id);
      const realmIds = self.realmIdsFor(job).filter(function (r: string) {
        return !onlyRealm || job.scope === 'service' || r === onlyRealm;
      });
      realmIds.forEach(function (realmId: string): void {
        jobs.push(self.jobView(job, realmId, at, leader, onlyRealm));
      });
    });
    const runs = this.recentRuns(o, at);
    const out = {
      generatedAt: new Date(at).toISOString(),
      nowMs: at,
      clock: this.clockSource(),
      answeredBy: this.who(),
      leader: leader,
      tickS: this.setting('scheduler.tickS'),
      enabled: !!this.deps.config.value('scheduler.enabled'),
      unknownDisabledIds: this.disabledIds().filter(function (id: string) {
        return !self.jobs.has(id);
      }),
      jobs: jobs,
      runs: runs,
      commands: this.commandViews()
    };
    log.debug("Leaving Scheduler.status(). " + jobs.length + " row(s).");
    return out;
  }

  private clockSource(): string {
    const { log } = this.deps;
    log.debug("Entering Scheduler.clockSource().");
    let source = 'this process';
    try {
      const persistence = require('../persistence/persistence');
      const store = persistence.clusterStore && persistence.clusterStore();
      if (store && typeof store.clusterClock === 'function') {
        source = 'the database';
      }
    } catch (e) {
      log.debug("Caught in Scheduler.clockSource(): " + ((e && e.message) ||
                                                           e));
    }
    log.debug("Leaving Scheduler.clockSource().");
    return source;
  }

  private async leaderView(row: Json, at: number): Promise<Json> {
    const { log, cluster } = this.deps;
    log.debug("Entering Scheduler.leaderView().");
    const clustered = this.clustered();
    let lease: Json = null;
    if (clustered) {
      try {
        const state = await cluster.state();
        lease = ((state && state.leases) || []).filter(function (l: Json) {
          return l.name === LEADER_LEASE;
        })[0] || null;
      } catch (e) {
        log.debug("Caught in Scheduler.leaderView(): " + ((e && e.message) ||
                                                           e));
      }
    }
    const me = this.who();
    const view: Json = {
      clustered: clustered,
      known: !!row,
      node: row ? row.node : '',
      nodeName: row ? row.nodeName : '',
      host: row ? row.host : '',
      pid: row ? row.pid : null,
      since: row && row.since ? new Date(row.since).toISOString() : null,
      token: lease ? Number(lease.token) : (row ? row.token : 0),
      leaseHolder: lease ? lease.holder : '',
      leaseAcquiredAt: lease && lease.acquiredAt
        ? new Date(Number(lease.acquiredAt)).toISOString() : null,
      leaseExpiresAt: lease && lease.expiresAt
        ? new Date(Number(lease.expiresAt)).toISOString() : null,
      lastTickAt: row && row.lastTickAt
        ? new Date(row.lastTickAt).toISOString() : null,
      lastTickAgoMs: row && row.lastTickAt ? Math.max(0, at - row.lastTickAt)
        : null,
      thisProcess: !!row && row.pid === me.pid &&
                   String(row.node || '') === String(me.node || '') &&
                   this.leading,
      live: !!row && row.lastTickAt &&
            at - row.lastTickAt <= Math.max(3 * this.tickMs(),
                                            OVERDUE_FLOOR_MS)
    };
    log.debug("Leaving Scheduler.leaderView().");
    return view;
  }

  // Every run row of one job in one realm, newest first.
  private runsOf(jobId: string, realmId: string): Json[] {
    const { log } = this.deps;
    log.debug("Entering Scheduler.runsOf().");
    const out: Json[] = [];
    this.storeOf(realmId).forEach(function (row: Json): void {
      if (row && (row.kind === 'run') && row.jobId === jobId &&
          row.realm === realmId) {
        out.push(row);
      }
    });
    out.sort(function (a: Json, b: Json): number {
      return (Number(b.startedAt) || Number(b.queuedAt) || 0) -
             (Number(a.startedAt) || Number(a.queuedAt) || 0);
    });
    log.debug("Leaving Scheduler.runsOf(). " + out.length + ".");
    return out;
  }

  private jobView(job: JobSpec, realmId: string, at: number, leader: Json,
                  onlyRealm: string): Json {
    const { log } = this.deps;
    log.debug("Entering Scheduler.jobView(). " + job.id + " " + realmId);
    const off = this.offReason(job, realmId);
    const view: Json = {
      id: job.id, title: job.title, describe: job.describe,
      owner: job.owner, kind: job.kind, scope: job.scope, realm: realmId,
      readOnly: !!onlyRealm && job.scope === 'service',
      schedule: {
        text: this.scheduleText(job),
        everyMs: job.cron || job.manualOnly ? null : this.intervalMs(job),
        setting: job.everySetting || null,
        cron: job.cron || null,
        manualOnly: !!job.manualOnly
      },
      state: off ? 'off' : 'enabled',
      offReason: off || null,
      manual: job.manual !== false && job.kind !== 'per-process',
      timeoutMs: this.timeoutMsOf(job)
    };
    if (job.kind === 'per-process') {
      view.processes = this.processViews(job, realmId, at);
      view.lastRun = null;
      view.running = null;
      view.queued = [];
      const next = this.slotAt(job, at);
      view.nextRunAt = off || !next ? null : new Date(next.nextAt)
        .toISOString();
      view.nextRunInMs = off || !next ? null : Math.max(0, next.nextAt - at);
      view.nextRunState = off ? 'off' : (next ? 'scheduled' : 'manual-only');
      log.debug("Leaving Scheduler.jobView(). Per-process.");
      return view;
    }
    const runs = this.runsOf(job.id, realmId);
    const finished = runs.filter(function (row: Json): boolean {
      return FINAL.indexOf(row.state) >= 0;
    });
    const running = runs.filter(function (row: Json): boolean {
      return row.state === 'running';
    })[0] || null;
    const queued = runs.filter(function (row: Json): boolean {
      return row.state === 'queued' && row.trigger === 'manual';
    });
    view.lastRun = finished.length ? this.runView(finished.sort(
      function (a: Json, b: Json): number {
        return (Number(b.endedAt) || 0) - (Number(a.endedAt) || 0);
      })[0]) : null;
    view.running = running ? this.runView(running) : null;
    view.queued = queued.map(this.runView.bind(this));
    this.nextRunOf(job, realmId, at, leader, view, off);
    log.debug("Leaving Scheduler.jobView().");
    return view;
  }

  // THE NEXT RUN, and the one word that says what kind of figure it is.
  private nextRunOf(job: JobSpec, realmId: string, at: number, leader: Json,
                    view: Json, off: string): void {
    const { log } = this.deps;
    log.debug("Entering Scheduler.nextRunOf().");
    view.nextRunAt = null;
    view.nextRunInMs = null;
    view.overdueSince = null;
    if (off) {
      view.nextRunState = 'off';
      log.debug("Leaving Scheduler.nextRunOf(). Off.");
      return;
    }
    if (view.queued.length) {
      view.nextRunState = 'queued';
      view.nextRunAt = new Date(Number(view.queued[0].queuedAtMs) || at)
        .toISOString();
      view.nextRunInMs = 0;
      log.debug("Leaving Scheduler.nextRunOf(). Queued.");
      return;
    }
    const slot = this.slotAt(job, at);
    if (!slot) {
      view.nextRunState = 'manual-only';
      log.debug("Leaving Scheduler.nextRunOf(). On demand only.");
      return;
    }
    const currentId = slot.slot === null ? null
      : this.runIdFor(job, realmId, slot.slot);
    const current = currentId ? this.storeOf(realmId).get(currentId) : null;
    if (slot.slot === null || (current && current.state !== 'queued')) {
      view.nextRunState = current && current.state === 'running'
        ? 'running' : 'scheduled';
      view.nextRunAt = slot.nextAt === null ? null
        : new Date(slot.nextAt).toISOString();
      view.nextRunInMs = slot.nextAt === null ? null
        : Math.max(0, slot.nextAt - at);
      log.debug("Leaving Scheduler.nextRunOf(). Scheduled.");
      return;
    }
    // Due in this slot and not run yet.
    view.nextRunAt = new Date(slot.startsAt).toISOString();
    view.nextRunInMs = 0;
    const late = at - slot.startsAt;
    if (late > Math.max(3 * this.tickMs(), OVERDUE_FLOOR_MS)) {
      view.nextRunState = 'overdue';
      view.overdueSince = new Date(slot.startsAt).toISOString();
      view.overdueWhy = leader && leader.live
        ? 'the leader is ticking; a previous run may still be going, or ' +
          'its claim has not lapsed'
        : 'no leader has ticked since ' + (leader && leader.lastTickAt ||
                                           'this service started');
    } else {
      view.nextRunState = 'due';
    }
    log.debug("Leaving Scheduler.nextRunOf(). " + view.nextRunState + ".");
  }

  runView(row: Json): Json {
    const { log } = this.deps;
    log.debug("Entering Scheduler.runView().");
    const iso = function (ms: Json): string | null {
      return Number(ms) ? new Date(Number(ms)).toISOString() : null;
    };
    const out = {
      runId: row.runId, jobId: row.jobId || null, realm: row.realm || null,
      trigger: row.trigger || 'schedule', state: row.state,
      attempt: Number(row.attempt) || 0, fenceAt: Number(row.fenceAt) || 0,
      node: row.node || '', nodeName: row.nodeName || '', host: row.host || '',
      pid: row.pid || null, worker: !!row.worker,
      dueAt: iso(row.dueAt), queuedAt: iso(row.queuedAt),
      queuedAtMs: Number(row.queuedAt) || null,
      startedAt: iso(row.startedAt), endedAt: iso(row.endedAt),
      durationMs: row.durationMs === undefined ? null
        : Number(row.durationMs),
      requestedBy: row.requestedBy || '', requestedVia: row.requestedVia || '',
      params: row.params || null, takenOver: !!row.takenOver,
      abandonedOf: row.abandonedOf || null,
      errorCode: row.errorCode || '', why: row.why || '',
      result: row.result === undefined ? null : row.result
    };
    log.debug("Leaving Scheduler.runView().");
    return out;
  }

  private processViews(job: JobSpec, realmId: string, at: number): Json[] {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering Scheduler.processViews().");
    const out: Json[] = [];
    this.storeOf(realms.DEFAULT_ID).forEach(function (row: Json): void {
      if (row && row.kind === 'process' && row.jobId === job.id &&
          row.realm === realmId) {
        const view: Json = self.runView(row);
        view.nextRunAt = row.nextAt ? new Date(row.nextAt).toISOString()
          : null;
        view.nextRunInMs = row.nextAt ? Math.max(0, row.nextAt - at) : null;
        // A process that has not run since two slots ago has probably gone.
        const every = self.intervalMs(job) || self.tickMs();
        view.stale = at - (Number(row.endedAt) || 0) > 2 * every +
                     2 * self.tickMs();
        out.push(view);
      }
    });
    out.sort(function (a: Json, b: Json): number {
      return String(a.nodeName + a.pid).localeCompare(String(b.nodeName +
                                                             b.pid));
    });
    log.debug("Leaving Scheduler.processViews(). " + out.length + ".");
    return out;
  }

  private commandViews(): Json[] {
    const { log } = this.deps;
    log.debug("Entering Scheduler.commandViews().");
    const out: Json[] = [];
    this.storeOf(realms.DEFAULT_ID).forEach(function (row: Json): void {
      if (row && row.kind === 'command') {
        out.push({ id: row.runId, command: row.command, state: row.state,
                   requestedBy: row.requestedBy || '',
                   queuedAt: row.queuedAt
                     ? new Date(row.queuedAt).toISOString() : null,
                   endedAt: row.endedAt
                     ? new Date(row.endedAt).toISOString() : null,
                   leaderAtRequest: row.leaderAtRequest || null,
                   obeyedBy: row.obeyedBy || null });
      }
    });
    out.sort(function (a: Json, b: Json): number {
      return String(b.queuedAt).localeCompare(String(a.queuedAt));
    });
    log.debug("Leaving Scheduler.commandViews().");
    return out.slice(0, 20);
  }

  // Recent runs, newest first, filtered by job, realm and outcome.
  recentRuns(opts: Json, at?: number): Json[] {
    const { log, realms } = this.deps;
    const self = this;
    log.debug("Entering Scheduler.recentRuns().");
    const o = opts || {};
    const out: Json[] = [];
    realms.list().forEach(function (realm: Json): void {
      const id = String(realm.id);
      if (o.realm && id !== String(o.realm) && id !== realms.DEFAULT_ID) {
        return;
      }
      self.storeOf(id).forEach(function (row: Json): void {
        if (!row || row.kind !== 'run') {
          return;
        }
        if (o.realm && id === realms.DEFAULT_ID &&
            String(o.realm) !== realms.DEFAULT_ID) {
          const job = self.jobs.get(row.jobId);
          if (job && job.scope === 'realm') {
            return;
          }
        }
        if (o.job && row.jobId !== String(o.job)) {
          return;
        }
        if (o.outcome && row.state !== String(o.outcome)) {
          return;
        }
        out.push(self.runView(row));
      });
    });
    out.sort(function (a: Json, b: Json): number {
      return String(b.startedAt || b.queuedAt || '').localeCompare(
        String(a.startedAt || a.queuedAt || ''));
    });
    log.debug("Leaving Scheduler.recentRuns(). " + out.length + ".");
    return out;
  }

  // One run by id, in whichever realm holds it.
  findRun(runId: string): Json | null {
    const { log, realms } = this.deps;
    const self = this;
    log.debug("Entering Scheduler.findRun().");
    let found: Json = null;
    realms.list().forEach(function (realm: Json): void {
      if (found) {
        return;
      }
      const row = self.storeOf(String(realm.id)).get(String(runId));
      if (row && (row.kind === 'run' || row.kind === 'process')) {
        found = self.runView(row);
      }
    });
    log.debug("Leaving Scheduler.findRun(). " + (found ? 'found' : 'none'));
    return found;
  }

  // For tests: forget what this instance holds in memory.
  resetForTests(): void {
    const { log } = this.deps;
    log.debug("Entering Scheduler.resetForTests().");
    this.stop();
    this.inFlight.clear();
    this.processSlots.clear();
    this.ticking = null;
    log.debug("Leaving Scheduler.resetForTests().");
  }
}

// ---------------------------------------------------------------------------
// THE ONE SCHEDULER OF THIS PROCESS. Every job's owner registers with it at
// require time; `server.js` and `common/request_worker.ts` start it.
// ---------------------------------------------------------------------------
const scheduler = new Scheduler(Scheduler.defaultDeps());

// The scheduler's own housekeeping is a job like any other.
scheduler.register({
  id: 'scheduler.history',
  title: 'Scheduler run history',
  describe: 'Removes finished runs older than scheduler.historyDays, and ' +
            'the oldest past scheduler.maxRuns per realm; the latest run of ' +
            'each job is always kept.',
  owner: 'cluster/scheduler.ts',
  everyMs: function (): number {
    return 60 * 60 * 1000;
  },
  run: function (): Json {
    return { removed: scheduler.prune() };
  }
});

export = {
  Scheduler: Scheduler,
  scheduler: scheduler,
  LEADER_LEASE: LEADER_LEASE,
  RUN_SCOPE: RUN_SCOPE,
  runStore: runStore,
  register: scheduler.register.bind(scheduler) as Scheduler['register'],
  start: scheduler.start.bind(scheduler) as Scheduler['start'],
  stop: scheduler.stop.bind(scheduler) as Scheduler['stop'],
  status: scheduler.status.bind(scheduler) as Scheduler['status'],
  requestRun: scheduler.requestRun.bind(scheduler) as Scheduler['requestRun'],
  requestStepDown: scheduler.requestStepDown.bind(scheduler) as
    Scheduler['requestStepDown'],
  findRun: scheduler.findRun.bind(scheduler) as Scheduler['findRun'],
  recentRuns: scheduler.recentRuns.bind(scheduler) as Scheduler['recentRuns'],
  job: scheduler.job.bind(scheduler) as Scheduler['job'],
  jobIds: scheduler.jobIds.bind(scheduler) as Scheduler['jobIds']
};
