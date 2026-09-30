// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: cluster/node_snapshots.ts
//
// ===========================================================================
// EVERY CLUSTER NODE ON MONITORING → WORKER POOLS AND → NODE HEALTH (#332,
// 2026-09-28), BY NAME, FROM THE SHARED STORE.
//
// Both pages describe the node that draws them — its pools, its container,
// its processes — and in a cluster that is one node in N. rcbj's standing
// rules decide the shape: NO NODE'S ADDRESS IS EVER PUBLISHED (any node
// answers for the cluster from shared state, so the page cannot send a
// request to another node, and would have nowhere to send it), and ANYTHING
// PERIODIC IS A SCHEDULER JOB. So:
//
//   * **A PER-PROCESS SCHEDULER JOB, `cluster.node-snapshot`**, runs every
//     INTERVAL_MS in each node's FRONT process — off in a request worker,
//     which is not the node, and off with no cluster — and writes the node's
//     own views of both pages (the providers the two page modules hand in)
//     to `sts_node_snapshots`: ONE ROW PER NODE NAME, overwritten, so the
//     table never grows with time. `quiet`, so the scheduler records its run
//     only when its outcome changes.
//   * **Whichever node draws a page reads every row** and draws a section per
//     node, its own from its LIVE figures and every other from its row,
//     stamped with its age by the DATABASE's clock (the row's `taken_at` and
//     the query's `now`, never this container's clock against another's).
//   * **A NODE IS MARKED, NEVER SILENTLY DROPPED.** `stale` when its row is
//     older than STALE_MS (three intervals), `gone` when cluster membership
//     has no live row by that name, `no-snapshot` when membership lists it
//     and it has written nothing yet. A gone node stays on the page, saying
//     when it will be removed, until its snapshot is older than
//     `cluster.nodeSnapshotRetentionHours` (a day — rcbj's answer on #332);
//     then the CLUSTER job `cluster.node-snapshot-purge`, hourly on the
//     scheduler's leader, deletes its row. **A live member's row is never
//     deleted, however old**, and **nothing is deleted while membership
//     cannot be read**: the list of names to keep is read fresh for the run,
//     and a read that fails or comes back empty ends the run with no delete.
//   * **NODES ARE NAMED, NEVER ADDRESSED.** The name is `cluster.nodeName`
//     (`STS_CLUSTER_NODE_NAME`, node-a, node-b, …); a name that is itself an
//     address — the host name a node falls back to, which on Fargate is
//     `ip-10-…` — is replaced by a digest of it, and every string of a view
//     has IPv4 literals replaced before it is written or answered
//     (`scrub()`), so an error message quoting an address cannot carry one
//     through.
//
// **WITH NO CLUSTER, NOTHING CHANGES**: memory and ldif stores cannot be
// shared, and `cluster.mode` off is one node by definition. The page draws
// its own section and says there is no cluster, in a sentence.
//
// A LIBRARY (rule 3): it registers no route. The two page modules require it
// at load and hand it their views through `provide()`, which also registers
// the job — so every process that loads the stack registers the same job
// (`cluster/CLAUDE.md`, *EVERY PROCESS MUST REGISTER THE SAME JOBS*). The
// cluster, the store and the scheduler are reached LAZILY: `scheduler.ts`
// requires this directory's modules, and the store is open only after start.
// ===========================================================================

import crypto = require('crypto');
import helpers = require('../common/helpers');
import errorCodes = require('../common/error_codes');
import InstanceSlot = require('../common/instance_slot');

type Json = any;

/**
 * How often each node writes its snapshot, in milliseconds.
 */
const INTERVAL_MS = 15000;

/**
 * A snapshot older than this is drawn as stale: three intervals.
 */
const STALE_MS = 3 * INTERVAL_MS;

/**
 * The scheduler job's id.
 */
const JOB_ID = 'cluster.node-snapshot';

/**
 * The job that deletes a gone node's row once it is older than
 * `cluster.nodeSnapshotRetentionHours`.
 */
const PURGE_JOB_ID = 'cluster.node-snapshot-purge';

/**
 * How often the purge runs: hourly.
 */
const PURGE_EVERY_MS = 60 * 60 * 1000;

// An IPv4 literal, wherever it is in a string. IPv6 is not matched: nothing
// on these pages is IPv6, and a pattern loose enough to find one would find
// every time of day.
const IPV4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;

// A host name that is an address in disguise: `ip-10-0-1-23`, as Fargate
// and EC2 name a host.
const IP_HOST = /^ip-\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}\b/;

interface NodeSnapshotsDeps {
  log: typeof helpers.log;
  errorCodes: typeof errorCodes;
  // `cluster.nodeSnapshotRetentionHours`, read when used.
  retentionHours: () => number;
  cluster: () => any;
  store: () => any;
  scheduler: () => any;
}

/**
 * Each cluster node's snapshot of Monitoring → Worker Pools and → Node
 * Health, written by a per-process scheduler job and read by whichever node
 * draws the pages.
 */
class NodeSnapshots {
  /**
   * See the module's `INTERVAL_MS`.
   */
  static readonly INTERVAL_MS = INTERVAL_MS;

  /**
   * See the module's `STALE_MS`.
   */
  static readonly STALE_MS = STALE_MS;

  /**
   * See the module's `JOB_ID`.
   */
  static readonly JOB_ID = JOB_ID;

  /**
   * See the module's `PURGE_JOB_ID`.
   */
  static readonly PURGE_JOB_ID = PURGE_JOB_ID;

  // The views this node writes, by key: `workerPools`, `nodeHealth`.
  private providers = new Map<string, () => Promise<Json>>();

  // Whether the last read or write of the store failed, so that a failure is
  // logged when it starts rather than on every page and every run.
  private failing = { read: false, write: false, purge: false };

  /**
   * Builds an instance over the modules it depends on.
   *
   * @param deps - the logger, the cluster, the store and the scheduler
   */
  constructor(private readonly deps: NodeSnapshotsDeps) {
    deps.log.debug("Entering NodeSnapshots.constructor().");
    deps.log.debug("Leaving NodeSnapshots.constructor().");
  }

  /**
   * Answers the real modules, reached lazily.
   *
   * @returns the dependencies of a default instance
   */
  static defaultDeps(): NodeSnapshotsDeps {
    helpers.log.debug("Entering NodeSnapshots.defaultDeps().");
    const log = helpers.log;
    helpers.log.debug("Leaving NodeSnapshots.defaultDeps().");
    return {
      log: log,
      errorCodes: errorCodes,
      retentionHours: function retentionHours(): number {
        log.debug("Entering retentionHours().");
        const hours = Number(require('../common/config')
          .value('cluster.nodeSnapshotRetentionHours'));
        log.debug("Leaving retentionHours().");
        return hours >= 1 ? hours : 24;
      },
      cluster: function cluster(): any {
        log.debug("Entering cluster().");
        log.debug("Leaving cluster().");
        return require('./cluster');
      },
      // The postgres driver when the store can be shared, null otherwise.
      store: function store(): any {
        log.debug("Entering store().");
        const driver = require('../persistence/persistence').clusterStore();
        log.debug("Leaving store().");
        return driver && typeof driver.putNodeSnapshot === 'function' &&
               typeof driver.nodeSnapshots === 'function' ? driver : null;
      },
      scheduler: function scheduler(): any {
        log.debug("Entering scheduler().");
        log.debug("Leaving scheduler().");
        return require('./scheduler');
      }
    };
  }

  /**
   * Replaces every IPv4 literal in every string of a value, deeply; the
   * value is copied, never changed.
   *
   * @param value - a view, or any JSON value
   * @returns the copy
   */
  static scrub(value: Json): Json {
    helpers.log.debug("Entering NodeSnapshots.scrub().");
    helpers.log.debug("Leaving NodeSnapshots.scrub().");
    return JSON.parse(JSON.stringify(value === undefined ? null : value)
      .replace(IPV4, '[address]'));
  }

  /**
   * The name a node is shown under: its configured name, or — for a name
   * that is an address — `node-` and a digest of it.
   *
   * @param name - the node's name as the cluster knows it
   * @returns the name to draw
   */
  static displayName(name: string): string {
    helpers.log.debug("Entering NodeSnapshots.displayName().");
    const text = String(name || '').trim();
    IPV4.lastIndex = 0;
    if (!text || IP_HOST.test(text) || IPV4.test(text) ||
        text.indexOf(':') >= 0) {
      IPV4.lastIndex = 0;
      helpers.log.debug("Leaving NodeSnapshots.displayName(). Digested.");
      return 'node-' + crypto.createHash('sha256').update(text)
        .digest('hex').slice(0, 8);
    }
    IPV4.lastIndex = 0;
    helpers.log.debug("Leaving NodeSnapshots.displayName().");
    return text;
  }

  /**
   * This node's name, as drawn.
   *
   * @returns the name
   */
  selfName(): string {
    const { log, cluster } = this.deps;
    log.debug("Entering NodeSnapshots.selfName().");
    let name = '';
    try {
      name = String(cluster().nodeName() || '');
    } catch (e) {
      log.debug("Caught in NodeSnapshots.selfName(): " +
                ((e && e.message) || e));
      // No cluster module to ask: the digest of nothing names this node.
      name = '';
    }
    log.debug("Leaving NodeSnapshots.selfName().");
    return NodeSnapshots.displayName(name);
  }

  /**
   * Why there is nothing to share, or '' when this node is in a cluster
   * whose store can hold the snapshots.
   *
   * @returns the sentence, or ''
   */
  whyNoCluster(): string {
    const { log, cluster, store } = this.deps;
    log.debug("Entering NodeSnapshots.whyNoCluster().");
    let clustered = false;
    try {
      clustered = !!cluster().enabled();
    } catch (e) {
      log.debug("Caught in NodeSnapshots.whyNoCluster(): " +
                ((e && e.message) || e));
      // Treated as no cluster, which is what the sentence says.
      clustered = false;
    }
    if (!clustered) {
      log.debug("Leaving NodeSnapshots.whyNoCluster(). Not clustered.");
      return 'There is no cluster: cluster.mode resolves to off here, so ' +
        'this node is the whole service and its own section is the page.';
    }
    let shared = null;
    try {
      shared = store();
    } catch (e) {
      log.debug("Caught in NodeSnapshots.whyNoCluster(): " +
                ((e && e.message) || e));
      // No store to ask: said below.
      shared = null;
    }
    log.debug("Leaving NodeSnapshots.whyNoCluster().");
    return shared ? ''
      : 'There is no cluster store: the persistence store is not one every ' +
        'node shares, so no other node\'s snapshot can be read.';
  }

  /**
   * Hands in one of this node's views, for the job to write, and registers
   * the job the first time.
   *
   * @param key - `workerPools` or `nodeHealth`
   * @param fn - resolves this node's own view
   */
  provide(key: string, fn: () => Promise<Json>): void {
    const { log } = this.deps;
    log.debug("Entering NodeSnapshots.provide(). " + key);
    this.providers.set(key, fn);
    this.ensureJob();
    log.debug("Leaving NodeSnapshots.provide().");
  }

  // Why the job is off in this process now, or ''.
  private jobOff(): string {
    const { log, cluster } = this.deps;
    log.debug("Entering NodeSnapshots.jobOff().");
    const why = this.whyNoCluster();
    if (why) {
      log.debug("Leaving NodeSnapshots.jobOff(). No cluster.");
      return why;
    }
    let status: Json = {};
    try {
      status = cluster().status() || {};
    } catch (e) {
      log.debug("Caught in NodeSnapshots.jobOff(): " +
                ((e && e.message) || e));
      // Said below as a process that has not joined.
      status = {};
    }
    log.debug("Leaving NodeSnapshots.jobOff().");
    return status.role === 'front' && status.nodeId ? ''
      : 'this process is not a joined front process: a request worker is ' +
        'part of its node, whose front process writes the snapshot';
  }

  /**
   * Registers `cluster.node-snapshot` with the scheduler, once.
   */
  ensureJob(): void {
    const { log, scheduler } = this.deps;
    const self = this;
    log.debug("Entering NodeSnapshots.ensureJob().");
    let sched: any = null;
    try {
      sched = scheduler();
    } catch (e) {
      log.debug("Caught in NodeSnapshots.ensureJob(): " +
                ((e && e.message) || e));
      // A process without the scheduler (a narrow test) runs no job.
      sched = null;
    }
    if (!sched || typeof sched.register !== 'function') {
      log.debug("Leaving NodeSnapshots.ensureJob(). No scheduler.");
      return;
    }
    if (!sched.job(PURGE_JOB_ID)) {
      sched.register({
        id: PURGE_JOB_ID,
        title: 'Node snapshot purge',
        describe: 'Deletes the Worker Pools and Node Health snapshot of a ' +
                  'node that is no longer a live cluster member once it is ' +
                  'older than cluster.nodeSnapshotRetentionHours; never a ' +
                  'live member\'s, and nothing while membership cannot be ' +
                  'read (#332).',
        owner: 'cluster/node_snapshots.ts',
        kind: 'cluster',
        everyMs: function (): number {
          return PURGE_EVERY_MS;
        },
        off: function (): string {
          return self.whyNoCluster();
        },
        manual: true,
        run: function (): Promise<Json> {
          return self.purge();
        }
      });
    }
    if (sched.job(JOB_ID)) {
      log.debug("Leaving NodeSnapshots.ensureJob(). Registered.");
      return;
    }
    sched.register({
      id: JOB_ID,
      title: 'Node snapshot',
      describe: 'Writes this node\'s Monitoring → Worker Pools and → Node ' +
                'Health views to the shared store, one row per node name, ' +
                'so every node draws every node on those pages (#332).',
      owner: 'cluster/node_snapshots.ts',
      kind: 'per-process', quiet: true,
      everyMs: function (): number {
        return INTERVAL_MS;
      },
      off: function (): string {
        return self.jobOff();
      },
      run: function (): Promise<Json> {
        return self.write();
      }
    });
    log.debug("Leaving NodeSnapshots.ensureJob(). Registered.");
  }

  /**
   * Takes this node's views from the providers and writes them as its row.
   *
   * @returns a promise of the run's summary
   */
  async write(): Promise<Json> {
    const { log, store, cluster, errorCodes } = this.deps;
    log.debug("Entering NodeSnapshots.write().");
    const shared = store();
    if (!shared) {
      log.debug("Leaving NodeSnapshots.write(). No store.");
      return { written: false, why: 'no cluster store' };
    }
    const body: Json = { version: 1 };
    const keys = Array.from(this.providers.keys());
    for (const key of keys) {
      try {
        body[key] = await (this.providers.get(key) as () => Promise<Json>)();
      } catch (e) {
        log.debug("Caught in NodeSnapshots.write(): " +
                  ((e && e.message) || e));
        // The other view is still worth writing; this one says why not.
        body[key] = { unavailable: String((e && e.message) || e) };
      }
    }
    const name = this.selfName();
    try {
      await shared.putNodeSnapshot(name, String(cluster().nodeId() || ''),
                                   NodeSnapshots.scrub(body));
    } catch (e) {
      log.debug("Caught in NodeSnapshots.write(): " +
                ((e && e.message) || e));
      if (!this.failing.write) {
        log.warn(errorCodes.tag('STS-CORE-0127') + 'node snapshots: this ' +
                 'node\'s snapshot could not be written to the shared ' +
                 'store: ' + ((e && e.message) || e));
      }
      this.failing.write = true;
      log.debug("Leaving NodeSnapshots.write(). Failed.");
      throw e;
    }
    this.failing.write = false;
    log.debug("Leaving NodeSnapshots.write(). " + name);
    return { written: true, node: name, views: keys };
  }

  /**
   * Deletes the row of every node that is not a live member and whose
   * snapshot is older than the retention; keeps everything when membership
   * cannot be read (#332).
   *
   * @returns a promise of the run's summary
   */
  async purge(): Promise<Json> {
    const { log, store, cluster, errorCodes, retentionHours } = this.deps;
    log.debug("Entering NodeSnapshots.purge().");
    const shared = store();
    if (!shared || typeof shared.purgeNodeSnapshots !== 'function') {
      log.debug("Leaving NodeSnapshots.purge(). No store.");
      return { purged: 0, why: 'no cluster store' };
    }
    // FRESH, not the snapshot a page reads: a purge acts on it.
    let live: Set<string> | null = null;
    try {
      live = this.liveNamesOf(await cluster().state());
    } catch (e) {
      log.debug("Caught in NodeSnapshots.purge(): " +
                ((e && e.message) || e));
      // Unknown membership deletes nothing; said in the summary.
      live = null;
    }
    if (!live || !live.size) {
      log.debug("Leaving NodeSnapshots.purge(). Membership unknown.");
      return { purged: 0,
               why: 'cluster membership could not be read, so nothing was ' +
                    'deleted' };
    }
    live.add(this.selfName());
    const hours = retentionHours();
    let gone: Json[] = [];
    try {
      gone = await shared.purgeNodeSnapshots(hours * 60 * 60 * 1000,
                                             Array.from(live));
    } catch (e) {
      log.debug("Caught in NodeSnapshots.purge(): " +
                ((e && e.message) || e));
      if (!this.failing.purge) {
        log.warn(errorCodes.tag('STS-CORE-0128') + 'node snapshots: gone ' +
                 'nodes\' snapshots could not be deleted from the shared ' +
                 'store: ' + ((e && e.message) || e));
      }
      this.failing.purge = true;
      log.debug("Leaving NodeSnapshots.purge(). Failed.");
      throw e;
    }
    this.failing.purge = false;
    gone.forEach(function (row: Json): void {
      log.info('node snapshots: removed the snapshot of ' +
               NodeSnapshots.displayName(row.name) + ', which is not a live ' +
               'cluster member and wrote nothing for ' + hours + ' h ' +
               '(cluster.nodeSnapshotRetentionHours).');
    });
    log.debug("Leaving NodeSnapshots.purge(). " + gone.length + " removed.");
    return { purged: gone.length, retentionHours: hours,
             nodes: gone.map(function (row: Json): string {
               return NodeSnapshots.displayName(row.name);
             }) };
  }

  // The names a cluster state lists as live, or null when it cannot say.
  private liveNamesOf(state: Json): Set<string> | null {
    const { log } = this.deps;
    log.debug("Entering NodeSnapshots.liveNamesOf().");
    if (!state || !state.available || !Array.isArray(state.nodes)) {
      log.debug("Leaving NodeSnapshots.liveNamesOf(). Unknown.");
      return null;
    }
    const now = Number(state.now) || 0;
    const names = new Set<string>();
    state.nodes.forEach(function (node: Json): void {
      if (!Number(node.leftAt) && Number(node.expiresAt) > now) {
        names.add(NodeSnapshots.displayName(node.name));
      }
    });
    log.debug("Leaving NodeSnapshots.liveNamesOf(). " + names.size);
    return names;
  }

  // The names cluster membership lists as live, or null when it cannot say.
  private async liveNames(): Promise<Set<string> | null> {
    const { log, cluster } = this.deps;
    log.debug("Entering NodeSnapshots.liveNames().");
    let state: Json = null;
    try {
      const c = cluster();
      state = (c.snapshot() || {}).state;
      if (!state) {
        state = await c.refreshState();
      }
    } catch (e) {
      log.debug("Caught in NodeSnapshots.liveNames(): " +
                ((e && e.message) || e));
      // Membership unknown: no node is called gone on a guess.
      state = null;
    }
    log.debug("Leaving NodeSnapshots.liveNames().");
    return this.liveNamesOf(state);
  }

  /**
   * Every node's section of one page: this node's from `selfView`, and every
   * other's from its row, each with its state and age.
   *
   * @param key - `workerPools` or `nodeHealth`
   * @param selfView - this node's live view
   * @returns a promise of `{ cluster, nodes }`
   */
  async read(key: string, selfView: Json): Promise<Json> {
    const { log, store, errorCodes } = this.deps;
    log.debug("Entering NodeSnapshots.read(). " + key);
    const selfName = this.selfName();
    const self = { name: selfName, self: true, state: 'live',
                   stateText: 'This node: its live figures, drawn now.',
                   ageSeconds: 0, takenAt: null, view: selfView };
    const why = this.whyNoCluster();
    const cluster: Json = { clustered: !why, text: why ||
                              'Every node of the cluster, by name. This ' +
                              'node\'s section is live; every other is its ' +
                              'latest snapshot, written every ' +
                              (INTERVAL_MS / 1000) + ' s, and stale past ' +
                              (STALE_MS / 1000) + ' s.',
                            intervalSeconds: INTERVAL_MS / 1000,
                            staleAfterSeconds: STALE_MS / 1000,
                            goneRemovedAfterHours: this.deps.retentionHours(),
                            readError: null };
    if (why) {
      log.debug("Leaving NodeSnapshots.read(). No cluster.");
      return { cluster: cluster, nodes: [self] };
    }
    let answer: Json = null;
    try {
      answer = await store().nodeSnapshots();
      this.failing.read = false;
    } catch (e) {
      log.debug("Caught in NodeSnapshots.read(): " +
                ((e && e.message) || e));
      if (!this.failing.read) {
        log.warn(errorCodes.tag('STS-CORE-0127') + 'node snapshots: the ' +
                 'other nodes\' snapshots could not be read: ' +
                 ((e && e.message) || e));
      }
      this.failing.read = true;
      cluster.readError = 'The other nodes\' snapshots could not be read ' +
        'from the shared store, so only this node is drawn (STS-CORE-0127).';
      log.debug("Leaving NodeSnapshots.read(). Read failed.");
      return { cluster: cluster, nodes: [self] };
    }
    const live = await this.liveNames();
    const now = Number(answer.now) || 0;
    const retention = this.deps.retentionHours() * 3600000;
    const seen = new Set<string>([selfName]);
    const others: Json[] = [];
    (answer.rows || []).forEach(function (row: Json): void {
      const name = NodeSnapshots.displayName(row.name);
      if (seen.has(name)) {
        return;
      }
      seen.add(name);
      const ageMs = Math.max(0, now - Number(row.takenAt || 0));
      const view = row.body && row.body[key] ? row.body[key] : null;
      let state: string;
      let stateText: string;
      if (live && !live.has(name)) {
        state = 'gone';
        const leftH = Math.max(0, retention - ageMs) / 3600000;
        stateText = 'Gone: cluster membership has no live node by this ' +
          'name. Its last snapshot is kept, ' + Math.round(ageMs / 1000) +
          ' s old, and removed after ' + (retention / 3600000) + ' h ' +
          'without a snapshot (cluster.nodeSnapshotRetentionHours) — ' +
          (leftH > 0 ? 'in about ' + (leftH >= 1 ? Math.ceil(leftH) + ' h'
                                                 : 'an hour')
                     : 'at the next hourly purge') + '.';
      } else if (ageMs > STALE_MS) {
        state = 'stale';
        stateText = 'Stale: its latest snapshot is ' +
          Math.round(ageMs / 1000) + ' s old, past ' + (STALE_MS / 1000) +
          ' s — the node is not writing it.';
      } else {
        state = 'live';
        stateText = 'Its snapshot, ' + Math.round(ageMs / 1000) + ' s old.';
      }
      if (!view) {
        stateText += ' It holds no view of this page.';
      } else if (view.unavailable) {
        stateText += ' Its view could not be built: ' +
          String(view.unavailable) + '.';
      }
      others.push({ name: name, self: false, state: state,
                    stateText: stateText,
                    ageSeconds: Math.round(ageMs / 1000),
                    takenAt: row.takenAt
                      ? new Date(Number(row.takenAt)).toISOString() : null,
                    view: view && !view.unavailable ? view : null });
    });
    if (live) {
      live.forEach(function (name: string): void {
        if (!seen.has(name)) {
          seen.add(name);
          others.push({ name: name, self: false, state: 'no-snapshot',
                        stateText: 'A live member that has written no ' +
                          'snapshot yet: its first comes within ' +
                          (INTERVAL_MS / 1000) + ' s of its start.',
                        ageSeconds: null, takenAt: null, view: null });
        }
      });
    }
    others.sort(function (a: Json, b: Json): number {
      return a.name < b.name ? -1 : a.name > b.name ? 1 : 0;
    });
    if (!live) {
      cluster.text += ' Cluster membership could not be read, so no node ' +
        'is marked gone.';
    }
    log.debug("Leaving NodeSnapshots.read(). " + (others.length + 1) +
              " node(s).");
    return { cluster: cluster, nodes: [self].concat(others) };
  }
}

const slot = new InstanceSlot<NodeSnapshots>(
  'cluster/node_snapshots',
  () => new NodeSnapshots(NodeSnapshots.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * Every cluster node on Monitoring → Worker Pools and → Node Health: the
 * per-process job that writes this node's snapshot, and the read of every
 * node's.
 * @namespace
 */
export = {
  NodeSnapshots: NodeSnapshots,
  INTERVAL_MS: INTERVAL_MS,
  STALE_MS: STALE_MS,
  JOB_ID: JOB_ID,
  PURGE_JOB_ID: PURGE_JOB_ID,
  /**
   * Installs the instance the composition root built; a second install is
   * refused.
   */
  installInstance: (instance: NodeSnapshots): void => slot.install(instance),
  /**
   * Says where the instance in use came from: `root`, `default` or `none`.
   */
  instanceOrigin: (): string => slot.origin(),
  provide: slot.forward('provide'),
  read: slot.forward('read'),
  write: slot.forward('write'),
  purge: slot.forward('purge'),
  selfName: slot.forward('selfName'),
  whyNoCluster: slot.forward('whyNoCluster'),
  scrub: NodeSnapshots.scrub,
  displayName: NodeSnapshots.displayName
};
