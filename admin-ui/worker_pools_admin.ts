// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: worker_pools_admin.ts
//
// ===========================================================================
// MONITORING → WORKER POOLS (#327, 2026-09-28): THE TWO POOLS OF WORKER
// THREADS THIS NODE RUNS, AND HOW WELL EACH IS DOING.
//
// **A WORKER IS A THREAD SINCE #364 (2026-09-30)**: a `worker_threads`
// Worker of the front process, where it was a forked process. So a worker is
// named by its `threadId` — every thread has the process's pid — and each
// row here says `threadId`, never `pid`. The pool's own counters keep the
// names they had (`forked`, a start of a worker); the page says "started".
//
// `GET /admin/worker-pools` draws one section per pool —
//
//   * the REQUEST pool (`common/request_pool.js`, `workers.requestCount`):
//     worker threads that run the whole protocol stack — one by default
//     where the store coordinates, none where it cannot
//     (`process_memory.requestWorkers()`, #364);
//   * the HOSTED-SURFACE pool (the same module, `workers.surfaceCount`): the
//     console's and the portal's own worker threads, the "admin" pool;
//
// There was a THIRD until #363 (2026-09-30): the post-quantum pool
// (`common/worker_pool.js`), processes forked to compute post-quantum
// signatures and scrypt off the main thread. It is gone — post-quantum
// operations run on node's own OpenSSL (`common/pq_native.js`) and scrypt is
// node's asynchronous `crypto.scrypt`, both on libuv's thread pool, which is
// not a pool of processes and has nothing of its own to draw here.
//
// and for each: the workers it has now, the most it may have and the number
// it started with, how many are busy and how many free, how many died unasked
// (and how many of those never started) against how many were stopped or
// retired, and the average time from dispatch to answer. rcbj asked for those
// seven figures on the ticket; everything else here is the sentence that
// makes one of them readable.
//
// **THE POOLS ARE THE MODULES' AND THIS FILE IS ONLY THE DRAWING.** Every
// figure is read from the pool's own `stats()` when the page is drawn —
// `common/CLAUDE.md` argues both pools, and the counters #327 added (what a
// pool had never counted: its crashes, its stops, its response times, its
// initial size) are in the pool beside what they count, not kept here.
//
// **A POOL THAT IS OFF SAYS SO IN WORDS.** The surface pool is off by
// default, and so is the request pool on a store that cannot coordinate; a
// row of zeros would read as a pool that is broken rather than one that is
// not there, so each pool carries a `state` and a sentence — which says
// WHICH off it is, since `workers.requestCount` at its default of 1 is none
// on the memory store.
//
// **EVERY NODE, BY NAME (#332, 2026-09-28).** In a cluster the page draws a
// section per node — this node's live, every other's from the snapshot its
// front process writes every fifteen seconds (`cluster/node_snapshots.ts`),
// stamped with its age and marked stale or gone rather than dropped — and the
// cluster's totals per pool above them. A node is named (`cluster.nodeName`),
// never addressed. `?node=<name>` narrows the page and the API to one node.
//
// **THE LIVE NUMBERS ARE THIS NODE'S.** Each node — each container of a
// cluster — has pools of its own, held by its front process, and the page
// says which node and which pid drew it. **AND IT IS ALWAYS THE FRONT
// PROCESS'S MAIN THREAD THAT DRAWS IT** (`mainThread` in the view): both
// paths are in `request_pool.js`'s `NEVER_DISPATCHED`, the debugger's
// arrangement, because a worker thread's copy of that module started nothing
// and would report every pool off on a service running eight workers.
// Nothing here is asked of a request worker since #363: the only pool a
// worker held of its own was the post-quantum one.
//
// **A SERVICE PAGE** (`admin_scope.ts`): the pools belong to the process, so
// a realm's own administrator is refused it. No control and no POST — the
// sizes are Global settings on `/admin/config`, and a pool is resized by
// them, or by a restart where the setting says so.
//
// Rule 7: `GET /admin-api/worker-pools` answers `workerPoolsView()`, the
// function the page's `?format=json` answers.
//
// TYPESCRIPT, AS A CLASS (#50): `mode_admin.ts`'s shape — dependencies
// through the constructor, `registerRoutes(app)` called by
// `common/protocol_stack.ts` (18r), facades for the JavaScript callers.
// ===========================================================================

import admin = require('./admin');
import helpers = require('../common/helpers');
import errorCodes = require('../common/error_codes');
import InstanceSlot = require('../common/instance_slot');
import nodeSnapshots = require('../cluster/node_snapshots');
import workerThreads = require('worker_threads');
import config = require('../common/config');

type Req = any;
type Res = any;
type Json = any;

/**
 * The console path of Monitoring → Worker Pools.
 */
const PAGE = '/admin/worker-pools';

interface WorkerPoolsAdminDeps {
  log: typeof helpers.log;
  admin: typeof admin;
  errorCodes: typeof errorCodes;
  // LAZY. `request_pool.js` pulls the keystore and the persistence layer in
  // at load, and `cluster/cluster.js` reaches it lazily for that reason; by
  // the time a page is drawn it is in node's module cache and this is a
  // lookup.
  requestPool: () => any;
  now: () => number;
  pid: number;
  // Whether this code runs in the process's main thread — the front process
  // that holds the pools — rather than a worker thread (#364).
  mainThread: boolean;
  // A setting's value and the layer it came from, for the sentence that says
  // which kind of off a pool is (#364).
  setting: (key: string) => { value: unknown; source: string };
  // This node's NAME, never its host or address (#332).
  nodeName: () => string;
  // Every other node's snapshot, and the job that writes this one's (#332).
  snapshots: () => typeof nodeSnapshots;
}

/**
 * Monitoring → Worker Pools: the request and hosted-surface pools of this
 * node, each with its workers now, its bounds, how many are
 * busy and free, its crashes and stops, and its response time.
 */
class WorkerPoolsAdmin {
  /**
   * See the module's `PAGE`.
   */
  static readonly PAGE = PAGE;

  /**
   * Builds an instance over the modules it depends on.
   *
   * @param deps - the logger, the console, and the request pool module
   */
  constructor(private readonly deps: WorkerPoolsAdminDeps) {
    deps.log.debug("Entering WorkerPoolsAdmin.constructor().");
    deps.log.debug("Leaving WorkerPoolsAdmin.constructor().");
  }

  /**
   * Answers the real modules the composition root passes to the constructor.
   *
   * @returns the dependencies of a default instance
   */
  static defaultDeps(): WorkerPoolsAdminDeps {
    helpers.log.debug("Entering WorkerPoolsAdmin.defaultDeps().");
    helpers.log.debug("Leaving WorkerPoolsAdmin.defaultDeps().");
    return {
      log: helpers.log,
      admin: admin,
      errorCodes: errorCodes,
      requestPool: function requestPool(): any {
        helpers.log.debug("Entering requestPool().");
        helpers.log.debug("Leaving requestPool().");
        return require('../common/request_pool');
      },
      now: Date.now,
      pid: process.pid,
      mainThread: workerThreads.isMainThread,
      setting: function setting(key: string): { value: unknown;
                                                source: string } {
        helpers.log.debug("Entering setting().");
        try {
          const answer = { value: config.value(key),
                           source: String(config.sourceOf(key)) };
          helpers.log.debug("Leaving setting().");
          return answer;
        } catch (e) {
          helpers.log.debug("Caught in setting(): " +
                            ((e && e.message) || e));
          // No configuration (a module loaded on its own): the sentence
          // falls back to the plain "is 0".
          helpers.log.debug("Leaving setting(). None.");
          return { value: null, source: '' };
        }
      },
      nodeName: function nodeName(): string {
        helpers.log.debug("Entering nodeName().");
        helpers.log.debug("Leaving nodeName().");
        return nodeSnapshots.selfName();
      },
      snapshots: function snapshots(): typeof nodeSnapshots {
        helpers.log.debug("Entering snapshots().");
        helpers.log.debug("Leaving snapshots().");
        return nodeSnapshots;
      }
    };
  }

  // Seconds since `at`, or null for a time never set.
  private since(at: number, now: number): number | null {
    const { log } = this.deps;
    log.debug("Entering WorkerPoolsAdmin.since().");
    log.debug("Leaving WorkerPoolsAdmin.since().");
    return at > 0 ? Math.max(0, Math.round((now - at) / 1000)) : null;
  }

  // One of the two request pools, from `request_pool.stats()`.
  /**
   * Builds one request pool's section: the protocol pool or the hosted-surface
   * pool, from `request_pool.js`'s `stats()`.
   *
   * @param stats - `request_pool.stats()`
   * @param which - `protocol` or `surfaces`
   * @param now - the current time in milliseconds
   * @returns the pool's view
   */
  requestPoolView(stats: Json, which: string, now: number): Json {
    const { log, requestPool } = this.deps;
    const self = this;
    log.debug("Entering WorkerPoolsAdmin.requestPoolView(). " + which);
    const surface = which === 'surfaces';
    const pool = (stats.pools || []).filter(function (one: Json): boolean {
      return one.pool === which;
    })[0] || {};
    const h = pool.history || {};
    const setting = surface ? 'workers.surfaceCount' : 'workers.requestCount';
    const configured = Number(pool.configured) || 0;
    const running = Number(pool.running) || 0;
    const ready = Number(pool.ready) || 0;
    const dispatching = (stats.dispatch || []).length > 0;
    let state: string;
    let stateText: string;
    if (!configured && !running) {
      state = 'off';
      // WHICH OFF (#364): `workers.requestCount` defaults to 1, and that
      // default means none where the store cannot coordinate
      // (`process_memory.requestWorkers()`), so "is 0" would be untrue.
      const count = surface ? { value: 0, source: '' }
                            : this.deps.setting(setting);
      const byDefault = /^defaults?$/.test(count.source) &&
        Number(count.value) > 0;
      stateText = surface
        ? 'Off: ' + setting + ' is 0, so /admin and /portal go wherever the ' +
          'rest of workers.dispatch goes — to the request pool, or answered ' +
          'here by the front process.'
        : byDefault
          ? 'Off: ' + setting + ' is at its default of ' + count.value +
            ', which means none where the store cannot coordinate ' +
            '(persistence.mode is not postgres, or persistence.coordinate ' +
            'is off), so every request is answered by the front process ' +
            'itself, on one thread.'
          : 'Off: ' + setting + ' is 0, so every request is answered by the ' +
            'front process itself, on one thread.';
    } else if (pool.gaveUp) {
      state = 'given-up';
      stateText = 'Given up: ' + (h.failedStarts || 0) + ' worker ' +
        'thread(s) failed to start and the pool stopped starting them ' +
        '(STS-WORKER-0023). ' +
        (surface ? 'The hosted surfaces go to the request pool.'
                 : 'Every request is answered by the front process.');
    } else if (!h.initial && !running) {
      let why = '';
      if (surface) {
        try {
          const problem = requestPool().surfacePoolProblem();
          why = problem ? ' ' + String(problem.message) : '';
        } catch (e) {
          log.debug("Caught in WorkerPoolsAdmin.requestPoolView(): " +
                    ((e && e.message) || e));
          // The reason is a courtesy; the state is said without it.
          why = '';
        }
      }
      state = 'not-started';
      stateText = 'Not started: ' + setting + ' is ' + configured + ', and ' +
        'this process started no worker thread — it was not started as the ' +
        'front process of a service, or the pool was idled at start.' + why;
    } else if (!dispatching) {
      state = 'not-dispatching';
      stateText = 'Running, and idle by configuration: workers.dispatch ' +
        'names nothing, so no request is sent to these worker threads.';
    } else {
      state = 'running';
      stateText = ready + ' of ' + configured + ' worker thread(s) serving.';
    }
    const workers = (stats.workers || []).filter(function (one: Json):
      boolean {
      return (one.pool || 'protocol') === which;
    }).map(function (one: Json): Json {
      // `pid` in the pool's table is the thread's id since #364.
      return { threadId: one.pid,
               slot: one.slot === undefined ? null : one.slot,
               ready: !!one.ready, busy: one.inFlight > 0,
               inFlight: one.inFlight, served: one.served,
               retiring: !!one.retiring,
               upSeconds: self.since(Number(one.startedAt) || 0, now) };
    });
    const view = {
      id: surface ? 'surface' : 'request',
      title: surface ? 'Hosted-surface pool (/admin and /portal)'
                     : 'Request pool',
      module: 'common/request_pool.js',
      setting: setting,
      state: state,
      stateText: stateText,
      maxWorkers: configured,
      initialWorkers: Number(h.initial) || 0,
      currentWorkers: running,
      readyWorkers: ready,
      startingWorkers: Math.max(0, running - ready),
      busyWorkers: Number(pool.busy) || 0,
      freeWorkers: Number(pool.free) || 0,
      restarts: {
        forked: Number(h.forked) || 0,
        replaced: Number(pool.replaced) || 0,
        crashed: Number(h.crashed) || 0,
        failedStarts: Number(h.failedStarts) || 0,
        stopped: Number(h.stoppedExits) || 0
      },
      responseTime: {
        answered: Number(h.answered) || 0,
        averageMs: pool.averageMs === undefined ? null : pool.averageMs,
        recentAverageMs: pool.recentAverageMs === undefined
          ? null : pool.recentAverageMs,
        maxMs: h.answered ? Number(h.maxAnswerMs) || 0 : null
      },
      startedAt: h.startedAt ? new Date(h.startedAt).toISOString() : null,
      prefixes: pool.prefixes || [],
      workers: workers
    };
    log.debug("Leaving WorkerPoolsAdmin.requestPoolView(). " + state);
    return view;
  }

  // This node's own view: what the page drew before #332, and what its
  // snapshot carries to the other nodes.
  /**
   * Answers this node's two pools, asked of the pool module when called.
   * A promise still, because the snapshot job (#332) awaits whatever a page
   * provides.
   *
   * @returns a promise of the view
   */
  localView(): Promise<Json> {
    const { log, requestPool, now, pid, mainThread, nodeName } = this.deps;
    log.debug("Entering WorkerPoolsAdmin.localView().");
    const node = nodeName();
    const stats = requestPool().stats();
    const at = now();
    const view = {
      generatedAt: new Date(at).toISOString(),
      node: node,
      pid: pid,
      mainThread: mainThread,
      scope: 'node',
      scopeText: 'These are the pools of the node ' + node + ', held ' +
        'by its front process, pid ' + pid + '. Each worker is a thread of ' +
        'that process (#364), named by its thread id, with a V8 heap of its ' +
        'own and the process\'s memory and CPU. Every node of a cluster ' +
        'has pools of its own. Post-quantum signing and scrypt have had no ' +
        'pool of processes since #363: they run on libuv\'s thread pool, ' +
        'inside whichever process asked.',
      pools: [
        this.requestPoolView(stats, 'protocol', at),
        this.requestPoolView(stats, 'surfaces', at)
      ]
    };
    log.debug("Leaving WorkerPoolsAdmin.localView().");
    return Promise.resolve(view);
  }

  /**
   * The cluster's totals per pool, over the nodes that are not gone and
   * have a view: current, busy and free workers, forks, crashes and failed
   * starts.
   *
   * @param nodes - the node sections
   * @returns the totals
   */
  static totalsOf(nodes: Json[]): Json {
    helpers.log.debug("Entering WorkerPoolsAdmin.totalsOf().");
    const counted = nodes.filter(function (n: Json): boolean {
      return n.state !== 'gone' && !!n.view && Array.isArray(n.view.pools);
    });
    const pools: Json = {};
    counted.forEach(function (n: Json): void {
      n.view.pools.forEach(function (p: Json): void {
        const t = pools[p.id] || (pools[p.id] = {
          id: p.id, title: p.title, currentWorkers: 0, busyWorkers: 0,
          freeWorkers: 0, forked: 0, crashed: 0, failedStarts: 0,
          nodesOn: 0 });
        const r = p.restarts || {};
        t.currentWorkers += Number(p.currentWorkers) || 0;
        t.busyWorkers += Number(p.busyWorkers) || 0;
        t.freeWorkers += Number(p.freeWorkers) || 0;
        t.forked += Number(r.forked) || 0;
        t.crashed += Number(r.crashed) || 0;
        t.failedStarts += Number(r.failedStarts) || 0;
        if (p.state !== 'off') {
          t.nodesOn++;
        }
      });
    });
    helpers.log.debug("Leaving WorkerPoolsAdmin.totalsOf().");
    return {
      nodes: nodes.length,
      nodesCounted: counted.length,
      pools: Object.keys(pools).map(function (id: string): Json {
        return pools[id];
      }),
      text: 'Over the ' + counted.length + ' node(s) that are not gone ' +
        'and have a snapshot, stale ones included and marked.'
    };
  }

  // The page's JSON, and the management API's answer.
  /**
   * Answers the page's JSON and `GET /admin-api/worker-pools`: this node's
   * live pools at the top, and a section per cluster node with the
   * cluster's totals (#332). With `node`, the answer is about that node.
   *
   * @param opts - `{ node }` to narrow to one node by name
   * @returns a promise of the view, or `{ notFound }` for an unknown name
   */
  async workerPoolsView(opts?: { node?: string }): Promise<Json> {
    const { log, now, pid, snapshots } = this.deps;
    log.debug("Entering WorkerPoolsAdmin.workerPoolsView().");
    const local = await this.localView();
    const read = await snapshots().read('workerPools', local);
    const want = opts && opts.node ? String(opts.node) : '';
    let nodes = read.nodes;
    let subject: Json = local;
    if (want) {
      const hit = nodes.filter(function (n: Json): boolean {
        return n.name === want;
      })[0];
      if (!hit) {
        log.debug("Leaving WorkerPoolsAdmin.workerPoolsView(). No such " +
                  "node.");
        return { notFound: want, nodeNames: nodes.map(function (n: Json):
          string {
          return n.name;
        }) };
      }
      nodes = [hit];
      subject = hit.view || { node: hit.name, pools: [] };
    }
    const answer = Object.assign({}, subject, {
      generatedAt: new Date(now()).toISOString(),
      answeredBy: { node: local.node, pid: pid },
      state: nodes.length === 1 && want ? nodes[0].state : 'live',
      cluster: read.cluster,
      nodes: nodes,
      totals: WorkerPoolsAdmin.totalsOf(nodes)
    });
    log.debug("Leaving WorkerPoolsAdmin.workerPoolsView(). " + nodes.length +
              " node(s).");
    return snapshots().scrub(answer);
  }

  // The page for every node: the cluster's totals and a section per node.
  private clusterHtml(json: Json): string {
    const { log, admin } = this.deps;
    const self = this;
    log.debug("Entering WorkerPoolsAdmin.clusterHtml().");
    const c = json.cluster || {};
    const nodes: Json[] = json.nodes || [];
    const own = nodes.filter(function (n: Json): boolean {
      return n.self;
    })[0];
    if (!c.clustered || nodes.length < 2) {
      const first = own || nodes[0];
      const html = admin.note(admin.esc(c.text || ''), 'Cluster') +
        (c.readError ? admin.warn(admin.esc(c.readError)) : '') +
        (first && first.view && first.view.pools ? this.html(first.view)
                                                 : '');
      log.debug("Leaving WorkerPoolsAdmin.clusterHtml(). One node.");
      return html;
    }
    const t = json.totals;
    const html = '<h2 id="cluster">Cluster</h2><p>' + admin.esc(c.text) +
      '</p>' + (c.readError ? admin.warn(admin.esc(c.readError)) : '') +
      '<table class="grid"><thead><tr><th>Pool</th><th>Worker threads</th>' +
      '<th>Busy</th><th>Free</th><th>Started</th><th>Crashed</th>' +
      '<th>Nodes on</th></tr></thead><tbody>' +
      t.pools.map(function (p: Json): string {
        return '<tr><td>' + admin.esc(p.title) + '</td><td>' +
          admin.esc(p.currentWorkers) + '</td><td>' +
          admin.esc(p.busyWorkers) + '</td><td>' +
          admin.esc(p.freeWorkers) + '</td><td>' + admin.esc(p.forked) +
          '</td><td>' + admin.esc(p.crashed) +
          (p.failedStarts ? ' (' + admin.esc(p.failedStarts) + ' never ' +
                            'started)' : '') + '</td><td>' +
          admin.esc(p.nodesOn) + '</td></tr>';
      }).join('') + '</tbody></table><p><small>' + admin.esc(t.text) +
      '</small></p>' +
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
        if (!n.view || !Array.isArray(n.view.pools)) {
          return head;
        }
        let body = '';
        try {
          body = self.html(n.view);
        } catch (e) {
          log.debug("Caught in WorkerPoolsAdmin.clusterHtml(): " +
                    ((e && e.message) || e));
          // A snapshot from another version of this page may lack a figure
          // this one draws; the node is still listed, and says so.
          return head + admin.warn('This node\'s snapshot could not be ' +
                                   'drawn: ' + admin.esc((e && e.message) ||
                                                         e) + '.');
        }
        // Another node's sections carry its name in their anchors, so the
        // page's own `id="pool-request"` and the rest stay this node's.
        return head + (n.self ? body
          : body.replace(/ id="/g, ' id="' + admin.esc(n.name) + '-'));
      }).join('');
    log.debug("Leaving WorkerPoolsAdmin.clusterHtml().");
    return html;
  }

  // A figure, or a dash for one that does not exist yet.
  private ms(value: unknown): string {
    const { log } = this.deps;
    log.debug("Entering WorkerPoolsAdmin.ms().");
    log.debug("Leaving WorkerPoolsAdmin.ms().");
    return value === null || value === undefined ? '—' : value + ' ms';
  }

  // The seven figures of one pool, as a table of two columns.
  private figures(p: Json): string {
    const { log, admin } = this.deps;
    log.debug("Entering WorkerPoolsAdmin.figures().");
    const r = p.restarts;
    const t = p.responseTime;
    const row = function (label: string, value: string, why: string):
      string {
      log.debug("Entering row().");
      log.debug("Leaving row().");
      return '<tr><th>' + admin.esc(label) + '</th><td>' + value +
        '</td><td><small>' + why + '</small></td></tr>';
    };
    const html = '<table class="grid"><tbody>' +
      row('Current workers', admin.esc(p.currentWorkers),
          'worker threads started now, ' + admin.esc(p.readyWorkers) +
          ' of them ready') +
      row('Busy', admin.esc(p.busyWorkers), 'with a request in flight') +
      row('Free', admin.esc(p.freeWorkers), 'ready and idle') +
      row('Maximum workers', admin.esc(p.maxWorkers),
          '<code>' + admin.esc(p.setting) + '</code>') +
      row('Initial workers', admin.esc(p.initialWorkers),
          'what the pool was started with') +
      row('Restarts and crashes',
          admin.esc(r.crashed) + ' crashed' +
          (r.failedStarts ? ' (' + admin.esc(r.failedStarts) + ' never ' +
                            'started)' : '') + ', ' +
          admin.esc(r.replaced) + ' replaced, ' +
          admin.esc(r.stopped) + ' stopped',
          admin.esc(r.forked) + ' started in all; a crash is an exit ' +
          'nobody asked for') +
      row('Average response time',
          this.ms(t.averageMs) + ' (recent ' +
            this.ms(t.recentAverageMs) + ')',
          admin.esc(t.answered) + ' answered, dispatch to answer; ' +
          'worst ' + this.ms(t.maxMs)) +
      '</tbody></table>';
    log.debug("Leaving WorkerPoolsAdmin.figures().");
    return html;
  }

  private html(json: Json): string {
    const { log, admin } = this.deps;
    const self = this;
    log.debug("Entering WorkerPoolsAdmin.html().");
    const tiles = '<div class="tiles">' +
      json.pools.map(function (p: Json): string {
        return admin.tile(p.state === 'off' ? 'off'
                                            : String(p.currentWorkers),
                          p.title);
      }).join('') + '</div>';
    const about = admin.note(
      '<p>' + admin.esc(json.scopeText) + '</p><p>Every figure is read from ' +
      'the pool\'s own module when the page is drawn, and counts from when ' +
      'this process started. The sizes are Global settings on ' +
      '<a href="/admin/config">Configuration</a>; this page changes ' +
      'nothing.</p>', 'What this page is');
    const sections = json.pools.map(function (p: Json): string {
      const head = '<h2 id="pool-' + admin.esc(p.id) + '">' +
        admin.esc(p.title) + '</h2><p><code>' + admin.esc(p.module) +
        '</code> · <code>' + admin.esc(p.setting) + '</code> · <strong>' +
        admin.esc(p.state) + '</strong>: ' + admin.esc(p.stateText) + '</p>';
      if (p.state === 'off') {
        return head;
      }
      let detail = '';
      if (p.workers.length) {
        detail = '<h3>Worker threads</h3><table class="grid"><thead><tr>' +
          '<th>Thread</th><th>Slot</th><th>State</th><th>In flight</th>' +
          '<th>Served</th><th>Up</th></tr></thead><tbody>' +
          p.workers.map(function (w: Json): string {
            return '<tr><td>' + admin.esc(w.threadId) + '</td><td>' +
              admin.esc(w.slot === null ? '—' : w.slot) + '</td><td>' +
              (w.retiring ? 'stopping' : !w.ready ? 'starting'
                                       : w.busy ? 'busy' : 'free') +
              '</td><td>' + admin.esc(w.inFlight) + '</td><td>' +
              admin.esc(w.served) + '</td><td>' +
              (w.upSeconds === null ? '—' : admin.esc(w.upSeconds) + ' s') +
              '</td></tr>';
          }).join('') + '</tbody></table>';
      }
      return head + self.figures(p) + detail;
    }).join('');
    log.debug("Leaving WorkerPoolsAdmin.html().");
    return tiles + about + sections;
  }

  /**
   * Registers `GET /admin/worker-pools`.
   *
   * @param app - the shared express app
   */
  registerRoutes(app: { get: Function }): void {
    const { log, admin, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering WorkerPoolsAdmin.registerRoutes().");
    // THIS NODE'S VIEW FOR THE OTHER NODES (#332): the job that writes it
    // is registered by the hand-over, in every process that loads the page.
    this.deps.snapshots().provide('workerPools', function (): Promise<Json> {
      return self.localView();
    });
    app.get(PAGE, function (req: Req, res: Res): void {
      log.debug('Entering GET ' + PAGE + '.');
      self.workerPoolsView({ node: req.query && req.query.node
                                     ? String(req.query.node) : '' })
        .then(function (json: Json): void {
          if (json.notFound) {
            errorCodes.mark(res, 'STS-CORE-0126');
            res.status(404).type('text/plain')
              .send('There is no node named ' + json.notFound + '.');
            return;
          }
          admin.respond(req, res, json, 'Worker pools', PAGE,
                        admin.messagesOf(req) + self.clusterHtml(json));
        }).catch(function (e: any): void {
        log.debug("Caught in GET " + PAGE + ": " + ((e && e.message) || e));
        log.error(errorCodes.tag('STS-WORKER-0044') + 'The worker pools ' +
                  'report could not be built: ' + ((e && e.message) || e));
        errorCodes.mark(res, 'STS-WORKER-0044');
        res.status(500).type('text/plain')
          .send('The worker pools report could not be built.');
      });
      log.debug('Leaving GET ' + PAGE + '.');
    });
    log.debug("Leaving WorkerPoolsAdmin.registerRoutes().");
  }
}

const slot = new InstanceSlot<WorkerPoolsAdmin>(
  'admin-ui/worker_pools_admin',
  () => new WorkerPoolsAdmin(WorkerPoolsAdmin.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * Monitoring → Worker Pools, `/admin/worker-pools`: the request and
 * hosted-surface pools of this node. A service page with
 * no control and no POST.
 * @namespace
 */
export = {
  registerRoutes: slot.forward('registerRoutes'),
  WorkerPoolsAdmin: WorkerPoolsAdmin,
  /**
   * Installs the instance the composition root built and runs its
   * wire step; a second install is refused.
   */
  installInstance: (instance: WorkerPoolsAdmin): void =>
    slot.install(instance),
  /**
   * Says where the instance in use came from: `root`, `default` or
   * `none`.
   */
  instanceOrigin: (): string => slot.origin(),
  PAGE: PAGE,
  // For `mgmt-api/admin_api.ts` (rule 7).
  workerPoolsView: slot.forward('workerPoolsView')
};
