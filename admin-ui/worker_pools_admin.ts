// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: worker_pools_admin.ts
//
// ===========================================================================
// MONITORING → WORKER POOLS (#327, 2026-09-28): THE THREE POOLS OF CHILD
// PROCESSES THIS NODE RUNS, AND HOW WELL EACH IS DOING.
//
// `GET /admin/worker-pools` draws one section per pool —
//
//   * the REQUEST pool (`common/request_pool.js`, `workers.requestCount`):
//     workers that run the whole protocol stack;
//   * the HOSTED-SURFACE pool (the same module, `workers.surfaceCount`): the
//     console's and the portal's own workers, the "admin" pool;
//   * the POST-QUANTUM pool (`common/worker_pool.js`, `workers.count`): the
//     job table — post-quantum signing and verification, key generation,
//     scrypt — forked lazily on the first such job;
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
// **A POOL THAT IS OFF SAYS SO IN WORDS.** Both request pools are off by
// default and the post-quantum pool forks nothing until its first job; a row
// of zeros would read as a pool that is broken rather than one that is not
// there, so each pool carries a `state` and a sentence.
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
// says which node and which pid drew it. **AND IT IS ALWAYS THE FRONT PROCESS THAT DRAWS
// IT**: both paths are in `request_pool.js`'s `NEVER_DISPATCHED`, the
// debugger's arrangement, because a request worker's copy of that module
// forked nothing and would report every pool off on a service running eight
// workers. The post-quantum pool is the one that is NOT the front process's
// alone: every request worker has one of its own (it loads `common/crypto.js`
// like any process), so the front process asks each ready worker for its
// `worker_pool.stats()` over the channel (`askWorkerPoolStatus()`, bounded)
// and the section has a row per process and a total.
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

type Req = any;
type Res = any;
type Json = any;

/**
 * The console path of Monitoring → Worker Pools.
 */
const PAGE = '/admin/worker-pools';

// How long the page waits for the request workers to say what their own
// post-quantum pools are doing. A worker that is not answering in a second is
// drawn as not having answered; see `askWorkerPoolStatus()`.
const ASK_WORKERS_MS = 1000;

interface WorkerPoolsAdminDeps {
  log: typeof helpers.log;
  admin: typeof admin;
  errorCodes: typeof errorCodes;
  // LAZY, both of them. `request_pool.js` pulls the keystore and the
  // persistence layer in at load, and `cluster/cluster.js` reaches it lazily
  // for that reason; by the time a page is drawn both pools are in node's
  // module cache and this is a lookup.
  requestPool: () => any;
  workerPool: () => any;
  now: () => number;
  pid: number;
  // This node's NAME, never its host or address (#332).
  nodeName: () => string;
  // Every other node's snapshot, and the job that writes this one's (#332).
  snapshots: () => typeof nodeSnapshots;
}

/**
 * Monitoring → Worker Pools: the request, hosted-surface and post-quantum
 * pools of this node, each with its workers now, its bounds, how many are
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
   * @param deps - the logger, the console, and the two pool modules
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
      workerPool: function workerPool(): any {
        helpers.log.debug("Entering workerPool().");
        helpers.log.debug("Leaving workerPool().");
        return require('../common/worker_pool');
      },
      now: Date.now,
      pid: process.pid,
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
      stateText = surface
        ? 'Off: ' + setting + ' is 0, so /admin and /portal go wherever the ' +
          'rest of workers.dispatch goes — to the request pool, or answered ' +
          'here by the front process.'
        : 'Off: ' + setting + ' is 0, so every request is answered by the ' +
          'front process itself, on one thread.';
    } else if (pool.gaveUp) {
      state = 'given-up';
      stateText = 'Given up: ' + (h.failedStarts || 0) + ' worker(s) failed ' +
        'to start and the pool stopped forking them (STS-WORKER-0023). ' +
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
        'this process forked none — it was not started as the front ' +
        'process of a service, or the pool was idled at start.' + why;
    } else if (!dispatching) {
      state = 'not-dispatching';
      stateText = 'Running, and idle by configuration: workers.dispatch ' +
        'names nothing, so no request is sent to these workers.';
    } else {
      state = 'running';
      stateText = ready + ' of ' + configured + ' worker(s) serving.';
    }
    const workers = (stats.workers || []).filter(function (one: Json):
      boolean {
      return (one.pool || 'protocol') === which;
    }).map(function (one: Json): Json {
      return { pid: one.pid, slot: one.slot === undefined ? null : one.slot,
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

  // One process's post-quantum pool, from its `worker_pool.stats()`.
  /**
   * Builds one process's row of the post-quantum pool.
   *
   * @param pq - that process's `worker_pool.stats()`
   * @param pid - the process
   * @param role - `front process` or the request pool it is a worker of
   * @returns the row
   */
  pqProcessView(pq: Json, pid: number, role: string): Json {
    const { log } = this.deps;
    log.debug("Entering WorkerPoolsAdmin.pqProcessView(). " + pid);
    const c = pq.counts || {};
    const configured = Number(pq.configured) || 0;
    const running = Number(pq.running) || 0;
    let state: string;
    let stateText: string;
    if (pq.gaveUp) {
      state = 'given-up';
      stateText = 'Given up (STS-WORKER-0003): jobs are computed in this ' +
        'process.';
    } else if (!configured && !running) {
      state = 'off';
      // A request or surface worker's pool is sized by its own setting
      // (#347), which `stats().setting` names.
      stateText = 'Off: ' + String(pq.setting || 'workers.count') +
        ' is 0, so every job is computed in this process.';
    } else if (!running && !c.forked) {
      state = 'not-forked';
      stateText = 'Not forked yet: the pool forks on the first ' +
        'post-quantum job, and this process has had none.';
    } else {
      state = 'running';
      stateText = running + ' of ' + configured + ' worker(s).';
    }
    const row = {
      pid: pid,
      role: role,
      state: state,
      stateText: stateText,
      maxWorkers: configured,
      initialWorkers: Number(c.firstForked) || 0,
      firstForkAt: c.firstForkAt ? new Date(c.firstForkAt).toISOString()
                                 : null,
      currentWorkers: running,
      busyWorkers: Number(pq.busy) || 0,
      freeWorkers: Number(pq.free) || 0,
      restarts: {
        forked: Number(c.forked) || 0,
        crashed: Number(c.crashed) || 0,
        failedStarts: Number(c.failedStarts) || 0,
        retired: Number(c.retired) || 0
      },
      responseTime: {
        jobs: Number(c.jobs) || 0,
        averageMs: pq.averageJobMs === undefined ? null : pq.averageJobMs,
        maxMs: c.jobs ? Number(c.maxJobMs) || 0 : null,
        failed: Number(c.failed) || 0,
        timedOut: Number(c.timedOut) || 0,
        inProcessJobs: Number(c.inProcess) || 0
      }
    };
    log.debug("Leaving WorkerPoolsAdmin.pqProcessView(). " + state);
    return row;
  }

  // The post-quantum pool: a row per process and their total.
  /**
   * Builds the post-quantum pool's section from the front process's own
   * `worker_pool.stats()` and each request worker's answer.
   *
   * @param own - this process's `worker_pool.stats()`
   * @param answers - `{ [pid]: { pq, error } }` from the request workers
   * @param asked - the request workers asked, `{ pid, pool }`
   * @returns the pool's view
   */
  pqPoolView(own: Json, answers: Json, asked: Json[]): Json {
    const { log, pid } = this.deps;
    const self = this;
    log.debug("Entering WorkerPoolsAdmin.pqPoolView().");
    const processes = [this.pqProcessView(own, pid, 'front process')];
    const unanswered: Json[] = [];
    asked.forEach(function (one: Json): void {
      const answer = answers[one.pid];
      if (answer && answer.pq) {
        processes.push(self.pqProcessView(answer.pq, one.pid,
                                          one.pool + ' worker'));
      } else {
        unanswered.push({ pid: one.pid, pool: one.pool,
                          why: answer && answer.error
                            ? String(answer.error)
                            : 'did not answer within ' + ASK_WORKERS_MS +
                              'ms' });
      }
    });
    const sum = function (pick: (row: Json) => number): number {
      log.debug("Entering sum().");
      log.debug("Leaving sum().");
      return processes.reduce(function (n: number, row: Json): number {
        return n + (pick(row) || 0);
      }, 0);
    };
    const jobs = sum(function (r: Json): number {
      return r.responseTime.jobs;
    });
    const jobMs = sum(function (r: Json): number {
      return (r.responseTime.averageMs || 0) * r.responseTime.jobs;
    });
    const anyForked = processes.some(function (r: Json): boolean {
      return r.state === 'running' || r.restarts.forked > 0;
    });
    const allOff = processes.every(function (r: Json): boolean {
      return r.state === 'off';
    });
    const front = processes[0];
    let state: string;
    let stateText: string;
    if (allOff) {
      state = 'off';
      stateText = front.stateText;
    } else if (!anyForked) {
      state = 'not-forked';
      stateText = 'Not forked yet: each process forks its pool on its ' +
        'first post-quantum job, and ' + (processes.length === 1
          ? 'this process has' : 'none of these ' + processes.length +
            ' processes has') + ' had one.';
    } else {
      state = 'running';
      stateText = processes.filter(function (r: Json): boolean {
        return r.currentWorkers > 0;
      }).length + ' of ' + processes.length + ' process(es) holding ' +
        'workers.';
    }
    const view = {
      id: 'post-quantum',
      title: 'Post-quantum pool',
      module: 'common/worker_pool.js',
      // Two settings size it (#347): `workers.count` in the front process,
      // `workers.countInRequestWorkers` in each request or surface worker.
      setting: 'workers.count, workers.countInRequestWorkers',
      state: state,
      stateText: stateText,
      perProcess: true,
      // The most any ONE process may fork; each process has its own pool.
      maxWorkers: front.maxWorkers,
      initialWorkers: front.initialWorkers,
      currentWorkers: sum(function (r: Json): number {
        return r.currentWorkers;
      }),
      busyWorkers: sum(function (r: Json): number {
        return r.busyWorkers;
      }),
      freeWorkers: sum(function (r: Json): number {
        return r.freeWorkers;
      }),
      restarts: {
        forked: sum(function (r: Json): number {
          return r.restarts.forked;
        }),
        crashed: sum(function (r: Json): number {
          return r.restarts.crashed;
        }),
        failedStarts: sum(function (r: Json): number {
          return r.restarts.failedStarts;
        }),
        retired: sum(function (r: Json): number {
          return r.restarts.retired;
        })
      },
      responseTime: {
        jobs: jobs,
        averageMs: jobs ? Math.round(jobMs / jobs) : null,
        maxMs: jobs ? Math.max.apply(null, processes.map(function (r: Json):
          number {
          return r.responseTime.maxMs || 0;
        })) : null,
        failed: sum(function (r: Json): number {
          return r.responseTime.failed;
        }),
        timedOut: sum(function (r: Json): number {
          return r.responseTime.timedOut;
        }),
        inProcessJobs: sum(function (r: Json): number {
          return r.responseTime.inProcessJobs;
        })
      },
      processes: processes,
      unanswered: unanswered
    };
    log.debug("Leaving WorkerPoolsAdmin.pqPoolView(). " + state);
    return view;
  }

  // This node's own view: what the page drew before #332, and what its
  // snapshot carries to the other nodes.
  /**
   * Answers this node's three pools, asked of the pools when called.
   *
   * @returns a promise of the view
   */
  localView(): Promise<Json> {
    const { log, requestPool, workerPool, now, pid, nodeName } = this.deps;
    const self = this;
    log.debug("Entering WorkerPoolsAdmin.localView().");
    const node = nodeName();
    const pool = requestPool();
    const stats = pool.stats();
    const asked = (stats.workers || []).filter(function (one: Json):
      boolean {
      return one.ready;
    }).map(function (one: Json): Json {
      return { pid: one.pid, pool: one.pool || 'protocol' };
    });
    const ask = asked.length ? pool.askWorkerPoolStatus(ASK_WORKERS_MS)
                             : Promise.resolve({});
    log.debug("Leaving WorkerPoolsAdmin.localView(). Asked " +
              asked.length + " worker(s).");
    return ask.then(function (answers: Json): Json {
      const at = now();
      return {
        generatedAt: new Date(at).toISOString(),
        node: node,
        pid: pid,
        scope: 'node',
        scopeText: 'These are the pools of the node ' + node + ', held ' +
          'by its front process, pid ' + pid + '. Every ' +
          'node of a cluster has pools of its own, and a request worker ' +
          'has a post-quantum pool of its own too, which is why that ' +
          'section has a row per process.',
        pools: [
          self.requestPoolView(stats, 'protocol', at),
          self.requestPoolView(stats, 'surfaces', at),
          self.pqPoolView(workerPool().stats(), answers || {}, asked)
        ]
      };
    });
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
      '<table class="grid"><thead><tr><th>Pool</th><th>Workers</th>' +
      '<th>Busy</th><th>Free</th><th>Forked</th><th>Crashed</th>' +
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
  private figures(p: Json, pq: boolean): string {
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
          pq ? 'forked now, across every process below'
             : 'forked now, ' + admin.esc(p.readyWorkers) + ' of them ' +
               'ready') +
      row('Busy', admin.esc(p.busyWorkers),
          'with ' + (pq ? 'a job' : 'a request') + ' in flight') +
      row('Free', admin.esc(p.freeWorkers),
          pq ? 'forked and idle' : 'ready and idle') +
      row('Maximum workers', admin.esc(p.maxWorkers),
          '<code>' + admin.esc(p.setting) + '</code>' +
          (pq ? ', per process' : '')) +
      row('Initial workers', admin.esc(p.initialWorkers),
          pq ? 'what the front process\'s first fork brought up (the pool ' +
               'is lazy)'
             : 'what the pool was started with') +
      row('Restarts and crashes',
          admin.esc(r.crashed) + ' crashed' +
          (r.failedStarts ? ' (' + admin.esc(r.failedStarts) + ' never ' +
                            'started)' : '') + ', ' +
          (pq ? admin.esc(r.retired) + ' retired'
              : admin.esc(r.replaced) + ' replaced, ' +
                admin.esc(r.stopped) + ' stopped'),
          admin.esc(r.forked) + ' forked in all; a crash is an exit ' +
          'nobody asked for' + (pq ? ', and the next job forks the ' +
          'replacement' : '')) +
      row('Average response time',
          this.ms(t.averageMs) + (pq ? '' : ' (recent ' +
            this.ms(t.recentAverageMs) + ')'),
          pq ? admin.esc(t.jobs) + ' job(s), send to reply; worst ' +
               this.ms(t.maxMs) + '; ' + admin.esc(t.failed) + ' failed, ' +
               admin.esc(t.timedOut) + ' timed out, ' +
               admin.esc(t.inProcessJobs) + ' computed in process'
             : admin.esc(t.answered) + ' answered, dispatch to answer; ' +
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
      const pq = p.id === 'post-quantum';
      const head = '<h2 id="pool-' + admin.esc(p.id) + '">' +
        admin.esc(p.title) + '</h2><p><code>' + admin.esc(p.module) +
        '</code> · <code>' + admin.esc(p.setting) + '</code> · <strong>' +
        admin.esc(p.state) + '</strong>: ' + admin.esc(p.stateText) + '</p>';
      if (p.state === 'off') {
        return head;
      }
      let detail = '';
      if (pq) {
        detail = '<h3>By process</h3><table class="grid"><thead><tr>' +
          '<th>Process</th><th>State</th><th>Workers</th><th>Busy</th>' +
          '<th>Free</th><th>Crashed</th><th>Jobs</th><th>Average</th>' +
          '</tr></thead><tbody>' +
          p.processes.map(function (r: Json): string {
            return '<tr><td>pid ' + admin.esc(r.pid) + '<br><small>' +
              admin.esc(r.role) + '</small></td><td>' + admin.esc(r.state) +
              '</td><td>' + admin.esc(r.currentWorkers) + ' of ' +
              admin.esc(r.maxWorkers) + '</td><td>' +
              admin.esc(r.busyWorkers) + '</td><td>' +
              admin.esc(r.freeWorkers) + '</td><td>' +
              admin.esc(r.restarts.crashed) + '</td><td>' +
              admin.esc(r.responseTime.jobs) + '</td><td>' +
              self.ms(r.responseTime.averageMs) + '</td></tr>';
          }).join('') + '</tbody></table>' +
          (p.unanswered.length ? admin.warn(
            p.unanswered.length + ' request worker(s) did not report: ' +
            p.unanswered.map(function (u: Json): string {
              return 'pid ' + admin.esc(u.pid) + ' (' + admin.esc(u.why) +
                ')';
            }).join(', ') + '.') : '');
      } else if (p.workers.length) {
        detail = '<h3>Workers</h3><table class="grid"><thead><tr>' +
          '<th>pid</th><th>Slot</th><th>State</th><th>In flight</th>' +
          '<th>Served</th><th>Up</th></tr></thead><tbody>' +
          p.workers.map(function (w: Json): string {
            return '<tr><td>' + admin.esc(w.pid) + '</td><td>' +
              admin.esc(w.slot === null ? '—' : w.slot) + '</td><td>' +
              (w.retiring ? 'stopping' : !w.ready ? 'starting'
                                       : w.busy ? 'busy' : 'free') +
              '</td><td>' + admin.esc(w.inFlight) + '</td><td>' +
              admin.esc(w.served) + '</td><td>' +
              (w.upSeconds === null ? '—' : admin.esc(w.upSeconds) + ' s') +
              '</td></tr>';
          }).join('') + '</tbody></table>';
      }
      return head + self.figures(p, pq) + detail;
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
 * Monitoring → Worker Pools, `/admin/worker-pools`: the request,
 * hosted-surface and post-quantum pools of this node. A service page with
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
