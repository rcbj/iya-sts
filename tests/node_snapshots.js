// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: node_snapshots.js
//
// ===========================================================================
// EVERY CLUSTER NODE ON MONITORING → WORKER POOLS AND → NODE HEALTH (#332).
//
// `cluster/node_snapshots.ts` writes each node's own views to the shared
// store and reads every node's back; the two pages draw a section per node
// and the cluster's totals. This file drives the REAL class over a cluster
// and a store it fakes — membership rows, snapshot rows and the database
// clock — and the REAL page classes over it. Eight claims:
//
//   1. STATES: this node live from its own view; another node live, stale
//      past three intervals, gone when membership has no live row by its
//      name (its row kept), and a live member with no row `no-snapshot` —
//      none dropped; ages by the DATABASE's clock.
//   2. THE WRITE: the providers' views under this node's NAME, every IPv4
//      literal scrubbed; a failed write thrown (for the scheduler) and
//      logged once.
//   3. NAMES, NOT ADDRESSES: a name that is an address is replaced by a
//      digest, and nothing a page answers carries a host or an IPv4 literal.
//   4. NO CLUSTER: cluster.mode off, or a store that cannot be shared — one
//      section and a sentence saying so.
//   5. THE JOB: `cluster.node-snapshot` registered once, per-process and
//      quiet, off in a request worker and with no cluster, on in a joined
//      front process, and its run is the write.
//   6. THE PAGES: Worker Pools' and Node Health's answers over two nodes'
//      rows — sections, totals summed over the nodes not gone, `?node=`
//      narrowing to one and refusing an unknown name — and each page's
//      HTML with a section per node whose anchors do not collide.
//   7. A READ THAT FAILS draws this node alone and says why.
//   8. THE PURGE (rcbj: a day): a gone node past
//      `cluster.nodeSnapshotRetentionHours` is deleted by the hourly CLUSTER
//      job; a gone node younger is kept and says when it goes; a live
//      member's old row and this node's are never deleted; membership that
//      cannot be read deletes nothing; a failed delete is thrown.
// ===========================================================================

delete process.env.CONFIG_FILE;

const snapshotsModule = require('../cluster/node_snapshots');
const workerPoolsAdmin = require('../admin-ui/worker_pools_admin');
const nodeHealthAdmin = require('../admin-ui/node_health_admin');

const NodeSnapshots = snapshotsModule.NodeSnapshots;
const WorkerPoolsAdmin = workerPoolsAdmin.WorkerPoolsAdmin;
const NodeHealthAdmin = nodeHealthAdmin.NodeHealthAdmin;

const log = require('bunyan').createLogger({
  name: 'node_snapshots',
  level: process.env.LOG_LEVEL || 'info' });

const NOW = 1790000000000;
const MIB = 1024 * 1024;
const IPV4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;

// A worker pools view of one node, as its page builds it.
function poolsView(name, current, busy, crashed) {
  log.debug("Entering poolsView().");
  log.debug("Leaving poolsView().");
  return { node: name, pid: 100, scope: 'node',
           scopeText: 'the pools of the node ' + name,
           pools: [
             { id: 'request', title: 'Request pool', state: 'running',
               stateText: 'running', module: 'm', setting: 's',
               maxWorkers: 4, initialWorkers: 4, currentWorkers: current,
               readyWorkers: current, busyWorkers: busy,
               freeWorkers: current - busy,
               restarts: { forked: current + crashed, crashed: crashed,
                           failedStarts: 0, replaced: crashed, stopped: 0 },
               responseTime: { answered: 1, averageMs: 1,
                               recentAverageMs: 1, maxMs: 1 },
               workers: [] },
             { id: 'surface', title: 'Surface pool', state: 'off',
               stateText: 'Off', module: 'm', setting: 's', maxWorkers: 0,
               initialWorkers: 0, currentWorkers: 0, readyWorkers: 0,
               busyWorkers: 0, freeWorkers: 0,
               restarts: { forked: 0, crashed: 0, failedStarts: 0,
                           replaced: 0, stopped: 0 },
               responseTime: { answered: 0, averageMs: null,
                               recentAverageMs: null, maxMs: null },
               workers: [] }
           ] };
}

// A node health view of one node.
function healthView(name, usedMiB, limitMiB, cores, vcpus) {
  log.debug("Entering healthView().");
  log.debug("Leaving healthView().");
  return { node: name, pid: 100, scope: 'node', scopeText: 'x', cgroup: '/',
           cpu: { available: true, utilisationPercent: 100 * cores / vcpus,
                  coresUsed: cores, percentOfVcpus: vcpus, limitVcpus: vcpus,
                  limitText: 'q', sampled: 'since-previous-sample',
                  windowSeconds: 15, usageSeconds: 1, userSeconds: 1,
                  systemSeconds: 0, source: '/c', throttling: null,
                  throttlingText: 'none' },
           memory: { available: true, currentBytes: usedMiB * MIB,
                     limitBytes: limitMiB * MIB, limitText: 'l',
                     utilisationPercent: 100 * usedMiB / limitMiB,
                     peakBytes: null, anonBytes: null, fileBytes: null,
                     kernelBytes: null, statText: 's', oomKills: 0,
                     source: '/m' },
           processes: { rows: [], unanswered: [], debuggerNote: null,
                        totals: { rows: 3, processes: 1,
                                  workerThreads: 2, rssBytes: 300 * MIB,
                                  processesWithRss: 1,
                                  heapUsedBytes: 90 * MIB,
                                  heapTotalBytes: 120 * MIB,
                                  externalBytes: 0, isolatesWithHeap: 3 },
                        totalsText: 't' },
           ecs: { available: false, unavailableText: 'not ECS' },
           machine: { text: 'm', loadavg: [0, 0, 0], totalmemBytes: 1,
                      freememBytes: 1, cpus: 1 } };
}

// A cluster whose members and whose node this is are given; and a store
// holding the rows given.
function aCluster(opts) {
  log.debug("Entering aCluster().");
  const puts = [];
  const purgeCalls = [];
  const cluster = {
    enabled: function () {
      return opts.enabled !== false;
    },
    nodeName: function () {
      return opts.self || 'node-a';
    },
    nodeId: function () {
      return 'uuid-self';
    },
    status: function () {
      return { role: opts.role || 'front', nodeId: 'uuid-self' };
    },
    snapshot: function () {
      return { state: { available: true, now: NOW,
                        nodes: (opts.members || []).map(function (m) {
                          return { name: m.name, leftAt: m.left ? 1 : 0,
                                   expiresAt: m.expired ? NOW - 1
                                                        : NOW + 30000 };
                        }) } };
    },
    refreshState: function () {
      return Promise.resolve(null);
    },
    // The fresh read a purge makes; `opts.stateFails` makes it throw and
    // `opts.stateUnavailable` answers a state with no membership.
    state: function () {
      if (opts.stateFails) {
        return Promise.reject(new Error('the pool is closed'));
      }
      if (opts.stateUnavailable) {
        return Promise.resolve({ available: false });
      }
      return Promise.resolve(cluster.snapshot().state);
    }
  };
  const store = opts.noStore ? null : {
    putNodeSnapshot: function (name, nodeId, body) {
      if (opts.failWrite) {
        return Promise.reject(new Error('connection refused by 10.0.0.9'));
      }
      puts.push({ name: name, nodeId: nodeId, body: body });
      return Promise.resolve({ written: true });
    },
    nodeSnapshots: function () {
      if (opts.failRead) {
        return Promise.reject(new Error('the pool is closed'));
      }
      return Promise.resolve({ now: NOW, rows: opts.rows || [] });
    },
    // The driver's rule, over the rows given: older than the age by the
    // database clock (NOW) and not a kept name.
    purgeNodeSnapshots: function (olderThanMs, keepNames) {
      purgeCalls.push({ olderThanMs: olderThanMs, keep: keepNames.slice() });
      if (opts.failPurge) {
        return Promise.reject(new Error('permission denied'));
      }
      const gone = (opts.rows || []).filter(function (row) {
        return row.takenAt < NOW - olderThanMs &&
               keepNames.indexOf(row.name) < 0;
      });
      opts.rows = (opts.rows || []).filter(function (row) {
        return gone.indexOf(row) < 0;
      });
      return Promise.resolve(gone.map(function (row) {
        return { name: row.name, takenAt: row.takenAt };
      }));
    }
  };
  const registered = [];
  const scheduler = {
    job: function (id) {
      return registered.filter(function (j) {
        return j.id === id;
      })[0] || null;
    },
    register: function (spec) {
      registered.push(spec);
      return spec;
    }
  };
  const instance = new NodeSnapshots({
    log: require('../common/helpers').log,
    errorCodes: require('../common/error_codes'),
    retentionHours: function () {
      return opts.retentionHours || 24;
    },
    cluster: function () {
      return cluster;
    },
    store: function () {
      return store;
    },
    scheduler: function () {
      return scheduler;
    }
  });
  log.debug("Leaving aCluster().");
  return { instance: instance, puts: puts, registered: registered,
           purgeCalls: purgeCalls, opts: opts };
}

// Two other nodes' rows and a membership, the shape of a three-node
// cluster with one node gone, one stale and one not yet written.
function threeNodes() {
  log.debug("Entering threeNodes().");
  log.debug("Leaving threeNodes().");
  return {
    self: 'node-a',
    members: [{ name: 'node-a' }, { name: 'node-b' }, { name: 'node-d' },
              { name: 'node-f' }, { name: 'node-c', left: true }],
    rows: [
      // This node's own row: never drawn, its live view is.
      { name: 'node-a', takenAt: NOW - 1000,
        body: { workerPools: poolsView('node-a', 9, 9, 9),
                nodeHealth: healthView('node-a', 1, 2, 1, 1) } },
      { name: 'node-b', takenAt: NOW - 5000,
        body: { workerPools: poolsView('node-b', 4, 1, 2),
                nodeHealth: healthView('node-b', 512, 1024, 1, 2) } },
      { name: 'node-c', takenAt: NOW - 100000,
        body: { workerPools: poolsView('node-c', 4, 0, 0),
                nodeHealth: healthView('node-c', 100, 1024, 1, 2) } },
      { name: 'node-f', takenAt: NOW - 60000,
        body: { workerPools: poolsView('node-f', 2, 2, 1),
                nodeHealth: healthView('node-f', 256, 1024, 0.5, 2) } }
    ]
  };
}

function byName(nodes, name) {
  log.debug("Entering byName().");
  log.debug("Leaving byName().");
  return nodes.filter(function (n) {
    return n.name === name;
  })[0];
}

async function checkStates(t) {
  log.debug("Entering checkStates().");
  t.log.info('=== 1. live, stale, gone and no-snapshot, none dropped ===');
  const c = aCluster(threeNodes());
  const read = await c.instance.read('workerPools', poolsView('node-a', 3,
                                                             1, 0));
  const names = read.nodes.map(function (n) {
    return n.name + ':' + n.state;
  });
  t.equal(names.join(', '),
          'node-a:live, node-b:live, node-c:gone, node-d:no-snapshot, ' +
          'node-f:stale',
          'this node first and live, then every other node by name');
  const a = read.nodes[0];
  t.check(a.self && a.view.pools[0].currentWorkers === 3 &&
          a.ageSeconds === 0,
          'this node\'s section is its live view, not its own row',
          JSON.stringify(a).slice(0, 200));
  t.check(byName(read.nodes, 'node-b').ageSeconds === 5 &&
          byName(read.nodes, 'node-f').ageSeconds === 60,
          'ages by the database clock: 5 s and 60 s', names.join());
  t.check(/Gone/.test(byName(read.nodes, 'node-c').stateText) &&
          !!byName(read.nodes, 'node-c').view,
          'a gone node keeps its last snapshot, marked', '');
  t.check(/Stale/.test(byName(read.nodes, 'node-f').stateText),
          'a stale one says so', byName(read.nodes, 'node-f').stateText);
  t.check(byName(read.nodes, 'node-d').view === null &&
          /no snapshot yet|written no/.test(
            byName(read.nodes, 'node-d').stateText),
          'a live member with no row is listed, saying it has written none',
          byName(read.nodes, 'node-d').stateText);
  t.check(read.cluster.clustered === true &&
          read.cluster.staleAfterSeconds === 45 &&
          read.cluster.intervalSeconds === 15,
          'the cluster block names the interval and the bound',
          JSON.stringify(read.cluster));
  log.debug("Leaving checkStates().");
}

async function checkWrite(t) {
  log.debug("Entering checkWrite().");
  t.log.info('=== 2. the write: this node\'s views by name, scrubbed ===');
  const c = aCluster({ self: 'node-a' });
  c.instance.provide('workerPools', function () {
    return Promise.resolve({ node: 'node-a', note: 'dialled 10.1.2.3:5432' });
  });
  c.instance.provide('nodeHealth', function () {
    return Promise.reject(new Error('the cgroup is gone'));
  });
  const summary = await c.instance.write();
  t.check(summary.written && c.puts.length === 1 &&
          c.puts[0].name === 'node-a' && c.puts[0].nodeId === 'uuid-self',
          'one row, under this node\'s name', JSON.stringify(summary));
  const body = c.puts[0].body;
  t.check(body.workerPools.note === 'dialled [address]:5432' &&
          !IPV4.test(JSON.stringify(body)),
          'an IPv4 literal in a view is scrubbed before it is written',
          JSON.stringify(body));
  t.check(/cgroup is gone/.test(body.nodeHealth.unavailable),
          'a view that could not be built is written as the reason, and ' +
          'the other is still written', JSON.stringify(body));
  const failing = aCluster({ failWrite: true });
  let threw = null;
  try {
    await failing.instance.write();
  } catch (e) {
    log.debug("Caught in checkWrite(): " + ((e && e.message) || e));
    threw = e;
  }
  t.check(!!threw, 'a failed write is thrown, for the scheduler to record',
          String(threw));
  log.debug("Leaving checkWrite().");
}

async function checkNames(t) {
  log.debug("Entering checkNames().");
  t.log.info('=== 3. names, never addresses ===');
  t.equal(NodeSnapshots.displayName('node-b'), 'node-b',
          'a configured name is drawn as it is');
  t.check(/^node-[0-9a-f]{8}$/.test(
    NodeSnapshots.displayName('ip-10-0-1-23.ec2.internal')) &&
          /^node-[0-9a-f]{8}$/.test(NodeSnapshots.displayName('10.0.1.23')) &&
          /^node-[0-9a-f]{8}$/.test(NodeSnapshots.displayName('fe80::1')),
          'a host name that is an address, an IPv4 and an IPv6 literal are ' +
          'each replaced by a digest', '');
  t.equal(NodeSnapshots.displayName('10.0.1.23'),
          NodeSnapshots.displayName('10.0.1.23'),
          'the digest is stable, so the node keeps its row');
  const c = aCluster({ self: 'ip-10-0-9-9', members: [{ name: 'ip-10-0-9-9' }],
                       rows: [] });
  const read = await c.instance.read('workerPools', poolsView('x', 1, 0, 0));
  t.check(!IPV4.test(JSON.stringify(read)) &&
          !/ip-10-0-9-9/.test(JSON.stringify(read)),
          'a node named by its address is drawn under the digest',
          read.nodes[0].name);
  log.debug("Leaving checkNames().");
}

async function checkNoCluster(t) {
  log.debug("Entering checkNoCluster().");
  t.log.info('=== 4. no cluster: one section, and a sentence ===');
  let c = aCluster({ enabled: false });
  let read = await c.instance.read('nodeHealth', healthView('n', 1, 2, 1, 1));
  t.check(read.nodes.length === 1 && read.cluster.clustered === false &&
          /There is no cluster/.test(read.cluster.text),
          'cluster.mode off: this node alone, saying there is no cluster',
          read.cluster.text);
  c = aCluster({ noStore: true });
  read = await c.instance.read('nodeHealth', healthView('n', 1, 2, 1, 1));
  t.check(read.nodes.length === 1 &&
          /no cluster store/.test(read.cluster.text),
          'a store that cannot be shared: the same, and why',
          read.cluster.text);
  log.debug("Leaving checkNoCluster().");
}

async function checkJob(t) {
  log.debug("Entering checkJob().");
  t.log.info('=== 5. the per-process job ===');
  const c = aCluster({ self: 'node-a' });
  c.instance.provide('workerPools', function () {
    return Promise.resolve({ node: 'node-a' });
  });
  c.instance.provide('nodeHealth', function () {
    return Promise.resolve({ node: 'node-a' });
  });
  t.equal(c.registered.length, 2,
          'one snapshot job for both views, and the purge');
  const job = c.registered.filter(function (j) {
    return j.id === 'cluster.node-snapshot';
  })[0];
  t.check(job.id === 'cluster.node-snapshot' && job.kind === 'per-process' &&
          job.quiet === true && job.everyMs() === 15000,
          'cluster.node-snapshot, per-process, quiet, every 15 s',
          JSON.stringify({ id: job.id, kind: job.kind }));
  t.equal(job.off(''), '', 'on in a joined front process');
  const summary = await job.run({});
  t.check(summary.written && c.puts.length === 1,
          'its run is the write', JSON.stringify(summary));
  const worker = aCluster({ role: 'worker' });
  worker.instance.provide('workerPools', function () {
    return Promise.resolve({});
  });
  const workerJob = worker.registered.filter(function (j) {
    return j.id === 'cluster.node-snapshot';
  })[0];
  t.check(/not a joined front process/.test(workerJob.off('')),
          'off in a request worker', workerJob.off(''));
  const off = aCluster({ enabled: false });
  off.instance.provide('workerPools', function () {
    return Promise.resolve({});
  });
  t.check(off.registered.every(function (j) {
    return /no cluster/.test(j.off(''));
  }), 'both off with no cluster', off.registered[0].off(''));
  log.debug("Leaving checkJob().");
}

async function checkPages(t) {
  log.debug("Entering checkPages().");
  t.log.info('=== 6. the two pages over every node ===');
  const c = aCluster(threeNodes());
  const snapshots = {
    read: function (key, view) {
      return c.instance.read(key, view);
    },
    scrub: NodeSnapshots.scrub,
    provide: function () {}
  };
  const pools = new WorkerPoolsAdmin(Object.assign(
    WorkerPoolsAdmin.defaultDeps(), { snapshots: function () {
      return snapshots;
    } }));
  pools.localView = function () {
    return Promise.resolve(poolsView('node-a', 3, 1, 0));
  };
  let json = await pools.workerPoolsView({});
  t.check(json.node === 'node-a' && json.answeredBy.node === 'node-a' &&
          json.nodes.length === 5,
          'Worker Pools: this node at the top, and five node sections',
          JSON.stringify(json.nodes.map(function (n) {
            return n.name;
          })));
  const request = json.totals.pools.filter(function (p) {
    return p.id === 'request';
  })[0];
  // node-a 3 (1 busy), node-b 4 (1 busy, 2 crashed), node-f 2 (2 busy, 1
  // crashed); node-c is gone and node-d has no view.
  t.check(request.currentWorkers === 9 && request.busyWorkers === 4 &&
          request.freeWorkers === 5 && request.crashed === 3 &&
          json.totals.nodesCounted === 3,
          'the totals sum the nodes that are not gone, stale included',
          JSON.stringify(request));
  const text = JSON.stringify(json);
  t.check(!/"host"/.test(text) && !IPV4.test(text),
          'no host and no IPv4 literal anywhere in the answer', '');
  json = await pools.workerPoolsView({ node: 'node-b' });
  t.check(json.node === 'node-b' && json.nodes.length === 1 &&
          json.state === 'live' && json.pools[0].currentWorkers === 4 &&
          json.totals.pools[0].currentWorkers === 4,
          '?node=node-b answers about node-b alone',
          JSON.stringify({ node: json.node, state: json.state }));
  json = await pools.workerPoolsView({ node: 'node-z' });
  t.check(json.notFound === 'node-z' &&
          json.nodeNames.indexOf('node-b') >= 0,
          'an unknown name is not found, with the names there are',
          JSON.stringify(json));
  const html = pools.clusterHtml(await pools.workerPoolsView({}));
  t.check(/id="cluster"/.test(html) && /id="node-node-b"/.test(html) &&
          /id="pool-request"/.test(html) &&
          /id="node-b-pool-request"/.test(html) &&
          (html.match(/ id="pool-request"/g) || []).length === 1 &&
          /stale/.test(html) && /gone/.test(html) &&
          /no-snapshot/.test(html),
          'the page draws every node, each marked, with anchors that do ' +
          'not collide', html.slice(0, 300));

  const health = new NodeHealthAdmin(Object.assign(
    NodeHealthAdmin.defaultDeps(), { snapshots: function () {
      return snapshots;
    } }));
  health.localView = function () {
    return Promise.resolve(healthView('node-a', 256, 1024, 0.5, 2));
  };
  json = await health.nodeHealthView({});
  const tt = json.totals;
  // node-a 256/1024 0.5/2, node-b 512/1024 1/2, node-f 256/1024 0.5/2.
  t.check(tt.memoryUsedBytes === 1024 * MIB &&
          tt.memoryLimitBytes === 3072 * MIB &&
          tt.memoryPercent === 33.3 && tt.cpuCoresUsed === 2 &&
          tt.cpuOf === 6 && tt.cpuPercent === 33.3 &&
          tt.processes === 3 && tt.workerThreads === 6 &&
          tt.rssBytes === 900 * MIB,
          'Node Health totals: container memory against the summed limits, ' +
          'CPU against the summed CPUs, the processes and, apart from them, ' +
          'the worker threads (#364)', JSON.stringify(tt));
  json = await health.nodeHealthView({ node: 'node-f' });
  t.check(json.node === 'node-f' && json.state === 'stale' &&
          json.memory.currentBytes === 256 * MIB,
          '?node=node-f answers node-f, marked stale', json.state);
  const page = health.clusterHtml(await health.nodeHealthView({}));
  t.check(/id="node-node-f"/.test(page) && /id="cpu"/.test(page) &&
          /id="node-f-cpu"/.test(page) &&
          (page.match(/ id="cpu"/g) || []).length === 1,
          'Node Health draws a section per node, anchors apart', '');
  log.debug("Leaving checkPages().");
}

async function checkReadFailure(t) {
  log.debug("Entering checkReadFailure().");
  t.log.info('=== 7. a read that fails ===');
  const c = aCluster({ failRead: true });
  const read = await c.instance.read('workerPools', poolsView('node-a', 1,
                                                             0, 0));
  t.check(read.nodes.length === 1 &&
          /could not be read/.test(read.cluster.readError) &&
          /STS-CORE-0127/.test(read.cluster.readError),
          'this node alone, and the reason with its code',
          read.cluster.readError);
  log.debug("Leaving checkReadFailure().");
}

// ---------------------------------------------------------------------------
// 8. A GONE NODE EXPIRES AFTER THE RETENTION, AND NOTHING ELSE DOES.
// ---------------------------------------------------------------------------
async function checkPurge(t) {
  log.debug("Entering checkPurge().");
  t.log.info('=== 8. the purge: a gone node older than the retention, and ' +
             'nothing else ===');
  const HOUR = 3600000;
  const rows = function () {
    return [
      // Gone, 30 h without a snapshot: past a day, deleted.
      { name: 'node-old', takenAt: NOW - 30 * HOUR, body: {} },
      // Gone, 2 h: kept, and the page says when it goes.
      { name: 'node-young', takenAt: NOW - 2 * HOUR, body: {
        workerPools: poolsView('node-young', 1, 0, 0) } },
      // A LIVE member whose row is 40 h old: never deleted.
      { name: 'node-b', takenAt: NOW - 40 * HOUR, body: {} },
      // This node's own, old: never deleted either.
      { name: 'node-a', takenAt: NOW - 50 * HOUR, body: {} }
    ];
  };
  const members = [{ name: 'node-a' }, { name: 'node-b' },
                   { name: 'node-old', left: true },
                   { name: 'node-young', expired: true }];
  let c = aCluster({ self: 'node-a', members: members, rows: rows() });
  c.instance.ensureJob();
  const job = c.registered.filter(function (j) {
    return j.id === 'cluster.node-snapshot-purge';
  })[0];
  t.check(!!job && job.kind === 'cluster' && job.everyMs() === HOUR &&
          job.off('') === '',
          'cluster.node-snapshot-purge: a CLUSTER job, hourly, on in a ' +
          'cluster', JSON.stringify(job && { kind: job.kind }));
  const read = await c.instance.read('workerPools',
                                     poolsView('node-a', 1, 0, 0));
  const young = byName(read.nodes, 'node-young');
  t.check(young.state === 'gone' &&
          /removed after 24 h without a snapshot/.test(young.stateText) &&
          /in about 22 h/.test(young.stateText) &&
          read.cluster.goneRemovedAfterHours === 24,
          'a gone node says when it will be removed', young.stateText);
  const summary = await job.run({});
  t.equal(summary.nodes.join(','), 'node-old',
          'the gone node past the retention is deleted, and only it');
  t.check(c.purgeCalls.length === 1 &&
          c.purgeCalls[0].olderThanMs === 24 * HOUR &&
          c.purgeCalls[0].keep.indexOf('node-b') >= 0 &&
          c.purgeCalls[0].keep.indexOf('node-a') >= 0 &&
          c.purgeCalls[0].keep.indexOf('node-young') < 0,
          'asked with the retention and the live names to keep',
          JSON.stringify(c.purgeCalls));
  t.equal(c.opts.rows.map(function (r) {
    return r.name;
  }).join(','), 'node-young,node-b,node-a',
  'the gone node younger than the retention, the live member\'s old row ' +
  'and this node\'s are kept');

  for (const failure of ['stateFails', 'stateUnavailable']) {
    const opts = { self: 'node-a', members: members, rows: rows() };
    opts[failure] = true;
    c = aCluster(opts);
    const s = await c.instance.purge();
    t.check(s.purged === 0 && c.purgeCalls.length === 0 &&
            /could not be read/.test(s.why) && c.opts.rows.length === 4,
            'membership unreadable (' + failure + '): nothing is deleted, ' +
            'and the store is not even asked', JSON.stringify(s));
  }
  c = aCluster({ self: 'node-a', members: members, rows: rows(),
                 retentionHours: 1 });
  const s1 = await c.instance.purge();
  t.equal(s1.nodes.sort().join(','), 'node-old,node-young',
          'a retention of one hour deletes both gone nodes, and still no ' +
          'live one');
  c = aCluster({ self: 'node-a', members: members, rows: rows(),
                 failPurge: true });
  let threw = null;
  try {
    await c.instance.purge();
  } catch (e) {
    log.debug("Caught in checkPurge(): " + ((e && e.message) || e));
    threw = e;
  }
  t.check(!!threw, 'a failed delete is thrown for the scheduler to record',
          String(threw));
  log.debug("Leaving checkPurge().");
}

async function run(t) {
  log.debug("Entering run().");
  await checkStates(t);
  await checkWrite(t);
  await checkNames(t);
  await checkNoCluster(t);
  await checkJob(t);
  await checkPages(t);
  await checkReadFailure(t);
  await checkPurge(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'node_snapshots',
  describe: 'Every cluster node on Worker Pools and Node Health (#332): ' +
            'live, stale, gone and no-snapshot marked and never dropped, the ' +
            'write by name with addresses scrubbed, no cluster said in a ' +
            'sentence, the per-process job, both pages\' totals and ?node=, ' +
            'and a failed read',
  run: run
};
