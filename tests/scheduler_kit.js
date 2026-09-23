'use strict';
//
// File: scheduler_kit.js
//
// ===========================================================================
// A SIMULATED CLUSTER FOR THE SCHEDULER'S TESTS (#49, 2026-09-22) — NOT A
// TEST ITSELF (`tests/run.js`'s NOT_A_TEST names it).
//
// `tests/scheduler.js` and `tests/scheduler_cluster.js` drive real
// `Scheduler` instances (the class `cluster/scheduler.ts` exports) through
// its constructor, with everything it depends on replaced by this world:
//
//   * ONE VIRTUAL DATABASE CLOCK, and each node's own clock SKEWED from it on
//     purpose, so a scheduler that read `Date.now()` where it should read the
//     database's gives itself away.
//   * VIRTUAL TIMERS against that clock. Nothing here ever sleeps: `advance()`
//     moves the clock to the next due timer, fires it and lets the promises
//     it started settle, which is the `sts_admin_console` lesson in
//     `tests/CLAUDE.md` — a test waits on a condition, never on a duration.
//   * ONE SHARED STORE, CLAIMS AND LEASES — what several nodes against one
//     postgres store share. The store is instantly consistent (replication is
//     somebody else's test); the claims keep a lifetime by the database clock
//     and are re-claimable once it lapses, as `sts_cluster_claims` is; the
//     leases carry a fencing token that goes up each time one changes hands.
//   * NODES THAT HEARTBEAT, DIE AND WAKE. A dead node's timers and heartbeat
//     stop; its lease and its claims lapse by the clock; when it wakes, its
//     timers fire late, as a process that was paused would.
// ===========================================================================

const path = require('path');

const ROOT = path.join(__dirname, '..');

const log = require('bunyan').createLogger({ name: 'scheduler_kit',
  level: process.env.LOG_LEVEL || 'info' });

function settle(turns) {
  log.debug('Entering settle().');
  let chain = Promise.resolve();
  for (let i = 0; i < (turns || 12); i++) {
    chain = chain.then(function () {
      return new Promise(function (resolve) { setImmediate(resolve); });
    });
  }
  log.debug('Leaving settle().');
  return chain;
}

function world(options) {
  log.debug('Entering world().');
  const o = options || {};
  const Scheduler = require(ROOT + '/cluster/scheduler').Scheduler;
  const w = {
    db: Number(o.startAt || Date.UTC(2026, 8, 22, 12, 0, 0)),
    clustered: o.clustered !== false,
    heartbeatMs: o.heartbeatMs || 1000,
    leaseTtlMs: o.leaseTtlMs || 3000,
    timers: [],
    seq: 0,
    stores: new Map(),
    claimRows: new Map(),
    leases: new Map(),
    nodes: [],
    audits: [],
    logs: [],
    settings: Object.assign({
      'scheduler.enabled': true,
      'scheduler.tickS': 5,
      'scheduler.historyDays': 30,
      'scheduler.maxRuns': 5000,
      'scheduler.disabledJobs': '',
      'scheduler.runTimeoutS': 600
    }, o.settings || {}),
    realmIds: o.realmIds || ['default', 'acme'],
    claimsDown: false
  };

  const store = {
    realmMap: function (id) {
      const key = String(id || 'default');
      if (!w.stores.has(key)) {
        w.stores.set(key, new Map());
      }
      return w.stores.get(key);
    }
  };

  const claims = {
    claim: function (opts) {
      if (w.claimsDown) {
        return Promise.resolve({ ok: false, reason: 'store',
                                 why: 'the store is down (simulated)' });
      }
      const key = String(opts.scope) + '|' + String(opts.realm) + '|' +
                  String(opts.value);
      const held = w.claimRows.get(key);
      if (held && held.expiresAt > w.db) {
        return Promise.resolve({ ok: false, reason: 'used', existing: held });
      }
      const claimedAt = w.db + (held && held.claimedAt >= w.db
        ? held.claimedAt - w.db + 1 : 0);
      const reservation = 'r' + (++w.seq);
      w.claimRows.set(key, { reservation: reservation, claimedAt: claimedAt,
                             expiresAt: claimedAt + Number(opts.ttlMs) });
      return Promise.resolve({ ok: true, claimedAt: claimedAt,
                               handle: { key: key,
                                         reservation: reservation } });
    },
    release: function (handle) {
      const held = handle && w.claimRows.get(handle.key);
      if (held && held.reservation === handle.reservation) {
        w.claimRows.delete(handle.key);
        return Promise.resolve(true);
      }
      return Promise.resolve(false);
    }
  };

  const realms = {
    DEFAULT_ID: 'default',
    list: function () {
      return w.realmIds.map(function (id) { return { id: id }; });
    },
    run: function (realm, fn) { return fn(); },
    get: function (id) {
      return w.realmIds.indexOf(String(id)) >= 0 ? { id: String(id) } : null;
    }
  };

  const config = {
    value: function (key) {
      return Object.prototype.hasOwnProperty.call(w.settings, key)
        ? w.settings[key] : undefined;
    }
  };

  function quietLog(prefix) {
    log.debug('Entering quietLog().');
    log.debug('Leaving quietLog().');
    const keep = function (level) {
      return function (m) {
        w.logs.push({ level: level, node: prefix, m: m });
      };
    };
    return { debug: function () {}, info: keep('info'), warn: keep('warn'),
             error: keep('error'), fatal: keep('fatal') };
  }

  // ---------------------------------------------------------------------
  // A NODE: one Scheduler, one fake `cluster`, its own skewed clock.
  // ---------------------------------------------------------------------
  w.node = function (name, nodeOptions) {
    const no = nodeOptions || {};
    const node = {
      name: name, alive: true, skewMs: no.skewMs || 0, roles: new Map(),
      held: new Map(), standingDownUntil: new Map(),
      pid: no.pid || (1000 + w.nodes.length), invoked: []
    };
    const fakeCluster = {
      enabled: function () { return w.clustered; },
      nodeId: function () { return w.clustered ? 'node-' + name : ''; },
      nodeName: function () { return name; },
      lead: function (lease, handlers) {
        node.roles.set(lease, handlers);
        if (!w.clustered) {
          handlers.onGain(0);
          return;
        }
        w.campaign(node);
      },
      holds: function (lease) {
        return !w.clustered || node.held.has(lease);
      },
      stepDown: function (lease) {
        if (!w.clustered) {
          return Promise.resolve({ ok: false, reason: 'not-clustered' });
        }
        const token = node.held.get(lease);
        if (!token) {
          return Promise.resolve({ ok: false, reason: 'not-held' });
        }
        node.held.delete(lease);
        node.standingDownUntil.set(lease, w.db + 3 * w.heartbeatMs);
        const row = w.leases.get(lease);
        if (row && row.holder === name && row.token === token) {
          row.expiresAt = 0;
        }
        const h = node.roles.get(lease);
        if (h && h.onLose) {
          h.onLose();
        }
        return Promise.resolve({ ok: true, token: token });
      },
      state: function () {
        return Promise.resolve({ leases: Array.from(w.leases.entries())
          .map(function (pair) {
            return { name: pair[0], holder: 'node-' + pair[1].holder,
                     token: pair[1].token, acquiredAt: pair[1].acquiredAt,
                     expiresAt: pair[1].expiresAt };
          }) });
      }
    };
    node.cluster = fakeCluster;
    node.scheduler = new Scheduler({
      log: quietLog(name),
      config: config,
      realms: realms,
      errorCodes: require(ROOT + '/common/error_codes'),
      audit: { record: function (row) { w.audits.push(Object.assign(
        { node: name }, row)); } },
      cluster: fakeCluster,
      claims: claims,
      store: store,
      dbNow: function () { return Promise.resolve(w.db); },
      now: function () { return w.db + node.skewMs; },
      setTimer: function (fn, ms) {
        const t = { at: w.db + Math.max(0, ms), fn: fn, node: node,
                    id: ++w.seq, cleared: false };
        w.timers.push(t);
        return t;
      },
      clearTimer: function (t) { if (t) { t.cleared = true; } },
      cronPrev: Scheduler.cronPrev,
      cronNext: Scheduler.cronNext,
      host: 'host-' + name,
      pid: node.pid,
      isRequestWorker: function () { return !!no.worker; }
    });
    node.kill = function () { node.alive = false; };
    node.wake = function () { node.alive = true; };
    w.nodes.push(node);
    return node;
  };

  // A node asks for every role it wants and does not hold.
  w.campaign = function (node) {
    if (!node.alive || !w.clustered) {
      return;
    }
    node.roles.forEach(function (handlers, lease) {
      if (node.held.has(lease)) {
        return;
      }
      if ((node.standingDownUntil.get(lease) || 0) > w.db) {
        return;
      }
      const row = w.leases.get(lease);
      if (row && row.expiresAt > w.db && row.holder !== node.name) {
        return;
      }
      const token = row ? (row.holder === node.name && row.expiresAt > w.db
        ? row.token : row.token + 1) : 1;
      w.leases.set(lease, { holder: node.name, token: token,
                            acquiredAt: w.db,
                            expiresAt: w.db + w.leaseTtlMs });
      node.held.set(lease, token);
      handlers.onGain(token);
    });
  };

  // The heartbeat: every live node renews what it holds, learns what it
  // lost, and campaigns.
  w.beat = function () {
    w.nodes.forEach(function (node) {
      if (!node.alive || !w.clustered) {
        return;
      }
      Array.from(node.held.entries()).forEach(function (pair) {
        const lease = pair[0];
        const row = w.leases.get(lease);
        if (row && row.holder === node.name && row.token === pair[1] &&
            row.expiresAt > w.db) {
          row.expiresAt = w.db + w.leaseTtlMs;
          return;
        }
        node.held.delete(lease);
        const h = node.roles.get(lease);
        if (h && h.onLose) {
          h.onLose();
        }
      });
      w.campaign(node);
    });
  };

  // ADVANCE THE DATABASE CLOCK BY `ms`, firing every timer that falls due on
  // the way, in order — and the heartbeat every `heartbeatMs` — letting each
  // one's promises settle before the next.
  w.advance = async function (ms) {
    const until = w.db + ms;
    let nextBeat = w.nextBeatAt || (w.db + w.heartbeatMs);
    // What was started before this call (a start(), a request) arms its
    // timers only once its promises resolve, so they settle first.
    await settle();
    for (;;) {
      const due = w.timers.filter(function (t) {
        return !t.cleared && t.node.alive && t.at <= until;
      }).sort(function (a, b) { return a.at - b.at || a.id - b.id; })[0];
      // No heartbeat without a cluster: nothing would listen to it.
      const beatDue = w.clustered && nextBeat <= until ? nextBeat : Infinity;
      if (!due && beatDue === Infinity) {
        break;
      }
      if (due && due.at <= beatDue) {
        w.db = Math.max(w.db, due.at);
        due.cleared = true;
        due.fn();
      } else {
        w.db = Math.max(w.db, beatDue);
        nextBeat = beatDue + w.heartbeatMs;
        w.beat();
      }
      await settle();
    }
    w.db = until;
    w.nextBeatAt = nextBeat;
    await settle();
  };

  w.settle = settle;

  w.runRows = function (realmId) {
    const out = [];
    store.realmMap(realmId || 'default').forEach(function (row) {
      if (row && row.kind === 'run') {
        out.push(row);
      }
    });
    return out;
  };

  w.leaderOf = function () {
    const row = w.leases.get('ops.scheduler');
    return row && row.expiresAt > w.db ? row.holder : null;
  };

  log.debug('Leaving world().');
  return w;
}

module.exports = { world: world, settle: settle };
