// @ts-check
'use strict';
//
// File: cluster/cluster.js
//
// ===========================================================================
// SEVERAL CONTAINERS AGAINST ONE STORE: MEMBERSHIP, LEASES AND THE FENCE
// (2026-09-14, #46).
//
// Inside one container the processes agree because the front process
// coordinates its workers over IPC. Between containers the only link was the
// change log, so a second container started, looked healthy and gave wrong
// answers. This module is what a node IS in that picture: a membership row it
// renews, the leases it holds, and the fence every write it makes is held to.
// `cluster/CLAUDE.md` argues all of it; the decisions rcbj made are these:
//
//   * **`cluster.mode` is on by default in product mode on postgres** —
//     `auto` resolves to `active-passive` there and to `off` everywhere else.
//   * **A node without the service lease WAITS BEFORE IT RESTORES ANYTHING OR
//     BINDS ANYTHING.** It joins, heartbeats, and asks for the lease on every
//     beat; nothing it holds in memory is the store's until it has it.
//   * **Every write is fenced, and a node that has lost its right to write
//     exits.** The check is inside the transaction (`persistence_postgres.js`,
//     `checkFence()`), and a node whose membership cannot be renewed within its
//     lifetime exits on its own rather than waiting to be told.
//   * **Active-active is the goal**, and it refuses to start while any
//     capability in `cluster_capabilities.js` is missing and not accepted.
//
// ---------------------------------------------------------------------------
// WHO IS A NODE. A CONTAINER, NOT A PROCESS.
//
// The front process joins and heartbeats. Its request workers are the same
// node: `forkEnvironment()` hands them the node id and the service lease's
// token through the fork's environment (neither is a secret — each is useless
// without the database credential), `attach()` installs the same fence in
// them, and they never heartbeat. A worker whose writes are fenced exits with
// the front process's reason; the front process's own heartbeat will have
// found the same thing.
//
// ---------------------------------------------------------------------------
// WHERE IT RUNS. `persistence.js` calls `gate()` the moment the store is open
// and BEFORE the keystore, the minted journal, the used-assertion history or a
// single restored row are touched — so an active-passive standby has nothing
// armed that could write. `common/service_state.js` calls `agree()` once the
// keystore is open, because the fingerprint is keyed by the key-encryption key.
//
// A LIBRARY (rule 3): no route. It requires config, mode, the capability table,
// the error-code table and node builtins, and is handed its driver.
// ===========================================================================

const bunyan = require('bunyan');
const os = require('os');
const nodeCrypto = require('crypto');
const { AsyncLocalStorage } = require('async_hooks');
const config = require('../common/config');
const errorCodes = require('../common/error_codes');
const capabilities = require('./cluster_capabilities');

const log = bunyan.createLogger({ name: 'sts-cluster' });
config.registerLogger(log);

// The environment a request worker is forked with. Internal names, so an
// operator's environment can never make a front process believe it is a
// worker of somebody else's node.
const ENV_NODE = 'STS_CLUSTER_INTERNAL_NODE_ID';
const ENV_SERVICE_TOKEN = 'STS_CLUSTER_INTERNAL_SERVICE_TOKEN';
const ENV_MODE = 'STS_CLUSTER_INTERNAL_MODE';

// The one lease active-passive mode is about.
const SERVICE_LEASE = 'service';

// The settings every node must hold the same value of, or two nodes answer the
// same request two ways. Keyed-digested under the KEK — several are passwords.
// `cluster/CLAUDE.md` says why each is here.
const AGREEMENT_SETTINGS = [
  'global.mode', 'global.https', 'global.publicBaseUrl',
  'persistence.mode', 'keys.source', 'keys.kidFormat',
  'oauth2.rfc9700', 'oauth2.oauth21', 'spiffe.trustDomain',
  'krb5.realm', 'krb5.krbtgtPassword', 'krb5.servicePassword',
  'krb5.servicePrincipal', 'krb5.serviceSalt', 'krb5.kvno', 'krb5.enctypes',
  'krb5.trustPassword', 'krb5.trustedRealm', 'krb5.trustedKrbtgtPassword',
  'krb5.domainSid', 'krb5.userPassword', 'krb5.personKeys'
];

let driver = null;
let resolved = null;          // { mode, why }
let nodeId = '';
let role = 'none';            // 'front' | 'worker' | 'none'
let joinedAt = 0;
let heartbeatTimer = null;
let lastRenewOk = 0;          // monotonic ms of the last successful renewal
let heartbeatFailures = 0;
let lastHeartbeatError = '';
// The longest this node's heartbeat has run LATE because its event loop was
// busy, and when: `{ ms, atMono }`. See scheduleHeartbeat().
let lastStall = null;
// When the pending heartbeat timer is due (monotonic ms). A timer still
// pending well past this is a loop that could not run it.
let heartbeatDueMono = 0;
let stopping = false;
let fingerprint = '';
// name -> token, for the leases this node holds.
const held = new Map();
// Roles some module wants led: name -> { onGain, onLose }.
const roles = new Map();
// A lease-guarded write in progress: `{ leases: [{ name, token }] }`.
const leaseContext = new AsyncLocalStorage();
// Replaced by tests. An exit is the only safe answer in a real node.
let exitProcess = function (code) {
  process.exit(code);
};

function monotonicMs() {
  log.debug("Entering monotonicMs().");
  log.debug("Leaving monotonicMs().");
  return Number(process.hrtime.bigint() / 1000000n);
}

function heartbeatMs() {
  log.debug("Entering heartbeatMs().");
  log.debug("Leaving heartbeatMs().");
  return Math.max(250, Number(config.value('cluster.heartbeatMs')));
}

function ttlMs() {
  log.debug("Entering ttlMs().");
  log.debug("Leaving ttlMs().");
  return Math.max(3 * heartbeatMs(),
                  Number(config.value('cluster.nodeTtlMs')));
}

function nodeName() {
  log.debug("Entering nodeName().");
  const configured = String(config.value('cluster.nodeName') || '').trim();
  log.debug("Leaving nodeName().");
  return configured || os.hostname();
}

// ---------------------------------------------------------------------------
// WHAT MODE THIS NODE IS IN, and the refusals that are about configuration
// rather than about other nodes. Pure: reads settings and answers.
// ---------------------------------------------------------------------------
function resolve() {
  log.debug("Entering resolve().");
  // A worker is whatever its node is. Reading the setting again could only
  // disagree with the process that forked it.
  if (process.env[ENV_MODE]) {
    log.debug("Leaving resolve(). Inherited.");
    return { mode: process.env[ENV_MODE], why: 'inherited from the node' };
  }
  const configured = String(config.value('cluster.mode') || 'auto');
  const store = String(config.value('persistence.mode') || 'memory');
  const product = String(config.value('global.mode')) === 'product';
  if (configured === 'off') {
    log.debug("Leaving resolve(). Off.");
    return { mode: 'off', why: 'cluster.mode is off' };
  }
  if (configured === 'auto') {
    if (product && store === 'postgres') {
      log.debug("Leaving resolve(). Auto: active-passive.");
      return { mode: 'active-passive',
               why: 'cluster.mode is auto, and this is product mode on a ' +
                    'postgres store' };
    }
    log.debug("Leaving resolve(). Auto: off.");
    return { mode: 'off',
             why: 'cluster.mode is auto, which is off outside product mode ' +
                  'on a postgres store' };
  }
  if (store !== 'postgres') {
    log.debug("Leaving resolve(). Refused: no postgres store.");
    return { mode: configured, refused: errorCodes.tag('STS-CLUSTER-0007') +
             'cluster.mode is "' + configured + '" and persistence.mode is "' +
             store + '". Only a postgres store can hold a membership table, ' +
             'leases and atomic claims that several containers agree on. Set ' +
             'persistence.mode=postgres, or cluster.mode=off for one node.' };
  }
  if (configured === 'active-active' &&
      String(config.value('keys.source')) !== 'persisted' &&
      !(String(config.value('keys.source')) === 'auto' && product)) {
    log.debug("Leaving resolve(). Refused: no persisted keys.");
    return { mode: configured, refused: errorCodes.tag('STS-CLUSTER-0008') +
             'cluster.mode is active-active and keys are not persisted under ' +
             'an operator key-encryption key (keys.source=' +
             config.value('keys.source') + ', global.mode=' +
             config.value('global.mode') + '). Every node has to sign with ' +
             'the same keys and open the same sealed rows, and a key ' +
             'generated per process — or a key-encryption key generated per ' +
             'container, which is what development mode shares between its ' +
             'own workers — is a different key on every node.' };
  }
  // ONE NAME FOR THE CLUSTER (2026-09-14). Every issuer a client verifies —
  // a token's `iss`, the management API's audience, a Shared Signals stream's
  // `iss` — is `global.publicBaseUrl` where it is set and the address the
  // request came in on where it is not. Behind a load balancer that is a
  // different name per node, or per client, and the settings agreement cannot
  // catch it: an empty value is the SAME value on every node. So active-active
  // is refused without one (`ssf/CLAUDE.md`, *Several nodes*, argued it).
  // Active-passive is not: one node serves at a time, so the name a request
  // derives is at least one node's answer to every request.
  if (configured === 'active-active' &&
      !String(config.value('global.publicBaseUrl') || '').trim()) {
    log.debug("Leaving resolve(). Refused: no public base URL.");
    return { mode: configured, refused: errorCodes.tag('STS-CLUSTER-0026') +
             'cluster.mode is active-active and global.publicBaseUrl is ' +
             'empty. Every node must issue under ONE name — the address ' +
             'clients reach the cluster at (the load balancer) — or a token ' +
             'minted on one node names an issuer and an audience the next ' +
             'node does not answer to. Set global.publicBaseUrl ' +
             '(STS_PUBLIC_BASE_URL) to that address on every node.' };
  }
  // A CLUSTER WHOSE NODES DO NOT SHARE WHAT THEY MINT IS NOT ONE (2026-09-14).
  // `persistence.minted` off keeps sessions, pending sign-ins, codes and tokens
  // in each node's memory, and every cross-node hop of every browser flow
  // then fails — measured by the suite's `cluster` mode before the fourth arm
  // of persistence_minted.js's enabled() existed. The capability table cannot
  // see it (every capability is provided; the state they act on is simply not
  // there), so it is refused here, by the setting that causes it.
  if (!config.value('persistence.minted')) {
    log.debug("Leaving resolve(). Refused: minted state not persisted.");
    return { mode: configured, refused: errorCodes.tag('STS-CLUSTER-0040') +
             'cluster.mode is ' + configured + ' and persistence.minted is ' +
             'off, so every node would keep its own sessions, pending ' +
             'sign-ins, codes and tokens and a flow whose hops land on two ' +
             'nodes would fail. Turn persistence.minted on, or run one node ' +
             'with cluster.mode=off.' };
  }
  log.debug("Leaving resolve(). " + configured + ".");
  return { mode: configured, why: 'cluster.mode is ' + configured };
}

function mode() {
  log.debug("Entering mode().");
  log.debug("Leaving mode().");
  return resolved ? resolved.mode : resolve().mode;
}

function enabled() {
  log.debug("Entering enabled().");
  log.debug("Leaving enabled().");
  return mode() !== 'off' && !!driver && !!nodeId;
}

function isActiveActive() {
  log.debug("Entering isActiveActive().");
  log.debug("Leaving isActiveActive().");
  return mode() === 'active-active';
}

// ---------------------------------------------------------------------------
// FAIL-STOP. Every path that finds this node may no longer act as one comes
// here, logs FATAL with its code, and exits. The exit is not negotiable: a
// process that keeps running after losing its membership serves from a copy
// nobody else believes in and retries its writes on every change.
// ---------------------------------------------------------------------------
function failStop(code, message) {
  log.debug("Entering failStop().");
  if (stopping) {
    log.debug("Leaving failStop(). Already stopping.");
    return;
  }
  stopping = true;
  if (heartbeatTimer) {
    clearTimeout(heartbeatTimer);
    heartbeatTimer = null;
  }
  log.fatal(errorCodes.tag(code) + 'cluster: node ' + nodeId + ' (' +
            nodeName() + ') is EXITING. ' + message);
  log.debug("Leaving failStop().");
  exitProcess(1);
}

// The fence the driver checks inside every transaction. The service lease is
// in it in active-passive mode; a lease-guarded write adds its own.
function fenceFor() {
  log.debug("Entering fenceFor().");
  if (!nodeId || mode() === 'off') {
    log.debug("Leaving fenceFor(). None.");
    return null;
  }
  // NOT BEFORE THE ROW EXISTS. The join itself is a transaction, and a fence
  // asking for a membership row inside the statement that writes it fences
  // every node on its first write. A front process has joined once `joinedAt`
  // is set; a worker is forked by a node that already had.
  if (role === 'front' && !joinedAt) {
    log.debug("Leaving fenceFor(). Not joined yet.");
    return null;
  }
  const leases = [];
  if (mode() === 'active-passive' && held.has(SERVICE_LEASE)) {
    leases.push({ name: SERVICE_LEASE, token: held.get(SERVICE_LEASE) });
  }
  const context = leaseContext.getStore();
  if (context && Array.isArray(context.leases)) {
    context.leases.forEach(function (one) {
      leases.push(one);
    });
  }
  log.debug("Leaving fenceFor().");
  return { nodeId: nodeId, leases: leases };
}

// What the driver calls when a transaction is fenced. A lease that only
// guarded ONE operation (an active-active role) fails that operation; losing
// the membership, or the service lease in active-passive mode, is fatal.
function whenFenced(err) {
  log.debug("Entering whenFenced().");
  const message = String((err && err.message) || err);
  const lost = (err && err.lost) || [];
  const serviceLost = lost.some(function (one) {
    return one.name === SERVICE_LEASE;
  });
  if (err && err.reason === 'lease' && !serviceLost) {
    log.warn('cluster: a write guarded by ' + lost.map(function (l) {
      return l.name + '@' + l.token;
    }).join(', ') + ' was fenced; the operation fails and this node stays ' +
             'up: ' + message);
    lost.forEach(function (one) {
      if (held.get(one.name) === Number(one.token)) {
        held.delete(one.name);
      }
    });
    log.debug("Leaving whenFenced(). One operation.");
    return;
  }
  log.debug("Leaving whenFenced(). Fatal.");
  // A write fenced for the membership is usually the FIRST thing to find a
  // stall out — work queued behind the stall writes before the overdue timer
  // gets its turn — so an overdue pending timer is measured here too.
  if (heartbeatTimer && err && err.reason === 'node') {
    noteLateness(monotonicMs() - heartbeatDueMono);
  }
  failStop('STS-CLUSTER-0011', 'A write was fenced: ' + message +
           stallClause());
}

function install(theDriver) {
  log.debug("Entering install().");
  driver = theDriver;
  if (driver && typeof driver.setFence === 'function') {
    driver.setFence(fenceFor, whenFenced);
  }
  log.debug("Leaving install().");
}

// ---------------------------------------------------------------------------
// THE GATE. Called by `persistence.js` with the open driver, before anything
// is restored. Resolves when this node may proceed; rejects with a refusal
// the service turns into a non-zero exit.
// ---------------------------------------------------------------------------
function gate(theDriver) {
  log.debug("Entering gate().");
  resolved = resolve();
  if (resolved.refused) {
    log.debug("Leaving gate(). Refused by configuration.");
    return Promise.reject(new Error(resolved.refused));
  }
  if (resolved.mode === 'off') {
    log.info('cluster: off (' + resolved.why + '). This process coordinates ' +
             'with others only through the change log, which is correct for ' +
             'one container and NOT for several.');
    log.debug("Leaving gate(). Off.");
    return Promise.resolve({ mode: 'off' });
  }
  if (!theDriver || typeof theDriver.joinCluster !== 'function') {
    log.debug("Leaving gate(). The driver cannot cluster.");
    return Promise.reject(new Error(errorCodes.tag('STS-CLUSTER-0007') +
      'cluster.mode resolved to ' + resolved.mode + ' and the open store has ' +
      'no cluster functions.'));
  }
  if (process.env.STS_REQUEST_WORKER && process.env[ENV_NODE]) {
    log.debug("Leaving gate(). A worker attaches.");
    return attach(theDriver);
  }
  if (resolved.mode === 'active-active') {
    const verdict = capabilities.report();
    if (verdict.unknownAccepted.length) {
      log.warn('cluster: cluster.acceptMissingCapabilities names ' +
               verdict.unknownAccepted.join(', ') + ', which this build does ' +
               'not know. They accept nothing.');
    }
    if (!verdict.ready) {
      log.debug("Leaving gate(). Active-active refused.");
      return Promise.reject(new Error(errorCodes.tag('STS-CLUSTER-0009') +
        'cluster.mode is active-active and this build does not yet provide ' +
        verdict.missing.length + ' capabilit' +
        (verdict.missing.length === 1 ? 'y' : 'ies') + ' that mode depends ' +
        'on: ' + verdict.missing.join(', ') + '. Each is a way two nodes give ' +
        'different answers — /admin/cluster and cluster/cluster_capabilities.js ' +
        'describe them. Run active-passive (cluster.mode=auto in product ' +
        'mode), or name the ones you accept in ' +
        'cluster.acceptMissingCapabilities.'));
    }
    if (verdict.acceptedMissing.length) {
      log.warn(errorCodes.tag('STS-CLUSTER-0020') + 'cluster: active-active ' +
               'with ' + verdict.acceptedMissing.length + ' capabilit' +
               (verdict.acceptedMissing.length === 1 ? 'y' : 'ies') +
               ' accepted as MISSING: ' +
               verdict.acceptedMissing.join(', ') + '. Each is a known way ' +
               'the nodes of this cluster disagree.');
    }
  }
  install(theDriver);
  role = 'front';
  nodeId = nodeCrypto.randomUUID();
  log.debug("Leaving gate(). Joining.");
  return join().then(function () {
    if (resolved.mode === 'active-passive') {
      return waitForServiceLease();
    }
    return null;
  }).then(function () {
    // THE WORKERS INHERIT THIS. Set on the process environment rather than
    // threaded into `request_pool.js`, because that module forks with
    // `Object.assign({}, process.env, …)` and every child this process makes
    // from here on is a process of this node.
    process.env[ENV_NODE] = nodeId;
    process.env[ENV_MODE] = resolved.mode;
    if (held.has(SERVICE_LEASE)) {
      process.env[ENV_SERVICE_TOKEN] = String(held.get(SERVICE_LEASE));
    }
    return { mode: resolved.mode, nodeId: nodeId };
  });
}

function join() {
  log.debug("Entering join().");
  const node = {
    nodeId: nodeId, name: nodeName(), mode: resolved.mode,
    version: versionString(), fingerprint: '', ttlMs: ttlMs(),
    info: nodeInfo()
  };
  log.debug("Leaving join().");
  return driver.joinCluster(node).then(function (answer) {
    if (!answer.joined) {
      throw new Error(errorCodes.tag('STS-CLUSTER-0002') + 'cluster: this ' +
        'node (' + resolved.mode + ') was refused membership: ' +
        describeDiffering(answer.differing) + '. Every node against one store ' +
        'must run the same cluster mode.');
    }
    joinedAt = Date.now();
    lastRenewOk = monotonicMs();
    log.info('cluster: node ' + nodeId + ' (' + node.name + ') joined in ' +
             resolved.mode + ' mode; ' + answer.live + ' other live ' +
             'node(s). Heartbeat every ' + heartbeatMs() + 'ms, lifetime ' +
             ttlMs() + 'ms by the database clock.');
    scheduleHeartbeat();
  });
}

function describeDiffering(rows) {
  log.debug("Entering describeDiffering().");
  log.debug("Leaving describeDiffering().");
  return (rows || []).map(function (row) {
    return row.name + ' (' + row.nodeId + ', ' + row.mode + ', ' +
           (row.version || 'unknown version') + ')';
  }).join('; ');
}

function versionString() {
  log.debug("Entering versionString().");
  try {
    const version = require('../common/version');
    const v = version.load();
    log.debug("Leaving versionString().");
    return String((v && v.version) || '');
  } catch (e) {
    log.debug("Caught in versionString(): " + ((e && e.message) || e));
    log.debug("Leaving versionString(). Unknown.");
    return '';
  }
}

function nodeInfo() {
  log.debug("Entering nodeInfo().");
  log.debug("Leaving nodeInfo().");
  return { pid: process.pid, host: os.hostname(),
           port: config.value('global.port') };
}

// A worker of this node: no row of its own and no heartbeat, the same fence.
function attach(theDriver) {
  log.debug("Entering attach().");
  install(theDriver);
  role = 'worker';
  nodeId = String(process.env[ENV_NODE]);
  const token = Number(process.env[ENV_SERVICE_TOKEN] || 0);
  if (token) {
    held.set(SERVICE_LEASE, token);
  }
  if (resolved.mode === 'active-passive' && !token) {
    log.debug("Leaving attach(). No service token.");
    return Promise.reject(new Error(errorCodes.tag('STS-CLUSTER-0021') +
      'cluster: a request worker of an active-passive node was forked ' +
      'without the service lease\'s token.'));
  }
  log.info('cluster: request worker ' + process.pid + ' attached to node ' +
           nodeId + ' (' + resolved.mode + ').');
  log.debug("Leaving attach().");
  return Promise.resolve({ mode: resolved.mode, nodeId: nodeId,
                           worker: true });
}

// ---------------------------------------------------------------------------
// THE HEARTBEAT. One statement renews the row and every lease this node holds.
// ---------------------------------------------------------------------------
function scheduleHeartbeat() {
  log.debug("Entering scheduleHeartbeat().");
  if (heartbeatTimer || stopping) {
    log.debug("Leaving scheduleHeartbeat().");
    return;
  }
  heartbeatDueMono = monotonicMs() + heartbeatMs();
  heartbeatTimer = setTimeout(function () {
    heartbeatTimer = null;
    noteLateness(monotonicMs() - heartbeatDueMono);
    beat().then(function () {
      scheduleHeartbeat();
    }, function (e) {
      log.debug("Caught in scheduleHeartbeat(): " + ((e && e.message) || e));
      scheduleHeartbeat();
    });
  }, heartbeatMs());
  if (heartbeatTimer.unref) {
    heartbeatTimer.unref();
  }
  log.debug("Leaving scheduleHeartbeat().");
}

// ---------------------------------------------------------------------------
// A HEARTBEAT THAT DID NOT RUN IS NOT A HEARTBEAT THAT FAILED — AND THE
// DIFFERENCE CHANGES WHAT IS SAID, NOT WHAT IS DONE (2026-09-14).
//
// The timer is a JavaScript timer, so a synchronous computation on this
// thread holds it: a burst of realm key generations measured at 7.7s did, and
// the node's row expired by the database's clock while nothing here ran. On
// the next turn the heartbeat's UPDATE (or a fenced write, which usually comes
// first) found the row dead and the node exited, which is RIGHT — while it
// was stalled another node could have taken its leases, and a stall is
// indistinguishable from a partition to everybody else. What was wrong was the
// sentence: `STS-CLUSTER-0011` said the row "has expired or been left", which
// sends an operator to the database and the network rather than to the CPU.
//
// So the lateness of every beat is measured against the monotonic clock, a
// stall of a heartbeat or more is logged when it happens (`STS-CLUSTER-0025`),
// and the fail-stop messages name the stall when one was the likely cause. The
// fence itself is untouched: it is the database clock's, and the only thing
// that keeps two nodes from both believing they hold a lease.
// ---------------------------------------------------------------------------
function noteLateness(lateMs) {
  log.debug("Entering noteLateness().");
  if (!(lateMs >= heartbeatMs())) {
    log.debug("Leaving noteLateness(). On time.");
    return;
  }
  lastStall = { ms: lateMs, atMono: monotonicMs() };
  log.warn(errorCodes.tag('STS-CLUSTER-0025') + 'cluster: this node\'s ' +
           'heartbeat ran ' + lateMs + 'ms late — the event loop was busy ' +
           'and nothing on it ran, the heartbeat included. The membership ' +
           'lifetime is ' + ttlMs() + 'ms by the database clock; a stall ' +
           'longer than ' + (ttlMs() - heartbeatMs()) + 'ms costs this node ' +
           'its membership and it exits.');
  log.debug("Leaving noteLateness(). Stalled.");
}

// The clause a fail-stop adds when a recent stall is the likely reason the row
// expired: within the last lifetime, and long enough to matter.
function stallClause() {
  log.debug("Entering stallClause().");
  if (!lastStall || monotonicMs() - lastStall.atMono > 2 * ttlMs() ||
      lastStall.ms < ttlMs() - heartbeatMs()) {
    log.debug("Leaving stallClause(). None.");
    return '';
  }
  log.debug("Leaving stallClause(). A stall.");
  return ' The likely cause is THIS NODE, not the store: its event loop was ' +
         'blocked for ' + lastStall.ms + 'ms, past its ' + ttlMs() + 'ms ' +
         'lifetime, so no heartbeat could run.';
}

function beat() {
  log.debug("Entering beat().");
  if (stopping || role !== 'front') {
    log.debug("Leaving beat(). Not beating.");
    return Promise.resolve();
  }
  const startedAt = monotonicMs();
  log.debug("Leaving beat().");
  return driver.heartbeat(nodeId, ttlMs(), nodeInfo()).then(function (answer) {
    if (!answer.alive) {
      failStop('STS-CLUSTER-0005', 'Its membership row had already expired ' +
               'when it was renewed, so another node may have taken over ' +
               'what it held. A node does not come back from that; it is ' +
               'restarted.' + stallClause());
      return;
    }
    lastRenewOk = startedAt;
    heartbeatFailures = 0;
    lastHeartbeatError = '';
    const renewed = new Map(answer.leases.map(function (one) {
      return [one.name, one.token];
    }));
    Array.from(held.keys()).forEach(function (name) {
      if (renewed.get(name) === held.get(name)) {
        return;
      }
      held.delete(name);
      if (name === SERVICE_LEASE && mode() === 'active-passive') {
        failStop('STS-CLUSTER-0006', 'It lost the service lease, so another ' +
                 'node may be serving.');
        return;
      }
      const wanted = roles.get(name);
      log.warn('cluster: node ' + nodeId + ' lost the "' + name + '" lease.');
      if (wanted && typeof wanted.onLose === 'function') {
        try {
          wanted.onLose();
        } catch (e) {
          log.debug("Caught in beat(): " + ((e && e.message) || e));
        }
      }
    });
    refreshState();
    return campaign();
  }, function (err) {
    heartbeatFailures += 1;
    lastHeartbeatError = err.message;
    const since = monotonicMs() - lastRenewOk;
    // The margin is one heartbeat: a renewal that has not landed by
    // `ttl - heartbeat` since the last one that did cannot be relied on to land
    // before the row expires by the database's clock.
    if (since >= ttlMs() - heartbeatMs()) {
      failStop('STS-CLUSTER-0004', 'It has not renewed its membership for ' +
               since + 'ms against a lifetime of ' + ttlMs() + 'ms (' +
               err.message + '). The other nodes may already treat it as ' +
               'dead and take over its leases.');
      return;
    }
    log.warn(errorCodes.tag('STS-CLUSTER-0003') + 'cluster: a heartbeat ' +
             'failed (' + err.message + '); ' + since + 'ms since the last ' +
             'renewal, ' + (ttlMs() - since) + 'ms of lifetime left.');
  });
}

// Asks for every role some module wants led and this node does not hold.
function campaign() {
  log.debug("Entering campaign().");
  let chain = Promise.resolve();
  roles.forEach(function (handlers, name) {
    if (held.has(name)) {
      return;
    }
    chain = chain.then(function () {
      return acquire(name).then(function (answer) {
        if (answer.held && typeof handlers.onGain === 'function') {
          try {
            handlers.onGain(answer.token);
          } catch (e) {
            log.debug("Caught in campaign(): " + ((e && e.message) || e));
          }
        }
      });
    });
  });
  log.debug("Leaving campaign().");
  return chain;
}

// ---------------------------------------------------------------------------
// LEASES.
// ---------------------------------------------------------------------------
function acquire(name) {
  log.debug("Entering acquire(). name=" + name);
  if (!enabled()) {
    log.debug("Leaving acquire(). Not clustered.");
    return Promise.resolve({ held: true, token: 0, unclustered: true });
  }
  log.debug("Leaving acquire().");
  return driver.acquireLease(name, nodeId, ttlMs()).then(function (answer) {
    if (answer.held) {
      const was = held.get(name);
      held.set(name, answer.token);
      if (was !== answer.token) {
        log.info('cluster: node ' + nodeId + ' holds the "' + name +
                 '" lease at token ' + answer.token + '.');
      }
    }
    return answer;
  }, function (err) {
    log.warn(errorCodes.tag('STS-CLUSTER-0012') + 'cluster: asking for the "' +
             name + '" lease failed: ' + err.message);
    return { held: false, error: err.message };
  });
}

function waitForServiceLease() {
  log.debug("Entering waitForServiceLease().");
  let announced = false;
  log.debug("Leaving waitForServiceLease().");
  return new Promise(function (resolve) {
    function attempt() {
      log.debug("Entering attempt().");
      if (stopping) {
        log.debug("Leaving attempt(). Stopping.");
        return;
      }
      acquire(SERVICE_LEASE).then(function (answer) {
        if (answer.held) {
          log.info('cluster: node ' + nodeId + ' is the ACTIVE node ' +
                   '(service lease token ' + answer.token + '). Restoring ' +
                   'the store and binding.');
          resolve(answer);
          return;
        }
        if (!announced) {
          announced = true;
          log.info('cluster: node ' + nodeId + ' is a STANDBY. The service ' +
                   'lease is held by ' + (answer.holder || 'nobody reachable') +
                   '; nothing is restored and nothing binds until it is ' +
                   'released or expires. Asking again every ' + heartbeatMs() +
                   'ms.');
        }
        // NOT unref'd: a standby has nothing else keeping it alive, and a
        // standby that exited because it was idle would not be one.
        setTimeout(attempt, heartbeatMs());
      });
      log.debug("Leaving attempt().");
    }
    attempt();
  });
}

// A module that wants a role led by exactly one node. The role is campaigned
// for on every heartbeat; `onGain(token)` and `onLose()` say when this node
// starts and stops holding it.
function lead(name, handlers) {
  log.debug("Entering lead(). name=" + name);
  roles.set(name, handlers || {});
  log.debug("Leaving lead().");
  if (!enabled()) {
    if (handlers && typeof handlers.onGain === 'function') {
      handlers.onGain(0);
    }
    return;
  }
  campaign();
}

function holds(name) {
  log.debug("Entering holds().");
  log.debug("Leaving holds().");
  return !enabled() || held.has(name);
}

// Runs `fn` with `name` held, and every transaction it opens fenced by that
// lease's token. Resolves `{ held: false, holder }` without running it when
// another node holds the lease.
function withLease(name, fn) {
  log.debug("Entering withLease(). name=" + name);
  log.debug("Leaving withLease().");
  return acquire(name).then(function (answer) {
    if (!answer.held) {
      return { held: false, holder: answer.holder || '' };
    }
    const outer = leaseContext.getStore();
    const leases = ((outer && outer.leases) || []).concat(
      answer.unclustered ? [] : [{ name: name, token: answer.token }]);
    return leaseContext.run({ leases: leases }, function () {
      return Promise.resolve().then(fn).then(function (result) {
        return { held: true, result: result };
      });
    });
  });
}

// ---------------------------------------------------------------------------
// AGREEMENT: the fingerprint, once the key-encryption key is open.
// ---------------------------------------------------------------------------
function agree(keystore) {
  log.debug("Entering agree().");
  if (!enabled() || role !== 'front') {
    log.debug("Leaving agree(). Nothing to agree.");
    return Promise.resolve({ agreed: true, skipped: true });
  }
  const values = {};
  AGREEMENT_SETTINGS.forEach(function (key) {
    try {
      values[key] = config.value(key);
    } catch (e) {
      log.debug("Caught in agree(): " + ((e && e.message) || e));
      values[key] = null;
    }
  });
  const canonical = JSON.stringify(values, Object.keys(values).sort());
  const keyed = keystore && typeof keystore.keyedDigest === 'function'
    ? keystore.keyedDigest('cluster-agreement', canonical) : null;
  fingerprint = keyed || ('unkeyed:' + nodeCrypto.createHash('sha256')
    .update(canonical).digest('base64url'));
  log.debug("Leaving agree().");
  return driver.agreeFingerprint(nodeId, fingerprint).then(function (answer) {
    if (answer.differing.length) {
      throw new Error(errorCodes.tag('STS-CLUSTER-0002') + 'cluster: this ' +
        'node\'s settings differ from ' + answer.differing.length + ' live ' +
        'node(s): ' + describeDiffering(answer.differing) + '. One of ' +
        AGREEMENT_SETTINGS.join(', ') + ' has a different value here, and ' +
        'two nodes with different values answer the same request two ways — ' +
        'a ticket sealed under one krbtgt key does not decrypt under the ' +
        'other. Nothing was written.');
    }
    log.info('cluster: node ' + nodeId + ' agrees with every live node on ' +
             AGREEMENT_SETTINGS.length + ' shared setting(s)' +
             (keyed ? '' : ' (UNKEYED digest: no key-encryption key is open)') +
             '.');
    return { agreed: true };
  });
}

// ---------------------------------------------------------------------------
// LEAVING, on SIGTERM/SIGINT. The leases expire now so a standby takes over in
// one heartbeat rather than a whole lifetime.
// ---------------------------------------------------------------------------
function leave() {
  log.debug("Entering leave().");
  if (!enabled() || role !== 'front') {
    log.debug("Leaving leave(). Nothing to leave.");
    return Promise.resolve();
  }
  stopping = true;
  if (heartbeatTimer) {
    clearTimeout(heartbeatTimer);
    heartbeatTimer = null;
  }
  log.debug("Leaving leave().");
  return driver.leaveCluster(nodeId).then(function () {
    log.info('cluster: node ' + nodeId + ' left; its leases were released.');
    held.clear();
  }, function (err) {
    log.warn(errorCodes.tag('STS-CLUSTER-0010') + 'cluster: leaving failed (' +
             err.message + '); this node\'s row and leases expire on their ' +
             'own within ' + ttlMs() + 'ms.');
  });
}

// ---------------------------------------------------------------------------
// WHAT THIS NODE SAYS ABOUT ITSELF, synchronously, and what the store says
// about every node, asynchronously. `/admin/cluster` and the API draw both.
// ---------------------------------------------------------------------------
function status() {
  log.debug("Entering status().");
  const r = resolved || resolve();
  log.debug("Leaving status().");
  return {
    mode: r.mode, why: r.why || '', refused: r.refused || null,
    configured: String(config.value('cluster.mode')),
    nodeId: nodeId, name: nodeName(), role: role,
    joinedAt: joinedAt ? new Date(joinedAt).toISOString() : null,
    heartbeatMs: heartbeatMs(), ttlMs: ttlMs(),
    lastStallMs: lastStall ? lastStall.ms : 0,
    msSinceRenewal: lastRenewOk ? monotonicMs() - lastRenewOk : null,
    heartbeatFailures: heartbeatFailures,
    lastHeartbeatError: lastHeartbeatError || null,
    leases: Array.from(held.entries()).map(function (pair) {
      return { name: pair[0], token: pair[1] };
    }),
    fingerprintSet: !!fingerprint,
    agreementSettings: AGREEMENT_SETTINGS.slice(),
    capabilities: capabilities.report()
  };
}

function state() {
  log.debug("Entering state().");
  if (!driver || typeof driver.clusterState !== 'function' ||
      mode() === 'off') {
    log.debug("Leaving state(). No cluster.");
    return Promise.resolve({ available: false, self: status() });
  }
  log.debug("Leaving state().");
  return driver.clusterState().then(function (answer) {
    answer.available = true;
    answer.self = status();
    // THE FINGERPRINT ITSELF IS NOT HANDED OUT — only whether a node's agrees
    // with this one's. It is a keyed digest and reveals nothing, and a page
    // that printed it would still invite somebody to compare it by eye.
    // Unknown (null) in a request worker, which never computes one.
    answer.nodes = answer.nodes.map(function (node) {
      const copy = Object.assign({}, node);
      copy.agrees = !node.fingerprint || !fingerprint ? null
        : node.fingerprint === fingerprint;
      delete copy.fingerprint;
      return copy;
    });
    return answer;
  });
}

// THE LAST STATE READ, for a console page that is drawn synchronously. Read on
// every heartbeat by a front process, and on demand — no more than once a
// heartbeat — by whichever process draws the page, so a request worker serving
// /admin/cluster is at most one heartbeat behind rather than empty.
let lastState = null;
let lastStateAt = 0;
let refreshing = null;

function refreshState() {
  log.debug("Entering refreshState().");
  if (refreshing) {
    log.debug("Leaving refreshState(). One is running.");
    return refreshing;
  }
  refreshing = state().then(function (answer) {
    lastState = answer;
    lastStateAt = Date.now();
    refreshing = null;
    return answer;
  }, function (err) {
    refreshing = null;
    log.debug("Caught in refreshState(): " + ((err && err.message) || err));
    return lastState;
  });
  log.debug("Leaving refreshState().");
  return refreshing;
}

function snapshot() {
  log.debug("Entering snapshot().");
  if (enabled() && Date.now() - lastStateAt > heartbeatMs()) {
    refreshState();
  }
  log.debug("Leaving snapshot().");
  return { state: lastState,
           ageMs: lastStateAt ? Date.now() - lastStateAt : null };
}

// The environment a request worker is forked with. See the header.
function forkEnvironment() {
  log.debug("Entering forkEnvironment().");
  const env = {};
  if (nodeId) {
    env[ENV_NODE] = nodeId;
    env[ENV_MODE] = mode();
  }
  if (held.has(SERVICE_LEASE)) {
    env[ENV_SERVICE_TOKEN] = String(held.get(SERVICE_LEASE));
  }
  log.debug("Leaving forkEnvironment().");
  return env;
}

function currentNodeId() {
  log.debug("Entering currentNodeId().");
  log.debug("Leaving currentNodeId().");
  return nodeId;
}

// For tests.
function reset(options) {
  log.debug("Entering reset().");
  if (heartbeatTimer) {
    clearTimeout(heartbeatTimer);
    heartbeatTimer = null;
  }
  driver = null;
  resolved = null;
  nodeId = '';
  role = 'none';
  joinedAt = 0;
  lastRenewOk = 0;
  heartbeatFailures = 0;
  lastHeartbeatError = '';
  stopping = false;
  fingerprint = '';
  lastState = null;
  lastStateAt = 0;
  refreshing = null;
  held.clear();
  roles.clear();
  [ENV_NODE, ENV_MODE, ENV_SERVICE_TOKEN].forEach(function (name) {
    delete process.env[name];
  });
  if (options && typeof options.exit === 'function') {
    exitProcess = options.exit;
  }
  log.debug("Leaving reset().");
}

// DECLARED AT REQUIRE TIME, like every capability: `gate()` holds active-active
// to the table before anything later in startup runs, so a capability can only
// be the CODE being present — a runtime failure of either is fatal on its own
// (a node that cannot join or agree does not start).
capabilities.provide('cluster.membership');
capabilities.provide('cluster.settings-agreement');

module.exports = {
  SERVICE_LEASE: SERVICE_LEASE,
  AGREEMENT_SETTINGS: AGREEMENT_SETTINGS,
  resolve: resolve,
  mode: mode,
  enabled: enabled,
  isActiveActive: isActiveActive,
  gate: gate,
  agree: agree,
  beat: beat,
  acquire: acquire,
  lead: lead,
  holds: holds,
  withLease: withLease,
  leave: leave,
  status: status,
  state: state,
  refreshState: refreshState,
  snapshot: snapshot,
  forkEnvironment: forkEnvironment,
  nodeId: currentNodeId,
  reset: reset
};
