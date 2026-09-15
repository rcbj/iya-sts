'use strict';
//
// File: ldap/ldap_cluster_connections.js
//
// ===========================================================================
// A SIGN-OUT THAT REACHES A DIRECTORY CONNECTION ON ANOTHER NODE, AND A SESSION
// INVENTORY THAT LISTS IT (2026-09-14, #46 section 4).
//
// In LDAP the connection IS the session (RFC 4511 section 4.2), so the only
// sign-out the protocol has is the socket closing, and only the process that
// holds the socket can close it. Inside one container that was solved twice
// already: a request worker reads the front process's MIRROR of what is open
// and states what it wants closed on its response (`LDAP_DROP_HEADER`,
// `common/request_pool.js`). Neither crosses a CONTAINER. A bind held on node A
// was invisible to `/admin/sessions` answered by node B, and a global sign-out
// answered by B ended everything B could see, said so, and left A's socket
// signed in.
//
// TWO THINGS, and they are kept apart because they fail differently:
//
//   * **THE INSTRUCTION CLOSES.** A sign-out writes one row to
//     `ldap.clusterSignOuts`, keyed by the identity key, and it is written
//     through the minted journal of the process answering the sign-out — the
//     flush the cluster barrier holds that response for — so by the time the
//     person is told they are signed out the instruction is COMMITTED. Every
//     other node's replication applier then hands the row to this store's
//     `reconcile.restore`, and the process there that holds sockets closes
//     every connection bound as that identity. **IT IS KEYED BY IDENTITY AND
//     NOT BY CONNECTION**, which is the property that matters: a connection
//     node A accepted a moment before the sign-out, which no listing could yet
//     have shown, is closed all the same.
//   * **THE TABLE LISTS.** The socket-holding process of each node writes ONE
//     row to `ldap.clusterConnections`, keyed by its node id, holding what it
//     has bound — debounced, on the same three changes that already publish
//     the in-container mirror. Every process reads the other nodes' rows into
//     `boundConnections()`, so a sign-out inventory and `/admin/sessions` list
//     them, and a row naming a node whose membership has expired is not listed
//     and is deleted by the next maintenance pass.
//
// ---------------------------------------------------------------------------
// WHAT A SIGN-OUT MAY SAY ABOUT ANOTHER NODE'S SOCKET, AND IT IS NOT "CLOSED".
//
// The barrier makes the instruction committed before the answer; it cannot
// make the other node ACT before the answer, because acting is that node
// applying the change log — a LISTEN/NOTIFY nudge, normally well under a
// second, and the poll interval at worst. So a row on another node is
// reported as INSTRUCTED, never as closed, and the page and the JSON say that
// the close is asynchronous. Waiting for an acknowledgement would put a
// sign-out's answer on the health of every other node, and a node that has
// died holds no socket to wait for.
//
// **IT CLOSES WHAT IS BOUND WHEN THE INSTRUCTION ARRIVES, NOT WHAT WAS BOUND
// WHEN IT WAS WRITTEN.** The two instants are on two machines' clocks, and
// comparing a bind time on A against a sign-out time on B would let a
// connection bound a moment BEFORE the sign-out survive whenever A's clock ran
// ahead — the failure this exists to prevent. Closing everything bound when
// the row arrives can also close a connection bound in the replication window
// AFTER the sign-out, which costs that client one reconnect; a closed socket
// that should have stayed open is the safe direction. An instruction older
// than `INSTRUCTION_TTL_MS` by the arriving node's clock is ignored, so a hole
// in the change log applied minutes late closes nothing.
//
// A node never acts on its OWN instruction: the process that answered the
// sign-out already closed its node's sockets (directly, or through the
// response header in a dispatched container), and acting again here would
// close what was bound in the moment since.
//
// ---------------------------------------------------------------------------
// ACTIVE-ACTIVE ONLY. In `off` there is one node; in `active-passive` only the
// lease holder binds anything. Everywhere else this module writes nothing and
// lists nothing, so a single container behaves exactly as it did.
//
// A LIBRARY (rule 3): it registers no route. It requires config, realms and
// the error-code table at the top and `cluster/cluster.js` LAZILY, and it
// reaches the sockets through hooks `ldap_server.js` installs — that module
// requires this one, and a require back would close a cycle.
// ===========================================================================

const bunyan = require('bunyan');
const nodeCrypto = require('crypto');
const config = require('../common/config');
const realms = require('../common/realms');
const errorCodes = require('../common/error_codes');
const capabilities = require('../cluster/cluster_capabilities');

const log = bunyan.createLogger({ name: 'sts-ldap-cluster' });
config.registerLogger(log);

// A burst of connects and closes publishes once. Longer than the setImmediate
// the in-container mirror uses, because this one is a sealed database row
// rather than an IPC message.
const PUBLISH_DELAY_MS = 250;
// How often a socket-holding process deletes the rows of nodes that are no
// longer members, and instructions past their lifetime.
const MAINTAIN_EVERY_MS = 15 * 1000;
// How long an instruction is acted on after it was written. Far longer than
// any replication delay a live node has, far shorter than a hole that is
// applied late (ten minutes, persistence_replication.js).
const INSTRUCTION_TTL_MS = 2 * 60 * 1000;

// node id -> { node, name, at, rows: [...] }
const connectionsByNode = realms.sharedMap({
  persist: 'ldap.clusterConnections' });

// identity key -> { key, at, node, nonce }
const signOuts = realms.sharedMap({
  persist: 'ldap.clusterSignOuts',
  reconcile: {
    restore: function (key, incoming, held) {
      log.debug("Entering restore().");
      log.debug("Leaving restore().");
      return instructionArrived(key, incoming, held);
    }
  } });

// What `ldap_server.js` installs: `{ holdsSockets(), localRows(),
// closeLocal(key) }`. Null in a process that loaded this file alone.
let hooks = null;
let publishTimer = null;
let maintainTimer = null;
// Replaced by tests: the cluster module, and the clock.
let clusterModule = null;
let now = function () {
  log.debug("Entering now().");
  log.debug("Leaving now().");
  return Date.now();
};
// What this process has done, for `/admin/ldap/service` and a test.
const stats = { published: 0, instructed: 0, instructionsActedOn: 0,
                closedByInstruction: 0, staleInstructions: 0,
                nodeRowsSwept: 0 };

function cluster() {
  log.debug("Entering cluster().");
  if (!clusterModule) {
    // LAZY: cluster.js requires nothing of the directory, but this file is
    // required at 21 and there is no reason to load the cluster layer into a
    // test that only wanted the directory.
    clusterModule = require('../cluster/cluster');
  }
  log.debug("Leaving cluster().");
  return clusterModule;
}

function active() {
  log.debug("Entering active().");
  let on = false;
  try {
    on = cluster().isActiveActive() && cluster().enabled();
  } catch (e) {
    log.debug("Caught in active(): " + ((e && e.message) || e));
    on = false;
  }
  log.debug("Leaving active(). " + on);
  return on;
}

function ownNode() {
  log.debug("Entering ownNode().");
  let id = '';
  try {
    id = String(cluster().nodeId() || '');
  } catch (e) {
    log.debug("Caught in ownNode(): " + ((e && e.message) || e));
    id = '';
  }
  log.debug("Leaving ownNode().");
  return id;
}

function install(theHooks) {
  log.debug("Entering install().");
  hooks = theHooks || null;
  log.debug("Leaving install().");
}

function holdsSockets() {
  log.debug("Entering holdsSockets().");
  let holds = false;
  try {
    holds = !!(hooks && hooks.holdsSockets());
  } catch (e) {
    log.debug("Caught in holdsSockets(): " + ((e && e.message) || e));
    holds = false;
  }
  log.debug("Leaving holdsSockets(). " + holds);
  return holds;
}

// ---------------------------------------------------------------------------
// THE TABLE.
// ---------------------------------------------------------------------------

// Something about this process's own connections changed. Called beside the
// in-container publish, from the three places that change the set.
//
// **A CHANGE NOTED WHILE A PUBLISH IS PENDING PUBLISHES AGAIN AFTER IT.** The
// first live two-node run listed two binds of five on the other node: the
// connect armed the timer, the bind — a password hash in product mode, longer
// than the delay — landed after the timer fired and found nothing to arm, so
// the row went out with the connection still anonymous and was never
// corrected.
let publishAgain = false;

function noteLocalChange() {
  log.debug("Entering noteLocalChange().");
  if (publishTimer) {
    publishAgain = true;
    log.debug("Leaving noteLocalChange(). One is pending; again after it.");
    return;
  }
  if (!active() || !holdsSockets()) {
    log.debug("Leaving noteLocalChange(). Nothing to schedule.");
    return;
  }
  publishTimer = setTimeout(function () {
    publishTimer = null;
    const again = publishAgain;
    publishAgain = false;
    publishNow();
    if (again) {
      noteLocalChange();
    }
  }, PUBLISH_DELAY_MS);
  if (publishTimer.unref) {
    publishTimer.unref();
  }
  armMaintenance();
  log.debug("Leaving noteLocalChange(). Scheduled.");
}

// Writes this node's row: what it holds, without the sockets. A node holding
// nothing has no row rather than an empty one, so the table is the nodes with
// something to list.
function publishNow() {
  log.debug("Entering publishNow().");
  if (!active() || !holdsSockets()) {
    log.debug("Leaving publishNow(). Not publishing.");
    return false;
  }
  const node = ownNode();
  if (!node) {
    log.debug("Leaving publishNow(). No node id.");
    return false;
  }
  let rows = [];
  try {
    rows = (hooks.localRows() || []).filter(function (row) {
      return row && row.key;
    }).map(function (row) {
      return { id: String(row.id), dn: row.dn || '', key: row.key,
               secure: !!row.secure, port: row.port || 0,
               boundAt: row.boundAt || 0 };
    });
  } catch (e) {
    log.warn(errorCodes.tag('STS-LDAP-0095') + 'ldap: this node\'s bound ' +
             'connections could not be read for the cluster table (' +
             ((e && e.message) || e) + '); other nodes list what was ' +
             'published last. A sign-out still reaches them — the ' +
             'instruction is by identity, not by listed connection.');
    log.debug("Leaving publishNow(). Could not read.");
    return false;
  }
  if (!rows.length) {
    if (connectionsByNode.has(node)) {
      connectionsByNode.delete(node);
      commitNow('nothing bound');
    }
    log.debug("Leaving publishNow(). Nothing bound.");
    return true;
  }
  let name = '';
  try {
    name = String(cluster().status().name || '');
  } catch (e) {
    log.debug("Caught in publishNow(): " + ((e && e.message) || e));
    name = '';
  }
  connectionsByNode.set(node, { node: node, name: name, at: now(),
                                rows: rows });
  commitNow('publish');
  stats.published += 1;
  log.debug("Leaving publishNow(). " + rows.length + " row(s).");
  return true;
}

// ---------------------------------------------------------------------------
// COMMITTED NOW, NOT WITH SOMEBODY ELSE'S NEXT WRITE.
//
// A minted write only journals its key; what commits the journal is a flush,
// and the doors that start one are a request's (the barrier holds a writing
// response for `flushMinted()`, a request worker announces its commit) and a
// directory, realm or setting change. A socket event is none of those. So the
// first live two-node run published a bind's row and it sat in the journal
// until an unrelated write flushed it — three binds of six were never listed
// on the other node within four seconds, and the three that were had been
// carried out by the probe's own next user creation. Same fix as
// `spiffe_ca.js` and `credentials.js`'s bootstrap: flush the minted journal
// right after writing. It coalesces with a flush already in flight.
// ---------------------------------------------------------------------------
function commitNow(why) {
  log.debug("Entering commitNow(). " + why);
  let persistence = null;
  try {
    persistence = require('../persistence/persistence');
  } catch (e) {
    log.debug("Caught in commitNow(): " + ((e && e.message) || e));
    log.debug("Leaving commitNow(). No store.");
    return Promise.resolve(null);
  }
  log.debug("Leaving commitNow().");
  return Promise.resolve().then(function () {
    return persistence.flushMinted();
  }).catch(function (e) {
    log.warn(errorCodes.tag('STS-LDAP-0095') + 'ldap: the cluster ' +
             'connection table could not be committed (' + why + '): ' +
             ((e && e.message) || e) + '. It is retried with the next ' +
             'flush; until then other nodes list what was committed last.');
    return null;
  });
}

// The node ids the last cluster state read says are members, or null when this
// process has no state to go on — in which case every row is listed, because
// over-listing a dead node's connections is the honest failure and hiding a
// live one's is not.
function liveNodes() {
  log.debug("Entering liveNodes().");
  let snap = null;
  try {
    snap = cluster().snapshot();
  } catch (e) {
    log.debug("Caught in liveNodes(): " + ((e && e.message) || e));
    snap = null;
  }
  const state = snap && snap.state;
  if (!state || !state.available || !Array.isArray(state.nodes)) {
    log.debug("Leaving liveNodes(). No state.");
    return null;
  }
  log.debug("Leaving liveNodes().");
  return liveFrom(state, snap.ageMs || 0);
}

function liveFrom(state, ageMs) {
  log.debug("Entering liveFrom().");
  // The database clock the state was read against, moved on by how long ago
  // it was read — every expiry here is by that clock, never this machine's.
  const at = (Number(state.now) || 0) + (Number(ageMs) || 0);
  const out = new Set();
  state.nodes.forEach(function (node) {
    if (!Number(node.leftAt) && Number(node.expiresAt) > at) {
      out.add(String(node.nodeId));
    }
  });
  log.debug("Leaving liveFrom(). " + out.size + " live.");
  return out;
}

// Every connection OTHER nodes have published, as `boundConnections()` rows
// without a socket. The id carries the node, because connection ids are
// per-listener and two nodes can both hold a `127.0.0.1:40000`.
function remoteRows() {
  log.debug("Entering remoteRows().");
  if (!active()) {
    log.debug("Leaving remoteRows(). Not active-active.");
    return [];
  }
  const self = ownNode();
  const live = liveNodes();
  const out = [];
  connectionsByNode.forEach(function (entry, node) {
    if (!entry || node === self || (live && !live.has(node))) {
      return;
    }
    (entry.rows || []).forEach(function (row) {
      const forgotten = forgottenAt.get(row.key);
      if (forgotten && (Number(entry.at) || 0) <= forgotten) {
        return;
      }
      out.push({ id: shortNode(node) + '/' + row.id, dn: row.dn,
                 key: row.key, secure: !!row.secure, port: row.port,
                 boundAt: row.boundAt || 0, node: node,
                 nodeName: entry.name || '', remote: true,
                 publishedAt: entry.at || 0 });
    });
  });
  log.debug("Leaving remoteRows(). " + out.length + " row(s).");
  return out;
}

// identity key -> the instant this process reported another node's rows for
// it as instructed. A row published no later than that is not listed again by
// this process, so the second row of one global sign-out is not re-reported;
// the node's next publish — after it has closed them — is the authority.
const forgottenAt = new Map();

function forgetRemote(key) {
  log.debug("Entering forgetRemote().");
  const wanted = String(key || '');
  let newest = 0;
  connectionsByNode.forEach(function (entry) {
    newest = Math.max(newest, Number(entry && entry.at) || 0);
  });
  forgottenAt.set(wanted, newest);
  // Bounded: a key is only worth remembering while a published row predates
  // it, and a process that signs out many people must not grow this for ever.
  if (forgottenAt.size > 1000) {
    forgottenAt.delete(forgottenAt.keys().next().value);
  }
  log.debug("Leaving forgetRemote().");
}

function shortNode(node) {
  log.debug("Entering shortNode().");
  log.debug("Leaving shortNode().");
  return String(node || '').slice(0, 8);
}

// ---------------------------------------------------------------------------
// THE INSTRUCTION.
// ---------------------------------------------------------------------------

// A sign-out of `key`. Answers `{ instructed: true, at, node }`, or null when
// there is no cluster to instruct. The nonce makes every instruction a new
// value, so two sign-outs in one millisecond are still two change rows.
function instructSignOut(key) {
  log.debug("Entering instructSignOut().");
  const wanted = String(key || '');
  if (!wanted || !active()) {
    log.debug("Leaving instructSignOut(). Nothing to instruct.");
    return null;
  }
  const row = { key: wanted, at: now(), node: ownNode(),
                nonce: nodeCrypto.randomBytes(6).toString('base64url') };
  signOuts.set(wanted, row);
  // A request's barrier commits this before the answer; a sign-out that is
  // not a request (none today) must not wait for somebody else's write.
  commitNow('sign-out instruction');
  stats.instructed += 1;
  log.info('ldap: instructed every other node to close the directory ' +
           'connections bound as ' + wanted + '. The instruction commits ' +
           'with this sign-out; each node closes them when it applies the ' +
           'change log.');
  log.debug("Leaving instructSignOut().");
  return { instructed: true, at: row.at, node: row.node };
}

// Another process's instruction reached this one — through replication, or a
// restore at startup. Held as it arrived; acted on by a process that holds
// sockets, a tick later so the applier is not running somebody else's close.
function instructionArrived(key, incoming, held) {
  log.debug("Entering instructionArrived().");
  if (!incoming || typeof incoming !== 'object') {
    log.debug("Leaving instructionArrived(). Not an instruction.");
    return held;
  }
  if (!holdsSockets() || !active()) {
    log.debug("Leaving instructionArrived(). Nothing here to close.");
    return incoming;
  }
  if (String(incoming.node || '') === ownNode()) {
    log.debug("Leaving instructionArrived(). This node's own.");
    return incoming;
  }
  if (now() - (Number(incoming.at) || 0) > INSTRUCTION_TTL_MS) {
    stats.staleInstructions += 1;
    log.debug("Leaving instructionArrived(). Too old to act on.");
    return incoming;
  }
  setImmediate(function () {
    actOn(String(key), incoming);
  });
  log.debug("Leaving instructionArrived(). Acting.");
  return incoming;
}

function actOn(key, instruction) {
  log.debug("Entering actOn(). key=" + key);
  let closed = [];
  try {
    closed = hooks.closeLocal(key) || [];
  } catch (e) {
    log.error(errorCodes.tag('STS-LDAP-0096') + 'ldap: another node signed ' +
              key + ' out and this node could not close the directory ' +
              'connections bound as that identity: ' +
              ((e && e.message) || e) + '. They may still be open.');
    log.debug("Leaving actOn(). Failed.");
    return [];
  }
  stats.instructionsActedOn += 1;
  stats.closedByInstruction += closed.length;
  if (closed.length) {
    log.info('ldap: node ' + String(instruction.node || '?') + ' signed ' +
             key + ' out; ' + closed.length + ' directory connection(s) ' +
             'bound as that identity were closed on this node.');
  }
  log.debug("Leaving actOn(). " + closed.length + " closed.");
  return closed;
}

// ---------------------------------------------------------------------------
// MAINTENANCE: rows of nodes that are not members any more, and instructions
// past their lifetime. Idempotent deletes, so every socket-holding process may
// do it; asynchronous, because membership is a database read.
// ---------------------------------------------------------------------------
function armMaintenance() {
  log.debug("Entering armMaintenance().");
  if (maintainTimer) {
    log.debug("Leaving armMaintenance(). Armed.");
    return;
  }
  maintainTimer = setInterval(function () {
    maintain().catch(function (e) {
      log.debug("Caught in armMaintenance(): " + ((e && e.message) || e));
    });
  }, MAINTAIN_EVERY_MS);
  if (maintainTimer.unref) {
    maintainTimer.unref();
  }
  log.debug("Leaving armMaintenance().");
}

function maintain() {
  log.debug("Entering maintain().");
  if (!active() || !holdsSockets()) {
    log.debug("Leaving maintain(). Not maintaining.");
    return Promise.resolve({ swept: 0, expired: 0 });
  }
  const expiredKeys = [];
  signOuts.forEach(function (row, key) {
    if (!row || now() - (Number(row.at) || 0) > INSTRUCTION_TTL_MS) {
      expiredKeys.push(key);
    }
  });
  expiredKeys.forEach(function (key) {
    signOuts.delete(key);
  });
  log.debug("Leaving maintain(). Reading membership.");
  return Promise.resolve().then(function () {
    return cluster().state();
  }).then(function (state) {
    if (!state || !state.available || !Array.isArray(state.nodes)) {
      return { swept: 0, expired: expiredKeys.length };
    }
    const live = liveFrom(state, 0);
    const gone = [];
    connectionsByNode.forEach(function (entry, node) {
      if (!live.has(node)) {
        gone.push(node);
      }
    });
    gone.forEach(function (node) {
      connectionsByNode.delete(node);
    });
    if (gone.length || expiredKeys.length) {
      commitNow('maintenance');
    }
    stats.nodeRowsSwept += gone.length;
    return { swept: gone.length, expired: expiredKeys.length };
  });
}

function report() {
  log.debug("Entering report().");
  log.debug("Leaving report().");
  return Object.assign({ active: active(), nodesListed: connectionsByNode.size,
                         instructionsHeld: signOuts.size }, stats);
}

// For tests.
function reset(options) {
  log.debug("Entering reset().");
  const o = options || {};
  if (publishTimer) {
    clearTimeout(publishTimer);
    publishTimer = null;
  }
  if (maintainTimer) {
    clearInterval(maintainTimer);
    maintainTimer = null;
  }
  connectionsByNode.clear();
  signOuts.clear();
  forgottenAt.clear();
  Object.keys(stats).forEach(function (name) {
    stats[name] = 0;
  });
  clusterModule = o.cluster || null;
  now = typeof o.now === 'function' ? o.now : function () {
    return Date.now();
  };
  log.debug("Leaving reset().");
}

// AT REQUIRE TIME, like every capability (cluster/CLAUDE.md): the code being
// present is the capability, and this file is only loaded by the directory.
capabilities.provide('ldap.connections-cluster');

module.exports = {
  INSTRUCTION_TTL_MS: INSTRUCTION_TTL_MS,
  install: install,
  noteLocalChange: noteLocalChange,
  publishNow: publishNow,
  remoteRows: remoteRows,
  forgetRemote: forgetRemote,
  instructSignOut: instructSignOut,
  maintain: maintain,
  report: report,
  reset: reset,
  // The two stores, for a test that plays "another node's row arrived" with
  // the accessor calls `persistence_minted.js`'s applier makes.
  CONNECTIONS_HANDLE: 'ldap.clusterConnections',
  SIGNOUTS_HANDLE: 'ldap.clusterSignOuts'
};
