'use strict';
//
// File: ldap/ldap_cluster_connections.ts
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
// A LIBRARY (rule 3): it registers no route. It requires config, realms, the
// error-code table and `cluster/cluster_capabilities.js` at the top, and
// `cluster/cluster.js` and `persistence/persistence.js` LAZILY, and it reaches
// the sockets through hooks `ldap_server.js` installs — that module requires
// this one, and a require back would close a cycle.
// ===========================================================================

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `LdapClusterConnections` takes the logger, the error codes, the
// random source and LOADERS for `cluster/cluster.js` and
// `persistence/persistence.js` through its constructor, so both stay as lazy
// as they were. The two shared stores and `forgottenAt` stay module-level
// constants declared as before (a store is per realm at its declaration); the
// hooks, the timers, the replaceable cluster module and clock are the
// instance's. The capability is still provided at require time, after the
// stores, and the module still exports every old name, for
// `ldap/ldap_server.js` and the tests. Since #50's R2 the composition root
// builds the instance (`LdapClusterConnections.defaultDeps()`) and installs it;
// the module's old export names are FACADES that forward to it, for the
// JavaScript callers, and a process without the root builds a default when this
// module finishes loading. Its `wire()` points the sign-out store's restore
// hook at the installed instance. `LdapClusterConnections` is exported beside
// them for the composition root.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import nodeCrypto = require('crypto');
import config = require('../common/config');
import realms = require('../common/realms');
import errorCodes = require('../common/error_codes');
import capabilities = require('../cluster/cluster_capabilities');
import InstanceSlot = require('../common/instance_slot');

const log = bunyan.createLogger({ name: 'sts-ldap-cluster' });
config.registerLogger(log);

// A connection another node published, as `remoteRows()` lists it.
interface RemoteRow {
  id: string;
  dn: string;
  key: string;
  secure: boolean;
  port: number;
  boundAt: number;
  node: string;
  nodeName: string;
  remote: boolean;
  publishedAt: number;
}

// One published connection, as a node's row holds it.
interface PublishedRow {
  id: string;
  dn: string;
  key: string;
  secure: boolean;
  port: number;
  boundAt: number;
}

// A node's row in `ldap.clusterConnections`.
interface NodeEntry {
  node: string;
  name: string;
  at: number;
  rows: PublishedRow[];
}

// A row in `ldap.clusterSignOuts`.
interface Instruction {
  key: string;
  at: number;
  node: string;
  nonce?: string;
}

// What `ldap_server.js` installs.
interface SocketHooks {
  holdsSockets(): boolean;
  localRows(): any[];
  closeLocal(key: string): any[];
}

// The parts of `cluster/cluster.js` this module reads.
interface ClusterView {
  isActiveActive(): boolean;
  enabled(): boolean;
  nodeId(): unknown;
  status(): { name?: unknown };
  snapshot(): any;
  state(): any;
}

// The counters `report()` hands out.
interface ConnectionStats {
  published: number;
  instructed: number;
  instructionsActedOn: number;
  closedByInstruction: number;
  staleInstructions: number;
  nodeRowsSwept: number;
  [name: string]: number;
}

interface LdapClusterConnectionsDeps {
  log: {
    debug(message: string): void;
    info(message: string): void;
    warn(message: string): void;
    error(message: string): void;
  };
  errorCodes: { tag(code: string): string };
  randomBytes(size: number): Buffer;
  // LAZY: see `cluster()` and `commitNow()`.
  loadCluster(): ClusterView;
  loadPersistence(): { flushMinted(): unknown };
}

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

// The instance the sign-out store's restore hands an arriving row to. Set
// by `LdapClusterConnections.wire()` when the instance is installed; a
// restore only happens once the store is started, which is after that.
let connections: LdapClusterConnections | null = null;

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
      return connections.instructionArrived(key, incoming, held);
    }
  } });

// What this process has done, for `/admin/ldap/service` and a test.
const stats: ConnectionStats = { published: 0, instructed: 0,
                                 instructionsActedOn: 0,
                                 closedByInstruction: 0,
                                 staleInstructions: 0, nodeRowsSwept: 0 };

// identity key -> the instant this process reported another node's rows for
// it as instructed. A row published no later than that is not listed again by
// this process, so the second row of one global sign-out is not re-reported;
// the node's next publish — after it has closed them — is the authority.
const forgottenAt: Map<string, number> = new Map();

class LdapClusterConnections {
  static readonly INSTRUCTION_TTL_MS = INSTRUCTION_TTL_MS;
  // The two stores, for a test that plays "another node's row arrived" with
  // the accessor calls `persistence_minted.js`'s applier makes.
  static readonly CONNECTIONS_HANDLE = 'ldap.clusterConnections';
  static readonly SIGNOUTS_HANDLE = 'ldap.clusterSignOuts';

  // What `ldap_server.js` installs: `{ holdsSockets(), localRows(),
  // closeLocal(key) }`. Null in a process that loaded this file alone.
  private hooks: SocketHooks | null = null;
  private publishTimer: NodeJS.Timeout | null = null;
  private maintainTimer: NodeJS.Timeout | null = null;
  // Replaced by tests: the cluster module, and the clock.
  private clusterModule: ClusterView | null = null;
  private now: () => number;

  // Something about this process's own connections changed — see
  // `noteLocalChange()`.
  //
  // **A CHANGE NOTED WHILE A PUBLISH IS PENDING PUBLISHES AGAIN AFTER IT.** The
  // first live two-node run listed two binds of five on the other node: the
  // connect armed the timer, the bind — a password hash in product mode,
  // longer than the delay — landed after the timer fired and found nothing to
  // arm, so the row went out with the connection still anonymous and was
  // never corrected.
  private publishAgain = false;

  constructor(private readonly deps: LdapClusterConnectionsDeps) {
    deps.log.debug("Entering LdapClusterConnections.constructor().");
    this.now = function () {
      deps.log.debug("Entering now().");
      deps.log.debug("Leaving now().");
      return Date.now();
    };
    deps.log.debug("Leaving LdapClusterConnections.constructor().");
  }

  // What the composition root passes: the modules the load-time instance
  // was built from before R2.
  static defaultDeps(): LdapClusterConnectionsDeps {
    log.debug("Entering LdapClusterConnections.defaultDeps().");
    log.debug("Leaving LdapClusterConnections.defaultDeps().");
    return {
      log: log,
      errorCodes: errorCodes,
      randomBytes: nodeCrypto.randomBytes,
      loadCluster: LdapClusterConnections.clusterFromRequire,
      loadPersistence: LdapClusterConnections.persistenceFromRequire
    };
  }

  // What loading this module did with its instance before R2, run once for
  // whichever instance is installed (#50, R2): the sign-out store's restore
  // hook above reaches the instance through `connections`, and it is set
  // before anything could restore a sign-out row into that store.
  //
  // It also hands the instance the socket hooks `install()` was given before
  // there was one — see `installHooks()` below.
  static wire(instance: LdapClusterConnections): void {
    log.debug("Entering LdapClusterConnections.wire().");
    connections = instance;
    if (pendingHooks) {
      instance.install(pendingHooks.hooks);
      pendingHooks = null;
    }
    log.debug("Leaving LdapClusterConnections.wire().");
  }

  // The default `loadCluster`, passed by `defaultDeps()`.
  static clusterFromRequire(): ClusterView {
    log.debug("Entering LdapClusterConnections.clusterFromRequire().");
    log.debug("Leaving LdapClusterConnections.clusterFromRequire().");
    return require('../cluster/cluster');
  }

  // The default `loadPersistence`, passed by `defaultDeps()`.
  static persistenceFromRequire(): { flushMinted(): unknown } {
    log.debug("Entering LdapClusterConnections.persistenceFromRequire().");
    log.debug("Leaving LdapClusterConnections.persistenceFromRequire().");
    return require('../persistence/persistence');
  }

  private cluster(): ClusterView {
    const { log, loadCluster } = this.deps;
    log.debug("Entering LdapClusterConnections.cluster().");
    if (!this.clusterModule) {
      // LAZY: cluster.js requires nothing of the directory, but this file is
      // required at 21 and there is no reason to load the cluster layer into
      // a test that only wanted the directory.
      this.clusterModule = loadCluster();
    }
    log.debug("Leaving LdapClusterConnections.cluster().");
    return this.clusterModule;
  }

  private active(): boolean {
    const { log } = this.deps;
    log.debug("Entering LdapClusterConnections.active().");
    let on = false;
    try {
      on = this.cluster().isActiveActive() && this.cluster().enabled();
    } catch (e) {
      log.debug("Caught in LdapClusterConnections.active(): " +
                ((e && e.message) || e));
      on = false;
    }
    log.debug("Leaving LdapClusterConnections.active(). " + on);
    return on;
  }

  private ownNode(): string {
    const { log } = this.deps;
    log.debug("Entering LdapClusterConnections.ownNode().");
    let id = '';
    try {
      id = String(this.cluster().nodeId() || '');
    } catch (e) {
      log.debug("Caught in LdapClusterConnections.ownNode(): " +
                ((e && e.message) || e));
      id = '';
    }
    log.debug("Leaving LdapClusterConnections.ownNode().");
    return id;
  }

  install(theHooks?: SocketHooks | null): void {
    const { log } = this.deps;
    log.debug("Entering LdapClusterConnections.install().");
    this.hooks = theHooks || null;
    log.debug("Leaving LdapClusterConnections.install().");
  }

  private holdsSockets(): boolean {
    const { log } = this.deps;
    log.debug("Entering LdapClusterConnections.holdsSockets().");
    let holds = false;
    try {
      holds = !!(this.hooks && this.hooks.holdsSockets());
    } catch (e) {
      log.debug("Caught in LdapClusterConnections.holdsSockets(): " +
                ((e && e.message) || e));
      holds = false;
    }
    log.debug("Leaving LdapClusterConnections.holdsSockets(). " + holds);
    return holds;
  }

  // -------------------------------------------------------------------------
  // THE TABLE.
  // -------------------------------------------------------------------------

  // Something about this process's own connections changed. Called beside
  // the in-container publish, from the three places that change the set. See
  // `publishAgain` above.
  noteLocalChange(): void {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering LdapClusterConnections.noteLocalChange().");
    if (this.publishTimer) {
      this.publishAgain = true;
      log.debug("Leaving LdapClusterConnections.noteLocalChange(). One is " +
                "pending; again after it.");
      return;
    }
    if (!this.active() || !this.holdsSockets()) {
      log.debug("Leaving LdapClusterConnections.noteLocalChange(). Nothing " +
                "to schedule.");
      return;
    }
    this.publishTimer = setTimeout(function () {
      self.publishTimer = null;
      const again = self.publishAgain;
      self.publishAgain = false;
      self.publishNow();
      if (again) {
        self.noteLocalChange();
      }
    }, PUBLISH_DELAY_MS);
    if (this.publishTimer.unref) {
      this.publishTimer.unref();
    }
    this.armMaintenance();
    log.debug("Leaving LdapClusterConnections.noteLocalChange(). Scheduled.");
  }

  // Writes this node's row: what it holds, without the sockets. A node
  // holding nothing has no row rather than an empty one, so the table is the
  // nodes with something to list.
  publishNow(): boolean {
    const { log, errorCodes } = this.deps;
    log.debug("Entering LdapClusterConnections.publishNow().");
    if (!this.active() || !this.holdsSockets()) {
      log.debug("Leaving LdapClusterConnections.publishNow(). Not " +
                "publishing.");
      return false;
    }
    const node = this.ownNode();
    if (!node) {
      log.debug("Leaving LdapClusterConnections.publishNow(). No node id.");
      return false;
    }
    let rows: PublishedRow[] = [];
    try {
      rows = (this.hooks.localRows() || []).filter(function (row) {
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
      log.debug("Leaving LdapClusterConnections.publishNow(). Could not " +
                "read.");
      return false;
    }
    if (!rows.length) {
      if (connectionsByNode.has(node)) {
        connectionsByNode.delete(node);
        this.commitNow('nothing bound');
      }
      log.debug("Leaving LdapClusterConnections.publishNow(). Nothing " +
                "bound.");
      return true;
    }
    let name = '';
    try {
      name = String(this.cluster().status().name || '');
    } catch (e) {
      log.debug("Caught in LdapClusterConnections.publishNow(): " +
                ((e && e.message) || e));
      name = '';
    }
    const entry: NodeEntry = { node: node, name: name, at: this.now(),
                               rows: rows };
    connectionsByNode.set(node, entry);
    this.commitNow('publish');
    stats.published += 1;
    log.debug("Leaving LdapClusterConnections.publishNow(). " + rows.length +
              " row(s).");
    return true;
  }

  // -------------------------------------------------------------------------
  // COMMITTED NOW, NOT WITH SOMEBODY ELSE'S NEXT WRITE.
  //
  // A minted write only journals its key; what commits the journal is a
  // flush, and the doors that start one are a request's (the barrier holds a
  // writing response for `flushMinted()`, a request worker announces its
  // commit) and a directory, realm or setting change. A socket event is none
  // of those. So the first live two-node run published a bind's row and it
  // sat in the journal until an unrelated write flushed it — three binds of
  // six were never listed on the other node within four seconds, and the
  // three that were had been carried out by the probe's own next user
  // creation. Same fix as `spiffe_ca.js` and `credentials.js`'s bootstrap:
  // flush the minted journal right after writing. It coalesces with a flush
  // already in flight.
  // -------------------------------------------------------------------------
  private commitNow(why: string): Promise<unknown> {
    const { log, errorCodes, loadPersistence } = this.deps;
    log.debug("Entering LdapClusterConnections.commitNow(). " + why);
    let persistence: { flushMinted(): unknown } | null = null;
    try {
      persistence = loadPersistence();
    } catch (e) {
      log.debug("Caught in LdapClusterConnections.commitNow(): " +
                ((e && e.message) || e));
      log.debug("Leaving LdapClusterConnections.commitNow(). No store.");
      return Promise.resolve(null);
    }
    log.debug("Leaving LdapClusterConnections.commitNow().");
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

  // The node ids the last cluster state read says are members, or null when
  // this process has no state to go on — in which case every row is listed,
  // because over-listing a dead node's connections is the honest failure and
  // hiding a live one's is not.
  private liveNodes(): Set<string> | null {
    const { log } = this.deps;
    log.debug("Entering LdapClusterConnections.liveNodes().");
    let snap = null;
    try {
      snap = this.cluster().snapshot();
    } catch (e) {
      log.debug("Caught in LdapClusterConnections.liveNodes(): " +
                ((e && e.message) || e));
      snap = null;
    }
    const state = snap && snap.state;
    if (!state || !state.available || !Array.isArray(state.nodes)) {
      log.debug("Leaving LdapClusterConnections.liveNodes(). No state.");
      return null;
    }
    log.debug("Leaving LdapClusterConnections.liveNodes().");
    return this.liveFrom(state, snap.ageMs || 0);
  }

  private liveFrom(state: any, ageMs: number): Set<string> {
    const { log } = this.deps;
    log.debug("Entering LdapClusterConnections.liveFrom().");
    // The database clock the state was read against, moved on by how long
    // ago it was read — every expiry here is by that clock, never this
    // machine's.
    const at = (Number(state.now) || 0) + (Number(ageMs) || 0);
    const out: Set<string> = new Set();
    state.nodes.forEach(function (node) {
      if (!Number(node.leftAt) && Number(node.expiresAt) > at) {
        out.add(String(node.nodeId));
      }
    });
    log.debug("Leaving LdapClusterConnections.liveFrom(). " + out.size +
              " live.");
    return out;
  }

  // Every connection OTHER nodes have published, as `boundConnections()`
  // rows without a socket. The id carries the node, because connection ids
  // are per-listener and two nodes can both hold a `127.0.0.1:40000`.
  remoteRows(): RemoteRow[] {
    const { log } = this.deps;
    log.debug("Entering LdapClusterConnections.remoteRows().");
    if (!this.active()) {
      log.debug("Leaving LdapClusterConnections.remoteRows(). Not " +
                "active-active.");
      return [];
    }
    const self = this.ownNode();
    const live = this.liveNodes();
    const out: RemoteRow[] = [];
    connectionsByNode.forEach(function (entry: NodeEntry, node: string) {
      if (!entry || node === self || (live && !live.has(node))) {
        return;
      }
      (entry.rows || []).forEach(function (row) {
        const forgotten = forgottenAt.get(row.key);
        if (forgotten && (Number(entry.at) || 0) <= forgotten) {
          return;
        }
        out.push({ id: LdapClusterConnections.shortNode(node) + '/' + row.id,
                   dn: row.dn, key: row.key, secure: !!row.secure,
                   port: row.port, boundAt: row.boundAt || 0, node: node,
                   nodeName: entry.name || '', remote: true,
                   publishedAt: entry.at || 0 });
      });
    });
    log.debug("Leaving LdapClusterConnections.remoteRows(). " + out.length +
              " row(s).");
    return out;
  }

  forgetRemote(key: unknown): void {
    const { log } = this.deps;
    log.debug("Entering LdapClusterConnections.forgetRemote().");
    const wanted = String(key || '');
    let newest = 0;
    connectionsByNode.forEach(function (entry: NodeEntry) {
      newest = Math.max(newest, Number(entry && entry.at) || 0);
    });
    forgottenAt.set(wanted, newest);
    // Bounded: a key is only worth remembering while a published row
    // predates it, and a process that signs out many people must not grow
    // this for ever.
    if (forgottenAt.size > 1000) {
      forgottenAt.delete(forgottenAt.keys().next().value);
    }
    log.debug("Leaving LdapClusterConnections.forgetRemote().");
  }

  private static shortNode(node: unknown): string {
    log.debug("Entering LdapClusterConnections.shortNode().");
    log.debug("Leaving LdapClusterConnections.shortNode().");
    return String(node || '').slice(0, 8);
  }

  // -------------------------------------------------------------------------
  // THE INSTRUCTION.
  // -------------------------------------------------------------------------

  // A sign-out of `key`. Answers `{ instructed: true, at, node }`, or null
  // when there is no cluster to instruct. The nonce makes every instruction a
  // new value, so two sign-outs in one millisecond are still two change rows.
  instructSignOut(key: unknown):
      { instructed: boolean; at: number; node: string } | null {
    const { log, randomBytes } = this.deps;
    log.debug("Entering LdapClusterConnections.instructSignOut().");
    const wanted = String(key || '');
    if (!wanted || !this.active()) {
      log.debug("Leaving LdapClusterConnections.instructSignOut(). Nothing " +
                "to instruct.");
      return null;
    }
    const row: Instruction = { key: wanted, at: this.now(),
                               node: this.ownNode(),
                               nonce: randomBytes(6).toString('base64url') };
    signOuts.set(wanted, row);
    // A request's barrier commits this before the answer; a sign-out that is
    // not a request (none today) must not wait for somebody else's write.
    this.commitNow('sign-out instruction');
    stats.instructed += 1;
    log.info('ldap: instructed every other node to close the directory ' +
             'connections bound as ' + wanted + '. The instruction commits ' +
             'with this sign-out; each node closes them when it applies the ' +
             'change log.');
    log.debug("Leaving LdapClusterConnections.instructSignOut().");
    return { instructed: true, at: row.at, node: row.node };
  }

  // Another process's instruction reached this one — through replication, or
  // a restore at startup. Held as it arrived; acted on by a process that
  // holds sockets, a tick later so the applier is not running somebody else's
  // close.
  instructionArrived(key: unknown, incoming: any, held: any): any {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering LdapClusterConnections.instructionArrived().");
    if (!incoming || typeof incoming !== 'object') {
      log.debug("Leaving LdapClusterConnections.instructionArrived(). Not " +
                "an instruction.");
      return held;
    }
    if (!this.holdsSockets() || !this.active()) {
      log.debug("Leaving LdapClusterConnections.instructionArrived(). " +
                "Nothing here to close.");
      return incoming;
    }
    if (String(incoming.node || '') === this.ownNode()) {
      log.debug("Leaving LdapClusterConnections.instructionArrived(). This " +
                "node's own.");
      return incoming;
    }
    if (this.now() - (Number(incoming.at) || 0) > INSTRUCTION_TTL_MS) {
      stats.staleInstructions += 1;
      log.debug("Leaving LdapClusterConnections.instructionArrived(). Too " +
                "old to act on.");
      return incoming;
    }
    setImmediate(function () {
      self.actOn(String(key), incoming);
    });
    log.debug("Leaving LdapClusterConnections.instructionArrived(). Acting.");
    return incoming;
  }

  private actOn(key: string, instruction: Instruction): any[] {
    const { log, errorCodes } = this.deps;
    log.debug("Entering LdapClusterConnections.actOn(). key=" + key);
    let closed: any[] = [];
    try {
      closed = this.hooks.closeLocal(key) || [];
    } catch (e) {
      log.error(errorCodes.tag('STS-LDAP-0096') + 'ldap: another node ' +
                'signed ' + key + ' out and this node could not close the ' +
                'directory connections bound as that identity: ' +
                ((e && e.message) || e) + '. They may still be open.');
      log.debug("Leaving LdapClusterConnections.actOn(). Failed.");
      return [];
    }
    stats.instructionsActedOn += 1;
    stats.closedByInstruction += closed.length;
    if (closed.length) {
      log.info('ldap: node ' + String(instruction.node || '?') + ' signed ' +
               key + ' out; ' + closed.length + ' directory connection(s) ' +
               'bound as that identity were closed on this node.');
    }
    log.debug("Leaving LdapClusterConnections.actOn(). " + closed.length +
              " closed.");
    return closed;
  }

  // -------------------------------------------------------------------------
  // MAINTENANCE: rows of nodes that are not members any more, and
  // instructions past their lifetime. Idempotent deletes, so every
  // socket-holding process may do it; asynchronous, because membership is a
  // database read.
  // -------------------------------------------------------------------------
  private armMaintenance(): void {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering LdapClusterConnections.armMaintenance().");
    if (this.maintainTimer) {
      log.debug("Leaving LdapClusterConnections.armMaintenance(). Armed.");
      return;
    }
    this.maintainTimer = setInterval(function () {
      self.maintain().catch(function (e) {
        log.debug("Caught in LdapClusterConnections.armMaintenance(): " +
                  ((e && e.message) || e));
      });
    }, MAINTAIN_EVERY_MS);
    if (this.maintainTimer.unref) {
      this.maintainTimer.unref();
    }
    log.debug("Leaving LdapClusterConnections.armMaintenance().");
  }

  maintain(): Promise<{ swept: number; expired: number }> {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering LdapClusterConnections.maintain().");
    if (!this.active() || !this.holdsSockets()) {
      log.debug("Leaving LdapClusterConnections.maintain(). Not " +
                "maintaining.");
      return Promise.resolve({ swept: 0, expired: 0 });
    }
    const expiredKeys: string[] = [];
    signOuts.forEach(function (row: Instruction, key: string) {
      if (!row || self.now() - (Number(row.at) || 0) > INSTRUCTION_TTL_MS) {
        expiredKeys.push(key);
      }
    });
    expiredKeys.forEach(function (key) {
      signOuts.delete(key);
    });
    log.debug("Leaving LdapClusterConnections.maintain(). Reading " +
              "membership.");
    return Promise.resolve().then(function () {
      return self.cluster().state();
    }).then(function (state) {
      if (!state || !state.available || !Array.isArray(state.nodes)) {
        return { swept: 0, expired: expiredKeys.length };
      }
      const live = self.liveFrom(state, 0);
      const gone: string[] = [];
      connectionsByNode.forEach(function (entry: NodeEntry, node: string) {
        if (!live.has(node)) {
          gone.push(node);
        }
      });
      gone.forEach(function (node) {
        connectionsByNode.delete(node);
      });
      if (gone.length || expiredKeys.length) {
        self.commitNow('maintenance');
      }
      stats.nodeRowsSwept += gone.length;
      return { swept: gone.length, expired: expiredKeys.length };
    });
  }

  report(): object {
    const { log } = this.deps;
    log.debug("Entering LdapClusterConnections.report().");
    log.debug("Leaving LdapClusterConnections.report().");
    return Object.assign({ active: this.active(),
                           nodesListed: connectionsByNode.size,
                           instructionsHeld: signOuts.size }, stats);
  }

  // For tests.
  reset(options?: { cluster?: ClusterView; now?: () => number }): void {
    const { log } = this.deps;
    log.debug("Entering LdapClusterConnections.reset().");
    const o = options || {};
    if (this.publishTimer) {
      clearTimeout(this.publishTimer);
      this.publishTimer = null;
    }
    if (this.maintainTimer) {
      clearInterval(this.maintainTimer);
      this.maintainTimer = null;
    }
    connectionsByNode.clear();
    signOuts.clear();
    forgottenAt.clear();
    Object.keys(stats).forEach(function (name) {
      stats[name] = 0;
    });
    this.clusterModule = o.cluster || null;
    this.now = typeof o.now === 'function' ? o.now : function () {
      return Date.now();
    };
    log.debug("Leaving LdapClusterConnections.reset().");
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when this module finishes loading (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<LdapClusterConnections>(
  'ldap/ldap_cluster_connections',
  () => new LdapClusterConnections(LdapClusterConnections.defaultDeps()),
  LdapClusterConnections.wire,
  log);

// AT REQUIRE TIME, like every capability (cluster/CLAUDE.md): the code being
// present is the capability, and this file is only loaded by the directory.
capabilities.provide('ldap.connections-cluster');

// ---------------------------------------------------------------------------
// THE `install()` FACADE IS THE ONE THAT MAY BE CALLED BEFORE THERE IS AN
// INSTANCE (#50, R2). `ldap/ldap_server.js` calls it at ITS require time, and
// under the composition root that is before the root reaches this module's
// build line: the directory is loaded inside an earlier line's requires, so
// this module finishes loading, then the directory's load goes on and calls
// `install()`, and only then does the root build this module. A plain facade
// there would build a default, and the root's own install would be refused.
//
// So while nothing is installed the hooks are HELD, and `wire()` hands them to
// whichever instance is installed. Nothing reads them before that — they are
// consulted when a table is published, which is after the store has started —
// so the directory sees exactly what it saw before. Once an instance exists
// the call goes straight to it. With no root, this module built its default
// when it finished loading, so the first branch is never taken.
// ---------------------------------------------------------------------------
let pendingHooks: { hooks: SocketHooks | null } | null = null;

function installHooks(theHooks?: SocketHooks | null): void {
  log.debug("Entering installHooks().");
  if (slot.origin() === 'none') {
    pendingHooks = { hooks: theHooks || null };
    log.debug("Leaving installHooks(). Held until an instance is installed.");
    return;
  }
  slot.get().install(theHooks);
  log.debug("Leaving installHooks().");
}

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  LdapClusterConnections: LdapClusterConnections,
  installInstance: (instance: LdapClusterConnections): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  INSTRUCTION_TTL_MS: LdapClusterConnections.INSTRUCTION_TTL_MS,
  install: installHooks,
  noteLocalChange: slot.forward('noteLocalChange'),
  publishNow: slot.forward('publishNow'),
  remoteRows: slot.forward('remoteRows'),
  forgetRemote: slot.forward('forgetRemote'),
  instructSignOut: slot.forward('instructSignOut'),
  maintain: slot.forward('maintain'),
  report: slot.forward('report'),
  reset: slot.forward('reset'),
  // The two stores, for a test that plays "another node's row arrived" with
  // the accessor calls `persistence_minted.js`'s applier makes.
  CONNECTIONS_HANDLE: LdapClusterConnections.CONNECTIONS_HANDLE,
  SIGNOUTS_HANDLE: LdapClusterConnections.SIGNOUTS_HANDLE
};
