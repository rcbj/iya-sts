'use strict';
//
// File: ssf/ssf_cluster.ts
//
// ===========================================================================
// SHARED SIGNALS ON SEVERAL NODES (2026-09-14, #46 section 6).
//
// The stream store, the queue rows and the dead letters are replicated stores,
// so a transmitter on several nodes already agrees about WHAT exists. Three
// things were still decided by whichever process happened to be looking, and
// each is one function here:
//
//   * **STREAM HEALTH TRANSITIONS WERE REPORTED ONCE PER NODE.** A push stream
//     whose pushes all fail is declared dead by the process that saw the
//     failure that crossed `ssf.deadStreamTimeoutS`; two nodes pushing to one
//     dead receiver both cross it, and each wrote `ssf.stream.dead`
//     (`STS-SSF-0093`) and its log line — and the same for a revival.
//     `transitionOnce()` lets that report out once, through a claim on the
//     stream and the transition.
//   * **EVERY PROCESS PROBED.** The sweep pushes a dead stream's oldest dead
//     letter as a probe once per timeout, and `nextProbeAtMs` — a member of a
//     whole-valued record — was the only thing keeping two processes from
//     both probing, which it did only after it replicated. `leadsProbes()`
//     answers true in ONE process of the cluster: the front process of the
//     node holding the `ssf.dead-stream-probes` lease. Half-open, which only
//     a probe decides, goes with it.
//   * **A GNAP KEY PROOF WAS SPENT IN THIS PROCESS'S MEMORY ONLY.**
//     `ssf_auth.ts` judges a GNAP token synchronously through
//     `gnap_rs.presentation()`, whose replay check is the in-memory cache;
//     the cluster half of that check,
//     `gnap_proof.spendProof()`, needs an await. `spendGnapProof` is route
//     middleware that runs the presentation and the spend BEFORE the handler
//     and leaves both on the request, so the synchronous gate reads a proof
//     that has already been spent across the cluster rather than judging it a
//     second time (which the in-memory cache would refuse as a replay).
//
// **WHAT IS NOT MADE ONE STATE, AND WHY IT IS LEFT.** The four dead-stream
// members still live on the stream record, which is last writer wins: a node
// whose copy predates a declaration and writes the record back for a counter
// can revert the declaration. It does not oscillate — `failingSinceMs` is
// already past the timeout on every copy, so the next failure anywhere
// declares it again at once, and the claim keeps that second declaration from
// being reported — and the stores' lost updates are section 3's to fix, not
// a second mechanism here.
//
// **WHAT STAYS PER PROCESS, SAID RATHER THAN FIXED.** `ssf.pushConcurrency` and
// `ssf.pushBacklog` are a gate in each process, so a cluster of N nodes of P
// processes pushes up to N×P×pushConcurrency at once; and each sweep's
// `STS-SSF-0094` summary counts the SETs ITS OWN process dead-lettered, so N
// nodes log N lines about N different sets of pushes — a sum, never a
// duplicate. `ssf/CLAUDE.md` carries both for an operator sizing a cluster.
//
// Outside active-active mode every function here answers what one process
// always did: report inline, probe everywhere, and leave the proof to the
// synchronous gate.
//
// A LIBRARY (rule 3): no route. `cluster/cluster.js` and `cluster_claims.js`
// are required at the top (both are leaves that require nothing of this
// family); `persistence.js` and `gnap/` LAZILY, the second because a process
// may load SSF without GNAP.
// ===========================================================================

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `SsfCluster` takes its logger, `config`, the error-code table, the
// cluster layer, the claim store and LOADERS for `persistence.js` and the two
// GNAP modules (loaders, for the lazy requires the header argues) through its
// constructor. The composition root builds the instance (#50, R2); the
// module's old names are FACADES that forward to it, for `ssf/ssf.ts`,
// `ssf/ssf_auth.ts` and the tests, and its `wire` step asks for the probe
// lease, which the old module did at load. A process that loads this module
// without the root builds a default when the module loads, and campaigns
// then.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import config = require('../common/config');
import errorCodes = require('../common/error_codes');
import cluster = require('../cluster/cluster');
import claims = require('../cluster/cluster_claims');
import InstanceSlot = require('../common/instance_slot');

const log = bunyan.createLogger({ name: 'sts-ssf-cluster' });
config.registerLogger(log);

const PROBE_LEASE = 'ssf.dead-stream-probes';

// The request member the middleware leaves its answer on. A Symbol, so a body
// or a header can never be mistaken for it.
const GNAP_SPENT = Symbol('ssf.gnapSpent');

// A stat for the console and a test: how many transitions were reported, and
// how many another process had already reported.
const stats = { transitionsReported: 0, transitionsAlreadyReported: 0,
                probeSweepsSkipped: 0, gnapProofsSpent: 0,
                gnapProofsRefused: 0 };

// What the middleware leaves on a request.
interface GnapSpent {
  presented: any;
  spent: any;
}

// The parts of an express request the middleware reads and writes.
interface ClusterRequest {
  headers?: Record<string, unknown>;
  [member: string | symbol]: unknown;
}

interface SsfClusterDeps {
  log: { debug(m: string): void; info(m: string): void;
         warn(m: string): void };
  config: { value(key: string): unknown };
  errorCodes: { tag(code: string): string };
  cluster: {
    isActiveActive(): boolean;
    enabled(): boolean;
    holds(name: string): boolean;
    lead(name: string, handlers: {
      onGain(token?: unknown): void;
      onLose(): void;
    }): void;
  };
  claims: {
    claim(opts: { scope: string; value: string;
                  ttlMs: number }): Promise<any>;
  };
  // `persistence/persistence.js`, `gnap/gnap_rs.ts` and
  // `gnap/gnap_proof.ts`, required when first asked for. See the header.
  loadPersistence(): { clusterStore(): unknown };
  loadGnapRs(): { presentation(req: ClusterRequest): any };
  loadGnapProof(): { spendProof(presented: unknown): unknown };
}

class SsfCluster {
  static readonly PROBE_LEASE = PROBE_LEASE;

  constructor(private readonly deps: SsfClusterDeps) {
    deps.log.debug("Entering SsfCluster.constructor().");
    deps.log.debug("Leaving SsfCluster.constructor().");
  }

  private activeActive(): boolean {
    const { log, cluster } = this.deps;
    log.debug("Entering SsfCluster.activeActive().");
    let on = false;
    try {
      on = cluster.isActiveActive() && cluster.enabled();
    } catch (e) {
      log.debug("Caught in SsfCluster.activeActive(): " +
                ((e && e.message) || e));
      on = false;
    }
    log.debug("Leaving SsfCluster.activeActive(). " + on);
    return on;
  }

  sharedStore(): unknown {
    const { log, loadPersistence } = this.deps;
    log.debug("Entering SsfCluster.sharedStore().");
    let store = null;
    try {
      store = loadPersistence().clusterStore();
    } catch (e) {
      log.debug("Caught in SsfCluster.sharedStore(): " +
                ((e && e.message) || e));
      store = null;
    }
    log.debug("Leaving SsfCluster.sharedStore(). " + !!store);
    return store;
  }

  // -------------------------------------------------------------------------
  // ONE REPORT PER TRANSITION.
  //
  //   transitionOnce('dead' | 'revived', streamId, emit)
  //
  // With no shared claim store `emit` runs inline — one process, exactly as
  // before. Otherwise it runs only for the process that wins a claim on the
  // realm, the stream and the transition, lived for half the dead-stream
  // timeout: a stream cannot legitimately make the same transition twice
  // inside one timeout (a declaration needs a whole timeout of failures after
  // a success, and a revival needs a declaration and a probe a timeout
  // later), so a second claim inside that window is a second node reporting
  // the same one.
  //
  // A store that cannot be asked REPORTS ANYWAY, for authn.js's reason about
  // a session's end: this is a notice that must not be lost, not a value that
  // must not be accepted twice.
  // -------------------------------------------------------------------------
  transitionOnce(kind: string, streamId: unknown,
                 emit: () => void): Promise<boolean> {
    const { log, config, errorCodes, claims } = this.deps;
    log.debug("Entering SsfCluster.transitionOnce(). " + kind + " " +
              streamId);
    if (!this.sharedStore()) {
      emit();
      log.debug("Leaving SsfCluster.transitionOnce(). One process; inline.");
      return Promise.resolve(true);
    }
    const timeoutS = Number(config.value('ssf.deadStreamTimeoutS'));
    const ttlMs = Math.max(5000,
      Number.isFinite(timeoutS) && timeoutS > 0 ? timeoutS * 500 : 150000);
    log.debug("Leaving SsfCluster.transitionOnce(). Claiming.");
    return claims.claim({ scope: 'ssf.stream-' + kind,
                          value: String(streamId), ttlMs: ttlMs })
      .then(function (answer) {
        if (answer.ok) {
          stats.transitionsReported += 1;
          emit();
          return true;
        }
        if (answer.reason === 'store') {
          log.warn(errorCodes.tag('STS-SSF-0098') + 'ssf: whether another ' +
                   'process already reported stream ' + streamId + ' as ' +
                   kind + ' could not be asked (' + (answer.why || '') +
                   '); it is reported here and may be reported twice.');
          emit();
          return true;
        }
        stats.transitionsAlreadyReported += 1;
        log.debug('transitionOnce(): stream ' + streamId + ' was already ' +
                  'reported ' + kind + ' by another process.');
        return false;
      });
  }

  // -------------------------------------------------------------------------
  // WHO PROBES.
  // -------------------------------------------------------------------------
  leadsProbes(): boolean {
    const { log, cluster } = this.deps;
    log.debug("Entering SsfCluster.leadsProbes().");
    if (!this.activeActive()) {
      log.debug("Leaving SsfCluster.leadsProbes(). Not active-active; every " +
                "process does.");
      return true;
    }
    // A REQUEST WORKER NEVER LEADS. It holds no heartbeat, so a lease it
    // asked for would be renewed by its front process and never noticed lost
    // here — and a container's own workers would all believe they held it.
    if (process.env.STS_REQUEST_WORKER) {
      stats.probeSweepsSkipped += 1;
      log.debug("Leaving SsfCluster.leadsProbes(). A request worker.");
      return false;
    }
    const leads = cluster.holds(PROBE_LEASE);
    if (!leads) {
      stats.probeSweepsSkipped += 1;
    }
    log.debug("Leaving SsfCluster.leadsProbes(). " + leads);
    return leads;
  }

  // -------------------------------------------------------------------------
  // THE GNAP SPEND, AS ROUTE MIDDLEWARE.
  //
  // Only for a request under the GNAP scheme; everything else passes
  // straight through. It never answers: a refusal is left on the request for
  // `ssf_auth.ts`'s `attemptGnap()` to turn into SSF's error document, so the
  // refusal's shape and code stay where every other SSF credential refusal is
  // written. A presentation that fails is left too — the gate reports it —
  // and nothing is spent for it.
  // -------------------------------------------------------------------------
  spendGnapProof(req: ClusterRequest, res: unknown,
                 next: () => void): void {
    const { log, loadGnapRs, loadGnapProof } = this.deps;
    log.debug("Entering SsfCluster.spendGnapProof().");
    const header = String((req.headers || {}).authorization || '');
    if (!/^GNAP\s/i.test(header)) {
      log.debug("Leaving SsfCluster.spendGnapProof(). Not the GNAP scheme.");
      next();
      return;
    }
    let rs = null;
    let proof = null;
    try {
      rs = loadGnapRs();
      proof = loadGnapProof();
    } catch (e) {
      // GNAP is not loaded in this process; the gate says so.
      log.debug("Caught in SsfCluster.spendGnapProof(): " +
                ((e && e.message) || e));
      log.debug("Leaving SsfCluster.spendGnapProof(). GNAP is not loaded.");
      next();
      return;
    }
    let presented = null;
    try {
      presented = rs.presentation(req);
    } catch (e) {
      log.debug("Caught in SsfCluster.spendGnapProof(): " +
                ((e && e.message) || e));
      presented = null;
    }
    if (!presented || !presented.ok) {
      req[GNAP_SPENT] = { presented: presented, spent: null };
      log.debug("Leaving SsfCluster.spendGnapProof(). The presentation was " +
                "refused.");
      next();
      return;
    }
    log.debug("Leaving SsfCluster.spendGnapProof(). Spending.");
    Promise.resolve().then(function () {
      return proof.spendProof(presented);
    }).then(function (spent) {
      if (spent && spent.ok) {
        stats.gnapProofsSpent += 1;
      } else {
        stats.gnapProofsRefused += 1;
      }
      req[GNAP_SPENT] = { presented: presented, spent: spent };
      next();
    }, function (e) {
      log.debug("Caught in SsfCluster.spendGnapProof(): " +
                ((e && e.message) || e));
      stats.gnapProofsRefused += 1;
      req[GNAP_SPENT] = { presented: presented,
        spent: { ok: false, why: 'the proof could not be spent: ' +
                                 ((e && e.message) || e) } };
      next();
    });
  }

  // What the middleware left, or null when it did not run for this request.
  gnapSpentOf(req?: ClusterRequest | null): GnapSpent | null {
    const { log } = this.deps;
    log.debug("Entering SsfCluster.gnapSpentOf().");
    log.debug("Leaving SsfCluster.gnapSpentOf().");
    return ((req && req[GNAP_SPENT]) as GnapSpent) || null;
  }

  report(): Record<string, unknown> {
    const { log } = this.deps;
    log.debug("Entering SsfCluster.report().");
    log.debug("Leaving SsfCluster.report().");
    return Object.assign({ activeActive: this.activeActive(),
                           probeLease: PROBE_LEASE,
                           leadsProbes: this.leadsProbes() }, stats);
  }

  // The role is asked for at require time and campaigned for on every
  // heartbeat of a front process; see cluster.js's lead(). A process that
  // never joins a cluster is told it holds the role at once, and holds()
  // answers true there.
  campaign(): void {
    const { log, cluster } = this.deps;
    log.debug("Entering SsfCluster.campaign().");
    cluster.lead(PROBE_LEASE, {
      onGain: function (token) {
        log.debug("Entering onGain().");
        if (token) {
          log.info('ssf: this node probes dead push streams for the ' +
                   'cluster (lease "' + PROBE_LEASE + '", token ' + token +
                   ').');
        }
        log.debug("Leaving onGain().");
      },
      onLose: function () {
        log.debug("Entering onLose().");
        log.warn('ssf: this node no longer probes dead push streams; ' +
                 'another node holds "' + PROBE_LEASE + '".');
        log.debug("Leaving onLose().");
      }
    });
    log.debug("Leaving SsfCluster.campaign().");
  }

  // What the composition root passes (#50, R2): the real modules, as the
  // module built its own instance from before.
  static defaultDeps(): SsfClusterDeps {
    log.debug("Entering SsfCluster.defaultDeps().");
    log.debug("Leaving SsfCluster.defaultDeps().");
    return {
      log: log,
      config: config,
      errorCodes: errorCodes,
      cluster: cluster,
      claims: claims,
      loadPersistence: function () {
        return require('../persistence/persistence');
      },
      loadGnapRs: function () {
        return require('../gnap/gnap_rs');
      },
      loadGnapProof: function () {
        return require('../gnap/gnap_proof');
      }
    };
  }

  // What loading this module did with its instance before R2 (#50): ask for
  // the probe lease, as the module always did. Run once, for whichever
  // instance is installed.
  static wire(instance: SsfCluster): void {
    log.debug("Entering SsfCluster.wire().");
    instance.campaign();
    log.debug("Leaving SsfCluster.wire().");
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds
// no instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` (see `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<SsfCluster>(
  'ssf/ssf_cluster',
  () => new SsfCluster(SsfCluster.defaultDeps()),
  SsfCluster.wire,
  log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  SsfCluster: SsfCluster,
  installInstance: (instance: SsfCluster): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  PROBE_LEASE: SsfCluster.PROBE_LEASE,
  transitionOnce: slot.forward('transitionOnce'),
  leadsProbes: slot.forward('leadsProbes'),
  spendGnapProof: slot.forward('spendGnapProof'),
  gnapSpentOf: slot.forward('gnapSpentOf'),
  sharedStore: slot.forward('sharedStore'),
  report: slot.forward('report')
};
