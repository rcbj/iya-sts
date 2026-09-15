'use strict';
//
// File: ssf/ssf_cluster.js
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
//     `ssf_auth.js` judges a GNAP token synchronously through
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

const bunyan = require('bunyan');
const config = require('../common/config');
const errorCodes = require('../common/error_codes');
const cluster = require('../cluster/cluster');
const claims = require('../cluster/cluster_claims');

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

function activeActive() {
  log.debug("Entering activeActive().");
  let on = false;
  try {
    on = cluster.isActiveActive() && cluster.enabled();
  } catch (e) {
    log.debug("Caught in activeActive(): " + ((e && e.message) || e));
    on = false;
  }
  log.debug("Leaving activeActive(). " + on);
  return on;
}

function sharedStore() {
  log.debug("Entering sharedStore().");
  let store = null;
  try {
    store = require('../persistence/persistence').clusterStore();
  } catch (e) {
    log.debug("Caught in sharedStore(): " + ((e && e.message) || e));
    store = null;
  }
  log.debug("Leaving sharedStore(). " + !!store);
  return store;
}

// ---------------------------------------------------------------------------
// ONE REPORT PER TRANSITION.
//
//   transitionOnce('dead' | 'revived', streamId, emit)
//
// With no shared claim store `emit` runs inline — one process, exactly as
// before. Otherwise it runs only for the process that wins a claim on the
// realm, the stream and the transition, lived for half the dead-stream
// timeout: a stream cannot legitimately make the same transition twice inside
// one timeout (a declaration needs a whole timeout of failures after a
// success, and a revival needs a declaration and a probe a timeout later), so
// a second claim inside that window is a second node reporting the same one.
//
// A store that cannot be asked REPORTS ANYWAY, for authn.js's reason about a
// session's end: this is a notice that must not be lost, not a value that
// must not be accepted twice.
// ---------------------------------------------------------------------------
function transitionOnce(kind, streamId, emit) {
  log.debug("Entering transitionOnce(). " + kind + " " + streamId);
  if (!sharedStore()) {
    emit();
    log.debug("Leaving transitionOnce(). One process; inline.");
    return Promise.resolve(true);
  }
  const timeoutS = Number(config.value('ssf.deadStreamTimeoutS'));
  const ttlMs = Math.max(5000,
    Number.isFinite(timeoutS) && timeoutS > 0 ? timeoutS * 500 : 150000);
  log.debug("Leaving transitionOnce(). Claiming.");
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
                 kind + ' could not be asked (' + (answer.why || '') + '); ' +
                 'it is reported here and may be reported twice.');
        emit();
        return true;
      }
      stats.transitionsAlreadyReported += 1;
      log.debug('transitionOnce(): stream ' + streamId + ' was already ' +
                'reported ' + kind + ' by another process.');
      return false;
    });
}

// ---------------------------------------------------------------------------
// WHO PROBES.
// ---------------------------------------------------------------------------
function leadsProbes() {
  log.debug("Entering leadsProbes().");
  if (!activeActive()) {
    log.debug("Leaving leadsProbes(). Not active-active; every process does.");
    return true;
  }
  // A REQUEST WORKER NEVER LEADS. It holds no heartbeat, so a lease it asked
  // for would be renewed by its front process and never noticed lost here —
  // and a container's own workers would all believe they held it.
  if (process.env.STS_REQUEST_WORKER) {
    stats.probeSweepsSkipped += 1;
    log.debug("Leaving leadsProbes(). A request worker.");
    return false;
  }
  const leads = cluster.holds(PROBE_LEASE);
  if (!leads) {
    stats.probeSweepsSkipped += 1;
  }
  log.debug("Leaving leadsProbes(). " + leads);
  return leads;
}

// ---------------------------------------------------------------------------
// THE GNAP SPEND, AS ROUTE MIDDLEWARE.
//
// Only for a request under the GNAP scheme; everything else passes straight
// through. It never answers: a refusal is left on the request for
// `ssf_auth.js`'s `attemptGnap()` to turn into SSF's error document, so the
// refusal's shape and code stay where every other SSF credential refusal is
// written. A presentation that fails is left too — the gate reports it — and
// nothing is spent for it.
// ---------------------------------------------------------------------------
function spendGnapProof(req, res, next) {
  log.debug("Entering spendGnapProof().");
  const header = String((req.headers || {}).authorization || '');
  if (!/^GNAP\s/i.test(header)) {
    log.debug("Leaving spendGnapProof(). Not the GNAP scheme.");
    next();
    return;
  }
  let rs = null;
  let proof = null;
  try {
    rs = require('../gnap/gnap_rs');
    proof = require('../gnap/gnap_proof');
  } catch (e) {
    // GNAP is not loaded in this process; the gate says so.
    log.debug("Caught in spendGnapProof(): " + ((e && e.message) || e));
    log.debug("Leaving spendGnapProof(). GNAP is not loaded.");
    next();
    return;
  }
  let presented = null;
  try {
    presented = rs.presentation(req);
  } catch (e) {
    log.debug("Caught in spendGnapProof(): " + ((e && e.message) || e));
    presented = null;
  }
  if (!presented || !presented.ok) {
    req[GNAP_SPENT] = { presented: presented, spent: null };
    log.debug("Leaving spendGnapProof(). The presentation was refused.");
    next();
    return;
  }
  log.debug("Leaving spendGnapProof(). Spending.");
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
    stats.gnapProofsRefused += 1;
    req[GNAP_SPENT] = { presented: presented,
      spent: { ok: false, why: 'the proof could not be spent: ' +
                               ((e && e.message) || e) } };
    next();
  });
}

// What the middleware left, or null when it did not run for this request.
function gnapSpentOf(req) {
  log.debug("Entering gnapSpentOf().");
  log.debug("Leaving gnapSpentOf().");
  return (req && req[GNAP_SPENT]) || null;
}

function report() {
  log.debug("Entering report().");
  log.debug("Leaving report().");
  return Object.assign({ activeActive: activeActive(),
                         probeLease: PROBE_LEASE,
                         leadsProbes: leadsProbes() }, stats);
}

// The role is asked for at require time and campaigned for on every heartbeat
// of a front process; see cluster.js's lead(). A process that never joins a
// cluster is told it holds the role at once, and holds() answers true there.
cluster.lead(PROBE_LEASE, {
  onGain: function (token) {
    log.debug("Entering onGain().");
    if (token) {
      log.info('ssf: this node probes dead push streams for the cluster ' +
               '(lease "' + PROBE_LEASE + '", token ' + token + ').');
    }
    log.debug("Leaving onGain().");
  },
  onLose: function () {
    log.debug("Entering onLose().");
    log.warn('ssf: this node no longer probes dead push streams; another ' +
             'node holds "' + PROBE_LEASE + '".');
    log.debug("Leaving onLose().");
  }
});

module.exports = {
  PROBE_LEASE: PROBE_LEASE,
  transitionOnce: transitionOnce,
  leadsProbes: leadsProbes,
  spendGnapProof: spendGnapProof,
  gnapSpentOf: gnapSpentOf,
  sharedStore: sharedStore,
  report: report
};
