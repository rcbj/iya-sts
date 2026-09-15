'use strict';
//
// File: persistence/persistence_replication.js
//
// ---------------------------------------------------------------------------
// SEVERAL PROCESSES AGAINST ONE STORE, AND THE SENTENCE THIS REVERSES.
//
// `persistence/CLAUDE.md` and `persistence.js`'s header both said it, in the
// section called THE SEAM: **persistence is not coordination.** Two processes
// pointed at one database each held their own copy of the directory in memory,
// each wrote their own changes down, and neither saw the other's until it
// restarted. That was stated rather than discovered, on purpose, and it was
// the honest description of what existed.
//
// This is the phase that closes it, and it covers EVERY kind of row rather
// than the directory alone — a service where two processes agree about who
// exists and disagree about who is signed in would be worse than one that
// admitted it shared nothing.
//
// ---------------------------------------------------------------------------
// THE ONE SENTENCE: THE CHANGE LOG IS THE CONTRACT, THE NOTIFICATION IS ONLY
// LATENCY.
//
// `sts_changes` is a monotonic log written INSIDE the transaction that made
// each change. A process remembers the highest `seq` it has applied and asks
// for everything after it. `LISTEN`/`NOTIFY` wakes that ask early and is
// allowed to fail in every way a best-effort mechanism can fail — dropped
// connection, at-most-once delivery, an 8000-byte payload limit — because
// losing a notification costs latency and never a change.
//
// **THIS IS THE ARGUMENT `xacml-pep/` ALREADY MAKES ABOUT ITS OWN PULL**, and
// citing it is the point: this repository has run exactly this trade once
// before, in the one other place where the alternative was a push nobody could
// guarantee. The nudge there is an optimisation over the polling interval and
// never a replacement for it. So it is here.
//
// The alternative that gets proposed first is an ORM with change tracking, and
// it does not fit for a reason that is about this service rather than about
// any ORM. **THE AUTHORITY HERE IS AN IN-MEMORY MAP**, read SYNCHRONOUSLY by
// every protocol module inside a request — `ldap_server.js`'s `entries`,
// `authn.js`'s `sessions` — and the database is a write-behind mirror of it.
// What is needed is therefore cache coherence, not data access: something has
// to get another process's write INTO this process's Map. An ORM solves the
// layer below that, would add a second schema definition beside
// `postgres/schema.sql` for the two to drift apart, and routing reads through
// it would make every one of those synchronous lookups an `await` — which is
// not a feature, it is a rewrite of the service.
//
// ---------------------------------------------------------------------------
// LAST WRITER WINS, PER ROW — AND THE TWO SHAPES WHERE THAT IS WRONG.
//
// A row is whole-valued, so a later write replaces an earlier one and both
// processes converge on it. That is EXACTLY the semantics a single process
// already has for two concurrent requests, which is what makes it the safe
// answer: nothing anybody relies on changes.
//
// It is wrong for two shapes, and both are handled by the store DECLARING
// which it is (`merge:` in `common/realms.js`):
//
//   * **A COUNTER.** `nums.callTotal++` is this process's tally. Two processes
//     overwriting each other's row silently loses counts and the number stays
//     plausible, which is what makes it hard to notice. So a counter store
//     writes ONE ROW PER ORIGIN, each process writes only its own, and the
//     console sums them on read.
//   * **AN APPEND-ONLY RING.** The audit log is a sequence of events, not a
//     value. Overwriting would throw away another process's events; merging
//     the arrays in memory and writing the result back would make each process
//     re-report the other's events as its own. So it is the same answer: one
//     row per origin, holding that origin's own events, merged on read.
//
// Both of those are `merge: 'own'` — "this row is MINE and I never write
// anybody else's" — and the fan-in happens where the value is REPORTED rather
// than where it is stored. `remoteRows()` below is that fan-in.
//
// ---------------------------------------------------------------------------
// WHAT STILL DOES NOT COORDINATE, SAID PLAINLY.
//
//   * **THE SOCKETS.** The KDC, the LDAP listeners, the two TLS ports and
//     SPIFFE's four are bound per process. Coordination is about state, and a
//     socket is not state.
//   * **THE REPLAY CACHES AND THE DPoP `jti` SETS CONVERGE RATHER THAN
//     SYNCHRONISE, AND THAT IS A SECURITY STATEMENT.** Between a write in one
//     process and its arrival in another there is a window the size of the
//     convergence lag, and inside it a proof or an Authenticator refused by
//     one process is accepted by another. Sticky sessions at the load balancer
//     close it; nothing here does. It is written down rather than left to be
//     found, and `/admin/persistence` says it too.
//   * **`ldap.maxEntries` IS STILL A CEILING ON WHAT THIS PROCESS HOLDS**,
//     which stops meaning "the size of the directory" when the store is
//     shared.
//
// ---------------------------------------------------------------------------
// A LIBRARY, HANDED ITS DRIVER (rule 3). Registers no route, requires
// `persistence.js` for nothing, and takes its appliers as an argument — which
// is what lets `tests/replication.js` drive the whole of it against a stub with
// no database.
// ---------------------------------------------------------------------------

const bunyan = require('bunyan');
const config = require('../common/config');
const realms = require('../common/realms');
// A LEAF with no requires: the failure codes on the log lines below. NOT
// audit.js, which requires THIS file — a require back would close a cycle.
const errorCodes = require('../common/error_codes');
// The table active-active mode is held to. A LEAF.
const capabilities = require('../cluster/cluster_capabilities');

const log = bunyan.createLogger({ name: 'sts-persistence-replication' });

// The driver, and the appliers `persistence.js` hands over — one per kind.
let driver = null;
let appliers = null;

// WHO THIS PROCESS IS, from the driver. It is the SECOND place a process's own
// rows are skipped, and that is belt-and-braces rather than a duplicate: the
// first is the `origin <> $2` in `changesSince()`'s SQL. A driver that forgot
// that clause — or a future driver written against this interface — would
// produce the one failure in this whole feature that is UNBOUNDED. Each
// process would apply its own write, journal it, flush it, and wake the other,
// for ever; both services would answer perfectly correctly the whole time, and
// the only symptom would be a database doing thousands of writes a second
// while nothing at all is happening. A string comparison per row is a cheap
// price for making that unreachable from either side.
let origin = '';

// The high-water mark: every change up to and including this one has been
// applied here. Set at startup to whatever the log's maximum was at the moment
// the restore finished, because a process that has just read the whole store
// is up to date with everything committed before that instant by definition.
//
// **SINCE 2026-09-14 (#46) IT IS A LOW-WATER MARK AND `highest` IS BESIDE
// IT.** `applied` is "every seq at or below this is applied or given up on";
// `highest` is the newest seq applied; the seqs between them that were not yet
// visible are `holes`. See page() for why the reader no longer stops at a hole.
let applied = 0;
let highest = 0;
// seq -> when this process first saw it missing (Date.now()).
const holes = new Map();

let timer = null;
let unwatch = null;
let running = false;   // one catch-up at a time
// HOW LONG A HOLE IS ASKED FOR. A hole is a transaction still committing, or
// one that rolled back and burnt its seq. Until 2026-09-14 the reader STOPPED at
// a hole for four seconds and then skipped it for ever — so a transaction that
// took longer than four seconds to commit, which under a busy database and a
// large directory flush is not exotic, was never applied in that process until
// it restarted. Now the reader applies what it can see and keeps asking for the
// hole, for long enough that a transaction still open at the end of it is not a
// transaction this service holds (every statement it issues is short).
const HOLE_EXPIRE_MS = 10 * 60 * 1000;
// A ceiling on the holes remembered, so a pathological run of rollbacks cannot
// make every pull ask for an unbounded array. The oldest are given up on first.
const MAX_HOLES = 10000;
let holesAbandoned = 0;
// How long syncNow() may spend reaching its guarantee. See step() in syncNow().
const SYNC_DEADLINE_MS = 4600;
// How many pulls have STARTED, and the start number of the newest one that
// FINISHED. See syncNow(): a barrier waits for a pull that began after it read
// its target.
let pullsStarted = 0;
let lastCompletedStartNo = 0;

// Holes older than HOLE_EXPIRE_MS, and the oldest beyond MAX_HOLES, are given
// up on. ONE log line per pass however many went, with the count, because a
// burst of rollbacks would otherwise be a line per burnt sequence number.
function expireHoles(now) {
  log.debug("Entering expireHoles().");
  const gone = [];
  holes.forEach(function (since, seq) {
    if (now - since >= HOLE_EXPIRE_MS) {
      gone.push(seq);
    }
  });
  if (holes.size - gone.length > MAX_HOLES) {
    const oldest = Array.from(holes.keys()).sort(function (a, b) {
      return a - b;
    });
    for (let i = 0; i < oldest.length &&
         holes.size - gone.length > MAX_HOLES; i++) {
      if (gone.indexOf(oldest[i]) < 0) {
        gone.push(oldest[i]);
      }
    }
  }
  gone.forEach(function (seq) {
    holes.delete(seq);
  });
  if (gone.length) {
    holesAbandoned += gone.length;
    log.warn(errorCodes.tag('STS-STORE-0049') + 'persistence: ' +
             gone.length + ' change-log sequence number(s) never became ' +
             'visible (the oldest was ' + Math.min.apply(null, gone) + ') and ' +
             'are no longer asked for; they were transactions that rolled ' +
             'back. ' + holes.size + ' hole(s) are still being asked for.');
  }
  log.debug("Leaving expireHoles().");
}

// `applied` is just below the oldest hole still asked for, or `highest`.
function settleWatermark() {
  log.debug("Entering settleWatermark().");
  let oldest = 0;
  holes.forEach(function (since, seq) {
    if (!oldest || seq < oldest) {
      oldest = seq;
    }
  });
  applied = oldest ? Math.max(applied, oldest - 1) : highest;
  log.debug("Leaving settleWatermark().");
}
// THE PULL THAT IS RUNNING, so a caller that needs one CAN WAIT for it rather
// than being told there is nothing to do. `pull()` answers immediately when one
// is already in flight — right for a timer, and wrong for `syncNow()`, which is
// a request waiting to be answered correctly. See syncNow().
let runningPull = null;
let pendingWake = false;
let stopped = false;

// What /admin/persistence reports.
let startedAt = null;
let lastPullAt = null;
let lastError = '';
let pulls = 0;
let failures = 0;
let rowsApplied = 0;
let nudges = 0;
const byKind = {};

// A page of log rows per query. Bounded because a process that was down for an
// hour has an hour of log to catch up on, and reading it in one query would be
// a multi-second stall on the event loop that owns every socket here.
const PAGE = 500;

function enabled() {
  log.debug("Entering enabled().");
  log.debug("Leaving enabled().");
  return !!driver && !stopped && !!config.value('persistence.coordinate');
}

function intervalMs() {
  log.debug("Entering intervalMs().");
  log.debug("Leaving intervalMs().");
  return Math.max(250,
                  Number(config.value('persistence.pollInterval')) || 5000);
}

// ---------------------------------------------------------------------------
// Does this driver coordinate at all? Tested by function name for the reason
// `persistence_minted.js`'s `supports()` is: the ldif driver has none of these
// and cannot have them — a change log needs a transaction and a sequence, and
// that driver's unit of writing is a whole file.
// ---------------------------------------------------------------------------
function supports(theDriver) {
  log.debug("Entering supports().");
  log.debug("Leaving supports().");
  return !!(theDriver &&
            typeof theDriver.changesSince === 'function' &&
            typeof theDriver.latestChangeSeq === 'function');
}

// ---------------------------------------------------------------------------
// STARTING. Called from `server.js` AFTER the whole store has been restored —
// including the minted rows, which need the keystore — because the high-water
// mark is only meaningful once this process is up to date.
// ---------------------------------------------------------------------------
function start(theDriver, theAppliers) {
  log.debug('Entering start().');
  driver = supports(theDriver) ? theDriver : null;
  appliers = theAppliers || {};
  origin = driver && typeof driver.origin === 'function' ? driver.origin() : '';
  if (!driver) {
    log.debug('Leaving start(). This driver does not coordinate.');
    return Promise.resolve({ coordinating: false });
  }
  if (!config.value('persistence.coordinate')) {
    log.info('persistence: cross-process coordination is OFF ' +
             '(persistence.coordinate). This process will not see another\'s ' +
             'writes until it restarts, which is what this service did ' +
             'before 2026-09-06.');
    driver = null;
    log.debug('Leaving start(). Turned off.');
    return Promise.resolve({ coordinating: false });
  }

  log.debug("Leaving start().");
  return driver.latestChangeSeq().then(function (seq) {
    applied = seq;
    highest = seq;
    holes.clear();
    startedAt = new Date().toISOString();
    // THE NUDGE FIRST, THE TIMER SECOND, and neither is load-bearing on its
    // own: the timer is the contract and the listener only makes it prompt.
    unwatch = typeof driver.watchChanges === 'function'
      ? driver.watchChanges(function () { nudges++; wake(); })
      : null;
    schedule();
    // WHERE THIS PROCESS STARTS READING, said before anything is trimmed
    // below it — see RETENTION below. Not awaited: a report that fails is
    // retried after the next pull, and the trim never goes below a reader
    // nobody has declared gone, which a process that has not reported yet is
    // not (the retention period covers it).
    reportPosition(true);
    startRetention();
    log.info('persistence: coordinating with other processes against this ' +
             'store, from change ' + applied + '. The change log is the ' +
             'contract and is polled every ' + intervalMs() + 'ms; the ' +
             'LISTEN/NOTIFY nudge only makes it prompt, so losing it costs ' +
             'latency and never a change. THIS DOES NOT SHARE SOCKETS: the ' +
             'KDC, the LDAP listeners, the TLS ports and SPIFFE\'s four are ' +
             'per process, and the replay caches converge rather than ' +
             'synchronise.');
    log.debug('Leaving start(). Coordinating from ' + applied + '.');
    return { coordinating: true, from: applied };
  }).catch(function (err) {
    // NOT FATAL, unlike the restore. A process that cannot read the change log
    // is exactly the process this service was before this file existed — it
    // holds its own copy and is correct about it — so it starts, says so, and
    // keeps trying on the timer.
    driver = theDriver;
    lastError = err.message;
    log.error(errorCodes.tag('STS-STORE-0037') +
              'persistence: the change log could not be read at startup (' +
              err.message + '). This process is running UNCOORDINATED: it ' +
              'holds its own copy and will not see another process\'s ' +
              'writes. It will keep trying.');
    schedule();
    log.debug('Leaving start(). Uncoordinated for now.');
    return { coordinating: false, error: err.message };
  });
}

function schedule() {
  log.debug("Entering schedule().");
  if (timer || stopped) {
    log.debug("Leaving schedule().");
    return;
  }
  timer = setTimeout(function () {
    timer = null;
    pull().catch(function (err) {
      log.error(errorCodes.tag('STS-STORE-0038') +
                'persistence: a scheduled change pull failed: ' + err.message);
    }).then(function () {
      schedule();
    });
  }, intervalMs());
  // Must not hold the process open on its own: a service with nothing else to
  // do should still be able to exit.
  if (timer.unref) {
    timer.unref();
  }
  log.debug("Leaving schedule().");
}

// A nudge arrived. Pull NOW rather than at the next tick — and if one is
// already running, remember to go round again, because the row that woke us
// may have been committed after the running pull took its page.
function wake() {
  log.debug("Entering wake().");
  if (!enabled()) {
    log.debug("Leaving wake().");
    return;
  }
  if (running) {
    pendingWake = true;
    log.debug("Leaving wake().");
    return;
  }
  pull().catch(function (err) {
    log.error(errorCodes.tag('STS-STORE-0038') +
              'persistence: a nudged change pull failed: ' + err.message);
  });
  log.debug("Leaving wake().");
}

// ---------------------------------------------------------------------------
// THE PULL. One page at a time, applied in `seq` order, until the log is
// exhausted.
//
// ORDER IS THE WHOLE CORRECTNESS ARGUMENT: two writes to one key have to be
// applied in the order they were COMMITTED, or the loser of a race wins here.
// `seq` is a bigserial assigned inside the transaction, so it is the commit
// order rather than a timestamp taken by whichever process happened to be
// writing.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// A READ BARRIER: EVERYTHING COMMITTED BEFORE THIS CALL IS APPLIED WHEN IT
// RESOLVES (2026-09-07).
//
// `pull()` below is the CONVERGENCE path and is deliberately fire-and-forget —
// it returns at once when a pull is already running, because a second
// overlapping catch-up would read the same pages twice to no purpose. That is
// right for the timer and for a nudge, and it is useless as a barrier: a caller
// that needs to know it is up to date cannot be told "a pull was already in
// flight" and take that for an answer.
//
// So this is the other shape. It reads the log's head ONCE, and then pulls
// until `applied` has reached it. Two properties follow and both are needed:
//
//   * **The target is taken at call time**, so this waits for the writes that
//     had already committed when it was asked and NOT for whatever is written
//     while it runs. Waiting for a moving head against a busy writer would
//     never resolve.
//   * **It waits out a pull already in flight** rather than returning, which is
//     the whole difference from `pull()`.
//
// What it is FOR is read-your-write across processes. `request_pool.js` calls
// it through a worker before that worker serves a request, when another worker
// has written since it last caught up — so a client that writes through one
// worker and reads through another sees its own write, which the polling
// convergence alone does not promise. That cost is paid by the READER that
// needs it, once per worker per write, rather than by every write waiting for
// every process.
//
// It resolves rather than rejects on a store that cannot be read: the caller is
// about to serve a request, and the honest answer is the same one this module
// gives everywhere else — this process is correct about its own copy and alone
// with it. `caughtUp` says which, so the caller can decide.
// ---------------------------------------------------------------------------
function syncNow() {
  log.debug('Entering syncNow(). applied=' + applied);
  if (!enabled()) {
    log.debug('Leaving syncNow(). Not coordinating.');
    return Promise.resolve({ caughtUp: false, applied: applied,
                             coordinating: false });
  }
  // -------------------------------------------------------------------------
  // NO HEAD QUERY, SINCE 2026-09-14 (#46) — THE PROOF IS THE PULL.
  //
  // This read the log's head first (`latestBlockingChangeSeq()`) and then
  // pulled until `highest` reached it AND a pull that began after the read had
  // finished. The second condition, added on 2026-09-14 for late commits, is a
  // proof on its own and makes the first redundant: a pull that STARTED after
  // this call reads with snapshots taken after it, and every row committed
  // before this call is visible to every such snapshot — so its pages take
  // every such row above `highest`, and its hole re-check takes every such row
  // below it that an earlier pull stepped over. (A seq one of ITS pages steps
  // over was not committed when that page was read, so was not committed
  // before this call either, and is not owed.) When it finishes, everything
  // committed before this call is applied; the head adds nothing.
  //
  // **AND THE HEAD WAS THE MOST EXPENSIVE QUERY A NODE RAN.** It was
  // `MAX(seq) WHERE kind <> 'minted-own' AND origin <> $1` — a backward walk
  // of the primary key past every row this process wrote and every
  // `minted-own` row, which on a node answering alone is every row in the log:
  // measured on one active-active node, a read that took 4ms without the
  // barrier took 23ms, then 68ms as the log grew. Waiting on the target also
  // tied a reader to rows it does not need (rule 1 of cluster_barrier.js is
  // "what was committed before it arrived", and the pull applies exactly
  // that, `minted-own` included — which is what audit read-back needs).
  //
  // What it costs now is one pull: one page query, and a hole query when an
  // earlier pull stepped over a seq that has not appeared yet. Concurrent
  // callers share it (cluster_barrier.js's syncShared()).
  //
  // WHAT IT STILL WAITS FOR, AND WHY: a pull already in flight when this was
  // called is not a proof — its page may have been read before a row committed
  // — so it is waited out and a new one is started; and a pull that FAILS
  // proves nothing either, so the loop below starts another, up to a bound.
  // -------------------------------------------------------------------------
  const needNo = pullsStarted;

  function settled() {
    log.debug("Entering settled().");
    log.debug("Leaving settled().");
    return (runningPull || Promise.resolve()).catch(function (e) {
      // A pull that failed is the timer's business to report; this only needs
      // to know it has finished.
      log.debug("Caught in syncNow(): a pull in flight failed: " +
                ((e && e.message) || e));
    });
  }

  // A DEADLINE, NOT A COUNT OF ATTEMPTS — carried over from develop's
  // 2026-09-15 change when feature/46 was rebased. It was `step(200)`, and a
  // pull that fails (a database that blinked) returns in a millisecond, so two
  // hundred of them could be spent long before the store came back. Develop's
  // version bounded the old wait for a hole; this reader never waits for a
  // hole, so what the deadline bounds here is a run of failing pulls. It stays
  // inside `request_pool.js`'s five-second BARRIER_TIMEOUT_MS so a reader is
  // answered by this rather than abandoned by that.
  const deadline = Date.now() + SYNC_DEADLINE_MS;

  function step() {
    log.debug("Entering step().");
    if (lastCompletedStartNo > needNo) {
      log.debug("Leaving step(). Caught up.");
      return Promise.resolve({ caughtUp: true, applied: applied,
                               target: highest, coordinating: true });
    }
    if (Date.now() >= deadline) {
      // A BOUND rather than a spin. Reaching it means something is wrong with
      // the store rather than that more time is needed, and a request held for
      // ever is worse than one answered from a copy that is a moment behind.
      log.warn(errorCodes.tag('STS-STORE-0039') +
               'persistence: a read barrier gave up at ' + highest +
               ': no change pull started after it completed. The request is ' +
               'being answered from what this process has.');
      log.debug("Leaving step(). Gave up.");
      return Promise.resolve({ caughtUp: false, applied: applied,
                               target: highest, coordinating: true });
    }
    log.debug("Leaving step().");
    // WAITED OUT RATHER THAN POLLED. This slept 5ms per turn while a pull ran,
    // which added up to 5ms to every barrier that met one — and under load
    // nearly every barrier meets one. `runningPull` settles when that pull's
    // pages have been applied.
    return settled().then(function () {
      if (lastCompletedStartNo > needNo) {
        return null;
      }
      return pull();
    }).then(function () {
      return step();
    });
  }

  log.debug("Leaving syncNow().");
  return step().catch(function (err) {
    log.warn(errorCodes.tag('STS-STORE-0040') +
             'persistence: a read barrier could not read the change log: ' +
             err.message + '. The request is being answered from what this ' +
             'process has.');
    return { caughtUp: false, applied: applied, coordinating: true };
  });
}

function pull() {
  log.debug("Entering pull().");
  if (!enabled() || running) {
    log.debug("Leaving pull().");
    return Promise.resolve({ applied: 0 });
  }
  running = true;
  log.debug('Entering pull(). from=' + applied);
  let settle = null;
  runningPull = new Promise(function (resolve) { settle = resolve; });

  // THE NUMBER OF THIS PULL, for syncNow(): a barrier is satisfied only by a
  // pull that STARTED after it read its target, because only such a pull's
  // queries could see every row committed before that read.
  const startNo = ++pullsStarted;

  function page() {
    log.debug("Entering page().");
    log.debug("Leaving page().");
    // -----------------------------------------------------------------------
    // PAST THE HOLES, AND BACK FOR THEM (2026-09-14, #46).
    //
    // `seq` is allocated at INSERT and becomes visible at COMMIT, so a reader
    // can see 105 while 103 is still committing. Until this date the reader
    // took only the unbroken run from `applied + 1`, waited up to four seconds
    // for the hole, then skipped it for ever — correct for one busy process
    // and wrong for a cluster, where several nodes commit at once and there is
    // nearly always a hole: every node's view stalled behind every other
    // node's slowest transaction, and a transaction slower than four seconds
    // was lost in every process that skipped it.
    //
    // Reading past a hole is safe BECAUSE EVERY APPLIER READS THE CURRENT ROW
    // rather than replaying an operation: applying 105 before 103 and 103
    // afterwards leaves exactly the state applying them in order would, since
    // each re-reads what its key holds NOW. So this page takes everything
    // visible above `highest`, remembers each gap it steps over as a hole,
    // asks for the holes again on every pull, and gives a hole up only after
    // HOLE_EXPIRE_MS — ten minutes, not four seconds.
    // -----------------------------------------------------------------------
    return driver.changesSince(highest, PAGE).then(function (rows) {
      if (!rows.length) {
        return 0;
      }
      const now = Date.now();
      let expect = highest + 1;
      rows.forEach(function (row) {
        while (expect < row.seq) {
          if (!holes.has(expect)) {
            holes.set(expect, now);
          }
          expect += 1;
        }
        expect = row.seq + 1;
      });
      return applyRows(rows).then(function () {
        // ADVANCED ONLY AFTER THE APPLY, so a failure part-way re-reads the
        // same page rather than skipping it. Applying a row twice is
        // harmless — every applier is idempotent by construction, because it
        // writes a whole value read from the store — and skipping one is not.
        highest = rows[rows.length - 1].seq;
        rowsApplied += rows.length;
        return rows.length === PAGE ? page() : rows.length;
      });
    });
  }

  // THE HOLES, ASKED FOR AGAIN. One query for all of them. A hole that has
  // appeared is applied and forgotten; one that has lasted HOLE_EXPIRE_MS is
  // given up on, out loud; and `applied` moves up to just below the oldest
  // hole still being asked for.
  function recheckHoles() {
    log.debug("Entering recheckHoles().");
    if (!holes.size) {
      applied = highest;
      log.debug("Leaving recheckHoles(). None.");
      return Promise.resolve(0);
    }
    const asked = Array.from(holes.keys());
    // A DRIVER THAT CANNOT BE ASKED FOR ONE SEQ is asked for everything above
    // the oldest hole instead, and only the holes are kept. It used to age the
    // hole out without ever reading it again, which loses a late commit in
    // exactly the way this function exists to prevent — found when a test
    // arriving from develop drove the late-commit case through a stub with no
    // `changesAt()`. A page is bounded, so a hole buried under more than a
    // page of newer rows waits for the page to reach it.
    const lookup = typeof driver.changesAt === 'function'
      ? driver.changesAt(asked)
      : driver.changesSince(Math.min.apply(null, asked) - 1, PAGE);
    log.debug("Leaving recheckHoles().");
    return Promise.resolve(lookup).then(function (found) {
      const rows = (found || []).filter(function (row) {
        return holes.has(row.seq);
      });
      return (rows.length ? applyRows(rows) : Promise.resolve())
        .then(function () {
          rows.forEach(function (row) {
            holes.delete(row.seq);
          });
          rowsApplied += rows.length;
          expireHoles(Date.now());
          settleWatermark();
          return rows.length;
        });
    });
  }

  log.debug("Leaving pull().");
  return page().then(function () {
    return recheckHoles();
  }).then(function () {
    pulls++;
    lastCompletedStartNo = Math.max(lastCompletedStartNo, startNo);
    lastPullAt = new Date().toISOString();
    lastError = '';
    running = false;
    reportPosition(false);
    if (settle) { settle(); settle = null; runningPull = null; }
    if (pendingWake) {
      pendingWake = false;
      return pull();
    }
    log.debug('Leaving pull(). At ' + applied + '.');
    return { applied: applied };
  }).catch(function (err) {
    failures++;
    lastError = err.message;
    running = false;
    if (settle) { settle(); settle = null; runningPull = null; }
    pendingWake = false;
    // NOT rethrown past the counters, for the reason every failure on this
    // path is swallowed: a database that blinked must not take down a service
    // that is answering perfectly well out of memory. The high-water mark was
    // not advanced, so the next pull retries exactly the same rows.
    log.error(errorCodes.tag('STS-STORE-0038') +
              'persistence: could not apply another process\'s changes: ' +
              err.message + '. This process is serving its own copy and will ' +
              'retry; it is BEHIND until it succeeds.');
    log.debug('Leaving pull(). It failed.');
    return { applied: applied, error: err.message };
  });
}

// ---------------------------------------------------------------------------
// APPLYING. Each row is a POINTER — a kind, a realm and a key — so this reads
// what it names and hands it to the applier for that kind.
//
// **EVERY APPLY RUNS INSIDE `realms.run()`.** The realm is ambient in this
// service, and a store written outside a realm context writes the default
// realm's partition — which for a change that came from realm `acme` would put
// another realm's session in this one. That is the single most likely bug in
// this file and it is why the wrapper is here rather than in each applier.
// ---------------------------------------------------------------------------
function applyRows(rows) {
  log.debug("Entering applyRows().");
  // COALESCED: a page can name one directory entry ten times, and re-reading
  // it ten times would be ten queries for one answer. The LAST occurrence
  // wins, which is also the correct one — it is the latest committed state.
  const seen = new Map();
  rows.forEach(function (row) {
    // THIS PROCESS'S OWN ROW, skipped here as well as in the query — see the
    // `origin` binding above for why both are worth having.
    if (origin && row.origin === origin) {
      return;
    }
    seen.set(row.kind + '\u0000' + row.realm + '\u0000' + row.key, row);
  });

  // ---------------------------------------------------------------------
  // A KIND MAY ASK TO SEE THE WHOLE PAGE FIRST (2026-09-07).
  //
  // The loop below is strictly serial and every applier reads what its row
  // names, which is one database round trip per row. That was affordable until
  // minted rows joined the change log and became most of it — a measured page
  // was 500 sequential reads, against a 5000ms read-your-write barrier.
  //
  // `prepare` is optional and advisory: an applier that implements it gets the
  // rows of its kind before any of them is applied and may read them in one
  // query; one that does not is untouched, and so is a driver that cannot
  // batch. Nothing below depends on it having run — a prepare that fails or is
  // absent leaves every applier reading for itself, which is the old path.
  // ---------------------------------------------------------------------
  const byKindRows = new Map();
  seen.forEach(function (row) {
    if (!byKindRows.has(row.kind)) {
      byKindRows.set(row.kind, []);
    }
    byKindRows.get(row.kind).push(row);
  });
  let chain = Promise.resolve();
  byKindRows.forEach(function (rowsOfKind, kind) {
    const applier = appliers[kind];
    if (applier && typeof applier.prepare === 'function') {
      chain = chain.then(function () {
        return Promise.resolve(applier.prepare(rowsOfKind)).catch(function (e) {
          log.warn(errorCodes.tag('STS-STORE-0041') +
                   'replication: preparing ' + rowsOfKind.length + ' "' + kind +
                   '" row(s) failed (' + e.message + '); they are applied ' +
                   'one at a time.');
        });
      });
    }
  });
  seen.forEach(function (row) {
    chain = chain.then(function () {
      byKind[row.kind] = (byKind[row.kind] || 0) + 1;
      const applier = appliers[row.kind];
      if (typeof applier !== 'function') {
        // A kind this build does not know. Ordinary during a rolling upgrade,
        // and counted rather than thrown for that reason: an older process
        // must not fall over because a newer one wrote a kind it has never
        // heard of.
        log.debug('persistence: change kind "' + row.kind + '" has no ' +
                  'applier here; skipped.');
        return null;
      }
      const realm = realms.get(row.realm) || null;
      return realms.run(realm, function () {
        // -----------------------------------------------------------------
        // ONE ROW'S FAILURE IS NOT THE PAGE'S. A single entry that will not
        // apply — a value this build cannot parse, a store that refused it —
        // must not stop every other change in the page, because the
        // alternative is one bad row wedging replication for ever at the same
        // `seq` while this process goes on reporting that it is coordinating.
        //
        // **THE `try` IS AROUND THE CALL AND NOT ONLY AROUND THE PROMISE, and
        // that is a defect `tests/replication.js` caught before this shipped.**
        // It was `Promise.resolve(applier(row)).catch(…)`, which handles a
        // REJECTED promise and does nothing at all for a SYNCHRONOUS throw:
        // the throw happens while the argument to `Promise.resolve` is being
        // evaluated, so it escapes the `.catch` that was written for it,
        // propagates out of this function into the chain, and takes every
        // later row in the page with it. Both applier shapes are real —
        // `applyKeysChange()` is synchronous and the rest are not — so the
        // wrong half was the one nothing in this repository would have
        // exercised.
        // -----------------------------------------------------------------
        function failed(err) {
          log.debug("Entering failed().");
          log.error(errorCodes.tag('STS-STORE-0042') +
                    'persistence: a "' + row.kind + '" change for "' +
                    row.key + '" in realm "' + (row.realm || 'default') +
                    '" could not be applied: ' + err.message +
                    '. The rest of the page is unaffected.');
          log.debug("Leaving failed().");
        }
        let out = null;
        try {
          out = applier(row);
        } catch (err) {
          failed(err);
          return null;
        }
        return Promise.resolve(out).catch(failed);
      });
    });
  });
  log.debug("Leaving applyRows().");
  // THE PAGE'S WORKING SET GOES WITH THE PAGE. A prefetch held past the page
  // it was read for would be this process believing a row is still there
  // because it was there a page ago; see persistence_minted.js's prefetch().
  return chain.then(function () {
    Object.keys(appliers || {}).forEach(function (kind) {
      const applier = appliers[kind];
      if (applier && typeof applier.done === 'function') {
        try {
          applier.done();
        } catch (e) {
          log.warn(errorCodes.tag('STS-STORE-0043') +
                   'replication: clearing the "' + kind + '" page state ' +
                   'failed: ' + e.message);
        }
      }
    });
  });
}

// ---------------------------------------------------------------------------
// THE FAN-IN FOR `merge: 'own'` STORES — the counters and the audit ring.
//
// Each process writes ONLY ITS OWN row for these, so what another process
// contributed is in the store and not in memory. This holds what the appliers
// have read, and the reporting functions in `admin_stats.js`, `audit.js` and
// `xacml_monitor.js` ask for it.
//
// It is HERE rather than in `persistence_minted.js` because it exists only
// because there is more than one process: a single process's report is its own
// memory and always was.
// ---------------------------------------------------------------------------
// handle -> realm -> key -> origin -> value. FOUR levels because all four are
// needed to name one contribution: `admin_stats.calls` is a MAP whose keys are
// HTTP paths, so "what did the other processes count for GET /oauth2/token in
// realm acme" needs every one of them. The obj- and arr-shaped stores use the
// empty string as their key, which is what their own accessors already do.
const contributions = new Map();

function contribute(handle, realmId, key, origin, value) {
  log.debug("Entering contribute().");
  let byRealm = contributions.get(handle);
  if (!byRealm) {
    byRealm = new Map();
    contributions.set(handle, byRealm);
  }
  const id = String(realmId || '');
  let byKey = byRealm.get(id);
  if (!byKey) {
    byKey = new Map();
    byRealm.set(id, byKey);
  }
  const k = String(key === undefined || key === null ? '' : key);
  let byOrigin = byKey.get(k);
  if (!byOrigin) {
    byOrigin = new Map();
    byKey.set(k, byOrigin);
  }
  if (value === null || value === undefined) {
    byOrigin.delete(origin);
    log.debug("Leaving contribute().");
    return;
  }
  byOrigin.set(origin, value);
  log.debug("Leaving contribute().");
}

// What every OTHER process has contributed under this handle, realm and key,
// as an array of values. THE CALLER MERGES — a sum for a counter, a
// concatenation for a ring — because only the caller knows what its own rows
// mean. This file deliberately has no idea: a generic "merge" here would be a
// second place the shape of every counter is written down.
//
// `realmId` undefined means THE AMBIENT REALM, which is what every caller
// wants: these are all read from inside a request or a console page, where the
// realm is already established.
function remoteRows(handle, realmId, key) {
  log.debug("Entering remoteRows().");
  const byRealm = contributions.get(handle);
  if (!byRealm) {
    log.debug("Leaving remoteRows().");
    return [];
  }
  const byKey = byRealm.get(String(realmId === undefined
                                   ? realms.currentId() : (realmId || '')));
  if (!byKey) {
    log.debug("Leaving remoteRows().");
    return [];
  }
  const byOrigin = byKey.get(String(key === undefined || key === null
                                    ? '' : key));
  if (!byOrigin) {
    log.debug("Leaving remoteRows().");
    return [];
  }
  log.debug("Leaving remoteRows().");
  return Array.from(byOrigin.values());
}

// ---------------------------------------------------------------------------
// THE SAME FAN-IN FOR A SEGMENTED ARRAY (`realms.arr({ segment })`, 2026-09-14,
// #46): one array of elements per other process, put back together from that
// process's segments in position order. A contribution under a segmented
// handle is `{ start, rows }` per key; a bare array is a whole-array row an
// older build wrote, and is taken as it is, ahead of any segment.
//
// THE CALLER TRIMS. A process drops a stored segment only once every element
// in it has left its ring (see realms.js), so what comes back can carry up to
// one segment more than that process holds — `audit.js` keeps the newest
// `audit.maxEvents` of each.
// ---------------------------------------------------------------------------
function remoteSegmentedRows(handle, realmId) {
  log.debug("Entering remoteSegmentedRows().");
  const byRealm = contributions.get(handle);
  const byKey = byRealm
    ? byRealm.get(String(realmId === undefined
                         ? realms.currentId() : (realmId || '')))
    : null;
  if (!byKey) {
    log.debug("Leaving remoteSegmentedRows(). None.");
    return [];
  }
  const parts = new Map();
  byKey.forEach(function (byOrigin) {
    byOrigin.forEach(function (value, from) {
      if (!parts.has(from)) {
        parts.set(from, []);
      }
      if (Array.isArray(value)) {
        parts.get(from).push({ start: -Infinity, rows: value });
      } else if (value && Array.isArray(value.rows)) {
        parts.get(from).push({ start: Number(value.start) || 0,
                               rows: value.rows });
      }
    });
  });
  const out = [];
  parts.forEach(function (segments) {
    segments.sort(function (a, b) {
      return a.start - b.start;
    });
    const rows = [];
    segments.forEach(function (one) {
      one.rows.forEach(function (row) {
        rows.push(row);
      });
    });
    out.push(rows);
  });
  log.debug("Leaving remoteSegmentedRows(). " + out.length + " origin(s).");
  return out;
}

// Every key another process has contributed under this handle in this realm.
// What a MAP-shaped counter store needs before it can ask for each: another
// process may be counting a path this one has never served.
function remoteKeys(handle, realmId) {
  log.debug("Entering remoteKeys().");
  const byRealm = contributions.get(handle);
  if (!byRealm) {
    log.debug("Leaving remoteKeys().");
    return [];
  }
  const byKey = byRealm.get(String(realmId === undefined
                                   ? realms.currentId() : (realmId || '')));
  log.debug("Leaving remoteKeys().");
  return byKey ? Array.from(byKey.keys()) : [];
}

// Is anything in another process's hands at all? The console asks, so that a
// single-process deployment can be told it is one rather than being shown an
// empty fan-in it has to interpret.
function origins() {
  log.debug("Entering origins().");
  const all = new Set();
  contributions.forEach(function (byRealm) {
    byRealm.forEach(function (byKey) {
      byKey.forEach(function (byOrigin) {
        byOrigin.forEach(function (value, origin) { all.add(origin); });
      });
    });
  });
  log.debug("Leaving origins().");
  return Array.from(all);
}

// ===========================================================================
// RETENTION: TRIMMING THE LOG BELOW WHAT EVERY READER HAS APPLIED (2026-09-14,
// #46 section 8).
//
// `sts_changes` was never trimmed — `purgeChanges()` in the driver had no
// caller — so it was the one table that grew for ever, a row per write of
// every kind by every process. The difficulty is not the DELETE; it is
// knowing which rows nobody will ask for again, and the only honest source
// of that is the readers themselves.
//
// **EVERY PROCESS THAT READS THE LOG SAYS WHERE IT HAS GOT TO.** A front
// process AND each of its request workers — a worker is an origin of its own
// with its own `applied`, and the front process cannot see a worker's
// position, so the worker must report it itself; routing it through the
// front would be a second path that could fall behind the first. The report
// is `applied` — the LOW-water mark, below the oldest hole still asked for —
// into `sts_change_readers`, at start, after a pull at most every
// REPORT_INTERVAL_MS, and removed at a clean stop.
//
// **THE BOUND.** A row is removed when BOTH hold:
//
//   1. its seq is below the lowest `applied` of every reader NOT DECLARED
//      GONE — and with no reader at all nothing is removed;
//   2. it is older than `persistence.changeLogRetentionS` by the database's
//      clock.
//
// A reader is gone when it has not reported for READER_TTL (the retention,
// never less than READER_TTL_FLOOR_MS), or when the cluster node it names is
// no longer a live member — a node whose membership lapsed exits
// (`cluster/cluster.js`), and its workers with it. Why each half is needed:
//
//   * (1) alone would delete a row that committed LATE, below a reader's mark
//     only because it was a hole the reader gave up on — impossible under ten
//     minutes (HOLE_EXPIRE_MS) and harmless after; and a process that has
//     just started and not yet reported sits at `latestChangeSeq()`, which
//     only rows younger than its start can be above. (2) covers both for as
//     long as the retention is longer than a start and a hole.
//   * (2) alone would delete what a live but slow reader has not applied.
//
// **A PROCESS THAT WAS DECLARED GONE AND IS NOT** — paused past READER_TTL,
// with its node still a member — finds its row missing on its next report
// (`inserted`) and says so, `STS-STORE-0057`: rows it had not applied may have
// been trimmed, and it should be restarted, which restores from the store.
// It is not made to exit: a request worker's exit is not a restart here, and
// a pause that long is already a process nothing else trusts.
//
// **ONE TRIM FOR THE CLUSTER**: the lease `ops.change-log-purge`, led by one
// node (`cluster.lead()`); outside a cluster every FRONT process runs it,
// which is safe because the bound comes from the reports and not from the
// trimmer — two trims agree. A request worker never trims.
//
// **WHAT THIS DOES NOT TRIM**: the `merge: 'own'` rows of `sts_minted` that
// dead origins wrote (their counters and audit rings) — a separate table with
// its own `mintedRetention`, and every restart still leaves one more origin's
// rows behind until that removes them. `persistence/CLAUDE.md` says so.
// ===========================================================================
const REPORT_INTERVAL_MS = 15 * 1000;
const PURGE_INTERVAL_MS = 5 * 60 * 1000;
const READER_TTL_FLOOR_MS = 2 * 60 * 1000;
const PURGE_LEASE = 'ops.change-log-purge';
let lastReportAt = 0;
let reportedOnce = false;
let reportInFlight = false;
let lastReportError = '';
let declaredGoneAt = null;
let purgeTimer = null;
let purging = false;
let lastPurge = null;

function retentionMs() {
  log.debug("Entering retentionMs().");
  const seconds = Number(config.value('persistence.changeLogRetentionS'));
  log.debug("Leaving retentionMs().");
  return Number.isFinite(seconds) && seconds > 0 ? seconds * 1000 : 0;
}

function readerTtlMs() {
  log.debug("Entering readerTtlMs().");
  log.debug("Leaving readerTtlMs().");
  return Math.max(READER_TTL_FLOOR_MS, retentionMs());
}

// `cluster/cluster.js`, for which node this process is and one leader for the
// trim. REQUIRED LAZILY: it closes no cycle either way, but this file is in
// the parent project's in-process Kerberos closure (through `admin_stats.js`)
// and a top-level require would add `cluster.js` to the COPY set that project
// owes (kerberos/CLAUDE.md). Only a process that coordinates reaches it.
function clusterModule() {
  log.debug("Entering clusterModule().");
  log.debug("Leaving clusterModule().");
  return require('../cluster/cluster');
}

function nodeIdOf() {
  log.debug("Entering nodeIdOf().");
  let id = '';
  try {
    const cluster = clusterModule();
    id = cluster.enabled() ? String(cluster.nodeId() || '') : '';
  } catch (e) {
    log.debug("Caught in nodeIdOf(): " + ((e && e.message) || e));
    id = '';
  }
  log.debug("Leaving nodeIdOf().");
  return id;
}

// Says where this process has got to. `force` skips the interval — the report
// at start. Never rejects; returns the promise so a test can wait for it.
function reportPosition(force) {
  log.debug("Entering reportPosition().");
  if (!driver || stopped || typeof driver.reportChangeReader !== 'function' ||
      reportInFlight) {
    log.debug("Leaving reportPosition(). Not reporting.");
    return Promise.resolve(null);
  }
  const now = Date.now();
  if (!force && now - lastReportAt < REPORT_INTERVAL_MS) {
    log.debug("Leaving reportPosition(). Not due.");
    return Promise.resolve(null);
  }
  reportInFlight = true;
  lastReportAt = now;
  const position = applied;
  log.debug("Leaving reportPosition(). Reporting " + position + ".");
  return Promise.resolve().then(function () {
    return driver.reportChangeReader(position, nodeIdOf());
  }).then(function (answer) {
    reportInFlight = false;
    lastReportError = '';
    if (answer && answer.inserted && reportedOnce) {
      declaredGoneAt = new Date().toISOString();
      log.error(errorCodes.tag('STS-STORE-0057') + 'persistence: this ' +
                'process\'s place in the change log had been REMOVED since ' +
                'it last reported — another process declared it gone after ' +
                'it went ' + Math.round(readerTtlMs() / 1000) + 's without ' +
                'reporting — so changes it had not applied may already have ' +
                'been trimmed. It is at change ' + position + ' and carries ' +
                'on, but what it holds may be missing other processes\' ' +
                'writes: restart it, which restores from the store.');
    }
    reportedOnce = true;
    return answer;
  }, function (e) {
    reportInFlight = false;
    lastReportError = (e && e.message) || String(e);
    log.warn(errorCodes.tag('STS-STORE-0058') + 'persistence: this ' +
             'process\'s position in the change log could not be reported (' +
             lastReportError + '); it is tried again after the next pull. ' +
             'Until it lands the log is not trimmed past where this process ' +
             'last said it was.');
    return null;
  });
}

// One trim. Resolves the driver's answer, or null when there was nothing to
// do. Never rejects.
function purgeOnce() {
  log.debug("Entering purgeOnce().");
  if (!driver || stopped || purging ||
      typeof driver.purgeChangeLog !== 'function') {
    log.debug("Leaving purgeOnce(). Not trimming.");
    return Promise.resolve(null);
  }
  const keep = retentionMs();
  if (!keep) {
    log.debug("Leaving purgeOnce(). Retention is off.");
    return Promise.resolve(null);
  }
  purging = true;
  log.debug("Leaving purgeOnce(). Trimming.");
  return Promise.resolve().then(function () {
    return driver.purgeChangeLog({ retentionMs: keep,
                                   readerTtlMs: readerTtlMs() });
  }).then(function (answer) {
    purging = false;
    lastPurge = Object.assign({ at: new Date().toISOString(), error: null },
                              answer || {});
    if (answer && (answer.trimmed || answer.readersGone)) {
      log.info('persistence: trimmed ' + answer.trimmed + ' change-log ' +
               'row(s) below change ' + answer.bound + ', the lowest ' +
               'position of ' + answer.readers + ' reader(s); ' +
               answer.readersGone + ' reader(s) that stopped reporting were ' +
               'declared gone.');
    }
    return answer;
  }, function (e) {
    purging = false;
    lastPurge = { at: new Date().toISOString(),
                  error: (e && e.message) || String(e) };
    log.warn(errorCodes.tag('STS-STORE-0059') + 'persistence: trimming the ' +
             'change log failed (' + lastPurge.error + '); it is tried again ' +
             'in ' + Math.round(PURGE_INTERVAL_MS / 1000) + 's.');
    return null;
  });
}

function schedulePurge() {
  log.debug("Entering schedulePurge().");
  if (purgeTimer || stopped) {
    log.debug("Leaving schedulePurge().");
    return;
  }
  purgeTimer = setTimeout(function () {
    purgeTimer = null;
    purgeOnce().then(function () {
      schedulePurge();
    });
  }, PURGE_INTERVAL_MS);
  if (purgeTimer.unref) {
    purgeTimer.unref();
  }
  log.debug("Leaving schedulePurge().");
}

function stopPurging() {
  log.debug("Entering stopPurging().");
  if (purgeTimer) {
    clearTimeout(purgeTimer);
    purgeTimer = null;
  }
  log.debug("Leaving stopPurging().");
}

// Who trims: see RETENTION. Asked once, at start.
function startRetention() {
  log.debug("Entering startRetention().");
  if (process.env.STS_REQUEST_WORKER || !driver ||
      typeof driver.purgeChangeLog !== 'function') {
    log.debug("Leaving startRetention(). This process does not trim.");
    return;
  }
  clusterModule().lead(PURGE_LEASE, {
    onGain: function () {
      log.debug("Entering onGain().");
      schedulePurge();
      log.debug("Leaving onGain().");
    },
    onLose: function () {
      log.debug("Entering onLose().");
      stopPurging();
      log.debug("Leaving onLose().");
    }
  });
  log.debug("Leaving startRetention().");
}

function stop() {
  log.debug('Entering stop().');
  stopped = true;
  if (timer) {
    clearTimeout(timer);
    timer = null;
  }
  if (unwatch) {
    unwatch();
    unwatch = null;
  }
  stopPurging();
  const leaving = driver && typeof driver.leaveChangeReader === 'function' &&
    reportedOnce ? driver.leaveChangeReader() : null;
  log.debug('Leaving stop().');
  // A clean stop takes this process's place out of the log's readers, so the
  // trim is not held back for READER_TTL by a process that no longer exists.
  return Promise.resolve(leaving).then(function () {
    return undefined;
  }, function (e) {
    log.debug("Caught in stop(): " + ((e && e.message) || e));
    return undefined;
  });
}

function status() {
  log.debug("Entering status().");
  log.debug("Leaving status().");
  return {
    coordinating: enabled(),
    supported: supports(driver),
    startedAt: startedAt,
    appliedSeq: applied,
    highestSeq: highest,
    holes: holes.size,
    holesAbandoned: holesAbandoned,
    pollIntervalMs: intervalMs(),
    pulls: pulls,
    nudges: nudges,
    failures: failures,
    rowsApplied: rowsApplied,
    byKind: Object.assign({}, byKind),
    lastPullAt: lastPullAt,
    lastError: lastError || null,
    otherProcesses: origins().length,
    retention: {
      retentionS: Math.round(retentionMs() / 1000),
      readerTtlS: Math.round(readerTtlMs() / 1000),
      reportedAt: lastReportAt ? new Date(lastReportAt).toISOString() : null,
      reportError: lastReportError || null,
      declaredGoneAt: declaredGoneAt,
      trimming: !!purgeTimer,
      lastTrim: lastPurge
    },
    // Said on the page rather than only in a comment, because it is the one
    // thing about this feature that can be got wrong in a way that matters.
    note: 'Coordination shares STATE and not SOCKETS. The KDC, the LDAP ' +
          'listeners, the two TLS ports and SPIFFE\'s four are bound per ' +
          'process. And the replay caches and DPoP jti sets CONVERGE rather ' +
          'than synchronise: between a write in one process and its arrival ' +
          'in another there is a window the size of the poll interval in ' +
          'which a proof one process refused is accepted by another.'
  };
}

// For the tests, and for the reason `keystore.reset()` is exported.
function reset() {
  log.debug("Entering reset().");
  driver = null;
  appliers = null;
  origin = '';
  applied = 0;
  highest = 0;
  holes.clear();
  holesAbandoned = 0;
  pullsStarted = 0;
  lastCompletedStartNo = 0;
  stopped = false;
  running = false;
  runningPull = null;
  pendingWake = false;
  contributions.clear();
  if (timer) {
    clearTimeout(timer);
    timer = null;
  }
  if (unwatch) {
    unwatch();
    unwatch = null;
  }
  startedAt = null;
  lastPullAt = null;
  lastError = '';
  pulls = 0;
  failures = 0;
  rowsApplied = 0;
  nudges = 0;
  Object.keys(byKind).forEach(function (k) { delete byKind[k]; });
  stopPurging();
  lastReportAt = 0;
  reportedOnce = false;
  reportInFlight = false;
  lastReportError = '';
  declaredGoneAt = null;
  purging = false;
  lastPurge = null;
  log.debug("Leaving reset().");
}

// AT REQUIRE TIME, like every capability — see cluster/cluster.js. Reading past
// a hole and re-asking for it is what this is (page(), recheckHoles()).
capabilities.provide('replication.late-commits');
// And the log is trimmed below what every reader has applied — RETENTION above.
capabilities.provide('ops.change-log-retention');

module.exports = {
  start: start,
  stop: stop,
  syncNow: syncNow,
  supports: supports,
  pull: pull,
  wake: wake,
  reportPosition: reportPosition,
  purgeOnce: purgeOnce,
  contribute: contribute,
  remoteRows: remoteRows,
  remoteSegmentedRows: remoteSegmentedRows,
  remoteKeys: remoteKeys,
  origins: origins,
  status: status,
  reset: reset
};
