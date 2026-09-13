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
let applied = 0;

let timer = null;
let unwatch = null;
let running = false;   // one catch-up at a time
// The seq a pull is waiting to see, and since when. See page() below: a hole is
// an in-flight transaction until it has lasted long enough to be a rolled back
// one.
let holeAt = 0;
let holeSince = 0;
const HOLE_WAIT_MS = 4000;
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
  return !!driver && !stopped && !!config.value('persistence.coordinate');
}

function intervalMs() {
  return Math.max(250, Number(config.value('persistence.pollInterval')) || 5000);
}

// ---------------------------------------------------------------------------
// Does this driver coordinate at all? Tested by function name for the reason
// `persistence_minted.js`'s `supports()` is: the ldif driver has none of these
// and cannot have them — a change log needs a transaction and a sequence, and
// that driver's unit of writing is a whole file.
// ---------------------------------------------------------------------------
function supports(theDriver) {
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

  return driver.latestChangeSeq().then(function (seq) {
    applied = seq;
    startedAt = new Date().toISOString();
    // THE NUDGE FIRST, THE TIMER SECOND, and neither is load-bearing on its
    // own: the timer is the contract and the listener only makes it prompt.
    unwatch = typeof driver.watchChanges === 'function'
      ? driver.watchChanges(function () { nudges++; wake(); })
      : null;
    schedule();
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
  if (timer || stopped) {
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
}

// A nudge arrived. Pull NOW rather than at the next tick — and if one is
// already running, remember to go round again, because the row that woke us
// may have been committed after the running pull took its page.
function wake() {
  if (!enabled()) {
    return;
  }
  if (running) {
    pendingWake = true;
    return;
  }
  pull().catch(function (err) {
    log.error(errorCodes.tag('STS-STORE-0038') +
              'persistence: a nudged change pull failed: ' + err.message);
  });
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
  // THE TARGET IS WHAT A READER HAS TO SEE, WHICH IS NOT EVERY ROW. A driver
  // that can tell them apart says so; one that cannot answers with all of them,
  // which is the old behaviour and is correct, just slower.
  const target = typeof driver.latestBlockingChangeSeq === 'function'
    ? driver.latestBlockingChangeSeq()
    : driver.latestChangeSeq();
  return Promise.resolve(target).then(function (target) {
    const want = Number(target) || 0;
    // ----------------------------------------------------------------------
    // ONE PULL PASS EVEN WHEN THE TARGET IS ALREADY MET (2026-09-08).
    //
    // The target deliberately excludes `minted-own` — see the driver — and the
    // consequence was that a barrier which found `applied >= want` returned
    // having applied NOTHING, leaving every per-process tally exactly as stale
    // as it was. The caller only reached this function because the pool
    // decided it was behind, and the generation moves for counter writes too,
    // so "already at the target" here nearly always means "the outstanding
    // changes are all counters" — which is precisely the case the console is
    // about to read.
    //
    // `admin_api` measured it: three probes of `/healthcheck` across three
    // workers, and the metrics page counted ONE of them, because the reader
    // was released against a target those three writes were excluded from.
    //
    // It is one pass and not a wait: nobody's correctness depends on a tally,
    // so this catches up what it can and never blocks on it. That keeps the
    // reason the exclusion exists — a target that moves faster than it can be
    // reached cost 224 barrier timeouts in one run, every one a stale answer.
    // ----------------------------------------------------------------------
    // UNCONDITIONALLY, AND IT WAS CONDITIONAL FOR AN HOUR — which fixed half
    // the problem and read as though it fixed all of it. Running this only when
    // `applied >= want` covers a reader whose outstanding changes are ALL
    // excluded rows; it does nothing for the commoner case where there is also
    // a blocking row, because `step()` below then waits for the blocking target
    // and returns the moment it is reached, with the excluded rows still
    // unapplied. `sts_global_logout` measured exactly that: a global sign-out
    // could not revoke the Kerberos ticket another worker had issued, because
    // the artifact register it walks is `merge: 'own'` and its rows are the
    // excluded kind — so the sign-out swept a register that did not contain the
    // thing it was there to end, reported success, and left the session live.
    // AND IT WAITS FOR A PULL THAT IS ALREADY RUNNING BEFORE STARTING ITS OWN.
    // `pull()` answers at once when one is in flight, which is right for the
    // poll timer and useless here: this pass would then apply NOTHING at
    // exactly the moment it is needed, `step()` would find the blocking target
    // already met, and the reader would be released against rows still in the
    // page being applied. That is not theoretical — it is why the audit row
    // for a request could be missing from the very next read, which
    // `admin_api` reported as "NO /healthcheck row of any kind came back".
    const inFlight = runningPull || Promise.resolve();
    const opening = inFlight.catch(function () {
      // A pull that failed is the timer's business to report; this pass only
      // needs to know it has finished.
    }).then(function () {
      return pull();
    }).catch(function (e) {
      // Swallowed with a reason: this pass is a courtesy to the rows the
      // target excludes and must never turn a barrier that would have
      // succeeded into a failure.
      log.debug('syncNow(): the catch-up pass did not run: ' + e.message);
    });
    return opening.then(function () {

    function step(attempts) {
      if (applied >= want) {
        return { caughtUp: true, applied: applied, target: want,
                 coordinating: true };
      }
      if (attempts <= 0) {
        // A BOUND rather than a spin. Reaching it means something is wrong
        // with the store rather than that more time is needed, and a request
        // held for ever is worse than one answered from a copy that is a
        // moment behind.
        log.warn(errorCodes.tag('STS-STORE-0039') +
                 'persistence: a read barrier gave up at ' + applied +
                 ' of ' + want + '. The request is being answered from what ' +
                 'this process has.');
        return { caughtUp: false, applied: applied, target: want,
                 coordinating: true };
      }
      if (running) {
        // A pull is in flight and will advance `applied`. Waited out rather
        // than duplicated — see the header.
        return new Promise(function (resolve) {
          setTimeout(resolve, 5);
        }).then(function () {
          return step(attempts - 1);
        });
      }
      return pull().then(function () {
        return step(attempts - 1);
      });
    }

    return step(200);
    });
  }).catch(function (err) {
    log.warn(errorCodes.tag('STS-STORE-0040') +
             'persistence: a read barrier could not read the change log: ' +
             err.message + '. The request is being answered from what this ' +
             'process has.');
    return { caughtUp: false, applied: applied, coordinating: true };
  });
}

function pull() {
  if (!enabled() || running) {
    return Promise.resolve({ applied: 0 });
  }
  running = true;
  log.debug('Entering pull(). from=' + applied);
  let settle = null;
  runningPull = new Promise(function (resolve) { settle = resolve; });

  function page() {
    return driver.changesSince(applied, PAGE).then(function (rows) {
      if (!rows.length) {
        return 0;
      }
      // ---------------------------------------------------------------------
      // ONLY THE CONTIGUOUS RUN, AND NEVER PAST A HOLE (2026-09-08).
      //
      // `seq` is allocated at INSERT and the row appears at COMMIT, so the two
      // orders differ: reading while 105 is visible and 103 is not, then
      // advancing to 105, skips 103 for ever — it is only ever asked for as
      // `seq > applied`. Silent, permanent, and shaped exactly like the
      // failures that chased this service round all day: one worker of three
      // missing one directory entry that the store plainly holds.
      //
      // So the watermark advances only through an unbroken run from
      // `applied + 1`. A hole is an in-flight transaction and the next poll
      // finds it committed. `changesSince()` no longer filters by origin
      // precisely so that a hole means that and nothing else.
      //
      // A HOLE THAT NEVER FILLS IS SKIPPED, because one exists: a ROLLED BACK
      // transaction burns its sequence value and leaves a permanent gap.
      // Waiting for it for ever would wedge replication at that seq while the
      // status page went on saying "coordinating". So the wait is bounded and
      // the skip says so out loud.
      // ---------------------------------------------------------------------
      const want = applied + 1;
      let usable = rows;
      if (rows[0].seq !== want) {
        const now = Date.now();
        if (holeAt !== want) {
          holeAt = want;
          holeSince = now;
        }
        if (now - holeSince < HOLE_WAIT_MS) {
          log.debug('pull(): waiting for change ' + want + '; the log starts ' +
                    'at ' + rows[0].seq + '. An in-flight transaction, not a ' +
                    'lost row.');
          return 0;
        }
        log.warn('persistence: change ' + want + ' never appeared after ' +
                 HOLE_WAIT_MS + 'ms, so it was a transaction that rolled ' +
                 'back rather than one still committing. Skipping to ' +
                 rows[0].seq + '.');
        holeAt = 0;
      } else {
        holeAt = 0;
      }
      // The unbroken run from the first row.
      let expect = rows[0].seq;
      let end = 0;
      while (end < rows.length && rows[end].seq === expect) {
        end += 1;
        expect += 1;
      }
      usable = rows.slice(0, end);
      if (!usable.length) {
        return 0;
      }
      return applyRows(usable).then(function () {
        // ADVANCED ONLY AFTER THE APPLY, so a failure part-way re-reads the
        // same page rather than skipping it. Applying a row twice is
        // harmless — every applier is idempotent by construction, because it
        // writes a whole value read from the store — and skipping one is not.
        applied = usable[usable.length - 1].seq;
        rowsApplied += usable.length;
        // Another page only when this one was full AND wholly contiguous —
        // otherwise the rest is waiting on a commit and belongs to the next
        // poll.
        return (usable.length === rows.length && rows.length === PAGE)
          ? page() : usable.length;
      });
    });
  }

  return page().then(function () {
    pulls++;
    lastPullAt = new Date().toISOString();
    lastError = '';
    running = false;
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
                   '" row(s) failed (' + e.message + '); they are applied one ' +
                   'at a time.');
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
          log.error(errorCodes.tag('STS-STORE-0042') +
                    'persistence: a "' + row.kind + '" change for "' +
                    row.key + '" in realm "' + (row.realm || 'default') +
                    '" could not be applied: ' + err.message +
                    '. The rest of the page is unaffected.');
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
    return;
  }
  byOrigin.set(origin, value);
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
  const byRealm = contributions.get(handle);
  if (!byRealm) {
    return [];
  }
  const byKey = byRealm.get(String(realmId === undefined
                                   ? realms.currentId() : (realmId || '')));
  if (!byKey) {
    return [];
  }
  const byOrigin = byKey.get(String(key === undefined || key === null
                                    ? '' : key));
  if (!byOrigin) {
    return [];
  }
  return Array.from(byOrigin.values());
}

// Every key another process has contributed under this handle in this realm.
// What a MAP-shaped counter store needs before it can ask for each: another
// process may be counting a path this one has never served.
function remoteKeys(handle, realmId) {
  const byRealm = contributions.get(handle);
  if (!byRealm) {
    return [];
  }
  const byKey = byRealm.get(String(realmId === undefined
                                   ? realms.currentId() : (realmId || '')));
  return byKey ? Array.from(byKey.keys()) : [];
}

// Is anything in another process's hands at all? The console asks, so that a
// single-process deployment can be told it is one rather than being shown an
// empty fan-in it has to interpret.
function origins() {
  const all = new Set();
  contributions.forEach(function (byRealm) {
    byRealm.forEach(function (byKey) {
      byKey.forEach(function (byOrigin) {
        byOrigin.forEach(function (value, origin) { all.add(origin); });
      });
    });
  });
  return Array.from(all);
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
  log.debug('Leaving stop().');
  return Promise.resolve();
}

function status() {
  return {
    coordinating: enabled(),
    supported: supports(driver),
    startedAt: startedAt,
    appliedSeq: applied,
    pollIntervalMs: intervalMs(),
    pulls: pulls,
    nudges: nudges,
    failures: failures,
    rowsApplied: rowsApplied,
    byKind: Object.assign({}, byKind),
    lastPullAt: lastPullAt,
    lastError: lastError || null,
    otherProcesses: origins().length,
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
  driver = null;
  appliers = null;
  origin = '';
  applied = 0;
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
}

module.exports = {
  start: start,
  stop: stop,
  syncNow: syncNow,
  supports: supports,
  pull: pull,
  wake: wake,
  contribute: contribute,
  remoteRows: remoteRows,
  remoteKeys: remoteKeys,
  origins: origins,
  status: status,
  reset: reset
};
