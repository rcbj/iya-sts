// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: persistence/granting_index_backfill.js
//
// ===========================================================================
// THE `grantinggroup` KEYS OF THE ENTRIES WRITTEN BEFORE #1306, ONCE (#1311).
//
// #1306 made federated provisioning ask the store whether a group name a
// partner sent is named by one of the six GRANTING_ATTRIBUTES
// (`directory_codec.js`), through a derived `value_keys` key,
// `grantinggroup`. An entry written before that carries no such key until it
// is next written (#636's and #1061's no-migration rule), so the question
// missed an old service account or role naming a group unless this process
// held the entry. rcbj's decision on #1306's open point: a one-time backfill.
//
// **A SCHEDULER JOB, NOT A STEP OF THE START** — the precedent the two
// earlier index catch-ups set, and the one that argues for an index rebuild
// over a large table. The session index's backfill (#350) is a start step
// because a window cannot answer a session walk until it is complete, and it
// is FATAL on a throw; this index is not needed for the service to start,
// and a walk of every directory row at 50M is hours, not seconds. The
// minted index's backfill (#820) was a start step first and ran 8081's front
// process out of heap, which is why it became a cluster job; the data-key
// index's catch-up (#623) runs inside two jobs, a page at a time under a
// budget. So: `persistence.granting-key-backfill`, a CLUSTER job — one node
// runs each slot, under the scheduler's claim, which is the exclusion — every
// two minutes until done, at most BUDGET_MS of work a run, its body in a
// request worker where there is one (#408): the opening and digesting is
// CPU, and it holds nothing the front process alone holds.
//
// **EVERY ROW IS VISITED, IN PRIMARY-KEY ORDER, A PAGE AT A TIME** — no index
// can select "the entries holding a granting attribute": the attribute names
// are indexed only for the names a holder question asks
// (`directory_queries.js`'s ASKED_ATTRIBUTES, an expression index whose
// change is a schema version), and `value_keys` holds keyed digests of
// values, which no question can widen to "any value". So each page is the
// next PAGE rows after the cursor by `(realm, dn_key)` — the primary key,
// constant cost whatever the table holds — and the database hands back the
// sealed attributes only of a row whose clear `attr_names` names one of the
// six; the rest cost a key and a name list. It is one-time, bounded per page
// and per run, and asynchronous; never a request's path
// (`tests/no_full_directory_walk_in_requests.js`).
//
// **ONLY THE INDEX IS WRITTEN.** A candidate's attributes are opened and
// given to the same `directory_codec.indexOf()` every write uses, and where
// its `valueKeys` differ from what the row holds, the row's `value_keys` —
// and on MariaDB its `value` key rows — are replaced, COMPARE-AND-SET on the
// blob read: a writer that changed the entry in between wrote its own keys
// and wins (`indexSealed()`'s rule, #623). The body is never rewritten and
// no change row is logged: no process holds `value_keys`, only the store's
// questions read it.
//
// **THE CURSOR AND THE DONE MARK ARE ROWS OF `sts_minted_index`**, under a
// handle no minted store declares (HANDLE), realm '' and a key no digest
// can be — the table both engines and both tiers have, which already holds
// #820's completion marks, so no schema version moves. ONE MARK PER
// DATABASE, not per realm: the walk is one keyset over the table, a realm
// created after this build is written with its keys already, and in a
// service deployed as cells each database (the global tier's and the
// cell's) is walked and marked by itself. The cursor is written after each
// page whose keys have committed, so an interrupted run — a restart, a lost
// claim, the budget — resumes after the last page it finished; a page done
// twice writes nothing the second time. Two walkers of one database (two
// cells' leaders over the global tier) are safe: each write is
// compare-and-set, and any cursor either writes names a prefix that some
// walk has finished.
//
// **A BLOB THAT WILL NOT OPEN IS SKIPPED, AND THE WALK STILL FINISHES**
// (#695's argument for the session index): it is opened again after the
// data-key rows are read once a run, and a blob that still will not open is
// one no process holding these keys can answer about — the question's
// answer drops it (`openAnswer()`, STS-STORE-0072) — so a mark withheld for
// it would buy a walk of every row on every run for nothing. It is keyed
// when it is next written. STS-STORE-0167 names the first few and the count.
//
// A LIBRARY: the walk, over a driver's statements (`walk()`), and the job,
// registered by `install()` from `common/protocol_stack.ts` beside the other
// libraries that own jobs. It reaches the scheduler, the persistence module
// and the keystore lazily. Its `off()` answers from the mark as every process
// reads it, so the finished job is off in all of them (#1316, below).
// ===========================================================================

const errorCodes = require('../common/error_codes');
const codec = require('./directory_codec');

const log = require('bunyan').createLogger({
  name: 'sts-granting-index-backfill',
  level: process.env.STS_LOG_LEVEL || process.env.LOG_LEVEL || 'info'
});

// The job's id.
const JOB = 'persistence.granting-key-backfill';
// How often it runs until the mark is written: one run's budget in every
// two minutes of a busy store.
const EVERY_MS = 2 * 60 * 1000;
// How long one run may walk. A run that has not finished stops at the next
// page boundary past it; the next run resumes from the cursor.
const BUDGET_MS = 45 * 1000;
// How many rows one page reads. The bound on one statement, one transaction
// and one turn of the event loop.
const PAGE = 500;
// How many skipped entries are named one line each.
const SKIP_LINES = 10;

// The rows of `sts_minted_index` this walk keeps: a handle no minted store
// declares (`realms.handles()` never names it, so no lookup, purge or
// completion probe sees it), realm '' and keys with a `$`, which no keyed
// digest holds.
const HANDLE = 'ldap.grantinggroup';
const MARK_KEY = '$index-complete$';
const CURSOR_KEY = '$cursor$';

// Whether this process has seen the mark in every database it walks, so the
// job says it is off rather than asking again. Set by a run that finds or
// writes the mark, and by a read of the mark (`primeAsync()`); never unset,
// since the mark is never removed.
let completeHere = false;
let installed = false;
// The read of the mark in flight, so `off()` asked again meanwhile starts no
// second one; and when the last one started, so a process that has not seen
// the mark asks the store at most once an interval (#1316).
let priming = null;
let primedAtMs = 0;

/**
 * The cursor row's `key` for a position: realm and DN key, which a realm id
 * cannot contain the separator of.
 *
 * @param realm - the realm of the last row done
 * @param dnKey - its key
 * @returns the column value
 */
function cursorValue(realm, dnKey) {
  log.debug("Entering cursorValue().");
  log.debug("Leaving cursorValue().");
  return String(realm) + '\n' + String(dnKey);
}

/**
 * A cursor row's `key` read back as a position.
 *
 * @param value - the column value
 * @returns `{ realm, dnKey }`, or null for a value that is not one
 */
function cursorOf(value) {
  log.debug("Entering cursorOf().");
  const text = String(value == null ? '' : value);
  const at = text.indexOf('\n');
  if (at < 0) {
    log.debug("Leaving cursorOf(). Not a cursor.");
    return null;
  }
  log.debug("Leaving cursorOf().");
  return { realm: text.slice(0, at), dnKey: text.slice(at + 1) };
}

/**
 * Whether two `value_keys` lists hold the same keys, in any order.
 *
 * @param held - what the row holds (an array, or a JSON text of one)
 * @param wanted - what `indexOf()` gives now
 * @returns true when they agree
 */
function sameKeys(held, wanted) {
  log.debug("Entering sameKeys().");
  let list = held;
  if (typeof list === 'string') {
    try {
      list = JSON.parse(list);
    } catch (e) {
      // Not a list this build wrote: it disagrees, and is written over.
      log.debug("Caught in sameKeys(): " + ((e && e.message) || e));
      list = null;
    }
  }
  if (!Array.isArray(list)) {
    log.debug("Leaving sameKeys(). Not a list.");
    return false;
  }
  const a = Array.from(new Set(list.map(String))).sort();
  const b = Array.from(new Set((wanted || []).map(String))).sort();
  log.debug("Leaving sameKeys().");
  return a.length === b.length && a.every(function (one, i) {
    return one === b[i];
  });
}

/**
 * A candidate's attributes, or null where its blob does not open — a throw
 * from opening included, which would otherwise stop every run at that row.
 *
 * @param ops - the statements
 * @param row - the row as read
 * @returns the attributes, or null
 */
function openedOf(ops, row) {
  log.debug("Entering openedOf().");
  let attrs = null;
  try {
    attrs = ops.open(row);
  } catch (e) {
    log.debug("Caught in openedOf(): " + ((e && e.message) || e));
    attrs = null;
  }
  log.debug("Leaving openedOf().");
  return attrs === undefined ? null : attrs;
}

/**
 * One database's walk, a page at a time, until the end of the table, the
 * budget or the run's ownership — over the driver's statements:
 *
 *   readState()                   `{ done, cursor }`, cursor `{ realm,
 *                                 dnKey }` or null for the start
 *   readPage(cursor, limit)       the next rows by `(realm, dn_key)`:
 *                                 `{ realm, dn_key, attrs, value_keys }`,
 *                                 `attrs` null for a row naming no granting
 *                                 attribute
 *   writeKeys(items)              `[{ realm, dnKey, attrs, valueKeys }]`,
 *                                 compare-and-set on `attrs` as read;
 *                                 answers how many rows were written
 *   saveCursor(realm, dnKey)      after a page's keys have committed
 *   saveDone()                    the mark, and the cursor gone
 *   open(row)                     the row's attributes, or null
 *
 * @param ops - the statements
 * @param options - `{ budgetMs, stillOwner, page, what }`
 * @returns `{ complete, already, stopped, examined, candidates, written,
 *   skipped }`
 */
async function walk(ops, options) {
  log.debug("Entering walk().");
  const o = options || {};
  const budget = Math.max(0, Number(o.budgetMs) || 0);
  const limit = Math.max(1, Number(o.page) || PAGE);
  const what = String(o.what || 'the store');
  const started = Date.now();
  const out = { complete: false, already: false, stopped: false,
                examined: 0, candidates: 0, written: 0, skipped: 0 };
  const state = await ops.readState();
  if (state && state.done) {
    out.complete = true;
    out.already = true;
    log.debug("Leaving walk(). Already complete.");
    return out;
  }
  let cursor = (state && state.cursor) || null;
  let reread = false;
  while (Date.now() - started < budget) {
    if (typeof o.stillOwner === 'function' && !o.stillOwner()) {
      out.stopped = true;
      break;
    }
    const rows = (await ops.readPage(cursor, limit)) || [];
    out.examined += rows.length;
    const candidates = rows.filter(function (row) {
      return row && row.attrs !== null && row.attrs !== undefined;
    });
    out.candidates += candidates.length;
    let opened = candidates.map(function (row) {
      return openedOf(ops, row);
    });
    if (!reread && opened.indexOf(null) >= 0) {
      // A blob under a data key this process has not read yet (a realm made
      // a moment ago elsewhere): the key rows once a run, and again.
      reread = true;
      await require('../common/keystore').refreshDekRows();
      opened = candidates.map(function (row) {
        return openedOf(ops, row);
      });
    }
    const items = [];
    candidates.forEach(function (row, i) {
      if (opened[i] === null) {
        out.skipped += 1;
        if (out.skipped <= SKIP_LINES) {
          log.warn(errorCodes.tag('STS-STORE-0167') + 'persistence: the ' +
                   'grantinggroup key backfill (#1311) skipped the ' +
                   'directory entry "' + row.dn_key + '" in realm "' +
                   row.realm + '" of ' + what + ': it does not open here. ' +
                   'It is keyed when it is next written.');
        }
        return;
      }
      const valueKeys = codec.indexOf(opened[i]).valueKeys;
      if (!sameKeys(row.value_keys, valueKeys)) {
        items.push({ realm: String(row.realm), dnKey: String(row.dn_key),
                     attrs: row.attrs, valueKeys: valueKeys });
      }
    });
    if (items.length) {
      out.written += Number(await ops.writeKeys(items)) || 0;
    }
    if (rows.length < limit) {
      await ops.saveDone();
      out.complete = true;
      break;
    }
    const last = rows[rows.length - 1];
    cursor = { realm: String(last.realm), dnKey: String(last.dn_key) };
    await ops.saveCursor(cursor.realm, cursor.dnKey);
    // The opening above is this process's CPU: a page, then the event loop.
    await new Promise(function (resolve) {
      setImmediate(resolve);
    });
  }
  if (out.skipped) {
    log.warn(errorCodes.tag('STS-STORE-0167') + 'persistence: the ' +
             'grantinggroup key backfill (#1311) skipped ' + out.skipped +
             ' directory entr' + (out.skipped === 1 ? 'y' : 'ies') + ' of ' +
             what + ' this run that do not open here.');
  }
  log.debug("Leaving walk(). " + out.examined + " examined, " +
            out.written + " written.");
  return out;
}

/**
 * Two walks' answers as one: complete only when both are.
 *
 * @param first - one database's answer
 * @param second - the other's
 * @returns the sum
 */
function combined(first, second) {
  log.debug("Entering combined().");
  const a = first || {};
  const b = second || {};
  log.debug("Leaving combined().");
  return {
    complete: !!(a.complete && b.complete),
    already: !!(a.already && b.already),
    stopped: !!(a.stopped || b.stopped),
    examined: (Number(a.examined) || 0) + (Number(b.examined) || 0),
    candidates: (Number(a.candidates) || 0) + (Number(b.candidates) || 0),
    written: (Number(a.written) || 0) + (Number(b.written) || 0),
    skipped: (Number(a.skipped) || 0) + (Number(b.skipped) || 0)
  };
}

/**
 * The store this process walks, when it can be walked here: the active
 * driver with an `indexGrantingKeys()`.
 *
 * @returns the driver, or null
 */
function walkableDriver() {
  log.debug("Entering walkableDriver().");
  let driver = null;
  try {
    driver = require('./persistence').currentDriver();
  } catch (e) {
    // A process that has not assembled its store: there is nothing to walk.
    log.debug("Caught in walkableDriver(): " + ((e && e.message) || e));
    driver = null;
  }
  log.debug("Leaving walkableDriver().");
  return driver && typeof driver.indexGrantingKeys === 'function'
    ? driver : null;
}

// ---------------------------------------------------------------------------
// THE JOB IS OFF IN EVERY PROCESS ONCE THE MARK IS WRITTEN (#1316).
//
// The run that writes the mark is usually a request worker's (#408), and a
// run's result reaches no other process's module state, so until #1316 only
// that worker knew: the front went on scheduling the job every two minutes
// for good — each run one read of the mark — and `/admin/scheduler` (another
// worker) showed it on until a restart. So `off()` answers from the MARK, as
// every process reads it, cached once true; a mark is never removed, so a
// true answer is never asked again.
//
// `off()` is synchronous and the mark is a row in the store, so the answer
// is PRIMED: a read started without waiting for it (`primeAsync()`), whose
// answer a later `off()` sees. Until it has answered the job is on, as it
// was before #1316 — the worst that costs is the one more run that reads
// the mark. It is primed at `install()` (in a process whose store is open
// by then; at the start of the stack none is, and that read is skipped) and
// from `off()` itself, at most once an interval while the mark is unseen:
// the scheduler's tick asks `off()` of every job, so that is when a process
// that never runs the body learns the walk finished, at the latest one
// interval after it did. No timer of its own (root `CLAUDE.md`, *Anything
// periodic is a scheduler job*): a read is started only by a question the
// scheduler asks. The process that ran the body knows from the run's
// answer and reads nothing.
//
// In a service deployed as cells the store's answer is both tiers' marks
// (`persistence_tiered.js`'s `grantingKeysComplete()`), so "finished" means
// the global tier and this cell's database are both keyed.
// ---------------------------------------------------------------------------
/**
 * Reads the done mark from the store, once at a time, and remembers a true
 * answer. Never throws and never rejects: a store that cannot be asked
 * leaves the job on.
 *
 * @returns whether this process now knows the walk is complete
 */
function primeAsync() {
  log.debug("Entering primeAsync().");
  if (completeHere) {
    log.debug("Leaving primeAsync(). Known.");
    return Promise.resolve(true);
  }
  if (priming) {
    log.debug("Leaving primeAsync(). In flight.");
    return priming;
  }
  const driver = walkableDriver();
  if (!driver || typeof driver.grantingKeysComplete !== 'function') {
    log.debug("Leaving primeAsync(). Nothing to ask.");
    return Promise.resolve(false);
  }
  primedAtMs = Date.now();
  let asked;
  try {
    asked = Promise.resolve(driver.grantingKeysComplete());
  } catch (e) {
    // A driver that throws rather than rejects: the same answer as below.
    log.debug("Caught in primeAsync(): " + ((e && e.message) || e));
    asked = Promise.reject(e);
  }
  priming = asked.then(function (done) {
    if (done === true) {
      completeHere = true;
    }
    priming = null;
    return completeHere;
  }, function (e) {
    // No code: nothing failed that anyone has to act on. The job stays on,
    // the next interval asks again, and a store that is really down fails
    // the job's own run, which is STS-STORE-0166.
    log.debug("Caught in primeAsync(): " + ((e && e.message) || e));
    priming = null;
    return false;
  });
  log.debug("Leaving primeAsync(). Asked.");
  return priming;
}

/**
 * Why the job is off here, or ''. Starts a read of the mark, without
 * waiting for it, when this process has not seen it and has not asked in
 * the last interval.
 *
 * @returns the reason
 */
function offReason() {
  log.debug("Entering offReason().");
  if (completeHere) {
    log.debug("Leaving offReason(). Complete.");
    return 'finished: every directory entry has its grantinggroup keys';
  }
  if (!walkableDriver()) {
    log.debug("Leaving offReason(). No database.");
    return 'the directory is not kept in a database here';
  }
  if (!priming && Date.now() - primedAtMs >= EVERY_MS) {
    primeAsync();
  }
  log.debug("Leaving offReason(). On.");
  return '';
}

/**
 * One run of the job.
 *
 * @param ctx - the scheduler's run context (`stillOwner()` is asked before
 *   each page)
 * @returns the run's result and summary
 */
async function runOnce(ctx) {
  log.debug("Entering runOnce().");
  const driver = walkableDriver();
  if (!driver) {
    log.debug("Leaving runOnce(). No database.");
    return { summary: 'the directory is not kept in a database here' };
  }
  try {
    const done = await driver.indexGrantingKeys({
      budgetMs: BUDGET_MS,
      stillOwner: ctx && typeof ctx.stillOwner === 'function'
        ? function () {
          return ctx.stillOwner();
        } : undefined
    });
    if (done.complete) {
      completeHere = true;
    }
    if (done.written || (done.complete && !done.already)) {
      log.info('persistence: the grantinggroup key backfill (#1311) ' +
               'examined ' + done.examined + ' directory entr' +
               (done.examined === 1 ? 'y' : 'ies') + ' and gave ' +
               done.written + ' of them their keys' +
               (done.complete ? '; it is complete.'
                 : '; the next run resumes after the last page.'));
    }
    log.debug("Leaving runOnce().");
    return Object.assign({}, done, {
      summary: done.already ? 'already complete'
        : (done.complete ? 'complete' : 'continues next run') + ': ' +
          done.examined + ' examined, ' + done.written + ' keyed' +
          (done.skipped ? ', ' + done.skipped + ' skipped' : '')
    });
  } catch (e) {
    log.debug("Caught in runOnce(): " + ((e && e.message) || e));
    log.warn(errorCodes.tag('STS-STORE-0166') + 'persistence: the ' +
             'grantinggroup key backfill (#1311) stopped: ' +
             ((e && e.message) || e) + '. What it finished is kept, and ' +
             'the next run resumes after the last page it wrote.');
    log.debug("Leaving runOnce(). Failed.");
    return { failed: true, summary: 'stopped: ' + ((e && e.message) || e) };
  }
}

/**
 * Registers the job, once per process. Called by `common/protocol_stack.ts`
 * in every process, so every process lists it.
 *
 * @param schedulerInstance - the scheduler, for the tests
 * @returns true when registered here, false when it already was
 */
function install(schedulerInstance) {
  log.debug("Entering install().");
  const scheduler = schedulerInstance || require('../cluster/scheduler');
  if (installed && !schedulerInstance) {
    log.debug("Leaving install(). Installed.");
    return false;
  }
  if (scheduler.job(JOB)) {
    installed = true;
    log.debug("Leaving install(). Registered elsewhere.");
    return false;
  }
  scheduler.register({
    id: JOB,
    title: 'Granting-group index backfill',
    describe: 'Gives every directory entry written before #1306 the ' +
              'grantinggroup index keys of its granting attributes, a page ' +
              'of the store at a time, so federated provisioning\'s store ' +
              'question finds a group such an entry names; marks the store ' +
              'complete once, and is off from then on (#1311).',
    owner: 'persistence/granting_index_backfill.js',
    kind: 'cluster', scope: 'service',
    everyMs: function () {
      return EVERY_MS;
    },
    off: function () {
      return offReason();
    },
    manual: true,
    run: function (ctx) {
      return runOnce(ctx);
    }
  });
  // Set after the registration, never before (`cluster/CLAUDE.md`).
  installed = true;
  // A process whose store is already open learns the mark now (#1316).
  primeAsync();
  log.debug("Leaving install().");
  return true;
}

/**
 * Forgets what this process learned, for the tests.
 */
function reset() {
  log.debug("Entering reset().");
  completeHere = false;
  installed = false;
  priming = null;
  primedAtMs = 0;
  log.debug("Leaving reset().");
}

module.exports = {
  JOB: JOB,
  HANDLE: HANDLE,
  MARK_KEY: MARK_KEY,
  CURSOR_KEY: CURSOR_KEY,
  PAGE: PAGE,
  BUDGET_MS: BUDGET_MS,
  cursorValue: cursorValue,
  cursorOf: cursorOf,
  sameKeys: sameKeys,
  walk: walk,
  combined: combined,
  offReason: offReason,
  primeAsync: primeAsync,
  runOnce: runOnce,
  install: install,
  reset: reset
};
