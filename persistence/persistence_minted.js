// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: persistence/persistence_minted.js
//
// ---------------------------------------------------------------------------
// WHAT THIS PROCESS MINTED, WRITTEN DOWN — IN PRODUCT MODE, AND NOWHERE ELSE.
//
// Every document in this repository said, in one wording or another, that
// **nothing this service MINTS ever persists**: sessions, access tokens, ID
// Tokens, refresh tokens, authorization codes, pre-authorized codes, SAML
// artifacts, Kerberos tickets, the replay caches, the statistics and the audit
// log were all in memory and all gone on restart. `persistence.js`'s own header
// said it, and `persistence/CLAUDE.md` called it deliberate rather than
// unfinished.
//
// **IT WAS DELIBERATE, AND IT RESTED ON EXACTLY ONE FACT: THE SIGNING KEY WAS
// REGENERATED ON EVERY START.** A token restored from a disk would verify
// against nothing, an assertion would be a document nobody can check, and a
// statistics file that outlived the key that signed the tokens it described
// would be worse than none at all.
//
// That fact stopped being true on 2026-09-06, in product mode only.
// `common/keystore.js` generates a realm's signing keys ONCE and reads them
// back from the store, encrypted under a key-encryption key `common/secrets.js`
// gets from a mounted file or one of four cloud secret stores — which is why
// product mode REQUIRES a store. A token restored beside the key that signed it
// verifies.
//
// So the non-goal is not deleted. It is QUALIFIED, and the two halves have to
// be said together or the sentence is worse than either half:
//
//   * **DEVELOPMENT MODE persists nothing it minted**, because the signing key
//     is still regenerated on every start there. Unchanged, and it is the
//     default.
//   * **PRODUCT MODE persists all of it**, because the key is not.
//
// And `persistence.mode=memory` reaches none of this in either mode, which is
// what keeps every job in the parent project's suite, every `npm test` and
// every run that has never heard of any of this behaving exactly as it did.
//
// ---------------------------------------------------------------------------
// PERSISTENCE, AND — SINCE THE SAME DAY — COORDINATION TOO.
//
// This block was headed *THIS IS STILL PERSISTENCE AND IS STILL NOT
// COORDINATION*: each process held its own copy in memory and neither saw the
// other's until it restarted, and the driver's `pg_notify` had no listener.
// `persistence_replication.js` closed that seam (2026-09-06): every minted
// write is also a row in the change log, and the appliers `persistence.js`
// hands it put another process's rows into this one's stores — which is what
// request workers and, since #46, other containers rely on. What this file
// still owns is the WRITING DOWN; convergence is that module's, and
// `persistence/CLAUDE.md` (*The seam is closed*) argues it.
//
// ---------------------------------------------------------------------------
// A JOURNAL, AND NOT THE DIFF NEXT DOOR. THE TWO ARGUMENTS ARE OPPOSITE AND
// BOTH ARE RIGHT.
//
// `persistence.js` compares the WHOLE directory against a shadow on every
// flush. It does that because `touchDirectory()` was already the one choke
// point every directory writer passes through and it does not say which entry
// moved — so the diff buys precision that fifteen call sites would otherwise
// have to be trusted to provide, and it costs a `JSON.stringify` per entry per
// flush over a store that changes when somebody types.
//
// Neither half of that reaches here.
//
//   * **THE CHOKE POINTS ALREADY NAME THE KEY.** These stores are declared
//     with `realms.map()`, `realms.arr()` and `realms.obj()`, and every
//     mutation any of them has ever had goes through `set`, `delete`, `clear`
//     or one of the array mutators. Naming the store at its DECLARATION
//     therefore names every write to it, with the key, for free. See the long
//     comment above `setPersistObserver()` in `common/realms.js`.
//   * **THE ROWS ARE HOT.** In postgres mode the flush delay is 0 — a
//     transaction per request, deliberately — so a full sweep would stringify
//     the audit ring (5,000 rows per realm) and the token register on EVERY
//     REQUEST that touched either. The directory's diff is affordable because
//     the directory is cold. These are not.
//
// So a store reports `{handle, realm, key}` as it is written, and a flush
// writes exactly those keys and nothing else.
//
// ---------------------------------------------------------------------------
// SEALED AT REST, UNDER THE KEY THAT WAS ALREADY THERE.
//
// A session id is a cookie value. An authorization code and a pre-authorized
// code are redeemable. A SAML artifact handle is dereferenceable. A Kerberos
// principal's long-term key IS the password. A store holding those in the
// clear is a store whose backup is a set of live credentials — which for a
// service whose entire subject is credentials is the wrong default to ship.
//
// Every row's body is therefore `keystore.seal()` — AES-256-GCM under the same
// key-encryption key that already seals `sts_keys`, held in one binding in one
// module, and never in the store it protects. That makes this ONE precedent
// rather than a second one, which is the whole reason it was not given a
// scheme of its own.
//
// **WHAT IT COSTS IS THAT THE ROWS ARE OPAQUE TO SQL.** Nobody can `SELECT` a
// session by username, and `psql` shows base64. That is the point rather than
// a regret: what wants querying is the DIRECTORY, which is not sealed and is
// JSONB, and what is here is this process's own working state.
//
// ---------------------------------------------------------------------------
// WHAT IS NOT PERSISTED, AND THE WORD THAT DECIDES IT.
//
// A CACHE is not minted state. `oauth2.js`'s `signedMetadataCache` and
// `xacml_store.js`'s `parsed` hold a copy of something re-derivable, keyed by
// the thing it was derived from; restoring one saves a computation and risks
// serving a stale document, which is a bad trade in both directions. They are
// left undeclared, each with a line at its declaration saying so, because "it
// has no handle" and "somebody forgot" look identical from here.
//
// ---------------------------------------------------------------------------
// A LIBRARY, AND ONE THAT IS HANDED ITS DRIVER (rule 3).
//
// It registers no route, so its place in the route order is not a place. And
// it does not require `persistence.js` — that module hands it the driver it
// chose, the same way it hands `keystore.setStore()` one. That is what lets
// `tests/minted_persistence.js` hand it a stub and assert the whole of this
// file in process, with no port, no container and no database, which is
// `tests/CLAUDE.md`'s rule for what may live there.
// ---------------------------------------------------------------------------

const bunyan = require('bunyan');
const config = require('../common/config');
const mode = require('../common/mode');
const keystore = require('../common/keystore');
const realms = require('../common/realms');
// WHICH TIER A STORE IS IN (#98): the cell tier is sealed under the cell's
// own key. A LEAF with no requires of this service.
const tiers = require('./tiers');
// THE FAN-IN FOR `merge: 'own'` STORES. A LIBRARY, like this one, and required
// in the ordinary direction: it does not require this file back.
const replication = require('./persistence_replication');
// A LEAF: where a flush's time goes (#820), beside the requests'.
const requestPhases = require('../common/request_phases');
// A LEAF with no requires: the failure codes on the log lines and the fatal
// refusals below. NOT audit.js, which requires persistence_replication.js.
const errorCodes = require('../common/error_codes');
const cacheRegistry = require('../common/cache_registry');
// The table of what active-active mode depends on (#46). A LEAF: bunyan and
// config. `sessions.no-resurrection` is provided below, at require time.
const capabilities = require('../cluster/cluster_capabilities');

const log = bunyan.createLogger({ name: 'sts-persistence-minted' });

// The driver `persistence.js` chose, or null before it has chosen one and in
// every mode that persists nothing.
let driver = null;

// WHO THIS PROCESS IS, from the driver. It is part of the stored key for every
// `merge: 'own'` store — see `storedKey()` — so that two processes appending to
// one audit ring write two rows rather than overwriting each other's.
let origin = '';

// ---------------------------------------------------------------------------
// THE KEY A ROW IS STORED UNDER, WHICH IS NOT ALWAYS THE KEY THE STORE USES.
//
// For a `replace` store they are the same, and the row is the value: whoever
// wrote last owns it.
//
// For an `own` store the origin is appended, because the row is THIS PROCESS'S
// CONTRIBUTION rather than the value. `nums.callTotal` in two processes is two
// tallies of two different things, and one row would make them alternate
// between each other's numbers while looking perfectly plausible.
//
// **THE SEPARATOR IS A NUL AND THAT IS DELIBERATE.** A key here can be a
// session id, an HTTP path, a jti or a DN, and every printable separator is
// something one of those can legitimately contain. A NUL is the one byte none
// of them can, so the split back apart cannot be ambiguous.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// AN `own` STORE'S KEY CARRIES THE ORIGIN, AND THE SEPARATOR WAS A NUL BYTE
// UNTIL 2026-09-07.
//
// The reasoning for a NUL was sound as far as it went — no key can contain one,
// which is the property a separator needs — and it optimised for the wrong
// half: **PostgreSQL's `text` cannot STORE a NUL either.** Every row from an
// `own`-merge store was refused by the database with `invalid byte sequence for
// encoding "UTF8": 0x00`, counted as unwritable, and logged at error with "the
// service is unaffected" beside it. One dispatched run produced 321 of them.
//
// So minted persistence has NEVER worked for those stores on the only driver
// that holds minted state — `xacml_monitor.counters` and the audit ring among
// them — in product mode as much as anywhere else. It went unseen because
// nothing asserted that a row written by an `own` store came back, and because
// the failure is caught and counted rather than raised.
//
// Base64url both halves and join with '.', which is not in that alphabet: the
// result is unambiguous, reversible and text-safe. **NOTHING IS MIGRATED
// BECAUSE NOTHING WAS EVER STORED** — every write in the old shape failed, so
// there is no row anywhere in the old format to read back.
// ---------------------------------------------------------------------------
// The stores already told that a NUL key is kept in memory only.
const nulKeyWarned = new Set();

function storedKey(row, key, whose) {
  log.debug("Entering storedKey().");
  if (row.merge !== 'own') {
    log.debug("Leaving storedKey().");
    return key;
  }
  log.debug("Leaving storedKey().");
  return Buffer.from(String(key), 'utf8').toString('base64url') + '.' +
         Buffer.from(String(whose === undefined ? origin : whose), 'utf8')
           .toString('base64url');
}

// ---------------------------------------------------------------------------
// A PER-ORIGIN ROW ON DEMAND (#1001, 2026-10-27).
//
// `admin_stats.users` is the first store that is both `merge: 'own'` and
// `onDemand`. Its rows are filed under `<key>.<origin>` (`storedKey()`), so
// three things the on-demand reader did for a one-row-per-key store are
// wrong for it: a read of a bare key misses this process's own row (the
// stored name carries the origin — `onDemandRead()` applies `storedKey()`,
// as `onDemandReadMany()` always did); an index answers EVERY origin's row
// for the person, and the facade must know which is this process's (its
// cache) and which is another's (read, folded, never cached — a foreign
// row cached under the bare key would be written back under THIS origin at
// the next flush); and another process's change to such a row is not held
// here at all (`applyChange()`, `prefetch()`), because the fan-in grew with
// every sign-in anywhere once #999 rewrote the row per sign-in, and the
// index is where a reader finds it.
// ---------------------------------------------------------------------------
/**
 * Whether a stored name of a `merge: 'own'` store names another process's
 * row.
 *
 * @param declared - the store
 * @param split - `splitKey()`'s answer for the stored name
 * @returns true for another origin's row
 */
function foreignRow(declared, split) {
  log.debug("Entering foreignRow().");
  const foreign = !!declared && declared.merge === 'own' &&
    !!split.origin && split.origin !== origin;
  log.debug("Leaving foreignRow().");
  return foreign;
}

// ---------------------------------------------------------------------------
// A ROW'S OWN EXPIRY (2026-09-28, #333), from the store's `expiresAt` hook
// (see `expiresAt` in common/realms.js). Anything but a finite positive number
// is "does not expire" — the safe failure, since a row wrongly kept is read
// once more at a start and a row wrongly expired is lost on every node. A
// hook that throws is said once per store, for the no-per-event-logs rule.
// ---------------------------------------------------------------------------
const expiryHookFailed = new Set();

// THE HOOK RUNS IN THE ROW'S REALM, not the flush's: a flush scheduled from a
// request runs in that request's realm and writes every realm's journal, and
// a hook that reads a lifetime setting must read the one the row's realm has.
function expiryOf(row, value, key, realmId) {
  log.debug("Entering expiryOf().");
  if (!row || typeof row.expiresAt !== 'function') {
    log.debug("Leaving expiryOf(). No hook.");
    return null;
  }
  let at = null;
  try {
    const id = String(realmId || '');
    const realm = id && id !== realms.DEFAULT_ID ? realms.get(id) : null;
    at = realms.run(realm, function () {
      return row.expiresAt(value, key);
    });
  } catch (e) {
    log.debug("Caught in expiryOf(): " + ((e && e.message) || e));
    if (!expiryHookFailed.has(row.handle)) {
      expiryHookFailed.add(row.handle);
      log.warn(errorCodes.tag('STS-STORE-0064') + 'persistence: "' +
               row.handle + '" could not say when a row expires (' +
               ((e && e.message) || e) + '); such rows are written as not ' +
               'expiring. Said once per store.');
    }
    at = null;
  }
  const ms = Number(at);
  log.debug("Leaving expiryOf().");
  return at !== null && at !== undefined && Number.isFinite(ms) && ms > 0
    ? Math.floor(ms) : null;
}

// The side-table columns for one plaintext row (#350). Null when the store
// has no `indexOf`, or when that hook declines (no digest key). Shared by
// the flush, the merge, apply and the backfill: a second copy of "call the
// hook, keep an object" would drift. A hook that throws writes no index row
// rather than failing the flush.
function indexColumns(row, value) {
  log.debug("Entering indexColumns().");
  if (!row || typeof row.indexOf !== 'function') {
    log.debug("Leaving indexColumns(). No hook.");
    return null;
  }
  try {
    const columns = row.indexOf(value);
    if (!columns || typeof columns !== 'object') {
      log.debug("Leaving indexColumns(). No columns.");
      return null;
    }
    log.debug("Leaving indexColumns().");
    return columns;
  } catch (e) {
    log.debug("Caught in indexColumns(): " + ((e && e.message) || e));
    log.debug("Leaving indexColumns().");
    return null;
  }
}

// The journal: handle -> realm -> Set of keys. Nested rather than a flat set of
// composite strings because the flush walks it handle-first (a handle is what
// finds the store) and because a composite key would have to be split back
// apart with a separator no key may contain — and a session id may contain
// anything.
const journal = new Map();

// A copy of the journal, emptied (#357): what `restore()` keeps aside.
function takePendingJournal() {
  log.debug("Entering takePendingJournal().");
  const copy = new Map();
  journal.forEach(function (byRealm, handle) {
    const realmsCopy = new Map();
    byRealm.forEach(function (keys, realmId) {
      realmsCopy.set(realmId, new Set(keys));
    });
    copy.set(handle, realmsCopy);
  });
  journal.clear();
  log.debug("Leaving takePendingJournal(). " + copy.size + " handle(s).");
  return copy;
}

// Puts what `takePendingJournal()` kept back into the journal; true when there
// was anything to put back.
function putBackJournal(pending) {
  log.debug("Entering putBackJournal().");
  let any = false;
  (pending || new Map()).forEach(function (byRealm, handle) {
    byRealm.forEach(function (keys, realmId) {
      keys.forEach(function (key) {
        let held = journal.get(handle);
        if (!held) {
          held = new Map();
          journal.set(handle, held);
        }
        let set = held.get(realmId);
        if (!set) {
          set = new Set();
          held.set(realmId, set);
        }
        set.add(key);
        any = true;
      });
    });
  });
  if (any) {
    generation += 1;
  }
  log.debug("Leaving putBackJournal(). " + any);
  return any;
}

// ---------------------------------------------------------------------------
// A REALM THAT IS GONE LEAVES NOTHING PENDING (2026-09-07).
//
// The journal is `handle -> realm -> keys` and it is what the next flush walks.
// A realm removed with writes still in it left its keys in here, and the flush
// that followed looked each one up in a store `realms.map()` had already
// dropped — work that reaches a row nobody can name, for a realm the driver is
// deleting from the store in the same breath.
//
// **IT IS NOT A CORRECTNESS FIX AND IS NOT WRITTEN AS ONE.** A lookup that
// misses becomes a delete of a row that is already going, so the old behaviour
// was wasteful rather than wrong. It is here because the alternative is a
// reader having to prove that, which is a harder thing to establish than to
// prevent — and because the flush is the one place a removed realm could still
// have written something after the delete.
// ---------------------------------------------------------------------------
realms.onRemove(function (id) {
  const realmId = String(id || '');
  let dropped = 0;
  journal.forEach(function (byRealm) {
    const keys = byRealm.get(realmId);
    if (keys) {
      dropped += keys.size;
      byRealm.delete(realmId);
    }
  });
  if (dropped) {
    log.info('persistence: the "' + realmId + '" realm was removed with ' +
             dropped + ' minted row(s) still pending; they were dropped ' +
             'rather than flushed to a realm that no longer exists.');
  }
});

// True while restore() is writing what it just read. Every note() is a no-op
// then, for `persistence.js`'s `restoring` reason: without it the first act of
// a restored process would be to write back exactly what it read.
let restoring = false;

// True once stop() has run, so a late flush cannot reach a closed pool.
let stopped = false;

// The flush whose write has not settled yet, or null. See flush()'s header:
// ONE AT A TIME PER PROCESS, which is what makes commit order the same as the
// order the values were read in.
let flushInFlight = null;
// ---------------------------------------------------------------------------
// WRITE GENERATIONS, for the cluster barrier's commit hold (2026-09-14, #46).
//
// `generation` goes up on every key journalled; `takenAt` is the generation a
// flush's journal take covered; `committedAt` is the highest `takenAt` whose
// write has settled. So "everything journalled up to generation G has reached
// the store" is `committedAt >= G`, which is what lets a response be held for
// ITS writes rather than for whatever flush happens to be pending in the
// process — see cluster/cluster_barrier.js for what that was costing.
// ---------------------------------------------------------------------------
let generation = 0;
let committedAt = 0;
// True from a failed write until the next one succeeds (#351): the keys it
// held are back on the journal and not in the store. `failing()` answers it
// for `persistence.commitBacklog()`.
let failedWrite = false;
let inFlightTakenAt = 0;
// ---------------------------------------------------------------------------
// HOW MANY OF THOSE KEYS WERE AN OBSERVATION (2026-09-15, #46): a store
// declared `observation: true` (common/realms.js) — a decision counter. The
// barrier subtracts this from `generation` when it asks whether a request
// WROTE, so a read whose only row is a tally is answered at once (rcbj's
// decision 6) while a request that wrote something else is held and its tally
// commits with it. `observational` caches the declaration per handle, because
// `note()` is on the path of every store write in the service.
//
// **WHY IT EXISTS: `xacml_monitor.js` INCREMENTED ITS ROW IN PLACE AND NEVER
// JOURNALLED IT.** Only the first decision per process created the row through
// `set()`; every later one changed the object and told nobody, so the row in
// `sts_minted` stayed at whatever that first write held. One node's page adds
// its own live tally to the OTHER node's stale row, so two nodes reported
// different totals for one service — the suite's `cluster` mode read 126 on
// node A and 142 on node B across one page load (and 21 then 17 in a run of
// that job alone). Journalling each decision fixes the row; without this count
// it would also have made every console, portal and `/admin-api` read a
// WRITING request, because the access PEP decides on each of them.
// ---------------------------------------------------------------------------
let observedGeneration = 0;
const observational = new Map();

// Described to `/admin/caches` (rule 3ap, 2026-09-18) — it was one of the
// single-value memos that page listed as held and not reported. One flag per
// store handle, and the handles are the persisted stores this build DECLARES
// (`realms.handles()`), so it cannot grow at runtime. A hit is a write whose
// store's declaration was already read.
const observationalCount = cacheRegistry.register({
  name: 'persistence.observational-stores',
  title: 'Observation-store declarations',
  description: 'Whether each persisted store was declared an observation ' +
    '(a tally the read barrier does not wait for), read once per store ' +
    'handle because the check is on the path of every store write.',
  owner: 'persistence/persistence_minted.js',
  scope: 'process',
  maxEntries: function () {
    return Math.max(1, realms.handles().length);
  },
  bound: 'Structural: one flag per persisted store this build declares.',
  lifetime: function () {
    return 'For the life of the process: a declaration cannot change ' +
      'while it runs.';
  },
  entries: function () {
    const out = [];
    observational.forEach(function (flag, handle) {
      out.push({ key: String(handle) + (flag ? ' — an observation' : ''),
                 validUntil: null, basis: 'no expiry' });
    });
    return out;
  }
});
// ---------------------------------------------------------------------------
// A MINTED WRITE ASKS FOR A FLUSH (2026-09-14, #46 follow-up). THE JOURNAL
// RECORDED THE KEY AND NOTHING EVER ASKED FOR IT TO BE WRITTEN.
//
// `persistence.js` has had a `mintedChanged()` door since minted persistence
// was written — "the one door that marks nothing and only schedules" — and
// nothing called it. A minted row therefore reached the store only when
// something ELSE flushed: a directory, realm or settings change in the same
// process, or one of the three explicit `flushMinted()` callers (the cluster
// barrier's commit-before-respond, a request worker's commit announcement, a
// credential spend). A sign-in usually touches the directory, so sessions
// were written; a SIGN-OUT touches nothing else, so its delete — the
// TOMBSTONE that keeps an ended session ended — sat in the journal until an
// unrelated write came along.
//
// **MEASURED, and it was the unexplained half of the section-3 session
// probe:** two product nodes with `cluster.mode=off`, a session revoked on
// node A — 8 of 8 rows still live in `sts_minted` six seconds later, with NO
// other node touching the session at all (4 of 4), and a single node alone
// the same. Active-active read 0 of 8 only because its barrier flushes every
// writing response. The row outlived the sign-out in the store, so a second
// node or a restart restored it: resurrection without any race.
//
// So the first key journalled after a flush asks `persistence.js` to schedule
// one — `schedule()`'s delay is 0 on postgres, a transaction per burst, which
// is what that file's header always said happened. Once per flush, not once
// per write: `flushAsked` is cleared where the journal is taken. A key put
// BACK after a failed write does not ask (`requeuing`), or a database outage
// would be a loop of zero-delay retries; it is retried by the next write, as
// the failure's log line says.
// ---------------------------------------------------------------------------
let scheduler = null;
let flushAsked = false;
let requeuing = false;

// What /admin/persistence and GET /admin-api/persistence report.
let lastWriteAt = null;
let lastError = '';
let writes = 0;
let failures = 0;
let rowsWritten = 0;
let rowsDeleted = 0;
let restoredAt = null;
let restoredRows = 0;
let droppedUnreadable = 0;
let droppedUnknown = 0;
let unsupportedReason = '';
// Whether flush() has said, once, that a product-mode realm's minted state is
// being dropped by a development process with no key. See flush().
let realmOnlyKeylessWarned = false;

// ---------------------------------------------------------------------------
// THE SETTINGS. Read per call like the rest of this service.
// ---------------------------------------------------------------------------

// Is this process writing minted state down at all? THREE things have to be
// true and each is a different kind of answer, which is why this is not one
// flag:
//
//   * the OPERATOR asked for it (`persistence.minted`);
//   * the MODE makes it meaningful (product, because only there does the
//     signing key survive the restart the rows are for);
//   * and a DRIVER that can hold it is open — which today means postgres, for
//     the reason `supports()` gives.
//
// A KEK is required too and is checked at the point of sealing rather than
// here, because it arrives later than everything above: `keystore.start()` runs
// after `persistence.start()`.
/**
 * Tells whether this process writes minted state down at all.
 *
 * True when `persistence.minted` is set, a driver that can hold minted rows
 * is open, and either the mode is product or several processes or nodes must
 * agree and hold a key to seal the rows with.
 * @returns true when minted state is being persisted
 */
function enabled() {
  log.debug("Entering enabled().");
  if (stopped || !driver) {
    log.debug("Leaving enabled().");
    return false;
  }
  if (!config.value('persistence.minted')) {
    log.debug("Leaving enabled().");
    return false;
  }
  log.debug("Leaving enabled().");
  // PRODUCT MODE, OR A DEVELOPMENT RUN WHOSE PROCESSES MUST AGREE (2026-09-07).
  //
  // The product half is unchanged and is what this file was written for. The
  // second half is the request worker pool: several processes answering one
  // port must share what they mint, or a token issued by one is unknown to the
  // next — measured as ~20 failing jobs in a dispatched run. There is no store
  // for it in development because there is no KEK, so the pool generates an
  // EPHEMERAL one and hands it to every worker; `hasEphemeralKek()` is true
  // exactly when that has happened. See keystore.js's block above sealed().
  //
  // It stays false for an ordinary single-process development service, which
  // is every run that does not configure a pool — so "development persists
  // nothing it minted" is unchanged for everybody who has not asked for
  // workers, and unchanged ACROSS RESTARTS for those who have.
  //
  // **AND A THIRD ARM SINCE 2026-09-12, BECAUSE THE SECOND ONE TESTS FOR THE
  // WRONG THING AND WENT SILENTLY FALSE.** `hasEphemeralKek()` is a proxy for
  // *the processes in this run share a key and must therefore agree*, and it
  // was exact while the only way to get a KEK in development was for the pool
  // to generate one. `keys.source=persisted` is the other way — it turns the
  // keystore on WITHOUT product mode, which is what `tests/keystore.js`
  // records as the reason that setting exists — and `useEphemeralKek()`
  // correctly REFUSES to substitute a per-run key when a real one has been
  // read. So a dispatched run that reads its KEK from a secret store had a
  // REAL key, no ephemeral one, and every arm of this condition false: each
  // worker went back to keeping its own minted state.
  //
  // **Nothing failed loudly, which is why this comment is long.** What it
  // measured was `sts_jwt_bearer_grant` accepting a REPLAYED RFC 7523
  // assertion — `assertion_grant.seen` is a declared persistable store, the
  // second POST landed on a worker that had never seen the jti, and a
  // credential meant to be spendable once was spent twice. Sessions, codes and
  // tokens diverge the same way; the replay is simply the one that noticed.
  //
  // **THE ARM ASKS THE QUESTION THE SECOND ONE WAS ASKING BADLY, AND NOT A
  // WIDER ONE.** Not `keystore.persists()`: that is true of a single-process
  // development service with `keys.source=persisted` too, and turning minted
  // persistence on there would reverse "development persists nothing it
  // minted" for a deployment that never asked for a pool and never had a
  // second process to disagree with. What matters is SEVERAL PROCESSES
  // ANSWERING ONE PORT, which is two config values and is read the same way in
  // the front process and in every worker. `sealed()` is the other half: there
  // has to be a key to seal the rows with, whoever supplied it.
  //
  // **AND A FOURTH ARM SINCE 2026-09-14 (#46): SEVERAL NODES, NOT ONLY SEVERAL
  // PROCESSES.** The third arm's question is "does more than one process
  // answer one address", and it read that question off `workers.*` — so two
  // single-process development containers in active-active mode, behind one
  // load balancer, each kept their own sessions, pending sign-ins and codes.
  // The suite's `cluster` mode measured it: a console sign-in with every hop
  // on node A worked, every hop on B worked, and alternating hops failed
  // `STS-AUTHN-0003` because the pending sign-in was minted on the other node
  // — 42 of 58 protocol jobs. The capability gate passed, because every
  // capability was provided; what was missing was that the state they spend
  // was not shared at all. A clustered node IS several processes answering one
  // address, and `sealed()` is guaranteed there: cluster.js refuses
  // active-active without persisted keys. Active-passive counts too — a
  // takeover that restored no sessions would sign everybody out.
  return mode.isProduct() || keystore.hasEphemeralKek() ||
         ((severalProcesses() || severalNodes()) && keystore.sealed());
}

// Is this process a node of a cluster? Asked of `cluster/cluster.js` LAZILY:
// that module is a leaf this file would not otherwise need at load, and the
// answer is read per call like every arm above.
function severalNodes() {
  log.debug("Entering severalNodes().");
  const cluster = require('../cluster/cluster');
  log.debug("Leaving severalNodes().");
  return cluster.mode() !== 'off';
}

// Is this process one of several answering one port? Dispatch needs BOTH a
// worker count and a path to dispatch — `workers.dispatch` empty means nothing
// is dispatched however many workers were forked — and dispatch without
// coordination is refused at startup, so this being true means the store is
// shared as well.
// The PROCESS's mode, whichever realm is ambient: the default realm's answer,
// which is what the environment and the appconfig file said. A realm override
// of `global.mode` changes that realm's behaviour and not what this process
// was started as.
function processIsProduct() {
  log.debug("Entering processIsProduct().");
  log.debug("Leaving processIsProduct().");
  return realms.run(null, function () {
    return mode.isProduct();
  });
}

function severalProcesses() {
  log.debug("Entering severalProcesses().");
  // The #364 rule: the default of one worker is none without a store that
  // coordinates.
  const count = require('../common/process_memory').requestWorkers();
  const paths = String(config.value('workers.dispatch') || '').trim();
  log.debug("Leaving severalProcesses().");
  return count > 0 && paths !== '';
}

// Rows older than this are neither restored nor kept. Without it a store that
// has been running for a month restores a month of dead sessions on the way
// up — every one of them expired, every one of them swept moments later, and
// all of them read, decrypted and parsed first.
function retentionMs() {
  log.debug("Entering retentionMs().");
  log.debug("Leaving retentionMs().");
  return Math.max(0, Number(config.value('persistence.mintedRetention')) || 0);
}

// ---------------------------------------------------------------------------
// WHY THE LDIF DRIVER DOES NOT DO THIS, SAID ONCE AND OUT LOUD.
//
// That driver writes WHOLE FILES, atomically, per flush — which is exactly
// right for a directory that changes when somebody types, and exactly wrong
// for an audit ring and a session table that change on every request. Product
// mode on `ldif` would rewrite megabytes per write delay under any real load.
//
// So it does not, and the service SAYS so at startup rather than letting it be
// discovered one restart later. It is the same shape of honesty
// `persistence.realms` already practises about a half-persisted service: one
// sentence at the point of the decision beats a surprise afterwards.
// ---------------------------------------------------------------------------
/**
 * Tells whether a persistence driver can hold minted rows.
 *
 * The ldif driver cannot: it writes whole files, which is wrong for stores
 * that change on every request.
 * @param theDriver - the driver to test
 * @returns true when it has `loadMinted()` and `saveMinted()`
 */
function supports(theDriver) {
  log.debug("Entering supports().");
  log.debug("Leaving supports().");
  return !!(theDriver && typeof theDriver.loadMinted === 'function' &&
            typeof theDriver.saveMinted === 'function');
}

// ---------------------------------------------------------------------------
// INSTALLATION. `persistence.js` calls this once it has opened a driver, and
// this is where the observer is armed — after which every declared store
// reports its writes.
// ---------------------------------------------------------------------------
/**
 * Installs the driver minted rows are written through, and arms the journal.
 *
 * For a driver that cannot hold minted state, says so at startup (a warning
 * in product mode) and journals nothing.
 * @param theDriver - the opened persistence driver
 * @param activeMode - the persistence mode's name, for the messages
 * @returns true when the driver was installed
 */
function setDriver(theDriver, activeMode) {
  log.debug('Entering setDriver(). mode=' + activeMode);
  if (!supports(theDriver)) {
    driver = null;
    unsupportedReason = 'the ' + activeMode + ' store cannot hold minted ' +
      'state: it writes whole files per flush, which is right for a ' +
      'directory somebody types into and wrong for a session table and an ' +
      'audit ring that change on every request';
    if (mode.isProduct() && config.value('persistence.minted')) {
      log.warn(errorCodes.tag('STS-STORE-0012') +
               'persistence: PRODUCT MODE, AND ' +
               unsupportedReason.toUpperCase() + '. The directory, the realm ' +
               'registry, the runtime settings and the signing keys are ' +
               'still written down and restored; sessions, tokens, codes, ' +
               'artifacts, tickets, the replay caches and the audit log are ' +
               'in memory and will be gone at the next restart. Set ' +
               'persistence.mode=postgres to persist them.');
    }
    log.debug('Leaving setDriver(). Unsupported.');
    return false;
  }
  driver = theDriver;
  origin = typeof theDriver.origin === 'function' ? theDriver.origin() :
           'local';
  unsupportedReason = '';
  realms.setPersistObserver(note);
  // And the on-demand stores their reader (#820).
  realms.setOnDemandReader({ active: demandLiveFor, read: onDemandRead,
                             byIndex: onDemandByIndex,
                             digestOf: residentDigestOf,
                             page: onDemandPage,
                             readMany: onDemandReadMany,
                             newestAsync: onDemandNewestAsync,
                             countAsync: onDemandCountAsync,
                             countEstimateAsync: onDemandCountEstimateAsync,
                             byIndexAsync: onDemandByIndexAsync,
                             journalled: pendingWrite });
  // And the fan-in its noted rows' reader (#820, `contributionsOnRead`).
  replication.setContributionReader(
    typeof theDriver.readMintedMany === 'function' ? readContributions : null);
  log.debug('Leaving setDriver(). ' + realms.handles().length +
            ' declared store(s).');
  return true;
}

// ---------------------------------------------------------------------------
// THE JOURNAL DOOR. This is `realms.js`'s persist observer, and it is called
// from inside `sessions.set()` — which is inside a sign-in — so it does the
// least it can: two Map lookups and a Set insert, no allocation past the
// first write to a store.
//
// **IT DOES NOT CHECK `enabled()`.** That is deliberate and it is the one
// non-obvious thing in this file. `enabled()` reads three settings, and this
// runs on the hot path of every store in the service; instead the observer is
// only ARMED at all when a driver that can hold minted state was opened, and
// the flush is where the mode and the setting are consulted. The cost of being
// wrong that way round is a Set that fills and is discarded, which is nothing;
// the cost of the other way round is three config reads per session write.
// One call gates the session window. `auto` loads it only when the window
// itself is active: minted persistence, one cell, and a digest key. Off
// does not. The value is not the ambient realm's: a realm cannot carry
// this setting.
// ---------------------------------------------------------------------------
function note(handle, realmId, key) {
  if (restoring || stopped) {
    return;
  }
  let byRealm = journal.get(handle);
  if (!byRealm) {
    byRealm = new Map();
    journal.set(handle, byRealm);
  }
  const id = String(realmId === undefined || realmId === null ? '' : realmId);
  let keys = byRealm.get(id);
  if (!keys) {
    keys = new Set();
    byRealm.set(id, keys);
  }
  const noted = key === null || key === undefined ? '' : String(key);
  keys.add(noted);
  generation += 1;
  if (handle === 'authn.sessions') {
    const sessionWindow = sessionWindowIfOn();
    if (sessionWindow) {
      try {
        sessionWindow.noteLocal(id, noted);
      } catch (e) {
        log.debug("Caught in note(): " + ((e && e.message) || e));
      }
    }
  }
  if (!observational.has(handle)) {
    observationalCount.miss();
    const declared = realms.handleFor(handle);
    observational.set(handle, !!(declared && declared.observation));
  } else {
    observationalCount.hit();
  }
  if (observational.get(handle)) {
    observedGeneration += 1;
  }
  if (!flushAsked && !requeuing && scheduler) {
    // `scheduler` answers false when nothing could be scheduled (the store is
    // restoring, or persistence is off), and the next write asks again.
    flushAsked = scheduler() !== false;
  }
}

// `persistence.js` hands its `mintedChanged()` here once a driver is open.
/**
 * Installs the function a journalled write calls to ask for a flush.
 * @param fn - `persistence.js`'s `mintedChanged()`; anything else clears it
 */
function setScheduler(fn) {
  log.debug("Entering setScheduler().");
  scheduler = typeof fn === 'function' ? fn : null;
  flushAsked = false;
  log.debug("Leaving setScheduler().");
}

// The inverse of `storedKey()`. A `replace` store's key is itself; an `own`
// store's carries the origin after a NUL.
function splitKey(row, storedName) {
  log.debug("Entering splitKey().");
  if (!row || row.merge !== 'own') {
    log.debug("Leaving splitKey().");
    return { key: storedName, origin: '' };
  }
  const text = String(storedName);
  const at = text.lastIndexOf('.');
  if (at < 0) {
    log.debug("Leaving splitKey().");
    // A row written before this store was declared `own`, or by an older
    // build. Treated as unqualified rather than dropped: it is somebody's
    // real data, and the worst it can do is be restored as this process's.
    return { key: text, origin: '' };
  }
  try {
    log.debug("Leaving splitKey().");
    return {
      key: Buffer.from(text.slice(0, at), 'base64url').toString('utf8'),
      origin: Buffer.from(text.slice(at + 1), 'base64url').toString('utf8')
    };
  } catch (e) {
    log.debug("Caught in splitKey(): " + ((e && e.message) || e));
    log.debug("Leaving splitKey().");
    // Not the shape storedKey() writes. Same answer as no separator at all:
    // somebody's real data, restored unqualified rather than thrown away.
    return { key: text, origin: '' };
  }
}

// ---------------------------------------------------------------------------
// APPLYING ONE ROW ANOTHER PROCESS WROTE. `persistence_replication.js` hands
// this a change-log pointer; this reads the row it names and puts it where it
// belongs — into the live store for a `replace` store, into the fan-in for an
// `own` one.
//
// A row that is GONE is a delete: the store drops the key. That is why the
// change log does not distinguish an upsert from a delete — "look at this
// key" covers both, and a distinction would be a second thing to keep in step
// with what is actually in the table.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// ONE ROUND TRIP FOR A PAGE OF CHANGES, RATHER THAN ONE PER ROW (2026-09-07).
//
// `applyChange()` below reads the row its change names, and it did that with a
// query of its own — which was free while minted rows never reached the change
// log, and stopped being free the moment they did. They are now most of the
// log: a measured dispatch run held 5,452 minted changes against 460 directory
// ones, because a browser flow mints a session, a code, an access token, an ID
// token and a refresh token and each is a row.
//
// So a catch-up was up to 500 sequential queries, `workers.readYourWrite` gives
// a worker 5000ms to catch up, and past that it serves what it has — which is a
// directory it has not caught up on. The visible failure was a test creating an
// application through `/admin-api` and being told, on the next request, that no
// such application exists.
//
// `prefetch()` is called once with the whole page before any row is applied and
// fills a map the applier reads instead of querying. It is CLEARED afterwards
// rather than kept: it is a page's working set and never a cache — a row held
// past the page it came from would be a row this process believes without
// having been told it is still there.
//
// A driver with no `readMintedMany` (the ldif one, and every test double) is
// unaffected: the map stays empty and every applier falls back to its own read,
// which is exactly what it did before.
// ---------------------------------------------------------------------------
let prefetched = null;

/**
 * Reads, in one query, every minted row a page of change-log rows names.
 *
 * The applier then reads from this map instead of querying per row; the map
 * is a page's working set, cleared by `endPrefetch()`. A driver without
 * `readMintedMany()` leaves it empty, and a failed read falls back to one
 * query per row.
 * @param changes - the change-log rows of the page
 * @returns a promise of the number of references read
 */
function prefetch(changes) {
  log.debug("Entering prefetch().");
  // A PAGE NAMING A DATA ENCRYPTION KEY NOT HELD YET READS THE DATA-KEY ROWS
  // ONCE FIRST (#1070), so its names open and its rows are in the one query.
  // One change key per missing key id, to ask again after the read.
  const unheld = new Map();
  (changes || []).forEach(function (change) {
    const id = unheldDekOfChange(change.key);
    if (id && !unheld.has(id) && worthRefreshFor(id)) {
      unheld.set(id, change.key);
    }
  });
  if (unheld.size) {
    log.debug("Leaving prefetch(). The data-key rows first.");
    return refreshForUnheld(null).then(function () {
      // WHAT THE READ DID NOT BRING IS NOT NOTED HERE (#1118): one read may
      // be too early, and `applyChange()` waits for such a key (a few fresh
      // reads, shared per key) before it skips anything.
      return prefetchPage(changes);
    });
  }
  log.debug("Leaving prefetch().");
  return prefetchPage(changes);
}

// prefetch()'s read, once every name the page can open opens.
function prefetchPage(changes) {
  log.debug("Entering prefetchPage().");
  // **THE PAGE'S ROWS ACCUMULATE (2026-10-21).** `minted` and `minted-own`
  // are two kinds, each with its own `prepare`, and replication prepares
  // every kind of a page before it applies any — so this began by dropping
  // what the kind before had read, and every `minted` row of the page was
  // then read alone: on 8081 the front process alone asked 750 single-row
  // reads a second. Each prepare adds its rows to the page's map now;
  // `endPrefetch()`, once the page is applied, still drops it.
  if (!driver || typeof driver.readMintedMany !== 'function') {
    log.debug("Leaving prefetchPage().");
    return Promise.resolve(0);
  }
  const refs = [];
  const wanted = new Set();
  (changes || []).forEach(function (change) {
    const parsed = splitChangeKey(change.key);
    if (!parsed) {
      return;
    }
    const id = parsed.handle + '\u0000' + change.realm + '\u0000' +
               parsed.storedName;
    if (wanted.has(id)) {
      return;
    }
    wanted.add(id);
    // Not an on-demand row this process does not hold (#820): applyChange()
    // reads none of those. Nor another process's row of a store only a page
    // reads: applyChange() notes it.
    const declared = realms.handleFor(parsed.handle);
    if (declared && contributedOnRead(declared,
                                      splitKey(declared, parsed.storedName))) {
      return;
    }
    if (declared && declared.onDemand && demandLiveFor(parsed.handle) &&
        foreignRow(declared, splitKey(declared, parsed.storedName))) {
      // #1001: see applyChange().
      return;
    }
    if (declared && declared.onDemand && !declared.keysResident &&
        demandLiveFor(parsed.handle)) {
      const name = splitKey(declared, parsed.storedName).key;
      const local = declared.read(change.realm, name);
      if (!local || !local.present) {
        // Not read; and no longer known to be absent (#820 part 2).
        forgetAbsentIn(declared, change.realm, name);
        return;
      }
    }
    // Asked for by the KEY COLUMN (#222) and remembered by the name, which is
    // what applyChange() looks the answer up by.
    refs.push({ handle: parsed.handle, realm: change.realm,
                key: keyColumnOf(parsed.handle, change.realm,
                                 parsed.storedName),
                name: parsed.storedName });
  });
  if (!refs.length) {
    log.debug("Leaving prefetchPage().");
    return Promise.resolve(0);
  }
  log.debug("Leaving prefetchPage().");
  return driver.readMintedMany(refs.map(function (ref) {
    return { handle: ref.handle, realm: ref.realm, key: ref.key };
  })).then(function (rows) {
    const byColumn = new Map();
    refs.forEach(function (ref) {
      byColumn.set(ref.handle + '\u0000' + ref.realm + '\u0000' + ref.key,
                   ref.name);
    });
    const map = new Map();
    (rows || []).forEach(function (row) {
      const name = byColumn.get(row.handle + '\u0000' + row.realm +
                                '\u0000' + row.key);
      map.set(row.handle + '\u0000' + row.realm + '\u0000' +
              (name === undefined ? row.key : name), row);
    });
    // EVERY REF IS RECORDED, including the ones that came back with nothing:
    // "asked for and absent" is a real answer — it is what a DELETE looks like
    // — and without it the applier would fall back to a query per missing row,
    // which is the case a page of deletes is made entirely of.
    refs.forEach(function (ref) {
      const id = ref.handle + '\u0000' + ref.realm + '\u0000' + ref.name;
      if (!map.has(id)) {
        map.set(id, null);
      }
    });
    if (prefetched) {
      map.forEach(function (row, id) {
        prefetched.set(id, row);
      });
    } else {
      prefetched = map;
    }
    log.debug('prefetch(): ' + (rows || []).length + ' row(s) for ' +
              refs.length + ' reference(s), in one query.');
    return refs.length;
  }).catch(function (e) {
    // NOT FATAL: the appliers fall back to a query each, which is slower and
    // correct. A catch-up that failed entirely because a batch read failed
    // would be worse than a slow one.
    prefetched = null;
    log.warn(errorCodes.tag('STS-STORE-0013') +
             'persistence: a batched minted read failed (' + e.message +
             '); this page falls back to one query per row.');
    return 0;
  });
}

/**
 * What the page's prefetch holds for one row (2026-10-21): the row, null
 * where it was asked for and is absent, or undefined where it was not asked.
 *
 * @param handle - the store's handle
 * @param realmId - the realm
 * @param name - the row's stored name
 * @returns the row, null, or undefined
 */
function prefetchedRow(handle, realmId, name) {
  log.debug("Entering prefetchedRow().");
  log.debug("Leaving prefetchedRow().");
  return prefetched ? prefetched.get(handle + '\u0000' + realmId + '\u0000' +
                                     name) : undefined;
}

/**
 * Discards the page's prefetched rows.
 */
function endPrefetch() {
  log.debug("Entering endPrefetch().");
  prefetched = null;
  openedNames.clear();
  log.debug("Leaving endPrefetch().");
}

// ---------------------------------------------------------------------------
// A CHANGE WHOSE NAME IS SEALED UNDER A DATA ENCRYPTION KEY NOT HELD YET
// (#1070, 2026-10-28).
//
// A request worker that defines a realm makes the realm's data encryption
// keys and seeds its stores in the same second, and every seed row's NAME is
// sealed under the new key (`columnsFor()`, `minted-key`). The data-key rows
// land before the minted rows do (`flush()` waits on `settleDeks()`), but the
// process that PULLS the change log has not read them: it meets a name it
// cannot open. `keystore.open()` answers null for that and for a malformed
// envelope alike, so every such change was reported as "not the shape
// recordChanges() writes" (STS-STORE-0014, at error, ~1,400 lines a full run,
// a third of them `ssf_streams.streams`) and DROPPED — the pulling process
// never applied the new realm's seed rows from the log.
//
// The case `keystore.writeAfterDeks()` closed for key and authority rows on
// 2026-10-05, closed here the same way: a name under a key not held is told
// apart from a malformed one, the data-key rows are read again
// (`keystore.refreshDekRows()`), and the change is applied once more. Only a
// name whose key is STILL not held after that — since #1118, after five FRESH
// reads with a pause between, `waitForDek()` — is skipped: another build's,
// or a realm's that was removed — under STS-STORE-0089, said once per key, so
// STS-STORE-0014 keeps its meaning. `prefetch()` does the read once for the
// page before splitting, so a page of a new realm's seed rows costs one read
// of the data-key rows and its rows are still read in one query.
// ---------------------------------------------------------------------------
// When a key was last found missing AFTER a read of the data-key rows, by key
// id: a change under it within the interval is skipped without another read,
// so a page of another build's rows is not a read of the data-key rows each.
const unheldAfterRefresh = new Map();
const UNHELD_RECHECK_MS = 2000;
// THE READS BEFORE A CHANGE IS SKIPPED (#1118, 2026-10-28). One read of the
// data-key rows was not enough: it could be a read already in flight, sent
// before the new key's row committed, and run #7 dropped a new realm's first
// minted change that way on the other node (STS-STORE-0089 for a key made a
// second earlier). Like the directory applier's `keyedRetries`
// (`persistence_replication.js`), a key is read for up to UNHELD_READS times,
// each a FRESH read (`refreshDekRows({ fresh: true })`), a pause between, and
// every change under that key shares the one wait.
const UNHELD_READS = 5;
const UNHELD_READ_PAUSE_MS = 200;
// The wait in progress for a key, by key id: a promise of whether it is held.
const unheldWaits = new Map();
// The keys STS-STORE-0089 has been said for.
const unheldWarned = new Set();
const UNHELD_TRACKED_MAX = 1000;

// The id of the data encryption key a sealed name half names, when this
// process does not hold it; null otherwise (held, or not sealed at all).
function unheldDekOfHalf(half) {
  log.debug("Entering unheldDekOfHalf().");
  const text = String(half || '');
  if (text.indexOf('$') < 0 || typeof keystore.namesUnheldDek !== 'function' ||
      !keystore.namesUnheldDek(text)) {
    log.debug("Leaving unheldDekOfHalf(). Not a key missing here.");
    return null;
  }
  // Lazily, as `persistence.js` does: a leaf this file needs only here.
  const id = require('../common/crypto').dekIdOf(text);
  log.debug("Leaving unheldDekOfHalf().");
  return id || null;
}

// The same question of a whole change key.
function unheldDekOfChange(key) {
  log.debug("Entering unheldDekOfChange().");
  const text = String(key == null ? '' : key);
  const at = text.indexOf('.');
  log.debug("Leaving unheldDekOfChange().");
  return at < 0 ? null : unheldDekOfHalf(text.slice(at + 1));
}

// Whether a change under key `id` is worth a read of the data-key rows: not
// when one, made a moment ago, already found the key missing.
function worthRefreshFor(id) {
  log.debug("Entering worthRefreshFor().");
  const at = unheldAfterRefresh.get(id);
  log.debug("Leaving worthRefreshFor().");
  return at === undefined || Date.now() - at >= UNHELD_RECHECK_MS;
}

// Reads the data-key rows again for a change under key `id` — a read that
// starts after this call (#1118).
function refreshForUnheld(id) {
  log.debug("Entering refreshForUnheld(). dek=" + (id || 'the page'));
  const refreshing = typeof keystore.refreshDekRows === 'function'
    ? keystore.refreshDekRows({ fresh: true }) : Promise.resolve(0);
  log.debug("Leaving refreshForUnheld().");
  return Promise.resolve(refreshing).then(function () {
    return null;
  }, function (e) {
    // The refresh resolves on a failed read already; this is belt and
    // braces, and the change is then judged on what is held.
    log.debug("Caught in refreshForUnheld(): " + ((e && e.message) || e));
    return null;
  });
}

// Waits, for a change whose name half `half` is sealed under key `id`, until
// the key is held or UNHELD_READS fresh reads have not brought it (#1118).
// One wait per key: every change under it shares the answer. A key still
// not held is noted, so changes under it in the next UNHELD_RECHECK_MS are
// skipped without another read.
function waitForDek(id, half) {
  log.debug("Entering waitForDek(). dek=" + id);
  const running = unheldWaits.get(id);
  if (running) {
    log.debug("Leaving waitForDek(). Shared.");
    return running;
  }
  const waiting = (async function () {
    for (let i = 0; i < UNHELD_READS; i++) {
      await refreshForUnheld(id);
      if (!unheldDekOfHalf(half)) {
        return true;
      }
      if (i + 1 < UNHELD_READS) {
        await new Promise(function (resolve) {
          setTimeout(resolve, UNHELD_READ_PAUSE_MS);
        });
      }
    }
    noteUnheldAfterRefresh(id);
    return false;
  })().then(function (held) {
    unheldWaits.delete(id);
    return held;
  }, function (e) {
    // A read that throws is answered as the key not held; the change is
    // skipped under STS-STORE-0089 as it would be after the reads.
    unheldWaits.delete(id);
    log.debug("Caught in waitForDek(): " + ((e && e.message) || e));
    return false;
  });
  unheldWaits.set(id, waiting);
  log.debug("Leaving waitForDek(). Reading.");
  return waiting;
}

// Records that key `id` was still missing after a read of the data-key rows.
function noteUnheldAfterRefresh(id) {
  log.debug("Entering noteUnheldAfterRefresh().");
  if (unheldAfterRefresh.size >= UNHELD_TRACKED_MAX) {
    unheldAfterRefresh.clear();
  }
  unheldAfterRefresh.set(id, Date.now());
  log.debug("Leaving noteUnheldAfterRefresh().");
}

// A change skipped because its name's key is not held: said once per key.
function skipUnheld(change, handle, id) {
  log.debug("Entering skipUnheld(). dek=" + id);
  if (!unheldWarned.has(id)) {
    if (unheldWarned.size < UNHELD_TRACKED_MAX) {
      unheldWarned.add(id);
    }
    log.warn(errorCodes.tag('STS-STORE-0089') +
             'persistence: a minted change to "' + handle + '" names its ' +
             'row under the data encryption key "' + id + '", which this ' +
             'process does not hold after reading the data-key rows again. ' +
             'Skipped; said once per key.');
  } else {
    log.debug('skipUnheld(): ' + change.key + ' skipped, its key "' + id +
              '" not held.');
  }
  log.debug("Leaving skipUnheld().");
  return Promise.resolve(false);
}

// The change key's two halves, or null. Shared by prefetch() and applyChange()
// so the encoding is read in one place.
function splitChangeKey(key) {
  log.debug("Entering splitChangeKey().");
  const text = String(key == null ? '' : key);
  const at = text.indexOf('.');
  if (at < 0) {
    log.debug("Leaving splitChangeKey().");
    return null;
  }
  try {
    log.debug("Leaving splitChangeKey().");
    const storedName = nameOfChangeHalf(text.slice(at + 1));
    return storedName === null ? null : {
      handle: Buffer.from(text.slice(0, at), 'base64url').toString('utf8'),
      storedName: storedName
    };
  } catch (e) {
    log.debug("Caught in splitChangeKey(): " + ((e && e.message) || e));
    log.debug("Leaving splitChangeKey().");
    return null;
  }
}

/**
 * Applies one minted change another process committed into this process.
 *
 * Reads the row the change names (from the prefetch where present), opens it
 * under the key-encryption key, and puts it in the live store with the
 * journal suppressed — or, for a `merge: 'own'` row of another origin, hands
 * it to the replication fan-in. A row that cannot be read is skipped.
 * @param change - the change-log row, `{ key, realm, ... }`
 * @returns a promise of true when the change was applied
 */
function applyChange(change, refreshed) {
  log.debug('Entering applyChange(). key=' + change.key);
  if (!driver || typeof driver.readMinted !== 'function') {
    log.debug("Leaving applyChange().");
    return Promise.resolve(false);
  }
  // THE INVERSE OF WHAT `recordChanges()` PACKS INTO A MINTED CHANGE ROW:
  // base64url(handle) + '.' + base64url(storedKey). It was `handle\u0000key`
  // until 2026-09-07 and could not be committed at all — `sts_changes.key` is
  // `text` and PostgreSQL refuses a NUL — so this reader has never once had a
  // row to read. See persistence_postgres.js's recordChanges() for the minted
  // flush.
  //
  // Split on the FIRST '.', which is unambiguous: both halves are base64url and
  // '.' is not in that alphabet, so the only '.' in the string is this one —
  // including when the stored key is itself an `own` store's two-part name,
  // because that whole name was encoded as one half here.
  const text = String(change.key);
  const at = text.indexOf('.');
  if (at < 0) {
    log.error(errorCodes.tag('STS-STORE-0014') +
              'persistence: a minted change names "' + change.key + '", ' +
              'which carries no handle. Skipped.');
    log.debug("Leaving applyChange().");
    return Promise.resolve(false);
  }
  let handle;
  let storedName;
  try {
    handle = Buffer.from(text.slice(0, at), 'base64url').toString('utf8');
    // Sealed since #222, or base64url of the name.
    storedName = nameOfChangeHalf(text.slice(at + 1));
  } catch (e) {
    log.debug("Caught in applyChange(): " + ((e && e.message) || e));
    storedName = null;
  }
  if (storedName === null) {
    // NOT HELD YET, OR NOT OURS — told apart from malformed (#1070): see
    // unheldDekOfHalf() above.
    const half = text.slice(at + 1);
    const dekId = unheldDekOfHalf(half);
    if (dekId && !refreshed && worthRefreshFor(dekId)) {
      log.debug("Leaving applyChange(). Waiting for its key.");
      return waitForDek(dekId, half).then(function (held) {
        return held ? applyChange(change, true)
                    : skipUnheld(change, handle || '?', dekId);
      });
    }
    if (dekId) {
      log.debug("Leaving applyChange(). Its key is not held.");
      return skipUnheld(change, handle || '?', dekId);
    }
    log.error(errorCodes.tag('STS-STORE-0014') +
              'persistence: a minted change names "' + change.key + '", ' +
              'which is not the shape recordChanges() writes. Skipped.');
    log.debug("Leaving applyChange().");
    return Promise.resolve(false);
  }
  const store = realms.handleFor(handle);
  if (!store) {
    // Another build's store. Ordinary during a rolling upgrade.
    log.debug('Leaving applyChange(). No such handle here: ' + handle);
    return Promise.resolve(false);
  }
  const split = splitKey(store, storedName);
  // Another process changed the row: what this one committed for it may no
  // longer be what is filed (see `committedLookups`).
  committedLookups.delete(demandId(handle, change.realm, split.key));
  // ANOTHER PROCESS'S ROW OF A STORE ONLY A PAGE READS IS NOTED, NOT READ
  // (#820, `contributionsOnRead` in `common/realms.js`): the page reads it,
  // with everything else noted, when it is drawn.
  if (contributedOnRead(store, split)) {
    replication.contributionStale(handle, change.realm, split.key,
                                  split.origin, storedName);
    log.debug("Leaving applyChange(). Noted, read when asked for.");
    return Promise.resolve(true);
  }
  // AN ON-DEMAND ROW THIS PROCESS DOES NOT HOLD IS NOT READ (#820): it would
  // only be skipped once read — `applyLocally()` admits nothing — and
  // whoever asks for it next reads it from the store as it then is. Only a
  // held row is read, to be replaced, or found gone.
  // A KEY-RESIDENT store's row IS read, held or not (#820 part 2): its
  // digests are kept exact, and only the row says whether this was a write
  // or a delete. `applyLocally()` files the digest and holds nothing new.
  if (store.onDemand && demandLiveFor(handle) && foreignRow(store, split)) {
    // Another process's row of a per-origin store on demand (#1001): read
    // from the index when a reader asks, never held here.
    log.debug("Leaving applyChange(). On demand, another origin's row.");
    return Promise.resolve(true);
  }
  if (store.onDemand && !store.keysResident && demandLiveFor(handle)) {
    const local = store.read(change.realm, split.key);
    if (!local || !local.present) {
      forgetAbsentIn(store, change.realm, split.key);
      log.debug("Leaving applyChange(). On demand, not held.");
      return Promise.resolve(true);
    }
  }

  // THE PAGE'S PREFETCH FIRST — see prefetch() above. A miss here is a real
  // "not there", recorded as null, and only an ABSENT entry means this row was
  // not in the page and has to be read on its own.
  const held = prefetched
    ? prefetched.get(handle + '\u0000' + change.realm + '\u0000' + storedName)
    : undefined;
  const reading = held === undefined
    ? driver.readMinted(handle, change.realm,
                        keyColumnOf(handle, change.realm, storedName))
    : Promise.resolve(held);
  log.debug("Leaving applyChange().");
  return reading
    .then(function (row) {
      if (!row) {
        // GONE. For an `own` store that means the other process's
        // contribution was removed; for a `replace` store, that the key was
        // deleted there and must be deleted here.
        if (store.merge === 'own' && split.origin && split.origin !== origin) {
          replication.contribute(handle, change.realm, split.key,
                                 split.origin, null);
          return true;
        }
        // The index first: a failed repair rejects and the change is
        // retried, rather than landing in memory with no index row.
        return repairSessionIndex(store, handle, change.realm, storedName,
                                  null).then(function () {
          return applyLocally(store, change.realm, split.key, undefined,
                              true);
        });
      }
      if (!keystore.sealed()) {
        log.error(errorCodes.tag('STS-STORE-0015') +
                  'persistence: another process\'s minted row cannot be ' +
                  'opened — no key-encryption key. This process is behind.');
        return false;
      }
      const text = keystore.open(row.body, 'minted-rows');
      if (text === null) {
        // Written under a different key-encryption key. Reported once per row
        // rather than thrown: the alternative is replication wedging for ever
        // at the same seq over a row it will never be able to read.
        log.warn(errorCodes.tag('STS-STORE-0016') +
                 'persistence: another process\'s "' + handle + '" row will ' +
                 'not open under this key-encryption key. Skipped.');
        return false;
      }
      let value = null;
      try {
        value = JSON.parse(text);
      } catch (e) {
        log.debug("Caught in a callback in applyChange(): " +
                  ((e && e.message) || e));
        log.warn(errorCodes.tag('STS-STORE-0017') +
                 'persistence: another process\'s "' + handle + '" row ' +
                 'opened and is not JSON. Skipped.');
        return false;
      }
      if (store.merge === 'own' && split.origin && split.origin !== origin) {
        replication.contribute(handle, change.realm, split.key,
                               split.origin, value);
        return true;
      }
      return repairSessionIndex(store, handle, change.realm, storedName,
                                value).then(function () {
        return applyLocally(store, change.realm, split.key, value, false);
      });
    });
}

// Whether a change to this row is noted rather than read (#820): another
// process's row of a `contributionsOnRead` store, with a reader to read it
// by later. Hot path: every change applied. No Entering/Leaving pair.
function contributedOnRead(store, split) {
  return !!(store && store.contributionsOnRead && store.merge === 'own' &&
            split && split.origin && split.origin !== origin &&
            replication.contributionsReadable());
}

/**
 * Reads noted contributions of other processes (#820, `contributionsOnRead`),
 * in batches, from the primary.
 *
 * @param refs - `{ handle, realm, name }` for each row, `name` its stored name
 * @returns a promise of a Map from `handle\0realm\0name` to the opened value,
 *   or null where the row is gone; a row that will not open is left out
 */
function readContributions(refs) {
  log.debug("Entering readContributions(). " + refs.length + " row(s).");
  if (!driver || typeof driver.readMintedMany !== 'function') {
    log.debug("Leaving readContributions(). No batched read.");
    return Promise.reject(new Error('no batched read'));
  }
  const out = new Map();
  const BATCH = 500;
  let at = 0;
  const next = function () {
    if (at >= refs.length) {
      return Promise.resolve(out);
    }
    const chunk = refs.slice(at, at + BATCH);
    at += BATCH;
    const byColumn = new Map();
    const asked = chunk.map(function (ref) {
      const column = keyColumnOf(ref.handle, ref.realm, ref.name);
      byColumn.set(ref.handle + '\u0000' + ref.realm + '\u0000' + column,
                   ref);
      // Gone until a row says otherwise.
      out.set(ref.handle + '\u0000' + ref.realm + '\u0000' + ref.name, null);
      return { handle: ref.handle, realm: ref.realm, key: column };
    });
    return driver.readMintedMany(asked, { primary: true })
      .then(function (rows) {
        (rows || []).forEach(function (row) {
          const ref = byColumn.get(row.handle + '\u0000' + row.realm +
                                   '\u0000' + row.key);
          if (!ref) {
            return;
          }
          const id = ref.handle + '\u0000' + ref.realm + '\u0000' + ref.name;
          const opened = openedBody(ref.handle, row.body);
          if (opened === undefined) {
            out.delete(id);
          } else {
            out.set(id, opened);
          }
        });
        return next();
      });
  };
  log.debug("Leaving readContributions().");
  return next();
}

// Brings `sts_sessions` in line with a body another node committed (#350).
// Idempotent. A driver without the methods (memory, ldif, an older stub)
// skips it. A null digest writes nothing and does not delete a live row.
function repairSessionIndex(store, handle, realmId, storedName, value) {
  log.debug("Entering repairSessionIndex().");
  const active = /** @type {any} */ (driver);
  if (!store || typeof store.indexOf !== 'function' || !active) {
    log.debug("Leaving repairSessionIndex(). No index.");
    return Promise.resolve();
  }
  const key = keyColumnOf(handle, realmId, storedName);
  if (value == null) {
    if (typeof active.deleteSessionIndex !== 'function') {
      log.debug("Leaving repairSessionIndex(). No delete.");
      return Promise.resolve();
    }
    log.debug("Leaving repairSessionIndex().");
    return Promise.resolve(active.deleteSessionIndex(realmId, key));
  }
  if (typeof active.writeSessionIndex !== 'function') {
    log.debug("Leaving repairSessionIndex(). No write.");
    return Promise.resolve();
  }
  const columns = indexColumns(store, value);
  if (!columns) {
    log.debug("Leaving repairSessionIndex(). No columns.");
    return Promise.resolve();
  }
  log.debug("Leaving repairSessionIndex().");
  return Promise.resolve(active.writeSessionIndex(realmId, key, columns));
}

// Writing another process's row into this one's memory, with the journal
// suppressed — the same `restoring` flag the startup restore uses, and for the
// same reason: applying somebody else's write must not make this process
// report it as its own and write it straight back.
function applyLocally(store, realmId, key, value, remove) {
  log.debug("Entering applyLocally().");
  const was = restoring;
  restoring = true;
  try {
    let decision = remove ? 'remove' : 'restore';
    // AN ON-DEMAND STORE ADMITS NOTHING (#820): another process's row
    // replaces one this process holds, and is not taken otherwise — it is
    // read from the store when somebody asks for it.
    if (store && store.keysResident && demandLiveFor(store.handle)) {
      residentIn(store, realmId, key, !remove);
    }
    if (store && store.onDemand && !remove && demandLiveFor(store.handle)) {
      forgetAbsentIn(store, realmId, key);
      const held = store.read(realmId, key);
      decision = held && held.present ? 'restore' : 'skip';
    }
    if (store && store.handle === 'authn.sessions') {
      try {
        const sessionWindow = sessionWindowIfOn();
        if (sessionWindow) {
          decision = sessionWindow.considerApply(realmId, key, value,
                                                 !!remove);
        }
      } catch (e) {
        // The window's decision is an optimisation of what is resident.
        // A throw falls back to today's restore, which is the full map.
        log.debug("Caught in applyLocally(): " + ((e && e.message) || e));
        decision = remove ? 'remove' : 'restore';
      }
    }
    if (decision === 'remove' || remove) {
      // THE ONLY PATH HERE THAT REACHES THE STORE'S ORDINARY `delete`, because
      // the registry's accessors are `dump`, `read` and `restore` and none of
      // them removes anything. It is done through the shape's own door and the
      // journal is suppressed around it, which is why this is not a fourth
      // accessor.
      if (typeof store.remove === 'function') {
        store.remove(realmId, key);
      }
      log.debug("Leaving applyLocally().");
      return true;
    }
    if (decision === 'restore') {
      store.restore(realmId, key, value);
    }
    log.debug("Leaving applyLocally().");
    return true;
  } finally {
    restoring = was;
  }
}

// Hot path: note() runs inside every sessions.set. No Entering/Leaving
// pair. active() is the gate, so auto is on only when the three
// predicates hold. A literal "on" left auto keeping the full map.
function sessionWindowIfOn() {
  const sessionWindow = require('../authn/session_window');
  if (!sessionWindow.active()) {
    return null;
  }
  return sessionWindow;
}

// Is there anything to write? `persistence.js` asks before scheduling.
/**
 * Tells whether any journalled key is waiting to be written.
 * @returns true when there is something to flush
 */
function dirty() {
  log.debug("Entering dirty().");
  log.debug("Leaving dirty().");
  return journal.size > 0;
}

// ---------------------------------------------------------------------------
// THE FLUSH.
//
// Takes the journal, reads each named key out of the live store, seals what is
// there and deletes what is not. The journal is CLEARED FIRST, for
// `persistence.js`'s reason: a write made while this is in flight has to get
// its own flush rather than being cleared away unwritten. On a failure the
// keys go back, so nothing is lost by a database that blinked.
//
// ---------------------------------------------------------------------------
// ONE FLUSH AT A TIME IN A PROCESS, AND THE LATER ONE WAITS (2026-09-13).
//
// **A FLUSH READS EACH VALUE WHEN IT TAKES THE JOURNAL AND WRITES IT WHEN ITS
// TRANSACTION COMMITS, AND THOSE ARE NOT THE SAME MOMENT.** Between them are a
// pool checkout, a BEGIN and a statement per row, each taking a row lock held
// to COMMIT. Two flushes from one process could run at once — this function
// has two callers that do not wait for each other: `persistence.js`'s
// scheduled flush, and `request_worker.ts`'s commit announcement through
// `flushMinted()` — and a key written between their two journal takes is in
// BOTH, carrying two different values. The two transactions then commit in
// whatever order their locks allow, and `ON CONFLICT DO UPDATE` keeps
// whichever commits LAST, which need not be the one that read LAST.
//
// **THAT IS HOW A SIGN-IN WAS STORED AS AN ANONYMOUS ARRIVAL, AND IT IS THE
// WHOLE OF `sts_global_logout`'S DISPATCH-MODE FAILURE.** A browser arriving
// at `/wsfed` is given an arrival session — `anonymous`, `chosen: false` — and
// the sign-in a moment later upgrades the SAME row in place. Worker 34 took the
// arrival into one flush and the upgrade into another; the arrival's
// transaction began first (15:00:44.079), waited on a lock the upgrade's held
// (begun 15:00:44.267), and committed after it, so `sts_changes` shows the two
// rows for that session with their sequence numbers the opposite way round from
// their start times (41715 at .267, 41778 at .079). Every other process
// applied what the store held — an anonymous row nobody had chosen — while
// worker 34 held the signed-in session in memory. So `/admin-api/sessions`
// listed seven sessions where eight were live, the global sign-out ended the
// seven it could see, and the one it could not see went on authorising
// `prompt=none` at the worker that had it.
//
// **NO READ BARRIER COULD HAVE HELPED**, which is why the fix is here and not
// in `request_pool.js`: the reader caught up correctly — to a store that was
// wrong. Nor would the sign-out syncing to the latest change first, for the
// same reason.
//
// So a call made while a flush is in flight waits for it and then takes the
// journal itself. Commit order is then journal order within a process, and a
// later value can never be overwritten by an earlier one. The waiting call
// also picks up everything written while it waited, so a burst costs fewer
// transactions rather than more. What it does not change is two DIFFERENT
// processes writing one key, which is last-writer-wins by design and argued in
// `persistence/CLAUDE.md`.
//
// `tests/minted_persistence.js` section 5b holds it with a store that commits
// when told to.
// ---------------------------------------------------------------------------
/**
 * Writes every journalled key to the store, sealed; deletes what is gone.
 *
 * One flush at a time per process: a call made while one is in flight waits
 * for it and then takes the journal itself. On failure the keys go back into
 * the journal. Resolves rather than rejects.
 * @returns a promise of `{ written, upserts, deletes }`, or `{ written:
 * false }` with `error` when nothing was written or the write failed
 */
function flush() {
  log.debug('Entering flush().');
  if (flushInFlight) {
    // THE LATER CALL WAITS, and re-enters rather than continuing here: the
    // journal it must take is the one that exists AFTER the write in flight
    // has settled, not the one that existed when it was called. Several
    // waiters are harmless — the first takes everything and the rest find
    // nothing and resolve.
    const waitingFor = flushInFlight;
    log.debug('Leaving flush(). One is in flight; waiting for it first.');
    return waitingFor.then(function () {
      // A SETTLED WRITE IS NEVER WAITED ON TWICE. The write clears its own
      // marker before resolving, so this is belt and braces — but the braces
      // matter: a marker left on a settled promise would make this re-entry
      // wait on it again at once, for ever, in microtasks, which is a process
      // that stops answering and then runs out of memory rather than one that
      // is merely slow.
      if (flushInFlight === waitingFor) {
        flushInFlight = null;
      }
      return flush();
    });
  }
  if (!enabled()) {
    // The journal is cleared rather than kept. A process that is not
    // persisting minted state must not accumulate the names of every session
    // it has ever held — which is a memory leak whose size is the service's
    // whole traffic.
    journal.clear();
    flushAsked = false;
    committedAt = generation;
    log.debug('Leaving flush(). Not persisting minted state.');
    return Promise.resolve({ written: false });
  }
  if (!keystore.sealed() && typeof keystore.hasStarted === 'function' &&
      !keystore.hasStarted()) {
    // NOT YET IS NOT NEVER (#357). The store opens, and things are minted,
    // before `keystore.start()` has read the key-encryption key — a network
    // call to the secret store. This branch used to fall through to the one
    // below, which CLEARS the journal: whatever was minted in that window was
    // dropped, not deferred, and every process logged STS-STORE-0018 as it
    // started. The journal is kept and nothing is committed; `restore()`,
    // which runs once the keystore has started, keeps it too and asks for the
    // flush that writes it.
    flushAsked = false;
    log.debug('Leaving flush(). The keystore has not started; deferred.');
    return Promise.resolve({ written: false, deferred: true });
  }
  if (!keystore.sealed()) {
    journal.clear();
    flushAsked = false;
    committedAt = generation;
    lastError = 'no key-encryption key is available, so nothing minted can ' +
                'be sealed';
    // A PRODUCT-MODE REALM IN A PROCESS THAT IS NOT IN PRODUCT MODE IS NOT THE
    // SAME FAILURE (2026-09-14). `enabled()` reads `global.mode` through the
    // AMBIENT realm, and a flush scheduled from a request inherits that
    // request's realm — so a development process with no key-encryption key,
    // serving a realm somebody switched to product, reached this line on every
    // flush that realm's traffic scheduled and logged an ERROR each time: 11
    // lines in one postgres-mode suite run, about a configuration that is
    // stated once and does not change. The process-level case is the one this
    // line was written for — a product service whose keystore is not open —
    // and it stays an error per flush. The realm-level case is said ONCE, as a
    // warning, with the same code (the no-per-event-logs rule). `enabled()` is
    // deliberately NOT narrowed to require a key: `restore()` reads it too, and
    // a product process with no key must go on failing that fatally
    // (STS-STORE-0022) rather than restoring nothing in silence.
    if (processIsProduct()) {
      log.error(errorCodes.tag('STS-STORE-0018') +
                'persistence: ' + lastError + '. Minted state is not being ' +
                'written down.');
    } else if (!realmOnlyKeylessWarned) {
      realmOnlyKeylessWarned = true;
      log.warn(errorCodes.tag('STS-STORE-0018') +
               'persistence: a trust realm in product mode wrote minted ' +
               'state, and this process is in development mode with no ' +
               'key-encryption key, so ' + lastError + '. That realm\'s ' +
               'sessions, tokens and codes are held in memory only. Said ' +
               'once per process.');
    }
    log.debug('Leaving flush(). Nothing to seal with.');
    return Promise.resolve({ written: false, error: lastError });
  }

  const taken = journal;
  // Everything journalled so far is in `taken`: no flush is in flight here.
  const takenAt = generation;
  // WHERE A FLUSH'S TIME GOES (2026-10-22, #820): a request's commit hold
  // was ~55 ms on 8081 while the flush's statements took a few. Taken here,
  // before the rows are read and sealed.
  const flushStartedAt = Date.now();
  const upserts = [];
  const deletes = [];
  let unsealable = 0;

  taken.forEach(function (byRealm, handle) {
    const row = realms.handleFor(handle);
    if (!row) {
      // Unreachable unless a handle is journalled by something that is not a
      // declared store. Counted rather than thrown, for the reason every
      // failure on this path is counted rather than thrown.
      log.error(errorCodes.tag('STS-STORE-0019') +
                'persistence: "' + handle + '" reported a write and is not a ' +
                'declared store. Its rows cannot be written.');
      return;
    }
    byRealm.forEach(function (keys, realmId) {
      keys.forEach(function (key) {
        // A KEY POSTGRESQL CANNOT HOLD IS LEFT OUT (2026-09-27). A NUL in a
        // text column fails the WHOLE transaction ("invalid byte sequence
        // for encoding UTF8: 0x00"), the catch below puts every key back on
        // the journal, and the next flush fails the same way — for ever.
        // `provider_commands.ts` keyed its remembered issuer '\u0000issuer'
        // and a single-node run stopped persisting anything minted from the
        // first command onward: 853 failed flushes, and every job after it
        // that crossed workers failed. Nothing is lost that could have been
        // written; the store keeps the value in memory. Said once per store.
        if (String(key).indexOf('\u0000') >= 0 ||
            String(realmId).indexOf('\u0000') >= 0) {
          if (!nulKeyWarned.has(handle)) {
            nulKeyWarned.add(handle);
            log.error(errorCodes.tag('STS-STORE-0063') +
                      'persistence: "' + handle + '" journalled a key ' +
                      'holding a NUL character; PostgreSQL cannot store it, ' +
                      'so that row is kept in memory only. Said once per ' +
                      'store.');
          }
          return;
        }
        const present = row.read(realmId, key);
        if (!present || !present.present) {
          const gone = columnsFor(handle, realmId, storedKey(row, key));
          deletes.push({ handle: handle, realm: realmId,
                         key: gone.key, keySealed: gone.keySealed,
                         // The key as the STORE knows it, for the retry — see
                         // the catch below.
                         journalKey: key,
                         own: row.merge === 'own',
                         // An ENDED key leaves a tombstone. See
                         // ENDED ROWS below.
                         tombstone: row.tombstone === true,
                         // An on-demand store's index rows go with it (#820),
                         // its sort row among them (2026-10-22).
                         indexed: isIndexed(row) });
          return;
        }
        // Of the plaintext about to be sealed, not of the ciphertext.
        const indexed = indexColumns(row, present.value);
        let body = null;
        try {
          // Under THIS ROW'S realm's data encryption key (#391), not the
          // ambient realm's: a flush writes every realm's rows.
          body = keystore.seal(JSON.stringify(present.value), 'minted-rows',
                               tierOfHandle(handle), { realm: realmId });
        } catch (e) {
          // A value with a cycle in it, or a BigInt. Counted and skipped:
          // failing the whole transaction because one store holds something
          // unserialisable would stop every other store persisting too.
          log.error(errorCodes.tag('STS-STORE-0020') +
                    'persistence: "' + handle + '" holds a value under "' +
                    key + '" that will not serialise: ' + e.message);
        }
        if (body === null) {
          unsealable++;
          return;
        }
        // Built first and merged into after: the merger writes the merged
        // record's expiry back onto it. `any`, because `merge` is filled in.
        const columns = columnsFor(handle, realmId, storedKey(row, key));
        const upsert = /** @type {any} */ ({ handle: handle, realm: realmId,
                       key: columns.key, keySealed: columns.keySealed,
                       journalKey: key, body: body,
                       // WHEN THE RECORD IS DEAD (#333), or null: what the
                       // restore and the expiry purge read. See expiryOf().
                       expiresAt: expiryOf(row, present.value, key, realmId),
                       // Side-table columns, or null when there is no index.
                       // The merge path replaces these from the merged row.
                       index: indexed,
                       // An on-demand store's index keys (#820), or null —
                       // and null too when they are what this process last
                       // committed for the key (`unchangedLookups()`).
                       lookups: unchangedLookups(row, handle, realmId, key,
                         indexKeysFor(row, handle, realmId, key,
                                      present.value),
                         sortAtFor(row, present.value, key)),
                       // The number a console's newest-first list orders
                       // this row by, or null (`sortBy`, 2026-10-22, #820):
                       // written as one more index row while `lookups` is.
                       sortAt: sortAtFor(row, present.value, key),
                       // WHETHER A READER HAS TO WAIT FOR THIS ROW. An `own`
                       // store is per-process fan-in — every process keeps its
                       // own contribution and the console SUMS them when
                       // somebody asks — so another worker does not need it
                       // applied before it can answer. See the driver's
                       // recordChanges() and replication's syncNow().
                       own: row.merge === 'own',
                       tombstone: row.tombstone === true,
                       merge: undefined });
        if (row.mergeRow) {
          upsert.merge = mergerFor(row, handle, key, present.value, upsert,
                                   realmId);
        }
        upserts.push(upsert);
      });
    });
  });

  // ON-DEMAND KEYS IN FLIGHT (#820): an on-demand store reads a key it does
  // not hold from `sts_minted`, and until this flush commits that row is the
  // OLD one — so every on-demand key this flush writes or deletes stays
  // `pendingWrite()` until it settles, after the journal has let it go.
  const flying = [];
  upserts.concat(deletes).forEach(function (one) {
    const declared = realms.handleFor(one.handle);
    if (declared && declared.onDemand) {
      const id = demandId(one.handle, one.realm, one.journalKey);
      flying.push(id);
      inFlightDemand.set(id, (inFlightDemand.get(id) || 0) + 1);
    }
  });
  // Cleared here, and only here: everything above read from `taken`, which is
  // this same Map, so a write that lands during the loop is picked up by the
  // loop and one that lands after it survives the clear below.
  journal.clear();
  flushAsked = false;

  if (!upserts.length && !deletes.length) {
    committedAt = Math.max(committedAt, takenAt);
    log.debug('Leaving flush(). Nothing survived the read.');
    return Promise.resolve({ written: false });
  }

  log.debug("Leaving flush().");
  // THE DATA-KEY ROWS LAND FIRST (#391): a row sealed under a data encryption
  // key made during this flush must not reach another process before the key
  // does.
  const flushSealedAt = Date.now();
  let flushSentAt = 0;
  const saving = Promise.resolve(typeof keystore.settleDeks === 'function'
    ? keystore.settleDeks() : null).then(function () {
    flushSentAt = Date.now();
    return driver.saveMinted(upserts, deletes);
  }).then(function (result) {
    const doneAt = Date.now();
    requestPhases.record('FLUSH minted', {
      prepare: flushSealedAt - flushStartedAt,
      queue: flushSentAt - flushSealedAt,
      db: doneAt - flushSentAt,
      rows: upserts.length + deletes.length,
      total: doneAt - flushStartedAt });
    committedAt = Math.max(committedAt, takenAt);
    settleDecided(result);
    noteCommittedLookups(upserts, deletes, result);
    try {
      const sessionWindow = sessionWindowIfOn();
      if (sessionWindow) {
        sessionWindow.onCommitted(upserts);
      }
    } catch (e) {
      // The rows are committed. A window that cannot unpin must not make
      // the flush look failed, or the keys would be written again.
      log.debug("Caught in flush(): " + ((e && e.message) || e));
    }
    ensureTombstoneJob();
    writes++;
    rowsWritten += upserts.length;
    rowsDeleted += deletes.length;
    lastWriteAt = new Date().toISOString();
    lastError = '';
    failedWrite = false;
    log.debug('Leaving flush(). ' + upserts.length + ' row(s) written, ' +
              deletes.length + ' removed' +
              (unsealable ? ', ' + unsealable + ' unsealable' : '') + '.');
    return { written: true, upserts: upserts.length, deletes: deletes.length };
  }).catch(function (err) {
    // NOT rethrown, for the reason `persistence.js` argues at length: the
    // service keeps answering out of memory, and a database outage must not
    // take down seventeen protocol families that do not need a database.
    //
    // THE KEYS GO BACK ON THE JOURNAL so the next flush retries them. That is
    // this file's equivalent of not advancing the shadow, and it is why a
    // failed write loses nothing — except that a key whose value has since
    // changed is re-read at the next flush and written with the NEWER value,
    // which is what anybody would want.
    //
    // **THE KEY THAT GOES BACK IS THE JOURNAL'S, NOT THE ROW'S (2026-09-12).**
    // This re-noted `row.key`, which is `storedKey()`'s answer — and for a
    // `merge: 'own'` store that is the key base64url-encoded with the origin
    // appended. The next flush then read the store under that name, found
    // nothing, and wrote a delete keyed `storedKey()` of IT: the key grew by a
    // third plus the origin on every consecutive failure. A dispatched stack
    // whose workers deadlocked on this table for forty minutes grew those keys
    // until PostgreSQL refused them (`index row size 3880 exceeds btree version
    // 4 maximum 2704`), which made every later flush fail by construction, and
    // then kept growing them: one worker reached 5.6 GB and spent every sample
    // of an 8-second CPU profile hashing keys in `note()`, with its commit
    // announcements — and so the read barrier — stalled behind it. The SCIM
    // bulk load was the job that timed out.
    requeuing = true;
    try {
      upserts.forEach(function (row) {
        note(row.handle, row.realm, row.journalKey);
      });
      deletes.forEach(function (row) {
        note(row.handle, row.realm, row.journalKey);
      });
    } finally {
      requeuing = false;
    }
    failures++;
    lastError = err.message;
    failedWrite = true;
    log.error(errorCodes.tag('STS-STORE-0021') +
              'persistence: minted state could not be written: ' + err.message +
              '. It is retried shortly (persistence.js, ' +
              'retryAfterFailure()); ' +
              'a request whose rows were in it is answered 503 in postgres ' +
              'mode (#351).');
    log.debug('Leaving flush(). It failed.');
    return { written: false, error: err.message };
  });
  // CLEARED BEFORE THE RESULT IS HANDED ON, so that a caller waiting on this
  // promise finds nothing in flight when it re-enters. Cleared on either path:
  // a handler above that threw must not leave every later flush waiting on a
  // write that is over. Only if it is still THIS flush — `reset()` may have
  // started a new life for the module while this one was out.
  const settled = saving.then(function (result) {
    landDemand(flying);
    if (flushInFlight === settled) {
      flushInFlight = null;
    }
    return result;
  }, function (err) {
    log.debug("Caught in flush(): " + ((err && err.message) || err));
    landDemand(flying);
    if (flushInFlight === settled) {
      flushInFlight = null;
    }
    lastError = (err && err.message) || String(err);
    return { written: false, error: lastError };
  });
  flushInFlight = settled;
  inFlightTakenAt = takenAt;
  return settled;
}

// The generation every key journalled so far has reached, and the one whose
// writes have settled in the store.
/**
 * Returns the generation every key journalled so far has reached.
 * @returns the generation counter
 */
function generationNow() {
  log.debug("Entering generationNow().");
  log.debug("Leaving generationNow().");
  return generation;
}

// The part of `generation` that was observations. See `observedGeneration`.
/**
 * Returns the part of the generation that was observations.
 *
 * Journalled writes to `observation: true` stores (decision counters), which
 * the cluster barrier subtracts when it asks whether a request wrote.
 * @returns the observed-generation counter
 */
function observedGenerationNow() {
  log.debug("Entering observedGenerationNow().");
  log.debug("Leaving observedGenerationNow().");
  return observedGeneration;
}

/**
 * Returns the generation whose writes have settled in the store.
 * @returns the committed-generation counter
 */
function committedGeneration() {
  log.debug("Entering committedGeneration().");
  log.debug("Leaving committedGeneration().");
  return committedAt;
}

// ---------------------------------------------------------------------------
// A FLUSH THAT COVERS GENERATION `target`, AND NO MORE THAN IT NEEDS TO.
//
// Already committed: nothing to wait for. A flush in flight whose journal take
// covered it: that flush, and not the one queued behind it — which is what
// flush() would have returned, and under concurrent writers that is a SECOND
// transaction the caller has no writes in. Otherwise flush(), which waits out
// the one in flight and then takes the journal holding the target. Resolves
// flush()'s answer; `error` set means the write did not land.
// ---------------------------------------------------------------------------
/**
 * Makes sure the writes up to a generation are in the store.
 *
 * Answers at once when already committed, returns the flush in flight when
 * its journal covered the target, and otherwise calls `flush()`.
 * @param target - the generation to cover
 * @returns a promise of `flush()`'s answer; `error` set means the write did
 * not land
 */
function flushThrough(target) {
  log.debug("Entering flushThrough().");
  if (committedAt >= target) {
    log.debug("Leaving flushThrough(). Already committed.");
    return Promise.resolve({ written: false });
  }
  if (flushInFlight && inFlightTakenAt >= target) {
    log.debug("Leaving flushThrough(). The flush in flight covers it.");
    return flushInFlight;
  }
  log.debug("Leaving flushThrough(). Flushing.");
  return flush();
}

/**
 * Tells whether a failed write's keys are back on the journal and have not
 * reached the store since (#351).
 * @returns true from a failed write until the next successful one
 */
function failing() {
  log.debug("Entering failing().");
  log.debug("Leaving failing().");
  return failedWrite && journal.size > 0;
}

// ---------------------------------------------------------------------------
// ENDED ROWS, AND ROWS TWO NODES EDIT (2026-09-14, #46 section 3).
//
// **A SESSION CAME BACK AFTER SIGN-OUT.** Node A ended it: a delete, written
// down, replicated. Node B still held it in memory a moment behind and wrote
// its copy back on the next request that touched it — `noteSessionUsed()` and
// `touchArrivalSession()` stamp a field and re-set the row — so the session
// somebody signed out of was live again on every node. `flushInFlight` above
// fixed that ordering INSIDE one process; between processes the store simply
// had no record that the key had ever been ended.
//
// **AND A SIGN-IN WAS UNDONE, AND A RELYING PARTY WAS FORGOTTEN, THE SAME
// WAY.** An arrival session upgraded to a sign-in on A was written back as the
// anonymous arrival by B's touch; a client A added to the session's
// front-channel list was dropped by B's write of the session without it, and a
// client that is not on the list never gets its logout iframe.
//
// Two declarations on the store fix both, each read by the driver:
//
//   * `tombstone: true` — a delete leaves a tombstone and a write of the key
//     is refused IN SQL. What was refused is dropped here too: another node
//     ended it (`STS-STORE-0054`).
//   * `mergeRow(mine, theirs)` — the stored row is read under a lock and this
//     process's copy is merged with it; `mergerFor()` below opens, merges and
//     seals, so the driver never holds a key. What the merge produced is put
//     into this process's store unless a newer local write is already
//     journalled for the key, in which case the next flush merges that.
//
// A tombstone expires with `persistence.mintedRetention` — longer than every
// lifetime this service issues, which is how long a copy could be written
// back — through the scheduler job `persistence.tombstone-purge`. 0 keeps
// them with everything else.
// ---------------------------------------------------------------------------
// THE TIER A ROW IS SEALED FOR (#98). A handle `tiers.js` has not classified
// is sealed as CELL — the tier that keeps it where it was made — and the
// refusal that makes an unclassified store an error is `tests/cell_tiers.js`,
// at build time, rather than a flush that fails in production.
function tierOfHandle(handle) {
  log.debug("Entering tierOfHandle().");
  const out = tiers.isClassified(handle) ? tiers.mintedTierOf(handle)
                                         : 'cell';
  log.debug("Leaving tierOfHandle().");
  return out;
}

// ---------------------------------------------------------------------------
// A ROW'S NAME IS NOT IN THE CLEAR (#222, 2026-10-01).
//
// The name a store files a record under is often the credential itself: a
// session id is the cookie, a SAML artifact is redeemed by presenting it. The
// body was sealed and the name was not, so a dump of `sts_minted` — and of
// `sts_changes`, which copied it — held every live session id. Now:
//
//   * `key` is a KEYED DIGEST of handle, realm and name (`keyedDigest`, the
//     same key on every node), so a row is found from a name this process
//     already holds and the column says nothing about it;
//   * `key_sealed` is the name, SEALED under the row's realm and tier, for
//     the one reader that has no name to start from: the restore;
//   * a change-log row carries the sealed name (the driver's
//     recordChanges()), because a reader told of a DELETE must drop the name
//     from its own store, and no digest can tell it which.
//
// Where nothing seals (no key-encryption key) a row is written as before:
// `key` the name and `key_sealed` ''. Every reader takes a row with an empty
// `key_sealed` at its word, so the two shapes read alike.
// ---------------------------------------------------------------------------
const NAME_LABEL = 'minted-key';

// The two columns a row is written with: `{ key, keySealed }`.
function columnsFor(handle, realmId, storedName) {
  log.debug("Entering columnsFor().");
  const digest = keyColumnOf(handle, realmId, storedName);
  if (digest === storedName) {
    log.debug("Leaving columnsFor(). Unkeyed.");
    return { key: storedName, keySealed: '' };
  }
  let sealed = '';
  try {
    sealed = String(keystore.seal(String(storedName), NAME_LABEL,
                                  tierOfHandle(handle),
                                  { realm: realmId }) || '');
  } catch (e) {
    log.debug("Caught in columnsFor(): " + ((e && e.message) || e));
    sealed = '';
  }
  log.debug("Leaving columnsFor().");
  return sealed ? { key: digest, keySealed: sealed }
                : { key: storedName, keySealed: '' };
}

// The `key` column a name is filed under: its keyed digest, or the name where
// no digest key is held.
function keyColumnOf(handle, realmId, storedName) {
  log.debug("Entering keyColumnOf().");
  const digest = keystore.sealed() && typeof keystore.keyedDigest ===
    'function'
    ? keystore.keyedDigest(NAME_LABEL, String(handle) + '\n' +
                           String(realmId) + '\n' + String(storedName))
    : null;
  log.debug("Leaving keyColumnOf().");
  return digest || String(storedName);
}

// A row's name: `key_sealed` opened, or `key` where there is none. Null when
// the sealed name does not open.
// ---------------------------------------------------------------------------
// THE ON-DEMAND READER (#820, 2026-10-21). An `onDemand` store
// (`common/realms.js`) is a bounded cache over `sts_minted`, and this is what
// it asks: a row by its name, the rows filed under one index key, and whether
// a key has a write that has not committed yet. The questions go through a
// synchronous bridge thread of its own (`common/sync_query.ts`, the session
// window's arrangement) and come back sealed; they are opened here, where the
// keys are.
// ---------------------------------------------------------------------------
const INDEX_LABEL = 'minted-index';
// demandId -> how many flushes in flight carry it.
const inFlightDemand = new Map();
let demandBridge = null;

// Hot path: every on-demand flush row. No Entering/Leaving pair.
// ---------------------------------------------------------------------------
// THE INDEX KEYS THIS PROCESS LAST COMMITTED FOR A ROW (2026-10-21). A row of
// an indexed store is rewritten far more often than its index keys change —
// a refresh rewrites the token it rotated and the register record it revoked,
// neither filed anywhere new — and every rewrite deleted and re-inserted all
// of its index rows: up to seven for a token. Remembered after a commit, a
// row whose keys are unchanged writes none. Forgotten when this process
// deletes the row, when another process's change to it is applied (it may
// have deleted it, and its index rows with it), and wholesale past a bound;
// a forgotten key is simply written in full again. Not for a store that
// merges, whose keys are recomputed from the merged row in the transaction.
// ---------------------------------------------------------------------------
const committedLookups = new Map();
const COMMITTED_LOOKUPS_MAX = 100000;

// The lookups to write, or null when they are the committed ones. The sort
// value is part of what is compared (2026-10-22, #820): a row whose index
// keys are unchanged and whose sort value moved rewrites its index rows, the
// sort row among them. Hot path (every indexed row a flush writes): no
// Entering/Leaving pair.
function unchangedLookups(row, handle, realmId, key, lookups, sortAt) {
  if (!lookups || row.mergeRow) {
    return lookups;
  }
  const committed = committedLookups.get(demandId(handle, realmId, key));
  if (committed !== undefined &&
      committed === filedFingerprint(lookups, sortAt)) {
    return null;
  }
  return lookups;
}

// What a row is filed under, as one string: its index keys and its sort
// value. Hot path: no Entering/Leaving pair.
function filedFingerprint(lookups, sortAt) {
  return lookups.join('\n') + '\n\u0000' +
    (sortAt === null || sortAt === undefined ? '' : String(sortAt));
}

// Whether a declared store writes `sts_minted_index` rows: index keys
// (`indexBy`), a sort value (`sortBy`), or both. Hot path (every delete a
// flush journals): no Entering/Leaving pair.
function isIndexed(row) {
  return !!row && (typeof row.lookupsOf === 'function' ||
                   typeof row.sortOf === 'function');
}

// After a commit: what each written row is now filed under. Hot path (once
// per settled flush): no Entering/Leaving pair.
function noteCommittedLookups(upserts, deletes, result) {
  const refused = new Set(((result && result.refused) || []).map(
    function (one) {
      return demandId(one.handle, one.realm, one.journalKey);
    }));
  upserts.forEach(function (one) {
    const declared = realms.handleFor(one.handle);
    if (!declared || !isIndexed(declared) || declared.mergeRow) {
      return;
    }
    const id = demandId(one.handle, one.realm, one.journalKey);
    if (refused.has(id)) {
      committedLookups.delete(id);
      return;
    }
    if (Array.isArray(one.lookups)) {
      if (committedLookups.size >= COMMITTED_LOOKUPS_MAX) {
        committedLookups.clear();
      }
      committedLookups.set(id, filedFingerprint(one.lookups, one.sortAt));
    }
  });
  deletes.forEach(function (one) {
    committedLookups.delete(demandId(one.handle, one.realm, one.journalKey));
  });
}

function demandId(handle, realmId, key) {
  return String(handle) + '\u0000' + String(realmId) + '\u0000' + String(key);
}

// Hot path: once per settled flush. No Entering/Leaving pair.
function landDemand(ids) {
  ids.forEach(function (id) {
    const n = (inFlightDemand.get(id) || 0) - 1;
    if (n > 0) {
      inFlightDemand.set(id, n);
    } else {
      inFlightDemand.delete(id);
    }
  });
}

/**
 * Whether a key has a write this process has not committed: journalled, or
 * in a flush in flight.
 *
 * @param handle - the store's handle
 * @param realmId - the realm
 * @param key - the row's name
 * @returns true while the store's row may still be the old one
 */
function pendingWrite(handle, realmId, key) {
  log.debug("Entering pendingWrite().");
  log.debug("Leaving pendingWrite().");
  return journalled(handle, realmId, key) ||
    inFlightDemand.has(demandId(handle, realmId, key));
}

/**
 * Whether on-demand stores read from the store: a database driver that can
 * lend the bridge a connection, minted state persisted, and a key to open
 * its rows with. Otherwise every on-demand store is read back whole, as any
 * other.
 *
 * @returns true when on-demand reads are live
 */
function onDemandActive() {
  log.debug("Entering onDemandActive().");
  log.debug("Leaving onDemandActive().");
  return !!driver && typeof driver.bridgeConnection === 'function' &&
    enabled() && keystore.sealed();
}

// The indexed on-demand stores whose index this store says is complete
// (`mintedIndexComplete()`, asked at the restore). Until it is, such a
// store is read back whole, as before: a lookup by its index would miss
// every row written before schema version 24.
const indexComplete = new Set();

// A row another process wrote or deleted (#820 part 2): its key column
// joins or leaves a key-resident store's keys.
function residentIn(declared, realmId, key, present) {
  log.debug("Entering residentIn().");
  const digest = residentDigestOf(declared.handle, realmId, key);
  if (present) {
    declared.residentAdd(realmId, digest);
  } else {
    declared.residentRemove(realmId, digest);
  }
  log.debug("Leaving residentIn().");
}

// A key another process wrote is no longer known to be absent here (#820
// part 2): `forgetAbsent()` on the store's handle, where it has one.
function forgetAbsentIn(declared, realmId, key) {
  log.debug("Entering forgetAbsentIn().");
  if (declared && typeof declared.forgetAbsent === 'function') {
    declared.forgetAbsent(realmId, key);
  }
  log.debug("Leaving forgetAbsentIn().");
}

/**
 * Whether one on-demand store reads on demand: the reader is active and,
 * for an indexed store, its index is complete.
 *
 * @param handle - the store's handle
 * @returns true when the store is a cache over the store
 */
function demandLiveFor(handle) {
  log.debug("Entering demandLiveFor().");
  const declared = realms.handleFor(handle);
  log.debug("Leaving demandLiveFor().");
  return !!declared && declared.onDemand && onDemandActive() &&
    (!owesMark(declared) || indexComplete.has(handle)) &&
    // A key-resident store needs its keys loaded at a start (#820 part 2).
    (!declared.keysResident || typeof driver.loadMintedKeys === 'function');
}

// Whether an on-demand store waits for the completion mark before it reads
// on demand: an index to fill (#820), or legacy rows' expiries (part 2).
function owesMark(declared) {
  log.debug("Entering owesMark().");
  log.debug("Leaving owesMark().");
  return typeof declared.lookupsOf === 'function' ||
    typeof declared.expiryFromWrittenMs === 'function';
}

// The key column a key-resident store's key is filed under (#820 part 2):
// what `loadMintedKeys()` answers, so the two can be compared.
// Hot path: every key-resident question. No Entering/Leaving pair.
function residentDigestOf(handle, realmId, key) {
  const declared = realms.handleFor(handle);
  return declared ? keyColumnOf(handle, realmId, storedKey(declared, key))
    : null;
}

/**
 * Loads the key column of every live row of each live key-resident store
 * into its handle (#820 part 2), beside the restore.
 *
 * @param filter - the restore's filter: its realms and instant
 * @returns a promise of the number of keys loaded
 */
function loadResidentKeys(filter) {
  log.debug("Entering loadResidentKeys().");
  const resident = realms.handles().filter(function (declared) {
    return declared.keysResident && demandLiveFor(declared.handle);
  });
  if (!resident.length) {
    log.debug("Leaving loadResidentKeys(). None.");
    return Promise.resolve(0);
  }
  resident.forEach(function (declared) {
    declared.residentClear();
  });
  log.debug("Leaving loadResidentKeys().");
  return driver.loadMintedKeys(resident.map(function (declared) {
    return declared.handle;
  }), filter.realms, filter.nowMs).then(function (rows) {
    (rows || []).forEach(function (row) {
      const declared = realms.handleFor(row.handle);
      if (declared) {
        declared.residentAdd(row.realm, row.key);
      }
    });
    log.info('persistence: ' + (rows || []).length + ' key(s) of ' +
             resident.length + ' key-resident store(s) loaded (' +
             resident.map(function (declared) {
               return declared.handle;
             }).join(', ') + '), and none of their rows (#820).');
    return (rows || []).length;
  });
}

// ---------------------------------------------------------------------------
// THE BACKFILL (#820): every row of an indexed on-demand store that is not
// yet complete, filed under its index values from what the front process
// restored — the store is held whole until then — and then the mark. A row
// written meanwhile files itself in the flush; a row deleted meanwhile leaves
// an index row that the lookup's join with `sts_minted` does not answer.
//
// **A SCHEDULER JOB, NOT A STEP OF THE START.** Run from the restore, the
// first start of #823 on 8081 ran out of heap: it copied two million rows
// into an array (`dump()`) on a front process restoring beside four workers,
// and a worker that overran its start was terminated mid-restore. As a
// cluster job it runs on the leading front process, at its first slot after
// the scheduler starts — after the pool is up and the listener bound — walks
// each partition IN PLACE, a batch at a time with a pause between, and stops
// for this run when the heap is past `BACKFILL_HEAP_SHARE` of its limit. A
// stopped run is resumed whole at the next slot (index rows are written ON
// CONFLICT DO NOTHING), and the mark is written only after a complete walk.
// ---------------------------------------------------------------------------
const BACKFILL_JOB = 'persistence.minted-index-backfill';
const BACKFILL_EVERY_MS = 5 * 60 * 1000;
const BACKFILL_BATCH = 1000;
const BACKFILL_PAUSE_MS = 10;
const BACKFILL_HEAP_SHARE = 0.85;
// The handles this process filed and marked: nothing is left to do for them.
const indexBackfilled = new Set();
let backfillJobRegistered = false;

// The indexed on-demand stores still owed a complete index here.
function backfillOwed() {
  log.debug("Entering backfillOwed().");
  log.debug("Leaving backfillOwed().");
  return realms.handles().filter(function (declared) {
    return declared.onDemand && owesMark(declared) &&
      !indexComplete.has(declared.handle) &&
      !indexBackfilled.has(declared.handle);
  });
}

// True when the heap is too full to go on this run.
function heapTooFull() {
  log.debug("Entering heapTooFull().");
  const limit = require('v8').getHeapStatistics().heap_size_limit;
  log.debug("Leaving heapTooFull().");
  return limit > 0 && process.memoryUsage().heapUsed > limit *
    BACKFILL_HEAP_SHARE;
}

async function backfillMintedIndexes() {
  log.debug("Entering backfillMintedIndexes().");
  if (process.env.STS_REQUEST_WORKER || !onDemandActive() || !driver ||
      typeof driver.writeMintedIndex !== 'function' ||
      typeof driver.markMintedIndexed !== 'function') {
    log.debug("Leaving backfillMintedIndexes(). Not here.");
    return { filed: 0, marked: 0, stopped: false };
  }
  let filed = 0;
  let marked = 0;
  // The ids a write is journalled under (`realms.currentId()`): '' is the
  // default realm's partition too, and is not filed twice.
  const realmIds = restoreFilter(Date.now()).realms.filter(function (id) {
    return id !== '';
  });
  for (const declared of backfillOwed()) {
    // LEGACY EXPIRIES FIRST (#820 part 2), in the store, by statement.
    if (typeof declared.expiryFromWrittenMs === 'function') {
      if (typeof driver.backfillMintedExpiry !== 'function') {
        continue;
      }
      const given = await driver.backfillMintedExpiry(declared.handle,
        Number(declared.expiryFromWrittenMs()) || 0);
      log.info('persistence: ' + given + ' row(s) of "' + declared.handle +
               '" written before it declared an expiry were given one ' +
               '(#820).');
    }
    if (typeof declared.lookupsOf !== 'function') {
      await driver.markMintedIndexed(declared.handle);
      indexBackfilled.add(declared.handle);
      marked++;
      log.info('persistence: the on-demand store "' + declared.handle +
               '" has every row\'s expiry (#820): from the next start it is ' +
               'read on demand rather than restored whole.');
      continue;
    }
    let batch = [];
    let inBatch = 0;
    const flushBatch = async function () {
      if (batch.length) {
        filed += await driver.writeMintedIndex(batch);
        batch = [];
      }
      inBatch = 0;
      await new Promise(function (resolve) {
        setTimeout(resolve, BACKFILL_PAUSE_MS);
      });
    };
    for (const realmId of realmIds) {
      // The partition itself, walked by its own iterator: no copy. A row
      // added during a pause is visited or not, and files itself either way.
      const partition = declared.partition(realmId);
      if (!partition) {
        continue;
      }
      // And, for a `merge: 'own'` store, every other origin's rows the
      // held-whole start fanned in (#1001): each is a row of its own in
      // the store, filed under its own stored name, or a lookup would
      // answer only this process's share of a person.
      const foreign = declared.merge === 'own'
        ? replication.remoteContributions(declared.handle, realmId) : [];
      const walk = function* () {
        for (const e of partition.entries()) {
          yield { key: e[0], value: e[1], origin: undefined };
        }
        for (const c of foreign) {
          yield { key: c.key, value: c.value, origin: c.origin };
        }
      };
      for (const entry of walk()) {
        const column = keyColumnOf(declared.handle, realmId,
                                   storedKey(declared, entry.key,
                                             entry.origin));
        const lookups = lookupsFor(declared, declared.handle, realmId,
                                   entry.key, entry.value) || [];
        lookups.forEach(function (indexKey) {
          batch.push({ handle: declared.handle, realm: realmId,
                       indexKey: indexKey, key: column });
        });
        // The row's sort value, filed the same way (2026-10-22, #820).
        const sortAt = sortAtFor(declared, entry.value, entry.key);
        if (sortAt !== null) {
          batch.push({ handle: declared.handle, realm: realmId,
                       indexKey: require('./minted_queries').SORT_INDEX_KEY,
                       key: column, sortAt: sortAt });
        }
        if (++inBatch >= BACKFILL_BATCH) {
          await flushBatch();
          if (heapTooFull()) {
            log.warn(errorCodes.tag('STS-STORE-0086') + 'persistence: the ' +
                     'index of "' + declared.handle + '" was not completed ' +
                     'this run (#820): the heap is past ' +
                     Math.round(BACKFILL_HEAP_SHARE * 100) + '% of its ' +
                     'limit. The store stays read back whole, and the next ' +
                     'run of ' + BACKFILL_JOB + ' tries again.');
            log.debug("Leaving backfillMintedIndexes(). Heap.");
            return { filed: filed, marked: marked, stopped: true };
          }
        }
      }
    }
    await flushBatch();
    // The owner's last word while the store is whole (`beforeLive`, #820
    // part 3), in every realm, before the mark makes the next start read it
    // on demand.
    if (typeof declared.beforeLive === 'function') {
      realmIds.forEach(function (realmId) {
        realms.run(realms.get(realmId), function () {
          declared.beforeLive(realmId);
        });
      });
    }
    await driver.markMintedIndexed(declared.handle);
    indexBackfilled.add(declared.handle);
    marked++;
    log.info('persistence: the on-demand store "' + declared.handle +
             '" has its index complete (#820): from the next start it is ' +
             'read on demand rather than restored whole.');
  }
  log.debug("Leaving backfillMintedIndexes(). " + filed + " row(s) filed.");
  return { filed: filed, marked: marked, stopped: false };
}

/**
 * Registers the backfill's scheduler job, once.
 *
 * @param schedulerInstance - the scheduler, for the tests
 */
function ensureIndexBackfillJob(schedulerInstance) {
  log.debug("Entering ensureIndexBackfillJob().");
  if (backfillJobRegistered) {
    log.debug("Leaving ensureIndexBackfillJob(). Registered.");
    return;
  }
  const scheduler = schedulerInstance || require('../cluster/scheduler');
  if (!scheduler || typeof scheduler.register !== 'function') {
    log.debug("Leaving ensureIndexBackfillJob(). No scheduler yet.");
    return;
  }
  backfillJobRegistered = true;
  if (scheduler.job(BACKFILL_JOB)) {
    log.debug("Leaving ensureIndexBackfillJob(). Registered elsewhere.");
    return;
  }
  scheduler.register({
    id: BACKFILL_JOB,
    title: 'On-demand store index backfill',
    describe: 'Files the rows stored before schema version 24 of each ' +
              'indexed on-demand minted store in sts_minted_index, then ' +
              'marks the index complete, so the next start reads the store ' +
              'on demand (#820).',
    owner: 'persistence/persistence_minted.js',
    onFront: 'it files the rows of stores the front process holds whole, ' +
             'and only the front process registers it',
    everyMs: function () {
      return BACKFILL_EVERY_MS;
    },
    off: function () {
      if (!onDemandActive()) {
        return 'no store is read on demand here';
      }
      return backfillOwed().length ? '' : 'every index is complete';
    },
    run: function () {
      return backfillMintedIndexes().catch(function (e) {
        log.warn(errorCodes.tag('STS-STORE-0086') +
                 'persistence: an on-demand store\'s index could not be ' +
                 'completed (#820): ' + ((e && e.message) || e) + '. The ' +
                 'store stays read back whole, and the next run tries again.');
        return { failed: true };
      });
    }
  });
  log.debug("Leaving ensureIndexBackfillJob().");
}

/**
 * Asks the store which indexed on-demand stores have a complete index, into
 * `indexComplete`. A store that cannot say is taken as incomplete: it is
 * then read back whole, which is what it always was.
 *
 * @returns a promise settled when it is known
 */
function indexesComplete() {
  log.debug("Entering indexesComplete().");
  const indexed = realms.handles().filter(function (declared) {
    return declared.onDemand && owesMark(declared);
  }).map(function (declared) {
    return declared.handle;
  });
  if (!indexed.length || !driver ||
      typeof driver.mintedIndexComplete !== 'function') {
    log.debug("Leaving indexesComplete(). Nothing to ask.");
    return Promise.resolve();
  }
  log.debug("Leaving indexesComplete().");
  return driver.mintedIndexComplete(indexed).then(function (complete) {
    (complete || []).forEach(function (handle) {
      indexComplete.add(String(handle));
    });
  }, function (e) {
    log.debug("Caught in indexesComplete(): " + ((e && e.message) || e));
  });
}

// The bridge, made at its first question. Null where it cannot be.
function onDemandBridge() {
  log.debug("Entering onDemandBridge().");
  if (!demandBridge && driver && typeof driver.bridgeConnection === 'function') {
    const SyncQuery = require('../common/sync_query');
    demandBridge = new SyncQuery({
      connection: driver.bridgeConnection(),
      timeoutMs: function () {
        return Number(config.value('ldap.workerDirectoryTimeoutMs'));
      },
      queries: '../persistence/minted_queries.js',
      timeoutCode: 'STS-STORE-0084',
      refusedCode: 'STS-STORE-0084',
      threadErrorCode: 'STS-STORE-0084'
    });
  }
  log.debug("Leaving onDemandBridge().");
  return demandBridge;
}

// A sealed body opened and parsed, or undefined where it will not open.
function openedBody(handle, body) {
  log.debug("Entering openedBody().");
  const text = keystore.open(body, 'minted-rows');
  if (text === null) {
    log.warn(errorCodes.tag('STS-STORE-0085') + 'persistence: an on-demand "' +
             handle + '" row will not open under this process\'s keys; it is ' +
             'answered as absent.');
    log.debug("Leaving openedBody(). Unopened.");
    return undefined;
  }
  try {
    log.debug("Leaving openedBody().");
    return JSON.parse(text);
  } catch (e) {
    log.debug("Caught in openedBody(): " + ((e && e.message) || e));
    log.debug("Leaving openedBody(). Not JSON.");
    return undefined;
  }
}

/**
 * One row of an on-demand store, read from `sts_minted` by its name.
 *
 * A read that fails answers absent — every reader of these stores refuses
 * what it cannot find, which is the safe side — and is logged under
 * STS-STORE-0084.
 *
 * @param handle - the store's handle
 * @param realmId - the realm
 * @param name - the row's name, as the store keys it
 * @returns `{ present: true, value }` or `{ present: false }`
 */
function onDemandRead(handle, realmId, name) {
  log.debug("Entering onDemandRead(). " + handle);
  const bridge = onDemandBridge();
  if (!bridge) {
    log.debug("Leaving onDemandRead(). No bridge.");
    return { present: false };
  }
  // The row's stored name: for a `merge: 'own'` store THIS process's row,
  // `<name>.<origin>` (#1001).
  const declared = realms.handleFor(handle);
  const stored = declared ? storedKey(declared, name) : name;
  let answer = null;
  try {
    answer = bridge.query('minted.read',
      [handle, realmId, keyColumnOf(handle, realmId, stored)]);
  } catch (e) {
    log.error(errorCodes.tag('STS-STORE-0084') + 'persistence: an on-demand "' +
              handle + '" row could not be read: ' + ((e && e.message) || e));
    log.debug("Leaving onDemandRead(). Failed.");
    return { present: false };
  }
  if (!answer || !answer.body) {
    log.debug("Leaving onDemandRead(). Absent.");
    return { present: false };
  }
  const value = openedBody(handle, answer.body);
  log.debug("Leaving onDemandRead().");
  return value === undefined ? { present: false }
    : { present: true, value: value };
}

/**
 * The keyed digest an on-demand store's index value is filed under.
 *
 * @param handle - the store's handle
 * @param realmId - the realm
 * @param value - the index value (a family, a person)
 * @returns the digest, or null without a key
 */
function indexKeyOf(handle, realmId, value) {
  log.debug("Entering indexKeyOf().");
  log.debug("Leaving indexKeyOf().");
  return keystore.keyedDigest(INDEX_LABEL, String(handle) + '\n' +
                              String(realmId) + '\n' + String(value));
}

/**
 * The rows of an on-demand store filed under one index value.
 *
 * @param handle - the store's handle
 * @param realmId - the realm
 * @param value - the index value
 * @returns `[{ key, value }]`, each key the row's name
 */
function onDemandByIndex(handle, realmId, value) {
  log.debug("Entering onDemandByIndex(). " + handle);
  const bridge = onDemandBridge();
  const digest = indexKeyOf(handle, realmId, value);
  if (!bridge || !digest) {
    log.debug("Leaving onDemandByIndex(). No bridge or key.");
    return [];
  }
  let rows = [];
  try {
    rows = bridge.query('minted.byIndex', [handle, realmId, digest]) || [];
  } catch (e) {
    log.error(errorCodes.tag('STS-STORE-0084') + 'persistence: an on-demand "' +
              handle + '" index could not be read: ' +
              ((e && e.message) || e));
    log.debug("Leaving onDemandByIndex(). Failed.");
    return [];
  }
  const out = openedRows(handle, rows, false);
  log.debug("Leaving onDemandByIndex(). " + out.length + " row(s).");
  return out;
}

/**
 * Several rows of one on-demand store in one realm, asked together and off
 * the event loop (`warm()`, 2026-10-21), from the primary.
 *
 * @param handle - the store
 * @param realmId - the realm partition
 * @param keys - the keys, as the store holds them
 * @returns a promise of a Map from each key present to its value
 */
function onDemandReadMany(handle, realmId, keys) {
  log.debug("Entering onDemandReadMany(). " + handle);
  const declared = realms.handleFor(handle);
  if (!declared || !driver || typeof driver.readMintedMany !== 'function') {
    log.debug("Leaving onDemandReadMany(). No batched read.");
    return Promise.reject(new Error('no batched read'));
  }
  const byColumn = new Map();
  const refs = (keys || []).map(function (k) {
    const column = keyColumnOf(handle, realmId, storedKey(declared, k));
    byColumn.set(column, k);
    return { handle: handle, realm: realmId, key: column };
  });
  log.debug("Leaving onDemandReadMany().");
  return driver.readMintedMany(refs, { primary: true }).then(function (rows) {
    const out = new Map();
    (rows || []).forEach(function (row) {
      const k = byColumn.get(String(row.key));
      const opened = k === undefined ? undefined
        : openedBody(handle, row.body);
      if (opened !== undefined) {
        out.set(k, opened);
      }
    });
    return out;
  });
}

/**
 * One page of an on-demand store's live rows in one realm, in key-column
 * order after `after` (#820 part 3): what `scan()` walks the store by. A
 * page that cannot be read THROWS (STS-STORE-0084): a walk that stopped
 * quietly would answer "everything" with part of it — a revoke-all that
 * missed tokens.
 *
 * @param handle - the store
 * @param realmId - the realm partition
 * @param after - the cursor: the last row's key column, or ''
 * @returns `{ rows: [{ key, value }], next }`, `next` '' at the end
 */
function onDemandPage(handle, realmId, after) {
  log.debug("Entering onDemandPage(). " + handle);
  const bridge = onDemandBridge();
  if (!bridge) {
    log.debug("Leaving onDemandPage(). No bridge.");
    throw new Error(errorCodes.tag('STS-STORE-0084') + 'persistence: the ' +
                    'on-demand store "' + handle + '" cannot be walked: no ' +
                    'bridge to the store');
  }
  let rows = [];
  try {
    rows = bridge.query('minted.page', [handle, realmId, String(after || ''),
                                        Date.now()]) || [];
  } catch (e) {
    log.error(errorCodes.tag('STS-STORE-0084') + 'persistence: a page of the ' +
              'on-demand store "' + handle + '" could not be read: ' +
              ((e && e.message) || e));
    log.debug("Leaving onDemandPage(). Failed.");
    throw e;
  }
  const declared = realms.handleFor(handle);
  const out = [];
  rows.forEach(function (row) {
    const name = nameOfRow({ key: row.key, keySealed: row.keySealed });
    const opened = name === null ? undefined : openedBody(handle, row.body);
    if (opened !== undefined) {
      out.push({ key: declared ? splitKey(declared, name).key : name,
                 value: opened });
    }
  });
  log.debug("Leaving onDemandPage(). " + out.length + " row(s).");
  return { rows: out,
           next: rows.length >= pageLimit()
             ? String(rows[rows.length - 1].key) : '' };
}

// ---------------------------------------------------------------------------
// THE SAME QUESTIONS, ASKED WITHOUT HOLDING THE EVENT LOOP (2026-10-22,
// #820). A console page about a store with a million rows — Monitoring →
// Tokens — asked `scan()`'s and `lookup()`'s questions through the bridge,
// which stands the worker still for each round trip; and it walked only
// what this process held, so two workers drew two different lists. These
// ask the driver's READ POOL (`mintedQuery()`, `minted_queries.js`'s
// statements) and open what comes back here. Each rejects where the store
// cannot be asked, and the caller says the list was not read: an empty
// answer would read as "nothing issued".
// ---------------------------------------------------------------------------
// The driver's asynchronous door, or a rejection naming why there is none.
function mintedQueryAsync(name, args) {
  log.debug("Entering mintedQueryAsync(). " + name);
  if (!driver || typeof driver.mintedQuery !== 'function') {
    log.debug("Leaving mintedQueryAsync(). No asynchronous door.");
    return Promise.reject(new Error('the store has no asynchronous door ' +
                                    'for on-demand questions'));
  }
  log.debug("Leaving mintedQueryAsync().");
  return driver.mintedQuery(name, args);
}

// Rows the driver answered, each named and opened; a row whose name or
// body will not open is left out, as a read leaves it.
function openedRows(handle, rows, split) {
  log.debug("Entering openedRows(). " + handle);
  const store = realms.handleFor(handle);
  // A `merge: 'own'` store's names are split whatever the caller asked
  // (#1001): the bare name is `<key>.<origin>`, which no caller files
  // anything under, and the origin says whose row it is.
  const own = !!store && store.merge === 'own';
  const declared = split || own ? store : null;
  const out = [];
  (rows || []).forEach(function (row) {
    const name = nameOfRow({ key: row.key, keySealed: row.keySealed });
    const opened = name === null ? undefined : openedBody(handle, row.body);
    if (opened !== undefined) {
      const parts = declared ? splitKey(declared, name)
        : { key: name, origin: '' };
      const entry = { key: parts.key, value: opened };
      if (own) {
        entry.origin = parts.origin;
        entry.own = !foreignRow(store, parts);
      }
      out.push(entry);
    }
  });
  log.debug("Leaving openedRows(). " + out.length + " row(s).");
  return out;
}

/**
 * The newest live rows of an on-demand store in one realm, highest sort
 * value (`sortBy`) first, asked on the read pool.
 *
 * @param handle - the store
 * @param realmId - the realm partition
 * @param limit - at most this many (`minted_queries.NEWEST_LIMIT` caps it)
 * @returns a promise of `[{ key, value }]`
 */
function onDemandNewestAsync(handle, realmId, limit) {
  log.debug("Entering onDemandNewestAsync(). " + handle);
  // ORDERED BY THE STORE'S SORT VALUE (2026-10-22, #820): `minted.newest`
  // walks the `sort_at` index rows, which only a store declaring `sortBy`
  // writes. Another store would answer an empty list, which reads as a
  // store with no rows; it is refused instead, and the caller says the
  // list was not read.
  const declared = realms.handleFor(handle);
  if (!declared || typeof declared.sortOf !== 'function') {
    log.debug("Leaving onDemandNewestAsync(). No sortBy.");
    return Promise.reject(new Error('persistence: "' + handle + '" ' +
      'declares no sortBy, so its newest rows cannot be asked for'));
  }
  log.debug("Leaving onDemandNewestAsync().");
  return mintedQueryAsync('minted.newest',
                          [handle, realmId, Date.now(), limit])
    .then(function (rows) {
      return openedRows(handle, rows, true);
    });
}

/**
 * How many live rows an on-demand store holds in one realm, counted by the
 * store on the read pool.
 *
 * @param handle - the store
 * @param realmId - the realm partition
 * @returns a promise of the count
 */
function onDemandCountAsync(handle, realmId) {
  log.debug("Entering onDemandCountAsync(). " + handle);
  log.debug("Leaving onDemandCountAsync().");
  return mintedQueryAsync('minted.count', [handle, realmId, Date.now()])
    .then(function (n) {
      return Number(n) || 0;
    });
}

// AN ESTIMATE WHERE THE EXACT COUNT WOULD BE A SCAN (2026-10-22, #820).
// `minted.count` reads every live row of the store's partition: measured on
// 8081 with 2.43M token records, 5.7-8.6 s for Monitoring -> Tokens' total,
// paid on every view. An index-only count of (handle, realm) was 427 ms and
// still grows with the store. The planner's row estimate (`minted.estimate`)
// is 0.5 ms and was within 3 % there (2,363,753 for 2,429,984). It is a
// statistic, so it is wrong for a small store — the realm with no tokens was
// estimated at 3,527 — and below ESTIMATE_EXACT_BELOW the exact count is
// asked instead, which is milliseconds at that size. The threshold is an
// on-demand store's held bound (20,000): a store that would fit in memory is
// counted, one that would not is estimated, and the answer says which.
const ESTIMATE_EXACT_BELOW = 20000;

/**
 * How many live rows an on-demand store holds in one realm: the planner's
 * estimate where that is large, the exact count where it is not.
 *
 * @param handle - the store
 * @param realmId - the realm partition
 * @returns a promise of `{ count, exact }`
 */
function onDemandCountEstimateAsync(handle, realmId) {
  log.debug("Entering onDemandCountEstimateAsync(). " + handle);
  log.debug("Leaving onDemandCountEstimateAsync().");
  return mintedQueryAsync('minted.estimate', [handle, realmId])
    .then(function (estimate) {
      const n = Number(estimate);
      if (estimate !== null && Number.isFinite(n) &&
          n >= ESTIMATE_EXACT_BELOW) {
        return { count: Math.round(n), exact: false };
      }
      return onDemandCountAsync(handle, realmId).then(function (exact) {
        return { count: exact, exact: true };
      });
    });
}

/**
 * The rows of an on-demand store filed under one index value, asked on the
 * read pool.
 *
 * @param handle - the store's handle
 * @param realmId - the realm
 * @param value - the index value
 * @returns a promise of `[{ key, value }]`
 */
function onDemandByIndexAsync(handle, realmId, value) {
  log.debug("Entering onDemandByIndexAsync(). " + handle);
  const digest = indexKeyOf(handle, realmId, value);
  if (!digest) {
    log.debug("Leaving onDemandByIndexAsync(). No key.");
    return Promise.resolve([]);
  }
  log.debug("Leaving onDemandByIndexAsync().");
  return mintedQueryAsync('minted.byIndex', [handle, realmId, digest])
    .then(function (rows) {
      return openedRows(handle, rows, false);
    });
}

// The page size `minted_queries.js` answers, read where it is defined.
function pageLimit() {
  log.debug("Entering pageLimit().");
  log.debug("Leaving pageLimit().");
  return require('./minted_queries').PAGE_LIMIT;
}

// An on-demand store's index keys for one row, or null for a store with
// none. A hook that throws files the row under nothing rather than failing
// the flush.
function lookupsFor(row, handle, realmId, key, value) {
  log.debug("Entering lookupsFor().");
  if (!row || typeof row.lookupsOf !== 'function') {
    log.debug("Leaving lookupsFor(). Not indexed.");
    return null;
  }
  let values = [];
  try {
    values = row.lookupsOf(value, key) || [];
  } catch (e) {
    log.debug("Caught in lookupsFor(): " + ((e && e.message) || e));
    values = [];
  }
  const out = [];
  values.forEach(function (one) {
    if (one === null || one === undefined || one === '') {
      return;
    }
    const digest = indexKeyOf(handle, realmId, one);
    if (digest) {
      out.push(digest);
    }
  });
  log.debug("Leaving lookupsFor(). " + out.length + ".");
  return out;
}

// The index keys a flush files a row under: `lookupsFor()`'s, or an empty
// list for a store with a sort value and no index keys, so its sort row is
// still replaced (2026-10-22, #820). Null for a store with neither.
function indexKeysFor(row, handle, realmId, key, value) {
  log.debug("Entering indexKeysFor().");
  const lookups = lookupsFor(row, handle, realmId, key, value);
  if (lookups === null && row && typeof row.sortOf === 'function') {
    log.debug("Leaving indexKeysFor(). Sorted only.");
    return [];
  }
  log.debug("Leaving indexKeysFor().");
  return lookups;
}

// THE SORT VALUE (2026-10-22, #820): what a store's `sortBy` answers for a
// row, as a whole number, or null — for a store with no `sortBy`, an answer
// that is not a finite number, or a hook that throws. A null writes no sort
// row: the row is simply not in `minted.newest`'s list, never a flush
// failure.
function sortAtFor(row, value, key) {
  log.debug("Entering sortAtFor().");
  if (!row || typeof row.sortOf !== 'function') {
    log.debug("Leaving sortAtFor(). Not sorted.");
    return null;
  }
  let answer = null;
  try {
    answer = row.sortOf(value, key);
  } catch (e) {
    log.debug("Caught in sortAtFor(): " + ((e && e.message) || e));
    answer = null;
  }
  const n = typeof answer === 'number' ? answer : Number(answer);
  if (answer === null || answer === undefined || answer === '' ||
      !Number.isFinite(n)) {
    log.debug("Leaving sortAtFor(). No value.");
    return null;
  }
  log.debug("Leaving sortAtFor().");
  return Math.trunc(n);
}

function nameOfRow(row) {
  log.debug("Entering nameOfRow().");
  if (!row || !row.keySealed) {
    log.debug("Leaving nameOfRow(). Unkeyed.");
    return row ? row.key : null;
  }
  const opened = keystore.open(row.keySealed, NAME_LABEL);
  log.debug("Leaving nameOfRow().");
  return opened === undefined ? null : opened;
}

// The name half of a change-log key: sealed (it holds '$', which base64url
// does not), or base64url of the name. Null when a sealed one does not open.
// THE NAMES OPENED FOR THE PAGE BEING APPLIED (2026-10-21). A change's
// sealed name was opened twice — by `prefetch()` and again by
// `applyChange()` — in every process, for every change: a tenth of a request
// worker's busy time on 8081 went to applying other processes' changes.
// Held for the page only (`endPrefetch()` drops it) and bounded.
const openedNames = new Map();
const OPENED_NAMES_MAX = 20000;

function nameOfChangeHalf(text) {
  log.debug("Entering nameOfChangeHalf().");
  const half = String(text || '');
  if (half.indexOf('$') >= 0) {
    if (openedNames.has(half)) {
      log.debug("Leaving nameOfChangeHalf(). Opened already.");
      return openedNames.get(half);
    }
    const opened = keystore.open(half, NAME_LABEL);
    const name = opened === undefined ? null : opened;
    // A NAME UNDER A DATA ENCRYPTION KEY NOT HELD YET IS NOT REMEMBERED AS
    // UNOPENABLE (#1070): `applyChange()` reads the data-key rows again and
    // asks once more, and a remembered null would answer that second asking.
    if (name === null && unheldDekOfHalf(half)) {
      log.debug("Leaving nameOfChangeHalf(). Its key is not held yet.");
      return null;
    }
    if (openedNames.size >= OPENED_NAMES_MAX) {
      openedNames.clear();
    }
    openedNames.set(half, name);
    log.debug("Leaving nameOfChangeHalf(). Sealed.");
    return name;
  }
  log.debug("Leaving nameOfChangeHalf().");
  return Buffer.from(half, 'base64url').toString('utf8');
}

function mergerFor(row, handle, key, mine, upsert, realmId) {
  log.debug("Entering mergerFor().");
  log.debug("Leaving mergerFor().");
  return function (storedBody) {
    try {
      const text = keystore.open(storedBody, 'minted-rows');
      if (text === null) {
        log.warn(errorCodes.tag('STS-STORE-0056') + 'persistence: the "' +
                 handle + '" row another node wrote will not open here, so ' +
                 'this process\'s copy is written as it is.');
        return null;
      }
      const merged = row.mergeRow(mine, JSON.parse(text));
      const sealed = keystore.seal(JSON.stringify(merged), 'minted-rows',
                                   tierOfHandle(handle), { realm: realmId });
      // Only the ciphertext that will be written. A throw above leaves the
      // columns flush took from this process's copy, which is the body the
      // driver keeps when this returns null (#350).
      if (!sealed) {
        return sealed;
      }
      upsert.expiresAt = expiryOf(row, merged, key, realmId);
      upsert.index = indexColumns(row, merged);
      upsert.lookups = indexKeysFor(row, handle, realmId, key, merged);
      upsert.sortAt = sortAtFor(row, merged, key);
      return sealed;
    } catch (e) {
      log.warn(errorCodes.tag('STS-STORE-0056') + 'persistence: the "' +
               handle + '" row under "' + key + '" could not be merged with ' +
               'the stored one (' + ((e && e.message) || e) + '), so this ' +
               'process\'s copy is written as it is.');
      return null;
    }
  };
}

function journalled(handle, realmId, key) {
  log.debug("Entering journalled().");
  const byRealm = journal.get(handle);
  const keys = byRealm ? byRealm.get(String(realmId)) : null;
  log.debug("Leaving journalled().");
  return !!keys && keys.has(String(key));
}

function settleDecided(result) {
  log.debug("Entering settleDecided().");
  const refused = (result && result.refused) || [];
  const merged = (result && result.merged) || [];
  refused.forEach(function (row) {
    const store = realms.handleFor(row.handle);
    if (!store) {
      return;
    }
    log.info(errorCodes.tag('STS-STORE-0054') + 'persistence: a "' +
             row.handle + '" row was not written back: another node ended ' +
             'it. Dropped here too.');
    const byRealm = journal.get(row.handle);
    const keys = byRealm ? byRealm.get(String(row.realm)) : null;
    if (keys) {
      keys.delete(String(row.journalKey));
    }
    applyLocally(store, row.realm, row.journalKey, undefined, true);
  });
  merged.forEach(function (row) {
    const store = realms.handleFor(row.handle);
    if (!store || journalled(row.handle, row.realm, row.journalKey)) {
      return;
    }
    const text = keystore.open(row.body, 'minted-rows');
    if (text === null) {
      return;
    }
    try {
      applyLocally(store, row.realm, row.journalKey, JSON.parse(text), false);
    } catch (e) {
      log.debug("Caught in settleDecided(): " + ((e && e.message) || e));
    }
  });
  log.debug("Leaving settleDecided(). " + refused.length + " refused, " +
            merged.length + " merged.");
}

const TOMBSTONE_SWEEP_MS = 10 * 60 * 1000;
// The sweep's scheduler job (#49 P5): see ensureTombstoneJob().
const TOMBSTONE_JOB = 'persistence.tombstone-purge';
let tombstoneJobRegistered = false;

// THE SWEEP IS A SCHEDULER JOB (#49 P5): `persistence.tombstone-purge`, a
// CLUSTER job every TOMBSTONE_SWEEP_MS — the tombstones are rows every
// process shares. It was piggy-backed on the next flush in every process.
// Registered at the first flush, lazily: the scheduler loads after this —
// **AND AT START-UP IN EVERY PROCESS (2026-09-28)**, by
// `common/protocol_stack.ts` with the scheduler it hands in, for
// `common/admin_stats.js`'s ensureTokenPurgeJob() reason: a cluster job known
// only to the processes that had flushed is not a job every node can run, nor
// one both of the console's doors list.
function ensureTombstoneJob(schedulerInstance) {
  log.debug("Entering ensureTombstoneJob().");
  if (tombstoneJobRegistered) {
    log.debug("Leaving ensureTombstoneJob(). Registered.");
    return;
  }
  const scheduler = schedulerInstance || require('../cluster/scheduler');
  // Not latched before a registration can happen: see ensureTokenPurgeJob().
  if (!scheduler || typeof scheduler.register !== 'function') {
    log.debug("Leaving ensureTombstoneJob(). No scheduler yet.");
    return;
  }
  tombstoneJobRegistered = true;
  if (scheduler.job(TOMBSTONE_JOB)) {
    log.debug("Leaving ensureTombstoneJob(). Registered elsewhere.");
    return;
  }
  scheduler.register({
    id: TOMBSTONE_JOB,
    title: 'Expired tombstones sweep',
    describe: 'Deletes the tombstones of ended minted rows older than ' +
              'persistence.mintedRetention from the shared store.',
    owner: 'persistence/persistence_minted.js',
    everyMs: function () {
      return TOMBSTONE_SWEEP_MS;
    },
    off: function () {
      if (!driver || typeof driver.purgeTombstones !== 'function') {
        return 'this store keeps no tombstones';
      }
      return retentionMs() ? '' : 'the minted-row retention is 0';
    },
    run: function () {
      const now = Date.now();
      return Promise.resolve().then(function () {
        return driver.purgeTombstones(now - retentionMs());
      }).then(function (removed) {
        if (removed) {
          log.info('persistence: ' + removed + ' expired tombstone(s) of ' +
                   'ended minted rows swept.');
        }
        return { removed: Number(removed) || 0 };
      }, function (e) {
        log.warn(errorCodes.tag('STS-STORE-0055') + 'persistence: sweeping ' +
                 'expired tombstones failed: ' + ((e && e.message) || e) +
                 '.');
        throw e;
      });
    }
  });
  log.debug("Leaving ensureTombstoneJob().");
}

// ---------------------------------------------------------------------------
// THE ROWS NOTHING WILL READ AGAIN, DELETED FROM THE TABLE (2026-09-28, #333).
//
// `persistence.minted-expiry-purge`: a CLUSTER job — the table is every
// process's, so one process deleting is enough and five per node would be
// four too many — every EXPIRY_PURGE_MS. Three kinds of row, each named in
// the driver's purgeExpiredMinted(): past its own expiry; of a realm that is
// no longer defined, written more than ORPHAN_GRACE_MS ago; and a short-lived
// store's row with no expiry older than `persistence.mintedRetention` — which
// the restore used to delete, in EVERY process at every start.
//
// BOUNDED PER RUN: batches of EXPIRY_PURGE_BATCH rows, at most
// EXPIRY_PURGE_MAX_BATCHES per kind per run, so one run is a few short
// statements and never one delete of a whole backlog holding locks on the
// busiest table here. A backlog larger than a run is finished by the next
// runs — and a start skips those rows in the meantime, so a backlog costs
// disk and never start-up time.
//
// Logged as ONE summary line per run that deleted anything, and the failure
// once per run with STS-STORE-0065 (the no-per-event-failure-logs rule).
// ---------------------------------------------------------------------------
const EXPIRY_PURGE_JOB = 'persistence.minted-expiry-purge';
const EXPIRY_PURGE_MS = 5 * 60 * 1000;
const EXPIRY_PURGE_BATCH = 5000;
const EXPIRY_PURGE_MAX_BATCHES = 20;
// A realm another node is creating writes its minted rows and its registry
// row in two transactions; an hour is far longer than the gap between them.
const ORPHAN_GRACE_MS = 60 * 60 * 1000;
let expiryPurgeJobRegistered = false;

// One kind, batch after batch until a batch comes back short or the bound is
// reached. Resolves to `{ removed, more }`: `more` when the bound stopped it.
function purgeKind(kind, options) {
  log.debug("Entering purgeKind(). " + kind);
  let removed = 0;
  let batches = 0;
  function next() {
    log.debug("Entering next().");
    if (batches >= EXPIRY_PURGE_MAX_BATCHES) {
      log.debug("Leaving next(). The bound was reached.");
      return Promise.resolve({ removed: removed, more: true });
    }
    batches++;
    log.debug("Leaving next().");
    return driver.purgeExpiredMinted(kind, Object.assign({
      limit: EXPIRY_PURGE_BATCH
    }, options)).then(function (count) {
      const n = Number(count) || 0;
      removed += n;
      if (n < EXPIRY_PURGE_BATCH) {
        return { removed: removed, more: false };
      }
      return next();
    });
  }
  log.debug("Leaving purgeKind().");
  return next();
}

/**
 * Deletes, in bounded batches, the minted rows no restore will read again:
 * expired, of an undefined realm, or a short-lived store's stale row.
 * @param nowMs - the instant, in epoch milliseconds
 * @returns a promise of `{ expired, orphaned, stale, more }`
 */
function purgeExpired(nowMs) {
  log.debug("Entering purgeExpired().");
  if (!driver || typeof driver.purgeExpiredMinted !== 'function') {
    log.debug("Leaving purgeExpired(). This store cannot.");
    return Promise.resolve({ expired: 0, orphaned: 0, stale: 0,
                             more: false });
  }
  const retention = retentionMs();
  const out = { expired: 0, orphaned: 0, stale: 0, more: false };
  log.debug("Leaving purgeExpired().");
  return purgeKind('expired', { nowMs: nowMs }).then(function (r) {
    out.expired = r.removed;
    out.more = out.more || r.more;
    return purgeKind('orphan', { defaultRealm: realms.DEFAULT_ID,
                                 orphanBeforeMs: nowMs - ORPHAN_GRACE_MS });
  }).then(function (r) {
    out.orphaned = r.removed;
    out.more = out.more || r.more;
    if (!retention) {
      return { removed: 0, more: false };
    }
    return purgeKind('stale', { handles: shortLivedHandles(),
                                staleBeforeMs: nowMs - retention });
  }).then(function (r) {
    out.stale = r.removed;
    out.more = out.more || r.more;
    return out;
  });
}

// Registered at start-up in every process, by `common/protocol_stack.ts`,
// for ensureTombstoneJob()'s reason.
function ensureExpiryPurgeJob(schedulerInstance) {
  log.debug("Entering ensureExpiryPurgeJob().");
  if (expiryPurgeJobRegistered) {
    log.debug("Leaving ensureExpiryPurgeJob(). Registered.");
    return;
  }
  const scheduler = schedulerInstance || require('../cluster/scheduler');
  if (!scheduler || typeof scheduler.register !== 'function') {
    log.debug("Leaving ensureExpiryPurgeJob(). No scheduler yet.");
    return;
  }
  expiryPurgeJobRegistered = true;
  if (scheduler.job(EXPIRY_PURGE_JOB)) {
    log.debug("Leaving ensureExpiryPurgeJob(). Registered elsewhere.");
    return;
  }
  scheduler.register({
    id: EXPIRY_PURGE_JOB,
    kind: 'cluster',
    title: 'Expired minted rows purge',
    describe: 'Deletes from the shared store, in batches of ' +
              EXPIRY_PURGE_BATCH + ' and at most ' +
              EXPIRY_PURGE_MAX_BATCHES + ' batches of each kind per run, ' +
              'the minted rows no start will read again: past their own ' +
              'expiry, of a realm that is no longer defined (written over ' +
              'an hour ago), and a short-lived store\'s rows with no expiry ' +
              'older than persistence.mintedRetention.',
    owner: 'persistence/persistence_minted.js',
    everyMs: function () {
      return EXPIRY_PURGE_MS;
    },
    off: function () {
      if (!driver || typeof driver.purgeExpiredMinted !== 'function') {
        return 'this store keeps no minted rows';
      }
      return enabled() ? '' : 'minted state is not persisted here';
    },
    run: function () {
      return Promise.resolve().then(function () {
        return purgeExpired(Date.now());
      }).then(function (result) {
        const total = result.expired + result.orphaned + result.stale;
        if (total) {
          log.info('persistence: ' + total + ' minted row(s) purged from ' +
                   'the store — ' + result.expired + ' expired, ' +
                   result.orphaned + ' of realms no longer defined, ' +
                   result.stale + ' short-lived and older than ' +
                   'persistence.mintedRetention' +
                   (result.more ? '; more remain for the next run' : '') +
                   '.');
        }
        return result;
      }, function (e) {
        log.warn(errorCodes.tag('STS-STORE-0065') + 'persistence: purging ' +
                 'expired minted rows failed: ' + ((e && e.message) || e) +
                 '. A start skips them anyway; the next run tries again.');
        throw e;
      });
    }
  });
  log.debug("Leaving ensureExpiryPurgeJob().");
}

capabilities.provide('sessions.no-resurrection');

// ---------------------------------------------------------------------------
// THE RESTORE.
//
// **IT IS A THIRD STARTUP STEP AND IT CANNOT BE ANYTHING ELSE.** The KEK does
// not exist until `keystore.start()` has resolved, and `server.js` calls that
// AFTER `persistence.start()` — so this cannot join that function's chain, and
// it runs from `server.js` between the keystore and the listener binding. The
// order is what makes it right: the service starts answering with its sessions
// already back, rather than turning away the first arrivals and letting them
// in a moment later.
//
// **ONLY WHAT IS STILL WORTH HAVING IS READ (2026-09-28, #333).** The query
// itself — `restoreFilter()` below, which the driver turns into a WHERE —
// leaves out three kinds of row, so they are never fetched, decrypted or
// parsed: a row of a realm that is not defined (the realm registry was loaded
// by `persistence.start()`, before this runs); a row whose own expiry
// (`expiresAt` on its store's declaration, `sts_minted.expires_at`) has
// passed; and a row of a `retain: 'age'` store that has NO expiry and was
// written longer than `persistence.mintedRetention` ago. None of them is
// deleted here: every process runs this, and the table is the cluster's, so
// the deleting is one job's (`persistence.minted-expiry-purge`, below).
// Until then this read the whole table, with no WHERE, in every process —
// 127,131 rows and 31 s per process on testidp.
//
// Two kinds of what IS read are dropped, and each is counted separately,
// because they mean completely different things to somebody reading the
// startup line:
//
//   * UNREADABLE — will not open under the current key-encryption key, which
//     is what rotating one does to every row written under the old one.
//     Ordinary after a rotation, alarming otherwise.
//   * UNKNOWN — a handle no store in this build declares, which is what an
//     older or newer build's rows look like. Harmless and worth saying.
// ---------------------------------------------------------------------------
// What the restore asks the driver for: the realm partitions that exist — the
// shared stores' '' and the default realm under both of its spellings (a row's
// realm is `currentId()`, 'default', and '' is what `partitionId()` also reads
// as it) — the instant a row's own expiry is compared with, and the write-age
// rule for the short-lived stores that declare no expiry.
/**
 * Describes which minted rows a restore reads.
 * @param nowMs - the instant, in epoch milliseconds
 * @returns `{ realms, nowMs, staleBefore, ageHandles }`
 */
function restoreFilter(nowMs) {
  log.debug("Entering restoreFilter().");
  const ids = new Set(['', realms.DEFAULT_ID]);
  realms.list().forEach(function (one) {
    ids.add(String(one.id));
  });
  const retention = retentionMs();
  log.debug("Leaving restoreFilter().");
  return {
    realms: Array.from(ids),
    nowMs: nowMs,
    // 0 is "no write-age rule": `persistence.mintedRetention` 0 keeps
    // everything, as it always did.
    staleBefore: retention ? nowMs - retention : 0,
    ageHandles: shortLivedHandles(),
    // What a request worker does not read back at all (#617).
    skipHandles: process.env.STS_REQUEST_WORKER ? notInWorkers() : []
  };
}

// ---------------------------------------------------------------------------
// THE STORES A REQUEST WORKER DOES NOT RESTORE (#617, 2026-10-14):
// `restoreInWorkers: false` at `realms.map()` (`common/realms.js` argues the
// declaration). On 8081, 42,740 of the 52,234 rows every process read back at
// every start were `scheduler.runs` — 34 MB of 55 MB of sealed bodies, each
// opened and parsed — and in a request worker nothing reads that store whole:
// /admin/scheduler and `GET /admin-api/scheduler` are answered by the front
// process (`common/request_pool.js`, NEVER_DISPATCHED). The query leaves the
// rows out (`loadMinted()`'s `skipHandles`) and the loop below skips any a
// driver returned anyway. **What still holds**: the worker applies the change
// log from the high-water mark it takes after its restore, exactly as before,
// so every row written after its start reaches it; it writes its own rows,
// and the flush merges them with the stored ones (`mergeRow`); and the front
// process restores everything, as every process did.
// ---------------------------------------------------------------------------
function notInWorkers() {
  log.debug("Entering notInWorkers().");
  log.debug("Leaving notInWorkers().");
  return realms.handles().filter(function (one) {
    return one.restoreInWorkers === false;
  }).map(function (one) {
    return one.handle;
  });
}

// THE STORES THE WRITE-AGE RULE COVERS: `retain: 'age'`. It is applied only
// to a row with NO expiry (a NULL `expires_at`): a store with an `expiresAt`
// hook is bounded by its records' own expiries, which are always shorter
// than the retention. What it still reaches is a short-lived store that
// declares no hook, a record the hook answers null for, and every row written
// before #333 added the column — read at most for one retention period and
// then purged, which is all the migration there is.
function shortLivedHandles() {
  log.debug("Entering shortLivedHandles().");
  log.debug("Leaving shortLivedHandles().");
  return realms.handles().filter(function (one) {
    return one.retain === 'age';
  }).map(function (one) {
    return one.handle;
  });
}

// ---------------------------------------------------------------------------
// THE RESTORE'S LOOP, IN SLICES (#613, 2026-10-13).
//
// The loop opens, parses and restores every row a restore read, and it was
// one synchronous `forEach`: 48K rows held a request worker's event loop for
// seconds at every start, and a front process's too — and the front process
// is the one whose heartbeat and origin-claim renewal have to run
// (STS-CLUSTER-0025, STS-STORE-0069). So it runs `RESTORE_SLICE_MS` at a
// time and yields with `setImmediate()` between slices.
//
// **`restoring` IS SET ONLY WHILE A SLICE RUNS.** It is what keeps the
// restore's own writes out of the journal, and a slice is synchronous, so it
// still covers every one of them. Between slices it is clear, so a write
// something else makes there is journalled as usual — and at the start of
// the next slice that journal is taken ASIDE (`aside`), as the writes made
// while the rows were loading always were (`pending`), and put back after
// the restore, so the final `journal.clear()` cannot drop it. Before the
// listener binds nothing much writes a minted store (the scheduler has not
// started); this keeps it right if something does.
// ---------------------------------------------------------------------------
/** How long one slice of the restore may hold the event loop. */
const RESTORE_SLICE_MS = 50;

/**
 * Runs `fn` over `rows` in slices of at most `RESTORE_SLICE_MS`, with the
 * journal suppressed during each slice and what was journalled between slices
 * pushed onto `aside`.
 *
 * @param rows - the rows read from the store
 * @param aside - where journals taken between slices are kept
 * @param fn - restores one row
 * @returns a promise settled when every row has been through `fn`, or
 *   rejected with what `fn` threw
 */
function restoreInSlices(rows, aside, fn) {
  log.debug("Entering restoreInSlices(). " + rows.length + " row(s).");
  let next = 0;
  let slices = 0;
  log.debug("Leaving restoreInSlices(). Slicing.");
  return new Promise(function (resolve, reject) {
    const slice = function () {
      if (slices > 0) {
        aside.push(takePendingJournal());
      }
      slices += 1;
      const started = Date.now();
      restoring = true;
      try {
        while (next < rows.length) {
          fn(rows[next]);
          next += 1;
          if (Date.now() - started >= RESTORE_SLICE_MS) {
            break;
          }
        }
      } catch (e) {
        restoring = false;
        log.debug("Caught in restoreInSlices(): " + ((e && e.message) || e));
        reject(e);
        return;
      }
      restoring = false;
      if (next < rows.length) {
        setImmediate(slice);
        return;
      }
      log.debug("restoreInSlices(): " + rows.length + " row(s) in " +
                slices + " slice(s).");
      resolve(null);
    };
    slice();
  });
}

/**
 * Restores the minted rows from the store into this process at startup.
 *
 * Runs after the keystore has started. The query reads only live rows of
 * defined realms; unreadable and unknown rows are dropped and counted.
 * @returns a promise of `{ restored }`
 * @throws a rejected promise when minted state is persisted but no
 * key-encryption key is available, or the rows cannot be read
 */
function restore() {
  log.debug('Entering restore().');
  if (!enabled()) {
    log.debug('Leaving restore(). Not persisting minted state.');
    return Promise.resolve({ restored: 0 });
  }
  if (!keystore.sealed()) {
    // FATAL to the caller, unlike everything else in this file, and the
    // asymmetry is deliberate: a flush that cannot seal loses the newest
    // writes, and a restore that cannot open comes up EMPTY while presenting
    // itself as the process that was persisting. `server.js` treats a
    // rejection here the way it treats a keystore failure.
    log.debug('Leaving restore(). No key-encryption key.');
    return Promise.reject(new Error(errorCodes.tag('STS-STORE-0022') +
      'minted state is persisted (persistence.minted) but no key-encryption ' +
      'key is available to open it. The stored sessions, tokens, codes and ' +
      'artifacts cannot be read.'));
  }

  // ---------------------------------------------------------------------
  // AN EPHEMERAL RUN RESTORES NOTHING AND CLEARS WHAT IT FINDS (2026-09-07).
  //
  // The key that sealed a previous run's rows was generated by that run and
  // never written down, so those rows cannot be opened by this one — that is
  // the design, and it is what keeps "development persists nothing it minted
  // across a restart" true while the pool shares everything within a run.
  // Trying to restore them would be a log full of decryption failures for rows
  // nobody wants; leaving them would let them accumulate until retention swept
  // them by age.
  //
  // **ONLY THE FRONT PROCESS DOES IT, and `STS_REQUEST_WORKER` is how it
  // knows.** A worker runs these same four startup steps, so without this test
  // three workers would each clear the table — and they start after the front
  // process is already serving, so they would be deleting rows this run had
  // just minted.
  // ---------------------------------------------------------------------
  if (keystore.hasEphemeralKek()) {
    if (process.env.STS_REQUEST_WORKER) {
      log.debug('Leaving restore(). A request worker restores nothing; the ' +
                'front process cleared the table before this one started.');
      return Promise.resolve({ restored: 0 });
    }
    log.debug("Leaving restore().");
    return driver.purgeMinted(Date.now()).then(function (removed) {
      log.info('persistence: ' + (removed || 0) + ' minted row(s) from an ' +
               'earlier run were cleared. This run seals under a key of its ' +
               'own, so nothing it finds here is readable and nothing is ' +
               'restored.');
      return { restored: 0, cleared: removed || 0 };
    }).catch(function (e) {
      // NOT FATAL. Everything this run mints is written and shared regardless;
      // what is left behind is unreadable rows that retention collects by age.
      log.warn(errorCodes.tag('STS-STORE-0023') +
               'persistence: an earlier run\'s minted rows could not be ' +
               'cleared: ' + e.message + '. They are unreadable and will be ' +
               'swept by persistence.mintedRetention.');
      return { restored: 0, cleared: 0 };
    });
  }
  const filter = restoreFilter(Date.now());
  try {
    const sessionWindow = sessionWindowIfOn();
    if (sessionWindow &&
        filter.skipHandles.indexOf('authn.sessions') < 0) {
      filter.skipHandles.push('authn.sessions');
    }
  } catch (e) {
    log.debug("Caught in restore(): " + ((e && e.message) || e));
  }
  log.debug("Leaving restore().");
  // WHAT WAS MINTED BEFORE THE RESTORE (#357): journalled and not written —
  // before the keystore started a flush had nothing to seal with, and one
  // during the load is not guaranteed to have run. Taken aside the moment
  // `restoring` is set (nothing is journalled after that), kept across the
  // restore, which clears the journal of its own writes, and flushed after.
  //
  // **IN SLICES SINCE #613 (2026-10-13)**, `restoreInSlices()` below: a
  // request worker on 8081 restored ~48K rows in one synchronous loop, about
  // 4–5 s of its start, and `tests/tools/startup_profile.js` measures 48K
  // small rows at 0.6 s held in one piece. Writes made by anything else
  // while it yields are taken aside with `pending`, exactly as writes made
  // while the rows were being LOADED always were, and flushed after.
  let pending = null;
  const aside = [];
  return indexesComplete().then(function () {
    // AN ON-DEMAND STORE IS NOT READ BACK AT ALL (#820): its rows are read by
    // key when they are asked for, so a start restores none of them — once
    // its index, if it has one, is complete (see `demandLiveFor()`).
    realms.handles().forEach(function (declared) {
      if (demandLiveFor(declared.handle) &&
          filter.skipHandles.indexOf(declared.handle) < 0) {
        filter.skipHandles.push(declared.handle);
      }
    });
    return Promise.all([driver.loadMinted(filter),
                        loadResidentKeys(filter)]);
  }).then(function (loaded) {
    const rows = loaded[0];
    pending = takePendingJournal();
    let restored = 0;
    droppedUnreadable = 0;
    droppedUnknown = 0;
    const staleHandles = new Set();

    const skipped = new Set(filter.skipHandles || []);
    return restoreInSlices(rows || [], aside, function (row) {
      if (skipped.has(row.handle)) {
        return;
      }
      const store = realms.handleFor(row.handle);
      if (!store) {
        droppedUnknown++;
        staleHandles.add(row.handle);
        return;
      }
      const text = keystore.open(row.body, 'minted-rows');
      if (text === null) {
        droppedUnreadable++;
        return;
      }
      let value = null;
      try {
        value = JSON.parse(text);
      } catch (e) {
        log.debug("Caught in a callback in restore(): " +
                  ((e && e.message) || e));
        // A row that opened and is not JSON. It cannot have been written by
        // this service, because everything here is stringified before it is
        // sealed — so this is corruption, and it is counted with the rows that
        // would not open because the operator's question is the same one.
        droppedUnreadable++;
        return;
      }
      // THE NAME, opened (#222): `key` is its digest where it was sealed.
      const name = nameOfRow(row);
      if (name === null) {
        droppedUnreadable++;
        return;
      }
      const split = splitKey(store, name);
      // -------------------------------------------------------------------
      // ANOTHER PROCESS'S CONTRIBUTION TO AN ACCUMULATOR IS NOT RESTORED INTO
      // MEMORY, IT IS CONTRIBUTED.
      //
      // Restoring it would make this process's tally include another
      // process's, and the next flush would then write the combined number
      // back as this process's own contribution — so every restart would
      // multiply the counts. The audit ring is the same shape of wrong: this
      // process would re-report another's events as its own.
      //
      // A row that IS this process's own — same origin, which happens after a
      // restart, since the origin includes the start time only for uniqueness
      // across containers — never matches, so a restarted process starts its
      // contribution fresh and its previous life's row ages out under
      // retention. That is a real limitation and it is the reason
      // `persistence.mintedRetention` matters for the counters: a process
      // that restarts often leaves a contribution behind each time.
      // -------------------------------------------------------------------
      if (store.merge === 'own' && split.origin && split.origin !== origin) {
        replication.contribute(row.handle, row.realm, split.key,
                               split.origin, value);
        restored++;
        return;
      }
      try {
        store.restore(row.realm, split.key, value);
        restored++;
      } catch (e) {
        // A store that refuses a row it wrote. Logged with the handle, because
        // the shape of the record is that store's business and this file has
        // no way to say what was wrong with it.
        log.error(errorCodes.tag('STS-STORE-0024') +
                  'persistence: "' + row.handle + '" refused a restored row ' +
                  'under "' + row.key + '": ' + e.message);
        droppedUnreadable++;
      }
    }).then(function () {
      restoredRows = restored;
      restoredAt = new Date().toISOString();
      // THE JOURNAL IS CLEARED RATHER THAN TRUSTED. `restoring` suppressed
      // every note above, but a store may write during a restore for a reason
      // of its own — `realms.create()` fires every builder, and a builder that
      // seeds something writes — and those writes are already in the store.
      // What anything else wrote between slices is in `aside`, put back.
      journal.clear();
      flushAsked = false;
      let putBack = putBackJournal(pending);
      aside.forEach(function (one) {
        putBack = putBackJournal(one) || putBack;
      });
      if (putBack && scheduler) {
        flushAsked = scheduler() !== false;
      }

      if (staleHandles.size) {
        log.info('persistence: ' + droppedUnknown + ' minted row(s) belong ' +
                 'to handle(s) nothing in this build declares (' +
                 Array.from(staleHandles).join(', ') + '). They were left ' +
                 'alone rather than deleted: a row this build does not ' +
                 'understand is usually an older or newer build\'s, and ' +
                 'deleting it would make a downgrade lose state a downgrade ' +
                 'should not lose.');
      }
      log.info('persistence: ' + restored + ' minted row(s) restored across ' +
               realms.handles().length + ' declared store(s) and ' +
               filter.realms.length + ' realm partition(s)' +
               (skipped.size ? ' — a request worker reads none of ' +
                Array.from(skipped).join(', ') + ', which only the front ' +
                'process answers from' : '') +
               (droppedUnreadable ? ', ' + droppedUnreadable + ' unreadable ' +
                                    '(written under a different ' +
                                    'key-encryption key?)' : '') +
               '. Sessions, tokens, codes, artifacts, tickets, the replay ' +
               'caches and the audit log are as they were before the ' +
               'restart.');

      // The index of every indexed on-demand store still read back whole is
      // filed by a scheduler job, after the start (see the backfill above).
      // REGISTERED ON EVERY FRONT PROCESS WITH AN ON-DEMAND STORE, not only
      // where a backfill is owed (2026-10-27): a cluster job runs on the
      // LEADER, so a job one node alone registered never ran unless that
      // node led, and the nodes' job lists disagreed (sts_scheduler's page
      // and API read through the balancer). The run itself asks
      // `backfillOwed()` and does nothing when nothing is.
      if (!process.env.STS_REQUEST_WORKER && onDemandActive()) {
        ensureIndexBackfillJob();
      }
      log.debug('Leaving restore(). ' + restored + ' row(s).');
      return { restored: restored };
    });
  }).catch(function (err) {
    restoring = false;
    putBackJournal(pending);
    aside.forEach(function (one) {
      putBackJournal(one);
    });
    log.debug('Leaving restore(). It failed.');
    return Promise.reject(new Error(errorCodes.tag('STS-STORE-0026') +
      'the minted state in the store could not be read: ' + err.message));
  });
}

// ---------------------------------------------------------------------------
// STOPPING. Called from `persistence.stop()`, which `server.js` calls on
// SIGTERM and SIGINT — so the last few sessions and audit rows are written
// rather than lost. A `docker kill -9` is not trapped and cannot be; what that
// costs here is whatever was journalled and not yet flushed, which in postgres
// mode is one turn of the event loop.
// ---------------------------------------------------------------------------
/**
 * Writes what is journalled and stops journalling, for a clean shutdown.
 * @returns a promise of the last flush's answer
 */
function stop() {
  log.debug('Entering stop().');
  log.debug("Leaving stop().");
  return flush().then(function (result) {
    stopped = true;
    log.debug('Leaving stop().');
    return result;
  });
}

// What the console and the management API draw. ONE object through ONE
// function, so the page and the API cannot disagree about what is persisted —
// rule 7's shape applied to a report rather than to an action.
/**
 * Describes minted persistence for the console and the management API.
 * @returns whether it is on and supported, the declared stores, and the
 * counters of writes, failures, restored and dropped rows
 */
function status() {
  log.debug("Entering status().");
  const declared = realms.handles();
  log.debug("Leaving status().");
  return {
    persisting: enabled(),
    supported: supports(driver),
    unsupportedReason: unsupportedReason,
    sealed: keystore.sealed(),
    mode: mode.current(),
    setting: !!config.value('persistence.minted'),
    retentionMs: retentionMs(),
    stores: declared.length,
    shared:
      declared.filter(function (row) { return row.scope === 'shared'; }).length,
    handles: declared.map(function (row) {
      return { handle: row.handle, shape: row.shape, scope: row.scope };
    }),
    pending: journal.size,
    writes: writes,
    failures: failures,
    rowsWritten: rowsWritten,
    rowsDeleted: rowsDeleted,
    lastWriteAt: lastWriteAt,
    lastError: lastError,
    restoredAt: restoredAt,
    restored: restoredRows,
    droppedUnreadable: droppedUnreadable,
    droppedUnknown: droppedUnknown
  };
}

// ---------------------------------------------------------------------------
// FOR THE TESTS, AND FOR NOTHING ELSE — the same real cost `keystore.reset()`
// pays and the same reason it is paid: the alternative is a test that launches
// two processes and therefore cannot run in the in-process suite at all.
// ---------------------------------------------------------------------------
// Captured before a walk's first page. Null when this process did not walk.
// The follower starts here so a commit during the walk is still applied.
let sessionIndexFloor = null;

/**
 * Clears every piece of state in this module, for the tests.
 */
function reset() {
  log.debug("Entering reset().");
  journal.clear();
  scheduler = null;
  flushAsked = false;
  requeuing = false;
  driver = null;
  stopped = false;
  restoring = false;
  // A write left in flight by the previous test must not make the next one's
  // first flush wait on a driver that is no longer installed.
  flushInFlight = null;
  indexComplete.clear();
  indexBackfilled.clear();
  unheldAfterRefresh.clear();
  unheldWarned.clear();
  unheldWaits.clear();
  generation = 0;
  observedGeneration = 0;
  observational.clear();
  committedAt = 0;
  failedWrite = false;
  inFlightTakenAt = 0;
  lastWriteAt = null;
  lastError = '';
  writes = 0;
  failures = 0;
  rowsWritten = 0;
  rowsDeleted = 0;
  restoredAt = null;
  restoredRows = 0;
  droppedUnreadable = 0;
  droppedUnknown = 0;
  unsupportedReason = '';
  realmOnlyKeylessWarned = false;
  expiryHookFailed.clear();
  sessionIndexFloor = null;
  log.debug("Leaving reset().");
}

// How many sealed bodies one backfill transaction opens. The ceiling: a
// start that cannot finish a page of this size is the upgrade, not a
// smaller page.
const SESSION_INDEX_BATCH = 500;

function sessionIndexChangeFloor() {
  log.debug("Entering sessionIndexChangeFloor().");
  log.debug("Leaving sessionIndexChangeFloor().");
  return sessionIndexFloor;
}

// Fills `sts_sessions` from sealed `authn.sessions` rows until the completion
// row commits with the last page (#350). A non-empty table is not that mark:
// another node may already have written a live row, and deleting would throw
// that row away. A throw leaves the mark unwritten, so the next start walks
// again. Upserts are idempotent. SQL cannot open the bodies. Expired rows
// are included; a tombstone is the only absence.
function backfillSessionIndex() {
  log.debug("Entering backfillSessionIndex().");
  const active = /** @type {any} */ (driver);
  if (!enabled() || !active ||
      typeof active.sessionIndexDone !== 'function' ||
      typeof active.loadSessionBodies !== 'function' ||
      typeof active.writeSessionIndexes !== 'function') {
    log.debug("Leaving backfillSessionIndex(). Not this store.");
    return Promise.resolve();
  }
  const row = realms.handleFor('authn.sessions');
  if (!row || typeof row.indexOf !== 'function') {
    log.debug("Leaving backfillSessionIndex(). No index hook.");
    return Promise.resolve();
  }
  // Probed once. A null digest writes no row, and asking whether the walk
  // finished would hide that the next start must try again.
  if (typeof keystore.keyedDigest !== 'function' ||
      !keystore.keyedDigest('session-subject', '')) {
    log.debug("Leaving backfillSessionIndex(). No digest.");
    return Promise.resolve();
  }
  // True once a page has committed. The mark itself commits only with the
  // last page, so a throw after this still resumes.
  let committed = false;
  function mark(err) {
    log.debug("Entering mark().");
    log.debug("Caught in mark(): " + ((err && err.message) || err));
    if (committed && err && typeof err === 'object') {
      err.sessionIndexCommitted = true;
    }
    log.debug("Leaving mark().");
    throw err;
  }
  // Every body in the page is opened before that page's transaction, so one
  // that will not open throws before the batch commits. A live body with no
  // columns is the same failure: skipping it would leave a hole the mark
  // would then call finished.
  function fillFrom(afterRealm, afterKey) {
    log.debug("Entering fillFrom().");
    log.debug("Leaving fillFrom().");
    return Promise.resolve(active.loadSessionBodies(afterRealm, afterKey,
                                                    SESSION_INDEX_BATCH))
      .then(function (page) {
        const rows = page || [];
        const ready = [];
        for (let i = 0; i < rows.length; i++) {
          const one = rows[i];
          const text = keystore.open(one.body, 'minted-rows');
          if (text == null) {
            throw new Error('a stored session body will not open');
          }
          let value;
          try {
            value = JSON.parse(text);
          } catch (e) {
            log.debug("Caught in a callback in fillFrom(): " +
                      ((e && e.message) || e));
            throw e;
          }
          const columns = indexColumns(row, value);
          if (!columns) {
            throw new Error('a stored session body has no index columns');
          }
          ready.push({ realm: one.realm, key: one.key, body: one.body,
                       index: columns });
        }
        const last = rows.length < SESSION_INDEX_BATCH;
        const writing = (ready.length || last)
          ? active.writeSessionIndexes(ready, last) : Promise.resolve();
        return Promise.resolve(writing).then(function () {
          if (last) {
            return null;
          }
          committed = true;
          const tail = rows[rows.length - 1];
          return fillFrom(tail.realm, tail.key);
        });
      });
  }
  log.debug("Leaving backfillSessionIndex().");
  return Promise.resolve(active.sessionIndexDone()).then(function (done) {
    if (done) {
      return null;
    }
    // Sampled before the first page, so a commit during the walk stays
    // above the follower. Published only after the walk returns: the last
    // transaction has then deleted index rows whose body is gone, and a
    // resume's fresh head is not a floor while those rows remain (#350).
    const seq = typeof active.latestChangeSeq === 'function'
      ? active.latestChangeSeq() : null;
    return Promise.resolve(seq).then(function (n) {
      let sampled = null;
      if (seq !== null) {
        const parsed = Number(n);
        sampled = Number.isFinite(parsed) ? parsed : 0;
      }
      return fillFrom('', '').then(function () {
        if (sampled !== null) {
          sessionIndexFloor = sampled;
        }
        return null;
      });
    });
  }).catch(mark);
}

/**
 * Persistence of what this process minted — sessions, tokens, codes, replay
 * caches, statistics and the audit log.
 *
 * In product mode, or where several processes or nodes must agree, each
 * declared store's writes are journalled and flushed sealed under the
 * key-encryption key; in development mode nothing minted is persisted.
 * @namespace
 */
module.exports = {
  // The key column a name is filed under, and a stored row's name (#222):
  // for the tests, which look rows up by the name they wrote.
  keyColumnOf: keyColumnOf,
  // The on-demand reader's two synchronous doors and the bridge they ask,
  // for the tests (#1001): a per-origin store's rows are named with their
  // origin, and that is asserted against a stand-in bridge.
  onDemandRead: onDemandRead,
  onDemandByIndex: onDemandByIndex,
  setDemandBridge: function (bridge) {
    log.debug("Entering setDemandBridge().");
    demandBridge = bridge || null;
    log.debug("Leaving setDemandBridge().");
  },
  journalled: journalled,
  nameOfRow: nameOfRow,
  backfillSessionIndex: backfillSessionIndex,
  backfillMintedIndexes: backfillMintedIndexes,
  ensureIndexBackfillJob: ensureIndexBackfillJob,
  sessionIndexChangeFloor: sessionIndexChangeFloor,
  ensureTombstoneJob: ensureTombstoneJob,
  ensureExpiryPurgeJob: ensureExpiryPurgeJob,
  purgeExpired: purgeExpired,
  restoreFilter: restoreFilter,
  setDriver: setDriver,
  setScheduler: setScheduler,
  applyChange: applyChange,
  prefetch: prefetch,
  endPrefetch: endPrefetch,
  prefetchedRow: prefetchedRow,
  supports: supports,
  enabled: enabled,
  dirty: dirty,
  flush: flush,
  flushThrough: flushThrough,
  failing: failing,
  generation: generationNow,
  observedGeneration: observedGenerationNow,
  committedGeneration: committedGeneration,
  restore: restore,
  stop: stop,
  status: status,
  reset: reset
};
