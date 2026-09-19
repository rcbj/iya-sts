// @ts-check
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
// THE FAN-IN FOR `merge: 'own'` STORES. A LIBRARY, like this one, and required
// in the ordinary direction: it does not require this file back.
const replication = require('./persistence_replication');
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
function storedKey(row, key) {
  log.debug("Entering storedKey().");
  if (row.merge !== 'own') {
    log.debug("Leaving storedKey().");
    return key;
  }
  log.debug("Leaving storedKey().");
  return Buffer.from(String(key), 'utf8').toString('base64url') + '.' +
         Buffer.from(String(origin), 'utf8').toString('base64url');
}

// The journal: handle -> realm -> Set of keys. Nested rather than a flat set of
// composite strings because the flush walks it handle-first (a handle is what
// finds the store) and because a composite key would have to be split back
// apart with a separator no key may contain — and a session id may contain
// anything.
const journal = new Map();

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
let droppedStale = 0;
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
  const count = Number(config.value('workers.requestCount')) || 0;
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
  log.debug('Leaving setDriver(). ' + realms.handles().length +
            ' declared store(s).');
  return true;
}

// ---------------------------------------------------------------------------
// THE JOURNAL DOOR. This is `realms.js`'s persist observer, and it is called
// from inside `sessions.set()` — which is inside a sign-in — so it does the
// least it can: two Map lookups and a Set insert, no settings read, no
// allocation past the first write to a store.
//
// **IT DOES NOT CHECK `enabled()`.** That is deliberate and it is the one
// non-obvious thing in this file. `enabled()` reads three settings, and this
// runs on the hot path of every store in the service; instead the observer is
// only ARMED at all when a driver that can hold minted state was opened, and
// the flush is where the mode and the setting are consulted. The cost of being
// wrong that way round is a Set that fills and is discarded, which is nothing;
// the cost of the other way round is three config reads per session write.
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
  keys.add(key === null || key === undefined ? '' : String(key));
  generation += 1;
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

function prefetch(changes) {
  log.debug("Entering prefetch().");
  prefetched = null;
  if (!driver || typeof driver.readMintedMany !== 'function') {
    log.debug("Leaving prefetch().");
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
    refs.push({ handle: parsed.handle, realm: change.realm,
                key: parsed.storedName });
  });
  if (!refs.length) {
    log.debug("Leaving prefetch().");
    return Promise.resolve(0);
  }
  log.debug("Leaving prefetch().");
  return driver.readMintedMany(refs).then(function (rows) {
    const map = new Map();
    (rows || []).forEach(function (row) {
      map.set(row.handle + '\u0000' + row.realm + '\u0000' + row.key, row);
    });
    // EVERY REF IS RECORDED, including the ones that came back with nothing:
    // "asked for and absent" is a real answer — it is what a DELETE looks like
    // — and without it the applier would fall back to a query per missing row,
    // which is the case a page of deletes is made entirely of.
    refs.forEach(function (ref) {
      const id = ref.handle + '\u0000' + ref.realm + '\u0000' + ref.key;
      if (!map.has(id)) {
        map.set(id, null);
      }
    });
    prefetched = map;
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

function endPrefetch() {
  log.debug("Entering endPrefetch().");
  prefetched = null;
  log.debug("Leaving endPrefetch().");
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
    return {
      handle: Buffer.from(text.slice(0, at), 'base64url').toString('utf8'),
      storedName: Buffer.from(text.slice(at + 1), 'base64url').toString('utf8')
    };
  } catch (e) {
    log.debug("Caught in splitChangeKey(): " + ((e && e.message) || e));
    log.debug("Leaving splitChangeKey().");
    return null;
  }
}

function applyChange(change) {
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
    storedName = Buffer.from(text.slice(at + 1), 'base64url').toString('utf8');
  } catch (e) {
    log.debug("Caught in applyChange(): " + ((e && e.message) || e));
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

  // THE PAGE'S PREFETCH FIRST — see prefetch() above. A miss here is a real
  // "not there", recorded as null, and only an ABSENT entry means this row was
  // not in the page and has to be read on its own.
  const held = prefetched
    ? prefetched.get(handle + '\u0000' + change.realm + '\u0000' + storedName)
    : undefined;
  const reading = held === undefined
    ? driver.readMinted(handle, change.realm, storedName)
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
        return applyLocally(store, change.realm, split.key, undefined, true);
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
      return applyLocally(store, change.realm, split.key, value, false);
    });
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
    if (remove) {
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
    store.restore(realmId, key, value);
    log.debug("Leaving applyLocally().");
    return true;
  } finally {
    restoring = was;
  }
}

// Is there anything to write? `persistence.js` asks before scheduling.
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
        const present = row.read(realmId, key);
        if (!present || !present.present) {
          deletes.push({ handle: handle, realm: realmId,
                         key: storedKey(row, key),
                         // The key as the STORE knows it, for the retry — see
                         // the catch below.
                         journalKey: key,
                         own: row.merge === 'own',
                         // An ENDED key leaves a tombstone. See
                         // ENDED ROWS below.
                         tombstone: row.tombstone === true });
          return;
        }
        let body = null;
        try {
          body = keystore.seal(JSON.stringify(present.value), 'minted-rows');
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
        upserts.push({ handle: handle, realm: realmId,
                       key: storedKey(row, key), journalKey: key, body: body,
                       // WHETHER A READER HAS TO WAIT FOR THIS ROW. An `own`
                       // store is per-process fan-in — every process keeps its
                       // own contribution and the console SUMS them when
                       // somebody asks — so another worker does not need it
                       // applied before it can answer. See the driver's
                       // recordChanges() and replication's syncNow().
                       own: row.merge === 'own',
                       tombstone: row.tombstone === true,
                       merge: row.mergeRow
                         ? mergerFor(row, handle, key, present.value)
                         : undefined });
      });
    });
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
  const saving = driver.saveMinted(upserts, deletes).then(function (result) {
    committedAt = Math.max(committedAt, takenAt);
    settleDecided(result);
    maybePurgeTombstones();
    writes++;
    rowsWritten += upserts.length;
    rowsDeleted += deletes.length;
    lastWriteAt = new Date().toISOString();
    lastError = '';
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
    log.error(errorCodes.tag('STS-STORE-0021') +
              'persistence: minted state could not be written: ' + err.message +
              '. The service is unaffected and is still answering from ' +
              'memory; the next change will try again.');
    log.debug('Leaving flush(). It failed.');
    return { written: false, error: err.message };
  });
  // CLEARED BEFORE THE RESULT IS HANDED ON, so that a caller waiting on this
  // promise finds nothing in flight when it re-enters. Cleared on either path:
  // a handler above that threw must not leave every later flush waiting on a
  // write that is over. Only if it is still THIS flush — `reset()` may have
  // started a new life for the module while this one was out.
  const settled = saving.then(function (result) {
    if (flushInFlight === settled) {
      flushInFlight = null;
    }
    return result;
  }, function (err) {
    log.debug("Caught in flush(): " + ((err && err.message) || err));
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
function generationNow() {
  log.debug("Entering generationNow().");
  log.debug("Leaving generationNow().");
  return generation;
}

// The part of `generation` that was observations. See `observedGeneration`.
function observedGenerationNow() {
  log.debug("Entering observedGenerationNow().");
  log.debug("Leaving observedGenerationNow().");
  return observedGeneration;
}

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
// back — through `maybePurgeTombstones()`. 0 keeps them with everything else.
// ---------------------------------------------------------------------------
function mergerFor(row, handle, key, mine) {
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
      return keystore.seal(JSON.stringify(merged), 'minted-rows');
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
let lastTombstoneSweep = 0;

function maybePurgeTombstones() {
  log.debug("Entering maybePurgeTombstones().");
  const now = Date.now();
  if (!driver || typeof driver.purgeTombstones !== 'function' ||
      !retentionMs() || now - lastTombstoneSweep < TOMBSTONE_SWEEP_MS) {
    log.debug("Leaving maybePurgeTombstones(). Not due.");
    return;
  }
  lastTombstoneSweep = now;
  Promise.resolve().then(function () {
    return driver.purgeTombstones(now - retentionMs());
  }).then(function (removed) {
    if (removed) {
      log.info('persistence: ' + removed + ' expired tombstone(s) of ended ' +
               'minted rows swept.');
    }
  }).catch(function (e) {
    log.warn(errorCodes.tag('STS-STORE-0055') + 'persistence: sweeping ' +
             'expired tombstones failed: ' + ((e && e.message) || e) + '.');
  });
  log.debug("Leaving maybePurgeTombstones(). Started.");
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
// Three kinds of row are dropped and each is counted separately, because they
// mean completely different things to somebody reading the startup line:
//
//   * STALE — older than `persistence.mintedRetention`. Ordinary.
//   * UNREADABLE — will not open under the current key-encryption key, which
//     is what rotating one does to every row written under the old one.
//     Ordinary after a rotation, alarming otherwise.
//   * UNKNOWN — a handle no store in this build declares, which is what an
//     older or newer build's rows look like. Harmless and worth saying.
// ---------------------------------------------------------------------------
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

  const cutoff = retentionMs() ? Date.now() - retentionMs() : 0;
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
  log.debug("Leaving restore().");
  return driver.loadMinted().then(function (rows) {
    restoring = true;
    let restored = 0;
    droppedStale = 0;
    droppedUnreadable = 0;
    droppedUnknown = 0;
    const staleHandles = new Set();

    (rows || []).forEach(function (row) {
      if (cutoff && Number(row.writtenAt || 0) &&
          Number(row.writtenAt) < cutoff) {
        droppedStale++;
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
      const split = splitKey(store, row.key);
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
    });

    restoring = false;
    restoredRows = restored;
    restoredAt = new Date().toISOString();
    // THE JOURNAL IS CLEARED RATHER THAN TRUSTED. `restoring` suppressed every
    // note above, but a store may write during a restore for a reason of its
    // own — `realms.create()` fires every builder, and a builder that seeds
    // something writes — and those writes are already in the store.
    journal.clear();
    flushAsked = false;

    if (staleHandles.size) {
      log.info('persistence: ' + droppedUnknown + ' minted row(s) belong to ' +
               'handle(s) nothing in this build declares (' +
               Array.from(staleHandles).join(', ') + '). They were left ' +
               'alone rather than deleted: a row this build does not ' +
               'understand is usually an older or newer build\'s, and ' +
               'deleting it would make a downgrade lose state a downgrade ' +
               'should not lose.');
    }
    log.info('persistence: ' + restored + ' minted row(s) restored across ' +
             realms.handles().length + ' declared store(s)' +
             (droppedStale ? ', ' + droppedStale + ' dropped as older than ' +
                             'persistence.mintedRetention' : '') +
             (droppedUnreadable ? ', ' + droppedUnreadable + ' unreadable ' +
                                  '(written under a different key-encryption ' +
                                  'key?)' : '') + '. Sessions, tokens, ' +
             'codes, artifacts, tickets, the replay caches and the audit log ' +
             'are as they were before the restart.');

    // WHAT THE RETENTION DROPPED IS DELETED, not merely skipped. Skipping
    // alone would leave every row this service has ever written in the table
    // for ever, and the next start would read them all again to skip them
    // again. Best-effort: a purge that fails is logged and the service starts.
    if (cutoff && droppedStale && typeof driver.purgeMinted === 'function') {
      return driver.purgeMinted(cutoff).then(function (removed) {
        log.info('persistence: ' + removed + ' stale minted row(s) removed ' +
                 'from the store.');
        return { restored: restored };
      }).catch(function (err) {
        log.warn(errorCodes.tag('STS-STORE-0025') +
                 'persistence: the stale minted rows could not be removed: ' +
                 err.message + '. They are skipped on every start until they ' +
                 'can be.');
        return { restored: restored };
      });
    }
    log.debug('Leaving restore(). ' + restored + ' row(s).');
    return { restored: restored };
  }).catch(function (err) {
    restoring = false;
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
    droppedStale: droppedStale,
    droppedUnreadable: droppedUnreadable,
    droppedUnknown: droppedUnknown
  };
}

// ---------------------------------------------------------------------------
// FOR THE TESTS, AND FOR NOTHING ELSE — the same real cost `keystore.reset()`
// pays and the same reason it is paid: the alternative is a test that launches
// two processes and therefore cannot run in the in-process suite at all.
// ---------------------------------------------------------------------------
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
  generation = 0;
  observedGeneration = 0;
  observational.clear();
  committedAt = 0;
  inFlightTakenAt = 0;
  lastTombstoneSweep = 0;
  lastWriteAt = null;
  lastError = '';
  writes = 0;
  failures = 0;
  rowsWritten = 0;
  rowsDeleted = 0;
  restoredAt = null;
  restoredRows = 0;
  droppedStale = 0;
  droppedUnreadable = 0;
  droppedUnknown = 0;
  unsupportedReason = '';
  realmOnlyKeylessWarned = false;
  log.debug("Leaving reset().");
}

module.exports = {
  setDriver: setDriver,
  setScheduler: setScheduler,
  applyChange: applyChange,
  prefetch: prefetch,
  endPrefetch: endPrefetch,
  supports: supports,
  enabled: enabled,
  dirty: dirty,
  flush: flush,
  flushThrough: flushThrough,
  generation: generationNow,
  observedGeneration: observedGenerationNow,
  committedGeneration: committedGeneration,
  restore: restore,
  stop: stop,
  status: status,
  reset: reset
};
