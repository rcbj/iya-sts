// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: audit_store.js
// ---------------------------------------------------------------------------
// THE AUDIT LOG IN ITS OWN TABLE, APPEND-ONLY (#1616, ASVS 5.0.0 16.4.2).
//
// Until #1616 the audit ring was `realms.arr({ persist: 'audit.events' })`,
// sealed segments of 32 events in `sts_minted`, each rewritten in place on
// every push and deleted when it left the ring — so the role holding the
// service's database credential could rewrite or delete audit rows, and the
// keyed chain only said that it had. Now every event is ONE sealed row in
// `sts_audit`, where that role holds INSERT and SELECT and nothing else,
// and rows leave through the owner's two SECURITY DEFINER functions only
// (`postgres/schema.sql`, `mariadb/schema.sql`). rcbj's decisions are on the
// ticket; the four that shape this file:
//
//   * **SEALED PER ROW** under the realm's data key, label `minted-rows` —
//     the label the segments had, so the data-key class is unchanged.
//     `realm`, `origin`, `seq` and `at` are plain columns: retention and
//     ordering are the database's.
//   * **RETENTION IS A CLUSTER SCHEDULER JOB** (`audit.retain`) calling the
//     owner's function, which keeps at least 1000 rows whatever it is asked.
//     The reader caps what it shows at `audit.maxEvents`, so the log a page
//     draws is bounded between runs.
//   * **THE OLD SEGMENTS ARE COPIED IN AT THE FIRST START**, each event with
//     its chain checksums, and then removed (`audit.js`'s `migrateLegacy()`).
//     Idempotent, and asked at EVERY start of the front process: an INSERT
//     meeting its own row does nothing, so a node still on 1.1 during a
//     rolling upgrade has its segments copied at the next start.
//   * **A ROW IS NEVER RE-SEALED.** Data-key rotation re-seals `sts_minted`
//     with UPDATE; this table refuses that, so a retired data key is kept
//     while an audit row still names it (common/keystore.js) and goes when
//     retention has aged those rows out.
//
// WHEN IT IS ACTIVE: wherever minted state persists (`persistence_minted`'s
// `enabled()`), on a driver with the `audit*` methods, whose store holds the
// table. Elsewhere — memory, an LDIF store, a development process — the
// ring is the process's own, in memory, as it always was there.
//
// WRITES ARE BATCHED PER BURST: `append()` queues, and one INSERT a turn
// later carries every row queued since (a debounce, which the scheduler
// rule permits). A failed INSERT keeps the rows for the next, to a bound,
// and says so once per burst (STS-AUDIT-0018). `flush()` is also what a
// test or a stopping process awaits.
//
// A LIBRARY (rule 3): it registers no route. `persistence.js` hands it the
// driver, `common/service_state.ts` starts it after the minted restore, and
// `common/audit.js` writes and reads through it, requiring it lazily.
// ---------------------------------------------------------------------------

// A logger of this file's own, as every module of this directory has:
// `common/helpers.js` is not required from here, which would close a cycle
// through the persistence layer it loads.
const bunyan = require('bunyan');
const log = bunyan.createLogger({ name: 'sts-audit-store',
  level: process.env.STS_LOG_LEVEL || process.env.LOG_LEVEL || 'info' });
const errorCodes = require('../common/error_codes');

// The rows a failing store may hold for its next try, per process: past it
// the oldest are let go, counted, and said (STS-AUDIT-0018).
const MAX_PENDING = 20000;

// The label the rows are sealed under: the segments', so the DEK class is
// the one they always used.
const LABEL = 'minted-rows';

// The handle the segments had in `sts_minted`, which the copy reads and
// then clears.
const LEGACY_HANDLE = 'audit.events';

let driver = null;
let probed = null;
let pending = [];
let flushing = null;
let scheduled = false;
let droppedPending = 0;

/**
 * Hands over the open driver; a driver without the `audit*` methods (memory,
 * LDIF) leaves the store inactive.
 *
 * @param theDriver - the persistence driver, or null
 */
function setDriver(theDriver) {
  log.debug("Entering audit_store.setDriver().");
  driver = theDriver && typeof theDriver.auditInsert === 'function'
    ? theDriver : null;
  probed = null;
  log.debug("Leaving audit_store.setDriver(). " + !!driver);
}

/**
 * Whether events are written to `sts_audit` now.
 *
 * @returns true where minted state persists, on a driver and store that
 *   hold the table
 */
function active() {
  log.debug("Entering audit_store.active().");
  let persisting = false;
  try {
    persisting = !!driver &&
      require('./persistence_minted').enabled() === true;
  } catch (e) {
    log.debug("Caught in audit_store.active(): " + ((e && e.message) || e));
    // No minted persistence loaded (a test of one module): not persisting.
    persisting = false;
  }
  const out = persisting && !(probed && probed.present === false);
  log.debug("Leaving audit_store.active(). " + out);
  return out;
}

/**
 * Queues one event for `sts_audit`; written a turn later with the rest.
 *
 * @param realmId - the realm it was recorded in
 * @param row - the audit row, its chain checksums on it
 * @returns true when it was queued
 */
function append(realmId, row) {
  log.debug("Entering audit_store.append().");
  if (!active()) {
    log.debug("Leaving audit_store.append(). Not active.");
    return false;
  }
  pending.push({ realm: String(realmId || 'default'), row: row });
  if (pending.length > MAX_PENDING) {
    const over = pending.length - MAX_PENDING;
    pending.splice(0, over);
    droppedPending += over;
  }
  if (!scheduled) {
    scheduled = true;
    // A DEBOUNCE, not a repeating timer: one INSERT per burst of events.
    setImmediate(function () {
      scheduled = false;
      flush().catch(function (e) {
        log.debug("Caught in audit_store.append(): " +
                  ((e && e.message) || e));
      });
    });
  }
  log.debug("Leaving audit_store.append().");
  return true;
}

// The sealed form of one row, or null when it cannot be sealed (no key):
// then it is not written, as an unsealable minted row is not.
function sealed(item) {
  log.debug("Entering audit_store.sealed().");
  const keystore = require('../common/keystore');
  const body = keystore.seal(JSON.stringify(item.row), LABEL, 'cell',
                             { realm: item.realm });
  log.debug("Leaving audit_store.sealed(). " + !!body);
  return body ? { realm: item.realm, origin: String(item.row.origin || ''),
                  seq: Number(item.row.seq), at: Number(item.row.at),
                  body: body } : null;
}

/**
 * Writes every queued row; resolves when it has been tried. Never rejects.
 *
 * @returns the count written
 */
function flush() {
  log.debug("Entering audit_store.flush().");
  if (flushing) {
    log.debug("Leaving audit_store.flush(). One is running; after it.");
    return flushing.then(function () {
      return pending.length ? flush() : 0;
    });
  }
  if (!pending.length || !driver) {
    log.debug("Leaving audit_store.flush(). Nothing.");
    return Promise.resolve(0);
  }
  const batch = pending;
  pending = [];
  const rows = batch.map(sealed).filter(Boolean);
  log.debug("Leaving audit_store.flush(). " + rows.length + " row(s).");
  flushing = Promise.resolve(driver.auditInsert(rows)).then(function (n) {
    flushing = null;
    if (droppedPending) {
      log.warn(errorCodes.tag('STS-AUDIT-0018') + 'audit: ' + droppedPending +
               ' event(s) were let go before they reached sts_audit, ' +
               'because the store refused writes for longer than ' +
               MAX_PENDING + ' events.');
      droppedPending = 0;
    }
    return n;
  }, function (err) {
    flushing = null;
    // KEPT FOR THE NEXT TRY, ahead of what arrived meanwhile, to the bound.
    pending = batch.concat(pending);
    if (pending.length > MAX_PENDING) {
      droppedPending += pending.length - MAX_PENDING;
      pending.splice(0, pending.length - MAX_PENDING);
    }
    log.warn(errorCodes.tag('STS-AUDIT-0018') + 'audit: ' + batch.length +
             ' event(s) could not be written to sts_audit and are kept for ' +
             'the next try: ' + ((err && err.message) || err));
    return 0;
  });
  return flushing;
}

// One stored row opened, or null when it will not open — a row sealed
// under an ephemeral development key, or under a data key this process does
// not hold: skipped, as the ring skipped what it could not read.
function opened(stored) {
  log.debug("Entering audit_store.opened().");
  const keystore = require('../common/keystore');
  let row = null;
  try {
    const text = keystore.open(stored.body, LABEL);
    row = text ? JSON.parse(text) : null;
  } catch (e) {
    log.debug("Caught in audit_store.opened(): " + ((e && e.message) || e));
    row = null;
  }
  log.debug("Leaving audit_store.opened(). " + !!row);
  return row;
}

/**
 * A realm's newest events, newest first, opened; rows that will not open are
 * left out. `origin`, when given, narrows to one process's.
 *
 * @param realmId - the realm
 * @param limit - how many
 * @param origin - optional: one process's origin
 * @returns a promise of the rows
 */
function newest(realmId, limit, origin) {
  log.debug("Entering audit_store.newest(). realm=" + realmId);
  if (!active()) {
    log.debug("Leaving audit_store.newest(). Not active.");
    return Promise.resolve(null);
  }
  log.debug("Leaving audit_store.newest().");
  return Promise.resolve(driver.auditNewest(String(realmId || 'default'),
    Math.max(1, Number(limit) || 1), origin === undefined ? undefined
      : String(origin)))
    .then(function (rows) {
      return (rows || []).map(opened).filter(Boolean);
    });
}

/**
 * Retention for one realm, through the owner's function (at least 1000 rows
 * are kept whatever `keep` says).
 *
 * @param realmId - the realm
 * @param keep - its `audit.maxEvents`
 * @returns a promise of the count removed, or null where not active
 */
function retain(realmId, keep) {
  log.debug("Entering audit_store.retain(). realm=" + realmId);
  if (!active()) {
    log.debug("Leaving audit_store.retain(). Not active.");
    return Promise.resolve(null);
  }
  log.debug("Leaving audit_store.retain().");
  return Promise.resolve(driver.auditRetain(String(realmId || 'default'),
                                            Number(keep) || 0));
}

/**
 * A removed realm's rows, through the owner's function, which deletes
 * nothing of a live realm or the default one.
 *
 * @param realmId - the realm
 * @returns a promise of the count removed, or null where not active
 */
function purgeRealm(realmId) {
  log.debug("Entering audit_store.purgeRealm(). realm=" + realmId);
  if (!driver || typeof driver.auditPurgeRealm !== 'function') {
    log.debug("Leaving audit_store.purgeRealm(). No driver.");
    return Promise.resolve(null);
  }
  log.debug("Leaving audit_store.purgeRealm().");
  return Promise.resolve(driver.auditPurgeRealm(String(realmId)));
}

/**
 * What the store says of the table: whether it is there, its functions, and
 * whether THIS role could change a row (decision 7: it keeps running, and
 * `/admin/mode` and STS-AUDIT-0019 say so). Cached; `refresh` asks again.
 *
 * @param refresh - ask the store again
 * @returns a promise of `{ present, functions, writable }`, or null with no
 *   driver
 */
function privileges(refresh) {
  log.debug("Entering audit_store.privileges().");
  if (!driver || typeof driver.auditPrivileges !== 'function') {
    log.debug("Leaving audit_store.privileges(). No driver.");
    return Promise.resolve(null);
  }
  if (probed && !refresh) {
    log.debug("Leaving audit_store.privileges(). Cached.");
    return Promise.resolve(probed);
  }
  log.debug("Leaving audit_store.privileges().");
  return Promise.resolve(driver.auditPrivileges()).then(function (p) {
    probed = p || null;
    return probed;
  });
}

/**
 * The last privilege probe's answer, synchronously, for `/admin/mode`.
 *
 * @returns `{ present, functions, writable }` or null before a probe
 */
function lastProbe() {
  log.debug("Entering audit_store.lastProbe().");
  log.debug("Leaving audit_store.lastProbe().");
  return probed;
}

/**
 * The legacy handle the old segments were written under.
 *
 * @returns 'audit.events'
 */
function legacyHandle() {
  log.debug("Entering audit_store.legacyHandle().");
  log.debug("Leaving audit_store.legacyHandle().");
  return LEGACY_HANDLE;
}

/**
 * Writes rows already shaped as audit rows (the copy of the old ring),
 * sealed one by one; resolves the count written.
 *
 * @param realmId - their realm
 * @param rows - audit rows, each with its own `origin`, `seq`, `at`, chain
 * @returns a promise of the count
 */
function insertRows(realmId, rows) {
  log.debug("Entering audit_store.insertRows(). " + rows.length);
  if (!active() || !rows.length) {
    log.debug("Leaving audit_store.insertRows(). Nothing.");
    return Promise.resolve(0);
  }
  const sealedRows = rows.map(function (row) {
    return sealed({ realm: String(realmId || 'default'), row: row });
  }).filter(Boolean);
  log.debug("Leaving audit_store.insertRows().");
  return Promise.resolve(driver.auditInsert(sealedRows));
}

/**
 * Removes the old ring's segments from `sts_minted` once they are copied.
 *
 * @returns a promise of the count removed
 */
function dropLegacy() {
  log.debug("Entering audit_store.dropLegacy().");
  if (!driver || typeof driver.auditDropLegacy !== 'function') {
    log.debug("Leaving audit_store.dropLegacy(). No driver.");
    return Promise.resolve(0);
  }
  log.debug("Leaving audit_store.dropLegacy().");
  return Promise.resolve(driver.auditDropLegacy(LEGACY_HANDLE));
}

// THE RETENTION JOB (#1616): one cluster job for the service, every ten
// minutes. For each live realm it asks the owner's function to remove what
// is past that realm's `audit.maxEvents` (it keeps at least 1000); for each
// realm the table holds rows of and the service no longer has, it asks the
// owner's other function, which deletes only where the realm is gone from
// `sts_realms` or retiring and never the default realm's (rcbj's decision
// 9). A cluster job because the table is shared: one node's run is every
// node's. A realm removed does not wait for this: nothing here reads its
// rows, and the next run takes them.
const RETAIN_JOB = 'audit.retain';

/**
 * One retention run: every live realm trimmed to its `audit.maxEvents` (at
 * least 1000 kept), and every removed realm's rows purged.
 *
 * @returns a promise of `{ realms, removed, purged }`
 */
function runRetention() {
  log.debug("Entering audit_store.runRetention().");
  const realms = require('../common/realms');
  const config = require('../common/config');
  const out = { realms: 0, removed: 0, purged: [] };
  const live = realms.list();
  const liveIds = new Set(live.map(function (realm) {
    return String(realm.id);
  }));
  log.debug("Leaving audit_store.runRetention().");
  return live.reduce(function (chain, realm) {
    return chain.then(function () {
      return realms.run(realm, function () {
        const keep = Number(config.value('audit.maxEvents')) || 0;
        return retain(realm.id, keep).then(function (gone) {
          out.realms++;
          out.removed += Number(gone) || 0;
        });
      });
    });
  }, Promise.resolve()).then(function () {
    if (!driver || typeof driver.auditRealms !== 'function') {
      return [];
    }
    return driver.auditRealms();
  }).then(function (held) {
    const gone = (held || []).filter(function (id) {
      return !liveIds.has(String(id));
    });
    return gone.reduce(function (chain, id) {
      return chain.then(function () {
        return purgeRealm(id).then(function () {
          out.purged.push(id);
        });
      });
    }, Promise.resolve());
  }).then(function () {
    return out;
  }, function (err) {
    log.warn(errorCodes.tag('STS-AUDIT-0021') + 'audit: retention failed: ' +
             ((err && err.message) || err));
    throw err;
  });
}

/**
 * Registers `audit.retain` with the scheduler, once per process.
 *
 * @returns true when it was registered
 */
function registerJobs() {
  log.debug("Entering audit_store.registerJobs().");
  let scheduler = null;
  try {
    scheduler = require('../cluster/scheduler');
  } catch (e) {
    log.debug("Caught in audit_store.registerJobs(): " +
              ((e && e.message) || e));
    scheduler = null;
  }
  if (!scheduler || typeof scheduler.register !== 'function' ||
      scheduler.job(RETAIN_JOB)) {
    log.debug("Leaving audit_store.registerJobs(). Nothing to do.");
    return false;
  }
  scheduler.register({
    id: RETAIN_JOB,
    title: 'Audit log retention',
    describe: 'For each realm: removes the audit events in sts_audit past ' +
      'the newest audit.maxEvents, through the table owner\'s function, ' +
      'which keeps at least 1000 whatever it is asked. The service\'s own ' +
      'database role cannot delete audit rows (ASVS 5.0.0 16.4.2).',
    owner: 'persistence/audit_store.js',
    kind: 'cluster',
    scope: 'service',
    everyMs: function () {
      return 10 * 60 * 1000;
    },
    manual: true,
    timeoutS: 120,
    off: function () {
      return active() ? '' : 'the audit log is not written to sts_audit ' +
        'here (memory, an LDIF store, or a development process)';
    },
    run: function () {
      return runRetention();
    }
  });
  log.debug("Leaving audit_store.registerJobs().");
  return true;
}

module.exports = {
  registerJobs: registerJobs,
  runRetention: runRetention,
  RETAIN_JOB: RETAIN_JOB,
  dropLegacy: dropLegacy,
  setDriver: setDriver,
  active: active,
  append: append,
  flush: flush,
  newest: newest,
  retain: retain,
  purgeRealm: purgeRealm,
  privileges: privileges,
  lastProbe: lastProbe,
  legacyHandle: legacyHandle,
  insertRows: insertRows,
  LABEL: LABEL,
  MAX_PENDING: MAX_PENDING
};
