// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: online_indexes.js
//
// ---------------------------------------------------------------------------
// AN INDEX A LIVE STORE IS OWED IS BUILT ONLINE, OR NOT AT ALL (#876, #882).
//
// The driver's `open()` creates what the schema is missing inside its one
// transaction, and that was right for a table or a column: either the store
// has it or the service cannot answer. Two indexes on `sts_sessions` broke
// that rule when release 1.0.0 shipped without them:
//
//   * `sts_sessions_subject_band` (#876), the per-person cap's one band per
//     sweep, and
//   * `sts_sessions_started` (#882, schema version 32), the console's live
//     session pages, newest first.
//
// Both are a COST and never a wrong answer: every statement that reads them
// asks the same question of the table without them, by a slower plan. And
// building either inside `open()`'s transaction was the worst of both: a
// plain `CREATE INDEX` holds a `SHARE` lock that stops every write to
// `sts_sessions` for the build — seconds to minutes at a million sessions,
// on a table every sign-in writes, while the transaction holds the start —
// and the role this service dials with in a product deployment (`sts_app`)
// does not own the table, so it was refused (STS-STORE-0029) and the 1.0.1
// image would not start on a 1.0.0 store until the owner had run
// `postgres/upgrade-1.0.0.sql`. rcbj's rule since 1.0.0 is that an existing
// store upgrades safely, so neither is acceptable.
//
// So an index the model marks `online` (its `driver` options in
// `models/persistence/*.tsp`) is left out of that transaction, and after it
// commits:
//
//   * PRESENT AND VALID: nothing.
//   * MISSING, OR INVALID (a `CREATE INDEX CONCURRENTLY` that died), AND THIS
//     ROLE DOES NOT OWN THE TABLE: the service starts, and says once
//     (STS-STORE-0172) which indexes are owed and that the owner's
//     `upgrade-1.0.0.sql` builds them without blocking writers. This is the
//     normal product split.
//   * MISSING OR INVALID AND THIS ROLE OWNS THE TABLE: it is built in the
//     BACKGROUND, on a connection of its own outside every transaction, with
//     `CREATE INDEX CONCURRENTLY` (an invalid one is dropped concurrently
//     first). The start does not wait for it. Two processes starting
//     together are serialised by a session advisory lock taken with
//     `pg_try_advisory_lock()`: the one that does not get it leaves the build
//     to the one that did, so an index another process is still building
//     (which reads as INVALID until it finishes) is never dropped from under
//     it. A build that fails is STS-STORE-0173, and the next start tries
//     again. `close()` ends the connection, which cancels a build in flight
//     and leaves an invalid index the next start drops and builds again.
//
// On MariaDB (`persistence/open_mariadb.js`) there are no invalid indexes and
// no CONCURRENTLY; the same index is built in the background as
// `ALTER TABLE … WAIT 5 ADD INDEX IF NOT EXISTS …, ALGORITHM=INPLACE,
// LOCK=NONE` — InnoDB builds it without blocking writers, and `WAIT 5`
// bounds the metadata lock it needs at either end, so a long transaction
// cannot queue every write behind it. An account that may not alter the
// table is STS-STORE-0172 naming `mariadb/upgrade-1.0.0.sql`.
//
// A FRESH store is unchanged: `postgres/schema.sql` builds both indexes in
// its own transaction on an empty table, and `open()` then finds them.
//
// THIS IS NOT A SCHEMA VERSION. Version 32's row is still written by every
// open, as it is while an advisory upgrade (STS-STORE-0083) is still owed:
// the version records the shape the tables answer to, and these indexes
// change no answer. A version 33 for them would be one more row and a
// MariaDB twin for no change of shape, and would leave the owner's
// `upgrade-1.0.0.sql` (which records 32) one version short.
//
// A LIBRARY: handed the client, the pool and the logger by the driver.
// ---------------------------------------------------------------------------

const errorCodes = require('../common/error_codes');

// This module's own logger, for the Entering/Leaving lines of the helpers
// that are not handed the driver's.
const moduleLog = require('bunyan').createLogger({
  name: 'sts-online-indexes',
  level: process.env.STS_LOG_LEVEL || process.env.LOG_LEVEL || 'info'
});

// The advisory lock two starting processes serialise their builds on: the
// first key is #876's number, the second the hash of this name. An advisory
// lock needs no privilege.
const BUILD_LOCK = 'sts-online-index-build';
const BUILD_LOCK_CLASS = 876;

// MariaDB's bound on the metadata lock an online build takes at its start and
// its end, in seconds (`ALTER TABLE … WAIT n`).
const MARIADB_WAIT_SECONDS = 5;

/**
 * The objects the model marks `online`.
 *
 * @param objects - the driver's SCHEMA_OBJECTS
 * @returns those with `online: true`, in order
 */
function onlineObjects(objects) {
  moduleLog.debug("Entering onlineObjects().");
  moduleLog.debug("Leaving onlineObjects().");
  return (objects || []).filter(function (object) {
    return object && object.online === true;
  });
}

/**
 * The table an index statement is ON.
 *
 * @param statement - a CREATE INDEX statement
 * @returns the table's name, or ''
 */
function tableOf(statement) {
  moduleLog.debug("Entering tableOf().");
  const m = /\bON\s+`?([a-z_0-9]+)`?\s*(?:USING\s+\w+\s*)?\(/i
    .exec(String(statement));
  moduleLog.debug("Leaving tableOf().");
  return m ? m[1] : '';
}

/**
 * PostgreSQL's statement, built concurrently.
 *
 * @param statement - `CREATE INDEX IF NOT EXISTS …`
 * @returns `CREATE INDEX CONCURRENTLY IF NOT EXISTS …`
 */
function concurrentStatement(statement) {
  moduleLog.debug("Entering concurrentStatement().");
  moduleLog.debug("Leaving concurrentStatement().");
  return String(statement).replace(/^CREATE INDEX IF NOT EXISTS\b/i,
    'CREATE INDEX CONCURRENTLY IF NOT EXISTS');
}

/**
 * MariaDB's statement, built in place without blocking writers.
 *
 * @param statement - `CREATE INDEX IF NOT EXISTS name ON table (cols)`
 * @returns the `ALTER TABLE … ADD INDEX` form, or '' for another shape
 */
function mariadbOnlineStatement(statement) {
  moduleLog.debug("Entering mariadbOnlineStatement().");
  const m = /^CREATE INDEX IF NOT EXISTS\s+(\w+)\s+ON\s+(\w+)\s*(\(.*\))\s*$/i
    .exec(String(statement));
  if (!m) {
    moduleLog.debug("Leaving mariadbOnlineStatement(). Another shape.");
    return '';
  }
  moduleLog.debug("Leaving mariadbOnlineStatement().");
  return 'ALTER TABLE ' + m[2] + ' WAIT ' + MARIADB_WAIT_SECONDS +
    ' ADD INDEX IF NOT EXISTS ' + m[1] + ' ' + m[3] +
    ', ALGORITHM=INPLACE, LOCK=NONE';
}

/**
 * What the online indexes are owed, asked inside `open()`'s transaction.
 *
 * @param client - the transaction's client
 * @param objects - the online objects
 * @param missing - the names `open()`'s probe found absent
 * @returns a promise of `{ owed: [{ object, invalid }], owner: boolean }`
 */
function probePostgres(client, objects, missing) {
  moduleLog.debug("Entering probePostgres().");
  const absent = new Set(missing || []);
  const present = objects.filter(function (object) {
    return !absent.has(object.name);
  });
  const plan = { owed: [], owner: false };
  objects.forEach(function (object) {
    if (absent.has(object.name)) {
      plan.owed.push({ object: object, invalid: false });
    }
  });
  moduleLog.debug("Leaving probePostgres().");
  return (present.length ? client.query(
    'SELECT c.relname AS name FROM pg_index i JOIN pg_class c ON c.oid = ' +
    'i.indexrelid JOIN pg_namespace n ON n.oid = c.relnamespace WHERE ' +
    'n.nspname = current_schema() AND c.relname = ANY($1::text[]) AND ' +
    'NOT i.indisvalid',
    [present.map(function (object) { return object.name; })])
    : Promise.resolve({ rows: [] })).then(function (result) {
    const invalid = new Set(((result && result.rows) || [])
      .map(function (row) { return String(row.name); }));
    present.forEach(function (object) {
      if (invalid.has(object.name)) {
        plan.owed.push({ object: object, invalid: true });
      }
    });
    if (!plan.owed.length) {
      return plan;
    }
    // CREATE INDEX needs the table's owner (or a member of its role).
    // Asked by name in the catalogue, so a role that may read it is asked
    // nothing it may not.
    const tables = Array.from(new Set(plan.owed.map(function (one) {
      return tableOf(one.object.statement);
    })));
    return client.query(
      'SELECT c.relname AS name, pg_has_role(current_user, c.relowner, ' +
      '\'USAGE\') AS owner FROM pg_class c JOIN pg_namespace n ON n.oid = ' +
      'c.relnamespace WHERE n.nspname = current_schema() AND c.relname = ' +
      'ANY($1::text[])', [tables]).then(function (owners) {
      const owned = new Set(((owners && owners.rows) || [])
        .filter(function (row) { return row.owner === true; })
        .map(function (row) { return String(row.name); }));
      plan.owner = tables.length > 0 && tables.every(function (name) {
        return owned.has(name);
      });
      return plan;
    });
  });
}

/**
 * The sentence an owed index is told with, to a role that cannot build it.
 *
 * @param names - the indexes owed
 * @param script - the owner's upgrade script
 * @returns the warning, tagged STS-STORE-0172
 */
function owedSentence(names, script) {
  moduleLog.debug("Entering owedSentence().");
  moduleLog.debug("Leaving owedSentence().");
  return errorCodes.tag('STS-STORE-0172') + 'persistence: the store is ' +
    'owed ' + names.join(', ') + ' (#876, #882), and this role does not ' +
    'own the table to build ' + (names.length > 1 ? 'them' : 'it') + '. ' +
    'The service starts and every question is still answered, by a slower ' +
    'plan. Run ' + script + ' as the table\'s owner: it builds ' +
    (names.length > 1 ? 'them' : 'it') + ' without blocking writers, ' +
    'while this service runs.';
}

/**
 * Tells, or builds, what `probePostgres()` found owed. Never rejects, and
 * the caller does not wait for a build.
 *
 * @param pool - the driver's pool (its `dedicated()` connection builds)
 * @param log - the driver's logger
 * @param plan - `probePostgres()`'s answer
 * @param state - `{ client }`, where the build's connection is kept for
 *   `close()`
 * @returns a promise settled when the build has finished or been left
 */
function settlePostgres(pool, log, plan, state) {
  log.debug("Entering settlePostgres().");
  const owed = (plan && plan.owed) || [];
  if (!owed.length) {
    log.debug("Leaving settlePostgres(). Nothing owed.");
    return Promise.resolve({ built: [], told: [] });
  }
  const names = owed.map(function (one) {
    return one.object.name + (one.invalid ? ' (invalid)' : '');
  });
  if (!plan.owner || !pool || typeof pool.dedicated !== 'function') {
    log.warn(owedSentence(names, 'postgres/upgrade-1.0.0.sql'));
    log.debug("Leaving settlePostgres(). Told.");
    return Promise.resolve({ built: [], told: names });
  }
  log.info('persistence: the store is owed ' + names.join(', ') +
           ' (#876, #882); this role owns the table, so ' +
           (owed.length > 1 ? 'they are' : 'it is') + ' being built ' +
           'concurrently, in the background. The service does not wait, ' +
           'and answers without ' + (owed.length > 1 ? 'them' : 'it') +
           ' until the build finishes.');
  const client = pool.dedicated();
  state.client = client;
  const built = [];
  client.on('error', function (err) {
    // A dropped build connection: the build is cancelled, and the next
    // start finds the index missing or invalid and tries again.
    log.debug("Caught in a callback in settlePostgres(): " +
              ((err && err.message) || err));
  });
  const end = function () {
    if (state.client === client) {
      state.client = null;
    }
    return Promise.resolve(client.end()).catch(function (e) {
      log.debug("Caught in a callback in settlePostgres(): " +
                ((e && e.message) || e));
    });
  };
  log.debug("Leaving settlePostgres(). Building.");
  return Promise.resolve(client.connect()).then(function () {
    return client.query('SELECT pg_try_advisory_lock($1, hashtext($2)) ' +
                        'AS got', [BUILD_LOCK_CLASS, BUILD_LOCK]);
  }).then(function (result) {
    const row = ((result && result.rows) || [])[0] || {};
    if (row.got !== true) {
      log.info('persistence: another process is building the session ' +
               'indexes (#876, #882); this one leaves it to that process.');
      return null;
    }
    let chain = Promise.resolve();
    owed.forEach(function (one) {
      const name = one.object.name;
      chain = chain.then(function () {
        // Asked again under the lock: a process that held it before may
        // have finished, and what is invalid now is a dead build, never one
        // in flight (every builder takes this lock).
        return client.query(
          'SELECT i.indisvalid AS valid FROM pg_index i JOIN pg_class c ON ' +
          'c.oid = i.indexrelid JOIN pg_namespace n ON n.oid = ' +
          'c.relnamespace WHERE n.nspname = current_schema() AND ' +
          'c.relname = $1', [name]);
      }).then(function (result) {
        const row = ((result && result.rows) || [])[0];
        if (row && row.valid === true) {
          return null;
        }
        return (row ? client.query('DROP INDEX CONCURRENTLY IF EXISTS ' +
                                   name) : Promise.resolve(null))
          .then(function () {
            return client.query(concurrentStatement(one.object.statement));
          }).then(function () {
            built.push(name);
            log.info('persistence: ' + name + ' was built concurrently ' +
                     '(#876, #882).');
          });
      });
    });
    return chain;
  }).catch(function (err) {
    log.warn(errorCodes.tag('STS-STORE-0173') + 'persistence: building ' +
             names.join(', ') + ' concurrently failed (' +
             ((err && err.message) || err) + '). The service goes on ' +
             'without ' + (names.length > 1 ? 'them' : 'it') + ', by a ' +
             'slower plan; the next start tries again, or run ' +
             'postgres/upgrade-1.0.0.sql as the table\'s owner.');
  }).then(function () {
    return end();
  }).then(function () {
    return { built: built, told: [] };
  });
}

/**
 * Whether a MariaDB refusal is the server saying this account may not alter.
 *
 * @param err - what the connection rejected with
 * @returns true for a missing privilege
 */
function mariadbDenied(err) {
  moduleLog.debug("Entering mariadbDenied().");
  const errno = err && err.errno;
  const code = err && err.code;
  moduleLog.debug("Leaving mariadbDenied().");
  return errno === 1142 || errno === 1044 || errno === 1227 ||
    code === 'ER_TABLEACCESS_DENIED_ERROR' ||
    code === 'ER_DBACCESS_DENIED_ERROR';
}

/**
 * Builds MariaDB's missing online indexes in place. Never rejects, and the
 * caller does not wait for it.
 *
 * @param pool - the store's pool
 * @param log - the driver's logger
 * @param owed - the online objects `open()` found missing
 * @returns a promise of `{ built, told, failed }`
 */
function settleMariadb(pool, log, owed) {
  log.debug("Entering settleMariadb().");
  const out = { built: [], told: [], failed: [] };
  if (!owed || !owed.length) {
    log.debug("Leaving settleMariadb(). Nothing owed.");
    return Promise.resolve(out);
  }
  log.info('persistence: the mariadb store is owed ' + owed.map(function (o) {
    return o.name;
  }).join(', ') + ' (#882); building it in place, in the background. The ' +
  'service does not wait for it.');
  let chain = Promise.resolve();
  owed.forEach(function (object) {
    chain = chain.then(function () {
      const statement = mariadbOnlineStatement(object.statement);
      if (!statement) {
        throw new Error('an index statement of another shape: ' +
                        object.statement);
      }
      return pool.query(statement).then(function () {
        out.built.push(object.name);
        log.info('persistence: ' + object.name + ' was built in place ' +
                 '(#882).');
      });
    }).catch(function (err) {
      log.debug("Caught in settleMariadb(): " + ((err && err.message) || err));
      if (mariadbDenied(err)) {
        out.told.push(object.name);
        log.warn(owedSentence([object.name], 'mariadb/upgrade-1.0.0.sql'));
        return;
      }
      out.failed.push(object.name);
      log.warn(errorCodes.tag('STS-STORE-0173') + 'persistence: building ' +
               object.name + ' in place failed (' +
               ((err && err.message) || err) + '). The service goes on ' +
               'without it, by a slower plan; the next start tries again, ' +
               'or run mariadb/upgrade-1.0.0.sql as the table\'s owner.');
    });
  });
  log.debug("Leaving settleMariadb().");
  return chain.then(function () {
    return out;
  });
}

module.exports = {
  BUILD_LOCK: BUILD_LOCK,
  BUILD_LOCK_CLASS: BUILD_LOCK_CLASS,
  onlineObjects: onlineObjects,
  tableOf: tableOf,
  concurrentStatement: concurrentStatement,
  mariadbOnlineStatement: mariadbOnlineStatement,
  probePostgres: probePostgres,
  settlePostgres: settlePostgres,
  settleMariadb: settleMariadb
};
