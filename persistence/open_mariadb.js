// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: open_mariadb.js
//
// ---------------------------------------------------------------------------
// OPENING A MARIADB STORE (#677, phase 3b): what the postgres driver's
// `open()` does, for the second engine.
//
// PostgreSQL's open() runs in one transaction: it asks `to_regclass` which
// objects exist, creates what is missing (a role without CREATE is refused,
// which is the point — the owner script builds the schema), brings older
// shapes forward (columns, upgrades, storage parameters, the counting
// triggers), checks the change log's sequence is dense, and records the
// schema version. On MariaDB:
//
//   * THERE IS NO TRANSACTION AROUND IT. MariaDB commits every DDL statement
//     on its own, so a transaction would be a fiction; an open interrupted
//     half way leaves what it made, and the next open finishes the rest —
//     every object is `IF NOT EXISTS`.
//   * WHAT EXISTS IS ASKED OF `information_schema` for the CURRENT database,
//     one query for the tables and one for the indexes; the application role
//     may read both. A missing object is created from
//     `persistence/schema_mariadb.js` — the owner script's second copy — and
//     a role that may not (error 1142, 1044) is refused with STS-STORE-0029,
//     as PostgreSQL's is: build the schema once with `mariadb/schema.sql`.
//     (`CREATE … IF NOT EXISTS` on an object that exists is ALSO refused to
//     such a role on MariaDB 11.8, which is why existence is asked first.)
//   * NOTHING OLDER IS BROUGHT FORWARD: every MariaDB store is built at its
//     schema version (`mariadb/CLAUDE.md`), so there are no columns, upgrades
//     or storage parameters to apply, and no triggers — the driver keeps the
//     counts itself on this engine.
//   * THE CHANGE LOG MUST BE DENSE (rcbj on #677): `sts_changes.seq` is
//     AUTO_INCREMENT, so the server's `auto_increment_increment` must be 1
//     and InnoDB's lock mode 0 (traditional) or 1 (consecutive) — mode 2
//     (interleaved) hands concurrent multi-row inserts values out of order
//     and leaves gaps a reader waits for. Refused with STS-STORE-0091 on
//     EVIDENCE, as on PostgreSQL: a server that does not answer is not
//     refused.
//
// A LIBRARY: handed the pool and the logger; requires the error-code table
// and the schema module.
// ---------------------------------------------------------------------------

const errorCodes = require('../common/error_codes');
const schemaMariadb = require('./schema_mariadb');

// This module's own logger, for the Entering/Leaving lines of the two
// helpers that are not handed the driver's.
const moduleLog = require('bunyan').createLogger({
  name: 'sts-open-mariadb',
  level: process.env.STS_LOG_LEVEL || process.env.LOG_LEVEL || 'info'
});

/**
 * The table an index statement is ON.
 *
 * @param statement - a CREATE INDEX statement
 * @returns the table's name, or ''
 */
function indexTable(statement) {
  moduleLog.debug("Entering indexTable().");
  const m = /\bON\s+`?([a-z_0-9]+)`?\s*\(/i.exec(String(statement));
  moduleLog.debug("Leaving indexTable().");
  return m ? m[1] : '';
}

/**
 * Whether a refusal is the server saying this role may not create.
 *
 * @param err - what the connection rejected with
 * @returns true for a missing privilege
 */
function deniedCreate(err) {
  moduleLog.debug("Entering deniedCreate().");
  const errno = err && err.errno;
  const code = err && err.code;
  moduleLog.debug("Leaving deniedCreate().");
  return errno === 1142 || errno === 1044 || errno === 1227 ||
    code === 'ER_TABLEACCESS_DENIED_ERROR' ||
    code === 'ER_DBACCESS_DENIED_ERROR';
}

/**
 * Refuses a change log whose AUTO_INCREMENT leaves gaps by design.
 *
 * @param pool - the store's pool
 * @param log - the driver's logger
 * @returns a promise settled when the sequence is dense, or rejected
 */
function checkChangeLogDense(pool, log) {
  log.debug("Entering checkChangeLogDense() (MariaDB).");
  log.debug("Leaving checkChangeLogDense() (MariaDB).");
  return pool.query('SELECT @@auto_increment_increment AS increment, ' +
                    '@@innodb_autoinc_lock_mode AS lockmode')
    .then(function (result) {
      const row = ((result && result.rows) || [])[0];
      if (!row) {
        return null;
      }
      const increment = Number(row.increment);
      const lockmode = Number(row.lockmode);
      if (!Number.isFinite(increment) || !Number.isFinite(lockmode)) {
        return null;
      }
      if (increment === 1 && (lockmode === 0 || lockmode === 1)) {
        return null;
      }
      throw errorCodes.mark(new Error(errorCodes.tag('STS-STORE-0091') +
        'the change log\'s sequence (sts_changes.seq, AUTO_INCREMENT) is ' +
        'not dense on this server: auto_increment_increment is ' + increment +
        ' and innodb_autoinc_lock_mode is ' + lockmode + '. It must be ' +
        'auto_increment_increment = 1 and innodb_autoinc_lock_mode = 1 (or ' +
        '0) in the server\'s configuration: an interleaved or stepped ' +
        'sequence leaves gaps every reader would wait for.'),
        'STS-STORE-0091');
    });
}

/**
 * Opens a MariaDB store: what exists asked, what is missing created, the
 * change log's density checked, the schema version recorded.
 *
 * @param pool - the store's pool (a StorePool on the mariadb engine)
 * @param log - the driver's logger
 * @returns a promise of the names this process created
 */
function open(pool, log) {
  log.debug("Entering open() (MariaDB).");
  const created = [];
  log.debug("Leaving open() (MariaDB).");
  return Promise.all([
    pool.query('SELECT TABLE_NAME AS name FROM information_schema.TABLES ' +
               'WHERE TABLE_SCHEMA = DATABASE()'),
    pool.query('SELECT DISTINCT TABLE_NAME AS tbl, INDEX_NAME AS name FROM ' +
               'information_schema.STATISTICS WHERE TABLE_SCHEMA = ' +
               'DATABASE()')
  ]).then(function (answers) {
    const tables = new Set((answers[0].rows || []).map(function (row) {
      return String(row.name);
    }));
    const indexes = new Set((answers[1].rows || []).map(function (row) {
      return String(row.tbl) + '.' + String(row.name);
    }));
    const missing = schemaMariadb.SCHEMA_OBJECTS.filter(function (object) {
      if (/^CREATE TABLE/i.test(object.statement)) {
        return !tables.has(object.name);
      }
      return !indexes.has(indexTable(object.statement) + '.' + object.name);
    });
    if (!missing.length) {
      log.debug('open() (MariaDB): every object in the schema is present; ' +
                'no CREATE is issued.');
      return null;
    }
    log.info('persistence: the mariadb store is missing ' + missing.length +
             ' object(s) (' + missing.map(function (o) {
               return o.name;
             }).join(', ') + ') and this process is creating them. A store ' +
             'built by mariadb/schema.sql needs none of this.');
    let chain = Promise.resolve();
    missing.forEach(function (object) {
      chain = chain.then(function () {
        return pool.query(object.statement).then(function () {
          created.push(object.name);
        });
      });
    });
    return chain;
  }).then(function () {
    return checkChangeLogDense(pool, log);
  }).then(function () {
    return pool.query('INSERT IGNORE INTO sts_schema (version) VALUES (?)',
                      [schemaMariadb.SCHEMA_VERSION]);
  }).catch(function (err) {
    log.debug("Caught in open() (MariaDB): " + ((err && err.message) || err));
    if (deniedCreate(err)) {
      throw new Error(errorCodes.tag('STS-STORE-0029') +
                      'persistence: the mariadb store could not be opened — ' +
                      err.message + '. This role may not create what is ' +
                      'missing, which is how it is meant to be: build the ' +
                      'schema once with mariadb/schema.sql, run by the ' +
                      'database\'s owner.');
    }
    throw err;
  }).then(function () {
    log.info('persistence: the mariadb store is open; schema version ' +
             schemaMariadb.SCHEMA_VERSION + ' is present' +
             (created.length
               ? ' (this process created ' + created.join(', ') + ')'
               : ' and this process created none of it') + '.');
    return created;
  });
}

module.exports = {
  open: open,
  checkChangeLogDense: checkChangeLogDense,
  indexTable: indexTable
};
