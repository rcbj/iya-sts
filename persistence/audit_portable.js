// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: audit_portable.js
// ---------------------------------------------------------------------------
// THE APPEND-ONLY AUDIT LOG ON MARIADB (#1616, ASVS 5.0.0 16.4.2).
//
// The postgres driver's five `audit*` methods written a second time, in
// builder statements and MariaDB's own text where it differs. The driver
// uses these when the engine is not PostgreSQL, and only then — the
// arrangement `risk_portable.js` argues for the risk engine's tables.
//
//   * AN INSERT IS `INSERT IGNORE`, because the rows are keyed (realm,
//     origin, seq) and a row written twice — a retried flush, the one-time
//     copy of the old ring run again — must be written once and must not
//     need UPDATE, which the account does not hold here.
//   * RETENTION AND A REALM'S PURGE ARE `CALL`s of the two SQL SECURITY
//     DEFINER procedures `mariadb/schema.sql` makes, which run as their
//     definer: the account itself may not DELETE from `sts_audit`.
//   * THE PRIVILEGE PROBE asks `information_schema` what the CURRENT account
//     holds on the table, the database and globally — any of UPDATE, DELETE
//     or DROP (TRUNCATE's) means the log is not append-only here, and
//     `/admin/mode` says so.
// ---------------------------------------------------------------------------

const log = require('bunyan').createLogger({
  name: 'audit_portable',
  level: (function () {
    try {
      return require(String(process.env.CONFIG_FILE)).logLevel || 'info';
    } catch (e) {
      // No configuration file to read the level from: the default.
      return 'info';
    }
  })()
});

/**
 * Builds the MariaDB audit-log operations over the driver's dialect and pool.
 *
 * @param deps - `dialect` (persistence/sql_dialect.js) and `pool`
 * @returns `{ auditInsert, auditNewest, auditRetain, auditPurgeRealm,
 *   auditDropLegacy, auditRealms, auditPrivileges }`, each answering what the PostgreSQL statement answers
 */
function create(deps) {
  log.debug("Entering create().");
  const dialect = deps.dialect;
  const kx = dialect.kx;
  const pool = deps.pool;

  /**
   * Sends one built statement.
   *
   * @param name - the statement's name
   * @param built - a Knex builder
   * @returns the connection's answer
   */
  function run(name, built) {
    log.debug("Entering run(). " + name);
    log.debug("Leaving run().");
    return dialect.run(pool, 'audit.' + name, built);
  }

  /**
   * Writes audit rows, each once whatever happens to the batch.
   *
   * @param rows - `[{ realm, origin, seq, at, body }]`, `body` sealed
   * @returns the count written
   */
  function auditInsert(rows) {
    log.debug("Entering auditInsert(). " + rows.length);
    if (!rows.length) {
      log.debug("Leaving auditInsert(). Nothing.");
      return Promise.resolve(0);
    }
    log.debug("Leaving auditInsert().");
    return run('insert', kx('sts_audit').insert(rows.map(function (r) {
      return { realm: String(r.realm), origin: String(r.origin || ''),
               seq: Number(r.seq), at: Number(r.at), body: String(r.body) };
    })).onConflict(['realm', 'origin', 'seq']).ignore())
      .then(function (result) {
        return dialect.affected(result);
      });
  }

  /**
   * A realm's newest rows, newest first, in the audit page's order.
   *
   * @param realm - the realm id
   * @param limit - how many
   * @param origin - optional: one process's rows only
   * @returns `[{ realm, origin, seq, at, body }]`
   */
  function auditNewest(realm, limit, origin) {
    log.debug("Entering auditNewest(). realm=" + realm);
    const built = kx('sts_audit')
      .select('realm', 'origin', 'seq', 'at', 'body')
      .where('realm', String(realm));
    if (origin !== undefined && origin !== null) {
      built.where('origin', String(origin));
    }
    log.debug("Leaving auditNewest().");
    return run('newest', built
      .orderBy([{ column: 'at', order: 'desc' },
                { column: 'origin', order: 'desc' },
                { column: 'seq', order: 'desc' }])
      .limit(Math.max(1, Number(limit) || 1)))
      .then(function (result) {
        return dialect.rowsOf(result).map(function (row) {
          return { realm: row.realm, origin: row.origin,
                   seq: Number(row.seq), at: Number(row.at), body: row.body };
        });
      });
  }

  /**
   * Retention through the definer's procedure, which keeps at least 1000.
   *
   * @param realm - the realm id
   * @param keep - how many of its newest rows to keep
   * @returns null: a procedure answers no count here
   */
  function auditRetain(realm, keep) {
    log.debug("Entering auditRetain(). realm=" + realm);
    log.debug("Leaving auditRetain().");
    return run('retain', kx.raw('CALL sts_audit_retain(?, ?)',
                                [String(realm), Number(keep) || 0]))
      .then(function () {
        return null;
      });
  }

  /**
   * A realm's rows, through the procedure that refuses a live realm.
   *
   * @param realm - the realm id
   * @returns null: a procedure answers no count here
   */
  function auditPurgeRealm(realm) {
    log.debug("Entering auditPurgeRealm(). realm=" + realm);
    log.debug("Leaving auditPurgeRealm().");
    return run('purgeRealm', kx.raw('CALL sts_audit_purge_realm(?)',
                                    [String(realm)]))
      .then(function () {
        return null;
      });
  }

  /**
   * The realms the table holds rows of.
   *
   * @returns the realm ids
   */
  function auditRealms() {
    log.debug("Entering auditRealms().");
    log.debug("Leaving auditRealms().");
    return run('realms', kx('sts_audit').distinct('realm'))
      .then(function (result) {
        return dialect.rowsOf(result).map(function (row) {
          return String(row.realm);
        });
      });
  }

  /**
   * The old ring's segments in `sts_minted`, once copied (#1616).
   *
   * @param handle - the handle they were written under
   * @returns the count deleted
   */
  function auditDropLegacy(handle) {
    log.debug("Entering auditDropLegacy(). " + handle);
    log.debug("Leaving auditDropLegacy().");
    return run('dropLegacy', kx('sts_minted').where('handle', String(handle))
      .del()).then(function (result) {
      return dialect.affected(result);
    });
  }

  /**
   * Whether the table is there and whether this account could change it.
   *
   * @returns `{ present, writable, functions }`
   */
  function auditPrivileges() {
    log.debug("Entering auditPrivileges().");
    // The grantee as information_schema spells it: 'user'@'host'.
    const grantee = "CONCAT('''', SUBSTRING_INDEX(CURRENT_USER(), '@', 1), " +
      "'''@''', SUBSTRING_INDEX(CURRENT_USER(), '@', -1), '''')";
    const verbs = "('UPDATE', 'DELETE', 'DROP')";
    const sql = 'SELECT ' +
      '(SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = ' +
      'DATABASE() AND table_name = \'sts_audit\') AS present, ' +
      '(SELECT COUNT(*) FROM information_schema.routines WHERE ' +
      'routine_schema = DATABASE() AND routine_name IN ' +
      '(\'sts_audit_retain\', \'sts_audit_purge_realm\')) AS functions, ' +
      '((SELECT COUNT(*) FROM information_schema.table_privileges WHERE ' +
      'table_schema = DATABASE() AND table_name = \'sts_audit\' AND ' +
      'grantee = ' + grantee + ' AND privilege_type IN ' + verbs + ') + ' +
      '(SELECT COUNT(*) FROM information_schema.schema_privileges WHERE ' +
      'table_schema = DATABASE() AND grantee = ' + grantee + ' AND ' +
      'privilege_type IN ' + verbs + ') + ' +
      '(SELECT COUNT(*) FROM information_schema.user_privileges WHERE ' +
      'grantee = ' + grantee + ' AND privilege_type IN ' + verbs +
      ')) AS writable';
    log.debug("Leaving auditPrivileges().");
    return run('privileges', kx.raw(sql)).then(function (result) {
      const row = dialect.rowsOf(result)[0] || {};
      return { present: Number(row.present) > 0,
               functions: Number(row.functions) === 2,
               writable: Number(row.writable) > 0 };
    });
  }

  log.debug("Leaving create().");
  return { auditInsert: auditInsert, auditNewest: auditNewest,
           auditRetain: auditRetain, auditPurgeRealm: auditPurgeRealm,
           auditDropLegacy: auditDropLegacy, auditRealms: auditRealms,
           auditPrivileges: auditPrivileges };
}

module.exports = {
  // `forDriver`, not `create`, at the call site: `risk_portable.js` says why.
  create: create,
  forDriver: create
};
