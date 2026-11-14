// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: metrics_mariadb.js
//
// ---------------------------------------------------------------------------
// WHAT `/admin/database` ASKS A MARIADB STORE (#677, phase 3b).
//
// PostgreSQL's probes (`METRIC_PROBES` in `persistence_postgres.js`) read the
// `pg_stat_*` views; MariaDB has none of them, and its answers live in
// `information_schema` — the server's status and variables, the process
// list, the tables and their indexes. This is the same kind of table under
// the same rules, `tests/database_metrics.js` holding both:
//
//   * EVERY PROBE IS A SELECT, A LITERAL, with no parameter and no
//     separator, and each is run, timed and caught on its own — so a probe
//     the role may not read costs one row of the page and not the page.
//   * THE GROUPS ARE THE PAGE'S SECTIONS (Server, Activity, Background,
//     Configuration, Schema), and every section has a probe.
//   * WHERE THE PAGE DERIVES A NUMBER FROM A COLUMN, THE COLUMN HAS
//     POSTGRESQL'S NAME when MariaDB has the same quantity: `database`'s
//     `xact_commit` / `xact_rollback` (COM_COMMIT / COM_ROLLBACK) and
//     `blks_hit` / `blks_read` (InnoDB buffer-pool requests less disk reads,
//     and disk reads); `tables`' `relname` and `n_live_tup` (an ESTIMATE on
//     InnoDB, said in its `what`); `indexes`' `table_name`, `index_name`,
//     `is_primary`; `size`'s `pretty`; `server`'s `search_schema`. Where
//     MariaDB keeps no such count — dead tuples, a table's or an index's
//     scans — the column is left out rather than answered 0, and the page
//     does not call an index unused for having no count.
//   * THE PROCESS LIST IS NARROWED BY THE ROLE, as `pg_stat_activity` is:
//     without PROCESS a role sees only its own threads, and the page says so
//     in the probe's `what` rather than under-reporting quietly.
//
// A LEAF: data only (bunyan for the one helper's Entering/Leaving lines).
// ---------------------------------------------------------------------------

const log = require('bunyan').createLogger({
  name: 'sts-metrics-mariadb',
  level: process.env.STS_LOG_LEVEL || process.env.LOG_LEVEL || 'info'
});

// A server status value as a number, by its name.
const STATUS = function (name) {
  log.debug("Entering STATUS().");
  log.debug("Leaving STATUS().");
  return '(SELECT CAST(VARIABLE_VALUE AS DECIMAL(20,0)) FROM ' +
    'information_schema.GLOBAL_STATUS WHERE VARIABLE_NAME = \'' + name +
    '\')';
};

const METRIC_PROBES = [
  { id: 'server', group: 'Server', shape: 'row',
    what: 'Which MariaDB this is, who this service is connected AS, and how ' +
          'long the server has been up.',
    sql: 'SELECT VERSION() AS version, DATABASE() AS `database`, ' +
         'CURRENT_USER() AS connected_as, USER() AS session_user, ' +
         'DATABASE() AS search_schema, CONNECTION_ID() AS backend_pid, ' +
         STATUS('UPTIME') + ' AS uptime_seconds, @@time_zone AS timezone, ' +
         '@@character_set_database AS server_encoding, ' +
         '@@collation_connection AS collation' },
  { id: 'size', group: 'Server', shape: 'row',
    what: 'How much disk this database occupies: its tables and their ' +
          'indexes, as InnoDB reports them.',
    sql: 'SELECT COALESCE(SUM(DATA_LENGTH + INDEX_LENGTH), 0) AS bytes, ' +
         'CONCAT(ROUND(COALESCE(SUM(DATA_LENGTH + INDEX_LENGTH), 0) / ' +
         '1048576, 1), \' MB\') AS pretty FROM information_schema.TABLES ' +
         'WHERE TABLE_SCHEMA = DATABASE()' },
  { id: 'database', group: 'Activity', shape: 'row',
    what: 'The counters MariaDB keeps for the whole server (not this ' +
          'database alone, which it does not count apart): commits and ' +
          'rollbacks, buffer-pool reads served from memory against those ' +
          'that went to disk, rows read and written, and deadlocks.',
    sql: 'SELECT ' + STATUS('COM_COMMIT') + ' AS xact_commit, ' +
         STATUS('COM_ROLLBACK') + ' AS xact_rollback, ' +
         STATUS('INNODB_BUFFER_POOL_READ_REQUESTS') + ' - ' +
         STATUS('INNODB_BUFFER_POOL_READS') + ' AS blks_hit, ' +
         STATUS('INNODB_BUFFER_POOL_READS') + ' AS blks_read, ' +
         STATUS('INNODB_ROWS_READ') + ' AS rows_read, ' +
         STATUS('INNODB_ROWS_INSERTED') + ' AS rows_inserted, ' +
         STATUS('INNODB_ROWS_UPDATED') + ' AS rows_updated, ' +
         STATUS('INNODB_ROWS_DELETED') + ' AS rows_deleted, ' +
         STATUS('INNODB_DEADLOCKS') + ' AS deadlocks, ' +
         STATUS('QUESTIONS') + ' AS statements, ' +
         STATUS('SLOW_QUERIES') + ' AS slow_statements' },
  { id: 'connections', group: 'Activity', shape: 'rows',
    what: 'The connections this role can see. WITHOUT the PROCESS ' +
          'privilege, which this service does not ask for, that is only its ' +
          'own: another role\'s connections are not listed at all.',
    sql: 'SELECT ID AS pid, USER AS usename, DB AS datname, COMMAND AS ' +
         'state, TIME AS seconds, STATE AS wait_event, LEFT(INFO, 200) AS ' +
         'query FROM information_schema.PROCESSLIST ORDER BY TIME DESC' },
  { id: 'threads', group: 'Activity', shape: 'row',
    what: 'How many connections the server holds, and its ceiling.',
    sql: 'SELECT ' + STATUS('THREADS_CONNECTED') + ' AS connected, ' +
         STATUS('THREADS_RUNNING') + ' AS running, ' +
         STATUS('MAX_USED_CONNECTIONS') + ' AS most_ever, ' +
         '@@max_connections AS max_connections' },
  { id: 'innodb', group: 'Background', shape: 'rows',
    what: 'InnoDB\'s buffer pool and its row locks: pages, and how often a ' +
          'statement waited for a lock and for how long.',
    sql: 'SELECT VARIABLE_NAME AS name, VARIABLE_VALUE AS value FROM ' +
         'information_schema.GLOBAL_STATUS WHERE VARIABLE_NAME LIKE ' +
         '\'INNODB\\_BUFFER\\_POOL\\_PAGES%\' OR VARIABLE_NAME LIKE ' +
         '\'INNODB\\_ROW\\_LOCK%\' ORDER BY VARIABLE_NAME' },
  { id: 'settings', group: 'Configuration', shape: 'rows',
    what: 'The server settings this store depends on: the change log\'s ' +
          'density (auto_increment_increment, innodb_autoinc_lock_mode), ' +
          'the isolation and durability, and the transport.',
    sql: 'SELECT VARIABLE_NAME AS name, VARIABLE_VALUE AS setting FROM ' +
         'information_schema.GLOBAL_VARIABLES WHERE VARIABLE_NAME IN ' +
         '(\'AUTO_INCREMENT_INCREMENT\', \'INNODB_AUTOINC_LOCK_MODE\', ' +
         '\'TRANSACTION_ISOLATION\', \'INNODB_FLUSH_LOG_AT_TRX_COMMIT\', ' +
         '\'INNODB_BUFFER_POOL_SIZE\', \'MAX_CONNECTIONS\', ' +
         '\'REQUIRE_SECURE_TRANSPORT\', \'WAIT_TIMEOUT\', \'SQL_MODE\', ' +
         '\'VERSION\') ORDER BY VARIABLE_NAME' },
  { id: 'tls', group: 'Configuration', shape: 'row',
    what: 'Whether THIS connection is TLS, and with what.',
    sql: 'SELECT (SELECT VARIABLE_VALUE FROM information_schema.' +
         'SESSION_STATUS WHERE VARIABLE_NAME = \'SSL_VERSION\') AS version, ' +
         '(SELECT VARIABLE_VALUE FROM information_schema.SESSION_STATUS ' +
         'WHERE VARIABLE_NAME = \'SSL_CIPHER\') AS cipher' },
  { id: 'tables', group: 'Schema', shape: 'rows',
    what: 'This store\'s tables: rows (InnoDB\'s ESTIMATE, not a count), ' +
          'the bytes of data and of indexes, and the space freed and not ' +
          'yet reused.',
    sql: 'SELECT TABLE_NAME AS relname, TABLE_ROWS AS n_live_tup, ' +
         'DATA_LENGTH AS data_bytes, INDEX_LENGTH AS index_bytes, DATA_FREE ' +
         'AS free_bytes, UPDATE_TIME AS last_write FROM ' +
         'information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() ' +
         'ORDER BY DATA_LENGTH + INDEX_LENGTH DESC' },
  { id: 'indexes', group: 'Schema', shape: 'rows',
    what: 'Every index of this store\'s tables and its columns. MariaDB ' +
          'keeps no count of an index\'s scans without the user-statistics ' +
          'plugin, so none is shown.',
    sql: 'SELECT TABLE_NAME AS table_name, INDEX_NAME AS index_name, ' +
         '(INDEX_NAME = \'PRIMARY\') AS is_primary, MIN(NON_UNIQUE) = 0 AS ' +
         'is_unique, GROUP_CONCAT(COLUMN_NAME ORDER BY SEQ_IN_INDEX) AS ' +
         'columns FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = ' +
         'DATABASE() GROUP BY TABLE_NAME, INDEX_NAME ORDER BY TABLE_NAME, ' +
         'INDEX_NAME' },
  { id: 'version', group: 'Schema', shape: 'row',
    what: 'The schema versions this store has recorded.',
    sql: 'SELECT MAX(version) AS version, COUNT(*) AS recorded FROM ' +
         'sts_schema' },
  { id: 'changelog', group: 'Schema', shape: 'row',
    what: 'The change log every process reads: how many rows it holds and ' +
          'the sequence numbers at its two ends.',
    sql: 'SELECT COUNT(*) AS rows_held, MIN(seq) AS lowest, MAX(seq) AS ' +
         'highest FROM sts_changes' }
];

module.exports = { METRIC_PROBES: METRIC_PROBES };
