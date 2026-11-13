// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: mariadb_schema.js
//
// ===========================================================================
// THE MARIADB SCHEMA'S TWO COPIES AGREE, AND AGREE WITH POSTGRESQL'S (#677).
//
// `mariadb/schema.sql` is what an owner runs; `persistence/schema_mariadb.js`
// is the driver's copy, which a store opened by the service creates a missing
// object from. `tests/postgres_schema.js` holds PostgreSQL's two copies
// together; this holds MariaDB's:
//
//   A. every CREATE in the script is an object in the module with the same
//      statement, whitespace aside, and in the same order — and the module
//      has no object the script lacks;
//   B. the script records the module's SCHEMA_VERSION, which is the postgres
//      driver's: one number for the store on either engine;
//   C. MariaDB has every table PostgreSQL has, plus its key table;
//   D. every table is InnoDB, utf8mb4 and NO PAD binary, so text compares as
//      it does in PostgreSQL (`mariadb/CLAUDE.md`);
//   E. what PostgreSQL alone has does not leak in: no jsonb, no GIN, no
//      trigger, no function, no `::` cast.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'mariadb_schema',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// The script's CREATE statements, comments removed, each up to its `;`.
function scriptStatements(sql) {
  log.debug("Entering scriptStatements().");
  const code = sql.split('\n').filter(function (line) {
    return !/^\s*--/.test(line);
  }).join('\n');
  const out = [];
  const re = /CREATE (?:TABLE|INDEX|UNIQUE INDEX) IF NOT EXISTS ([a-z_0-9]+)[\s\S]*?;/g;
  let m;
  while ((m = re.exec(code)) !== null) {
    out.push({ name: m[1], statement: m[0].replace(/;$/, '') });
  }
  log.debug("Leaving scriptStatements().");
  return out;
}

function squash(text) {
  log.debug("Entering squash().");
  log.debug("Leaving squash().");
  return String(text).replace(/\s+/g, ' ').replace(/\( /g, '(')
    .replace(/ \)/g, ')').trim();
}

// Release 1.0.0's MariaDB delta is sts_sessions_started and the version
// row. The upgrade script adds that index online and must not invent
// sts_sessions_subject_band, which this engine does not have.
function checkTheReleaseUpgrade(t, sql, schema) {
  log.debug("Entering checkTheReleaseUpgrade().");
  const upgrade = fs.readFileSync(
    path.join(ROOT, 'mariadb', 'upgrade-1.0.0.sql'), 'utf8');
  // Comments may name the PostgreSQL-only statement. The check is the SQL.
  const code = upgrade.split('\n').filter(function (line) {
    return !/^\s*--/.test(line);
  }).join('\n');
  const started = scriptStatements(sql).filter(function (one) {
    return one.name === 'sts_sessions_started';
  })[0];
  const cols = started &&
    /\((realm, started_at DESC, `key`)\)/.exec(started.statement);
  t.check(!!cols && upgrade.indexOf(cols[1]) >= 0,
          'F1. upgrade-1.0.0.sql uses schema.sql\'s started-index columns',
          started && started.statement);
  t.check(/ALGORITHM=INPLACE/.test(upgrade) && /LOCK=NONE/.test(upgrade),
          'F2. the build is online (INPLACE, LOCK=NONE)');
  t.check(!/INDEX\s+sts_sessions_subject_band/i.test(code),
          'F3. no sts_sessions_subject_band: MariaDB has none');
  t.check(!/CREATE INDEX CONCURRENTLY/i.test(code),
          'F4. no CREATE INDEX CONCURRENTLY: MariaDB has none');
  t.check(upgrade.indexOf(
    'INSERT IGNORE INTO sts_schema (version) VALUES (' +
    schema.SCHEMA_VERSION + ')') >= 0,
          'F5. the script records the module\'s SCHEMA_VERSION');
  // The driver builds this index in place, after open(), and never refuses a
  // start over it (#882): it is the one the model marks `online`.
  const online = (schema.SCHEMA_OBJECTS || []).filter(function (one) {
    return one.online === true;
  }).map(function (one) { return one.name; });
  t.equal(JSON.stringify(online), JSON.stringify(['sts_sessions_started']),
          'F6. the driver\'s online index is the one this script adds');
  log.debug("Leaving checkTheReleaseUpgrade().");
}

async function run(t) {
  log.debug("Entering run().");
  const schema = require('../persistence/schema_mariadb');
  const postgres = require('../persistence/persistence_postgres');
  const sql = fs.readFileSync(path.join(ROOT, 'mariadb', 'schema.sql'),
                              'utf8');
  const script = scriptStatements(sql);

  t.log.info('=== A. the script and the module are one schema ===');
  const moduleNames = schema.SCHEMA_OBJECTS.map(function (o) {
    return o.name;
  });
  const scriptNames = script.map(function (o) {
    return o.name;
  });
  t.check(scriptNames.join() === moduleNames.join(),
          'A1. the same objects in the same order',
          'script ' + scriptNames.length + ', module ' + moduleNames.length);
  const differ = [];
  script.forEach(function (one, i) {
    const theirs = schema.SCHEMA_OBJECTS[i];
    if (!theirs || squash(theirs.statement) !== squash(one.statement)) {
      differ.push(one.name);
    }
  });
  t.check(differ.length === 0,
          'A2. EVERY STATEMENT IS THE SAME TEXT in both, whitespace aside',
          differ.join(', '));

  t.log.info('=== B. one schema version ===');
  t.check(schema.SCHEMA_VERSION === postgres.SCHEMA_VERSION,
          'B1. the MariaDB schema is the postgres driver\'s version',
          schema.SCHEMA_VERSION + ' / ' + postgres.SCHEMA_VERSION);
  t.check(new RegExp('INSERT IGNORE INTO sts_schema \\(version\\) VALUES \\(' +
                     schema.SCHEMA_VERSION + '\\)').test(sql),
          'B2. and the script records it');

  t.log.info('=== C. the same tables ===');
  const pgTables = postgres.SCHEMA_OBJECTS.filter(function (o) {
    return /^CREATE TABLE/i.test(o.statement);
  }).map(function (o) {
    return o.name;
  }).concat(['sts_schema']);
  const missing = pgTables.filter(function (name) {
    return schema.TABLES.indexOf(name) < 0;
  });
  t.check(missing.length === 0,
          'C1. every table PostgreSQL has, MariaDB has', missing.join(', '));
  t.check(schema.TABLES.indexOf('sts_ldap_entry_keys') >= 0,
          'C2. and the key table that stands in for the GIN indexes');

  t.log.info('=== D. InnoDB, utf8mb4, NO PAD binary ===');
  const tables = schema.SCHEMA_OBJECTS.filter(function (o) {
    return /^CREATE TABLE/i.test(o.statement);
  });
  const wrong = tables.filter(function (o) {
    return !/ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin\s*$/
      .test(o.statement);
  }).map(function (o) {
    return o.name;
  });
  t.check(wrong.length === 0,
          'D1. every table is InnoDB with the NO PAD binary collation',
          wrong.join(', '));

  t.log.info('=== E. nothing of PostgreSQL\'s ===');
  const leaks = [];
  schema.SCHEMA_OBJECTS.forEach(function (o) {
    if (/\bjsonb\b|\bUSING gin\b|CREATE TRIGGER|CREATE (OR REPLACE )?FUNCTION|::[a-z]|\bbigserial\b|\btimestamptz\b|\bbytea\b/i
          .test(o.statement)) {
      leaks.push(o.name);
    }
  });
  t.check(leaks.length === 0,
          'E1. no jsonb, GIN, trigger, function, cast or PostgreSQL type',
          leaks.join(', '));

  t.log.info('=== F. the release 1.0.0 upgrade ===');
  checkTheReleaseUpgrade(t, sql, schema);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'mariadb_schema',
  describe: 'the MariaDB schema\'s script and module agree with each other ' +
            'and with PostgreSQL\'s tables (#677)',
  run: run
};
