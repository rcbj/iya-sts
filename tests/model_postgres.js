// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: model_postgres.js
//
// ---------------------------------------------------------------------------
// THE PERSISTENCE NAMESPACE KEEPS TODAY'S DDL (#1390).
//
// `emit()` is the SQL file's own bytes. The driver's statement strings are
// that file's strings, not a reformatting. A generated column whose
// expression contains commas stays one column. A later model may not drop
// or retype a column. Directory attributes do not become columns.
// A PostgreSQL table the MariaDB module does not name is a gap.
// `mariadb/schema.sql` itself is `tests/model_mariadb.js`.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');

const log = require('bunyan').createLogger({
  name: 'model_postgres',
  level: process.env.LOG_LEVEL || 'info'
});

const ROOT = path.join(__dirname, '..');

const FIXTURE = [
  'CREATE TABLE example (',
  '  id text PRIMARY KEY,',
  '  parent_key text GENERATED ALWAYS AS (CASE WHEN strpos(dn, \',\') > 0',
  '    THEN substr(dn, strpos(dn, \',\') + 1) ELSE \'\' END) STORED,',
  '  note text',
  ');',
  'CREATE OR REPLACE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $$',
  'BEGIN',
  '  PERFORM 1;',
  'END $$;',
  'CREATE INDEX example_note ON example (note);'
].join('\n');

const MISMATCH = [
  'ddl-only-in-driver', 'ddl-only-in-script',
  'column-upgrade-not-in-script', 'routine-not-in-script',
  'upgrade-not-in-script', 'column-unparsed', 'table-unparsed',
  'lookup-column-missing', 'extension-missing'
];

function statementsEqual(actual, expected) {
  log.debug("Entering statementsEqual().");
  if (actual.length !== expected.length) {
    log.debug("Leaving statementsEqual(). Count.");
    return false;
  }
  let index = 0;
  while (index < actual.length) {
    if (actual[index] !== expected[index]) {
      log.debug("Leaving statementsEqual(). A statement differs.");
      return false;
    }
    index += 1;
  }
  log.debug("Leaving statementsEqual().");
  return true;
}

function sameText(t, actual, expected, what) {
  log.debug("Entering sameText().");
  if (actual === expected) {
    t.check(true, what);
    log.debug("Leaving sameText(). Equal.");
    return;
  }
  let at = 0;
  const end = Math.min(actual.length, expected.length);
  while (at < end && actual.charAt(at) === expected.charAt(at)) {
    at += 1;
  }
  t.check(false, what, 'lengths ' + actual.length + ' and ' +
    expected.length + ', first difference at ' + at + ', expected ' +
    JSON.stringify(expected.slice(at, at + 60)) + ', got ' +
    JSON.stringify(actual.slice(at, at + 60)));
  log.debug("Leaving sameText(). Differ.");
}

function run(t) {
  log.debug("Entering run().");
  const PostgresImport = require('../common/postgres_import');
  const ModelEmit = require('../common/model_emit');
  const driver = require('../persistence/persistence_postgres');

  const fixture = PostgresImport.build(FIXTURE, null, '');
  t.equal(fixture.tables.length, 1, 'the fixture is one table');
  t.equal(fixture.tables[0].columns.length, 3,
    'a generated expression with commas is one column, and PRIMARY KEY ' +
    'is not a column');
  const generated = fixture.tables[0].columns.filter(function (column) {
    return column.name === 'parent_key';
  })[0];
  t.check(generated.generated, 'parent_key is generated');
  const statements = PostgresImport.statements(FIXTURE);
  const functionText = statements.filter(function (statement) {
    return statement.indexOf('PERFORM 1') >= 0;
  });
  t.equal(functionText.length, 1,
    'a semicolon inside $$ stays in the function');
  t.check(functionText[0].indexOf('END') >= 0,
    'the function statement still has its end');

  const sql = fs.readFileSync(path.join(ROOT, 'postgres', 'schema.sql'),
    'utf8');
  const model = PostgresImport.read(ROOT);
  sameText(t, PostgresImport.emit(model), sql,
    'emit() is postgres/schema.sql byte for byte');
  t.equal(model.version, 32, 'schema version 32');
  t.equal(driver.SCHEMA_VERSION, 32, 'the driver reports 32');
  const creates = PostgresImport.statements(sql).filter(
    function (statement) {
      return /^CREATE TABLE\b/i.test(statement);
    });
  t.equal(model.tables.length, creates.length,
    'every CREATE TABLE statement is a table');
  const disagreed = model.gaps.filter(function (gap) {
    return MISMATCH.indexOf(gap.code) >= 0;
  }).map(function (gap) {
    return gap.code + ' ' + String(gap.detail).slice(0, 100);
  });
  t.check(disagreed.length === 0, 'the two DDL copies agree',
    disagreed.slice(0, 6).join(' | '));
  t.equal(model.gaps.filter(function (gap) {
    return gap.code === 'column-version-unspecified';
  }).length, 1, 'column versions are one standing gap');

  const entries = model.tables.filter(function (table) {
    return table.name === 'sts_ldap_entries';
  })[0];
  const columnNames = [];
  model.tables.forEach(function (table) {
    table.columns.forEach(function (column) {
      if (column.name === 'uid' || column.name === 'appIdentifier') {
        columnNames.push(table.name + '.' + column.name);
      }
    });
  });
  t.equal(columnNames.join(','), '',
    'directory attributes are not columns');
  const parent = entries.columns.filter(function (column) {
    return column.name === 'parent_key';
  })[0];
  t.check(parent.generated, 'sts_ldap_entries.parent_key is one generated ' +
    'column');
  const attrs = entries.columns.filter(function (column) {
    return column.name === 'attrs';
  })[0];
  t.equal(attrs.sqlType.toLowerCase(), 'jsonb', 'attrs is jsonb');
  t.check(attrs.required, 'attrs is required');
  const origin = entries.columns.filter(function (column) {
    return column.name === 'origin';
  })[0];
  t.check(!origin.required, 'origin is nullable');
  t.equal(entries.columns.filter(function (column) {
    return column.name === 'name_keys';
  })[0].attributes.join(','), 'uid', 'name_keys names uid');
  t.equal(entries.columns.filter(function (column) {
    return column.name === 'mail_keys';
  })[0].attributes.join(','), 'mail', 'mail_keys names mail');
  t.equal(entries.columns.filter(function (column) {
    return column.name === 'uuid_keys';
  })[0].attributes.join(','), 'entryUUID,stsEntryUuidAlias',
    'uuid_keys names the entry uuid and the alias');
  t.equal(entries.columns.filter(function (column) {
    return column.name === 'class_keys';
  })[0].attributes.join(','), 'objectClass',
    'class_keys names objectClass');

  t.check(statementsEqual(model.driverSchema, driver.SCHEMA),
    'driver SCHEMA strings are the driver\'s own strings');
  t.check(statementsEqual(model.driverColumns.map(function (column) {
    return column.statement;
  }), driver.SCHEMA_COLUMNS.map(function (column) {
    return column.statement;
  })), 'driver column statements are the driver\'s own strings');
  t.check(statementsEqual(model.routines.map(function (routine) {
    return routine.statement;
  }), driver.SCHEMA_ROUTINES.map(function (routine) {
    return routine.statement;
  })), 'driver routines are the driver\'s own strings');
  const upgradeStatements = [];
  model.driverUpgrades.forEach(function (step) {
    step.statements.forEach(function (statement) {
      upgradeStatements.push(statement);
    });
  });
  const driverUpgradeStatements = [];
  driver.SCHEMA_UPGRADES.forEach(function (step) {
    step.statements.forEach(function (statement) {
      driverUpgradeStatements.push(statement);
    });
  });
  t.check(statementsEqual(upgradeStatements, driverUpgradeStatements),
    'driver upgrades are the driver\'s own strings, DROP included');
  t.check(model.grants.length > 0, 'the script grants');
  t.equal(model.extensions.slice().sort().join(','),
    'pg_stat_statements,pg_trgm', 'both extensions');

  const mariadb = fs.readFileSync(path.join(ROOT, 'persistence',
    'schema_mariadb.js'), 'utf8');
  const mariadbNames = {};
  const re = /CREATE TABLE IF NOT EXISTS\s+([A-Za-z0-9_]+)/g;
  let match = re.exec(mariadb);
  while (match) {
    mariadbNames[match[1]] = true;
    match = re.exec(mariadb);
  }
  const missing = model.tables.map(function (table) {
    return table.name;
  }).filter(function (name) {
    return !mariadbNames[name];
  }).sort();
  const gaps = model.gaps.filter(function (gap) {
    return gap.code === 'mariadb-missing';
  }).map(function (gap) {
    return gap.name;
  }).sort();
  t.equal(gaps.join(','), missing.join(','),
    'mariadb-missing is a PostgreSQL table the MariaDB file does not name');
  t.check(gaps.indexOf('sts_ldap_entry_keys') < 0,
    'a MariaDB-only table is not a gap');

  PostgresImport.assertAdditive(model, model);
  const dropped = JSON.parse(JSON.stringify(model));
  dropped.tables[0].columns.pop();
  let refused = false;
  try {
    PostgresImport.assertAdditive(model, dropped);
  } catch (error) {
    log.debug("Caught in run(): " + ((error && error.message) || error));
    refused = true;
  }
  t.check(refused, 'dropping a column is refused');

  const row = {};
  entries.columns.forEach(function (column) {
    if (!column.required) {
      return;
    }
    if (column.sqlType.toLowerCase() === 'jsonb') {
      row[column.name] = [];
      return;
    }
    row[column.name] = 'x';
  });
  const parsed = PostgresImport.parseRow(model, 'sts_ldap_entries', row);
  t.check(parsed.ok, 'a minimal directory row matches',
    parsed.errors.join(';'));
  row.notAColumn = 1;
  const extra = PostgresImport.parseRow(model, 'sts_ldap_entries', row);
  t.check(!extra.ok, 'an unknown column fails');
  const nodes = PostgresImport.parseRow(model, 'sts_cluster_nodes', {
    node_id: 'n',
    name: 'n',
    mode: 'm',
    version: 'v',
    fingerprint: 'f',
    started_at: 'not-a-number',
    heartbeat_at: 1,
    expires_at: 1,
    left_at: 0,
    info: {}
  });
  t.check(!nodes.ok, 'text that is not digits is not a bigint');

  const tableClass = ModelEmit.tableClass(entries);
  t.check(tableClass.indexOf('class StsLdapEntries') >= 0,
    'the table class is StsLdapEntries');
  t.check(tableClass.indexOf('attrs!: unknown') >= 0, 'jsonb is unknown');
  t.check(tableClass.indexOf('z.strictObject') >= 0,
    'the table class parses with strictObject');
  sameText(t, ModelEmit.persistenceDocs(model),
    fs.readFileSync(path.join(ROOT, 'docs',
      'data-model-persistence.md'), 'utf8'),
    'the persistence reading page matches the model');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'model_postgres',
  run: run
};
