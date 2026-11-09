// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: model_mariadb.js
//
// ---------------------------------------------------------------------------
// THE MARIADB SCRIPT COMES BACK AS ITS OWN BYTES (#1390).
//
// `emit()` is `mariadb/schema.sql`. The module's statements are that
// file's statements, whitespace aside. A back-quoted `key` is a column.
// An inline `KEY` is an index. The engine clause is part of the table.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');

const log = require('bunyan').createLogger({
  name: 'model_mariadb',
  level: process.env.LOG_LEVEL || 'info'
});

const ROOT = path.join(__dirname, '..');
const MariaDbImport = require('../common/mariadb_import');

const ENGINE = 'ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 ' +
  'COLLATE=utf8mb4_nopad_bin';

const FIXTURE = [
  '-- a comment',
  'CREATE TABLE IF NOT EXISTS example (',
  '  `key` VARCHAR(8) NOT NULL,',
  '  note LONGTEXT,',
  '  PRIMARY KEY (`key`),',
  '  KEY example_id (note)',
  ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin;',
  'CREATE INDEX IF NOT EXISTS example_note ON example (note);'
].join('\n');

const FIXTURE_OBJECTS = [
  { name: 'example', statement:
    'CREATE TABLE IF NOT EXISTS example ( `key` VARCHAR(8) NOT NULL, ' +
    'note LONGTEXT, PRIMARY KEY (`key`), KEY example_id (note) ) ' +
    ENGINE },
  { name: 'example_note', statement:
    'CREATE INDEX IF NOT EXISTS example_note ON example (note)' }
];

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

function columnNamed(table, name) {
  log.debug("Entering columnNamed().");
  const found = table.columns.filter(function (column) {
    return column.name === name;
  })[0];
  log.debug("Leaving columnNamed().");
  return found;
}

async function run(t) {
  log.debug("Entering run().");
  const fixture = MariaDbImport.build(FIXTURE, {
    SCHEMA_VERSION: 31,
    SCHEMA_OBJECTS: FIXTURE_OBJECTS
  });
  sameText(t, MariaDbImport.emit(fixture), FIXTURE,
    'a fixture emits its own SQL');
  const example = fixture.tables.filter(function (table) {
    return table.name === 'example';
  })[0];
  const key = columnNamed(example, 'key');
  t.check(key && key.sqlType === 'VARCHAR(8)' && key.required === true,
    'a back-quoted key is a required column');
  t.check(example.columns.every(function (column) {
    return column.name !== 'KEY' && column.name !== 'PRIMARY';
  }), 'an inline KEY is not a column');
  t.equal(fixture.gaps.map(function (gap) {
    return gap.code;
  }).join(','), '', 'a matching fixture has no gaps');

  const short = MariaDbImport.build(FIXTURE, {
    SCHEMA_VERSION: 31,
    SCHEMA_OBJECTS: [FIXTURE_OBJECTS[0]]
  });
  t.check(short.gaps.some(function (gap) {
    return gap.code === 'mariadb-only-in-script' &&
      gap.name === 'example_note';
  }), 'a create missing from the module is a gap');

  const sql = fs.readFileSync(path.join(ROOT, 'mariadb', 'schema.sql'),
    'utf8');
  const schema = require('../persistence/schema_mariadb');
  const model = MariaDbImport.read(ROOT);
  sameText(t, MariaDbImport.emit(model), sql,
    'mariadb/schema.sql comes back as its own bytes');
  t.equal(model.version, 31, 'the schema version is 31');
  t.equal(model.tables.length, 42, 'forty-two tables');
  t.check(model.tables.some(function (table) {
    return table.name === 'sts_ldap_entry_keys';
  }), 'the key table is in the model');
  t.check(model.tables.every(function (table) {
    return table.engine === ENGINE;
  }), 'every table is InnoDB with the NO PAD binary collation');
  const appconfig = model.tables.filter(function (table) {
    return table.name === 'sts_appconfig';
  })[0];
  const appKey = columnNamed(appconfig, 'key');
  t.check(appKey && appKey.sqlType === 'VARCHAR(255)' &&
    appKey.required === true, 'sts_appconfig.key keeps its length');
  const entries = model.tables.filter(function (table) {
    return table.name === 'sts_ldap_entries';
  })[0];
  const parent = columnNamed(entries, 'parent_key');
  t.check(parent && parent.generated === true &&
    parent.sqlType === 'VARCHAR(352)',
    'parent_key stays one generated column');
  const failures = model.tables.filter(function (table) {
    return table.name === 'sts_risk_failures';
  })[0];
  t.check(failures.constraints.some(function (piece) {
    return /^KEY sts_risk_failures_id\b/.test(piece);
  }), 'sts_risk_failures keeps its inline index');
  t.check(failures.columns.every(function (column) {
    return column.name !== 'KEY';
  }), 'that index is not a column');
  const parsed = model.gaps.filter(function (gap) {
    return gap.code === 'column-unparsed' ||
      gap.code === 'mariadb-type-unparsed' ||
      gap.code === 'table-unparsed' ||
      gap.code === 'mariadb-engine' ||
      gap.code === 'mariadb-statement-differs' ||
      gap.code === 'mariadb-only-in-script' ||
      gap.code === 'mariadb-only-in-module';
  });
  t.equal(parsed.map(function (gap) {
    return gap.code + ' ' + gap.name + ' ' + gap.detail;
  }).join('\n'), '', 'the script and the module are one schema');
  t.equal(model.objects.length, schema.SCHEMA_OBJECTS.length,
    'every module object is on the model');
  t.check(model.objects.every(function (object, index) {
    return object.statement === schema.SCHEMA_OBJECTS[index].statement;
  }), 'module statements are the module\'s own strings');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'model_mariadb',
  describe: 'the MariaDB script is emitted as its own bytes (#1390)',
  run: run
};
