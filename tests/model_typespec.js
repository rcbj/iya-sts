// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: model_typespec.js
//
// ---------------------------------------------------------------------------
// THE TYPESPEC COMPILES, AND WHAT COMES OUT OF IT IS THE SOURCES (#1390).
//
// `application` is the object already switched: its TypeSpec is the source
// and `common/applications.js` reads what the build generated from it.
//
// `models/main.tsp` goes through the real compiler. Every SCHEMA table is
// rebuilt from the compiled program and has to equal the table in code, and
// every statement of `postgres/schema.sql` likewise. An edit made to a copy
// of the TypeSpec has to reach the emitted output, because that is the
// difference between a model and a description of one. The classes are
// compiled and run, since a substring test once passed on classes with no
// commas between their fields.
// ---------------------------------------------------------------------------

const fs = require('fs');
const os = require('os');
const path = require('path');
const url = require('url');
const { spawnSync } = require('child_process');

const log = require('bunyan').createLogger({
  name: 'model_typespec',
  level: process.env.LOG_LEVEL || 'info'
});

const ROOT = path.join(__dirname, '..');

async function toolchain() {
  log.debug("Entering toolchain().");
  const compiler = await import(url.pathToFileURL(path.join(__dirname,
    'node_modules', '@typespec', 'compiler', 'dist', 'src', 'index.js')).href);
  const lib = await import(url.pathToFileURL(path.join(ROOT, 'models', 'lib',
    'model_lib.mjs')).href);
  log.debug("Leaving toolchain().");
  return { compiler: compiler, lib: lib };
}

async function compiled(tools, modelsDir) {
  log.debug("Entering compiled().");
  const program = await tools.compiler.compile(tools.compiler.NodeHost,
    path.join(modelsDir, 'main.tsp'), { noEmit: true });
  log.debug("Leaving compiled().");
  return program;
}

function errorsOf(program) {
  log.debug("Entering errorsOf().");
  const errors = program.diagnostics.filter(function (one) {
    return one.severity === 'error';
  }).map(function (one) {
    return one.code + ': ' + one.message;
  });
  log.debug("Leaving errorsOf().");
  return errors;
}

function schemas() {
  log.debug("Entering schemas().");
  const directory = require('../common/directory_model');
  const deps = directory.DirectoryModel.defaultDeps();
  const out = {};
  directory.SCHEMA_OWNERS.forEach(function (owner) {
    out[owner.id] = deps.load(owner.modulePath).SCHEMA;
  });
  deps.load('../admin-core/policy_kinds').list().forEach(function (kind) {
    out['policy.' + kind.id] = kind.module.SCHEMA;
  });
  log.debug("Leaving schemas().");
  return out;
}

function roundTrips(t, tools, objects) {
  log.debug("Entering roundTrips().");
  const ModelIr = require('../common/model_ir');
  const tables = schemas();
  Object.keys(tables).forEach(function (id) {
    const object = objects.filter(function (one) {
      return one.id === id;
    })[0];
    t.check(!!object, 'the compiled model has ' + id);
    if (object) {
      if (object.authored) {
        // `common/applications.js` adds each row's `editable` once it has
        // loaded the table, so what is compared is the file it read.
        t.equal(JSON.stringify(tools.lib.schemaOf(object)),
          fs.readFileSync(path.join(ROOT, 'models', 'generated',
            id + '.schema.json'), 'utf8'),
          id + ', written by hand, is the file the service reads');
        t.equal((tables[id].attributes || []).length, object.attributes.length,
          id + ': the service loaded every row');
        return;
      }
      t.equal(ModelIr.stable(tools.lib.schemaOf(object)),
        ModelIr.stable(tables[id]),
        id + ' rebuilt from the compiled model is its SCHEMA table');
    }
  });
  log.debug("Leaving roundTrips().");
}

function federationLists(t, objects) {
  log.debug("Entering federationLists().");
  // The lists are written once, in the model, and the code reads them. A
  // mechanism or policy has a row of behaviour in the code too, so each list
  // is held to those rows: an id with no behaviour would fail at sign-in.
  const federation = require('../federation/federation');
  const object = objects.filter(function (one) {
    return one.id === 'federationRelationship';
  })[0];
  const expected = {
    fedSubjectPolicy: federation.SUBJECT_POLICY_IDS,
    fedEncryptionKeyType: federation.ENCRYPTION_KEY_TYPES,
    fedKeyManagementAlgorithm: federation.XML_KEY_MANAGEMENT.concat(
      federation.JOSE_KEY_MANAGEMENT),
    fedContentEncryptionAlgorithm: federation.XML_CONTENT_ENCRYPTION.concat(
      federation.JOSE_CONTENT_ENCRYPTION),
    fedAuthnMechanism: federation.MECHANISM_IDS
  };
  t.equal(federation.MECHANISMS.map(function (one) {
    return one.mechanism;
  }).join(','), federation.MECHANISM_IDS.join(','),
  'every federation mechanism in the model has its row in the code');
  t.equal(federation.SUBJECT_POLICIES.map(function (one) {
    return one.policy;
  }).join(','), federation.SUBJECT_POLICY_IDS.join(','),
  'every subject policy in the model has its row in the code');
  Object.keys(expected).forEach(function (name) {
    const row = object.attributes.filter(function (one) {
      return one.name === name;
    })[0];
    t.equal(row && row.allowed && row.allowed.join(','),
      expected[name].join(','), name + ': the model\'s values are the code\'s');
  });
  log.debug("Leaving federationLists().");
}

function policyFields(t, tools, objects) {
  log.debug("Entering policyFields().");
  const directory = require('../common/directory_model');
  const deps = directory.DirectoryModel.defaultDeps();
  deps.load('../admin-core/policy_kinds').list().forEach(function (kind) {
    const object = objects.filter(function (one) {
      return one.id === 'policy.' + kind.id;
    })[0];
    const declared = tools.lib.fieldsOf(object);
    const have = kind.module.FIELDS.map(function (row) {
      return row.key;
    });
    declared.fields.forEach(function (row) {
      t.check(have.indexOf(row.key) >= 0,
        kind.id + ': the service has the model\'s setting ' + row.key);
    });
    // A row the code computes (a mechanism, a door) has its sentence in
    // the published table too, so the two are held equal here.
    kind.module.FIELDS.forEach(function (row) {
      t.check(row.dflt !== undefined && !!row.type && !!row.what,
        kind.id + '.' + row.key + ' is complete once the code has bound it');
      const published = kind.module.SCHEMA.attributes.filter(function (one) {
        return one.name === row.attribute;
      })[0];
      t.equal(published && published.what, row.what,
        kind.id + '.' + row.key + ': the table says what the setting says');
    });
  });
  log.debug("Leaving policyFields().");
}

function namesAreTheService(t, tools, program) {
  log.debug("Entering namesAreTheService().");
  const names = tools.lib.readSpellings(program);
  const generated = JSON.parse(fs.readFileSync(path.join(ROOT, 'models',
    'generated', 'directory.names.json'), 'utf8'));
  t.equal(JSON.stringify(names), JSON.stringify(generated),
    'the name lists in the service are the ones in the model');
  log.debug("Leaving namesAreTheService().");
}

function columnsAreInTheModel(t, persistence) {
  log.debug("Entering columnsAreInTheModel().");
  // An upgrade's ALTER is migration history and stays in the driver, so
  // each one is held to the column the model says the table has.
  const driver = require('../persistence/persistence_postgres');
  driver.SCHEMA_COLUMNS.forEach(function (one) {
    const table = persistence.tables.filter(function (row) {
      return row.name === one.table;
    })[0];
    const column = table && table.columns.filter(function (row) {
      return row.name === one.column;
    })[0];
    t.check(!!column && one.statement.replace(/\s+/g, ' ').indexOf(
      ' ' + one.column + ' ' + column.sqlType) >= 0,
      one.table + '.' + one.column + ': the upgrade adds what the model has');
  });
  log.debug("Leaving columnsAreInTheModel().");
}

function classesRun(t, objects, persistence) {
  log.debug("Entering classesRun().");
  const ModelEmit = require('../common/model_emit');
  const dir = fs.mkdtempSync(path.join(ROOT, 'common', '.model-classes-'));
  try {
    const parts = ["import { z } from 'zod';"];
    const names = [];
    objects.forEach(function (object) {
      if (object.projectionOf) {
        return;
      }
      parts.push(ModelEmit.directoryClass(object));
      names.push(ModelEmit.className(object.id));
    });
    persistence.tables.forEach(function (table) {
      parts.push(ModelEmit.tableClass(table));
    });
    parts.push('export { ' + names.join(', ') + ' };');
    const file = path.join(dir, 'classes.ts');
    fs.writeFileSync(file, parts.join('\n\n') + '\n');
    const tsc = spawnSync(path.join(__dirname, 'node_modules', '.bin', 'tsc'),
      ['--ignoreConfig', '--noEmit', '--skipLibCheck', '--target', 'es2020',
        '--module', 'preserve', '--esModuleInterop', '--moduleResolution',
        'bundler', file], { encoding: 'utf8', cwd: ROOT });
    t.check(tsc.status === 0, 'the generated classes compile',
      String(tsc.stdout).slice(0, 600));
    const out = path.join(dir, 'classes.js');
    fs.writeFileSync(out, require('esbuild').transformSync(
      fs.readFileSync(file, 'utf8'),
      { loader: 'ts', format: 'cjs' }).code);
    const classes = require(out);
    const schema = classes.Application.schema();
    t.check(schema.safeParse({ appIdentifier: 'x' }).success,
      'the generated Application accepts its own attribute');
    t.check(!schema.safeParse({ notAField: 'x' }).success,
      'the generated Application refuses a key it does not declare');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  log.debug("Leaving classesRun().");
}

async function editsReachTheOutput(t, tools) {
  log.debug("Entering editsReachTheOutput().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'model-edit-'));
  try {
    fs.cpSync(path.join(ROOT, 'models'), dir, { recursive: true });
    fs.symlinkSync(path.join(ROOT, 'node_modules'),
      path.join(dir, 'node_modules'));
    const directoryFile = path.join(dir, 'directory', 'application.tsp');
    fs.writeFileSync(directoryFile, fs.readFileSync(directoryFile, 'utf8')
      .replace(/model Application \{/,
        'model Application {\n  @attr(#{kind: "single", what: "w"})\n' +
        '  modelAuthoredField?: string;'));
    const tableFile = path.join(dir, 'persistence', 'persistence.tsp');
    fs.writeFileSync(tableFile, fs.readFileSync(tableFile, 'utf8')
      .replace(/model StsRealms \{/,
        'model StsRealms {\n  @column(#{sql: "text"})\n' +
        '  model_authored_column?: string;'));
    const program = await compiled(tools, dir);
    t.equal(errorsOf(program).join('\n'), '', 'the edited copy compiles');
    const objects = tools.lib.readDirectory(program);
    const application = objects.filter(function (one) {
      return one.id === 'application';
    })[0];
    t.equal(tools.lib.schemaOf(application).attributes[0].name,
      'modelAuthoredField', 'a field written in TypeSpec reaches the SCHEMA');
    const ModelEmit = require('../common/model_emit');
    t.check(ModelEmit.directoryClass(application)
      .indexOf('modelAuthoredField') >= 0,
      'a field written in TypeSpec reaches the class');
    t.check(tools.lib.readPersistence(program).objects.some(
      function (object) {
        return object.statement.indexOf('model_authored_column text') >= 0;
      }), 'a column written in TypeSpec reaches the DDL');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  log.debug("Leaving editsReachTheOutput().");
}

function ldapDefinitions(t, objects) {
  log.debug("Entering ldapDefinitions().");
  const ModelEmit = require('../common/model_emit');
  const rfc = JSON.parse(fs.readFileSync(path.join(ROOT, 'models', 'directory',
    'rfc_schema.json'), 'utf8'));
  const schema = ModelEmit.ldapSchema(objects);
  const cn = schema.attributeTypes.filter(function (one) {
    return one.indexOf("NAME 'cn'") >= 0;
  })[0];
  t.equal(cn, "( 2.5.4.3 NAME 'cn' SUP name EQUALITY caseIgnoreMatch SUBSTR " +
    'caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )',
    'cn is written as RFC 4519 defines it');
  const register = JSON.parse(fs.readFileSync(path.join(ROOT, 'models',
    'directory', 'oid_register.json'), 'utf8'));
  let invented = 0;
  const wrong = function (row, fact, arc, number) {
    const own = number === undefined ? null :
      register.root + arc + String(number);
    return row.oid && (fact ? fact.oid !== row.oid : own !== row.oid);
  };
  objects.forEach(function (object) {
    object.attributes.concat(object.personAttributes).forEach(function (row) {
      if (wrong(row, rfc.attributes[row.name.toLowerCase()], '.1.1.',
          register.attributes[row.name])) {
        invented += 1;
      }
    });
    object.objectClasses.forEach(function (row) {
      if (wrong(row, rfc.classes[row.name.toLowerCase()], '.1.2.',
          register.classes[row.name])) {
        invented += 1;
      }
    });
  });
  t.equal(invented, 0,
    'every OID is an RFC\'s or comes from this service\'s register');
  ['attributes', 'classes'].forEach(function (kind) {
    const numbers = Object.values(register[kind]);
    t.equal(new Set(numbers).size, numbers.length,
      'no two ' + kind + ' share a number');
  });
  t.check(schema.withoutOid.indexOf('stsApplication') < 0,
    'a name of this service has an OID');
  t.check(schema.withoutOid.indexOf('groupOfURLs') >= 0,
    'a name somebody else publishes is listed rather than given one of ours');
  t.check(schema.objectClasses.some(function (one) {
    return /NAME 'stsApplication' SUP top AUXILIARY/.test(one);
  }), 'a class beside a published structural class is auxiliary to it');
  log.debug("Leaving ldapDefinitions().");
}

function firstDifference(index, expected, actual) {
  log.debug("Entering firstDifference().");
  let at = 0;
  while (at < expected.length && expected.charAt(at) === actual.charAt(at)) {
    at += 1;
  }
  const text = 'statement ' + index + ' differs at ' + at + ', expected ' +
    expected.slice(Math.max(0, at - 40), at + 80) + ' got ' +
    actual.slice(Math.max(0, at - 40), at + 80);
  log.debug("Leaving firstDifference().");
  return text;
}

function sameStatements(t, actual, expected) {
  log.debug("Entering sameStatements().");
  const at = expected.findIndex(function (statement, index) {
    return statement !== actual[index];
  });
  t.check(at < 0 && actual.length === expected.length,
    'the DDL from the compiled model is postgres/schema.sql, statement by ' +
    'statement', at < 0 ? String(actual.length) + ' statements' :
      firstDifference(at, expected[at], String(actual[at])));
  log.debug("Leaving sameStatements().");
}

async function run(t) {
  log.debug("Entering run().");
  const tools = await toolchain();
  const program = await compiled(tools, path.join(ROOT, 'models'));
  t.equal(errorsOf(program).join('\n'), '',
    'models/main.tsp compiles with the TypeSpec compiler');
  const objects = tools.lib.readDirectory(program);
  const persistence = tools.lib.readPersistence(program);
  roundTrips(t, tools, objects);
  federationLists(t, objects);
  policyFields(t, tools, objects);
  const PostgresImport = require('../common/postgres_import');
  const sql = PostgresImport.read(ROOT);
  const script = tools.lib.renderScript(fs.readFileSync(path.join(ROOT,
    'models', 'persistence', 'schema.template.sql'), 'utf8'), persistence);
  t.equal(script, fs.readFileSync(path.join(ROOT, 'postgres', 'schema.sql'),
    'utf8'), 'postgres/schema.sql is what the model generates');
  sameStatements(t, PostgresImport.statements(script), sql.statements);
  columnsAreInTheModel(t, persistence);
  const mariadb = tools.lib.readPersistence(program, 'mariadb');
  t.equal(tools.lib.renderScript(fs.readFileSync(path.join(ROOT, 'models',
    'persistence', 'mariadb.template.sql'), 'utf8'), mariadb),
    fs.readFileSync(path.join(ROOT, 'mariadb', 'schema.sql'), 'utf8'),
    'mariadb/schema.sql is what the model generates');
  t.equal(mariadb.version, persistence.version,
    'one schema version across both engines');
  t.equal(persistence.version, sql.version, 'the schema version');
  const directory = require('../common/directory_model');
  ldapDefinitions(t, new directory.DirectoryModel(
    directory.DirectoryModel.defaultDeps()).collect().objects);
  namesAreTheService(t, tools, program);
  classesRun(t, objects, persistence);
  await editsReachTheOutput(t, tools);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'model_typespec',
  run: run
};
