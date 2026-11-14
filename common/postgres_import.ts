// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: postgres_import.ts
//
// ---------------------------------------------------------------------------
// THE PERSISTENCE NAMESPACE (#1390).
//
// PostgreSQL is written twice: `postgres/schema.sql` and the statement
// strings in `persistence/persistence_postgres.js`. This importer reads
// both. `emit()` returns the SQL file's own bytes. It does not format
// them, reorder them, or drop a comment. The two copies are not
// byte-identical to each other today — the driver concatenates string
// literals and the script is formatted SQL — and `tests/postgres_schema.js`
// already compares them with whitespace collapsed. A statement that
// comparison cannot find in both copies is a gap. This module does not
// pick a winner.
//
// Columns are split on commas only at parenthesis depth zero, because a
// generated expression contains commas. Directory attributes do not become
// columns. The four lookup links below are the ones the SQL comment
// already names. Nothing else is inferred.
//
// `assertAdditive()` refuses a model that drops or retypes a table or a
// column relative to an earlier model. It does not delete the DROP
// statements today's upgrades already contain: those statements are part
// of the current artifact and have to round-trip.
//
// MariaDB table names are read here only to list a PostgreSQL table the
// MariaDB module does not name. `mariadb/schema.sql` is emitted by
// `mariadb_import.ts`, as that file's own bytes.
//
// A LIBRARY. No route. The driver is required from `read()`, not from
// this file's top, so loading the importer does not load the store.
// ---------------------------------------------------------------------------

import fs = require('fs');
import path = require('path');
import { createRequire } from 'module';
import bunyan = require('bunyan');
import zodModule = require('zod');
import ModelIr = require('./model_ir');

const log = bunyan.createLogger({
  name: 'sts-postgres-import',
  level: process.env.LOG_LEVEL || process.env.STS_LOG_LEVEL || 'info'
});

const requireFromHere = createRequire(__filename);
const z: any = (zodModule as any).z;

/**
 * Lookup columns the schema comment already ties to directory attributes.
 * `name_keys` also holds other name attributes the codec writes; only
 * `uid` is named for that column in the parallel list.
 */
const LOOKUPS = [
  { table: 'sts_ldap_entries', column: 'name_keys',
    attributes: ['uid'] },
  { table: 'sts_ldap_entries', column: 'mail_keys',
    attributes: ['mail'] },
  { table: 'sts_ldap_entries', column: 'uuid_keys',
    attributes: ['entryUUID', 'stsEntryUuidAlias'] },
  { table: 'sts_ldap_entries', column: 'class_keys',
    attributes: ['objectClass'] }
];

const EXTENSIONS = ['pg_stat_statements', 'pg_trgm'];

interface PgColumn {
  name: string;
  raw: string;
  sqlType: string;
  required: boolean;
  generated: boolean;
  primaryKey: boolean;
  clauses: string;
  attributes: string[];
}

interface PgTable {
  name: string;
  raw: string;
  columns: PgColumn[];
  constraints: string[];
  placed: { at: number; text: string }[];
  head: string;
  suffix: string;
  tightClose: boolean;
  at: number;
}

interface PgGap {
  code: string;
  object: string;
  name: string;
  detail: string;
}

interface PgModel {
  sql: string;
  statements: string[];
  version: number;
  tables: PgTable[];
  indexes: string[];
  routines: { name: string; kind: string; statement: string }[];
  grants: string[];
  extensions: string[];
  driverSchema: string[];
  driverColumns: { table: string; column: string; statement: string }[];
  driverUpgrades: { name: string; statements: string[] }[];
  driverRetired: { name: string; statement: string }[];
  driverReloptions: { name: string; statement: string }[];
  gaps: PgGap[];
}

/**
 * Reads both DDL copies and emits the SQL file unchanged.
 */
class PostgresImport {
  /**
   * Reads the schema file and the driver's statement lists.
   *
   * @param root - the package root
   * @returns the model. `sql` is the file's bytes.
   */
  static read(root: string): PgModel {
    log.debug("Entering PostgresImport.read().");
    const sqlPath = path.join(root, 'postgres', 'schema.sql');
    const sql = fs.readFileSync(sqlPath, 'utf8');
    const driver = requireFromHere(path.join(root, 'persistence',
      'persistence_postgres.js'));
    const mariadb = fs.readFileSync(path.join(root, 'persistence',
      'schema_mariadb.js'), 'utf8');
    const model = PostgresImport.build(sql, driver, mariadb);
    log.debug("Leaving PostgresImport.read().");
    return model;
  }

  /**
   * Builds a model from texts the caller already has. Tests pass a
   * fixture here without loading the driver.
   *
   * @param sql - the schema script
   * @param driver - the driver's exported lists, or null in a fixture
   * @param mariadbSource - the MariaDB module source, or empty
   * @returns the model
   */
  static build(sql: string, driver: any, mariadbSource: string): PgModel {
    log.debug("Entering PostgresImport.build().");
    const gaps: PgGap[] = [];
    const tables = PostgresImport.tablesIn(sql, gaps);
    PostgresImport.attachLookups(tables, gaps);
    const statements = PostgresImport.statements(sql);
    PostgresImport.placeTables(tables, statements, gaps);
    const indexes = statements.filter(function (statement) {
      return /^CREATE (UNIQUE )?INDEX\b/i.test(statement);
    });
    const grants = statements.filter(function (statement) {
      return /^GRANT\b/i.test(statement) || /^REVOKE\b/i.test(statement);
    });
    const extensions = EXTENSIONS.filter(function (name) {
      return sql.indexOf(name) >= 0;
    });
    EXTENSIONS.forEach(function (name) {
      if (sql.indexOf(name) < 0) {
        gaps.push(ModelIr.gap('extension-missing',
          'The schema file does not name this extension.', 'postgres',
          name));
      }
    });
    const model: PgModel = {
      sql: sql,
      statements: statements,
      version: driver && typeof driver.SCHEMA_VERSION === 'number' ?
        driver.SCHEMA_VERSION : 0,
      tables: tables,
      indexes: indexes,
      routines: [],
      grants: grants,
      extensions: extensions,
      driverSchema: [],
      driverColumns: [],
      driverUpgrades: [],
      driverRetired: [],
      driverReloptions: [],
      gaps: []
    };
    if (driver) {
      PostgresImport.takeDriver(model, driver, statements, gaps);
    }
    PostgresImport.mariadbGaps(tables, mariadbSource || '', gaps);
    model.gaps = ModelIr.sortGaps(gaps);
    log.debug("Leaving PostgresImport.build().");
    return model;
  }

  /**
   * The SQL file, unchanged.
   *
   * @param model - a model from `read()` or `build()`
   * @returns the file bytes stored on the model
   */
  static emit(model: PgModel): string {
    log.debug("Entering PostgresImport.emit().");
    log.debug("Leaving PostgresImport.emit().");
    return model.sql;
  }

  /**
   * Copies the driver's lists and records a gap wherever the script
   * comparison used by `tests/postgres_schema.js` would fail.
   *
   * @param model - the model being filled
   * @param driver - `persistence_postgres.js` exports
   * @param statements - normalized script statements
   * @param gaps - the gap list
   */
  static takeDriver(model: PgModel, driver: any, statements: string[],
      gaps: PgGap[]): void {
    log.debug("Entering PostgresImport.takeDriver().");
    model.driverSchema = (driver.SCHEMA || []).slice();
    model.driverColumns = (driver.SCHEMA_COLUMNS || []).map(
      function (one: any) {
        return {
          table: one.table,
          column: one.column,
          statement: one.statement
        };
      });
    model.driverUpgrades = (driver.SCHEMA_UPGRADES || []).map(
      function (step: any) {
        return { name: step.name, statements: (step.statements || []).slice() };
      });
    model.driverRetired = (driver.SCHEMA_RETIRED || []).map(
      function (one: any) {
        return { name: one.name, statement: one.statement };
      });
    model.driverReloptions = (driver.SCHEMA_RELOPTIONS || []).map(
      function (one: any) {
        return { name: one.name, statement: one.statement };
      });
    model.routines = (driver.SCHEMA_ROUTINES || []).map(function (one: any) {
      return {
        name: one.name,
        kind: one.kind,
        statement: one.statement
      };
    });
    const scriptCreates = new Set(statements.filter(function (statement) {
      return /^CREATE (TABLE|INDEX)\b/i.test(statement) ||
        /^CREATE UNIQUE INDEX\b/i.test(statement);
    }));
    model.driverSchema.forEach(function (statement) {
      const normalized = PostgresImport.normalize(statement);
      if (!scriptCreates.has(normalized)) {
        gaps.push(ModelIr.gap('ddl-only-in-driver',
          normalized.slice(0, 160), 'postgres', ''));
      }
    });
    const driverCreates = new Set(model.driverSchema.map(
      function (statement) {
        return PostgresImport.normalize(statement);
      }));
    scriptCreates.forEach(function (statement) {
      if (!driverCreates.has(statement)) {
        gaps.push(ModelIr.gap('ddl-only-in-script',
          statement.slice(0, 160), 'postgres', ''));
      }
    });
    const scriptText = statements.join('\n');
    model.driverColumns.forEach(function (column) {
      const normalized = PostgresImport.normalize(column.statement);
      if (scriptText.indexOf(normalized) < 0) {
        gaps.push(ModelIr.gap('column-upgrade-not-in-script',
          normalized, column.table, column.column));
      }
    });
    model.routines.forEach(function (routine) {
      const normalized = PostgresImport.normalize(routine.statement);
      if (scriptText.indexOf(normalized) < 0) {
        gaps.push(ModelIr.gap('routine-not-in-script',
          routine.kind + ' ' + routine.name, 'postgres', routine.name));
      }
    });
    model.driverUpgrades.forEach(function (step) {
      step.statements.forEach(function (statement) {
        const normalized = PostgresImport.normalize(statement);
        if (scriptText.indexOf(normalized) < 0) {
          gaps.push(ModelIr.gap('upgrade-not-in-script',
            normalized.slice(0, 160), 'postgres', step.name));
        }
      });
    });
    const versionGap = 'The column list does not carry a schema version ' +
      'per column. The statement text is the artifact.';
    gaps.push(ModelIr.gap('column-version-unspecified', versionGap,
      'postgres', ''));
    log.debug("Leaving PostgresImport.takeDriver().");
  }

  /**
   * PostgreSQL tables whose name the MariaDB file does not use.
   *
   * @param tables - parsed PostgreSQL tables
   * @param source - `schema_mariadb.js` text
   * @param gaps - the gap list
   */
  static mariadbGaps(tables: PgTable[], source: string,
      gaps: PgGap[]): void {
    log.debug("Entering PostgresImport.mariadbGaps().");
    const names = new Set<string>();
    const re = /CREATE TABLE IF NOT EXISTS\s+([a-zA-Z0-9_]+)/g;
    let match = re.exec(source);
    while (match) {
      names.add(match[1]);
      match = re.exec(source);
    }
    tables.forEach(function (table) {
      if (!names.has(table.name)) {
        gaps.push(ModelIr.gap('mariadb-missing',
          'PostgreSQL has this table. The MariaDB file does not name it. ' +
          'That file is not changed here.', 'postgres', table.name));
      }
    });
    log.debug("Leaving PostgresImport.mariadbGaps().");
  }

  /**
   * Writes the lookup links onto columns the script actually has.
   *
   * @param tables - parsed tables
   * @param gaps - the gap list
   */
  static attachLookups(tables: PgTable[], gaps: PgGap[]): void {
    log.debug("Entering PostgresImport.attachLookups().");
    LOOKUPS.forEach(function (link) {
      const table = tables.filter(function (one) {
        return one.name === link.table;
      })[0];
      const column = table && table.columns.filter(function (one) {
        return one.name === link.column;
      })[0];
      if (!column) {
        gaps.push(ModelIr.gap('lookup-column-missing',
          'The schema comment names this lookup column and the script ' +
          'does not have it.', link.table, link.column));
        return;
      }
      column.attributes = link.attributes.slice();
    });
    log.debug("Leaving PostgresImport.attachLookups().");
  }

  /**
   * Finds each table's statement, so the model can say where in the
   * script it runs and what follows its closing parenthesis. A table
   * rebuilt from its columns that is not the script's statement is a gap.
   *
   * @param tables - parsed tables
   * @param statements - the script's statements
   * @param gaps - the gap list
   */
  static placeTables(tables: PgTable[], statements: string[],
      gaps: PgGap[]): void {
    log.debug("Entering PostgresImport.placeTables().");
    tables.forEach(function (table) {
      const at = statements.findIndex(function (statement) {
        return new RegExp('^CREATE TABLE( IF NOT EXISTS)? ' + table.name +
          ' \\(').test(statement);
      });
      if (at < 0) {
        gaps.push(ModelIr.gap('table-not-in-statements',
          'The parser found this table and the statement list did not.',
          'postgres', table.name));
        return;
      }
      table.at = at;
      table.head = /^CREATE TABLE IF NOT EXISTS/.test(statements[at]) ?
        'CREATE TABLE IF NOT EXISTS' : 'CREATE TABLE';
      let rebuilt = PostgresImport.rebuild(table);
      if (statements[at].indexOf(rebuilt) !== 0) {
        table.tightClose = true;
        rebuilt = PostgresImport.rebuild(table);
      }
      if (statements[at].indexOf(rebuilt) !== 0) {
        gaps.push(ModelIr.gap('table-not-rebuilt',
          'The columns and constraints do not rebuild the statement.',
          'postgres', table.name));
        return;
      }
      table.suffix = statements[at].slice(rebuilt.length).trim();
    });
    log.debug("Leaving PostgresImport.placeTables().");
  }

  /**
   * One table's CREATE statement, from its parts.
   *
   * @param table - the table
   * @returns the statement, whitespace normalized
   */
  static rebuild(table: PgTable): string {
    log.debug("Entering PostgresImport.rebuild().");
    const items: string[] = [];
    table.columns.forEach(function (column, index) {
      table.placed.filter(function (one) {
        return one.at === index;
      }).forEach(function (one) {
        items.push(one.text);
      });
      items.push(column.name + ' ' + column.sqlType +
        (column.clauses ? ' ' + column.clauses : ''));
    });
    table.placed.filter(function (one) {
      return one.at >= table.columns.length;
    }).forEach(function (one) {
      items.push(one.text);
    });
    const statement = table.head + ' ' + table.name + ' ( ' +
      items.join(', ') + (table.tightClose ? ')' : ' )');
    log.debug("Leaving PostgresImport.rebuild().");
    return statement;
  }

  /**
   * Every CREATE TABLE, with columns split at depth zero.
   *
   * @param sql - the script
   * @param gaps - the gap list
   * @returns the tables, in script order
   */
  static tablesIn(sql: string, gaps: PgGap[]): PgTable[] {
    log.debug("Entering PostgresImport.tablesIn().");
    const tables: PgTable[] = [];
    const re = /CREATE TABLE(?: IF NOT EXISTS)?\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/g;
    let match = re.exec(sql);
    while (match) {
      const open = match.index + match[0].length - 1;
      const close = PostgresImport.matchingParen(sql, open);
      if (close < 0) {
        gaps.push(ModelIr.gap('table-unparsed',
          'CREATE TABLE has no closing parenthesis.', 'postgres',
          match[1]));
      } else {
        const raw = sql.slice(open + 1, close);
        tables.push(PostgresImport.tableFrom(match[1], raw, gaps));
      }
      match = re.exec(sql);
    }
    log.debug("Leaving PostgresImport.tablesIn().");
    return tables;
  }

  /**
   * One table body.
   *
   * @param name - the table
   * @param raw - the text inside the parentheses
   * @param gaps - the gap list
   * @returns the table
   */
  static tableFrom(name: string, raw: string, gaps: PgGap[]): PgTable {
    log.debug("Entering PostgresImport.tableFrom().");
    const parts = PostgresImport.splitCsv(raw);
    const columns: PgColumn[] = [];
    const constraints: string[] = [];
    const primary: string[] = [];
    const placed: { at: number; text: string }[] = [];
    parts.forEach(function (part) {
      const piece = part.trim();
      if (!piece) {
        return;
      }
      if (/^(CONSTRAINT|PRIMARY KEY|UNIQUE|CHECK|FOREIGN KEY|EXCLUDE)\b/i
          .test(piece)) {
        constraints.push(piece);
        placed.push({ at: columns.length,
          text: PostgresImport.normalize(piece) });
        const key = /^PRIMARY KEY\s*\(([^)]*)\)/i.exec(piece);
        if (key) {
          key[1].split(',').forEach(function (column) {
            primary.push(column.trim());
          });
        }
        return;
      }
      const column = PostgresImport.columnFrom(piece);
      if (!column) {
        gaps.push(ModelIr.gap('column-unparsed', piece.slice(0, 160),
          name, ''));
        return;
      }
      columns.push(column);
    });
    columns.forEach(function (column) {
      if (primary.indexOf(column.name) >= 0) {
        column.required = true;
        column.primaryKey = true;
      }
    });
    log.debug("Leaving PostgresImport.tableFrom().");
    return {
      name: name,
      raw: raw,
      columns: columns,
      constraints: constraints,
      placed: placed,
      head: 'CREATE TABLE IF NOT EXISTS',
      suffix: '',
      tightClose: false,
      at: -1
    };
  }

  /**
   * One column piece. A piece that does not start with an identifier is
   * not a column.
   *
   * @param piece - trimmed SQL
   * @returns the column, or null
   */
  static columnFrom(piece: string): PgColumn | null {
    log.debug("Entering PostgresImport.columnFrom().");
    const name = /^"?([a-zA-Z_][a-zA-Z0-9_]*)"?\s+([\s\S]+)$/.exec(piece);
    if (!name) {
      log.debug("Leaving PostgresImport.columnFrom(). Not a column.");
      return null;
    }
    const sqlType = PostgresImport.sqlType(name[2]);
    const rest = PostgresImport.normalize(name[2]);
    // An inline PRIMARY KEY implies NOT NULL, and most of these tables
    // declare theirs that way.
    const primaryKey = /\bPRIMARY KEY\b/i.test(piece);
    const column = {
      name: name[1],
      raw: piece,
      sqlType: sqlType,
      required: /\bNOT NULL\b/i.test(piece) || primaryKey,
      generated: /\bGENERATED\s+ALWAYS\b/i.test(piece),
      primaryKey: primaryKey,
      clauses: rest.slice(sqlType.length).trim(),
      attributes: [] as string[]
    };
    log.debug("Leaving PostgresImport.columnFrom().");
    return column;
  }

  /**
   * The type tokens at the start of a column's remainder.
   *
   * @param rest - the SQL after the column name
   * @returns the type, or `unknown` when it does not match
   */
  static sqlType(rest: string): string {
    log.debug("Entering PostgresImport.sqlType().");
    const match = /^(double precision|character varying(?:\s*\(\d+\))?|timestamp (?:with|without) time zone|[a-zA-Z_][a-zA-Z0-9_]*(?:\s*\[[\s0-9]*\])?)/i
      .exec(rest.trim());
    const sqlType = match ? match[1].replace(/\s+/g, ' ') : 'unknown';
    log.debug("Leaving PostgresImport.sqlType().");
    return sqlType;
  }

  /**
   * Splits on commas that are not inside parentheses or quotes.
   *
   * @param body - a CREATE TABLE body
   * @returns the pieces, untrimmed
   */
  static splitCsv(body: string): string[] {
    log.debug("Entering PostgresImport.splitCsv().");
    const parts: string[] = [];
    let current = '';
    let depth = 0;
    let i = 0;
    while (i < body.length) {
      const ch = body.charAt(i);
      if (ch === "'" || ch === '"') {
        const eaten = PostgresImport.quoted(body, i, ch);
        current += eaten.text;
        i = eaten.next;
        continue;
      }
      if (ch === '(') {
        depth += 1;
      } else if (ch === ')') {
        depth -= 1;
      }
      if (ch === ',' && depth === 0) {
        parts.push(current);
        current = '';
        i += 1;
        continue;
      }
      current += ch;
      i += 1;
    }
    parts.push(current);
    log.debug("Leaving PostgresImport.splitCsv().");
    return parts;
  }

  /**
   * A quoted span, with doubled quotes kept.
   *
   * @param body - the text
   * @param start - the opening quote
   * @param quote - `'` or `"`
   * @returns the span including quotes, and the index after it
   */
  static quoted(body: string, start: number, quote: string): {
      text: string; next: number } {
    log.debug("Entering PostgresImport.quoted().");
    let i = start + 1;
    let text = quote;
    while (i < body.length) {
      const ch = body.charAt(i);
      text += ch;
      if (ch === quote && body.charAt(i + 1) === quote) {
        text += body.charAt(i + 1);
        i += 2;
        continue;
      }
      if (ch === quote) {
        log.debug("Leaving PostgresImport.quoted().");
        return { text: text, next: i + 1 };
      }
      i += 1;
    }
    log.debug("Leaving PostgresImport.quoted(). Unclosed.");
    return { text: text, next: body.length };
  }

  /**
   * The index of the parenthesis matching `open`.
   *
   * @param sql - the script
   * @param open - the index of `(`
   * @returns the index of `)`, or -1
   */
  static matchingParen(sql: string, open: number): number {
    log.debug("Entering PostgresImport.matchingParen().");
    let depth = 0;
    let i = open;
    while (i < sql.length) {
      const ch = sql.charAt(i);
      if (ch === "'" || ch === '"') {
        i = PostgresImport.quoted(sql, i, ch).next;
        continue;
      }
      if (ch === '(') {
        depth += 1;
      } else if (ch === ')') {
        depth -= 1;
        if (depth === 0) {
          log.debug("Leaving PostgresImport.matchingParen().");
          return i;
        }
      }
      i += 1;
    }
    log.debug("Leaving PostgresImport.matchingParen(). Unclosed.");
    return -1;
  }

  /**
   * Normalized statements, comments and psql meta-commands removed.
   * Semicolons inside dollar quotes stay inside the statement. This is
   * the same whitespace rule as `tests/postgres_schema.js`.
   *
   * @param sql - the script
   * @returns the statements
   */
  static statements(sql: string): string[] {
    log.debug("Entering PostgresImport.statements().");
    const body = sql.split('\n').filter(function (line) {
      return !/^\s*--/.test(line) && !/^\s*\\/.test(line);
    }).join('\n');
    const out: string[] = [];
    let current = '';
    let dollar = '';
    let i = 0;
    while (i < body.length) {
      if (dollar) {
        if (body.slice(i, i + dollar.length) === dollar) {
          current += dollar;
          i += dollar.length;
          dollar = '';
          continue;
        }
        current += body.charAt(i);
        i += 1;
        continue;
      }
      const tag = /^\$[A-Za-z0-9_]*\$/.exec(body.slice(i));
      if (tag) {
        dollar = tag[0];
        current += dollar;
        i += dollar.length;
        continue;
      }
      if (body.charAt(i) === "'") {
        const eaten = PostgresImport.quoted(body, i, "'");
        current += eaten.text;
        i = eaten.next;
        continue;
      }
      if (body.charAt(i) === ';' ) {
        const statement = PostgresImport.normalize(current);
        if (statement) {
          out.push(statement);
        }
        current = '';
        i += 1;
        continue;
      }
      current += body.charAt(i);
      i += 1;
    }
    const tail = PostgresImport.normalize(current);
    if (tail) {
      out.push(tail);
    }
    log.debug("Leaving PostgresImport.statements().");
    return out;
  }

  /**
   * Collapses whitespace. The two DDL copies differ only by it.
   *
   * @param statement - one statement
   * @returns the comparable text
   */
  static normalize(statement: string): string {
    log.debug("Entering PostgresImport.normalize().");
    const text = statement.replace(/\s+/g, ' ').trim();
    log.debug("Leaving PostgresImport.normalize().");
    return text;
  }

  /**
   * Problems that would drop or retype a table or a column. Empty when
   * `after` still has everything `before` has, with the same type token.
   *
   * @param before - the earlier model
   * @param after - the model a later emit would write
   * @returns the problems
   */
  static shapeProblems(before: PgModel, after: PgModel): string[] {
    log.debug("Entering PostgresImport.shapeProblems().");
    const problems: string[] = [];
    const afterTables = new Map<string, PgTable>();
    after.tables.forEach(function (table) {
      afterTables.set(table.name, table);
    });
    before.tables.forEach(function (table) {
      const next = afterTables.get(table.name);
      if (!next) {
        problems.push('dropped table ' + table.name);
        return;
      }
      const nextColumns = new Map<string, PgColumn>();
      next.columns.forEach(function (column) {
        nextColumns.set(column.name, column);
      });
      table.columns.forEach(function (column) {
        const kept = nextColumns.get(column.name);
        if (!kept) {
          problems.push('dropped column ' + table.name + '.' + column.name);
          return;
        }
        if (kept.sqlType !== column.sqlType) {
          problems.push('retyped ' + table.name + '.' + column.name);
        }
      });
    });
    log.debug("Leaving PostgresImport.shapeProblems().");
    return problems;
  }

  /**
   * Throws when `after` drops or retypes something `before` has.
   *
   * @param before - the earlier model
   * @param after - the candidate
   */
  static assertAdditive(before: PgModel, after: PgModel): void {
    log.debug("Entering PostgresImport.assertAdditive().");
    const problems = PostgresImport.shapeProblems(before, after);
    if (problems.length > 0) {
      log.debug("Leaving PostgresImport.assertAdditive(). Refused.");
      throw new Error(problems.join('; '));
    }
    log.debug("Leaving PostgresImport.assertAdditive().");
  }

  /**
   * Checks one row against the column types the DDL states. `unknown`
   * accepts any JSON value, which is what an unmapped type and `jsonb`
   * are here. This does not replace the driver.
   *
   * @param model - the model
   * @param tableName - the table
   * @param value - the candidate row
   * @returns whether it matches
   */
  static parseRow(model: PgModel, tableName: string, value: unknown): {
      ok: boolean; errors: string[] } {
    log.debug("Entering PostgresImport.parseRow().");
    const table = model.tables.filter(function (one) {
      return one.name === tableName;
    })[0];
    if (!table) {
      log.debug("Leaving PostgresImport.parseRow(). Unknown table.");
      return { ok: false, errors: ['unknown table ' + tableName] };
    }
    const shape: Record<string, any> = {};
    table.columns.forEach(function (column) {
      let field = PostgresImport.zodOf(column.sqlType);
      if (!column.required) {
        field = field.optional();
      }
      shape[column.name] = field;
    });
    const parsed = z.strictObject(shape).safeParse(value);
    if (!parsed.success) {
      const errors = parsed.error.issues.map(function (issue: any) {
        return issue.path.join('.') + ': ' + issue.message;
      });
      log.debug("Leaving PostgresImport.parseRow(). Rejected.");
      return { ok: false, errors: errors };
    }
    log.debug("Leaving PostgresImport.parseRow().");
    return { ok: true, errors: [] };
  }

  /**
   * A Zod schema for one SQL type token.
   *
   * @param sqlType - the type from the column
   * @returns the schema
   */
  static zodOf(sqlType: string): any {
    log.debug("Entering PostgresImport.zodOf().");
    const token = sqlType.toLowerCase();
    if (token === 'text' || token.indexOf('char') === 0) {
      log.debug("Leaving PostgresImport.zodOf(). string.");
      return z.string();
    }
    if (token === 'boolean') {
      log.debug("Leaving PostgresImport.zodOf(). boolean.");
      return z.boolean();
    }
    if (token === 'smallint' || token === 'integer' || token === 'int' ||
        token === 'real' || token === 'double precision') {
      log.debug("Leaving PostgresImport.zodOf(). number.");
      return z.number();
    }
    // The pg driver answers int8 as a string unless a parser says
    // otherwise, and this service installs none.
    if (token === 'bigint' || token === 'bigserial') {
      log.debug("Leaving PostgresImport.zodOf(). A number or its text.");
      return z.union([z.number(), z.string().regex(/^-?[0-9]+$/)]);
    }
    if (token === 'inet' || token === 'cidr' || token === 'xid8') {
      log.debug("Leaving PostgresImport.zodOf(). string.");
      return z.string();
    }
    if (token === 'text[]') {
      log.debug("Leaving PostgresImport.zodOf(). string array.");
      return z.array(z.string());
    }
    log.debug("Leaving PostgresImport.zodOf(). unknown.");
    return z.unknown();
  }
}

export = PostgresImport;
