// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: mariadb_import.ts
//
// ---------------------------------------------------------------------------
// THE MARIADB SCRIPT (#1390).
//
// MariaDB is the second store engine. It is written twice:
// `mariadb/schema.sql`, which an owner runs, and the statement strings in
// `persistence/schema_mariadb.js`, which the driver runs. This importer
// reads both. `emit()` returns the SQL file's own bytes. It does not
// format them, reorder them, translate a PostgreSQL statement, or drop a
// comment. The two copies are the same statements modulo whitespace
// (`tests/mariadb_schema.js` is that comparison). A statement that
// comparison cannot find in both copies is a gap. This module does not
// pick a winner, and it does not rewrite either file.
//
// Columns are split on commas only at parenthesis depth zero, because a
// generated expression contains commas. A back-quoted name (`key`) is an
// identifier. `KEY name (...)` inside a table is an index, not a column.
// Directory attributes do not become columns.
//
// A LIBRARY. No route. The schema module is required from `read()`, not
// from this file's top, so loading the importer does not load the store.
// ---------------------------------------------------------------------------

import fs = require('fs');
import path = require('path');
import { createRequire } from 'module';
import bunyan = require('bunyan');
import ModelIr = require('./model_ir');
import PostgresImport = require('./postgres_import');

const log = bunyan.createLogger({
  name: 'sts-mariadb-import',
  level: process.env.LOG_LEVEL || process.env.STS_LOG_LEVEL || 'info'
});

const requireFromHere = createRequire(__filename);

const ENGINE = 'ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 ' +
  'COLLATE=utf8mb4_nopad_bin';

interface MdColumn {
  name: string;
  raw: string;
  sqlType: string;
  required: boolean;
  generated: boolean;
}

interface MdTable {
  name: string;
  raw: string;
  columns: MdColumn[];
  constraints: string[];
  engine: string;
}

interface MdObject {
  name: string;
  statement: string;
}

interface MdGap {
  code: string;
  object: string;
  name: string;
  detail: string;
}

interface MdModel {
  sql: string;
  version: number;
  tables: MdTable[];
  objects: MdObject[];
  indexes: MdObject[];
  gaps: MdGap[];
}

/**
 * Reads both MariaDB DDL copies and emits the SQL file unchanged.
 */
class MariaDbImport {
  /**
   * Reads the schema file and the driver's statement list.
   *
   * @param root - the package root
   * @returns the model. `sql` is the file's bytes.
   */
  static read(root: string): MdModel {
    log.debug("Entering MariaDbImport.read().");
    const sqlPath = path.join(root, 'mariadb', 'schema.sql');
    const sql = fs.readFileSync(sqlPath, 'utf8');
    const schemaModule = requireFromHere(path.join(root, 'persistence',
      'schema_mariadb.js'));
    const model = MariaDbImport.build(sql, schemaModule);
    log.debug("Leaving MariaDbImport.read().");
    return model;
  }

  /**
   * Builds a model from texts the caller already has. Tests pass a
   * fixture here without loading the schema module.
   *
   * @param sql - the schema script
   * @param schemaModule - `schema_mariadb.js` exports, or null
   * @returns the model
   */
  static build(sql: string, schemaModule: any): MdModel {
    log.debug("Entering MariaDbImport.build().");
    const gaps: MdGap[] = [];
    const tables = MariaDbImport.tablesIn(sql, gaps);
    const scriptObjects = MariaDbImport.creates(sql);
    const objects = MariaDbImport.objectsOf(schemaModule);
    MariaDbImport.compareObjects(scriptObjects, objects, gaps);
    const indexes = scriptObjects.filter(function (object) {
      return /^CREATE (?:UNIQUE )?INDEX\b/i.test(object.statement);
    });
    const version = schemaModule &&
      typeof schemaModule.SCHEMA_VERSION === 'number' ?
      schemaModule.SCHEMA_VERSION : 0;
    const model = {
      sql: sql,
      version: version,
      tables: tables,
      objects: objects,
      indexes: indexes,
      gaps: ModelIr.sortGaps(gaps)
    };
    log.debug("Leaving MariaDbImport.build().");
    return model;
  }

  /**
   * The SQL file, unchanged.
   *
   * @param model - a model from `read()` or `build()`
   * @returns the file bytes stored on the model
   */
  static emit(model: MdModel): string {
    log.debug("Entering MariaDbImport.emit().");
    log.debug("Leaving MariaDbImport.emit().");
    return model.sql;
  }

  /**
   * The module's objects, in its order, as the strings it exports.
   *
   * @param schemaModule - the module exports, or null
   * @returns the objects
   */
  static objectsOf(schemaModule: any): MdObject[] {
    log.debug("Entering MariaDbImport.objectsOf().");
    const listed = schemaModule && schemaModule.SCHEMA_OBJECTS ?
      schemaModule.SCHEMA_OBJECTS : [];
    const objects = listed.map(function (object: any) {
      return { name: object.name, statement: object.statement };
    });
    log.debug("Leaving MariaDbImport.objectsOf().");
    return objects;
  }

  /**
   * CREATE statements in the script, comments removed, each without its
   * semicolon. The cut is `tests/mariadb_schema.js`'s: a semicolon ends
   * the statement, and the two copies are compared after `squash()`.
   *
   * @param sql - the script
   * @returns the creates, in script order
   */
  static creates(sql: string): MdObject[] {
    log.debug("Entering MariaDbImport.creates().");
    const code = sql.split('\n').filter(function (line) {
      return !/^\s*--/.test(line);
    }).join('\n');
    const found: MdObject[] = [];
    const re = /CREATE (?:TABLE|INDEX|UNIQUE INDEX) IF NOT EXISTS /g;
    let match = re.exec(code);
    while (match) {
      const start = match.index;
      const end = MariaDbImport.statementEnd(code, start);
      const statement = code.slice(start, end).replace(/;$/, '');
      const name = /^CREATE (?:TABLE|INDEX|UNIQUE INDEX) IF NOT EXISTS\s+([a-z_0-9]+)/i
        .exec(statement);
      if (name) {
        found.push({ name: name[1], statement: statement });
      }
      match = re.exec(code);
    }
    log.debug("Leaving MariaDbImport.creates().");
    return found;
  }

  /**
   * The index of the semicolon that ends the statement at `start`.
   * Quotes and back-quotes are skipped, so a semicolon inside one is
   * not the end.
   *
   * @param code - the script with comment lines removed
   * @param start - the start of the statement
   * @returns the index of `;`, or the length
   */
  static statementEnd(code: string, start: number): number {
    log.debug("Entering MariaDbImport.statementEnd().");
    let i = start;
    while (i < code.length) {
      const ch = code.charAt(i);
      if (ch === '\'' || ch === '"' || ch === '`') {
        i = PostgresImport.quoted(code, i, ch).next;
        continue;
      }
      if (ch === ';') {
        log.debug("Leaving MariaDbImport.statementEnd().");
        return i;
      }
      i += 1;
    }
    log.debug("Leaving MariaDbImport.statementEnd(). Unclosed.");
    return code.length;
  }

  /**
   * Records a create the two copies do not share. Whitespace is not a
   * difference: `squash()` is the same collapse as
   * `tests/mariadb_schema.js`.
   *
   * @param scriptObjects - creates from the SQL file
   * @param objects - creates from the module
   * @param gaps - the gap list
   */
  static compareObjects(scriptObjects: MdObject[], objects: MdObject[],
      gaps: MdGap[]): void {
    log.debug("Entering MariaDbImport.compareObjects().");
    scriptObjects.forEach(function (one, index) {
      const theirs = objects[index];
      if (!theirs) {
        gaps.push(ModelIr.gap('mariadb-only-in-script',
          one.name, 'mariadb', one.name));
        return;
      }
      const sameName = theirs.name === one.name;
      const sameText = MariaDbImport.squash(theirs.statement) ===
        MariaDbImport.squash(one.statement);
      if (!sameName || !sameText) {
        gaps.push(ModelIr.gap('mariadb-statement-differs',
          one.name, 'mariadb', one.name));
      }
    });
    objects.forEach(function (one, index) {
      if (index >= scriptObjects.length) {
        gaps.push(ModelIr.gap('mariadb-only-in-module',
          one.name, 'mariadb', one.name));
      }
    });
    log.debug("Leaving MariaDbImport.compareObjects().");
  }

  /**
   * Collapses whitespace the way `tests/mariadb_schema.js` does, so a
   * gap here is a gap that test would also report.
   *
   * @param text - one statement
   * @returns the comparable text
   */
  static squash(text: string): string {
    log.debug("Entering MariaDbImport.squash().");
    const flat = String(text).replace(/\s+/g, ' ').replace(/\( /g, '(')
      .replace(/ \)/g, ')').trim();
    log.debug("Leaving MariaDbImport.squash().");
    return flat;
  }

  /**
   * Every CREATE TABLE, with the engine clause that follows the body.
   *
   * @param sql - the script
   * @param gaps - the gap list
   * @returns the tables, in script order
   */
  static tablesIn(sql: string, gaps: MdGap[]): MdTable[] {
    log.debug("Entering MariaDbImport.tablesIn().");
    const tables: MdTable[] = [];
    const re = /CREATE TABLE IF NOT EXISTS\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/g;
    let match = re.exec(sql);
    while (match) {
      const open = match.index + match[0].length - 1;
      const close = PostgresImport.matchingParen(sql, open);
      if (close < 0) {
        gaps.push(ModelIr.gap('table-unparsed',
          'CREATE TABLE has no closing parenthesis.', 'mariadb',
          match[1]));
      } else {
        const raw = sql.slice(open + 1, close);
        const end = MariaDbImport.statementEnd(sql, close);
        const engine = sql.slice(close + 1, end).trim();
        tables.push(MariaDbImport.tableFrom(match[1], raw, engine,
          gaps));
      }
      match = re.exec(sql);
    }
    log.debug("Leaving MariaDbImport.tablesIn().");
    return tables;
  }

  /**
   * One table body.
   *
   * @param name - the table
   * @param raw - the text inside the parentheses
   * @param engine - the clause between `)` and `;`
   * @param gaps - the gap list
   * @returns the table
   */
  static tableFrom(name: string, raw: string, engine: string,
      gaps: MdGap[]): MdTable {
    log.debug("Entering MariaDbImport.tableFrom().");
    const parts = MariaDbImport.splitCsv(raw);
    const columns: MdColumn[] = [];
    const constraints: string[] = [];
    const primary: string[] = [];
    parts.forEach(function (part) {
      const piece = part.trim();
      if (!piece) {
        return;
      }
      if (MariaDbImport.isConstraint(piece)) {
        constraints.push(piece);
        const key = /^PRIMARY KEY\s*\(([^)]*)\)/i.exec(piece);
        if (key) {
          key[1].split(',').forEach(function (column) {
            primary.push(MariaDbImport.bareName(column));
          });
        }
        return;
      }
      const column = MariaDbImport.columnFrom(piece);
      if (!column) {
        gaps.push(ModelIr.gap('column-unparsed', piece.slice(0, 160),
          name, ''));
        return;
      }
      if (column.sqlType === 'unknown') {
        gaps.push(ModelIr.gap('mariadb-type-unparsed',
          piece.slice(0, 160), name, column.name));
      }
      columns.push(column);
    });
    columns.forEach(function (column) {
      if (primary.indexOf(column.name) >= 0) {
        column.required = true;
      }
    });
    if (engine !== ENGINE) {
      gaps.push(ModelIr.gap('mariadb-engine',
        'The table is not InnoDB with utf8mb4_nopad_bin.', name,
        name));
    }
    log.debug("Leaving MariaDbImport.tableFrom().");
    return {
      name: name,
      raw: raw,
      columns: columns,
      constraints: constraints,
      engine: engine
    };
  }

  /**
   * A table-body piece that is a key or a check, not a column. `KEY`
   * is MariaDB's inline index. A column named `key` is back-quoted, so
   * it does not start with that word.
   *
   * @param piece - trimmed SQL
   * @returns whether the piece is a constraint
   */
  static isConstraint(piece: string): boolean {
    log.debug("Entering MariaDbImport.isConstraint().");
    const constraint = /^(CONSTRAINT|PRIMARY KEY|UNIQUE|CHECK|FOREIGN KEY|KEY|INDEX)\b/i
      .test(piece);
    log.debug("Leaving MariaDbImport.isConstraint().");
    return constraint;
  }

  /**
   * One column piece. A back-quoted name is the same column as an
   * unquoted one.
   *
   * @param piece - trimmed SQL
   * @returns the column, or null
   */
  static columnFrom(piece: string): MdColumn | null {
    log.debug("Entering MariaDbImport.columnFrom().");
    const named = /^`([A-Za-z_][A-Za-z0-9_]*)`\s+([\s\S]+)$/.exec(piece) ||
      /^([A-Za-z_][A-Za-z0-9_]*)\s+([\s\S]+)$/.exec(piece);
    if (!named) {
      log.debug("Leaving MariaDbImport.columnFrom(). Not a column.");
      return null;
    }
    const column = {
      name: named[1],
      raw: piece,
      sqlType: MariaDbImport.sqlType(named[2]),
      required: /\bNOT NULL\b/i.test(piece),
      generated: /\bGENERATED\s+ALWAYS\b/i.test(piece)
    };
    log.debug("Leaving MariaDbImport.columnFrom().");
    return column;
  }

  /**
   * The type tokens at the start of a column's remainder, including a
   * length. `unknown` is a type this schema does not use.
   *
   * @param rest - the SQL after the column name
   * @returns the type, or `unknown`
   */
  static sqlType(rest: string): string {
    log.debug("Entering MariaDbImport.sqlType().");
    const match = /^([A-Za-z]+(?:\s+PRECISION)?(?:\(\d+\))?)/
      .exec(rest.trim());
    const sqlType = match ? match[1].replace(/\s+/g, ' ') : 'unknown';
    log.debug("Leaving MariaDbImport.sqlType().");
    return sqlType;
  }

  /**
   * An identifier with its quotes removed.
   *
   * @param token - one primary-key column
   * @returns the name
   */
  static bareName(token: string): string {
    log.debug("Entering MariaDbImport.bareName().");
    const name = token.trim().replace(/^[`"]+|[`"]+$/g, '');
    log.debug("Leaving MariaDbImport.bareName().");
    return name;
  }

  /**
   * Splits on commas that are not inside parentheses, quotes, or
   * back-quotes.
   *
   * @param body - a CREATE TABLE body
   * @returns the pieces, untrimmed
   */
  static splitCsv(body: string): string[] {
    log.debug("Entering MariaDbImport.splitCsv().");
    const parts: string[] = [];
    let current = '';
    let depth = 0;
    let i = 0;
    while (i < body.length) {
      const ch = body.charAt(i);
      if (ch === '\'' || ch === '"' || ch === '`') {
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
    log.debug("Leaving MariaDbImport.splitCsv().");
    return parts;
  }
}

export = MariaDbImport;
