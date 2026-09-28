// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
// File: attribute_source_drivers.ts
// ---------------------------------------------------------------------------
// THE DATABASES AN ATTRIBUTE SOURCE READS, THROUGH KNEX (#94, 2026-09-28).
//
// rcbj's decision on #94: Knex is this service's database layer, adopted in
// phases, and attribute sources are the first thing built on it (#326 moves
// the service's own PostgreSQL onto it next). A query builder rather than an
// ORM: an attribute source reads one row of a table somebody else owns, and
// there is no model of it here to map.
//
// **WHAT THIS FILE DOES AND NOTHING ELSE**: given a source's definition, it
// holds a pool, runs `SELECT <columns> FROM <table> WHERE <key> = ?` with the
// key BOUND, and hands back the columns as text. Which sources exist, what is
// written where and when is `attribute_sources.ts`.
//
//   * **THE DIALECTS.** PostgreSQL (`pg`, already the service's own driver)
//     and MySQL / MariaDB (`mysql2`) in this step; SQL Server (`tedious`)
//     and Oracle (`oracledb`, thin mode) are #94's next step. A driver is an
//     OPTIONAL package, installed into the image at build time
//     (`STS_CLOUD_SDKS="mysql2"`, as the cloud SDKs are), and Knex requires
//     it by name; a missing one is refused by name (STS-ATTR-0001).
//   * **TLS IS ALWAYS VERIFIED** — `OutboundTls.verifiedOptions()` (#201),
//     the helper every dialer outside the four families asks, with a source's
//     own CA file beside node's store and its own server name. There is no
//     plaintext and no switch to turn verification off: a database holding
//     people's attributes is exactly what is worth not reading in the clear.
//   * **THE STATEMENT IS BUILT, NEVER WRITTEN.** Knex builds it from
//     identifiers `attribute_sources.ts` validated against IDENTIFIER and
//     TABLE and quotes them; the one value in it, the person's key, is a
//     bound parameter. So no text an administrator types becomes SQL.
//   * **ONE POOL PER SOURCE PER PROCESS**, keyed by the realm and the
//     source, and rebuilt when anything the connection is built from changes
//     (`fingerprint()`), as the mail channel's transport is. A lookup that
//     fails for a reason that is not the query (connect, TLS, a password)
//     drops the pool, so the next one re-reads the password.
//   * **A CLIENT THAT DIES WHILE CHECKED OUT** is Knex's to hold — its `pg`
//     and `mysql2` clients listen for a connection's own error and dispose of
//     it — which is the hazard `persistence/CLAUDE.md` found in raw
//     `pg-pool`. Nothing here checks a client out by hand.
// ---------------------------------------------------------------------------

import fs = require('fs');
import helpers = require('../common/helpers');
import errorCodes = require('../common/error_codes');
import OutboundTls = require('../common/outbound_tls');
import secrets = require('../common/secrets');

type Json = Record<string, any>;

// What Knex's `client` is and which package it loads, per dialect. SQL Server
// and Oracle arrive with #94's next step.
const DIALECTS: Record<string, { client: string; driver: string;
                                 port: number }> = {
  postgres: { client: 'pg', driver: 'pg', port: 5432 },
  mysql: { client: 'mysql2', driver: 'mysql2', port: 3306 }
};

// A column or key name, and a table (optionally `schema.table`). Knex quotes
// them; these keep an identifier to one a person can read.
const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_$]{0,62}$/;
const TABLE = /^[A-Za-z_][A-Za-z0-9_$]{0,62}(\.[A-Za-z_][A-Za-z0-9_$]{0,62})?$/;

interface DriverDeps {
  log: { debug(m: string): void; info(m: string): void; warn(m: string): void };
  load(name: string): any;
  readSecret(source: Json): Promise<string | null>;
  readFile(path: string): string;
}

/**
 * The databases an attribute source reads, through Knex: a pool per source,
 * and one parameterised lookup.
 */
class AttributeSourceDrivers {
  private deps: DriverDeps;
  private pools: Map<string, { fingerprint: string; db: any }>;

  /**
   * Builds the drivers from their dependencies.
   *
   * @param deps - from `AttributeSourceDrivers.defaultDeps()`, or a test's
   */
  constructor(deps: DriverDeps) {
    deps.log.debug("Entering AttributeSourceDrivers.constructor().");
    this.deps = deps;
    this.pools = new Map();
    deps.log.debug("Leaving AttributeSourceDrivers.constructor().");
  }

  /**
   * The dependencies a running service gives the drivers.
   *
   * @returns the deps
   */
  static defaultDeps(): DriverDeps {
    helpers.log.debug("Entering AttributeSourceDrivers.defaultDeps().");
    helpers.log.debug("Leaving AttributeSourceDrivers.defaultDeps().");
    return {
      log: helpers.log,
      load: function (name: string) {
        return require(name);
      },
      readSecret: function (source: Json) {
        return secrets.readSourceSecret(source);
      },
      readFile: function (path: string) {
        return fs.readFileSync(path, 'utf8');
      }
    };
  }

  /**
   * The dialects this step supports.
   *
   * @returns their names
   */
  static dialects(): string[] {
    helpers.log.debug("Entering AttributeSourceDrivers.dialects().");
    helpers.log.debug("Leaving AttributeSourceDrivers.dialects().");
    return Object.keys(DIALECTS);
  }

  /**
   * A dialect's default port.
   *
   * @param dialect - the dialect
   * @returns the port, or 0 for one this step does not support
   */
  static defaultPort(dialect: string): number {
    helpers.log.debug("Entering AttributeSourceDrivers.defaultPort().");
    helpers.log.debug("Leaving AttributeSourceDrivers.defaultPort().");
    return DIALECTS[dialect] ? DIALECTS[dialect].port : 0;
  }

  /**
   * Says why a column, key or table name is not one this service builds a
   * statement from, or '' when it is.
   *
   * @param kind - `table` or `column`
   * @param value - the name
   * @returns the reason, or ''
   */
  static identifierProblem(kind: string, value: unknown): string {
    helpers.log.debug("Entering AttributeSourceDrivers.identifierProblem().");
    const text = String(value == null ? '' : value);
    const ok = kind === 'table' ? TABLE.test(text) : IDENTIFIER.test(text);
    helpers.log.debug("Leaving AttributeSourceDrivers.identifierProblem().");
    return ok ? '' : '"' + text + '" is not a ' + kind + ' name: letters, ' +
      'digits, _ and $, not starting with a digit' +
      (kind === 'table' ? ', optionally schema.table' : '') + '.';
  }

  // What the connection is built from, as one string: a change to any of it
  // rebuilds the pool.
  private fingerprint(source: Json): string {
    const { log } = this.deps;
    log.debug("Entering AttributeSourceDrivers.fingerprint().");
    log.debug("Leaving AttributeSourceDrivers.fingerprint().");
    return JSON.stringify([source.dialect, source.host, source.port,
      source.database, source.user, source.passwordProvider,
      source.passwordRef, source.passwordField, source.caFile,
      source.serverName, source.timeoutMs]);
  }

  // The coded error a failure becomes. `retry` is whether the pool should be
  // dropped and the next lookup build it again.
  private failure(code: string, why: string): Error {
    const { log } = this.deps;
    log.debug("Entering AttributeSourceDrivers.failure(). " + code);
    const error: any = errorCodes.mark(new Error(errorCodes.tag(code) + why),
                                       code);
    log.debug("Leaving AttributeSourceDrivers.failure().");
    return error;
  }

  private async pool(realmId: string, source: Json): Promise<any> {
    const { log, load, readSecret, readFile } = this.deps;
    log.debug("Entering AttributeSourceDrivers.pool(). " + source.id);
    const key = realmId + '\n' + source.id;
    const print = this.fingerprint(source);
    const held = this.pools.get(key);
    if (held && held.fingerprint === print) {
      log.debug("Leaving AttributeSourceDrivers.pool(). Held.");
      return held.db;
    }
    if (held) {
      this.close(realmId, source.id);
    }
    const dialect = DIALECTS[source.dialect];
    if (!dialect) {
      log.debug("Leaving AttributeSourceDrivers.pool(). No such dialect.");
      throw this.failure('STS-ATTR-0005', '"' + source.dialect + '" is not ' +
        'a dialect this service reads: ' + Object.keys(DIALECTS).join(', ') +
        '.');
    }
    let knex: any;
    try {
      const loaded = load('knex');
      knex = loaded && typeof loaded.knex === 'function' ? loaded.knex
                                                         : loaded;
      load(dialect.driver);
    } catch (e) {
      log.debug("Caught in AttributeSourceDrivers.pool(): " +
                ((e && e.message) || e));
      throw this.failure('STS-ATTR-0001', 'the ' + source.dialect +
        ' driver is not installed: build the image with STS_CLOUD_SDKS="' +
        dialect.driver + '" or run `npm install ' + dialect.driver + '` (' +
        ((e && e.message) || e) + ').');
    }
    let ca: string | null = null;
    if (source.caFile) {
      try {
        ca = readFile(String(source.caFile));
      } catch (e) {
        log.debug("Caught in AttributeSourceDrivers.pool(): " +
                  ((e && e.message) || e));
        throw this.failure('STS-ATTR-0002', 'the CA file ' + source.caFile +
          ' for attribute source ' + source.id + ' could not be read: ' +
          ((e && e.message) || e));
      }
    }
    const password = await readSecret({ realm: realmId, id: source.id,
      provider: source.passwordProvider, ref: source.passwordRef,
      field: source.passwordField });
    const tls = Object.assign(OutboundTls.verifiedOptions(ca),
                              { servername: String(source.serverName ||
                                                   source.host) });
    const connection: Json = {
      host: String(source.host), port: Number(source.port) ||
        dialect.port,
      database: String(source.database), user: String(source.user),
      ssl: tls
    };
    if (password !== null) {
      connection.password = password;
    }
    const timeout = Number(source.timeoutMs) || 2000;
    const db = knex({ client: dialect.client, connection: connection,
                      pool: { min: 0, max: 4 },
                      acquireConnectionTimeout: timeout });
    this.pools.set(key, { fingerprint: print, db: db });
    log.debug("Leaving AttributeSourceDrivers.pool(). Built.");
    return db;
  }

  /**
   * Drops a source's pool in this process.
   *
   * @param realmId - the realm
   * @param id - the source
   */
  close(realmId: string, id: string): void {
    const { log } = this.deps;
    log.debug("Entering AttributeSourceDrivers.close(). " + id);
    const key = realmId + '\n' + id;
    const held = this.pools.get(key);
    this.pools.delete(key);
    if (held && held.db && typeof held.db.destroy === 'function') {
      Promise.resolve(held.db.destroy()).catch(function (e) {
        log.debug("Caught in AttributeSourceDrivers.close(): " +
                  ((e && e.message) || e));
        // A pool that will not close is already gone from the map; nothing
        // uses it again.
      });
    }
    log.debug("Leaving AttributeSourceDrivers.close().");
  }

  // One value off a row, as the texts a directory attribute holds: an array
  // (a PostgreSQL array column) is several values, a date its ISO form, a
  // binary value nothing — no attribute here holds bytes from a source.
  // Called once per value of a row, so no Entering/Leaving pair — the
  // hot-path exception, stated here as the style requires.
  private textsOf(value: unknown): string[] {
    if (value === null || value === undefined) {
      return [];
    }
    if (Array.isArray(value)) {
      return ([] as string[]).concat(...value.map((one) => this.textsOf(one)));
    }
    if (value instanceof Date) {
      return [value.toISOString()];
    }
    if (Buffer.isBuffer(value)) {
      return [];
    }
    if (typeof value === 'object') {
      return [JSON.stringify(value)];
    }
    return [String(value)];
  }

  /**
   * Reads the row a person's key names: each column's values as text, or
   * null when no row matches.
   *
   * @param realmId - the realm
   * @param source - the source's definition
   * @param key - the person's key value
   * @returns `{ <column>: [texts] }`, or null for no row
   * @throws a coded Error: STS-ATTR-0001 (driver), 0002 (connection),
   *   0003 (timeout), 0004 (two rows), 0005 (dialect)
   */
  async lookup(realmId: string, source: Json, key: string):
      Promise<Record<string, string[]> | null> {
    const { log } = this.deps;
    log.debug("Entering AttributeSourceDrivers.lookup(). " + source.id);
    const db = await this.pool(realmId, source);
    const columns = Object.keys(source.columns || {});
    const timeout = Number(source.timeoutMs) || 2000;
    let rows: Json[];
    try {
      rows = await db.select(columns).from(String(source.table))
        .where(String(source.keyColumn), String(key)).limit(2)
        .timeout(timeout, { cancel: true });
    } catch (e) {
      log.debug("Caught in AttributeSourceDrivers.lookup(): " +
                ((e && e.message) || e));
      const timedOut = e && (e.name === 'KnexTimeoutError' ||
                             /timeout/i.test(String(e.message || '')));
      if (!timedOut) {
        this.close(realmId, source.id);
      }
      throw this.failure(timedOut ? 'STS-ATTR-0003' : 'STS-ATTR-0002',
        'attribute source ' + source.id + ' could not be read: ' +
        ((e && e.message) || e));
    }
    if (rows.length > 1) {
      log.debug("Leaving AttributeSourceDrivers.lookup(). Two rows.");
      throw this.failure('STS-ATTR-0004', 'attribute source ' + source.id +
        ' has more than one row whose ' + source.keyColumn + ' is the ' +
        'person\'s key; it names nobody.');
    }
    if (!rows.length) {
      log.debug("Leaving AttributeSourceDrivers.lookup(). No row.");
      return null;
    }
    const out: Record<string, string[]> = {};
    columns.forEach((column) => {
      out[column] = this.textsOf(rows[0][column]);
    });
    log.debug("Leaving AttributeSourceDrivers.lookup(). A row.");
    return out;
  }
}

export = AttributeSourceDrivers;
