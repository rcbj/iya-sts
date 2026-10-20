// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: persistence/knex_store.js
//
// ===========================================================================
// THE ONE DOOR TO POSTGRESQL (#326, 2026-10-19): Knex, and nothing else.
//
// Phase 2 of the database-layer decision made on #94 (rcbj, 2026-09-28):
// Knex is this service's one database access layer. Every connection this
// service makes to its own store — the driver's write pool and read pool,
// its liveness connection and its LISTEN connection, the directory bridge's
// thread, `bulk_import.js` and `cell_convert.js`, and the tests that open a
// database beside the service — is made HERE, by a Knex instance. `pg` is
// Knex's PostgreSQL driver and nothing else requires it (the done condition
// of #326; `tests/knex_store.js` holds it).
//
// **WHAT KNEX OWNS**: the driver (`pg`, loaded by Knex's dialect), the pool
// (tarn, through Knex's `acquireConnection()` / `releaseConnection()`), how
// a connection is made and validated and destroyed (the dialect's
// `acquireRawConnection()` / `destroyRawConnection()`), and the error
// listener every connection it makes carries.
//
// **WHAT IT DOES NOT OWN: THE STATEMENT TEXT, OR ITS BINDINGS.** Every
// statement this service sends is node-postgres `$1`…`$n` text — with
// `$n::type`, `ANY($n::text[])`, `unnest($n::jsonb[])` — and several hold a
// `?` that is PostgreSQL's, not a binding: the jsonb existence operators
// `?` and `?|` and a jsonpath filter's `?` (`directory_queries.js`'s asked
// names and holders, `classesUnder()`, the count trigger, `resealSealed()`).
// `knex.raw(sql, bindings)` counts `?` as its own placeholders: handed
// `$n` text and an array it refuses ("Expected N bindings, saw 0"), and a
// literal `?` it reads as a binding (`??` as an identifier) unless escaped
// `\?`. Rewriting 186 statements' placeholders to `?`, and escaping every
// operator correctly, is a rewrite of the SQL — which the ticket rules out
// ("no change in behaviour") and four tests pin (`EXPLAIN` of the builders'
// text, the DDL against `postgres/schema.sql`, one generated DELETE).
//
// **SO A STATEMENT GOES TO THE CONNECTION KNEX HOLDS**, as text and values,
// exactly as it did to the connection `pg-pool` held: `query(text, values)`
// here is the dialect's own connection's `query()`, called on a connection
// Knex acquired from its pool and is given back. That is the decision #326's
// plan (`persistence/326-sql.md`, deleted with this change) made and the
// review of #678 asked to be deliberate about; `persistence/CLAUDE.md`
// (*Knex is the one door*) is where it is argued for a reader. A query
// BUILDER is not used anywhere, and none is to be added by analogy: a
// builder that emits different SQL is a behaviour change, and every
// statement here is PostgreSQL's own (ON CONFLICT, RETURNING, FOR UPDATE,
// LISTEN, `pg_advisory_xact_lock`, jsonb, the `pg_stat` probes).
//
// **TRANSACTIONS STAY `BEGIN` / `COMMIT` ON ONE HELD CONNECTION**, for the
// same reason — Knex's `transaction()` runs its statements through the same
// `?` binder — and because the driver's flush is one transaction that
// records its change rows inside it and NOTIFYs only after COMMIT, which a
// held connection says outright.
//
// **NO ORM-LEVEL CACHE (rcbj on #326).** Nothing here remembers a row. Every
// cache stays in `common/cache_registry.js`, where the change log
// invalidates it across nodes; one below it would serve stale rows on other
// nodes. This module holds connections and nothing they returned.
//
// What carried over from `pg-pool`, each argued where it is:
//
//   * the LAZY REQUIRE — `knex` (and through it `pg`) is loaded by
//     `openPool()`, never by requiring this file, so `memory` and `ldif`
//     never need either package (`loadKnex()`);
//   * a CHECKED-OUT connection's errors — Knex's dialect gives every
//     connection a permanent `'error'` listener, so a database restarted
//     under a borrowed connection cannot be the process exit
//     `guardClient()` was written for (`persistence/CLAUDE.md`); the
//     driver's `guardClient()` still reports one (STS-STORE-0031);
//   * an IDLE connection's errors — reported to the pool's `'error'`
//     listeners, as `pg-pool`'s were (`watchIdle()`);
//   * a connection released WITH AN ERROR is not handed out again
//     (`giveBack()`);
//   * the bounds — a connection made within `connectionTimeoutMillis`, a
//     pool slot waited for no longer than that (`acquireTimeoutMillis`),
//     an idle connection closed after `idleTimeoutMillis`.
//
// The pool's reaper is tarn's own `setInterval`, running while the pool
// holds a connection and stopped when it is empty — a library's, in
// `node_modules`, which `tests/no_periodic_timers.js` does not read, and the
// same thing `pg-pool`'s per-client idle timers were. This module arms no
// timer: a dedicated connection that drops is opened again by the next
// statement or by the caller's own bounded retry, as before.
// ===========================================================================

const bunyan = require('bunyan');
const errorCodes = require('../common/error_codes');

const log = bunyan.createLogger({ name: 'sts-knex-store' });

// What Knex's own logger says goes to this module's debug lines: the
// failures it reports ("Acquire connection error", "Connection Error") reach
// the caller as the rejected promise, and the caller logs those under its
// own error code — a second line at warn from the library would say the same
// thing twice, untagged.
const KNEX_LOG = {
  debug: function (message) {
    log.debug("Knex: " + String(message));
  },
  warn: function (message) {
    log.debug("Knex warned: " + String(message));
  },
  error: function (message) {
    log.debug("Knex errored: " + String(message));
  },
  deprecate: function (message) {
    log.debug("Knex deprecation: " + String(message));
  }
};

// How long a connection may take to be made, and a pool slot to be waited
// for, where a caller says nothing: `pg-pool`'s `connectionTimeoutMillis`
// as this service set it.
const CONNECT_TIMEOUT_MS = 5000;
const IDLE_TIMEOUT_MS = 30000;

// The text of Knex's own "no pool slot came free in time" error
// (`KnexTimeoutError`), which `timedOutWaiting()` recognises.
const ACQUIRE_TIMEOUT_TEXT = /Timeout acquiring a connection/i;

/**
 * Loads Knex, lazily: see the header. The message names both packages,
 * because "Cannot find module 'knex'" arriving out of an identity service
 * is a sentence with no obvious cause.
 *
 * @returns Knex's constructor
 */
function loadKnex() {
  log.debug("Entering loadKnex().");
  let loaded;
  try {
    loaded = require('knex');
  } catch (err) {
    log.debug("Caught in loadKnex(): " + ((err && err.message) || err));
    log.debug("Leaving loadKnex(). Not installed.");
    throw notInstalled(err);
  }
  log.debug("Leaving loadKnex().");
  return loaded && typeof loaded.knex === 'function' ? loaded.knex : loaded;
}

/**
 * The refusal for a missing `knex` or `pg`.
 *
 * @param err - what the require or Knex said
 * @returns the error, tagged STS-STORE-0028
 */
function notInstalled(err) {
  log.debug("Entering notInstalled().");
  log.debug("Leaving notInstalled().");
  return new Error(errorCodes.tag('STS-STORE-0028') +
                   'persistence.mode is "postgres" but the "knex" package, ' +
                   'or the "pg" package it dials PostgreSQL with, is not ' +
                   'installed (' + String((err && err.message) || err) +
                   '). Run `npm install` in this package, or use ' +
                   'persistence.mode=ldif, which needs nothing but a ' +
                   'directory to write in.');
}

/**
 * Whether an error is Knex's "no pool slot came free in time" — what
 * `pg-pool` said as "timeout exceeded when trying to connect", and what the
 * driver's maintenance passes wait out and try again (`maintenance()`).
 * A connection the DATABASE did not answer within the connect timeout is
 * not this: it is `pg`'s own error, propagated as the acquire's.
 *
 * @param err - the error
 * @returns true for a wait for a pool slot that timed out
 */
function timedOutWaiting(err) {
  log.debug("Entering timedOutWaiting().");
  log.debug("Leaving timedOutWaiting().");
  return !!err && (err.name === 'KnexTimeoutError' ||
                   ACQUIRE_TIMEOUT_TEXT.test(String(err.message || err)));
}

// ---------------------------------------------------------------------------
// A CONNECTION CHECKED OUT OF THE POOL: the shape `pg-pool` handed out —
// `query()`, `release(err)`, `on()`, `removeListener()` — because that is
// the shape the driver's transactions, `bulk_import.js` and
// `cell_convert.js` were written against, and the statements they run are
// unchanged. `release()` gives the connection back to KNEX; a second call is
// ignored, as a client released twice is a pool corrupted.
// ---------------------------------------------------------------------------
class StoreClient {
  /**
   * @param pool - the StorePool it came from
   * @param connection - the dialect's connection Knex acquired
   */
  constructor(pool, connection) {
    log.debug("Entering StoreClient.constructor().");
    this.pool = pool;
    this.connection = connection;
    this.released = false;
    log.debug("Leaving StoreClient.constructor().");
  }

  /**
   * One statement, `$n` text and its values, on the held connection.
   *
   * @param text - the statement
   * @param [values] - its parameters
   * @returns the dialect's result (`rows`, `rowCount`)
   */
  query(text, values) {
    log.debug("Entering StoreClient.query().");
    log.debug("Leaving StoreClient.query().");
    return this.connection.query(text, values);
  }

  on(event, fn) {
    log.debug("Entering StoreClient.on(). " + event);
    this.connection.on(event, fn);
    log.debug("Leaving StoreClient.on().");
    return this;
  }

  removeListener(event, fn) {
    log.debug("Entering StoreClient.removeListener(). " + event);
    this.connection.removeListener(event, fn);
    log.debug("Leaving StoreClient.removeListener().");
    return this;
  }

  /**
   * Gives the connection back; with an error, it is never handed out again.
   *
   * @param [err] - why the borrower is giving it back broken, if it is
   */
  release(err) {
    log.debug("Entering StoreClient.release().");
    if (this.released) {
      log.debug("Leaving StoreClient.release(). Already released.");
      return;
    }
    this.released = true;
    this.pool.giveBack(this.connection, err);
    log.debug("Leaving StoreClient.release().");
  }
}

// ---------------------------------------------------------------------------
// A CONNECTION OF ITS OWN, OUTSIDE THE POOL — the LISTEN connection (a
// pooled one cannot hold a subscription: the pool hands it to the next
// caller), the liveness connection (a lease must not queue behind the
// writes), the directory bridge's thread, a test's connection beside the
// service. The shape is `pg.Client`'s — `on()`, `connect()`, `query()`,
// `end()` — and the connection is the dialect's, made by the SAME Knex
// instance as the pool it is asked of, so it dials the same database the
// same way: a listener with different TLS settings from the pool would be a
// second, weaker connection to the same store that nothing would report.
//
// Listeners given before `connect()` are attached the moment the connection
// exists, and Knex's own `'error'` listener is on it from before it
// connects, so no error is ever emitted with nobody listening.
// ---------------------------------------------------------------------------
class StoreConnection {
  /**
   * @param pool - the StorePool whose Knex instance dials it
   * @param [owned] - true when ending it also ends that pool (a connection
   *   opened by `openConnection()`, whose pool exists only for it)
   */
  constructor(pool, owned) {
    log.debug("Entering StoreConnection.constructor().");
    this.pool = pool;
    this.owned = !!owned;
    this.connection = null;
    this.listeners = [];
    this.ended = false;
    log.debug("Leaving StoreConnection.constructor().");
  }

  on(event, fn) {
    log.debug("Entering StoreConnection.on(). " + event);
    this.listeners.push({ event: event, fn: fn });
    if (this.connection) {
      this.connection.on(event, fn);
    }
    log.debug("Leaving StoreConnection.on().");
    return this;
  }

  /**
   * Dials, through the Knex instance's dialect.
   *
   * @returns this, connected
   */
  connect() {
    log.debug("Entering StoreConnection.connect().");
    const self = this;
    log.debug("Leaving StoreConnection.connect().");
    return Promise.resolve().then(function () {
      return self.pool.knex.client.acquireRawConnection();
    }).then(function (connection) {
      if (self.ended) {
        // Ended while it was being dialled: closed at once, not kept.
        return self.pool.knex.client.destroyRawConnection(connection)
          .catch(function (e) {
            log.debug("Caught in a callback in StoreConnection.connect(): " +
                      ((e && e.message) || e));
          }).then(function () {
            throw new Error('the connection was ended while it was being ' +
                            'made');
          });
      }
      self.connection = connection;
      self.listeners.forEach(function (one) {
        connection.on(one.event, one.fn);
      });
      return self;
    });
  }

  /**
   * One statement, `$n` text and its values.
   *
   * @param text - the statement
   * @param [values] - its parameters
   * @returns the dialect's result
   */
  query(text, values) {
    log.debug("Entering StoreConnection.query().");
    if (!this.connection) {
      log.debug("Leaving StoreConnection.query(). Not connected.");
      return Promise.reject(new Error('the connection is not open'));
    }
    log.debug("Leaving StoreConnection.query().");
    return this.connection.query(text, values);
  }

  /**
   * Closes it. Never rejects: closing a connection that has already gone
   * is the expected case after a drop, and there is nothing to report.
   *
   * @returns when it is closed
   */
  end() {
    log.debug("Entering StoreConnection.end().");
    this.ended = true;
    const connection = this.connection;
    const self = this;
    this.connection = null;
    const closed = connection
      ? this.pool.knex.client.destroyRawConnection(connection)
      : Promise.resolve();
    log.debug("Leaving StoreConnection.end().");
    return Promise.resolve(closed).catch(function (e) {
      log.debug("Caught in StoreConnection.end(): " +
                ((e && e.message) || e));
    }).then(function () {
      return self.owned ? self.pool.end() : null;
    });
  }
}

// ---------------------------------------------------------------------------
// A POOL: one Knex instance over one database. The shape is `pg.Pool`'s —
// `query()`, `connect()`, `on('error')`, `end()` — plus `stats()` (the
// numbers `/admin/database` draws, which `pg-pool` kept as properties) and
// `dedicated()`.
// ---------------------------------------------------------------------------
class StorePool {
  /**
   * @param knex - Knex's constructor
   * @param settings - `{ connectionString, ssl, connectionTimeoutMillis }`,
   *   what the dialect's `pg.Client` is given (`dialOptions()` decides the
   *   TLS, once, in `persistence_postgres.js`)
   * @param options - `max` (connections), `idleTimeoutMillis`
   */
  constructor(knex, settings, options) {
    log.debug("Entering StorePool.constructor().");
    const self = this;
    const opts = options || {};
    const connectMs = Number(settings.connectionTimeoutMillis) > 0
      ? Number(settings.connectionTimeoutMillis) : CONNECT_TIMEOUT_MS;
    this.idleListeners = [];
    // The connections a borrower holds: an error on one of them is the
    // borrower's (`guardClient()`), not the pool's idle report.
    this.held = new Set();
    this.max = Number(opts.max) > 0 ? Number(opts.max) : 4;
    try {
      this.knex = knex({
        client: 'pg',
        connection: Object.assign({}, settings,
                                  { connectionTimeoutMillis: connectMs }),
        log: KNEX_LOG,
        pool: {
          // Made on demand, as `pg-pool` made them: a process that never
          // writes holds no connection.
          min: 0,
          max: this.max,
          idleTimeoutMillis: Number(opts.idleTimeoutMillis) > 0
            ? Number(opts.idleTimeoutMillis) : IDLE_TIMEOUT_MS,
          // How long a caller waits for a slot: `pg-pool`'s
          // `connectionTimeoutMillis` bounded that wait too.
          acquireTimeoutMillis: connectMs,
          // A connection the database does not answer fails with `pg`'s own
          // connect timeout, which is the error a caller should see; tarn's
          // create timeout is set past it so that it never fires first.
          createTimeoutMillis: connectMs + 1000,
          // A failed connection fails the acquire waiting on it at once,
          // with the database's own reason, as `pg-pool` did.
          propagateCreateError: true,
          afterCreate: function (connection, done) {
            self.watchIdle(connection);
            done(null, connection);
          }
        }
      });
    } catch (err) {
      // Knex loads its dialect's driver as it is constructed, and says
      // "run npm install pg" when that fails.
      log.debug("Caught in StorePool.constructor(): " +
                ((err && err.message) || err));
      log.debug("Leaving StorePool.constructor(). Not installed.");
      throw notInstalled(err);
    }
    log.debug("Leaving StorePool.constructor().");
  }

  // An idle connection's error goes to the pool's listeners, as `pg-pool`
  // emitted it on the pool. Knex's own listener has already marked the
  // connection disposed, so the next acquire destroys it and makes another.
  watchIdle(connection) {
    log.debug("Entering StorePool.watchIdle().");
    const self = this;
    connection.on('error', function (err) {
      if (self.held.has(connection)) {
        return;
      }
      self.idleListeners.forEach(function (fn) {
        fn(err);
      });
    });
    log.debug("Leaving StorePool.watchIdle().");
  }

  on(event, fn) {
    log.debug("Entering StorePool.on(). " + event);
    if (event === 'error') {
      this.idleListeners.push(fn);
    }
    log.debug("Leaving StorePool.on().");
    return this;
  }

  /**
   * A connection from Knex's pool, held until `giveBack()`.
   *
   * @returns the dialect's connection
   */
  acquire() {
    log.debug("Entering StorePool.acquire().");
    const self = this;
    log.debug("Leaving StorePool.acquire().");
    return this.knex.client.acquireConnection().then(function (connection) {
      self.held.add(connection);
      return connection;
    });
  }

  /**
   * A held connection back to Knex's pool. With an error it is marked the
   * way Knex's own error listener marks a dead one (`__knex__disposed`), so
   * Knex's validation refuses it at the next acquire and destroys it: a
   * connection whose statement failed, or whose session could not be reset,
   * is not handed to the next caller — `pg-pool`'s `release(err)`.
   *
   * @param connection - the dialect's connection
   * @param [err] - why it is not to be reused
   */
  giveBack(connection, err) {
    log.debug("Entering StorePool.giveBack().");
    this.held.delete(connection);
    if (err) {
      connection.__knex__disposed = connection.__knex__disposed || err;
    }
    this.knex.client.releaseConnection(connection);
    log.debug("Leaving StorePool.giveBack().");
  }

  /**
   * A connection checked out for several statements (a transaction).
   *
   * @returns a StoreClient
   */
  connect() {
    log.debug("Entering StorePool.connect().");
    const self = this;
    log.debug("Leaving StorePool.connect().");
    return this.acquire().then(function (connection) {
      return new StoreClient(self, connection);
    });
  }

  /**
   * One statement on a pooled connection, given back when it answers; a
   * statement that fails gives it back broken (`pg-pool`'s `query()`).
   *
   * @param text - the statement
   * @param [values] - its parameters
   * @returns the dialect's result
   */
  query(text, values) {
    log.debug("Entering StorePool.query().");
    const self = this;
    log.debug("Leaving StorePool.query().");
    return this.acquire().then(function (connection) {
      return Promise.resolve().then(function () {
        return connection.query(text, values);
      }).then(function (result) {
        self.giveBack(connection);
        return result;
      }, function (err) {
        self.giveBack(connection, err);
        throw err;
      });
    });
  }

  /**
   * A connection of its own, outside the pool, dialled the pool's way.
   *
   * @returns a StoreConnection, not yet connected
   */
  dedicated() {
    log.debug("Entering StorePool.dedicated().");
    log.debug("Leaving StorePool.dedicated().");
    return new StoreConnection(this, false);
  }

  /**
   * The pool's own numbers, which are this PROCESS's and in no catalog
   * view: connections open (made, being made), idle, callers waiting, the
   * bound.
   *
   * @returns `{ total, idle, waiting, max }`
   */
  stats() {
    log.debug("Entering StorePool.stats().");
    const p = this.knex.client.pool;
    if (!p) {
      log.debug("Leaving StorePool.stats(). Ended.");
      return { total: 0, idle: 0, waiting: 0, max: this.max };
    }
    log.debug("Leaving StorePool.stats().");
    return {
      total: p.numUsed() + p.numFree() + p.numPendingCreates(),
      idle: p.numFree(),
      waiting: p.numPendingAcquires(),
      max: this.max
    };
  }

  /**
   * Closes every connection, waiting for the held ones to come back.
   *
   * @returns when the pool is closed
   */
  end() {
    log.debug("Entering StorePool.end().");
    log.debug("Leaving StorePool.end().");
    return this.knex.destroy();
  }
}

/**
 * A pool over one database.
 *
 * @param settings - `{ connectionString, ssl, connectionTimeoutMillis }`
 * @param [options] - `max`, `idleTimeoutMillis`
 * @returns a StorePool
 */
function openPool(settings, options) {
  log.debug("Entering openPool().");
  const pool = new StorePool(loadKnex(), settings || {}, options || {});
  log.debug("Leaving openPool().");
  return pool;
}

/**
 * One connection over one database, with nothing else: a pool of its own
 * that never holds a connection, ended with it.
 *
 * @param settings - as `openPool()`'s
 * @returns a StoreConnection, not yet connected
 */
function openConnection(settings) {
  log.debug("Entering openConnection().");
  const connection = new StoreConnection(openPool(settings, { max: 1 }),
                                         true);
  log.debug("Leaving openConnection().");
  return connection;
}

module.exports = {
  openPool: openPool,
  openConnection: openConnection,
  timedOutWaiting: timedOutWaiting
};
