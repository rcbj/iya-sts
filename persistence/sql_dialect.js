// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: sql_dialect.js
//
// ---------------------------------------------------------------------------
// ONE STORE, SEVERAL DATABASES: WHAT DIFFERS BETWEEN THEM, IN ONE PLACE (#677).
//
// rcbj's decisions on #677 (2026-11-03): PostgreSQL is and stays the primary
// store; MariaDB is a second engine the suite runs against; and the store's
// SQL is split three ways —
//
//   A. ORDINARY STATEMENTS are written ONCE with the Knex query builder and
//      compiled here for the engine in use. Where an engine differs only by a
//      small piece — the statement clock, a JSON cast — the piece is a
//      fragment from this module, spliced in as `knex.raw()`.
//   B. A STATEMENT THAT NEEDS ONE ENGINE'S FEATURE (jsonb `?`, a conditional
//      `ON CONFLICT … WHERE`, `ctid`) keeps hand-written text per engine, and
//      PostgreSQL's is the text this driver always sent.
//   C. WHERE THE DESIGN ITSELF DIFFERS (counting triggers, GIN indexes,
//      LISTEN) the engine has code of its own. `capabilities` says which.
//
// THE COMPILER HAS NO CONNECTION. `knex({ client })` with no `connection`
// builds and compiles statements and dials nothing; `toSQL().toNative()`
// answers the engine's own placeholders (`$1` for PostgreSQL, `?` for
// MariaDB) and its values. That is what makes the builder fit this driver:
// a compiled statement is text and values, and it goes to the connection the
// Knex pool holds exactly as the hand-written text does — inside the same
// held-connection `BEGIN`/`COMMIT`, beside the same fence. `knex.raw()` and
// `knex.transaction()` are not used to RUN anything, because both put a
// statement through Knex's `?` binder, which eats jsonb's `?` (#326).
//
// EVERY COMPILED STATEMENT CARRIES ITS NAME as a trailing comment,
// `/* sts:<name> */`. A test's database double answers by the name rather
// than by the text (whose quoting and placeholders are the compiler's, and
// move with a Knex upgrade), and an operator reading `pg_stat_activity` or
// MariaDB's processlist sees which operation a statement is. Trailing, so a
// double anchored on `^INSERT` still matches while the doubles move over.
//
// A LEAF but for the error-code table: it requires `knex` LAZILY, inside
// create() — so memory and ldif mode never need the package — and a missing
// one is STS-STORE-0028, as from `knex_store.js`. It is the second file of
// the store allowed to require `knex` (`tests/knex_store.js`), because it
// only COMPILES: no connection is ever made from here. Not through
// `knex_store.js`'s loader, because a test replaces that module whole with a
// double (`tests/tools/store_double.js`), and a statement must compile the
// same under the double as against a database.
// ---------------------------------------------------------------------------

const errorCodes = require('../common/error_codes');

const log = require('bunyan').createLogger({
  name: 'sts-sql-dialect',
  level: process.env.STS_LOG_LEVEL || process.env.LOG_LEVEL || 'info'
});

// THE STATEMENT CLOCK, in the milliseconds every cluster table stores. Not
// the transaction's start (`now()` / `NOW()`) and not a process's clock: a
// lease checked late in a long transaction is checked against when the check
// ran, and two containers' clocks differ. PostgreSQL's is the text
// `persistence_postgres.js` has always spliced in (`DB_NOW`).
const NOW = {
  postgres: '(extract(epoch from clock_timestamp()) * 1000)::bigint',
  // `SYSDATE(6)` is evaluated when it runs; `NOW(6)` is fixed at the start of
  // the statement. Microseconds, so the rounding is to the millisecond.
  mariadb: 'CAST(ROUND(UNIX_TIMESTAMP(SYSDATE(6)) * 1000) AS SIGNED)'
};

// The Knex client each engine compiles with. One driver per engine (#677):
// `pg` for PostgreSQL, `mysql2` for MariaDB — the one attribute sources
// already load.
const CLIENT = {
  postgres: 'pg',
  mariadb: 'mysql2'
};

// WHAT AN ENGINE CAN DO THAT THE DRIVER'S DESIGN LEANS ON (tier C). A missing
// capability is a fallback the driver takes, never a feature it pretends.
const CAPABILITIES = {
  postgres: {
    // LISTEN/NOTIFY: the nudge that wakes the change-log poll early. Lossy by
    // design; the poll is the contract.
    nudge: true,
    // Statement-level triggers over transition tables (the directory counts).
    transitionTriggers: true,
    // `synchronous_commit = off` for the tally pool and the claim statements.
    asyncCommit: true,
    // A transaction-scoped advisory lock (`pg_advisory_xact_lock`).
    transactionLocks: true,
    // `UPDATE … RETURNING`.
    updateReturning: true,
    // GIN indexes over JSON arrays (existence and containment).
    jsonIndexes: true
  },
  mariadb: {
    nudge: false,
    transitionTriggers: false,
    asyncCommit: false,
    transactionLocks: false,
    updateReturning: false,
    jsonIndexes: false
  }
};

// The default change-log poll where an engine has no nudge (rcbj on #677,
// 2026-11-03): one indexed read a process a second when nothing changed.
const POLL_WITHOUT_NUDGE_MS = 1000;

/**
 * The engines this store can be.
 *
 * @returns the engine names
 */
function engines() {
  log.debug("Entering engines().");
  log.debug("Leaving engines().");
  return Object.keys(CLIENT);
}

/**
 * Builds the dialect for one engine.
 *
 * @param engine - 'postgres' or 'mariadb'
 * @returns the dialect: `engine`, `kx` (a connectionless Knex to build with),
 *   `compile()`, the fragments, and `capabilities`
 */
function create(engine) {
  log.debug("Entering create(). engine=" + engine);
  if (!Object.prototype.hasOwnProperty.call(CLIENT, engine)) {
    log.debug("Leaving create(). Unknown engine.");
    throw new Error('sql_dialect: unknown engine "' + engine + '"; the ' +
                    'engines are ' + engines().join(', '));
  }
  let knex;
  try {
    knex = require('knex');
  } catch (err) {
    log.debug("Caught in create(): " + ((err && err.message) || err));
    log.debug("Leaving create(). Knex is not installed.");
    throw new Error(errorCodes.tag('STS-STORE-0028') + 'the store\'s SQL ' +
                    'is compiled with the "knex" package, which is not ' +
                    'installed: ' + ((err && err.message) || err));
  }
  knex = knex && typeof knex.knex === 'function' ? knex.knex : knex;
  const kx = knex({ client: CLIENT[engine] });
  const nowText = NOW[engine];

  /**
   * Compiles a built statement into the text and values a connection takes,
   * with its name as a trailing comment.
   *
   * @param name - the operation's name, `[a-zA-Z0-9_.:-]` only
   * @param built - a Knex query builder, or a `knex.raw()`
   * @returns `{ text, values, name }`
   */
  function compile(name, built) {
    log.debug("Entering compile(). " + name);
    if (!/^[A-Za-z0-9_.:-]+$/.test(String(name))) {
      log.debug("Leaving compile(). Bad name.");
      throw new Error('sql_dialect: a statement name is a bare token, not "' +
                      name + '"');
    }
    const native = built.toSQL().toNative();
    log.debug("Leaving compile().");
    return { text: native.sql + ' /* sts:' + name + ' */',
             values: native.bindings, name: name };
  }

  /**
   * Compiles and sends a built statement on a connection or pool.
   *
   * @param runner - anything with `query(text, values)`
   * @param name - the operation's name
   * @param built - a Knex query builder
   * @returns the connection's answer
   */
  function run(runner, name, built) {
    log.debug("Entering run(). " + name);
    const statement = compile(name, built);
    log.debug("Leaving run().");
    return runner.query(statement.text, statement.values);
  }

  /**
   * The statement clock as a fragment, optionally offset by a bound number
   * of milliseconds (`now(+ttl)`, `now(-age)`).
   *
   * @param offsetMs - added to the clock when given; a bound value
   * @param sign - '+' (the default) or '-'
   * @returns a `knex.raw()` fragment
   */
  function now(offsetMs, sign) {
    log.debug("Entering now().");
    if (offsetMs === undefined || offsetMs === null) {
      log.debug("Leaving now(). Bare.");
      return kx.raw(nowText);
    }
    const op = sign === '-' ? '-' : '+';
    log.debug("Leaving now(). Offset.");
    return kx.raw('(' + nowText + ' ' + op + ' ?)', [Number(offsetMs)]);
  }

  /**
   * A JSON value as a fragment: a jsonb cast on PostgreSQL, the text on
   * MariaDB (whose JSON is LONGTEXT with a check).
   *
   * @param value - anything JSON.stringify takes
   * @returns a `knex.raw()` fragment
   */
  function json(value) {
    log.debug("Entering json().");
    const text = JSON.stringify(value === undefined ? null : value);
    log.debug("Leaving json().");
    return engine === 'postgres' ? kx.raw('?::jsonb', [text])
      : kx.raw('?', [text]);
  }

  /**
   * The rows of a connection's answer, whichever driver gave it: `pg`
   * answers `{ rows }`, the store layer normalises `mysql2` to the same.
   *
   * @param result - a connection's answer
   * @returns its rows, or []
   */
  function rowsOf(result) {
    log.debug("Entering rowsOf().");
    log.debug("Leaving rowsOf().");
    return (result && Array.isArray(result.rows)) ? result.rows : [];
  }

  /**
   * How many rows a write touched, whichever driver gave the answer.
   *
   * @param result - a connection's answer
   * @returns the count, or 0
   */
  function affected(result) {
    log.debug("Entering affected().");
    log.debug("Leaving affected().");
    return Number((result && (result.rowCount !== undefined
      ? result.rowCount : result.affectedRows)) || 0);
  }

  /**
   * An instant this many milliseconds before the start of the statement, as
   * a fragment comparable with a timestamp column (`sts_changes.at`).
   *
   * @param ms - how long ago; a bound value
   * @returns a `knex.raw()` fragment
   */
  function ago(ms) {
    log.debug("Entering ago().");
    const span = Math.max(0, Math.floor(Number(ms) || 0));
    log.debug("Leaving ago().");
    return engine === 'postgres'
      ? kx.raw('(now() - (? * interval \'1 millisecond\'))', [span])
      : kx.raw('(NOW(6) - INTERVAL ? MICROSECOND)', [span * 1000]);
  }

  /**
   * Whether a refusal is a unique-key violation — the answer a portable
   * "once" reads as "somebody else holds it".
   *
   * @param err - what the connection rejected with
   * @returns true for a duplicate key
   */
  function isUniqueViolation(err) {
    log.debug("Entering isUniqueViolation().");
    const code = err && err.code;
    log.debug("Leaving isUniqueViolation().");
    return code === '23505' || code === 'ER_DUP_ENTRY' ||
      (err && err.errno === 1062) || false;
  }

  /**
   * Whether a failure is one the engine expects the client to retry: a
   * deadlock, a serialization failure, a lock wait that timed out.
   *
   * @param err - what the connection rejected with
   * @returns true when running the transaction again is the answer
   */
  function isRetryable(err) {
    log.debug("Entering isRetryable().");
    const code = err && err.code;
    log.debug("Leaving isRetryable().");
    return code === '40P01' || code === '40001' ||
      code === 'ER_LOCK_DEADLOCK' || code === 'ER_LOCK_WAIT_TIMEOUT' ||
      (!!err && (err.errno === 1213 || err.errno === 1205));
  }

  log.debug("Leaving create().");
  return {
    engine: engine,
    ago: ago,
    isRetryable: isRetryable,
    isUniqueViolation: isUniqueViolation,
    kx: kx,
    compile: compile,
    run: run,
    now: now,
    nowText: nowText,
    json: json,
    rowsOf: rowsOf,
    affected: affected,
    capabilities: Object.assign({}, CAPABILITIES[engine]),
    pollWithoutNudgeMs: POLL_WITHOUT_NUDGE_MS
  };
}

module.exports = {
  create: create,
  // The same factory under a name that does not read as a call of a
  // caller's own `create()` (`tests/no_periodic_timers.js` treats a
  // function that calls its own name as one that repeats).
  forEngine: create,
  engines: engines,
  NOW: NOW,
  CAPABILITIES: CAPABILITIES,
  POLL_WITHOUT_NUDGE_MS: POLL_WITHOUT_NUDGE_MS
};
