// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: minted_portable.js
//
// ---------------------------------------------------------------------------
// WHAT THIS SERVICE MINTS, IN STATEMENTS A SECOND ENGINE RUNS (#677, 3b).
//
// `persistence_postgres.js` keeps the minted rows (`sts_minted`), their
// index (`sts_minted_index`) and the session index (`sts_sessions`) with
// PostgreSQL's own text: `ANY($n::text[])`, `unnest()`, `ctid` batches,
// `to_timestamp()`, and the whole flush as ONE statement of data-modifying
// CTEs (`MINTED_FLUSH`). This library is `cluster_portable.js`'s pattern for
// that family: one function per driver method, each the native statement's
// contract re-stated in Knex builder statements compiled by `sql_dialect.js`,
// answering what the connection would have answered for the native text
// (`{ rows, rowCount }`) so the driver's own reading of the answer is
// unchanged. The driver builds it when the engine is not PostgreSQL, and on
// PostgreSQL under `persistence.sqlDialect=portable` — every statement here
// runs unchanged against `postgres/schema.sql` too, which is how the
// `cluster-portable` mode proves this code on the reference engine.
//
// THE FLUSH (`flush()`) IS A TRANSACTION, NOT A STATEMENT. MariaDB has no
// data-modifying CTE, so the flush is the shape it had before #820 — a
// transaction on one held connection, the driver's `withTransaction()`,
// which runs the fence first (`checkFence()`, `cluster_portable.js`'s
// fences on this engine) and counts and announces the change rows at COMMIT
// (`noteChanges()` through `settleMintedFlush()`). It is handed the same
// named parameters `MINTED_FLUSH` takes (`mintedFlushWrites()`), so what is
// written is decided in one place for both engines, and keeps every rule
// the one statement keeps:
//
//   1. EVERY EXISTING ROW THE FLUSH TOUCHES IS LOCKED FIRST, `FOR UPDATE`,
//      ordered by (handle, realm, key), before any write — the one lock
//      order every flush takes, so two flushes over rows that exist cannot
//      deadlock. The lock also reads each stored body, which is the merge's
//      input (the driver's `resolveMerges()`): under the lock the merge is
//      exact, so there is no compare-and-set to miss.
//   2. THE TOMBSTONE RULE, decided against the locked row: an upsert of a
//      key holding `$tombstone$1` is not written unless it is a tombstone
//      itself or its store keeps none (`plain_*`), and is answered
//      `unwritten`. A key that did NOT exist at the lock is inserted with
//      "insert or nothing" (INSERT IGNORE / ON CONFLICT DO NOTHING); one
//      another flush inserted meanwhile is then locked and the rule applied
//      to what it holds — PostgreSQL's `ON CONFLICT … DO UPDATE … WHERE`
//      reads the conflicting row the same way.
//   3. THE WRITES GO IN (handle, realm, key) ORDER, upserts and the
//      tombstones written among them, so two flushes inserting overlapping
//      new keys meet them in one order; a run of rows of one kind is one
//      statement, and the runs follow the order.
//   4. THE SIDE TABLES FOLLOW THE BODIES, and are written only for a body
//      that was: the session index (`ses_*`, deleted for every key the
//      flush removed), the minted index (a written row's index rows not
//      filed again removed, the new set filed, a sort row's `sort_at`
//      updated in place), and the change log (a row per written upsert and
//      per delete, in the flush's order).
//
// INNODB ANSWERS SOME RACES WITH A DEADLOCK WHERE POSTGRESQL WAITS (two
// "insert or nothing" of one new key and a third writer). The transaction
// is rolled back whole and run again by `withTransaction()`
// (`retryableConflict()` reads `dialect.isRetryable()`), as a deadlocked
// PostgreSQL flush always was.
//
// A VALUE LONGER THAN ITS MARIADB COLUMN IS REFUSED, never truncated
// (STS-STORE-0120). `sts_minted.key` is 512 characters, and where nothing
// seals it is a row's NAME in the clear (`mariadb/CLAUDE.md`); the server
// refuses a longer one under strict mode, and an INSERT IGNORE would turn
// that refusal into a silent truncation, so every bounded column a flush
// writes is measured first and a flush holding one too long fails whole,
// saying which.
//
// THE OTHER METHODS are one statement each: the restore's read with its
// required filter, the keys of a key-resident store, the reads by key, the
// index's completion mark and backfill, the session index's repairs and
// backfill pages, and the purges — `purgeExpiredMinted()`'s batch is
// `DELETE … LIMIT n` on MariaDB, where PostgreSQL chooses its batch by
// `ctid`; the bound per call is the same.
//
// WHAT IS NOT HERE: the on-demand reader's and the session window's
// SYNCHRONOUS questions. Their thread (`common/sync_query_thread.ts`) dials
// `pg` alone, the driver offers no `bridgeConnection()` on MariaDB, and
// `persistence_minted.js` and `persistence.js` then hold those stores whole.
// The same questions asked on the read pool (`mintedQuery()`,
// `sessionIndexQuery()`) have MariaDB spellings in `minted_queries.js` and
// `session_queries.js`.
//
// A LIBRARY: handed the dialect, the pools and the driver's constants; it
// requires only the error-code table and bunyan, and holds no state.
// ---------------------------------------------------------------------------

const errorCodes = require('../common/error_codes');

const log = require('bunyan').createLogger({
  name: 'sts-minted-portable',
  level: process.env.STS_LOG_LEVEL || process.env.LOG_LEVEL || 'info'
});

// The change rows one INSERT carries: the driver's CHANGE_ROWS_PER_STATEMENT.
const CHANGE_ROWS_PER_STATEMENT = 5000;

// How many times an "insert or nothing" that met another flush's row is
// asked again when that row has gone by the time it is locked.
const RACE_RETRIES = 3;

// The bounded columns a flush writes, by table, as `mariadb/schema.sql`
// sizes them (characters). PostgreSQL's are `text`.
const LIMITS = {
  sts_minted: { handle: 64, realm: 64, key: 512 },
  sts_minted_index: { handle: 64, realm: 64, index_key: 128, key: 512 },
  sts_sessions: { realm: 64, key: 512, subject_key: 255, username_key: 255,
                  rp_surface: 255, parent_key: 512, credential_key: 255,
                  partner_relationship: 255 }
};

// `sts_sessions`' fifteen columns, in `sessionIndexParams()`' order.
const SESSION_COLUMNS = ['realm', 'key', 'expires_at', 'last_seen_at',
  'started_at', 'subject_key', 'username_key', 'chosen', 'authenticated',
  'kind', 'rp_surface', 'parent_key', 'backs_console', 'credential_key',
  'partner_relationship'];

// A minted row's identity, as the driver's `mintedIdOf()`. Hot path (every
// row of every flush): no Entering/Leaving pair.
function idOf(h, r, k) {
  return String(h) + '\n' + String(r) + '\n' + String(k);
}

// The length of a value in characters (code points), as a VARCHAR counts
// it. Hot path (every bounded value of every flush): no Entering/Leaving
// pair; a string no longer than the bound in code units is no longer in
// code points either, so only a long one is counted.
function charactersOver(value, bound) {
  const text = String(value === null || value === undefined ? '' : value);
  return text.length > bound && Array.from(text).length > bound;
}

/**
 * Builds the portable minted statements over one driver's connections.
 *
 * @param deps - `{ dialect, pool, readPool, tombstone, indexMark,
 *   sessionMark }`: the dialect, the write and read pools, the tombstone
 *   body, the minted index's completion key, and the session index's
 *   completion row (`{ realm, key }`)
 * @returns the portable operations
 */
function create(deps) {
  log.debug("Entering create().");
  const dialect = deps.dialect;
  const kx = dialect.kx;
  const pool = deps.pool;
  const readPool = deps.readPool || deps.pool;
  const TOMBSTONE = String(deps.tombstone);
  const INDEX_MARK = String(deps.indexMark);
  const SESSION_MARK = deps.sessionMark;
  const mariadb = dialect.engine === 'mariadb';

  // ENGINE FRAGMENTS this family needs and `sql_dialect.js` does not offer:
  // a timestamp column as epoch milliseconds (the `written_ms` every reader
  // takes), and the transaction's write instant (`written_at`). MariaDB's
  // session is UTC (`knex_store.js`), which UNIX_TIMESTAMP reads a DATETIME
  // in.
  const epochMs = function (column) {
    return mariadb
      ? kx.raw('CAST(ROUND(UNIX_TIMESTAMP(??) * 1000) AS SIGNED)', [column])
      : kx.raw('(extract(epoch from ??) * 1000)::bigint', [column]);
  };
  const stamp = function () {
    return kx.raw(mariadb ? 'NOW(6)' : 'now()');
  };
  // An instant in epoch milliseconds, bound as a Date: `mysql2` writes it in
  // the connection's UTC and `pg` with its offset, so either compares it
  // with `written_at` as `to_timestamp($n / 1000.0)` did.
  const instant = function (ms) {
    return new Date(Number(ms) || 0);
  };

  /**
   * Sends one built statement.
   *
   * @param runner - a pool or a held connection
   * @param name - the statement's name
   * @param built - a Knex builder
   * @returns the connection's answer
   */
  function run(runner, name, built) {
    log.debug("Entering run(). " + name);
    log.debug("Leaving run().");
    return dialect.run(runner, 'minted.' + name, built);
  }

  /**
   * The rows of an answer with every listed column made a boolean: MariaDB
   * answers a BOOLEAN as 0 or 1, `pg` as true or false.
   *
   * @param result - a connection's answer
   * @param columns - the boolean columns
   * @returns the answer, its rows normalised
   */
  function booleans(result, columns) {
    log.debug("Entering booleans().");
    const rows = dialect.rowsOf(result).map(function (row) {
      const out = Object.assign({}, row);
      columns.forEach(function (c) {
        if (out[c] !== undefined && out[c] !== null) {
          out[c] = out[c] === true || Number(out[c]) === 1 || out[c] === 't';
        }
      });
      return out;
    });
    log.debug("Leaving booleans().");
    return { rows: rows, rowCount: rows.length };
  }

  /**
   * Refuses a value longer than its MariaDB column (STS-STORE-0120). Not on
   * PostgreSQL, whose columns are `text`.
   *
   * @param table - the table the values go to
   * @param rows - objects keyed by column
   */
  function measure(table, rows) {
    log.debug("Entering measure(). " + table);
    if (!mariadb) {
      log.debug("Leaving measure(). Unbounded.");
      return;
    }
    const limits = LIMITS[table];
    const columns = Object.keys(limits);
    for (const row of rows) {
      for (const c of columns) {
        if (charactersOver(row[c], limits[c])) {
          log.debug("Leaving measure(). Too long.");
          throw errorCodes.mark(new Error(errorCodes.tag('STS-STORE-0120') +
            'persistence: a minted flush holds a ' + table + '.' + c +
            ' of ' + Array.from(String(row[c])).length + ' characters, ' +
            'and the MariaDB column holds ' + limits[c] + '; the flush is ' +
            'refused rather than truncated (handle ' +
            String(row.handle || '') + ', realm ' + String(row.realm || '') +
            ').'), 'STS-STORE-0120');
        }
      }
    }
    log.debug("Leaving measure().");
  }

  // ===================================================================
  // THE FLUSH
  // ===================================================================

  /**
   * One minted flush on a held connection inside the driver's transaction
   * (the fence already checked): MINTED_FLUSH's contract, step by step.
   *
   * @param client - the transaction's connection
   * @param touched - every row the flush touches (`plan.touched`)
   * @param prepare - given the stored bodies (an id to a body), answers
   *   `{ resolved, named }`: the merges done against them and
   *   MINTED_FLUSH_LAYOUT's named parameters for that resolution
   * @returns `{ resolved, unwritten }`: `unwritten` the ids of the upserts
   *   the tombstone rule did not write
   */
  async function flush(client, touched, prepare) {
    log.debug("Entering flush(). " + touched.length + " row(s).");
    // 1. THE LOCK: every existing row, in one order, before any write.
    const stored = new Map();
    if (touched.length) {
      const locked = await run(client, 'flush.lock',
        kx('sts_minted').select('handle', 'realm', 'key', 'body')
          .whereIn(['handle', 'realm', 'key'], touched.map(function (row) {
            return [String(row.handle), String(row.realm), String(row.key)];
          }))
          .orderBy(['handle', 'realm', 'key']).forUpdate());
      dialect.rowsOf(locked).forEach(function (row) {
        stored.set(idOf(row.handle, row.realm, row.key), String(row.body));
      });
    }
    const prepared = prepare(stored);
    const p = prepared.named;
    const up = (p.up_h || []).map(function (h, i) {
      return { handle: String(h), realm: String(p.up_r[i]),
               key: String(p.up_k[i]), body: String(p.up_body[i]),
               expires_at: p.up_expires[i] === undefined ? null
                 : p.up_expires[i],
               key_sealed: String(p.up_sealed[i] || '') };
    });
    measure('sts_minted', up);
    const plain = new Set((p.plain_h || []).map(function (h, i) {
      return idOf(h, p.plain_r[i], p.plain_k[i]);
    }));
    // 2. THE TOMBSTONE RULE against the locked rows, and each upsert's kind:
    // `write` (it exists and the rule allows it, or its store keeps no
    // tombstones: written whatever is there) or `fresh` (it did not exist
    // and the rule must be applied to whatever a racing flush leaves).
    const written = new Set();
    const unwritten = new Set();
    const runs = [];
    up.forEach(function (row) {
      const id = idOf(row.handle, row.realm, row.key);
      const isPlain = plain.has(id);
      let kind = 'write';
      if (stored.has(id)) {
        if (!isPlain && stored.get(id) === TOMBSTONE &&
            row.body !== TOMBSTONE) {
          unwritten.add(id);
          return;
        }
      } else if (!isPlain) {
        kind = 'fresh';
      }
      const last = runs[runs.length - 1];
      if (last && last.kind === kind) {
        last.rows.push(row);
      } else {
        runs.push({ kind: kind, rows: [row] });
      }
    });
    // 3. THE WRITES, in the flush's order, a run a statement.
    for (const one of runs) {
      const rows = one.rows.map(function (row) {
        return Object.assign({}, row, { written_at: stamp() });
      });
      if (one.kind === 'write') {
        await run(client, 'flush.upsert',
          kx('sts_minted').insert(rows)
            .onConflict(['handle', 'realm', 'key'])
            .merge(['body', 'written_at', 'expires_at', 'key_sealed']));
        one.rows.forEach(function (row) {
          written.add(idOf(row.handle, row.realm, row.key));
        });
      } else {
        await freshRun(client, one.rows, rows, written, unwritten);
      }
    }
    const dels = (p.del_h || []).map(function (h, i) {
      return [String(h), String(p.del_r[i]), String(p.del_k[i])];
    });
    if (dels.length) {
      await run(client, 'flush.delete',
        kx('sts_minted').whereIn(['handle', 'realm', 'key'], dels).del());
    }
    // 4. THE SIDE TABLES, for the bodies written.
    await sideTables(client, p, written);
    log.debug("Leaving flush(). " + written.size + " written, " +
              unwritten.size + " unwritten.");
    return { resolved: prepared.resolved, unwritten: unwritten };
  }

  /**
   * A run of upserts of keys that did not exist at the lock, under the
   * tombstone rule: inserted or nothing, and any another flush got to first
   * locked and judged as the lock would have judged it.
   *
   * @param client - the transaction's connection
   * @param rows - the upserts, in order
   * @param values - the same rows with their `written_at` fragment
   * @param written - the ids written, added to
   * @param unwritten - the ids refused, added to
   */
  async function freshRun(client, rows, values, written, unwritten) {
    log.debug("Entering freshRun(). " + rows.length + " row(s).");
    const inserted = await run(client, 'flush.insert',
      kx('sts_minted').insert(values)
        .onConflict(['handle', 'realm', 'key']).ignore());
    if (dialect.affected(inserted) >= rows.length) {
      rows.forEach(function (row) {
        written.add(idOf(row.handle, row.realm, row.key));
      });
      log.debug("Leaving freshRun(). Every row inserted.");
      return;
    }
    // SOME KEY WAS TAKEN BETWEEN THE LOCK AND THE INSERT. Which ones is not
    // in the count, so each row is locked and read: one that is not this
    // flush's (another body, expiry or sealed name) is judged by the rule
    // and written over, as `ON CONFLICT … DO UPDATE … WHERE` would; one that
    // holds exactly this flush's values is this flush's insert.
    for (const row of rows) {
      const id = idOf(row.handle, row.realm, row.key);
      for (let attempt = 0; ; attempt++) {
        const found = dialect.rowsOf(await run(client, 'flush.recheck',
          kx('sts_minted').select('body', 'expires_at', 'key_sealed')
            .where({ handle: row.handle, realm: row.realm, key: row.key })
            .forUpdate()))[0];
        if (!found) {
          if (attempt >= RACE_RETRIES) {
            log.debug("Leaving freshRun(). A row kept vanishing.");
            throw errorCodes.mark(new Error(errorCodes.tag('STS-STORE-0121') +
              'persistence: a minted row (' + row.handle + ') was ' +
              'inserted and removed by other writers ' + (RACE_RETRIES + 1) +
              ' times while this flush wrote it.'), 'STS-STORE-0121');
          }
          const again = await run(client, 'flush.insert',
            kx('sts_minted').insert(Object.assign({}, row,
                                                  { written_at: stamp() }))
              .onConflict(['handle', 'realm', 'key']).ignore());
          if (dialect.affected(again) > 0) {
            written.add(id);
            break;
          }
          continue;
        }
        const body = String(found.body);
        const same = body === row.body &&
          String(found.key_sealed || '') === row.key_sealed &&
          (found.expires_at === null ? null : Number(found.expires_at)) ===
          (row.expires_at === null ? null : Number(row.expires_at));
        if (same) {
          written.add(id);
        } else if (body === TOMBSTONE && row.body !== TOMBSTONE) {
          unwritten.add(id);
        } else {
          await run(client, 'flush.overwrite',
            kx('sts_minted').update({ body: row.body, written_at: stamp(),
                                      expires_at: row.expires_at,
                                      key_sealed: row.key_sealed })
              .where({ handle: row.handle, realm: row.realm,
                       key: row.key }));
          written.add(id);
        }
        break;
      }
    }
    log.debug("Leaving freshRun().");
  }

  /**
   * The session index, the minted index and the change log of a flush, for
   * the bodies `written` names.
   *
   * @param client - the transaction's connection
   * @param p - MINTED_FLUSH_LAYOUT's named parameters
   * @param written - the ids whose bodies were written
   */
  async function sideTables(client, p, written) {
    log.debug("Entering sideTables().");
    // THE SESSION INDEX (#350): a written session's row, every removed
    // session's row gone.
    const sessions = [];
    (p.ses_realm || []).forEach(function (r, i) {
      if (!written.has(idOf('authn.sessions', r, p.ses_key[i]))) {
        return;
      }
      sessions.push(sessionRow([r, p.ses_key[i], p.ses_expires[i],
        p.ses_last_seen[i], p.ses_started[i], p.ses_subject[i],
        p.ses_username[i], p.ses_chosen[i], p.ses_authenticated[i],
        p.ses_kind[i], p.ses_rp_surface[i], p.ses_parent[i],
        p.ses_backs_console[i], p.ses_credential[i], p.ses_partner[i]]));
    });
    if (sessions.length) {
      measure('sts_sessions', sessions);
      await run(client, 'flush.sessions',
        kx('sts_sessions').insert(sessions).onConflict(['realm', 'key'])
          .merge(SESSION_COLUMNS.slice(2)));
    }
    const sessionsGone = (p.sesdel_realm || []).map(function (r, i) {
      return [String(r), String(p.sesdel_key[i])];
    });
    if (sessionsGone.length) {
      await run(client, 'flush.sessionsGone',
        kx('sts_sessions').whereIn(['realm', 'key'], sessionsGone).del());
    }
    // THE MINTED INDEX (#820): the rows of a written body and of a removed
    // one cleared, except those filed again (kept, so a sort row is updated
    // in place below rather than deleted and inserted).
    const clear = [];
    (p.ixup_h || []).forEach(function (h, i) {
      if (written.has(idOf(h, p.ixup_r[i], p.ixup_k[i]))) {
        clear.push([String(h), String(p.ixup_r[i]), String(p.ixup_k[i])]);
      }
    });
    (p.ixgone_h || []).forEach(function (h, i) {
      clear.push([String(h), String(p.ixgone_r[i]), String(p.ixgone_k[i])]);
    });
    const filed = (p.ixnew_h || []).map(function (h, i) {
      return { handle: String(h), realm: String(p.ixnew_r[i]),
               index_key: String(p.ixnew_i[i]), key: String(p.ixnew_k[i]),
               sort_at: p.ixnew_s[i] === undefined ? null : p.ixnew_s[i] };
    });
    if (clear.length) {
      await run(client, 'flush.indexClear',
        kx('sts_minted_index').whereIn(['handle', 'realm', 'key'], clear)
          .whereNotIn(['handle', 'realm', 'index_key', 'key'],
                      filed.map(function (one) {
                        return [one.handle, one.realm, one.index_key, one.key];
                      })).del());
    }
    const filing = filed.filter(function (one) {
      return written.has(idOf(one.handle, one.realm, one.key));
    });
    if (filing.length) {
      measure('sts_minted_index', filing);
      await run(client, 'flush.indexFile',
        kx('sts_minted_index').insert(filing)
          .onConflict(['handle', 'realm', 'index_key', 'key'])
          .merge(['sort_at']));
    }
    // THE CHANGE LOG: a row per written upsert and per delete, in order.
    const changes = [];
    (p.chg_kind || []).forEach(function (kind, i) {
      if (p.chg_h[i] !== null && p.chg_h[i] !== undefined &&
          !written.has(idOf(p.chg_h[i], p.chg_r[i], p.chg_k[i]))) {
        return;
      }
      changes.push({ origin: String(p.origin), kind: String(kind),
                     realm: String(p.chg_realm[i] || ''),
                     key: String(p.chg_key[i] || '') });
    });
    for (let start = 0; start < changes.length;
      start += CHANGE_ROWS_PER_STATEMENT) {
      await run(client, 'flush.changes',
        kx('sts_changes').insert(changes.slice(start,
          start + CHANGE_ROWS_PER_STATEMENT)));
    }
    log.debug("Leaving sideTables(). " + changes.length + " change(s).");
  }

  /**
   * One `sts_sessions` row from `sessionIndexParams()`' fifteen values.
   *
   * @param values - the values, in SESSION_COLUMNS' order
   * @returns the row, keyed by column
   */
  function sessionRow(values) {
    log.debug("Entering sessionRow().");
    const row = {};
    SESSION_COLUMNS.forEach(function (c, i) {
      row[c] = values[i];
    });
    log.debug("Leaving sessionRow().");
    return row;
  }

  // ===================================================================
  // READS
  // ===================================================================

  /**
   * `loadMinted()`'s read: every live row of the realms asked for, under
   * the caller's filter (the driver has already refused a missing one).
   *
   * @param filter - `persistence_minted.js`'s restoreFilter()
   * @returns the answer, `written_ms`, `expires_at` and `key_sealed` as the
   *   native text names them
   */
  function loadMinted(filter) {
    log.debug("Entering loadMinted().");
    const staleBefore = Number(filter.staleBefore) || 0;
    const shortLived = Array.isArray(filter.ageHandles)
      ? filter.ageHandles.map(String) : [];
    const skipped = Array.isArray(filter.skipHandles)
      ? filter.skipHandles.map(String) : [];
    const q = kx('sts_minted')
      .select('handle', 'realm', 'key', 'body',
              { written_ms: epochMs('written_at') }, 'expires_at',
              'key_sealed')
      .whereNot('body', TOMBSTONE)
      .whereIn('realm', filter.realms.map(String))
      .where(function () {
        this.whereNull('expires_at')
          .orWhere('expires_at', '>', Number(filter.nowMs) || Date.now());
      });
    if (staleBefore > 0 && shortLived.length > 0) {
      q.whereNot(function () {
        this.whereNull('expires_at').whereIn('handle', shortLived)
          .where('written_at', '<', instant(staleBefore));
      });
    }
    if (skipped.length) {
      q.whereNotIn('handle', skipped);
    }
    log.debug("Leaving loadMinted().");
    return run(readPool, 'loadMinted', q);
  }

  /**
   * `loadMintedKeys()`' read: the key of every live row of the stores.
   *
   * @param handles - the stores
   * @param realmIds - the realms
   * @param nowMs - the instant an expiry is compared with
   * @returns the answer
   */
  function loadMintedKeys(handles, realmIds, nowMs) {
    log.debug("Entering loadMintedKeys().");
    log.debug("Leaving loadMintedKeys().");
    return run(readPool, 'loadMintedKeys',
      kx('sts_minted').select('handle', 'realm', 'key')
        .whereIn('handle', handles.map(String))
        .whereIn('realm', (realmIds || []).map(String))
        .whereNot('body', TOMBSTONE)
        .where(function () {
          this.whereNull('expires_at')
            .orWhere('expires_at', '>', Number(nowMs) || Date.now());
        }));
  }

  /**
   * `readMintedMany()`' read: the rows named by (handle, realm, key).
   *
   * @param runner - the pool asked (the primary or the read pool)
   * @param refs - `[{ handle, realm, key }]`, at least one
   * @returns the answer
   */
  function readMintedMany(runner, refs) {
    log.debug("Entering readMintedMany(). " + refs.length);
    log.debug("Leaving readMintedMany().");
    return run(runner, 'readMintedMany',
      kx('sts_minted')
        .select('handle', 'realm', 'key', 'body',
                { written_ms: epochMs('written_at') })
        .whereIn(['handle', 'realm', 'key'], refs.map(function (ref) {
          return [String(ref.handle), String(ref.realm), String(ref.key)];
        })));
  }

  /**
   * `readMinted()`'s read: one row.
   *
   * @returns the answer
   */
  function readMinted(handle, realmId, key) {
    log.debug("Entering readMinted().");
    log.debug("Leaving readMinted().");
    return run(readPool, 'readMinted',
      kx('sts_minted')
        .select('handle', 'realm', 'key', 'body',
                { written_ms: epochMs('written_at') })
        .where({ handle: String(handle), realm: String(realmId),
                 key: String(key) }));
  }

  // ===================================================================
  // THE MINTED INDEX
  // ===================================================================

  /**
   * `mintedIndexComplete()`' read: the stores whose completion row exists.
   *
   * @param handles - the stores asked about
   * @returns the answer
   */
  function mintedIndexComplete(handles) {
    log.debug("Entering mintedIndexComplete().");
    log.debug("Leaving mintedIndexComplete().");
    return run(pool, 'mintedIndexComplete',
      kx('sts_minted_index').select('handle')
        .whereIn('handle', (handles || []).map(String))
        .where({ realm: '', index_key: INDEX_MARK, key: INDEX_MARK }));
  }

  /**
   * `MINTED_INDEX_INSERT`'s contract: index rows filed, a row already
   * there left alone, in primary-key order so two writers take the rows'
   * locks in one order.
   *
   * @param rows - `{ handle, realm, index_key, key, sort_at }`
   * @returns the answer (`rowCount` the rows written)
   */
  function insertIndex(rows) {
    log.debug("Entering insertIndex(). " + rows.length);
    measure('sts_minted_index', rows);
    const ordered = rows.slice().sort(function (a, b) {
      const left = [a.handle, a.realm, a.index_key, a.key].join('\n');
      const right = [b.handle, b.realm, b.index_key, b.key].join('\n');
      return left < right ? -1 : left > right ? 1 : 0;
    });
    log.debug("Leaving insertIndex().");
    return run(pool, 'insertIndex',
      kx('sts_minted_index').insert(ordered)
        .onConflict(['handle', 'realm', 'index_key', 'key']).ignore());
  }

  /**
   * `markMintedIndexed()`: the store's completion row.
   *
   * @param handle - the store
   * @returns the answer
   */
  function markMintedIndexed(handle) {
    log.debug("Entering markMintedIndexed().");
    log.debug("Leaving markMintedIndexed().");
    return insertIndex([{ handle: String(handle), realm: '',
                          index_key: INDEX_MARK, key: INDEX_MARK,
                          sort_at: null }]);
  }

  /**
   * One batch of `backfillMintedExpiry()`: up to `limit` live rows of one
   * store with no expiry given `written_at` plus `addMs`. MariaDB's UPDATE
   * takes the LIMIT itself; PostgreSQL's builder form chooses the batch by
   * primary key in a subquery.
   *
   * @returns the answer (`rowCount` the rows given an expiry)
   */
  function backfillExpiryBatch(handle, addMs, limit) {
    log.debug("Entering backfillExpiryBatch().");
    const add = Math.max(0, Number(addMs) || 0);
    const due = function (q) {
      return q.where({ handle: String(handle) }).whereNull('expires_at')
        .whereNot('body', TOMBSTONE);
    };
    const set = { expires_at: kx.raw('(? + ?)', [epochMs('written_at'),
                                                 add]) };
    log.debug("Leaving backfillExpiryBatch().");
    if (mariadb) {
      return run(pool, 'backfillExpiry',
        due(kx('sts_minted')).update(set).limit(limit));
    }
    return run(pool, 'backfillExpiry',
      kx('sts_minted').update(set)
        .whereIn(['handle', 'realm', 'key'],
                 due(kx('sts_minted').select('handle', 'realm', 'key'))
                   .limit(limit)));
  }

  // ===================================================================
  // THE SESSION INDEX
  // ===================================================================

  /**
   * `SESSION_INDEX_READ`: one index row as it is held, booleans as
   * booleans.
   *
   * @returns the answer
   */
  function readSessionIndex(realmId, key) {
    log.debug("Entering readSessionIndex().");
    log.debug("Leaving readSessionIndex().");
    return run(readPool, 'sessionIndex.read',
      kx('sts_sessions').select(SESSION_COLUMNS.slice(2))
        .where({ realm: String(realmId), key: String(key) })
    ).then(function (r) {
      return booleans(r, ['chosen', 'authenticated', 'backs_console']);
    });
  }

  /**
   * `SESSION_INDEX_UPSERT`: one index row written whole.
   *
   * @param client - a held connection, inside a transaction
   * @param values - `sessionIndexParams()`' fifteen values
   * @returns the answer
   */
  function upsertSession(client, values) {
    log.debug("Entering upsertSession().");
    const row = sessionRow(values);
    measure('sts_sessions', [row]);
    log.debug("Leaving upsertSession().");
    return run(client, 'sessionIndex.upsert',
      kx('sts_sessions').insert(row).onConflict(['realm', 'key'])
        .merge(SESSION_COLUMNS.slice(2)));
  }

  /**
   * `SESSION_INDEX_DELETE`: one index row gone.
   *
   * @returns the answer
   */
  function deleteSession(client, realmId, key) {
    log.debug("Entering deleteSession().");
    log.debug("Leaving deleteSession().");
    return run(client, 'sessionIndex.delete',
      kx('sts_sessions').where({ realm: String(realmId), key: String(key) })
        .del());
  }

  /**
   * `sessionIndexDone()`'s read: whether the completion row exists.
   *
   * @returns the answer, one row `{ done }`
   */
  function sessionIndexDone() {
    log.debug("Entering sessionIndexDone().");
    log.debug("Leaving sessionIndexDone().");
    return run(readPool, 'sessionIndex.done',
      kx('sts_sessions').select(kx.raw('1 AS hit'))
        .where({ realm: SESSION_MARK.realm, key: SESSION_MARK.key })
        .limit(1)
    ).then(function (r) {
      return { rows: [{ done: dialect.rowsOf(r).length > 0 }], rowCount: 1 };
    });
  }

  /**
   * `loadSessionBodies()`' read: a page of sealed session bodies, keyset on
   * (realm, key) — a row comparison both engines have.
   *
   * @returns the answer
   */
  function loadSessionBodies(afterRealm, afterKey, limit) {
    log.debug("Entering loadSessionBodies().");
    log.debug("Leaving loadSessionBodies().");
    return run(readPool, 'sessionBodies',
      kx('sts_minted').select('realm', 'key', 'body')
        .where({ handle: 'authn.sessions' }).whereNot('body', TOMBSTONE)
        .whereRaw('(??, ??) > (?, ?)', ['realm', 'key', String(afterRealm),
                                       String(afterKey)])
        .orderBy(['realm', 'key']).limit(Math.max(1, Number(limit) || 1)));
  }

  /**
   * One row of a backfill page, locked: the session body as it is now.
   *
   * @param client - the page's held connection
   * @returns the answer
   */
  function lockSessionBody(client, realmId, key) {
    log.debug("Entering lockSessionBody().");
    log.debug("Leaving lockSessionBody().");
    return run(client, 'sessionIndex.lockBody',
      kx('sts_minted').select('body')
        .where({ handle: 'authn.sessions', realm: String(realmId),
                 key: String(key) }).forUpdate());
  }

  /**
   * The backfill's last sweep: every index row but the completion row
   * whose session body is missing or a tombstone, deleted.
   *
   * @param client - the page's held connection
   * @returns the answer
   */
  function sweepSessionIndex(client) {
    log.debug("Entering sweepSessionIndex().");
    log.debug("Leaving sweepSessionIndex().");
    return run(client, 'sessionIndex.sweep',
      kx('sts_sessions')
        .whereNot({ realm: SESSION_MARK.realm, key: SESSION_MARK.key })
        .whereNotExists(function () {
          this.select(kx.raw('1')).from({ m: 'sts_minted' })
            .where('m.handle', 'authn.sessions')
            .whereRaw('?? = ??', ['m.realm', 'sts_sessions.realm'])
            .whereRaw('?? = ??', ['m.key', 'sts_sessions.key'])
            .whereNot('m.body', TOMBSTONE);
        }).del());
  }

  // ===================================================================
  // PURGES
  // ===================================================================

  /**
   * `purgeTombstones()`: tombstones written before `beforeMs`, at most
   * `limit` of them when it is positive (#1313), in purgeExpiredMinted()'s
   * two shapes; with no limit, the one unbounded delete it always was.
   *
   * @param beforeMs - the instant, in epoch milliseconds
   * @param limit - the batch's bound, or 0 for none
   * @returns the answer
   */
  function purgeTombstones(beforeMs, limit) {
    log.debug("Entering purgeTombstones().");
    const which = function (q) {
      return q.where({ body: TOMBSTONE })
        .where('written_at', '<', instant(beforeMs));
    };
    if (!(limit > 0)) {
      log.debug("Leaving purgeTombstones(). Unbounded.");
      return run(pool, 'purgeTombstones', which(kx('sts_minted')).del());
    }
    log.debug("Leaving purgeTombstones().");
    if (mariadb) {
      return run(pool, 'purgeTombstones',
        which(kx('sts_minted')).del().limit(limit));
    }
    return run(pool, 'purgeTombstones',
      kx('sts_minted').whereIn(['handle', 'realm', 'key'],
        which(kx('sts_minted').select('handle', 'realm', 'key'))
          .limit(limit)).del());
  }

  /**
   * `purgeMinted()`: every row written before `beforeMs`.
   *
   * @returns the answer
   */
  function purgeMinted(beforeMs) {
    log.debug("Entering purgeMinted().");
    log.debug("Leaving purgeMinted().");
    return run(pool, 'purgeMinted',
      kx('sts_minted').where('written_at', '<', instant(beforeMs)).del());
  }

  /**
   * One batch of `purgeExpiredMinted()`: at most `limit` rows of one kind.
   * MariaDB deletes with `LIMIT`; PostgreSQL's builder form names the batch
   * by primary key in a subquery (MariaDB refuses a LIMIT inside `IN`).
   *
   * @param kind - 'expired', 'orphan' or 'stale' (the driver has checked)
   * @param o - the driver's options
   * @param limit - the batch's bound
   * @returns the answer
   */
  function purgeExpiredMinted(kind, o, limit) {
    log.debug("Entering purgeExpiredMinted(). " + kind);
    const which = function (q) {
      if (kind === 'expired') {
        return q.whereNotNull('expires_at')
          .where('expires_at', '<=', Number(o.nowMs));
      }
      if (kind === 'stale') {
        return q.whereNull('expires_at').whereNot('body', TOMBSTONE)
          .whereIn('handle', o.handles.map(String))
          .where('written_at', '<', instant(o.staleBeforeMs));
      }
      q.whereNot('realm', '').whereNot('realm',
                                       String(o.defaultRealm || 'default'))
        .where('written_at', '<', instant(o.orphanBeforeMs));
      if (Array.isArray(o.realms)) {
        return q.whereNotIn('realm', o.realms.map(String));
      }
      return q.whereNotExists(function () {
        this.select(kx.raw('1')).from({ r: 'sts_realms' })
          .whereRaw('?? = ??', ['r.id', 'sts_minted.realm']);
      });
    };
    log.debug("Leaving purgeExpiredMinted().");
    if (mariadb) {
      return run(pool, 'purgeExpired.' + kind,
        which(kx('sts_minted')).del().limit(limit));
    }
    return run(pool, 'purgeExpired.' + kind,
      kx('sts_minted').whereIn(['handle', 'realm', 'key'],
        which(kx('sts_minted').select('handle', 'realm', 'key'))
          .limit(limit)).del());
  }

  log.debug("Leaving create().");
  return {
    flush: flush,
    loadMinted: loadMinted,
    loadMintedKeys: loadMintedKeys,
    readMintedMany: readMintedMany,
    readMinted: readMinted,
    mintedIndexComplete: mintedIndexComplete,
    insertIndex: insertIndex,
    markMintedIndexed: markMintedIndexed,
    backfillExpiryBatch: backfillExpiryBatch,
    readSessionIndex: readSessionIndex,
    upsertSession: upsertSession,
    deleteSession: deleteSession,
    sessionIndexDone: sessionIndexDone,
    loadSessionBodies: loadSessionBodies,
    lockSessionBody: lockSessionBody,
    sweepSessionIndex: sweepSessionIndex,
    purgeTombstones: purgeTombstones,
    purgeMinted: purgeMinted,
    purgeExpiredMinted: purgeExpiredMinted
  };
}

module.exports = {
  create: create,
  // The same factory under a name that does not read as a call of the
  // driver's own `create()` (`tests/no_periodic_timers.js`).
  forDriver: create,
  LIMITS: LIMITS
};
