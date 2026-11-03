// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: persistence/directory_portable.js
//
// ---------------------------------------------------------------------------
// THE EMBEDDED DIRECTORY'S STORE ON MARIADB (#677, phase 3b).
//
// `persistence_postgres.js` keeps the directory in `sts_ldap_entries` with
// PostgreSQL's features: GIN indexes over the JSON lookup columns, counts kept
// by statement triggers over transition tables, `unnest()` bulk writes, a
// conditional `ON CONFLICT … DO UPDATE … WHERE … RETURNING`, `jsonb ?|`. This
// library is the same store on MariaDB, built by the driver only when the
// engine is not PostgreSQL. IT IS NOT BUILT UNDER `persistence.sqlDialect=
// portable` ON POSTGRESQL, because it writes `sts_ldap_entry_keys`, which
// PostgreSQL's schema has not got: its statements do not run there, and the
// `cluster-portable` mode cannot prove them.
//
// WHAT EACH CONTRACT IS, AND HOW IT IS KEPT HERE:
//
//   * THE FLUSH IS ONE TRANSACTION, the driver's (`withTransaction()`: BEGIN,
//     the fence first, COMMIT; a deadlock run again, `dialect.isRetryable()`).
//     Every EXISTING row it touches is locked first, by one `SELECT … ORDER
//     BY realm, dn_key FOR UPDATE` per chunk, so two flushes lock in one order.
//     The rows that did not exist are inserted by one multi-row INSERT in key
//     order. The three-way merge is `directory_merge.js`'s, unchanged.
//   * A ROW THAT APPEARED BETWEEN THE LOCK AND THE INSERT. READ COMMITTED takes
//     no gap lock, so another node can commit a row the lock did not find.
//     PostgreSQL answers that inside its one upsert (a blind row replaces, a
//     merged one is "lost" and merged after COMMIT, #447). Here a plain INSERT
//     that meets a duplicate is rolled back by the engine for that statement
//     alone, and the chunk is inserted again a row at a time: a blind row that
//     meets one is locked and replaced, a merged one goes to the driver's lost
//     rows, merged by `mergeLostRow()` after COMMIT in a transaction of its
//     own. Not `INSERT IGNORE`: IGNORE also turns a strict-mode refusal (a
//     value too long, a CHECK) into a warning and a truncated or skipped row.
//   * A ROW BEING DELETED is deleted only if this transaction found it under
//     its lock — read again, locked, for a key the first lock did not find —
//     so what is subtracted from the counts is what was removed.
//   * THE KEY ROWS (`sts_ldap_entry_keys`, MariaDB's stand-in for GIN): every
//     entry written or deleted has its rows deleted and its current ones
//     inserted, in the same transaction, from the same `directory_codec` index
//     the JSON columns are filled from. The entry's own row lock orders two
//     writers of one entry, so they never race on its key rows.
//   * THE COUNTS (`sts_ldap_counts`, `sts_ldap_dek_counts`). PostgreSQL's
//     triggers append per-statement deltas and fold them at COMMIT; MariaDB has
//     no statement trigger, so the deltas are computed HERE from what each
//     statement replaced (the old row came from the lock, the new one is what
//     was written) — per base of the entry's parent (the parent, every suffix
//     after a comma, and '' for the realm: `sts_ldap_count_bases()`), for the
//     entries and for each COUNTED attribute's holders, and per data key, the
//     values each `dek_keys` names — and folded before COMMIT, last, in key
//     order, into one shard (0–15, chosen per transaction as PostgreSQL's is
//     per connection). A count row is MADE TO EXIST FIRST, by an autocommit
//     `INSERT IGNORE … n = 0` on the driver's TALLY pool — not the pool the
//     flush holds a connection from, which twenty flushes waiting on each
//     other's would exhaust — (its values are bounded, so IGNORE
//     hides nothing), and then updated `n = n + ?` by one statement under the
//     transaction: an insert of a missing row inside it would take a lock out
//     of key order, and an upsert's duplicate path an exclusive one too early.
//     What PostgreSQL's TRUNCATE trigger does is not done: the service's
//     account cannot TRUNCATE (`mariadb/CLAUDE.md`).
//   * AN EMPTY STORE HAS ZERO COUNTS, and every writer of `sts_ldap_entries`
//     on MariaDB is this library (the bulk import and the cell conversion are
//     refused on the engine), so the counts equal a fresh count from the first
//     row. A table loaded some other way is not supported — nothing here
//     backfills the counts or the key rows, where PostgreSQL's open() counts
//     the table once under a lock.
//   * `dek_keys` IS NEVER NULL HERE: every writer above writes it, and a
//     MariaDB store is built at schema version 31. So nothing is left for
//     `indexSealed()` to catch up and the data-key counts are never refused
//     for it; asking "is any NULL" would be a scan (the partial index
//     PostgreSQL asks is not in MariaDB's schema).
//   * REMOVED REALMS: their rows, key rows, count rows, registry row and
//     minted rows deleted; what the rows held under each data key subtracted,
//     read a page at a time under the lock.
//   * SIZE: a DN key over 352 characters, or a realm over 64, cannot be a key
//     of `sts_ldap_entries` (InnoDB's 3072-byte limit); the flush is refused
//     before it writes, STS-STORE-0140. A LOOKUP value over 344 is digested
//     (`directory_queries_mariadb.tableKey()`).
//
// A LIBRARY, built by the driver with its dialect, pools and helpers; it
// requires the error-code table, bunyan, `directory_merge.js`,
// `directory_queries.js` and its MariaDB spelling, and `common/crypto`
// lazily (the shard).
// ---------------------------------------------------------------------------

const errorCodes = require('../common/error_codes');
const directoryMerge = require('./directory_merge');
const directoryQueries = require('./directory_queries');
const mariadbQueries = require('./directory_queries_mariadb');

const log = require('bunyan').createLogger({
  name: 'sts-directory-portable',
  level: process.env.STS_LOG_LEVEL || process.env.LOG_LEVEL || 'info'
});

// The widths `mariadb/CLAUDE.md` gives the keyed columns.
const DN_KEY_LIMIT = 352;
const REALM_LIMIT = 64;
// How many entries one locking read, one write or one key-row DELETE carries.
const ENTRIES_PER_STATEMENT = 500;
// How many key rows one INSERT carries.
const KEY_ROWS_PER_STATEMENT = 1000;
// How many count rows one fold statement carries.
const COUNT_ROWS_PER_STATEMENT = 200;
// A page of the restore, of a removed realm's walk, of a sealed walk.
const PAGE = 1000;
// PostgreSQL's COUNT_SHARDS.
const COUNT_SHARDS = 16;

// The fourteen columns an entry is written with, in `entryWrite()`'s order.
const WRITE_COLUMNS = ['realm', 'dn_key', 'dn', 'attrs', 'origin',
                       'created_at', 'modified_at', 'name_keys', 'mail_keys',
                       'uuid_keys', 'class_keys', 'value_keys', 'attr_names',
                       'dek_keys'];
// The columns an entry is read with, PostgreSQL's order.
const READ_COLUMNS = 'realm, dn_key, dn, attrs, origin, created_at, ' +
                     'modified_at';
// ...and what a lock also reads: what the counts subtract.
const LOCK_COLUMNS = READ_COLUMNS + ', attr_names, dek_keys';

// A sealed value's data key, as `persistence_postgres.js`'s countAllSealed()
// pattern finds it.
const SEALED_ID = /\$aes(?:gcm|siv)\$2\$([A-Za-z0-9_.-]+)\$/g;

/**
 * The bases a row with this parent is strictly under: the parent, every
 * suffix after a comma, and '' unless the parent is '' — PostgreSQL's
 * `sts_ldap_count_bases()`, a duplicate included where it has one.
 *
 * @param parent - the row's parent key
 * @returns the bases
 */
function basesOf(parent) {
  log.debug("Entering basesOf().");
  const p = String(parent);
  const out = [p];
  for (let i = 0; i < p.length; i++) {
    if (p.charAt(i) === ',') {
      out.push(p.slice(i + 1));
    }
  }
  if (p !== '') {
    out.push('');
  }
  log.debug("Leaving basesOf().");
  return out;
}

/**
 * A JSON column's value as an object or array, whichever shape the
 * connection answered (`mysql2` parses MariaDB's JSON; text is parsed here).
 *
 * @param value - the column value
 * @returns the value, parsed where it was text that parses
 */
function jsonOf(value) {
  log.debug("Entering jsonOf().");
  if (typeof value !== 'string') {
    log.debug("Leaving jsonOf().");
    return value;
  }
  try {
    const parsed = JSON.parse(value);
    log.debug("Leaving jsonOf(). Parsed.");
    return parsed;
  } catch (e) {
    // A sealed blob comes back as the string it is, which is not JSON.
    log.debug("Caught in jsonOf(): " + ((e && e.message) || e));
    log.debug("Leaving jsonOf(). A string.");
    return value;
  }
}

/**
 * A row as read, its JSON columns in the shape `pg` answers (`attrs` the
 * object or the sealed string).
 *
 * @param row - a row of `sts_ldap_entries`
 * @returns the row
 */
function shaped(row) {
  log.debug("Entering shaped().");
  const out = Object.assign({}, row);
  ['attrs', 'attr_names', 'dek_keys'].forEach(function (name) {
    if (Object.prototype.hasOwnProperty.call(out, name)) {
      out[name] = jsonOf(out[name]);
    }
  });
  log.debug("Leaving shaped().");
  return out;
}

/**
 * Builds the directory's MariaDB store over one driver's connections.
 *
 * @param deps - `{ dialect, pool, readPool, entryCodec, entryFromRow,
 *   openedOfRow, withTransaction, recordChanges, releaseClaims, maintenance,
 *   extraSealed, sealedLike, resealText, ensurePool }`
 * @returns the operations the driver delegates to
 */
function create(deps) {
  log.debug("Entering create().");
  const dialect = deps.dialect;
  const pool = deps.pool;
  const readPool = deps.readPool || deps.pool;
  // WHERE A MISSING COUNT ROW IS MADE: a pool other than the one the flush
  // holds its connection from (the driver's tally pool), so a flush waiting
  // for it can never be waiting for a connection another flush holds while
  // that flush waits for one too. Its statements are single autocommit
  // inserts, so nothing on it is held long.
  const ensurePool = deps.ensurePool || deps.pool;
  const entryCodec = deps.entryCodec;
  const entryFromRow = deps.entryFromRow;
  const recordChanges = deps.recordChanges;
  const maintenance = deps.maintenance || function (what, fn) {
    return fn();
  };

  /**
   * Sends one statement, its name at the end as the builder's are.
   *
   * @param runner - a pool or a held connection
   * @param name - the statement's name
   * @param text - MariaDB text, `?` placeholders
   * @param values - its values
   * @returns the connection's answer
   */
  function send(runner, name, text, values) {
    log.debug("Entering send(). " + name);
    log.debug("Leaving send().");
    return runner.query(text + ' /* sts:directory.' + name + ' */',
                        values || []);
  }

  /**
   * The rows of an answer, shaped.
   *
   * @param result - a connection's answer
   * @returns the rows
   */
  function rowsOf(result) {
    log.debug("Entering rowsOf().");
    log.debug("Leaving rowsOf().");
    return dialect.rowsOf(result).map(shaped);
  }

  /**
   * `fn` over `list` in chunks of `size`, one after another.
   *
   * @param list - the items
   * @param size - the chunk size
   * @param fn - given a chunk; answers a promise
   * @returns a promise settled after the last
   */
  async function inChunks(list, size, fn) {
    log.debug("Entering inChunks(). " + list.length);
    for (let at = 0; at < list.length; at += size) {
      await fn(list.slice(at, at + size));
    }
    log.debug("Leaving inChunks().");
  }

  // =========================================================================
  // READS
  // =========================================================================

  /**
   * The whole directory, a primary-key page at a time, in key order.
   *
   * @returns `{ rows }`, every row
   */
  async function loadRows() {
    log.debug("Entering loadRows().");
    const out = [];
    let afterRealm = null;
    let afterKey = '';
    for (;;) {
      const r = afterRealm === null
        ? await send(readPool, 'load', 'SELECT ' + READ_COLUMNS + ' FROM ' +
            'sts_ldap_entries ORDER BY realm, dn_key LIMIT ?', [PAGE])
        : await send(readPool, 'load', 'SELECT ' + READ_COLUMNS + ' FROM ' +
            'sts_ldap_entries WHERE realm > ? OR (realm = ? AND dn_key > ?) ' +
            'ORDER BY realm, dn_key LIMIT ?',
            [afterRealm, afterRealm, afterKey, PAGE]);
      const rows = rowsOf(r);
      rows.forEach(function (row) {
        out.push(row);
      });
      if (rows.length < PAGE) {
        break;
      }
      afterRealm = rows[rows.length - 1].realm;
      afterKey = rows[rows.length - 1].dn_key;
    }
    log.debug("Leaving loadRows(). " + out.length + " row(s).");
    return { rows: out };
  }

  /**
   * One entry's row.
   *
   * @param realmId - the realm
   * @param dnKey - the key
   * @returns `{ rows }`
   */
  function readRow(realmId, dnKey) {
    log.debug("Entering readRow().");
    log.debug("Leaving readRow().");
    return send(readPool, 'readEntry', 'SELECT ' + READ_COLUMNS + ' FROM ' +
      'sts_ldap_entries WHERE realm = ? AND dn_key = ?',
      [String(realmId), String(dnKey)]).then(function (r) {
      return { rows: rowsOf(r) };
    });
  }

  /**
   * A directory question (`directory_queries.js`'s names), its arguments
   * keyed already, answered as rows for `directory_queries.answerOf()`.
   *
   * @param name - the question
   * @param args - its keyed arguments
   * @returns the rows
   */
  function query(name, args) {
    log.debug("Entering query(). " + name);
    const ask = function (step, text, values) {
      return send(readPool, 'q.' + step, text, values).then(rowsOf);
    };
    log.debug("Leaving query().");
    return mariadbQueries.run(ask, name, args);
  }

  // =========================================================================
  // WHAT A WRITE CHANGES IN THE COUNTS
  // =========================================================================

  /**
   * A transaction's pending count changes.
   *
   * @returns `{ counts: Map, deks: Map, removed: Set }`
   */
  function freshTally() {
    log.debug("Entering freshTally().");
    log.debug("Leaving freshTally().");
    return { counts: new Map(), deks: new Map(), removed: new Set() };
  }

  /**
   * Adds (sign 1) or takes away (sign -1) one row's part of the counts.
   *
   * @param tally - the transaction's tally
   * @param state - `{ realm, key, attrNames, dekKeys }`
   * @param sign - 1 or -1
   */
  function contribute(tally, state, sign) {
    log.debug("Entering contribute().");
    const names = Array.isArray(state.attrNames) ? state.attrNames : [];
    const held = directoryQueries.COUNTED_ATTRIBUTES.filter(function (one) {
      return names.indexOf(one) >= 0;
    });
    basesOf(directoryQueries.parentOf(state.key)).forEach(function (base) {
      [''].concat(held).forEach(function (attribute) {
        const id = JSON.stringify([String(state.realm), base, attribute]);
        tally.counts.set(id, (tally.counts.get(id) || 0) + sign);
      });
    });
    const deks = state.dekKeys;
    if (deks && typeof deks === 'object' && !Array.isArray(deks)) {
      Object.keys(deks).forEach(function (dekId) {
        const n = Math.floor(Number(deks[dekId]) || 0);
        if (dekId && n) {
          tally.deks.set(dekId, (tally.deks.get(dekId) || 0) + sign * n);
        }
      });
    }
    log.debug("Leaving contribute().");
  }

  /**
   * A stored row as `contribute()` reads it.
   *
   * @param row - a locked row (`LOCK_COLUMNS`)
   * @returns its state
   */
  function stateOfRow(row) {
    log.debug("Entering stateOfRow().");
    log.debug("Leaving stateOfRow().");
    return { realm: row.realm, key: row.dn_key,
             attrNames: jsonOf(row.attr_names) || [],
             dekKeys: jsonOf(row.dek_keys) };
  }

  /**
   * Folds one table's pending changes into one shard, in key order: the rows
   * made to exist on the pool first, then one UPDATE a chunk under the
   * transaction.
   *
   * @param client - the transaction's connection
   * @param table - `sts_ldap_counts` or `sts_ldap_dek_counts`
   * @param columns - the key columns but the shard
   * @param rows - `[{ key: [...], n }]`, sorted
   * @param shard - the shard
   * @returns a promise settled once folded
   */
  async function foldInto(client, table, columns, rows, shard) {
    log.debug("Entering foldInto(). " + table + " " + rows.length);
    const tuple = '(' + mariadbQueries.marks(columns.length) + ')';
    const match = columns.map(function (c) {
      return c + ' = ?';
    }).join(' AND ');
    await inChunks(rows, COUNT_ROWS_PER_STATEMENT, async function (chunk) {
      const keys = [];
      chunk.forEach(function (row) {
        row.key.forEach(function (v) {
          keys.push(v);
        });
      });
      const inList = chunk.map(function () {
        return tuple;
      }).join(', ');
      const found = rowsOf(await send(client, 'fold.exists', 'SELECT ' +
        columns.join(', ') + ' FROM ' + table + ' WHERE shard = ? AND (' +
        columns.join(', ') + ') IN (' + inList + ')', [shard].concat(keys)));
      const have = new Set(found.map(function (row) {
        return JSON.stringify(columns.map(function (c) {
          return String(row[c]);
        }));
      }));
      const missing = chunk.filter(function (row) {
        return !have.has(JSON.stringify(row.key.map(String)));
      });
      if (missing.length) {
        // MADE TO EXIST OUTSIDE THE TRANSACTION, so the UPDATE below is the
        // only lock it takes on them, in key order with the rest.
        const values = [];
        missing.forEach(function (row) {
          row.key.forEach(function (v) {
            values.push(v);
          });
          values.push(shard);
        });
        await send(ensurePool, 'fold.ensure', 'INSERT IGNORE INTO ' + table +
          ' (' +
          columns.join(', ') + ', shard, n) VALUES ' +
          missing.map(function () {
            return '(' + mariadbQueries.marks(columns.length + 1) + ', 0)';
          }).join(', '), values);
      }
      const cases = [];
      const values = [];
      chunk.forEach(function (row) {
        cases.push('WHEN ' + match + ' THEN ?');
        row.key.forEach(function (v) {
          values.push(v);
        });
        values.push(row.n);
      });
      const r = await send(client, 'fold', 'UPDATE ' + table + ' SET n = n ' +
        '+ CASE ' + cases.join(' ') + ' ELSE 0 END WHERE shard = ? AND (' +
        columns.join(', ') + ') IN (' + inList + ')',
        values.concat([shard], keys));
      if (dialect.affected(r) !== chunk.length) {
        // Only a removed realm deletes count rows; a fold that lost one to it
        // would count into nothing, and must not commit as if it had not.
        throw errorCodes.mark(new Error(errorCodes.tag('STS-STORE-0141') +
          'directory_portable: ' + table + ': ' +
          (chunk.length - dialect.affected(r)) + ' count row(s) vanished ' +
          'between their insert and the fold'), 'STS-STORE-0141');
      }
    });
    log.debug("Leaving foldInto().");
  }

  /**
   * A transaction's count changes, folded: last, before COMMIT.
   *
   * @param client - the transaction's connection
   * @param tally - its tally
   * @returns a promise settled once folded
   */
  async function foldTally(client, tally) {
    log.debug("Entering foldTally().");
    const counts = [];
    tally.counts.forEach(function (n, id) {
      const key = JSON.parse(id);
      if (n && !tally.removed.has(key[0])) {
        counts.push({ key: key, n: n });
      }
    });
    const deks = [];
    tally.deks.forEach(function (n, id) {
      if (n) {
        deks.push({ key: [id], n: n });
      }
    });
    if (!counts.length && !deks.length) {
      log.debug("Leaving foldTally(). Nothing moved.");
      return;
    }
    const byKey = function (a, b) {
      const left = a.key;
      const right = b.key;
      for (let i = 0; i < left.length; i++) {
        if (left[i] !== right[i]) {
          return left[i] < right[i] ? -1 : 1;
        }
      }
      return 0;
    };
    counts.sort(byKey);
    deks.sort(byKey);
    const shard = require('../common/crypto').randomInt(0, COUNT_SHARDS);
    await foldInto(client, 'sts_ldap_counts',
                   ['realm', 'base_key', 'attribute'], counts, shard);
    await foldInto(client, 'sts_ldap_dek_counts', ['dek_id'], deks, shard);
    log.debug("Leaving foldTally().");
  }

  // =========================================================================
  // WRITES
  // =========================================================================

  /**
   * Refuses keys MariaDB cannot hold, before anything is written.
   *
   * @param rows - `[{ realm, key }]`
   */
  function checkSizes(rows) {
    log.debug("Entering checkSizes().");
    rows.forEach(function (row) {
      const realm = String(row.realm || '');
      const key = String(row.key || '');
      if (Array.from(key).length > DN_KEY_LIMIT ||
          Array.from(realm).length > REALM_LIMIT) {
        log.debug("Leaving checkSizes(). Too long.");
        throw errorCodes.mark(new Error(errorCodes.tag('STS-STORE-0140') +
          'the directory entry ' + key.slice(0, 80) + '… in the "' +
          realm.slice(0, 64) + '" realm cannot be stored on MariaDB: its DN ' +
          'key is ' + Array.from(key).length + ' characters (at most ' +
          DN_KEY_LIMIT + ') or its realm over ' + REALM_LIMIT + '.'),
          'STS-STORE-0140');
      }
    });
    log.debug("Leaving checkSizes().");
  }

  /**
   * What one entry is written as: the fourteen values, its key rows and its
   * part of the counts.
   *
   * @param realmId - the realm
   * @param dnKey - the key
   * @param entry - the entry, plaintext
   * @returns `{ values, keys, state }`
   */
  function entryWrite(realmId, dnKey, entry) {
    log.debug("Entering entryWrite().");
    const attrs = (entry && entry.attributes) || {};
    const index = entryCodec.index(attrs);
    const sealed = entryCodec.sealAttributes(realmId, dnKey, attrs);
    const dekKeys = entryCodec.dekKeys(attrs, sealed);
    const keys = [];
    const seen = new Set();
    const add = function (kind, k) {
      const id = kind + '\n' + k;
      if (!seen.has(id)) {
        seen.add(id);
        keys.push({ kind: kind, k: k });
      }
    };
    [['name', index.nameKeys], ['mail', index.mailKeys],
     ['uuid', index.uuidKeys], ['class', index.classKeys],
     ['value', index.valueKeys]].forEach(function (pair) {
      (pair[1] || []).forEach(function (one) {
        add(pair[0], mariadbQueries.tableKey(one));
      });
    });
    (index.attrNames || []).forEach(function (name) {
      if (directoryQueries.ASKED_ATTRIBUTES.indexOf(name) >= 0) {
        add('attr', mariadbQueries.tableKey(name));
      }
    });
    Object.keys(dekKeys || {}).forEach(function (dekId) {
      add('dek', mariadbQueries.tableKey(dekId));
    });
    log.debug("Leaving entryWrite().");
    return {
      values: [String(realmId), String(dnKey), entry.dn,
               JSON.stringify(sealed), entry.origin || null,
               entry.createdAt || null, entry.modifiedAt || null,
               JSON.stringify(index.nameKeys), JSON.stringify(index.mailKeys),
               JSON.stringify(index.uuidKeys), JSON.stringify(index.classKeys),
               JSON.stringify(index.valueKeys),
               JSON.stringify(index.attrNames), JSON.stringify(dekKeys)],
      keys: keys,
      state: { realm: String(realmId), key: String(dnKey),
               attrNames: index.attrNames, dekKeys: dekKeys }
    };
  }

  /**
   * The INSERT of several entries, and its values.
   *
   * @param writes - `entryWrite()` answers
   * @param replace - true to replace a row that is there (the rows are
   *   locked and exist), false for a plain insert
   * @returns `{ text, values }`
   */
  function insertOf(writes, replace) {
    log.debug("Entering insertOf().");
    const row = '(' + mariadbQueries.marks(WRITE_COLUMNS.length) + ')';
    const values = [];
    writes.forEach(function (w) {
      w.values.forEach(function (v) {
        values.push(v === undefined ? null : v);
      });
    });
    let text = 'INSERT INTO sts_ldap_entries (' + WRITE_COLUMNS.join(', ') +
               ') VALUES ' + writes.map(function () {
                 return row;
               }).join(', ');
    if (replace) {
      text += ' ON DUPLICATE KEY UPDATE ' + WRITE_COLUMNS.slice(2)
        .map(function (c) {
          return c + ' = VALUES(' + c + ')';
        }).join(', ');
    }
    log.debug("Leaving insertOf().");
    return { text: text, values: values };
  }

  /**
   * Locks and reads the rows at some keys, in key order.
   *
   * @param client - the transaction's connection
   * @param keys - `[{ realm, key }]`, sorted
   * @returns a Map of `realm\nkey` to the shaped row
   */
  async function lockRows(client, keys) {
    log.debug("Entering lockRows(). " + keys.length);
    const found = new Map();
    await inChunks(keys, ENTRIES_PER_STATEMENT, async function (chunk) {
      const values = [];
      chunk.forEach(function (one) {
        values.push(String(one.realm), String(one.key));
      });
      const r = await send(client, 'lock', 'SELECT ' + LOCK_COLUMNS +
        ' FROM sts_ldap_entries WHERE (realm, dn_key) IN (' +
        chunk.map(function () {
          return '(?, ?)';
        }).join(', ') + ') ORDER BY realm, dn_key FOR UPDATE', values);
      rowsOf(r).forEach(function (row) {
        found.set(String(row.realm) + '\n' + String(row.dn_key), row);
      });
    });
    log.debug("Leaving lockRows(). " + found.size + " found.");
    return found;
  }

  /**
   * Every written or deleted entry's key rows replaced by its current ones.
   *
   * @param client - the transaction's connection
   * @param entries - `[{ realm, key, keys }]`, `keys` [] for a deleted one
   * @returns a promise settled once written
   */
  async function rewriteKeys(client, entries) {
    log.debug("Entering rewriteKeys(). " + entries.length);
    await inChunks(entries, ENTRIES_PER_STATEMENT, async function (chunk) {
      const values = [];
      chunk.forEach(function (one) {
        values.push(String(one.realm), String(one.key));
      });
      await send(client, 'keys.delete', 'DELETE FROM sts_ldap_entry_keys ' +
        'WHERE (realm, dn_key) IN (' + chunk.map(function () {
          return '(?, ?)';
        }).join(', ') + ')', values);
    });
    const rows = [];
    entries.forEach(function (one) {
      one.keys.forEach(function (k) {
        rows.push([String(one.realm), k.kind, k.k, String(one.key)]);
      });
    });
    await inChunks(rows, KEY_ROWS_PER_STATEMENT, async function (chunk) {
      const values = [];
      chunk.forEach(function (one) {
        one.forEach(function (v) {
          values.push(v);
        });
      });
      await send(client, 'keys.insert', 'INSERT INTO sts_ldap_entry_keys ' +
        '(realm, kind, k, dn_key) VALUES ' + chunk.map(function () {
          return '(?, ?, ?, ?)';
        }).join(', '), values);
    });
    log.debug("Leaving rewriteKeys().");
  }

  /**
   * Replaces rows that exist and this transaction has locked, one statement
   * a chunk, in key order.
   *
   * @param client - the transaction's connection
   * @param items - `[{ write, old }]`, `old` the locked row
   * @param tally - the transaction's tally
   * @returns a promise settled once written
   */
  async function replaceLocked(client, items, tally) {
    log.debug("Entering replaceLocked(). " + items.length);
    await inChunks(items, ENTRIES_PER_STATEMENT, async function (chunk) {
      const statement = insertOf(chunk.map(function (one) {
        return one.write;
      }), true);
      await send(client, 'replace', statement.text, statement.values);
      chunk.forEach(function (one) {
        contribute(tally, stateOfRow(one.old), -1);
        contribute(tally, one.write.state, 1);
      });
    });
    log.debug("Leaving replaceLocked().");
  }

  /**
   * Inserts rows the lock did not find, in key order: one statement a chunk,
   * or — where a row appeared meanwhile — one a row, each telling which.
   *
   * @param client - the transaction's connection
   * @param items - `[{ write, blind }]`, sorted
   * @param tally - the transaction's tally
   * @returns `{ inserted: [...items], replaced: [...items], lost: [...] }`
   */
  async function insertNew(client, items, tally) {
    log.debug("Entering insertNew(). " + items.length);
    const out = { inserted: [], replaced: [], lost: [] };
    await inChunks(items, ENTRIES_PER_STATEMENT, async function (chunk) {
      const statement = insertOf(chunk.map(function (one) {
        return one.write;
      }), false);
      let whole = true;
      try {
        await send(client, 'insert', statement.text, statement.values);
      } catch (e) {
        log.debug("Caught in insertNew(): " + ((e && e.message) || e));
        if (!dialect.isUniqueViolation(e)) {
          throw e;
        }
        // The engine rolled back this statement alone; the chunk again, a
        // row at a time.
        whole = false;
      }
      if (whole) {
        chunk.forEach(function (one) {
          contribute(tally, one.write.state, 1);
          out.inserted.push(one);
        });
        return;
      }
      for (const one of chunk) {
        const single = insertOf([one.write], false);
        let mine = true;
        try {
          await send(client, 'insert.one', single.text, single.values);
        } catch (e) {
          log.debug("Caught in insertNew(): " + ((e && e.message) || e));
          if (!dialect.isUniqueViolation(e)) {
            throw e;
          }
          mine = false;
        }
        if (mine) {
          contribute(tally, one.write.state, 1);
          out.inserted.push(one);
          continue;
        }
        if (!one.blind) {
          out.lost.push(one);
          continue;
        }
        // A blind row replaces what another node committed, as PostgreSQL's
        // upsert does; locked first, so what it replaced is known.
        const locked = await lockRows(client, [{
          realm: one.write.state.realm, key: one.write.state.key }]);
        const old = locked.get(one.write.state.realm + '\n' +
                               one.write.state.key);
        if (old) {
          await replaceLocked(client, [{ write: one.write, old: old }], tally);
        } else {
          // Gone again between the duplicate and the lock: an insert after
          // all (the lock now covers it).
          await send(client, 'insert.one', single.text, single.values);
          contribute(tally, one.write.state, 1);
        }
        out.replaced.push(one);
      }
    });
    log.debug("Leaving insertNew().");
    return out;
  }

  /**
   * Deletes the rows at some keys that this transaction holds, the counts
   * told what went.
   *
   * @param client - the transaction's connection
   * @param keys - `[{ realm, key }]`
   * @param locked - the rows the flush's lock found
   * @param tally - the transaction's tally
   * @returns a promise settled once deleted
   */
  async function deleteHeld(client, keys, locked, tally) {
    log.debug("Entering deleteHeld(). " + keys.length);
    const misses = keys.filter(function (one) {
      return !locked.has(String(one.realm) + '\n' + String(one.key));
    });
    // A key the first lock did not find, read again under a lock: a row
    // committed since is deleted with the rest and subtracted.
    const late = misses.length ? await lockRows(client, misses.slice().sort(
      function (a, b) {
        const left = String(a.realm) + '\n' + String(a.key);
        const right = String(b.realm) + '\n' + String(b.key);
        return left < right ? -1 : left > right ? 1 : 0;
      })) : new Map();
    const doomed = [];
    keys.forEach(function (one) {
      const id = String(one.realm) + '\n' + String(one.key);
      const row = locked.get(id) || late.get(id);
      if (row) {
        doomed.push(row);
      }
    });
    await inChunks(doomed, ENTRIES_PER_STATEMENT, async function (chunk) {
      const values = [];
      chunk.forEach(function (row) {
        values.push(String(row.realm), String(row.dn_key));
      });
      await send(client, 'delete', 'DELETE FROM sts_ldap_entries WHERE ' +
        '(realm, dn_key) IN (' + chunk.map(function () {
          return '(?, ?)';
        }).join(', ') + ')', values);
      chunk.forEach(function (row) {
        contribute(tally, stateOfRow(row), -1);
      });
    });
    log.debug("Leaving deleteHeld(). " + doomed.length + " deleted.");
  }

  /**
   * A realm that went away: what its rows hold under each data key
   * subtracted, a locked page at a time, then its rows, key rows, counts,
   * registry row and minted rows deleted.
   *
   * @param client - the transaction's connection
   * @param realmId - the realm
   * @param tally - the transaction's tally
   * @returns a promise settled once removed
   */
  async function removeRealm(client, realmId, tally) {
    log.debug("Entering removeRealm(). " + realmId);
    const realm = String(realmId);
    let after = '';
    for (;;) {
      const rows = rowsOf(await send(client, 'realm.walk', 'SELECT realm, ' +
        'dn_key, dek_keys FROM sts_ldap_entries WHERE realm = ? AND dn_key > ' +
        '? ORDER BY dn_key LIMIT ? FOR UPDATE', [realm, after, PAGE]));
      rows.forEach(function (row) {
        contribute(tally, { realm: realm, key: row.dn_key, attrNames: [],
                            dekKeys: jsonOf(row.dek_keys) }, -1);
      });
      if (rows.length < PAGE) {
        break;
      }
      after = rows[rows.length - 1].dn_key;
    }
    tally.removed.add(realm);
    await send(client, 'realm.entries', 'DELETE FROM sts_ldap_entries WHERE ' +
               'realm = ?', [realm]);
    await send(client, 'realm.keys', 'DELETE FROM sts_ldap_entry_keys WHERE ' +
               'realm = ?', [realm]);
    await send(client, 'realm.counts', 'DELETE FROM sts_ldap_counts WHERE ' +
               'realm = ?', [realm]);
    await send(client, 'realm.registry', 'DELETE FROM sts_realms WHERE id = ?',
               [realm]);
    // Everything the realm minted, for `saveDirectory()`'s reason (a removed
    // realm's sessions would come back at the next start). A scan, as there.
    await send(client, 'realm.minted', 'DELETE FROM sts_minted WHERE realm = ?',
               [realm]);
    log.debug("Leaving removeRealm().");
  }

  /**
   * THE DIRECTORY FLUSH'S TRANSACTION: `saveDirectory()`'s body on MariaDB.
   *
   * @param client - the transaction's connection (fenced already)
   * @param ctx - `{ merging, blind, deletes, removedRealms, releasing,
   *   outcomes, pendingLost, mergingIds }` from the driver, the arrays
   *   `outcomes` and `pendingLost` filled here
   * @returns a promise settled before COMMIT
   */
  async function flushBody(client, ctx) {
    log.debug("Entering flushBody().");
    const idOf = function (realm, key) {
      return String(realm) + '\n' + String(key);
    };
    const byKey = function (a, b) {
      const left = idOf(a.realm, a.key);
      const right = idOf(b.realm, b.key);
      return left < right ? -1 : left > right ? 1 : 0;
    };
    const moved = [];
    const tally = freshTally();
    ctx.pendingLost.length = 0;
    // Only what is WRITTEN: a delete of a key no row can have finds nothing.
    checkSizes(ctx.merging.concat(ctx.blind));

    // THE LOCKS, every row this flush touches, in key order.
    const locked = await lockRows(client, ctx.merging.concat(ctx.blind,
                                  ctx.deletes).sort(byKey));

    // THE WRITES, each key once: its last blind row, else its last merged.
    const chosen = new Map();
    ctx.merging.forEach(function (row) {
      chosen.set(idOf(row.realm, row.key), { row: row, merge: true });
    });
    ctx.blind.forEach(function (row) {
      chosen.set(idOf(row.realm, row.key), { row: row, merge: false });
    });
    const writes = Array.from(chosen.values()).sort(function (a, b) {
      return byKey(a.row, b.row);
    });
    const replaces = [];
    const inserts = [];
    writes.forEach(function (one) {
      const row = one.row;
      const old = locked.get(idOf(row.realm, row.key)) || null;
      let entry = row.entry;
      if (one.merge) {
        // ONLY A ROW BEING MERGED IS OPENED (PostgreSQL's 2026-10-02 note).
        const theirs = old ? entryFromRow(old) : null;
        const base = row.base ? JSON.parse(row.base) : null;
        const verdict = directoryMerge.mergeEntry(base, row.entry, theirs);
        if (verdict.outcome === 'theirs' || verdict.outcome === 'deleted') {
          ctx.outcomes.push({ realm: row.realm, key: row.key,
                              outcome: verdict.outcome,
                              entry: verdict.entry });
          return;
        }
        if (verdict.outcome === 'merged') {
          ctx.outcomes.push({ realm: row.realm, key: row.key,
                              outcome: 'merged', entry: verdict.entry });
        }
        entry = verdict.entry;
      }
      const write = entryWrite(row.realm, row.key, entry);
      if (old) {
        replaces.push({ row: row, write: write, old: old });
      } else {
        inserts.push({ row: row, write: write, blind: !one.merge });
      }
    });
    // Each entry's key rows once, as it is when the flush is done: a key
    // written and then deleted by the same flush keeps none.
    const keyed = new Map();
    const keysOf = function (realm, key, keys) {
      keyed.set(idOf(realm, key), { realm: realm, key: key, keys: keys });
    };
    await replaceLocked(client, replaces, tally);
    replaces.forEach(function (one) {
      moved.push({ realm: one.row.realm, dn: one.row.key });
      keysOf(one.row.realm, one.row.key, one.write.keys);
    });
    const answer = await insertNew(client, inserts, tally);
    answer.inserted.concat(answer.replaced).forEach(function (one) {
      moved.push({ realm: one.row.realm, dn: one.row.key });
      keysOf(one.row.realm, one.row.key, one.write.keys);
    });
    // A MERGED INSERT THAT MET A ROW committed since the lock: merged after
    // COMMIT, one row to a transaction (#447).
    answer.lost.forEach(function (one) {
      ctx.pendingLost.push(one.row);
    });

    await deleteHeld(client, ctx.deletes, locked, tally);
    ctx.deletes.forEach(function (row) {
      moved.push({ realm: row.realm, dn: row.key });
      keysOf(row.realm, row.key, []);
    });
    await rewriteKeys(client, Array.from(keyed.values()));

    for (const realmId of ctx.removedRealms || []) {
      await removeRealm(client, realmId, tally);
    }
    if ((ctx.releasing || []).length) {
      await deps.releaseClaims(client, ctx.releasing);
    }
    await foldTally(client, tally);
    await recordChanges(client, moved.map(function (one) {
      return { kind: 'directory', realm: one.realm, key: one.dn };
    }));
    log.debug("Leaving flushBody(). " + moved.length + " moved.");
  }

  /**
   * A merged insert that lost, merged after the flush committed, in a
   * transaction that locks only its row: the driver's `mergeLostRow()`.
   *
   * @param client - the transaction's connection
   * @param row - the flush's row
   * @param outcomes - the flush's outcomes, amended
   * @returns a promise settled before COMMIT
   */
  async function mergeLostRow(client, row, outcomes) {
    log.debug("Entering mergeLostRow().");
    checkSizes([row]);
    const id = String(row.realm) + '\n' + String(row.key);
    const tally = freshTally();
    const locked = await lockRows(client, [{ realm: row.realm,
                                             key: row.key }]);
    const now = locked.get(id) || null;
    // Throws where the row does not open (STS-STORE-0072): saveDirectory()
    // reads the data keys again and tries once more.
    const theirs = now ? entryFromRow(now) : null;
    const base = row.base ? JSON.parse(row.base) : null;
    for (let i = outcomes.length - 1; i >= 0; i--) {
      if (outcomes[i].realm === row.realm && outcomes[i].key === row.key) {
        outcomes.splice(i, 1);
      }
    }
    const verdict = directoryMerge.mergeEntry(base, row.entry, theirs);
    if (verdict.outcome === 'theirs' || verdict.outcome === 'deleted') {
      outcomes.push({ realm: row.realm, key: row.key,
                      outcome: verdict.outcome, entry: verdict.entry });
      log.debug("Leaving mergeLostRow(). The stored row stands.");
      return;
    }
    if (verdict.outcome === 'merged') {
      outcomes.push({ realm: row.realm, key: row.key, outcome: 'merged',
                      entry: verdict.entry });
    }
    const write = entryWrite(row.realm, row.key, verdict.entry);
    if (now) {
      await replaceLocked(client, [{ write: write, old: now }], tally);
    } else {
      await insertNew(client, [{ write: write, blind: true }], tally);
    }
    await rewriteKeys(client, [{ realm: row.realm, key: row.key,
                                 keys: write.keys }]);
    await foldTally(client, tally);
    await recordChanges(client, [{ kind: 'directory', realm: row.realm,
                                   key: row.key }]);
    log.debug("Leaving mergeLostRow().");
  }

  // =========================================================================
  // WHAT IS SEALED UNDER EACH DATA KEY
  // =========================================================================

  /**
   * The directory's kept per-data-key counts, for the keys asked or all.
   * Never refused for unindexed entries: there are none here (the header).
   *
   * @param wanted - a Set of ids, or null for every key
   * @returns `{ <id>: n }`
   */
  function directoryDekCounts(wanted) {
    log.debug("Entering directoryDekCounts().");
    const ids = wanted ? Array.from(wanted).map(String) : null;
    if (ids && !ids.length) {
      log.debug("Leaving directoryDekCounts(). None asked.");
      return Promise.resolve({});
    }
    log.debug("Leaving directoryDekCounts().");
    return maintenance('the data-key count', function () {
      return send(pool, 'dekCounts', 'SELECT dek_id, CAST(SUM(n) AS SIGNED) ' +
        'AS n FROM sts_ldap_dek_counts' + (ids ? ' WHERE dek_id IN (' +
        mariadbQueries.marks(ids.length) + ')' : '') + ' GROUP BY dek_id',
        ids || []);
    }).then(function (r) {
      const counts = {};
      dialect.rowsOf(r).forEach(function (row) {
        counts[String(row.dek_id)] = Number(row.n) || 0;
      });
      return counts;
    });
  }

  /**
   * A column as it is compared and matched: a JSON column is LONGTEXT here,
   * so it is its own text.
   *
   * @param one - an extra sealed column (`EXTRA_SEALED`)
   * @returns the SQL
   */
  function columnOf(one) {
    log.debug("Entering columnOf().");
    log.debug("Leaving columnOf().");
    return '`' + one.column + '`';
  }

  /**
   * The tables outside the directory that hold sealed values, each with the
   * key columns that page it: PostgreSQL's three and `EXTRA_SEALED`.
   *
   * @returns `[{ table, keys, column, where?, jsonb, change }]`
   */
  function sealedTables() {
    log.debug("Entering sealedTables().");
    const out = [
      { table: 'sts_keys', keys: ['realm'], column: 'material',
        where: 'realm NOT LIKE \'dek:%\'' },
      { table: 'sts_minted', keys: ['handle', 'realm', 'key'],
        column: 'body' },
      { table: 'sts_cluster_secrets', keys: ['name'], column: 'material' }
    ].concat(deps.extraSealed || []);
    log.debug("Leaving sealedTables().");
    return out;
  }

  /**
   * How many values each data key in `ids` seals: one statement a key over
   * every sealed table (LIKE, as PostgreSQL's), and the directory's counts.
   *
   * @param ids - the data key ids
   * @returns `{ <id>: n }`
   */
  async function countSealed(ids) {
    log.debug("Entering countSealed(). " + ids.length);
    const tables = sealedTables();
    const out = {};
    for (const id of ids) {
      const like = deps.sealedLike(id);
      const parts = tables.map(function (one) {
        return '(SELECT COUNT(*) FROM ' + one.table + ' WHERE ' +
               (one.where ? one.where + ' AND ' : '') + columnOf(one) +
               ' LIKE ? ESCAPE \'\\\\\')';
      });
      const r = await maintenance('the data-key count', function () {
        return send(pool, 'countSealed', 'SELECT CAST(' + parts.join(' + ') +
          ' AS SIGNED) AS n', tables.map(function () {
            return like;
          }));
      });
      out[id] = Number((dialect.rowsOf(r)[0] || {}).n) || 0;
    }
    const inDirectory = await directoryDekCounts(new Set(ids));
    ids.forEach(function (id) {
      out[id] += Number(inDirectory[id]) || 0;
    });
    log.debug("Leaving countSealed().");
    return out;
  }

  /**
   * A keyset condition "after this row" over several key columns, written
   * out as ORs (the row form is not a range on MariaDB).
   *
   * @param keys - the key columns
   * @param after - their values, or null for the first page
   * @returns `{ text, values }`, text '' for the first page
   */
  function afterRow(keys, after) {
    log.debug("Entering afterRow().");
    if (!after) {
      log.debug("Leaving afterRow(). First.");
      return { text: '', values: [] };
    }
    const terms = [];
    const values = [];
    keys.forEach(function (key, i) {
      const parts = [];
      for (let j = 0; j < i; j++) {
        parts.push('`' + keys[j] + '` = ?');
        values.push(after[j]);
      }
      parts.push('`' + key + '` > ?');
      values.push(after[i]);
      terms.push('(' + parts.join(' AND ') + ')');
    });
    log.debug("Leaving afterRow().");
    return { text: '(' + terms.join(' OR ') + ')', values: values };
  }

  /**
   * Every data key's count at once: each sealed table read a page at a time
   * — only its rows holding a sealed value at all — and each value's key
   * counted here, as PostgreSQL's `regexp_matches(…, 'g')` counts it; and
   * the directory's kept counts. A pass over every sealed row, as there.
   *
   * @returns `{ <id>: n }`
   */
  async function countAllSealed() {
    log.debug("Entering countAllSealed().");
    const out = {};
    for (const one of sealedTables()) {
      const keyList = one.keys.map(function (k) {
        return '`' + k + '`';
      }).join(', ');
      let after = null;
      for (;;) {
        const cursor = afterRow(one.keys, after);
        const where = [columnOf(one) + ' LIKE ?']
          .concat(one.where ? [one.where] : [],
                  cursor.text ? [cursor.text] : []);
        const r = await maintenance('the data-key count', function () {
          return send(pool, 'countAllSealed', 'SELECT ' + keyList + ', ' +
            columnOf(one) + ' AS v FROM ' + one.table + ' WHERE ' +
            where.join(' AND ') + ' ORDER BY ' + keyList + ' LIMIT ?',
            /** @type {Array<string | number>} */ (['%$aes%$2$%'])
              .concat(cursor.values, [PAGE]));
        });
        const rows = dialect.rowsOf(r);
        rows.forEach(function (row) {
          const text = typeof row.v === 'string' ? row.v
            : JSON.stringify(row.v);
          let m;
          SEALED_ID.lastIndex = 0;
          while ((m = SEALED_ID.exec(text)) !== null) {
            out[m[1]] = (out[m[1]] || 0) + 1;
          }
        });
        if (rows.length < PAGE) {
          break;
        }
        const last = rows[rows.length - 1];
        after = one.keys.map(function (k) {
          return last[k];
        });
      }
    }
    const inDirectory = await directoryDekCounts(null);
    Object.keys(inDirectory).forEach(function (id) {
      out[id] = (out[id] || 0) + inDirectory[id];
    });
    log.debug("Leaving countAllSealed().");
    return out;
  }

  /**
   * The re-encryption pass: `resealSealed()`'s contract, PostgreSQL's
   * orchestration with MariaDB's statements. Every write is a compare and
   * swap on the value read; the directory's rows are found by their `dek`
   * key rows, a realm at a time.
   *
   * @param ids - the data keys being retired
   * @param reseal - a sealed value to its replacement, or null
   * @param options - `{ limit, ownHandle }`
   * @returns the tally
   */
  async function resealSealed(ids, reseal, options) {
    log.debug("Entering resealSealed(). " + ids.length);
    const limit = Math.max(1, Number(options && options.limit) || 500);
    const ownHandle = (options && options.ownHandle) || function () {
      return false;
    };
    const tally = { minted: 0, entries: 0, secrets: 0, skipped: 0,
                    changed: [] };
    const tx = function (fn) {
      return maintenance('the re-encryption pass', function () {
        return deps.withTransaction(fn);
      });
    };
    const ask = function (name, text, values) {
      return maintenance('the re-encryption pass', function () {
        return send(pool, name, text, values);
      });
    };
    for (const id of ids) {
      const like = deps.sealedLike(id);
      const minted = dialect.rowsOf(await ask('reseal.minted', 'SELECT ' +
        'handle, realm, `key`, body FROM sts_minted WHERE body LIKE ? ESCAPE ' +
        '\'\\\\\' LIMIT ?', [like, limit]));
      for (const row of minted) {
        const next = deps.resealText(row.body, reseal);
        if (!next) {
          tally.skipped += 1;
          continue;
        }
        await tx(async function (client) {
          const u = await send(client, 'reseal.minted.write', 'UPDATE ' +
            'sts_minted SET body = ?, written_at = CURRENT_TIMESTAMP(6) ' +
            'WHERE handle = ? AND realm = ? AND `key` = ? AND body = ?',
            [next, row.handle, row.realm, row.key, row.body]);
          if (!dialect.affected(u)) {
            return null;
          }
          tally.minted += 1;
          return recordChanges(client, [{
            kind: ownHandle(row.handle) ? 'minted-own' : 'minted',
            realm: row.realm,
            key: Buffer.from(String(row.handle), 'utf8')
                   .toString('base64url') + '.' +
                 Buffer.from(String(row.key), 'utf8').toString('base64url') }]);
        });
      }
      const secrets = dialect.rowsOf(await ask('reseal.secrets', 'SELECT ' +
        'name, material FROM sts_cluster_secrets WHERE material LIKE ? ' +
        'ESCAPE \'\\\\\' LIMIT ?', [like, limit]));
      for (const row of secrets) {
        const next = deps.resealText(row.material, reseal);
        if (!next) {
          tally.skipped += 1;
          continue;
        }
        const u = await ask('reseal.secrets.write', 'UPDATE ' +
          'sts_cluster_secrets SET material = ? WHERE name = ? AND material ' +
          '= ?', [next, row.name, row.material]);
        tally.secrets += dialect.affected(u) ? 1 : 0;
      }
      for (const one of deps.extraSealed || []) {
        await resealExtra(one, like, limit, reseal, tally, ask, tx);
      }
    }
    await resealDirectory(ids, reseal, limit, tally, tx);
    log.debug("Leaving resealSealed().");
    return tally;
  }

  /**
   * One extra sealed column re-sealed, compare and swap per row.
   *
   * @param one - the column (`EXTRA_SEALED`)
   * @param like - the LIKE pattern of the key
   * @param limit - the most rows
   * @param reseal - the re-sealer
   * @param tally - the pass's tally
   * @param ask - sends a statement on the pool
   * @param tx - runs a transaction
   * @returns a promise settled once done
   */
  async function resealExtra(one, like, limit, reseal, tally, ask, tx) {
    log.debug("Entering resealExtra(). " + one.table);
    const keyList = one.keys.map(function (k) {
      return '`' + k + '`';
    }).join(', ');
    const rows = dialect.rowsOf(await ask('reseal.extra', 'SELECT ' + keyList +
      ', ' + columnOf(one) + ' AS v FROM ' + one.table + ' WHERE ' +
      columnOf(one) + ' LIKE ? ESCAPE \'\\\\\' LIMIT ?', [like, limit]));
    for (const row of rows) {
      // A JSON column's TEXT, which is what is stored and compared: the
      // connection hands it back parsed.
      const text = one.jsonb ? JSON.stringify(jsonOf(row.v)) : String(row.v);
      const next = deps.resealText(text, reseal);
      if (!next) {
        tally.skipped += 1;
        continue;
      }
      await tx(async function (client) {
        const u = await send(client, 'reseal.extra.write', 'UPDATE ' +
          one.table + ' SET ' + columnOf(one) + ' = ? WHERE ' +
          one.keys.map(function (k) {
            return '`' + k + '` = ?';
          }).join(' AND ') + ' AND ' + columnOf(one) + ' = ?',
          [next].concat(one.keys.map(function (k) {
            return row[k];
          }), [text]));
        if (!dialect.affected(u)) {
          return null;
        }
        tally.other = (tally.other || 0) + 1;
        return one.change
          ? recordChanges(client, [Object.assign({}, one.change)])
          : null;
      });
    }
    log.debug("Leaving resealExtra().");
  }

  /**
   * The directory's entries under the retiring keys, found by their `dek`
   * key rows a realm and a page at a time, each re-sealed in a transaction:
   * compare and swap on the blob, the key rows and the data-key counts moved
   * with it, a change-log row.
   *
   * @param ids - the data keys
   * @param reseal - the re-sealer
   * @param limit - the most entries this pass
   * @param tally - the pass's tally
   * @param tx - runs a transaction
   * @returns a promise settled once done
   */
  async function resealDirectory(ids, reseal, limit, tally, tx) {
    log.debug("Entering resealDirectory().");
    const crypto = require('../common/crypto');
    const ask = function (name, text, values) {
      return maintenance('the re-encryption pass', function () {
        return send(pool, name, text, values).then(rowsOf);
      });
    };
    const keys = ids.map(mariadbQueries.tableKey);
    let budget = limit;
    try {
      const realms = await mariadbQueries.realmsOf(ask);
      for (const realm of realms) {
        let after = '';
        while (budget > 0) {
          const rows = await ask('reseal.entries', 'SELECT e.realm, ' +
            'e.dn_key, e.dn, e.attrs, e.attr_names, e.dek_keys FROM (SELECT ' +
            'DISTINCT dn_key FROM sts_ldap_entry_keys WHERE realm = ? AND ' +
            'kind = \'dek\' AND k IN (' + mariadbQueries.marks(keys.length) +
            ') AND dn_key > ? ORDER BY dn_key LIMIT ?) AS u JOIN ' +
            'sts_ldap_entries AS e ON e.realm = ? AND e.dn_key = u.dn_key ' +
            'ORDER BY e.dn_key', [realm].concat(keys,
              [after, Math.min(budget, PAGE), realm]));
          if (!rows.length) {
            break;
          }
          after = rows[rows.length - 1].dn_key;
          for (const row of rows) {
            await resealEntry(row, reseal, tally, tx, crypto);
            budget -= 1;
          }
        }
        if (budget <= 0) {
          break;
        }
      }
    } catch (e) {
      log.error(errorCodes.tag('STS-STORE-0073') + 'persistence: the ' +
                'directory could not be read to re-seal it: ' +
                ((e && e.message) || e));
      log.debug("Leaving resealDirectory(). Failed.");
      throw e;
    }
    log.debug("Leaving resealDirectory().");
  }

  /**
   * One entry re-sealed.
   *
   * @param row - the entry's row
   * @param reseal - the re-sealer
   * @param tally - the pass's tally
   * @param tx - runs a transaction
   * @param crypto - `common/crypto`
   * @returns a promise settled once done
   */
  async function resealEntry(row, reseal, tally, tx, crypto) {
    log.debug("Entering resealEntry().");
    const opened = deps.openedOfRow(row);
    if (opened === null) {
      tally.skipped += 1;
      log.debug("Leaving resealEntry(). Does not open.");
      return;
    }
    const inner = deps.resealText(opened, reseal) || opened;
    let attrs = null;
    try {
      const parsed = JSON.parse(inner);
      attrs = typeof row.attrs === 'string' &&
        crypto.isEncryptedWithKek(row.attrs) ? parsed.a : parsed;
    } catch (e) {
      log.debug("Caught in resealEntry(): " + ((e && e.message) || e));
      tally.skipped += 1;
      log.debug("Leaving resealEntry(). Does not parse.");
      return;
    }
    const sealed = entryCodec.sealAttributes(row.realm, row.dn_key,
                                             attrs || {});
    const dekKeys = entryCodec.dekKeys(attrs || {}, sealed);
    await tx(async function (client) {
      const t = freshTally();
      const u = await send(client, 'reseal.entry', 'UPDATE sts_ldap_entries ' +
        'SET attrs = ?, dek_keys = ? WHERE realm = ? AND dn_key = ? AND ' +
        'attrs = ?', [JSON.stringify(sealed), JSON.stringify(dekKeys),
                      row.realm, row.dn_key, JSON.stringify(row.attrs)]);
      if (!dialect.affected(u)) {
        return null;
      }
      // The row is locked by the UPDATE, so what it held is what was read.
      contribute(t, { realm: row.realm, key: row.dn_key, attrNames: [],
                      dekKeys: row.dek_keys }, -1);
      contribute(t, { realm: row.realm, key: row.dn_key, attrNames: [],
                      dekKeys: dekKeys }, 1);
      t.counts.clear();
      await send(client, 'reseal.entry.keys', 'DELETE FROM ' +
        'sts_ldap_entry_keys WHERE realm = ? AND dn_key = ? AND kind = ' +
        '\'dek\'', [row.realm, row.dn_key]);
      const ids = Object.keys(dekKeys || {});
      if (ids.length) {
        const values = [];
        ids.forEach(function (one) {
          values.push(row.realm, 'dek', mariadbQueries.tableKey(one),
                      row.dn_key);
        });
        await send(client, 'reseal.entry.keys', 'INSERT INTO ' +
          'sts_ldap_entry_keys (realm, kind, k, dn_key) VALUES ' +
          ids.map(function () {
            return '(?, ?, ?, ?)';
          }).join(', '), values);
      }
      await foldTally(client, t);
      tally.entries += 1;
      tally.changed.push({ realm: row.realm, key: row.dn });
      return recordChanges(client, [{ kind: 'directory', realm: row.realm,
                                      key: row.dn }]);
    });
    log.debug("Leaving resealEntry().");
  }

  log.debug("Leaving create().");
  return {
    loadRows: loadRows,
    readRow: readRow,
    query: query,
    flushBody: flushBody,
    mergeLostRow: mergeLostRow,
    directoryDekCounts: directoryDekCounts,
    countSealed: countSealed,
    countAllSealed: countAllSealed,
    resealSealed: resealSealed,
    // For the tests: what a row contributes, and the bases of a parent.
    basesOf: basesOf
  };
}

module.exports = {
  create: create,
  // The same factory under a name that does not read as a call of the
  // driver's own `create()` (`tests/no_periodic_timers.js`).
  forDriver: create,
  basesOf: basesOf,
  DN_KEY_LIMIT: DN_KEY_LIMIT,
  WRITE_COLUMNS: WRITE_COLUMNS
};
