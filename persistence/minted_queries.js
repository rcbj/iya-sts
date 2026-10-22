// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';

//
// File: persistence/minted_queries.js
//
// ===========================================================================
// THE QUESTIONS AN ON-DEMAND MINTED STORE ASKS (#820, 2026-10-21).
//
// A store declared `onDemand` (`common/realms.js`) is not read back whole at
// a start: it holds a bounded set of rows, and a row it does not hold is read
// by key from `sts_minted` when somebody asks for it, through the synchronous
// bridge (`common/sync_query.ts`) — the session window's arrangement
// (`authn/session_window.ts`, `session_queries.js`) for every such store.
// The bridge's thread loads this module by path and answers in the shape
// `answerOf()` gives.
//
//   minted.read     one row by (handle, realm, key) — the key column is the
//                   keyed digest `persistence_minted.js` files a row under;
//   minted.page     a page of one store's live rows in one realm, in key
//                   column order after a cursor (part 2): what a walk of
//                   the whole store reads, a page at a time (`scan()`);
//   minted.byIndex  the rows filed under one index key of an `indexBy`
//                   store (`sts_minted_index`, schema version 24): what a
//                   walk of the whole store used to find, such as every
//                   refresh token of one family.
//   minted.newest   the live rows of one store in one realm with the
//                   highest sort value first (2026-10-22, #820): what a
//                   console list of the newest of a store shows, asked on
//                   the driver's read pool and never through the bridge.
//                   Only a store declaring `sortBy` has a sort value.
//   minted.count    how many live rows one store holds in one realm
//                   (2026-10-22, #820): a console total, on the read pool.
//   minted.estimate the PLANNER's estimate of how many rows one store holds
//                   in one realm (2026-10-22, #820): the console total of a
//                   large store, where the exact count is a scan of it.
//
// A tombstone is an absence to every reader. Nothing here opens a body: the
// rows come back sealed, and the process that asked opens them.
// ===========================================================================

const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'minted_queries',
  level: process.env.STS_LOG_LEVEL || 'info' });

const TOMBSTONE = '$tombstone$1';

const READ = 'SELECT body FROM sts_minted WHERE handle = $1 AND realm = $2 ' +
  'AND key = $3';

const BY_INDEX = 'SELECT m.key, m.key_sealed, m.body FROM sts_minted_index i ' +
  'JOIN sts_minted m ON m.handle = i.handle AND m.realm = i.realm AND ' +
  'm.key = i.key WHERE i.handle = $1 AND i.realm = $2 AND i.index_key = $3 ' +
  'AND m.body <> $4 ORDER BY m.key LIMIT $5';

const PAGE = 'SELECT key, key_sealed, body FROM sts_minted WHERE handle = $1 ' +
  'AND realm = $2 AND key > $3 AND body <> $4 AND (expires_at IS NULL OR ' +
  'expires_at > $5) ORDER BY key LIMIT $6';

// THE NEWEST ROWS, BY AN INDEX (2026-10-22, #820). It was `ORDER BY
// written_at DESC` over `sts_minted`, which has only a BRIN on `written_at`
// (#630: a btree, even a partial one, makes every update of the busiest
// table non-HOT, since `written_at` changes on every write), so every page
// view sorted the store's whole partition: 13-14 s for 1.7M token rows on
// 8081. A store declaring `sortBy` writes one more `sts_minted_index` row
// per row, `index_key` SORT_INDEX_KEY and `sort_at` its value — that table
// is insert and delete only, so its index costs no HOT update — and this
// walks `sts_minted_index_sort` newest first. The predicate `sort_at IS NOT
// NULL` is the partial index's own, written out so a plan made without the
// parameters' values can still use it. A sort row whose body is gone
// (expiry-purged) or a tombstone finds no row and is passed over.
//
// THE BODY IS A LATERAL SUBQUERY WITH LIMIT 1, NOT A JOIN, AND THAT IS THE
// FIX FOR THE GENERIC PLAN (2026-10-22, #820). Measured on a copy of 8081's
// index with 2.37M sort rows: the plain JOIN's custom plan walked the index
// (7.9 ms), but its GENERIC plan — what a prepared statement settles on
// after five executions — estimated the handle's rows from the column's
// average and chose a bitmap scan of the whole store, a hash join and a sort:
// 52 s. The LIMIT inside the LATERAL keeps the planner from pulling the
// subquery up into a join, so every plan is the ordered index walk on the
// outside and one primary-key probe per row: 16 ms of execution for 500 rows
// in the generic plan, 7.6 ms custom.
const NEWEST = 'SELECT m.key, m.key_sealed, m.body FROM sts_minted_index i ' +
  'CROSS JOIN LATERAL (SELECT x.key, x.key_sealed, x.body FROM sts_minted x ' +
  'WHERE x.handle = i.handle AND x.realm = i.realm AND x.key = i.key AND ' +
  'x.body <> $3 AND (x.expires_at IS NULL OR x.expires_at > $4) LIMIT 1) m ' +
  'WHERE i.handle = $1 AND i.realm = $2 AND i.sort_at IS NOT NULL ' +
  'ORDER BY i.sort_at DESC, i.key DESC LIMIT $5';

// The `index_key` of a row's sort row. `$` is not in base64url, so no
// `indexBy` digest is this, and it is not the completion mark
// (`$index-complete$`), which sits under realm ''.
const SORT_INDEX_KEY = '$sort$';

const COUNT = 'SELECT count(*)::bigint AS n FROM sts_minted WHERE ' +
  'handle = $1 AND realm = $2 AND body <> $3 AND (expires_at IS NULL OR ' +
  'expires_at > $4)';

// THE ESTIMATE IS THE PLANNER'S, READ OUT OF `EXPLAIN` (2026-10-22, #820).
// `minted.count` is exact and is a scan of the store's whole partition —
// measured on 8081 with 2.43M token rows, 5.7-8.6 s per Monitoring -> Tokens
// view; an index-only count of (handle, realm) is still linear (427 ms) and
// grows with the store. `EXPLAIN` runs nothing: it asks the planner how many
// rows the predicate matches, from the column statistics ANALYZE (and
// autovacuum) keep — 0.5 ms warm, and 2,363,753 against 2,429,984 there,
// within 3 %. It is a statistic, so it can be stale (a store that has just
// grown or been purged) and is no count at all for a small store: the
// realm with no tokens was estimated at 3,527. The caller therefore asks
// the exact count below a threshold (`persistence_minted.js`) and labels
// what it shows as an estimate above it. Only the two equality columns are
// in the predicate — the planner's guess at `body <> tombstone` and the
// expiry adds error, not precision.
const ESTIMATE = 'EXPLAIN (FORMAT JSON) SELECT 1 FROM sts_minted WHERE ' +
  'handle = $1 AND realm = $2';

// The most rows one page answers.
const PAGE_LIMIT = 500;

// The most rows `minted.newest` answers: a console list, not a walk.
const NEWEST_LIMIT = 1000;

// The most rows one index key answers. An index key is a family, a person:
// a few rows, and a bound keeps a key that collects thousands from holding
// the bridge.
const BY_INDEX_LIMIT = 10000;

/**
 * Builds one named statement.
 *
 * @param {string} name - `minted.read`, `minted.page`, `minted.byIndex`,
 *   `minted.newest`, `minted.count` or `minted.estimate`
 * @param {unknown[]} args - `[handle, realm, key]`,
 *   `[handle, realm, indexKey]`, `[handle, realm, now, limit]`,
 *   `[handle, realm, now]` or `[handle, realm]`
 * @returns {{ text: string, values: unknown[] }}
 */
function build(name, args) {
  log.debug("Entering build().");
  const a = Array.isArray(args) ? args : [];
  if (name === 'minted.read') {
    log.debug("Leaving build().");
    return { text: READ, values: [String(a[0]), String(a[1]), String(a[2])] };
  }
  if (name === 'minted.page') {
    log.debug("Leaving build().");
    return { text: PAGE, values: [String(a[0]), String(a[1]), String(a[2]),
                                  TOMBSTONE, Number(a[3]) || Date.now(),
                                  PAGE_LIMIT] };
  }
  if (name === 'minted.newest') {
    log.debug("Leaving build().");
    return { text: NEWEST, values: [String(a[0]), String(a[1]), TOMBSTONE,
                                    Number(a[2]) || Date.now(),
                                    Math.max(1, Math.min(NEWEST_LIMIT,
                                      Math.floor(Number(a[3]) || 1)))] };
  }
  if (name === 'minted.count') {
    log.debug("Leaving build().");
    return { text: COUNT, values: [String(a[0]), String(a[1]), TOMBSTONE,
                                   Number(a[2]) || Date.now()] };
  }
  if (name === 'minted.estimate') {
    log.debug("Leaving build().");
    return { text: ESTIMATE, values: [String(a[0]), String(a[1])] };
  }
  if (name === 'minted.byIndex') {
    log.debug("Leaving build().");
    return { text: BY_INDEX, values: [String(a[0]), String(a[1]),
                                      String(a[2]), TOMBSTONE,
                                      BY_INDEX_LIMIT] };
  }
  log.debug("Leaving build().");
  throw new Error('minted_queries: unknown query "' + name + '"');
}

/**
 * Turns driver rows into the answer the window takes.
 *
 * @param {string} name - the query
 * @param {any[]} rows - the driver's rows
 * @returns {unknown} `{ body }` or null for a read; `[{ key, keySealed,
 *   body }]` for an index lookup
 */
function answerOf(name, rows) {
  log.debug("Entering answerOf().");
  const list = rows || [];
  if (name === 'minted.read') {
    const row = list[0];
    log.debug("Leaving answerOf().");
    return !row || row.body === TOMBSTONE ? null : { body: String(row.body) };
  }
  if (name === 'minted.count') {
    log.debug("Leaving answerOf().");
    return list.length ? Number(list[0].n) || 0 : 0;
  }
  if (name === 'minted.estimate') {
    log.debug("Leaving answerOf().");
    return estimateOf(list[0]);
  }
  if (name === 'minted.byIndex' || name === 'minted.page' ||
      name === 'minted.newest') {
    log.debug("Leaving answerOf().");
    return list.map(function (row) {
      return { key: String(row.key),
               keySealed: row.key_sealed ? String(row.key_sealed) : '',
               body: String(row.body) };
    });
  }
  log.debug("Leaving answerOf().");
  throw new Error('minted_queries: unknown query "' + name + '"');
}

/**
 * The planner's row estimate out of an `EXPLAIN (FORMAT JSON)` row. The
 * driver hands the plan back parsed (a `json` column) or as text, depending
 * on the driver and its type parsers, so both are read.
 *
 * @param {any} row - the one row `EXPLAIN` answers
 * @returns {number | null} the estimate, or null where none can be read
 */
function estimateOf(row) {
  log.debug("Entering estimateOf().");
  let plan = row ? row['QUERY PLAN'] : null;
  if (typeof plan === 'string') {
    try {
      plan = JSON.parse(plan);
    } catch (e) {
      log.debug("Caught in estimateOf(): " + ((e && e.message) || e));
      log.debug("Leaving estimateOf().");
      return null;
    }
  }
  const top = Array.isArray(plan) ? plan[0] : plan;
  const n = top && top.Plan ? Number(top.Plan['Plan Rows']) : NaN;
  log.debug("Leaving estimateOf().");
  return Number.isFinite(n) && n >= 0 ? Math.round(n) : null;
}

module.exports = {
  build: build,
  answerOf: answerOf,
  TOMBSTONE: TOMBSTONE,
  BY_INDEX_LIMIT: BY_INDEX_LIMIT,
  PAGE_LIMIT: PAGE_LIMIT,
  NEWEST_LIMIT: NEWEST_LIMIT,
  SORT_INDEX_KEY: SORT_INDEX_KEY
};
