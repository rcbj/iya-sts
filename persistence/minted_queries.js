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
//   minted.newest   the most recently written live rows of one store in one
//                   realm, newest first (2026-10-22, #820): what a console
//                   list of the newest of a store shows, asked on the
//                   driver's read pool and never through the bridge.
//   minted.count    how many live rows one store holds in one realm
//                   (2026-10-22, #820): a console total, on the read pool.
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

// NEWEST BY THE STORE'S `n:` INDEX KEYS (2026-10-22, #820): a backward scan
// of `sts_minted_index`'s primary key over the keys `n:` up to `n;` (the
// next character), joined to the rows. Ordering `sts_minted` by
// `written_at` was a sort of the whole store (13 s on 8081), and a btree
// there would make every update of that table non-HOT. A store that files
// no `n:` key answers nothing here; the token register files one per
// record (`admin_stats.js`).
const NEWEST = 'SELECT m.key, m.key_sealed, m.body FROM sts_minted_index i ' +
  'JOIN sts_minted m ON m.handle = i.handle AND m.realm = i.realm AND ' +
  'm.key = i.key WHERE i.handle = $1 AND i.realm = $2 AND ' +
  'i.index_key >= \'n:\' AND i.index_key < \'n;\' AND m.body <> $3 AND ' +
  '(m.expires_at IS NULL OR m.expires_at > $4) ORDER BY i.index_key DESC, ' +
  'i.key DESC LIMIT $5';

const COUNT = 'SELECT count(*)::bigint AS n FROM sts_minted WHERE ' +
  'handle = $1 AND realm = $2 AND body <> $3 AND (expires_at IS NULL OR ' +
  'expires_at > $4)';

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
 *   `minted.newest` or `minted.count`
 * @param {unknown[]} args - `[handle, realm, key]`,
 *   `[handle, realm, indexKey]`, `[handle, realm, now, limit]` or
 *   `[handle, realm, now]`
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

module.exports = {
  build: build,
  answerOf: answerOf,
  TOMBSTONE: TOMBSTONE,
  BY_INDEX_LIMIT: BY_INDEX_LIMIT,
  PAGE_LIMIT: PAGE_LIMIT,
  NEWEST_LIMIT: NEWEST_LIMIT
};
