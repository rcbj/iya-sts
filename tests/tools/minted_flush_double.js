// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/tools/minted_flush_double.js
//
// ===========================================================================
// THE MINTED FLUSH, PLAYED AGAINST MAPS (2026-10-22, #820).
//
// Since #820 a minted flush is ONE statement, `MINTED_FLUSH` in
// `persistence/persistence_postgres.js`: data-modifying CTEs over unnest()ed
// arrays, sent as a named query (`{ name, text, values }`). A test's `pg`
// double cannot read SQL, and it does not have to: every parameter is named
// in `MINTED_FLUSH_LAYOUT`, so `play()` does what the statement does from
// the named arrays — the fence, the lock, the compare-and-set, the guarded
// upsert, the deletes, the session index, the minted index and the change
// log — against a state of Maps, and answers the one row the database does.
//
// What it does NOT play is the database's concurrency: there are no locks
// here, only their effects. The lock order and the deadlock behaviour were
// measured against a real postgres (#820's PR); `tests/
// minted_flush_one_statement.js` holds the statement's shape.
// ===========================================================================

const log = require('bunyan').createLogger({ name: 'minted_flush_double',
  level: process.env.LOG_LEVEL || 'info' });

const postgres = require('../../persistence/persistence_postgres');

const TOMBSTONE = '$tombstone$1';

/**
 * Whether a query handed to a double is the minted flush.
 *
 * @param sql - what the driver passed as the statement: text or a config
 * @returns true for MINTED_FLUSH
 */
function isFlush(sql) {
  log.debug("Entering isFlush().");
  const text = sql && typeof sql === 'object' ? sql.text : sql;
  log.debug("Leaving isFlush().");
  return String(text || '').indexOf('/* sts:minted-flush */') === 0;
}

/**
 * The flush's parameters by name.
 *
 * @param sql - the query config, or the text
 * @param [params] - the values, when `sql` is text
 * @returns `{ name: value }` over MINTED_FLUSH_LAYOUT
 */
function named(sql, params) {
  log.debug("Entering named().");
  const values = sql && typeof sql === 'object' && sql.values
    ? sql.values : (params || []);
  const out = {};
  postgres.MINTED_FLUSH_LAYOUT.forEach(function (one, i) {
    out[one[0]] = values[i];
  });
  log.debug("Leaving named().");
  return out;
}

/**
 * A fresh state for `play()`.
 *
 * @returns `{ minted, sessions, index, changes }`
 */
function state() {
  log.debug("Entering state().");
  log.debug("Leaving state().");
  return { minted: new Map(), sessions: new Map(), index: new Set(),
           changes: [] };
}

// A minted row's identity, as the driver's own.
function id(h, r, k) {
  log.debug("Entering id().");
  log.debug("Leaving id().");
  return String(h) + '\n' + String(r) + '\n' + String(k);
}

/**
 * Plays one MINTED_FLUSH against `db`, as the database does.
 *
 * @param db - from `state()`: `minted` (id to `{ handle, realm, key, body,
 *   expiresAt, keySealed }`), `sessions` (realm\nkey to the index row's
 *   values), `index` (Set of handle\nrealm\nindexKey\nkey), `changes`
 * @param sql - the query config
 * @param [params] - the values, when `sql` is text
 * @param [opts] - `fenceOk` (default true): what the fence answers
 * @returns a `pg` result with the statement's one row
 */
function play(db, sql, params, opts) {
  log.debug("Entering play().");
  const p = named(sql, params);
  const o = opts || {};
  const fenceOk = o.fenceOk !== false;
  // The lock and the compare-and-set: each expected body against the row.
  const lockedIds = new Set();
  if (fenceOk) {
    (p.lock_h || []).forEach(function (h, i) {
      lockedIds.add(id(h, p.lock_r[i], p.lock_k[i]));
    });
  }
  let bad = 0;
  const current = [];
  (p.cas_h || []).forEach(function (h, i) {
    const k = id(h, p.cas_r[i], p.cas_k[i]);
    const held = lockedIds.has(k) ? db.minted.get(k) : undefined;
    const body = held ? held.body : null;
    const want = p.cas_body[i] === undefined ? null : p.cas_body[i];
    if (body !== want) {
      bad++;
    }
    current.push([h, p.cas_r[i], p.cas_k[i], body]);
  });
  const go = fenceOk && bad === 0;
  const written = new Set();
  const unwritten = [];
  let changes = 0;
  if (go) {
    const plain = new Set((p.plain_h || []).map(function (h, i) {
      return id(h, p.plain_r[i], p.plain_k[i]);
    }));
    (p.up_h || []).forEach(function (h, i) {
      const k = id(h, p.up_r[i], p.up_k[i]);
      const had = db.minted.get(k);
      const body = p.up_body[i];
      if (had && had.body === p.tombstone && body !== p.tombstone &&
          !plain.has(k)) {
        unwritten.push([h, p.up_r[i], p.up_k[i]]);
        return;
      }
      db.minted.set(k, { handle: h, realm: p.up_r[i], key: p.up_k[i],
                         body: body, expiresAt: p.up_expires[i],
                         keySealed: p.up_sealed[i] });
      written.add(k);
    });
    (p.del_h || []).forEach(function (h, i) {
      db.minted.delete(id(h, p.del_r[i], p.del_k[i]));
    });
    (p.ses_realm || []).forEach(function (r, i) {
      if (!written.has(id('authn.sessions', r, p.ses_key[i]))) {
        return;
      }
      db.sessions.set(r + '\n' + p.ses_key[i], {
        realm: r, key: p.ses_key[i], expiresAt: p.ses_expires[i],
        lastSeenAt: p.ses_last_seen[i], startedAt: p.ses_started[i],
        subjectKey: p.ses_subject[i], usernameKey: p.ses_username[i],
        chosen: p.ses_chosen[i], authenticated: p.ses_authenticated[i],
        kind: p.ses_kind[i], rpSurface: p.ses_rp_surface[i],
        parentKey: p.ses_parent[i], backsConsole: p.ses_backs_console[i],
        credentialKey: p.ses_credential[i],
        partnerRelationship: p.ses_partner[i] });
    });
    (p.sesdel_realm || []).forEach(function (r, i) {
      db.sessions.delete(r + '\n' + p.sesdel_key[i]);
    });
    const filed = new Set((p.ixnew_h || []).map(function (h, i) {
      return [h, p.ixnew_r[i], p.ixnew_i[i], p.ixnew_k[i]].join('\n');
    }));
    const clear = new Set();
    (p.ixup_h || []).forEach(function (h, i) {
      const k = id(h, p.ixup_r[i], p.ixup_k[i]);
      if (written.has(k)) {
        clear.add(k);
      }
    });
    (p.ixgone_h || []).forEach(function (h, i) {
      clear.add(id(h, p.ixgone_r[i], p.ixgone_k[i]));
    });
    Array.from(db.index).forEach(function (row) {
      const parts = row.split('\n');
      if (clear.has(id(parts[0], parts[1], parts[3])) && !filed.has(row)) {
        db.index.delete(row);
      }
    });
    (p.ixnew_h || []).forEach(function (h, i) {
      if (written.has(id(h, p.ixnew_r[i], p.ixnew_k[i]))) {
        db.index.add([h, p.ixnew_r[i], p.ixnew_i[i], p.ixnew_k[i]]
          .join('\n'));
      }
    });
    (p.chg_kind || []).forEach(function (kind, i) {
      if (p.chg_h[i] !== null && p.chg_h[i] !== undefined &&
          !written.has(id(p.chg_h[i], p.chg_r[i], p.chg_k[i]))) {
        return;
      }
      db.changes.push({ origin: p.origin, kind: kind,
                        realm: p.chg_realm[i], key: p.chg_key[i] });
      changes++;
    });
  } else {
    (p.up_h || []).forEach(function (h, i) {
      unwritten.push([h, p.up_r[i], p.up_k[i]]);
    });
  }
  log.debug("Leaving play().");
  return { rows: [{ fence_ok: fenceOk, cas_bad: String(bad), go: go,
                    changes: String(changes), side: '0',
                    unwritten: unwritten.length ? unwritten : null,
                    current: bad > 0 ? current : null }],
           rowCount: 1 };
}

module.exports = { isFlush: isFlush, named: named, state: state,
                   play: play, TOMBSTONE: TOMBSTONE };
