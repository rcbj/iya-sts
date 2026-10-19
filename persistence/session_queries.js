// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: persistence/session_queries.js
//
// Named reads of one sealed session and of sts_sessions (#350). The bridge
// thread builds them; the window consumes answerOf(), never a raw row. The
// session id is not a column: sts_minted.key and sts_sessions.key are the
// keyed digest.

const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'sts-session-queries' });

const TOMBSTONE = '$tombstone$1';

const READ = 'SELECT handle, realm, key, body, (extract(epoch from ' +
  'written_at) * 1000)::bigint AS written_ms FROM sts_minted WHERE ' +
  'handle = $1 AND realm = $2 AND key = $3';

const COUNT = 'SELECT count(*)::bigint AS n FROM sts_sessions WHERE ' +
  'realm = $1';

const EXISTS = 'SELECT 1 AS hit FROM sts_sessions WHERE realm = $1 AND ' +
  'key = $2 LIMIT 1';

const OLDEST = 'SELECT key, last_seen_at, started_at FROM sts_sessions ' +
  'WHERE realm = $1 AND subject_key = $2 AND chosen ORDER BY ' +
  'last_seen_at, started_at';

const EXPIRED = 'SELECT key FROM sts_sessions WHERE realm = $1 AND (' +
  '(expires_at IS NOT NULL AND expires_at <= $2) OR ' +
  '(chosen AND $3 > 0 AND last_seen_at < $3))';

const SUBJECT_ROWS = 'SELECT key, subject_key, last_seen_at, started_at ' +
  'FROM sts_sessions WHERE realm = $1 AND chosen AND subject_key <> \'\' ' +
  'AND (subject_key, key) > ($2, $3) ORDER BY subject_key, key LIMIT 500';

const CHILDREN = 'SELECT key FROM sts_sessions WHERE realm = $1 AND ' +
  'parent_key = $2';

const CREDENTIAL = 'SELECT key FROM sts_sessions WHERE realm = $1 AND ' +
  'credential_key = $2 LIMIT 5';

const USERNAME = 'SELECT key FROM sts_sessions WHERE realm = $1 AND ' +
  'username_key = $2';

const PAGE = 'SELECT key FROM sts_sessions WHERE realm = $1 AND key > $2 ' +
  'ORDER BY key LIMIT $3';

const SURFACE = 'SELECT key FROM sts_sessions WHERE realm = $1 AND ' +
  'rp_surface = $2';

const PARTNER = 'SELECT key FROM sts_sessions WHERE realm = $1 AND ' +
  'partner_relationship = $2';

/**
 * Builds one named statement.
 *
 * @param {string} name
 * @param {unknown[]} args
 * @returns {{ text: string, values: unknown[] }}
 */
function build(name, args) {
  log.debug("Entering build().");
  const a = Array.isArray(args) ? args : [];
  let text = '';
  let values = [];
  if (name === 'session.read') {
    text = READ;
    values = ['authn.sessions', a[0], a[1]];
  } else if (name === 'session.count') {
    text = COUNT;
    values = [a[0]];
  } else if (name === 'session.exists') {
    text = EXISTS;
    values = [a[0], a[1]];
  } else if (name === 'session.oldest') {
    text = OLDEST;
    values = [a[0], a[1]];
  } else if (name === 'session.expired') {
    text = EXPIRED;
    values = [a[0], a[1], a[2]];
  } else if (name === 'session.subjectRows') {
    text = SUBJECT_ROWS;
    values = [a[0], a[1], a[2]];
  } else if (name === 'session.children') {
    text = CHILDREN;
    values = [a[0], a[1]];
  } else if (name === 'session.credential') {
    text = CREDENTIAL;
    values = [a[0], a[1]];
  } else if (name === 'session.username') {
    text = USERNAME;
    values = [a[0], a[1]];
  } else if (name === 'session.page') {
    text = PAGE;
    values = [a[0], a[1], a[2]];
  } else if (name === 'session.surface') {
    text = SURFACE;
    values = [a[0], a[1]];
  } else if (name === 'session.partner') {
    text = PARTNER;
    values = [a[0], a[1]];
  } else {
    log.debug("Leaving build().");
    throw new Error('session_queries: unknown query "' + name + '"');
  }
  log.debug("Leaving build().");
  return { text: text, values: values };
}

/**
 * Turns driver rows into the object the window holds.
 *
 * A tombstone body and a missing row are both null: absence, not a body.
 *
 * @param {string} name
 * @param {any[]} rows
 * @returns {unknown}
 */
function answerOf(name, rows) {
  log.debug("Entering answerOf().");
  const list = rows || [];
  if (name === 'session.read') {
    const row = list[0];
    if (!row || row.body === TOMBSTONE) {
      log.debug("Leaving answerOf(). Absent.");
      return null;
    }
    log.debug("Leaving answerOf().");
    return { body: row.body, writtenAt: Number(row.written_ms || 0) };
  }
  if (name === 'session.count') {
    const row = list[0] || {};
    log.debug("Leaving answerOf().");
    return { n: Number(row.n || 0) };
  }
  if (name === 'session.exists') {
    log.debug("Leaving answerOf().");
    return { hit: list.length > 0 };
  }
  if (name === 'session.oldest') {
    const out = list.map(function (row) {
      return {
        key: String(row.key),
        lastSeenAt: Number(row.last_seen_at || 0),
        startedAt: Number(row.started_at || 0)
      };
    });
    log.debug("Leaving answerOf().");
    return out;
  }
  if (name === 'session.subjectRows') {
    const out = list.map(function (row) {
      return {
        key: String(row.key),
        subjectKey: String(row.subject_key || ''),
        lastSeenAt: Number(row.last_seen_at || 0),
        startedAt: Number(row.started_at || 0)
      };
    });
    log.debug("Leaving answerOf().");
    return out;
  }
  if (name === 'session.expired' || name === 'session.children' ||
      name === 'session.credential' || name === 'session.username' ||
      name === 'session.page' || name === 'session.surface' ||
      name === 'session.partner') {
    const out = [];
    list.forEach(function (row) {
      if (row && row.key != null) {
        out.push(String(row.key));
      }
    });
    log.debug("Leaving answerOf().");
    return out;
  }
  log.debug("Leaving answerOf().");
  throw new Error('session_queries: unknown query "' + name + '"');
}

module.exports = {
  build: build,
  answerOf: answerOf
};
