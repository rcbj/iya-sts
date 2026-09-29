// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: session_cap.js
//
// ===========================================================================
// A REALM HOLDS AT MOST `authn.maxSessions` SIGN-ON SESSIONS (#345,
// 2026-09-29).
//
// Only the `authn.session-expiry` job bounded the store, so a burst of
// sign-ins grew every process until it caught up. The cap is checked where a
// session is CREATED, and at it the least recently used session is ENDED —
// through `expireSession()`, the one end an expiry takes — not dropped:
//
//   A. at the cap, a new session ends the least recently used one, which is
//      gone from the store, has a `session.end` audit row carrying
//      STS-AUTHN-0292, and a CAEP notice initiated by `policy`;
//   B. the others, and the new one, are untouched, and a write back to a
//      session that already exists is not an insert and ends nothing;
//   C. a cap lowered below the store's size is met at the next insert.
//
// WHY IN PROCESS: the choice of victim is decided by `lastSeenAt`, which is
// set here directly as `session_clocks.js` does, and the observer is read
// without a transmitter. It runs in a realm of its own, so the sessions
// other files leave in the default realm cannot be the victim.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const realms = require('../common/realms');
const audit = require('../common/audit');
const authn = require('../authn/authn');

const log = require('bunyan').createLogger({ name: 'session_cap',
  level: process.env.LOG_LEVEL || 'info' });

function signIn(username) {
  log.debug("Entering signIn().");
  log.debug("Leaving signIn().");
  return authn.startSession({ set: function () {}, req: null },
                            username, ['pwd'], '1', 'Test');
}

// Makes a session look last used at `atMs`, through the store as a real
// write is.
function lastUsedAt(session, atMs) {
  log.debug("Entering lastUsedAt().");
  const held = authn.sessions.get(session.id);
  held.lastSeenAt = atMs;
  authn.sessions.set(session.id, held);
  log.debug("Leaving lastUsedAt().");
}

function endRowFor(id) {
  log.debug("Entering endRowFor().");
  const rows = audit.list().filter(function (row) {
    return row.action === 'session.end' && row.target === id;
  });
  log.debug("Leaving endRowFor().");
  return rows[0] || null;
}

function withSetting(key, value, fn) {
  log.debug("Entering withSetting().");
  config.setOverride(key, String(value));
  try {
    log.debug("Leaving withSetting().");
    return fn();
  } finally {
    config.clearOverride(key);
  }
}

function sections(t) {
  log.debug("Entering sections().");
  const told = [];
  authn.setSessionObserver(function (notice) {
    told.push(notice);
    return null;
  });
  const a = signIn('cap-alice');
  const b = signIn('cap-bob');
  const c = signIn('cap-carol');
  t.equal(authn.sessions.size, 3, 'a new realm holds the three sessions');
  lastUsedAt(a, Date.now() - 60000);
  lastUsedAt(b, Date.now() - 120000);
  lastUsedAt(c, Date.now() - 30000);

  // -------------------------------------------------------------------------
  t.log.info('A. at the cap the least recently used session is ended');
  // -------------------------------------------------------------------------
  withSetting('authn.maxSessions', 3, function () {
    told.length = 0;
    const d = signIn('cap-dave');
    t.check(!!d && !!authn.sessions.get(d.id),
            'the fourth session is created');
    t.equal(authn.sessions.size, 3, 'and the store stays at the cap');
    t.check(!authn.sessions.get(b.id),
            'the session ended is Bob\'s, the least recently used — not ' +
            'Alice\'s, which is the oldest by creation');
    t.check(!!authn.sessions.get(a.id) && !!authn.sessions.get(c.id),
            'and the other two are untouched');
    const row = endRowFor(b.id);
    t.check(!!row && row.errorCode === 'STS-AUTHN-0292',
            'its end is a session.end audit row carrying STS-AUTHN-0292',
            row ? JSON.stringify({ errorCode: row.errorCode,
                                   summary: row.summary }) : '(no row)');
    const notice = told.filter(function (n) {
      return n && n.session && n.session.id === b.id;
    })[0] || null;
    t.check(!!notice && notice.initiatingEntity === 'policy' &&
            notice.expired === true,
            'and CAEP is told it was revoked, initiated by policy — the ' +
            'same end an expiry takes',
            notice ? JSON.stringify({ kind: notice.kind,
                                      entity: notice.initiatingEntity })
                   : '(no notice)');

    // -----------------------------------------------------------------------
    t.log.info('B. a write back to an existing session is not an insert');
    // -----------------------------------------------------------------------
    const held = authn.sessions.get(a.id);
    t.check(authn.noteSessionChanged(held) === true &&
            authn.sessions.size === 3 && !!authn.sessions.get(c.id) &&
            !!authn.sessions.get(d.id),
            'at the cap, re-setting a live session ends nothing');
  });

  // -------------------------------------------------------------------------
  t.log.info('C. a lowered cap is met at the next insert');
  // -------------------------------------------------------------------------
  withSetting('authn.maxSessions', 1, function () {
    const e = signIn('cap-erin');
    t.equal(authn.sessions.size, 1,
            'a cap lowered to one holds one after the next sign-in');
    t.check(!!authn.sessions.get(e.id),
            'and it is the session just created');
  });
  authn.setSessionObserver(function () {
    return null;
  });
  log.debug("Leaving sections().");
}

function run(t) {
  log.debug("Entering run().");
  const made = realms.create({ id: 'session-cap', name: 'session-cap',
                               description: 'Created by ' + __filename });
  if (!made.ok) {
    t.bad('could not create the realm "session-cap"',
          (made.errors || []).join(' '));
    log.debug("Leaving run().");
    return;
  }
  try {
    realms.run(made.realm, function () {
      sections(t);
    });
  } finally {
    realms.remove('session-cap');
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'session_cap',
  describe: 'authn.maxSessions: at the cap a new session ends the least ' +
            'recently used one through the expiry path (audit row with ' +
            'STS-AUTHN-0292, CAEP policy), a re-set is not an insert, and a ' +
            'lowered cap is met at once',
  run: run
};
