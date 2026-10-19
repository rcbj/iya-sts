// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: session_cap.js
//
// ===========================================================================
// A REALM HOLDS AT MOST `authn.maxSessions` SESSIONS (#345, #350).
//
// Checked where a session is created. At the realm cap a new row is refused.
// A subject already at `authn.maxSessionsPerSubject` loses their own oldest
// countable row, one per insert. Each realm's sweep ends at most that
// realm's `authn.sessionShedPerSweep`. An arrival is not countable, and the
// client address is not an admission key. A refused sign-in leaves the
// browser's current session.
//
//   A. a new chosen session at a full cap of other subjects is refused;
//   B. a re-set of a live session is not an insert;
//   C. a lowered cap does not mass-end; one own row, then the sweep's budget;
//   D. an arrival flood ends nobody, and a full realm refuses the new one;
//   E. two browsers at one address both receive a cookie while there is room;
//   F. Bob's insert past his own cap ends Bob's oldest, not Alice;
//   G. a full realm does not grow for an /admin crawl or a console insert;
//   H. a relying-party row is stored with chosen: true;
//   I. upgrading an arrival ends one other own row, not another subject;
//   J. a portal insert does not end the sign-on it was derived from;
//   K. two copies merge with backsConsole the OR;
//   L. a refused sign-in leaves the browser's session; an exact-cap switch
//      still replaces it;
//   M. two realms do not share one shed budget.
//
// WHY IN PROCESS: the victim is chosen from lastSeenAt, set here directly,
// and the observer is read without a transmitter. Its own realm, so sessions
// other files leave in the default realm are not this realm's victims.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const realms = require('../common/realms');
const audit = require('../common/audit');
const scheduler = require('../cluster/scheduler');
const authn = require('../authn/authn');

const log = require('bunyan').createLogger({ name: 'session_cap',
  level: process.env.LOG_LEVEL || 'info' });

function signIn(username, extra) {
  log.debug("Entering signIn().");
  const session = authn.startSession({ set: function () {}, req: null },
                                     username, ['pwd'], '1', 'Test', extra);
  log.debug("Leaving signIn().");
  return session;
}

function fakeRes() {
  log.debug("Entering fakeRes().");
  const headers = [];
  log.debug("Leaving fakeRes().");
  return {
    headers: headers,
    set: function (name, value) {
      log.debug("Entering set().");
      headers.push(value);
      log.debug("Leaving set().");
    },
    req: null
  };
}

function cookieFrom(res, name) {
  log.debug("Entering cookieFrom().");
  let found = '';
  res.headers.forEach(function (line) {
    const pair = String(line).split(';')[0];
    const i = pair.indexOf('=');
    if (i > 0 && pair.slice(0, i).trim() === name) {
      found = pair.slice(i + 1).trim();
    }
  });
  log.debug("Leaving cookieFrom().");
  return found;
}

function reqWith(name, value) {
  log.debug("Entering reqWith().");
  log.debug("Leaving reqWith().");
  return { headers: { cookie: name + '=' + value }, query: {} };
}

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

function refuseFor(username) {
  log.debug("Entering refuseFor().");
  const rows = audit.list().filter(function (row) {
    return row.action === 'session.refuse' &&
           row.errorCode === 'STS-AUTHN-0337' &&
           row.actor === username;
  });
  log.debug("Leaving refuseFor().");
  return rows;
}

function withSetting(key, value, fn) {
  log.debug("Entering withSetting().");
  config.setOverride(key, String(value));
  try {
    const out = fn();
    log.debug("Leaving withSetting().");
    return out;
  } finally {
    config.clearOverride(key);
  }
}

function clearSessions() {
  log.debug("Entering clearSessions().");
  const ids = [];
  authn.sessions.forEach(function (session, id) {
    ids.push(id);
  });
  ids.forEach(function (id) {
    authn.sessions.delete(id);
  });
  log.debug("Leaving clearSessions().");
}

function plant(id, subjectId, seen, chosen) {
  log.debug("Entering plant().");
  authn.sessions.set(id, {
    id: id,
    user: { username: subjectId || 'anonymous', sub: '' },
    subjectId: subjectId,
    chosen: chosen,
    lastSeenAt: seen,
    startedAt: seen,
    expires: Date.now() + 3600000,
    authenticated: chosen === true,
    authTime: 1,
    amr: [],
    acr: '0',
    via: 'Test'
  });
  log.debug("Leaving plant().");
}

function runSweep() {
  log.debug("Entering runSweep().");
  const job = scheduler.job('authn.session-expiry');
  const result = job.run({
    realm: 'session-cap', runId: 'cap-shed', trigger: 'manual',
    params: null,
    stillOwner: function () {
      return true;
    },
    nowMs: function () {
      return Date.now();
    },
    log: log
  });
  log.debug("Leaving runSweep().");
  return result;
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
  t.check(!!a.subjectId, 'a chosen session freezes a subjectId');
  t.check(a.subjectId && a.subjectId !== b.subjectId,
          'two people do not share a subjectId',
          JSON.stringify({ alice: a.subjectId, bob: b.subjectId }));
  lastUsedAt(a, Date.now() - 60000);
  lastUsedAt(b, Date.now() - 120000);
  lastUsedAt(c, Date.now() - 30000);

  // -------------------------------------------------------------------------
  t.log.info('A. at the cap a new chosen session of someone else is refused');
  // -------------------------------------------------------------------------
  withSetting('authn.maxSessions', 3, function () {
    told.length = 0;
    const detail = {};
    const d = signIn('cap-dave', detail);
    t.equal(d, null, 'the fourth session is not created');
    t.equal(detail.refusedWith, 'STS-AUTHN-0337',
            'the sign-in is marked for the screen to draw again');
    t.equal(authn.sessions.size, 3, 'and the store stays at the cap');
    t.check(!!authn.sessions.get(b.id),
            'Bob remains — a full realm does not end somebody else');
    t.check(!!authn.sessions.get(a.id) && !!authn.sessions.get(c.id),
            'and the other two are untouched');
    t.equal(endRowFor(b.id), null, 'Bob has no session.end row');
    t.check(refuseFor('cap-dave').length >= 1,
            'Dave\'s refusal is a session.refuse row carrying STS-AUTHN-0337');
    const notice = told.filter(function (n) {
      return n && n.session && n.session.id === b.id;
    })[0] || null;
    t.equal(notice, null, 'and CAEP is not told that Bob was revoked');

    // -----------------------------------------------------------------------
    t.log.info('B. a write back to an existing session is not an insert');
    // -----------------------------------------------------------------------
    const held = authn.sessions.get(a.id);
    t.check(authn.noteSessionChanged(held) === true &&
            authn.sessions.size === 3 && !!authn.sessions.get(b.id) &&
            !!authn.sessions.get(c.id),
            'at the cap, re-setting a live session ends nothing');
  });

  // -------------------------------------------------------------------------
  t.log.info('C. a lowered cap does not mass-end');
  // -------------------------------------------------------------------------
  withSetting('authn.maxSessions', 1, function () {
    const e = signIn('cap-erin');
    t.equal(e, null, 'a new subject at a lowered cap is refused');
    t.equal(authn.sessions.size, 3,
            'the three already held are still there');
    t.check(!!authn.sessions.get(a.id) && !!authn.sessions.get(b.id) &&
            !!authn.sessions.get(c.id),
            'a lowered cap does not leave only the newcomer');
  });

  clearSessions();
  withSetting('authn.maxSessions', 100, function () {
    withSetting('authn.maxSessionsPerSubject', 2, function () {
      const alice = signIn('cap-alice');
      const older = signIn('cap-bob');
      const newer = signIn('cap-bob');
      lastUsedAt(older, Date.now() - 90000);
      lastUsedAt(newer, Date.now() - 10000);
      const third = signIn('cap-bob');
      t.check(!!third && !authn.sessions.get(older.id),
              'one insert ends at most the subject\'s own oldest row');
      t.check(!!authn.sessions.get(newer.id) &&
              !!authn.sessions.get(alice.id),
              'the newer own row and Alice both remain');
    });
  });

  clearSessions();
  withSetting('authn.maxSessions', 3, function () {
    withSetting('authn.maxSessionsPerSubject', 2, function () {
      withSetting('authn.sessionShedPerSweep', 2, function () {
        const now = Date.now();
        plant('cap-shed-b1', 'shed-bob', now - 50000, true);
        plant('cap-shed-b2', 'shed-bob', now - 40000, true);
        plant('cap-shed-b3', 'shed-bob', now - 30000, true);
        plant('cap-shed-b4', 'shed-bob', now - 20000, true);
        plant('cap-shed-b5', 'shed-bob', now - 10000, true);
        plant('cap-shed-a', 'shed-alice', now - 80000, true);
        plant('cap-shed-z', '', now - 90000, false);
        const before = authn.sessions.size;
        const swept = runSweep();
        t.equal(authn.sessions.get('cap-shed-b1'), undefined,
                'the sweep ends the oldest surplus row');
        t.equal(authn.sessions.get('cap-shed-b2'), undefined,
                'and a second, which is the whole budget');
        t.check(!!authn.sessions.get('cap-shed-b3') &&
                !!authn.sessions.get('cap-shed-b4') &&
                !!authn.sessions.get('cap-shed-b5'),
                'it does not bring the subject all the way down in one run');
        t.check(!!authn.sessions.get('cap-shed-a'),
                'a subject at or under their cap stays, though the realm ' +
                'is over authn.maxSessions');
        t.check(!!authn.sessions.get('cap-shed-z'),
                'an arrival is not ended for capacity');
        t.equal(before - authn.sessions.size, 2,
                'the sweep ended its budget and nothing else');
        t.check(swept && swept.ended >= 2,
                'and those capacity ends are in the job\'s ended count');
      });
    });
  });

  // -------------------------------------------------------------------------
  t.log.info('D. an arrival flood ends nobody');
  // -------------------------------------------------------------------------
  clearSessions();
  withSetting('authn.maxSessions', 3, function () {
    const alice = signIn('cap-alice');
    const first = fakeRes();
    const second = fakeRes();
    const one = authn.startArrivalSession({ headers: {}, query: {} },
                                          first, '/admin');
    const two = authn.startArrivalSession({ headers: {}, query: {} },
                                          second, '/admin');
    t.check(!!one && one.subjectId === '' && one.chosen === false,
            'an arrival is stored with an empty subjectId');
    t.check(!!two && !!authn.sessions.get(two.id),
            'a second browser\'s arrival is stored while there is room');
    t.equal(authn.sessions.size, 3, 'Alice and two arrivals fill the cap');
    let refused = 0;
    for (let i = 0; i < 8; i++) {
      const res = fakeRes();
      const made = authn.startArrivalSession({ headers: {}, query: {} },
                                             res, '/admin');
      if (made) {
        refused += 0;
      } else {
        refused += 1;
        t.equal(res.headers.length, 0,
                'a refused arrival sets no cookie');
      }
    }
    t.equal(refused, 8, 'further arrivals are refused');
    t.equal(authn.sessions.size, 3, 'and the store does not grow');
    t.check(!!authn.sessions.get(alice.id) && !!authn.sessions.get(two.id),
            'Alice and the second arrival both remain');
  });

  // -------------------------------------------------------------------------
  t.log.info('E. one address is not an admission key');
  // -------------------------------------------------------------------------
  clearSessions();
  withSetting('authn.maxSessions', 10, function () {
    const address = '203.0.113.9';
    const left = fakeRes();
    const right = fakeRes();
    left.req = { ip: address, headers: {},
                 socket: { remoteAddress: address } };
    right.req = { ip: address, headers: {},
                  socket: { remoteAddress: address } };
    const one = authn.startSession(left, 'cap-ada', ['pwd'], '1', 'Test',
                                   { request: left.req });
    const two = authn.startSession(right, 'cap-bea', ['pwd'], '1', 'Test',
                                   { request: right.req });
    t.check(!!one && !!two && !!authn.sessions.get(one.id) &&
            !!authn.sessions.get(two.id),
            'two browsers at one address are both stored while there is room');
    t.check(!!cookieFrom(left, authn.SESSION_COOKIE) &&
            !!cookieFrom(right, authn.SESSION_COOKIE),
            'and both receive a sign-in cookie');
  });

  // -------------------------------------------------------------------------
  t.log.info('F. Bob past his own cap ends Bob, not Alice');
  // -------------------------------------------------------------------------
  clearSessions();
  told.length = 0;
  withSetting('authn.maxSessions', 100, function () {
    withSetting('authn.maxSessionsPerSubject', 1, function () {
      const alice = signIn('cap-alice');
      const bob = signIn('cap-bob');
      lastUsedAt(bob, Date.now() - 50000);
      told.length = 0;
      const again = signIn('cap-bob');
      t.check(!!again && !authn.sessions.get(bob.id),
              'Bob\'s oldest session was ended');
      t.check(!!authn.sessions.get(alice.id), 'Alice was not');
      const row = endRowFor(bob.id);
      t.check(!!row && row.errorCode === 'STS-AUTHN-0292',
              'the end is a session.end row carrying STS-AUTHN-0292',
              row ? JSON.stringify({ errorCode: row.errorCode }) : '(none)');
      const notice = told.filter(function (n) {
        return n && n.session && n.session.id === bob.id;
      })[0] || null;
      t.check(!!notice && notice.initiatingEntity === 'policy' &&
              notice.expired === true,
              'and CAEP is told it was revoked, initiated by policy',
              notice ? JSON.stringify({ entity: notice.initiatingEntity,
                                       expired: notice.expired })
                     : '(no notice)');
    });
  });

  // -------------------------------------------------------------------------
  t.log.info('G. a full realm does not grow for a console crawl');
  // -------------------------------------------------------------------------
  clearSessions();
  withSetting('authn.maxSessions', 3, function () {
    const alice = signIn('cap-alice');
    signIn('cap-bob');
    signIn('cap-carol');
    const before = authn.sessions.size;
    for (let i = 0; i < 12; i++) {
      authn.startArrivalSession({ headers: {}, query: {} }, fakeRes(),
                                '/admin');
    }
    t.equal(authn.sessions.size, before,
            'cookieless /admin arrivals do not grow a full realm');
    const child = authn.startRelyingPartySession({
      res: fakeRes(), username: 'cap-alice',
      claims: {}, parent: alice.id, surface: 'admin',
      label: 'Admin console', clientId: 'sts-admin-console',
      cookie: 'sts_admin'
    });
    t.equal(child, null, 'a console insert at a full realm is refused');
    t.equal(authn.sessions.size, before, 'and the store does not grow');
    t.check(!!authn.sessions.get(alice.id), 'Alice remains');
  });

  // -------------------------------------------------------------------------
  t.log.info('H. a relying-party row is chosen, and backs the console');
  // -------------------------------------------------------------------------
  clearSessions();
  withSetting('authn.maxSessions', 100, function () {
    withSetting('authn.maxSessionsPerSubject', 5, function () {
      const parent = signIn('cap-alice');
      const child = authn.startRelyingPartySession({
        res: fakeRes(), username: 'cap-alice', claims: { sid: parent.id },
        parent: parent.id, surface: 'admin', label: 'Admin console',
        clientId: 'sts-admin-console', cookie: 'sts_admin'
      });
      t.check(!!child && child.chosen === true,
              'a relying-party row is stored with chosen: true');
      t.equal(child.subjectId, parent.subjectId,
              'and it freezes the same subjectId as the sign-on');
      t.equal(authn.sessions.get(parent.id).backsConsole, true,
              'an admin child sets backsConsole on the parent');
    });
  });

  // -------------------------------------------------------------------------
  t.log.info('I. an upgrade ends one other own row');
  // -------------------------------------------------------------------------
  clearSessions();
  withSetting('authn.maxSessions', 100, function () {
    withSetting('authn.maxSessionsPerSubject', 1, function () {
      const alice = signIn('cap-alice');
      const bob = signIn('cap-bob');
      const plantedRes = fakeRes();
      const arrival = authn.startArrivalSession(
        { headers: {}, query: {} }, plantedRes, 'arrival');
      t.check(!!arrival && arrival.subjectId === '',
              'the arrival does not count toward Alice');
      const planted = cookieFrom(plantedRes, authn.SESSION_COOKIE);
      const signInRes = fakeRes();
      const upgraded = authn.startSession(
        signInRes, 'cap-alice', ['pwd'], '1', 'Test', {
          request: reqWith(authn.SESSION_COOKIE, planted)
        });
      t.check(!!upgraded && upgraded.id === arrival.id,
              'the arrival id is kept');
      t.equal(authn.sessions.get(alice.id), undefined,
              'Alice\'s other row was the victim');
      t.check(!!authn.sessions.get(bob.id),
              'Bob was not ended by Alice\'s upgrade');
      t.equal(upgraded.chosen, true, 'the upgraded row is chosen');
      t.equal(upgraded.subjectId, alice.subjectId,
              'and it keeps Alice\'s subjectId');
    });
  });

  // -------------------------------------------------------------------------
  t.log.info('J. a portal insert does not end its parent');
  // -------------------------------------------------------------------------
  clearSessions();
  withSetting('authn.maxSessions', 100, function () {
    withSetting('authn.maxSessionsPerSubject', 1, function () {
      const alice = signIn('cap-alice');
      const bob = signIn('cap-bob');
      const child = authn.startRelyingPartySession({
        res: fakeRes(), username: 'cap-alice', claims: {},
        parent: alice.id, surface: 'portal', label: 'User portal',
        clientId: 'sts-user-portal', cookie: 'sts_portal'
      });
      t.check(!!child && child.chosen === true,
              'the portal session is admitted');
      t.check(!!authn.sessions.get(alice.id),
              'and it does not end the sign-on it was derived from');
      t.equal(endRowFor(alice.id), null, 'the parent has no session.end');
      t.check(!!authn.sessions.get(bob.id), 'Bob is untouched');
    });
  });

  // -------------------------------------------------------------------------
  t.log.info('K. merge keeps backsConsole and a non-empty subjectId');
  // -------------------------------------------------------------------------
  const ahead = {
    chosen: true, authTime: 10, backsConsole: false,
    subjectId: 'urn:uuid:aaa', lastSeenAt: 1
  };
  const behind = {
    chosen: false, authTime: 99, backsConsole: true,
    subjectId: 'urn:uuid:bbb', lastSeenAt: 2
  };
  const merged = authn.mergeSessionRows(behind, ahead);
  const swapped = authn.mergeSessionRows(ahead, behind);
  t.equal(merged.backsConsole, true, 'backsConsole is the OR');
  t.equal(swapped.backsConsole, true, 'whichever copy is stored');
  t.equal(merged.subjectId, 'urn:uuid:aaa',
          'two different subject ids keep the further-along copy');
  t.equal(swapped.subjectId, 'urn:uuid:aaa',
          'and the same when the copies are swapped');
  const emptyAhead = {
    chosen: true, authTime: 50, subjectId: '', backsConsole: false
  };
  const filled = {
    chosen: false, authTime: 1, subjectId: 'urn:uuid:ccc',
    backsConsole: true
  };
  const kept = authn.mergeSessionRows(emptyAhead, filled);
  t.equal(kept.subjectId, 'urn:uuid:ccc',
          'an empty further-along subjectId keeps the other copy\'s');
  t.equal(kept.backsConsole, true, 'and the OR still holds');

  // -------------------------------------------------------------------------
  t.log.info('L. a refused sign-in leaves the browser\'s session');
  // -------------------------------------------------------------------------
  clearSessions();
  const keptRes = fakeRes();
  const keptSession = authn.startSession(keptRes, 'cap-ada', ['pwd'],
                                         '1', 'Test', {
                                           request: { headers: {}, query: {} }
                                         });
  const keptCookie = cookieFrom(keptRes, authn.SESSION_COOKIE);
  signIn('cap-bob');
  signIn('cap-carol');
  withSetting('authn.maxSessions', 1, function () {
    const detail = { request: reqWith(authn.SESSION_COOKIE, keptCookie) };
    const refusedRes = fakeRes();
    const refused = authn.startSession(refusedRes, 'cap-dave', ['pwd'],
                                       '1', 'Test', detail);
    t.equal(refused, null, 'the replacement is not admitted');
    t.equal(detail.refusedWith, 'STS-AUTHN-0337',
            'the refusal is the realm cap');
    t.equal(refusedRes.headers.length, 0,
            'and no cookie is written for it');
    t.check(!!authn.sessions.get(keptSession.id),
            'the browser\'s current session stays');
    t.equal(endRowFor(keptSession.id), null, 'it was not ended');
    t.equal(authn.sessions.size, 3,
            'Bob and Carol are still held with it');
  });

  clearSessions();
  withSetting('authn.maxSessions', 2, function () {
    const firstRes = fakeRes();
    const first = authn.startSession(firstRes, 'cap-ada', ['pwd'], '1',
                                    'Test', {
                                      request: { headers: {}, query: {} }
                                    });
    const second = signIn('cap-bea');
    const third = authn.startSession(fakeRes(), 'cap-cara', ['pwd'],
                                    '1', 'Test', {
                                      request: reqWith(
                                        authn.SESSION_COOKIE,
                                        cookieFrom(firstRes,
                                                   authn.SESSION_COOKIE))
                                    });
    t.check(!!third && !!authn.sessions.get(third.id),
            'a realm exactly at the cap admits the switch');
    t.equal(authn.sessions.get(first.id), undefined,
            'and then ends the session this browser was on');
    t.check(!!authn.sessions.get(second.id), 'the other subject stays');
    const ended = endRowFor(first.id);
    t.check(!!ended && ended.detail && ended.detail.via ===
            'a new sign-in in the same browser',
            'the end names the replacement',
            ended ? JSON.stringify(ended.detail) : '(none)');
  });

  // -------------------------------------------------------------------------
  t.log.info('M. two realms do not share one shed budget');
  // -------------------------------------------------------------------------
  clearSessions();
  const other = realms.create({
    id: 'session-cap-b', name: 'session-cap-b',
    description: 'Created by ' + __filename
  });
  if (!other.ok) {
    t.bad('could not create the realm "session-cap-b"',
          (other.errors || []).join(' '));
  } else {
    try {
      const now = Date.now();
      withSetting('authn.maxSessionsPerSubject', 1, function () {
        withSetting('authn.sessionShedPerSweep', 1, function () {
          plant('cap-bud-a1', 'shed-a', now - 40000, true);
          plant('cap-bud-a2', 'shed-a', now - 30000, true);
          plant('cap-bud-a3', 'shed-a', now - 20000, true);
          plant('cap-bud-a4', 'shed-a', now - 10000, true);
          realms.run(other.realm, function () {
            withSetting('authn.maxSessionsPerSubject', 1, function () {
              withSetting('authn.sessionShedPerSweep', 3, function () {
                plant('cap-bud-b1', 'shed-b', now - 35000, true);
                plant('cap-bud-b2', 'shed-b', now - 25000, true);
                plant('cap-bud-b3', 'shed-b', now - 15000, true);
                plant('cap-bud-b4', 'shed-b', now - 5000, true);
                const swept = runSweep();
                t.equal(authn.sessions.get('cap-bud-b1'), undefined,
                        'realm B spends its own budget of three');
                t.equal(authn.sessions.get('cap-bud-b2'), undefined,
                        'the second surplus row of B');
                t.equal(authn.sessions.get('cap-bud-b3'), undefined,
                        'and the third');
                t.check(!!authn.sessions.get('cap-bud-b4'),
                        'B keeps the row still inside its cap');
                t.check(swept && swept.ended >= 4,
                        'the job counts every realm\'s sheds');
              });
            });
          });
          t.equal(authn.sessions.get('cap-bud-a1'), undefined,
                  'realm A spends only its own budget of one');
          t.check(!!authn.sessions.get('cap-bud-a2') &&
                  !!authn.sessions.get('cap-bud-a3') &&
                  !!authn.sessions.get('cap-bud-a4'),
                  'A\'s newer surplus stays for a later sweep');
        });
      });
    } finally {
      realms.remove('session-cap-b');
    }
  }

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
  describe: 'authn.maxSessions refuses a new row at the realm cap, ends ' +
            'one own session at the per-subject cap (STS-AUTHN-0292), and ' +
            'each realm\'s sweep sheds at most its own budget (#350)',
  run: run
};
