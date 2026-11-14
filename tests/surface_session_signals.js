// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: surface_session_signals.js
//
// ===========================================================================
// A HOSTED SURFACE'S RECEIVED SIGNAL VISITS ITS OWN SESSIONS, NOT EVERY
// SESSION HELD (#767).
//
// `Authn.endRelyingPartySessions()` runs for every signal the console and
// the portal receive — each password write sends CAEP credential-change to
// both — and it walked every session the process held to find the
// surface's: about 15% of the two request workers on 8081 under a
// password-write load. The session store files a session by its
// `rpSurface` (`realms.map()`'s `indexBy`, #766), and the call visits those.
//
//   S1. among 2,000 sign-on sessions, a signal about one person ends that
//       person's portal sessions and nothing else: not another person's,
//       not the person's console sessions, not a sign-on session;
//   S2. a signal about somebody with no surface session — the case of
//       every password write here — makes no walk of the realm's
//       sessions (ending one still asks for its children, which is the
//       sign-out's own cost, once per session ended);
//   S3. a session made after the first call is filed and found by the next.
//
// In process, development mode, the session store in memory (no window).
// ===========================================================================

delete process.env.CONFIG_FILE;

const realms = require('../common/realms');
const authn = require('../authn/authn');

const log = require('bunyan').createLogger({ name: 'surface_session_signals',
  level: process.env.LOG_LEVEL || 'info' });

const STAMP = Date.now().toString(36);

function body(id, over) {
  log.debug("Entering body().");
  const row = {
    id: id, user: { username: id, sub: '' }, subjectId: id, chosen: true,
    authenticated: true, authTime: 1, lastSeenAt: 1000, startedAt: 500,
    expires: Date.now() + 3600000, amr: [], acr: '1', via: 'Test'
  };
  log.debug("Leaving body().");
  return Object.assign(row, over || {});
}

function surface(id, who, rp) {
  log.debug("Entering surface().");
  log.debug("Leaving surface().");
  return body(id, { user: { username: who, sub: '' }, rpSurface: rp,
                    derivedFrom: 'signon-' + who + '-' + STAMP,
                    derivedFromRealm: realms.DEFAULT_ID });
}

// The number of times a Map at least `min` long is walked while `fn` runs.
function walksDuring(min, fn) {
  log.debug("Entering walksDuring().");
  const real = Map.prototype.forEach;
  let walks = 0;
  Map.prototype.forEach = function () {
    if (this.size >= min) {
      walks += 1;
    }
    return real.apply(this, arguments);
  };
  try {
    const answer = fn();
    log.debug("Leaving walksDuring().");
    return { walks: walks, answer: answer };
  } finally {
    Map.prototype.forEach = real;
  }
}

function run(t) {
  log.debug("Entering run().");
  const store = authn.sessions.realmMap(realms.DEFAULT_ID);
  const made = [];
  const put = function (s) {
    store.set(s.id, s);
    made.push(s.id);
  };
  try {
    for (let i = 0; i < 2000; i++) {
      put(body('signon-' + i + '-' + STAMP));
    }
    for (let i = 0; i < 5; i++) {
      put(surface('portal-a-' + i + '-' + STAMP, 'pe-a-' + STAMP, 'portal'));
    }
    for (let i = 0; i < 3; i++) {
      put(surface('portal-b-' + i + '-' + STAMP, 'pe-b-' + STAMP, 'portal'));
    }
    for (let i = 0; i < 2; i++) {
      put(surface('admin-a-' + i + '-' + STAMP, 'pe-a-' + STAMP, 'admin'));
    }
    const about = function (user) {
      return user && user.username === 'pe-a-' + STAMP;
    };
    const nobody = walksDuring(1000, function () {
      return realms.run(realms.get(realms.DEFAULT_ID), function () {
        return authn.endRelyingPartySessions('portal', realms.DEFAULT_ID,
          function () {
            return false;
          }, 'a test signal', 'policy');
      });
    });
    const first = walksDuring(1000, function () {
      return realms.run(realms.get(realms.DEFAULT_ID), function () {
        return authn.endRelyingPartySessions('portal', realms.DEFAULT_ID,
          about, 'a test signal', 'policy');
      });
    });
    const left = function (prefix) {
      return made.filter(function (id) {
        return id.indexOf(prefix) === 0 && !!store.get(id);
      }).length;
    };
    t.check(first.answer === 5 && left('portal-a-') === 0 &&
            left('portal-b-') === 3 && left('admin-a-') === 2 &&
            left('signon-') === 2000,
            'S1. the signal ends that person\'s portal sessions and nothing ' +
            'else', JSON.stringify({ ended: first.answer,
              portalA: left('portal-a-'), portalB: left('portal-b-'),
              adminA: left('admin-a-'), signons: left('signon-') }));
    t.check(nobody.answer === 0 && nobody.walks === 0,
            'S2. a signal about somebody with no surface session walks none ' +
            'of the realm\'s 2,000-odd sessions',
            JSON.stringify({ ended: nobody.answer, walks: nobody.walks }));
    put(surface('portal-a-late-' + STAMP, 'pe-a-' + STAMP, 'portal'));
    const second = realms.run(realms.get(realms.DEFAULT_ID), function () {
      return authn.endRelyingPartySessions('portal', realms.DEFAULT_ID,
        about, 'a test signal', 'policy');
    });
    t.check(second === 1 && left('portal-a-late-') === 0,
            'S3. a session made after the first call is filed and ended by ' +
            'the next', String(second));
  } finally {
    // Tidied up: this store is module-wide (tests/CLAUDE.md).
    made.forEach(function (id) {
      store.delete(id);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'surface_session_signals',
  describe: 'a hosted surface\'s received signal visits its own sessions, ' +
            'not every session held (#767)',
  run: run
};
