// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: held_by_one_person.js
//
// ===========================================================================
// WHAT ONE PERSON HOLDS IS READ AS ONE PERSON'S SESSIONS, NOT EVERY SESSION
// IN THE REALM (#774).
//
// `logout.heldIds()` — the risk engine's `heldBy()`, asked at every sign-in
// whose level changes, which is every person's first — read every session of
// the realm and resolved each one's subject. With the session window on that
// is every sealed body and every subject asked of the store synchronously:
// on 8081 at 85,000 sessions, eighty seconds a sign-in after a restart.
// `authn.sessionsHeldUnder()` reads the two indexed columns that name a
// person, and `holderKeyOf()` is still asked of each candidate.
//
//   H1. heldIds() for one person reads authn's per-person door and never the
//       whole realm, and lists that person's sessions and nobody else's;
//   H2. a set of people still walks once, and gives each the same answer;
//   H3. a candidate the subject column finds that holderKeyOf() files under
//       another person is not counted (holderKeyOf() still decides);
//   Q1. the store's `session.subject` question carries its partial index's
//       predicate, and answers keys.
//
// In a child process: it fills the module-wide session store. The windowed
// read itself is the two queries Q1 and `session.username` name; the load
// that found this (`../load-users/sessions-1m`) holds it against postgres.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'held_by_one_person',
  level: process.env.LOG_LEVEL || 'info' });

// Runs in the child. Stringified, so it may use nothing from this file's scope.
function child() {
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  const OUT = process.env.HB_OUT;
  const ROOT = process.env.HB_ROOT;
  const finish = function () {
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  };
  try {
    const realms = require(ROOT + '/common/realms');
    const authn = require(ROOT + '/authn/authn');
    const logoutModule = require(ROOT + '/logout/logout');
    const queries = require(ROOT + '/persistence/session_queries');
    const store = authn.sessions.realmMap(realms.DEFAULT_ID);
    const STAMP = Date.now().toString(36);
    const session = function (id, username) {
      return { id: id, user: { username: username, sub: '' },
               subjectId: username, chosen: true, authenticated: true,
               authTime: 1, lastSeenAt: Date.now(), startedAt: Date.now(),
               expires: Date.now() + 3600000, amr: ['pwd'], acr: '1',
               via: 'Test' };
    };
    const A = 'hb-a-' + STAMP;
    const B = 'hb-b-' + STAMP;
    const ids = { a: [], b: [] };
    for (let i = 0; i < 3; i++) {
      ids.a.push('hb-sa-' + i + '-' + STAMP);
      store.set(ids.a[i], session(ids.a[i], A));
    }
    for (let i = 0; i < 2; i++) {
      ids.b.push('hb-sb-' + i + '-' + STAMP);
      store.set(ids.b[i], session(ids.b[i], B));
    }
    for (let i = 0; i < 500; i++) {
      store.set('hb-x-' + i + '-' + STAMP,
                session('hb-x-' + i + '-' + STAMP, 'hb-x-' + i + '-' + STAMP));
    }
    // The door logout reads, counted.
    const calls = { matching: 0, heldUnder: 0 };
    const spied = new Proxy(authn, { get: function (target, name) {
      if (name === 'sessionsMatching') {
        return function () {
          calls.matching++;
          return target.sessionsMatching.apply(target, arguments);
        };
      }
      if (name === 'sessionsHeldUnder') {
        return function () {
          calls.heldUnder++;
          return target.sessionsHeldUnder.apply(target, arguments);
        };
      }
      return target[name];
    } });
    const deps = Object.assign(logoutModule.Logout.defaultDeps(),
                               { authn: spied });
    const logout = new logoutModule.Logout(deps);
    const sessionIdsIn = function (list, wanted) {
      return wanted.filter(function (id) {
        return list.some(function (one) {
          return String(one).indexOf(id) >= 0;
        });
      }).length;
    };
    const inRealm = function (fn) {
      return realms.run(realms.get(realms.DEFAULT_ID), fn);
    };

    const one = inRealm(function () {
      return logout.heldIds(A);
    });
    note(calls.heldUnder === 1 && calls.matching === 0,
         'H1. one person\'s holdings read authn\'s per-person door and not ' +
         'the whole realm', JSON.stringify(calls));
    note(sessionIdsIn(one, ids.a) === 3 && sessionIdsIn(one, ids.b) === 0,
         'H1. and list that person\'s three sessions and none of another\'s',
         JSON.stringify(one));

    calls.matching = 0;
    calls.heldUnder = 0;
    const both = inRealm(function () {
      return logout.heldIdsFor([A, B]);
    });
    note(calls.matching === 1 && calls.heldUnder === 0,
         'H2. a set of people still walks the realm once',
         JSON.stringify(calls));
    note(JSON.stringify((both.get(A) || []).slice().sort()) ===
           JSON.stringify(one.slice().sort()) &&
         sessionIdsIn(both.get(B) || [], ids.b) === 2,
         'H2. and gives each person what the per-person read gave',
         JSON.stringify([both.get(A), one]));

    // A CANDIDATE THAT IS NOT A's: found through the subject column (its
    // subjectId is A's name) and held by another username, so holderKeyOf()
    // files it under that name — and it is not counted, as the walk does not.
    const stats = require(ROOT + '/common/admin_stats');
    const elsewhere = 'hb-elsewhere-' + STAMP;
    const odd = session(elsewhere, 'hb-other-' + STAMP);
    odd.subjectId = A;
    const filed = stats.holderKeyOf(odd.user.username, odd.user.sub);
    store.set(elsewhere, odd);
    calls.heldUnder = 0;
    const again = inRealm(function () {
      return logout.heldIds(A);
    });
    const walked = inRealm(function () {
      return logout.heldIdsFor([A, B]).get(A);
    });
    note(filed !== A && calls.heldUnder === 1 &&
         sessionIdsIn(again, [elsewhere]) === 0 &&
         sessionIdsIn(walked, [elsewhere]) === 0 &&
         sessionIdsIn(again, ids.a) === 3,
         'H3. a candidate the subject column finds and holderKeyOf() files ' +
         'under another person is not counted, as the walk does not count it',
         JSON.stringify({ filed: filed, again: again }));
    ids.a.push(elsewhere);

    const built = queries.build('session.subject', ['default', 'd1']);
    note(/subject_key = \$2/.test(built.text) && /chosen/.test(built.text) &&
         /subject_key <> ''/.test(built.text) &&
         JSON.stringify(built.values) === '["default","d1"]' &&
         JSON.stringify(queries.answerOf('session.subject',
           [{ key: 'k1' }, { key: 'k2' }])) === '["k1","k2"]',
         'Q1. session.subject carries sts_sessions_subject\'s predicate and ' +
         'answers keys', built.text);

    Object.keys(ids).forEach(function (k) {
      ids[k].forEach(function (id) {
        store.delete(id);
      });
    });
  } catch (e) {
    note(false, 'the child threw', (e && e.stack) || e);
  }
  finish();
}

function run(t) {
  log.debug("Entering run().");
  const root = path.join(__dirname, '..');
  const out = path.join(os.tmpdir(), 'sts-hb-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|CONFIG_FILE$)/.test(key)) {
      env[key] = process.env[key];
    }
  });
  Object.assign(env, { HB_OUT: out, HB_ROOT: root, LOG_LEVEL: 'fatal',
                       STS_LOG_LEVEL: 'fatal' });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + child.toString() + ')()'], {
      cwd: root, env: env, encoding: 'utf8', timeout: 180000,
      maxBuffer: 64 * 1024 * 1024 });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.rmSync(out, { force: true });
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (t.check(Array.isArray(findings),
              'the child process reported its findings',
              'status=' + result.status + ' ' +
              String(result.stderr || '').slice(-2000))) {
    findings.forEach(function (one) {
      t.check(one.ok, one.what, one.detail);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'held_by_one_person',
  describe: 'what one person holds is read as one person\'s sessions, not ' +
            'every session in the realm (#774)',
  run: run
};
