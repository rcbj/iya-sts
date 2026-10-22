// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: console_sessions_index.js
//
// ===========================================================================
// THE CONSOLE'S SESSION PAGES READ THE SESSION INDEX, NOT EVERY SESSION
// (2026-10-22, #820).
//
// Monitoring → Sessions on 8081 opened every session's sealed body, one
// synchronous read each — about 470,000 — on a request worker, for two
// minutes; through read-your-write every other worker waited behind it and
// sign-ins and refreshes stopped. Monitoring → Metrics and a person's page
// walked the same list.
//
//   S1. the index answers the counts and a page with a search by digest, and
//       `answerOf()` shapes them;
//   S2. `sessionsViewAsync()`, while the window is on, never lists every
//       session: the held count is the index's, the rows are one page, the
//       search is handed to the index, and the answer says it is windowed;
//   S3. the other families are listed ahead of the sessions, and the
//       sessions' page starts after them;
//   S4. `metricsJsonAsync()` counts from the index and draws the newest page;
//   S5. `sessionRowsFor()` reads only the person's sessions while the window
//       is on;
//   S6. with the window off, both views answer as before.
//
// In a child process: it stands in for the logout reader and the session
// reads.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'console_sessions_index',
  level: process.env.LOG_LEVEL || 'info' });

// Runs in the child. Stringified, so it may use nothing from this file's scope.
function child() {
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  const OUT = process.env.CSI_OUT;
  const ROOT = process.env.CSI_ROOT;
  (async function () {
    const queries = require(ROOT + '/persistence/session_queries');
    const views = require(ROOT + '/admin-core/admin_views');
    const authn = require(ROOT + '/authn/authn');

    const totals = queries.build('session.liveTotals',
                                 ['r', 5, 'u', 's', 'k', -1]);
    const page = queries.build('session.livePage',
                               ['r', 5, '', '', '', 0, 50, 100]);
    const shaped = queries.answerOf('session.liveTotals', [{ a: '7', u: '2' }]);
    const keys = queries.answerOf('session.livePage', [{ key: 'd1' },
                                                       { key: 'd2' }]);
    note(/count\(\*\) FILTER/.test(totals.text) &&
         totals.values.length === 6 && /LIMIT \$7 OFFSET \$8/.test(page.text) &&
         page.values[6] === 50 && page.values[7] === 100 &&
         /username_key = \$3 OR subject_key = \$4 OR key = \$5/
           .test(page.text) &&
         shaped.authenticated === 7 && shaped.unauthenticated === 2 &&
         keys.join(',') === 'd1,d2',
         'S1. the index counts and pages live sessions, searching by digest',
         JSON.stringify({ totals: totals.values, page: page.values,
                          shaped: shaped, keys: keys }));

    const session = function (id, user, started) {
      return { id: id, family: 'session', username: user, sub: '',
               protocol: 'OAuth 2.0 / OIDC', handle: id, key: user,
               kind: 'Browser sign-on session', startedAt: started,
               expiresAt: 0, authenticated: true, carries: [] };
    };
    const ticket = { id: 'krb5:alice@R', family: 'krb5', username: 'alice',
                     sub: '', protocol: 'Kerberos v5', handle: 'alice@R',
                     key: 'alice', kind: 'Kerberos ticket-granting ticket',
                     startedAt: 1, authenticated: true, carries: [] };
    const asked = [];
    let walked = 0;
    views.setLogoutReader({
      liveSessions: function () {
        walked++;
        return [ticket, session('s-1', 'alice', 3)];
      },
      liveSessionsPageAsync: function (options) {
        asked.push(JSON.stringify(options));
        const rows = [ticket];
        for (let i = 0; i < Math.min(2, options.limit); i++) {
          rows.push(session('p-' + (options.offset + i), 'bob', 100 - i));
        }
        return Promise.resolve({ rows: rows, sessionTotal: 470000,
                                 authenticated: 470000, unauthenticated: 0 });
      },
      inventoryFor: function () {
        return [];
      },
      terminate: function () {
        return {};
      },
      SESSION_EXPIRY_RULES: {}
    });
    const view = await views.sessionsViewAsync({ query: { q: 'bob' } });
    const json = view.json;
    // `bob` matches the sessions the index answered, and not alice's
    // Kerberos ticket, which the view filters itself.
    note(walked === 0 && json.held === 470000 && json.windowed === true &&
         json.sessions.length === 2 && json.sessions.every(function (row) {
           return row.family === 'session';
         }) && asked.length >= 2 && JSON.parse(asked[0]).q === 'bob',
         'S2. the Sessions view counts from the index and draws one page, ' +
         'never every session', JSON.stringify({ walked: walked,
           held: json.held, shown: json.sessions.length, asked: asked }));
    asked.length = 0;
    await views.sessionsViewAsync({ query: { page: '2' } });
    const second = asked.map(function (one) {
      return JSON.parse(one);
    }).filter(function (one) {
      return one.limit > 1;
    })[0];
    // Page 2 of 50 with one other family ahead: the sessions' offset is
    // 50 - 1.
    note(second && second.offset === 49,
         'S3. a later page of sessions starts after the other families',
         JSON.stringify(asked));

    const realPage = authn.liveSessionPageAsync;
    const realOn = authn.sessionWindowOn;
    const realHeld = authn.sessionsHeldUnder;
    const realMatching = authn.sessionsMatching;
    let matchedAll = 0;
    authn.sessionsMatching = function () {
      matchedAll++;
      return [];
    };
    try {
      authn.liveSessionPageAsync = function () {
        return Promise.resolve({ authenticated: 470000, unauthenticated: 0,
          total: 470000, sessions: [
            { id: 'm-1', user: { username: 'carol' }, amr: [] }] });
      };
      const metrics = await views.metricsJsonAsync();
      note(matchedAll === 0 && metrics.signOnSessions.held === 470000 &&
           metrics.signOnSessions.rows.length === 1 &&
           metrics.signOnSessions.windowed === true,
           'S4. Metrics counts from the index and draws the newest page',
           JSON.stringify(metrics.signOnSessions));

      authn.sessionWindowOn = function () {
        return true;
      };
      let heldAsked = '';
      authn.sessionsHeldUnder = function (name) {
        heldAsked = name;
        return [{ id: 'h-1', user: { username: 'dave' }, amr: [] }];
      };
      const own = views.sessionRowsFor('dave');
      note(matchedAll === 0 && heldAsked === 'dave' && own.length === 1 &&
           own[0].id === 'h-1',
           'S5. a person\'s page reads only that person\'s sessions',
           JSON.stringify({ asked: heldAsked, rows: own.length }));

      authn.liveSessionPageAsync = function () {
        return Promise.resolve(null);
      };
      authn.sessionWindowOn = function () {
        return false;
      };
      const off = await views.metricsJsonAsync();
      views.setLogoutReader({
        liveSessions: function () {
          walked++;
          return [session('w-1', 'erin', 1)];
        },
        liveSessionsPageAsync: function () {
          return Promise.resolve(null);
        },
        inventoryFor: function () {
          return [];
        },
        terminate: function () {
          return {};
        },
        SESSION_EXPIRY_RULES: {}
      });
      const before = walked;
      const offView = await views.sessionsViewAsync({ query: {} });
      note(matchedAll === 1 && off.signOnSessions.windowed === undefined &&
           walked === before + 1 && offView.json.windowed === false &&
           offView.json.held === 1,
           'S6. with the window off both views answer as before',
           JSON.stringify({ matchedAll: matchedAll,
                            held: offView.json.held }));
    } finally {
      authn.liveSessionPageAsync = realPage;
      authn.sessionWindowOn = realOn;
      authn.sessionsHeldUnder = realHeld;
      authn.sessionsMatching = realMatching;
    }
  })().catch(function (e) {
    note(false, 'the child threw', (e && e.stack) || e);
  }).then(function () {
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function run(t) {
  log.debug("Entering run().");
  const root = path.join(__dirname, '..');
  const out = path.join(os.tmpdir(), 'sts-csi-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|CONFIG_FILE$)/.test(key)) {
      env[key] = process.env[key];
    }
  });
  Object.assign(env, { CSI_OUT: out, CSI_ROOT: root, LOG_LEVEL: 'fatal',
                       STS_LOG_LEVEL: 'fatal' });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + child.toString() + ')()'], {
      cwd: root, env: env, encoding: 'utf8', timeout: 120000 });
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
  name: 'console_sessions_index',
  describe: 'the console\'s Sessions, Metrics and person pages read the ' +
            'session index, not every session (#820)',
  run: run
};
