// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: console_consent_scale.js
//
// ===========================================================================
// MONITORING → CONSENT READS ONE PAGE OF PEOPLE, NOT EVERY CONSENT HOLDER
// (2026-10-22, #820).
//
// `GET /admin-api/consent` built the whole register: every person holding
// `oauthConsent` — about 470,000 on 8081, since consent is required by
// default — read through the synchronous bridge with a decrypt each, on a
// request worker, and then counted the people with a reduce that was
// O(P²). This holds the replacement:
//
//   C1. the store answers the two questions — how many hold an attribute,
//       and one page of them at an offset — through the asked names' index
//       expression, and `answerOf()` shapes the count;
//   C2. `consentPageViewAsync()`, where the directory pages, never lists
//       every holder: the count is the store's, one page of PEOPLE is read
//       at the paging's offset, and the answer says `windowed`;
//   C3. a search is exact: a whole username is asked by name, and a
//       client_id or scope is looked for in a bounded number of holders,
//       the answer saying whether that was everybody;
//   C4. with the directory in memory (`consentHoldersPageAsync()` absent,
//       or answering null) the page answers exactly as before, and the
//       people count is right for a person holding several consents;
//   C5. the real directory, not windowed in this process, answers null, so
//       the console keeps its old path.
//
// In a child process: it installs a stand-in directory in the consent
// register, which `tests/run.js`'s shared process must not keep.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'console_consent_scale',
  level: process.env.LOG_LEVEL || 'info' });

// Runs in the child. Stringified, so it may use nothing from this file's scope.
function child() {
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  const OUT = process.env.CCS_OUT;
  const ROOT = process.env.CCS_ROOT;
  (async function () {
    const queries = require(ROOT + '/persistence/directory_queries');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const consent = require(ROOT + '/common/consent');
    const views = require(ROOT + '/admin-core/admin_views');

    // C1. The two statements.
    const counted = queries.build('countWithAttribute',
                                  ['r', 'ou=users,dc=x', 'oauthconsent']);
    const paged = queries.build('withAttributeAt',
                                ['r', 'ou=users,dc=x', 'oauthconsent', 100,
                                 50]);
    note(counted.text.indexOf(queries.ASKED_NAMES) >= 0 &&
         counted.text.indexOf(queries.ASKED_NAMES_HELD) >= 0 &&
         /^SELECT count\(\*\)/.test(counted.text) &&
         paged.text.indexOf(queries.ASKED_NAMES) >= 0 &&
         /ORDER BY dn_key LIMIT \$4 OFFSET \$5/.test(paged.text) &&
         paged.values[3] === 50 && paged.values[4] === 100 &&
         queries.answerOf('countWithAttribute', [{ n: '470000' }]) === 470000,
         'C1. the store counts and pages the holders through the asked ' +
         'names\' index', JSON.stringify({ count: counted.text,
                                           page: paged.values }));

    // C5. Not windowed in this process: the real directory answers null.
    const real = ldap && consent.directoryInstalled();
    const realPage = await real.consentHoldersPageAsync(0, 10);
    const realNamed = await real.consentHolderNamedAsync('alice');
    note(realPage === null && realNamed === null,
         'C5. the directory held in memory answers null, so the console ' +
         'keeps its old path', JSON.stringify({ realPage, realNamed }));

    const value = function (i, client, scope) {
      return '2026101' + (i % 10) + '120000Z ' + scope + ' ' + client;
    };
    const holder = function (i) {
      return { username: 'p' + i, dn: 'uid=p' + i + ',ou=users,dc=x',
               values: [value(i, 'client-' + (i % 7), 'openid'),
                        value(i, 'client-' + (i % 7), 'profile')] };
    };
    const TOTAL = 470000;
    let walked = 0;
    const pages = [];
    const named = [];
    const base = {
      consentsOf: function () { return { values: [] }; },
      addConsent: function () { return { ok: true }; },
      removeConsent: function () { return {}; },
      listConsents: function () {
        walked++;
        return [holder(1), holder(2), holder(1)];
      },
      withdrawalsOf: function () { return { values: [] }; },
      addWithdrawal: function () { return { ok: true }; },
      removeWithdrawal: function () { return {}; }
    };
    const windowed = Object.assign({}, base, {
      consentHoldersPageAsync: function (offset, limit) {
        pages.push([offset, limit]);
        const rows = [];
        for (let i = 0; i < limit && offset + i < TOTAL; i++) {
          rows.push(holder(offset + i));
        }
        return Promise.resolve({ total: TOTAL, read: rows.length,
                                 rows: rows });
      },
      consentHolderNamedAsync: function (name) {
        named.push(name);
        return Promise.resolve({ row: name === 'p3' ? holder(3) : null });
      }
    });
    const before = consent.directoryInstalled
      ? consent.directoryInstalled() : null;
    try {
      // C2. One page of people.
      note(consent.setDirectory(windowed) === true,
           'the stand-in directory is installed', '');
      const view = await views.consentPageViewAsync(
        { query: { per: '25', usersPage: '3' } });
      const json = view.json;
      const read = pages.filter(function (one) {
        return one[1] > 0;
      });
      note(walked === 0 && json.windowed === true &&
           json.matched === TOTAL && json.counts.people === TOTAL &&
           json.usersPaging.noun === 'people' &&
           json.usersPaging.total === TOTAL && json.usersPaging.page === 3 &&
           read.length === 1 && read[0][0] === 50 && read[0][1] === 25 &&
           json.users.length === 50 && json.counts.consents === 50 &&
           json.counts.countsOf === 'page',
           'C2. the page counts from the store and reads one page of ' +
           'people, never every holder',
           JSON.stringify({ walked: walked, pages: pages,
                            matched: json.matched, shown: json.users.length,
                            paging: json.usersPaging }));

      // C3. An exact search.
      pages.length = 0;
      const byName = (await views.consentPageViewAsync(
        { query: { q: 'p3' } })).json;
      const scannedRows = pages.reduce(function (sum, one) {
        return sum + one[1];
      }, 0);
      note(walked === 0 && byName.windowed === true &&
           named[named.length - 1] === 'p3' &&
           byName.users.length === 2 && byName.users.every(function (one) {
             return one.username === 'p3';
           }) && byName.search && byName.search.exact === true &&
           byName.search.complete === false &&
           byName.search.scanned === 5000 && scannedRows <= 5000,
           'C3a. a whole username is asked by name, and the bounded scan ' +
           'says it did not look at everybody',
           JSON.stringify({ named: named, search: byName.search,
                            rows: byName.users.length,
                            scannedRows: scannedRows }));
      const byClient = (await views.consentPageViewAsync(
        { query: { q: 'CLIENT-4', per: '10' } })).json;
      note(byClient.users.length === 10 && byClient.users.every(
        function (one) {
          return one.client === 'client-4';
        }) && byClient.usersPaging.total > 10 &&
        byClient.usersPaging.noun === 'consents',
           'C3b. a whole client_id finds its consents among the scanned ' +
           'holders, paged', JSON.stringify(byClient.usersPaging));

      // C4. Window off: the hooks absent, and the hooks answering null.
      walked = 0;
      consent.setDirectory(base);
      const off = (await views.consentPageViewAsync({ query: {} })).json;
      note(walked === 1 && off.windowed === false &&
           off.counts.people === 2 && off.counts.consents === 6 &&
           off.matched === 6,
           'C4a. with no paged directory the whole register answers, and ' +
           'a person holding several consents is counted once',
           JSON.stringify({ walked: walked, counts: off.counts }));
      walked = 0;
      consent.setDirectory(Object.assign({}, base, {
        consentHoldersPageAsync: function () {
          return Promise.resolve(null);
        },
        consentHolderNamedAsync: function () {
          return Promise.resolve(null);
        }
      }));
      const nulled = (await views.consentPageViewAsync(
        { query: { q: 'p1' } })).json;
      const sync = views.consentPageView({ q: 'p1' }).json;
      note(walked === 2 && nulled.windowed === false &&
           JSON.stringify(nulled.users) === JSON.stringify(sync.users) &&
           nulled.matched === sync.matched,
           'C4b. a directory that is not windowed answers exactly as the ' +
           'synchronous page', JSON.stringify({ walked: walked,
                                                matched: nulled.matched }));
    } finally {
      if (before) {
        consent.setDirectory(before);
      }
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
  const out = path.join(os.tmpdir(), 'sts-ccs-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|CONFIG_FILE$)/.test(key)) {
      env[key] = process.env[key];
    }
  });
  Object.assign(env, { CCS_OUT: out, CCS_ROOT: root, LOG_LEVEL: 'fatal',
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
  name: 'console_consent_scale',
  describe: 'Monitoring → Consent counts consent holders from the store and ' +
            'reads one page of people, not every holder (#820)',
  run: run
};
