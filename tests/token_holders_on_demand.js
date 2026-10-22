// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: token_holders_on_demand.js
//
// ===========================================================================
// THE TOKEN HOLDERS ON DEMAND (2026-10-22, #820).
//
// `admin_stats.tokenHolders` was held whole, so every request worker read
// back every row at its start (562,120 on 8081, a worker's start from 16 s
// to 52 s). It is on demand with its keys resident now, and nothing that
// reads it may block on the store where it did not before:
//
//   H1. the store is declared on demand, keys resident, with a `mergeRow`
//       that keeps the earliest first sighting, the latest expiry and a
//       client once a client, and is the same whichever row is "mine";
//   H2. a JWT recorded for a holder this process does not hold writes the
//       row BLINDLY and reads nothing — no `read`, no `readMany`, no index
//       — whether or not its key is resident (H2b is the resident case,
//       the one a blocking `get()` would read for);
//   H3. a holder warmed first (`warmTokenHolders()`) is read in ONE batch,
//       and the next token for it, inside its row, writes nothing; a name
//       whose key is not resident is not asked of the store at all;
//   H4. `userKeyTest()` answers from the resident keys with no read;
//   H5. `userCountsAsync()` counts every holder from the resident keys and
//       the clients from the store's `client` index, asked asynchronously
//       and never through the blocking `byIndex`.
//
// In a child process: it installs a stand-in reader in `common/realms.js`.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'token_holders_on_demand',
  level: process.env.LOG_LEVEL || 'info' });

// Runs in the child. Stringified, so it may use nothing from this file's scope.
function child() {
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  const OUT = process.env.THD_OUT;
  const ROOT = process.env.THD_ROOT;
  (async function () {
    const realms = require(ROOT + '/common/realms');
    const stats = require(ROOT + '/common/admin_stats');
    const HOLDERS = 'admin_stats.tokenHolders';
    const TOKENS = 'admin_stats.tokens';
    const future = Math.floor(Date.now() / 1000) + 3600;
    const inRealm = function (fn) {
      return realms.run(realms.get(realms.currentId()), fn);
    };
    // The store: the holders' rows, keyed as the register keys them.
    const stored = new Map();
    stored.set('erin', { firstAt: 5, lastExp: future + 7 * 86400,
                         isClient: false });
    stored.set('svc-app', { firstAt: 6, lastExp: future + 7 * 86400,
                            isClient: true });
    const declared = realms.handleFor(HOLDERS);
    const asked = [];
    realms.setOnDemandReader({
      active: function (handle) {
        return handle === HOLDERS || handle === TOKENS;
      },
      digestOf: function (handle, realmId, key) {
        return handle === HOLDERS ? 'd:' + key : null;
      },
      read: function (handle, realmId, key) {
        asked.push(handle + ' read:' + key);
        if (handle === HOLDERS && stored.has(key)) {
          return { present: true, value: stored.get(key) };
        }
        return { present: false };
      },
      readMany: async function (handle, realmId, keys) {
        asked.push(handle + ' readMany:' + keys.join(','));
        const out = new Map();
        keys.forEach(function (key) {
          if (handle === HOLDERS && stored.has(key)) {
            out.set(key, stored.get(key));
          }
        });
        return out;
      },
      byIndex: function (handle, realmId, indexKey) {
        asked.push(handle + ' index:' + indexKey);
        return [];
      },
      byIndexAsync: async function (handle, realmId, indexKey) {
        asked.push(handle + ' indexAsync:' + indexKey);
        const out = [];
        if (handle === HOLDERS) {
          stored.forEach(function (value, key) {
            if ((declared.lookupsOf(value, key) || []).indexOf(indexKey) >=
                0) {
              out.push({ key: key, value: value });
            }
          });
        }
        return out;
      },
      page: function () {
        return { rows: [], next: '' };
      },
      journalled: function () {
        return false;
      }
    });
    // Every live row's key is resident, as a start loads them.
    declared.residentAdd('default', 'd:erin');
    declared.residentAdd('default', 'd:svc-app');
    const holderReads = function () {
      return asked.filter(function (a) {
        return a.indexOf(HOLDERS + ' ') === 0;
      });
    };

    // H1.
    const merged = declared.mergeRow({ firstAt: 100, lastExp: 50,
                                       isClient: false },
                                     { firstAt: 10, lastExp: 80,
                                       isClient: true });
    const mergedBack = declared.mergeRow({ firstAt: 10, lastExp: 80,
                                           isClient: true },
                                         { firstAt: 100, lastExp: 50,
                                           isClient: false });
    const blindFirst = declared.mergeRow({ firstAt: 0, lastExp: 90 },
                                         { firstAt: 40, lastExp: 20 });
    note(declared.keysResident === true &&
         merged.firstAt === 10 && merged.lastExp === 80 &&
         merged.isClient === true &&
         JSON.stringify(merged) === JSON.stringify(mergedBack) &&
         blindFirst.firstAt === 40 && blindFirst.lastExp === 90,
         'H1. on demand with its keys resident, and a mergeRow that keeps ' +
         'the earliest first sighting, the latest expiry and a client',
         JSON.stringify({ keysResident: declared.keysResident,
                          merged: merged, mergedBack: mergedBack,
                          blindFirst: blindFirst }));

    // H2.
    let writes = 0;
    realms.setPersistObserver(function (handle) {
      if (handle === HOLDERS) {
        writes++;
      }
    });
    asked.length = 0;
    inRealm(function () {
      stats.recordJwt({ jti: 'h-1', sub: '', username: 'frank', iat: 1,
                        exp: future, typ: 'Bearer' }, 'x.y.z',
                      { kind: 'access_token' });
    });
    const blind = holderReads();
    note(blind.length === 0 && writes === 1,
         'H2. a JWT for a holder not held writes the row blindly and reads ' +
         'nothing', JSON.stringify({ asked: blind, writes: writes }));

    // H2b. The case a `get()` would pay for: a holder whose key IS
    // resident but whose row this process does not hold. A key that is
    // not resident is answered absent by `get()` without a read, so
    // 'frank' alone cannot tell `peek()` from `get()`.
    asked.length = 0;
    writes = 0;
    inRealm(function () {
      stats.recordJwt({ jti: 'h-1b', sub: '', username: 'svc-app', iat: 1,
                        exp: future, typ: 'Bearer' }, 'x.y.z',
                      { kind: 'access_token' });
    });
    const residentBlind = holderReads();
    note(residentBlind.length === 0 && writes === 1,
         'H2b. a JWT for a holder whose key is resident and whose row is ' +
         'not held writes blindly and reads nothing',
         JSON.stringify({ asked: residentBlind, writes: writes }));

    // H3.
    asked.length = 0;
    writes = 0;
    await inRealm(function () {
      return stats.warmTokenHolders(['erin', 'nobody-here', '']);
    });
    const warmAsked = holderReads();
    inRealm(function () {
      stats.recordJwt({ jti: 'h-2', sub: '', username: 'erin', iat: 1,
                        exp: future, typ: 'Bearer' }, 'x.y.z',
                      { kind: 'access_token' });
    });
    const afterWarm = holderReads();
    note(warmAsked.length === 1 &&
         warmAsked[0] === HOLDERS + ' readMany:erin' &&
         afterWarm.length === 1 && writes === 0,
         'H3. a warmed holder is read in one batch, an unresident name not ' +
         'at all, and the next token inside its row writes nothing',
         JSON.stringify({ warm: warmAsked, after: afterWarm,
                          writes: writes }));

    // H4.
    asked.length = 0;
    const test = inRealm(function () {
      return stats.userKeyTest();
    });
    const known = typeof test === 'function' &&
      test('svc-app') === true && test('frank') === true &&
      test('nobody-at-all') === false;
    note(known && holderReads().length === 0,
         'H4. userKeyTest() answers from the resident keys with no read',
         JSON.stringify({ known: known, asked: holderReads() }));

    // H5.
    asked.length = 0;
    const counts = await inRealm(function () {
      return stats.userCountsAsync();
    });
    const countAsked = holderReads();
    note(counts.known >= 3 && counts.clients >= 1 &&
         countAsked.indexOf(HOLDERS + ' indexAsync:client') >= 0 &&
         countAsked.every(function (a) {
           return a.indexOf(' index:') < 0 && a.indexOf(' read:') < 0;
         }),
         'H5. userCountsAsync() counts every holder from the resident keys ' +
         'and the clients from the index, asked asynchronously',
         JSON.stringify({ counts: counts, asked: countAsked }));
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
  const out = path.join(os.tmpdir(), 'sts-thd-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|CONFIG_FILE$)/.test(key)) {
      env[key] = process.env[key];
    }
  });
  Object.assign(env, { THD_OUT: out, THD_ROOT: root, LOG_LEVEL: 'fatal',
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
  name: 'token_holders_on_demand',
  describe: 'the token holders on demand: keys resident, a blind write ' +
            'merged by the store, warm-ups in one batch and counts ' +
            'without a blocking read (#820)',
  run: run
};
