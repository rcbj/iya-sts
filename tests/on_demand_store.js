// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: on_demand_store.js
//
// ===========================================================================
// AN ON-DEMAND STORE IS A BOUNDED CACHE OVER THE STORE (#820, 2026-10-21).
//
// `realms.map({ onDemand })` is not read back whole at a start: with an
// active reader (`realms.setOnDemandReader()`, installed by
// `persistence_minted.js`) it holds a bounded set of rows and asks for the
// rest by key.
//
//   D1. a key not held is read from the store, answered, and then held;
//   D2. a key with a write not yet committed and not held — a delete not
//       written yet — reads as absent, and the store is not asked;
//   D3. past `maxEntries` the oldest held keys go, never a pending one;
//   D4. `lookup()` answers the index's rows and the held keys filed under
//       the index key, leaves out a pending delete, and holds what it read;
//   D5. with no active reader the store is the plain Map it always was:
//       nothing is asked, `onDemandLive()` is false, and nothing is dropped.
//
// In a child process: it installs a stand-in reader in `common/realms.js`.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'on_demand_store',
  level: process.env.LOG_LEVEL || 'info' });

// Runs in the child. Stringified, so it may use nothing from this file's scope.
function child() {
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  const OUT = process.env.ODS_OUT;
  const ROOT = process.env.ODS_ROOT;
  try {
    const realms = require(ROOT + '/common/realms');
    const stored = new Map([['far-1', { family: 'f', n: 1 }],
                            ['far-2', { family: 'f', n: 2 }],
                            ['gone', { family: 'f', n: 3 }]]);
    const pending = new Set();
    const asked = [];
    let active = true;
    realms.setOnDemandReader({
      active: function () {
        return active;
      },
      read: function (handle, realmId, key) {
        asked.push('read:' + key);
        return stored.has(key) ? { present: true, value: stored.get(key) }
          : { present: false };
      },
      byIndex: function (handle, realmId, indexKey) {
        asked.push('index:' + indexKey);
        return Array.from(stored.entries()).filter(function (e) {
          return e[1].family === indexKey;
        }).map(function (e) {
          return { key: e[0], value: e[1] };
        });
      },
      journalled: function (handle, realmId, key) {
        return pending.has(key);
      }
    });
    const store = realms.map({ persist: 'ods.test', onDemand: { maxEntries: 3 },
      indexBy: function (value) {
        return value && value.family ? [value.family] : [];
      } });

    const one = store.get('far-1');
    const heldAfter = store.realmMap().has('far-1');
    asked.length = 0;
    const again = store.get('far-1');
    note(one && one.n === 1 && heldAfter && again === one && !asked.length,
         'D1. a key not held is read from the store, answered, and held',
         JSON.stringify({ one: one, held: heldAfter, asked: asked }));

    pending.add('gone');
    asked.length = 0;
    note(store.get('gone') === undefined && store.has('gone') === false &&
         !asked.length,
         'D2. a pending key not held reads as absent; the store is not asked',
         JSON.stringify(asked));

    pending.add('p1');
    store.set('p1', { family: 'g', n: 10 });
    ['a', 'b', 'c', 'd'].forEach(function (k) {
      store.set(k, { family: 'h', n: k });
    });
    const held = Array.from(store.realmMap().keys());
    note(held.length <= 3 + 1 && held.indexOf('p1') >= 0 &&
         held.indexOf('d') >= 0 && held.indexOf('far-1') < 0,
         'D3. past maxEntries the oldest held keys go, never a pending one',
         JSON.stringify(held));

    asked.length = 0;
    const family = store.lookup('f').sort();
    note(family.join(',') === 'far-1,far-2' &&
         asked.indexOf('index:f') >= 0 && store.realmMap().has('far-2'),
         'D4. lookup() answers the index\'s rows, leaves out a pending ' +
         'delete, and holds what it read', JSON.stringify(family));

    active = false;
    const plain = realms.map({ persist: 'ods.plain', onDemand: { maxEntries: 1 } });
    asked.length = 0;
    plain.set('x', 1);
    plain.set('y', 2);
    note(plain.get('nobody') === undefined && !asked.length &&
         plain.size === 2 && plain.onDemandLive() === false &&
         store.onDemandLive() === false,
         'D5. with no active reader it is the plain Map it always was',
         JSON.stringify({ asked: asked, size: plain.size }));
  } catch (e) {
    note(false, 'the child threw', (e && e.stack) || e);
  }
  require('fs').writeFileSync(OUT, JSON.stringify(findings));
  process.exit(0);
}

function run(t) {
  log.debug("Entering run().");
  const root = path.join(__dirname, '..');
  const out = path.join(os.tmpdir(), 'sts-ods-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|CONFIG_FILE$)/.test(key)) {
      env[key] = process.env[key];
    }
  });
  Object.assign(env, { ODS_OUT: out, ODS_ROOT: root, LOG_LEVEL: 'fatal',
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
  name: 'on_demand_store',
  describe: 'an on-demand store is a bounded cache over the store (#820)',
  run: run
};
