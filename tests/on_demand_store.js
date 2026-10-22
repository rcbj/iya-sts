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
//       nothing is asked, `onDemandLive()` is false, and nothing is dropped;
//   D6. a key the store said is absent is remembered: asked once, not again
//       (#820 part 2) — a read that FAILED is not remembered;
//   D7. the handle's `forgetAbsent()` (what the appliers call for another
//       process's write) and a local `set()` each forget it;
//   D8. a KEY-RESIDENT store answers `has()` from its digests alone, with no
//       read, and `get()` reads only a digest it holds;
//   D9. its `size` is the count of digests; `set()` adds one, `delete()`
//       removes one and says it was there;
//   D10. a `get()` that finds a held digest's row gone takes the digest out;
//   D11. `warm()` reads the keys it does not hold in ONE batch, holds what
//        is there, remembers what is not, and skips a key already held;
//   D12. a key another process changed while the batch was reading is not
//        held from it (its answer may be the older one).
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
  (async function () {
    const realms = require(ROOT + '/common/realms');
    const stored = new Map([['far-1', { family: 'f', n: 1 }],
                            ['far-2', { family: 'f', n: 2 }],
                            ['gone', { family: 'f', n: 3 }]]);
    const pending = new Set();
    const asked = [];
    let active = true;
    let failing = false;
    let duringRead = null;
    realms.setOnDemandReader({
      active: function () {
        return active;
      },
      read: function (handle, realmId, key) {
        asked.push('read:' + key);
        if (failing) {
          return null;
        }
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
      readMany: function (handle, realmId, keys) {
        asked.push('many:' + keys.slice().sort().join('+'));
        const out = new Map();
        keys.forEach(function (k) {
          if (stored.has(k)) {
            out.set(k, stored.get(k));
          }
        });
        return new Promise(function (resolve) {
          setImmediate(function () {
            if (duringRead) {
              duringRead();
            }
            resolve(out);
          });
        });
      },
      digestOf: function (handle, realmId, key) {
        return 'd:' + key;
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

    asked.length = 0;
    const first = store.get('never');
    const second = store.has('never');
    note(first === undefined && second === false &&
         asked.filter(function (a) {
           return a === 'read:never';
         }).length === 1,
         'D6. a key the store said is absent is asked for once, not again',
         JSON.stringify(asked));
    failing = true;
    asked.length = 0;
    store.get('flaky');
    store.get('flaky');
    failing = false;
    note(asked.filter(function (a) {
      return a === 'read:flaky';
    }).length === 2,
         'D6. a read that failed is not remembered as absent',
         JSON.stringify(asked));

    stored.set('never', { family: 'f', n: 9 });
    realms.handleFor('ods.test').forgetAbsent('default', 'never');
    asked.length = 0;
    const now = store.get('never');
    note(now && now.n === 9 && asked.indexOf('read:never') >= 0,
         'D7. forgetAbsent() — another process wrote it — makes it read again',
         JSON.stringify({ now: now, asked: asked }));
    store.get('later');
    store.set('later', { family: 'z', n: 1 });
    store.realmMap().delete('later');
    asked.length = 0;
    store.get('later');
    note(asked.indexOf('read:later') >= 0,
         'D7. a local set() forgets that it was absent',
         JSON.stringify(asked));

    const resident = realms.map({ persist: 'ods.resident',
      onDemand: { maxEntries: 3, keysResident: true } });
    const rHandle = realms.handleFor('ods.resident');
    rHandle.residentAdd('default', 'd:far-1');
    rHandle.residentAdd('default', 'd:gone-row');
    asked.length = 0;
    note(resident.has('far-1') === true && resident.has('nobody') === false &&
         !asked.length,
         'D8. a key-resident store answers has() from its digests, unread',
         JSON.stringify(asked));
    const got = resident.get('far-1');
    const none = resident.get('nobody');
    note(got && got.n === 1 && none === undefined &&
         asked.join(',') === 'read:far-1',
         'D8. get() reads only a digest it holds', JSON.stringify(asked));
    const before = resident.size;
    resident.set('new-1', { n: 5 });
    const afterSet = resident.size;
    const said = resident.delete('gone-row');
    note(before === 2 && afterSet === 3 && said === true &&
         resident.size === 2 && resident.has('gone-row') === false,
         'D9. size counts digests; set() adds one, delete() removes one',
         JSON.stringify({ before: before, afterSet: afterSet, said: said,
                          size: resident.size }));
    rHandle.residentAdd('default', 'd:vanished');
    asked.length = 0;
    const vanished = resident.get('vanished');
    note(vanished === undefined && asked.indexOf('read:vanished') >= 0 &&
         resident.has('vanished') === false,
         'D10. a get() that finds the row gone takes the digest out',
         JSON.stringify(asked));

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

    active = true;
    const warmed = realms.map({ persist: 'ods.warm',
                                onDemand: { maxEntries: 10 } });
    stored.set('w-1', { n: 1 });
    stored.set('w-2', { n: 2 });
    warmed.set('w-held', { n: 0 });
    asked.length = 0;
    await warmed.warm(['w-1', 'w-2', 'w-none', 'w-held']);
    const batch = asked.slice();
    asked.length = 0;
    const got1 = warmed.get('w-1');
    const gotNone = warmed.get('w-none');
    note(batch.join(',') === 'many:w-1+w-2+w-none' && got1 && got1.n === 1 &&
         gotNone === undefined && !asked.length,
         'D11. warm() reads the keys not held in one batch, holds what is ' +
         'there and remembers what is not', JSON.stringify({ batch: batch,
           after: asked }));

    stored.set('w-3', { n: 3, old: true });
    duringRead = function () {
      stored.set('w-3', { n: 33 });
      realms.handleFor('ods.warm').forgetAbsent('default', 'w-3');
    };
    await warmed.warm(['w-3']);
    duringRead = null;
    asked.length = 0;
    const got3 = warmed.get('w-3');
    note(got3 && got3.n === 33 && asked.indexOf('read:w-3') >= 0,
         'D12. a key changed by another process while the batch read is not ' +
         'held from it, and is read again', JSON.stringify({ got3: got3,
           asked: asked }));
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
