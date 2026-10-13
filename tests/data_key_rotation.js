// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: data_key_rotation.js
//
// ===========================================================================
// THE DATA ENCRYPTION KEY LIFECYCLE (#391 P2): ROTATE, RE-SEAL, DESTROY, AND A
// ROTATED KEY-ENCRYPTION KEY.
//
// In a CHILD PROCESS, because the keystore's state is the process's and four
// sections restart it against a store this file holds. The store is a fake
// with the two halves the lifecycle needs from postgres: `mergeKeys`/`loadKey`
// (so a data-key row is MERGED under its lock, the way two nodes write one)
// and `countSealed`/`resealSealed` over a table of sealed values. Asserted:
//
//   A. a rotation publishes a successor that is NOT used until its lead has
//      passed, and the key it replaces is then superseded and still opens;
//   B. `reseal()` moves a value to the current key and leaves a current one;
//   C. the re-encryption job re-seals the table, counts nothing left, and
//      destroys the superseded key only once it has been superseded for
//      `keys.dataKeyRetireAfterDays` — never on the same pass otherwise;
//   D. a destroyed key stays destroyed across a restart, and against a stale
//      copy of its row in either direction of the merge;
//   E. the schedule: `rotationDue()` and the daily job after the interval,
//      none before it, and none at an interval of 0;
//   F. a ROTATED key-encryption key: a start with only the new key refuses
//      (STS-KEYS-0091), a start with the previous one beside it re-wraps
//      every data key, and the next start needs only the new key;
//   G. where data keys are derived per run, the jobs are off and a rotation
//      by hand is refused STS-KEYS-0100;
//   H. a keyed digest is made under a stored digest key, so it is the same
//      after the KEK is rotated, and that key is never rotated.
//   J. (#391 P5) the count job records every key's values on the key, the
//      row carries them across a restart and its merge keeps the newer
//      count; a KEK read into the process is not rotated from here
//      (STS-KEYS-0104); a store that cannot count turns the job off.
//   I. `keys.directoryCipher=aes-256-siv` seals the directory's classes with
//      AES-256-SIV and nothing else; changing it back makes the class due a
//      rotation, and the re-encryption moves the value to AES-256-GCM.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'data_key_rotation',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  const ROOT = process.env.DK_ROOT;
  const OUT = process.env.DK_OUT;
  const DIR = process.env.DK_DIR;
  const fs = require('fs');
  const nodeCrypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  function sleep(ms) {
    return new Promise(function (resolve) { setTimeout(resolve, ms); });
  }
  const DAY = 86400000;
  let shift = 0;
  const realNow = Date.now;
  Date.now = function () {
    return realNow() + shift;
  };

  // THE STORE: key rows, merged under a "lock", and a table of sealed values
  // standing for sts_minted.
  const rows = new Map();
  const table = new Map();
  const SEALED = /\$aes(?:gcm|siv)\$2\$[A-Za-z0-9_.-]+\$[A-Za-z0-9+/=]*\$[A-Za-z0-9+/=]*\$[A-Za-z0-9+/=]*/g;
  const store = {
    loadKeys: function () {
      return Promise.resolve(Array.from(rows.entries()).map(function (p) {
        return { realm: p[0], material: p[1] };
      }));
    },
    loadKey: function (key) {
      return Promise.resolve(rows.has(key) ? { realm: key,
                                               material: rows.get(key) }
        : null);
    },
    saveKeys: function (key, text) {
      rows.set(key, text);
      return Promise.resolve();
    },
    deleteKeys: function (key) {
      rows.delete(key);
      return Promise.resolve();
    },
    mergeKeys: function (key, text, merge) {
      return Promise.resolve().then(function () {
        const current = rows.has(key) ? rows.get(key) : null;
        const next = current === null ? text : merge(current);
        if (next !== null && next !== undefined) {
          rows.set(key, next);
        }
        return { material: rows.get(key), merged: current !== null };
      });
    },
    countSealed: function (ids) {
      const out = {};
      ids.forEach(function (id) {
        out[id] = 0;
        table.forEach(function (v) {
          if (v.indexOf('$2$' + id + '$') >= 0) {
            out[id] += 1;
          }
        });
      });
      return Promise.resolve(out);
    },
    // One pass, every key: postgres's `countAllSealed()` (#391 P5).
    countAllSealed: function () {
      const out = {};
      table.forEach(function (v) {
        (v.match(SEALED) || []).forEach(function (one) {
          const id = one.split('$')[3];
          out[id] = (out[id] || 0) + 1;
        });
      });
      return Promise.resolve(out);
    },
    resealSealed: function (ids, reseal) {
      let n = 0;
      table.forEach(function (v, k) {
        let changed = false;
        const next = v.replace(SEALED, function (one) {
          const id = one.split('$')[3];
          if (ids.indexOf(id) < 0) {
            return one;
          }
          const r = reseal(one);
          if (r) {
            changed = true;
            return r;
          }
          return one;
        });
        if (changed) {
          table.set(k, next);
          n += 1;
        }
      });
      return Promise.resolve({ minted: n, entries: 0, secrets: 0, skipped: 0,
                               changed: [] });
    }
  };

  function writeKek(name) {
    const file = DIR + '/' + name;
    fs.writeFileSync(file, nodeCrypto.randomBytes(32).toString('base64'),
                     { mode: 0o600 });
    return file;
  }
  const kek1 = writeKek('kek1');
  const kek2 = writeKek('kek2');
  process.env.STS_KEYS_SOURCE = 'persisted';
  process.env.STS_KEYS_KEK_PROVIDER = 'file';
  process.env.STS_KEYS_KEK_FILE = kek1;
  process.env.STS_KEYS_DATA_KEY_ACTIVATION_LEAD_SECONDS = '1';

  (async function () {
    const keystore = require(ROOT + '/common/keystore');
    const rotation = require(ROOT + '/common/data_key_rotation');
    const audited = [];
    function job(nowShift) {
      const deps = rotation.DataKeyRotation.defaultDeps();
      deps.audit = function () {
        return { record: function (row) { audited.push(row); } };
      };
      deps.now = function () { return Date.now() + (nowShift || 0); };
      return new rotation.DataKeyRotation(deps);
    }
    async function restart() {
      await keystore.settleAll();
      keystore.reset();
      keystore.setStore(store);
      await keystore.start();
    }
    keystore.setStore(store);
    await keystore.start();
    note(keystore.deksStored(), 'data keys are stored with a durable key');
    const digest1 = keystore.keyedDigest('test', 'carol');
    note(typeof digest1 === 'string' && digest1.length > 20 &&
         /"cls":"keyed-digest"/.test(rows.get('dek:service:default') || ''),
         'H1. a keyed digest is made under a STORED digest key');

    // ---------------------------------------------------------------- A
    const v1 = keystore.seal('alpha', 'minted-rows', undefined,
                             { realm: '' });
    const old = require(ROOT + '/common/crypto').dekIdOf(v1);
    table.set('a', v1);
    await keystore.settleDeks();
    const done = keystore.rotateDeks({ realm: '', cls: 'minted-rows',
                                       reason: 'test' });
    note(done.ok && done.rotated.length === 1,
         'A1. a rotation of one slot makes one successor',
         JSON.stringify(done));
    const fresh = done.rotated[0].id;
    const during = require(ROOT + '/common/crypto')
      .dekIdOf(keystore.seal('beta', 'minted-rows', undefined, { realm: '' }));
    note(during === old, 'A2. within its lead the successor seals nothing',
         during + ' vs ' + old);
    await sleep(1200);
    const after = keystore.seal('gamma', 'minted-rows', undefined,
                                { realm: '' });
    note(require(ROOT + '/common/crypto').dekIdOf(after) === fresh,
         'A3. after its lead the successor seals', after.slice(0, 40));
    table.set('c', after);
    note(keystore.open(v1, 'minted-rows') === 'alpha',
         'A4. the superseded key still opens what it sealed');
    const sup = keystore.supersededDeks().map(function (d) { return d.id; });
    note(sup.indexOf(old) >= 0 && sup.indexOf(fresh) < 0,
         'A5. the replaced key is superseded and the successor is not',
         JSON.stringify(sup));

    // ---------------------------------------------------------------- B
    const moved = keystore.reseal(v1);
    note(moved && require(ROOT + '/common/crypto').dekIdOf(moved) === fresh &&
         keystore.open(moved, 'minted-rows') === 'alpha',
         'B1. reseal() moves a value to the current key, same plaintext');
    note(keystore.reseal(after) === null,
         'B2. and leaves a value already under it alone');

    // ---------------------------------------------------------------- C
    const pass1 = await job(0).reencrypt({ trigger: 'test' });
    note(pass1.resealed === 1 && pass1.remaining === 0 &&
         pass1.destroyed === 0,
         'C1. a pass re-seals the table and destroys nothing before ' +
         'keys.dataKeyRetireAfterDays', JSON.stringify(pass1));
    note(table.get('a').indexOf('$' + fresh + '$') > 0,
         'C2. the stored value now names the current key');
    const pass2 = await job(8 * DAY).reencrypt({ trigger: 'test' });
    note(pass2.destroyed === 1,
         'C3. once superseded long enough and nothing names it, it is ' +
         'destroyed', JSON.stringify(pass2));
    note(audited.some(function (r) {
      return r.action === 'keys.data-key-destroy';
    }) && audited.some(function (r) {
      return r.action === 'keys.data-key-reencrypt';
    }), 'C4. both acts are audited, one row each');
    const row = rows.get('dek:service:default') || '';
    note(/"status":"destroyed"/.test(row) && row.indexOf(old) >= 0,
         'C5. the destruction is written to the data-key row');
    note(keystore.open(v1, 'minted-rows') === null,
         'C6. a value still under the destroyed key no longer opens');
    const stale = keystore.seal('delta', 'minted-rows', undefined,
                                { realm: '' });
    table.set('d', stale);

    // ---------------------------------------------------------------- D
    await restart();
    note(keystore.open(table.get('a'), 'minted-rows') === 'alpha' &&
         keystore.open(table.get('d'), 'minted-rows') === 'delta',
         'D1. after a restart the re-sealed values open');
    note(!keystore.dataKeys().some(function (d) {
      return d.id === old && d.held;
    }), 'D2. and the destroyed key is not held again');
    // A STALE COPY OF THE ROW (one written before the destruction) comes
    // back under a write of ours: the destruction must win.
    const destroyedRow = rows.get('dek:service:default');
    const staleRow = JSON.parse(destroyedRow);
    staleRow.deks.forEach(function (d) {
      if (d.id === old) {
        d.status = 'superseded';
        d.wrapped = '$dekwrap$1$AAAA$AAAA$AAAA';
      }
    });
    rows.set('dek:service:default', JSON.stringify(staleRow));
    // A first value of a new class makes a key, which writes the row.
    keystore.seal('epsilon', 'general', undefined, { realm: '' });
    await keystore.settleDeks();
    note(/"status":"destroyed"/.test(rows.get('dek:service:default')),
         'D3. a stale copy merged with ours keeps the destruction');

    // ---------------------------------------------------------------- E
    note(keystore.rotationDue(365).length === 0,
         'E1. nothing is due a rotation the day it was made');
    note(keystore.rotationDue(0).length === 0,
         'E2. and nothing at an interval of 0');
    shift = 400 * DAY;
    const due = keystore.rotationDue(365);
    note(due.length >= 1, 'E3. a year on, every slot is due',
         JSON.stringify(due));
    const ran = job(0).rotateDue({ trigger: 'test' });
    note(ran.rotated === due.length,
         'E4. and the daily job rotates exactly those', JSON.stringify(ran));
    note(keystore.rotationDue(365).length === 0,
         'E5. a slot with a successor waiting is not due again');
    shift = 0;

    // ---------------------------------------------------------------- F
    await keystore.settleAll();
    process.env.STS_KEYS_KEK_FILE = kek2;
    let refused = '';
    try {
      await restart();
    } catch (e) {
      refused = (e && e.message) || String(e);
    }
    note(/STS-KEYS-0091/.test(refused),
         'F1. a start with only a NEW key-encryption key refuses', refused);
    process.env.STS_PREVIOUS_KEK_PROVIDER = 'file';
    process.env.STS_PREVIOUS_KEK_REF = kek1;
    await restart();
    await keystore.settleAll();
    note(keystore.open(table.get('a'), 'minted-rows') === 'alpha',
         'F2. with the previous key beside it, every value opens');
    delete process.env.STS_PREVIOUS_KEK_PROVIDER;
    delete process.env.STS_PREVIOUS_KEK_REF;
    await restart();
    note(keystore.open(table.get('d'), 'minted-rows') === 'delta',
         'F3. the data keys were re-wrapped: the next start needs only ' +
         'the new key');

    // ---------------------------------------------------------------- H
    note(keystore.keyedDigest('test', 'carol') === digest1,
         'H2. a keyed digest is the same after the KEK was rotated');
    const notRotated = keystore.rotateDeks({ realm: '', cls: 'keyed-digest',
                                             reason: 'test' });
    note(notRotated.ok && notRotated.rotated.length === 0,
         'H3. the digest key is never rotated', JSON.stringify(notRotated));

    // ---------------------------------------------------------------- I
    // THE DIRECTORY CIPHER: AES-256-SIV for the classes stored on directory
    // entries, and nothing else; a change of setting is a rotation.
    process.env.STS_KEYS_DIRECTORY_CIPHER = 'aes-256-siv';
    const sivValue = keystore.seal('JBSWY3DPEHPK3PXP', 'totp-secret',
                                   undefined, { realm: '' });
    const notDir = keystore.seal('epsilon2', 'minted-rows', undefined,
                                 { realm: '' });
    table.set('t', sivValue);
    note(/^\$aessiv\$2\$/.test(sivValue) && /^\$aesgcm\$2\$/.test(notDir),
         'I1. a directory class is sealed with AES-256-SIV, other data with ' +
         'AES-256-GCM', sivValue.slice(0, 30) + ' / ' + notDir.slice(0, 30));
    note(keystore.open(sivValue, 'totp-secret') === 'JBSWY3DPEHPK3PXP',
         'I2. and opens');
    const twice = keystore.seal('JBSWY3DPEHPK3PXP', 'totp-secret', undefined,
                                { realm: '' });
    note(twice !== sivValue,
         'I3. the same value sealed twice is two ciphertexts (the nonce)');
    note(keystore.dataKeys().some(function (d) {
      return d.cls === 'totp-secret' && d.alg === 'aes-256-siv';
    }), 'I4. the data key says its cipher');
    await keystore.settleDeks();
    process.env.STS_KEYS_DIRECTORY_CIPHER = 'aes-256-gcm';
    const mismatch = keystore.rotationDue(365).some(function (d) {
      return d.cls === 'totp-secret';
    });
    note(mismatch, 'I5. a changed setting makes the class due a rotation');
    keystore.rotateDeks({ realm: '', cls: 'totp-secret', reason: 'test' });
    await sleep(1200);
    const back = await job(8 * DAY).reencrypt({ trigger: 'test' });
    note(/^\$aesgcm\$2\$/.test(table.get('t')) &&
         keystore.open(table.get('t'), 'totp-secret') === 'JBSWY3DPEHPK3PXP',
         'I6. and the re-encryption moves the value to AES-256-GCM',
         JSON.stringify(back));
    delete process.env.STS_KEYS_DIRECTORY_CIPHER;

    // ---------------------------------------------------------------- J
    // WHAT IS SEALED UNDER EACH KEY, COUNTED (#391 P5).
    await keystore.settleDeks();
    const expected = {};
    table.forEach(function (v) {
      (v.match(SEALED) || []).forEach(function (one) {
        const id = one.split('$')[3];
        expected[id] = (expected[id] || 0) + 1;
      });
    });
    const tally = await job().countAll({ trigger: 'test' });
    const stored = keystore.dataKeys().filter(function (d) {
      return !d.derived && d.status !== 'destroyed';
    });
    note(tally.keys === stored.length && stored.every(function (d) {
      return d.values === (expected[d.id] || 0) && d.countedAt > 0;
    }), 'J1. the count job records every stored key\'s values, 0 for a ' +
        'key nothing is sealed under', JSON.stringify({ tally: tally,
        expected: expected }));
    await keystore.settleDeks();
    note(/"values":\d+,"countedAt":\d+/.test(rows.get('dek:service:default') ||
                                            ''),
         'J2. and the counts are written on the keys\' row');
    await restart();
    note(keystore.dataKeys().filter(function (d) {
      return !d.derived && d.status !== 'destroyed';
    }).every(function (d) {
      return d.values === (expected[d.id] || 0);
    }), 'J3. a restart reads them back from the row');
    // A newer count in the store, from another node, is kept when this one
    // writes the row with an older one.
    const rowNow = JSON.parse(rows.get('dek:service:default'));
    const target = rowNow.deks.filter(function (d) {
      return d.status !== 'destroyed' && d.countedAt;
    })[0];
    target.values = 4242;
    target.countedAt = Date.now() + 10 * DAY;
    rows.set('dek:service:default', JSON.stringify(rowNow));
    const other = rowNow.deks.filter(function (d) {
      return d.id !== target.id && d.status !== 'destroyed';
    })[0];
    const one = {};
    one[other.id] = 7;
    keystore.recordCounts(one, {});
    await keystore.settleDeks();
    const merged = JSON.parse(rows.get('dek:service:default')).deks;
    note(merged.some(function (d) {
      return d.id === target.id && d.values === 4242;
    }) && merged.some(function (d) {
      return d.id === other.id && d.values === 7;
    }), 'J4. the row\'s merge keeps the newer count of each key',
         JSON.stringify(merged.map(function (d) {
           return [d.id, d.values, d.countedAt];
         })));
    const kekAsk = job().requestKekRotation({ requestedBy: 'test' });
    note(!kekAsk.ok && kekAsk.errorCode === 'STS-KEYS-0104' &&
         /previousKek/.test(kekAsk.why),
         'J5. a key-encryption key read into the process is not rotated ' +
         'from here (STS-KEYS-0104), and the refusal says how',
         JSON.stringify(kekAsk));
    const noCount = rotation.DataKeyRotation.defaultDeps();
    noCount.keystore = function () {
      return Object.assign({}, keystore,
                           { sealedStore: function () { return null; } });
    };
    note(/PostgreSQL/.test(new rotation.DataKeyRotation(noCount)
      .countOffReason()),
         'J6. where the store cannot count, the count job is off and says ' +
         'why');

    // ---------------------------------------------------------------- G
    const deps = rotation.DataKeyRotation.defaultDeps();
    deps.keystore = function () {
      return { deksStored: function () { return false; },
               dataKeys: function () { return []; } };
    };
    const derived = new rotation.DataKeyRotation(deps);
    note(/derived per run/.test(derived.offReason()),
         'G1. where data keys are derived the jobs are off and say why');
    const asked = derived.requestRotation({});
    note(!asked.ok && asked.errorCode === 'STS-KEYS-0100',
         'G2. and a rotation by hand is refused STS-KEYS-0100',
         JSON.stringify(asked));
  })().catch(function (e) {
    note(false, 'the child ran to the end', e && e.stack);
  }).then(function () {
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function run(t) {
  log.debug("Entering run().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-dek-'));
  const out = path.join(dir, 'findings.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', DK_ROOT: ROOT,
                                  DK_OUT: out, DK_DIR: dir }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (t.check(Array.isArray(findings), 'the child process reported its ' +
                                       'findings',
              'exit ' + result.status + ' ' +
              String(result.stderr || '').slice(-1500))) {
    findings.forEach(function (one) {
      t.check(one.ok, one.what, one.detail);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'data_key_rotation',
  describe: 'the data encryption key lifecycle: rotation with a lead, ' +
            're-sealing, destruction, a rotated key-encryption key, and the ' +
            'jobs off where data keys are derived',
  run: run
};
