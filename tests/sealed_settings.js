// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: sealed_settings.js
//
// ===========================================================================
// A SECRET SETTING IS SEALED WHERE IT IS WRITTEN DOWN (#222).
//
// `persistence/sealed_settings.js` wraps a driver's four settings methods. In
// a CHILD PROCESS, for `data_key_rotation.js`'s reason: the keystore is the
// process's, and it is started here with a file key-encryption key named in
// the environment, which an in-process test must not touch. Asserted:
//
//   A. a secret setting saved for the service is sealed in what the driver
//      is handed — in the whole map and in the delta — and another setting
//      is not; loading opens it;
//   B. the same for a realm's overrides, under that realm's data key, in the
//      rows and in the delta's upserts; loading opens it;
//   C. a sealed value that does not open is dropped, not handed over;
//   D. where nothing durable seals (no key-encryption key), nothing is sealed;
//   E. the cluster's claim and counter keys are keyed digests once a key is
//      held (#222), and the plain digest where none is.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'sealed_settings',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  const ROOT = process.env.SS_ROOT;
  const OUT = process.env.SS_OUT;
  const DIR = process.env.SS_DIR;
  const fs = require('fs');
  const nodeCrypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  const SEALED = /^\$aes(gcm|siv)\$2\$/;

  // A key store that keeps what it is given.
  const rows = new Map();
  const keyStore = {
    loadKeys: function () {
      return Promise.resolve(Array.from(rows.entries()).map(function (p) {
        return { realm: p[0], material: p[1] };
      }));
    },
    loadKey: function (key) {
      return Promise.resolve(rows.has(key) ? rows.get(key) : null);
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
        return { material: rows.get(key) };
      });
    }
  };

  // A settings driver that keeps exactly what it is handed.
  function settingsDriver() {
    const held = { overrides: null, overridesDelta: null, realms: null,
                   realmsDelta: null };
    return {
      held: held,
      saveOverrides: function (map, delta) {
        held.overrides = map;
        held.overridesDelta = delta;
        return Promise.resolve();
      },
      loadOverrides: function () {
        return Promise.resolve(held.overrides);
      },
      saveRealms: function (rowsIn, delta) {
        held.realms = rowsIn;
        held.realmsDelta = delta;
        return Promise.resolve();
      },
      loadRealms: function () {
        return Promise.resolve(held.realms);
      }
    };
  }

  const kekFile = DIR + '/kek';
  fs.writeFileSync(kekFile, nodeCrypto.randomBytes(32).toString('base64'),
                   { mode: 0o600 });
  process.env.STS_MODE = 'product';
  process.env.STS_KEYS_SOURCE = 'persisted';
  process.env.STS_KEYS_KEK_PROVIDER = 'file';
  process.env.STS_KEYS_KEK_FILE = kekFile;

  (async function () {
    const keystore = require(ROOT + '/common/keystore');
    const crypto = require(ROOT + '/common/crypto');
    const sealedSettings = require(ROOT + '/persistence/sealed_settings');
    keystore.setStore(keyStore);
    await keystore.start();
    note(sealedSettings.secretSettingKeys().has('scim.digestPassword'),
         'scim.digestPassword is a secret setting that is saved');

    // ------------------------------------------------------------------ A
    const d = sealedSettings.wrap(settingsDriver());
    const live = { 'scim.digestPassword': 'hunter2', 'scim.maxResults': 50 };
    await d.saveOverrides(live, { set: live, cleared: [], live: live });
    const map = d.held.overrides;
    const set = d.held.overridesDelta.set;
    note(SEALED.test(map['scim.digestPassword']) &&
         SEALED.test(set['scim.digestPassword']) &&
         map['scim.digestPassword'].indexOf('hunter2') < 0,
         'A1. the secret setting is sealed in the map and in the delta',
         String(map['scim.digestPassword']).slice(0, 30));
    note(map['scim.maxResults'] === 50 && set['scim.maxResults'] === 50,
         'A2. another setting is written as it was');
    note(live['scim.digestPassword'] === 'hunter2',
         'A3. the caller\'s own map is not changed');
    const loaded = await d.loadOverrides();
    note(loaded['scim.digestPassword'] === 'hunter2' &&
         loaded['scim.maxResults'] === 50,
         'A4. loading opens it', JSON.stringify(loaded));

    // ------------------------------------------------------------------ B
    const row = { id: 'acme', name: 'Acme',
                  overrides: { 'scim.digestPassword': 'acme-pw' } };
    await d.saveRealms([row], { upserts: [{ row: row, name: true,
      description: false, set: { 'scim.digestPassword': 'acme-pw' },
      cleared: [] }], removed: [] });
    const savedRow = d.held.realms[0];
    const savedSet = d.held.realmsDelta.upserts[0].set;
    note(SEALED.test(savedRow.overrides['scim.digestPassword']) &&
         SEALED.test(savedSet['scim.digestPassword']) &&
         SEALED.test(d.held.realmsDelta.upserts[0].row.overrides[
           'scim.digestPassword']),
         'B1. a realm\'s secret override is sealed in the rows and the delta');
    const realmDek = crypto.dekIdOf(savedRow.overrides['scim.digestPassword']);
    const serviceDek = crypto.dekIdOf(map['scim.digestPassword']);
    note(realmDek && serviceDek && realmDek !== serviceDek,
         'B2. under the realm\'s own data key, not the service\'s');
    const realmsBack = await d.loadRealms();
    note(realmsBack[0].overrides['scim.digestPassword'] === 'acme-pw' &&
         row.overrides['scim.digestPassword'] === 'acme-pw',
         'B3. loading opens it, and the caller\'s row is not changed');

    // ------------------------------------------------------------------ C
    d.held.overrides = { 'scim.digestPassword':
      '$aesgcm$2$nosuchkey0000000$AAAA$AAAA$AAAA', 'scim.maxResults': 7 };
    const broken = await d.loadOverrides();
    note(!Object.prototype.hasOwnProperty.call(broken,
                                               'scim.digestPassword') &&
         broken['scim.maxResults'] === 7,
         'C1. a sealed value that does not open is dropped, not handed over',
         JSON.stringify(broken));

    // ------------------------------------------------------------------ E
    // The claim and counter keys are KEYED digests once a key is held, so a
    // username or an address in them is not recovered by hashing guesses.
    const claims = require(ROOT + '/cluster/cluster_claims');
    const counters = require(ROOT + '/cluster/cluster_counters');
    const unkeyed = nodeCrypto.createHash('sha256')
      .update('login\nalice').digest('base64url');
    const keyedClaim = claims.digestOf('login', 'alice');
    const keyedCounter = counters.digestOf('login', 'alice');
    note(keyedClaim !== unkeyed && keyedCounter !== unkeyed &&
         keyedClaim === claims.digestOf('login', 'alice') &&
         keyedClaim !== keyedCounter,
         'E1. claim and counter keys are keyed digests, stable, and ' +
         'different for the two stores');

    // ------------------------------------------------------------------ D
    keystore.reset();
    const plain = sealedSettings.sealMap({ 'scim.digestPassword': 'x' }, '');
    note(plain['scim.digestPassword'] === 'x',
         'D1. with no key-encryption key held, nothing is sealed');
    note(claims.digestOf('login', 'alice') === unkeyed,
         'D2. and a claim key is the plain digest, as every process ' +
         'without a key computes it');
  })().catch(function (e) {
    note(false, 'the child ran to the end', e && e.stack);
  }).then(function () {
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function run(t) {
  log.debug("Entering run().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-ss-'));
  const out = path.join(dir, 'findings.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', SS_ROOT: ROOT,
                                  SS_OUT: out, SS_DIR: dir }),
      encoding: 'utf8', timeout: 120000, cwd: ROOT
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
  name: 'sealed_settings',
  describe: 'a secret setting sealed where it is saved, for the service and ' +
            'for a realm, opened when loaded, dropped when it does not open, ' +
            'and left alone where nothing durable seals',
  run: run
};
