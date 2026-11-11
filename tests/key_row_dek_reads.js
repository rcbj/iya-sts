// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: key_row_dek_reads.js
//
// ===========================================================================
// A KEY-ROW WRITE READS THE DATA-KEY ROWS, NOT THE WHOLE KEY TABLE
// (2026-11-11).
//
// `keystore.refreshDekRows()` runs before every key-set and certificate-
// authority write where the store merges (`writeAfterDeks()`), and it read
// the whole of `sts_keys` — every realm's key set and hierarchy — to keep the
// `dek:` rows. In fuzz run 16's single-node stack (165 realms with a
// hierarchy, three rebuilt every twenty seconds) a builder's own writes
// queued behind that read, and the change-log pull that waits for them
// (`applyStoredChange()`'s `afterOurWrite`) spent 2-26 s on one "keys" row:
// STS-STORE-0039 and STS-WORKER-0027. Measured against PostgreSQL 18 with a
// 71 MB `sts_keys` of 500 rows: the whole table 61 ms median, four at once
// 303 ms; the data-key rows alone 1 ms. And in process, with the whole-table
// read costing 60 ms, the builder's apply during its own write took 85 ms;
// with it free, 25 ms.
//
// What this file holds:
//   A. a certificate-authority write through a store that offers
//      `loadDekRows()` reads the data-key rows through it and never calls
//      `loadKeys()`, and a data key ANOTHER process made is still adopted
//      from that read (so a row sealed under it opens);
//   B. a store with no `loadDekRows()` still works, through `loadKeys()`,
//      and keeps only the `dek:` rows of what it answers;
//   C. the postgres driver's `loadDekRows()` sends one statement selecting
//      by the `dek:` prefix and answers its rows; the tiered driver routes
//      it to the global tier with the other key methods.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const nodeCrypto = require('crypto');

const storeDouble = require('./tools/store_double');

const log = require('bunyan').createLogger({
  name: 'key_row_dek_reads', level: process.env.LOG_LEVEL || 'info' });

const COMMON = path.join(__dirname, '..', 'common');

const QUIET = { debug: function () {}, info: function () {},
                warn: function () {}, error: function () {} };

// A fresh copy of the keystore, with the cached original put back, so this
// file's "processes" are module instances (cluster_key_pki_agreement.js's
// arrangement).
function freshKeystore() {
  log.debug("Entering freshKeystore().");
  const file = require.resolve(path.join(COMMON, 'keystore'));
  const saved = require.cache[file];
  delete require.cache[file];
  const out = require(file);
  if (saved) {
    require.cache[file] = saved;
  } else {
    delete require.cache[file];
  }
  log.debug("Leaving freshKeystore().");
  return out;
}

// One store two instances share. `withDekRows` decides whether it offers
// the narrow read; `calls` counts each read.
function sharedStore(withDekRows, calls) {
  log.debug("Entering sharedStore().");
  const rows = new Map();
  const locks = new Map();
  const store = {
    rows: rows,
    loadKeys: function () {
      log.debug("Entering loadKeys().");
      calls.loadKeys += 1;
      log.debug("Leaving loadKeys().");
      return Promise.resolve(Array.from(rows.entries()).map(function (p) {
        return { realm: p[0], material: p[1] };
      }));
    },
    saveKeys: function (realm, material) {
      log.debug("Entering saveKeys().");
      rows.set(realm, material);
      log.debug("Leaving saveKeys().");
      return Promise.resolve();
    },
    deleteKeys: function (realm) {
      log.debug("Entering deleteKeys().");
      rows.delete(realm);
      log.debug("Leaving deleteKeys().");
      return Promise.resolve();
    },
    loadKey: function (realm) {
      log.debug("Entering loadKey().");
      log.debug("Leaving loadKey().");
      return Promise.resolve(rows.has(realm) ? rows.get(realm) : null);
    },
    mergeKeys: function (realm, cipher, merge) {
      log.debug("Entering mergeKeys().");
      const ahead = locks.get(realm) || Promise.resolve();
      const run = ahead.then(function () {
        const current = rows.has(realm) ? rows.get(realm) : null;
        const next = merge(current);
        if (!next || next === current) {
          return { written: false, inserted: false, material: current };
        }
        rows.set(realm, next);
        return { written: true, inserted: current === null, material: next };
      });
      locks.set(realm, run.then(function () {
        return null;
      }, function (e) {
        log.debug("Caught in mergeKeys(): " + ((e && e.message) || e));
        return null;
      }));
      log.debug("Leaving mergeKeys().");
      return run;
    },
    hierarchyAdopted: function () {}
  };
  if (withDekRows) {
    store.loadDekRows = function () {
      log.debug("Entering loadDekRows().");
      calls.loadDekRows += 1;
      log.debug("Leaving loadDekRows().");
      return Promise.resolve(Array.from(rows.entries()).filter(function (p) {
        return p[0].indexOf('dek:') === 0;
      }).map(function (p) {
        return { realm: p[0], material: p[1] };
      }));
    };
  }
  log.debug("Leaving sharedStore().");
  return store;
}

function seedRow(scope, serial) {
  log.debug("Entering seedRow().");
  log.debug("Leaving seedRow().");
  return {
    version: 2, scope: scope,
    intermediate: { serialHex: '01', certificatePem: 'I1' },
    issuing: { jose: { serialHex: '02', certificatePem: 'J1' } },
    revoked: { jose: [] }, crlNumbers: { jose: 1 },
    issuedKeyPairs: [{ serialHex: serial, useCase: 'jose',
      notAfter: new Date(Date.now() + 86400000).toISOString() }]
  };
}

async function section(t, withDekRows) {
  log.debug("Entering section().");
  const label = withDekRows ? 'A' : 'B';
  t.log.info('=== ' + label + '. a hierarchy write through a store ' +
             (withDekRows ? 'that offers' : 'with no') + ' loadDekRows() ===');
  const calls = { loadKeys: 0, loadDekRows: 0 };
  const store = sharedStore(withDekRows, calls);
  const scope = 'dek-reads-' + nodeCrypto.randomBytes(3).toString('hex');
  const a = freshKeystore();
  a.setStore(store);
  await a.start();
  const b = freshKeystore();
  b.setStore(store);
  await b.start();
  // ROWS THAT ARE NOT DATA KEYS, standing for every realm's key set and
  // hierarchy: a read that brought them back is the cost this file is for.
  // Added after both starts, which read every row and would refuse these.
  for (let i = 0; i < 20; i++) {
    store.rows.set('filler-' + i, 'x'.repeat(1000));
  }
  const startReads = calls.loadKeys;
  calls.loadDekRows = 0;
  // A makes the scope's data key NOW, after B started, and seals the row
  // under it: B can open it only by reading the data-key rows again.
  a.attachPki(scope, seedRow(scope, 'a1'));
  await a.settleAll();
  const adopted = await b.applyStoredChange('pki:' + scope);
  t.check(!!adopted && adopted.adopted === true && !!b.pkiFor(scope),
          'B opens the row A sealed under a data key B did not hold, ' +
          'having read the data-key rows again', JSON.stringify(adopted));
  const rowB = JSON.parse(JSON.stringify(b.pkiFor(scope) ||
                                         seedRow(scope, 'a1')));
  rowB.issuedKeyPairs.push({ serialHex: 'b2', useCase: 'jose',
    notAfter: new Date(Date.now() + 86400000).toISOString() });
  b.attachPki(scope, rowB);
  await b.settleAll();
  if (withDekRows) {
    t.check(calls.loadDekRows >= 1,
            'the write read the data-key rows through loadDekRows()',
            JSON.stringify(calls));
    t.equal(calls.loadKeys - startReads, 0,
            'AND NEVER THE WHOLE KEY TABLE: loadKeys() is not called by a ' +
            'key-row write once the store offers the narrow read');
  } else {
    t.check(calls.loadKeys - startReads >= 1,
            'a store with no loadDekRows() is read through loadKeys(), as ' +
            'before', JSON.stringify(calls));
  }
  // A, which did not write B's change, takes it.
  await a.applyStoredChange('pki:' + scope);
  const held = a.pkiFor(scope);
  t.check(!!held && held.issuedKeyPairs.some(function (one) {
    return one.serialHex === 'b2';
  }) && held.issuedKeyPairs.some(function (one) {
    return one.serialHex === 'a1';
  }), 'both processes\' issued records are in the row A now holds',
  JSON.stringify(held && held.issuedKeyPairs));
  log.debug("Leaving section().");
}

// The postgres driver against a `pg` that records statements.
async function driverSection(t) {
  log.debug("Entering driverSection().");
  t.log.info('=== C. the postgres driver selects the data-key rows by ' +
             'prefix ===');
  const seen = [];
  function reply(sql) {
    seen.push(String(sql));
    if (/FROM sts_keys WHERE realm LIKE 'dek:%'/.test(String(sql))) {
      return Promise.resolve({ rows: [{ realm: 'dek:one', material: 'm1' }],
                               rowCount: 1 });
    }
    return Promise.resolve({ rows: [], rowCount: 0 });
  }
  function FakeClient() {}
  FakeClient.prototype.query = reply;
  FakeClient.prototype.release = function () {};
  FakeClient.prototype.on = function () {};
  FakeClient.prototype.removeListener = function () {};
  FakeClient.prototype.connect = function () {
    return Promise.resolve();
  };
  FakeClient.prototype.end = function () {
    return Promise.resolve();
  };
  function FakePool() {}
  FakePool.prototype.on = function () {};
  FakePool.prototype.connect = function () {
    return Promise.resolve(new FakeClient());
  };
  FakePool.prototype.query = reply;
  FakePool.prototype.end = function () {
    return Promise.resolve();
  };
  const restore = storeDouble.install({ Pool: FakePool, Client: FakeClient });
  let driver;
  try {
    driver = require('../persistence/persistence_postgres').create({
      url: 'postgres://sts_app@localhost:5432/sts', log: QUIET });
  } finally {
    restore();
  }
  t.check(typeof driver.loadDekRows === 'function',
          'the postgres driver offers loadDekRows()');
  const answer = await driver.loadDekRows();
  const sent = seen.filter(function (sql) {
    return /sts_keys/.test(sql);
  });
  t.equal(sent.length, 1, 'one statement');
  t.check(/^SELECT realm, material FROM sts_keys WHERE realm LIKE 'dek:%'$/
            .test(sent[0] || ''),
          'selecting by the dek: prefix, so no other row\'s material leaves ' +
          'the server', sent[0]);
  t.equal(JSON.stringify(answer),
          JSON.stringify([{ realm: 'dek:one', material: 'm1' }]),
          'and it answers the rows in loadKeys()\' shape');
  const tiered = require('../persistence/persistence_tiered');
  t.check(tiered.GLOBAL_METHODS.indexOf('loadDekRows') >= 0,
          'the tiered driver sends it to the global tier, with the key rows');
  log.debug("Leaving driverSection().");
}

async function run(t) {
  log.debug("Entering run().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-dek-reads-'));
  const kekFile = path.join(dir, 'kek');
  fs.writeFileSync(kekFile, nodeCrypto.randomBytes(32).toString('base64'),
                   { mode: 0o600 });
  const names = ['STS_KEYS_SOURCE', 'STS_KEYS_KEK_PROVIDER',
                 'STS_SECRETS_ALLOW_LOCAL_SECRETS', 'STS_KEYS_KEK_FILE',
                 'STS_CLUSTER_MODE', 'STS_PERSISTENCE_MODE'];
  const saved = {};
  names.forEach(function (name) {
    saved[name] = process.env[name];
  });
  process.env.STS_KEYS_SOURCE = 'persisted';
  process.env.STS_KEYS_KEK_PROVIDER = 'file';
  process.env.STS_SECRETS_ALLOW_LOCAL_SECRETS = 'true';
  process.env.STS_KEYS_KEK_FILE = kekFile;
  process.env.STS_CLUSTER_MODE = 'active-active';
  process.env.STS_PERSISTENCE_MODE = 'postgres';
  try {
    await section(t, true);
    await section(t, false);
    await driverSection(t);
  } finally {
    names.forEach(function (name) {
      if (saved[name] === undefined) {
        delete process.env[name];
      } else {
        process.env[name] = saved[name];
      }
    });
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch (e) {
      log.debug("Caught in run(): " + ((e && e.message) || e));
    }
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'key_row_dek_reads',
  describe: 'a key-row write reads the data-key rows and not the whole key ' +
            'table',
  run: run
};
