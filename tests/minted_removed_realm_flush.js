// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: minted_removed_realm_flush.js
//
// ===========================================================================
// A REALM REMOVED WITH MINTED ROWS PENDING LEAVES A FLUSH THAT SETTLES
// (run #551).
//
// `persistence_minted.js`'s `realms.onRemove()` handler dropped the removed
// realm's keys from the journal (`handle -> realm -> keys`) but left the
// handle's now EMPTY map in it. `dirty()` is `journal.size > 0`, so the next
// flush skipped its "nothing journalled" branch, `takeDisjoint()` took no key
// (and only then deleted the empty map), and `flush()` answered
// `deferUntilSlot()` — a gate only a finishing save wakes. With no save in
// flight that promise never settled, so the directory flush that awaits it
// (`persistence.js`) never cleared `flushing`, and the change-log applier,
// which waits on `flushing` for a key that flush carried
// (`applyDirectoryChange()`), waited for ever: in run #551's cluster mode a
// request worker on node b stopped catching up at 22:16:21, one second after
// `sts_worker_pools` removed its realm, and answered every read-your-write
// request 503 (STS-WORKER-0053) for 44 minutes, until a restart.
//
// Claims:
//   1. a flush after the removal SETTLES, within a deadline, and writes
//      nothing of the removed realm;
//   2. `dirty()` is false once the removed realm's keys are dropped and
//      nothing else is journalled;
//   3. a row of another realm journalled beside the removed one is still
//      written by that flush.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const nodeCrypto = require('crypto');

const log = require('bunyan').createLogger({
  name: 'minted_removed_realm_flush',
  level: process.env.LOG_LEVEL || 'info' });

const config = require('../common/config');
const realms = require('../common/realms');
const keystore = require('../common/keystore');
const minted = require('../persistence/persistence_minted');

// How long a flush may take here before it is called wedged. Every save of
// the stub driver resolves at once, so a flush that has not settled in this
// time is one that never will.
const SETTLE_DEADLINE_MS = 3000;

// The minted driver interface, keeping rows and nothing else
// (`tests/minted_persistence.js`'s stub, cut to what a flush calls).
function fakeDriver() {
  log.debug("Entering fakeDriver().");
  const rows = new Map();
  log.debug("Leaving fakeDriver().");
  return {
    rows: rows,
    origin: function () {
      log.debug("Entering origin().");
      log.debug("Leaving origin().");
      return 'removed-realm-flush';
    },
    loadMinted: function () {
      log.debug("Entering loadMinted().");
      log.debug("Leaving loadMinted().");
      return Promise.resolve([]);
    },
    saveMinted: function (upserts, deletes) {
      log.debug("Entering saveMinted().");
      upserts.forEach(function (row) {
        rows.set(row.handle + '\u0000' + row.realm + '\u0000' + row.key, row);
      });
      deletes.forEach(function (row) {
        rows.delete(row.handle + '\u0000' + row.realm + '\u0000' + row.key);
      });
      log.debug("Leaving saveMinted().");
      return Promise.resolve();
    },
    readMinted: function () {
      log.debug("Entering readMinted().");
      log.debug("Leaving readMinted().");
      return Promise.resolve(null);
    },
    purgeMinted: function () {
      log.debug("Entering purgeMinted().");
      log.debug("Leaving purgeMinted().");
      return Promise.resolve(0);
    }
  };
}

// A key-encryption key through the module's own start path, as
// `tests/minted_persistence.js` arms it, and why there.
async function armKeystore(dir) {
  log.debug("Entering armKeystore().");
  const kekFile = path.join(dir, 'kek');
  fs.writeFileSync(kekFile, nodeCrypto.randomBytes(32).toString('base64'),
                   { encoding: 'utf8', mode: 0o600 });
  process.env.STS_KEYS_SOURCE = 'persisted';
  process.env.STS_KEYS_KEK_PROVIDER = 'file';
  process.env.STS_SECRETS_ALLOW_LOCAL_SECRETS = 'true';
  process.env.STS_KEYS_KEK_FILE = kekFile;
  keystore.reset();
  keystore.setStore({
    loadKeys: function () {
      log.debug("Entering loadKeys().");
      log.debug("Leaving loadKeys().");
      return Promise.resolve([]);
    },
    saveKeys: function () {
      log.debug("Entering saveKeys().");
      log.debug("Leaving saveKeys().");
      return Promise.resolve();
    },
    deleteKeys: function () {
      log.debug("Entering deleteKeys().");
      log.debug("Leaving deleteKeys().");
      return Promise.resolve();
    }
  });
  await keystore.start();
  log.debug("Leaving armKeystore().");
}

function disarmKeystore() {
  log.debug("Entering disarmKeystore().");
  delete process.env.STS_KEYS_SOURCE;
  delete process.env.STS_KEYS_KEK_PROVIDER;
  delete process.env.STS_SECRETS_ALLOW_LOCAL_SECRETS;
  delete process.env.STS_KEYS_KEK_FILE;
  keystore.reset();
  log.debug("Leaving disarmKeystore().");
}

// The flush's answer, or `'wedged'` when it has not settled by the deadline.
// The timer is cleared either way, so a settled flush leaves nothing armed.
function settledWithin(promise, ms) {
  log.debug("Entering settledWithin().");
  let timer = null;
  const deadline = new Promise(function (resolve) {
    timer = setTimeout(function () {
      resolve('wedged');
    }, ms);
  });
  log.debug("Leaving settledWithin().");
  return Promise.race([promise, deadline]).finally(function () {
    clearTimeout(timer);
  });
}

// THE REMOVAL AS ANOTHER NODE'S CHANGE ARRIVES HERE: applied from the change
// log, it journals nothing minted in this process — a local `realms.remove()`
// writes its own audit row, which would hand the flush a key to take and hide
// the wedge. So the persist observer is one that keeps nothing for the
// removal, and `setDriver()` puts the module's own back (it leaves the
// journal as it is).
function removedElsewhere(driver, id) {
  log.debug("Entering removedElsewhere().");
  realms.setPersistObserver(function () {
    return null;
  });
  try {
    realms.remove(id);
  } finally {
    minted.setDriver(driver, 'postgres');
  }
  log.debug("Leaving removedElsewhere().");
}

async function run(t) {
  log.debug("Entering run().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-removed-flush-'));
  try {
    await armKeystore(dir);
    await body(t);
  } finally {
    config.clearOverride('global.mode');
    config.clearOverride('persistence.minted');
    minted.reset();
    disarmKeystore();
    fs.rmSync(dir, { recursive: true, force: true });
  }
  log.debug("Leaving run().");
}

async function body(t) {
  log.debug("Entering body().");
  config.setOverride('global.mode', 'product');
  config.setOverride('persistence.minted', true);
  minted.reset();
  const driver = fakeDriver();
  t.check(minted.setDriver(driver, 'postgres') !== false,
          'precondition: the stub driver is accepted');
  t.check(keystore.sealed(), 'precondition: a key-encryption key is held');

  // Two stores, so claim 3 has a handle the removal does not empty.
  const gone = realms.map({ persist: 'test.removedFlush.gone' });
  const kept = realms.map({ persist: 'test.removedFlush.kept' });

  // -------------------------------------------------------------------------
  // 1 and 2. ONE REALM'S ROW, PENDING, AND THE REALM REMOVED.
  // -------------------------------------------------------------------------
  t.log.info('=== a realm removed with its minted rows pending ===');
  const id = 'removed-flush-' + Date.now().toString(36);
  const created = realms.create({ id: id, name: 'removed flush' });
  t.check(created && created.ok !== false, 'precondition: the realm was ' +
          'created', JSON.stringify(created));
  // WHAT THE CREATION JOURNALLED (its audit row) is written first, so the
  // journal holds the removed realm's key and nothing else — the state the
  // node-b worker was in.
  const drained = await settledWithin(minted.flush(), SETTLE_DEADLINE_MS);
  t.check(drained !== 'wedged' && !minted.dirty(), 'precondition: the ' +
          'creation\'s own rows are written and nothing is journalled',
          JSON.stringify(drained));
  await realms.run(realms.get(id), function () {
    gone.set('sid-in-removed-realm', { user: 'nobody' });
  });
  t.check(minted.dirty(), 'precondition: its row is journalled');
  removedElsewhere(driver, id);
  t.check(!realms.get(id), 'precondition: the realm is removed');
  t.check(!minted.dirty(),
          'NOTHING IS LEFT JOURNALLED once the removed realm\'s keys are ' +
          'dropped — an empty map left behind made dirty() true for ever');
  const first = await settledWithin(minted.flush(), SETTLE_DEADLINE_MS);
  t.check(first !== 'wedged',
          'THE FLUSH AFTER THE REMOVAL SETTLES — it waited for a save that ' +
          'was never sent, and the directory flush and the change-log pull ' +
          'behind it waited with it (run #551)', JSON.stringify(first));
  let leaked = 0;
  driver.rows.forEach(function (row) {
    if (row.realm === id && row.handle === 'test.removedFlush.gone') {
      leaked += 1;
    }
  });
  t.equal(leaked, 0, 'and the row pending in the removed realm was not ' +
          'written');

  // -------------------------------------------------------------------------
  // 3. ANOTHER REALM'S ROW BESIDE IT IS STILL WRITTEN.
  // -------------------------------------------------------------------------
  t.log.info('=== a row of a live realm beside the removed one ===');
  const id2 = 'removed-flush-b-' + Date.now().toString(36);
  const created2 = realms.create({ id: id2, name: 'removed flush b' });
  t.check(created2 && created2.ok !== false, 'precondition: the second ' +
          'realm was created', JSON.stringify(created2));
  await realms.run(realms.get(id2), function () {
    gone.set('sid-two', { user: 'nobody' });
  });
  kept.set('sid-default', { user: 'carol' });
  realms.remove(id2);
  const second = await settledWithin(minted.flush(), SETTLE_DEADLINE_MS);
  t.check(second !== 'wedged', 'the flush settles with a live row beside ' +
          'the removed realm\'s', JSON.stringify(second));
  let keptRows = 0;
  driver.rows.forEach(function (row) {
    if (row.handle === 'test.removedFlush.kept') {
      keptRows += 1;
    }
  });
  t.equal(keptRows, 1, 'and the live realm\'s row was written');
  t.check(!minted.dirty(), 'and nothing is left journalled');
  log.debug("Leaving body().");
}

module.exports = {
  name: 'minted_removed_realm_flush',
  describe: 'a realm removed with minted rows pending leaves a flush that ' +
            'settles, so the change-log pull behind it is not wedged ' +
            '(run #551)',
  run: run
};
