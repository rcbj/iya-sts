// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: startup_profile.js
//
// ===========================================================================
// WHAT A START COSTS THAT GROWS WITH THE DATA (#613, 2026-10-13).
//
// A measuring tool, not a test: it prints figures and asserts nothing. Run it
// in the tests image (the TypeScript is compiled only there):
//
//   docker run --rm iya-sts-npm-test:<tag> node tests/tools/startup_profile.js
//
// Environment: PROFILE_PEOPLE (131546, what 8081 held), PROFILE_MINTED
// (48000, what 8081's processes restored), PROFILE_RUNS (42740) and
// PROFILE_OTHER (9494), the split of 8081's 52,234 rows on 2026-10-14
// between `scheduler.runs` and every other store. Four figures, each with
// the longest the event loop was held while it ran:
//
//   prefill   what `replaceRealm()` did until #613 for every restored
//             person — `noteKnownIdentity(name, 'restored')` — and the
//             minted flush that followed it, because the register is a
//             minted store and every note and every eviction past
//             `MAX_USERS` was journalled. The pass is gone; this measures
//             the mechanism, so the record says what it cost.
//   flush     that flush alone: rows written, rows deleted, milliseconds.
//   restore   `persistence_minted.restore()` over PROFILE_MINTED sealed
//             rows of one store, as a worker's start does it.
//   split     (#617) the same restore over PROFILE_RUNS rows of a store
//             declared `restoreInWorkers: false` (as `scheduler.runs` is),
//             of 8081's average size (~800 bytes), and PROFILE_OTHER rows of
//             an ordinary store: once as the front process, which restores
//             both, and once as a request worker, which leaves the first
//             out of the query and the loop.
//
// It drives `persistence_minted.js` over a driver that keeps rows in a Map,
// as `tests/minted_persistence.js` does, so what it measures is the work
// above the SQL: sealing, opening, the journal and the loops.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const nodeCrypto = require('crypto');
const perfHooks = require('perf_hooks');

const log = require('bunyan').createLogger({ name: 'startup_profile',
  level: process.env.LOG_LEVEL || 'fatal' });

// A driver that keeps rows and nothing else; tests/minted_persistence.js's,
// cut to what a flush and a restore use.
function mapDriver() {
  log.debug("Entering mapDriver().");
  const rows = new Map();
  const counts = { upserts: 0, deletes: 0 };
  log.debug("Leaving mapDriver().");
  return {
    rows: rows,
    counts: counts,
    origin: function () {
      log.debug("Entering origin().");
      log.debug("Leaving origin().");
      return 'profile-origin';
    },
    loadMinted: function (filter) {
      log.debug("Entering loadMinted().");
      // The postgres driver's `skipHandles` clause (#617).
      const skip = (filter && filter.skipHandles) || [];
      log.debug("Leaving loadMinted().");
      return Promise.resolve(Array.from(rows.values()).filter(function (row) {
        return skip.indexOf(row.handle) < 0;
      }));
    },
    purgeExpiredMinted: function () {
      log.debug("Entering purgeExpiredMinted().");
      log.debug("Leaving purgeExpiredMinted().");
      return Promise.resolve(0);
    },
    saveMinted: function (upserts, deletes) {
      log.debug("Entering saveMinted().");
      upserts.forEach(function (row) {
        counts.upserts++;
        rows.set(row.handle + '\u0000' + row.realm + '\u0000' + row.key,
                 { handle: row.handle, realm: row.realm, key: row.key,
                   keySealed: row.keySealed || '', body: row.body,
                   writtenAt: Date.now(), expiresAt: null });
      });
      deletes.forEach(function (row) {
        counts.deletes++;
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

// The longest the event loop was held while `work` ran, from a 5 ms timer's
// lateness — the same question persistence.js's STS-STORE-0068 asks.
async function heldWhile(work) {
  log.debug("Entering heldWhile().");
  let worst = 0;
  let last = perfHooks.performance.now();
  const timer = setInterval(function () {
    const now = perfHooks.performance.now();
    worst = Math.max(worst, now - last - 5);
    last = now;
  }, 5);
  const started = perfHooks.performance.now();
  let result;
  try {
    result = await work();
  } finally {
    clearInterval(timer);
  }
  const tookMs = perfHooks.performance.now() - started;
  // A synchronous `work` never let the timer run at all: its whole length
  // was one block.
  worst = Math.max(worst, perfHooks.performance.now() - last - 5);
  log.debug("Leaving heldWhile().");
  return { result: result, tookMs: Math.round(tookMs),
           heldMs: Math.round(Math.max(0, worst)) };
}

async function main() {
  log.debug("Entering main().");
  const people = Number(process.env.PROFILE_PEOPLE || 131546);
  const mintedRows = Number(process.env.PROFILE_MINTED || 48000);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-profile-'));
  const kekFile = path.join(dir, 'kek');
  fs.writeFileSync(kekFile, nodeCrypto.randomBytes(32).toString('base64'),
                   { encoding: 'utf8', mode: 0o600 });
  process.env.STS_KEYS_SOURCE = 'persisted';
  process.env.STS_KEYS_KEK_PROVIDER = 'file';
  process.env.STS_KEYS_KEK_FILE = kekFile;
  const config = require('../../common/config');
  const realms = require('../../common/realms');
  const keystore = require('../../common/keystore');
  const minted = require('../../persistence/persistence_minted');
  const stats = require('../../common/admin_stats');
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
  config.setOverride('global.mode', 'product');
  config.setOverride('persistence.minted', true);
  const out = { people: people, mintedRows: mintedRows };

  // 1. THE PRE-FILL THAT WAS, AND THE FLUSH IT CAUSED.
  let driver = mapDriver();
  minted.reset();
  minted.setDriver(driver, 'postgres');
  const prefill = await heldWhile(function () {
    for (let i = 0; i < people; i++) {
      stats.noteKnownIdentity('person' + i, 'restored');
    }
    return null;
  });
  out.prefill = { tookMs: prefill.tookMs, heldMs: prefill.heldMs,
                  journalled: minted.status().pending,
                  registerKeeps: stats.MAX_USERS };
  const flushed = await heldWhile(function () {
    return minted.flush();
  });
  out.flush = { tookMs: flushed.tookMs, heldMs: flushed.heldMs,
                upserts: driver.counts.upserts,
                deletes: driver.counts.deletes };

  // 2. A WORKER'S MINTED RESTORE.
  driver = mapDriver();
  minted.reset();
  minted.setDriver(driver, 'postgres');
  const store = realms.map({ persist: 'test.profile.rows' });
  for (let i = 0; i < mintedRows; i++) {
    store.set('row-' + i, { n: i, who: 'person' + (i % 1000),
                            at: Date.now(), scopes: ['openid', 'profile'] });
  }
  await minted.flush();
  store.clear();
  const restored = await heldWhile(function () {
    return minted.restore();
  });
  out.restore = { tookMs: restored.tookMs, heldMs: restored.heldMs,
                  restored: (restored.result || {}).restored,
                  stored: driver.rows.size };

  // 3. THE SAME RESTORE, SPLIT AS 8081'S ROWS WERE (#617): front vs worker.
  const runRows = Number(process.env.PROFILE_RUNS || 42740);
  const otherRows = Number(process.env.PROFILE_OTHER || 9494);
  driver = mapDriver();
  minted.reset();
  minted.setDriver(driver, 'postgres');
  const runs = realms.map({ persist: 'test.profile.runs',
                            restoreInWorkers: false });
  const other = realms.map({ persist: 'test.profile.other' });
  const filler = 'x'.repeat(600);
  for (let i = 0; i < runRows; i++) {
    runs.set('run-' + i, { runId: 'run-' + i, jobId: 'job-' + (i % 60),
                           state: 'succeeded', at: Date.now(), pad: filler });
  }
  for (let i = 0; i < otherRows; i++) {
    other.set('row-' + i, { n: i, who: 'person' + (i % 1000),
                            at: Date.now(), pad: filler });
  }
  await minted.flush();
  const split = {};
  for (const role of ['front', 'worker']) {
    runs.clear();
    other.clear();
    minted.reset();
    minted.setDriver(driver, 'postgres');
    if (role === 'worker') {
      process.env.STS_REQUEST_WORKER = '1';
    } else {
      delete process.env.STS_REQUEST_WORKER;
    }
    const one = await heldWhile(function () {
      return minted.restore();
    });
    delete process.env.STS_REQUEST_WORKER;
    split[role] = { tookMs: one.tookMs, heldMs: one.heldMs,
                    restored: (one.result || {}).restored };
  }
  out.split = split;
  process.stdout.write(JSON.stringify(out, null, 2) + '\n');
  fs.rmSync(dir, { recursive: true, force: true });
  log.debug("Leaving main().");
}

main().then(function () {
  process.exit(0);
}, function (e) {
  log.debug("Caught in main(): " + ((e && e.message) || e));
  process.stderr.write(((e && e.stack) || e) + '\n');
  process.exit(1);
});
