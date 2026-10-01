// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: minted_persistence.js
//
// ===========================================================================
// WHAT THIS PROCESS MINTED, WRITTEN DOWN — AND WHAT NO HTTP CLIENT CAN SEE
// ABOUT IT.
//
// Product mode persists sessions, tokens, authorization codes, SAML artifacts,
// Kerberos principals, the replay caches, the counters and the audit log
// (2026-09-06). Every one of those is observable over HTTP while the process is
// alive, and that is exactly the problem: **a service that journals the wrong
// key, seals nothing, or restores another process's counters into its own
// tally is CORRECT ON EVERY ENDPOINT for the whole life of the process that got
// it wrong.** The damage appears on the next start, in a different process, as
// a session that should have survived and did not — or as a call count that
// doubles every restart.
//
// That is `tests/CLAUDE.md`'s clause for what belongs here, and it is the same
// one `appconfig_persistence.js` and `ldif_codec.js` pass: the failure is
// invisible until a restart and it happens somewhere an HTTP client is not.
//
// ---------------------------------------------------------------------------
// IT DRIVES A STUB DRIVER AND NOT POSTGRES, DELIBERATELY.
//
// `persistence_minted.js` is handed its driver rather than requiring one, for
// this reason: what is asserted below — which keys were journalled, what the
// sealed row looks like, where a restored row lands, what a `merge: 'own'` row
// does — is entirely above the SQL. The SQL is `persistence_postgres.js`'s and
// is exercised against a real database by the parent suite's persistence job.
// A test here may not need a port, a container or a network, which is what
// makes the whole in-process suite worth running on every save.
// ===========================================================================

// Deleted rather than set, for the reason config_realm_layer.js gives.
delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const nodeCrypto = require('crypto');

const config = require('../common/config');
const realms = require('../common/realms');
const keystore = require('../common/keystore');
const minted = require('../persistence/persistence_minted');
const replication = require('../persistence/persistence_replication');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'minted_persistence',
  level: process.env.LOG_LEVEL || 'info' });

// ---------------------------------------------------------------------------
// A DRIVER THAT KEEPS ROWS AND NOTHING ELSE. It is the interface
// `persistence_minted.js` actually uses — five functions — rather than the
// whole driver contract, which is what makes it obvious when that interface
// grows: this stub stops satisfying `supports()` and every assertion below
// turns off rather than quietly passing.
// ---------------------------------------------------------------------------
function fakeDriver(origin) {
  log.debug("Entering fakeDriver().");
  const rows = new Map();   // handle \u0000 realm \u0000 key -> row
  function id(handle, realm, key) {
    log.debug("Entering id().");
    log.debug("Leaving id().");
    return handle + '\u0000' + realm + '\u0000' + key;
  }
  log.debug("Leaving fakeDriver().");
  return {
    rows: rows,
    origin: function () {
      log.debug("Entering origin().");
      log.debug("Leaving origin().");
      return origin || 'test-origin';
    },
    // THE SAME WHERE THE POSTGRES DRIVER'S QUERY APPLIES (#333), so what a
    // restore asks for is asserted here: realms that exist, rows not past
    // their own expiry, and a short-lived store's row with no expiry only
    // while it is younger than the retention. `lastFilter` is what it asked.
    lastFilter: null,
    loadMinted: function (filter) {
      log.debug("Entering loadMinted().");
      this.lastFilter = filter;
      const out = Array.from(rows.values()).filter(function (row) {
        if (filter.realms.indexOf(row.realm) < 0) {
          return false;
        }
        if (row.expiresAt !== null && row.expiresAt !== undefined &&
            row.expiresAt <= filter.nowMs) {
          return false;
        }
        return !(filter.staleBefore > 0 &&
                 (row.expiresAt === null || row.expiresAt === undefined) &&
                 filter.ageHandles.indexOf(row.handle) >= 0 &&
                 Number(row.writtenAt || 0) < filter.staleBefore);
      });
      log.debug("Leaving loadMinted().");
      return Promise.resolve(out);
    },
    purgeExpiredMinted: function (kind, options) {
      log.debug("Entering purgeExpiredMinted().");
      let gone = 0;
      rows.forEach(function (row, k) {
        if (gone >= options.limit) {
          return;
        }
        const noExpiry = row.expiresAt === null || row.expiresAt === undefined;
        const hit = kind === 'expired'
          ? !noExpiry && row.expiresAt <= options.nowMs
          : kind === 'stale'
            ? noExpiry && options.handles.indexOf(row.handle) >= 0 &&
              Number(row.writtenAt || 0) < options.staleBeforeMs
            : row.realm !== '' && row.realm !== options.defaultRealm &&
              !realms.get(row.realm) &&
              Number(row.writtenAt || 0) < options.orphanBeforeMs;
        if (hit) {
          rows.delete(k);
          gone++;
        }
      });
      log.debug("Leaving purgeExpiredMinted().");
      return Promise.resolve(gone);
    },
    saveMinted: function (upserts, deletes) {
      log.debug("Entering saveMinted().");
      upserts.forEach(function (row) {
        rows.set(id(row.handle, row.realm, row.key),
                 { handle: row.handle, realm: row.realm, key: row.key,
                   body: row.body, writtenAt: Date.now(),
                   expiresAt: row.expiresAt === undefined ? null
                     : row.expiresAt });
      });
      deletes.forEach(function (row) {
        rows.delete(id(row.handle, row.realm, row.key));
      });
      log.debug("Leaving saveMinted().");
      return Promise.resolve();
    },
    readMinted: function (handle, realm, key) {
      log.debug("Entering readMinted().");
      log.debug("Leaving readMinted().");
      return Promise.resolve(rows.get(id(handle, realm, key)) || null);
    },
    purgeMinted: function (before, handles) {
      log.debug("Entering purgeMinted().");
      let gone = 0;
      rows.forEach(function (row, k) {
        if (Array.isArray(handles) && handles.indexOf(row.handle) < 0) {
          return;
        }
        if (Number(row.writtenAt || 0) < before) {
          rows.delete(k);
          gone++;
        }
      });
      log.debug("Leaving purgeMinted().");
      return Promise.resolve(gone);
    }
  };
}

// ---------------------------------------------------------------------------
// A KEY-ENCRYPTION KEY, THROUGH THE MODULE'S OWN START PATH.
//
// **THE ENVIRONMENT LAYER AND NOT `setOverride()`**, for the reason
// `tests/keystore.js` gives beside the same three variables: `keys.source` and
// `keys.kekProvider` are restart-only rows, `setOverride()` refuses one
// correctly, and the environment is the layer a deployment would use anyway.
//
// It writes the key into a file in a temporary directory, which is not how a
// deployment would do it — the whole point of a KEK is that it is somewhere the
// ciphertext is not — but a test that put them apart would be testing the
// filesystem.
// ---------------------------------------------------------------------------
async function armKeystore(dir) {
  log.debug("Entering armKeystore().");
  const kekFile = path.join(dir, 'kek');
  fs.writeFileSync(kekFile, nodeCrypto.randomBytes(32).toString('base64'),
                   { encoding: 'utf8', mode: 0o600 });
  process.env.STS_KEYS_SOURCE = 'persisted';
  process.env.STS_KEYS_KEK_PROVIDER = 'file';
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
  delete process.env.STS_KEYS_KEK_FILE;
  keystore.reset();
  log.debug("Leaving disarmKeystore().");
}

// A directory of its own per run, removed at the end — `tests/keystore.js`'s
// `withTempDir()`, and its comment about `async`/`await` applies here for the
// same reason.
async function withTempDir(fn) {
  log.debug("Entering withTempDir().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-minted-'));
  try {
    log.debug("Leaving withTempDir().");
    return await fn(dir);
  } finally {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch (e) {
      // A directory that could not be removed is not a failed assertion.
      process.stderr.write('minted test: could not remove ' + dir + ': ' +
                           e.message + '\n');
    }
  }
}

async function run(t) {
  log.debug("Entering run().");
  log.debug("Leaving run().");
  return withTempDir(function (dir) { return body(t, dir); });
}

async function body(t, dir) {
  log.debug("Entering body().");
  // -------------------------------------------------------------------------
  // 1. THE JOURNAL NAMES EXACTLY WHAT MOVED.
  //
  // This is the assertion the whole design rests on. `persistence.js` diffs the
  // directory because its choke point cannot say which entry changed; these
  // stores CAN say, which is the entire reason a journal was affordable here.
  // If a store reports a key that did not move, every flush writes rows that
  // did not change; if it fails to report one that did, that row is lost at the
  // next restart and nothing anywhere shows it.
  // -------------------------------------------------------------------------
  t.log.info('=== the journal names the keys that moved, and no others ===');

  const seen = [];
  realms.setPersistObserver(function (handle, realm, key) {
    seen.push(handle + '/' + realm + '/' + (key === null ? '(whole)' : key));
  });

  const sessions = realms.map({ persist: 'test.sessions' });
  sessions.set('sid-1', { user: 'alice' });
  sessions.set('sid-2', { user: 'bob' });
  sessions.delete('sid-1');

  t.equal(seen.join(' '),
          'test.sessions/default/sid-1 test.sessions/default/sid-2 ' +
          'test.sessions/default/sid-1',
          'a map reports every set and every delete, with the key, in order');

  seen.length = 0;
  const ring = realms.arr({ persist: 'test.ring', merge: 'own' });
  ring.push({ at: 1 });
  ring.shift();
  // -----------------------------------------------------------------------
  // **`push` AND `shift` ARE THE ASSERTION THAT MATTERS HERE**, and they very
  // nearly did not work. `realms.arr()` is a Proxy over a real array and it
  // hands array METHODS back bound to that real array — so `push` mutates it
  // without ever reaching the `set` trap. A persisted audit ring, which is
  // written with exactly `push` on one end and `shift` on the other, would
  // have journalled NOTHING while looking entirely correct, and the failure
  // would have arrived one restart later as an empty audit log.
  // -----------------------------------------------------------------------
  t.equal(seen.length, 2,
          'AN ARRAY REPORTS push AND shift — the two the audit ring is ' +
          'written with, and the two a Proxy over a real array does not see ' +
          'unless the mutating methods are wrapped',
          seen.join(' '));

  seen.length = 0;
  const counters = realms.obj(function () { return { n: 0 }; },
                              { persist: 'test.counters', merge: 'own' });
  counters.n++;
  t.equal(seen.length, 1,
          'and an object reports a field assignment, which is what nums.n++ ' +
          'is');

  seen.length = 0;
  const quiet = realms.map();
  quiet.set('x', 1);
  t.equal(seen.length, 0,
          'A STORE THAT DECLARES NO HANDLE REPORTS NOTHING, which is every ' +
          'store in this service that was not converted and is what keeps ' +
          'the conversion opt-in rather than a sweep that has to be complete ' +
          'to be safe');

  // -------------------------------------------------------------------------
  // 2. SEALING. A row in the store must not be a usable credential.
  // -------------------------------------------------------------------------
  t.log.info('=== every row is sealed ===');

  await armKeystore(dir);

  t.check(keystore.sealed(), 'the keystore has a key-encryption key');
  const sealed = keystore.seal('sid-1');
  t.check(sealed && sealed.indexOf('sid-1') < 0,
          'AND THE PLAINTEXT IS NOT IN THE SEALED FORM — the assertion that ' +
          'separates "it is encrypted" from "it is encrypted and also stored ' +
          'beside itself", which every round-trip check in the world would ' +
          'pass',
          String(sealed).slice(0, 30));
  t.equal(keystore.open(sealed), 'sid-1', 'and it opens back');

  // -------------------------------------------------------------------------
  // 3. THE FLUSH WRITES WHAT THE JOURNAL NAMED, AND THE RESTORE PUTS IT BACK.
  // -------------------------------------------------------------------------
  t.log.info('=== flush and restore ===');

  const driver = fakeDriver('process-a');
  config.setOverride('global.mode', 'product');
  config.setOverride('persistence.minted', true);
  minted.reset();
  minted.setDriver(driver, 'postgres');

  sessions.set('sid-3', { user: 'carol' });
  await minted.flush();

  t.check(driver.rows.size > 0, 'the flush wrote rows',
          String(driver.rows.size));
  let leaked = false;
  driver.rows.forEach(function (row) {
    if (String(row.body).indexOf('carol') >= 0) {
      leaked = true;
    }
  });
  t.check(!leaked,
          'AND NO ROW CARRIES A VALUE IN THE CLEAR. A session id is a cookie ' +
          'value and an authorization code is redeemable; a database dump ' +
          'that held them would be a set of usable credentials, which for a ' +
          'service whose entire subject is credentials is the wrong thing to ' +
          'ship');

  sessions.clear();
  t.equal(sessions.size, 0, 'the live store is emptied, standing in for a ' +
                            'restart');
  await minted.restore();
  t.equal((sessions.get('sid-3') || {}).user, 'carol',
          'and the restore puts the session back where it was');
  t.equal(sessions.get('sid-1'), undefined,
          'while a key that was DELETED before the flush does not come back ' +
          '— which is the half a write-only journal would get wrong');

  // -------------------------------------------------------------------------
  // 4. A RESTORE MUST NOT JOURNAL WHAT IT JUST READ.
  //
  // Without the suppression the first act of a restored process is to write
  // back exactly what it read — harmless once, and an endless exchange between
  // two coordinating processes, each one's write waking the other.
  // -------------------------------------------------------------------------
  t.log.info('=== a restore is silent ===');
  // -------------------------------------------------------------------------
  // TWO THINGS ABOUT THIS SECTION ARE THE MUTATION ROUND'S DOING, and both are
  // the same lesson: **a mutant that survives is usually telling you about the
  // FIXTURE.**
  //
  // 1. It asserted against the `seen` array above, which stops recording the
  //    moment `minted.setDriver()` installs ITS OWN persist observer over the
  //    one this file installed. The assertion was about a stub that had been
  //    unplugged, and it passed however the restore behaved.
  // 2. It then emptied the live store and FLUSHED before restoring — which
  //    deletes the rows, so the restore had nothing to restore and could not
  //    have journalled anything whatever it did. Three guards were broken at
  //    once and the assertion still passed.
  //
  // So the store is seeded DIRECTLY here, exactly as a previous process would
  // have left it, and nothing is journalled before the restore runs. What is
  // asserted is the behaviour rather than any one of the three mechanisms that
  // produce it: **after a restore there is nothing for the next flush to
  // write.** A process that journalled its own restore would flush it straight
  // back — harmless once, and with coordination on, two processes exchanging
  // one row for ever, each write waking the other, both answering correctly
  // the whole time.
  // -------------------------------------------------------------------------
  const quietDriver = fakeDriver('process-a');
  quietDriver.rows.set('test.sessions default sid-restored',
                       { handle: 'test.sessions', realm: 'default',
                         key: 'sid-restored',
                         body: keystore.seal(JSON.stringify({ user: 'erin' })),
                         writtenAt: Date.now() });
  minted.reset();
  minted.setDriver(quietDriver, 'postgres');
  t.equal(minted.dirty(), false, 'nothing is pending before the restore');

  await minted.restore();
  t.equal((sessions.get('sid-restored') || {}).user, 'erin',
          'the seeded row really was restored, so the assertion below is ' +
          'about a restore that did something');
  t.equal(minted.dirty(), false,
          'AND NOTHING IS PENDING AFTER IT — a restore writes nothing back');

  // -------------------------------------------------------------------------
  // 5. `merge: 'own'` — ANOTHER PROCESS'S TALLY IS NOT THIS ONE'S.
  //
  // This is the assertion that stops the counters multiplying. A counter row
  // written by another process must reach the FAN-IN and never the local
  // store: adopting it would make this process's next flush write the combined
  // number back as its own contribution, so every restart would double it —
  // and the number would stay entirely plausible the whole time.
  // -------------------------------------------------------------------------
  t.log.info('=== an accumulator is per process ===');
  replication.reset();
  minted.reset();
  minted.setDriver(driver, 'postgres');
  counters.n = 7;
  await minted.flush();

  // The same row, as if a SECOND process had written it: same handle, same
  // realm, a different origin in the stored key.
  const theirs = keystore.seal(JSON.stringify({ n: 100 }));
  // THE STORED KEY OF AN `own` ROW: base64url(key) + '.' + base64url(origin),
  // which is what `storedKey()` writes. It was `key + '\u0000' + origin` until
  // 2026-09-07 and this line said so — and that shape could never reach a real
  // database, because PostgreSQL's `text` cannot hold a NUL: every `own` row
  // was refused with `invalid byte sequence for encoding "UTF8": 0x00`. This
  // test passed throughout, because its driver is a JS Map and a Map will hold
  // anything. Encoding it the way the real one does is what makes the double
  // stand for the store rather than merely resemble it.
  const theirKey = Buffer.from('', 'utf8').toString('base64url') + '.' +
                   Buffer.from('process-b', 'utf8').toString('base64url');
  driver.rows.set('test.counters\u0000default\u0000' + theirKey,
                  { handle: 'test.counters', realm: 'default',
                    key: theirKey, body: theirs,
                    writtenAt: Date.now() });

  await minted.restore();
  t.equal(counters.n, 7,
          'ANOTHER PROCESS\'S COUNTER IS NOT ADDED TO THIS PROCESS\'S. If it ' +
          'were, the next flush would write 107 as this process\'s own ' +
          'contribution and the total would double on every restart');
  const remote = replication.remoteRows('test.counters', 'default', '');
  t.equal(remote.length, 1,
          'it went to the fan-in instead, which is where the console sums it');
  t.equal((remote[0] || {}).n, 100, 'with the other process\'s number intact');

  // -------------------------------------------------------------------------
  // 5a. A FAILED FLUSH PUTS BACK THE KEY IT TOOK, NOT THE KEY IT WROTE
  //     (2026-09-12).
  //
  // The retry re-noted `storedKey()`'s answer, which for an `own` store is the
  // key base64url-encoded with the origin appended — so every consecutive
  // failure encoded it again. A dispatched stack whose workers deadlocked on
  // `sts_minted` grew those keys past PostgreSQL's index limit and then into
  // gigabytes. Three failures and a success is enough to see it: a correct
  // retry offers the same stored key four times.
  // -------------------------------------------------------------------------
  t.log.info('=== a failed flush puts back the key it took ===');
  replication.reset();
  minted.reset();
  const flaky = fakeDriver('process-a');
  const realSave = flaky.saveMinted;
  let failuresLeft = 3;
  const offered = [];
  flaky.saveMinted = function (upserts, deletes) {
    log.debug("Entering saveMinted().");
    upserts.concat(deletes).forEach(function (row) {
      if (row.handle === 'test.retry') {
        offered.push(row.key);
      }
    });
    if (failuresLeft > 0) {
      failuresLeft--;
      log.debug("Leaving saveMinted().");
      return Promise.reject(new Error('deadlock detected'));
    }
    log.debug("Leaving saveMinted().");
    return realSave(upserts, deletes);
  };
  minted.setDriver(flaky, 'postgres');
  const retried = realms.map({ persist: 'test.retry', merge: 'own' });
  retried.set('alice', { n: 1 });
  for (let i = 0; i < 4; i++) {
    await minted.flush();
  }
  const expectedKey = Buffer.from('alice', 'utf8').toString('base64url') + '.' +
                      Buffer.from('process-a', 'utf8').toString('base64url');
  t.equal(offered.length, 4,
          'the key is offered on every attempt, the three that failed and ' +
          'the one that did not', JSON.stringify(offered.map(function (k) {
            return k.length;
          })));
  t.check(offered.every(function (k) { return k === expectedKey; }),
          'AND IT IS THE SAME STORED KEY EVERY TIME — base64url(key) + "." + ' +
          'base64url(origin), not that encoded again per failure',
          'key lengths offered: ' + offered.map(function (k) {
            return k.length;
          }).join(', '));
  t.check(flaky.rows.has('test.retry\u0000default\u0000' + expectedKey),
          'and the row that finally lands is under that key, as an upsert ' +
          'rather than a delete of a name nothing holds');
  // Put back the driver section 6 restores from: `restore()` reads whichever
  // driver is installed, and leaving this one in place made retention count
  // this section's rows.
  retried.delete('alice');
  minted.reset();
  minted.setDriver(driver, 'postgres');

  // -------------------------------------------------------------------------
  // 5b. A KEY POSTGRESQL CANNOT HOLD IS LEFT OUT, NOT RETRIED FOR EVER
  //     (2026-09-27).
  //
  // A NUL in a text column fails the whole transaction, and a failed flush
  // puts every key back — so one such key stopped every minted write after
  // it (a single-node run: 853 failed flushes from the first OpenID Provider
  // Command onward). The driver here refuses a NUL the way PostgreSQL does.
  // -------------------------------------------------------------------------
  t.log.info('=== a key PostgreSQL cannot hold is left out of the write ===');
  replication.reset();
  minted.reset();
  const strict = fakeDriver('process-a');
  const strictSave = strict.saveMinted;
  let refusedWrites = 0;
  strict.saveMinted = function (upserts, deletes) {
    log.debug("Entering saveMinted().");
    const bad = upserts.concat(deletes).some(function (row) {
      return String(row.key).indexOf('\u0000') >= 0;
    });
    if (bad) {
      refusedWrites++;
      log.debug("Leaving saveMinted().");
      return Promise.reject(new Error('invalid byte sequence for encoding ' +
                                      '"UTF8": 0x00'));
    }
    log.debug("Leaving saveMinted().");
    return strictSave(upserts, deletes);
  };
  minted.setDriver(strict, 'postgres');
  const nulKeyed = realms.map({ persist: 'test.nulkey' });
  nulKeyed.set('\u0000issuer', { issuer: 'https://x.example' });
  nulKeyed.set('ordinary', { n: 1 });
  await minted.flush();
  await minted.flush();
  t.equal(refusedWrites, 0,
          'no write carried the NUL key, so the store never refused one');
  t.check(strict.rows.has('test.nulkey\u0000default\u0000ordinary'),
          'and the row beside it was written');
  t.check(nulKeyed.get('\u0000issuer') &&
          nulKeyed.get('\u0000issuer').issuer === 'https://x.example',
          'while the NUL-keyed value is still held in memory');
  nulKeyed.delete('\u0000issuer');
  nulKeyed.delete('ordinary');
  minted.reset();
  minted.setDriver(driver, 'postgres');

  // -------------------------------------------------------------------------
  // 6. RETENTION, PER STORE (2026-09-18). A SHORT-LIVED store's month-old row
  //    is not restored and is deleted; every other store's is kept however
  //    old it is. Until that day every old row of every store went — a
  //    configuration or an account not written for a week included.
  //    SINCE #333 THE READ SKIPS IT AND THE PURGE JOB DELETES IT: a restore
  //    runs in every process and deletes nothing.
  // -------------------------------------------------------------------------
  t.log.info('=== retention ===');
  const shortLived = realms.map({ persist: 'test.short', retain: 'age' });
  shortLived.set('nonce-1', { at: 1 });
  await minted.flush();
  // What the STORE holds for the kept store — what a restore can put back.
  let sessionRows = 0;
  driver.rows.forEach(function (row) {
    if (row.handle === 'test.sessions') {
      sessionRows++;
    }
  });
  t.check(sessionRows > 0 && shortLived.size === 1,
          'the fixture holds a kept store\'s rows and a short-lived one\'s');
  driver.rows.forEach(function (row) {
    row.writtenAt = Date.now() - (30 * 24 * 60 * 60 * 1000);
  });
  sessions.clear();
  shortLived.clear();
  const before = driver.rows.size;
  config.setOverride('persistence.mintedRetention', 7 * 24 * 60 * 60 * 1000);
  await minted.restore();
  t.equal(shortLived.size, 0,
          'a SHORT-LIVED store\'s row older than persistence.mintedRetention ' +
          'is not restored');
  t.equal(sessions.size, sessionRows,
          'and a KEPT store\'s row is restored however old it is — unchanged ' +
          'is not stale');
  t.check(driver.lastFilter &&
          driver.lastFilter.ageHandles.indexOf('test.short') >= 0 &&
          driver.lastFilter.ageHandles.indexOf('test.sessions') < 0 &&
          driver.lastFilter.staleBefore > 0,
          'the READ was asked to leave it out: the short-lived stores and ' +
          'the retention cutoff are in the filter, the kept store is not',
          JSON.stringify(driver.lastFilter && driver.lastFilter.ageHandles
            .filter(function (h) { return /^test\./.test(h); })));
  t.equal(driver.rows.size, before,
          'and the restore DELETES NOTHING (#333) — every process runs it');
  const swept = await minted.purgeExpired(Date.now());
  let shortRows = 0;
  driver.rows.forEach(function (row) {
    if (row.handle === 'test.short') {
      shortRows++;
    }
  });
  t.check(shortRows === 0 && driver.rows.size === before - 1 &&
          swept.stale === 1,
          'AND THE PURGE JOB DELETES THE SHORT-LIVED ROW, while every other ' +
          'old row stays in the store',
          JSON.stringify([before, driver.rows.size, shortRows, swept]));

  // -------------------------------------------------------------------------
  // 6b. ONLY LIVE ROWS OF DEFINED REALMS ARE READ (2026-09-28, #333). A store
  //     that declares `expiresAt` has each row's own expiry written with it;
  //     a restore reads no row past it, however recently it was written, and
  //     no row of a realm that is not defined; the purge job deletes both —
  //     in bounded batches — and leaves a live row and a row with no expiry.
  // -------------------------------------------------------------------------
  t.log.info('=== expiry and realms (#333) ===');
  const expiring = realms.map({
    persist: 'test.expiring', retain: 'age',
    expiresAt: function (value) {
      return value && value.expiresAt;
    }
  });
  const now = Date.now();
  expiring.set('dead', { expiresAt: now - 1000 });
  expiring.set('live', { expiresAt: now + 60 * 60 * 1000 });
  expiring.set('forever', { note: 'no expiry' });
  await minted.flush();
  const stored = function (key) {
    return driver.rows.get(['test.expiring', 'default', key].join('\u0000'));
  };
  t.check(stored('dead') && stored('dead').expiresAt === now - 1000 &&
          stored('live').expiresAt === now + 60 * 60 * 1000 &&
          stored('forever').expiresAt === null,
          'the flush writes each row\'s own expiry, from the store\'s hook, ' +
          'and none for a record the hook answers nothing for',
          JSON.stringify(['dead', 'live', 'forever'].map(function (k) {
            return stored(k) && stored(k).expiresAt;
          })));
  // A row of a realm nobody defines, as a removed realm's straggler would be.
  driver.rows.set(['test.expiring', 'gone-realm', 'x'].join('\u0000'),
                  { handle: 'test.expiring', realm: 'gone-realm', key: 'x',
                    body: keystore.seal(JSON.stringify({ expiresAt: now +
                                                         3600000 }),
                                        'minted-rows'),
                    writtenAt: now - 2 * 60 * 60 * 1000,
                    expiresAt: now + 3600000 });
  expiring.clear();
  minted.reset();
  minted.setDriver(driver, 'postgres');
  await minted.restore();
  t.check(!expiring.has('dead') && expiring.has('live') &&
          expiring.has('forever'),
          'a restore reads no row past its own expiry, and reads a live one ' +
          'and one that does not expire',
          JSON.stringify(Array.from(expiring.keys())));
  t.check(driver.lastFilter.realms.indexOf('gone-realm') < 0 &&
          driver.lastFilter.realms.indexOf('default') >= 0 &&
          driver.lastFilter.realms.indexOf('') >= 0,
          'the read names the realms that exist — the default realm and the ' +
          'shared stores\' partition — and not one that does not',
          JSON.stringify(driver.lastFilter.realms));
  const purge = await minted.purgeExpired(Date.now());
  t.check(purge.expired === 1 && purge.orphaned === 1 && !stored('dead') &&
          !!stored('live') && !!stored('forever'),
          'the purge job deletes the expired row and the undefined realm\'s ' +
          'row, and keeps the live one and the one that does not expire',
          JSON.stringify(purge));
  // The hook that throws: written as not expiring, never lost.
  const throwing = realms.map({
    persist: 'test.expiring-throws',
    expiresAt: function () {
      throw new Error('no idea');
    }
  });
  throwing.set('k', { a: 1 });
  await minted.flush();
  t.equal(driver.rows.get(['test.expiring-throws', 'default', 'k']
                          .join('\u0000')).expiresAt, null,
          'a hook that throws writes the row as NOT expiring — kept, never ' +
          'lost');
  throwing.delete('k');
  expiring.clear();
  await minted.flush();
  // The common shape of a hook: a field in ms, in seconds, an ISO string, the
  // bare value; anything else is "does not expire".
  const ms = realms.expiryField('expires', 1);
  const sec = realms.expiryField('until', 1000);
  const bare = realms.expiryField(null, 1000);
  t.check(ms({ expires: 1234 }) === 1234 && sec({ until: 5 }) === 5000 &&
          bare(7) === 7000 &&
          ms({ expires: '2030-01-01T00:00:00.000Z' }) ===
            Date.parse('2030-01-01T00:00:00.000Z') &&
          ms({}) === null && ms({ expires: 0 }) === null && ms(null) === null &&
          bare('x') === null,
          'realms.expiryField() reads ms, seconds, ISO and a bare value, and ' +
          'answers null for anything that is not a positive instant');
  // The real stores' hooks, where the ticket found the rows (#333): a code,
  // a DPoP nonce (issued, seconds), a refresh family, a tracked token past
  // its retention — each answers the store's own rule.
  require('../oauth-oidc/oauth2');
  require('../oauth-oidc/dpop');
  require('../common/admin_stats');
  const hook = function (handle) {
    const row = realms.handleFor(handle);
    return row && row.expiresAt;
  };
  t.check(hook('oauth2.authzCodes')({ expires: now + 5 }) === now + 5 &&
          hook('oauth2_bcp.refreshFamilies')({ forget: now + 9 }) ===
            now + 9 &&
          hook('dpop.issuedNonces')(1000) ===
            (1000 + Number(config.value('oauth2.dpopNonceTtlS'))) * 1000 &&
          hook('admin_stats.tokens')({ exp: 1000 }) ===
            (1000 + Number(config.value('oauth2.clockSkewS')) +
             Number(config.value('oauth2.expiredTokenRetentionS'))) * 1000 &&
          hook('admin_stats.tokens')({ exp: 0 }) === null,
          'the declared stores\' hooks answer their own rules — a code its ' +
          'expires, a DPoP nonce its issue time plus its lifetime, a tracked ' +
          'token its exp plus the skew and the retention, and none for exp 0');
  t.check(!hook('authn.sessions') && !hook('gnap.tokens') &&
          !hook('vc_status.entries') && !hook('oauth2.backchannelDeliveries'),
          'and the stores whose ending DOES something declare none: a ' +
          'session (audit, CAEP, back-channel logout), a GNAP token (an ' +
          'expired one may be rotated), a status-list entry (its bit), a ' +
          'delivery (dead-lettered first)');
  // The job: a cluster job, bounded, owned here.
  const jobs = [];
  minted.ensureExpiryPurgeJob({
    register: function (spec) {
      jobs.push(spec);
    },
    job: function () {
      return null;
    }
  });
  t.check(jobs.length === 1 && jobs[0].id ===
          'persistence.minted-expiry-purge' && jobs[0].kind === 'cluster' &&
          jobs[0].owner === 'persistence/persistence_minted.js' &&
          jobs[0].everyMs() > 0 && /batches of \d+/.test(jobs[0].describe),
          'the purge is ONE cluster scheduler job, bounded per run',
          JSON.stringify(jobs.map(function (j) {
            return { id: j.id, kind: j.kind, describe: j.describe };
          })));
  // Bounded: a backlog larger than one run is left for the next.
  for (let i = 0; i < 20 * 5000 + 10; i++) {
    driver.rows.set('bulk\u0000default\u0000' + i,
                    { handle: 'test.expiring', realm: 'default',
                      key: 'b' + i, body: 'x', writtenAt: now,
                      expiresAt: now - 1 });
  }
  const bounded = await minted.purgeExpired(Date.now());
  t.check(bounded.expired === 20 * 5000 && bounded.more === true,
          'one run deletes at most its bound and says more remain',
          JSON.stringify(bounded));
  const rest = await minted.purgeExpired(Date.now());
  t.check(rest.expired === 10 && rest.more === false,
          'and the next run finishes the backlog', JSON.stringify(rest));
  // An unknown retention word is refused and read as keep.
  const odd = realms.map({ persist: 'test.odd-retain', retain: 'forever' });
  t.equal(realms.handleFor('test.odd-retain').retain, 'keep',
          'a retention word that is neither keep nor age is read as keep');
  t.check(odd.size === 0, 'and the store is otherwise ordinary');

  // -------------------------------------------------------------------------
  // 7. DEVELOPMENT MODE WRITES NOTHING, which is the property every other
  //    test in this repository and every single-process job in the parent
  //    suite depends on.
  // -------------------------------------------------------------------------
  t.log.info('=== development mode ===');
  config.setOverride('global.mode', 'development');
  minted.reset();
  minted.setDriver(fakeDriver('process-a'), 'postgres');
  t.equal(minted.enabled(), false,
          'DEVELOPMENT MODE PERSISTS NOTHING IT MINTS, whatever the store ' +
          'is — because the signing key is regenerated on every start there, ' +
          'so a restored token would verify against nothing');

  const devDriver = fakeDriver('process-a');
  minted.reset();
  minted.setDriver(devDriver, 'postgres');
  sessions.set('sid-9', { user: 'dave' });
  await minted.flush();
  t.equal(devDriver.rows.size, 0,
          'and a flush in development mode writes no rows at all');

  // -------------------------------------------------------------------------
  // 7b. UNLESS SEVERAL PROCESSES ARE ANSWERING ONE PORT (2026-09-12).
  //
  // The arm above is the promise; this is one of its two exceptions, and it
  // is not a softening of it. (The other, since 2026-09-14, is a node of a
  // cluster — `cluster.mode` not `off` — which
  // `tests/cluster_node_state_sharing.js` asserts.) A dispatched run is
  // several processes against one store, and what they mint has to be in that
  // store or they disagree: a token
  // minted on one worker is unknown to the next, and — the way it was actually
  // found — a REPLAYED RFC 7523 assertion is refused by the worker that saw it
  // and accepted by the two that did not.
  //
  // **IT WAS `hasEphemeralKek()` ALONE AND THAT WENT SILENTLY FALSE.** The
  // pool generates a per-run KEK precisely because development mode has none;
  // `keys.source=persisted` gives it a REAL one, `useEphemeralKek()` then
  // refuses to substitute a per-run key, and every arm of the condition was
  // false — so a dispatched run reading its KEK from a secret store shared
  // nothing, with no error anywhere. The question is SEVERAL PROCESSES, and it
  // is asked as such now.
  //
  // The two variables go through the ENVIRONMENT for `armKeystore()`'s reason:
  // both are restart-only rows and `setOverride()` refuses one correctly.
  // -------------------------------------------------------------------------
  t.log.info('=== development mode, dispatched ===');
  process.env.STS_WORKERS_REQUEST_COUNT = '3';
  process.env.STS_WORKERS_DISPATCH = '*';
  minted.reset();
  const poolDriver = fakeDriver('process-a');
  minted.setDriver(poolDriver, 'postgres');
  t.equal(minted.enabled(), true,
          'A DISPATCHED development run DOES persist what it mints, because ' +
          'its workers have to agree — the keystore holds a real ' +
          'key-encryption key here, which is the case that used to answer no');
  sessions.set('sid-10', { user: 'erin' });
  await minted.flush();
  t.check(poolDriver.rows.size > 0,
          'and a flush writes rows the other workers can read',
          String(poolDriver.rows.size) + ' row(s)');

  // AN EMPTY LIST, NAMED: since #364 `workers.dispatch` defaults to `*`, so
  // unsetting it would dispatch everything rather than nothing.
  process.env.STS_WORKERS_DISPATCH = '';
  minted.reset();
  minted.setDriver(fakeDriver('process-a'), 'postgres');
  t.equal(minted.enabled(), false,
          'and WORKERS ALONE ARE NOT THE CONDITION — with nothing dispatched ' +
          'the children answer no request, so there is no second process to ' +
          'disagree with and the promise above is unchanged');
  delete process.env.STS_WORKERS_DISPATCH;
  delete process.env.STS_WORKERS_REQUEST_COUNT;

  // -------------------------------------------------------------------------
  // 8. AN ldif STORE SAYS SO RATHER THAN HALF-WORKING.
  // -------------------------------------------------------------------------
  t.log.info('=== the ldif store ===');
  minted.reset();
  const fileDriver = { open: function () {}, loadKeys: function () {} };
  t.equal(minted.setDriver(fileDriver, 'ldif'), false,
          'a driver with no loadMinted/saveMinted is refused');
  t.check(String(minted.status().unsupportedReason).indexOf('whole files') > 0,
          'AND THE REASON IS REPORTED rather than the feature silently not ' +
          'happening — /admin/persistence draws it, so an operator who chose ' +
          'ldif and product together learns it on the way up rather than at ' +
          'the next restart',
          minted.status().unsupportedReason);

  // Leave the process as it was found: these are process-wide overrides and
  // run.js runs every file in one process.
  config.clearOverride('global.mode');
  config.clearOverride('persistence.minted');
  config.clearOverride('persistence.mintedRetention');
  minted.reset();
  replication.reset();
  disarmKeystore();
  log.debug("Leaving body().");
}

module.exports = {
  name: 'minted_persistence',
  describe: 'sessions, tokens and the audit log across a restart — and the ' +
            'counters that must not double',
  run: run
};
