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
const errorCodes = require('../common/error_codes');
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
                   // The name, sealed, beside its digest (#222).
                   keySealed: row.keySealed || '',
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

  // THE NAME IS NOT IN THE CLEAR EITHER (#222): a session id is the cookie,
  // and the key column held it. It is the name's keyed digest now, with the
  // name sealed beside it.
  let keyedRow = null;
  driver.rows.forEach(function (row) {
    if (minted.nameOfRow(row) === 'sid-3') {
      keyedRow = row;
    }
  });
  t.check(keyedRow && keyedRow.key !== 'sid-3' &&
          keyedRow.key.indexOf('sid-3') < 0 &&
          /^\$aes(gcm|siv)\$2\$/.test(keyedRow.keySealed) &&
          keyedRow.keySealed.indexOf('sid-3') < 0,
          'AND NOR IS ITS NAME: the key column is a keyed digest and the ' +
          'session id is only in the sealed name beside it',
          keyedRow ? String(keyedRow.key).slice(0, 20) : 'no row');
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
  // 3b. MINTED BEFORE THE KEYSTORE STARTED IS DEFERRED, NOT DROPPED (#357).
  //
  // A product process opens its store, and mints, before `keystore.start()`
  // has read the key-encryption key. The flush then had nothing to seal with
  // and CLEARED the journal, and the restore after the start cleared it again:
  // what was minted in that window was never written. Now the flush keeps it,
  // the restore keeps it, and the next flush writes it.
  // -------------------------------------------------------------------------
  t.log.info('=== minted before the keystore started is deferred (#357) ===');
  keystore.reset();
  t.check(!keystore.hasStarted() && !keystore.sealed(),
          'a keystore that has not started yet holds no key');
  sessions.set('sid-357', { user: 'early' });
  const early = await minted.flush();
  const hasEarlyRow = function () {
    let found = false;
    driver.rows.forEach(function (row) {
      if (minted.nameOfRow(row) === 'sid-357') {
        found = true;
      }
    });
    return found;
  };
  t.check(early.deferred === true && !hasEarlyRow(),
          'a flush before the keystore starts is DEFERRED and writes nothing',
          JSON.stringify(early));
  await armKeystore(dir);
  t.check(keystore.hasStarted(), 'the keystore has started');
  await minted.restore();
  await minted.flush();
  t.check(hasEarlyRow(),
          'and once the keystore has started and the store is restored, the ' +
          'session minted before the start is written — not dropped, which ' +
          'is what clearing the journal at the deferred flush used to do');
  t.equal((sessions.get('sid-357') || {}).user, 'early',
          'and it is still live in this process');

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
  // The `own` store's two-part name, and the key column it is filed under —
  // its keyed digest since #222.
  const expectedKey = minted.keyColumnOf('test.retry', 'default',
    Buffer.from('alice', 'utf8').toString('base64url') + '.' +
    Buffer.from('process-a', 'utf8').toString('base64url'));
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
  t.check(strict.rows.has('test.nulkey\u0000default\u0000' +
                          minted.keyColumnOf('test.nulkey', 'default',
                                             'ordinary')),
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
  // A row whose sealed NAME does not open is not one a restore can put back:
  // section 3b armed a second keystore, and this fixture's key store keeps
  // nothing, so rows written before it are under a key that is gone (#222).
  driver.rows.forEach(function (row) {
    if (row.handle === 'test.sessions' && minted.nameOfRow(row) !== null) {
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
    return driver.rows.get(['test.expiring', 'default',
      minted.keyColumnOf('test.expiring', 'default', key)].join('\u0000'));
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
  t.equal(driver.rows.get(['test.expiring-throws', 'default',
    minted.keyColumnOf('test.expiring-throws', 'default', 'k')]
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
  // Two since #695: the second is the global tier's, off unless the store
  // is deployed as cells, and claimed in the global tier where it is.
  t.check(jobs.length === 2 && jobs[0].id ===
          'persistence.minted-expiry-purge' && jobs[0].kind === 'cluster' &&
          jobs[0].owner === 'persistence/persistence_minted.js' &&
          jobs[0].everyMs() > 0 && /batches of \d+/.test(jobs[0].describe) &&
          jobs[1].id === 'persistence.minted-expiry-purge-global' &&
          jobs[1].kind === 'cluster' && jobs[1].everyMs() > 0,
          'the purge is ONE cluster scheduler job per tier, bounded per run',
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
  // A single store is asked with no tier, exactly as before #695.
  let tierAsked = 'unasked';
  const plainPurge = driver.purgeExpiredMinted;
  driver.purgeExpiredMinted = function (kind, options) {
    log.debug("Entering purgeExpiredMinted(), recording the tier.");
    tierAsked = Object.prototype.hasOwnProperty.call(options, 'tier')
      ? String(options.tier) : '';
    log.debug("Leaving purgeExpiredMinted().");
    return plainPurge.call(this, kind, options);
  };
  const single = await minted.purgeExpired(Date.now());
  driver.purgeExpiredMinted = plainPurge;
  t.check(tierAsked === '' && single.tier === '' &&
          single.failures.length === 0,
          'a single-database store is purged as before: no tier is named ' +
          'and nothing failed', JSON.stringify([tierAsked, single]));
  t.check(jobs[1].off() === 'this store has no global tier',
          'and the global tier\'s purge is off there', jobs[1].off());

  // -------------------------------------------------------------------------
  // 6c. ONE TIER AT A TIME (#695). In a service deployed as cells the store
  //     is two databases, and the purge used to ask both in one call with
  //     one limit, summing the counts — up to twice the limit per batch, a
  //     stop test asked of the sum, and an unreachable global database
  //     losing the cell's count with it. Each tier is its own job now, with
  //     its own batches and its own failure; the global one is claimed in
  //     the global tier (cell_tiers.js asserts that), so one cell runs it.
  // -------------------------------------------------------------------------
  t.log.info('=== the expiry purge, one tier at a time (#695) ===');
  const tieredStore = require('../persistence/persistence_tiered');
  const globalDb = fakeDriver('global');
  const cellDb = fakeDriver('cell');
  let globalDown = false;
  globalDb.loadRealms = function () {
    log.debug("Entering loadRealms(), the global registry.");
    log.debug("Leaving loadRealms().");
    return globalDown ? Promise.reject(new Error('the global database is ' +
                                                 'unreachable'))
                      : Promise.resolve([{ id: 'default' }]);
  };
  const limitsOf = { global: [], cell: [] };
  [['global', globalDb], ['cell', cellDb]].forEach(function (pair) {
    const own = pair[1].purgeExpiredMinted;
    pair[1].purgeExpiredMinted = function (kind, options) {
      log.debug("Entering purgeExpiredMinted(), the " + pair[0] + " tier.");
      limitsOf[pair[0]].push({ kind: kind, limit: options.limit,
                               tier: options.tier });
      if (pair[0] === 'global' && globalDown) {
        log.debug("Leaving purgeExpiredMinted(). Unreachable.");
        return Promise.reject(new Error('the global database is ' +
                                        'unreachable'));
      }
      log.debug("Leaving purgeExpiredMinted().");
      return own.call(this, kind, options);
    };
  });
  const fill = function (db, count, prefix) {
    log.debug("Entering fill(). " + prefix);
    for (let i = 0; i < count; i++) {
      db.rows.set(prefix + '\u0000default\u0000' + i,
                  { handle: 'test.expiring', realm: 'default',
                    key: prefix + i, body: 'x', writtenAt: now,
                    expiresAt: now - 1 });
    }
    log.debug("Leaving fill().");
  };
  fill(cellDb, 5000 + 3, 'c');
  fill(globalDb, 5000 + 7, 'g');
  const both = tieredStore.create({ global: globalDb, cell: cellDb,
                                    cellId: 'test-cell' });
  minted.reset();
  minted.setDriver(both, 'postgres');
  t.equal(jobs[1].off(), '',
          'in a tiered store the global tier\'s purge is on');
  const cellRun = await minted.purgeExpired(Date.now());
  const cellExpired = limitsOf.cell.filter(function (x) {
    return x.kind === 'expired';
  });
  t.check(cellRun.tier === 'cell' && cellRun.expired === 5003 &&
          cellDb.rows.size === 0 && globalDb.rows.size === 5007 &&
          limitsOf.global.length === 0,
          'THE CELL\'S PURGE DELETES ONLY THE CELL\'S ROWS: the global tier ' +
          'is not asked at all',
          JSON.stringify([cellRun, cellDb.rows.size, globalDb.rows.size,
                          limitsOf.global.length]));
  t.check(cellExpired.length === 2 && cellExpired.every(function (x) {
    return x.limit === 5000 && x.tier === undefined;
  }), 'with its OWN limit per batch — two batches for 5003 rows, each ' +
      'of 5000, the tier name consumed by the tiered driver',
          JSON.stringify(cellExpired));
  const globalRun = await minted.purgeExpired(Date.now(), 'global');
  const globalExpired = limitsOf.global.filter(function (x) {
    return x.kind === 'expired';
  });
  t.check(globalRun.tier === 'global' && globalRun.expired === 5007 &&
          globalDb.rows.size === 0 && globalExpired.length === 2 &&
          globalExpired.every(function (x) {
            return x.limit === 5000;
          }) && cellExpired.length ===
            limitsOf.cell.filter(function (x) {
              return x.kind === 'expired';
            }).length,
          'and the global tier\'s purge deletes only the global rows, in ' +
          'its own batches, without asking the cell',
          JSON.stringify([globalRun, globalExpired]));
  // The global database unreachable: the cell's job still purges and
  // counts what it can; the orphan kind, which needs the global realm
  // registry, is SKIPPED rather than failed (#1313): no tier is asked, so
  // nothing is deleted on a guess, and the run succeeds saying why.
  // The lines the purge logs, caught at bunyan's prototype as
  // cache_registry.js does, to hold "once per outage".
  const bunyanProto = require('bunyan').createLogger({ name: 'probe' })
    .constructor.prototype;
  const ownWarn = bunyanProto.warn;
  const ownInfo = bunyanProto.info;
  const logged = [];
  bunyanProto.warn = function (msg) {
    logged.push(String(msg));
    return ownWarn.apply(this, arguments);
  };
  bunyanProto.info = function (msg) {
    logged.push(String(msg));
    return ownInfo.apply(this, arguments);
  };
  const linesOf = function (re) {
    log.debug("Entering linesOf().");
    log.debug("Leaving linesOf().");
    // The test's own ✓/✗ lines go through bunyan too, and may quote a
    // logged line in their detail; only the service's lines are counted.
    return logged.filter(function (line) {
      return !/^\s*[\u2713\u2717]/.test(line) && re.test(line);
    });
  };
  globalDown = true;
  fill(cellDb, 4, 'down');
  fill(globalDb, 2, 'unreached');
  const downRun = await minted.purgeExpired(Date.now());
  t.check(downRun.expired === 4 && cellDb.rows.size === 0 &&
          downRun.failures.length === 0 && downRun.skipped.length === 1 &&
          downRun.skipped[0].kind === 'orphan' &&
          /global realm registry could not be read/.test(
            downRun.skipped[0].message),
          'AN UNREACHABLE GLOBAL DATABASE DOES NOT LOSE THE CELL\'S PURGE: ' +
          'the cell\'s expired rows are deleted and counted, and the orphan ' +
          'kind (judged against the global registry) is SKIPPED, not failed',
          JSON.stringify(downRun));
  fill(cellDb, 3, 'down2');
  let cellJobError = null;
  const skipRun = await jobs[0].run().catch(function (e) {
    log.debug("Caught in the cell job's run: " + ((e && e.message) || e));
    cellJobError = e;
  });
  t.check(!cellJobError && !!skipRun && skipRun.orphanCheck === 'skipped' &&
          skipRun.orphanSkippedRuns === 1 && skipRun.expired === 3 &&
          /^The orphan check was skipped: the global realm registry could /
            .test(skipRun.why) && /3 expired/.test(skipRun.why),
          'THE CELL JOB\'S RUN SUCCEEDS with the orphan check skipped: the ' +
          'result says so, counts the skipped run and carries a why the ' +
          'scheduler writes on the row',
          cellJobError ? cellJobError.message : JSON.stringify(skipRun));
  const skipAgain = await jobs[0].run();
  t.check(skipAgain.orphanCheck === 'skipped' &&
          skipAgain.orphanSkippedRuns === 2 &&
          linesOf(/STS-STORE-0164.*this cell's store/).length === 1,
          'and the skip is logged ONCE per outage (STS-STORE-0164), however ' +
          'many runs skip it; the count goes on in each run\'s result',
          JSON.stringify([skipAgain.orphanSkippedRuns,
                          linesOf(/STS-STORE-0164/)]));
  t.check(linesOf(/STS-STORE-0065/).length === 0,
          'no run of the cell job is logged as failed while only the ' +
          'registry is unreadable', JSON.stringify(linesOf(/STS-STORE-0065/)));
  // A failure of the cell's OWN delete is still a failure, skip or not.
  const cellPurge = cellDb.purgeExpiredMinted;
  cellDb.purgeExpiredMinted = function (kind, options) {
    log.debug("Entering purgeExpiredMinted(), the cell's, which fails.");
    if (kind === 'expired') {
      log.debug("Leaving purgeExpiredMinted(). Refused.");
      return Promise.reject(new Error('the cell database refused it'));
    }
    log.debug("Leaving purgeExpiredMinted().");
    return cellPurge.call(this, kind, options);
  };
  await jobs[0].run().catch(function (e) {
    log.debug("Caught in the cell job's run: " + ((e && e.message) || e));
    cellJobError = e;
  });
  cellDb.purgeExpiredMinted = cellPurge;
  t.check(!!cellJobError && /this cell's store/.test(cellJobError.message) &&
          /expired: [^;]*the cell database refused it/
            .test(cellJobError.message) &&
          /orphan check was skipped/.test(cellJobError.message) &&
          !/orphan:/.test(cellJobError.message) &&
          linesOf(/STS-STORE-0065/).length === 1,
          'but a failure of the cell\'s own purge still fails the run, once, ' +
          'under STS-STORE-0065, naming the kind that failed and the skip',
          cellJobError ? cellJobError.message : 'it succeeded');
  let globalJobError = null;
  await jobs[1].run().catch(function (e) {
    log.debug("Caught in the global job's run: " + ((e && e.message) || e));
    globalJobError = e;
  });
  t.check(!!globalJobError &&
          /the global tier's store/.test(globalJobError.message) &&
          /expired/.test(globalJobError.message) &&
          globalDb.rows.size === 2,
          'and the global job\'s run fails on its own, its rows left for ' +
          'the next run', globalJobError ? globalJobError.message : 'ok');
  t.check(errorCodes.isKnown('STS-STORE-0162') &&
          errorCodes.isKnown('STS-STORE-0065') &&
          errorCodes.isKnown('STS-STORE-0164'),
          'the global tier\'s failure has a code of its own, STS-STORE-0162, ' +
          'beside the cell\'s STS-STORE-0065, and the skip STS-STORE-0164');
  globalDown = false;
  const madeAgain = await jobs[0].run();
  t.check(madeAgain.orphanCheck === 'made' && !madeAgain.why &&
          linesOf(/makes its orphan check again.*after 3 run\(s\)/)
            .length === 1,
          'once the registry can be read the check is made again, the run ' +
          'carries no why, and one line says it recovered and how many ' +
          'runs skipped it', JSON.stringify([madeAgain,
            linesOf(/orphan check again/)]));
  await jobs[0].run();
  t.equal(linesOf(/orphan check again/).length, 1,
          'and says it only once');
  bunyanProto.warn = ownWarn;
  bunyanProto.info = ownInfo;
  globalDown = false;
  const recovered = await minted.purgeExpired(Date.now(), 'global');
  t.check(recovered.expired === 2 && recovered.failures.length === 0 &&
          globalDb.rows.size === 0,
          'and once the global database answers, the next run finishes it',
          JSON.stringify(recovered));

  // -------------------------------------------------------------------------
  // 6d. THE TOMBSTONES, ONE TIER AT A TIME (#1313). The sweep was the last
  //     purge sent to both databases through Promise.all: a down global
  //     database lost the cell's count with it, and every cell's leader
  //     swept the shared global table. Each tier is its own job now, in
  //     its own batches; the global one is a GLOBAL_JOBS job (cell_tiers.js
  //     asserts the claim). A single database is batched the same way,
  //     with no tier named (#1315).
  // -------------------------------------------------------------------------
  t.log.info('=== the tombstone sweep, one tier at a time (#1313) ===');
  const tombCalls = { global: [], cell: [] };
  [['global', globalDb], ['cell', cellDb]].forEach(function (pair) {
    pair[1].purgeTombstones = function (beforeMs, options) {
      log.debug("Entering purgeTombstones(), the " + pair[0] + " tier.");
      tombCalls[pair[0]].push({ beforeMs: beforeMs, args: arguments.length,
                                options: options });
      if (pair[0] === 'global' && globalDown) {
        log.debug("Leaving purgeTombstones(). Unreachable.");
        return Promise.reject(new Error('the global database is ' +
                                        'unreachable'));
      }
      const limit = options && options.limit > 0 ? options.limit : Infinity;
      let gone = 0;
      pair[1].rows.forEach(function (row, k) {
        if (gone < limit && row.body === 'TOMBSTONE' &&
            Number(row.writtenAt) < beforeMs) {
          pair[1].rows.delete(k);
          gone++;
        }
      });
      log.debug("Leaving purgeTombstones().");
      return Promise.resolve(gone);
    };
  });
  const bury = function (db, count, prefix) {
    log.debug("Entering bury(). " + prefix);
    for (let i = 0; i < count; i++) {
      db.rows.set(prefix + '\u0000default\u0000' + i,
                  { handle: 'test.expiring', realm: 'default',
                    key: prefix + i, body: 'TOMBSTONE', writtenAt: 0,
                    expiresAt: null });
    }
    log.debug("Leaving bury().");
  };
  // The jobs: registered at the first flush with the real scheduler (or
  // here, with this fake, when none had been).
  const tombJobs = [];
  minted.ensureTombstoneJob({
    register: function (spec) {
      tombJobs.push(spec);
    },
    job: function () {
      return null;
    }
  });
  const tombJob = function (id) {
    log.debug("Entering tombJob(). " + id);
    const mine = tombJobs.filter(function (j) {
      return j.id === id;
    })[0];
    log.debug("Leaving tombJob().");
    return mine || require('../cluster/scheduler').job(id);
  };
  const cellTombs = tombJob('persistence.tombstone-purge');
  const globalTombs = tombJob('persistence.tombstone-purge-global');
  t.check(!!cellTombs && !!globalTombs &&
          (globalTombs.kind || 'cluster') === 'cluster' &&
          globalTombs.owner === 'persistence/persistence_minted.js' &&
          globalTombs.everyMs() === cellTombs.everyMs() &&
          /batches of 5000/.test(cellTombs.describe),
          'the sweep is ONE cluster job per tier, on the same ten-minute ' +
          'schedule it always had');
  minted.reset();
  minted.setDriver(both, 'postgres');
  t.equal(globalTombs.off(), '',
          'in a tiered store the global tier\'s sweep is on');
  bury(cellDb, 5000 + 3, 'tc');
  bury(globalDb, 5000 + 7, 'tg');
  const cellSwept = await cellTombs.run();
  t.check(cellSwept.removed === 5003 && cellSwept.more === false &&
          cellDb.rows.size === 0 && globalDb.rows.size === 5007 &&
          tombCalls.global.length === 0 && tombCalls.cell.length === 2 &&
          tombCalls.cell.every(function (x) {
            return x.options && x.options.limit === 5000 &&
                   !('tier' in x.options);
          }),
          'THE CELL\'S SWEEP SWEEPS ONLY THE CELL: two batches of its own ' +
          '5000 for 5003 tombstones, the stop test its own, the tier name ' +
          'consumed by the tiered driver, and the global tier not asked',
          JSON.stringify([cellSwept, tombCalls]));
  const globalSwept = await globalTombs.run();
  t.check(globalSwept.removed === 5007 && globalDb.rows.size === 0 &&
          tombCalls.global.length === 2 && tombCalls.cell.length === 2 &&
          tombCalls.global.every(function (x) {
            return x.options && x.options.limit === 5000;
          }),
          'and the global tier\'s sweeps only the global database, in its ' +
          'own batches', JSON.stringify([globalSwept, tombCalls.global]));
  // A backlog larger than one run is left for the next.
  bury(cellDb, 20 * 5000 + 1, 'tb');
  const boundedSweep = await cellTombs.run();
  t.check(boundedSweep.removed === 20 * 5000 && boundedSweep.more === true &&
          cellDb.rows.size === 1,
          'one run sweeps at most its bound and says more remain',
          JSON.stringify(boundedSweep));
  await cellTombs.run();
  // The global database down: the cell's sweep does not notice; the
  // global one fails on its own, under its own code.
  globalDown = true;
  bury(cellDb, 4, 'td');
  bury(globalDb, 2, 'tu');
  logged.length = 0;
  bunyanProto.warn = function (msg) {
    logged.push(String(msg));
    return ownWarn.apply(this, arguments);
  };
  const downSweep = await cellTombs.run();
  let globalSweepError = null;
  await globalTombs.run().catch(function (e) {
    log.debug("Caught in the global sweep: " + ((e && e.message) || e));
    globalSweepError = e;
  });
  // Asked of both, as nothing batching does, the refusal still carries the
  // cell's count.
  bury(cellDb, 5, 'tboth');
  let bothSweepError = null;
  await both.purgeTombstones(Date.now()).catch(function (e) {
    log.debug("Caught in the sweep of both: " + ((e && e.message) || e));
    bothSweepError = e;
  });
  bunyanProto.warn = ownWarn;
  t.check(downSweep.removed === 4 && cellDb.rows.size === 0,
          'A DOWN GLOBAL DATABASE LOSES NO CELL COUNT: the cell\'s sweep ' +
          'sweeps and counts its own', JSON.stringify(downSweep));
  t.check(!!globalSweepError && globalDb.rows.size === 2 &&
          linesOf(/STS-STORE-0165.*the global tier's store/).length === 1 &&
          linesOf(/STS-STORE-0165.*tombstone purge failed/).length === 0 &&
          linesOf(/STS-STORE-0055/).length === 0,
          'and the global tier\'s sweep fails on its own, once, under ' +
          'STS-STORE-0165, its tombstones left for the next run, and its ' +
          'line says the failure once (the database\'s words, not the ' +
          'tiered driver\'s sentence around them, #1315)',
          JSON.stringify(linesOf(/STS-STORE-01|STS-STORE-0055/)));
  t.check(!!bothSweepError && bothSweepError.removed === 5 &&
          bothSweepError.tier === 'global' &&
          /tombstone purge failed/.test(bothSweepError.message),
          'asked of both with no tier, the tiered driver settles them apart: ' +
          'the refusal names the failed tier and carries the cell\'s count',
          bothSweepError ? bothSweepError.message : 'it succeeded');
  globalDown = false;
  t.equal((await globalTombs.run()).removed, 2,
          'and once the global database answers, the next run sweeps it');
  // A SINGLE DATABASE IS BOUNDED TOO (#1315): no tier is named, the limit
  // is, and a backlog larger than a run's cap is left for the next run.
  const lone = fakeDriver('lone');
  const loneCalls = [];
  let loneBacklog = 5000 * 20 + 3;
  lone.purgeTombstones = function (beforeMs, options) {
    log.debug("Entering purgeTombstones(), the only database.");
    loneCalls.push({ beforeMs: beforeMs, options: options || null });
    const limit = Number(options && options.limit) || loneBacklog;
    const n = Math.min(limit, loneBacklog);
    loneBacklog -= n;
    log.debug("Leaving purgeTombstones().");
    return Promise.resolve(n);
  };
  minted.reset();
  minted.setDriver(lone, 'postgres');
  const loneSwept = await cellTombs.run();
  t.check(loneCalls.length === 20 && loneCalls.every(function (c) {
    return c.options && c.options.limit === 5000 && !('tier' in c.options) &&
           c.beforeMs <= Date.now();
  }), 'A SINGLE DATABASE IS SWEPT IN BOUNDED BATCHES (#1315): 20 calls of ' +
      '5000, no tier named', JSON.stringify(loneCalls.slice(0, 2)));
  t.check(loneSwept.removed === 100000 && loneSwept.more === true &&
          loneBacklog === 3,
          'and a backlog larger than a run is left for the next one',
          JSON.stringify([loneSwept, loneBacklog]));
  loneCalls.length = 0;
  const loneNext = await cellTombs.run();
  t.check(loneNext.removed === 3 && loneNext.more === false &&
          loneCalls.length === 1,
          'the next run sweeps the rest in one short batch',
          JSON.stringify([loneNext, loneCalls.length]));
  t.equal(globalTombs.off(), 'this store has no global tier',
          'and the global tier\'s sweep is off there');
  t.check(errorCodes.isKnown('STS-STORE-0165') &&
          errorCodes.isKnown('STS-STORE-0055'),
          'the global tier\'s sweep has a code of its own, STS-STORE-0165, ' +
          'beside the cell\'s (and the only store\'s) STS-STORE-0055');
  minted.reset();
  minted.setDriver(driver, 'postgres');

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
