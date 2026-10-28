// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: user_register_journal.js
//
// ===========================================================================
// A SIGN-IN REWRITES THE PERSON'S REGISTER ROW, SO THE COUNT SURVIVES A
// RESTART AND REACHES THE OTHER WORKERS (#999, 2026-10-27).
//
// `common/admin_stats.js`'s `users` is `realms.map({ persist:
// 'admin_stats.users', merge: 'own' })`, and that facade journals a `set()`
// and nothing else. A record there is edited IN PLACE by every sign-in —
// `authentications++`, the event, `lastAt`, the protocol and method counts —
// and until #999 the only `set()` was the one at creation. So the row in the
// store was the record as it stood at the first flush after that, one
// authentication, and it was never rewritten: on 8081 an account with
// sixty-two accepted credentials read `authentications: 1`, every restart
// restored that frozen row, and the other worker read the same row through
// the fan-in. The portal's "Times you have signed in" (#672) and the
// console's user page both draw it.
//
// `touchUserRecord()` re-sets the key after the edits. Asserted here, against
// the minted journal and a stub store, the way `minted_persistence.js` holds
// the journal itself:
//   1. the first sign-in writes the record, with one authentication;
//   2. a SECOND sign-in leaves the journal dirty and the next flush writes the
//      record again, now with two — the assertion that failed before #999;
//   3. the written record is the record as it stands: the count, the event
//      list, a `lastAt` after `firstAt`;
//   4. a restart (a fresh module state restoring from what the store holds)
//      puts the stored count back, not the count at creation;
//   5. a person created by hand (`noteKnownIdentity()`) is written with the
//      `knownBy` that was set after the record was made.
//
// In process rather than over HTTP because the claim is about what reaches
// the journal between two flushes, which no response shows; the protocol
// suite's `sts_portal_sessions.js` asserts the figure a person sees.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const nodeCrypto = require('crypto');

const config = require('../common/config');
const keystore = require('../common/keystore');
const minted = require('../persistence/persistence_minted');
const replication = require('../persistence/persistence_replication');
const stats = require('../common/admin_stats');

const log = require('bunyan').createLogger({ name: 'user_register_journal',
  level: process.env.LOG_LEVEL || 'info' });

const HANDLE = 'admin_stats.users';
const TAG = 'journal' + process.pid;
const USER = TAG + '-user';
const MADE = TAG + '-made';

/**
 * A store double in the shape `persistence_minted.js` drives, keeping every
 * row it was given and the names each `saveMinted()` upserted.
 *
 * @param origin - the origin the driver claims
 * @returns the driver
 */
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
    // The rows of each saveMinted() call, newest last.
    saves: [],
    origin: function () {
      log.debug("Entering origin().");
      log.debug("Leaving origin().");
      return origin || 'test-origin';
    },
    loadMinted: function (filter) {
      log.debug("Entering loadMinted().");
      const out = Array.from(rows.values()).filter(function (row) {
        return filter.realms.indexOf(row.realm) >= 0;
      });
      log.debug("Leaving loadMinted().");
      return Promise.resolve(out);
    },
    purgeExpiredMinted: function () {
      log.debug("Entering purgeExpiredMinted().");
      log.debug("Leaving purgeExpiredMinted().");
      return Promise.resolve(0);
    },
    saveMinted: function (upserts, deletes) {
      log.debug("Entering saveMinted().");
      upserts.forEach(function (row) {
        rows.set(id(row.handle, row.realm, row.key),
                 { handle: row.handle, realm: row.realm, key: row.key,
                   keySealed: row.keySealed || '',
                   body: row.body, writtenAt: Date.now(),
                   expiresAt: row.expiresAt === undefined ? null
                     : row.expiresAt });
      });
      deletes.forEach(function (row) {
        rows.delete(id(row.handle, row.realm, row.key));
      });
      this.saves.push({ upserts: upserts.slice(), deletes: deletes.slice() });
      log.debug("Leaving saveMinted().");
      return Promise.resolve();
    },
    readMinted: function (handle, realm, key) {
      log.debug("Entering readMinted().");
      log.debug("Leaving readMinted().");
      return Promise.resolve(rows.get(id(handle, realm, key)) || null);
    },
    purgeMinted: function () {
      log.debug("Entering purgeMinted().");
      log.debug("Leaving purgeMinted().");
      return Promise.resolve(0);
    }
  };
}

/**
 * Arms the keystore with a file key-encryption key, so the flush can seal.
 *
 * @param dir - a scratch directory for the key file
 */
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

/**
 * One recorded sign-in for the person, as the sign-in screen records one.
 *
 * @param username - the person
 * @param n - which sign-in this is, for the session id
 */
function signedIn(username, n) {
  log.debug("Entering signedIn().");
  stats.recordAuthentication({
    presented: username, protocol: 'OpenID Connect', method: 'password',
    sessionId: TAG + '-sid-' + n, amr: ['pwd'], acr: '1'
  });
  log.debug("Leaving signedIn().");
}

/**
 * The person a stored row is filed under. A `merge: 'own'` store files a row
 * under `<base64url(key)>.<base64url(origin)>` (`persistence_minted.js`,
 * `storedKey()`), so that every process keeps a row of its own; the sealed
 * name beside the row is that whole string, and the person is its first
 * half.
 *
 * @param row - a stored row
 * @returns the person's key, or null
 */
function personOfRow(row) {
  log.debug("Entering personOfRow().");
  const name = minted.nameOfRow(row);
  if (name === null || name === undefined) {
    log.debug("Leaving personOfRow(). Unnamed.");
    return null;
  }
  const dot = String(name).indexOf('.');
  const person = dot > 0
    ? Buffer.from(String(name).slice(0, dot), 'base64url').toString('utf8')
    : String(name);
  log.debug("Leaving personOfRow().");
  return person;
}

/**
 * The register row the store holds for a person, opened.
 *
 * @param driver - the store double
 * @param username - the person
 * @returns `{ row, record }`, or nulls
 */
function storedRecord(driver, username) {
  log.debug("Entering storedRecord().");
  let found = null;
  driver.rows.forEach(function (row) {
    if (row.handle === HANDLE && personOfRow(row) === username) {
      found = row;
    }
  });
  let record = null;
  if (found) {
    try {
      record = JSON.parse(keystore.open(found.body));
    } catch (e) {
      // Reported through the assertion that reads `record`.
      log.debug("Caught in storedRecord(): " + ((e && e.message) || e));
    }
  }
  log.debug("Leaving storedRecord().");
  return { row: found, record: record };
}

/**
 * Whether a saveMinted() call upserted the person's register row.
 *
 * @param save - one entry of `driver.saves`
 * @param username - the person
 * @returns true when it did
 */
function saveWrote(save, username) {
  log.debug("Entering saveWrote().");
  const hit = save.upserts.some(function (row) {
    return row.handle === HANDLE && personOfRow(row) === username;
  });
  log.debug("Leaving saveWrote().");
  return hit;
}

async function run(t) {
  log.debug("Entering run().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'user-register-journal-'));
  await armKeystore(dir);
  const driver = fakeDriver('process-a');
  config.setOverride('global.mode', 'product');
  config.setOverride('persistence.minted', true);
  minted.reset();
  minted.setDriver(driver, 'postgres');
  t.check(minted.enabled(), 'the minted journal is on for this store double');

  // 1. The first sign-in writes the record.
  signedIn(USER, 1);
  await minted.flush();
  const first = storedRecord(driver, USER);
  t.check(!!first.record && first.record.authentications === 1,
          '1. the first sign-in writes the register row, with one ' +
          'authentication',
          JSON.stringify(first.record && {
            authentications: first.record.authentications }));

  // 2. THE SECOND SIGN-IN REACHES THE JOURNAL. Before #999 nothing set the
  //    key again, the journal stayed clean, and the next flush wrote nothing
  //    for this person.
  const savesBefore = driver.saves.length;
  signedIn(USER, 2);
  t.check(minted.dirty(),
          '2a. a second sign-in leaves the journal dirty (its audit rows ' +
          'alone would; 2b is the assertion about the register)');
  await minted.flush();
  const rewrote = driver.saves.slice(savesBefore).some(function (save) {
    return saveWrote(save, USER);
  });
  t.check(rewrote,
          '2b. and the next flush writes the register row AGAIN, not only ' +
          'at creation',
          driver.saves.length + ' save(s) so far');

  // 3. What was written is the record as it stands.
  const second = storedRecord(driver, USER);
  t.check(!!second.record && second.record.authentications === 2,
          '3a. the stored count is two',
          JSON.stringify(second.record && {
            authentications: second.record.authentications }));
  t.check(!!second.record && Array.isArray(second.record.events) &&
          second.record.events.length === 2 &&
          second.record.events[1].sessionId === TAG + '-sid-2',
          '3b. and the stored event list carries both sign-ins');
  t.check(!!second.record && second.record.lastAt >= second.record.firstAt &&
          second.record.firstAt === first.record.firstAt,
          '3c. firstAt is the first sign-in\'s and lastAt has moved with ' +
          'the second — the frozen row on 8081 had the two equal');

  // 4. A RESTART PUTS THE STORED COUNT BACK. A fresh module state restores
  //    from what the store holds, seeded here exactly as the flush left it
  //    but with the count the store would carry after a longer life, so the
  //    assertion is about the restore reading the ROW and not this
  //    process's own memory of three sign-ins.
  signedIn(USER, 3);
  await minted.flush();
  const third = storedRecord(driver, USER);
  t.check(!!third.record && third.record.authentications === 3,
          '4a. a third sign-in is three in the store');
  const next = fakeDriver('process-a');
  const seeded = Object.assign({}, third.record, { authentications: 7 });
  next.rows.set('seed', Object.assign({}, third.row, {
    body: keystore.seal(JSON.stringify(seeded)) }));
  minted.reset();
  minted.setDriver(next, 'postgres');
  await minted.restore();
  const restored = stats.userDetail(USER);
  t.check(!!restored && !!restored.user &&
          restored.user.authentications === 7,
          '4b. after a restore the register answers the count the store ' +
          'holds — what a restart reads — rather than the one at creation',
          JSON.stringify({ authentications: restored && restored.user &&
                           restored.user.authentications }));
  t.equal(minted.dirty(), false,
          '4c. and a restore journals nothing back');

  // 5. A person made by hand is written with `knownBy` set after creation.
  stats.noteKnownIdentity(MADE, 'created');
  await minted.flush();
  const made = storedRecord(next, MADE);
  t.check(!!made.record && made.record.knownBy === 'created' &&
          made.record.authentications === 0,
          '5. noteKnownIdentity() writes the record with the knownBy it set ' +
          'after userRecord() made it',
          JSON.stringify(made.record && { knownBy: made.record.knownBy }));

  config.clearOverride('global.mode');
  config.clearOverride('persistence.minted');
  minted.reset();
  replication.reset();
  disarmKeystore();
  fs.rmSync(dir, { recursive: true, force: true });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'user register journal',
  describe: 'a sign-in re-sets the person\'s register record so the minted ' +
            'journal writes it again, and a restart restores the count the ' +
            'store holds (#999)',
  run: run
};
