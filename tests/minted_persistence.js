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
    loadMinted: function () {
      log.debug("Entering loadMinted().");
      log.debug("Leaving loadMinted().");
      return Promise.resolve(Array.from(rows.values()));
    },
    saveMinted: function (upserts, deletes) {
      log.debug("Entering saveMinted().");
      upserts.forEach(function (row) {
        rows.set(id(row.handle, row.realm, row.key),
                 { handle: row.handle, realm: row.realm, key: row.key,
                   body: row.body, writtenAt: Date.now() });
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
    purgeMinted: function (before) {
      log.debug("Entering purgeMinted().");
      let gone = 0;
      rows.forEach(function (row, k) {
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
  t.check(flaky.rows.has('test.retry default ' + expectedKey),
          'and the row that finally lands is under that key, as an upsert ' +
          'rather than a delete of a name nothing holds');
  // Put back the driver section 6 restores from: `restore()` reads whichever
  // driver is installed, and leaving this one in place made retention count
  // this section's rows.
  retried.delete('alice');
  minted.reset();
  minted.setDriver(driver, 'postgres');

  // -------------------------------------------------------------------------
  // 6. RETENTION. A month-old store must not restore a month of dead sessions.
  // -------------------------------------------------------------------------
  t.log.info('=== retention ===');
  driver.rows.forEach(function (row) {
    row.writtenAt = Date.now() - (30 * 24 * 60 * 60 * 1000);
  });
  sessions.clear();
  config.setOverride('persistence.mintedRetention', 7 * 24 * 60 * 60 * 1000);
  await minted.restore();
  t.equal(sessions.size, 0,
          'a row older than persistence.mintedRetention is not restored');
  t.equal(driver.rows.size, 0,
          'AND IT IS DELETED RATHER THAN SKIPPED. Skipping alone would leave ' +
          'every row this service has ever written in the table for ever, ' +
          'and every start would read them all again in order to skip them ' +
          'again');

  // -------------------------------------------------------------------------
  // 7. DEVELOPMENT MODE WRITES NOTHING, which is the property every other
  //    test in this repository and every job in the parent suite depends on.
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
  // The arm above is the promise; this is its one exception, and it is not a
  // softening of it. A dispatched run is several processes against one store,
  // and what they mint has to be in that store or they disagree: a token
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

  delete process.env.STS_WORKERS_DISPATCH;
  minted.reset();
  minted.setDriver(fakeDriver('process-a'), 'postgres');
  t.equal(minted.enabled(), false,
          'and WORKERS ALONE ARE NOT THE CONDITION — with nothing dispatched ' +
          'the children answer no request, so there is no second process to ' +
          'disagree with and the promise above is unchanged');
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
