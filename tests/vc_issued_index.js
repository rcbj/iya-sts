// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// ===========================================================================
// tests/vc_issued_index.js — THE ISSUED REGISTER'S TWO INDEXES (rcbj,
// 2026-10-17: "lists are maintained as you go rather than ... full table
// scans that do not scale").
//
// `oid4vc/vc_issued.ts` over plain Maps, every store counted:
//   1. rows recorded before the indexes existed are indexed ONCE, on the
//      first read, and the mark keeps any later read from scanning again;
//   2. a person's history, Remove and `rowsForSubject()`, and a wallet's
//      notification, read the indexes and scan no table;
//   3. a row this process does not hold, or cannot read, KEEPS its key
//      (2026-10-20: "not here" is not "gone" in a persisted store, and a
//      pruned entry was lost for good); a row the size bound evicts and one
//      this module deletes (`forget()`) leave both indexes at once; a row
//      that is here and names another subject is pruned; a read that throws
//      is logged once with STS-VC-0151 and the entry is left as it was;
//   4. one person's credential is still not another's to remove;
//   5. an entry an older reader pruned is given back by the `-v2` backfill.
// ===========================================================================
'use strict';
const VcIssued = require('../oid4vc/vc_issued').VcIssued;
const stsCrypto = require('../common/crypto');
const log = require('bunyan').createLogger({ name: 'vc_issued_index',
  level: process.env.LOG_LEVEL || 'info' });

// A Map whose full scans are counted.
function counted() {
  const m = new Map();
  m.scans = 0;
  const forEach = m.forEach.bind(m);
  m.forEach = function (fn) {
    m.scans += 1;
    return forEach(fn);
  };
  return m;
}

function register(max) {
  log.debug("Entering register().");
  const store = counted();
  const subjectIndex = counted();
  const notificationIndex = counted();
  const errors = [];
  const quiet = { debug: function () {}, info: function () {},
                  warn: function () {},
                  error: function (line) {
                    errors.push(String(line));
                  } };
  const issued = new VcIssued({
    log: quiet,
    nameForSubject: function () {
      return '';
    },
    subjectForName: function () {
      return '';
    },
    jwkThumbprint: stsCrypto.jwkThumbprint,
    artifactRevokedByKey: function () {
      return null;
    },
    artifactByKey: function () {
      return null;
    },
    revokeArtifact: function () {
      return false;
    },
    statusOf: function () {
      return 0;
    },
    setStatus: function () {
      return true;
    },
    store: store, subjectIndex: subjectIndex,
    notificationIndex: notificationIndex,
    maxRows: function () {
      return max || 1000;
    }
  });
  log.debug("Leaving register().");
  return { issued: issued, store: store, subjectIndex: subjectIndex,
           notificationIndex: notificationIndex, errors: errors };
}

function holderJwk() {
  return require('crypto').generateKeyPairSync('ec', { namedCurve: 'P-256' })
    .publicKey.export({ format: 'jwk' });
}

function record(r, subject, n) {
  return r.issued.record({ credential: 'cred-' + subject + '-' + n +
                             '.payload.sig',
                           format: 'dc+sd-jwt', configId: 'IdentityCredential',
                           subject: subject, holderJwk: holderJwk(),
                           expiresAt: Date.now() + 3600 * 1000,
                           statusKey: subject + '-' + n,
                           notificationId: 'n-' + subject + '-' + n });
}

async function run(t) {
  log.debug("Entering run().");
  const ALICE = 'urn:uuid:aaaaaaaa-0000-0000-0000-000000000001';
  const BOB = 'urn:uuid:bbbbbbbb-0000-0000-0000-000000000002';

  t.log.info('=== 1. the backfill, once ===');
  const r = register();
  ['1', '2', '3'].forEach(function (n) {
    record(r, ALICE, n);
  });
  record(r, BOB, '1');
  // As if recorded before the indexes existed: drop what record() wrote.
  r.subjectIndex.clear();
  r.notificationIndex.clear();
  r.store.scans = 0;
  const first = r.issued.historyForSubject(ALICE);
  const scansForBackfill = r.store.scans;
  const second = r.issued.historyForSubject(ALICE);
  t.check(first.length === 3 && second.length === 3 &&
          scansForBackfill === 1 && r.store.scans === 1,
          '1. rows recorded before the indexes are indexed by one scan, ' +
          'and the next read scans nothing',
          JSON.stringify({ first: first.length, scans: r.store.scans }));

  t.log.info('=== 2. reads through the indexes ===');
  const fresh = register();
  ['1', '2'].forEach(function (n) {
    record(fresh, ALICE, n);
  });
  record(fresh, BOB, '1');
  fresh.issued.historyForSubject(ALICE);
  fresh.store.scans = 0;
  const history = fresh.issued.historyForSubject(ALICE);
  const rows = fresh.issued.rowsForSubject(ALICE);
  const told = fresh.issued.noteWalletEvent('n-' + ALICE + '-1',
                                            'credential_deleted');
  const removed = fresh.issued.removeForSubject(ALICE, history[0].id,
                                                'test');
  const after = fresh.issued.historyForSubject(ALICE);
  t.check(history.length === 2 && rows.length === 2 && told === 1 &&
          removed.ok && after.some(function (h) {
            return h.status === 'removed';
          }) && after.some(function (h) {
            return h.walletEvent === 'credential_deleted';
          }) && fresh.store.scans === 0 && fresh.subjectIndex.scans === 0 &&
          fresh.notificationIndex.scans === 0,
          '2. history, rowsForSubject, a notification and Remove scan no ' +
          'table', JSON.stringify({ scans: fresh.store.scans,
                                    told: told, removed: removed }));

  t.log.info('=== 3. a row not here, and a row gone ===');
  const aliceKey = stsCrypto.digest('sha256', ALICE, 'base64url');
  const bobKey = stsCrypto.digest('sha256', BOB, 'base64url');
  const jwsKey = function (subject, n) {
    return 'jws:' + fresh.issued.digestOf('cred-' + subject + '-' + n +
                                          '.payload.sig');
  };
  // 3a. NOT HERE: as a row another process wrote that has not arrived, or
  // one the restore could not open. Held aside, then put back.
  const notHereKey = jwsKey(ALICE, '2');
  const heldAside = fresh.store.get(notHereKey);
  fresh.store.delete(notHereKey);
  const without = fresh.issued.historyForSubject(ALICE);
  const toldWithout = fresh.issued.noteWalletEvent('n-' + ALICE + '-2',
                                                   'credential_accepted');
  const keptEntry = fresh.subjectIndex.get(aliceKey);
  const keptNote = fresh.notificationIndex.get('n-' + ALICE + '-2');
  fresh.store.set(notHereKey, heldAside);
  const back = fresh.issued.historyForSubject(ALICE);
  t.check(without.length === 1 && toldWithout === 0 && keptEntry &&
          keptEntry.keys.indexOf(notHereKey) >= 0 &&
          keptEntry.keys.length === 2 && keptNote &&
          keptNote.keys.indexOf(notHereKey) >= 0 && back.length === 2 &&
          fresh.errors.length === 0,
          '3a. a row this process does not hold is left out of the answer ' +
          'and KEEPS its key in both indexes, so it is listed again once ' +
          'it arrives', JSON.stringify({ without: without.length,
                                         entry: keptEntry, note: keptNote,
                                         back: back.length }));

  // 3b. A READ THAT THROWS: the entry is left whole and the failure is
  // logged once, with its code.
  const realGet = fresh.store.get.bind(fresh.store);
  fresh.store.get = function (key) {
    if (key === notHereKey) {
      throw new Error('the store could not answer');
    }
    return realGet(key);
  };
  const throwing = fresh.issued.historyForSubject(ALICE);
  const toldThrowing = fresh.issued.noteWalletEvent('n-' + ALICE + '-2',
                                                    'credential_accepted');
  fresh.store.get = realGet;
  const afterThrow = fresh.subjectIndex.get(aliceKey);
  const coded = fresh.errors.filter(function (line) {
    return line.indexOf('STS-VC-0151') >= 0;
  });
  t.check(throwing.length === 1 && toldThrowing === 0 && afterThrow &&
          afterThrow.keys.length === 2 &&
          afterThrow.keys.indexOf(notHereKey) >= 0 &&
          fresh.notificationIndex.get('n-' + ALICE + '-2') &&
          coded.length === 2 &&
          fresh.issued.historyForSubject(ALICE).length === 2,
          '3b. a read that throws leaves both index entries as they were, ' +
          'logged once per read with STS-VC-0151',
          JSON.stringify({ throwing: throwing.length, entry: afterThrow,
                           errors: fresh.errors }));

  // 3c. A ROW HERE THAT NAMES ANOTHER SUBJECT: a fact about the row, pruned.
  const strayKey = jwsKey(BOB, '1');
  const aliceEntry = fresh.subjectIndex.get(aliceKey);
  fresh.subjectIndex.set(aliceKey, { keys: aliceEntry.keys.concat([strayKey]),
                                     expiresAt: aliceEntry.expiresAt });
  const stray = fresh.issued.historyForSubject(ALICE);
  const strayEntry = fresh.subjectIndex.get(aliceKey);
  t.check(stray.length === 2 && strayEntry.keys.indexOf(strayKey) < 0 &&
          strayEntry.keys.length === 2,
          '3c. a key whose row is here and names another subject is pruned',
          JSON.stringify(strayEntry));

  // 3d. FORGOTTEN: this module deleted it, so both indexes drop it at once.
  fresh.issued.forget('cred-' + BOB + '-1.payload.sig');
  t.check(!fresh.subjectIndex.get(bobKey) &&
          !fresh.notificationIndex.get('n-' + BOB + '-1'),
          '3d. a forgotten row leaves both indexes at once',
          JSON.stringify(fresh.subjectIndex.get(bobKey) || null));

  // 3e. EVICTED BY THE SIZE BOUND: record() reads the rows makeRoom() will
  // take, and each one it took leaves both indexes.
  const bounded = register(2);
  record(bounded, ALICE, '1');
  record(bounded, ALICE, '2');
  const oldest = 'jws:' + bounded.issued.digestOf('cred-' + ALICE +
                                                   '-1.payload.sig');
  record(bounded, BOB, '1');
  const boundedAlice = bounded.subjectIndex.get(aliceKey);
  t.check(!bounded.store.has(oldest) && bounded.store.size === 2 &&
          boundedAlice && boundedAlice.keys.length === 1 &&
          boundedAlice.keys.indexOf(oldest) < 0 &&
          !bounded.notificationIndex.get('n-' + ALICE + '-1') &&
          bounded.notificationIndex.get('n-' + ALICE + '-2') &&
          bounded.issued.historyForSubject(ALICE).length === 1,
          '3e. a row the size bound evicts leaves both indexes as it goes',
          JSON.stringify({ size: bounded.store.size, entry: boundedAlice }));

  t.log.info('=== 4. somebody else\'s ===');
  const theirs = register();
  record(theirs, ALICE, '1');
  record(theirs, BOB, '1');
  const bobsId = theirs.issued.historyForSubject(BOB)[0].id;
  const refused = theirs.issued.removeForSubject(ALICE, bobsId, 'test');
  t.check(refused.ok === false &&
          theirs.issued.historyForSubject(BOB)[0].status === 'valid',
          '4. alice naming bob\'s credential is refused, and it stays valid',
          JSON.stringify(refused));

  t.log.info('=== 5. the -v2 backfill gives back a pruned entry ===');
  const pruned = register();
  record(pruned, ALICE, '1');
  record(pruned, ALICE, '2');
  // As an older reader left it: one key pruned, and the realm marked as
  // indexed by the -v1 scan.
  const kept = pruned.subjectIndex.get(aliceKey);
  pruned.subjectIndex.set(aliceKey, { keys: kept.keys.slice(0, 1),
                                      expiresAt: kept.expiresAt });
  pruned.subjectIndex.delete('#indexed-v2');
  pruned.subjectIndex.set('#indexed-v1', { at: 1, expiresAt: 0 });
  const restored = pruned.issued.historyForSubject(ALICE);
  t.check(restored.length === 2 &&
          pruned.subjectIndex.get(aliceKey).keys.length === 2 &&
          !pruned.subjectIndex.get('#indexed-v1') &&
          !!pruned.subjectIndex.get('#indexed-v2'),
          '5. a realm marked by the -v1 scan is indexed once more, which ' +
          'gives back a key an older reader pruned',
          JSON.stringify(pruned.subjectIndex.get(aliceKey)));

  // THE REPORTS' TWO FIELDS (#1021): the holder key's algorithm and the
  // channel the request came by are kept on the copy, and read back.
  const walletRow = r.issued.record({ credential: 'cred-wallet.payload.sig',
    format: 'dc+sd-jwt', configId: 'IdentityCredential', subject: ALICE,
    holderJwk: holderJwk(), expiresAt: Date.now() + 3600 * 1000,
    holderAlg: 'ES256', channel: 'web' });
  const walletCopy = r.issued.rowByKey(walletRow);
  t.check(!!walletCopy && walletCopy.credentials[0].holderAlg === 'ES256' &&
          walletCopy.credentials[0].channel === 'web',
          'a copy keeps its holder algorithm and channel (#1021)',
          JSON.stringify(walletCopy && walletCopy.credentials[0]));
  log.debug("Leaving run().");
}

module.exports = {
  name: 'vc_issued_index',
  describe: 'The issued register\'s subject and notification indexes: one ' +
            'backfill per realm, no table scan for a person\'s history, ' +
            'Remove or a wallet\'s notification, a key kept for a row not ' +
            'here or unreadable, and pruned for one verifiably gone',
  run: run
};
