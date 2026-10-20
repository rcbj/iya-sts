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
//   3. a row gone from the register (the size bound evicts one without this
//      module seeing it) is pruned from the index when next read, and one
//      this module deletes (`forget()`) leaves it at once;
//   4. one person's credential is still not another's to remove.
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

function register() {
  log.debug("Entering register().");
  const store = counted();
  const subjectIndex = counted();
  const notificationIndex = counted();
  const quiet = { debug: function () {}, info: function () {},
                  warn: function () {}, error: function () {} };
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
      return 1000;
    }
  });
  log.debug("Leaving register().");
  return { issued: issued, store: store, subjectIndex: subjectIndex,
           notificationIndex: notificationIndex };
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

  t.log.info('=== 3. a row gone from the register ===');
  const evictedKey = 'jws:' + fresh.issued.digestOf('cred-' + ALICE +
                                                     '-2.payload.sig');
  fresh.store.delete(evictedKey);
  const pruned = fresh.issued.historyForSubject(ALICE);
  const entry = fresh.subjectIndex.get(stsCrypto.digest('sha256', ALICE,
                                                        'base64url'));
  fresh.issued.forget('cred-' + BOB + '-1.payload.sig');
  const bobEntry = fresh.subjectIndex.get(stsCrypto.digest('sha256', BOB,
                                                           'base64url'));
  t.check(pruned.length === 1 && entry && entry.keys.length === 1 &&
          entry.keys.indexOf(evictedKey) < 0 && !bobEntry &&
          !fresh.notificationIndex.get('n-' + BOB + '-1'),
          '3. an evicted row is pruned from the index on the next read, and ' +
          'a forgotten one leaves both indexes at once',
          JSON.stringify({ pruned: pruned.length, entry: entry,
                           bob: bobEntry || null }));

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
  log.debug("Leaving run().");
}

module.exports = {
  name: 'vc_issued_index',
  describe: 'The issued register\'s subject and notification indexes: one ' +
            'backfill per realm, no table scan for a person\'s history, ' +
            'Remove or a wallet\'s notification, and stale keys pruned',
  run: run
};
