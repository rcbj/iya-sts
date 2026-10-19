// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: session_index.js
//
// `sts_sessions` is written in the same transaction as the sealed session
// body (#350). The failure is a column that does not match the row that was
// sealed, which no HTTP client can see while the process still holds the map.

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const nodeCrypto = require('crypto');

const config = require('../common/config');
const realms = require('../common/realms');
const keystore = require('../common/keystore');
const stats = require('../common/admin_stats');
const minted = require('../persistence/persistence_minted');
const tiers = require('../persistence/tiers');
const postgres = require('../persistence/persistence_postgres');
const replication = require('../persistence/persistence_replication');
const scheduler = require('../cluster/scheduler');
const authn = require('../authn/authn');
const storeDouble = require('./tools/store_double');

const log = require('bunyan').createLogger({ name: 'session_index',
  level: process.env.LOG_LEVEL || 'info' });

const REALM = 'session-index';
const SUBJECT = 'urn:uuid:11111111-1111-4111-8111-111111111111';
const TOMBSTONE = '$tombstone$1';

function emptyLoad() {
  log.debug("Entering emptyLoad().");
  log.debug("Leaving emptyLoad().");
  return Promise.resolve([]);
}

function emptySave() {
  log.debug("Entering emptySave().");
  log.debug("Leaving emptySave().");
  return Promise.resolve({ refused: [], merged: [] });
}

function noRead() {
  log.debug("Entering noRead().");
  log.debug("Leaving noRead().");
  return Promise.resolve(null);
}

function testOrigin() {
  log.debug("Entering testOrigin().");
  log.debug("Leaving testOrigin().");
  return 'session-index-origin';
}

function install(driver) {
  log.debug("Entering install().");
  minted.reset();
  minted.endPrefetch();
  const ok = minted.setDriver(driver, 'postgres');
  log.debug("Leaving install().");
  return ok;
}

// The postgres driver calls `row.merge` and then writes the columns that
// call left on the row. Reading them after it returns is the whole point.
function capturingDriver(planted, captured) {
  log.debug("Entering capturingDriver().");
  log.debug("Leaving capturingDriver().");
  return {
    loadMinted: emptyLoad,
    readMinted: noRead,
    origin: testOrigin,
    saveMinted: function (upserts) {
      log.debug("Entering saveMinted().");
      upserts.forEach(function (row) {
        const stored = planted[row.journalKey];
        let body = row.body;
        if (typeof row.merge === 'function' && stored &&
            stored !== row.body) {
          const answer = row.merge(stored);
          if (answer && answer !== row.body) {
            body = answer;
          }
        }
        captured.push({
          journalKey: row.journalKey,
          realm: row.realm,
          key: row.key,
          body: body,
          expiresAt: row.expiresAt,
          index: row.index && typeof row.index === 'object'
            ? Object.assign({}, row.index) : row.index
        });
      });
      log.debug("Leaving saveMinted().");
      return Promise.resolve({ refused: [], merged: [] });
    }
  };
}

function sessionValue(over) {
  log.debug("Entering sessionValue().");
  const row = {
    user: { username: 'alice' },
    subjectId: SUBJECT,
    chosen: true,
    authenticated: true,
    authTime: 200,
    lastSeenAt: 1000,
    startedAt: 500,
    expires: 9000000,
    backsConsole: false
  };
  log.debug("Leaving sessionValue().");
  return Object.assign(row, over || {});
}

function sealSession(value) {
  log.debug("Entering sealSession().");
  const sealed = keystore.seal(JSON.stringify(value), 'minted-rows',
                                tiers.mintedTierOf('authn.sessions'),
                                { realm: REALM });
  log.debug("Leaving sealSession().");
  return sealed;
}

function changeKey(sid) {
  log.debug("Entering changeKey().");
  const key = Buffer.from('authn.sessions').toString('base64url') + '.' +
    Buffer.from(sid).toString('base64url');
  log.debug("Leaving changeKey().");
  return key;
}

function probeIndex(value) {
  log.debug("Entering probeIndex().");
  log.debug("Leaving probeIndex().");
  return value;
}

function indexRow() {
  log.debug("Entering indexRow().");
  log.debug("Leaving indexRow().");
  return {
    expiresAt: null,
    lastSeenAt: 5000,
    startedAt: 1000,
    subjectKey: 'subject-digest',
    usernameKey: 'username-digest',
    chosen: true,
    authenticated: true,
    kind: 'sign-on',
    rpSurface: '',
    parentKey: '',
    backsConsole: false,
    credentialKey: '',
    partnerRelationship: ''
  };
}

function txOf(statements) {
  log.debug("Entering txOf().");
  let begin = -1;
  for (let i = 0; i < statements.length; i++) {
    if (/^\s*BEGIN\b/i.test(statements[i].sql)) {
      begin = i;
      break;
    }
  }
  let out = [];
  if (begin >= 0) {
    out = statements.slice(begin);
    for (let i = begin + 1; i < statements.length; i++) {
      if (/^\s*COMMIT\b/i.test(statements[i].sql)) {
        out = statements.slice(begin, i + 1);
        break;
      }
    }
  }
  log.debug("Leaving txOf().");
  return out;
}

function matching(list, re) {
  log.debug("Entering matching().");
  const found = list.filter(function (one) {
    return re.test(one.sql);
  });
  log.debug("Leaving matching().");
  return found;
}

// A `pg`-shaped double that connects to nothing, installed in the knex_store
// layer's place (`tests/tools/store_double.js`). `answer` is mutated between
// calls so one driver can refuse a row and then accept the next.
function fakePg(statements, answer) {
  log.debug("Entering fakePg().");
  function FakeClient() {}
  FakeClient.prototype.query = function (sql, params) {
    const text = String(sql);
    statements.push({ sql: text, params: params || [] });
    if (/SELECT body FROM sts_minted/i.test(text)) {
      if (answer.selectBody == null) {
        return Promise.resolve({ rows: [], rowCount: 0 });
      }
      return Promise.resolve({
        rows: [{ body: answer.selectBody }], rowCount: 1
      });
    }
    if (/AS done\b/.test(text)) {
      return Promise.resolve({
        rows: [{ done: answer.done }], rowCount: 1
      });
    }
    if (/LIMIT \$5/.test(text)) {
      const rows = answer.bodies || [];
      return Promise.resolve({ rows: rows, rowCount: rows.length });
    }
    return Promise.resolve({ rows: [], rowCount: answer.rowCount });
  };
  FakeClient.prototype.release = function () {};
  FakeClient.prototype.on = function () {};
  FakeClient.prototype.removeListener = function () {};
  FakeClient.prototype.connect = function () { return Promise.resolve(); };
  FakeClient.prototype.end = function () { return Promise.resolve(); };

  function FakePool() {}
  FakePool.prototype.on = function () {};
  FakePool.prototype.connect = function () {
    return Promise.resolve(new FakeClient());
  };
  FakePool.prototype.query = FakeClient.prototype.query;
  FakePool.prototype.end = function () { return Promise.resolve(); };
  log.debug("Leaving fakePg().");
  return { Pool: FakePool, Client: FakeClient };
}

function driverWith(statements, answer) {
  log.debug("Entering driverWith().");
  // The double goes where the driver dials its store since #326: the
  // knex_store layer, not `pg`, which only Knex loads now.
  const restore = storeDouble.install(fakePg(statements, answer));
  let driver = null;
  try {
    driver = postgres.create({
      url: 'postgres://sts_app@localhost:5432/sts',
      log: { debug: function () {}, info: function () {},
             warn: function () {}, error: function () {} }
    });
  } catch (e) {
    log.debug("Caught in driverWith(): " + ((e && e.message) || e));
    log.debug("Leaving driverWith().");
    throw e;
  } finally {
    restore();
  }
  log.debug("Leaving driverWith().");
  return driver;
}

function checkTheCallSite(t) {
  log.debug("Entering checkTheCallSite().");
  const text = fs.readFileSync(path.join(__dirname, '..', 'persistence',
                                          'persistence.js'), 'utf8');
  const at = text.indexOf('minted.backfillSessionIndex()');
  t.check(at > 0, 'persistence.start backfills the session index');
  const before = text.slice(Math.max(0, at - 400), at);
  t.check(before.indexOf('keystore.start()') >= 0,
          'the backfill runs after the keystore has started');
  t.check(text.indexOf('sessionIndexCommitted') > 0,
          'a committed page is not reported as nothing changed');
  t.check(text.indexOf('sessionIndexChangeFloor') > 0,
          'coordinate starts the follower at the walk\'s floor');
  log.debug("Leaving checkTheCallSite().");
}

async function sqlHalf(t) {
  log.debug("Entering sqlHalf().");
  t.log.info('=== the index moves in the minted transaction ===');
  const statements = [];
  const answer = { rowCount: 1, selectBody: null, empty: true, bodies: [] };
  const driver = driverWith(statements, answer);
  const index = indexRow();
  const sessionDelete = /DELETE FROM sts_sessions/i;
  const sessionInsert = /INSERT INTO sts_sessions/i;

  statements.length = 0;
  await driver.saveMinted([], [{
    handle: 'authn.sessions', realm: REALM, key: 'digest-gone',
    tombstone: true, keySealed: ''
  }]);
  const tombTx = txOf(statements);
  const tombInsert = matching(tombTx, /INSERT INTO sts_minted/i);
  const tombDelete = matching(tombTx, sessionDelete);
  t.equal(tombInsert.length, 1, 'a tombstone writes the marker');
  t.equal(tombInsert[0].params[3], TOMBSTONE,
          'and the marker is the tombstone body');
  t.equal(tombDelete.length, 1,
          'and deletes the index row in that same transaction');
  t.equal(tombDelete[0].params[0], REALM, 'the delete names the realm');
  t.equal(tombDelete[0].params[1], 'digest-gone', 'and the minted key');
  t.check(tombTx.indexOf(tombInsert[0]) < tombTx.indexOf(tombDelete[0]) &&
          tombTx.indexOf(tombDelete[0]) < tombTx.length - 1,
          'the index delete follows the marker and precedes COMMIT');

  statements.length = 0;
  answer.selectBody = TOMBSTONE;
  let merged = false;
  const refused = await driver.saveMinted([{
    handle: 'authn.sessions', realm: REALM, key: 'digest-back',
    body: 'this-process', tombstone: true, index: index,
    merge: function () {
      merged = true;
      return 'put-back';
    }
  }], []);
  const refusedTx = txOf(statements);
  t.check(!merged, 'a stored tombstone is not merged');
  t.equal(refused.refused.length, 1, 'and the upsert is refused');
  t.check(!matching(refusedTx, /INSERT INTO sts_minted/i).length,
          'a refused upsert does not put the body back');
  t.check(!matching(refusedTx, sessionInsert).length,
          'and does not write an index row');

  statements.length = 0;
  answer.selectBody = null;
  answer.rowCount = 0;
  const guarded = await driver.saveMinted([{
    handle: 'authn.sessions', realm: REALM, key: 'digest-lost',
    body: 'sealed', tombstone: true, index: index
  }], []);
  const guardedTx = txOf(statements);
  const guardedBody = matching(guardedTx, /INSERT INTO sts_minted/i);
  t.equal(guarded.refused.length, 1,
          'a guarded upsert the database did not apply is refused');
  t.check(guardedBody.length === 1 && /body <>/.test(guardedBody[0].sql),
          'the guard is the tombstone comparison');
  t.check(!matching(guardedTx, sessionInsert).length,
          'and no index row is written for it');

  statements.length = 0;
  answer.rowCount = 1;
  const accepted = await driver.saveMinted([{
    handle: 'authn.sessions', realm: REALM, key: 'digest-live',
    body: 'sealed', tombstone: true, index: index
  }], []);
  const liveTx = txOf(statements);
  const liveBody = matching(liveTx, /INSERT INTO sts_minted/i);
  const liveIndex = matching(liveTx, sessionInsert);
  t.equal(accepted.refused.length, 0, 'a guarded upsert that lands is kept');
  t.equal(liveIndex.length, 1, 'and the index is written with it');
  t.equal(liveIndex[0].params.length, 15, 'fifteen columns');
  t.equal(liveIndex[0].params[0], REALM, 'the index realm');
  t.equal(liveIndex[0].params[1], 'digest-live', 'the minted key');
  t.equal(liveIndex[0].params[2], null,
          'a null expiresAt stays SQL NULL, not zero');
  t.equal(liveIndex[0].params[3], 5000, 'last_seen_at is the millisecond');
  t.check(liveTx.indexOf(liveBody[0]) < liveTx.indexOf(liveIndex[0]),
          'the index insert follows the body insert');

  statements.length = 0;
  await driver.saveMinted([], [{
    handle: 'authn.sessions', realm: REALM, key: 'digest-hard'
  }]);
  const hardTx = txOf(statements);
  t.equal(matching(hardTx, /DELETE FROM sts_minted/i).length, 1,
          'a hard delete removes the body');
  t.equal(matching(hardTx, sessionDelete).length, 1,
          'and the index row with it');

  statements.length = 0;
  await driver.saveMinted([], [{
    handle: 'oauth2.authzCodes', realm: REALM, key: 'code-1'
  }]);
  t.check(!matching(txOf(statements), sessionDelete).length,
          'a delete of another store does not touch sts_sessions');

  statements.length = 0;
  await driver.saveMinted([{
    handle: 'authn.sessions', realm: REALM, key: 'digest-plain', body: 'x'
  }], []);
  t.check(!matching(txOf(statements), sessionInsert).length &&
          !matching(txOf(statements), sessionDelete).length,
          'a session upsert with no index columns writes no index SQL');

  statements.length = 0;
  answer.done = true;
  t.equal(await driver.sessionIndexDone(), true,
          'a completion row answers done');
  answer.done = 't';
  t.equal(await driver.sessionIndexDone(), true,
          'and so does the text form');
  answer.done = false;
  t.equal(await driver.sessionIndexDone(), false,
          'no completion row is not done');
  answer.done = 'f';
  t.equal(await driver.sessionIndexDone(), false,
          'and the text false is not read as true');

  statements.length = 0;
  await driver.loadSessionBodies('', '', 0);
  const zero = statements[statements.length - 1];
  t.equal(zero.params[4], 0, 'a limit of 0 is passed through');
  t.equal(zero.params[2], '', 'the first page starts at an empty realm');
  t.equal(zero.params[3], '', 'and an empty key');
  statements.length = 0;
  await driver.loadSessionBodies('a', 'b', 500);
  t.equal(statements[statements.length - 1].params[4], 500,
          'and 500 stays 500');

  statements.length = 0;
  await driver.writeSessionIndex(REALM, 'digest-one', index);
  const writeTx = txOf(statements);
  t.equal(matching(writeTx, sessionInsert).length, 1,
          'writeSessionIndex upserts inside a transaction');
  statements.length = 0;
  await driver.deleteSessionIndex(REALM, 'digest-one');
  t.equal(matching(txOf(statements), sessionDelete).length, 1,
          'deleteSessionIndex deletes inside a transaction');

  statements.length = 0;
  answer.selectBody = 'cipher-a';
  await driver.writeSessionIndexes([{
    realm: REALM, key: 'digest-page', body: 'cipher-a', index: index
  }], true);
  const pageTx = txOf(statements);
  const locked = matching(pageTx, /SELECT body FROM sts_minted/i);
  const inserts = matching(pageTx, sessionInsert);
  t.equal(locked.length, 1, 'the page re-reads the body');
  t.check(/FOR UPDATE/i.test(locked[0].sql), 'and locks it');
  t.equal(inserts.length, 2, 'the index row and the completion row');
  t.equal(inserts[0].params[1], 'digest-page', 'the session key');
  t.equal(inserts[1].params[1], '$session-index-complete$',
          'the completion row is in that same transaction');
  t.check(pageTx.indexOf(locked[0]) < pageTx.indexOf(inserts[0]) &&
          pageTx.indexOf(inserts[0]) < pageTx.indexOf(inserts[1]),
          'the lock precedes both inserts');
  const swept = matching(pageTx, /DELETE FROM sts_sessions AS s/i);
  t.equal(swept.length, 1,
          'the last page drops index rows with no live body');
  t.check(swept[0].sql.indexOf('m.body <>') >= 0,
          'a tombstone counts as no live body');
  t.equal(swept[0].params[0], '', 'the sweep keeps the mark realm');
  t.equal(swept[0].params[1], '$session-index-complete$',
          'and does not delete the mark');
  t.equal(swept[0].params[2], 'authn.sessions',
          'and only considers session bodies');
  t.equal(swept[0].params[3], TOMBSTONE, 'against the tombstone body');
  t.check(pageTx.indexOf(inserts[0]) < pageTx.indexOf(swept[0]) &&
          pageTx.indexOf(swept[0]) < pageTx.indexOf(inserts[1]),
          'the sweep sits between the page and the mark');

  statements.length = 0;
  answer.selectBody = 'cipher-b';
  await driver.writeSessionIndexes([{
    realm: REALM, key: 'digest-page', body: 'cipher-a', index: index
  }], false);
  const skipTx = txOf(statements);
  t.equal(matching(skipTx, /FOR UPDATE/i).length, 1,
          'a changed body is still locked');
  t.check(!matching(skipTx, sessionInsert).length,
          'and is not indexed from the ciphertext that was opened');
  t.check(!matching(skipTx, /DELETE FROM sts_sessions AS s/i).length,
          'a page that is not last does not sweep');

  statements.length = 0;
  answer.selectBody = TOMBSTONE;
  await driver.writeSessionIndexes([{
    realm: REALM, key: 'digest-page', body: 'cipher-a', index: index
  }], false);
  t.check(!matching(txOf(statements), sessionInsert).length,
          'a tombstone seen in the write is not indexed');

  statements.length = 0;
  answer.selectBody = null;
  await driver.writeSessionIndexes([{
    realm: REALM, key: 'digest-page', body: 'cipher-a', index: index
  }], false);
  t.check(!matching(txOf(statements), sessionInsert).length,
          'a missing body is not indexed');
  log.debug("Leaving sqlHalf().");
}

function columnCases(t, handle) {
  log.debug("Entering columnCases().");
  t.log.info('=== index columns ===');
  t.check(typeof handle.indexOf === 'function',
          'declareHandle kept indexOf on authn.sessions');
  t.equal(handle.expiresAt, null,
          'and the sessions store still has no expiresAt hook');
  realms.map({ persist: 'test.sessionIndexProbe', indexOf: probeIndex,
               ignoredOption: true });
  const probe = realms.handleFor('test.sessionIndexProbe');
  t.equal(probe.indexOf, probeIndex,
          'a handle keeps the indexOf it was given');
  t.equal(probe.ignoredOption, undefined,
          'and does not keep an option it does not know');

  const row = sessionValue();
  const columns = handle.indexOf(row);
  const holder = stats.holderKeyOf('alice', SUBJECT);
  t.check(holder !== SUBJECT,
          'holderKeyOf did not resolve the frozen subject', holder);
  t.equal(columns.subjectKey,
          keystore.keyedDigest('session-subject', SUBJECT),
          'subject_key is the digest of the frozen subjectId');
  t.check(columns.subjectKey !==
          keystore.keyedDigest('session-subject', holder),
          'and not the digest of holderKeyOf');
  t.equal(Object.prototype.hasOwnProperty.call(columns, 'authTime'), false,
          'authTime is seconds and is not a column');

  const bare = handle.indexOf({
    user: { username: 'alice' }, subjectId: SUBJECT
  });
  t.equal(bare.chosen, true, 'a missing chosen is indexed as chosen');
  t.equal(bare.kind, 'sign-on', 'and the kind is a sign-on');
  t.equal(bare.authenticated, true, 'a missing authenticated is true');
  t.equal(bare.expiresAt, null, 'a missing expires is SQL NULL');

  const relying = handle.indexOf(sessionValue({
    derivedFrom: 'parent-sid', rpSurface: 'portal'
  }));
  t.equal(relying.kind, 'relying-party', 'derivedFrom is a relying party');
  t.equal(relying.parentKey,
          keystore.keyedDigest('session-parent', 'parent-sid'),
          'parent_key is the digest of that sid');
  t.equal(relying.rpSurface, 'portal', 'rp_surface is kept');

  const keyed = handle.indexOf(sessionValue({ credentialKey: 'fp-abc' }));
  t.equal(keyed.kind, 'keyed', 'a credential fingerprint is a keyed session');
  t.equal(keyed.credentialKey, 'fp-abc',
          'and the fingerprint is stored, not digested');

  const partner = handle.indexOf(sessionValue({
    fedPartnerSession: {
      relationship: 'partner-a', nameId: 'secret-name',
      sessionIndex: 'idx', sid: 'partner-sid'
    }
  }));
  t.equal(partner.partnerRelationship, 'partner-a',
          'only the relationship is indexed');
  t.check(JSON.stringify(partner).indexOf('secret-name') < 0,
          'the NameID stays in the sealed body');

  const named = handle.indexOf({ user: 'dave', subjectId: SUBJECT });
  t.equal(named.usernameKey, keystore.keyedDigest('session-username', ''),
          'a string user files the empty username');

  const arrival = handle.indexOf({
    chosen: false, user: { username: 'alice' }
  });
  t.equal(arrival.kind, 'arrival', 'an unchosen session is an arrival');
  t.equal(arrival.chosen, false, 'and chosen is false, not null');
  t.equal(arrival.subjectKey, keystore.keyedDigest('session-subject', ''),
          'an arrival with no subject files the empty subject');
  log.debug("Leaving columnCases().");
}

async function mergeCases(t, handle, planted, captured) {
  log.debug("Entering mergeCases().");
  t.log.info('=== a merge indexes the sealed row ===');
  install(capturingDriver(planted, captured));
  t.check(minted.enabled(), 'minted persistence is on for this realm');
  const mine = sessionValue();
  const theirs = sessionValue({
    backsConsole: true, authTime: 100, lastSeenAt: 5000
  });
  const before = handle.indexOf(mine);
  planted['merge-sid'] = sealSession(theirs);
  authn.sessions.set('merge-sid', mine);
  const wrote = await minted.flush();
  t.check(wrote.written, 'the merge flush wrote', wrote && wrote.error);
  const row = captured.filter(function (one) {
    return one.journalKey === 'merge-sid';
  })[0];
  const merged = authn.mergeSessionRows(mine, theirs);
  t.equal(JSON.stringify(row.index), JSON.stringify(handle.indexOf(merged)),
          'the index matches indexOf of the merged row');
  t.equal(row.index.lastSeenAt, 5000,
          'lastSeenAt is the later millisecond, not authTime');
  t.equal(row.index.backsConsole, true, 'backsConsole is the OR');
  t.equal(before.lastSeenAt, 1000, 'the caller\'s copy was earlier');
  t.equal(before.backsConsole, false, 'and did not back the console');
  t.equal(row.expiresAt, null,
          'sts_minted.expires_at stays null for a session');
  const opened = JSON.parse(keystore.open(row.body, 'minted-rows'));
  t.equal(opened.authTime, 200, 'the sealed authTime is 200');
  t.equal(opened.backsConsole, true, 'and the merged backsConsole');
  t.equal(opened.lastSeenAt, 5000, 'and the merged lastSeenAt');
  t.equal(row.realm, REALM, 'the row is the realm the session was set in');
  t.equal(row.key, minted.keyColumnOf('authn.sessions', REALM, 'merge-sid'),
          'the index key is the minted digest');

  const stale = sessionValue({ lastSeenAt: 2222, authTime: 50 });
  planted['unopenable-sid'] = 'not-a-seal';
  authn.sessions.set('unopenable-sid', stale);
  const again = await minted.flush();
  t.check(again.written, 'a body that will not open still writes this copy',
          again && again.error);
  const kept = captured.filter(function (one) {
    return one.journalKey === 'unopenable-sid';
  })[0];
  t.equal(JSON.stringify(kept.index), JSON.stringify(handle.indexOf(stale)),
          'and the index is indexOf of the copy that was written');
  t.check(kept.body !== 'not-a-seal', 'the stored seal is this process\'s');
  t.equal(JSON.parse(keystore.open(kept.body, 'minted-rows')).lastSeenAt,
          2222, 'which still carries this process\'s lastSeenAt');

  const realSeal = keystore.seal;
  keystore.seal = function (plaintext, label) {
    if (label === 'minted-rows' &&
        String(plaintext).indexOf('"lastSeenAt":5000') >= 0) {
      throw new Error('seal failed');
    }
    return realSeal.apply(keystore, arguments);
  };
  try {
    const keptMine = sessionValue({ lastSeenAt: 3333, authTime: 40 });
    const ahead = sessionValue({
      backsConsole: true, authTime: 10, lastSeenAt: 5000
    });
    planted['seal-throws'] = realSeal(JSON.stringify(ahead), 'minted-rows',
      tiers.mintedTierOf('authn.sessions'), { realm: REALM });
    authn.sessions.set('seal-throws', keptMine);
    const third = await minted.flush();
    t.check(third.written, 'a seal that throws still writes this copy',
            third && third.error);
    const sealedRow = captured.filter(function (one) {
      return one.journalKey === 'seal-throws';
    })[0];
    t.equal(JSON.stringify(sealedRow.index),
            JSON.stringify(handle.indexOf(keptMine)),
            'the index stays indexOf of the copy that was kept');
    t.equal(JSON.parse(keystore.open(sealedRow.body, 'minted-rows'))
              .lastSeenAt, 3333,
            'and the sealed body is this process\'s');
  } catch (e) {
    log.debug("Caught in mergeCases(): " + ((e && e.message) || e));
    log.debug("Leaving mergeCases().");
    throw e;
  } finally {
    keystore.seal = realSeal;
  }
  log.debug("Leaving mergeCases().");
}

async function nullDigestCase(t, handle, captured) {
  log.debug("Entering nullDigestCase().");
  t.log.info('=== no digest writes no index row ===');
  const real = keystore.keyedDigest;
  keystore.keyedDigest = function () {
    return null;
  };
  try {
    captured.length = 0;
    authn.sessions.set('null-digest', sessionValue({ lastSeenAt: 9 }));
    const wrote = await minted.flush();
    t.check(wrote.written, 'the body is still sealed', wrote && wrote.error);
    const row = captured.filter(function (one) {
      return one.journalKey === 'null-digest';
    })[0];
    t.check(row && row.index == null, 'a null digest writes no index columns');
    t.equal(handle.indexOf(sessionValue()), null,
            'indexOf itself declines');
    let asked = false;
    const backfill = {
      loadMinted: emptyLoad,
      saveMinted: emptySave,
      origin: testOrigin,
      sessionIndexDone: function () {
        log.debug("Entering sessionIndexDone().");
        asked = true;
        log.debug("Leaving sessionIndexDone().");
        return Promise.resolve(false);
      },
      loadSessionBodies: function () {
        log.debug("Entering loadSessionBodies().");
        log.debug("Leaving loadSessionBodies().");
        throw new Error('walked without a digest');
      },
      writeSessionIndexes: function () {
        log.debug("Entering writeSessionIndexes().");
        log.debug("Leaving writeSessionIndexes().");
        throw new Error('wrote without a digest');
      }
    };
    t.check(install(backfill), 'the backfill driver is installed');
    t.check(minted.enabled(), 'and minted persistence is still on');
    await minted.backfillSessionIndex();
    t.check(!asked, 'a null digest is probed before the index is asked');
  } finally {
    keystore.keyedDigest = real;
  }
  log.debug("Leaving nullDigestCase().");
}

async function backfillCases(t, handle) {
  log.debug("Entering backfillCases().");
  t.log.info('=== backfill opens every body before it writes ===');
  const value = sessionValue({ lastSeenAt: 4242 });
  const good = { realm: REALM, key: 'backfill-good', body: sealSession(value) };
  const bad = { realm: REALM, key: 'backfill-bad', body: 'not-a-seal' };
  const wrote = [];
  const seen = [];
  const order = [];
  const pages = [[good, bad]];
  install({
    loadMinted: emptyLoad,
    saveMinted: emptySave,
    origin: testOrigin,
    sessionIndexDone: function () {
      log.debug("Entering sessionIndexDone().");
      log.debug("Leaving sessionIndexDone().");
      return Promise.resolve(false);
    },
    latestChangeSeq: function () {
      log.debug("Entering latestChangeSeq().");
      order.push('seq');
      log.debug("Leaving latestChangeSeq().");
      return Promise.resolve(17);
    },
    loadSessionBodies: function (afterRealm, afterKey, limit) {
      log.debug("Entering loadSessionBodies().");
      order.push('load');
      seen.push({ afterRealm: afterRealm, afterKey: afterKey, limit: limit });
      const page = pages.shift() || [];
      log.debug("Leaving loadSessionBodies().");
      return Promise.resolve(page);
    },
    writeSessionIndexes: function (rows) {
      log.debug("Entering writeSessionIndexes().");
      wrote.push(rows);
      log.debug("Leaving writeSessionIndexes().");
      return Promise.resolve();
    }
  });
  let failed = null;
  try {
    await minted.backfillSessionIndex();
  } catch (e) {
    failed = e;
    log.debug("Caught in backfillCases(): " + ((e && e.message) || e));
  }
  t.check(failed && /will not open/.test(failed.message),
          'a body that will not open throws', failed && failed.message);
  t.equal(failed && failed.sessionIndexCommitted, undefined,
          'and a throw before any page commits names nothing written');
  t.equal(wrote.length, 0, 'and that page writes nothing');
  t.equal(seen[0].limit, 500, 'a page asks for 500');
  t.equal(seen[0].afterRealm, '', 'starting from an empty realm');
  t.equal(seen[0].afterKey, '', 'and an empty key');
  t.check(order.indexOf('seq') >= 0 &&
          order.indexOf('seq') < order.indexOf('load'),
          'the change seq is taken before the first page');
  t.equal(minted.sessionIndexChangeFloor(), null,
          'a walk that throws publishes no floor');

  const full = [];
  for (let i = 0; i < 500; i++) {
    full.push({ realm: REALM, key: 'p' + i, body: good.body });
  }
  const splitPages = [full, [bad]];
  const splitWrote = [];
  install({
    loadMinted: emptyLoad,
    saveMinted: emptySave,
    origin: testOrigin,
    sessionIndexDone: function () {
      log.debug("Entering sessionIndexDone().");
      log.debug("Leaving sessionIndexDone().");
      return Promise.resolve(false);
    },
    latestChangeSeq: function () {
      log.debug("Entering latestChangeSeq().");
      log.debug("Leaving latestChangeSeq().");
      return Promise.resolve(18);
    },
    loadSessionBodies: function () {
      log.debug("Entering loadSessionBodies().");
      const page = splitPages.shift() || [];
      log.debug("Leaving loadSessionBodies().");
      return Promise.resolve(page);
    },
    writeSessionIndexes: function (rows, complete) {
      log.debug("Entering writeSessionIndexes().");
      splitWrote.push({ rows: rows, complete: complete });
      log.debug("Leaving writeSessionIndexes().");
      return Promise.resolve();
    }
  });
  let splitFailed = null;
  try {
    await minted.backfillSessionIndex();
  } catch (e) {
    splitFailed = e;
    log.debug("Caught in backfillCases(): " + ((e && e.message) || e));
  }
  t.check(splitFailed && /will not open/.test(splitFailed.message),
          'a later page that will not open throws',
          splitFailed && splitFailed.message);
  t.equal(splitWrote.length, 1, 'the page that committed is kept');
  t.equal(splitWrote[0].complete, false,
          'and it is not marked finished');
  t.equal(splitFailed.sessionIndexCommitted, true,
          'the throw says a page has committed');
  t.equal(minted.sessionIndexChangeFloor(), null,
          'a resume head is not the floor until the mark commits');

  const okPages = [[good]];
  const okWrote = [];
  install({
    loadMinted: emptyLoad,
    saveMinted: emptySave,
    origin: testOrigin,
    sessionIndexDone: function () {
      log.debug("Entering sessionIndexDone().");
      log.debug("Leaving sessionIndexDone().");
      return Promise.resolve(false);
    },
    latestChangeSeq: function () {
      log.debug("Entering latestChangeSeq().");
      log.debug("Leaving latestChangeSeq().");
      return Promise.resolve(19);
    },
    loadSessionBodies: function (afterRealm) {
      log.debug("Entering loadSessionBodies().");
      okWrote.push({ afterRealm: afterRealm });
      const page = okPages.shift() || [];
      log.debug("Leaving loadSessionBodies().");
      return Promise.resolve(page);
    },
    writeSessionIndexes: function (rows, complete) {
      log.debug("Entering writeSessionIndexes().");
      okWrote.push({ rows: rows, complete: complete });
      log.debug("Leaving writeSessionIndexes().");
      return Promise.resolve();
    }
  });
  await minted.backfillSessionIndex();
  const written = okWrote.filter(function (one) {
    return one.rows;
  });
  t.equal(written.length, 1, 'an open page is written');
  t.equal(written[0].complete, true,
          'the last page carries the completion row');
  t.equal(written[0].rows[0].realm, REALM, 'under the loaded realm');
  t.equal(written[0].rows[0].key, 'backfill-good', 'and the loaded key');
  t.equal(written[0].rows[0].body, good.body,
          'and the ciphertext that was opened');
  t.equal(JSON.stringify(written[0].rows[0].index),
          JSON.stringify(handle.indexOf(value)),
          'with indexOf of the opened body');
  t.equal(okWrote[0].afterRealm, '',
          'a resumed walk starts again at the beginning');
  t.equal(minted.sessionIndexChangeFloor(), 19,
          'the floor is the seq taken before that walk');

  let skipped = false;
  // setDriver, not install(): install() resets, which would drop the floor
  // the walk just took. A finished index must not move it.
  const finished = {
    loadMinted: emptyLoad,
    saveMinted: emptySave,
    origin: testOrigin,
    sessionIndexDone: function () {
      log.debug("Entering sessionIndexDone().");
      log.debug("Leaving sessionIndexDone().");
      return Promise.resolve(true);
    },
    loadSessionBodies: function () {
      log.debug("Entering loadSessionBodies().");
      skipped = true;
      log.debug("Leaving loadSessionBodies().");
      return Promise.resolve([]);
    },
    writeSessionIndexes: function () {
      log.debug("Entering writeSessionIndexes().");
      skipped = true;
      log.debug("Leaving writeSessionIndexes().");
      return Promise.resolve();
    }
  };
  t.check(minted.setDriver(finished, 'postgres'),
          'the finished-index driver replaces the one that walked');
  await minted.backfillSessionIndex();
  t.check(!skipped, 'a finished index is not walked again');
  t.equal(minted.sessionIndexChangeFloor(), 19,
          'and a skipped walk does not move the floor');

  const noneWrote = [];
  const emptyStore = {
    loadMinted: emptyLoad,
    saveMinted: emptySave,
    origin: testOrigin,
    sessionIndexDone: function () {
      log.debug("Entering sessionIndexDone().");
      log.debug("Leaving sessionIndexDone().");
      return Promise.resolve(false);
    },
    latestChangeSeq: function () {
      log.debug("Entering latestChangeSeq().");
      log.debug("Leaving latestChangeSeq().");
      return Promise.resolve(20);
    },
    loadSessionBodies: function () {
      log.debug("Entering loadSessionBodies().");
      log.debug("Leaving loadSessionBodies().");
      return Promise.resolve([]);
    },
    writeSessionIndexes: function (rows, complete) {
      log.debug("Entering writeSessionIndexes().");
      noneWrote.push({ rows: rows, complete: complete });
      log.debug("Leaving writeSessionIndexes().");
      return Promise.resolve();
    }
  };
  t.check(minted.setDriver(emptyStore, 'postgres'),
          'the empty-store driver replaces the finished one');
  await minted.backfillSessionIndex();
  t.equal(noneWrote.length, 1, 'an empty store still writes one page');
  t.equal(noneWrote[0].rows.length, 0, 'with no session rows');
  t.equal(noneWrote[0].complete, true,
          'and that page carries the completion row');
  log.debug("Leaving backfillCases().");
}

async function floorCase(t) {
  log.debug("Entering floorCase().");
  t.log.info('=== the follower starts at the seq taken before the walk ===');
  const previous = process.env.STS_PERSISTENCE_COORDINATE;
  process.env.STS_PERSISTENCE_COORDINATE = 'true';
  const follower = replication.createReplication('sessidx');
  let asked = 0;
  const stub = {
    origin: function () {
      log.debug("Entering origin().");
      log.debug("Leaving origin().");
      return 'sessidx-origin';
    },
    latestChangeSeq: function () {
      log.debug("Entering latestChangeSeq().");
      asked += 1;
      log.debug("Leaving latestChangeSeq().");
      return Promise.resolve(99);
    },
    changesSince: function () {
      log.debug("Entering changesSince().");
      log.debug("Leaving changesSince().");
      return Promise.resolve([]);
    }
  };
  try {
    const started = await follower.start(stub, {}, 17);
    t.equal(started.from, 17,
            'a finite floor is the high-water, not the head');
    t.equal(started.coordinating, true, 'and the follower is coordinating');
    t.equal(asked, 0, 'the head is not read when the floor is passed');
    t.equal(follower.status().appliedSeq, 17, 'applied is that floor');
  } catch (e) {
    log.debug("Caught in floorCase(): " + ((e && e.message) || e));
    log.debug("Leaving floorCase().");
    throw e;
  } finally {
    follower.reset();
    // The instance: the module export does not include unregister.
    scheduler.scheduler.unregister(
      'persistence.sessidx-change-log-pull');
    scheduler.scheduler.unregister(
      'persistence.sessidx-change-log-purge');
    if (previous === undefined) {
      delete process.env.STS_PERSISTENCE_COORDINATE;
    } else {
      process.env.STS_PERSISTENCE_COORDINATE = previous;
    }
  }
  log.debug("Leaving floorCase().");
}

async function applyCases(t, handle, realm) {
  log.debug("Entering applyCases().");
  t.log.info('=== apply repairs the index from the opened body ===');
  const downValue = sessionValue({ lastSeenAt: 77 });
  const downSid = 'apply-down';
  const downKey = minted.keyColumnOf('authn.sessions', REALM, downSid);
  const okValue = sessionValue({ lastSeenAt: 88 });
  const okSid = 'apply-ok';
  const okKey = minted.keyColumnOf('authn.sessions', REALM, okSid);
  const goneSid = 'apply-gone';
  const goneKey = minted.keyColumnOf('authn.sessions', REALM, goneSid);
  const bodies = {};
  bodies[downKey] = {
    handle: 'authn.sessions', realm: REALM, key: downKey,
    body: sealSession(downValue), fail: true
  };
  bodies[okKey] = {
    handle: 'authn.sessions', realm: REALM, key: okKey,
    body: sealSession(okValue)
  };
  const writes = [];
  const deletes = [];
  install({
    loadMinted: emptyLoad,
    saveMinted: emptySave,
    origin: testOrigin,
    readMinted: function (handleName, realmId, key) {
      log.debug("Entering readMinted().");
      log.debug("Leaving readMinted().");
      return Promise.resolve(bodies[key] || null);
    },
    writeSessionIndex: function (realmId, key, index) {
      log.debug("Entering writeSessionIndex().");
      if (bodies[key] && bodies[key].fail) {
        log.debug("Leaving writeSessionIndex().");
        return Promise.reject(new Error('index down'));
      }
      writes.push({
        realm: realmId, key: key, index: Object.assign({}, index)
      });
      log.debug("Leaving writeSessionIndex().");
      return Promise.resolve();
    },
    deleteSessionIndex: function (realmId, key) {
      log.debug("Entering deleteSessionIndex().");
      deletes.push({ realm: realmId, key: key });
      log.debug("Leaving deleteSessionIndex().");
      return Promise.resolve();
    }
  });

  let rejected = null;
  try {
    await minted.applyChange({ key: changeKey(downSid), realm: REALM });
  } catch (e) {
    rejected = e;
    log.debug("Caught in applyCases(): " + ((e && e.message) || e));
  }
  t.check(rejected && /index down/.test(rejected.message),
          'a failed index repair rejects the change',
          rejected && rejected.message);
  t.equal(realms.run(realm, function () {
    return authn.sessions.get(downSid);
  }), undefined, 'and the session is not restored');

  await minted.applyChange({ key: changeKey(okSid), realm: REALM });
  t.equal(writes.length, 1, 'a live body repairs the index');
  t.equal(writes[0].realm, REALM, 'in the change\'s realm');
  t.equal(writes[0].key, okKey, 'under the minted digest');
  t.equal(JSON.stringify(writes[0].index),
          JSON.stringify(handle.indexOf(okValue)),
          'from indexOf of the opened body');
  t.equal(realms.run(realm, function () {
    return (authn.sessions.get(okSid) || {}).lastSeenAt;
  }), 88, 'and then the session is restored');

  await minted.applyChange({ key: changeKey(goneSid), realm: REALM });
  t.equal(deletes.length, 1, 'an absent body deletes the index');
  t.equal(deletes[0].realm, REALM, 'in that realm');
  t.equal(deletes[0].key, goneKey, 'by the minted digest');
  log.debug("Leaving applyCases().");
}

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

async function withTempDir(fn) {
  log.debug("Entering withTempDir().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-session-index-'));
  try {
    log.debug("Leaving withTempDir().");
    return await fn(dir);
  } finally {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch (e) {
      log.debug("Caught in withTempDir(): " + ((e && e.message) || e));
    }
  }
}

async function liveHalf(t, realm) {
  log.debug("Entering liveHalf().");
  const handle = realms.handleFor('authn.sessions');
  columnCases(t, handle);
  const planted = {};
  const captured = [];
  await mergeCases(t, handle, planted, captured);
  await nullDigestCase(t, handle, captured);
  await backfillCases(t, handle);
  await floorCase(t);
  await applyCases(t, handle, realm);
  log.debug("Leaving liveHalf().");
}

function clearOverrides(realm) {
  log.debug("Entering clearOverrides().");
  realms.run(realm, function () {
    authn.sessions.clear();
    config.clearOverride('global.mode');
    config.clearOverride('persistence.minted');
  });
  config.clearOverride('global.mode');
  config.clearOverride('persistence.minted');
  log.debug("Leaving clearOverrides().");
}

async function body(t, dir) {
  log.debug("Entering body().");
  await sqlHalf(t);
  checkTheCallSite(t);
  let armed = false;
  const made = realms.create({ id: REALM, name: REALM,
                               description: 'Created by ' + __filename });
  if (!made.ok) {
    t.bad('could not create the realm "session-index"',
          (made.errors || []).join(' '));
    log.debug("Leaving body().");
    return;
  }
  try {
    armed = true;
    await armKeystore(dir);
    // `persistence.minted` is restart-only; its default is already on.
    // `global.mode` is runtime-settable, which is what turns the flush on.
    config.setOverride('global.mode', 'product');
    config.setOverride('persistence.minted', true);
    t.equal(config.value('global.mode'), 'product', 'product mode is in force');
    t.equal(config.value('persistence.minted'), true,
            'minted persistence is on');
    await realms.run(made.realm, function () {
      return liveHalf(t, made.realm);
    });
  } finally {
    try {
      clearOverrides(made.realm);
    } catch (e) {
      log.debug("Caught in body(): " + ((e && e.message) || e));
    }
    realms.remove(REALM);
    if (armed) {
      disarmKeystore();
    }
    minted.reset();
    minted.endPrefetch();
  }
  log.debug("Leaving body().");
}

async function run(t) {
  log.debug("Entering run().");
  log.debug("Leaving run().");
  return withTempDir(function (dir) { return body(t, dir); });
}

module.exports = {
  name: 'session_index',
  describe: 'sts_sessions is written and deleted with the sealed session ' +
            'body (#350): the same transaction, the merged row, and no ' +
            'index when there is no digest',
  run: run
};
