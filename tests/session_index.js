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
const flushDouble = require('./tools/minted_flush_double');

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
    // THE MINTED FLUSH IS ONE STATEMENT SINCE #820, played against Maps by
    // `tools/minted_flush_double.js`: each key it touches holds
    // `answer.selectBody` when that is set, and a guarded upsert holds a
    // tombstone (so it is not written) while `answer.rowCount` is 0.
    // Recorded as `MINTED_FLUSH`, with its parameters by name and the
    // state it left in `answer.flushed`.
    if (flushDouble.isFlush(sql)) {
      const named = flushDouble.named(sql);
      const db = flushDouble.state();
      named.lock_h.forEach(function (h, i) {
        const key = h + '\n' + named.lock_r[i] + '\n' + named.lock_k[i];
        if (answer.selectBody != null) {
          db.minted.set(key, { body: answer.selectBody });
        } else if (!answer.rowCount) {
          db.minted.set(key, { body: TOMBSTONE });
        }
      });
      const played = flushDouble.play(db, sql);
      answer.flushed = db;
      statements.push({ sql: 'MINTED_FLUSH', text: sql.text, params: named,
                        go: played.rows[0].go });
      return Promise.resolve(played);
    }
    const text = String(sql);
    statements.push({ sql: text, params: params || [] });
    // A repair's read of the index row first (2026-10-21): the row in
    // `answer.heldIndex`, or none.
    if (/^SELECT expires_at, last_seen_at, started_at/.test(text)) {
      const held = answer.heldIndex ? [answer.heldIndex] : [];
      return Promise.resolve({ rows: held, rowCount: held.length });
    }
    // The flush's lock-and-read when it is a transaction (#820): every key
    // with selectBody.
    if (/^SELECT handle, realm, key, body FROM sts_minted/i.test(text)) {
      const p = params || [];
      const found = answer.selectBody == null ? [] : (p[0] || []).map(
        function (h, i) {
          return { handle: h, realm: p[1][i], key: p[2][i],
                   body: answer.selectBody };
        });
      return Promise.resolve({ rows: found, rowCount: found.length });
    }
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

  // SINCE #820 THE FLUSH IS ONE STATEMENT (MINTED_FLUSH): what was a
  // statement of the transaction is a set of its named arrays, and "in the
  // same transaction" is "in the same statement". The order the CTEs run
  // in is the statement's own: every side-table write reads `done`, which
  // counts the bodies' writes, and writes only for a body `ins` returned.
  const flushes = function () {
    return statements.filter(function (one) {
      return one.sql === 'MINTED_FLUSH';
    });
  };
  const last = function () {
    const all = flushes();
    return all.length ? all[all.length - 1].params : {};
  };
  const text = postgres.MINTED_FLUSH;
  t.check(/sdel AS \(DELETE FROM sts_sessions .*\(SELECT n FROM done\) >= 0/
            .test(text) &&
          /ses AS \(INSERT INTO sts_sessions .*\(SELECT n FROM done\) >= 0 AND EXISTS \(SELECT 1 FROM ins WHERE ins\.handle = 'authn\.sessions'/
            .test(text),
          'the index is written in the body\'s statement, after the ' +
          'bodies, and only for a body that was written');

  statements.length = 0;
  await driver.saveMinted([], [{
    handle: 'authn.sessions', realm: REALM, key: 'digest-gone',
    tombstone: true, keySealed: ''
  }]);
  let p = last();
  const marker = (p.up_k || []).indexOf('digest-gone');
  t.check(flushes().length === 1 && marker >= 0,
          'a tombstone writes the marker');
  t.equal(marker >= 0 ? p.up_body[marker] : null, TOMBSTONE,
          'and the marker is the tombstone body');
  t.equal((p.sesdel_key || []).length, 1,
          'and deletes the index row in that same statement');
  t.equal((p.sesdel_realm || [])[0], REALM, 'the delete names the realm');
  t.equal((p.sesdel_key || [])[0], 'digest-gone', 'and the minted key');

  // #820: an on-demand store's index rows (`sts_minted_index`) are replaced
  // in the statement that writes the body, and go with a deleted row.
  statements.length = 0;
  answer.selectBody = null;
  answer.rowCount = 1;
  await driver.saveMinted([{
    handle: 'oauth2_bcp.refreshTokens', realm: REALM, key: 'digest-tok',
    body: 'sealed', tombstone: true, lookups: ['family-digest']
  }], [{ handle: 'oauth2_bcp.refreshTokens', realm: REALM,
         key: 'digest-old', tombstone: true, indexed: true, keySealed: '' }]);
  p = last();
  t.check((p.ixup_k || []).indexOf('digest-tok') >= 0 &&
          (p.ixgone_k || []).indexOf('digest-old') >= 0,
          'an indexed row\'s old index rows are deleted, and a deleted ' +
          'row\'s with it (#820)', JSON.stringify([p.ixup_k, p.ixgone_k]));
  t.check((p.ixnew_i || [])[0] === 'family-digest' &&
          (p.ixnew_k || [])[0] === 'digest-tok' &&
          answer.flushed.index.has(['oauth2_bcp.refreshTokens', REALM,
                                    'family-digest', 'digest-tok']
            .join('\n')),
          'and its new index rows are written in that statement (#820)',
          JSON.stringify([p.ixnew_i, p.ixnew_k]));
  statements.length = 0;
  answer.rowCount = 0;
  await driver.saveMinted([{
    handle: 'oauth2_bcp.refreshTokens', realm: REALM, key: 'digest-refused',
    body: 'sealed', tombstone: true, lookups: ['family-digest']
  }], []);
  t.check(answer.flushed.index.size === 0,
          'a refused body files no index row (#820)');
  answer.rowCount = 1;

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
  p = last();
  t.check(!merged, 'a stored tombstone is not merged');
  t.equal(refused.refused.length, 1, 'and the upsert is refused');
  t.check((p.up_k || []).indexOf('digest-back') < 0,
          'a refused upsert does not put the body back');
  t.check(!(p.ses_key || []).length && !answer.flushed.sessions.size,
          'and does not write an index row');

  statements.length = 0;
  answer.selectBody = null;
  answer.rowCount = 0;
  const guarded = await driver.saveMinted([{
    handle: 'authn.sessions', realm: REALM, key: 'digest-lost',
    body: 'sealed', tombstone: true, index: index
  }], []);
  p = last();
  t.equal(guarded.refused.length, 1,
          'a guarded upsert the database did not apply is refused');
  t.check(/WHERE sts_minted\.body <> \$[0-9]+::text OR/.test(text) &&
          (p.plain_k || []).indexOf('digest-lost') < 0,
          'the guard is the tombstone comparison, and the row is not ' +
          'among the unguarded');
  t.check(!answer.flushed.sessions.size,
          'and no index row is written for it');

  statements.length = 0;
  answer.rowCount = 1;
  const accepted = await driver.saveMinted([{
    handle: 'authn.sessions', realm: REALM, key: 'digest-live',
    body: 'sealed', tombstone: true, index: index
  }], []);
  p = last();
  t.equal(accepted.refused.length, 0, 'a guarded upsert that lands is kept');
  t.equal(answer.flushed.sessions.size, 1, 'and the index is written with it');
  t.equal(postgres.MINTED_FLUSH_LAYOUT.filter(function (one) {
    return /^ses_/.test(one[0]);
  }).length, 15, 'fifteen columns');
  t.equal((p.ses_realm || [])[0], REALM, 'the index realm');
  t.equal((p.ses_key || [])[0], 'digest-live', 'the minted key');
  t.equal((p.ses_expires || [])[0], null,
          'a null expiresAt stays SQL NULL, not zero');
  t.equal((p.ses_last_seen || [])[0], 5000,
          'last_seen_at is the millisecond');

  statements.length = 0;
  await driver.saveMinted([], [{
    handle: 'authn.sessions', realm: REALM, key: 'digest-hard'
  }]);
  p = last();
  t.equal((p.del_k || []).length, 1, 'a hard delete removes the body');
  t.equal((p.sesdel_key || []).length, 1,
          'and the index row with it');

  statements.length = 0;
  await driver.saveMinted([], [{
    handle: 'oauth2.authzCodes', realm: REALM, key: 'code-1'
  }]);
  t.check(!(last().sesdel_key || []).length,
          'a delete of another store does not touch sts_sessions');

  statements.length = 0;
  await driver.saveMinted([{
    handle: 'authn.sessions', realm: REALM, key: 'digest-plain', body: 'x'
  }], []);
  p = last();
  t.check(!(p.ses_key || []).length && !(p.sesdel_key || []).length,
          'a session upsert with no index columns writes no index row');

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
  // 2026-10-21: a repair writes only where the held row differs. The row
  // as postgres hands it back: bigints as strings, NULL as null.
  const asHeld = { expires_at: null, last_seen_at: '5000',
                   started_at: '1000', subject_key: 'subject-digest',
                   username_key: 'username-digest', chosen: true,
                   authenticated: true, kind: 'sign-on', rp_surface: '',
                   parent_key: '', backs_console: false, credential_key: '',
                   partner_relationship: '' };
  answer.heldIndex = asHeld;
  statements.length = 0;
  await driver.writeSessionIndex(REALM, 'digest-one', index);
  t.equal(matching(statements, sessionInsert).length +
          matching(statements, /^BEGIN/).length, 0,
          'a repair whose row already says what the body implies writes ' +
          'nothing and opens no transaction');
  answer.heldIndex = Object.assign({}, asHeld, { last_seen_at: '4000' });
  statements.length = 0;
  await driver.writeSessionIndex(REALM, 'digest-one', index);
  t.equal(matching(txOf(statements), sessionInsert).length, 1,
          'a repair whose row differs is written');
  answer.heldIndex = asHeld;
  statements.length = 0;
  await driver.deleteSessionIndex(REALM, 'digest-one');
  t.equal(matching(txOf(statements), sessionDelete).length, 1,
          'deleteSessionIndex deletes inside a transaction');
  answer.heldIndex = null;
  statements.length = 0;
  await driver.deleteSessionIndex(REALM, 'digest-one');
  t.equal(matching(statements, sessionDelete).length, 0,
          'and deletes nothing where there is no row');

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

// The index of an indexed on-demand store (#820) — `sts_minted_index` — is
// written beside every body since schema version 24, so the rows stored
// before it have none. Such a store is read back whole until the front
// process has filed every row it holds and committed the mark.
function indexDriver(complete, filed, marked, filters) {
  log.debug("Entering indexDriver().");
  log.debug("Leaving indexDriver().");
  return {
    loadMinted: function (filter) {
      filters.push((filter.skipHandles || []).slice());
      return Promise.resolve([]);
    },
    readMinted: noRead,
    origin: testOrigin,
    saveMinted: emptySave,
    bridgeConnection: function () {
      return { host: 'unused' };
    },
    mintedIndexComplete: function (handles) {
      return Promise.resolve(handles.filter(function (one) {
        return complete.indexOf(one) >= 0;
      }));
    },
    writeMintedIndex: function (rows) {
      rows.forEach(function (one) {
        filed.push(one);
      });
      return Promise.resolve(rows.length);
    },
    markMintedIndexed: function (handle) {
      marked.push(handle);
      return Promise.resolve({});
    }
  };
}

async function indexBackfillCases(t, realm) {
  log.debug("Entering indexBackfillCases().");
  t.log.info('=== an indexed on-demand store waits for its index (#820) ===');
  const store = realms.handleFor('test.session-index.on-demand') ? null :
    realms.map({ persist: 'test.session-index.on-demand',
                 onDemand: { maxEntries: 10 },
                 indexBy: function (value) {
                   return value && value.family ? [value.family] : [];
                 } });
  if (!store) {
    t.bad('the on-demand test store was declared twice');
    log.debug("Leaving indexBackfillCases().");
    return;
  }
  store.set('old-1', { family: 'fam-a' });
  store.set('old-2', { family: 'fam-b' });
  let filed = [];
  let marked = [];
  let filters = [];
  install(indexDriver([], filed, marked, filters));
  await minted.restore();
  for (let i = 0; i < 20; i++) {
    await new Promise(function (resolve) {
      setImmediate(resolve);
    });
  }
  t.equal(filed.length + marked.length, 0,
          'the restore files nothing: the backfill is not a step of the ' +
          'start (the first start of #823 ran out of heap)');
  t.check(!!scheduler.job('persistence.minted-index-backfill'),
          'it is a scheduler job, registered by the front process\'s restore');
  t.equal(JSON.stringify(store.lookup('fam-a')), JSON.stringify(['old-1']),
          'a store held whole answers lookup() by walking what it holds, ' +
          'with no index in memory');
  const ran = await minted.backfillMintedIndexes();
  t.check(ran && !ran.stopped, 'the job\'s run completes',
          JSON.stringify(ran));
  t.check(filters.length &&
          filters[0].indexOf('test.session-index.on-demand') < 0,
          'an indexed on-demand store with no mark is read back whole',
          JSON.stringify(filters));
  t.equal(store.onDemandLive(), false,
          'and it is not on demand for the rest of this run');
  const mine = filed.filter(function (one) {
    return one.handle === 'test.session-index.on-demand';
  });
  const expect = ['old-1', 'old-2'].map(function (name) {
    return minted.keyColumnOf('test.session-index.on-demand', realm.id, name);
  }).sort();
  t.equal(JSON.stringify(mine.map(function (one) {
    return one.key;
  }).sort()), JSON.stringify(expect),
          'the backfill files every row it holds, under its key column');
  t.check(mine.every(function (one) {
    return one.realm === realm.id && one.indexKey && one.indexKey !==
      'fam-a' && one.indexKey !== 'fam-b';
  }), 'each in its realm, under the index value\'s digest, never the value',
          JSON.stringify(mine));
  t.check(marked.indexOf('test.session-index.on-demand') >= 0,
          'and then commits the completion mark', JSON.stringify(marked));

  filed = [];
  marked = [];
  filters = [];
  install(indexDriver(['test.session-index.on-demand'], filed, marked,
                      filters));
  await minted.restore();
  await minted.backfillMintedIndexes();
  t.check(filters.length &&
          filters[0].indexOf('test.session-index.on-demand') >= 0,
          'with the mark, the store is not read back at a start',
          JSON.stringify(filters));
  t.equal(store.onDemandLive(), true, 'it is on demand');
  t.equal(filed.filter(function (one) {
    return one.handle === 'test.session-index.on-demand';
  }).length + marked.filter(function (one) {
    return one === 'test.session-index.on-demand';
  }).length, 0, 'and nothing is filed again');
  store.realmMap().clear();
  log.debug("Leaving indexBackfillCases().");
}

// A KEY-RESIDENT on-demand store (#820 part 2) is not read back: a start
// loads the key column of its live rows (`loadMintedKeys()`), and a change
// from another process files or removes the digest by what the row says.
// An on-demand store that declared its expiry after rows were written
// (#820 part 2, `expiryFromWrittenMs`) is read back whole until those rows
// are given one: on demand only the store's expiry purge deletes a dead row.
async function expiryBackfillCases(t) {
  log.debug("Entering expiryBackfillCases().");
  t.log.info('=== a store waits for its legacy rows\' expiries (#820) ===');
  const handle = 'session-index.expiring';
  const store = realms.map({ persist: handle,
    onDemand: { maxEntries: 10, expiryFromWrittenMs: function () {
      return 1234;
    } },
    expiresAt: function () {
      return null;
    } });
  const filters = [];
  const marked = [];
  const given = [];
  const driver = indexDriver([], [], marked, filters);
  driver.backfillMintedExpiry = function (name, addMs) {
    given.push({ handle: name, addMs: addMs });
    return Promise.resolve(7);
  };
  install(driver);
  await minted.restore();
  t.check(filters.length && filters[0].indexOf(handle) < 0,
          'with no mark it is read back whole', JSON.stringify(filters));
  t.equal(store.onDemandLive(), false, 'and is not on demand');
  await minted.backfillMintedIndexes();
  t.equal(JSON.stringify(given.filter(function (one) {
    return one.handle === handle;
  })), JSON.stringify([{ handle: handle, addMs: 1234 }]),
          'the job gives its legacy rows written_at plus the store\'s rule');
  t.check(marked.indexOf(handle) >= 0, 'and then writes the mark',
          JSON.stringify(marked));
  filters.length = 0;
  install(indexDriver([handle], [], [], filters));
  await minted.restore();
  t.check(filters.length && filters[0].indexOf(handle) >= 0,
          'with the mark it is not read back', JSON.stringify(filters));
  log.debug("Leaving expiryBackfillCases().");
}

// A row rewritten with the index keys it was last committed under writes no
// index rows (2026-10-21): a refresh rewrote two such rows, each deleting and
// re-inserting up to seven.
async function unchangedLookupCases(t, realm) {
  log.debug("Entering unchangedLookupCases().");
  t.log.info('=== an unchanged index is not rewritten ===');
  const handle = 'session-index.lookups';
  // On demand: only such a store files its index in `sts_minted_index`.
  const store = realms.map({ persist: handle, onDemand: { maxEntries: 10 },
    indexBy: function (value) {
      return value && value.family ? ['f:' + value.family] : [];
    } });
  const seen = [];
  install({
    loadMinted: emptyLoad,
    readMinted: noRead,
    origin: testOrigin,
    saveMinted: function (upserts) {
      upserts.forEach(function (one) {
        if (one.handle === handle) {
          seen.push(one.lookups === null ? 'none'
            : JSON.stringify(one.lookups).length > 2 ? 'written' : 'empty');
        }
      });
      return Promise.resolve({ refused: [], merged: [] });
    }
  });
  store.set('row-1', { family: 'a', n: 1 });
  await minted.flush();
  store.set('row-1', { family: 'a', n: 2 });
  await minted.flush();
  store.set('row-1', { family: 'a', n: 3 });
  await minted.flush();
  store.set('row-1', { family: 'b', n: 4 });
  await minted.flush();
  t.equal(seen.join(','), 'written,none,none,written',
          'a rewrite under the same index keys writes no index rows; a ' +
          'change of keys writes them');
  seen.length = 0;
  await minted.applyChange({ key: Buffer.from(handle).toString('base64url') +
                                  '.' + Buffer.from('row-1')
                                    .toString('base64url'),
                             realm: realm.id });
  store.set('row-1', { family: 'b', n: 5 });
  await minted.flush();
  t.equal(seen.join(','), 'written',
          'after another process\'s change to the row they are written in ' +
          'full again');
  store.realmMap().clear();
  log.debug("Leaving unchangedLookupCases().");
}

// `warm()` (2026-10-21): an on-demand store's keys read together, off the
// event loop, from the PRIMARY, under their key columns, and held opened.
async function warmCases(t, realm) {
  log.debug("Entering warmCases().");
  t.log.info('=== warm() reads its keys in one batch from the primary ===');
  const handle = 'session-index.warm';
  const store = realms.map({ persist: handle, onDemand: { maxEntries: 10 } });
  const column = minted.keyColumnOf(handle, realm.id, 'warm-1');
  const calls = [];
  const driver = indexDriver([], [], [], []);
  driver.readMintedMany = function (refs, opts) {
    calls.push({ keys: refs.map(function (one) {
      return one.key;
    }), primary: !!(opts && opts.primary) });
    return Promise.resolve([{ handle: handle, realm: realm.id, key: column,
      body: keystore.seal(JSON.stringify({ n: 7 }), 'minted-rows',
                          tiers.mintedTierOf('authn.sessions'),
                          { realm: realm.id }) }]);
  };
  install(driver);
  await minted.restore();
  await store.warm(['warm-1', 'warm-2']);
  t.check(calls.length === 1 && calls[0].primary &&
          calls[0].keys.indexOf(column) >= 0 && calls[0].keys.length === 2,
          'warm() asks once, from the primary, by key column',
          JSON.stringify(calls));
  t.equal(JSON.stringify(store.realmMap().get('warm-1')),
          JSON.stringify({ n: 7 }), 'and holds the row it read, opened');
  store.realmMap().clear();
  log.debug("Leaving warmCases().");
}

async function residentCases(t, realm) {
  log.debug("Entering residentCases().");
  t.log.info('=== a key-resident store loads its keys, not its rows ===');
  const handle = 'session-index.resident';
  const store = realms.map({ persist: handle,
                             onDemand: { maxEntries: 10, keysResident: true } });
  const asked = [];
  const filters = [];
  const driver = indexDriver([], [], [], filters);
  driver.loadMintedKeys = function (handles, realmIds) {
    asked.push({ handles: handles.slice(), realms: realmIds.slice() });
    return Promise.resolve([{ handle: handle, realm: realm.id,
      key: minted.keyColumnOf(handle, realm.id, 'revoked-1') }]);
  };
  install(driver);
  await minted.restore();
  t.check(filters.length && filters[0].indexOf(handle) >= 0,
          'a key-resident store is not read back', JSON.stringify(filters));
  t.check(asked.length === 1 && asked[0].handles.indexOf(handle) >= 0 &&
          asked[0].realms.indexOf(realm.id) >= 0,
          'its keys are loaded, in every realm the restore reads',
          JSON.stringify(asked));
  t.equal(store.onDemandLive(), true, 'it is on demand');
  t.equal(store.has('revoked-1'), true,
          'a loaded key answers has() without a read');
  t.equal(store.has('fresh-jti'), false, 'any other key is absent');
  t.equal(store.size, 1, 'size is the count of keys');

  // Another process's write, then its delete: the applier reads the row and
  // files or removes the digest by what it says, holding no record.
  const bodies = {};
  const otherKey = minted.keyColumnOf(handle, realm.id, 'other-1');
  bodies[otherKey] = { handle: handle, realm: realm.id, key: otherKey,
    body: keystore.seal(JSON.stringify({ exp: 0 }), 'minted-rows',
                        tiers.mintedTierOf('authn.sessions'),
                        { realm: realm.id }) };
  driver.readMinted = function (handleName, realmId, key) {
    return Promise.resolve(bodies[key] || null);
  };
  const change = { key: Buffer.from(handle).toString('base64url') + '.' +
                   Buffer.from('other-1').toString('base64url'),
                   realm: realm.id };
  await minted.applyChange(change);
  t.equal(store.has('other-1'), true,
          'another process\'s write files the digest');
  t.equal(store.realmMap().has('other-1'), false, 'and holds no record');
  delete bodies[otherKey];
  await minted.applyChange(change);
  t.equal(store.has('other-1'), false,
          'and its delete removes it: a "no" is never a stale "yes"');
  delete driver.loadMintedKeys;
  install(driver);
  t.equal(store.onDemandLive(), false,
          'a driver that cannot load keys does not make it key-resident');
  log.debug("Leaving residentCases().");
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
  await indexBackfillCases(t, realm);
  await residentCases(t, realm);
  await expiryBackfillCases(t);
  await unchangedLookupCases(t, realm);
  await warmCases(t, realm);
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
  // THE FULL MAP RESIDENT, AS THIS FILE ASSERTS IT (#350's second pull
  // request): the index beside the sealed body, with every session held.
  // The default `auto` turns the window on here (minted persistence, one
  // cell, a digest key), and a change for a session no process holds is
  // then not restored into the map; `tests/session_window.js` holds that.
  const windowWas = process.env.STS_AUTHN_SESSION_WINDOW;
  process.env.STS_AUTHN_SESSION_WINDOW = 'off';
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
    if (windowWas === undefined) {
      delete process.env.STS_AUTHN_SESSION_WINDOW;
    } else {
      process.env.STS_AUTHN_SESSION_WINDOW = windowWas;
    }
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
