// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: minted_flush_one_statement.js
//
// ===========================================================================
// A MINTED FLUSH IS ONE ROUND TRIP (2026-10-22, #820).
//
// On 8081 a request worker ran one minted flush at a time, every writing
// request waited for its commit, and `saveMinted()` took 23 ms at the median
// for about ten rows while `pg_stat_statements` counted about 5 ms of
// statements: the rest was about eleven round trips (BEGIN, the fence, the
// lock, seven writes, the change log, COMMIT), each an event-loop turn on a
// worker ~85% busy. The flush is one statement now, MINTED_FLUSH, and this
// file counts what the driver sends for each `saveMinted()` against a `pg`
// double that plays the statement (`tools/minted_flush_double.js`):
//
//   A. a flush of plain, guarded and deleted rows: ONE statement, named (a
//      prepared statement, so it is planned once per connection), no BEGIN
//      and no COMMIT, and the effects its arrays carry;
//   B. a merging row (`mergeRow`) never written here: one statement,
//      expecting no row; written again by this process: one statement, the
//      merge handed the body this process committed; changed by another
//      process: two — the miss answers the stored body and the merge is
//      done again from it — and a stored tombstone refuses it with nothing
//      written;
//   C. a guarded upsert the tombstone refuses: reported refused, no index
//      row and no change row for it, and the change rows counted at once;
//   D. a deadlock (40P01) on the statement: sent again, as a transaction
//      always was;
//   E. a fence that does not hold: the flush becomes a transaction, whose
//      fence refuses it with nothing written;
//   F. a compare-and-set that misses twice: the read-then-write transaction,
//      merging with the body it locked.
//
// What a double cannot show — the plan, the lock order between two
// processes, the deadlocks — was measured against a real postgres and is in
// `persistence/CLAUDE.md` (*A minted flush is one statement*).
// ===========================================================================

const storeDouble = require('./tools/store_double');
const flushDouble = require('./tools/minted_flush_double');

const log = require('bunyan').createLogger({
  name: 'minted_flush_one_statement',
  level: process.env.LOG_LEVEL || 'info' });

const postgres = require('../persistence/persistence_postgres');

const TOMBSTONE = '$tombstone$1';

// A database of Maps every pooled query reaches. `ctl.fenceOk` answers the
// statement's fence and the transaction's node check; `ctl.deadlocks` fails
// that many flush statements with 40P01; `ctl.meddle(db)` runs before each
// flush statement (another process writing).
function fakePg(sent, ctl) {
  log.debug("Entering fakePg().");
  const db = ctl.db;
  function FakeClient() {}
  FakeClient.prototype.query = function (sql, params) {
    const flush = flushDouble.isFlush(sql);
    const text = flush ? sql.text : String(sql);
    if (!/pg_notify/.test(text)) {
      sent.push({ flush: flush, name: flush ? sql.name : null,
                  sql: flush ? 'MINTED_FLUSH' : text,
                  params: flush ? flushDouble.named(sql) : (params || []) });
    }
    if (flush) {
      if (ctl.deadlocks > 0) {
        ctl.deadlocks--;
        const err = /** @type {any} */ (new Error('deadlock detected'));
        err.code = '40P01';
        return Promise.reject(err);
      }
      if (ctl.meddle) {
        ctl.meddle(db);
      }
      // A statement sent in a transaction carries no fence (the
      // transaction asked it); one sent alone is answered by `ctl`.
      const fenceOk = flushDouble.named(sql).node_id === null ||
        ctl.fenceOk !== false;
      return Promise.resolve(flushDouble.play(db, sql, null,
                                              { fenceOk: fenceOk }));
    }
    if (/^SELECT 1 FROM sts_cluster_nodes/.test(text)) {
      const ok = ctl.fenceOk !== false;
      return Promise.resolve({ rows: ok ? [{}] : [], rowCount: ok ? 1 : 0 });
    }
    if (/^SELECT handle, realm, key, body FROM sts_minted/.test(text)) {
      if (ctl.meddle) {
        ctl.meddle(db);
      }
      const p = params || [];
      const rows = [];
      (p[0] || []).forEach(function (h, i) {
        const one = db.minted.get(h + '\n' + p[1][i] + '\n' + p[2][i]);
        if (one) {
          rows.push({ handle: h, realm: p[1][i], key: p[2][i],
                      body: one.body });
        }
      });
      return Promise.resolve({ rows: rows, rowCount: rows.length });
    }
    return Promise.resolve({ rows: [], rowCount: 0 });
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

function driverWith(sent, ctl) {
  log.debug("Entering driverWith().");
  const restore = storeDouble.install(fakePg(sent, ctl));
  try {
    log.debug("Leaving driverWith().");
    return postgres.create({
      url: 'postgres://sts_app@localhost:5432/sts',
      log: { debug: function () {}, info: function () {},
             warn: function () {}, error: function () {} }
    });
  } finally {
    restore();
  }
}

// A session row whose store merges: `merge(stored)` records what it was
// handed and answers a merge of it with this copy.
function sessionRow(key, body, seen) {
  log.debug("Entering sessionRow().");
  const row = { handle: 'authn.sessions', realm: 'default', key: key,
                journalKey: key, body: body, tombstone: true, keySealed: '',
                index: { lastSeenAt: 7, startedAt: 1 } };
  row.merge = function (stored) {
    seen.push(stored);
    return 'merged(' + stored + '+' + body + ')';
  };
  log.debug("Leaving sessionRow().");
  return row;
}

function round(sent) {
  log.debug("Entering round().");
  log.debug("Leaving round().");
  return sent.map(function (one) { return one.sql; }).join(' | ');
}

async function sectionA(t) {
  log.debug("Entering sectionA().");
  t.log.info('=== A. plain, guarded and deleted rows: one statement ===');
  const sent = [];
  const ctl = { db: flushDouble.state() };
  ctl.db.minted.set('test.gone\ndefault\nd1', { body: 'old' });
  ctl.db.index.add('tok.x\ndefault\nold-family\nt1');
  const driver = driverWith(sent, ctl);
  const before = driver.changeRowsWritten();
  const out = await driver.saveMinted([
    { handle: 'test.plain', realm: 'default', key: 'p1', body: 'P',
      journalKey: 'p1', keySealed: 'S$p1', expiresAt: 1234 },
    { handle: 'tok.x', realm: 'default', key: 't1', body: 'T',
      journalKey: 't1', tombstone: true, keySealed: '',
      lookups: ['family'] },
    { handle: 'test.own', realm: 'default', key: 'o1', body: 'O',
      journalKey: 'o1', own: true, keySealed: '' }
  ], [
    { handle: 'test.gone', realm: 'default', key: 'd1', journalKey: 'd1',
      keySealed: '' },
    { handle: 'authn.sessions', realm: 'default', key: 's9',
      journalKey: 's9', tombstone: true, keySealed: '' }
  ]);
  t.equal(round(sent), 'MINTED_FLUSH',
          'ONE round trip: the flush statement, no BEGIN, no fence, no ' +
          'lock and no COMMIT of its own');
  t.equal(sent[0] && sent[0].name, 'sts_minted_flush_v1',
          'sent as a named (prepared) statement, planned once per ' +
          'connection');
  t.equal(out.refused.length + out.merged.length, 0,
          'nothing refused, nothing merged');
  const db = ctl.db;
  t.check(db.minted.get('test.plain\ndefault\np1').body === 'P' &&
          db.minted.get('test.plain\ndefault\np1').expiresAt === 1234 &&
          db.minted.get('test.plain\ndefault\np1').keySealed === 'S$p1',
          'a plain upsert with its expiry and sealed name');
  t.check(!db.minted.has('test.gone\ndefault\nd1'),
          'a delete removes its row');
  t.equal(db.minted.get('authn.sessions\ndefault\ns9').body, TOMBSTONE,
          'a tombstoned delete writes the tombstone');
  t.check(db.index.has('tok.x\ndefault\nfamily\nt1') &&
          !db.index.has('tok.x\ndefault\nold-family\nt1'),
          'an indexed row\'s index is replaced (#820)');
  t.equal(db.changes.map(function (c) { return c.kind; }).join(','),
          'minted,minted,minted-own,minted,minted',
          'a change row per key, upserts then deletes, `minted-own` for ' +
          'an own store');
  t.equal(db.changes[0].key,
          Buffer.from('test.plain').toString('base64url') + '.S$p1',
          'the change row names the sealed name');
  t.equal(driver.changeRowsWritten() - before, 5,
          'and the five are counted as committed when the statement answers');
  log.debug("Leaving sectionA().");
}

async function sectionB(t) {
  log.debug("Entering sectionB().");
  t.log.info('=== B. a merging row: one statement, two on a miss ===');
  const sent = [];
  const ctl = { db: flushDouble.state() };
  const driver = driverWith(sent, ctl);
  const seen = [];
  await driver.saveMinted([sessionRow('s1', 'first', seen)], []);
  t.equal(round(sent), 'MINTED_FLUSH',
          'a session never written: one statement, expecting no row');
  t.equal(sent[0].params.cas_body[0], null,
          'the compare-and-set expects no row');
  t.equal(seen.length, 0, 'and there is nothing to merge with');
  t.equal(ctl.db.sessions.size, 1, 'its index row is written with it');

  sent.length = 0;
  const again = await driver.saveMinted([sessionRow('s1', 'second', seen)],
                                        []);
  t.equal(round(sent), 'MINTED_FLUSH',
          'written again by this process: still one statement');
  t.equal(sent[0].params.cas_body[0], 'first',
          'expecting the body this process committed');
  t.equal(seen.join(','), 'first',
          'and the merge is handed that body, as the read under the lock ' +
          'would have handed it');
  t.equal(ctl.db.minted.get('authn.sessions\ndefault\ns1').body,
          'merged(first+second)', 'the merge is what is written');
  t.equal(again.merged.length, 1, 'and it is reported merged');

  sent.length = 0;
  seen.length = 0;
  ctl.db.minted.get('authn.sessions\ndefault\ns1').body = 'theirs';
  const missed = await driver.saveMinted([sessionRow('s1', 'third', seen)],
                                         []);
  t.equal(round(sent), 'MINTED_FLUSH | MINTED_FLUSH',
          'another process wrote it since: two statements');
  t.equal(seen.join(','), 'merged(first+second),theirs',
          'the first merged with what this process expected, the second ' +
          'with the body the miss answered');
  t.equal(ctl.db.minted.get('authn.sessions\ndefault\ns1').body,
          'merged(theirs+third)', 'and only the second is written');
  t.equal(missed.merged.length, 1, 'one merge reported, not two');
  t.equal(ctl.db.changes.length, 3,
          'and one change row for each flush that wrote');

  sent.length = 0;
  seen.length = 0;
  ctl.db.minted.get('authn.sessions\ndefault\ns1').body = TOMBSTONE;
  const before = ctl.db.changes.length;
  const ended = await driver.saveMinted([sessionRow('s1', 'fourth', seen)],
                                        []);
  t.equal(ended.refused.length, 1,
          'a session another node ended is refused');
  t.equal(seen.length, 1,
          'the tombstone itself is never handed to the merge');
  t.equal(ctl.db.minted.get('authn.sessions\ndefault\ns1').body, TOMBSTONE,
          'the tombstone stands');
  t.equal(ctl.db.changes.length, before, 'and no change row is written');
  sent.length = 0;
  await driver.saveMinted([sessionRow('s1', 'fifth', seen)], []);
  t.equal(round(sent), 'MINTED_FLUSH',
          'the tombstone is remembered: the next try is one statement');
  log.debug("Leaving sectionB().");
}

async function sectionC(t) {
  log.debug("Entering sectionC().");
  t.log.info('=== C. a guarded upsert the tombstone refuses ===');
  const sent = [];
  const ctl = { db: flushDouble.state() };
  ctl.db.minted.set('authn.sessions\ndefault\ns2', { body: TOMBSTONE });
  const driver = driverWith(sent, ctl);
  const before = driver.changeRowsWritten();
  const out = await driver.saveMinted([
    { handle: 'authn.sessions', realm: 'default', key: 's2', body: 'B',
      journalKey: 's2', tombstone: true, keySealed: '',
      index: { lastSeenAt: 1 } },
    { handle: 'test.plain', realm: 'default', key: 'p2', body: 'P',
      journalKey: 'p2', keySealed: '' }
  ], []);
  t.equal(round(sent), 'MINTED_FLUSH', 'one statement');
  t.equal(out.refused.map(function (r) { return r.key; }).join(','), 's2',
          'the guarded upsert is refused');
  t.equal(ctl.db.sessions.size, 0, 'and writes no index row');
  t.equal(ctl.db.changes.length, 1, 'and no change row: only p2\'s');
  t.equal(driver.changeRowsWritten() - before, 1,
          'and one change row counted');
  log.debug("Leaving sectionC().");
}

async function sectionD(t) {
  log.debug("Entering sectionD().");
  t.log.info('=== D. a deadlock on the statement is sent again ===');
  const sent = [];
  const ctl = { db: flushDouble.state(), deadlocks: 2 };
  const driver = driverWith(sent, ctl);
  await driver.saveMinted([{ handle: 'test.plain', realm: 'default',
                             key: 'p3', body: 'P', journalKey: 'p3',
                             keySealed: '' }], []);
  t.equal(round(sent), 'MINTED_FLUSH | MINTED_FLUSH | MINTED_FLUSH',
          'two deadlocks, then the statement commits');
  t.equal(ctl.db.minted.get('test.plain\ndefault\np3').body, 'P',
          'and the row is written once');
  t.equal(ctl.db.changes.length, 1, 'with one change row');
  log.debug("Leaving sectionD().");
}

async function sectionE(t) {
  log.debug("Entering sectionE().");
  t.log.info('=== E. a fence that does not hold ===');
  const sent = [];
  const ctl = { db: flushDouble.state(), fenceOk: false };
  const driver = driverWith(sent, ctl);
  const fenced = [];
  driver.setFence(function () {
    return { nodeId: 'node-1', leases: [] };
  }, function (err) {
    fenced.push(err);
  });
  let thrown = null;
  try {
    await driver.saveMinted([{ handle: 'test.plain', realm: 'default',
                               key: 'p4', body: 'P', journalKey: 'p4',
                               keySealed: '' }], []);
  } catch (e) {
    thrown = e;
  }
  t.equal(sent[0] && sent[0].params.node_id, 'node-1',
          'the statement carries the fence');
  t.check(/^MINTED_FLUSH \| BEGIN \| SELECT 1 FROM sts_cluster_nodes/
            .test(round(sent)) && !/COMMIT/.test(round(sent)),
          'which did not hold, so the flush became a transaction whose ' +
          'fence refused it', round(sent));
  t.check(!!thrown && thrown.fenced === true && thrown.reason === 'node' &&
          fenced.length === 1,
          'the write is fenced and the cluster told');
  t.equal(ctl.db.minted.size + ctl.db.changes.length, 0,
          'and nothing was written');
  log.debug("Leaving sectionE().");
}

async function sectionF(t) {
  log.debug("Entering sectionF().");
  t.log.info('=== F. a compare-and-set that misses twice ===');
  const sent = [];
  let n = 0;
  const ctl = { db: flushDouble.state() };
  // Another process writes the row before each of this one's tries.
  ctl.meddle = function (db) {
    n++;
    db.minted.set('authn.sessions\ndefault\ns3', { body: 'other' + n });
  };
  const driver = driverWith(sent, ctl);
  const seen = [];
  const out = await driver.saveMinted([sessionRow('s3', 'mine', seen)], []);
  t.equal(round(sent), 'MINTED_FLUSH | MINTED_FLUSH | BEGIN | ' +
          'SELECT handle, realm, key, body FROM sts_minted WHERE (handle, ' +
          'realm, key) IN (SELECT h, r, k FROM unnest($1::text[], ' +
          '$2::text[], $3::text[]) AS u(h, r, k)) ORDER BY handle, realm, ' +
          'key FOR UPDATE | MINTED_FLUSH | COMMIT',
          'two misses, then the read-then-write transaction');
  t.equal(seen[seen.length - 1], 'other3',
          'which merges with the body it locked');
  t.equal(out.merged.length, 1, 'and reports that merge');
  log.debug("Leaving sectionF().");
}

async function run(t) {
  log.debug("Entering run().");
  await sectionA(t);
  await sectionB(t);
  await sectionC(t);
  await sectionD(t);
  await sectionE(t);
  await sectionF(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'minted_flush_one_statement',
  describe: 'a minted flush is one round trip: one statement, a ' +
            'compare-and-set for merging rows, a transaction only when ' +
            'the fence or the compare-and-set needs one (#820)',
  run: run
};
