// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: notify_after_commit.js
//
// ===========================================================================
// THE CHANGE-LOG NUDGE GOES OUT AFTER THE COMMIT, AND AT MOST ONE A WINDOW
// (#630, 2026-10-14).
//
// `recordChanges()` sent `pg_notify` inside the writing transaction. A
// transaction that has notified takes the server's notify-queue lock at
// COMMIT and holds it through its WAL flush, so every writer of every
// process committed one at a time behind it: 0.34–0.58 backends waiting on
// `Lock:object` on 8081 under the bulk load, and 42 adds/s against 108 in a
// replay with the notify moved out. Now a transaction's kinds wait for its
// COMMIT, and `announce()` sends one notify per NOTIFY_COALESCE_MS window.
//
//   A. ONE COMMIT: no `pg_notify` on the transaction's client, one on the
//      pool, after the COMMIT, carrying the kind.
//   B. A ROLLED-BACK TRANSACTION, and one whose COMMIT fails, announce
//      nothing — not then, and not when the window closes.
//   C. MANY COMMITS IN A BURST: N transactions over a measured span send at
//      most one notify per window (plus the first), never fewer than one,
//      and the last notify follows the last COMMIT and carries every kind.
//   D. close() sends a nudge still due before the pool ends.
//
// Against a `pg` stand-in that numbers every statement in one sequence, so
// "after the COMMIT" is an order, not a timing.
// ===========================================================================

const storeDouble = require('./tools/store_double');
const log = require('bunyan').createLogger({ name: 'notify_after_commit',
  level: process.env.LOG_LEVEL || 'info' });

const QUIET = { debug: function () {}, info: function () {},
                warn: function () {}, error: function () {} };

// The window the driver coalesces over; asserted against its own export.
const WINDOW_MS = 25;

function sequencedPg(state) {
  log.debug("Entering sequencedPg().");
  state.seq = 0;
  state.log = [];
  let clients = 0;
  function record(via, sql, params) {
    state.seq += 1;
    state.log.push({ seq: state.seq, via: via, sql: String(sql),
                     params: params || [], at: Date.now() });
  }
  function FakeClient() {
    clients += 1;
    this.id = 'client-' + clients;
  }
  FakeClient.prototype.query = function (sql, params) {
    record(this.id, sql, params);
    const text = String(sql);
    if (state.failInsert && /INSERT INTO sts_appconfig/.test(text)) {
      return Promise.reject(new Error('the insert failed on purpose'));
    }
    if (state.failCommit && text === 'COMMIT') {
      return Promise.reject(new Error('the commit failed on purpose'));
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
  FakePool.prototype.query = function (sql, params) {
    record('pool', sql, params);
    return Promise.resolve({ rows: [], rowCount: 0 });
  };
  FakePool.prototype.end = function () {
    record('pool', 'END');
    return Promise.resolve();
  };
  log.debug("Leaving sequencedPg().");
  return { Pool: FakePool, Client: FakeClient };
}

function driverOver(state) {
  log.debug("Entering driverOver().");
  const restore = storeDouble.install(sequencedPg(state));
  try {
    log.debug("Leaving driverOver().");
    return require('../persistence/persistence_postgres').create({
      url: 'postgres://sts_app@localhost:5432/sts', log: QUIET });
  } finally {
    restore();
  }
}

function notifies(state) {
  log.debug("Entering notifies().");
  log.debug("Leaving notifies().");
  return state.log.filter(function (one) {
    return /pg_notify/.test(one.sql);
  });
}

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) { setTimeout(resolve, ms); });
}

function setting(i) {
  log.debug("Entering setting().");
  const set = {};
  set['audit.maxEvents'] = String(1000 + i);
  log.debug("Leaving setting().");
  return { set: set, cleared: [] };
}

async function oneCommit(t) {
  log.debug("Entering oneCommit().");
  t.log.info('=== A. one commit, one notify, after it ===');
  const state = {};
  const driver = driverOver(state);
  await driver.saveOverrides({}, setting(1));
  await sleep(WINDOW_MS * 3);
  const sent = notifies(state);
  const commit = state.log.filter(function (one) {
    return one.sql === 'COMMIT';
  })[0];
  t.equal(sent.length, 1, 'A1. one commit sends one notify');
  t.check(sent.every(function (one) { return one.via === 'pool'; }),
          'A2. on the pool, outside the transaction — never on the ' +
          'transaction\'s client, whose COMMIT it would serialise',
          JSON.stringify(sent.map(function (one) { return one.via; })));
  t.check(!!commit && sent.length > 0 && sent[0].seq > commit.seq,
          'A3. and after the COMMIT', JSON.stringify({
            commit: commit && commit.seq, notify: sent[0] && sent[0].seq }));
  const payload = sent.length ? JSON.parse(sent[0].params[1]) : {};
  t.check(JSON.stringify(payload.kinds) === '["appconfig"]' &&
          payload.rows === 1 && typeof payload.from === 'string',
          'A4. carrying the origin, the kind and the row count',
          JSON.stringify(payload));
  t.equal(driver.notifiesSent(), 1, 'A5. notifiesSent() counts it');
  log.debug("Leaving oneCommit().");
}

async function nothingUncommitted(t) {
  log.debug("Entering nothingUncommitted().");
  t.log.info('=== B. a rollback announces nothing ===');
  const state = { failInsert: true };
  const driver = driverOver(state);
  const rolled = await driver.saveOverrides({}, setting(2)).then(function () {
    return 'committed';
  }, function (e) {
    log.debug("Caught in nothingUncommitted(): " + ((e && e.message) || e));
    return 'rolled back';
  });
  state.failInsert = false;
  state.failCommit = true;
  const failed = await driver.saveOverrides({}, setting(3)).then(function () {
    return 'committed';
  }, function (e) {
    log.debug("Caught in nothingUncommitted(): " + ((e && e.message) || e));
    return 'failed';
  });
  await sleep(WINDOW_MS * 3);
  t.check(rolled === 'rolled back' && failed === 'failed',
          'B1. one transaction rolled back, one COMMIT failed',
          rolled + ' / ' + failed);
  t.equal(notifies(state).length, 0,
          'B2. and neither sent a notify, then or when the window closed');
  log.debug("Leaving nothingUncommitted().");
}

async function aBurst(t) {
  log.debug("Entering aBurst().");
  t.log.info('=== C. a burst of commits is coalesced ===');
  const state = {};
  const driver = driverOver(state);
  const N = 300;
  const began = Date.now();
  // Concurrent and sequential both: ten at a time, thirty rounds a few
  // milliseconds apart, so the burst spans several windows.
  for (let round = 0; round < N / 10; round += 1) {
    if (round > 0) {
      await sleep(7);
    }
    const batch = [];
    for (let i = 0; i < 10; i += 1) {
      const k = round * 10 + i;
      batch.push(k % 2 === 0
        ? driver.saveOverrides({}, setting(k))
        : driver.saveKeys('r' + k, '$aesgcm$2$x'));
    }
    await Promise.all(batch);
  }
  const ended = Date.now();
  await sleep(WINDOW_MS * 4);
  const sent = notifies(state);
  const commits = state.log.filter(function (one) {
    return one.sql === 'COMMIT';
  });
  const span = ended - began;
  const ceiling = Math.ceil(span / WINDOW_MS) + 1;
  t.equal(commits.length, N, 'C1. ' + N + ' transactions committed');
  t.check(sent.length >= 1 && sent.length <= ceiling,
          'C2. ' + sent.length + ' notify(ies) for ' + N + ' commits over ' +
          span + ' ms: at most one a ' + WINDOW_MS + ' ms window (ceiling ' +
          ceiling + ')', String(sent.length));
  t.check(sent.length < N / 4, 'C3. far fewer notifies than commits — ' +
          'coalesced', sent.length + ' of ' + N);
  t.check(sent.length >= 3, 'C3a. and the burst spanned several windows, ' +
          'each announced', String(sent.length));
  for (let i = 1; i < sent.length; i += 1) {
    if (sent[i].at - sent[i - 1].at < WINDOW_MS - 2) {
      t.bad('C4. two notifies inside one window',
            JSON.stringify([sent[i - 1].at, sent[i].at]));
      break;
    }
  }
  const last = sent[sent.length - 1];
  const lastCommit = commits[commits.length - 1];
  t.check(!!last && last.seq > lastCommit.seq,
          'C5. the last notify follows the last COMMIT — no commit is left ' +
          'unannounced', JSON.stringify({ commit: lastCommit.seq,
                                         notify: last && last.seq }));
  const kinds = new Set();
  let rows = 0;
  sent.forEach(function (one) {
    const payload = JSON.parse(one.params[1]);
    payload.kinds.forEach(function (k) { kinds.add(k); });
    rows += payload.rows;
  });
  t.check(kinds.has('appconfig') && kinds.has('keys'),
          'C6. the notifies carry both kinds between them',
          JSON.stringify(Array.from(kinds)));
  t.equal(rows, N, 'C7. and every committed change row is counted once');
  t.equal(driver.changeRowsWritten(), N,
          'C8. changeRowsWritten() still counts every committed row');
  log.debug("Leaving aBurst().");
}

async function theClose(t) {
  log.debug("Entering theClose().");
  t.log.info('=== D. close() sends a nudge still due ===');
  const state = {};
  const driver = driverOver(state);
  await driver.saveOverrides({}, setting(10));
  await driver.saveOverrides({}, setting(11));
  // The first went at once; the second is due when the window closes.
  t.equal(notifies(state).length, 1,
          'D1. the second commit inside the window is held');
  await driver.close();
  const sent = notifies(state);
  const end = state.log.filter(function (one) { return one.sql === 'END'; });
  t.equal(sent.length, 2, 'D2. close() sent it');
  t.check(end.length > 0 && sent[1].seq < end[0].seq,
          'D3. before the pool ended');
  await sleep(WINDOW_MS * 3);
  t.equal(notifies(state).length, 2, 'D4. and nothing after');
  log.debug("Leaving theClose().");
}

function theWindowIsTheDriver(t) {
  log.debug("Entering theWindowIsTheDriver().");
  const source = require('fs').readFileSync(require('path').join(__dirname,
    '..', 'persistence', 'persistence_postgres.js'), 'utf8');
  const match = /const NOTIFY_COALESCE_MS = (\d+);/.exec(source);
  t.check(!!match && Number(match[1]) === WINDOW_MS,
          'E1. the window asserted here is the driver\'s, ' + WINDOW_MS +
          ' ms — inside the ticket\'s 20–50', match && match[0]);
  // The one statement in a transaction that named the channel is gone.
  t.check(!/client\.query\('SELECT pg_notify/.test(source),
          'E2. no pg_notify is sent on a transaction\'s client');
  log.debug("Leaving theWindowIsTheDriver().");
}

async function run(t) {
  log.debug("Entering run().");
  theWindowIsTheDriver(t);
  await oneCommit(t);
  await nothingUncommitted(t);
  await aBurst(t);
  await theClose(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'notify_after_commit',
  describe: 'the change-log nudge is sent after the commit and coalesced to ' +
            'one per window (#630)',
  run: run
};
