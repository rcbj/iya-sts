// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: change_log_jump.js
//
// ===========================================================================
// A JUMP IN THE CHANGE-LOG SEQUENCE, AND A SEQUENCE THAT IS NOT DENSE (#677).
//
// `persistence_replication.js` remembered every number it stepped over, one
// at a time, in a synchronous loop. A gap of ten million (a `setval`, or an
// engine whose generator is sparse) held the event loop until the node's
// heartbeat lapsed. Now a gap wider than HOLE_SPAN_LIMIT is ONE range, asked
// for again with one read a pull, and a late commit inside it is still
// applied. And the postgres driver refuses at open a change log whose
// sequence leaves gaps by design (STS-STORE-0091), on evidence only.
// ===========================================================================

delete process.env.CONFIG_FILE;

const replication = require('../persistence/persistence_replication');
const postgres = require('../persistence/persistence_postgres');

const log = require('bunyan').createLogger({ name: 'change_log_jump',
  level: process.env.LOG_LEVEL || 'info' });

// A change log and nothing else: every row after the mark, paged.
function fakeDriver() {
  log.debug("Entering fakeDriver().");
  const rows = [];
  log.debug("Leaving fakeDriver().");
  return {
    rows: rows,
    reads: 0,
    origin: function () {
      log.debug("Entering origin().");
      log.debug("Leaving origin().");
      return 'me';
    },
    latestChangeSeq: function () {
      log.debug("Entering latestChangeSeq().");
      log.debug("Leaving latestChangeSeq().");
      return Promise.resolve(0);
    },
    changesSince: function (after, limit) {
      log.debug("Entering changesSince().");
      this.reads++;
      log.debug("Leaving changesSince().");
      return Promise.resolve(rows.filter(function (row) {
        return row.seq > after;
      }).sort(function (a, b) {
        return a.seq - b.seq;
      }).slice(0, limit));
    },
    changesAt: function (seqs) {
      log.debug("Entering changesAt().");
      log.debug("Leaving changesAt().");
      return Promise.resolve(rows.filter(function (row) {
        return seqs.indexOf(row.seq) >= 0;
      }));
    }
  };
}

// A row from another process.
function row(seq, key) {
  log.debug("Entering row().");
  log.debug("Leaving row().");
  return { seq: seq, origin: 'them', kind: 'directory', realm: '',
           key: key };
}

// A `pg` client double answering only the density probe.
function catalogClient(answer) {
  log.debug("Entering catalogClient().");
  log.debug("Leaving catalogClient().");
  return {
    query: function (sql) {
      log.debug("Entering query().");
      log.debug("Leaving query().");
      return Promise.resolve(/pg_sequence/.test(sql) ? answer : { rows: [] });
    }
  };
}

async function run(t) {
  log.debug("Entering run().");
  process.env.STS_PERSISTENCE_COORDINATE = 'true';
  replication.reset();
  const driver = fakeDriver();
  const seen = [];
  await replication.start(driver, {
    directory: function (change) {
      log.debug("Entering directory().");
      seen.push(change.key);
      log.debug("Leaving directory().");
    }
  });

  t.log.info('=== A. a jump of ten million is one range, not a loop ===');
  driver.rows.push(row(1, 'cn=before'));
  driver.rows.push(row(10000002, 'cn=after'));
  const started = Date.now();
  await replication.pull();
  const took = Date.now() - started;
  const status = replication.status();
  t.check(took < 1000,
          'THE PULL THAT STEPPED OVER TEN MILLION NUMBERS TOOK UNDER A ' +
          'SECOND — it used to hold the event loop for every one of them',
          took + 'ms');
  t.check(status.holeRanges === 1 && status.holes === 0,
          'and the gap is remembered as ONE range, with no hole per number',
          JSON.stringify({ holes: status.holes,
                           holeRanges: status.holeRanges }));
  t.check(seen.join(',') === 'cn=before,cn=after',
          'both visible rows were applied', seen.join(','));
  t.check(status.appliedSeq === 1,
          'and the low-water mark stays below the range',
          String(status.appliedSeq));

  t.log.info('=== B. a late commit inside the range is applied once ===');
  driver.rows.push(row(5000000, 'cn=late'));
  await replication.pull();
  await replication.pull();
  const late = seen.filter(function (key) {
    return key === 'cn=late';
  });
  t.check(late.length === 1,
          'A TRANSACTION THAT TOOK ITS NUMBER BEFORE THE JUMP AND COMMITTED ' +
          'AFTER IT IS APPLIED, AND ONLY ONCE across two pulls',
          seen.join(','));

  t.log.info('=== C. a small gap is still a hole per number ===');
  driver.rows.push(row(10000005, 'cn=small-gap'));
  await replication.pull();
  t.check(replication.status().holes === 2,
          'two missing numbers below HOLE_SPAN_LIMIT are two holes, as ' +
          'before', String(replication.status().holes));
  delete process.env.STS_PERSISTENCE_COORDINATE;
  replication.reset();

  t.log.info('=== D. a sequence that is not dense is refused at open ===');
  const check = function (client) {
    log.debug("Entering check().");
    log.debug("Leaving check().");
    return postgres.checkChangeLogDense(client, log);
  };
  t.check(typeof postgres.checkChangeLogDense === 'function',
          'the driver exposes its density check to this test',
          typeof postgres.checkChangeLogDense);
  let refused = null;
  try {
    await check(catalogClient({ rows: [{ increment: 1, cache: 20 }] }));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    refused = e;
  }
  t.check(refused && /STS-STORE-0091/.test(refused.message),
          'A CACHE OF 20 IS REFUSED with STS-STORE-0091',
          refused ? refused.message : 'not refused');
  refused = null;
  try {
    await check(catalogClient({ rows: [{ increment: 5, cache: 1 }] }));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    refused = e;
  }
  t.check(refused && /STS-STORE-0091/.test(refused.message),
          'an increment of 5 is refused', refused ? refused.message
            : 'not refused');
  let passed = true;
  try {
    await check(catalogClient({ rows: [{ increment: 1, cache: 1 }] }));
    await check(catalogClient({ rows: [] }));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    passed = false;
  }
  t.check(passed,
          'INCREMENT 1 CACHE 1 opens, and so does a server that says ' +
          'nothing: the refusal is on evidence only', String(passed));
  log.debug("Leaving run().");
}

module.exports = {
  name: 'change_log_jump',
  describe: 'a jump in the change-log sequence is one range; a sequence ' +
            'that is not dense is refused at open (#677)',
  run: run
};
