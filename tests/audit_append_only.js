// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: audit_append_only.js
//
// ===========================================================================
// THE AUDIT LOG IN ITS OWN APPEND-ONLY TABLE (#1616, ASVS 5.0.0 16.4.2).
//
// `persistence/audit_store.js` and `common/audit.js` against a stand-in
// driver, with the keystore's seal and open and minted persistence's switch
// stood in for, so what is asserted is this code's and not the database's
// (the role's refusals are `tests/postgres_schema.js`'s and
// `tests/mariadb_schema.js`'s, and were run against PostgreSQL 18 and
// MariaDB 11 when this was written):
//
//   A. an event recorded is ONE sealed row handed to `auditInsert()`, a
//      burst in one call, its chain checksums inside the seal;
//   B. a refused write keeps the rows for the next, and a driver that
//      throws does not throw out of the flush;
//   C. `fresh()` reads the realm's newest rows, every process's, and the
//      list shows them beside this process's own, each once, capped at
//      `audit.maxEvents`;
//   D. `restoreFromStore()` puts this process's own rows back into its
//      ring and copies the old segments in, then removes them;
//   E. retention asks the owner's function for every live realm and the
//      purge for a realm the table holds and the service does not;
//   F. `/admin/mode` reports the requirement not met where the probe found
//      the role able to change the table;
//   G. a data key's count includes `sts_audit` and its re-seal does not.
// ===========================================================================

const fs = require('fs');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'audit_append_only',
  level: process.env.LOG_LEVEL || 'info' });

// A driver with the five `audit*` methods and a call log.
function fakeDriver() {
  log.debug("Entering fakeDriver().");
  const d = { inserted: [], insertCalls: 0, refuse: 0, throwNow: false,
              stored: [], retained: [], purged: [], dropped: [],
              probe: { present: true, functions: true, writable: false } };
  d.auditInsert = function (rows) {
    if (d.throwNow) {
      d.throwNow = false;
      throw new Error('a synchronous throw');
    }
    d.insertCalls++;
    if (d.refuse > 0) {
      d.refuse--;
      return Promise.reject(new Error('the store refused'));
    }
    Array.prototype.push.apply(d.inserted, rows);
    return Promise.resolve(rows.length);
  };
  d.auditNewest = function (realm, limit, origin) {
    const rows = d.stored.filter(function (row) {
      return row.realm === realm &&
        (origin === undefined || row.origin === origin);
    }).sort(function (a, b) { return b.at - a.at; });
    return Promise.resolve(rows.slice(0, limit));
  };
  d.auditRetain = function (realm, keep) {
    d.retained.push(realm + ':' + keep);
    return Promise.resolve(0);
  };
  d.auditPurgeRealm = function (realm) {
    d.purged.push(realm);
    return Promise.resolve(0);
  };
  d.auditRealms = function () {
    return Promise.resolve(['default', 'removed-realm']);
  };
  d.auditDropLegacy = function (handle) {
    d.dropped.push(handle);
    return Promise.resolve(3);
  };
  d.auditPrivileges = function () {
    return Promise.resolve(d.probe);
  };
  log.debug("Leaving fakeDriver().");
  return d;
}

// One stored row as the driver keeps it, sealed the stand-in way.
function storedRow(realm, origin, seq, at, extra) {
  log.debug("Entering storedRow().");
  const row = Object.assign({ seq: seq, origin: origin, at: at,
                              category: 'protocol', action: 'protocol.call',
                              outcome: 'success', summary: 'stored ' + seq },
                            extra || {});
  log.debug("Leaving storedRow().");
  return { realm: realm, origin: origin, seq: seq, at: at,
           body: 'sealed:' + JSON.stringify(row) };
}

function settle() {
  log.debug("Entering settle().");
  log.debug("Leaving settle().");
  return new Promise(function (resolve) {
    setImmediate(function () {
      setImmediate(resolve);
    });
  });
}

async function run(t) {
  log.debug("Entering run().");
  const config = require('../common/config');
  const realms = require('../common/realms');
  const keystore = require('../common/keystore');
  const minted = require('../persistence/persistence_minted');
  const store = require('../persistence/audit_store');
  const audit = require('../common/audit');
  const mode = require('../common/mode');
  const replication = require('../persistence/persistence_replication');
  const saved = { seal: keystore.seal, open: keystore.open,
                  enabled: minted.enabled,
                  remote: replication.remoteSegmentedRows,
                  refresh: replication.refreshContributions };
  const driver = fakeDriver();
  keystore.seal = function (text) {
    return 'sealed:' + text;
  };
  keystore.open = function (text) {
    return String(text).indexOf('sealed:') === 0
      ? String(text).slice(7) : null;
  };
  minted.enabled = function () { return true; };
  store.setDriver(driver);
  config.setOverride('audit.maxEvents', 4);
  try {
    t.log.info('=== A. a recorded event is one sealed row ===');
    await store.flush();
    driver.inserted.length = 0;
    driver.insertCalls = 0;
    realms.run(realms.DEFAULT_REALM, function () {
      for (let i = 0; i < 3; i++) {
        audit.record({ action: 'protocol.call', summary: 'aao ' + i });
      }
    });
    await settle();
    await store.flush();
    const mine = driver.inserted.filter(function (row) {
      return /aao /.test(row.body);
    });
    t.equal(mine.length, 3, 'A1. three events, three rows');
    t.equal(driver.insertCalls, 1, 'A2. written in one call, a burst');
    const opened = JSON.parse(mine[0].body.slice(7));
    t.check(mine.every(function (row) {
      return row.realm === realms.DEFAULT_REALM.id &&
             /^sealed:/.test(row.body) && Number.isInteger(row.seq) &&
             row.at > 0;
    }) && typeof opened.mac === 'string' && 'prev' in opened,
            'A3. each row sealed, in its realm, with its seq and time, and ' +
            'its chain checksums inside the seal', JSON.stringify(opened));

    t.log.info('=== B. a refused write is kept; a throw does not escape ===');
    driver.inserted.length = 0;
    driver.refuse = 1;
    realms.run(realms.DEFAULT_REALM, function () {
      audit.record({ action: 'protocol.call', summary: 'aao kept' });
    });
    // The burst's own flush runs a turn later, and is refused.
    await settle();
    await settle();
    t.equal(driver.inserted.length, 0, 'B1. the first write was refused');
    await store.flush();
    t.check(driver.inserted.some(function (row) {
      return /aao kept/.test(row.body);
    }), 'B2. and the row went with the next');
    driver.throwNow = true;
    realms.run(realms.DEFAULT_REALM, function () {
      audit.record({ action: 'protocol.call', summary: 'aao thrown' });
    });
    let escaped = '';
    try {
      await settle();
      await store.flush();
      await store.flush();
    } catch (e) {
      escaped = e.message;
    }
    t.check(!escaped && driver.inserted.some(function (row) {
      return /aao thrown/.test(row.body);
    }), 'B3. a driver that throws does not throw out of the flush, and the ' +
       'row is written next time', escaped);

    t.log.info('=== C. every process\'s rows, each once, capped ===');
    driver.stored = [storedRow('default', 'node-b', 1, 10),
                     storedRow('default', 'node-b', 2, 11),
                     storedRow('default', 'node-c', 1, 12),
                     storedRow('default', 'node-c', 2, 9e15),
                     { realm: 'default', origin: 'node-d', seq: 1, at: 13,
                       body: 'not-openable' }];
    const listed = await realms.run(realms.DEFAULT_REALM, function () {
      return audit.fresh().then(function () {
        return audit.list();
      });
    });
    const ids = listed.map(function (row) {
      return row.origin + ':' + row.seq;
    });
    t.equal(listed.length, 4, 'C1. capped at audit.maxEvents (4)');
    t.equal(ids[0], 'node-c:2', 'C2. newest first, another process\'s row ' +
            'read from the table');
    t.check(ids.indexOf('node-d:1') < 0,
            'C3. a row that will not open is left out');
    t.equal(new Set(ids).size, ids.length, 'C4. each event once');

    t.log.info('=== D. a start: own rows back, the old ring copied ===');
    // Room for the stored rows, which are older than what the ring holds.
    config.setOverride('audit.maxEvents', 50);
    const origin = require('../persistence/persistence').originId() || '';
    driver.stored = [storedRow('default', origin, 900001, 1),
                     storedRow('default', origin, 900002, 2)];
    driver.inserted.length = 0;
    driver.dropped.length = 0;
    replication.refreshContributions = function () {
      return Promise.resolve();
    };
    replication.remoteSegmentedRows = function (handle, realmId) {
      return handle === 'audit.events' && realmId === 'default'
        ? [[{ seq: 7, origin: 'old-node', at: 5, prev: '', mac: 'm7',
              action: 'protocol.call', summary: 'old ring 7' }]] : [];
    };
    const done = await audit.restoreFromStore({ migrate: true });
    const ring = realms.run(realms.DEFAULT_REALM, function () {
      return audit.localEvents().map(function (row) { return row.seq; });
    });
    t.check(ring.indexOf(900001) >= 0 && ring.indexOf(900002) >= 0 &&
            done.restored >= 2,
            'D1. this process\'s own stored rows are back in its ring',
            JSON.stringify({ done: done, ring: ring }));
    const copiedRow = driver.inserted.filter(function (row) {
      return row.origin === 'old-node' && row.seq === 7;
    })[0];
    t.check(done.copied === 1 && !!copiedRow &&
            JSON.parse(copiedRow.body.slice(7)).mac === 'm7',
            'D2. the old ring\'s event is copied with its chain checksum',
            JSON.stringify(done));
    t.equal(driver.dropped.join(','), 'audit.events',
            'D3. and then the old segments are removed');

    t.log.info('=== E. retention and a removed realm ===');
    driver.retained.length = 0;
    driver.purged.length = 0;
    const out = await store.runRetention();
    t.check(driver.retained.indexOf('default:4') >= 0 && out.realms >= 1,
            'E1. every live realm is asked to keep its audit.maxEvents',
            JSON.stringify(driver.retained));
    t.equal(driver.purged.join(','), 'removed-realm',
            'E2. and the realm the table holds and the service does not is ' +
            'purged (the function checks it is gone)');

    t.log.info('=== F. /admin/mode when the role can change the table ===');
    config.setOverride('global.mode', 'product');
    try {
      driver.probe = { present: true, functions: true, writable: true };
      await store.privileges(true);
      const row = mode.report().requirements.filter(function (one) {
        return one.id === 'audit-append-only';
      })[0];
      t.check(!!row && Array.isArray(row.waived) &&
              row.waived[0].section === 'ASVS 5.0.0 16.4.2',
              'F1. the requirement is reported not met',
              JSON.stringify(row && row.waived));
      driver.probe = { present: true, functions: true, writable: false };
      await store.privileges(true);
      const fine = mode.report().requirements.filter(function (one) {
        return one.id === 'audit-append-only';
      })[0];
      t.check(!!fine && !fine.waived,
              'F2. and not where the role may only add and read');
    } finally {
      config.clearOverride('global.mode');
    }

    t.log.info('=== G. data keys: counted, never re-sealed ===');
    const source = fs.readFileSync(path.join(__dirname, '..', 'persistence',
                                             'persistence_postgres.js'),
                                   'utf8');
    t.check(/table: 'sts_audit', keys: \['realm', 'origin', 'seq'\], column: 'body',\s+jsonb: false, change: null, countOnly: true/
              .test(source),
            'G1. sts_audit is in the data-key count, marked count-only');
    t.check(/EXTRA_SEALED\.filter\(function \(one\) \{\s+return !one\.countOnly;/
              .test(source),
            'G2. and the re-seal pass leaves a count-only column alone');
  } finally {
    await store.flush();
    store.setDriver(null);
    keystore.seal = saved.seal;
    keystore.open = saved.open;
    minted.enabled = saved.enabled;
    replication.remoteSegmentedRows = saved.remote;
    replication.refreshContributions = saved.refresh;
    config.clearOverride('audit.maxEvents');
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'audit_append_only',
  describe: 'the audit log written to sts_audit, the append-only table: ' +
            'one sealed row per event, read back across processes, restored, ' +
            'the old ring copied, retention and the realm purge, the mode ' +
            'report and the data-key count (#1616)',
  run: run
};
