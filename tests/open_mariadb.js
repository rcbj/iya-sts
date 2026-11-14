// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: open_mariadb.js
//
// ===========================================================================
// OPENING A MARIADB STORE (#677): `persistence/open_mariadb.js`.
//
//   A. ALWAYS: an index statement names its table; the change log's density
//      is refused on evidence only (an increment above one, InnoDB's
//      interleaved lock mode) and passed for 1 / 0 or 1 and for a server that
//      says nothing.
//   B. AGAINST A REAL MARIADB, when STS_TEST_MARIADB_URL names a server the
//      test may create a database and a user on (both dropped after):
//      the first open creates every object of `schema_mariadb.js` and
//      records the schema version; a second creates nothing; the
//      least-privilege role opens a built store and creates nothing; and the
//      same role, with an index missing, is refused STS-STORE-0029 rather
//      than half-opening the store.
// ===========================================================================

delete process.env.CONFIG_FILE;

const openMariadb = require('../persistence/open_mariadb');
const schemaMariadb = require('../persistence/schema_mariadb');

const log = require('bunyan').createLogger({ name: 'open_mariadb',
  level: process.env.LOG_LEVEL || 'info' });

// A pool that answers the density probe with `row`.
function probePool(row) {
  log.debug("Entering probePool().");
  log.debug("Leaving probePool().");
  return {
    query: function () {
      log.debug("Entering query().");
      log.debug("Leaving query().");
      return Promise.resolve({ rows: row ? [row] : [] });
    }
  };
}

async function refusedBy(row) {
  log.debug("Entering refusedBy().");
  try {
    await openMariadb.checkChangeLogDense(probePool(row), log);
  } catch (e) {
    log.debug("Caught in refusedBy(): " + ((e && e.message) || e));
    log.debug("Leaving refusedBy(). Refused.");
    return String(e.message);
  }
  log.debug("Leaving refusedBy(). Passed.");
  return '';
}

async function staticChecks(t) {
  log.debug("Entering staticChecks().");
  t.log.info('=== A. the parts that need no server ===');
  const indexes = schemaMariadb.SCHEMA_OBJECTS.filter(function (o) {
    return /^CREATE (UNIQUE )?INDEX/i.test(o.statement);
  });
  const unnamed = indexes.filter(function (o) {
    return schemaMariadb.TABLES.indexOf(openMariadb.indexTable(o.statement)) <
      0;
  }).map(function (o) {
    return o.name;
  });
  t.check(indexes.length > 0 && unnamed.length === 0,
          'A1. every index statement names a table of the schema',
          unnamed.join(', '));
  t.check(/STS-STORE-0091/.test(await refusedBy({ increment: 2,
                                                  lockmode: 1 })),
          'A2. an auto_increment_increment of 2 is refused');
  t.check(/STS-STORE-0091/.test(await refusedBy({ increment: 1,
                                                  lockmode: 2 })),
          'A3. InnoDB\'s interleaved lock mode is refused');
  t.check(await refusedBy({ increment: 1, lockmode: 1 }) === '' &&
          await refusedBy({ increment: 1, lockmode: 0 }) === '' &&
          await refusedBy(null) === '' &&
          await refusedBy({ other: 1 }) === '',
          'A4. 1 with lock mode 0 or 1 opens, and so does a server that says ' +
          'nothing: the refusal is on evidence only');
  log.debug("Leaving staticChecks().");
}

async function againstMariadb(t) {
  log.debug("Entering againstMariadb().");
  const url = process.env.STS_TEST_MARIADB_URL || '';
  if (!url) {
    t.log.info('=== B. skipped: STS_TEST_MARIADB_URL names no database ===');
    log.debug("Leaving againstMariadb(). Skipped.");
    return;
  }
  t.log.info('=== B. against a real MariaDB ===');
  const knexStore = require('../persistence/knex_store');
  const scratch = 'open_' + process.pid;
  const user = 'open_app_' + process.pid;
  const admin = knexStore.openConnection({ connectionString: url });
  await admin.connect();
  await admin.query('CREATE DATABASE ' + scratch);
  const owner = knexStore.openPool({ connectionString:
    url.replace(/\/[^/?]*(\?|$)/, '/' + scratch + '$1') }, { max: 2 });
  let app = null;
  try {
    const first = await openMariadb.open(owner, log);
    t.check(first.length === schemaMariadb.SCHEMA_OBJECTS.length,
            'B1. THE FIRST OPEN CREATES THE WHOLE SCHEMA',
            first.length + ' of ' + schemaMariadb.SCHEMA_OBJECTS.length);
    const version = await owner.query('SELECT version FROM sts_schema');
    t.check(Number((version.rows[0] || {}).version) ===
              schemaMariadb.SCHEMA_VERSION,
            'B2. and records the schema version', JSON.stringify(version.rows));
    const second = await openMariadb.open(owner, log);
    t.check(second.length === 0, 'B3. a second open creates nothing',
            second.join(', '));
    await admin.query('CREATE USER \'' + user + '\'@\'%\' IDENTIFIED BY ' +
                      '\'probe-app\'');
    await admin.query('GRANT SELECT, INSERT, UPDATE, DELETE ON ' + scratch +
                      '.* TO \'' + user + '\'@\'%\'');
    const parsed = new URL(url.replace(/^mariadb:/, 'http:'));
    const appUrl = 'mariadb://' + user + ':probe-app@' + parsed.host + '/' +
      scratch;
    app = knexStore.openPool({ connectionString: appUrl }, { max: 2 });
    const asApp = await openMariadb.open(app, log);
    t.check(asApp.length === 0,
            'B4. the least-privilege role opens a built store and creates ' +
            'nothing', asApp.join(', '));
    const probes = require('../persistence/metrics_mariadb').METRIC_PROBES;
    const failed = [];
    for (const probe of probes) {
      try {
        const answer = await app.query(probe.sql);
        if (probe.shape === 'row' && !(answer.rows || [])[0]) {
          failed.push(probe.id + ': no row');
        }
      } catch (e) {
        log.debug("Caught in againstMariadb(): " + ((e && e.message) || e));
        failed.push(probe.id + ': ' + e.message);
      }
    }
    t.check(failed.length === 0,
            'B4b. EVERY /admin/database PROBE ANSWERS for the ' +
            'least-privilege role', failed.join(' | '));
    await owner.query('DROP INDEX sts_cluster_claims_expiry ON ' +
                      'sts_cluster_claims');
    let refusal = '';
    try {
      await openMariadb.open(app, log);
    } catch (e) {
      log.debug("Caught in againstMariadb(): " + ((e && e.message) || e));
      refusal = String(e.message);
    }
    t.check(/STS-STORE-0029/.test(refusal) && /mariadb\/schema\.sql/.test(
              refusal),
            'B5. WITH AN INDEX MISSING THE ROLE IS REFUSED STS-STORE-0029, ' +
            'naming the owner script', refusal.slice(0, 200));
  } finally {
    if (app) {
      await app.end();
    }
    await owner.end();
    await admin.query('DROP USER IF EXISTS \'' + user + '\'@\'%\'');
    await admin.query('DROP DATABASE ' + scratch);
    await admin.end();
  }
  log.debug("Leaving againstMariadb().");
}

async function run(t) {
  log.debug("Entering run().");
  await staticChecks(t);
  await againstMariadb(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'open_mariadb',
  describe: 'opening a MariaDB store: what exists asked, what is missing ' +
            'created by an owner and refused to the application role, the ' +
            'change log\'s density (#677)',
  run: run
};
