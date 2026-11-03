// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: sql_dialect.js
//
// ===========================================================================
// THE STORE'S STATEMENTS, COMPILED PER ENGINE (#677).
//
// `persistence/sql_dialect.js` builds an ordinary statement once with the
// Knex query builder and compiles it for PostgreSQL or MariaDB with a Knex
// that has no connection. What this holds:
//
//   A. the compiler dials nothing and answers each engine's own placeholders;
//   B. every compiled statement carries its name, and a name is a bare token;
//   C. the statement clock is the statement's, not the transaction's, on
//      both engines — and PostgreSQL's is the one copy the driver splices in;
//   D. the fragments a cluster statement needs compile on both engines,
//      including the row lock MariaDB spells differently;
//   E. the capabilities say what MariaDB lacks, so the driver takes its
//      fallback rather than pretending.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');
const sqlDialect = require('../persistence/sql_dialect');

const log = require('bunyan').createLogger({ name: 'sql_dialect',
  level: process.env.LOG_LEVEL || 'info' });

async function run(t) {
  log.debug("Entering run().");
  const pg = sqlDialect.create('postgres');
  const maria = sqlDialect.create('mariadb');

  t.log.info('=== A. one statement, two engines ===');
  const since = function (d) {
    log.debug("Entering since().");
    log.debug("Leaving since().");
    return d.compile('changesSince',
      d.kx('sts_changes').select('seq', 'origin', 'kind', 'realm', 'key')
        .where('seq', '>', 7).orderBy('seq', 'asc').limit(500));
  };
  const a = since(pg);
  const b = since(maria);
  t.check(/where "seq" > \$1 order by "seq" asc limit \$2/.test(a.text),
          'A1. PostgreSQL gets $n placeholders and quoted identifiers',
          a.text);
  t.check(/where `seq` > \? order by `seq` asc limit \?/.test(b.text),
          'A2. MariaDB gets ? placeholders and backquoted identifiers',
          b.text);
  t.check(JSON.stringify(a.values) === '[7,500]' &&
          JSON.stringify(b.values) === '[7,500]',
          'A3. the values are the same, in the same order',
          JSON.stringify([a.values, b.values]));
  t.check(!pg.kx.client.pool && !maria.kx.client.pool,
          'A4. neither compiler holds a pool: it dials nothing');

  t.log.info('=== B. a statement carries its name ===');
  t.check(/ \/\* sts:changesSince \*\/$/.test(a.text) && a.name ===
          'changesSince',
          'B1. the name is a trailing comment, so a double anchored at the ' +
          'start still matches and an operator sees the operation', a.text);
  let refused = null;
  try {
    pg.compile('x */ DROP TABLE y; /*', pg.kx('t').select('a'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    refused = e;
  }
  t.check(!!refused, 'B2. a name that is not a bare token is refused, so ' +
          'it cannot close the comment', refused ? refused.message : '');

  t.log.info('=== C. the statement clock ===');
  const driverSource = fs.readFileSync(path.join(__dirname, '..',
    'persistence', 'persistence_postgres.js'), 'utf8');
  t.check(/^const DB_NOW = sqlDialect\.NOW\.postgres;$/m.test(driverSource),
          'C1. the driver\'s DB_NOW IS the dialect\'s PostgreSQL clock — one ' +
          'copy');
  t.check(/clock_timestamp\(\)/.test(sqlDialect.NOW.postgres) &&
          !/\bnow\(\)/.test(sqlDialect.NOW.postgres),
          'C2. PostgreSQL\'s is clock_timestamp(), not now() (the ' +
          'transaction\'s start)', sqlDialect.NOW.postgres);
  t.check(/SYSDATE\(6\)/.test(sqlDialect.NOW.mariadb) &&
          !/\bNOW\(/.test(sqlDialect.NOW.mariadb),
          'C3. MariaDB\'s is SYSDATE(6), evaluated when it runs, not NOW()',
          sqlDialect.NOW.mariadb);
  const later = maria.compile('purge', maria.kx('sts_cluster_nodes')
    .where('expires_at', '<', maria.now(60000, '-')).del());
  t.check(/`expires_at` < \(CAST\(ROUND\(UNIX_TIMESTAMP\(SYSDATE\(6\)\) \* 1000\) AS SIGNED\) - \?\)/
            .test(later.text) && later.values[0] === 60000,
          'C4. an offset from the clock is a bound value', later.text);

  t.log.info('=== D. what the cluster statements need ===');
  const insert = function (d) {
    log.debug("Entering insert().");
    log.debug("Leaving insert().");
    return d.compile('joinCluster.insert', d.kx('sts_cluster_nodes').insert({
      node_id: 'n', started_at: d.now(), expires_at: d.now(3000),
      info: d.json({ a: 1 })
    }));
  };
  t.check(/\$\d::jsonb/.test(insert(pg).text) &&
          !/::jsonb/.test(insert(maria).text),
          'D1. a JSON value is a jsonb cast on PostgreSQL and plain text on ' +
          'MariaDB', insert(pg).text + ' | ' + insert(maria).text);
  const share = function (d) {
    log.debug("Entering share().");
    log.debug("Leaving share().");
    return d.compile('fence', d.kx('sts_cluster_nodes').select('node_id')
      .where('expires_at', '>', d.now()).forShare());
  };
  t.check(/ for share /.test(share(pg).text) &&
          / lock in share mode /.test(share(maria).text),
          'D2. a shared row lock is FOR SHARE on PostgreSQL and LOCK IN ' +
          'SHARE MODE on MariaDB', share(maria).text);
  const upsert = function (d) {
    log.debug("Entering upsert().");
    log.debug("Leaving upsert().");
    return d.compile('offer', d.kx('sts_cluster_secrets')
      .insert({ name: 'n', material: 'm' }).onConflict('name').ignore());
  };
  t.check(/on conflict \("name"\) do nothing/.test(upsert(pg).text) &&
          /^insert ignore into `sts_cluster_secrets`/.test(upsert(maria).text),
          'D3. a first-writer-wins insert compiles on both engines',
          upsert(maria).text);

  t.log.info('=== E. capabilities ===');
  t.check(pg.capabilities.nudge && !maria.capabilities.nudge &&
          !maria.capabilities.transitionTriggers &&
          !maria.capabilities.transactionLocks,
          'E1. MariaDB has no nudge, no transition triggers and no ' +
          'transaction-scoped advisory lock — the driver\'s fallbacks',
          JSON.stringify(maria.capabilities));
  t.check(sqlDialect.POLL_WITHOUT_NUDGE_MS === 1000,
          'E2. the poll without a nudge is a second (rcbj on #677)');
  let unknown = null;
  try {
    sqlDialect.create('oracle');
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    unknown = e;
  }
  t.check(!!unknown, 'E3. an engine this store does not support is refused',
          unknown ? unknown.message : '');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'sql_dialect',
  describe: 'the store\'s statements compiled per engine by a Knex with no ' +
            'connection (#677)',
  run: run
};
