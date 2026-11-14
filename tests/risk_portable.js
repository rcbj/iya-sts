// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: risk_portable.js
//
// ===========================================================================
// THE RISK ENGINE'S STORE ON MARIADB (#677): THE NATIVE CONTRACTS, IN SQL
// THE SECOND ENGINE RUNS.
//
//   A. ALWAYS: every operation of `persistence/risk_portable.js`, compiled
//      for MariaDB, carries none of PostgreSQL's syntax — no `$n`, no `::`
//      cast, no `ON CONFLICT`, no `RETURNING`, no `ctid`, no `unnest`, no
//      `FILTER`, no `GROUPING SETS`, no `DISTINCT ON`, no `inet` function,
//      no jsonb operator — and the values a substitute would replace are
//      refused before anything is sent. Driven against a runner that
//      records what it is sent. (No section B: the library is MariaDB's
//      only; PostgreSQL keeps its native text, which this does not touch.)
//   C. THE CONTRACTS AGAINST A REAL MARIADB, when STS_TEST_MARIADB_URL names
//      a server the test may create a database on (it makes one and drops
//      it), its tables from `persistence/schema_mariadb.js`: a version begun
//      once, its rows in batches, activated, looked up by IPv4 and IPv6
//      address at each end of a range and in each family only, by an
//      indexed seek; deactivated and its rows deleted in bounded batches;
//      failures recorded, listed and purged by age; the counts incremented
//      by twenty concurrent sign-ins and equal to the sum; an assessment
//      recorded, listed, settled, amended and counted; an action claimed by
//      ten callers at once with one winner; standings, session contexts and
//      terms acceptances.
//   D. THE REAL RISK STORE OVER THE DRIVER ON MARIADB: `risk/risk_store`'s
//      RiskStore given the postgres driver built with `engine: 'mariadb'`,
//      which sends every `risk*` method through the library.
// ===========================================================================

delete process.env.CONFIG_FILE;

const sqlDialect = require('../persistence/sql_dialect');
const riskPortable = require('../persistence/risk_portable');

const log = require('bunyan').createLogger({ name: 'risk_portable',
  level: process.env.LOG_LEVEL || 'info' });

// The tables a scratch database is given.
const TABLES = ['sts_changes', 'sts_risk_datasets',
                'sts_risk_dataset_versions', 'sts_risk_geo_ranges',
                'sts_risk_asn_ranges', 'sts_risk_ip_lists',
                'sts_risk_fido_authenticators', 'sts_risk_assessments',
                'sts_risk_feature_counts', 'sts_risk_failures',
                'sts_risk_session_context', 'sts_risk_subjects',
                'sts_risk_terms_acceptances'];

// Row shapes standing in for the driver's (`riskDatasetFrom()` and the
// rest): the row as the library hands it over.
const SHAPES = {
  dataset: function (r) {
    return Object.assign({ shaped: 'dataset' }, r);
  },
  version: function (r) {
    return Object.assign({ shaped: 'version' }, r);
  },
  range: function (kind, r) {
    return Object.assign({ shaped: kind }, r);
  },
  failure: function (r) {
    return Object.assign({ shaped: 'failure' }, r);
  }
};

/**
 * The library over a pool, with the driver's fenced transaction played by
 * plain BEGIN/COMMIT on a held connection and change rows written into
 * `sts_changes` as the driver's `recordChanges()` writes them.
 */
function opsOver(dialect, pool) {
  log.debug("Entering opsOver().");
  const transaction = function (fn) {
    return pool.connect().then(function (client) {
      return client.query('BEGIN').then(function () {
        return fn(client);
      }).then(function (result) {
        return client.query('COMMIT').then(function () {
          client.release();
          return result;
        });
      }, function (err) {
        return client.query('ROLLBACK').then(function () {
          client.release();
          throw err;
        });
      });
    });
  };
  log.debug("Leaving opsOver().");
  return riskPortable.create({
    dialect: dialect, pool: pool, tallyPool: pool,
    withTransaction: transaction,
    recordChanges: function (client, rows) {
      log.debug("Entering recordChanges().");
      let chain = Promise.resolve();
      rows.forEach(function (row) {
        chain = chain.then(function () {
          return client.query('INSERT INTO sts_changes (origin, kind, realm, ' +
                              '`key`) VALUES (?, ?, ?, ?)',
                              ['proc-1', row.kind, row.realm || '',
                               row.key || '']);
        });
      });
      log.debug("Leaving recordChanges().");
      return chain;
    },
    processId: function () {
      log.debug("Entering processId().");
      log.debug("Leaving processId().");
      return 'proc-1';
    },
    shapes: SHAPES
  });
}

// A runner that records each statement and answers by its name.
function recorder() {
  log.debug("Entering recorder().");
  const sent = [];
  const answer = function (text) {
    const name = (/\/\* sts:risk\.([A-Za-z.]+) \*\//.exec(text) || [])[1] ||
      '';
    const one = function (row) {
      return { rows: [row], rowCount: 1 };
    };
    if (name === 'finishVersion.lock') {
      return one({ parameters: '{"a":1}' });
    }
    if (name === 'activate.version') {
      return one({ state: 'ready' });
    }
    if (name === 'activate.dataset') {
      return one({ active_version: 'old' });
    }
    if (name === 'deactivate.dataset') {
      return one({ active_version: 'v1' });
    }
    if (name === 'abandonStalled.lock') {
      return one({ realm: '', dataset: 'd', version: 'v' });
    }
    if (name === 'upsertSubject.lock') {
      return one({ level: 'LOW', crossed_at: '0' });
    }
    if (name === 'beginVersion.reload') {
      return { rows: [], rowCount: 0, affectedRows: 0 };
    }
    return { rows: [], rowCount: 1, affectedRows: 1, insertId: 7 };
  };
  const runner = {
    sent: sent,
    query: function (text, values) {
      log.debug("Entering query().");
      sent.push({ text: String(text), values: values || [] });
      log.debug("Leaving query().");
      return Promise.resolve(answer(String(text)));
    },
    connect: function () {
      log.debug("Entering connect().");
      log.debug("Leaving connect().");
      return Promise.resolve({
        query: runner.query,
        release: function () {
          log.debug("Entering release().");
          log.debug("Leaving release().");
        }
      });
    }
  };
  log.debug("Leaving recorder().");
  return runner;
}

function version(over) {
  log.debug("Entering version().");
  log.debug("Leaving version().");
  return Object.assign({
    realm: '', dataset: 'geo.city', version: 'v1', format: 'csv',
    provider: 'p', licence: 'l', source: 's', sha256: 'h', byteCount: 10,
    parameters: { a: 1 }, verification: 'none', publishedAt: 1,
    fetchedAt: 100
  }, over || {});
}

function assessment(id, over) {
  log.debug("Entering assessment().");
  log.debug("Leaving assessment().");
  return Object.assign({
    realm: 'r', id: id, at: 1000, phase: 'user', door: 'password',
    subject: 'alice', sessionId: '', addressSealed: 'sealed',
    addressPrefix: '192.0.2.0/24', asn: 64500, country: 'DE',
    city: 'Berlin', latitude: 52.5, longitude: 13.4, ipLists: ['tor'],
    bot: false, backupEligible: true, backupState: false,
    datasets: { geo: 'v1' },
    signals: [{ signal: 'new-ip' }, { signal: 'new_ua' }],
    score: 0.123456789, level: 'LOW', decision: 'observe'
  }, over || {});
}

// Every operation once.
async function exercise(ops) {
  log.debug("Entering exercise().");
  await ops.riskListDatasets();
  await ops.riskListVersions('', 'geo.city');
  await ops.riskBeginVersion(version(), false);
  await ops.riskBeginVersion(version(), true);
  await ops.riskInsertRows('geo', '', 'geo.city', 'v1', [
    { start: '192.0.2.0', end: '192.0.2.255', country: 'DE',
      latitude: 1, longitude: 2 },
    { start: '2001:db8::', end: '2001:db8::ffff' }]);
  await ops.riskInsertRows('asn', '', 'asn', 'v1',
                           [{ start: '192.0.2.0', end: '192.0.2.255',
                              asn: 64500 }]);
  await ops.riskInsertRows('iplist', 'r', 'tor', 'v1',
                           [{ start: '192.0.2.1', end: '192.0.2.1',
                              category: 'tor' }]);
  await ops.riskInsertRows('fido', '', 'fido', 'v1',
                           [{ keyKind: 'aaguid', key: 'k',
                              statusReports: [{ status: 'X' }] }]);
  await ops.riskFinishVersion('', 'geo.city', 'v1',
                              { state: 'ready', parameters: { b: 2 } });
  await ops.riskTouchVersion('', 'geo.city', 'v1', 5, 6);
  await ops.riskAbandonStalled(10, 11, 'why', 'STS-X');
  await ops.riskActivate('', 'geo.city', 'geo', 'v1', 7);
  await ops.riskDeleteRows('geo', '', 'geo.city', 'v1', 2);
  await ops.riskDeleteRows('iplist', 'r', 'tor', 'v1', 2);
  await ops.riskDeactivate('', 'geo.city', 'v1', 8);
  await ops.riskMarkRowsDeleted('', 'geo.city', 'v1', 9);
  await ops.riskLookupFido('fido', 'v1', 'aaguid', 'K');
  await ops.riskLookupRange('geo', '', 'geo.city', 'v1', '192.0.2.7');
  await ops.riskLookupRange('iplist', 'r', 'tor', 'v1', '2001:db8::1');
  await ops.riskRecordFailure({ realm: 'r', at: 1, door: 'password',
                                addressPrefix: '192.0.2.0/24',
                                errorCode: 'E' });
  await ops.riskListFailures('r', { prefix: '192.0.2.0/24',
                                    excludeDoor: ['totp-replay'] });
  await ops.riskPurgeFailures(5, 3);
  await ops.riskFeatureCounts('r', 'alice', [{ feature: 'ip', value: 'x' }]);
  await ops.riskDistinctValues('r', 'alice', 'ip>asn', '1_2%');
  await ops.riskDistinctValuesMany('r', 'alice', [{ feature: 'ip' },
                                                  { feature: 'ip>asn',
                                                    prefix: 'a|' }]);
  await ops.riskIncrementCounts('r', [{ subject: 'alice', feature: 'ip',
                                        value: 'x' }], 5);
  await ops.riskRecordAssessment(assessment('a1'));
  await ops.riskListAssessments('r', { subject: 'alice', level: 'LOW' });
  await ops.riskSetFeedback('r', 'a1', 'alice', 'mine', 5);
  await ops.riskSettleAssessment({ realm: 'r', id: 'a1', decision: 'allow',
                                   sessionId: 's1' });
  await ops.riskAmendAssessment({ realm: 'r', id: 'a1', signals: [],
                                  score: 1, level: 'MEDIUM' });
  await ops.riskClaimAction('r', 'alice', 'end-sessions', 'a1');
  await ops.riskSubjectOf('r', 'alice');
  await ops.riskUpsertSubject({ realm: 'r', subject: 'alice', score: 1,
                                level: 'HIGH', updatedAt: 5 });
  await ops.riskListSubjects('r', {});
  await ops.riskAssessmentMetrics('r', { quantiles: [0.5, 0.9] });
  await ops.riskSubjectLevels('r');
  await ops.riskGeography('r', { countries: ['DE'], continents: ['EU'] });
  await ops.riskGeography('r', { sessionIds: ['s1'] });
  await ops.riskUpsertSessionContext({ realm: 'r', sessionId: 's1',
                                       subject: 'alice',
                                       addressPrefix: '192.0.2.0/24',
                                       score: 1, level: 'LOW',
                                       updatedAt: 5 });
  await ops.riskPurgeHistory('assessments', 5, 3);
  await ops.riskPurgeHistory('counts', 5, 3);
  await ops.riskPurgeHistory('sessions', 5, 3);
  await ops.riskRecordAcceptance({ provider: 'p', termsDigest: 'd',
                                   termsText: 't', acceptedBy: 'b',
                                   acceptedVia: 'v', acceptedAt: 1 });
  await ops.riskListAcceptances();
  log.debug("Leaving exercise().");
}

async function refusedWith(code, promise) {
  log.debug("Entering refusedWith().");
  try {
    await promise;
  } catch (e) {
    log.debug("Leaving refusedWith(). Refused.");
    return new RegExp(code).test(String(e && e.message));
  }
  log.debug("Leaving refusedWith(). Not refused.");
  return false;
}

async function staticChecks(t) {
  log.debug("Entering staticChecks().");
  t.log.info('=== A. compiled for MariaDB, none of PostgreSQL ===');
  const maria = sqlDialect.create('mariadb');
  const runner = recorder();
  const ops = opsOver(maria, runner);
  await exercise(ops);
  const statements = runner.sent.map(function (one) {
    return one.text;
  }).filter(function (text) {
    return !/^(BEGIN|COMMIT|ROLLBACK)$/.test(text) &&
      !/^INSERT INTO sts_changes/.test(text);
  });
  const names = {};
  statements.forEach(function (text) {
    const name = (/sts:risk\.([A-Za-z.]+)/.exec(text) || [])[1];
    if (name) {
      names[name] = true;
    }
  });
  const exported = Object.keys(ops);
  t.check(exported.length === 36 && Object.keys(names).length >= 50,
          'A1. all 36 operations sent their statements, each named',
          exported.length + ' operation(s), ' + Object.keys(names).length +
          ' distinct statement(s): ' + Object.keys(names).join(' '));
  const pgOnly = [
    [/\$\d/, 'a $n placeholder'],
    [/::[a-z]/, 'a :: cast'],
    [/\bon conflict\b/i, 'ON CONFLICT'],
    [/\breturning\b/i, 'RETURNING'],
    [/"[a-z_]+"/, 'a double-quoted identifier'],
    [/\bctid\b|\bunnest\b|\bANY\(|\bALL\(|\bcardinality\b|\bstarts_with\b/i,
     'a PostgreSQL function'],
    [/\bhost\(|\bmasklen\(|\binet\b|\bcidr\b/i, 'an inet function or type'],
    [/\bFILTER\s*\(|GROUPING|DISTINCT ON|WITH ORDINALITY/i,
     'a PostgreSQL aggregate form'],
    [/jsonb|->>|\?\||@>|\bchr\(/i, 'a jsonb operator'],
    [/\bIS DISTINCT FROM\b/i, 'IS DISTINCT FROM']
  ];
  const offending = [];
  statements.forEach(function (text) {
    const body = text.replace(/\/\* sts:[^*]+\*\//, '');
    pgOnly.forEach(function (rule) {
      if (rule[0].test(body)) {
        offending.push(rule[1] + ' in: ' + text.slice(0, 160));
      }
    });
  });
  t.check(offending.length === 0,
          'A2. NO STATEMENT CARRIES POSTGRESQL\'S SYNTAX',
          offending.join(' | '));
  const find = function (name) {
    return runner.sent.filter(function (one) {
      return one.text.indexOf('sts:risk.' + name + ' ') >= 0;
    });
  };
  const geo = find('insertRows.geo')[0];
  t.check(!!geo && /^insert ignore into `sts_risk_geo_ranges`/.test(geo.text) &&
          geo.values.indexOf('::ffff:192.0.2.0') >= 0 &&
          geo.values.indexOf('2001:db8::') >= 0,
          'A3. a batch of ranges is one INSERT IGNORE, an IPv4 address in ' +
          'its INET6 form', geo && geo.text.slice(0, 120));
  const v4 = find('lookupRange.geo')[0];
  const v6 = find('lookupRange.iplist')[0];
  t.check(!!v4 && /order by `range_start` desc limit \?\) as `s` where/.test(
            v4.text) && v4.values.indexOf('::ffff:0.0.0.0') >= 0 &&
          !!v6 && /`range_start` < CAST\(\? AS INET6\) or `range_start` > /
            .test(v6.text),
          'A4. a lookup is one descending seek bounded to its family: IPv4 ' +
          'within the mapped block, IPv6 outside it',
          (v4 && v4.text) + ' | ' + (v6 && v6.text));
  const deletes = find('deleteRows.geo').concat(find('purgeFailures'),
                                                find('purgeHistory.counts'));
  t.check(deletes.length === 3 && deletes.every(function (one) {
    return /^delete from `[a-z_]+` where .* limit \?/.test(one.text);
  }), 'A5. a batch delete is DELETE … LIMIT n',
          deletes.map(function (one) {
            return one.text;
          }).join(' | '));
  const like = find('distinctValues')[0];
  t.check(!!like && /LIKE \? ESCAPE '!'/.test(like.text) &&
          like.values.indexOf('1!_2!%%') >= 0,
          'A6. a prefix is a LIKE whose own wildcards are escaped',
          like && JSON.stringify(like));
  const update = find('finishVersion.update')[0];
  t.check(!!find('finishVersion.lock')[0] &&
          /for update/.test(find('finishVersion.lock')[0].text) && !!update &&
          update.values.indexOf('{"a":1,"b":2}') >= 0,
          'A7. a jsonb merge is the row locked FOR UPDATE and merged in ' +
          'JavaScript', update && JSON.stringify(update.values));
  const claim = find('claimAction')[0];
  t.check(!!claim && /JSON_SET\(`actions`/.test(claim.text) &&
          /NOT \(JSON_VALUE\(`actions`, \?\) <=> \?\)/.test(claim.text),
          'A8. a claim is one conditional UPDATE', claim && claim.text);
  const ops2 = opsOver(maria, recorder());
  t.check(await refusedWith('STS-STORE-0100', ops2.riskBeginVersion(
            version({ dataset: 'x'.repeat(129) }), false)) &&
          await refusedWith('STS-STORE-0100', ops2.riskIncrementCounts('r',
            [{ subject: 'a', feature: 'f', value: 'v'.repeat(256) }], 1)),
          'A9. a value longer than its MariaDB key column is refused, not ' +
          'truncated');
  const quiet = recorder();
  const ops3 = opsOver(maria, quiet);
  t.check(await refusedWith('STS-STORE-0160', ops3.riskInsertRows('geo', '',
            'g', 'v', [{ start: '192.0.2.0', end: '192.0.2.255' },
                       { start: 'not-an-address', end: '192.0.2.9' }])) &&
          await refusedWith('STS-STORE-0160', ops3.riskInsertRows('asn', '',
            'a', 'v', [{ start: '192.0.2.0', end: '192.0.2.255',
                         asn: 1.5 }])) &&
          quiet.sent.length === 0,
          'A10. a batch with an address that is not one, or an integer that ' +
          'is not, is refused whole before anything is sent');
  t.check(riskPortable.WIDTH.prefix === 50 && riskPortable.WIDTH.value === 255,
          'A11. the widths are mariadb/CLAUDE.md\'s');
  log.debug("Leaving staticChecks().");
}

// ---------------------------------------------------------------------------
// C. AGAINST A REAL MARIADB
// ---------------------------------------------------------------------------

async function scratchDatabase(url, prefix) {
  log.debug("Entering scratchDatabase().");
  const knexStore = require('../persistence/knex_store');
  const schemaMariadb = require('../persistence/schema_mariadb');
  const scratch = prefix + process.pid;
  const admin = knexStore.openConnection({ connectionString: url });
  await admin.connect();
  await admin.query('CREATE DATABASE ' + scratch);
  const scoped = url.replace(/\/[^/?]*(\?|$)/, '/' + scratch + '$1');
  const pool = knexStore.openPool({ connectionString: scoped }, { max: 12 });
  for (const object of schemaMariadb.SCHEMA_OBJECTS) {
    const table = (/(sts_[a-z_]+)/.exec(object.name) || [])[1];
    if (TABLES.indexOf(object.name) >= 0 ||
        (object.name.indexOf('sts_risk_') === 0 &&
         TABLES.some(function (name) {
           return object.statement.indexOf(' ON ' + name + ' ') >= 0;
         })) || (table && TABLES.indexOf(table) >= 0 &&
                 /^CREATE INDEX/.test(object.statement))) {
      await pool.query(object.statement);
    }
  }
  log.debug("Leaving scratchDatabase().");
  return {
    pool: pool, scoped: scoped,
    drop: async function () {
      log.debug("Entering drop().");
      await pool.end();
      await admin.query('DROP DATABASE ' + scratch);
      await admin.end();
      log.debug("Leaving drop().");
    }
  };
}

async function count(pool, sql) {
  log.debug("Entering count().");
  const r = await pool.query(sql);
  log.debug("Leaving count().");
  return Number(r.rows[0].n);
}

async function datasetContracts(t, ops, pool) {
  log.debug("Entering datasetContracts().");
  // ---- a version begun once -----------------------------------------
  const first = await ops.riskBeginVersion(version(), false);
  const again = await ops.riskBeginVersion(version(), false);
  const reload = await ops.riskBeginVersion(version(), true);
  const racers = [];
  for (let i = 0; i < 8; i++) {
    racers.push(ops.riskBeginVersion(version({ version: 'v2' }), i % 2 === 0));
  }
  const raced = await Promise.all(racers);
  t.check(first === true && again === false && reload === false &&
          raced.filter(Boolean).length === 1,
          'C1. a version is begun once: again, or reloaded while it is not ' +
          'deleted, is "already recorded"; eight concurrent beginnings, one ' +
          'wins', JSON.stringify(raced));
  // ---- rows, in batches ---------------------------------------------
  const geo = [
    { start: '10.0.0.0', end: '10.0.0.255', country: 'AA', latitude: 1.5,
      longitude: -2.25, anonymousProxy: true },
    { start: '10.0.2.0', end: '10.0.2.255', country: 'BB' },
    { start: '::', end: '::ffff', country: 'V6LOW' },
    { start: '2001:db8::', end: '2001:db8::ffff', country: 'CC' },
    { start: '2001:db8:1::', end: '2001:db8:1::ff', country: 'DD' }
  ];
  const inserted = await ops.riskInsertRows('geo', '', 'geo.city', 'v1',
                                            geo.slice(0, 3)) +
    await ops.riskInsertRows('geo', '', 'geo.city', 'v1', geo.slice(3));
  const duplicate = await ops.riskInsertRows('geo', '', 'geo.city', 'v1',
                                             geo.slice(0, 2));
  const refused = await refusedWith('STS-STORE-0160', ops.riskInsertRows(
    'geo', '', 'geo.city', 'v1', [{ start: '10.9.9.0', end: '10.9.9.9' },
                                  { start: 'bogus', end: '10.9.9.9' }]));
  t.check(inserted === 5 && duplicate === 0 && refused &&
          await count(pool, 'SELECT count(*) AS n FROM sts_risk_geo_ranges') ===
            5,
          'C2. rows go in by batch, a row already there is left (0 written, ' +
          'as ON CONFLICT DO NOTHING answers), and a batch with a bad ' +
          'address is refused whole', inserted + ' ' + duplicate);
  await ops.riskInsertRows('iplist', 'r', 'tor', 'v1',
                           [{ start: '10.0.0.7', end: '10.0.0.7',
                              category: 'tor' },
                            { start: '::', end: 'ffff:ffff:ffff:ffff:ffff:' +
                              'ffff:ffff:ffff', category: 'all-v6' }]);
  await ops.riskInsertRows('iplist', 'r', 'v6only', 'v1',
                           [{ start: '::', end: 'ffff:ffff:ffff:ffff:ffff:' +
                              'ffff:ffff:ffff', category: 'only-v6' }]);
  await ops.riskInsertRows('fido', '', 'fido', 'v1', [{
    keyKind: 'aaguid', key: 'abc', description: 'Key', compromised: true,
    latestStatus: 'REVOKED', latestStatusAt: 12,
    statusReports: [{ status: 'REVOKED' }],
    metadataStatement: { attestationRootCertificates: ['MII'] } }]);
  // ---- finishing, progress, the stalled imports ----------------------
  await ops.riskTouchVersion('', 'geo.city', 'v1', 500, 5);
  const finished = await ops.riskFinishVersion('', 'geo.city', 'v1', {
    state: 'ready', rowCount: 5, loadedAt: 600, parameters: { b: 2 } });
  const touchedReady = await ops.riskTouchVersion('', 'geo.city', 'v1',
                                                  700, 6);
  const versions = await ops.riskListVersions('', 'geo.city');
  const v1 = versions.filter(function (v) {
    return v.version === 'v1';
  })[0];
  t.check(finished && !touchedReady && v1.state === 'ready' &&
          v1.parameters.a === 1 && v1.parameters.b === 2 &&
          v1.parameters.progressAt === 500 &&
          v1.parameters.progressRows === 5 &&
          versions[0].version === 'v2',
          'C3. a version\'s outcome merges its parameters over the stored ' +
          'ones (progress kept), progress stops once it is not loading, and ' +
          'versions list newest first', JSON.stringify(versions));
  const stalls = await Promise.all([
    ops.riskAbandonStalled(1000, 1001, 'stalled', 'STS-RISK-X'),
    ops.riskAbandonStalled(1000, 1001, 'stalled', 'STS-RISK-X')]);
  const refusedVersions = stalls[0].concat(stalls[1]);
  t.check(refusedVersions.length === 1 && refusedVersions[0].version === 'v2',
          'C4. two nodes refusing stalled imports at once refuse each once, ' +
          'and the ready one is left', JSON.stringify(stalls));
  // ---- activation ----------------------------------------------------
  const changesBefore = await count(pool, 'SELECT count(*) AS n FROM ' +
                                    'sts_changes');
  const activated = await ops.riskActivate('', 'geo.city', 'geo', 'v1', 800);
  const unchanged = await ops.riskActivate('', 'geo.city', 'geo', 'v1', 801);
  const notReady = await ops.riskActivate('', 'geo.city', 'geo', 'v2', 802);
  await ops.riskBeginVersion(version({ dataset: 'tor', version: 'v1',
                                       realm: 'r' }), false);
  await ops.riskFinishVersion('r', 'tor', 'v1', { state: 'ready' });
  await ops.riskActivate('r', 'tor', 'iplist', 'v1', 803);
  const datasets = await ops.riskListDatasets();
  t.check(activated.activated && activated.previous === '' &&
          unchanged.unchanged && !notReady.activated &&
          notReady.state === 'refused' && datasets.length === 2 &&
          datasets[0].active_version === 'v1' &&
          await count(pool, 'SELECT count(*) AS n FROM sts_changes') ===
            changesBefore + 2,
          'C5. activation names the version, refuses one not ready, and ' +
          'writes one change row each time it moves',
          JSON.stringify([activated, unchanged, notReady, datasets]));
  // ---- the lookups -----------------------------------------------------
  const look = async function (kind, realm, dataset, address) {
    const hit = await ops.riskLookupRange(kind, realm, dataset, 'v1',
                                          address);
    return hit ? hit.country || hit.category : null;
  };
  const answers = {
    v4Start: await look('geo', '', 'geo.city', '10.0.0.0'),
    v4End: await look('geo', '', 'geo.city', '10.0.0.255'),
    v4Gap: await look('geo', '', 'geo.city', '10.0.1.0'),
    v4Mapped: await look('geo', '', 'geo.city', '::ffff:10.0.2.9'),
    v4Below: await look('geo', '', 'geo.city', '9.255.255.255'),
    v6Start: await look('geo', '', 'geo.city', '2001:db8::'),
    v6End: await look('geo', '', 'geo.city', '2001:db8::ffff'),
    v6Past: await look('geo', '', 'geo.city', '2001:db8::1:0'),
    v6Low: await look('geo', '', 'geo.city', '::1'),
    v6Above: await look('geo', '', 'geo.city', '2001:db8:1::ff'),
    listV4: await look('iplist', 'r', 'tor', '10.0.0.7'),
    listV4Miss: await look('iplist', 'r', 'tor', '10.0.0.8'),
    listV6: await look('iplist', 'r', 'tor', '2001:db8::5'),
    otherRealm: await look('iplist', 'q', 'tor', '10.0.0.7'),
    v6OnlyV4: await look('iplist', 'r', 'v6only', '10.0.0.7'),
    v6OnlyV6: await look('iplist', 'r', 'v6only', '2001:db8::9')
  };
  t.check(answers.v4Start === 'AA' && answers.v4End === 'AA' &&
          answers.v4Gap === null && answers.v4Mapped === 'BB' &&
          answers.v4Below === null && answers.v6Start === 'CC' &&
          answers.v6End === 'CC' && answers.v6Past === null &&
          answers.v6Low === 'V6LOW' && answers.v6Above === 'DD',
          'C6. AN ADDRESS AT EACH END OF A RANGE IS IN IT, ONE PAST IT IS ' +
          'NOT, in both families', JSON.stringify(answers));
  t.check(answers.listV4 === 'tor' && answers.listV4Miss === null &&
          answers.listV6 === 'all-v6' && answers.otherRealm === null &&
          answers.v6OnlyV4 === null && answers.v6OnlyV6 === 'only-v6',
          'C7. AN IPV4 ADDRESS FINDS ONLY IPV4 RANGES AND AN IPV6 ONE ONLY ' +
          'IPV6 RANGES: the all-IPv6 list row (::/0, which spans the mapped ' +
          'block on this engine) answers no IPv4 address, and an IP list is ' +
          'per realm', JSON.stringify(answers));
  const hit = await ops.riskLookupRange('geo', '', 'geo.city', 'v1',
                                        '10.0.0.9');
  t.check(hit.range_start === '10.0.0.0' && hit.range_end === '10.0.0.255' &&
          hit.anonymous_proxy === true && hit.satellite === false &&
          Number(hit.latitude) === 1.5,
          'C8. a range reads back as inet prints it, its booleans as ' +
          'booleans', JSON.stringify(hit));
  // THE PLAN: each lookup's statement captured as sent, then EXPLAINed
  // with its own values.
  const dialect = sqlDialect.create('mariadb');
  const inner = [];
  for (const probe of ['10.0.0.9', '2001:db8::5']) {
    const captured = [];
    const capture = { query: function (text, values) {
      captured.push({ text: text, values: values });
      return Promise.resolve({ rows: [], rowCount: 0 });
    } };
    await riskPortable.create({
      dialect: dialect, pool: capture, tallyPool: capture,
      withTransaction: null, recordChanges: null,
      processId: function () {
        return 'p';
      },
      shapes: SHAPES
    }).riskLookupRange('geo', '', 'geo.city', 'v1', probe);
    const r = await pool.query('EXPLAIN ' + captured[0].text,
                               captured[0].values);
    inner.push(r.rows);
  }
  t.check(inner.every(function (rows) {
    return rows.some(function (row) {
      return row.key === 'PRIMARY' && /range|ref/.test(String(row.type));
    }) && !rows.some(function (row) {
      return String(row.type) === 'ALL' &&
        String(row.table).indexOf('sts_risk') >= 0;
    });
  }), 'C9. A LOOKUP IS AN INDEXED SEEK OF THE PRIMARY KEY, in both ' +
          'families (no full scan)', JSON.stringify(inner));
  const model = await ops.riskLookupFido('fido', 'v1', 'aaguid', 'ABC');
  t.check(!!model && model.compromised === true &&
          model.latestStatusAt === 12 &&
          model.statusReports[0].status === 'REVOKED' &&
          model.metadataStatement.attestationRootCertificates[0] === 'MII',
          'C10. a FIDO model reads back with its booleans and JSON',
          JSON.stringify(model));
  // ---- deactivation, and the rows deleted in bounded batches ----------
  const off = await ops.riskDeactivate('', 'geo.city', 'v1', 900);
  const offAgain = await ops.riskDeactivate('', 'geo.city', 'v1', 901);
  const keptWhileActive = await ops.riskMarkRowsDeleted('r', 'tor', 'v1',
                                                        902);
  const batches = [];
  for (;;) {
    const gone = await ops.riskDeleteRows('geo', '', 'geo.city', 'v1', 2);
    batches.push(gone);
    if (!gone) {
      break;
    }
  }
  const marked = await ops.riskMarkRowsDeleted('', 'geo.city', 'v1', 903);
  const reloaded = await ops.riskBeginVersion(version(), true);
  const after = (await ops.riskListVersions('', 'geo.city')).filter(
    function (v) {
      return v.version === 'v1';
    })[0];
  t.check(off.deactivated && !offAgain.deactivated && !keptWhileActive &&
          batches.join() === '2,2,1,0' && marked && reloaded &&
          after.state === 'loading' && Number(after.row_count) === 0 &&
          (await ops.riskListDatasets())[0].state === 'empty',
          'C11. a version deactivated once, its rows deleted two at a time ' +
          '(2, 2, 1, 0), marked deleted, and a deleted record begun again',
          JSON.stringify([batches, after]));
  log.debug("Leaving datasetContracts().");
}

async function historyContracts(t, ops, pool) {
  log.debug("Entering historyContracts().");
  // ---- failures ------------------------------------------------------
  const ids = [];
  for (let i = 0; i < 5; i++) {
    ids.push(await ops.riskRecordFailure({
      realm: 'r', at: 100 + i, door: i === 4 ? 'totp-replay' : 'password',
      subject: i < 2 ? 'alice' : '', nameHmac: 'h' + i,
      addressSealed: 's', addressPrefix: i % 2 ? '2001:db8::/48'
        : '192.0.2.0/24', asn: 1, errorCode: 'E' }));
  }
  const all = await ops.riskListFailures('r', {});
  const narrowed = await ops.riskListFailures('r', {
    prefix: '192.0.2.0/24', excludeDoor: ['totp-replay'] });
  const alice = await ops.riskListFailures('r', { subject: 'alice',
                                                  limit: 1, offset: 1 });
  t.check(ids.every(function (id) {
    return /^\d+$/.test(id);
  }) && all.total === 5 && all.rows[0].at === '104' &&
          narrowed.total === 2 && alice.total === 2 &&
          alice.rows.length === 1 && alice.rows[0].at === '100' &&
          all.rows[0].address_prefix === '192.0.2.0/24',
          'C12. failures are recorded with their id, listed newest first, ' +
          'narrowed by prefix, door and subject, paged',
          JSON.stringify([ids, narrowed, alice]));
  const purged = [];
  for (;;) {
    const gone = await ops.riskPurgeFailures(103, 2);
    purged.push(gone);
    if (!gone) {
      break;
    }
  }
  t.check(purged.join() === '2,1,0' &&
          (await ops.riskListFailures('r', {})).total === 2,
          'C13. failures older than the cut are purged in bounded batches',
          purged.join());
  // ---- the counts, incremented concurrently ----------------------------
  const sign = function (i) {
    return ops.riskIncrementCounts('r', [
      { subject: 'alice', feature: 'ip', value: '192.0.2.1' },
      { subject: '*', feature: 'ip', value: '192.0.2.1' },
      { subject: 'alice', feature: 'ip>asn', value: '1_2|64500' },
      { subject: 'alice', feature: 'ip>asn', value: '1x2|' + i }
    ], 1000 + i);
  };
  const signIns = [];
  for (let i = 0; i < 20; i++) {
    signIns.push(sign(i));
  }
  await Promise.all(signIns);
  const counted = await ops.riskFeatureCounts('r', 'alice', [
    { feature: 'ip', value: '192.0.2.1' },
    { feature: 'ip>asn', value: '1_2|64500' },
    { feature: 'ip', value: 'never' }]);
  const population = await ops.riskFeatureCounts('r', '*', [
    { feature: 'ip', value: '192.0.2.1' }]);
  const byValue = {};
  counted.forEach(function (c) {
    byValue[c.feature + ' ' + c.value] = c.count;
  });
  t.check(counted.length === 2 && byValue['ip 192.0.2.1'] === 20 &&
          byValue['ip>asn 1_2|64500'] === 20 && population[0].count === 20,
          'C14. TWENTY CONCURRENT SIGN-INS COUNTED: EACH COUNT IS TWENTY, ' +
          'the sum of the increments, and a pair never seen is left out',
          JSON.stringify([counted, population]));
  const distinct = await ops.riskDistinctValues('r', 'alice', 'ip>asn', '');
  const underscore = await ops.riskDistinctValues('r', 'alice', 'ip>asn',
                                                  '1_2|');
  const many = await ops.riskDistinctValuesMany('r', 'alice', [
    { feature: 'ip>asn', prefix: '1x2|' }, { feature: 'ip' },
    { feature: 'nothing' }]);
  t.check(distinct === 21 && underscore === 1 &&
          many.join() === '20,1,0',
          'C15. distinct values, by prefix — an underscore in the prefix is ' +
          'a character, not a wildcard — and many in one statement, in the ' +
          'order asked', JSON.stringify([distinct, underscore, many]));
  // ---- assessments ---------------------------------------------------
  const written = await ops.riskRecordAssessment(assessment('a1'));
  const twice = await ops.riskRecordAssessment(assessment('a1'));
  await ops.riskRecordAssessment(assessment('a2', {
    at: 2000, subject: 'bob', sessionId: 's2', bot: true, score: 42,
    level: 'HIGH', country: 'FR', city: 'Paris', backupEligible: undefined,
    signals: [{ signal: 'bot' }] }));
  await ops.riskRecordAssessment(assessment('a3', {
    at: 3000, sessionId: 's1', phase: 'session', country: 'DE',
    city: 'Munich', subdivision: 'BY', score: 5 }));
  const settled = await ops.riskSettleAssessment({
    realm: 'r', id: 'a1', decision: 'allow', policyId: 'p', sessionId: 's1' });
  await ops.riskSettleAssessment({ realm: 'r', id: 'a1', decision: 'allow',
                                   sessionId: '' });
  const amended = await ops.riskAmendAssessment({
    realm: 'r', id: 'a2', signals: [{ signal: 'device' }], score: 43,
    level: 'HIGH' });
  const feedback = await ops.riskSetFeedback('r', 'a1', 'alice', 'mine', 5);
  const feedbackAgain = await ops.riskSetFeedback('r', 'a1', 'alice', 'no', 6);
  const listed = await ops.riskListAssessments('r', {});
  const a1 = listed.rows.filter(function (r) {
    return r.id === 'a1';
  })[0];
  const a2 = listed.rows.filter(function (r) {
    return r.id === 'a2';
  })[0];
  const high = await ops.riskListAssessments('r', { level: 'HIGH' });
  t.check(written && !twice && settled && amended && feedback &&
          !feedbackAgain && listed.total === 3 && listed.rows[0].id === 'a3' &&
          a1.sessionId === 's1' && a1.decision === 'allow' &&
          a1.feedback === 'mine' && a1.score === 0.12345679 &&
          a1.ipLists[0] === 'tor' && a1.datasets.geo === 'v1' &&
          a1.signals[1].signal === 'new_ua' && a1.bot === false &&
          a1.backupEligible === true && a1.backupState === false &&
          a2.bot === true && a2.backupEligible === null && a2.score === 43 &&
          a2.signals[0].signal === 'device' && high.total === 1,
          'C16. an assessment is recorded once, settled (its session filled ' +
          'in, never cleared), amended, answered once, and listed with its ' +
          'booleans, JSON and single-precision score as PostgreSQL gives them',
          JSON.stringify(listed));
  const metrics = await ops.riskAssessmentMetrics('r', {
    bucketMs: 60000, quantiles: [0, 0.5, 1] });
  const group = function (k, v) {
    const found = metrics.groups.filter(function (g) {
      return g.k === k && g.v === v;
    })[0];
    return found ? found.n : 0;
  };
  t.check(metrics.totals.total === 3 && metrics.totals.subjects === 2 &&
          metrics.totals.bots === 1 && metrics.totals.maxScore === 43 &&
          group('level', 'LOW') === 2 && group('band', '0.1 – 1') === 1 &&
          group('band', '≥ 100') === 0 && group('band', '10 – 100') === 1 &&
          group('signal', 'new-ip') === 2 && group('feedback', 'mine') === 1 &&
          group('signal-level', 'device\u0001HIGH') === 1 &&
          group('signal-feedback', 'new_ua\u0001mine') === 1 &&
          metrics.series.length === 2 && metrics.series.every(function (s) {
            return s.bucket % 60000 === 0;
          }) && metrics.quantiles['0'] === 0.12345679 &&
          metrics.quantiles['0.5'] === 5 && metrics.quantiles['1'] === 43,
          'C17. the window counted: totals, groups (signals through ' +
          'JSON_TABLE, the halves apart at U+0001), buckets and quantiles',
          JSON.stringify(metrics));
  const geography = await ops.riskGeography('r', {
    countries: ['DE', 'FR'], continents: ['EU', 'EU'] });
  const level = function (rows, name) {
    return rows.filter(function (r) {
      return r.level === name;
    });
  };
  const world = level(geography.rows, 'world')[0];
  const live = await ops.riskGeography('r', { sessionIds: ['s1', 'gone'] });
  const empty = await ops.riskGeography('nobody', {});
  t.check(world.people === 2 && world.signIns === 2 &&
          world.assessments === 3 && level(geography.rows, 'continent')
            .length === 1 && level(geography.rows, 'continent')[0]
            .continent === 'EU' && level(geography.rows, 'country')
            .length === 2 && level(geography.rows, 'city').length === 3 &&
          geography.rows.length === 7 &&
          level(live.rows, 'world')[0].assessments === 1 &&
          level(live.rows, 'city')[0].city === 'Munich' &&
          empty.rows.length === 1 && empty.rows[0].level === 'world' &&
          empty.rows[0].people === 0,
          'C18. the geography at the world, each continent, country and ' +
          'city (no subdivision level), a live session\'s latest assessment ' +
          'only, and the world\'s row for an empty window',
          JSON.stringify([geography, live, empty]));
  // ---- standings and the claim --------------------------------------
  const changes = async function () {
    return count(pool, 'SELECT count(*) AS n FROM sts_changes WHERE kind = ' +
                 '\'risk-standing\'');
  };
  const firsts = [];
  for (let i = 0; i < 5; i++) {
    firsts.push(ops.riskUpsertSubject({ realm: 'r', subject: 'alice',
                                        score: 1, level: 'LOW',
                                        updatedAt: 10 }));
  }
  await Promise.all(firsts);
  const noChange = await changes();
  await ops.riskUpsertSubject({ realm: 'r', subject: 'alice', score: 50,
                                level: 'HIGH', reason: 'new-ip',
                                updatedAt: 20 });
  await ops.riskUpsertSubject({ realm: 'r', subject: 'alice', score: 60,
                                level: 'HIGH', updatedAt: 30 });
  await ops.riskUpsertSubject({ realm: 'r', subject: 'bob', score: 0.5,
                                level: 'LOW', updatedAt: 30 });
  const standing = await ops.riskSubjectOf('r', 'alice');
  t.check(noChange === 0 && await changes() === 1 &&
          standing.level === 'HIGH' && standing.previousLevel === 'HIGH' &&
          standing.crossedAt === 20 && standing.score === 60 &&
          await ops.riskSubjectOf('r', 'nobody') === null,
          'C19. five concurrent first standings make one row and no change ' +
          'row; a change of level is one risk-standing change row and its ' +
          'crossing time, a standing at the same level neither',
          JSON.stringify(standing));
  const subjects = await ops.riskListSubjects('r', { limit: 1 });
  const levels = await ops.riskSubjectLevels('r');
  t.check(subjects.total === 2 && subjects.rows[0].subject === 'alice' &&
          levels.HIGH === 1 && levels.LOW === 1,
          'C20. the people listed by score with their count, and by level',
          JSON.stringify([subjects, levels]));
  const claims = [];
  for (let i = 0; i < 10; i++) {
    claims.push(ops.riskClaimAction('r', 'alice', 'end-sessions', 'a9'));
  }
  const claimed = await Promise.all(claims);
  const second = await ops.riskClaimAction('r', 'alice', 'end-sessions',
                                           'a9');
  const next = await ops.riskClaimAction('r', 'alice', 'end-sessions',
                                         'a10');
  const other = await ops.riskClaimAction('r', 'alice', 'odd "name"', 'a9');
  const stored = await pool.query('SELECT actions FROM sts_risk_subjects ' +
                                  'WHERE subject = \'alice\'');
  const raw = stored.rows[0].actions;
  const actions = typeof raw === 'string' ? JSON.parse(raw) : raw;
  t.check(claimed.filter(Boolean).length === 1 && !second && next && other &&
          actions['end-sessions'] === 'a10' && actions['odd "name"'] === 'a9',
          'C21. TEN CONCURRENT CLAIMS OF ONE ACTION: EXACTLY ONE TAKES IT; a ' +
          'retry does not, the next assessment does, and a reaction\'s name ' +
          'is one member whatever it holds', JSON.stringify([claimed,
                                                             actions]));
  // ---- session contexts, retention, terms -----------------------------
  const ctx = { realm: 'r', sessionId: 's1', subject: 'alice',
                addressPrefix: '192.0.2.0/24', score: 1, level: 'LOW',
                updatedAt: 10 };
  const ctx1 = await ops.riskUpsertSessionContext(ctx);
  const ctx2 = await ops.riskUpsertSessionContext(Object.assign({}, ctx, {
    level: 'HIGH', updatedAt: 20 }));
  const held = await pool.query('SELECT level, updated_at FROM ' +
                                'sts_risk_session_context');
  t.check(ctx1 && ctx2 && held.rows.length === 1 &&
          held.rows[0].level === 'HIGH',
          'C22. a session\'s context is replaced whole', JSON.stringify(
            held.rows));
  const history = [];
  for (let i = 0; i < 3; i++) {
    history.push(await ops.riskPurgeHistory('assessments', 2500, 1));
  }
  history.push(await ops.riskPurgeHistory('counts', 1020, 100));
  history.push(await ops.riskPurgeHistory('sessions', 30, 100));
  history.push(await ops.riskPurgeHistory('bogus', 30, 100));
  t.check(history.join() === '1,1,0,23,1,0',
          'C23. history past its retention purged a bounded batch at a time',
          history.join());
  const accepted = [];
  for (let i = 0; i < 2; i++) {
    accepted.push(await ops.riskRecordAcceptance({
      provider: 'maxmind', termsDigest: 'd' + i, termsText: 't',
      acceptedBy: 'admin', acceptedVia: 'console', acceptedAt: 10 + i }));
  }
  const acceptances = await ops.riskListAcceptances();
  t.check(Number(accepted[1]) > Number(accepted[0]) &&
          acceptances.length === 2 && acceptances[0].termsDigest === 'd1',
          'C24. terms acceptances appended with their ids, newest first',
          JSON.stringify(acceptances));
  log.debug("Leaving historyContracts().");
}

async function againstMariadb(t) {
  log.debug("Entering againstMariadb().");
  const url = process.env.STS_TEST_MARIADB_URL || '';
  if (!url) {
    t.log.info('=== C. skipped: STS_TEST_MARIADB_URL names no database ===');
    log.debug("Leaving againstMariadb(). Skipped.");
    return;
  }
  t.log.info('=== C. the contracts against a real MariaDB ===');
  const db = await scratchDatabase(url, 'risk_portable_');
  try {
    const ops = opsOver(sqlDialect.create('mariadb'), db.pool);
    await datasetContracts(t, ops, db.pool);
    await historyContracts(t, ops, db.pool);
  } finally {
    await db.drop();
  }
  log.debug("Leaving againstMariadb().");
}

// ---------------------------------------------------------------------------
// D. THE REAL RISK STORE OVER THE DRIVER ON MARIADB
// ---------------------------------------------------------------------------

async function throughDriver(t) {
  log.debug("Entering throughDriver().");
  const url = process.env.STS_TEST_MARIADB_URL || '';
  if (!url) {
    t.log.info('=== D. skipped: STS_TEST_MARIADB_URL names no database ===');
    log.debug("Leaving throughDriver(). Skipped.");
    return;
  }
  t.log.info('=== D. risk/risk_store over the driver, on MariaDB ===');
  const driverModule = require('../persistence/persistence_postgres');
  const RiskStore = require('../risk/risk_store').RiskStore;
  const db = await scratchDatabase(url, 'risk_driver_');
  let driver = null;
  try {
    driver = driverModule.create({
      url: db.scoped + (db.scoped.indexOf('?') >= 0 ? '&' : '?') +
        'sslmode=require',
      log: log, verifyTls: false, tlsCa: '', poolMax: 6, engine: 'mariadb'
    });
    const store = new RiskStore(RiskStore.defaultDeps());
    store.setDriver(driver, 'mariadb');
    t.check(store.inDatabase(), 'D1. the driver on MariaDB carries every ' +
            'method of the risk group');
    const v = version({ dataset: 'asn', version: '2026-11' });
    const begun = await store.beginVersion(v);
    let rows = 0;
    rows += await store.insertRows('asn', '', 'asn', '2026-11', [
      { start: '198.51.100.0', end: '198.51.100.255', asn: 64496,
        asOrg: 'Example' }]);
    rows += await store.insertRows('asn', '', 'asn', '2026-11', [
      { start: '2001:db8::', end: '2001:db8:ffff:ffff:ffff:ffff:ffff:ffff',
        asn: 64497, asOrg: 'Six' }]);
    await store.finishVersion('', 'asn', '2026-11', { state: 'ready',
                                                      rowCount: rows });
    const activated = await store.activate('', 'asn', 'asn', '2026-11', 5);
    const v4 = await store.lookupRange('asn', '', 'asn', '2026-11',
                                       '198.51.100.255');
    const v6 = await store.lookupRange('asn', '', 'asn', '2026-11',
                                       '2001:db8::1');
    const miss = await store.lookupRange('asn', '', 'asn', '2026-11',
                                         '198.51.101.0');
    t.check(begun && rows === 2 && activated.activated && v4.asn === 64496 &&
            v4.start === '198.51.100.0' && v4.asOrg === 'Example' &&
            v6.asn === 64497 && v6.start === '2001:db8::' && miss === null,
            'D2. a version begun, its rows inserted in batches, activated ' +
            'and looked up by IPv4 and IPv6 address, through RiskStore',
            JSON.stringify([v4, v6]));
    const off = await store.deactivate('', 'asn', '2026-11', 6);
    const batches = [];
    for (;;) {
      const gone = await store.deleteRows('asn', '', 'asn', '2026-11', 1);
      batches.push(gone);
      if (!gone) {
        break;
      }
    }
    const marked = await store.markRowsDeleted('', 'asn', '2026-11', 7);
    const versions = await store.listVersions('', 'asn');
    t.check(off.deactivated && batches.join() === '1,1,0' && marked &&
            versions[0].state === 'deleted' && versions[0].rowCount === 2 &&
            versions[0].parameters.a === 1,
            'D3. deactivated, its rows deleted in bounded batches, marked ' +
            'deleted; the version reads back in the store\'s shape',
            JSON.stringify(versions));
    await store.recordAssessment(assessment('d1', { realm: 'r' }), true);
    await store.settleAssessment({ realm: 'r', id: 'd1', decision: 'allow',
                                   sessionId: 'sx' }, true);
    await store.amendAssessment({ realm: 'r', id: 'd1', signals: [],
                                  score: 2, level: 'MEDIUM' }, true);
    const listed = await store.listAssessments('r', {}, true);
    t.check(listed.total === 1 && listed.rows[0].sessionId === 'sx' &&
            listed.rows[0].level === 'MEDIUM' && listed.rows[0].score === 2,
            'D4. an assessment recorded, settled, amended and listed ' +
            'through RiskStore', JSON.stringify(listed));
    const signIns = [];
    for (let i = 0; i < 12; i++) {
      signIns.push(store.incrementCounts('r', [
        { subject: 'alice', feature: 'ua', value: 'h1' },
        { subject: '*', feature: 'ua', value: 'h1' }], 100 + i, true));
    }
    await Promise.all(signIns);
    const counts = await store.featureCounts('r', 'alice',
      [{ feature: 'ua', value: 'h1' }], true);
    t.check(counts.length === 1 && counts[0].count === 12,
            'D5. twelve concurrent increments through RiskStore: twelve',
            JSON.stringify(counts));
    await store.upsertSubject({ realm: 'r', subject: 'alice', score: 1,
                                level: 'LOW', updatedAt: 1 }, true);
    const claims = [];
    for (let i = 0; i < 6; i++) {
      claims.push(store.claimAction('r', 'alice', 'step-up', 'd1', true));
    }
    const claimed = await Promise.all(claims);
    t.check(claimed.filter(Boolean).length === 1,
            'D6. six concurrent claims through RiskStore: one taken',
            JSON.stringify(claimed));
    for (let i = 0; i < 3; i++) {
      await store.recordFailure({ realm: 'r', at: 10 + i, door: 'password',
                                  addressSealed: 's',
                                  addressPrefix: '198.51.100.0/24',
                                  errorCode: 'E' }, true);
    }
    const purged = await store.purgeFailures(12, 10, true);
    const left = await store.listFailures('r', {}, true);
    t.check(purged === 2 && left.total === 1 && left.rows[0].at === 12,
            'D7. failures recorded and purged by age through RiskStore',
            JSON.stringify(left));
  } finally {
    if (driver && typeof driver.close === 'function') {
      await driver.close();
    }
    await db.drop();
  }
  log.debug("Leaving throughDriver().");
}

async function run(t) {
  log.debug("Entering run().");
  await staticChecks(t);
  await againstMariadb(t);
  await throughDriver(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'risk_portable',
  describe: 'the risk engine\'s store on MariaDB: no PostgreSQL syntax, and ' +
            'the native contracts — range seeks per family, batches, the ' +
            'claim taken once, the counts under concurrency — kept against ' +
            'a real MariaDB, directly and through RiskStore (#677)',
  run: run
};
