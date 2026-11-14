// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: subjects_resolved_together.js
//
// ===========================================================================
// THE SUBJECTS OF EVERY HELD TOKEN AND ARTIFACT, RESOLVED TOGETHER IN A
// WINDOWED PROCESS (2026-10-14).
//
// `sts_admin_closed_sets` was killed by its 300 s watchdog in the postgres
// modes after #320 made the directory a window onto the store in every
// process (`ldap.workerDirectory=auto`). Its second section asks
// `GET /admin-api/audit` once per audit category and once per audit action
// (335 of them) with a value FROM the set, which runs the handler; the
// handler's `knownUserKeys()` is `admin_stats.userKeys()`, which files every
// held token and artifact under its holder and resolved each `urn:uuid:`
// subject with its own `entryByUuid()` — in a windowed process a synchronous
// `byUuid` round trip per record, since no person is resident, and one more
// on every call for each subject naming nobody (a person a job deleted). Each
// audit answer took about a second on a request worker; 12 categories took
// 13.4 s and the 335 actions outlasted the watchdog.
//
// Held here by COUNTING what the store is asked, in a child holding the
// directory as a windowed request worker over a stand-in bridge of a few
// hundred people, with a register of tokens and artifacts whose subjects
// name them, name nobody, or name an entry by an alias:
//
//   1. `userKeys()`, `userRows()` and `holdingsOf()` each ask `withUuids`
//      once per five hundred distinct subjects and never `byUuid` or
//      `byKeys` — whatever the number of records;
//   2. and answer what one `identityOf()` per subject answers: a person by
//      their name, an alias by its entry's name, a subject naming nobody as
//      itself;
//   3. `ldap.entriesByUuids()` ranks a primary value before an alias, as
//      `entryByUuid()` does.
//
// WHY IN PROCESS: the claim is how many synchronous questions one call asks
// the store, which only a bridge stand-in can count; the HTTP job is the one
// that found it, and it now runs in seconds again.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'subjects_resolved_together',
  level: process.env.LOG_LEVEL || 'info' });

const CHILD_FLAG = 'STS_TEST_SUBJECTS_RESOLVED_TOGETHER_CHILD';

const PEOPLE = 300;
// Records whose subject names nobody — the deleted people a full run leaves.
const NOBODY = 1700;

// A bridge over the shared stand-in, answering `withUuids` too and counting
// every synchronous question by name.
function countingBridge(rows) {
  log.debug('Entering countingBridge().');
  const shared = require('./directory_window');
  const queries = require('../persistence/directory_queries');
  const base = shared.fakeBridge(rows);
  const asked = {};
  const uuidsOf = function (r) {
    return (r.attrs.entryuuid || []).concat(r.attrs.stsentryuuidalias || [])
      .map(function (v) {
        return String(v).toLowerCase();
      });
  };
  const bridge = {
    asked: asked,
    query: function (name, args) {
      asked[name] = (asked[name] || 0) + 1;
      if (name === 'withUuids') {
        const wanted = new Set(args[1]);
        return Array.from(rows.values()).filter(function (r) {
          return r.realm === args[0] && uuidsOf(r).some(function (u) {
            return wanted.has(u);
          });
        }).map(function (r) {
          return queries.rowOf(JSON.parse(JSON.stringify(r)));
        });
      }
      return base.query(name, args);
    },
    reset: function () {
      Object.keys(asked).forEach(function (k) {
        delete asked[k];
      });
    }
  };
  log.debug('Leaving countingBridge().');
  return bridge;
}

function total(asked) {
  return Object.keys(asked).reduce(function (n, k) {
    return n + asked[k];
  }, 0);
}

async function inTheWorker(t) {
  log.debug('Entering inTheWorker().');
  const shared = require('./directory_window');
  const ldap = require('../ldap/ldap_server');
  const stats = require('../common/admin_stats');
  const w = ldap.directoryWindow;
  t.check(!!w, '0. the directory is a window onto the store');
  if (!w) {
    log.debug('Leaving inTheWorker(). No window.');
    return;
  }
  const users = ldap.usersDn();
  const rows = new Map();
  const people = [];
  for (let i = 0; i < PEOPLE; i++) {
    const uid = 'srt' + String(i).padStart(4, '0');
    const uuid = crypto.randomUUID();
    const dn = 'uid=' + uid + ',' + users;
    const attrs = { uid: [uid], objectclass: ['inetOrgPerson'],
                    cn: ['Person ' + i], entryuuid: [uuid] };
    rows.set('default\n' + dn.toLowerCase(),
             shared.row('default', dn, attrs));
    people.push({ uid: uid, uuid: uuid });
  }
  // One person also answers to an ALIAS (a create race reconciled), and
  // one alias is ALSO another person's primary value — the primary wins.
  const aliased = crypto.randomUUID();
  rows.get('default\n' + ('uid=' + people[0].uid + ',' + users)
    .toLowerCase()).attrs.stsentryuuidalias = [aliased, people[1].uuid];
  w.residentRows('default').forEach(function (one) {
    rows.set('default\n' + one.key, { realm: 'default', dn_key: one.key,
      dn: one.entry.dn, attrs: one.entry.attributes, origin: null,
      created_at: '1', modified_at: '1' });
  });
  const bridge = countingBridge(rows);
  w.attach(bridge);

  // The register: an assertion for every person, one under the alias, and
  // NOBODY assertions whose subject names nobody.
  const nobody = [];
  people.forEach(function (p, i) {
    stats.recordAssertion('2.0', { id: 'srt-p-' + i,
                                   subject: 'urn:uuid:' + p.uuid });
  });
  stats.recordAssertion('2.0', { id: 'srt-alias',
                                 subject: 'urn:uuid:' + aliased });
  for (let i = 0; i < NOBODY; i++) {
    const uuid = crypto.randomUUID();
    nobody.push(uuid);
    stats.recordAssertion('2.0', { id: 'srt-n-' + i,
                                   subject: 'urn:uuid:' + uuid });
  }
  const distinct = PEOPLE + 1 + NOBODY;
  const statements = Math.ceil(distinct / 500);

  // 1. userKeys(), counted.
  bridge.reset();
  let started = Date.now();
  const keys = stats.userKeys();
  const tookKeys = Date.now() - started;
  t.check(!bridge.asked.byUuid && !bridge.asked.byKeys &&
          bridge.asked.withUuids === statements &&
          total(bridge.asked) === statements,
          '1a. userKeys() over ' + distinct + ' subjects asks withUuids ' +
          statements + ' times and nothing else — not one byUuid per ' +
          'record', JSON.stringify(bridge.asked) + ', ' + tookKeys +
          ' ms (information only)');
  bridge.reset();
  stats.userKeys();
  t.check(total(bridge.asked) === statements,
          '1b. and the same again on the next call (the subjects naming ' +
          'nobody are asked together, not one by one)',
          JSON.stringify(bridge.asked));
  bridge.reset();
  started = Date.now();
  const rowsListed = stats.userRows();
  const tookRows = Date.now() - started;
  t.check(!bridge.asked.byUuid && !bridge.asked.byKeys &&
          total(bridge.asked) === statements,
          '1c. userRows() asks the same', JSON.stringify(bridge.asked) +
          ', ' + tookRows + ' ms (information only)');
  bridge.reset();
  const held = stats.holdingsOf([people[2].uid, 'urn:uuid:' + nobody[0]]);
  t.check(!bridge.asked.byUuid && !bridge.asked.byKeys &&
          total(bridge.asked) === statements,
          '1d. holdingsOf() asks the same', JSON.stringify(bridge.asked));

  // 2. The same answers as one identityOf() per subject.
  const wrong = [];
  people.forEach(function (p, i) {
    if (!keys.has(p.uid) || keys.has('urn:uuid:' + p.uuid)) {
      wrong.push(i + ' ' + p.uid);
    }
  });
  t.check(!wrong.length, '2a. every person is filed under their name',
          wrong.slice(0, 5).join(', '));
  t.check(nobody.every(function (u) {
    return keys.has('urn:uuid:' + u);
  }), '2b. every subject naming nobody is filed as itself');
  t.check(!keys.has('urn:uuid:' + aliased),
          '2c. a subject held as an alias is filed under its entry\'s name');
  const alone = stats.identityOf('urn:uuid:' + people[3].uuid);
  t.check(alone.key === people[3].uid && keys.has(alone.key),
          '2d. as one identityOf() files it', JSON.stringify(alone));
  t.check(rowsListed.some(function (r) {
    return r.key === people[4].uid;
  }) && held.get(people[2].uid).artifacts.length === 1 &&
          held.get('urn:uuid:' + nobody[0]).artifacts.length === 1,
          '2e. userRows() and holdingsOf() find the same holders');

  // 3. A primary value before an alias.
  const found = ldap.entriesByUuids(['urn:uuid:' + people[1].uuid,
                                     aliased.toUpperCase(), nobody[1]]);
  t.check(found.get(people[1].uuid) &&
          found.get(people[1].uuid).dn === 'uid=' + people[1].uid + ',' +
            users &&
          found.get(aliased) &&
          found.get(aliased).dn === 'uid=' + people[0].uid + ',' + users &&
          found.get(nobody[1]) === null,
          '3. entriesByUuids(): a primary value wins over an alias, an alias ' +
          'finds its entry, nobody is null — entryByUuid()\'s answers',
          JSON.stringify(Array.from(found.entries()).map(function (p) {
            return [p[0], p[1] && p[1].dn];
          })));
  log.debug('Leaving inTheWorker().');
}

async function childMain() {
  log.debug('Entering childMain().');
  const seen = [];
  const t = {
    log: log,
    check: function (ok, what, detail) {
      seen.push({ ok: !!ok, what: what, detail: detail || '' });
      return !!ok;
    }
  };
  let threw = '';
  try {
    await inTheWorker(t);
  } catch (e) {
    log.debug('Caught in childMain(): ' + ((e && e.message) || e));
    threw = (e && e.stack) || String(e);
  }
  fs.writeFileSync(process.env.PROBE_OUT,
                   JSON.stringify({ seen: seen, threw: threw }));
  log.debug('Leaving childMain().');
  process.exit(0);
}

function run(t) {
  log.debug('Entering run().');
  t.log.info('=== the subjects of the register, in a windowed worker ===');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-srt-'));
  const outFile = path.join(dir, 'out.json');
  const env = Object.assign({}, process.env, { PROBE_OUT: outFile,
                                               LOG_LEVEL: 'fatal' });
  env[CHILD_FLAG] = '1';
  delete env.CONFIG_FILE;
  env.STS_REQUEST_WORKER = '1';
  env.LDAP_WORKER_DIRECTORY = 'postgres-lru';
  env.STS_PERSISTENCE_MODE = 'postgres';
  env.LDAP_WORKER_CACHE_ENTRIES = '100';
  const child = childProcess.spawnSync(process.execPath, [__filename],
    { cwd: path.join(__dirname, '..'), env: env, encoding: 'utf8',
      timeout: 180000 });
  let result = null;
  try {
    result = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  } catch (e) {
    log.debug('Caught in run(): ' + ((e && e.message) || e));
    t.bad('the windowed child reported nothing', 'status ' + child.status +
          ': ' + String(child.stderr || '').slice(-2000));
    log.debug('Leaving run().');
    return;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  result.seen.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  if (result.threw) {
    t.bad('the windowed child threw', result.threw);
  }
  t.check(result.seen.length >= 11, 'every assertion of the windowed child ' +
          'ran', String(result.seen.length));
  log.debug('Leaving run().');
}

if (require.main === module && process.env[CHILD_FLAG] === '1') {
  childMain();
}

module.exports = {
  name: 'subjects_resolved_together',
  describe: 'the subjects of every held token and artifact resolved ' +
            'together in a windowed process: userKeys(), userRows() and ' +
            'holdingsOf() ask withUuids once per batch, never byUuid per ' +
            'record, with the same answers',
  run: run
};
