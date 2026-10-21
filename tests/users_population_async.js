// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: users_population_async.js
//
// ===========================================================================
// THE USERS PAGE RESOLVES THE REGISTER'S SUBJECTS ASYNCHRONOUSLY (#790).
//
// On 8081 `GET /admin-api/users` resolved the subjects of the whole token
// register — ~228,000 — through synchronous `withUuids` statements, spent
// the request's directory budget and answered 503.
// `stats.userRowsAsync()` gathers the same subjects and asks the directory
// through `findWindowedAsync()`; the page's population is built from it.
//
//   P1. userRowsAsync() asks `withUuids` asynchronously, once per batch, and
//       never synchronously;
//   P2. and answers the rows userRows() answers — a person by their name,
//       a subject naming nobody as itself;
//   P3. the Users page's population (`peopleAndCensusAsync()`) is built from
//       it: building it asks `withUuids` synchronously not at all.
//   P4. its tiles too (2026-10-21): the directory's tallies and signed-in
//       count on the read pool, none synchronously, the register's subjects
//       never asked one at a time, and the live sign-on sessions from the
//       session index — no session body walked.
//
// In a child holding the directory as a windowed request worker over a
// stand-in bridge that counts synchronous and asynchronous questions.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'users_population_async',
  level: process.env.LOG_LEVEL || 'info' });

const CHILD_FLAG = 'STS_TEST_USERS_POPULATION_ASYNC_CHILD';
const PEOPLE = 300;
const NOBODY = 900;

async function inTheWorker(t) {
  log.debug('Entering inTheWorker().');
  const shared = require('./directory_window');
  const queries = require('../persistence/directory_queries');
  const ldap = require('../ldap/ldap_server');
  const stats = require('../common/admin_stats');
  const realms = require('../common/realms');
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
    const uid = 'upa' + String(i).padStart(4, '0');
    const uuid = crypto.randomUUID();
    const dn = 'uid=' + uid + ',' + users;
    rows.set('default\n' + dn.toLowerCase(), shared.row('default', dn,
      { uid: [uid], objectclass: ['inetOrgPerson'], cn: ['P ' + i],
        entryuuid: [uuid] }));
    people.push({ uid: uid, uuid: uuid });
  }
  w.residentRows('default').forEach(function (one) {
    rows.set('default\n' + one.key, { realm: 'default', dn_key: one.key,
      dn: one.entry.dn, attrs: one.entry.attributes, origin: null,
      created_at: '1', modified_at: '1' });
  });
  const base = shared.fakeBridge(rows);
  const asked = { sync: 0, async: 0 };
  // Every question by name, for P4.
  const byName = { sync: {}, async: {} };
  const withUuids = function (args) {
    const wanted = new Set(args[1]);
    return Array.from(rows.values()).filter(function (r) {
      return r.realm === args[0] && (r.attrs.entryuuid || []).some(
        function (u) {
          return wanted.has(String(u).toLowerCase());
        });
    }).map(function (r) {
      return queries.rowOf(JSON.parse(JSON.stringify(r)));
    });
  };
  w.attach({
    query: function (name, args) {
      byName.sync[name] = (byName.sync[name] || 0) + 1;
      if (name === 'withUuids') {
        asked.sync++;
        return withUuids(args);
      }
      return base.query(name, args);
    },
    queryAsync: function (name, args) {
      byName.async[name] = (byName.async[name] || 0) + 1;
      if (name === 'withUuids') {
        asked.async++;
        return Promise.resolve(withUuids(args));
      }
      // A question the shared stand-in does not know (the population's
      // first directory names, `keysUnder`) answers empty: P3 counts only
      // withUuids.
      try {
        return Promise.resolve(base.query(name, args));
      } catch (e) {
        log.debug('Caught in queryAsync(): ' + ((e && e.message) || e));
        return Promise.resolve([]);
      }
    }
  });
  const inRealm = function (fn) {
    return realms.run(realms.get(realms.DEFAULT_ID), fn);
  };
  people.forEach(function (p, i) {
    stats.recordAssertion('2.0', { id: 'upa-p-' + i,
                                   subject: 'urn:uuid:' + p.uuid });
  });
  for (let i = 0; i < NOBODY; i++) {
    stats.recordAssertion('2.0', { id: 'upa-n-' + i,
                                   subject: 'urn:uuid:' + crypto.randomUUID() });
  }
  const distinct = PEOPLE + NOBODY;
  const batches = Math.ceil(distinct / 500);

  asked.sync = 0;
  asked.async = 0;
  const viaAsync = await inRealm(function () {
    return stats.userRowsAsync();
  });
  t.check(asked.sync === 0 && asked.async === batches,
          'P1. userRowsAsync() asks withUuids asynchronously, once per batch ' +
          'of ' + distinct + ' subjects, and never synchronously',
          JSON.stringify(asked));
  const viaSync = inRealm(function () {
    return stats.userRows();
  });
  const keysOf = function (list) {
    return list.map(function (r) {
      return r.key;
    }).sort().join('|');
  };
  t.check(keysOf(viaAsync) === keysOf(viaSync) && viaAsync.some(function (r) {
    return r.key === people[0].uid;
  }), 'P2. and answers the rows userRows() answers, a person by their name',
          JSON.stringify({ async: viaAsync.length, sync: viaSync.length }));

  const views = require('../admin-core/admin_views');
  asked.sync = 0;
  asked.async = 0;
  await inRealm(function () {
    return views.peopleAndCensusAsync();
  });
  t.check(asked.sync === 0 && asked.async >= batches,
          'P3. the Users page\'s population is built from it, asking ' +
          'withUuids synchronously not at all', JSON.stringify(asked));

  // P4 (2026-10-21): the page's TILES are asked asynchronously too — the
  // directory's credential tallies and its count of the signed-in names on
  // the read pool, and the live sign-on sessions from the session index
  // (`liveSessionCountsAsync()`, stood in for here) — and no session body
  // is walked.
  const authnModule = require('../authn/authn');
  const realLive = authnModule.liveSessionCountsAsync;
  const realMatching = authnModule.sessionsMatching;
  let liveAsked = 0;
  let walked = 0;
  authnModule.liveSessionCountsAsync = function () {
    liveAsked++;
    return Promise.resolve({ people: 7,
                             byUsername: new Map([[people[0].uid, 3]]) });
  };
  authnModule.sessionsMatching = function () {
    walked++;
    return [];
  };
  byName.sync = {};
  byName.async = {};
  let listed = null;
  try {
    listed = await inRealm(function () {
      return views.usersJsonAsync({ query: {} });
    });
  } finally {
    authnModule.liveSessionCountsAsync = realLive;
    authnModule.sessionsMatching = realMatching;
  }
  // The questions that grow with the realm: the tallies, and the register's
  // subjects (`byUuid` once per subject when the population was built after
  // their answer). A shown row's own flags are bounded by the page and are
  // not counted here.
  const tiled = ['countHolding', 'withUuids', 'byUuid', 'withNames'];
  const syncTiles = tiled.filter(function (name) {
    return byName.sync[name];
  });
  t.check(listed && syncTiles.length === 0 &&
          (byName.async.countHolding || 0) >= 1,
          'P4. the directory\'s tiles and the register\'s subjects are ' +
          'asked on the read pool, none synchronously',
          JSON.stringify(byName));
  const first = ((listed && listed.users) || []).filter(function (row) {
    return row.key === people[0].uid;
  })[0];
  t.check(liveAsked === 1 && walked === 0 && listed &&
          listed.withActiveSession === 7 &&
          (!first || first.liveSessions === 3),
          'P4. and the live sign-on sessions are the index\'s counts: no ' +
          'session is walked', JSON.stringify({ liveAsked: liveAsked,
            walked: walked, tile: listed && listed.withActiveSession,
            first: first && first.liveSessions }));
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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-upa-'));
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
  t.check(result.seen.length >= 4, 'every assertion of the windowed child ' +
          'ran', String(result.seen.length));
  log.debug('Leaving run().');
}

if (require.main === module && process.env[CHILD_FLAG] === '1') {
  childMain();
}

module.exports = {
  name: 'users_population_async',
  describe: 'the Users page resolves the register\'s subjects asynchronously ' +
            '(#790)',
  run: run
};
