// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: directory_window_requests.js
//
// ===========================================================================
// THE REQUESTS THAT WALKED A WINDOWED DIRECTORY, COUNTED (#616).
//
// On 8081 (about 200,000 people, the directory a window onto postgres) three
// requests paged every person through the SYNCHRONOUS bridge on a request
// worker's event loop: `GET /admin-api/ldap/directory?per=1` (38–45 s), an
// LDAP search the index could not narrow (28.5 s), and `/admin-api/users`'
// first names (3 s). This file holds the fixes by COUNTING what the store is
// asked — synchronously and asynchronously, by question, and how many rows it
// answered — over a stand-in bridge holding thousands of people, never by
// timing anything:
//
//   A. THE WINDOW'S ASYNCHRONOUS QUESTIONS: `walkAsync()` pages only through
//      `queryAsync()`, gives the event loop back between pages and stops
//      paging when its consumer stops; `realmPageAsync()` is one statement;
//      `keysUnder()` / `keysUnderAsync()` read `limit` + 1 keys and no
//      entry; `classesUnderAsync()` is one statement and pages nothing.
//   B. THE DIRECTORY PAGE (`ldap_server.js` loaded as a windowed worker):
//      a promise, answered from `realmCount`, `originCounts` and one
//      `realmPage` of `per` rows; the origin filter pushed down; a `q`
//      looking inside at most its bound and saying so; nothing synchronous.
//   C. AN LDAP SEARCH NO INDEX NARROWS: through `performOperation()` as a
//      worker runs it — asynchronous, the store asked only through
//      `queryAsync()`, the paging stopped by the size limit (two pages for
//      five hundred matches of five thousand people) and by the time limit
//      (code 3, the entries already sent kept), the entries STREAMED through
//      `emit` before the answer, and a search for groups asking the class
//      index and paging no person at all.
//   D. THE FIRST NAMES: `personNamesUpTo()` asks `keysUnder` (no `page`, no
//      entry), `personNamesUpToAsync()` only asynchronously.
//
// A and the parent's checks run here; B–D run in a child that loads the
// directory as a windowed request worker (`tests/directory_window.js`'s
// section H arrangement).
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const shared = require('./directory_window');

const log = require('bunyan').createLogger({
  name: 'directory_window_requests',
  level: process.env.LOG_LEVEL || 'info' });

const CHILD_FLAG = 'STS_TEST_DIRECTORY_WINDOW_REQUESTS_CHILD';

// The stand-in bridge, answering #616's questions too, counting every
// question by name and by door (synchronous or not) and every row answered,
// and — when `delayMs` is set — answering asynchronously after a delay.
function countingBridge(rows, opts) {
  log.debug('Entering countingBridge().');
  const options = opts || {};
  const base = shared.fakeBridge(rows);
  const queries = require('../persistence/directory_queries');
  const counts = { sync: {}, async: {}, rows: 0 };
  const sorted = function (realm) {
    return Array.from(rows.values()).filter(function (r) {
      return r.realm === realm;
    }).map(function (r) {
      return JSON.parse(JSON.stringify(r));
    }).sort(function (a, b) {
      return a.dn_key < b.dn_key ? -1 : (a.dn_key > b.dn_key ? 1 : 0);
    });
  };
  const under = function (key, b) {
    return key.length > b.length + 1 && key.endsWith(',' + b);
  };
  const originOf = function (r) {
    return r.origin ? String(r.origin) : 'unstated';
  };
  const answer = function (name, args) {
    if (name === 'realmPage') {
      const o = args[3] || {};
      return sorted(args[0]).filter(function (r) {
        return r.dn_key > args[1] && (!o.origin || originOf(r) === o.origin);
      }).slice(o.offset || 0, (o.offset || 0) + args[2])
        .map(queries.rowOf);
    }
    if (name === 'realmCount') {
      return sorted(args[0]).filter(function (r) {
        return !args[1] || originOf(r) === args[1];
      }).length;
    }
    if (name === 'originCounts') {
      const out = {};
      sorted(args[0]).forEach(function (r) {
        out[originOf(r)] = (out[originOf(r)] || 0) + 1;
      });
      return out;
    }
    if (name === 'keysUnder') {
      return sorted(args[0]).filter(function (r) {
        return under(r.dn_key, args[1]) && r.dn_key > args[2];
      }).slice(0, args[3]).map(function (r) {
        return { key: r.dn_key, dn: r.dn };
      });
    }
    if (name === 'equalUnder') {
      const column = args[2] === 'mail' ? 'mail' : 'uid';
      return sorted(args[0]).filter(function (r) {
        return (r.dn_key === args[1] || under(r.dn_key, args[1])) &&
          (r.attrs[column] || []).some(function (v) {
            return String(v).toLowerCase() ===
              String(args[3]).toLowerCase();
          });
      }).slice(0, args[4]).map(queries.rowOf);
    }
    return base.query(name, args);
  };
  const tally = function (door, name, value) {
    door[name] = (door[name] || 0) + 1;
    if (Array.isArray(value)) {
      counts.rows += value.length;
    }
    return value;
  };
  const bridge = {
    counts: counts,
    query: function (name, args) {
      return tally(counts.sync, name, answer(name, args));
    },
    queryAsync: function (name, args) {
      const value = tally(counts.async, name, answer(name, args));
      if (!options.delayMs) {
        return Promise.resolve(value);
      }
      return new Promise(function (resolve) {
        setTimeout(function () {
          resolve(value);
        }, options.delayMs);
      });
    },
    reset: function () {
      counts.sync = {};
      counts.async = {};
      counts.rows = 0;
    }
  };
  log.debug('Leaving countingBridge().');
  return bridge;
}

// The number of questions a door was asked, of any name or of one.
function asked(door, name) {
  return name ? (door[name] || 0) : Object.keys(door).reduce(function (n, k) {
    return n + door[k];
  }, 0);
}

// A table of `n` people under `users`, and `groups` groups among them.
function peopleTable(users, n, groups) {
  log.debug('Entering peopleTable().');
  const rows = new Map();
  for (let i = 0; i < n; i++) {
    const uid = 'p' + String(i).padStart(6, '0');
    const dn = 'uid=' + uid + ',' + users;
    const r = shared.row('default', dn, { uid: [uid],
      objectclass: ['inetOrgPerson'], cn: ['Person ' + i],
      description: [i % 2 ? 'odd' : 'even'] });
    r.origin = i % 3 ? 'scim' : 'seed';
    rows.set('default\n' + dn.toLowerCase(), r);
  }
  for (let g = 0; g < (groups || 0); g++) {
    const dn = 'cn=team' + g + ',' + users;
    rows.set('default\n' + dn.toLowerCase(), shared.row('default', dn,
      { cn: ['team' + g], objectclass: ['groupOfNames'],
        member: ['uid=p000001,' + users] }));
  }
  log.debug('Leaving peopleTable().');
  return rows;
}

// Counts the macrotask turns the event loop takes while `work` runs.
async function turnsDuring(work) {
  log.debug('Entering turnsDuring().');
  let turns = 0;
  let running = true;
  const spin = function () {
    if (running) {
      turns += 1;
      setImmediate(spin);
    }
  };
  setImmediate(spin);
  const value = await work();
  running = false;
  log.debug('Leaving turnsDuring(). ' + turns);
  return { value: value, turns: turns };
}

// --- A. the window's asynchronous questions --------------------------------

async function windowQuestions(t) {
  log.debug('Entering windowQuestions().');
  t.log.info('=== A. the window\'s asynchronous questions ===');
  const DirectoryWindow = require('../ldap/directory_window');
  const users = 'ou=users,dc=example,dc=com';
  const devices = 'ou=devices,dc=example,dc=com';
  const rows = peopleTable(users, 6000, 3);
  const w = new DirectoryWindow({
    currentId: function () { return 'default'; },
    onRemove: function () {},
    windowedContainers: function () { return [users, devices]; },
    fromRow: function (realmId, r) {
      return { dn: r.dn, attributes: r.attributes, origin: r.origin };
    },
    maxEntries: function () { return 100; },
    onTouched: function () {}
  });
  const bridge = countingBridge(rows);
  w.attach(bridge);

  // A1–A3: the whole walk, asynchronously, and the event loop between.
  const walked = await turnsDuring(async function () {
    let n = 0;
    for await (const pair of w.walkAsync('default', users)) {
      n += pair ? 1 : 0;
    }
    return n;
  });
  t.equal(walked.value, 6003, 'A1. walkAsync() visits every entry under ' +
          'the base');
  t.check(asked(bridge.counts.sync) === 0 &&
          asked(bridge.counts.async, 'page') === 13,
          'A2. and asks the store ONLY asynchronously — thirteen pages of ' +
          'five hundred, no synchronous question',
          JSON.stringify(bridge.counts));
  t.check(walked.turns >= 12,
          'A3. giving the event loop back between pages', walked.turns +
          ' turn(s)');
  t.equal(w.stats().size, 0, 'A4. and holding nothing it read');

  // A5: a consumer that stops early pages no further.
  bridge.reset();
  let taken = 0;
  for await (const pair of w.walkAsync('default', users)) {
    taken += pair ? 1 : 0;
    if (taken === 600) {
      break;
    }
  }
  t.check(asked(bridge.counts.async, 'page') === 2,
          'A5. a walk stopped after 600 entries asked two pages, not ' +
          'thirteen', JSON.stringify(bridge.counts));

  // A6: one page of the whole realm.
  bridge.reset();
  const page = await w.realmPageAsync('default', '', 25,
                                      { offset: 50, origin: 'scim' });
  t.check(page.rows.length === 25 && page.more &&
          asked(bridge.counts.async) === 1 && bridge.counts.rows === 25 &&
          asked(bridge.counts.sync) === 0 &&
          page.rows.every(function (one) {
            return one.entry.origin === 'scim';
          }),
          'A6. realmPageAsync() is ONE statement answering one page of the ' +
          'origin asked for', JSON.stringify(bridge.counts));

  // A7–A8: the first keys, both doors.
  bridge.reset();
  const keys = await w.keysUnderAsync('default', users, 5000);
  t.check(keys.rows.length === 5000 && keys.more &&
          asked(bridge.counts.async, 'keysUnder') === 6 &&
          asked(bridge.counts.sync) === 0 && bridge.counts.rows === 5001,
          'A7. keysUnderAsync(5000) reads 5,001 keys in six statements and ' +
          'no entry', JSON.stringify(bridge.counts));
  bridge.reset();
  const few = w.keysUnder('default', users, 10);
  t.check(few.rows.length === 10 && few.more &&
          asked(bridge.counts.sync, 'keysUnder') === 1 &&
          asked(bridge.counts.sync) === 1 && bridge.counts.rows === 11,
          'A8. keysUnder(10) is one synchronous statement of eleven keys',
          JSON.stringify(bridge.counts));

  // A9: the groups, from the class index.
  bridge.reset();
  const groups = await w.classesUnderAsync('default', users,
    ['groupofnames'], function () {
      return true;
    });
  t.check(groups.length === 3 &&
          asked(bridge.counts.async, 'classesUnder') === 1 &&
          asked(bridge.counts.async, 'page') === 0 &&
          asked(bridge.counts.sync) === 0,
          'A9. classesUnderAsync() is one asynchronous statement and pages ' +
          'no person', JSON.stringify(bridge.counts));
  log.debug('Leaving windowQuestions().');
}

// --- B–D: in a child, ldap_server.js as a windowed worker -------------------

async function throughTheDirectory(t) {
  log.debug('Entering throughTheDirectory().');
  const config = require('../common/config');
  const ldap = require('../ldap/ldap_server');
  const w = ldap.directoryWindow;
  t.check(!!w, 'B0. the directory is a window onto the store');
  if (!w) {
    log.debug('Leaving throughTheDirectory(). No window.');
    return;
  }
  const users = ldap.usersDn().toLowerCase();
  const rows = peopleTable(users, 5000, 2);
  // THE STORE HOLDS THE RESIDENT ENTRIES TOO, as postgres does: the base,
  // the containers, the seeded groups and applications.
  w.residentRows('default').forEach(function (one) {
    rows.set('default\n' + one.key, { realm: 'default', dn_key: one.key,
      dn: one.entry.dn, attrs: one.entry.attributes,
      origin: one.entry.origin || null, created_at: '1', modified_at: '1' });
  });
  const total = rows.size;
  const bridge = countingBridge(rows);
  w.attach(bridge);

  // B. the directory page.
  bridge.reset();
  const pending = ldap.ldapDirectoryView({ query: { per: '1' } });
  t.check(pending && typeof pending.then === 'function',
          'B1. /admin/ldap/directory is a promise in a windowed process');
  const one = (await pending).json;
  t.check(one.count === total && one.entries.length === 1 &&
          one.order === 'key' && one.search === null &&
          one.pages === total,
          'B2. ?per=1 answers one row of every entry in the realm, in the ' +
          'store\'s key order', JSON.stringify({ count: one.count,
            total: total, shown: one.entries.length, order: one.order }));
  t.check(asked(bridge.counts.sync) === 0 &&
          asked(bridge.counts.async, 'realmCount') === 1 &&
          asked(bridge.counts.async, 'originCounts') === 1 &&
          asked(bridge.counts.async, 'realmPage') === 1 &&
          asked(bridge.counts.async, 'page') === 0 &&
          bridge.counts.rows === 1,
          'B3. ASKED, NOT WALKED: two counts and one page of one row, all ' +
          'asynchronous, where it paged every person synchronously',
          JSON.stringify(bridge.counts));
  bridge.reset();
  const scim = (await ldap.ldapDirectoryView({ query: { origin: 'scim',
                                                        per: '25',
                                                        page: '3' } })).json;
  t.check(scim.matched === scim.originCounts.scim &&
          scim.entries.length === 25 && scim.page === 3 &&
          scim.entries.every(function (entry) {
            return entry.origin === 'scim';
          }) &&
          asked(bridge.counts.async, 'realmPage') === 1 &&
          asked(bridge.counts.sync) === 0 && bridge.counts.rows === 25,
          'B4. THE ORIGIN FILTER AND THE PAGE ARE PUSHED DOWN: page 3 of ' +
          'scim is one statement of 25 rows, matched counted by the store',
          JSON.stringify({ matched: scim.matched, counts: bridge.counts }));
  bridge.reset();
  const found = (await ldap.ldapDirectoryView({ query: { q: 'p000123' } }))
    .json;
  t.check(found.matched === 1 && found.search &&
          found.search.complete === false &&
          found.search.scanned === found.search.scanLimit &&
          asked(bridge.counts.async, 'realmPage') ===
            found.search.scanLimit / 500 &&
          asked(bridge.counts.sync) === 0,
          'B5. A `q` LOOKS INSIDE AT MOST ITS BOUND, asynchronously, and ' +
          'says it did not see everything', JSON.stringify({
            search: found.search, matched: found.matched,
            counts: bridge.counts }));

  // C. an LDAP search no index narrows, as a worker runs it.
  const search = function (filter, extra) {
    const emitted = [];
    const shape = Object.assign({ dn: ldap.baseDn(), boundDn: '',
      channel: 'ldap', remoteAddress: '', scope: 2, filter: filter,
      attributes: ['uid'], sizeLimit: 0, timeLimit: 0 }, extra || {});
    return turnsDuring(function () {
      return Promise.resolve(ldap.performOperation('search', shape,
        function (batch) {
          emitted.push(batch.length);
        }));
    }).then(function (done) {
      return { outcome: done.value, turns: done.turns, emitted: emitted,
               sent: emitted.reduce(function (n, k) {
                 return n + k;
               }, 0) + ((done.value && done.value.entries) || []).length };
    });
  };
  bridge.reset();
  const none = await search('(description=nomatch)');
  t.check(none.outcome.ok && none.sent === 0 &&
          asked(bridge.counts.sync, 'page') === 0 &&
          asked(bridge.counts.sync, 'byKeys') === 0 &&
          asked(bridge.counts.async, 'page') >= 10 && none.turns >= 10,
          'C1. A SEARCH MATCHING NOBODY pages every person ASYNCHRONOUSLY, ' +
          'the event loop turning between pages — no synchronous page',
          JSON.stringify({ counts: bridge.counts, turns: none.turns }));
  bridge.reset();
  const everyone = await search('(objectClass=inetOrgPerson)');
  t.check(everyone.outcome.ok === false &&
          everyone.outcome.errorName === 'SizeLimitExceededError' &&
          everyone.sent === 500 &&
          asked(bridge.counts.async, 'page') <= 2 &&
          asked(bridge.counts.sync, 'page') === 0,
          'C2. THE SIZE LIMIT STOPS THE PAGING: five hundred entries and ' +
          'code 4 after at most two pages of five thousand people',
          JSON.stringify({ sent: everyone.sent, counts: bridge.counts,
                           error: everyone.outcome.errorName }));
  t.check(everyone.emitted.length >= 1 && everyone.emitted[0] > 0 &&
          everyone.outcome.entries.length < 500,
          'C3. AND THE ENTRIES STREAM: batches went out through emit ' +
          'before the answer, which carries only the rest',
          JSON.stringify({ batches: everyone.emitted,
                           rest: everyone.outcome.entries.length }));
  bridge.reset();
  const teams = await search('(objectClass=groupOfNames)');
  const teamDns = (teams.outcome.entries || []).map(function (entry) {
    return String(entry.objectName).toLowerCase();
  });
  t.check(teams.outcome.ok &&
          asked(bridge.counts.async, 'page') === 0 &&
          asked(bridge.counts.sync, 'page') === 0 &&
          asked(bridge.counts.async, 'classesUnder') >= 1 &&
          teamDns.indexOf('cn=team0,' + users) >= 0 &&
          teamDns.indexOf('cn=team1,' + users) >= 0,
          'C4. A SEARCH FOR GROUPS asks the class index and pages no ' +
          'person, and still finds the groups under ou=users',
          JSON.stringify({ counts: bridge.counts, groups: teamDns.length }));
  const slow = countingBridge(rows, { delayMs: 300 });
  w.attach(slow);
  config.setOverride('ldap.timeLimit', '1');
  const late = await search('(description=nomatch)');
  config.clearOverride('ldap.timeLimit');
  t.check(late.outcome.ok === false &&
          late.outcome.errorName === 'TimeLimitExceededError' &&
          asked(slow.counts.async, 'page') <= 5,
          'C5. THE TIME LIMIT STOPS THE PAGING: ldap.timeLimit=1 against a ' +
          'store answering a page in 300 ms ends with code 3 after a few ' +
          'pages, not eleven', JSON.stringify({ error:
            late.outcome.errorName, counts: slow.counts }));
  slow.reset();
  const client = await search('(description=nomatch)', { timeLimit: 1 });
  t.check(client.outcome.errorName === 'TimeLimitExceededError' &&
          asked(slow.counts.async, 'page') <= 5,
          'C6. and so does the CLIENT\'s shorter timeLimit',
          JSON.stringify({ error: client.outcome.errorName,
                           counts: slow.counts }));
  w.attach(bridge);

  // D. the first names.
  const credentials = require('../common/credentials');
  bridge.reset();
  const first = await credentials.directoryFirstNames(5000);
  t.check(first && first.names.length === 5000 && first.more &&
          asked(bridge.counts.sync) === 0 &&
          asked(bridge.counts.async, 'keysUnder') === 6 &&
          asked(bridge.counts.async, 'page') === 0 &&
          bridge.counts.rows === 5001,
          'D1. /admin-api/users\' first 5,000 names are 5,001 keys asked ' +
          'asynchronously, no entry read', JSON.stringify(bridge.counts));
  bridge.reset();
  const population = credentials.secondFactorPopulation([], { limit: 100 });
  t.check(population.scanned === 100 && population.capped &&
          asked(bridge.counts.sync, 'keysUnder') === 1 &&
          asked(bridge.counts.sync, 'page') === 0 &&
          asked(bridge.counts.async) === 0,
          'D2. personNamesUpTo(100), asked synchronously, is one keysUnder ' +
          'statement of 101 keys and no page of entries',
          JSON.stringify(bridge.counts));
  bridge.reset();
  const handed = credentials.secondFactorPopulation([], { limit: 5000,
    directoryFirst: first });
  t.check(handed.scanned === 5000 && handed.capped &&
          asked(bridge.counts.sync, 'keysUnder') === 0 &&
          asked(bridge.counts.async) === 0,
          'D3. and handed the names asked already, asks the directory ' +
          'nothing more for them', JSON.stringify(bridge.counts));
  log.debug('Leaving throughTheDirectory().');
}

async function childMain() {
  log.debug('Entering childMain().');
  const seen = [];
  const t = {
    log: log,
    check: function (ok, what, detail) {
      seen.push({ ok: !!ok, what: what, detail: detail || '' });
      return !!ok;
    },
    equal: function (a, b, what, detail) {
      return t.check(a === b, what, 'expected ' + JSON.stringify(b) +
                     ', got ' + JSON.stringify(a) +
                     (detail ? ' — ' + detail : ''));
    }
  };
  let threw = '';
  try {
    await throughTheDirectory(t);
  } catch (e) {
    log.debug('Caught in childMain(): ' + ((e && e.message) || e));
    threw = (e && e.stack) || String(e);
  }
  fs.writeFileSync(process.env.PROBE_OUT,
                   JSON.stringify({ seen: seen, threw: threw }));
  log.debug('Leaving childMain().');
  process.exit(0);
}

function inChild(t, minimum) {
  log.debug('Entering inChild().');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-dwr-'));
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
    log.debug('Caught in inChild(): ' + ((e && e.message) || e));
    t.bad('the windowed child reported nothing', 'status ' + child.status +
          ': ' + String(child.stderr || '').slice(-2000));
    log.debug('Leaving inChild().');
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
  t.check(result.seen.length >= minimum, 'every assertion of the windowed ' +
          'child ran', String(result.seen.length));
  log.debug('Leaving inChild().');
}

async function run(t) {
  log.debug('Entering run().');
  await windowQuestions(t);
  t.log.info('=== B–D. through the directory, as a windowed worker ===');
  inChild(t, 15);
  log.debug('Leaving run().');
}

if (require.main === module && process.env[CHILD_FLAG] === '1') {
  childMain();
}

module.exports = {
  name: 'directory_window_requests',
  describe: 'the requests that walked a windowed directory, counted (#616): ' +
            'the window\'s asynchronous questions, the directory page, an ' +
            'LDAP search no index narrows, and the first names',
  run: run
};
