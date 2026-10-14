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
//   E. THE CREDENTIAL CENSUS (#621): `/admin-api/users`' census of about
//      5,000 names asked 5,000 synchronous round trips; `credentialCensus-
//      Async()` asks none — `byKeys` a page of five hundred at a time, a
//      `byName` only for a name not at `uid=<name>`, one question per
//      identifier — and answers exactly what the synchronous census does,
//      a copy held here and a delete made here included, each identifier
//      shape resolved as `locateEntry()` resolves it.
//   F. AN LDAP ADD ASKS FIRST (#621): its existence and one-entry-per-person
//      questions are asked asynchronously before the body runs, which then
//      asks neither synchronously; and an answer asked first is never older
//      than this process — a name or a DN created here, or applied from
//      another process, while the questions were out still refuses the
//      add.
//
// A and the parent's checks run here; B–F run in a child that loads the
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
      // What happens while the answer is on its way (#621): the store
      // changes after it answered, and this process hears of it.
      if (typeof bridge.afterAnswer === 'function') {
        bridge.afterAnswer(name, args);
      }
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

  // E. the credential census (#621).
  await censusQuestions(t, ldap, w, rows, users, bridge);
  // F. an LDAP add asks first.
  await addQuestions(t, ldap, w, rows, users, bridge);
  log.debug('Leaving throughTheDirectory().');
}

// --- E. the credential census (#621) ---------------------------------------

// What the census is handed besides the five thousand `p` names: a person
// named otherwise (`cn=quill`, found by `byName`), a name nobody holds, and
// the four identifier shapes `locateEntry()` resolves by what an entry
// RECORDED.
const IDENTIFIERS = {
  uuid: 'urn:uuid:0f8fad5b-d9cb-469f-a165-70867728950e',
  dn: 'CN=dave,O=Example Corp,C=US',
  did: 'did:example:erin',
  spiffe: 'spiffe://example.org/frank'
};

// Adds the census's people to the stand-in store: credentials on some of
// the `p` people, and the five named above.
function censusPeople(rows, users) {
  log.debug('Entering censusPeople().');
  const put = function (dn, attrs) {
    rows.set('default\n' + dn.toLowerCase(), shared.row('default', dn,
      Object.assign({ objectclass: ['inetOrgPerson'] }, attrs)));
  };
  for (let i = 0; i < 60; i++) {
    const uid = 'p' + String(i).padStart(6, '0');
    const r = rows.get('default\nuid=' + uid + ',' + users);
    if (i % 2 === 0) {
      r.attrs.userpassword = ['{SCRYPT}p' + i];
    }
    if (i % 3 === 0) {
      r.attrs.stswebauthncredential = ['{"id":"k' + i + '"}'];
    }
    if (i % 5 === 0) {
      r.attrs.ststotpcredential = ['sealed-' + i];
      r.attrs.mail = [uid + '@example.com'];
      r.attrs.stsmailverified = ['TRUE'];
    }
  }
  // NOT a name the development seed gives anybody (it seeds a `carol`),
  // so the only entry answering to it is this one, at `cn=`.
  put('cn=quill,' + users, { cn: ['quill'], uid: ['quill'],
                             userpassword: ['{SCRYPT}q'],
                             ststotpcredential: ['sealed-quill'] });
  put('cn=dave,' + users, { cn: ['dave'],
                            x509subject: [IDENTIFIERS.dn],
                            stswebauthncredential: ['{"id":"dave"}'] });
  put('uid=erin-digest,' + users, { uid: ['erin-digest'],
                                    didsubject: [IDENTIFIERS.did],
                                    userpassword: ['{SCRYPT}e'] });
  put('uid=frank-digest,' + users, { uid: ['frank-digest'],
                                     spiffesubject: [IDENTIFIERS.spiffe] });
  put('uid=gina,' + users, { uid: ['gina'],
    entryuuid: [IDENTIFIERS.uuid.slice('urn:uuid:'.length)],
    userpassword: ['{SCRYPT}g'] });
  log.debug('Leaving censusPeople().');
}

async function censusQuestions(t, ldap, w, rows, users, bridge) {
  log.debug('Entering censusQuestions().');
  censusPeople(rows, users);
  // THE NAMES THE USERS LIST HANDS OVER: the directory's first five
  // thousand, as `directoryFirstNames()` asks them, and the rest.
  const credentials = require('../common/credentials');
  const first = await credentials.directoryFirstNames(5000);
  const names = first.names.concat(['quill', 'nobody-here',
    IDENTIFIERS.uuid, IDENTIFIERS.dn, IDENTIFIERS.did, IDENTIFIERS.spiffe]);
  // A NEWER COPY HELD HERE, and a DELETE made here: the census must answer
  // what this process holds, as `locateEntry()` does, not the store's row.
  const held = ldap.existingUserEntry('p000011');
  held.attributes.userpassword = ['{SCRYPT}changed-here'];
  ldap.entries.delete('uid=p000013,' + users);
  t.check(names.indexOf('p000011') >= 0 && names.indexOf('p000013') >= 0,
          'E0. (precondition) the held and deleted people are on the list');

  bridge.reset();
  const counter = { pages: 0, rows: 0 };
  const after = await turnsDuring(function () {
    return ldap.credentialCensusAsync(names, counter);
  });
  const asyncCounts = JSON.parse(JSON.stringify(bridge.counts));
  t.log.info('AFTER (#621): a census of ' + names.length + ' names asked ' +
             asked(asyncCounts.sync) + ' synchronous and ' +
             asked(asyncCounts.async) + ' asynchronous question(s): ' +
             JSON.stringify(asyncCounts) + ', ' + after.turns + ' turn(s)');
  t.check(asked(asyncCounts.sync) === 0,
          'E1. THE CENSUS ASKS THE STORE NOTHING SYNCHRONOUSLY: ' +
          names.length + ' names, no blocking round trip',
          JSON.stringify(asyncCounts));
  // A `byName` for each name that is not at `uid=<name>`: the `cn=`
  // entries among the first names (quill, dave, the two teams), the name
  // nobody holds and the person deleted here.
  t.check(asked(asyncCounts.async, 'byKeys') <= Math.ceil(names.length /
                                                          500) + 1 &&
          asked(asyncCounts.async, 'byName') === counter.byName &&
          counter.byName >= 3 && counter.byName <= 10 &&
          asked(asyncCounts.async) <= Math.ceil(names.length / 500) + 15,
          'E2. and about one asynchronous question per five hundred names: ' +
          'byKeys pages, a byName only for a name not at uid=<name>, one ' +
          'question per identifier', JSON.stringify({ counts: asyncCounts,
            counter: counter }));
  t.check(after.turns >= counter.pages - 1 && counter.pages >= 10,
          'E3. giving the event loop back between pages', after.turns +
          ' turn(s) for ' + counter.pages + ' page(s)');

  // THE OLD PATH, ON THE SAME DATA: every name a `locateEntry()`.
  bridge.reset();
  const before = ldap.credentialCensus(names);
  const syncCounts = JSON.parse(JSON.stringify(bridge.counts));
  t.log.info('BEFORE: the synchronous census asked ' +
             asked(syncCounts.sync) + ' synchronous question(s): ' +
             JSON.stringify(syncCounts.sync));
  t.check(asked(syncCounts.sync) >= 5000,
          'E4. (the cost #621 removes) the synchronous census asks the ' +
          'store once per person it does not hold',
          String(asked(syncCounts.sync)));
  // Compared name by name, and only the first difference printed: the
  // whole answer is megabytes, and a detail that size loses the report's
  // tail to the exiting child.
  const differs = names.filter(function (name, i) {
    return JSON.stringify(after.value[i]) !== JSON.stringify(before[i]);
  });
  t.check(after.value.length === before.length && differs.length === 0,
          'E5. AND ANSWERS EXACTLY WHAT IT DID: every name\'s raw values ' +
          'equal the synchronous census\'s', differs.length ? differs.length +
          ' differ, first ' + differs[0] + ': ' + JSON.stringify([
            after.value[names.indexOf(differs[0])],
            before[names.indexOf(differs[0])]]) : names.length + ' alike');
  const at = function (name) {
    return after.value[names.indexOf(name)];
  };
  t.check(at('p000011') && at('p000011').password === true &&
          at('p000013') === null && at('p000012') &&
          at('p000012').password === true && at('p000001') &&
          at('p000001').password === false,
          'E6. the copy held here wins over the store\'s row, a delete made ' +
          'here is nobody, and the store\'s rows are read',
          JSON.stringify([at('p000011'), at('p000013'), at('p000012')]));
  t.check(at('quill') && at('quill').password === true &&
          at('quill').totp === 'sealed-quill' && at('nobody-here') === null,
          'E7. a person named cn=quill is found by name, and a name nobody ' +
          'holds is nobody', JSON.stringify([at('quill'),
                                             at('nobody-here')]));
  t.check(at(IDENTIFIERS.uuid) && at(IDENTIFIERS.uuid).password === true &&
          at(IDENTIFIERS.dn) && at(IDENTIFIERS.dn).webauthn.length === 1 &&
          at(IDENTIFIERS.did) && at(IDENTIFIERS.did).password === true &&
          at(IDENTIFIERS.spiffe) !== null,
          'E8. each identifier shape resolves to the entry that recorded it',
          JSON.stringify(Object.keys(IDENTIFIERS).map(function (k) {
            return at(IDENTIFIERS[k]);
          })));
  const located = [];
  for (const key of ['quill', 'p000011', 'p000013', 'nobody-here']
    .concat(Object.keys(IDENTIFIERS).map(function (k) {
      return IDENTIFIERS[k];
    }))) {
    const one = await ldap.locateStoredAsync(key);
    const two = ldap.locateEntry(key).stored;
    located.push([key, one ? one.dn : null, two ? two.dn : null]);
  }
  t.check(located.every(function (one) {
    return one[1] === one[2];
  }), 'E9. locateStoredAsync() finds, for each shape, the entry ' +
      'locateEntry() finds', JSON.stringify(located));

  // THROUGH credentials.ts, as /admin-api/users and /admin-api/mfa ask it.
  bridge.reset();
  const facts = await credentials.factorCensusAsync(names.slice(0, 600));
  t.check(asked(bridge.counts.sync) === 0 && facts.size === 600,
          'E10. credentials.factorCensusAsync() asks nothing synchronously',
          JSON.stringify(bridge.counts));
  const factsBefore = credentials.factorCensus(names.slice(0, 600));
  t.check(JSON.stringify(Array.from(facts.entries())) ===
          JSON.stringify(Array.from(factsBefore.entries())),
          'E11. and answers the facts factorCensus() answers',
          facts.size + ' name(s)');

  // A PERSON CHANGED HERE WHILE THEIR PAGE WAS BEING ASKED FOR: the store
  // answered the page before the change, so the row is older than what
  // this process holds by the time it arrives — and what it holds wins.
  // Two people past the first names, whom nothing above has read (an entry
  // read before may still be held, and is then never asked about).
  let fired = false;
  bridge.afterAnswer = function (name, args) {
    if (name !== 'byKeys' ||
        (args[1] || []).indexOf('uid=p004997,' + users) < 0) {
      return;
    }
    bridge.afterAnswer = null;
    fired = true;
    const changed = ldap.existingUserEntry('p004997');
    changed.attributes.userpassword = ['{SCRYPT}changed-meanwhile'];
  };
  const midway = await ldap.credentialCensusAsync(['p004997', 'p004998']);
  bridge.afterAnswer = null;
  t.check(fired && midway[0] && midway[0].password === true &&
          midway[1] && midway[1].password === false &&
          JSON.stringify(midway) === JSON.stringify(ldap.credentialCensus(
            ['p004997', 'p004998'])),
          'E12. an entry changed here while its page was asked for is ' +
          'answered as this process now holds it', JSON.stringify({
            fired: fired, midway: midway }));
  log.debug('Leaving censusQuestions().');
}

// --- F. an LDAP add asks first (#621) ---------------------------------------

// An add of a person, as the socket hands it to a worker.
function addShape(dn, uid) {
  log.debug('Entering addShape().');
  log.debug('Leaving addShape().');
  return { dn: dn, boundDn: '', channel: 'ldap', remoteAddress: '',
           attributes: [{ type: 'objectClass', values: ['inetOrgPerson'] },
                        { type: 'uid', values: [uid] },
                        { type: 'cn', values: [uid] },
                        { type: 'sn', values: ['Added'] }] };
}

async function addQuestions(t, ldap, w, rows, users, bridge) {
  log.debug('Entering addQuestions().');
  const add = function (dn, uid) {
    return Promise.resolve(ldap.performOperation('add', addShape(dn, uid)));
  };
  bridge.reset();
  const made = await add('uid=newbie,' + users, 'newbie');
  const madeCounts = JSON.parse(JSON.stringify(bridge.counts));
  t.log.info('AFTER (#621): an LDAP add asked ' + asked(madeCounts.sync) +
             ' synchronous and ' + asked(madeCounts.async) +
             ' asynchronous question(s): ' + JSON.stringify(madeCounts));
  t.check(made && made.ok === true, 'F1. an LDAP add of a new person ' +
          'succeeds', JSON.stringify(made));
  // (`count` may be asked synchronously: `ldap.maxEntries`' reading of
  // the store's count, at most once in ten seconds per realm.)
  t.check(asked(madeCounts.sync, 'byKeys') === 0 &&
          asked(madeCounts.sync, 'byName') === 0 &&
          asked(madeCounts.async, 'byKeys') === 1 &&
          asked(madeCounts.async, 'byName') === 1,
          'F2. ASKED FIRST: its existence and one-entry-per-person ' +
          'questions are one byKeys and one byName, asynchronous, and the ' +
          'body asks neither synchronously', JSON.stringify(madeCounts));
  bridge.reset();
  const taken = await add('cn=other,' + users, 'quill');
  t.check(taken && taken.ok === false &&
          taken.errorName === 'EntryAlreadyExistsError' &&
          asked(bridge.counts.sync, 'byName') === 0,
          'F3. an add whose uid is quill\'s (held at cn=quill) is refused ' +
          'by the answer asked first', JSON.stringify({ taken: taken,
            counts: bridge.counts }));
  bridge.reset();
  const again = await add('uid=p000005,' + users, 'p000005');
  t.check(again && again.ok === false &&
          again.errorName === 'EntryAlreadyExistsError' &&
          asked(bridge.counts.sync) === 0,
          'F4. and an add of an entry the store holds is refused with ' +
          'nothing asked synchronously', JSON.stringify({ again: again,
            counts: bridge.counts }));

  // THE ANSWER ASKED FIRST IS NEVER OLDER THAN THIS PROCESS: a person
  // created here while the add's questions are out must refuse it.
  const slow = countingBridge(rows, { delayMs: 50 });
  w.attach(slow);
  const pendingName = add('uid=racer-one-b,' + users, 'racer-one');
  const pendingDn = add('uid=racer-two,' + users, 'racer-two');
  const one = ldap.createUser('racer-one', { invent: false, origin: 'test' });
  const two = ldap.createUser('racer-two', { invent: false, origin: 'test' });
  const raced = await pendingName;
  const racedDn = await pendingDn;
  w.attach(bridge);
  t.check(one && one.ok && raced && raced.ok === false &&
          raced.errorName === 'EntryAlreadyExistsError',
          'F5. A NAME TAKEN HERE WHILE THE ADD WAS ASKING refuses the add: ' +
          'the clock moved and the body asked again',
          JSON.stringify({ created: !!(one && one.ok), raced: raced,
                           counts: slow.counts }));
  t.check(two && two.ok && racedDn && racedDn.ok === false &&
          racedDn.errorName === 'EntryAlreadyExistsError',
          'F6. and A DN CREATED HERE WHILE IT WAS ASKING is not hidden by ' +
          'the store\'s older absence', JSON.stringify({ created:
            !!(two && two.ok), raced: racedDn }));

  // AND NEVER OLDER THAN WHAT THIS PROCESS HAS APPLIED: another process
  // commits a person after the store answered the add's question, and this
  // one applies the row (`forgetEntry()`, as the change log does) before
  // the answer arrives. The answer asked first is then stale, and must not
  // be what the body believes — neither the window's slot for the key
  // (`warmAsync()`), nor the name's resolution (`heldUserEntry()`).
  const elsewhere = function (uid, when) {
    log.debug('Entering elsewhere().');
    const dn = 'uid=' + uid + ',' + users;
    const key = dn.toLowerCase();
    bridge.afterAnswer = function (name, args) {
      if (!when(name, args)) {
        return;
      }
      bridge.afterAnswer = null;
      const made = shared.row('default', dn, { uid: [uid],
        objectclass: ['inetOrgPerson'], cn: [uid], sn: ['Elsewhere'] });
      rows.set('default\n' + key, made);
      ldap.directoryHooks.forgetEntry('default', key,
        { dn: dn, attributes: made.attrs, origin: 'test' });
    };
    log.debug('Leaving elsewhere().');
  };
  // F7: the DN itself, while `warmAsync()` asks `byKeys` about it.
  elsewhere('racer-three', function (name, args) {
    return name === 'byKeys' &&
      (args[1] || []).indexOf('uid=racer-three,' + users) >= 0;
  });
  bridge.reset();
  const warmed = await add('uid=racer-three,' + users, 'racer-three');
  t.check(warmed && warmed.ok === false &&
          warmed.errorName === 'EntryAlreadyExistsError',
          'F7. A ROW APPLIED WHILE THE ADD WAS ASKING about its DN is not ' +
          'hidden by the store\'s older absence in the window',
          JSON.stringify({ warmed: warmed, counts: bridge.counts }));
  // F8: a name, while `byName` is asked about it.
  elsewhere('racer-four', function (name, args) {
    return name === 'byName' && args[2] === 'racer-four';
  });
  bridge.reset();
  const named = await add('uid=racer-four-b,' + users, 'racer-four');
  t.check(named && named.ok === false &&
          named.errorName === 'EntryAlreadyExistsError' &&
          asked(bridge.counts.sync, 'byKeys') +
            asked(bridge.counts.sync, 'byName') > 0,
          'F8. and a NAME another process took while the add was asking ' +
          'refuses it: the clock moved, and the body asked again',
          JSON.stringify({ named: named, counts: bridge.counts }));
  bridge.afterAnswer = null;
  log.debug('Leaving addQuestions().');
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
  t.log.info('=== B–F. through the directory, as a windowed worker ===');
  inChild(t, 36);
  log.debug('Leaving run().');
}

if (require.main === module && process.env[CHILD_FLAG] === '1') {
  childMain();
}

module.exports = {
  name: 'directory_window_requests',
  describe: 'the requests that walked a windowed directory, counted (#616): ' +
            'the window\'s asynchronous questions, the directory page, an ' +
            'LDAP search no index narrows, the first names, the credential ' +
            'census and an LDAP add (#621)',
  run: run
};
