// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: group_index_clock.js
//
// ===========================================================================
// THE GROUP INDEX MOVES ONLY WITH A GROUP (#618, 2026-10-14).
//
// `ldap/ldap_server.js`'s group index was keyed on `directoryVersion`, which
// every write moves, so an LDAP add's own authorization (`rolesOf()` ->
// `groupsOfUser()`) rebuilt it on every add, and every person another
// process made rebuilt it in every other process. It now has a clock of its
// own, `groupsVersion`, moved by `touchDirectory()` only for a write that may
// have touched a group (`noteGroupsTouched()`).
//
// What is asserted, in BOTH modes — a process holding the whole directory,
// and a windowed worker (#349) whose store is a stand-in bridge that counts
// the questions it is asked:
//
//   1. a person add, and a person another process added or deleted, does
//      NOT rebuild the index (counted builds; in a window, no `classesUnder`
//      question — the rebuild's — is asked by an add);
//   2. a group write does, and the very next read sees it: a membership
//      added here, a group another process created under `ou=users`, the
//      same group overwritten as a non-group (the case the 2026-09-07 stamp
//      got wrong), a group overwritten locally, and a group another process
//      deleted;
//   3. after every step, the index held is EXACTLY the one a rebuild gives
//      (`groupIndexState(true)` builds one afresh, uncounted, to compare).
//
// The interleaving is the method, as in `tests/directory_indexes.js`: group
// writes between runs of person writes and replicated changes, because a
// clock that moved too seldom is a cache surviving a change it should not.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'group_index_clock',
  level: process.env.LOG_LEVEL || 'info' });

const CHILD_FLAG = 'STS_TEST_GROUP_INDEX_CLOCK_CHILD';

// One row of the stand-in store, in the table's shape.
function storeRow(dn, attributes) {
  log.debug("Entering storeRow().");
  log.debug("Leaving storeRow().");
  return { realm: 'default', dn_key: dn.toLowerCase(), dn: dn,
           attrs: attributes, origin: 'other process', created_at: '1',
           modified_at: '1' };
}

// The entry shape a change-log applier hands the directory.
function entryOf(dn, attributes) {
  log.debug("Entering entryOf().");
  log.debug("Leaving entryOf().");
  return { dn: dn, attributes: attributes, origin: 'other process',
           createdAt: '20261014000000Z', modifiedAt: '20261014000000Z' };
}

// The scenario, in the child: `t` collects, the parent reports.
function scenario(t) {
  log.debug("Entering scenario().");
  const ldap = require('../ldap/ldap_server');
  const w = ldap.directoryWindow;
  const table = new Map();
  let bridge = null;
  if (w) {
    bridge = require('./directory_window').fakeBridge(table);
    w.attach(bridge);
  }
  const mode = w ? '(window) ' : '(whole) ';
  const users = ldap.usersDn();
  const builds = function () {
    return ldap.groupIndexState().builds;
  };
  const asked = function (name) {
    return bridge ? bridge.asked.filter(function (one) {
      return one === name;
    }).length : 0;
  };
  const same = function (what) {
    const state = ldap.groupIndexState(true);
    t.check(state.current &&
            JSON.stringify(state.held) === JSON.stringify(state.fresh),
            mode + what + ': the index held is the one a rebuild gives',
            JSON.stringify({ held: state.held, fresh: state.fresh })
              .slice(0, 600));
  };
  const groupsOf = function (name) {
    return ldap.groupsOfUser(name).groups.map(function (g) {
      return g.cn;
    }).sort();
  };
  // ANOTHER PROCESS's write, as this process's change-log applier hands it
  // over: a windowed key read and forgotten, anything else applied whole.
  const replicated = function (dn, attributes) {
    const key = dn.toLowerCase();
    if (w && w.isWindowed('default', key)) {
      if (attributes) {
        table.set('default\n' + key, storeRow(dn, attributes));
      } else {
        table.delete('default\n' + key);
      }
      ldap.directoryHooks.forgetEntry('default', key,
        attributes ? entryOf(dn, attributes) : null, false);
    } else if (attributes) {
      ldap.directoryHooks.applyEntry('default', key,
                                     entryOf(dn, attributes));
    } else {
      ldap.directoryHooks.removeEntry('default', key);
    }
  };

  // 1. The index is built once, by a read.
  ldap.createUser('gic-ann', { invent: false });
  ldap.createGroup('gic-ops');
  ldap.addGroupMember('gic-ops', 'gic-ann');
  t.equal(JSON.stringify(groupsOf('gic-ann')), JSON.stringify(['gic-ops']),
          mode + '1. a person added to a group is in it');
  const b0 = builds();
  same('1');

  // 2. Person adds, each followed by the read an add's authorization makes.
  const before = bridge ? bridge.asked.length : 0;
  const classesBefore = asked('classesUnder');
  for (let i = 0; i < 25; i++) {
    const made = ldap.createUser('gic-p' + i, { invent: false });
    t.check(made && made.ok !== false, mode + '2. gic-p' + i + ' is made',
            JSON.stringify(made).slice(0, 200));
    t.equal(groupsOf('gic-p' + i).length, 0,
            mode + '2. and is in no group');
  }
  t.equal(builds(), b0, mode + '2. TWENTY-FIVE PERSON ADDS, EACH READ BACK, ' +
          'DID NOT REBUILD THE GROUP INDEX');
  t.equal(asked('classesUnder'), classesBefore,
          mode + '2. and asked the store nothing a rebuild asks');
  if (bridge) {
    t.check((bridge.asked.length - before) / 25 <= 4,
            mode + '2. a person add asks the store a handful of questions ' +
            'at most, none of them the group index\'s',
            String((bridge.asked.length - before) / 25) + ' per add');
  }
  same('2');

  // 3. Persons another process added and deleted.
  for (let i = 0; i < 10; i++) {
    replicated('uid=gic-r' + i + ',' + users,
               { objectclass: ['inetOrgPerson'], uid: ['gic-r' + i] });
  }
  replicated('uid=gic-r0,' + users, null);
  t.equal(groupsOf('gic-ann').length, 1, mode + '3. read after replicated ' +
          'person writes');
  t.equal(builds(), b0, mode + '3. PERSONS ANOTHER PROCESS ADDED OR ' +
          'DELETED did not rebuild it either');
  same('3');

  // 4. A membership written here.
  ldap.addGroupMember('gic-ops', 'gic-p1');
  t.equal(JSON.stringify(groupsOf('gic-p1')), JSON.stringify(['gic-ops']),
          mode + '4. A MEMBERSHIP WRITTEN HERE is seen by the very next read');
  t.equal(builds(), b0 + 1, mode + '4. by one rebuild');
  same('4');

  // 5. A group another process created UNDER ou=users (a windowed key).
  const team = 'cn=gic-team,' + users;
  replicated(team, { objectclass: ['groupOfNames'], cn: ['gic-team'],
                     member: ['uid=gic-p2,' + users] });
  t.equal(JSON.stringify(groupsOf('gic-p2')), JSON.stringify(['gic-team']),
          mode + '5. A GROUP ANOTHER PROCESS CREATED under ou=users is seen');
  same('5');
  const b5 = builds();
  for (let i = 25; i < 30; i++) {
    ldap.createUser('gic-p' + i, { invent: false });
    groupsOf('gic-p' + i);
  }
  t.equal(builds(), b5, mode + '5. and person adds after it keep the index');

  // 6. The same group overwritten by another process as a NON-group.
  replicated(team, { objectclass: ['inetOrgPerson'], cn: ['gic-team'],
                     member: ['uid=gic-p2,' + users] });
  t.equal(groupsOf('gic-p2').length, 0,
          mode + '6. A GROUP OVERWRITTEN AS A NON-GROUP leaves the index');
  same('6');

  // 7. A group overwritten here as a non-group (adoptEntry is a local put
  // through the applier's door; in a window it ADOPTS what the store holds,
  // so the stand-in store is given the row as well).
  const crew = 'cn=gic-crew,' + users;
  const adopt = function (attributes) {
    if (w) {
      table.set('default\n' + crew.toLowerCase(), storeRow(crew, attributes));
    }
    ldap.adoptEntry(crew, attributes, 'test');
  };
  adopt({ objectclass: ['groupOfNames'], cn: ['gic-crew'],
          member: ['uid=gic-p3,' + users] });
  t.equal(JSON.stringify(groupsOf('gic-p3')), JSON.stringify(['gic-crew']),
          mode + '7. a group put here is seen');
  adopt({ objectclass: ['inetOrgPerson'], cn: ['gic-crew'],
          member: ['uid=gic-p3,' + users] });
  t.equal(groupsOf('gic-p3').length, 0,
          mode + '7. AND OVERWRITTEN HERE AS A NON-GROUP, it is gone — the ' +
          'case the 2026-09-07 stamp kept wrongly');
  same('7');

  // 8. A group another process deleted.
  const band = 'cn=gic-band,' + users;
  replicated(band, { objectclass: ['groupOfUniqueNames'], cn: ['gic-band'],
                     uniquemember: ['uid=gic-p4,' + users] });
  t.equal(JSON.stringify(groupsOf('gic-p4')), JSON.stringify(['gic-band']),
          mode + '8. a group another process made is seen');
  replicated(band, null);
  t.equal(groupsOf('gic-p4').length, 0,
          mode + '8. A GROUP ANOTHER PROCESS DELETED is gone at once');
  same('8');

  // 9. And person writes after all of it still keep the index.
  const b9 = builds();
  for (let i = 30; i < 40; i++) {
    ldap.createUser('gic-p' + i, { invent: false });
    groupsOf('gic-p' + i);
  }
  replicated('uid=gic-r1,' + users, null);
  groupsOf('gic-ann');
  t.equal(builds(), b9, mode + '9. person writes after the group writes ' +
          'keep the index');
  t.equal(JSON.stringify(groupsOf('gic-p1')), JSON.stringify(['gic-ops']),
          mode + '9. and every membership is still answered');
  same('9');
  log.debug("Leaving scenario().");
}

async function childMain() {
  log.debug("Entering childMain().");
  const seen = [];
  const t = {
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
    scenario(t);
  } catch (e) {
    log.debug("Caught in childMain(): " + ((e && e.message) || e));
    threw = (e && e.stack) || String(e);
  }
  fs.writeFileSync(process.env.PROBE_OUT,
                   JSON.stringify({ seen: seen, threw: threw }));
  log.debug("Leaving childMain().");
  process.exit(0);
}

// One mode in a child of its own: a windowed worker needs its environment
// before the directory module is first required.
function inChild(t, windowed) {
  log.debug("Entering inChild().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-gic-'));
  const outFile = path.join(dir, 'out.json');
  const env = Object.assign({}, process.env, { PROBE_OUT: outFile,
                                               LOG_LEVEL: 'fatal' });
  env[CHILD_FLAG] = '1';
  delete env.CONFIG_FILE;
  delete env.LDAP_WORKER_DIRECTORY;
  delete env.STS_REQUEST_WORKER;
  if (windowed) {
    env.STS_REQUEST_WORKER = '1';
    env.LDAP_WORKER_DIRECTORY = 'postgres-lru';
    env.STS_PERSISTENCE_MODE = 'postgres';
    env.LDAP_WORKER_CACHE_ENTRIES = '100';
  }
  const child = childProcess.spawnSync(process.execPath, [__filename],
    { cwd: path.join(__dirname, '..'), env: env, encoding: 'utf8',
      timeout: 120000 });
  let result = null;
  try {
    result = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  } catch (e) {
    log.debug("Caught in inChild(): " + ((e && e.message) || e));
    t.bad('the ' + (windowed ? 'windowed' : 'whole-directory') + ' child ' +
          'reported nothing', 'status ' + child.status + ': ' +
          String(child.stderr || '').slice(-2000));
    log.debug("Leaving inChild().");
    return;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  result.seen.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  if (result.threw) {
    t.bad('the child threw', result.threw);
  }
  t.check(result.seen.length >= 40, 'every assertion of the child ran',
          String(result.seen.length));
  log.debug("Leaving inChild().");
}

function run(t) {
  log.debug("Entering run().");
  t.log.info('=== a process holding the whole directory ===');
  inChild(t, false);
  t.log.info('=== a windowed worker (#349) over a counting bridge ===');
  inChild(t, true);
  log.debug("Leaving run().");
}

if (require.main === module && process.env[CHILD_FLAG] === '1') {
  childMain();
}

module.exports = {
  name: 'group_index_clock',
  describe: 'the group index rebuilds only for a group write (#618): ' +
            'person adds and replicated person changes keep it, group ' +
            'writes local and replicated rebuild it, and it always equals ' +
            'a fresh build, whole and windowed',
  run: run
};
