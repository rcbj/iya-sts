// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: change_rows_per_add.js
//
// ===========================================================================
// WHAT ONE DIRECTORY ADD WRITES TO THE CHANGE LOG (#618 phase 2, 2026-10-14).
//
// Every minted row a flush writes is also a row of `sts_changes`: sealed,
// inserted, NOTIFY'd, then pulled, opened and applied by every other
// process. On 8081 (about 3M entries, 55 LDAP adds a second) each add cost
// about 9.7 of them:
//
//   directory                       1
//   admin_stats.users (own)         4.0   every OTHER process noted the
//                                         replicated create in its identity
//                                         register, and past MAX_USERS
//                                         journalled the eviction too
//   risc.register                   2.3   a blank row per account created,
//                                         and past risc.maxAccountsTracked
//                                         the eviction of the oldest
//   admin_stats.nums (own)          0.9   `usersForgotten`, bumped by those
//                                         evictions
//   audit.events (own)              0.8   the add's audit row — legitimate
//   audit.nums (own)                0.7   its counter — legitimate
//
// What this asserts, counting what the stores JOURNAL (a persist observer
// installed through `realms.setPersistObserver()`, which is exactly what
// `persistence_minted.js`'s `note()` is handed) and modelling the worst
// flush cadence — one flush per operation, which is postgres mode's: the
// flush delay is 0 and a request worker flushes at every commit
// announcement — so the rows a flush would write are the DISTINCT keys
// journalled during the operation:
//
//   1. once the identity register is past MAX_USERS, a person ANOTHER process
//      created costs this process NO minted row: neither a note in the
//      identity register, nor its eviction, nor `usersForgotten`;
//   2. once the RISC register is past its cap, an LDAP add made HERE costs at
//      most the audit event and the audit counter — no `risc.register` row
//      and no `admin_stats.users` row — so with the directory row the add is
//      at most three change rows; and ten adds in ONE flush write the audit
//      counter once (a counter row is per flush, never per event);
//   3. what readers rely on is still there: a person made through a DOOR
//      (`createUser()`) is still `knownBy: 'created'` in this process's
//      register; an account created DISABLED, a service account, and an
//      update of an account the register already holds still have their
//      RISC rows; a blank create leaves none;
//   4. the replicated person is not in this process's register at all (the
//      creating process's record reaches the users page through the fan-in,
//      and the directory side lists them since #610).
//
// In BOTH directory modes — a process holding the whole directory, where the
// change-log applier calls `applyEntry()`, and a windowed worker (#349),
// where it calls `forgetEntry()` — each in a child of its own, because a
// windowed worker needs its environment before the directory module is
// first required, and because the persist observer installed here must not
// outlive the scenario into the rest of the suite.
//
// WHY IN PROCESS: what a flush would write is visible to nothing outside the
// process, and the cadence that makes it expensive is a property of the
// store, not of a request.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'change_rows_per_add',
  level: process.env.LOG_LEVEL || 'info' });

const CHILD_FLAG = 'STS_TEST_CHANGE_ROWS_PER_ADD_CHILD';
// How many of each kind of create are MEASURED, after the warm-up that puts
// both capped registers past their caps.
const MEASURED = 100;
// The RISC register's cap for the scenario, so that a few dozen adds put it
// past the cap — the steady state of a directory larger than the cap.
const RISC_CAP = 20;
// The bounds asserted, in minted rows per create.
const REPLICATED_BOUND = 0;
const LOCAL_BOUND = 2;

function storeRow(dn, attributes) {
  log.debug("Entering storeRow().");
  log.debug("Leaving storeRow().");
  return { realm: 'default', dn_key: dn.toLowerCase(), dn: dn,
           attrs: attributes, origin: 'other process', created_at: '1',
           modified_at: '1' };
}

function entryOf(dn, attributes) {
  log.debug("Entering entryOf().");
  log.debug("Leaving entryOf().");
  return { dn: dn, attributes: attributes, origin: 'other process',
           createdAt: '20261014000000Z', modifiedAt: '20261014000000Z' };
}

function personAttributes(uid) {
  log.debug("Entering personAttributes().");
  log.debug("Leaving personAttributes().");
  return { objectclass: ['top', 'person', 'organizationalPerson',
                         'inetOrgPerson'],
           uid: [uid], cn: [uid], sn: [uid],
           mail: [uid + '@example.com'] };
}

// The scenario, in the child: `t` collects, the parent reports.
async function scenario(t) {
  log.debug("Entering scenario().");
  const config = require('../common/config');
  const realms = require('../common/realms');
  const stats = require('../common/admin_stats');
  const ldap = require('../ldap/ldap_server');
  const risc = require('../ssf/risc');
  const w = ldap.directoryWindow;
  const table = new Map();
  if (w) {
    w.attach(require('./directory_window').fakeBridge(table));
  }
  const mode = w ? '(window) ' : '(whole) ';
  const users = ldap.usersDn();
  config.setOverride('risc.maxAccountsTracked', String(RISC_CAP));
  // SSF's own installation, without the rest of SSF: the directory's
  // account observer is the RISC register's `observe()`.
  ldap.setAccountObserver(function (notice) {
    risc.observe(notice);
  });

  // What a flush would write: the distinct (handle, realm, key) journalled
  // since the last take.
  let journalled = new Set();
  realms.setPersistObserver(function (handle, realmId, key) {
    journalled.add(handle + '\n' + realmId + '\n' + String(key));
  });
  const take = function () {
    const out = {};
    journalled.forEach(function (one) {
      const handle = one.split('\n')[0];
      out[handle] = (out[handle] || 0) + 1;
    });
    journalled = new Set();
    return out;
  };
  // Runs `fn(i)` `n` times, a flush after each, and answers the rows each
  // handle cost per run.
  const measure = async function (n, fn) {
    const total = {};
    for (let i = 0; i < n; i++) {
      take();
      await fn(i);
      const rows = take();
      Object.keys(rows).forEach(function (handle) {
        total[handle] = (total[handle] || 0) + rows[handle];
      });
    }
    const per = { all: 0 };
    Object.keys(total).forEach(function (handle) {
      per[handle] = total[handle] / n;
      per.all += total[handle] / n;
    });
    return per;
  };
  // ANOTHER PROCESS's create, as this process's change-log applier hands it
  // over: a windowed key read and forgotten, anything else applied whole.
  const replicated = function (uid) {
    const dn = 'uid=' + uid + ',' + users;
    const key = dn.toLowerCase();
    const attributes = personAttributes(uid);
    if (w && w.isWindowed('default', key)) {
      table.set('default\n' + key, storeRow(dn, attributes));
      ldap.directoryHooks.forgetEntry('default', key,
                                      entryOf(dn, attributes), false);
    } else {
      ldap.directoryHooks.applyEntry('default', key,
                                     entryOf(dn, attributes));
    }
  };
  // An LDAP add made HERE, through the function a request worker runs —
  // asynchronous in a windowed worker, which asks the store (#621, #622).
  const added = async function (uid, extra) {
    const attributes = [{ type: 'objectClass',
                          values: ['top', 'person', 'organizationalPerson',
                                   'inetOrgPerson'] },
                        { type: 'uid', values: [uid] },
                        { type: 'cn', values: [uid] },
                        { type: 'sn', values: [uid] },
                        { type: 'mail', values: [uid + '@example.com'] }]
      .concat(extra || []);
    return await ldap.performOperation('add', {
      dn: 'uid=' + uid + ',' + users, boundDn: '', channel: 'ldaps',
      attributes: attributes });
  };

  // --- warm up: both capped registers past their caps --------------------
  for (let i = 0; i < stats.MAX_USERS + 10; i++) {
    replicated('crpa-warm-r' + i);
  }
  let refused = 0;
  for (let i = 0; i < RISC_CAP + 10; i++) {
    if ((await added('crpa-warm-l' + i)).ok === false) {
      refused++;
    }
  }
  t.equal(refused, 0, mode + '0. every warm-up LDAP add was accepted');

  // --- 1. a replicated create ---------------------------------------------
  const rep = await measure(MEASURED, function (i) {
    replicated('crpa-rep' + i);
  });
  t.check(rep.all <= REPLICATED_BOUND,
          mode + '1. a person ANOTHER process created costs this process ' +
          'at most ' + REPLICATED_BOUND + ' minted rows (no identity-' +
          'register note, no eviction, no usersForgotten)',
          JSON.stringify(rep));
  t.check(!rep['admin_stats.users'] && !rep['admin_stats.nums'],
          mode + '1b. in particular nothing in admin_stats.users or ' +
          'admin_stats.nums', JSON.stringify(rep));

  // --- 2. a local LDAP add ------------------------------------------------
  let localRefused = 0;
  const loc = await measure(MEASURED, async function (i) {
    if ((await added('crpa-loc' + i)).ok === false) {
      localRefused++;
    }
  });
  t.equal(localRefused, 0, mode + '2. every measured LDAP add was accepted');
  t.check(loc.all <= LOCAL_BOUND,
          mode + '2. an LDAP add made here costs at most ' + LOCAL_BOUND +
          ' minted rows (the audit event and its counter); with the ' +
          'directory row, at most ' + (LOCAL_BOUND + 1) + ' change rows',
          JSON.stringify(loc));
  t.check(!loc['risc.register'] && !loc['admin_stats.users'],
          mode + '2b. no risc.register row and no admin_stats.users row for ' +
          'a blank create', JSON.stringify(loc));
  t.check((loc['audit.events'] || 0) > 0,
          mode + '2c. and the add is still AUDITED: its audit event is ' +
          'journalled', JSON.stringify(loc));

  // --- 2d. counters are written once per flush, not once per event --------
  take();
  for (let i = 0; i < 10; i++) {
    await added('crpa-burst' + i);
  }
  const burst = take();
  t.check(burst['audit.nums'] === 1 && (burst['audit.events'] || 0) <= 2 &&
          !burst['risc.register'] && !burst['admin_stats.users'],
          mode + '2d. ten adds in ONE flush write the audit counter once and ' +
          'at most two audit segments: a counter row is per flush, never ' +
          'per event', JSON.stringify(burst));

  // --- 3. what readers rely on --------------------------------------------
  const doorMade = 'crpa-door';
  ldap.createUser(doorMade, { invent: false, origin: 'api' });
  const doorRow = stats.userRow(stats.identityKeyOf(doorMade));
  t.equal(doorRow && doorRow.knownBy, 'created',
          mode + '3a. a person made through a DOOR is still known here as ' +
          'created', JSON.stringify(doorRow && doorRow.knownBy));
  const lastLocal = 'crpa-loc' + (MEASURED - 1);
  t.equal(risc.get(lastLocal), null,
          mode + '3b. a BLANK create leaves no RISC row: nothing in it ' +
          'differs from what an absent row answers');
  t.equal(risc.optOutOf(lastLocal).state, 'opt-in',
          mode + '3b. and the portal still reads that account as opted in');
  const locked = await added('crpa-locked', [{ type: 'pwdAccountLockedTime',
                                         values: ['000001010000Z'] }]);
  t.check(locked.ok !== false && !!risc.get('crpa-locked'),
          mode + '3c. an account created DISABLED still has its RISC row ' +
          '(its account-disabled is due)', JSON.stringify({
            ok: locked.ok, error: locked.errorName || locked.error,
            row: !!risc.get('crpa-locked') }));
  const svcAfter = { uid: ['crpa-svc'], stsserviceaccount: ['TRUE'],
                     objectclass: ['inetOrgPerson', 'stsServiceAccount'] };
  risc.observe({ kind: 'created', username: 'crpa-svc',
    dn: 'uid=crpa-svc,' + users, realm: 'default', before: {},
    after: svcAfter });
  const svcRow = risc.get('crpa-svc');
  const isSvc = risc.serviceAccountIn(svcAfter);
  t.check(isSvc && !!svcRow && svcRow.serviceAccount === true,
          mode + '3d. a SERVICE ACCOUNT still has its row: the opt-out ' +
          'gate reads that fact off it',
          JSON.stringify({ isSvc: isSvc,
                           row: svcRow && svcRow.serviceAccount }));
  const held = risc.rowFor('crpa-held', { iss: 'https://sts.example.com' });
  t.check(!!held, mode + '3e. a row made for an account is held');
  take();
  risc.observe({ kind: 'updated', username: 'crpa-held',
    dn: 'uid=crpa-held,' + users, realm: 'default',
    before: { uid: ['crpa-held'] },
    after: { uid: ['crpa-held'], title: ['Foreman'] } });
  const heldRows = take();
  t.check(!!risc.get('crpa-held') && heldRows['risc.register'] === 1,
          mode + '3e. an update of an account the register HOLDS still ' +
          'rewrites its row', JSON.stringify(heldRows));

  // --- 4. the replicated person is not in this process's register --------
  const repKey = stats.identityKeyOf('crpa-rep0');
  t.check(!stats.userKeys().has(repKey),
          mode + '4. a person another process created is NOT in this ' +
          'process\'s identity register — the creator\'s record reaches ' +
          'the page through the fan-in', repKey);
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
    await scenario(t);
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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-crpa-'));
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
      timeout: 300000 });
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
  t.check(result.seen.length >= 16, 'every assertion of the child ran',
          String(result.seen.length));
  log.debug("Leaving inChild().");
}

function run(t) {
  log.debug("Entering run().");
  t.log.info('=== a process holding the whole directory ===');
  inChild(t, false);
  t.log.info('=== a windowed worker (#349) ===');
  inChild(t, true);
  log.debug("Leaving run().");
}

if (require.main === module && process.env[CHILD_FLAG] === '1') {
  childMain();
}

module.exports = {
  name: 'change_rows_per_add',
  describe: 'one directory add costs the change log at most the audit ' +
            'event and its counter beside the directory row, and a person ' +
            'another process created costs nothing, whole and windowed ' +
            '(#618 phase 2)',
  run: run
};
