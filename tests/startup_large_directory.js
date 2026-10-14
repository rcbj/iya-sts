// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: startup_large_directory.js
//
// ===========================================================================
// A START WITH A LARGE DIRECTORY (#613, 2026-10-13).
//
// On 8081 (131,546 people, product, postgres, front + 2 workers) every process
// held its event loop 14–18 s at start, filling `admin_stats.js`'s identity
// register with every restored person — through the synchronous bridge in a
// windowed process — and then flushed ~131K journalled writes and deletes of
// that minted register into the store and the change log. The heartbeat ran
// 15 s late (STS-CLUSTER-0025) and an origin-claim renewal took 22.5 s of a
// 30 s claim (STS-STORE-0069); a larger directory would cost the node its
// membership. This holds the fix in process, in a child per configuration:
//
//   A. WINDOWED (`ldap.workerDirectory=postgres-lru`, the configuration 8081
//      ran): a store of PEOPLE people behind a synchronous stand-in bridge,
//      the resident entries restored through `replaceRealm()` —
//        A1  the restore holds the event loop less than BOUND_MS;
//        A2  it reads NO person from the store (no name page, no entry);
//        A3  the identity register holds nobody it did not observe, and
//        A4  is the same size with SMALL people as with PEOPLE.
//   B. THE WHOLE DIRECTORY (memory): `replaceRealm()` is handed every entry,
//      which is linear by construction — the directory IS the data there —
//      and the register does not grow with it (B1, B2).
//   C. THE MINTED RESTORE yields: MINTED sealed rows restored with the event
//      loop never held longer than BOUND_MS (C1), every row restored (C2).
//
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const nodeCrypto = require('crypto');

const log = require('bunyan').createLogger({ name: 'startup_large_directory',
  level: process.env.LOG_LEVEL || 'info' });

const CHILD_FLAG = 'STS_TEST_STARTUP_LARGE_CHILD';
// Tens of thousands, as the issue asks, and small enough for the in-process
// suite: the windowed child never reads them, and the whole-directory child
// holds them as entries (about a second to build).
const PEOPLE = 40000;
const SMALL = 400;
const MINTED = 40000;
// The longest the event loop may be held by any one step measured here. The
// pass this test exists for held it 14–18 s on 8081, and a few hundred ms
// at this test's size; nothing left in these steps should come near it.
const BOUND_MS = 250;

// The longest the event loop was held while `work` ran: a 5 ms timer's worst
// lateness, and the whole of a `work` that never let it run.
async function heldWhile(work) {
  log.debug("Entering heldWhile().");
  const now = function () {
    return Number(process.hrtime.bigint() / 1000000n);
  };
  let worst = 0;
  let last = now();
  const timer = setInterval(function () {
    const at = now();
    worst = Math.max(worst, at - last - 5);
    last = at;
  }, 5);
  let result;
  try {
    result = await work();
  } finally {
    clearInterval(timer);
  }
  worst = Math.max(worst, now() - last - 5);
  log.debug("Leaving heldWhile().");
  return { result: result, heldMs: Math.max(0, worst) };
}

// A sorted table and the questions the window asks of it, counting the rows
// it hands out under `ou=users` — the store reads this test forbids.
function tableBridge(rows, usersBase) {
  log.debug("Entering tableBridge().");
  const queries = require('../persistence/directory_queries');
  const sorted = rows.slice().sort(function (a, b) {
    return a.dn_key < b.dn_key ? -1 : (a.dn_key > b.dn_key ? 1 : 0);
  });
  const under = function (key, base) {
    return key.length > base.length + 1 && key.endsWith(',' + base);
  };
  const bridge = { asked: [], peopleRead: 0 };
  const handed = function (list) {
    list.forEach(function (r) {
      if (under(r.dn_key, usersBase)) {
        bridge.peopleRead++;
      }
    });
    return list;
  };
  bridge.query = function (name, args) {
    bridge.asked.push(name);
    if (name === 'byKeys') {
      return handed(sorted.filter(function (r) {
        return args[1].indexOf(r.dn_key) >= 0;
      })).map(queries.rowOf);
    }
    if (name === 'page') {
      return handed(sorted.filter(function (r) {
        return under(r.dn_key, args[1]) && r.dn_key > args[2];
      }).slice(0, args[3])).map(queries.rowOf);
    }
    if (name === 'namesUnder') {
      return handed(sorted.filter(function (r) {
        return under(r.dn_key, args[1]) && r.dn_key > args[2];
      }).slice(0, args[3])).map(function (r) {
        return { key: r.dn_key, dn: r.dn, origin: r.origin || '',
                 uid: String((r.attrs.uid || [])[0] || '') };
      });
    }
    if (name === 'count') {
      return sorted.filter(function (r) {
        return !args[1] || under(r.dn_key, args[1]);
      }).length;
    }
    if (name === 'hasChild') {
      return sorted.some(function (r) {
        return under(r.dn_key, args[1]);
      });
    }
    if (name === 'anyWithAttribute') {
      return false;
    }
    // Any other question is answered with nothing; this test asserts what
    // was asked, not the answers.
    return [];
  };
  log.debug("Leaving tableBridge().");
  return bridge;
}

// The directory of `n` people under `base`, as restore rows.
function directoryOf(base, n) {
  log.debug("Entering directoryOf().");
  const users = 'ou=users,' + base;
  const e = function (dn, origin, attributes) {
    return { dn: dn, origin: origin, createdAt: '20261013000000Z',
             modifiedAt: '20261013000000Z', attributes: attributes };
  };
  const out = [
    e(base, 'seed', { objectclass: ['top', 'domain'] }),
    e(users, 'seed', { objectclass: ['organizationalUnit'], ou: ['users'] }),
    e('ou=groups,' + base, 'seed', { objectclass: ['organizationalUnit'],
                                     ou: ['groups'] }),
    e('ou=devices,' + base, 'seed', { objectclass: ['organizationalUnit'],
                                      ou: ['devices'] })
  ];
  for (let i = 0; i < n; i++) {
    const uid = 'p' + String(i).padStart(6, '0');
    out.push(e('uid=' + uid + ',' + users, 'scim',
               { objectclass: ['inetOrgPerson'], uid: [uid],
                 cn: ['Person ' + i], sn: ['P'],
                 mail: [uid + '@example.com'] }));
  }
  log.debug("Leaving directoryOf().");
  return out;
}

// One configuration, `n` people: the directory restored, what it cost and
// what the register holds after it.
async function restoreDirectory(n, windowed) {
  log.debug("Entering restoreDirectory().");
  const ldap = require('../ldap/ldap_server');
  const stats = require('../common/admin_stats');
  const base = ldap.baseDn().toLowerCase();
  const rows = directoryOf(base, n);
  const w = ldap.directoryWindow;
  let restored = rows;
  let bridge = null;
  if (windowed) {
    if (!w) {
      throw new Error('the child was asked for a window and holds none');
    }
    bridge = tableBridge(rows.map(function (one) {
      return { realm: 'default', dn_key: one.dn.toLowerCase(), dn: one.dn,
               attrs: one.attributes, origin: one.origin,
               created_at: one.createdAt, modified_at: one.modifiedAt };
    }), 'ou=users,' + base);
    w.attach(bridge);
    // What the residentOnly restore hands over: nothing under the windowed
    // containers.
    restored = rows.filter(function (one) {
      return !w.isWindowed('default', one.dn.toLowerCase());
    });
  }
  const before = stats.userRows().length;
  const held = await heldWhile(function () {
    ldap.directoryHooks.replaceRealm('default', restored);
    return null;
  });
  const register = stats.userRows();
  log.debug("Leaving restoreDirectory().");
  return {
    n: n, windowed: !!w, handed: restored.length, heldMs: held.heldMs,
    registerBefore: before, register: register.length,
    restoredMarks: register.filter(function (row) {
      return row.knownBy === 'restored';
    }).length,
    peopleRead: bridge ? bridge.peopleRead : -1,
    asked: bridge ? Array.from(new Set(bridge.asked)) : []
  };
}

// MINTED sealed rows of one store, restored as a worker's start does it.
async function restoreMinted(count) {
  log.debug("Entering restoreMinted().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-start-'));
  const kekFile = path.join(dir, 'kek');
  fs.writeFileSync(kekFile, nodeCrypto.randomBytes(32).toString('base64'),
                   { encoding: 'utf8', mode: 0o600 });
  process.env.STS_KEYS_SOURCE = 'persisted';
  process.env.STS_KEYS_KEK_PROVIDER = 'file';
  process.env.STS_KEYS_KEK_FILE = kekFile;
  const config = require('../common/config');
  const realms = require('../common/realms');
  const keystore = require('../common/keystore');
  const minted = require('../persistence/persistence_minted');
  keystore.reset();
  keystore.setStore({
    loadKeys: function () {
      log.debug("Entering loadKeys().");
      log.debug("Leaving loadKeys().");
      return Promise.resolve([]);
    },
    saveKeys: function () {
      log.debug("Entering saveKeys().");
      log.debug("Leaving saveKeys().");
      return Promise.resolve();
    },
    deleteKeys: function () {
      log.debug("Entering deleteKeys().");
      log.debug("Leaving deleteKeys().");
      return Promise.resolve();
    }
  });
  await keystore.start();
  config.setOverride('global.mode', 'product');
  config.setOverride('persistence.minted', true);
  const kept = new Map();
  const driver = {
    origin: function () {
      log.debug("Entering origin().");
      log.debug("Leaving origin().");
      return 'startup-test';
    },
    loadMinted: function () {
      log.debug("Entering loadMinted().");
      log.debug("Leaving loadMinted().");
      return Promise.resolve(Array.from(kept.values()));
    },
    purgeExpiredMinted: function () {
      log.debug("Entering purgeExpiredMinted().");
      log.debug("Leaving purgeExpiredMinted().");
      return Promise.resolve(0);
    },
    saveMinted: function (upserts, deletes) {
      log.debug("Entering saveMinted().");
      upserts.forEach(function (row) {
        kept.set(row.handle + '\u0000' + row.realm + '\u0000' + row.key,
                 { handle: row.handle, realm: row.realm, key: row.key,
                   keySealed: row.keySealed || '', body: row.body,
                   writtenAt: Date.now(), expiresAt: null });
      });
      deletes.forEach(function (row) {
        kept.delete(row.handle + '\u0000' + row.realm + '\u0000' + row.key);
      });
      log.debug("Leaving saveMinted().");
      return Promise.resolve();
    },
    readMinted: function () {
      log.debug("Entering readMinted().");
      log.debug("Leaving readMinted().");
      return Promise.resolve(null);
    },
    purgeMinted: function () {
      log.debug("Entering purgeMinted().");
      log.debug("Leaving purgeMinted().");
      return Promise.resolve(0);
    }
  };
  minted.reset();
  minted.setDriver(driver, 'postgres');
  const store = realms.map({ persist: 'test.startup-rows' });
  for (let i = 0; i < count; i++) {
    store.set('row-' + i, { n: i, who: 'p' + (i % 1000) });
  }
  await minted.flush();
  store.clear();
  const held = await heldWhile(function () {
    return minted.restore();
  });
  fs.rmSync(dir, { recursive: true, force: true });
  log.debug("Leaving restoreMinted().");
  return { stored: kept.size, restored: (held.result || {}).restored,
           live: store.size, heldMs: held.heldMs };
}

async function childMain() {
  log.debug("Entering childMain().");
  let answers = null;
  let threw = '';
  try {
    const part = process.env.SL_PART;
    if (part === 'minted') {
      answers = await restoreMinted(Number(process.env.SL_N));
    } else {
      answers = await restoreDirectory(Number(process.env.SL_N),
                                       part === 'windowed');
    }
  } catch (e) {
    log.debug("Caught in childMain(): " + ((e && e.message) || e));
    threw = (e && e.stack) || String(e);
  }
  fs.writeFileSync(process.env.PROBE_OUT,
                   JSON.stringify({ answers: answers, threw: threw }));
  log.debug("Leaving childMain().");
  process.exit(0);
}

function inChild(t, part, n) {
  log.debug("Entering inChild().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-start-'));
  const outFile = path.join(dir, 'out.json');
  const env = Object.assign({}, process.env, { PROBE_OUT: outFile,
                                               LOG_LEVEL: 'fatal',
                                               SL_PART: part,
                                               SL_N: String(n) });
  env[CHILD_FLAG] = '1';
  delete env.CONFIG_FILE;
  delete env.LDAP_WORKER_DIRECTORY;
  delete env.STS_REQUEST_WORKER;
  if (part === 'windowed') {
    env.STS_REQUEST_WORKER = '1';
    env.LDAP_WORKER_DIRECTORY = 'postgres-lru';
    env.STS_PERSISTENCE_MODE = 'postgres';
    env.LDAP_WORKER_CACHE_ENTRIES = '1000';
  }
  const child = childProcess.spawnSync(process.execPath, [__filename],
    { cwd: path.join(__dirname, '..'), env: env, encoding: 'utf8',
      timeout: 180000 });
  let result = null;
  try {
    const read = JSON.parse(fs.readFileSync(outFile, 'utf8'));
    if (read.threw) {
      t.check(false, 'the ' + part + ' child threw', read.threw);
    }
    result = read.answers;
  } catch (e) {
    log.debug("Caught in inChild(): " + ((e && e.message) || e));
    t.check(false, 'the ' + part + ' child reported nothing', 'status ' +
            child.status + ': ' + String(child.stderr || '').slice(-2000));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  log.debug("Leaving inChild().");
  return result;
}

async function run(t) {
  log.debug("Entering run().");
  t.log.info('=== A. a windowed process restores ' + PEOPLE + ' people ===');
  const big = inChild(t, 'windowed', PEOPLE);
  const small = inChild(t, 'windowed', SMALL);
  if (big && small) {
    t.check(big.windowed, 'A0. the child holds a window onto the store');
    t.check(big.heldMs < BOUND_MS,
            'A1. the restore held the event loop less than ' + BOUND_MS +
            ' ms with ' + PEOPLE + ' people in the store',
            big.heldMs + ' ms');
    t.equal(big.peopleRead, 0,
            'A2. AND READ NO PERSON FROM THE STORE — no page of names, no ' +
            'entry — so its cost cannot grow with the directory',
            'asked: ' + JSON.stringify(big.asked));
    t.check(big.register === big.registerBefore && big.restoredMarks === 0,
            'A3. the identity register holds nobody the restore put there: ' +
            'no row is marked restored', JSON.stringify(big));
    t.equal(big.register, small.register,
            'A4. and it is the same size with ' + SMALL + ' people as with ' +
            PEOPLE);
  }

  t.log.info('=== B. the whole directory, in memory ===');
  const whole = inChild(t, 'whole', PEOPLE);
  const wholeSmall = inChild(t, 'whole', SMALL);
  if (whole && wholeSmall) {
    t.check(!whole.windowed && whole.handed > PEOPLE,
            'B0. the child holds the whole directory and was handed every ' +
            'entry', JSON.stringify({ handed: whole.handed }));
    t.check(whole.register === wholeSmall.register &&
            whole.restoredMarks === 0,
            'B1. the identity register does not grow with the directory ' +
            'restored into it', JSON.stringify({ big: whole.register,
                                                 small: wholeSmall.register }));
    t.log.info('B2. (reported, not asserted) restoring ' + PEOPLE +
               ' entries into memory held the loop ' + whole.heldMs +
               ' ms — the directory IS the data in this configuration');
  }

  t.log.info('=== C. the minted restore of ' + MINTED + ' rows ===');
  const minted = inChild(t, 'minted', MINTED);
  if (minted) {
    t.check(minted.heldMs < BOUND_MS,
            'C1. restoring ' + MINTED + ' sealed rows never held the event ' +
            'loop ' + BOUND_MS + ' ms', minted.heldMs + ' ms');
    t.check(minted.stored === MINTED && minted.restored === MINTED &&
            minted.live === MINTED,
            'C2. and every row was restored', JSON.stringify(minted));
  }
  log.debug("Leaving run().");
}

if (process.env[CHILD_FLAG]) {
  childMain();
} else {
  module.exports = { run: run };
}
