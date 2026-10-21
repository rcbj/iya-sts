// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: windowed_entryuuid.js
//
// ===========================================================================
// A WINDOWED PERSON'S SUBJECT RESOLVES TO THE ENTRY THE WINDOW HOLDS,
// WITHOUT ASKING THE STORE AGAIN (#773).
//
// In a windowed process `entryByUuid()` asked the store (`byUuid`) every
// time, and a sign-in asks it three times for the same person. The key the
// store answered with is kept, and used while the entry the window holds at
// that key still carries the UUID as its own.
//
//   W1. the second lookup of a person asks the store nothing, and answers
//       the same entry;
//   W2. an entry the window has dropped is asked of the store again;
//   W3. an entry at that key that no longer carries the UUID is a miss, and
//       the store's answer wins;
//   W4. a UUID held only as an ALIAS is asked of the store every time.
//
// In a child holding the directory as a windowed request worker over a
// stand-in bridge that counts what it is asked.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'windowed_entryuuid',
  level: process.env.LOG_LEVEL || 'info' });

const CHILD_FLAG = 'STS_TEST_WINDOWED_ENTRYUUID_CHILD';

function inTheWorker(t) {
  log.debug('Entering inTheWorker().');
  const shared = require('./directory_window');
  const ldap = require('../ldap/ldap_server');
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
  for (let i = 0; i < 20; i++) {
    const uid = 'weu' + String(i).padStart(3, '0');
    const uuid = crypto.randomUUID();
    const dn = 'uid=' + uid + ',' + users;
    rows.set('default\n' + dn.toLowerCase(), shared.row('default', dn,
      { uid: [uid], objectclass: ['inetOrgPerson'], cn: ['P ' + i],
        entryuuid: [uuid] }));
    people.push({ uid: uid, uuid: uuid, key: dn.toLowerCase() });
  }
  const alias = crypto.randomUUID();
  rows.get('default\n' + people[5].key).attrs.stsentryuuidalias = [alias];
  w.residentRows('default').forEach(function (one) {
    rows.set('default\n' + one.key, { realm: 'default', dn_key: one.key,
      dn: one.entry.dn, attrs: one.entry.attributes, origin: null,
      created_at: '1', modified_at: '1' });
  });
  const bridge = shared.fakeBridge(rows);
  w.attach(bridge);
  const asked = function () {
    return bridge.asked.filter(function (n) {
      return n === 'byUuid';
    }).length;
  };
  const inRealm = function (fn) {
    return realms.run(realms.get(realms.DEFAULT_ID), fn);
  };

  const p = people[3];
  const first = inRealm(function () {
    return ldap.entryByUuid('urn:uuid:' + p.uuid);
  });
  const afterFirst = asked();
  const second = inRealm(function () {
    return ldap.entryByUuid('urn:uuid:' + p.uuid);
  });
  const third = inRealm(function () {
    return ldap.entryByUuid(p.uuid.toUpperCase());
  });
  t.check(first && second && third && afterFirst === 1 && asked() === 1 &&
          second.dn === first.dn && third.dn === first.dn,
          'W1. the second and third lookups ask the store nothing and ' +
          'answer the same entry', JSON.stringify({ asked: asked(),
            dn: first && first.dn }));

  w.forget('default', p.key);
  const dropped = inRealm(function () {
    return ldap.entryByUuid('urn:uuid:' + p.uuid);
  });
  t.check(dropped && dropped.dn === first.dn && asked() === 2,
          'W2. once the window has dropped the entry, the store is asked ' +
          'again', String(asked()));

  // The key now holds an entry that does not carry this UUID; the store
  // has the UUID at another person's key (a value moved).
  const q = people[4];
  inRealm(function () {
    return ldap.entryByUuid('urn:uuid:' + q.uuid);
  });
  const before = asked();
  const moved = crypto.randomUUID();
  const held = w.peekIn('default', q.key);
  held.attributes.entryuuid = [moved];
  const missed = inRealm(function () {
    return ldap.entryByUuid('urn:uuid:' + q.uuid);
  });
  t.check(asked() === before + 1,
          'W3. an entry at that key that no longer carries the UUID is a ' +
          'miss, and the store is asked', JSON.stringify({ asked: asked(),
            got: missed && missed.dn }));

  const a1 = asked();
  inRealm(function () {
    return ldap.entryByUuid('urn:uuid:' + alias);
  });
  inRealm(function () {
    return ldap.entryByUuid('urn:uuid:' + alias);
  });
  t.check(asked() === a1 + 2,
          'W4. a UUID held only as an alias is asked of the store every ' +
          'time', String(asked() - a1));
  log.debug('Leaving inTheWorker().');
}

function childMain() {
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
    inTheWorker(t);
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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-weu-'));
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
  t.check(result.seen.length >= 5, 'every assertion of the windowed child ' +
          'ran', String(result.seen.length));
  log.debug('Leaving run().');
}

if (require.main === module && process.env[CHILD_FLAG] === '1') {
  childMain();
}

module.exports = {
  name: 'windowed_entryuuid',
  describe: 'a windowed person\'s subject resolves to the entry the window ' +
            'holds without asking the store again (#773)',
  run: run
};
