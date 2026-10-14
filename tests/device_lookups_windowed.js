// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: device_lookups_windowed.js
//
// ===========================================================================
// A PERSON'S PAGE AND A DEVICE'S RECOGNITION ASK THE STORE, AND NEVER WALK
// `ou=devices` (#636).
//
// Found on the local stack at about 6.4M people, the directory a window
// onto postgres:
//
//   1. `GET /admin-api/users?user=<name>` — the console's page of one
//      person — answered 503: `devices.listForOwner()` read EVERY device
//      (`all()`, the directory's `listDeviceEntries()`), which a windowed
//      process pages through the synchronous bridge, and a `page()` under
//      `ou=devices` is a suffix comparison no index narrows, so its last
//      page reads the realm's keys past the last device — the whole
//      directory. The bridge's 2 s limit cut it off (STS-LDAP-0130).
//   2. Recognising a device on a token request (STS-DEVICE-0029) built the
//      directory's device index from the same walk, once per write under
//      `ou=devices` anywhere — and a recognition is such a write.
//
// Both now ask one indexed question: the device's DN for its id, and
// `byAttribute` under `ou=devices` for a key thumbprint, a secret's hash, a
// WebAuthn credential id or an owner — which `value_keys` holds since #636.
// This file holds that by COUNTING what a stand-in bridge is asked, never by
// timing anything:
//
//   A. THE STORE'S HALF, in this process: the codec keys the four device
//      attributes into `value_keys` and a lookup keyed the same way finds
//      them; it refuses a `byAttribute` for an attribute it does not index
//      (it would answer "nobody"); `byAttribute` narrowed to a parent asks
//      `parent_key`.
//   B. THE PERSON PAGE, in a child loading the directory as a windowed
//      request worker: `usersJsonAsync()` for one person asks no page, no
//      holder question and no key listing, and lists exactly that person's
//      devices — not a group that names them its owner.
//   C. RECOGNITION: by id, key thumbprint, secret, WebAuthn credential and
//      owner, each found (or a miss answered "none") with no page and at
//      most a few rows read, the same with ten times the people.
//   D. A DEVICE WRITTEN HERE AND NOT YET FLUSHED is found by its key and
//      listed for its owner (the window's own changes are added).
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'device_lookups_windowed',
  level: process.env.LOG_LEVEL || 'info' });

const CHILD_FLAG = 'STS_TEST_DEVICE_LOOKUPS_WINDOWED_CHILD';

// The questions that read a container rather than an index: none may be
// asked synchronously by these paths.
const WALKING = ['page', 'namesUnder', 'keysUnder', 'withAttribute',
                 'realmPage'];

// --- A. the store's half ----------------------------------------------------

function storeHalf(t) {
  log.debug('Entering storeHalf().');
  t.log.info('=== A. the store\'s half ===');
  const codec = require('../persistence/directory_codec');
  const queries = require('../persistence/directory_queries');
  const attrs = { cn: ['d1'], owner: ['uid=alice,ou=users,dc=x'],
                  stsdevicekeythumbprint: ['jwk:AbC'],
                  stsdevicesecrethash: ['h4sh'],
                  stsdevicecredentialid: ['cr3d'] };
  const index = codec.indexOf(attrs);
  const asked = [['owner', 'uid=alice,ou=users,dc=x'],
                 ['stsDeviceKeyThumbprint', 'jwk:AbC'],
                 ['stsdevicesecrethash', 'h4sh'],
                 ['stsDeviceCredentialId', 'cr3d']].map(function (one) {
    return codec.keyArgs('byAttribute', ['default', one[0], one[1]])[2].key;
  });
  t.check(asked.every(function (key) {
    return index.valueKeys.indexOf(key) >= 0;
  }), 'A1. a device\'s owner, key thumbprint, secret hash and WebAuthn ' +
      'credential id are in value_keys, keyed as a lookup keys them',
          JSON.stringify(index.valueKeys));
  const other = codec.keyArgs('byAttribute', ['default', 'owner',
                                              'uid=bob,ou=users,dc=x'])[2];
  t.check(index.valueKeys.indexOf(other.key) < 0,
          'A2. and another owner\'s lookup does not find them');
  let refused = '';
  try {
    codec.keyArgs('byAttribute', ['default', 'description', 'x']);
  } catch (e) {
    log.debug('Caught in storeHalf(): ' + ((e && e.message) || e));
    refused = String((e && e.message) || e);
  }
  t.check(/not description/.test(refused),
          'A3. byAttribute for an attribute value_keys does not hold is ' +
          'refused, not answered "nobody"', refused);
  const plain = queries.byAttribute('default', 'owner', 'x', 5);
  const under = queries.byAttribute('default', 'owner', 'x', 5,
                                    'ou=devices,dc=x');
  t.check(!/parent_key/.test(plain.text) && plain.values.length === 3 &&
          /parent_key = \$4 AND value_keys @> \$2::jsonb/.test(under.text) &&
          under.values[3] === 'ou=devices,dc=x' && under.values[2] === 5,
          'A4. byAttribute under a parent asks parent_key beside value_keys, ' +
          'and without one is as it was', under.text);
  log.debug('Leaving storeHalf().');
}

// --- B–D: in a child, the directory as a windowed request worker -----------

// A stand-in bridge over `rows`, counting every question by name and door
// and every row answered.
function countingBridge(rows) {
  log.debug('Entering countingBridge().');
  const shared = require('./directory_window');
  const base = shared.fakeBridge(rows);
  const counts = { sync: {}, async: {}, rows: 0 };
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
      return tally(counts.sync, name, base.query(name, args));
    },
    queryAsync: function (name, args) {
      return Promise.resolve(tally(counts.async, name,
                                   base.query(name, args)));
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

// How many walking questions were asked synchronously.
function walked(counts) {
  log.debug('Entering walked().');
  const n = WALKING.reduce(function (sum, name) {
    return sum + (counts.sync[name] || 0);
  }, 0);
  log.debug('Leaving walked().');
  return n;
}

// Hot path (thousands of rows): no Entering/Leaving pair, the exception the
// code style allows.
function uid(i) {
  return 'p' + String(i).padStart(6, '0');
}

function secretHash(secret) {
  log.debug('Entering secretHash().');
  log.debug('Leaving secretHash().');
  return crypto.createHash('sha256').update(String(secret))
    .digest('base64url');
}

function deviceId(i) {
  log.debug('Entering deviceId().');
  log.debug('Leaving deviceId().');
  return '00000000-0000-4000-8000-d' + String(i).padStart(11, '0');
}

// The table: `people` people, a device each for the first twenty (two for
// p000001, the second a WebAuthn one), and a service account and a GROUP
// p000001 owns.
function table(users, people) {
  log.debug('Entering table().');
  const shared = require('./directory_window');
  const devices = users.replace(/^ou=users,/, 'ou=devices,');
  const groups = users.replace(/^ou=users,/, 'ou=groups,');
  const rows = new Map();
  const put = function (dn, attrs) {
    rows.set('default\n' + dn.toLowerCase(), shared.row('default', dn,
                                                          attrs));
  };
  for (let i = 0; i < people; i++) {
    put('uid=' + uid(i) + ',' + users, { uid: [uid(i)],
      objectclass: ['inetOrgPerson'], cn: ['P ' + i], sn: ['P'] });
  }
  const device = function (n, owner, key) {
    put('cn=' + deviceId(n) + ',' + devices, {
      objectclass: ['device', 'stsDevice'], cn: [deviceId(n)],
      owner: ['uid=' + owner + ',' + users],
      stsdevicekey: [JSON.stringify(key)],
      stsdevicekeythumbprint: [key.kind + ':' + key.thumbprint],
      stsdevicesecrethash: [secretHash('secret-' + n)],
      stsdevicecredentialid: key.material ? [key.material.credentialId] : [],
      stsdevicelastused: ['2026-10-1' + (n % 10) + 'T00:00:00Z']
    });
  };
  for (let n = 0; n < 20; n++) {
    device(n, uid(n), { id: 'k' + n, kind: 'jwk', thumbprint: 'T' + n });
  }
  device(20, uid(1), { id: 'w20', kind: 'webauthn', thumbprint: 'W20',
                       material: { credentialId: 'cred-20' } });
  // A SERVICE ACCOUNT p000001 owns: a person under ou=users, windowed like
  // a device, whose `owner` is the same DN.
  put('uid=svc-p1,' + users, { uid: ['svc-p1'],
    objectclass: ['inetOrgPerson'], cn: ['svc'], sn: ['svc'],
    owner: ['uid=' + uid(1) + ',' + users] });
  put('cn=p1-team,' + groups, { cn: ['p1-team'],
    objectclass: ['groupOfNames'], owner: ['uid=' + uid(1) + ',' + users],
    member: ['uid=' + uid(1) + ',' + users] });
  log.debug('Leaving table().');
  return { rows: rows, devices: devices };
}

async function personPage(t, ctx) {
  log.debug('Entering personPage().');
  const bridge = ctx.bridge;
  bridge.reset();
  const json = await ctx.adminViews.usersJsonAsync({
    query: { user: uid(1) }, headers: {}, protocol: 'http',
    get: function () {
      return '';
    } }, null);
  const shown = (((json.page || {}).mfa || {}).devices || {}).devices || [];
  const ids = shown.map(function (one) {
    return one.id;
  }).sort();
  t.check(json.known === true &&
          JSON.stringify(ids) === JSON.stringify([deviceId(1),
                                                  deviceId(20)].sort()),
          'B1. the person page lists exactly the person\'s two devices — ' +
          'not the service account or the group that names them its owner',
          JSON.stringify(ids));
  t.check(walked(bridge.counts) === 0,
          'B2. ASKED, NOT WALKED: no page, holder question or key listing ' +
          'is asked synchronously for one person', JSON.stringify(
            bridge.counts));
  t.check((bridge.counts.sync.byAttribute || 0) >= 1 &&
          bridge.counts.rows < 40,
          'B3. the devices are one byAttribute under ou=devices, and the ' +
          'page reads a few dozen rows at most of ' + ctx.rows.size,
          JSON.stringify(bridge.counts));
  log.debug('Leaving personPage().');
}

async function recognition(t, ctx, label) {
  log.debug('Entering recognition(). ' + label);
  const devices = ctx.devices;
  const bridge = ctx.bridge;
  bridge.reset();
  const byKey = devices.byKeyThumbprint('T5', 'jwk');
  const bySecret = devices.bySecret('secret-7');
  const byCredential = devices.byCredentialId('cred-20');
  const byId = devices.byId(deviceId(9));
  const owns = devices.holdsAny(uid(3));
  const ownsNone = devices.holdsAny(uid(150));
  const miss = devices.byKeyThumbprint('nobody-holds-this', 'jwk');
  t.check(!!byKey && byKey.id === deviceId(5) &&
          !!bySecret && bySecret.id === deviceId(7) &&
          !!byCredential && byCredential.id === deviceId(20) &&
          !!byId && byId.id === deviceId(9) && owns === true &&
          ownsNone === false && miss === null,
          label + '1. each lookup finds its device — key, secret, WebAuthn ' +
          'credential, id, owner — and a key nobody holds is nobody',
          JSON.stringify([byKey && byKey.id, bySecret && bySecret.id,
                          byCredential && byCredential.id, byId && byId.id,
                          owns, ownsNone, miss]));
  t.check(walked(bridge.counts) === 0,
          label + '2. NO INDEX IS BUILT: recognition asks no page of ' +
          'ou=devices', JSON.stringify(bridge.counts));
  t.check((bridge.counts.sync.byAttribute || 0) === 6 &&
          bridge.counts.rows <= 12,
          label + '3. one byAttribute per lookup (the id is a key read), a ' +
          'row or so each, of ' + ctx.rows.size + ' entries',
          JSON.stringify(bridge.counts));
  log.debug('Leaving recognition().');
}

function unflushed(t, ctx) {
  log.debug('Entering unflushed().');
  const credentials = ctx.credentials;
  const users = ctx.users;
  const id = deviceId(99);
  const wrote = credentials.deviceStore('writeDeviceEntry', [id, {
    objectclass: ['device', 'stsDevice'], cn: [id],
    owner: ['uid=' + uid(2) + ',' + users],
    stsdevicekey: [JSON.stringify({ id: 'k99', kind: 'jwk',
                                    thumbprint: 'T99' })],
    stsdevicekeythumbprint: ['jwk:T99'] }]);
  ctx.bridge.reset();
  const found = ctx.devices.byKeyThumbprint('T99', 'jwk');
  const listed = ctx.devices.listFor(uid(2)).map(function (one) {
    return one.id;
  }).sort();
  t.check(wrote === true && !!found && found.id === id &&
          JSON.stringify(listed) === JSON.stringify([deviceId(2), id].sort()),
          'D1. a device written here and not yet flushed is found by its ' +
          'key and listed for its owner', JSON.stringify({ wrote: wrote,
            found: found && found.id, listed: listed }));
  t.check(walked(ctx.bridge.counts) === 0,
          'D2. and nothing was walked to find it',
          JSON.stringify(ctx.bridge.counts));
  log.debug('Leaving unflushed().');
}

async function throughTheDirectory(t) {
  log.debug('Entering throughTheDirectory().');
  const app = require('../common/app');
  const ldap = require('../ldap/ldap_server');
  const credentials = require('../common/credentials');
  const devices = require('../common/devices');
  require('../admin-ui/admin').registerRoutes(app);
  const adminViews = require('../admin-core/admin_views');
  const w = ldap.directoryWindow;
  t.check(!!w, 'B0. the directory is a window onto the store');
  if (!w) {
    log.debug('Leaving throughTheDirectory(). No window.');
    return;
  }
  const users = ldap.usersDn();
  const built = table(users.toLowerCase(), 300);
  // The store holds the resident entries too, as postgres does.
  w.residentRows('default').forEach(function (one) {
    built.rows.set('default\n' + one.key, { realm: 'default',
      dn_key: one.key, dn: one.entry.dn, attrs: one.entry.attributes,
      origin: one.entry.origin || null, created_at: '1', modified_at: '1' });
  });
  const bridge = countingBridge(built.rows);
  w.attach(bridge);
  const ctx = { bridge: bridge, rows: built.rows, devices: devices,
                credentials: credentials, adminViews: adminViews,
                users: users.toLowerCase() };
  t.log.info('=== B. the person page ===');
  await personPage(t, ctx);
  t.log.info('=== C. recognition ===');
  await recognition(t, ctx, 'C');
  // TEN TIMES THE PEOPLE: the same questions, the same rows.
  const shared = require('./directory_window');
  for (let i = 300; i < 3000; i++) {
    const dn = 'uid=' + uid(i) + ',' + ctx.users;
    built.rows.set('default\n' + dn, shared.row('default', dn,
      { uid: [uid(i)], objectclass: ['inetOrgPerson'], cn: ['P ' + i] }));
  }
  await recognition(t, ctx, 'C-tenfold-');
  t.log.info('=== D. a device written here ===');
  unflushed(t, ctx);
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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-dlw-'));
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

function run(t) {
  log.debug('Entering run().');
  storeHalf(t);
  t.log.info('=== B–D. through the directory, as a windowed worker ===');
  inChild(t, 12);
  log.debug('Leaving run().');
}

if (require.main === module && process.env[CHILD_FLAG] === '1') {
  childMain();
}

module.exports = {
  name: 'device_lookups_windowed',
  describe: 'a person\'s page and a device\'s recognition ask the store\'s ' +
            'indexes and never walk ou=devices in a windowed process (#636)',
  run: run
};
