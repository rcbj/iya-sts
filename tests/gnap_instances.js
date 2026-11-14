// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: gnap_instances.js
//
// ===========================================================================
// GNAP INSTANCE RECORDS ARE REUSED AND EXPIRE (#1221).
//
// rcbj, 2026-10-30: the `gnap.instances` store only grew — a new random
// instance_id per grant request that sent its key by value, and nothing ever
// deleted — which #1216 made one record per browser sign-in. Now:
//
//   N1. the same key at the same application is given the same identifier,
//       derived; another key, or another application, gets another one;
//   N2. writing the same identifier again keeps the record's createdAt and
//       refreshes seenAt — one record, not one per sign-in;
//   N3. a record unused for gnap.grantLifetimeS is answered as unknown;
//   N4. purgeInstances() deletes exactly the expired records, a record from
//       before #1221 (createdAt only) among them;
//   N5. touchInstance() refreshes a record used by reference, at most once a
//       minute, which keeps it past the lifetime it would have ended at;
//   N6. the gnap.grant-expiry job's body deletes unused records and says so.
//
// IN PROCESS, in a throwaway realm, on the real store with its clock
// replaced.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const realms = require('../common/realms');
require('../common/app');
require('../ldap/ldap_server');

const log = require('bunyan').createLogger({
  name: 'gnap_instances',
  level: process.env.LOG_LEVEL || 'info' });

const LIFETIME = 600;

async function cases(t, suffix) {
  log.debug("Entering cases().");
  const storeModule = require('../gnap/gnap_store');
  let clock = 1_000_000;
  const deps = storeModule.GnapStore.defaultDeps();
  deps.nowSec = function () { return clock; };
  deps.instanceLifetime = function () { return LIFETIME; };
  const store = new storeModule.GnapStore(deps);
  const raw = deps.stores.instances;

  // N1.
  const app = 'ni-app-' + suffix;
  const a1 = store.instanceIdFor(app, 'key-a');
  const a2 = store.instanceIdFor(app, 'key-a');
  const b = store.instanceIdFor(app, 'key-b');
  const other = store.instanceIdFor('ni-other-' + suffix, 'key-a');
  t.check(a1 === a2 && a1 !== b && a1 !== other &&
          /^[A-Za-z0-9_-]{24}/.test(a1),
          'N1. the same key at the same application gets the same ' +
          'identifier; another key or application gets another one',
          JSON.stringify({ a1: a1, a2: a2, b: b, other: other }));

  // N2.
  store.putInstance(a1, { identifier: app, key: { proof: 'httpsig' } });
  const first = store.instanceById(a1);
  clock += 100;
  store.putInstance(a1, { identifier: app, key: { proof: 'httpsig' } });
  const second = store.instanceById(a1);
  let count = 0;
  raw.forEach(function (record) {
    if (record && record.identifier === app) {
      count += 1;
    }
  });
  t.check(first && second && second.createdAt === first.createdAt &&
          second.seenAt === first.seenAt + 100 && count === 1,
          'N2. writing the same identifier again keeps createdAt, refreshes ' +
          'seenAt, and leaves one record', JSON.stringify({ first: first,
                                                            second: second,
                                                            count: count }));

  // N3.
  clock += LIFETIME;
  t.check(store.instanceById(a1) === null,
          'N3. a record unused for the lifetime is answered as unknown');

  // N4.
  const live = store.instanceIdFor(app, 'key-live');
  store.putInstance(live, { identifier: app });
  const legacyKey = store.digest('ni-legacy-' + suffix);
  raw.set(legacyKey, { identifier: app, createdAt: clock - LIFETIME - 1 });
  const purged = store.purgeInstances();
  t.check(purged >= 2 && !raw.has(store.digest(a1)) && !raw.has(legacyKey) &&
          store.instanceById(live) !== null,
          'N4. purgeInstances() deletes the expired records, one from before ' +
          '#1221 (createdAt only) among them, and keeps the live one',
          JSON.stringify({ purged: purged }));

  // N5.
  const seenBefore = store.instanceById(live).seenAt;
  clock += 30;
  store.touchInstance(live);
  const notYet = store.instanceById(live).seenAt;
  clock += 40;
  store.touchInstance(live);
  const touched = store.instanceById(live).seenAt;
  clock += LIFETIME - 10;
  const stillThere = store.instanceById(live);
  t.check(notYet === seenBefore && touched === clock - (LIFETIME - 10) &&
          stillThere !== null,
          'N5. touchInstance() refreshes a record used by reference at most ' +
          'once a minute, which keeps it past where it would have expired',
          JSON.stringify({ seenBefore: seenBefore, notYet: notYet,
                           touched: touched }));
  raw.delete(store.digest(live));

  // N6. Through the real job body, on the real clock.
  const grants = require('../gnap/gnap_grants');
  const staleKey = store.digest('ni-stale-' + suffix);
  raw.set(staleKey, { identifier: app, createdAt: 1, seenAt: 1 });
  const out = await Promise.resolve(grants.expireGrants());
  t.check(!raw.has(staleKey) &&
          /unused instance record\(s\) deleted/.test(String(out && out.summary)),
          'N6. the gnap.grant-expiry job deletes an unused instance record ' +
          'and says so', JSON.stringify(out));
  log.debug("Leaving cases().");
}

function run(t) {
  log.debug("Entering run().");
  const suffix = nodeCrypto.randomBytes(4).toString('hex');
  const id = 'ni-' + suffix;
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename });
  if (!made.ok) {
    t.bad('could not create the realm "' + id + '"',
          (made.errors || []).join(' '));
    log.debug("Leaving run().");
    return undefined;
  }
  const cleanUp = function () {
    realms.remove(id);
  };
  let done;
  try {
    done = realms.run(made.realm, function () {
      return cases(t, suffix);
    });
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    cleanUp();
    throw e;
  }
  log.debug("Leaving run().");
  return Promise.resolve(done).then(cleanUp, function (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    cleanUp();
    throw e;
  });
}

module.exports = {
  name: 'gnap_instances',
  describe: 'GNAP instance records: the same key and application get the ' +
            'same instance_id back, and a record unused for ' +
            'gnap.grantLifetimeS is answered as unknown and purged (#1221)',
  run: run
};
