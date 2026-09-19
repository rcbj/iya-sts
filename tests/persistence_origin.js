'use strict';
//
// File: persistence_origin.js
//
// ===========================================================================
// WHAT A RESTART MUST NOT LOSE (2026-09-18).
//
// A restarted container was a NEW persistence origin, so what its previous
// life wrote to a `merge: 'own'` store became somebody else's contribution;
// every persisted row older than `persistence.mintedRetention` was deleted at
// the next start of any node, whatever store it belonged to; two accumulators
// were never fanned in; and a few stores were never written down at all. This
// file holds the four fixes:
//
//   A. RETENTION IS PER STORE. The short-lived stores declare `retain: 'age'`
//      and every other store keeps its rows (the restore half is
//      `tests/minted_persistence.js` section 6; this asserts the
//      declarations — the stores that hold configuration and accounts are
//      kept, the nonces and pending flows are not).
//   B. A STABLE ORIGIN. The postgres driver's `adoptOrigin()` against a fake
//      `pg` whose `sts_cluster_claims` is an in-memory table with a clock
//      this file moves: the first process takes `n:<name>`; a second with the
//      same name is refused while the first holds it and keeps a random
//      origin; once the first's claim lapses (a crash) the second takes it;
//      the first then finds every write FENCED and its renewal refused, and
//      the second's release lets a third take it at once. Plus, as source,
//      that `persistence.js` names the origin by node and slot and that
//      `request_pool.js` hands each worker its slot.
//   C. THE TWO ACCUMULATORS NO READER FANNED IN — the SCIM counters and what
//      `POST /ssf/receive` received — and the SSF sweep history, read with
//      another origin's contribution in place.
//   D. THE STORES THAT WERE NOT PERSISTED AT ALL — SCIM's Digest counts and
//      HOBA history, the sweep history — are declared now.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');
const realms = require('../common/realms');
const postgres = require('../persistence/persistence_postgres');
const replication = require('../persistence/persistence_replication');

const log = require('bunyan').createLogger({ name: 'persistence_origin',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const QUIET = { debug: function () {}, info: function () {},
                warn: function () {}, error: function () {} };

// ---------------------------------------------------------------------------
// A fake `pg` over ONE shared claims table, so two drivers are two processes
// against one database. Only the statements the origin code issues are
// understood; everything else answers an empty result.
// ---------------------------------------------------------------------------
function fakeDatabase() {
  log.debug("Entering fakeDatabase().");
  const db = { now: 1000000, claims: new Map(), statements: [] };
  const keyOf = function (scope, realm, key) {
    return scope + '|' + realm + '|' + key;
  };
  db.query = function (sql, params) {
    const p = params || [];
    const text = String(sql);
    db.statements.push(text);
    if (/^INSERT INTO sts_cluster_claims/.test(text)) {
      const k = keyOf(p[0], p[1], p[2]);
      const row = db.claims.get(k);
      if (!row || row.expires <= db.now) {
        db.claims.set(k, { reservation: p[3], origin: p[4],
                           expires: db.now + Number(p[5]) });
        return Promise.resolve({ rowCount: 1, rows: [
          { claimed_at: db.now, expires_at: db.now + Number(p[5]) }] });
      }
      return Promise.resolve({ rowCount: 0, rows: [] });
    }
    if (/^SELECT origin, claimed_at, expires_at FROM sts_cluster_claims/
          .test(text)) {
      const row = db.claims.get(keyOf(p[0], p[1], p[2]));
      return Promise.resolve({ rowCount: row ? 1 : 0, rows: row ? [
        { origin: row.origin, claimed_at: 0, expires_at: row.expires }] : [] });
    }
    if (/^UPDATE sts_cluster_claims SET expires_at/.test(text)) {
      const row = db.claims.get(keyOf(p[0], '', p[1]));
      if (row && row.reservation === p[2] && row.expires > db.now) {
        row.expires = db.now + Number(p[3]);
        return Promise.resolve({ rowCount: 1, rows: [] });
      }
      return Promise.resolve({ rowCount: 0, rows: [] });
    }
    if (/^DELETE FROM sts_cluster_claims/.test(text)) {
      const k = keyOf(p[0], p[1], p[2]);
      const row = db.claims.get(k);
      if (row && row.reservation === p[3]) {
        db.claims.delete(k);
        return Promise.resolve({ rowCount: 1, rows: [] });
      }
      return Promise.resolve({ rowCount: 0, rows: [] });
    }
    if (/^SELECT 1 FROM sts_cluster_claims/.test(text)) {
      const row = db.claims.get(keyOf(p[0], '', p[1]));
      const live = !!row && row.reservation === p[2] && row.expires > db.now;
      return Promise.resolve({ rowCount: live ? 1 : 0, rows: [] });
    }
    return Promise.resolve({ rowCount: 0, rows: [] });
  };
  log.debug("Leaving fakeDatabase().");
  return db;
}

function fakePg(db) {
  log.debug("Entering fakePg().");
  function FakeClient() {}
  FakeClient.prototype.query = function (sql, params) {
    return db.query(sql, params);
  };
  FakeClient.prototype.release = function () {};
  FakeClient.prototype.on = function () {};
  FakeClient.prototype.removeListener = function () {};
  FakeClient.prototype.connect = function () {
    return Promise.resolve();
  };
  FakeClient.prototype.end = function () {
    return Promise.resolve();
  };
  function FakePool() {}
  FakePool.prototype.on = function () {};
  FakePool.prototype.connect = function () {
    return Promise.resolve(new FakeClient());
  };
  FakePool.prototype.query = function (sql, params) {
    return db.query(sql, params);
  };
  FakePool.prototype.end = function () {
    return Promise.resolve();
  };
  log.debug("Leaving fakePg().");
  return { Pool: FakePool, Client: FakeClient };
}

// A driver over the shared fake — one "process".
function driverOver(db) {
  log.debug("Entering driverOver().");
  const pgPath = require.resolve('pg');
  const previous = require.cache[pgPath];
  require.cache[pgPath] = { id: pgPath, filename: pgPath, loaded: true,
                            exports: fakePg(db) };
  try {
    log.debug("Leaving driverOver().");
    return postgres.create({ url: 'postgres://sts_app@localhost:5432/sts',
                             log: QUIET });
  } finally {
    if (previous) {
      require.cache[pgPath] = previous;
    } else {
      delete require.cache[pgPath];
    }
  }
}

function claimA(t) {
  log.debug("Entering claimA().");
  t.log.info('=== A. retention is declared per store ===');
  const want = {
    keep: ['authorization_servers.profiles', 'acme.accounts',
           'vc_status.entries', 'admin_stats.revokedJtis', 'audit.events',
           'admin_stats.users', 'spiffe.federatedBundles', 'caep.register',
           'ssf_streams.streams', 'authn.sessions'],
    age: ['dpop.seenJtis', 'oauth2.authzCodes', 'authn.pending',
          'oidc_rp.flows', 'vc_issuer.vciNonces', 'scim.digestNonces',
          'acme.usedNonces', 'gnap.replay', 'scim.digestCounts',
          'scim.hobaSeen']
  };
  // The owners, loaded so their declarations exist.
  ['../oauth-oidc/authorization_servers', '../acme/acme_store',
   '../oid4vc/vc_status', '../common/admin_stats', '../common/audit',
   '../spiffe/spiffe_ca', '../ssf/caep', '../ssf/ssf_streams',
   '../authn/authn', '../oauth-oidc/dpop', '../oauth-oidc/oauth2',
   '../common/oidc_rp', '../oid4vc/vc_issuer', '../scim/scim_auth',
   '../gnap/gnap_store'].forEach(function (one) {
    require(one);
  });
  Object.keys(want).forEach(function (policy) {
    const wrong = want[policy].filter(function (handle) {
      const row = realms.handleFor(handle);
      return !row || row.retain !== policy;
    });
    t.check(wrong.length === 0,
            'every ' + policy + ' store here declares retain "' + policy + '"',
            wrong.map(function (handle) {
              const row = realms.handleFor(handle);
              return handle + '=' + (row ? row.retain : 'undeclared');
            }).join(', '));
  });
  log.debug("Leaving claimA().");
}

async function claimB(t) {
  log.debug("Entering claimB().");
  t.log.info('=== B. a restarted process takes its origin back ===');
  const db = fakeDatabase();
  const first = driverOver(db);
  const lost = [];
  first.setOriginLost(function (err) {
    lost.push(err);
  });
  const a = await first.adoptOrigin({ name: 'node-a:front', ttlMs: 30000 });
  t.check(a.adopted && first.origin() === 'n:node-a:front',
          'the first process takes the stable origin for its name',
          JSON.stringify(a));

  const second = driverOver(db);
  const refused = await second.adoptOrigin({ name: 'node-a:front',
                                             ttlMs: 30000, waitMs: 0 });
  t.check(!refused.adopted && second.origin() !== 'n:node-a:front' &&
          /held by a live process/.test(refused.why),
          'a second process with the same name is refused while the first ' +
          'holds it, and keeps a random origin', JSON.stringify(refused));

  // The first process crashes: its claim is not renewed and lapses.
  db.now += 30001;
  const third = driverOver(db);
  const taken = await third.adoptOrigin({ name: 'node-a:front',
                                          ttlMs: 30000, waitMs: 1000,
                                          pollMs: 100 });
  t.check(taken.adopted && third.origin() === 'n:node-a:front',
          'once the holder\'s claim has lapsed, the replacement takes the ' +
          'origin', JSON.stringify(taken));

  // The first process was only paused: its next write is fenced.
  const before = db.statements.length;
  let fenced = null;
  try {
    await first.saveMinted([{ handle: 'test.x', realm: 'default', key: 'k',
                              body: 'b' }], []);
  } catch (e) {
    fenced = e;
  }
  const wrote = db.statements.slice(before).some(function (sql) {
    return /INSERT INTO sts_minted/.test(sql);
  });
  t.check(!!fenced && fenced.fenced === true && fenced.reason === 'origin' &&
          !wrote && lost.length === 1,
          'the process that lost the origin has its write FENCED before ' +
          'anything is written, and is told it lost the origin',
          (fenced && fenced.message) + ' wrote=' + wrote +
          ' lost=' + lost.length);
  t.equal(await first.renewOrigin(30000), false,
          'and its renewal is refused');
  t.equal(await third.renewOrigin(30000), true,
          'while the holder\'s renewal succeeds');

  await third.releaseOrigin();
  const fourth = driverOver(db);
  const atOnce = await fourth.adoptOrigin({ name: 'node-a:front',
                                           ttlMs: 30000, waitMs: 0 });
  t.check(atOnce.adopted,
          'a clean stop releases the origin, so the next process takes it ' +
          'without waiting');

  const unnamed = await driverOver(db).adoptOrigin({ name: '' });
  t.check(!unnamed.adopted && unnamed.why === 'no stable name',
          'a process with no stable name keeps a random origin');

  // The two halves of the wiring that only the source shows.
  const persistenceSrc = fs.readFileSync(path.join(ROOT, 'persistence',
                                                   'persistence.js'), 'utf8');
  const poolSrc = fs.readFileSync(path.join(ROOT, 'common',
                                            'request_pool.js'), 'utf8');
  t.check(/return adoptStableOrigin\(\);/.test(persistenceSrc) &&
          /cluster\.nodeName\(\)/.test(persistenceSrc) &&
          /STS_REQUEST_WORKER_SLOT/.test(persistenceSrc) &&
          /driver\.releaseOrigin\(\)/.test(persistenceSrc),
          'persistence.js adopts the origin by node and slot when the store ' +
          'opens, and releases it at a clean stop');
  t.check(/fork\(pool, i\)/.test(poolSrc) &&
          /STS_REQUEST_WORKER_SLOT: typeof slot === 'number'/.test(poolSrc),
          'request_pool.js hands every worker its slot');
  log.debug("Leaving claimB().");
}

function claimC(t) {
  log.debug("Entering claimC().");
  t.log.info('=== C. the accumulators are every process\'s ===');
  const stats = require('../common/admin_stats');
  const before = stats.scimSnapshot();
  replication.contribute('admin_stats.scimCounts', realms.currentId(), '',
                         'n:other-node:front', {
    total: 7, ok: 5, failed: 2, firstAt: 1, lastAt: 2,
    byOperation: { 'Create a user': 7 }, byResourceType: { User: 7 },
    byStatus: {}, byStatusClass: {}, byScimType: {}, byAuthScheme: {},
    detail: {}, clients: {}, clientsCapped: false, anonymous: 0,
    refused: 0, ms: 0, maxMs: 0, bytes: 0, recent: []
  });
  const after = stats.scimSnapshot();
  t.check(after.total === before.total + 7 && after.ok === before.ok + 5 &&
          after.failed === before.failed + 2,
          'the SCIM counts include another process\'s',
          JSON.stringify([before.total, after.total]));
  replication.contribute('admin_stats.scimCounts', realms.currentId(), '',
                         'n:other-node:front', null);

  const streams = require('../ssf/ssf_streams');
  const mine = streams.listReceived().length;
  replication.contribute('ssf_streams.received', realms.currentId(), '',
                         'n:other-node:front',
                         [{ at: '2000-01-01T00:00:00.000Z', token: 'x' }]);
  const all = streams.listReceived();
  t.check(all.length === mine + 1 &&
          all[0].at === '2000-01-01T00:00:00.000Z',
          'what another process received is listed, oldest first');
  replication.contribute('ssf_streams.received', realms.currentId(), '',
                         'n:other-node:front', null);

  const report = require('../ssf/ssf_dead_letter_report');
  replication.contribute('ssf_dead_letter_report.sweeps', realms.currentId(),
                         '', 'n:other-node:front', {
    recent: [{ at: '2099-01-01T00:00:00.000Z', letters: 3 }],
    since: { sweeps: 4, letters: 3, expired: 0, orphaned: 0, trimmed: 0,
             probes: 0 },
    firstAt: '2000-01-01T00:00:00.000Z'
  });
  const view = report.report({ nowMs: Date.now() });
  const sweeps = (view && view.process && view.process.sweeps) || [];
  t.check(sweeps.length > 0 && sweeps[0].at === '2099-01-01T00:00:00.000Z',
          'the sweep history includes another process\'s sweeps, newest first',
          JSON.stringify(sweeps.slice(0, 1)));
  replication.contribute('ssf_dead_letter_report.sweeps', realms.currentId(),
                         '', 'n:other-node:front', null);
  log.debug("Leaving claimC().");
}

function claimD(t) {
  log.debug("Entering claimD().");
  t.log.info('=== D. the stores that were not persisted are ===');
  ['scim.digestCounts', 'scim.hobaSeen'].forEach(function (handle) {
    const row = realms.handleFor(handle);
    t.check(!!row && row.retain === 'age',
            handle + ' is persisted, short-lived');
  });
  const sweeps = realms.handleFor('ssf_dead_letter_report.sweeps');
  t.check(!!sweeps && sweeps.merge === 'own' && sweeps.retain === 'keep',
          'the SSF sweep history is persisted, one row per process, kept');
  log.debug("Leaving claimD().");
}

async function run(t) {
  log.debug("Entering run().");
  claimA(t);
  await claimB(t);
  claimC(t);
  claimD(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'persistence_origin',
  describe: 'what a restart must not lose: retention per store, a stable ' +
            'origin taken back through a claim and fenced, the accumulators ' +
            'fanned in, and the stores that were not persisted',
  run: run
};
