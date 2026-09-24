'use strict';
//
// File: cluster_key_pki_agreement.js
//
// ===========================================================================
// SIGNING KEYS AND THE CERTIFICATE AUTHORITY, AGREED BETWEEN NODES
// (2026-09-14, #46 section 1).
//
// Issue #46's worst section, and each assertion below is one of its bullets:
//
//   * two nodes cold-starting against an empty store end with ONE key set,
//     and the one that lost adopts the winner rather than overwriting it;
//   * a realm's keys another node wrote — gained members, a rotation — reach a
//     node that did not write them;
//   * two nodes ensuring the Root and a branch at once build ONE of each;
//   * a revocation, or an issued serial, recorded on one node is not thrown
//     out of the store by another node's save of an older copy, a released
//     hold stays released, a CA tier is first writer wins;
//   * a CRL number only goes up across nodes whose clocks disagree.
//
// ---------------------------------------------------------------------------
// HOW TWO "NODES" LIVE IN ONE PROCESS. A node's state is module state —
// `keystore.js`'s maps, `pki.js`'s queue — so a node here is a FRESH INSTANCE
// of those modules, required with their cache entries removed and the
// originals put back, so nothing else in `tests/run.js`'s one process sees
// them. Both instances talk to ONE stub store that behaves like the postgres
// driver where it matters: `mergeKeys()` holds a per-row lock across the
// caller's decision, and a small delay inside it is what lets two writes be
// in flight together, which is the whole of the race.
//
// The claims under `pki.js`'s build are `cluster/cluster_claims.js`'s memory
// store, which is the same instance for both "nodes" — exactly as the
// postgres table is the same table for two containers.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const nodeCrypto = require('crypto');

const crypto = require('../common/crypto');
const pkiMerge = require('../common/pki_merge');

const log = require('bunyan').createLogger({
  name: 'cluster_key_pki_agreement', level: process.env.LOG_LEVEL || 'info' });

const COMMON = path.join(__dirname, '..', 'common');

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

// A fresh copy of each named module under `common/`, with the cached
// originals restored afterwards. Required in the order given, so a later name
// requiring an earlier one gets the fresh copy.
function freshNode(names) {
  log.debug("Entering freshNode().");
  const saved = {};
  const out = {};
  names.forEach(function (name) {
    const file = require.resolve(path.join(COMMON, name));
    saved[file] = require.cache[file];
    delete require.cache[file];
  });
  names.forEach(function (name) {
    out[name] = require(path.join(COMMON, name));
  });
  Object.keys(saved).forEach(function (file) {
    if (saved[file]) {
      require.cache[file] = saved[file];
    } else {
      delete require.cache[file];
    }
  });
  log.debug("Leaving freshNode().");
  return out;
}

// THE STORE BOTH NODES SHARE. `mergeKeys()` serialises per row and waits
// `delayMs` holding the "lock", which is what a SELECT … FOR UPDATE does to a
// second transaction.
function sharedStore(delayMs) {
  log.debug("Entering sharedStore().");
  const rows = new Map();
  const locks = new Map();
  const adopted = [];
  log.debug("Leaving sharedStore().");
  return {
    rows: rows,
    adopted: adopted,
    loadKeys: function () {
      log.debug("Entering loadKeys().");
      log.debug("Leaving loadKeys().");
      return Promise.resolve(Array.from(rows.entries()).map(function (pair) {
        return { realm: pair[0], material: pair[1] };
      }));
    },
    saveKeys: function (realm, material) {
      log.debug("Entering saveKeys().");
      rows.set(realm, material);
      log.debug("Leaving saveKeys().");
      return Promise.resolve();
    },
    deleteKeys: function (realm) {
      log.debug("Entering deleteKeys().");
      rows.delete(realm);
      log.debug("Leaving deleteKeys().");
      return Promise.resolve();
    },
    loadKey: function (realm) {
      log.debug("Entering loadKey().");
      log.debug("Leaving loadKey().");
      return Promise.resolve(rows.has(realm) ? rows.get(realm) : null);
    },
    mergeKeys: function (realm, cipher, merge) {
      log.debug("Entering mergeKeys().");
      const ahead = locks.get(realm) || Promise.resolve();
      const run = ahead.then(function () {
        return sleep(delayMs);
      }).then(function () {
        const current = rows.has(realm) ? rows.get(realm) : null;
        const next = merge(current);
        if (!next || next === current) {
          return { written: false, inserted: false, material: current };
        }
        rows.set(realm, next);
        return { written: true, inserted: current === null, material: next };
      });
      locks.set(realm, run.then(function () { return null; }, function (e) {
        log.debug("Caught in mergeKeys(): " + ((e && e.message) || e));
        return null;
      }));
      log.debug("Leaving mergeKeys().");
      return run;
    },
    hierarchyAdopted: function (scopeId) {
      log.debug("Entering hierarchyAdopted().");
      adopted.push(scopeId);
      log.debug("Leaving hierarchyAdopted().");
    }
  };
}

// Something shaped like a serialised key set, as far as the keystore's write
// path reads one: the certificate that names it, and its lazily made members.
function keySet(label, extra) {
  log.debug("Entering keySet().");
  log.debug("Leaving keySet().");
  return Object.assign({
    createdAt: Date.now(),
    privateKeyPem: 'private-' + label,
    certPem: 'cert-' + label,
    certB64: 'b64-' + label + '-' + nodeCrypto.randomBytes(4).toString('hex'),
    extraKeys: [],
    pqKeys: []
  }, extra || {});
}

function opened(kek, cipher) {
  log.debug("Entering opened().");
  log.debug("Leaving opened().");
  return JSON.parse(crypto.decryptWithKek(kek, cipher));
}

async function startNode(store, spies) {
  log.debug("Entering startNode().");
  const node = freshNode(['keystore']);
  const keystore = node.keystore;
  keystore.setStore(store);
  keystore.onAdopt(function (realmId) {
    spies.adopted.push(realmId);
  });
  keystore.setKeyPublisher(function (realmId, blob, options) {
    spies.published.push({ realm: realmId, certB64: blob.certB64,
                           confirmed: !!(options && options.confirmed) });
  });
  await keystore.start();
  log.debug("Leaving startNode().");
  return keystore;
}

async function offSection(t, kek) {
  log.debug("Entering offSection().");
  t.log.info('=== 0. cluster.mode=off keeps a single node\'s upsert ===');
  process.env.STS_CLUSTER_MODE = 'off';
  try {
    const store = sharedStore(5);
    const a = await startNode(store, { adopted: [], published: [] });
    const b = await startNode(store, { adopted: [], published: [] });
    t.equal(a.arbitrates(), false,
            'the store is not asked to arbitrate when the operator said this ' +
            'is one container');
    const setA = keySet('off-a');
    const setB = keySet('off-b');
    a.remember('probe', setA);
    b.remember('probe', setB);
    await Promise.all([a.settleAll(), b.settleAll()]);
    t.check(a.storedFor('probe').certB64 !== b.storedFor('probe').certB64,
            'THE CONTROL: two instances with the cluster off still hold two ' +
            'key sets, so what the sections below measure is the cluster ' +
            'path and not something that was always true');
    t.equal(opened(kek, store.rows.get('probe')).certB64, setB.certB64,
            'and the later upsert owns the row, as it always did');
  } finally {
    process.env.STS_CLUSTER_MODE = 'active-active';
  }
  log.debug("Leaving offSection().");
}

async function keysSection(t, kek) {
  log.debug("Entering keysSection().");
  t.log.info('=== 1. a cold start of two nodes ends with ONE key set ===');
  const store = sharedStore(20);
  const spiesA = { adopted: [], published: [] };
  const spiesB = { adopted: [], published: [] };
  const a = await startNode(store, spiesA);
  const b = await startNode(store, spiesB);
  t.check(a !== b && a.arbitrates() && b.arbitrates(),
          'two keystore instances, both on a store that can arbitrate');

  const setA = keySet('a');
  const setB = keySet('b');
  // BOTH GENERATE BEFORE EITHER WRITE LANDS — the cold start.
  a.remember('probe', setA);
  b.remember('probe', setB);
  const outcomes = await Promise.all([a.settleAll(), b.settleAll()]);
  const stored = opened(kek, store.rows.get('probe'));
  t.equal(stored.certB64, setA.certB64,
          'THE FIRST WRITER\'S SET IS THE ROW — the second write did not ' +
          'overwrite it, which is what the old upsert did');
  t.equal(a.storedFor('probe').certB64, setA.certB64,
          'node A holds its own set');
  t.equal(b.storedFor('probe').certB64, setA.certB64,
          'AND NODE B, WHICH GENERATED A DIFFERENT ONE, NOW HOLDS A\'S — ' +
          'one JWKS for the cluster rather than one per node');
  t.check(spiesB.adopted.indexOf('probe') >= 0,
          'node B dropped the key set it had cached, or it would go on ' +
          'signing with the one it adopted away from', spiesB.adopted);
  t.check(spiesB.published.some(function (one) {
    return one.confirmed && one.certB64 === setA.certB64;
  }), 'and offered the winner to its own container marked CONFIRMED, so the ' +
      'request pool adopts it instead of arbitrating it away',
          spiesB.published);
  t.check(!spiesA.adopted.length,
          'node A adopted nothing: it won', spiesA.adopted);
  t.check((outcomes[1] || []).some(function (one) {
    return one && one.outcome === 'lost' && one.adopted;
  }), 'node B\'s write reports that it lost and adopted', outcomes[1]);

  t.log.info('=== 2. members made later JOIN the set on every node ===');
  const pq = [{ alg: 'ML-DSA-44', privateKey: 'cHE=',
                publicJwk: { kid: 'pq' } }];
  b.remember('probe', Object.assign({}, setA, { pqKeys: pq }));
  await b.settleAll();
  t.equal((opened(kek, store.rows.get('probe')).pqKeys || []).length, 1,
          'a member one node made for the SAME set is written into the row');
  const applied = await a.applyStoredChange('probe');
  t.check(applied.adopted && (a.storedFor('probe').pqKeys || []).length === 1,
          'and node A, applying the change row, holds it', applied);
  // A late, POORER offer — node A's cached set without the member — must not
  // take it back out.
  a.remember('probe', setA);
  await a.settleAll();
  t.equal((opened(kek, store.rows.get('probe')).pqKeys || []).length, 1,
          'an offer lacking a member the row has does not remove it');
  t.equal((a.storedFor('probe').pqKeys || []).length, 1,
          'and the node that offered it keeps the richer set');

  t.log.info('=== 3. a rotation reaches the node that did not rotate ===');
  spiesB.adopted.length = 0;
  await b.applyStoredChange('probe');
  const rotated = await a.rotate('probe');
  t.equal(rotated.ok, true, 'node A rotates');
  t.check(!store.rows.has('probe'), 'the row is gone');
  const removal = await b.applyStoredChange('probe');
  t.check(removal.adopted && removal.removed && !b.storedFor('probe'),
          'NODE B DROPS THE ROTATED KEYS when the change reaches it, where ' +
          'applyKeysChange() used to log and keep them', removal);
  t.check(spiesB.adopted.indexOf('probe') >= 0,
          'and its cached key set with them');
  const next = keySet('after-rotation');
  b.remember('probe', next);
  await b.settleAll();
  await a.applyStoredChange('probe');
  t.equal(a.storedFor('probe').certB64, next.certB64,
          'the set the next node made is the one node A adopts');

  t.log.info('=== 4. a realm created on A and first used on B ===');
  a.remember('runtime', keySet('made-on-a'));
  await a.settleAll();
  b.remember('runtime', keySet('made-on-b'));
  await b.settleAll();
  t.equal(b.storedFor('runtime').certB64,
          a.storedFor('runtime').certB64,
          'B generated on first use, found A\'s set under the lock, and ' +
          'adopted it instead of overwriting A\'s row');

  t.log.info('=== 5. a write in flight is not adopted underneath ===');
  b.remember('inflight', keySet('in-flight'));
  const deferred = await b.applyStoredChange('inflight');
  t.check(deferred.pending === true && !deferred.adopted,
          'applying a change while this node\'s own write is queued ' +
          'defers to that write, whose merge decides against the same row',
          deferred);
  await b.settleAll();
  log.debug("Leaving keysSection().");
}

async function mergeSection(t, kek) {
  log.debug("Entering mergeSection().");
  t.log.info('=== 6. two nodes saving one CA row keep both changes ===');
  const store = sharedStore(20);
  const seed = {
    version: 2, scope: 'acme',
    intermediate: { serialHex: '01', certificatePem: 'I1' },
    issuing: { jose: { serialHex: '02', certificatePem: 'J1' } },
    revoked: { jose: [{ serialHex: 'aa', reason: 'certificateHold',
                        revokedAt: '2026-09-01T00:00:00.000Z' }] },
    crlNumbers: { jose: 4 },
    issuedKeyPairs: []
  };
  store.rows.set('pki:acme', crypto.encryptWithKek(kek, JSON.stringify(seed),
                                                   'pki-hierarchy'));
  const spies = { adopted: [], published: [] };
  const a = await startNode(store, spies);
  const b = await startNode(store, { adopted: [], published: [] });

  const rowA = JSON.parse(JSON.stringify(a.pkiFor('acme')));
  rowA.revoked.jose.push({ serialHex: 'bb', reason: 'keyCompromise',
                           revokedAt: '2026-09-14T10:00:00.000Z' });
  rowA.crlNumbers.jose = 5;
  const future = new Date(Date.now() + 86400000).toISOString();
  const rowB = JSON.parse(JSON.stringify(b.pkiFor('acme')));
  rowB.issuedKeyPairs.push({ serialHex: 'cc', useCase: 'jose',
                             notAfter: future });
  rowB.crlNumbers.jose = 5;
  a.attachPki('acme', rowA);
  b.attachPki('acme', rowB);
  await Promise.all([a.settleAll(), b.settleAll()]);
  let row = opened(kek, store.rows.get('pki:acme'));
  t.check(row.revoked.jose.some(function (one) {
    return one.serialHex === 'bb';
  }), 'A\'S REVOCATION SURVIVED B\'S SAVE of a copy that did not have it — ' +
      'the security finding of #46 section 1', row.revoked);
  t.check(row.issuedKeyPairs.some(function (one) {
    return one.serialHex === 'cc';
  }), 'and B\'s issued serial survived A\'s save', row.issuedKeyPairs);
  t.equal(row.crlNumbers.jose, 6,
          'two changes from one base move the register\'s CRL number twice');
  t.check(b.pkiFor('acme').revoked.jose.some(function (one) {
    return one.serialHex === 'bb';
  }), 'the node whose write merged holds the merged row, not its own');

  t.log.info('=== 7. a stale copy cannot un-revoke, a release stays ===');
  await a.applyStoredChange('pki:acme');
  const stale = JSON.parse(JSON.stringify(seed));
  stale.objects = [{ id: 'o1' }];
  // Node B saves a copy built from the ORIGINAL seed — no `bb`, no `cc`.
  const bBase = await b.applyStoredChange('pki:acme');
  t.check(!bBase.adopted, 'node B is current with the store', bBase);
  const released = JSON.parse(JSON.stringify(a.pkiFor('acme')));
  released.revoked.jose = released.revoked.jose.filter(function (one) {
    return one.serialHex !== 'aa';
  });
  a.attachPki('acme', released);
  b.attachPki('acme', Object.assign(JSON.parse(JSON.stringify(
    b.pkiFor('acme'))), { objects: [{ id: 'o1' }] }));
  await Promise.all([a.settleAll(), b.settleAll()]);
  row = opened(kek, store.rows.get('pki:acme'));
  t.check(!row.revoked.jose.some(function (one) {
    return one.serialHex === 'aa';
  }), 'A RELEASED HOLD STAYS RELEASED when another node saves a copy that ' +
      'still has it unchanged', row.revoked.jose);
  t.check(row.revoked.jose.some(function (one) {
    return one.serialHex === 'bb';
  }) && (row.objects || []).length === 1,
          'and everything else both made is there');
  const noRevocations = JSON.parse(JSON.stringify(row));
  noRevocations.revoked = {};
  const merged = pkiMerge.merge(row, noRevocations, row);
  t.check(merged.row.revoked.jose && merged.row.revoked.jose.some(
    function (one) { return one.serialHex === 'bb'; }),
          'a writer that DROPPED a permanent revocation does not remove it ' +
          '— only a certificateHold can be released');

  t.log.info('=== 8. a CA tier is first writer wins, and says so ===');
  const rootA = JSON.parse(JSON.stringify(a.pkiFor('acme')));
  rootA.intermediate = { serialHex: '0a', certificatePem: 'I-A' };
  const rootB = JSON.parse(JSON.stringify(b.pkiFor('acme')));
  rootB.intermediate = { serialHex: '0b', certificatePem: 'I-B' };
  rootB.certs = { 'jose:RS256': { serialHex: '77', useCase: 'jose',
                                  notAfter: future } };
  await b.applyStoredChange('pki:acme');
  a.attachPki('acme', rootA);
  b.attachPki('acme', rootB);
  const tiers = await Promise.all([a.pkiSettled('acme'), b.pkiSettled('acme')]);
  row = opened(kek, store.rows.get('pki:acme'));
  t.equal(row.intermediate.certificatePem, 'I-A',
          'the Intermediate committed first is the one kept');
  t.check((tiers[1].lost || []).indexOf('intermediate') >= 0,
          'the node whose Intermediate was not kept is told', tiers[1]);
  t.equal(b.pkiFor('acme').intermediate.certificatePem, 'I-A',
          'and holds the one that was');
  t.check(store.adopted.indexOf('acme') >= 0,
          'and the listener reconcile hook was called for the merged row');

  const slotBase = { certs: { s: { serialHex: '10', useCase: 'tls' } } };
  const slot = pkiMerge.merge(slotBase,
    { certs: { s: { serialHex: '11', useCase: 'tls', notAfter: future } } },
    { certs: { s: { serialHex: '12', useCase: 'tls', notAfter: future } } });
  t.check(slot.row.certs.s.serialHex === '12' &&
          slot.row.issuedKeyPairs.some(function (one) {
            return one.serialHex === '11';
          }),
          'a certificate slot both nodes filled keeps the first, and the ' +
          'displaced certificate\'s serial is kept in the issued register ' +
          'so OCSP does not answer `unknown` about it', slot.row);
  log.debug("Leaving mergeSection().");
}

async function buildSection(t) {
  log.debug("Entering buildSection().");
  t.log.info('=== 9. two nodes ensuring the Root and a branch build one ===');
  const store = sharedStore(5);
  const nodeA = freshNode(['keystore', 'pki']);
  const nodeB = freshNode(['keystore', 'pki']);
  [nodeA, nodeB].forEach(function (node) {
    node.keystore.setStore(store);
  });
  await nodeA.keystore.start();
  await nodeB.keystore.start();
  const built = await Promise.all([
    nodeA.pki.ensureRoot({ keyAlg: 'ec-p256' }),
    nodeB.pki.ensureRoot({ keyAlg: 'ec-p256' })
  ]);
  t.check(built[0].ok && built[1].ok, 'both answer ok', built);
  t.check(!!built[0].existing !== !!built[1].existing,
          'EXACTLY ONE BUILT: the other waited on the build claim and took ' +
          'the Root from the store', built.map(function (one) {
            return one.existing;
          }));
  t.check(!built.some(function (one) { return one.adoptedFromCluster; }),
          'AND NEITHER BUILT ONE TO THROW AWAY: the waiting node took the ' +
          'build claim\'s result, not a merge that discarded its own Root',
          built.map(function (one) { return !!one.adoptedFromCluster; }));
  const rootA = nodeA.pki.serviceRoot();
  const rootB = nodeB.pki.serviceRoot();
  t.check(rootA && rootB && rootA.certificatePem === rootB.certificatePem,
          'ONE ROOT FOR THE CLUSTER — every node\'s Intermediates chain to it');

  const branches = await Promise.all([
    nodeA.pki.ensureScope('*process', { keyAlg: 'ec-p256' }),
    nodeB.pki.ensureScope('*process', { keyAlg: 'ec-p256' })
  ]);
  t.check(branches[0].ok && branches[1].ok, 'both branches answer ok',
          branches);
  const interA = nodeA.pki.rawRowFor('*process').intermediate;
  const interB = nodeB.pki.rawRowFor('*process').intermediate;
  t.check(interA && interB && interA.serialHex === interB.serialHex,
          'and one process Intermediate, not one per node',
          [interA && interA.serialHex, interB && interB.serialHex]);

  t.log.info('=== 10. a node that starts later reads, and builds nothing ===');
  const nodeC = freshNode(['keystore', 'pki']);
  nodeC.keystore.setStore(store);
  await nodeC.keystore.start();
  const late = await nodeC.pki.ensureRoot({ keyAlg: 'ec-p256' });
  t.check(late.ok && late.existing &&
          nodeC.pki.serviceRoot().certificatePem === rootA.certificatePem,
          'the Root read back from the store at start is the one it keeps');
  log.debug("Leaving buildSection().");
}

async function crlSection(t) {
  log.debug("Entering crlSection().");
  t.log.info('=== 11. a CRL number only goes up across skewed clocks ===');
  const persistence = require('../persistence/persistence');
  const revocation = require('../common/pki_revocation');
  const counters = new Map();
  let failing = false;
  const fake = {
    claimOnce: function () {
      log.debug("Entering claimOnce().");
      log.debug("Leaving claimOnce().");
      return Promise.resolve({ claimed: true });
    },
    advanceCounter: function (scope, realm, key, value) {
      log.debug("Entering advanceCounter().");
      if (failing) {
        log.debug("Leaving advanceCounter(). Failing.");
        return Promise.reject(new Error('the store is gone'));
      }
      const id = scope + ' ' + realm + ' ' + key;
      const had = counters.has(id);
      const current = counters.get(id) || 0;
      if (!had || current < value) {
        counters.set(id, value);
        log.debug("Leaving advanceCounter(). Advanced.");
        return Promise.resolve({ advanced: true, highest: value });
      }
      log.debug("Leaving advanceCounter(). Behind.");
      return Promise.resolve({ advanced: false, highest: current });
    }
  };
  const original = persistence.clusterStore;
  persistence.clusterStore = function () {
    log.debug("Entering the stubbed clusterStore().");
    log.debug("Leaving the stubbed clusterStore().");
    return fake;
  };
  try {
    const ahead = await revocation.agreedCrlNumber('acme', 'jose', 9000);
    // THE SECOND NODE'S CLOCK IS BEHIND: its candidate is lower.
    const behind = await revocation.agreedCrlNumber('acme', 'jose', 7000);
    t.equal(ahead, 9000, 'the first node signs with its clock-based number');
    t.check(behind > ahead,
            'A NODE WHOSE CLOCK IS BEHIND STILL SIGNS A HIGHER NUMBER — it ' +
            'stepped past the one the other node used', [ahead, behind]);
    const same = await revocation.agreedCrlNumber('acme', 'jose', behind);
    t.check(same > behind,
            'and two signings with one candidate get two numbers',
            [behind, same]);
    failing = true;
    const refused = await revocation.agreedCrlNumber('acme', 'jose', 99999);
    t.equal(refused, null,
            'a store that cannot be asked gives NO number, and buildCrl() ' +
            'signs nothing rather than a number another node may have used');
  } finally {
    persistence.clusterStore = original;
  }
  const alone = await revocation.agreedCrlNumber('acme', 'jose', 1234);
  t.equal(alone, 1234,
          'with no shared store the clock-based number is used as before');

  t.log.info('=== 12. a high-bit serial is its own bytes, not the pool ===');
  // Found by the live two-node revocation probe for this file: the CRL
  // entry for `d02d2cf246925247` carried node's whole 8 KB buffer pool.
  Buffer.from('allocate from the pool so it is not empty');
  const bytes = Buffer.from(revocation.serialBytes('d02d2cf246925247'));
  t.equal(bytes.toString('hex'), '00d02d2cf246925247',
          'the DER INTEGER of a serial with its high bit set is the serial ' +
          'with ONE leading zero byte — and nothing of whatever else shared ' +
          'the allocation pool');
  log.debug("Leaving crlSection().");
}

async function spiffeSection(t) {
  log.debug("Entering spiffeSection().");
  t.log.info('=== 13. two nodes establish ONE SPIFFE JWT authority ===');
  const keystore = require('../common/keystore');
  const persistence = require('../persistence/persistence');
  const spiffeCa = require('../spiffe/spiffe_ca');
  const claims = require('../cluster/cluster_claims');
  // THE STORE, as far as this protocol reads it: what is COMMITTED, what a
  // sync has made visible, and what each node has made and not yet flushed.
  const committed = [];
  let visible = [];
  const local = { a: null, b: null };
  let makes = 0;
  const rows = new Map();
  const fakeStore = {
    claimOnce: function (scope, realm, key, opts) {
      log.debug("Entering claimOnce().");
      const id = scope + ' ' + realm + ' ' + key;
      if (rows.has(id)) {
        log.debug("Leaving claimOnce(). Held.");
        return Promise.resolve({ claimed: false, existing: null });
      }
      rows.set(id, opts.reservation);
      log.debug("Leaving claimOnce(). Claimed.");
      return Promise.resolve({ claimed: true });
    },
    releaseClaim: function (scope, realm, key, reservation) {
      log.debug("Entering releaseClaim().");
      const id = scope + ' ' + realm + ' ' + key;
      const mine = rows.get(id) === reservation;
      if (mine) {
        rows.delete(id);
      }
      log.debug("Leaving releaseClaim().");
      return Promise.resolve(mine);
    },
    purgeClaims: function () {
      log.debug("Entering purgeClaims().");
      log.debug("Leaving purgeClaims().");
      return Promise.resolve(0);
    }
  };
  const saved = { arbitrates: keystore.arbitrates,
                  clusterStore: persistence.clusterStore,
                  syncNow: persistence.syncNow,
                  flushMinted: persistence.flushMinted };
  keystore.arbitrates = function () {
    log.debug("Entering the stubbed arbitrates().");
    log.debug("Leaving the stubbed arbitrates().");
    return true;
  };
  persistence.clusterStore = function () {
    log.debug("Entering the stubbed clusterStore().");
    log.debug("Leaving the stubbed clusterStore().");
    return fakeStore;
  };
  persistence.syncNow = function () {
    log.debug("Entering the stubbed syncNow().");
    visible = committed.slice();
    log.debug("Leaving the stubbed syncNow().");
    return Promise.resolve({ caughtUp: true });
  };
  persistence.flushMinted = function () {
    log.debug("Entering the stubbed flushMinted().");
    ['a', 'b'].forEach(function (name) {
      if (local[name] && committed.indexOf(local[name]) < 0) {
        committed.push(local[name]);
      }
    });
    log.debug("Leaving the stubbed flushMinted().");
    return Promise.resolve(null);
  };
  function node(name) {
    log.debug("Entering node().");
    log.debug("Leaving node().");
    return {
      holds: function () {
        log.debug("Entering holds().");
        log.debug("Leaving holds().");
        return local[name] || visible[0] || null;
      },
      present: function () {
        log.debug("Entering present().");
        log.debug("Leaving present().");
        return !!(local[name] || visible.length);
      },
      make: async function () {
        log.debug("Entering make().");
        makes += 1;
        await sleep(40);
        local[name] = 'authority-made-on-' + name;
        log.debug("Leaving make().");
      }
    };
  }
  const a = node('a');
  const b = node('b');
  try {
    const both = await Promise.allSettled([
      spiffeCa.establishOnce('probe', 'jwt', a.present, a.make),
      spiffeCa.establishOnce('probe', 'jwt', b.present, b.make)
    ]);
    t.check(both.every(function (one) { return one.status === 'fulfilled'; }),
            'both nodes\' establishments settle', both);
    t.equal(makes, 1,
            'ONE AUTHORITY WAS MADE: the node that found the claim held ' +
            'waited for the other\'s commit instead of generating its own, ' +
            'which is the JWT-SVID a second node would have refused');
    t.check(a.holds() && a.holds() === b.holds() && committed.length === 1,
            'and both nodes hold the one that was committed',
            [a.holds(), b.holds(), committed]);
    makes = 0;
    committed.length = 0;
    visible = [];
    local.a = null;
    local.b = null;
    keystore.arbitrates = function () {
      log.debug("Entering the stubbed arbitrates().");
      log.debug("Leaving the stubbed arbitrates().");
      return false;
    };
    await Promise.all([
      spiffeCa.establishOnce('probe2', 'jwt', a.present, a.make),
      spiffeCa.establishOnce('probe2', 'jwt', b.present, b.make)
    ]);
    t.equal(makes, 2,
            'THE CONTROL: where the store does not arbitrate each node makes ' +
            'its own, as it always did — so the count above is the claim');
  } finally {
    keystore.arbitrates = saved.arbitrates;
    persistence.clusterStore = saved.clusterStore;
    persistence.syncNow = saved.syncNow;
    persistence.flushMinted = saved.flushMinted;
    claims.reset();
  }
  log.debug("Leaving spiffeSection().");
}

// ---------------------------------------------------------------------------
// A CERTIFICATE THE ROW PUBLISHES IS NOT ON THE ROW'S OWN CRL (2026-09-22).
//
// The two rules this file already holds can contradict one another: a TIER is
// first writer wins, and a REVOCATION is never lost. A node that rebuilt a
// branch — superseding the Intermediate it replaced — and then did NOT get its
// new tier into the row leaves the union carrying a revocation of the
// certificate the row STILL PUBLISHES. `sts_pki_distribution_points` found
// exactly that in `cluster` mode: *lists CN=sts Intermediate CA … as REVOKED,
// and this service is publishing that certificate right now*, on both the http
// and the ldap distribution point.
//
// The invariant is the narrow one — whatever the row publishes as a live tier
// is not revoked BY THAT ROW — so this asserts both halves: the revocation of
// the LIVE tier is dropped, and a revocation of anything else is untouched,
// because RFC 5280 makes those permanent.
// ---------------------------------------------------------------------------
async function publishedNotRevokedSection(t, kek) {
  log.debug("Entering publishedNotRevokedSection().");
  t.log.info('=== 6b. a live tier is never on its own row\'s CRL ===');
  const store = sharedStore(20);
  const seed = {
    version: 2, scope: 'acme',
    root: { serialHex: 'r1', certificatePem: 'R1' },
    intermediate: { serialHex: '01', certificatePem: 'I1' },
    issuing: { jose: { serialHex: '02', certificatePem: 'J1' } },
    revoked: {},
    crlNumbers: { root: 1 },
    issuedKeyPairs: []
  };
  store.rows.set('pki:acme', crypto.encryptWithKek(kek, JSON.stringify(seed),
                                                   'pki-hierarchy'));
  const a = await startNode(store, { adopted: [], published: [] });

  // A REBUILD THAT SUPERSEDED THE INTERMEDIATE AND DID NOT REPLACE IT — the
  // state a lost tier write leaves behind: the revocation is in the row and
  // the certificate it names is still the live Intermediate.
  const row = JSON.parse(JSON.stringify(a.pkiFor('acme')));
  row.revoked = row.revoked || {};
  row.revoked.root = [
    { serialHex: '01', reason: 'superseded',
      revokedAt: '2026-09-22T21:00:00.000Z' },
    // And one that must SURVIVE: a leaf this authority really did revoke.
    { serialHex: 'de', reason: 'keyCompromise',
      revokedAt: '2026-09-22T21:00:01.000Z' }
  ];
  a.attachPki('acme', row);
  await a.settleAll();

  const stored = opened(kek, store.rows.get('pki:acme'));
  const listed = (stored.revoked && stored.revoked.root) || [];
  t.check(!listed.some(function (one) {
    return String(one.serialHex).toLowerCase() === '01';
  }), 'THE LIVE INTERMEDIATE IS NOT ON THE ROOT\'S LIST — a row may not ' +
      'publish a certificate its own CRL calls revoked, which is what ' +
      'sts_pki_distribution_points found in cluster mode',
      JSON.stringify(listed.map(function (one) {
        return one.serialHex;
      })));
  t.check(listed.some(function (one) {
    return String(one.serialHex).toLowerCase() === 'de';
  }), 'and a revocation of anything that is NOT a live tier is untouched — ' +
      'RFC 5280 makes those permanent',
      JSON.stringify(listed.map(function (one) {
        return one.serialHex;
      })));
  t.check(stored.intermediate && stored.intermediate.serialHex === '01',
          'the tier the row publishes is unchanged by the drop');
  log.debug("Leaving publishedNotRevokedSection().");
}

// ---------------------------------------------------------------------------
// 6c. A MERGE THIS NODE DID NOT ADOPT MUST NOT BECOME ITS BASE (2026-09-23).
//
// `sts_pki_distribution_points` in single-node and cluster mode, three runs:
// the Root's CRL listed a realm's Intermediate as superseded and that realm
// went on publishing it. The realm was the SECOND of an enrollment job's, so
// `realms.create()`'s watcher built a branch in one process and was still
// saving certificates under it when another process's `/pki/build` replaced
// it. The first process's running write merged correctly and kept the new
// tier; it did not ADOPT the merged row, because it had attached again while
// that write ran — but it advanced its base to the merged row anyway. Its
// waiting write, built from the copy with the OLD tier, then found the row
// "unchanged underneath" and was written verbatim over the rebuild. The
// Root's revocation is in another row, so it stayed.
// ---------------------------------------------------------------------------
async function unadoptedMergeSection(t, kek) {
  log.debug("Entering unadoptedMergeSection().");
  t.log.info('=== 6c. a merge not adopted does not become the base ===');
  const store = sharedStore(20);
  const seed = {
    version: 2, scope: 'acme',
    intermediate: { serialHex: '01', certificatePem: 'I1' },
    issuing: { jose: { serialHex: '02', certificatePem: 'J1' } },
    revoked: {},
    crlNumbers: {},
    issuedKeyPairs: []
  };
  store.rows.set('pki:acme', crypto.encryptWithKek(kek, JSON.stringify(seed),
                                                   'pki-hierarchy'));
  const a = await startNode(store, { adopted: [], published: [] });
  const b = await startNode(store, { adopted: [], published: [] });

  // B REBUILDS: a new Intermediate and Issuing CA, committed first.
  const rebuilt = JSON.parse(JSON.stringify(b.pkiFor('acme')));
  rebuilt.intermediate = { serialHex: '0b', certificatePem: 'I2' };
  rebuilt.issuing = { jose: { serialHex: '0c', certificatePem: 'J2' } };
  b.attachPki('acme', rebuilt);
  await b.settleAll();

  // A, NOT YET TOLD, saves twice from its old copy: the second attach lands
  // while the first write is inside the row's lock.
  const future = new Date(Date.now() + 86400000).toISOString();
  const first = JSON.parse(JSON.stringify(a.pkiFor('acme')));
  first.certs = { 'jose:RS256': { serialHex: '71', useCase: 'jose',
                                  notAfter: future } };
  a.attachPki('acme', first);
  // INSIDE the lock, not before it: an attach before the first write starts
  // is coalesced into it (`queueWrite()`), and there is then only one write.
  await sleep(5);
  const second = JSON.parse(JSON.stringify(first));
  second.certs['jose:ES256'] = { serialHex: '72', useCase: 'jose',
                                 notAfter: future };
  a.attachPki('acme', second);
  await a.settleAll();

  const row = opened(kek, store.rows.get('pki:acme'));
  t.equal(row.intermediate && row.intermediate.certificatePem, 'I2',
          'THE REBUILT INTERMEDIATE IS STILL THE ROW\'S after the other ' +
          'node\'s second save from a copy that predates it');
  t.equal(row.issuing && row.issuing.jose &&
          row.issuing.jose.certificatePem, 'J2',
          'and so is the rebuilt Issuing CA');
  log.debug("Leaving unadoptedMergeSection().");
}

// ---------------------------------------------------------------------------
// 6d. A CERTIFICATE FROM THE BRANCH A REBUILD REPLACED IS REPORTED, NOT KEPT
// QUIETLY (2026-09-24).
//
// `sts_pki_distribution_points` in cluster mode: *CN=XML signing (RS256) …
// with no authority found*. One process certified a new realm's XML key from
// its first branch and committed; another process's `POST …/pki/build`,
// whose copy never recorded that slot, rebuilt the branch and wrote after it.
// A tier and a certificate are different members, so each side won the one it
// changed — the rebuilt Issuing CA and the slot signed by the one it replaced
// — and the row published a certificate from an authority nothing publishes.
// `pki_merge.js`'s orphanedSlots() names such a slot; the keystore hands the
// list to `pki.js` in the process whose write made the row.
// ---------------------------------------------------------------------------
async function orphanedSlotSection(t, kek) {
  log.debug("Entering orphanedSlotSection().");
  t.log.info('=== 6d. a slot from a replaced Issuing CA is reported ===');
  const store = sharedStore(20);
  const seed = {
    version: 2, scope: 'acme',
    intermediate: { serialHex: '01', certificatePem: 'I1' },
    issuing: { xml: { serialHex: '02', certificatePem: 'X1' } },
    revoked: {},
    crlNumbers: {},
    issuedKeyPairs: []
  };
  store.rows.set('pki:acme', crypto.encryptWithKek(kek, JSON.stringify(seed),
                                                   'pki-hierarchy'));
  const a = await startNode(store, { adopted: [], published: [] });
  const b = await startNode(store, { adopted: [], published: [] });
  const told = [];
  a.onOrphanedCertificates(function (scopeId, slots) {
    told.push({ scope: scopeId, slots: slots });
  });

  // B CERTIFIES the XML key from the first branch, and commits first.
  const future = new Date(Date.now() + 86400000).toISOString();
  const certified = JSON.parse(JSON.stringify(b.pkiFor('acme')));
  certified.certs = { 'xml:RS256': { serialHex: '71', useCase: 'xml',
                                     chainPem: ['X1', 'I1'],
                                     notAfter: future } };
  b.attachPki('acme', certified);
  await b.settleAll();

  // A REBUILDS from its copy, which never recorded that slot.
  const rebuilt = JSON.parse(JSON.stringify(a.pkiFor('acme')));
  rebuilt.intermediate = { serialHex: '0b', certificatePem: 'I2' };
  rebuilt.issuing = { xml: { serialHex: '0c', certificatePem: 'X2' } };
  a.attachPki('acme', rebuilt);
  const outcome = await a.pkiSettled('acme');

  const row = opened(kek, store.rows.get('pki:acme'));
  t.equal(row.issuing.xml.certificatePem, 'X2',
          'the rebuilt Issuing CA is the row\'s', outcome);
  t.check(told.length === 1 && told[0].scope === 'acme' &&
          told[0].slots.length === 1 && told[0].slots[0] === 'xml:RS256',
          'THE SLOT SIGNED BY THE REPLACED ISSUING CA IS REPORTED to the ' +
          'process whose write merged the row, which is what lets pki.js ' +
          'certify it again from the live one', told);
  t.check(!pkiMerge.orphanedSlots({
    issuing: { xml: { certificatePem: 'X2' } },
    certs: { 'xml:RS256': { useCase: 'xml', chainPem: ['X2', 'I2'] },
             'jose:RS256': { useCase: 'jose', chainPem: ['J1', 'I1'] } }
  }).length, 'and a slot signed by the live Issuing CA, or under a use case ' +
             'the row holds no Issuing CA for, is not');
  log.debug("Leaving orphanedSlotSection().");
}

async function run(t) {
  log.debug("Entering run().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-cluster-keys-'));
  const kekFile = path.join(dir, 'kek');
  const kek = nodeCrypto.randomBytes(32).toString('base64');
  fs.writeFileSync(kekFile, kek, { mode: 0o600 });
  const saved = {
    STS_KEYS_SOURCE: process.env.STS_KEYS_SOURCE,
    STS_KEYS_KEK_PROVIDER: process.env.STS_KEYS_KEK_PROVIDER,
    STS_KEYS_KEK_FILE: process.env.STS_KEYS_KEK_FILE,
    STS_CLUSTER_MODE: process.env.STS_CLUSTER_MODE,
    STS_PERSISTENCE_MODE: process.env.STS_PERSISTENCE_MODE
  };
  // The environment layer and not `setOverride()`: all of these are
  // restart-only rows, which `tests/keystore.js` argues. The cluster mode is
  // what `keystore.arbitrates()` asks — `off` keeps a single node's upsert —
  // and it resolves only on a postgres store; no store is opened for it.
  process.env.STS_KEYS_SOURCE = 'persisted';
  process.env.STS_KEYS_KEK_PROVIDER = 'file';
  process.env.STS_KEYS_KEK_FILE = kekFile;
  process.env.STS_CLUSTER_MODE = 'active-active';
  process.env.STS_PERSISTENCE_MODE = 'postgres';
  try {
    await offSection(t, kek);
    await keysSection(t, kek);
    await mergeSection(t, kek);
    await publishedNotRevokedSection(t, kek);
    await unadoptedMergeSection(t, kek);
    await orphanedSlotSection(t, kek);
    await buildSection(t);
    await crlSection(t);
    await spiffeSection(t);
  } finally {
    Object.keys(saved).forEach(function (name) {
      if (saved[name] === undefined) {
        delete process.env[name];
      } else {
        process.env[name] = saved[name];
      }
    });
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch (e) {
      log.debug("Caught in run(): " + ((e && e.message) || e));
    }
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'cluster_key_pki_agreement',
  describe: 'issue #46 section 1: one key set, one Root and one branch for ' +
            'the cluster, no revocation lost to another node\'s save, and ' +
            'CRL numbers that only go up',
  run: run
};
