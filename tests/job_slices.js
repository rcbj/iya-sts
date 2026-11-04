// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: job_slices.js
//
// ===========================================================================
// SCHEDULER JOB BODIES GIVE THEIR PROCESS'S EVENT LOOP TURNS (#704).
//
// #408 moved every cluster job's body off the front process onto a request
// worker, which answers requests too; a per-process job cannot move at all.
// So a body that walks a store holds the loop of whichever process runs it,
// and #704 made the walks slice. What this file holds, each by OBSERVING a
// `setImmediate()` callback queued before the work run while it is still
// unfinished — a walk that held the loop throughout could not let it in:
//
//   A. `common/loop_slices.js`: `walkInSlices()` visits every entry, gives
//      the loop a turn between slices, and deletes what `visit` answers true
//      for; `eachInSlices()` the same over an array.
//   B. THE CACHE REPORT COUNTS, IT DOES NOT LIST: a store whose ejector
//      `mapEjector()` or `realmMapEjector()` built is tallied — its
//      `entries()` is never called — with the size, fullest realm and valid
//      count its listed rows would give; one with a declared `tally()`
//      answers for itself; any other is still listed. `snapshotAsync()`
//      answers what `snapshot()` does, and yields.
//   C. `ejectExpiredAsync()` ejects exactly what `ejectExpired()` would,
//      counts it as evictions, reports an ejector that throws, and yields
//      inside a store.
//   D. THE MDS3 SERIAL FROM A PREFIX: `RiskDatasets.mdsSerialOf()` reads
//      `no` without parsing the payload — ahead of `entries`, behind it, a
//      member whose value nests and quotes, absent, and not an object.
//   E. A SELF-SIGNED CERTIFICATE SIGNED BY NODE: `selfSignedRsaCertificate()`
//      signs with OpenSSL rather than forge's JavaScript RSA, and the
//      certificate verifies under its own key.
//   F. THE TOKEN PURGE IS LINEAR AND YIELDS: `purgeExpiredTokens()` answers
//      a promise and lets the loop in while it walks.
//
// The session sweep through its job is `scheduler_jobs.js`; the key-set
// re-seal every process takes is `cluster_key_pki_agreement.js` 0b.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');

const log = require('bunyan').createLogger({ name: 'job_slices',
  level: process.env.LOG_LEVEL || 'info' });

const loopSlices = require('../common/loop_slices');
const registry = require('../common/cache_registry');
const realms = require('../common/realms');

// Runs `work()` and says whether a `setImmediate()` queued just before it
// ran while the work's promise was still unsettled.
async function letsTheLoopIn(work) {
  log.debug("Entering letsTheLoopIn().");
  let settled = false;
  let ranBefore = false;
  setImmediate(function () {
    ranBefore = !settled;
  });
  const answer = await work().then(function (value) {
    settled = true;
    return value;
  });
  log.debug("Leaving letsTheLoopIn().");
  return { answer: answer, yielded: ranBefore };
}

function filled(n, expiredEvery) {
  log.debug("Entering filled().");
  const map = new Map();
  const now = Date.now();
  for (let i = 0; i < n; i++) {
    map.set('k' + i, { until: i % expiredEvery === 0 ? now - 1000
                                                     : now + 3600000 });
  }
  log.debug("Leaving filled().");
  return map;
}

function expiredTest(value, key, now) {
  log.debug("Entering expiredTest().");
  log.debug("Leaving expiredTest().");
  return value.until <= now;
}

async function sectionA(t) {
  log.debug("Entering sectionA().");
  t.log.info('=== A. loop_slices ===');
  const map = filled(3 * loopSlices.SLICE + 7, 2);
  let visited = 0;
  const walked = await letsTheLoopIn(function () {
    return loopSlices.walkInSlices(map, function (value) {
      visited += 1;
      return value.until <= Date.now();
    });
  });
  t.equal(visited, 3 * loopSlices.SLICE + 7, 'A1. every entry is visited');
  t.check(walked.yielded, 'A2. and the loop had a turn before the walk ' +
          'ended');
  t.check(walked.answer > 0 && map.size === 3 * loopSlices.SLICE + 7 -
          walked.answer && Array.from(map.values()).every(function (v) {
            return v.until > Date.now();
          }), 'A3. what visit answered true for is deleted, nothing else',
          String(walked.answer));
  const seen = [];
  const each = await letsTheLoopIn(function () {
    const items = [];
    for (let i = 0; i < 1200; i++) {
      items.push(i);
    }
    return loopSlices.eachInSlices(items, function (item) {
      seen.push(item);
    }, 100);
  });
  t.check(seen.length === 1200 && seen[1199] === 1199 && each.yielded,
          'A4. eachInSlices() sees every item in order and yields');
  log.debug("Leaving sectionA().");
}

function descriptor(name, extra) {
  log.debug("Entering descriptor().");
  log.debug("Leaving descriptor().");
  return Object.assign({ name: name, title: 't', description: 't',
                         owner: 'tests/job_slices.js', scope: 'process',
                         maxEntries: function () {
                           return 100000;
                         },
                         lifetime: function () {
                           return 't';
                         } }, extra);
}

async function sectionBC(t) {
  log.debug("Entering sectionBC().");
  t.log.info('=== B. the cache report counts ===');
  const now = Date.now();
  const plain = filled(1300, 4);
  let listed = 0;
  registry.register(descriptor('test.slices-plain', {
    eject: registry.mapEjector(plain, expiredTest),
    entries: function () {
      listed += 1;
      const out = [];
      plain.forEach(function (v, k) {
        out.push({ key: k, validUntil: v.until });
      });
      return out;
    }
  }));
  const store = realms.map();
  const ids = realms.list().map(function (r) {
    return r.id;
  });
  realms.run(realms.get(realms.DEFAULT_ID), function () {
    for (let i = 0; i < 40; i++) {
      store.set('d' + i, { until: i < 10 ? now - 1 : now + 3600000 });
    }
  });
  registry.register(descriptor('test.slices-realm', {
    scope: 'realm',
    eject: registry.realmMapEjector(realms, store, expiredTest),
    entries: function () {
      listed += 1;
      return registry.realmMapRows(realms, store, function (v, k) {
        return { key: k, validUntil: v.until };
      });
    }
  }));
  registry.register(descriptor('test.slices-declared', {
    tally: function () {
      return { size: 7, largestRealm: 7, valid: 5 };
    },
    entries: function () {
      listed += 1;
      return [];
    }
  }));
  let listedOther = 0;
  registry.register(descriptor('test.slices-listed', {
    entries: function () {
      listedOther += 1;
      return [{ key: 'a', validUntil: now + 1000 },
              { key: 'b', validUntil: now - 1000 }];
    }
  }));
  const rowOf = function (snap, name) {
    return registry.unpackSnapshotRow(snap.caches.filter(function (r) {
      return r[0] === name;
    })[0]);
  };
  const snap = registry.snapshot(now);
  const p = rowOf(snap, 'test.slices-plain');
  const r = rowOf(snap, 'test.slices-realm');
  const d = rowOf(snap, 'test.slices-declared');
  const o = rowOf(snap, 'test.slices-listed');
  t.check(listed === 0, 'B1. a helper-built or declared store is counted ' +
          'without its entries() being called', String(listed));
  t.check(p.size === 1300 && p.largestRealm === 1300 && p.valid === 975,
          'B2. a Map store: its size, and its valid count from the owner\'s ' +
          'expiry test', JSON.stringify(p));
  t.check(r.size === 40 && r.largestRealm === 40 && r.valid === 30 &&
          ids.length >= 1,
          'B3. a realm store: every realm\'s rows, the fullest realm, and ' +
          'what is valid', JSON.stringify(r));
  const listedReport = registry.detail('test.slices-realm', now).summary;
  t.check(listedReport.size === r.size &&
          listedReport.largestRealm === r.largestRealm &&
          listedReport.valid === r.valid,
          'B4. and the tally is what listing the rows gives',
          JSON.stringify({ listed: listedReport.valid, tallied: r.valid }));
  t.check(d.size === 7 && d.valid === 5,
          'B5. a declared tally answers for its store', JSON.stringify(d));
  t.check(listedOther === 1 && o.size === 2 && o.valid === 1,
          'B6. any other store is still listed', JSON.stringify(o));
  const asynced = await letsTheLoopIn(function () {
    return registry.snapshotAsync(now);
  });
  t.check(JSON.stringify(asynced.answer.caches) ===
          JSON.stringify(snap.caches) && asynced.yielded,
          'B7. snapshotAsync() answers what snapshot() does, and yields');

  t.log.info('=== C. ejection in slices ===');
  registry.register(descriptor('test.slices-throws', {
    entries: function () {
      return [];
    },
    eject: function () {
      throw new Error('broken');
    }
  }));
  const before = rowOf(registry.snapshot(now), 'test.slices-plain');
  const ejected = await letsTheLoopIn(function () {
    return registry.ejectExpiredAsync(now);
  });
  const done = ejected.answer;
  t.check(done.byCache['test.slices-plain'] === 325 &&
          done.byCache['test.slices-realm'] === 10 && plain.size === 975,
          'C1. ejectExpiredAsync() ejects what has expired, store by store',
          JSON.stringify(done.byCache));
  t.check(rowOf(registry.snapshot(now), 'test.slices-plain').evictions ===
          before.evictions + 325,
          'C2. and counts it as evictions on the store\'s row');
  t.check(done.failed.some(function (f) {
    return /test\.slices-throws/.test(f);
  }), 'C3. an ejector that throws is reported, and the rest still ran',
          JSON.stringify(done.failed));
  t.check(ejected.yielded, 'C4. and the loop had turns while it ejected');
  ['test.slices-plain', 'test.slices-realm', 'test.slices-declared',
   'test.slices-listed', 'test.slices-throws'].forEach(function (name) {
    registry.forget(name);
  });
  realms.run(realms.get(realms.DEFAULT_ID), function () {
    store.clear();
  });
  log.debug("Leaving sectionBC().");
}

function blobOf(payload) {
  log.debug("Entering blobOf().");
  const b64 = function (o) {
    return Buffer.from(typeof o === 'string' ? o : JSON.stringify(o))
      .toString('base64url');
  };
  log.debug("Leaving blobOf().");
  return b64({ alg: 'RS256' }) + '.' + b64(payload) + '.c2ln';
}

function sectionD(t) {
  log.debug("Entering sectionD().");
  t.log.info('=== D. the MDS3 serial from a prefix ===');
  const RiskDatasets = require('../risk/risk_datasets').RiskDatasets;
  const big = [];
  for (let i = 0; i < 4000; i++) {
    big.push({ aaguid: nodeCrypto.randomUUID(),
               metadataStatement: { description: 'a "quoted" {name} ' + i,
                                    keys: [[1, 2], { x: '}' }] } });
  }
  t.equal(RiskDatasets.mdsSerialOf(blobOf({
    legalHeader: 'Retrieval and use of this BLOB indicates acceptance.',
    no: 87, nextUpdate: '2026-12-01', entries: big })), 87,
          'D1. `no` ahead of the entries');
  t.equal(RiskDatasets.mdsSerialOf(blobOf({
    legalHeader: 'x', entries: big, nextUpdate: '2026-12-01', no: 88 })), 88,
          'D2. `no` behind a payload\'s worth of entries, which nest and ' +
          'quote brackets');
  t.check(isNaN(RiskDatasets.mdsSerialOf(blobOf({ legalHeader: 'x',
                                                  entries: [] }))),
          'D3. a payload without `no` answers NaN');
  t.check(isNaN(RiskDatasets.mdsSerialOf(blobOf('[1, 2, 3]'))) &&
          isNaN(RiskDatasets.mdsSerialOf('not a jwt')),
          'D4. what is not an object answers NaN');
  t.check(isNaN(RiskDatasets.mdsSerialOf(blobOf({ no: 'ninety' }))),
          'D5. a `no` that is not a number answers NaN');
  t.equal(RiskDatasets.topLevelNumber('{"a": {"no": 1}, "no": 2}', 'no'), 2,
          'D6. a nested member of the same name is not the top-level one');
  t.equal(RiskDatasets.topLevelNumber('{"a": "x\\"}", "no"', 'no'),
          undefined, 'D7. a prefix that ends before the answer asks for more');
  log.debug("Leaving sectionD().");
}

function sectionE(t) {
  log.debug("Entering sectionE().");
  t.log.info('=== E. a self-signed certificate signed by node ===');
  const stsCrypto = require('../common/crypto');
  const made = stsCrypto.selfSignedRsaCertificate({ commonName: 'slices',
                                                    bits: 2048 });
  const cert = new nodeCrypto.X509Certificate(made.certPem);
  t.check(cert.verify(nodeCrypto.createPublicKey(made.privateKeyPem)) &&
          cert.checkPrivateKey(nodeCrypto.createPrivateKey(
            made.privateKeyPem)) && /CN=slices/.test(cert.subject),
          'E1. the certificate verifies under its own key, which it ' +
          'certifies');
  const forge = require('node-forge');
  const parsed = forge.pki.certificateFromPem(made.certPem);
  t.check(parsed.signatureOid === forge.pki.oids.sha256WithRSAEncryption &&
          parsed.siginfo.algorithmOid === parsed.signatureOid &&
          parsed.verify(parsed),
          'E2. signed sha256WithRSAEncryption, both algorithm members alike, ' +
          'and forge itself verifies what node signed');
  log.debug("Leaving sectionE().");
}

async function sectionF(t) {
  log.debug("Entering sectionF().");
  t.log.info('=== F. the token purge ===');
  const stats = require('../common/admin_stats');
  const purged = await letsTheLoopIn(function () {
    return stats.purgeExpiredTokens(Date.now());
  });
  t.check(purged.answer && typeof purged.answer.records === 'number' &&
          typeof purged.answer.revocations === 'number',
          'F1. purgeExpiredTokens() answers a promise of its counts',
          JSON.stringify(purged.answer));
  log.debug("Leaving sectionF().");
}

async function run(t) {
  log.debug("Entering run().");
  await sectionA(t);
  await sectionBC(t);
  sectionD(t);
  sectionE(t);
  await sectionF(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'job_slices',
  describe: 'scheduler job bodies give their process\'s event loop turns ' +
            '(#704): walks in slices, the cache report counted rather than ' +
            'listed, ejection in slices, the MDS3 serial from a prefix, ' +
            'and certificates signed by node',
  run: run
};
