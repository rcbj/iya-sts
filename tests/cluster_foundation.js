'use strict';
//
// File: cluster_foundation.js
//
// ===========================================================================
// THE CLUSTER FOUNDATION (2026-09-14, #46): WHAT A NODE IS, AND THE SIX WAYS IT
// FAILS WITHOUT SAYING SO.
//
// Several containers against one store is issue #46, and every failure it
// lists is SILENT — a node that answers from a copy nobody else believes in
// looks exactly like one that does not. This file is the in-process half of the
// test for the layer every family's fix is built on:
//
//   1. a change committed after later ones were visible is applied, not lost;
//   2. a read barrier is satisfied only by a pull that began after its target;
//   3. the cluster mode resolves the way `cluster.mode`'s description says, and
//      refuses the configurations that cannot work;
//   4. a node that loses its membership, its service lease or its database
//      EXITS — the fail-stop rcbj chose — and a lost role lease does not;
//   5. active-active refuses to start while a capability is missing, and an
//      operator's named exception is the only way past it;
//   6. a claim is once, a release gives it back, and a shared secret is the
//      store's value in every process.
//
// WHY IN PROCESS. Each is a decision inside one module against a driver's
// answers, and a stub driver can give the answer that is hard to arrange with
// a real database on demand — an expired row, a lost lease, a hole. The
// behaviour against a real postgres (two nodes, a paused active node, a
// takeover) is exercised by the two-node run cluster/CLAUDE.md records.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');
const { isSourceFile } = require('./tools/source_file');
const realms = require('../common/realms');
const replication = require('../persistence/persistence_replication');
const cluster = require('../cluster/cluster');
const capabilities = require('../cluster/cluster_capabilities');
const claims = require('../cluster/cluster_claims');
const clusterSecrets = require('../cluster/cluster_secrets');

const log = require('bunyan').createLogger({ name: 'cluster_foundation',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// The settings this file varies. All restart-only, so through the environment
// — `config.js` reads `process.env` per call, and `setOverride()` refuses a
// restart-only row (tests/replication.js says why that matters).
const VARIED = ['STS_CLUSTER_MODE', 'STS_MODE', 'STS_PERSISTENCE_MODE',
                'STS_KEYS_SOURCE', 'STS_CLUSTER_HEARTBEAT_MS',
                'STS_CLUSTER_NODE_TTL_MS',
                'STS_CLUSTER_ACCEPT_MISSING_CAPABILITIES',
                'STS_PERSISTENCE_COORDINATE', 'STS_REQUEST_WORKER',
                // Active-active refuses to start without one name for the
                // cluster (STS-CLUSTER-0026, tests/cluster_followups.js).
                'STS_PUBLIC_BASE_URL'];
const saved = {};

function setEnv(values) {
  log.debug("Entering setEnv().");
  VARIED.forEach(function (name) {
    if (!(name in saved)) {
      saved[name] = process.env[name];
    }
    if (values && Object.prototype.hasOwnProperty.call(values, name)) {
      process.env[name] = values[name];
    } else {
      delete process.env[name];
    }
  });
  log.debug("Leaving setEnv().");
}

function restoreEnv() {
  log.debug("Entering restoreEnv().");
  Object.keys(saved).forEach(function (name) {
    if (saved[name] === undefined) {
      delete process.env[name];
    } else {
      process.env[name] = saved[name];
    }
  });
  log.debug("Leaving restoreEnv().");
}

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

// ---------------------------------------------------------------------------
// A CHANGE LOG WHOSE ROWS BECOME VISIBLE WHEN TOLD — which is what a
// transaction still committing looks like to a reader.
// ---------------------------------------------------------------------------
function holeyDriver() {
  log.debug("Entering holeyDriver().");
  const rows = [];
  log.debug("Leaving holeyDriver().");
  return {
    rows: rows,
    origin: function () {
      log.debug("Entering origin().");
      log.debug("Leaving origin().");
      return 'me';
    },
    add: function (seq, key, visible) {
      log.debug("Entering add().");
      rows.push({ seq: seq, origin: 'them', kind: 'minted', realm: '',
                  key: key, visible: !!visible });
      log.debug("Leaving add().");
    },
    show: function (seq) {
      log.debug("Entering show().");
      rows.forEach(function (row) {
        if (row.seq === seq) {
          row.visible = true;
        }
      });
      log.debug("Leaving show().");
    },
    latestChangeSeq: function () {
      log.debug("Entering latestChangeSeq().");
      const seen = rows.filter(function (r) { return r.visible; });
      log.debug("Leaving latestChangeSeq().");
      return Promise.resolve(seen.length ? Math.max.apply(null,
        seen.map(function (r) { return r.seq; })) : 0);
    },
    changesSince: function (after, limit) {
      log.debug("Entering changesSince().");
      log.debug("Leaving changesSince().");
      return Promise.resolve(rows.filter(function (r) {
        return r.visible && r.seq > after;
      }).sort(function (a, b) { return a.seq - b.seq; }).slice(0, limit));
    },
    changesAt: function (seqs) {
      log.debug("Entering changesAt().");
      log.debug("Leaving changesAt().");
      return Promise.resolve(rows.filter(function (r) {
        return r.visible && seqs.indexOf(r.seq) >= 0;
      }));
    }
  };
}

// ---------------------------------------------------------------------------
// A CLUSTER DRIVER THAT ANSWERS WHAT A TEST TELLS IT TO.
// ---------------------------------------------------------------------------
function clusterDriver(script) {
  log.debug("Entering clusterDriver().");
  const calls = [];
  const s = script || {};
  log.debug("Leaving clusterDriver().");
  const driver = {
    calls: calls,
    fence: null,
    whenFenced: null,
    setFence: function (fence, whenFenced) {
      log.debug("Entering setFence().");
      driver.fence = fence;
      driver.whenFenced = whenFenced;
      log.debug("Leaving setFence().");
    },
    joinCluster: function (node) {
      log.debug("Entering joinCluster().");
      calls.push('join');
      log.debug("Leaving joinCluster().");
      return Promise.resolve(s.join ? s.join(node)
        : { joined: true, differing: [], live: 0 });
    },
    acquireLease: function (name) {
      log.debug("Entering acquireLease().");
      calls.push('acquire:' + name);
      log.debug("Leaving acquireLease().");
      return Promise.resolve(s.acquire ? s.acquire(name)
        : { held: true, token: 7 });
    },
    heartbeat: function () {
      log.debug("Entering heartbeat().");
      calls.push('heartbeat');
      log.debug("Leaving heartbeat().");
      return s.heartbeat ? s.heartbeat() : Promise.resolve({
        alive: true, leases: [{ name: 'service', token: 7 }] });
    },
    agreeFingerprint: function () {
      log.debug("Entering agreeFingerprint().");
      calls.push('agree');
      log.debug("Leaving agreeFingerprint().");
      return Promise.resolve(s.agree ? s.agree() : { differing: [] });
    },
    leaveCluster: function () {
      log.debug("Entering leaveCluster().");
      calls.push('leave');
      log.debug("Leaving leaveCluster().");
      return Promise.resolve(true);
    }
  };
  return driver;
}

async function run(t) {
  log.debug("Entering run().");
  try {
    await holes(t);
    await barrier(t);
    resolution(t);
    await failStop(t);
    await activeActiveGate(t);
    await claimsAndSecrets(t);
    capabilityTable(t);
  } finally {
    cluster.reset();
    replication.reset();
    restoreEnv();
  }
  log.debug("Leaving run().");
}

async function holes(t) {
  log.debug("Entering holes().");
  t.log.info('=== 1. a late commit is applied, not skipped ===');
  setEnv({ STS_PERSISTENCE_COORDINATE: 'true' });
  replication.reset();
  const driver = holeyDriver();
  const applied = [];
  await replication.start(driver, {
    minted: function (change) {
      log.debug("Entering minted().");
      applied.push(change.key);
      log.debug("Leaving minted().");
    }
  });
  driver.add(1, 'still-committing', false);
  driver.add(2, 'already-visible', true);
  await replication.pull();
  t.equal(applied.join(','), 'already-visible',
          'A ROW PAST A HOLE IS APPLIED AT ONCE. Until 2026-09-14 the reader ' +
          'stopped at the first seq it could not see and waited up to four ' +
          'seconds, so one node\'s slow transaction stalled every other ' +
          'node\'s view of every later change');
  t.equal(replication.status().holes, 1,
          'and the seq it stepped over is remembered as a hole');
  driver.show(1);
  await replication.pull();
  t.equal(applied.join(','), 'already-visible,still-committing',
          'THE HOLE IS APPLIED WHEN IT APPEARS, however late. The old reader ' +
          'skipped it after four seconds and never asked again — a ' +
          'transaction slower than that was lost in that process until it ' +
          'restarted');
  t.equal(replication.status().holes, 0, 'and it is no longer a hole');
  t.equal(replication.status().appliedSeq, 2,
          'the low-water mark moves up once nothing below it is missing');
  log.debug("Leaving holes().");
}

async function barrier(t) {
  log.debug("Entering barrier().");
  t.log.info('=== 2. a barrier waits for a pull that began after its target ===');
  replication.reset();
  const driver = holeyDriver();
  const applied = [];
  driver.latestBlockingChangeSeq = driver.latestChangeSeq;
  await replication.start(driver, {
    minted: function (change) {
      log.debug("Entering minted().");
      applied.push(change.key);
      log.debug("Leaving minted().");
    }
  });
  // Seq 1 is a hole when the first pull runs; it commits before the barrier
  // reads its target, and seq 2 is visible throughout.
  driver.add(1, 'committed-before-the-read', false);
  driver.add(2, 'newest', true);
  await replication.pull();
  driver.show(1);
  const answer = await replication.syncNow();
  t.check(answer.caughtUp, 'the barrier reports caught up', JSON.stringify(
    answer));
  // WHAT THIS DOES AND DOES NOT PROVE. It proves the barrier's own pull
  // re-asks for a hole that committed before the target was read, even when
  // the newest seq was already applied. It does NOT pin the rule that only a
  // pull STARTED after the target counts (`lastCompletedStartNo > needNo`):
  // the opening pull here always starts after the target, so the old
  // "highest >= target" test passes this too. Pinning that rule needs a pull
  // already in flight whose page was taken before the hole committed, which
  // this stub cannot time reliably. `cluster_barrier_throughput.js` section 3
  // does, with a driver whose page is answered when the test says (2026-09-14,
  // when the target read itself was removed and that rule became the proof).
  t.check(applied.indexOf('committed-before-the-read') >= 0,
          'AND WHAT COMMITTED BEFORE IT READ ITS TARGET IS APPLIED, even though ' +
          'the newest seq was already applied', applied.join(','));
  log.debug("Leaving barrier().");
}

function resolution(t) {
  log.debug("Entering resolution().");
  t.log.info('=== 3. what cluster.mode resolves to ===');
  cluster.reset();
  setEnv({ STS_MODE: 'product', STS_PERSISTENCE_MODE: 'postgres' });
  t.equal(cluster.resolve().mode, 'active-passive',
          'auto is ACTIVE-PASSIVE in product mode on a postgres store — ' +
          'rcbj\'s default: a second container is a standby, not a second ' +
          'writer');
  setEnv({ STS_MODE: 'development', STS_PERSISTENCE_MODE: 'postgres' });
  t.equal(cluster.resolve().mode, 'off',
          'and off in development mode, which changes nothing that ran before');
  setEnv({ STS_MODE: 'product', STS_PERSISTENCE_MODE: 'ldif' });
  t.equal(cluster.resolve().mode, 'off',
          'and off on a store that cannot be shared');
  setEnv({ STS_CLUSTER_MODE: 'active-passive', STS_PERSISTENCE_MODE: 'ldif' });
  t.check(/STS-CLUSTER-0007/.test(String(cluster.resolve().refused)),
          'an explicit cluster mode without postgres is REFUSED, not quietly ' +
          'off', cluster.resolve().refused);
  setEnv({ STS_CLUSTER_MODE: 'active-active', STS_MODE: 'development',
           STS_PERSISTENCE_MODE: 'postgres', STS_KEYS_SOURCE: 'generated' });
  t.check(/STS-CLUSTER-0008/.test(String(cluster.resolve().refused)),
          'ACTIVE-ACTIVE WITHOUT PERSISTED KEYS IS REFUSED: a key generated ' +
          'per process is a different key on every node',
          cluster.resolve().refused);
  log.debug("Leaving resolution().");
}

async function failStop(t) {
  log.debug("Entering failStop().");
  t.log.info('=== 4. a node that may no longer act exits ===');
  setEnv({ STS_MODE: 'product', STS_PERSISTENCE_MODE: 'postgres',
           STS_CLUSTER_HEARTBEAT_MS: '250', STS_CLUSTER_NODE_TTL_MS: '1000' });

  // A standby waits, then serves.
  let exits = [];
  cluster.reset({ exit: function (code) { exits.push(code); } });
  let asked = 0;
  const standby = clusterDriver({
    acquire: function () {
      asked += 1;
      return asked < 3 ? { held: false, holder: 'the-other-node' }
                       : { held: true, token: 12 };
    }
  });
  const began = Date.now();
  const gated = await cluster.gate(standby);
  t.equal(gated.mode, 'active-passive', 'the gate opens in active-passive');
  t.check(asked === 3 && Date.now() - began >= 400,
          'A STANDBY WAITS — the gate did not resolve until the third ask for ' +
          'the service lease, a heartbeat apart', asked + ' asks, ' +
          (Date.now() - began) + 'ms');
  const fence = standby.fence();
  t.check(fence && fence.leases.some(function (l) {
    return l.name === 'service' && l.token === 12;
  }), 'every write is fenced by the service lease at the token acquired',
          JSON.stringify(fence));
  t.equal(process.env.STS_CLUSTER_INTERNAL_NODE_ID, cluster.nodeId(),
          'and the node id is in the environment every request worker is ' +
          'forked with');

  // The row expired while paused.
  exits = [];
  cluster.reset({ exit: function (code) { exits.push(code); } });
  await cluster.gate(clusterDriver({
    heartbeat: function () {
      return Promise.resolve({ alive: false, leases: [] });
    }
  }));
  await cluster.beat();
  t.equal(exits.join(','), '1',
          'A NODE WHOSE MEMBERSHIP HAD EXPIRED EXITS on its next heartbeat, ' +
          'rather than renewing a row others may already treat as dead');

  // The service lease went to somebody else.
  exits = [];
  cluster.reset({ exit: function (code) { exits.push(code); } });
  await cluster.gate(clusterDriver({
    heartbeat: function () {
      return Promise.resolve({ alive: true, leases: [] });
    }
  }));
  await cluster.beat();
  t.equal(exits.join(','), '1',
          'an active-passive node that LOST THE SERVICE LEASE exits');

  // The database went away for longer than the lifetime.
  exits = [];
  cluster.reset({ exit: function (code) { exits.push(code); } });
  await cluster.gate(clusterDriver({
    heartbeat: function () {
      return Promise.reject(new Error('the database went away'));
    }
  }));
  await cluster.beat();
  t.equal(exits.length, 0,
          'one failed heartbeat inside the lifetime is survived');
  await sleep(800);
  await cluster.beat();
  t.equal(exits.join(','), '1',
          'A NODE THAT CANNOT RENEW WITHIN ITS LIFETIME EXITS ON ITS OWN, ' +
          'because the others may already have taken over what it held');

  // A fenced write.
  exits = [];
  cluster.reset({ exit: function (code) { exits.push(code); } });
  const fenced = clusterDriver({});
  await cluster.gate(fenced);
  const lostRole = new Error('[STS-CLUSTER-0001] no longer holds pki@3');
  lostRole.fenced = true;
  lostRole.reason = 'lease';
  lostRole.lost = [{ name: 'pki', token: 3 }];
  fenced.whenFenced(lostRole);
  t.equal(exits.length, 0,
          'a write fenced because ONE ROLE was lost fails that write and the ' +
          'node stays up');
  const lostNode = new Error('[STS-CLUSTER-0001] membership expired');
  lostNode.fenced = true;
  lostNode.reason = 'node';
  fenced.whenFenced(lostNode);
  t.equal(exits.join(','), '1',
          'A WRITE FENCED BECAUSE THE MEMBERSHIP IS GONE IS FATAL');
  cluster.reset();
  log.debug("Leaving failStop().");
}

async function activeActiveGate(t) {
  log.debug("Entering activeActiveGate().");
  t.log.info('=== 5. active-active refuses what it cannot yet do ===');
  setEnv({ STS_CLUSTER_MODE: 'active-active', STS_MODE: 'product',
           STS_PERSISTENCE_MODE: 'postgres',
           STS_PUBLIC_BASE_URL: 'https://cluster.example' });
  cluster.reset({ exit: function () {} });
  let refusal = null;
  try {
    await cluster.gate(clusterDriver({}));
  } catch (e) {
    refusal = e;
  }
  const missing = capabilities.report().missing;
  t.check(refusal && /STS-CLUSTER-0009/.test(refusal.message) &&
          missing.length > 0,
          'ACTIVE-ACTIVE WITH CAPABILITIES MISSING DOES NOT START — the ' +
          'failure #46 opens with is a cluster that starts healthy and ' +
          'answers wrongly', refusal ? refusal.message.slice(0, 160) : 'none');
  setEnv({ STS_CLUSTER_MODE: 'active-active', STS_MODE: 'product',
           STS_PERSISTENCE_MODE: 'postgres',
           STS_PUBLIC_BASE_URL: 'https://cluster.example',
           STS_CLUSTER_ACCEPT_MISSING_CAPABILITIES: missing.slice(1).join(',') });
  cluster.reset({ exit: function () {} });
  refusal = null;
  try {
    await cluster.gate(clusterDriver({}));
  } catch (e) {
    refusal = e;
  }
  t.check(refusal && refusal.message.indexOf(missing[0]) >= 0,
          'accepting all but one still refuses, and names the one',
          refusal ? '' : 'it started');
  setEnv({ STS_CLUSTER_MODE: 'active-active', STS_MODE: 'product',
           STS_PERSISTENCE_MODE: 'postgres',
           STS_PUBLIC_BASE_URL: 'https://cluster.example',
           STS_CLUSTER_ACCEPT_MISSING_CAPABILITIES: missing.join(',') });
  cluster.reset({ exit: function () {} });
  const opened = await cluster.gate(clusterDriver({}));
  t.equal(opened.mode, 'active-active',
          'naming every missing capability, one by one, is the only way past');
  cluster.reset();
  log.debug("Leaving activeActiveGate().");
}

async function claimsAndSecrets(t) {
  log.debug("Entering claimsAndSecrets().");
  t.log.info('=== 6. a claim is once; a shared secret is the store\'s ===');
  setEnv({});
  claims.reset();
  await realms.run(realms.DEFAULT_REALM, async function () {
    const first = await claims.claim({ scope: 'test.code', value: 'abc',
                                       ttlMs: 60000 });
    const second = await claims.claim({ scope: 'test.code', value: 'abc',
                                        ttlMs: 60000 });
    t.check(first.ok && !second.ok && second.reason === 'used',
            'the same value in the same scope is claimed ONCE',
            JSON.stringify([first.ok, second.reason]));
    const other = await claims.claim({ scope: 'test.artifact', value: 'abc',
                                       ttlMs: 60000 });
    t.check(other.ok, 'a different scope is a different namespace');
    await claims.release(first.handle);
    const again = await claims.claim({ scope: 'test.code', value: 'abc',
                                       ttlMs: 60000 });
    t.check(again.ok, 'a released claim can be claimed again');
    const handler = {};
    const fakeRes = {
      statusCode: 400,
      writableEnded: true,
      once: function (event, fn) { handler[event] = fn; }
    };
    claims.releaseUnlessSucceeded(fakeRes, again.handle);
    handler.finish();
    await sleep(5);
    const afterRefusal = await claims.claim({ scope: 'test.code',
                                              value: 'abc', ttlMs: 60000 });
    t.check(afterRefusal.ok,
            'A CLAIM BOUND TO A RESPONSE THAT FAILED IS GIVEN BACK — a code ' +
            'whose token request was refused has not been spent');
    t.check(claims.digestOf('test.code', 'abc') !== 'abc' &&
            claims.digestOf('test.code', 'abc').length === 43,
            'the key stored is a digest, never the value');
  });

  // Two processes, one store: each is a reset of this module.
  clusterSecrets.reset();
  const table = new Map();
  const fakeStore = {
    claimOnce: function () {},
    ensureSharedSecret: function (name, material) {
      if (!table.has(name)) {
        table.set(name, material);
      }
      return Promise.resolve({ material: table.get(name) });
    }
  };
  const fakeKeystore = {
    sealed: function () { return true; },
    hasEphemeralKek: function () { return false; },
    seal: function (text) { return 'sealed:' + text; },
    open: function (text) { return String(text).replace(/^sealed:/, ''); }
  };
  const persistence = require('../persistence/persistence');
  const realStore = persistence.clusterStore;
  persistence.clusterStore = function () { return fakeStore; };
  try {
    const before = clusterSecrets.get('csrf');
    await clusterSecrets.start(fakeKeystore);
    const first = clusterSecrets.get('csrf');
    clusterSecrets.reset();
    await clusterSecrets.start(fakeKeystore);
    const second = clusterSecrets.get('csrf');
    t.check(first.equals(second),
            'TWO PROCESSES AGAINST ONE STORE GET ONE CSRF KEY — the first ' +
            'offer is kept and every later one reads it');
    t.check(!before.equals(first),
            'and a value read before start() was this process\'s own');
    t.check(Array.from(table.values()).every(function (v) {
      return /^sealed:/.test(v);
    }), 'what reached the store was sealed');
  } finally {
    persistence.clusterStore = realStore;
    clusterSecrets.reset();
  }
  log.debug("Leaving claimsAndSecrets().");
}

function capabilityTable(t) {
  log.debug("Entering capabilityTable().");
  t.log.info('=== 7. the capability table and the code agree ===');
  const ids = capabilities.CAPABILITIES.map(function (row) { return row.id; });
  t.equal(new Set(ids).size, ids.length, 'every capability id is unique');
  const missingFiles = capabilities.CAPABILITIES.filter(function (row) {
    return !fs.existsSync(path.join(ROOT, row.by));
  }).map(function (row) { return row.id + ' → ' + row.by; });
  t.equal(missingFiles.join('; '), '',
          'every row names a module that exists, which is where the fix is');
  // Every provide() call in the tree names a row, and is in the file the row
  // says — a capability declared from somewhere else is a claim nobody checked.
  const wrong = [];
  function walk(dir) {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    const names = entries.map(function (e) { return e.name; });
    entries.forEach(function (entry) {
      if (entry.name === 'node_modules' || entry.name === 'node-ldapjs' ||
          entry.name === 'tests' || entry.name.charAt(0) === '.') {
        return;
      }
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full);
        return;
      }
      // Source only: a `.ts`, or a `.js` that is not its compiled twin (#50).
      if (!isSourceFile(entry.name, names)) {
        return;
      }
      const text = fs.readFileSync(full, 'utf8');
      const re = /capabilities\.provide\(\s*'([^']+)'/g;
      let m = re.exec(text);
      while (m) {
        const row = capabilities.CAPABILITIES.find(function (r) {
          return r.id === m[1];
        });
        const rel = path.relative(ROOT, full);
        if (!row) {
          wrong.push(rel + ' provides unknown ' + m[1]);
        } else if (row.by !== rel) {
          wrong.push(rel + ' provides ' + m[1] + ', which names ' + row.by);
        }
        m = re.exec(text);
      }
    });
  }
  walk(ROOT);
  t.equal(wrong.join('; '), '',
          'EVERY provide() NAMES A ROW, FROM THE FILE THAT ROW NAMES');
  log.debug("Leaving capabilityTable().");
}

module.exports = {
  name: 'cluster_foundation',
  describe: 'the cluster layer #46 is built on: late commits, the barrier, ' +
            'the mode, fail-stop, the active-active gate, claims and secrets',
  run: run
};
