'use strict';
//
// File: cluster_barrier_throughput.js
//
// ===========================================================================
// WHAT A CLUSTER BARRIER COSTS, AND THE FOUR PLACES THE TIME WENT
// (2026-09-14, #46).
//
// The suite's `cluster` mode — two single-process nodes, active-active, one
// postgres — measured a management-API create at 190ms against 2.3ms in
// `postgres` mode, a SCIM create at ~500ms against 16ms, and the 5,000-user
// SCIM load hit its thirty-minute watchdog. Profiled on two nodes, the time
// was in four places, and each is a section here:
//
//   1. THE AUDIT RING WAS ONE ROW. 2.3 MB sealed, written, and read back by
//      the other node, per request. `realms.arr({ segment })` stores it in
//      rows of N by absolute position; its journal, its reads, its restore and
//      the fan-in are held here.
//   2. EVERY REQUEST WAS HELD FOR ANY PENDING WRITE — the previous request's
//      audit row, most of the time. A request is now held only when the store's
//      write position moved while it was handled, and only for the flush that
//      covers it: `persistence_minted.flushThrough()` and
//      `persistence.commitThrough()`.
//   3. THE BARRIER READ THE LOG'S HEAD FIRST, and that query walked every row
//      the node had written. The pull that starts after the call is the proof
//      on its own; a pull already in flight is still not accepted.
//   4. THE CALL LOG RECORDED AFTER THE RESPONSE, so a refused request's audit
//      row was not in the commit the response waited for, and the other node
//      did not list it (`admin_api`'s refused `POST /healthcheck`). And A REALM
//      CREATED ON ONE NODE WAS A 404 ON THE OTHER'S FIRST REQUEST, because the
//      realm middleware runs above the barrier. Both are driven through the
//      real `common/app.js` on a loopback port, with the cluster and the store
//      stubbed so that a commit and a catch-up happen when the test says.
//
// WHY IN PROCESS, which tests/CLAUDE.md asks first: every one of these is a
// timing inside one process — a commit that has not landed, a pull whose page
// was read before a row committed — that a job against two live nodes wins
// only sometimes. The live before-and-after numbers are in cluster/CLAUDE.md.
//
// IN A CHILD PROCESS, for `minted_flush_order.js`'s reason: the store modules
// are one per process, and this file installs stubs on them.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const nodeCrypto = require('crypto');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'cluster_barrier_throughput',
  level: process.env.LOG_LEVEL || 'info' });

const CHILD_FLAG = 'STS_CLUSTER_BARRIER_THROUGHPUT_CHILD';

function settle() {
  log.debug("Entering settle().");
  log.debug("Leaving settle().");
  return new Promise(function (resolve) {
    setImmediate(resolve);
  });
}

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

// A promise that may never settle, raced against a bound: 'timed out' then.
function bounded(promise, ms) {
  log.debug("Entering bounded().");
  let timer = null;
  const late = new Promise(function (resolve) {
    timer = setTimeout(function () {
      resolve('timed out');
    }, ms || 2000);
  });
  log.debug("Leaving bounded().");
  return Promise.race([promise, late]).then(function (value) {
    clearTimeout(timer);
    return value;
  });
}

function recordingHarness() {
  log.debug("Entering recordingHarness().");
  const seen = [];
  function check(condition, what, detail) {
    log.debug("Entering check().");
    seen.push({ ok: !!condition, what: what,
                detail: detail === undefined ? '' : String(detail) });
    log.debug("Leaving check().");
    return !!condition;
  }
  log.debug("Leaving recordingHarness().");
  return {
    log: log,
    seen: seen,
    check: check,
    equal: function (actual, expected, what) {
      log.debug("Entering equal().");
      log.debug("Leaving equal().");
      return check(actual === expected, what,
                   'expected ' + JSON.stringify(expected) + ', got ' +
                   JSON.stringify(actual));
    }
  };
}

// ---------------------------------------------------------------------------
// 1. THE SEGMENTED RING.
// ---------------------------------------------------------------------------
function segmentedRing(t) {
  log.debug("Entering segmentedRing().");
  t.log.info('=== 1. a ring stored in segments ===');
  const realms = require('../common/realms');
  const replication = require('../persistence/persistence_replication');
  const notes = [];
  realms.setPersistObserver(function (handle, realmId, key) {
    if (handle === 'test.throughput.ring') {
      notes.push(String(key));
    }
  });
  const ring = realms.arr({ persist: 'test.throughput.ring', merge: 'own',
                            segment: 4 });
  const handle = realms.handleFor('test.throughput.ring');
  const DEFAULT = realms.DEFAULT_REALM.id;
  t.check(Array.isArray(ring), 'a segmented array is still an array');

  for (let i = 0; i < 10; i++) {
    ring.push({ n: i });
  }
  t.equal(Array.from(new Set(notes)).join(','), '0,1,2',
          'A PUSH JOURNALS THE SEGMENT IT LANDS IN, and nothing else: ten ' +
          'pushes named segments 0, 1 and 2 — never a whole-array row');
  t.equal(JSON.stringify(handle.read(DEFAULT, '2').value),
          JSON.stringify({ start: 8, rows: [{ n: 8 }, { n: 9 }] }),
          'a segment reads as its absolute start and its elements');
  t.equal(handle.read(DEFAULT, '').present, false,
          'and there is no whole-array row to read');

  notes.length = 0;
  ring.shift();
  ring.shift();
  ring.shift();
  t.equal(notes.length, 0,
          'A SHIFT WRITES NOTHING while its segment still holds an element — ' +
          'the trim that happens on every event once the ring is full costs ' +
          'no row');
  ring.shift();
  t.equal(notes.join(','), '0',
          'and the shift that empties a segment journals it, once');
  t.equal(handle.read(DEFAULT, '0').present, false,
          'so the flush finds it empty and deletes the row');
  t.equal(JSON.stringify(handle.read(DEFAULT, '1').value.rows.map(
    function (row) { return row.n; })), '[4,5,6,7]',
          'positions did not move: segment 1 still holds elements 4 to 7');

  notes.length = 0;
  ring.pop();
  t.equal(notes.join(','), '2', 'a pop rewrites the last segment');
  notes.length = 0;
  ring.splice(1, 1);
  t.equal(Array.from(new Set(notes)).join(','), '1,2',
          'A SPLICE RENUMBERS, so every segment the array covered is ' +
          'rewritten — the whole cost the one-row design always paid, and ' +
          'still correct');
  t.equal(ring.length, 4, 'and the array is what a plain array would be');

  // THE FAN-IN: another origin's segments, arriving out of order, with a
  // whole-array row an older build wrote.
  replication.contribute('test.throughput.ring', DEFAULT, '3', 'other',
                         { start: 12, rows: [{ n: 12 }, { n: 13 }] });
  replication.contribute('test.throughput.ring', DEFAULT, '2', 'other',
                         { start: 10, rows: [{ n: 10 }, { n: 11 }] });
  replication.contribute('test.throughput.ring', DEFAULT, '', 'older',
                         [{ n: 'old' }]);
  const others = replication.remoteSegmentedRows('test.throughput.ring',
                                                 DEFAULT);
  const byFirst = others.map(function (rows) {
    return rows.map(function (row) { return row.n; }).join(',');
  }).sort();
  t.equal(JSON.stringify(byFirst), JSON.stringify(['10,11,12,13', 'old']),
          'ANOTHER PROCESS\'S SEGMENTS COME BACK AS ONE LIST IN POSITION ' +
          'ORDER, and an older whole-array row as its own');
  replication.contribute('test.throughput.ring', DEFAULT, '2', 'other', null);
  t.equal(replication.remoteSegmentedRows('test.throughput.ring', DEFAULT)
    .map(function (rows) { return rows.length; }).sort().join(','), '1,2',
          'and a segment that origin deleted leaves its list');

  // THE RESTORE of this process's own segments, out of order.
  handle.remove(DEFAULT);
  handle.restore(DEFAULT, '5', { start: 20, rows: [{ n: 20 }] });
  handle.restore(DEFAULT, '4', { start: 17, rows: [{ n: 17 }, { n: 18 },
                                                   { n: 19 }] });
  t.equal(ring.map(function (row) { return row.n; }).join(','), '17,18,19,20',
          'A RESTORE PUTS SEGMENTS BACK IN POSITION ORDER, whatever order ' +
          'the store handed them over in');
  notes.length = 0;
  ring.push({ n: 21 });
  t.equal(notes.join(','), '5',
          'and the next push lands in the segment its position names');

  // THE AUDIT RING: declared segmented, and trimmed to the cap on the way in.
  const audit = require('../common/audit');
  const config = require('../common/config');
  config.setOverride('audit.maxEvents', 3);
  const rows = [];
  for (let i = 0; i < 6; i++) {
    rows.push({ seq: i + 1, at: 1000 + i, category: 'protocol',
                action: 'protocol.call', outcome: 'success',
                origin: 'node-b', summary: 'from node b ' + i });
  }
  replication.contribute('audit.events', DEFAULT, '0', 'node-b',
                         { start: 0, rows: rows });
  const listed = realms.run(realms.DEFAULT_REALM, function () {
    return audit.list().filter(function (row) {
      return String(row.summary || '').indexOf('from node b') === 0;
    });
  });
  t.equal(listed.map(function (row) { return row.seq; }).join(','), '6,5,4',
          'THE AUDIT LOG KEEPS THE NEWEST audit.maxEvents OF ANOTHER ' +
          'PROCESS\'S EVENTS: a stored copy can carry one segment that ' +
          'process already dropped');
  t.check(realms.handleFor('audit.events') &&
          realms.handleFor('audit.events').read(DEFAULT, '').present === false,
          'and audit.events is the segmented kind');
  config.setOverride('audit.maxEvents', 5000);
  log.debug("Leaving segmentedRing().");
}

// ---------------------------------------------------------------------------
// 3. A BARRIER WITH NO HEAD QUERY STILL REFUSES A PULL ALREADY IN FLIGHT.
// ---------------------------------------------------------------------------
async function barrierWithoutHead(t) {
  log.debug("Entering barrierWithoutHead().");
  t.log.info('=== 3. the barrier\'s proof is a pull started after it ===');
  process.env.STS_PERSISTENCE_COORDINATE = 'true';
  const replication = require('../persistence/persistence_replication');
  replication.reset();
  const rows = [];
  const state = { gate: null, headQueries: 0 };
  const driver = {
    origin: function () {
      log.debug("Entering origin().");
      log.debug("Leaving origin().");
      return 'me';
    },
    latestChangeSeq: function () {
      log.debug("Entering latestChangeSeq().");
      log.debug("Leaving latestChangeSeq().");
      return Promise.resolve(0);
    },
    latestBlockingChangeSeq: function () {
      log.debug("Entering latestBlockingChangeSeq().");
      state.headQueries += 1;
      log.debug("Leaving latestBlockingChangeSeq().");
      return Promise.resolve(rows.length);
    },
    // THE SNAPSHOT IS TAKEN WHEN THE QUERY IS MADE, and the answer is handed
    // back when the gate opens — a page read before a row committed.
    changesSince: function (after, limit) {
      log.debug("Entering changesSince().");
      const snapshot = rows.filter(function (row) {
        return row.visible && row.seq > after;
      }).slice(0, limit).map(function (row) {
        return Object.assign({}, row);
      });
      const gate = state.gate;
      log.debug("Leaving changesSince().");
      return gate ? gate.then(function () { return snapshot; })
                  : Promise.resolve(snapshot);
    },
    changesAt: function (seqs) {
      log.debug("Entering changesAt().");
      log.debug("Leaving changesAt().");
      return Promise.resolve(rows.filter(function (row) {
        return row.visible && seqs.indexOf(row.seq) >= 0;
      }));
    }
  };
  const applied = [];
  await replication.start(driver, {
    minted: function (change) {
      log.debug("Entering minted().");
      applied.push(change.key);
      log.debug("Leaving minted().");
    }
  });
  rows.push({ seq: 1, origin: 'them', kind: 'minted', realm: '', key: 'one',
              visible: true });
  rows.push({ seq: 2, origin: 'them', kind: 'minted', realm: '', key: 'two',
              visible: false });
  let open = null;
  state.gate = new Promise(function (resolve) { open = resolve; });
  const inFlight = replication.pull();
  await settle();
  // Seq 2 commits AFTER the in-flight pull read its page and BEFORE the
  // barrier is asked for.
  rows[1].visible = true;
  state.gate = null;
  const barrier = replication.syncNow();
  await settle();
  open();
  await inFlight;
  const answer = await bounded(barrier, 3000);
  t.check(answer && answer.caughtUp, 'the barrier reports caught up',
          JSON.stringify(answer));
  t.check(applied.indexOf('two') >= 0,
          'A PULL ALREADY IN FLIGHT IS NOT THE PROOF: the row that committed ' +
          'after its page was read and before the barrier was asked for is ' +
          'applied before the barrier answers — this pins the rule ' +
          'cluster_foundation.js section 2 could not time',
          applied.join(','));
  t.equal(state.headQueries, 0,
          'AND NO HEAD QUERY WAS MADE. It walked every row this node had ' +
          'written, and measured as a read going from 4ms to 68ms as the log ' +
          'grew; the pull that started after the call proves as much');
  replication.reset();
  log.debug("Leaving barrierWithoutHead().");
}

// ---------------------------------------------------------------------------
// 4. THE DIRECTORY'S WRITE POSITION AND ITS COMMIT, on an ldif store.
// ---------------------------------------------------------------------------
async function directoryPosition(t, dir) {
  log.debug("Entering directoryPosition().");
  t.log.info('=== 4. a response waits for the commit covering its writes ===');
  process.env.STS_PERSISTENCE_MODE = 'ldif';
  process.env.STS_PERSISTENCE_DATA_DIR = dir;
  process.env.STS_PERSISTENCE_APPCONFIG = 'true';
  process.env.STS_PERSISTENCE_REALMS = 'true';
  process.env.STS_PERSISTENCE_WRITE_DELAY = '50';
  const config = require('../common/config');
  const persistence = require('../persistence/persistence');
  persistence.setDirectory({
    realmEntries: function () {
      log.debug("Entering realmEntries().");
      log.debug("Leaving realmEntries().");
      return [];
    },
    replaceRealm: function () {
      log.debug("Entering replaceRealm().");
      log.debug("Leaving replaceRealm().");
      return undefined;
    }
  });
  await persistence.start();
  await persistence.flush();
  const before = persistence.writeGeneration();
  config.setOverride('audit.maxEvents', '1111');
  const after = persistence.writeGeneration();
  t.check(after.directory > before.directory,
          'A WRITE MOVES THE POSITION — what the barrier compares at arrival ' +
          'and at the answer', JSON.stringify([before, after]));
  const file = path.join(dir, 'appconfig.json');
  const answers = await bounded(persistence.commitThrough(after), 3000);
  t.check(Array.isArray(answers), 'commitThrough() settles with the answers',
          JSON.stringify(answers));
  const onDisk = fs.existsSync(file)
    ? JSON.parse(fs.readFileSync(file, 'utf8')) : {};
  t.equal(String((onDisk.overrides || {})['audit.maxEvents']), '1111',
          'AND WHEN IT SETTLES THE WRITE IS IN THE STORE — without waiting ' +
          'out the 50ms write delay the scheduled flush would have');
  const writes = persistence.status().writes;
  await bounded(persistence.commitThrough(after), 3000);
  t.equal(persistence.status().writes, writes,
          'A POSITION ALREADY COMMITTED COSTS NO FLUSH: the second wait ' +
          'wrote nothing');
  await persistence.stop();
  log.debug("Leaving directoryPosition().");
}

// ---------------------------------------------------------------------------
// 2. THE MINTED FLUSH THAT COVERS A GENERATION, AND NO MORE THAN IT.
// ---------------------------------------------------------------------------
async function armKeystore(dir) {
  log.debug("Entering armKeystore().");
  const keystore = require('../common/keystore');
  const kekFile = path.join(dir, 'kek');
  fs.writeFileSync(kekFile, nodeCrypto.randomBytes(32).toString('base64'),
                   { encoding: 'utf8', mode: 0o600 });
  process.env.STS_KEYS_SOURCE = 'persisted';
  process.env.STS_KEYS_KEK_PROVIDER = 'file';
  process.env.STS_KEYS_KEK_FILE = kekFile;
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
  log.debug("Leaving armKeystore().");
}

async function mintedGenerations(t, dir) {
  log.debug("Entering mintedGenerations().");
  t.log.info('=== 2. a held response waits for ITS flush ===');
  const config = require('../common/config');
  const realms = require('../common/realms');
  const minted = require('../persistence/persistence_minted');
  await armKeystore(dir);
  config.setOverride('global.mode', 'product');
  config.setOverride('persistence.minted', true);
  const calls = [];
  const state = { hold: false };
  const driver = {
    origin: function () {
      log.debug("Entering origin().");
      log.debug("Leaving origin().");
      return 'process-a';
    },
    loadMinted: function () {
      log.debug("Entering loadMinted().");
      log.debug("Leaving loadMinted().");
      return Promise.resolve([]);
    },
    saveMinted: function (upserts) {
      log.debug("Entering saveMinted().");
      const call = { keys: upserts.map(function (row) { return row.key; }),
                     release: null };
      calls.push(call);
      if (!state.hold) {
        log.debug("Leaving saveMinted().");
        return Promise.resolve();
      }
      state.hold = false;
      log.debug("Leaving saveMinted().");
      return new Promise(function (resolve) {
        call.release = resolve;
      });
    }
  };
  minted.reset();
  t.check(minted.setDriver(driver, 'postgres'),
          'the minted store is installed');
  const sessions = realms.map({ persist: 'test.throughput.sessions' });

  sessions.set('s1', { v: 1 });
  const g1 = minted.generation();
  state.hold = true;
  const first = minted.flush();
  const covered = minted.flushThrough(g1);
  await settle();
  t.check(covered === first,
          'A FLUSH IN FLIGHT THAT TOOK THE WRITE IS THE ONE WAITED FOR — not ' +
          'the one flush() would queue behind it, which under concurrent ' +
          'writers is a second transaction holding none of this response\'s ' +
          'writes');
  sessions.set('s2', { v: 2 });
  const g2 = minted.generation();
  const behind = minted.flushThrough(g2);
  await settle();
  t.equal(calls.length, 1,
          'a write made after the take waits for the flush in flight to ' +
          'settle before its own starts');
  t.check(minted.committedGeneration() < g1,
          'nothing counts as committed while the transaction is open');
  calls[0].release();
  await bounded(first);
  t.check(minted.committedGeneration() >= g1,
          'the generation the take covered is committed when it lands');
  const later = await bounded(behind);
  t.check(later !== 'timed out' && minted.committedGeneration() >= g2,
          'and the later write\'s own flush follows and commits it',
          JSON.stringify(later));
  t.equal(calls.length, 2, 'two writes, one per take');
  await bounded(minted.flushThrough(g2));
  t.equal(calls.length, 2,
          'A GENERATION ALREADY COMMITTED IS ANSWERED WITHOUT A WRITE');
  sessions.clear();
  minted.reset();
  config.setOverride('global.mode', 'development');
  log.debug("Leaving mintedGenerations().");
}

// ---------------------------------------------------------------------------
// 5. THE REAL APP: WHO IS HELD, AND A REALM NOT YET HERE.
// ---------------------------------------------------------------------------
function request(port, method, urlPath) {
  log.debug("Entering request().");
  log.debug("Leaving request().");
  return new Promise(function (resolve) {
    const began = Date.now();
    const req = http.request({ host: '127.0.0.1', port: port, path: urlPath,
                               method: method,
                               headers: { 'content-length': 0 } },
                             function (res) {
      let text = '';
      res.on('data', function (chunk) { text += chunk; });
      res.on('end', function () {
        resolve({ status: res.statusCode, text: text,
                  ms: Date.now() - began });
      });
    });
    req.on('error', function (e) {
      resolve({ status: 0, text: String(e && e.message), ms: 0 });
    });
    req.end();
  });
}

async function theApp(t) {
  log.debug("Entering theApp().");
  t.log.info('=== 5. the call log\'s rows, the hold, and a late realm ===');
  const realms = require('../common/realms');
  const cluster = require('../cluster/cluster');
  const persistence = require('../persistence/persistence');
  const position = { directory: 0, minted: 0 };
  const commits = [];
  // From section "a realm not yet here" on, a hold's commit lands at once: a
  // 404 is a refusal and is held for its audit row.
  const autoCommit = { value: false };
  const sync = { count: 0, onSync: null };
  const active = { value: true };
  cluster.isActiveActive = function () {
    log.debug("Entering the stubbed isActiveActive().");
    log.debug("Leaving the stubbed isActiveActive().");
    return active.value;
  };
  cluster.enabled = function () {
    log.debug("Entering the stubbed enabled().");
    log.debug("Leaving the stubbed enabled().");
    return active.value;
  };
  persistence.writeGeneration = function () {
    log.debug("Entering the stubbed writeGeneration().");
    log.debug("Leaving the stubbed writeGeneration().");
    return { directory: position.directory, minted: position.minted };
  };
  persistence.keysPending = function () {
    log.debug("Entering the stubbed keysPending().");
    log.debug("Leaving the stubbed keysPending().");
    return false;
  };
  persistence.commitThrough = function (target) {
    log.debug("Entering the stubbed commitThrough().");
    log.debug("Leaving the stubbed commitThrough().");
    if (autoCommit.value) {
      return Promise.resolve([]);
    }
    return new Promise(function (resolve) {
      commits.push({ target: target, resolve: resolve });
    });
  };
  persistence.syncNow = function () {
    log.debug("Entering the stubbed syncNow().");
    sync.count += 1;
    if (sync.onSync) {
      sync.onSync();
    }
    log.debug("Leaving the stubbed syncNow().");
    return Promise.resolve({ caughtUp: true, coordinating: true });
  };
  // Every write any store journals moves the minted position — the call
  // log's tally and audit row among them.
  realms.setPersistObserver(function () {
    position.minted += 1;
  });
  const app = require('../common/app');
  app.get('/test/throughput/read', function (req, res) {
    log.debug("Entering the test read route.");
    log.debug("Leaving the test read route.");
    res.json({ ok: true });
  });
  app.get('/test/throughput/write', function (req, res) {
    log.debug("Entering the test write route.");
    position.directory += 1;
    log.debug("Leaving the test write route.");
    res.json({ ok: true });
  });
  const server = http.createServer(app);
  await new Promise(function (resolve) {
    server.listen(0, '127.0.0.1', resolve);
  });
  const port = server.address().port;
  try {
    // A SUCCESSFUL READ.
    const mintedBefore = position.minted;
    const read = await bounded(request(port, 'GET', '/test/throughput/read'),
                               3000);
    t.equal(read.status, 200, 'a read answers');
    t.check(position.minted > mintedBefore,
            'its call log wrote — a tally and an audit row — so "not held" ' +
            'below is a decision and not an absence',
            String(position.minted - mintedBefore));
    t.equal(commits.length, 0,
            'A SUCCESSFUL READ IS NOT HELD FOR ITS OWN CALL-LOG ROWS. ' +
            'Holding ' +
            'for them made every request in the service pay a transaction: ' +
            'a discovery document at 23-66ms where it is 3ms');

    // A REFUSAL.
    const refusing = request(port, 'POST', '/healthcheck');
    await sleep(150);
    t.equal(commits.length, 1,
            'A REFUSED REQUEST IS HELD FOR ITS AUDIT ROW\'S COMMIT, ' +
            'though it ' +
            'wrote nothing else');
    const early = await bounded(refusing, 50);
    t.equal(early, 'timed out',
            'and it is not answered until that commit lands — so the other ' +
            'node\'s next audit read lists it (the `admin_api` job)');
    commits[0].resolve([]);
    const refused = await bounded(refusing, 3000);
    t.check(refused && refused.status === 404 &&
            /Cannot POST \/healthcheck/.test(refused.text),
            'then it is answered, with Express\'s own 404 body',
            JSON.stringify(refused));
    t.check(commits[0].target.minted >= mintedBefore,
            'the commit waited for covers the row recorded in end()',
            JSON.stringify(commits[0].target));

    // A WRITE.
    const writing = request(port, 'GET', '/test/throughput/write');
    await sleep(150);
    t.equal(commits.length, 2, 'A REQUEST THAT WROTE IS HELD, as ever');
    commits[1].resolve([]);
    const wrote = await bounded(writing, 3000);
    t.equal(wrote.status, 200, 'and answered once its commit lands');

    // A REALM NOT YET HERE.
    autoCommit.value = true;
    const realmId = 'late-throughput';
    let synced = sync.count;
    const control = await bounded(request(port, 'GET',
      '/realm/never-throughput/healthcheck'), 10000);
    t.check(control.status === 404 &&
            /Cannot GET \/realm\/never-throughput\/healthcheck/
              .test(control.text),
            'a realm that does not exist anywhere is still Express\'s own ' +
            '404 — `Cannot GET` is what sts_metadata.js reads',
            JSON.stringify(control).slice(0, 300));
    t.equal(sync.count - synced, 1,
            'and the request caught up once, not once in the realm ' +
            'middleware and again in the barrier');
    active.value = false;
    sync.onSync = function () {
      realms.create({ id: realmId });
    };
    synced = sync.count;
    const inactive = await bounded(request(port, 'GET',
      '/realm/' + realmId + '/healthcheck'), 10000);
    t.equal(inactive.status, 404,
            'THE CONTROL: with the node not active-active the realm ' +
            'middleware does not catch up, so a realm the catch-up would ' +
            'have brought is ' +
            'a 404 — which is what node B answered two times in six');
    t.equal(sync.count - synced, 0, 'and no catch-up ran');
    active.value = true;
    synced = sync.count;
    const late = await bounded(request(port, 'GET',
      '/realm/' + realmId + '/healthcheck'), 20000);
    t.equal(late.status, 200,
            'A REALM ANOTHER NODE HAS JUST CREATED ANSWERS THIS NODE\'S ' +
            'FIRST ' +
            'REQUEST: the realm middleware caught up before falling through',
            JSON.stringify(late).slice(0, 300));
    t.equal(sync.count - synced, 1,
            'with one catch-up for the request');
    sync.onSync = null;
    synced = sync.count;
    const plain = await bounded(request(port, 'GET', '/healthcheck'), 3000);
    t.equal(plain.status, 200, 'a path outside every realm answers');
    t.equal(sync.count - synced, 1,
            'and catches up once, in the barrier, as before');
  } finally {
    server.close();
  }
  log.debug("Leaving theApp().");
}

async function childMain() {
  log.debug("Entering childMain().");
  delete process.env.CONFIG_FILE;
  const out = process.env.PROBE_OUT;
  const t = recordingHarness();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-barrier-tp-'));
  let threw = '';
  try {
    segmentedRing(t);
    await barrierWithoutHead(t);
    await directoryPosition(t, path.join(dir, 'ldif'));
    await mintedGenerations(t, dir);
    await theApp(t);
  } catch (e) {
    log.debug("Caught in childMain(): " + ((e && e.message) || e));
    threw = (e && e.stack) || String(e);
  } finally {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch (e) {
      log.debug("Caught in childMain(): " + ((e && e.message) || e));
    }
  }
  fs.writeFileSync(out, JSON.stringify({ seen: t.seen, threw: threw }));
  log.debug("Leaving childMain().");
  // Timers from the app and the store may still be armed; the answer is out.
  process.exit(0);
}

function run(t) {
  log.debug("Entering run().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-barrier-tp-out-'));
  const outFile = path.join(dir, 'out.json');
  const env = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|CONFIG_FILE$)/.test(key)) {
      env[key] = process.env[key];
    }
  });
  Object.assign(env, { PROBE_OUT: outFile, LOG_LEVEL: 'fatal' });
  env[CHILD_FLAG] = '1';
  const child = childProcess.spawnSync(process.execPath, [__filename],
    { cwd: path.join(__dirname, '..'), env: env, encoding: 'utf8',
      timeout: 120000 });
  let result = null;
  try {
    result = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    t.bad('the child process reported nothing',
          'status ' + child.status + ', signal ' + child.signal + ': ' +
          String(child.stderr || '').slice(-2000));
    log.debug("Leaving run().");
    return;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  result.seen.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  if (result.threw) {
    t.bad('the child process threw', result.threw);
  }
  t.check(result.seen.length >= 40,
          'every section ran — a section that stopped being reached would ' +
          'take its assertions with it and still say "passed"',
          String(result.seen.length) + ' assertion(s) recorded');
  log.debug("Leaving run().");
}

if (require.main === module && process.env[CHILD_FLAG] === '1') {
  childMain();
}

module.exports = {
  name: 'cluster_barrier_throughput',
  describe: 'issue #46 cluster throughput: the segmented audit ring, holding ' +
            'a response for its own commit, the barrier without a head ' +
            'query, the call log inside the hold, and a realm created on ' +
            'another node',
  run: run
};
