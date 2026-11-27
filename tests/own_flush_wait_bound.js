// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: own_flush_wait_bound.js
//
// ===========================================================================
// A CHANGE-LOG APPLY WAITS ON ITS OWN PROCESS'S FLUSH FOR A BOUNDED TIME,
// SAYS SO, AND DROPS NOTHING (#1934).
//
// `applyDirectoryChange()` (persistence/persistence.js) waits for the running
// flush when the entry it is about to apply is in that flush. Until #1934
// the wait had no bound and no line: in run #551 a flush that never settled
// (#1933's removed realm) held a request worker's pull for 44 minutes, every
// read-your-write request on it was refused (STS-WORKER-0053), and the
// barrier's STS-STORE-0039 line did not say that the applier was waiting on
// its own process.
//
// Over `cluster_lww_stores.js`'s PostgreSQL double, with a directory flush
// held open at its COMMIT and never released until the end, and the bound
// (`workers.readBarrierTimeoutMs`) at its minimum of 1000 ms:
//
//   1. a read barrier with an apply waiting on the held flush ANSWERS, at
//      its own deadline, `caughtUp: false` — the pull is not wedged for
//      ever;
//   2. its STS-STORE-0039 line says the apply is waiting on this process's
//      own flush, names the entry, and how long;
//   3. a wait past the bound is STS-STORE-0176, logged ONCE for the flush
//      however many pulls waited it out;
//   4. as a request worker, the process asks the front to replace it, once
//      (`{ replaceWorker }` on the worker channel) — and only once its flush
//      is STUCK, out four bounds since it began, not at the first bound a
//      wait runs out (STS-STORE-0177); the ask carries the flush's start
//      and the instant it is given up on, ten bounds after it began, and
//      a drain's `settleOwnFlush()` waits for the held flush and answers
//      true once it lands, so a flush that is only slow keeps its writes;
//   5. NO ROW IS DROPPED: no STS-STORE-0042, and once the flush settles the
//      next barrier catches up and the other node's change is applied;
//   6. the front process (no STS_REQUEST_WORKER) reports a second wedged
//      flush on its own line and asks nobody to replace it.
//
// The front process's half — a worker that asks is retired and replaced in
// its slot — is `tests/request_worker_replacement.js`.
//
// IN A CHILD PROCESS, for `cluster_lww_stores.js`'s reason: `persistence.js`
// has one life a process, and the runner shares its process with every
// other file.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'own_flush_wait_bound',
  level: process.env.LOG_LEVEL || 'info' });

const CHILD_FLAG = 'STS_TEST_OWN_FLUSH_WAIT_CHILD';
const LOCK_KEY = 'uid=fwbcarol,dc=fwb';

function tick(ms) {
  log.debug("Entering tick().");
  log.debug("Leaving tick().");
  return new Promise(function (resolve) { setTimeout(resolve, ms || 5); });
}

// The promise's answer, or `'wedged'` when it has not settled by `ms`.
function settledWithin(promise, ms) {
  log.debug("Entering settledWithin().");
  let timer = null;
  const deadline = new Promise(function (resolve) {
    timer = setTimeout(function () {
      resolve('wedged');
    }, ms);
  });
  log.debug("Leaving settledWithin().");
  return Promise.race([promise, deadline]).finally(function () {
    clearTimeout(timer);
  });
}

function entry(dn, attributes) {
  log.debug("Entering entry().");
  log.debug("Leaving entry().");
  return { dn: dn, attributes: attributes, createdAt: '20261119000000Z',
           modifiedAt: '20261119000000Z' };
}

// ---------------------------------------------------------------------------
// THE CHILD.
// ---------------------------------------------------------------------------
async function childMain() {
  log.debug("Entering childMain().");
  delete process.env.CONFIG_FILE;
  const seen = [];
  const check = function (condition, what, detail) {
    log.debug("Entering check().");
    seen.push({ ok: !!condition, what: what, detail: detail || '' });
    log.debug("Leaving check().");
    return !!condition;
  };
  // EVERY LINE THE SERVICE WRITES, kept: bunyan writes JSON to stdout, and
  // the codes are at the front of each message.
  const lines = [];
  const write = process.stdout.write.bind(process.stdout);
  process.stdout.write = function (chunk) {
    lines.push(String(chunk));
    return true;
  };
  let threw = '';
  try {
    const lww = require('./cluster_lww_stores');
    const db = lww.fakeDatabase();
    require('./tools/store_double').install(lww.fakePg(db));
    process.env.STS_PERSISTENCE_MODE = 'postgres';
    process.env.STS_PERSISTENCE_COORDINATE = 'true';
    process.env.STS_WORKERS_READ_BARRIER_TIMEOUT_MS = '1000';
    // THE CHANNEL TO THE FRONT PROCESS, recorded: outside a worker thread
    // send() is a no-op, and what is asserted is what would have been sent.
    const sent = [];
    const channel = require('../common/worker_channel');
    channel.send = function (message) {
      sent.push(message);
      return true;
    };
    const realms = require('../common/realms');
    const persistence = require('../persistence/persistence');
    const dirs = new Map();
    persistence.setDirectory({
      realmEntries: function (realmId) {
        const held = dirs.get(realmId) || new Map();
        return Array.from(held.keys()).map(function (key) {
          return { key: key, entry: held.get(key) };
        });
      },
      replaceRealm: function (realmId, list) {
        const held = new Map();
        list.forEach(function (row) {
          held.set(String(row.dn).toLowerCase(), row);
        });
        dirs.set(realmId, held);
      },
      entryAt: function (realmId, key) {
        return (dirs.get(realmId) || new Map()).get(key) || null;
      },
      applyEntry: function (realmId, key, row) {
        const held = dirs.get(realmId) || new Map();
        held.set(key, row);
        dirs.set(realmId, held);
      },
      removeEntry: function (realmId, key) {
        (dirs.get(realmId) || new Map()).delete(key);
      }
    });
    await persistence.start();
    check(persistence.activeMode() === 'postgres',
          'precondition: the store opened over the double',
          JSON.stringify(persistence.status().lastError || ''));
    await persistence.coordinate();
    realms.create({ id: 'fwb', name: 'fwb' });
    await persistence.flush();
    dirs.set('fwb', new Map());
    const PERSON = { uid: ['fwbcarol'], entryuuid: ['fwb-1'] };
    let heldSince = 0;
    const carol = function (attributes) {
      log.debug("Entering carol().");
      dirs.get('fwb').set(LOCK_KEY, entry(LOCK_KEY, attributes));
      persistence.directoryChanged();
      log.debug("Leaving carol().");
    };
    carol(Object.assign({}, PERSON));
    await persistence.flush();
    check(db.entries.has('fwb\n' + LOCK_KEY),
          'precondition: the entry is committed');

    // FROM HERE THIS PROCESS IS A REQUEST WORKER, as far as the wedge's
    // report is concerned (read when it is reported). Set after start(),
    // which as a worker would claim an origin slot the double cannot grant.
    process.env.STS_REQUEST_WORKER = '1';

    // THE FLUSH HELD OPEN, AND NEVER RELEASED UNTIL STEP 5.
    let release = null;
    db.hold = new Promise(function (resolve) {
      release = resolve;
    });
    carol(Object.assign({ title: ['here'] }, PERSON));
    heldSince = Date.now();
    const heldFlush = persistence.flush();
    await tick(30);
    // ANOTHER NODE WRITES THE SAME ENTRY, and says so in the change log.
    db.entries.set('fwb\n' + LOCK_KEY, { realm: 'fwb', dn_key: LOCK_KEY,
      dn: LOCK_KEY, attrs: Object.assign({ description: ['node b'] },
                                         PERSON),
      origin: 'node-b', created_at: '1', modified_at: '2' });
    db.log.push({ seq: db.log.length + 1, origin: 'node-b', kind: 'directory',
                  realm: 'fwb', key: LOCK_KEY });
    const began = Date.now();
    const barrier = await settledWithin(persistence.syncNow(), 15000);
    const tookMs = Date.now() - began;

    // 1.
    check(barrier !== 'wedged' && barrier && barrier.caughtUp === false,
          '1. A READ BARRIER WITH AN APPLY WAITING ON THE HELD FLUSH ' +
          'ANSWERS caughtUp: false — the pull is bounded, not wedged',
          JSON.stringify(barrier) + ' after ' + tookMs + ' ms');
    // 2.
    const gaveUp = lines.filter(function (line) {
      return line.indexOf('STS-STORE-0039') >= 0;
    });
    check(gaveUp.some(function (line) {
      // Waiting at the instant the barrier gives up, or between two pulls
      // with the flush still out: which depends on where the deadline
      // falls, and both name the entry, the time and the bound.
      return line.indexOf('ON THIS PROCESS\'S OWN FLUSH') >= 0 &&
        line.indexOf(LOCK_KEY) >= 0 &&
        (/for \d+ ms \(1 apply\(ies\) waiting; bounded at 1000 ms/
          .test(line) ||
         /past its bound of 1000 ms .*still out \d+ ms after/.test(line));
    }), '2. ITS STS-STORE-0039 LINE SAYS THE APPLY IS WAITING ON THIS ' +
       'PROCESS\'S OWN FLUSH, names the entry and how long',
    gaveUp.join('').slice(-1500));
    // 3.
    const wedged = lines.filter(function (line) {
      return line.indexOf('"msg":"[STS-STORE-0176]') >= 0 &&
        /"level":50/.test(line);
    });
    const failedPulls = lines.filter(function (line) {
      return line.indexOf('[STS-STORE-0038]') >= 0;
    });
    const waits = (barrier && barrier !== 'wedged') ? tookMs : 0;
    check(wedged.length === 1 && failedPulls.length === 0 && waits >= 2000,
          '3. A WAIT PAST THE BOUND IS STS-STORE-0176, LOGGED ONCE for the ' +
          'flush though several pulls waited it out (and no STS-STORE-0038 ' +
          'a pull)', wedged.length + ' error line(s), ' + failedPulls.length +
          ' STS-STORE-0038 line(s), the barrier held ' + tookMs + ' ms: ' +
          wedged.join('').slice(0, 800));
    check(wedged.length === 1 && wedged[0].indexOf(LOCK_KEY) >= 0 &&
          wedged[0].indexOf('asks the front process to replace it only if ' +
                            'the flush is still out 4000 ms') >= 0,
          '3b. and the line names the entry and says this worker asks to ' +
          'be replaced only once the flush is stuck',
          wedged.join('').slice(0, 800));
    // 4. SLOW IS NOT STUCK: nothing is asked while the flush is younger
    // than four bounds (4000 ms here).
    const askedEarly = sent.filter(function (message) {
      return message && message.replaceWorker;
    }).length;
    const ageThen = Date.now() - heldSince;
    check(ageThen >= 4000 || askedEarly === 0,
          '4a. A FLUSH THAT IS ONLY SLOW IS NOT A REASON TO BE REPLACED: ' +
          'no ask while it is out less than four bounds',
          askedEarly + ' ask(s) with the flush out ' + ageThen + ' ms');
    // A DRAIN WAITS FOR THE FLUSH: still out, the wait has not answered.
    // Started now, well inside the ten bounds (10000 ms) it is given.
    const drained = persistence.settleOwnFlush();
    const drainedEarly = await settledWithin(drained, 500);
    if (Date.now() - heldSince < 4300) {
      await tick(4300 - (Date.now() - heldSince));
    }
    db.log.push({ seq: db.log.length + 1, origin: 'node-b', kind: 'directory',
                  realm: 'fwb', key: LOCK_KEY });
    // The pull is not awaited whole: the flush is released as soon as the
    // ask is sent, before the ten bounds are up, as a slow flush would land.
    const stuckPull = persistence.syncNow();
    const askedBy = Date.now() + 10000;
    while (Date.now() < askedBy && !sent.some(function (message) {
      return message && message.replaceWorker;
    })) {
      await tick(50);
    }
    const asks = sent.filter(function (message) {
      return message && message.replaceWorker;
    });
    const flushingAsk = (asks[0] && asks[0].replaceWorker.flushing) || {};
    check(asks.length === 1 &&
          asks[0].replaceWorker.code === 'STS-STORE-0177' &&
          String(asks[0].replaceWorker.reason).indexOf(LOCK_KEY) >= 0 &&
          flushingAsk.since > 0 &&
          flushingAsk.giveUpAt === flushingAsk.since + 10000,
          '4. ONCE IT IS STUCK, AS A REQUEST WORKER IT ASKS THE FRONT ' +
          'PROCESS TO REPLACE IT, ONCE, carrying the flush\'s start and the ' +
          'instant it is given up on (ten bounds after it began)',
          JSON.stringify(asks));
    check(lines.filter(function (line) {
      return line.indexOf('"msg":"[STS-STORE-0177]') >= 0;
    }).length === 1, '4b. and says so once, under STS-STORE-0177',
    lines.filter(function (line) {
      return line.indexOf('STS-STORE-0177') >= 0;
    }).join('').slice(0, 800));
    check(drainedEarly === 'wedged' &&
          (persistence.ownFlushInFlight() || {}).giveUpAt ===
            flushingAsk.giveUpAt,
          '4c. A DRAIN\'S settleOwnFlush() WAITS while the flush is out, ' +
          'with the same give-up instant the ask carried',
          JSON.stringify(persistence.ownFlushInFlight()));

    // 5.
    check(!lines.some(function (line) {
      return line.indexOf('STS-STORE-0042') >= 0;
    }), '5. NO ROW IS DROPPED: no "could not be applied" (STS-STORE-0042)',
    lines.filter(function (line) {
      return line.indexOf('STS-STORE-0042') >= 0;
    }).join('').slice(0, 800));
    db.hold = null;
    release();
    await settledWithin(heldFlush, 5000);
    await settledWithin(stuckPull, 15000);
    check(await settledWithin(drained, 5000) === true &&
          persistence.ownFlushInFlight() === null,
          '4d. and answers true once the flush lands: a slow flush keeps its ' +
          'writes', '');
    const after = await settledWithin(persistence.syncNow(), 15000);
    check(after !== 'wedged' && after && after.caughtUp === true,
          '5b. once the flush settles the next barrier catches up',
          JSON.stringify(after));
    const live = dirs.get('fwb').get(LOCK_KEY) || { attributes: {} };
    check(String(live.attributes.description) === 'node b',
          '5c. AND THE OTHER NODE\'S CHANGE THE WEDGED PULLS COULD NOT ' +
          'APPLY IS APPLIED — read again from the log, not lost',
          JSON.stringify(live.attributes));

    // 6. THE FRONT PROCESS, AND A SECOND FLUSH THAT DOES NOT SETTLE.
    delete process.env.STS_REQUEST_WORKER;
    const before = lines.length;
    let release2 = null;
    db.hold = new Promise(function (resolve) {
      release2 = resolve;
    });
    carol(Object.assign({ title: ['again'] }, live.attributes));
    const heldFlush2 = persistence.flush();
    await tick(30);
    db.log.push({ seq: db.log.length + 1, origin: 'node-b', kind: 'directory',
                  realm: 'fwb', key: LOCK_KEY });
    const barrier2 = await settledWithin(persistence.syncNow(), 15000);
    const wedged2 = lines.slice(before).filter(function (line) {
      return line.indexOf('"msg":"[STS-STORE-0176]') >= 0 &&
        /"level":50/.test(line);
    });
    check(barrier2 !== 'wedged' && barrier2.caughtUp === false &&
          wedged2.length === 1 &&
          wedged2[0].indexOf('This is the front process') >= 0,
          '6. THE FRONT PROCESS REPORTS A SECOND WEDGED FLUSH ON ITS OWN ' +
          'LINE, saying nothing replaces it',
          JSON.stringify(barrier2) + ' ' + wedged2.join('').slice(0, 800));
    check(sent.filter(function (message) {
      return message && message.replaceWorker;
    }).length === 1, '6b. and asks nobody to replace it',
    JSON.stringify(sent));
    db.hold = null;
    release2();
    await settledWithin(heldFlush2, 5000);
    await persistence.stop();
  } catch (e) {
    log.debug("Caught in childMain(): " + ((e && e.message) || e));
    threw = (e && e.stack) || String(e);
  }
  process.stdout.write = write;
  fs.writeFileSync(process.env.PROBE_OUT,
                   JSON.stringify({ seen: seen, threw: threw }));
  log.debug("Leaving childMain().");
  process.exit(0);
}

function run(t) {
  log.debug("Entering run().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-own-flush-'));
  const outFile = path.join(dir, 'out.json');
  const env = Object.assign({}, process.env, { PROBE_OUT: outFile });
  env[CHILD_FLAG] = '1';
  delete env.CONFIG_FILE;
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
  t.check(result.seen.length >= 16,
          'every step ran — a step that stopped being reached would take ' +
          'its assertions with it and still say "passed"',
          String(result.seen.length) + ' assertion(s) recorded');
  log.debug("Leaving run().");
}

if (require.main === module && process.env[CHILD_FLAG] === '1') {
  childMain();
}

module.exports = {
  name: 'own_flush_wait_bound',
  describe: 'issue #1934: a change-log apply waiting on its own process\'s ' +
            'flush is bounded by workers.readBarrierTimeoutMs, named on the ' +
            'barrier\'s STS-STORE-0039 line, reported once (STS-STORE-0176), ' +
            'asks a request worker\'s replacement, and drops no row',
  run: run
};
