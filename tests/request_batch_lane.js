'use strict';
//
// File: request_batch_lane.js
//
// ===========================================================================
// BATCH TRAFFIC MAY USE A SHARE OF A POOL'S WORKERS AND A NUMBER OF REQUESTS IN
// FLIGHT, AND WAITS FOR THE REST (2026-09-14).
//
// `common/request_pool.js`'s batch lane, asserted on its decisions rather than
// by starting a pool, on `tests/request_barrier.js`'s argument: what could be
// wrong is bookkeeping over settings and closures. The run that asked for it:
// a SCIM bulk load whose every write pushed Shared Signals events back into
// this service took every worker, and nothing was answered for fourteen
// minutes.
//
//   1. which paths are batch — the default list, the realm segment stripped,
//      a segment boundary, and empty turning the lane off;
//   2. how many workers a lane is — at least one, one fewer than the pool
//      unless the pool is one worker or the share is 100 — and that it is the
//      FIRST workers by fork order, so it is stable;
//   3. admission — at the cap a request waits, a release starts the next in
//      order, a full queue is a 503 with Retry-After and STS-WORKER-0040, a
//      request that waits too long is a 503 with STS-WORKER-0041, a client that
//      leaves is dropped from the queue, and a cap of 0 queues nothing;
//   4. a request already BOUND to a worker keeps it: `workerFor()` asks for
//      the held binding before the lane narrows anything — read as source,
//      because the binding is what stops two read-modify-writes of one SCIM
//      resource losing an update, and nothing without a worker can reach it.
// ===========================================================================

const fs = require('fs');
const path = require('path');
const EventEmitter = require('events');

const config = require('../common/config');
const pool = require('../common/request_pool');

const log = require('bunyan').createLogger({ name: 'request_batch_lane',
  level: process.env.LOG_LEVEL || 'info' });

// A response as the lane touches one: status, headers, a body, `finish` and
// `close`, and the two flags it reads.
function fakeResponse() {
  log.debug("Entering fakeResponse().");
  const res = new EventEmitter();
  res.statusCode = 200;
  res.headers = {};
  res.body = '';
  res.headersSent = false;
  res.writableEnded = false;
  res.destroyed = false;
  res.status = function (code) {
    res.statusCode = code;
    return res;
  };
  res.set = function (name, value) {
    res.headers[name] = value;
    return res;
  };
  res.type = function () {
    return res;
  };
  res.send = function (text) {
    res.body = String(text);
    res.headersSent = true;
    res.writableEnded = true;
    res.emit('finish');
    res.emit('close');
    return res;
  };
  log.debug("Leaving fakeResponse().");
  return res;
}

function codeOf(res) {
  log.debug("Entering codeOf().");
  log.debug("Leaving codeOf().");
  return require('../common/error_codes').codeOf(res);
}

// Set some settings for the length of `fn`, and clear them afterwards.
function withSettings(values, fn) {
  log.debug("Entering withSettings().");
  Object.keys(values).forEach(function (key) {
    config.setOverride(key, values[key]);
  });
  log.debug("Leaving withSettings().");
  return Promise.resolve().then(fn).finally(function () {
    Object.keys(values).forEach(function (key) {
      try {
        config.clearOverride(key);
      } catch (e) {
        // Nothing was overridden, which is the state wanted.
        log.debug("Caught in withSettings(): " + ((e && e.message) || e));
      }
    });
  });
}

function wait(ms) {
  log.debug("Entering wait().");
  log.debug("Leaving wait().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

async function run(t) {
  t.log.debug('Entering run().');
  const PROTO = pool.PROTOCOL_POOL;

  // 1. WHICH PATHS ARE BATCH.
  t.check(pool.isBatch('/scim/v2/Users'), 'SCIM is batch by default');
  t.check(pool.isBatch('/realm/acme/scim/v2/Groups/g1'),
          'with the realm segment stripped first');
  t.check(pool.isBatch('/admin/signals/receive') &&
          pool.isBatch('/realm/acme/portal/signals/receive'),
          'and this service\'s own two Shared Signals receive endpoints');
  t.check(!pool.isBatch('/admin/users') && !pool.isBatch('/scimx') &&
          !pool.isBatch('/oauth2/token'),
          'and not the console, a longer name, or a protocol endpoint');
  await withSettings({ 'workers.batch': '' }, function () {
    t.check(!pool.isBatch('/scim/v2/Users'),
            'an EMPTY workers.batch turns the lane off');
  });

  // 2. HOW MANY WORKERS, AND WHICH.
  t.equal(pool.laneSize(1, 50), 1, 'a pool of one is a lane of one');
  t.equal(pool.laneSize(2, 50), 1, 'two workers at 50% is one');
  t.equal(pool.laneSize(3, 50), 1, 'three at 50% is one');
  t.equal(pool.laneSize(4, 50), 2, 'four at 50% is two');
  t.equal(pool.laneSize(3, 99), 2,
          'ALWAYS ONE FEWER THAN THE POOL below 100%, so a worker is left ' +
          'for everything else');
  t.equal(pool.laneSize(3, 100), 3, 'and 100% is every worker');
  t.equal(pool.laneSize(5, 1), 1, 'and never fewer than one');
  const ready = [{ pid: 30, startedAt: 3000 }, { pid: 10, startedAt: 1000 },
                 { pid: 20, startedAt: 2000 }, { pid: 40, startedAt: 4000 }];
  await withSettings({ 'workers.batchWorkerShare': 50 }, function () {
    t.equal(pool.laneOf(ready).map(function (one) { return one.pid; })
              .join(','), '10,20',
            'THE LANE IS THE FIRST WORKERS BY FORK ORDER, so it is the same ' +
            'lane on every request');
  });
  t.equal(pool.leastLoaded(PROTO, [{ pid: 7, inFlight: 3, served: 0 },
                                   { pid: 8, inFlight: 1, served: 9 }]).pid, 8,
          'leastLoaded() chooses only among the lane when handed one');

  // 3. ADMISSION.
  pool.reset();
  await withSettings({ 'workers.batchConcurrency': 2,
                       'workers.batchQueueLimit': 2,
                       'workers.batchQueueTimeoutS': 1 }, async function () {
    const started = [];
    const releases = [];
    const admit = function (name) {
      const res = fakeResponse();
      pool.admitBatch(PROTO, {}, res, function (release) {
        started.push(name);
        releases.push(release);
      });
      return res;
    };
    admit('a');
    admit('b');
    const third = admit('c');
    t.equal(started.join(','), 'a,b',
            'with no worker a lane counts as one, so the cap is ' +
            'workers.batchConcurrency: two start and the third waits');
    t.equal(pool.batchStats()[PROTO].waiting, 1, 'and one is waiting');
    admit('d');
    const fifth = admit('e');
    t.equal(fifth.statusCode, 503,
            'PAST workers.batchQueueLimit A BATCH REQUEST IS A 503 AT ONCE');
    t.check(Number(fifth.headers['Retry-After']) > 0 &&
            codeOf(fifth) === 'STS-WORKER-0040',
            'with Retry-After, marked STS-WORKER-0040', codeOf(fifth));
    releases[0]();
    releases[0]();
    t.equal(started.join(','), 'a,b,c',
            'A RELEASE STARTS THE NEXT IN ORDER — and a release called twice ' +
            'counts once');
    t.equal(third.statusCode, 200, 'the waiting request was not refused');
    // `d` is waiting now; it times out.
    await wait(1300);
    t.equal(started.indexOf('d'), -1, 'a request still waiting never ran');
    t.equal(pool.batchStats()[PROTO].timedOut, 1,
            'AND ONE THAT WAITED workers.batchQueueTimeoutS IS REFUSED');
    const sixth = admit('f');
    t.equal(started.indexOf('f'), -1, 'the next waits again at the cap');
    sixth.emit('close');
    releases[1]();
    t.equal(started.indexOf('f'), -1,
            'A CLIENT THAT WENT AWAY WHILE WAITING IS DROPPED, not dispatched');
    t.equal(pool.batchStats()[PROTO].waiting, 0, 'and the queue is empty');
  });
  pool.reset();
  await withSettings({ 'workers.batchConcurrency': 0 }, function () {
    let ran = 0;
    for (let i = 0; i < 50; i++) {
      pool.admitBatch(PROTO, {}, fakeResponse(), function () { ran += 1; });
    }
    t.equal(ran, 50, 'a cap of 0 keeps the lane and queues nothing');
  });
  pool.reset();

  // 4. A BOUND REQUEST KEEPS ITS WORKER.
  const source = fs.readFileSync(path.join(__dirname, '..', 'common',
                                           'request_pool.js'), 'utf8');
  const body = source.slice(source.indexOf('function workerFor('),
                            source.indexOf('function heldWorker('));
  const held = body.indexOf('  const held = heldWorker(key, pool);\n');
  const narrowed = body.indexOf('leastLoaded(pool, candidates)',
                                body.indexOf('if (held)'));
  t.check(held > 0 && narrowed > held,
          'workerFor() asks for the key\'s HELD worker before the lane ' +
          'narrows a new choice — a write to one SCIM resource keeps the ' +
          'worker that stops it losing an update');
  t.log.debug('Leaving run().');
}

module.exports = {
  name: 'request_batch_lane',
  describe: 'batch traffic is confined to a share of a pool\'s workers and a ' +
            'number in flight, waits in order, and is refused 503 past its ' +
            'queue or its wait',
  run: run
};
