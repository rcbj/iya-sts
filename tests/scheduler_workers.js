// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: scheduler_workers.js
//
// ===========================================================================
// A CLUSTER RUN'S BODY ON A REQUEST WORKER, AND A RUN HELD FOR LOAD (#408).
//
// `cluster/scheduler.ts` keeps the lease, the claim, the fence, the time
// limit and the run row on the leader, and hands the call to a cluster job's
// `run()` to a request worker through its `runner` dependency. Here the
// leader is a real `Scheduler` in `tests/scheduler_kit.js`'s simulated world,
// and the "pool" is a stand-in whose workers are a SECOND real `Scheduler` —
// the worker's half, `runDelegated()` and `fenceDelegated()`, is the code a
// request worker runs. Nothing sleeps.
//
//   A. a run is handed to the worker: the worker's job runs, the leader's
//      does not, and the leader writes the outcome (ranIn: worker);
//   B. a run past its time limit is failed by the leader (STS-SCHED-0002)
//      and FENCED: the worker's `stillOwner()` answers false from then on;
//   C. a worker that ends under a run fails it with STS-SCHED-0019;
//   D. no ready worker: the run is inline, as before #408 (ranIn: front);
//   E. a job with an `onFront` reason runs inline whatever the pool has;
//   F. an exemption must be a reason: an empty or non-string `onFront`, an
//      `onFront` on a per-process job and a `nice` outside 0..19 are refused
//      (STS-SCHED-0009); the real module's `scheduler.history` carries one;
//   G. a job the worker has not registered runs on the front
//      (STS-SCHED-0020), and from then on is not offered to a worker;
//   H. nice: a scheduled run held while even the least-loaded worker is
//      busy (requests in flight, or event-loop delay), forced through at
//      its bound measured from when it was FIRST held, released when the
//      load drops, and never held for nice 0, an on-demand job, a manual
//      Run now or an inline run.
// ===========================================================================

delete process.env.CONFIG_FILE;

const path = require('path');
const ROOT = path.join(__dirname, '..');
const kit = require('./scheduler_kit');

const log = require('bunyan').createLogger({ name: 'scheduler_workers',
  level: process.env.LOG_LEVEL || 'info' });

const MINUTE = 60000;

function job(overrides) {
  log.debug('Entering job().');
  log.debug('Leaving job().');
  return Object.assign({
    id: 'test.delegated', title: 'A test job', describe: 'For the test.',
    owner: 'tests/scheduler_workers.js',
    everyMs: function () { return 10 * MINUTE; },
    run: function () { return { ran: 'nowhere' }; }
  }, overrides || {});
}

// THE POOL'S STAND-IN: one worker (id 7) whose body is run by a real
// Scheduler's `runDelegated()`. `loads` is what `workers()` answers; `kill()`
// is the worker ending under its runs, as `request_pool.js`'s reap() does.
function stubPool(workerNode) {
  log.debug('Entering stubPool().');
  const pool = {
    loads: [{ id: 7, inFlight: 0, lagMs: null }],
    pending: new Map(),
    fenced: [],
    asked: 0,
    workers: function () {
      return pool.loads.map(function (one) {
        return Object.assign({}, one);
      });
    },
    run: function (workerId, request) {
      pool.asked += 1;
      return new Promise(function (resolve) {
        pool.pending.set(request.runId, resolve);
        workerNode.scheduler.runDelegated(request).then(function (answer) {
          if (pool.pending.get(request.runId) === resolve) {
            pool.pending.delete(request.runId);
            resolve(answer);
          }
        });
      });
    },
    fence: function (runId) {
      pool.fenced.push(runId);
      workerNode.scheduler.fenceDelegated(runId);
      const resolve = pool.pending.get(runId);
      if (resolve) {
        pool.pending.delete(runId);
        resolve({ ok: false, fenced: true, error: 'stopped waiting' });
      }
    },
    kill: function () {
      pool.pending.forEach(function (resolve) {
        resolve({ ok: false, code: 'STS-SCHED-0019',
                  error: 'request worker 7 ended (1) before it answered' });
      });
      pool.pending.clear();
    }
  };
  log.debug('Leaving stubPool().');
  return pool;
}

// A leader and a worker in one world, the pool between them.
function setup(settings) {
  log.debug('Entering setup().');
  const w = kit.world({ clustered: false, settings: Object.assign({
    'scheduler.niceBusyThreshold': 4,
    'scheduler.niceLagMs': 200,
    'scheduler.niceMaxDeferS': 190
  }, settings || {}) });
  const worker = w.node('worker', { worker: true });
  const pool = stubPool(worker);
  const front = w.node('front', { runner: pool });
  log.debug('Leaving setup().');
  return { w: w, worker: worker, pool: pool, front: front };
}

function rowsOf(w, jobId) {
  log.debug('Entering rowsOf().');
  log.debug('Leaving rowsOf().');
  return w.runRows().filter(function (r) {
    return r.jobId === jobId;
  });
}

function codeOfThrow(fn) {
  log.debug('Entering codeOfThrow().');
  try {
    fn();
    log.debug('Leaving codeOfThrow(). No throw.');
    return '';
  } catch (e) {
    log.debug('Caught in codeOfThrow(): ' + ((e && e.message) || e));
    const m = /STS-[A-Z]+-\d{4}/.exec(String(e.message));
    log.debug('Leaving codeOfThrow().');
    return m ? m[0] : 'threw: ' + e.message;
  }
}

function logsMatching(w, re) {
  log.debug('Entering logsMatching().');
  log.debug('Leaving logsMatching().');
  return w.logs.filter(function (one) {
    return re.test(String(one.m));
  });
}

async function run(t) {
  log.debug('Entering run().');
  // -------------------------------------------------------------------------
  t.log.info('=== A. a run is handed to the worker ===');
  {
    const s = setup();
    let onFront = 0;
    let onWorker = 0;
    s.front.scheduler.register(job({ run: function () {
      onFront += 1;
      return { ran: 'front' };
    } }));
    s.worker.scheduler.register(job({ run: function (ctx) {
      onWorker += 1;
      return { ran: 'worker', owner: ctx.stillOwner(),
               realm: ctx.realm };
    } }));
    s.front.scheduler.start('front');
    await s.w.advance(MINUTE);
    const rows = rowsOf(s.w, 'test.delegated');
    t.equal(onWorker, 1, 'the job ran once, in the worker');
    t.equal(onFront, 0, 'and not on the leader\'s thread');
    t.check(rows.length === 1 && rows[0].state === 'succeeded' &&
            rows[0].ranIn === 'worker' &&
            /"ran":"worker"/.test(rows[0].result) &&
            /"owner":true/.test(rows[0].result),
            'the leader wrote the worker\'s outcome, saying where it ran; ' +
            'the worker\'s stillOwner() answered true while it ran',
            JSON.stringify(rows));
    t.equal(s.pool.asked, 1, 'the pool was asked once');
    const view = (await s.front.scheduler.status()).jobs.filter(function (j) {
      return j.id === 'test.delegated';
    })[0];
    t.check(!!view && view.runsOn === 'worker' && view.nice === 10,
            'the report says the job runs on a worker, nice 10 by default',
            JSON.stringify(view && { runsOn: view.runsOn, nice: view.nice }));
  }

  // -------------------------------------------------------------------------
  t.log.info('=== B. a run past its time limit is fenced ===');
  {
    const s = setup();
    let seen = null;
    s.front.scheduler.register(job({ timeoutS: 30 }));
    s.worker.scheduler.register(job({ timeoutS: 30, run: function (ctx) {
      seen = ctx;
      return new Promise(function () {});
    } }));
    s.front.scheduler.start('front');
    await s.w.advance(MINUTE);
    const rows = rowsOf(s.w, 'test.delegated');
    t.check(rows.length === 1 && rows[0].state === 'failed' &&
            rows[0].errorCode === 'STS-SCHED-0002',
            'the leader failed the run at its time limit, STS-SCHED-0002',
            JSON.stringify(rows));
    t.check(s.pool.fenced.indexOf(rows[0] && rows[0].runId) >= 0,
            'and told the worker running it', JSON.stringify(s.pool.fenced));
    t.check(!!seen && seen.stillOwner() === false,
            'whose stillOwner() answers false from then on');
  }

  // -------------------------------------------------------------------------
  t.log.info('=== C. a worker that ends under a run fails it ===');
  {
    const s = setup();
    s.front.scheduler.register(job());
    s.worker.scheduler.register(job({ run: function () {
      return new Promise(function () {});
    } }));
    s.front.scheduler.start('front');
    await s.w.advance(1000);
    s.pool.kill();
    await s.w.advance(1000);
    const rows = rowsOf(s.w, 'test.delegated');
    t.check(rows.length === 1 && rows[0].state === 'failed' &&
            rows[0].errorCode === 'STS-SCHED-0019' &&
            /ended/.test(rows[0].why),
            'the run is failed with STS-SCHED-0019 at once, not at its ' +
            'time limit', JSON.stringify(rows));
  }

  // -------------------------------------------------------------------------
  t.log.info('=== D. no ready worker: inline ===');
  {
    const s = setup();
    s.pool.loads = [];
    let onFront = 0;
    s.front.scheduler.register(job({ run: function () {
      onFront += 1;
      return 'here';
    } }));
    s.worker.scheduler.register(job());
    s.front.scheduler.start('front');
    await s.w.advance(MINUTE);
    const rows = rowsOf(s.w, 'test.delegated');
    t.equal(onFront, 1, 'the leader ran the job itself');
    t.check(rows.length === 1 && rows[0].ranIn === 'front' &&
            rows[0].state === 'succeeded' && s.pool.asked === 0,
            'recorded as run on the front, and no worker was asked',
            JSON.stringify(rows));
  }

  // -------------------------------------------------------------------------
  t.log.info('=== E. a job with an onFront reason stays on the front ===');
  {
    const s = setup();
    let onFront = 0;
    const reason = 'it reads what only the front process holds';
    s.front.scheduler.register(job({ onFront: reason, run: function () {
      onFront += 1;
    } }));
    s.worker.scheduler.register(job({ onFront: reason }));
    s.front.scheduler.start('front');
    await s.w.advance(MINUTE);
    t.check(onFront === 1 && s.pool.asked === 0,
            'it ran on the leader with a worker ready and idle',
            JSON.stringify({ onFront: onFront, asked: s.pool.asked }));
    const view = (await s.front.scheduler.status()).jobs.filter(function (j) {
      return j.id === 'test.delegated';
    })[0];
    t.check(!!view && view.runsOn === 'front' && view.onFront === reason,
            'and the report says where, with the reason',
            JSON.stringify(view && { runsOn: view.runsOn,
                                     onFront: view.onFront }));
  }

  // -------------------------------------------------------------------------
  t.log.info('=== F. an exemption is a reason ===');
  {
    const s = setup();
    const sc = s.front.scheduler;
    t.equal(codeOfThrow(function () {
      sc.register(job({ onFront: '' }));
    }), 'STS-SCHED-0009', 'an empty onFront is refused');
    t.equal(codeOfThrow(function () {
      sc.register(job({ onFront: '   ' }));
    }), 'STS-SCHED-0009', 'a blank onFront is refused');
    t.equal(codeOfThrow(function () {
      sc.register(job({ onFront: true }));
    }), 'STS-SCHED-0009', 'onFront: true is refused — a flag is not a reason');
    t.equal(codeOfThrow(function () {
      sc.register(job({ kind: 'per-process', onFront: 'why not' }));
    }), 'STS-SCHED-0009', 'an onFront on a per-process job is refused');
    t.equal(codeOfThrow(function () {
      sc.register(job({ nice: 20 }));
    }), 'STS-SCHED-0009', 'a nice of 20 is refused');
    t.equal(codeOfThrow(function () {
      sc.register(job({ nice: 1.5 }));
    }), 'STS-SCHED-0009', 'a nice that is not whole is refused');
    t.equal(sc.jobIds().length, 0, 'and nothing refused was registered');
    const real = require(ROOT + '/cluster/scheduler');
    const history = real.job('scheduler.history');
    t.check(!!history && typeof history.onFront === 'string' &&
            /restore/.test(history.onFront),
            'the real scheduler.history stays on the front, and says why',
            history && history.onFront);
    const blank = real.jobIds().filter(function (id) {
      const one = real.job(id);
      return one.onFront !== undefined &&
        !(typeof one.onFront === 'string' && one.onFront.trim());
    });
    t.equal(blank.length, 0, 'no job the real module registers carries an ' +
                             'empty exemption');
    const now = real.jobIds().map(function (id) {
      return real.job(id);
    }).filter(function (one) {
      return one.manualOnly && one.nice !== 0;
    });
    t.equal(now.length, 0, 'every on-demand job is nice 0');
  }

  // -------------------------------------------------------------------------
  t.log.info('=== G. a job the worker has not registered ===');
  {
    const s = setup();
    let onFront = 0;
    s.front.scheduler.register(job({ run: function () {
      onFront += 1;
    } }));
    s.front.scheduler.start('front');
    await s.w.advance(MINUTE);
    t.check(onFront === 1 && s.pool.asked === 1,
            'the worker was asked, answered it has no such job, and the ' +
            'leader ran it', JSON.stringify({ onFront: onFront,
                                              asked: s.pool.asked }));
    t.equal(logsMatching(s.w, /STS-SCHED-0020/).length, 1,
            'said once, STS-SCHED-0020');
    await s.w.advance(10 * MINUTE);
    t.check(onFront === 2 && s.pool.asked === 1,
            'the next slot runs on the front without asking again',
            JSON.stringify({ onFront: onFront, asked: s.pool.asked }));
  }

  // -------------------------------------------------------------------------
  t.log.info('=== H. nice: held for load, never for long ===');
  {
    // H1-H2: held while busy, forced through at the bound, measured from
    // the first hold. Nice 19 of 190 s is 190 s, under half of 10 minutes.
    const s = setup();
    let ran = 0;
    s.front.scheduler.register(job({ nice: 19 }));
    s.worker.scheduler.register(job({ nice: 19, run: function () {
      ran += 1;
    } }));
    s.pool.loads = [{ id: 7, inFlight: 9, lagMs: null },
                    { id: 8, inFlight: 4, lagMs: 10 }];
    s.front.scheduler.start('front');
    await s.w.advance(MINUTE);
    t.check(ran === 0 && rowsOf(s.w, 'test.delegated').length === 0 &&
            s.w.claimRows.size === 0,
            'held while even the least-loaded worker has the threshold in ' +
            'flight — and not claimed', JSON.stringify({
              ran: ran, rows: rowsOf(s.w, 'test.delegated').length,
              claims: s.w.claimRows.size }));
    t.equal(logsMatching(s.w, /is held for load/).length, 1,
            'the hold is said once, however many ticks it lasts');
    await s.w.advance(2 * MINUTE);
    t.equal(ran, 0, 'still held at three minutes, inside its 190 s bound');
    await s.w.advance(20000);
    const rows = rowsOf(s.w, 'test.delegated');
    t.check(ran === 1 && rows.length === 1 &&
            rows[0].deferredMs >= 190000 && rows[0].deferredMs < 200000,
            'forced through once the bound passed, measured from the FIRST ' +
            'hold (a hold reset by each tick would never end), and the row ' +
            'says how long it waited', JSON.stringify(rows.map(function (r) {
              return { state: r.state, deferredMs: r.deferredMs };
            })));
    t.equal(logsMatching(s.w, /runs although every request worker is busy/)
      .length, 1, 'and the forcing through is said once');
  }
  {
    // H3: released when the load drops; the delay signal holds too.
    const s = setup();
    let ran = 0;
    s.front.scheduler.register(job());
    s.worker.scheduler.register(job({ run: function () {
      ran += 1;
    } }));
    s.pool.loads = [{ id: 7, inFlight: 0, lagMs: 500 }];
    s.front.scheduler.start('front');
    await s.w.advance(30000);
    t.equal(ran, 0, 'held by a 500 ms event-loop delay against a 200 ms ' +
                    'threshold, nothing in flight');
    s.pool.loads = [{ id: 7, inFlight: 0, lagMs: 20 }];
    await s.w.advance(10000);
    const rows = rowsOf(s.w, 'test.delegated');
    t.check(ran === 1 && rows.length === 1 && rows[0].deferredMs >= 30000 &&
            rows[0].deferredMs <= 40000,
            'released at the next tick once the worker is lighter, with the ' +
            'wait on its row', JSON.stringify(rows.map(function (r) {
              return r.deferredMs;
            })));
  }
  {
    // H4: nice 0, an on-demand job and a manual Run now are never held.
    const s = setup();
    const ran = { zero: 0, button: 0, patient: 0 };
    ['front', 'worker'].forEach(function (which) {
      const node = s[which];
      node.scheduler.register(job({ id: 'test.zero', nice: 0,
        run: function () { ran.zero += which === 'worker' ? 1 : 0; } }));
      node.scheduler.register(job({ id: 'test.button', nice: 19,
        everyMs: undefined, manualOnly: true,
        run: function () { ran.button += which === 'worker' ? 1 : 0; } }));
      node.scheduler.register(job({ id: 'test.patient', nice: 19,
        run: function () { ran.patient += which === 'worker' ? 1 : 0; } }));
    });
    s.pool.loads = [{ id: 7, inFlight: 50, lagMs: 5000 }];
    s.front.scheduler.start('front');
    await s.w.advance(5000);
    t.equal(ran.zero, 1, 'a job of nice 0 runs under any load');
    t.equal(ran.patient, 0, 'beside a patient one that is held');
    t.equal(s.front.scheduler.job('test.button').nice, 0,
            'an on-demand job is registered nice 0 whatever it asked for');
    const button = s.front.scheduler.requestRun('test.button', {});
    const manual = s.front.scheduler.requestRun('test.patient', {});
    t.check(!!button.ok && !!manual.ok, 'two runs requested by hand',
            JSON.stringify([button, manual]));
    await s.w.advance(5000);
    t.equal(ran.button, 1, 'an on-demand job ran at once under load');
    const patient = rowsOf(s.w, 'test.patient');
    t.check(ran.patient === 1 && patient.length === 1 &&
            patient[0].trigger === 'manual' && !patient[0].deferredMs,
            'a manual Run now of the patient job ran at once, while its ' +
            'scheduled run is still held', JSON.stringify(patient));
  }
  {
    // H5: an inline run is never held: no worker, nothing to wait for.
    const s = setup();
    s.pool.loads = [];
    let ran = 0;
    s.front.scheduler.register(job({ nice: 19, run: function () {
      ran += 1;
    } }));
    s.front.scheduler.start('front');
    await s.w.advance(5000);
    t.equal(ran, 1, 'with no worker the run is inline and is not held');
  }
  log.debug('Leaving run().');
}

module.exports = {
  name: 'scheduler_workers',
  describe: 'a cluster job\'s body run on a request worker (#408): the ' +
            'outcome, the fence, a worker ending, no worker, onFront ' +
            'exemptions, an unregistered job, and a run held for load',
  run: run
};
