'use strict';
//
// File: scheduler.js
//
// ===========================================================================
// THE SCHEDULER, ONE PROCESS AT A TIME (#49, 2026-09-22) — the plan's T1.
//
// `cluster/scheduler.ts` is driven through its constructor in the simulated
// world of `tests/scheduler_kit.js`: a virtual DATABASE clock with each
// node's own clock skewed from it by an hour, virtual timers, and a store,
// claims and leases of the shapes the real ones have. Nothing sleeps.
//
//   A. a registration missing a member, with two schedules, an unreadable
//      cron expression, or a taken id is refused WHOLE (STS-SCHED-0009);
//   B. requiring the module starts nothing, and a request worker starts
//      per-process jobs only and never leads;
//   C. an interval job runs ONCE PER SLOT by the database's clock — a local
//      clock an hour off changes nothing — and a job whose interval is a
//      setting follows the setting at runtime, 0 meaning off (the `|| n`
//      rule);
//   D. a cron job's slot and next time come from croner, in UTC;
//   E. the run lifecycle: succeeded with its summary; failed with
//      STS-SCHED-0001 while the other jobs still run; a run past its time
//      limit failed with STS-SCHED-0002, its claim given back and its late
//      result fenced out;
//   F. OFF MEANS OFF, and says why: scheduler.enabled, scheduler.disabledJobs
//      and a job's own predicate (the signer rotation's "off in development
//      mode") — never called, and every reason on the report;
//   G. manual runs: queued, run once at the next tick; a second request is
//      the same run; an unknown job (STS-SCHED-0004), a job that runs on its
//      schedule only (0005), a job that is off (0006) and an unknown realm
//      (0012) are refused;
//   H. the report: never run, running, succeeded, failed, off, queued and
//      overdue, with nextRunAt/nextRunInMs from the database clock;
//   I. a per-process job runs in every process that starts, a request worker
//      included, and writes its own row;
//   J. history: finished runs past scheduler.historyDays go, the latest run
//      of each job stays;
//   K. the real module: its own history job and the two P1 jobs are
//      registered by their owners, and the singleton leads nothing at load.
// ===========================================================================

delete process.env.CONFIG_FILE;

const path = require('path');
const ROOT = path.join(__dirname, '..');
const kit = require('./scheduler_kit');

const log = require('bunyan').createLogger({ name: 'scheduler',
  level: process.env.LOG_LEVEL || 'info' });

const HOUR = 60 * 60 * 1000;

function baseJob(overrides) {
  log.debug('Entering baseJob().');
  log.debug('Leaving baseJob().');
  return Object.assign({
    id: 'test.job', title: 'A test job', describe: 'For the test.',
    owner: 'tests/scheduler.js', everyMs: function () { return 60000; },
    run: function () { return { ok: true }; }
  }, overrides || {});
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

async function run(t) {
  log.debug('Entering run().');
  // -------------------------------------------------------------------------
  t.log.info('=== A. registration is refused whole ===');
  {
    const w = kit.world({ clustered: false });
    const s = w.node('solo', { skewMs: HOUR }).scheduler;
    t.equal(codeOfThrow(function () {
      s.register(baseJob({ title: '' }));
    }), 'STS-SCHED-0009', 'a job with no title is refused');
    t.equal(codeOfThrow(function () {
      s.register(baseJob({ cron: '0 3 * * *' }));
    }), 'STS-SCHED-0009', 'a job with two schedules is refused');
    t.equal(codeOfThrow(function () {
      s.register(baseJob({ everyMs: undefined, cron: 'not a cron' }));
    }), 'STS-SCHED-0009', 'an unreadable cron expression is refused');
    t.equal(codeOfThrow(function () {
      s.register(baseJob({ id: 'NoDots' }));
    }), 'STS-SCHED-0009', 'an id that is not dot-separated words is refused');
    t.equal(codeOfThrow(function () {
      s.register(baseJob({ kind: 'per-process', everyMs: undefined,
                           manualOnly: true }));
    }), 'STS-SCHED-0009', 'a per-process job that is on demand only is ' +
                          'refused');
    s.register(baseJob());
    t.equal(codeOfThrow(function () { s.register(baseJob()); }),
            'STS-SCHED-0009', 'a second job with a taken id is refused');
    t.equal(s.jobIds().join(','), 'test.job',
            'and nothing refused was registered');
  }

  // -------------------------------------------------------------------------
  t.log.info('=== B. where it runs ===');
  {
    const w = kit.world({ clustered: false });
    const node = w.node('solo');
    let calls = 0;
    node.scheduler.register(baseJob({ run: function () { calls++; } }));
    await w.advance(5 * 60000);
    t.equal(calls, 0, 'registering a job starts nothing: five minutes on, ' +
                      'before start(), it has never run');
    const worker = w.node('worker', { worker: true });
    let workerCalls = 0;
    let workerProcessCalls = 0;
    worker.scheduler.register(baseJob({ run: function () {
      workerCalls++;
    } }));
    worker.scheduler.register(baseJob({ id: 'test.per-process',
      kind: 'per-process', run: function () { workerProcessCalls++; } }));
    worker.scheduler.start('front');
    await w.advance(3 * 60000);
    t.check(!worker.scheduler.isLeading() && workerCalls === 0,
            'a request worker never leads and never runs a cluster job, ' +
            'even asked to start as a front process',
            JSON.stringify({ leading: worker.scheduler.isLeading(),
                             workerCalls: workerCalls }));
    t.check(workerProcessCalls >= 3,
            'but it runs its per-process jobs, once a slot',
            String(workerProcessCalls));
  }

  // -------------------------------------------------------------------------
  t.log.info('=== C. once per slot, by the database clock ===');
  {
    const w = kit.world({ clustered: false });
    // An hour AHEAD, so a scheduler reading its own clock would think the
    // slots of the next hour were due now.
    const node = w.node('solo', { skewMs: HOUR });
    const slotsRun = [];
    node.scheduler.register(baseJob({ run: function (ctx) {
      slotsRun.push(Math.floor(ctx.nowMs() / 60000));
      return { at: ctx.nowMs() };
    } }));
    node.scheduler.start('front');
    await w.advance(5 * 60000 + 1000);
    const distinct = slotsRun.filter(function (v, i, a) {
      return a.indexOf(v) === i;
    });
    t.check(slotsRun.length === distinct.length &&
            slotsRun.length >= 5 && slotsRun.length <= 6,
            'five minutes of a one-minute job is five or six runs, one per ' +
            'slot, never two in one', JSON.stringify(slotsRun));
    const firstSlot = Math.floor((w.db - 5 * 60000 - 1000) / 60000);
    t.check(slotsRun[0] === firstSlot,
            'and the slots are the DATABASE\'s: the first run was in the ' +
            'slot the database clock was in, not the one an hour on',
            JSON.stringify({ first: slotsRun[0], expected: firstSlot }));
    const rows = w.runRows();
    t.check(rows.length === slotsRun.length && rows.every(function (r) {
      return r.state === 'succeeded' && r.attempt === 1 && r.fenceAt > 0;
    }), 'every slot is one run row, succeeded at attempt 1 with a fence',
    JSON.stringify(rows.map(function (r) {
      return [r.state, r.attempt, r.fenceAt > 0];
    })));

    // A job whose interval is a setting, changed at runtime; 0 is OFF.
    const w2 = kit.world({ clustered: false,
                           settings: { 'test.everyS': 120 } });
    const n2 = w2.node('solo');
    let hits = 0;
    n2.scheduler.register(baseJob({ id: 'test.set', everyMs: undefined,
      everySetting: 'test.everyS', everySettingUnit: 's',
      run: function () { hits++; } }));
    n2.scheduler.start('front');
    await w2.advance(10 * 60000);
    const at120 = hits;
    w2.settings['test.everyS'] = 30;
    await w2.advance(10 * 60000);
    const at30 = hits - at120;
    w2.settings['test.everyS'] = 0;
    await w2.advance(10 * 60000);
    const at0 = hits - at120 - at30;
    t.check(at120 >= 4 && at120 <= 6 && at30 >= 18 && at30 <= 21 &&
            at0 === 0,
            'an interval from a setting follows it at runtime: ~5 runs in ' +
            '10 min at 120 s, ~20 at 30 s, and NONE at 0',
            JSON.stringify({ at120: at120, at30: at30, at0: at0 }));
    const status = await n2.scheduler.status();
    const row = status.jobs.filter(function (j) {
      return j.id === 'test.set';
    })[0];
    t.check(row && row.state === 'off' &&
            /test\.everyS is 0/.test(row.offReason),
            'and at 0 the report says the job is off because the setting ' +
            'is 0 — not quietly running at a default',
            JSON.stringify(row && { state: row.state, why: row.offReason }));
  }

  // -------------------------------------------------------------------------
  t.log.info('=== D. cron, through croner, in UTC ===');
  {
    // A tick of a minute: two simulated days of five-second ticks is a
    // slow test and proves nothing more.
    const w = kit.world({ clustered: false,
                          settings: { 'scheduler.tickS': 60 },
                          startAt: Date.UTC(2026, 8, 22, 2, 59, 0) });
    const node = w.node('solo', { skewMs: -HOUR });
    const ranAt = [];
    node.scheduler.register(baseJob({ id: 'test.cron', everyMs: undefined,
      cron: '0 3 * * *',
      run: function (ctx) { ranAt.push(new Date(ctx.nowMs()).toISOString()); }
    }));
    const before = await node.scheduler.status();
    const cronRow = before.jobs.filter(function (j) {
      return j.id === 'test.cron';
    })[0];
    t.check(cronRow && cronRow.nextRunState === 'overdue' &&
            cronRow.nextRunAt === '2026-09-21T03:00:00.000Z',
            'at 02:59 a cron job that has never run is OVERDUE for its most ' +
            'recent occurrence — yesterday\'s 03:00 UTC, a slot missed, ' +
            'which runs ONCE (the catch-up)',
            JSON.stringify(cronRow && { state: cronRow.nextRunState,
                                        at: cronRow.nextRunAt }));
    node.scheduler.start('front');
    await w.advance(2 * 24 * HOUR);
    const after = await node.scheduler.status();
    const later = after.jobs.filter(function (j) {
      return j.id === 'test.cron';
    })[0];
    t.check(ranAt.length === 3 && /T02:59:0/.test(ranAt[0]) &&
            /^2026-09-22T03:00:0/.test(ranAt[1]) &&
            /^2026-09-23T03:00:0/.test(ranAt[2]),
            'two days of "0 3 * * *" is the catch-up at start and then one ' +
            'run just after each 03:00 UTC, whatever this node\'s clock says',
            JSON.stringify(ranAt));
    t.check(later && later.nextRunAt === '2026-09-24T03:00:00.000Z' &&
            later.nextRunState === 'scheduled',
            'and the next run is the next occurrence, from croner',
            JSON.stringify(later && later.nextRunAt));
  }

  // -------------------------------------------------------------------------
  t.log.info('=== E. the run lifecycle ===');
  {
    const w = kit.world({ clustered: false });
    const node = w.node('solo');
    let good = 0;
    node.scheduler.register(baseJob({ id: 'test.throws', run: function () {
      throw new Error('boom');
    } }));
    node.scheduler.register(baseJob({ id: 'test.good', run: function () {
      good++;
      return { counted: good };
    } }));
    let release = null;
    let lateWrites = 0;
    node.scheduler.register(baseJob({ id: 'test.slow', timeoutS: 30,
      everyMs: function () { return 10 * 60000; },
      run: function (ctx) {
        return new Promise(function (resolve) {
          release = function () {
            if (ctx.stillOwner()) {
              lateWrites++;
            }
            resolve('done late');
          };
        });
      } }));
    node.scheduler.start('front');
    await w.advance(3 * 60000);
    const rows = w.runRows();
    const threw = rows.filter(function (r) {
      return r.jobId === 'test.throws';
    });
    t.check(threw.length >= 3 && threw.every(function (r) {
      return r.state === 'failed' && r.errorCode === 'STS-SCHED-0001' &&
             /boom/.test(r.why);
    }), 'a job that throws is recorded failed, STS-SCHED-0001, with the ' +
        'reason — every slot', JSON.stringify(threw.map(function (r) {
      return [r.state, r.errorCode];
    })));
    t.check(good >= 3, 'and it stops neither the tick nor the other jobs',
            String(good));
    const okRow = rows.filter(function (r) { return r.jobId === 'test.good'; })
      .sort(function (a, b) { return b.endedAt - a.endedAt; })[0];
    t.check(okRow && okRow.state === 'succeeded' &&
            /"counted":/.test(String(okRow.result)),
            'a job that succeeds keeps its summary on the row',
            JSON.stringify(okRow && okRow.result));
    const slow = rows.filter(function (r) { return r.jobId === 'test.slow'; });
    t.check(slow.length === 1 && slow[0].state === 'failed' &&
            slow[0].errorCode === 'STS-SCHED-0002',
            'a run past its 30 s limit is recorded failed, STS-SCHED-0002',
            JSON.stringify(slow.map(function (r) {
              return [r.state, r.errorCode];
            })));
    const claimKey = Array.from(w.claimRows.keys()).filter(function (k) {
      return k.indexOf(slow[0].runId) >= 0;
    });
    t.check(claimKey.length === 0,
            'and its claim was given back', JSON.stringify(claimKey));
    if (release) {
      release();
    }
    await w.settle();
    t.check(lateWrites === 0,
            'and when it finally finishes, stillOwner() is false: its late ' +
            'result is fenced out', String(lateWrites));
  }

  // -------------------------------------------------------------------------
  t.log.info('=== F. off means off, and says why ===');
  {
    const w = kit.world({ clustered: false });
    const node = w.node('solo');
    const calls = { a: 0, b: 0, c: 0 };
    node.scheduler.register(baseJob({ id: 'test.a', run: function () {
      calls.a++;
    } }));
    node.scheduler.register(baseJob({ id: 'test.b', run: function () {
      calls.b++;
    } }));
    node.scheduler.register(baseJob({ id: 'test.c',
      off: function () { return 'off in development mode'; },
      run: function () { calls.c++; } }));
    w.settings['scheduler.disabledJobs'] = 'test.b, test.nothing';
    node.scheduler.start('front');
    await w.advance(3 * 60000);
    t.check(calls.a >= 3 && calls.b === 0 && calls.c === 0,
            'a job named in scheduler.disabledJobs and a job whose own ' +
            'predicate says off are never called; the other runs',
            JSON.stringify(calls));
    const st = await node.scheduler.status();
    const byId = {};
    st.jobs.forEach(function (j) { byId[j.id] = j; });
    t.check(byId['test.b'].state === 'off' &&
            /scheduler\.disabledJobs/.test(byId['test.b'].offReason) &&
            byId['test.c'].state === 'off' &&
            byId['test.c'].offReason === 'off in development mode' &&
            byId['test.b'].nextRunState === 'off',
            'and the report says which reason, per job',
            JSON.stringify({ b: byId['test.b'].offReason,
                             c: byId['test.c'].offReason }));
    t.check(st.unknownDisabledIds.join(',') === 'test.nothing',
            'an id in scheduler.disabledJobs no job has is reported',
            JSON.stringify(st.unknownDisabledIds));
    w.settings['scheduler.enabled'] = false;
    const before = calls.a;
    await w.advance(3 * 60000);
    const st2 = await node.scheduler.status();
    t.check(calls.a === before && st2.jobs.every(function (j) {
      return j.state === 'off' && /scheduler\.enabled/.test(j.offReason);
    }), 'scheduler.enabled off: nothing runs, and every row says so',
    JSON.stringify({ before: before, after: calls.a }));
  }

  // -------------------------------------------------------------------------
  t.log.info('=== G. manual runs ===');
  {
    const w = kit.world({ clustered: false });
    const node = w.node('solo');
    let manual = 0;
    let lastParams = null;
    node.scheduler.register(baseJob({ id: 'test.manual', manualOnly: true,
      everyMs: undefined, run: function (ctx) {
        manual++;
        lastParams = ctx.params;
      } }));
    node.scheduler.register(baseJob({ id: 'test.never', manual: false }));
    node.scheduler.register(baseJob({ id: 'test.realm', scope: 'realm',
      manualOnly: true, everyMs: undefined, run: function () {} }));
    node.scheduler.register(baseJob({ id: 'test.offjob',
      off: function () { return 'off in development mode'; } }));
    node.scheduler.start('front');
    await w.advance(60000);
    t.equal(manual, 0, 'a job on demand only never runs on its own');
    const first = node.scheduler.requestRun('test.manual',
                                            { params: { units: ['jose'] },
                                              requestedBy: 'alice' });
    const again = node.scheduler.requestRun('test.manual',
                                            { params: { units: ['jose'] } });
    t.check(first.ok && again.ok && again.runId === first.runId &&
            again.alreadyQueued,
            'a second request while one is queued is the same run',
            JSON.stringify({ first: first.runId, again: again.runId }));
    const queuedView = await node.scheduler.status();
    const qRow = queuedView.jobs.filter(function (j) {
      return j.id === 'test.manual';
    })[0];
    t.check(qRow.nextRunState === 'queued' &&
            qRow.queued[0].requestedBy === 'alice',
            'the report shows it queued, and by whom',
            JSON.stringify({ state: qRow.nextRunState }));
    await w.advance(10000);
    t.check(manual === 1 && lastParams && lastParams.units[0] === 'jose',
            'the next tick runs it once, with its parameters',
            JSON.stringify({ manual: manual, params: lastParams }));
    await w.advance(60000);
    t.equal(manual, 1, 'and never again');
    t.equal(node.scheduler.requestRun('test.nosuch', {}).errorCode,
            'STS-SCHED-0004', 'an unknown job is refused');
    t.equal(node.scheduler.requestRun('test.never', {}).errorCode,
            'STS-SCHED-0005', 'a job that runs on its schedule only is ' +
                              'refused');
    t.equal(node.scheduler.requestRun('test.offjob', {}).errorCode,
            'STS-SCHED-0006', 'a job that is off is refused, with the reason');
    t.equal(node.scheduler.requestRun('test.realm',
                                      { realm: 'nowhere' }).errorCode,
            'STS-SCHED-0012', 'a realm that does not exist is refused');
    const inAcme = node.scheduler.requestRun('test.realm', { realm: 'acme' });
    t.check(inAcme.ok && inAcme.run.realm === 'acme' &&
            w.stores.get('acme').has(inAcme.runId),
            'a realm job\'s manual run is a row of that realm\'s store',
            JSON.stringify(inAcme.run && inAcme.run.realm));
  }

  // -------------------------------------------------------------------------
  t.log.info('=== H. the report, in every state ===');
  {
    const w = kit.world({ clustered: false });
    const node = w.node('solo', { skewMs: 7 * 60000 });
    let hold = null;
    node.scheduler.register(baseJob({ id: 'test.never-run',
      everyMs: function () { return 24 * HOUR; } }));
    node.scheduler.register(baseJob({ id: 'test.ok',
      everyMs: function () { return 5 * 60000; } }));
    node.scheduler.register(baseJob({ id: 'test.bad',
      everyMs: function () { return 5 * 60000; },
      run: function () { throw new Error('bad'); } }));
    node.scheduler.register(baseJob({ id: 'test.hold',
      everyMs: function () { return 5 * 60000; },
      run: function () {
        return new Promise(function (resolve) { hold = resolve; });
      } }));
    const cold = await node.scheduler.status();
    const coldRow = cold.jobs.filter(function (j) {
      return j.id === 'test.ok';
    })[0];
    t.check(coldRow.lastRun === null && coldRow.nextRunState === 'due',
            'never run: no last run, and due now — before anybody leads',
            JSON.stringify({ last: coldRow.lastRun,
                             state: coldRow.nextRunState }));
    t.check(!cold.leader.known,
            'and no leader is known yet', JSON.stringify(cold.leader));
    await w.advance(4 * 60000);
    const unled = await node.scheduler.status();
    const lateRow = unled.jobs.filter(function (j) {
      return j.id === 'test.ok';
    })[0];
    t.check(lateRow.nextRunState === 'overdue' &&
            /no leader has ticked/.test(lateRow.overdueWhy),
            'due for longer than three ticks with no leader: OVERDUE, and why',
            JSON.stringify({ state: lateRow.nextRunState,
                             why: lateRow.overdueWhy }));
    node.scheduler.start('front');
    await w.advance(10000);
    const st = await node.scheduler.status();
    const by = {};
    st.jobs.forEach(function (j) { by[j.id] = j; });
    const slot5 = Math.floor(w.db / 300000);
    t.check(by['test.ok'].lastRun.state === 'succeeded' &&
            by['test.ok'].nextRunState === 'scheduled' &&
            by['test.ok'].nextRunAt ===
              new Date((slot5 + 1) * 300000).toISOString() &&
            by['test.ok'].nextRunInMs === (slot5 + 1) * 300000 - w.db,
            'succeeded: the next run is the next slot, as an absolute time ' +
            'and a duration by the DATABASE clock (this node\'s is 7 min off)',
            JSON.stringify({ at: by['test.ok'].nextRunAt,
                             inMs: by['test.ok'].nextRunInMs }));
    t.check(by['test.bad'].lastRun.state === 'failed' &&
            by['test.bad'].lastRun.errorCode === 'STS-SCHED-0001',
            'failed: its code on the last run',
            JSON.stringify(by['test.bad'].lastRun.errorCode));
    t.check(by['test.hold'].running && !by['test.hold'].lastRun &&
            by['test.hold'].nextRunState === 'running',
            'running: the running run, since when and on which node',
            JSON.stringify(by['test.hold'].running &&
                           by['test.hold'].running.nodeName));
    t.check(by['test.never-run'].lastRun && st.leader.known &&
            st.leader.thisProcess && st.leader.clustered === false,
            'and the leader is this process, not clustered',
            JSON.stringify(st.leader));
    if (hold) {
      hold();
    }
    await w.settle();
  }

  // -------------------------------------------------------------------------
  t.log.info('=== I. per-process jobs ===');
  {
    const w = kit.world({ clustered: false });
    const front = w.node('front');
    const workers = [w.node('front', { worker: true, pid: 2001 }),
                     w.node('front', { worker: true, pid: 2002 })];
    [front].concat(workers).forEach(function (n) {
      n.scheduler.register(baseJob({ id: 'test.eject', kind: 'per-process',
        run: function () { n.invoked.push(w.db); } }));
    });
    front.scheduler.start('front');
    workers.forEach(function (n) { n.scheduler.start('per-process'); });
    await w.advance(3 * 60000);
    t.check([front].concat(workers).every(function (n) {
      return n.invoked.length >= 3;
    }), 'a per-process job runs in every process — the front process and ' +
        'each request worker — once a slot',
    JSON.stringify([front].concat(workers).map(function (n) {
      return n.invoked.length;
    })));
    const st = await front.scheduler.status();
    const row = st.jobs.filter(function (j) {
      return j.id === 'test.eject';
    })[0];
    t.check(row.processes.length === 3 && row.processes.filter(function (p) {
      return p.worker;
    }).length === 2,
            'and each process has its own row on the report, read from the ' +
            'store', JSON.stringify(row.processes.map(function (p) {
              return [p.pid, p.worker, p.state];
            })));
    t.check(Array.from(w.claimRows.keys()).every(function (k) {
      return k.indexOf('test.eject') < 0;
    }), 'and it took no claim');
  }

  // -------------------------------------------------------------------------
  t.log.info('=== J. history ===');
  {
    const w = kit.world({ clustered: false,
                          settings: { 'scheduler.historyDays': 1,
                                      'scheduler.tickS': 600 } });
    const node = w.node('solo');
    node.scheduler.register(baseJob({ id: 'test.hourly',
      everyMs: function () { return HOUR; } }));
    node.scheduler.start('front');
    await w.advance(3 * 24 * HOUR);
    const before = w.runRows().length;
    const removed = node.scheduler.prune();
    const after = w.runRows();
    t.check(before >= 70 && removed > 40 && after.length >= 23 &&
            after.length <= 26,
            'three days of an hourly job with one day of history keeps about ' +
            'a day', JSON.stringify({ before: before, removed: removed,
                                      after: after.length }));
    // Started a day into a 90-day slot, so the thirty days below are all in
    // the one slot and the job runs once.
    const NINETY = 90 * 24 * HOUR;
    const w2 = kit.world({ clustered: false,
                           settings: { 'scheduler.historyDays': 1,
                                       'scheduler.tickS': 3600 },
                           startAt: Math.floor(Date.UTC(2026, 8, 22) / NINETY) *
                                    NINETY + 24 * HOUR });
    const n2 = w2.node('solo');
    n2.scheduler.register(baseJob({ id: 'test.rare',
      everyMs: function () { return 90 * 24 * HOUR; } }));
    n2.scheduler.start('front');
    await w2.advance(60000);
    await w2.advance(30 * 24 * HOUR);
    n2.scheduler.prune();
    t.check(w2.runRows().length === 1,
            'the LATEST run of a job is kept whatever its age: a 90-day job ' +
            'still shows when it last ran a month later',
            String(w2.runRows().length));
  }

  // -------------------------------------------------------------------------
  t.log.info('=== L. a job shorter than a tick, and a quiet one (P5) ===');
  {
    const w = kit.world({ clustered: false,
                          settings: { 'scheduler.tickS': 60 } });
    const node = w.node('solo');
    let fast = 0;
    node.scheduler.register(baseJob({ id: 'test.fast',
      everyMs: function () { return 2000; },
      run: function () { fast++; } }));
    let quietRuns = 0;
    let failing = false;
    node.scheduler.register(baseJob({ id: 'test.quiet', kind: 'per-process',
      quiet: true, everyMs: function () { return 1000; },
      run: function () {
        quietRuns++;
        if (failing) {
          throw new Error('the pull failed');
        }
      } }));
    node.scheduler.start('front');
    await w.advance(20000);
    t.check(fast >= 8 && fast <= 11,
            'a cluster job every 2 s runs every 2 s under a 60 s tick — the ' +
            'next tick is the next due job, not the tick interval',
            String(fast));
    t.check(quietRuns >= 17,
            'and a per-process job every second runs every second',
            String(quietRuns));
    const rowOf = async function () {
      const st = await node.scheduler.status();
      const job = st.jobs.filter(function (j) {
        return j.id === 'test.quiet';
      })[0];
      return job && job.processes[0];
    };
    const first = await rowOf();
    t.check(first && first.state === 'succeeded' &&
            w.db - Date.parse(first.endedAt || 0) >= 15000,
            'a QUIET job\'s row is not rewritten while its outcome holds: ' +
            'the one on the report is from its first run',
            JSON.stringify(first && { state: first.state,
                                      endedAt: first.endedAt }));
    failing = true;
    await w.advance(3000);
    const failed = await rowOf();
    t.check(failed && failed.state === 'failed',
            'but a change of outcome is recorded at once',
            JSON.stringify(failed && failed.state));
    t.check(codeOfThrow(function () {
      node.scheduler.register(baseJob({ id: 'test.loud', quiet: true }));
    }) === 'STS-SCHED-0009',
            'and only a per-process job may be quiet');
  }

  // -------------------------------------------------------------------------
  t.log.info('=== K. the real module ===');
  {
    const mod = require(ROOT + '/cluster/scheduler');
    t.check(!mod.scheduler.isLeading(),
            'the process\'s scheduler leads nothing at load: only server.js ' +
            'starts it');
    t.check(mod.jobIds().indexOf('scheduler.history') >= 0,
            'its own history job is registered', mod.jobIds().join(','));
    require(ROOT + '/authn/authn');
    t.check(mod.jobIds().indexOf('authn.session-expiry') >= 0,
            'authn/authn registers authn.session-expiry at load',
            mod.jobIds().join(','));
    const job = mod.job('authn.session-expiry');
    t.check(job && job.kind === 'cluster' &&
            job.everySetting === 'authn.sessionSweepS',
            'as a cluster job whose interval is authn.sessionSweepS',
            JSON.stringify(job && { kind: job.kind,
                                    setting: job.everySetting }));
    const revocation = require(ROOT + '/common/pki_revocation');
    revocation.keepDirectoryCurrent();
    t.check(mod.jobIds().indexOf('pki.crl-directory-refresh') >= 0,
            'and pki_revocation registers pki.crl-directory-refresh when ' +
            'pki.start() asks it to keep the directory current',
            mod.jobIds().join(','));
  }
  log.debug('Leaving run().');
}

module.exports = {
  name: 'scheduler',
  describe: 'the scheduler in one process: registration, where it runs, ' +
            'once per slot by the database clock, cron, the run lifecycle, ' +
            'off states, manual runs, the report, per-process jobs, history',
  run: run
};
