'use strict';
//
// File: scheduler_cluster.js
//
// ===========================================================================
// THE SCHEDULER ACROSS NODES (#49, 2026-09-22) — the plan's T2.
//
// Two or three `Scheduler` instances, each a "node" of `tests/scheduler_kit.js`
// with its own skewed clock and its own fake `cluster`, over ONE store, ONE
// claim table and ONE lease table — what several containers against one
// postgres store share. Each claim below is one the plan makes (#49, Part 4a):
//
//   A. ONE LEADER: of three nodes campaigning, one holds ops.scheduler, and
//      only it runs a cluster job;
//   B. ONCE PER SLOT over a hundred slots, with the leadership forced to
//      change hands every ten of them by the step-down command (D10) — every
//      slot exactly one succeeded run, whichever node ran it;
//   C. TAKEOVER AND THE FENCE: the leader dies mid-run; once its lease lapses
//      another node leads, and once the run's claim lapses it runs the slot
//      again (attempt 2) and records the first attempt ABANDONED; the second
//      attempt starts only after the first lost its claim; and when the dead
//      node wakes and tries to report, its outcome is FENCED OUT and the row
//      keeps the survivor's;
//   D. CATCH-UP: no leader for three slots, then one — the job runs ONCE;
//   E. MANUAL RUNS ACROSS NODES: a run requested on B while A leads is run by
//      A, once; and one requested while A is dying is run by B, once, after
//      it takes over;
//   F. PER-PROCESS JOBS: two nodes of three processes each — the job runs in
//      all six, each writes its own row, and no claim is taken;
//   G. A STANDBY that never started never leads and never runs a job, and
//      a node that STOOD DOWN does not take the lease straight back;
//   H. THE REPORT FROM EITHER NODE: the same leader and the same nextRunAt,
//      whichever node draws it — the page and the API read the store.
// ===========================================================================

delete process.env.CONFIG_FILE;

const kit = require('./scheduler_kit');

const log = require('bunyan').createLogger({ name: 'scheduler_cluster',
  level: process.env.LOG_LEVEL || 'info' });

const MINUTE = 60000;

function job(overrides) {
  log.debug('Entering job().');
  log.debug('Leaving job().');
  return Object.assign({
    id: 'test.minutely', title: 'A job', describe: 'For the test.',
    owner: 'tests/scheduler_cluster.js',
    everyMs: function () { return MINUTE; },
    run: function () { return null; }
  }, overrides || {});
}

// Three nodes with clocks skewed apart, each with the same job, started.
function cluster3(w, spec) {
  log.debug('Entering cluster3().');
  const skews = [0, 45000, -30000];
  log.debug('Leaving cluster3().');
  return ['a', 'b', 'c'].map(function (name, i) {
    const node = w.node(name, { skewMs: skews[i] });
    node.scheduler.register(job(Object.assign({
      run: function (ctx) {
        node.invoked.push({ at: w.db, slot: Math.floor(ctx.nowMs() / MINUTE),
                            runId: ctx.runId });
        return spec && spec.run ? spec.run(node, ctx) : null;
      }
    }, (spec && spec.job) || {})));
    return node;
  });
}

function succeededBySlot(w) {
  log.debug('Entering succeededBySlot().');
  const bySlot = {};
  w.runRows().forEach(function (r) {
    if (r.jobId === 'test.minutely' && r.trigger === 'schedule' &&
        r.state === 'succeeded') {
      bySlot[r.slot] = (bySlot[r.slot] || 0) + 1;
    }
  });
  log.debug('Leaving succeededBySlot().');
  return bySlot;
}

async function run(t) {
  log.debug('Entering run().');
  // -------------------------------------------------------------------------
  t.log.info('=== A. one leader ===');
  {
    const w = kit.world();
    const nodes = cluster3(w);
    nodes.forEach(function (n) { n.scheduler.start('front'); });
    await w.advance(5 * MINUTE);
    const leading = nodes.filter(function (n) {
      return n.scheduler.isLeading();
    });
    t.check(leading.length === 1 && w.leaderOf() === leading[0].name,
            'of three nodes campaigning, exactly one leads the scheduler',
            JSON.stringify(nodes.map(function (n) {
              return [n.name, n.scheduler.isLeading()];
            })));
    const ran = nodes.filter(function (n) { return n.invoked.length; });
    t.check(ran.length === 1 && ran[0] === leading[0],
            'and only the leader ran the cluster job',
            JSON.stringify(nodes.map(function (n) {
              return [n.name, n.invoked.length];
            })));
  }

  // -------------------------------------------------------------------------
  t.log.info('=== B. once per slot, over a hundred slots and ten ' +
             'handovers ===');
  {
    const w = kit.world();
    const nodes = cluster3(w);
    nodes.forEach(function (n) { n.scheduler.start('front'); });
    const leaders = [];
    for (let i = 0; i < 10; i++) {
      await w.advance(10 * MINUTE);
      leaders.push(w.leaderOf());
      // Asked of whichever node — it is a command in the store, and the
      // leader obeys it at its next tick.
      const answer = nodes[i % 3].scheduler.requestStepDown({
        requestedBy: 'the test' });
      t.check(answer.ok, 'step-down ' + (i + 1) + ' is accepted',
              JSON.stringify(answer));
    }
    await w.advance(2 * MINUTE);
    const bySlot = succeededBySlot(w);
    const slots = Object.keys(bySlot).map(Number).sort(function (a, b) {
      return a - b;
    });
    const doubles = slots.filter(function (s) { return bySlot[s] !== 1; });
    const first = slots[0];
    const last = slots[slots.length - 1];
    const missing = [];
    for (let s = first; s <= last; s++) {
      if (!bySlot[s]) {
        missing.push(s);
      }
    }
    const distinctLeaders = leaders.filter(function (v, i, a) {
      return a.indexOf(v) === i;
    });
    t.check(slots.length >= 100 && doubles.length === 0 &&
            missing.length === 0,
            'every one of over a hundred slots has exactly ONE succeeded run',
            JSON.stringify({ slots: slots.length, doubles: doubles,
                             missing: missing }));
    t.check(distinctLeaders.length >= 2,
            'while the leadership really changed hands',
            JSON.stringify(leaders));
    const invocations = nodes.reduce(function (n, node) {
      return n + node.invoked.length;
    }, 0);
    t.equal(invocations, slots.length,
            'and the job itself was CALLED once per slot, not merely ' +
            'recorded once');
  }

  // -------------------------------------------------------------------------
  t.log.info('=== C. takeover, and the fence ===');
  {
    const w = kit.world();
    let hang = true;
    const pending = [];
    const nodes = ['a', 'b'].map(function (name, i) {
      const node = w.node(name, { skewMs: i ? 20000 : 0 });
      node.scheduler.register(job({
        id: 'test.slow', timeoutS: 60,
        everyMs: function () { return 60 * MINUTE; },
        run: function (ctx) {
          node.invoked.push({ at: w.db, runId: ctx.runId });
          if (!hang || name !== 'a') {
            return { by: name };
          }
          return new Promise(function (resolve) {
            pending.push({ resolve: resolve, ctx: ctx });
          });
        }
      }));
      return node;
    });
    nodes[0].scheduler.start('front');
    await w.advance(2000);
    nodes[1].scheduler.start('front');
    await w.advance(2000);
    t.check(nodes[0].scheduler.isLeading() && pending.length === 1,
            'A leads, and its run of the hourly job is hanging',
            JSON.stringify({ a: nodes[0].scheduler.isLeading(),
                             pending: pending.length }));
    const claimKey = Array.from(w.claimRows.keys())[0];
    const firstClaim = Object.assign({}, w.claimRows.get(claimKey));
    nodes[0].kill();
    await w.advance(3 * w.leaseTtlMs);
    t.check(nodes[1].scheduler.isLeading() &&
            w.leaderOf() === 'b',
            'once A\'s lease lapses, B leads', w.leaderOf());
    t.check(nodes[1].invoked.length === 0,
            'but B does not run the slot while A\'s claim is still live',
            JSON.stringify(nodes[1].invoked));
    await w.advance(70000);
    t.check(nodes[1].invoked.length === 1 &&
            nodes[1].invoked[0].at >= firstClaim.expiresAt,
            'once A\'s claim lapses B runs the slot — the second attempt, ' +
            'and only after the first lost its claim',
            JSON.stringify({ b: nodes[1].invoked,
                             claimExpired: firstClaim.expiresAt }));
    const rows = w.runRows().filter(function (r) {
      return r.jobId === 'test.slow';
    });
    const main = rows.filter(function (r) { return !r.abandonedOf; })[0];
    const abandoned = rows.filter(function (r) { return r.abandonedOf; })[0];
    t.check(main && main.state === 'succeeded' && main.attempt === 2 &&
            main.nodeName === 'b' && main.takenOver,
            'the run is succeeded at attempt 2, on B, marked taken over',
            JSON.stringify(main && { state: main.state, attempt: main.attempt,
                                     node: main.nodeName }));
    t.check(abandoned && abandoned.state === 'abandoned' &&
            abandoned.errorCode === 'STS-SCHED-0011' &&
            abandoned.nodeName === 'a',
            'and A\'s attempt is recorded ABANDONED, STS-SCHED-0011',
            JSON.stringify(abandoned && { state: abandoned.state,
                                          code: abandoned.errorCode }));
    // A WAKES — a process that was paused — and its hung run finishes.
    nodes[0].wake();
    const stillOwnerOnWake = pending[0].ctx.stillOwner();
    pending[0].resolve({ by: 'a, late' });
    await w.advance(5000);
    const after = w.runRows().filter(function (r) {
      return r.jobId === 'test.slow' && !r.abandonedOf;
    })[0];
    t.check(!stillOwnerOnWake,
            'the woken attempt\'s stillOwner() is false before it does ' +
            'anything', String(stillOwnerOnWake));
    t.check(after.state === 'succeeded' && after.nodeName === 'b' &&
            /"by":"b"/.test(String(after.result)),
            'and its outcome is FENCED OUT: the row keeps B\'s result',
            JSON.stringify({ node: after.nodeName, result: after.result }));
    t.check(w.logs.some(function (l) {
      return l.node === 'a' && /STS-SCHED-0003/.test(l.m);
    }), 'and A says so, STS-SCHED-0003');
    t.check(!nodes[0].scheduler.isLeading() || w.leaderOf() !== 'a',
            'and A no longer leads once it has heard from the store',
            w.leaderOf());
  }

  // -------------------------------------------------------------------------
  t.log.info('=== D. catch-up runs once ===');
  {
    const w = kit.world();
    const a = w.node('a');
    a.scheduler.register(job({ id: 'test.five',
      everyMs: function () { return 5 * MINUTE; },
      run: function () { a.invoked.push(w.db); } }));
    // Nobody leads for fifteen minutes: three slots go by.
    await w.advance(15 * MINUTE + 1000);
    a.scheduler.start('front');
    await w.advance(30000);
    t.equal(a.invoked.length, 1,
            'three slots missed while nobody led are ONE run when a node ' +
            'leads, not three');
  }

  // -------------------------------------------------------------------------
  t.log.info('=== E. manual runs across nodes ===');
  {
    const w = kit.world();
    const counts = { a: 0, b: 0 };
    const nodes = ['a', 'b'].map(function (name) {
      const node = w.node(name);
      node.scheduler.register(job({ id: 'test.button', manualOnly: true,
        everyMs: undefined,
        run: function () { counts[name]++; } }));
      return node;
    });
    nodes[0].scheduler.start('front');
    await w.advance(1000);
    nodes[1].scheduler.start('front');
    await w.advance(1000);
    const asked = nodes[1].scheduler.requestRun('test.button',
                                                { requestedBy: 'bob' });
    await w.advance(10000);
    t.check(asked.ok && counts.a === 1 && counts.b === 0,
            'a run requested on B while A leads is run by A, once',
            JSON.stringify(counts));
    // Asked again, and A dies before its next tick.
    const again = nodes[1].scheduler.requestRun('test.button', {});
    nodes[0].kill();
    await w.advance(3 * w.leaseTtlMs + 10000);
    t.check(again.ok && counts.a === 1 && counts.b === 1,
            'one requested as A dies is run by B, once, after it takes over',
            JSON.stringify(counts));
    await w.advance(60000);
    t.check(counts.a + counts.b === 2, 'and neither ever runs again',
            JSON.stringify(counts));
  }

  // -------------------------------------------------------------------------
  t.log.info('=== F. per-process jobs, on every process of every node ===');
  {
    const w = kit.world();
    const processes = [];
    ['a', 'b'].forEach(function (name) {
      [0, 1, 2].forEach(function (i) {
        const node = w.node(name, { worker: i > 0, pid: (name === 'a' ?
                                                          3000 : 4000) + i });
        node.scheduler.register(job({ id: 'test.eject', kind: 'per-process',
          run: function () { node.invoked.push(w.db); } }));
        processes.push(node);
      });
    });
    processes.forEach(function (n) {
      n.scheduler.start(n.pid % 1000 ? 'per-process' : 'front');
    });
    await w.advance(3 * MINUTE);
    t.check(processes.every(function (n) { return n.invoked.length >= 3; }),
            'a per-process job runs in all six processes, once a slot each',
            JSON.stringify(processes.map(function (n) {
              return n.invoked.length;
            })));
    const st = await processes[4].scheduler.status();
    const row = st.jobs.filter(function (j) {
      return j.id === 'test.eject';
    })[0];
    t.check(row.processes.length === 6,
            'each has its own row, and a worker of node B draws all six',
            JSON.stringify(row.processes.map(function (p) {
              return p.nodeName + ':' + p.pid;
            })));
    t.check(!Array.from(w.claimRows.keys()).some(function (k) {
      return k.indexOf('test.eject') >= 0;
    }), 'and no claim was taken');
  }

  // -------------------------------------------------------------------------
  t.log.info('=== G. a standby, and a node that stood down ===');
  {
    const w = kit.world();
    const active = w.node('active');
    const standby = w.node('standby');
    [active, standby].forEach(function (n) {
      n.scheduler.register(job({ run: function () { n.invoked.push(w.db); } }));
    });
    // The standby is an active-passive node without the service lease:
    // server.js never reaches start(), so it never campaigns.
    active.scheduler.start('front');
    await w.advance(2 * MINUTE);
    active.kill();
    await w.advance(5 * MINUTE);
    t.check(!standby.scheduler.isLeading() && standby.invoked.length === 0,
            'a node that never started never leads and never runs, even with ' +
            'nobody leading', JSON.stringify(standby.invoked));
    const w2 = kit.world();
    const x = w2.node('x');
    const y = w2.node('y');
    [x, y].forEach(function (n) { n.scheduler.register(job()); });
    x.scheduler.start('front');
    await w2.advance(1000);
    y.scheduler.start('front');
    await w2.advance(1000);
    t.equal(w2.leaderOf(), 'x', 'x leads');
    x.scheduler.requestStepDown({});
    await w2.advance(10000);
    t.equal(w2.leaderOf(), 'y',
            'after a step-down y leads, and x did not take the lease ' +
            'straight back on its next heartbeat');
    const single = kit.world({ clustered: false });
    t.equal(single.node('solo').scheduler.requestStepDown({}).errorCode,
            'STS-SCHED-0010', 'with clustering off a step-down is refused: ' +
                              'there is nobody to hand to');
  }

  // -------------------------------------------------------------------------
  t.log.info('=== H. the report is the same from either node ===');
  {
    const w = kit.world();
    const a = w.node('a', { skewMs: 90000 });
    const b = w.node('b', { skewMs: -90000 });
    [a, b].forEach(function (n) {
      n.scheduler.register(job({ everyMs: function () {
        return 10 * MINUTE;
      } }));
    });
    a.scheduler.start('front');
    b.scheduler.start('front');
    await w.advance(3 * MINUTE);
    const ra = await a.scheduler.status();
    const rb = await b.scheduler.status();
    const ja = ra.jobs.filter(function (j) {
      return j.id === 'test.minutely';
    })[0];
    const jb = rb.jobs.filter(function (j) {
      return j.id === 'test.minutely';
    })[0];
    t.check(ra.leader.node === rb.leader.node && ra.leader.node &&
            ja.nextRunAt === jb.nextRunAt &&
            ja.nextRunInMs === jb.nextRunInMs &&
            ja.lastRun.runId === jb.lastRun.runId,
            'both nodes, three minutes apart by their own clocks, report the ' +
            'same leader, the same last run and the same next run',
            JSON.stringify({ a: [ra.leader.node, ja.nextRunAt, ja.nextRunInMs],
                             b: [rb.leader.node, jb.nextRunAt,
                                 jb.nextRunInMs] }));
  }
  log.debug('Leaving run().');
}

module.exports = {
  name: 'scheduler_cluster',
  describe: 'the scheduler across nodes: one leader, once per slot over a ' +
            'hundred slots and ten handovers, takeover and the fence, ' +
            'catch-up, manual runs across nodes, per-process jobs, standby ' +
            'and step-down, the same report from every node',
  run: run
};
