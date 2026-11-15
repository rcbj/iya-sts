// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/scheduler_report_paging.js
//
// ---------------------------------------------------------------------------
// MONITORING -> SCHEDULER BUILDS ONE PAGE, AND ANSWERS WHAT IT ALWAYS DID
// (#1766, 2026-11-14).
//
// `schedulerView()` built every job view in every realm and every run's
// view, and then kept one page of each, so a walk of the page cost pages ×
// rows: 13 s a walk in run 29, with the realms the suite leaves standing.
// The scheduler now lists the (job, realm) pairs and the run rows, hands
// each length to the view's pager, and builds only the slice it names. The
// change is cost only, so this file holds the one property that matters:
//
//   1. THE ANSWER IS THE OLD ANSWER, byte for byte, for every query a page
//      or a caller sends — one page, another page of each list, a page past
//      the end, a job filter, an outcome filter, one run by id, the whole
//      list — against a fixture of 40 realms, 15 jobs (605 job rows) and a
//      few hundred runs, some resident and some from the newest-window read,
//      enough to make the window cap apply. The old answer is computed here
//      the way the code before #1766 computed it: every job view built by
//      `jobView()` with no index (its old path), every run view built and
//      sorted on the views' own text, then `pagedRows()` and an `indexOf`.
//   2. THE UNPAGED REPORT IS UNCHANGED TOO: `status()` with no pager still
//      lists every row, the same rows in the same order.
//   3. ONE PAGE BUILDS ONE PAGE: a page of ten jobs builds ten job views and
//      reads each realm's run store once, where the old order built all 605;
//      a page of ten runs builds ten run views.
//
// The clock is frozen for the file, so the old and new answers are asked at
// the same instant; it is put back at the end, with every job and realm the
// file made.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const scheduler = require('../cluster/scheduler');
const schedulerAdmin = require('../admin-ui/scheduler_admin');
const adminViews = require('../admin-core/admin_views');
const admin = require('../admin-ui/admin');
const realms = require('../common/realms');

const log = require('bunyan').createLogger({ name: 'scheduler_report_paging',
  level: process.env.LOG_LEVEL || 'info' });

const TAG = 'srp' + process.pid;
const REALMS = 40;
const REALM_JOBS = 12;
const SERVICE_JOBS = 3;

function requestFor(query) {
  log.debug("Entering requestFor().");
  log.debug("Leaving requestFor().");
  return { query: query || {}, headers: {}, method: 'GET',
           originalUrl: '/admin/scheduler', url: '/admin/scheduler',
           socket: { remoteAddress: '127.0.0.1' } };
}

function firstOf(value) {
  log.debug("Entering firstOf().");
  log.debug("Leaving firstOf().");
  return String((Array.isArray(value) ? value[0] : value) || '');
}

// THE RUNS AS recentRuns() GATHERED THEM BEFORE #1766: a view per accepted
// row as it was found, the newest window's rows after the resident ones,
// sorted on the VIEWS' text, capped when the window was read. (A job filter's
// slot read answers nothing here: the in-process store is not persisted.)
async function oldRecentRuns(s, o) {
  log.debug("Entering oldRecentRuns().");
  const byId = new Map();
  realms.list().forEach(function (realm) {
    const id = String(realm.id);
    if (o.realm && id !== String(o.realm) && id !== realms.DEFAULT_ID) {
      return;
    }
    s.storeOf(id).forEach(function (row) {
      if (!s.acceptsRun(row, id, o)) {
        return;
      }
      byId.set(String(row.runId), s.runView(row));
    });
  });
  let windowed = false;
  const extra = await s.deps.newestRuns(s.newestRealmIds(o), 20);
  if (Array.isArray(extra)) {
    windowed = true;
    extra.forEach(function (row) {
      if (!row || !row.runId || byId.has(String(row.runId))) {
        return;
      }
      const partition = String(row.realm || realms.DEFAULT_ID);
      if (!s.acceptsRun(row, partition, o)) {
        return;
      }
      byId.set(String(row.runId), s.runView(row));
    });
  }
  const out = Array.from(byId.values());
  out.sort(function (a, b) {
    return String(b.startedAt || b.queuedAt || '').localeCompare(
      String(a.startedAt || a.queuedAt || ''));
  });
  log.debug("Leaving oldRecentRuns().");
  return windowed ? out.slice(0, 200) : out;
}

// EVERY JOB VIEW, BUILT AS BEFORE #1766: `jobView()` with no index takes
// `runsOf()`'s old path, a walk of the realm's store per job.
async function oldJobs(s, at, leader) {
  log.debug("Entering oldJobs().");
  const jobs = [];
  s.jobIds().forEach(function (id) {
    const job = s.jobs.get(id);
    s.realmIdsFor(job).forEach(function (realmId) {
      jobs.push(s.jobView(job, realmId, at, leader, ''));
    });
  });
  log.debug("Leaving oldJobs().");
  return jobs;
}

// `schedulerView()` AS IT WAS, over the report as `status()` built it.
async function oldView(q) {
  log.debug("Entering oldView().");
  const s = scheduler.scheduler;
  const o = { realm: '', job: firstOf(q.job), outcome: firstOf(q.outcome) };
  const report = await scheduler.status(o);
  report.jobs = await oldJobs(s, report.nowMs, report.leader);
  report.runs = await oldRecentRuns(s, o);
  report.confinedToRealm = null;
  report.filters = { job: firstOf(q.job) || null,
                     outcome: firstOf(q.outcome) || null };
  const runId = firstOf(q.run);
  if (runId) {
    const run = await scheduler.findRun(runId);
    log.debug("Leaving oldView(). One run.");
    return { generatedAt: report.generatedAt, run: runId, found: !!run,
             detail: run || null, leader: report.leader };
  }
  const paged = adminViews.pagedRows(q, report.runs, { noun: 'runs' });
  report.runs = paged.shown;
  report.runsPaging = adminViews.pagingJson(paged.paging);
  const everyJobId = [];
  report.jobs.forEach(function (job) {
    if (everyJobId.indexOf(String(job.id)) < 0) {
      everyJobId.push(String(job.id));
    }
  });
  const pagedJobs = adminViews.pagedRows(q, report.jobs, { noun: 'jobs',
                                                          name: 'jobs' });
  report.jobs = pagedJobs.shown;
  report.jobsPaging = adminViews.pagingJson(pagedJobs.paging);
  report.jobIds = everyJobId;
  report.settings = admin.configSettingsJson(schedulerAdmin.PAGE);
  log.debug("Leaving oldView().");
  return report;
}

function registerJob(id, scope, registered) {
  log.debug("Entering registerJob().");
  scheduler.register({
    id: id, scope: scope,
    title: 'A job this test registered (' + id + ')',
    describe: 'Registered by tests/scheduler_report_paging.js.',
    owner: 'tests/scheduler_report_paging.js',
    everyMs: function () {
      return 3600000;
    },
    off: function () {
      return '';
    },
    run: function () {
      return Promise.resolve({});
    }
  });
  registered.push(id);
  log.debug("Leaving registerJob().");
}

async function run(t) {
  log.debug("Entering run().");
  const s = scheduler.scheduler;
  const realNow = s.deps.now;
  const realDbNow = s.deps.dbNow;
  const realNewest = s.deps.newestRuns;
  let clock = Date.UTC(2026, 10, 14, 12, 0, 30);
  // Both clocks: the report reads the database's and carries it by its
  // offset from this process's.
  s.deps.now = function () {
    return clock;
  };
  s.deps.dbNow = function () {
    return Promise.resolve(clock);
  };
  const registered = [];
  const made = [];
  try {
    for (let i = 0; i < REALMS; i++) {
      const id = TAG + '-r' + String(i).padStart(2, '0');
      realms.create({ id: id, name: 'Scheduler report paging ' + i });
      made.push(id);
    }
    for (let i = 0; i < REALM_JOBS; i++) {
      registerJob(TAG + '.realm-' + String(i).padStart(2, '0'), 'realm',
                  registered);
    }
    for (let i = 0; i < SERVICE_JOBS; i++) {
      registerJob(TAG + '.service-' + i, 'service', registered);
    }
    // RESIDENT RUNS: queued by hand (one second apart, and some at one
    // instant, so the order has ties to keep), and finished rows written
    // with a start time, which sorts before an un-started one's queue time.
    const runIds = [];
    for (let r = 0; r < 12; r++) {
      for (let j = 0; j < 3; j++) {
        clock += (j === 1 ? 0 : 1000);
        const asked = scheduler.requestRun(
          TAG + '.realm-' + String(j * 4).padStart(2, '0'),
          { realm: made[r], requestedBy: 'scheduler_report_paging' });
        if (asked.ok) {
          runIds.push(asked.runId);
        }
      }
    }
    for (let r = 0; r < REALMS; r++) {
      for (let j = 0; j < 4; j++) {
        const started = clock - (r * 7 + j) * 60000;
        // Queued well before it started, by a varying wait, so ordering by
        // the queue time would give another order than by the start.
        const queued = started - ((r * 5 + j * 11) % 17) * 300000;
        s.writeRow(made[r], {
          runId: TAG + '-done-' + r + '-' + j, kind: 'run',
          jobId: TAG + '.realm-' + String(j).padStart(2, '0'),
          realm: made[r], slot: null, trigger: 'schedule',
          state: j === 3 ? 'failed' : 'succeeded', attempt: 1, fenceAt: 1,
          dueAt: queued, queuedAt: queued, startedAt: started,
          endedAt: started + 1500, durationMs: 1500,
          errorCode: j === 3 ? 'STS-SCHED-0001' : '', why: ''
        });
      }
    }
    // THE NEWEST WINDOW, as the persisted store answers it: rows that are
    // not resident, with one that is (its resident copy wins by id), so the
    // window is read and the 200-row cap applies.
    s.deps.newestRuns = function (realmIds) {
      const rows = [];
      realmIds.forEach(function (realmId, n) {
        for (let k = 0; k < 6; k++) {
          const at = clock - (n * 13 + k) * 45000;
          rows.push({ runId: TAG + '-window-' + realmId + '-' + k,
                      kind: 'run', jobId: TAG + '.realm-05', realm: realmId,
                      slot: k, trigger: 'schedule', state: 'succeeded',
                      attempt: 1, fenceAt: 1, dueAt: at, queuedAt: at,
                      startedAt: at, endedAt: at + 10 });
        }
      });
      rows.push({ runId: TAG + '-done-0-0', kind: 'run', realm: made[0],
                  jobId: TAG + '.realm-00', state: 'succeeded',
                  startedAt: 1 });
      return Promise.resolve(rows);
    };

    // 1. THE OLD ANSWER, FOR EVERY KIND OF QUERY.
    const queries = [
      {},
      { per: '10' },
      { per: '10', jobsPage: '3' },
      { per: '7', page: '2' },
      { per: '10', jobsPage: '9999', page: '9999' },
      { per: '25', jobsPage: '4', page: '3' },
      { job: TAG + '.realm-00', per: '5' },
      { outcome: 'queued', per: '5', page: '2' },
      { outcome: 'failed', job: TAG + '.realm-03' },
      { run: runIds[0] || 'none' },
      { per: '500' }
    ];
    for (const q of queries) {
      const before = JSON.stringify(await oldView(q));
      const after = JSON.stringify(await schedulerAdmin.schedulerView(
        requestFor(q), q));
      t.check(before === after,
              'the paged-before-built view answers exactly what the old ' +
              'view did for ' + JSON.stringify(q),
              before === after ? after.length + ' bytes'
                : 'old ' + before.slice(0, 400) + ' … new ' +
                  after.slice(0, 400));
    }
    const all = await schedulerAdmin.schedulerView(requestFor({}),
                                                   { per: '500' });
    t.check(all.jobsPaging.total >= REALMS * REALM_JOBS + SERVICE_JOBS &&
            all.runsPaging.total === 200,
            'the fixture is large: every (job, realm) row is counted and ' +
            'the run window is capped',
            JSON.stringify({ jobs: all.jobsPaging.total,
                             runs: all.runsPaging.total }));

    // 2. THE UNPAGED REPORT.
    const plain = await scheduler.status({ realm: '' });
    const oldJobsAll = await oldJobs(s, plain.nowMs, plain.leader);
    const oldRunsAll = await oldRecentRuns(s, {});
    t.check(JSON.stringify(plain.jobs) === JSON.stringify(oldJobsAll),
            'status() with no pager lists every job row as before',
            plain.jobs.length + ' row(s)');
    t.check(JSON.stringify(plain.runs) === JSON.stringify(oldRunsAll),
            'and every run, in the old order',
            plain.runs.length + ' run(s)');

    // 3. ONE PAGE BUILDS ONE PAGE.
    const counts = { jobView: 0, runView: 0, storeOf: 0 };
    const real = { jobView: s.jobView, runView: s.runView,
                   storeOf: s.storeOf };
    Object.keys(counts).forEach(function (name) {
      s[name] = function () {
        counts[name] += 1;
        return real[name].apply(this, arguments);
      };
    });
    let page = null;
    try {
      page = await schedulerAdmin.schedulerView(requestFor({}),
                                                { per: '10', jobsPage: '2' });
    } finally {
      Object.keys(real).forEach(function (name) {
        delete s[name];
      });
    }
    t.equal(counts.jobView, 10,
            'a page of ten jobs builds ten job views (all ' +
            all.jobsPaging.total + ' before #1766)');
    // A run view is built for each run on the page and for a job view's
    // last, running and queued runs; the old order built one for every run
    // gathered (over 400 here) before it paged.
    t.check(page.runs.length === 10 && counts.runView <= 10 + 3 * 10,
            'and a page of ten runs builds the views of that page, not of ' +
            'every run gathered',
            counts.runView + ' run view(s)');
    // One walk of each realm's runs for the run list, and for the page's job
    // views one index per realm and one lookup per view; the old order
    // walked a realm's store for every one of its 605 rows.
    t.check(counts.storeOf <= 3 * REALMS,
            'and reads the realms\' run stores a bounded number of times, ' +
            'not once per (job, realm) row',
            counts.storeOf + ' read(s) for ' + REALMS + ' realms');
  } finally {
    s.deps.now = realNow;
    s.deps.dbNow = realDbNow;
    s.deps.newestRuns = realNewest;
    registered.forEach(function (id) {
      s.unregister(id);
    });
    made.forEach(function (id) {
      try {
        realms.remove(id);
      } catch (e) {
        log.debug("Caught in run(): " + ((e && e.message) || e));
      }
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'scheduler_report_paging',
  describe: 'the scheduler report builds only the page it answers, and ' +
            'answers exactly what it did when it built every row first',
  run: run
};
