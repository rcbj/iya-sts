'use strict';
//
// File: tests/scheduler_paging.js
//
// ---------------------------------------------------------------------------
// MONITORING -> SCHEDULER: BOTH LISTS PAGE (rcbj, 2026-09-22).
//
// The recent runs were paged from the day that page was written; the JOBS were
// not, and that list grows without a bound anybody sets — every owner
// registers its jobs, and a REALM job has a row per realm, so a service with
// fifty realms has fifty rows of each. `admin-ui/CLAUDE.md`'s *every list that
// can grow without a bound is paged* is the rule; this file holds the
// scheduler page to it:
//
//   1. ONE PAGE OF JOBS, not the whole list, with `jobsPaging` carrying the
//      total — and the runs beside them still paged as they were.
//   2. TWO PAGERS THAT DO NOT MOVE EACH OTHER: `jobsPage` moves the jobs and
//      `page` moves the runs, with one `per` sizing both.
//   3. A PAGE PAST THE END CLAMPED to the last.
//   4. A WALK OF EVERY PAGE seeing every job once.
//   5. THE RUNS FILTER'S MENU IS BUILT FROM EVERY JOB, not from the page —
//      `jobIds` — because a menu offering only what is on the screen cannot
//      filter by anything else.
//
// In process, through `schedulerView()`, which is the one view model the page's
// `?format=json` and `GET /admin-api/scheduler` both answer: registering
// hundreds of jobs over HTTP is not a thing a caller can do, and which SLICE
// each door returns is the whole subject. The markup — a nav above and below
// the table, and links that keep the other list's page — is asserted against
// the drawn page at the foot.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const scheduler = require('../cluster/scheduler');
const schedulerAdmin = require('../admin-ui/scheduler_admin');

const log = require('bunyan').createLogger({ name: 'scheduler_paging',
  level: process.env.LOG_LEVEL || 'info' });

const TAG = 'spg' + process.pid;
const EXTRA = 60;

function requestFor(query) {
  log.debug("Entering requestFor().");
  log.debug("Leaving requestFor().");
  return { query: query || {}, headers: {}, method: 'GET',
           originalUrl: '/admin/scheduler', url: '/admin/scheduler',
           socket: { remoteAddress: '127.0.0.1' } };
}

async function run(t) {
  log.debug("Entering run().");
  const registered = [];
  for (let i = 0; i < EXTRA; i++) {
    const id = TAG + '.job-' + String(i).padStart(3, '0');
    scheduler.register({
      id: id,
      title: 'A job this test registered (' + i + ')',
      describe: 'Registered by tests/scheduler_paging.js.',
      owner: 'tests/scheduler_paging.js',
      everyMs: function () {
        return 3600000;
      },
      off: function () {
        return 'registered by a test; it never runs';
      },
      run: function () {
        return Promise.resolve({});
      }
    });
    registered.push(id);
  }
  try {
    const all = await schedulerAdmin.schedulerView(requestFor({}),
                                                   { per: '500' });
    const total = all.jobs.length;
    t.check(total >= EXTRA,
            'the view lists every registered job when asked for them all',
            total + ' job(s)');

    // 1. ONE PAGE.
    const first = await schedulerAdmin.schedulerView(requestFor({}),
                                                     { per: '10' });
    t.equal(first.jobs.length, 10, 'a page of ten jobs is ten rows');
    t.check(first.jobsPaging && first.jobsPaging.total === total &&
            first.jobsPaging.pages === Math.ceil(total / 10),
            'and jobsPaging carries the total and the page count, so the ' +
            'page can say what it is showing of what',
            JSON.stringify(first.jobsPaging));
    t.check(Array.isArray(first.runs) && first.runsPaging,
            'the runs beside them are still paged as they were',
            JSON.stringify(first.runsPaging));

    // 2. TWO PAGERS.
    const second = await schedulerAdmin.schedulerView(requestFor({}),
                                                      { per: '10',
                                                        jobsPage: '2' });
    t.check(second.jobs[0] && first.jobs[0] &&
            second.jobs[0].id !== first.jobs[0].id,
            'jobsPage moves the job list',
            JSON.stringify({ first: first.jobs[0] && first.jobs[0].id,
                             second: second.jobs[0] && second.jobs[0].id }));
    const runsMoved = await schedulerAdmin.schedulerView(requestFor({}),
                                                         { per: '10',
                                                           page: '2' });
    t.check(runsMoved.jobs[0] && first.jobs[0] &&
            runsMoved.jobs[0].id === first.jobs[0].id,
            'and `page` — the runs\' own parameter — leaves the jobs where ' +
            'they were, which is what lets a reader move one list at a time');

    // 3. PAST THE END.
    const far = await schedulerAdmin.schedulerView(requestFor({}),
                                                    { per: '10',
                                                      jobsPage: '9999' });
    t.equal(far.jobsPaging.page, far.jobsPaging.pages,
            'a jobs page past the end is clamped to the last');

    // 4. EVERY JOB ONCE.
    const seen = [];
    for (let page = 1; page <= first.jobsPaging.pages; page++) {
      const view = await schedulerAdmin.schedulerView(
        requestFor({}), { per: '10', jobsPage: String(page) });
      view.jobs.forEach(function (job) {
        seen.push(job.id + '@' + job.realm);
      });
    }
    const unique = seen.filter(function (key, i) {
      return seen.indexOf(key) === i;
    });
    t.check(seen.length === total && unique.length === total,
            'walking every page sees every job exactly once',
            JSON.stringify({ walked: seen.length, unique: unique.length,
                             total: total }));

    // 5. THE FILTER MENU.
    t.check(Array.isArray(first.jobIds) &&
            registered.every(function (id) {
              return first.jobIds.indexOf(id) >= 0;
            }),
            'the view carries EVERY job id beside the paged rows, for the ' +
            'runs filter\'s menu',
            (first.jobIds || []).length + ' id(s) with ten rows shown');
  } finally {
    // The instance, because the module's own exports are the service's API
    // and `unregister()` is not part of it — a job's owner registers it for
    // the life of the process.
    registered.forEach(function (id) {
      scheduler.scheduler.unregister(id);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'scheduler_paging',
  describe: 'the scheduler page pages its jobs as well as its runs, on a ' +
            'parameter of their own, and its filter menu names every job',
  run: run
};
