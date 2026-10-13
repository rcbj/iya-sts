// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/ssf_streams_paging.js
//
// ---------------------------------------------------------------------------
// MONITORING -> SHARED SIGNALS, THE STREAMS TABLES PAGED (#313).
//
// Three tables listed every Shared Signals stream they had, whole, on the page
// and on its `/admin-api` read alike: *Where a CAEP event could go* on
// `/admin/caep-sessions`, *Where a RISC event could go* on
// `/admin/risc-accounts`, and *Streams* on `/admin/ssf/dead-letters`.
// `ssf.maxStreams` limits each receiver, not the number of receivers, so each
// grew with the realm. Each now moves on `streamsPage`, and this file holds
// the view model both doors read to it:
//
//   1. ONE PAGE OF STREAMS, with `streamCounts` still counting the whole list
//      (the tile above the tables reads it).
//   2. EACH PARAMETER MOVES ONLY ITS OWN LIST — `streamsPage` leaves the
//      sessions and the receivers where they were, and they leave it.
//   3. A PAGE PAST THE END CLAMPED to the last.
//   4. THE DEAD LETTERS' STREAMS NARROWED BEFORE PAGING by `dlstream` and
//      `dlcause`, with `dlq` (over the letters) leaving them whole.
//   5. A WALK OF EVERY PAGE seeing every stream once.
//
// In process, over synthetic reports: the functions are the ones
// `caepSessionsJson()`, `riscAccountsJson()` and `ssfDeadLettersJson()` call,
// and filling a realm with real streams would be a registered receiver and a
// stream negotiation per row. The reporter slots are process-wide and other
// tests read them, so this file does not replace them.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const adminViews = require('../admin-core/admin_views');

const log = require('bunyan').createLogger({ name: 'ssf_streams_paging',
  level: process.env.LOG_LEVEL || 'info' });

const STREAMS = 23;
const SESSIONS = 17;
const RECEIVERS = 12;

function streamRows() {
  log.debug("Entering streamRows().");
  const rows = [];
  for (let i = 0; i < STREAMS; i++) {
    // Every third stream takes nothing, so `taking` differs from `total`.
    rows.push({ stream_id: 'stream-' + String(i).padStart(2, '0'),
                aud: 'https://rp' + i + '.example', status: 'enabled',
                delivery: 'push', subjects: i,
                takes: i % 3 === 0 ? [] : ['session-revoked'] });
  }
  log.debug("Leaving streamRows().");
  return rows;
}

function caepReport() {
  log.debug("Entering caepReport().");
  const sessions = [];
  for (let i = 0; i < SESSIONS; i++) {
    sessions.push({ sessionId: 'sid-' + i, username: 'person' + i,
                    sub: 'sub-' + i, subject: '', protocol: 'oidc' });
  }
  const applications = [];
  for (let i = 0; i < RECEIVERS; i++) {
    applications.push({ identifier: 'app-' + i, name: 'App ' + i,
                        audiences: ['https://rp' + i + '.example'] });
  }
  log.debug("Leaving caepReport().");
  return { sessions: sessions, applications: applications,
           streams: streamRows() };
}

function deadLetterReport() {
  log.debug("Entering deadLetterReport().");
  const streams = streamRows().map(function (row, i) {
    return { stream_id: row.stream_id, state: i % 2 ? 'failing' : 'dead',
             held: i % 4,
             causes: { 'push-failed': i % 4, 'backlog-full': i % 2 ? 1 : 0,
                       'declared-dead': 0, 'dead-stream': 0 } };
  });
  const letters = [];
  for (let i = 0; i < 9; i++) {
    letters.push({ jti: 'jti-' + i, stream_id: 'stream-01', reason: 'x',
                   errorCode: '', status: 500, cause: 'push-failed',
                   event: { name: '', types: [], subject: '' } });
  }
  log.debug("Leaving deadLetterReport().");
  return { streams: streams, letters: letters };
}

function ids(rows) {
  return rows.map(function (row) {
    return row.stream_id;
  });
}

function run(t) {
  log.debug("Entering run().");
  const report = caepReport();

  // --- 1. One page, the counts over the whole list ------------------------
  const first = adminViews.signalStreamsState({ query: { per: '5' } }, report);
  t.check(first.page.shown.length === 5 &&
          first.page.paging.total === STREAMS &&
          first.page.paging.pages === Math.ceil(STREAMS / 5) &&
          first.page.paging.param === 'streamsPage',
          '1a. the streams list is one page of five, on streamsPage',
          JSON.stringify(first.page.paging));
  const taking = report.streams.filter(function (row) {
    return row.takes.length;
  }).length;
  t.check(first.counts.total === STREAMS && first.counts.taking === taking,
          '1b. the counts are over every stream, not the page',
          JSON.stringify(first.counts));

  // --- 2. Each parameter moves only its own list --------------------------
  const asked = { per: '5', streamsPage: '3' };
  const moved = adminViews.signalStreamsState({ query: asked }, report);
  const sessions = adminViews.caepSessionsState({ query: asked }, report);
  const receivers = adminViews.caepApplicationsState({ query: asked },
                                                     report);
  t.check(moved.page.paging.page === 3 &&
          ids(moved.page.shown)[0] === 'stream-10' &&
          sessions.page.paging.page === 1 &&
          receivers.page.paging.page === 1,
          '2a. streamsPage moves the streams and nothing else',
          JSON.stringify({ streams: moved.page.paging.page,
                           sessions: sessions.page.paging.page,
                           receivers: receivers.page.paging.page }));
  const other = { per: '5', sessionsPage: '2', applicationsPage: '2' };
  const still = adminViews.signalStreamsState({ query: other }, report);
  t.check(still.page.paging.page === 1 &&
          adminViews.caepSessionsState({ query: other }, report)
            .page.paging.page === 2 &&
          adminViews.caepApplicationsState({ query: other }, report)
            .page.paging.page === 2,
          '2b. the other two lists\' pages leave the streams on page 1',
          JSON.stringify(still.page.paging));
  const risc = { per: '5', accountsPage: '2', rapplicationsPage: '2' };
  t.check(adminViews.signalStreamsState({ query: risc }, report)
            .page.paging.page === 1,
          '2c. the RISC page\'s two lists leave the streams on page 1', '');

  // --- 3. Past the end, clamped -------------------------------------------
  const past = adminViews.signalStreamsState(
    { query: { per: '5', streamsPage: '99' } }, report);
  t.check(past.page.paging.page === past.page.paging.pages &&
          past.page.shown.length === STREAMS % 5,
          '3. a page past the end is the last page',
          JSON.stringify(past.page.paging));

  // --- 4. The dead letters' streams, narrowed then paged ------------------
  const dl = deadLetterReport();
  const whole = adminViews.ssfDeadLettersState(
    { query: { per: '4' } }, dl);
  t.check(whole.streamPage.paging.total === STREAMS &&
          whole.streamPage.shown.length === 4 &&
          whole.streamPage.paging.param === 'streamsPage',
          '4a. the dead letters\' streams are paged on streamsPage',
          JSON.stringify(whole.streamPage.paging));
  const oneStream = adminViews.ssfDeadLettersState(
    { query: { per: '4', dlstream: 'stream-05' } }, dl);
  t.check(oneStream.streamPage.paging.total === 1 &&
          ids(oneStream.streamPage.shown)[0] === 'stream-05',
          '4b. dlstream narrows the streams to that one', '');
  const byCause = adminViews.ssfDeadLettersState(
    { query: { per: '4', dlcause: 'backlog-full' } }, dl);
  const backlog = dl.streams.filter(function (row) {
    return row.causes['backlog-full'] > 0;
  }).length;
  t.check(byCause.streamPage.paging.total === backlog &&
          byCause.streamPage.shown.every(function (row) {
            return row.causes['backlog-full'] > 0;
          }),
          '4c. dlcause narrows the streams to those holding that cause',
          JSON.stringify({ total: byCause.streamPage.paging.total,
                           expected: backlog }));
  const searched = adminViews.ssfDeadLettersState(
    { query: { per: '4', dlq: 'jti-3' } }, dl);
  t.check(searched.rows.length === 1 &&
          searched.streamPage.paging.total === STREAMS,
          '4d. dlq narrows the letters and leaves the streams whole', '');
  const lettersMoved = adminViews.ssfDeadLettersState(
    { query: { per: '4', lettersPage: '2' } }, dl);
  t.check(lettersMoved.page.paging.page === 2 &&
          lettersMoved.streamPage.paging.page === 1,
          '4e. lettersPage moves the letters and not the streams', '');

  // --- 5. A walk of every page reads every stream once --------------------
  const seen = [];
  for (let page = 1; page <= 20; page++) {
    const one = adminViews.signalStreamsState(
      { query: { per: '4', streamsPage: String(page) } }, report);
    seen.push.apply(seen, ids(one.page.shown));
    if (page >= one.page.paging.pages) {
      break;
    }
  }
  const distinct = seen.filter(function (id, i) {
    return seen.indexOf(id) === i;
  });
  t.check(seen.length === STREAMS && distinct.length === STREAMS,
          '5. walking every page reads every stream exactly once',
          JSON.stringify({ seen: seen.length, distinct: distinct.length }));
  log.debug("Leaving run().");
}

module.exports = {
  name: 'ssf streams paging',
  describe: 'Monitoring -> Shared Signals: the streams tables on CAEP ' +
            'sessions, RISC accounts and dead letters paged on streamsPage, ' +
            'each pager moving only its list, clamped, narrowed and walked',
  run: run
};
