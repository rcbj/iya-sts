'use strict';
//
// File: ssf_dead_letter_report.js
//
// ===========================================================================
// MONITORING → SHARED SIGNALS → DEAD LETTERS COUNTS WHAT THE QUEUES HOLD
// (2026-09-14).
//
// `ssf/ssf_dead_letter_report.ts` is the one place the page and
// `GET /admin-api/ssf/dead-letters` get their numbers, and
// `admin-core/admin_views.ts`'s `ssfDeadLettersState()` the one place the
// letters are narrowed and paged. What this holds:
//
//   A. THE CAUSES. STS-SSF-0092, -0093 and -0096 are causes of their own and
//      every other code is a push that failed; the counts per cause, per code,
//      per status and per event type add up to what is held.
//   B. NO TOKEN LEAVES. A signed letter says `signed: true` and its token is
//      in no row of the report.
//   C. PER REALM. Letters added in one realm are in no other realm's report,
//      because the queue is a `realms.map()` — one Map per realm.
//   D. THE TIMELINE. Buckets over the retention window ending now, a round
//      bucket size keeping it within sixty, letters older than the window
//      counted beside the buckets rather than in the first one.
//   E. STREAM STATES. Dead, half-open (failing for the dead-stream timeout
//      without being dead) and failing, dead first; a healthy stream with no
//      letters is not a row.
//   F. THE SWEEP HISTORY keeps the last twenty, newest first, with running
//      totals — and is per realm.
//   G. THE NARROWING. `dlstream` and `dlcause` are exact, `dlq` is a
//      substring over the row, they combine, and paging comes after.
//
// In a CHILD PROCESS: it sets SSF settings, creates a realm and requires the
// SSF family's libraries.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'ssf_dead_letter_report',
  level: process.env.LOG_LEVEL || 'info' });

// Runs in the child. Stringified, so it may use nothing from this file's scope.
function child() {
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what, detail: detail || '' });
  };
  const OUT = process.env.SSF_DLR_CHILD_OUT;
  const ROOT = process.env.SSF_DLR_CHILD_ROOT;
  const finish = function () {
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  };
  (async function () {
    const config = require(ROOT + '/common/config');
    [['ssf.enabled', 'true'], ['ssf.pushDelivery', 'true'],
     ['ssf.pushAllowInsecure', 'true'], ['ssf.deadStreamTimeoutS', '300'],
     ['ssf.deadLetterRetentionS', '3600'],
     ['ssf.deadLetterMaxPerStream', '1000']].forEach(function (pair) {
      try {
        config.setOverride(pair[0], pair[1]);
      } catch (e) {
        note(false, 'setting ' + pair[0] + ' is accepted', e.message);
      }
    });
    require(ROOT + '/common/app');
    const realms = require(ROOT + '/common/realms');
    const streams = require(ROOT + '/ssf/ssf_streams');
    const events = require(ROOT + '/ssf/ssf_events');
    const report = require(ROOT + '/ssf/ssf_dead_letter_report');
    const views = require(ROOT + '/admin-core/admin_views');
    const VERIFY = events.SSF_PREFIX + 'verification';
    const UPDATED = events.SSF_PREFIX + 'stream-updated';

    const makeStream = function (url, aud) {
      return streams.createStream({
        events_requested: [VERIFY, UPDATED],
        delivery: { method: streams.DELIVERY_PUSH, endpoint_url: url }
      }, { issuer: 'https://sts.test', principal: 'dlr-probe',
           audience: aud }).stream;
    };
    const claimsFor = function (jti, type) {
      const out = { jti: jti, iss: 'https://sts.test', aud: 'rx', events: {} };
      out.events[type] = {};
      return out;
    };
    const add = function (record, jti, type, why, signed) {
      streams.addDeadLetter(record, { jti: jti,
        token: signed ? 'eyJ.secret-token-' + jti : '',
        claims: claimsFor(jti, type), queuedAt: new Date().toISOString() },
        why);
    };

    // A, B. Three streams in the default realm, every cause.
    const now = Date.now();
    const refused = makeStream('http://127.0.0.1:1/refused',
                               'https://refused.test');
    const down = makeStream('http://127.0.0.1:1/down', 'https://down.test');
    const quiet = makeStream('http://127.0.0.1:1/quiet', 'https://quiet.test');
    add(refused, 'r1', VERIFY, { why: 'refused', errorCode: 'STS-SSF-0043',
      status: 0 }, true);
    add(refused, 'r2', VERIFY, { why: 'refused', errorCode: 'STS-SSF-0043',
      status: 0 }, true);
    add(down, 'd1', UPDATED, { why: 'answered 503', errorCode: 'STS-SSF-0039',
      status: 503 }, true);
    add(down, 'd2', UPDATED, { why: 'backlog', errorCode: 'STS-SSF-0092' },
        false);
    add(down, 'd3', UPDATED, { why: 'declared dead',
      errorCode: 'STS-SSF-0093' }, true);
    add(down, 'd4', UPDATED, { why: 'dead stream',
      errorCode: 'STS-SSF-0096' }, false);
    add(down, 'd5', UPDATED, { why: 'dead stream',
      errorCode: 'STS-SSF-0096' }, false);

    const one = report.report({ nowMs: now + 1000 });
    const cause = {};
    one.causes.forEach(function (row) {
      cause[row.id] = row.count;
    });
    note(cause['push-failed'] === 3 && cause['backlog-full'] === 1 &&
         cause['declared-dead'] === 1 && cause['dead-stream'] === 2,
         'THREE CODES ARE CAUSES OF THEIR OWN AND EVERY OTHER CODE IS A PUSH ' +
         'THAT FAILED', JSON.stringify(cause));
    const sum = function (rows) {
      return rows.reduce(function (n, row) {
        return n + row.count;
      }, 0);
    };
    note(one.totals.held === 7 && sum(one.causes) === 7 &&
         sum(one.byCode) === 7 && sum(one.byStatus) === 7 &&
         sum(one.byEventType) === 7,
         'the counts per cause, code, status and event type each add up to ' +
         'what is held', JSON.stringify({ held: one.totals.held,
           code: sum(one.byCode), status: sum(one.byStatus),
           type: sum(one.byEventType) }));
    note(one.byCode[0].errorCode === 'STS-SSF-0043' &&
         one.byCode[0].count === 2 && one.byCode[0].summary,
         'byCode is biggest first and carries each code\'s summary',
         JSON.stringify(one.byCode[0]));
    note(one.totals.signed === 4 && one.totals.unsigned === 3 &&
         one.totals.streamsHolding === 2,
         'signed and unsigned letters, and the streams holding any, are ' +
         'counted', JSON.stringify(one.totals));
    const text = JSON.stringify(one);
    note(text.indexOf('secret-token') < 0 &&
         one.letters.every(function (row) {
           return !('token' in row);
         }),
         'NO TOKEN LEAVES THE REPORT — a letter says whether it was signed',
         text.indexOf('secret-token') >= 0 ? 'a token is in the report' : '');
    note(one.letters.length === 7 && one.letters[0].event &&
         one.letters[0].event.name,
         'every held letter is listed with its event described',
         JSON.stringify(one.letters[0]));

    // C. PER REALM.
    const realmId = 'dlr-' + process.pid;
    realms.create({ id: realmId, name: 'dead-letter report isolation' });
    const other = realms.run(realms.get(realmId), function () {
      const s = makeStream('http://127.0.0.1:1/other', 'https://other.test');
      add(s, 'o1', VERIFY, { why: 'refused', errorCode: 'STS-SSF-0043' },
          true);
      return report.report({ nowMs: now + 1000 });
    });
    const again = report.report({ nowMs: now + 1000 });
    note(other.realm === realmId && other.totals.held === 1 &&
         other.letters[0].jti === 'o1' && again.totals.held === 7 &&
         again.letters.every(function (row) {
           return row.jti !== 'o1';
         }),
         'PER REALM: a letter added in one realm is in no other realm\'s ' +
         'report', JSON.stringify({ other: other.totals.held,
           here: again.totals.held }));

    // D. THE TIMELINE.
    note(one.timeline.bucketS === 60 && one.timeline.buckets.length === 60 &&
         sum(one.timeline.buckets.map(function (bucket) {
           return { count: bucket.total };
         })) === 7 && one.timeline.peak === 7,
         'the default hour is sixty one-minute buckets holding every letter',
         JSON.stringify({ bucketS: one.timeline.bucketS,
           n: one.timeline.buckets.length, peak: one.timeline.peak }));
    note(report.bucketSecondsFor(2592000) === 43200 &&
         report.bucketSecondsFor(86400) === 1800 &&
         report.bucketSecondsFor(60) === 60,
         'a longer window takes a round bucket size that keeps it within ' +
         'sixty', [report.bucketSecondsFor(2592000),
           report.bucketSecondsFor(86400)].join(','));
    const later = report.report({ nowMs: now + 2 * 3600 * 1000 });
    note(later.timeline.olderThanWindow === 7 && later.timeline.peak === 0,
         'LETTERS OLDER THAN THE WINDOW ARE COUNTED BESIDE IT, not piled ' +
         'into the first bucket', JSON.stringify({
           older: later.timeline.olderThanWindow, peak: later.timeline.peak }));

    // E. STREAM STATES.
    down.deadSinceMs = now - 1000;
    down.deadReason = 'answered 503';
    refused.failingSinceMs = now - 400 * 1000;
    quiet.failingSinceMs = now - 10 * 1000;
    const states = report.report({ nowMs: now });
    const stateOf = {};
    states.streams.forEach(function (row) {
      stateOf[row.stream_id] = row.state;
    });
    note(stateOf[down.stream_id] === 'dead' &&
         stateOf[refused.stream_id] === 'half-open' &&
         stateOf[quiet.stream_id] === 'failing' &&
         states.streams[0].stream_id === down.stream_id &&
         states.totals.deadStreams === 1 &&
         states.totals.halfOpenStreams === 1 &&
         states.totals.failingStreams === 1,
         'DEAD, HALF-OPEN AND FAILING are told apart, dead first',
         JSON.stringify(stateOf));
    quiet.failingSinceMs = 0;
    const healthy = report.report({ nowMs: now });
    note(healthy.streams.every(function (row) {
           return row.stream_id !== quiet.stream_id;
         }),
         'a delivering stream with no letters is not a row',
         JSON.stringify(healthy.streams.map(function (row) {
           return row.stream_id;
         })));

    // F. THE SWEEP HISTORY.
    for (let i = 0; i < 25; i += 1) {
      report.noteSweep({ held: 7, letters: 1, expired: i === 24 ? 3 : 0,
        orphaned: 0, trimmed: 0, byCode: [['STS-SSF-0043', 1]] },
        { nowMs: now + i * 1000, deadStreams: 1, probes: 1 });
    }
    const swept = report.report({ nowMs: now + 30000 });
    note(swept.process.sweeps.length === 20 &&
         swept.process.sweeps[0].expired === 3 &&
         swept.process.sinceStart.sweeps === 25 &&
         swept.process.sinceStart.letters === 25 &&
         swept.process.sinceStart.probes === 25 &&
         swept.process.pid === process.pid,
         'THE SWEEP HISTORY keeps the last twenty, newest first, with totals ' +
         'since the process started', JSON.stringify({
           kept: swept.process.sweeps.length,
           since: swept.process.sinceStart }));
    const otherSweeps = realms.run(realms.get(realmId), function () {
      return report.report().process.sinceStart.sweeps;
    });
    note(otherSweeps === 0, 'and it is per realm', String(otherSweeps));

    // G. THE NARROWING.
    const narrowed = function (query) {
      return views.ssfDeadLettersState({ query: query }, again);
    };
    const byStream = narrowed({ dlstream: refused.stream_id });
    const byCause = narrowed({ dlcause: 'dead-stream' });
    const byText = narrowed({ dlq: 'sts-ssf-0039' });
    const both = narrowed({ dlstream: down.stream_id,
                            dlcause: 'backlog-full' });
    const partial = narrowed({ dlstream: refused.stream_id.slice(0, 6) });
    const paged = narrowed({ per: '3', lettersPage: '3' });
    note(byStream.rows.length === 2 && byCause.rows.length === 2 &&
         byText.rows.length === 1 && byText.rows[0].jti === 'd1' &&
         both.rows.length === 1 && both.rows[0].jti === 'd2' &&
         partial.rows.length === 0,
         'dlstream and dlcause are EXACT, dlq is a substring, and they combine',
         JSON.stringify({ stream: byStream.rows.length,
           cause: byCause.rows.length, text: byText.rows.length,
           both: both.rows.length, partial: partial.rows.length }));
    note(paged.page.shown.length === 1 && paged.page.paging.page === 3 &&
         paged.page.paging.pages === 3 && paged.rows.length === 7,
         'paging comes after the narrowing, on lettersPage',
         JSON.stringify(paged.page.paging));
  })().catch(function (e) {
    note(false, 'the child ran to the end', e && e.stack);
  }).then(finish);
}

function run(t) {
  log.debug("Entering run().");
  const root = path.join(__dirname, '..');
  const out = path.join(os.tmpdir(), 'sts-ssf-dlr-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = Object.assign({}, process.env, {
    SSF_DLR_CHILD_OUT: out, SSF_DLR_CHILD_ROOT: root, LOG_LEVEL: 'fatal',
    STS_LOG_LEVEL: 'fatal',
    // This file's streams are its own; the console's and portal's receivers
    // would only add streams to count.
    STS_SSF_INTERNAL_RECEIVERS: 'false' });
  delete env.CONFIG_FILE;
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + child.toString() + ')()'], {
      cwd: root, env: env, encoding: 'utf8', timeout: 180000,
      maxBuffer: 64 * 1024 * 1024 });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    // The child died before writing a report; said below with its status.
    findings = null;
  }
  try {
    fs.rmSync(out, { force: true });
  } catch (e) {
    // A temporary file left behind is not a failed assertion.
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (t.check(Array.isArray(findings),
              'the child process reported its findings',
              'status=' + result.status + ' ' +
              String(result.stderr || '').slice(-2000))) {
    findings.forEach(function (one) { t.check(one.ok, one.what, one.detail); });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'ssf_dead_letter_report',
  describe: 'Monitoring → Shared Signals → Dead letters counts the queues by ' +
            'cause, code, status, event type, time and stream, per realm, ' +
            'with no token, and narrows and pages the letters',
  run: run
};
