// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_ssf_dead_letters.ts
//
// ---------------------------------------------------------------------------
// MONITORING → SHARED SIGNALS DEAD LETTERS, DRAWN FROM ITS VIEW ALONE (#446,
// 2026-10-05).
//
// Draws the Shared Signals dead letters from the answer of `GET
// /admin-api/ssf/dead-letters`: the events a receiver never acknowledged, over
// time, stream by stream, with Retry.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// It was drawn inside the route of `/admin/ssf/dead-letters` in
// `admin-ui/admin.ts`, which still draws the page until the console's cutover
// by calling this with its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('../admin-ui/web_kit');

type Json = any;

// ---------------------------------------------------------------------------
// MONITORING -> SHARED SIGNALS -> DEAD LETTERS (2026-09-14).
//
// What every dead-letter queue in the realm being read holds, counted, and the
// letters themselves. `ssf/ssf_dead_letter_report.ts` computes every number
// and `admin-core/admin_views.ts`'s `ssfDeadLettersJson()` searches and pages
// the list, for this page and `GET /admin-api/ssf/dead-letters` alike; this
// draws them.
//
// **READ-ONLY, AND THE CONTROLS ARE ONE LINK AWAY.** Revive and Drop its dead
// letters act on ONE stream and live on that stream's card at /admin/ssf,
// which every stream row here links to. A second copy of either here would be
// a second door onto the same two actions for no reader who needs it — the
// reason to come to this page is to find WHICH stream, and the next click is
// that stream.
//
// **THE CHART IS THE FIRST IN THIS CONSOLE**, so its choices are written down
// here rather than inherited. A stacked column per time bucket over the whole
// retention window, one colour per CAUSE (not per error code — there are more
// than a dozen of those, and four is what a reader acts on). The four colours
// were checked with a colour-vision validator rather than chosen by eye: the
// worst adjacent pair is ΔE 9.1 under protanopia and 22.9 in normal vision.
// Two of them are under 3:1 against the white card, which is why no value is
// ever carried by colour alone: the legend names each cause and its count in
// text, every column's `<title>` gives its counts on hover, and the same
// numbers are a table under it. There is no script, so the hover is the
// browser's own tooltip on an SVG `<title>`, over a hit area the full height
// of the plot so a one-letter column can still be pointed at.
// ---------------------------------------------------------------------------
const DEAD_LETTER_COLOURS = {
  'push-failed': '#2a78d6',
  'backlog-full': '#eb6834',
  'declared-dead': '#1baf7a',
  'dead-stream': '#eda100'
};

/**
 * Draws the Shared Signals dead letters from the answer of `GET
 * /admin-api/ssf/dead-letters`: the events a receiver never acknowledged, over
 * time, stream by stream, with Retry.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class SsfDeadLettersPage {
  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static body(ctx, json) {
    if (!json.installed) {
      const missing = '<h1>Dead letters</h1><div ' +
        'class="err"><strong>Shared Signals is not loaded in this ' +
        'process</strong>, so there are no dead-letter queues to report ' +
        'on.</div>';
      return missing;
    }
    const totals = json.totals;
    const causeById = {};
    json.causes.forEach(function (cause) {
      causeById[cause.id] = cause;
    });
    const listView = kit.listViewOf('/admin/ssf/dead-letters', ctx.query);
    // A link to the letters narrowed, keeping the rest of the view and going
    // back to the first page of what it narrows to.
    const lettersOf = function (overrides) {
      return kit.esc('/admin/ssf/dead-letters' + kit.queryWith(listView,
        Object.assign({ lettersPage: '' }, overrides))) + '#find-dlq';
    };
    const share = function (count) {
      return totals.held
        ? Math.round(count * 100 / totals.held) + '%' : '&mdash;';
    };

    const tiles = '<div class="tiles">' +
      kit.tile(totals.held, 'dead letters held') +
      kit.tile(totals.streamsHolding, 'streams holding them') +
      kit.tile(totals.deadStreams, 'dead streams') +
      kit.tile(totals.halfOpenStreams, 'half-open') +
      kit.tile(totals.failingStreams, 'failing') +
      kit.tile(totals.unsigned, 'never signed') +
      kit.tile(totals.newestAgeS === null ? '—'
        : kit.durationText(totals.newestAgeS * 1000), 'since the newest') +
      kit.tile(totals.oldestAgeS === null ? '—'
        : kit.durationText(totals.oldestAgeS * 1000), 'since the oldest') +
      '</div>';

    const off = (!json.enabled
      ? kit.warn('<strong>Shared Signals is turned off</strong> ' +
        '(<code>ssf.enabled</code>), so nothing new is sent or ' +
        'dead-lettered. What is below is held until ' +
        '<code>ssf.deadLetterRetentionS</code> passes.')
      : '') +
      (json.enabled && !json.pushDelivery
        ? kit.warn('<strong>Push delivery is off</strong> ' +
          '(<code>ssf.pushDelivery</code>), so no push is made and none ' +
          'can fail. Poll streams have no dead letters.')
        : '');

    // WHEN. The chart, its legend, and the same numbers as a table.
    const timeline = json.timeline;
    const legend = '<div class="legend">' + json.causes.map(function (cause) {
      return '<span title="' + kit.esc(cause.what) + '">' +
        SsfDeadLettersPage.deadLetterSwatch(
          DEAD_LETTER_COLOURS[cause.id] || '#8a8a99') +
        kit.esc(cause.label) + ' ' + kit.esc(String(cause.count)) +
        '</span>';
    }).join('') + '</div>';
    const busy = timeline.buckets.filter(function (bucket) {
      return bucket.total > 0;
    });
    const timelineTable = busy.length
      ? '<details><summary>The same as a table (' + busy.length + ' of ' +
        timeline.buckets.length + ' columns hold anything)</summary>' +
        kit.wideTable('Dead letters by time', '<table><tr><th>From</th>' +
        json.causes.map(function (cause) {
          return '<th class="num">' + kit.esc(cause.label) + '</th>';
        }).join('') + '<th class="num">All</th></tr>' +
        busy.map(function (bucket) {
          return '<tr><td class="sub">' +
            kit.esc(kit.whenText(Date.parse(bucket.start))) + '</td>' +
            json.causes.map(function (cause) {
              return '<td class="num">' + bucket.counts[cause.id] + '</td>';
            }).join('') + '<td class="num">' + bucket.total + '</td></tr>';
        }).join('') + '</table>') + '</details>'
      : '';
    const older = timeline.olderThanWindow
      ? kit.note(kit.esc(String(timeline.olderThanWindow)) + ' letter(s) ' +
        'are older than the window and are not drawn: the next sweep ' +
        'deletes them. That happens when ' +
        '<code>ssf.deadLetterRetentionS</code> is shortened, and before a ' +
        'process has swept since it started.')
      : '';

    // WHY.
    const causeRows = json.causes.map(function (cause) {
      return '<tr><td>' +
             SsfDeadLettersPage.deadLetterSwatch(
               DEAD_LETTER_COLOURS[cause.id]) +
        ' ' + kit.esc(cause.label) +
        (cause.code
          ? '<div><a href="/admin/error-codes#' + kit.esc(cause.code) +
            '"><code class="ec">' + kit.esc(cause.code) + '</code></a></div>'
          : '') + '</td>' +
        '<td>' + kit.esc(cause.what) + '</td>' +
        '<td class="num">' + (cause.count
          ? '<a href="' + lettersOf({ dlcause: cause.id }) + '">' +
            cause.count + '</a>'
          : '0') + '</td>' +
        '<td class="num">' + share(cause.count) + '</td></tr>';
    }).join('');
    const codeRows = json.byCode.map(function (row) {
      const cause = causeById[row.cause] || { label: row.cause };
      return '<tr><td>' + (row.errorCode
          ? '<a href="/admin/error-codes#' + kit.esc(row.errorCode) + '">' +
            '<code class="ec">' + kit.esc(row.errorCode) + '</code></a>'
          : '<span class="sub">none recorded</span>') + '</td>' +
        '<td>' + kit.esc(cause.label) + '</td>' +
        '<td>' + kit.esc(row.summary) + '</td>' +
        '<td class="num">' + (row.errorCode
          ? '<a href="' + lettersOf({ dlq: row.errorCode }) + '">' +
            row.count + '</a>'
          : String(row.count)) + '</td></tr>';
    }).join('') || '<tr><td colspan="4">Nothing held.</td></tr>';
    const statusRows = json.byStatus.map(function (row) {
      return '<tr><td>' + (row.status
          ? 'HTTP ' + kit.esc(String(row.status))
          : '<span class="sub">no HTTP answer &mdash; not pushed, or ' +
            'nothing answered</span>') + '</td>' +
        '<td class="num">' + row.count + '</td>' +
        '<td class="num">' + share(row.count) + '</td></tr>';
    }).join('') || '<tr><td colspan="3">Nothing held.</td></tr>';
    const typeRows = json.byEventType.map(function (row) {
      return '<tr><td>' + kit.esc(row.name || '(unreadable)') + '</td>' +
        '<td class="sub"><code>' + kit.esc(row.type || '') + '</code></td>' +
        '<td class="num">' + (row.name
          ? '<a href="' + lettersOf({ dlq: row.type || row.name }) + '">' +
            row.count + '</a>'
          : String(row.count)) + '</td>' +
        '<td class="num">' + share(row.count) + '</td></tr>';
    }).join('') || '<tr><td colspan="4">Nothing held.</td></tr>';

    // WHICH STREAMS.
    const stateText = {
      dead: '<span class="state-revoked">dead</span>',
      'half-open': '<span class="state-expired">half-open</span>',
      failing: '<span class="state-expired">failing</span>',
      healthy: '<span class="state-valid">delivering</span>',
      poll: '<span class="sub">poll</span>',
      unknown: '<span class="sub">not held here</span>'
    };
    const streamRows = json.streams.map(function (row) {
      const when = row.state === 'dead'
        ? 'dead since ' + kit.whenText(Date.parse(row.deadSince)) +
          (row.nextProbeAt
            ? '; next probe ' + kit.whenText(Date.parse(row.nextProbeAt)) :
              '')
        : (row.failingSince
          ? 'failing since ' + kit.whenText(Date.parse(row.failingSince)) :
            '');
      return '<tr><td class="who">' + (row.state === 'unknown'
          ? '<code>' + kit.esc(row.stream_id) + '</code>'
          : '<a href="/admin/ssf#stream-' + kit.esc(row.stream_id) +
            '" title="' +
            kit.esc('This stream\'s card on Protocols → Shared Signals, ' +
                     'where Revive and Drop its dead letters are.') +
                     '"><code>' +
            kit.esc(row.stream_id) + '</code></a>') +
        (row.aud
          ? '<div class="sub">' + kit.esc(Array.isArray(row.aud)
            ? row.aud.join(', ') : String(row.aud)) + '</div>'
          : '') + '</td>' +
        '<td>' + (stateText[row.state] || kit.esc(row.state)) +
        (when ? '<div class="sub">' + kit.esc(when) + '</div>' : '') +
        '</td><td>' + kit.esc(row.deadReason || row.lastPushError || '') +
        '</td><td class="num">' + (row.held
          ? '<a href="' + lettersOf({ dlstream: row.stream_id }) + '">' +
            row.held + '</a>'
          : '0') + '</td>' +
        '<td class="sub">' + json.causes.filter(function (cause) {
          return row.causes[cause.id] > 0;
        }).map(function (cause) {
          return kit.esc(cause.label) + ' ' + row.causes[cause.id];
        }).join('<br>') + '</td>' +
        '<td class="num">' + row.deadLetteredEver + '</td></tr>';
    }).join('') ||
      '<tr><td colspan="6">Every push stream is delivering and ' +
      'none holds a dead letter.</td></tr>';

    // THE LETTERS.
    const search = kit.sectionSearchForm({
      path: '/admin/ssf/dead-letters', param: 'dlq', pageParam: 'lettersPage',
      query: ctx.query, label: 'Find',
      placeholder: 'a jti, STS-SSF-0092, session-revoked, 503',
      what: 'Over the jti, the stream, the reason, the error code, the ' +
            'receiver\'s status, the event name and type URI and the ' +
            'subject. The counts above are the whole realm\'s whatever is ' +
            'searched.' });
    const narrowed = [];
    if (json.filter.stream) {
      narrowed.push('stream <code>' + kit.esc(json.filter.stream) +
                    '</code> ' +
        '(<a href="' + lettersOf({ dlstream: '' }) + '">any stream</a>)');
    }
    if (json.filter.cause) {
      narrowed.push('cause ' + kit.esc((causeById[json.filter.cause] ||
        { label: json.filter.cause }).label) + ' (<a href="' +
        lettersOf({ dlcause: '' }) + '">any cause</a>)');
    }
    const nav = kit.pageNavPair('/admin/ssf/dead-letters',
                                 kit.pageParamsOf(ctx.query),
      Object.assign({ param: 'lettersPage', noun: 'dead letters' },
                    json.paging.letters));
    const letterRows = SsfDeadLettersPage.deadLetterRows(json, causeById,
      listView) ||
      '<tr><td colspan="7">' + (json.matched === 0 && totals.held
        ? 'No dead letter matches.'
        : 'No dead letters are held in this realm.') + '</td></tr>';

    // THIS PROCESS.
    const proc = json.process;
    const pushes = proc.pushes || {};
    const sweepRows = proc.sweeps.map(function (row) {
      return '<tr><td class="sub">' +
             kit.esc(kit.whenText(Date.parse(row.at))) +
        '</td><td class="num">' + row.letters + '</td>' +
        '<td class="num">' + row.held + '</td>' +
        '<td class="num">' + row.expired + '</td>' +
        '<td class="num">' + row.trimmed + '</td>' +
        '<td class="num">' + row.orphaned + '</td>' +
        '<td class="num">' + row.deadStreams + '</td>' +
        '<td class="num">' + row.probes + '</td></tr>';
    }).join('') || '<tr><td colspan="8">This process has not swept this ' +
      'realm yet. It sweeps every ' +
      '<code>ssf.deadLetterSweepS</code>.</td></tr>';
    const since = proc.sinceStart;

    const s = json.settings;
    const settingRows = [
      ['ssf.deadLetterRetentionS', s.retentionS, 'seconds a letter is kept'],
      ['ssf.deadLetterMaxPerStream', s.maxPerStream,
       'letters one stream keeps; past it the oldest go'],
      ['ssf.deadStreamTimeoutS', s.deadStreamTimeoutS,
       'seconds of failed pushes before a stream is dead (0: never)'],
      ['ssf.deadLetterSweepS', s.sweepS, 'seconds between sweeps'],
      ['ssf.pushConcurrency', s.pushConcurrency,
       'pushes in flight per process (0: no cap)'],
      ['ssf.pushBacklog', s.pushBacklog,
       'pushes waiting per process before STS-SSF-0092'],
      ['ssf.pushRetries', s.pushRetries, 'retries before a push has failed']
    ].map(function (row) {
      return '<tr><td><code>' + kit.esc(row[0]) + '</code></td>' +
        '<td class="num">' + kit.esc(String(row[1])) + '</td>' +
        '<td>' + kit.esc(row[2]) + '</td></tr>';
    }).join('');

    const inner = '<h1>Dead letters</h1><p>Every Security Event Token the ' +
      'transmitter <strong>could not deliver</strong> and is still ' +
      'holding, in the &ldquo;' + kit.esc(json.realm) + '&rdquo; realm ' +
      '&mdash; each realm has dead-letter queues of its own. A letter is ' +
      'kept for <code>ssf.deadLetterRetentionS</code> with the reason, and ' +
      'nothing resends it except the probe that tries to revive a dead ' +
      'stream.</p>' +
      off +
      tiles +
      kit.note('<strong>This page reports; it changes nothing.</strong> ' +
      'Revive a dead stream or drop its letters on that stream\'s card at ' +
      '<a href="/admin/ssf">Protocols &rarr; Shared Signals</a> &mdash; ' +
      'every stream below links to it. Counted ' +
      kit.esc(kit.whenText(Date.parse(json.generatedAt))) + '.') +

      '<h2>When</h2>' +
      kit.note('Held letters by when they were dead-lettered, in ' +
      kit.esc(SsfDeadLettersPage.deadLetterSpan(timeline.bucketS)) +
        ' columns over the ' +
        'last ' +
      kit.esc(SsfDeadLettersPage.deadLetterSpan(timeline.windowS)) +
        ' &mdash; the ' +
      'whole retention window, so a letter that has aged out is gone from ' +
      'the chart as it is from the queue. Point at a column for its ' +
      'counts.') +
      legend +
      SsfDeadLettersPage.deadLetterTimeline(timeline, json.causes) +
      timelineTable +
      older +

      '<h2>Why</h2>' +
      kit.note('Four causes, each a different thing to do about it. Every ' +
      'other code a failed push can carry is a push that failed, and is ' +
      'broken out below.') +
      '<table><tr><th>Cause</th><th>What it means</th>' +
      '<th class="num">Held</th><th class="num">Share</th></tr>' +
      causeRows + '</table>' +
      '<h3>By error code</h3>' +
      '<table><tr><th>Code</th><th>Cause</th><th>What the code means</th>' +
      '<th class="num">Held</th></tr>' + codeRows + '</table>' +
      '<h3>By the receiver\'s answer</h3>' +
      '<table><tr><th>Status</th><th class="num">Held</th>' +
      '<th class="num">Share</th></tr>' + statusRows + '</table>' +
      '<h3>By event type</h3>' +
      '<table><tr><th>Event</th><th>Type</th><th class="num">Held</th>' +
      '<th class="num">Share</th></tr>' + typeRows + '</table>' +

      '<h2>Streams</h2>' +
      kit.note('Every stream that holds a dead letter or is not ' +
      'delivering. <strong>Dead</strong>: nothing is pushed to it and one ' +
      'letter is pushed as a probe each ' +
      '<code>ssf.deadStreamTimeoutS</code>. <strong>Half-open</strong>: ' +
      'failing for that long without being dead, so the next failure kills ' +
      'it. <strong>Failing</strong>: younger than that. <em>Ever</em> is ' +
      'the stream\'s own count of every letter it was given, including the ' +
      'ones since deleted.') +
      kit.wideTable('Streams with dead letters',
                     '<table><tr><th>Stream</th>' +
      '<th>State</th><th>Last failure</th><th class="num">Held</th>' +
      '<th>Held, by cause</th><th class="num">Ever</th></tr>' +
      streamRows + '</table>') +

      '<h2 id="letters">The letters</h2>' +
      search +
      (narrowed.length
        ? '<p class="sub">Showing only ' + narrowed.join(' and ') + '.</p>'
        : '') +
      nav.head +
      kit.wideTable('Dead letters', '<table><tr><th>Dead-lettered</th>' +
      '<th>Stream</th><th>Event</th><th>Cause</th>' +
      '<th class="num">Status</th><th>Reason</th><th>SET</th></tr>' +
      letterRows + '</table>') +
      nav.foot +
      kit.note('No token is shown or returned: a SET is a signed ' +
      'statement about somebody. <em>Not signed</em> is a SET for a dead ' +
      'stream, kept as its claims because signing what nothing would ' +
      'receive is the cost dead streams exist to stop.') +

      '<h2>This process</h2>' +
      kit.warn('<strong>Everything in this section is process ' +
      kit.esc(String(proc.pid)) + '\'s alone</strong> (' +
      kit.esc(proc.role) + '). ' +
      'In a service with request workers the next refresh may be answered ' +
      'by another process with different numbers, and the push cap is not ' +
      'per realm: every realm\'s pushes from one process share it, so a ' +
      'burst in one realm can dead-letter another\'s with ' +
      '<code>STS-SSF-0092</code>.') +
      '<div class="tiles">' +
      kit.tile(String(pushes.active || 0) + ' / ' +
                (pushes.concurrency ? String(pushes.concurrency) : '∞'),
                'pushes in flight') +
      kit.tile(String(pushes.waiting || 0) + ' / ' +
                String(pushes.backlog || 0), 'pushes waiting') +
      kit.tile(since.sweeps, 'sweeps of this realm') +
      kit.tile(since.letters, 'dead-lettered here') +
      kit.tile(since.expired, 'expired') +
      kit.tile(since.trimmed, 'over the per-stream cap') +
      kit.tile(since.probes, 'probes') +
      '</div>' +
      '<h3>Recent sweeps</h3>' +
      kit.note('The last twenty sweeps of this realm by this process, ' +
      'newest first. <em>New</em> counts the letters this process added ' +
      'since its previous sweep; <em>held</em>, <em>expired</em>, <em>over ' +
      'cap</em> and <em>orphaned</em> (a letter whose stream is gone) are ' +
      'the shared store as this process found it.') +
      kit.wideTable('Recent sweeps', '<table><tr><th>When</th>' +
      '<th class="num">New</th><th class="num">Held</th>' +
      '<th class="num">Expired</th><th class="num">Over cap</th>' +
      '<th class="num">Orphaned</th><th class="num">Dead streams</th>' +
      '<th class="num">Probes</th></tr>' + sweepRows + '</table>') +

      '<h2>Settings</h2>' +
      kit.note('What decides what is dead-lettered and for how long. ' +
      'Changed on <a href="/admin/ssf">Protocols &rarr; Shared ' +
      'Signals</a>, with every other <code>ssf.*</code> setting.') +
      '<table><tr><th>Setting</th><th ' +
      'class="num">Value</th><th>Meaning</th></tr>' + settingRows +
      '</table>' +

      kit.note('<a href="/admin/ssf/dead-letters?format=json">this page ' +
      'as JSON</a> &middot; <a href="/admin-api/ssf/dead-letters">the same ' +
      'over the management API</a> &middot; <a href="/admin/ssf">the ' +
      'streams and their controls</a> &middot; <a ' +
      'href="/admin/error-codes">every error code</a> &middot; <a ' +
      'href="/admin/audit">the audit log</a>');

    return inner;
  }

  // The letters list's rows. Called once per page load over at most one page.
  /**
   * Draws the rows of the dead-letter list for one page of letters.
   *
   * @param json - the report, whose `letters` are drawn
   * @param causeById - each cause's description, keyed by its id
   * @param listView - the list's query, carried into each stream link
   * @returns the table rows as HTML
   */
  static deadLetterRows(json, causeById, listView) {
    const rows = json.letters.map(function (row) {
      const cause = causeById[row.cause] || { label: row.cause };
      const event = row.event;
      return '<tr>' +
        '<td class="sub">' + kit.esc(kit.whenText(Date.parse(row.deadAt))) +
        (row.ageS !== null
          ? '<div>' + kit.esc(kit.durationText(row.ageS * 1000)) +
            ' ago</div>' : '') +
        '</td>' +
        '<td class="who"><a href="' + kit.esc('/admin/ssf/dead-letters' +
          kit.queryWith(listView, { dlstream: row.stream_id,
            lettersPage: '' })) +
        '#find-dlq"><code>' + kit.esc(row.stream_id) + '</code></a>' +
        (row.streamKnown
          ? ''
          : '<div class="sub">no such stream here</div>') + '</td>' +
        '<td>' + (event
          ? kit.esc(event.name) + '<div class="sub"><code>' +
            kit.esc(event.types[0] || '') + '</code></div>' +
            (event.subject
              ? '<div class="sub">' + kit.esc(event.subject) + '</div>' : '')
          : '<span class="sub">unreadable</span>') + '</td><td>' +
        SsfDeadLettersPage.deadLetterSwatch(
          DEAD_LETTER_COLOURS[row.cause] || '#8a8a99') +
        ' ' + kit.esc(cause.label) +
        (row.errorCode
          ? '<div><a href="/admin/error-codes#' + kit.esc(row.errorCode) +
            '"><code class="ec">' + kit.esc(row.errorCode) +
            '</code></a></div>'
          : '') + '</td>' +
        '<td class="num">' + (row.status ? kit.esc(String(row.status))
          : '<span class="sub" title="' +
            kit.esc('No HTTP answer: the push was ' +
              'never made, or nothing answered it.') + '">&mdash;</span>') +
        '</td>' +
        '<td>' + kit.esc(row.reason) + '</td>' +
        '<td class="sub">' + (row.signed ? 'signed' : 'not signed') +
        '<div><code>' + kit.esc(row.jti) + '</code></div></td>' +
        '</tr>';
    }).join('');
    return rows;
  }

  // A window length for an axis label: `60m`, `12h`, `30d`.
  /**
   * Formats a window length for an axis label, as `60m`, `12h` or `30d`.
   *
   * @param seconds - the length in seconds
   * @returns the short label
   */
  static deadLetterSpan(seconds) {
    let out = Math.round(seconds / 60) + 'm';
    if (seconds >= 172800 && seconds % 86400 === 0) {
      out = (seconds / 86400) + 'd';
    } else if (seconds >= 7200) {
      out = Math.round(seconds / 3600) + 'h';
    }
    return out;
  }

  /**
   * Draws a 12px rounded square of one colour, the swatch beside a cause.
   *
   * @param colour - the fill colour
   * @returns the swatch as inline SVG markup
   */
  static deadLetterSwatch(colour) {
    return '<svg width="12" height="12" viewBox="0 0 12 12" ' +
      'aria-hidden="true"><rect x="0" y="0" width="12" height="12" rx="3" ' +
      'fill="' + kit.esc(colour) + '"/></svg>';
  }

  // The whole timeline: axes, gridlines, one column per bucket, and the text a
  // reader who cannot see the colours still gets.
  /**
   * Draws the whole dead-letter timeline: axes, gridlines, a column per
   * bucket, a title per column and an aria-label for a reader who cannot
   * see the colours.
   *
   * @param timeline - the buckets, peak, bucket length and window length
   * @param causes - the report's causes, in order
   * @returns the chart as HTML wrapping an SVG
   */
  static deadLetterTimeline(timeline, causes) {
    const W = 760;
    const H = 230;
    const left = 46;
    const right = 14;
    const top = 12;
    const bottom = 34;
    const plotW = W - left - right;
    const plotH = H - top - bottom;
    const baseline = top + plotH;
    const n = timeline.buckets.length;
    const band = plotW / n;
    const width = Math.max(2, Math.min(24, band - 2));
    const step = SsfDeadLettersPage.deadLetterAxisStep(timeline.peak);
    const ceiling = Math.max(step, Math.ceil(timeline.peak / step) * step);
    const perLetter = plotH / ceiling;

    const grid = [];
    for (let v = 0; v <= ceiling; v += step) {
      const y = baseline - v * perLetter;
      grid.push('<line x1="' + left + '" x2="' + (W - right) + '" y1="' +
        y.toFixed(1) + '" y2="' + y.toFixed(1) + '" stroke="' +
        (v === 0 ? '#c9c9d3' : '#ececf2') + '" stroke-width="1"/>' +
        '<text x="' + (left - 8) + '" y="' + (y + 4).toFixed(1) +
        '" text-anchor="end" font-size="11" fill="#666">' +
        kit.esc(v.toLocaleString('en-US')) + '</text>');
    }

    const ticks = [0, 0.25, 0.5, 0.75, 1].map(function (fraction) {
      const x = left + plotW * fraction;
      const ago = Math.round(timeline.windowS * (1 - fraction));
      const anchor = fraction === 0 ? 'start' : (fraction === 1 ? 'end'
                                                                 : 'middle');
      return '<text x="' + x.toFixed(1) + '" y="' + (baseline + 20) +
        '" text-anchor="' + anchor + '" font-size="11" fill="#666">' +
        kit.esc(ago ? SsfDeadLettersPage.deadLetterSpan(ago) +
          ' ago' : 'now') + '</text>';
    }).join('');

    const columns = timeline.buckets.map(function (bucket, i) {
      const x = left + i * band;
      const from = Date.parse(bucket.start);
      const until = from + timeline.bucketS * 1000;
      const what = causes.filter(function (cause) {
        return bucket.counts[cause.id] > 0;
      }).map(function (cause) {
        return cause.label + ' ' + bucket.counts[cause.id];
      }).join(', ');
      const title = kit.whenText(from) + ' to ' + kit.whenText(until) + ': ' +
        (bucket.total
          ? bucket.total + ' dead-lettered (' + what + ')'
          : 'nothing dead-lettered');
      return '<g><title>' + kit.esc(title) + '</title>' +
        '<rect x="' + x.toFixed(1) + '" y="' + top + '" width="' +
        band.toFixed(1) + '" height="' + plotH + '" fill="#fff" ' +
        'fill-opacity="0"/>' +
        (bucket.total
          ? SsfDeadLettersPage.deadLetterColumn(bucket, causes, { x: x +
            (band - width) / 2,
              width: width, baseline: baseline, perLetter: perLetter })
          : '') +
        '</g>';
    }).join('');

    const empty = timeline.peak
      ? ''
      : '<text x="' + (left + plotW / 2) + '" y="' + (top + plotH / 2) +
        '" text-anchor="middle" font-size="13" fill="#666">' +
        'Nothing held was dead-lettered in this window.</text>';

    const label = timeline.peak
      ? 'Dead letters held, by when they were dead-lettered, in ' +
        SsfDeadLettersPage.deadLetterSpan(timeline.bucketS) +
          ' columns over the last ' +
        SsfDeadLettersPage.deadLetterSpan(timeline.windowS) +
          '; the busiest column holds ' +
        timeline.peak + '. The same numbers are in the table below.'
      : 'No dead letter held was dead-lettered in the last ' +
        SsfDeadLettersPage.deadLetterSpan(timeline.windowS) + '.';
    return '<div class="chart"><svg xmlns="http://www.w3.org/2000/svg" ' +
      'viewBox="0 0 ' + W + ' ' + H + '" role="img" aria-label="' +
      kit.esc(label) +
      '">' + grid.join('') + columns + ticks + empty + '</svg></div>';
  }

  // A round step for the value axis: 1, 2 or 5 times a power of ten, never
  // below one letter, so the ticks read 0 / 5 / 10 rather than 0 / 3.25 / 6.5.
  /**
   * Chooses a round step for the dead-letter timeline's value axis: 1, 2 or
   * 5 times a power of ten, never below one.
   *
   * @param peak - the largest column count on the timeline
   * @returns the step between gridlines
   */
  static deadLetterAxisStep(peak) {
    const rough = Math.max(1, peak / 4);
    const power = Math.pow(10, Math.floor(Math.log10(rough)));
    const step = [1, 2, 5, 10].map(function (m) {
      return m * power;
    }).filter(function (candidate) {
      return candidate >= rough;
    })[0];
    return step;
  }

  // One stacked column's segments, bottom up in the report's cause order, with
  // a 2px gap of the card's white between touching segments and the top one
  // rounded. `geometry` is the column's x, width, baseline and pixels per
  // letter.
  /**
   * Draws one stacked column of the dead-letter timeline, a segment per
   * cause present, bottom up in the report's cause order, the top rounded.
   *
   * @param bucket - the time bucket, with its counts per cause id
   * @param causes - the report's causes, in order
   * @param geometry - the column's x, width, baseline and pixels per letter
   * @returns the column's segments as SVG markup
   */
  static deadLetterColumn(bucket, causes, geometry) {
    const present = causes.filter(function (cause) {
      return bucket.counts[cause.id] > 0;
    });
    let base = geometry.baseline;
    const parts = present.map(function (cause, index) {
      const full = bucket.counts[cause.id] * geometry.perLetter;
      const gap = index > 0 ? 2 : 0;
      const height = Math.max(1, full - gap);
      const bottom = base - gap;
      const top = bottom - height;
      base = base - full;
      const colour = DEAD_LETTER_COLOURS[cause.id] || '#8a8a99';
      const x = geometry.x;
      const w = geometry.width;
      if (index < present.length - 1) {
        return '<rect x="' + x.toFixed(1) + '" y="' + top.toFixed(1) +
          '" width="' + w.toFixed(1) + '" height="' + height.toFixed(1) +
          '" fill="' + colour + '"/>';
      }
      const r = Math.min(4, height, w / 2);
      return '<path d="M' + x.toFixed(1) + ' ' + bottom.toFixed(1) +
        'V' + (top + r).toFixed(1) +
        'Q' + x.toFixed(1) + ' ' + top.toFixed(1) + ' ' +
        (x + r).toFixed(1) + ' ' + top.toFixed(1) +
        'H' + (x + w - r).toFixed(1) +
        'Q' + (x + w).toFixed(1) + ' ' + top.toFixed(1) + ' ' +
        (x + w).toFixed(1) + ' ' + (top + r).toFixed(1) +
        'V' + bottom.toFixed(1) + 'Z" fill="' + colour + '"/>';
    });
    return parts.join('');
  }
}

export = SsfDeadLettersPage;
