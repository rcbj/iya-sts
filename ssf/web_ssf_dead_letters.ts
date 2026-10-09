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
    const t = ctx.t;
    if (!json.installed) {
      const missing = '<h1>' + t.html('consoleSsfDeadLetters.heading') +
        '</h1><div class="err">' +
        t.html('consoleSsfDeadLetters.notLoaded') + '</div>';
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
      kit.tile(totals.held,
               t.text('consoleSsfDeadLetters.tile.held')) +
      kit.tile(totals.streamsHolding,
               t.text('consoleSsfDeadLetters.tile.streamsHolding')) +
      kit.tile(totals.deadStreams,
               t.text('consoleSsfDeadLetters.tile.deadStreams')) +
      kit.tile(totals.halfOpenStreams,
               t.text('consoleSsfDeadLetters.tile.halfOpen')) +
      kit.tile(totals.failingStreams,
               t.text('consoleSsfDeadLetters.tile.failing')) +
      kit.tile(totals.unsigned,
               t.text('consoleSsfDeadLetters.tile.unsigned')) +
      kit.tile(totals.newestAgeS === null ? '—'
        : kit.durationText(totals.newestAgeS * 1000),
               t.text('consoleSsfDeadLetters.tile.newest')) +
      kit.tile(totals.oldestAgeS === null ? '—'
        : kit.durationText(totals.oldestAgeS * 1000),
               t.text('consoleSsfDeadLetters.tile.oldest')) +
      '</div>';

    const off = (!json.enabled
      ? kit.warn(t.html('consoleSsfDeadLetters.off'))
      : '') +
      (json.enabled && !json.pushDelivery
        ? kit.warn(t.html('consoleSsfDeadLetters.pushOff'))
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
      ? '<details><summary>' +
        t.html('consoleSsfDeadLetters.when.asTable',
               { busy: busy.length, all: timeline.buckets.length }) +
        '</summary>' +
        kit.wideTable(t.text('consoleSsfDeadLetters.when.tableLabel'),
                      '<table><tr><th>' +
                      t.html('consoleSsfDeadLetters.th.from') + '</th>' +
        json.causes.map(function (cause) {
          return '<th class="num">' + kit.esc(cause.label) + '</th>';
        }).join('') + '<th class="num">' +
        t.html('consoleSsfDeadLetters.th.all') + '</th></tr>' +
        busy.map(function (bucket) {
          return '<tr><td class="sub">' +
            kit.esc(kit.whenText(Date.parse(bucket.start))) + '</td>' +
            json.causes.map(function (cause) {
              return '<td class="num">' + bucket.counts[cause.id] + '</td>';
            }).join('') + '<td class="num">' + bucket.total + '</td></tr>';
        }).join('') + '</table>') + '</details>'
      : '';
    const older = timeline.olderThanWindow
      ? kit.note(t.html('consoleSsfDeadLetters.when.older',
                        { n: String(timeline.olderThanWindow) }))
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
          : '<span class="sub">' +
            t.html('consoleSsfDeadLetters.why.noneRecorded') + '</span>') +
          '</td>' +
        '<td>' + kit.esc(cause.label) + '</td>' +
        '<td>' + kit.esc(row.summary) + '</td>' +
        '<td class="num">' + (row.errorCode
          ? '<a href="' + lettersOf({ dlq: row.errorCode }) + '">' +
            row.count + '</a>'
          : String(row.count)) + '</td></tr>';
    }).join('') || '<tr><td colspan="4">' +
      t.html('consoleSsfDeadLetters.nothingHeld') + '</td></tr>';
    const statusRows = json.byStatus.map(function (row) {
      return '<tr><td>' + (row.status
          ? 'HTTP ' + kit.esc(String(row.status))
          : '<span class="sub">' +
            t.html('consoleSsfDeadLetters.why.noAnswer') + '</span>') +
          '</td>' +
        '<td class="num">' + row.count + '</td>' +
        '<td class="num">' + share(row.count) + '</td></tr>';
    }).join('') || '<tr><td colspan="3">' +
      t.html('consoleSsfDeadLetters.nothingHeld') + '</td></tr>';
    const typeRows = json.byEventType.map(function (row) {
      return '<tr><td>' + kit.esc(row.name ||
        t.text('consoleSsfDeadLetters.why.unreadable')) + '</td>' +
        '<td class="sub"><code>' + kit.esc(row.type || '') + '</code></td>' +
        '<td class="num">' + (row.name
          ? '<a href="' + lettersOf({ dlq: row.type || row.name }) + '">' +
            row.count + '</a>'
          : String(row.count)) + '</td>' +
        '<td class="num">' + share(row.count) + '</td></tr>';
    }).join('') || '<tr><td colspan="4">' +
      t.html('consoleSsfDeadLetters.nothingHeld') + '</td></tr>';

    // WHICH STREAMS.
    const stateText = {
      dead: '<span class="state-revoked">' +
        t.html('consoleSsfDeadLetters.state.dead') + '</span>',
      'half-open': '<span class="state-expired">' +
        t.html('consoleSsfDeadLetters.state.halfOpen') + '</span>',
      failing: '<span class="state-expired">' +
        t.html('consoleSsfDeadLetters.state.failing') + '</span>',
      healthy: '<span class="state-valid">' +
        t.html('consoleSsfDeadLetters.state.healthy') + '</span>',
      poll: '<span class="sub">' +
        t.html('consoleSsfDeadLetters.state.poll') + '</span>',
      unknown: '<span class="sub">' +
        t.html('consoleSsfDeadLetters.state.unknown') + '</span>'
    };
    const streamRows = json.streams.map(function (row) {
      const when = row.state === 'dead'
        ? t.text('consoleSsfDeadLetters.state.deadSince',
                 { at: kit.whenText(Date.parse(row.deadSince)) }) +
          (row.nextProbeAt
            ? t.text('consoleSsfDeadLetters.state.nextProbe',
                     { at: kit.whenText(Date.parse(row.nextProbeAt)) }) :
              '')
        : (row.failingSince
          ? t.text('consoleSsfDeadLetters.state.failingSince',
                   { at: kit.whenText(Date.parse(row.failingSince)) }) :
            '');
      return '<tr><td class="who">' + (row.state === 'unknown'
          ? '<code>' + kit.esc(row.stream_id) + '</code>'
          : '<a href="/admin/ssf#stream-' + kit.esc(row.stream_id) +
            '" title="' +
            kit.esc(t.text('consoleSsfDeadLetters.streams.cardTip')) +
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
      '<tr><td colspan="6">' +
      t.html('consoleSsfDeadLetters.streams.none') + '</td></tr>';

    // THE LETTERS.
    const search = kit.sectionSearchForm({
      path: '/admin/ssf/dead-letters', param: 'dlq', pageParam: 'lettersPage',
      query: ctx.query, label: t.text('consoleSsfDeadLetters.find.label'),
      placeholder: t.text('consoleSsfDeadLetters.find.placeholder'),
      what: t.html('consoleSsfDeadLetters.find.what') }, t);
    const narrowed = [];
    if (json.filter.stream) {
      narrowed.push(t.html('consoleSsfDeadLetters.narrow.stream',
                           { stream: json.filter.stream }) + ' ' +
        '(<a href="' + lettersOf({ dlstream: '' }) + '">' +
        t.html('consoleSsfDeadLetters.narrow.anyStream') + '</a>)');
    }
    if (json.filter.cause) {
      narrowed.push(t.html('consoleSsfDeadLetters.narrow.cause', {
        cause: (causeById[json.filter.cause] ||
                { label: json.filter.cause }).label }) + ' (<a href="' +
        lettersOf({ dlcause: '' }) + '">' +
        t.html('consoleSsfDeadLetters.narrow.anyCause') + '</a>)');
    }
    const nav = kit.pageNavPair('/admin/ssf/dead-letters',
                                 kit.pageParamsOf(ctx.query),
      Object.assign({ param: 'lettersPage',
                      noun: t.text('consoleSsfDeadLetters.letters.noun') },
                    json.paging.letters), t);
    const letterRows = SsfDeadLettersPage.deadLetterRows(json, causeById,
      listView, t) ||
      '<tr><td colspan="7">' + (json.matched === 0 && totals.held
        ? t.html('consoleSsfDeadLetters.letters.noMatch')
        : t.html('consoleSsfDeadLetters.letters.none')) + '</td></tr>';

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
    }).join('') || '<tr><td colspan="8">' +
      t.html('consoleSsfDeadLetters.process.noSweeps') + '</td></tr>';
    const since = proc.sinceStart;

    const s = json.settings;
    const settingRows = [
      ['ssf.deadLetterRetentionS', s.retentionS,
        t.text('consoleSsfDeadLetters.setting.retention')],
      ['ssf.deadLetterMaxPerStream', s.maxPerStream,
       t.text('consoleSsfDeadLetters.setting.maxPerStream')],
      ['ssf.deadStreamTimeoutS', s.deadStreamTimeoutS,
       t.text('consoleSsfDeadLetters.setting.deadStreamTimeout')],
      ['ssf.deadLetterSweepS', s.sweepS,
        t.text('consoleSsfDeadLetters.setting.sweep')],
      ['ssf.pushConcurrency', s.pushConcurrency,
       t.text('consoleSsfDeadLetters.setting.pushConcurrency')],
      ['ssf.pushBacklog', s.pushBacklog,
       t.text('consoleSsfDeadLetters.setting.pushBacklog')],
      ['ssf.pushRetries', s.pushRetries,
        t.text('consoleSsfDeadLetters.setting.pushRetries')]
    ].map(function (row) {
      return '<tr><td><code>' + kit.esc(row[0]) + '</code></td>' +
        '<td class="num">' + kit.esc(String(row[1])) + '</td>' +
        '<td>' + kit.esc(row[2]) + '</td></tr>';
    }).join('');

    const inner = '<h1>' + t.html('consoleSsfDeadLetters.heading') +
      '</h1><p>' +
      t.html('consoleSsfDeadLetters.intro', { realm: json.realm }) + '</p>' +
      off +
      tiles +
      // The link is markup a message cannot carry (#539).
      kit.note(t.html('consoleSsfDeadLetters.reports.before') +
      '<a href="/admin/ssf">' + t.html('consoleSsfDeadLetters.link.ssf') +
      '</a>' + t.html('consoleSsfDeadLetters.reports.after',
        { when: kit.whenText(Date.parse(json.generatedAt)) })) +

      '<h2>' + t.html('consoleSsfDeadLetters.when.heading') + '</h2>' +
      kit.note(t.html('consoleSsfDeadLetters.when.note', {
        bucket: SsfDeadLettersPage.deadLetterSpan(timeline.bucketS),
        window: SsfDeadLettersPage.deadLetterSpan(timeline.windowS) })) +
      legend +
      SsfDeadLettersPage.deadLetterTimeline(timeline, json.causes, t) +
      timelineTable +
      older +

      '<h2>' + t.html('consoleSsfDeadLetters.why.heading') + '</h2>' +
      kit.note(t.html('consoleSsfDeadLetters.why.note')) +
      '<table><tr><th>' + t.html('consoleSsfDeadLetters.th.cause') +
      '</th><th>' + t.html('consoleSsfDeadLetters.th.meaning') + '</th>' +
      '<th class="num">' + t.html('consoleSsfDeadLetters.th.held') +
      '</th><th class="num">' + t.html('consoleSsfDeadLetters.th.share') +
      '</th></tr>' +
      causeRows + '</table>' +
      '<h3>' + t.html('consoleSsfDeadLetters.why.byCode') + '</h3>' +
      '<table><tr><th>' + t.html('consoleSsfDeadLetters.th.code') +
      '</th><th>' + t.html('consoleSsfDeadLetters.th.cause') + '</th><th>' +
      t.html('consoleSsfDeadLetters.th.codeMeaning') + '</th>' +
      '<th class="num">' + t.html('consoleSsfDeadLetters.th.held') +
      '</th></tr>' + codeRows + '</table>' +
      '<h3>' + t.html('consoleSsfDeadLetters.why.byAnswer') + '</h3>' +
      '<table><tr><th>' + t.html('consoleSsfDeadLetters.th.status') +
      '</th><th class="num">' + t.html('consoleSsfDeadLetters.th.held') +
      '</th>' +
      '<th class="num">' + t.html('consoleSsfDeadLetters.th.share') +
      '</th></tr>' + statusRows + '</table>' +
      '<h3>' + t.html('consoleSsfDeadLetters.why.byType') + '</h3>' +
      '<table><tr><th>' + t.html('consoleSsfDeadLetters.th.event') +
      '</th><th>' + t.html('consoleSsfDeadLetters.th.type') +
      '</th><th class="num">' + t.html('consoleSsfDeadLetters.th.held') +
      '</th>' +
      '<th class="num">' + t.html('consoleSsfDeadLetters.th.share') +
      '</th></tr>' + typeRows + '</table>' +

      '<h2>' + t.html('consoleSsfDeadLetters.streams.heading') + '</h2>' +
      kit.note(t.html('consoleSsfDeadLetters.streams.note')) +
      kit.wideTable(t.text('consoleSsfDeadLetters.streams.tableLabel'),
                     '<table><tr><th>' +
      t.html('consoleSsfDeadLetters.th.stream') + '</th>' +
      '<th>' + t.html('consoleSsfDeadLetters.th.state') + '</th><th>' +
      t.html('consoleSsfDeadLetters.th.lastFailure') +
      '</th><th class="num">' + t.html('consoleSsfDeadLetters.th.held') +
      '</th>' +
      '<th>' + t.html('consoleSsfDeadLetters.th.heldByCause') +
      '</th><th class="num">' + t.html('consoleSsfDeadLetters.th.ever') +
      '</th></tr>' +
      streamRows + '</table>') +

      '<h2 id="letters">' + t.html('consoleSsfDeadLetters.letters.heading') +
      '</h2>' +
      search +
      (narrowed.length
        ? '<p class="sub">' + t.html('consoleSsfDeadLetters.narrow.before') +
          narrowed.join(t.html('consoleSsfDeadLetters.narrow.and')) +
          t.html('consoleSsfDeadLetters.narrow.after') + '</p>'
        : '') +
      nav.head +
      kit.wideTable(t.text('consoleSsfDeadLetters.letters.tableLabel'),
                    '<table><tr><th>' +
      t.html('consoleSsfDeadLetters.th.deadLettered') + '</th>' +
      '<th>' + t.html('consoleSsfDeadLetters.th.stream') + '</th><th>' +
      t.html('consoleSsfDeadLetters.th.event') + '</th><th>' +
      t.html('consoleSsfDeadLetters.th.cause') + '</th>' +
      '<th class="num">' + t.html('consoleSsfDeadLetters.th.status') +
      '</th><th>' + t.html('consoleSsfDeadLetters.th.reason') +
      '</th><th>SET</th></tr>' +
      letterRows + '</table>') +
      nav.foot +
      kit.note(t.html('consoleSsfDeadLetters.letters.note')) +

      '<h2>' + t.html('consoleSsfDeadLetters.process.heading') + '</h2>' +
      kit.warn(t.html('consoleSsfDeadLetters.process.warn',
                      { pid: String(proc.pid), role: proc.role })) +
      '<div class="tiles">' +
      kit.tile(String(pushes.active || 0) + ' / ' +
                (pushes.concurrency ? String(pushes.concurrency) : '∞'),
                t.text('consoleSsfDeadLetters.tile.inFlight')) +
      kit.tile(String(pushes.waiting || 0) + ' / ' +
                String(pushes.backlog || 0),
               t.text('consoleSsfDeadLetters.tile.pushesWaiting')) +
      kit.tile(since.sweeps, t.text('consoleSsfDeadLetters.tile.sweeps')) +
      kit.tile(since.letters,
               t.text('consoleSsfDeadLetters.tile.deadLetteredHere')) +
      kit.tile(since.expired, t.text('consoleSsfDeadLetters.tile.expired')) +
      kit.tile(since.trimmed, t.text('consoleSsfDeadLetters.tile.overCap')) +
      kit.tile(since.probes, t.text('consoleSsfDeadLetters.tile.probes')) +
      '</div>' +
      '<h3>' + t.html('consoleSsfDeadLetters.sweeps.heading') + '</h3>' +
      kit.note(t.html('consoleSsfDeadLetters.sweeps.note')) +
      kit.wideTable(t.text('consoleSsfDeadLetters.sweeps.heading'),
                    '<table><tr><th>' +
      t.html('consoleSsfDeadLetters.th.when') + '</th>' +
      '<th class="num">' + t.html('consoleSsfDeadLetters.th.new') +
      '</th><th class="num">' + t.html('consoleSsfDeadLetters.th.held') +
      '</th>' +
      '<th class="num">' + t.html('consoleSsfDeadLetters.th.expired') +
      '</th><th class="num">' + t.html('consoleSsfDeadLetters.th.overCap') +
      '</th>' +
      '<th class="num">' + t.html('consoleSsfDeadLetters.th.orphaned') +
      '</th><th class="num">' +
      t.html('consoleSsfDeadLetters.th.deadStreams') + '</th>' +
      '<th class="num">' + t.html('consoleSsfDeadLetters.th.probes') +
      '</th></tr>' + sweepRows + '</table>') +

      '<h2>' + t.html('consoleSsfDeadLetters.settings.heading') + '</h2>' +
      kit.note(t.html('consoleSsfDeadLetters.settings.before') +
      '<a href="/admin/ssf">' + t.html('consoleSsfDeadLetters.link.ssf') +
      '</a>' + t.html('consoleSsfDeadLetters.settings.after')) +
      '<table><tr><th>' + t.html('consoleSsfDeadLetters.th.setting') +
      '</th><th class="num">' + t.html('consoleSsfDeadLetters.th.value') +
      '</th><th>' + t.html('consoleSsfDeadLetters.th.settingMeaning') +
      '</th></tr>' + settingRows +
      '</table>' +

      kit.note('<a href="/admin/ssf/dead-letters?format=json">' +
      t.html('consoleSsfDeadLetters.foot.json') + '</a> &middot; ' +
      '<a href="/admin-api/ssf/dead-letters">' +
      t.html('consoleSsfDeadLetters.foot.api') + '</a> &middot; ' +
      '<a href="/admin/ssf">' + t.html('consoleSsfDeadLetters.foot.ssf') +
      '</a> &middot; <a ' +
      'href="/admin/error-codes">' +
      t.html('consoleSsfDeadLetters.foot.codes') + '</a> &middot; <a ' +
      'href="/admin/audit">' + t.html('consoleSsfDeadLetters.foot.audit') +
      '</a>');

    return inner;
  }

  // The letters list's rows. Called once per page load over at most one page.
  /**
   * Draws the rows of the dead-letter list for one page of letters.
   *
   * @param json - the report, whose `letters` are drawn
   * @param causeById - each cause's description, keyed by its id
   * @param listView - the list's query, carried into each stream link
   * @param t - the page's translator (#539)
   * @returns the table rows as HTML
   */
  static deadLetterRows(json, causeById, listView, t) {
    const rows = json.letters.map(function (row) {
      const cause = causeById[row.cause] || { label: row.cause };
      const event = row.event;
      return '<tr>' +
        '<td class="sub">' + kit.esc(kit.whenText(Date.parse(row.deadAt))) +
        (row.ageS !== null
          ? '<div>' + t.html('consoleSsfDeadLetters.row.ago',
              { span: kit.durationText(row.ageS * 1000) }) +
            '</div>' : '') +
        '</td>' +
        '<td class="who"><a href="' + kit.esc('/admin/ssf/dead-letters' +
          kit.queryWith(listView, { dlstream: row.stream_id,
            lettersPage: '' })) +
        '#find-dlq"><code>' + kit.esc(row.stream_id) + '</code></a>' +
        (row.streamKnown
          ? ''
          : '<div class="sub">' +
            t.html('consoleSsfDeadLetters.row.noStream') + '</div>') +
        '</td>' +
        '<td>' + (event
          ? kit.esc(event.name) + '<div class="sub"><code>' +
            kit.esc(event.types[0] || '') + '</code></div>' +
            (event.subject
              ? '<div class="sub">' + kit.esc(event.subject) + '</div>' : '')
          : '<span class="sub">' +
            t.html('consoleSsfDeadLetters.row.unreadable') + '</span>') +
        '</td><td>' +
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
            kit.esc(t.text('consoleSsfDeadLetters.row.noAnswerTip')) +
            '">&mdash;</span>') +
        '</td>' +
        '<td>' + kit.esc(row.reason) + '</td>' +
        '<td class="sub">' + (row.signed
          ? t.html('consoleSsfDeadLetters.row.signed')
          : t.html('consoleSsfDeadLetters.row.notSigned')) +
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
   * @param t - the page's translator (#539)
   * @returns the chart as HTML wrapping an SVG
   */
  static deadLetterTimeline(timeline, causes, t) {
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
        kit.esc(ago ? t.text('consoleSsfDeadLetters.chart.ago',
          { span: SsfDeadLettersPage.deadLetterSpan(ago) })
          : t.text('consoleSsfDeadLetters.chart.now')) + '</text>';
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
      const title = bucket.total
        ? t.text('consoleSsfDeadLetters.chart.column',
                 { from: kit.whenText(from), until: kit.whenText(until),
                   n: bucket.total, what: what })
        : t.text('consoleSsfDeadLetters.chart.columnEmpty',
                 { from: kit.whenText(from), until: kit.whenText(until) });
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
        t.html('consoleSsfDeadLetters.chart.empty') + '</text>';

    const label = timeline.peak
      ? t.text('consoleSsfDeadLetters.chart.label', {
        bucket: SsfDeadLettersPage.deadLetterSpan(timeline.bucketS),
        window: SsfDeadLettersPage.deadLetterSpan(timeline.windowS),
        peak: timeline.peak })
      : t.text('consoleSsfDeadLetters.chart.labelEmpty', {
        window: SsfDeadLettersPage.deadLetterSpan(timeline.windowS) });
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
