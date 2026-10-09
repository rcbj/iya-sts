// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_metrics.ts
//
// ---------------------------------------------------------------------------
// MONITORING → METRICS, DRAWN FROM ITS VIEW ALONE (#446, 2026-10-05).
//
// Draws Metrics from the answer of `GET /admin-api/metrics`: endpoint calls,
// tokens and artifacts by kind, and sessions counted both ways.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// It was drawn inside the route of `/admin/metrics` in `admin-ui/admin.ts`,
// which still draws the page until the console's cutover by calling this with
// its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');

type Json = any;


// How many subjects the metrics page names in one "Who" cell before it says how
// many more there are. A separate cap from MAX_ROWS because it bounds a cell
// rather than a list: the ceiling that matters here is the width of one row,
// and the full list is on /admin/users and in `?format=json` either way.
const MAX_WHO = 12;
/**
 * Draws Metrics from the answer of `GET /admin-api/metrics`: endpoint calls,
 * tokens and artifacts by kind, and sessions counted both ways.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class MetricsPage {
  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static body(ctx, json) {
    // THE WORDS ARE THE READER'S LANGUAGE (#539): `consoleMetrics.*`, whose
    // English is exactly what was drawn before. A link is markup no message
    // can carry, so a note with one is two messages around the `<a>`.
    const t = ctx.t;
    // The snapshot's keys are the top level of that object; see the note on
    // it.
    const snap = json;
    const signOn = json.signOnSessions.rows;
    const liveSignOn = signOn.filter(function (s) { return !s.expired; });

    // The Who column holds SUBJECTS, and one family's are not names in any
    // readable sense: an OID4VCI credential's subject is a `did:jwk:` — a
    // couple of hundred characters of base64url with not one place in it a
    // browser will break a line. Emitted as plain text that made the cell's
    // minimum width wider than the card, so the table overflowed and took the
    // OAuth 2.0 / OIDC row's column with it, even though a subject was rarely
    // the long one (a `urn:uuid:` subject, since 2026-09-14, is 45 characters
    // and is shortened like the rest). So each subject is drawn the way the
    // tokens page draws a jti — shortened, with the whole string in the title
    // so it is still recoverable by hovering — and inside <code>, which the
    // stylesheet already lets break mid-string.
    const sessionFamilyRows = snap.sessions.families.map(function (row) {
      const shown = row.who.slice(0, MAX_WHO).map(function (subject) {
        return kit.shortened(subject, 28);
      }).join(' ');
      return '<tr><td>' + kit.esc(row.family) + '</td><td class="num">' +
        row.subjects + '</td><td ' +
        'class="who">' + shown +
        (row.who.length > MAX_WHO ?
         ' ' + t.html('consoleMetrics.who.more',
                      { n: row.who.length - MAX_WHO }) : '') +
        '</td></tr>';
    }).join('');

    const signOnRows = signOn.slice(0, kit.MAX_ROWS).map(function (s) {
      return '<tr><td>' + kit.esc(s.username) + '</td>' +
        '<td class="' + (s.expired ? 'state-expired' : 'state-valid') + '">' +
          (s.expired ? t.html('consoleMetrics.state.expired')
                     : t.html('consoleMetrics.state.active')) + '</td>' +
        '<td>' + kit.esc(s.amr || '—') + '</td><td>' +
        kit.esc(s.acr || '—') + '</td>' +
        '<td>' + kit.esc(kit.whenText(s.startedAt)) + '</td>' +
        '<td>' + kit.esc(kit.whenText(s.authTime)) +
        (s.authentications > 1 ? ' (' + s.authentications + ')' : '') +
        '</td>' +
        '<td>' + kit.esc(kit.whenText(s.expires)) + '</td><td>' +
        (s.wsfedRealms.length ? kit.esc(s.wsfedRealms.join(', ')) : '—') +
        '</td></tr>';
    }).join('');

    const inner = '<div class="tiles">' +
        kit.tile(snap.calls.total, t.text('consoleMetrics.tile.calls')) +
        kit.tile(snap.calls.paths, t.text('consoleMetrics.tile.routes')) +
        kit.tile(snap.tokens.held,
                 t.text('consoleMetrics.tile.tokensIssued')) +
        kit.tile(snap.tokens.revoked,
                 t.text('consoleMetrics.tile.tokensRevoked')) +
        kit.tile(snap.artifacts.held,
                 t.text('consoleMetrics.tile.artifacts')) +
        kit.tile(liveSignOn.length, t.text('consoleMetrics.tile.sessions')) +
        kit.tile(snap.sessions.distinctSubjects,
                 t.text('consoleMetrics.tile.subjects')) +
        kit.tile(kit.durationText(snap.uptimeMs),
                 t.text('consoleMetrics.tile.uptime')) +
      '</div>' +
      kit.note(t.html('consoleMetrics.since',
                      { when: kit.whenText(snap.startedAt) })) +

      '<h2>' + t.html('consoleMetrics.calls.heading') + '</h2>' +
      kit.note(t.html('consoleMetrics.calls.noteA') + ' ' +
      '<a href="/admin/sts-metadata">/admin/sts-metadata</a> ' +
      t.html('consoleMetrics.calls.noteB')) +
      MetricsPage.callTable(snap, t) +

      '<h2>' + t.html('consoleMetrics.tokens.heading') + '</h2>' +
      kit.note(t.html('consoleMetrics.tokens.noteA') + ' ' +
      '<a href="/admin/tokens">' + t.html('consoleMetrics.link.tokensPage') +
      '</a> ' + t.html('consoleMetrics.tokens.noteB')) +
      MetricsPage.tokenKindTable(snap, t) +
      (snap.tokens.forgotten > 0
        ? kit.note(t.html('consoleMetrics.tokens.forgotten',
                          { n: snap.tokens.forgotten,
                            cap: snap.tokens.cap }))
        : '') +

      '<h2>' + t.html('consoleMetrics.artifacts.heading') + '</h2>' +
      kit.note(t.html('consoleMetrics.artifacts.noteA') + ' ' +
      '<a href="/admin/tokens">' + t.html('consoleMetrics.link.tokensPageLc') +
      '</a>' + t.html('consoleMetrics.artifacts.noteB')) +
      MetricsPage.artifactKindTable(snap, t) +
      (snap.artifacts.forgotten > 0
        ? kit.note(t.html('consoleMetrics.artifacts.forgotten',
                          { n: snap.artifacts.forgotten,
                            cap: snap.artifacts.cap }))
        : '') +

      '<h2>' + t.html('consoleMetrics.sessions.heading') + '</h2>' +
      kit.note(t.html('consoleMetrics.sessions.noteA') + ' ' +
      '<a href="/admin/users">' + t.html('consoleMetrics.link.usersPage') +
      '</a> ' + t.html('consoleMetrics.sessions.noteB')) +
      '<h3>' + t.html('consoleMetrics.signOn.heading',
                      { active: liveSignOn.length, held: signOn.length }) +
      '</h3><table><tr><th>' + t.html('consoleMetrics.th.user') +
      '</th><th>' + t.html('consoleMetrics.th.state') +
      '</th><th>amr</th><th>acr' +
      '</th><th>' + t.html('consoleMetrics.th.signedIn') + '</th><th>' +
      t.html('consoleMetrics.th.lastAuthenticated') + '</th>' +
      '<th>' + t.html('consoleMetrics.th.expires') + '</th><th>' +
      t.html('consoleMetrics.th.wsfedRps') + '</th></tr>' +
      (signOnRows || '<tr><td colspan="8">' +
                     t.html('consoleMetrics.signOn.none') + '</td></tr>') +
      '</table>' +
      kit.note(t.html('consoleMetrics.signOn.expiredNote')) +
      '<h3>' + t.html('consoleMetrics.derived.heading',
                      { n: snap.sessions.distinctSubjects }) +
      '</h3><table><tr><th>' + t.html('consoleMetrics.th.family') +
      '</th><th class="num">' + t.html('consoleMetrics.th.subjects') +
      '</th><th>' + t.html('consoleMetrics.th.who') + '</th></tr>' +
      (sessionFamilyRows ||
       '<tr><td colspan="3">' + t.html('consoleMetrics.derived.none') +
       '</td></tr>') +
      '</table>' +
      kit.note(t.html('consoleMetrics.derived.tgtNote'));

    return inner;
  }

  /**
   * Draws the metrics page's table of calls per route.
   *
   * At most MAX_ROWS routes are drawn, busiest first; notes say how many
   * were left out and how many unmatched paths were collapsed.
   *
   * @param snap - a snapshot from stats.snapshot()
   * @param t - the page's translator (#539)
   * @returns the table and its notes as HTML
   */
  static callTable(snap, t) {
    const rows = snap.calls.rows.slice(0, kit.MAX_ROWS);
    const body = rows.map(function (row) {
      return '<tr><td><code>' + kit.esc(row.method) + '</code></td>' +
        '<td><code>' + kit.esc(row.path) + '</code>' +
        (row.matched ? '' : ' <span class="state-expired">' +
         t.html('consoleMetrics.calls.noRoute') + '</span>') +
        '</td><td ' +
        'class="num">' + row.count + '</td>' +
        '<td class="num">' + (row.statuses['2xx'] || 0) + '</td>' +
        '<td class="num">' + (row.statuses['3xx'] || 0) + '</td>' +
        '<td class="num">' + (row.statuses['4xx'] || 0) + '</td>' +
        '<td class="num">' + (row.statuses['5xx'] || 0) + '</td>' +
        '<td class="num">' + Math.round(row.totalMs / Math.max(row.count, 1)) +
        '</td><td ' +
        'class="num">' + row.maxMs + '</td>' +
        '<td>' + kit.esc(kit.whenText(row.lastAt)) + '</td></tr>';
    }).join('');
    const hidden = snap.calls.rows.length - rows.length;
    // The collapsed row's name is the registry's own key, so it stays in
    // code between two messages rather than being translated.
    return '<table><tr><th>' + t.html('consoleMetrics.th.method') +
      '</th><th>' + t.html('consoleMetrics.th.route') + '</th><th ' +
      'class="num">' + t.html('consoleMetrics.th.calls') +
      '</th><th class="num">2xx</th><th ' +
      'class="num">3xx</th><th class="num">4xx</th><th ' +
      'class="num">5xx</th><th class="num">' +
      t.html('consoleMetrics.th.avgMs') + '</th><th class="num">' +
      t.html('consoleMetrics.th.maxMs') + '</th><th>' +
      t.html('consoleMetrics.th.last') + '</th></tr>' +
      (body ||
       '<tr><td colspan="10">' + t.html('consoleMetrics.calls.none') +
       '</td></tr>') +
      '</table>' +
      (hidden > 0 ? kit.note(t.html('consoleMetrics.calls.hidden',
                                    { n: hidden, max: kit.MAX_ROWS }))
                  : '') +
      (snap.calls.pathsCollapsed > 0
        ? kit.note(t.html('consoleMetrics.calls.collapsedA',
                          { n: snap.calls.pathsCollapsed }) + ' ' +
          '<code>' + kit.esc('(other unmatched paths)') + '</code> ' +
          t.html('consoleMetrics.calls.collapsedB'))
        : '');
  }

  /**
   * Draws the metrics page's table of tokens by kind and state.
   *
   * @param snap - a snapshot from stats.snapshot()
   * @param t - the page's translator (#539)
   * @returns the table as HTML
   */
  static tokenKindTable(snap, t) {
    const body = snap.tokens.byKind.map(function (row) {
      return '<tr><td>' + kit.esc(row.kind) + '</td>' +
        '<td class="num">' + row.issued + '</td>' +
        '<td class="num state-valid">' + row.valid + '</td>' +
        '<td class="num state-expired">' + row.expired + '</td>' +
        '<td class="num state-revoked">' + row.revoked + '</td>' +
        '<td class="num">' + row.notYetValid + '</td>' +
        '<td class="num">' + row.noExpiry + '</td>' +
        '<td class="num">' + row.bound + '</td></tr>';
    }).join('');
    return '<table><tr><th>' + t.html('consoleMetrics.th.token') +
      '</th><th class="num">' + t.html('consoleMetrics.th.issued') +
      '</th><th class="num">' + t.html('consoleMetrics.th.valid') +
      '</th><th class="num">' + t.html('consoleMetrics.th.expired') +
      '</th><th class="num">' + t.html('consoleMetrics.th.revoked') +
      '</th><th class="num">' + t.html('consoleMetrics.th.notYetValid') +
      '</th><th class="num">' + t.html('consoleMetrics.th.noExpiry') +
      '</th><th class="num">' + t.html('consoleMetrics.th.dpopBound') +
      '</th></tr>' +
      (body || '<tr><td colspan="8">' +
               t.html('consoleMetrics.tokens.none') + '</td></tr>') +
      '</table>';
  }

  /**
   * Draws the metrics page's table of assertions, tickets and SVIDs.
   *
   * @param snap - a snapshot from stats.snapshot()
   * @param t - the page's translator (#539)
   * @returns the table as HTML
   */
  static artifactKindTable(snap, t) {
    const body = snap.artifacts.byKind.map(function (row) {
      return '<tr><td>' + kit.esc(row.kind) + '</td>' +
        '<td class="num">' + row.issued + '</td>' +
        '<td class="num state-valid">' + row.valid + '</td>' +
        '<td class="num state-expired">' + row.expired + '</td>' +
        '<td class="num">' + row.noExpiry + '</td></tr>';
    }).join('');
    return '<table><tr><th>' + t.html('consoleMetrics.th.artifact') +
      '</th><th class="num">' + t.html('consoleMetrics.th.issued') +
      '</th><th class="num">' + t.html('consoleMetrics.th.valid') +
      '</th><th class="num">' + t.html('consoleMetrics.th.expired') +
      '</th><th class="num">' + t.html('consoleMetrics.th.noExpiry') +
      '</th></tr>' +
      (body || '<tr><td colspan="5">' +
               t.html('consoleMetrics.artifacts.none') + '</td></tr>') +
      '</table>';
  }
}

export = MetricsPage;
