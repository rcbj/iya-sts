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
         ' &hellip; and ' + (row.who.length - MAX_WHO) + ' ' +
            'more' : '') +
        '</td></tr>';
    }).join('');

    const signOnRows = signOn.slice(0, kit.MAX_ROWS).map(function (s) {
      return '<tr><td>' + kit.esc(s.username) + '</td>' +
        '<td class="' + (s.expired ? 'state-expired' : 'state-valid') + '">' +
          (s.expired ? 'expired, not yet swept' : 'active') + '</td>' +
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
        kit.tile(snap.calls.total, 'endpoint calls') +
        kit.tile(snap.calls.paths, 'routes called') +
        kit.tile(snap.tokens.held, 'tokens issued') +
        kit.tile(snap.tokens.revoked, 'tokens revoked') +
        kit.tile(snap.artifacts.held, 'assertions, tickets, credentials') +
        kit.tile(liveSignOn.length, 'sign-on sessions') +
        kit.tile(snap.sessions.distinctSubjects,
                  'subjects with a live artifact') +
        kit.tile(MetricsPage.durationText(snap.uptimeMs), 'uptime') +
      '</div>' +
      kit.note('Since <code>' + kit.esc(kit.whenText(snap.startedAt)) +
                '</code>. Every ' +
      'figure on this page is computed when the page is drawn rather than ' +
      'kept up to date as things happen, because &ldquo;valid&rdquo; and ' +
      '&ldquo;expired&rdquo; are functions of the clock: a counter ' +
      'incremented at issuance would be wrong a second later.') +

      '<h2>Endpoint calls</h2>' +
      kit.note('Keyed on the route Express matched, not on the URL ' +
      'requested, so <code>/oauth2/register/:client_id</code> is one row ' +
      'rather than one row per client. These are the same route patterns ' +
      '<a href="/admin/sts-metadata">/admin/sts-metadata</a> lists.') +
      MetricsPage.callTable(snap) +

      '<h2>Tokens</h2>' +
      kit.note('Every JWT this service signs, by <code>typ</code> — which ' +
      'is the only thing that tells them apart, since all of them are ' +
      'RS256 and signed with the same key. <a href="/admin/tokens">The ' +
      'tokens page</a> lists them one by one — beside the SAML assertions ' +
      'and Kerberos tickets, which it also lists — and can invalidate ' +
      'these.') +
      MetricsPage.tokenKindTable(snap) +
      (snap.tokens.forgotten > 0
        ? kit.note(snap.tokens.forgotten + ' older token(s) have been ' +
          'forgotten: the registry holds the most ' +
          'recent ' + snap.tokens.cap + '. Their ' +
          'revocations are NOT forgotten — the set of revoked ' +
          '<code>jti</code>s is kept separately and is not capped, so a ' +
          'token revoked long ago stays revoked.')
        : '') +

      '<h2>Assertions, tickets and credentials</h2>' +
      kit.note('The artifacts that are not JWTs. None of them can be ' +
      'revoked and the console does not pretend otherwise — see the index ' +
      'for why — so the only distinction here is whether the validity ' +
      'window has closed. The assertions and the tickets are listed one by ' +
      'one on <a href="/admin/tokens">the tokens page</a>, beside the JWTs ' +
      'and in the order they were all issued; the credentials are counted ' +
      'here and nowhere else.') +
      MetricsPage.artifactKindTable(snap) +
      (snap.artifacts.forgotten > 0
        ? kit.note(snap.artifacts.forgotten + ' older artifact(s) have ' +
          'been forgotten; the registry holds the most ' +
          'recent ' + snap.artifacts.cap + '.')
        : '') +

      '<h2>Sessions, counted both ways</h2>' +
      kit.note('The two numbers mean different things and disagree on ' +
      'purpose. A <strong>sign-on session</strong> is a real one: a ' +
      'browser holding the <code>sts_session</code> cookie, shared between ' +
      'the OAuth 2.0 / OIDC login screen and WS-Federation, which is what ' +
      'makes single sign-on across the two work. An ' +
      '<strong>artifact-derived session</strong> is an inference: a ' +
      'subject that holds at least one artifact from that protocol family ' +
      'which is still valid. A <code>client_credentials</code> token is ' +
      'the second and not the first (there is no human and no browser ' +
      'behind it); a browser that has signed in but been issued nothing ' +
      'yet is the first and not the second; a Kerberos client is never the ' +
      'first at all. Both are counted here per family; <a ' +
      'href="/admin/users">the users page</a> is where one person\'s ' +
      'sessions and the tokens issued on each of them are.') +
      '<h3>Sign-on sessions (' + liveSignOn.length + ' active of ' +
      signOn.length + ' ' +
      'held)</h3><table><tr><th>User</th><th>State</th><th>amr</th><th>acr' +
      '</th><th>Signed in</th><th>Last authenticated</th>' +
      '<th>Expires</th><th>WS-Fed relying parties signed into</th></tr>' +
      (signOnRows || '<tr><td colspan="8">Nobody is signed in.</td></tr>') +
      '</table>' +
      kit.note('An expired session stays in the map until something reads ' +
      'it — <code>sessionOf()</code> drops one when it finds it stale — so ' +
      'it is listed as held but not active rather than quietly omitted.') +
      '<h3>Artifact-derived sessions (' + snap.sessions.distinctSubjects +
      ' distinct subject(s))</h3><table><tr><th>Protocol family</th><th ' +
      'class="num">Subjects</th><th>Who</th></tr>' +
      (sessionFamilyRows ||
       '<tr><td colspan="3">Nothing valid has been issued ' +
                            'yet.</td></tr>') +
      '</table>' +
      kit.note('A Kerberos TGT is counted as a session and a service ' +
      'ticket is not, because that is what they are: the TGT is the ' +
      'credential the session consists of, and a service ticket is one use ' +
      'of it. Counting both would report the same session twice.');

    return inner;
  }

  /**
   * Formats a duration as days, hours, minutes and seconds.
   *
   * @param ms - the duration in milliseconds
   * @returns the text, such as `1d 2h 3m 4s`
   */
  static durationText(ms) {
    const s = Math.floor((ms || 0) / 1000);
    const days = Math.floor(s / 86400);
    const hours = Math.floor((s % 86400) / 3600);
    const minutes = Math.floor((s % 3600) / 60);
    const parts = [];
    if (days) parts.push(days + 'd');
    if (days || hours) parts.push(hours + 'h');
    parts.push(minutes + 'm');
    parts.push((s % 60) + 's');
    return parts.join(' ');
  }

  /**
   * Draws the metrics page's table of calls per route.
   *
   * At most MAX_ROWS routes are drawn, busiest first; notes say how many
   * were left out and how many unmatched paths were collapsed.
   *
   * @param snap - a snapshot from stats.snapshot()
   * @returns the table and its notes as HTML
   */
  static callTable(snap) {
    const rows = snap.calls.rows.slice(0, kit.MAX_ROWS);
    const body = rows.map(function (row) {
      return '<tr><td><code>' + kit.esc(row.method) + '</code></td>' +
        '<td><code>' + kit.esc(row.path) + '</code>' +
        (row.matched ? '' : ' <span class="state-expired">no route</span>') +
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
    return '<table><tr><th>Method</th><th>Route</th><th ' +
      'class="num">Calls</th><th class="num">2xx</th><th ' +
      'class="num">3xx</th><th class="num">4xx</th><th ' +
      'class="num">5xx</th><th class="num">Avg ms</th><th class="num">Max ' +
      'ms</th><th>Last</th></tr>' +
      (body ||
       '<tr><td colspan="10">No call has been recorded yet.</td></tr>') +
      '</table>' +
      (hidden > 0 ? kit.note(hidden + ' further route(s) are not shown; the ' +
                                       'table draws the ' +
                    kit.MAX_ROWS + ' busiest.') : '') +
      (snap.calls.pathsCollapsed > 0
        ? kit.note(snap.calls.pathsCollapsed + ' request(s) to paths that ' +
          'matched no route were counted in the single ' +
          '<code>' + kit.esc('(other unmatched paths)') + '</code> ' +
          'row: the table is capped so that a scanner inventing URLs cannot ' +
          'grow it without limit.')
        : '');
  }

  /**
   * Draws the metrics page's table of tokens by kind and state.
   *
   * @param snap - a snapshot from stats.snapshot()
   * @returns the table as HTML
   */
  static tokenKindTable(snap) {
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
    return '<table><tr><th>Token</th><th class="num">Issued</th><th ' +
      'class="num">Valid</th><th class="num">Expired</th><th ' +
      'class="num">Revoked</th><th class="num">Not yet valid</th><th ' +
      'class="num">No expiry</th><th class="num">DPoP-bound</th></tr>' +
      (body || '<tr><td colspan="8">No token has been issued yet.</td></tr>') +
      '</table>';
  }

  /**
   * Draws the metrics page's table of assertions, tickets and SVIDs.
   *
   * @param snap - a snapshot from stats.snapshot()
   * @returns the table as HTML
   */
  static artifactKindTable(snap) {
    const body = snap.artifacts.byKind.map(function (row) {
      return '<tr><td>' + kit.esc(row.kind) + '</td>' +
        '<td class="num">' + row.issued + '</td>' +
        '<td class="num state-valid">' + row.valid + '</td>' +
        '<td class="num state-expired">' + row.expired + '</td>' +
        '<td class="num">' + row.noExpiry + '</td></tr>';
    }).join('');
    return '<table><tr><th>Artifact</th><th class="num">Issued</th><th ' +
      'class="num">Valid</th><th class="num">Expired</th><th class="num">No ' +
      'expiry</th></tr>' +
      (body || '<tr><td colspan="5">No assertion, ticket or credential has ' +
               'been issued yet.</td></tr>') +
      '</table>';
  }
}

export = MetricsPage;
