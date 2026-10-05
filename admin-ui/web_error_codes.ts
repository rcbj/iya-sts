// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_error_codes.ts
//
// ---------------------------------------------------------------------------
// AUDIT → ERROR CODES, DRAWN FROM ITS VIEW ALONE (#446, 2026-10-05).
//
// Draws Error codes from the answer of `GET /admin-api/error-codes`: every
// code this service records, by subsystem, filtered, with how often each has
// been seen in the audit log.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// It was drawn inside the route of `/admin/error-codes` in
// `admin-ui/admin.ts`, which still draws the page until the console's cutover
// by calling this with its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');

type Json = any;

/**
 * Draws Error codes from the answer of `GET /admin-api/error-codes`: every
 * code this service records, by subsystem, filtered, with how often each has
 * been seen in the audit log.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class ErrorCodesPage {
  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static body(ctx, json) {
    const paging = json.paging;
    const filterParams = { subsystem: (json.filter.subsystem || ''),
                           q: (json.filter.q || ''),
                           seen: !!json.filter.seen ? '1' : '',
                           per: ctx.query.per ? paging.perPage : '' };
    const nav = kit.pageNavPair('/admin/error-codes', filterParams, paging);

    const subsystemOptions = '<option value=""' +
      ((json.filter.subsystem || '') ? '' : ' ' +
        'selected') +
      '>every subsystem</option>' +
      json.subsystems.map(function (sub) {
        return '<option value="' + kit.esc(sub.id) + '"' +
               (sub.id === (json.filter.subsystem || '') ? ' selected' : '') +
                 '>' +
               kit.esc(sub.prefix + ' — ' + sub.label) + ' (' + sub.codes +
               ')</option>';
      }).join('');

    const subsystemRows = json.subsystems.map(function (sub) {
      return '<tr><td><a href="/admin/error-codes?subsystem=' +
             encodeURIComponent(sub.id) + '"><code>' + kit.esc(sub.prefix) +
             '</code></a></td><td>' + kit.esc(sub.label) + '</td><td ' +
             'class="num">' + kit.esc(sub.codes) + '</td>' +
             '<td class="num">' + (sub.seen
               ? '<a href="/admin/audit?code=' +
                 encodeURIComponent(sub.prefix) +
                 '">' +
                 kit.esc(sub.seen) + '</a>'
               : '<span class="state-none">0</span>') + '</td>' +
             '<td class="who">' + kit.esc(sub.where) + '</td></tr>';
    }).join('');

    const codeRows = json.codes.map(function (row) {
      return '<tr id="' + kit.esc(row.code) + '">' +
        '<td><code>' + kit.esc(row.code) + '</code>' +
          (row.retired ? '<br><span class="state-none">retired</span>' : '') +
        '</td><td>' + kit.esc(row.summary) + '</td><td>' +
        (row.spec ? kit.esc(row.spec) : '<span ' +
              'class="state-none">—</span>') + '</td><td ' +
        'class="num">' + (row.seen
          ? '<a href="/admin/audit?code=' + encodeURIComponent(row.code) +
            '">' +
            kit.esc(row.seen) + '</a><br><span class="state-none">last ' +
            kit.esc(kit.whenText(row.lastSeenAt)) + '</span>'
          : '<span class="state-none">0</span>') + '</td>' +
        '</tr>';
    }).join('');

    const unregistered = json.unregisteredSeen.length
      ? '<h3>Codes on audit rows that the table does not hold</h3>' +
        kit.note('These were recorded as given rather than dropped, so ' +
        'that the row saying the table is incomplete survives. Each one is ' +
        'a failure site whose code was never added to ' +
        '<code>common/error_codes.js</code>.') +
        '<table><tr><th>Code</th><th class="num">Rows</th></tr>' +
        json.unregisteredSeen.map(function (u) {
          return '<tr><td><a href="/admin/audit?code=' +
                 encodeURIComponent(u.code) +
                 '"><code>' + kit.esc(u.code) +
                 '</code></a></td><td class="num">' +
                 kit.esc(u.seen) + '</td></tr>';
        }).join('') + '</table>'
      : '';

    const filtering = (json.filter.subsystem || '') || (json.filter.q || '') ||
                      !!json.filter.seen;

    const inner = '<div class="tiles">' +
        kit.tile(json.registered, 'codes') +
        kit.tile(json.subsystemCount, 'subsystems') +
        kit.tile(json.distinctCodesSeen, 'codes on held audit rows') +
        kit.tile(json.auditRowsWithCode, 'audit rows with a code') +
        kit.tile(json.unregisteredSeen.length, 'unregistered codes seen') +
      '</div>' +

      kit.note('Every way this service can fail or refuse has a code of ' +
      'the form <code>STS-&lt;SUBSYSTEM&gt;-&lt;NNNN&gt;</code>. It is ' +
      'recorded on the audit row for the event and at the front of the ' +
      'service\'s log line, and <strong>it is never sent to a ' +
      'client</strong> — not in a body, a header or a redirect. Each ' +
      'protocol here already defines how it reports an error, and a client ' +
      'under test must see exactly that: the <em>Client sees</em> column ' +
      'says what it is sent, and the code changes nothing about it.') +

      kit.note('<strong>Seen</strong> counts the rows <a ' +
      'href="/admin/audit">the audit log</a> holds in this realm right now ' +
      '(' + kit.esc(json.auditRowsHeld) + '), ' +
      'so it falls as that log\'s cap discards the oldest, and it is zero ' +
      'for a failure recorded only as a log line — one that stops the ' +
      'service starting, and everything the remote PEP container records, ' +
      'since that container has no audit log of its own. A zero here is ' +
      'not "never happens".') +

      kit.note('<code>STS-HTTP-0002</code> and <code>STS-HTTP-0003</code> ' +
      'are what the HTTP call log records for a 4xx or 5xx response no ' +
      'handler gave a more specific code. <strong>A row carrying either ' +
      'names a failure site that is missing its own code.</strong> ' +
      '<code>STS-HTTP-0001</code> is an unrouted path, which is an ' +
      'ordinary outcome.') +

      '<h2>Subsystems</h2>' +
      '<table><tr><th>Prefix</th><th>Subsystem</th><th ' +
      'class="num">Codes</th><th class="num">Seen</th><th>Raised ' +
      'from</th></tr>' + subsystemRows +
      '</table><h2>Codes</h2><form ' +
      'method="get" action="/admin/error-codes"><div ' +
      'class="formrow"><label for="subsystem">Subsystem</label><select ' +
      'id="subsystem" name="subsystem">' +
          subsystemOptions + '</select>' +
        '<label for="q">Text</label>' +
        '<input type="text" id="q" name="q" size="30" value="' +
      kit.esc((json.filter.q || '')) +
          '" placeholder="a code, a word, invalid_grant">' +
        '<label for="seen"><input type="checkbox" id="seen" name="seen" ' +
        'value="1"' +
          (!!json.filter.seen ? ' checked' : '') + '> only codes on held ' +
        'rows</label><label for="per">Per page</label><select id="per" ' +
        'name="per">' +
          kit.perPageOptions(paging.perPage) + '</select>' +
        '<button class="secondary">Filter</button>' +
        (filtering ? ' <a href="/admin/error-codes">clear</a>' : '') +
      '</div></form>' +
      nav.head +
      '<table><tr><th>Code</th><th>What failed</th><th>Client sees</th>' +
      '<th class="num">Seen</th></tr>' +
      (codeRows || '<tr><td colspan="4">Nothing matches.</td></tr>') +
      '</table>' +
      nav.foot +
      unregistered +

      kit.note('The table is <code>common/error_codes.js</code> and this ' +
      'page has no control: a code is never renumbered or reused, because ' +
      'it ends up in alert rules and saved searches, and a condition that ' +
      'stops existing keeps its row marked retired. The same table is ' +
      'published as <code>docs/error-codes.md</code>, generated from the ' +
      'source, and this list is at <code>GET /admin-api/error-codes</code> ' +
      'with the same parameters. Paging is <code>?page=</code> and ' +
      '<code>?per=</code> (at most ' +
      kit.MAX_ROWS + ' rows a page).');

    return inner;
  }
}

export = ErrorCodesPage;
