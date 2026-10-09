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
    const t = ctx.t;
    const paging = json.paging;
    const filterParams = { subsystem: (json.filter.subsystem || ''),
                           q: (json.filter.q || ''),
                           seen: !!json.filter.seen ? '1' : '',
                           per: ctx.query.per ? paging.perPage : '' };
    const nav = kit.pageNavPair('/admin/error-codes', filterParams, paging);

    const subsystemOptions = '<option value=""' +
      ((json.filter.subsystem || '') ? '' : ' ' +
        'selected') +
      '>' + t.html('consoleErrorCodes.filter.everySubsystem') +
      '</option>' +
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
          (row.retired ? '<br><span class="state-none">' +
            t.html('consoleErrorCodes.codes.retired') + '</span>' : '') +
        '</td><td>' + kit.esc(row.summary) + '</td><td>' +
        (row.spec ? kit.esc(row.spec) : '<span ' +
              'class="state-none">—</span>') + '</td><td ' +
        'class="num">' + (row.seen
          ? '<a href="/admin/audit?code=' + encodeURIComponent(row.code) +
            '">' +
            kit.esc(row.seen) + '</a><br><span class="state-none">' +
            t.html('consoleErrorCodes.codes.last',
                   { when: kit.whenText(row.lastSeenAt) }) + '</span>'
          : '<span class="state-none">0</span>') + '</td>' +
        '</tr>';
    }).join('');

    const unregistered = json.unregisteredSeen.length
      ? '<h3>' + t.html('consoleErrorCodes.unregistered.heading') +
        '</h3>' +
        kit.note(t.html('consoleErrorCodes.unregistered.note')) +
        '<table><tr><th>' + t.html('consoleErrorCodes.th.code') +
        '</th><th class="num">' + t.html('consoleErrorCodes.th.rows') +
        '</th></tr>' +
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
        kit.tile(json.registered, t.text('consoleErrorCodes.tile.codes')) +
        kit.tile(json.subsystemCount,
                 t.text('consoleErrorCodes.tile.subsystems')) +
        kit.tile(json.distinctCodesSeen,
                 t.text('consoleErrorCodes.tile.distinctSeen')) +
        kit.tile(json.auditRowsWithCode,
                 t.text('consoleErrorCodes.tile.rowsWithCode')) +
        kit.tile(json.unregisteredSeen.length,
                 t.text('consoleErrorCodes.tile.unregistered')) +
      '</div>' +

      kit.note(t.html('consoleErrorCodes.note.form')) +

      // Split around its link (#539): a catalog message cannot carry an
      // anchor.
      kit.note(t.html('consoleErrorCodes.note.seenBefore') + '<a ' +
      'href="/admin/audit">' + t.html('consoleErrorCodes.note.seenLink') +
      '</a>' + t.html('consoleErrorCodes.note.seenAfter',
                      { held: json.auditRowsHeld })) +

      kit.note(t.html('consoleErrorCodes.note.http')) +

      '<h2>' + t.html('consoleErrorCodes.subsystems.heading') + '</h2>' +
      '<table><tr><th>' + t.html('consoleErrorCodes.th.prefix') +
      '</th><th>' + t.html('consoleErrorCodes.th.subsystem') + '</th><th ' +
      'class="num">' + t.html('consoleErrorCodes.th.codes') +
      '</th><th class="num">' + t.html('consoleErrorCodes.th.seen') +
      '</th><th>' + t.html('consoleErrorCodes.th.raisedFrom') +
      '</th></tr>' + subsystemRows +
      '</table><h2>' + t.html('consoleErrorCodes.codes.heading') +
      '</h2><form ' +
      'method="get" action="/admin/error-codes"><div ' +
      'class="formrow"><label for="subsystem">' +
      t.html('consoleErrorCodes.th.subsystem') + '</label><select ' +
      'id="subsystem" name="subsystem">' +
          subsystemOptions + '</select>' +
        '<label for="q">' + t.html('consoleErrorCodes.filter.text') +
        '</label>' +
        '<input type="text" id="q" name="q" size="30" value="' +
      kit.esc((json.filter.q || '')) +
          '" placeholder="' +
        kit.esc(t.text('consoleErrorCodes.filter.placeholder')) + '">' +
        '<label for="seen"><input type="checkbox" id="seen" name="seen" ' +
        'value="1"' +
          (!!json.filter.seen ? ' checked' : '') + '> ' +
        t.html('consoleErrorCodes.filter.onlyHeld') +
        '</label><label for="per">' +
        t.html('consoleErrorCodes.filter.perPage') + '</label><select ' +
        'id="per" name="per">' +
          kit.perPageOptions(paging.perPage) + '</select>' +
        '<button class="secondary">' +
        t.html('consoleErrorCodes.filter.filter') + '</button>' +
        (filtering ? ' <a href="/admin/error-codes">' +
         t.html('consoleErrorCodes.filter.clear') + '</a>' : '') +
      '</div></form>' +
      nav.head +
      '<table><tr><th>' + t.html('consoleErrorCodes.th.code') +
      '</th><th>' + t.html('consoleErrorCodes.th.whatFailed') +
      '</th><th>' + t.html('consoleErrorCodes.th.clientSees') + '</th>' +
      '<th class="num">' + t.html('consoleErrorCodes.th.seen') +
      '</th></tr>' +
      (codeRows || '<tr><td colspan="4">' +
       t.html('consoleErrorCodes.codes.none') + '</td></tr>') +
      '</table>' +
      nav.foot +
      unregistered +

      kit.note(t.html('consoleErrorCodes.note.table',
                      { max: kit.MAX_ROWS }));

    return inner;
  }
}

export = ErrorCodesPage;
