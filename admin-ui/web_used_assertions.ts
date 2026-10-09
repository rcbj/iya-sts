// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_used_assertions.ts
//
// ---------------------------------------------------------------------------
// USED ASSERTIONS, DRAWN FROM ITS VIEW ALONE (#446, 2026-10-05).
//
// Draws `/admin/used-assertions` from the answer of `GET
// /admin-api/used-assertions`: every RFC 7523 and RFC 7522 assertion this
// realm has accepted, filtered and paged, and where the history is held.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// It was drawn inside the route of `method:usedAssertionsPage` in
// `admin-ui/admin.ts`, which still draws the page until the console's cutover
// by calling this with its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');

type Json = any;

/**
 * Draws `/admin/used-assertions` from the answer of `GET
 * /admin-api/used-assertions`: every RFC 7523 and RFC 7522 assertion this
 * realm has accepted, filtered and paged, and where the history is held.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class UsedAssertionsPage {
  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static body(ctx, json) {
    // The page's words are its translator's (#539 phase 6); what the view
    // carries — issuers, identifiers, the store's own note — is drawn as it
    // comes.
    const t = ctx.t;
    const paging = json.paging;
    const filter = json.filter;
    const filterParams = { q: filter.q, format: filter.format,
                           use: filter.use,
                           state: filter.state,
                           per: ctx.query.per ? paging.perPage : '' };
    const nav = kit.pageNavPair('/admin/used-assertions', filterParams,
                                 paging);

    const optionsOf = function (table, chosen, allLabel) {
      return '<option value=""' + (chosen ? '' : ' selected') + '>' +
        kit.esc(allLabel) + '</option>' +
        Object.keys(table).map(function (id) {
          return '<option value="' + kit.esc(id) + '"' +
                 (id === chosen ? ' selected' : '') + '>' + kit.esc(id) +
                 ' — ' +
                 kit.esc(table[id]) + '</option>';
        }).join('');
    };

    const rows = json.rows.map(function (row) {
      return '<tr><td>' + kit.esc(kit.whenText(row.usedAt)) + '</td>' +
        '<td>' + kit.esc(row.format === 'saml' ? 'SAML 2.0' : 'JWT') +
        '</td><td>' + kit.esc(row.use === 'authorization-grant'
          ? t.text('consoleUsedAssertions.useGrant')
          : row.use === 'request-object'
            ? t.text('consoleUsedAssertions.useRequestObject')
            : t.text('consoleUsedAssertions.useClientAuth')) +
        '</td>' +
        '<td class="who">' + kit.shortened(row.issuer, 40) + '</td>' +
        '<td class="who">' + kit.shortened(row.identifier, 32) + '</td>' +
        '<td class="who">' +
        (row.clientId ? kit.shortened(row.clientId, 32)
          : '<span class="state-none">—</span>') + '</td>' +
        '<td class="who">' + (row.subject ? kit.shortened(row.subject, 32)
          : '<span class="state-none">—</span>') + '</td>' +
        '<td>' + (row.state === 'spent'
          ? t.html('consoleUsedAssertions.stateSpent')
          : '<span class="state-none" title="' +
            kit.esc(json.states.reserved) + '">' +
            t.html('consoleUsedAssertions.stateInFlight') + '</span>') +
            '</td>' +
        '<td>' + kit.esc(kit.whenText(row.expiresAt)) + '</td></tr>';
    }).join('');

    const filtering = filter.q || filter.format || filter.use ||
                      filter.state;
    const storeSentence = json.persistent
      ? kit.note(t.html('consoleUsedAssertions.storeHeld',
                        { store: json.store }) +
                  (json.atomicAcrossProcesses
                    ? t.html('consoleUsedAssertions.storeAtomic')
                    : t.html('consoleUsedAssertions.storeNotAtomic')))
      : kit.warn(t.html('consoleUsedAssertions.storeProcessOnly') + ' ' +
                  kit.esc(json.storeNote),
                  t.text('consoleUsedAssertions.notPersisted'));

    const inner = '<div class="tiles">' +
        kit.tile(json.live, t.text('consoleUsedAssertions.tileLive')) +
        kit.tile(json.cap, t.text('consoleUsedAssertions.tileCap')) +
        kit.tile(json.matched, filtering
          ? t.text('consoleUsedAssertions.tileMatch')
          : t.text('consoleUsedAssertions.tileListed')) +
        kit.tile(json.store, t.text('consoleUsedAssertions.tileStore')) +
      '</div>' +
      (json.searchNote ? kit.warn(kit.esc(json.searchNote),
                                   t.text('consoleUsedAssertions.searchNewest'))
        : '') +

      kit.note(t.html('consoleUsedAssertions.leadEvery')) +

      kit.note(t.html('consoleUsedAssertions.leadInFlight')) +

      storeSentence +

      kit.note(t.html('consoleUsedAssertions.leadKept')) +

      '<form method="get" action="/admin/used-assertions"><div ' +
      'class="formrow">' +
        '<label for="q">' + t.html('consoleUsedAssertions.labelText') +
        '</label>' +
        '<input type="text" id="q" name="q" size="28" value="' +
        kit.esc(filter.q) + '" placeholder="' +
        kit.esc(t.text('consoleUsedAssertions.placeholder')) + '">' +
        '<label for="format">' +
        t.html('consoleUsedAssertions.labelFormat') +
        '</label><select id="format" ' +
        'name="format">' +
        optionsOf(json.formats, filter.format,
                  t.text('consoleUsedAssertions.both')) + '</select>' +
        '<label for="use">' + t.html('consoleUsedAssertions.labelUse') +
        '</label><select id="use" name="use">' +
        optionsOf(json.uses, filter.use,
                  t.text('consoleUsedAssertions.both')) + '</select>' +
        '<label for="state">' +
        t.html('consoleUsedAssertions.labelState') +
        '</label><select id="state" name="state">' +
        optionsOf(json.states, filter.state,
                  t.text('consoleUsedAssertions.both')) + '</select>' +
        '<label for="per">' + t.html('consoleUsedAssertions.labelPer') +
        '</label><select id="per" name="per">' +
        kit.perPageOptions(paging.perPage) + '</select>' +
        '<button class="secondary">' +
        t.html('consoleUsedAssertions.filter') + '</button>' +
        (filtering ? ' <a href="/admin/used-assertions">' +
          t.html('consoleUsedAssertions.clear') + '</a>' : '') +
      '</div></form>' +
      nav.head +
      '<table><tr><th>' + t.html('consoleUsedAssertions.thUsed') +
      '</th><th>' + t.html('consoleUsedAssertions.thFormat') +
      '</th><th>' + t.html('consoleUsedAssertions.thAs') +
      '</th><th>' + t.html('consoleUsedAssertions.thIssuer') + '</th>' +
      '<th>jti / ID</th><th>' + t.html('consoleUsedAssertions.thClient') +
      '</th><th>' + t.html('consoleUsedAssertions.thSubject') +
      '</th><th>' + t.html('consoleUsedAssertions.thState') + '</th>' +
      '<th>' + t.html('consoleUsedAssertions.thUntil') + '</th></tr>' +
      (rows || '<tr><td colspan="9">' + (filtering
        ? t.html('consoleUsedAssertions.nothingMatches')
        : t.html('consoleUsedAssertions.empty')) + '</td></tr>') +
      '</table>' +
      nav.foot +

      kit.note(t.html('consoleUsedAssertions.footer',
                      { max: kit.MAX_ROWS }));

    return inner;
  }
}

export = UsedAssertionsPage;
