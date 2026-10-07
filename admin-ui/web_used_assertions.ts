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
        '</td><td>' + kit.esc(row.use === 'authorization-grant' ? 'grant'
          : row.use === 'request-object' ? 'request object'
            : 'client auth') +
        '</td>' +
        '<td class="who">' + kit.shortened(row.issuer, 40) + '</td>' +
        '<td class="who">' + kit.shortened(row.identifier, 32) + '</td>' +
        '<td class="who">' +
        (row.clientId ? kit.shortened(row.clientId, 32)
          : '<span class="state-none">—</span>') + '</td>' +
        '<td class="who">' + (row.subject ? kit.shortened(row.subject, 32)
          : '<span class="state-none">—</span>') + '</td>' +
        '<td>' + (row.state === 'spent' ? 'spent'
          : '<span class="state-none" title="' +
            kit.esc(json.states.reserved) + '">in flight</span>') +
            '</td>' +
        '<td>' + kit.esc(kit.whenText(row.expiresAt)) + '</td></tr>';
    }).join('');

    const filtering = filter.q || filter.format || filter.use ||
                      filter.state;
    const storeSentence = json.persistent
      ? kit.note('<strong>Held in the <code>' + kit.esc(json.store) +
                  '</code> store</strong>, so it survives a restart' +
                  (json.atomicAcrossProcesses
                    ? ', and recording a use is one atomic claim in that ' +
                      'database, so every process against it agrees at ' +
                      'once.'
                    : '. That store does not coordinate processes, and a ' +
                      'service that dispatches refuses to start without ' +
                      'one that does.'))
      : kit.warn('<strong>Held in this process only.</strong> ' +
                  kit.esc(json.storeNote),
                  'Not persisted');

    const inner = '<div class="tiles">' +
        kit.tile(json.live, 'unexpired rows in this realm') +
        kit.tile(json.cap, 'the most it will hold') +
        kit.tile(json.matched, filtering ? 'match' : 'listed') +
        kit.tile(json.store, 'store') +
      '</div>' +
      (json.searchNote ? kit.warn(kit.esc(json.searchNote),
                                   'A search of the newest rows') : '') +

      kit.note('Every <strong>RFC 7523</strong> JWT and <strong>RFC ' +
      '7522</strong> SAML assertion this realm has accepted — to ' +
      'authenticate a client (<code>client_assertion</code>) or as an ' +
      'authorization grant (<code>assertion</code>) — and that has not ' +
      'yet expired. <strong>An assertion is accepted once, ' +
      'ever</strong>: this is ONE history for both uses and both ' +
      'profiles, keyed by the document\'s format, its issuer and its ' +
      '<code>jti</code> or <code>ID</code>, so a JWT that authenticated ' +
      'a client cannot then be spent as a grant. The assertion itself is ' +
      'never stored.') +

      kit.note('<strong>In flight</strong> is an assertion that was ' +
      'accepted on a token request whose response has not finished; a ' +
      'replay racing it is refused exactly as on a spent one. It becomes ' +
      '<strong>spent</strong> only when that response is a 2xx — tokens ' +
      'were issued — and a request that failed for another reason (a bad ' +
      'code, an invalid scope, the issuance gate) RELEASES it, because ' +
      'an assertion that bought nothing has not been used.') +

      storeSentence +

      kit.note('A row is kept until the assertion would have expired — ' +
      'its <code>exp</code> or <code>NotOnOrAfter</code> plus the clock ' +
      'skew allowed when it was read — and not a moment longer. When ' +
      '<code>oauth2.assertionReplayCacheSize</code> unexpired rows are ' +
      'held, the next assertion is REFUSED rather than a live row ' +
      'forgotten.') +

      '<form method="get" action="/admin/used-assertions"><div ' +
      'class="formrow">' +
        '<label for="q">Text</label>' +
        '<input type="text" id="q" name="q" size="28" value="' +
        kit.esc(filter.q) + '" placeholder="an issuer, a jti, a client">' +
        '<label for="format">Format</label><select id="format" ' +
        'name="format">' +
        optionsOf(json.formats, filter.format, 'both') + '</select>' +
        '<label for="use">Use</label><select id="use" name="use">' +
        optionsOf(json.uses, filter.use, 'both') + '</select>' +
        '<label for="state">State</label><select id="state" name="state">' +
        optionsOf(json.states, filter.state, 'both') + '</select>' +
        '<label for="per">Per page</label><select id="per" name="per">' +
        kit.perPageOptions(paging.perPage) + '</select>' +
        '<button class="secondary">Filter</button>' +
        (filtering ? ' <a href="/admin/used-assertions">clear</a>' : '') +
      '</div></form>' +
      nav.head +
      '<table><tr><th>Used</th><th>Format</th><th>As</th><th>Issuer</th>' +
      '<th>jti / ID</th><th>Client</th><th>Subject</th><th>State</th>' +
      '<th>Remembered until</th></tr>' +
      (rows || '<tr><td colspan="9">' + (filtering ? 'Nothing matches.'
        : 'No assertion has been accepted in this realm, or every one ' +
          'has expired.') + '</td></tr>') +
      '</table>' +
      nav.foot +

      kit.note('This list is <code>GET ' +
      '/admin-api/used-assertions</code> with the same parameters. ' +
      'Paging is <code>?page=</code> and <code>?per=</code> (at most ' +
      kit.MAX_ROWS + ' rows a page).');

    return inner;
  }
}

export = UsedAssertionsPage;
