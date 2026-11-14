// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_gnap.ts
//
// ---------------------------------------------------------------------------
// `/portal/gnap`, DRAWN IN THE BROWSER (#568), from `GET /account-api/gnap`
// (`portal_gnap.ts`): the GNAP grants the person gave, a card each with its
// rights and tokens, and a Revoke button where there is something left to
// end.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import kit = require('./web_portal_kit');

type Json = any;
type PortalPage = import('../types/account-api').PortalPage;

const PATH = kit.BASE + '/gnap';

/**
 * `/portal/gnap`. A static utility class.
 */
class GnapPages {
  // Epoch seconds as a reader writes a date — in the reader's language and
  // their locale's way of writing it (#539), in UTC and saying so.
  /**
   * An instant in seconds, readable.
   *
   * @param seconds - epoch seconds
   * @param t - the translator
   * @returns the text
   */
  static readable(seconds: unknown, t: Json): string {
    const n = Number(seconds);
    return n > 0
      ? t.date(n * 1000, { dateStyle: 'medium', timeStyle: 'short' }) +
        ' UTC'
      : '—';
  }

  // One access right, in words: the type (or reference) and what it names,
  // including any limits it carries. The dimension names (`actions`,
  // `identifier`, `limits`) are RFC 9635's own field names, and stay as
  // they are in every language (#539).
  /**
   * One access right.
   *
   * @param one - an RFC 9635 access right, or a reference
   * @returns its HTML
   */
  static right(one: Json): string {
    if (typeof one === 'string') {
      return '<code>' + kit.esc(one) + '</code>';
    }
    const parts: string[] = [];
    ['actions', 'locations', 'datatypes', 'privileges'].forEach(
        function (dimension) {
      if (Array.isArray(one[dimension]) && one[dimension].length) {
        parts.push(dimension + ': ' + one[dimension].join(', '));
      }
    });
    if (one.identifier) {
      parts.push('identifier: ' + one.identifier);
    }
    if (one.limits !== undefined) {
      parts.push('limits: ' + JSON.stringify(one.limits));
    }
    return '<code>' + kit.esc(one.type || '') + '</code>' +
      (parts.length ? ' — ' + kit.esc(parts.join('; ')) : '');
  }

  /**
   * One grant's card.
   *
   * @param row - the grant
   * @param at - the page of the list it is on
   * @param t - the translator
   * @returns the card's HTML
   */
  static card(row: Json, at: number, t: Json): string {
    const state = row.finalization
      ? t.text('portalGnap.stateEnded',
               { reason: t.text('portalGnap.ended',
                                { reason: String(row.finalization.reason) }),
                 when: GnapPages.readable(row.finalization.at, t) })
      : (row.state === 'approved' ? t.text('portalGnap.stateActive')
                                  : t.text('portalGnap.stateWaiting'));
    // `bearer` is RFC 9635's flag on the token and stays as written; the
    // token's state (`live`, `rotated`, `revoked`, `expired`) is the
    // catalog's.
    const tokens = (row.tokens || []).length
      ? '<table><tr><th>' + t.html('portalGnap.token') + '</th><th>' +
        t.html('portalGnap.format') + '</th><th>' +
        t.html('portalGnap.expires') + '</th><th>' +
        t.html('portalGnap.tokenState') + '</th></tr>' +
        row.tokens.map(function (token: Json) {
          return '<tr><td>' + kit.esc(token.label || '—') + '</td><td><code>' +
            kit.esc(token.format) + '</code>' +
            (token.bearer ? ' <span class="sub">bearer</span>' : '') +
            '</td><td>' + kit.esc(GnapPages.readable(token.expiresAt, t)) +
            '</td><td>' +
            t.html('portalGnap.tokenStateValue',
                   { state: String(token.state) }) + '</td></tr>';
        }).join('') + '</table>'
      : '<p class="sub">' + t.html('portalGnap.noTokens') + '</p>';
    const revoke = row.revocable
      ? '<form method="post" action="' + kit.esc(PATH) + '">' +
        '<input type="hidden" name="grant" value="' + kit.esc(row.id) + '">' +
        '<input type="hidden" name="page" value="' + kit.esc(String(at)) +
        '"><button type="submit" class="danger">' +
        t.html('portalGnap.revoke') + '</button></form>'
      : '';
    return '<div class="card"><h2>' + kit.esc(row.clientName || row.client) +
      '</h2><p class="sub"><code>' + kit.esc(row.client) + '</code> · ' +
      kit.esc(state) + '</p>' +
      '<p>' + (row.rightsAre === 'approved' ? t.html('portalGnap.may')
                                            : t.html('portalGnap.askedTo')) +
      '</p>' +
      '<ul>' + ((row.rights || []).map(function (one: Json) {
        return '<li>' + GnapPages.right(one) + '</li>';
      }).join('') || '<li>' + t.html('portalGnap.nothingSpecific') +
        '</li>') + '</ul>' +
      (row.subjectReleasedAt
        ? '<p class="note">' + t.html('portalGnap.subjectReleased',
            { when: GnapPages.readable(row.subjectReleasedAt, t) }) + '</p>'
        : '') +
      tokens +
      '<p class="note">' + (row.finalization
        ? t.html('portalGnap.granted',
                 { when: GnapPages.readable(row.createdAt, t) })
        : t.html('portalGnap.grantedRenewable',
                 { when: GnapPages.readable(row.createdAt, t),
                   until: GnapPages.readable(row.grantExpiresAt, t) })) +
      '</p>' + revoke + '</div>';
  }

  /**
   * The page's body.
   *
   * @param view - `GET /account-api/gnap`'s answer
   * @param ctx - the render context
   * @returns the HTML
   */
  static render(view: Json, ctx: Json): string {
    const t = ctx.t;
    const paging = view.paging || { page: 1, pages: 1 };
    const at = paging.page;
    const rows: Json[] = view.rows || [];
    const body = rows.length
      ? rows.map(function (row: Json): string {
          return GnapPages.card(row, at, t);
        }).join('')
      : '<div class="card"><p class="sub">' + t.html('portalGnap.none') +
        '</p></div>';
    const nav = paging.pages > 1
      ? '<p class="pagenav">' +
        (at > 1
          ? '<a href="' + kit.esc(PATH + '?page=' + (at - 1)) + '">' +
            t.html('portalGnap.previous') + '</a>'
          : '<span class="off">' + t.html('portalGnap.previous') +
            '</span>') +
        '<span class="here">' +
        t.html('portalGnap.pageOf', { page: at, pages: paging.pages }) +
        '</span>' +
        (at < paging.pages
          ? '<a href="' + kit.esc(PATH + '?page=' + (at + 1)) + '">' +
            t.html('portalGnap.next') + '</a>'
          : '<span class="off">' + t.html('portalGnap.next') + '</span>') +
        '</p>'
      : '';
    // The view layer's note is English prose for the console; the portal
    // draws the same sentence from its own catalog (#539).
    const cells = view.cells && view.cells.multiCell
      ? '<p class="note">' + t.html('portalGnap.cellsNote') + '</p>' : '';
    return '<div class="card"><p class="sub">' + t.html('portalGnap.sub') +
      '</p>' + cells + '</div>' + body + nav;
  }

  /**
   * The pages, for `web_portal_pages.ts`.
   */
  static readonly PAGES: PortalPage[] = [
    { path: PATH, operation: '/account-api/gnap', render: GnapPages.render }
  ];
}

export = GnapPages;
