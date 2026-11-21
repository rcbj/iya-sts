// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_tokens.ts
//
// ---------------------------------------------------------------------------
// `/portal/tokens`, DRAWN IN THE BROWSER (#1955 P1), from `GET
// /account-api/tokens` (`account_tokens.ts`): the person's hardware tokens —
// each physical security key or smart card the register recorded from its
// attestation — with the credentials of theirs on it, and an "I lost this
// key" button on each active one, which posts `lost` to `POST
// /portal/tokens` (the account API's `actOnTokens`).
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import kit = require('./web_portal_kit');

type Json = any;
type PortalPage = import('../types/account-api').PortalPage;

const PATH = kit.BASE + '/tokens';

/**
 * `/portal/tokens`. A static utility class.
 */
class TokensPages {
  /**
   * One token's credentials.
   *
   * @param one - the token
   * @param t - the translator
   * @returns the HTML
   */
  static credentialsCell(one: Json, t: Json): string {
    const list: Json[] = one.credentials || [];
    return list.length ? list.map(function (c: Json): string {
      return kit.esc(c.kind === 'fido' ? t.text('portalTokens.kind.fido')
        : (c.kind === 'x509' ? t.text('portalTokens.kind.x509') : c.kind)) +
        (c.label ? ' — ' + kit.esc(c.label) : '') +
        (c.retired ? ' (' + t.html('portalTokens.retired') + ')' : '');
    }).join('<br>') : '—';
  }

  /**
   * The page's body.
   *
   * @param view - `GET /account-api/tokens`' answer
   * @param ctx - the render context
   * @returns the HTML
   */
  static render(view: Json, ctx: Json): string {
    const t = ctx.t;
    const held: Json[] = view.tokens || [];
    const rows = held.map(function (one: Json): string {
      const lost = one.status === 'lost';
      return '<tr><td>' + kit.esc(one.model || one.vendor) + '</td><td>' +
        kit.esc(one.serial) + '</td><td>' +
        TokensPages.credentialsCell(one, t) + '</td><td>' +
        (lost ? t.html('portalTokens.status.lost', { at: one.lostAt
          ? t.date(one.lostAt) : '' })
              : t.html('portalTokens.status.active')) + '</td><td>' +
        (lost ? '' : '<form method="post" action="' + PATH + '">' +
          '<input type="hidden" name="action" value="lost">' +
          '<input type="hidden" name="key" value="' + kit.esc(one.key) +
          '"><button class="danger" type="submit">' +
          t.html('portalTokens.lost.button') + '</button></form>') +
        '</td></tr>';
    });
    return '<div class="card"><h2>' + t.html('portalTokens.heading') +
      '</h2><p class="sub">' + t.html('portalTokens.intro') + '</p>' +
      (held.length
        ? '<table><tr><th>' + t.html('portalTokens.col.model') + '</th><th>' +
          t.html('portalTokens.col.serial') + '</th><th>' +
          t.html('portalTokens.col.credentials') + '</th><th>' +
          t.html('portalTokens.col.status') + '</th><th></th></tr>' +
          rows.join('') + '</table>' +
          '<p class="note">' + t.html('portalTokens.lost.what') + '</p>'
        : '<p id="tokens-none">' + t.html('portalTokens.none') + '</p>') +
      '</div>';
  }

  /**
   * The pages, for `web_portal_pages.ts`.
   */
  static readonly PAGES: PortalPage[] = [
    { path: PATH, operation: '/account-api/tokens',
      render: TokensPages.render }
  ];
}

export = TokensPages;
