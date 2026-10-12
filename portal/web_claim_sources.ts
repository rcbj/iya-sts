// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_claim_sources.ts
//
// ---------------------------------------------------------------------------
// `/portal/claim-sources`, DRAWN IN THE BROWSER (#568), from `GET
// /account-api/claim-sources` (`portal_claim_sources.ts`): every Claims
// Provider of the realm, with Link, Link again or Unlink. Link's answer is the
// provider's address, and the runtime sends the window there; the provider's
// callback comes back here with `done` or `problem`, drawn from the view.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import kit = require('./web_portal_kit');

type Json = any;
type PortalPage = import('../types/account-api').PortalPage;

const PATH = kit.BASE + '/claim-sources';

/**
 * `/portal/claim-sources`. A static utility class.
 */
class ClaimSourcesPages {
  /**
   * One Link or Unlink form.
   *
   * @param action - `link` or `unlink`
   * @param id - the provider
   * @param label - the button's HTML
   * @param danger - whether the button is a danger one
   * @returns the form's HTML
   */
  static form(action: string, id: string, label: string,
              danger: boolean): string {
    return '<form method="post" action="' + kit.esc(PATH) + '" ' +
      'style="display:inline">' +
      '<input type="hidden" name="action" value="' + action + '">' +
      '<input type="hidden" name="id" value="' + kit.esc(id) + '">' +
      '<button type="submit"' + (danger ? ' class="danger"' : '') +
      ' id="claim-source-' + action + '-' + kit.esc(id) + '">' + label +
      '</button></form> ';
  }

  /**
   * The page's body.
   *
   * @param view - `GET /account-api/claim-sources`' answer
   * @param ctx - the render context
   * @returns the HTML
   */
  static render(view: Json, ctx: Json): string {
    const t = ctx.t;
    const form = ClaimSourcesPages.form;
    const rows = (view.providers || []).map(function (p: Json): string {
      const link = p.link;
      // THE SENTENCE IS SPLIT AROUND THE LIST OF CLAIMS (#539): each claim
      // is a <code> the code draws, which a message cannot carry as a
      // parameter, so the words before and after it are two messages.
      return '<div class="card claim-source" id="claim-source-' +
        kit.esc(p.id) + '"><p><strong>' + kit.esc(p.name) +
        '</strong> <code>' + kit.esc(p.issuer) + '</code></p>' +
        '<p class="sub">' + t.html('portalClaimSources.supplies') + ' ' +
        (p.claims || []).map(function (c: string): string {
          return '<code>' + kit.esc(c) + '</code>';
        }).join(', ') + (p.delivery === 'distributed'
          ? t.html('portalClaimSources.distributed')
          : t.html('portalClaimSources.aggregated')) + '</p>' +
        (link
          ? '<p class="claim-source-linked">' + (link.stale
              ? t.html('portalClaimSources.linkedStale',
                       { when: t.date(link.linkedAt) })
              : t.html('portalClaimSources.linked',
                       { when: t.date(link.linkedAt) })) + '</p>' +
            (link.stale ? form('link', p.id,
              t.html('portalClaimSources.linkAgain'), false) : '') +
            form('unlink', p.id, t.html('portalClaimSources.unlink'), true)
          : form('link', p.id, t.html('portalClaimSources.link'), false)) +
        '</div>';
    });
    return (view.problem ? '<div class="err">' + kit.esc(view.problem) +
                           '</div>' : '') +
      (view.notice ? '<div class="ok">' + kit.esc(view.notice) + '</div>'
                   : '') +
      '<div class="card"><h2>' + t.html('portalClaimSources.heading') +
      '</h2><p class="sub">' + t.html('portalClaimSources.sub') +
      '</p></div>' +
      (rows.length ? rows.join('')
        : '<div class="card"><p id="claim-sources-none">' +
          t.html('portalClaimSources.none') + '</p></div>');
  }

  /**
   * The pages, for `web_portal_pages.ts`.
   */
  static readonly PAGES: PortalPage[] = [
    { path: PATH, operation: '/account-api/claim-sources',
      render: ClaimSourcesPages.render }
  ];
}

export = ClaimSourcesPages;
