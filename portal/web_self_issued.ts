// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_self_issued.ts
//
// ---------------------------------------------------------------------------
// `/portal/self-issued`, DRAWN IN THE BROWSER (#568), from `GET
// /account-api/self-issued` (`portal_self_issued.ts`): the enrolled SIOPv2
// subjects, a Remove button each, and the link that enrols one by proving it
// at `/authn/wallet` — a plain link, because that is a sign-in, not a form.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import kit = require('./web_portal_kit');

type Json = any;
type PortalPage = import('../types/account-api').PortalPage;

const PATH = kit.BASE + '/self-issued';

/**
 * `/portal/self-issued`. A static utility class.
 */
class SelfIssuedPages {
  /**
   * The page's body.
   *
   * @param view - `GET /account-api/self-issued`'s answer
   * @param ctx - the render context
   * @returns the HTML
   */
  static render(view: Json, ctx: Json): string {
    const t = ctx.t;
    const held: Json[] = view.subjects || [];
    const rows = held.map(function (one: Json) {
      // The enrolment instant in the reader's own way of writing a date
      // (#539).
      return '<tr><td><code>' + kit.esc(one.subject) + '</code></td><td>' +
        kit.esc(one.label || '') + '</td><td>' +
        kit.esc(one.enrolledAt ? t.date(one.enrolledAt) : '') +
        (one.by ? ' (' + kit.esc(one.by) + ')' : '') + '</td><td>' +
        // How it was enrolled (#693): proved with the person's wallet, or
        // by an administrator, unproven.
        (one.proof === 'wallet' ? t.html('portalSelfIssued.proofWallet')
                                : t.html('portalSelfIssued.proofAdmin')) +
        '</td><td>' +
        '<form method="post" action="' + kit.esc(PATH) + '">' +
        '<input type="hidden" name="action" value="remove">' +
        '<input type="hidden" name="subject" value="' + kit.esc(one.subject) +
        '"><button class="danger" type="submit">' +
        t.html('portalSelfIssued.remove') + '</button></form></td></tr>';
    });
    return (view.notice ? '<div class="ok">' + kit.esc(view.notice) +
                          '</div>' : '') +
      '<div class="card"><h2>' + t.html('portalSelfIssued.heading') +
      '</h2><p class="sub">' + t.html('portalSelfIssued.sub') + '</p>' +
      (held.length
        ? '<table><tr><th>' + t.html('portalSelfIssued.subject') +
          '</th><th>' + t.html('portalSelfIssued.label') + '</th><th>' +
          t.html('portalSelfIssued.enrolled') + '</th><th>' +
          t.html('portalSelfIssued.how') + '</th><th></th></tr>' +
          rows.join('') + '</table>'
        : '<p id="siop-none">' + t.html('portalSelfIssued.none') + '</p>') +
      (view.enabled
        ? '<p><a class="button" id="siop-enrol" href="/authn/wallet?siop=1' +
          '&amp;enrol=1">' + t.html('portalSelfIssued.enrol') +
          '</a></p><p class="sub">' + t.html('portalSelfIssued.enrolNote') +
          ' ' + t.html('portalSelfIssued.reprove') + '</p>'
        : '<p class="sub" id="siop-off">' + t.html('portalSelfIssued.off') +
          '</p>') + '</div>';
  }

  /**
   * The pages, for `web_portal_pages.ts`.
   */
  static readonly PAGES: PortalPage[] = [
    { path: PATH, operation: '/account-api/self-issued',
      render: SelfIssuedPages.render }
  ];
}

export = SelfIssuedPages;
