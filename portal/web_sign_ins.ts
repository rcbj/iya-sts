// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_sign_ins.ts
//
// ---------------------------------------------------------------------------
// `/portal/sign-ins`, DRAWN IN THE BROWSER (#568), from `GET
// /account-api/sign-ins` (`portal_sign_ins.ts`): the person's recent
// sign-ins as the risk engine saw them, the application each one named,
// and two buttons on each one nobody has answered yet.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import kit = require('./web_portal_kit');

type Json = any;
type PortalPage = import('../types/account-api').PortalPage;

// A level's colours: the badge a person reads at a glance.
const LEVEL_STYLE: Record<string, string> = {
  LOW: 'background:#e6f4ea;color:#137333',
  MEDIUM: 'background:#fef7e0;color:#b06000',
  HIGH: 'background:#fce8e6;color:#a50e0e',
  UNSCORED: 'background:#f1f3f4;color:#3c4043'
};

const PATH = kit.BASE + '/sign-ins';

/**
 * `/portal/sign-ins`. A static utility class.
 */
class SignInsPages {
  /**
   * The two answers for one assessment.
   *
   * @param id - the assessment
   * @param t - the translator
   * @returns the forms' HTML
   */
  static answerForms(id: string, t: Json): string {
    return [['confirm', t.html('portalSignIns.yes')],
            ['deny', t.html('portalSignIns.no')]]
      .map(function (pair: string[]): string {
        return '<form method="post" action="' + PATH + '" ' +
          'style="display:inline">' +
          '<input type="hidden" name="action" value="' + pair[0] + '">' +
          '<input type="hidden" name="assessment" value="' + kit.esc(id) +
          '"><button type="submit">' + pair[1] + '</button></form>';
      }).join(' ');
  }

  /**
   * The page's body.
   *
   * @param view - `GET /account-api/sign-ins`' answer
   * @param ctx - the render context
   * @returns the HTML
   */
  static render(view: Json, ctx: Json): string {
    const t = ctx.t;
    const rows: Json[] = view.rows || [];
    const body = rows.length
      ? '<table><tr><th>' + t.html('portalSignIns.when') + '</th><th>' +
        t.html('portalSignIns.from') + '</th><th>' +
        t.html('portalSignIns.with') + '</th><th>' +
        t.html('portalSignIns.through') + '</th><th>' +
        t.html('portalSignIns.application') + '</th><th>' +
        t.html('portalSignIns.risk') + '</th><th>' +
        t.html('portalSignIns.wasItYou') + '</th></tr>' +
        rows.map(function (a: Json): string {
          const where = [a.city, a.country].filter(Boolean).join(', ') ||
                        t.text('portalSignIns.nowhere');
          const network = a.asOrg ? String(a.asOrg)
                                  : String(a.addressPrefix || '');
          // "Chrome on Linux" is a sentence, so its "on" is the catalog's
          // (#539); the two names are data.
          const device = a.uaFamily && a.uaOs
            ? t.text('portalSignIns.deviceOn',
                     { family: a.uaFamily, os: a.uaOs })
            : (a.uaFamily || a.uaOs || t.text('portalSignIns.noDevice'));
          const style = LEVEL_STYLE[String(a.level)] || LEVEL_STYLE.UNSCORED;
          const answer = a.feedback === 'confirmed'
            ? t.html('portalSignIns.saidYes')
            : a.feedback === 'denied' ? t.html('portalSignIns.saidNo')
            : SignInsPages.answerForms(a.id, t);
          const application = a.application
            ? kit.esc(String(a.application)) : '&mdash;';
          return '<tr><td>' + kit.esc(t.date(Number(a.at))) +
            '</td><td>' + kit.esc(where) + '<br><small>' + kit.esc(network) +
            '</small></td><td>' + kit.esc(device) + '</td><td>' +
            kit.esc(a.door || '') + '</td><td>' + application +
            '</td><td><span style="' + style +
            ';padding:2px 8px;border-radius:10px;font-weight:600">' +
            t.html('portalSignIns.level', { level: String(a.level) }) +
            '</span>' + (a.id && a.id === view.thisSession ? '<br><small>' +
              t.html('portalSignIns.thisSession') + '</small>' : '') +
            '</td><td>' + answer + '</td></tr>';
        }).join('') + '</table>'
      : '<p class="sub">' + t.html('portalSignIns.none', { days: view.days }) +
        '</p>';
    return '<div class="card"><h2>' + t.html('portalSignIns.heading') +
      '</h2><p class="sub">' + t.html('portalSignIns.sub') + '</p>' + body +
      // Thirty days of sign-ins, a page at a time (#313's sweep).
      kit.pageNav(PATH, ctx.query, view.paging, 'page', t) +
      '</div>';
  }

  /**
   * The pages, for `web_portal_pages.ts`.
   */
  static readonly PAGES: PortalPage[] = [
    { path: PATH, operation: '/account-api/sign-ins',
      render: SignInsPages.render }
  ];
}

export = SignInsPages;
