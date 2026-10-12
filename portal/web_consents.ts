// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_consents.ts
//
// ---------------------------------------------------------------------------
// `/portal/consents`, DRAWN IN THE BROWSER (#568), from `GET
// /account-api/consents` (`portal_consents.ts`): what the person has agreed
// each application may ask for, a form per scope and per application to take
// it back, and — apart, with no button — the administrative consents an
// application's global consent answered for them (#537).
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import kit = require('./web_portal_kit');

type Json = any;
type PortalPage = import('../types/account-api').PortalPage;

const PATH = kit.BASE + '/consents';

/**
 * `/portal/consents`. A static utility class.
 */
class ConsentsPages {
  // A GeneralizedTime as a reader writes a date — in the reader's own
  // language and their locale's way of writing it (#539), still in UTC and
  // saying so. Anything shorter is drawn as it came, as it always was.
  /**
   * A consent's instant, readable.
   *
   * @param at - a GeneralizedTime
   * @param t - the translator
   * @returns the text
   */
  static readable(at: string, t: Json): string {
    const text = String(at || '');
    return text.length >= 14
      ? t.date(Date.UTC(Number(text.slice(0, 4)),
                        Number(text.slice(4, 6)) - 1,
                        Number(text.slice(6, 8)),
                        Number(text.slice(8, 10)),
                        Number(text.slice(10, 12))),
               { dateStyle: 'medium', timeStyle: 'short' }) + ' UTC'
      : text;
  }

  /**
   * One withdrawal form.
   *
   * @param fields - its hidden fields
   * @param label - the button's text
   * @returns the form's HTML
   */
  static form(fields: Record<string, string>, label: string): string {
    return '<form method="post" action="' + kit.esc(PATH) + '" ' +
      'style="display:inline">' +
      Object.keys(fields).map(function (name) {
        return '<input type="hidden" name="' + kit.esc(name) + '" value="' +
          kit.esc(fields[name]) + '">';
      }).join('') +
      '<button type="submit" class="danger">' + kit.esc(label) +
      '</button></form>';
  }

  /**
   * The administrative consents (#537): no button, not paged.
   *
   * @param groups - the view's `administrative`
   * @param t - the translator
   * @returns the section's HTML
   */
  static administrative(groups: Json[], t: Json): string {
    const body = (groups || []).length
      ? groups.map(function (group: Json): string {
          return '<div class="card"><h3>' + kit.esc(group.name) + '</h3>' +
            '<p class="sub"><code>' + kit.esc(group.client) + '</code></p>' +
            '<table><tr><th>' + t.html('portalConsents.forEverybody') +
            '</th><th>' + t.html('portalConsents.firstApplied') +
            '</th></tr>' +
            group.rows.map(function (one: Json): string {
              return '<tr><td><code>' + kit.esc(one.scope) +
                '</code></td><td>' +
                kit.esc(ConsentsPages.readable(one.at, t)) + '</td></tr>';
            }).join('') + '</table></div>';
        }).join('')
      : '<div class="card"><p class="sub">' +
        t.html('portalConsents.adminNone') + '</p></div>';
    return '<h2 id="administrative-consents">' +
      t.html('portalConsents.adminHeading') + '</h2>' +
      '<div class="card"><p class="sub">' + t.html('portalConsents.adminSub') +
      '</p></div>' + body;
  }

  /**
   * The page's body.
   *
   * @param view - `GET /account-api/consents`' answer
   * @param ctx - the render context
   * @returns the HTML
   */
  static render(view: Json, ctx: Json): string {
    const t = ctx.t;
    const paging = view.paging || { page: 1, pages: 1 };
    const at = paging.page;
    const pages = paging.pages;
    const groups: Json[] = view.groups || [];
    const body = groups.length
      ? groups.map(function (group: Json): string {
          return '<div class="card"><h2>' + kit.esc(group.name) + '</h2>' +
            '<p class="sub"><code>' + kit.esc(group.client) + '</code></p>' +
            '<table><tr><th>' + t.html('portalConsents.agreed') +
            '</th><th>' + t.html('portalConsents.when') + '</th>' +
            '<th></th></tr>' +
            group.rows.map(function (one: Json): string {
              return '<tr><td><code>' + kit.esc(one.scope) +
                '</code></td><td>' +
                kit.esc(ConsentsPages.readable(one.at, t)) + '</td><td>' +
                ConsentsPages.form({ action: 'scope', client: group.client,
                                     scope: one.scope, page: String(at) },
                                   t.text('portalConsents.withdraw')) +
                '</td></tr>';
            }).join('') + '</table><p>' +
            ConsentsPages.form({ action: 'application', client: group.client,
                                 page: String(at) },
                               t.text('portalConsents.withdrawAll')) +
            '</p></div>';
        }).join('')
      : '<div class="card"><p class="sub">' + t.html('portalConsents.none') +
        '</p></div>';
    const nav = pages > 1
      ? '<p class="pagenav">' +
        (at > 1
          ? '<a href="' + kit.esc(PATH + '?page=' + (at - 1)) + '">' +
            t.html('portalConsents.previous') + '</a>'
          : '<span class="off">' + t.html('portalConsents.previous') +
            '</span>') +
        '<span class="here">' +
        t.html('portalConsents.pageOf', { page: at, pages: pages }) +
        '</span>' +
        (at < pages
          ? '<a href="' + kit.esc(PATH + '?page=' + (at + 1)) + '">' +
            t.html('portalConsents.next') + '</a>'
          : '<span class="off">' + t.html('portalConsents.next') +
            '</span>') +
        '</p>'
      : '';
    return '<div class="card"><p class="sub">' + t.html('portalConsents.sub') +
      '</p><p class="note">' + t.html('portalConsents.adminNote') +
      '</p></div>' + body + nav +
      ConsentsPages.administrative(view.administrative, t);
  }

  /**
   * The pages, for `web_portal_pages.ts`.
   */
  static readonly PAGES: PortalPage[] = [
    { path: PATH, operation: '/account-api/consents',
      render: ConsentsPages.render }
  ];
}

export = ConsentsPages;
