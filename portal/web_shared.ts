// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_shared.ts
//
// ---------------------------------------------------------------------------
// THE SHARING SECTION, DRAWN IN THE BROWSER (#1192): `/portal/shared` from
// `GET /account-api/shared` and `/portal/shared-with-me` from `GET
// /account-api/shared-with-me` (`portal_shared.ts`). Each resource a card,
// its shares listed with a Remove button, and the share form under them;
// the custom rules as ALFA; the pending requests; the ALFA editor where the
// realm allows it.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import kit = require('./web_portal_kit');

type Json = any;
type PortalPage = import('../types/account-api').PortalPage;

const PATH = kit.BASE + '/shared';
const WITH_ME = kit.BASE + '/shared-with-me';

/**
 * The Sharing section. A static utility class.
 */
class SharedPages {
  /**
   * An instant, readable, in UTC.
   *
   * @param ms - epoch milliseconds, or an ISO string
   * @param t - the translator
   * @returns the text
   */
  static readable(ms: unknown, t: Json): string {
    const n = typeof ms === 'string' ? Date.parse(ms) : Number(ms);
    return Number.isFinite(n) && n > 0
      ? t.date(n, { dateStyle: 'medium', timeStyle: 'short' }) + ' UTC'
      : '—';
  }

  /**
   * Who a share is with, in words.
   *
   * @param r - the share's recipient
   * @param t - the translator
   * @returns the HTML
   */
  static recipient(r: Json, t: Json): string {
    if (r.kind === 'person') {
      return t.html('portalShared.recipientPerson',
                    { name: String(r.label || r.value) });
    }
    if (r.kind === 'group') {
      return t.html('portalShared.recipientGroup',
                    { name: String(r.label || r.value) });
    }
    if (r.kind === 'claim') {
      return t.html('portalShared.recipientClaim',
                    { claim: String(r.claim), value: String(r.value) });
    }
    return t.html('portalShared.recipientRealm');
  }

  /**
   * One share, with its Remove button.
   *
   * @param share - the share
   * @param at - the page it is on
   * @param t - the translator
   * @returns the list item
   */
  static share(share: Json, at: number, t: Json): string {
    const extra: string[] = [];
    if (share.expires) {
      extra.push(t.html('portalShared.until',
                        { when: SharedPages.readable(share.expires, t) }));
    }
    if (share.acr) {
      extra.push(t.html('portalShared.atLevel', { acr: share.acr }));
    }
    if (share.askMe) {
      extra.push(t.html('portalShared.askMe'));
    }
    return '<li>' + SharedPages.recipient(share.recipient, t) + ' — ' +
      share.scopes.map(function (s: string) {
        return '<code>' + kit.esc(s) + '</code>';
      }).join(', ') + (extra.length ? '; ' + extra.join('; ') : '') +
      ' <form method="post" action="' + kit.esc(PATH) + '" ' +
      'style="display:inline"><input type="hidden" name="action" ' +
      'value="unshare"><input type="hidden" name="share" value="' +
      kit.esc(share.id) + '"><input type="hidden" name="page" value="' +
      kit.esc(String(at)) + '"><button type="submit" class="danger">' +
      t.html('portalShared.remove') + '</button></form></li>';
  }

  /**
   * The share form for one resource.
   *
   * @param row - the resource
   * @param at - the page it is on
   * @param t - the translator
   * @returns the form
   */
  static form(row: Json, at: number, t: Json): string {
    const kinds = ['person', 'group', 'realm', 'claim'];
    return '<form method="post" action="' + kit.esc(PATH) + '">' +
      '<input type="hidden" name="action" value="share">' +
      '<input type="hidden" name="resource" value="' + kit.esc(row.id) +
      '"><input type="hidden" name="page" value="' + kit.esc(String(at)) +
      '"><h3>' + t.html('portalShared.shareHeading') + '</h3>' +
      '<p>' + t.html('portalShared.chooseScopes') + ' ' +
      row.scopes.map(function (s: string) {
        return '<label><input type="checkbox" name="scope" value="' +
          kit.esc(s) + '"> <code>' + kit.esc(s) + '</code></label>';
      }).join(' ') + '</p>' +
      '<p><label>' + t.html('portalShared.who') + ' <select ' +
      'name="recipientKind">' + kinds.map(function (k: string) {
        return '<option value="' + k + '">' +
          t.html('portalShared.kind', { kind: k }) + '</option>';
      }).join('') + '</select></label></p>' +
      '<p><label>' + t.html('portalShared.recipientField') +
      ' <input name="recipient" maxlength="256"></label></p>' +
      '<p><label>' + t.html('portalShared.claimField') +
      ' <input name="claim" maxlength="64"></label></p>' +
      '<p><label>' + t.html('portalShared.expiresField') +
      ' <input type="date" name="expires"></label></p>' +
      '<p><label>' + t.html('portalShared.acrField') +
      ' <input name="acr" maxlength="128"></label></p>' +
      '<p><label><input type="checkbox" name="askMe" value="on"> ' +
      t.html('portalShared.askMeField') + '</label></p>' +
      '<button type="submit">' + t.html('portalShared.shareButton') +
      '</button></form>';
  }

  /**
   * One resource's card.
   *
   * @param row - the resource
   * @param at - the page it is on
   * @param t - the translator
   * @returns the card
   */
  static resource(row: Json, at: number, t: Json): string {
    return '<div class="card"><h2>' + kit.esc(row.name || row.id) +
      '</h2><p class="sub">' + t.html('portalShared.server',
                                      { server: row.resourceServer }) +
      (row.type ? ' · <code>' + kit.esc(row.type) + '</code>' : '') +
      ' · <code>' + kit.esc(row.id) + '</code></p>' +
      '<h3>' + t.html('portalShared.sharedWith') + '</h3>' +
      (row.shares.length
        ? '<ul>' + row.shares.map(function (s: Json) {
            return SharedPages.share(s, at, t);
          }).join('') + '</ul>'
        : '<p class="sub">' + t.html('portalShared.nobodyYet') + '</p>') +
      SharedPages.form(row, at, t) + '</div>';
  }

  // The previous and next links of a paged list.
  private static pager(path: string, paging: Json, t: Json): string {
    const at = paging.page;
    if (!(paging.pages > 1)) {
      return '';
    }
    return '<p class="pagenav">' + (at > 1
      ? '<a href="' + kit.esc(path + '?page=' + (at - 1)) + '">' +
        t.html('portalShared.previous') + '</a>'
      : '<span class="off">' + t.html('portalShared.previous') + '</span>') +
      '<span class="here">' + t.html('portalShared.pageOf',
                                     { page: at, pages: paging.pages }) +
      '</span>' + (at < paging.pages
      ? '<a href="' + kit.esc(path + '?page=' + (at + 1)) + '">' +
        t.html('portalShared.next') + '</a>'
      : '<span class="off">' + t.html('portalShared.next') + '</span>') +
      '</p>';
  }

  /**
   * `/portal/shared`.
   *
   * @param view - `GET /account-api/shared`'s answer
   * @param ctx - the render context
   * @returns the HTML
   */
  static render(view: Json, ctx: Json): string {
    const t = ctx.t;
    const paging = view.paging || { page: 1, pages: 1 };
    const resources: Json[] = view.resources || [];
    const intro = '<div class="card"><p class="sub">' +
      t.html('portalShared.sub') + '</p>' +
      (view.enabled ? '' : '<p class="note">' + t.html('portalShared.off') +
                           '</p>') + '</div>';
    const body = resources.length
      ? resources.map(function (row: Json) {
          return SharedPages.resource(row, paging.page, t);
        }).join('')
      : '<div class="card"><p class="sub">' +
        t.html('portalShared.noResources') + '</p></div>';
    const pending = '<h2>' + t.html('portalShared.pendingHeading') +
      '</h2><div class="card">' + ((view.pending || []).length
        ? '<ul>' + view.pending.map(function (p: Json) {
            return '<li>' + kit.esc(p.requestingParty) + ' · <code>' +
              kit.esc(p.client) + '</code></li>';
          }).join('') + '</ul>'
        : '<p class="sub">' + t.html('portalShared.pendingNone') + '</p>') +
      '</div>';
    const custom = (view.custom || []).length
      ? '<h2>' + t.html('portalShared.customHeading') + '</h2>' +
        '<div class="card"><p class="sub">' + t.html('portalShared.customSub') +
        '</p>' + view.custom.map(function (c: Json) {
          return '<h3><code>' + kit.esc(c.id) + '</code></h3>' +
            (c.description ? '<p>' + kit.esc(c.description) + '</p>' : '') +
            (c.alfa ? '<pre>' + kit.esc(c.alfa) + '</pre>' : '');
        }).join('') + '</div>'
      : '';
    const alfa = view.alfaEditing
      ? '<h2>' + t.html('portalShared.alfaHeading') + '</h2>' +
        '<div class="card"><p class="sub">' + t.html('portalShared.alfaSub') +
        '</p><form method="post" action="' + kit.esc(PATH) + '">' +
        '<input type="hidden" name="action" value="alfa">' +
        '<textarea name="alfa" rows="20" cols="80">' + kit.esc(view.alfa) +
        '</textarea><p><button type="submit" class="danger">' +
        t.html('portalShared.alfaSave') + '</button></p></form></div>'
      : '';
    return intro + body + SharedPages.pager(PATH, paging, t) + pending +
      custom + alfa;
  }

  /**
   * `/portal/shared-with-me`.
   *
   * @param view - `GET /account-api/shared-with-me`'s answer
   * @param ctx - the render context
   * @returns the HTML
   */
  static withMe(view: Json, ctx: Json): string {
    const t = ctx.t;
    const rows: Json[] = view.rows || [];
    const table = rows.length
      ? '<table><tr><th>' + t.html('portalShared.resource') + '</th><th>' +
        t.html('portalShared.owner') + '</th><th>' +
        t.html('portalShared.scopes') + '</th><th>' +
        t.html('portalShared.expires') + '</th></tr>' +
        rows.map(function (r: Json) {
          return '<tr><td>' + kit.esc(r.name || r.resourceId) +
            '<br><span class="sub">' + kit.esc(r.resourceServer) +
            '</span></td><td>' + kit.esc(r.owner) + '</td><td>' +
            r.scopes.map(function (s: string) {
              return '<code>' + kit.esc(s) + '</code>';
            }).join(', ') + '</td><td>' +
            kit.esc(SharedPages.readable(r.expiresAt * 1000, t)) +
            '</td></tr>';
        }).join('') + '</table>'
      : '<p class="sub">' + t.html('portalShared.withMeNone') + '</p>';
    return '<div class="card"><p class="sub">' +
      t.html('portalShared.withMeSub') + '</p>' + table + '</div>' +
      SharedPages.pager(WITH_ME, view.paging || { page: 1, pages: 1 }, t);
  }

  /**
   * The pages, for `web_portal_pages.ts`.
   */
  static readonly PAGES: PortalPage[] = [
    { path: PATH, operation: '/account-api/shared',
      render: SharedPages.render },
    { path: WITH_ME, operation: '/account-api/shared-with-me',
      render: SharedPages.withMe }
  ];
}

export = SharedPages;
