// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_kerberos.ts
//
// ---------------------------------------------------------------------------
// `/portal/kerberos`, DRAWN IN THE BROWSER (#568), from `GET
// /account-api/kerberos` (`portal_kerberos.ts`): the person's principal, and
// the form that makes a keytab from their own password. The keytab an act
// just made arrives in the answer's `view.made` and is drawn here, once, as a
// `data:` download link beside its base64 — what the server-drawn page drew.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import kit = require('./web_portal_kit');

type Json = any;
type PortalPage = import('../types/account-api').PortalPage;

const PATH = kit.BASE + '/kerberos';

/**
 * `/portal/kerberos`. A static utility class.
 */
class KerberosPages {
  /**
   * The principal and its keys.
   *
   * @param state - the view
   * @param t - the translator
   * @returns the card's HTML
   */
  static stateCard(state: Json, t: Json): string {
    const heading = '<h2>' + t.html('portalKerberos.principalHeading') +
      '</h2>';
    if (!state.kdc) {
      return '<div class="card">' + heading + '<p class="sub">' +
        t.html('portalKerberos.noKdc') + '</p></div>';
    }
    if (!state.person) {
      return '<div class="card">' + heading + '<p class="sub">' +
        t.html('portalKerberos.notPrincipal') + '</p></div>';
    }
    const keys = state.keys;
    const rows = '<tr><th>' + t.html('portalKerberos.principal') +
      '</th><td><code>' + kit.esc(state.principal) + '</code></td></tr>' +
      (state.productKdc
        ? '<tr><th>' + t.html('portalKerberos.kvno') + '</th><td>' +
          (keys && keys.kvno != null
            ? kit.esc(String(keys.kvno)) + (keys.current ? ''
                : t.html('portalKerberos.kvnoNotCurrent'))
            : t.html('portalKerberos.kvnoNone')) + '</td></tr>' +
          '<tr><th>' + t.html('portalKerberos.etypes') + '</th><td>' + (keys
            ? (keys.etypes || []).map(function (one: Json) {
                return '<code>' + kit.esc(one.name) + '</code>';
              }).join(' ')
            : '—') + '</td></tr>'
        : '<tr><th>' + t.html('portalKerberos.keys') + '</th><td>' +
          t.html('portalKerberos.devKeys') + '</td></tr>') +
      (state.disabled
        ? '<tr><th>' + t.html('portalKerberos.account') + '</th><td>' +
          t.html('portalKerberos.disabled') + '</td></tr>'
        : '');
    return '<div class="card">' + heading + '<table>' + rows + '</table>' +
      '<p class="note">' + t.html('portalKerberos.keysNote') + '</p></div>';
  }

  /**
   * The form that makes a keytab.
   *
   * @param state - the view
   * @param t - the translator
   * @returns the card's HTML
   */
  static formCard(state: Json, t: Json): string {
    if (state.disabled) {
      return '<div class="card"><h2>' +
        t.html('portalKerberos.downloadHeading') + '</h2><p class="sub">' +
        t.html('portalKerberos.disabledNoKeytab') + '</p></div>';
    }
    // The command is a parameter (#539): it holds the principal, which is
    // data, and `<file>`, which the parameter's escaping writes as text.
    return '<div class="card"><h2>' +
      t.html('portalKerberos.downloadHeading') + '</h2>' +
      '<p class="sub">' + t.html('portalKerberos.downloadSub',
        { command: 'kinit -k -t <file> ' + state.principal }) + '</p>' +
      '<form method="post" action="' + PATH + '">' +
      '<input type="hidden" name="action" value="keytab">' +
      '<p><label>' + t.html('portalKerberos.currentPassword') +
      ' <input type="password" ' +
      'name="current" autocomplete="current-password" required></label></p>' +
      '<p><button type="submit">' + t.html('portalKerberos.make') +
      '</button></p></form>' +
      '<p class="note">' + t.html('portalKerberos.downloadNote') + '</p>' +
      '</div>';
  }

  /**
   * The keytab just made, shown once.
   *
   * @param made - `view.made`
   * @param t - the translator
   * @returns the card's HTML
   */
  static keytabCard(made: Json, t: Json): string {
    const file = String(made.keytabFilename);
    // A warning, not a refusal, though it wears the error box's colour, so
    // it is the catalog's (#539). The commands are parameters.
    return '<div class="card"><h2>' + t.html('portalKerberos.keytabHeading') +
      '</h2><div class="err">' + t.html('portalKerberos.saveNow') + '</div>' +
      '<table><tr><th>' + t.html('portalKerberos.principal') +
      '</th><td><code>' + kit.esc(made.principal) +
      '</code></td></tr><tr><th>' + t.html('portalKerberos.kvno') +
      '</th><td>' + kit.esc(String(made.kvno)) + '</td></tr>' +
      '<tr><th>' + t.html('portalKerberos.etypes') + '</th><td>' +
      (made.etypes || []).map(function (etype: unknown) {
        return '<code>' + kit.esc(String(etype)) + '</code>';
      }).join(' ') + '</td></tr></table>' +
      (made.source === 'development'
        ? '<p class="note">' + t.html('portalKerberos.devKeytab') + '</p>'
        : '') +
      '<p><a class="btn" download="' + kit.esc(made.keytabFilename) +
      '" href="data:application/octet-stream;base64,' + kit.esc(made.keytab) +
      '">' + t.html('portalKerberos.save', { file: file }) + '</a></p>' +
      '<p class="note">' + t.html('portalKerberos.pasteNote', {
        decode: 'base64 -d > ' + file,
        list: 'klist -k -e ' + file,
        use: 'kinit -k -t ' + file + ' ' + made.principal }) + '</p>' +
      '<textarea readonly rows="6" name="keytab-base64">' +
      kit.esc(made.keytab) + '</textarea></div>';
  }

  /**
   * The page's body.
   *
   * @param view - `GET /account-api/kerberos`' answer, or an act's `view`
   * @param ctx - the render context
   * @returns the HTML
   */
  static render(view: Json, ctx: Json): string {
    const t = ctx.t;
    const cards: string[] = [];
    if (view.made) {
      cards.push(KerberosPages.keytabCard(view.made, t));
    }
    cards.push(KerberosPages.stateCard(view, t));
    if (view.kdc && view.person) {
      cards.push(KerberosPages.formCard(view, t));
    }
    return cards.join('');
  }

  /**
   * The pages, for `web_portal_pages.ts`.
   */
  static readonly PAGES: PortalPage[] = [
    { path: PATH, operation: '/account-api/kerberos',
      render: KerberosPages.render }
  ];
}

export = KerberosPages;
