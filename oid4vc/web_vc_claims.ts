// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_vc_claims.ts
//
// ---------------------------------------------------------------------------
// CREDENTIAL CLAIMS, DRAWN FROM ITS VIEW ALONE (#446, 2026-10-05).
//
// Draws `/admin/vc` from the answer of `GET /admin-api/vc`: which directory
// attributes a Verifiable Credential carries, what they would say about one
// person, and the forms that change the selection.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// It was drawn inside the route of `/admin/vc` in `admin-ui/admin.ts`, which
// still draws the page until the console's cutover by calling this with its
// view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('../admin-ui/web_kit');

type Json = any;

/**
 * Draws `/admin/vc` from the answer of `GET /admin-api/vc`: which directory
 * attributes a Verifiable Credential carries, what they would say about one
 * person, and the forms that change the selection.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class VcClaimsPage {
  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static body(ctx, json) {
    // THE WORDS ARE THE CATALOG'S (#539): `consoleVcClaims`, whose English is
    // exactly what this page drew before, so English output is unchanged.
    const t = ctx.t;

    const inner = kit.note(t.html('consoleVcClaims.intro')) +

      kit.note(t.html('consoleVcClaims.ldapTypes')) +

      kit.warn(t.html('consoleVcClaims.garbage')) +

      '<h2>' + t.html('consoleVcClaims.hAttributes') + '</h2>' +
      VcClaimsPage.vcAttributeTable(json, t) +

      '<h2>' + t.html('consoleVcClaims.hPreview') + '</h2>' +
      VcClaimsPage.vcPreviewSection(json, t) +

      '<h2>' + t.html('consoleVcClaims.hSources') + '</h2>' +
      // Split at the link: a message carries no element with an attribute.
      kit.note(t.html('consoleVcClaims.sources1') +
      '<a href="/admin/claims">' + t.html('consoleVcClaims.customClaims') +
      '</a>' + t.html('consoleVcClaims.sources2')) +
      kit.note(t.html('consoleVcClaims.neverOverwrites')) +

      '<h2>' + t.html('consoleVcClaims.hNotDo') + '</h2>' +
      kit.note(t.html('consoleVcClaims.notDo1') +
      '<a href="/admin/users">' + t.html('consoleVcClaims.users') + '</a>' +
      t.html('consoleVcClaims.notDo2'));

    return inner;
  }

  /**
   * Draws the /admin/vc selection form: a checkbox per credential attribute
   * with its value for the preview user, and the defaults and populate
   * forms.
   *
   * Saving the selection also fills in missing attributes on every person
   * under ou=users.
   *
   * @param previewUser - the username being previewed
   * @param t - the page's translator (#539)
   * @returns the forms as HTML
   */
  static vcAttributeTable(json, t) {
    const previewUser = json.preview.user;

    const rows = json.attributes.map(function (row) {
      const on = row.selected;
      return '<tr><td><input type="checkbox" name="attribute" value="' +
        kit.esc(row.ldap) + '"' +
        (on ? ' checked' : '') + '></td>' +
        '<td><code>' + kit.esc(row.ldap) + '</code></td>' +
        '<td>' + kit.esc(row.schema) + '</td>' +
        '<td><code>' + kit.esc(row.claim) + '</code></td>' +
        '<td>' + (row.ldpTerm ? '<code>' + kit.esc(row.ldpTerm) + '</code>' :
                  '<span ' +
            'class="state-none">—</span>') +
        '</td>' + VcClaimsPage.vcExampleCell(row.example) + '</tr>';
    }).join('');

    return '<form method="post" action="/admin/vc"><input type="hidden" ' +
      'name="action" value="select"><table><tr><th>' +
      t.html('consoleVcClaims.thIn') + '</th><th>' +
      t.html('consoleVcClaims.thLdap') + '</th><th>' +
      t.html('consoleVcClaims.thDefinedBy') + '</th><th>' +
      t.html('consoleVcClaims.thClaim') + '</th><th>' +
      t.html('consoleVcClaims.thLdpTerm') + '</th><th>' +
      // t.text and kit.esc, not t.html: a username is data, and kit.esc is
      // what drew it before (an apostrophe as &apos;, not &#39;).
      kit.esc(t.text('consoleVcClaims.thInCredential',
                     { user: previewUser })) +
      '</th><th>' + t.html('consoleVcClaims.thSource') + '</th></tr>' +
      rows + '</table><div class="formrow"><button>' +
      t.html('consoleVcClaims.save') + '</button><span class="note">' +
      t.html('consoleVcClaims.saveNote') + '</span></div></form><div ' +
      'class="formrow"><form method="post" action="/admin/vc" ' +
      'class="inline"><input type="hidden" name="action" ' +
      'value="defaults"><button class="secondary">' +
      t.html('consoleVcClaims.restore') + '</button></form> <form ' +
      'method="post" action="/admin/vc" ' +
      'class="inline"><input type="hidden" name="action" ' +
      'value="populate"><button class="secondary">' +
      t.html('consoleVcClaims.populate') + '</button></form></div>';
  }

  // What a credential for this person would actually assert, claim by claim. It
  // is built by the same function the issuer calls, not by a second walk of the
  // catalogue — a preview that agreed with the page and disagreed with the
  // credential would be worse than no preview.
  /**
   * Draws what a credential for the preview user would assert, claim by
   * claim, built by the function the issuer calls.
   *
   * @param previewUser - the username being previewed
   * @param t - the page's translator (#539)
   * @returns the preview form, notes and table as HTML
   */
  static vcPreviewSection(json, t) {
    const previewUser = json.preview.user;
    const built = json.preview.claims;
    const rows = built.report.map(function (item) {
      return '<tr><td><code>' + kit.esc(item.claim) + '</code></td>' +
        '<td><code>' + kit.esc(item.value) + '</code></td>' +
        '<td>' + kit.esc(item.source) + '</td>' +
        '<td>' + (item.ldpTerm ? t.html('consoleVcClaims.yes') :
                  '<span class="state-none">' +
                  t.html('consoleVcClaims.no') + '</span>') +
        '</td></tr>';
    }).join('');
    const omitted = json.ldpOmitted;

    return '<form method="get" action="/admin/vc"><div class="formrow">' +
      '<label for="user">' + t.html('consoleVcClaims.previewFor') +
      '</label>' +
      '<input type="text" id="user" name="user" size="20" value="' +
      kit.esc(previewUser) + '"><button ' +
      'class="secondary">' + t.html('consoleVcClaims.show') +
      '</button></div></form>' +
      kit.note((built.entryFound
        ? t.html('consoleVcClaims.entryFound')
        : t.html('consoleVcClaims.entryMissing'))) +
      '<table><tr><th>' + t.html('consoleVcClaims.thClaim') + '</th><th>' +
      t.html('consoleVcClaims.thValue') + '</th><th>' +
      t.html('consoleVcClaims.thFrom') + '</th><th>' +
      t.html('consoleVcClaims.thInLdp') + '</th></tr>' +
      (rows ||
       '<tr><td colspan="4">' + t.html('consoleVcClaims.noneSelected') +
       '</td></tr>') + '</table>' +
      // The list of names is markup, so it stays in code; the verb agrees
      // with how many there are through the message's plural.
      (omitted.length
        ? kit.note('<strong>' + kit.codeList(omitted) + '</strong> ' +
          t.html('consoleVcClaims.ldpOmitted', { n: omitted.length }))
        : '');
  }

  // The one preview row's two cells, from `admin_views.vcExampleOf()`'s
  // answer (#446).
  /**
   * Draws the value and source cells of one credential attribute row for
   * the person being previewed.
   *
   * @param example - `{ value, source }`, from the page's answer
   * @returns two table cells as HTML
   */
  static vcExampleCell(example) {
    const one = example || { value: null, source: '' };
    return '<td>' + (one.value === null
                       ? '—'
                       : '<code>' + kit.esc(one.value) + '</code>') +
           '</td><td>' + kit.esc(one.source) + '</td>';
  }
}

export = VcClaimsPage;
