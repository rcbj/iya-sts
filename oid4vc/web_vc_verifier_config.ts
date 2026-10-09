// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_vc_verifier_config.ts
//
// ---------------------------------------------------------------------------
// PROTOCOLS → OPENID4VP VERIFIER REQUEST, DRAWN FROM ITS VIEW ALONE (#446,
// 2026-10-05).
//
// Draws the Verifier request from the answer of `GET
// /admin-api/verifier-request`: which claims the mock Verifier asks for, in
// which format, and the DCQL query it builds.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// It was drawn inside the route of `/admin/vc-verifier-config` in
// `admin-ui/admin.ts`, which still draws the page until the console's cutover
// by calling this with its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('../admin-ui/web_kit');

type Json = any;

/**
 * Draws the Verifier request from the answer of `GET
 * /admin-api/verifier-request`: which claims the mock Verifier asks for, in
 * which format, and the DCQL query it builds.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class VcVerifierConfigPage {
  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static body(ctx, json) {
    // THE WORDS ARE THE CATALOG'S (#539): `consoleVcVerifierConfig`, whose
    // English is exactly what this page drew before. Prose that names a path
    // as a link is split at the link, because a message carries no element
    // with an attribute.
    const t = ctx.t;
    const format = json.format;
    const requested = json.requested;
    const query = json.dcqlQuery;

    const inner = kit.note(t.html('consoleVcVerifierConfig.intro1') + '<a ' +
      'href="/oid4vp/verifier">/oid4vp/verifier</a>' +
      t.html('consoleVcVerifierConfig.intro2')) +

      kit.note(t.html('consoleVcVerifierConfig.catalogue1') + '<a ' +
      'href="/admin/vc">/admin/vc</a>' +
      t.html('consoleVcVerifierConfig.catalogue2')) +

      kit.warn(t.html('consoleVcVerifierConfig.asks1') +
      '<a href="/admin/oid4vp">OpenID4VP</a>' +
      t.html('consoleVcVerifierConfig.asks2') +
      '<a href="/admin/vc">/admin/vc</a>' +
      t.html('consoleVcVerifierConfig.asks3')) +

      '<h2>' + t.html('consoleVcVerifierConfig.hClaims') + '</h2>' +
      (requested.length
        ? kit.note(t.html('consoleVcVerifierConfig.askingFor',
                          { n: requested.length }) +
                    kit.codeList(requested) +
                    '.')
        : kit.warn(t.html('consoleVcVerifierConfig.noClaim'))) +
      VcVerifierConfigPage.vpClaimsSection(json, t) +

      '<h2>' + t.html('consoleVcVerifierConfig.hFormats') + '</h2>' +
      VcVerifierConfigPage.vpFormatsSection(json, t) +

      '<h2>' + t.html('consoleVcVerifierConfig.hQuery') + '</h2>' +
      kit.note(t.html('consoleVcVerifierConfig.queryNote')) +
      '<textarea readonly spellcheck="false">' +
      kit.esc(JSON.stringify(query, null, 2)) + '</textarea><h2>' +
      t.html('consoleVcVerifierConfig.hNotChange') + '</h2>' +
      kit.note(t.html('consoleVcVerifierConfig.notChange1') + '<a ' +
      'href="/admin/vc">/admin/vc</a>' +
      t.html('consoleVcVerifierConfig.notChange2'));

    return inner;
  }

  /**
   * Draws the Verifier's claim selection form, the extra claims, the note on
   * claims dropped from an ldp_vc query, and the add and defaults forms.
   *
   * A saved selection applies to the next Authorization Request, not to one
   * already in flight.
   *
   * @param json - the page's view (`vpConfigJson()`)
   * @param t - the page's translator (#539)
   * @returns the forms and notes as HTML
   */
  static vpClaimsSection(json, t) {
    const format = json.format;
    const rows = json.catalogue.map(function (
        row) {
      return VcVerifierConfigPage.vpClaimRow(row, format, t);
    }).join('');
    const omitted = format === 'ldp_vc' ? json.ldpOmitted : [];
    return '<form method="post" action="/admin/vc-verifier-config"><input ' +
      'type="hidden" name="action" value="select"><table><tr><th>' +
      t.html('consoleVcVerifierConfig.thAsk') + '</th><th>' +
      t.html('consoleVcVerifierConfig.thClaim') + '</th><th>' +
      t.html('consoleVcVerifierConfig.thLabel') + '</th><th>' +
      t.html('consoleVcVerifierConfig.thLdap') + '</th><th>' +
      t.html('consoleVcVerifierConfig.thPath', { format: format }) +
      '</th><th>' + t.html('consoleVcVerifierConfig.thLdpTerm') + '</th>' +
      '<th>' + t.html('consoleVcVerifierConfig.thIssuedNow') + '</th></tr>' +
      rows + '</table>' +
      VcVerifierConfigPage.vpExtraRows(format, json.extras, t) +
      '<div class="formrow"><button>' +
      t.html('consoleVcVerifierConfig.save') + '</button>' +
      kit.note(t.html('consoleVcVerifierConfig.nextRequest')) +
      '</div></form>' +
      // The list of names is markup, so it stays in code; the verb agrees
      // with how many there are through the message's plural.
      (omitted.length
        ? kit.note('<strong>' + kit.codeList(omitted) + '</strong> ' +
          t.html('consoleVcVerifierConfig.ldpOmitted',
                 { n: omitted.length }))
        : '') +
      '<div class="formrow"><form method="post" ' +
      'action="/admin/vc-verifier-config" class="inline"><input ' +
      'type="hidden" name="action" value="add"><label for="claim">' +
      t.html('consoleVcVerifierConfig.alsoAsk') + '</label><input ' +
      'type="text" ' +
      'id="claim" name="claim" size="24" ' +
      'placeholder="drivers_licence_number"><button ' +
      'class="secondary">' + t.html('consoleVcVerifierConfig.add') +
      '</button></form> <form method="post" ' +
      'action="/admin/vc-verifier-config" class="inline"><input ' +
      'type="hidden" name="action" value="defaults"><button ' +
      'class="secondary">' + t.html('consoleVcVerifierConfig.backToStart') +
      '</button></form></div>';
  }

  // The credential types a wallet may submit, and which one an unqualified
  // request asks for. One request is for ONE of them: a presentation cannot
  // convert between formats, so a wallet holding a jwt_vc_json credential has
  // nothing to answer a dc+sd-jwt query with — and the honest outcome is that
  // it says so rather than that this page pretends the choice does not matter.
  /**
   * Draws the form that chooses which credential format an unqualified
   * presentation request asks for, with what each format is.
   *
   * @param json - the page's view (`vpConfigJson()`)
   * @param t - the page's translator (#539)
   * @returns the form and notes as HTML
   */
  static vpFormatsSection(json, t) {
    const format = json.format;
    const rows = json.formats.map(function (item) {
      const configs = item.configurations.map(function (id) {
        return '<code>' + kit.esc(id) + '</code>';
      }).join('<br>');
      return '<tr><td><input type="radio" name="format" value="' +
             kit.esc(item.id) +
        '"' +
        (item.id === format ? ' checked' : '') + '></td>' +
        '<td><code>' + kit.esc(item.id) + '</code><br>' +
        kit.esc(item.label) + '</td>' +
        '<td><code>' + kit.esc(item.identifiedBy) + '</code><br><code>' +
        kit.esc(item.identifierText) + '</code></td>' +
        '<td>' + kit.esc(item.selectiveDisclosure) + '</td>' +
        '<td>' + kit.esc(item.holderBinding) + '</td>' +
        '<td>' + configs + '</td>' +
        '<td><a href="' + kit.esc('/oid4vp/verifier?format=' +
                                   encodeURIComponent(item.id)) +
        '">' + t.html('consoleVcVerifierConfig.presentOne') + '</a></td></tr>';
    }).join('');
    return '<form method="post" action="/admin/vc-verifier-config"><input ' +
      'type="hidden" name="action" ' +
      'value="format"><table><tr><th>' +
      t.html('consoleVcVerifierConfig.thDefault') + '</th><th>' +
      t.html('consoleVcVerifierConfig.thFormat') + '</th><th>' +
      t.html('consoleVcVerifierConfig.thIdentifiedBy') + '</th><th>' +
      t.html('consoleVcVerifierConfig.thSelective') + '</th><th>' +
      t.html('consoleVcVerifierConfig.thHolderBinding') + '</th><th>' +
      t.html('consoleVcVerifierConfig.thIssuedAs') + '</th><th></th></tr>' +
      rows + '</table>' +
      '<div class="formrow"><button>' +
      t.html('consoleVcVerifierConfig.askDefault') + '</button>' +
      kit.note(t.html('consoleVcVerifierConfig.defaultNote')) +
      '</div></form>' +
      // Each format's `what` is the view's prose, drawn as it comes.
      kit.note(json.formats.map(function (item) {
        return '<strong>' + kit.esc(item.id) + '</strong> — ' +
               kit.esc(item.what);
      }).join('<br><br>')) +
      kit.note(t.html('consoleVcVerifierConfig.notSettable'));
  }

  // One catalogue row. The DCQL path column is shown for the format the next
  // unqualified request will use, because a path is not a property of the
  // claim: the same claim is ["given_name"], ["credentialSubject","given_name"]
  // or ["credentialSubject","birthDate"] depending on what is being asked for,
  // and a column that picked one silently would be wrong two-thirds of the
  // time.
  /**
   * Draws one Verifier catalogue row: its checkbox, attributes, DCQL paths
   * for the format, ldp_vc terms and whether the issuer carries it.
   *
   * @param row - the requestable claim row
   * @param format - the credential format the DCQL paths are shown for
   * @param t - the page's translator (#539)
   * @returns the table row as HTML
   */
  static vpClaimRow(row, format, t) {
    // The catalogue row as the view carries it (#446).
    const on = row.requested;
    const paths = row.paths;
    const attributes = row.attributes.map(function (member) {
      return '<code>' + kit.esc(member.ldap) + '</code> <span ' +
        'class="state-none">(' +
             kit.esc(member.schema) + ')</span>';
    }).join('<br>');
    return '<tr><td><input type="checkbox" name="claim" value="' +
      kit.esc(row.claim) + '"' +
      (on ? ' checked' : '') + '></td>' +
      '<td><code>' + kit.esc(row.claim) + '</code>' +
      (row.nested ?
       '<br><span class="state-none">' +
       t.html('consoleVcVerifierConfig.oneObject',
              { n: row.attributes.length }) +
       '</span>' : '') + '</td>' +
      '<td>' + kit.esc(row.label) + '</td>' +
      '<td>' + attributes + '</td>' +
      '<td>' + (paths.length
        ? paths.map(function (path) {
          return '<code>' + kit.esc(JSON.stringify(path)) + '</code>';
        }).join('<br>')
        : '<span class="state-expired">' +
          t.html('consoleVcVerifierConfig.cannotAsk') + '</span>') +
          '</td><td>' +
          (row.ldpTerms.length ? kit.codeList(row.ldpTerms)
                                    : '<span class="state-none">—</span>') +
      '</td>' +
      VcVerifierConfigPage.vpIssuedCell(row.issued, t) + '</tr>';
  }

  // The claims being asked for that are NOT in the catalogue. Rendered as
  // ticked checkboxes in the same form rather than as a separate list with its
  // own Save, because a form that dropped them the moment somebody saved the
  // table above would silently undo a deliberate configuration.
  /**
   * Draws the claims asked for that are not in the catalogue, as ticked
   * checkboxes inside the selection form so a save keeps them.
   *
   * @param format - the credential format the DCQL paths are shown for
   * @param extras - the view's `extras`
   * @param t - the page's translator (#539)
   * @returns the heading, note and table as HTML, or an empty string
   */
  static vpExtraRows(format, extras, t) {
    if (!extras.length) {
      return '';
    }
    return '<h3>' + t.html('consoleVcVerifierConfig.hExtras') + '</h3>' +
      kit.note(t.html('consoleVcVerifierConfig.extrasNote')) +
      '<table><tr><th>' + t.html('consoleVcVerifierConfig.thIn') +
      '</th><th>' + t.html('consoleVcVerifierConfig.thClaim') + '</th><th>' +
      t.html('consoleVcVerifierConfig.thPath', { format: format }) +
      '</th></tr>' +
      extras.map(function (row) {
        const paths = row.paths;
        return '<tr><td><input type="checkbox" name="claim" value="' +
          kit.esc(row.claim) + '" ' +
          'checked></td><td><code>' + kit.esc(row.claim) + '</code></td>' +
          '<td>' + paths.map(function (path) {
            return '<code>' + kit.esc(JSON.stringify(path)) + '</code>';
          }).join('<br>') + '</td></tr>';
      }).join('') + '</table>';
  }

  // Whether the ISSUER currently mints the claim this Verifier is asking for.
  // The two pages are separate settings on purpose (see the header), so the
  // disagreement is a state to report rather than one to prevent — and
  // reporting it is what stops "the wallet disclosed nothing" being
  // investigated as a wallet bug.
  /**
   * Draws the "Issued now" cell: whether this service's issuer currently
   * mints the claim the Verifier asks for, wholly, partly or not at all.
   *
   * @param carried - the catalogue row's `issued` (`carriedNow()`)
   * @param t - the page's translator (#539)
   * @returns the table cell as HTML
   */
  static vpIssuedCell(carried, t) {
    if (!carried.known) {
      return '<td><span class="state-none">' +
             t.html('consoleVcVerifierConfig.notIssued') + '</span></td>';
    }
    if (!carried.carried.length) {
      return '<td><span class="state-expired">' +
             t.html('consoleVcVerifierConfig.noNotSelected') +
             '<a href="/admin/vc">/admin/vc</a></span></td>';
    }
    if (carried.missing.length) {
      return '<td><span class="state-expired">' +
             t.html('consoleVcVerifierConfig.partly') +
             kit.codeList(carried.missing) +
             t.html('consoleVcVerifierConfig.partlyNotSelected') +
             '</span></td>';
    }
    return '<td><span class="state-valid">' +
           t.html('consoleVcVerifierConfig.yes') + '</span></td>';
  }
}

export = VcVerifierConfigPage;
