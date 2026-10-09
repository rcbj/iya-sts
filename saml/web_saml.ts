// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_saml.ts
//
// ---------------------------------------------------------------------------
// PROTOCOLS → SAML 2.0 AND SAML 1.1, DRAWN FROM THEIR VIEWS ALONE (#446,
// 2026-10-05).
//
// Draws the two SAML identity providers' console pages, `/admin/saml2` and
// `/admin/saml11`, and their service-provider drill-downs, from the answers of
// `GET /admin-api/saml2` and `GET /admin-api/saml11`.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// It was drawn inside the route of `method:saml2ListPage` in
// `admin-ui/admin.ts`, which still draws the page until the console's cutover
// by calling this with its view passed through JSON.
// ---------------------------------------------------------------------------
//
// THE WORDS ARE THE CATALOG'S (#539, 2026-10-09): `consoleSaml`, whose
// English is exactly what these pages drew before, byte for byte. A sentence
// that held a link is split around it, the `<a href>` staying here and the
// words on either side in the catalog. What the VIEW says — a verification
// outcome, a refusal's reason, a metadata state's why — is drawn as it comes,
// in English, as every error is.
// ---------------------------------------------------------------------------

import kit = require('../admin-ui/web_kit');
import SettingsForms = require('../admin-ui/web_settings');

type Json = any;

/**
 * Draws the two SAML identity providers' console pages, `/admin/saml2` and
 * `/admin/saml11`, and their service-provider drill-downs, from the answers of
 * `GET /admin-api/saml2` and `GET /admin-api/saml11`.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class SamlPage {
  // The two SAML 1.1 browser profiles' URIs, from the SAML 1.1 bindings and
  // profiles specification, written out because this module may not
  // require `saml/saml11_sso.ts`, whose PROFILE_POST and PROFILE_ARTIFACT
  // they are.
  static readonly SAML11_PROFILE_POST =
    'urn:oasis:names:tc:SAML:1.0:profiles:browser-post';

  static readonly SAML11_PROFILE_ARTIFACT =
    'urn:oasis:names:tc:SAML:1.0:profiles:artifact-01';

  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static saml2Body(ctx, json) {
    const t = ctx.t;
    const needle = String(ctx.query.q || '').trim();
    const paging = json.paging;
    const filterParams = { q: String(ctx.query.q || ''),
                           per: ctx.query.per ? paging.perPage : '' };
    const nav = kit.pageNavPair('/admin/saml2', filterParams, paging);
    // The refused-lookup list's own pager (#112), carrying every other
    // parameter so the service-provider table stays where it was.
    const refusedNav = kit.pageNavPair('/admin/saml2',
                                        kit.pageParamsOf(ctx.query),
                                        json.mdqRefusedPaging);
    const listView = kit.listViewOf('/admin/saml2', ctx.query);
    const refusedRows = json.mdqRefused.map(function (row) {
      return '<tr><td><code>' + kit.esc(row.entityId) + '</code></td><td>' +
             kit.esc(row.why) + '</td><td>' + kit.esc(String(row.count)) +
             '</td><td>' + kit.esc(row.firstAt.replace('T', ' ')
                                      .slice(0, 19)) +
             '</td><td>' + kit.esc(row.lastAt.replace('T', ' ')
                                      .slice(0, 19)) +
             '</td></tr>';
    }).join('');
    const rows = json.serviceProviders.map(function (row) {
      const facts = row;
      const href = '/admin/saml2' + kit.queryWith(listView,
        { sp: row.identifier });
      const acs = row.assertionConsumerServices;
      const slo = row.singleLogoutServices;
      return '<tr><td><a href="' + kit.esc(href) + '"><code>' +
             kit.esc(row.identifier) +
        '</code></a><div ' +
        'class="sub">' + t.html('consoleSaml.list.itsIdp') +
        '<code>' + kit.esc(facts.idpEntityId) + '</code></div></td><td><a ' +
        'href="' + kit.esc(facts.metadataUrl) + '">' +
        t.html('consoleSaml.list.metadata') + '</a></td>' +
        '<td>' +
        (acs.length ? kit.codeList(acs) : '<span ' +
            'class="sub">' + t.html('consoleSaml.list.noneSeen') +
            '</span>') +
        '</td>' +
        '<td>' + (slo.length ? kit.codeList(slo)
                      : '<span class="sub">' +
                        t.html('consoleSaml.saml2.sloGuessed') + '</span>') +
        '</td><td>' +
        kit.esc(row.lastRequestVerification || '—') +
        '</td><td>' + kit.esc(String(row.authentications)) + '</td><td>' +
        kit.esc(row.lastSeen ? row.lastSeen.replace('T', ' ').slice(0, 19) :
                 '') +
        '</td></tr>';
    }).join('');

    const inner = '<h1>' + t.html('consoleSaml.saml2.title') +
      '</h1><p class="sub">' + t.html('consoleSaml.saml2.intro') + '</p>' +
      kit.note(t.html('consoleSaml.saml2.perSp') + '<a ' +
      'href="/saml2/metadata">/saml2/metadata</a>' +
      t.html('consoleSaml.common.unscopedAfter')) +
      '<p class="sub"><a href="/saml2">' +
      t.html('consoleSaml.common.linkProfile') + '</a> &middot; <a ' +
      'href="/saml2/sp">' + t.html('consoleSaml.saml2.linkMockSp') +
      '</a> &middot; <a ' +
      'href="/admin/saml-attributes">' +
      t.html('consoleSaml.common.linkAttributes') + '</a> ' +
      '&middot; <a ' +
      'href="/admin/applications?kind=' + json.kind + '">' +
      t.html('consoleSaml.common.linkApplications') +
      '</a></p><form method="get" ' +
      'action="/admin/saml2"><div class="formrow"><label ' +
      'for="q">' + t.html('consoleSaml.common.search') +
      '</label><input type="text" id="q" name="q" ' +
      'value="' + kit.esc(String(ctx.query.q || '')) + '" ' +
      'placeholder="' + kit.esc(t.text('consoleSaml.saml2.searchPlaceholder')) +
      '">' +
      (ctx.query.per ?
       '<input type="hidden" name="per" value="' + kit.esc(paging.perPage) +
       '">' :
       '') +
      '<button class="secondary">' + t.html('consoleSaml.common.filter') +
      '</button>' +
      (String(ctx.query.q || '') ? ' <a href="/admin/saml2">' +
        t.html('consoleSaml.common.clear') + '</a>' : '') +
      '</div></form>' +
      nav.head +
      (rows
        ? '<table><thead><tr><th>' + t.html('consoleSaml.saml2.thSp') +
          '</th><th>' + t.html('consoleSaml.common.thMetadata') +
          '</th><th>' + t.html('consoleSaml.saml2.thAcs') +
          '</th><th>' + t.html('consoleSaml.saml2.thSlo') +
          '</th><th>' + t.html('consoleSaml.saml2.thLastSignature') +
          '</th><th>' + t.html('consoleSaml.saml2.thResponses') + '</th>' +
          '<th>' + t.html('consoleSaml.common.thLastSeen') +
          '</th></tr></thead><tbody>' + rows + '</tbody></table>' + nav.foot
        : kit.note(t.html('consoleSaml.saml2.noneYet',
          { filtered: needle ? 'yes' : 'no' }) + ' ' +
          t.html('consoleSaml.common.startOne') + '<a ' +
          'href="/saml2/sp">' + t.html('consoleSaml.saml2.linkMockSp') +
          '</a>' + t.html('consoleSaml.saml2.orRegister'))) +
      '<h2>' + t.html('consoleSaml.saml2.hRegister') +
      '</h2><p class="sub">' + t.html('consoleSaml.saml2.registerIntro') +
      '</p><form ' +
      'method="post" action="/admin/saml2"><div class="formrow"><input ' +
      'type="hidden" name="action" value="register"><label ' +
      'for="new_sp">entityID</label><input type="text" id="new_sp" name="sp" ' +
      'placeholder="https://sp.example.com/saml"><button>' +
      t.html('consoleSaml.common.register') + '</button>' +
      '<span class="note">' + t.html('consoleSaml.saml2.registerNote') +
      '</span></div></form>' +
      '<h2>' + t.html('consoleSaml.saml2.hMdqImport') + '</h2><p ' +
      'class="sub">' + t.html('consoleSaml.saml2.mdqIntro') +
      '</p><form method="post" ' +
      'action="/admin/saml2"><div class="formrow"><input type="hidden" ' +
      'name="action" value="mdq-import"><label for="mdq_sp">entityID</label>' +
      '<input type="text" id="mdq_sp" name="sp" ' +
      'placeholder="https://sp.example.com/saml"><button>' +
      t.html('consoleSaml.saml2.import') + '</button>' +
      '</div></form>' +
      '<h2>' + t.html('consoleSaml.saml2.hRefused') + '</h2><p ' +
      'class="sub">' + t.html('consoleSaml.saml2.refusedIntro') + '</p>' +
      (refusedRows
        ? refusedNav.head + '<table><thead><tr><th>entityID</th><th>' +
          t.html('consoleSaml.saml2.thWhy') +
          '</th><th>' + t.html('consoleSaml.saml2.thTimes') + '</th><th>' +
          t.html('consoleSaml.saml2.thFirst') + '</th><th>' +
          t.html('consoleSaml.saml2.thLast') + '</th></tr></thead>' +
          '<tbody>' + refusedRows + '</tbody></table>' + refusedNav.foot
        : '<p class="sub">' + t.html('consoleSaml.saml2.none') + '</p>') +
      SettingsForms.forms(json.settings, '/admin/saml2') +
      kit.note(t.html('consoleSaml.saml2.shape') + '<a ' +
      'href="/admin/saml-attributes">' +
      t.html('consoleSaml.common.linkCustomAttributes') + '</a>' +
      t.html('consoleSaml.saml2.shapeAfter')) +
      kit.perPageForm('/admin/saml2', 'q', String(ctx.query.q || ''),
                       paging.perPage,
                       '', {});

    return inner;
  }

  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static saml2Detail(ctx, json) {
    const t = ctx.t;
    const facts = json;
    const found = json.found;
    const sp = json.identifier;
    const acs = json.assertionConsumerServices;
    const slo = json.singleLogoutServices;
    const verification = json.lastRequestVerification;
    const required = json.signedRequestsRequired;
    const listView = kit.listViewOf('/admin/saml2', ctx.query);
    const carryBack = '<input type="hidden" name="back" value="' +
      kit.esc(kit.queryWith(listView, {})) + '">';

    // The first and last cells are TEXT, escaped below, so they are the
    // catalog's plain-text form.
    const endpointRows = [
      [t.text('consoleSaml.detail2.rowIdp'), facts.idpEntityId,
       t.text('consoleSaml.detail2.rowIdpWhy')],
      [t.text('consoleSaml.common.rowMetadata'), facts.metadataUrl,
       t.text('consoleSaml.detail2.rowMetadataWhy')],
      [t.text('consoleSaml.detail2.rowSso'), facts.ssoUrl,
       t.text('consoleSaml.detail2.rowSsoWhy')],
      [t.text('consoleSaml.detail2.rowSlo'), facts.sloUrl,
       t.text('consoleSaml.detail2.rowSloWhy')],
      [t.text('consoleSaml.detail2.rowArs'), facts.arsUrl,
       t.text('consoleSaml.detail2.rowArsWhy')]
    ].map(function (r) {
      return '<tr><td>' + kit.esc(r[0]) + '</td><td><code>' + kit.esc(r[1]) +
        '</code></td><td ' +
        'class="sub">' + kit.esc(r[2]) + '</td></tr>';
    }).join('');

    const inner = '<h1><code>' + kit.esc(sp) + '</code></h1>' +
      '<p class="sub">' + t.html('consoleSaml.detail2.entryIs') +
      (found ?
       '<a href="/admin/applications?application=' +
             encodeURIComponent(sp) +
             '">' + t.html('consoleSaml.common.inRegistry') + '</a>'
           : t.html('consoleSaml.common.notInRegistry')) + '.</p><h2>' +
      t.html('consoleSaml.common.hEndpoints') + '</h2>' +
      '<table><thead><tr><th>' + t.html('consoleSaml.common.thWhat') +
      '</th><th>' + t.html('consoleSaml.common.thWhere') +
      '</th><th></th></tr></thead>' +
      '<tbody>' +
      endpointRows + '</tbody></table>' +
      '<p class="sub">' + t.html('consoleSaml.common.slugIs') + '<code>' +
      kit.esc(facts.slug) +
      '</code>' +
      (facts.slug === sp ? '' :
        t.html('consoleSaml.detail2.slugDigest')) + '.</p><h2>' +
      t.html('consoleSaml.common.hRecorded') + '</h2><table><tbody><tr><td>' +
      t.html('consoleSaml.detail2.acsSeen') + '</td><td>' +
        (acs.length ? kit.codeList(acs) : '<span class="sub">' +
          t.html('consoleSaml.common.none') + '</span>') +
      '</td></tr><tr><td>' + t.html('consoleSaml.detail2.nameIdFormats') +
      '</td><td>' +
        (json.nameIdFormats.length
          ? kit.codeList(json.nameIdFormats)
          : '<span class="sub">' +
            t.html('consoleSaml.detail2.nameIdFormatsNone') + '</span>') +
        '</td></tr>' +
      '<tr><td>' + t.html('consoleSaml.detail2.responseBindings') +
      '</td><td>' +
        (json.responseBindings.length
          ? kit.codeList(json.responseBindings) : '<span ' +
              'class="sub">' + t.html('consoleSaml.common.none') +
              '</span>') +
        '</td></tr>' +
      '<tr><td>' + t.html('consoleSaml.detail2.lastSignature') + '</td><td>' +
        (verification.outcome
          ? '<strong>' + kit.esc(verification.outcome) + '</strong>' +
            (verification.binding
              ? ' <span class="sub">(' + kit.esc(verification.binding) +
                t.html('consoleSaml.detail2.bindingComma') +
                kit.esc(verification.signatureMethod ||
                        t.text('consoleSaml.detail2.noSigAlg')) +
                (verification.weak ? t.html('consoleSaml.detail2.weak') :
                 '') + ')</span>'
              : '')
          : '<span class="sub">' + t.html('consoleSaml.common.unknown') +
            '</span>') +
        ' <span class="sub">' + t.html('consoleSaml.detail2.verifiedNote') +
        '</span></td></tr>' +
        '<tr><td>' + t.html('consoleSaml.detail2.signedRequired') +
        '</td><td>' +
        (required.required
          ? '<strong>' + t.html('consoleSaml.common.yes') + '</strong>'
          : t.html('consoleSaml.common.no')) +
        ' <span class="sub">&mdash; ' + kit.esc(required.why) +
        t.html('consoleSaml.detail2.signedRequiredWhy') +
        '</span></td></tr><tr><td>' +
        t.html('consoleSaml.detail2.responsesIssued') +
        '</td><td>' + kit.esc(String(json.authentications || 0)) +
        '</td></tr>' +
      '</tbody></table>' +
      '<h2>' + t.html('consoleSaml.detail2.hLogoutResponse') + '</h2>' +
      kit.note(t.html('consoleSaml.detail2.logoutNote')) +
      (slo.length
        ? '<table><thead><tr><th>' + t.html('consoleSaml.detail2.thDeclared') +
          '</th><th></th></tr></thead><tbody>' +
          slo.map(function (one) {
            return '<tr><td><code>' + kit.esc(one) + '</code></td><td>' +
              '<form method="post" action="/admin/saml2">' + carryBack +
              '<input type="hidden" name="action" ' +
              'value="remove-logout-service"><input type="hidden" name="sp" ' +
              'value="' + kit.esc(sp) + '">' +
              '<input type="hidden" name="value" value="' + kit.esc(one) +
              '"><button class="secondary">' +
              t.html('consoleSaml.common.remove') +
              '</button></form></td></tr>';
          }).join('') + '</tbody></table>'
        : kit.note(t.html('consoleSaml.detail2.nothingDeclared') +
          (acs.length ?
           t.html('consoleSaml.detail2.wouldGuess') + '<code>' +
           kit.esc(acs[acs.length - 1]) +
           '</code>' :
           '') +
          '.')) +
      '<form method="post" action="/admin/saml2">' + carryBack + '<div ' +
      'class="formrow"><input type="hidden" name="action" ' +
      'value="set-logout-service"><input type="hidden" name="sp" ' +
      'value="' + kit.esc(sp) + '"><label ' +
      'for="slo">' + t.html('consoleSaml.detail2.addOne') +
      '</label><input type="text" id="slo" name="value" ' +
      'placeholder="https://sp.example.com/saml/slo"><button>' +
      t.html('consoleSaml.detail2.add') + '</button>' +
      '<span ' +
      'class="note">' + t.html('consoleSaml.detail2.addNote') +
      '</span></div></form>' +
      SamlPage.saml2SigningCertificatesSection(t, sp, json, carryBack) +
      SamlPage.saml2MetadataSection(t, sp, json, carryBack) +
      '<p class="sub"><a ' +
      'href="' + kit.esc(facts.metadataUrl) + '">' +
      t.html('consoleSaml.detail2.itsMetadata') + '</a> &middot; <a ' +
      'href="/saml2">' + t.html('consoleSaml.detail2.theProfile') + '</a>' +
      (found ? ' &middot; <a href="/admin/applications?application=' +
             encodeURIComponent(sp) + '">' +
             t.html('consoleSaml.detail2.itsRegistryEntry') + '</a>' : '') +
      '</p>';

    return inner;
  }

  // ---------------------------------------------------------------------------
  // THE SIGNING CERTIFICATES (#37): what this service provider's signatures
  // are verified against, and the one a request carried that nobody has
  // vouched for. Each registered value has a Remove; the observed one has
  // Confirm and Discard. Values on ONE entry, bounded by what a person or a
  // metadata document registered, so the list is drawn whole — the same as
  // the endpoint lists above it.
  // ---------------------------------------------------------------------------
  /**
   * Draws the certificates a service provider's signatures are verified
   * against, each with Remove, and an observed one with Confirm and
   * Discard.
   *
   * @param t - the page's translator (#539), handed down by `saml2Detail()`
   * @param identifier - the service provider's identifier
   * @param json - the detail page's JSON view
   * @param carryBack - the hidden `back` field every form carries
   * @returns the section as HTML
   */
  static saml2SigningCertificatesSection(t, identifier, json, carryBack) {
    const hidden = function (action) {
      return '<form method="post" action="/admin/saml2">' + carryBack +
        '<input type="hidden" name="action" value="' + action + '">' +
        '<input type="hidden" name="sp" value="' + kit.esc(identifier) +
        '">';
    };
    const certs = json.signingCertificates || [];
    const shown = function (der) {
      return '<pre>' + kit.esc(String(der).replace(/(.{72})/g, '$1\n')) +
             '</pre>';
    };
    const html = '<h2>' + t.html('consoleSaml.certs.title') + '</h2>' +
      kit.note(t.html('consoleSaml.certs.intro')) +
      (certs.length
        ? '<table><thead><tr><th>' + t.html('consoleSaml.certs.thRegistered') +
          '</th><th></th></tr></thead>' +
          '<tbody>' + certs.map(function (der) {
            return '<tr><td>' + shown(der) + '</td><td>' +
              hidden('remove-signing-certificate') +
              '<input type="hidden" name="value" value="' + kit.esc(der) +
              '"><button class="secondary">' +
              t.html('consoleSaml.common.remove') +
              '</button></form></td></tr>';
          }).join('') + '</tbody></table>'
        : kit.note(t.html('consoleSaml.certs.noneRegistered'))) +
      hidden('set-signing-certificate') + '<div class="formrow"><label ' +
      'for="cert">' + t.html('consoleSaml.certs.replace') +
      '</label><input type="text" id="cert" ' +
      'name="value" placeholder="' +
      kit.esc(t.text('consoleSaml.common.derOrPem')) + '"><button>' +
      t.html('consoleSaml.common.set') + '</button>' +
      '<span class="note">' + t.html('consoleSaml.certs.replaceNote') +
      '</span></div></form>' +
      '<h3>' + t.html('consoleSaml.certs.hObserved') + '</h3>' +
      (json.observedSigningCertificate
        ? kit.note(t.html('consoleSaml.certs.observed')) +
          shown(json.observedSigningCertificate) +
          '<div class="formrow">' + hidden('confirm-signing-certificate') +
          '<button>' + t.html('consoleSaml.certs.confirm') +
          '</button></form> ' +
          hidden('discard-signing-certificate') +
          '<button class="secondary">' + t.html('consoleSaml.certs.discard') +
          '</button></form></div>'
        : kit.note(t.html('consoleSaml.certs.noneObserved')));
    return html;
  }

  // ---------------------------------------------------------------------------
  // THE CONSUMED METADATA (#37): what the last refresh or upload registered,
  // and the upload form. The refresh button is on the application's own page,
  // beside the URL it dials, and this links there rather than drawing a second
  // copy of it.
  // ---------------------------------------------------------------------------
  /**
   * Draws what a service provider's consumed metadata registered, and the
   * form to upload a metadata document.
   *
   * @param t - the page's translator (#539), handed down by `saml2Detail()`
   * @param identifier - the service provider's identifier
   * @param json - the detail page's JSON view
   * @param carryBack - the hidden `back` field every form carries
   * @returns the section as HTML
   */
  static saml2MetadataSection(t, identifier, json, carryBack) {
    const meta = json.metadata || {};
    // `true` and `false` are the metadata document's own attribute values,
    // and stay as the document spells them in every language.
    const yes = function (flag) {
      return flag ? 'true' : 'false';
    };
    const acsRows = (meta.assertionConsumerServices || []).map(function (e) {
      return '<tr><td>' + kit.esc(e.index || '—') + '</td><td>' +
        (e.isDefault === true ? t.html('consoleSaml.common.yes') :
         (e.isDefault === false ? t.html('consoleSaml.common.no') : '—')) +
        '</td><td><code>' + kit.esc(e.binding) + '</code></td><td><code>' +
        kit.esc(e.location) + '</code></td></tr>';
    }).join('');
    const sloRows = (meta.singleLogoutServices || []).map(function (e) {
      return '<tr><td><code>' + kit.esc(e.binding) + '</code></td><td><code>' +
        kit.esc(e.location) + '</code></td><td>' +
        (e.responseLocation ? '<code>' + kit.esc(e.responseLocation) +
                              '</code>' : '—') + '</td></tr>';
    }).join('');
    const facts = meta.consumed
      ? '<table><tbody>' +
        '<tr><td>' + t.html('consoleSaml.meta.consumed') + '</td><td>' +
          kit.esc(meta.consumedAt) + ' (' +
          kit.esc(meta.how) + ')' +
          (meta.url ? t.html('consoleSaml.meta.from') + '<code>' +
                      kit.esc(meta.url) + '</code>' : '') +
          '</td></tr>' +
        '<tr><td>' + t.html('consoleSaml.meta.ownSignature') + '</td><td>' +
          kit.esc(meta.signature || t.text('consoleSaml.common.unknown')) +
          '</td></tr>' +
        '<tr><td>' + t.html('consoleSaml.meta.state') + '</td><td><strong>' +
          kit.esc(String(meta.state || '').toUpperCase()) + '</strong>' +
          (meta.stateWhy ? ' <span class="sub">— ' + kit.esc(meta.stateWhy) +
                           '</span>' : '') +
          (meta.state === 'expired'
            ? ' <span class="sub">' + t.html('consoleSaml.meta.expired') +
              '</span>' : '') +
          '</td></tr>' +
        '<tr><td>' + t.html('consoleSaml.meta.validUntil') + '</td><td>' +
          (meta.validUntil
            ? kit.esc(meta.validUntil) + ' <span class="sub">' +
              t.html('consoleSaml.meta.validUntilEnforced') + '</span>'
            : '<span class="sub">' + t.html('consoleSaml.meta.noneStated') +
              '</span>') + '</td></tr>' +
        '<tr><td>' + t.html('consoleSaml.meta.cacheDuration') + '</td><td>' +
          (meta.cacheDuration ? kit.esc(meta.cacheDuration) : '<span ' +
           'class="sub">' + t.html('consoleSaml.meta.noneStated') +
           '</span>') +
          (meta.staleAt ? ' <span class="sub">' +
                          t.html('consoleSaml.meta.staleFrom') +
                          kit.esc(meta.staleAt) + '</span>' : '') +
          '</td></tr>' +
        '<tr><td>' + t.html('consoleSaml.meta.backgroundRefresh') +
        '</td><td>' +
          (!meta.refreshable
            ? '<span class="sub">' + t.html('consoleSaml.meta.notRefreshable') +
              '</span>'
            : (meta.refresherEnabled ? t.html('consoleSaml.meta.on')
                                     : t.html('consoleSaml.meta.off')) +
              (meta.refresh
                ? t.html('consoleSaml.meta.lastAttempt') +
                  kit.esc(meta.refresh.lastAttemptAt) +
                  (meta.refresh.ok ? t.html('consoleSaml.meta.succeeded')
                    : t.html('consoleSaml.meta.failingSince') +
                      kit.esc(meta.refresh.failingSince) + ' (' +
                      kit.esc(String(meta.refresh.failures)) +
                      t.html('consoleSaml.meta.attempts') +
                      kit.esc(meta.refresh.why))
                : ' <span class="sub">' +
                  t.html('consoleSaml.meta.notAttempted') + '</span>')) +
          '</td></tr>' +
        '<tr><td>AuthnRequestsSigned</td><td>' +
          yes(meta.authnRequestsSigned) + '</td></tr>' +
        '<tr><td>WantAssertionsSigned</td><td>' +
          yes(meta.wantAssertionsSigned) + '</td></tr>' +
        '<tr><td>' + t.html('consoleSaml.meta.encryptedWanted') +
        '</td><td>' +
          yes(meta.wantAssertionsEncrypted) + ' <span class="sub">' +
          t.html('consoleSaml.meta.encryptedWantedWhy') + '</span></td></tr>' +
        '<tr><td>NameIDFormats</td><td>' +
          ((meta.nameIdFormats || []).length
            ? kit.codeList(meta.nameIdFormats) + ' <span class="sub">' +
              t.html('consoleSaml.meta.nameIdPolicy') + '</span>'
            : '<span class="sub">' + t.html('consoleSaml.meta.nameIdAny') +
              '</span>') + '</td></tr>' +
        '<tr><td>' + t.html('consoleSaml.meta.encryptionCertificate') +
        '</td><td>' +
          (meta.encryptionCertificate ? t.html('consoleSaml.meta.onEntry')
                                      : t.html('consoleSaml.common.none')) +
          '</td></tr>' +
        '</tbody></table>' +
        '<h3>' + t.html('consoleSaml.meta.hAcs') + '</h3>' +
        (acsRows
          ? '<table><thead><tr><th>index</th><th>isDefault</th>' +
            '<th>Binding</th><th>Location</th></tr></thead><tbody>' +
            acsRows + '</tbody></table>'
          : kit.note(t.html('consoleSaml.meta.registeredNone'))) +
        '<h3>' + t.html('consoleSaml.meta.hSlo') + '</h3>' +
        (sloRows
          ? '<table><thead><tr><th>Binding</th><th>Location</th>' +
            '<th>ResponseLocation</th></tr></thead><tbody>' + sloRows +
            '</tbody></table>'
          : kit.note(t.html('consoleSaml.meta.registeredNone')))
      : kit.note(t.html('consoleSaml.meta.noneConsumed'));
    const html = '<h2>' + t.html('consoleSaml.meta.title') + '</h2>' +
      kit.note(t.html('consoleSaml.meta.intro') + '<a ' +
      'href="/admin/applications?application=' +
      encodeURIComponent(identifier) + '">' +
      t.html('consoleSaml.meta.applicationPage') + '</a>' +
      t.html('consoleSaml.meta.introAfter')) +
      facts +
      '<form method="post" action="/admin/saml2" ' +
      'enctype="multipart/form-data">' + carryBack +
      '<input type="hidden" name="action" value="upload-metadata">' +
      '<input type="hidden" name="sp" value="' + kit.esc(identifier) + '">' +
      '<div class="formrow"><label for="md-doc">' +
      t.html('consoleSaml.meta.upload') + '</label>' +
      '<textarea id="md-doc" name="document" rows="4" cols="60" ' +
      // The element's name is markup the catalog cannot carry, and stays
      // as it is in every language; only the verb before it is a message.
      'placeholder="' + kit.esc(t.text('consoleSaml.meta.paste')) +
      kit.esc('<md:EntityDescriptor>…') + '"></textarea></div>' +
      '<div class="formrow"><label for="md-file">' +
      t.html('consoleSaml.meta.orFile') + '</label>' +
      '<input type="file" id="md-file" name="file" accept=".xml,' +
      'application/samlmetadata+xml,application/xml,text/xml">' +
      '<button>' + t.html('consoleSaml.meta.consume') +
      '</button><span class="note">' +
      t.html('consoleSaml.meta.consumeNote') + '</span>' +
      '</div></form>' +
      '<form method="post" action="/admin/saml2">' + carryBack +
      '<div class="formrow"><input type="hidden" name="action" ' +
      'value="refresh-metadata"><input type="hidden" name="sp" value="' +
      kit.esc(identifier) + '"><button>' +
      t.html('consoleSaml.meta.refreshNow') + '</button>' +
      '<span class="note">' + t.html('consoleSaml.meta.refreshFrom') +
      (meta.mdqUrl ? t.html('consoleSaml.meta.fromMdq') + '<code>' +
                     kit.esc(meta.mdqUrl) + '</code>'
                   : t.html('consoleSaml.meta.fromMdqUnset')) +
      '.</span></div></form>' +
      '<h3>' + t.html('consoleSaml.meta.hSigningCert') + '</h3>' +
      kit.note((meta.signingCertificateConfigured
        ? t.html('consoleSaml.meta.signingSet')
        : (meta.trustAnchors
          ? t.html('consoleSaml.meta.signingAnchors',
                   { n: meta.trustAnchors })
          : t.html('consoleSaml.meta.signingNone'))) +
        ((meta.trustAnchorProblems || []).length
          ? ' <strong>' + kit.esc(meta.trustAnchorProblems.join('; ')) +
            '.</strong>' : '')) +
      '<form method="post" action="/admin/saml2">' + carryBack +
      '<div class="formrow"><input type="hidden" name="action" ' +
      'value="set-metadata-signing-certificate"><input type="hidden" ' +
      'name="sp" value="' + kit.esc(identifier) + '"><label ' +
      'for="md-cert">' + t.html('consoleSaml.meta.signingCertLabel') +
      '</label><input type="text" ' +
      'id="md-cert" name="value" placeholder="' +
      kit.esc(t.text('consoleSaml.common.derOrPem')) + '">' +
      '<button>' + t.html('consoleSaml.common.set') +
      '</button><span class="note">' +
      t.html('consoleSaml.meta.emptyClears') + '</span>' +
      '</div></form>';
    return html;
  }

  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static saml11Body(ctx, json) {
    const t = ctx.t;
    const needle = String(ctx.query.q || '').trim();
    const paging = json.paging;
    const filterParams = { q: String(ctx.query.q || ''),
                           per: ctx.query.per ? paging.perPage : '' };
    const nav = kit.pageNavPair('/admin/saml11', filterParams, paging);
    const listView = kit.listViewOf('/admin/saml11', ctx.query);

    const rows = json.relyingParties.map(function (row) {
      const facts = row;
      const href = '/admin/saml11' +
                   kit.queryWith(listView, { rp: row.identifier });
      const acs = row.assertionConsumerServices;
      const profiles = row.profiles
        .map(SamlPage.saml11ProfileLabel.bind(SamlPage));
      return '<tr><td><a href="' + kit.esc(href) + '"><code>' +
             kit.esc(row.identifier) +
        '</code></a><div ' +
        'class="sub">' + t.html('consoleSaml.list.itsIdp') +
        '<code>' + kit.esc(facts.idpProviderId) + '</code></div></td><td><a ' +
        'href="' + kit.esc(facts.metadataUrl) + '">' +
        t.html('consoleSaml.list.metadata') + '</a></td>' +
        '<td>' + (acs.length ? kit.codeList(acs)
                      : '<span class="sub">' +
                        t.html('consoleSaml.list.noneSeen') + '</span>') +
        '</td>' +
        '<td>' + (profiles.length ? kit.esc(profiles.join(', '))
                                  : '<span class="sub">' +
                                    t.html('consoleSaml.saml11.noProfiles') +
                                    '</span>') +
                                    '</td><td>' +
        kit.esc(String(row.authentications)) + '</td><td>' +
        kit.esc(row.lastSeen ? row.lastSeen.replace('T', ' ').slice(0, 19) :
                 '') +
        '</td></tr>';
    }).join('');

    const inner = '<h1>' + t.html('consoleSaml.saml11.title') +
      '</h1><p class="sub">' + t.html('consoleSaml.saml11.intro') + '</p>' +
      kit.note(t.html('consoleSaml.saml11.noRequest') + '<a ' +
      'href="/admin/saml2">' + t.html('consoleSaml.saml11.linkSaml2Page') +
      '</a>' + t.html('consoleSaml.saml11.noRequestAfter')) +
      kit.note(t.html('consoleSaml.saml11.perRp') + '<a ' +
      'href="/saml11/metadata">/saml11/metadata</a>' +
      t.html('consoleSaml.common.unscopedAfter')) +
      '<p class="sub"><a href="/saml11">' +
      t.html('consoleSaml.common.linkProfile') + '</a> &middot; <a ' +
      'href="/saml11/rp">' + t.html('consoleSaml.saml11.linkMockRp') +
      '</a> &middot; <a ' +
      'href="/admin/saml-attributes">' +
      t.html('consoleSaml.common.linkAttributes') + '</a> ' +
      '&middot; <a ' +
      'href="/admin/applications?kind=' + json.kind + '">' +
      t.html('consoleSaml.common.linkApplications') +
      '</a></p><form method="get" ' +
      'action="/admin/saml11"><div class="formrow"><label ' +
      'for="q">' + t.html('consoleSaml.common.search') +
      '</label><input type="text" id="q" name="q" ' +
      'value="' + kit.esc(String(ctx.query.q || '')) + '" ' +
      'placeholder="' +
      kit.esc(t.text('consoleSaml.saml11.searchPlaceholder')) + '">' +
      (ctx.query.per ?
       '<input type="hidden" name="per" value="' + kit.esc(paging.perPage) +
       '">' :
       '') +
      '<button class="secondary">' + t.html('consoleSaml.common.filter') +
      '</button>' +
      (String(ctx.query.q || '') ? ' <a href="/admin/saml11">' +
        t.html('consoleSaml.common.clear') + '</a>' : '') +
      '</div></form>' +
      nav.head +
      (rows
        ? '<table><thead><tr><th>' + t.html('consoleSaml.saml11.thRp') +
          '</th><th>' + t.html('consoleSaml.common.thMetadata') + '</th>' +
          '<th>' + t.html('consoleSaml.saml11.thShire') + '</th><th>' +
          t.html('consoleSaml.saml11.thProfiles') + '</th>' +
          '<th>' + t.html('consoleSaml.saml11.thAssertions') + '</th><th>' +
          t.html('consoleSaml.common.thLastSeen') +
          '</th></tr></thead><tbody>' + rows +
          '</tbody></table>' + nav.foot
        : kit.note(t.html('consoleSaml.saml11.noneYet',
          { filtered: needle ? 'yes' : 'no' }) + ' ' +
          t.html('consoleSaml.common.startOne') + '<a ' +
          'href="/saml11/rp">' + t.html('consoleSaml.saml11.linkMockRp') +
          '</a>' + t.html('consoleSaml.saml11.orRegister'))) +
      '<h2>' + t.html('consoleSaml.saml11.hRegister') +
      '</h2><p class="sub">' + t.html('consoleSaml.saml11.registerIntro') +
      '</p><form method="post" action="/admin/saml11"><div ' +
      'class="formrow"><input type="hidden" name="action" ' +
      'value="register"><label for="new_rp">' +
      t.html('consoleSaml.saml11.identifier') + '</label><input ' +
      'type="text" id="new_rp" name="rp" ' +
      'placeholder="urn:example:app"><button>' +
      t.html('consoleSaml.common.register') + '</button><span ' +
      'class="note">' + t.html('consoleSaml.saml11.registerNote') +
      '</span></div></form>' +
      SettingsForms.forms(json.settings, '/admin/saml11') +
      kit.note(t.html('consoleSaml.saml11.shape') + '<a ' +
      'href="/admin/saml-attributes">' +
      t.html('consoleSaml.common.linkCustomAttributes') + '</a>' +
      t.html('consoleSaml.saml11.shapeAfter')) +
      kit.perPageForm('/admin/saml11', 'q', String(ctx.query.q || ''),
                       paging.perPage,
                       '', {});

    return inner;
  }

  // Which of the two browser profiles a recorded binding value names, in words.
  // The registry holds the profile URI, which is what the metadata publishes
  // and what a person reading a table does not want to compare character by
  // character. The two names are the specification's own, and are not
  // translated (#539).
  /**
   * Names the SAML 1.1 browser profile a profile URI stands for.
   *
   * @param value - the recorded profile URI
   * @returns `Browser/POST`, `Browser/Artifact`, or the value unchanged
   */
  static saml11ProfileLabel(value) {
    if (value === SamlPage.SAML11_PROFILE_POST) {
      return 'Browser/POST';
    }
    if (value === SamlPage.SAML11_PROFILE_ARTIFACT) {
      return 'Browser/Artifact';
    }
    return value;
  }

  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static saml11Detail(ctx, json) {
    const t = ctx.t;
    const facts = json;
    const rp = json.identifier;
    const acs = json.assertionConsumerServices;
    const profiles = json.profiles;
    // The first and last cells are TEXT, escaped below, so they are the
    // catalog's plain-text form.
    const endpointRows = [
      [t.text('consoleSaml.detail11.rowIdp'), facts.idpProviderId,
       t.text('consoleSaml.detail11.rowIdpWhy')],
      [t.text('consoleSaml.common.rowMetadata'), facts.metadataUrl,
       t.text('consoleSaml.detail11.rowMetadataWhy')],
      [t.text('consoleSaml.detail11.rowTransfer'), facts.ssoUrl,
       t.text('consoleSaml.detail11.rowTransferWhy')],
      [t.text('consoleSaml.detail11.rowResponder'), facts.responderUrl,
       t.text('consoleSaml.detail11.rowResponderWhy')]
    ].map(function (r) {
      return '<tr><td>' + kit.esc(r[0]) + '</td><td><code>' + kit.esc(r[1]) +
        '</code></td><td ' +
        'class="sub">' + kit.esc(r[2]) + '</td></tr>';
    }).join('');

    // A relying party whose identifier looks like a bare origin is very likely
    // one this service GUESSED, and saying so here is the whole reason the
    // guess is survivable. It is a heuristic and is worded as one: somebody may
    // perfectly well have registered `https://app.example.com` on purpose.
    const looksGuessed = json.identifierLooksGuessed;

    const inner = '<h1><code>' + kit.esc(rp) + '</code></h1>' +
      '<p class="sub">' + t.html('consoleSaml.detail11.entryIs') +
      (json.registered ?
       '<a href="/admin/applications?application=' +
             encodeURIComponent(rp) +
             '">' + t.html('consoleSaml.common.inRegistry') + '</a>'
           : t.html('consoleSaml.common.notInRegistry')) + '.</p>' +
      (looksGuessed
        ? kit.note(t.html('consoleSaml.detail11.guessed'))
        : '') +
      '<h2>' + t.html('consoleSaml.common.hEndpoints') + '</h2>' +
      '<table><thead><tr><th>' + t.html('consoleSaml.common.thWhat') +
      '</th><th>' + t.html('consoleSaml.common.thWhere') +
      '</th><th></th></tr></thead>' +
      '<tbody>' +
      endpointRows + '</tbody></table>' +
      '<p class="sub">' + t.html('consoleSaml.common.slugIs') + '<code>' +
      kit.esc(facts.slug) +
      '</code>' +
      (facts.slug === rp ? '' :
        t.html('consoleSaml.detail11.slugDigest')) +
      t.html('consoleSaml.detail11.sameSlug') + '<a href="/admin/saml2">' +
      t.html('consoleSaml.detail11.linkSaml2Profile') + '</a>' +
      t.html('consoleSaml.detail11.sameSlugAfter') + '</p><h2>' +
      t.html('consoleSaml.common.hRecorded') + '</h2><table><tbody><tr><td>' +
      t.html('consoleSaml.detail11.acsSeen') + '</td><td>' +
        (acs.length ? kit.codeList(acs) : '<span class="sub">' +
          t.html('consoleSaml.common.none') + '</span>') +
        ' <span class="sub">' + t.html('consoleSaml.detail11.shire') +
        '</span>' +
        '</td></tr><tr><td>' + t.html('consoleSaml.detail11.profilesUsed') +
        '</td><td>' +
        (profiles.length ?
         kit.esc(profiles.map(SamlPage.saml11ProfileLabel.bind(SamlPage))
           .join(', '))
                         : '<span class="sub">' +
                           t.html('consoleSaml.detail11.noProfiles') +
                           '</span>') +
      '</td></tr><tr><td>' + t.html('consoleSaml.detail11.nameIdFormats') +
      '</td><td>' +
        (json.nameIdFormats.length
          ? kit.codeList(json.nameIdFormats)
          : '<span class="sub">' +
            t.html('consoleSaml.detail11.nameIdFormatsNone') + '</span>') +
      '</td></tr><tr><td>' + t.html('consoleSaml.detail11.assertionsIssued') +
      '</td><td>' +
      kit.esc(String(json.authentications || 0)) +
        '</td></tr></tbody></table><h2>' +
      t.html('consoleSaml.detail11.hNotHere') + '</h2><p ' +
      'class="sub">' + t.html('consoleSaml.detail11.notHere') + '</p><p ' +
      'class="sub"><a href="/saml11/rp">' +
      t.html('consoleSaml.detail11.mockRp') + '</a>' +
      t.html('consoleSaml.detail11.mockRpAfter') + '</p>';

    return inner;
  }
}

export = SamlPage;
