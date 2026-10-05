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
  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static saml2Body(ctx, json) {
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
        'class="sub">its identity provider: ' +
        '<code>' + kit.esc(facts.idpEntityId) + '</code></div></td><td><a ' +
        'href="' + kit.esc(facts.metadataUrl) + '">metadata</a></td>' +
        '<td>' +
        (acs.length ? kit.codeList(acs) : '<span ' +
            'class="sub">none seen</span>') +
        '</td>' +
        '<td>' + (slo.length ? kit.codeList(slo)
                      : '<span class="sub">not declared &mdash; ' +
                        'guessed</span>') +
        '</td><td>' +
        kit.esc(row.lastRequestVerification || '—') +
        '</td><td>' + kit.esc(String(row.authentications)) + '</td><td>' +
        kit.esc(row.lastSeen ? row.lastSeen.replace('T', ' ').slice(0, 19) :
                 '') +
        '</td></tr>';
    }).join('');

    const inner = '<h1>SAML 2.0 identity provider</h1><p class="sub">The Web ' +
      'Browser SSO profile, all three bindings, and Single Logout. This page ' +
      'holds nothing: every row is an entry in ' +
      '<code>ou=applications</code>.</p>' +
      kit.note('<strong>Every service provider gets its own metadata ' +
      'document.</strong> The identity provider names itself differently to ' +
      'each one and publishes endpoints scoped to it, which is what Okta and ' +
      'Ping do. <strong>In development it is minted for anything asked ' +
      'for</strong> — a service provider does not have to appear here before ' +
      'it can be pointed at this service, because asking for its metadata is ' +
      'what creates it. <strong>In product it is not</strong>: a name that ' +
      'is not registered below is a 404 at every per-service-provider ' +
      'path. The unscoped document at <a ' +
      'href="/saml2/metadata">/saml2/metadata</a> works too and names one ' +
      'identity provider for everybody.') +
      '<p class="sub"><a href="/saml2">what the profile is</a> &middot; <a ' +
      'href="/saml2/sp">the mock service provider</a> &middot; <a ' +
      'href="/admin/saml-attributes">what goes into an assertion</a> ' +
      '&middot; <a ' +
      'href="/admin/applications?kind=' + json.kind + '">these entries ' +
      'on the applications page</a></p><form method="get" ' +
      'action="/admin/saml2"><div class="formrow"><label ' +
      'for="q">Search</label><input type="text" id="q" name="q" ' +
      'value="' + kit.esc(String(ctx.query.q || '')) + '" ' +
      'placeholder="an entityID or a name">' +
      (ctx.query.per ?
       '<input type="hidden" name="per" value="' + kit.esc(paging.perPage) +
       '">' :
       '') +
      '<button class="secondary">Filter</button>' +
      (String(ctx.query.q || '') ? ' <a href="/admin/saml2">clear</a>' : '') +
      '</div></form>' +
      nav.head +
      (rows
        ? '<table><thead><tr><th>Service provider (entityID)</th><th>Its ' +
          'metadata</th><th>Assertion consumer service</th><th>Single logout ' +
          'service</th><th>Last request\'s signature</th><th>Responses</th>' +
          '<th>Last ' +
          'seen</th></tr></thead><tbody>' + rows + '</tbody></table>' + nav.foot
        : kit.note('No service provider has used this profile yet' +
          (needle ? ' under that filter' : '') + '. Start one at <a ' +
          'href="/saml2/sp">the mock service provider</a>, or register an ' +
          'entityID below.')) +
      '<h2>Register a service provider</h2><p class="sub">Optional in ' +
      'development, where an entityID is accepted whether or not it is here ' +
      'and what this buys is a metadata document to hand somebody before ' +
      'they have sent anything. In product it is how a service provider ' +
      'comes to exist: its metadata and endpoints answer only once it is ' +
      'registered.</p><form ' +
      'method="post" action="/admin/saml2"><div class="formrow"><input ' +
      'type="hidden" name="action" value="register"><label ' +
      'for="new_sp">entityID</label><input type="text" id="new_sp" name="sp" ' +
      'placeholder="https://sp.example.com/saml"><button>Register</button>' +
      '<span class="note">The same thing a request or a metadata fetch would ' +
      'do.</span></div></form>' +
      '<h2>Import one from the Metadata Query responder</h2><p ' +
      'class="sub">Asks <code>saml2.mdqBaseUrl</code> for the entity by ' +
      'name (<code>&lt;base&gt;/entities/&lt;entityID&gt;</code>), creates ' +
      'the entry if the answer describes it, and consumes the document — ' +
      'held to the realm\'s metadata trust anchors when it has any. A ' +
      'request from a service provider with no metadata starts the same ' +
      'lookup in the background. <strong>In product mode the answer must ' +
      'verify against a trust anchor</strong> ' +
      '(<code>saml2.metadataTrustAnchors</code>): with none, this import is ' +
      'refused unless <code>saml2.mdqImportWithoutAnchors</code> is on — ' +
      'and then the document is consumed with no signature check — and a ' +
      'lookup a request starts for an unknown entityID is not made at ' +
      'all.</p><form method="post" ' +
      'action="/admin/saml2"><div class="formrow"><input type="hidden" ' +
      'name="action" value="mdq-import"><label for="mdq_sp">entityID</label>' +
      '<input type="text" id="mdq_sp" name="sp" ' +
      'placeholder="https://sp.example.com/saml"><button>Import</button>' +
      '</div></form>' +
      '<h2>Metadata Query lookups refused</h2><p ' +
      'class="sub">EntityIDs a request asked to be registered through the ' +
      'responder and was not (product mode): no trust anchor, so nothing ' +
      'was fetched, or an answer that did not verify against one. Newest ' +
      'first; this process\'s record, since it started. To register one, ' +
      'import it above or register it by hand.</p>' +
      (refusedRows
        ? refusedNav.head + '<table><thead><tr><th>entityID</th><th>Why' +
          '</th><th>Times</th><th>First</th><th>Last</th></tr></thead>' +
          '<tbody>' + refusedRows + '</tbody></table>' + refusedNav.foot
        : '<p class="sub">None.</p>') +
      SettingsForms.forms(json.settings, '/admin/saml2') +
      kit.note('These decide the SHAPE of an assertion — who issued it, how ' +
      'long it is good for, what is signed. <a ' +
      'href="/admin/saml-attributes">Custom SAML attributes</a> is the page ' +
      'that changes what one CONTAINS, and its SAML 2.0 set reaches this ' +
      'profile through the same assertion builder that serves WS-Trust and ' +
      'WS-Federation.') +
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

    const endpointRows = [
      ['entityID of the identity provider', facts.idpEntityId,
       json.perApplicationEntityId
         ? 'Unique to this service provider. saml2.perApplicationEntityId ' +
           'turns that off, and then every document names the same identity ' +
           'provider.'
         : 'The same for every service provider, because ' +
           'saml2.perApplicationEntityId is off. The ENDPOINTS below are ' +
           'still this service provider\'s own.'],
      ['Metadata', facts.metadataUrl, 'Signed, and served no-store because ' +
       'the signing key is regenerated on every start. This is the URL to ' +
       'configure the service provider from.'],
      ['Single Sign-On', facts.ssoUrl, 'HTTP Redirect and HTTP POST both. ' +
       'Which binding the RESPONSE comes back on is the AuthnRequest\'s own ' +
       'ProtocolBinding.'],
      ['Single Logout', facts.sloUrl, 'A LogoutRequest arriving from this ' +
       'service provider, and a bare GET to start one from here.'],
      ['Artifact Resolution', facts.arsUrl, 'SOAP over HTTP, and a back ' +
       'channel: the browser never touches it. An artifact resolves exactly ' +
       'once.']
    ].map(function (r) {
      return '<tr><td>' + kit.esc(r[0]) + '</td><td><code>' + kit.esc(r[1]) +
        '</code></td><td ' +
        'class="sub">' + kit.esc(r[2]) + '</td></tr>';
    }).join('');

    const inner = '<h1><code>' + kit.esc(sp) + '</code></h1>' +
      '<p class="sub">A SAML 2.0 service provider. Its entry is ' +
      (found ?
       '<a href="/admin/applications?application=' +
             encodeURIComponent(sp) +
             '">in the applications registry</a>'
           : 'NOT in the registry yet — this page is showing what it WOULD ' +
             'be given') + '.</p><h2>The endpoints it is configured from</h2>' +
      '<table><thead><tr><th>What</th><th>Where</th><th></th></tr></thead>' +
      '<tbody>' +
      endpointRows + '</tbody></table>' +
      '<p class="sub">The path segment is <code>' + kit.esc(facts.slug) +
      '</code>' +
      (facts.slug === sp ? '' :
        ', which is a digest of the entityID because the entityID is not ' +
        'safe in a URL path segment. The percent-encoded entityID works in ' +
        'the same place') + '.</p><h2>What ' +
      'this service has recorded</h2><table><tbody><tr><td>Assertion ' +
      'consumer services seen</td><td>' +
        (acs.length ? kit.codeList(acs) : '<span class="sub">none</span>') +
      '</td></tr><tr><td>NameID ' +
      'formats asked for</td><td>' +
        (json.nameIdFormats.length
          ? kit.codeList(json.nameIdFormats)
          : '<span class="sub">none — it has never named one, so it gets ' +
            'saml2.nameIdFormat</span>') +
        '</td></tr>' +
      '<tr><td>Response bindings asked for</td><td>' +
        (json.responseBindings.length
          ? kit.codeList(json.responseBindings) : '<span ' +
              'class="sub">none</span>') +
        '</td></tr>' +
      '<tr><td>Its last AuthnRequest\'s signature</td><td>' +
        (verification.outcome
          ? '<strong>' + kit.esc(verification.outcome) + '</strong>' +
            (verification.binding
              ? ' <span class="sub">(' + kit.esc(verification.binding) +
                ' binding, ' + kit.esc(verification.signatureMethod ||
                                        'no SigAlg') +
                (verification.weak ? ', SHA-1 — weak' : '') + ')</span>'
              : '')
          : '<span class="sub">unknown</span>') +
        ' <span class="sub">&mdash; VERIFIED against the registered signing ' +
        'certificates below, never against the one a request carries. ' +
        '<code>no-certificate</code> means it was signed and nothing is ' +
        'registered to check it against.</span></td></tr>' +
        '<tr><td>Signed requests required</td><td>' +
        (required.required ? '<strong>yes</strong>' : 'no') +
        ' <span class="sub">&mdash; ' + kit.esc(required.why) +
        '. An unsigned AuthnRequest or LogoutRequest is refused when this ' +
        'is yes; a signature that does not verify is refused ' +
        'always.</span></td></tr><tr><td>Responses issued to ' +
        'it</td><td>' + kit.esc(String(json.authentications || 0)) +
        '</td></tr>' +
      '</tbody></table>' +
      '<h2>Where its LogoutResponse goes</h2>' +
      kit.note('A <code>&lt;samlp:LogoutRequest&gt;</code> carries no ' +
      'return address — only SP metadata does. The SingleLogoutService ' +
      'endpoints of its CONSUMED metadata (below) are used first; with none, ' +
      'what is declared here; then <code>saml2.defaultSingleLogoutService' +
      '</code>; and then the assertion consumer service URL this service ' +
      'provider last used, <strong>which is a guess and is logged as ' +
      'one</strong>. Consuming its metadata, or declaring an address here, ' +
      'removes the guess.') +
      (slo.length
        ? '<table><thead><tr><th>Declared</th><th></th></tr></thead><tbody>' +
          slo.map(function (one) {
            return '<tr><td><code>' + kit.esc(one) + '</code></td><td>' +
              '<form method="post" action="/admin/saml2">' + carryBack +
              '<input type="hidden" name="action" ' +
              'value="remove-logout-service"><input type="hidden" name="sp" ' +
              'value="' + kit.esc(sp) + '">' +
              '<input type="hidden" name="value" value="' + kit.esc(one) +
              '"><button class="secondary">Remove</button></form></td></tr>';
          }).join('') + '</tbody></table>'
        : kit.note('Nothing is declared, so the fallback above applies' +
          (acs.length ?
           ' — and it would guess <code>' + kit.esc(acs[acs.length - 1]) +
           '</code>' :
           '') +
          '.')) +
      '<form method="post" action="/admin/saml2">' + carryBack + '<div ' +
      'class="formrow"><input type="hidden" name="action" ' +
      'value="set-logout-service"><input type="hidden" name="sp" ' +
      'value="' + kit.esc(sp) + '"><label ' +
      'for="slo">Add one</label><input type="text" id="slo" name="value" ' +
      'placeholder="https://sp.example.com/saml/slo"><button>Add</button>' +
      '<span ' +
      'class="note">Writes <code>samlSingleLogoutService</code> on the ' +
      'entry. An <code>ldapmodify</code> of the same attribute does exactly ' +
      'this.</span></div></form>' +
      SamlPage.saml2SigningCertificatesSection(sp, json, carryBack) +
      SamlPage.saml2MetadataSection(sp, json, carryBack) +
      '<p class="sub"><a ' +
      'href="' + kit.esc(facts.metadataUrl) + '">its ' +
      'metadata</a> &middot; <a href="/saml2">the profile</a>' +
      (found ? ' &middot; <a href="/admin/applications?application=' +
             encodeURIComponent(sp) + '">its registry entry, with ' +
                                              'every attribute</a>' : '') +
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
   * @param identifier - the service provider's identifier
   * @param json - the detail page's JSON view
   * @param carryBack - the hidden `back` field every form carries
   * @returns the section as HTML
   */
  static saml2SigningCertificatesSection(identifier, json, carryBack) {
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
    const html = '<h2>Its signing certificates</h2>' +
      kit.note('What this service provider\'s AuthnRequests, ' +
      'LogoutRequests and LogoutResponses are <strong>VERIFIED</strong> ' +
      'against, in every mode — a signature that verifies against none of ' +
      'them is refused. Written by consuming its metadata, by the form ' +
      'below, or by confirming an observed certificate. The certificate a ' +
      'request carries in its <code>ds:KeyInfo</code> is never trusted by ' +
      'arriving: it is shown as OBSERVED until you confirm it. RSA ' +
      'certificates only, because the verifier here is RSA.') +
      (certs.length
        ? '<table><thead><tr><th>Registered</th><th></th></tr></thead>' +
          '<tbody>' + certs.map(function (der) {
            return '<tr><td>' + shown(der) + '</td><td>' +
              hidden('remove-signing-certificate') +
              '<input type="hidden" name="value" value="' + kit.esc(der) +
              '"><button class="secondary">Remove</button></form></td></tr>';
          }).join('') + '</tbody></table>'
        : kit.note('None registered, so a signed request from this service ' +
                    'provider is recorded as <code>no-certificate</code> ' +
                    'and not verified.')) +
      hidden('set-signing-certificate') + '<div class="formrow"><label ' +
      'for="cert">Replace them with</label><input type="text" id="cert" ' +
      'name="value" placeholder="base64 DER or PEM"><button>Set</button>' +
      '<span class="note">The list becomes this one certificate; empty ' +
      'clears it.</span></div></form>' +
      '<h3>Observed</h3>' +
      (json.observedSigningCertificate
        ? kit.note('The last signed request carried this certificate, and ' +
          'it is not registered. It verifies <strong>nothing</strong>. ' +
          'Development mode encrypts an assertion to it when nothing else ' +
          'is on the entry; product does not. Confirm it only if it is ' +
          'genuinely this service provider\'s.') +
          shown(json.observedSigningCertificate) +
          '<div class="formrow">' + hidden('confirm-signing-certificate') +
          '<button>Confirm — trust it</button></form> ' +
          hidden('discard-signing-certificate') +
          '<button class="secondary">Discard</button></form></div>'
        : kit.note('No request has carried a certificate that is not ' +
                    'already registered.'));
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
   * @param identifier - the service provider's identifier
   * @param json - the detail page's JSON view
   * @param carryBack - the hidden `back` field every form carries
   * @returns the section as HTML
   */
  static saml2MetadataSection(identifier, json, carryBack) {
    const meta = json.metadata || {};
    const yes = function (flag) {
      return flag ? 'true' : 'false';
    };
    const acsRows = (meta.assertionConsumerServices || []).map(function (e) {
      return '<tr><td>' + kit.esc(e.index || '—') + '</td><td>' +
        (e.isDefault === true ? 'yes' : (e.isDefault === false ? 'no' : '—')) +
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
        '<tr><td>Consumed</td><td>' + kit.esc(meta.consumedAt) + ' (' +
          kit.esc(meta.how) + ')' +
          (meta.url ? ' from <code>' + kit.esc(meta.url) + '</code>' : '') +
          '</td></tr>' +
        '<tr><td>The document\'s own signature</td><td>' +
          kit.esc(meta.signature || 'unknown') + '</td></tr>' +
        '<tr><td>State</td><td><strong>' +
          kit.esc(String(meta.state || '').toUpperCase()) + '</strong>' +
          (meta.stateWhy ? ' <span class="sub">— ' + kit.esc(meta.stateWhy) +
                           '</span>' : '') +
          (meta.state === 'expired'
            ? ' <span class="sub">Every request from this service provider ' +
              'is REFUSED until a newer document is consumed.</span>' : '') +
          '</td></tr>' +
        '<tr><td>validUntil (effective)</td><td>' +
          (meta.validUntil
            ? kit.esc(meta.validUntil) + ' <span class="sub">— enforced: ' +
              'past it this service provider\'s requests are refused</span>'
            : '<span class="sub">none stated</span>') + '</td></tr>' +
        '<tr><td>cacheDuration (effective)</td><td>' +
          (meta.cacheDuration ? kit.esc(meta.cacheDuration) : '<span ' +
           'class="sub">none stated</span>') +
          (meta.staleAt ? ' <span class="sub">— stale from ' +
                          kit.esc(meta.staleAt) + '</span>' : '') +
          '</td></tr>' +
        '<tr><td>Background refresh</td><td>' +
          (!meta.refreshable
            ? '<span class="sub">not possible: the document was ' +
              'uploaded, and a stale one keeps working until its ' +
              'validUntil</span>'
            : (meta.refresherEnabled ? 'on' : '<strong>off</strong> ' +
               '(saml2.spMetadataRefresh)') +
              (meta.refresh
                ? ' — last attempt ' + kit.esc(meta.refresh.lastAttemptAt) +
                  (meta.refresh.ok ? ', succeeded'
                    : ', <strong>FAILING</strong> since ' +
                      kit.esc(meta.refresh.failingSince) + ' (' +
                      kit.esc(String(meta.refresh.failures)) +
                      ' attempt(s)): ' + kit.esc(meta.refresh.why))
                : ' <span class="sub">— not attempted in this ' +
                  'process</span>')) +
          '</td></tr>' +
        '<tr><td>AuthnRequestsSigned</td><td>' +
          yes(meta.authnRequestsSigned) + '</td></tr>' +
        '<tr><td>WantAssertionsSigned</td><td>' +
          yes(meta.wantAssertionsSigned) + '</td></tr>' +
        '<tr><td>Encrypted assertions wanted</td><td>' +
          yes(meta.wantAssertionsEncrypted) + ' <span class="sub">— true ' +
          'when the document publishes a use="encryption" key; the ' +
          'assertion is then encrypted to it in every mode</span></td></tr>' +
        '<tr><td>NameIDFormats</td><td>' +
          ((meta.nameIdFormats || []).length
            ? kit.codeList(meta.nameIdFormats) + ' <span class="sub">— a ' +
              'NameIDPolicy asking for another is answered ' +
              'InvalidNameIDPolicy</span>'
            : '<span class="sub">none declared — any format asked for is ' +
              'answered</span>') + '</td></tr>' +
        '<tr><td>Encryption certificate</td><td>' +
          (meta.encryptionCertificate ? 'on the entry' : 'none') +
          '</td></tr>' +
        '</tbody></table>' +
        '<h3>Registered assertion consumer services</h3>' +
        (acsRows
          ? '<table><thead><tr><th>index</th><th>isDefault</th>' +
            '<th>Binding</th><th>Location</th></tr></thead><tbody>' +
            acsRows + '</tbody></table>'
          : kit.note('The document registered none.')) +
        '<h3>Registered single logout services</h3>' +
        (sloRows
          ? '<table><thead><tr><th>Binding</th><th>Location</th>' +
            '<th>ResponseLocation</th></tr></thead><tbody>' + sloRows +
            '</tbody></table>'
          : kit.note('The document registered none.'))
      : kit.note('No metadata has been consumed for this service provider, ' +
                  'so its return addresses and signing certificates are ' +
                  'whatever was recorded or declared above.');
    const html = '<h2>Its metadata</h2>' +
      kit.note('Consuming a service provider\'s metadata REGISTERS what it ' +
      'says: its AssertionConsumerService endpoints (a request is answered ' +
      'only at one of them, in every mode), its SingleLogoutService ' +
      'endpoints, its signing certificates, its encryption certificate, its ' +
      'NameIDFormats, AuthnRequestsSigned and WantAssertionsSigned. It ' +
      'happens only when you refresh the URL on <a ' +
      'href="/admin/applications?application=' +
      encodeURIComponent(identifier) + '">its application page</a> or ' +
      'upload a document here — never while somebody is signing in.') +
      facts +
      '<form method="post" action="/admin/saml2" ' +
      'enctype="multipart/form-data">' + carryBack +
      '<input type="hidden" name="action" value="upload-metadata">' +
      '<input type="hidden" name="sp" value="' + kit.esc(identifier) + '">' +
      '<div class="formrow"><label for="md-doc">Upload a document</label>' +
      '<textarea id="md-doc" name="document" rows="4" cols="60" ' +
      'placeholder="paste &lt;md:EntityDescriptor&gt;…"></textarea></div>' +
      '<div class="formrow"><label for="md-file">or a file</label>' +
      '<input type="file" id="md-file" name="file" accept=".xml,' +
      'application/samlmetadata+xml,application/xml,text/xml">' +
      '<button>Consume it</button><span class="note">Its entityID must be ' +
      'this service provider\'s. Nothing changes if it is refused.</span>' +
      '</div></form>' +
      '<form method="post" action="/admin/saml2">' + carryBack +
      '<div class="formrow"><input type="hidden" name="action" ' +
      'value="refresh-metadata"><input type="hidden" name="sp" value="' +
      kit.esc(identifier) + '"><button>Refresh it now</button>' +
      '<span class="note">From its samlSpMetadataUrl, or — with none — ' +
      (meta.mdqUrl ? 'from the MDQ responder, <code>' +
                     kit.esc(meta.mdqUrl) + '</code>'
                   : 'from the MDQ responder (saml2.mdqBaseUrl, not set ' +
                     'here)') + '.</span></div></form>' +
      '<h3>The certificate its metadata must be signed with</h3>' +
      kit.note((meta.signingCertificateConfigured
        ? 'Set: a document that is unsigned, or not signed with this key ' +
          'or a realm trust anchor, is refused.'
        : (meta.trustAnchors
          ? 'Not set on the entry, and this realm has ' + meta.trustAnchors +
            ' metadata trust anchor(s) (saml2.metadataTrustAnchors): a ' +
            'document that verifies against none of them is refused.'
          : 'Not set, and no realm trust anchor: a signed document is ' +
            'consumed and recorded as <code>signed-not-verified</code>, and ' +
            'the trust act is your choice of URL or document.')) +
        ((meta.trustAnchorProblems || []).length
          ? ' <strong>' + kit.esc(meta.trustAnchorProblems.join('; ')) +
            '.</strong>' : '')) +
      '<form method="post" action="/admin/saml2">' + carryBack +
      '<div class="formrow"><input type="hidden" name="action" ' +
      'value="set-metadata-signing-certificate"><input type="hidden" ' +
      'name="sp" value="' + kit.esc(identifier) + '"><label ' +
      'for="md-cert">Metadata signing certificate</label><input type="text" ' +
      'id="md-cert" name="value" placeholder="base64 DER or PEM">' +
      '<button>Set</button><span class="note">Empty clears it.</span>' +
      '</div></form>';
    return html;
  }
}

export = SamlPage;
