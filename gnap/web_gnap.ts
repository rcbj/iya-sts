// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_gnap.ts
//
// ---------------------------------------------------------------------------
// PROTOCOLS → GNAP AND MONITORING → GNAP GRANTS, DRAWN FROM THEIR VIEWS ALONE
// (#446, 2026-10-05).
//
// Draws GNAP from the answer of `GET /admin-api/gnap` — its endpoints, grants,
// resource servers, verification material, capabilities and settings — and
// GNAP grants from that of `GET /admin-api/gnap/monitor`.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// Its methods were `GnapAdmin`'s in `gnap/gnap_admin.ts`, moved with their
// comments; that module still draws the page until the console's cutover, by
// calling `render()` with its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('../admin-ui/web_kit');
import SettingsForms = require('../admin-ui/web_settings');

type Json = any;

/**
 * Draws GNAP from the answer of `GET /admin-api/gnap` — its endpoints, grants,
 * resource servers, verification material, capabilities and settings — and
 * GNAP grants from that of `GET /admin-api/gnap/monitor`.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class GnapPage {
  /**
   * Draws the page's body from its view.
   *
   * @param view - the answer of the page's management API operation
   * @param ctx - the render context: the page's query and whether
   *   the reader may write (`WebKit.context()`)
   * @returns the body as HTML
   */
  static render(view: Json, ctx: Json): string {
    return GnapPage.body(ctx, view);
  }

  static when(seconds: number): string {
    return seconds ?
           new Date(seconds * 1000).toISOString()
                                   .replace('T', ' ')
                                   .replace(/\.\d+Z$/, 'Z') : '—';
  }

  // A static helper with no render context: its caller hands it the page's
  // translator (#539), for the one word it draws.
  static list(values: unknown[] | null | undefined, t: Json): string {
    const esc = kit.esc;
    return (values || []).length ? (values || []).map(function (one) {
      return '<code>' + esc(one) + '</code>';
    }).join(' ') : '<span class="sub">' + t.html('consoleGnap.none') +
                   '</span>';
  }

  // THE TWO PAGES' BODIES (#446), each one method so that it can be one
  // renderer: Protocols → GNAP and Monitoring → GNAP grants. Each was the
  // body of its route; the notice and error banner stays there.
  /**
   * Draws Protocols → GNAP from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - `gnapView()`'s answer
   * @returns the body as HTML
   */
  static body(ctx, json) {
    const t = ctx.t;
    const self = this;
    const esc = kit.esc;
    const list = function (values) {
      return self.list(values, t);
    };
    const when = function (seconds) {
      return self.when(seconds);
    };
    const endpointRows = Object.keys(json.endpoints).map(function (name) {
      // A Copy button beside each, as on every Protocols page's
      // Endpoints section (2026-10-01): kit.copyButton().
      return '<tr><th>' + esc(name) + '</th><td><code>' +
             esc(json.endpoints[name]) + '</code>' +
             kit.copyButton(json.endpoints[name]) + '</td></tr>';
    }).join('');
    const capabilityRows = json.authorizationServers.length
      ? json.authorizationServers.map(function (profile) {
        const caps = profile.capabilities;
        return '<tr><td><code>' + esc(profile.id) + '</code></td>' +
          '<td><code>' + esc(caps.grant_request_endpoint) +
          '</code></td>' +
          '<td>' + list(caps.interaction_start_modes_supported) + '</td>' +
          '<td>' + list(caps.interaction_finish_methods_supported) +
          '</td>' +
          '<td>' + list(caps.key_proofs_supported) + '</td>' +
          '<td>' + list(caps.token_formats_supported) + '</td>' +
          '<td>' +
          (caps.key_rotation_supported === undefined ? '—' :
           esc(caps.key_rotation_supported)) + '</td></tr>';
      }).join('')
      : '<tr><td colspan="7" class="sub">' +
        t.html('consoleGnap.noNamedServer',
               { endpoint: json.endpoints.grant }) + '</td></tr>';
    const stateLinks = ['all'].concat(json.grants.states)
      .map(function (state) {
        const on = (state === 'all' &&
                    !json.grants.state) || state === json.grants.state;
        return on ? '<strong>' + esc(state) + '</strong>'
                  : '<a href="/admin/gnap' +
                    (state === 'all' ? '' : '?state=' + esc(state)) +
                    '#list-grantsPage">' +
                    esc(state) + '</a>';
      }).join(' · ');
    const grantNav = kit.pageNavPair('/admin/gnap', ctx.query,
                                       Object.assign({},
                                                     json.grants.paging,
                                                     { param:
                                                         'grantsPage' }));
    const grantRows = json.grants.rows.length ?
                      json.grants.rows.map(function (grant) {
      // A grant finalized as `issued` still has live tokens, so it can
      // still be revoked (#432 phase 7).
      const control = grant.state === 'finalized' &&
        !(grant.finalization && grant.finalization.reason === 'issued')
        ? '<span class="sub">' + t.html('consoleGnap.finalized') +
          '</span>'
        : '<form method="post" action="/admin/gnap"><input type="hidden" ' +
          'name="action" value="revoke-grant"><input type="hidden" ' +
          'name="grant" value="' + esc(grant.id) + '">' +
          '<button type="submit" class="danger">' +
          t.html('consoleGnap.revoke') + '</button></form>';
      // The reason a finalized grant ended (#432 phase 7).
      return '<tr><td><code>' + esc(grant.id) + '</code></td><td>' +
        esc(grant.state) +
        (grant.finalization ? '<div class="sub">' +
          esc(grant.finalization.reason) + '</div>' : '') + '</td><td><a ' +
        'href="/admin/applications?application=' + encodeURIComponent(
            grant.client || '') + '"><code>' +
        esc(grant.client) + '</code></a><div class="sub">' + esc(
            grant.proof) + '</div></td><td>' +
        (grant.resourceOwner ?
         '<code>' + esc(grant.resourceOwner) + '</code>' :
         '<span ' +
            'class="sub">' + t.html('consoleGnap.none') + '</span>') +
        '</td><td><code>' + esc(
                grant.authorizationServer) + '</code></td><td>' +
        (grant.interaction ? list(grant.interaction.modes) +
          (grant.interaction.finish ?
           '<div class="sub">finish: ' + esc(grant.interaction.finish) +
           '</div>' : '')
          : '<span class="sub">' + t.html('consoleGnap.none') + '</span>') +
        '</td>' +
        '<td class="num">' + grant.tokens + '</td><td>' + esc(
            when(grant.updatedAt)) + '</td><td>' + control + '</td></tr>';
    }).join('') : '<tr><td colspan="9" class="sub">' +
                  (json.grants.state
                    ? t.html('consoleGnap.noGrantsInState',
                             { state: json.grants.state })
                    : t.html('consoleGnap.noGrants')) + '</td></tr>';
    const resourceNav = kit.pageNavPair('/admin/gnap', ctx.query,
                                          Object.assign(
                                              {},
                                              json.resourceSets.paging,
                                              {
      param: 'resourcesPage' }));
    const resourceRows = json.resourceSets.rows.length ?
                         json.resourceSets.rows.map(function (row) {
      return '<tr><td><code>' + esc(row.reference) +
        '</code></td><td><code>' +
        esc(row.resourceServer) +
        '</code></td><td><code>' + esc(JSON.stringify(
            row.access)) + '</code></td><td>' +
        list(row.tokenFormats) + '</td><td>' +
        (row.introspectionRequired ? t.html('consoleGnap.yes')
                                   : t.html('consoleGnap.no')) + '</td><td>' +
        esc(when(row.createdAt)) + '</td><td><form method="post" ' +
        'action="/admin/gnap"><input type="hidden" name="action" ' +
        'value="delete-resource-set"><input type="hidden" ' +
        'name="reference" ' +
        'value="' + esc(row.reference) + '"><button ' +
        'type="submit" class="danger">' + t.html('consoleGnap.delete') +
        '</button></form></td></tr>';
    }).join('') : '<tr><td colspan="7" class="sub">' +
      t.html('consoleGnap.noResourceSets') + '</td></tr>';
    const material = json.verificationMaterial;
    const caps = json.capabilities;
    const inner =
      kit.note(t.html('consoleGnap.intro') +
        (json.enabled ? '' : t.html('consoleGnap.turnedOff'))) +
      kit.warn(t.html('consoleGnap.keyProofWarn')) +
      '<h2>' + t.html('consoleGnap.endpoints') + '</h2><table class="kv">' +
      endpointRows +
      '</table><h2>' + t.html('consoleGnap.authorizationServers') +
      '</h2><p class="sub">' +
      // The path's `{id}` is a parameter's value rather than message text: a
      // catalog message cannot carry a literal brace (#539). The link is
      // markup a message cannot carry either, so its sentence is the words
      // before it, the link's text and the words after.
      t.html('consoleGnap.namedServersAt', { path: '/{id}/gnap' }) + ' ' +
      t.html('consoleGnap.discoveryOverriddenOn') + ' <a ' +
      'href="/admin/authorization-servers">' +
      t.html('consoleGnap.authorizationServersLink') + '</a>' +
      t.html('consoleGnap.publishesWhatEnforces') +
      '</p><table><thead><tr><th>' + t.html('consoleGnap.thServer') +
      '</th><th>' + t.html('consoleGnap.thGrantEndpoint') + '</th><th>' +
      t.html('consoleGnap.thStartModes') + '</th><th>' +
      t.html('consoleGnap.thFinish') + '</th><th>' +
      t.html('consoleGnap.thKeyProofs') + '</th><th>' +
      t.html('consoleGnap.thTokenFormats') + '</th><th>' +
      t.html('consoleGnap.thKeyRotation') + '</th></tr>' +
      '</thead>' +
      '<tbody><tr><td><code>default</code></td><td>' +
      '<code>' + esc(caps.grant_request_endpoint) +
      '</code></td><td>' + list(caps.interaction_start_modes_supported) +
      '</td><td>' +
      list(caps.interaction_finish_methods_supported) + '</td><td>' +
      list(caps.key_proofs_supported) + '</td><td>' +
      list(caps.token_formats_supported) + '</td><td>' +
      esc(caps.key_rotation_supported) + '</td></tr>' + capabilityRows +
      '</tbody></table><h2>' + t.html('consoleGnap.tokenFormats') +
      '</h2><table class="kv"><tr><th>jwt-signed</th><td>' +
      t.html('consoleGnap.jwtSigned',
             { uri: material ? material.jwt.jwks_uri : '' }) +
      '</td></tr><tr><th>jwt-encrypted</th><td>' +
      t.html('consoleGnap.jwtEncrypted') +
      '</td></tr><tr><th>macaroon</th><td>' +
      t.html('consoleGnap.macaroon') +
      '</td></tr><tr><th>biscuit</th><td>' +
      t.html('consoleGnap.biscuit',
             { key: material ? material.biscuit.root_public_key : '' }) +
      '</td></tr>' +
      '<tr><th>zcap</th><td>' +
      t.html('consoleGnap.zcap',
             { controller: material ? material.zcap.controller : '' }) +
      '</td></tr></table><h2 ' +
      'id="list-grantsPage">' + t.html('consoleGnap.grants') + '</h2><p ' +
      'class="sub">' + stateLinks + ' — ' +
      t.html('consoleGnap.grantCount', { n: json.grants.paging.total }) +
      '</p>' + grantNav.head +
      '<table><thead><tr><th>' + t.html('consoleGnap.thGrant') +
      '</th><th>' + t.html('consoleGnap.thState') + '</th><th>' +
      t.html('consoleGnap.thClient') + '</th><th>' +
      t.html('consoleGnap.thResourceOwner') + '</th><th>' +
      t.html('consoleGnap.thServer') + '</th><th>' +
      t.html('consoleGnap.thInteraction') + '</th>' +
      '<th>' + t.html('consoleGnap.thTokens') + '</th>' +
      '<th>' + t.html('consoleGnap.thUpdated') +
      '</th><th></th></tr></thead><tbody>' + grantRows +
      '</tbody></table>' + grantNav.foot +
      '<h2 id="list-resourcesPage">' +
      t.html('consoleGnap.registeredResourceSets') + '</h2>' +
      resourceNav.head +
      '<table><thead><tr><th>' + t.html('consoleGnap.thReference') +
      '</th><th>' + t.html('consoleGnap.thResourceServer') + '</th><th>' +
      t.html('consoleGnap.thAccess') + '</th><th>' +
      t.html('consoleGnap.thFormats') + '</th><th>' +
      t.html('consoleGnap.thIntrospection') + '</th>' +
      '<th>' + t.html('consoleGnap.thRegistered') + '</th><th>' +
      '</th></tr></thead><tbody>' + resourceRows +
      '</tbody></table>' + resourceNav.foot +
      '<h2>' + t.html('consoleGnap.settings') + '</h2>' +
      SettingsForms.forms(json.settings, '/admin/gnap', undefined, t) +
      '<p class="links"><a href="/admin/gnap?format=json">JSON</a> · ' +
      '<code>GET ' +
      '/admin-api/gnap</code> · <a href="/admin/gnap/monitor">' +
      t.html('consoleGnap.linkMonitor') + '</a> · <a ' +
      'href="/admin/applications/new">' +
      t.html('consoleGnap.linkNewApplication') + '</a> · <a ' +
      'href="/admin/error-codes">' + t.html('consoleGnap.linkErrorCodes') +
      '</a></p>';
    return inner;
  }

  /**
   * Draws Monitoring → GNAP grants from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - `gnapMonitorView()`'s answer
   * @returns the body as HTML
   */
  static monitorBody(ctx, json) {
    const t = ctx.t;
    const self = this;
    const esc = kit.esc;
    const list = function (values) {
      return self.list(values, t);
    };
    const when = function (seconds) {
      return self.when(seconds);
    };
    // `totals`, not `t`, since #539: `t` is the page's translator, always.
    const totals = json.totals;
    const tiles = '<div class="tiles">' +
      kit.tile(json.applications, t.text('consoleGnap.tileApplications')) +
      kit.tile(totals.grants, t.text('consoleGnap.tileGrantRequests')) +
      kit.tile(totals.approved, t.text('consoleGnap.tileApproved')) +
      kit.tile(totals.denied, t.text('consoleGnap.tileDenied')) +
      kit.tile(totals.tokens, t.text('consoleGnap.tileTokensIssued')) +
      kit.tile(totals.rotations + totals.keyRotations,
               t.text('consoleGnap.tileRotations')) +
      kit.tile(totals.tokenRevocations + totals.revoked,
               t.text('consoleGnap.tileRevocations')) +
      kit.tile(totals.proofFailures, t.text('consoleGnap.tileFailedProofs')) +
      kit.tile(totals.introspections,
               t.text('consoleGnap.tileIntrospections')) +
      '</div>';
    const formatRow = Object.keys(json.tokensByFormat)
      .map(function (format) {
        return '<td class="num">' + json.tokensByFormat[format] + '</td>';
      }).join('');
    const nav = kit.pageNavPair('/admin/gnap/monitor', ctx.query,
                                  json.paging);
    const rows = json.rows.length ? json.rows.map(function (row) {
      const c = row.counters;
      const formats = Object.keys(c.formats || {})
                            .filter(function (f) {
                              return c.formats[f];
                            })
                            .map(function (f) {
        return esc(f) + ' ' + c.formats[f];
      }).join(', ');
      const errors = Object.keys(c.errors || {}).map(function (code) {
        return '<code>' + esc(code) + '</code> ' + c.errors[code];
      }).join(', ');
      return '<tr><td><a href="/admin/applications?application=' +
        encodeURIComponent(row.identifier) +
        '"><code>' + esc(row.identifier) + '</code></a>' +
        (row.name ? '<div ' +
            'class="sub">' + esc(row.name) +
        '</div>' : '') + '</td><td>' + esc(row.role) +
        (row.webApplication ?
         '<div ' +
            'class="sub">web</div>' : '') +
        '</td><td class="num">' + row.grantsHeld.pending + ' / ' +
        row.grantsHeld.approved + ' ' +
            '/ ' +
        row.grantsHeld.finalized + '</td><td class="num">' +
        row.activeTokens +
        '</td><td ' +
        'class="num">' + c.grants + '</td><td class="num">' + c.approved +
        '</td><td ' +
            'class="num">' + c.denied +
        '</td><td class="num">' + c.tokens + '<div class="sub">' +
        (formats ||
            '—') + '</div></td><td ' +
        'class="num">' + (c.rotations + c.keyRotations) + '</td><td ' +
            'class="num">' +
        (c.tokenRevocations +
         c.revoked) + '</td><td class="num">' + c.proofFailures +
        '</td><td ' +
        'class="num">' + c.introspections + ' / ' + c.registrations +
        ' / ' +
        c.derivations + '</td><td>' + (errors || '<span ' +
            'class="sub">' + t.html('consoleGnap.none') + '</span>') +
        '</td><td>' + esc(
                row.lastAt || '—') + '<div ' +
                'class="sub">' + esc(row.lastEvent || '') +
                '</div></td></tr>';
    }).join('') : '<tr><td colspan="14" class="sub">' +
                  t.html('consoleGnap.noApplications') + '</td></tr>';
    const inner =
      kit.note(t.html('consoleGnap.monitorIntro', { since: json.since })) +
      tiles +
      '<h2>' + t.html('consoleGnap.tokensByFormat') +
      '</h2><table><thead><tr>' + Object.keys(
          json.tokensByFormat).map(function (f) {
        return '<th>' + esc(f) + '</th>';
      }).join('') + '</tr></thead><tbody><tr>' + formatRow +
      '</tr></tbody></table><h2 ' +
      'id="list-page">' + t.html('consoleGnap.applications') + '</h2>' +
      nav.head +
      '<table><thead><tr><th>' + t.html('consoleGnap.thApplication') +
      '</th><th>' + t.html('consoleGnap.thRole') + '</th><th>' +
      t.html('consoleGnap.thGrantsHeld') + '<div ' +
      'class="sub">' + t.html('consoleGnap.thGrantsHeldSub') +
      '</div></th><th>' + t.html('consoleGnap.thLiveTokens') +
      '</th><th>' + t.html('consoleGnap.thRequested') + '</th><th>' +
      t.html('consoleGnap.thApproved') + '</th><th>' +
      t.html('consoleGnap.thDenied') + '</th>' +
      '<th>' + t.html('consoleGnap.thTokensIssued') + '</th><th>' +
      t.html('consoleGnap.thRotations') + '</th><th>' +
      t.html('consoleGnap.thRevocations') + '</th><th>' +
      t.html('consoleGnap.thFailedProofs') + '</th><th>' +
      t.html('consoleGnap.thRsCalls') + '<div class="sub">' +
      t.html('consoleGnap.thRsCallsSub') + '</div></th><th>' +
      t.html('consoleGnap.thErrorsReturned') + '</th><th>' +
      t.html('consoleGnap.thLastActivity') +
      '</th></tr></thead><tbody>' + rows + '</tbody></table>' +
      nav.foot +
      // The link is markup a message cannot carry (#539), so the sentence
      // is the words before it, the link's text, and the words after.
      kit.note(t.html('consoleGnap.noReset') + '<a ' +
        'href="/admin/audit">' + t.html('consoleGnap.auditLog') + '</a>' +
        t.html('consoleGnap.noResetEnd')) +
      '<p class="links"><a href="/admin/gnap/monitor?format=json">JSON</a> ' +
      '· ' +
      '<code>GET /admin-api/gnap/monitor</code> · <a ' +
      'href="/admin/gnap">' + t.html('consoleGnap.linkSettings') +
      '</a></p>';
    return inner;
  }
}

export = GnapPage;
