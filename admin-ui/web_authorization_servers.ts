// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_authorization_servers.ts
//
// ---------------------------------------------------------------------------
// PROTOCOLS → AUTHORIZATION SERVERS, DRAWN FROM ITS VIEW ALONE (#446,
// 2026-10-05).
//
// Draws `/admin/authorization-servers` from the answer of `GET
// /admin-api/authorization-servers`: every named authorization server, its
// overrides and drift, and the form that adds one.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// It was drawn inside the route of `method:asListPage` in `admin-ui/admin.ts`,
// which still draws the page until the console's cutover by calling this with
// its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');

type Json = any;

const AS_LINKS =
  '<p class="sub"><a href="/.well-known/oauth-authorization-server">the ' +
  'default RFC 8414 document</a> &middot; <a ' +
  'href="/.well-known/openid-configuration">the default OpenID Provider ' +
  'Configuration</a> &middot; <a href="/admin/applications">the clients that ' +
  'read them</a></p>';

/**
 * Draws `/admin/authorization-servers` from the answer of `GET
 * /admin-api/authorization-servers`: every named authorization server, its
 * overrides and drift, and the form that adds one.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class AuthorizationServersPage {
  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static body(ctx, json) {
    const paging = json.paging;
    const nav = kit.pageNavPair('/admin/authorization-servers',
                        { per: ctx.query.per ? paging.perPage : '' }, paging);

    const listView = kit.listViewOf('/admin/authorization-servers', ctx.query);
    const rows = json.authorizationServers.map(function (row) {
      const drift = row.drift;
      // The link carries the list AS IT IS BEING VIEWED, which is what lets the
      // trail on the other side come back to this page of this filter rather
      // than to the top of everything. See listViewOf().
      const href = '/admin/authorization-servers' +
                   kit.queryWith(listView, { profile: row.id });
      return '<tr><td><a href="' + kit.esc(href) + '"><code>' +
             kit.esc(row.id) +
        '</code></a></td><td>' + kit.esc(row.label || '') + '</td><td ' +
        'class="num">' + Object.keys(row.overrides).length + '</td>' +
        '<td class="num">' + row.removed.length + '</td>' +
        '<td class="num">' + (drift.length
          ? '<span class="state-expired" title="Members whose published ' +
            'value disagrees with what this service would ' +
            'publish.">' + drift.length + '</span>'
          : '<span class="state-none">0</span>') + '</td>' +
        '<td><code>' + kit.esc(row.urls.authorize) + '</code><br><code>' +
        kit.esc(
            row.urls.token) +
        '</code><div class="sub">metadata at <code>' + kit.esc(
            row.urls.oidc) + '</code></div></td><td>' + (row.autoCreated
          ? '<span class="sub">asked for</span>' : '<span ' +
                                                   'class="sub">configured' +
                                                   '</span>') +
        '</td><td class="num">' + kit.esc(row.seen) + '</td></tr>';
    }).join('');

    const inner = '<div class="tiles">' +
      kit.tile(json.profileCount, 'Profiles') +
      kit.tile(json.overrideTotal, 'Overrides') +
      kit.tile(json.driftTotal, 'Drifting members') +
      '</div>' +
      kit.note('<strong>One process, several authorization ' +
      'servers.</strong> The path component the two discovery shapes already ' +
      'carry now selects a CONFIGURATION as well as an issuer identifier ' +
      '&mdash; RFC 8414 section 3.1 <em>inserts</em> it after the well-known ' +
      'segment and OpenID Connect Discovery section 4 <em>appends</em> the ' +
      'well-known segment to it, which is the commonest reason a discovery ' +
      'fetch 404s, and this service has answered both for a long time. ' +
      '<strong>A path nobody has configured publishes the document this ' +
      'service always published</strong>, so nothing that worked before this ' +
      'page existed behaves differently.') +
      nav.head +
      '<table><tr><th>Authorization server</th><th>Label</th><th ' +
      'class="num">Overrides</th><th class="num">Removed</th><th ' +
      'class="num">Drift</th><th>Its endpoints</th><th>Came from</th><th ' +
      'class="num">Asked for</th></tr>' +
      (rows || '<tr><td colspan="8">No authorization server has been named. ' +
               'Every discovery URL answers with the document this service ' +
               'builds for itself, which is what RFC 9700 section 2.6 asks ' +
               'for &mdash; these are for when you need it to say something ' +
               'else.</td></tr>') +
      '</table>' +
      nav.foot +
      '<h2>Add an authorization server</h2><form method="post" ' +
      'action="/admin/authorization-servers"><div class="formrow"><input ' +
      'type="hidden" name="action" value="create"><label ' +
      'for="asid">Id</label><input type="text" id="asid" name="id" size="18" ' +
      'required placeholder="tenant1"><label ' +
      'for="aslabel">Label</label><input type="text" id="aslabel" ' +
      'name="label" size="20" placeholder="optional"><label ' +
      'for="asdesc">Note</label><input type="text" id="asdesc" ' +
      'name="description" size="28" placeholder="what it is for"><button ' +
      'type="submit">Add</button></div></form>' +
      kit.note('The id is a single URL path segment &mdash; letters, ' +
      'digits, dot, dash, underscore or tilde &mdash; because it has to ' +
      'appear in a URL without being escaped. One that had to be escaped ' +
      'would be one nobody could find again.') +
      AuthorizationServersPage.asCaveat() + AS_LINKS;

    return inner;
  }

  /**
   * Draws the caveat both authorization-server pages carry.
   *
   * @returns the caveat as HTML
   */
  static asCaveat() {
    return (
      kit.note('<strong>What a document says is what that ' +
      'authorization server DOES.</strong> Advertise ' +
      '<code>code_challenge_methods_supported: ["S256"]</code> here and this ' +
      'server\'s own authorization endpoint refuses <code>plain</code> — at ' +
      '<code>/{id}/oauth2/authorize</code>, and nowhere else. The members ' +
      'marked <em>enforced</em> below drive behaviour; the rest are ' +
        'published ' +
      'and cannot be made true by this service, which is still useful (a ' +
      'document a client did not expect is a client error path worth ' +
        'running) ' +
      'and is listed ' +
      'as <em>drift</em> so that nobody discovers it the hard way.') +
      kit.note('<strong>Every authorization server starts ' +
      'equal.</strong> A new one — or one created by somebody simply asking ' +
      'for it — has exactly the capabilities the default server has, and ' +
      'differs only where it has been made to. <strong>Every client may use ' +
      'every one of them</strong>: nothing here restricts a client to a ' +
      'server, and <a href="/admin/applications">the applications page</a> ' +
      'records which ones each client has actually used. What does NOT cross ' +
      'between them is a credential — an authorization code issued by one is ' +
      'refused at another\'s ' +
      'token endpoint.'));
  }
}

export = AuthorizationServersPage;
