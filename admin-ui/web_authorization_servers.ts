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

  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static detail(ctx, json) {
    const profile = json.found ? json : null;
    const carryBack = '<input type="hidden" name="back" value="' +
      kit.esc(kit.queryWith(kit.listViewOf('/admin/authorization-servers',
                                         ctx.query), {})) +
      '">';
    let inner;
    if (!profile) {
      inner = '<p class="warn">There is no authorization server profile ' +
        'called ' +
          '<code>' + kit.esc(json.id) +
          '</code>. Its discovery URLs still answer &mdash; with the ' +
          'document this service builds and the issuer taken from the path ' +
          '&mdash; because an unconfigured path component has always been ' +
          'served that way rather than 404\'d.</p>' + AS_LINKS;
    } else {
      const id = profile.id;
      const drift = profile.drift;
      const capabilities = profile.capabilities;
      const memberRows = Object.keys(profile.overrides)
                               .sort()
                               .map(function (member) {
        const spec = json.members.filter(function (row) {
          return row.name === member;
        })[0];
        const bad = drift.filter(function (d) {
          return d.member === member;
        })[0];
        return '<tr><td><code>' + kit.esc(member) + '</code></td>' +
          '<td><code>' + kit.esc(JSON.stringify(profile.overrides[member])) +
          '</code></td><td>' + (bad
            ? '<span class="state-expired">' + kit.esc(bad.kind) +
              '</span><div ' +
                'class="sub">' +
              kit.esc(bad.what) + '</div>'
            : '<span class="state-valid">agrees</span>') + '</td>' +
          '<td class="sub">' + kit.esc(spec ? spec.what : 'Not a member this ' +
            'service recognises — which is allowed, and is half the point: ' +
            'publishing something a client did not expect is what this page ' +
              'is ' +
            'for.') + '</td>' +
          '<td><form method="post" action="/admin/authorization-servers">' +
          carryBack +
          '<input type="hidden" name="action" value="reset">' +
          '<input type="hidden" name="profile" value="' + kit.esc(id) + '">' +
          '<input type="hidden" name="member" value="' + kit.esc(member) +
            '">' +
          '<button type="submit">Reset</button></form></td></tr>';
      }).join('');

      const removedRows = profile.removed.map(function (member) {
        return '<tr><td><code>' + kit.esc(member) + '</code></td><td ' +
          'class="sub">Not published at all. A client reading this document ' +
          'cannot tell that this server supports it &mdash; which is not the ' +
          'same as learning that it does not, and is the difference RFC 9700 ' +
          'section 2.6 is arguing about.</td><td><form method="post" ' +
          'action="/admin/authorization-servers">' + carryBack +
          '<input type="hidden" name="action" value="reset">' +
          '<input type="hidden" name="profile" value="' + kit.esc(id) + '">' +
          '<input type="hidden" name="member" value="' + kit.esc(member) +
            '">' +
          '<button type="submit">Put it back</button></form></td></tr>';
      }).join('');

      inner = '<h2><code>' + kit.esc(profile.id) + '</code>' +
        (profile.label ? ' &mdash; ' + kit.esc(profile.label) : '') + '</h2>' +
        (profile.description ? kit.note(kit.esc(profile.description)) : '') +
        '<table><tr><th>Thing</th><th>Value</th></tr>' +
        '<tr><td>RFC 8414 document</td><td><a href="' +
        kit.esc(profile.urls.oauth) +
        '"><code>' +
        kit.esc(profile.urls.oauth) + '</code></a></td></tr>' +
        '<tr><td>OpenID Provider Configuration</td><td><a href="' +
        kit.esc(profile.urls.oidc) +
        '"><code>' + kit.esc(profile.urls.oidc) + '</code></a></td></tr>' +
        '<tr><td>Last changed</td><td><code>' + kit.esc(profile.changedAt) +
        '</code></td></tr></table>' +
        (drift.length
          ? kit.warn('<strong>' + drift.length +
            ' member(s) of this document ' +
            'do not describe this service.</strong> That is allowed and is ' +
            'often the point &mdash; but a client configured from this ' +
            'document will behave as though these were true.')
          : '<div class="ok">Every member of this document agrees with what ' +
            'this service would publish. A client configured from it is ' +
            'configured correctly.</div>') +
        '<h2>What this authorization server does</h2><p class="sub">Its ' +
        'effective capabilities — the defaults every authorization server ' +
          'here ' +
        'starts with, plus whatever this one has been given. This IS the ' +
        'document it publishes and it IS what its endpoints enforce; there ' +
          'is ' +
        'no second table that could disagree with ' +
        'it.</p><table><tr><th>Capability</th><th>This ' +
        'server</th><th>Enforced</th></tr>' +
        json.members
          .filter(function (row) { return row.enforces; })
          .map(function (row) {
            const value = capabilities[row.name];
            return '<tr><td><code>' + kit.esc(row.name) + '</code></td>' +
              '<td>' + (value === undefined
                ? '<span class="state-none">not published — the check does ' +
                  'not ' +
                  'run</span>'
                : '<code>' + kit.esc(JSON.stringify(value)) + '</code>') +
                  '</td>' +
              '<td class="sub">' + kit.esc(row.enforces) + '</td></tr>';
          }).join('') +
        '</table><h2>Overridden ' +
        'members</h2><table><tr><th>Member</th><th>Published ' +
        'as</th><th>Agreement</th><th>What it is</th><th></th></tr>' +
        (memberRows || '<tr><td colspan="5">Nothing is overridden, so this ' +
                       'document says exactly what this service says about ' +
                       'itself.</td></tr>') + '</table>' +
        (removedRows
          ? '<h2>Removed members</h2><table><tr><th>Member</th><th>What that ' +
            'means</th><th></th></tr>' +
            removedRows + '</table>'
          : '') +
        '<h2>Publish a member</h2>' +
        kit.note('The value is read as JSON first and as a plain string if ' +
        'that fails, so <code>["S256"]</code> is a list, <code>false</code> ' +
          'is ' +
        'a boolean and <code>https://example.com/token</code> is a string. ' +
        '<strong>Any member name is accepted</strong> &mdash; the list below ' +
        'is help rather than a schema, and one this service has never heard ' +
          'of ' +
        'is published just the same.') +
        '<form method="post" action="/admin/authorization-servers">' +
          carryBack +
        '<div ' +
        'class="formrow"><input type="hidden" name="action" ' +
          'value="set"><input ' +
        'type="hidden" name="profile" value="' + kit.esc(id) + '">' +
        '<label for="asmember">Member</label>' +
        '<select id="asmember" name="member">' +
          AuthorizationServersPage.asMemberOptions(json, '') +
        '</select><label ' +
        'for="asvalue">as</label><input type="text" id="asvalue" ' +
          'name="value" ' +
        'size="36" placeholder=\'["S256"]\'><button ' +
        'type="submit">Publish</button></div></form><form method="post" ' +
        'action="/admin/authorization-servers">' + carryBack + '<div ' +
        'class="formrow"><input type="hidden" name="action" ' +
          'value="set"><input ' +
        'type="hidden" name="profile" value="' + kit.esc(id) + '">' +
        '<label for="asother">Or any member</label>' +
        '<input type="text" id="asother" name="member" size="30" required ' +
        'placeholder="a name this service has never heard of">' +
        '<label for="asothervalue">as</label>' +
        '<input type="text" id="asothervalue" name="value" size="26">' +
        '<button type="submit">Publish</button>' +
        '</div></form>' +
        '<h2>Stop publishing a member</h2>' +
        '<form method="post" action="/admin/authorization-servers">' +
          carryBack +
        '<div ' +
        'class="formrow"><input type="hidden" name="action" ' +
        'value="remove"><input type="hidden" name="profile" ' +
        'value="' + kit.esc(id) + '">' +
        '<label for="asrem">Remove</label>' +
        '<select id="asrem" name="member">' +
        AuthorizationServersPage.asMemberOptions(json,
          'code_challenge_methods_supported') +
        '</select><button type="submit">Remove it from the ' +
        'document</button><span class="sub">Different from resetting it: ' +
          'reset ' +
        'undoes an override, this publishes an ' +
        'ABSENCE.</span></div></form><h2>Delete this authorization ' +
        'server</h2><form method="post" ' +
        'action="/admin/authorization-servers">' + carryBack + '<div ' +
        'class="formrow"><input type="hidden" name="action" ' +
        'value="delete"><input type="hidden" name="profile" ' +
        'value="' + kit.esc(id) + '"><button ' +
        'type="submit" class="danger">Delete</button><span class="sub">The ' +
          'two ' +
        'URLs go on answering &mdash; with this service\'s own document ' +
        '&mdash; because an unconfigured path has always been served that ' +
        'way.</span></div></form>' +
        AuthorizationServersPage.asCaveat() + AS_LINKS;
    }

    return inner;
  }

  /**
   * Draws the authorization server metadata members as options grouped by
   * their group.
   *
   * @param view - the profile's answer, whose `members` and `memberGroups`
   *   are the catalogue
   * @param selected - the member to mark selected
   * @returns the optgroup elements as HTML
   */
  static asMemberOptions(view, selected) {
    return view.memberGroups.map(function (group) {
      const inGroup = view.members.filter(function (row) {
        return row.group === group;
      });
      return '<optgroup label="' + kit.esc(group) + '">' +
             inGroup.map(function (row) {
        return '<option value="' + kit.esc(row.name) + '"' +
          (row.name === selected ? ' selected' : '') + '>' +
          kit.esc(row.name) +
               '</option>';
      }).join('') + '</optgroup>';
    }).join('');
  }
}

export = AuthorizationServersPage;
