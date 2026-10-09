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

// The links both pages end with. A function of the translator since #539,
// where it was a constant.
const asLinks = function (t) {
  return '<p class="sub"><a href="/.well-known/oauth-authorization-server">' +
    t.html('consoleAuthorizationServers.linkRfc8414') + '</a> &middot; <a ' +
    'href="/.well-known/openid-configuration">' +
    t.html('consoleAuthorizationServers.linkOidc') + '</a> &middot; <a ' +
    'href="/admin/applications">' +
    t.html('consoleAuthorizationServers.linkClients') + '</a></p>';
};

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
    const t = ctx.t;
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
          ? '<span class="state-expired" title="' +
            kit.esc(t.text('consoleAuthorizationServers.driftTitle')) +
            '">' + drift.length + '</span>'
          : '<span class="state-none">0</span>') + '</td>' +
        '<td><code>' + kit.esc(row.urls.authorize) + '</code><br><code>' +
        kit.esc(
            row.urls.token) +
        '</code><div class="sub">' +
        t.html('consoleAuthorizationServers.metadataAt',
               { url: row.urls.oidc }) + '</div></td><td>' + (row.autoCreated
          ? '<span class="sub">' +
            t.html('consoleAuthorizationServers.askedFor') + '</span>'
          : '<span class="sub">' +
            t.html('consoleAuthorizationServers.configured') + '</span>') +
        '</td><td class="num">' + kit.esc(row.seen) + '</td></tr>';
    }).join('');

    const th = function (cls, key) {
      return '<th' + cls + '>' + t.html(key) + '</th>';
    };
    const inner = '<div class="tiles">' +
      kit.tile(json.profileCount,
               t.text('consoleAuthorizationServers.tileProfiles')) +
      kit.tile(json.overrideTotal,
               t.text('consoleAuthorizationServers.tileOverrides')) +
      kit.tile(json.driftTotal,
               t.text('consoleAuthorizationServers.tileDrift')) +
      '</div>' +
      kit.note(t.html('consoleAuthorizationServers.intro')) +
      nav.head +
      '<table><tr>' + th('', 'consoleAuthorizationServers.colAs') +
      th('', 'consoleAuthorizationServers.colLabel') +
      th(' class="num"', 'consoleAuthorizationServers.colOverrides') +
      th(' class="num"', 'consoleAuthorizationServers.colRemoved') +
      th(' class="num"', 'consoleAuthorizationServers.colDrift') +
      th('', 'consoleAuthorizationServers.colEndpoints') +
      th('', 'consoleAuthorizationServers.colCameFrom') +
      th(' class="num"', 'consoleAuthorizationServers.colAskedFor') +
      '</tr>' +
      (rows || '<tr><td colspan="8">' +
               t.html('consoleAuthorizationServers.noneNamed') +
               '</td></tr>') +
      '</table>' +
      nav.foot +
      '<h2>' + t.html('consoleAuthorizationServers.addHeading') +
      '</h2><form method="post" ' +
      'action="/admin/authorization-servers"><div class="formrow"><input ' +
      'type="hidden" name="action" value="create"><label ' +
      'for="asid">' + t.html('consoleAuthorizationServers.id') +
      '</label><input type="text" id="asid" name="id" size="18" ' +
      'required placeholder="tenant1"><label ' +
      'for="aslabel">' + t.html('consoleAuthorizationServers.label') +
      '</label><input type="text" id="aslabel" ' +
      'name="label" size="20" placeholder="' +
      kit.esc(t.text('consoleAuthorizationServers.optional')) + '"><label ' +
      'for="asdesc">' + t.html('consoleAuthorizationServers.note') +
      '</label><input type="text" id="asdesc" ' +
      'name="description" size="28" placeholder="' +
      kit.esc(t.text('consoleAuthorizationServers.whatFor')) + '"><button ' +
      'type="submit">' + t.html('consoleAuthorizationServers.add') +
      '</button></div></form>' +
      kit.note(t.html('consoleAuthorizationServers.idRule')) +
      AuthorizationServersPage.asCaveat(t) + asLinks(t);

    return inner;
  }

  /**
   * Draws the caveat both authorization-server pages carry.
   *
   * @param t - the page's translator (#539)
   * @returns the caveat as HTML
   */
  static asCaveat(t) {
    // `/{id}/oauth2/authorize` holds braces, which a message may not, so it
    // goes in as a parameter; the link splits the second note (#539).
    return (
      kit.note(t.html('consoleAuthorizationServers.caveatDoes',
                      { path: '/{id}/oauth2/authorize' })) +
      kit.note(t.html('consoleAuthorizationServers.caveatEqual') +
      '<a href="/admin/applications">' +
      t.html('consoleAuthorizationServers.applicationsPage') + '</a>' +
      t.html('consoleAuthorizationServers.caveatEqualEnd')));
  }

  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static detail(ctx, json) {
    const t = ctx.t;
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
          'served that way rather than 404\'d.</p>' + asLinks(t);
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
            : '<span class="state-valid">' +
              t.html('consoleAuthorizationServers.agrees') + '</span>') +
          '</td>' +
          '<td class="sub">' + (spec ? kit.esc(spec.what)
            : t.html('consoleAuthorizationServers.unknownMember')) +
          '</td>' +
          '<td><form method="post" action="/admin/authorization-servers">' +
          carryBack +
          '<input type="hidden" name="action" value="reset">' +
          '<input type="hidden" name="profile" value="' + kit.esc(id) + '">' +
          '<input type="hidden" name="member" value="' + kit.esc(member) +
            '">' +
          '<button type="submit">' +
          t.html('consoleAuthorizationServers.reset') +
          '</button></form></td></tr>';
      }).join('');

      const removedRows = profile.removed.map(function (member) {
        return '<tr><td><code>' + kit.esc(member) + '</code></td><td ' +
          'class="sub">' + t.html('consoleAuthorizationServers.notPublished') +
          '</td><td><form method="post" ' +
          'action="/admin/authorization-servers">' + carryBack +
          '<input type="hidden" name="action" value="reset">' +
          '<input type="hidden" name="profile" value="' + kit.esc(id) + '">' +
          '<input type="hidden" name="member" value="' + kit.esc(member) +
            '">' +
          '<button type="submit">' +
          t.html('consoleAuthorizationServers.putBack') +
          '</button></form></td></tr>';
      }).join('');

      inner = '<h2><code>' + kit.esc(profile.id) + '</code>' +
        (profile.label ? ' &mdash; ' + kit.esc(profile.label) : '') + '</h2>' +
        (profile.description ? kit.note(kit.esc(profile.description)) : '') +
        '<table><tr><th>' + t.html('consoleAuthorizationServers.colThing') +
        '</th><th>' + t.html('consoleAuthorizationServers.colValue') +
        '</th></tr>' +
        '<tr><td>' + t.html('consoleAuthorizationServers.rfc8414') +
        '</td><td><a href="' +
        kit.esc(profile.urls.oauth) +
        '"><code>' +
        kit.esc(profile.urls.oauth) + '</code></a></td></tr>' +
        '<tr><td>' + t.html('consoleAuthorizationServers.oidcConfig') +
        '</td><td><a href="' +
        kit.esc(profile.urls.oidc) +
        '"><code>' + kit.esc(profile.urls.oidc) + '</code></a></td></tr>' +
        '<tr><td>' + t.html('consoleAuthorizationServers.lastChanged') +
        '</td><td><code>' + kit.esc(profile.changedAt) +
        '</code></td></tr></table>' +
        (drift.length
          ? kit.warn(t.html('consoleAuthorizationServers.driftWarn',
                            { n: drift.length }))
          : '<div class="ok">' +
            t.html('consoleAuthorizationServers.allAgree') + '</div>') +
        '<h2>' + t.html('consoleAuthorizationServers.doesHeading') +
        '</h2><p class="sub">' +
        t.html('consoleAuthorizationServers.doesNote') +
        '</p><table><tr><th>' +
        t.html('consoleAuthorizationServers.colCapability') + '</th><th>' +
        t.html('consoleAuthorizationServers.colThisServer') + '</th><th>' +
        t.html('consoleAuthorizationServers.colEnforced') + '</th></tr>' +
        json.members
          .filter(function (row) { return row.enforces; })
          .map(function (row) {
            const value = capabilities[row.name];
            return '<tr><td><code>' + kit.esc(row.name) + '</code></td>' +
              '<td>' + (value === undefined
                ? '<span class="state-none">' +
                  t.html('consoleAuthorizationServers.notPublishedCheck') +
                  '</span>'
                : '<code>' + kit.esc(JSON.stringify(value)) + '</code>') +
                  '</td>' +
              '<td class="sub">' + kit.esc(row.enforces) + '</td></tr>';
          }).join('') +
        '</table><h2>' +
        t.html('consoleAuthorizationServers.overriddenHeading') +
        '</h2><table><tr><th>' +
        t.html('consoleAuthorizationServers.colMember') + '</th><th>' +
        t.html('consoleAuthorizationServers.colPublishedAs') + '</th><th>' +
        t.html('consoleAuthorizationServers.colAgreement') + '</th><th>' +
        t.html('consoleAuthorizationServers.colWhat') +
        '</th><th></th></tr>' +
        (memberRows || '<tr><td colspan="5">' +
                       t.html('consoleAuthorizationServers.noneOverridden') +
                       '</td></tr>') + '</table>' +
        (removedRows
          ? '<h2>' + t.html('consoleAuthorizationServers.removedHeading') +
            '</h2><table><tr><th>' +
            t.html('consoleAuthorizationServers.colMember') + '</th><th>' +
            t.html('consoleAuthorizationServers.colMeans') +
            '</th><th></th></tr>' +
            removedRows + '</table>'
          : '') +
        '<h2>' + t.html('consoleAuthorizationServers.publishHeading') +
        '</h2>' +
        kit.note(t.html('consoleAuthorizationServers.publishNote')) +
        '<form method="post" action="/admin/authorization-servers">' +
          carryBack +
        '<div ' +
        'class="formrow"><input type="hidden" name="action" ' +
          'value="set"><input ' +
        'type="hidden" name="profile" value="' + kit.esc(id) + '">' +
        '<label for="asmember">' +
        t.html('consoleAuthorizationServers.member') + '</label>' +
        '<select id="asmember" name="member">' +
          AuthorizationServersPage.asMemberOptions(json, '') +
        '</select><label ' +
        'for="asvalue">' + t.html('consoleAuthorizationServers.as') +
        '</label><input type="text" id="asvalue" ' +
          'name="value" ' +
        'size="36" placeholder=\'["S256"]\'><button ' +
        'type="submit">' + t.html('consoleAuthorizationServers.publish') +
        '</button></div></form><form method="post" ' +
        'action="/admin/authorization-servers">' + carryBack + '<div ' +
        'class="formrow"><input type="hidden" name="action" ' +
          'value="set"><input ' +
        'type="hidden" name="profile" value="' + kit.esc(id) + '">' +
        '<label for="asother">' +
        t.html('consoleAuthorizationServers.anyMember') + '</label>' +
        '<input type="text" id="asother" name="member" size="30" required ' +
        'placeholder="' +
        kit.esc(t.text('consoleAuthorizationServers.neverHeard')) + '">' +
        '<label for="asothervalue">' +
        t.html('consoleAuthorizationServers.as') + '</label>' +
        '<input type="text" id="asothervalue" name="value" size="26">' +
        '<button type="submit">' +
        t.html('consoleAuthorizationServers.publish') + '</button>' +
        '</div></form>' +
        '<h2>' + t.html('consoleAuthorizationServers.stopHeading') +
        '</h2>' +
        '<form method="post" action="/admin/authorization-servers">' +
          carryBack +
        '<div ' +
        'class="formrow"><input type="hidden" name="action" ' +
        'value="remove"><input type="hidden" name="profile" ' +
        'value="' + kit.esc(id) + '">' +
        '<label for="asrem">' + t.html('consoleAuthorizationServers.remove') +
        '</label>' +
        '<select id="asrem" name="member">' +
        AuthorizationServersPage.asMemberOptions(json,
          'code_challenge_methods_supported') +
        '</select><button type="submit">' +
        t.html('consoleAuthorizationServers.removeButton') +
        '</button><span class="sub">' +
        t.html('consoleAuthorizationServers.removeNote') +
        '</span></div></form><h2>' +
        t.html('consoleAuthorizationServers.deleteHeading') +
        '</h2><form method="post" ' +
        'action="/admin/authorization-servers">' + carryBack + '<div ' +
        'class="formrow"><input type="hidden" name="action" ' +
        'value="delete"><input type="hidden" name="profile" ' +
        'value="' + kit.esc(id) + '"><button ' +
        'type="submit" class="danger">' +
        t.html('consoleAuthorizationServers.delete') +
        '</button><span class="sub">' +
        t.html('consoleAuthorizationServers.deleteNote') +
        '</span></div></form>' +
        AuthorizationServersPage.asCaveat(t) + asLinks(t);
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
