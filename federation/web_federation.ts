// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_federation.ts
//
// ---------------------------------------------------------------------------
// FEDERATION, DRAWN FROM ITS VIEW ALONE (#446, 2026-10-05).
//
// Draws `/admin/federation` and its relationship drill-down from the answer of
// `GET /admin-api/federation`: every relationship in either direction, its
// state, the form that adds one, and the settings.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// It was drawn inside the route of `method:federationListPage` in
// `admin-ui/admin.ts`, which still draws the page until the console's cutover
// by calling this with its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('../admin-ui/web_kit');
import SettingsForms = require('../admin-ui/web_settings');

type Json = any;

/**
 * Draws `/admin/federation` and its relationship drill-down from the answer of
 * `GET /admin-api/federation`: every relationship in either direction, its
 * state, the form that adds one, and the settings.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class FederationPage {
  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static body(ctx, json) {
    const wantedText = json.filter.q || '';
    const wantedRole = json.filter.role || '';
    const paging = json.paging;
    const nav = kit.pageNavPair('/admin/federation',
      kit.pageParamsOf(ctx.query),
                                 paging);

    const rows = json.relationships.map(function (row) {
      return '<tr><td><a href="/admin/federation' +
        kit.esc(kit.queryWith(kit.listViewOf('/admin/federation', ctx.query),
                           { relationship: row.id })) +
        '">' + kit.esc(row.id) + '</a>' +
        (row.name !== row.id ? '<span class="sub">' + kit.esc(row.name) +
         '</span>' :
         '') + '</td><td>' + kit.esc(row.roleLabel) + '</td><td>' +
        kit.esc(row.protocolLabel) + '</td><td ' +
        'class="who">' + kit.esc(row.peer || row.application || '') +
        (!row.peer && !row.application ? '<span class="sub">nothing named ' +
                                         'yet</span>' : '') +
        '</td>' +
        FederationPage.federationStateCell(row) +
        '<td class="num">' + row.authentications + '</td>' +
        '<td class="num">' + row.users + '</td>' +
        '<td>' + (row.lastError
          ? '<span class="bad">' + kit.shortened(row.lastError, 60) + '</span>'
          : '<span class="sub">none recorded</span>') + '</td></tr>';
    }).join('');

    const roleOptions = ['<option value="">any role</option>'].concat(
      json.roles.map(function (one) {
        const n = json.roleCounts[one.role] || 0;
        return '<option value="' + kit.esc(one.role) + '"' +
          (one.role === wantedRole ? ' selected' : '') + '>' +
          kit.esc(one.short) +
          ' (' + n + ')</option>';
      })).join('');

    const inner = '<div class="tiles">' +
      kit.tile(json.relationshipCount, 'Relationships') +
      kit.tile(json.ready, 'Ready') +
      kit.tile(json.enabledNotConfigured, 'Enabled, not configured') +
      kit.tile(json.authentications, 'Federated sign-ins') +
      '</div>' +
      FederationPage.federationCaveat() +
      // THE PICTURE, pointed at from the page it drills down from. This table
      // has one row per relationship and no row can say anything about another,
      // so three questions an operator arrives with have no cell here: how many
      // applications are behind a partner, how many people have come through it
      // FOR EACH of them, and what an arriving foreign service provider
      // actually meets. All three are facts about two registers at once.
      kit.note('<a href="/admin/federation/map">The picture</a> draws this ' +
      'register as a diagram, laid out on the server. It adds the three ' +
      'things a table of relationships has nowhere to put: how many ' +
      'applications are configured to use each partner, how many people have ' +
      'signed in through each <em>application and relationship</em> pair, ' +
      'and what the identity-provider side is configured to do about ' +
      'authenticating somebody — including where one relationship brokers to ' +
      'another, which is what makes this service an identity bridge and is ' +
      'invisible in any single row.') +
      '<form method="get" action="/admin/federation"><div class="formrow">' +
      '<label for="q">Relationship</label>' +
      '<input type="text" id="q" name="q" value="' +
      kit.esc(String(ctx.query.q || '')) +
      '" size="24" placeholder="id, name, partner or application">' +
      '<label for="role">Role</label><select id="role" name="role">' +
      roleOptions + '</select><label for="per">Show</label><select id="per" ' +
      'name="per">' + kit.perPageOptions(paging.perPage) +
      '</select><button ' +
      'type="submit">Filter</button>' +
      ((wantedText || wantedRole) ? ' <a href="/admin/federation">clear</a>' :
        '') +
      '</div></form>' + nav.head +
      '<table><tr><th>Relationship</th><th>This service ' +
      'is</th><th>Protocol</th><th>Partner</th><th>State</th><th ' +
      'class="num">Sign-ins</th><th class="num">People</th><th>Last ' +
      'refusal</th></tr>' +
      (rows || '<tr><td colspan="8">No federation relationship ' +
        ((wantedText || wantedRole) ? 'matches. The filter above may be ' +
                                      'hiding some.'
          : 'is configured. Nothing federated happens until one is — and ' +
            'then not until it is enabled, which is a second, deliberate ' +
            'act.') + '</td></tr>') +
      '</table>' + nav.foot +
      FederationPage.federationCreateForm(json.roles, json.protocols) +
      '<h2>The two directions</h2>' +
      '<table><tr><th>This service is</th><th>What it means</th></tr>' +
      json.roles.map(function (one) {
        return '<tr><td>' + kit.esc(one.short) + '</td><td>' +
               kit.esc(one.what) +
               '</td></tr>';
      }).join('') + '</table>' +
      kit.note('<strong>One relationship is one DIRECTION.</strong> A ' +
      'partner this service both consumes from and asserts to is two ' +
      'relationships with two ids, because everything that configures one ' +
      'differs by direction — the endpoints are theirs or ours, the ' +
      'certificate is theirs or ours, the attribute mapping runs inbound or ' +
      'the release list runs outbound.') +
      '<h2>The five protocols</h2><table><tr><th>Protocol</th><th>What ' +
      'happens</th><th>Specification</th></tr>' +
      json.protocols.map(function (one) {
        return '<tr><td>' + kit.esc(one.label) + '</td><td>' +
               kit.esc(one.what) +
          '</td><td ' +
          'class="sub">' + kit.esc(one.spec) + '</td></tr>';
      }).join('') + '</table>' +
      // The federation.* rows (fifteen as of 2026-09-16), on the page that
      // configures the feature. `federation.enabled` and `federation.outbound`
      // are the two that turn halves of it off, and a person reading a
      // relationship that does not work should not have to guess that the
      // answer is a setting somewhere else.
      SettingsForms.forms(json.settings, '/admin/federation') +
      FederationPage.federationLinks(json.paths.base);

    return inner;
  }

  // THE STATE CELL, and it is the most important thing on the page. Four states
  // and each is a different instruction to the reader, which is why they are
  // four sentences rather than a boolean and a tooltip.
  /**
   * Draws a federation relationship's state as a table cell: ready,
   * disabled, or enabled and not configured with what is still missing.
   *
   * @param row - the relationship's row
   * @returns the cell as HTML
   */
  static federationStateCell(row) {
    if (row.usable) {
      return '<td class="ok">ready</td>';
    }
    if (!row.enabled) {
      return '<td class="off">disabled' +
        (row.ready ? '' : ' <span class="sub">and not configured</span>') +
             '</td>';
    }
    return '<td class="bad">ENABLED, not configured<span class="sub">' +
      kit.esc(row.missing.join(', ')) + ' still to set. It refuses rather ' +
      'than half-working.</span></td>';
  }

  /**
   * Draws the form that adds a federation relationship.
   *
   * @returns the form as HTML
   */
  static federationCreateForm(roles, protocols) {
    return '<h2>Add a relationship</h2>' +
      kit.note('It is created <strong>disabled</strong>, whatever is filled ' +
      'in here, and nothing about it does anything until it is enabled on ' +
      'its own page. That is not caution for its own sake: a partner that ' +
      'half-exists and silently accepts assertions is the failure this whole ' +
      'register is arranged to prevent, and enabling is the second, ' +
      'deliberate act that says the configuration is finished.') +
      '<form method="post" action="/admin/federation"><div ' +
      'class="formrow"><input type="hidden" name="action" ' +
      'value="create"><label for="fedid">Id</label><input type="text" ' +
      'id="fedid" name="id" size="16" required ' +
      'placeholder="partner-a"><label for="fedrole">This service ' +
      'is</label><select id="fedrole" name="role">' +
      roles.map(function (one) {
        return '<option value="' + kit.esc(one.role) + '">' +
               kit.esc(one.short) +
               '</option>';
      }).join('') + '</select>' +
      '<label for="fedprotocol">Protocol</label>' +
      '<select id="fedprotocol" name="protocol">' +
      protocols.map(function (one) {
        return '<option value="' + kit.esc(one.protocol) + '">' +
               kit.esc(one.label) +
               '</option>';
      }).join('') + '</select><label for="fedname">Name</label><input ' +
      'type="text" id="fedname" name="name" size="16" ' +
      'placeholder="optional"><label for="fedpeer">Partner</label><input ' +
      'type="text" id="fedpeer" name="peer" size="26" placeholder="their ' +
      'entityID, issuer or realm"><button ' +
      'type="submit">Add</button></div></form>' +
      kit.note('The <strong>id</strong> is the key, the RDN and a URL ' +
      'segment, so it has to start with a letter or a digit and hold only ' +
      'letters, digits, dot, dash and underscore. <strong>Partner</strong> ' +
      'is their own identifier in whatever their protocol calls it, and on a ' +
      'service-provider-side relationship it is CHECKED: an assertion whose ' +
      'issuer is not that string is refused, even when the signature ' +
      'verifies.');
  }

  /**
   * Draws the caveat both federation pages carry.
   *
   * @returns the caveat as HTML
   */
  static federationCaveat() {
    return (
      kit.note('<strong>This is the one feature here that has to be ' +
      'configured before it will do anything, and the one page in this ' +
        'console ' +
      'that configures a REFUSAL.</strong> Everywhere else this service ' +
      'accepts what it is given — any username, any client_id, any entityID, ' +
      'any LDAP bind. It cannot do that at an assertion consumer service: ' +
        'what ' +
      'arrives there is an unauthenticated HTTP request claiming to be a ' +
      'person, and the session it would produce is the same one ' +
      '<code>/oauth2/authorize</code>, <code>/wsfed</code>, ' +
      '<code>/saml2</code> and this console all read. A permissive version ' +
        'of ' +
      'it would not be a permissive mock; it would be an ' +
      'authentication bypass for every protocol in this process.') +
      kit.note('<strong>The gate is on the SIGNER, and on the SUBJECT ' +
      'too (#109).</strong> A verified assertion signs in only the person ' +
        'its ' +
      'partner\'s subject is LINKED to — a <code>federationLink</code> on ' +
        'the ' +
      'entry. What happens to a subject nobody linked is the relationship\'s ' +
      '<code>fedSubjectPolicy</code>: the person it names signs in here ' +
        'first ' +
      'and is then linked (<code>link-at-first-sign-in</code>, the default), ' +
      'it is refused (<code>pre-linked</code>), it gets a new entry of its ' +
        'own ' +
      '(<code>jit-namespaced</code>), or — in development only — the old ' +
        'name ' +
      'match (<code>any-existing</code>). Three rules narrow it further, ' +
        'and a ' +
      'console administrator is refused unless ' +
      '<code>fedMayAssertAdministrators</code> is on. Nothing is written ' +
        'onto ' +
      'an entry before all of that has passed.'));
  }

  /**
   * Draws the links at the foot of the federation pages.
   *
   * @param base - the federation index's path (`federation.PATHS.base`)
   * @returns the links as HTML
   */
  static federationLinks(base) {
    return (
      '<p class="sub"><a href="/admin/federation/map">the picture</a> ' +
        '&middot; ' +
      '<a href="' + base + '">the federation index</a> &middot; ' +
      '<a href="/admin/applications">the applications registry</a> &middot; ' +
        '<a ' +
      'href="/admin/users">who has signed in</a> &middot; <a ' +
      'href="/admin/ldap/federations">the register as the directory sees ' +
      'it</a></p>');
  }
}

export = FederationPage;
