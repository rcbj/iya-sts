// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_groups.ts
//
// ---------------------------------------------------------------------------
// DIRECTORY → GROUPS, DRAWN FROM ITS VIEW ALONE (#446, 2026-10-05).
//
// Draws `/admin/groups` from the answer of `GET /admin-api/groups`: every
// group in the directory, filtered and paged, the create form when the
// process has a group writer, and the settings of the groups claim — and
// the pieces the group drill-down shares with it: the listener warning, the
// rule cell, the caveat and the links.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// It was drawn by `AdminConsole.groupsListPage()` in `admin-ui/admin.ts`,
// which still draws the page until the console's cutover by calling this
// with its view passed through JSON; the console's `groupLabel()`,
// `groupRuleCell()` and `directoryListenerWarning()` delegate here.
//
// THE CAVEAT WAS A WIRE-TIME CONSTANT that read the two console groups out
// of the configuration when the console was built. A page drawn in a browser
// has no configuration, so the answer carries the two names (`adminGroups`)
// and the caveat is drawn from them.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');
import SettingsForms = require('./web_settings');

type Json = any;

/**
 * Draws Directory → Groups from the answer of `GET /admin-api/groups`, and
 * the pieces the group drill-down shares with it.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class GroupsPage {
  // How a socket warning names what a page shows. A warning about sockets
  // has to name the thing the reader came for — the whole point of it is the
  // gap between "this service holds it" and "an LDAP client can fetch it" —
  // and that sentence needs a noun that agrees with itself.
  static readonly ENTRY_SUBJECT = { upper: 'The entry below',
                                    lower: 'the entry below',
                                    verb: 'is', pronoun: 'it' };

  static readonly GROUPS_SUBJECT = { upper: 'The groups below',
                                     lower: 'the groups below',
                                     verb: 'are', pronoun: 'they' };

  static readonly GROUP_SUBJECT = { upper: 'The group below',
                                    lower: 'the group below',
                                    verb: 'is', pronoun: 'it' };

  // Why this entry counted as a group, in words. The rule is ldap_server.js's;
  // this is only its three values spelled out, and it is on the page because
  // "developers is a group" is uninteresting next to "this entry is a group
  // because somebody put it under ou=groups and it carries no group
  // objectClass at all".
  static readonly GROUP_RULES: Json = {
    both: { label: 'placement + objectClass',
            title: 'It is under ou=groups AND carries a group objectClass. ' +
                   'This is what a group written the conventional way looks ' +
                   'like.' },
    placement: { label: 'placement only',
                 title: 'It is under ou=groups but carries no group ' +
                        'objectClass. This directory is schemaless, so ' +
                        'nothing refused the add — it is listed here ' +
                        'because of where it sits.' },
    objectClass: { label: 'objectClass only',
                   title: 'It carries a group objectClass but sits outside ' +
                          'ou=groups. Nothing here requires a group to live ' +
                          'under the groups container.' }
  };

  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of `GET /admin-api/groups`
   * @returns the body as HTML
   */
  static body(ctx, json) {
    const wantedText = json.filter.q || '';
    const paging = json.paging;
    const filterParams = { q: wantedText,
                           per: ctx.query.per ? paging.perPage : '' };
    const nav = kit.pageNavPair('/admin/groups', filterParams, paging);
    const listView = kit.listViewOf('/admin/groups', ctx.query);
    const rows = json.groups.map(function (group) {
      // The link carries the list AS IT IS BEING VIEWED, which is what lets
      // the trail on the other side come back to this page of this filter
      // rather than to the top of everything. See listViewOf().
      const href = '/admin/groups' +
                   kit.queryWith(listView, { group: group.dn });
      return '<tr><td><a href="' + kit.esc(href) + '">' +
             kit.esc(GroupsPage.groupLabel(group)) +
        '</a></td><td ' +
        'class="who"><code>' + kit.esc(group.dn) + '</code></td>' +
        '<td>' + GroupsPage.groupRuleCell(group.rule) + '</td>' +
        '<td class="num">' + group.memberCount + '</td>' +
        '<td class="num">' + (group.presentCount
          ? '<span class="state-valid">' + group.presentCount + '</span>'
          : '<span class="state-none">0</span>') + '</td>' +
        '<td class="num">' + (group.danglingCount
          ? '<span class="state-revoked" title="Membership values naming an ' +
            'entry this directory does not hold. Deleting a user does not ' +
            'remove it from the groups that list it — referential integrity ' +
            'is a directory feature and not a protocol rule, and this ' +
            'directory deliberately does not have it.">' +
            group.danglingCount + '</span>'
          : '<span class="state-none">0</span>') + '</td>' +
        '<td class="num">' + (group.claimedCount
          ? '<span class="state-expired" title="Entries whose own memberOf ' +
            'names this group and which this group does not list back. ' +
            'Nothing here maintains memberOf, so a client that writes it ' +
            'creates exactly this disagreement.">' + group.claimedCount +
            '</span>'
          : '<span class="state-none">0</span>') + '</td>' +
        '<td class="num">' + group.attributeCount + '</td>' +
        '<td>' + kit.esc(group.origin) + '</td>' +
        '<td><code>' + kit.esc(group.modifiedAt) + '</code></td></tr>';
    }).join('');

    return GroupsPage.directoryListenerWarning(json,
                                               GroupsPage.GROUPS_SUBJECT) +
      '<div class="tiles">' +
      kit.tile(json.groupCount, 'Groups') +
      kit.tile(json.membershipValues, 'Membership values') +
      kit.tile(json.dangling, 'Dangling') +
      kit.tile(json.entryCount, 'Entries in the directory') +
      '</div><form method="get" action="/admin/groups"><div ' +
      'class="formrow"><label for="q">Group</label><input type="text" ' +
      'id="q" name="q" value="' + kit.esc(wantedText) + '" ' +
      'size="28" placeholder="part of a cn or a DN"><label for="per">Per ' +
      'page</label><select id="per" ' +
      'name="per">' + kit.perPageOptions(paging.perPage) +
      '</select><button ' +
      'type="submit">Filter</button>' +
      (wantedText ? ' <a href="/admin/groups">clear</a>' : '') +
      '</div></form>' +
      nav.head +
      '<table><tr><th>Group</th><th>DN</th><th>Counted because</th><th ' +
      'class="num">Members</th><th class="num">Resolve</th><th ' +
      'class="num">Dangling</th><th class="num">Claimed</th><th ' +
      'class="num">Attributes</th><th>Came from</th><th>Last ' +
      'modified</th></tr>' +
      (rows || '<tr><td colspan="10">No group matches. ' +
               (wantedText ? 'The filter above may be hiding some.' : 'This ' +
                'directory holds none — the two it seeds can be deleted ' +
                'through the protocol like any other entry.') +
               '</td></tr>') + '</table>' +
      nav.foot +
      kit.note('A group is an entry that sits under <code>' +
                kit.esc(json.groupsDn) +
      '</code>, or that carries one of the group object classes ' +
      '(<code>groupOfNames</code>, <code>groupOfUniqueNames</code>, ' +
      '<code>posixGroup</code>, <code>groupOfURLs</code>) wherever it sits ' +
      '&mdash; either rule is enough, and the column above says which one ' +
      'caught each. Both are applied because this directory is ' +
      '<strong>schemaless</strong>: nothing stops a client adding a ' +
      '<code>groupOfNames</code> under <code>' + kit.esc(json.usersDn) +
      '</code>, or an entry with no <code>objectClass</code> at all under ' +
      'the groups container, and a page that applied only one rule would ' +
      'answer for one of those and quietly lose the other.') +
      kit.note('<strong>Members</strong> counts the values of ' +
      '<code>member</code>, <code>uniqueMember</code> and ' +
      '<code>memberUid</code> together; <strong>Resolve</strong> is how many ' +
      'of them name an entry this directory actually holds and ' +
      '<strong>Dangling</strong> is the rest. The two are shown apart ' +
      'because a group whose seven members resolve to five is this ' +
      'directory doing exactly what it says it does &mdash; deleting a user ' +
      'leaves its DN in every group that listed it &mdash; and one combined ' +
      'number would report that as seven members with nothing wrong. ' +
      '<strong>Claimed</strong> is the disagreement in the other direction: ' +
      'entries whose own <code>memberOf</code> names the group while the ' +
      'group does not list them back.') +
      // THE ONE CONTROL ON THIS LIST (rule 7's mirror is
      // POST /admin-api/groups/create). Below the table rather than above it,
      // because the question this page is usually open to answer is "what is
      // in this directory" and a create form at the top would answer a
      // different one first. A REAL BUTTON AND NO SCRIPT, like every other
      // form on this console.
      (json.canWrite
        ? '<h2>Create a group</h2>' +
          '<form method="post" action="/admin/groups">' +
          '<input type="hidden" name="action" value="create">' +
          '<input type="hidden" name="back" value="' +
          kit.esc(kit.queryWith(listView, {})) + '">' +
          '<div class="formrow">' +
          '<label for="newgroup">cn</label>' +
          '<input type="text" id="newgroup" name="group" size="28" required ' +
          'placeholder="developers">' +
          '<label for="newnote">Description</label>' +
          '<input type="text" id="newnote" name="note" size="40" ' +
          'placeholder="what this group is for">' +
          '</div><div class="formrow">' +
          '<label for="newmembers">Members</label>' +
          '<textarea id="newmembers" name="members" rows="3" cols="60" ' +
          'placeholder="alice&#10;bob&#10;cn=another-group,' +
          kit.esc(json.groupsDn) + '"></textarea>' +
          '<button type="submit">Create</button>' +
          '</div></form>' +
          kit.note('It goes to <code>cn=&lt;what you typed&gt;,' +
          kit.esc(json.groupsDn) + '</code> as a <code>groupOfNames</code>, ' +
          'so it is counted here by <em>both</em> rules. <strong>Members are ' +
          'one per line or comma-separated</strong>, and each may be a user ' +
          'name or any DN — a group can hold another group, and no user name ' +
          'names one. A name with no entry behind it is written as a ' +
          '<strong>dangling</strong> member rather than refused: this ' +
          'directory does no referential integrity in either direction, and ' +
          'refusing here would make the state the Dangling column reports ' +
          'impossible to produce from this page. Leaving the box empty ' +
          'creates a group with no members, which RFC 4519 says a real ' +
          'directory would refuse and this schemaless one does not.')
        : kit.note('<strong>No group can be created from here.</strong> The ' +
          'list above is read through one slot and the writes through ' +
          'another, and this process has only the first — a build without ' +
          '<code>ldap_server.js</code>\'s group writer. An ' +
          '<code>ldapadd</code> and <code>POST /scim/v2/Groups</code> are ' +
          'unaffected.')) +
      SettingsForms.forms(json.settings, '/admin/groups') +
      GroupsPage.groupsCaveat(json.adminGroups) + GroupsPage.groupsLinks();
  }

  /**
   * Names a group for a person: its cn, or a placeholder when it has none.
   *
   * @param group - the group as the directory reader returns it
   * @returns the label as plain text
   */
  static groupLabel(group) {
    return group.cn || '(no cn)';
  }

  /**
   * Draws the cell saying which rule made an entry count as a group.
   *
   * @param rule - the rule's key in GROUP_RULES
   * @returns the cell's HTML, with the rule's explanation as a tooltip
   */
  static groupRuleCell(rule) {
    const rendered = GroupsPage.GROUP_RULES[rule];
    if (!rendered) {
      return '<span class="state-none">' + kit.esc(rule || 'unstated') +
             '</span>';
    }
    return '<span title="' + kit.esc(rendered.title) + '">' +
           kit.esc(rendered.label) +
           '</span>';
  }

  // A page that reads the directory answers over HTTP whether or not its
  // sockets bound, so a page reporting a full directory while no LDAP client
  // could reach it says so — the silence costs somebody an afternoon looking
  // for a directory that was there all along.
  /**
   * Draws a warning when either of the directory's listeners (plain LDAP
   * and LDAPS) is not up, saying which.
   *
   * @param info - the LDAP server's listener state
   * @param subject - the wording for what the page shows (upper, lower,
   *   verb, pronoun)
   * @returns the warning as HTML, or '' when both are listening
   */
  static directoryListenerWarning(info, subject) {
    if (!info.listening && !info.ldapsListening) {
      return kit.warn('<strong>The directory\'s listeners are not ' +
        'up</strong> — ' +
        kit.esc(info.listenError || 'it never bound') + '. ' + subject.upper +
        ' ' + subject.verb +
        ' in this process\'s store and ' + subject.verb + ' what an LDAP ' +
        'client WOULD read; right now no client can connect, most likely ' +
        'because TCP ' + kit.esc(info.port) +
        ' was already taken. This page is HTTP and answers either way.');
    }
    if (!info.listening) {
      return kit.warn('<strong>The directory\'s plain listener is not ' +
        'up</strong> — ' +
        kit.esc(info.listenError || 'it never bound') + ' — but ' +
        '<strong>LDAPS on ' +
        kit.esc(info.ldapsPort) + ' is</strong>, so ' + subject.lower + ' ' +
        subject.verb +
        ' reachable over TLS. TCP ' + kit.esc(info.port) + ' was most ' +
        'likely already taken.');
    }
    if (info.ldapsPort && !info.ldapsListening) {
      return kit.warn('The plain listener on ' + kit.esc(info.port) + ' is ' +
        'up; <strong>LDAPS is not</strong>. That affects how ' +
        subject.lower + ' can be reached, not ' +
        'whether ' + subject.pronoun + ' ' + subject.verb + ' there.');
    }
    return '';
  }

  // What this directory's groups are and are not, said on both pages.
  // Repeated rather than shown once on the list, for the reason the
  // open-console banner is repeated: the page somebody arrives at directly is
  // exactly the one that needs it. CARRYING a fact and ACTING on it are
  // different claims, and the notes say them in that order.
  /**
   * Draws the caveat both groups pages carry.
   *
   * @param adminGroups - the two console groups (`read`, `write`)
   * @returns the caveat as HTML
   */
  static groupsCaveat(adminGroups) {
    const named = adminGroups || {};
    return kit.note('<strong>A group here grants nothing, with exactly ' +
      'two exceptions and they are named below.</strong> No ' +
      '<em>endpoint</em> in this service checks a group, and nothing in any ' +
      'protocol decides anything on one. Adding somebody to ' +
      '<code>cn=directory-admins</code> changes what a directory client ' +
      'sees, and what a token <em>says</em>, and changes nothing at all ' +
      'about what that token can DO &mdash; on a service that ' +
      'authenticates nobody, it could hardly be otherwise.') +
      // THE EXCEPTION, said HERE and not only on the page that owns it. A
      // reader meeting this caveat and then finding cn=admin-write in the
      // table above it would be entitled to conclude that one of the two was
      // lying.
      kit.note('<strong>The two exceptions are <code>' +
      kit.esc(named.read) + '</code> and <code>' +
      kit.esc(named.write) + '</code>, which ' +
      'decide who may use THIS CONSOLE</strong> &mdash; see <a ' +
      'href="/admin/rbac">Admin roles</a>, where they are granted and taken ' +
      'away. They are ordinary groups and appear in the table above like ' +
      'any other, deliberately: the alternative was a membership store of ' +
      'the console\'s own that an <code>ldapmodify</code> could not see. ' +
      'Even those two grant nothing outside <code>/admin</code> &mdash; no ' +
      'token, assertion, ticket, PAC or credential is changed by being in ' +
      'one, and every protocol endpoint answers a member exactly as it ' +
      'answers anybody else.') +
      kit.note('<strong>A token can now carry one.</strong> With ' +
      '<code>groups.claim</code> on &mdash; it is on by default &mdash; ' +
      'every OAuth 2.0 access token, OIDC ID Token, SAML 2.0 assertion and ' +
      'SAML 1.1 assertion this service issues carries a claim naming the ' +
      'groups its subject is in, read from these entries at the moment it ' +
      'is minted. Somebody in no group gets no claim at all rather than an ' +
      'empty list. What it is called, whether each value is a ' +
      '<code>cn</code> or a whole DN, and whether a person\'s own ' +
      '<code>memberOf</code> counts are the four settings at the foot of ' +
      'this page; <a href="/admin/claims">the claims page</a> shows what it ' +
      'would say about one person. No Kerberos PAC and no ' +
      'WS-Federation-specific token carries a group either way.');
  }

  /**
   * Draws the links at the foot of both groups pages.
   *
   * @returns the links as HTML
   */
  static groupsLinks() {
    return kit.note('<a href="/admin/ldap/service">What this directory ' +
      'is</a> &middot; <a href="/admin/ldap/directory">every entry in ' +
      'it</a> &middot; <a href="/admin/ldap/directory?format=json">the same ' +
      'as JSON</a> &middot; <a href="/admin/users">the people who have ' +
      'authenticated here</a>.');
  }
}

export = GroupsPage;
