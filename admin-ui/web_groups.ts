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

  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static detail(ctx, json) {
    const info = json;
    const back = kit.note('<a href="' +
      kit.esc('/admin/groups' +
               kit.queryWith(kit.listViewOf('/admin/groups', ctx.query), {})) +
      '">Back to the groups</a>.');

    let inner;
    if (!info.found) {
      // Three ways to be here and they are different answers, so they get
      // different words. A 404 is none of them: the console linked here from a
      // list it drew from this same store, and the interesting case is
      // precisely that the store has changed since — a client can delete a
      // group, rename it out of ou=groups, or strip its objectClass through the
      // protocol between one click and the next.
      const because = info.notAGroup
        ? 'There <strong>is</strong> an entry at <code>' +
          kit.esc(info.entryDn) +
          '</code>, ' +
          'and it is not a group: it sits outside ' +
          '<code>' + kit.esc(info.groupsDn) + '</code> ' +
          'and carries no group <code>objectClass</code>. A ' +
          '<code>modifyDN</code> out of the groups container or a ' +
          '<code>modify</code> that deleted the <code>objectClass</code> ' +
          'does exactly this, and neither is refused &mdash; this directory ' +
          'has no schema. <a href="/admin/ldap/directory">The full dump</a> ' +
          'still shows it.'
        : 'Nothing is at <code>' + kit.esc(info.wanted) +
          '</code>. Either it ' +
          'was <code>delete</code>d or <code>modifyDN</code>&rsquo;d through ' +
          'the protocol since the link was drawn, or the DN was typed. DNs ' +
          'are compared case-folded and with the space after each comma ' +
          'ignored, so the spelling is not what is wrong.';
      inner = GroupsPage.directoryListenerWarning(info,
        GroupsPage.GROUP_SUBJECT) +
        kit.note(because) + back;
    } else {
      const group = json.group;
      const known = json.known;
      const params = kit.pageParamsOf(ctx.query);
      const membersNav = kit.pageNavPair('/admin/groups', params,
                                          json.membersPaging);
      const claimedNav = kit.pageNavPair('/admin/groups', params,
                                          json.claimedPaging);
      const memberRows = group.members.map(function (member) {
        const state = member.present
          ? '<span class="state-valid">in the directory</span>'
          : '<span class="state-revoked" title="The value names an entry ' +
            'this ' +
            'directory does not hold. It is shown rather than dropped: ' +
              'nothing ' +
            'here enforces referential integrity, so this is the state the ' +
            'protocol leaves behind when a member is deleted.">dangling</span>';
        return '<tr><td class="who">' + GroupsPage.memberLink(member, known) +
          '</td>' +
          '<td><code>' + kit.esc(member.attribute) + '</code></td>' +
          '<td>' + state + '</td>' +
          '<td>' + kit.esc(member.kind === 'group' ? 'a group' :
                            member.kind === 'entry' ? 'an entry' : '—') +
                            '</td>' +
          '<td>' +
          (member.cn ? kit.esc(member.cn) :
           '<span class="state-none">—</span>') +
          '</td><td>' +
          (member.mail ? '<code>' + kit.esc(member.mail) + '</code>'
                                : '<span class="state-none">—</span>') +
                                  '</td>' +
          '<td>' + GroupsPage.usersPageCell(member.userKey, known) + '</td>' +
          // The raw value, last, because for `member` and `uniqueMember` it is
          // the DN in the first column all over again — and for `memberUid` it
          // is
          // not, which is the whole reason the column is here.
          '<td class="who"><code>' + kit.esc(member.value) +
            '</code></td></tr>';
      }).join('');

      const claimedRows = group.claimed.map(function (entry) {
        return '<tr><td class="who"><code>' + kit.esc(entry.dn) +
               '</code></td>' +
          '<td>' +
          (entry.cn ? kit.esc(entry.cn) : '<span class="state-none">—</span>') +
          '</td><td>' + (entry.mail ? '<code>' + kit.esc(entry.mail) + '</code>'
                               : '<span class="state-none">—</span>') +
                                 '</td>' +
          '<td>' + GroupsPage.usersPageCell(entry.userKey, known) +
            '</td></tr>';
      }).join('');

      const claimedSection = json.claimedPaging.total
        ? '<h2>Entries that claim this group, and that it does not list</h2>' +
          claimedNav.head +
          '<table><tr><th>DN</th><th>cn</th><th>mail</th><th>On the users ' +
          'page</th></tr>' +
          claimedRows + '</table>' +
          claimedNav.foot +
          kit.note('Each of these carries a <code>memberOf</code> naming ' +
            'this ' +
          'group while this group&rsquo;s own <code>member</code> does not ' +
          'name them back. <strong>Nothing here maintains ' +
          '<code>memberOf</code></strong> &mdash; it is not a standard ' +
          'attribute at all (Microsoft&rsquo;s directory and ' +
            'OpenLDAP&rsquo;s ' +
          '<code>memberof</code> overlay both write it, the server keeping ' +
            'it ' +
          'in step with <code>member</code> itself), and a schemaless mock ' +
          'that neither writes nor checks it lets a client create exactly ' +
            'this ' +
          'disagreement in one <code>modify</code>. They are listed apart ' +
            'from ' +
          'the members above rather than merged into them, because which ' +
            'side ' +
          'of the disagreement a name came from is the only interesting ' +
            'thing ' +
          'about it.')
        : '';

      inner = GroupsPage.directoryListenerWarning(info,
        GroupsPage.GROUP_SUBJECT) +
        '<h2>' + kit.esc(GroupsPage.groupLabel(group)) +
        '</h2><table><tr><th>DN</th><th>Counted ' +
        'as a group because</th><th>Came from</th><th>Created</th><th>Last ' +
        'modified</th></tr><tr><td ' +
        'class="who"><code>' + kit.esc(group.dn) + '</code></td>' +
        '<td>' + GroupsPage.groupRuleCell(group.rule) + '</td>' +
        '<td>' + kit.esc(group.origin) + '</td>' +
        '<td><code>' + kit.esc(group.createdAt) + '</code></td>' +
        '<td><code>' + kit.esc(group.modifiedAt) + '</code></td></tr></table>' +
        kit.note('The two timestamps are <em>generalized time</em> ' +
        '(<code>YYYYMMDDHHMMSSZ</code>), which is what a directory shows ' +
        '&mdash; not the ISO 8601 strings the rest of this console uses. An ' +
        'LDAP client bound to <code>ldap://&lt;host&gt;:' +
        kit.esc(info.port) + '</code> reading <code>' + kit.esc(group.dn) +
        '</code> sees exactly the object below, because it <em>is</em> that ' +
        'object and not a copy of it.') +

        kit.perPageForm('/admin/groups', 'group', group.dn,
                         json.membersPaging.perPage,
                         '',
                         kit.filterOnly(kit.listViewOf('/admin/groups',
                                                         ctx.query))) +

        '<h2>Members</h2>' +
        '<div class="tiles">' +
        kit.tile(group.memberCount, 'Membership values') +
        kit.tile(group.presentCount, 'Resolve to an entry') +
        kit.tile(group.danglingCount, 'Dangling') +
        kit.tile(json.claimedPaging.total, 'Claim it back') +
        '</div>' +
        (group.memberCount
          ? membersNav.head +
            '<table><tr><th>Member</th><th>From</th><th>State</th><th>What ' +
              'it ' +
            'is</th><th>cn</th><th>mail</th><th>On the users ' +
              'page</th><th>The ' +
            'value as stored</th></tr>' +
            memberRows + '</table>' + membersNav.foot
          : kit.note('This group lists nobody. An empty ' +
            '<code>groupOfNames</code> is something a real directory refuses ' +
            '&mdash; RFC 4519 makes <code>member</code> MUST &mdash; and ' +
              'this ' +
            'one has no schema, so it is here because something wrote it.')) +
        kit.note('Membership is read from <code>' +
        kit.esc(group.memberAttributes.join('</code>, ' +
        '<code>')) + '</code>. The first two hold a <strong>DN</strong>; ' +
        '<code>memberUid</code> holds a bare user name, which is looked up ' +
        'under <code>' + kit.esc(info.usersDn) + '</code> ' +
        '&mdash; treating the three alike is how a page ends up reporting ' +
        'every <code>posixGroup</code> member as dangling. <strong>Nesting ' +
          'is ' +
        'shown and not expanded</strong>: a member that is itself a group ' +
        'links to its own page, and nobody inside it is counted here, ' +
          'because ' +
        'nothing in this service walks a group tree and a flattened list ' +
          'would ' +
        'be claiming a feature that is not here.') +
        kit.note('The last column links to the users page only for somebody ' +
        'this service has actually seen <strong>authenticate</strong>. The ' +
        'other members are marked <em>never here</em>, and that is not a ' +
        'fault: the directory holds whatever somebody wrote into it — the ' +
        'three people it seeds at startup, and anything a client has added ' +
        'since — while the users page holds whoever has presented a ' +
          'credential ' +
        'to this process. <code>alice</code> is in this directory from the ' +
        'moment it starts and appears on the users page only once somebody ' +
        'signs in as her. A link that was always drawn would usually land on ' +
        '&ldquo;nothing here has authenticated as alice&rdquo;, which reads ' +
          'as ' +
        'a broken link rather than as the answer it is.') +
        claimedSection +

        // ---------------------------------------------------------------------
        // ADD SOMEBODY (2026-09-06). On the drill-down rather than on the list,
        // because it needs a group in hand and this is the page that has one.
        // `back` carries the list AS IT IS BEING VIEWED, which is the rule
        // every
        // form on a drill-down here follows — rebuilt through
        // kit.listViewOf()'s
        // whitelist on the way back rather than echoed, so a hand-written
        // `back`
        // cannot become a redirect this file did not write.
        // ---------------------------------------------------------------------
        (json.canWrite
          ? '<h2>Add a member</h2>' +
            '<form method="post" action="/admin/groups">' +
            '<input type="hidden" name="action" value="add-member">' +
            '<input type="hidden" name="group" value="' + kit.esc(group.dn) +
            '"><input type="hidden" name="back" value="' +
            kit.esc(kit.queryWith(kit.listViewOf('/admin/groups', ctx.query),
              {})) +
            '"><div class="formrow"><label for="newmember">User or ' +
            'DN</label><input type="text" id="newmember" name="member" ' +
            'size="44" required placeholder="alice, or cn=another-group,' +
            kit.esc(info.groupsDn) + '">' +
            '<button type="submit">Add</button>' +
            '</div></form>' +
            kit.note('The value written is that person&rsquo;s OWN entry ' +
            'wherever it is &mdash; somebody whose entry was seeded by a ' +
            'client certificate is at ' +
            '<code>cn=&lt;name&gt;,' + kit.esc(info.usersDn) + '</code> and ' +
            'not at <code>uid=</code>, and a membership written in the wrong ' +
            'form would dangle beside the entry it was meant to name. With ' +
            'nobody there yet, the <code>uid=</code> form is written, so the ' +
            'value resolves the moment they authenticate. It goes onto ' +
            '<code>member</code> whatever else this entry carries, and ' +
              'adding ' +
            'somebody already listed changes nothing and says so. ' +
            '<strong>Taking one out is not here</strong>: it is an ' +
            '<code>ldapmodify</code> or a SCIM <code>PATCH</code>, and <a ' +
            'href="/admin/rbac">Admin roles</a> for the two groups that ' +
              'grant ' +
            'this console.')
          : '') +

        '<h2>Every attribute this group has</h2>' +
        GroupsPage.attributeTable(group) +
        kit.note('The whole object, operational attributes included &mdash; ' +
          'a ' +
        'search returns those only when they are asked for by name (RFC 4511 ' +
        '&sect;4.5.1.8), and this is a dump rather than a search. The ' +
        'membership attributes are in here too, as the raw values the store ' +
        'holds; the table above is the same values resolved. This directory ' +
          'is ' +
        '<strong>schemaless</strong>: no <code>objectClass</code> is ' +
          'enforced ' +
        'and no value is checked against a syntax, so an attribute a real ' +
        'directory would refuse is here because something wrote it.') +
        GroupsPage.groupsCaveat(json.adminGroups) +
        back + GroupsPage.groupsLinks();
    }
    return inner;
  }

  // A member's link. To the group page when the member is itself a group, so
  // nesting can be walked; to the users page when this console has actually
  // seen that person authenticate. Neither, and the DN stands on its own —
  // which is the commonest case in a directory nobody has signed in to yet.
  /**
   * Draws a group member's DN, linked to its group page when it is a group
   * or to the users page when that person has authenticated here.
   *
   * @param member - the member row from the group view
   * @param known - the user keys this console has seen authenticate
   * @returns the member's HTML
   */
  static memberLink(member, known) {
    const label = '<code>' + kit.esc(member.dn) + '</code>';
    if (member.kind === 'group') {
      return '<a href="' +
        kit.esc('/admin/groups' + kit.queryWith({ group: member.dn }, {})) +
        '">' + label + '</a>';
    }
    if (member.userKey && known[member.userKey]) {
      return '<a href="' +
        kit.esc('/admin/users' + kit.queryWith({ user: member.userKey }, {})) +
        '">' + label + '</a>';
    }
    return label;
  }

  // The "On the users page" cell, for a member and for a memberOf claimant
  // alike. Three states and they are all worth telling apart: a name this
  // console has seen authenticate, a name it could file somebody under but
  // never has, and an entry named in a way that yields no user name at all.
  /**
   * Draws the "On the users page" cell for a member or a memberOf claimant:
   * a link, a name marked never here, or a dash when there is no name.
   *
   * @param userKey - the user name derived from the entry, or empty
   * @param known - the user keys this console has seen authenticate
   * @returns the cell's HTML
   */
  static usersPageCell(userKey, known) {
    if (!userKey) {
      return '<span class="state-none" title="This entry is not named ' +
        'uid=&lt;name&gt; and carries no uid, so there is no name to look it ' +
        'up by. The console files people under the local name userFor() ' +
        'derives; an entry named some other way — a cn=, or the one a TLS ' +
        'client certificate seeds — has none.">—</span>';
    }
    if (!known[userKey]) {
      return '<span class="state-none" title="The directory holds an entry ' +
        'for them and nothing has authenticated as this name in this ' +
        'process, so the users page has no row to link to. The two lists ' +
        'answer different questions: the directory is what somebody wrote ' +
        'into it, the users page is who has actually presented a credential ' +
        'here.">' + kit.esc(userKey) +
        ' <em>(never here)</em></span>';
    }
    return '<a href="' +
           kit.esc('/admin/users' + kit.queryWith({ user: userKey }, {})) +
      '">' +
      kit.esc(userKey) + '</a>';
  }

  // Every attribute of one entry, operational ones included, as the table both
  // the user page and the group page draw. `entry` is what the directory's
  // readers return: canonically spelled names, values already arrays, and
  // `operational` naming which of them a search would have withheld.
  /**
   * Draws every attribute of one directory entry, operational ones marked,
   * with each value.
   *
   * @param entry - the entry as the directory's readers return it
   * @returns the table as HTML
   */
  static attributeTable(entry) {
    const rows = Object.keys(entry.attributes).map(function (name) {
      const values = entry.attributes[name];
      const operational = entry.operational.indexOf(name) >= 0;
      return '<tr><td><code>' + kit.esc(name) + '</code>' +
        (operational
          ? ' <span class="state-none" title="An operational attribute. A ' +
            'search returns it only when it is asked for by name (RFC 4511 ' +
            'section 4.5.1.8) — this dump shows it ' +
            'always.">(operational)</span>'
          : '') + '</td>' +
        '<td class="num">' + values.length + '</td>' +
        '<td>' + (values.map(function (value) {
          return '<code>' + kit.esc(value) + '</code>';
        }).join('<br>') || '—') + '</td></tr>';
    }).join('');
    return '<table><tr><th>Attribute</th><th ' +
           'class="num">Values</th><th>Value(s)</th></tr>' +
      rows + '</table>';
  }
}

export = GroupsPage;
