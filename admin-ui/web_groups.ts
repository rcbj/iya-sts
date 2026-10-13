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

// THE PAGE'S TRANSLATOR, ESCAPING AS THIS PAGE ALWAYS ESCAPED (#539). A DN,
// a listener's error or a directory's suffix fills many of these messages,
// and an apostrophe in one was drawn by `kit.esc()` as `&apos;` where the
// translator's escaping writes `&#39;`: the same character in different
// bytes, and the console's browser jobs compare bytes. So a message WITH
// parameters has its `&#39;` written as `&apos;`; no message of this
// page's catalog carries a literal `&#39;` for this to change. Every other
// member is the translator's own, through the prototype, and wrapping a
// wrapped translator changes nothing.
const kitEscaping = function (translator: Json): Json {
  const wrapped = Object.create(translator);
  wrapped.html = function (key: string, params?: Json): string {
    const out = translator.html(key, params);
    return params ? out.replace(/&#39;/g, '&apos;') : out;
  };
  return wrapped;
};

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
  // and that sentence needs a noun that agrees with itself. Since #539 the
  // noun is chosen INSIDE each message, by a `select` on one of these ids:
  // a language agrees its nouns and verbs its own way, and the pieces that
  // were joined here (upper, lower, verb, pronoun) could not do that.
  static readonly ENTRY_SUBJECT = 'entry';

  static readonly GROUPS_SUBJECT = 'groups';

  static readonly GROUP_SUBJECT = 'group';

  // Why this entry counted as a group, in words. The rule is ldap_server.js's;
  // this is only its three values spelled out, and it is on the page because
  // "developers is a group" is uninteresting next to "this entry is a group
  // because somebody put it under ou=groups and it carries no group
  // objectClass at all". A method of the translator since #539.
  /**
   * The three rules' labels and tooltips, by rule.
   *
   * @param t - the page's translator
   * @returns `{ both, placement, objectClass }`, each `{ label, title }` as
   *   plain text
   */
  static groupRules(t: Json): Json {
    return {
      both: { label: t.text('consoleGroups.groupRules.both'),
              title: t.text('consoleGroups.groupRules.bothTitle') },
      placement: { label: t.text('consoleGroups.groupRules.placement'),
                   title: t.text('consoleGroups.groupRules.placementTitle') },
      objectClass: {
        label: t.text('consoleGroups.groupRules.objectClass'),
        title: t.text('consoleGroups.groupRules.objectClassTitle') }
    };
  }

  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of `GET /admin-api/groups`
   * @returns the body as HTML
   */
  static body(ctx, json) {
    // The page's words are its translator's (#539 phase 6); the view's
    // facts — DNs, origins, settings — are drawn as they come.
    const t = kitEscaping(ctx.t);
    const wantedText = json.filter.q || '';
    const paging = json.paging;
    const filterParams = { q: wantedText,
                           per: ctx.query.per ? paging.perPage : '' };
    const nav = kit.pageNavPair('/admin/groups', filterParams, paging, t);
    const listView = kit.listViewOf('/admin/groups', ctx.query);
    const rows = json.groups.map(function (group) {
      // The link carries the list AS IT IS BEING VIEWED, which is what lets
      // the trail on the other side come back to this page of this filter
      // rather than to the top of everything. See listViewOf().
      const href = '/admin/groups' +
                   kit.queryWith(listView, { group: group.dn });
      return '<tr><td><a href="' + kit.esc(href) + '">' +
             kit.esc(GroupsPage.groupLabel(t, group)) +
        '</a></td><td ' +
        'class="who"><code>' + kit.esc(group.dn) + '</code></td>' +
        '<td>' + GroupsPage.groupRuleCell(t, group.rule) + '</td>' +
        '<td class="num">' + group.memberCount + '</td>' +
        '<td class="num">' + (group.presentCount
          ? '<span class="state-valid">' + group.presentCount + '</span>'
          : '<span class="state-none">0</span>') + '</td>' +
        '<td class="num">' + (group.danglingCount
          ? '<span class="state-revoked" title="' +
            kit.esc(t.text('consoleGroups.body.danglingTitle')) + '">' +
            group.danglingCount + '</span>'
          : '<span class="state-none">0</span>') + '</td>' +
        '<td class="num">' + (group.claimedCount
          ? '<span class="state-expired" title="' +
            kit.esc(t.text('consoleGroups.body.claimedTitle')) + '">' +
            group.claimedCount +
            '</span>'
          : '<span class="state-none">0</span>') + '</td>' +
        '<td class="num">' + group.attributeCount + '</td>' +
        '<td>' + kit.esc(group.origin) + '</td>' +
        '<td><code>' + kit.esc(group.modifiedAt) + '</code></td></tr>';
    }).join('');

    return GroupsPage.directoryListenerWarning(t, json,
                                               GroupsPage.GROUPS_SUBJECT) +
      '<div class="tiles">' +
      kit.tile(json.groupCount, t.text('consoleGroups.body.tileGroups')) +
      kit.tile(json.membershipValues,
               t.text('consoleGroups.body.tileValues')) +
      kit.tile(json.dangling, t.text('consoleGroups.body.tileDangling')) +
      kit.tile(json.entryCount, t.text('consoleGroups.body.tileEntries')) +
      // THE LIST IS A TAB (2026-10-12), headed by the page's own name; the
      // warning, the tiles and the notes under the table are Metadata.
      '</div><h2 data-tab="groups">' + t.html('console.nav.groups') +
      '</h2><form method="get" action="/admin/groups"><div ' +
      'class="formrow"><label for="q">' + t.html('consoleGroups.body.group') +
      '</label><input type="text" ' +
      'id="q" name="q" value="' + kit.esc(wantedText) + '" ' +
      'size="28" placeholder="' +
      kit.esc(t.text('consoleGroups.body.filterHint')) + '"><label ' +
      'for="per">' + t.html('consoleGroups.body.perPage') +
      '</label><select id="per" ' +
      'name="per">' + kit.perPageOptions(paging.perPage, t) +
      '</select><button ' +
      'type="submit">' + t.html('consoleGroups.body.filter') + '</button>' +
      (wantedText
        ? ' <a href="/admin/groups">' + t.html('consoleGroups.body.clear') +
          '</a>'
        : '') +
      '</div></form>' +
      nav.head +
      '<table><tr><th>' + t.html('consoleGroups.body.thGroup') +
      '</th><th>DN</th><th>' + t.html('consoleGroups.body.thRule') +
      '</th><th ' +
      'class="num">' + t.html('consoleGroups.body.thMembers') +
      '</th><th class="num">' + t.html('consoleGroups.body.thResolve') +
      '</th><th ' +
      'class="num">' + t.html('consoleGroups.body.thDangling') +
      '</th><th class="num">' + t.html('consoleGroups.body.thClaimed') +
      '</th><th ' +
      'class="num">' + t.html('consoleGroups.body.thAttributes') +
      '</th><th>' + t.html('consoleGroups.body.thOrigin') + '</th><th>' +
      t.html('consoleGroups.body.thModified') + '</th></tr>' +
      (rows || '<tr><td colspan="10">' +
               t.html('consoleGroups.body.noMatch',
                      { filtered: wantedText ? 'yes' : 'no' }) +
               '</td></tr>') + '</table>' +
      nav.foot +
      '<div data-metadata>' +
      kit.note(t.html('consoleGroups.body.whatAGroupIs',
                      { groupsDn: json.groupsDn, usersDn: json.usersDn })) +
      kit.note(t.html('consoleGroups.body.counts')) + '</div>' +
      // THE ONE CONTROL ON THIS LIST (rule 7's mirror is
      // POST /admin-api/groups/create). Below the table rather than above it,
      // because the question this page is usually open to answer is "what is
      // in this directory" and a create form at the top would answer a
      // different one first. A REAL BUTTON AND NO SCRIPT, like every other
      // form on this console.
      (json.canWrite
        ? '<h2 data-tab="create">' +
          t.html('consoleGroups.body.createHeading') + '</h2>' +
          '<form method="post" action="/admin/groups">' +
          '<input type="hidden" name="action" value="create">' +
          '<input type="hidden" name="back" value="' +
          kit.esc(kit.queryWith(listView, {})) + '">' +
          '<div class="formrow">' +
          '<label for="newgroup">cn</label>' +
          '<input type="text" id="newgroup" name="group" size="28" required ' +
          'placeholder="developers">' +
          '<label for="newnote">' + t.html('consoleGroups.body.description') +
          '</label>' +
          '<input type="text" id="newnote" name="note" size="40" ' +
          'placeholder="' + kit.esc(t.text('consoleGroups.body.noteHint')) +
          '">' +
          '</div><div class="formrow">' +
          '<label for="newmembers">' + t.html('consoleGroups.body.thMembers') +
          '</label>' +
          '<textarea id="newmembers" name="members" rows="3" cols="60" ' +
          'placeholder="alice&#10;bob&#10;cn=another-group,' +
          kit.esc(json.groupsDn) + '"></textarea>' +
          '<button type="submit">' + t.html('consoleGroups.body.create') +
          '</button>' +
          '</div></form>' +
          kit.note(t.html('consoleGroups.body.createNote',
                          { groupsDn: json.groupsDn }))
        : kit.note(t.html('consoleGroups.body.noWriter'))) +
      SettingsForms.forms(json.settings, '/admin/groups', undefined, t) +
      GroupsPage.groupsCaveat(t, json.adminGroups) +
      GroupsPage.groupsLinks(t);
  }

  /**
   * Names a group for a person: its cn, or a placeholder when it has none.
   *
   * @param t - the page's translator
   * @param group - the group as the directory reader returns it
   * @returns the label as plain text
   */
  static groupLabel(t, group) {
    return group.cn || t.text('consoleGroups.groupLabel.noCn');
  }

  /**
   * Draws the cell saying which rule made an entry count as a group.
   *
   * @param t - the page's translator
   * @param rule - the rule's key in groupRules()
   * @returns the cell's HTML, with the rule's explanation as a tooltip
   */
  static groupRuleCell(t, rule) {
    const rendered = GroupsPage.groupRules(t)[rule];
    if (!rendered) {
      return '<span class="state-none">' +
             kit.esc(rule || t.text('consoleGroups.groupRuleCell.unstated')) +
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
   * @param t - the page's translator
   * @param info - the LDAP server's listener state
   * @param subject - what the page shows: ENTRY_SUBJECT, GROUPS_SUBJECT or
   *   GROUP_SUBJECT
   * @returns the warning as HTML, or '' when both are listening
   */
  static directoryListenerWarning(t, info, subject) {
    // A caller's translator escapes as the translator does; this warning's
    // parameters are drawn as kit.esc() always drew them.
    t = kitEscaping(t);
    const error = info.listenError ||
      t.text('consoleGroups.directoryListenerWarning.neverBound');
    if (!info.listening && !info.ldapsListening) {
      return kit.warn(t.html('consoleGroups.directoryListenerWarning.down',
        { error: error, subject: subject, port: info.port }));
    }
    if (!info.listening) {
      return kit.warn(t.html('consoleGroups.directoryListenerWarning.plainDown',
        { error: error, subject: subject, port: info.port,
          ldapsPort: info.ldapsPort }));
    }
    if (info.ldapsPort && !info.ldapsListening) {
      return kit.warn(t.html('consoleGroups.directoryListenerWarning.ldapsDown',
        { subject: subject, port: info.port }));
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
   * @param t - the page's translator
   * @param adminGroups - the two console groups (`read`, `write`)
   * @returns the caveat as HTML
   */
  static groupsCaveat(t, adminGroups) {
    t = kitEscaping(t);
    const named = adminGroups || {};
    return kit.note(t.html('consoleGroups.groupsCaveat.grantsNothing')) +
      // THE EXCEPTION, said HERE and not only on the page that owns it. A
      // reader meeting this caveat and then finding cn=admin-write in the
      // table above it would be entitled to conclude that one of the two was
      // lying. The links carry hrefs, so each note is messages around them.
      kit.note(t.html('consoleGroups.groupsCaveat.exceptionsBefore',
                      { read: named.read, write: named.write }) +
      '<a href="/admin/rbac">' +
      t.html('consoleGroups.groupsCaveat.adminRoles') + '</a>' +
      t.html('consoleGroups.groupsCaveat.exceptionsAfter')) +
      kit.note(t.html('consoleGroups.groupsCaveat.claimBefore') +
      '<a href="/admin/claims">' +
      t.html('consoleGroups.groupsCaveat.claimsPage') + '</a>' +
      t.html('consoleGroups.groupsCaveat.claimAfter'));
  }

  /**
   * Draws the links at the foot of both groups pages.
   *
   * @param t - the page's translator
   * @returns the links as HTML
   */
  static groupsLinks(t) {
    return kit.note('<a href="/admin/ldap/service">' +
      t.html('consoleGroups.groupsLinks.service') + '</a> &middot; ' +
      '<a href="/admin/ldap/directory">' +
      t.html('consoleGroups.groupsLinks.directory') + '</a> &middot; ' +
      '<a href="/admin/ldap/directory?format=json">' +
      t.html('consoleGroups.groupsLinks.json') + '</a> &middot; ' +
      '<a href="/admin/users">' + t.html('consoleGroups.groupsLinks.users') +
      '</a>.');
  }

  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static detail(ctx, json) {
    const t = kitEscaping(ctx.t);
    const info = json;
    const back = kit.note('<a href="' +
      kit.esc('/admin/groups' +
               kit.queryWith(kit.listViewOf('/admin/groups', ctx.query), {})) +
      '">' + t.html('consoleGroups.detail.back') + '</a>.');

    let inner;
    if (!info.found) {
      // Three ways to be here and they are different answers, so they get
      // different words. A 404 is none of them: the console linked here from a
      // list it drew from this same store, and the interesting case is
      // precisely that the store has changed since — a client can delete a
      // group, rename it out of ou=groups, or strip its objectClass through the
      // protocol between one click and the next.
      const because = info.notAGroup
        ? t.html('consoleGroups.detail.notAGroup',
                 { entryDn: info.entryDn, groupsDn: info.groupsDn }) +
          '<a href="/admin/ldap/directory">' +
          t.html('consoleGroups.detail.fullDump') + '</a>' +
          t.html('consoleGroups.detail.stillShows')
        : t.html('consoleGroups.detail.nothingAt', { wanted: info.wanted });
      inner = GroupsPage.directoryListenerWarning(t, info,
        GroupsPage.GROUP_SUBJECT) +
        kit.note(because) + back;
    } else {
      const group = json.group;
      const known = json.known;
      const params = kit.pageParamsOf(ctx.query);
      const membersNav = kit.pageNavPair('/admin/groups', params,
                                          json.membersPaging, t);
      const claimedNav = kit.pageNavPair('/admin/groups', params,
                                          json.claimedPaging, t);
      const memberRows = group.members.map(function (member) {
        const state = member.present
          ? '<span class="state-valid">' +
            t.html('consoleGroups.detail.inDirectory') + '</span>'
          : '<span class="state-revoked" title="' +
            kit.esc(t.text('consoleGroups.detail.danglingTitle')) + '">' +
            t.html('consoleGroups.detail.dangling') + '</span>';
        return '<tr><td class="who">' + GroupsPage.memberLink(member, known) +
          '</td>' +
          '<td><code>' + kit.esc(member.attribute) + '</code></td>' +
          '<td>' + state + '</td>' +
          '<td>' +
          kit.esc(member.kind === 'group'
            ? t.text('consoleGroups.detail.aGroup')
            : member.kind === 'entry' ? t.text('consoleGroups.detail.anEntry')
                                      : '—') +
          '</td>' +
          '<td>' +
          (member.cn ? kit.esc(member.cn) :
           '<span class="state-none">—</span>') +
          '</td><td>' +
          (member.mail ? '<code>' + kit.esc(member.mail) + '</code>'
                                : '<span class="state-none">—</span>') +
                                  '</td>' +
          '<td>' + GroupsPage.usersPageCell(member.userKey, known, t) +
          '</td>' +
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
          '<td>' + GroupsPage.usersPageCell(entry.userKey, known, t) +
            '</td></tr>';
      }).join('');

      const claimedSection = json.claimedPaging.total
        ? '<h2>' + t.html('consoleGroups.detail.claimedHeading') + '</h2>' +
          claimedNav.head +
          '<table><tr><th>DN</th><th>cn</th><th>mail</th><th>' +
          t.html('consoleGroups.detail.thUsersPage') + '</th></tr>' +
          claimedRows + '</table>' +
          claimedNav.foot +
          kit.note(t.html('consoleGroups.detail.claimedNote'))
        : '';

      // TWO TABS SINCE #603 (rcbj: "Call the primary tab group. Call this
      // new tab owners"): Group — everything this page drew before — and
      // Owners. The way back and the links stay under both.
      const groupPanel =
        '<h2>' + kit.esc(GroupsPage.groupLabel(t, group)) +
        '</h2><table><tr><th>DN</th><th>' +
        t.html('consoleGroups.detail.thRule') + '</th><th>' +
        t.html('consoleGroups.body.thOrigin') + '</th><th>' +
        t.html('consoleGroups.detail.thCreated') + '</th><th>' +
        t.html('consoleGroups.body.thModified') + '</th></tr><tr><td ' +
        'class="who"><code>' + kit.esc(group.dn) + '</code></td>' +
        '<td>' + GroupsPage.groupRuleCell(t, group.rule) + '</td>' +
        '<td>' + kit.esc(group.origin) + '</td>' +
        '<td><code>' + kit.esc(group.createdAt) + '</code></td>' +
        '<td><code>' + kit.esc(group.modifiedAt) + '</code></td></tr></table>' +
        kit.note(t.html('consoleGroups.detail.timestamps',
                        { port: info.port, dn: group.dn })) +

        kit.perPageForm('/admin/groups', 'group', group.dn,
                         json.membersPaging.perPage,
                         '',
                         kit.filterOnly(kit.listViewOf('/admin/groups',
                                                         ctx.query)), t) +

        '<h2>' + t.html('consoleGroups.body.thMembers') + '</h2>' +
        '<div class="tiles">' +
        kit.tile(group.memberCount, t.text('consoleGroups.body.tileValues')) +
        kit.tile(group.presentCount,
                 t.text('consoleGroups.detail.tileResolve')) +
        kit.tile(group.danglingCount,
                 t.text('consoleGroups.body.tileDangling')) +
        kit.tile(json.claimedPaging.total,
                 t.text('consoleGroups.detail.tileClaim')) +
        '</div>' +
        (group.memberCount
          ? membersNav.head +
            '<table><tr><th>' + t.html('consoleGroups.detail.thMember') +
            '</th><th>' + t.html('consoleGroups.detail.thFrom') +
            '</th><th>' + t.html('consoleGroups.detail.thState') +
            '</th><th>' + t.html('consoleGroups.detail.thWhat') +
            '</th><th>cn</th><th>mail</th><th>' +
            t.html('consoleGroups.detail.thUsersPage') + '</th><th>' +
            t.html('consoleGroups.detail.thStored') + '</th></tr>' +
            memberRows + '</table>' + membersNav.foot
          : kit.note(t.html('consoleGroups.detail.empty'))) +
        // The attributes are joined with the very markup kit.esc() then
        // escapes — drawn that way before #539, and kept to the byte.
        kit.note(t.html('consoleGroups.detail.membershipRead', {
          attributes: group.memberAttributes.join('</code>, <code>'),
          usersDn: info.usersDn })) +
        kit.note(t.html('consoleGroups.detail.usersColumn')) +
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
          ? '<h2>' + t.html('consoleGroups.detail.addHeading') + '</h2>' +
            '<form method="post" action="/admin/groups">' +
            '<input type="hidden" name="action" value="add-member">' +
            '<input type="hidden" name="group" value="' + kit.esc(group.dn) +
            '"><input type="hidden" name="back" value="' +
            kit.esc(kit.queryWith(kit.listViewOf('/admin/groups', ctx.query),
              {})) +
            '"><div class="formrow"><label for="newmember">' +
            t.html('consoleGroups.detail.userOrDn') + '</label><input ' +
            'type="text" id="newmember" name="member" ' +
            'size="44" required placeholder="' +
            kit.esc(t.text('consoleGroups.detail.memberHint',
                           { groupsDn: info.groupsDn })) + '">' +
            '<button type="submit">' + t.html('consoleGroups.detail.add') +
            '</button>' +
            '</div></form>' +
            kit.note(t.html('consoleGroups.detail.addBefore',
                            { usersDn: info.usersDn }) +
            '<a href="/admin/rbac">' +
            t.html('consoleGroups.groupsCaveat.adminRoles') + '</a>' +
            t.html('consoleGroups.detail.addAfter'))
          : '') +

        '<h2>' + t.html('consoleGroups.detail.attributesHeading') + '</h2>' +
        GroupsPage.attributeTable(group, t) +
        kit.note(t.html('consoleGroups.detail.attributesNote')) +
        GroupsPage.groupsCaveat(t, json.adminGroups);
      inner = GroupsPage.directoryListenerWarning(t, info,
        GroupsPage.GROUP_SUBJECT) +
        kit.tabbedPanels('grouptabs', [
          { id: 'gtab-group', label: t.text('consoleGroups.detail.tabGroup'),
            html: groupPanel },
          { id: 'gtab-owners',
            label: t.text('consoleGroups.detail.tabOwners'),
            // The controls for a reader holding Admin Write, on a process
            // whose directory can be written (`canWrite`).
            html: GroupsPage.ownersSection(t, group,
              !!json.canWrite && !!ctx.write,
              kit.queryWith(kit.listViewOf('/admin/groups', ctx.query), {}),
              json.state) }
        ]) +
        back + GroupsPage.groupsLinks(t);
    }
    return inner;
  }

  // ---------------------------------------------------------------------------
  // A GROUP'S OWNERS (#603): the service account's owner pattern (#600,
  // #602) on a group, where the group always exists, so every Add and
  // Remove WRITES AT ONCE. The table is the group's (`group.owners`); each
  // Remove is a small form of its own (`remove-owner`); the search is a form
  // posting to the tab's own route, `/admin/groups/owners`, whose Find,
  // Previous and Next the runtime answers in the browser from the Users or
  // Groups list (rule 7), FIND_PER_PAGE to a page, and whose result's Add is a
  // button named `owner` with a `formaction` naming `add-owner`. What the
  // last press said, and the search, ride on the page's `state.groupOwners`.
  // ---------------------------------------------------------------------------
  /**
   * Draws a group's Owners tab: its owners, and — for Admin Write — the
   * search that adds one and the Remove beside each.
   *
   * @param t - the page's translator
   * @param group - the group's view (`dn`, `owners`, `maxOwners`)
   * @param write - whether the reader may write
   * @param back - the list view to return to
   * @param pageState - the page's state: `groupOwners` (`find`, `notice`,
   *   `error`), after a press
   * @param opts - optional; for another kind of thing with owners (#604, a
   *   role): `route`, `id` (the section's anchor), `field` and `value` (the
   *   hidden field naming it), `stateKey`, `lead` and `leadRead` (markup),
   *   and `self` (a DN the search may not add; a group's own)
   * @returns the tab as HTML
   */
  static ownersSection(t, group, write, back, pageState?, opts?) {
    const o = opts || {};
    const route = o.route || '/admin/groups/owners';
    const id = o.id || 'group-owners';
    const anchor = '#' + id;
    const owners = group.owners || [];
    const max = Number(group.maxOwners) || 25;
    const drawn = (pageState && pageState[o.stateKey || 'groupOwners']) || {};
    const selfDn = o.self === undefined ? group.dn : o.self;
    const lower = function (dn) {
      return String(dn || '').toLowerCase().replace(/\s*,\s*/g, ',');
    };
    const kindOf = function (kind) {
      return t.text('consoleGroups.owners.kind', { kind: kind || 'unknown' });
    };
    const hidden = function (name, value) {
      return '<input type="hidden" name="' + name + '" value="' +
        kit.esc(value) + '">';
    };
    const who = hidden(o.field || 'group',
                       o.value === undefined ? group.dn : o.value) +
      hidden('back', back);
    const button = function (name, value, label, tipText, cls?, off?,
                             goes?) {
      return '<button type="submit" class="secondary ' + (cls || '') +
        '" name="' + name + '" value="' + kit.esc(value) +
        '" formaction="' + kit.esc(goes || route + anchor) +
        '" formnovalidate' + kit.tip(tipText) +
        (off ? ' disabled' : '') + '>' + kit.esc(label) + '</button>';
    };
    const said = (drawn.error && drawn.error.length
      ? kit.warn(kit.esc(drawn.error.join(' '))) : '') +
      (drawn.notice ? kit.note(kit.esc(drawn.notice)) : '');
    const removeOf = function (one) {
      if (!write) {
        return '';
      }
      return '<form method="post" class="inline" action="' +
        kit.esc(route + anchor) + '">' + hidden('action', 'remove-owner') +
        who + hidden('owner', one.dn) +
        '<button type="submit" class="secondary danger"' +
        kit.tip(t.text('consoleGroups.owners.removeTip',
                       { name: one.name || one.dn })) + '>' +
        t.html('consoleGroups.owners.remove') + '</button></form>';
    };
    const table = owners.length
      ? '<table class="key sa-owners"><tr><th>' +
        t.html('consoleGroups.owners.thKind') + '</th><th>' +
        t.html('consoleGroups.owners.thName') + '</th><th>' +
        t.html('consoleGroups.owners.thDn') + '</th>' +
        (write ? '<th></th>' : '') + '</tr>' +
        owners.map(function (one) {
          return '<tr><td' + (one.kind ? ''
            : kit.tip(t.text('consoleGroups.owners.notFoundTip'))) + '>' +
            kit.esc(kindOf(one.kind)) + '</td><td>' + kit.esc(one.name) +
            '</td><td>' + kit.shortened(one.dn, 60) + '</td>' +
            (write ? '<td>' + removeOf(one) + '</td>' : '') + '</tr>';
        }).join('') + '</table>'
      : '<p class="state-none">' + t.html('consoleGroups.owners.none') +
        '</p>';
    const head = '<h3 id="' + id + '">' +
      t.html('consoleGroups.owners.heading') + '</h3>' +
      kit.note((write ? (o.lead || t.html('consoleGroups.owners.lead'))
                      : (o.leadRead ||
                         t.html('consoleGroups.owners.leadRead'))) + ' ' +
               t.html('consoleGroups.owners.max', { max: String(max) })) +
      said + table;
    if (!write) {
      return head +
        kit.note(t.html('consoleGroups.owners.needsWrite'));
    }
    // THE SEARCH: people or groups, each result with an Add that writes —
    // or why it has none: already an owner, this group itself, or an
    // identity with no entry to name.
    const found = drawn.find || null;
    const which = found && found.which === 'groups' ? 'groups' : 'people';
    const kindRadio = function (value, label, tipText) {
      return '<label class="fg-radio"' + kit.tip(tipText) + '>' +
        '<input type="radio" name="fgkind.owners" value="' + value + '"' +
        (which === value ? ' checked' : '') + '>' + kit.esc(label) +
        '</label>';
    };
    const ownerSet = {};
    owners.forEach(function (one) {
      ownerSet[lower(one.dn)] = true;
    });
    const full = owners.length >= max;
    const pick = function (one) {
      if (!one.value) {
        return '<span class="state-none"' +
          kit.tip(t.text('consoleKit.find.noEntry.tip')) + '>' +
          t.html('consoleKit.find.noEntry') + '</span>';
      }
      if (ownerSet[lower(one.value)]) {
        return '<span class="state-none"' +
          kit.tip(t.text('consoleGroups.owners.isOwnerTip')) + '>' +
          t.html('consoleGroups.owners.isOwner') + '</span>';
      }
      if (selfDn && lower(one.value) === lower(selfDn)) {
        return '<span class="state-none"' +
          kit.tip(t.text('consoleGroups.owners.itselfTip')) + '>' +
          t.html('consoleGroups.owners.itself') + '</span>';
      }
      return button('owner', one.value, t.text('consoleKit.find.add'),
                    t.text('consoleGroups.owners.addTip',
                           { value: one.value }), 'fg-add', full,
                    route + '?action=add-owner' + anchor);
    };
    const pager = found && !found.failed && (found.pages || 1) > 1
      ? '<div class="fg-pager">' +
        button('fgsearch', 'owners|' + (found.page - 1),
               t.text('consoleKit.find.previous'),
               t.text('consoleKit.find.previous.tip',
                      { n: kit.FIND_PER_PAGE }), 'fg-prev', found.page <= 1) +
        '<span class="fg-pageof">' + t.html('consoleKit.find.pageOf', {
          page: found.page, pages: found.pages, matched: found.matched }) +
        '</span>' +
        button('fgsearch', 'owners|' + (found.page + 1),
               t.text('consoleKit.find.next'),
               t.text('consoleKit.find.next.tip',
                      { n: kit.FIND_PER_PAGE }), 'fg-next',
               found.page >= found.pages) + '</div>'
      : '';
    const results = !found ? ''
      : '<div class="fg-found" aria-live="polite">' +
        hidden('fgpage.owners', String(found.page || 1)) +
        (found.failed
          // A FAILURE, and failures stay English (#539).
          ? '<span class="state-none">The search could not be run: ' +
            '/admin-api did not answer it.</span>'
          : !found.rows.length
            ? '<span class="state-none fg-none">' + (found.query
              ? t.html('consoleKit.find.noMatches', { query: found.query })
              : t.html('consoleGroups.owners.findHint', { which: which })) +
              '</span>'
            : found.rows.map(function (one) {
              return '<div class="fg-hit"><span class="fg-hit-name">' +
                '<span class="fg-hit-kind">' + kit.esc(kindOf(one.kind)) +
                '</span> ' + kit.esc(one.label) +
                (one.value ? ' ' + kit.shortened(one.value, 60) : '') +
                '</span>' + pick(one) + '</div>';
            }).join('')) + pager + '</div>';
    const placeholder = t.text('consoleGroups.owners.findPlaceholder');
    const findTip = t.text('consoleGroups.owners.findTip',
                           { n: kit.FIND_PER_PAGE });
    const search = '<h3 id="' + id + '-find">' +
      t.html('consoleGroups.owners.findHeading') + '</h3>' +
      '<form method="post" action="' + kit.esc(route + anchor) +
      '" class="sa-form">' + hidden('action', 'add-owner') + who +
      // THE DEFAULT BUTTON, first in the form: Enter in the search box is a
      // Find, never an Add.
      '<button type="submit" class="default-submit" tabindex="-1" ' +
      'aria-hidden="true" name="fgsearch" value="owners" formaction="' +
      kit.esc(route + anchor) + '">' +
      kit.esc(t.text('consoleKit.find.find')) + '</button>' +
      '<div class="sa-find"><div class="fg-bool fg-kinds" role="radiogroup" ' +
      'aria-label="' + kit.esc(t.text('consoleGroups.owners.findWhat')) +
      '">' +
      kindRadio('people', t.text('consoleKit.find.people'),
                t.text('consoleGroups.owners.peopleTip')) +
      kindRadio('groups', t.text('consoleGroups.owners.groups'),
                t.text('consoleGroups.owners.groupsTip')) +
      '</div><div class="fg-item fg-findrow"><input type="search" ' +
      'id="fgq-owners" name="fgfind.owners" data-fg-find="owners" value="' +
      kit.esc(found ? found.query : '') + '" placeholder="' +
      kit.esc(placeholder) + '" aria-label="' + kit.esc(placeholder) + '"' +
      kit.tip(findTip) + '>' +
      button('fgsearch', 'owners', t.text('consoleKit.find.find'), findTip,
             'fg-findbtn') +
      '</div>' + results + '</div></form>';
    return head + search;
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
   * @param t - optional; the page's translator. `web_delegation.ts` calls
   *   this without one, and its words are then the default translator's
   * @returns the cell's HTML
   */
  static usersPageCell(userKey, known, t?) {
    t = t || kit.context().t;
    // The two tooltips hold `&lt;` and are drawn as markup into the
    // attribute, as they always were: a translation holds no double quote.
    if (!userKey) {
      return '<span class="state-none" title="' +
        t.html('consoleGroups.usersPageCell.noNameTitle') + '">—</span>';
    }
    if (!known[userKey]) {
      return '<span class="state-none" title="' +
        t.html('consoleGroups.usersPageCell.neverHereTitle') + '">' +
        kit.esc(userKey) +
        ' <em>' + t.html('consoleGroups.usersPageCell.neverHere') +
        '</em></span>';
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
   * @param t - optional; the page's translator. `admin.ts` calls this
   *   without one, and its words are then the default translator's
   * @returns the table as HTML
   */
  static attributeTable(entry, t?) {
    t = t || kit.context().t;
    const rows = Object.keys(entry.attributes).map(function (name) {
      const values = entry.attributes[name];
      const operational = entry.operational.indexOf(name) >= 0;
      return '<tr><td><code>' + kit.esc(name) + '</code>' +
        (operational
          ? ' <span class="state-none" title="' +
            kit.esc(t.text('consoleGroups.attributeTable.operationalTitle')) +
            '">' + t.html('consoleGroups.attributeTable.operational') +
            '</span>'
          : '') + '</td>' +
        '<td class="num">' + values.length + '</td>' +
        '<td>' + (values.map(function (value) {
          return '<code>' + kit.esc(value) + '</code>';
        }).join('<br>') || '—') + '</td></tr>';
    }).join('');
    return '<table><tr><th>' + t.html('consoleGroups.attributeTable.thName') +
           '</th><th ' +
           'class="num">' + t.html('consoleGroups.attributeTable.thValues') +
           '</th><th>' + t.html('consoleGroups.attributeTable.thValueList') +
           '</th></tr>' +
      rows + '</table>';
  }
}

export = GroupsPage;
