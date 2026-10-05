// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_rbac.ts
//
// ---------------------------------------------------------------------------
// ADMIN ROLES, DRAWN FROM ITS VIEW ALONE (#446, 2026-10-05).
//
// Draws `/admin/rbac` from the answer of `GET /admin-api/rbac`: who may use
// this console, the grants of its two roles, the person chooser and the forms
// that grant and revoke, and the settings.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// It was drawn inside the route of `method:rbacListPage` in
// `admin-ui/admin.ts`, which still draws the page until the console's cutover
// by calling this with its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');
import SettingsForms = require('./web_settings');

type Json = any;

/**
 * Draws `/admin/rbac` from the answer of `GET /admin-api/rbac`: who may use
 * this console, the grants of its two roles, the person chooser and the forms
 * that grant and revoke, and the settings.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class RbacPage {
  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static body(ctx, json) {
    const info = json;
    const mayWrite = ctx.write;
    const wantedText = json.filter.q || '';
    const wantedRole = json.filter.role || '';
    const paging = json.paging;
    const shown = json.grants;
    const filterParams = { q: wantedText, role: wantedRole,
                           per: ctx.query.per ? paging.perPage : '',
                           personq: kit.queryOne(ctx.query, 'personq').trim(),
                           personfrom: kit.queryOne(ctx.query, 'personfrom'),
                           person: kit.queryOne(ctx.query, 'person').trim() };
    const knownKeys = json.known;
    const picked = json.picked ? json.picked.candidate : null;
    const personAsked = json.picked ? json.picked.asked : '';
    const nav = kit.pageNavPair('/admin/rbac', filterParams, paging);
    const carryBack = '<input type="hidden" name="back" value="' +
      kit.esc(kit.queryWith(kit.listViewOf('/admin/rbac', ctx.query), {})) +
        '">';

    const rows = shown.map(function (row) {
      return '<tr><td>' + RbacPage.rbacMemberCell(row, knownKeys) +
             RbacPage.rbacClaimedMark(row) +
        '</td><td>' + kit.esc(row.roleLabel) + '</td><td><a ' +
        'href="' + kit.esc('/admin/groups?group=' +
                            encodeURIComponent(row.dn)) + '"><code>' +
          kit.esc(row.dn) + '</code></a></td>' +
        '<td><code>' + kit.esc(row.attribute) + '</code>: <code>' + kit.esc(
            row.value) + '</code></td><td>' +
          (row.kind === 'claimed'
            ? '<span class="state-expired" title="The membership is on their ' +
              'own entry as memberOf, so there is nothing in the group to ' +
              'remove. An ldapmodify or a SCIM PATCH of the PERSON takes it ' +
              'away.">not from here</span>'
            : mayWrite
            ? '<form class="inline" method="post" action="/admin/rbac">' +
              '<input type="hidden" name="action" value="revoke">' +
              '<input type="hidden" name="username" value="' +
              kit.esc(row.username) +
              '"><input ' +
              'type="hidden" name="role" ' +
              'value="' + kit.esc(row.role) + '">' + carryBack +
              '<button class="danger">Revoke</button></form>'
            : '<span class="state-none">read-only</span>') +
        '</td></tr>';
    }).join('');

    // WHO CAN BE PICKED. `stats.userRows()` is who has authenticated and the
    // directory is who has an entry; admin_rbac.js unions them, because a list
    // built from either alone would silently omit half the people somebody
    // wants to grant a role to.
    //
    // **IT WAS A `<select>` OF ALL OF THEM UNTIL 2026-09-13 AND IS A SEARCH
    // NOW**, for the reason /admin/delegation's person chooser stopped being
    // one: a default realm bulk loaded with thousands of people made the select
    // a control nobody could scroll, find a name in, or load quickly. It is
    // kit.chooserPane() — the same search, the same twenty-at-a-time pane, the
    // same
    // clamped offset — and a RESULT IS A LINK that picks that person, which
    // opens the grant form for them below the pane. So granting is search,
    // click, choose the role, Grant: one step more than the select, and the one
    // that makes the list usable at any size.
    const whereFrom = function (row) {
      return row.inDirectory && row.seen ? 'directory, and has signed in'
        : (row.inDirectory ? 'in the directory' : 'has signed in');
    };
    const pickCarry = kit.pageParamsOf(ctx.query);
    delete pickCarry.person;
    const personPane = kit.chooserPane({
      here: { path: '/admin/rbac', query: ctx.query },
      param: 'personq', fromParam: 'personfrom',
      label: 'Find a person',
      placeholder: 'part of a username',
      slice: { matched: json.candidatePane.matched,
               from: json.candidatePane.from },
      entries: json.candidatePane.shown.map(function (row) {
        return {
          key: row.username.toLowerCase(),
          names: [row.username],
          label: row.username,
          detail: whereFrom(row),
          href: '/admin/rbac' + kit.queryWith(pickCarry,
            { person: row.username }) +
                '#grant-picked'
        };
      }),
      selectedKey: picked ? picked.username.toLowerCase() : '',
      nothing: json.candidateSearch.total
        ? 'Nobody in the directory or among the people who have signed in ' +
          'matches that. To grant a role to a name this service has never ' +
          'seen, use the form below the results.'
        : 'Nobody is in the directory and nobody has signed in yet, so there ' +
          'is nobody to pick. The form below takes a typed name.'
    });
    const roleOptions = json.roleChoices.map(function (role) {
      return '<option value="' + kit.esc(role.id) + '">' +
             kit.esc(role.label) +
             '</option>';
    }).join('');

    const tiles = '<div class="tiles">' +
      info.roles.map(function (role) {
        return kit.tile(role.memberCount, role.label);
      }).join('') +
      kit.tile(json.candidateSearch.total, 'People who could hold one') +
      '</div>';

    const status = info.closedToEveryone
      ? '<div class="err"><strong>Nobody can use this console.</strong> The ' +
        'gate is on, no role has a member, and ' +
        (info.bootstrap && info.bootstrap.seeded && info.bootstrap.claimedAt
          ? 'the bootstrap administrator has already signed in. '
          : (info.windowOpens === false
              ? 'this is product mode, which never opens the console to ' +
                'whoever signs in. '
              : '<code>admin.openWhenEmpty</code> is off. ')) +
        'Anything you are reading ' +
        'here you are reading through <code>/admin-api</code> or with the ' +
        'gate off.</div>'
      : (info.bootstrapPasswordRequired
          ? kit.warn('<strong>Only <code>' +
            kit.esc(info.bootstrap.username) + '</code>, signing in with ' +
            'its password, can use this console until it does.</strong> ' +
            'This is product mode and the console has not been claimed: ' +
            'the window in which anybody who signs in holds both roles is ' +
            'a development convenience and never opens here. Its first ' +
            'password sign-in through this realm claims the console; a ' +
            'sign-in as that account by any other method holds nothing ' +
            'until then. Anybody granted a role on this page holds it at ' +
            'once.')
      : (info.openToAnyone && info.bootstrap && info.bootstrap.seeded
          ? kit.warn('<strong><code>' + kit.esc(info.bootstrap.username) +
                      '</code> ' +
            'has not signed in to this console yet, so anybody who signs in ' +
            'has the whole console.</strong> This service\'s bootstrap ' +
            'administrator holds both roles already; its first sign-in here ' +
            'ends the open console — for everybody who holds no role. ' +
            '<strong>Grant yourself a role now</strong> if you will need the ' +
            'console after that.')
      : (info.openToAnyone
          ? kit.warn('<strong>No role has a member, so anybody who signs in ' +
            'has the whole console.</strong> The first grant made on this ' +
            'page ends that — for everybody, including whoever makes it. ' +
            '<strong>Grant yourself a role before you grant anybody else ' +
            'one</strong>, or the next page you click will be a 403.')
          : (info.enforced
              ? '<div class="ok">The roster is enforced. ' + info.grantCount +
                ' grant(s) across two roles; everybody else is refused at ' +
                'every page of this console.</div>'
              : kit.warn('<strong>None of this is in force.</strong> The ' +
                'gate is OFF, so the console is open to anybody who can ' +
                'reach this port and these roles decide nothing. They are ' +
                'still real directory groups and can be granted now. ' +
                '(UNREACHABLE since 2026-09-06: the gate is ' +
                'unconditional.)')))));

    const noDirectory = info.available ? '' :
      '<div class="err">No LDAP directory is loaded in this process, so ' +
      'there is nowhere to hold these roles and nothing on this page can be ' +
      'granted. That is a build of this service without ' +
      '<code>ldap_server.js</code> rather than a failure — but the console ' +
      'gate is unconditional, so it leaves this console reachable only while ' +
      '<code>admin.openWhenEmpty</code> is on.</div>';

    const forms = mayWrite && info.available
      ? '<h2 id="grant">Grant a role</h2>' +
        kit.note('Search for the person, then pick them from the results. ' +
        'The list is everybody with an entry in the directory and everybody ' +
        'this service has seen authenticate — two different sets, which is ' +
        'why both are searched and why each result says which it came from. ' +
        'An empty search lists everybody, twenty at a time.') +
        personPane +
        (picked
          ? '<form method="post" action="/admin/rbac" id="grant-picked">' +
            '<div class="formrow">' +
            '<input type="hidden" name="action" value="grant">' + carryBack +
            '<input type="hidden" name="username" value="' +
              kit.esc(picked.username) + '">' +
            '<span>Person: <strong>' + kit.esc(picked.username) +
              '</strong> <span class="state-none">' +
              kit.esc(whereFrom(picked)) + '</span></span>' +
            '<label for="role">Role</label>' +
            '<select id="role" name="role">' + roleOptions + '</select>' +
            '<button type="submit">Grant</button>' +
            ' <a href="' + kit.esc('/admin/rbac' + kit.queryWith(pickCarry,
              {})) +
              '#find-personq">pick somebody else</a>' +
            '</div></form>'
          : (personAsked
              ? '<div class="err" id="grant-picked"><strong>' +
                kit.esc(personAsked) + '</strong> is not in the ' +
                'directory and has not signed in, so there is nobody by that ' +
                'name to pick. Search again, or grant to the name as typed ' +
                'with the form below.</div>'
              : '')) +
        '<h3>Grant to a name that is not listed</h3>' +
        '<form method="post" action="/admin/rbac"><div class="formrow">' +
        '<input type="hidden" name="action" value="grant">' + carryBack +
        '<label for="typed">Name</label><input type="text" id="typed" ' +
        'name="username" size="24" placeholder="the name they will sign in ' +
        'as"><label for="typedrole">Role</label><select id="typedrole" ' +
        'name="role">' + roleOptions + '</select>' +
        '<button type="submit" class="secondary">Grant</button>' +
        '</div></form>' +
        kit.note('The membership will DANGLE until that person exists — it ' +
        'names a DN this directory does not hold yet — and the role counts ' +
        'from the moment they first sign in. That is the interesting case ' +
        'for a mock and is why this form is here: nothing about a grant ' +
        'requires the person to have been seen. A name carrying a character ' +
        'RFC 4514 reserves in a DN is refused, the same refusal creating a ' +
        'person gets.')
      : (info.available && info.enforced && !mayWrite
          ? kit.note('Granting and revoking need <strong>Admin ' +
            'Write</strong>. The table above is what you can see with ' +
            '<strong>Admin Read</strong>.')
          : '');

    // The grant pane's search, carried through the table's filter form: a GET
    // form posts its own fields and nothing else, so without these narrowing
    // the table would clear the search the reader is still using below it.
    const personCarry = ['personq', 'personfrom', 'person']
      .map(function (name) {
      const value = kit.queryOne(ctx.query, name);
      return value === ''
        ? ''
        : '<input type="hidden" name="' + name + '" value="' + kit.esc(value) +
          '">';
    }).join('');
    const inner = noDirectory + status + tiles +
      '<form method="get" action="/admin/rbac"><div class="formrow">' +
      personCarry +
      '<label for="q">Person</label>' +
      '<input type="text" id="q" name="q" value="' + kit.esc(wantedText) +
      '" size="22" placeholder="part of a name"><label ' +
      'for="rolefilter">Role</label><select id="rolefilter" ' +
      'name="role"><option value="">both</option>' +
      json.roleChoices.map(function (role) {
        return '<option value="' + kit.esc(role.id) + '"' +
               (wantedRole === role.id ? ' selected' : '') + '>' +
               kit.esc(role.label) + '</option>';
      }).join('') + '</select>' +
      '<label for="per">Per page</label>' +
      '<select id="per" name="per">' + kit.perPageOptions(paging.perPage) +
      '</select><button ' +
      'type="submit">Filter</button>' +
      (wantedText || wantedRole ? ' <a href="/admin/rbac">clear</a>' : '') +
      '</div></form>' +
      nav.head +
      '<table><tr><th>Person</th><th>Role</th><th>Group</th><th>Membership ' +
      'value</th><th>Take it away</th></tr>' +
      (rows || '<tr><td colspan="5">' +
        (wantedText || wantedRole
          ? 'No grant matches. The filter above may be hiding some.'
          : 'Nobody holds either role.' +
            (info.openToAnyone ? ' Which is why anybody who signs in can ' +
                                 'read this page.' : '')) +
        '</td></tr>') +
      '</table>' + nav.foot +
      (info.roles.some(function (r) { return r.claimedCount; })
        ? kit.note('<strong>Some of those grants are on the PERSON rather ' +
          'than in the group.</strong> An entry whose own ' +
          '<code>memberOf</code> names a role group holds the role — the ' +
          'directory is asked in both directions — and nothing here ' +
          'maintains <code>memberOf</code>, so a client wrote it. They are ' +
          'listed because a page answering &ldquo;who has access&rdquo; that ' +
          'omitted them would be showing a console somebody could use and a ' +
          'list they were not on. They cannot be revoked from here: the ' +
          'value is on their entry, and this console writes only to groups. ' +
          'One edge worth knowing — a <code>memberOf</code> naming a role ' +
          'group that has <em>never been created</em> grants nothing, and ' +
          'starts granting the moment the first ordinary grant creates it.')
        : '') + forms +
      '<h2>What the two roles ' +
      'are</h2><table><tr><th>Role</th><th>Group</th><th>What it ' +
      'allows</th><th class="num">Members</th></tr>' +
      info.roles.map(function (role) {
        return '<tr><td><strong>' + kit.esc(role.label) + '</strong></td>' +
          '<td><code>' + kit.esc(role.dn || ('cn=' + role.cn)) + '</code>' +
          (role.exists ? '' : ' <span class="state-none" title="The group is ' +
            'created by the first grant rather than at startup, so &quot;no ' +
            'group&quot; and &quot;no members&quot; are the same state ' +
            'here.">not created yet</span>') + '</td><td>' +
            kit.esc(role.what) +
          '</td><td ' +
          'class="num">' + role.memberCount +
          (role.claimedCount
            ? ' <span class="state-expired" title="Of which ' +
              role.claimedCount +
              ' are claimed by the person&#39;s own memberOf rather than ' +
              'listed by the group.">(' + role.claimedCount + ')</span>'
            : '') + '</td></tr>';
      }).join('') + '</table>' +
      kit.note('<strong>Write implies read.</strong> A member of <code>' +
      kit.esc(info.roles[1] ? info.roles[1].cn : '') + '</code> does not ' +
                                                        'also need <code>' +
      kit.esc(info.roles[0] ? info.roles[0].cn : '') + '</code>: a role ' +
      'that could post a form to a page it was not allowed to look at would ' +
      'be a trap rather than a permission.') +
      // THE FOUR SETTINGS THEMSELVES, AND NOT A TABLE OF READINGS BESIDE THEM.
      // This page carried its own four-row table saying what each one was set
      // to and what it did, above a link to /admin/config; the descriptions in
      // that table and the ones in config.js's own rows had already begun to
      // differ. The form below is drawn from config.js, so there is one
      // description and it is the one the API answers with. The two sentences
      // that were ONLY in that table are the note under it — they are about
      // this console rather than about the settings, which is why they are not
      // in config.js either.
      SettingsForms.forms(json.settings, '/admin/rbac') +
      kit.note('<strong>Renaming a role group does not move ' +
      'anybody.</strong> The members stay in the group they were put in, ' +
      'which stops granting anything the moment the name changes — and the ' +
      'new name grants nothing until somebody is put in it. ' +
      '<code>/admin-api</code> is not gated by any of these four, on ' +
      'purpose: it is the way back in when nobody who holds a role can sign ' +
      'in, and it is why turning the gate on does not break a test suite ' +
      'driving the management API.') +
      RbacPage.rbacCaveat();

    return inner;
  }

  // A membership value that names an entry which is not there. It is a normal
  // state here rather than a fault — see the grant form's note — so it is
  // marked and explained rather than hidden or repaired.
  /**
   * Draws the person cell of one admin-role grant row.
   *
   * A known person links to their Users page; one in the directory but never
   * seen is marked "never here", and a DN with no entry is marked "dangling".
   *
   * @param row - the grant row
   * @param knownKeys - the user keys that have a page on Users
   * @returns the cell's contents as HTML
   */
  static rbacMemberCell(row, knownKeys) {
    const name = kit.esc(row.username || row.value);
    if (row.userKey && knownKeys[row.userKey]) {
      return '<a href="' +
             kit.esc('/admin/users?user=' + encodeURIComponent(row.userKey)) +
             '">' +
             name + '</a>';
    }
    if (row.present) {
      // In the directory, but this service has never seen them authenticate.
      // The same distinction /admin/groups draws on its member rows, and drawn
      // the same way so the two pages cannot be read as disagreeing.
      return name + ' <span class="state-none" title="This person has an ' +
             'entry in the directory, but nothing here has authenticated as ' +
             'them yet, so there is no page about them on Users.">never ' +
             'here</span>';
    }
    return name + ' <span class="state-expired" title="Nothing is at this ' +
           'DN. The role still counts — it resolves the moment somebody ' +
           'authenticates under this name or the entry is created — but ' +
           'until then no directory client can see who it ' +
           'names.">dangling</span>';
  }

  // The mark on a row whose membership is on the PERSON'S entry rather than in
  // the group. It really grants the role — `groupsOfUser()` reads both
  // directions, so admin_rbac.js merges these in — which is why it is on this
  // list at all; and it cannot be taken away from here, so the row says that
  // too rather than offering a button that would report success and change
  // nothing.
  /**
   * Draws the mark on a grant held through the person's own memberOf rather
   * than the group's member list.
   *
   * @param row - the grant row
   * @returns the "via their own memberOf" mark as HTML, or an empty string
   */
  static rbacClaimedMark(row) {
    if (row.kind !== 'claimed') {
      return '';
    }
    return ' <span class="state-expired" title="Their own entry&#39;s ' +
           'memberOf names this group and the group does not list them back. ' +
           'Nothing here maintains memberOf — a client wrote it — and it ' +
           'grants the role all the same, so it is on this list. The Revoke ' +
           'button cannot remove it: the value is on the person, and this ' +
           'console writes only to groups.">via their own memberOf</span>';
  }

  /**
   * Draws the caveat at the foot of Admin roles.
   *
   * @returns the caveat as HTML
   */
  static rbacCaveat() {
    return (
      kit.note('<strong>These two groups are the only groups in this ' +
      'service that grant anything, and what they grant is this ' +
      'console.</strong> Every other group here still grants nothing at all ' +
        '— ' +
      'see <a href="/admin/groups">Groups</a>, which says so — and even ' +
        'these ' +
      'two grant nothing outside <code>/admin</code>: no token\'s scopes ' +
      'change, no assertion gains an attribute, no Kerberos PAC is affected, ' +
      'and a member of <code>admin-write</code> gets exactly the same answer ' +
      'from <code>/oauth2/token</code> as anybody else. They are also ' +
        'ordinary ' +
      'directory entries, so <code>ldapmodify</code>, a SCIM PATCH, this ' +
        'page ' +
      'and <code>POST /admin-api/rbac/grant</code> are four doors onto one ' +
      'membership — which is the point rather than a leak: a role no test ' +
        'can ' +
      'grant is a role no test can exercise.'));
  }
}

export = RbacPage;
