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
    // The page's words are its translator's (#539 phase 6). What the view
    // carries — role labels, what a role allows, the settings — is drawn
    // as it comes.
    const t = ctx.t;
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
    const nav = kit.pageNavPair('/admin/rbac', filterParams, paging, t);
    const carryBack = '<input type="hidden" name="back" value="' +
      kit.esc(kit.queryWith(kit.listViewOf('/admin/rbac', ctx.query), {})) +
        '">';

    const rows = shown.map(function (row) {
      return '<tr><td>' + RbacPage.rbacMemberCell(t, row, knownKeys) +
             RbacPage.rbacClaimedMark(t, row) +
        '</td><td>' + kit.esc(row.roleLabel) + '</td><td><a ' +
        'href="' + kit.esc('/admin/groups?group=' +
                            encodeURIComponent(row.dn)) + '"><code>' +
          kit.esc(row.dn) + '</code></a></td>' +
        '<td><code>' + kit.esc(row.attribute) + '</code>: <code>' + kit.esc(
            row.value) + '</code></td><td>' +
          (row.kind === 'claimed'
            ? '<span class="state-expired" title="' +
              t.html('consoleRbac.body.claimedTitle') + '">' +
              t.html('consoleRbac.body.notFromHere') + '</span>'
            : mayWrite
            ? '<form class="inline" method="post" action="/admin/rbac">' +
              '<input type="hidden" name="action" value="revoke">' +
              '<input type="hidden" name="username" value="' +
              kit.esc(row.username) +
              '"><input ' +
              'type="hidden" name="role" ' +
              'value="' + kit.esc(row.role) + '">' + carryBack +
              '<button class="danger">' + t.html('consoleRbac.body.revoke') +
              '</button></form>'
            : '<span class="state-none">' +
              t.html('consoleRbac.body.readOnly') + '</span>') +
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
      return row.inDirectory && row.seen
        ? t.text('consoleRbac.body.fromBoth')
        : (row.inDirectory ? t.text('consoleRbac.body.fromDirectory')
                           : t.text('consoleRbac.body.fromSignIn'));
    };
    const pickCarry = kit.pageParamsOf(ctx.query);
    delete pickCarry.person;
    const personPane = kit.chooserPane({
      here: { path: '/admin/rbac', query: ctx.query },
      param: 'personq', fromParam: 'personfrom',
      label: t.text('consoleRbac.body.findPerson'),
      placeholder: t.text('consoleRbac.body.findPlaceholder'),
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
        ? t.text('consoleRbac.body.nobodyMatches')
        : t.text('consoleRbac.body.nobodyAtAll')
    }, t);
    const roleOptions = json.roleChoices.map(function (role) {
      return '<option value="' + kit.esc(role.id) + '">' +
             kit.esc(role.label) +
             '</option>';
    }).join('');

    const tiles = '<div class="tiles">' +
      info.roles.map(function (role) {
        return kit.tile(role.memberCount, role.label);
      }).join('') +
      kit.tile(json.candidateSearch.total,
               t.text('consoleRbac.body.tileCandidates')) +
      '</div>';

    // The reason nobody can get in is one word of a select, so the
    // sentence around it is one message a translator can reorder.
    const status = info.closedToEveryone
      ? '<div class="err">' + t.html('consoleRbac.body.closed', {
          reason: info.bootstrap && info.bootstrap.seeded &&
                  info.bootstrap.claimedAt
            ? 'claimed'
            : (info.windowOpens === false ? 'product' : 'setting') }) +
        '</div>'
      : (info.bootstrapPasswordRequired
          ? kit.warn(t.html('consoleRbac.body.bootstrapPassword',
                            { username: info.bootstrap.username }))
      : (info.openToAnyone && info.bootstrap && info.bootstrap.seeded
          ? kit.warn(t.html('consoleRbac.body.bootstrapUnclaimed',
                            { username: info.bootstrap.username }))
      : (info.openToAnyone
          ? kit.warn(t.html('consoleRbac.body.openToAnyone'))
          : (info.enforced
              ? '<div class="ok">' + t.html('consoleRbac.body.enforced',
                                            { count: info.grantCount }) +
                '</div>'
              : kit.warn(t.html('consoleRbac.body.notInForce'))))));

    const noDirectory = info.available ? '' :
      '<div class="err">' + t.html('consoleRbac.body.noDirectory') +
      '</div>';

    const forms = mayWrite && info.available
      ? '<h2 id="grant">' + t.html('consoleRbac.body.grantHeading') +
        '</h2>' + kit.note(t.html('consoleRbac.body.grantNote')) +
        personPane +
        (picked
          ? '<form method="post" action="/admin/rbac" id="grant-picked">' +
            '<div class="formrow">' +
            '<input type="hidden" name="action" value="grant">' + carryBack +
            '<input type="hidden" name="username" value="' +
              kit.esc(picked.username) + '">' +
            '<span>' + t.html('consoleRbac.body.pickedPerson',
                              { name: picked.username }) +
              ' <span class="state-none">' +
              kit.esc(whereFrom(picked)) + '</span></span>' +
            '<label for="role">' + t.html('consoleRbac.body.role') +
            '</label>' +
            '<select id="role" name="role">' + roleOptions + '</select>' +
            '<button type="submit">' + t.html('consoleRbac.body.grant') +
            '</button>' +
            ' <a href="' + kit.esc('/admin/rbac' + kit.queryWith(pickCarry,
              {})) +
              '#find-personq">' + t.html('consoleRbac.body.pickOther') +
              '</a>' +
            '</div></form>'
          : (personAsked
              ? '<div class="err" id="grant-picked"><strong>' +
                kit.esc(personAsked) + '</strong> is not in the ' +
                'directory and has not signed in, so there is nobody by that ' +
                'name to pick. Search again, or grant to the name as typed ' +
                'with the form below.</div>'
              : '')) +
        '<h3>' + t.html('consoleRbac.body.typedHeading') + '</h3>' +
        '<form method="post" action="/admin/rbac"><div class="formrow">' +
        '<input type="hidden" name="action" value="grant">' + carryBack +
        '<label for="typed">' + t.html('consoleRbac.body.name') +
        '</label><input type="text" id="typed" ' +
        'name="username" size="24" placeholder="' +
        kit.esc(t.text('consoleRbac.body.typedPlaceholder')) +
        '"><label for="typedrole">' + t.html('consoleRbac.body.role') +
        '</label><select id="typedrole" ' +
        'name="role">' + roleOptions + '</select>' +
        '<button type="submit" class="secondary">' +
        t.html('consoleRbac.body.grant') + '</button>' +
        '</div></form>' +
        kit.note(t.html('consoleRbac.body.typedNote'))
      : (info.available && info.enforced && !mayWrite
          ? kit.note(t.html('consoleRbac.body.readOnlyNote'))
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
      '<label for="q">' + t.html('consoleRbac.body.person') + '</label>' +
      '<input type="text" id="q" name="q" value="' + kit.esc(wantedText) +
      '" size="22" placeholder="' +
      kit.esc(t.text('consoleRbac.body.filterPlaceholder')) + '"><label ' +
      'for="rolefilter">' + t.html('consoleRbac.body.role') +
      '</label><select id="rolefilter" ' +
      'name="role"><option value="">' + t.html('consoleRbac.body.both') +
      '</option>' +
      json.roleChoices.map(function (role) {
        return '<option value="' + kit.esc(role.id) + '"' +
               (wantedRole === role.id ? ' selected' : '') + '>' +
               kit.esc(role.label) + '</option>';
      }).join('') + '</select>' +
      '<label for="per">' + t.html('consoleRbac.body.perPage') + '</label>' +
      '<select id="per" name="per">' + kit.perPageOptions(paging.perPage, t) +
      '</select><button ' +
      'type="submit">' + t.html('consoleRbac.body.filter') + '</button>' +
      (wantedText || wantedRole
        ? ' <a href="/admin/rbac">' + t.html('consoleRbac.body.clear') +
          '</a>'
        : '') +
      '</div></form>' +
      nav.head +
      '<table><tr><th>' + t.html('consoleRbac.body.thPerson') + '</th><th>' +
      t.html('consoleRbac.body.thRole') + '</th><th>' +
      t.html('consoleRbac.body.thGroup') + '</th><th>' +
      t.html('consoleRbac.body.thValue') + '</th><th>' +
      t.html('consoleRbac.body.thTakeAway') + '</th></tr>' +
      (rows || '<tr><td colspan="5">' +
        (wantedText || wantedRole
          ? t.html('consoleRbac.body.noMatch')
          : t.html('consoleRbac.body.nobodyHolds') +
            (info.openToAnyone ? t.html('consoleRbac.body.whyOpen') : '')) +
        '</td></tr>') +
      '</table>' + nav.foot +
      (info.roles.some(function (r) { return r.claimedCount; })
        ? kit.note(t.html('consoleRbac.body.claimedNote'))
        : '') + forms +
      '<h2>' + t.html('consoleRbac.body.rolesHeading') +
      '</h2><table><tr><th>' + t.html('consoleRbac.body.thRole') +
      '</th><th>' + t.html('consoleRbac.body.thGroup') + '</th><th>' +
      t.html('consoleRbac.body.thAllows') + '</th><th class="num">' +
      t.html('consoleRbac.body.thMembers') + '</th></tr>' +
      info.roles.map(function (role) {
        return '<tr><td><strong>' + kit.esc(role.label) + '</strong></td>' +
          '<td><code>' + kit.esc(role.dn || ('cn=' + role.cn)) + '</code>' +
          (role.exists ? '' : ' <span class="state-none" title="' +
            t.html('consoleRbac.body.notCreatedTitle') + '">' +
            t.html('consoleRbac.body.notCreated') + '</span>') +
            '</td><td>' +
            kit.esc(role.what) +
          '</td><td ' +
          'class="num">' + role.memberCount +
          (role.claimedCount
            ? ' <span class="state-expired" title="' +
              t.html('consoleRbac.body.claimedCountTitle',
                     { count: role.claimedCount }) + '">(' +
              role.claimedCount + ')</span>'
            : '') + '</td></tr>';
      }).join('') + '</table>' +
      kit.note(t.html('consoleRbac.body.writeImpliesRead', {
        write: info.roles[1] ? info.roles[1].cn : '',
        read: info.roles[0] ? info.roles[0].cn : '' })) +
      // THE FOUR SETTINGS THEMSELVES, AND NOT A TABLE OF READINGS BESIDE THEM.
      // This page carried its own four-row table saying what each one was set
      // to and what it did, above a link to /admin/config; the descriptions in
      // that table and the ones in config.js's own rows had already begun to
      // differ. The form below is drawn from config.js, so there is one
      // description and it is the one the API answers with. The two sentences
      // that were ONLY in that table are the note under it — they are about
      // this console rather than about the settings, which is why they are not
      // in config.js either.
      SettingsForms.forms(json.settings, '/admin/rbac', undefined, t) +
      kit.note(t.html('consoleRbac.body.renaming')) +
      RbacPage.rbacCaveat(t);

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
   * @param t - the page's translator
   * @param row - the grant row
   * @param knownKeys - the user keys that have a page on Users
   * @returns the cell's contents as HTML
   */
  static rbacMemberCell(t, row, knownKeys) {
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
      return name + ' <span class="state-none" title="' +
             t.html('consoleRbac.rbacMemberCell.neverHereTitle') + '">' +
             t.html('consoleRbac.rbacMemberCell.neverHere') + '</span>';
    }
    return name + ' <span class="state-expired" title="' +
           t.html('consoleRbac.rbacMemberCell.danglingTitle') + '">' +
           t.html('consoleRbac.rbacMemberCell.dangling') + '</span>';
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
   * @param t - the page's translator
   * @param row - the grant row
   * @returns the "via their own memberOf" mark as HTML, or an empty string
   */
  static rbacClaimedMark(t, row) {
    if (row.kind !== 'claimed') {
      return '';
    }
    return ' <span class="state-expired" title="' +
           t.html('consoleRbac.rbacClaimedMark.title') + '">' +
           t.html('consoleRbac.rbacClaimedMark.mark') + '</span>';
  }

  /**
   * Draws the caveat at the foot of Admin roles.
   *
   * @param t - the page's translator
   * @returns the caveat as HTML
   */
  static rbacCaveat(t) {
    // The link to Groups carries an href, which a message may not: the
    // sentence is three messages with the anchor in the code.
    return (
      kit.note(t.html('consoleRbac.rbacCaveat.before') +
      '<a href="/admin/groups">' + t.html('consoleRbac.rbacCaveat.link') +
      '</a>' + t.html('consoleRbac.rbacCaveat.after')));
  }
}

export = RbacPage;
