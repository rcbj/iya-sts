// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_roles.ts
//
// ---------------------------------------------------------------------------
// DIRECTORY → ROLES, DRAWN FROM ITS VIEW ALONE (#446, 2026-10-05).
//
// Draws Roles from the answer of `GET /admin-api/roles`: who holds each role,
// what requires one, the forms that change both, a preview of what would be
// issued, and the settings.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// It was drawn inside the route of `/admin/roles` in `admin-ui/admin.ts`,
// which still draws the page until the console's cutover by calling this with
// its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');
import SettingsForms = require('./web_settings');

type Json = any;

// THE PAGE'S TRANSLATOR, ESCAPING AS THIS PAGE ALWAYS ESCAPED (#539). A
// role's name, an application's identifier or a policy's reason fills many
// of these messages, and an apostrophe in one was drawn by `kit.esc()` as
// `&apos;` where the translator's escaping writes `&#39;`: the same
// character in different bytes, and the console's browser jobs compare
// bytes. So a message WITH parameters has its `&#39;` written as `&apos;`;
// no message of this page's catalog carries a literal `&#39;` for this to
// change. Every other member is the translator's own, through the
// prototype.
const kitEscaping = function (translator: Json): Json {
  const wrapped = Object.create(translator);
  wrapped.html = function (key: string, params?: Json): string {
    const out = translator.html(key, params);
    return params ? out.replace(/&#39;/g, '&apos;') : out;
  };
  return wrapped;
};

/**
 * Draws Roles from the answer of `GET /admin-api/roles`: who holds each role,
 * what requires one, the forms that change both, a preview of what would be
 * issued, and the settings.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class RolesPage {
  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static body(ctx, json) {
    // The page's words are its translator's (#539 phase 6). What the view
    // carries — the built-in roles' descriptions, the member kinds, a
    // preview's reason — is drawn as it comes.
    const t = kitEscaping(ctx.t);
    const register = json;
    const listView = kit.listViewOf('/admin/roles', ctx.query);
    const navParams = kit.pageParamsOf(ctx.query);
    const q = json.query.q;
    const rolesNav = kit.pageNavPair('/admin/roles', navParams,
                                      json.paging, t);
    const rolePage = { shown: json.shownRoles };

    const roleOptions = register.roles.map(function (one) {
      return '<option value="' + kit.esc(one.name) + '">' +
             kit.esc(one.name) +
             '</option>';
    }).join('');
    const kindOptions = json.memberKinds.map(function (one) {
      return '<option value="' + kit.esc(one.kind) + '">' +
             kit.esc(one.label) +
             '</option>';
    }).join('');
    const applicationOptions = json.applicationChoices.map(function (row) {
      return '<option value="' + kit.esc(row.identifier) + '">' +
             kit.esc(row.name && row.name !== row.identifier
               ? row.name + ' — ' + row.identifier : row.identifier) +
             '</option>';
    }).join('');
    const issuanceOptions = json.issuanceKinds.map(function (one) {
      return '<option value="' + kit.esc(one) + '">' + kit.esc(one) +
             '</option>';
    }).join('');

    const preview = json.preview;

    const inner =
      '<h2>' + t.html('consoleRoles.body.heading') + '</h2>' +
      // The links carry hrefs, so the sentences around them are messages
      // and the anchors are code.
      kit.note(t.html('consoleRoles.body.introBefore') + '<a ' +
      'href="/admin/xacml/policies">' + t.html('consoleRoles.body.policies') +
      '</a>' + t.html('consoleRoles.body.introTest') + '<a ' +
      'href="/admin/xacml/decide">' + t.html('consoleRoles.body.tryDecision') +
      '</a>' + t.html('consoleRoles.body.introSee') + '<a ' +
      'href="/admin/audit">' + t.html('consoleRoles.body.auditLog') + '</a>' +
      t.html('consoleRoles.body.introEnd')) +

      kit.note('<strong>' + t.html('consoleRoles.body.notRbacBefore') +
      '<a href="/admin/rbac">' + t.html('consoleRoles.body.adminRoles') +
      '</a>' + t.html('consoleRoles.body.notRbacAfter') + '</strong>' +
      t.html('consoleRoles.body.thatOne',
             { container: register.container || 'ou=roles' }) +
      '<strong>' + t.html('consoleRoles.body.notGroupsBefore') + '<a ' +
      'href="/admin/groups">' + t.html('consoleRoles.body.groups') + '</a>' +
      t.html('consoleRoles.body.notGroupsAfter') + '</strong>' +
      t.html('consoleRoles.body.twoMeet')) +

      (register.storable ? ''
        : kit.warn(t.html('consoleRoles.body.notStorable'))) +

      (register.enforced ? ''
        : kit.warn(t.html('consoleRoles.body.notEnforced'))) +

      (register.gated ? '' : kit.warn(t.html('consoleRoles.body.notGated'))) +

      '<h3 id="built-in">' +
      t.html('consoleRoles.body.builtInHeading',
             { count: register.builtIn.length }) + '</h3>' +
      kit.note(t.html('consoleRoles.body.builtInNote',
                      { defaultRequired: register.defaultRequired })) +
      '<table><thead><tr><th>' + t.html('consoleRoles.body.thRole') +
      '</th><th>' + t.html('consoleRoles.body.thWhoHolds') +
      '</th></tr></thead><tbody>' +
      register.builtIn.map(function (one) {
        return '<tr><td class="who"><code>' + kit.esc(one.name) +
               '</code></td><td>' + kit.esc(one.what) + '</td></tr>';
      }).join('') +
      '</tbody></table>' +

      '<h3 id="roles">' + t.html('consoleRoles.body.madeHeading') + '</h3>' +
      kit.note(t.html('consoleRoles.body.madeNote',
                      { container: register.container || 'ou=roles' })) +
      '<form method="get" action="/admin/roles"><div class="formrow">' +
        '<label for="q">' + t.html('consoleRoles.body.text') + '</label>' +
        '<input type="text" id="q" name="q" size="40" value="' + kit.esc(q) +
          '" placeholder="' + kit.esc(t.text('consoleRoles.body.textHint')) +
          '">' +
        '<button class="secondary">' + t.html('consoleRoles.body.filter') +
        '</button>' +
        (q ? ' <a href="/admin/roles#roles">' +
             t.html('consoleRoles.body.clear') + '</a>' : '') +
      '</div></form>' +
      '<table><thead><tr><th>' + t.html('consoleRoles.body.thRole') +
      '</th>' +
      json.memberKinds.map(function (one) {
        return '<th>' + t.html('consoleRoles.body.thHeldBy',
                               { kind: one.label }) + '</th>';
      }).join('') +
      '<th>' + t.html('consoleRoles.body.thAuthorizes') +
      '</th><th></th></tr></thead><tbody>' +
      (rolePage.shown.length
        ? rolePage.shown.map(function (one) { return RolesPage.roleRow(one,
            listView, json.memberKinds, t); })
                        .join('')
        : '<tr><td colspan="6"><span class="state-none">' +
          (q ? t.html('consoleRoles.body.noMatch', { q: q })
             : t.html('consoleRoles.body.noneMade',
                      { defaultRequired: register.defaultRequired })) +
          '</span></td></tr>') +
      // `rolesNav` is a { head, foot } pair drawn as a string, and has been
      // since before #539; the words are what changed here, not that.
      '</tbody></table>' + rolesNav +

      '<h3 id="create">' + t.html('consoleRoles.body.makeHeading') + '</h3>' +
      kit.note(t.html('consoleRoles.body.makeNote',
                      { container: register.container || 'ou=roles' })) +
      '<form method="post" action="/admin/roles">' +
      RolesPage.rolesBack(listView) +
      '<input type="hidden" name="action" value="create-role"><div ' +
      'class="formrow"><label>' + t.html('consoleRoles.body.name') +
      ' <input type="text" name="role" ' +
      'required></label><label>' + t.html('consoleRoles.body.description') +
      ' <input type="text" ' +
      'name="description" size="50"></label>' +
      // FOR ONE APPLICATION (#310), or for the realm when left empty. The
      // tooltip's `<role>@<application>` is a parameter, so the translator
      // escapes it as kit.esc() did the whole sentence.
      '<label title="' + t.html('consoleRoles.body.forApplicationTitle',
                                { pattern: '<role>@<application>' }) +
      '">' + t.html('consoleRoles.body.forApplication') + ' ' +
      '<input type="text" name="application" list="role-create-apps" ' +
      'placeholder="' + kit.esc(t.text('consoleRoles.body.realmWide')) +
      '"></label><datalist id="role-create-apps">' +
      applicationOptions + '</datalist>' +
      // ITS LABEL AND WHO MAY HOLD IT (#93).
      '<label>' + t.html('consoleRoles.body.displayName') +
      ' <input type="text" name="displayName" ' +
      'placeholder="' + kit.esc(t.text('consoleRoles.body.optional')) +
      '"></label><label>' + t.html('consoleRoles.body.mayBeHeldBy') +
      ' <select ' +
      'name="memberTypes"><option value="">' +
      t.html('consoleRoles.body.peopleAndApps') +
      '</option><option value="user">' +
      t.html('consoleRoles.body.peopleOnly') + '</option><option ' +
      'value="application">' + t.html('consoleRoles.body.appsOnly') +
      '</option></select></label>' +
      '<button type="submit">' + t.html('consoleRoles.body.create') +
      '</button></div></form>' +

      // "SOMEBODY" IS THREE KINDS AND THE HEADING USED TO HIDE TWO OF THEM.
      //
      // This read `Give somebody a role`, and the note under it was the three
      // ROLE_MEMBER_KINDS joined — so `kit.note()` derived its summary from the
      // first of them and the fold read `a person — A username.` The one
      // sentence saying an application may hold a role AS ITSELF was inside a
      // collapsed block whose opening words were about people, on a page
      // whose heading was also about people. Somebody looking for how to put
      // an application in a role could read this whole section and not find
      // it, which is exactly what happened.
      //
      // The heading names all three now, and the note LEADS with a sentence
      // naming all three so that the derived summary does too. The per-kind
      // detail is unchanged and still folded — the fix is which sentence is
      // visible with the fold shut, not how much prose there is.
      '<h3 id="member">' + t.html('consoleRoles.body.memberHeading') +
      '</h3>' +
      kit.note(t.html('consoleRoles.body.memberLead') + '<br>' +
      json.memberKinds.map(function (one) {
        return '<strong>' + kit.esc(one.label) + '</strong> &mdash; ' +
               kit.esc(one.what);
      }).join('<br>')) +
      (register.roles.length ? ''
        : kit.warn(t.html('consoleRoles.body.noRoleBefore') +
          '<a href="#create">' + t.html('consoleRoles.body.createARole') +
          '</a>' + t.html('consoleRoles.body.noRoleAfter'))) +
      '<form method="post" action="/admin/roles">' +
      RolesPage.rolesBack(listView) +
      '<input type="hidden" name="action" value="add-member">' +
      '<div class="formrow">' +
      '<label>' + t.html('consoleRoles.body.thRole') +
      ' <select name="role" required>' + roleOptions +
      '</select></label><label>' + t.html('consoleRoles.body.kind') + ' ' +
      '<select name="kind">' + kindOptions + '</select></label>' +
      // THE SUGGESTIONS ARE THE APPLICATIONS, AND ONLY THE APPLICATIONS.
      //
      // A datalist SUGGESTS and never constrains, which is what makes one
      // field serving three kinds tolerable: a person or a group is still
      // typed by hand and still need not exist yet, which is this service's
      // rule everywhere and is stated in the fold above.
      //
      // Applications are the kind with a knowable set — this realm's registry
      // has them all — and they are the kind somebody cannot guess, because
      // an application's identifier is whatever it registered itself as. The
      // other two are open by design: a person need not exist, and a group
      // lives in the directory behind a hook this page has no reader for.
      //
      // ITS OWN datalist rather than the preview form's `role-preview-apps`
      // below. Both render the same `applicationOptions` — one computation,
      // two renderings, so they cannot disagree — but referencing an id
      // defined by another section would make this field's suggestions vanish
      // silently if that section were ever made conditional or moved.
      '<label title="' +
        kit.esc(t.text('consoleRoles.body.memberNameTitle')) +
        '">' + t.html('consoleRoles.body.name') +
        ' <input type="text" name="member" list="role-member-apps" ' +
        'required></label>' +
      '<datalist id="role-member-apps">' + applicationOptions +
      '</datalist><button type="submit"' +
        (register.roles.length ? '' : ' disabled') + '>' +
        t.html('consoleRoles.body.add') + '</button>' +
      '</div></form>' +

      // WHAT A ROLE AUTHORIZES (#303, part B of #88).
      '<h3 id="authorizes">' + t.html('consoleRoles.body.authorizeHeading') +
      '</h3>' +
      kit.note(t.html('consoleRoles.body.authorizeBefore') +
      '<a href="/admin/rbac">' + t.html('consoleRoles.body.adminRoles') +
      '</a>' + t.html('consoleRoles.body.authorizeAfter')) +
      '<form method="post" action="/admin/roles">' +
      RolesPage.rolesBack(listView) +
      '<input type="hidden" name="from" value="authorizes">' +
      '<input type="hidden" name="action" value="add-permission">' +
      '<div class="formrow">' +
      '<label>' + t.html('consoleRoles.body.thRole') +
      ' <select name="role" required>' +
      register.roles.filter(function (one) {
        return !one.native;
      }).map(function (one) {
        return '<option value="' + kit.esc(one.name) + '">' +
               kit.esc(one.name) + '</option>';
      }).join('') + '</select></label>' +
      '<label>' + t.html('consoleRoles.body.permission') +
      ' <input type="text" name="permission" size="50" ' +
      'list="role-permission-ids" required></label>' +
      '<datalist id="role-permission-ids">' + register.permissionIds
        .map(function (id) {
          return '<option value="' + kit.esc(id) + '">';
        }).join('') + '</datalist>' +
      '<button type="submit"' +
        (register.roles.some(function (one) { return !one.native; })
          ? '' : ' disabled') + '>' + t.html('consoleRoles.body.authorize') +
      '</button>' +
      '</div></form>' +

      '<h3 id="requiring">' + t.html('consoleRoles.body.requiringHeading') +
      '</h3>' +
      kit.note(t.html('consoleRoles.body.requiringNote',
                      { defaultRequired: register.defaultRequired })) +
      '<table><thead><tr><th>' + t.html('consoleRoles.body.thApplication') +
      '</th><th>' + t.html('consoleRoles.body.thRequires') + '</th>' +
      '<th>' + t.html('consoleRoles.body.thHoldable') +
      '</th></tr></thead><tbody>' +
      (register.requiring.length
        ? register.requiring.map(function (one) {
            return '<tr><td class="who"><a href="' +
              kit.esc('/admin/applications' +
                       kit.queryWith(listView,
                                 { application: one.application })) +
              '">' + kit.esc(one.name) + '</a>' +
              (one.name === one.application ? ''
                : '<br><code>' + kit.esc(one.application) + '</code>') +
                  '</td>' +
              '<td>' + one.required.map(function (role) {
                return '<code>' + kit.esc(role) + '</code>';
              }).join(' ' + t.html('consoleRoles.body.or') + ' ') + '</td>' +
              // The unknown roles are markup (each in its <code>), so the
              // sentence is two messages around them.
              '<td>' + (one.unknown.length
                ? '<span class="state-none">' +
                  t.html('consoleRoles.body.unknownBefore') +
                  one.unknown.map(function (role) {
                    return '<code>' + kit.esc(role) + '</code>';
                  }).join(', ') + t.html('consoleRoles.body.unknownAfter') +
                  '</span>'
                : t.html('consoleRoles.body.allDefined')) + '</td></tr>';
          }).join('')
        : '<tr><td colspan="3"><span class="state-none">' +
          t.html('consoleRoles.body.nothingNarrowed',
                 { defaultRequired: register.defaultRequired }) +
          '</span></td></tr>') +
      '</tbody></table>' +

      '<h3 id="preview">' + t.html('consoleRoles.body.previewHeading') +
      '</h3>' +
      kit.note(t.html('consoleRoles.body.previewBefore') + '<a ' +
      'href="/admin/xacml/decide">' + t.html('consoleRoles.body.tryDecision') +
      '</a>' + t.html('consoleRoles.body.previewAfter')) +
      // NEITHER FIELD IS `required`, and that is not laziness. A browser will
      // not SUBMIT a form with an empty required field at all — constraint
      // validation blocks it silently — so a reader who pressed Ask with one
      // box empty would get no navigation, no message and no way to tell that
      // from a control that does nothing. The handler answers the honest
      // thing instead: with nothing asked it draws no decision, exactly as
      // `GET /admin-api/roles/preview` answers 200 with `answered: false`. It
      // was `required` for one run, and `tests/vendored/sts_admin_console.js`
      // caught it — that job submits every GET form on this console and
      // asserts the browser actually went somewhere.
      '<form method="get" action="/admin/roles"><div ' +
      'class="formrow"><label>' + t.html('consoleRoles.body.thApplication') +
      ' <input type="text" ' +
      'name="application" list="role-preview-apps" value="' +
        kit.esc((preview && preview.asked.application) || '') +
        '"></label>' +
      '<datalist id="role-preview-apps">' + applicationOptions +
      '</datalist><label>' + t.html('consoleRoles.body.subject') +
      ' <input type="text" name="subject" value="' +
        kit.esc((preview && preview.asked.subject) || '') + '"></label>' +
      '<label>' + t.html('consoleRoles.body.as') +
      ' <select name="subjectKind">' +
        '<option value="user">' + t.html('consoleRoles.body.aPerson') +
        '</option>' +
        '<option value="application"' +
        (preview && preview.asked.subjectKind === 'application' ?
         ' selected' :
         '') +
        '>' + t.html('consoleRoles.body.anApplication') +
        '</option></select></label>' +
      '<label>' + t.html('consoleRoles.body.issuing') +
      ' <select name="kind">' + issuanceOptions +
      '</select></label><button ' +
      'type="submit">' + t.html('consoleRoles.body.ask') +
      '</button></div></form>' +
      (preview
        ? (preview.available === false
            ? kit.warn(kit.esc(preview.why))
            : '<div class="' + (preview.allowed ? 'ok' : 'err') + '">' +
              '<strong>' + t.html('consoleRoles.body.verdict', {
                decision: preview.decision,
                allowed: preview.allowed ? 'yes' : 'no' }) +
              '</strong><br>' + kit.esc(preview.why) + '<br>' +
              '<span class="sub">' + t.html('consoleRoles.body.holds') +
              (preview.roles.length ? kit.codeList(preview.roles) :
               t.html('consoleRoles.body.noRole')) +
              t.html('consoleRoles.body.requires') +
              (preview.required.length ? kit.codeList(preview.required) :
               t.html('consoleRoles.body.nothing')) +
              t.html('consoleRoles.body.policy') + '<code>' +
              kit.esc(String(preview.policy ||
                             t.text('consoleRoles.body.none'))) +
              '</code>.</span></div>'
          )
        : '') +

      '<h3 id="policy">' + t.html('consoleRoles.body.policyHeading') +
      '</h3>' +
      (register.policy
        ? (register.policy.ok
            ? kit.note('<strong>' + (register.policy.builtIn
                ? t.html('consoleRoles.body.builtInDeciding')
                : t.html('consoleRoles.body.customDeciding',
                         { name: register.policy.name })) +
              '</strong>' + t.html('consoleRoles.body.theRule') +
              '<br><br>' +
              (register.policy.builtIn
                ? t.html('consoleRoles.body.seededBefore',
                         { name: register.policy.name }) +
                  '<a href="/admin/xacml/policies">' +
                  t.html('consoleRoles.body.policies') + '</a>' +
                  t.html('consoleRoles.body.seededAfter')
                : t.html('consoleRoles.body.overrideBefore') +
                  '<a href="/admin/xacml/editor">' +
                  t.html('consoleRoles.body.editor') + '</a>' +
                  t.html('consoleRoles.body.overrideAfter')) +
              '<br><br>' + t.html('consoleRoles.body.notRoot'))
            : kit.warn(t.html('consoleRoles.body.notEvaluated',
                              { why: register.policy.why }) +
              '<br><br>' + t.html('consoleRoles.body.notEvaluatedRest',
                { defaultRequired: register.defaultRequired })))
        : '') +

      '<h3 id="claim">' + t.html('consoleRoles.body.claimHeading') + '</h3>' +
      kit.note('<strong>' + (register.claim
        ? t.html('consoleRoles.body.claimOn', { name: register.claimName })
        : t.html('consoleRoles.body.claimOff')) +
      '</strong>' + t.html('consoleRoles.body.claimRest', {
        defaultRequired: register.defaultRequired,
        name: register.claimName })) +

      SettingsForms.forms(json.settings, '/admin/roles', undefined, t);

    return inner;
  }

  // One row of the configured table. The three membership lists are drawn as
  // one column each rather than one list of "members", because the three are
  // looked up in three different places and a reader tracking down why somebody
  // holds a role needs to know which one to look in.
  /**
   * Draws one row of the configured roles table: a column per member kind,
   * the permissions, and a Delete form.
   *
   * A console role's people and groups link to Admin roles instead of
   * carrying Remove buttons, and a console role cannot be deleted.
   *
   * @param one - the configured role
   * @param listView - the list view the forms carry
   * @param memberKinds - the kinds of member a role has, as the view
   *   carries them (`memberKinds`)
   * @param t - optional; the page's translator. `admin.ts` calls this
   *   without one, and its words are then the default translator's
   * @returns the table row as HTML
   */
  static roleRow(one, listView, memberKinds, t?) {
    t = kitEscaping(t || kit.context().t);
    const members = memberKinds.map(function (kindRow) {
      const list = one[kindRow.field];
      if (!list.length) {
        return '<td><span class="state-none">' +
               t.html('consoleRoles.roleRow.none') + '</span></td>';
      }
      // A CONSOLE ROLE'S PEOPLE AND GROUPS ARE THE ROSTER'S (#303): drawn,
      // with the door that changes them, and no Remove button here.
      if (one.console && kindRow.kind !== 'application') {
        return '<td>' + list.map(function (member) {
          return '<div><code>' + kit.esc(member) + '</code></div>';
        }).join('') + '<span class="sub">' +
          t.html('consoleRoles.roleRow.setOn') + '<a href="/admin/rbac">' +
          t.html('consoleRoles.body.adminRoles') + '</a></span></td>';
      }
      return '<td>' + list.map(function (member) {
        return '<div><code>' + kit.esc(member) + '</code> ' +
          '<form method="post" action="/admin/roles" class="inline">' +
          RolesPage.rolesBack(listView) +
          '<input type="hidden" name="action" value="remove-member">' +
          '<input type="hidden" name="role" value="' + kit.esc(one.name) +
          '">' +
          '<input type="hidden" name="kind" value="' + kit.esc(kindRow.kind) +
          '"><input type="hidden" name="member" value="' + kit.esc(member) +
          '"><button type="submit" class="danger">' +
          t.html('consoleRoles.roleRow.remove') + '</button></form></div>';
      }).join('') + '</td>';
    }).join('');
    // WHAT THE ROLE AUTHORIZES (#303), each removable unless the role is a
    // console role, whose permission is fixed.
    const permissions = (one.permissions || []).length
      ? '<td>' + one.permissions.map(function (permission) {
          return '<div><code>' + kit.esc(permission) + '</code>' +
            (one.native ? '' :
              ' <form method="post" action="/admin/roles" class="inline">' +
              RolesPage.rolesBack(listView) +
              '<input type="hidden" name="action" value="remove-permission">' +
              '<input type="hidden" name="role" value="' +
              kit.esc(one.name) + '"><input type="hidden" ' +
              'name="permission" value="' + kit.esc(permission) + '">' +
              '<button type="submit" class="danger">' +
              t.html('consoleRoles.roleRow.remove') + '</button>' +
              '</form>') + '</div>';
        }).join('') + '</td>'
      : '<td><span class="state-none">' + t.html('consoleRoles.roleRow.none') +
        '</span></td>';
    return '<tr><td class="who"><code>' + kit.esc(one.name) + '</code>' +
      (one.console
        ? ' <span class="sub">' + t.html('consoleRoles.roleRow.consoleRole') +
          '</span>'
        : (one.native
          ? ' <span class="sub">' + t.html('consoleRoles.roleRow.nativeRole') +
            '</span>'
          : '')) +
      // AN APPLICATION'S ROLE (#310): whose it is, and the name its tokens
      // carry.
      (one.application ? '<br><span class="sub">' +
        t.html('consoleRoles.roleRow.roleOf', { application: one.application,
                                                 local: one.localName }) +
        '</span>' : '') +
      (one.description ? '<br><span class="sub">' + kit.esc(one.description) +
                         '</span>' : '') +
      // ITS LABEL, WHO MAY HOLD IT AND ITS STABLE ID (#93). The display name
      // is in a <b>, which a message may not carry, so it stays in code.
      (one.displayName ? '<br><span class="sub">' +
        t.html('consoleRoles.roleRow.shownAs') + '<b>' +
        kit.esc(one.displayName) + '</b></span>' : '') +
      ((one.memberTypes || []).length ? '<br><span class="sub">' +
        t.html('consoleRoles.roleRow.heldBy', {
          types: RolesPage.roleMemberTypesLabel(one.memberTypes, t) }) +
        '</span>'
        : '') +
      (one.id ? '<br><span class="sub">' +
        t.html('consoleRoles.roleRow.id', { id: one.id }) +
        '</span>' : '') +
      RolesPage.conferredBy(t, one, listView) +
      '</td>' + members + permissions +
      '<td class="act">' + RolesPage.roleEditFold(t, one, listView) +
      (one.native
        ? '<span class="sub">' + t.html('consoleRoles.roleRow.kept') +
          '</span>'
        : '<form method="post" action="/admin/roles">' +
          RolesPage.rolesBack(listView) +
          '<input type="hidden" name="action" value="delete-role">' +
          '<input type="hidden" name="role" value="' + kit.esc(one.name) +
          '">' +
          '<button type="submit" class="danger">' +
          t.html('consoleRoles.roleRow.delete') + '</button>' +
          '</form>') + '</td></tr>';
  }

  // WHICH CLIENTS CONFER IT (#454): every person signing in through one of
  // them holds the role on that client's token. Each with its Remove; the
  // add is in the Edit fold.
  /**
   * Draws the clients that confer a role, each with a Remove form.
   *
   * @param t - the page's translator
   * @param one - the configured role
   * @param listView - the list view the forms carry
   * @returns the lines as HTML, or nothing when no client confers it
   */
  static conferredBy(t, one, listView) {
    const clients = one.conferredBy || [];
    if (!clients.length) {
      return '';
    }
    return '<br><span class="sub">' +
      t.html('consoleRoles.conferredBy.lead') + '</span>' +
      clients.map(function (client) {
        return '<div><code>' + kit.esc(client) + '</code> ' +
          '<form method="post" action="/admin/roles" class="inline">' +
          RolesPage.rolesBack(listView) +
          '<input type="hidden" name="action" ' +
          'value="remove-conferring-client">' +
          '<input type="hidden" name="role" value="' + kit.esc(one.name) +
          '"><input type="hidden" name="client" value="' +
          kit.esc(client) + '"><button type="submit" class="danger">' +
          t.html('consoleRoles.roleRow.remove') + '</button></form></div>';
      }).join('');
  }

  /**
   * Draws the hidden "back" field the roles page's forms carry.
   *
   * @param listView - the list view to return to, or nothing
   * @returns a hidden input as HTML
   */
  static rolesBack(listView) {
    return '<input type="hidden" name="back" value="' +
           kit.esc(kit.queryWith(listView || {}, {})) + '">';
  }

  // THE EDIT FOLD (#93): describe-role's form — the description, the display
  // name and, for any role but a console role, who may hold it. Every field
  // is posted, filled with what the role has, so saving one change keeps the
  // others. A `<details>`, which needs no script (the policy's rule).
  /**
   * Draws a role's Edit fold: its description, display name and member
   * types, posted as describe-role.
   *
   * @param t - the page's translator
   * @param one - the configured role
   * @param listView - the list view the form carries
   * @returns the fold as HTML
   */
  static roleEditFold(t, one, listView) {
    const current = (one.memberTypes || []).length === 1
      ? one.memberTypes[0] : '';
    const typeField = one.console ? ''
      : '<label>' + t.html('consoleRoles.body.mayBeHeldBy') +
        ' <select name="memberTypes">' +
        [['', t.text('consoleRoles.body.peopleAndApps')],
         ['user', t.text('consoleRoles.body.peopleOnly')],
         ['application', t.text('consoleRoles.body.appsOnly')]]
          .map(function (option) {
          return '<option value="' + option[0] + '"' +
                 (option[0] === current ? ' selected' : '') + '>' +
                 kit.esc(option[1]) + '</option>';
        }).join('') + '</select></label>';
    return '<details><summary>' + t.html('consoleRoles.roleEditFold.edit') +
      '</summary>' +
      '<form method="post" action="/admin/roles">' +
      RolesPage.rolesBack(listView) +
      '<input type="hidden" name="action" value="describe-role">' +
      '<input type="hidden" name="role" value="' + kit.esc(one.name) + '">' +
      '<label>' + t.html('consoleRoles.body.displayName') +
      ' <input name="displayName" value="' +
      kit.esc(one.displayName || '') + '"></label>' +
      '<label>' + t.html('consoleRoles.body.description') +
      ' <input name="description" value="' +
      kit.esc(one.description || '') + '"></label>' + typeField +
      '<button type="submit">' + t.html('consoleRoles.roleEditFold.save') +
      '</button></form>' +
      // CONFERRED BY A CLIENT (#454), for any role but a console role, whose
      // people are the roster's, or one only applications may hold.
      (one.console || ((one.memberTypes || []).length &&
                       one.memberTypes.indexOf('user') < 0) ? ''
        : '<form method="post" action="/admin/roles">' +
          RolesPage.rolesBack(listView) +
          '<input type="hidden" name="action" ' +
          'value="add-conferring-client">' +
          '<input type="hidden" name="role" value="' + kit.esc(one.name) +
          '"><label title="' +
          kit.esc(t.text('consoleRoles.roleEditFold.conferTitle')) + '">' +
          t.html('consoleRoles.roleEditFold.conferredBy') + ' ' +
          '<input name="client" required></label>' +
          '<button type="submit">' + t.html('consoleRoles.body.add') +
          '</button></form>') +
      '</details>';
  }

  // Who a role's member types let hold it, in words (#93).
  /**
   * Names a role's member types for people: "people", "applications".
   *
   * @param types - the role's `memberTypes`
   * @param t - optional; the page's translator
   * @returns the words
   */
  static roleMemberTypesLabel(types, t?) {
    t = t || kit.context().t;
    return (types || []).map(function (one) {
      return one === 'user' ? t.text('consoleRoles.roleMemberTypesLabel.people')
        : t.text('consoleRoles.roleMemberTypesLabel.applications');
    }).join(' ' + t.text('consoleRoles.roleMemberTypesLabel.and') + ' ');
  }
}

export = RolesPage;
