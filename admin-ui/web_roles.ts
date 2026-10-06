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
    const register = json;
    const listView = kit.listViewOf('/admin/roles', ctx.query);
    const navParams = kit.pageParamsOf(ctx.query);
    const q = json.query.q;
    const rolesNav = kit.pageNavPair('/admin/roles', navParams,
                                      json.paging);
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
      '<h2>Roles</h2>' +
      kit.note('<strong>A role is a name somebody may hold, and holding ' +
      'one is what this service decides an ISSUANCE on.</strong> Three ' +
      'kinds of thing can be mapped into a role &mdash; a person, a group ' +
      '(so every member of it holds the role) and an APPLICATION (so a ' +
      'client authenticating as itself holds one, which is what a ' +
      '<code>client_credentials</code> grant is decided on, where there is ' +
      'no person at all). An application entry names the roles it REQUIRES ' +
      'in <code>appRequiredRole</code>, and nothing is issued for that ' +
      'application to somebody who holds none of them &mdash; a decision ' +
      'made by the XACML PDP against the policy ' +
      '<code>xacml.issuancePolicy</code> names, never by an ' +
      '<code>if</code> in an issuance site. So the reason for a refusal is ' +
      'a document you can read on <a ' +
      'href="/admin/xacml/policies">Policies</a>, test on <a ' +
      'href="/admin/xacml/decide">Try a decision</a>, and see in the <a ' +
      'href="/admin/audit">audit log</a>.') +

      kit.note('<strong>This is not <a href="/admin/rbac">Admin ' +
      'roles</a>, which is the page above it in the sidebar.</strong> That ' +
      'one has exactly two roles, they are ordinary directory GROUPS, and ' +
      'what they grant is this console. This one has as many roles as you ' +
      'make, they live in <code>' +
      kit.esc(register.container || 'ou=roles') + '</code>, and what they ' +
      'grant is being issued something. <strong>It is not <a ' +
      'href="/admin/groups">Groups</a> either</strong>. <strong>The two ' +
      'meet in one place since #303</strong>: <code>ADMIN_READ</code> and ' +
      '<code>ADMIN_WRITE</code> below are roles over those two groups, ' +
      'authorizing the management API\'s <code>admin:read</code> and ' +
      '<code>admin:write</code>. People hold them through Admin roles; an ' +
      'application is added to them here. And a group still ' +
      'grants nothing on its own, and that sentence is still true ' +
      'everywhere it is written. What changed is that a role may NAME a ' +
      'group &mdash; so adding somebody to <code>cn=developers</code> can ' +
      'now give them a role, through this register and only through it.') +

      (register.storable ? '' : kit.warn('<strong>There is nowhere to ' +
        'keep a role.</strong> This process has no embedded directory ' +
        'installed behind the register, so no role can be created. The six ' +
        'BUILT-IN roles below still answer &mdash; they are computed ' +
        'rather than stored &mdash; so an application requiring EVERYBODY ' +
        'still admits everybody, which is the default and means nothing is ' +
        'refused. There is no fallback store, deliberately: a role ' +
        'register that quietly lived in memory would decide things nobody ' +
        'could find.')) +

      (register.enforced ? '' : kit.warn('<strong>Nothing is being ' +
        'decided.</strong> <code>roles.enforceIssuance</code> is OFF, so ' +
        'no issuance asks the PDP at all and every application admits ' +
        'everybody whatever its entry says. This page still records what ' +
        'would be asked. The switch is in Settings at the foot of this ' +
        'page, and it is the way back if a policy edit locks something ' +
        'out.')) +

      (register.gated ? '' : kit.warn('<strong>The XACML family is not ' +
        'loaded in this process.</strong> ' +
        '<code>common/issuance_gate.js</code> has no decider, so every ' +
        'issuance is allowed and this page is a register that nothing ' +
        'reads. That is the designed behaviour for a process without the ' +
        'engine &mdash; a smaller service rather than a broken one &mdash; ' +
        'and it is what <code>npm test</code> and the parent project\'s ' +
        'in-process Kerberos jobs run as.')) +

      '<h3 id="built-in">The ' + register.builtIn.length +
      ' built-in roles</h3>' +
      kit.note('<strong>Computed, in no container, and not ' +
      'editable.</strong> Every one of them is answered from the CONTEXT ' +
      'of the decision being made rather than from a store, so they have ' +
      'no members to list and cannot be created, renamed or deleted. ' +
      '<code>' + kit.esc(register.defaultRequired) + '</code> is the one ' +
      'that matters most: an application that names no required role ' +
      'requires it, everybody holds it, and nothing is refused &mdash; ' +
      'which is exactly how this service behaved before roles existed. ' +
      '<strong>That is what makes this feature off by default without ' +
      'being absent</strong>: the machinery is always running and always ' +
      'visible, and narrowing an application is shortening a list rather ' +
      'than switching on a subsystem that has never run. The pairs are ' +
      'complementary ON PURPOSE and both halves exist because ' +
      '&ldquo;everyone who did not sign in&rdquo; is a thing policy ' +
      'authors reach for and cannot express as a negation in a XACML ' +
      'target.') +
      '<table><thead><tr><th>Role</th><th>Who holds ' +
      'it</th></tr></thead><tbody>' +
      register.builtIn.map(function (one) {
        return '<tr><td class="who"><code>' + kit.esc(one.name) +
               '</code></td><td>' + kit.esc(one.what) + '</td></tr>';
      }).join('') +
      '</tbody></table>' +

      '<h3 id="roles">Roles you have made</h3>' +
      kit.note('<strong>Membership, and nothing else.</strong> Each row ' +
      'is one entry under ' +
      '<code>' + kit.esc(register.container || 'ou=roles') + '</code>; ' +
      'every column but the first is somebody who HOLDS the role. What a ' +
      'role is REQUIRED for is not here &mdash; that lives on the ' +
      'application entry that requires it and is drawn read-only further ' +
      'down, because it is a fact about the application rather than about ' +
      'the role.') +
      '<form method="get" action="/admin/roles"><div class="formrow">' +
        '<label for="q">Text</label>' +
        '<input type="text" id="q" name="q" size="40" value="' + kit.esc(q) +
          '" placeholder="a role, a description or a member">' +
        '<button class="secondary">Filter</button>' +
        (q ? ' <a href="/admin/roles#roles">clear</a>' : '') +
      '</div></form>' +
      '<table><thead><tr><th>Role</th>' +
      json.memberKinds.map(function (one) {
        return '<th>Held by ' + kit.esc(one.label) + '</th>';
      }).join('') +
      '<th>Authorizes</th><th></th></tr></thead><tbody>' +
      (rolePage.shown.length
        ? rolePage.shown.map(function (one) { return RolesPage.roleRow(one,
            listView, json.memberKinds); })
                        .join('')
        : '<tr><td colspan="6"><span class="state-none">' +
          (q ? 'No role matches &ldquo;' + kit.esc(q) + '&rdquo;.'
             : 'No role has been made. Every application therefore ' +
               'requires ' +
               kit.esc(register.defaultRequired) + ' and refuses nobody.') +
          '</span></td></tr>') +
      '</tbody></table>' + rolesNav +

      '<h3 id="create">Make a role</h3>' +
      kit.note('The name becomes an LDAP RDN under <code>' +
      kit.esc(register.container || 'ou=roles') + '</code> and a value in ' +
      'a token claim, so it is up to 64 characters of letters, digits, and ' +
      '<code>. _ : @ -</code> or a space. It may not be one of the six ' +
      'above: those are computed and answered first, so a stored role of ' +
      'the same name could never be reached.') +
      '<form method="post" action="/admin/roles">' +
      RolesPage.rolesBack(listView) +
      '<input type="hidden" name="action" value="create-role"><div ' +
      'class="formrow"><label>Name <input type="text" name="role" ' +
      'required></label><label>Description <input type="text" ' +
      'name="description" size="50"></label>' +
      // FOR ONE APPLICATION (#310), or for the realm when left empty.
      '<label title="' + kit.esc('Leave empty for a realm-wide role. ' +
        'Name an application to make a role that belongs to it alone: ' +
        'it is registered as <role>@<application>, and only a token for ' +
        'that application carries it.') + '">For application ' +
      '<input type="text" name="application" list="role-create-apps" ' +
      'placeholder="realm-wide"></label><datalist id="role-create-apps">' +
      applicationOptions + '</datalist>' +
      // ITS LABEL AND WHO MAY HOLD IT (#93).
      '<label>Display name <input type="text" name="displayName" ' +
      'placeholder="optional"></label><label>May be held by <select ' +
      'name="memberTypes"><option value="">people and applications' +
      '</option><option value="user">people only</option><option ' +
      'value="application">applications only</option></select></label>' +
      '<button type="submit">Create</button></div></form>' +

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
      '<h3 id="member">Give a person, a group or an application a role</h3>' +
      kit.note('<strong>All three are first-class members of a role ' +
      'here</strong> &mdash; a person, a group, and an APPLICATION holding ' +
      'it as itself.<br>' +
      json.memberKinds.map(function (one) {
        return '<strong>' + kit.esc(one.label) + '</strong> &mdash; ' +
               kit.esc(one.what);
      }).join('<br>')) +
      (register.roles.length ? '' : kit.warn('<strong>There is no role to ' +
        'add anybody to yet, so this form is disabled.</strong> ' +
        '<a href="#create">Create a role</a> first &mdash; the six ' +
        'built-in roles have no membership, because they are COMPUTED from ' +
        'what the party is rather than from anything anybody wrote down. ' +
        'That is why the Role list below is empty on a service where ' +
        'nobody has made one.')) +
      '<form method="post" action="/admin/roles">' +
      RolesPage.rolesBack(listView) +
      '<input type="hidden" name="action" value="add-member">' +
      '<div class="formrow">' +
      '<label>Role <select name="role" required>' + roleOptions +
      '</select></label><label>Kind ' +
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
        kit.esc('The suggestions are the applications registered in this ' +
                 'realm. A person or a group is typed by hand and need not ' +
                 'exist yet — this service creates an entry for any name ' +
                 'on first sight.') +
        '">Name <input type="text" name="member" list="role-member-apps" ' +
        'required></label>' +
      '<datalist id="role-member-apps">' + applicationOptions +
      '</datalist><button type="submit"' +
        (register.roles.length ? '' : ' disabled') + '>Add</button>' +
      '</div></form>' +

      // WHAT A ROLE AUTHORIZES (#303, part B of #88).
      '<h3 id="authorizes">Let a role authorize a permission</h3>' +
      kit.note('<strong>A scope is a request; a role is what authorizes ' +
      'it.</strong> A permission its resource application GATES ' +
      '(<code>oauthRoleGatedPermission</code> on the application\'s page) ' +
      'is issued only to a person or an application holding a role that ' +
      'names it here, and is left off the token otherwise &mdash; and a ' +
      'request asking for nothing else is refused ' +
      '<code>invalid_scope</code>. Name the permission as a client asks ' +
      'for it: the resource\'s <code>oauthPermissionBaseUri</code> ' +
      'followed by the name. It must be defined first. ' +
      '<code>admin:read</code> and <code>admin:write</code> are this ' +
      'service\'s own and are authorized by the console roles ' +
      '<code>ADMIN_READ</code> and <code>ADMIN_WRITE</code> alone: a person ' +
      'holds those through <a href="/admin/rbac">Admin roles</a>, and an ' +
      'application by being added to them above.') +
      '<form method="post" action="/admin/roles">' +
      RolesPage.rolesBack(listView) +
      '<input type="hidden" name="from" value="authorizes">' +
      '<input type="hidden" name="action" value="add-permission">' +
      '<div class="formrow">' +
      '<label>Role <select name="role" required>' +
      register.roles.filter(function (one) {
        return !one.native;
      }).map(function (one) {
        return '<option value="' + kit.esc(one.name) + '">' +
               kit.esc(one.name) + '</option>';
      }).join('') + '</select></label>' +
      '<label>Permission <input type="text" name="permission" size="50" ' +
      'list="role-permission-ids" required></label>' +
      '<datalist id="role-permission-ids">' + register.permissionIds
        .map(function (id) {
          return '<option value="' + kit.esc(id) + '">';
        }).join('') + '</datalist>' +
      '<button type="submit"' +
        (register.roles.some(function (one) { return !one.native; })
          ? '' : ' disabled') + '>Authorize</button>' +
      '</div></form>' +

      '<h3 id="requiring">What requires a role</h3>' +
      kit.note('<strong>The other relation, and it is edited somewhere ' +
      'else.</strong> An application demands roles through ' +
      '<code>appRequiredRole</code> on its own entry, which is where it is ' +
      'written &mdash; on the application\'s page, in the attribute ' +
      'editor, or with an <code>ldapmodify</code>. This table RESOLVES it, ' +
      'which that page cannot: it says whether anything actually defines ' +
      'each role named. <strong>Only NARROWED applications are ' +
      'listed.</strong> Every other application in this realm requires ' +
      '<code>' +
      kit.esc(register.defaultRequired) + '</code>, which everybody ' +
      'holds, and listing all of them would bury the ones somebody ' +
      'restricted on purpose.') +
      '<table><thead><tr><th>Application</th><th>Requires</th>' +
      '<th>Any of them holdable?</th></tr></thead><tbody>' +
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
              }).join(' or ') + '</td>' +
              '<td>' + (one.unknown.length
                ? '<span class="state-none">No. ' +
                  one.unknown.map(function (role) {
                    return '<code>' + kit.esc(role) + '</code>';
                  }).join(', ') + ' is not a built-in role and no entry ' +
                  'defines it, so NOBODY can hold it and this application ' +
                  'is issued nothing at all &mdash; which looks exactly ' +
                  'like the application being broken. Make the role, or ' +
                  'clear the value.</span>'
                : 'Yes &mdash; every role named is defined.') + '</td></tr>';
          }).join('')
        : '<tr><td colspan="3"><span class="state-none">Nothing has been ' +
          'narrowed. Every application in this realm requires <code>' +
          kit.esc(register.defaultRequired) + '</code> and refuses ' +
          'nobody, which is the state this service starts ' +
          'in.</span></td></tr>') +
      '</tbody></table>' +

      '<h3 id="preview">Would this be issued?</h3>' +
      kit.note('<strong>The same call the nine issuance sites ' +
      'make.</strong> It goes through the embedded PEP and the PDP against ' +
      'the issuance policy, so a preview that agreed with the enforcement ' +
      'only by coincidence is impossible &mdash; which is the only reason ' +
      'it is worth having. Nothing is issued and nothing is recorded. <a ' +
      'href="/admin/xacml/decide">Try a decision</a> asks the same engine ' +
      'the other way round: an arbitrary request against the repository ' +
      'root, which is the policy about somebody ELSE\'s boundary.') +
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
      'class="formrow"><label>Application <input type="text" ' +
      'name="application" list="role-preview-apps" value="' +
        kit.esc((preview && preview.asked.application) || '') +
        '"></label>' +
      '<datalist id="role-preview-apps">' + applicationOptions +
      '</datalist><label>Subject <input type="text" name="subject" value="' +
        kit.esc((preview && preview.asked.subject) || '') + '"></label>' +
      '<label>as <select name="subjectKind">' +
        '<option value="user">a person</option>' +
        '<option value="application"' +
        (preview && preview.asked.subjectKind === 'application' ?
         ' selected' :
         '') +
        '>an application</option></select></label>' +
      '<label>Issuing <select name="kind">' + issuanceOptions +
      '</select></label><button ' +
      'type="submit">Ask</button></div></form>' +
      (preview
        ? (preview.available === false
            ? kit.warn(kit.esc(preview.why))
            : '<div class="' + (preview.allowed ? 'ok' : 'err') + '">' +
              '<strong>' + kit.esc(preview.decision) + ' &mdash; ' +
              (preview.allowed ? 'it would be issued' :
               'it would be REFUSED') +
              '.</strong><br>' + kit.esc(preview.why) + '<br>' +
              '<span class="sub">Holds: ' +
              (preview.roles.length ? kit.codeList(preview.roles) :
               'no role at all') +
              '. Requires: ' +
              (preview.required.length ? kit.codeList(preview.required) :
               'nothing') +
              '. Policy: <code>' +
              kit.esc(String(preview.policy || '(none)')) +
              '</code>.</span></div>'
          )
        : '') +

      '<h3 id="policy">The policy that decides</h3>' +
      (register.policy
        ? (register.policy.ok
            ? kit.note('<strong>' + (register.policy.builtIn
                ? 'The BUILT-IN issuance policy is deciding.'
                : 'A policy you wrote is deciding: <code>' +
                  kit.esc(register.policy.name) + '</code>.') +
              '</strong> The rule it states is the same either way &mdash; ' +
              'the party being authenticated must hold one of the roles ' +
              'the application requires &mdash; and the requirement ' +
              'travels in the REQUEST rather than being written into the ' +
              'document, which is why ONE policy decides for every ' +
              'application and narrowing one is editing its entry rather ' +
              'than editing a policy.<br><br>' +
              (register.policy.builtIn
                ? '<strong>Nothing is seeded and there is nothing to ' +
                  'delete.</strong> It was seeded once and the realm case ' +
                  'killed that: <code>ou=policies</code> is per realm and ' +
                  'the seed is written in the default realm at startup, so ' +
                  'a realm created afterwards had no issuance policy and ' +
                  'every application narrowed in it was issued NOTHING. To ' +
                  'EDIT the rule, create a policy named <code>' +
                  kit.esc(register.policy.name) + '</code> from the ' +
                  '<code>role-issuance</code> template on ' +
                  '<a href="/admin/xacml/policies">Policies</a>: an entry ' +
                  'of that name overrides the built-in one.'
                : 'It is an ordinary entry under <code>ou=policies</code>, ' +
                  'so the <a href="/admin/xacml/editor">editor</a>, ALFA, ' +
                  '<code>/admin-api/xacml</code> and an ' +
                  '<code>ldapmodify</code> all reach it. DELETING it puts ' +
                  'the built-in policy back &mdash; it is an override ' +
                  'rather than the only copy.') +
              '<br><br><strong>It is not the repository ROOT and it is not ' +
              'sent to remote PEPs.</strong> Two questions, two documents: ' +
              'the root answers what a caller asks at ' +
              '<code>/xacml/pdp</code> and what every remote PEP pulls, ' +
              'and this answers who may be issued something HERE. Making ' +
              'them one document would mean editing the demo policy ' +
              'changed who could sign in.')
            : kit.warn('<strong>The issuance policy is not being ' +
              'evaluated.</strong> ' +
              kit.esc(register.policy.why) + '<br><br>An application that ' +
              'requires only <code>' + kit.esc(register.defaultRequired) +
              '</code> is unaffected &mdash; everybody holds it, so there ' +
              'was never anything to decide. <strong>An application whose ' +
              'entry names a role is REFUSED</strong>, and that asymmetry ' +
              'is deliberate: somebody deliberately asked for a ' +
              'restriction, and permitting because the document ' +
              'implementing it is missing would be a configured refusal ' +
              'silently not happening.'))
        : '') +

      '<h3 id="claim">The claim</h3>' +
      kit.note('<strong>' + (register.claim
        ? 'Every access token, ID Token, SAML 2.0 assertion and SAML 1.1 ' +
          'assertion names the roles its subject holds, in <code>' +
          kit.esc(register.claimName) + '</code>.'
        : 'The claim is OFF, so nothing carries a role.') +
      '</strong> The claim is OMITTED ENTIRELY for anybody holding no ' +
      'CONFIGURED role, and the six built-in ones are never in it: <code>' +
      kit.esc(register.defaultRequired) + '</code> and ' +
      '<code>ALL_AUTHENTICATED_USERS</code> are true of almost every token ' +
      'this service issues, so carrying them would add two meaningless ' +
      'members to every token every existing client parses and tell a ' +
      'relying party nothing it did not know from holding the token. They ' +
      'exist to be REQUIRED, not to be ' +
      'carried.<br><br><code>' + kit.esc(register.claimName) + '</code> ' +
      'is ALSO what is looked for on the way IN: the embedded PEP reads ' +
      'that member out of a token a caller presented and unions what it ' +
      'finds with this register\'s own answer. <strong>That half is weaker ' +
      'and the policy says so in its own description</strong> &mdash; this ' +
      'service does not verify access tokens it did not issue, so a claim ' +
      'is evidence about a token rather than about a person. The ' +
      '<code>role-issuance</code> template has a parameter that leaves ' +
      'that arm out.') +

      SettingsForms.forms(json.settings, '/admin/roles');

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
   * @returns the table row as HTML
   */
  static roleRow(one, listView, memberKinds) {
    const members = memberKinds.map(function (kindRow) {
      const list = one[kindRow.field];
      if (!list.length) {
        return '<td><span class="state-none">none</span></td>';
      }
      // A CONSOLE ROLE'S PEOPLE AND GROUPS ARE THE ROSTER'S (#303): drawn,
      // with the door that changes them, and no Remove button here.
      if (one.console && kindRow.kind !== 'application') {
        return '<td>' + list.map(function (member) {
          return '<div><code>' + kit.esc(member) + '</code></div>';
        }).join('') + '<span class="sub">set on <a href="/admin/rbac">Admin ' +
          'roles</a></span></td>';
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
          '"><button type="submit" class="danger">Remove</button></form></div>';
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
              '<button type="submit" class="danger">Remove</button>' +
              '</form>') + '</div>';
        }).join('') + '</td>'
      : '<td><span class="state-none">none</span></td>';
    return '<tr><td class="who"><code>' + kit.esc(one.name) + '</code>' +
      (one.console ? ' <span class="sub">console role</span>'
        : (one.native ? ' <span class="sub">native role</span>' : '')) +
      // AN APPLICATION'S ROLE (#310): whose it is, and the name its tokens
      // carry.
      (one.application ? '<br><span class="sub">role of <code>' +
        kit.esc(one.application) + '</code>, carried as <code>' +
        kit.esc(one.localName) + '</code></span>' : '') +
      (one.description ? '<br><span class="sub">' + kit.esc(one.description) +
                         '</span>' : '') +
      // ITS LABEL, WHO MAY HOLD IT AND ITS STABLE ID (#93).
      (one.displayName ? '<br><span class="sub">shown as <b>' +
        kit.esc(one.displayName) + '</b></span>' : '') +
      ((one.memberTypes || []).length ? '<br><span class="sub">held by ' +
        kit.esc(RolesPage.roleMemberTypesLabel(one.memberTypes)) +
          ' only</span>'
        : '') +
      (one.id ? '<br><span class="sub">id <code>' + kit.esc(one.id) +
        '</code></span>' : '') +
      RolesPage.conferredBy(one, listView) +
      '</td>' + members + permissions +
      '<td class="act">' + RolesPage.roleEditFold(one, listView) + (one.native
        ? '<span class="sub">kept in every realm</span>'
        : '<form method="post" action="/admin/roles">' +
          RolesPage.rolesBack(listView) +
          '<input type="hidden" name="action" value="delete-role">' +
          '<input type="hidden" name="role" value="' + kit.esc(one.name) +
          '">' +
          '<button type="submit" class="danger">Delete</button>' +
          '</form>') + '</td></tr>';
  }

  // WHICH CLIENTS CONFER IT (#454): every person signing in through one of
  // them holds the role on that client's token. Each with its Remove; the
  // add is in the Edit fold.
  /**
   * Draws the clients that confer a role, each with a Remove form.
   *
   * @param one - the configured role
   * @param listView - the list view the forms carry
   * @returns the lines as HTML, or nothing when no client confers it
   */
  static conferredBy(one, listView) {
    const clients = one.conferredBy || [];
    if (!clients.length) {
      return '';
    }
    return '<br><span class="sub">conferred on everybody signing in ' +
      'through</span>' + clients.map(function (client) {
        return '<div><code>' + kit.esc(client) + '</code> ' +
          '<form method="post" action="/admin/roles" class="inline">' +
          RolesPage.rolesBack(listView) +
          '<input type="hidden" name="action" ' +
          'value="remove-conferring-client">' +
          '<input type="hidden" name="role" value="' + kit.esc(one.name) +
          '"><input type="hidden" name="client" value="' +
          kit.esc(client) + '"><button type="submit" class="danger">' +
          'Remove</button></form></div>';
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
   * @param one - the configured role
   * @param listView - the list view the form carries
   * @returns the fold as HTML
   */
  static roleEditFold(one, listView) {
    const current = (one.memberTypes || []).length === 1
      ? one.memberTypes[0] : '';
    const typeField = one.console ? ''
      : '<label>May be held by <select name="memberTypes">' +
        [['', 'people and applications'], ['user', 'people only'],
         ['application', 'applications only']].map(function (option) {
          return '<option value="' + option[0] + '"' +
                 (option[0] === current ? ' selected' : '') + '>' +
                 kit.esc(option[1]) + '</option>';
        }).join('') + '</select></label>';
    return '<details><summary>Edit</summary>' +
      '<form method="post" action="/admin/roles">' +
      RolesPage.rolesBack(listView) +
      '<input type="hidden" name="action" value="describe-role">' +
      '<input type="hidden" name="role" value="' + kit.esc(one.name) + '">' +
      '<label>Display name <input name="displayName" value="' +
      kit.esc(one.displayName || '') + '"></label>' +
      '<label>Description <input name="description" value="' +
      kit.esc(one.description || '') + '"></label>' + typeField +
      '<button type="submit">Save</button></form>' +
      // CONFERRED BY A CLIENT (#454), for any role but a console role, whose
      // people are the roster's, or one only applications may hold.
      (one.console || ((one.memberTypes || []).length &&
                       one.memberTypes.indexOf('user') < 0) ? ''
        : '<form method="post" action="/admin/roles">' +
          RolesPage.rolesBack(listView) +
          '<input type="hidden" name="action" ' +
          'value="add-conferring-client">' +
          '<input type="hidden" name="role" value="' + kit.esc(one.name) +
          '"><label title="' + kit.esc('Every person who signs in through ' +
            'this client holds the role on the token it is issued, beside ' +
            'the roles they hold themselves.') + '">Conferred by the client ' +
          '<input name="client" required></label>' +
          '<button type="submit">Add</button></form>') +
      '</details>';
  }

  // Who a role's member types let hold it, in words (#93).
  /**
   * Names a role's member types for people: "people", "applications".
   *
   * @param types - the role's `memberTypes`
   * @returns the words
   */
  static roleMemberTypesLabel(types) {
    return (types || []).map(function (one) {
      return one === 'user' ? 'people' : 'applications';
    }).join(' and ');
  }
}

export = RolesPage;
