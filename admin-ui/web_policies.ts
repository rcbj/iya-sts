// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_policies.ts
//
// ---------------------------------------------------------------------------
// DIRECTORY → POLICIES, DRAWN FROM ITS VIEW ALONE (#446, 2026-10-05).
//
// Draws Policies from the answer of `GET /admin-api/policies`: every kind of
// policy a realm holds — password, authentication and the others — each
// profile with its form.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// It was drawn inside the route of `/admin/policies` in `admin-ui/admin.ts`,
// which still draws the page until the console's cutover by calling this with
// its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');

type Json = any;

/**
 * Draws Policies from the answer of `GET /admin-api/policies`: every kind of
 * policy a realm holds — password, authentication and the others — each
 * profile with its form.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class PoliciesPage {
  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param view - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static body(ctx, view) {
    // The view's own paging, which is the same paging this recomputed
    // (#446): the page is drawn from the answer alone.
    const listedNav = kit.pageNavPair('/admin/policies',
                                       kit.pageParamsOf(ctx.query),
                                       view.paging);
    const kindLabel = {};
    view.kinds.forEach(function (kind) {
      kindLabel[kind.id] = kind.label;
    });

    const inner = '<div class="tiles">' +
        kit.tile(view.kinds.length, 'kind of policy') +
        kit.tile(view.paging.total, 'profile') +
        kit.tile(view.enforced ? 'yes' : 'no',
                  'password policy enforced in this realm') +
      '</div>' +

      kit.note('<strong>A policy here is a rule this realm holds a ' +
      'credential to.</strong> Each kind below is a SEPARATE policy with ' +
      'its own entry in its own container, and each has one profile — ' +
      '<code>default</code> — which applies to every person in this ' +
      'realm. ' +
      view.kinds.map(function (kind) {
        return '<a href="#' + kit.esc(kind.id) + '">' +
          kit.esc(kind.label) + '</a> (<code>' +
          kit.esc(kind.container) + '</code>)';
      }).join(', ') + '. <strong>This is not the XACML policy ' +
      'repository</strong>: <a href="/admin/xacml/policies">that one</a> ' +
      'holds documents a PDP evaluates, in <code>ou=policies</code>.') +

      view.kinds.map(function (kind) {
        if (kind.id === 'password') {
          return PoliciesPage.passwordPolicySection(view);
        }
        if (kind.id === 'authn') {
          return PoliciesPage.authnPolicySection(view);
        }
        return PoliciesPage.genericPolicySection(view, kind);
      }).join('') +

      '<h2 id="profiles">Profiles</h2>' +
      kit.note('One profile of each kind today, and the list is paged ' +
      'like every list in this console. A second profile of a kind cannot ' +
      'be created yet: nothing assigns a profile to a person, so a second ' +
      'one would decide nothing while looking exactly like one that does.') +
      listedNav.head +
      '<table><tr><th>Kind</th><th>Profile</th><th>Stored at</th>' +
      '<th>Problems</th></tr>' +
      view.profiles.map(function (row) {
        return '<tr><td>' + kit.esc(kindLabel[row.kind] || row.kind) +
          '</td><td><a href="#' + kit.esc(row.kind) + '">' +
          kit.esc(row.name) + '</a></td><td>' +
          (row.stored ? '<code>' + kit.esc(row.dn) + '</code>'
            : row.inherited
              ? 'inherited from the default realm: <code>' +
                kit.esc(row.dn) + '</code>'
              : '<span class="state-none">not stored — built-in ' +
                'defaults</span>') +
          '</td><td>' + kit.esc(String(row.problems.length)) + '</td></tr>';
      }).join('') + '</table>' +
      listedNav.foot +

      kit.note('The same over JSON is ' +
      '<code>/admin/policies?format=json</code> and <code>GET ' +
      '/admin-api/policies</code>; the actions on this page are ' +
      view.actions.map(function (action) {
        return '<code>POST /admin-api/policies/' + kit.esc(action) +
               '</code>';
      }).join(', ') + '.');

    return inner;
  }

  /**
   * Draws the authentication policy section of /admin/policies: the mail and
   * NIST warnings, where the profile comes from, the forms, and which
   * mechanisms are accepted as a first and a second factor.
   *
   * @param view - the policies view from adminViews.policiesView()
   * @returns the section as HTML
   */
  static authnPolicySection(view) {
    const kind = view.kinds.filter(function (k) {
      return k.id === 'authn';
    })[0];
    const ap = view.authn;
    const profile = ap.profile;
    const yesNo = function (value, active) {
      return value === null ? '<span class="off">—</span>'
        : value ? (active ? 'yes' : 'yes — <strong>inactive</strong>')
          : 'no';
    };
    const out =
      '<h2 id="authn">Authentication policy — the default profile</h2>' +
      kit.note('Which ways of signing in this realm accepts as a FIRST ' +
      'factor and as a SECOND, and when a second factor is required. ' +
      'Asked at every sign-in door, in both modes: this policy decides what ' +
      'the sign-in screen offers, not whether a credential is checked.') +

      (ap.mail.usable ? ''
        : kit.warn('<strong>This realm cannot send mail</strong>, so the ' +
          'two email mechanisms are drawn disabled below and are never ' +
          'offered. Configure a transport on <a href="/admin/mail">Server ' +
          'configuration → Mail</a>.')) +

      kit.warn('<strong>Email as an authenticator.</strong> ' +
        kit.esc(ap.nistWarning)) +

      PoliciesPage.policyProblems(profile) +

      kit.note(profile.from === 'realm'
        ? 'This realm\'s own profile is <strong>stored</strong> at <code>' +
          kit.esc(profile.dn) + '</code>. Removing it puts this realm back ' +
          'to the default realm\'s profile, or to the built-in defaults ' +
          'where the default realm has none.'
        : profile.from === 'default-realm'
          ? '<strong>This realm has no profile of its own, and follows the ' +
            'default realm\'s</strong> (<code>' + kit.esc(profile.dn) +
            '</code>). Saving this form writes this realm\'s own, which ' +
            'overrides it here and nowhere else.'
          : '<strong>Nothing is stored, so the built-in defaults are in ' +
            'force.</strong> Saving this form writes <code>cn=default</code> ' +
            'under <code>ou=authnPolicies</code>. Saved in the DEFAULT ' +
            'realm, it is the policy of every realm that has none of its ' +
            'own.') +

      PoliciesPage.policyForms(kind, ap, 'ap-',
        kit.note('Every field is checked ' +
      'before anything is written. At least one mechanism must be accepted ' +
      'as a first factor, and if a second factor is required of everybody ' +
      'at least one must be accepted as a second. <strong>A person who ' +
      'HOLDS a second factor is asked for it whatever this says</strong>: ' +
      'there is no setting that skips a held factor.')) +

      '<h3 id="authn-now">What this realm accepts, right now</h3>' +
      '<ul>' + ap.rules.map(function (rule) {
        return '<li>' + kit.esc(rule) + '</li>';
      }).join('') + '</ul>' +
      '<table><tr><th>Mechanism</th><th>First factor</th>' +
      '<th>Second factor</th></tr>' +
      ap.mechanisms.map(function (m) {
        return '<tr><td>' + kit.esc(m.label) + '</td><td>' +
          yesNo(m.primary, m.active) + '</td><td>' +
          yesNo(m.secondFactor, m.active) + '</td></tr>';
      }).join('') + '</table>' +
      kit.note('A dash is a role the mechanism cannot have: an ' +
      'authenticator app or a recovery code is never a first factor, and ' +
      'a certificate, a Kerberos ticket, a wallet or a federation partner ' +
      'is never asked for second.') +

      '<h3 id="authn-schema">Schema</h3>' +
      PoliciesPage.policySchemaTables(ap.schema);
    return out;
  }

  // A kind this console has nothing particular to say about: its fields,
  // its rules and its schema, from its module.
  /**
   * Draws the section of /admin/policies for a kind of policy with nothing
   * particular to say: its forms, rules and schema, from its module.
   *
   * @param view - the policies view from adminViews.policiesView()
   * @param kind - the policy kind
   * @returns the section as HTML
   */
  static genericPolicySection(view, kind) {
    const member = view[kind.id];
    const out = '<h2 id="' + kit.esc(kind.id) + '">' +
      kit.esc(kind.label) + ' — the default profile</h2>' +
      kit.note('Governs ' + kit.esc(kind.governs) + '. Stored under ' +
      '<code>' + kit.esc(kind.container) + '</code>.') +
      PoliciesPage.policyProblems(member.profile) +
      PoliciesPage.policyForms(kind, member, kind.id + '-', '') +
      '<ul>' + member.rules.map(function (rule) {
        return '<li>' + kit.esc(rule) + '</li>';
      }).join('') + '</ul>' +
      PoliciesPage.policySchemaTables(member.schema);
    return out;
  }

  /**
   * Draws the password policy section of /admin/policies: enforcement, the
   * save and reset forms, the current rules, the doors that enforce it, the
   * history cost, the generator and the schema.
   *
   * @param view - the policies view from adminViews.policiesView()
   * @returns the section as HTML
   */
  static passwordPolicySection(view) {
    const kind = view.kinds.filter(function (k) {
      return k.id === 'password';
    })[0];
    const pw = view.password;
    const profile = pw.profile;
    const out =
      '<h2 id="password">Password policy — the default profile</h2>' +
      kit.note('What a password set in this realm must look like. It is ' +
      'stored as <code>' +
      kit.esc(profile.dn || ('cn=default,ou=passwordPolicies,…')) +
      '</code>, in the shape of draft-behera-ldap-password-policy (the ' +
      'schema OpenLDAP\'s ppolicy overlay reads), so an ' +
      '<code>ldapsearch</code> finds it and an <code>ldapmodify</code> ' +
      'changes it.') +

      (view.enforced
        ? '<div class="ok">' + kit.esc(view.enforcement) + '</div>'
        : kit.warn(kit.esc(view.enforcement) + ' Switch the realm with ' +
          '<code>global.mode</code> on <a ' +
          'href="/admin/config">Configuration</a>.')) +

      PoliciesPage.policyProblems(profile) +

      kit.note(profile.stored
        ? 'This profile is <strong>stored</strong> at <code>' +
          kit.esc(profile.dn) +
          '</code>. Saving replaces it; removing it deletes it, after which ' +
          'the built-in defaults below are in force.'
        : '<strong>Nothing is stored yet, so the built-in defaults are in ' +
          'force.</strong> Saving this form writes <code>cn=default</code> ' +
          'under <code>ou=passwordPolicies</code> in this realm\'s ' +
          'directory. A realm created later starts with the same built-in ' +
          'defaults rather than a copy of this one — the profile is not ' +
          'seeded, so it cannot be missing from a realm nobody seeded.') +

      PoliciesPage.policyForms(kind, pw, 'pp-',
        kit.note('Every field is checked ' +
      'before anything is written, and two rules relate fields to each ' +
      'other: a generated password must be at least the minimum length, and ' +
      'at least twice the symbol count plus two — a generator asked for ' +
      'more symbols than that would be drawing for a very long time. ' +
      '<strong>A change applies to the NEXT password set in this ' +
      'realm</strong>; nothing already stored is re-checked, because a ' +
      'stored password is a hash and there is nothing left to check it ' +
      'against.')) +

      '<h3 id="rules">What a password must be, right now</h3>' +
      kit.note('The rules as the <a href="/portal/password">user ' +
      'portal</a> and the activation page print them to the person ' +
      'choosing a password, so the page they read and the rule this ' +
      'service applies are one sentence.') +
      '<ul>' + pw.rules.map(function (rule) {
        return '<li>' + kit.esc(rule) + '</li>';
      }).join('') + '</ul>' +

      '<h3 id="doors">Where it is enforced</h3>' +
      kit.note('Every door that sets a password ends in one function in ' +
      '<code>common/credentials.ts</code>, which is what makes the list ' +
      'below complete rather than a list somebody remembered. ' +
      kit.esc(pw.notDoors)) +
      '<table><tr><th>Door</th><th>Reaches</th></tr>' +
      pw.doors.map(function (row) {
        return '<tr><td>' + kit.esc(row.door) + '</td><td><code>' +
               kit.esc(row.via) +
          '</code></td></tr>';
      }).join('') + '</table>' +

      '<h3 id="history">The history, and what it costs</h3>' +
      kit.note('<strong>A remembered password is the scrypt hash it was ' +
      'already stored as</strong>, moved into <code>pwdHistory</code> on ' +
      'the person\'s own entry when the next one replaces it — no new hash ' +
      'is made, and the password itself is never kept. Checking a new ' +
      'password costs one scrypt comparison per remembered one, about 70ms ' +
      'each on this thread, so a history of ' + kit.esc(profile.history) +
      ' is up to ' +
      kit.esc((profile.history + 1) * 70) + 'ms at a password change. A ' +
      'generated password skips the comparison, because nothing drawn at ' +
      'random is a previous password. <code>pwdHistory</code> and ' +
      '<code>pwdChangedTime</code> are maintained by this service and an ' +
      'LDAP modify naming either is refused in product mode.') +

      '<h3 id="generator">The generator</h3>' +
      kit.note('<strong>New users created from the console or ' +
      '<code>/admin-api</code> get a generated password by ' +
      'default</strong>, shown or returned ONCE. It is drawn by ' +
      '<code>' + kit.esc(pw.generator.module) + '</code>' +
      (pw.generator.version ? ' ' + kit.esc(pw.generator.version) : '') +
      ' from ' +
      kit.esc(pw.generator.source) + ', using ' +
      kit.esc(pw.generator.pools.join(', ')) +
      ' (leaving out ' + pw.generator.excluded.map(function (one) {
        return '<code>' + kit.esc(one) + '</code>';
      }).join(' and ') + ', which silently end or change a string pasted ' +
      'into a shell or a JSON body), and it draws until ' +
      kit.esc(pw.generator.drawsUntil) +
      '.') +

      '<h3 id="schema">Schema</h3>' +
      kit.note('This directory is schemaless, so a container of entries ' +
      'carrying invented attributes says what they mean here. The ' +
      '<code>pwd*</code> names are draft-behera-ldap-password-policy\'s; ' +
      'the <code>stsPwd*</code> ones are this service\'s own, because the ' +
      'draft delegates composition rules to the server and defines none.') +
      PoliciesPage.policySchemaTables(pw.schema);
    return out;
  }

  // The save form and the reset form every kind has. The reset is its own
  // form, for the reason in the header above.
  static policyForms(kind, member, prefix, intro) {
    const profile = member.profile;
    const saveAction = kind.actions[0];
    const resetAction = kind.actions[1];
    const out = '<form method="post" action="/admin/policies">' +
      '<input type="hidden" name="action" value="' + kit.esc(saveAction) +
      '">' +
      '<input type="hidden" name="profile" value="' + kit.esc(profile.name) +
      '">' +
      kit.wideTable('The default ' + kind.label.toLowerCase() + ' profile',
        '<table><tr><th>Rule</th><th>Value</th><th>Attribute</th>' +
        '<th>Built-in default</th><th>Source</th></tr>' +
        member.fields.map((field) => {
          return PoliciesPage.policyFieldRow(field, prefix);
        }).join('') +
        '<tr><td><label for="' + kit.esc(prefix) + 'description">' +
        'Description</label></td>' +
        '<td colspan="4"><input type="text" id="' + kit.esc(prefix) +
        'description" name="description" size="60" maxlength="1024" ' +
        'value="' + kit.esc(profile.description) + '" placeholder="what ' +
        'this profile is for"></td></tr></table>') +
      '<p><button>Save the profile</button></p>' + (intro || '') +
      '</form>' +
      (profile.stored
        ? '<form method="post" action="/admin/policies" class="inline">' +
          '<input type="hidden" name="action" value="' +
          kit.esc(resetAction) + '"><input type="hidden" ' +
          'name="profile" value="' + kit.esc(profile.name) + '"><button ' +
          'class="secondary">Remove this realm\'s profile</button></form>'
        : '');
    return out;
  }

  static policyProblems(profile) {
    return profile.problems.length
      ? kit.warn('<strong>The stored profile has ' +
                  profile.problems.length +
        ' problem(s), and the built-in default is in force for each ' +
        'field named:</strong> ' +
        profile.problems.map(kit.esc.bind(kit)).join(' '))
      : '';
  }

  static policySchemaTables(schema) {
    const out = '<table><tr><th>Object class</th><th>What it is</th></tr>' +
      schema.objectClasses.map((row) => {
        return '<tr><td><code>' + kit.esc(row.name) + '</code></td><td>' +
          kit.esc(row.what) + '</td></tr>';
      }).join('') + '</table>' +
      '<table><tr><th>Attribute</th><th>On</th><th>What it holds</th></tr>' +
      schema.attributes.map((row) => {
        return '<tr><td><code>' + kit.esc(row.name) +
               '</code></td><td>the profile</td><td>' + kit.esc(row.what) +
               '</td></tr>';
      }).join('') +
      (schema.personAttributes || []).map((row) => {
        return '<tr><td><code>' + kit.esc(row.name) + '</code></td><td>a ' +
          'person</td><td>' + kit.esc(row.what) + '</td></tr>';
      }).join('') + '</table>';
    return out;
  }

  // ---------------------------------------------------------------------------
  // /admin/policies (2026-09-12) — DIRECTORY → POLICIES, and the PASSWORD
  // POLICY is the first kind of policy on it.
  //
  // ONE COMPUTATION, TWO RENDERINGS: `adminViews.policiesView()` is the
  // model, this route draws it, and `GET /admin-api/policies` hands the same
  // model back. The writes are `adminActions.policiesAction()`,
  // which `POST /admin-api/policies/{action}` calls too — rule 7 by
  // construction.
  //
  // **THE FORM CARRIES EVERY FIELD**, because a save replaces the whole
  // profile; the action is told it came from the console so that an unticked
  // checkbox — which posts nothing — reads as "no" here and as a refusal from
  // an API caller that forgot one.
  //
  // **THE RESET IS ITS OWN FORM, NOT A SECOND BUTTON IN THE SAVE FORM**, for
  // `/admin/users/new`'s reason: two submit buttons named `action` make
  // `form.elements.action` a RadioNodeList whose value is empty, and the
  // console suite finds every form it presses by the action it posts.
  // ---------------------------------------------------------------------------
  //
  // **ONE ROW RENDERER FOR EVERY KIND (#64)**, told the id prefix of its form
  // (`pp-` for the password policy, as the console suite finds it). A field
  // the view marks `disabled` — an email mechanism in a realm that cannot send
  // mail — is drawn DISABLED WITH THE REASON BESIDE IT, `configRow()`'s
  // pattern, rather than left out: a control that vanished would read as a
  // mechanism this service does not have.
  /**
   * Draws one field of a policy profile form as a table row: its control,
   * attribute, built-in default and source.
   *
   * A field the view marks disabled is drawn disabled with its reason.
   *
   * @param field - the field from the policies view
   * @param prefix - the id prefix of the form (defaults to "pp-")
   * @returns the table row as HTML
   */
  static policyFieldRow(field, prefix) {
    const id = String(prefix || 'pp-') + field.key;
    const hint = kit.tip(field.what, Infinity);
    const off = field.disabled ? ' disabled' : '';
    let control;
    if (field.type === 'bool') {
      control = '<input type="checkbox" id="' + kit.esc(id) + '" name="' +
        kit.esc(field.key) + '" value="TRUE"' +
        (field.value ? ' checked' : '') + off +
        hint + '>' +
        (field.disabled
          ? ' <span class="off">' + kit.esc(field.disabledWhy) + '</span>'
          : '');
    } else if (field.type === 'enum') {
      control = '<select id="' + kit.esc(id) + '" name="' +
        kit.esc(field.key) + '"' + off + hint + '>' +
        (field.values || []).map((value) => {
          return '<option value="' + kit.esc(value) + '"' +
            (String(field.value) === String(value) ? ' selected' : '') +
            '>' + kit.esc(value) + '</option>';
        }).join('') + '</select>';
    } else if (field.type === 'list') {
      // AN ORDERED LIST (#531): typed, comma-separated, or `none`. A list of
      // checkboxes could not say the order, which is the point of one.
      control = '<input type="text" id="' + kit.esc(id) + '" name="' +
        kit.esc(field.key) + '" value="' + kit.esc(field.value) + '"' + off +
        hint + '> <span class="sub">in order, from ' +
        kit.esc((field.values || []).join(', ')) + ', or none</span>';
    } else {
      control = '<input type="number" id="' + kit.esc(id) + '" name="' +
        kit.esc(field.key) + '" min="' + kit.esc(field.min) + '" max="' +
        kit.esc(field.max) +
        '" step="1" required value="' + kit.esc(field.value) + '"' + off +
        hint + '> <span class="sub">' + kit.esc(field.unit) + '</span>';
    }
    return '<tr><td><label for="' + kit.esc(id) + '"' + hint + '>' +
      kit.esc(field.label) +
      '</label></td><td>' + control + '</td>' +
      '<td><code>' + kit.esc(field.attribute) + '</code></td>' +
      '<td>' + kit.esc(field.type === 'bool' ? (field.default ? 'yes' : 'no')
                                              : String(field.default)) +
                                                '</td>' +
      '<td class="' + (field.source === 'directory' ? '' : 'state-none') +
      '">' +
      kit.esc(field.source === 'directory' ? 'this profile'
        : field.source === 'default realm' ? 'the default realm\'s profile'
          : 'built-in default') +
      '</td></tr>';
  }
}

export = PoliciesPage;
