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
    const t = ctx.t;
    // The view's own paging, which is the same paging this recomputed
    // (#446): the page is drawn from the answer alone.
    const listedNav = kit.pageNavPair('/admin/policies',
                                       kit.pageParamsOf(ctx.query),
                                       view.paging);
    const kindLabel = {};
    view.kinds.forEach(function (kind) {
      kindLabel[kind.id] = kind.label;
    });

    const tiles = '<div class="tiles">' +
        kit.tile(view.kinds.length, t.text('consolePolicies.tile.kinds')) +
        kit.tile(view.paging.total, t.text('consolePolicies.tile.profiles')) +
        kit.tile(view.enforced ? t.text('consolePolicies.yes')
                                : t.text('consolePolicies.no'),
                  t.text('consolePolicies.tile.enforced')) +
      '</div>';

    // ONE TAB PER KIND OF POLICY (#540, rcbj 2026-10-09: "That page is
    // getting long and messy"), `kit.tabbedPanels()` as the application page
    // and Listeners have them, in `policy_kinds.ts`'s order, so a kind added
    // there gets its tab with nothing here. Each kind's `<h2 id>` stays inside
    // its panel: a panel is shown when anything in it is the `:target`, so
    // `/admin/policies#passkey` and every other page's link still land on the
    // right tab, and a Save keeps the address's fragment and comes back to
    // its own. The profile list is reference, so it is the last tab.
    const panels = view.kinds.map(function (kind) {
      let html;
      if (kind.id === 'password') {
        html = PoliciesPage.passwordPolicySection(view, t);
      } else if (kind.id === 'authn') {
        html = PoliciesPage.authnPolicySection(view, t);
      } else if (kind.id === 'attributes') {
        html = PoliciesPage.attributePolicySection(view, t);
      } else {
        html = PoliciesPage.genericPolicySection(view, kind, t, view.state);
      }
      return { id: 'tab-' + kind.id, label: kind.label, html: html };
    });
    panels.push({ id: 'tab-profiles',
      label: t.text('consolePolicies.profiles.tab'),
      html: '<h2 id="profiles">' + t.html('consolePolicies.profiles.heading') +
      '</h2>' +
      kit.note(t.html('consolePolicies.profiles.note')) +
      listedNav.head +
      '<table><tr><th>' + t.html('consolePolicies.profiles.kind') +
      '</th><th>' + t.html('consolePolicies.profiles.profile') + '</th><th>' +
      t.html('consolePolicies.profiles.storedAt') + '</th>' +
      '<th>' + t.html('consolePolicies.profiles.problems') + '</th></tr>' +
      view.profiles.map(function (row) {
        return '<tr><td>' + kit.esc(kindLabel[row.kind] || row.kind) +
          '</td><td><a href="#' + kit.esc(row.kind) + '">' +
          kit.esc(row.name) + '</a></td><td>' +
          (row.stored ? '<code>' + kit.esc(row.dn) + '</code>'
            : row.inherited
              ? t.html('consolePolicies.profiles.inherited', { dn: row.dn })
              : '<span class="state-none">' +
                t.html('consolePolicies.profiles.notStored') + '</span>') +
          '</td><td>' + kit.esc(String(row.problems.length)) + '</td></tr>';
      }).join('') + '</table>' +
      listedNav.foot +

      kit.note(t.html('consolePolicies.profiles.json') +
      view.actions.map(function (action) {
        return '<code>POST /admin-api/policies/' + kit.esc(action) +
               '</code>';
      }).join(', ') + '.') });

    // The links are markup a message cannot carry (#539): the words around
    // them are messages, spaces and punctuation included.
    // METADATA FIRST (2026-10-12): the tiles and the lead are a tab of their
    // own ahead of the kinds, as on every Protocols and Directory page drawn
    // as tabs.
    const metadata = tiles +

      kit.note(t.html('consolePolicies.lead') +
      view.kinds.map(function (kind) {
        return '<a href="#' + kit.esc(kind.id) + '">' +
          kit.esc(kind.label) + '</a> (<code>' +
          kit.esc(kind.container) + '</code>)';
      }).join(', ') + t.html('consolePolicies.notXacml') +
      '<a href="/admin/xacml/policies">' +
      t.html('consolePolicies.notXacmlLink') + '</a>' +
      t.html('consolePolicies.notXacmlEnd'));

    return kit.tabbedPanels('policytabs', [
      { id: 'policies-tab-metadata',
        label: t.text('consoleProtocolSettings.metadataHeading'),
        html: metadata }
    ].concat(panels));
  }

  /**
   * Draws the authentication policy section of /admin/policies: the mail and
   * NIST warnings, where the profile comes from, the forms, and which
   * mechanisms are accepted as a first and a second factor.
   *
   * @param view - the policies view from adminViews.policiesView()
   * @param t - the page's translator (#539)
   * @returns the section as HTML
   */
  static authnPolicySection(view, t) {
    const kind = view.kinds.filter(function (k) {
      return k.id === 'authn';
    })[0];
    const ap = view.authn;
    const profile = ap.profile;
    const yesNo = function (value, active) {
      return value === null ? '<span class="off">—</span>'
        : value ? (active ? t.html('consolePolicies.yes')
          : t.html('consolePolicies.authn.yesInactive'))
          : t.html('consolePolicies.no');
    };
    const out =
      '<h2 id="authn">' + t.html('consolePolicies.authn.heading') + '</h2>' +
      kit.note(t.html('consolePolicies.authn.lead')) +

      (ap.mail.usable ? ''
        : kit.warn(t.html('consolePolicies.authn.noMail') +
          '<a href="/admin/mail">' +
          t.html('consolePolicies.authn.noMailLink') + '</a>.')) +

      kit.warn('<strong>' + t.html('consolePolicies.authn.emailWarning') +
        '</strong> ' + kit.esc(ap.nistWarning));
    // THREE SUB-TABS, AS THE PASSKEY POLICY HAS (rcbj, 2026-10-29): Default
    // (the realm's own policy, its forms and what it accepts now), Named
    // policies (each one an application may name, #1148) and New policy.
    // The schema is reference for all three, so it stays under them.
    const named = PoliciesPage.namedAuthnPoliciesSection(ap, t);
    const byDefault =
      PoliciesPage.policyProblems(profile, t) +

      kit.note(profile.from === 'realm'
        ? t.html('consolePolicies.authn.fromRealm', { dn: profile.dn })
        : profile.from === 'default-realm'
          ? t.html('consolePolicies.authn.fromDefaultRealm',
            { dn: profile.dn })
          : t.html('consolePolicies.authn.builtIn')) +

      PoliciesPage.policyForms(kind, ap, 'ap-',
        kit.note(t.html('consolePolicies.authn.checked')), t) +

      '<h3 id="authn-now">' + t.html('consolePolicies.authn.now') + '</h3>' +
      '<ul>' + ap.rules.map(function (rule) {
        return '<li>' + kit.esc(rule) + '</li>';
      }).join('') + '</ul>' +
      '<table><tr><th>' + t.html('consolePolicies.authn.mechanism') +
      '</th><th>' + t.html('consolePolicies.authn.first') + '</th>' +
      '<th>' + t.html('consolePolicies.authn.second') + '</th></tr>' +
      ap.mechanisms.map(function (m) {
        return '<tr><td>' + kit.esc(m.label) + '</td><td>' +
          yesNo(m.primary, m.active) + '</td><td>' +
          yesNo(m.secondFactor, m.active) + '</td></tr>';
      }).join('') + '</table>' +
      kit.note(t.html('consolePolicies.authn.dash'));
    return out + kit.subTabbedPanels(kind.label, [
      { id: 'authn-sub-default',
        label: t.text('consolePolicies.sub.default'), html: byDefault },
      { id: 'authn-sub-named',
        label: t.text('consolePolicies.sub.named'), html: named.list },
      { id: 'authn-sub-new',
        label: t.text('consolePolicies.sub.new'), html: named.add }
    ]) +
      '<h3 id="authn-schema">' + t.html('consolePolicies.schema') + '</h3>' +
      PoliciesPage.policySchemaTables(ap.schema, t);
  }

  // ---------------------------------------------------------------------------
  // NAMED AUTHENTICATION POLICIES (#1148, rcbj 2026-10-29): the policies an
  // application names in `appAuthnPolicy`, each holding the first-factor
  // mechanisms and the second factors it allows. A row each — its lists, the
  // applications naming it, a Change form under a disclosure and a Delete —
  // and a form for a new one. Each checkbox group posts an EMPTY value first,
  // so a policy saved with nothing ticked is an empty list ("every one"),
  // and the save replaces a policy of the same name.
  // ---------------------------------------------------------------------------
  /**
   * Draws the named authentication policies of the authentication tab: the
   * list for its Named policies sub-tab and the form for its New policy one.
   *
   * @param ap - the authentication policy's member of the policies view
   * @param t - the page's translator (#539)
   * @returns `{ list, add }`, each as HTML
   */
  static namedAuthnPoliciesSection(ap, t) {
    const vocabulary = ap.vocabulary || { mechanisms: [], secondFactors: [] };
    const named = ap.named || [];
    const boxes = function (member, ids, held, prefix) {
      return '<input type="hidden" name="' + member + '" value="">' +
        ids.map(function (id) {
          return '<label class="fg-radio"><input type="checkbox" name="' +
            member + '" value="' + kit.esc(id) + '" id="' +
            kit.esc(prefix + member + '-' + id) + '"' +
            (held.indexOf(id) >= 0 ? ' checked' : '') + '> ' +
            kit.esc(id) + '</label>';
        }).join(' ');
    };
    const form = function (policy) {
      const prefix = 'nap-' + (policy ? policy.name : 'new') + '-';
      return '<form method="post" action="/admin/policies#authn-named">' +
        '<input type="hidden" name="action" ' +
        'value="save-named-authn-policy">' +
        (policy
          ? '<input type="hidden" name="name" value="' +
            kit.esc(policy.name) + '">'
          : '<div class="formrow"><label for="' + prefix + 'name">' +
            t.html('consolePolicies.authnNamed.name') + '</label> ' +
            '<input type="text" id="' + prefix + 'name" name="name" ' +
            'required pattern="[a-z0-9][a-z0-9-]{0,62}" ' +
            'placeholder="passkeys-only"></div>') +
        '<div class="formrow"><label for="' + prefix + 'description">' +
        t.html('consolePolicies.form.description') + '</label> ' +
        '<input type="text" id="' + prefix + 'description" ' +
        'name="description" size="60" maxlength="1024" value="' +
        kit.esc(policy ? policy.description : '') + '"></div>' +
        '<div class="formrow"><span>' +
        t.html('consolePolicies.authnNamed.first') + '</span> ' +
        boxes('mechanisms', vocabulary.mechanisms,
              policy ? policy.mechanisms : [], prefix) + '</div>' +
        '<div class="formrow"><span>' +
        t.html('consolePolicies.authnNamed.second') + '</span> ' +
        boxes('secondFactors', vocabulary.secondFactors,
              policy ? policy.secondFactors : [], prefix) + '</div>' +
        '<div class="formrow"><button>' +
        t.html('consolePolicies.authnNamed.save') + '</button></div></form>';
    };
    const none = '<span class="state-none">' +
      t.html('consolePolicies.authnNamed.every') + '</span>';
    const listCell = function (list) {
      return list.length ? kit.codeList(list) : none;
    };
    const rows = named.map(function (policy) {
      return '<tr><td><code>' + kit.esc(policy.name) + '</code>' +
        (policy.description ? '<br><span class="sub">' +
          kit.esc(policy.description) + '</span>' : '') + '</td><td>' +
        listCell(policy.mechanisms) + '</td><td>' +
        listCell(policy.secondFactors) + '</td><td>' +
        (policy.namedBy.length ? kit.codeList(policy.namedBy)
          : '<span class="state-none">' +
            t.html('consolePolicies.authnNamed.nobody') + '</span>') +
        '</td><td><details><summary>' +
        t.html('consolePolicies.authnNamed.change') + '</summary>' +
        form(policy) + '</details>' +
        '<form method="post" action="/admin/policies#authn-named" ' +
        'class="inline"><input type="hidden" name="action" ' +
        'value="delete-named-authn-policy"><input type="hidden" ' +
        'name="name" value="' + kit.esc(policy.name) + '"><button ' +
        'class="secondary"' + (policy.namedBy.length
          ? ' disabled' + kit.tip(t.text('consolePolicies.authnNamed.inUse'))
          : '') + '>' + t.html('consolePolicies.authnNamed.delete') +
        '</button></form></td></tr>';
    }).join('');
    return {
      list: '<h3 id="authn-named">' +
        t.html('consolePolicies.authnNamed.heading') + '</h3>' +
        kit.note(t.html('consolePolicies.authnNamed.lead')) +
        '<table><tr><th>' + t.html('consolePolicies.authnNamed.name') +
        '</th><th>' + t.html('consolePolicies.authnNamed.first') +
        '</th><th>' + t.html('consolePolicies.authnNamed.second') +
        '</th><th>' + t.html('consolePolicies.authnNamed.namedBy') +
        '</th><th></th></tr>' +
        (rows || '<tr><td colspan="5" class="sub">' +
          t.html('consolePolicies.authnNamed.empty') + '</td></tr>') +
        '</table>',
      add: '<h3 id="authn-new">' +
        t.html('consolePolicies.authnNamed.newHeading') + '</h3>' +
        form(null)
    };
  }

  // ---------------------------------------------------------------------------
  // THE ATTRIBUTE POLICY (#396): rcbj's "a list of all attributes, custom
  // attributes, ability to add a new attribute, and require each individual
  // attribute as needed". Three parts, one tab: every attribute a person here
  // may be given, each with a Required box (the save form); the realm's
  // custom attributes, each with Remove; and a form that defines one.
  //
  // **THE SAVE FORM CARRIES A HIDDEN, EMPTY `requiredAttributes` FIRST**, so
  // a form with every box unticked still sends the member — an empty list,
  // which is a choice — where a form that sent nothing would be refused as a
  // save that forgot the field. A ticked box's value follows it.
  // `uid`, `cn` and `sn` are drawn ticked and disabled: always required.
  // ---------------------------------------------------------------------------
  /**
   * Draws the attribute policy section of /admin/policies: enforcement,
   * where the profile comes from, every attribute with its Required box, the
   * people who lack one, the realm's custom attributes and the form that
   * defines one, and the schema.
   *
   * @param view - the policies view from adminViews.policiesView()
   * @param t - the page's translator (#539)
   * @returns the section as HTML
   */
  static attributePolicySection(view, t) {
    const kind = view.kinds.filter(function (k) {
      return k.id === 'attributes';
    })[0];
    const ap = view.attributes;
    const profile = ap.profile;
    const saveAction = kind.actions[0];
    const resetAction = kind.actions[1];
    const listed = String(profile.requiredAttributes || '').split(',')
      .map(function (one) {
        return one.trim().toLowerCase();
      }).filter(Boolean);
    const rows = ap.catalogue.map(function (row) {
      const id = 'ap-req-' + row.name;
      const ticked = row.locked || listed.indexOf(row.name.toLowerCase()) >= 0;
      return '<tr><td><input type="checkbox" id="' + kit.esc(id) + '" ' +
        'name="requiredAttributes" value="' + kit.esc(row.name) + '"' +
        (ticked ? ' checked' : '') + (row.locked ? ' disabled' : '') +
        '></td><td><label for="' + kit.esc(id) + '"><code>' +
        kit.esc(row.name) + '</code></label></td><td>' + kit.esc(row.label) +
        '</td><td>' + (row.custom
          ? t.html('consolePolicies.attributes.custom')
          : kit.esc(row.schema)) + '</td><td>' + (row.locked
          ? t.html('consolePolicies.attributes.always')
          : row.required ? t.html('consolePolicies.yes')
            : '<span class="state-none">' + t.html('consolePolicies.no') +
              '</span>') + '</td></tr>';
    }).join('');
    const saveForm = '<form method="post" action="/admin/policies">' +
      '<input type="hidden" name="action" value="' + kit.esc(saveAction) +
      '">' +
      '<input type="hidden" name="profile" value="' + kit.esc(profile.name) +
      '">' +
      '<input type="hidden" name="requiredAttributes" value="">' +
      kit.wideTable(t.text('consolePolicies.attributes.tableLabel'),
        '<table><tr><th>' + t.html('consolePolicies.attributes.required') +
        '</th><th>' + t.html('consolePolicies.field.attribute') + '</th><th>' +
        t.html('consolePolicies.attributes.label') + '</th><th>' +
        t.html('consolePolicies.attributes.definedBy') + '</th><th>' +
        t.html('consolePolicies.attributes.inForce') + '</th></tr>' + rows +
        '</table>') +
      '<div class="formrow"><label for="ap-description">' +
      t.html('consolePolicies.form.description') + '</label> ' +
      '<input type="text" id="ap-description" name="description" size="60" ' +
      'maxlength="1024" value="' + kit.esc(profile.description) +
      '" placeholder="' +
      kit.esc(t.text('consolePolicies.form.descriptionPlaceholder')) +
      '"></div>' +
      '<p><button>' + t.html('consolePolicies.saveProfile') +
      '</button></p></form>' +
      (profile.stored
        ? '<form method="post" action="/admin/policies" class="inline">' +
          '<input type="hidden" name="action" value="' +
          kit.esc(resetAction) + '"><input type="hidden" ' +
          'name="profile" value="' + kit.esc(profile.name) + '"><button ' +
          'class="secondary">' + t.html('consolePolicies.form.remove') +
          '</button></form>'
        : '');
    // THE PEOPLE WHO LACK ONE: counted only when asked (a walk of the
    // realm's people), and the filter that finds them always.
    const missing = (ap.missingAsked
      ? (ap.missing === null || ap.missing === undefined
        ? t.html('consolePolicies.attributes.missingNotCounted')
        : t.html('consolePolicies.attributes.missingCount',
                 { n: String(ap.missing) }))
      : '<a href="/admin/policies?missing=count#attributes">' +
        t.html('consolePolicies.attributes.missingAsk') + '</a>') +
      t.html('consolePolicies.attributes.missingFilter') +
      '<code>' + kit.esc(ap.missingFilter) + '</code>.';
    const syntaxOptions = ap.syntaxes.map(function (one) {
      return '<option value="' + kit.esc(one.id) + '" title="' +
        kit.esc(one.what) + '">' + kit.esc(one.id) + '</option>';
    }).join('');
    const custom = ap.custom.length
      ? '<table><tr><th>' + t.html('consolePolicies.field.attribute') +
        '</th><th>' + t.html('consolePolicies.attributes.label') + '</th><th>' +
        t.html('consolePolicies.attributes.syntax') + '</th><th>' +
        t.html('consolePolicies.attributes.values') + '</th><th>' +
        t.html('consolePolicies.attributes.description') + '</th><th>' +
        '</th></tr>' +
        ap.custom.map(function (one) {
          return '<tr><td><code>' + kit.esc(one.name) + '</code></td><td>' +
            kit.esc(one.label) + '</td><td><code>' + kit.esc(one.syntax) +
            '</code></td><td>' + (one.multi
              ? t.html('consolePolicies.attributes.several')
              : t.html('consolePolicies.attributes.one')) + '</td><td>' +
            kit.esc(one.description) + '</td><td>' +
            '<form method="post" action="/admin/policies" class="inline">' +
            '<input type="hidden" name="action" value="' +
            kit.esc(ap.actions.remove) + '"><input type="hidden" ' +
            'name="name" value="' + kit.esc(one.name) + '"><button ' +
            'class="secondary">' +
            t.html('consolePolicies.attributes.removeCustom') +
            '</button></form></td></tr>';
        }).join('') + '</table>'
      : '<p>' + t.html('consolePolicies.attributes.noCustom') + '</p>';
    const defineForm = '<form method="post" action="/admin/policies">' +
      '<input type="hidden" name="action" value="' +
      kit.esc(ap.actions.define) + '">' +
      '<table><tr><td><label for="ap-new-name">' +
      t.html('consolePolicies.field.attribute') + '</label></td><td>' +
      '<input type="text" id="ap-new-name" name="name" required ' +
      'maxlength="64" size="32" ' +
      'placeholder="employeeBadge"></td></tr>' +
      '<tr><td><label for="ap-new-label">' +
      t.html('consolePolicies.attributes.label') + '</label></td><td>' +
      '<input type="text" id="ap-new-label" name="label" required ' +
      'maxlength="128" size="40" placeholder="' +
      kit.esc(t.text('consolePolicies.attributes.labelPlaceholder')) +
      '"></td></tr>' +
      '<tr><td><label for="ap-new-syntax">' +
      t.html('consolePolicies.attributes.syntax') + '</label></td><td>' +
      '<select id="ap-new-syntax" name="syntax">' + syntaxOptions +
      '</select></td></tr>' +
      '<tr><td><label for="ap-new-multi">' +
      t.html('consolePolicies.attributes.values') + '</label></td><td>' +
      '<select id="ap-new-multi" name="multiValued">' +
      '<option value="single">' + t.html('consolePolicies.attributes.one') +
      '</option><option value="multiple">' +
      t.html('consolePolicies.attributes.several') + '</option></select>' +
      '</td></tr>' +
      '<tr><td><label for="ap-new-description">' +
      t.html('consolePolicies.attributes.description') + '</label></td><td>' +
      '<input type="text" id="ap-new-description" name="description" ' +
      'maxlength="1024" size="60"></td></tr></table>' +
      '<p><button>' + t.html('consolePolicies.attributes.define') +
      '</button></p></form>';
    return '<h2 id="attributes">' +
      t.html('consolePolicies.attributes.heading') + '</h2>' +
      kit.note(t.html('consolePolicies.attributes.lead')) +
      (ap.enforced
        ? '<div class="ok">' +
          t.html('consolePolicies.attributes.enforced') + '</div>'
        : kit.warn(t.html('consolePolicies.attributes.notEnforced') +
          '<a href="/admin/config">' +
          t.html('consolePolicies.configuration') + '</a>.')) +
      PoliciesPage.policyProblems(profile, t) +
      kit.note(profile.from === 'realm'
        ? t.html('consolePolicies.attributes.fromRealm', { dn: profile.dn })
        : profile.from === 'default-realm'
          ? t.html('consolePolicies.attributes.fromDefaultRealm',
                   { dn: profile.dn })
          : t.html('consolePolicies.attributes.builtIn')) +
      saveForm +
      '<ul>' + ap.rules.map(function (rule) {
        return '<li>' + kit.esc(rule) + '</li>';
      }).join('') + '</ul>' +
      kit.note(missing) +
      '<h3 id="attributes-custom">' +
      t.html('consolePolicies.attributes.customHeading') + '</h3>' +
      kit.note(t.html('consolePolicies.attributes.customLead',
                      { max: String(ap.maxCustom) })) +
      custom +
      '<h4>' + t.html('consolePolicies.attributes.defineHeading') + '</h4>' +
      defineForm +
      '<h3 id="attributes-schema">' + t.html('consolePolicies.schema') +
      '</h3>' +
      PoliciesPage.policySchemaTables(ap.schema, t);
  }

  // A kind this console has nothing particular to say about: its fields,
  // its rules and its schema, from its module.
  /**
   * Draws the section of /admin/policies for a kind of policy with nothing
   * particular to say: its forms, rules and schema, from its module.
   *
   * @param view - the policies view from adminViews.policiesView()
   * @param kind - the policy kind
   * @param t - the page's translator (#539)
   * @param state - optional; the page's state: a named profile form's
   *   draft and its application search's results (#609)
   * @returns the section as HTML
   */
  static genericPolicySection(view, kind, t, state?) {
    const member = view[kind.id];
    // The kind's label and what it governs are the view's English, drawn
    // as they come; only the words around them are messages (#539).
    const head = '<h2 id="' + kit.esc(kind.id) + '">' +
      kit.esc(kind.label) + t.html('consolePolicies.defaultProfileSuffix') +
      '</h2>' +
      kit.note(t.html('consolePolicies.generic.governs') +
      kit.esc(kind.governs) +
      t.html('consolePolicies.generic.storedUnder',
        { container: kind.container }));
    // THE PASSKEY POLICY IS THREE SUB-TABS (#609, rcbj's decision 5):
    // Default (the `default` profile), Named policies (every named one,
    // each with what it selects) and New policy (the form that adds one),
    // `kit.subTabbedPanels()` as Cert issuance's SPIFFE tab has them. The
    // schema is reference for all three, so it stays under them.
    if (PoliciesPage.isTabbedKind(kind, member)) {
      const named = PoliciesPage.namedProfileParts(kind, member, t,
                                                   state || {});
      return head + kit.subTabbedPanels(kind.label, [
        { id: kind.id + '-sub-default',
          label: t.text('consolePolicies.sub.default'),
          html: PoliciesPage.policyProblems(member.profile, t) +
            PoliciesPage.policyForms(kind, member, kind.id + '-', '', t) +
            '<ul>' + member.rules.map(function (rule) {
              return '<li>' + kit.esc(rule) + '</li>';
            }).join('') + '</ul>' },
        { id: kind.id + '-sub-named',
          label: t.text('consolePolicies.sub.named'),
          html: '<h3 id="' + kit.esc(kind.id) + '-named">' +
            t.html('consolePolicies.named.heading') + '</h3>' + named.list },
        { id: kind.id + '-sub-new',
          label: t.text('consolePolicies.sub.new'),
          html: '<h3>' + t.html('consolePolicies.named.addHeading') +
            '</h3>' + named.add }
      ].concat(member.clients ? [
        // THE LEARNED CLIENTS (#1112), the realm's register, beside the
        // profiles whose `clientRules` row is the configured half.
        { id: kind.id + '-sub-clients',
          label: t.text('consolePolicies.sub.clients'),
          html: PoliciesPage.passkeyClientsSection(member.clients, t) }
      ] : [])) + PoliciesPage.policySchemaTables(member.schema, t);
    }
    const out = head +
      PoliciesPage.policyProblems(member.profile, t) +
      PoliciesPage.policyForms(kind, member, kind.id + '-', '', t) +
      '<ul>' + member.rules.map(function (rule) {
        return '<li>' + kit.esc(rule) + '</li>';
      }).join('') + '</ul>' +
      (Array.isArray(member.named)
        ? PoliciesPage.namedProfilesSection(kind, member, t) : '') +
      PoliciesPage.policySchemaTables(member.schema, t);
    return out;
  }

  /**
   * Draws the passkey policy's learned clients (#1112): the switch and its
   * thresholds, a page of the register — learned first — each with a Clear
   * form, and Clear all. Each form posts the kind's own act, which the
   * runtime sends to `POST /admin-api/policies/{action}`.
   *
   * @param clients - `passkey.clients` of the policies view
   * @param t - the page's translator (#539)
   * @returns the section as HTML
   */
  static passkeyClientsSection(clients, t) {
    const pg = clients.paging || { page: 1, pages: 1, per: 25, total: 0 };
    const firstRow = pg.total ? (pg.page - 1) * pg.per + 1 : 0;
    const nav = kit.pageNavPair('/admin/policies', {}, {
      page: pg.page, pages: pg.pages, param: 'clientsPage',
      noun: t.text('consolePolicies.clients.noun'), total: pg.total,
      firstRow: firstRow,
      lastRow: Math.min(pg.total, firstRow + clients.rows.length - 1) }, t);
    const clearForm = function (action, client, label) {
      return '<form method="post" action="/admin/policies" class="inline">' +
        '<input type="hidden" name="action" value="' + kit.esc(action) +
        '">' + (client === null ? ''
          : '<input type="hidden" name="client" value="' +
            kit.esc(client) + '">') +
        '<button class="secondary">' + label + '</button></form>';
    };
    const out = '<h3 id="passkey-clients">' +
      t.html('consolePolicies.clients.heading') + '</h3>' +
      kit.note(t.html('consolePolicies.clients.note', {
        threshold: String(clients.threshold),
        hours: String(clients.windowHours) })) +
      (clients.learning ? ''
        : kit.warn(t.html('consolePolicies.clients.learningOff'))) +
      (clients.rows.length
        ? nav.head + '<table><tr><th>' +
          t.html('consolePolicies.clients.client') + '</th><th>' +
          t.html('consolePolicies.clients.state') + '</th><th>' +
          t.html('consolePolicies.clients.failures') + '</th><th>' +
          t.html('consolePolicies.clients.last') + '</th><th></th></tr>' +
          clients.rows.map(function (row) {
            return '<tr><td><code>' + kit.esc(row.client) + '</code></td>' +
              '<td>' + (row.learned
                ? t.html('consolePolicies.clients.learned',
                         { at: row.learnedAt })
                : '<span class="state-none">' +
                  t.html('consolePolicies.clients.counting') + '</span>') +
              '</td><td>' + kit.esc(String(row.failures)) + '</td><td>' +
              kit.esc(row.lastAt) + '</td><td>' +
              clearForm(clients.actions.clear, row.client,
                        t.html('consolePolicies.clients.clear')) +
              '</td></tr>';
          }).join('') + '</table>' + nav.foot +
          '<p>' + clearForm(clients.actions.clearAll, null,
                            t.html('consolePolicies.clients.clearAll')) +
          '</p>'
        : '<p class="state-none">' + t.html('consolePolicies.clients.none') +
          '</p>');
    return out;
  }

  // Whether a kind is drawn as sub-tabs (#609): a kind whose registration
  // says `tabbed` (#1235: declared, so a kind adopting named policies says
  // so in its own row rather than here) and that has named profiles — the
  // passkey policy. The locale and post-login policies' named profiles are
  // drawn as they were, under the default profile.
  static isTabbedKind(kind, member) {
    return kind.tabbed === true && Array.isArray(member.named);
  }

  /**
   * Draws a kind's NAMED profiles (#535, the passkey policy): one form per
   * profile with its selectors, and a form to add one. The one that applies
   * to a sign-in is the matching profile with the lowest precedence.
   *
   * @param kind - the policy kind
   * @param member - the kind's member of the policies view
   * @param t - the page's translator (#539)
   * @returns the section as HTML
   */
  static namedProfilesSection(kind, member, t) {
    const parts = PoliciesPage.namedProfileParts(kind, member, t, {});
    return '<h3 id="' + kit.esc(kind.id) + '-named">' +
      t.html('consolePolicies.named.heading') + '</h3>' + parts.list +
      '<h4>' + t.html('consolePolicies.named.addHeading') + '</h4>' +
      parts.add;
  }

  /**
   * The key a New policy form's draft is kept under (#841): the form's, not
   * the typed name's.
   *
   * @param kindId - the policy kind's id
   * @returns the key
   */
  static draftKeyOf(kindId) {
    return String(kindId) + '-new';
  }

  // The New policy form as a REDRAW shows it (#841): the form's own posted
  // fields laid over the blank profile, so a refused save loses nothing the
  // reader typed.
  static withDraft(named, draft) {
    if (!draft) {
      return named;
    }
    const one = function (key) {
      const value = draft[key];
      return Array.isArray(value) ? String(value[0] === undefined ? ''
                                                                  : value[0])
        : value === undefined || value === null ? undefined : String(value);
    };
    const listOf = function (key, held) {
      const text = one(key);
      return text === undefined ? held : text.split(/[,\n]/)
        .map(function (v) { return v.trim(); }).filter(Boolean);
    };
    return Object.assign({}, named, {
      name: one('profile') !== undefined ? one('profile') : named.name,
      selectApplications: listOf('selectApplications',
                                 named.selectApplications),
      selectGroups: listOf('selectGroups', named.selectGroups),
      precedence: one('precedence') !== undefined ? one('precedence')
                                                  : named.precedence,
      fields: (named.fields || []).map(function (field) {
        const posted = one(field.key);
        if (field.type === 'bool') {
          // An unticked box posts nothing, so its absence is "no".
          return Object.assign({}, field, {
            value: /^(true|on|1|yes)$/i.test(String(posted || '')) });
        }
        return posted === undefined ? field
          : Object.assign({}, field, { value: posted });
      })
    });
  }

  /**
   * Draws a kind's named profiles in two parts: the list of profiles, each
   * with what it selects and its form, and the form that adds one.
   *
   * GENERIC OVER WHAT THE KIND DECLARES (#1235, rule 3cx): a box per
   * selector in `member.selectors` (`selectApplications` — the locale
   * policy's, until its applications name it — — the post-login policy's, until its groups name it —
   * `precedence`), and, for a tabbed kind, what names each profile
   * (`named.namedBy`, the applications, groups and people whose reference
   * attributes in `member.references` name it), read-only.
   *
   * @param kind - the policy kind
   * @param member - the kind's member of the policies view
   * @param t - the page's translator (#539)
   * @param state - the page's state: `policyDrafts` and `policySaveErrors`
   *   by draft key (#841)
   * @returns `{ list, add }`, each HTML
   */
  static namedProfileParts(kind, member, t, state) {
    // The selectors this kind carries (#539): the locale policy's
    // applications, the post-login policy's groups, and every ranked kind's
    // precedence. A view from before the member was published names none,
    // and means precedence alone.
    const selectors = Array.isArray(member.selectors) ? member.selectors
      : ['precedence'];
    const has = function (key) {
      return selectors.indexOf(key) >= 0;
    };
    const references = member.references || {};
    const referenced = !!(references.application || references.group ||
                          references.person);
    const tabbed = PoliciesPage.isTabbedKind(kind, member);
    const drafts = (state && state.policyDrafts) || {};
    const saveErrors = (state && state.policySaveErrors) || {};
    const listRow = function (named, prefix, key, label, placeholder) {
      return '<tr><td><label for="' + kit.esc(prefix) + key + '">' +
        t.html(label) + '</label></td><td colspan="4"><input type="text" ' +
        'id="' + kit.esc(prefix) + key + '" name="' +
        (key === 'apps' ? 'selectApplications' : 'selectGroups') +
        '" size="60" value="' +
        kit.esc((named[key === 'apps' ? 'selectApplications'
                                      : 'selectGroups'] || []).join(', ')) +
        '" placeholder="' + kit.esc(t.text(placeholder)) + '"></td></tr>';
    };
    const selectorRows = function (named, prefix) {
      return (!has('selectApplications') ? '' :
        listRow(named, prefix, 'apps', 'consolePolicies.named.applications',
                'consolePolicies.named.applicationsPlaceholder')) +
        (!has('selectGroups') ? '' :
        listRow(named, prefix, 'groups', 'consolePolicies.named.groups',
                'consolePolicies.named.groupsPlaceholder')) +
        (!has('precedence') ? '' :
        '<tr><td><label for="' +
        kit.esc(prefix) + 'precedence">' +
        t.html('consolePolicies.named.precedence') + '</label></td><td ' +
        'colspan="4"><input type="number" id="' + kit.esc(prefix) +
        'precedence" name="precedence" min="1" max="1000" value="' +
        kit.esc(named.precedence || 100) + '"> <span class="sub">' +
        t.html('consolePolicies.named.lowestApplies') + '</span></td></tr>');
    };
    const form = function (stored, prefix, adding) {
      const key = PoliciesPage.draftKeyOf(kind.id);
      const named = tabbed && adding
        ? PoliciesPage.withDraft(stored, drafts[key]) : stored;
      // A refused create (#841) is drawn on this form. The hidden field is
      // what tells a Save apart from a save of a stored profile whose name
      // the reader happened to type.
      const refused = adding ? saveErrors[key] : null;
      const refusal = refused && refused.length
        ? kit.warn(refused.map(function (one) {
          return kit.esc(one);
        }).join(' '), 'That was refused')
        : '';
      return refusal + '<form method="post" action="/admin/policies">' +
        '<input type="hidden" name="action" value="' +
        kit.esc(kind.actions[0]) + '">' +
        (adding && tabbed
          ? '<input type="hidden" name="newProfile" value="1">'
          : '') +
        (adding
          ? '<p><label for="' + kit.esc(prefix) + 'name">' +
            t.html('consolePolicies.named.name') + '</label> ' +
            '<input type="text" id="' + kit.esc(prefix) + 'name" ' +
            'name="profile" pattern="[a-z0-9][a-z0-9-]{0,63}" required ' +
            'value="' + kit.esc(named.name || '') + '" ' +
            'placeholder="administrators"></p>'
          : '<input type="hidden" name="profile" value="' +
            kit.esc(named.name) + '">') +
        PoliciesPage.fieldHeader(t) +
        selectorRows(named, prefix) +
        named.fields.map(function (field) {
          return PoliciesPage.policyFieldRow(field, prefix, t);
        }).join('') + '</table>' +
        '<p><button>' + (adding ? t.html('consolePolicies.named.add')
          : t.html('consolePolicies.saveProfile')) +
        '</button></p></form>' +
        (adding ? ''
          : '<form method="post" action="/admin/policies" class="inline">' +
            '<input type="hidden" name="action" value="' +
            kit.esc(kind.actions[1]) + '"><input type="hidden" ' +
            'name="profile" value="' + kit.esc(named.name) + '"><button ' +
            'class="secondary">' + t.html('consolePolicies.named.remove') +
            '</button></form>');
    };
    // WHAT NAMES A NAMED PROFILE (#609, #1235), said above its form on the
    // Named policies sub-tab, so the list reads without opening a form:
    // read-only, each edited on its own page, the applications, groups and
    // people that name it (and any list the kind still keeps itself).
    const selects = function (named) {
      if (!tabbed) {
        return '';
      }
      const listed = function (values) {
        return values && values.length ? kit.codeList(values)
          : '<span class="state-none">—</span>';
      };
      const by = named.namedBy || {};
      const parts = [];
      if (has('selectApplications')) {
        parts.push(t.html('consolePolicies.named.applications') + ': ' +
                   listed(named.selectApplications));
      }
      if (has('selectGroups')) {
        parts.push(t.html('consolePolicies.named.groups') + ': ' +
                   listed(named.selectGroups));
      }
      if (references.application) {
        parts.push(t.html('consolePolicies.named.namedByApplications',
                          { attribute: references.application }) + ': ' +
                   listed(by.applications));
      }
      if (references.group) {
        parts.push(t.html('consolePolicies.named.namedByGroups',
                          { attribute: references.group }) + ': ' +
                   listed(by.groups));
      }
      if (references.person) {
        parts.push(t.html('consolePolicies.named.namedByPeople',
                          { attribute: references.person }) + ': ' +
                   listed(by.people));
      }
      return '<p class="sub">' + parts.join(' · ') + '</p>';
    };
    const blank = { name: '', selectApplications: [], selectGroups: [],
                    precedence: 100, fields: member.fields.map(function (f) {
                      return Object.assign({}, f, { value: f.default,
                                                    source: 'built-in' });
                    }) };
    const list = kit.note(referenced
        ? t.html('consolePolicies.named.noteReferenced')
        : has('precedence')
          ? t.html('consolePolicies.named.noteRanked')
          : t.html('consolePolicies.named.noteUnranked')) +
      (member.named.length ? member.named.map(function (named) {
        // The heading's id is where an application's Passkey policy card
        // links to (#609): `<kind>-profile-<name>`.
        return '<h4 id="' + kit.esc(kind.id) + '-profile-' +
          kit.esc(named.name) + '">' + kit.esc(named.name) +
          (has('precedence')
          ? t.html('consolePolicies.named.precedenceOf',
            { n: String(named.precedence) }) : '') +
          '</h4>' + selects(named) +
          form(named, kind.id + '-' + named.name + '-', false) +
          '<ul>' + named.rules.map(function (rule) {
            return '<li>' + kit.esc(rule) + '</li>';
          }).join('') + '</ul>';
      }).join('') : '<p>' + t.html('consolePolicies.named.none') + '</p>');
    return { list: list, add: form(blank, kind.id + '-new-', true) };
  }

  /**
   * Draws the password policy section of /admin/policies: enforcement, the
   * save and reset forms, the current rules, the doors that enforce it, the
   * history cost, the generator and the schema.
   *
   * @param view - the policies view from adminViews.policiesView()
   * @param t - the page's translator (#539)
   * @returns the section as HTML
   */
  static passwordPolicySection(view, t) {
    const kind = view.kinds.filter(function (k) {
      return k.id === 'password';
    })[0];
    const pw = view.password;
    const profile = pw.profile;
    const out =
      '<h2 id="password">' + t.html('consolePolicies.password.heading') +
      '</h2>' +
      kit.note(t.html('consolePolicies.password.lead',
        { dn: profile.dn || ('cn=default,ou=passwordPolicies,…') })) +

      (view.enforced
        ? '<div class="ok">' + kit.esc(view.enforcement) + '</div>'
        : kit.warn(kit.esc(view.enforcement) +
          t.html('consolePolicies.password.switch') +
          '<a href="/admin/config">' +
          t.html('consolePolicies.configuration') + '</a>.')) +

      PoliciesPage.policyProblems(profile, t) +

      kit.note(profile.stored
        ? t.html('consolePolicies.password.stored', { dn: profile.dn })
        : t.html('consolePolicies.password.builtIn')) +

      PoliciesPage.policyForms(kind, pw, 'pp-',
        kit.note(t.html('consolePolicies.password.checked')), t) +

      '<h3 id="rules">' + t.html('consolePolicies.password.rulesHeading') +
      '</h3>' +
      kit.note(t.html('consolePolicies.password.rules1') +
      '<a href="/portal/password">' +
      t.html('consolePolicies.password.rulesLink') + '</a>' +
      t.html('consolePolicies.password.rules2')) +
      '<ul>' + pw.rules.map(function (rule) {
        return '<li>' + kit.esc(rule) + '</li>';
      }).join('') + '</ul>' +

      '<h3 id="doors">' + t.html('consolePolicies.password.doorsHeading') +
      '</h3>' +
      kit.note(t.html('consolePolicies.password.doors') +
      kit.esc(pw.notDoors)) +
      '<table><tr><th>' + t.html('consolePolicies.password.door') +
      '</th><th>' + t.html('consolePolicies.password.reaches') +
      '</th></tr>' +
      pw.doors.map(function (row) {
        return '<tr><td>' + kit.esc(row.door) + '</td><td><code>' +
               kit.esc(row.via) +
          '</code></td></tr>';
      }).join('') + '</table>' +

      '<h3 id="history">' + t.html('consolePolicies.password.historyHeading') +
      '</h3>' +
      kit.note(t.html('consolePolicies.password.history',
        { history: String(profile.history),
          ms: String((profile.history + 1) * 70) })) +

      // The generator's module, source, pools and stopping rule are the
      // view's English, drawn as they come between the messages (#539).
      '<h3 id="generator">' +
      t.html('consolePolicies.password.generatorHeading') + '</h3>' +
      kit.note(t.html('consolePolicies.password.generator1') +
      '<code>' + kit.esc(pw.generator.module) + '</code>' +
      (pw.generator.version ? ' ' + kit.esc(pw.generator.version) : '') +
      t.html('consolePolicies.password.generatorFrom') +
      kit.esc(pw.generator.source) +
      t.html('consolePolicies.password.generatorUsing') +
      kit.esc(pw.generator.pools.join(', ')) +
      t.html('consolePolicies.password.generatorLeaving') +
      pw.generator.excluded.map(function (one) {
        return '<code>' + kit.esc(one) + '</code>';
      }).join(t.html('consolePolicies.password.generatorAnd')) +
      t.html('consolePolicies.password.generatorUntil') +
      kit.esc(pw.generator.drawsUntil) +
      '.') +

      '<h3 id="schema">' + t.html('consolePolicies.schema') + '</h3>' +
      kit.note(t.html('consolePolicies.password.schema')) +
      PoliciesPage.policySchemaTables(pw.schema, t);
    return out;
  }

  // The save form and the reset form every kind has. The reset is its own
  // form, for the reason in the header above.
  static policyForms(kind, member, prefix, intro, t) {
    const profile = member.profile;
    const saveAction = kind.actions[0];
    const resetAction = kind.actions[1];
    const out = '<form method="post" action="/admin/policies">' +
      '<input type="hidden" name="action" value="' + kit.esc(saveAction) +
      '">' +
      '<input type="hidden" name="profile" value="' + kit.esc(profile.name) +
      '">' +
      kit.wideTable(t.text('consolePolicies.form.label',
        { kind: kind.label.toLowerCase() }),
        PoliciesPage.fieldHeader(t) +
        member.fields.map((field) => {
          return PoliciesPage.policyFieldRow(field, prefix, t);
        }).join('') +
        '<tr><td><label for="' + kit.esc(prefix) + 'description">' +
        t.html('consolePolicies.form.description') + '</label></td>' +
        '<td colspan="4"><input type="text" id="' + kit.esc(prefix) +
        'description" name="description" size="60" maxlength="1024" ' +
        'value="' + kit.esc(profile.description) + '" placeholder="' +
        kit.esc(t.text('consolePolicies.form.descriptionPlaceholder')) +
        '"></td></tr></table>') +
      '<p><button>' + t.html('consolePolicies.saveProfile') +
      '</button></p>' + (intro || '') +
      '</form>' +
      (profile.stored
        ? '<form method="post" action="/admin/policies" class="inline">' +
          '<input type="hidden" name="action" value="' +
          kit.esc(resetAction) + '"><input type="hidden" ' +
          'name="profile" value="' + kit.esc(profile.name) + '"><button ' +
          'class="secondary">' + t.html('consolePolicies.form.remove') +
          '</button></form>'
        : '');
    return out;
  }

  // The problems themselves are the view's English (errors stay English,
  // #539); only the sentence before them is a message.
  static policyProblems(profile, t) {
    return profile.problems.length
      ? kit.warn('<strong>' + t.html('consolePolicies.problems',
        { n: String(profile.problems.length) }) + '</strong> ' +
        profile.problems.map(kit.esc.bind(kit)).join(' '))
      : '';
  }

  // The header row of a profile's field table, shared by the default
  // profile's form and a named profile's (#539: one set of messages).
  static fieldHeader(t) {
    return '<table><tr><th>' + t.html('consolePolicies.field.rule') +
      '</th><th>' + t.html('consolePolicies.field.value') + '</th><th>' +
      t.html('consolePolicies.field.attribute') + '</th>' +
      '<th>' + t.html('consolePolicies.field.builtInDefault') + '</th><th>' +
      t.html('consolePolicies.field.source') + '</th></tr>';
  }

  static policySchemaTables(schema, t) {
    const out = '<table><tr><th>' +
      t.html('consolePolicies.schemaTable.objectClass') + '</th><th>' +
      t.html('consolePolicies.schemaTable.whatItIs') + '</th></tr>' +
      schema.objectClasses.map((row) => {
        return '<tr><td><code>' + kit.esc(row.name) + '</code></td><td>' +
          kit.esc(row.what) + '</td></tr>';
      }).join('') + '</table>' +
      '<table><tr><th>' + t.html('consolePolicies.field.attribute') +
      '</th><th>' + t.html('consolePolicies.schemaTable.on') + '</th><th>' +
      t.html('consolePolicies.schemaTable.whatItHolds') + '</th></tr>' +
      schema.attributes.map((row) => {
        return '<tr><td><code>' + kit.esc(row.name) +
               '</code></td><td>' +
               t.html('consolePolicies.schemaTable.theProfile') + '</td><td>' +
               kit.esc(row.what) +
               '</td></tr>';
      }).join('') +
      (schema.personAttributes || []).map((row) => {
        return '<tr><td><code>' + kit.esc(row.name) + '</code></td><td>' +
          t.html('consolePolicies.schemaTable.aPerson') + '</td><td>' +
          kit.esc(row.what) + '</td></tr>';
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
   * @param t - the page's translator (#539)
   * @returns the table row as HTML
   */
  static policyFieldRow(field, prefix, t) {
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
    } else if (field.type === 'attributes' || field.type === 'text') {
      // A LIST OF ATTRIBUTES, OR A LABEL (#533), typed.
      control = '<input type="text" id="' + kit.esc(id) + '" name="' +
        kit.esc(field.key) + '" value="' + kit.esc(field.value) + '"' + off +
        // `{provider}` and `{kind}` are literal braces a message cannot hold
        // (#539), so they are drawn here between two messages.
        hint + '> <span class="sub">' + (field.type === 'text'
          ? t.html('consolePolicies.field.textBefore') + '{provider}' +
            t.html('consolePolicies.field.textAnd') + '{kind}' +
            t.html('consolePolicies.field.textAfter')
          : t.html('consolePolicies.field.attributes')) + '</span>';
    } else if (field.type === 'clientRules') {
      // THE CLIENT RULES (#1112), typed: `<browser> on <system>` with `;`
      // between rules. The save says what it could not read.
      control = '<input type="text" id="' + kit.esc(id) + '" name="' +
        kit.esc(field.key) + '" value="' + kit.esc(field.value) + '"' + off +
        ' size="60" maxlength="1200"' + hint + '> <span class="sub">' +
        t.html('consolePolicies.field.clientRules') + '</span>';
    } else if (field.type === 'locale') {
      // A BCP 47 LANGUAGE TAG (#539), typed: any tag is a locale, and the
      // save says whether it is well-formed.
      control = '<input type="text" id="' + kit.esc(id) + '" name="' +
        kit.esc(field.key) + '" value="' + kit.esc(field.value) + '"' + off +
        ' maxlength="64"' + hint + '> <span class="sub">' +
        t.html('consolePolicies.field.locale') + '</span>';
    } else if (field.type === 'attribute') {
      // A DIRECTORY ATTRIBUTE NAME, or empty (#532).
      control = '<input type="text" id="' + kit.esc(id) + '" name="' +
        kit.esc(field.key) + '" value="' + kit.esc(field.value) + '"' + off +
        hint + '> <span class="sub">' +
        t.html('consolePolicies.field.attributeName') + '</span>';
    } else if (field.type === 'list') {
      // AN ORDERED LIST (#531): typed, comma-separated, or `none`. A list of
      // checkboxes could not say the order, which is the point of one. A
      // row whose empty list is the REALM'S (#940, `registrationAlgorithms`)
      // says `realm` instead.
      control = '<input type="text" id="' + kit.esc(id) + '" name="' +
        kit.esc(field.key) + '" value="' + kit.esc(field.value) + '"' + off +
        hint + '> <span class="sub">' +
        t.html('consolePolicies.field.listFrom') +
        kit.esc((field.values || []).join(', ')) +
        t.html(field.empty === 'realm' ? 'consolePolicies.field.listOrRealm'
                                       : 'consolePolicies.field.listOrNone') +
        '</span>';
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
      '<td>' + kit.esc(field.type === 'bool'
        ? (field.default ? t.text('consolePolicies.yes')
                         : t.text('consolePolicies.no'))
        : String(field.default)) +
                                                '</td>' +
      '<td class="' + (field.source === 'directory' ? '' : 'state-none') +
      '">' +
      kit.esc(field.source === 'directory'
        ? t.text('consolePolicies.field.thisProfile')
        : field.source === 'default realm'
          ? t.text('consolePolicies.field.defaultRealmProfile')
          : t.text('consolePolicies.field.builtIn')) +
      '</td></tr>';
  }
}

export = PoliciesPage;
