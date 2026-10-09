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
//
// THE WORDS ARE THE `consoleFederation` CATALOG'S (#539 phases 5 and 6).
// Every word this file writes is a message in
// `common/locales/consoleFederation/`, and the English messages are the text
// this file drew before, to the byte. What the VIEW says — a role's or a
// protocol's description, a setting's `what`, a refusal — is drawn as it
// comes, in English, and so is every refusal. A sentence holding a link is
// split around it: a message carries no attribute, so the `<a href>` stays
// here and the words either side of it are messages. A value a person could
// have typed with an apostrophe in it (a username, a relationship's name) is
// kept OUT of a message, because a message's parameter is escaped as `&#39;`
// where `kit.esc()` writes `&apos;`, and the English must not change.
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
    const t = ctx.t;
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
        (!row.peer && !row.application
          ? '<span class="sub">' +
            t.html('consoleFederation.nothingNamedYet') + '</span>'
          : '') +
        '</td>' +
        FederationPage.federationStateCell(row, t) +
        '<td class="num">' + row.authentications + '</td>' +
        '<td class="num">' + row.users + '</td>' +
        '<td>' + (row.lastError
          ? '<span class="bad">' + kit.shortened(row.lastError, 60) + '</span>'
          : '<span class="sub">' +
            t.html('consoleFederation.noneRecorded') + '</span>') +
        '</td></tr>';
    }).join('');

    const roleOptions = ['<option value="">' +
      t.html('consoleFederation.anyRole') + '</option>'].concat(
      json.roles.map(function (one) {
        const n = json.roleCounts[one.role] || 0;
        return '<option value="' + kit.esc(one.role) + '"' +
          (one.role === wantedRole ? ' selected' : '') + '>' +
          kit.esc(one.short) +
          ' (' + n + ')</option>';
      })).join('');

    const inner = '<div class="tiles">' +
      kit.tile(json.relationshipCount,
               t.text('consoleFederation.tileRelationships')) +
      kit.tile(json.ready, t.text('consoleFederation.tileReady')) +
      kit.tile(json.enabledNotConfigured,
               t.text('consoleFederation.tileEnabledNotConfigured')) +
      kit.tile(json.authentications,
               t.text('consoleFederation.tileFederatedSignIns')) +
      '</div>' +
      FederationPage.federationCaveat(t) +
      // THE PICTURE, pointed at from the page it drills down from. This table
      // has one row per relationship and no row can say anything about another,
      // so three questions an operator arrives with have no cell here: how many
      // applications are behind a partner, how many people have come through it
      // FOR EACH of them, and what an arriving foreign service provider
      // actually meets. All three are facts about two registers at once.
      kit.note('<a href="/admin/federation/map">' +
      t.html('consoleFederation.pictureLink') + '</a>' +
      t.html('consoleFederation.pictureNote')) +
      '<form method="get" action="/admin/federation"><div class="formrow">' +
      '<label for="q">' + t.html('consoleFederation.labelRelationship') +
      '</label>' +
      '<input type="text" id="q" name="q" value="' +
      kit.esc(String(ctx.query.q || '')) +
      '" size="24" placeholder="' +
      kit.esc(t.text('consoleFederation.filterPlaceholder')) + '">' +
      '<label for="role">' + t.html('consoleFederation.labelRole') +
      '</label><select id="role" name="role">' +
      roleOptions + '</select><label for="per">' +
      t.html('consoleFederation.labelShow') +
      '</label><select id="per" ' +
      'name="per">' + kit.perPageOptions(paging.perPage) +
      '</select><button ' +
      'type="submit">' + t.html('consoleFederation.buttonFilter') +
      '</button>' +
      ((wantedText || wantedRole) ? ' <a href="/admin/federation">' +
        t.html('consoleFederation.clear') + '</a>' :
        '') +
      '</div></form>' + nav.head +
      '<table><tr><th>' + t.html('consoleFederation.thRelationship') +
      '</th><th>' + t.html('consoleFederation.thThisServiceIs') +
      '</th><th>' + t.html('consoleFederation.thProtocol') + '</th><th>' +
      t.html('consoleFederation.thPartner') + '</th><th>' +
      t.html('consoleFederation.thState') + '</th><th ' +
      'class="num">' + t.html('consoleFederation.thSignIns') +
      '</th><th class="num">' + t.html('consoleFederation.thPeople') +
      '</th><th>' + t.html('consoleFederation.thLastRefusal') +
      '</th></tr>' +
      (rows || '<tr><td colspan="8">' +
        ((wantedText || wantedRole)
          ? t.html('consoleFederation.noneMatches')
          : t.html('consoleFederation.noneConfigured')) + '</td></tr>') +
      '</table>' + nav.foot +
      FederationPage.federationCreateForm(json.roles, json.protocols, t) +
      '<h2>' + t.html('consoleFederation.headingTwoDirections') + '</h2>' +
      '<table><tr><th>' + t.html('consoleFederation.thThisServiceIs') +
      '</th><th>' + t.html('consoleFederation.thWhatItMeans') +
      '</th></tr>' +
      json.roles.map(function (one) {
        return '<tr><td>' + kit.esc(one.short) + '</td><td>' +
               kit.esc(one.what) +
               '</td></tr>';
      }).join('') + '</table>' +
      kit.note(t.html('consoleFederation.oneDirection')) +
      '<h2>' + t.html('consoleFederation.headingFiveProtocols') +
      '</h2><table><tr><th>' + t.html('consoleFederation.thProtocol') +
      '</th><th>' + t.html('consoleFederation.thWhatHappens') +
      '</th><th>' + t.html('consoleFederation.thSpecification') +
      '</th></tr>' +
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
      FederationPage.federationLinks(json.paths.base, t);

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
   * @param t - the page's translator
   * @returns the cell as HTML
   */
  static federationStateCell(row, t) {
    if (row.usable) {
      return '<td class="ok">' + t.html('consoleFederation.stateReady') +
        '</td>';
    }
    if (!row.enabled) {
      return '<td class="off">' + t.html('consoleFederation.stateDisabled') +
        (row.ready ? '' : ' <span class="sub">' +
         t.html('consoleFederation.andNotConfigured') + '</span>') +
             '</td>';
    }
    // The missing fields are attribute names, so they go in as a parameter.
    return '<td class="bad">' +
      t.html('consoleFederation.stateEnabledNotConfigured') +
      '<span class="sub">' +
      t.html('consoleFederation.stillToSetRefuses',
             { missing: row.missing.join(', ') }) + '</span></td>';
  }

  /**
   * Draws the form that adds a federation relationship.
   *
   * @param roles - the two roles, from the view
   * @param protocols - the five protocols, from the view
   * @param t - the page's translator
   * @returns the form as HTML
   */
  static federationCreateForm(roles, protocols, t) {
    return '<h2>' + t.html('consoleFederation.headingAdd') + '</h2>' +
      kit.note(t.html('consoleFederation.createdDisabled')) +
      '<form method="post" action="/admin/federation"><div ' +
      'class="formrow"><input type="hidden" name="action" ' +
      'value="create"><label for="fedid">' +
      t.html('consoleFederation.labelId') + '</label><input type="text" ' +
      'id="fedid" name="id" size="16" required ' +
      'placeholder="partner-a"><label for="fedrole">' +
      t.html('consoleFederation.thThisServiceIs') +
      '</label><select id="fedrole" name="role">' +
      roles.map(function (one) {
        return '<option value="' + kit.esc(one.role) + '">' +
               kit.esc(one.short) +
               '</option>';
      }).join('') + '</select>' +
      '<label for="fedprotocol">' + t.html('consoleFederation.thProtocol') +
      '</label>' +
      '<select id="fedprotocol" name="protocol">' +
      protocols.map(function (one) {
        return '<option value="' + kit.esc(one.protocol) + '">' +
               kit.esc(one.label) +
               '</option>';
      }).join('') + '</select><label for="fedname">' +
      t.html('consoleFederation.labelName') + '</label><input ' +
      'type="text" id="fedname" name="name" size="16" ' +
      'placeholder="' + kit.esc(t.text('consoleFederation.optional')) +
      '"><label for="fedpeer">' + t.html('consoleFederation.thPartner') +
      '</label><input ' +
      'type="text" id="fedpeer" name="peer" size="26" placeholder="' +
      kit.esc(t.text('consoleFederation.peerPlaceholder')) + '"><button ' +
      'type="submit">' + t.html('consoleFederation.buttonAdd') +
      '</button></div></form>' +
      kit.note(t.html('consoleFederation.idRules'));
  }

  /**
   * Draws the caveat both federation pages carry.
   *
   * @param t - the page's translator
   * @returns the caveat as HTML
   */
  static federationCaveat(t) {
    return (
      kit.note(t.html('consoleFederation.caveatRefusal')) +
      kit.note(t.html('consoleFederation.caveatSigner')));
  }

  /**
   * Draws the links at the foot of the federation pages.
   *
   * @param base - the federation index's path (`federation.PATHS.base`)
   * @param t - optional; the page's translator. `admin-ui/admin.ts` still
   *   calls this without one, and gets the default (English in node).
   * @returns the links as HTML
   */
  static federationLinks(base, t?) {
    t = t || kit.context().t;
    return (
      '<p class="sub"><a href="/admin/federation/map">' +
      t.html('consoleFederation.linkPicture') + '</a> ' +
        '&middot; ' +
      '<a href="' + base + '">' + t.html('consoleFederation.linkIndex') +
      '</a> &middot; ' +
      '<a href="/admin/applications">' +
      t.html('consoleFederation.linkApplications') + '</a> &middot; ' +
        '<a ' +
      'href="/admin/users">' + t.html('consoleFederation.linkWhoSignedIn') +
      '</a> &middot; <a ' +
      'href="/admin/ldap/federations">' +
      t.html('consoleFederation.linkDirectoryView') + '</a></p>');
  }

  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static detail(ctx, json) {
    const t = ctx.t;
    const record = json.found ? json.fields : null;
    const carryBack = '<input type="hidden" name="back" value="' +
      kit.esc(kit.queryWith(kit.listViewOf('/admin/federation', ctx.query),
        {})) +
      '">';
    let inner;
    if (!record) {
      // The id came from the address bar, so it stays out of the message.
      inner = '<p class="warn">' + t.html('consoleFederation.notFoundA') +
        '<code>' + kit.esc(json.id) + '</code>' +
        t.html('consoleFederation.notFoundB') +
        '</p>' + FederationPage.federationLinks(json.paths.base, t);
    } else {
      const row = json;
      const acs = json.endpoints.assertionConsumerService;
      const login = json.loginHref;
      const metadata = json.metadataUrl;
      const setFields = json.setFields;
      const multiFields = json.multiFields;
      const fieldRows = setFields.map(function (field) {
        const value = record[field.name] || '';
        return '<tr><td><code>' + kit.esc(field.name) + '</code></td>' +
          '<td><form method="post" action="/admin/federation"><div ' +
          'class="formrow">' + carryBack +
          '<input type="hidden" name="action" value="set">' +
          '<input type="hidden" name="id" value="' + kit.esc(row.id) + '">' +
          '<input type="hidden" name="field" value="' + kit.esc(field.name) +
          '">' +
          // A FIELD WITH A FIXED SET OF VALUES GETS A SELECT, and the list
          // comes
          // off the schema row rather than being typed here — the same reason
          // the
          // form itself is built from fieldsForRole(): a page offering a value
          // the action refuses is a page that cannot be trusted about the ones
          // it
          // accepts. It matters most on fedAuthnMechanism, where a typo does
          // not
          // fail loudly: the relationship simply says nothing this service
          // recognises and the sign-in falls through to a password box, which
          // is
          // indistinguishable from the feature not being configured at all.
          //
          // The blank option is FIRST and is not a value — it clears the
          // attribute, which for this field is meaningfully different from
          // `password`: empty means "this relationship says nothing" and falls
          // through to the application entry.
          (Array.isArray(field.enum) && field.enum.length
            ? '<select name="value"' + kit.tip(field.what) + '>' +
              '<option value=""' + (value ? '' : ' selected') + '>' +
              (field.name === 'fedSubjectPolicy'
                ? t.html('consoleFederation.notSetDefault',
                         { policy: json.defaultSubjectPolicy })
                : t.html('consoleFederation.notSetNothing')) + '</option>' +
              field.enum.map(function (one) {
                const label = json.enumLabels[one];
                return '<option value="' + kit.esc(one) + '"' +
                  (String(value) === one ? ' selected' : '') + '>' +
                  kit.esc(one) +
                  (label ? ' — ' + kit.esc(label) : '') + '</option>';
              }).join('') + '</select>'
            : '<input type="text" name="value" size="42"' +
              kit.tip(field.what) +
              ' value="' + kit.esc(field.sensitive && value ? '' : value) +
                '"' +
              (field.sensitive ? ' placeholder="' +
               kit.esc(t.text('consoleFederation.setNotShown')) + '"' : '') +
              '>') +
          '<button type="submit">' + t.html('consoleFederation.buttonSet') +
          '</button></div></form></td>' +
          '<td class="sub">' + kit.note(kit.esc(field.what) +
            (field.sensitive
              ? ' ' + t.html('consoleFederation.neverPrinted')
              : '')) + '</td></tr>';
      }).join('');

      // WHO THIS PARTNER'S SUBJECTS ARE LINKED TO (#109), paged, each name a
      // link to the person's page — which is where a link is added or removed.
      const linkNav = kit.pageNavPair('/admin/federation',
                                       kit.pageParamsOf(ctx.query),
                                       json.linksPaging);
      const linkedSection = row.role !== 'service-provider' ? ''
        : '<h2 id="linked-people">' +
          t.html('consoleFederation.headingLinkedPeople') + '</h2>' +
          (row.signsIn
            ? kit.note(t.html('consoleFederation.linkedSignsIn',
                              { policy: json.subjectPolicy }))
            : kit.note(t.html('consoleFederation.linkedSignalsOnly'))) +
          linkNav.head +
          (json.links.length
            ? '<table><tr><th>' + t.html('consoleFederation.thPerson') +
              '</th><th>' + t.html('consoleFederation.thIssuer') +
              '</th><th>' + t.html('consoleFederation.thSubject') +
              '</th></tr>' +
              json.links.map(function (one) {
                return '<tr><td><a href="' + kit.esc('/admin/users' +
                  kit.queryWith({}, { user: one.username })) +
                    '#federation-links">' +
                  kit.esc(one.username) + '</a></td><td><code>' +
                  kit.esc(one.issuer) + '</code></td><td><code>' +
                  kit.esc(one.subject) + '</code></td></tr>';
              }).join('') + '</table>'
            : kit.note(t.html('consoleFederation.nobodyLinked'))) +
          linkNav.foot;

      // An `ssf` relationship (#374) has no sign-in to switch; its two
      // signals switches are in its Shared Signals section.
      const switches = ['fedEnabled'].concat(
        row.role === 'service-provider' && row.signsIn
          ? ['fedAutocreateUsers', 'fedUpdateUserAttributes',
             'fedMayAssertAdministrators', 'fedAllowUnsolicited',
             'fedSignRequest', 'fedAcceptSignout', 'fedRequireSignedLogout']
              .concat(json.encrypts ? ['fedAllowUnencrypted'] : [])
          : []).map(function (name) {
        const field = json.schema.filter(
            function (f) { return f.name === name; })[0];
        if (!field) return '';
        // The two provisioning switches and the two sign-out switches (#167)
        // default ON; the rest default off.
        const dflt = name === 'fedAutocreateUsers' ||
                     name === 'fedUpdateUserAttributes' ||
                     name === 'fedAcceptSignout' ||
                     name === 'fedRequireSignedLogout';
        const on = FederationPage.boolOf(record[name], dflt);
        // TRUE and FALSE are the attribute's own values, not words.
        return '<tr><td><code>' + kit.esc(name) + '</code></td>' +
          '<td class="' + (on ? 'ok' : 'off') + '">' + (on ? 'TRUE' : 'FALSE') +
          '</td><td><form ' +
          'method="post" action="/admin/federation"><div ' +
          'class="formrow">' + carryBack +
          '<input type="hidden" name="action" value="set">' +
          '<input type="hidden" name="id" value="' + kit.esc(row.id) + '">' +
          '<input type="hidden" name="field" value="' + kit.esc(name) + '">' +
          '<input type="hidden" name="value" value="' +
            (on ? 'FALSE' : 'TRUE') +
          '"><button ' +
          'type="submit"' + (name === 'fedEnabled' && !on && !row.ready ? ' ' +
              'class="danger"' : '') +
          '>' + (on ? t.html('consoleFederation.turnOff')
                    : t.html('consoleFederation.turnOn')) +
          '</button></div></form></td>' +
          '<td class="sub">' + kit.esc(field.what) + '</td></tr>';
      }).join('');

      const multiSections = multiFields.map(function (field) {
        const values = record[field.name] || [];
        return '<h3><code>' + kit.esc(field.name) + '</code></h3>' +
          kit.note(kit.esc(field.what)) +
          (values.length
            ? '<table><tr><th>' + t.html('consoleFederation.thValue') +
              '</th><th></th></tr>' +
              values.map(function (value) {
                return '<tr><td class="who"><code>' + kit.esc(value) +
                  '</code></td><td><form ' +
                  'method="post" action="/admin/federation"><div ' +
                  'class="formrow">' +
                  carryBack +
                  '<input type="hidden" name="action" value="remove-value">' +
                  '<input type="hidden" name="id" value="' + kit.esc(row.id) +
                  '"><input type="hidden" name="field" value="' + kit.esc(
                      field.name) + '"><input ' +
                  'type="hidden" name="value" value="' + kit.esc(value) + '">' +
                  '<button ' +
                    'type="submit">' +
                  t.html('consoleFederation.buttonRemove') +
                  '</button></div></form></td></tr>';
              }).join('') + '</table>'
            : '<p class="sub">' +
              // The English of the release list's message ends in two full
              // stops, as the page always drew it; the translations do not.
              (field.name === 'fedRelease'
                ? t.html('consoleFederation.noneRelease')
                : t.html('consoleFederation.noneDot')) + '</p>') +
          '<form method="post" action="/admin/federation"><div ' +
            'class="formrow">' +
          carryBack +
          '<input type="hidden" name="action" value="add-value">' +
          '<input type="hidden" name="id" value="' + kit.esc(row.id) + '">' +
          '<input type="hidden" name="field" value="' + kit.esc(field.name) +
          '"><input type="text" name="value" size="40" placeholder="' +
          kit.esc(field.name === 'fedAttributeMap'
            ? t.text('consoleFederation.mapPlaceholder')
            : (field.name === 'fedRelease'
               ? t.text('consoleFederation.releasePlaceholder') :
               t.text('consoleFederation.valuePlaceholder'))) + '"><button ' +
          'type="submit">' + t.html('consoleFederation.buttonAdd') +
          '</button></div></form>' +
          (field.name === 'fedAttributeMap'
            ? FederationPage.federationUnmappedSection(row,
              json.unmappedAttributes || [],
                                             carryBack, t)
            : '');
      }).join('');

      inner = '<div class="tiles">' +
        kit.tile(row.authentications,
                 t.text('consoleFederation.tileFederatedSignIns')) +
        kit.tile(row.users, t.text('consoleFederation.tileDistinctPeople')) +
        kit.tile(row.usable ? t.text('consoleFederation.stateReady')
                            : (row.enabled
                                ? t.text('consoleFederation.stateNotReady')
                                : t.text('consoleFederation.stateDisabled')),
                 t.text('consoleFederation.thState')) +
        '</div>' +
        // A REFUSAL STAYS ENGLISH (#539): this banner is the last refusal
        // the view recorded, framed, and is drawn as it always was.
        (row.lastError
          ? '<p class="warn"><strong>The last attempt was refused.</strong> ' +
            kit.esc(row.lastError) +
            (row.lastErrorAt ?
             ' <span class="sub">at ' + kit.esc(row.lastErrorAt) +
             '</span>' : '') +
            ' A success clears this, so it standing here means nothing has ' +
            'worked since.</p>'
          : '') +
        (row.enabled && !row.ready
          ? '<p class="warn">' +
            t.html('consoleFederation.enabledNotConfiguredWarn',
                   { missing: row.missing.join(', ') }) + '</p>'
          : '') +
        '<table><tr><th>' + t.html('consoleFederation.thWhat') +
        '</th><th>' + t.html('consoleFederation.thValue') + '</th></tr>' +
        '<tr><td>' + t.html('consoleFederation.thThisServiceIs') +
        '</td><td>' + kit.esc(row.roleLabel) +
        '</td></tr>' +
        '<tr><td>' + t.html('consoleFederation.thProtocol') + '</td><td>' +
        kit.esc(row.protocolLabel) +
          '</td></tr>' +
        '<tr><td>' + t.html('consoleFederation.thPartner') +
        '</td><td class="who"><code>' +
        kit.esc(row.peer || t.text('consoleFederation.noneNamed')) +
          '</code></td></tr>' +
        (row.role === 'identity-provider'
          ? '<tr><td>' + t.html('consoleFederation.thApplication') +
            '</td><td class="who">' +
            (row.application
              ? '<a href="/admin/applications?application=' +
                encodeURIComponent(row.application) +
                '"><code>' + kit.esc(row.application) + '</code></a>'
              : '<span class="sub">' +
                t.html('consoleFederation.noApplicationNamed') + '</span>') +
            '</td></tr>'
          : '') +
        '<tr><td>' + t.html('consoleFederation.lastUsed') + '</td><td>' +
        kit.esc(row.lastSeen || t.text('consoleFederation.never')) +
          // The username is kept out of the message (see the header).
          (row.lastUser ? ' <span class="sub">' +
           t.html('consoleFederation.by') + ' ' + kit.esc(row.lastUser) +
           '</span>' :
           '') +
          '</td></tr>' +
        '<tr><td>' + t.html('consoleFederation.directoryEntry') +
        '</td><td class="who"><code>' + kit.esc(row.dn) +
        '</code></td></tr></table>' +
        (row.role === 'service-provider' && !row.signsIn
          ? FederationPage.federationSignalsSection(row, record, json,
            carryBack, t)
          : row.role === 'service-provider'
          ? '<h2>' + t.html('consoleFederation.headingConfigureAtPartner') +
            '</h2>' +
            kit.note(t.html('consoleFederation.configureAtPartnerNote')) +
            '<table><tr><th>' + t.html('consoleFederation.thWhatTheyNeed') +
            '</th><th>' + t.html('consoleFederation.thValue') + '</th></tr>' +
            '<tr><td>' + t.html('consoleFederation.acsRow') +
              '</td><td class="who"><code>' +
              kit.esc(acs) +
              '</code></td></tr>' +
            '<tr><td>' + t.html('consoleFederation.entityIdRow') + '</td><td ' +
            'class="who"><code>' + kit.esc(acs) +
              '</code><span class="sub">' +
              t.html('consoleFederation.entityIdSameString') +
              '</span></td></tr>' +
            ((row.protocol === 'saml2' || row.protocol === 'saml11' ||
              row.protocol === 'wsfed')
              ? '<tr><td>' + t.html('consoleFederation.ourMetadata',
                  { protocol: row.protocol === 'wsfed' ? 'WS-Federation'
                                                       : 'SAML' }) +
                '</td><td class="who"><a href="' +
                kit.esc(json.paths.metadata + '/' +
                         encodeURIComponent(row.id)) +
                '"><code>' +
                kit.esc(metadata) + '</code></a><span class="sub">' +
                t.html('consoleFederation.metadataUnsigned') +
                '</span></td></tr>'
              : '') +
            // A PARTNER'S SIGN-OUT (#167): what the partner registers so it can
            // tell this service a session ended, and — below the table — what
            // this service tells it.
            Object.keys(json.signOut || {}).map(function (name) {
              const words = {
                singleLogout: t.html('consoleFederation.signOutSingleLogout'),
                signOutCleanup: t.html('consoleFederation.signOutCleanup'),
                backchannelLogout:
                  t.html('consoleFederation.signOutBackchannel'),
                frontchannelLogout:
                  t.html('consoleFederation.signOutFrontchannel'),
                postLogoutRedirect:
                  t.html('consoleFederation.signOutPostLogout')
              };
              return '<tr><td>' + (words[name] || kit.esc(name)) + '</td><td ' +
                'class="who"><code>' + kit.esc(json.signOut[name]) +
                '</code></td></tr>';
            }).join('') +
            ((row.protocol === 'saml11' || row.protocol === 'oauth2')
              ? '<tr><td>' + t.html('consoleFederation.signOut') +
                '</td><td><span class="sub">' +
                t.html('consoleFederation.noSignOut',
                       { protocol: row.protocol === 'saml11' ? 'SAML 1.1'
                                                             : 'OAuth 2.0' }) +
                '</span></td></tr>'
              : '') +
            // THE KEY THE PARTNER ENCRYPTS TO (#168): the certificate, or
            // for OpenID Connect the JWKS and the two registration members.
            (json.encryption
              ? '<tr><td>' + t.html('consoleFederation.encryptionCertificate',
                  { keyType: json.encryption.policy.keyType }) + '</td>' +
                '<td class="who">' + (json.encryption.certificatePem
                  ? '<pre>' + kit.esc(json.encryption.certificatePem) +
                    '</pre>'
                  : '<span class="warn">' +
                    t.html('consoleFederation.noCertificate') + '</span>') +
                '</td></tr>' +
                (json.endpoints.jwks
                  ? '<tr><td>' + t.html('consoleFederation.jwksRow') +
                    '</td><td class="who"><code>' +
                    kit.esc(json.endpoints.jwks) + '</code></td></tr>' +
                    '<tr><td><code>id_token_encrypted_response_alg</code> / ' +
                    '<code>_enc</code></td><td><code>' +
                    kit.esc(json.encryption.policy.management) +
                    '</code> / <code>' +
                    kit.esc(json.encryption.policy.content) + '</code></td>' +
                    '</tr>'
                  : '<tr><td>' +
                    t.html('consoleFederation.encryptionAlgorithms') +
                    '</td><td>' +
                    t.html('consoleFederation.algorithmsUnder',
                      { content: json.encryption.policy.content,
                        management: json.encryption.policy.management }) +
                    '</td></tr>')
              : '') +
            '</table>' +
            (json.encryption ? FederationPage.federationEncryptionSection(row,
                                 json.encryption, carryBack, t) : '') +
            kit.note('<a class="btn" href="' + kit.esc(login) +
                      '">' + t.html('consoleFederation.startSignIn') +
            '</a> ' + (row.usable ? '' : '<span class="sub">' +
            t.html('consoleFederation.willRefuse') + '</span>')) +
            // THE SAME PARTNER AS A TRANSMITTER (#373).
            FederationPage.federationSignalsSection(row, record, json,
              carryBack, t)
          : '<h2>' + t.html('consoleFederation.headingWhatItDoes') + '</h2>' +
            kit.note(t.html('consoleFederation.whatItDoesNote')) +
            // The sentence is split at its two links, which sit inside the
            // bold opening.
            kit.note('<strong>' + t.html('consoleFederation.releaseOnlyA') +
            '<a href="/admin/claims">' +
            t.html('consoleFederation.customClaims') + '</a>, <a ' +
            'href="/admin/saml-attributes">' +
            t.html('consoleFederation.customSamlAttributes') + '</a>' +
            t.html('consoleFederation.releaseOnlyB') + '</strong>' +
            t.html('consoleFederation.releaseOnlyC')) +
            // WHAT THIS SERVICE TELLS THE PARTNER (#373).
            FederationPage.federationOutboundSection(json.outboundSignals,
                                                     t)) +
        '<h2>' + t.html('consoleFederation.headingSettings') + '</h2>' +
        '<table><tr><th>' + t.html('consoleFederation.thField') +
        '</th><th>' + t.html('consoleFederation.thValue') + '</th><th>' +
        t.html('consoleFederation.thWhatItIs') + '</th></tr>' +
        fieldRows +
        '</table><h2>' + t.html('consoleFederation.headingSwitches') +
        '</h2><table><tr><th>' + t.html('consoleFederation.thField') +
        '</th><th>' + t.html('consoleFederation.thNow') + '</th><th>' +
        '</th>' +
        '<th>' + t.html('consoleFederation.thWhatItIs') + '</th></tr>' +
        switches +
        '</table>' +
        '<h2>' + t.html('consoleFederation.headingLists') + '</h2>' +
        multiSections +
        linkedSection +
        '<h2>' + t.html('consoleFederation.headingDelete') + '</h2>' +
        '<form method="post" action="/admin/federation"><div class="formrow">' +
        carryBack +
        '<input type="hidden" name="action" value="delete">' +
        '<input type="hidden" name="id" value="' + kit.esc(row.id) + '">' +
        '<button type="submit" class="danger">' +
        t.html('consoleFederation.buttonDelete') + '</button>' +
        '<span class="sub">' +
        t.html('consoleFederation.deleteNote',
               { count: String(row.authentications) }) +
        '</span></div></form>' +
        kit.note(t.html('consoleFederation.oneEntryNote', { dn: row.dn })) +
        FederationPage.federationCaveat(t) +
        '<p class="sub"><a href="' +
        kit.esc('/admin/federation' +
                 kit.queryWith(kit.listViewOf('/admin/federation', ctx.query),
                   {})) +
        '">' + t.html('consoleFederation.backToList') + '</a></p>' +
        FederationPage.federationLinks(json.paths.base, t);
    }

    return inner;
  }

  // ---------------------------------------------------------------------------
  // A PARTNER'S SHARED SIGNALS (#373, #374): the configuration on the entry,
  // the stream this realm holds at the partner and its acts, the people the
  // partner has blocked, and the latest arrivals. Every act posts to
  // /admin/federation as a `signals-*` action, whose API twin is
  // `POST /admin-api/federation/signals-*` (rule 7). Never a secret.
  // ---------------------------------------------------------------------------
  /**
   * Draws a service-provider-side relationship's Shared Signals section.
   *
   * @param row - the relationship's row
   * @param record - the relationship
   * @param view - the detail view: `signals`, `arrivals`, `signalSetFields`
   * @param carryBack - the hidden `back` field carried into each form
   * @param t - the page's translator
   * @returns the section as HTML
   */
  static federationSignalsSection(row, record, view, carryBack, t) {
    const s = view.signals;
    if (!s) {
      return '';
    }
    const act = function (action, label, extra?, danger?) {
      return '<form method="post" action="/admin/federation" ' +
        'class="inline">' + carryBack +
        '<input type="hidden" name="action" value="' + kit.esc(action) +
        '"><input type="hidden" name="id" value="' + kit.esc(row.id) +
        '">' + (extra || '') + ' <button type="submit"' +
        (danger ? ' class="danger"' : '') + '>' + kit.esc(label) +
        '</button></form>';
    };
    const setRow = function (field) {
      const value = record[field.name] || '';
      return '<tr><td><code>' + kit.esc(field.name) + '</code></td><td>' +
        '<form method="post" action="/admin/federation"><div ' +
        'class="formrow">' + carryBack +
        '<input type="hidden" name="action" value="set">' +
        '<input type="hidden" name="id" value="' + kit.esc(row.id) + '">' +
        '<input type="hidden" name="field" value="' + kit.esc(field.name) +
        '">' + (Array.isArray(field.enum)
          ? '<select name="value">' + field.enum.map(function (one) {
              return '<option' + (String(value || 'poll') === one
                ? ' selected' : '') + '>' + kit.esc(one) + '</option>';
            }).join('') + '</select>'
          : '<input type="' + (field.sensitive ? 'password' : 'text') +
            '" name="value" size="42" autocomplete="off" value="' +
            kit.esc(field.sensitive ? '' : value) + '"' +
            (field.sensitive && value
              ? ' placeholder="' +
                kit.esc(t.text('consoleFederation.setNotShown')) + '"'
              : '') + '>') +
        '<button type="submit">' + t.html('consoleFederation.buttonSet') +
        '</button></div></form></td><td ' +
        'class="sub">' + kit.note(kit.esc(field.what)) + '</td></tr>';
    };
    const switchRow = function (name, dflt) {
      const field = view.schema.filter(function (f) {
        return f.name === name;
      })[0];
      const on = FederationPage.boolOf(record[name], dflt);
      return '<tr><td><code>' + kit.esc(name) + '</code></td><td class="' +
        (on ? 'ok' : 'off') + '">' + (on ? 'TRUE' : 'FALSE') + '</td><td>' +
        act('set', on ? t.text('consoleFederation.turnOff')
                      : t.text('consoleFederation.turnOn'),
            '<input type="hidden" name="field" value="' + kit.esc(name) +
            '"><input type="hidden" name="value" value="' +
            (on ? 'FALSE' : 'TRUE') + '">') + '</td><td class="sub">' +
        kit.esc(field ? field.what : '') + '</td></tr>';
    };
    const events = [].concat(record.fedSignalsEvents || []);
    const eventRows = events.map(function (one) {
      return '<tr><td class="who"><code>' + kit.esc(one) + '</code></td>' +
        '<td>' + act('remove-value', t.text('consoleFederation.buttonRemove'),
          '<input type="hidden" name="field" value="fedSignalsEvents">' +
          '<input type="hidden" name="value" value="' + kit.esc(one) +
          '">', true) + '</td></tr>';
    }).join('');
    const streamActs = s.streamId
      ? act('signals-read-stream', t.text('consoleFederation.actReadStream')) +
        act('signals-update-stream',
            t.text('consoleFederation.actSendEvents')) +
        act('signals-verify', t.text('consoleFederation.actVerify')) +
        (s.streamDelivery === 'poll'
          ? act('signals-poll-now', t.text('consoleFederation.actPollNow'))
          : '') +
        act('signals-set-status', t.text('consoleFederation.actPause'),
            '<input type="hidden" name="status" value="paused">') +
        act('signals-set-status', t.text('consoleFederation.actEnable'),
            '<input type="hidden" name="status" value="enabled">') +
        act('signals-delete-stream',
            t.text('consoleFederation.actDeleteStream'), '', true)
      : act('signals-discover', t.text('consoleFederation.actDiscover')) +
        act('signals-create-stream',
            t.text('consoleFederation.actCreateStream'));
    const blocks = (s.blocks || []).length
      ? '<h3 id="signal-blocks">' +
        t.html('consoleFederation.headingBlocked') + '</h3>' +
        '<table><tr><th>' + t.html('consoleFederation.thPerson') +
        '</th><th>' + t.html('consoleFederation.thSince') + '</th><th>' +
        t.html('consoleFederation.thEvent') + '</th><th></th>' +
        '</tr>' + s.blocks.map(function (b) {
          return '<tr><td><a href="' + kit.esc('/admin/users?user=' +
            encodeURIComponent(b.username)) + '">' + kit.esc(b.username) +
            '</a></td><td>' + kit.esc(b.at) + '</td><td><code>' +
            kit.esc(b.event) + '</code></td><td>' +
            act('signals-unblock', t.text('consoleFederation.actUnblock'),
                '<input type="hidden" name="user" value="' +
                kit.esc(b.username) + '">') + '</td></tr>';
        }).join('') + '</table>'
      : '';
    const arrivals = (view.signalArrivals || []).length
      ? '<h3>' + t.html('consoleFederation.headingArrivals') +
        '</h3><table><tr><th>' + t.html('consoleFederation.thWhen') +
        '</th><th>' + t.html('consoleFederation.thEvents') + '</th>' +
        '<th>' + t.html('consoleFederation.thVerified') + '</th><th>' +
        t.html('consoleFederation.thPerson') + '</th><th>' +
        t.html('consoleFederation.thReactions') + '</th></tr>' +
        view.signalArrivals.map(function (r) {
          // A refusal is the view's, and stays English; the word drawn
          // where an arrival carries none is this page's.
          return '<tr><td>' + kit.esc(r.receivedAt) + ' <span class="sub">' +
            kit.esc(r.via) + '</span></td><td>' + (r.events || [])
              .map(function (e) {
                return '<code>' + kit.esc(String(e).replace(/^.*\//, '')) +
                  '</code>';
              }).join(' ') + '</td><td>' + (r.verified
              ? t.html('consoleFederation.verified')
              : '<strong>' + kit.esc(r.refusal ||
                  t.text('consoleFederation.unverified')) +
                '</strong>') + '</td><td>' + kit.esc(r.person || '—') +
            (r.mapping ? '<br><span class="sub">' + kit.esc(r.mapping) +
                         '</span>' : '') + '</td><td>' +
            (r.reactions || []).map(function (x) {
              return kit.esc(x.reaction || '—') + (x.done ? ' ✓' : '') +
                (x.observed ? ' ' + t.html('consoleFederation.observedOnly')
                            : '') +
                (x.why ? ' <span class="sub">' + kit.esc(x.why) +
                         '</span>' : '');
            }).join('<br>') + '</td></tr>';
        }).join('') + '</table>' +
        kit.note(t.html('consoleFederation.everyArrivalA') + '<a href="' +
          '/admin/ssf/transmitters">' +
          t.html('consoleFederation.everyArrivalLink') + '</a>' +
          t.html('consoleFederation.everyArrivalB'))
      : '';
    return '<h2 id="signals">' +
      t.html('consoleFederation.headingSignalsFrom') + '</h2>' +
      kit.note(row.signsIn
        ? t.html('consoleFederation.signalsSignsIn')
        : t.html('consoleFederation.signalsOnly')) +
      '<table><tr><th>' + t.html('consoleFederation.thWhat') + '</th><th>' +
      t.html('consoleFederation.thValue') + '</th></tr>' +
      '<tr><td>' + t.html('consoleFederation.receiving') +
      '</td><td class="' + (s.receiving ? 'ok' : 'off') +
      '">' + (s.receiving ? t.html('consoleFederation.yes')
        : (s.enabled ? t.html('consoleFederation.noSignalsOff')
                     : t.html('consoleFederation.noRelationshipDisabled'))) +
      '</td></tr>' +
      '<tr><td>' + t.html('consoleFederation.ssfIssuer') +
      '</td><td class="who"><code>' +
      kit.esc(s.issuer || t.text('consoleFederation.none')) +
      '</code></td></tr>' +
      '<tr><td>' + t.html('consoleFederation.configuration') + '</td><td>' +
      (s.config
        ? t.html('consoleFederation.discoveredFrom',
                 { at: s.discoveredAt, url: s.discoveryUrl })
        : '<span class="sub">' +
          t.html('consoleFederation.notDiscovered') + '</span>') +
      '</td></tr>' +
      // The stream's own line is its values and `aud`, the claim's name;
      // only the verification after it is words.
      '<tr><td>' + t.html('consoleFederation.stream') + '</td><td>' +
      (s.streamId
        ? '<code>' + kit.esc(s.streamId) + '</code> (' +
          kit.esc(s.streamDelivery) + ', aud <code>' +
          kit.esc((s.streamAud || []).join(' ')) + '</code>)' +
          (s.verifiedAt ? ' ' + t.html('consoleFederation.verifiedAt',
                                       { at: s.verifiedAt }) : '')
        : '<span class="sub">' + t.html('consoleFederation.noneLower') +
          '</span>') + '</td></tr>' +
      (s.streamDelivery === 'push' || s.delivery === 'push'
        ? '<tr><td>' + t.html('consoleFederation.pushEndpoint') +
          '</td><td class="who"><code>' +
          kit.esc(view.base + s.pushEndpoint) + '</code><span class="sub">' +
          ' ' + t.html('consoleFederation.givenWithStream') +
          '</span></td></tr>' : '') +
      '<tr><td>' + t.html('consoleFederation.counts') + '</td><td>' +
      t.html('consoleFederation.countsLine',
             { received: String(s.counts.received || 0),
               verified: String(s.counts.verified || 0),
               refused: String(s.counts.refused || 0),
               acted: String(s.counts.acted || 0) }) +
      // The poll's result is the view's, and is drawn as it comes.
      (s.lastPollAt ? t.html('consoleFederation.lastPoll',
                             { at: s.lastPollAt }) +
        kit.esc(s.lastPollResult) : '') +
      '</td></tr>' +
      (s.lastError ? '<tr><td>' + t.html('consoleFederation.lastError') +
                     '</td><td class="warn">' +
                     kit.esc(s.lastError) + '</td></tr>' : '') +
      (s.ready ? '' : '<tr><td>' + t.html('consoleFederation.stillToSet') +
                      '</td><td class="warn">' +
                      kit.esc(s.missing.join(', ')) + '</td></tr>') +
      '</table>' +
      '<p>' + streamActs + '</p>' +
      '<table><tr><th>' + t.html('consoleFederation.thField') + '</th><th>' +
      t.html('consoleFederation.thNow') + '</th><th></th><th>' +
      t.html('consoleFederation.thWhatItIs') + '</th>' +
      '</tr>' + (row.signsIn ? switchRow('fedSignalsEnabled', false) : '') +
      switchRow('fedSignalEmailMatch', false) + '</table>' +
      '<table><tr><th>' + t.html('consoleFederation.thField') + '</th><th>' +
      t.html('consoleFederation.thValue') + '</th><th>' +
      t.html('consoleFederation.thWhatItIs') + '</th></tr>' +
      (view.signalSetFields || []).map(setRow).join('') + '</table>' +
      '<h3><code>fedSignalsEvents</code></h3>' +
      (eventRows ? '<table>' + eventRows + '</table>'
                 : kit.note(t.html('consoleFederation.noEventsListed'))) +
      '<form method="post" action="/admin/federation"><div class="formrow">' +
      carryBack + '<input type="hidden" name="action" value="add-value">' +
      '<input type="hidden" name="id" value="' + kit.esc(row.id) + '">' +
      '<input type="hidden" name="field" value="fedSignalsEvents">' +
      '<input type="text" name="value" size="60" placeholder="' +
      kit.esc(t.text('consoleFederation.eventPlaceholder')) +
      '"><button type="submit">' + t.html('consoleFederation.buttonAdd') +
      '</button></div></form>' +
      blocks + arrivals;
  }

  // ---------------------------------------------------------------------------
  // A RELATIONSHIP'S ENCRYPTION KEY (#168): whether plaintext is refused, the
  // key table — never a private key — and the Rotate button, whose API twin
  // is `POST /admin-api/federation/rotate-key` (rule 7).
  // ---------------------------------------------------------------------------
  /**
   * Draws a relationship's encryption section: whether plaintext is
   * refused, its keys (never a private key) and the Rotate button.
   *
   * @param row - the relationship's row
   * @param encryption - the relationship's encryption state and keys
   * @param carryBack - the hidden `back` field carried into the form
   * @param t - the page's translator
   * @returns the section as HTML
   */
  static federationEncryptionSection(row, encryption, carryBack, t) {
    const rows = encryption.keys.map(function (key) {
      return '<tr><td><code>' + kit.esc(key.kid) + '</code></td><td>' +
        kit.esc(key.keyType) + '</td><td class="' +
        (key.decrypts ? 'ok' : 'off') + '">' + kit.esc(key.state) +
        (key.retiresAt ? ' ' + t.html('consoleFederation.decryptsUntil',
          { at: new Date(key.retiresAt).toISOString() }) : '') +
        '</td><td>' + kit.esc(key.notAfter || '') + '</td><td>' +
        (key.sealed ? t.html('consoleFederation.sealed')
                    : t.html('consoleFederation.inClear')) +
        '</td></tr>';
    }).join('');
    return '<h2 id="encryption">' +
      t.html('consoleFederation.headingEncryption') + '</h2>' +
      kit.note(encryption.required
        ? t.html('consoleFederation.plaintextRefused')
        : (encryption.allowUnencrypted
            // The class on the bold opening keeps it out of the message.
            ? '<strong class="warn">' +
              t.html('consoleFederation.allowUnencryptedA') + '</strong>' +
              t.html('consoleFederation.allowUnencryptedB')
            : t.html('consoleFederation.plaintextDevelopment'))) +
      (rows
        ? '<table><tr><th>kid</th><th>' + t.html('consoleFederation.thType') +
          '</th><th>' + t.html('consoleFederation.thState') + '</th><th>' +
          t.html('consoleFederation.thExpires') +
          '</th><th>' + t.html('consoleFederation.thAtRest') + '</th></tr>' +
          rows + '</table>'
        : kit.note(t.html('consoleFederation.noKeyHeld'))) +
      '<form method="post" action="/admin/federation"><div class="formrow">' +
      carryBack +
      '<input type="hidden" name="action" value="rotate-key">' +
      '<input type="hidden" name="id" value="' + kit.esc(row.id) + '">' +
      '<button type="submit">' + t.html('consoleFederation.buttonRotate') +
      '</button>' +
      '<span class="sub">' +
      t.html('consoleFederation.rotateNote',
             { seconds: String(encryption.graceS) }) +
      '</span></div></form>';
  }

  /**
   * Draws what this service SENDS the partner of an identity-provider-side
   * relationship: its application's streams on this service's transmitter.
   *
   * @param outbound - `{ application, streams }`
   * @param t - the page's translator
   * @returns the section as HTML
   */
  static federationOutboundSection(outbound, t) {
    if (!outbound || !outbound.application) {
      return '';
    }
    return '<h2 id="signals-sent">' +
      t.html('consoleFederation.headingSignalsSent') + '</h2>' +
      kit.note(t.html('consoleFederation.signalsSentNote',
                      { application: outbound.application })) +
      ((outbound.streams || []).length
        ? '<table><tr><th>' + t.html('consoleFederation.thStream') +
          '</th><th>' + t.html('consoleFederation.thDelivery') + '</th><th>' +
          t.html('consoleFederation.thStatus') + '</th>' +
          '<th>' + t.html('consoleFederation.thEventsDelivered') +
          '</th><th>' + t.html('consoleFederation.thLastActivity') +
          '</th><th>' + t.html('consoleFederation.thDeadLetters') +
          '</th></tr>' + outbound.streams.map(function (one) {
            return '<tr><td><code>' + kit.esc(one.streamId) + '</code>' +
              '</td><td>' + kit.esc(one.delivery) + '</td><td class="' +
              (one.dead ? 'warn' : '') + '">' + kit.esc(one.status) +
              (one.dead ? ' ' + t.html('consoleFederation.notDelivering')
                        : '') + '</td><td>' +
              (one.eventsDelivered || []).map(function (e) {
                return '<code>' + kit.esc(String(e).replace(/^.*\//, '')) +
                  '</code>';
              }).join(' ') + '</td><td>' +
              kit.esc(one.lastActivityAt || '—') + '</td><td>' +
              kit.esc(String(one.deadLetters)) + '</td></tr>';
          }).join('') + '</table>'
        : kit.note(t.html('consoleFederation.noOutboundStream')));
  }

  // WHAT THE PARTNER SENT AND NOTHING WROTE (#94), under the mapping it
  // would take to keep one: a name no mapping names, or a name mapped onto an
  // attribute no partner may write (with why). Each row carries a Map form
  // with the name filled in, so keeping one is naming its attribute.
  /**
   * Draws the names a relationship's partner sent that were not written,
   * each with a form to map it.
   *
   * @param row - the relationship's view
   * @param unmapped - `federation.unmappedOf()`
   * @param carryBack - the hidden `back` field every form carries
   * @param t - the page's translator
   * @returns the section as HTML, or '' when there is nothing to show
   */
  static federationUnmappedSection(row, unmapped, carryBack, t) {
    if (!unmapped.length) {
      return '';
    }
    return '<h3 id="unmapped">' +
      t.html('consoleFederation.headingUnmapped') + '</h3>' +
      kit.note(t.html('consoleFederation.unmappedNote')) +
      '<table><tr><th>' + t.html('consoleFederation.thName') + '</th><th>' +
      t.html('consoleFederation.thWhy') + '</th><th>' +
      t.html('consoleFederation.thLastSent') + '</th><th>' +
      t.html('consoleFederation.thMapIt') +
      '</th></tr>' +
      unmapped.map(function (one) {
        // Why a mapping was refused is the view's, and stays English.
        return '<tr><td class="who"><code>' + kit.esc(one.name) +
          '</code></td><td class="sub">' +
          (one.refused ? kit.esc(one.refused)
                       : t.html('consoleFederation.nothingMapsIt')) +
          '</td><td class="sub">' + kit.esc(one.last) + '</td><td><form ' +
          'method="post" action="/admin/federation"><div class="formrow">' +
          carryBack +
          '<input type="hidden" name="action" value="add-value">' +
          '<input type="hidden" name="id" value="' + kit.esc(row.id) +
          '"><input type="hidden" name="field" value="fedAttributeMap">' +
          '<input type="text" name="value" size="30" value="' +
          kit.esc(one.name + '=') + '"><button type="submit">' +
          t.html('consoleFederation.buttonMap') +
          '</button></div></form></td></tr>';
      }).join('') + '</table>';
  }

  // federation.js's boolOf(), copied for the page (#446): how the register
  // reads a boolean attribute it stores as text, with a default for one that
  // is not there. The page draws a switch from the record it is given, and
  // must read the value exactly as the register would act on it.
  /**
   * Reads a boolean attribute as the federation register reads it.
   *
   * @param value - the attribute's value, as stored
   * @param dflt - what an absent or unreadable value means
   * @returns the boolean
   */
  static boolOf(value, dflt) {
    const text = String(value == null ? '' : value).trim().toUpperCase();
    if (text === 'TRUE' || text === 'YES' || text === '1' || text === 'ON') {
      return true;
    }
    if (text === 'FALSE' || text === 'NO' || text === '0' || text === 'OFF') {
      return false;
    }
    return !!dflt;
  }

  // ---------------------------------------------------------------------------
  // /admin/federation/map, FROM `GET /admin-api/federation/map` (#446): one
  // realm's relationships drawn (laid out on the server), filtered, with
  // the relationships, the applications behind them and the key in words.
  // ---------------------------------------------------------------------------
  /**
   * Draws `/admin/federation/map` from its answer.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of `GET /admin-api/federation/map`
   * @returns the body as HTML
   */
  static map(ctx: Json, json: Json): string {
    const t = ctx.t;
    const filter = json.filter || {};
    const wanted = { role: filter.role || '', protocol: filter.protocol || '',
                     q: filter.q || '' };
    const filtering = !!(wanted.role || wanted.protocol ||
                         wanted.q);

    // The filter, and it is the list page's own plus a protocol select —
    // because narrowing the picture and narrowing the table under it has to
    // be ONE control. It carries no `page`: this view has no paging, and a
    // page number carried into a view with none is a parameter that does
    // nothing and comes back with the reader on the next hop.
    const roleOptions = ['<option value="">' +
      t.html('consoleFederation.anyRole') + '</option>'].concat(
      json.roles.map(function (one) {
        return '<option value="' + kit.esc(one.role) + '"' +
          (one.role === wanted.role ? ' selected' : '') + '>' +
          kit.esc(one.short) + '</option>';
      })).join('');
    const protocolOptions = ['<option value="">' +
      t.html('consoleFederation.anyProtocol') + '</option>'].concat(
      json.protocols.map(function (one) {
        return '<option value="' + kit.esc(one.protocol) + '"' +
          (one.protocol === wanted.protocol ? ' selected' : '') + '>' +
          kit.esc(one.label) + '</option>';
      })).join('');

    // Every application on the picture, once, with which relationships it
    // uses and what has crossed each. It is the per-application half laid out
    // flat, because the picture can carry three lines on a label and this is
    // the place the fourth fact goes.
    const useRows = [];
    json.relationships.forEach(function (row) {
      row.applications.forEach(function (use) {
        useRows.push({ row: row, use: use });
      });
    });
    useRows.sort(function (a, b) {
      if (b.use.authentications !== a.use.authentications) {
        return b.use.authentications - a.use.authentications;
      }
      return a.use.application < b.use.application ? -1
           : a.use.application > b.use.application ? 1 : 0;
    });

    return (
      '<div class="tiles">' +
      kit.tile(json.counts.relationships,
               t.text('consoleFederation.tileRelationshipsDrawn')) +
      kit.tile(json.counts.applications,
               t.text('consoleFederation.tileApplicationsBehind')) +
      kit.tile(json.counts.partners,
               t.text('consoleFederation.tileForeignPartners')) +
      kit.tile(json.counts.authentications,
               t.text('consoleFederation.tileFederatedSignIns')) +
      '</div>' +

      kit.note(t.html('consoleFederation.mapOneRealm',
                      { realm: json.realm.id })) +

      kit.note(t.html('consoleFederation.mapLeftRight')) +

      '<form method="get" action="/admin/federation/map"><div ' +
      'class="formrow"><label for="q">' +
      t.html('consoleFederation.labelRelationship') + '</label>' +
      '<input type="text" id="q" name="q" value="' + kit.esc(wanted.q) +
      '" size="24" placeholder="' +
      kit.esc(t.text('consoleFederation.filterPlaceholder')) + '">' +
      '<label for="role">' + t.html('consoleFederation.labelRole') +
      '</label><select id="role" name="role">' +
      roleOptions + '</select><label ' +
      'for="protocol">' + t.html('consoleFederation.thProtocol') +
      '</label><select id="protocol" ' +
      'name="protocol">' +
      protocolOptions + '</select>' +
      '<button type="submit">' + t.html('consoleFederation.buttonFilter') +
      '</button>' +
      (filtering ? ' <a href="/admin/federation/map">' +
        t.html('consoleFederation.clear') + '</a>' : '') +
      '</div></form>' +

      (json.relationships.length
        ? FederationPage.mapDrawing(json, wanted, t)
        : kit.note(json.empty
            ? '<strong>' + t.html('consoleFederation.mapEmptyHeadline') +
              '</strong>' + t.html('consoleFederation.mapEmptyA') +
              '<a ' +
              'href="/admin/federation">' +
              t.html('consoleFederation.mapEmptyLink') + '</a>' +
              t.html('consoleFederation.mapEmptyB')
            : '<strong>' + t.html('consoleFederation.mapNoMatchHeadline') +
              '</strong>' + t.html('consoleFederation.mapNoMatchA') + '<a ' +
              'href="/admin/federation/map">' +
              t.html('consoleFederation.mapNoMatchLink') + '</a>' +
              t.html('consoleFederation.mapNoMatchB'))) +

      '<h2>' + t.html('consoleFederation.headingRelationships') + '</h2>' +
      kit.note(t.html('consoleFederation.mapRowsA') +
      '<a href="/admin/federation">' +
      t.html('consoleFederation.mapRowsLink') + '</a>' +
      t.html('consoleFederation.mapRowsB')) +
      '<table><tr><th>' + t.html('consoleFederation.thRelationship') +
      '</th><th>' + t.html('consoleFederation.thThisServiceIs') +
      '</th><th>' + t.html('consoleFederation.thProtocol') + '</th><th>' +
      t.html('consoleFederation.thPartner') + '</th><th>' +
      t.html('consoleFederation.thState') + '</th><th ' +
      'class="num">' + t.html('consoleFederation.thApplications') +
      '</th><th class="num">' + t.html('consoleFederation.thPeople') +
      '</th><th ' +
      'class="num">' + t.html('consoleFederation.thSignIns') + '</th><th>' +
      t.html('consoleFederation.thAuthenticationMethod') + '</th></tr>' +
      (json.relationships.map(function (row) {
        return FederationPage.federationMapRow(row, t);
      }).join('') ||
        '<tr><td colspan="9">' + t.html('consoleFederation.nothingToShow') +
        '</td></tr>') +
      '</table>' +

      '<h2>' + t.html('consoleFederation.headingPerRelationship') + '</h2>' +
      kit.note(t.html('consoleFederation.perRelationshipNote')) +
      '<table><tr><th>' + t.html('consoleFederation.thApplication') +
      '</th><th>' + t.html('consoleFederation.thRelationship') +
      '</th><th>' + t.html('consoleFederation.thPartner') + '</th>' +
      '<th class="num">' + t.html('consoleFederation.thPeople') +
      '</th><th class="num">' + t.html('consoleFederation.thSignIns') +
      '</th>' +
      '<th>' + t.html('consoleFederation.thConfiguredBy') + '</th><th>' +
      t.html('consoleFederation.thLast') + '</th></tr>' +
      (useRows.map(function (one) {
        const use = one.use;
        const row = one.row;
        return '<tr><td><a href="' +
          kit.esc('/admin/applications' +
                   kit.queryWith({}, { application: use.application })) +
          '">' + kit.esc(use.application) + '</a></td>' +
          '<td><a href="' +
          kit.esc('/admin/federation' +
                   kit.queryWith({}, { relationship: row.id })) +
          '">' +
          kit.esc(row.id) + '</a></td>' +
          '<td class="who">' + kit.esc(row.peer || '') + '</td>' +
          '<td class="num">' + use.users + '</td>' +
          '<td class="num">' + use.authentications + '</td>' +
          '<td>' + (use.configured
            ? (use.source === 'broker'
                ? t.html('consoleFederation.brokerA') + '<a href="' +
                  kit.esc('/admin/federation' +
                           kit.queryWith({}, { relationship: use.via })) +
                  '">' + kit.esc(use.via) + '</a>' +
                  t.html('consoleFederation.brokerB')
                : t.html('consoleFederation.ownRelationship'))
            : '<span class="bad">' +
              t.html('consoleFederation.nothingAnyMore') + '</span>' +
              '<span class="sub">' +
              t.html('consoleFederation.keptRatherThanDropped') +
              '</span>') + '</td>' +
          '<td>' + (use.lastSeen
            ? kit.esc(use.lastSeen) +
              (use.lastUser ?
               '<span class="sub">' + kit.esc(use.lastUser) + '</span>' : '')
            : '<span class="state-none">' +
              t.html('consoleFederation.neverUsed') + '</span>') +
          '</td></tr>';
      }).join('') ||
        '<tr><td colspan="7">' +
        t.html('consoleFederation.noApplicationConfigured') + '</td></tr>') +
      (json.relationships.filter(function (r) { return r.unattributed; })
        .length
        // `{id}` is the route's own placeholder, and a message cannot carry
        // a brace, so the path goes in as a parameter.
        ? kit.note(t.html('consoleFederation.unattributedNote',
                          { path: '/federation/login/{id}' })) +
          '<table><tr><th>' + t.html('consoleFederation.thRelationship') +
          '</th><th class="num">' + t.html('consoleFederation.thSignIns') +
          '</th>' +
          '<th class="num">' + t.html('consoleFederation.thAttributed') +
          '</th>' +
          '<th class="num">' + t.html('consoleFederation.thNoApplication') +
          '</th></tr>' +
          json.relationships.filter(function (r) { return r.unattributed; })
            .map(function (r) {
              return '<tr><td><a href="' +
                kit.esc('/admin/federation' +
                         kit.queryWith({}, { relationship: r.id })) +
                '">' + kit.esc(r.id) + '</a></td>' +
                '<td class="num">' + r.authentications + '</td>' +
                '<td class="num">' + r.attributed + '</td>' +
                '<td class="num">' + r.unattributed + '</td></tr>';
            }).join('') + '</table>'
        : '') +

      '<h2>' + t.html('consoleFederation.headingKey') + '</h2>' +
      kit.note(t.html('consoleFederation.keyNote')) +
      json.mapKey);
  }

  /**
   * Draws the federation picture from its answer, with the links to its SVG
   * and JSON forms.
   *
   * @param json - the answer: `svg` and `drawing`
   * @param params - the page's filter, carried into the two links
   * @param t - the page's translator
   * @returns the drawing and its note as HTML
   */
  static mapDrawing(json: Json, params: Json, t: Json): string {
    const drawn = json.drawing || {};
    // The layout's failure is a refusal of sorts, and stays English.
    return '<div class="diagram">' + json.svg + '</div>' +
      kit.note(drawn.width + '&times;' + drawn.height + ' &mdash; ' +
      '<a href="' +
      kit.esc('/admin/federation/map' +
              kit.queryWith(params, { format: 'svg' })) +
      '">' + t.html('consoleFederation.documentOnItsOwn') + '</a>' +
      t.html('consoleFederation.drawingOr') +
      '<a href="' +
      kit.esc('/admin/federation/map' +
              kit.queryWith(params, { format: 'json' })) +
      '">' + t.html('consoleFederation.graphAsJson') + '</a>' +
      t.html('consoleFederation.drawingNoPan') +
      (drawn.failed ? ' <span class="state-revoked">The layout failed: ' +
        kit.esc(drawn.failed) + '</span>' : ''));
  }

  // One relationship's row in the table under the picture. It carries the two
  // numbers the picture was asked for and the ones a label had no room for, and
  // its first cell links back to the drill-down that configures it.
  /**
   * Draws one relationship's row of the table under the federation picture:
   * its state, application count, sign-in counts and how it authenticates.
   *
   * @param row - the relationship's row in the graph
   * @param t - the page's translator
   * @returns the row as HTML
   */
  static federationMapRow(row, t) {
    const state = row.usable
      ? '<span class="ok">' + t.html('consoleFederation.stateReady') +
        '</span>'
      : !row.enabled
          ? '<span class="off">' + t.html('consoleFederation.stateDisabled') +
            '</span>'
          : '<span class="bad">' +
            t.html('consoleFederation.stateEnabledNotConfigured') + '</span>';
    const noCount = kit.esc(t.text('consoleFederation.nothingCountsTitle'));
    return '<tr><td><a href="' +
      kit.esc('/admin/federation' +
              kit.queryWith({}, { relationship: row.id })) +
      '">' +
      kit.esc(row.id) + '</a>' +
      (row.name !== row.id ? '<span class="sub">' + kit.esc(row.name) +
       '</span>' :
       '') +
      '</td>' +
      '<td>' + kit.esc(row.roleLabel) + '</td>' +
      '<td>' + kit.esc(row.protocolLabel) +
        (row.signsIn !== false && row.signalsEnabled
          ? '<span class="sub">' + t.html('consoleFederation.andItsSignals') +
            '</span>' : '') +
        '</td>' +
      '<td class="who">' + kit.esc(row.peer || row.application || '') +
        (!row.peer && !row.application
          ? '<span class="sub">' + t.html('consoleFederation.nothingNamedYet') +
            '</span>' : '') + '</td>' +
      '<td>' + state + '</td>' +
      // THE ANSWER TO "HOW MANY APPLICATIONS", and a dash where the question
      // does not apply rather than a zero: an identity-provider-side
      // relationship names exactly one application by construction, so `0`
      // there would be false and `1` would be a number nobody needs.
      '<td class="num">' + (row.role === 'service-provider'
        ? row.applicationCount
        : '<span class="state-none" title="' +
          kit.esc(t.text('consoleFederation.oneApplicationTitle')) +
          '">&mdash;</span>') + '</td>' +
      // ---------------------------------------------------------------------
      // THE TWO COUNTS, AND A BARE `0` IS REFUSED ON THE IDENTITY-PROVIDER
      // SIDE.
      //
      // `fedAuthentications` there is not a number that happens to be low: it
      // is a number NOTHING WRITES. What it counts is assertions CONSUMED and
      // that side issues them, which `federation/CLAUDE.md` states as a
      // deliberate non-goal. So printing it would assert that nobody has ever
      // signed in for this partner, in the same column that means exactly that
      // two rows up.
      //
      // Where the relationship BROKERS, there is a real number and it belongs
      // to the pair — the sign-ins happened and were counted against the
      // relationship they went through — so `brokeredUse` is printed instead,
      // marked as belonging to the onward relationship rather than to this one.
      // ---------------------------------------------------------------------
      (row.role === 'identity-provider'
        ? (row.brokeredUse
            ? '<td class="num">' + row.brokeredUse.users +
              '<span class="sub">' +
              t.html('consoleFederation.via', { relationship: row.brokersTo }) +
              '</span></td><td class="num">' + row.brokeredUse.authentications +
              '<span class="sub">' +
              t.html('consoleFederation.via', { relationship: row.brokersTo }) +
              '</span></td>'
            : '<td class="num"><span class="state-none" title="' + noCount +
              '">&mdash;</span></td>' +
              '<td class="num"><span class="state-none" title="' + noCount +
              '">&mdash;</span></td>')
        : '<td class="num">' + row.users + '</td>' +
          '<td class="num">' + row.authentications + '</td>') +
      // THE AUTHENTICATION METHOD, WHICH IS THE IDENTITY-PROVIDER SIDE'S
      // COLUMN. An unset mechanism is printed as what it MEANS rather than left
      // blank: it is the sign-in screen, which is a decision and the commonest
      // one.
      '<td>' + (row.role === 'identity-provider'
        ? (row.brokersTo
            ? t.html('consoleFederation.through') + '<a href="' +
              kit.esc('/admin/federation' +
                       kit.queryWith({}, { relationship: row.brokersTo })) +
              '">' + kit.esc(row.brokersTo) + '</a>' +
              (row.brokerUsable ? ''
                : '<span class="sub bad">' + kit.esc(row.brokerProblem ||
                    t.text('consoleFederation.brokerNotUsable')) + '</span>')
            : kit.esc(row.mechanismLabel) +
              (row.mechanismKnown ? ''
                : '<span class="sub bad">' +
                  t.html('consoleFederation.notAMechanism') + '</span>'))
        : '<span class="state-none" title="' +
          kit.esc(t.text('consoleFederation.authAtPartnerTitle')) +
          '">&mdash;</span>') + '</td>' +
      '</tr>';
  }
}

export = FederationPage;
