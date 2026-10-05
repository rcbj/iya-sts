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
        (!row.peer && !row.application ? '<span class="sub">nothing named ' +
                                         'yet</span>' : '') +
        '</td>' +
        FederationPage.federationStateCell(row) +
        '<td class="num">' + row.authentications + '</td>' +
        '<td class="num">' + row.users + '</td>' +
        '<td>' + (row.lastError
          ? '<span class="bad">' + kit.shortened(row.lastError, 60) + '</span>'
          : '<span class="sub">none recorded</span>') + '</td></tr>';
    }).join('');

    const roleOptions = ['<option value="">any role</option>'].concat(
      json.roles.map(function (one) {
        const n = json.roleCounts[one.role] || 0;
        return '<option value="' + kit.esc(one.role) + '"' +
          (one.role === wantedRole ? ' selected' : '') + '>' +
          kit.esc(one.short) +
          ' (' + n + ')</option>';
      })).join('');

    const inner = '<div class="tiles">' +
      kit.tile(json.relationshipCount, 'Relationships') +
      kit.tile(json.ready, 'Ready') +
      kit.tile(json.enabledNotConfigured, 'Enabled, not configured') +
      kit.tile(json.authentications, 'Federated sign-ins') +
      '</div>' +
      FederationPage.federationCaveat() +
      // THE PICTURE, pointed at from the page it drills down from. This table
      // has one row per relationship and no row can say anything about another,
      // so three questions an operator arrives with have no cell here: how many
      // applications are behind a partner, how many people have come through it
      // FOR EACH of them, and what an arriving foreign service provider
      // actually meets. All three are facts about two registers at once.
      kit.note('<a href="/admin/federation/map">The picture</a> draws this ' +
      'register as a diagram, laid out on the server. It adds the three ' +
      'things a table of relationships has nowhere to put: how many ' +
      'applications are configured to use each partner, how many people have ' +
      'signed in through each <em>application and relationship</em> pair, ' +
      'and what the identity-provider side is configured to do about ' +
      'authenticating somebody — including where one relationship brokers to ' +
      'another, which is what makes this service an identity bridge and is ' +
      'invisible in any single row.') +
      '<form method="get" action="/admin/federation"><div class="formrow">' +
      '<label for="q">Relationship</label>' +
      '<input type="text" id="q" name="q" value="' +
      kit.esc(String(ctx.query.q || '')) +
      '" size="24" placeholder="id, name, partner or application">' +
      '<label for="role">Role</label><select id="role" name="role">' +
      roleOptions + '</select><label for="per">Show</label><select id="per" ' +
      'name="per">' + kit.perPageOptions(paging.perPage) +
      '</select><button ' +
      'type="submit">Filter</button>' +
      ((wantedText || wantedRole) ? ' <a href="/admin/federation">clear</a>' :
        '') +
      '</div></form>' + nav.head +
      '<table><tr><th>Relationship</th><th>This service ' +
      'is</th><th>Protocol</th><th>Partner</th><th>State</th><th ' +
      'class="num">Sign-ins</th><th class="num">People</th><th>Last ' +
      'refusal</th></tr>' +
      (rows || '<tr><td colspan="8">No federation relationship ' +
        ((wantedText || wantedRole) ? 'matches. The filter above may be ' +
                                      'hiding some.'
          : 'is configured. Nothing federated happens until one is — and ' +
            'then not until it is enabled, which is a second, deliberate ' +
            'act.') + '</td></tr>') +
      '</table>' + nav.foot +
      FederationPage.federationCreateForm(json.roles, json.protocols) +
      '<h2>The two directions</h2>' +
      '<table><tr><th>This service is</th><th>What it means</th></tr>' +
      json.roles.map(function (one) {
        return '<tr><td>' + kit.esc(one.short) + '</td><td>' +
               kit.esc(one.what) +
               '</td></tr>';
      }).join('') + '</table>' +
      kit.note('<strong>One relationship is one DIRECTION.</strong> A ' +
      'partner this service both consumes from and asserts to is two ' +
      'relationships with two ids, because everything that configures one ' +
      'differs by direction — the endpoints are theirs or ours, the ' +
      'certificate is theirs or ours, the attribute mapping runs inbound or ' +
      'the release list runs outbound.') +
      '<h2>The five protocols</h2><table><tr><th>Protocol</th><th>What ' +
      'happens</th><th>Specification</th></tr>' +
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
      FederationPage.federationLinks(json.paths.base);

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
   * @returns the cell as HTML
   */
  static federationStateCell(row) {
    if (row.usable) {
      return '<td class="ok">ready</td>';
    }
    if (!row.enabled) {
      return '<td class="off">disabled' +
        (row.ready ? '' : ' <span class="sub">and not configured</span>') +
             '</td>';
    }
    return '<td class="bad">ENABLED, not configured<span class="sub">' +
      kit.esc(row.missing.join(', ')) + ' still to set. It refuses rather ' +
      'than half-working.</span></td>';
  }

  /**
   * Draws the form that adds a federation relationship.
   *
   * @returns the form as HTML
   */
  static federationCreateForm(roles, protocols) {
    return '<h2>Add a relationship</h2>' +
      kit.note('It is created <strong>disabled</strong>, whatever is filled ' +
      'in here, and nothing about it does anything until it is enabled on ' +
      'its own page. That is not caution for its own sake: a partner that ' +
      'half-exists and silently accepts assertions is the failure this whole ' +
      'register is arranged to prevent, and enabling is the second, ' +
      'deliberate act that says the configuration is finished.') +
      '<form method="post" action="/admin/federation"><div ' +
      'class="formrow"><input type="hidden" name="action" ' +
      'value="create"><label for="fedid">Id</label><input type="text" ' +
      'id="fedid" name="id" size="16" required ' +
      'placeholder="partner-a"><label for="fedrole">This service ' +
      'is</label><select id="fedrole" name="role">' +
      roles.map(function (one) {
        return '<option value="' + kit.esc(one.role) + '">' +
               kit.esc(one.short) +
               '</option>';
      }).join('') + '</select>' +
      '<label for="fedprotocol">Protocol</label>' +
      '<select id="fedprotocol" name="protocol">' +
      protocols.map(function (one) {
        return '<option value="' + kit.esc(one.protocol) + '">' +
               kit.esc(one.label) +
               '</option>';
      }).join('') + '</select><label for="fedname">Name</label><input ' +
      'type="text" id="fedname" name="name" size="16" ' +
      'placeholder="optional"><label for="fedpeer">Partner</label><input ' +
      'type="text" id="fedpeer" name="peer" size="26" placeholder="their ' +
      'entityID, issuer or realm"><button ' +
      'type="submit">Add</button></div></form>' +
      kit.note('The <strong>id</strong> is the key, the RDN and a URL ' +
      'segment, so it has to start with a letter or a digit and hold only ' +
      'letters, digits, dot, dash and underscore. <strong>Partner</strong> ' +
      'is their own identifier in whatever their protocol calls it, and on a ' +
      'service-provider-side relationship it is CHECKED: an assertion whose ' +
      'issuer is not that string is refused, even when the signature ' +
      'verifies.');
  }

  /**
   * Draws the caveat both federation pages carry.
   *
   * @returns the caveat as HTML
   */
  static federationCaveat() {
    return (
      kit.note('<strong>This is the one feature here that has to be ' +
      'configured before it will do anything, and the one page in this ' +
        'console ' +
      'that configures a REFUSAL.</strong> Everywhere else this service ' +
      'accepts what it is given — any username, any client_id, any entityID, ' +
      'any LDAP bind. It cannot do that at an assertion consumer service: ' +
        'what ' +
      'arrives there is an unauthenticated HTTP request claiming to be a ' +
      'person, and the session it would produce is the same one ' +
      '<code>/oauth2/authorize</code>, <code>/wsfed</code>, ' +
      '<code>/saml2</code> and this console all read. A permissive version ' +
        'of ' +
      'it would not be a permissive mock; it would be an ' +
      'authentication bypass for every protocol in this process.') +
      kit.note('<strong>The gate is on the SIGNER, and on the SUBJECT ' +
      'too (#109).</strong> A verified assertion signs in only the person ' +
        'its ' +
      'partner\'s subject is LINKED to — a <code>federationLink</code> on ' +
        'the ' +
      'entry. What happens to a subject nobody linked is the relationship\'s ' +
      '<code>fedSubjectPolicy</code>: the person it names signs in here ' +
        'first ' +
      'and is then linked (<code>link-at-first-sign-in</code>, the default), ' +
      'it is refused (<code>pre-linked</code>), it gets a new entry of its ' +
        'own ' +
      '(<code>jit-namespaced</code>), or — in development only — the old ' +
        'name ' +
      'match (<code>any-existing</code>). Three rules narrow it further, ' +
        'and a ' +
      'console administrator is refused unless ' +
      '<code>fedMayAssertAdministrators</code> is on. Nothing is written ' +
        'onto ' +
      'an entry before all of that has passed.'));
  }

  /**
   * Draws the links at the foot of the federation pages.
   *
   * @param base - the federation index's path (`federation.PATHS.base`)
   * @returns the links as HTML
   */
  static federationLinks(base) {
    return (
      '<p class="sub"><a href="/admin/federation/map">the picture</a> ' +
        '&middot; ' +
      '<a href="' + base + '">the federation index</a> &middot; ' +
      '<a href="/admin/applications">the applications registry</a> &middot; ' +
        '<a ' +
      'href="/admin/users">who has signed in</a> &middot; <a ' +
      'href="/admin/ldap/federations">the register as the directory sees ' +
      'it</a></p>');
  }

  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static detail(ctx, json) {
    const record = json.found ? json.fields : null;
    const carryBack = '<input type="hidden" name="back" value="' +
      kit.esc(kit.queryWith(kit.listViewOf('/admin/federation', ctx.query),
        {})) +
      '">';
    let inner;
    if (!record) {
      inner = '<p class="warn">There is no federation relationship called ' +
        '<code>' +
          kit.esc(json.id) +
          '</code>. Unlike almost everything else in this console, one does ' +
          'not appear because somebody used it: this register is configured ' +
          'and nothing creates an entry in it by turning ' +
          'up.</p>' + FederationPage.federationLinks(json.paths.base);
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
                ? '(not set — ' + json.defaultSubjectPolicy + ')'
                : '(not set — this relationship says nothing)') + '</option>' +
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
              (field.sensitive ? ' placeholder="set — not shown"' : '') + '>') +
          '<button type="submit">Set</button></div></form></td>' +
          '<td class="sub">' + kit.note(kit.esc(field.what) +
            (field.sensitive
              ? ' <strong>Never printed on this page or in the audit ' +
                'log</strong>, though an ldapsearch of this directory will ' +
                'show it — see the note at the foot.'
              : '')) + '</td></tr>';
      }).join('');

      // WHO THIS PARTNER'S SUBJECTS ARE LINKED TO (#109), paged, each name a
      // link to the person's page — which is where a link is added or removed.
      const linkNav = kit.pageNavPair('/admin/federation',
                                       kit.pageParamsOf(ctx.query),
                                       json.linksPaging);
      const linkedSection = row.role !== 'service-provider' ? ''
        : '<h2 id="linked-people">People linked to this partner</h2>' +
          (row.signsIn
            ? kit.note('Each person below carries a <code>federationLink' +
              '</code> through this relationship: the partner\'s identifier ' +
              'for them, which is what signs them in. Under <code>' +
              'fedSubjectPolicy</code> <code>' +
              kit.esc(json.subjectPolicy) + '</code>. A link ' +
              'is added and removed on the person\'s own page, and removing ' +
              'one ends the sessions this partner signed them in to.')
            : kit.note('Each person below carries a <code>federationLink' +
              '</code> through this relationship, written by an ' +
                'administrator ' +
              'on the person\'s own page: the issuer and subject the ' +
                'partner\'s ' +
              'iss_sub events name them by, or <code>opaque</code> and the ' +
              'opaque id. It signs nobody in; it is how this partner\'s ' +
              'events find the person (#374).')) +
          linkNav.head +
          (json.links.length
            ? '<table><tr><th>Person</th><th>Issuer</th><th>Subject</th></tr>' +
              json.links.map(function (one) {
                return '<tr><td><a href="' + kit.esc('/admin/users' +
                  kit.queryWith({}, { user: one.username })) +
                    '#federation-links">' +
                  kit.esc(one.username) + '</a></td><td><code>' +
                  kit.esc(one.issuer) + '</code></td><td><code>' +
                  kit.esc(one.subject) + '</code></td></tr>';
              }).join('') + '</table>'
            : kit.note('Nobody is linked to this partner yet.')) +
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
          '>' + (on ? 'Turn off' : 'Turn on') + '</button></div></form></td>' +
          '<td class="sub">' + kit.esc(field.what) + '</td></tr>';
      }).join('');

      const multiSections = multiFields.map(function (field) {
        const values = record[field.name] || [];
        return '<h3><code>' + kit.esc(field.name) + '</code></h3>' +
          kit.note(kit.esc(field.what)) +
          (values.length
            ? '<table><tr><th>Value</th><th></th></tr>' +
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
                    'type="submit">Remove</button></div></form></td></tr>';
              }).join('') + '</table>'
            : '<p class="sub">None' +
              (field.name === 'fedRelease'
                ? ' — <strong>and that means no release policy rather than ' +
                  'release nothing</strong>. This partner receives exactly ' +
                  'what /admin/claims and /admin/saml-attributes would give ' +
                  'anybody. Adding the first name here starts filtering.'
                : '') + '.</p>') +
          '<form method="post" action="/admin/federation"><div ' +
            'class="formrow">' +
          carryBack +
          '<input type="hidden" name="action" value="add-value">' +
          '<input type="hidden" name="id" value="' + kit.esc(row.id) + '">' +
          '<input type="hidden" name="field" value="' + kit.esc(field.name) +
          '"><input type="text" name="value" size="40" placeholder="' +
          (field.name === 'fedAttributeMap' ? 'incoming name=ldapAttribute'
            : (field.name === 'fedRelease' ? 'a claim or attribute name' :
               'a value')) + '"><button ' +
          'type="submit">Add</button></div></form>' +
          (field.name === 'fedAttributeMap'
            ? FederationPage.federationUnmappedSection(row,
              json.unmappedAttributes || [],
                                             carryBack)
            : '');
      }).join('');

      inner = '<div class="tiles">' +
        kit.tile(row.authentications, 'Federated sign-ins') +
        kit.tile(row.users, 'Distinct people') +
        kit.tile(row.usable ? 'ready'
                            : (row.enabled ? 'NOT READY' : 'disabled'),
                 'State') +
        '</div>' +
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
          ? '<p class="warn"><strong>Enabled and not configured.</strong> ' +
            kit.esc(row.missing.join(', ')) + ' still to set. Every endpoint ' +
            'for this relationship refuses in this state rather than ' +
            'half-working — a federated sign-in that got half way and ' +
              'produced ' +
            'a session would be the worst possible outcome.</p>'
          : '') +
        '<table><tr><th>What</th><th>Value</th></tr>' +
        '<tr><td>This service is</td><td>' + kit.esc(row.roleLabel) +
        '</td></tr>' +
        '<tr><td>Protocol</td><td>' + kit.esc(row.protocolLabel) +
          '</td></tr>' +
        '<tr><td>Partner</td><td class="who"><code>' +
        kit.esc(row.peer || '(none ' +
            'named)') +
          '</code></td></tr>' +
        (row.role === 'identity-provider'
          ? '<tr><td>Application</td><td class="who">' +
            (row.application
              ? '<a href="/admin/applications?application=' +
                encodeURIComponent(row.application) +
                '"><code>' + kit.esc(row.application) + '</code></a>'
              : '<span class="sub">none named — this relationship configures ' +
                'nothing until one is</span>') + '</td></tr>'
          : '') +
        '<tr><td>Last used</td><td>' + kit.esc(row.lastSeen || '(never)') +
          (row.lastUser ? ' <span class="sub">by ' + kit.esc(row.lastUser) +
           '</span>' :
           '') +
          '</td></tr>' +
        '<tr><td>Directory entry</td><td class="who"><code>' + kit.esc(row.dn) +
        '</code></td></tr></table>' +
        (row.role === 'service-provider' && !row.signsIn
          ? FederationPage.federationSignalsSection(row, record, json,
            carryBack)
          : row.role === 'service-provider'
          ? '<h2>What to configure at the partner</h2>' +
            kit.note('These are the URLs to give whoever runs the identity ' +
            'provider. The assertion consumer service is the one that ' +
              'matters: ' +
            'a partner sending its answer anywhere else produces a 404 in a ' +
            'browser AFTER a successful sign-in somewhere else, which is the ' +
            'least diagnosable failure this feature has.') +
            '<table><tr><th>What they need</th><th>Value</th></tr>' +
            '<tr><td>Assertion consumer service / <code>wreply</code> / ' +
              '<code>redirect_uri</code></td><td class="who"><code>' +
              kit.esc(acs) +
              '</code></td></tr>' +
            '<tr><td>Our entityID / <code>wtrealm</code></td><td ' +
            'class="who"><code>' + kit.esc(acs) +
              '</code><span class="sub">the same string, deliberately: one ' +
              'name for this service per partner, so a partner keying its ' +
              'trust store off an entityID gets one that is only ' +
              'ours-with-them</span></td></tr>' +
            ((row.protocol === 'saml2' || row.protocol === 'saml11' ||
              row.protocol === 'wsfed')
              ? '<tr><td>Our ' + (row.protocol === 'wsfed' ? 'WS-Federation'
                                                           : 'SAML') +
                ' metadata</td><td class="who"><a href="' +
                kit.esc(json.paths.metadata + '/' +
                         encodeURIComponent(row.id)) +
                '"><code>' +
                kit.esc(metadata) + '</code></a><span class="sub">unsigned, ' +
                'deliberately — a signature over it made by the very key it ' +
                'publishes proves nothing they did not already have to ' +
                'trust</span></td></tr>'
              : '') +
            // A PARTNER'S SIGN-OUT (#167): what the partner registers so it can
            // tell this service a session ended, and — below the table — what
            // this service tells it.
            Object.keys(json.signOut || {}).map(function (name) {
              const words = {
                singleLogout: 'SingleLogoutService (Redirect and POST), for ' +
                              'the partner\'s LogoutRequest and its ' +
                              'LogoutResponse to ours',
                signOutCleanup: 'Sign-out cleanup URL, for ' +
                  'wsignoutcleanup1.0 ' +
                                '— the person confirms it here',
                backchannelLogout: '<code>backchannel_logout_uri</code>',
                frontchannelLogout: '<code>frontchannel_logout_uri</code>, ' +
                                    'with <code>frontchannel_logout_session' +
                                    '_required</code>',
                postLogoutRedirect: '<code>post_logout_redirect_uri</code>, ' +
                                    'for a sign-out here that ends at the ' +
                                    'partner'
              };
              return '<tr><td>' + (words[name] || kit.esc(name)) + '</td><td ' +
                'class="who"><code>' + kit.esc(json.signOut[name]) +
                '</code></td></tr>';
            }).join('') +
            ((row.protocol === 'saml11' || row.protocol === 'oauth2')
              ? '<tr><td>Sign-out</td><td><span class="sub">none — ' +
                (row.protocol === 'saml11' ? 'SAML 1.1' : 'OAuth 2.0') +
                ' defines no sign-out, so the partner cannot end a session ' +
                'here and is not told of one ending</span></td></tr>'
              : '') +
            // THE KEY THE PARTNER ENCRYPTS TO (#168): the certificate, or
            // for OpenID Connect the JWKS and the two registration members.
            (json.encryption
              ? '<tr><td>Encryption certificate (<code>' +
                kit.esc(json.encryption.policy.keyType) + '</code>)</td>' +
                '<td class="who">' + (json.encryption.certificatePem
                  ? '<pre>' + kit.esc(json.encryption.certificatePem) +
                    '</pre>'
                  : '<span class="warn">none — rotate the key below to ' +
                    'issue one</span>') + '</td></tr>' +
                (json.endpoints.jwks
                  ? '<tr><td><code>jwks_uri</code> (or its contents as ' +
                    '<code>jwks</code>)</td><td class="who"><code>' +
                    kit.esc(json.endpoints.jwks) + '</code></td></tr>' +
                    '<tr><td><code>id_token_encrypted_response_alg</code> / ' +
                    '<code>_enc</code></td><td><code>' +
                    kit.esc(json.encryption.policy.management) +
                    '</code> / <code>' +
                    kit.esc(json.encryption.policy.content) + '</code></td>' +
                    '</tr>'
                  : '<tr><td>Encryption algorithms</td><td><code>' +
                    kit.esc(json.encryption.policy.content) + '</code> under ' +
                    '<code>' + kit.esc(json.encryption.policy.management) +
                    '</code>, published in the metadata</td></tr>')
              : '') +
            '</table>' +
            (json.encryption ? FederationPage.federationEncryptionSection(row,
                                 json.encryption, carryBack) : '') +
            kit.note('<a class="btn" href="' + kit.esc(login) +
                      '">Start a federated ' +
            'sign-in through this ' +
            'partner</a> ' + (row.usable ? '' : '<span class="sub">— it will ' +
            'refuse until this relationship is enabled and ' +
            'configured</span>')) +
            // THE SAME PARTNER AS A TRANSMITTER (#373).
            FederationPage.federationSignalsSection(row, record, json,
              carryBack)
          : '<h2>What this relationship does</h2>' +
            kit.note('Every protocol endpoint here already issues to anybody ' +
            'that asks, so this relationship changes nothing about whether ' +
              'the ' +
            'partner is answered. What it adds is two things: the partner is ' +
            'marked as a FEDERATION PARTNER rather than a test client, and ' +
            '<code>fedRelease</code> below decides which attributes are ' +
            'released to it.') +
            kit.note('<strong>The release list can only remove, and only ' +
              'from ' +
            'what <a href="/admin/claims">custom claims</a>, <a ' +
            'href="/admin/saml-attributes">custom SAML attributes</a> and ' +
              'the ' +
            'groups claim would add.</strong> It cannot touch ' +
            '<code>sub</code>, <code>iss</code>, <code>exp</code>, a NameID ' +
              'or ' +
            'anything else the protocol puts in an artifact itself — those ' +
              'are ' +
            'what make the artifact verifiable, and a release list that ' +
              'could ' +
            'drop <code>iss</code> would produce tokens that fail to verify ' +
            'with nothing pointing back at this page.') +
            // WHAT THIS SERVICE TELLS THE PARTNER (#373).
            FederationPage.federationOutboundSection(json.outboundSignals)) +
        '<h2>Settings</h2>' +
        '<table><tr><th>Field</th><th>Value</th><th>What it is</th></tr>' +
        fieldRows +
        '</table><h2>Switches</h2><table><tr><th>Field</th><th>Now</th><th>' +
        '</th>' +
        '<th>What it is</th></tr>' + switches +
        '</table>' +
        '<h2>Lists</h2>' + multiSections +
        linkedSection +
        '<h2>Delete</h2>' +
        '<form method="post" action="/admin/federation"><div class="formrow">' +
        carryBack +
        '<input type="hidden" name="action" value="delete">' +
        '<input type="hidden" name="id" value="' + kit.esc(row.id) + '">' +
        '<button type="submit" class="danger">Delete this ' +
          'relationship</button>' +
        '<span class="sub">The entry goes and takes its ' +
          row.authentications +
        ' recorded sign-in(s) with it. The PEOPLE it authenticated keep ' +
          'their ' +
        'entries under <code>ou=users</code> — nothing is ever deleted from ' +
        'there — and any session they hold is unaffected until it expires or ' +
        'is ended.</span></div></form>' +
        kit.note('<strong>Everything on this page is an attribute on one ' +
        'directory entry</strong>, so an <code>ldapmodify</code> of <code>' +
        kit.esc(row.dn) +
        '</code> does exactly what these forms do — two doors onto one ' +
        'register, not two registers. That cuts both ways: ' +
        '<code>fedClientSecret</code> is this service\'s own credential AT ' +
          'the ' +
        'partner, held in the clear, in a directory where every bind ' +
          'succeeds. ' +
        'It is never shown here and never written to the audit log, and ' +
        'anybody who can read this directory can authenticate as this ' +
          'service ' +
        'at that partner. A deployment federating with something real should ' +
        'know that. The Shared Signals credentials, <code>fedSignalsClient' +
        'Secret</code> and <code>fedSignalsBearer</code>, are sealed under ' +
          'the ' +
        'key-encryption key wherever keys persist (#373).') +
        FederationPage.federationCaveat() +
        '<p class="sub"><a href="' +
        kit.esc('/admin/federation' +
                 kit.queryWith(kit.listViewOf('/admin/federation', ctx.query),
                   {})) +
        '">back to the list</a></p>' +
        FederationPage.federationLinks(json.paths.base);
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
   * @returns the section as HTML
   */
  static federationSignalsSection(row, record, view, carryBack) {
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
            (field.sensitive && value ? ' placeholder="set — not shown"'
                                      : '') + '>') +
        '<button type="submit">Set</button></div></form></td><td ' +
        'class="sub">' + kit.note(kit.esc(field.what)) + '</td></tr>';
    };
    const switchRow = function (name, dflt) {
      const field = view.schema.filter(function (f) {
        return f.name === name;
      })[0];
      const on = FederationPage.boolOf(record[name], dflt);
      return '<tr><td><code>' + kit.esc(name) + '</code></td><td class="' +
        (on ? 'ok' : 'off') + '">' + (on ? 'TRUE' : 'FALSE') + '</td><td>' +
        act('set', on ? 'Turn off' : 'Turn on',
            '<input type="hidden" name="field" value="' + kit.esc(name) +
            '"><input type="hidden" name="value" value="' +
            (on ? 'FALSE' : 'TRUE') + '">') + '</td><td class="sub">' +
        kit.esc(field ? field.what : '') + '</td></tr>';
    };
    const events = [].concat(record.fedSignalsEvents || []);
    const eventRows = events.map(function (one) {
      return '<tr><td class="who"><code>' + kit.esc(one) + '</code></td>' +
        '<td>' + act('remove-value', 'Remove',
          '<input type="hidden" name="field" value="fedSignalsEvents">' +
          '<input type="hidden" name="value" value="' + kit.esc(one) +
          '">', true) + '</td></tr>';
    }).join('');
    const streamActs = s.streamId
      ? act('signals-read-stream', 'Read stream') +
        act('signals-update-stream', 'Send fedSignalsEvents') +
        act('signals-verify', 'Verify') +
        (s.streamDelivery === 'poll' ? act('signals-poll-now', 'Poll now')
                                     : '') +
        act('signals-set-status', 'Pause',
            '<input type="hidden" name="status" value="paused">') +
        act('signals-set-status', 'Enable',
            '<input type="hidden" name="status" value="enabled">') +
        act('signals-delete-stream', 'Delete stream', '', true)
      : act('signals-discover', 'Discover') +
        act('signals-create-stream', 'Create stream');
    const blocks = (s.blocks || []).length
      ? '<h3 id="signal-blocks">Sign-ins this partner has blocked</h3>' +
        '<table><tr><th>Person</th><th>Since</th><th>Event</th><th></th>' +
        '</tr>' + s.blocks.map(function (b) {
          return '<tr><td><a href="' + kit.esc('/admin/users?user=' +
            encodeURIComponent(b.username)) + '">' + kit.esc(b.username) +
            '</a></td><td>' + kit.esc(b.at) + '</td><td><code>' +
            kit.esc(b.event) + '</code></td><td>' +
            act('signals-unblock', 'Unblock',
                '<input type="hidden" name="user" value="' +
                kit.esc(b.username) + '">') + '</td></tr>';
        }).join('') + '</table>'
      : '';
    const arrivals = (view.signalArrivals || []).length
      ? '<h3>Latest arrivals</h3><table><tr><th>When</th><th>Events</th>' +
        '<th>Verified</th><th>Person</th><th>Reactions</th></tr>' +
        view.signalArrivals.map(function (r) {
          return '<tr><td>' + kit.esc(r.receivedAt) + ' <span class="sub">' +
            kit.esc(r.via) + '</span></td><td>' + (r.events || [])
              .map(function (e) {
                return '<code>' + kit.esc(String(e).replace(/^.*\//, '')) +
                  '</code>';
              }).join(' ') + '</td><td>' + (r.verified ? 'verified'
              : '<strong>' + kit.esc(r.refusal || 'unverified') +
                '</strong>') + '</td><td>' + kit.esc(r.person || '—') +
            (r.mapping ? '<br><span class="sub">' + kit.esc(r.mapping) +
                         '</span>' : '') + '</td><td>' +
            (r.reactions || []).map(function (x) {
              return kit.esc(x.reaction || '—') + (x.done ? ' ✓' : '') +
                (x.observed ? ' (observed only)' : '') +
                (x.why ? ' <span class="sub">' + kit.esc(x.why) +
                         '</span>' : '');
            }).join('<br>') + '</td></tr>';
        }).join('') + '</table>' +
        kit.note('Every arrival from every partner is on <a href="' +
          '/admin/ssf/transmitters">Monitoring → Shared Signals from ' +
          'partners</a>.')
      : '';
    return '<h2 id="signals">Shared Signals from this partner</h2>' +
      kit.note(row.signsIn
        ? 'The partner\'s CAEP and RISC events about the people it signs ' +
          'in. A verified one is acted on as the <code>signal-response' +
          '</code> policy permits — by default ending the sessions THIS ' +
          'relationship started for the person, and on ' +
          '<code>account-disabled</code> blocking its sign-ins of them until ' +
          'its <code>account-enabled</code>. A local sign-in and every other ' +
          'partner are untouched.'
        : 'This partner signs nobody in: it only sends CAEP and RISC events. ' +
          'By default they are recorded and nothing more, except a ' +
          'device\'s compliance, which is set. Its people are the ones ' +
          'linked to it below (<code>&lt;iss&gt; &lt;sub&gt;</code>, or ' +
          '<code>opaque &lt;id&gt;</code>), or matched by mail where ' +
          '<code>fedSignalEmailMatch</code> is on.') +
      '<table><tr><th>What</th><th>Value</th></tr>' +
      '<tr><td>Receiving</td><td class="' + (s.receiving ? 'ok' : 'off') +
      '">' + (s.receiving ? 'yes'
        : 'no — ' + (s.enabled ? 'fedSignalsEnabled is off'
                               : 'the relationship is disabled')) +
      '</td></tr>' +
      '<tr><td>SSF issuer</td><td class="who"><code>' +
      kit.esc(s.issuer || '(none)') + '</code></td></tr>' +
      '<tr><td>Configuration</td><td>' + (s.config
        ? 'discovered ' + kit.esc(s.discoveredAt) + ' from <code>' +
          kit.esc(s.discoveryUrl) + '</code>'
        : '<span class="sub">not discovered yet</span>') + '</td></tr>' +
      '<tr><td>Stream</td><td>' + (s.streamId
        ? '<code>' + kit.esc(s.streamId) + '</code> (' +
          kit.esc(s.streamDelivery) + ', aud <code>' +
          kit.esc((s.streamAud || []).join(' ')) + '</code>)' +
          (s.verifiedAt ? ' — verified ' + kit.esc(s.verifiedAt) : '')
        : '<span class="sub">none</span>') + '</td></tr>' +
      (s.streamDelivery === 'push' || s.delivery === 'push'
        ? '<tr><td>Push endpoint</td><td class="who"><code>' +
          kit.esc(view.base + s.pushEndpoint) + '</code><span class="sub">' +
          ' given to the partner with the stream</span></td></tr>' : '') +
      '<tr><td>Counts</td><td>' + kit.esc(String(s.counts.received || 0)) +
      ' received, ' + kit.esc(String(s.counts.verified || 0)) +
      ' verified, ' + kit.esc(String(s.counts.refused || 0)) +
      ' refused, ' + kit.esc(String(s.counts.acted || 0)) +
      ' reaction(s)' + (s.lastPollAt ? '; last poll ' +
        kit.esc(s.lastPollAt) + ': ' + kit.esc(s.lastPollResult) : '') +
      '</td></tr>' +
      (s.lastError ? '<tr><td>Last error</td><td class="warn">' +
                     kit.esc(s.lastError) + '</td></tr>' : '') +
      (s.ready ? '' : '<tr><td>Still to set</td><td class="warn">' +
                      kit.esc(s.missing.join(', ')) + '</td></tr>') +
      '</table>' +
      '<p>' + streamActs + '</p>' +
      '<table><tr><th>Field</th><th>Now</th><th></th><th>What it is</th>' +
      '</tr>' + (row.signsIn ? switchRow('fedSignalsEnabled', false) : '') +
      switchRow('fedSignalEmailMatch', false) + '</table>' +
      '<table><tr><th>Field</th><th>Value</th><th>What it is</th></tr>' +
      (view.signalSetFields || []).map(setRow).join('') + '</table>' +
      '<h3><code>fedSignalsEvents</code></h3>' +
      (eventRows ? '<table>' + eventRows + '</table>'
                 : kit.note('None: the stream asks for whatever the ' +
                             'partner supports.')) +
      '<form method="post" action="/admin/federation"><div class="formrow">' +
      carryBack + '<input type="hidden" name="action" value="add-value">' +
      '<input type="hidden" name="id" value="' + kit.esc(row.id) + '">' +
      '<input type="hidden" name="field" value="fedSignalsEvents">' +
      '<input type="text" name="value" size="60" placeholder="an event ' +
      'type URI"><button type="submit">Add</button></div></form>' +
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
   * @returns the section as HTML
   */
  static federationEncryptionSection(row, encryption, carryBack) {
    const rows = encryption.keys.map(function (key) {
      return '<tr><td><code>' + kit.esc(key.kid) + '</code></td><td>' +
        kit.esc(key.keyType) + '</td><td class="' +
        (key.decrypts ? 'ok' : 'off') + '">' + kit.esc(key.state) +
        (key.retiresAt ? ' — decrypts until ' +
          kit.esc(new Date(key.retiresAt).toISOString()) : '') +
        '</td><td>' + kit.esc(key.notAfter || '') + '</td><td>' +
        (key.sealed ? 'sealed' : 'in clear (keys do not persist)') +
        '</td></tr>';
    }).join('');
    return '<h2 id="encryption">Encryption</h2>' +
      kit.note(encryption.required
        ? '<strong>A plaintext assertion is refused.</strong> The partner ' +
          'must encrypt to the key above, with the algorithms above.'
        : (encryption.allowUnencrypted
            ? '<strong class="warn">fedAllowUnencrypted is on: a plaintext ' +
              'assertion is ACCEPTED</strong>, and the person\'s ' +
              'identifier and attributes may cross their browser in clear.'
            : 'A plaintext assertion is accepted in development mode; ' +
              'product mode refuses it. An encrypted one is decrypted and ' +
              'held to the algorithms above in both.')) +
      (rows
        ? '<table><tr><th>kid</th><th>Type</th><th>State</th><th>Expires' +
          '</th><th>At rest</th></tr>' + rows + '</table>'
        : kit.note('No key is held.')) +
      '<form method="post" action="/admin/federation"><div class="formrow">' +
      carryBack +
      '<input type="hidden" name="action" value="rotate-key">' +
      '<input type="hidden" name="id" value="' + kit.esc(row.id) + '">' +
      '<button type="submit">Rotate the encryption key</button>' +
      '<span class="sub">A new key is issued under this realm\'s ' +
      'Intermediate and published at once; the one it replaces still ' +
      'decrypts for ' + kit.esc(String(encryption.graceS)) + ' seconds ' +
      '(federation.encryptionKeyGraceS).</span></div></form>';
  }

  /**
   * Draws what this service SENDS the partner of an identity-provider-side
   * relationship: its application's streams on this service's transmitter.
   *
   * @param outbound - `{ application, streams }`
   * @returns the section as HTML
   */
  static federationOutboundSection(outbound) {
    if (!outbound || !outbound.application) {
      return '';
    }
    return '<h2 id="signals-sent">Shared Signals this service sends the ' +
      'partner</h2>' +
      kit.note('The streams on this service\'s own transmitter that the ' +
        'partner\'s application <code>' + kit.esc(outbound.application) +
        '</code> owns. Read only: a stream belongs to the receiver that ' +
        'created it, and is managed through SSF\'s stream management API.') +
      ((outbound.streams || []).length
        ? '<table><tr><th>Stream</th><th>Delivery</th><th>Status</th>' +
          '<th>Events delivered</th><th>Last activity</th><th>Dead letters' +
          '</th></tr>' + outbound.streams.map(function (one) {
            return '<tr><td><code>' + kit.esc(one.streamId) + '</code>' +
              '</td><td>' + kit.esc(one.delivery) + '</td><td class="' +
              (one.dead ? 'warn' : '') + '">' + kit.esc(one.status) +
              (one.dead ? ' — not delivering' : '') + '</td><td>' +
              (one.eventsDelivered || []).map(function (e) {
                return '<code>' + kit.esc(String(e).replace(/^.*\//, '')) +
                  '</code>';
              }).join(' ') + '</td><td>' +
              kit.esc(one.lastActivityAt || '—') + '</td><td>' +
              kit.esc(String(one.deadLetters)) + '</td></tr>';
          }).join('') + '</table>'
        : kit.note('The partner\'s application holds no stream here.'));
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
   * @returns the section as HTML, or '' when there is nothing to show
   */
  static federationUnmappedSection(row, unmapped, carryBack) {
    if (!unmapped.length) {
      return '';
    }
    return '<h3 id="unmapped">Sent and not written</h3>' +
      kit.note('Names this partner sent at a sign-in that were NOT ' +
        'written to the directory: nothing maps them, or a mapping sends ' +
        'them onto an attribute no partner may write. The newest first; a ' +
        'name is kept for ' + 'as long as minted state is (' +
        '<code>persistence.mintedRetention</code>).') +
      '<table><tr><th>Name</th><th>Why</th><th>Last sent</th><th>Map it' +
      '</th></tr>' +
      unmapped.map(function (one) {
        return '<tr><td class="who"><code>' + kit.esc(one.name) +
          '</code></td><td class="sub">' +
          (one.refused ? kit.esc(one.refused) : 'nothing maps it') +
          '</td><td class="sub">' + kit.esc(one.last) + '</td><td><form ' +
          'method="post" action="/admin/federation"><div class="formrow">' +
          carryBack +
          '<input type="hidden" name="action" value="add-value">' +
          '<input type="hidden" name="id" value="' + kit.esc(row.id) +
          '"><input type="hidden" name="field" value="fedAttributeMap">' +
          '<input type="text" name="value" size="30" value="' +
          kit.esc(one.name + '=') + '"><button type="submit">Map' +
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
}

export = FederationPage;
