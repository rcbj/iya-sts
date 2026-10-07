// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_ldap.ts
//
// ---------------------------------------------------------------------------
// THE DIRECTORY'S PAGES, DRAWN FROM THEIR VIEWS ALONE (#446, 2026-10-05).
//
// Draws the nine `/admin/ldap/*` pages — what the directory is, every entry
// in it, and the applications, federations, SPIFFE entries, devices, roles,
// policies and remote PEPs as the directory holds them — from the answers of
// `GET /admin-api/ldap/*`.
//
// **NO CREDENTIAL IS IN THOSE ANSWERS** (rcbj, 2026-10-05): every attribute
// `ldap_server.js`'s `SECRET_ATTRIBUTES` names — the ones the directory
// already withholds from every LDAP read — is masked in them, and so on
// these pages. A value that can be used is revealed on the page that owns
// it (an application's client secret on the application's page).
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// The views in `ldap/ldap_server.js` draw through it until the console's
// cutover.
// ---------------------------------------------------------------------------

import kit = require('../admin-ui/web_kit');

type Json = any;

/**
 * Draws the directory's console pages from their answers.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class LdapPage {

  /**
   * Draws `/admin/ldap/applications` from its answer.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of `GET /admin-api/ldap/applications`
   * @returns the body as HTML
   */
  static applications(ctx: Json, json: Json): string {
    const wantedText = json.filter.q || '';
    const paging = json.paging;
    const nav = kit.pageNavPair('/admin/ldap/applications',
      { q: wantedText, per: ctx.query.per ? String(paging.perPage) : '' },
      paging);

    const appRows = json.applications.map(function (row) {
      // EVERY attribute, which now includes the operational ones and entryDN. A
      // search would withhold those unless they were asked for by name (RFC
      // 4511 section 4.5.1.8); this is the service showing its own store, so it
      // shows them, and the column heading below says so.
      const attrs = Object.keys(row.attributes).sort().map(function (name) {
        return '<div><code>' + kit.esc(name) + '</code>: ' +
          kit.clippedValues(row.attributes[name]) + '</div>';
      }).join('') +
        // A CREDENTIAL IS MASKED HERE (#446, rcbj 2026-10-05): no answer
        // carries one. What can be used is revealed on the application's own
        // page, and this says where.
        (Object.keys(row.attributes).some(function (name) {
          return [].concat(row.attributes[name]).some(function (one) {
            return one === '(set — not returned)';
          });
        })
          ? '<div class="sub">Credentials are masked. <a href="' +
            kit.esc('/admin/applications?application=' +
                    encodeURIComponent(row.identifier) + '#tab-credentials') +
            '">Reveal one on its page</a>.</div>'
          : '');
      // The DN on every row. This is the page headed "the registry as the
      // directory sees it", and the directory sees an entry by its DN — a row
      // that named only the identifier left the one address an ldapsearch needs
      // to be reconstructed by the reader from a naming rule published nowhere.
      return '<tr><td>' + kit.clipped(row.identifier, 40) +
        (row.dn ? '<div class="sub">' + kit.clipped(row.dn, 40) +
          (row.identifier === row.dnLabel ? '' :
            ' &mdash; the identifier is too long for a readable RDN, so the ' +
            'cn is a digest of it and <code>appIdentifier</code> is the ' +
            'identity') +
          '</div>' : '') +
        '</td><td>' + kit.esc(row.name) + '</td><td>' +
        kit.esc(row.kinds.join(', ') || '(unstated)') + '<div class="sub">' +
        kit.esc(row.protocols.join(', ')) + '</div></td><td>' +
        (row.registered ? '<span class="state-valid">yes</span>'
                        : '<span class="state-none">no</span>') +
        '</td><td class="counts">' + row.authentications + ' auth<br>' +
        row.sessions + ' session(s)<br>' + row.users +
        ' user(s)</td><td class="attrs">' + attrs + '</td></tr>';
    }).join('');
    const classRows = json.schema.objectClasses.map(function (one) {
      return '<tr><td><code>' + kit.esc(one.name) + '</code></td><td>' +
        kit.esc(one.where) + (one.standard ? '' : ' <strong>(invented ' +
                                                    'here)</strong>') +
        '</td><td>' + kit.esc(one.what) + '</td></tr>';
    }).join('');
    const attrRows = json.schema.attributes.map(function (row) {
      return '<tr><td><code>' + kit.esc(row.name) + '</code>' +
        (row.sensitive ? ' <strong>(credential)</strong>' : '') +
        '</td><td>' + kit.esc(row.kind) + '</td><td>' + kit.esc(row.from) +
        '</td><td>' + kit.esc(row.what) + '</td></tr>';
    }).join('');
    const kindRows = json.kinds.map(function (one) {
      return '<tr><td><code>' + kit.esc(one.kind) + '</code></td><td>' +
        kit.esc(one.label) + '</td><td>' + kit.esc(one.what) + '</td></tr>';
    }).join('');

    const inner = '<p class="sub">' + json.count + ' of a maximum ' +
      json.max + ' under <code>' + kit.esc(json.container) +
      '</code>: every OAuth client, OpenID Connect relying party, SAML ' +
      'service provider, WS-Federation application, WS-Trust relying party, ' +
      'OpenID4VP verifier and Kerberos service this instance has been asked ' +
      'about. One entry per unique identifier, so an application that speaks ' +
      'two protocols under one name is one row with two kinds rather than ' +
      'two rows.</p><div class="tiles">' +
      kit.tile(json.count, 'Application entries') +
      kit.tile(json.matched, 'Matching the filter') +
      kit.tile(json.max, 'Maximum held') +
      '</div>' +
      kit.note('<strong>These entries are the registry, not a copy of ' +
      'one.</strong> An <code>ldapmodify</code> here changes what the ' +
      'protocol endpoints do: add a value to <code>oauthRedirectUri</code> ' +
      'and RFC 9700 mode accepts that redirect URI by exact match on the ' +
      'next authorization request. Nothing caches them. To EDIT one, <a ' +
      'href="/admin/applications">Applications</a> is the page with the ' +
      'controls on it; this one is the dump.') +
      '<form method="get" action="/admin/ldap/applications"><div ' +
      'class="formrow"><label for="q">Anywhere in the entry</label><input ' +
      'type="text" id="q" name="q" value="' + kit.esc(wantedText) +
      '" size="30" placeholder="an identifier, a name, a DN or any value">' +
      '<label for="per">Show</label>' +
      '<select id="per" name="per">' +
      kit.perPageOptions(paging.perPage) + '</select>' +
      '<button type="submit">Filter</button>' +
      (wantedText ? ' <a href="/admin/ldap/applications">clear</a>' : '') +
      '</div></form>' +
      nav.head +
      '<table><tr><th>Identifier</th><th>Name</th><th>Kind</th>' +
      '<th>Registered</th><th>Seen</th><th>Every ' +
      'attribute</th></tr>' +
      (appRows || '<tr><td colspan="6">' +
        (wantedText
          ? 'No application matches. The filter above may be hiding some.'
          : 'Nothing yet. An entry appears the first time a client_id, ' +
            'wtrealm, AppliesTo, entityID or service principal name is ' +
            'accepted.') +
        '</td></tr>') +
      '</table>' +
      nav.foot +
      '<h2>What an application can be</h2>' +
      '<table><tr><th>Kind</th><th>Label</th><th>What it means</th></tr>' +
      kindRows + '</table>' +
      '<h2>The object classes</h2>' +
      kit.note('node-ldapjs has no schema subsystem &mdash; it is protocol ' +
      'machinery, and it is a submodule this repository does not modify ' +
      '&mdash; and this directory is schemaless on purpose. So this is a ' +
      'VOCABULARY rather than a constraint: nothing rejects an entry for ' +
      'disobeying it. Where a registered class fits, it is used.') +
      '<table><tr><th>Class</th><th>Where from</th><th>What it ' +
      'brings</th></tr>' +
      classRows + '</table>' +
      '<h2>The attributes</h2>' +
      kit.note('<code>multi</code> accumulates a repeat, <code>single</code> ' +
      'is assigned &mdash; which is what stops a counter growing a value per ' +
      'sign-in. Two attributes hold CREDENTIALS in the clear, for the reason ' +
      '<code>/krb5/principals</code> prints the Kerberos passwords; they are ' +
      'never written to the audit log.') +
      '<table><tr><th>Attribute</th><th>Values</th><th>Set by</th>' +
      '<th>What it is</th></tr>' + attrRows + '</table>' +
      '<p class="sub"><a href="/admin/ldap/applications?format=json">This ' +
      'page as JSON</a> &middot; <a href="/admin/applications">the same ' +
      'registry with the controls on it</a> &middot; <a ' +
      'href="/admin/ldap/directory">every entry in the directory</a> ' +
      '&middot; <a href="/admin/ldap/service">what this directory is</a></p>';
    return inner;
  }

  /**
   * Draws `/admin/ldap/federations` from its answer.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of `GET /admin-api/ldap/federations`
   * @returns the body as HTML
   */
  static federations(ctx: Json, json: Json): string {
    const wantedText = json.filter.q || '';
    const paging = json.paging;
    const nav = kit.pageNavPair('/admin/ldap/federations',
      { q: wantedText, per: ctx.query.per ? String(paging.perPage) : '' },
      paging);

    const relRows = json.relationships.map(function (row) {
      const attrs = Object.keys(row.entryAttributes).sort()
        .map(function (name) {
        return '<div><code>' + kit.esc(name) + '</code>: ' +
          kit.clippedValues(row.entryAttributes[name]) + '</div>';
      }).join('');
      const readiness = { ready: row.ready, missing: row.missing };
      return '<tr><td>' + kit.clipped(row.fedId, 40) +
        '<div class="sub">' + kit.clipped(row.dn, 40) + '</div></td>' +
        '<td>' +
        kit.esc(row.roleShort) +
        '<div class="sub">' +
        kit.esc(row.protocolLabel) +
        '</div></td>' +
        '<td>' + (row.enabled
          ? (readiness.ready
              ? '<span class="state-valid">enabled and ready</span>'
              : '<span class="state-expired">ENABLED, not configured</span>' +
                '<div class="sub">' +
                kit.esc(readiness.missing.join(', ')) + '</div>')
          : '<span class="state-none">disabled</span>') + '</td>' +
        '<td>' + kit.esc(row.fedAuthentications || '0') + ' sign-in(s)<br>' +
        kit.esc(row.fedUsers || '0') + ' person/people</td>' +
        '<td class="attrs">' + attrs + '</td></tr>';
    }).join('');
    const classRows = json.schema.objectClasses.map(function (one) {
      return '<tr><td><code>' + kit.esc(one.name) + '</code></td><td>' +
        kit.esc(one.where) + (one.standard ? '' : ' <strong>(invented ' +
                                                    'here)</strong>') +
        '</td><td>' + kit.esc(one.what) + '</td></tr>';
    }).join('');
    const attrRows = json.schema.attributes.map(function (row) {
      return '<tr><td><code>' + kit.esc(row.name) + '</code>' +
        (row.sensitive ? ' <strong>(credential)</strong>' : '') +
        '</td><td>' + kit.esc(row.kind) + '</td><td>' + kit.esc(row.role) +
        '</td><td>' + kit.esc(row.what) + '</td></tr>';
    }).join('');

    const inner = '<p class="sub">' + json.count + ' of a maximum ' +
      json.max + ' under <code>' + kit.esc(json.container) +
      '</code>: the foreign identity providers this service consumes ' +
      'assertions from, and the foreign service providers it asserts to. One ' +
      'relationship is one DIRECTION, so a partner in both is two ' +
      'entries.</p><div class="tiles">' +
      kit.tile(json.count, 'Relationships') +
      kit.tile(json.enabledCount,
                 'Enabled') +
      kit.tile(json.max, 'Maximum held') +
      '</div>' +
      kit.warn('<strong>An ldapmodify here is a security change, which is ' +
      'not true of any other container in this directory.</strong> ' +
      '<code>fedSigningCertificate</code> decides whose assertions this ' +
      'service will believe; <code>fedEnabled</code> turns a partner on. ' +
      'Everywhere else here an edit changes what this service hands out, and ' +
      'every bind to this directory succeeds &mdash; so this container is ' +
      'exactly as protected as the rest of it, which is to say not at all. ' +
      'That is the honest state of a mock, and it is why federation is the ' +
      'one ' +
      'feature here that refuses by default.') +
      '<form method="get" action="/admin/ldap/federations"><div ' +
      'class="formrow"><label for="q">Relationship</label><input type="text" ' +
      'id="q" name="q" value="' + kit.esc(wantedText) +
      '" size="30" placeholder="an id, a DN, a protocol or a direction">' +
      '<label for="per">Show</label>' +
      '<select id="per" name="per">' +
      kit.perPageOptions(paging.perPage) + '</select>' +
      '<button type="submit">Filter</button>' +
      (wantedText ? ' <a href="/admin/ldap/federations">clear</a>' : '') +
      '</div></form>' +
      nav.head +
      '<table><tr><th>Relationship</th><th>Direction</th><th>State</th>' +
      '<th>Seen</th><th>Every ' +
      'attribute</th></tr>' +
      (relRows || '<tr><td colspan="5">' +
        (wantedText
          ? 'No relationship matches. The filter above may be hiding some.'
          : 'Nothing yet, and nothing will appear by itself: unlike every ' +
            'other container here, this one is CONFIGURED. Add a ' +
            'relationship on <a ' +
            'href="/admin/federation">/admin/federation</a> or through ' +
            '<code>POST /admin-api/federation/create</code>.') +
        '</td></tr>') +
      '</table>' +
      nav.foot +
      '<h2>The two directions</h2>' +
      '<table><tr><th>Role</th><th>What it means</th></tr>' +
      json.roles.map(function (one) {
        return '<tr><td>' + kit.esc(one.short) + '</td><td>' +
          kit.esc(one.what) +
          '</td></tr>';
      }).join('') + '</table>' +
      '<h2>The five protocols</h2>' +
      '<table><tr><th>Protocol</th><th>What happens</th><th>Needs</th></tr>' +
      json.protocols.map(function (one) {
        return '<tr><td>' + kit.esc(one.label) + '</td><td>' +
          kit.esc(one.what) +
          '</td><td><code>' + kit.esc(one.needs.join(
              ', ')) + '</code></td></tr>';
      }).join('') + '</table>' +
      '<h2>The object classes</h2><table><tr><th>Class</th><th>Where ' +
      'from</th><th>What it brings</th></tr>' +
      classRows + '</table>' +
      '<h2>The attributes</h2>' +
      kit.note('<code>multi</code> accumulates a repeat, <code>single</code> ' +
      'is assigned. The <code>role</code> column says which direction an ' +
      'attribute is for; one belonging to the other direction is refused by ' +
      'the console and by the management API, and an <code>ldapmodify</code> ' +
      'can still write it, where it will be ignored. ' +
      '<code>fedClientSecret</code> is THIS SERVICE\'S OWN CREDENTIAL AT THE ' +
      'PARTNER &mdash; a real secret at a real foreign service, which is a ' +
      'stronger statement than anything else in this directory &mdash; and ' +
      'it is here in the clear for the reason <code>/krb5/principals</code> ' +
      'prints the Kerberos passwords. It is never written to the audit log ' +
      'and ' +
      'never shown in the console.') +
      '<table><tr><th>Attribute</th><th>Values</th><th>Direction</th>' +
      '<th>What it is</th></tr>' + attrRows + '</table>' +
      '<p class="sub"><a href="/admin/ldap/federations?format=json">This ' +
      'page as JSON</a> &middot; <a href="/admin/federation">configure them ' +
      'in the console</a> &middot; <a href="/federation">what federation is ' +
      'here</a> ' +
      '&middot; <a href="/admin/ldap/service">what this directory is</a></p>';
    return inner;
  }

  /**
   * Draws `/admin/ldap/spiffe` from its answer.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of `GET /admin-api/ldap/spiffe`
   * @returns the body as HTML
   */
  static spiffe(ctx: Json, json: Json): string {
    const carried = { entryq: json.filter.entryq || '',
                      agentq: json.filter.agentq || '',
                      entriesPage: ctx.query.entriesPage || '',
                      agentsPage: ctx.query.agentsPage || '',
                      per: ctx.query.per ? String(json.entriesPaging.perPage)
                                         : '' };
    const entriesNav = kit.pageNavPair('/admin/ldap/spiffe', carried,
                                       json.entriesPaging);
    const agentsNav = kit.pageNavPair('/admin/ldap/spiffe', carried,
                                      json.agentsPaging);

    const classRows = json.schema.objectClasses.map(function (one) {
      return '<tr><td><code>' + kit.esc(one.name) + '</code></td><td>' +
        kit.esc(one.where) + (one.standard ? '' : ' <strong>(invented ' +
                                                    'here)</strong>') +
        '</td><td>' + kit.esc(one.what) + '</td></tr>';
    }).join('');
    const attrRows = json.schema.attributes.map(function (row) {
      return '<tr><td><code>' + kit.esc(row.name) + '</code></td><td>' +
        kit.esc(row.kind) + '</td><td>' +
        (row.editable ? 'yes' : 'no') + '</td><td>' + kit.esc(row.from) +
        '</td><td>' + kit.esc(row.what) + '</td></tr>';
    }).join('');
    const entryRows = json.registrationEntries.map(function (row) {
      return '<tr><td>' + kit.clipped(row.spiffeId, 52) +
        '<div class="sub">' + kit.clipped(row.dn, 52) + '</div></td><td>' +
        kit.clipped(row.selectorTexts.join(', ') ||
                      '(none — matches every workload)', 60) +
        '</td><td>' + kit.esc(row.origin) + '</td><td class="num">' +
        row.svidsIssued + '</td></tr>';
    }).join('');
    const agentRows = json.attestedAgents.map(function (row) {
      return '<tr><td>' + kit.clipped(row.id, 52) +
        '<div class="sub">' + kit.clipped(row.dn, 52) + '</div></td><td>' +
        kit.esc(row.attestationType) + '</td><td>' +
        (row.banned ? '<span class="state-revoked">banned</span>'
                    : '<span class="state-valid">active</span>') +
        '</td><td class="num">' + row.attestations + '</td></tr>';
    }).join('');

    const inner = '<p class="sub">Registration entries live under <code>' +
      kit.esc(json.entriesContainer) + '</code> and attested agents under ' +
      '<code>' + kit.esc(json.agentsContainer) + '</code>. ' +
      '<a href="/spiffe">What SPIFFE is here</a> &middot; ' +
      '<a href="/admin/spiffe">the console page for it</a>.</p>' +
      '<div class="tiles">' +
      kit.tile(json.entries, 'Registration entries') +
      kit.tile(json.maxEntries, 'Maximum entries') +
      kit.tile(json.agents, 'Attested agents') +
      kit.tile(json.maxAgents, 'Maximum agents') +
      '</div>' +
      kit.note(kit.esc(json.sourceOfTruth)) +
      '<form method="get" action="/admin/ldap/spiffe"><div class="formrow">' +
      '<input type="hidden" name="entryq" value="' + kit.esc(carried.entryq) +
      '"><input type="hidden" name="agentq" ' +
      'value="' + kit.esc(carried.agentq) + '"><label ' +
      'for="per">Rows per table</label><select id="per" name="per">' +
      kit.perPageOptions(json.entriesPaging.perPage) + '</select>' +
      '<button class="secondary" type="submit">Apply</button></div></form>' +
      kit.note('Both tables below are paged separately and they share this ' +
      'size. Changing it starts each of them at its first page.') +
      '<h2>Registration entries</h2>' +
      '<form method="get" action="/admin/ldap/spiffe"><div class="formrow">' +
      '<input type="hidden" name="agentq" value="' + kit.esc(carried.agentq) +
      '"><input ' +
      'type="hidden" name="per" value="' + kit.esc(carried.per) + '">' +
      '<label for="entryq">SPIFFE ID or DN</label>' +
      '<input type="text" id="entryq" name="entryq" size="30" value="' +
      kit.esc(carried.entryq) + '" placeholder="spiffe://…, or part of a DN">' +
      '<button type="submit">Search</button>' +
      (carried.entryq ? ' <a href="/admin/ldap/spiffe">clear</a>' : '') +
      '</div></form>' +
      entriesNav.head +
      '<table><tr><th>SPIFFE ID / DN</th><th>Selectors</th><th>Origin</th>' +
      '<th class="num">SVIDs</th></tr>' +
      (entryRows || '<tr><td colspan="4">None.</td></tr>') + '</table>' +
      entriesNav.foot +
      '<h2>Attested agents</h2>' +
      '<form method="get" action="/admin/ldap/spiffe"><div class="formrow">' +
      '<input type="hidden" name="entryq" value="' + kit.esc(carried.entryq) +
      '"><input ' +
      'type="hidden" name="per" value="' + kit.esc(carried.per) + '">' +
      '<label for="agentq">Agent or DN</label>' +
      '<input type="text" id="agentq" name="agentq" size="30" value="' +
      kit.esc(carried.agentq) + '" placeholder="an agent SPIFFE ID, or part ' +
      'of a DN"><button type="submit">Search</button>' +
      (carried.agentq ? ' <a href="/admin/ldap/spiffe">clear</a>' : '') +
      '</div></form>' +
      agentsNav.head +
      '<table><tr><th>Agent / DN</th><th>Attestor</th><th>State</th>' +
      '<th class="num">Attestations</th></tr>' +
      (agentRows ||
       '<tr><td colspan="4">None. Nothing has attested here.</td></tr>') +
      '</table>' +
      agentsNav.foot +
      '<h2>Object classes</h2><table><tr><th>Class</th><th>Where from</th>' +
      '<th>What</th></tr>' + classRows + '</table>' +
      '<h2>Attributes</h2>' +
      kit.note('Declared is what an entry may DO and is editable from the ' +
      'console; derived is what HAPPENED and is not. <code>ldapmodify</code> ' +
      'reaches everything either way &mdash; refusing it in the console is ' +
      'the difference between offering an operation and merely not ' +
      'preventing ' +
      'it.') +
      '<table><tr><th>Attribute</th><th>Values</th><th>Editable</th>' +
      '<th>Written by</th><th>What</th></tr>' + attrRows + '</table>' +
      '<p class="sub"><a href="/admin/ldap/spiffe?format=json">This page as ' +
      'JSON</a> &middot; <a href="/admin/spiffe/entries">the entries as the ' +
      'console edits them</a> &middot; <a href="/admin/ldap/directory">every ' +
      'entry in the directory</a> &middot; <a ' +
      'href="/admin/ldap/service">what ' +
      'this directory is</a></p>';
    return inner;
  }

  /**
   * Draws `/admin/ldap/devices` from its answer.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of `GET /admin-api/ldap/devices`
   * @returns the body as HTML
   */
  static devices(ctx: Json, json: Json): string {
    const wantedText = json.filter.q || '';
    const paging = json.paging;
    const nav = kit.pageNavPair('/admin/ldap/devices',
      { q: wantedText, per: ctx.query.per ? String(paging.perPage) : '' },
      paging);
    const rows = json.entries.map(function (entry) {
      const a = entry.attributes;
      const attrs = Object.keys(a).map(function (name) {
        return '<div><code>' + kit.esc(name) + '</code>: ' +
          kit.clippedValues(a[name]) + '</div>';
      }).join('');
      const id = String((a.cn || [])[0] || '');
      return '<tr><td><a href="/admin/devices?device=' +
        encodeURIComponent(id) + '">' + kit.clipped(id, 40) + '</a>' +
        '<div class="sub">' + kit.clipped(entry.dn, 40) + '</div></td>' +
        '<td>' + kit.esc(String((a.stsDeviceOwnerKind || ['person'])[0])) +
        '<div class="sub">' + kit.clipped(String((a.owner || [''])[0]), 40) +
        '</div></td><td class="attrs">' + attrs + '</td></tr>';
    }).join('');
    const classRows = json.schema.objectClasses.map(function (one) {
      return '<tr><td><code>' + kit.esc(one.name) + '</code></td><td>' +
        kit.esc(one.where) + (one.standard ? '' : ' <strong>(invented ' +
                                                    'here)</strong>') +
        '</td><td>' + kit.esc(one.what) + '</td></tr>';
    }).join('');
    const attrRows = json.schema.attributes.map(function (row) {
      return '<tr><td><code>' + kit.esc(row.name) + '</code>' +
        (row.sensitive ? ' <strong>(withheld)</strong>' : '') + '</td><td>' +
        kit.esc(row.kind) + '</td><td>' + kit.esc(row.what) + '</td></tr>';
    }).join('');
    const inner = '<p class="sub">' + json.count + ' under <code>' +
      kit.esc(json.container) +
        '</code>: every device this realm knows, each ' +
      'owned by one person or one application. The same register ' +
      '<a href="/admin/devices">Devices</a> lists and edits.</p>' +
      '<div class="tiles">' + kit.tile(json.count, 'Device entries') +
      '</div>' +
      kit.note('These entries ARE the register: nothing caches them, so an ' +
      '<code>ldapmodify</code> here is what the next read sees. One value is ' +
      'withheld on this page as from every LDAP read: ' +
      '<code>stsDeviceSecretHash</code>, the verifier of a Native SSO ' +
      'device_secret. A key\'s JSON is public material and is shown whole.') +
      '<form method="get" action="/admin/ldap/devices"><div class="formrow">' +
      '<label for="q">Device</label><input type="text" id="q" name="q" ' +
      'value="' + kit.esc(wantedText) + '" size="30" placeholder="an id, a ' +
      'DN, an owner or any value">' +
      '<label for="per">Show</label><select id="per" name="per">' +
      kit.perPageOptions(paging.perPage) + '</select>' +
      '<button type="submit">Filter</button>' +
      (wantedText ? ' <a href="/admin/ldap/devices">clear</a>' : '') +
      '</div></form>' + nav.head +
      '<table><tr><th>Device</th><th>Owner</th><th>Every attribute</th></tr>' +
      (rows || '<tr><td colspan="3">' + (wantedText
        ? 'No device matches. The filter above may be hiding some.'
        : 'None yet. A Native SSO sign-in makes one, and an administrator ' +
          'can register one on <a href="/admin/devices">Devices</a>.') +
        '</td></tr>') + '</table>' + nav.foot +
      '<h2>The object classes</h2><table><tr><th>Class</th><th>Where ' +
      'from</th><th>What it brings</th></tr>' +
      classRows + '</table>' +
      '<h2>The attributes</h2>' +
      kit.note('<code>multi</code> holds several values; <code>single</code> ' +
      'one. Several hold ONE JSON VALUE each: a key, the last compliance and ' +
      'status change, and the enrolment. <code>common/devices.ts</code> ' +
      'argues the layout.') +
      '<table><tr><th>Attribute</th><th>Values</th><th>What it is</th></tr>' +
      attrRows + '</table>' +
      '<p class="sub"><a href="/admin/ldap/devices?format=json">This page as ' +
      'JSON</a> &middot; <a href="/admin/devices">the register in the ' +
      'console</a> &middot; <a href="/admin/ldap/directory">every entry in ' +
      'the directory</a> &middot; <a href="/admin/ldap/service">what this ' +
      'directory is</a></p>';
    return inner;
  }

  /**
   * Draws `/admin/ldap/roles` from its answer.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of `GET /admin-api/ldap/roles`
   * @returns the body as HTML
   */
  static roles(ctx: Json, json: Json): string {
    const wantedText = json.filter.q || '';
    const paging = json.paging;
    const nav = kit.pageNavPair('/admin/ldap/roles',
      { q: wantedText, per: ctx.query.per ? String(paging.perPage) : '' },
      paging);

    const roleRows = json.roles.map(function (row) {
      const attrs = Object.keys(row.attributes).sort().map(function (name) {
        return '<div><code>' + kit.esc(name) + '</code>: ' +
          kit.clippedValues(row.attributes[name]) + '</div>';
      }).join('');
      const held = function (name) {
        const value = row.attributes[name];
        if (!value) {
          return 0;
        }
        return Array.isArray(value) ? value.length : 1;
      };
      return '<tr><td>' + kit.clipped(row.name, 40) +
        (row.dn ? '<div class="sub">' + kit.clipped(row.dn, 40) + '</div>' :
         '') +
        '</td><td class="counts">' + held('roleMemberUser') + ' user(s)<br>' +
        held('roleMemberGroup') + ' group(s)<br>' +
        held('roleMemberApplication') + ' application(s)</td>' +
        '<td class="attrs">' + attrs + '</td></tr>';
    }).join('');
    const classRows = json.schema.objectClasses.map(function (one) {
      return '<tr><td><code>' + kit.esc(one.name) + '</code></td><td>' +
        kit.esc(one.what) + '</td></tr>';
    }).join('');
    const attrRows = json.schema.attributes.map(function (row) {
      return '<tr><td><code>' + kit.esc(row.name) + '</code></td><td>' +
        kit.esc(row.what) + '</td></tr>';
    }).join('');
    const builtInRows = json.builtInCatalogue.map(function (one) {
      return '<tr><td><code>' + kit.esc(one.name) + '</code></td><td>' +
        kit.esc(one.what) +
        '</td></tr>';
    }).join('');

    const inner = '<p class="sub">' + json.count + ' of a maximum ' +
      json.max + ' under <code>' + kit.esc(json.container) +
      '</code>: one entry per role, and everything on it is MEMBERSHIP — who ' +
      'holds it. A person, a group and an application are all first-class ' +
      'members, which is what lets a client_credentials grant with no person ' +
      'in it be decided at all.</p><div class="tiles">' +
      kit.tile(json.count, 'Role entries') +
      kit.tile(json.builtIn.length, 'Built in, in no container') +
      kit.tile(json.max, 'Maximum held') +
      '</div>' +
      kit.note('<strong>Half the feature is not in this container.</strong> ' +
      'A role has two relations and they live apart on purpose: MEMBERSHIP ' +
      'is here, and the REQUIREMENT — which roles an application demands ' +
      'before anything is issued for it — is <code>appRequiredRole</code> on ' +
      'the application\'s own entry under <code>ou=applications</code>. So ' +
      'nothing in this container refuses anybody by itself, and a reader ' +
      'looking here for the reason somebody was turned away is one container ' +
      'across from it. <a href="/admin/roles">Roles</a> is the page with ' +
      'both halves and the controls on it; <a ' +
      'href="/admin/ldap/applications">Application ' +
      'entries</a> is where the other half is stored.') +
      '<form method="get" action="/admin/ldap/roles"><div class="formrow">' +
      '<label for="q">Anywhere in the entry</label>' +
      '<input type="text" id="q" name="q" value="' + kit.esc(wantedText) +
      '" size="30" placeholder="a role name, a DN, or a member">' +
      '<label for="per">Show</label>' +
      '<select id="per" name="per">' +
      kit.perPageOptions(paging.perPage) + '</select>' +
      '<button type="submit">Filter</button>' +
      (wantedText ? ' <a href="/admin/ldap/roles">clear</a>' : '') +
      '</div></form>' +
      nav.head +
      '<table><tr><th>Role</th><th>Who holds it</th>' +
      '<th>Every attribute</th></tr>' +
      (roleRows || '<tr><td colspan="3">' +
        (wantedText
          ? 'No role matches. The filter above may be hiding some.'
          : 'Nothing yet, which is the ORDINARY state rather than an empty ' +
            'one: an application that names no required role requires ' +
            'EVERYBODY, everybody holds EVERYBODY, and nothing is refused. ' +
            'A role is made on the Roles page or through POST ' +
            '/admin-api/roles/create-role.') +
        '</td></tr>') +
      '</table>' +
      nav.foot +
      '<h2>The six that are in no container</h2>' +
      kit.note('These are COMPUTED from the context of the decision being ' +
      'made rather than stored, so they have no entry here, no members to ' +
      'list, and cannot be created, edited or deleted. They are the reason ' +
      'an empty container above is not the feature being switched off: ' +
      '<code>EVERYBODY</code> is what an application requires when its entry ' +
      'names nothing, and everybody holds it.') +
      '<table><tr><th>Role</th><th>Who holds it</th></tr>' +
      builtInRows + '</table>' +
      '<h2>The object classes</h2>' +
      kit.note('node-ldapjs has no schema subsystem and this directory is ' +
      'schemaless on purpose, so this is a VOCABULARY rather than a ' +
      'constraint: nothing rejects an entry for disobeying it.') +
      '<table><tr><th>Class</th><th>What it brings</th></tr>' +
      classRows + '</table>' +
      '<h2>The attributes</h2>' +
      '<table><tr><th>Attribute</th><th>What it is</th></tr>' + attrRows +
      '</table><p class="sub"><a href="/admin/ldap/roles?format=json">This ' +
      'page as JSON</a> &middot; <a href="/admin/roles">the same register ' +
      'with the controls on it</a> &middot; <a ' +
      'href="/admin/ldap/directory">every entry in the directory</a> ' +
      '&middot; <a href="/admin/ldap/service">what this ' +
      'directory is</a></p>';
    return inner;
  }

  /**
   * Draws `/admin/ldap/policies` from its answer.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of `GET /admin-api/ldap/policies`
   * @returns the body as HTML
   */
  static policies(ctx: Json, json: Json): string {
    const wantedText = json.filter.q || '';
    const paging = json.paging;
    const nav = kit.pageNavPair('/admin/ldap/policies',
      { q: wantedText, per: ctx.query.per ? String(paging.perPage) : '' },
      paging);
    const first = function (row, name) {
      const value = (row.attributes || {})[name];
      if (!value) {
        return '';
      }
      return String(Array.isArray(value) ? value[0] : value);
    };

    const policyRows = json.policies.map(function (row) {
      const attrs = Object.keys(row.attributes).sort().map(function (name) {
        return '<div><code>' + kit.esc(name) + '</code>: ' +
          kit.clippedValues(row.attributes[name]) + '</div>';
      }).join('');
      // 'FALSE' AND 'TRUE', not 'false' and 'true'. RFC 4517's Boolean syntax
      // is upper case and `xacml_store.js` writes it that way, so this reads it
      // the way that module reads it — `at('xacmlEnabled') !== 'FALSE'` —
      // rather than inventing a third spelling. The lower-case comparison this
      // replaced drew every DISABLED policy as enabled, which is the direction
      // that matters: a page that overstates what is switched on.
      const enabled = first(row, 'xacmlEnabled') !== 'FALSE';
      const isRoot = first(row, 'xacmlIsRoot') === 'TRUE';
      return '<tr><td>' + kit.clipped(row.name, 40) +
        (row.dn ? '<div class="sub">' + kit.clipped(row.dn, 40) + '</div>' :
         '') +
        '</td><td>' + kit.esc(first(row, 'xacmlKind') || '(unstated)') +
        '<div class="sub">' + kit.clipped(first(row, 'xacmlPolicyId'), 40) +
        '</div></td><td>' +
        (enabled ? '<span class="state-valid">enabled</span>'
                 : '<span class="state-none">disabled</span>') +
        (isRoot ? '<div class="sub">the root</div>' : '') +
        '</td><td class="attrs">' + attrs + '</td></tr>';
    }).join('');
    const classRows = json.schema.objectClasses.map(function (one) {
      return '<tr><td><code>' + kit.esc(one.name) + '</code></td><td>' +
        kit.esc(one.what) + '</td></tr>';
    }).join('');
    const attrRows = json.schema.attributes.map(function (row) {
      return '<tr><td><code>' + kit.esc(row.name) + '</code></td><td>' +
        kit.esc(row.what) + '</td></tr>';
    }).join('');

    const inner = '<p class="sub">' + json.count + ' of a maximum ' +
      json.max + ' under <code>' + kit.esc(json.container) +
      '</code>: one entry per policy or policy set, holding the XACML ' +
      'document itself. Exactly one of them is the ROOT — a PDP evaluates ' +
      'one document and reaches the rest through PolicyIdReference.</p><div ' +
      'class="tiles">' +
      kit.tile(json.count, 'Policy entries') +
      kit.tile(json.enabledCount, 'Enabled') +
      kit.tile(json.max, 'Maximum held') +
      '</div>' +
      kit.warn('<strong>A write here skips the typechecker, which is not ' +
      'true of any other door into this repository.</strong> Every write ' +
      'through <a href="/admin/xacml">XACML</a> and ' +
      '<code>/admin-api/xacml</code> parses the document and statically ' +
      'typechecks it, so a policy that does not typecheck is refused at ' +
      'WRITE time instead of going Indeterminate on every request. An ' +
      '<code>ldapmodify</code> of <code>xacmlPolicyDocument</code> reaches ' +
      'the entry directly and skips that, and nothing caches these entries — ' +
      'so ' +
      'the next request is decided against whatever was written.') +
      '<form method="get" action="/admin/ldap/policies"><div class="formrow">' +
      '<label for="q">Anywhere in the entry</label>' +
      '<input type="text" id="q" name="q" value="' + kit.esc(wantedText) +
      '" size="30" placeholder="a name, a DN, a PolicyId or anything in the ' +
      'document"><label for="per">Show</label><select id="per" name="per">' +
      kit.perPageOptions(paging.perPage) + '</select>' +
      '<button type="submit">Filter</button>' +
      (wantedText ? ' <a href="/admin/ldap/policies">clear</a>' : '') +
      '</div></form>' +
      nav.head +
      '<table><tr><th>Policy</th><th>Kind</th><th>State</th><th>Every ' +
      'attribute</th></tr>' +
      (policyRows || '<tr><td colspan="4">' +
        (wantedText
          ? 'No policy matches. The filter above may be hiding some.'
          : 'Nothing yet. A repository with no policies in it answers ' +
            'NotApplicable to every request, which a PEP turns into a ' +
            'refusal ' +
            'or an allow according to its bias.') +
        '</td></tr>') +
      '</table>' +
      nav.foot +
      '<h2>The object classes</h2>' +
      kit.note('node-ldapjs has no schema subsystem and this directory is ' +
      'schemaless on purpose, so this is a VOCABULARY rather than a ' +
      'constraint: nothing rejects an entry for disobeying it.') +
      '<table><tr><th>Class</th><th>What it brings</th></tr>' +
      classRows + '</table>' +
      '<h2>The attributes</h2>' +
      '<table><tr><th>Attribute</th><th>What it is</th></tr>' + attrRows +
      '</table><p class="sub"><a ' +
      'href="/admin/ldap/policies?format=json">This page as JSON</a> ' +
      '&middot; <a href="/admin/xacml">the same repository with the controls ' +
      'on it</a> &middot; <a href="/admin/ldap/peps">the PEPs that pull ' +
      'it</a> &middot; <a href="/admin/ldap/directory">every entry in the ' +
      'directory</a></p>';
    return inner;
  }

  /**
   * Draws `/admin/ldap/peps` from its answer.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of `GET /admin-api/ldap/peps`
   * @returns the body as HTML
   */
  static peps(ctx: Json, json: Json): string {
    const wantedText = json.filter.q || '';
    const paging = json.paging;
    const nav = kit.pageNavPair('/admin/ldap/peps',
      { q: wantedText, per: ctx.query.per ? String(paging.perPage) : '' },
      paging);
    const first = function (row, name) {
      const value = (row.attributes || {})[name];
      if (!value) {
        return '';
      }
      return String(Array.isArray(value) ? value[0] : value);
    };

    const pepRows = json.peps.map(function (row) {
      const attrs = Object.keys(row.attributes).sort().map(function (name) {
        return '<div><code>' + kit.esc(name) + '</code>: ' +
          kit.clippedValues(row.attributes[name]) + '</div>';
      }).join('');
      // 'FALSE', for the reason the policies page above states.
      const enabled = first(row, 'xacmlPepEnabled') !== 'FALSE';
      return '<tr><td>' + kit.clipped(row.name, 40) +
        (row.dn ? '<div class="sub">' + kit.clipped(row.dn, 40) + '</div>' :
         '') +
        '</td><td>' + kit.clipped(first(row, 'xacmlPepCertificateSubject') ||
          '(no client certificate)', 40) +
        '<div class="sub">' +
        kit.clipped(first(row, 'xacmlPepThumbprint'), 24) +
        '</div></td><td>' +
        (enabled ? '<span class="state-valid">enabled</span>'
                 : '<span class="state-none">disabled by an ' +
                   'administrator</span>') +
        '<div class="sub">' + kit.esc(first(row, 'xacmlPepLastSeen') ||
          'never seen') + '</div></td>' +
        '<td class="counts">' +
        kit.esc(first(row, 'xacmlPepDecisions') || '0') +
        ' decision(s)<br>' + kit.esc(first(row, 'xacmlPepAllowed') || '0') +
        ' allowed<br>' + kit.esc(first(row, 'xacmlPepRefused') || '0') +
        ' refused</td>' +
        '<td class="attrs">' + attrs + '</td></tr>';
    }).join('');
    const classRows = json.schema.objectClasses.map(function (one) {
      return '<tr><td><code>' + kit.esc(one.name) + '</code></td><td>' +
        kit.esc(one.what) + '</td></tr>';
    }).join('');
    const attrRows = json.schema.attributes.map(function (row) {
      return '<tr><td><code>' + kit.esc(row.name) + '</code></td><td>' +
        kit.esc(row.what) + '</td></tr>';
    }).join('');

    const inner = '<p class="sub">' + json.count + ' of a maximum ' +
      json.max + ' under <code>' + kit.esc(json.container) +
      '</code>: the remote Policy Enforcement Points that have registered ' +
      'with this PDP. Each holds its own copy of the engine, pulls the ' +
      'policy repository, and decides in its own process.</p><div ' +
      'class="tiles">' +
      kit.tile(json.count, 'Registered PEPs') +
      kit.tile(json.enabledCount, 'Enabled') +
      kit.tile(json.max, 'Maximum held') +
      '</div>' +
      kit.note('<strong>An empty container is not a feature that is ' +
      'off.</strong> A remote PEP pulls <code>GET /xacml/pep/policies</code> ' +
      'and converges whether or not it ever registers; registering is what ' +
      'buys it the change nudge and a row here. And an identity in this ' +
      'container was taken from the CLIENT CERTIFICATE the PEP presented, ' +
      'never from the body it sent — so a PEP cannot name itself anything it ' +
      'cannot prove. <a href="/admin/xacml/peps">XACML PEPs</a> is the page ' +
      'with the controls on it.') +
      '<form method="get" action="/admin/ldap/peps"><div class="formrow">' +
      '<label for="q">Anywhere in the entry</label>' +
      '<input type="text" id="q" name="q" value="' + kit.esc(wantedText) +
      '" size="30" placeholder="a name, a DN, a certificate subject or a ' +
      'URL"><label for="per">Show</label><select id="per" name="per">' +
      kit.perPageOptions(paging.perPage) + '</select>' +
      '<button type="submit">Filter</button>' +
      (wantedText ? ' <a href="/admin/ldap/peps">clear</a>' : '') +
      '</div></form>' +
      nav.head +
      '<table><tr><th>PEP</th><th>What it proved</th><th>State</th>' +
      '<th>What it has decided</th><th>Every attribute</th></tr>' +
      (pepRows || '<tr><td colspan="5">' +
        (wantedText
          ? 'No PEP matches. The filter above may be hiding some.'
          : 'Nothing has registered. Policy distribution is unaffected: a ' +
            'PEP that pulls GET /xacml/pep/policies without registering ' +
            'converges ' +
            'on the same repository and appears nowhere.') +
        '</td></tr>') +
      '</table>' +
      nav.foot +
      '<h2>The object classes</h2>' +
      kit.note('node-ldapjs has no schema subsystem and this directory is ' +
      'schemaless on purpose, so this is a VOCABULARY rather than a ' +
      'constraint: nothing rejects an entry for disobeying it.') +
      '<table><tr><th>Class</th><th>What it brings</th></tr>' +
      classRows + '</table>' +
      '<h2>The attributes</h2>' +
      '<table><tr><th>Attribute</th><th>What it is</th></tr>' + attrRows +
      '</table><p class="sub"><a href="/admin/ldap/peps?format=json">This ' +
      'page as JSON</a> &middot; <a href="/admin/xacml/peps">the same ' +
      'registry with the controls on it</a> &middot; <a ' +
      'href="/admin/ldap/policies">what they pull</a> &middot; <a ' +
      'href="/admin/ldap/directory">every entry in ' +
      'the directory</a></p>';
    return inner;
  }

  /**
   * Draws `/admin/ldap/directory` from its answer.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of `GET /admin-api/ldap/directory`
   * @returns the body as HTML
   */
  static directory(ctx: Json, json: Json): string {
    const wantedText = json.filter.q || '';
    const wantedOrigin = json.filter.origin || '';
    const paging = json.paging;
    const origins = json.origins;
    const nav = kit.pageNavPair('/admin/ldap/directory',
      { q: wantedText, origin: wantedOrigin,
        per: ctx.query.per ? String(paging.perPage) : '' }, paging);
    const originOptions = ['<option value=""' +
                           (wantedOrigin ? '' : ' selected') +
                           '>any origin</option>']
      .concat(origins.map(function (origin) {
        const n = json.originCounts[origin];
        return '<option value="' + kit.esc(origin) + '"' +
               (origin === wantedOrigin ? ' selected' : '') + '>' +
               kit.esc(origin) + ' (' + n + ')</option>';
      })).join('');


    const rows = json.entries.map(function (entry) {
      const attrs = Object.keys(entry.attributes).sort().map(function (name) {
        return '<div><code>' + kit.esc(name) + '</code>: ' +
          kit.clippedValues(entry.attributes[name]) + '</div>';
      }).join('');
      return '<tr><td class="dn">' + kit.clipped(entry.dn, 60) +
        '</td><td class="from">' + kit.esc(entry.origin) +
        '</td><td class="attrs">' + attrs + '</td></tr>';
    }).join('');

    const inner = '<p class="sub">' + json.count + ' entry/entries under ' +
      '<code>' + kit.esc(json.baseDn) +
        '</code>. This page is not LDAP &mdash; it is this service showing ' +
        'its own store, which is how you can tell an empty directory from a ' +
        'search filter that matched nothing.</p><div class="tiles">' +
      kit.tile(json.count, 'Entries in this realm') +
      kit.tile(json.matched, 'Matching the filter') +
      kit.tile(origins.length, 'Origins') +
      '</div><form method="get" action="/admin/ldap/directory"><div ' +
      'class="formrow"><label for="q">Anywhere in the entry</label>' +
      '<input type="text" id="q" name="q" value="' + kit.esc(wantedText) +
      '" size="30" placeholder="a DN, an attribute name, or a value">' +
      '<label for="origin">Came from</label>' +
      '<select id="origin" name="origin">' + originOptions + '</select>' +
      '<label for="per">Show</label>' +
      '<select id="per" name="per">' +
      kit.perPageOptions(paging.perPage) + '</select>' +
      '<button type="submit">Filter</button>' +
      ((wantedText || wantedOrigin)
        ? ' <a href="/admin/ldap/directory">clear</a>' : '') +
      '</div></form>' +
      kit.note('The box matches the DN, any attribute NAME and any attribute ' +
      'VALUE, case-insensitively. Values are searched because the reader who ' +
      'needs this most often has a thumbprint or a secret in hand and no ' +
      'idea ' +
      'which entry carries it, which a search over DNs alone cannot answer.') +
      nav.head +
      '<table><tr><th class="dn">DN</th><th class="from">Came ' +
      'from</th><th>Attributes</th></tr>' +
      (rows || '<tr><td colspan="3">No entry matches. ' +
               ((wantedText || wantedOrigin)
                 ? 'The filter above may be hiding some.'
                 : 'This realm&rsquo;s directory is empty.') + '</td></tr>') +
      '</table>' +
      nav.foot +
      kit.note('<strong>A value too long for its column is shortened, and ' +
      'the whole of it is one hover away.</strong> Hovering a shortened ' +
      'value opens a box holding it in full; one click inside that box ' +
      'selects all of it, so it can be copied. Nothing is lost by the ' +
      'shortening &mdash; <code>?format=json</code> below is the whole store ' +
      'with nothing cut, ' +
      'and the full value is in this page&rsquo;s markup either way.') +
      '<p class="sub"><a href="/admin/ldap/directory?format=json">This page ' +
      'as JSON</a> &middot; <a href="/admin/ldap/service">what this ' +
      'directory is</a> &middot; <a href="/admin/users">the people in it</a> ' +
      '&middot; ' +
      '<a href="/admin/groups">the groups in it</a></p>';
    return inner;
  }

  /**
   * Draws `/admin/ldap/service` from its answer.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of `GET /admin-api/ldap/service`
   * @returns the body as HTML
   */
  static service(ctx: Json, json: Json): string {
    const info = json;
    const rows = [
      ['URL', info.url],
      ['LDAPS URL', info.tls.ldaps
        ? info.tls.url
        : 'not offered — ' + (info.tls.error || 'no reason was recorded')],
      ['Base DN', info.baseDn],
      ['People', info.usersDn],
      ['Groups', info.groupsDn],
      // Only where there is more than one, so the ordinary single-realm page is
      // exactly the page it was — a row that always said the same thing as the
      // one above it would be noise on every deployment that has no realms.
      ...(info.namingContexts.length > 1
        ? [['Naming contexts', info.namingContexts.join(', ')],
           ['What a search answers about', info.searchScope]]
        : []),
      ['Protocol version', 'LDAPv3'],
      ['Transport', 'plain TCP on ' + info.port +
        ', and LDAPS — TLS from the ' +
        'first byte — on ' + (info.tls.port || json.ldapsPort) +
          '. There is no ' +
        'StartTLS: it is an extended operation and this library implements ' +
        'none.'],
      ['Entries right now', String(info.limits.currentEntries)],
      // The one row on this page that answers "and will any of this still be
      // here tomorrow". See description()'s `persistence` member.
      ['Persistence', info.persistence.mode === 'memory'
        ? 'NONE — this directory is in memory and goes when the process ' +
          'does, which is what this service did until 2026-08-27. Set ' +
          'persistence.mode to ldif (a file per realm, no database) or ' +
          'postgres (a shared store) to change that.'
        : info.persistence.mode + ' — ' +
          (info.persistence.mode === 'ldif'
            ? 'an RFC 2849 LDIF file per realm in ' + info.persistence.dataDir
            : 'PostgreSQL at ' +
              (info.persistence.database ? info.persistence.database.host +
                ':' +
               info.persistence.database.port + '/' +
               info.persistence.database.database : 'a connection string')) +
          '. ' + info.persistence.entriesTracked + ' entry/entries written; ' +
          (info.persistence.lastError
            ? 'THE LAST WRITE FAILED (' + info.persistence.lastError + ') — ' +
              'the directory is unaffected and is still answering from ' +
              'memory, ' +
              'and the next change will try again'
            : 'last write ' + (info.persistence.lastWriteAt || 'not yet')) +
          '. Sessions, tokens, codes, artifacts and tickets are NEVER ' +
          'persisted in any mode.'],
      ['Listener', info.listening
        ? 'up on TCP ' + info.port
        : 'DOWN — ' + (info.listenError || 'it never bound') +
          '. This page is HTTP and answers either way; the directory does ' +
            'not.'],
      ['LDAPS listener', info.tls.listening
        ? 'up on TCP ' + info.tls.port
        : 'DOWN — ' + (info.tls.error || 'it never bound') +
          '. The two sockets are independent, so this says nothing about the ' +
          'one above.'],
      ['An entry per authenticated user', info.autoCreateUsers ? 'on' : 'off']
    ].map(function (pair) {
      // The VALUE is clipped and the LABEL is not: a label here is four words
      // and a value is a sentence or a DN. kit.clipped() leaves anything under
      // its limit exactly as it was, so the short rows are untouched and the
      // two long ones stop pushing the table past the card.
      return '<tr><td>' + kit.esc(pair[0]) + '</td><td>' +
        kit.clipped(pair[1], 150) + '</td></tr>';
    }).join('');

    // The two sockets as TILES, which is the console's own way of saying "here
    // are the numbers, and here is the one that is wrong". A listener that
    // failed to bind is the single most useful fact on this page and it was
    // previously the eleventh row of a fourteen-row table.
    const tiles = '<div class="tiles">' +
      kit.tile(info.limits.currentEntries, 'Entries in this realm') +
      kit.tile(info.limits.currentEntriesEverywhere, 'Entries in the process') +
      kit.tile(info.listening ? 'up' : 'down', 'TCP ' + info.port) +
      kit.tile(info.tls.listening ? 'up' : 'down',
                 'LDAPS ' + (info.tls.port || json.ldapsPort)) +
      '</div>';

    const inner = '<p class="sub">LDAPv3 over TCP ' + json.ldapPort +
      ', and over ' +
      'TLS on ' + json.ldapsPort +
        ', RFC 4511. A browser cannot speak it &mdash; the debugger&rsquo;s ' +
        'api opens the socket. What the sockets are SET to is <a ' +
        'href="/admin/ldap">LDAP / LDAPS</a>; this page is what actually ' +
        'happened when this process tried to bind them.</p>' +
      tiles +
      '<table><tr><th>Thing</th><th>Value</th></tr>' + rows + '</table>' +
      '<h2>It authenticates nobody</h2>' +
      kit.note(kit.esc(info.bindPolicy) + '.') +
      '<h2>Where an identity&rsquo;s entry goes</h2>' +
      kit.note(kit.esc(info.autoCreateRule)) +
      '<h2>And how they authenticated</h2>' +
      kit.note(kit.esc(info.authenticationFacts)) +
      '<h2>LDAPS, and what it does not change</h2>' +
      kit.note('Port ' + (info.tls.port || json.ldapsPort) + ' is the same ' +
      'directory over TLS &mdash; the same entries, the same handlers, the ' +
      'same every-bind-succeeds. What TLS adds is that the password is not ' +
      'on the wire in the clear; it does not make it <em>checked</em>. The ' +
      'certificate is <strong>the one the HTTPS listeners serve</strong>: ' +
      '<code>' + kit.esc(info.tls.certificate.subject) + '</code>, SHA-256 ' +
      '<code>' + kit.esc(info.tls.certificate.fingerprint256) + '</code>, ' +
      kit.esc(json.certificateProvenance) + '. Fetch it from <a ' +
      'href="/tls/server-certificate">/tls/server-certificate</a> and put it ' +
      'in your truststore &mdash; <code>LDAPTLS_REQCERT=never</code> is the ' +
      'habit this endpoint exists to avoid, and it would also hide the one ' +
      'thing worth checking here.') +
      kit.note(kit.esc(info.tls.clientCertificates) + ' There is no ' +
      'StartTLS: it is an extended operation (RFC 4511 &sect;4.14) and ' +
      'ldapjs implements none, and this service does not patch that ' +
      'submodule. LDAPS is the one of the two no RFC defines &mdash; RFC ' +
      '4513 standardised StartTLS and left <code>ldaps://</code> as the ' +
      'de-facto scheme every ' +
      'client speaks anyway.') +
      '<h2>It has no schema</h2>' +
      kit.note(kit.esc(info.schema)) +
      '<h2>What it does still enforce</h2>' +
      info.enforcedRules.map(function (rule) {
        return kit.bullet(kit.esc(rule));
      }).join('') +
      kit.note('And one thing it does <em>not</em>: deleting a user leaves ' +
      'its DN in every group that lists it as a <code>member</code>. ' +
      'Referential integrity is a directory feature, not a protocol rule.') +
      '<h2>The containers</h2>' +
      kit.note('The tree has three containers. <code>ou=users</code> holds ' +
      'people, one per identity that has authenticated here through any ' +
      'protocol. <code>ou=groups</code> holds groups, which grant nothing. ' +
      '<code>ou=applications</code> holds the OTHER side of those ' +
      'authentications &mdash; every OAuth client, relying party, service ' +
      'provider and Kerberos service this service has been asked about ' +
      '&mdash; and it is different from the other two in one way worth ' +
      'knowing: <strong>it is a registry rather than a record</strong>. The ' +
      'RFC 7591 client registrations live there and nothing caches them, so ' +
      'an <code>ldapmodify</code> of an application entry changes what the ' +
      'protocol endpoints do. <a href="/admin/ldap/applications">What is in ' +
      'it, and the schema it ' +
      'uses</a>.') +
      '<p class="sub"><a href="/admin/ldap/service?format=json">This page as ' +
      'JSON</a> &middot; <a href="/admin/ldap/applications">the application ' +
      'registry</a> &middot; <a href="/admin/ldap/directory">every entry in ' +
      'the directory</a> &middot; <a href="/admin/ldap">the settings behind ' +
      'these sockets</a> &middot; <a href="/admin/sts-metadata">everything ' +
      'this service speaks</a></p>';
    return inner;
  }
}

export = LdapPage;
