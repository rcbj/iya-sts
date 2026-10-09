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
//
// THE WORDS ARE THE `consoleLdap` CATALOG'S (#539, 2026-10-09), through the
// page's translator `ctx.t`; the English catalog is, to the byte, what this
// file drew before. What the VIEW says — the schema's descriptions, the bind
// policy, an error — is drawn as it comes, in English. A sentence with a
// link in it is cut at the link, because a message cannot carry an `href`.
// A DN or a container goes into a message as a parameter: the message
// escapes it, and a DN this service builds holds no apostrophe, the one
// character the two escapers spell differently.
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
    const t = ctx.t;
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
          ? '<div class="sub">' + t.html('consoleLdap.apps.masked') +
            ' <a href="' +
            kit.esc('/admin/applications?application=' +
                    encodeURIComponent(row.identifier) + '#tab-credentials') +
            '">' + t.html('consoleLdap.apps.reveal') + '</a>' +
            t.html('consoleLdap.common.period') + '</div>'
          : '');
      // The DN on every row. This is the page headed "the registry as the
      // directory sees it", and the directory sees an entry by its DN — a row
      // that named only the identifier left the one address an ldapsearch needs
      // to be reconstructed by the reader from a naming rule published nowhere.
      return '<tr><td>' + kit.clipped(row.identifier, 40) +
        (row.dn ? '<div class="sub">' + kit.clipped(row.dn, 40) +
          (row.identifier === row.dnLabel ? '' :
            ' &mdash; ' + t.html('consoleLdap.apps.digestRdn')) +
          '</div>' : '') +
        '</td><td>' + kit.esc(row.name) + '</td><td>' +
        kit.esc(row.kinds.join(', ') ||
                t.text('consoleLdap.common.unstated')) +
        '<div class="sub">' +
        kit.esc(row.protocols.join(', ')) + '</div></td><td>' +
        (row.registered
          ? '<span class="state-valid">' + t.html('consoleLdap.common.yes') +
            '</span>'
          : '<span class="state-none">' + t.html('consoleLdap.common.no') +
            '</span>') +
        '</td><td class="counts">' +
        t.html('consoleLdap.apps.counts',
               { auth: row.authentications, sessions: row.sessions,
                 users: row.users }) +
        '</td><td class="attrs">' + attrs + '</td></tr>';
    }).join('');
    const classRows = json.schema.objectClasses.map(function (one) {
      return '<tr><td><code>' + kit.esc(one.name) + '</code></td><td>' +
        kit.esc(one.where) + (one.standard ? '' : ' <strong>' +
          t.html('consoleLdap.common.inventedHere') + '</strong>') +
        '</td><td>' + kit.esc(one.what) + '</td></tr>';
    }).join('');
    const attrRows = json.schema.attributes.map(function (row) {
      return '<tr><td><code>' + kit.esc(row.name) + '</code>' +
        (row.sensitive ? ' <strong>' +
          t.html('consoleLdap.common.credential') + '</strong>' : '') +
        '</td><td>' + kit.esc(row.kind) + '</td><td>' + kit.esc(row.from) +
        '</td><td>' + kit.esc(row.what) + '</td></tr>';
    }).join('');
    const kindRows = json.kinds.map(function (one) {
      return '<tr><td><code>' + kit.esc(one.kind) + '</code></td><td>' +
        kit.esc(one.label) + '</td><td>' + kit.esc(one.what) + '</td></tr>';
    }).join('');

    const inner = '<p class="sub">' +
      t.html('consoleLdap.apps.intro', { count: json.count, max: json.max,
                                         container: json.container }) +
      '</p><div class="tiles">' +
      kit.tile(json.count, t.text('consoleLdap.apps.tileEntries')) +
      kit.tile(json.matched, t.text('consoleLdap.common.tileMatching')) +
      kit.tile(json.max, t.text('consoleLdap.common.tileMaxHeld')) +
      '</div>' +
      kit.note(t.html('consoleLdap.apps.registryNote') +
      ' <a href="/admin/applications">' +
      t.html('consoleLdap.apps.registryLink') + '</a> ' +
      t.html('consoleLdap.apps.registryNoteEnd')) +
      '<form method="get" action="/admin/ldap/applications"><div ' +
      'class="formrow"><label for="q">' +
      t.html('consoleLdap.common.anywhere') + '</label><input ' +
      'type="text" id="q" name="q" value="' + kit.esc(wantedText) +
      '" size="30" placeholder="' +
      kit.esc(t.text('consoleLdap.apps.placeholder')) + '">' +
      '<label for="per">' + t.html('consoleLdap.common.show') + '</label>' +
      '<select id="per" name="per">' +
      kit.perPageOptions(paging.perPage) + '</select>' +
      '<button type="submit">' + t.html('consoleLdap.common.filter') +
      '</button>' +
      (wantedText ? ' <a href="/admin/ldap/applications">' +
        t.html('consoleLdap.common.clear') + '</a>' : '') +
      '</div></form>' +
      nav.head +
      '<table><tr><th>' + t.html('consoleLdap.apps.thIdentifier') +
      '</th><th>' + t.html('consoleLdap.apps.thName') + '</th><th>' +
      t.html('consoleLdap.apps.thKind') + '</th>' +
      '<th>' + t.html('consoleLdap.apps.thRegistered') + '</th><th>' +
      t.html('consoleLdap.common.thSeen') + '</th><th>' +
      t.html('consoleLdap.common.thEveryAttribute') + '</th></tr>' +
      (appRows || '<tr><td colspan="6">' +
        (wantedText
          ? t.html('consoleLdap.apps.noMatch')
          : t.html('consoleLdap.apps.nothingYet')) +
        '</td></tr>') +
      '</table>' +
      nav.foot +
      '<h2>' + t.html('consoleLdap.apps.kindsHeading') + '</h2>' +
      '<table><tr><th>' + t.html('consoleLdap.apps.thKind') + '</th><th>' +
      t.html('consoleLdap.apps.thLabel') + '</th><th>' +
      t.html('consoleLdap.common.thWhatItMeans') + '</th></tr>' +
      kindRows + '</table>' +
      '<h2>' + t.html('consoleLdap.common.objectClassesHeading') + '</h2>' +
      kit.note(t.html('consoleLdap.apps.schemaNote')) +
      '<table><tr><th>' + t.html('consoleLdap.common.thClass') +
      '</th><th>' + t.html('consoleLdap.common.thWhereFrom') + '</th><th>' +
      t.html('consoleLdap.common.thWhatItBrings') + '</th></tr>' +
      classRows + '</table>' +
      '<h2>' + t.html('consoleLdap.common.attributesHeading') + '</h2>' +
      kit.note(t.html('consoleLdap.apps.attrNote')) +
      '<table><tr><th>' + t.html('consoleLdap.common.thAttribute') +
      '</th><th>' + t.html('consoleLdap.common.thValues') + '</th><th>' +
      t.html('consoleLdap.apps.thSetBy') + '</th>' +
      '<th>' + t.html('consoleLdap.common.thWhatItIs') + '</th></tr>' +
      attrRows + '</table>' +
      '<p class="sub"><a href="/admin/ldap/applications?format=json">' +
      t.html('consoleLdap.common.asJson') + '</a> &middot; ' +
      '<a href="/admin/applications">' +
      t.html('consoleLdap.apps.footControls') + '</a> &middot; <a ' +
      'href="/admin/ldap/directory">' +
      t.html('consoleLdap.common.footEveryEntry') + '</a> ' +
      '&middot; <a href="/admin/ldap/service">' +
      t.html('consoleLdap.common.footWhatDirectory') + '</a></p>';
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
    const t = ctx.t;
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
              ? '<span class="state-valid">' +
                t.html('consoleLdap.fed.enabledReady') + '</span>'
              : '<span class="state-expired">' +
                t.html('consoleLdap.fed.enabledNotConfigured') + '</span>' +
                '<div class="sub">' +
                kit.esc(readiness.missing.join(', ')) + '</div>')
          : '<span class="state-none">' +
            t.html('consoleLdap.common.disabled') + '</span>') + '</td>' +
        '<td>' +
        t.html('consoleLdap.fed.counts',
               { signIns: row.fedAuthentications || '0',
                 people: row.fedUsers || '0' }) + '</td>' +
        '<td class="attrs">' + attrs + '</td></tr>';
    }).join('');
    const classRows = json.schema.objectClasses.map(function (one) {
      return '<tr><td><code>' + kit.esc(one.name) + '</code></td><td>' +
        kit.esc(one.where) + (one.standard ? '' : ' <strong>' +
          t.html('consoleLdap.common.inventedHere') + '</strong>') +
        '</td><td>' + kit.esc(one.what) + '</td></tr>';
    }).join('');
    const attrRows = json.schema.attributes.map(function (row) {
      return '<tr><td><code>' + kit.esc(row.name) + '</code>' +
        (row.sensitive ? ' <strong>' +
          t.html('consoleLdap.common.credential') + '</strong>' : '') +
        '</td><td>' + kit.esc(row.kind) + '</td><td>' + kit.esc(row.role) +
        '</td><td>' + kit.esc(row.what) + '</td></tr>';
    }).join('');

    const inner = '<p class="sub">' +
      t.html('consoleLdap.fed.intro', { count: json.count, max: json.max,
                                        container: json.container }) +
      '</p><div class="tiles">' +
      kit.tile(json.count, t.text('consoleLdap.fed.tileRelationships')) +
      kit.tile(json.enabledCount,
                 t.text('consoleLdap.common.tileEnabled')) +
      kit.tile(json.max, t.text('consoleLdap.common.tileMaxHeld')) +
      '</div>' +
      kit.warn(t.html('consoleLdap.fed.warn')) +
      '<form method="get" action="/admin/ldap/federations"><div ' +
      'class="formrow"><label for="q">' +
      t.html('consoleLdap.fed.thRelationship') + '</label><input ' +
      'type="text" ' +
      'id="q" name="q" value="' + kit.esc(wantedText) +
      '" size="30" placeholder="' +
      kit.esc(t.text('consoleLdap.fed.placeholder')) + '">' +
      '<label for="per">' + t.html('consoleLdap.common.show') + '</label>' +
      '<select id="per" name="per">' +
      kit.perPageOptions(paging.perPage) + '</select>' +
      '<button type="submit">' + t.html('consoleLdap.common.filter') +
      '</button>' +
      (wantedText ? ' <a href="/admin/ldap/federations">' +
        t.html('consoleLdap.common.clear') + '</a>' : '') +
      '</div></form>' +
      nav.head +
      '<table><tr><th>' + t.html('consoleLdap.fed.thRelationship') +
      '</th><th>' + t.html('consoleLdap.fed.thDirection') + '</th><th>' +
      t.html('consoleLdap.common.thState') + '</th>' +
      '<th>' + t.html('consoleLdap.common.thSeen') + '</th><th>' +
      t.html('consoleLdap.common.thEveryAttribute') + '</th></tr>' +
      (relRows || '<tr><td colspan="5">' +
        (wantedText
          ? t.html('consoleLdap.fed.noMatch')
          : t.html('consoleLdap.fed.nothingYet') + ' <a ' +
            'href="/admin/federation">/admin/federation</a> ' +
            t.html('consoleLdap.fed.nothingYetEnd')) +
        '</td></tr>') +
      '</table>' +
      nav.foot +
      '<h2>' + t.html('consoleLdap.fed.directionsHeading') + '</h2>' +
      '<table><tr><th>' + t.html('consoleLdap.common.thRole') + '</th><th>' +
      t.html('consoleLdap.common.thWhatItMeans') + '</th></tr>' +
      json.roles.map(function (one) {
        return '<tr><td>' + kit.esc(one.short) + '</td><td>' +
          kit.esc(one.what) +
          '</td></tr>';
      }).join('') + '</table>' +
      '<h2>' + t.html('consoleLdap.fed.protocolsHeading') + '</h2>' +
      '<table><tr><th>' + t.html('consoleLdap.fed.thProtocol') + '</th><th>' +
      t.html('consoleLdap.fed.thWhatHappens') + '</th><th>' +
      t.html('consoleLdap.fed.thNeeds') + '</th></tr>' +
      json.protocols.map(function (one) {
        return '<tr><td>' + kit.esc(one.label) + '</td><td>' +
          kit.esc(one.what) +
          '</td><td><code>' + kit.esc(one.needs.join(
              ', ')) + '</code></td></tr>';
      }).join('') + '</table>' +
      '<h2>' + t.html('consoleLdap.common.objectClassesHeading') +
      '</h2><table><tr><th>' + t.html('consoleLdap.common.thClass') +
      '</th><th>' + t.html('consoleLdap.common.thWhereFrom') + '</th><th>' +
      t.html('consoleLdap.common.thWhatItBrings') + '</th></tr>' +
      classRows + '</table>' +
      '<h2>' + t.html('consoleLdap.common.attributesHeading') + '</h2>' +
      kit.note(t.html('consoleLdap.fed.attrNote')) +
      '<table><tr><th>' + t.html('consoleLdap.common.thAttribute') +
      '</th><th>' + t.html('consoleLdap.common.thValues') + '</th><th>' +
      t.html('consoleLdap.fed.thDirection') + '</th>' +
      '<th>' + t.html('consoleLdap.common.thWhatItIs') + '</th></tr>' +
      attrRows + '</table>' +
      '<p class="sub"><a href="/admin/ldap/federations?format=json">' +
      t.html('consoleLdap.common.asJson') + '</a> &middot; ' +
      '<a href="/admin/federation">' +
      t.html('consoleLdap.fed.footConfigure') + '</a> &middot; ' +
      '<a href="/federation">' + t.html('consoleLdap.fed.footWhat') +
      '</a> ' +
      '&middot; <a href="/admin/ldap/service">' +
      t.html('consoleLdap.common.footWhatDirectory') + '</a></p>';
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
    const t = ctx.t;
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
        kit.esc(one.where) + (one.standard ? '' : ' <strong>' +
          t.html('consoleLdap.common.inventedHere') + '</strong>') +
        '</td><td>' + kit.esc(one.what) + '</td></tr>';
    }).join('');
    const attrRows = json.schema.attributes.map(function (row) {
      return '<tr><td><code>' + kit.esc(row.name) + '</code></td><td>' +
        kit.esc(row.kind) + '</td><td>' +
        (row.editable ? t.html('consoleLdap.common.yes')
                      : t.html('consoleLdap.common.no')) +
        '</td><td>' + kit.esc(row.from) +
        '</td><td>' + kit.esc(row.what) + '</td></tr>';
    }).join('');
    const entryRows = json.registrationEntries.map(function (row) {
      return '<tr><td>' + kit.clipped(row.spiffeId, 52) +
        '<div class="sub">' + kit.clipped(row.dn, 52) + '</div></td><td>' +
        kit.clipped(row.selectorTexts.join(', ') ||
                      t.text('consoleLdap.spiffe.noSelectors'), 60) +
        '</td><td>' + kit.esc(row.origin) + '</td><td class="num">' +
        row.svidsIssued + '</td></tr>';
    }).join('');
    const agentRows = json.attestedAgents.map(function (row) {
      return '<tr><td>' + kit.clipped(row.id, 52) +
        '<div class="sub">' + kit.clipped(row.dn, 52) + '</div></td><td>' +
        kit.esc(row.attestationType) + '</td><td>' +
        (row.banned
          ? '<span class="state-revoked">' +
            t.html('consoleLdap.spiffe.banned') + '</span>'
          : '<span class="state-valid">' +
            t.html('consoleLdap.spiffe.active') + '</span>') +
        '</td><td class="num">' + row.attestations + '</td></tr>';
    }).join('');

    const inner = '<p class="sub">' +
      t.html('consoleLdap.spiffe.intro',
             { entries: json.entriesContainer,
               agents: json.agentsContainer }) + ' ' +
      '<a href="/spiffe">' + t.html('consoleLdap.spiffe.introWhat') +
      '</a> &middot; ' +
      '<a href="/admin/spiffe">' + t.html('consoleLdap.spiffe.introConsole') +
      '</a>' + t.html('consoleLdap.common.period') + '</p>' +
      '<div class="tiles">' +
      kit.tile(json.entries, t.text('consoleLdap.spiffe.tileEntries')) +
      kit.tile(json.maxEntries, t.text('consoleLdap.spiffe.tileMaxEntries')) +
      kit.tile(json.agents, t.text('consoleLdap.spiffe.tileAgents')) +
      kit.tile(json.maxAgents, t.text('consoleLdap.spiffe.tileMaxAgents')) +
      '</div>' +
      kit.note(kit.esc(json.sourceOfTruth)) +
      '<form method="get" action="/admin/ldap/spiffe"><div class="formrow">' +
      '<input type="hidden" name="entryq" value="' + kit.esc(carried.entryq) +
      '"><input type="hidden" name="agentq" ' +
      'value="' + kit.esc(carried.agentq) + '"><label ' +
      'for="per">' + t.html('consoleLdap.spiffe.rowsPerTable') +
      '</label><select id="per" name="per">' +
      kit.perPageOptions(json.entriesPaging.perPage) + '</select>' +
      '<button class="secondary" type="submit">' +
      t.html('consoleLdap.spiffe.apply') + '</button></div></form>' +
      kit.note(t.html('consoleLdap.spiffe.pagedNote')) +
      '<h2>' + t.html('consoleLdap.spiffe.tileEntries') + '</h2>' +
      '<form method="get" action="/admin/ldap/spiffe"><div class="formrow">' +
      '<input type="hidden" name="agentq" value="' + kit.esc(carried.agentq) +
      '"><input ' +
      'type="hidden" name="per" value="' + kit.esc(carried.per) + '">' +
      '<label for="entryq">' + t.html('consoleLdap.spiffe.entryLabel') +
      '</label>' +
      '<input type="text" id="entryq" name="entryq" size="30" value="' +
      kit.esc(carried.entryq) + '" placeholder="' +
      kit.esc(t.text('consoleLdap.spiffe.entryPlaceholder')) + '">' +
      '<button type="submit">' + t.html('consoleLdap.spiffe.search') +
      '</button>' +
      (carried.entryq ? ' <a href="/admin/ldap/spiffe">' +
        t.html('consoleLdap.common.clear') + '</a>' : '') +
      '</div></form>' +
      entriesNav.head +
      '<table><tr><th>' + t.html('consoleLdap.spiffe.thEntry') + '</th><th>' +
      t.html('consoleLdap.spiffe.thSelectors') + '</th><th>' +
      t.html('consoleLdap.spiffe.thOrigin') + '</th>' +
      '<th class="num">SVIDs</th></tr>' +
      (entryRows || '<tr><td colspan="4">' +
        t.html('consoleLdap.spiffe.none') + '</td></tr>') + '</table>' +
      entriesNav.foot +
      '<h2>' + t.html('consoleLdap.spiffe.tileAgents') + '</h2>' +
      '<form method="get" action="/admin/ldap/spiffe"><div class="formrow">' +
      '<input type="hidden" name="entryq" value="' + kit.esc(carried.entryq) +
      '"><input ' +
      'type="hidden" name="per" value="' + kit.esc(carried.per) + '">' +
      '<label for="agentq">' + t.html('consoleLdap.spiffe.agentLabel') +
      '</label>' +
      '<input type="text" id="agentq" name="agentq" size="30" value="' +
      kit.esc(carried.agentq) + '" placeholder="' +
      kit.esc(t.text('consoleLdap.spiffe.agentPlaceholder')) +
      '"><button type="submit">' + t.html('consoleLdap.spiffe.search') +
      '</button>' +
      (carried.agentq ? ' <a href="/admin/ldap/spiffe">' +
        t.html('consoleLdap.common.clear') + '</a>' : '') +
      '</div></form>' +
      agentsNav.head +
      '<table><tr><th>' + t.html('consoleLdap.spiffe.thAgent') + '</th><th>' +
      t.html('consoleLdap.spiffe.thAttestor') + '</th><th>' +
      t.html('consoleLdap.common.thState') + '</th>' +
      '<th class="num">' + t.html('consoleLdap.spiffe.thAttestations') +
      '</th></tr>' +
      (agentRows ||
       '<tr><td colspan="4">' + t.html('consoleLdap.spiffe.noAgents') +
       '</td></tr>') +
      '</table>' +
      agentsNav.foot +
      '<h2>' + t.html('consoleLdap.spiffe.objectClassesHeading') +
      '</h2><table><tr><th>' + t.html('consoleLdap.common.thClass') +
      '</th><th>' + t.html('consoleLdap.common.thWhereFrom') + '</th>' +
      '<th>' + t.html('consoleLdap.spiffe.thWhat') + '</th></tr>' +
      classRows + '</table>' +
      '<h2>' + t.html('consoleLdap.spiffe.attributesHeading') + '</h2>' +
      kit.note(t.html('consoleLdap.spiffe.attrNote')) +
      '<table><tr><th>' + t.html('consoleLdap.common.thAttribute') +
      '</th><th>' + t.html('consoleLdap.common.thValues') + '</th><th>' +
      t.html('consoleLdap.spiffe.thEditable') + '</th>' +
      '<th>' + t.html('consoleLdap.spiffe.thWrittenBy') + '</th><th>' +
      t.html('consoleLdap.spiffe.thWhat') + '</th></tr>' + attrRows +
      '</table>' +
      '<p class="sub"><a href="/admin/ldap/spiffe?format=json">' +
      t.html('consoleLdap.common.asJson') + '</a> &middot; ' +
      '<a href="/admin/spiffe/entries">' +
      t.html('consoleLdap.spiffe.footEntries') + '</a> &middot; ' +
      '<a href="/admin/ldap/directory">' +
      t.html('consoleLdap.common.footEveryEntry') + '</a> &middot; <a ' +
      'href="/admin/ldap/service">' +
      t.html('consoleLdap.common.footWhatDirectory') + '</a></p>';
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
    const t = ctx.t;
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
      // The owner's KIND is a value of the entry (`person`, `application`),
      // not a word of this page, so it is drawn as it is stored.
      return '<tr><td><a href="/admin/devices?device=' +
        encodeURIComponent(id) + '">' + kit.clipped(id, 40) + '</a>' +
        '<div class="sub">' + kit.clipped(entry.dn, 40) + '</div></td>' +
        '<td>' + kit.esc(String((a.stsDeviceOwnerKind || ['person'])[0])) +
        '<div class="sub">' + kit.clipped(String((a.owner || [''])[0]), 40) +
        '</div></td><td class="attrs">' + attrs + '</td></tr>';
    }).join('');
    const classRows = json.schema.objectClasses.map(function (one) {
      return '<tr><td><code>' + kit.esc(one.name) + '</code></td><td>' +
        kit.esc(one.where) + (one.standard ? '' : ' <strong>' +
          t.html('consoleLdap.common.inventedHere') + '</strong>') +
        '</td><td>' + kit.esc(one.what) + '</td></tr>';
    }).join('');
    const attrRows = json.schema.attributes.map(function (row) {
      return '<tr><td><code>' + kit.esc(row.name) + '</code>' +
        (row.sensitive ? ' <strong>' +
          t.html('consoleLdap.devices.withheld') + '</strong>' : '') +
        '</td><td>' +
        kit.esc(row.kind) + '</td><td>' + kit.esc(row.what) + '</td></tr>';
    }).join('');
    const inner = '<p class="sub">' +
      t.html('consoleLdap.devices.intro', { count: json.count,
                                            container: json.container }) +
      ' <a href="/admin/devices">' + t.html('consoleLdap.devices.link') +
      '</a> ' + t.html('consoleLdap.devices.introEnd') + '</p>' +
      '<div class="tiles">' +
      kit.tile(json.count, t.text('consoleLdap.devices.tileEntries')) +
      '</div>' +
      kit.note(t.html('consoleLdap.devices.note')) +
      '<form method="get" action="/admin/ldap/devices"><div class="formrow">' +
      '<label for="q">' + t.html('consoleLdap.devices.thDevice') +
      '</label><input type="text" id="q" name="q" ' +
      'value="' + kit.esc(wantedText) + '" size="30" placeholder="' +
      kit.esc(t.text('consoleLdap.devices.placeholder')) + '">' +
      '<label for="per">' + t.html('consoleLdap.common.show') +
      '</label><select id="per" name="per">' +
      kit.perPageOptions(paging.perPage) + '</select>' +
      '<button type="submit">' + t.html('consoleLdap.common.filter') +
      '</button>' +
      (wantedText ? ' <a href="/admin/ldap/devices">' +
        t.html('consoleLdap.common.clear') + '</a>' : '') +
      '</div></form>' + nav.head +
      '<table><tr><th>' + t.html('consoleLdap.devices.thDevice') +
      '</th><th>' + t.html('consoleLdap.devices.thOwner') + '</th><th>' +
      t.html('consoleLdap.common.thEveryAttribute') + '</th></tr>' +
      (rows || '<tr><td colspan="3">' + (wantedText
        ? t.html('consoleLdap.devices.noMatch')
        : t.html('consoleLdap.devices.noneYet') +
          ' <a href="/admin/devices">' + t.html('consoleLdap.devices.link') +
          '</a>' + t.html('consoleLdap.common.period')) +
        '</td></tr>') + '</table>' + nav.foot +
      '<h2>' + t.html('consoleLdap.common.objectClassesHeading') +
      '</h2><table><tr><th>' + t.html('consoleLdap.common.thClass') +
      '</th><th>' + t.html('consoleLdap.common.thWhereFrom') + '</th><th>' +
      t.html('consoleLdap.common.thWhatItBrings') + '</th></tr>' +
      classRows + '</table>' +
      '<h2>' + t.html('consoleLdap.common.attributesHeading') + '</h2>' +
      kit.note(t.html('consoleLdap.devices.attrNote')) +
      '<table><tr><th>' + t.html('consoleLdap.common.thAttribute') +
      '</th><th>' + t.html('consoleLdap.common.thValues') + '</th><th>' +
      t.html('consoleLdap.common.thWhatItIs') + '</th></tr>' +
      attrRows + '</table>' +
      '<p class="sub"><a href="/admin/ldap/devices?format=json">' +
      t.html('consoleLdap.common.asJson') + '</a> &middot; ' +
      '<a href="/admin/devices">' + t.html('consoleLdap.devices.footRegister') +
      '</a> &middot; <a href="/admin/ldap/directory">' +
      t.html('consoleLdap.common.footEveryEntry') + '</a> &middot; ' +
      '<a href="/admin/ldap/service">' +
      t.html('consoleLdap.common.footWhatDirectory') + '</a></p>';
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
    const t = ctx.t;
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
        '</td><td class="counts">' +
        t.html('consoleLdap.roles.counts',
               { users: held('roleMemberUser'),
                 groups: held('roleMemberGroup'),
                 applications: held('roleMemberApplication') }) +
        '</td>' +
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

    const inner = '<p class="sub">' +
      t.html('consoleLdap.roles.intro', { count: json.count, max: json.max,
                                          container: json.container }) +
      '</p><div class="tiles">' +
      kit.tile(json.count, t.text('consoleLdap.roles.tileEntries')) +
      kit.tile(json.builtIn.length, t.text('consoleLdap.roles.tileBuiltIn')) +
      kit.tile(json.max, t.text('consoleLdap.common.tileMaxHeld')) +
      '</div>' +
      kit.note(t.html('consoleLdap.roles.note') +
      ' <a href="/admin/roles">' + t.html('consoleLdap.roles.noteRolesLink') +
      '</a> ' + t.html('consoleLdap.roles.noteMiddle') + ' <a ' +
      'href="/admin/ldap/applications">' +
      t.html('consoleLdap.roles.noteAppsLink') + '</a> ' +
      t.html('consoleLdap.roles.noteEnd')) +
      '<form method="get" action="/admin/ldap/roles"><div class="formrow">' +
      '<label for="q">' + t.html('consoleLdap.common.anywhere') + '</label>' +
      '<input type="text" id="q" name="q" value="' + kit.esc(wantedText) +
      '" size="30" placeholder="' +
      kit.esc(t.text('consoleLdap.roles.placeholder')) + '">' +
      '<label for="per">' + t.html('consoleLdap.common.show') + '</label>' +
      '<select id="per" name="per">' +
      kit.perPageOptions(paging.perPage) + '</select>' +
      '<button type="submit">' + t.html('consoleLdap.common.filter') +
      '</button>' +
      (wantedText ? ' <a href="/admin/ldap/roles">' +
        t.html('consoleLdap.common.clear') + '</a>' : '') +
      '</div></form>' +
      nav.head +
      '<table><tr><th>' + t.html('consoleLdap.common.thRole') + '</th><th>' +
      t.html('consoleLdap.roles.thWhoHolds') + '</th>' +
      '<th>' + t.html('consoleLdap.common.thEveryAttribute') + '</th></tr>' +
      (roleRows || '<tr><td colspan="3">' +
        (wantedText
          ? t.html('consoleLdap.roles.noMatch')
          : t.html('consoleLdap.roles.nothingYet')) +
        '</td></tr>') +
      '</table>' +
      nav.foot +
      '<h2>' + t.html('consoleLdap.roles.builtInHeading') + '</h2>' +
      kit.note(t.html('consoleLdap.roles.builtInNote')) +
      '<table><tr><th>' + t.html('consoleLdap.common.thRole') + '</th><th>' +
      t.html('consoleLdap.roles.thWhoHolds') + '</th></tr>' +
      builtInRows + '</table>' +
      '<h2>' + t.html('consoleLdap.common.objectClassesHeading') + '</h2>' +
      kit.note(t.html('consoleLdap.common.schemalessNote')) +
      '<table><tr><th>' + t.html('consoleLdap.common.thClass') + '</th><th>' +
      t.html('consoleLdap.common.thWhatItBrings') + '</th></tr>' +
      classRows + '</table>' +
      '<h2>' + t.html('consoleLdap.common.attributesHeading') + '</h2>' +
      '<table><tr><th>' + t.html('consoleLdap.common.thAttribute') +
      '</th><th>' + t.html('consoleLdap.common.thWhatItIs') + '</th></tr>' +
      attrRows +
      '</table><p class="sub"><a href="/admin/ldap/roles?format=json">' +
      t.html('consoleLdap.common.asJson') + '</a> &middot; ' +
      '<a href="/admin/roles">' + t.html('consoleLdap.roles.footControls') +
      '</a> &middot; <a ' +
      'href="/admin/ldap/directory">' +
      t.html('consoleLdap.common.footEveryEntry') + '</a> ' +
      '&middot; <a href="/admin/ldap/service">' +
      t.html('consoleLdap.common.footWhatDirectory') + '</a></p>';
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
    const t = ctx.t;
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
        '</td><td>' + kit.esc(first(row, 'xacmlKind') ||
                              t.text('consoleLdap.common.unstated')) +
        '<div class="sub">' + kit.clipped(first(row, 'xacmlPolicyId'), 40) +
        '</div></td><td>' +
        (enabled
          ? '<span class="state-valid">' +
            t.html('consoleLdap.common.enabled') + '</span>'
          : '<span class="state-none">' +
            t.html('consoleLdap.common.disabled') + '</span>') +
        (isRoot ? '<div class="sub">' +
          t.html('consoleLdap.policies.theRoot') + '</div>' : '') +
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

    const inner = '<p class="sub">' +
      t.html('consoleLdap.policies.intro',
             { count: json.count, max: json.max,
               container: json.container }) +
      '</p><div ' +
      'class="tiles">' +
      kit.tile(json.count, t.text('consoleLdap.policies.tileEntries')) +
      kit.tile(json.enabledCount, t.text('consoleLdap.common.tileEnabled')) +
      kit.tile(json.max, t.text('consoleLdap.common.tileMaxHeld')) +
      '</div>' +
      kit.warn(t.html('consoleLdap.policies.warn') +
      ' <a href="/admin/xacml">XACML</a> ' +
      t.html('consoleLdap.policies.warnEnd')) +
      '<form method="get" action="/admin/ldap/policies"><div class="formrow">' +
      '<label for="q">' + t.html('consoleLdap.common.anywhere') + '</label>' +
      '<input type="text" id="q" name="q" value="' + kit.esc(wantedText) +
      '" size="30" placeholder="' +
      kit.esc(t.text('consoleLdap.policies.placeholder')) +
      '"><label for="per">' + t.html('consoleLdap.common.show') +
      '</label><select id="per" name="per">' +
      kit.perPageOptions(paging.perPage) + '</select>' +
      '<button type="submit">' + t.html('consoleLdap.common.filter') +
      '</button>' +
      (wantedText ? ' <a href="/admin/ldap/policies">' +
        t.html('consoleLdap.common.clear') + '</a>' : '') +
      '</div></form>' +
      nav.head +
      '<table><tr><th>' + t.html('consoleLdap.policies.thPolicy') +
      '</th><th>' + t.html('consoleLdap.apps.thKind') + '</th><th>' +
      t.html('consoleLdap.common.thState') + '</th><th>' +
      t.html('consoleLdap.common.thEveryAttribute') + '</th></tr>' +
      (policyRows || '<tr><td colspan="4">' +
        (wantedText
          ? t.html('consoleLdap.policies.noMatch')
          : t.html('consoleLdap.policies.nothingYet')) +
        '</td></tr>') +
      '</table>' +
      nav.foot +
      '<h2>' + t.html('consoleLdap.common.objectClassesHeading') + '</h2>' +
      kit.note(t.html('consoleLdap.common.schemalessNote')) +
      '<table><tr><th>' + t.html('consoleLdap.common.thClass') + '</th><th>' +
      t.html('consoleLdap.common.thWhatItBrings') + '</th></tr>' +
      classRows + '</table>' +
      '<h2>' + t.html('consoleLdap.common.attributesHeading') + '</h2>' +
      '<table><tr><th>' + t.html('consoleLdap.common.thAttribute') +
      '</th><th>' + t.html('consoleLdap.common.thWhatItIs') + '</th></tr>' +
      attrRows +
      '</table><p class="sub"><a ' +
      'href="/admin/ldap/policies?format=json">' +
      t.html('consoleLdap.common.asJson') + '</a> ' +
      '&middot; <a href="/admin/xacml">' +
      t.html('consoleLdap.policies.footControls') + '</a> &middot; ' +
      '<a href="/admin/ldap/peps">' + t.html('consoleLdap.policies.footPeps') +
      '</a> &middot; <a href="/admin/ldap/directory">' +
      t.html('consoleLdap.common.footEveryEntry') + '</a></p>';
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
    const t = ctx.t;
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
          t.text('consoleLdap.peps.noCertificate'), 40) +
        '<div class="sub">' +
        kit.clipped(first(row, 'xacmlPepThumbprint'), 24) +
        '</div></td><td>' +
        (enabled
          ? '<span class="state-valid">' +
            t.html('consoleLdap.common.enabled') + '</span>'
          : '<span class="state-none">' +
            t.html('consoleLdap.peps.disabledByAdmin') + '</span>') +
        '<div class="sub">' + kit.esc(first(row, 'xacmlPepLastSeen') ||
          t.text('consoleLdap.peps.neverSeen')) + '</div></td>' +
        '<td class="counts">' +
        t.html('consoleLdap.peps.counts',
               { decisions: first(row, 'xacmlPepDecisions') || '0',
                 allowed: first(row, 'xacmlPepAllowed') || '0',
                 refused: first(row, 'xacmlPepRefused') || '0' }) +
        '</td>' +
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

    const inner = '<p class="sub">' +
      t.html('consoleLdap.peps.intro', { count: json.count, max: json.max,
                                         container: json.container }) +
      '</p><div ' +
      'class="tiles">' +
      kit.tile(json.count, t.text('consoleLdap.peps.tileRegistered')) +
      kit.tile(json.enabledCount, t.text('consoleLdap.common.tileEnabled')) +
      kit.tile(json.max, t.text('consoleLdap.common.tileMaxHeld')) +
      '</div>' +
      kit.note(t.html('consoleLdap.peps.note') +
      ' <a href="/admin/xacml/peps">' + t.html('consoleLdap.peps.noteLink') +
      '</a> ' + t.html('consoleLdap.peps.noteEnd')) +
      '<form method="get" action="/admin/ldap/peps"><div class="formrow">' +
      '<label for="q">' + t.html('consoleLdap.common.anywhere') + '</label>' +
      '<input type="text" id="q" name="q" value="' + kit.esc(wantedText) +
      '" size="30" placeholder="' +
      kit.esc(t.text('consoleLdap.peps.placeholder')) +
      '"><label for="per">' + t.html('consoleLdap.common.show') +
      '</label><select id="per" name="per">' +
      kit.perPageOptions(paging.perPage) + '</select>' +
      '<button type="submit">' + t.html('consoleLdap.common.filter') +
      '</button>' +
      (wantedText ? ' <a href="/admin/ldap/peps">' +
        t.html('consoleLdap.common.clear') + '</a>' : '') +
      '</div></form>' +
      nav.head +
      '<table><tr><th>PEP</th><th>' + t.html('consoleLdap.peps.thProved') +
      '</th><th>' + t.html('consoleLdap.common.thState') + '</th>' +
      '<th>' + t.html('consoleLdap.peps.thDecided') + '</th><th>' +
      t.html('consoleLdap.common.thEveryAttribute') + '</th></tr>' +
      (pepRows || '<tr><td colspan="5">' +
        (wantedText
          ? t.html('consoleLdap.peps.noMatch')
          : t.html('consoleLdap.peps.nothingYet')) +
        '</td></tr>') +
      '</table>' +
      nav.foot +
      '<h2>' + t.html('consoleLdap.common.objectClassesHeading') + '</h2>' +
      kit.note(t.html('consoleLdap.common.schemalessNote')) +
      '<table><tr><th>' + t.html('consoleLdap.common.thClass') + '</th><th>' +
      t.html('consoleLdap.common.thWhatItBrings') + '</th></tr>' +
      classRows + '</table>' +
      '<h2>' + t.html('consoleLdap.common.attributesHeading') + '</h2>' +
      '<table><tr><th>' + t.html('consoleLdap.common.thAttribute') +
      '</th><th>' + t.html('consoleLdap.common.thWhatItIs') + '</th></tr>' +
      attrRows +
      '</table><p class="sub"><a href="/admin/ldap/peps?format=json">' +
      t.html('consoleLdap.common.asJson') + '</a> &middot; ' +
      '<a href="/admin/xacml/peps">' + t.html('consoleLdap.peps.footControls') +
      '</a> &middot; <a ' +
      'href="/admin/ldap/policies">' + t.html('consoleLdap.peps.footPull') +
      '</a> &middot; <a ' +
      'href="/admin/ldap/directory">' +
      t.html('consoleLdap.common.footEveryEntry') + '</a></p>';
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
    const t = ctx.t;
    const wantedText = json.filter.q || '';
    const wantedOrigin = json.filter.origin || '';
    const paging = json.paging;
    const origins = json.origins;
    const nav = kit.pageNavPair('/admin/ldap/directory',
      { q: wantedText, origin: wantedOrigin,
        per: ctx.query.per ? String(paging.perPage) : '' }, paging);
    const originOptions = ['<option value=""' +
                           (wantedOrigin ? '' : ' selected') +
                           '>' + t.html('consoleLdap.directory.anyOrigin') +
                           '</option>']
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

    const inner = '<p class="sub">' +
      t.html('consoleLdap.directory.intro', { count: json.count,
                                              base: json.baseDn }) +
      '</p><div class="tiles">' +
      kit.tile(json.count, t.text('consoleLdap.common.tileEntriesRealm')) +
      kit.tile(json.matched, t.text('consoleLdap.common.tileMatching')) +
      kit.tile(origins.length, t.text('consoleLdap.directory.tileOrigins')) +
      '</div><form method="get" action="/admin/ldap/directory"><div ' +
      'class="formrow"><label for="q">' +
      t.html('consoleLdap.common.anywhere') + '</label>' +
      '<input type="text" id="q" name="q" value="' + kit.esc(wantedText) +
      '" size="30" placeholder="' +
      kit.esc(t.text('consoleLdap.directory.placeholder')) + '">' +
      '<label for="origin">' + t.html('consoleLdap.directory.cameFrom') +
      '</label>' +
      '<select id="origin" name="origin">' + originOptions + '</select>' +
      '<label for="per">' + t.html('consoleLdap.common.show') + '</label>' +
      '<select id="per" name="per">' +
      kit.perPageOptions(paging.perPage) + '</select>' +
      '<button type="submit">' + t.html('consoleLdap.common.filter') +
      '</button>' +
      ((wantedText || wantedOrigin)
        ? ' <a href="/admin/ldap/directory">' +
          t.html('consoleLdap.common.clear') + '</a>' : '') +
      '</div></form>' +
      kit.note(t.html('consoleLdap.directory.searchNote')) +
      nav.head +
      '<table><tr><th class="dn">DN</th><th class="from">' +
      t.html('consoleLdap.directory.cameFrom') + '</th><th>' +
      t.html('consoleLdap.directory.thAttributes') + '</th></tr>' +
      (rows || '<tr><td colspan="3">' +
               t.html('consoleLdap.directory.noMatch') + ' ' +
               ((wantedText || wantedOrigin)
                 ? t.html('consoleLdap.directory.filterHiding')
                 : t.html('consoleLdap.directory.empty')) + '</td></tr>') +
      '</table>' +
      nav.foot +
      kit.note(t.html('consoleLdap.directory.clipNote')) +
      '<p class="sub"><a href="/admin/ldap/directory?format=json">' +
      t.html('consoleLdap.common.asJson') + '</a> &middot; ' +
      '<a href="/admin/ldap/service">' +
      t.html('consoleLdap.common.footWhatDirectory') + '</a> &middot; ' +
      '<a href="/admin/users">' + t.html('consoleLdap.directory.footPeople') +
      '</a> ' +
      '&middot; ' +
      '<a href="/admin/groups">' + t.html('consoleLdap.directory.footGroups') +
      '</a></p>';
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
    const t = ctx.t;
    const info = json;
    const ldapsPort = info.tls.port || json.ldapsPort;
    // The persistence row's middle: where the store is.
    const persistedWhere = info.persistence.mode === 'ldif'
      ? t.text('consoleLdap.service.persistLdif',
               { dir: info.persistence.dataDir })
      : t.text('consoleLdap.service.persistPostgres',
               { where: info.persistence.database
                 ? info.persistence.database.host + ':' +
                   info.persistence.database.port + '/' +
                   info.persistence.database.database
                 : t.text('consoleLdap.service.connectionString') });
    const rows = [
      ['URL', info.url],
      ['LDAPS URL', info.tls.ldaps
        ? info.tls.url
        : t.text('consoleLdap.service.notOffered',
                 { reason: info.tls.error ||
                   t.text('consoleLdap.service.noReason') })],
      [t.text('consoleLdap.service.baseDn'), info.baseDn],
      [t.text('consoleLdap.service.people'), info.usersDn],
      [t.text('consoleLdap.service.groups'), info.groupsDn],
      // Only where there is more than one, so the ordinary single-realm page is
      // exactly the page it was — a row that always said the same thing as the
      // one above it would be noise on every deployment that has no realms.
      ...(info.namingContexts.length > 1
        ? [[t.text('consoleLdap.service.namingContexts'),
            info.namingContexts.join(', ')],
           [t.text('consoleLdap.service.searchAnswers'), info.searchScope]]
        : []),
      [t.text('consoleLdap.service.protocolVersion'), 'LDAPv3'],
      [t.text('consoleLdap.service.transport'),
       t.text('consoleLdap.service.transportValue',
              { port: info.port, ldapsPort: ldapsPort })],
      [t.text('consoleLdap.service.entriesNow'),
       String(info.limits.currentEntries)],
      // The one row on this page that answers "and will any of this still be
      // here tomorrow". See description()'s `persistence` member.
      //
      // A FAILED WRITE STAYS IN ENGLISH (#539): it is an error, and errors are
      // drawn in the language the log and the error code are in.
      [t.text('consoleLdap.service.persistence'),
       info.persistence.mode === 'memory'
        ? t.text('consoleLdap.service.persistNone')
        : info.persistence.mode + ' — ' + persistedWhere +
          '. ' + t.text('consoleLdap.service.persistWritten',
                        { n: info.persistence.entriesTracked }) + ' ' +
          (info.persistence.lastError
            ? 'THE LAST WRITE FAILED (' + info.persistence.lastError + ') — ' +
              'the directory is unaffected and is still answering from ' +
              'memory, ' +
              'and the next change will try again'
            : t.text('consoleLdap.service.lastWrite',
                     { when: info.persistence.lastWriteAt ||
                       t.text('consoleLdap.service.notYet') })) +
          '. ' + t.text('consoleLdap.service.neverPersisted')],
      [t.text('consoleLdap.service.listener'), info.listening
        ? t.text('consoleLdap.service.upOn', { port: info.port })
        : t.text('consoleLdap.service.listenerDown',
                 { why: info.listenError ||
                   t.text('consoleLdap.service.neverBound') })],
      [t.text('consoleLdap.service.ldapsListener'), info.tls.listening
        ? t.text('consoleLdap.service.upOn', { port: info.tls.port })
        : t.text('consoleLdap.service.ldapsDown',
                 { why: info.tls.error ||
                   t.text('consoleLdap.service.neverBound') })],
      [t.text('consoleLdap.service.autoCreate'), info.autoCreateUsers
        ? t.text('consoleLdap.service.on')
        : t.text('consoleLdap.service.off')]
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
      kit.tile(info.limits.currentEntries,
               t.text('consoleLdap.common.tileEntriesRealm')) +
      kit.tile(info.limits.currentEntriesEverywhere,
               t.text('consoleLdap.service.tileEntriesProcess')) +
      kit.tile(info.listening ? t.text('consoleLdap.service.up')
                              : t.text('consoleLdap.service.down'),
               'TCP ' + info.port) +
      kit.tile(info.tls.listening ? t.text('consoleLdap.service.up')
                                  : t.text('consoleLdap.service.down'),
                 'LDAPS ' + ldapsPort) +
      '</div>';

    const inner = '<p class="sub">' +
      t.html('consoleLdap.service.intro', { ldapPort: json.ldapPort,
                                            ldapsPort: json.ldapsPort }) +
      ' <a ' +
        'href="/admin/ldap">LDAP / LDAPS</a>' +
      t.html('consoleLdap.service.introEnd') + '</p>' +
      tiles +
      '<table><tr><th>' + t.html('consoleLdap.service.thThing') +
      '</th><th>' + t.html('consoleLdap.service.thValue') + '</th></tr>' +
      rows + '</table>' +
      '<h2>' + t.html('consoleLdap.service.authHeading') + '</h2>' +
      kit.note(kit.esc(info.bindPolicy) + '.') +
      '<h2>' + t.html('consoleLdap.service.entryHeading') + '</h2>' +
      kit.note(kit.esc(info.autoCreateRule)) +
      '<h2>' + t.html('consoleLdap.service.howHeading') + '</h2>' +
      kit.note(kit.esc(info.authenticationFacts)) +
      '<h2>' + t.html('consoleLdap.service.ldapsHeading') + '</h2>' +
      kit.note(t.html('consoleLdap.service.ldapsNote', { port: ldapsPort }) +
      ' <code>' + kit.esc(info.tls.certificate.subject) + '</code>, SHA-256 ' +
      '<code>' + kit.esc(info.tls.certificate.fingerprint256) + '</code>, ' +
      kit.esc(json.certificateProvenance) + '. ' +
      t.html('consoleLdap.service.fetchIt') + ' <a ' +
      'href="/tls/server-certificate">/tls/server-certificate</a> ' +
      t.html('consoleLdap.service.fetchItEnd')) +
      kit.note(kit.esc(info.tls.clientCertificates) + ' ' +
      t.html('consoleLdap.service.noStartTls')) +
      '<h2>' + t.html('consoleLdap.service.schemaHeading') + '</h2>' +
      kit.note(kit.esc(info.schema)) +
      '<h2>' + t.html('consoleLdap.service.enforceHeading') + '</h2>' +
      info.enforcedRules.map(function (rule) {
        return kit.bullet(kit.esc(rule));
      }).join('') +
      kit.note(t.html('consoleLdap.service.referentialNote')) +
      '<h2>' + t.html('consoleLdap.service.containersHeading') + '</h2>' +
      kit.note(t.html('consoleLdap.service.containersNote') +
      ' <a href="/admin/ldap/applications">' +
      t.html('consoleLdap.service.containersLink') + '</a>' +
      t.html('consoleLdap.common.period')) +
      '<p class="sub"><a href="/admin/ldap/service?format=json">' +
      t.html('consoleLdap.common.asJson') + '</a> &middot; ' +
      '<a href="/admin/ldap/applications">' +
      t.html('consoleLdap.service.footRegistry') + '</a> &middot; ' +
      '<a href="/admin/ldap/directory">' +
      t.html('consoleLdap.common.footEveryEntry') + '</a> &middot; ' +
      '<a href="/admin/ldap">' + t.html('consoleLdap.service.footSettings') +
      '</a> &middot; <a href="/admin/sts-metadata">' +
      t.html('consoleLdap.service.footSpeaks') + '</a></p>';
    return inner;
  }
}

export = LdapPage;
