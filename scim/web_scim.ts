// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_scim.ts
//
// ---------------------------------------------------------------------------
// PROTOCOLS → SCIM AND MONITORING → SCIM, DRAWN FROM THEIR VIEWS ALONE (#446,
// 2026-10-05).
//
// Draws SCIM from the answer of `GET /admin-api/scim` and SCIM activity from
// that of `GET /admin-api/scim/monitor`.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// It was drawn inside the route of `/admin/scim` in `admin-ui/admin.ts`, which
// still draws the page until the console's cutover by calling this with its
// view passed through JSON.
//
// ITS WORDS ARE THE `consoleScim` NAMESPACE (#539). What the VIEW says — an
// operation's `what`, a scheme's description, the access control policy,
// the doesNotDo list, the identifier argument — is the server's and drawn
// as it comes, in English; so are the two `err` boxes, which are errors.
// A sentence carrying a link is split around it, because a message cannot
// carry an `href`.
// ---------------------------------------------------------------------------

import kit = require('../admin-ui/web_kit');
import SettingsForms = require('../admin-ui/web_settings');

type Json = any;

/**
 * Draws SCIM from the answer of `GET /admin-api/scim` and SCIM activity from
 * that of `GET /admin-api/scim/monitor`.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class ScimPage {
  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static body(ctx, json) {
    const t = ctx.t;
    const counters = json.counters;

    // The `<div class="tiles">` around them was missing since this page was
    // written, so its six tiles were six full-width blocks down the page
    // where every other page here has one row. Nothing failed and nothing
    // could have shown it: `.tile` draws correctly on its own, and it is the
    // CONTAINER that makes a row.
    const tiles = '<div class="tiles">' +
      kit.tile(counters.total, t.text('consoleScim.tileRequests')) +
      kit.tile(counters.ok, t.text('consoleScim.tileAnswered')) +
      kit.tile(counters.failed, t.text('consoleScim.tileRefused')) +
      kit.tile(json.store ? json.store.userCount : '—',
                t.text('consoleScim.tilePeople')) +
      kit.tile(json.store ? json.store.groupCount : '—',
               t.text('consoleScim.tileGroups')) +
      kit.tile(json.store ? json.store.entryCount + ' / ' +
                json.store.maxEntries :
                '—', t.text('consoleScim.tileEntries')) +
      '</div>';

    const operationRows = counters.operations.map(function (row) {
      return '<tr><td><code>' + kit.esc(row.method) + '</code> ' +
             kit.esc(row.label) +
        '</td><td ' +
        'class="num">' + row.count + '</td>' +
        '<td class="sub">' + kit.esc(row.what) + '</td></tr>';
    }).join('');

    const typeRows = counters.resourceTypes.map(function (row) {
      return '<tr><td><code>' + kit.esc(row.resourceType) + '</code></td>' +
        '<td class="num">' + row.count + '</td></tr>';
    }).join('');

    const statusRows = Object.keys(counters.byStatus).sort()
      .map(function (code) {
      return '<tr><td><code>' + kit.esc(code) + '</code></td><td ' +
        'class="num">' +
        counters.byStatus[code] + '</td></tr>';
    }).join('') ||
      '<tr><td colspan="2">' + t.html('consoleScim.nothingAnswered') +
      '</td></tr>';

    const scimTypeRows = Object.keys(counters.byScimType)
                               .sort()
                               .map(function (name) {
      return '<tr><td><code>' + kit.esc(name) + '</code></td><td ' +
        'class="num">' +
        counters.byScimType[name] + '</td></tr>';
    }).join('') ||
      '<tr><td colspan="2">' + t.html('consoleScim.nothingRefusedPermissive') +
      '</td></tr>';

    const endpointRows = json.endpoints.map(function (row) {
      return '<tr><td><code>' + kit.esc(row.method) +
             '</code></td><td><code>' +
        kit.esc(row.path) + '</code></td><td class="sub">' +
        kit.esc(row.what) +
        '</td></tr>';
    }).join('');

    const negativeRows = json.reachableNegatives.map(function (row) {
      return '<tr><td>' + kit.esc(row.what) + '</td><td>' +
             kit.esc(row.answer) +
             '</td></tr>';
    }).join('');

    function mappingTable(rows) {
      return '<table><tr><th>SCIM</th><th>' +
      t.html('consoleScim.colLdapAttribute') +
        '</th><th>' + t.html('consoleScim.colHow') + '</th>' +
        '<th>' + t.html('consoleScim.colDefinedBy') + '</th></tr>' +
        rows.map(function (row) {
          return '<tr><td><code>' + kit.esc(row.scim) + '</code>' +
            (row.required ? ' <span class="state-valid">' +
             t.html('consoleScim.required') + '</span>' :
             '') +
            (row.extension ?
             ' <span class="sub">' + t.html('consoleScim.enterpriseExtension') +
             '</span>' :
             '') +
            '</td>' +
            '<td><code>' + kit.esc(row.ldap) + '</code></td>' +
            '<td>' + kit.esc(row.kind) +
            (row.readOnly ? t.html('consoleScim.readOnly') : '') +
            (row.note ? '<div class="sub">' + kit.esc(row.note) + '</div>' :
             '') +
            '</td><td ' +
            'class="sub">' + kit.esc(row.schema) + '</td></tr>';
        }).join('') + '</table>';
    }

    const inner = (!json.installed
        ? '<div class="err"><strong>SCIM is not loaded in this ' +
          'process.</strong> The module registers no routes here, so there ' +
          'is nothing to report. Everything else on this console is ' +
          'unaffected.</div>'
        : '') +

      // WHERE THE TRAFFIC QUESTION IS ANSWERED. This page keeps the headline
      // counts — a page about a surface with no evidence anything ever called
      // it is a page about a hypothesis — and everything past them is over
      // there: who is calling, how long it took, what came back, and the last
      // fifty requests individually. Both are drawn from ONE set of counters
      // in `admin_stats.js` through two functions, so there is no second
      // tally to disagree with this one.
      kit.note(t.html('consoleScim.headline1') + ' <strong><a ' +
      'href="/admin/scim/monitor">' + t.html('consoleScim.linkMonitoringScim') +
      '</a></strong> ' + t.html('consoleScim.headline2')) +
      (json.installed && !json.enabled
        ? kit.warn(t.html('consoleScim.turnedOff'))
        : '') +

      kit.note(t.html('consoleScim.about1') + ' <code>' +
      kit.esc(json.baseUrl || '/scim/v2') + '</code>' +
      t.html('consoleScim.about2') + ' <a href="/admin/users">' +
      t.html('consoleScim.linkUsers') + '</a>' + t.html('consoleScim.about3') +
      ' <a href="/admin/vc">' + t.html('consoleScim.linkCredentialClaims') +
      '</a> ' +
      t.html('consoleScim.about4') + ' <a ' +
      'href="/admin/groups">' + t.html('consoleScim.linkGroups') + '</a>' +
      t.html('consoleScim.fullStop')) +

      // Whether the credential is currently required is a select, so the
      // clause sits inside the one bolded sentence it belongs to.
      kit.warn(t.html('consoleScim.credentialWarn', {
        off: json.authentication && !json.authentication.required
          ? 'yes' : 'no' })) +

      tiles +

      (json.authentication ?
       ScimPage.authenticationSection(t, json.authentication, counters) :
       '') +

      '<h2>' + t.html('consoleScim.operations') + '</h2>' +
      kit.note(t.html('consoleScim.operationsNote')) +
      '<table><tr><th>' + t.html('consoleScim.colOperation') +
      '</th><th class="num">' + t.html('consoleScim.colCount') + '</th><th>' +
      t.html('consoleScim.colWhatItIs') + '</th></tr>' +
      operationRows + '</table>' +

      '<h2>' + t.html('consoleScim.byResourceType') + '</h2>' +
      '<table><tr><th>' + t.html('consoleScim.colResourceType') +
      '</th><th class="num">' + t.html('consoleScim.colCount') + '</th></tr>' +
      typeRows +
      '</table>' +

      '<h2>' + t.html('consoleScim.whatWentBack') + '</h2>' +
      kit.note(t.html('consoleScim.whatWentBackNote')) +
      '<div class="tiles" style="align-items:flex-start">' +
      '<div><table><tr><th>' + t.html('consoleScim.colStatus') +
      '</th><th class="num">' + t.html('consoleScim.colCount') + '</th></tr>' +
      statusRows +
      '</table></div>' +
      '<div><table><tr><th>scimType</th><th class="num">' +
      t.html('consoleScim.colCount') + '</th></tr>' +
      scimTypeRows + '</table></div></div>' +

      (json.identifiers
        ? '<h2>' + t.html('consoleScim.idIsDn') + '</h2>' +
          kit.note(kit.esc(json.identifiers.why)) +
          kit.note(t.html('consoleScim.forExample') + ' <code>' +
                    kit.esc(json.identifiers.example) +
          '</code>')
        : '') +

      (endpointRows
        // NOT "Endpoints": that heading is the realm's addresses, which
        // `respond()` draws at the top of every Protocols page. This table is
        // what each operation DOES, by method and path under `/scim/v2`.
        ? '<h2>' + t.html('consoleScim.whatEachDoes') + '</h2><table><tr><th>' +
          t.html('consoleScim.colMethod') + '</th>' +
          '<th>' + t.html('consoleScim.colPath') + '</th><th>' +
          t.html('consoleScim.colWhat') + '</th></tr>' + endpointRows +
          '</table>'
        : '') +

      (json.doesNotDo.length
        ? '<h2>' + t.html('consoleScim.doesNotDo') + '</h2><ul>' +
          json.doesNotDo.map(function (text) {
            return ScimPage.bullet(kit.esc(text));
          }).join('') + '</ul>'
        : '') +

      (negativeRows
        ? '<h2>' + t.html('consoleScim.makeFail') + '</h2>' +
          kit.note(t.html('consoleScim.makeFailNote')) +
          '<table><tr><th>' + t.html('consoleScim.colDoThis') + '</th><th>' +
          t.html('consoleScim.colGetThis') + '</th></tr>' + negativeRows +
          '</table>'
        : '') +

      '<h2>' + t.html('consoleScim.userMapping') + '</h2>' +
      kit.note(t.html('consoleScim.mapping1') + ' <a href="/admin/vc">' +
      t.html('consoleScim.linkCredentialClaims') + '</a> ' +
      t.html('consoleScim.and') +
      ' <a href="/admin/claims">' + t.html('consoleScim.linkCustomClaims') +
      '</a> ' +
      t.html('consoleScim.mapping2')) +
      mappingTable(json.mapping.user) +

      '<h2>' + t.html('consoleScim.groupMapping') + '</h2>' +
      mappingTable(json.mapping.group) +

      // THIS PAGE USED TO SAY IT HAD NO CONTROLS, and the sentence it said it
      // in was the one every other page here cited: "a form here would be a
      // second door to one setting". What that argument was actually
      // protecting is the ONE-STORE rule, and the form below does not break
      // it — it is `configSection()`, posting to the same action against the
      // same override map as /admin/config, which is the arrangement
      // /admin/token-lifetimes established. What has changed is only which
      // page draws the door.
      SettingsForms.forms(json.settings, '/admin/scim', undefined, t) +
      kit.note(t.html('consoleScim.settingsNote') + ' <a ' +
      'href="/admin/users">' + t.html('consoleScim.linkUsers') + '</a> ' +
      t.html('consoleScim.and') + ' <a ' +
      'href="/admin/groups">' + t.html('consoleScim.linkGroups') + '</a>' +
      t.html('consoleScim.fullStop')) +

      kit.note('<a href="/scim">' + t.html('consoleScim.footerForAPerson') +
      '</a> &middot; ' +
      '<a href="/admin/scim/monitor">' + t.html('consoleScim.footerAskedToDo') +
      '</a> &middot; <a href="/admin/scim?format=json">' +
      t.html('consoleScim.footerAsJson') +
      '</a> &middot; <a href="/admin-api/scim">' +
      t.html('consoleScim.footerOverApi') +
      '</a> &middot; <a href="/admin/ldap/service">' +
      t.html('consoleScim.footerDirectory') + '</a>');

    return inner;
  }

  // ---------------------------------------------------------------------------
  // THE AUTHENTICATION SECTION OF /admin/scim.
  //
  // Two tables and a list, and the division between them is the one this page
  // already draws everywhere else: the SCHEMES come from scim.js's
  // description() — which is scim_auth.js's table, the same one that builds the
  // WWW-Authenticate challenge and the ServiceProviderConfig — while the COUNTS
  // come from admin_stats.js. So a scheme that is offered cannot be missing
  // from this page and a count cannot be attributed to a scheme that does not
  // exist.
  //
  // Every scheme is drawn INCLUDING the ones at zero and the ones turned off,
  // for the reason the operations table below draws its zeroes: "can I use
  // Digest against this server" is the question somebody arrives with, and a
  // table that listed only what had been used would answer it by omission.
  //
  // There are no CONTROLS in this section, which is what keeps rule 7 satisfied
  // with only a GET on /admin-api/scim: every one of these is a config.js row,
  // drawn in the page's settings block (`configFormsFor('/admin/scim')`), which
  // posts to /admin/config — and POST /admin-api/config/set already has the
  // operation. A second form here would be a second door to one setting.
  // ---------------------------------------------------------------------------
  /**
   * Draws the Authentication section of /admin/scim: every scheme with its
   * state, scope and request count, the anonymous and refused counts, and
   * the access control policy.
   *
   * @param t - the page's translator (#539)
   * @param auth - the authentication description from scim.js
   * @param counters - the SCIM counters, with byAuthScheme
   * @returns the section as HTML
   */
  static authenticationSection(t, auth, counters) {
    const counts = (counters && counters.byAuthScheme) || {};
    const rows = auth.schemes.map(function (row) {
      return '<tr><td>' + kit.esc(row.name) +
        (row.primary ? ' <span class="sub">' + t.html('consoleScim.primary') +
         '</span>' : '') +
        // The scheme's description is scim_auth.js's own and is a paragraph on
        // every row, so five of them made this the longest table on the page
        // while the column somebody scans — the scheme's NAME — was one line.
        kit.note(kit.esc(row.description)) + '</td>' +
        '<td><code>' + kit.esc(row.type) + '</code>' +
        (row.canonical ? '' : '<div class="sub">' +
          t.html('consoleScim.noCanonical') + '</div>') +
          '</td>' +
        '<td>' + (row.enabled
          ? '<span class="state-valid">' + t.html('consoleScim.offered') +
            '</span>'
          : '<span class="state-none">' + t.html('consoleScim.off') +
            '</span>') +
        '<div class="sub"><code>' + kit.esc(row.setting) +
        '</code></div></td>' +
        '<td>' + (row.scoped ? t.html('consoleScim.whatItsScopesSay') :
                  t.html('consoleScim.everything')) + '</td>' +
        '<td class="num">' + (counts[row.id] || 0) + '</td></tr>';
    }).join('');
    const extra = ['anonymous', 'refused'].map(function (name) {
      return '<tr><td>' + kit.esc(name === 'anonymous'
        ? t.text('consoleScim.rowAnonymous')
        : t.text('consoleScim.rowRefused')) +
          '</td><td></td><td></td><td></td>' +
        '<td class="num">' + (counts[name] || 0) + '</td></tr>';
    }).join('');
    const policy = auth.policy.map(function (text) {
      return ScimPage.bullet(kit.esc(text));
    }).join('');
    // The realm, the scopes, the algorithms and the HOBA path are the view's
    // and are escaped here, between the messages, as they always were.
    const out = '<h2>' + t.html('consoleScim.authentication') + '</h2>' +
      kit.note(t.html('consoleScim.authNote1') + ' <code>' +
      kit.esc(auth.realm) + '</code>' +
      t.html('consoleScim.authNote2',
             { open: auth.discoveryOpen ? 'yes' : 'no' })) +
      '<table><tr><th>' + t.html('consoleScim.colScheme') + '</th><th>' +
      t.html('consoleScim.colType') + '</th><th>' +
      t.html('consoleScim.colState') +
      '</th><th>' + t.html('consoleScim.colMayDo') + '</th>' +
      '<th class="num">' + t.html('consoleScim.colRequests') + '</th></tr>' +
      rows +
      extra + '</table>' +
      kit.note(t.html('consoleScim.scopes1') + ' <code>' +
      kit.esc(auth.scopes.read) +
      '</code> ' + t.html('consoleScim.and') + ' <code>' +
      kit.esc(auth.scopes.write) + '</code> ' + t.html('consoleScim.scopes2') +
      ' ' +
      kit.esc(auth.digestAlgorithms.join(', ')) +
      t.html('consoleScim.scopes3') +
      ' <code>' + kit.esc(auth.hobaRegistration) + '</code> ' +
      t.html('consoleScim.scopes4') + ' <a ' +
      'href="/admin/users">' + t.html('consoleScim.linkUsers') + '</a> ' +
      t.html('consoleScim.showsThem')) +
      '<h3>' + t.html('consoleScim.accessPolicy') + '</h3><ul class="note">' +
      policy + '</ul>';
    return out;
  }

  // One item of a prose list — the *what it deliberately does not do* lists,
  // and nothing else. Every one of those bullets opens with a bolded headline
  // and then argues it for a paragraph, which is exactly the shape a fold
  // suits: the list stays a list of claims, and the argument for each is under
  // it.
  /**
   * Draws one item of a prose list, folded when longer than a line.
   *
   * An item opening with a link is never folded; one opening with `<code>`
   * keeps it in the summary.
   *
   * @param html - the item as HTML
   * @param label - optional; a summary, which also forces the fold
   * @returns the `<li>` as HTML
   */
  static bullet(html, label?) {
    // The kit's since #446: the LDAP service page draws the same list.
    return kit.bullet(html, label);
  }

  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static monitorBody(ctx, json) {
    const t = ctx.t;
    const c: any = json.counters;

    const tiles = '<div class="tiles">' +
      kit.tile(c.calls, t.text('consoleScim.tileApiCalls')) +
      kit.tile(c.ok, t.text('consoleScim.tileSuccessful')) +
      kit.tile(c.failed, t.text('consoleScim.tileFailed')) +
      kit.tile(c.successRate === null ? '—' : c.successRate + '%',
                t.text('consoleScim.tileSuccessRate')) +
      kit.tile(c.authentication.distinct, t.text('consoleScim.tileClients')) +
      kit.tile(c.latency.averageMs === null ? '—' : c.latency.averageMs +
                ' ms',
                t.text('consoleScim.tileAverage')) +
      '</div>';

    // THE BREAKDOWN BY CALL TYPE, which is the table this page exists for.
    // Every operation the server implements is drawn INCLUDING the ones at
    // zero — the vocabulary is admin_stats.js's SCIM_OPERATIONS, so an
    // operation cannot be performed and go unreported nor be reported and
    // never occur.
    const operationRows = c.operations.map(function (row) {
      return '<tr><td>' +
        (row.method ? '<code>' + kit.esc(row.method) + '</code> ' : '') +
        kit.esc(row.label) + '</td>' +
        '<td class="num">' + row.count + '</td>' +
        '<td class="num">' + row.ok + '</td>' +
        '<td class="num">' + row.failed + '</td>' +
        '<td class="num">' + (row.averageMs === null ? '—' :
                              row.averageMs) + '</td><td ' +
        'class="num">' + (row.maxMs === null ? '—' : row.maxMs) + '</td>' +
        '<td class="num">' + row.bytes + '</td>' +
        '<td class="sub">' + kit.esc(row.what) + '</td></tr>';
    }).join('');

    const resourceRows = c.resourceTypes.map(function (row) {
      return '<tr><td><code>' + kit.esc(row.resourceType) + '</code></td>' +
        '<td class="num">' + row.count + '</td></tr>';
    }).join('');

    // THE CLIENTS. Sorted busiest first by the snapshot, because that and
    // "most recent" are the two orders somebody reading a traffic page wants
    // and alphabetical is neither.
    const clientRows = c.clients.map(function (row) {
      return '<tr><td>' + kit.shortened(row.principal, 40) + '</td>' +
        '<td>' + (row.kind === 'application'
          ? t.html('consoleScim.kindApplication') + ' <span class="sub">' +
            t.html('consoleScim.aClientId') + '</span>'
          : t.html('consoleScim.kindIdentity')) + '</td>' +
        '<td>' + row.schemes.map(function (s) {
          return '<code>' + kit.esc(s) + '</code>';
        }).join(' ') + '</td>' +
        '<td class="num">' + row.calls + '</td>' +
        '<td class="num">' + row.ok + '</td>' +
        '<td class="num">' + row.failed + '</td>' +
        '<td>' + kit.esc(row.lastOperation || '—') + ' <span class="sub">' +
        kit.esc(row.lastStatus || '') + '</span></td>' +
        '<td class="sub">' + kit.esc(kit.whenText(row.firstAt)) + '</td>' +
        '<td class="sub">' + kit.esc(kit.whenText(row.lastAt)) +
        '</td></tr>';
    }).join('') || '<tr><td colspan="9">' +
      t.html('consoleScim.noClients') + ' ' +
      (json.authRequired
        ? t.html('consoleScim.noClientsGateOn')
        : t.html('consoleScim.noClientsGateOff')) +
      '</td></tr>';

    // The scheme table, with the declared vocabulary first and anything
    // counted under a name it does not declare after it.
    const declared = {};
    const schemeRows = json.schemes.map(function (row) {
      declared[row.id] = true;
      return ScimPage.scimSchemeRow(t, row.id, row.name, row.enabled,
                                c.authentication.byScheme[row.id] || 0,
                                kit.esc(row.spec || ''));
    }).join('') +
    ScimPage.scimSchemeRow(t, 'anonymous', '', null,
                       c.authentication.byScheme.anonymous || 0,
      t.html('consoleScim.schemeAnonymous')) +
    ScimPage.scimSchemeRow(t, 'refused', '', null,
                       c.authentication.byScheme.refused || 0,
      t.html('consoleScim.schemeRefused')) +
    Object.keys(c.authentication.byScheme).sort().filter(function (id) {
      return !declared[id] && id !== 'anonymous' && id !== 'refused';
    }).map(function (id) {
      return ScimPage.scimSchemeRow(t, id, '', null,
                                    c.authentication.byScheme[id],
        t.html('consoleScim.schemeUndeclared'));
    }).join('');

    const statusClassRows = Object.keys(c.byStatusClass).sort()
      .map(function (k) {
      return '<tr><td><code>' + kit.esc(k) + '</code></td><td class="num">' +
        c.byStatusClass[k] + '</td></tr>';
    }).join('') ||
      '<tr><td colspan="2">' + t.html('consoleScim.nothingAnswered') +
      '</td></tr>';

    const statusRows = Object.keys(c.byStatus).sort().map(function (code) {
      return '<tr><td><code>' + kit.esc(code) + '</code></td><td ' +
        'class="num">' +
        c.byStatus[code] + '</td></tr>';
    }).join('') ||
      '<tr><td colspan="2">' + t.html('consoleScim.nothingAnswered') +
      '</td></tr>';

    const scimTypeRows = Object.keys(c.byScimType).sort()
      .map(function (name) {
      return '<tr><td><code>' + kit.esc(name) + '</code></td><td ' +
        'class="num">' +
        c.byScimType[name] + '</td></tr>';
    }).join('') ||
      '<tr><td colspan="2">' + t.html('consoleScim.nothingRefused') +
      '</td></tr>';

    const recentRows = c.recent.map(function (row) {
      return '<tr><td class="sub">' + kit.esc(kit.whenText(row.at)) +
             '</td>' +
        '<td>' +
        (row.method ? '<code>' + kit.esc(row.method) + '</code> ' : '') +
        kit.esc(row.operation) + '</td>' +
        '<td><code>' + kit.esc(row.resourceType) + '</code></td>' +
        '<td>' +
        (row.ok ? '<span class="state-valid">' + kit.esc(row.status) +
         '</span>'
                         : '<span class="state-revoked">' +
                           kit.esc(row.status) +
                           '</span>') +
        (row.scimType ? ' <span class="sub">' + kit.esc(row.scimType) +
         '</span>' :
         '') +
        '</td>' +
        '<td>' + (row.principal ? kit.shortened(row.principal, 24)
                                : '<span class="sub">' +
                                  kit.esc(row.scheme) +
                                  '</span>') +
        '</td>' +
        '<td class="num">' + (row.ms === null ? '—' : row.ms) + '</td>' +
        '<td class="num">' + row.bytes + '</td></tr>';
    }).join('') ||
      '<tr><td colspan="7">' + t.html('consoleScim.nothingCalled') +
      '</td></tr>';

    const inner = (!json.installed
        ? '<div class="err"><strong>SCIM is not loaded in this ' +
          'process.</strong> The module registers no routes here, so there ' +
          'is no traffic to report and the zeroes below mean "no such ' +
          'endpoint" rather than "no calls". Everything else on this ' +
          'console is unaffected.</div>'
        : '') +
      (json.installed && !json.enabled
        ? kit.warn(t.html('consoleScim.monitorOff') +
          ' <a href="/admin/scim">' +
          t.html('consoleScim.linkProtocolsScim') + '</a>' +
          t.html('consoleScim.fullStop'))
        : '') +

      // Split at its two values and its two links; the instant and the
      // realm's name are escaped here as they always were.
      kit.note(t.html('consoleScim.monitorIntro1') + ' <code>' +
      kit.esc(kit.whenText(c.since)) + '</code>' +
      t.html('consoleScim.monitorIntro2') + ' <code>' +
      kit.esc(c.realm.name || c.realm.id ||
      t.text('consoleScim.theDefaultRealm')) + '</code>' +
      t.html('consoleScim.monitorIntro3') + ' <a ' +
      'href="/admin/audit">' + t.html('consoleScim.linkAuditLog') + '</a>' +
      t.html('consoleScim.monitorIntro4') + ' <a ' +
      'href="/admin/scim">' + t.html('consoleScim.linkProtocolsScim') + '</a>' +
      t.html('consoleScim.monitorIntro5')) +

      tiles +

      '<h2>' + t.html('consoleScim.byCallType') + '</h2>' +
      kit.note(t.html('consoleScim.byCallTypeNote')) +
      '<table><tr><th>' + t.html('consoleScim.colOperation') +
      '</th><th class="num">' + t.html('consoleScim.colCalls') + '</th>' +
      '<th class="num">' + t.html('consoleScim.colOk') +
      '</th><th class="num">' +
      t.html('consoleScim.colFailed') + '</th>' +
      '<th class="num">' + t.html('consoleScim.colAvgMs') +
      '</th><th class="num">' +
      t.html('consoleScim.colMaxMs') + '</th>' +
      '<th class="num">' + t.html('consoleScim.colBytesOut') + '</th><th>' +
      t.html('consoleScim.colWhatItIs') + '</th></tr>' +
      operationRows + '</table>' +

      '<h2>' + t.html('consoleScim.byResourceType') + '</h2>' +
      '<table><tr><th>' + t.html('consoleScim.colResourceType') +
      '</th><th class="num">' + t.html('consoleScim.colCalls') + '</th></tr>' +
      resourceRows + '</table>' +

      '<h2>' + t.html('consoleScim.clients') + '</h2>' +
      kit.note(t.html('consoleScim.clientsNote')) +
      '<div class="tiles">' +
      kit.tile(c.authentication.distinct,
               t.text('consoleScim.tileDistinctClients')) +
      kit.tile(c.authentication.identities,
               t.text('consoleScim.tilePeopleShort')) +
      kit.tile(c.authentication.applications,
               t.text('consoleScim.tileApplications')) +
      kit.tile(c.authentication.anonymous,
               t.text('consoleScim.tileAnonymousCalls')) +
      kit.tile(c.authentication.refused,
               t.text('consoleScim.tileRefusedAtGate')) +
      '</div>' +
      (c.authentication.capped
        ? kit.warn(t.html('consoleScim.capped',
                          { cap: c.authentication.cap }))
        : '') +
      '<table><tr><th>' + t.html('consoleScim.colPrincipal') + '</th><th>' +
      t.html('consoleScim.colKind') + '</th><th>' +
      t.html('consoleScim.colSchemes') +
      '</th><th ' +
      'class="num">' + t.html('consoleScim.colCalls') +
      '</th><th class="num">' +
      t.html('consoleScim.colOk') + '</th><th ' +
      'class="num">' + t.html('consoleScim.colFailed') + '</th><th>' +
      t.html('consoleScim.colLast') + '</th><th>' +
      t.html('consoleScim.colFirstSeen') +
      '</th><th>' + t.html('consoleScim.colLastSeen') + '</th></tr>' +
      clientRows + '</table>' +

      '<h2>' + t.html('consoleScim.byScheme') + '</h2>' +
      kit.note(t.html('consoleScim.bySchemeNote')) +
      '<table><tr><th>' + t.html('consoleScim.colScheme') + '</th><th>' +
      t.html('consoleScim.colEnabled') + '</th><th class="num">' +
      t.html('consoleScim.colCalls') + '</th>' +
      '<th>' + t.html('consoleScim.colNotes') + '</th></tr>' + schemeRows +
      '</table>' +

      '<h2>' + t.html('consoleScim.whatWentBack') + '</h2>' +
      kit.note(t.html('consoleScim.whatWentBackMonitorNote')) +
      '<div class="tiles" style="align-items:flex-start">' +
      '<div><table><tr><th>' + t.html('consoleScim.colClass') +
      '</th><th class="num">' + t.html('consoleScim.colCount') + '</th></tr>' +
      statusClassRows + '</table></div>' +
      '<div><table><tr><th>' + t.html('consoleScim.colStatus') +
      '</th><th class="num">' + t.html('consoleScim.colCount') + '</th></tr>' +
      statusRows + '</table></div>' +
      '<div><table><tr><th>scimType</th><th class="num">' +
      t.html('consoleScim.colCount') + '</th></tr>' +
      scimTypeRows + '</table></div></div>' +

      '<h2>' + t.html('consoleScim.volume') + '</h2>' +
      '<div class="tiles">' +
      kit.tile(c.bytesOut, t.text('consoleScim.tileBytesReturned')) +
      kit.tile(c.latency.maxMs, t.text('consoleScim.tileSlowest')) +
      kit.tile(c.latency.totalMs, t.text('consoleScim.tileTotalTime')) +
      '</div>' +
      // THE TWO INSTANTS ARE A SENTENCE AND NOT TWO MORE TILES. A tile draws
      // its value in the headline face, and a timestamp there is twenty-four
      // characters set like a three-digit count — it reads as the most
      // important figure on the page and is the least. Every other tile in
      // this console holds a number for the same reason.
      // The two instants are ISO strings or a dash, so they go in as
      // parameters.
      kit.note(t.html('consoleScim.volumeNote', {
        first: kit.whenText(c.firstAt), last: kit.whenText(c.lastAt) })) +

      '<h2>' + t.html('consoleScim.lastCalls', { n: c.recentCap }) +
      '</h2>' +
      kit.note(t.html('consoleScim.recentNote1', { n: c.recentCap }) +
      ' <a href="/admin/audit">' + t.html('consoleScim.linkAuditLog') + '</a>' +
      t.html('consoleScim.recentNote2')) +
      '<table><tr><th>' + t.html('consoleScim.colWhen') + '</th><th>' +
      t.html('consoleScim.colOperation') + '</th><th>' +
      t.html('consoleScim.colResource') +
      '</th><th>' +
      t.html('consoleScim.colStatus') + '</th><th>' +
      t.html('consoleScim.colWho') +
      '</th><th class="num">ms</th><th ' +
      'class="num">' + t.html('consoleScim.colBytes') + '</th></tr>' +
      recentRows + '</table>' +

      (json.store
        ? '<h2>' + t.html('consoleScim.whatItWrote') + '</h2>' +
          // The opening sentence carries no HTML entity, deliberately: the
          // console derives an h2 tooltip from it through plainTextOf() and
          // esc(), which leaves an entity showing as its own source text.
          // Every other note here happens to be cut before its first one;
          // this was the first that was not, and rewording it was cheaper
          // than teaching the tooltip pass to decode.
          kit.note(t.html('consoleScim.wrote1') + ' <a ' +
          'href="/admin/users">' + t.html('consoleScim.linkUsers') + '</a> ' +
          t.html('consoleScim.and') + ' <a ' +
          'href="/admin/groups">' + t.html('consoleScim.linkGroups') + '</a> ' +
          t.html('consoleScim.wrote2')) +
          '<div class="tiles">' +
          kit.tile(json.store.userCount, t.text('consoleScim.tilePeople')) +
          kit.tile(json.store.groupCount, t.text('consoleScim.tileGroups')) +
          kit.tile(json.store.entryCount + ' / ' + json.store.maxEntries,
                    t.text('consoleScim.tileEntries')) +
          '</div>'
        : '') +

      kit.note(t.html('consoleScim.noReset1') + ' <a href="/admin/audit">' +
      t.html('consoleScim.linkAuditLog') + '</a>' +
      t.html('consoleScim.noReset2')) +

      kit.note('<a href="/admin/scim">' + t.html('consoleScim.footerSurface') +
      '</a> &middot; <a href="/admin/scim/monitor?format=json">' +
      t.html('consoleScim.footerAsJson') +
      '</a> &middot; <a href="/admin-api/scim/monitor">' +
      t.html('consoleScim.footerOverApi') +
      '</a> &middot; <a href="/admin/audit">' +
      t.html('consoleScim.footerDurable') +
      '</a> &middot; <a href="/admin/metrics">' +
      t.html('consoleScim.footerByRoute') + '</a>');

    return inner;
  }

  // One row of the by-scheme table. Not folded into the page body because the
  // same rows are wanted in two orders — the schemes the surface declares, then
  // anything counted under a name it does not declare — and a second copy of
  // the markup is how the two come to be formatted differently.
  /**
   * Draws one row of the SCIM by-scheme table.
   *
   * @param t - the page's translator (#539)
   * @param id - the scheme's id
   * @param name - optional; the scheme's name
   * @param enabled - true, false, or null when the state does not apply
   * @param count - the number of requests counted under it
   * @param note - optional; a note for the last cell, as HTML
   * @returns the table row as HTML
   */
  static scimSchemeRow(t, id, name, enabled, count, note) {
    return '<tr><td><code>' + kit.esc(id) + '</code>' +
      (name ? ' ' + kit.esc(name) : '') + '</td>' +
      '<td>' + (enabled === null ? '<span class="sub">—</span>'
        : (enabled ? '<span class="state-valid">' + t.html('consoleScim.on') +
                     '</span>'
                   : '<span class="state-none">' + t.html('consoleScim.off') +
                     '</span>')) + '</td>' +
      '<td class="num">' + count + '</td>' +
      '<td class="sub">' + (note || '') + '</td></tr>';
  }
}

export = ScimPage;
