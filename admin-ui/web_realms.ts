// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_realms.ts
//
// ---------------------------------------------------------------------------
// TRUST REALMS, DRAWN FROM ITS VIEW ALONE (#446, 2026-10-05).
//
// Draws `/admin/realms` from the answer of `GET /admin-api/realms`: every
// realm, the form that makes one, the support table — what a realm separates
// and what it shares — and the settings.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// It was drawn inside the route of `method:realmsListPage` in
// `admin-ui/admin.ts`, which still draws the page until the console's cutover
// by calling this with its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');
import SettingsForms = require('./web_settings');

type Json = any;

/**
 * Draws `/admin/realms` from the answer of `GET /admin-api/realms`: every
 * realm, the form that makes one, the support table — what a realm separates
 * and what it shares — and the settings.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class RealmsPage {
  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static body(ctx, json) {
    const listView = kit.listViewOf('/admin/realms', ctx.query);
    const pg = json.paging;
    const rows = json.realms.slice((pg.page - 1) * pg.perPage,
                                   pg.page * pg.perPage).map(function (row) {
      const href = '/admin/realms' + kit.queryWith(listView, { realm: row.id });
      return '<tr><td><a href="' + kit.esc(href) + '"><code>' +
             kit.esc(row.id) +
        '</code></a>' +
        (row.builtin ? ' <span class="why">built in</span>' : '') +
        (row.retiring
          ? ' <span class="none">' + (row.retiring.interrupted
              ? 'removal interrupted' : 'being removed') + '</span>'
          : '') +
        '</td><td>' + kit.esc(row.name) + '</td>' +
        '<td><code>' + kit.esc(row.domain) + '</code></td>' +
        '<td><code>' + kit.esc(row.pathPrefix || '/') + '</code></td>' +
        '<td><code>' + kit.esc(row.kid) + '</code></td>' +
        '<td class="num">' + row.settings.length + '</td></tr>';
    }).join('');

    const carryBack = '<input type="hidden" name="back" value="' +
      kit.esc(kit.queryWith(listView, {})) + '">';

    // THE REALMS BEING REMOVED (#294), above everything else on the page:
    // an interrupted one refuses every sign-in in it until somebody finishes
    // the removal, and nothing else in this console says so.
    const retiringRows = json.realms.filter(function (row) {
      return !!row.retiring;
    });
    const retiringBlock = retiringRows.map(function (row) {
      return RealmsPage.retiringNotice(row, carryBack, json.current);
    }).join('');

    const inner =
      '<p class="sub">' + json.count + ' realm(s). Everything under a ' +
      'realm\'s prefix is that realm; everything under no prefix is the ' +
      'default one.</p>' +
      retiringBlock +
      RealmsPage.realmsCaveat(json.persistence) +

      // `realms.active()` IS FALSE FOR TWO DIFFERENT REASONS AND THIS USED TO
      // NAME ONLY ONE OF THEM. It is `realms.size > 0 &&
      // config.value('realms.enabled')`, and the banner here said
      // "`realms.enabled` is false" whenever it came back false — which on a
      // service with the setting ON and no realm yet defined is a page
      // asserting something untrue about a setting a reader can go and look at.
      // That is the worst shape a console message can take: it sent somebody to
      // Configuration to turn on a thing that was already on.
      //
      // So the two states are told apart, and the second is not a warning at
      // all. "The flag is on and nothing has been defined" is the ORDINARY
      // state of this service — the contract `common/realms.js` states is that
      // a service with no realms defined behaves exactly as it did before
      // realms existed — so it is a note saying what to do next, not a yellow
      // box saying something is wrong.
      (json.active
        ? ''
        : !json.enabled
          ? kit.warn('<strong>Trust realms are switched off.</strong> ' +
            '<code>realms.enabled</code> is false, so every prefix below ' +
            'answers 404 and this whole service is the default realm. The ' +
            'definitions are untouched — that is what this setting is for: ' +
            'it lets a realm be ruled out as the cause of something without ' +
            'anything being deleted. Turn it back on in the settings at the ' +
            'foot of this page.')
          : kit.note('<strong>Trust realms are switched ON and none has ' +
            'been defined, which is this service\'s ordinary state rather ' +
            'than something to fix.</strong> <code>realms.enabled</code> is ' +
            '<code>true</code>; the feature does nothing until a realm ' +
            'exists, because the built-in <code>default</code> realm has an ' +
            'empty prefix and IS this service. That is a property rather ' +
            'than a coincidence — a service with no realm defined behaves ' +
            'exactly as it did before realms existed, which is what keeps ' +
            'every client, container and test that predates them working ' +
            'unchanged. <strong>Define one below</strong> and its prefix ' +
            'starts answering immediately: a switcher appears on every page ' +
            'of this console, and <code>GET /realms</code> starts reporting ' +
            '<code>active: true</code>.')) +

      '<h2>The realms</h2><table><tr><th>Id</th><th>Name</th>' +
      '<th>Domain</th><th>Path prefix</th><th>Signing key</th><th ' +
      'class="num">Settings</th></tr>' + rows + '</table>' +
      kit.pageNavPair('/admin/realms', kit.pageParamsOf(ctx.query), pg).head +
      kit.perPageForm('/admin/realms', 'per', ctx.query.per, pg.perPage, '',
                       listView) +

      '<h2>Define a realm</h2>' +
      kit.note('The id becomes a path segment, so it is lower-case letters, ' +
      'digits and hyphens. It may not be <code>default</code> and it may not ' +
      'be the first segment of a path this service already serves — ' +
      (json.reserved.length ? kit.codeList(json.reserved.slice(0, 12)) +
        (json.reserved.length > 12 ? ' and ' + (json.reserved.length - 12) +
         ' ' +
            'more' : '')
        : 'nothing is registered yet') +
      ' — whatever <code>realms.pathSegment</code> is set to, precisely so ' +
      'that clearing that setting cannot turn an existing realm into a ' +
      'shadow over the console or the authorization server.') +
      kit.note('<strong>The domain</strong> — <code>iyasec.io</code>, ' +
      '<code>dev.iyasec.io</code> — is the root of every NAME the realm ' +
      'invents: its directory is a tree of its own at the RFC 2247 mapping ' +
      'of it (<code>iyasec.io</code> is <code>dc=iyasec,dc=io</code>), its ' +
      'Kerberos realm is the domain in capitals, its SPIFFE trust domain is ' +
      'the domain, and its identity providers call themselves ' +
      '<code>urn:&lt;domain&gt;:idp</code>. It is not where the realm is ' +
      'REACHED — the issuer and every URL still come from the host a request ' +
      'arrived on. No two realms may share one; one inside another\'s is ' +
      'allowed and is a separate tree. <strong>It is fixed once the realm is ' +
      'created.</strong> Left empty it is <code>&lt;id&gt;.' +
      kit.esc(json.defaultDomain) + '</code>.') +
      '<form method="post" action="/admin/realms">' + carryBack +
      '<input type="hidden" name="action" value="create"><div ' +
      'class="formrow"><label for="rid">Id</label><input type="text" ' +
      'id="rid" name="id" size="16" placeholder="acme" required><label ' +
      'for="rname">Name</label><input type="text" id="rname" name="name" ' +
      'size="22" placeholder="Acme Corporation"><label ' +
      'for="rdomain">Domain</label><input type="text" id="rdomain" ' +
      'name="domain" size="22" placeholder="iyasec.io" ' +
      'autocapitalize="off" spellcheck="false"><label ' +
      'for="rdesc">Description</label><input type="text" id="rdesc" ' +
      'name="description" size="40"><button type="submit">Define ' +
      'it</button></div></form><h2>What is separated, and what is ' +
      'shared</h2><p class="lead">A realm separates what this service ISSUES ' +
      'and everything it is holding while it issues it — keys, sessions, ' +
      'codes, tokens, offers, artifacts, statistics and the audit log — and ' +
      'since each realm has a directory of its own, the people, groups, ' +
      'applications and policies in it. The families on sockets with no ' +
      'path in them are told apart some other way, and a few things belong ' +
      'to the process and are shared. This table is the whole list, ' +
      'and <code>GET /realms</code> answers the same thing to a client that ' +
      'cannot read a console.</p>' +
      RealmsPage.realmSupportTable(json.support) +
      // The realms.* rows. `realms.enabled` is the one that makes every
      // prefixed path in this service answer or not, which is worth being able
      // to see beside the list of realms it governs.
      SettingsForms.forms(json.settings, '/admin/realms');

    return inner;
  }

  // A REALM BEING REMOVED (#262, #294), as a console block: when it began,
  // what it refuses, and — for an INTERRUPTED removal — the button that
  // finishes it, which is the Remove action again (realms.js argues why
  // there is no other). `row` is `realmJson()`'s shape. Drawn on
  // /admin/realms and on the realm's own drill-down; `retiringBanner()` is
  // the line on every other page of the realm.
  /**
   * Draws the notice for a realm being removed: why, what it refuses, and
   * how to finish.
   *
   * An interrupted removal viewed from another realm also gets the button
   * that finishes it.
   *
   * @param row - the realm, in realmJson()'s shape
   * @param carryBack - the hidden back field the form carries, as HTML
   * @param current - the realm this console is being read in
   * @returns the notice as HTML
   */
  static retiringNotice(row, carryBack, current) {
    const state = row.retiring;
    const fromHere = current !== row.id;
    const button = state.interrupted && fromHere
      ? '<form method="post" action="/admin/realms">' + carryBack +
        '<input type="hidden" name="action" value="remove">' +
        '<input type="hidden" name="id" value="' + kit.esc(row.id) + '">' +
        '<button type="submit" class="danger">Finish removing ' +
        kit.esc(row.id) + '</button></form>'
      : '';
    const html = (state.interrupted ? kit.warn.bind(kit)
                                    : kit.note.bind(kit))(
      '<strong>The realm <code>' + kit.esc(row.id) + '</code> ' +
      (state.interrupted ? 'was being removed, and the removal was ' +
                           'interrupted' : 'is being removed') +
      '.</strong> ' + kit.esc(state.why) + ' Refused: ' +
      kit.esc(state.refusing) + '. ' + kit.esc(state.finish) +
      (state.interrupted && !fromHere
        ? ' You are reading this console inside it, so do it from another ' +
          'realm: the switcher at the top of the sidebar.'
        : '')) + button;
    return html;
  }

  /**
   * Draws the table of what trust realms separate and what they share, one
   * row per family, from realms.realmSupport().
   *
   * @param support - `realms.realmSupport()`, from the page's answer
   * @returns the table as HTML
   */
  static realmSupportTable(support) {
    const rows = support.map(function (row) {
      const state = row.state === 'full'
        ? '<span class="m">' + kit.esc(RealmsPage.separatedBy(row.by)) +
          '</span>'
        : (row.state === 'partial'
            ? '<span class="eff" title="Realm-aware, but not wholly">' +
              kit.esc(row.by) + '</span>'
            : '<span class="none">shared</span>');
      // The note is realms.js's own prose and runs to a paragraph on the rows
      // that matter most — the directory's is 1,700 characters — so it folds.
      // What stays on the row is the family and whether it is separated, which
      // is the question somebody scans this table to answer.
      return '<tr><td>' + kit.esc(row.family) + '</td><td>' + state +
             '</td><td>' +
             kit.note(kit.esc(row.note)) + '</td></tr>';
    }).join('');
    return '<table><tr><th>Family</th><th>Separated</th><th>What that ' +
           'means</th></tr>' +
           rows + '</table>';
  }

  // HOW a family is separated, in the words the row itself carries. This used
  // to print the literal "by path" for every `full` row, which was true of all
  // of them until the embedded directory became per realm: LDAP is separated by
  // DN — a subtree per realm inside one naming context — and a table that
  // called that "by path" would be describing the one family whose separation
  // is NOT a path segment as though it were.
  /**
   * Words how a protocol family is separated between realms.
   *
   * @param by - the separation from the realm support row; defaults to path
   * @returns "by DN" for "dn", otherwise "by " and the value
   */
  static separatedBy(by) {
    const how = String(by || 'path');
    return 'by ' + (how === 'dn' ? 'DN' : how);
  }

  /**
   * Draws the caveat on Trust realms.
   *
   * @param store - the persistence store's `persistsRealms` and `mode`
   * @returns the caveat as HTML
   */
  static realmsCaveat(store) {
    return (
      kit.note('<strong>A realm separates what this service ISSUES, ' +
      'not who it knows.</strong> Each realm has its own signing key, so a ' +
      'token minted in one does not verify against another\'s JWKS — that is ' +
      'the point of a realm rather than a side effect. Each realm also has a ' +
      'directory of its own — its own <code>ou=users</code>, ' +
      '<code>ou=groups</code> and <code>ou=applications</code> under ' +
      '<code>dc=&lt;id&gt;</code> — and so <strong>administrators of its ' +
      'own</strong>: the two role groups in that directory administer that ' +
      'realm and nothing outside it, while the default realm\'s two groups ' +
      'administer every realm. A new realm is seeded with an ' +
      '<code>admin</code> account that holds both. The table at ' +
      'the foot of this page is the whole list of what is separated how.') +
      (store.persistsRealms
        ? '<div class="ok"><strong>A realm defined here WILL come ' +
          'back.</strong> ' +
          'This process is running with ' +
          '<code>persistence.mode=' +
          kit.esc(store.mode) + '</code>, ' +
          'so the realm rows — their names, descriptions and per-realm ' +
          'settings — and each realm\'s own directory are written down and ' +
          'restored at the next start. WHAT DOES NOT COME BACK IS THE KEYS: ' +
          'every realm\'s signing key is regenerated on every start, exactly ' +
          'like the default realm\'s, so a token minted in this realm today ' +
          'verifies against nothing tomorrow. See <a ' +
          'href="/admin/persistence">Persistence</a>.</div>'
        : kit.note('<strong>Nothing here is persisted on this ' +
          'process.</strong> Realms are held in memory and die with it, ' +
            'along ' +
          'with the keys they signed with. Define them from <code>POST ' +
          '/admin-api/realms</code> in whatever starts your stack if you ' +
            'want ' +
          'them back — or turn on <a ' +
          'href="/admin/persistence">Persistence</a>, which writes the realm ' +
          'registry and each realm\'s directory down. The ' +
          'KEYS are regenerated on every start either way.')));
  }

  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static detail(ctx, json) {
    const wantedId = kit.queryOne(ctx.query, 'realm').trim();
    const realm = json.realms.filter(function (row) {
      return row.id === wantedId;
    })[0] || null;
    let inner;
    if (!realm) {
      inner = '<div class="err">No realm called <code>' +
              kit.esc(wantedId) +
              '</code> is defined. <a href="/admin/realms">The ' +
              'list</a> is what there is.</div>';
    } else {
      const row = realm;
      const listView = kit.listViewOf('/admin/realms', ctx.query);
      const carryBack = '<input type="hidden" name="back" value="' +
        kit.esc(kit.queryWith(listView, {})) + '">';
      const inRealm = json.current === realm.id;

      const settingRows = row.settings.length
        ? row.settings.map(function (row) {
            return '<tr><td><code>' + kit.esc(row.key) + '</code></td>' +
                   '<td>' + kit.esc(row.label) + '</td>' +
                   '<td><code>' + kit.esc(row.value) + '</code></td>' +
                   '<td><form method="post" action="/admin/realms" ' +
                   'class="inline">' +
                   carryBack + '<input type="hidden" name="action" ' +
                   'value="unset"><input type="hidden" name="id" value="' +
                   kit.esc(realm.id) + '">' +
                   '<input type="hidden" name="key" value="' +
                     kit.esc(row.key) +
                   '"><button type="submit" ' +
                   'class="secondary">Unset</button></form></td></tr>';
          }).join('')
        : '<tr><td colspan="4" class="none">Nothing. This realm is ' +
          'configured ' +
          'exactly as the process is — which is a realm that differs only in ' +
          'its key, its sessions and what it has issued.</td></tr>';

      const endpointRows = Object.keys(row.endpoints).map(function (name) {
        return '<tr><td>' + kit.esc(name) + '</td><td class="who"><a href="' +
               kit.esc(row.endpoints[name]) + '"><code>' +
               kit.esc(row.endpoints[name]) +
               '</code></a></td></tr>';
      }).join('');

      inner =
        '<p class="sub">' + kit.esc(realm.name) +
        (realm.builtin ? ' — the built-in realm' : '') + '</p>' +
        (realm.description ? '<p class="lead">' + kit.esc(realm.description) +
         '</p>' :
         '') +

        (row.retiring ? RealmsPage.retiringNotice(row, carryBack, json.current)
                       : '') +
        (inRealm
          ? '<div class="ok">You are reading this console ' +
            '<strong>inside</strong> this realm. Every settings form in this ' +
            'console writes here.</div>'
          : kit.warn('You are reading this console in the <strong>' +
            kit.esc(json.currentName) + '</strong> realm. The switcher ' +
            'on the left moves to this one; until then a settings form ' +
              'writes ' +
            'to the realm you are in, not to this one.')) +

        '<h2>Its domain</h2>' +
        kit.note('<code>' + kit.esc(row.domain) + '</code>' +
        (realm.builtin ? ', from <code>global.domain</code>' : '') +
        ', fixed ' + (realm.builtin ? 'until a restart with another value'
                                    : 'since the realm was created') +
        '. Its directory is the tree at <code>' + kit.esc(row.baseDn) +
        '</code>, a naming context of its own on the shared LDAP socket, and ' +
        'the names it invents — Kerberos realm, SPIFFE trust domain, entity ' +
        'IDs, the address a development-mode person is given — are built ' +
          'from ' +
        'it; the ones seeded when it was created are among its settings ' +
        'below.') +
        '<h2>Where it answers</h2>' +
        kit.note('Path prefix <code>' +
                  kit.esc(row.pathPrefix || '(none — this is ' +
        'the default realm)') +
          '</code>. Every HTTP endpoint this service has ' +
        'is under it, unchanged: what is <code>/oauth2/token</code> in the ' +
        'default realm is ' +
        '<code>' + kit.esc(row.pathPrefix) + '/oauth2/token</code> here.') +
        '<table><tr><th>Document</th><th>URL</th></tr>' + endpointRows +
        '</table>' +
        kit.note('The signing key is <code>' + kit.esc(row.kid) + '</code>, ' +
        'generated for this realm and held only in memory. A token minted ' +
          'here ' +
        'does not verify against any other realm\'s JWKS, which is what ' +
          'makes ' +
        'two realms two authorization servers rather than one served twice.') +

        '<h2>What this realm sets</h2>' +
        kit.note('Every setting in <a href="/admin/config">this service\'s ' +
        'table</a> can be set per realm, above whatever the process as a ' +
          'whole ' +
        'is configured with and below nothing. The two exceptions are ' +
        '<code>realms.enabled</code> and <code>realms.pathSegment</code>: a ' +
        'realm that could switch realms off, or move the prefix it was found ' +
        'under, would be doing it half way through the request that ' +
        'found it.') +
        '<table><tr><th>Key</th><th>Setting</th><th>Value</th><th></th></tr>' +
        settingRows + '</table>' +
        '<form method="post" action="/admin/realms">' + carryBack +
        '<input type="hidden" name="action" value="set">' +
        '<input type="hidden" name="id" value="' + kit.esc(realm.id) +
        '"><div class="formrow"><label for="skey">Key</label><input ' +
        'type="text" id="skey" name="key" size="30" ' +
        'placeholder="saml.organizationName" required><label ' +
        'for="sval">Value</label><input type="text" id="sval" name="value" ' +
        'size="30"><button type="submit">Set it ' +
        'here</button></div></form><h2>Name and description</h2><form ' +
        'method="post" action="/admin/realms">' + carryBack +
        '<input type="hidden" name="action" value="update">' +
        '<input type="hidden" name="id" value="' + kit.esc(realm.id) + '">' +
        '<div class="formrow"><label for="uname">Name</label>' +
        '<input type="text" id="uname" name="name" size="22" value="' +
        kit.esc(realm.name) + '"><label ' +
        'for="udesc">Description</label><input type="text" id="udesc" ' +
        'name="description" size="46" value="' +
        kit.esc(realm.description) + '">' +
        '<button type="submit">Save</button></div></form>' +

        (realm.builtin
          ? '<h2>It cannot be removed</h2>' +
            kit.note('Every URL this service published before trust realms ' +
            'existed is a URL in this realm, so removing it would remove the ' +
            'service. There is deliberately no button.')
          : '<h2>Remove it</h2>' +
            kit.note('<strong>Everything it holds goes with it</strong> — ' +
              'its ' +
            'sessions, its authorization codes, its tokens, its offers, its ' +
            'service providers, its statistics, its audit log and its ' +
              'signing ' +
            'key. That is deliberate rather than thorough: a realm ' +
              're-created ' +
            'with the same id inheriting the last one\'s sessions would be ' +
              'the ' +
            'single most surprising thing a re-created realm could do. ' +
              'Nothing ' +
            'is removed from the shared directory, because nothing there ' +
            'belongs to a realm.') +
            '<form method="post" action="/admin/realms">' + carryBack +
            '<input type="hidden" name="action" value="remove">' +
            '<input type="hidden" name="id" value="' + kit.esc(realm.id) +
              '">' +
            '<button type="submit" class="danger">Remove ' + kit.esc(realm.id) +
            '</button></form>');

    }

    return inner;
  }
}

export = RealmsPage;
