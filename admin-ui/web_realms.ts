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
    // The page's words are its catalog's (#539); what the view answered —
    // realm names, the support table's prose, a removal's reasons — is
    // drawn as it came.
    const t = ctx.t;
    const listView = kit.listViewOf('/admin/realms', ctx.query);
    const pg = json.paging;
    const rows = json.realms.slice((pg.page - 1) * pg.perPage,
                                   pg.page * pg.perPage).map(function (row) {
      const href = '/admin/realms' + kit.queryWith(listView, { realm: row.id });
      return '<tr><td><a href="' + kit.esc(href) + '"><code>' +
             kit.esc(row.id) +
        '</code></a>' +
        (row.builtin ? ' <span class="why">' +
          t.html('consoleRealms.builtIn') + '</span>' : '') +
        (row.retiring
          ? ' <span class="none">' + (row.retiring.interrupted
              ? t.html('consoleRealms.removalInterrupted')
              : t.html('consoleRealms.beingRemoved')) + '</span>'
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
      return RealmsPage.retiringNotice(row, carryBack, json.current, t);
    }).join('');

    const inner =
      '<p class="sub">' +
      t.html('consoleRealms.count', { count: String(json.count) }) +
      '</p>' +
      retiringBlock +
      RealmsPage.realmsCaveat(json.persistence, t) +

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
          ? kit.warn(t.html('consoleRealms.switchedOff'))
          : kit.note(t.html('consoleRealms.switchedOnNone'))) +

      '<h2>' + t.html('consoleRealms.theRealms') + '</h2><table><tr><th>' +
      t.html('consoleRealms.id') + '</th><th>' +
      t.html('consoleRealms.name') + '</th>' +
      '<th>' + t.html('consoleRealms.domain') + '</th><th>' +
      t.html('consoleRealms.pathPrefix') + '</th><th>' +
      t.html('consoleRealms.signingKey') + '</th><th ' +
      'class="num">' + t.html('consoleRealms.settings') + '</th></tr>' +
      rows + '</table>' +
      kit.pageNavPair('/admin/realms', kit.pageParamsOf(ctx.query), pg).head +
      kit.perPageForm('/admin/realms', 'per', ctx.query.per, pg.perPage, '',
                       listView) +

      '<h2>' + t.html('consoleRealms.defineHeading') + '</h2>' +
      // The reserved segments are code, and sit between two messages: the
      // catalog carries no markup a list of <code> elements would need.
      kit.note(t.html('consoleRealms.idRuleHead') + ' ' +
      (json.reserved.length ? kit.codeList(json.reserved.slice(0, 12)) +
        (json.reserved.length > 12
          ? t.html('consoleRealms.andMore',
                   { n: String(json.reserved.length - 12) })
          : '')
        : t.html('consoleRealms.nothingRegistered')) +
      ' ' + t.html('consoleRealms.idRuleTail')) +
      kit.note(t.html('consoleRealms.domainNote',
                      { defaultDomain: json.defaultDomain })) +
      '<form method="post" action="/admin/realms">' + carryBack +
      '<input type="hidden" name="action" value="create"><div ' +
      'class="formrow"><label for="rid">' + t.html('consoleRealms.id') +
      '</label><input type="text" ' +
      'id="rid" name="id" size="16" placeholder="acme" required><label ' +
      'for="rname">' + t.html('consoleRealms.name') +
      '</label><input type="text" id="rname" name="name" ' +
      'size="22" placeholder="Acme Corporation"><label ' +
      'for="rdomain">' + t.html('consoleRealms.domain') +
      '</label><input type="text" id="rdomain" ' +
      'name="domain" size="22" placeholder="iyasec.io" ' +
      'autocapitalize="off" spellcheck="false"><label ' +
      'for="rdesc">' + t.html('consoleRealms.description') +
      '</label><input type="text" id="rdesc" ' +
      'name="description" size="40"><button type="submit">' +
      t.html('consoleRealms.defineIt') + '</button></div></form><h2>' +
      t.html('consoleRealms.separatedHeading') + '</h2><p class="lead">' +
      t.html('consoleRealms.separatedLead') + '</p>' +
      RealmsPage.realmSupportTable(json.support, t) +
      // The realms.* rows. `realms.enabled` is the one that makes every
      // prefixed path in this service answer or not, which is worth being able
      // to see beside the list of realms it governs.
      SettingsForms.forms(json.settings, '/admin/realms',
                          undefined, t);

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
   * @param t - the page's translator
   * @returns the notice as HTML
   */
  static retiringNotice(row, carryBack, current, t) {
    const state = row.retiring;
    const fromHere = current !== row.id;
    const button = state.interrupted && fromHere
      ? '<form method="post" action="/admin/realms">' + carryBack +
        '<input type="hidden" name="action" value="remove">' +
        '<input type="hidden" name="id" value="' + kit.esc(row.id) + '">' +
        '<button type="submit" class="danger">' +
        t.html('consoleRealms.finishRemoving', { id: row.id }) +
        '</button></form>'
      : '';
    const html = (state.interrupted ? kit.warn.bind(kit)
                                    : kit.note.bind(kit))(
      // Why, what is refused and how to finish are the view's sentences,
      // drawn as they came; the words around them are the catalog's.
      t.html('consoleRealms.retiringHead',
             { id: row.id,
               state: state.interrupted ? 'interrupted' : 'running' }) +
      ' ' + kit.esc(state.why) + ' ' + t.html('consoleRealms.refused') +
      ' ' + kit.esc(state.refusing) + '. ' + kit.esc(state.finish) +
      (state.interrupted && !fromHere
        ? ' ' + t.html('consoleRealms.finishElsewhere')
        : '')) + button;
    return html;
  }

  /**
   * Draws the table of what trust realms separate and what they share, one
   * row per family, from realms.realmSupport().
   *
   * @param support - `realms.realmSupport()`, from the page's answer
   * @param t - the page's translator; the default (English in node) when
   *   omitted, which is how `admin.ts`'s `realmSupportTable()` calls it
   * @returns the table as HTML
   */
  static realmSupportTable(support, t?) {
    t = t || kit.context().t;
    const rows = support.map(function (row) {
      const state = row.state === 'full'
        ? '<span class="m">' + kit.esc(RealmsPage.separatedBy(row.by, t)) +
          '</span>'
        : (row.state === 'partial'
            ? '<span class="eff" title="' +
              kit.esc(t.text('consoleRealms.realmAwareNotWholly')) + '">' +
              kit.esc(row.by) + '</span>'
            : '<span class="none">' + t.html('consoleRealms.shared') +
              '</span>');
      // The note is realms.js's own prose and runs to a paragraph on the rows
      // that matter most — the directory's is 1,700 characters — so it folds.
      // What stays on the row is the family and whether it is separated, which
      // is the question somebody scans this table to answer.
      return '<tr><td>' + kit.esc(row.family) + '</td><td>' + state +
             '</td><td>' +
             kit.note(kit.esc(row.note)) + '</td></tr>';
    }).join('');
    return '<table><tr><th>' + t.html('consoleRealms.family') +
           '</th><th>' + t.html('consoleRealms.separated') + '</th><th>' +
           t.html('consoleRealms.whatThatMeans') + '</th></tr>' +
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
   * @param t - the page's translator
   * @returns "by DN" for "dn", otherwise "by " and the value
   */
  static separatedBy(by, t) {
    const how = String(by || 'path');
    // A select over the values `realms.js` uses, so a translation can word
    // each; anything else is drawn as `by <value>`, as it always was.
    return t.text('consoleRealms.separatedBy', { how: how });
  }

  /**
   * Draws the caveat on Trust realms.
   *
   * @param store - the persistence store's `persistsRealms` and `mode`
   * @param t - the page's translator
   * @returns the caveat as HTML
   */
  static realmsCaveat(store, t) {
    return (
      kit.note(t.html('consoleRealms.caveatIssues')) +
      // The store's mode is a setting value, which carries no apostrophe;
      // the link is markup, so it sits between two messages.
      (store.persistsRealms
        ? '<div class="ok">' +
          t.html('consoleRealms.persistsBack', { mode: store.mode }) +
          ' <a ' +
          'href="/admin/persistence">' + t.html('consoleRealms.persistence') +
          '</a>.</div>'
        : kit.note(t.html('consoleRealms.notPersistedHead') + ' <a ' +
          'href="/admin/persistence">' + t.html('consoleRealms.persistence') +
          '</a>' + t.html('consoleRealms.notPersistedTail'))));
  }

  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static detail(ctx, json) {
    // The page's words are its catalog's (#539); the realm's name and
    // description, and the refusal for an unknown realm, are not.
    const t = ctx.t;
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
                   'class="secondary">' + t.html('consoleRealms.unset') +
                   '</button></form></td></tr>';
          }).join('')
        : '<tr><td colspan="4" class="none">' +
          t.html('consoleRealms.nothingSet') + '</td></tr>';

      const endpointRows = Object.keys(row.endpoints).map(function (name) {
        return '<tr><td>' + kit.esc(name) + '</td><td class="who"><a href="' +
               kit.esc(row.endpoints[name]) + '"><code>' +
               kit.esc(row.endpoints[name]) +
               '</code></a></td></tr>';
      }).join('');

      inner =
        '<p class="sub">' + kit.esc(realm.name) +
        (realm.builtin ? ' ' + t.html('consoleRealms.theBuiltinRealm')
                       : '') + '</p>' +
        (realm.description ? '<p class="lead">' + kit.esc(realm.description) +
         '</p>' :
         '') +

        (row.retiring
          ? RealmsPage.retiringNotice(row, carryBack, json.current, t)
          : '') +
        // The current realm's name is free text, so it is escaped here
        // rather than handed to the catalog as a parameter: the catalog
        // escapes an apostrophe differently from kit.esc(), and English
        // must not change by a byte. The two messages carry their own
        // spaces, so a language may end the sentence right after the name.
        (inRealm
          ? '<div class="ok">' + t.html('consoleRealms.readingInside') +
            '</div>'
          : kit.warn(t.html('consoleRealms.readingInHead') + '<strong>' +
            kit.esc(json.currentName) + '</strong>' +
            t.html('consoleRealms.readingInTail'))) +

        '<h2>' + t.html('consoleRealms.itsDomain') + '</h2>' +
        kit.note(t.html('consoleRealms.domainDetail',
                        { domain: row.domain, baseDn: row.baseDn,
                          builtin: realm.builtin ? 'yes' : 'no' })) +
        '<h2>' + t.html('consoleRealms.whereItAnswers') + '</h2>' +
        kit.note(t.html('consoleRealms.prefixNote',
                        { prefix: row.pathPrefix ||
                            t.text('consoleRealms.noPrefix'),
                          pathPrefix: row.pathPrefix })) +
        '<table><tr><th>' + t.html('consoleRealms.document') + '</th><th>' +
        t.html('consoleRealms.url') + '</th></tr>' + endpointRows +
        '</table>' +
        kit.note(t.html('consoleRealms.kidNote', { kid: row.kid })) +

        '<h2>' + t.html('consoleRealms.whatItSets') + '</h2>' +
        kit.note(t.html('consoleRealms.setsHead') +
        ' <a href="/admin/config">' + t.html('consoleRealms.setsLink') +
        '</a> ' + t.html('consoleRealms.setsTail')) +
        '<table><tr><th>' + t.html('consoleRealms.key') + '</th><th>' +
        t.html('consoleRealms.setting') + '</th><th>' +
        t.html('consoleRealms.value') + '</th><th></th></tr>' +
        settingRows + '</table>' +
        '<form method="post" action="/admin/realms">' + carryBack +
        '<input type="hidden" name="action" value="set">' +
        '<input type="hidden" name="id" value="' + kit.esc(realm.id) +
        '"><div class="formrow"><label for="skey">' +
        t.html('consoleRealms.key') + '</label><input ' +
        'type="text" id="skey" name="key" size="30" ' +
        'placeholder="saml.organizationName" required><label ' +
        'for="sval">' + t.html('consoleRealms.value') +
        '</label><input type="text" id="sval" name="value" ' +
        'size="30"><button type="submit">' +
        t.html('consoleRealms.setItHere') + '</button></div></form><h2>' +
        t.html('consoleRealms.nameAndDescription') + '</h2><form ' +
        'method="post" action="/admin/realms">' + carryBack +
        '<input type="hidden" name="action" value="update">' +
        '<input type="hidden" name="id" value="' + kit.esc(realm.id) + '">' +
        '<div class="formrow"><label for="uname">' +
        t.html('consoleRealms.name') + '</label>' +
        '<input type="text" id="uname" name="name" size="22" value="' +
        kit.esc(realm.name) + '"><label ' +
        'for="udesc">' + t.html('consoleRealms.description') +
        '</label><input type="text" id="udesc" ' +
        'name="description" size="46" value="' +
        kit.esc(realm.description) + '">' +
        '<button type="submit">' + t.html('consoleRealms.save') +
        '</button></div></form>' +

        (realm.builtin
          ? '<h2>' + t.html('consoleRealms.cannotRemoveHeading') + '</h2>' +
            kit.note(t.html('consoleRealms.cannotRemove'))
          : '<h2>' + t.html('consoleRealms.removeHeading') + '</h2>' +
            kit.note(t.html('consoleRealms.removeNote')) +
            '<form method="post" action="/admin/realms">' + carryBack +
            '<input type="hidden" name="action" value="remove">' +
            '<input type="hidden" name="id" value="' + kit.esc(realm.id) +
              '">' +
            '<button type="submit" class="danger">' +
            t.html('consoleRealms.removeButton', { id: realm.id }) +
            '</button></form>');

    }

    return inner;
  }
}

export = RealmsPage;
