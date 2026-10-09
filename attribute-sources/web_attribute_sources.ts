// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_attribute_sources.ts
//
// ---------------------------------------------------------------------------
// DIRECTORY → ATTRIBUTE SOURCES, DRAWN FROM ITS VIEW ALONE (#446, 2026-10-05).
//
// Draws Attribute sources from the answer of `GET
// /admin-api/attribute-sources`: the SQL databases this realm reads people's
// attributes from, each with its form, and the family's settings.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// Its methods were `AttributeSourcesAdmin`'s in
// `attribute-sources/attribute_sources_admin.ts`, moved with their comments;
// that module still draws the page until the console's cutover, by calling
// `render()` with its view passed through JSON.
//
// ITS WORDS ARE THE `consoleAttributeSources` NAMESPACE (#539): every helper
// that draws one is handed the page's translator `t`. The option values of
// the selects and the refresh modes are VALUES (an `<option>` with no
// `value` posts its text), so they stay as they are.
// ---------------------------------------------------------------------------

import kit = require('../admin-ui/web_kit');
import settings = require('../admin-ui/web_settings');

type Json = any;

// The console's escaping, under the name the moved code calls it by.
const esc = kit.esc;

/**
 * The page's path.
 */
const PAGE = '/admin/attribute-sources';

/**
 * Draws Attribute sources from the answer of `GET
 * /admin-api/attribute-sources`: the SQL databases this realm reads people's
 * attributes from, each with its form, and the family's settings.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class AttributeSourcesPage {
  /**
   * Draws the page's body from its view.
   *
   * @param view - the answer of the page's management API operation
   * @param ctx - optional; the render context (`WebKit.context()`), whose
   *   translator draws the words — the console's page table passes one, the
   *   server-drawn page does not and gets the default (#539)
   * @returns the body as HTML
   */
  static render(view: Json, ctx?: Json): string {
    return AttributeSourcesPage.body(ctx || kit.context(), view);
  }

  // The fields of a source's form, filled with `source` (empty for a new
  // one). The refresh modes are checkboxes, read back as a list.
  static fields(t: Json, json: Json, source: Json): string {
    const s = source || {};
    const text = function (name: string, label: string, value: unknown,
                           hint?: string): string {
      return '<label>' + esc(label) + ' <input type="text" name="' + name +
        '" value="' + esc(value == null ? '' : value) + '"' +
        (hint ? ' placeholder="' + esc(hint) + '"' : '') + '></label>';
    };
    const select = function (name: string, label: string,
                              options: string[], value: string): string {
      return '<label>' + esc(label) + ' <select name="' + name + '">' +
        options.map(function (one) {
          return '<option' + (one === value ? ' selected' : '') + '>' +
                 esc(one) + '</option>';
        }).join('') + '</select></label>';
    };
    const columns = Object.keys(s.columns || {}).map(function (c) {
      return c + '=' + s.columns[c];
    }).join('\n');
    const refresh = s.refresh || ['sign-in'];
    return '<div class="formrow">' +
      select('dialect', t.text('consoleAttributeSources.database'),
             json.dialects, s.dialect || 'postgres') +
      text('host', t.text('consoleAttributeSources.host'), s.host,
           'db.example.com') +
      text('port', t.text('consoleAttributeSources.port'), s.port,
           t.text('consoleAttributeSources.portHint')) +
      text('database', t.text('consoleAttributeSources.databaseName'),
           s.database) +
      text('user', t.text('consoleAttributeSources.user'), s.user) +
      '</div><div class="formrow">' +
      select('passwordProvider',
             t.text('consoleAttributeSources.passwordFrom'),
             json.passwordProviders, s.passwordProvider || 'none') +
      text('passwordRef', t.text('consoleAttributeSources.passwordAt'),
           s.passwordRef, t.text('consoleAttributeSources.passwordRefHint')) +
      text('passwordField', t.text('consoleAttributeSources.passwordField'),
           s.passwordField, t.text('consoleAttributeSources.optional')) +
      text('caFile', t.text('consoleAttributeSources.caFile'), s.caFile,
           t.text('consoleAttributeSources.caFileHint')) +
      text('serverName', t.text('consoleAttributeSources.serverName'),
           s.serverName, t.text('consoleAttributeSources.serverNameHint')) +
      '</div><div class="formrow"><label>' +
      t.html('consoleAttributeSources.caCertificates') +
      ' <textarea name="caCertificates" rows="4" ' +
      'cols="64" placeholder="-----BEGIN CERTIFICATE-----">' +
      esc(s.caCertificates || '') + '</textarea></label><label><input ' +
      'type="checkbox" name="trustPublicRoots" value="true"' +
      (s.trustPublicRoots ? ' checked' : '') + '> ' +
      t.html('consoleAttributeSources.trustPublicRoots') +
      '</label></div><div class="formrow">' +
      text('table', t.text('consoleAttributeSources.table'), s.table,
           'schema.table') +
      text('keyColumn', t.text('consoleAttributeSources.keyColumn'),
           s.keyColumn) +
      text('keyAttribute', t.text('consoleAttributeSources.keyAttribute'),
           s.keyAttribute || 'uid') +
      '</div><div class="formrow"><label>' +
      t.html('consoleAttributeSources.columnsLabel') +
      ' <textarea name="columns" rows="3" cols="40">' +
      esc(columns) + '</textarea></label></div><div class="formrow">' +
      t.html('consoleAttributeSources.readLabel') + ' ' +
      json.modes.map(function (mode: string) {
        return '<label><input type="checkbox" name="refresh" value="' +
               esc(mode) + '"' + (refresh.indexOf(mode) >= 0 ? ' checked'
                                                            : '') + '> ' +
               esc(mode) + '</label>';
      }).join(' ') +
      text('scheduleS', t.text('consoleAttributeSources.everySeconds'),
           s.scheduleS || 3600) +
      text('timeoutMs', t.text('consoleAttributeSources.timeoutMs'),
           s.timeoutMs || 2000) +
      select('onFailure', t.text('consoleAttributeSources.onFailure'),
             json.onFailure, s.onFailure || 'keep') +
      // `true` and `false` are the values posted, so they are not words.
      select('enabled', t.text('consoleAttributeSources.enabled'),
             ['true', 'false'],
             s.enabled === false ? 'false' : 'true') + '</div>';
  }

  // What a source's connection trusts (#94): its own chain, each
  // certificate by subject, expiry and SHA-256, and whether node's store is
  // trusted beside it.
  //
  // The title is built with `t.text()` — its parameters NOT escaped — and
  // then escaped whole by `esc()`, so the English is the string it was.
  static trustCell(t: Json, source: Json): string {
    const trust = source.trust || { certificates: [] };
    const chain = (trust.certificates || []).map(function (one: Json) {
      return '<div><span title="' +
        esc(t.text('consoleAttributeSources.issuedBy',
                   { issuer: one.issuer, sha256: one.sha256 })) + '">' +
        esc(one.subject) + '</span>' +
        '<br><span class="sub">' +
        (one.ca ? t.html('consoleAttributeSources.ca')
                : t.html('consoleAttributeSources.notCa')) +
        (one.selfSigned ? t.html('consoleAttributeSources.selfSigned')
                        : '') +
        t.html('consoleAttributeSources.until') + ' ' +
        esc(one.notAfter.slice(0, 10)) +
        (one.expired ? ' <span class="state-revoked">' +
          t.html('consoleAttributeSources.expired') + '</span>' : '') +
        '</span></div>';
    }).join('');
    return chain + (trust.caFile ? '<div class="sub">' +
      t.html('consoleAttributeSources.andTheFile') + ' <code>' +
      esc(trust.caFile) + '</code></div>' : '') +
      '<div class="sub">' + (trust.publicRoots
        ? (chain || trust.caFile
          ? t.html('consoleAttributeSources.andThePublicRoots')
          : t.html('consoleAttributeSources.thePublicRoots'))
        : t.html('consoleAttributeSources.theseAlone')) + '</div>';
  }

  // One source's row: where it reads, what it writes, and its status.
  static row(t: Json, json: Json, source: Json): string {
    const st = source.status || {};
    const form = function (action: string, extra: string, label: string,
                           danger?: boolean): string {
      return '<form method="post" action="' + PAGE + '" class="inline">' +
        '<input type="hidden" name="action" value="' + action + '">' +
        '<input type="hidden" name="id" value="' + esc(source.id) + '">' +
        extra + ' <button type="submit"' + (danger ? ' class="danger"' : '') +
        '>' + esc(label) + '</button></form>';
    };
    return '<tr><td class="who"><code>' + esc(source.id) + '</code>' +
      (source.enabled ? '' : ' <span class="sub">' +
        t.html('consoleAttributeSources.disabled') + '</span>') +
      '</td><td>' + esc(source.dialect) + ' <code>' +
      esc(source.host + ':' + source.port + '/' + source.database) +
      '</code><br><span class="sub">' +
      t.html('consoleAttributeSources.asUser') + ' ' + esc(source.user) +
      '</span>' +
      '<br><span class="sub">' +
      t.html('consoleAttributeSources.tlsVerifiedAgainst') + '</span>' +
      this.trustCell(t, source) + '</td>' +
      '<td><code>' + esc(source.table) + '.' + esc(source.keyColumn) +
      '</code> = ' + t.html('consoleAttributeSources.thePersons') +
      ' <code>' + esc(source.keyAttribute) +
      '</code></td><td>' + Object.keys(source.columns || {}).map(function (c) {
        return '<div><code>' + esc(c) + '</code> &rarr; <code>' +
               esc(source.columns[c]) + '</code></div>';
      }).join('') + '</td><td>' + esc((source.refresh || []).join(', ')) +
      '<br><span class="sub">' + t.html('consoleAttributeSources.onFailure') +
      ' ' + esc(source.onFailure) +
      '</span></td><td>' +
      // The error and its code are the view's and stay English (#539).
      (st.lastError
        ? '<span class="state-revoked">' + esc(st.lastCode || '') +
          '</span> <span class="sub">' + esc(st.lastError) + ' ' +
          t.html('consoleAttributeSources.at') + ' ' +
          esc(st.lastErrorAt || '') + '</span>'
        : (st.lastOkAt ? t.html('consoleAttributeSources.readAt') + ' ' +
                         esc(st.lastOkAt)
                       : '<span class="state-none">' +
                         t.html('consoleAttributeSources.notYet') +
                         '</span>')) +
      (st.lastRunAt ? '<br><span class="sub">' +
        t.html('consoleAttributeSources.scheduledRun') + ' ' +
        esc(st.lastRunAt) + ', ' +
        t.html('consoleAttributeSources.people',
               { n: st.lastRunPeople || 0 }) +
        (st.cursorOpen ? t.html('consoleAttributeSources.continuing')
                       : '') + '</span>' : '') +
      '</td><td class="act">' +
      form('test-source', '<input type="text" name="username" size="12" ' +
           'placeholder="' +
           esc(t.text('consoleAttributeSources.aPerson')) + '">',
           t.text('consoleAttributeSources.test')) +
      form('refresh-source', '',
           t.text('consoleAttributeSources.readEveryoneNow')) +
      '<details><summary>' + t.html('consoleAttributeSources.edit') +
      '</summary><form method="post" action="' + PAGE +
      '"><input type="hidden" name="action" value="update-source">' +
      '<input type="hidden" name="id" value="' + esc(source.id) + '">' +
      this.fields(t, json, source) + '<button type="submit">' +
      t.html('consoleAttributeSources.save') + '</button>' +
      '</form></details>' +
      form('remove-source', '', t.text('consoleAttributeSources.remove'),
           true) + '</td></tr>';
  }

  /**
   * Draws the page body.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the view `GET /admin-api/attribute-sources` answers
   * @returns the HTML
   */
  static body(ctx: Json, json: Json): string {
    const t = ctx.t;
    const rows = json.sources.map((source: Json) => this.row(t, json, source))
      .join('');
    return kit.note(t.html('consoleAttributeSources.intro')) +
      (json.hostPatterns ? '' :
        kit.warn(t.html('consoleAttributeSources.anyHost'))) +
      '<h3 id="sources">' + t.html('consoleAttributeSources.sources') +
      '</h3><table><thead><tr><th>' +
      t.html('consoleAttributeSources.colSource') + '</th>' +
      '<th>' + t.html('consoleAttributeSources.colDatabase') + '</th><th>' +
      t.html('consoleAttributeSources.colRow') + '</th><th>' +
      t.html('consoleAttributeSources.colColumns') + '</th><th>' +
      t.html('consoleAttributeSources.colRead') + '</th>' +
      '<th>' + t.html('consoleAttributeSources.colStatus') +
      '</th><th></th></tr></thead><tbody>' +
      (rows || '<tr><td colspan="7"><span class="state-none">' +
               t.html('consoleAttributeSources.noSource') +
               '</span></td></tr>') +
      '</tbody></table>' +
      '<h3 id="add">' + t.html('consoleAttributeSources.addSource') +
      '</h3><form method="post" action="' + PAGE +
      '"><input type="hidden" name="action" value="add-source">' +
      '<div class="formrow"><label>' + t.html('consoleAttributeSources.id') +
      ' <input type="text" name="id" ' +
      'placeholder="hr-db" required></label></div>' +
      this.fields(t, json, null) + '<button type="submit">' +
      t.html('consoleAttributeSources.add') + '</button></form>' +
      '<h3 id="person">' + t.html('consoleAttributeSources.readOnePerson') +
      '</h3><form method="post" ' +
      'action="' + PAGE + '"><div class="formrow"><input type="hidden" ' +
      'name="action" value="refresh-person"><label>' +
      t.html('consoleAttributeSources.person') + ' <input ' +
      'type="text" name="username" required></label><button ' +
      'type="submit">' + t.html('consoleAttributeSources.read') +
      '</button></div></form>' +
      // The link is markup a message cannot carry, so the sentence is split
      // around it.
      '<p class="sub">' +
      t.html('consoleAttributeSources.fromEverySource') + ' <code>' +
      esc(json.job) + '</code> ' +
      t.html('consoleAttributeSources.jobOn') + ' ' +
      '<a href="/admin/scheduler">' +
      t.html('consoleAttributeSources.scheduler') + '</a>' +
      t.html('consoleAttributeSources.jobOnEnd') + '</p>' +
      '<h2>' + t.html('consoleAttributeSources.settings') + '</h2>' +
      settings.forms(json.settings, PAGE) +
      '<p class="links"><a href="' + PAGE + '?format=json">JSON</a> · ' +
      '<code>GET /admin-api/attribute-sources</code></p>';
  }
}

export = AttributeSourcesPage;
