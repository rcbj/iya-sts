// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_audit_export.ts
//
// ---------------------------------------------------------------------------
// MONITORING → AUDIT EXPORT, DRAWN FROM ITS VIEW ALONE (#641).
//
// Draws the destinations from `GET /admin-api/audit-export`: each one
// without its secrets, this process's queue and counters, a form to add
// one, and the page's settings. Every form posts to this page. The hidden
// `action` is the last segment of the management API path (`add`,
// `update`, `remove`, `enable`, `disable`, `test`).
//
// THE FIGURES ARE THIS PROCESS. Each process delivers its own audit rows.
// A token box is never filled from a stored destination; empty keeps the
// one set. Plain headers are sent back, because an empty headers field
// replaces them.
//
// A REFUSED ADD OR UPDATE KEEPS WHAT WAS POSTED. The page is drawn from
// the saved destinations, and a refusal is not one of them, so a notice
// that reloaded the page drew the add form empty. `WebAnswers.redraw()`
// puts the posted fields in `state.auditExportDraft` and the page draws
// that form again: the add form, or that destination's update form, open.
// The token and the secret headers come back only from that draft. A
// stored destination still draws both empty.
//
// THE THREE WEBHOOK TEXTAREAS NAME THEMSELVES BESIDE THE BOX. A textarea
// inside its label takes the hover, so the name's tooltip never appears.
// The description is the label's `title`. The same sentences are the
// management API's field descriptions and `docs/audit-export.md`.
//
// A `web_` MODULE: other `web_` modules only, no log, bundled for a
// browser by `build-typescript.sh`.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');
import SettingsForms = require('./web_settings');

type Json = any;

const esc = kit.esc;
const PAGE = '/admin/audit-export';
const TYPES = ['syslog', 'file', 'webhook', 'splunk', 'logrhythm'];
const TRANSPORTS = ['tcp', 'udp', 'tls'];

/**
 * Draws Monitoring → Audit export from its management API answer.
 */
class AuditExportPage {
  /**
   * Draws the page body.
   *
   * @param view - `GET /admin-api/audit-export`
   * @param ctx - the render context
   * @returns the body as HTML
   */
  static render(view: Json, ctx?: Json): string {
    return AuditExportPage.body(view || {}, ctx || kit.context());
  }

  /**
   * One text field.
   *
   * @param name - the field name
   * @param label - the label
   * @param value - the current value
   * @returns the label and input
   */
  static text(name: string, label: string, value: unknown): string {
    return '<label>' + esc(label) + ' <input type="text" name="' + name +
      '" value="' + esc(value == null ? '' : value) + '"></label>';
  }

  /**
   * One select.
   *
   * @param name - the field name
   * @param label - the label
   * @param options - the options
   * @param value - the selected option
   * @returns the label and select
   */
  static select(name: string, label: string, options: string[],
                value: string): string {
    return '<label>' + esc(label) + ' <select name="' + name + '">' +
      options.map(function (one) {
        return '<option' + (one === value ? ' selected' : '') + '>' +
               esc(one) + '</option>';
      }).join('') + '</select></label>';
  }

  /**
   * A yes/no checkbox. Unticked is sent as false.
   *
   * @param name - the field name
   * @param label - the label
   * @param on - whether it is ticked
   * @returns the label and checkbox
   */
  static box(name: string, label: string, on: boolean): string {
    return '<label><input type="checkbox" name="' + name +
      '" value="true"' + (on ? ' checked' : '') + '> ' + esc(label) +
      '</label>';
  }

  /**
   * One posted value. A repeated name keeps the last.
   *
   * @param fields - the form's fields
   * @param name - the field
   * @returns the value
   */
  static posted(fields: Json, name: string): string {
    const value = fields ? fields[name] : '';
    if (Array.isArray(value)) {
      return String(value.length ? value[value.length - 1] : '');
    }
    return value == null ? '' : String(value);
  }

  /**
   * Whether a checkbox was ticked. An unticked box is absent.
   *
   * @param fields - the form's fields
   * @param name - the field
   * @returns true when the posted value is true
   */
  static ticked(fields: Json, name: string): boolean {
    const value = AuditExportPage.posted(fields, name);
    return value === 'true' || value === '1';
  }

  /**
   * The row a refused save draws, from the fields that were posted.
   * A token and a secret header come back only here.
   *
   * @param fields - the form's fields
   * @returns the row the form draws
   */
  static draftRow(fields: Json): Json {
    const f = fields || {};
    return {
      id: AuditExportPage.posted(f, 'id'),
      name: AuditExportPage.posted(f, 'name'),
      type: AuditExportPage.posted(f, 'type'),
      enabled: AuditExportPage.ticked(f, 'enabled'),
      host: AuditExportPage.posted(f, 'host'),
      port: AuditExportPage.posted(f, 'port'),
      transport: AuditExportPage.posted(f, 'transport'),
      facility: AuditExportPage.posted(f, 'facility'),
      appName: AuditExportPage.posted(f, 'appName'),
      path: AuditExportPage.posted(f, 'path'),
      mode: AuditExportPage.posted(f, 'mode'),
      rotateBytes: AuditExportPage.posted(f, 'rotateBytes'),
      url: AuditExportPage.posted(f, 'url'),
      contentType: AuditExportPage.posted(f, 'contentType'),
      index: AuditExportPage.posted(f, 'index'),
      sourcetype: AuditExportPage.posted(f, 'sourcetype'),
      source: AuditExportPage.posted(f, 'source'),
      ack: AuditExportPage.ticked(f, 'ack'),
      template: AuditExportPage.posted(f, 'template'),
      headerText: AuditExportPage.posted(f, 'headers'),
      secretHeaderText: AuditExportPage.posted(f, 'secretHeaders'),
      tokenDraft: AuditExportPage.posted(f, 'token'),
      excludeAttributes:
        AuditExportPage.posted(f, 'excludeAttributes')
    };
  }

  /**
   * A textarea whose name is the label beside it. The box is not inside
   * the label: inside, the box takes the hover and the name's tooltip
   * never appears.
   *
   * @param id - the textarea id, unique on the page
   * @param name - the field name
   * @param label - the field's name
   * @param tip - the tooltip
   * @param value - the current text
   * @param rows - the rows
   * @returns the label and the textarea
   */
  static area(id: string, name: string, label: string, tip: string,
              value: string, rows: number): string {
    return '<div class="formrow"><label for="' + esc(id) + '"' +
      kit.tip(tip, Infinity) + '>' + esc(label) + '</label><textarea ' +
      'id="' + esc(id) + '" name="' + esc(name) + '" rows="' + rows +
      '" cols="64">' + esc(value) + '</textarea></div>';
  }

  /**
   * The fields of one destination. A new one passes an empty row.
   *
   * @param t - the translator
   * @param row - the destination, or null
   * @param stem - makes each textarea id unique on the page
   * @returns the fields
   */
  static fields(t: Json, row: Json, stem: string): string {
    const at = row || {};
    const key = function (name: string): string {
      return t.text('consoleAuditExport.' + name);
    };
    const id = function (name: string): string {
      return 'ax-' + stem + '-' + name;
    };
    return '<div class="formrow">' +
      this.text('name', key('body.name'), at.name || '') +
      this.select('type', key('body.type'), TYPES, at.type || 'syslog') +
      this.box('enabled', key('row.enabled'), at.enabled !== false) +
      '</div><div class="formrow">' +
      this.text('host', key('body.host'), at.host || '') +
      this.text('port', key('body.port'), at.port || '') +
      this.select('transport', key('body.transport'), TRANSPORTS,
                  at.transport || 'tcp') +
      this.text('facility', key('body.facility'),
                at.facility == null ? '' : at.facility) +
      this.text('appName', key('body.appName'), at.appName || '') +
      '</div><div class="formrow">' +
      this.text('path', key('body.path'), at.path || '') +
      this.text('mode', key('body.mode'), at.mode || '') +
      this.text('rotateBytes', key('body.rotate'), at.rotateBytes || '') +
      '</div><div class="formrow">' +
      this.text('url', key('body.url'), at.url || '') +
      this.text('contentType', key('body.contentType'),
                at.contentType || '') +
      this.text('index', key('body.index'), at.index || '') +
      this.text('sourcetype', key('body.sourcetype'), at.sourcetype || '') +
      this.text('source', key('body.source'), at.source || '') +
      this.box('ack', key('body.ack'), !!at.ack) +
      '</div>' +
      this.area(id('template'), 'template', key('body.template'),
                key('body.templateTip'), at.template || '', 2) +
      this.area(id('headers'), 'headers', key('body.headers'),
                key('body.headersTip'), at.headerText || '', 3) +
      this.area(id('secretHeaders'), 'secretHeaders',
                key('body.secretHeaders'), key('body.secretHeadersTip'),
                at.secretHeaderText || '', 2) +
      '<div class="formrow">' +
      '<label>' + esc(key('body.token')) +
      ' <input type="password" name="token" autocomplete="off" value="' +
      esc(at.tokenDraft || '') + '" placeholder="' +
      esc(at.tokenSet ? key('body.tokenKept') : '') +
      '"></label> ' +
      this.text('excludeAttributes', key('body.exclude'),
                at.excludeAttributes || '') +
      '</div>';
  }

  /**
   * One small act: enable, disable, remove, or test.
   *
   * @param id - the destination id
   * @param action - the act
   * @param label - the button
   * @param danger - whether the button is the removing one
   * @returns the form
   */
  static act(id: string, action: string, label: string,
             danger?: boolean): string {
    return '<form method="post" action="' + PAGE + '" class="inline">' +
      '<input type="hidden" name="action" value="' + action + '">' +
      '<input type="hidden" name="id" value="' + esc(id) + '">' +
      '<button type="submit"' + (danger ? ' class="danger"' : '') + '>' +
      esc(label) + '</button></form>';
  }

  /**
   * One destination's row.
   *
   * @param t - the translator
   * @param row - the destination
   * @param write - whether controls are drawn
   * @param draft - a refused update's posted fields, if this page has one
   * @returns the table row
   */
  static row(t: Json, row: Json, write: boolean, draft?: Json): string {
    const key = function (name: string): string {
      return t.text('consoleAuditExport.' + name);
    };
    const refused = !!(draft && draft.action === 'update' &&
      AuditExportPage.posted(draft.fields, 'id') === String(row.id));
    const shown = refused
      ? Object.assign({}, row, AuditExportPage.draftRow(draft.fields))
      : row;
    const status = key('row.' + (row.status || 'healthy'));
    const when = row.lastSuccessAt
      ? new Date(row.lastSuccessAt).toISOString()
      : (row.lastFailure || '');
    const controls = write
      ? this.act(row.id, 'test', key('body.testButton')) +
        (row.enabled
          ? this.act(row.id, 'disable', key('body.disable'))
          : this.act(row.id, 'enable', key('body.enable'))) +
        '<details' + (refused ? ' open' : '') + '><summary>' +
        esc(key('body.save')) +
        '</summary><form method="post" action="' + PAGE + '">' +
        '<input type="hidden" name="action" value="update">' +
        '<input type="hidden" name="id" value="' + esc(row.id) + '">' +
        this.fields(t, shown, String(row.id)) + '<button type="submit">' +
        esc(key('body.save')) + '</button></form></details>' +
        this.act(row.id, 'remove', key('body.remove'), true)
      : '';
    return '<tr><td class="who">' + esc(row.name || row.id) +
      '<br><span class="sub"><code>' + esc(row.id) + '</code></span></td>' +
      '<td><code>' + esc(row.type || '') + '</code></td><td>' +
      esc(status) + (row.lastFailure
        ? '<div class="sub">' + esc(row.lastFailure) + '</div>' : '') +
      '</td><td>' + esc(row.queueDepth || 0) + '</td><td>' +
      esc(row.delivered || 0) + '</td><td>' + esc(when) + '</td><td ' +
      'class="act">' + controls + '</td></tr>';
  }

  /**
   * Draws the page.
   *
   * @param json - the view
   * @param ctx - the render context
   * @returns the HTML
   */
  static body(json: Json, ctx?: Json): string {
    const c = ctx || kit.context();
    const t = c.t;
    const key = function (name: string): string {
      return t.html('consoleAuditExport.' + name);
    };
    const draft = json.state && json.state.auditExportDraft;
    const addDraft = draft && draft.action === 'add'
      ? AuditExportPage.draftRow(draft.fields) : null;
    const rows = (json.destinations || []).map((row: Json) =>
      AuditExportPage.row(t, row, !!c.write, draft)).join('');
    const stats = json.stats || {};
    const add = c.write
      ? '<h2 id="add" data-tab="add">' + key('body.add') +
        '</h2><form method="post" action="' + PAGE + '">' +
        '<input type="hidden" name="action" value="add">' +
        '<div class="formrow">' +
        AuditExportPage.text('id', t.text('consoleAuditExport.body.id'),
                             addDraft ? addDraft.id : '') + '</div>' +
        AuditExportPage.fields(t, addDraft, 'add') +
        '<button type="submit">' +
        key('body.addButton') + '</button></form>'
      : '<h2 id="add" data-tab="add">' + key('body.add') + '</h2>';
    return kit.note(key('body.lead')) +
      kit.note(key('body.thisProcess')) +
      '<h2 id="destinations" data-tab="destinations">' +
      key('body.destinations') + '</h2><table><thead><tr><th>' +
      key('body.thName') + '</th><th>' + key('body.thType') + '</th><th>' +
      key('body.thEnabled') + '</th><th>' + key('body.thQueue') +
      '</th><th>' + key('body.thDelivered') + '</th><th>' +
      key('body.thLast') + '</th><th></th></tr></thead><tbody>' +
      (rows || '<tr><td colspan="7"><span class="state-none">' +
               key('body.none') + '</span></td></tr>') +
      '</tbody></table>' + add +
      '<h2 id="status" data-tab="status">' + key('body.status') +
      '</h2><ul><li>' + key('stats.delivered') + ' ' +
      esc(stats.delivered || 0) + '</li><li>' + key('stats.awaiting') +
      ' ' + esc(stats.awaiting || 0) + '</li><li>' +
      key('stats.retrying') + ' ' + esc(stats.retrying || 0) +
      '</li><li>' + key('stats.failed') + ' ' +
      esc(stats.permanentlyFailed || 0) + '</li><li>' +
      key('stats.dropped') + ' ' + esc(stats.dropped || 0) +
      '</li><li>' + key('stats.latency') + ' ' +
      esc(stats.latencyMs || 0) + '</li><li>' +
      key('stats.availability') + ' ' + esc(stats.availability == null
        ? '' : stats.availability) + '</li></ul>' +
      SettingsForms.forms(json.settings || { groups: [] }, PAGE,
                          undefined, t) +
      '<p class="links" data-metadata><code>GET ' +
      '/admin-api/audit-export</code></p>';
  }
}

export = AuditExportPage;
