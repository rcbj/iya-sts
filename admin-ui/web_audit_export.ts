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
// A token box is never filled; empty keeps the one set. Plain headers are
// sent back, because an empty headers field replaces them.
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
   * The fields of one destination. A new one passes an empty row.
   *
   * @param t - the translator
   * @param row - the destination, or null
   * @returns the fields
   */
  static fields(t: Json, row: Json): string {
    const at = row || {};
    const key = function (name: string): string {
      return t.text('consoleAuditExport.' + name);
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
      '</div><div class="formrow"><label>' +
      esc(key('body.template')) +
      ' <textarea name="template" rows="2" cols="64">' +
      esc(at.template || '') + '</textarea></label></div>' +
      '<div class="formrow"><label>' + esc(key('body.headers')) +
      ' <textarea name="headers" rows="3" cols="64">' +
      esc(at.headerText || '') + '</textarea></label></div>' +
      '<div class="formrow"><label>' + esc(key('body.secretHeaders')) +
      ' <textarea name="secretHeaders" rows="2" cols="64"></textarea>' +
      '</label></div><div class="formrow">' +
      '<label>' + esc(key('body.token')) +
      ' <input type="password" name="token" autocomplete="off" value=""' +
      ' placeholder="' + esc(at.tokenSet ? key('body.tokenKept') : '') +
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
   * @returns the table row
   */
  static row(t: Json, row: Json, write: boolean): string {
    const key = function (name: string): string {
      return t.text('consoleAuditExport.' + name);
    };
    const status = key('row.' + (row.status || 'healthy'));
    const when = row.lastSuccessAt
      ? new Date(row.lastSuccessAt).toISOString()
      : (row.lastFailure || '');
    const controls = write
      ? this.act(row.id, 'test', key('body.testButton')) +
        (row.enabled
          ? this.act(row.id, 'disable', key('body.disable'))
          : this.act(row.id, 'enable', key('body.enable'))) +
        '<details><summary>' + esc(key('body.save')) +
        '</summary><form method="post" action="' + PAGE + '">' +
        '<input type="hidden" name="action" value="update">' +
        '<input type="hidden" name="id" value="' + esc(row.id) + '">' +
        this.fields(t, row) + '<button type="submit">' +
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
    const rows = (json.destinations || []).map((row: Json) =>
      AuditExportPage.row(t, row, !!c.write)).join('');
    const stats = json.stats || {};
    const add = c.write
      ? '<h2 id="add" data-tab="add">' + key('body.add') +
        '</h2><form method="post" action="' + PAGE + '">' +
        '<input type="hidden" name="action" value="add">' +
        '<div class="formrow">' +
        AuditExportPage.text('id', t.text('consoleAuditExport.body.id'),
                             '') + '</div>' +
        AuditExportPage.fields(t, null) + '<button type="submit">' +
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
      SettingsForms.forms(json.settings, PAGE, undefined, t) +
      '<p class="links" data-metadata><code>GET ' +
      '/admin-api/audit-export</code></p>';
  }
}

export = AuditExportPage;
