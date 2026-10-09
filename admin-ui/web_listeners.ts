// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_listeners.ts
//
// ---------------------------------------------------------------------------
// SERVER CONFIGURATION → LISTENERS, DRAWN FROM ITS VIEW ALONE (#446,
// 2026-10-05).
//
// Draws Listeners from the answer of `GET /admin-api/listeners`: every socket,
// its TLS policy and client authentication, the custom listeners and which
// hosted application is on which (#472), and the settings, a tab each.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// Its methods were `ListenersAdmin`'s in `admin-ui/listeners_admin.ts`, moved
// with their comments; that module still draws the page until the console's
// cutover, by calling `render()` with its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');
import SettingsForms = require('./web_settings');

type Json = any;

/**
 * The console path of Server configuration → Listeners.
 */
const PAGE = '/admin/listeners';

/**
 * Draws Listeners from the answer of `GET /admin-api/listeners`: every socket,
 * its TLS policy and client authentication, a realm's own listener, and the
 * settings, a tab each.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class ListenersPage {
  /**
   * Draws the page's body from its view.
   *
   * @param view - the answer of the page's management API operation
   * @param ctx - the render context (`WebKit.context()`); the server's
   *   own drawing passes none, and gets English
   * @returns the body as HTML
   */
  static render(view: Json, ctx?: Json): string {
    return ListenersPage.html(view, ctx || kit.context());
  }

  // The helpers below have no context, so each is handed the page's
  // translator `t` by its caller (#539).

  // One policy as table cells.
  static policyCells(policy: Json, t: Json): string {
    if (!policy) {
      return '<td colspan="4"><em>' + t.html('consoleListeners.notTls') +
        '</em></td>';
    }
    const suites = policy.tls13Suites.map(function (one: Json): string {
      return '<code>' + kit.esc(one.name) + '</code>' +
        (one.postQuantum ? ' <small>' +
                           t.html('consoleListeners.pqSafe') + '</small>'
                         : '');
    }).join('<br>');
    return '<td>' + kit.esc(policy.minVersion) +
      (policy.tls12 ? '' : '<br><small>' +
                           t.html('consoleListeners.tls12Off') + '</small>') +
      (policy.pqcOnly ? '<br><strong>' + t.html('consoleListeners.pqOnly') +
                        '</strong>' : '') +
      '</td><td>' + suites + '</td><td><small><code>' +
      kit.esc(policy.groups) + '</code></small></td><td>' +
      kit.esc(String(policy.clientAuth || '—')) + '</td>';
  }

  // One custom listener's row: its address, owner, state on this node and
  // the policy in force.
  static customRow(one: Json, t: Json): string {
    return '<tr id="listener-' + kit.esc(one.id) + '"><th>' +
      kit.esc(one.id) + '<br><small>' + kit.esc(one.publicBaseUrl) + ' ' +
      (one.owner !== 'default'
        ? t.html('consoleListeners.ownerRealm', { realm: String(one.owner) })
        : t.html('consoleListeners.everyRealm')) +
      ' · ' + t.html('consoleListeners.certificateFrom',
                     { source: String(one.certificateSource) }) + ' · ' +
      kit.esc(one.state) + (one.why ? ' — ' + kit.esc(one.why) : '') +
      '</small></th><td>' + kit.esc(String(one.port)) + '</td>' +
      ListenersPage.policyCells(one.policy, t) + '</tr>';
  }

  // Which application is on which listener: the mapping as it stands.
  static mappingTable(rows: Json[], t: Json): string {
    return '<table class="grid"><thead><tr><th>' +
      t.html('consoleListeners.thApplication') + '</th>' +
      '<th>' + t.html('consoleListeners.thListeners') + '</th><th>' +
      t.html('consoleListeners.thAdvertised') + '</th><th>' +
      t.html('consoleListeners.thDecidedBy') + '</th></tr>' +
      '</thead><tbody>' + rows.map(function (row: Json): string {
        return '<tr id="application-' + kit.esc(row.application) + '"><th>' +
          kit.esc(row.label) + ' <small><code>' + kit.esc(row.application) +
          '</code>' + (row.session
            ? ' ' + t.html('consoleListeners.readsSession') : '') +
          '</small><br><small>' + kit.esc(row.what) + '</small></th><td>' +
          row.listeners.map(function (id: string): string {
            return '<code>' + kit.esc(id) + '</code>';
          }).join(', ') + '</td><td><code>' + kit.esc(row.advertised) +
          '</code></td><td>' + kit.esc(row.decidedBy) + '</td></tr>';
      }).join('') + '</tbody></table>';
  }

  // The two writes: the listeners this realm defines, and its mapping, each
  // as the JSON a person reads and edits.
  //
  // The two notes name JSON shapes in <code>, which carry braces a message
  // cannot hold (#539), so each shape stays in the code between messages.
  static forms(json: Json, t: Json): string {
    const d = json.definitions || {};
    const isDefault = json.realm === 'default';
    const whose = isDefault ? 'default' : 'realm';
    const pretty = function (text: string): string {
      try {
        return text ? JSON.stringify(JSON.parse(text), null, 2) : '';
      } catch (e) {
        // A value that is not JSON — set in the environment by hand — is
        // shown as it was written, for the person to correct; the page's
        // problem box says what is wrong with it.
        return text;
      }
    };
    return '<h2>' + (isDefault ? t.html('consoleListeners.headServiceCustom')
                               : t.html('consoleListeners.headRealmOwn')) +
      '</h2>' +
      kit.note('<p>' + t.html('consoleListeners.defArray') +
        ' <code>{ "id", "port", "publicBaseUrl", ' +
        '"hostnames", "certificateFile", "privateKeyFile", "clientAuth", ' +
        '"tls" }</code>. ' + t.html('consoleListeners.defClientAuth') + ' ' +
        t.html('consoleListeners.defFiles', { whose: whose }) + ' ' +
        t.html('consoleListeners.defTls') + ' ' +
        t.html('consoleListeners.defAnswers', { whose: whose }) + '</p>',
        t.text('consoleListeners.defLabel')) +
      '<form method="post" action="/admin/listeners"><div class="formrow">' +
      '<input type="hidden" name="action" value="set-listeners">' +
      '<textarea name="value" rows="10" cols="90" spellcheck="false">' +
      kit.esc(pretty(d.listeners || '')) + '</textarea></div>' +
      '<div class="formrow"><button>' +
      t.html('consoleListeners.saveListeners') + '</button></div>' +
      '</form>' +
      '<h2>' + (isDefault ? t.html('consoleListeners.headWhichOn')
                          : t.html('consoleListeners.headRealmMapping')) +
      '</h2>' +
      kit.note('<p>' + t.html('consoleListeners.mapObject') +
        ' <code>{ "listeners": [...], ' +
        '"advertised": "..." }</code>. ' +
        t.html('consoleListeners.mapMain') + ' ' +
        (isDefault ? ''
          : t.html('consoleListeners.mapRealmFirst') + ' <code>' +
            kit.esc(d.serviceApplications || '{}') + '</code>. ') +
        t.html('consoleListeners.mapIssuer') + '</p>',
        t.text('consoleListeners.mapLabel')) +
      '<form method="post" action="/admin/listeners"><div class="formrow">' +
      '<input type="hidden" name="action" value="set-applications">' +
      '<textarea name="value" rows="10" cols="90" spellcheck="false">' +
      kit.esc(pretty(d.applications || '')) + '</textarea></div>' +
      '<div class="formrow"><label><input type="checkbox" name="confirm" ' +
      'value="true"> ' + t.html('consoleListeners.confirmOff') +
      '</label></div>' +
      '<div class="formrow"><button>' +
      t.html('consoleListeners.saveMapping') + '</button></div></form>';
  }

  // The page's words are its translator's (#539 phase 6); what the view
  // carries — a listener's name and purpose, a warning, a state — is drawn
  // as it comes, and the problem box stays English.
  static html(json: Json, ctx: Json): string {
    const t = ctx.t;
    const self = this;
    const head = '<table class="grid"><thead><tr><th>' +
      t.html('consoleListeners.thListener') + '</th>' +
      '<th>' + t.html('consoleListeners.thPort') + '</th><th>' +
      t.html('consoleListeners.thFloor') + '</th><th>' +
      t.html('consoleListeners.thSuites') + '</th><th>' +
      t.html('consoleListeners.thGroups') + '</th>' +
      '<th>' + t.html('consoleListeners.thClientCert') +
      '</th></tr></thead><tbody>';
    const custom: Json[] = json.custom || [];
    const status = (json.problem
      ? kit.warn('<p>' + kit.esc(json.problem.message) + ' <small>(' +
                 kit.esc(json.problem.code) + ')</small></p>',
                 'What is wrong with the listeners') : '') +
      (json.warnings || []).map(function (one: string): string {
        return kit.warn('<p>' + kit.esc(one) + '</p>',
                        t.text('consoleListeners.worthKnowing'));
      }).join('') +
      (json.rescue
        ? kit.warn('<p>' + t.html('consoleListeners.rescueText') + '</p>',
                   t.text('consoleListeners.rescueLabel')) : '');
    // The two links carry an href, which a message may not, so the
    // paragraph around them is messages with the anchors in the code.
    const builtIn = kit.note('<p>' + (json.realm === 'default'
        ? t.html('consoleListeners.builtInDefault')
        : t.html('consoleListeners.builtInRealm',
                 { realm: String(json.realm) })) +
        '</p><p>' + t.html('consoleListeners.clientCertBefore') +
        ' <a href="/admin/tls/trust">' +
        t.html('consoleListeners.clientCertLink') + '</a> ' +
        t.html('consoleListeners.clientCertAfter') +
        ' <a href="/admin/tls">TLS / mutual TLS</a>. ' +
        t.html('consoleListeners.appliedNext') + '</p>',
        t.text('consoleListeners.builtInLabel')) + head +
      json.listeners.map(function (row: Json): string {
        return '<tr id="listener-' + kit.esc(row.id) + '"><th>' +
          kit.esc(row.name) + '<br><small>' + kit.esc(row.what) +
          '</small></th><td>' + kit.esc(String(row.port)) +
          '<br><small><code>' + kit.esc(row.setting) + '</code></small>' +
          '</td>' + self.policyCells(row.policy, t) + '</tr>';
      }).join('') + '</tbody></table>';
    const customPanel = kit.note('<p>' +
        t.html('consoleListeners.customText') + '</p>',
        t.text('consoleListeners.customLabel')) +
      (custom.length ? head + custom.map(function (one: Json): string {
        return self.customRow(one, t);
      }).join('') + '</tbody></table>'
        : '<p><em>' + t.html('consoleListeners.customNone') + '</em></p>') +
      self.forms(json, t);
    const onOff = function (on: boolean): string {
      return on ? t.text('consoleListeners.on')
                : t.text('consoleListeners.off');
    };
    const tiles = '<div class="tiles">' +
      kit.tile(onOff(json.process.tls12), 'TLS 1.2') +
      kit.tile(String(json.process.tls13Suites.length),
               t.text('consoleListeners.thSuites')) +
      kit.tile(onOff(json.process.pqcOnly),
               t.text('consoleListeners.pqOnly')) +
      kit.tile(String(custom.length),
               t.text('consoleListeners.tileCustom')) +
      kit.tile(String(json.live.length),
               t.text('consoleListeners.tileLive')) +
      '</div>';
    // TABS, AS AN APPLICATION'S PAGE HAS THEM (rcbj, 2026-10-02), AND ONE
    // PER LISTENER SINCE #429 ("all of the settings ... to be per
    // listener"): the overview; the custom listeners and the mapping (#472);
    // the service-wide defaults every listener inherits; then each built-in
    // TLS listener, its policy in force first and its own rows after, and
    // each custom one's policy in force. `kit.tabbedPanels()`, no script; a
    // Save lands back on its tab.
    const settings = function (groups: string[]): string {
      return SettingsForms.forms(json.settings, PAGE, groups, t);
    };
    const inForce = function (policy: Json, pooling?: Json): string {
      if (!policy && !pooling) {
        return '';
      }
      const tlsRows: string[][] = !policy ? [] : [
        [t.text('consoleListeners.rowProtocol'), policy.tls12
          ? t.text('consoleListeners.tls12And13',
                   { floor: String(policy.minVersion) })
          : t.text('consoleListeners.tls13Only')],
         [t.text('consoleListeners.thSuites'),
          policy.tls13Suites.map(function (one: Json) {
            return one.name + (one.postQuantum
              ? ' ' + t.text('consoleListeners.pqSafe') : '');
          }).join(', ')],
         [t.text('consoleListeners.rowTls12Ciphers'),
          policy.tls12 ? policy.tls12Ciphers.join(', ') : '—'],
         [t.text('consoleListeners.rowPqOnly'), policy.pqcOnly
           ? t.text('consoleListeners.yes') : t.text('consoleListeners.no')],
         [t.text('consoleListeners.thGroups'), policy.groups],
         [t.text('consoleListeners.rowSigAlgs'), policy.signatureAlgorithms],
         [t.text('consoleListeners.thClientCert'),
          String(policy.clientAuth || '—')],
         [t.text('consoleListeners.rowTruststore'), policy.truststore],
         [t.text('consoleListeners.rowSessionLifetime'),
          policy.sessionTimeoutS + ' s'],
         [t.text('consoleListeners.rowSessionCache'), policy.sessionCacheSize
           ? t.text('consoleListeners.sessionIds',
                    { n: String(policy.sessionCacheSize) })
           : t.text('consoleListeners.ticketsOnly')]];
      const httpRows: string[][] = !pooling ? [] : [
        [t.text('consoleListeners.rowIdle'), pooling.keepAliveTimeoutS + ' s'],
        [t.text('consoleListeners.rowHeaderTimeout'),
         pooling.headersTimeoutS + ' s'],
        [t.text('consoleListeners.rowRequestsPer'),
         pooling.maxRequestsPerSocket
           ? String(pooling.maxRequestsPerSocket)
           : t.text('consoleListeners.noLimit')],
        [t.text('consoleListeners.rowMaxConnections'), pooling.maxConnections
          ? String(pooling.maxConnections)
          : t.text('consoleListeners.noLimit')]];
      return '<h2>' + t.html('consoleListeners.headInForce') +
        '</h2><table class="grid"><tbody>' +
        tlsRows.concat(httpRows).map(function (row) {
          return '<tr><th>' + kit.esc(row[0]) + '</th><td><code>' +
            kit.esc(String(row[1])) + '</code></td></tr>';
        }).join('') + '</tbody></table>' +
        kit.note(t.html('consoleListeners.inForceNote'));
    };
    const panels: Json[] = [
      { id: 'tab-listeners', label: t.text('consoleListeners.tabListeners'),
        html: status + builtIn },
      { id: 'tab-custom', label: t.text('consoleListeners.customLabel'),
        html: customPanel },
      { id: 'tab-applications',
        label: t.text('consoleListeners.tabApplications'),
        html: kit.note('<p>' + t.html('consoleListeners.applicationsText') +
          '</p>', t.text('consoleListeners.headWhichOn')) +
          self.mappingTable(json.applications || [], t) +
          settings(['Custom listeners']) },
      { id: 'tab-defaults', label: t.text('consoleListeners.tabDefaults'),
        html: kit.note(t.html('consoleListeners.defaultsNote')) +
              settings(['Listeners', 'HTTP connections', 'TLS']) }
    ];
    // Every built-in listener with settings of its own: the TLS ones, and
    // the plain-HTTP revocation listener for its connection pooling (#429).
    json.listeners.filter(function (row: Json): boolean {
      return !!row.group && (row.tls || !!row.http);
    }).forEach(function (row: Json): void {
      panels.push({ id: 'tab-' + row.id, label: row.name,
                    html: inForce(row.policy, row.http) +
                          settings([row.group]) });
    });
    custom.forEach(function (one: Json): void {
      panels.push({ id: 'tab-custom-' + one.id, label: one.id,
                    html: inForce(one.policy, one.http) +
                          kit.note(t.html('consoleListeners.customTabNote')) });
    });
    return tiles + kit.tabbedPanels('listeners', panels);
  }
}

export = ListenersPage;
