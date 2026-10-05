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
// its TLS policy and client authentication, a realm's own listener, and the
// settings, a tab each.
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
   * @returns the body as HTML
   */
  static render(view: Json): string {
    return ListenersPage.html(view);
  }

  // One policy as table cells.
  static policyCells(policy: Json): string {
    if (!policy) {
      return '<td colspan="4"><em>not TLS</em></td>';
    }
    const suites = policy.tls13Suites.map(function (one: Json): string {
      return '<code>' + kit.esc(one.name) + '</code>' +
        (one.postQuantum ? ' <small>(post-quantum safe)</small>' : '');
    }).join('<br>');
    return '<td>' + kit.esc(policy.minVersion) +
      (policy.tls12 ? '' : '<br><small>TLS 1.2 off</small>') +
      (policy.pqcOnly ? '<br><strong>post-quantum only</strong>' : '') +
      '</td><td>' + suites + '</td><td><small><code>' +
      kit.esc(policy.groups) + '</code></small></td><td>' +
      kit.esc(String(policy.clientAuth || '—')) + '</td>';
  }

  static html(json: Json): string {
    const self = this;
    const head = '<table class="grid"><thead><tr><th>Listener</th>' +
      '<th>Port</th><th>Floor</th><th>TLS 1.3 suites</th><th>Groups</th>' +
      '<th>Client certificate</th></tr></thead><tbody>';
    let body = '';
    if (json.ownListener) {
      const own = json.ownListener;
      body = kit.note('<p>Realm <code>' + kit.esc(json.realm) + '</code> ' +
        'is served on a listener of its own, configured below in the Realm ' +
        'listener group. Its TLS settings follow the process\'s unless set ' +
        'here (<code>inherit</code>, or an empty suite list).</p>',
        'This realm\'s own listener') +
        head + '<tr id="listener-realm"><th>' + kit.esc(json.realm) +
        '<br><small>' + kit.esc(own.publicBaseUrl) + ' · ' +
        kit.esc(own.state) + (own.why ? ' — ' + kit.esc(own.why) : '') +
        '</small></th><td>' + kit.esc(String(own.port)) + '</td>' +
        self.policyCells(own.policy) + '</tr></tbody></table>';
    } else {
      body = kit.note('<p>' + (json.realm === 'default'
        ? 'The default listeners, which every realm without a listener of ' +
          'its own is served on.'
        : 'Realm <code>' + kit.esc(json.realm) + '</code> has no listener ' +
          'of its own, so it is served on the default listeners below, ' +
          'under its <code>/realm/' + kit.esc(json.realm) + '</code> ' +
          'prefix. Their settings are the service\'s and are changed in the ' +
          'default realm; a listener of this realm\'s own is set up in the ' +
          'Realm listener group (<code>listener.port</code>).') + '</p>' +
        '<p>"Client certificate" is <strong>none</strong> (no ' +
        'CertificateRequest), <strong>optional</strong> (asked for, not ' +
        'required) or <strong>required</strong> (a handshake without one ' +
        'that chains to the <a href="/admin/tls/trust">client ' +
        'truststore</a> is refused). What a presented certificate is worth ' +
        'to a protocol — RFC 8705, GET /tls/sign-in, the remote PEP — is on ' +
        '<a href="/admin/tls">TLS / mutual TLS</a>. The TLS policy is ' +
        'applied at the next handshake when a setting changes.</p>',
        'Which listeners') + head +
        json.listeners.map(function (row: Json): string {
          return '<tr id="listener-' + kit.esc(row.id) + '"><th>' +
            kit.esc(row.name) + '<br><small>' + kit.esc(row.what) +
            '</small></th><td>' + kit.esc(String(row.port)) +
            '<br><small><code>' + kit.esc(row.setting) + '</code></small>' +
            '</td>' + self.policyCells(row.policy) + '</tr>';
        }).join('') + '</tbody></table>';
    }
    const tiles = '<div class="tiles">' +
      kit.tile(json.process.tls12 ? 'on' : 'off', 'TLS 1.2') +
      kit.tile(String(json.process.tls13Suites.length), 'TLS 1.3 suites') +
      kit.tile(json.process.pqcOnly ? 'on' : 'off', 'post-quantum only') +
      kit.tile(String(json.live.length), 'TLS listeners live here') +
      '</div>';
    // TABS, AS AN APPLICATION'S PAGE HAS THEM (rcbj, 2026-10-02), AND ONE
    // PER LISTENER SINCE #429 ("all of the settings ... to be per
    // listener"): the overview; the service-wide defaults every listener
    // inherits; then each TLS listener, its policy in force first and its own
    // rows after. `kit.tabbedPanels()`, no script; a Save lands back on its
    // tab. In a realm with a listener of its own, that listener and its
    // Realm listener rows; in a realm without one, the default listeners,
    // whose rows the realm cannot carry and the form draws read-only.
    const settings = function (groups: string[]): string {
      return SettingsForms.forms(json.settings, PAGE, groups);
    };
    const inForce = function (policy: Json, pooling?: Json): string {
      if (!policy && !pooling) {
        return '';
      }
      const tlsRows: string[][] = !policy ? [] : [
        ['Protocol', policy.tls12 ? 'TLS 1.2 and 1.3 (floor ' +
                                     policy.minVersion + ')' : 'TLS 1.3 only'],
         ['TLS 1.3 suites', policy.tls13Suites.map(function (one: Json) {
           return one.name + (one.postQuantum ? ' (post-quantum safe)' : '');
         }).join(', ')],
         ['TLS 1.2 ciphers', policy.tls12 ? policy.tls12Ciphers.join(', ')
                                           : '—'],
         ['Post-quantum only', policy.pqcOnly ? 'yes' : 'no'],
         ['Groups', policy.groups],
         ['Signature algorithms', policy.signatureAlgorithms],
         ['Client certificate', String(policy.clientAuth || '—')],
         ['Client truststore', policy.truststore],
         ['TLS session lifetime', policy.sessionTimeoutS + ' s'],
         ['TLS session cache', policy.sessionCacheSize
           ? policy.sessionCacheSize + ' session ID(s)'
           : 'none (tickets only)']];
      const httpRows: string[][] = !pooling ? [] : [
        ['Idle connection kept', pooling.keepAliveTimeoutS + ' s'],
        ['Request header timeout', pooling.headersTimeoutS + ' s'],
        ['Requests per connection', pooling.maxRequestsPerSocket
          ? String(pooling.maxRequestsPerSocket) : 'no limit'],
        ['Open connections at most', pooling.maxConnections
          ? String(pooling.maxConnections) : 'no limit']];
      return '<h2>In force on this listener</h2><table class="grid"><tbody>' +
        tlsRows.concat(httpRows).map(function (row) {
          return '<tr><th>' + kit.esc(row[0]) + '</th><td><code>' +
            kit.esc(String(row[1])) + '</code></td></tr>';
        }).join('') + '</tbody></table>' +
        kit.note('Each value is this listener\'s own where its row below ' +
                   'sets one, and the service-wide default otherwise ' +
                   '(<em>inherit</em>, an empty box, or -1 for a number).');
    };
    const panels: Json[] = [
      { id: 'tab-listeners', label: json.ownListener ? 'This realm\'s listener'
                                                     : 'Listeners',
        html: body }
    ];
    if (json.ownListener) {
      panels.push({ id: 'tab-realm-listener', label: 'Its settings',
                    html: inForce(json.ownListener.policy,
                                  json.ownListener.http) +
                          settings(['Realm listener']) });
    } else {
      panels.push({ id: 'tab-defaults', label: 'Service-wide defaults',
                    html: kit.note('What every TLS listener inherits unless ' +
                                     'its own tab says otherwise.') +
                          settings(['Listeners', 'HTTP connections',
                                    'TLS']) });
      // Every listener with settings of its own: the TLS ones, and the
      // plain-HTTP revocation listener for its connection pooling (#429).
      json.listeners.filter(function (row: Json): boolean {
        return !!row.group && (row.tls || !!row.http);
      }).forEach(function (row: Json): void {
        panels.push({ id: 'tab-' + row.id, label: row.name,
                      html: inForce(row.policy, row.http) +
                            settings([row.group]) });
      });
      if (json.realm !== 'default') {
        panels.push({ id: 'tab-realm-listener', label: 'Realm listener',
                      html: settings(['Realm listener']) });
      }
    }
    return tiles + kit.tabbedPanels('listeners', panels);
  }
}

export = ListenersPage;
