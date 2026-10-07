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

  // One custom listener's row: its address, owner, state on this node and
  // the policy in force.
  static customRow(one: Json): string {
    return '<tr id="listener-' + kit.esc(one.id) + '"><th>' +
      kit.esc(one.id) + '<br><small>' + kit.esc(one.publicBaseUrl) +
      (one.owner !== 'default' ? ' · realm <code>' + kit.esc(one.owner) +
                                 '</code>' : ' · every realm') +
      ' · ' + kit.esc(one.certificateSource) + ' certificate · ' +
      kit.esc(one.state) + (one.why ? ' — ' + kit.esc(one.why) : '') +
      '</small></th><td>' + kit.esc(String(one.port)) + '</td>' +
      ListenersPage.policyCells(one.policy) + '</tr>';
  }

  // Which application is on which listener: the mapping as it stands.
  static mappingTable(rows: Json[]): string {
    return '<table class="grid"><thead><tr><th>Application</th>' +
      '<th>Listeners</th><th>Advertised on</th><th>Decided by</th></tr>' +
      '</thead><tbody>' + rows.map(function (row: Json): string {
        return '<tr id="application-' + kit.esc(row.application) + '"><th>' +
          kit.esc(row.label) + ' <small><code>' + kit.esc(row.application) +
          '</code>' + (row.session ? ' · reads the sign-on session' : '') +
          '</small><br><small>' + kit.esc(row.what) + '</small></th><td>' +
          row.listeners.map(function (id: string): string {
            return '<code>' + kit.esc(id) + '</code>';
          }).join(', ') + '</td><td><code>' + kit.esc(row.advertised) +
          '</code></td><td>' + kit.esc(row.decidedBy) + '</td></tr>';
      }).join('') + '</tbody></table>';
  }

  // The two writes: the listeners this realm defines, and its mapping, each
  // as the JSON a person reads and edits.
  static forms(json: Json): string {
    const d = json.definitions || {};
    const isDefault = json.realm === 'default';
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
    return '<h2>' + (isDefault ? 'The service\'s custom listeners'
                               : 'This realm\'s own listeners') + '</h2>' +
      kit.note('<p>A JSON array of <code>{ "id", "port", "publicBaseUrl", ' +
        '"hostnames", "certificateFile", "privateKeyFile", "clientAuth", ' +
        '"tls" }</code>. <code>clientAuth</code> is <code>none</code>, ' +
        '<code>optional</code> (the default) or <code>required</code> — a ' +
        'listener for mutual TLS. Without certificate files the ' +
        (isDefault ? 'default realm\'s' : 'realm\'s') + ' certificate ' +
        'authority issues one for <code>hostnames</code>. ' +
        '<code>tls</code> takes the per-listener TLS settings by their ' +
        'short names (<code>disableTls12</code>, ' +
        '<code>tls13CipherSuites</code>, <code>pqcOnly</code>, ...). ' +
        (isDefault ? 'These answer every realm.'
                   : 'These answer this realm alone.') +
        ' Empty for none.</p>', 'The listener definition') +
      '<form method="post" action="/admin/listeners"><div class="formrow">' +
      '<input type="hidden" name="action" value="set-listeners">' +
      '<textarea name="value" rows="10" cols="90" spellcheck="false">' +
      kit.esc(pretty(d.listeners || '')) + '</textarea></div>' +
      '<div class="formrow"><button>Save the listeners</button></div>' +
      '</form>' +
      '<h2>' + (isDefault ? 'Which application is on which listener'
                          : 'This realm\'s mapping') + '</h2>' +
      kit.note('<p>A JSON object from an application id, or <code>*</code> ' +
        'for every one not named, to <code>{ "listeners": [...], ' +
        '"advertised": "..." }</code>. <code>main</code> is the main port. ' +
        'An application not named is on <code>main</code> alone. ' +
        (isDefault ? ''
          : 'This realm\'s entries are read before the service\'s, ' +
            'which are <code>' + kit.esc(d.serviceApplications || '{}') +
            '</code>. ') +
        'Changing where <code>oauth-oidc</code> is advertised changes the ' +
        'issuer every token and client names. Taking ' +
        '<code>management-api</code> off the listener this page was ' +
        'reached on needs the confirmation below; ' +
        '<code>STS_LISTENERS_ADMIN_ON_MAIN=true</code> puts the console and ' +
        'the API back on the main port at the next start.</p>',
        'The mapping') +
      '<form method="post" action="/admin/listeners"><div class="formrow">' +
      '<input type="hidden" name="action" value="set-applications">' +
      '<textarea name="value" rows="10" cols="90" spellcheck="false">' +
      kit.esc(pretty(d.applications || '')) + '</textarea></div>' +
      '<div class="formrow"><label><input type="checkbox" name="confirm" ' +
      'value="true"> Take the management API off the listener this page ' +
      'was reached on, if this does</label></div>' +
      '<div class="formrow"><button>Save the mapping</button></div></form>';
  }

  static html(json: Json): string {
    const self = this;
    const head = '<table class="grid"><thead><tr><th>Listener</th>' +
      '<th>Port</th><th>Floor</th><th>TLS 1.3 suites</th><th>Groups</th>' +
      '<th>Client certificate</th></tr></thead><tbody>';
    const custom: Json[] = json.custom || [];
    const status = (json.problem
      ? kit.warn('<p>' + kit.esc(json.problem.message) + ' <small>(' +
                 kit.esc(json.problem.code) + ')</small></p>',
                 'What is wrong with the listeners') : '') +
      (json.warnings || []).map(function (one: string): string {
        return kit.warn('<p>' + kit.esc(one) + '</p>', 'Worth knowing');
      }).join('') +
      (json.rescue
        ? kit.warn('<p><code>listeners.adminOnMain</code> is on: the ' +
                   'console and the management API are on the main port ' +
                   'and advertised there, whatever the mapping says.</p>',
                   'The rescue is on') : '');
    const builtIn = kit.note('<p>' + (json.realm === 'default'
        ? 'The built-in listeners, which every realm is served on.'
        : 'The built-in listeners. Their settings are the service\'s and ' +
          'are changed in the default realm; this realm is served on them ' +
          'under its <code>/realm/' + kit.esc(json.realm) + '</code> ' +
          'prefix, and on its own listeners where its mapping says.') +
        '</p><p>"Client certificate" is <strong>none</strong> (no ' +
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
    const customPanel = kit.note('<p>Listeners an administrator defined ' +
        '(#472): HTTPS, bound on every node, each answering only the hosted ' +
        'applications mapped to it — a path of any other is a 404 there. ' +
        'Its TLS settings follow the service\'s unless its definition\'s ' +
        '<code>tls</code> says otherwise.</p>', 'Custom listeners') +
      (custom.length ? head + custom.map(function (one: Json): string {
        return self.customRow(one);
      }).join('') + '</tbody></table>'
        : '<p><em>None: every application is on the main port.</em></p>') +
      self.forms(json);
    const tiles = '<div class="tiles">' +
      kit.tile(json.process.tls12 ? 'on' : 'off', 'TLS 1.2') +
      kit.tile(String(json.process.tls13Suites.length), 'TLS 1.3 suites') +
      kit.tile(json.process.pqcOnly ? 'on' : 'off', 'post-quantum only') +
      kit.tile(String(custom.length), 'custom listeners') +
      kit.tile(String(json.live.length), 'TLS listeners live here') +
      '</div>';
    // TABS, AS AN APPLICATION'S PAGE HAS THEM (rcbj, 2026-10-02), AND ONE
    // PER LISTENER SINCE #429 ("all of the settings ... to be per
    // listener"): the overview; the custom listeners and the mapping (#472);
    // the service-wide defaults every listener inherits; then each built-in
    // TLS listener, its policy in force first and its own rows after, and
    // each custom one's policy in force. `kit.tabbedPanels()`, no script; a
    // Save lands back on its tab.
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
      { id: 'tab-listeners', label: 'Listeners', html: status + builtIn },
      { id: 'tab-custom', label: 'Custom listeners', html: customPanel },
      { id: 'tab-applications', label: 'Applications',
        html: kit.note('<p>Where each hosted application is: the listeners ' +
          'that answer it, and the one its URLs — its issuer, metadata, ' +
          'redirects and mailed links — are built on.</p>',
          'Which application is on which listener') +
          self.mappingTable(json.applications || []) +
          settings(['Custom listeners']) },
      { id: 'tab-defaults', label: 'Service-wide defaults',
        html: kit.note('What every TLS listener inherits unless its own ' +
                       'tab or definition says otherwise.') +
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
                          kit.note('Set in the listener\'s definition, on ' +
                                   'the Custom listeners tab.') });
    });
    return tiles + kit.tabbedPanels('listeners', panels);
  }
}

export = ListenersPage;
