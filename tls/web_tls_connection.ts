// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_tls_connection.ts
//
// ---------------------------------------------------------------------------
// MONITORING → TLS CONNECTION, DRAWN FROM ITS VIEW ALONE (#597, 2026-10-12).
//
// Draws the answer of `GET /admin-api/tls-connection`
// (`tls/tls_server.js`'s `connectionView()`): what this service saw of the
// console's own call to that operation — the TLS connection, the client
// certificate on it, and the forwarding headers with what was believed of
// them. Two tabs, Connection and Forwarded headers, the two development
// pages (`/tls`, `/tls/forwarded`) it replaced.
//
// **THE PAGE SAYS WHICH REQUEST IT DESCRIBES**: the console is a static
// application (#446), so the view is the API call the runtime made after
// the page loaded, not the page load itself. For the facts drawn here that
// is the same answer (the certificate is per connection, a proxy's headers
// are the same on every request it relays), and the lead says so.
//
// The page's own words are the `consoleTlsConnection` catalogs'. WHAT THE
// SERVER SAYS IS DATA, and English (#539): a header's description, the
// notes, `whatItMeans`, the identity gate's `why` and the revocation
// verdict's sentence are drawn as they are, escaped.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_`
// modules only, logs nothing, and is bundled for a browser by
// `build-typescript.sh` with the rest of the console. It was born static:
// no page module draws it.
// ---------------------------------------------------------------------------

import kit = require('../admin-ui/web_kit');

type Json = any;

/**
 * Draws Monitoring → TLS connection from the answer of `GET
 * /admin-api/tls-connection`.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class TlsConnectionPage {
  /**
   * Draws the page's body from its view.
   *
   * @param view - the answer of the page's management API operation
   * @param ctx - the render context (`WebKit.context()`)
   * @returns the body as HTML
   */
  static render(view: Json, ctx?: Json): string {
    const context = ctx || kit.context();
    const t = context.t;
    const v = view || {};
    return kit.note(t.html('consoleTlsConnection.lead')) +
      '<h2 data-tab="connection">' +
      t.html('consoleTlsConnection.connection') + '</h2>' +
      TlsConnectionPage.connection(v.connection || {}, t) +
      '<h2>' + t.html('consoleTlsConnection.clientCertificate') + '</h2>' +
      TlsConnectionPage.certificate(v.clientCertificate || {}, t) +
      '<h2 data-tab="forwarded">' +
      t.html('consoleTlsConnection.forwarded') + '</h2>' +
      TlsConnectionPage.forwarded(v.forwarded || {}, t) +
      kit.note('<a href="/admin-api/tls-connection">' +
        t.html('consoleTlsConnection.linkApi') + '</a> &middot; ' +
        '<a href="/admin/tls/trust">' +
        t.html('consoleTlsConnection.linkTrust') + '</a> &middot; ' +
        '<a href="/admin/tls">' +
        t.html('consoleTlsConnection.linkSettings') + '</a> &middot; ' +
        '<a href="/admin/listeners">' +
        t.html('consoleTlsConnection.linkListeners') + '</a>');
  }

  // A two-column table of label and value; a missing value is a dash.
  private static rows(pairs: Array<[string, string]>): string {
    return '<table>' + pairs.map(function (pair) {
      return '<tr><td>' + pair[0] + '</td><td>' + pair[1] + '</td></tr>';
    }).join('') + '</table>';
  }

  // A value from the view, escaped, in code type; a dash when there is none.
  private static code(value: Json): string {
    return value === null || value === undefined || value === ''
      ? '—' : '<code>' + kit.esc(String(value)) + '</code>';
  }

  // Yes or no, in the reader's language.
  private static yesNo(on: boolean, t: Json): string {
    return on ? t.html('consoleTlsConnection.yes')
              : t.html('consoleTlsConnection.no');
  }

  // The Connection tab's first table: the socket's own TLS facts.
  private static connection(c: Json, t: Json): string {
    const self = TlsConnectionPage;
    return self.rows([
      [t.html('consoleTlsConnection.https'),
       c.https ? '<span class="state-valid">' +
                 t.html('consoleTlsConnection.yes') + '</span>'
               : '<span class="state-invalid">' +
                 t.html('consoleTlsConnection.no') + '</span>'],
      [t.html('consoleTlsConnection.protocol'), self.code(c.protocol)],
      [t.html('consoleTlsConnection.cipher'), self.code(c.cipher)],
      [t.html('consoleTlsConnection.peerAddress'), self.code(c.peerAddress)],
      [t.html('consoleTlsConnection.clientAddress'),
       self.code(c.clientAddress)]
    ]);
  }

  // The client certificate the connection carried, what verified, what the
  // identity gate made of it, and its revocation verdict.
  private static certificate(cc: Json, t: Json): string {
    const self = TlsConnectionPage;
    if (!cc.presented) {
      return kit.note(t.html('consoleTlsConnection.noCertificate')) +
        kit.note(kit.esc(cc.note || ''));
    }
    const cert = cc.certificate || {};
    const identity = cc.identity || null;
    const revocation = cc.revocation || null;
    const verified = cc.verified
      ? '<span class="state-valid">' +
        t.html('consoleTlsConnection.verified') + '</span>'
      : '<span class="state-invalid">' +
        t.html('consoleTlsConnection.notVerified') + '</span>' +
        (cc.authorizationError
          ? ' <code>' + kit.esc(cc.authorizationError) + '</code>' : '');
    const gate = !identity ? '—'
      : (identity.accepted
        ? '<span class="state-valid">' +
          t.html('consoleTlsConnection.accepted') + '</span> ' +
          kit.esc(String(identity.kind || '')) + ' <code>' +
          kit.esc(String(identity.username || '')) + '</code>' +
          (identity.realm !== null && identity.realm !== undefined
            ? ' (' + t.html('consoleTlsConnection.realm') + ' <code>' +
              kit.esc(String(identity.realm || 'default')) + '</code>)'
            : '')
        : (identity.issuedHere
          ? '<span class="state-invalid">' +
            t.html('consoleTlsConnection.notAccepted') + '</span>' +
            (identity.why ? ' — ' + kit.esc(identity.why) : '')
          : t.html('consoleTlsConnection.notIssuedHere')));
    const revoked = !revocation ? t.html('consoleTlsConnection.notChecked')
      : '<code>' + kit.esc(String(revocation.status || '')) + '</code>' +
        (revocation.why || revocation.reason
          ? ' — ' + kit.esc(String(revocation.why || revocation.reason))
          : '');
    return self.rows([
      [t.html('consoleTlsConnection.presented'),
       self.yesNo(true, t)],
      [t.html('consoleTlsConnection.verifiedRow'), verified],
      [t.html('consoleTlsConnection.subject'), self.code(cert.subject)],
      [t.html('consoleTlsConnection.issuer'), self.code(cert.issuer)],
      [t.html('consoleTlsConnection.serial'), self.code(cert.serialNumber)],
      [t.html('consoleTlsConnection.validity'),
       kit.esc(String(cert.validFrom || '—')) + '<br>' +
       kit.esc(String(cert.validTo || '—'))],
      [t.html('consoleTlsConnection.altNames'),
       self.code(cert.subjectAltName)],
      [t.html('consoleTlsConnection.fingerprint'),
       self.code(cert.fingerprint256)],
      [t.html('consoleTlsConnection.thumbprint'), self.code(cc.thumbprint)],
      [t.html('consoleTlsConnection.identity'), gate],
      [t.html('consoleTlsConnection.revocation'), revoked]
    ]) + kit.note(kit.esc(cc.note || ''));
  }

  // The Forwarded headers tab: the two settings, what was believed, every
  // forwarding header, and the client-certificate headers read by nothing.
  private static forwarded(f: Json, t: Json): string {
    const self = TlsConnectionPage;
    const socket = f.socket || {};
    const list = Array.isArray(f.trustedProxies) ? f.trustedProxies : [];
    const headerRows = function (rows: Json[]): string {
      return (rows || []).map(function (row) {
        return '<tr><td><code>' + kit.esc(row.header) + '</code></td><td>' +
          (row.present ? '<code>' + kit.esc(String(row.value)) + '</code>'
                       : '<span class="sub">' +
                         t.html('consoleTlsConnection.notSent') +
                         '</span>') +
          '</td><td class="sub">' + kit.esc(row.what || '') + '</td></tr>';
      }).join('');
    };
    const certHeaders = f.clientCertificateHeaders || {};
    return kit.note(kit.esc(f.whatItMeans || '')) +
      self.rows([
        ['<code>global.trustProxy</code>', self.yesNo(!!f.trustProxy, t)],
        ['<code>global.trustedProxies</code>',
         list.length ? self.code(list.join(', '))
                     : t.html('consoleTlsConnection.anyPeer')],
        [t.html('consoleTlsConnection.peerTrusted'),
         self.yesNo(!!f.peerIsTrustedProxy, t)],
        [t.html('consoleTlsConnection.believed'),
         self.yesNo(!!f.believed, t)],
        [t.html('consoleTlsConnection.socketSaw'),
         self.code((socket.scheme || '') + '://' + (socket.host || ''))],
        [t.html('consoleTlsConnection.effectiveBase'),
         self.code(f.effectiveBaseUrl)]
      ]) +
      '<h3>' + t.html('consoleTlsConnection.forwardingHeaders') + '</h3>' +
      '<table><tr><th>' + t.html('consoleTlsConnection.header') +
      '</th><th>' + t.html('consoleTlsConnection.thisRequest') +
      '</th><th>' + t.html('consoleTlsConnection.whatHere') + '</th></tr>' +
      headerRows(f.forwarding) + '</table>' +
      '<h3>' + t.html('consoleTlsConnection.certificateHeaders') + '</h3>' +
      kit.warn(kit.esc(certHeaders.note || '')) +
      '<table><tr><th>' + t.html('consoleTlsConnection.header') +
      '</th><th>' + t.html('consoleTlsConnection.thisRequest') +
      '</th><th>' + t.html('consoleTlsConnection.whatItIs') + '</th></tr>' +
      headerRows(certHeaders.headers) + '</table>' +
      kit.note(kit.esc(f.proxyMustSanitize || ''));
  }
}

export = TlsConnectionPage;
