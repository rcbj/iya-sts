// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_tls_trust.ts
//
// ---------------------------------------------------------------------------
// SERVER CONFIGURATION → CLIENT-CERTIFICATE TRUSTSTORE, DRAWN FROM ITS VIEW
// ALONE (#446, 2026-10-05).
//
// Draws the client-certificate truststore from the answer of `GET
// /admin-api/tls/trust`: the anchors a client certificate is verified against,
// where each came from, and the forms that add and remove them.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// It was drawn inside the route of `/admin/tls/trust` in `admin-ui/admin.ts`,
// which still draws the page until the console's cutover by calling this with
// its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('../admin-ui/web_kit');

type Json = any;

/**
 * Draws the client-certificate truststore from the answer of `GET
 * /admin-api/tls/trust`: the anchors a client certificate is verified against,
 * where each came from, and the forms that add and remove them.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class TlsTrustPage {
  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static body(ctx, json) {
    const mayChange = ctx.write;
    if (!json.installed) {
      const missing = '<div class="err"><strong>The ' +
        'client-certificate truststore is not installed in this process.' +
        '</strong> ' + kit.esc(json.note) + '</div>';
      return missing;
    }
    const back = kit.queryWith(kit.listViewOf('/admin/tls/trust', ctx.query),
                           {});
    const nav = kit.pageNavPair('/admin/tls/trust', kit.pageParamsOf(ctx.query),
                                 json.paging && Object.assign({ param: 'page',
                                   noun: 'anchors', offset: 0 },
                                   json.paging));
    const rows = json.anchors.map(function (anchor) {
      return '<tr>' +
        '<td><code>' + kit.esc(anchor.subject) + '</code>' +
        (anchor.readable ? '' : '<div class="state-invalid">' +
          kit.esc('OpenSSL cannot read this certificate, so no handshake ' +
                   'uses it.') +
          '</div>') +
        '<div class="sub">' + (anchor.ca ? 'CA' : 'not a CA') +
        '</div></td>' +
        '<td><code>' + kit.esc(anchor.issuer || '—') + '</code></td>' +
        '<td class="sub"><code>' + kit.esc(anchor.serial || '—') +
        '</code></td>' +
        '<td class="sub">' + kit.esc(anchor.notBefore || '—') + '<br>' +
        kit.esc(anchor.notAfter || '—') + '</td>' +
        '<td class="sub"><code>' + kit.esc(anchor.fingerprint256) +
        '</code></td><td>' + (anchor.source === 'file'
          ? '<span title="' +
            kit.esc('Loaded from tls.trustAnchorsFile at ' +
              'startup. Removing it here lasts until the next start, when ' +
              'the file is read again.') + '">file</span>'
          : '<span title="' + kit.esc(anchor.persisted
              ? 'Added at runtime and written to ou=trustAnchors, so it ' +
                'survives a restart wherever the directory is persisted.'
              : 'Added at runtime and NOT written down — the directory was ' +
                'full or no store is installed — so it is gone at the next ' +
                'start.') +
            '">runtime' + (anchor.persisted ? '' : ' (not stored)') +
            '</span>') +
        '</td>' +
        '<td>' + (mayChange
          ? '<form method="post" action="/admin/tls/trust">' +
            '<input type="hidden" name="action" value="remove">' +
            '<input type="hidden" name="fingerprint" value="' +
            kit.esc(anchor.fingerprint256) + '">' +
            '<input type="hidden" name="back" value="' + kit.esc(back) +
            '"><button type="submit" class="secondary" title="' +
            kit.esc(anchor.source === 'file'
              ? 'Stops client certificates chaining only to this anchor ' +
                     'from verifying, until the next start re-reads ' +
                     'tls.trustAnchorsFile.'
              : 'Stops client certificates chaining only to this anchor ' +
                     'from verifying. Nothing brings it back.') +
                     '">Remove</button></form>'
          : '<span class="sub">Admin Write</span>') + '</td></tr>';
    }).join('') || '<tr><td colspan="7">' + kit.esc('Empty. No client ' +
      'certificate verifies on any listener, so every one presented ' +
      'arrives UNVERIFIED and everything that reads one refuses it.') +
      '</td></tr>';

    const inner = kit.note('Every anchor <strong>LDAPS 636 and the main ' +
      'port</strong> verify a client certificate against. A certificate ' +
      'that chains to one of these is VERIFIED — and since 2026-09-06 a ' +
      'verified certificate is an identity here: it starts a sign-on ' +
      'session, and it is what admits a remote XACML PEP to ' +
      '<code>/xacml/pep/*</code>. So this list decides whose certificates ' +
      'this service believes.') +
      kit.warn('<strong>Nothing on this page is persisted.</strong> ' +
      kit.esc(json.notes.persisted)) +
      kit.note(kit.esc(json.notes.scope) + ' ' +
                kit.esc(json.notes.effect) + ' ' +
      kit.esc(json.notes.revocation)) +
      '<div class="tiles">' +
      kit.tile(json.total, 'anchors') +
      kit.tile(json.fromFile, 'from the file') +
      kit.tile(json.atRuntime, 'added at runtime') +
      kit.tile(json.max, 'maximum') +
      '</div>' +
      kit.note('<code>tls.trustAnchorsFile</code> is ' + (json.anchorsFile
        ? '<code>' + kit.esc(json.anchorsFile) + '</code>, and ' +
          kit.esc(String(json.loadedFromFile)) + ' anchor(s) were loaded ' +
          'from it at startup.'
        : 'not set, so every anchor here was added while this process was ' +
          'running.') +
      ' The two test controls on <a href="/tls">/tls</a> — <code>POST ' +
      '/tls/trust</code> and <code>POST /tls/trust/clear</code> — ' +
      (json.doors.testControls.open
        ? 'answer anybody in this development-mode process.'
        : 'are refused in product mode; this page and ' +
          '<code>/admin-api/tls/trust</code> are the runtime doors.')) +
      '<h2>Anchors</h2>' + nav.head +
      '<table><tr><th>Subject</th><th>Issuer</th><th>Serial</th>' +
      '<th>Not before / not after</th><th>SHA-256 fingerprint</th>' +
      '<th>Source</th><th></th></tr>' + rows + '</table>' + nav.foot +
      kit.perPageForm('/admin/tls/trust', 'page', '1', json.perPage) +
      (mayChange
        ? '<h2>Add anchors</h2>' +
          kit.note('One or more <code>-----BEGIN CERTIFICATE-----</code> ' +
          'blocks — the root, or the whole chain above the leaf. Every ' +
          'block must be one OpenSSL can read, or NONE is added: a block ' +
          'the listener cannot parse makes the next truststore change ' +
          'throw on every listener. A certificate already held is counted ' +
          'and not added twice.') +
          '<form method="post" action="/admin/tls/trust">' +
          '<input type="hidden" name="action" value="add">' +
          '<input type="hidden" name="back" value="' + kit.esc(back) + '">' +
          '<textarea name="certificates" rows="8" ' +
          'placeholder="-----BEGIN CERTIFICATE-----"></textarea>' +
          '<div class="formrow"><button type="submit">Trust these</button>' +
          '</div></form>'
        : kit.note('Changing this list needs <strong>Admin Write</strong>' +
          '.')) +
      '<h2>What there is deliberately no button for</h2>' +
      kit.note('<strong>Emptying the truststore.</strong> A bulk clear on ' +
      'this door would be the one control whose reach is every client ' +
      'certificate every other caller relies on — a remote PEP ' +
      'authenticating as nobody for the rest of a run is what one ' +
      'unguarded clear has already cost. Remove the rows you mean, one at ' +
      'a time; the ones you did not put there are the ones you have to ' +
      'name. Removing a <code>file</code> anchor is allowed and lasts ' +
      'until the next start.') +
      kit.note('<a href="/admin/tls/trust?format=json">this page as ' +
      'JSON</a> &middot; <a href="/admin-api/tls/trust">the same over the ' +
      'management API</a> &middot; <a href="/admin/tls">the TLS ' +
      'listeners\' settings</a> &middot; <a href="/tls">the TLS ' +
      'endpoint</a> &middot; <a href="/admin/pki">this service\'s own ' +
      'certificate authority</a>');

    return inner;
  }
}

export = TlsTrustPage;
