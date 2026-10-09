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
    const t = ctx.t;
    const mayChange = ctx.write;
    // A problem banner: it stays English, as every refusal does (#539).
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
                                   json.paging), t);
    const rows = json.anchors.map(function (anchor) {
      return '<tr>' +
        '<td><code>' + kit.esc(anchor.subject) + '</code>' +
        (anchor.readable ? '' : '<div class="state-invalid">' +
          kit.esc(t.text('consoleTlsTrust.unreadable')) +
          '</div>') +
        '<div class="sub">' + (anchor.ca ? t.html('consoleTlsTrust.ca')
                                         : t.html('consoleTlsTrust.notCa')) +
        '</div></td>' +
        '<td><code>' + kit.esc(anchor.issuer || '—') + '</code></td>' +
        '<td class="sub"><code>' + kit.esc(anchor.serial || '—') +
        '</code></td>' +
        '<td class="sub">' + kit.esc(anchor.notBefore || '—') + '<br>' +
        kit.esc(anchor.notAfter || '—') + '</td>' +
        '<td class="sub"><code>' + kit.esc(anchor.fingerprint256) +
        '</code></td><td>' + (anchor.source === 'file'
          ? '<span title="' +
            kit.esc(t.text('consoleTlsTrust.sourceFileTip')) + '">' +
            t.html('consoleTlsTrust.sourceFile') + '</span>'
          : '<span title="' + kit.esc(anchor.persisted
              ? t.text('consoleTlsTrust.sourceRuntimeStoredTip')
              : t.text('consoleTlsTrust.sourceRuntimeUnstoredTip')) +
            '">' + t.html('consoleTlsTrust.sourceRuntime') +
            (anchor.persisted ? ''
                              : t.html('consoleTlsTrust.notStored')) +
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
              ? t.text('consoleTlsTrust.removeFileTip')
              : t.text('consoleTlsTrust.removeRuntimeTip')) +
                     '">' + t.html('consoleTlsTrust.remove') +
                     '</button></form>'
          : '<span class="sub">Admin Write</span>') + '</td></tr>';
    }).join('') || '<tr><td colspan="7">' +
      kit.esc(t.text('consoleTlsTrust.empty')) +
      '</td></tr>';

    // The notes below are drawn from the view as they come (English); only
    // what this file writes is translated (#539).
    const inner = kit.note(t.html('consoleTlsTrust.intro')) +
      kit.warn(t.html('consoleTlsTrust.notPersisted') + ' ' +
      kit.esc(json.notes.persisted)) +
      kit.note(kit.esc(json.notes.scope) + ' ' +
                kit.esc(json.notes.effect) + ' ' +
      kit.esc(json.notes.revocation)) +
      '<div class="tiles">' +
      kit.tile(json.total, t.text('consoleTlsTrust.tileAnchors')) +
      kit.tile(json.fromFile, t.text('consoleTlsTrust.tileFromFile')) +
      kit.tile(json.atRuntime, t.text('consoleTlsTrust.tileAtRuntime')) +
      kit.tile(json.max, t.text('consoleTlsTrust.tileMaximum')) +
      '</div>' +
      // The link to /tls is markup a message cannot carry, so the sentence
      // around it is cut there.
      kit.note((json.anchorsFile
        ? t.html('consoleTlsTrust.fileSet',
                 { file: json.anchorsFile,
                   n: String(json.loadedFromFile) })
        : t.html('consoleTlsTrust.fileUnset')) +
      t.html('consoleTlsTrust.controlsBefore') + '<a href="/tls">/tls</a>' +
      t.html('consoleTlsTrust.controlsAfter') +
      (json.doors.testControls.open
        ? t.html('consoleTlsTrust.controlsOpen')
        : t.html('consoleTlsTrust.controlsRefused'))) +
      '<h2>' + t.html('consoleTlsTrust.anchors') + '</h2>' + nav.head +
      '<table><tr><th>' + t.html('consoleTlsTrust.thSubject') + '</th><th>' +
      t.html('consoleTlsTrust.thIssuer') + '</th><th>' +
      t.html('consoleTlsTrust.thSerial') + '</th>' +
      '<th>' + t.html('consoleTlsTrust.thValidity') + '</th><th>' +
      t.html('consoleTlsTrust.thFingerprint') + '</th>' +
      '<th>' + t.html('consoleTlsTrust.thSource') + '</th><th></th></tr>' +
      rows + '</table>' + nav.foot +
      kit.perPageForm('/admin/tls/trust', 'page', '1', json.perPage,
                      undefined, undefined, t) +

      (mayChange
        ? '<h2>' + t.html('consoleTlsTrust.addAnchors') + '</h2>' +
          kit.note(t.html('consoleTlsTrust.addNote')) +
          '<form method="post" action="/admin/tls/trust">' +
          '<input type="hidden" name="action" value="add">' +
          '<input type="hidden" name="back" value="' + kit.esc(back) + '">' +
          '<textarea name="certificates" rows="8" ' +
          'placeholder="-----BEGIN CERTIFICATE-----"></textarea>' +
          '<div class="formrow"><button type="submit">' +
          t.html('consoleTlsTrust.trustThese') + '</button>' +
          '</div></form>'
        : kit.note(t.html('consoleTlsTrust.needsWrite'))) +
      '<h2>' + t.html('consoleTlsTrust.noButton') + '</h2>' +
      kit.note(t.html('consoleTlsTrust.noClear')) +
      // A row of links: the words are messages, the anchors are code.
      kit.note('<a href="/admin/tls/trust?format=json">' +
      t.html('consoleTlsTrust.linkJson') + '</a> &middot; ' +
      '<a href="/admin-api/tls/trust">' + t.html('consoleTlsTrust.linkApi') +
      '</a> &middot; <a href="/admin/tls">' +
      t.html('consoleTlsTrust.linkSettings') + '</a> &middot; ' +
      '<a href="/tls">' + t.html('consoleTlsTrust.linkEndpoint') +
      '</a> &middot; <a href="/admin/pki">' +
      t.html('consoleTlsTrust.linkPki') + '</a>');

    return inner;
  }
}

export = TlsTrustPage;
