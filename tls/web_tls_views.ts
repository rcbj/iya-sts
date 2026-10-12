// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_tls_views.ts
//
// ---------------------------------------------------------------------------
// THE TLS DIAGNOSTIC PAGES' RENDERERS (#583, 2026-10-12).
//
// Each page is drawn from the view its shell carried (`tls_pages.ts`,
// `data-sts-state`), or — after one of the `/tls` page's two acts — from
// what the act answered, by the view's `kind`:
//
//   * `tls` — `GET /tls`: the certificate this service presents, the
//     listener, the client truststore and its two buttons (where the
//     process serves them, #585), revocation, and what a client
//     certificate is worth here. The view is `info`, the very object
//     `GET /tls?format=json` answers, beside `https`;
//   * `forwarded` — `GET /tls/forwarded`: what a proxy told this service,
//     and what was believed of it; the view is `/tls/forwarded?format=json`'s
//     object;
//   * `trusted`, `cleared` — what `POST /tls/trust` and `POST
//     /tls/trust/clear` answered, drawn by the runtime as the pages those
//     acts answered to a browser's form until #583;
//   * `notAdded` — `POST /tls/trust`'s refusal, English (#539's decision 6),
//     through the one outcome renderer (`common/web_outcome.ts`).
//
// The page's own words are the `tlsPages` catalogs'. WHAT THE SERVER SAYS
// IS DATA, and English: a listener's `what`, a header's description, the
// revocation policy's sentence, `what_it_means` and the notes are members
// of the JSON views scripts read, and are drawn as they are, escaped.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import WebOutcome = require('../common/web_outcome');

type Json = any;

const esc = WebOutcome.esc;

// Where the pages link to, root-relative: the realm's prefix is put on by
// the runtime (`WebPage.realmLinks()`).
const TLS_PATH = '/tls';
const FORWARDED_PATH = '/tls/forwarded';
const SIGN_IN_PATH = '/tls/sign-in';
const SERVER_CERTIFICATE_PATH = '/tls/server-certificate';

/**
 * The TLS diagnostic pages' renderers. A static utility class.
 */
class WebTlsViews {
  /**
   * Draws a view by its kind.
   *
   * @param view - the view
   * @param ctx - the context (`t`)
   * @returns the body
   */
  static render(view: Json, ctx: Json): string {
    const v = view || {};
    if (v.kind === 'tls') {
      return WebTlsViews.tls(v, ctx.t);
    }
    if (v.kind === 'forwarded') {
      return WebTlsViews.forwarded(v, ctx.t);
    }
    if (v.kind === 'trusted') {
      return WebTlsViews.trusted(v, ctx.t);
    }
    if (v.kind === 'cleared') {
      return WebTlsViews.cleared(v, ctx.t);
    }
    if (v.kind === 'notAdded') {
      return WebTlsViews.notAdded(v, ctx.t);
    }
    return WebOutcome.draw({ heading: 'This page could not be drawn',
      why: 'The service sent a view this page does not know (' +
           String(v.kind) + ').', whyTone: 'err' });
  }

  /**
   * The document's title for a view, as text.
   *
   * @param view - the view
   * @param ctx - the context (`t`)
   * @returns the title
   */
  static title(view: Json, ctx: Json): string {
    const kind = String((view && view.kind) || '');
    if (kind === 'tls') {
      return ctx.t.text('tlsPages.tls.title');
    }
    if (kind === 'forwarded') {
      return ctx.t.text('tlsPages.forwarded.title');
    }
    if (kind === 'trusted' || kind === 'cleared') {
      return ctx.t.text('tlsPages.outcome.title');
    }
    return kind === 'notAdded' ? WebTlsViews.refusedHeading(view) : 'TLS';
  }

  /**
   * A refused act's heading, English: which act did nothing.
   *
   * @param view - the `notAdded` view: `act`
   * @returns the heading, as text
   */
  static refusedHeading(view: Json): string {
    return view && view.act === 'clear' ? 'The truststore was not emptied'
                                        : 'Nothing was added';
  }

  /**
   * A table of label and value rows, every value in `<code>`.
   *
   * @param rows - `[label as markup, value]`
   * @param t - the translator
   * @returns the rows' markup
   */
  static rows(rows: Array<[string, Json]>, t: Json): string {
    return rows.map(function (row) {
      const value = row[1];
      return '<tr><td>' + row[0] + '</td><td><code>' +
        (value === null || value === undefined
          ? t.html('tlsPages.tls.none') : esc(String(value))) +
        '</code></td></tr>';
    }).join('');
  }

  /**
   * `GET /tls`: what this service presents, what it verifies a client
   * certificate against, and what a verified one is worth.
   *
   * @param v - the `tls` view: `info` (`/tls?format=json`) and `https`
   * @param t - the translator
   * @returns the body
   */
  static tls(v: Json, t: Json): string {
    const info = v.info || {};
    const cert = info.serverCertificate || {};
    const store = info.truststore || {};
    const subjects: string[] = Array.isArray(store.subjects)
      ? store.subjects : [];
    const fingerprints: string[] = Array.isArray(store.fingerprints)
      ? store.fingerprints : [];
    const listeners = (Array.isArray(info.listeners) ? info.listeners : [])
      .map(function (one: Json): string {
        return '<tr><td><code>' + esc(one.url) + '</code></td><td>' +
          (one.requiresClientCertificate ? t.html('tlsPages.tls.required')
                                         : t.html('tlsPages.tls.optional')) +
          '</td><td>' + (one.listening ? t.html('tlsPages.tls.up')
                                       : t.html('tlsPages.tls.down')) +
          '</td><td>' + esc(one.what) + '</td></tr>';
      }).join('');
    const anchors = subjects.length
      ? subjects.map(function (subject: string, i: number): string {
          return '<tr><td><code>' + esc(subject) + '</code></td><td><code>' +
            esc(fingerprints[i]) + '</code></td></tr>';
        }).join('')
      : '<tr><td colspan="2">' + t.html('tlsPages.tls.emptyStore') +
        '</td></tr>';
    const revocation = info.revocation || {};
    return '<h1>' + t.html('tlsPages.tls.heading') + '</h1><p class="sub">' +
      t.html(v.https ? 'tlsPages.tls.leadHttps' : 'tlsPages.tls.leadHttp') +
      '</p><table><tr><th>' + t.html('tlsPages.tls.url') + '</th><th>' +
      t.html('tlsPages.tls.clientCertificate') + '</th><th>' +
      t.html('tlsPages.tls.listener') + '</th><th>' +
      t.html('tlsPages.tls.purpose') + '</th></tr>' + listeners +
      '</table>' +
      (info.listenError
        ? '<p class="verdict">' + t.html('tlsPages.tls.listenError',
            { error: String(info.listenError) }) + '</p>'
        : '') +
      '<h2>' + t.html('tlsPages.tls.serverCertificate') + '</h2><p>' +
      t.html('tlsPages.tls.serverCertificateNote') + '</p><table>' +
      WebTlsViews.rows([
        [t.html('tlsPages.tls.subject'), cert.subject],
        [t.html('tlsPages.tls.names'),
         Array.isArray(cert.names) ? cert.names.join(', ') : cert.names],
        [t.html('tlsPages.tls.fingerprint'), cert.fingerprint256],
        [t.html('tlsPages.tls.notAfter'), cert.notAfter],
        [t.html('tlsPages.tls.pem'), 'GET ' + SERVER_CERTIFICATE_PATH]
      ], t) + '</table><h2>' + t.html('tlsPages.tls.verifiedAgainst') +
      '</h2><p>' + t.html('tlsPages.tls.verifiedAgainstNote') +
      '</p><table><tr><th>' + t.html('tlsPages.tls.anchor') + '</th><th>' +
      t.html('tlsPages.tls.fingerprint') + '</th></tr>' + anchors +
      '</table>' +
      // The two open doors only where the PROCESS serves them (#585): a
      // development realm inside a product process draws this page and
      // must not draw buttons posting to routes that are not there.
      (store.addUrl && store.clearUrl
        ? '<form method="post" action="' + esc(store.addUrl) +
          '" id="tls-trust"><textarea name="certificates" rows="6" ' +
          'placeholder="-----BEGIN CERTIFICATE-----"></textarea><p><button ' +
          'type="submit">' + t.html('tlsPages.tls.trustThese') +
          '</button></p></form><form method="post" action="' +
          esc(store.clearUrl) + '" id="tls-clear"><button type="submit">' +
          t.html('tlsPages.tls.emptyTheStore') + '</button></form>'
        : '') +
      '<p class="sub">' + t.html('tlsPages.tls.testControls') + ' <a href="' +
      esc(store.consoleUrl || '/admin/tls/trust') + '">' +
      t.html('tlsPages.tls.consoleTrust') + '</a></p><h2>' +
      t.html('tlsPages.tls.revocation') + '</h2><p>' +
      esc(revocation.sentence || '') + '</p><h2>' +
      t.html('tlsPages.tls.worth') + '</h2><p>' +
      t.html('tlsPages.tls.worthNote') + '</p><p>' +
      t.html('tlsPages.tls.recorded') + '</p><p class="sub"><a href="' +
      SIGN_IN_PATH + '">GET ' + SIGN_IN_PATH + '</a> · <a ' +
      'href="/admin/users">/admin/users</a> · <a ' +
      'href="/admin/ldap/service">' + t.html('tlsPages.tls.directory') +
      '</a></p><p class="sub"><a href="' + TLS_PATH + '?format=json">' +
      t.html('tlsPages.tls.asJson') + '</a> · <a ' +
      'href="/admin/sts-metadata">' + t.html('tlsPages.tls.everything') +
      '</a></p>';
  }

  /**
   * A header table of `/tls/forwarded`: each header, what this request
   * carried, and what it is.
   *
   * @param rows - the view's header rows
   * @param t - the translator
   * @returns the rows' markup
   */
  static headerRows(rows: Json, t: Json): string {
    return (Array.isArray(rows) ? rows : []).map(function (row: Json) {
      return '<tr><td><code>' + esc(row.header) + '</code></td><td>' +
        (row.present
          ? '<code>' + esc(row.value) + '</code>'
          : '<span class="none">' + t.html('tlsPages.forwarded.notSent') +
            '</span>') + '</td><td>' + esc(row.what) + '</td></tr>';
    }).join('');
  }

  /**
   * `GET /tls/forwarded`: the request as it arrived, and what was believed
   * of it.
   *
   * @param v - the `forwarded` view (`/tls/forwarded?format=json`'s object)
   * @param t - the translator
   * @returns the body
   */
  static forwarded(v: Json, t: Json): string {
    const socket = v.socket || {};
    const certs = v.clientCertificateHeaders || {};
    return '<h1>' + t.html('tlsPages.forwarded.heading') +
      '</h1><p class="sub">' + t.html('tlsPages.forwarded.lead') +
      '</p><table><tr><th>' + t.html('tlsPages.forwarded.thing') +
      '</th><th>' + t.html('tlsPages.forwarded.value') + '</th></tr><tr>' +
      '<td>global.trustProxy</td><td>' +
      (v.trustProxy ? t.html('tlsPages.forwarded.trustProxyOn')
                    : t.html('tlsPages.forwarded.trustProxyOff')) +
      '</td></tr><tr><td>' + t.html('tlsPages.forwarded.socketSaw') +
      '</td><td><code>' + esc(socket.scheme) + '://' + esc(socket.host) +
      '</code> ' + (socket.encrypted ? t.html('tlsPages.forwarded.encrypted')
                     : t.html('tlsPages.forwarded.notEncrypted')) +
      '</td></tr><tr><td>' + t.html('tlsPages.forwarded.effectiveBase') +
      '</td><td><code>' + esc(v.effectiveBaseUrl) + '</code></td></tr>' +
      '</table><p class="' + (v.trustProxy ? 'sub' : 'verdict') + '">' +
      esc(v.what_it_means) + '</p><h2>' +
      t.html('tlsPages.forwarded.forwardingHeaders') + '</h2><table><tr><th>' +
      t.html('tlsPages.forwarded.header') + '</th><th>' +
      t.html('tlsPages.forwarded.thisRequest') + '</th><th>' +
      t.html('tlsPages.forwarded.whatHere') + '</th></tr>' +
      WebTlsViews.headerRows(v.forwarding, t) + '</table><h2>' +
      t.html('tlsPages.forwarded.certificateHeaders') +
      '</h2><p class="verdict">' + esc(certs.note) + '</p><table><tr><th>' +
      t.html('tlsPages.forwarded.header') + '</th><th>' +
      t.html('tlsPages.forwarded.thisRequest') + '</th><th>' +
      t.html('tlsPages.forwarded.whatItIs') + '</th></tr>' +
      WebTlsViews.headerRows(certs.headers, t) + '</table><h2>' +
      t.html('tlsPages.forwarded.proxyMust') + '</h2><p>' +
      esc(v.proxyMustSanitize) + '</p><p class="sub"><a href="' +
      FORWARDED_PATH + '?format=json">' + t.html('tlsPages.tls.asJson') +
      '</a> · <a href="' + TLS_PATH + '">' +
      t.html('tlsPages.forwarded.whatTls') + '</a> · <a ' +
      'href="/.well-known/oauth-authorization-server">' +
      t.html('tlsPages.forwarded.document') + '</a></p>';
  }

  /**
   * What `POST /tls/trust` answered: how many anchors were added, and how
   * many are held now.
   *
   * @param v - the `trusted` view: `added`, `anchors`
   * @param t - the translator
   * @returns the body
   */
  static trusted(v: Json, t: Json): string {
    return WebOutcome.draw({
      heading: t.text('tlsPages.outcome.added',
                      { added: Number(v.added) || 0 }),
      ids: { links: 'tls-outcome' },
      notes: [t.html('tlsPages.outcome.addedNote',
                     { anchors: Number(v.anchors) || 0 })],
      links: [{ href: TLS_PATH, label: t.text('tlsPages.outcome.back') }] });
  }

  /**
   * What `POST /tls/trust/clear` answered: how many anchors were removed.
   *
   * @param v - the `cleared` view: `removed`
   * @param t - the translator
   * @returns the body
   */
  static cleared(v: Json, t: Json): string {
    return WebOutcome.draw({
      heading: t.text('tlsPages.outcome.cleared'),
      ids: { links: 'tls-outcome' },
      notes: [t.html('tlsPages.outcome.clearedNote',
                     { removed: Number(v.removed) || 0 })],
      links: [{ href: TLS_PATH, label: t.text('tlsPages.outcome.back') }] });
  }

  /**
   * A refused act — `POST /tls/trust`'s, or either act's binding: what it
   * said, English, as the server drew the first until #583.
   *
   * @param v - the `notAdded` view: `act`, `error`
   * @param t - the translator
   * @returns the body
   */
  static notAdded(v: Json, t: Json): string {
    return WebOutcome.draw({ heading: WebTlsViews.refusedHeading(v),
      why: String(v.error || ''), whyTone: 'err',
      ids: { why: 'tls-refused', links: 'tls-outcome' },
      links: [{ href: TLS_PATH, label: t.text('tlsPages.outcome.back') }] });
  }
}

export = WebTlsViews;
