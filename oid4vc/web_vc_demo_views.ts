// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_vc_demo_views.ts
//
// ---------------------------------------------------------------------------
// THE OPENID4VC DEMONSTRATION'S PAGES, DRAWN IN THE BROWSER (#582).
//
// The demonstration issuer ("Mock University") and verifier ("The Bar
// Door") were pages `vc_offers.ts` and `vc_verifier.ts` drew until #582;
// these are their renderers, moved with their markup and their element ids,
// over the views `/vc-demo-api` answers (`vc_demo_api.ts`):
//
//   * `issuer` — `/issuer`: the credential on offer and the four links;
//   * `offerStart` — `/issuer/offer` while the runtime makes the offer;
//   * `offer` — the offer for another device: the QR code, drawn here from
//     the offer's URI by `common/web_qr.ts` (it was a PNG the server made),
//     the Transaction Code beside it, the URI, and the same-device link;
//   * `verifier` — `/oid4vp/verifier`: what the door asks for, and the
//     links that start a presentation;
//   * `presentStart` — `/oid4vp/start` while the runtime starts it;
//   * `request` — the request for another device: the QR code from the
//     request's URI, the URI, the poll's line and the same-device link;
//   * `done` — `/oid4vp/done`: what the Verifier decided.
//
// The words are the `vcDemo` catalogs; the identifiers, the URIs, the
// claim names and values are the protocol's and are drawn as they are. A
// refusal is not drawn here: it is English, and the runtime draws it as a
// problem page (`common/web_surface.ts`).
//
// A `web_` MODULE: it requires only another `web_` module and logs nothing.
// ---------------------------------------------------------------------------

import WebQr = require('../common/web_qr');

type Json = any;

/**
 * Escapes text for HTML, as `Html.esc()` does.
 *
 * @param value - anything
 * @returns the escaped text
 */
function esc(value: unknown): string {
  return String(value == null ? '' : value)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/**
 * The renderers of the OpenID4VC demonstration's pages. A static utility
 * class.
 */
class WebVcDemoViews {
  /**
   * A path with the bar door's format carried on it, as the page's links
   * always carried it.
   *
   * @param path - the path, with or without a query
   * @param format - the format, '' for none
   * @returns the path
   */
  static withFormat(path: string, format: string): string {
    if (!format) {
      return path;
    }
    return path + (path.indexOf('?') === -1 ? '?' : '&') + 'format=' +
      encodeURIComponent(format);
  }

  /**
   * A QR code for a URI, or the sentence that it is too long for one.
   *
   * @param uri - the text the code carries
   * @param id - the element's id
   * @param label - its accessible name
   * @param t - the translator
   * @returns the markup
   */
  static qr(uri: string, id: string, label: string, t: Json): string {
    try {
      return '<div class="qr">' + WebQr.svg(String(uri),
        { id: id, pixels: 320, label: label }) + '</div>';
    } catch (e) {
      // Longer than any QR code holds: the links below still carry it.
      return '<p class="err">' + t.html('vcDemo.qr.tooLong') + '</p>';
    }
  }

  /**
   * The issuer's page (OpenID4VCI Appendix H).
   *
   * @param v - the view
   * @param t - the translator
   * @returns the body
   */
  static issuer(v: Json, t: Json): string {
    return '<h1>' + t.html('vcDemo.issuer.heading') + '</h1>' +
      '<p>' + t.html('vcDemo.issuer.intro',
                     { configuration: String(v.configurationId) }) + '</p>' +
      '<p><a class="cta" id="request_offer" href="/issuer/offer">' +
      t.html('vcDemo.issuer.request') + '</a><a class="cta secondary" ' +
      'id="request_offer_by_reference" href="/issuer/offer?by=reference">' +
      t.html('vcDemo.issuer.requestByReference') + '</a></p>' +
      '<p class="alt">' + t.html('vcDemo.issuer.otherDevice') + '<br>' +
      '<a class="cta secondary" id="request_offer_cross_device" ' +
      'href="/issuer/offer?mode=cross-device">' +
      t.html('vcDemo.issuer.qrNow') + '</a><a class="cta secondary" ' +
      'id="request_offer_deferred" href="/issuer/offer?mode=deferred">' +
      t.html('vcDemo.issuer.qrLater') + '</a></p>' +
      '<div class="meta">' + t.html('vcDemo.issuer.meta',
        { wallet: String(v.wallet), issuer: String(v.issuer) }) + '</div>';
  }

  /**
   * The offer page while the offer is made.
   *
   * @param t - the translator
   * @returns the body
   */
  static offerStart(t: Json): string {
    return '<h1>' + t.html('vcDemo.issuer.heading') + '</h1>' +
      '<p class="sub" id="offer_starting">' + t.html('vcDemo.offer.starting') +
      '</p>';
  }

  /**
   * The issuer's screen for another device: the QR code carrying the offer
   * and, separately — which is the whole point — the Transaction Code.
   *
   * @param v - the view
   * @param t - the translator
   * @returns the body
   */
  static offer(v: Json, t: Json): string {
    const deferred = v.mode === 'deferred';
    return '<div class="center"><h1>' + t.html('vcDemo.offer.heading') +
      '</h1><p>' + t.html(deferred ? 'vcDemo.offer.readyDeferred'
                                   : 'vcDemo.offer.ready') + '</p>' +
      WebVcDemoViews.qr(String(v.offerUri), 'offer_qr',
                        t.text('vcDemo.offer.qrAlt'), t) +
      '<p>' + t.html('vcDemo.offer.typeCode') + '</p>' +
      '<div class="txcode" id="tx_code">' + esc(v.txCode) + '</div>' +
      '<p class="small">' + t.html('vcDemo.offer.codeOnlyHere') + '</p>' +
      '<div class="uri" id="offer_uri">' + esc(v.offerUri) + '</div></div>' +
      '<div class="meta">' + t.html('vcDemo.offer.meta',
        { appendix: deferred ? 'H.3' : 'H.2' }) +
      (deferred ? ' ' + t.html('vcDemo.offer.metaDeferred') : '') +
      '<div><a id="open_in_wallet" href="' + esc(v.walletUrl) + '">' +
      t.html('vcDemo.offer.openHere') + '</a></div></div>';
  }

  /**
   * The bar door: what it asks for, and the links that start a
   * presentation.
   *
   * @param v - the view
   * @param t - the translator
   * @returns the body
   */
  static verifier(v: Json, t: Json): string {
    const format = String(v.format || '');
    const claims = Array.isArray(v.claims) ? v.claims.map(String) : [];
    const omitted = Array.isArray(v.ldpOmitted) ? v.ldpOmitted.map(String)
                                                : [];
    const start = function (query: string): string {
      return esc(WebVcDemoViews.withFormat('/oid4vp/start' + query, format));
    };
    return '<h1>' + t.html('vcDemo.verifier.heading') + '</h1>' +
      // A configuration naming no claims is a real setting and not an
      // empty page: DCQL with no `claims` member asks for the whole
      // credential, which is the opposite of everything else this door
      // says, so it says THAT instead of printing an empty list.
      (claims.length
        ? '<p>' + t.html('vcDemo.verifier.asking',
            { claims: claims.join(', '), type: String(v.askingType) }) +
          '</p>'
        : '<p>' + t.html('vcDemo.verifier.askingAll',
            { type: String(v.askingType) }) + '</p>') +
      (omitted.length
        ? '<p class="alt">' + t.html('vcDemo.verifier.ldpOmitted',
            { count: omitted.length, claims: omitted.join(', ') }) + '</p>'
        : '') +
      '<p><a class="cta" id="present_by_value" href="' + start('') + '">' +
      t.html('vcDemo.verifier.present') + '</a><a class="cta secondary" ' +
      'id="present_by_reference" href="' + start('?by=reference') + '">' +
      t.html('vcDemo.verifier.presentByReference') + '</a></p>' +
      '<p class="alt">' + t.html('vcDemo.verifier.otherDevice') + '<br>' +
      '<a class="cta secondary" id="present_cross_device" href="' +
      start('?mode=cross-device') + '">' + t.html('vcDemo.verifier.qr') +
      '</a></p>' +
      '<p class="alt">' + t.html('vcDemo.verifier.formats',
        { format: String(v.askingFor) }) + '<br>' +
      '<a class="cta secondary" id="present_sd_jwt_vc" ' +
      'href="/oid4vp/start?format=dc%2Bsd-jwt">' +
      t.html('vcDemo.verifier.presentSdJwt') + '</a> <a class="cta ' +
      'secondary" id="present_jwt_vc_json" ' +
      'href="/oid4vp/start?format=jwt_vc_json">' +
      t.html('vcDemo.verifier.presentJwtVc') + '</a> <a class="cta ' +
      'secondary" id="present_ldp_vc" href="/oid4vp/start?format=ldp_vc">' +
      t.html('vcDemo.verifier.presentLdpVc') + '</a></p>' +
      '<p class="alt">' + t.html('vcDemo.verifier.formatsNote') + '</p>' +
      '<div class="meta">' + t.html('vcDemo.verifier.meta',
        { response: String(v.responseUri), wallet: String(v.wallet) }) +
      ' ' + t.html('vcDemo.verifier.configure') +
      '<div><a href="/admin/vc-verifier-config">/admin/vc-verifier-config' +
      '</a></div></div>';
  }

  /**
   * The start page while the presentation request is built.
   *
   * @param t - the translator
   * @returns the body
   */
  static presentStart(t: Json): string {
    return '<h1>' + t.html('vcDemo.verifier.heading') + '</h1>' +
      '<p class="sub" id="present_starting">' +
      t.html('vcDemo.start.starting') + '</p>';
  }

  /**
   * The Verifier's screen for another device: the request as a QR code, and
   * the poll that moves on to the outcome once the wallet has answered.
   *
   * @param v - the view
   * @param t - the translator
   * @returns the body
   */
  static request(v: Json, t: Json): string {
    return '<div class="center"><h1>' + t.html('vcDemo.request.heading') +
      '</h1><p>' + t.html('vcDemo.request.sub') + '</p>' +
      WebVcDemoViews.qr(String(v.requestUri), 'request_qr',
                        t.text('vcDemo.request.qrAlt'), t) +
      '<div class="uri" id="request_uri">' + esc(v.requestUri) + '</div>' +
      '<p class="small" id="request_waiting">' +
      t.html('vcDemo.request.waiting',
             { poll: Number(v.pollSeconds) || 3 }) +
      ' <a id="request_outcome" href="' +
      esc('/oid4vp/done?state=' + encodeURIComponent(String(v.state))) +
      '">' + t.html('vcDemo.request.outcome') + '</a></p></div>' +
      '<div class="meta">' + t.html('vcDemo.request.meta') +
      '<div><a id="open_in_wallet" href="' + esc(v.walletUrl) + '">' +
      t.html('vcDemo.offer.openHere') + '</a></div></div>';
  }

  /**
   * The closing page: what the Verifier decided, the claims it was shown,
   * and what it asked for.
   *
   * @param v - the view
   * @param t - the translator
   * @returns the body
   */
  static done(v: Json, t: Json): string {
    if (!v.received) {
      return '<h1>' + t.html('vcDemo.done.heading') + '</h1>' +
        '<p id="verdict">' + t.html('vcDemo.done.nothing') + '</p>';
    }
    const claims = Array.isArray(v.claims) ? v.claims : [];
    const requested = Array.isArray(v.requested) ? v.requested : [];
    return '<h1>' + t.html('vcDemo.done.heading') + '</h1>' +
      '<p class="verdict ' + (v.accepted ? 'good' : 'bad') + '" ' +
      'id="verdict">' + t.html(v.accepted ? 'vcDemo.done.accepted'
                                          : 'vcDemo.done.refused') +
      '</p><ul id="claims">' + claims.map(function (c: Json) {
        return '<li><code>' + esc(c.name) + '</code>: <code>' +
          esc(c.value) + '</code></li>';
      }).join('') + '</ul>' +
      '<p class="small">' + t.html('vcDemo.done.askedFor',
        { requested: requested.map(String).join(', ') }) + '</p>';
  }

  /**
   * Draws a page's body from its view, by the view's kind.
   *
   * @param view - the view
   * @param ctx - the surface's context: `t`
   * @returns the body
   */
  static render(view: Json, ctx: Json): string {
    const v = view || {};
    const t = ctx.t;
    switch (v.kind) {
      case 'issuer':
        return WebVcDemoViews.issuer(v, t);
      case 'offerStart':
        return WebVcDemoViews.offerStart(t);
      case 'offer':
        return WebVcDemoViews.offer(v, t);
      case 'verifier':
        return WebVcDemoViews.verifier(v, t);
      case 'presentStart':
        return WebVcDemoViews.presentStart(t);
      case 'request':
        return WebVcDemoViews.request(v, t);
      case 'done':
        return WebVcDemoViews.done(v, t);
      default:
        return '';
    }
  }

  /**
   * The document's title for a view.
   *
   * @param view - the view
   * @param ctx - the context
   * @returns the title, as text
   */
  static title(view: Json, ctx: Json): string {
    const t = ctx.t;
    const v = view || {};
    switch (v.kind) {
      case 'issuer':
      case 'offerStart':
        return t.text('vcDemo.issuer.title');
      case 'offer':
        return t.text('vcDemo.offer.title');
      case 'request':
        return t.text('vcDemo.request.title');
      case 'done':
        return v.received
          ? t.text(v.accepted ? 'vcDemo.done.titleAccepted'
                              : 'vcDemo.done.titleRefused')
          : t.text('vcDemo.done.heading');
      default:
        return t.text('vcDemo.verifier.title');
    }
  }
}

export = WebVcDemoViews;
