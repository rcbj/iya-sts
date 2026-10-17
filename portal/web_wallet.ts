// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_wallet.ts
//
// ---------------------------------------------------------------------------
// `/portal/wallet`, DRAWN IN THE BROWSER (#589), from `GET
// /account-api/credentials/offerable` (`portal_wallet.ts`): the credentials
// this realm's issuer offers, and a form that asks
// `POST /account-api/credentials/offers` for a pre-authorized Credential
// Offer of one of them, for the person's own wallet.
//
// THE OFFER IS DRAWN IN PLACE, from the POST's `view`, and never from a URL:
// it carries a pre-authorized code and the Transaction Code beside it, and
// neither may reach the address bar or the history. It is drawn as the
// demo issuer's screen drew it (`vc_offers.ts`'s `renderOfferQrPage()`),
// with the same element ids — `offer_qr`, `tx_code`, `offer_uri`,
// `open_in_wallet` — so a reader of either finds the same things:
//
//   * a QR code of the offer BY REFERENCE (`credential_offer_uri`), which is
//     short enough to scan, drawn here by `web_qr.ts` from the URI;
//   * the Transaction Code, shown and never carried in the offer — the
//     wallet on the other device asks for it, and it is what ties that
//     wallet to the person looking at this screen;
//   * "open in a wallet on this device": the `openid-credential-offer://`
//     URI (HAIP's `haip-vci://` where `oid4vci.walletInvocation` says so)
//     with the offer by value, which a wallet app registers for, the
//     configured web wallet's link where there is one — none by default
//     since 2026-10-12 — and what to do when nothing opens.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import kit = require('./web_portal_kit');
import WebQr = require('../common/web_qr');

type Json = any;
type PortalPage = import('../types/account-api').PortalPage;

const PATH = kit.BASE + '/wallet';

/**
 * `/portal/wallet`. A static utility class.
 */
class WalletPages {
  /**
   * The offer just made: the QR code, the Transaction Code, the links.
   *
   * @param offer - the POST's `offer`
   * @param ctx - the render context
   * @returns the HTML
   */
  static offer(offer: Json, ctx: Json): string {
    const t = ctx.t;
    const scan = (offer.byReference && offer.byReference.offerUri) ||
                 (offer.byValue && offer.byValue.offerUri) || '';
    const byValue = offer.byValue || {};
    const deferred = offer.mode === 'deferred';
    let qr = '';
    try {
      qr = WebQr.svg(scan, { id: 'offer_qr', pixels: 280,
                             label: t.text('portalWallet.qrAlt') });
    } catch (e) {
      // An offer too long for any QR code: the links below still carry it.
      qr = '<p class="err">' + t.html('portalWallet.noQr') + '</p>';
    }
    return '<div class="card" id="wallet-offer"><h2>' +
      t.html('portalWallet.offerHeading') + '</h2><p class="sub">' +
      (deferred ? t.html('portalWallet.offerDeferred')
                : t.html('portalWallet.offerNow')) + '</p>' +
      '<p>' + qr + '</p>' +
      '<p>' + t.html('portalWallet.txCodeSay') + '</p>' +
      '<p class="txcode" id="tx_code">' + kit.esc(offer.txCode) + '</p>' +
      '<p class="sub">' + t.html('portalWallet.txCodeNote') + '</p>' +
      '<p class="sub">' + t.html('portalWallet.expires', {
        when: t.date(offer.expiresAt) }) + '</p>' +
      '<p><a class="dl" id="open_in_wallet" href="' +
      kit.esc(byValue.offerUri || scan) + '">' +
      t.html('portalWallet.openHere') + '</a>' +
      // THE WEB WALLET IN A TAB OF ITS OWN (2026-10-16): this page keeps
      // the Transaction Code the wallet asks for.
      (byValue.walletUrl
        ? ' <a class="dl secondary" id="open_in_web_wallet" target="_blank" ' +
          'rel="noopener" href="' + kit.esc(byValue.walletUrl) + '">' +
          t.html('portalWallet.openWebWallet') + '</a>'
        : '') + '</p>' +
      // WHAT TO DO WHEN NOTHING OPENS (2026-10-12): the link is under a
      // scheme only a wallet app registers for, and on a device without one
      // it does nothing at all.
      '<p class="sub" id="wallet-no-app">' + t.html('portalWallet.noApp') +
      '</p>' +
      '<details><summary>' + t.html('portalWallet.uriHeading') +
      '</summary><p class="offer-uri" id="offer_uri">' + kit.esc(scan) +
      '</p></details></div>';
  }

  /**
   * The page's body.
   *
   * @param view - `GET /account-api/credentials/offerable`'s answer, or a
   *   POST's `view` with `offer` in it
   * @param ctx - the render context
   * @returns the HTML
   */
  static render(view: Json, ctx: Json): string {
    const t = ctx.t;
    const rows: Json[] = view.configurations || [];
    const options = rows.map(function (one: Json, i: number): string {
      return '<label class="chk"><input type="radio" name="configuration" ' +
        'value="' + kit.esc(one.id) + '"' + (i === 0 ? ' checked' : '') +
        '> ' + kit.esc(one.name) + ' <span class="sub"><code>' +
        kit.esc(one.id) + '</code> &middot; ' + kit.esc(one.format) +
        (one.issuerDid ? ' &middot; ' + t.html('portalWallet.byDid') : '') +
        '</span></label>';
    }).join('');
    const modes = (view.modes || []).map(function (mode: string,
                                                    i: number): string {
      const key = mode === 'deferred' ? 'portalWallet.modeDeferred'
                                      : 'portalWallet.modeNow';
      return '<label class="chk"><input type="radio" name="mode" value="' +
        kit.esc(mode) + '"' + (i === 0 ? ' checked' : '') + '> ' +
        t.html(key) + '</label>';
    }).join('');
    const minutes = Math.max(1, Math.round(
      Number(view.lifetimeSeconds || 0) / 60));
    return (view.offer ? WalletPages.offer(view.offer, ctx) : '') +
      '<div class="card"><h2>' + t.html('portalWallet.heading') +
      '</h2><p class="sub">' + t.html('portalWallet.sub') + '</p>' +
      (rows.length
        ? '<form method="post" action="' + kit.esc(PATH) + '">' +
          '<p class="sub"><strong>' + t.html('portalWallet.which') +
          '</strong></p>' + options +
          '<p class="sub"><strong>' + t.html('portalWallet.when') +
          '</strong></p>' + modes +
          '<p><button type="submit" id="wallet-make">' +
          t.html('portalWallet.make') + '</button></p>' +
          '<p class="sub">' + t.html('portalWallet.lifetime',
                                     { minutes: minutes }) + '</p></form>'
        : '<p id="wallet-none">' + t.html('portalWallet.none') + '</p>') +
      '</div>';
  }

  /**
   * The pages, for `web_portal_pages.ts`.
   */
  static readonly PAGES: PortalPage[] = [
    { path: PATH, operation: '/account-api/credentials/offerable',
      render: WalletPages.render }
  ];
}

export = WalletPages;
