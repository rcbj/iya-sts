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
// THE CREDENTIALS ISSUED TO THE PERSON (#661, 2026-10-16), from the same
// answer's `issued`: each one's state, what their wallet last reported, and
// a Remove button that posts to `/portal/remove-wallet-credential` (`POST
// /account-api/credentials/remove`). Remove revokes; it cannot reach the
// wallet, and the page says so. Paged by `kit.pageNav()` on `page`, as the
// portal's other lists are, and each form carries the page it was on, so
// the page drawn from its answer is that one.
//
// ONE ROW PER ISSUANCE (#670, rcbj 2026-10-17). With batch issuance on, one
// "Add to your wallet" gives the wallet several copies, each bound to a
// different key of its own, and `issued` lists the issuance once: its
// state (the copies' where they agree, else how many are in each), how
// many copies, and Remove, which removes every copy. Under it, a
// `<details>` fold lists the copies — "Copy 2 of 4", the wallet key each is
// bound to (the first twelve characters of its RFC 7638 thumbprint, the
// whole of it and any holder DID as the tooltip: twelve characters of a
// `did:jwk` would be `did:jwk:eyJ` for every key), its status-list index
// and its own Remove. Above the list, while `batchSize` is over one, a note
// says batching is on and why; at one it says nothing about batching.
//
// THE SIGNING ALGORITHM (2026-10-16): one `<select name="signingAlg">`
// holding every configuration's algorithms, each option naming in
// `data-for` the configurations it applies to and in `data-default-for`
// those it is the default of. The first configuration's are drawn shown
// and its default selected, so the form is right without a script; the
// portal runtime's `wire()` (`data-depends-on="configuration"`) shows only
// the chosen configuration's and selects its default when another is
// picked.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import kit = require('./web_portal_kit');
import WebQr = require('../common/web_qr');

type Json = any;
type PortalPage = import('../types/account-api').PortalPage;

const PATH = kit.BASE + '/wallet';
const REMOVE_PATH = kit.BASE + '/remove-wallet-credential';

// A credential's state, and the wallet's report, as the catalog says them.
const STATE_KEYS: Json = {
  valid: 'portalWallet.stateValid', suspended: 'portalWallet.stateSuspended',
  revoked: 'portalWallet.stateRevoked', removed: 'portalWallet.stateRemoved',
  'signed-out': 'portalWallet.stateSignedOut',
  expired: 'portalWallet.stateExpired'
};
// The order a mixed issuance's counts are said in.
const STATE_ORDER = ['valid', 'suspended', 'revoked', 'signed-out',
                     'removed', 'expired'];
const STATE_SHORT_KEYS: Json = Object.assign({}, STATE_KEYS,
  { removed: 'portalWallet.stateRemovedShort' });
// How much of a key's thumbprint is shown: as much as the console's
// sign-out page shows of the same key (`logout/logout.ts`).
const KEY_SHOWN = 12;
const WALLET_KEYS: Json = {
  credential_accepted: 'portalWallet.walletAccepted',
  credential_failure: 'portalWallet.walletFailure',
  credential_deleted: 'portalWallet.walletDeleted'
};

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
   * The credentials issued to the person, each with its state, what the
   * wallet reported, and Remove where it is still good.
   *
   * @param view - the page's view: `issued` and `paging`
   * @param ctx - the render context
   * @returns the HTML
   */
  static history(view: Json, ctx: Json): string {
    const t = ctx.t;
    const issued: Json[] = view.issued || [];
    const keep = WalletPages.pageField(view);
    const said = function (one: Json): string {
      return WALLET_KEYS[one.walletEvent]
        ? t.html(WALLET_KEYS[one.walletEvent],
                 { when: t.date(one.walletEventAt) })
        : t.html('portalWallet.walletNothing');
    };
    const removeForm = function (id: string, label: string): string {
      return '<form method="post" action="' + kit.esc(REMOVE_PATH) + '">' +
        '<input type="hidden" name="id" value="' + kit.esc(id) + '">' +
        keep + '<button class="danger" type="submit">' + t.html(label) +
        '</button></form>';
    };
    const rows = issued.map(function (one: Json): string {
      const copies: Json[] = one.copies || [];
      const many = copies.length > 1;
      return '<tr data-issuance="' + kit.esc(one.id) + '"><td>' +
        kit.esc(one.name) + ' <span class="sub"><code>' +
        kit.esc(one.configurationId) + '</code> &middot; ' +
        kit.esc(one.format) + '</span></td><td>' +
        kit.esc(t.date(one.issuedAt)) + '</td><td>' +
        (one.expiresAt ? kit.esc(t.date(one.expiresAt))
                       : t.html('portalWallet.noExpiry')) + '</td><td>' +
        WalletPages.issuanceState(one, t) + '</td><td>' + said(one) +
        '</td><td>' +
        (one.removable
          ? removeForm(one.id, many ? 'portalWallet.removeAll'
                                    : 'portalWallet.remove')
          : '') + '</td></tr>' +
        (copies.length
          ? '<tr class="copies"><td colspan="6"><details><summary>' +
            t.html('portalWallet.copies', { count: copies.length }) +
            '</summary><table>' + copies.map(function (c: Json): string {
              return WalletPages.copy(c, t, many ? removeForm : null);
            }).join('') + '</table></details></td></tr>'
          : '');
    });
    const batch = Number(view.batchSize) || 1;
    return '<div class="card" id="wallet-issued"><h2>' +
      t.html('portalWallet.historyHeading') + '</h2><p class="sub">' +
      t.html('portalWallet.historySub') + '</p>' +
      // BATCHING, said while it is on (#670), and nothing about it at one.
      (batch > 1
        ? '<p class="sub" id="wallet-batch-note">' +
          t.html('portalWallet.batchNote', { size: batch }) + '</p>'
        : '') +
      (issued.length
        ? '<table><tr><th>' + t.html('portalWallet.colCredential') +
          '</th><th>' + t.html('portalWallet.colIssued') + '</th><th>' +
          t.html('portalWallet.colExpires') + '</th><th>' +
          t.html('portalWallet.colStatus') + '</th><th>' +
          t.html('portalWallet.colWallet') + '</th><th></th></tr>' +
          rows.join('') + '</table>' +
          kit.pageNav(PATH, ctx.query, view.paging, 'page', t) +
          '<p class="sub" id="wallet-remove-note">' +
          t.html('portalWallet.removeNote') + '</p>'
        : '<p id="wallet-issued-none">' + t.html('portalWallet.historyNone') +
          '</p>') + '</div>';
  }

  /**
   * One copy's state, as the catalog says it.
   *
   * @param one - a copy, or an issuance whose copies agree
   * @param t - the translator
   * @returns the HTML
   */
  static state(one: Json, t: Json): string {
    return one.status === 'removed'
      ? t.html(STATE_KEYS.removed, { when: t.date(one.removedAt) })
      : t.html(STATE_KEYS[one.status] || STATE_KEYS.revoked);
  }

  /**
   * An issuance's state: its copies' where they agree, and otherwise how
   * many of them are in each state.
   *
   * @param one - the issuance
   * @param t - the translator
   * @returns the HTML
   */
  static issuanceState(one: Json, t: Json): string {
    if (one.status !== 'mixed') {
      return WalletPages.state(one, t);
    }
    const counts: Json = one.counts || {};
    const total = (one.copies || []).length;
    return STATE_ORDER.filter(function (state: string): boolean {
      return Number(counts[state]) > 0;
    }).map(function (state: string): string {
      return t.html('portalWallet.stateCount', {
        count: Number(counts[state]), total: total,
        state: t.text(STATE_SHORT_KEYS[state]) });
    }).join('<br>');
  }

  /**
   * One copy of an issuance, in its fold: its position, the wallet key it is
   * bound to, its status-list index, its state, and its own Remove where
   * the issuance has others.
   *
   * @param c - the copy
   * @param t - the translator
   * @param removeForm - draws a Remove form, or null for an issuance of one
   * @returns the HTML
   */
  static copy(c: Json, t: Json,
              removeForm: ((id: string, label: string) => string) | null):
              string {
    const jkt = String(c.keyThumbprint || '');
    const did = String(c.holderDid || '');
    const key = jkt
      ? t.html('portalWallet.copyKey') + ' <code title="' +
        kit.esc(did ? jkt + ' · ' + did : jkt) + '">' +
        kit.esc(jkt.slice(0, KEY_SHOWN)) +
        (jkt.length > KEY_SHOWN ? '&hellip;' : '') + '</code>'
      : t.html('portalWallet.keyNotRecorded');
    return '<tr data-credential="' + kit.esc(c.id) + '"><td>' +
      t.html('portalWallet.copyOf', { position: c.position, of: c.of }) +
      '</td><td>' + key +
      (c.statusIndex
        ? '<br><span class="sub">' + t.html('portalWallet.copyStatusIndex',
            { index: String(c.statusIndex) }) + '</span>'
        : '') + '</td><td>' + WalletPages.state(c, t) + '</td><td>' +
      (removeForm && c.removable
        ? removeForm(c.id, 'portalWallet.removeCopy') : '') + '</td></tr>';
  }

  /**
   * The signing algorithm's one list, every configuration's algorithms in
   * it and the first configuration's shown.
   *
   * @param rows - the view's `configurations`
   * @param t - the translator
   * @returns the HTML, '' where no configuration names an algorithm
   */
  static algorithmSelect(rows: Json[], t: Json): string {
    const order: string[] = [];
    const seen: Json = {};
    rows.forEach(function (row: Json) {
      (row.signingAlgs || []).forEach(function (one: Json) {
        if (!seen[one.alg]) {
          seen[one.alg] = { note: one, for: [], defaultFor: [] };
          order.push(one.alg);
        }
        seen[one.alg].for.push(row.id);
        if (row.defaultSigningAlg === one.alg) {
          seen[one.alg].defaultFor.push(row.id);
        }
      });
    });
    if (!order.length) {
      return '';
    }
    const first = rows[0] ? String(rows[0].id) : '';
    const options = order.map(function (alg: string): string {
      const one = seen[alg];
      const shown = one.for.indexOf(first) >= 0;
      return '<option value="' + kit.esc(alg) + '" data-for="' +
        kit.esc(one.for.join(' ')) + '" data-default-for="' +
        kit.esc(one.defaultFor.join(' ')) + '"' +
        (one.note.spec ? ' title="' + kit.esc(one.note.spec) + '"' : '') +
        (shown ? '' : ' hidden disabled') +
        (one.defaultFor.indexOf(first) >= 0 ? ' selected' : '') + '>' +
        kit.esc(alg) + (one.note.what ? ' — ' + kit.esc(one.note.what) : '') +
        '</option>';
    }).join('');
    return '<p class="sub"><label for="wallet-alg"><strong>' +
      t.html('portalWallet.signingAlg') + '</strong></label></p>' +
      '<p><select id="wallet-alg" name="signingAlg" ' +
      'data-depends-on="configuration">' + options + '</select></p>' +
      '<p class="sub">' + t.html('portalWallet.signingAlgSub') + '</p>';
  }

  /**
   * The hidden field that keeps the history's page across a form, or ''
   * on the first.
   *
   * @param view - the page's view
   * @returns the HTML
   */
  static pageField(view: Json): string {
    const at = Number(view.paging && view.paging.page) || 1;
    return at > 1 ? '<input type="hidden" name="page" value="' + at + '">'
                  : '';
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
    const algs = WalletPages.algorithmSelect(rows, t);
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
          '</strong></p>' + modes + algs +
          WalletPages.pageField(view) +
          '<p><button type="submit" id="wallet-make">' +
          t.html('portalWallet.make') + '</button></p>' +
          '<p class="sub">' + t.html('portalWallet.lifetime',
                                     { minutes: minutes }) + '</p></form>'
        : '<p id="wallet-none">' + t.html('portalWallet.none') + '</p>') +
      '</div>' + WalletPages.history(view, ctx);
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
