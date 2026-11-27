// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_tokens_and_keys.ts
//
// ---------------------------------------------------------------------------
// `/portal/tokens-and-keys`, DRAWN IN THE BROWSER (#2053, rcbj 2026-11-23:
// "The user portal needs to provide a page where a user can register each of
// these application artifacts."). One page, a tab per kind, in the order and
// with the names of the person's Credentials sub-tabs on the console (#2052):
// Hardware tokens, OATH tokens, YubiKey OTP, PIV, SSH user certificates, and
// OpenPGP and S/MIME.
//
// EACH TAB IS THE EXISTING PORTAL CARD, not a copy: `web_tokens.ts`'s
// `heldCard()`, `claimCard()`, `enrolCard()` and `escrowCard()`,
// `web_mfa.ts`'s `hotpCard()` and `yubiCard()`, and `web_openpgp.ts`'s page
// body. Their forms post where they always did — `/portal/tokens`,
// `/portal/mfa`, `/portal/openpgp` — so every one reaches the same
// `/account-api` operation, and the runtime puts what it answers back into
// this page's member for that tab (`members`), so the page, its address and
// its tab stay. `/portal/tokens`, `/portal/mfa` and `/portal/openpgp` are
// unchanged.
//
// THE ONE NEW CARD IS SSH's: the person's SSH user certificates, issuing one
// for a pasted OpenSSH public key, and revoking one, over the account API's
// existing `/account-api/ssh/*` operations (`account-api/ssh_user_ca.ts`),
// which take `account:manage` as well as `ssh:certificate`. A certificate is
// shown once, as the answer that issued it.
//
// The page is drawn from `GET /account-api/tokens-and-keys` (the tokens view)
// and composes `GET /account-api/mfa`, `GET /account-api/openpgp` and `GET
// /account-api/ssh/certificates` (`compose`). A member that refuses is drawn
// as a note on its tab.
//
// The tabs are fragments, shown by the stylesheet (`.ptabs`, `:target`):
// no script decides which is open.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import kit = require('./web_portal_kit');
import TokensPages = require('./web_tokens');
import MfaPages = require('./web_mfa');
import OpenPgpPages = require('./web_openpgp');

type Json = any;
type PortalPage = import('../types/account-api').PortalPage;

const PATH = kit.BASE + '/tokens-and-keys';
const SSH = kit.BASE + '/ssh';

/**
 * `/portal/tokens-and-keys`. A static utility class.
 */
class TokensAndKeysPages {
  // The tabs, in the console's order (#2052): the id and its label's key.
  static readonly TABS: Array<{ id: string; label: string }> = [
    { id: 'tk-hardware-tokens', label: 'portalTokens.tk.tab.tokens' },
    { id: 'tk-oath-tokens', label: 'portalTokens.tk.tab.oath' },
    { id: 'tk-yubiotp', label: 'portalTokens.tk.tab.yubiotp' },
    { id: 'tk-piv', label: 'portalTokens.tk.tab.piv' },
    { id: 'tk-ssh', label: 'portalTokens.tk.tab.ssh' },
    { id: 'tk-openpgp', label: 'portalTokens.tk.tab.openpgp' }
  ];

  /**
   * A composed member's refusal, as its tab's card.
   *
   * @param v - the member
   * @param t - the translator
   * @returns the card, or '' when the member is drawn
   */
  static refused(v: Json, t: Json): string {
    return v && !v.refused ? '' : '<div class="card"><p class="note">' +
      t.html('portalTokens.tk.unavailable') + '</p></div>';
  }

  /**
   * The SSH tab: what was just issued, the person's certificates with
   * Revoke, and the issue form.
   *
   * @param v - `GET /account-api/ssh/certificates`' answer
   * @param answer - what the issue answered, once, or null
   * @param t - the translator
   * @param username - the person, the default principal
   * @returns the HTML
   */
  static sshCards(v: Json, answer: Json, t: Json, username: string): string {
    const refused = TokensAndKeysPages.refused(v, t);
    if (refused) {
      return refused;
    }
    const rows: Json[] = v.certificates || [];
    const limits = v.lifetimes || {};
    const issued = answer && answer.certificate
      ? '<div class="card fresh" id="ssh-issued"><h2>' +
        t.html('portalTokens.tk.ssh.issuedHeading') + '</h2><p>' +
        t.html('portalTokens.tk.ssh.issuedWhat') + '</p>' +
        '<textarea readonly rows="6" name="certificate">' +
        kit.esc(answer.certificate) + '</textarea>' +
        (answer.pqcCertificate
          ? '<p class="note">' + t.html('portalTokens.tk.ssh.pqcWhat') +
            '</p><textarea readonly rows="6" name="pqc-certificate">' +
            kit.esc(answer.pqcCertificate) + '</textarea>' : '') +
        '</div>'
      : '';
    const list = rows.length
      ? '<table><tr><th>' + t.html('portalTokens.tk.ssh.serial') +
        '</th><th>' + t.html('portalTokens.tk.ssh.key') + '</th><th>' +
        t.html('portalTokens.tk.ssh.principals') + '</th><th>' +
        t.html('portalTokens.tk.ssh.expires') + '</th><th></th></tr>' +
        rows.map(function (one: Json): string {
          return '<tr><td><code>' + kit.esc(one.serialHex) + '</code>' +
            (one.authority === 'ssh-mldsa-65' ? ' (ML-DSA)' : '') +
            '</td><td>' + kit.esc(one.keyType) + '<br><code>' +
            kit.esc(one.keyFingerprint) + '</code>' +
            (one.hardwareBound ? ' (' +
              t.html('portalTokens.tk.ssh.hardware') + ')' : '') +
            '</td><td>' + kit.esc((one.principals || []).join(', ')) +
            '</td><td>' + (one.notAfter ? t.date(one.notAfter) : '') +
            (one.revoked ? ' (' + t.html('portalTokens.tk.ssh.revoked') +
              ')' : '') + '</td><td>' + (one.revoked ? ''
              : '<form method="post" action="' + SSH + '/revoke">' +
                '<input type="hidden" name="serialHex" value="' +
                kit.esc(one.serialHex) + '"><button type="submit" ' +
                'class="danger">' + t.html('portalTokens.tk.ssh.revoke') +
                '</button></form>') + '</td></tr>';
        }).join('') + '</table>'
      : '<p id="ssh-none">' + t.html('portalTokens.tk.ssh.none') + '</p>';
    return issued + '<div class="card" id="ssh"><h2>' +
      t.html('portalTokens.tk.ssh.heading') + '</h2><p class="sub">' +
      t.html('portalTokens.tk.ssh.intro') + '</p>' + list + '</div>' +
      '<div class="card"><h2>' +
      t.html('portalTokens.tk.ssh.issueHeading') + '</h2><p class="sub">' +
      t.html('portalTokens.tk.ssh.issueIntro', {
        software: String(limits.softwareSeconds || ''),
        hardware: String(limits.hardwareSeconds || '') }) + '</p>' +
      '<form method="post" action="' + SSH + '" data-array="principals" ' +
      'data-integer="lifetimeS">' +
      '<label for="ssh-key">' + t.html('portalTokens.tk.ssh.publicKey') +
      '</label><textarea id="ssh-key" name="publicKey" rows="3" required ' +
      'spellcheck="false" placeholder="ssh-ed25519 AAAA..."></textarea>' +
      '<div class="row"><label for="ssh-principals">' +
      t.html('portalTokens.tk.ssh.principalsLabel') + '</label>' +
      '<input type="text" id="ssh-principals" name="principals" required ' +
      'maxlength="1024" value="' + kit.esc(username) + '"></div>' +
      '<div class="row"><label for="ssh-lifetime">' +
      t.html('portalTokens.tk.ssh.lifetime') + '</label>' +
      '<input type="number" id="ssh-lifetime" name="lifetimeS" min="60" ' +
      'max="3600" step="1"></div>' +
      '<button type="submit">' + t.html('portalTokens.tk.ssh.issue') +
      '</button></form></div>';
  }

  /**
   * The page's body: the tab bar, then a panel per tab.
   *
   * @param view - the tokens view, with `mfa`, `openpgp`, `ssh` and, once,
   *   `sshAnswer`
   * @param ctx - the render context
   * @returns the HTML
   */
  static render(view: Json, ctx: Json): string {
    const t = ctx.t;
    const v = view || {};
    const mfa = v.mfa || null;
    const pgp = v.openpgp || null;
    const me = (ctx.me && ctx.me.user && ctx.me.user.username) || '';
    const panels: Record<string, string> = {
      'tk-hardware-tokens': TokensPages.heldCard(v, t),
      'tk-oath-tokens': TokensPages.claimCard(t) +
        (TokensAndKeysPages.refused(mfa, t) || MfaPages.hotpCard(mfa, t)),
      'tk-yubiotp': TokensAndKeysPages.refused(mfa, t) ||
        MfaPages.yubiCard(mfa, t),
      'tk-piv': TokensPages.enrolCard(v, t) +
        TokensPages.certificatesCard(v, t) + TokensPages.escrowCard(v, t),
      'tk-ssh': TokensAndKeysPages.sshCards(v.ssh || null,
                                            v.sshAnswer || null, t, me),
      'tk-openpgp': TokensAndKeysPages.refused(pgp, t) ||
        OpenPgpPages.render(pgp, ctx)
    };
    return '<div class="ptabs"><nav class="ptabbar" aria-label="' +
      kit.esc(t.text('portalTokens.tk.tabs')) + '">' +
      TokensAndKeysPages.TABS.map(function (one, n: number): string {
        return '<a href="#' + one.id + '"' + (n === 0 ? ' class="first"'
                                                       : '') + '>' +
          t.html(one.label) + '</a>';
      }).join('') + '</nav>' +
      TokensAndKeysPages.TABS.map(function (one, n: number): string {
        return '<section class="ptabpanel' + (n === 0 ? ' first' : '') +
          '" id="' + one.id + '">' + panels[one.id] + '</section>';
      }).join('') + '</div>';
  }

  /**
   * The pages, for `web_portal_pages.ts`.
   */
  static readonly PAGES: PortalPage[] = [
    { path: PATH, operation: '/account-api/tokens-and-keys',
      compose: { mfa: '/account-api/mfa', openpgp: '/account-api/openpgp',
                 ssh: '/account-api/ssh/certificates' },
      members: { [kit.BASE + '/tokens']: '', [kit.BASE + '/mfa']: 'mfa',
                 [kit.BASE + '/openpgp']: 'openpgp', [SSH]: 'ssh',
                 [SSH + '/revoke']: 'ssh' },
      render: TokensAndKeysPages.render }
  ];
}

export = TokensAndKeysPages;
