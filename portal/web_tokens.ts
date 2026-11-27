// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_tokens.ts
//
// ---------------------------------------------------------------------------
// `/portal/tokens`, DRAWN IN THE BROWSER (#1955 P1), from `GET
// /account-api/tokens` (`account_tokens.ts`): the person's hardware tokens —
// each physical security key or smart card the register recorded from its
// attestation — with the credentials of theirs on it, and an "I lost this
// key" button on each active one, which posts `lost` to `POST
// /portal/tokens` (the account API's `actOnTokens`). Since #1955 P4 a
// second card: CLAIM a one-time code token an administrator imported, by
// the serial printed on it and a code it shows now (`claim`, the same
// operation).
//
// #1955 P2 adds two cards: the PIV enrolment form (the slot profile, the
// certificate request and the two attestation certificates, `enrol-piv`),
// with the certificate it issued drawn once; and the person's escrowed
// piv-key-management keys, each with "Recover key" (`recover-key`, the key
// drawn once) and "It is on this key" (`attach-key`).
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import kit = require('./web_portal_kit');

type Json = any;
type PortalPage = import('../types/account-api').PortalPage;

const PATH = kit.BASE + '/tokens';

/**
 * `/portal/tokens`. A static utility class.
 */
class TokensPages {
  /**
   * One token's credentials.
   *
   * @param one - the token
   * @param t - the translator
   * @returns the HTML
   */
  static credentialsCell(one: Json, t: Json): string {
    const list: Json[] = one.credentials || [];
    return list.length ? list.map(function (c: Json): string {
      return kit.esc(c.kind === 'fido' ? t.text('portalTokens.kind.fido')
        : (c.kind === 'x509' ? t.text('portalTokens.kind.x509')
          : (c.kind === 'hotp' || c.kind === 'totp'
            ? t.text('portalTokens.kind.oath') : c.kind))) +
        (c.label ? ' — ' + kit.esc(c.label) : '') +
        (c.algorithm ? ' (' + kit.esc(c.algorithm) + ')' : '') +
        (c.retired ? ' (' + t.html('portalTokens.retired') + ')' : '');
    }).join('<br>') : '—';
  }

  // The slot each PIV profile is for, for the import command.
  static readonly SLOTS: Record<string, string> = {
    'piv-auth': '9a', 'piv-sign': '9c', 'piv-key-management': '9d',
    'piv-card-auth': '9e'
  };

  /**
   * A file chooser for one PEM box (#2294): the file is read and checked in
   * the browser by `web_pem_file.ts` and put in the box only when it is a
   * PEM `kind`; it has no name, so the form never sends it.
   *
   * @param box - the text box's id
   * @param kind - `certificate` or `request`
   * @param t - the translator
   * @returns the HTML
   */
  static fileChooser(box: string, kind: string, t: Json): string {
    return '<label class="file" for="' + box + '-file">' +
      t.html('portalTokens.piv.file') + '</label> <input type="file" id="' +
      box + '-file" accept=".pem,.crt,.cer,.csr,.req,.txt" data-pem-file="' +
      box + '" data-pem-kind="' + kind + '" data-pem-note="' + box +
      '-note"><p class="note" id="' + box + '-note" role="status" ' +
      'aria-live="polite"></p>';
  }

  /**
   * The PIV enrolment card, and what it issued once.
   *
   * @param view - the page's view
   * @param t - the translator
   * @returns the HTML
   */
  static enrolCard(view: Json, t: Json): string {
    const rules = view.piv || { profiles: [] };
    const issued = view.issued;
    const slot = issued ? (TokensPages.SLOTS[issued.profile] || '9a') : '';
    const done = issued
      ? '<div class="card" id="piv-issued"><h2>' +
        t.html('portalTokens.piv.issuedHeading') + '</h2><p>' +
        t.html('portalTokens.piv.issuedWhat', { slot: slot }) +
        '</p><textarea readonly rows="10" name="certificate">' +
        kit.esc(issued.certificatePem) + '</textarea></div>'
      : '';
    if (!(rules.profiles || []).length) {
      return done + '<div class="card"><h2>' +
        t.html('portalTokens.piv.heading') + '</h2><p id="piv-none">' +
        t.html('portalTokens.piv.noProfiles') + '</p></div>';
    }
    const options = rules.profiles.map(function (one: string): string {
      return '<option value="' + kit.esc(one) + '">' + kit.esc(one) + ' (' +
        kit.esc(TokensPages.SLOTS[one] || '') + ')</option>';
    }).join('');
    return done + '<div class="card"><h2>' +
      t.html('portalTokens.piv.heading') + '</h2><p class="sub">' +
      t.html('portalTokens.piv.intro') + '</p><pre>' +
      t.html('portalTokens.piv.commands') + '</pre>' +
      '<form method="post" action="' + PATH + '" id="piv-enrol">' +
      '<input type="hidden" name="action" value="enrol-piv">' +
      '<label for="piv-profile">' + t.html('portalTokens.piv.profile') +
      '</label><select id="piv-profile" name="profile">' + options +
      '</select><label for="piv-csr">' + t.html('portalTokens.piv.csr') +
      '</label><textarea id="piv-csr" name="csr" rows="6"></textarea>' +
      TokensPages.fileChooser('piv-csr', 'request', t) +
      '<label for="piv-attest">' + t.html('portalTokens.piv.attestation') +
      '</label><textarea id="piv-attest" name="attestationCertificate" ' +
      'rows="6"></textarea>' +
      TokensPages.fileChooser('piv-attest', 'certificate', t) +
      '<label for="piv-f9">' +
      t.html('portalTokens.piv.issuer') + '</label><textarea id="piv-f9" ' +
      'name="attestationIssuer" rows="6"></textarea>' +
      TokensPages.fileChooser('piv-f9', 'certificate', t) +
      '<p class="note">' +
      t.html(rules.requireAttestation ? 'portalTokens.piv.required'
                                      : 'portalTokens.piv.optional') +
      '</p><button type="submit">' + t.html('portalTokens.piv.button') +
      '</button></form></div>';
  }

  /**
   * The escrowed keys card, and a recovered key once.
   *
   * @param view - the page's view
   * @param t - the translator
   * @returns the HTML, or '' where the realm escrows nothing and the
   *   person has nothing escrowed
   */
  static escrowCard(view: Json, t: Json): string {
    const rows: Json[] = view.escrowed || [];
    const recovered = view.recovered;
    if (!rows.length && !recovered && !(view.piv && view.piv.keyEscrow)) {
      return '';
    }
    const tokens: Json[] = (view.tokens || []).filter(function (one: Json) {
      return one.status !== 'lost';
    });
    const choose = tokens.map(function (one: Json): string {
      return '<option value="' + kit.esc(one.key) + '">' +
        kit.esc((one.model || one.vendor) + ' ' + one.serial) + '</option>';
    }).join('');
    const body = rows.map(function (one: Json): string {
      return '<tr><td>' + kit.esc(one.serialHex) + '</td><td>' +
        kit.esc(one.subject) + '</td><td>' +
        (one.notAfter ? t.date(one.notAfter) : '') +
        (one.revoked ? ' (' + t.html('portalTokens.escrow.revoked') + ')'
                     : '') + '</td><td>' +
        '<form method="post" action="' + PATH + '">' +
        '<input type="hidden" name="action" value="recover-key">' +
        '<input type="hidden" name="serial" value="' +
        kit.esc(one.serialHex) + '"><button type="submit">' +
        t.html('portalTokens.escrow.recover') + '</button></form>' +
        (choose && !one.revoked
          ? '<form method="post" action="' + PATH + '">' +
            '<input type="hidden" name="action" value="attach-key">' +
            '<input type="hidden" name="serial" value="' +
            kit.esc(one.serialHex) + '"><select name="key" aria-label="' +
            t.html('portalTokens.escrow.attach') + '">' + choose +
            '</select><button type="submit">' +
            t.html('portalTokens.escrow.attach') + '</button></form>' : '') +
        '</td></tr>';
    }).join('');
    return (recovered
      ? '<div class="card" id="piv-recovered"><h2>' +
        t.html('portalTokens.escrow.recoveredHeading') + '</h2><p>' +
        t.html('portalTokens.escrow.recoveredWhat') +
        '</p><textarea readonly rows="10" name="private-key">' +
        kit.esc(recovered.privateKeyPem) + '</textarea></div>' : '') +
      '<div class="card"><h2>' + t.html('portalTokens.escrow.heading') +
      '</h2><p class="sub">' + t.html('portalTokens.escrow.intro') + '</p>' +
      (rows.length
        ? '<table><tr><th>' + t.html('portalTokens.col.serial') + '</th><th>' +
          t.html('portalTokens.escrow.subject') + '</th><th>' +
          t.html('portalTokens.escrow.expires') + '</th><th></th></tr>' +
          body + '</table>'
        : '<p id="escrow-none">' + t.html('portalTokens.escrow.none') +
          '</p>') + '</div>';
  }

  /**
   * The page's body.
   *
   * @param view - `GET /account-api/tokens`' answer
   * @param ctx - the render context
   * @returns the HTML
   */
  static render(view: Json, ctx: Json): string {
    const t = ctx.t;
    return TokensPages.heldCard(view, t) + TokensPages.claimCard(t) +
      TokensPages.enrolCard(view, t) +
      TokensPages.escrowCard(view, t);
  }

  // THE TOKENS THEMSELVES, the first card: drawn here and on the Hardware
  // tokens tab of Tokens and keys (#2053), one card on both.
  /**
   * The person's tokens, each with "I lost this key".
   *
   * @param view - the page's view
   * @param t - the translator
   * @returns the HTML
   */
  static heldCard(view: Json, t: Json): string {
    const held: Json[] = view.tokens || [];
    const rows = held.map(function (one: Json): string {
      const lost = one.status === 'lost';
      return '<tr><td>' + kit.esc(one.model || one.vendor) + '</td><td>' +
        kit.esc(one.serial) + '</td><td>' +
        TokensPages.credentialsCell(one, t) + '</td><td>' +
        (lost ? t.html('portalTokens.status.lost', { at: one.lostAt
          ? t.date(one.lostAt) : '' })
              : t.html('portalTokens.status.active')) + '</td><td>' +
        (lost ? '' : '<form method="post" action="' + PATH + '">' +
          '<input type="hidden" name="action" value="lost">' +
          '<input type="hidden" name="key" value="' + kit.esc(one.key) +
          '"><button class="danger" type="submit">' +
          t.html('portalTokens.lost.button') + '</button></form>') +
        '</td></tr>';
    });
    return '<div class="card"><h2>' + t.html('portalTokens.heading') +
      '</h2><p class="sub">' + t.html('portalTokens.intro') + '</p>' +
      (held.length
        ? '<table><tr><th>' + t.html('portalTokens.col.model') + '</th><th>' +
          t.html('portalTokens.col.serial') + '</th><th>' +
          t.html('portalTokens.col.credentials') + '</th><th>' +
          t.html('portalTokens.col.status') + '</th><th></th></tr>' +
          rows.join('') + '</table>' +
          '<p class="note">' + t.html('portalTokens.lost.what') + '</p>'
        : '<p id="tokens-none">' + t.html('portalTokens.none') + '</p>') +
      '</div>';
  }

  /**
   * The claim card (#1955 P4): a serial and a current code.
   *
   * @param t - the translator
   * @returns the HTML
   */
  static claimCard(t: Json): string {
    return '<div class="card" id="claim"><h2>' +
      t.html('portalTokens.claim.heading') + '</h2><p class="sub">' +
      t.html('portalTokens.claim.intro') + '</p>' +
      '<form method="post" action="' + PATH + '">' +
      '<input type="hidden" name="action" value="claim">' +
      '<div class="row"><label for="claim-serial">' +
      t.html('portalTokens.claim.serial') + '</label>' +
      '<input type="text" id="claim-serial" name="serial" required ' +
      'maxlength="64" autocomplete="off" spellcheck="false"></div>' +
      '<div class="row"><label for="claim-code">' +
      t.html('portalTokens.claim.code') + '</label>' +
      '<input type="text" id="claim-code" name="code" required ' +
      'inputmode="numeric" pattern="[0-9 ]{6,10}" maxlength="10" ' +
      'autocomplete="one-time-code"></div>' +
      '<button type="submit">' + t.html('portalTokens.claim.button') +
      '</button></form></div>';
  }

  /**
   * The pages, for `web_portal_pages.ts`.
   */
  static readonly PAGES: PortalPage[] = [
    { path: PATH, operation: '/account-api/tokens',
      render: TokensPages.render }
  ];
}

export = TokensPages;
