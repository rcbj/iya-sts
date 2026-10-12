// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_signing_key.ts
//
// ---------------------------------------------------------------------------
// `/portal/signing-key`, DRAWN IN THE BROWSER (#568), from `GET
// /account-api/signing-key` (`account_signing_key.ts`): the two signing key
// profiles (RFC 7523's JWT key pair and RFC 7522's SAML one) and the TLS
// client certificates. The cards are `Portal.signingKeyPage()`'s, moved.
//
// THE CARD THAT ONLY EXISTS FOR ONE ANSWER: a private key, or the files of a
// TLS client certificate, which arrive in `view.fresh` only in the answer to
// the act that made them and are drawn in place — never on a URL, never in
// the history. The files are `data:` links with `download` on them, the
// arrangement that lets the page carrying them carry the install steps too.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import kit = require('./web_portal_kit');

type Json = any;
type PortalPage = import('../types/account-api').PortalPage;

const PATH = kit.BASE + '/signing-key';

/**
 * `/portal/signing-key`. A static utility class.
 */
class SigningKeyPages {
  // RFC 4517 GeneralizedTime as a person reads a date: `20270912074512Z` is
  // what a directory holds, and a date with no separators in it is one a
  // person has to count digits in. An unparseable value says so.
  /**
   * A GeneralizedTime as `YYYY-MM-DD`.
   *
   * @param value - the attribute's value
   * @param t - the translator
   * @returns the date
   */
  static readableDate(value: Json, t: Json): string {
    const found = /^(\d{4})(\d{2})(\d{2})/.exec(String(value || ''));
    return found ? found[1] + '-' + found[2] + '-' + found[3]
                 : t.text('portal.signingKey.unknownDate');
  }

  /**
   * A POST form to this page.
   *
   * @param action - the action
   * @param inner - the rest of the form
   * @returns the form's HTML
   */
  static form(action: string, inner: string): string {
    return '<form method="post" action="' + PATH + '">' +
      '<input type="hidden" name="action" value="' + action + '">' + inner +
      '</form>';
  }

  // The one-time card's instructions, per profile. The prose is translated
  // (#539); the commands and the claim names are protocol and stay as they
  // are.
  /**
   * What to do with a just-issued private key.
   *
   * @param profile - the profile
   * @param fresh - the one-time answer
   * @param view - the page's view
   * @param t - the translator
   * @returns the HTML
   */
  static freshInstructions(profile: Json, fresh: Json, view: Json,
                           t: Json): string {
    const who = String(fresh.issuer || view.username);
    const endpoint = view.tokenEndpoint;
    if (profile.id === 'saml') {
      return '<p class="note">' + t.html('portal.signingKey.samlHow',
          { who: who, endpoint: endpoint,
            thumbprint: String(fresh.thumbprint || '') }) + '</p>' +
        '<pre class="pem">' + kit.esc('curl -X POST ' + endpoint + ' \\\n' +
          '  -d grant_type=' + profile.grantType + ' \\\n' +
          '  -d assertion=<the signed assertion, base64url>') + '</pre>' +
        '<p class="note">' + t.html('portal.signingKey.samlOnlyYou') + '</p>';
    }
    return '<p class="note">' + t.html('portal.signingKey.jwtHow',
        { who: who, endpoint: endpoint, alg: String(fresh.jwsAlg || ''),
          kid: String(fresh.kid || '') }) + '</p>' +
      '<pre class="pem">' + kit.esc('curl -X POST ' + endpoint + ' \\\n' +
        '  -d grant_type=' + profile.grantType + ' \\\n' +
        '  -d assertion=<the signed JWT>') + '</pre>' +
      '<p class="note">' + t.html('portal.signingKey.jwtOnlyYou') + '</p>';
  }

  /**
   * One profile's card: what is held, and its two controls.
   *
   * @param profile - the profile, with `held`
   * @param view - the page's view
   * @param t - the translator
   * @returns the card's HTML
   */
  static profileCard(profile: Json, view: Json, t: Json): string {
    const mine = profile.held;
    const saml = profile.id === 'saml';
    const rfc = profile.rfc;
    const heading = '<h2 id="' + kit.esc(profile.id) + '">' + kit.esc(rfc) +
      ': ' + (saml ? t.html('portal.signingKey.samlTitle')
                   : t.html('portal.signingKey.jwtTitle')) + '</h2>';
    const status = !view.entry ? ''
      : (mine
        ? '<table><tr><th>' + (saml ? t.html('portal.signingKey.thumbprint')
                                    : t.html('portal.signingKey.key')) +
          '</th><td><code>' + kit.esc(mine.handle) + '</code></td></tr>' +
          '<tr><th>' + t.html('portal.signingKey.assertAs') + '</th><td>' +
          (mine.issuers || []).map(function (one: string): string {
            return '<code>' + kit.esc(one) + '</code>';
          }).join(' ') + '</td></tr><tr><th>' +
          t.html('portal.signingKey.goodUntil') + '</th><td>' +
          kit.esc(SigningKeyPages.readableDate(mine.expiresAt, t)) +
          '</td></tr></table>' +
          (mine.certificate
            ? '<details><summary>' + t.html('portal.signingKey.certificate') +
              '</summary><pre class="pem">' + kit.esc(mine.certificate) +
              '</pre></details>'
            : '')
        : '<p class="sub">' + t.html('portal.signingKey.noneHeld',
            { rfc: rfc }) + '</p>');
    const purpose = '<input type="hidden" name="purpose" value="' +
      kit.esc(profile.id) + '">';
    let controls = '';
    if (view.entry && view.issuable && view.offered) {
      controls = SigningKeyPages.form('generate', purpose + '<button' +
          (mine ? ' class="secondary"' : '') + '>' +
          (mine ? t.html('portal.signingKey.generateNew', { rfc: rfc })
                : t.html('portal.signingKey.generateMine', { rfc: rfc })) +
          '</button>') +
        (mine ? '<p class="note">' + t.html('portal.signingKey.replaces',
                  { rfc: rfc }) + '</p>'
              : '<p class="note">' + t.html('portal.signingKey.shownOnce') +
                '</p>');
    }
    const removeForm = mine
      ? SigningKeyPages.form('remove', purpose + '<button class="danger">' +
          t.html('portal.signingKey.takeOff', { rfc: rfc }) + '</button>') +
        '<p class="note">' + t.html('portal.signingKey.notRevocation') +
        '</p>'
      : '';
    return '<div class="card">' + heading + status + controls + removeForm +
      '</div>';
  }

  /**
   * The TLS client certificate card.
   *
   * @param view - the page's view
   * @param t - the translator
   * @returns the card's HTML
   */
  static tlsClientCard(view: Json, t: Json): string {
    const tls = view.tls || {};
    const held: Json[] = tls.held || [];
    const active = held.filter(function (one: Json): boolean {
      return one.state === 'valid';
    });
    // The sign-in address is a link, so its sentence is two messages around
    // it (#539); the register's note is its own words.
    const what = '<p class="sub">' + t.html('portal.tls.what',
        { name: view.username }) + '</p><p class="note">' +
      t.html('portal.tls.whereWorks') + ' <a href="' + kit.esc(tls.signIn) +
      '">' + kit.esc(tls.signIn) + '</a>' +
      t.html('portal.tls.whereWorksAfter') + '</p>' +
      (tls.trusted ? ''
        : '<p class="note">' + t.html('portal.tls.notAccepted') + ' ' +
          kit.esc(tls.note) + ' ' + t.html('portal.tls.adminCanChange') +
          '</p>');
    const rows = held.length
      ? '<table class="grid"><tr><th>' + t.html('portal.tls.name') +
        '</th><th>' + t.html('portal.tls.serial') + '</th><th>' +
        t.html('portal.tls.key') + '</th><th>' +
        t.html('portal.signingKey.goodUntil') + '</th><th>' +
        t.html('portal.tls.state') + '</th><th></th></tr>' +
        held.map(function (one: Json): string {
          const revokeForm = one.state === 'valid'
            ? SigningKeyPages.form('revoke-tls-client',
                '<input type="hidden" name="serial" value="' +
                kit.esc(one.serialHex) + '"><select name="reason" ' +
                'aria-label="' + kit.esc(t.text('portal.tls.why')) + '">' +
                '<option value="cessationOfOperation">' +
                t.html('portal.tls.noLongerUse') + '</option>' +
                '<option value="keyCompromise">' +
                t.html('portal.tls.compromised') + '</option></select> ' +
                '<button class="danger">' + t.html('portal.tls.revoke') +
                '</button>')
            : (one.revokedAt ? '<span class="note">' +
                t.html('portal.tls.revokedOn',
                       { day: String(one.revokedAt).slice(0, 10) }) +
                '</span>' : '');
          // The state is the register's own word, drawn as data.
          return '<tr><td>' + kit.esc(one.label) + '</td><td><code>' +
            kit.esc(String(one.serialHex).slice(-16)) + '</code></td><td>' +
            kit.esc(one.keyAlg) + '</td><td>' +
            kit.esc(String(one.notAfter).slice(0, 10)) + '</td><td><span ' +
            'class="state-' + kit.esc(one.state) + '">' + kit.esc(one.state) +
            (one.reason && one.state === 'revoked'
              ? ' (' + kit.esc(one.reason) + ')' : '') +
            '</span></td><td>' + revokeForm + '</td></tr>';
        }).join('') + '</table>'
      : '<p class="sub">' + t.html('portal.tls.noneHeld') + '</p>';
    let controls = '';
    if (view.issuable && view.offered) {
      if (active.length >= tls.maxPerPerson) {
        controls = '<p class="note">' + t.html('portal.tls.atCap',
          { n: active.length }) + '</p>';
      } else {
        controls = SigningKeyPages.form('generate-tls-client',
          '<label for="tls-label">' + t.html('portal.tls.labelName') +
          '</label><input type="text" id="tls-label" name="label" ' +
          'maxlength="40" placeholder="' +
          kit.esc(t.text('portal.tls.labelPlaceholder')) + '">' +
          '<label for="tls-key-alg">' + t.html('portal.tls.key') +
          '</label><select id="tls-key-alg" name="key_alg">' +
          (tls.keyAlgs || []).map(function (one: string): string {
            return '<option value="' + kit.esc(one) + '"' +
              (one === tls.defaultKeyAlg ? ' selected' : '') + '>' +
              (one === 'rsa-2048' ? t.html('portal.tls.rsa2048')
                : kit.esc(one === 'rsa-3072' ? 'RSA 3072'
                  : one === 'ec-p256' ? 'ECDSA P-256' : 'ECDSA P-384')) +
              '</option>';
          }).join('') + '</select>' +
          '<label for="tls-p12-password">' +
          t.html('portal.tls.p12Password') + '</label><input ' +
          'type="password" id="tls-p12-password" name="p12_password" ' +
          'minlength="' + kit.esc(tls.passwordMin) + '" ' +
          'autocomplete="new-password" required><label ' +
          'for="tls-p12-confirm">' + t.html('portal.tls.p12Again') +
          '</label><input type="password" id="tls-p12-confirm" ' +
          'name="p12_confirm" minlength="' + kit.esc(tls.passwordMin) + '" ' +
          'autocomplete="new-password" required><p class="note">' +
          t.html('portal.tls.p12Note') + '</p><button>' +
          t.html('portal.tls.generate') + '</button>');
      }
    }
    return '<div class="card"><h2 id="tls-client">' +
      t.html('portal.tls.heading') + '</h2>' + what + rows + controls +
      (active.length ? '<p class="note">' + t.html('portal.tls.revokingIs') +
                       '</p>' : '') + '</div>';
  }

  /**
   * The one-time card of a TLS client certificate: the three files, and
   * what to do with them.
   *
   * @param fresh - `view.fresh`
   * @param view - the page's view
   * @param t - the translator
   * @returns the card's HTML
   */
  static tlsClientFreshCard(fresh: Json, view: Json, t: Json): string {
    const files = fresh.files || {};
    const issued = fresh.issued || {};
    const signIn = (view.tls || {}).signIn || '';
    const link = function (file: Json, cls: string): string {
      return '<a class="dl' + cls + '" download="' + kit.esc(file.name) +
        '" href="' + kit.esc('data:' + file.mime + ';base64,' + file.base64) +
        '">' + t.html('portal.tlsFresh.download', { file: file.name }) +
        '</a>';
    };
    const p12 = files.pkcs12.name;
    const key = files.key.name;
    const chain = files.chain.name;
    const step = function (title: string, items: string[]): string {
      return '<details><summary>' + title + '</summary><ol class="steps">' +
        items.map(function (one: string): string {
          return '<li>' + one + '</li>';
        }).join('') + '</ol></details>';
    };
    return '<div class="card"><h2>' + t.html('portal.tlsFresh.heading') +
      '</h2><p class="sub">' + t.html('portal.tlsFresh.onlyTime') + '</p>' +
      '<p>' + link(files.pkcs12, '') + link(files.key, ' secondary') +
      link(files.chain, ' secondary') + '</p>' +
      '<table><tr><th>' + t.html('portal.tlsFresh.issuedTo') +
      '</th><td><code>' + kit.esc(issued.subject) +
      '</code></td></tr><tr><th>' +
      t.html('portal.tls.serial') + '</th><td><code>' +
      kit.esc(issued.serialHex) + '</code></td></tr><tr><th>' +
      t.html('portal.tls.key') + '</th><td>' + kit.esc(issued.keyAlg) +
      '</td></tr><tr><th>' + t.html('portal.signingKey.goodUntil') +
      '</th><td>' + kit.esc(String(issued.notAfter).slice(0, 10)) +
      '</td></tr></table><p class="note">' + t.html('portal.tlsFresh.files') +
      '</p><h3>' + t.html('portal.tlsFresh.install') + '</h3>' +
      step(t.html('portal.tlsFresh.winTitle'), [
        t.html('portal.tlsFresh.win1', { file: p12 }),
        t.html('portal.tlsFresh.win2'), t.html('portal.tlsFresh.win3'),
        t.html('portal.tlsFresh.win4')]) +
      step(t.html('portal.tlsFresh.macTitle'), [
        t.html('portal.tlsFresh.mac1', { file: p12 }),
        t.html('portal.tlsFresh.mac2'), t.html('portal.tlsFresh.mac3')]) +
      step(t.html('portal.tlsFresh.firefoxTitle'), [
        t.html('portal.tlsFresh.firefox1'),
        t.html('portal.tlsFresh.firefox2'),
        t.html('portal.tlsFresh.firefox3', { file: p12 })]) +
      step(t.html('portal.tlsFresh.linuxTitle'), [
        t.html('portal.tlsFresh.linux1'),
        t.html('portal.tlsFresh.linux2', { file: p12 }),
        t.html('portal.tlsFresh.linux3', { file: p12 })]) +
      step(t.html('portal.tlsFresh.curlTitle'), [
        '<code>curl --cert ' + kit.esc(chain) + ' --key ' + kit.esc(key) +
        ' --pass &lt;' + t.html('portal.tlsFresh.filePassword') + '&gt; ' +
        kit.esc(signIn) + '</code>',
        t.html('portal.tlsFresh.legacy', { key: key, chain: chain })]) +
      // The two links are markup, so the sentence is three messages around
      // them (#539).
      '<h3>' + t.html('portal.tlsFresh.use') + '</h3><p>' +
      t.html('portal.tlsFresh.useOpen') + ' <a href="' + kit.esc(signIn) +
      '">' + kit.esc(signIn) + '</a> ' + t.html('portal.tlsFresh.useChoose') +
      ' <a href="' + kit.BASE + '">' + t.html('portal.tlsFresh.yourAccount') +
      '</a>' + t.html('portal.tlsFresh.useAfter') + '</p></div>';
  }

  /**
   * The one-time card, of whichever kind the answer carried.
   *
   * @param view - the page's view
   * @param t - the translator
   * @returns the card's HTML, or ''
   */
  static freshCard(view: Json, t: Json): string {
    const fresh = view.fresh;
    if (!fresh) {
      return '';
    }
    if (fresh.kind === 'tls-client' && fresh.files) {
      return SigningKeyPages.tlsClientFreshCard(fresh, view, t);
    }
    if (!fresh.privateKeyPem) {
      return '';
    }
    const profile = (view.profiles || []).filter(function (one: Json) {
      return one.id === fresh.purpose;
    })[0] || (view.profiles || [])[0] || { id: 'jwt', rfc: 'RFC 7523' };
    return '<div class="card"><h2>' + t.html('portal.signingKey.saveHeading',
        { rfc: profile.rfc }) + '</h2><p class="sub">' +
      t.html('portal.signingKey.onlyTime') + '</p><pre class="pem">' +
      kit.esc(String(fresh.privateKeyPem)) + '</pre>' +
      SigningKeyPages.freshInstructions(profile, fresh, view, t) + '</div>';
  }

  /**
   * The page's body.
   *
   * @param view - `GET /account-api/signing-key`'s answer
   * @param ctx - the render context
   * @returns the HTML
   */
  static render(view: Json, ctx: Json): string {
    const t = ctx.t;
    // WHAT IT IS FOR, drawn whether or not one is held: this is the page
    // somebody arrives at not knowing what a signing key would be for.
    const what = '<p class="sub">' + t.html('portal.signingKey.what') +
      '</p><p class="note">' + t.html('portal.signingKey.twoKinds') +
      '</p><p class="note">' + t.html('portal.signingKey.thirdCard') +
      ' <a href="#tls-client">' + t.html('portal.tls.heading') + '</a>' +
      t.html('portal.signingKey.thirdCardAfter') + '</p>';
    // WHAT APPLIES TO BOTH, said once rather than once per profile.
    let shared = '';
    if (!view.entry) {
      shared = '<p class="sub">' + t.html('portal.signingKey.noEntry') +
        '</p>';
    } else if (!view.issuable) {
      shared = '<p class="note">' + t.html('portal.signingKey.noAuthority') +
        '</p>';
    } else if (!view.offered) {
      shared = '<p class="note">' + t.html('portal.signingKey.notOffered') +
        (view.holdsAny ? ' ' + t.html('portal.signingKey.unaffected') : '') +
        '</p>';
    }
    return SigningKeyPages.freshCard(view, t) +
      '<div class="card">' + what + shared + '</div>' +
      (view.profiles || []).map(function (profile: Json): string {
        return SigningKeyPages.profileCard(profile, view, t);
      }).join('') + SigningKeyPages.tlsClientCard(view, t);
  }

  /**
   * The pages, for `web_portal_pages.ts`.
   */
  static readonly PAGES: PortalPage[] = [
    { path: PATH, operation: '/account-api/signing-key',
      render: SigningKeyPages.render }
  ];
}

export = SigningKeyPages;
