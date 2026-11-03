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
// WHAT ONLY EXISTS FOR ONE ANSWER: the private key and the certificate chain
// a generation answers, which arrive in `view.fresh.files` only in the answer
// to the act that made them and are drawn in place — never on a URL, never in
// the history. The files are `data:` links with `download` on them, the same
// two on all three cards (`downloads()`), and they sit IN THE CERTIFICATE'S
// ROW of that card's table: the signing key's *Certificate* row, the TLS
// client certificate's row in the list of them (rcbj, #671, 2026-11-03).
//
// **AND IN THE PANE WHOSE BUTTON MADE IT (#671).** Until 2026-11-03 the
// one-time block was a card of its own at the TOP of the page, while the
// TLS client certificate's Generate is in the LAST card: a person pressed
// Generate at the bottom, the page was drawn again with nothing new where
// they were looking, and the downloads sat three cards above. rcbj read it
// as "nothing was downloaded". So everything a generation answers is drawn
// in the card that offered the act: the buttons in the certificate's row
// (`tr.fresh-row`, which the runtime scrolls to), and what to do with the
// files in a `.fresh` block just below the table.
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

  /**
   * The two download links a generation answers (#671): the private key
   * and the certificate chain, in the certificate's row. The label is short,
   * since it sits in a table cell; the file name is the link's `download`
   * and its title.
   *
   * @param files - `view.fresh.files`
   * @param t - the translator
   * @returns the links' HTML, or ''
   */
  static downloads(files: Json, t: Json): string {
    if (!files || !files.key || !files.chain) {
      return '';
    }
    const link = function (file: Json, label: string, cls: string): string {
      return '<a class="dl' + cls + '" download="' + kit.esc(file.name) +
        '" title="' + kit.esc(file.name) + '" href="' +
        kit.esc('data:' + file.mime + ';base64,' + file.base64) + '">' +
        label + '</a>';
    };
    return '<div class="dl-row">' +
      link(files.key, t.html('portal.signingKey.downloadKey'), '') +
      link(files.chain, t.html('portal.signingKey.downloadChain'),
           ' secondary') + '</div>';
  }

  /**
   * What a generation just answered for this signing key profile, or null.
   *
   * @param profile - the card's profile
   * @param view - the page's view
   * @returns `view.fresh`, or null
   */
  static freshFor(profile: Json, view: Json): Json {
    const fresh = view.fresh;
    // A generation always names its profile; absent is `jwt`, as the form's
    // own `purpose` is.
    if (!fresh || fresh.kind === 'tls-client' || !fresh.files ||
        String(fresh.purpose || 'jwt') !== profile.id) {
      return null;
    }
    return fresh;
  }

  /**
   * A held signing key's *Certificate* row (#671): the two downloads, in the
   * one answer that issued it, and the public certificate to read.
   *
   * @param profile - the profile, with `held`
   * @param view - the page's view
   * @param t - the translator
   * @returns the row's HTML, or ''
   */
  static certificateRow(profile: Json, view: Json, t: Json): string {
    const mine = profile.held || {};
    const fresh = SigningKeyPages.freshFor(profile, view);
    const files = fresh ? SigningKeyPages.downloads(fresh.files, t) : '';
    if (!files && !mine.certificate) {
      return '';
    }
    return '<tr' + (files ? ' class="fresh-row"' : '') + '><th>' +
      t.html('portal.signingKey.certificateRow') + '</th><td>' + files +
      (mine.certificate
        ? '<details><summary>' + t.html('portal.signingKey.certificate') +
          '</summary><pre class="pem">' + kit.esc(mine.certificate) +
          '</pre></details>'
        : '') + '</td></tr>';
  }

  // EVERY BLOCK OF TEXT FOLDS (#1289, rcbj, 2026-11-03: "the UI is messy
  // the way it currently is"). A block whose catalog text OPENS WITH ITS OWN
  // BOLD LEAD folds under that lead, so the summary is the block's first
  // words in every language and nothing is split by hand; a block with no
  // lead gets a short title of its own. A block that is only its lead, or a
  // one-sentence note, stays as it is — folding it would hide nothing but
  // the same words. `<details>` is markup, so this needs no script.
  /**
   * A block of text, folded under its bold lead or a title.
   *
   * @param html - the block's translated HTML
   * @param extra - more HTML that belongs inside the fold, after the text
   * @param title - the summary for a block with no bold lead
   * @returns the fold's HTML, or the block as a note when nothing would fold
   */
  static fold(html: string, extra?: string, title?: string): string {
    const more = extra || '';
    if (title) {
      return '<details class="prose"><summary>' + title + '</summary>' +
        '<div class="prose-body">' + html + more + '</div></details>';
    }
    const lead = /^\s*<strong>([\s\S]*?)<\/strong>\s*([\s\S]*)$/
      .exec(String(html));
    if (!lead || (!lead[2] && !more)) {
      return '<p class="note">' + html + '</p>' + more;
    }
    return '<details class="prose"><summary>' + lead[1] + '</summary>' +
      '<div class="prose-body">' +
      (lead[2] ? '<p class="note">' + lead[2] + '</p>' : '') + more +
      '</div></details>';
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
      return SigningKeyPages.fold(t.html('portal.signingKey.samlHow',
          { who: who, endpoint: endpoint,
            thumbprint: String(fresh.thumbprint || '') }),
        '<pre class="pem">' + kit.esc('curl -X POST ' + endpoint + ' \\\n' +
          '  -d grant_type=' + profile.grantType + ' \\\n' +
          '  -d assertion=<the signed assertion, base64url>') + '</pre>') +
        SigningKeyPages.fold(t.html('portal.signingKey.samlOnlyYou'));
    }
    return SigningKeyPages.fold(t.html('portal.signingKey.jwtHow',
        { who: who, endpoint: endpoint, alg: String(fresh.jwsAlg || ''),
          kid: String(fresh.kid || '') }),
      '<pre class="pem">' + kit.esc('curl -X POST ' + endpoint + ' \\\n' +
        '  -d grant_type=' + profile.grantType + ' \\\n' +
        '  -d assertion=<the signed JWT>') + '</pre>') +
      SigningKeyPages.fold(t.html('portal.signingKey.jwtOnlyYou'));
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
          '</td></tr>' + SigningKeyPages.certificateRow(profile, view, t) +
          '</table>' + SigningKeyPages.keyFresh(profile, view, t)
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
        (mine ? SigningKeyPages.fold(t.html('portal.signingKey.replaces',
                  { rfc: rfc }))
              : '<p class="note">' + t.html('portal.signingKey.shownOnce') +
                '</p>');
    }
    const removeForm = mine
      ? SigningKeyPages.form('remove', purpose + '<button class="danger">' +
          t.html('portal.signingKey.takeOff', { rfc: rfc }) + '</button>') +
        SigningKeyPages.fold(t.html('portal.signingKey.notRevocation'))
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
    const fresh = view.fresh && view.fresh.kind === 'tls-client' &&
                  view.fresh.files ? view.fresh : null;
    const active = held.filter(function (one: Json): boolean {
      return one.state === 'valid';
    });
    // The sign-in address is a link, so its sentence is two messages around
    // it (#539); the register's note is its own words.
    const what = SigningKeyPages.fold('<p class="sub">' +
        t.html('portal.tls.what', { name: view.username }) +
        '</p><p class="note">' + t.html('portal.tls.whereWorks') +
        ' <a href="' + kit.esc(tls.signIn) + '">' + kit.esc(tls.signIn) +
        '</a>' + t.html('portal.tls.whereWorksAfter') + '</p>', '',
        t.html('portal.tls.aboutTitle')) +
      (tls.trusted ? ''
        : SigningKeyPages.fold(t.html('portal.tls.notAccepted') + ' ' +
          kit.esc(tls.note) + ' ' + t.html('portal.tls.adminCanChange')));
    const rows = held.length
      ? '<table class="grid"><tr><th>' + t.html('portal.tls.name') +
        '</th><th>' + t.html('portal.tls.serial') + '</th><th>' +
        t.html('portal.tls.key') + '</th><th>' +
        t.html('portal.signingKey.goodUntil') + '</th><th>' +
        t.html('portal.tls.state') + '</th><th></th></tr>' +
        held.map(function (one: Json): string {
          // THE CERTIFICATE JUST ISSUED carries its two files in its own row
          // (#671), beside its Revoke.
          const files = fresh && String(one.serialHex) ===
                          String((fresh.issued || {}).serialHex)
            ? SigningKeyPages.downloads(fresh.files, t) : '';
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
          return '<tr' + (files ? ' class="fresh-row"' : '') + '><td>' +
            kit.esc(one.label) + '</td><td><code>' +
            kit.esc(String(one.serialHex).slice(-16)) + '</code></td><td>' +
            kit.esc(one.keyAlg) + '</td><td>' +
            kit.esc(String(one.notAfter).slice(0, 10)) + '</td><td><span ' +
            'class="state-' + kit.esc(one.state) + '">' + kit.esc(one.state) +
            (one.reason && one.state === 'revoked'
              ? ' (' + kit.esc(one.reason) + ')' : '') +
            '</span></td><td>' + files + revokeForm + '</td></tr>';
        }).join('') + '</table>'
      : '<p class="sub">' + t.html('portal.tls.noneHeld') + '</p>';
    let controls = '';
    if (view.issuable && view.offered) {
      if (active.length >= tls.maxPerPerson) {
        controls = SigningKeyPages.fold(t.html('portal.tls.atCap',
          { n: active.length }));
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
          }).join('') + '</select><button>' +
          t.html('portal.tls.generate') + '</button>');
      }
    }
    return '<div class="card"><h2 id="tls-client">' +
      t.html('portal.tls.heading') + '</h2>' + what + rows +
      (fresh ? SigningKeyPages.tlsClientFresh(fresh, view, t) : '') +
      controls +
      (active.length
        ? SigningKeyPages.fold(t.html('portal.tls.revokingIs')) : '') +
      '</div>';
  }

  /**
   * What to do with a TLS client certificate just issued, drawn under the
   * card's list of them (#671); the downloads are in the certificate's row.
   *
   * @param fresh - `view.fresh`
   * @param view - the page's view
   * @param t - the translator
   * @returns the block's HTML
   */
  static tlsClientFresh(fresh: Json, view: Json, t: Json): string {
    const files = fresh.files || {};
    const signIn = (view.tls || {}).signIn || '';
    return '<div class="fresh" id="tls-client-fresh"><h3>' +
      t.html('portal.tlsFresh.heading') + '</h3>' +
      SigningKeyPages.fold(t.html('portal.tlsFresh.onlyTime'),
        '<p class="note">' + t.html('portal.tlsFresh.files') + '</p>') +
      SigningKeyPages.fold('<pre class="pem">' +
        kit.esc('curl --cert ' + files.chain.name + ' --key ' +
                files.key.name + ' ' + signIn) + '</pre>', '',
        t.html('portal.tlsFresh.curlTitle')) + '</div>';
  }

  /**
   * What to do with a signing key pair just issued, drawn under its card's
   * table (#671); the downloads are in the table's *Certificate* row.
   *
   * @param profile - the card's profile
   * @param view - the page's view
   * @param t - the translator
   * @returns the block's HTML, or ''
   */
  static keyFresh(profile: Json, view: Json, t: Json): string {
    const fresh = SigningKeyPages.freshFor(profile, view);
    if (!fresh) {
      return '';
    }
    return '<div class="fresh" id="' + kit.esc(profile.id) + '-fresh"><h3>' +
      t.html('portal.signingKey.saveHeading', { rfc: profile.rfc }) +
      '</h3>' + SigningKeyPages.fold(t.html('portal.signingKey.onlyTime')) +
      SigningKeyPages.freshInstructions(profile, fresh, view, t) +
      '</div>';
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
    const what = SigningKeyPages.fold('<p class="sub">' +
      t.html('portal.signingKey.what') + '</p><p class="note">' +
      t.html('portal.signingKey.twoKinds') + '</p><p class="note">' +
      t.html('portal.signingKey.thirdCard') + ' <a href="#tls-client">' +
      t.html('portal.tls.heading') + '</a>' +
      t.html('portal.signingKey.thirdCardAfter') + '</p>', '',
      t.html('portal.signingKey.aboutTitle'));
    // WHAT APPLIES TO BOTH, said once rather than once per profile.
    let shared = '';
    if (!view.entry) {
      shared = '<p class="sub">' + t.html('portal.signingKey.noEntry') +
        '</p>';
    } else if (!view.issuable) {
      shared = SigningKeyPages.fold(t.html('portal.signingKey.noAuthority'));
    } else if (!view.offered) {
      shared = SigningKeyPages.fold(t.html('portal.signingKey.notOffered') +
        (view.holdsAny ? ' ' + t.html('portal.signingKey.unaffected') : ''));
    }
    return '<div class="card">' + what + shared + '</div>' +
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
