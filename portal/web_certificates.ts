// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_certificates.ts
//
// ---------------------------------------------------------------------------
// `/portal/certificates`, DRAWN IN THE BROWSER (#568), from `GET
// /account-api/certificates` (`portal_certificates.ts`): the person's
// certificates with a Revoke each, a card per enrollment family turned on
// (ACME, EST, SCEP), and the host names on their entry. A secret an act just
// made — an account binding key, a challenge password — arrives in the
// answer's `view.fresh` and is drawn here, once. Every address printed was
// built by the server and arrives in the view.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import kit = require('./web_portal_kit');

type Json = any;
type PortalPage = import('../types/account-api').PortalPage;

const PATH = kit.BASE + '/certificates';

/**
 * `/portal/certificates`. A static utility class.
 */
class CertificatesPages {
  // A time for a person to read, in the page's language (#539): the
  // translator's date, which is UTC and says so.
  /**
   * A time.
   *
   * @param when - an instant
   * @param t - the translator
   * @returns the text
   */
  static readable(when: unknown, t: Json): string {
    const at = new Date(when as any);
    return isNaN(at.getTime()) ? String(when || '') : t.date(at);
  }

  /**
   * The secret just made, shown once.
   *
   * @param view - the view
   * @param t - the translator
   * @returns the card's HTML
   */
  static freshCard(view: Json, t: Json): string {
    const fresh = view.fresh;
    if (fresh.kind === 'eab') {
      const directory = view.urls.acmeDirectory;
      return '<div class="card"><h2>' +
        t.html('portalCertificates.fresh.eabHeading') + '</h2>' +
        '<div class="err">' + t.html('portalCertificates.fresh.eabCopy') +
        '</div><table><tr><th>' +
        t.html('portalCertificates.fresh.directory') + '</th><td><code>' +
        kit.esc(directory) + '</code></td></tr><tr><th>' +
        t.html('portalCertificates.keyId') + '</th><td><code>' +
        kit.esc(fresh.kid) + '</code></td></tr><tr><th>' +
        t.html('portalCertificates.fresh.hmacKey') + '</th><td><code>' +
        kit.esc(fresh.hmacKey) + '</code></td></tr><tr><th>' +
        t.html('portalCertificates.fresh.bindsUntil') + '</th><td>' +
        kit.esc(CertificatesPages.readable(fresh.expiresAt, t)) +
        '</td></tr></table><p class="sub">' +
        t.html('portalCertificates.fresh.example') + '</p><pre class="pem">' +
        kit.esc('certbot certonly --server ' + directory + ' \\\n' +
                '  --eab-kid ' + fresh.kid + ' \\\n' +
                '  --eab-hmac-key ' + fresh.hmacKey + ' ...') + '</pre>' +
        '<p class="note">' + t.html('portalCertificates.fresh.eabNote') +
        '</p></div>';
    }
    return '<div class="card"><h2>' +
      t.html('portalCertificates.fresh.challengeHeading') + '</h2>' +
      '<div class="err">' + t.html('portalCertificates.fresh.challengeCopy') +
      '</div><table><tr><th>' + t.html('portalCertificates.fresh.scepUrl') +
      '</th><td><code>' + kit.esc(fresh.scepUrl) + '</code></td></tr>' +
      // The plain-HTTP address too (#210): sscep and most device firmware
      // speak no TLS, and SCEP secures its own messages.
      '<tr><th>' + t.html('portalCertificates.fresh.plainScepUrl') +
      '</th><td><code>' + kit.esc(fresh.plainScepUrl) + '</code></td></tr>' +
      '<tr><th>' + t.html('portalCertificates.fresh.challenge') +
      '</th><td><code>' + kit.esc(fresh.challenge) +
      '</code></td></tr><tr><th>' + t.html('portalCertificates.profile') +
      '</th><td><code>' + kit.esc(fresh.profile) + '</code></td></tr><tr><th>' +
      t.html('portalCertificates.fresh.usableUntil') + '</th><td>' +
      kit.esc(CertificatesPages.readable(fresh.expiresAt, t)) +
      '</td></tr></table><p class="note">' +
      t.html('portalCertificates.fresh.challengeNote') + '</p></div>';
  }

  /**
   * The certificates issued, each valid one with its Revoke.
   *
   * @param view - the view
   * @param t - the translator
   * @returns the card's HTML
   */
  static certificatesCard(view: Json, t: Json): string {
    const records: Json[] = view.enrolled || [];
    if (!records.length) {
      return '<div class="card"><h2>' +
        t.html('portalCertificates.enrolled.heading') + '</h2><p ' +
        'class="sub">' + t.html('portalCertificates.enrolled.none') +
        '</p></div>';
    }
    const labels = view.familyLabels || {};
    const rows = records.map(function (one: Json) {
      const revoke = one.status === 'valid'
        ? '<form method="post" action="' + PATH + '">' +
          '<input type="hidden" name="action" value="revoke">' +
          '<input type="hidden" name="serial" value="' +
          kit.esc(one.serialHex) + '"><select name="reason" aria-label="' +
          kit.esc(t.text('portalCertificates.enrolled.reason')) + '">' +
          // The reasons are RFC 5280's names, and stay as they are.
          (view.reasons || []).map(function (reason: string) {
            return '<option value="' + kit.esc(reason) + '">' +
              kit.esc(reason) + '</option>';
          }).join('') + '</select> <button class="danger">' +
          t.html('portalCertificates.enrolled.revoke') + '</button>' +
          '</form>'
        : '';
      return '<tr><td>' + kit.esc(labels[one.family] || one.family) +
        '</td><td><code>' + kit.esc(one.profile) + '</code></td><td><code>' +
        kit.esc(one.serialHex) + '</code></td><td>' +
        (one.names || []).map(function (name: string) {
          return '<code>' + kit.esc(name) + '</code>';
        }).join('<br>') + '</td><td>' +
        kit.esc(CertificatesPages.readable(one.notAfter, t)) +
        '</td><td>' + kit.esc(one.status) +
        (one.keySource === 'server' ? '<br><span class="sub">' +
          t.html('portalCertificates.enrolled.keyMadeHere') + '</span>'
          : '') + '</td><td>' + revoke + '</td></tr>';
    }).join('');
    return '<div class="card"><h2>' +
      t.html('portalCertificates.enrolled.heading') + '</h2>' +
      '<table><tr><th>' + t.html('portalCertificates.enrolled.protocol') +
      '</th><th>' + t.html('portalCertificates.profile') + '</th><th>' +
      t.html('portalCertificates.enrolled.serial') + '</th><th>' +
      t.html('portalCertificates.enrolled.names') + '</th><th>' +
      t.html('portalCertificates.enrolled.until') + '</th><th>' +
      t.html('portalCertificates.status') + '</th><th></th></tr>' + rows +
      '</table><p class="note">' +
      t.html('portalCertificates.enrolled.note') + '</p></div>';
  }

  /**
   * ACME: the account binding keys held, and the button that makes one.
   *
   * @param view - the view
   * @param t - the translator
   * @returns the card's HTML
   */
  static acmeCard(view: Json, t: Json): string {
    const rows = (view.acme.keys || []).map(function (one: Json) {
      return '<tr><td><code>' + kit.esc(one.kid) + '</code></td><td>' +
        kit.esc(one.status) + '</td><td>' +
        kit.esc(CertificatesPages.readable(one.expiresAt, t)) +
        '</td><td>' + (one.status === 'bound' ? '' :
          '<form method="post" action="' + PATH + '">' +
          '<input type="hidden" name="action" value="delete-eab">' +
          '<input type="hidden" name="kid" value="' + kit.esc(one.kid) +
          '"><button class="secondary">' +
          t.html('portalCertificates.delete') + '</button></form>') +
        '</td></tr>';
    }).join('');
    return '<div class="card"><h2>ACME</h2><p class="sub">' +
      t.html('portalCertificates.acme.text',
             { url: view.urls.acmeDirectory }) + '</p>' +
      (rows ? '<table><tr><th>' + t.html('portalCertificates.keyId') +
        '</th><th>' + t.html('portalCertificates.status') + '</th><th>' +
        t.html('portalCertificates.expires') + '</th><th></th></tr>' + rows +
        '</table>' : '') +
      '<form method="post" action="' + PATH + '">' +
      '<input type="hidden" name="action" value="create-eab"><button>' +
      t.html('portalCertificates.acme.make') + '</button></form></div>';
  }

  /**
   * EST: the profiles and where each enrolls.
   *
   * @param view - the view
   * @param t - the translator
   * @returns the card's HTML
   */
  static estCard(view: Json, t: Json): string {
    return '<div class="card"><h2>EST</h2><p class="sub">' +
      t.html('portalCertificates.est.text') + '</p><table><tr><th>' +
      t.html('portalCertificates.profile') + '</th><th>' +
      t.html('portalCertificates.est.enrollAt') + '</th></tr>' +
      (view.est.profiles || []).map(function (profile: string) {
        return '<tr><td><code>' + kit.esc(profile) + '</code></td><td><code>' +
          kit.esc(view.urls.est + '/' + profile + '/simpleenroll') +
          '</code></td></tr>';
      }).join('') + '</table></div>';
  }

  /**
   * SCEP: the challenge passwords held, and the form that makes one.
   *
   * @param view - the view
   * @param t - the translator
   * @returns the card's HTML
   */
  static scepCard(view: Json, t: Json): string {
    const scep = view.scep;
    const rows = (scep.challenges || []).map(function (one: Json) {
      return '<tr><td><code>' + kit.esc(one.id) + '</code></td><td><code>' +
        kit.esc(one.profile) + '</code></td><td>' + kit.esc(one.status) +
        '</td><td>' + kit.esc(CertificatesPages.readable(one.expiresAt, t)) +
        '</td><td>' + (one.status === 'unused'
          ? '<form method="post" action="' + PATH + '">' +
            '<input type="hidden" name="action" value="delete-challenge">' +
            '<input type="hidden" name="id" value="' + kit.esc(one.id) +
            '"><button class="secondary">' +
            t.html('portalCertificates.delete') + '</button></form>'
          : '') + '</td></tr>';
    }).join('');
    const options = (scep.profiles || []).map(function (profile: string) {
      return '<option value="' + kit.esc(profile) + '"' +
        (profile === scep.defaultProfile ? ' selected' : '') + '>' +
        kit.esc(profile) + '</option>';
    }).join('');
    return '<div class="card"><h2>SCEP</h2><p class="sub">' +
      t.html('portalCertificates.scep.text', { url: view.urls.scep }) +
      '</p>' +
      (rows ? '<table><tr><th>' + t.html('portalCertificates.scep.id') +
        '</th><th>' + t.html('portalCertificates.profile') + '</th><th>' +
        t.html('portalCertificates.status') + '</th><th>' +
        t.html('portalCertificates.expires') + '</th><th></th></tr>' + rows +
        '</table>' : '') +
      '<form method="post" action="' + PATH + '">' +
      '<input type="hidden" name="action" value="create-challenge">' +
      '<label>' + t.html('portalCertificates.profile') +
      ' <select name="profile">' + options + '</select></label> <button>' +
      t.html('portalCertificates.scep.make') + '</button></form></div>';
  }

  /**
   * The host names registered on the entry.
   *
   * @param names - the names
   * @param t - the translator
   * @returns the card's HTML
   */
  static hostNamesCard(names: string[], t: Json): string {
    return '<div class="card"><h2>' +
      t.html('portalCertificates.hostNames.heading') + '</h2>' +
      (names.length
        ? '<p>' + names.map(function (one: string) {
          return '<code>' + kit.esc(one) + '</code>';
        }).join(' ') + '</p>'
        : '<p class="sub">' + t.html('portalCertificates.hostNames.none') +
          '</p>') +
      '<p class="note">' + t.html('portalCertificates.hostNames.note') +
      '</p></div>';
  }

  /**
   * The page's body.
   *
   * @param view - `GET /account-api/certificates`' answer, or an act's
   * @param ctx - the render context
   * @returns the HTML
   */
  static render(view: Json, ctx: Json): string {
    const t = ctx.t;
    const cards: string[] = [];
    if (view.fresh) {
      cards.push(CertificatesPages.freshCard(view, t));
    }
    if (!view.resolved) {
      cards.push('<div class="card"><h2>' +
        t.html('portalCertificates.noEntry.heading') + '</h2><p ' +
        'class="sub">' + t.html('portalCertificates.noEntry.text',
          { name: view.name }) + '</p></div>');
      return cards.join('');
    }
    cards.push(CertificatesPages.certificatesCard(view, t));
    if (view.acme) {
      cards.push(CertificatesPages.acmeCard(view, t));
    }
    if (view.est) {
      cards.push(CertificatesPages.estCard(view, t));
    }
    if (view.scep) {
      cards.push(CertificatesPages.scepCard(view, t));
    }
    cards.push(CertificatesPages.hostNamesCard(view.hostNames || [], t));
    // The link is markup a message may not carry (#539), so the sentence is
    // two messages around it.
    cards.push('<div class="card"><h2>' +
      t.html('portalCertificates.other.heading') + '</h2><p ' +
      'class="sub">' + t.html('portalCertificates.other.before') + ' <a ' +
      'href="' + kit.BASE + '/signing-key">' +
      t.html('portalCertificates.other.link') + '</a>' +
      t.html('portalCertificates.other.after') + '</p></div>');
    return cards.join('');
  }

  /**
   * The pages, for `web_portal_pages.ts`.
   */
  static readonly PAGES: PortalPage[] = [
    { path: PATH, operation: '/account-api/certificates',
      render: CertificatesPages.render }
  ];
}

export = CertificatesPages;
