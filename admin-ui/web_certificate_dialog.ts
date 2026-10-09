// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_certificate_dialog.ts
//
// ---------------------------------------------------------------------------
// THE CERTIFICATE DETAILS DIALOG, AS A RENDERER A BROWSER CAN LOAD (#446,
// 2026-10-05).
//
// `admin-ui/certificate_dialog.ts` argues the dialog — a link that adds
// `?certificate=` to the page, the page drawn with the dialog over it, the X
// and the Close button going back, where the reader was kept — and this is
// its drawing, moved so a page drawn in the browser opens a certificate as
// the server-rendered console does. It draws from `certificate_views`'
// `detailsView()`, which carries the key's post-quantum classification as
// `pqc` (since #446) so that this never parses a certificate.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// Its methods were `CertificateDialog`'s, moved with their comments; that
// class keeps `requested()`, which reads a request, and calls these.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');
import PqcBadgeView = require('./web_pqc_badge');
import webMessages = require('./web_messages');

type Json = any;

// The console's escaping, under the name the moved code calls it by.
const esc = kit.esc;

// The query parameters this dialog owns, named once.
/**
 * The query parameter that opens the dialog: a certificate's SHA-256
 * fingerprint.
 */
const PARAM = 'certificate';
/**
 * The query parameter naming the section the opening link sits in, so closing
 * returns to it.
 */
const FROM = 'from';

// ---------------------------------------------------------------------------
// THE STYLE. Scoped under `.certdlg-` so that nothing on either page is
// restyled by opening a dialog, and inline because this console's shell is one
// document with its stylesheet in it — `style-src` allows that and nothing
// here needs a second resource.
// ---------------------------------------------------------------------------
const STYLE = '<style>' +
  'body:has(.certdlg-backdrop){overflow:hidden}' +
  '.certdlg-backdrop{position:fixed;inset:0;background:rgba(20,20,30,.55);' +
  'z-index:1000;display:flex;align-items:flex-start;justify-content:center;' +
  'padding:4vh 1rem;overflow:auto}' +
  '.certdlg{background:#fff;color:#222;border-radius:10px;' +
  'box-shadow:0 18px 60px rgba(0,0,0,.35);width:100%;max-width:68rem;' +
  'display:flex;flex-direction:column;max-height:92vh}' +
  '.certdlg-head{display:flex;align-items:flex-start;gap:1rem;' +
  'padding:1rem 1.25rem .75rem;border-bottom:1px solid #e3e3ea}' +
  '.certdlg-head h2{margin:0;font-size:1.25rem;flex:1 1 auto;' +
  'word-break:break-word}' +
  '.certdlg-head .sub{display:block;font-size:.85rem;font-weight:normal;' +
  'color:#555;margin-top:.2rem}' +
  '.certdlg-x{flex:0 0 auto;font-size:1.6rem;line-height:1;' +
  'text-decoration:none;color:#444;padding:.1rem .45rem;border-radius:6px}' +
  '.certdlg-x:hover,.certdlg-x:focus{background:#eee;color:#000}' +
  '.certdlg-body{padding:.75rem 1.25rem;overflow:auto}' +
  '.certdlg-body h3{margin:1.1rem 0 .4rem;font-size:1.02rem}' +
  '.certdlg-body table{border-collapse:collapse;width:100%;margin:.25rem 0}' +
  '.certdlg-body th,.certdlg-body td{text-align:left;vertical-align:top;' +
  'padding:.3rem .5rem;border-bottom:1px solid #eee;font-size:.88rem}' +
  '.certdlg-body th{width:16rem;color:#444;font-weight:600}' +
  '.certdlg-body code,.certdlg-hex{word-break:break-all}' +
  '.certdlg-hex{font-family:ui-monospace,Menlo,Consolas,monospace;' +
  'font-size:.8rem}' +
  '.certdlg-body pre{white-space:pre-wrap;word-break:break-all;' +
  'font-size:.8rem;background:#f6f6f9;padding:.6rem;border-radius:6px}' +
  '.certdlg-ok{color:#1a6b2c;font-weight:600}' +
  '.certdlg-bad{color:#a4161a;font-weight:600}' +
  '.certdlg-na{color:#666}' +
  '.certdlg-crit{display:inline-block;font-size:.72rem;padding:0 .35rem;' +
  'border-radius:4px;background:#fde8e8;color:#a4161a;margin-left:.3rem}' +
  '.certdlg-body ul{margin:.1rem 0;padding-left:1.1rem}' +
  '.certdlg-foot{padding:.75rem 1.25rem;border-top:1px solid #e3e3ea;' +
  'display:flex;justify-content:flex-end}' +
  '.certdlg-foot form{margin:0}' +
  '.certdlg-foot button{font-size:.95rem;padding:.45rem 1.2rem}' +
  '</style>';

// The sentences are messages since #539, so this is a function of the
// page's translator rather than a table.
const CHAIN_STATUS = function (t: Json): Record<string, string> {
  return {
    complete: t.text('consoleCertificateDialog.chainComplete'),
    incomplete: t.text('consoleCertificateDialog.chainIncomplete'),
    unverified: t.text('consoleCertificateDialog.chainUnverified'),
    'too-deep': t.text('consoleCertificateDialog.chainTooDeep')
  };
};

/**
 * Draws a certificate's details dialog and the link that opens it.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class CertificateDialogView {
  /**
   * The query parameter naming the certificate to open.
   */
  static readonly PARAM = PARAM;

  /**
   * The query parameter naming the section to return to.
   */
  static readonly FROM = FROM;

  static fromOf(value: Json): string {
    const text = String(value || '');
    return /^[A-Za-z][A-Za-z0-9_-]{0,63}$/.test(text) ? text : '';
  }

  // ---------------------------------------------------------------------------
  // THE LINK THAT OPENS ONE. `pagePath` is the page it is drawn on, so the
  // dialog opens over that page; `from` is the id of the section the link
  // sits in.
  // ---------------------------------------------------------------------------
  /**
   * Draws the link that opens a certificate's dialog over the page it is on.
   *
   * @param pagePath - the page the link is drawn on
   * @param fingerprint - the certificate's SHA-256 fingerprint
   * @param from - the id of the section the link sits in
   * @param text - the link's text; "View details" when absent
   * @param t - the page's translator (#539); the default (English in node)
   *   when absent, which is what `admin-ui/certificate_dialog.ts` draws with
   * @returns the link's HTML, or an empty string without a usable fingerprint
   */
  static link(pagePath: string, fingerprint: Json, from?: Json,
       text?: string, t?: Json): string {
    const self = this;
    t = t || webMessages.WebTranslator.fallback();
    const fp = String(fingerprint || '').toLowerCase()
      .replace(/[^0-9a-f]/g, '');
    if (fp.length !== 64) {
      return '';
    }
    const back = self.fromOf(from);
    return '<a class="certdlg-open" href="' + esc(pagePath) + '?' + PARAM +
      '=' + fp + (back ? '&amp;' + FROM + '=' + esc(back) : '') + '" ' +
      'title="' + esc(t.text('consoleCertificateDialog.linkTip')) + '">' +
      esc(text || t.text('consoleCertificateDialog.viewDetails')) + '</a>';
  }

  static verdict(value: Json, yes: string, no: string,
                  unknown: string | undefined, t: Json): string {
    if (value === true) {
      return '<span class="certdlg-ok">' + esc(yes) + '</span>';
    }
    if (value === false) {
      return '<span class="certdlg-bad">' + esc(no) + '</span>';
    }
    return '<span class="certdlg-na">' +
           esc(unknown || t.text('consoleCertificateDialog.notApplicable')) +
           '</span>';
  }

  static row(label: string, html: string): string {
    return '<tr><th scope="row">' + esc(label) + '</th><td>' + html +
           '</td></tr>';
  }

  // An extension's decoded value, as whatever shape it came in. A list is a
  // list, an object is its members, and anything else is text — the vendored
  // `extensionValueText()` is the fallback, so no shape can print as
  // "[object Object]".
  static valueHtml(value: Json, text: Json, t: Json): string {
    if (Array.isArray(value)) {
      return value.length
        ? '<ul>' + value.map(function (one) {
            return '<li><code>' + esc(typeof one === 'object'
              ? JSON.stringify(one) : String(one)) + '</code></li>';
          }).join('') + '</ul>'
        : '<span class="certdlg-na">' +
          t.html('consoleCertificateDialog.empty') + '</span>';
    }
    if (value && typeof value === 'object') {
      return '<ul>' + Object.keys(value).map(function (key) {
        const member = value[key];
        return '<li>' + esc(key) + ': <code>' + esc(member === null
          ? t.text('consoleCertificateDialog.absentMember')
          : (typeof member === 'object'
            ? JSON.stringify(member) : String(member))) + '</code></li>';
      }).join('') + '</ul>';
    }
    return '<code>' + esc(text) + '</code>';
  }

  static nameTable(name: Json, t: Json): string {
    const rows = (name.attributes || []).map(function (one) {
      return '<tr><td>' + esc(one.label) +
        (one.short ? ' (<code>' + esc(one.short) + '</code>)' : '') +
        '</td><td><code>' + esc(one.oid) + '</code></td><td><code>' +
        esc(one.value) + '</code></td></tr>';
    }).join('');
    return '<code>' + esc(name.text) + '</code>' +
      (rows ? '<table><thead><tr><th>' +
              t.html('consoleCertificateDialog.thAttribute') + '</th><th>' +
              t.html('consoleCertificateDialog.thOid') + '</th><th>' +
              t.html('consoleCertificateDialog.thValue') + '</th>' +
              '</tr></thead><tbody>' + rows + '</tbody></table>' : '');
  }

  static algorithmHtml(alg: Json, t: Json): string {
    return (alg.name ? esc(alg.name) + ' ' : '') + '<code>' + esc(alg.oid) +
      '</code>' + (alg.parameters && alg.parameters !== 'absent'
        ? t.html('consoleCertificateDialog.parameters',
                 { value: alg.parameters })
        : t.html('consoleCertificateDialog.parametersAbsent'));
  }

  // A long run of hex, shown whole behind a disclosure. Everything in a
  // certificate is public, and a details view that truncated the key or the
  // signature would be the one place a reader could not check a byte.
  static hexHtml(label: string, hex: Json, octets: Json, t: Json): string {
    return t.html('consoleCertificateDialog.octets', { n: octets }) +
      ' <details><summary>' + esc(label) +
      '</summary><div class="certdlg-hex">' + esc(hex) + '</div></details>';
  }

  // ---------------------------------------------------------------------------
  // EVERY FIELD, IN THE ORDER RFC 5280 SECTION 4.1 WRITES THEM. One function
  // for the certificate the dialog was opened on and for every certificate in
  // its chain, so a chain member is never described with fewer fields than a
  // leaf.
  // ---------------------------------------------------------------------------
  /**
   * Draws every field of a described certificate in the order RFC 5280 section
   * 4.1 writes them; used for the opened certificate and each member of its
   * chain.
   *
   * @param described - `common/certificate_details.ts`'s model of a certificate
   * @param t - the page's translator (#539); the default when absent
   * @returns the fields as HTML
   */
  static fieldsHtml(described: Json, t?: Json): string {
    const self = this;
    t = t || webMessages.WebTranslator.fallback();
    const f = described.fields;
    const tbs = f.tbsCertificate;
    const spki = tbs.subjectPublicKeyInfo;
    const key = spki.key || {};
    const keyFacts = [];
    if (key.modulusBits) {
      keyFacts.push(t.text('consoleCertificateDialog.modulusBits',
                           { n: key.modulusBits }));
    }
    if (key.publicExponent) {
      keyFacts.push(t.text('consoleCertificateDialog.exponent',
                           { value: key.publicExponent }));
    }
    if (key.namedCurve) {
      keyFacts.push(t.text('consoleCertificateDialog.curve',
                           { name: key.namedCurve }));
    }
    const extensions = tbs.extensions.length
      ? '<table><thead><tr><th>' +
        t.html('consoleCertificateDialog.thExtension') + '</th><th>' +
        t.html('consoleCertificateDialog.thOid') + '</th><th>' +
        t.html('consoleCertificateDialog.thValue') + '</th></tr>' +
        '</thead><tbody>' + tbs.extensions.map(function (one) {
          return '<tr><td>' + esc(one.label) +
            (one.name ? '<br><code>' + esc(one.name) + '</code>' : '') +
            (one.critical ? '<span class="certdlg-crit">' +
              t.html('consoleCertificateDialog.critical') + '</span>' : '') +
            '</td><td><code>' + esc(one.oid) + '</code></td><td>' +
            self.valueHtml(one.value, one.text, t) +
            (one.parseError ? '<br><span class="certdlg-bad">Could not be ' +
              'decoded: ' + esc(one.parseError) + '</span>' : '') +
            '</td></tr>';
        }).join('') + '</tbody></table>'
      : '<p class="certdlg-na">' +
        t.html('consoleCertificateDialog.noExtensions') +
        '</p>';
    const absent = '<span class="certdlg-na">' +
      t.html('consoleCertificateDialog.absent') + '</span>';
    const html =
      '<table><tbody>' +
      self.row(t.text('consoleCertificateDialog.rowVersion'),
               'v' + esc(tbs.version.value) + ' <span ' +
               'class="certdlg-na">' +
               t.html('consoleCertificateDialog.encodedAs',
                      { value: tbs.version.encoded }) + '</span>') +
      self.row(t.text('consoleCertificateDialog.rowSerial'),
               '<code>' + esc(tbs.serialNumber.hex) +
               '</code>' +
               '<br><span class="certdlg-na">' +
               t.html('consoleCertificateDialog.serialDecimal',
                      { decimal: tbs.serialNumber.decimal,
                        n: tbs.serialNumber.octets }) + '</span>') +
      self.row(t.text('consoleCertificateDialog.rowSignatureInside'),
               self.algorithmHtml(tbs.signature, t)) +
      self.row(t.text('consoleCertificateDialog.rowIssuer'),
               self.nameTable(tbs.issuer, t)) +
      self.row(t.text('consoleCertificateDialog.rowNotBefore'),
               esc(tbs.validity.notBefore.iso) +
               ' <span class="certdlg-na">(' +
               esc(tbs.validity.notBefore.type) + ')</span>') +
      self.row(t.text('consoleCertificateDialog.rowNotAfter'),
               esc(tbs.validity.notAfter.iso) +
               ' <span class="certdlg-na">(' +
               esc(tbs.validity.notAfter.type) + ')</span>') +
      self.row(t.text('consoleCertificateDialog.rowSubject'),
               self.nameTable(tbs.subject, t)) +
      self.row(t.text('consoleCertificateDialog.rowKeyAlgorithm'),
               self.algorithmHtml(spki.algorithm, t)) +
      self.row(t.text('consoleCertificateDialog.rowKey'),
               esc(spki.description) +
               (keyFacts.length ? ' — ' + esc(keyFacts.join(', ')) : '') +
               '<br>' +
               self.hexHtml(t.text('consoleCertificateDialog.keyHex'),
                            spki.publicKeyHex, spki.publicKeyOctets, t)) +
      self.row(t.text('consoleCertificateDialog.rowSpki'),
               '<code>' + esc(spki.spkiSha256) + '</code>') +
      self.row(t.text('consoleCertificateDialog.rowIssuerUid'),
        tbs.issuerUniqueID
        ? '<code>' + esc(tbs.issuerUniqueID) + '</code>'
        : absent) +
      self.row(t.text('consoleCertificateDialog.rowSubjectUid'),
        tbs.subjectUniqueID
        ? '<code>' + esc(tbs.subjectUniqueID) + '</code>'
        : absent) +
      '</tbody></table>' +
      '<h4>' + t.html('consoleCertificateDialog.extensionsHeading',
                      { n: tbs.extensions.length }) + '</h4>' +
      extensions +
      '<table><tbody>' +
      self.row(t.text('consoleCertificateDialog.rowSignatureAlgorithm'),
               self.algorithmHtml(f.signatureAlgorithm, t) +
               (f.signatureAlgorithmsAgree ? ''
                 : '<br><span class="certdlg-bad">' +
                   t.html('consoleCertificateDialog.algorithmsDisagree') +
                   '</span>')) +
      self.row(t.text('consoleCertificateDialog.rowSignatureValue'),
               self.hexHtml(t.text('consoleCertificateDialog.signatureHex'),
                            f.signatureValue.hex,
                            f.signatureValue.octets, t)) +
      self.row(t.text('consoleCertificateDialog.rowSha256'), '<code>' +
               esc(described.fingerprints.sha256) + '</code>') +
      self.row(t.text('consoleCertificateDialog.rowSha1'), '<code>' +
               esc(described.fingerprints.sha1) + '</code>') +
      '</tbody></table>' +
      '<details><summary>PEM</summary><pre>' + esc(described.pem) +
      '</pre></details>';
    return html;
  }

  static chainHtml(view: Json, pagePath: string,
                    from: string, t: Json): string {
    const self = this;
    const rows = view.chain.map(function (one) {
      const c = one.certificate;
      const validity = c.summary.expired
        ? '<span class="certdlg-bad">' +
          t.html('consoleCertificateDialog.expiredOn',
                 { date: c.summary.notAfter.slice(0, 10) }) + '</span>'
        : (c.summary.notYetValid
          ? '<span class="certdlg-bad">' +
            t.html('consoleCertificateDialog.notValidUntil',
                   { date: c.summary.notBefore.slice(0, 10) }) + '</span>'
          : '<span class="certdlg-ok">' +
            t.html('consoleCertificateDialog.validUntil',
                   { date: c.summary.notAfter.slice(0, 10) }) + '</span>');
      return '<tr><td>' + esc(one.position) + '</td><td><strong>' +
        esc(one.role) + '</strong>' +
        (one.anchor ? '<br><span class="certdlg-ok">' + esc(one.anchor) +
          '</span>' : '') + '</td><td><code>' + esc(one.subject) +
        '</code><br><span class="certdlg-na">' +
        t.html('consoleCertificateDialog.issuedBy') + '</span> <code>' +
        esc(one.issuer) + '</code></td><td>' +
        self.verdict(one.signatureValid,
                     t.text('consoleCertificateDialog.verifies'),
                     t.text('consoleCertificateDialog.doesNotVerify'),
                     t.text('consoleCertificateDialog.issuerNotHeld'), t) +
        (one.signedBy && one.signatureValid !== null
          ? '<br><span class="certdlg-na">' +
            (one.signedBy === one.subject
              ? t.html('consoleCertificateDialog.againstOwnKey')
              : t.html('consoleCertificateDialog.againstNextKey')) +
            '</span>' : '') + '</td><td>' +
        self.verdict(one.issuerMayCertify, 'keyCertSign',
                     t.text('consoleCertificateDialog.noKeyCertSign'),
                     undefined, t) +
        '</td><td>' + validity + '</td></tr>' +
        (one.position > 0
          ? '<tr><td></td><td colspan="5"><details><summary>' +
            (one.role === 'trust anchor'
              ? t.html('consoleCertificateDialog.everyFieldAnchor')
              : t.html('consoleCertificateDialog.everyFieldThis')) +
            '</summary>' + self.fieldsHtml(c, t) + '<p>' +
            self.link(pagePath, one.fingerprint, from,
                      t.text('consoleCertificateDialog.openOnItsOwn'), t) +
            '</p></details></td></tr>'
          : '');
    }).join('');
    const status = view.chainStatus;
    // The anchor's name and the chain's reason are the view's, drawn as
    // they come.
    const summary = view.chainTrusted
      ? '<span class="certdlg-ok">' +
        t.html('consoleCertificateDialog.trusted') + '</span> ' +
        t.html('consoleCertificateDialog.trustedWhy') +
        esc(view.chain[view.chain.length - 1].anchor) + '.'
      : '<span class="certdlg-bad">' +
        t.html('consoleCertificateDialog.notTrusted') + '</span> ' +
        esc(CHAIN_STATUS(t)[status] || status) +
        (view.chainReason ? ' ' + esc(view.chainReason) : '') +
        (status === 'complete' && !view.chain[view.chain.length - 1].anchor
          ? t.html('consoleCertificateDialog.notAnAnchor') : '');
    return '<p>' + summary + '</p><p class="certdlg-na">' +
      t.html('consoleCertificateDialog.builtFrom') + '</p>' +
      '<table><thead><tr><th>#</th><th>' +
      t.html('consoleCertificateDialog.thRole') + '</th><th>' +
      t.html('consoleCertificateDialog.thSubjectIssuer') + '</th>' +
      '<th>' + t.html('consoleCertificateDialog.thSignature') + '</th><th>' +
      t.html('consoleCertificateDialog.thMayCertify') + '</th><th>' +
      t.html('consoleCertificateDialog.thValidity') + '</th></tr>' +
      '</thead><tbody>' + rows + '</tbody></table>';
  }

  // ---------------------------------------------------------------------------
  // THE DIALOG. `view` is `certificate_views.detailsView()`'s answer, a
  // refusal included: an open that cannot be answered still opens, and says
  // why, because a link that did nothing would read as a broken control.
  // ---------------------------------------------------------------------------
  /**
   * Draws the dialog over a page, with its style: the certificate's fields and
   * its chain, or, for a refusal, why it cannot be opened.
   *
   * @param pagePath - the page the dialog is drawn over, which the close
   * controls return to
   * @param view - `certificate_views.detailsView()`'s answer
   * @param from - the id of the section to return to
   * @param t - the page's translator (#539); the default when absent
   * @returns the dialog's HTML
   */
  static dialog(pagePath: string, view: Json, from?: Json, t?: Json): string {
    const self = this;
    t = t || webMessages.WebTranslator.fallback();
    const back = self.fromOf(from);
    const closeHref = esc(pagePath) + (back ? '#' + esc(back) : '');
    const ok = view && view.ok;
    // A certificate that cannot be opened is a refusal, and its title and
    // its reason stay English, as every refusal does (#539).
    const title = ok ? t.text('consoleCertificateDialog.title')
                     : 'Certificate not available';
    const sub = ok ? view.certificate.summary.subject : '';
    let body;
    if (!ok) {
      body = '<p class="certdlg-bad">' + esc(((view && view.errors) ||
        ['The certificate could not be opened.'])[0]) + '</p>';
    } else {
      const s = view.certificate.summary;
      body =
        '<table><tbody>' +
        self.row(t.text('consoleCertificateDialog.rowSubject'),
                 '<code>' + esc(s.subject) + '</code>') +
        self.row(t.text('consoleCertificateDialog.rowIssuer'),
                 '<code>' + esc(s.issuer) + '</code>' +
                 (s.selfIssued
                   ? ' <span class="certdlg-na">' +
                     t.html('consoleCertificateDialog.selfIssued') + '</span>'
                   : '')) +
        self.row(t.text('consoleCertificateDialog.rowValidity'),
                 esc(s.notBefore) + ' → ' + esc(s.notAfter) +
                 ' — ' +
                 (s.expired ? '<span class="certdlg-bad">' +
                   t.html('consoleCertificateDialog.expired') + '</span>'
                   : (s.notYetValid ? '<span class="certdlg-bad">' +
                      t.html('consoleCertificateDialog.notYetValid') +
                      '</span>' : '<span class="certdlg-ok">' +
                      t.html('consoleCertificateDialog.validDaysLeft',
                             { n: s.daysRemaining }) + '</span>'))) +
        self.row(t.text('consoleCertificateDialog.rowKeyShort'),
                 esc(s.publicKey) +
                 PqcBadgeView.badge(view.pqc, t)) +
        self.row(t.text('consoleCertificateDialog.rowSignatureAlgorithm'),
                 esc(s.signatureAlgorithm)) +
        self.row(t.text('consoleCertificateDialog.rowCa'),
                 s.ca ? t.html('consoleCertificateDialog.caYes')
                      : t.html('consoleCertificateDialog.caNo')) +
        self.row(t.text('consoleCertificateDialog.rowSha256'), '<code>' +
                 esc(view.certificate.fingerprints.sha256) + '</code>') +
        self.row(t.text('consoleCertificateDialog.rowHeldAs'), '<ul>' +
                 view.appearances.map(function (one) {
                   return '<li>' + esc(one.label) + '</li>';
                 }).join('') + '</ul>') +
        self.row(t.text('consoleCertificateDialog.rowRealm'),
                 '<code>' + esc(view.realm) + '</code>') +
        '</tbody></table>' +
        '<h3>' + t.html('consoleCertificateDialog.trustChain') + '</h3>' +
        self.chainHtml(view, pagePath, back, t) +
        '<h3>' + t.html('consoleCertificateDialog.everyField') + '</h3>' +
        self.fieldsHtml(view.certificate, t);
    }
    return STYLE +
      '<div class="certdlg-backdrop" id="certificate-details">' +
      '<div class="certdlg" role="dialog" aria-modal="true" ' +
      'aria-labelledby="certdlg-title">' +
      '<div class="certdlg-head"><h2 id="certdlg-title">' + esc(title) +
      (sub ? '<span class="sub"><code>' + esc(sub) + '</code></span>' : '') +
      '</h2><a class="certdlg-x" href="' + closeHref + '" aria-label="' +
      esc(t.text('consoleCertificateDialog.closeLabel')) + '" title="' +
      esc(t.text('consoleCertificateDialog.close')) +
      '">&times;</a></div>' +
      '<div class="certdlg-body">' + body + '</div>' +
      '<div class="certdlg-foot"><form method="get" action="' + closeHref +
      '"><button type="submit" autofocus>' +
      t.html('consoleCertificateDialog.close') + '</button></form></div>' +
      '</div></div>';
  }
}

export = CertificateDialogView;
