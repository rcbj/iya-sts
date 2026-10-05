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

const CHAIN_STATUS = {
  complete: 'The path ends at a certificate that signed itself.',
  incomplete: 'The path stops before a self-signed certificate.',
  unverified: 'The path stops at an issuer whose key does not verify the ' +
              'signature below it.',
  'too-deep': 'The path did not end.'
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
   * @returns the link's HTML, or an empty string without a usable fingerprint
   */
  static link(pagePath: string, fingerprint: Json, from?: Json,
       text?: string): string {
    const self = this;
    const fp = String(fingerprint || '').toLowerCase()
      .replace(/[^0-9a-f]/g, '');
    if (fp.length !== 64) {
      return '';
    }
    const back = self.fromOf(from);
    return '<a class="certdlg-open" href="' + esc(pagePath) + '?' + PARAM +
      '=' + fp + (back ? '&amp;' + FROM + '=' + esc(back) : '') + '" ' +
      'title="Every X.509 field of this certificate and the chain it builds, ' +
      'in a dialog over this page">' + esc(text || 'View details') + '</a>';
  }

  static verdict(value: Json, yes: string, no: string,
                  unknown?: string): string {
    if (value === true) {
      return '<span class="certdlg-ok">' + esc(yes) + '</span>';
    }
    if (value === false) {
      return '<span class="certdlg-bad">' + esc(no) + '</span>';
    }
    return '<span class="certdlg-na">' + esc(unknown || 'not applicable') +
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
  static valueHtml(value: Json, text: Json): string {
    if (Array.isArray(value)) {
      return value.length
        ? '<ul>' + value.map(function (one) {
            return '<li><code>' + esc(typeof one === 'object'
              ? JSON.stringify(one) : String(one)) + '</code></li>';
          }).join('') + '</ul>'
        : '<span class="certdlg-na">(empty)</span>';
    }
    if (value && typeof value === 'object') {
      return '<ul>' + Object.keys(value).map(function (key) {
        const member = value[key];
        return '<li>' + esc(key) + ': <code>' + esc(member === null
          ? '(absent)' : (typeof member === 'object'
            ? JSON.stringify(member) : String(member))) + '</code></li>';
      }).join('') + '</ul>';
    }
    return '<code>' + esc(text) + '</code>';
  }

  static nameTable(name: Json): string {
    const rows = (name.attributes || []).map(function (one) {
      return '<tr><td>' + esc(one.label) +
        (one.short ? ' (<code>' + esc(one.short) + '</code>)' : '') +
        '</td><td><code>' + esc(one.oid) + '</code></td><td><code>' +
        esc(one.value) + '</code></td></tr>';
    }).join('');
    return '<code>' + esc(name.text) + '</code>' +
      (rows ? '<table><thead><tr><th>Attribute</th><th>OID</th><th>Value</th>' +
              '</tr></thead><tbody>' + rows + '</tbody></table>' : '');
  }

  static algorithmHtml(alg: Json): string {
    return (alg.name ? esc(alg.name) + ' ' : '') + '<code>' + esc(alg.oid) +
      '</code>' + (alg.parameters && alg.parameters !== 'absent'
        ? ' — parameters <code>' + esc(alg.parameters) + '</code>'
        : ' — parameters absent');
  }

  // A long run of hex, shown whole behind a disclosure. Everything in a
  // certificate is public, and a details view that truncated the key or the
  // signature would be the one place a reader could not check a byte.
  static hexHtml(label: string, hex: Json, octets: Json): string {
    return esc(octets) + ' octets <details><summary>' + esc(label) +
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
   * @returns the fields as HTML
   */
  static fieldsHtml(described: Json): string {
    const self = this;
    const f = described.fields;
    const tbs = f.tbsCertificate;
    const spki = tbs.subjectPublicKeyInfo;
    const key = spki.key || {};
    const keyFacts = [];
    if (key.modulusBits) {
      keyFacts.push('modulus ' + key.modulusBits + ' bits');
    }
    if (key.publicExponent) {
      keyFacts.push('exponent ' + key.publicExponent);
    }
    if (key.namedCurve) {
      keyFacts.push('curve ' + key.namedCurve);
    }
    const extensions = tbs.extensions.length
      ? '<table><thead><tr><th>Extension</th><th>OID</th><th>Value</th></tr>' +
        '</thead><tbody>' + tbs.extensions.map(function (one) {
          return '<tr><td>' + esc(one.label) +
            (one.name ? '<br><code>' + esc(one.name) + '</code>' : '') +
            (one.critical ? '<span class="certdlg-crit">critical</span>' : '') +
            '</td><td><code>' + esc(one.oid) + '</code></td><td>' +
            self.valueHtml(one.value, one.text) +
            (one.parseError ? '<br><span class="certdlg-bad">Could not be ' +
              'decoded: ' + esc(one.parseError) + '</span>' : '') +
            '</td></tr>';
        }).join('') + '</tbody></table>'
      : '<p class="certdlg-na">No extensions — a version 1 or 2 certificate, ' +
        'or a version 3 one that carries none.</p>';
    const html =
      '<table><tbody>' +
      self.row('Version', 'v' + esc(tbs.version.value) + ' <span ' +
               'class="certdlg-na">(encoded as ' + esc(tbs.version.encoded) +
               ')</span>') +
      self.row('Serial number', '<code>' + esc(tbs.serialNumber.hex) +
               '</code>' +
               '<br><span class="certdlg-na">decimal ' +
               esc(tbs.serialNumber.decimal) + ', ' +
               esc(tbs.serialNumber.octets) + ' octets</span>') +
      self.row('Signature (inside tbsCertificate)',
               self.algorithmHtml(tbs.signature)) +
      self.row('Issuer', self.nameTable(tbs.issuer)) +
      self.row('Validity: not before', esc(tbs.validity.notBefore.iso) +
               ' <span class="certdlg-na">(' +
               esc(tbs.validity.notBefore.type) + ')</span>') +
      self.row('Validity: not after', esc(tbs.validity.notAfter.iso) +
               ' <span class="certdlg-na">(' +
               esc(tbs.validity.notAfter.type) + ')</span>') +
      self.row('Subject', self.nameTable(tbs.subject)) +
      self.row('Subject public key algorithm',
               self.algorithmHtml(spki.algorithm)) +
      self.row('Subject public key', esc(spki.description) +
               (keyFacts.length ? ' — ' + esc(keyFacts.join(', ')) : '') +
               '<br>' +
               self.hexHtml('The subjectPublicKey bits, in hex',
                            spki.publicKeyHex, spki.publicKeyOctets)) +
      self.row('SubjectPublicKeyInfo SHA-256 (base64)',
               '<code>' + esc(spki.spkiSha256) + '</code>') +
      self.row('Issuer unique ID', tbs.issuerUniqueID
        ? '<code>' + esc(tbs.issuerUniqueID) + '</code>'
        : '<span class="certdlg-na">absent</span>') +
      self.row('Subject unique ID', tbs.subjectUniqueID
        ? '<code>' + esc(tbs.subjectUniqueID) + '</code>'
        : '<span class="certdlg-na">absent</span>') +
      '</tbody></table>' +
      '<h4>X.509 v3 extensions (' + esc(tbs.extensions.length) + ')</h4>' +
      extensions +
      '<table><tbody>' +
      self.row('Signature algorithm',
               self.algorithmHtml(f.signatureAlgorithm) +
               (f.signatureAlgorithmsAgree ? ''
                 : '<br><span class="certdlg-bad">Does NOT match the ' +
                   'signature ' +
                   'algorithm inside tbsCertificate, which RFC 5280 section ' +
                   '4.1.1.2 requires</span>')) +
      self.row('Signature value', self.hexHtml('The signature, in hex',
                                               f.signatureValue.hex,
                                               f.signatureValue.octets)) +
      self.row('SHA-256 fingerprint', '<code>' +
               esc(described.fingerprints.sha256) + '</code>') +
      self.row('SHA-1 fingerprint', '<code>' +
               esc(described.fingerprints.sha1) + '</code>') +
      '</tbody></table>' +
      '<details><summary>PEM</summary><pre>' + esc(described.pem) +
      '</pre></details>';
    return html;
  }

  static chainHtml(view: Json, pagePath: string,
                    from: string): string {
    const self = this;
    const rows = view.chain.map(function (one) {
      const c = one.certificate;
      const validity = c.summary.expired
        ? '<span class="certdlg-bad">expired ' +
          esc(c.summary.notAfter.slice(0, 10)) + '</span>'
        : (c.summary.notYetValid
          ? '<span class="certdlg-bad">not valid until ' +
            esc(c.summary.notBefore.slice(0, 10)) + '</span>'
          : '<span class="certdlg-ok">valid until ' +
            esc(c.summary.notAfter.slice(0, 10)) + '</span>');
      return '<tr><td>' + esc(one.position) + '</td><td><strong>' +
        esc(one.role) + '</strong>' +
        (one.anchor ? '<br><span class="certdlg-ok">' + esc(one.anchor) +
          '</span>' : '') + '</td><td><code>' + esc(one.subject) +
        '</code><br><span class="certdlg-na">issued by</span> <code>' +
        esc(one.issuer) + '</code></td><td>' +
        self.verdict(one.signatureValid, 'verifies', 'does NOT verify',
                     'issuer not held here') +
        (one.signedBy && one.signatureValid !== null
          ? '<br><span class="certdlg-na">against ' +
            (one.signedBy === one.subject ? 'its own key' : 'the next key') +
            '</span>' : '') + '</td><td>' +
        self.verdict(one.issuerMayCertify, 'keyCertSign', 'no keyCertSign') +
        '</td><td>' + validity + '</td></tr>' +
        (one.position > 0
          ? '<tr><td></td><td colspan="5"><details><summary>Every field of ' +
            esc(one.role === 'trust anchor' ? 'the trust anchor'
                                            : 'this certificate') +
            '</summary>' + self.fieldsHtml(c) + '<p>' +
            self.link(pagePath, one.fingerprint, from,
                      'Open this certificate on its own') +
            '</p></details></td></tr>'
          : '');
    }).join('');
    const status = view.chainStatus;
    const summary = view.chainTrusted
      ? '<span class="certdlg-ok">Trusted:</span> every signature on the ' +
        'path verifies, every certificate is in date, every issuer may sign ' +
        'certificates, and the path ends at ' +
        esc(view.chain[view.chain.length - 1].anchor) + '.'
      : '<span class="certdlg-bad">Not a trusted path:</span> ' +
        esc(CHAIN_STATUS[status] || status) +
        (view.chainReason ? ' ' + esc(view.chainReason) : '') +
        (status === 'complete' && !view.chain[view.chain.length - 1].anchor
          ? ' The certificate it ends at is not a trust anchor this service ' +
            'publishes.' : '');
    return '<p>' + summary + '</p><p class="certdlg-na">Built from the ' +
      'certificates this service holds, matching each issuer by name AND ' +
      'verifying its signature — not read from a stored chain, which is a ' +
      'snapshot and goes stale when an authority is replaced.</p>' +
      '<table><thead><tr><th>#</th><th>Role</th><th>Subject / issuer</th>' +
      '<th>Signature</th><th>Issuer may certify</th><th>Validity</th></tr>' +
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
   * @returns the dialog's HTML
   */
  static dialog(pagePath: string, view: Json, from?: Json): string {
    const self = this;
    const back = self.fromOf(from);
    const closeHref = esc(pagePath) + (back ? '#' + esc(back) : '');
    const ok = view && view.ok;
    const title = ok ? 'Certificate details' : 'Certificate not available';
    const sub = ok ? view.certificate.summary.subject : '';
    let body;
    if (!ok) {
      body = '<p class="certdlg-bad">' + esc(((view && view.errors) ||
        ['The certificate could not be opened.'])[0]) + '</p>';
    } else {
      const s = view.certificate.summary;
      body =
        '<table><tbody>' +
        self.row('Subject', '<code>' + esc(s.subject) + '</code>') +
        self.row('Issuer', '<code>' + esc(s.issuer) + '</code>' +
                 (s.selfIssued
                   ? ' <span class="certdlg-na">(self-issued)</span>'
                   : '')) +
        self.row('Validity', esc(s.notBefore) + ' → ' + esc(s.notAfter) +
                 ' — ' +
                 (s.expired ? '<span class="certdlg-bad">expired</span>'
                   : (s.notYetValid ? '<span class="certdlg-bad">not yet ' +
                      'valid</span>' : '<span class="certdlg-ok">valid, ' +
                      esc(s.daysRemaining) + ' day(s) left</span>'))) +
        self.row('Key', esc(s.publicKey) +
                 PqcBadgeView.badge(view.pqc)) +
        self.row('Signature algorithm', esc(s.signatureAlgorithm)) +
        self.row('Certificate authority', s.ca ? 'yes (basicConstraints cA)'
                                               : 'no') +
        self.row('SHA-256 fingerprint', '<code>' +
                 esc(view.certificate.fingerprints.sha256) + '</code>') +
        self.row('Held by this service as', '<ul>' +
                 view.appearances.map(function (one) {
                   return '<li>' + esc(one.label) + '</li>';
                 }).join('') + '</ul>') +
        self.row('Trust realm', '<code>' + esc(view.realm) + '</code>') +
        '</tbody></table>' +
        '<h3>Trust chain</h3>' + self.chainHtml(view, pagePath, back) +
        '<h3>Every X.509 field</h3>' + self.fieldsHtml(view.certificate);
    }
    return STYLE +
      '<div class="certdlg-backdrop" id="certificate-details">' +
      '<div class="certdlg" role="dialog" aria-modal="true" ' +
      'aria-labelledby="certdlg-title">' +
      '<div class="certdlg-head"><h2 id="certdlg-title">' + esc(title) +
      (sub ? '<span class="sub"><code>' + esc(sub) + '</code></span>' : '') +
      '</h2><a class="certdlg-x" href="' + closeHref + '" aria-label="Close ' +
      'the certificate details" title="Close">&times;</a></div>' +
      '<div class="certdlg-body">' + body + '</div>' +
      '<div class="certdlg-foot"><form method="get" action="' + closeHref +
      '"><button type="submit" autofocus>Close</button></form></div>' +
      '</div></div>';
  }
}

export = CertificateDialogView;
