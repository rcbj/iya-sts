'use strict';
//
// File: certificate_dialog.js
//
// ===========================================================================
// THE CERTIFICATE DETAILS POPUP, DRAWN BY THE SERVER, AND THE ONE RENDERER
// BOTH PAGES USE (2026-09-13).
//
// `/admin/pki` and `/admin/crypto-metadata` open a certificate's details in a
// dialog over the page, in the same tab, with an X at the top and a Close
// button at the foot. This file draws that dialog and the link that opens it,
// and nothing else draws either: the model is
// `common/certificate_details.js`'s and which certificates may be opened is
// `admin-core/certificate_views.js`'s, so a certificate described on one page
// is described on the other by the same function in the same words.
//
// ---------------------------------------------------------------------------
// A POPUP WITH NO SCRIPT, AND WHY THAT IS NOT A CONSTRAINT WORKED AROUND.
//
// Both pages are `script-src 'none'`, like every page of this console but the
// API explorer, and the root CLAUDE.md's rule for a scripted page is that it
// CANNOT work without one. This one can. Opening a certificate is a link that
// adds `?certificate=<SHA-256>` to the page it is on; the server draws the page
// with the dialog over it; the X and the Close button go back to the same page
// without the parameter. So:
//
//   * **it stays in the tab** — every control is a same-document navigation,
//     and there is no `target` anywhere in this file for a reason;
//   * **the URL IS the open dialog** — it can be bookmarked, sent to somebody,
//     reloaded, and the Back button closes it, which a script-opened dialog
//     does none of;
//   * **only the certificate asked for is described.** The alternative with
//     no script — every dialog rendered hidden and shown by CSS `:target` —
//     would parse and describe every certificate on the page on every render,
//     and `/admin/pki` holds dozens.
//
// What it costs is a round trip per open, which is the cost every other control
// in this console already pays, and it is said here rather than discovered.
//
// **THE CLOSE BUTTON IS A REAL `<button>` IN A GET FORM**, not a link dressed
// as one, because a person asked for a button and a button is what a keyboard
// and a screen reader announce as one. The X is a link, labelled for a screen
// reader, because a close glyph in a corner is a link in every design system
// that has one. Both go to the same address.
//
// **WHERE THE READER WAS IS KEPT.** A link that opens a dialog carries a `from`
// naming the page section it was pressed in, and closing returns to that
// fragment, so closing a certificate forty rows down a tree does not land at
// the top of the page. `from` is an element id and is refused unless it looks
// like one: it is written into an `href`.
//
// A LIBRARY: it registers no route. It requires `admin-ui/admin.js` for the
// escaper and the certificate details model's label function, and nothing
// requires it but the two pages.
// ===========================================================================

const bunyan = require('bunyan');
const config = require('../common/config');

const log = bunyan.createLogger({
  name: 'certificate_dialog',
  level: config.value('global.logLevel')
});

const admin = require('./admin');
const esc = admin.esc;
// The post-quantum icon beside the key, the same one the two pages draw.
const pqcBadge = require('./pqc_badge');

// The query parameters this dialog owns, named once.
const PARAM = 'certificate';
const FROM = 'from';

function fromOf(value) {
  log.debug("Entering fromOf().");
  const text = String(value || '');
  log.debug("Leaving fromOf().");
  return /^[A-Za-z][A-Za-z0-9_-]{0,63}$/.test(text) ? text : '';
}

// Is a dialog being asked for on this request?
function requested(req) {
  log.debug("Entering requested().");
  log.debug("Leaving requested().");
  return !!(req && req.query &&
            String(req.query[PARAM] || '').trim());
}

// ---------------------------------------------------------------------------
// THE LINK THAT OPENS ONE. `pagePath` is the page it is drawn on, so the dialog
// opens over that page; `from` is the id of the section the link sits in.
// ---------------------------------------------------------------------------
function link(pagePath, fingerprint, from, text) {
  log.debug("Entering link().");
  const fp = String(fingerprint || '').toLowerCase().replace(/[^0-9a-f]/g, '');
  if (fp.length !== 64) {
    log.debug("Leaving link(). No fingerprint to open.");
    return '';
  }
  const back = fromOf(from);
  log.debug("Leaving link().");
  return '<a class="certdlg-open" href="' + esc(pagePath) + '?' + PARAM +
    '=' + fp + (back ? '&amp;' + FROM + '=' + esc(back) : '') + '" ' +
    'title="Every X.509 field of this certificate and the chain it builds, ' +
    'in a dialog over this page">' + esc(text || 'View details') + '</a>';
}

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

function verdict(value, yes, no, unknown) {
  log.debug("Entering verdict().");
  log.debug("Leaving verdict().");
  if (value === true) {
    return '<span class="certdlg-ok">' + esc(yes) + '</span>';
  }
  if (value === false) {
    return '<span class="certdlg-bad">' + esc(no) + '</span>';
  }
  return '<span class="certdlg-na">' + esc(unknown || 'not applicable') +
         '</span>';
}

function row(label, html) {
  log.debug("Entering row().");
  log.debug("Leaving row().");
  return '<tr><th scope="row">' + esc(label) + '</th><td>' + html +
         '</td></tr>';
}

// An extension's decoded value, as whatever shape it came in. A list is a
// list, an object is its members, and anything else is text — the vendored
// `extensionValueText()` is the fallback, so no shape can print as
// "[object Object]".
function valueHtml(value, text) {
  log.debug("Entering valueHtml().");
  if (Array.isArray(value)) {
    log.debug("Leaving valueHtml(). A list.");
    return value.length
      ? '<ul>' + value.map(function (one) {
          return '<li><code>' + esc(typeof one === 'object'
            ? JSON.stringify(one) : String(one)) + '</code></li>';
        }).join('') + '</ul>'
      : '<span class="certdlg-na">(empty)</span>';
  }
  if (value && typeof value === 'object') {
    log.debug("Leaving valueHtml(). An object.");
    return '<ul>' + Object.keys(value).map(function (key) {
      const member = value[key];
      return '<li>' + esc(key) + ': <code>' + esc(member === null
        ? '(absent)' : (typeof member === 'object'
          ? JSON.stringify(member) : String(member))) + '</code></li>';
    }).join('') + '</ul>';
  }
  log.debug("Leaving valueHtml(). Text.");
  return '<code>' + esc(text) + '</code>';
}

function nameTable(name) {
  log.debug("Entering nameTable().");
  const rows = (name.attributes || []).map(function (one) {
    return '<tr><td>' + esc(one.label) +
      (one.short ? ' (<code>' + esc(one.short) + '</code>)' : '') +
      '</td><td><code>' + esc(one.oid) + '</code></td><td><code>' +
      esc(one.value) + '</code></td></tr>';
  }).join('');
  log.debug("Leaving nameTable().");
  return '<code>' + esc(name.text) + '</code>' +
    (rows ? '<table><thead><tr><th>Attribute</th><th>OID</th><th>Value</th>' +
            '</tr></thead><tbody>' + rows + '</tbody></table>' : '');
}

function algorithmHtml(alg) {
  log.debug("Entering algorithmHtml().");
  log.debug("Leaving algorithmHtml().");
  return (alg.name ? esc(alg.name) + ' ' : '') + '<code>' + esc(alg.oid) +
    '</code>' + (alg.parameters && alg.parameters !== 'absent'
      ? ' — parameters <code>' + esc(alg.parameters) + '</code>'
      : ' — parameters absent');
}

// A long run of hex, shown whole behind a disclosure. Everything in a
// certificate is public, and a details view that truncated the key or the
// signature would be the one place a reader could not check a byte.
function hexHtml(label, hex, octets) {
  log.debug("Entering hexHtml().");
  log.debug("Leaving hexHtml().");
  return esc(octets) + ' octets <details><summary>' + esc(label) +
    '</summary><div class="certdlg-hex">' + esc(hex) + '</div></details>';
}

// ---------------------------------------------------------------------------
// EVERY FIELD, IN THE ORDER RFC 5280 SECTION 4.1 WRITES THEM. One function for
// the certificate the dialog was opened on and for every certificate in its
// chain, so a chain member is never described with fewer fields than a leaf.
// ---------------------------------------------------------------------------
function fieldsHtml(described) {
  log.debug("Entering fieldsHtml().");
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
          valueHtml(one.value, one.text) +
          (one.parseError ? '<br><span class="certdlg-bad">Could not be ' +
            'decoded: ' + esc(one.parseError) + '</span>' : '') +
          '</td></tr>';
      }).join('') + '</tbody></table>'
    : '<p class="certdlg-na">No extensions — a version 1 or 2 certificate, ' +
      'or a version 3 one that carries none.</p>';
  const html =
    '<table><tbody>' +
    row('Version', 'v' + esc(tbs.version.value) + ' <span ' +
        'class="certdlg-na">(encoded as ' + esc(tbs.version.encoded) +
        ')</span>') +
    row('Serial number', '<code>' + esc(tbs.serialNumber.hex) + '</code>' +
        '<br><span class="certdlg-na">decimal ' +
        esc(tbs.serialNumber.decimal) + ', ' + esc(tbs.serialNumber.octets) +
        ' octets</span>') +
    row('Signature (inside tbsCertificate)', algorithmHtml(tbs.signature)) +
    row('Issuer', nameTable(tbs.issuer)) +
    row('Validity: not before', esc(tbs.validity.notBefore.iso) +
        ' <span class="certdlg-na">(' + esc(tbs.validity.notBefore.type) +
        ')</span>') +
    row('Validity: not after', esc(tbs.validity.notAfter.iso) +
        ' <span class="certdlg-na">(' + esc(tbs.validity.notAfter.type) +
        ')</span>') +
    row('Subject', nameTable(tbs.subject)) +
    row('Subject public key algorithm', algorithmHtml(spki.algorithm)) +
    row('Subject public key', esc(spki.description) +
        (keyFacts.length ? ' — ' + esc(keyFacts.join(', ')) : '') + '<br>' +
        hexHtml('The subjectPublicKey bits, in hex', spki.publicKeyHex,
                spki.publicKeyOctets)) +
    row('SubjectPublicKeyInfo SHA-256 (base64)',
        '<code>' + esc(spki.spkiSha256) + '</code>') +
    row('Issuer unique ID', tbs.issuerUniqueID
      ? '<code>' + esc(tbs.issuerUniqueID) + '</code>'
      : '<span class="certdlg-na">absent</span>') +
    row('Subject unique ID', tbs.subjectUniqueID
      ? '<code>' + esc(tbs.subjectUniqueID) + '</code>'
      : '<span class="certdlg-na">absent</span>') +
    '</tbody></table>' +
    '<h4>X.509 v3 extensions (' + esc(tbs.extensions.length) + ')</h4>' +
    extensions +
    '<table><tbody>' +
    row('Signature algorithm', algorithmHtml(f.signatureAlgorithm) +
        (f.signatureAlgorithmsAgree ? ''
          : '<br><span class="certdlg-bad">Does NOT match the signature ' +
            'algorithm inside tbsCertificate, which RFC 5280 section ' +
            '4.1.1.2 requires</span>')) +
    row('Signature value', hexHtml('The signature, in hex',
                                   f.signatureValue.hex,
                                   f.signatureValue.octets)) +
    row('SHA-256 fingerprint', '<code>' +
        esc(described.fingerprints.sha256) + '</code>') +
    row('SHA-1 fingerprint', '<code>' + esc(described.fingerprints.sha1) +
        '</code>') +
    '</tbody></table>' +
    '<details><summary>PEM</summary><pre>' + esc(described.pem) +
    '</pre></details>';
  log.debug("Leaving fieldsHtml().");
  return html;
}

const CHAIN_STATUS = {
  complete: 'The path ends at a certificate that signed itself.',
  incomplete: 'The path stops before a self-signed certificate.',
  unverified: 'The path stops at an issuer whose key does not verify the ' +
              'signature below it.',
  'too-deep': 'The path did not end.'
};

function chainHtml(view, pagePath, from) {
  log.debug("Entering chainHtml().");
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
      verdict(one.signatureValid, 'verifies', 'does NOT verify',
              'issuer not held here') +
      (one.signedBy && one.signatureValid !== null
        ? '<br><span class="certdlg-na">against ' +
          (one.signedBy === one.subject ? 'its own key' : 'the next key') +
          '</span>' : '') + '</td><td>' +
      verdict(one.issuerMayCertify, 'keyCertSign', 'no keyCertSign') +
      '</td><td>' + validity + '</td></tr>' +
      (one.position > 0
        ? '<tr><td></td><td colspan="5"><details><summary>Every field of ' +
          esc(one.role === 'trust anchor' ? 'the trust anchor'
                                          : 'this certificate') +
          '</summary>' + fieldsHtml(c) + '<p>' +
          link(pagePath, one.fingerprint, from,
               'Open this certificate on its own') + '</p></details></td></tr>'
        : '');
  }).join('');
  const status = view.chainStatus;
  const summary = view.chainTrusted
    ? '<span class="certdlg-ok">Trusted:</span> every signature on the path ' +
      'verifies, every certificate is in date, every issuer may sign ' +
      'certificates, and the path ends at ' +
      esc(view.chain[view.chain.length - 1].anchor) + '.'
    : '<span class="certdlg-bad">Not a trusted path:</span> ' +
      esc(CHAIN_STATUS[status] || status) +
      (view.chainReason ? ' ' + esc(view.chainReason) : '') +
      (status === 'complete' && !view.chain[view.chain.length - 1].anchor
        ? ' The certificate it ends at is not a trust anchor this service ' +
          'publishes.' : '');
  log.debug("Leaving chainHtml().");
  return '<p>' + summary + '</p><p class="certdlg-na">Built from the ' +
    'certificates this service holds, matching each issuer by name AND ' +
    'verifying its signature — not read from a stored chain, which is a ' +
    'snapshot and goes stale when an authority is replaced.</p>' +
    '<table><thead><tr><th>#</th><th>Role</th><th>Subject / issuer</th>' +
    '<th>Signature</th><th>Issuer may certify</th><th>Validity</th></tr>' +
    '</thead><tbody>' + rows + '</tbody></table>';
}

// ---------------------------------------------------------------------------
// THE DIALOG. `view` is `certificate_views.detailsView()`'s answer, a refusal
// included: an open that cannot be answered still opens, and says why, because
// a link that did nothing would read as a broken control.
// ---------------------------------------------------------------------------
function dialog(pagePath, view, from) {
  log.debug("Entering dialog().");
  const back = fromOf(from);
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
      row('Subject', '<code>' + esc(s.subject) + '</code>') +
      row('Issuer', '<code>' + esc(s.issuer) + '</code>' +
          (s.selfIssued ? ' <span class="certdlg-na">(self-issued)</span>'
                        : '')) +
      row('Validity', esc(s.notBefore) + ' → ' + esc(s.notAfter) + ' — ' +
          (s.expired ? '<span class="certdlg-bad">expired</span>'
            : (s.notYetValid ? '<span class="certdlg-bad">not yet valid' +
               '</span>' : '<span class="certdlg-ok">valid, ' +
               esc(s.daysRemaining) + ' day(s) left</span>'))) +
      row('Key', esc(s.publicKey) +
          pqcBadge.badgeFor({ certificatePem: view.certificate.pem })) +
      row('Signature algorithm', esc(s.signatureAlgorithm)) +
      row('Certificate authority', s.ca ? 'yes (basicConstraints cA)'
                                         : 'no') +
      row('SHA-256 fingerprint', '<code>' +
          esc(view.certificate.fingerprints.sha256) + '</code>') +
      row('Held by this service as', '<ul>' +
          view.appearances.map(function (one) {
            return '<li>' + esc(one.label) + '</li>';
          }).join('') + '</ul>') +
      row('Trust realm', '<code>' + esc(view.realm) + '</code>') +
      '</tbody></table>' +
      '<h3>Trust chain</h3>' + chainHtml(view, pagePath, back) +
      '<h3>Every X.509 field</h3>' + fieldsHtml(view.certificate);
  }
  log.debug("Leaving dialog().");
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

module.exports = {
  PARAM: PARAM,
  FROM: FROM,
  requested: requested,
  link: link,
  dialog: dialog,
  fieldsHtml: fieldsHtml
};
