// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_crypto_metadata.ts
//
// ---------------------------------------------------------------------------
// SERVICE → CRYPTOGRAPHY, KEY PAIRS AND KEY PAIR HISTORY, DRAWN FROM THEIR
// VIEWS ALONE (#446, 2026-10-05).
//
// Draws Cryptography from the answer of `GET /admin-api/crypto`, Key pairs
// from that of `GET /admin-api/keys` and their history from that of `GET
// /admin-api/keys/history`.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// Its methods were `CryptoMetadata`'s in `admin-ui/crypto_metadata.ts`, moved
// with their comments; that module still draws the page until the console's
// cutover, by calling `render()` with its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');
import CertificateDialogView = require('./web_certificate_dialog');
import PqcBadgeView = require('./web_pqc_badge');
import SettingsForms = require('./web_settings');

type Json = any;

// The console's escaping, under the name the moved code calls it by.
const esc = kit.esc;

/**
 * Draws Cryptography from the answer of `GET /admin-api/crypto`, Key pairs
 * from that of `GET /admin-api/keys` and their history from that of `GET
 * /admin-api/keys/history`.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class CryptoMetadataPage {
  /**
   * Draws the page's body from its view.
   *
   * @param view - the answer of the page's management API operation
   * @param ctx - the render context: the page's query and whether
   *   the reader may write (`WebKit.context()`)
   * @returns the body as HTML
   */
  static render(view: Json, ctx: Json): string {
    return CryptoMetadataPage.cryptoBody(ctx, view);
  }

  // ---------------------------------------------------------------------------
  // PROSE FOR THE PAGE. The tables above are written with `backticks` around
  // identifiers, because the SAME strings are served as JSON at `?format=json`
  // and on `/admin-api/crypto`, where the convention every description in this
  // service follows is markdown — `mgmt-api/admin_api.ts`'s operation
  // descriptions are full of them.
  //
  // So the conversion belongs HERE, in the renderer, and nowhere else: the JSON
  // keeps its backticks and the page gets `<code>`. ESCAPING HAPPENS FIRST and
  // the substitution second, which is the order that matters — the content
  // between a pair of backticks has already been through `esc()` by the time
  // this looks at it, so nothing inside one can close the element it is about
  // to be put in.
  // ---------------------------------------------------------------------------
  static prose(text) {
    return esc(String(text == null ? '' : text))
      .replace(/`([^`]+)`/g, '<code>$1</code>');
  }

  // A list of algorithm names as code chips. Empty renders as an em dash rather
  // than as nothing, because an empty cell and a cell this function has not
  // reached look identical and only one of them is a fact.
  static chips(values) {
    if (!values || !values.length) {
      return '<span class="why">—</span>';
    }
    return values.map(function (one) {
      return '<code>' + esc(String(one)) + '</code>';
    }).join(' ');
  }

  // One verb's cell in the family table. An empty string means this service
  // does not do it in that family, which is a claim and is drawn as one.
  static verbCell(text, t) {
    const self = this;
    if (!text) {
      return '<span class="why">' + t.html('consoleCryptoMetadata.doesNot') +
             '</span>';
    }
    return self.prose(text);
  }

  static anchorFor(name) {
    return 'fam-' + String(name).toLowerCase().replace(/[^a-z0-9]+/g, '-')
      .replace(/^-|-$/g, '');
  }

  static renderFamilies(report, t) {
    const self = this;
    // The link is markup a message cannot carry, so the lead is cut at it.
    let html = '<h2 id="families">' +
      t.html('consoleCryptoMetadata.familiesHeading') +
      '</h2><p class="lead">' + t.html('consoleCryptoMetadata.familiesLead') +
      ' <a href="/admin/sts-metadata">' +
      t.html('consoleCryptoMetadata.serviceMetadata') + '</a>' +
      t.html('consoleCryptoMetadata.familiesLeadAfter') + '</p>';

    const drift = report.drift;
    if (!drift.checked) {
      html += kit.warn(t.html('consoleCryptoMetadata.driftUnchecked'));
    } else if (drift.undescribed.length || drift.stale.length ||
               drift.envelopes.length) {
      html += kit.warn(t.html('consoleCryptoMetadata.driftDisagree') + ' ' +
        (drift.undescribed.length
          ? t.html('consoleCryptoMetadata.driftUndescribed') + ' ' +
            self.chips(drift.undescribed) + '. '
          : '') +
        (drift.stale.length
          ? t.html('consoleCryptoMetadata.driftStale') + ' ' +
            self.chips(drift.stale) + '. '
          : '') +
        (drift.envelopes.length
          ? t.html('consoleCryptoMetadata.driftEnvelopes') + ' ' +
            self.chips(drift.envelopes) + '. '
          : '') +
        t.html('consoleCryptoMetadata.driftBoth'));
    } else {
      html += '<p class="why">' +
        t.html('consoleCryptoMetadata.driftChecked',
               { n: report.families.length }) + '</p>';
    }

    // A family's name, its verbs, its algorithm groups and what it does not
    // do are the report's, drawn as they come.
    html += '<table><thead><tr><th class="n">' +
      t.html('consoleCryptoMetadata.thService') + '</th>' +
      '<th>' + t.html('consoleCryptoMetadata.thSigns') + '</th><th>' +
      t.html('consoleCryptoMetadata.thVerifies') + '</th><th>' +
      t.html('consoleCryptoMetadata.thEncrypts') + '</th><th>' +
      t.html('consoleCryptoMetadata.thDecrypts') + '</th>' +
      '</tr></thead><tbody>' +
      report.families.map(function (row) {
        return '<tr><td class="n"><a href="#' + esc(self.anchorFor(row.name)) +
          '">' + esc(row.name) + '</a></td>' +
          '<td>' + self.verbCell(row.signs, t) + '</td>' +
          '<td>' + self.verbCell(row.verifies, t) + '</td>' +
          '<td>' + self.verbCell(row.encrypts, t) + '</td>' +
          '<td>' + self.verbCell(row.decrypts, t) + '</td></tr>';
      }).join('') + '</tbody></table>';

    report.families.forEach(function (row) {
      html += '<h3 id="' + esc(self.anchorFor(row.name)) + '">' +
        esc(row.name) + '</h3>' +
        '<table><tbody>' +
        '<tr><th class="n">' + t.html('consoleCryptoMetadata.hashing') +
        '</th><td>' + self.prose(row.hashes) +
        '</td></tr>' +
        row.algorithms.map(function (group) {
          return '<tr><th class="n">' + esc(group.what) + '</th><td>' +
            self.chips(group.values) + '</td></tr>';
        }).join('') +
        '<tr><th class="n">' + t.html('consoleCryptoMetadata.envelopes') +
        '</th><td>' +
        row.envelopes.map(function (key) {
          const std = report.standards.filter(function (s) {
            return s.key === key;
          })[0];
          return std ? '<a href="#std-' + esc(key) + '">' + esc(std.name) +
                       '</a>' : '<code>' + esc(key) + '</code>';
        }).join(', ') + '</td></tr>' +
        '</tbody></table>' +
        kit.note(t.html('consoleCryptoMetadata.doesNotDo') + ' ' +
                   self.prose(row.whatItDoesNot));
    });
    return html;
  }

  // A "View details" link on a key row, opening the certificate dialog over
  // this page and closing back to this section. Nothing where the key holds no
  // certificate — a BBS key, a post-quantum key not made yet.
  static certificateLink(fingerprint, t, text?) {
    const html = CertificateDialogView.link('/admin/crypto-metadata',
                                            fingerprint, 'keys', text, t);
    return html ? '<br>' + html : '';
  }

  static renderKeys(report, t) {
    const self = this;
    const keys = report.keys;
    let html = '<h2 id="keys">' + t.html('consoleCryptoMetadata.keysHeading') +
      '</h2><p ' +
      'class="lead">' + t.html('consoleCryptoMetadata.keysLead',
                               { realm: keys.realm }) + '</p>';

    const thisRealm = t.html('consoleCryptoMetadata.scopeRealm');
    const theProcess = t.html('consoleCryptoMetadata.scopeProcess');
    html += '<table><thead><tr><th class="n">' +
      t.html('consoleCryptoMetadata.thKey') + '</th><th>' +
      t.html('consoleCryptoMetadata.thType') + '</th>' +
      '<th>' + t.html('consoleCryptoMetadata.thIdentifier') + '</th><th>' +
      t.html('consoleCryptoMetadata.thScope') + '</th></tr></thead><tbody>' +
      '<tr><td class="n">' + t.html('consoleCryptoMetadata.signingKey') +
      '</td><td><code>RSA 2048</code> ' +
      '<code>RS256</code></td><td><code>' + esc(keys.signing.kid) +
      '</code>' +
      self.certificateLink(keys.signing.certificateFingerprint, t) +
      '</td><td>' + thisRealm + '</td></tr>' +
      keys.curveKeys.map(function (one) {
        return '<tr><td class="n">' + t.html('consoleCryptoMetadata.curveKey') +
          '</td><td><code>' + esc(one.alg) +
          '</code> <code>' + esc(one.kty) +
          (one.crv ? '</code> <code>' + esc(one.crv) : '') +
          '</code></td><td><code>' + esc(one.kid) +
          '</code>' + self.certificateLink(one.certificateFingerprint, t) +
          '</td><td>' + thisRealm + '</td></tr>';
      }).join('') +
      (keys.postQuantum.generated
        ? keys.postQuantum.keys.map(function (one) {
            return '<tr><td class="n">' +
              t.html('consoleCryptoMetadata.pqKey') + '</td><td><code>' +
              esc(one.alg) + '</code> <code>AKP</code></td><td><code>' +
              esc(one.kid) + '</code>' +
              self.certificateLink(one.certificateFingerprint, t) +
              '</td><td>' + thisRealm + '</td></tr>';
          }).join('')
        : '<tr><td class="n">' + t.html('consoleCryptoMetadata.pqKeys') +
          '</td><td>' +
          t.html('consoleCryptoMetadata.pqAlgorithms',
                 { n: keys.postQuantum.algorithms.length }) +
          '</td><td><span class="why">' +
          t.html('consoleCryptoMetadata.notMadeYetRealm') +
          '</span></td><td>' + thisRealm + '</td></tr>') +
      // THE SIGNER GROUPS (#68), one row per key, its hybrid partner named.
      keys.signerGroups.keys.map(function (one) {
        return '<tr><td class="n">' +
          t.html('consoleCryptoMetadata.signerGroup', { group: one.group }) +
          '</td><td><code>' + esc(one.alg) + '</code>' +
          (one.pairedSlot
            ? ' <span class="why">' + (one.kind === 'pq'
                ? t.html('consoleCryptoMetadata.alternativeOf',
                         { slot: one.pairedSlot })
                : t.html('consoleCryptoMetadata.hybridWith',
                         { slot: one.pairedSlot })) + '</span>'
            : '') + '</td><td><code>' + esc(one.kid) + '</code>' +
          self.certificateLink(one.certificateFingerprint, t) +
          '</td><td>' + thisRealm + '</td></tr>';
      }).join('') +
      '<tr><td class="n">' + t.html('consoleCryptoMetadata.bbsKey') +
      '</td><td><code>' +
      esc(keys.bbs.cryptosuite) + '</code> ' + esc(keys.bbs.curve) +
      '</td><td><span class="why">' +
      t.html('consoleCryptoMetadata.bbsPublished') + '</span></td>' +
      '<td>' + thisRealm + '</td></tr>' +
      '<tr><td class="n">' + t.html('consoleCryptoMetadata.tlsCertificate') +
      '</td><td><code>RSA 2048</code> ' +
      '<code>SHA-256</code></td><td><code>' + esc(keys.tls.fingerprint256) +
      '</code>' + (keys.tls.certificates || []).map(function (one) {
        return self.certificateLink(one.certificateFingerprint, t,
          t.text('consoleCryptoMetadata.viewDetailsOf',
                 { alg: one.algorithm }));
      }).join('') + '</td><td>' + theProcess + '</td></tr>' +
      '<tr><td class="n">' + t.html('consoleCryptoMetadata.spiffeX509') +
      '</td><td><code>' +
      esc(keys.spiffe.authorityKeyType || keys.spiffe.x509KeyType) +
      '</code></td><td>' +
      (keys.spiffe.ready
        ? t.html('consoleCryptoMetadata.authorities',
                 { n: keys.spiffe.x509Authorities }) + ', ' +
          (keys.spiffe.authoritySource === 'pki'
            ? t.html('consoleCryptoMetadata.thisRealms') +
              ' <a href="/admin/pki">' +
              t.html('consoleCryptoMetadata.spiffeIssuingCa') + '</a>'
            : '<span class="why">' +
              t.html('consoleCryptoMetadata.selfSignedNoCa') + '</span>') +
          self.certificateLink(keys.spiffe.authorityFingerprint, t)
        : '<span class="why">' + t.html('consoleCryptoMetadata.notStarted') +
          '</span>') +
      '</td><td>' + thisRealm + '</td></tr>' +
      '<tr><td class="n">' + t.html('consoleCryptoMetadata.spiffeSvidKey') +
      '</td><td><code>' +
      esc(keys.spiffe.svidKeyType) + '</code></td><td><span class="why">' +
      t.html('consoleCryptoMetadata.svidKeyNote') +
      '</span></td><td>' + thisRealm + '</td></tr>' +
      '<tr><td class="n">' + t.html('consoleCryptoMetadata.spiffeJwt') +
      '</td><td><code>' +
      esc(keys.spiffe.jwtKeyType) + '</code></td><td>' +
      (keys.spiffe.ready
        ? t.html('consoleCryptoMetadata.authorities',
                 { n: keys.spiffe.jwtAuthorities })
        : '<span class="why">' + t.html('consoleCryptoMetadata.notStarted') +
          '</span>') +
      '</td><td>' + theProcess + '</td></tr>' +
      '</tbody></table>';

    // `postQuantum.what` is the report's sentence, drawn as it comes.
    html += kit.note(t.html('consoleCryptoMetadata.firstUse') + ' ' +
      self.prose(keys.postQuantum.what) + ' ' +
      t.html('consoleCryptoMetadata.firstUseAfter'));
    html += kit.note(t.html('consoleCryptoMetadata.noSecret'));
    return html;
  }

  static renderHashing(report, t) {
    const self = this;
    const h = report.hashing;
    // Every row's where, what and why are the report's, drawn as they come.
    let html = '<h2 id="hashing">' + t.html('consoleCryptoMetadata.hashing') +
      '</h2>' +
      '<p class="lead">' + t.html('consoleCryptoMetadata.hashingLead') +
      '</p>';

    html += '<table><tbody>' +
      '<tr><th class="n">' + t.html('consoleCryptoMetadata.jwsDigests') +
      '</th><td>' +
      self.chips(h.jws) + ' <span class="why">' +
      t.html('consoleCryptoMetadata.jwsDigestsNote') + '</span></td></tr>' +
      '<tr><th class="n">' + t.html('consoleCryptoMetadata.httpDigest') +
      '</th><td>' +
      self.chips(h.scimDigest.map(function (r) { return r.token; })) +
      ' <span class="why">' + t.html('consoleCryptoMetadata.httpDigestNote') +
      '</span></td></tr>' +
      '</tbody></table>';

    html += '<h3>XML DigestMethod</h3><table><thead><tr><th class="n">' +
            'URI</th>' +
      '<th>' + t.html('consoleCryptoMetadata.thLabel') +
      '</th></tr></thead><tbody>' +
      h.xmlDigestMethods.map(function (row) {
        return '<tr><td class="n"><code>' + esc(row.uri) + '</code></td><td>' +
          esc(row.label) + '</td></tr>';
      }).join('') + '</tbody></table>';

    html += '<h3>' + t.html('consoleCryptoMetadata.fixedUses') +
      '</h3><table><thead><tr><th class="n">' +
      t.html('consoleCryptoMetadata.thWhere') + '</th>' +
      '<th>' + t.html('consoleCryptoMetadata.thDigest') + '</th><th>' +
      t.html('consoleCryptoMetadata.thWhat') + '</th></tr></thead><tbody>' +
      h.fixed.map(function (row) {
        return '<tr><td class="n">' + self.prose(row.where) +
          '</td><td><code>' + esc(row.hash) + '</code></td><td>' +
          self.prose(row.what) + '</td></tr>';
      }).join('') + '</tbody></table>';

    html += '<h3>' + t.html('consoleCryptoMetadata.weakOnes') + '</h3>' +
      kit.note(t.html('consoleCryptoMetadata.weakNote')) +
      '<table><thead><tr><th class="n">' +
      t.html('consoleCryptoMetadata.thDigest') + '</th><th>' +
      t.html('consoleCryptoMetadata.thWhere') + '</th><th>' +
      t.html('consoleCryptoMetadata.thWhy') + '</th>' +
      '</tr></thead><tbody>' +
      h.weak.map(function (row) {
        return '<tr><td class="n"><code>' + esc(row.hash) + '</code></td><td>' +
          self.prose(row.where) + '</td><td>' + self.prose(row.why) +
          '</td></tr>';
      }).join('') + '</tbody></table>';
    return html;
  }

  static renderSignatures(report, t) {
    const self = this;
    const s = report.signatures;
    const yes = t.html('consoleCryptoMetadata.yes');
    const no = t.html('consoleCryptoMetadata.no');
    let html = '<h2 id="signatures">' +
      t.html('consoleCryptoMetadata.signaturesHeading') + '</h2>' +
      '<p class="lead">' + t.html('consoleCryptoMetadata.signaturesLead') +
      '</p>';

    html += '<h3>JWS</h3><table><thead><tr><th class="n">alg</th><th>' +
      t.html('consoleCryptoMetadata.thFamily') + '</th><th>' +
      t.html('consoleCryptoMetadata.thKey') + '</th><th>' +
      t.html('consoleCryptoMetadata.thDigest') + '</th><th>' +
      t.html('consoleCryptoMetadata.thAsymmetric') + '</th><th>DPoP</th>' +
      '</tr></thead><tbody>' +
      s.jws.map(function (row) {
        return '<tr><td class="n"><code>' + esc(row.alg) + '</code></td>' +
          '<td>' + esc(row.family) +
          (row.composite ? ' <span class="why">' +
                           t.html('consoleCryptoMetadata.composite') +
                           '</span>' : '') +
          '</td>' +
          '<td><code>' + esc(row.kty) + '</code>' +
          (row.crv ? ' <code>' + esc(row.crv) + '</code>' : '') + '</td>' +
          '<td>' + (row.hash ? '<code>' + esc(row.hash) + '</code>'
                             : '<span class="why">' +
                               t.html('consoleCryptoMetadata.none') +
                               '</span>') + '</td>' +
          '<td>' + (row.asymmetric ? yes
                                   : t.html('consoleCryptoMetadata.noMac')) +
          '</td>' +
          '<td>' + (row.dpop ? yes : no) + '</td></tr>';
      }).join('') + '</tbody></table>' +
      kit.note(t.html('consoleCryptoMetadata.dpopNote'));

    html += '<h3>XML SignatureMethod</h3>' +
      '<p class="lead">' + t.html('consoleCryptoMetadata.xmlSigLead') +
      '</p><table><thead><tr><th class="n">URI</th><th>' +
      t.html('consoleCryptoMetadata.thLabel') + '</th><th>' +
      t.html('consoleCryptoMetadata.thKey') + '</th><th>' +
      t.html('consoleCryptoMetadata.thSignsWith') +
      '</th></tr></thead><tbody>' +
      s.xml.map(function (row) {
        return '<tr><td class="n"><code>' + esc(row.uri) + '</code></td><td>' +
          esc(row.label) + '</td><td><code>' + esc(row.keyKind) +
          '</code></td><td>' + (row.signsWith ? yes : '<span class="why">' +
          t.html('consoleCryptoMetadata.verifyOnly') + '</span>') +
          '</td></tr>';
      }).join('') + '</tbody></table>';

    html += '<h3>' + t.html('consoleCryptoMetadata.canonicalization') +
      '</h3>' +
      '<table><thead><tr><th class="n">URI</th><th>' +
      t.html('consoleCryptoMetadata.thLabel') + '</th>' +
      '<th>' + t.html('consoleCryptoMetadata.thUsedHere') +
      '</th></tr></thead><tbody>' +
      s.canonicalization.map(function (row) {
        return '<tr><td class="n"><code>' + esc(row.uri) + '</code></td><td>' +
          esc(row.label) + '</td><td>' + (row.usedHere
            ? t.html('consoleCryptoMetadata.usedDefault')
            : '<span class="why">' + t.html('consoleCryptoMetadata.readOnly') +
              '</span>') + '</td></tr>';
      }).join('') + '</tbody></table>' +
      kit.note(t.html('consoleCryptoMetadata.exclusiveNote'));

    html += '<h3>COSE (WebAuthn)</h3><table><thead><tr>' +
      '<th class="n">COSE alg</th><th>' +
      t.html('consoleCryptoMetadata.thJoseName') +
      '</th></tr></thead><tbody>' +
      s.cose.map(function (row) {
        return '<tr><td class="n"><code>' + esc(row.coseAlg) +
          '</code></td><td><code>' + esc(row.jose) + '</code></td></tr>';
      }).join('') + '</tbody></table>';

    html += '<h3>' + t.html('consoleCryptoMetadata.everythingElse') +
      '</h3><table><thead><tr><th class="n">' +
      t.html('consoleCryptoMetadata.thWhat') + '</th>' +
      '<th>' + t.html('consoleCryptoMetadata.thDetail') +
      '</th></tr></thead><tbody>' +
      s.other.map(function (row) {
        return '<tr><td class="n">' + esc(row.name) + '</td><td>' +
          self.prose(row.what) + '</td></tr>';
      }).join('') + '</tbody></table>';
    return html;
  }

  static renderEncryption(report, t) {
    const self = this;
    const e = report.encryption;
    const yes = t.html('consoleCryptoMetadata.yes');
    let html = '<h2 id="encryption">' +
      t.html('consoleCryptoMetadata.encryptionHeading') + '</h2><p ' +
      'class="lead">' + t.html('consoleCryptoMetadata.encryptionLead') +
      '</p>';

    html += '<h3>JWE</h3><table><tbody>' +
      '<tr><th class="n">' + t.html('consoleCryptoMetadata.kmEncrypting') +
      '</th><td>' +
      self.chips(e.jwe.keyManagementOut) + '</td></tr>' +
      '<tr><th class="n">' + t.html('consoleCryptoMetadata.kmDecrypting') +
      '</th><td>' +
      // **IT IS THE LONGER LIST NOW AND THIS NOTE SAID "shorter on purpose".**
      // It was written when the decrypt list was `['RSA-OAEP-256']` alone; the
      // symmetric families arrived in `crypto.js` and the two lists swapped
      // ends, leaving the page explaining an asymmetry in the direction it no
      // longer has.
      self.chips(e.jwe.keyManagementIn) + ' <span class="why">' +
      t.html('consoleCryptoMetadata.kmLonger') + '</span></td></tr>' +
      '</tbody></table><table><thead><tr><th class="n">enc</th><th>' +
      t.html('consoleCryptoMetadata.thBits') + '</th>' +
      '<th>' + t.html('consoleCryptoMetadata.thMode') +
      '</th><th>CEK</th><th>' +
      t.html('consoleCryptoMetadata.thNote') + '</th></tr></thead><tbody>' +
      e.jwe.contentEncryption.map(function (row) {
        return '<tr><td class="n"><code>' + esc(row.enc) + '</code></td><td>' +
          esc(row.bits) + '</td><td><code>' + esc(row.mode) +
          '</code></td><td>' +
          t.html('consoleCryptoMetadata.bytes', { n: row.cekBytes }) +
          '</td><td>' +
          esc(row.note) + '</td></tr>';
      }).join('') + '</tbody></table>' +
      kit.note(t.html('consoleCryptoMetadata.cbcNote'));

    // The link is markup a message cannot carry, so the lead is cut at it.
    html += '<h3>XML Encryption</h3>' +
      '<p class="lead">' + t.html('consoleCryptoMetadata.xmlEncLead') +
      ' <a href="/admin/saml2">SAML 2.0</a>' +
      t.html('consoleCryptoMetadata.xmlEncNow',
             { cipher: e.xml.configured.blockCipher,
               transport: e.xml.configured.keyTransport }) + ' ' +
      (e.xml.configured.encryptAssertion
        ? t.html('consoleCryptoMetadata.assertionsEncrypted')
        : t.html('consoleCryptoMetadata.assertionsNotEncrypted')) + ', ' +
      (e.xml.configured.encryptLogoutNameId
        ? t.html('consoleCryptoMetadata.nameIdEncrypted')
        : t.html('consoleCryptoMetadata.nameIdNotEncrypted')) +
      '.</p>' +
      '<table><thead><tr><th class="n">' +
      t.html('consoleCryptoMetadata.thBlockCipher') + '</th><th>URI</th>' +
      '<th>' + t.html('consoleCryptoMetadata.thKey') + '</th><th>' +
      t.html('consoleCryptoMetadata.thAuthenticated') +
      '</th></tr></thead><tbody>' +
      e.xml.blockCiphers.map(function (row) {
        return '<tr><td class="n"><code>' + esc(row.name) +
          '</code></td><td><code>' + esc(row.uri) + '</code></td><td>' +
          esc(row.keyBits) + '-bit ' + esc(row.mode) + '</td><td>' +
          (row.authenticated ? yes
                             : t.html('consoleCryptoMetadata.noStrong')) +
          '</td></tr>';
      }).join('') + '</tbody></table>' +
      '<table><thead><tr><th class="n">' +
      t.html('consoleCryptoMetadata.thKeyTransport') + '</th><th>URI</th>' +
      '<th>' + t.html('consoleCryptoMetadata.thScheme') +
      '</th></tr></thead><tbody>' +
      e.xml.keyTransports.map(function (row) {
        return '<tr><td class="n"><code>' + esc(row.name) +
          '</code></td><td><code>' + esc(row.uri) + '</code></td><td>' +
          esc(row.scheme) + (row.safe ? ''
            : t.html('consoleCryptoMetadata.broken')) +
          '</td></tr>';
      }).join('') + '</tbody></table>' +
      kit.warn(t.html('consoleCryptoMetadata.unsafeNote'));

    html += '<h3>' + t.html('consoleCryptoMetadata.kerberosEtypes') + '</h3>' +
      '<table><thead><tr><th class="n">etype</th><th>' +
      t.html('consoleCryptoMetadata.thName') + '</th>' +
      '<th>' + t.html('consoleCryptoMetadata.thPerformed') +
      '</th></tr></thead><tbody>' +
      e.kerberos.performed.map(function (row) {
        return '<tr><td class="n"><code>' + esc(row.id) +
          '</code></td><td><code>' + esc(row.name) +
          '</code></td><td>' + yes + '</td></tr>';
      }).join('') +
      e.kerberos.decodeOnly.map(function (row) {
        return '<tr><td class="n"><code>' + esc(row.id) +
          '</code></td><td><code>' + esc(row.name) +
          '</code></td><td><span class="why">' +
          t.html('consoleCryptoMetadata.decodeOnly') + '</span></td></tr>';
      }).join('') + '</tbody></table>' +
      kit.note(t.html('consoleCryptoMetadata.decodeOnlyNote'));

    // `tls.what` is the report's sentence, drawn as it comes.
    html += '<h3>TLS</h3>' + kit.note('<strong>' + self.prose(e.tls.what) +
      '</strong> ' + t.html('consoleCryptoMetadata.sockets') + ' ' +
      self.chips(e.tls.sockets) + '.');
    return html;
  }

  static renderPostQuantum(report, t) {
    const self = this;
    const pq = report.postQuantum;
    // The `what`, `strongest`, `independence`, `how` and drafts sentences
    // are the report's, drawn as they come.
    let html = '<h2 id="post-quantum">' +
      t.html('consoleCryptoMetadata.pqHeading') + '</h2>' +
      '<p class="lead">' + t.html('consoleCryptoMetadata.pqLead') + '</p>' +
      kit.note(t.html('consoleCryptoMetadata.pqHalves')) +
      kit.note(t.html('consoleCryptoMetadata.pqSymmetric') + ' ' +
        self.prose(pq.symmetric.what) + ' ' +
        t.html('consoleCryptoMetadata.pqStrongest') + ' ' +
        self.prose(pq.symmetric.strongest));

    html += '<h3>' + t.html('consoleCryptoMetadata.pqHeld') + '</h3>' +
      '<table><tbody>' +
      '<tr><th class="n">ML-DSA (FIPS 204)</th><td>' +
      self.chips(pq.algorithms.mlDsa) +
      '</td></tr>' +
      '<tr><th class="n">SLH-DSA (FIPS 205)</th><td>' +
      self.chips(pq.algorithms.slhDsa) +
      '</td></tr>' +
      '<tr><th class="n">' + t.html('consoleCryptoMetadata.keyType') +
      '</th><td><code>' + esc(pq.algorithms.keyType) +
      '</code></td></tr>' +
      '</tbody></table>' +
      '<table><thead><tr><th class="n">' +
      t.html('consoleCryptoMetadata.thComposite') + '</th><th>' +
      t.html('consoleCryptoMetadata.thMlDsaHalf') + '</th>' +
      '<th>' + t.html('consoleCryptoMetadata.thTraditionalHalf') + '</th><th>' +
      t.html('consoleCryptoMetadata.thDomainSeparator') +
      '</th></tr></thead><tbody>' +
      pq.algorithms.composite.map(function (row) {
        return '<tr><td class="n"><code>' + esc(row.alg) +
          '</code></td><td><code>' + esc(row.mlDsa) +
          '</code></td><td><code>' + esc(row.traditional) +
          '</code></td><td><code>' + esc(row.domainSeparator) +
          '</code></td></tr>';
      }).join('') + '</tbody></table>' +
      kit.note(t.html('consoleCryptoMetadata.compositesBuy') + ' ' +
        self.prose(pq.algorithms.what)) +
      kit.note(t.html('consoleCryptoMetadata.independence') + ' ' +
        self.prose(pq.algorithms.independence));

    const pqAvailable = '<strong>' +
      t.html('consoleCryptoMetadata.pqAvailable') + '</strong>';
    const classicalOnly = '<span class="why">' +
      t.html('consoleCryptoMetadata.classicalOnly') + '</span>';
    html += '<h3>' + t.html('consoleCryptoMetadata.sigSurfaces') + '</h3>' +
      '<table><thead><tr><th class="n">' +
      t.html('consoleCryptoMetadata.thSurface') + '</th><th>' +
      t.html('consoleCryptoMetadata.thState') + '</th><th>' +
      t.html('consoleCryptoMetadata.thHow') + '</th>' +
      '</tr></thead><tbody>' +
      pq.signatures.map(function (row) {
        return '<tr><td class="n">' + esc(row.surface) + '</td><td>' +
          (row.state === 'pq' ? pqAvailable : classicalOnly) +
          '</td><td>' + self.prose(row.how) + '</td></tr>';
      }).join('') + '</tbody></table>';

    html += '<h3>' + t.html('consoleCryptoMetadata.keSurfaces') + '</h3>' +
      kit.note(t.html('consoleCryptoMetadata.keNote') + ' ' +
        self.prose(pq.keyEstablishment.what)) +
      '<table><thead><tr><th class="n">' +
      t.html('consoleCryptoMetadata.thSurface') + '</th><th>' +
      t.html('consoleCryptoMetadata.thState') + '</th><th>' +
      t.html('consoleCryptoMetadata.thHow') +
      '</th></tr></thead><tbody>' +
      pq.keyEstablishment.surfaces.map(function (row) {
        return '<tr><td class="n">' + esc(row.surface) + '</td><td>' +
          (row.state === 'pq'
            ? pqAvailable + ' ' +
              PqcBadgeView.badge({ kind: 'kem', label: 'ML-KEM / HPKE',
                               standard: 'draft-ietf-jose-pqc-kem-05, ' +
                                 'draft-reddy-cose-jose-pqc-hybrid-hpke-11' },
                                 t)
            : row.state === 'optional'
              ? '<span class="why">' +
                t.html('consoleCryptoMetadata.pqNotEnabled') + '</span>'
              : classicalOnly) +
          '</td><td>' + self.prose(row.how) + '</td></tr>';
      }).join('') + '</tbody></table>' +
      '<table><tbody><tr><th class="n">' +
      t.html('consoleCryptoMetadata.pqJwe') + '</th><td>' +
      self.chips(pq.keyEstablishment.postQuantum) + '</td></tr>' +
      '<tr><th class="n">' + t.html('consoleCryptoMetadata.ofWhichHybrid') +
      '</th><td>' +
      self.chips(pq.keyEstablishment.hybrid) + '</td></tr>' +
      '<tr><th class="n">' + t.html('consoleCryptoMetadata.everyMechanism') +
      '</th><td>' +
      self.chips(pq.keyEstablishment.mechanisms) + '</td></tr>' +
      '<tr><th class="n">' + t.html('consoleCryptoMetadata.drafts') +
      '</th><td>' +
      self.prose(pq.keyEstablishment.drafts.mlKem) + '<br>' +
      self.prose(pq.keyEstablishment.drafts.hpke) + '<br>' +
      self.prose(pq.keyEstablishment.drafts.hybrid) + '</td></tr>' +
      '<tr><th class="n">' + t.html('consoleCryptoMetadata.whatRemains') +
      '</th><td>' +
      self.prose(pq.keyEstablishment.whatWouldClose) +
      '</td></tr></tbody></table>';
    return html;
  }

  static renderStandards(report, t) {
    const self = this;
    // The link is markup a message cannot carry, so the lead is cut at it.
    let html = '<h2 id="standards">' +
      t.html('consoleCryptoMetadata.standardsHeading') + '</h2><p ' +
      'class="lead">' + t.html('consoleCryptoMetadata.standardsLead') +
      ' <a href="/admin/sts-metadata">' +
      t.html('consoleCryptoMetadata.serviceMetadata') + '</a> ' +
      t.html('consoleCryptoMetadata.standardsLeadAfter') + '</p>';

    // A standard's name, coverage and description are the report's.
    html += report.standards.map(function (row) {
      return '<h3 id="std-' + esc(row.key) + '">' + esc(row.name) + '</h3>' +
        '<table><tbody>' +
        '<tr><th class="n">' + t.html('consoleCryptoMetadata.specifications') +
        '</th><td>' + self.chips(row.specs) +
        '</td></tr>' +
        '<tr><th class="n">' + t.html('consoleCryptoMetadata.coverage') +
        '</th><td>' + self.prose(row.coverage) +
        '</td></tr><tr><th ' +
        'class="n">' + t.html('consoleCryptoMetadata.whatItIsHere') +
        '</th><td>' + self.prose(row.what) +
        '</td></tr>' +
        '</tbody></table>';
    }).join('');
    return html;
  }

  static renderInner(report, t) {
    const self = this;
    // The links are markup a message cannot carry, so the sentences are cut
    // at them, and the counts beside the download go in as parameters.
    let html = '<p class="lead">' + t.html('consoleCryptoMetadata.innerLead') +
      ' <a href="/admin/sts-metadata">' +
      t.html('consoleCryptoMetadata.serviceMetadata') + '</a> ' +
      t.html('consoleCryptoMetadata.innerLeadAfter') + '</p>';

    html += '<p><a class="btn" href="/admin/crypto-metadata?format=json" ' +
      'download="crypto-metadata.json" title="' +
      esc(t.text('consoleCryptoMetadata.downloadTip')) + '">' +
      t.html('consoleCryptoMetadata.download') + '</a> ' +
      '<span class="why">' +
      t.html('consoleCryptoMetadata.downloadCounts',
             { services: report.families.length,
               jws: report.signatures.jws.length,
               standards: report.standards.length }) + '</span></p>';

    html += kit.note(t.html('consoleCryptoMetadata.onePlace'));

    html += '<p class="lead">' + t.html('consoleCryptoMetadata.onThisPage') +
      ' ' +
      '<a href="#families">' + t.html('consoleCryptoMetadata.tocFamilies') +
      '</a> &middot; ' +
      '<a href="#keys">' + t.html('consoleCryptoMetadata.tocKeys') +
      '</a> &middot; ' +
      '<a href="#hashing">' + t.html('consoleCryptoMetadata.tocHashing') +
      '</a> &middot; ' +
      '<a href="#signatures">' +
      t.html('consoleCryptoMetadata.tocSignatures') + '</a> &middot; ' +
      '<a href="#encryption">' +
      t.html('consoleCryptoMetadata.tocEncryption') + '</a> &middot; ' +
      '<a href="#post-quantum">' + t.html('consoleCryptoMetadata.tocPq') +
      '</a> &middot; ' +
      '<a href="#standards">' + t.html('consoleCryptoMetadata.tocStandards') +
      '</a></p>';

    html += self.renderFamilies(report, t);
    html += self.renderKeys(report, t);
    html += self.renderHashing(report, t);
    html += self.renderSignatures(report, t);
    html += self.renderEncryption(report, t);
    html += self.renderPostQuantum(report, t);
    html += self.renderStandards(report, t);
    return html;
  }

  // THE PAGES' BODIES (#446), each one method so that it can be one
  // renderer: Cryptography (with a certificate's details over it when the
  // view carries them) and Key pairs.
  /**
   * Draws Cryptography from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - `cryptoJson()`'s answer
   * @returns the body as HTML
   */
  static cryptoBody(ctx, json) {
    return this.renderInner(json, ctx.t) + (json.certificateDetails
      ? CertificateDialogView.dialog('/admin/crypto-metadata',
                                 json.certificateDetails, ctx.query.from,
                                 ctx.t)
      : '');
  }

  /**
   * Draws Key pairs from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - `keysJson()`'s answer
   * @returns the body as HTML
   */
  static keysBody(ctx, json) {
    const t = ctx.t;
    // The two links are markup a message cannot carry, so the sentence is
    // cut at them.
    return this.renderRotation(json.rotation, ctx.write, t) +
      this.renderKeyPairs(json, t) +
      '<p>' + t.html('consoleCryptoMetadata.publishedIn') + ' ' +
      '<a href="' + esc(json.issuer + '/crypto/metadata.json') +
      '">' + t.html('consoleCryptoMetadata.metadataDocument') + '</a> ' +
      t.html('consoleCryptoMetadata.alsoAs') + ' <a href="' +
      esc(json.issuer + '/crypto/metadata.xml') +
      '">XML</a>).</p>' +
      '<h2>' + t.html('consoleCryptoMetadata.settings') + '</h2>' +
      SettingsForms.forms(json.settings, '/admin/keys', undefined, t);
  }

  // The section drawn above the key list: each unit's generations, and the
  // two forms. No script: checkboxes and a submit button.
  // ---------------------------------------------------------------------------
  // THE HISTORY SUB-PAGE'S MARKUP. A table per unit, newest first, with the
  // certificate offered as a DOWNLOAD rather than printed: a PEM in a cell
  // makes every other column unreadable, and the whole point of keeping one
  // is that somebody takes it away to check a signature with.
  // ---------------------------------------------------------------------------
  /**
   * Draws the history sub-page: a table per unit, newest first, each
   * certificate offered as a download.
   *
   * @param view - `historyJson()`'s answer
   * @param ctx - the console request
   * @returns the markup
   */
  static renderHistory(ctx, view) {
    const t = ctx.t;
    const lead = '<p>' + t.html('consoleCryptoMetadata.historyLead') +
      '</p>' +
      '<p><a href="/admin/keys">&larr; ' +
      t.html('consoleCryptoMetadata.keyPairs') + '</a></p>';
    if (!view.observed) {
      return lead + '<p class="warn">' +
             t.html('consoleCryptoMetadata.noHistoryModule') + '</p>';
    }
    const index = '<h2>' + t.html('consoleCryptoMetadata.units') + '</h2>' +
      (view.units.length
      ? '<table class="data"><thead><tr><th>' +
        t.html('consoleCryptoMetadata.thUnit') + '</th><th>' +
        t.html('consoleCryptoMetadata.thGenerations') + '</th>' +
        '<th>' + t.html('consoleCryptoMetadata.thHeldNow') + '</th><th>' +
        t.html('consoleCryptoMetadata.thDropped') + '</th><th>' +
        t.html('consoleCryptoMetadata.thWithCertificate') + '</th>' +
        '</tr></thead><tbody>' + view.units.map(function (u) {
          return '<tr><td><a href="' +
            esc('/admin/keys/history?unit=' + encodeURIComponent(u.unit)) +
            '"><code>' + esc(u.unit) + '</code></a></td><td>' +
            esc(String(u.generations)) + '</td><td>' + esc(String(u.live)) +
            '</td><td>' + esc(String(u.dropped)) + '</td><td>' +
            esc(String(u.withCertificate)) + '</td></tr>';
        }).join('') + '</tbody></table>'
      : '<p>' + t.html('consoleCryptoMetadata.noKeyObserved') + '</p>');
    if (!view.unit) {
      return lead + index;
    }
    if (!view.found) {
      return lead + '<p class="warn">' +
             t.html('consoleCryptoMetadata.noSuchUnit', { unit: view.unit }) +
             '</p>' + index;
    }
    const nav = kit.pageNavPair('/admin/keys/history',
                                  { unit: view.unit }, view.paging, t);
    // The `&mdash;` fallbacks are escaped as they always were, so they draw
    // as written; the words are this file's, the dates the view's.
    const rows = view.rows.map(function (row) {
      const cert = row.certificate;
      return '<tr><td><code>' + esc(row.kid) + '</code></td>' +
        '<td>' + esc(row.role) + '</td>' +
        '<td>' + esc(row.createdAt || row.firstSeenAt || '') + '</td>' +
        '<td>' + esc(row.promotedAt || '&mdash;') + '</td>' +
        '<td>' + esc(row.retiredAt || '&mdash;') +
        (row.verifiesUntil ? '<br>' +
         t.html('consoleCryptoMetadata.verifiedUntil',
                { when: row.verifiesUntil })
         : '') + '</td>' +
        '<td>' + esc(row.droppedAt || '&mdash;') + '</td>' +
        '<td>' + esc(row.reason || '&mdash;') + '</td>' +
        '<td>' + (cert
          ? '<code>' + esc(cert.serialHex) + '</code><br>' +
            esc(cert.notBefore) + ' &ndash; ' + esc(cert.notAfter) +
            // An /admin-api resource since #446: the console's runtime
            // fetches it with its own token and saves it.
            '<br><a href="' +
            esc('/admin-api/keys/history/certificate?unit=' +
                encodeURIComponent(view.unit) + '&kid=' +
                encodeURIComponent(row.kid)) + '" download>' +
            t.html('consoleCryptoMetadata.certificateAndChain') + '</a>'
          : t.html('consoleCryptoMetadata.none')) + '</td></tr>';
    }).join('');
    const out = lead + '<h2>' + esc(view.unit) + '</h2>' + nav.head +
      '<table class="data"><thead><tr><th>' +
      t.html('consoleCryptoMetadata.thKey') + '</th><th>' +
      t.html('consoleCryptoMetadata.thRole') + '</th>' +
      '<th>' + t.html('consoleCryptoMetadata.thMinted') + '</th><th>' +
      t.html('consoleCryptoMetadata.thPromoted') + '</th><th>' +
      t.html('consoleCryptoMetadata.thRetired') + '</th><th>' +
      t.html('consoleCryptoMetadata.thDropped') + '</th>' +
      '<th>' + t.html('consoleCryptoMetadata.thWhy') + '</th><th>' +
      t.html('consoleCryptoMetadata.thCertificate') +
      '</th></tr></thead><tbody>' + rows +
      '</tbody></table>' + nav.foot + index;
    return out;
  }

  /**
   * Draws the rotation section above the key list: each unit's generations and
   * the Rotate and Emergency forms.
   *
   * @param view - `rotationViewOf()`'s answer
   * @param canWrite - whether the reader holds Admin Write
   * @returns the markup, or an empty string without a view
   */
  static renderRotation(view, canWrite, t) {
    if (!view) {
      return '';
    }
    const rows = view.units.map(function (u) {
      return '<tr>' +
        (canWrite ? '<td><input type="checkbox" name="units" value="' +
                    esc(u.unit) + '" id="rotate-unit-' + esc(u.unit) +
                    '"></td>' : '') +
        '<td><code>' + esc(u.unit) + '</code>' +
        (u.credentialSigner ? ' ' +
          t.html('consoleCryptoMetadata.credentialsMark') : '') + '</td>' +
        '<td><code>' + esc(u.current) + '</code></td>' +
        '<td>' + (u.next ? '<code>' + esc(u.next.kid) + '</code><br>' +
                  t.html('consoleCryptoMetadata.since',
                         { when: u.next.since || '' }) : '—') + '</td>' +
        '<td>' + (u.retired.length ? u.retired.map(function (r) {
          return t.html('consoleCryptoMetadata.retiredUntil',
                        { kid: r.kid, when: r.verifiesUntil || '' });
        }).join('<br>') : '—') + '</td>' +
        '<td>' + (u.lastRotated ? esc(u.lastRotated)
                                : t.html('consoleCryptoMetadata.never')) +
        '</td>' +
        '<td>' + esc(String(u.intervalDays)) + ' / ' +
        esc(String(u.graceDays)) + '</td>' +
        // EVERY GENERATION THIS UNIT HAS EVER HAD (#42's follow-up). The row
        // above it says what the realm holds NOW; the private half of
        // anything older is gone, and this is where the record of it is.
        '<td><a href="' +
        esc('/admin/keys/history?unit=' + encodeURIComponent(u.unit)) +
        '">' + t.html('consoleCryptoMetadata.history') + '</a></td></tr>';
    }).join('');
    const table = '<table class="data"><thead><tr>' +
      (canWrite ? '<th>' + t.html('consoleCryptoMetadata.thRotate') + '</th>'
                : '') +
      '<th>' + t.html('consoleCryptoMetadata.thUnit') + '</th><th>' +
      t.html('consoleCryptoMetadata.thCurrent') + '</th><th>' +
      t.html('consoleCryptoMetadata.thNext') + '</th><th>' +
      t.html('consoleCryptoMetadata.thRetiredUntil') + '</th><th>' +
      t.html('consoleCryptoMetadata.thLastRotated') + '</th><th>' +
      t.html('consoleCryptoMetadata.thIntervalGrace') + '</th>' +
      '<th>' + t.html('consoleCryptoMetadata.thEveryGeneration') + '</th>' +
      '</tr></thead><tbody>' + rows + '</tbody></table>';
    // `offReason` is the view's, drawn as it comes.
    const status = '<p>' + (view.scheduled
      ? t.html('consoleCryptoMetadata.rotationOn')
      : t.html('consoleCryptoMetadata.rotationOffBefore') + ' ' +
        esc(view.offReason) + '. ' +
        t.html('consoleCryptoMetadata.rotationOffAfter')) +
      ' ' + t.html('consoleCryptoMetadata.refreshKeys',
                   { n: String(view.refresh.retired),
                     days: String(view.refresh.graceDays) }) +
      '</p>';
    if (!canWrite) {
      return '<h2>' + t.html('consoleCryptoMetadata.rotation') + '</h2>' +
        status + table;
    }
    const out = '<h2>' + t.html('consoleCryptoMetadata.rotation') + '</h2>' +
      status +
      '<form method="post" action="/admin/keys/rotate">' +
      '<input type="hidden" name="action" value="rotate">' + table +
      '<p><button type="submit" id="keys-rotate-selected">' +
      t.html('consoleCryptoMetadata.rotateSelected') + '</button> ' +
      '<button type="submit" name="units" value="all" ' +
      'id="keys-rotate-all">' + t.html('consoleCryptoMetadata.rotateAll') +
      '</button>' + t.html('consoleCryptoMetadata.rotateNote') +
      '</p></form>' +
      '<h3>' + t.html('consoleCryptoMetadata.emergency') + '</h3>' +
      '<p class="warn">' + t.html('consoleCryptoMetadata.emergencyNote') +
      '</p>' +
      '<form method="post" action="/admin/keys/rotate">' +
      '<input type="hidden" name="action" value="emergency">' +
      '<label>' + t.html('consoleCryptoMetadata.typeToConfirm') +
      ' <input type="text" ' +
      'name="confirm" id="keys-emergency-confirm" autocomplete="off">' +
      '</label> <button type="submit" id="keys-emergency">' +
      t.html('consoleCryptoMetadata.rotateEveryKey') + '</button></form>';
    return out;
  }

  // NAMED `renderKeyPairs` AND NOT `renderKeys`, AND A 500 IS WHY. This file
  // already had a `renderKeys()` — the KEY MATERIAL section of
  // /admin/crypto-metadata — and a second function declaration of that name
  // silently replaced it, so the page above started calling this one and threw
  // `report.keys.map is not a function` on a report that has no `keys`. Two
  // functions, one name, nine hundred lines apart: exactly what the `keystore`
  // import a few hundred lines up was renamed to avoid, met a second time
  // because the first rename fixed the symptom rather than teaching the lesson.
  // ---------------------------------------------------------------------------
  // HOW LONG A DECRYPTED PRIVATE KEY IS IN MEMORY (2026-09-06).
  //
  // A REPORT AND NOT A CONTROL, and that is rule 7 read exactly rather than a
  // gap. Everything on it is either a SETTING — drawn on `/admin/config` with
  // the rest of the Key material group, because that is where its group's row
  // in `SETTING_HOMES` sends it — or an observation. A *Purge now* button was
  // considered and refused: the one POST this page has answers with a FILE
  // rather than a page (see the routes above), so a second action here would be
  // the one form in this console whose two buttons answer in two different
  // shapes, and what it would buy is shortening a window the timer shortens
  // anyway.
  //
  // **THE NUMBER IS THE POINT.** A page that only named the policy would be
  // describing a promise; naming the realms whose key is decrypted RIGHT NOW is
  // something a reader can watch change, which is the only way an operator can
  // tell this is working rather than configured.
  // ---------------------------------------------------------------------------
  static renderResidency(residency, t) {
    if (!residency.persisting) {
      return kit.note(t.html('consoleCryptoMetadata.residencyNothing'));
    }
    const held = residency.plaintextHeld || [];
    const all = residency.realmsHeld || [];
    // The retention note is the view's, put into the sentence at a marker:
    // it is escaped the console's way rather than a parameter's.
    let html = '<h2 id="residency">' +
      t.html('consoleCryptoMetadata.residencyHeading') + '</h2>';
    html += kit.note(t.html('consoleCryptoMetadata.residencyCiphertext',
                            { note: '\u0001note\u0001' })
      .split('\u0001note\u0001').join(esc(residency.note || '')));
    html += '<table><thead><tr><th class="n">' +
      t.html('consoleCryptoMetadata.thRealm') + '</th><th>' +
      t.html('consoleCryptoMetadata.thHeld') + '</th>' +
      '<th>' + t.html('consoleCryptoMetadata.thDecryptedNow') +
      '</th></tr></thead><tbody>' +
      (all.length
        ? all.map(function (id) {
            const open = held.indexOf(id) >= 0;
            return '<tr><td class="n"><code>' + esc(id || 'default') +
              '</code></td><td>' +
              t.html('consoleCryptoMetadata.encryptedGcm') +
              '</td><td>' + (open ? '<strong>' +
                               t.html('consoleCryptoMetadata.yes') +
                               '</strong>'
                             : '<span class="why">' +
                               t.html('consoleCryptoMetadata.no') +
                               '</span>') + '</td></tr>';
          }).join('')
        : '<tr><td colspan="3"><span class="why">' +
          t.html('consoleCryptoMetadata.noRealmStored') +
          '</span></td></tr>') +
      '</tbody></table>';
    html += kit.note(t.html('consoleCryptoMetadata.residencyReads'));
    return html;
  }

  static renderKeyPairs(report, t) {
    const self = this;
    const residency = report.residency || {};
    let html = '<p class="lead">' +
      t.html('consoleCryptoMetadata.keyPairsLead', { realm: report.realm }) +
      '</p>';

    // **THE OLD WARNING SAID THESE KEYS DIE WITH THE PROCESS, FULL STOP.** That
    // was true of every key in this service until the keystore landed, and it
    // is the sentence that makes handing a private key to a browser defensible
    // — so leaving it standing on a service whose signing key now OUTLIVES the
    // process would be this console's most consequential untruth. It is
    // computed.
    html += kit.warn(t.html('consoleCryptoMetadata.handsOver') + ' <a ' +
      'href="/admin/crypto-metadata">' +
      t.html('consoleCryptoMetadata.cryptography') + '</a> ' +
      t.html('consoleCryptoMetadata.nextDoor') + ' ' +
      (residency.persisting
        ? t.html('consoleCryptoMetadata.persisted') + ' '
        : t.html('consoleCryptoMetadata.defensible') + ' ') +
      t.html('consoleCryptoMetadata.needsWrite'));

    html += self.renderResidency(residency, t);

    html += kit.note(t.html('consoleCryptoMetadata.exporter'));

    html += PqcBadgeView.legend(t);

    // A key's label, its uses and its names are the view's.
    html += '<h2 id="keys">' + t.html('consoleCryptoMetadata.theKeyPairs') +
      '</h2>' +
      '<table><thead><tr><th class="n">' +
      t.html('consoleCryptoMetadata.thKey') + '</th><th>' +
      t.html('consoleCryptoMetadata.thType') + '</th><th>' +
      t.html('consoleCryptoMetadata.thIdentifier') + '</th><th>' +
      t.html('consoleCryptoMetadata.thScope') + '</th><th>' +
      t.html('consoleCryptoMetadata.thFormats') +
      '</th></tr></thead><tbody>' +
      report.keys.map(function (row) {
        return '<tr><td class="n"><a href="#key-' + esc(row.id) + '">' +
          esc(row.label) + '</a></td>' +
          '<td><code>' + esc(row.alg) + '</code> <code>' + esc(row.kty) +
          '</code>' + (row.crv ? ' <code>' + esc(row.crv) + '</code>' : '') +
          (row.bits ? ' ' + esc(row.bits) + '-bit' : '') +
          PqcBadgeView.badge(row.pqc, t) + '</td>' +
          '<td>' + (row.kid ? '<code>' + esc(row.kid) + '</code>'
                    : (row.fingerprint ?
                       '<code>' + esc(row.fingerprint) + '</code>'
                       : '<span class="why">' +
                         (row.generated === false
                           ? t.html('consoleCryptoMetadata.notMadeYet')
                           : t.html('consoleCryptoMetadata.none')) +
                         '</span>')) + '</td>' +
          '<td>' + (row.scope === 'realm'
                     ? t.html('consoleCryptoMetadata.scopeRealm')
                     : t.html('consoleCryptoMetadata.scopeProcess')) +
          '</td><td>' + (row.formats.length ? self.chips(row.formats)
                    : '<span class="why">' +
                      t.html('consoleCryptoMetadata.notExportable') +
                      '</span>') + '</td></tr>';
      }).join('') + '</tbody></table>';

    report.keys.forEach(function (row) {
      html += '<h3 id="key-' + esc(row.id) + '">' + esc(row.label) +
        PqcBadgeView.badge(row.pqc, t) + '</h3>' +
        '<table><tbody><tr><th class="n">' +
        t.html('consoleCryptoMetadata.usedFor') + '</th><td><ul>' +
        row.usedFor.map(function (what) {
          return '<li>' + self.prose(what) + '</li>';
        }).join('') + '</ul></td></tr>' +
        (row.subject ? '<tr><th class="n">' +
          t.html('consoleCryptoMetadata.subject') + '</th><td><code>' +
          esc(row.subject) + '</code></td></tr>' : '') +
        (row.names ? '<tr><th class="n">' +
          t.html('consoleCryptoMetadata.names') + '</th><td>' +
          self.chips(row.names) + '</td></tr>' : '') +
        (row.notAfter ? '<tr><th class="n">' +
          t.html('consoleCryptoMetadata.validTo') + '</th><td>' +
          esc(row.notAfter) + '</td></tr>' : '') +
        '</tbody></table>' +
        self.keyExportForm(row, t);
    });
    return html;
  }

  // ---------------------------------------------------------------------------
  // ONE FORM PER KEY, and it is a real form with a real button because this
  // console runs no script (`script-src 'none'`). The POST answers with the
  // FILE rather than with a redirect, which is the one place in this console a
  // form does not come back as a page — a download is what was asked for, and a
  // 303 to a page saying "your key is ready" would be a page with nothing on
  // it.
  // ---------------------------------------------------------------------------
  static keyExportForm(row, t) {
    if (!row.formats.length) {
      return kit.note(t.html('consoleCryptoMetadata.notExportableHead') +
        ' ' +
        (row.generated === false
          ? t.html('consoleCryptoMetadata.notExportablePq')
          : t.html('consoleCryptoMetadata.notExportableNone')));
    }
    return '<form method="post" action="/admin/keys/export" class="formrow">' +
      '<input type="hidden" name="key" value="' + esc(row.id) + '">' +
      '<label for="fmt-' + esc(row.id) + '">' +
      t.html('consoleCryptoMetadata.keystoreFormat') + '</label> ' +
      '<select id="fmt-' + esc(row.id) + '" name="format">' +
      row.formats.map(function (f) {
        return '<option value="' + esc(f) + '">' + esc(f.toUpperCase()) +
          (f === 'pkcs12' ? ' ' + t.html('consoleCryptoMetadata.p12') : '') +
          '</option>';
      }).join('') + '</select> ' +
      '<label for="pw-' + esc(row.id) + '">' +
      t.html('consoleCryptoMetadata.password') + '</label> ' +
      '<input type="password" id="pw-' + esc(row.id) + '" name="password" ' +
      'placeholder="' + esc(t.text('consoleCryptoMetadata.passwordHint')) +
      '"> <button type="submit">' +
      t.html('consoleCryptoMetadata.downloadKey') +
      '</button>' +
      (row.kty === 'AKP'
        ? kit.note(t.html('consoleCryptoMetadata.publicOnly'))
        : kit.note(t.html('consoleCryptoMetadata.passwordNote'))) +
      '</form>';
  }
}

export = CryptoMetadataPage;
