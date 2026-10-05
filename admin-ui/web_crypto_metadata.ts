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
  static verbCell(text) {
    const self = this;
    if (!text) {
      return '<span class="why">does not</span>';
    }
    return self.prose(text);
  }

  static anchorFor(name) {
    return 'fam-' + String(name).toLowerCase().replace(/[^a-z0-9]+/g, '-')
      .replace(/^-|-$/g, '');
  }

  static renderFamilies(report) {
    const self = this;
    let html = '<h2 id="families">The identity services this mock ' +
      'advertises</h2><p class="lead">One row per protocol family on <a ' +
      'href="/admin/sts-metadata">Service metadata</a>, with what each does ' +
      'with cryptography. The four verbs are kept apart on purpose: signing ' +
      'is minting something a relying party will believe, verifying is a ' +
      'decision that can be got wrong, encrypting uses somebody else\'s key, ' +
      'and decrypting means holding a private key a caller can aim ' +
      'ciphertext at. Those are four different exposures and this service ' +
      'does a different amount of each.</p>';

    const drift = report.drift;
    if (!drift.checked) {
      html += kit.warn('<strong>The family list was not checked against ' +
                         'the ' +
        'service metadata.</strong> This page names the identity services it ' +
        'reports on, and <code>/admin/sts-metadata</code> names the ones ' +
        'this process advertises; normally that module hands its list over ' +
        'at require time and both directions of drift are reported here. It ' +
        'did not, so the table below is this file\'s own word for what the ' +
        'service offers.');
    } else if (drift.undescribed.length || drift.stale.length ||
               drift.envelopes.length) {
      html += kit.warn('<strong>This page and the service metadata ' +
                         'disagree.' +
        '</strong> ' +
        (drift.undescribed.length
          ? 'Advertised with no crypto profile here: ' +
            self.chips(drift.undescribed) + '. '
          : '') +
        (drift.stale.length
          ? 'Profiled here and not advertised — which is what a rename ' +
            'produces: ' + self.chips(drift.stale) + '. '
          : '') +
        (drift.envelopes.length
          ? 'Citing an envelope with no row in the standards table: ' +
            self.chips(drift.envelopes) + '. '
          : '') +
        'Both directions are reported rather than reconciled, for the reason ' +
        '<code>/admin/sts-metadata</code> reports both directions of ' +
        'endpoint drift: the one that is silent is the one that costs an ' +
        'afternoon.');
    } else {
      html += '<p class="why">Checked against the service metadata: all ' +
        esc(report.families.length) + ' advertised families have a profile ' +
        'here, none is profiled that is not advertised, and every envelope ' +
        'cited has a row below.</p>';
    }

    html += '<table><thead><tr><th class="n">Identity service</th>' +
      '<th>Signs</th><th>Verifies</th><th>Encrypts</th><th>Decrypts</th>' +
      '</tr></thead><tbody>' +
      report.families.map(function (row) {
        return '<tr><td class="n"><a href="#' + esc(self.anchorFor(row.name)) +
          '">' + esc(row.name) + '</a></td>' +
          '<td>' + self.verbCell(row.signs) + '</td>' +
          '<td>' + self.verbCell(row.verifies) + '</td>' +
          '<td>' + self.verbCell(row.encrypts) + '</td>' +
          '<td>' + self.verbCell(row.decrypts) + '</td></tr>';
      }).join('') + '</tbody></table>';

    report.families.forEach(function (row) {
      html += '<h3 id="' + esc(self.anchorFor(row.name)) + '">' +
        esc(row.name) + '</h3>' +
        '<table><tbody>' +
        '<tr><th class="n">Hashing</th><td>' + self.prose(row.hashes) +
        '</td></tr>' +
        row.algorithms.map(function (group) {
          return '<tr><th class="n">' + esc(group.what) + '</th><td>' +
            self.chips(group.values) + '</td></tr>';
        }).join('') +
        '<tr><th class="n">Envelopes</th><td>' +
        row.envelopes.map(function (key) {
          const std = report.standards.filter(function (s) {
            return s.key === key;
          })[0];
          return std ? '<a href="#std-' + esc(key) + '">' + esc(std.name) +
                       '</a>' : '<code>' + esc(key) + '</code>';
        }).join(', ') + '</td></tr>' +
        '</tbody></table>' +
        kit.note('<strong>What it deliberately does not do.</strong> ' +
                   self.prose(row.whatItDoesNot));
    });
    return html;
  }

  // A "View details" link on a key row, opening the certificate dialog over
  // this page and closing back to this section. Nothing where the key holds no
  // certificate — a BBS key, a post-quantum key not made yet.
  static certificateLink(fingerprint, text?) {
    const html = CertificateDialogView.link('/admin/crypto-metadata',
                                            fingerprint, 'keys', text);
    return html ? '<br>' + html : '';
  }

  static renderKeys(report) {
    const self = this;
    const keys = report.keys;
    let html = '<h2 id="keys">The key material this process holds</h2><p ' +
      'class="lead">Every key here is generated at start and none of them is ' +
      'persisted, in any persistence mode. That is deliberate and two things ' +
      'depend on it: the <code>kid</code> is derived from the key material, ' +
      'so two instances of this mock cannot publish one name over two ' +
      'different keys, and every document that carries or describes a key is ' +
      'served <code>Cache-Control: no-store</code>. <strong>The signing keys ' +
      'are per trust realm; the TLS certificate and the SPIFFE authorities ' +
      'are not.</strong> This shows realm <code>' + esc(keys.realm) +
      '</code>.</p>';

    html += '<table><thead><tr><th class="n">Key</th><th>Type</th>' +
      '<th>Identifier</th><th>Scope</th></tr></thead><tbody>' +
      '<tr><td class="n">Signing key</td><td><code>RSA 2048</code> ' +
      '<code>RS256</code></td><td><code>' + esc(keys.signing.kid) +
      '</code>' + self.certificateLink(keys.signing.certificateFingerprint) +
      '</td><td>this realm</td></tr>' +
      keys.curveKeys.map(function (one) {
        return '<tr><td class="n">Curve key</td><td><code>' + esc(one.alg) +
          '</code> <code>' + esc(one.kty) +
          (one.crv ? '</code> <code>' + esc(one.crv) : '') +
          '</code></td><td><code>' + esc(one.kid) +
          '</code>' + self.certificateLink(one.certificateFingerprint) +
          '</td><td>this realm</td></tr>';
      }).join('') +
      (keys.postQuantum.generated
        ? keys.postQuantum.keys.map(function (one) {
            return '<tr><td class="n">Post-quantum key</td><td><code>' +
              esc(one.alg) + '</code> <code>AKP</code></td><td><code>' +
              esc(one.kid) + '</code>' +
              self.certificateLink(one.certificateFingerprint) +
              '</td><td>this realm</td></tr>';
          }).join('')
        : '<tr><td class="n">Post-quantum keys</td><td><code>AKP</code>, ' +
          esc(keys.postQuantum.algorithms.length) +
          ' algorithms</td><td><span class="why">not made yet in this realm' +
          '</span></td><td>this realm</td></tr>') +
      // THE SIGNER GROUPS (#68), one row per key, its hybrid partner named.
      keys.signerGroups.keys.map(function (one) {
        return '<tr><td class="n">Signer group <code>' + esc(one.group) +
          '</code></td><td><code>' + esc(one.alg) + '</code>' +
          (one.pairedSlot
            ? ' <span class="why">' + (one.kind === 'pq'
                ? 'alternative key of ' : 'hybrid with ') +
              esc(one.pairedSlot) + '</span>'
            : '') + '</td><td><code>' + esc(one.kid) + '</code>' +
          self.certificateLink(one.certificateFingerprint) +
          '</td><td>this realm</td></tr>';
      }).join('') +
      '<tr><td class="n">BBS key</td><td><code>' +
      esc(keys.bbs.cryptosuite) + '</code> ' + esc(keys.bbs.curve) +
      '</td><td><span class="why">published as publicKeyMultibase</span></td>' +
      '<td>this realm</td></tr>' +
      '<tr><td class="n">TLS certificate</td><td><code>RSA 2048</code> ' +
      '<code>SHA-256</code></td><td><code>' + esc(keys.tls.fingerprint256) +
      '</code>' + (keys.tls.certificates || []).map(function (one) {
        return self.certificateLink(one.certificateFingerprint,
                               'View details (' + one.algorithm + ')');
      }).join('') + '</td><td>the process</td></tr>' +
      '<tr><td class="n">SPIFFE X.509 authority</td><td><code>' +
      esc(keys.spiffe.authorityKeyType || keys.spiffe.x509KeyType) +
      '</code></td><td>' +
      (keys.spiffe.ready
        ? esc(keys.spiffe.x509Authorities) + ' authority/ies, ' +
          (keys.spiffe.authoritySource === 'pki'
            ? 'this realm\'s <a href="/admin/pki">SPIFFE Issuing CA</a>'
            : '<span class="why">self-signed &mdash; this realm has no ' +
              'certificate authority</span>') +
          self.certificateLink(keys.spiffe.authorityFingerprint)
        : '<span class="why">not started</span>') +
      '</td><td>this realm</td></tr>' +
      '<tr><td class="n">SPIFFE X509-SVID key</td><td><code>' +
      esc(keys.spiffe.svidKeyType) + '</code></td><td><span class="why">the ' +
      'key in each SVID, generated per mint &mdash; not the authority\'s' +
      '</span></td><td>this realm</td></tr>' +
      '<tr><td class="n">SPIFFE JWT authority</td><td><code>' +
      esc(keys.spiffe.jwtKeyType) + '</code></td><td>' +
      (keys.spiffe.ready ? esc(keys.spiffe.jwtAuthorities) + ' authority/ies'
                         : '<span class="why">not started</span>') +
      '</td><td>the process</td></tr>' +
      '</tbody></table>';

    html += kit.note('<strong>The post-quantum and BBS keys are made on ' +
      'first use, not at start.</strong> ' + self.prose(keys.postQuantum.what) +
      ' The consequence a reader meets is that the first JWKS fetch on a ' +
      'realm is slow — about two seconds, nearly all of it one SLH-DSA ' +
      'keygen — and every one after it is not.');
    html += kit.note('<strong>Nothing on this page is a secret.</strong> ' +
                       'Key ' +
      'types, key identifiers, curve names, certificate fingerprints and ' +
      'validity dates are all readable already from <code>/oauth2/jwks</code>' +
      ', <code>/tls/server-certificate</code> and the SPIFFE bundle ' +
      'endpoint. That is a rule for anything added here later rather than an ' +
      'observation about what is here now: a page about cryptography is ' +
      'exactly the page somebody would think to put a private key on.');
    return html;
  }

  static renderHashing(report) {
    const self = this;
    const h = report.hashing;
    let html = '<h2 id="hashing">Hashing</h2>' +
      '<p class="lead">Every digest this service computes. The first three ' +
      'tables are read from the modules that compute them; the fourth cannot ' +
      'be, because "SHA-256, because RFC 7638 says so" is a fact about a ' +
      'specification and not a row in a table — so each of those names the ' +
      'mechanism it belongs to.</p>';

    html += '<table><tbody>' +
      '<tr><th class="n">Digests behind the JWS algorithms</th><td>' +
      self.chips(h.jws) + ' <span class="why">EdDSA and the post-quantum ' +
      'algorithms name none — Ed25519 hashes internally and ML-DSA takes the ' +
      'message</span></td></tr>' +
      '<tr><th class="n">HTTP Digest (SCIM)</th><td>' +
      self.chips(h.scimDigest.map(function (r) { return r.token; })) +
      ' <span class="why">strongest first, and each checked against the ' +
      'openssl this process actually has</span></td></tr>' +
      '</tbody></table>';

    html += '<h3>XML DigestMethod</h3><table><thead><tr><th class="n">' +
            'URI</th>' +
      '<th>Label</th></tr></thead><tbody>' +
      h.xmlDigestMethods.map(function (row) {
        return '<tr><td class="n"><code>' + esc(row.uri) + '</code></td><td>' +
          esc(row.label) + '</td></tr>';
      }).join('') + '</tbody></table>';

    html += '<h3>Fixed uses</h3><table><thead><tr><th class="n">Where</th>' +
      '<th>Digest</th><th>What</th></tr></thead><tbody>' +
      h.fixed.map(function (row) {
        return '<tr><td class="n">' + self.prose(row.where) +
          '</td><td><code>' + esc(row.hash) + '</code></td><td>' +
          self.prose(row.what) + '</td></tr>';
      }).join('') + '</tbody></table>';

    html += '<h3>The weak ones, and why they are here</h3>' +
      kit.note('<strong>None of these is an oversight and none is a ' +
        'recommendation.</strong> This service exists to exercise other ' +
        'people\'s clients, and a mock that offered only the safe choice ' +
        'could not be used to show what the unsafe one does. Each row says ' +
        'which ' +
        'installed base asks for it.') +
      '<table><thead><tr><th class="n">Digest</th><th>Where</th><th>Why</th>' +
      '</tr></thead><tbody>' +
      h.weak.map(function (row) {
        return '<tr><td class="n"><code>' + esc(row.hash) + '</code></td><td>' +
          self.prose(row.where) + '</td><td>' + self.prose(row.why) +
          '</td></tr>';
      }).join('') + '</tbody></table>';
    return html;
  }

  static renderSignatures(report) {
    const self = this;
    const s = report.signatures;
    let html = '<h2 id="signatures">Signatures and MACs</h2>' +
      '<p class="lead">Read from the module that performs each one. The JWS ' +
      'table is <em>the</em> table for this service — there were two once, ' +
      'which is how DPoP came to accept a different set of algorithms from ' +
      'everything else for no reason anybody chose.</p>';

    html += '<h3>JWS</h3><table><thead><tr><th class="n">alg</th><th>' +
      'Family</th><th>Key</th><th>Digest</th><th>Asymmetric</th><th>DPoP</th>' +
      '</tr></thead><tbody>' +
      s.jws.map(function (row) {
        return '<tr><td class="n"><code>' + esc(row.alg) + '</code></td>' +
          '<td>' + esc(row.family) +
          (row.composite ? ' <span class="why">composite</span>' : '') +
          '</td>' +
          '<td><code>' + esc(row.kty) + '</code>' +
          (row.crv ? ' <code>' + esc(row.crv) + '</code>' : '') + '</td>' +
          '<td>' + (row.hash ? '<code>' + esc(row.hash) + '</code>'
                             : '<span class="why">none</span>') + '</td>' +
          '<td>' + (row.asymmetric ? 'yes' : 'no — a MAC') + '</td>' +
          '<td>' + (row.dpop ? 'yes' : 'no') + '</td></tr>';
      }).join('') + '</tbody></table>' +
      kit.note('<strong>The DPoP column is a filter over this table and ' +
                 'not ' +
        'a table of its own.</strong> It excludes the HMAC family because ' +
        'RFC 9449 section 4.2 requires an asymmetric algorithm, and it ' +
        'excludes every post-quantum one because a DPoP proof is bound ' +
        'through the RFC 7638 thumbprint — which is defined for RSA, EC, OKP ' +
        'and oct and not for <code>AKP</code>. A proof signed with ML-DSA ' +
        'would verify perfectly and bind to nothing, which is worse than a ' +
        'refusal.');

    html += '<h3>XML SignatureMethod</h3>' +
      '<p class="lead">This service <strong>signs</strong> with one of these ' +
      'and <strong>verifies</strong> any of them — the asymmetry is the ' +
      'point of the vendored implementation, which is the other end of most ' +
      'of these exchanges.</p><table><thead><tr><th class="n">URI</th><th>' +
      'Label</th><th>Key</th><th>Signs with</th></tr></thead><tbody>' +
      s.xml.map(function (row) {
        return '<tr><td class="n"><code>' + esc(row.uri) + '</code></td><td>' +
          esc(row.label) + '</td><td><code>' + esc(row.keyKind) +
          '</code></td><td>' + (row.signsWith ? 'yes' : '<span class="why">' +
          'verify only</span>') + '</td></tr>';
      }).join('') + '</tbody></table>';

    html += '<h3>Canonicalization</h3>' +
      '<table><thead><tr><th class="n">URI</th><th>Label</th>' +
      '<th>Used here</th></tr></thead><tbody>' +
      s.canonicalization.map(function (row) {
        return '<tr><td class="n"><code>' + esc(row.uri) + '</code></td><td>' +
          esc(row.label) + '</td><td>' + (row.usedHere
            ? 'yes — the default at every call site'
            : '<span class="why">read only</span>') + '</td></tr>';
      }).join('') + '</tbody></table>' +
      kit.note('<strong>Exclusive canonicalization is load-bearing here ' +
                 'and ' +
        'not a matter of taste.</strong> An assertion is signed as a ' +
        'standalone document and then embedded inside an RSTR, a Response or ' +
        'a <code>wresult</code> that declares prefixes of its own. Inclusive ' +
        'c14n would pull those ancestor declarations into the digest at ' +
        'verification time, so the signature would fail for every relying ' +
        'party while verifying perfectly here — the worst shape of bug to ' +
        'chase. C14N 1.1 is not offered at all: its whole difference is how ' +
        '<code>xml:base</code>, <code>xml:lang</code> and <code>' +
        'xml:space</code> inherit into a detached subtree, this engine does ' +
        'not implement that inheritance, and an option naming a method it ' +
        'does not perform is worse than an absent one.');

    html += '<h3>COSE (WebAuthn)</h3><table><thead><tr>' +
      '<th class="n">COSE alg</th><th>JOSE name</th></tr></thead><tbody>' +
      s.cose.map(function (row) {
        return '<tr><td class="n"><code>' + esc(row.coseAlg) +
          '</code></td><td><code>' + esc(row.jose) + '</code></td></tr>';
      }).join('') + '</tbody></table>';

    html += '<h3>Everything else</h3><table><thead><tr><th class="n">' +
            'What</th>' +
      '<th>Detail</th></tr></thead><tbody>' +
      s.other.map(function (row) {
        return '<tr><td class="n">' + esc(row.name) + '</td><td>' +
          self.prose(row.what) + '</td></tr>';
      }).join('') + '</tbody></table>';
    return html;
  }

  static renderEncryption(report) {
    const self = this;
    const e = report.encryption;
    let html = '<h2 id="encryption">Encryption and key transport</h2><p ' +
      'class="lead">What this service encrypts with, and — separately — what ' +
      'it will decrypt. The two lists are different on purpose in both JOSE ' +
      'and XML, and the reason is the same each time: it holds one private ' +
      'key of each kind and can encrypt to anybody\'s.</p>';

    html += '<h3>JWE</h3><table><tbody>' +
      '<tr><th class="n">Key management, encrypting</th><td>' +
      self.chips(e.jwe.keyManagementOut) + '</td></tr>' +
      '<tr><th class="n">Key management, decrypting</th><td>' +
      // **IT IS THE LONGER LIST NOW AND THIS NOTE SAID "shorter on purpose".**
      // It was written when the decrypt list was `['RSA-OAEP-256']` alone; the
      // symmetric families arrived in `crypto.js` and the two lists swapped
      // ends, leaving the page explaining an asymmetry in the direction it no
      // longer has.
      self.chips(e.jwe.keyManagementIn) + ' <span class="why">longer on ' +
      'purpose, and it is the row above that is narrow: this service ' +
      'encrypts OUTWARD to a recipient\'s published key and shares no secret ' +
      'with it, so it offers the asymmetric families only — while what ' +
      'ARRIVES may be wrapped with a key the sender already holds, and a ' +
      'caller picks by what it has rather than by what this table ' +
      'permits</span></td></tr>' +
      '</tbody></table><table><thead><tr><th class="n">enc</th><th>Bits</th>' +
      '<th>Mode</th><th>CEK</th><th>Note</th></tr></thead><tbody>' +
      e.jwe.contentEncryption.map(function (row) {
        return '<tr><td class="n"><code>' + esc(row.enc) + '</code></td><td>' +
          esc(row.bits) + '</td><td><code>' + esc(row.mode) +
          '</code></td><td>' + esc(row.cekBytes) + ' bytes</td><td>' +
          esc(row.note) + '</td></tr>';
      }).join('') + '</tbody></table>' +
      kit.note('<strong>The CBC-HMAC family is here because it is what an ' +
        'OpenID Connect client gets by default.</strong> Register <code>' +
        'userinfo_encrypted_response_alg</code> and say nothing about <code>' +
        'enc</code>, and section 2 of the registration specification has ' +
        'chosen <code>A128CBC-HS256</code> for you. A service that spoke ' +
        'only AES-GCM would refuse the commonest encrypted response there ' +
        'is, and would look to the client like it had refused the request.');

    html += '<h3>XML Encryption</h3>' +
      '<p class="lead">The configured choice is what the next encrypted ' +
      'assertion will actually use; both settings are editable on ' +
      '<a href="/admin/saml2">SAML 2.0</a>. Right now: block cipher <code>' +
      esc(e.xml.configured.blockCipher) + '</code>, key transport <code>' +
      esc(e.xml.configured.keyTransport) + '</code>, assertions ' +
      (e.xml.configured.encryptAssertion ? 'encrypted' : 'not encrypted') +
      ', logout NameID ' +
      (e.xml.configured.encryptLogoutNameId ? 'encrypted' : 'not encrypted') +
      '.</p>' +
      '<table><thead><tr><th class="n">Block cipher</th><th>URI</th>' +
      '<th>Key</th><th>Authenticated</th></tr></thead><tbody>' +
      e.xml.blockCiphers.map(function (row) {
        return '<tr><td class="n"><code>' + esc(row.name) +
          '</code></td><td><code>' + esc(row.uri) + '</code></td><td>' +
          esc(row.keyBits) + '-bit ' + esc(row.mode) + '</td><td>' +
          (row.authenticated ? 'yes' : '<strong>no</strong>') + '</td></tr>';
      }).join('') + '</tbody></table>' +
      '<table><thead><tr><th class="n">Key transport</th><th>URI</th>' +
      '<th>Scheme</th></tr></thead><tbody>' +
      e.xml.keyTransports.map(function (row) {
        return '<tr><td class="n"><code>' + esc(row.name) +
          '</code></td><td><code>' + esc(row.uri) + '</code></td><td>' +
          esc(row.scheme) + (row.safe ? '' : ' — <strong>broken</strong>') +
          '</td></tr>';
      }).join('') + '</tbody></table>' +
      kit.warn('<strong>Two of these are unsafe and are offered ' +
        'anyway.</strong> The CBC ciphers are not authenticated — that is ' +
        'the property CBC has, not a defect in this service — and what this ' +
        'service does about it when READING is parse the result and refuse ' +
        'anything that is not well-formed XML, which catches ordinary ' +
        'corruption and is not integrity. <code>rsa-1_5</code> is ' +
        'RSAES-PKCS1-v1_5, which Bleichenbacher\'s adaptive ' +
        'chosen-ciphertext attack is against exactly. Both are here because ' +
        'a great many deployed service providers accept nothing else, which ' +
        'is a fact about the world that a client library is entitled to be ' +
        'tested against. Nothing this service encrypts is a real secret. ' +
        '<code>rsa-oaep-mgf1p</code> is SHA-1 by definition — the URI means ' +
        'it — and the newer <code>rsa-oaep</code> carries its digest in a ' +
        'child element and is offered since #168 with SHA-256 and ' +
        'MGF1-SHA-256, which is what a federation relationship publishes and ' +
        'requires. A recipient whose certificate is EC is encrypted to by ' +
        'ECDH-ES key agreement (ConcatKDF, kw-aes256).');

    html += '<h3>Kerberos encryption types</h3>' +
      '<table><thead><tr><th class="n">etype</th><th>Name</th>' +
      '<th>Performed</th></tr></thead><tbody>' +
      e.kerberos.performed.map(function (row) {
        return '<tr><td class="n"><code>' + esc(row.id) +
          '</code></td><td><code>' + esc(row.name) +
          '</code></td><td>yes</td></tr>';
      }).join('') +
      e.kerberos.decodeOnly.map(function (row) {
        return '<tr><td class="n"><code>' + esc(row.id) +
          '</code></td><td><code>' + esc(row.name) +
          '</code></td><td><span class="why">decode only</span></td></tr>';
      }).join('') + '</tbody></table>' +
      kit.note('<strong>The decode-only rows are named rather than left as ' +
        'bare numbers, and that is the whole reason they are in the ' +
        'codec.</strong> A packet capture or a KDC\'s advertised list ' +
        'containing one of them renders honestly instead of showing an ' +
        'integer nobody can look up. DES was removed from Windows Server ' +
        '2025 and is not performed here either. This table is read back out ' +
        'of the codec through its own <code>etypeName()</code>, not copied — ' +
        'those modules are vendored and cannot be edited to export a list.');

    html += '<h3>TLS</h3>' + kit.note('<strong>' + self.prose(e.tls.what) +
      '</strong> The sockets: ' + self.chips(e.tls.sockets) + '.');
    return html;
  }

  static renderPostQuantum(report) {
    const self = this;
    const pq = report.postQuantum;
    let html = '<h2 id="post-quantum">Post-quantum readiness</h2>' +
      '<p class="lead"><strong>The headline is one sentence and it is not ' +
      'the flattering one: this service\'s signatures are partly ' +
      'post-quantum and its key establishment is entirely ' +
      'classical.</strong> Those two halves are in very different positions, ' +
      'and a page that said "supports ML-DSA" without separating them would ' +
      'be making the kind of claim this repository exists not to make.</p>' +
      kit.note('<strong>The two halves differ because of the threat, not ' +
                 'the ' +
        'effort.</strong> A signature is verified at the moment it is ' +
        'presented, so a signature algorithm that falls to a quantum ' +
        'computer in 2035 is a problem in 2035. A key agreement is not: ' +
        'ciphertext captured today can be kept and opened when the machine ' +
        'arrives, which is what "harvest now, decrypt later" names. So the ' +
        'surface here that ' +
        'most needs a post-quantum answer is the one that has none.') +
      kit.note('<strong>Symmetric cryptography is a third category and is ' +
        'the one people get wrong.</strong> ' + self.prose(pq.symmetric.what) +
        ' The strongest this service performs: ' +
        self.prose(pq.symmetric.strongest));

    html += '<h3>The post-quantum algorithms this service holds</h3>' +
      '<table><tbody>' +
      '<tr><th class="n">ML-DSA (FIPS 204)</th><td>' +
      self.chips(pq.algorithms.mlDsa) +
      '</td></tr>' +
      '<tr><th class="n">SLH-DSA (FIPS 205)</th><td>' +
      self.chips(pq.algorithms.slhDsa) +
      '</td></tr>' +
      '<tr><th class="n">Key type</th><td><code>' + esc(pq.algorithms.keyType) +
      '</code></td></tr>' +
      '</tbody></table>' +
      '<table><thead><tr><th class="n">Composite</th><th>ML-DSA half</th>' +
      '<th>Traditional half</th><th>Domain separator</th></tr></thead><tbody>' +
      pq.algorithms.composite.map(function (row) {
        return '<tr><td class="n"><code>' + esc(row.alg) +
          '</code></td><td><code>' + esc(row.mlDsa) +
          '</code></td><td><code>' + esc(row.traditional) +
          '</code></td><td><code>' + esc(row.domainSeparator) +
          '</code></td></tr>';
      }).join('') + '</tbody></table>' +
      kit.note('<strong>What the composites buy, and what the domain ' +
        'separator is for.</strong> ' + self.prose(pq.algorithms.what)) +
      kit.note('<strong>Where the independence is, and where it is ' +
                 'not.</strong> ' +
        self.prose(pq.algorithms.independence));

    html += '<h3>Signatures, surface by surface</h3>' +
      '<table><thead><tr><th class="n">Surface</th><th>State</th><th>How</th>' +
      '</tr></thead><tbody>' +
      pq.signatures.map(function (row) {
        return '<tr><td class="n">' + esc(row.surface) + '</td><td>' +
          (row.state === 'pq'
            ? '<strong>post-quantum available</strong>'
            : '<span class="why">classical only</span>') +
          '</td><td>' + self.prose(row.how) + '</td></tr>';
      }).join('') + '</tbody></table>';

    html += '<h3>Key establishment, surface by surface</h3>' +
      kit.note('<strong>Post-quantum and hybrid key establishment ' +
                 '(#82).</strong> ' + self.prose(pq.keyEstablishment.what)) +
      '<table><thead><tr><th class="n">Surface</th><th>State</th><th>How' +
      '</th></tr></thead><tbody>' +
      pq.keyEstablishment.surfaces.map(function (row) {
        return '<tr><td class="n">' + esc(row.surface) + '</td><td>' +
          (row.state === 'pq'
            ? '<strong>post-quantum available</strong> ' +
              PqcBadgeView.badge({ kind: 'kem', label: 'ML-KEM / HPKE',
                               standard: 'draft-ietf-jose-pqc-kem-05, ' +
                                 'draft-reddy-cose-jose-pqc-hybrid-hpke-11' })
            : row.state === 'optional'
              ? '<span class="why">post-quantum available, not enabled' +
                '</span>'
              : '<span class="why">classical only</span>') +
          '</td><td>' + self.prose(row.how) + '</td></tr>';
      }).join('') + '</tbody></table>' +
      '<table><tbody><tr><th class="n">Post-quantum JWE algorithms</th><td>' +
      self.chips(pq.keyEstablishment.postQuantum) + '</td></tr>' +
      '<tr><th class="n">Of which PQ/T hybrid</th><td>' +
      self.chips(pq.keyEstablishment.hybrid) + '</td></tr>' +
      '<tr><th class="n">Every mechanism</th><td>' +
      self.chips(pq.keyEstablishment.mechanisms) + '</td></tr>' +
      '<tr><th class="n">Drafts implemented</th><td>' +
      self.prose(pq.keyEstablishment.drafts.mlKem) + '<br>' +
      self.prose(pq.keyEstablishment.drafts.hpke) + '<br>' +
      self.prose(pq.keyEstablishment.drafts.hybrid) + '</td></tr>' +
      '<tr><th class="n">What remains</th><td>' +
      self.prose(pq.keyEstablishment.whatWouldClose) +
      '</td></tr></tbody></table>';
    return html;
  }

  static renderStandards(report) {
    const self = this;
    let html = '<h2 id="standards">The higher-level standards</h2><p ' +
      'class="lead">Knowing that this service signs with RSA-SHA256 does not ' +
      'say whether that signature is a JWS, an enveloped XMLDSIG, a detached ' +
      'signature over a query string or a <code>&lt;wsse:Security&gt;</code> ' +
      'header — four different documents with four different failure modes. ' +
      'This is that layer. <strong>Every coverage note starts ' +
      '<code>full</code>, <code>partial</code> or <code>mock</code></strong> ' +
      'and says what is missing, which is the rule <a ' +
      'href="/admin/sts-metadata">Service metadata</a> follows and which is ' +
      'worth more here: a page about cryptography that overstates what it ' +
      'implements is actively dangerous to somebody using it to learn.</p>';

    html += report.standards.map(function (row) {
      return '<h3 id="std-' + esc(row.key) + '">' + esc(row.name) + '</h3>' +
        '<table><tbody>' +
        '<tr><th class="n">Specifications</th><td>' + self.chips(row.specs) +
        '</td></tr>' +
        '<tr><th class="n">Coverage</th><td>' + self.prose(row.coverage) +
        '</td></tr><tr><th ' +
        'class="n">What it is here</th><td>' + self.prose(row.what) +
        '</td></tr>' +
        '</tbody></table>';
    }).join('');
    return html;
  }

  static renderInner(report) {
    const self = this;
    let html = '<p class="lead">What this service does when it signs, ' +
      'verifies, encrypts or decrypts something — for every identity service ' +
      'it advertises, with the algorithms each one really uses and the ' +
      'higher-level envelope each is wrapped in. <strong>Every algorithm ' +
      'table below is read from the module that performs the ' +
      'algorithm</strong>, the way <a href="/admin/sts-metadata">Service ' +
      'metadata</a> reads its endpoint list off the live router, so none of ' +
      'it can claim something this service does not do.</p>';

    html += '<p><a class="btn" href="/admin/crypto-metadata?format=json" ' +
      'download="crypto-metadata.json" title="The whole of this page as ' +
      'JSON: every identity service, every algorithm table, the post-quantum ' +
      'posture and the standards list">Download all of this as JSON</a> ' +
      '<span class="why">' + esc(report.families.length) +
      ' identity services, ' + esc(report.signatures.jws.length) +
      ' JWS algorithms, ' + esc(report.standards.length) +
      ' standards</span></p>';

    html += kit.note('<strong>There is one place in this service that ' +
                       'signs, ' +
      'verifies, encrypts and decrypts, and this page is its ' +
      'report.</strong> Before 2026-08-27 all four happened in about twenty ' +
      'places: six independent XML signers, four independent XML signature ' +
      'verifiers, ten <code>jwt.verify()</code> calls of which four had ' +
      'quietly stopped applying the configured clock skew, two RFC 7638 ' +
      'thumbprints and two self-signed certificate builders. None of that ' +
      'was carelessness — each was written where it was needed and the ' +
      'copies agreed on the day they were made. What it cost is on the ' +
      'record: every SAML 1.1 assertion this service ever issued carried an ' +
      '<code>Id="_0"</code> attribute the schema does not have, and three of ' +
      'the four verifiers took the FIRST <code>&lt;ds:Signature&gt;</code> ' +
      'in the document — which on a Response carrying a signed assertion is ' +
      'the assertion\'s, so a caller asking "is this Response signed by us" ' +
      'was answered about a different element and told yes.');

    html += '<p class="lead">On this page: ' +
      '<a href="#families">the identity services</a> &middot; ' +
      '<a href="#keys">key material</a> &middot; ' +
      '<a href="#hashing">hashing</a> &middot; ' +
      '<a href="#signatures">signatures and MACs</a> &middot; ' +
      '<a href="#encryption">encryption</a> &middot; ' +
      '<a href="#post-quantum">post-quantum readiness</a> &middot; ' +
      '<a href="#standards">the standards</a></p>';

    html += self.renderFamilies(report);
    html += self.renderKeys(report);
    html += self.renderHashing(report);
    html += self.renderSignatures(report);
    html += self.renderEncryption(report);
    html += self.renderPostQuantum(report);
    html += self.renderStandards(report);
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
    return this.renderInner(json) + (json.certificateDetails
      ? CertificateDialogView.dialog('/admin/crypto-metadata',
                                 json.certificateDetails, ctx.query.from)
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
    return this.renderRotation(json.rotation, ctx.write) +
      this.renderKeyPairs(json) +
      '<p>Every signer of this realm, each key generation ' +
      'with its chain, is published anonymously in the ' +
      '<a href="' + esc(json.issuer + '/crypto/metadata.json') +
      '">crypto metadata document</a> (also as <a href="' +
      esc(json.issuer + '/crypto/metadata.xml') +
      '">XML</a>).</p>' +
      '<h2>Settings</h2>' + SettingsForms.forms(json.settings, '/admin/keys');
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
    const lead = '<p>Every signing key this realm has held, kept for ever: ' +
      'when it was minted, promoted, retired and dropped, and the ' +
      'certificate that vouched for it. <strong>The private half is still ' +
      'thrown away</strong> when a retired key passes its grace ' +
      '(<code>signing.retire</code>) — what survives here is the record ' +
      'that the key existed and the public certificate, so a signature or a ' +
      'chain captured months ago can still be read back. Nothing on this ' +
      'page can produce a signature.</p>' +
      '<p><a href="/admin/keys">&larr; Key pairs</a></p>';
    if (!view.observed) {
      return lead + '<p class="warn">This process does not hold the ' +
             'signing-key history module, so no history can be drawn.</p>';
    }
    const index = '<h2>Units</h2>' + (view.units.length
      ? '<table class="data"><thead><tr><th>Unit</th><th>Generations</th>' +
        '<th>Held now</th><th>Dropped</th><th>With a certificate</th>' +
        '</tr></thead><tbody>' + view.units.map(function (u) {
          return '<tr><td><a href="' +
            esc('/admin/keys/history?unit=' + encodeURIComponent(u.unit)) +
            '"><code>' + esc(u.unit) + '</code></a></td><td>' +
            esc(String(u.generations)) + '</td><td>' + esc(String(u.live)) +
            '</td><td>' + esc(String(u.dropped)) + '</td><td>' +
            esc(String(u.withCertificate)) + '</td></tr>';
        }).join('') + '</tbody></table>'
      : '<p>No key of this realm has been observed yet. A realm records its ' +
        'keys when this page is opened and whenever one is minted, rotated ' +
        'or dropped.</p>');
    if (!view.unit) {
      return lead + index;
    }
    if (!view.found) {
      return lead + '<p class="warn">This realm has no record of a signing ' +
             'unit called <code>' + esc(view.unit) + '</code>.</p>' + index;
    }
    const nav = kit.pageNavPair('/admin/keys/history',
                                  { unit: view.unit }, view.paging);
    const rows = view.rows.map(function (row) {
      const cert = row.certificate;
      return '<tr><td><code>' + esc(row.kid) + '</code></td>' +
        '<td>' + esc(row.role) + '</td>' +
        '<td>' + esc(row.createdAt || row.firstSeenAt || '') + '</td>' +
        '<td>' + esc(row.promotedAt || '&mdash;') + '</td>' +
        '<td>' + esc(row.retiredAt || '&mdash;') +
        (row.verifiesUntil ? '<br>verified until ' + esc(row.verifiesUntil)
         : '') + '</td>' +
        '<td>' + esc(row.droppedAt || '&mdash;') + '</td>' +
        '<td>' + esc(row.reason || '&mdash;') + '</td>' +
        '<td>' + (cert
          ? '<code>' + esc(cert.serialHex) + '</code><br>' +
            esc(cert.notBefore) + ' &ndash; ' + esc(cert.notAfter) +
            '<br><a href="' +
            esc('/admin/keys/history/certificate?unit=' +
                encodeURIComponent(view.unit) + '&kid=' +
                encodeURIComponent(row.kid)) + '">The certificate and its ' +
            'chain (PEM)</a>'
          : 'none') + '</td></tr>';
    }).join('');
    const out = lead + '<h2>' + esc(view.unit) + '</h2>' + nav.head +
      '<table class="data"><thead><tr><th>Key</th><th>Role</th>' +
      '<th>Minted</th><th>Promoted</th><th>Retired</th><th>Dropped</th>' +
      '<th>Why</th><th>Certificate</th></tr></thead><tbody>' + rows +
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
  static renderRotation(view, canWrite) {
    if (!view) {
      return '';
    }
    const rows = view.units.map(function (u) {
      return '<tr>' +
        (canWrite ? '<td><input type="checkbox" name="units" value="' +
                    esc(u.unit) + '" id="rotate-unit-' + esc(u.unit) +
                    '"></td>' : '') +
        '<td><code>' + esc(u.unit) + '</code>' +
        (u.credentialSigner ? ' <em>(credentials)</em>' : '') + '</td>' +
        '<td><code>' + esc(u.current) + '</code></td>' +
        '<td>' + (u.next ? '<code>' + esc(u.next.kid) + '</code><br>since ' +
                  esc(u.next.since || '') : '—') + '</td>' +
        '<td>' + (u.retired.length ? u.retired.map(function (r) {
          return '<code>' + esc(r.kid) + '</code> until ' +
                 esc(r.verifiesUntil || '');
        }).join('<br>') : '—') + '</td>' +
        '<td>' + esc(u.lastRotated || 'never') + '</td>' +
        '<td>' + esc(String(u.intervalDays)) + ' / ' +
        esc(String(u.graceDays)) + '</td>' +
        // EVERY GENERATION THIS UNIT HAS EVER HAD (#42's follow-up). The row
        // above it says what the realm holds NOW; the private half of
        // anything older is gone, and this is where the record of it is.
        '<td><a href="' +
        esc('/admin/keys/history?unit=' + encodeURIComponent(u.unit)) +
        '">History</a></td></tr>';
    }).join('');
    const table = '<table class="data"><thead><tr>' +
      (canWrite ? '<th>Rotate</th>' : '') +
      '<th>Unit</th><th>Current</th><th>Next</th><th>Retired, verifying ' +
      'until</th><th>Last rotated</th><th>Interval / grace (days)</th>' +
      '<th>Every generation</th>' +
      '</tr></thead><tbody>' + rows + '</tbody></table>';
    const status = '<p>' + (view.scheduled
      ? 'Scheduled rotation is <strong>on</strong>: each next key is ' +
        'promoted once it has been published for a whole interval ' +
        '(<code>signing.rotate</code>, hourly).'
      : 'Scheduled rotation is <strong>off</strong>: ' + esc(view.offReason) +
        '. A rotation by hand still works.') +
      ' The refresh-token encryption keys rotate with every unit; ' +
      esc(String(view.refresh.retired)) + ' retired set(s) still open old ' +
      'refresh tokens (grace ' + esc(String(view.refresh.graceDays)) +
      ' days).</p>';
    if (!canWrite) {
      return '<h2>Rotation</h2>' + status + table;
    }
    const out = '<h2>Rotation</h2>' + status +
      '<form method="post" action="/admin/keys/rotate">' +
      '<input type="hidden" name="action" value="rotate">' + table +
      '<p><button type="submit" id="keys-rotate-selected">Rotate ' +
      'selected</button> ' +
      '<button type="submit" name="units" value="all" ' +
      'id="keys-rotate-all">Rotate all</button> — the next key of each ' +
      'becomes current and the key it replaces goes on verifying through ' +
      'its grace.</p></form>' +
      '<h3>Emergency rotation</h3>' +
      '<p class="warn">For keys presumed <strong>compromised</strong>. ' +
      'Every key of every unit is replaced with a NEW key — the published ' +
      'next keys too — with no grace; their certificates are revoked for ' +
      'keyCompromise; the refresh-token keys are replaced; and EVERY ' +
      'session of this realm is ended, with CAEP session-revoked and RISC ' +
      'sessions-revoked sent. Everything already issued stops verifying at ' +
      'once. It cannot be undone.</p>' +
      '<form method="post" action="/admin/keys/rotate">' +
      '<input type="hidden" name="action" value="emergency">' +
      '<label>Type <code>compromised</code> to confirm: <input type="text" ' +
      'name="confirm" id="keys-emergency-confirm" autocomplete="off">' +
      '</label> <button type="submit" id="keys-emergency">Rotate every key ' +
      'now</button></form>';
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
  static renderResidency(residency) {
    if (!residency.persisting) {
      return kit.note('<strong>Nothing here is held encrypted in memory, ' +
        'because nothing here is written down.</strong> This service ' +
        'generates its signing key at start and keeps it for as long as it ' +
        'runs — there is no ciphertext for a decrypted key to be purged back ' +
        'TO, so <code>keys.plaintextRetention</code> means nothing in this ' +
        'configuration. It is the keystore that makes it apply, and <code>' +
        'keys.source</code> is what turns that on.');
    }
    const held = residency.plaintextHeld || [];
    const all = residency.realmsHeld || [];
    let html = '<h2 id="residency">How long a private key stays decrypted</h2>';
    html += kit.note('<strong>What this process holds is the ' +
      'CIPHERTEXT.</strong> A realm\'s signing key is decrypted when ' +
      'something signs with it and dropped again ' +
      '— ' + esc(residency.note || '') + '. It narrows a WINDOW ' +
      'and nothing more: the key-encryption key is resident too, so anybody ' +
      'who can read this process\'s memory at a moment of their choosing can ' +
      'wait for the next signature. What it takes away is the value of a ' +
      'SNAPSHOT — a core dump, a swapped page, a debugger attached for a ' +
      'moment — of material that used to sit here for weeks.');
    html += '<table><thead><tr><th class="n">Realm</th><th>Held</th>' +
      '<th>Decrypted right now</th></tr></thead><tbody>' +
      (all.length
        ? all.map(function (id) {
            const open = held.indexOf(id) >= 0;
            return '<tr><td class="n"><code>' + esc(id || 'default') +
              '</code></td><td>encrypted, ' +
              'AES-256-GCM</td><td>' + (open ? '<strong>yes</strong>'
                             : '<span class="why">no</span>') + '</td></tr>';
          }).join('')
        : '<tr><td colspan="3"><span class="why">no realm has stored key ' +
          'material yet</span></td></tr>') +
      '</tbody></table>';
    html += kit.note('A realm reads <strong>no</strong> here until ' +
                       'something ' +
      'signs for it, and goes back to <strong>no</strong> on its own. ' +
      'Reading this page does not decrypt anything: the key list above is ' +
      'built from the PUBLIC half — certificates, key identifiers, public ' +
      'JWKs — which the key set holds in the clear precisely so that ' +
      'discovery and this console never touch a private key. Exporting one ' +
      'does.');
    return html;
  }

  static renderKeyPairs(report) {
    const self = this;
    const residency = report.residency || {};
    let html = '<p class="lead">Every key pair this process holds, what each ' +
      'one is used for, and a way to take it away. <strong>The signing keys ' +
      'are per trust realm</strong> — this shows <code>' + esc(report.realm) +
      '</code> — and the TLS certificate belongs to the process.</p>';

    // **THE OLD WARNING SAID THESE KEYS DIE WITH THE PROCESS, FULL STOP.** That
    // was true of every key in this service until the keystore landed, and it
    // is the sentence that makes handing a private key to a browser defensible
    // — so leaving it standing on a service whose signing key now OUTLIVES the
    // process would be this console's most consequential untruth. It is
    // computed.
    html += kit.warn('<strong>THIS PAGE HANDS OVER PRIVATE KEYS, and it is ' +
      'the only one here that does.</strong> <a ' +
      'href="/admin/crypto-metadata">Cryptography</a> next door publishes ' +
      'key types, identifiers and fingerprints and deliberately no key ' +
      'material at all; this one is the other half. ' +
      (residency.persisting
        ? '<strong>This realm\'s signing keys are PERSISTED</strong>, so a ' +
          'key exported here is not a throwaway: it goes on signing after a ' +
          'restart, and anything signed with a copy of it goes on verifying ' +
          'against this service\'s live JWKS. The TLS and SPIFFE keys below ' +
          'are still per start. '
        : 'It is defensible because of what these keys are: generated at ' +
          'start, held only in memory, dead when the process exits, and ' +
          'protecting nothing — this service checks no password and ' +
          'validates ' +
          'no token it did not mint. ') +
      'It needs <strong>Admin Write</strong>, which is a stronger ' +
      'requirement than any other read on this console, because here reading ' +
      'IS taking.');

    html += self.renderResidency(residency);

    html += kit.note('<strong>The exporter is the debugger\'s own, ' +
      'vendored.</strong> <code>common/vendored/key_material.js</code> does ' +
      'the four formats with a password — PEM, DER, JWK and PKCS#12 — and is ' +
      'the same code the debugger\'s PKI page has been exercised through. A ' +
      'second exporter beside it would be the worse copy.');

    html += PqcBadgeView.legend();

    html += '<h2 id="keys">The key pairs</h2>' +
      '<table><thead><tr><th class="n">Key</th><th>Type</th><th>' +
      'Identifier</th><th>Scope</th><th>Formats</th></tr></thead><tbody>' +
      report.keys.map(function (row) {
        return '<tr><td class="n"><a href="#key-' + esc(row.id) + '">' +
          esc(row.label) + '</a></td>' +
          '<td><code>' + esc(row.alg) + '</code> <code>' + esc(row.kty) +
          '</code>' + (row.crv ? ' <code>' + esc(row.crv) + '</code>' : '') +
          (row.bits ? ' ' + esc(row.bits) + '-bit' : '') +
          PqcBadgeView.badge(row.pqc) + '</td>' +
          '<td>' + (row.kid ? '<code>' + esc(row.kid) + '</code>'
                    : (row.fingerprint ?
                       '<code>' + esc(row.fingerprint) + '</code>'
                       : '<span class="why">' +
                         (row.generated === false ? 'not made yet' : 'none') +
                         '</span>')) + '</td>' +
          '<td>' + (row.scope === 'realm' ? 'this realm' : 'the process') +
          '</td><td>' + (row.formats.length ? self.chips(row.formats)
                    : '<span class="why">not exportable</span>') + '</td></tr>';
      }).join('') + '</tbody></table>';

    report.keys.forEach(function (row) {
      html += '<h3 id="key-' + esc(row.id) + '">' + esc(row.label) +
        PqcBadgeView.badge(row.pqc) + '</h3>' +
        '<table><tbody><tr><th class="n">Used for</th><td><ul>' +
        row.usedFor.map(function (what) {
          return '<li>' + self.prose(what) + '</li>';
        }).join('') + '</ul></td></tr>' +
        (row.subject ? '<tr><th class="n">Subject</th><td><code>' +
          esc(row.subject) + '</code></td></tr>' : '') +
        (row.names ? '<tr><th class="n">Names</th><td>' +
          self.chips(row.names) + '</td></tr>' : '') +
        (row.notAfter ? '<tr><th class="n">Valid to</th><td>' +
          esc(row.notAfter) + '</td></tr>' : '') +
        '</tbody></table>' +
        self.keyExportForm(row);
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
  static keyExportForm(row) {
    if (!row.formats.length) {
      return kit.note('<strong>Not exportable.</strong> ' +
        (row.generated === false
          ? 'The post-quantum keys are made on FIRST USE — one SLH-DSA ' +
            'keygen is most of two seconds — so this page deliberately does ' +
            'not make them. Fetch <code>/oauth2/jwks</code> in this realm ' +
            'and come back.'
          : 'There is no interoperable encoding for this key to hand over.'));
    }
    return '<form method="post" action="/admin/keys/export" class="formrow">' +
      '<input type="hidden" name="key" value="' + esc(row.id) + '">' +
      '<label for="fmt-' + esc(row.id) + '">Keystore format</label> ' +
      '<select id="fmt-' + esc(row.id) + '" name="format">' +
      row.formats.map(function (f) {
        return '<option value="' + esc(f) + '">' + esc(f.toUpperCase()) +
          (f === 'pkcs12' ? ' (.p12 — password required)' : '') + '</option>';
      }).join('') + '</select> ' +
      '<label for="pw-' + esc(row.id) + '">Password</label> ' +
      '<input type="password" id="pw-' + esc(row.id) + '" name="password" ' +
      'placeholder="required for PKCS#12; encrypts the private half of the ' +
      'rest"> <button type="submit">Download</button>' +
      (row.kty === 'AKP'
        ? kit.note('<strong>The PUBLIC half only.</strong> RFC 9964 ' +
                     'defines ' +
          'the public members of an AKP key and the private seed handling is ' +
          'still moving, so there is no interoperable private encoding to ' +
          'hand over. A file no library reads would be worse than saying so.')
        : kit.note('<strong>A password is REQUIRED for PKCS#12 and ' +
                     'optional ' +
          'for the other three</strong>, where it encrypts the private half ' +
          '(PKCS#8 for PEM and DER, PBES2 as a .jwe for JWK). Leave it empty ' +
          'and the private key comes out in the clear, which is usually what ' +
          'you want from a mock and is never what you want anywhere else.')) +
      '</form>';
  }
}

export = CryptoMetadataPage;
