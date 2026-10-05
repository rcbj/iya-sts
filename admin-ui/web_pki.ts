// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_pki.ts
//
// ---------------------------------------------------------------------------
// PROTOCOLS → PKI, DRAWN FROM ITS VIEW ALONE (#446, 2026-10-05).
//
// Draws PKI from the answer of `GET /admin-api/pki`: this realm's certificate
// authority and the tree it is under, the key pairs issued to applications and
// people, revocation, pinned signers, the Certificate & Key Configuration pane
// and the settings.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// Its methods were `PkiAdmin`'s in `admin-ui/pki_admin.ts`, moved with their
// comments; that module still draws the page until the console's cutover, by
// calling `render()` with its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');
import CertificateDialogView = require('./web_certificate_dialog');
import PqcBadgeView = require('./web_pqc_badge');
import SettingsForms = require('./web_settings');

type Json = any;

// The console's escaping, under the name the moved code calls it by.
const esc = kit.esc;

const KEY_PAIR_LIST_PARAMS = ['per', 'issuedPage', 'personsPage', 'issuedq',
                              'personsq'];

// The longest search a link carries. A term longer than any field it could
// match is dropped rather than echoed into every link on the page.
const SEARCH_MAX_LENGTH = 200;

const REVOCATION_LIST_PARAM =
  /^ca-[a-z0-9_-]{1,120}-(issued|orphans)(Page|q)$/;

/**
 * Draws PKI from the answer of `GET /admin-api/pki`: this realm's certificate
 * authority and the tree it is under, the key pairs issued to applications and
 * people, revocation, pinned signers, the Certificate & Key Configuration pane
 * and the settings.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class PkiPage {
  /**
   * Draws the page's body from its view.
   *
   * @param view - the answer of the page's management API operation
   * @param ctx - the render context: the page's query and whether
   *   the reader may write (`WebKit.context()`)
   * @returns the body as HTML
   */
  static render(view: Json, ctx: Json): string {
    return PkiPage.body(ctx, view);
  }

  // The two tables' paging state out of a query, and ONLY those names: what
  // comes out of here is put into every paging link and every Take-off button's
  // `back`, so the set of names is one this file wrote. A repeated parameter is
  // its first value, and a page or `per` that is not a positive integer is
  // dropped rather than carried — `pagingOf()` would clamp it anyway, and a
  // link has no business repeating it. A SEARCH (a name ending in `q`) is
  // carried trimmed, when it is not empty and not longer than
  // `SEARCH_MAX_LENGTH`; the links escape it like every other value.
  static keyPairListView(query: Json) {
    const out: Json = {};
    // The key-pair tables' names, and every authority list's (#370): only
    // names this file writes, so a link carries nothing a browser made up.
    const names = KEY_PAIR_LIST_PARAMS.concat(Object.keys(query || {})
      .filter(function (name) {
        return REVOCATION_LIST_PARAM.test(name);
      }).sort());
    names.forEach(function (name) {
      const raw = (query || {})[name];
      const first = Array.isArray(raw) ? raw[0] : raw;
      const value = first == null ? '' : String(first);
      if (/q$/.test(name)) {
        const term = value.trim();
        if (term && term.length <= SEARCH_MAX_LENGTH) {
          out[name] = term;
        }
      } else if (/^[1-9][0-9]{0,5}$/.test(value)) {
        out[name] = value;
      }
    });
    return out;
  }

  // ---------------------------------------------------------------------------
  // THE PAGE.
  // ---------------------------------------------------------------------------
  static chainTable(chain: Json) {
    const self = this;
    if (!chain) {
      return '';
    }
    const rows = chain.tiers.map(function (tier) {
      return '<tr>' +
        '<td><strong>' + esc(tier.label) + '</strong></td>' +
        '<td><code>' + esc(tier.subject) + '</code></td>' +
        '<td><code>' + esc(tier.serialHex.slice(0, 16)) +
        '&hellip;</code></td>' + '<td>' + esc(tier.notAfter.slice(0, 10)) +
          (tier.expired ? ' <strong>(expired)</strong>' : '') + '</td>' +
        '<td><code>' + esc(tier.keyAlg) + '</code> / <code>' +
          esc(tier.signatureAlg) + '</code>' +
          PqcBadgeView.badge(tier.pqc) +
          self.alternativeNote(tier) + '</td>' +
        '<td><code>' + esc(tier.thumbprint.slice(0, 16)) +
        '&hellip;</code><br>' +
        CertificateDialogView.link('/admin/pki', tier.thumbprint, 'pki-chain') +
        '</td></tr><tr><td ' +
        'colspan="6">' + kit.tip(tier.what,
          'What the ' + tier.label + ' is for') + '</td></tr>';
    }).join('');
    return '<table><thead><tr><th>Tier</th><th>Subject</th><th>Serial</th>' +
           '<th>Expires</th><th>Key / signature</th><th>SHA-256</th></tr>' +
           '</thead><tbody>' + rows + '</tbody></table>';
  }

  static pemBlocks(chain: Json) {
    if (!chain) {
      return '';
    }
    // The certificates, in full, because the ONE thing a relying party has to
    // be given out of band is the Root — and a page that showed a thumbprint
    // and made somebody find the bytes elsewhere would be a page that stops at
    // the interesting part. They are public: a certificate is the half of a key
    // pair that is meant to be handed around.
    return chain.tiers.map(function (tier) {
      return '<details><summary>' + esc(tier.label) +
        ' certificate (PEM)</summary><pre>' + esc(tier.certificatePem) +
        '</pre></details>';
    }).join('');
  }

  static algorithmOptions(json: Json, selected: Json) {
    return json.keyAlgorithms.map(function (one) {
      return '<option value="' + esc(one.id) + '"' +
        (one.id === selected ? ' selected' : '') + '>' + esc(one.label) +
        '</option>';
    }).join('');
  }

  // The alternative (post-quantum) key a tier holds beside its classical one
  // (#68, ITU-T X.509 clause 9.8). One labelled select, drawn on all three
  // build forms, so the console offers what `altKeyAlg` on the three
  // `/admin-api/pki` actions takes (rule 7).
  static alternativeField(json: Json, selected: Json) {
    const chosen = String(selected || '') ||
                   String(json.pageDefaults.alternativeKeyAlgorithm);
    const options = (json.alternativeKeyAlgorithms || []).map(function (id) {
      return '<option value="' + esc(id) + '"' +
        (id === chosen ? ' selected' : '') + '>' +
        esc(id === 'none' ? 'none (classical only)' : id.toUpperCase()) +
        '</option>';
    }).join('');
    return '<label' + kit.tip('The post-quantum key each authority holds ' +
      'beside its classical one, in the alternative-key extensions of ' +
      'ITU-T X.509 (2019) clause 9.8. Every certificate the authority ' +
      'issues is then signed twice, and this service refuses one whose ' +
      'second signature is wrong or missing. "none" builds a classical-only ' +
      'authority, which a quantum-capable attacker can forge.') +
      '>Alternative key <select name="altKeyAlg">' + options +
      '</select></label> ';
  }

  // A tier's hybrid half (#68), under its classical algorithms: the key it
  // holds and the algorithm its own alternative signature was made with.
  static alternativeNote(tier: Json) {
    if (!tier || !tier.altKeyAlg) {
      return '';
    }
    return '<br><small>alt <code>' + esc(tier.altKeyAlg) + '</code>' +
      (tier.altSignatureAlg
        ? ' / signed <code>' + esc(tier.altSignatureAlg) + '</code>'
        : ' / no alternative signature') + '</small>';
  }

  static signatureOptions(json: Json, keyAlg: Json) {
    // Every algorithm, with the ones this key cannot produce marked rather than
    // hidden — a dropdown that silently drops half its entries when another
    // field changes is a dropdown nobody can reason about with no script to
    // explain it. An impossible pair is refused at the build with the list
    // beside it, which is a sentence rather than a mystery.
    const kind = (json.keyAlgorithms.filter(function (one) {
      return one.id === keyAlg;
    })[0] || {}).kind;
    return '<option value="">(the right one for the key algorithm)</option>' +
      json.signatureAlgorithms.map(function (one) {
        return '<option value="' + esc(one.id) + '">' + esc(one.label) +
          (one.kind !== kind ? ' — needs a ' + esc(one.kind) + ' key' : '') +
          (one.weak ? ' [weak, on purpose — refused in product mode]' : '') +
          '</option>';
      }).join('');
  }

  // A one-line text box, with the draft's value in it.
  static textField(draft: Json, name: Json, label: Json, title: Json,
                    extra?: Json) {
    return '<label' + kit.tip(title) + '>' + esc(label) +
      ' <input type="text" name="' + esc(name) + '" value="' +
      esc(String(draft[name] === undefined ? '' : draft[name])) + '"' +
      (extra || '') + '></label> ';
  }

  // A textarea. `rows` is small everywhere on this pane on purpose: twenty-two
  // extension cards each with a four-line box is a page nobody can see the foot
  // of, and every one of these grammars is one item per line.
  static areaField(draft: Json, name: Json, label: Json, title: Json,
                    rows: Json, placeholder?: Json) {
    return '<div class="pki-field"><label' + kit.tip(title) + '>' +
        esc(label) +
      '<textarea name="' + esc(name) + '" rows="' + (rows || 2) + '"' +
      (placeholder ? ' placeholder="' + esc(placeholder) + '"' : '') + '>' +
      esc(String(draft[name] === undefined ? '' : draft[name])) +
      '</textarea></label></div>';
  }

  // A checkbox. **AN UNTICKED BOX POSTS NOTHING**, which is what `draftFrom()`
  // reads a flag as, so there is deliberately no hidden companion field here: a
  // `<input type="hidden" value="0">` beside each would make every one of these
  // post twice and the last-one-wins parser would decide the answer.
  static checkField(draft: Json, name: Json, label: Json, title: Json) {
    return '<label class="pki-flag"' + kit.tip(title) + '><input ' +
      'type="checkbox" name="' + esc(name) + '" value="1"' +
      (draft[name] ? ' checked' : '') + '> ' + esc(label) + '</label> ';
  }

  // A dropdown. `options` is `[{ value, label, group }]`; a group name puts the
  // option in an `<optgroup>`, which is how forty-one key algorithms become a
  // menu with landmarks in it rather than a scroll bar.
  static selectField(draft: Json, name: Json, label: Json, title: Json,
                      options: Json, extra?: Json) {
    const current = String(draft[name] === undefined ? '' : draft[name]);
    let html = '';
    let group = null;
    options.forEach(function (one) {
      if (one.group !== group) {
        if (group !== null) {
          html += '</optgroup>';
        }
        group = one.group;
        if (group) {
          html += '<optgroup label="' + esc(group) + '">';
        }
      }
      html += '<option value="' + esc(one.value) + '"' +
        (one.value === current ? ' selected' : '') + '>' + esc(one.label) +
        '</option>';
    });
    if (group) {
      html += '</optgroup>';
    }
    return '<label' + kit.tip(title) + '>' + esc(label) +
      ' <select name="' + esc(name) + '"' + (extra || '') + '>' + html +
      '</select></label> ';
  }

  // One extension card: the head is the extension's own checkbox and its
  // critical flag, the body is whatever that extension carries.
  static extCard(head: Json, body: Json) {
    return '<div class="pki-ext"><div class="pki-exthead">' + head + '</div>' +
      (body || '') + '</div>';
  }

  // The twenty-two cards, in RFC 5280's order and then the ones it does not
  // define. Every algorithm list in them is read from the encoder — the nine
  // keyUsage bits, the sixteen extendedKeyUsage purposes, the five Netscape
  // types — so a bit the encoder gains is a checkbox here the day it is added.
  static extensionCards(json: Json, draft: Json) {
    const self = this;
    const cards = [];

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_bc', 'basicConstraints',
                      'Whether this certificate may act as a CA, and how ' +
                      'many CAs may follow it. RFC 5280 requires it to be ' +
                      'critical in a CA certificate.') +
      self.checkField(draft, 'pki_bc_critical', 'critical',
                      'RFC 5280: MUST be critical in a CA certificate.'),
      self.checkField(draft, 'pki_bc_ca', 'cA',
                      'This certificate may sign other certificates.') +
      self.textField(draft, 'pki_bc_pathlen', 'pathLenConstraint',
                     'How many further CA certificates may appear below this ' +
                     'one. 0 means it may only sign leaves. Empty means ' +
                     'unlimited.',
                     ' size="6" placeholder="(unlimited)"')));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_ku', 'keyUsage',
                      'What the certified key may be used for. RFC 5280 says ' +
                      'this SHOULD be critical.') +
      self.checkField(draft, 'pki_ku_critical', 'critical',
                      'RFC 5280: SHOULD be critical.'),
      '<div class="pki-flags">' +
      json.workbench.keyUsageBits.map(function (bit) {
        return self.checkField(draft, 'pki_ku_' + bit.name, bit.name, bit.what);
      }).join('') + '</div>'));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_eku', 'extendedKeyUsage',
                      'The purposes this certificate is for. A TLS client ' +
                      'refuses a server certificate without serverAuth; a ' +
                      'server refuses a client certificate without ' +
                      'clientAuth.') +
      self.checkField(draft, 'pki_eku_critical', 'critical',
                      'Marking this critical means a validator that does not ' +
                      'recognise one of the OIDs must reject the certificate.'),
      '<div class="pki-flags">' +
      json.workbench.extendedKeyUsages.map(function (one) {
        return self.checkField(draft, 'pki_eku_' + one.name, one.name, one.oid);
      }).join('') + '</div>' +
      self.areaField(draft, 'pki_eku_extra', 'Further OIDs (one per line)',
                     'For a purpose that is not one of the ' +
                     json.workbench.extendedKeyUsages.length + ' above.', 1,
                     '1.3.6.1.4.1.99999.1.1')));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_skid', 'subjectKeyIdentifier',
                      'The SHA-1 of this certificate’s public key, RFC 5280 ' +
                      'section 4.2.1.2 method (1) — the same value every ' +
                      'other implementation computes, so key identifiers ' +
                      'match across tools.'), ''));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_akid', 'authorityKeyIdentifier',
                      'Identifies the ISSUER’s key, so a validator can find ' +
                      'the right CA certificate when several share a subject.'),
      self.checkField(draft, 'pki_akid_issuer_serial',
                      'also include authorityCertIssuer + serial',
                      'Also name the issuer’s own issuer and serial number. ' +
                      'Rarely needed, occasionally required.')));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_san', 'subjectAltName',
                      'The names this certificate is for. For TLS this — not ' +
                      'the Common Name — is what a client checks.') +
      self.checkField(draft, 'pki_san_critical', 'critical',
                      'Should be critical when the subject DN is empty, and ' +
                      'only then.'),
      self.areaField(draft, 'pki_san', 'Names, one per line',
                     'dns:example.com — ip:10.0.0.1 or ip:2001:db8::1 — ' +
                     'email:user@example.com — uri:https://example.com/x — ' +
                     'upn:user@EXAMPLE.COM — krb5:host/x@EXAMPLE.COM — ' +
                     'rid:1.2.3.4 — dirname:CN=alt,O=Example — ' +
                     'othername:<oid>:<base64 DER>.',
                     2, 'dns:localhost\nip:127.0.0.1')));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_ian', 'issuerAltName',
                      'Alternative names for the issuer. Same syntax as ' +
                      'subjectAltName.') +
      self.checkField(draft, 'pki_ian_critical', 'critical',
                      'Should not normally be critical.'),
      self.areaField(draft, 'pki_ian', 'Names, one per line',
                     'The same syntax as subjectAltName above.', 1,
                     'uri:https://ca.example.com/')));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_cdp', 'cRLDistributionPoints',
                      'Where to fetch the CRL that would revoke this ' +
                      'certificate. NOTE that this service publishes none: ' +
                      'the extension is a URL you are asserting, not a ' +
                      'promise this mock keeps.') +
      self.checkField(draft, 'pki_cdp_critical', 'critical',
                      'Rarely critical.'),
      self.areaField(draft, 'pki_cdp', 'URLs, one per line',
                     'Where the CRL that would revoke this certificate is ' +
                     'published.', 1, 'http://crl.example.com/issuing.crl')));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_freshest', 'freshestCRL',
                      'Where to fetch the DELTA CRL. The same shape as ' +
                      'cRLDistributionPoints and a different extension.'),
      self.areaField(draft, 'pki_freshest', 'URLs, one per line',
                     'Where the delta CRL is published.', 1,
                     'http://crl.example.com/delta.crl')));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_aia', 'authorityInfoAccess',
                      'Where to reach the issuer: its OCSP responder, and a ' +
                      'copy of its own certificate for a client that was ' +
                      'sent an incomplete chain.'),
      self.areaField(draft, 'pki_aia', 'Access descriptions, one per line',
                     'ocsp:<url>, caissuers:<url>, timestamping:<url>, ' +
                     'carepository:<url>, or <oid>:<url> for a method this ' +
                     'page does not name.', 2,
                     'ocsp:http://ocsp.example.com\n' +
                     'caissuers:http://example.com/ca.cer')));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_sia', 'subjectInfoAccess',
                      'Services offered by the SUBJECT of this certificate, ' +
                      'rather than by its issuer.'),
      self.areaField(draft, 'pki_sia', 'Access descriptions, one per line',
                     'The same syntax as authorityInfoAccess above.', 1,
                     'carepository:http://example.com/certs/')));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_policies', 'certificatePolicies',
                      'The policies this certificate was issued under, with ' +
                      'the two qualifiers RFC 5280 defines.') +
      self.checkField(draft, 'pki_policies_critical', 'critical',
                      'Critical means a validator that cannot process the ' +
                      'policy must reject the certificate.'),
      self.areaField(draft, 'pki_policies', 'Policies, one per line',
                     '<policy oid>, optionally followed by |cps=<uri> and ' +
                     '|notice=<text>. 2.5.29.32.0 is anyPolicy.', 2,
                     '1.3.6.1.4.1.99999.1.1|cps=https://example.com/cps' +
                     '|notice=Test certificates only')));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_policy_mappings', 'policyMappings',
                      'Declares that one policy OID in the issuer’s domain ' +
                      'is equivalent to another in the subject’s. RFC 5280 ' +
                      'says this SHOULD be critical, and it is.'),
      self.areaField(draft, 'pki_policy_mappings', 'Mappings, one per line',
                     '<issuer policy oid>=<subject policy oid>.', 1,
                     '1.3.6.1.4.1.99999.1.1=1.3.6.1.4.1.88888.1.1')));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_policy_constraints', 'policyConstraints',
                      'Requires an explicit policy, or inhibits policy ' +
                      'mapping, after a number of further certificates. RFC ' +
                      '5280: MUST be critical, and it is.'),
      self.textField(draft, 'pki_require_explicit_policy',
                     'requireExplicitPolicy',
                     'How many further certificates may appear before an ' +
                     'acceptable policy is required. Empty means it is not ' +
                     'set.',
                     ' size="6" placeholder="(not set)"') +
      self.textField(draft, 'pki_inhibit_policy_mapping',
                     'inhibitPolicyMapping',
                     'How many further certificates may still map policies. ' +
                     'Empty means it is not set.',
                     ' size="6" placeholder="(not set)"')));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_name_constraints', 'nameConstraints',
                      'Limits the names a CA below this one may certify — ' +
                      'the extension that makes a private CA safe to trust. ' +
                      'RFC 5280: MUST be critical, and only meaningful in a ' +
                      'CA certificate.') +
      self.checkField(draft, 'pki_nc_critical', 'critical',
                      'RFC 5280: MUST be ' +
                                                            'critical.'),
      self.areaField(draft, 'pki_name_constraints', 'Constraints, one per line',
                     '"permit <name>" or "exclude <name>", using the ' +
                     'subjectAltName syntax. An IP constraint takes a PREFIX ' +
                     '(10.0.0.0/8): a name constraint’s iPAddress is the ' +
                     'address followed by its mask, which is the one place a ' +
                     'general name is not simply an address.', 2,
                     'permit dns:example.com\npermit ip:10.0.0.0/8\nexclude ' +
                     'dns:bad.example.com')));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_inhibit_any', 'inhibitAnyPolicy',
                      'How many further certificates may still use the ' +
                      'anyPolicy OID. RFC 5280: MUST be critical, and it is.'),
      self.textField(draft, 'pki_inhibit_any_skip', 'skipCerts',
                     '0 means anyPolicy is not accepted below this ' +
                     'certificate at all.', ' size="6" placeholder="0"')));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_pkup', 'privateKeyUsagePeriod',
                      'A validity period for the PRIVATE key that is shorter ' +
                      'than the certificate’s — signatures made after it are ' +
                      'not to be trusted, while the certificate goes on ' +
                      'validating them.'),
      self.textField(draft, 'pki_pkup_not_before', 'notBefore',
                     'When the private key may start signing. Encoded as a ' +
                     'GeneralizedTime in UTC. Empty leaves it out.',
                     ' size="18" placeholder="2026-01-01T00:00"') +
      self.textField(draft, 'pki_pkup_not_after', 'notAfter',
                     'When the private key must stop signing — earlier than ' +
                     'the certificate’s own notAfter, which goes on ' +
                     'validating what was signed before it. Empty leaves it ' +
                     'out.',
                     ' size="18" placeholder="2027-01-01T00:00"')));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_tls_feature', 'TLS Feature (RFC 7633)',
                      'The TLS extensions a server promises to support. 5 is ' +
                      'status_request — "must-staple"; 17 is ' +
                      'status_request_v2.'),
      self.areaField(draft, 'pki_tls_feature',
                     'Extension numbers, one per line',
                     'One TLS extension number per line.', 1, '5')));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_ocsp_nocheck', 'id-pkix-ocsp-nocheck',
                      'Tells a validator not to check the revocation status ' +
                      'of this certificate — correct on an OCSP responder’s ' +
                      'own certificate and almost nowhere else.'), ''));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_ns_cert_type',
                      'Netscape certificate type',
                      'A pre-RFC 5280 relic that some old appliances still ' +
                      'read. Kept for the same reason SHA-1 is: this is ' +
                      'where you find out.'),
      '<div class="pki-flags">' +
      json.workbench.netscapeTypes.map(function (one) {
        return self.checkField(draft, 'pki_ns_' + one.name, one.name, '');
      }).join('') + '</div>'));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_ns_comment', 'Netscape comment',
                      'A free-text comment some tools display when showing ' +
                      'the certificate.'),
      self.textField(draft, 'pki_ns_comment', 'Comment', 'Free text.',
                     ' size="40" placeholder="Issued by IYA STS"')));

    cards.push(self.extCard(
      '<strong' + kit.tip('Any extension at all, by OID and base64 DER — ' +
      'including one this page has never heard of. Without this the ' +
      'extension set would be whatever this page happens to know about, ' +
      'which is not what a debugging tool is for.') +
      '>Any other extension</strong>',
      self.areaField(draft, 'pki_custom_extensions', 'One per line',
                     '<oid>|<critical or ->|<base64 DER of the extension ' +
                     'value>. The value is the DER of the extnValue’s ' +
                     'contents, not the OCTET STRING wrapping it.', 2,
                     '1.3.6.1.4.1.99999.7.7|-|DANDYWJj')));

    return '<div class="pki-extlist">' + cards.join('') + '</div>';
  }

  // The Issue a Certificate column: what kind of certificate this is, who signs
  // it, how, with what serial and for how long.
  static certificateColumn(json: Json, draft: Json) {
    const self = this;
    const wb = json.workbench;
    const profile = wb.profiles.filter(function (one) {
      return one.id === draft.pki_profile;
    })[0] || {};
    const mode = wb.pqModes.filter(function (one) {
      return one.id === wb.pqMode;
    })[0] || wb.pqModes[0];
    const issuerOptions = [{ value: '', label: wb.issuers.length
      ? '(choose one)' : '(no certificate authority in this realm yet)' }]
      .concat(wb.issuers.map(function (one) {
        return { value: one.id, label: one.label };
      }));
    const html =
      '<div class="pki-col">' +
      '<div class="pki-group">Issue a Certificate</div>' +
      kit.note(
        'The profile sets the extensions below to what that kind of ' +
        'certificate normally carries; every one of them is then editable, ' +
        'which is the point &mdash; issuing the certificate that is wrong in ' +
        'exactly one way is how you find out what refuses it and what does ' +
        'not. <strong>Pressing <em>Apply the profile</em> rewrites the ' +
        'extension boxes</strong>, because on this console the form IS the ' +
        'extension set: a profile that changed what gets issued and not what ' +
        'is shown would be a page that lies about what it is about to do.',
        'What the profile does, and why every field it sets stays editable') +
      '<div class="pki-row">' +
      self.selectField(draft, 'pki_profile', 'Profile',
                       'What kind of certificate this is. It sets the ' +
                       'default extensions, the default validity, and ' +
                       'whether it is self-signed.',
                       // **THE LABEL IS THE PROFILE'S OWN AND NOTHING IS
                       // APPENDED TO IT.** `root-ca` is already called "Root CA
                       // (self-signed)" in the encoder's table, so a page
                       // adding its own "(self-signed)" printed it twice —
                       // which is what happens every time a renderer restates a
                       // fact the table it is reading already carries.
                       wb.profiles.map(function (one) {
                         return { value: one.id, label: one.label };
                       })) +
      '<button type="submit" name="defaults" value="1"' +
        kit.tip('Rewrite the extension boxes, the default validity and the ' +
                  'profile\'s Common Name from the profile chosen beside ' +
                  'this button. Nothing is issued and a name you typed is ' +
                  'kept.') +
        '>Apply the profile</button>' +
      '</div>' +
      (profile.selfSigned
        ? kit.note('<strong>' + esc(profile.label) + ' is ' +
          'SELF-SIGNED</strong>, so the key pair below signs its own ' +
          'certificate and <em>Signed by</em> is ignored. A "root" signed by ' +
          'something else is an intermediate.')
        : '') +
      '<div class="pki-row">' +
      self.selectField(draft, 'pki_issuer', 'Signed by',
                       'The certificate authority that signs this ' +
                       'certificate. Only authorities whose private key is ' +
                       'still in this service are listed — one whose key was ' +
                       'never kept cannot sign. The three tiers come from ' +
                       'the hierarchy above; anything else is a CA issued ' +
                       'from this pane.', issuerOptions) +
      '</div>' +
      '<div class="pki-row">' +
      self.selectField(draft, 'pki_pq_mode', 'Cryptographic Approach',
                       'Which of the three ways this certificate carries ' +
                       'post-quantum cryptography. It filters the Key ' +
                       'Algorithm list beside this column and narrows the ' +
                       'Signature Algorithm below; Hybrid additionally uses ' +
                       'the alternative key pair, which goes into the X.509 ' +
                       '(2019) alternative-signature extensions.',
                       wb.pqModes.map(function (one) {
                         return { value: one.id, label: one.label };
                       })) +
      '<button type="submit" name="defaults" value="1"' +
        kit.tip('Redraw the two algorithm menus for the approach chosen ' +
                  'beside this button. It is the same button as the one ' +
                  'above it: with no script on this console, narrowing a ' +
                  'menu is a round trip.') + '>Apply</button>' +
      '</div>' +
      kit.note(esc(mode.note), mode.label) +
      '<div class="pki-row">' +
      self.selectField(draft, 'pki_sig_alg', 'Signature Algorithm',
                       'The algorithm the ISSUER signs with. The list is ' +
                       'what the signing key can actually produce' +
                       (wb.signerLabel ? ' — it is ' + wb.signerLabel + ' — ' :
                        ' ') +
                       'because an RSA key cannot make an ECDSA signature ' +
                       'and offering it produces a Web Crypto error that ' +
                       'names neither.',
                       [{ value: '',
                       label: '(the right one for the signing key)' }]
                    .concat(wb.signatureAlgorithms.map(function (one) {
                      return { value: one.id,
                               label: one.label + (one.weak
                                 ? ' [weak, on purpose]' : '') };
                    }))) +
      '</div>' +
      '<div class="pki-row">' +
      self.textField(draft, 'pki_serial', 'Serial Number (hex)',
                     'Hex, and editable. A random 128-bit positive serial is ' +
                     'filled in for you and a fresh one replaces it after ' +
                     'every issue — that is what the CA/Browser Forum ' +
                     'requires, and what makes a collision on the signed ' +
                     'bytes impractical to arrange. Cleared, one is ' +
                     'generated at issue time anyway.', ' size="36"') +
      self.textField(draft, 'pki_validity_years', 'Validity (years)',
                     'Counted from Not Before, and used only when Not After ' +
                     'below is empty. The profile sets it — 20 for a root, ' +
                     '10 for an intermediate, 5 for an issuing CA, 1 for a ' +
                     'leaf.', ' size="5"') +
      '</div>' +
      '<div class="pki-row">' +
      self.textField(draft, 'pki_not_before', 'Not Before',
                     'Optional — empty means the moment the button is ' +
                     'pressed. Anything Date can read; what is encoded is ' +
                     'the instant, in UTC. A date at or after 2050 is ' +
                     'encoded as a GeneralizedTime, as RFC 5280 requires — a ' +
                     'UTCTime there is read as 1950, i.e. a certificate that ' +
                     'expired seventy years ago.',
                     ' size="20" placeholder="2026-01-01T00:00"') +
      self.textField(draft, 'pki_not_after', 'Not After',
                     'Optional — empty means Not Before plus the validity in ' +
                     'years beside it.',
                     ' size="20" placeholder="(Not Before + validity)"') +
      '</div>' +
      '</div>';
    return html;
  }

  // The Key Pair column: the pair this certificate certifies, the certification
  // request nothing here consumes, the hybrid half, and the export.
  static keyPairColumn(json: Json, draft: Json) {
    const self = this;
    const wb = json.workbench;
    const algOptions = wb.keyAlgorithms.map(function (one) {
      return { value: one.id, group: one.family,
               label: one.label + (one.slow ? ' — slow to generate' : '') +
                      (one.signs ? '' : ' — subject key only, cannot sign') };
    });
    const slow = wb.keyAlgorithms.filter(function (one) { return one.slow; });
    const html =
      '<div class="pki-col">' +
      '<div class="pki-group">Key Pair</div>' +
      kit.note(
        'The key pair the next certificate certifies &mdash; and, for a ' +
        'self-signed profile, the key that signs it. It is generated ' +
        '<strong>here, in this service</strong>, which is the one place this ' +
        'page differs in kind from the debugger\'s: that page generates in ' +
        'the browser because its whole claim is that the key never leaves ' +
        'it, and this one holds the certificate authority, so the key ' +
        'belongs in the process that signs. It is the same module either way ' +
        '(<code>common/vendored/key_material.js</code>), so the algorithms, ' +
        'the PEM/JWK conversion and the keystore formats are identical ' +
        'rather than similar.',
        'Where this pair comes from') +
      (slow.length
        ? kit.warn(
          '<strong>' + esc(slow.map(function (one) { return one.family; })
            .filter(function (v, i, a) { return a.indexOf(v) === i; })
                               .join(', ')) +
          ' key generation takes up to a second and it runs on this ' +
          'thread.</strong> This process owns six listener families on one ' +
          'thread, so while a key like that is being made this service ' +
          'answers nobody &mdash; not the next HTTP caller, not the KDC on ' +
          'port 88, not the LDAP socket. The primitive is native (node\'s ' +
          'OpenSSL since #363), and the SLH-DSA <code>s</code> parameter ' +
          'sets are slow by design even so. In <code>dispatch</code> mode ' +
          'the console holds affinity to a request worker, so the stall is ' +
          'that worker\'s rather than the listener\'s.',
          'One algorithm family is slow, and the cost is real')
        : '') +
      '<div class="pki-row">' +
      self.selectField(draft, 'pki_key_alg', 'Key Algorithm',
                       'The algorithm and parameters of the key pair. RSA ' +
                       'sizes are the modulus; the EC entries are the NIST ' +
                       'curves; Ed25519 is the only Edwards curve here. The ' +
                       'list is narrowed by the Cryptographic Approach in ' +
                       'the column beside this one.',
                       algOptions) +
      self.checkField(draft, 'pki_key_jwk', 'show as JWK',
                      'Show the key pair as JWK instead of PEM. The ' +
                      'conversion is key material only — the same key either ' +
                      'way. A POST-QUANTUM pair is shown as PEM whatever ' +
                      'this says, because these two boxes are also the INPUT ' +
                      'for a reuse and a round trip through a representation ' +
                      'this encoder cannot read back would lose the key.') +
      '<button type="submit" name="generate" value="1"' +
        kit.tip('Generate a key pair into the two boxes below WITHOUT ' +
                  'issuing anything, and tick nothing. It exists because ' +
                  'generating a post-quantum pair takes seconds: making one ' +
                  'and then issuing four certificates from it is the ' +
                  'difference between a page somebody can use and one they ' +
                  'cannot.') + '>Generate a key pair</button>' +
      '</div>' +
      '<div class="pki-row">' +
      self.checkField(draft, 'pki_reuse_key', 'reuse the key pair below',
                      'Certify the key pair already in the boxes below ' +
                      'instead of generating a new one — a CA re-issuing its ' +
                      'own certificate, or the pair the store\'s "Use this ' +
                      'key pair" button loaded here. Cleared, every issue ' +
                      'starts from a fresh pair.') +
      self.checkField(draft, 'pki_save_keys',
                      'keep the private key in this service',
                      'THIS IS THE ONE CONTROL ON THIS PANE THAT MEANS ' +
                      'SOMETHING DIFFERENT FROM THE DEBUGGER\'S. There it ' +
                      'decides whether the private key is written to the ' +
                      'browser\'s localStorage; here there is no browser ' +
                      'store, so it decides whether the issued object keeps ' +
                      'its private key in this realm\'s keystore row. ' +
                      'Cleared, the certificate and the public key are ' +
                      'stored and the private half is discarded the moment ' +
                      'the reply is written — so the object can be inspected ' +
                      'and used as a trust anchor, and can never sign again ' +
                      'or be exported.') +
      '</div>' +
      self.areaField(draft, 'pki_private_key', 'Private Key',
                     'PKCS#8 PEM (or JWK). It signs, and for a CA it goes on ' +
                     'signing long after this certificate was issued. There ' +
                     'is no Copy button because this console has no script; ' +
                     'the box selects.', 4) +
      self.areaField(draft, 'pki_public_key', 'Public Key',
                     'SubjectPublicKeyInfo PEM (or JWK). This is what the ' +
                     'certificate certifies.', 3) +
      '<div class="pki-row">' +
      self.checkField(draft, 'pki_gen_csr', 'generate a CSR when the ' +
                                            'certificate is issued',
                      'Also build the PKCS#10 certification request this key ' +
                      'pair and subject would have sent to an external ' +
                      'authority. It is FOR REFERENCE: this page signs the ' +
                      'certificate itself, so nothing here consumes the CSR ' +
                      '— it is what you would paste into a CA that will not ' +
                      'take a certificate you made yourself. The signature ' +
                      'on it is by the private key above, which is the proof ' +
                      'of possession that lets an authority certify a key it ' +
                      'has never seen.') +
      '</div>' +
      self.areaField(draft, 'pki_csr', 'CSR (PKCS#10)',
                     'The certification request for the key pair and subject ' +
                     'above, built from the SAME inputs the certificate was ' +
                     '— a request assembled from a second reading of the ' +
                     'form would differ in ways nobody could see. THREE ' +
                     'EXTENSIONS TRAVEL AND THE REST DO NOT: key usage, ' +
                     'extended key usage, basic constraints and ' +
                     'subjectAltName. subjectKeyIdentifier and ' +
                     'authorityKeyIdentifier are the ISSUER\'s to compute, ' +
                     'and a requester asserting them is asking a CA to ' +
                     'certify its own arithmetic. Empty until the box above ' +
                     'is ticked and something is issued.', 3) +
      // The hybrid half. It is drawn ALWAYS rather than revealed, because
      // revealing it needs a script — and a pane that hid it would leave the
      // alternative key pair unreachable on the one console setting that uses
      // it. The heading says when it applies instead.
      '<div class="pki-group">Alternative (hybrid) Key Pair' +
        (wb.pqMode === 'hybrid' ? '' : ' — not in use') + '</div>' +
      kit.note(
        'ITU-T X.509 (2019) clause 9.8 adds three non-critical extensions ' +
        'that mirror three fields of the certificate: ' +
        '<code>subjectAltPublicKeyInfo</code> (2.5.29.72), ' +
        '<code>altSignatureAlgorithm</code> (2.5.29.73) and ' +
        '<code>altSignatureValue</code> (2.5.29.74). A certificate carrying ' +
        'them is signed twice, with two keys, and a validator that has never ' +
        'heard of the extensions sees an ordinary certificate and accepts it ' +
        '&mdash; which is the entire point. The alternative signature does ' +
        '<strong>not</strong> cover the whole TBSCertificate: it covers the ' +
        '<em>preTBSCertificate</em>, which is the TBSCertificate with the ' +
        '<code>signature</code> field removed and without the ' +
        '<code>altSignatureValue</code> extension. These boxes are used only ' +
        'when the Cryptographic Approach is <em>Hybrid</em>; for a ' +
        'self-signed certificate this pair makes the second signature, and ' +
        'for an issued one the ISSUER\'s alternative key does and this one ' +
        'is only certified.',
        'What the second key is for') +
      '<div class="pki-row">' +
      self.selectField(draft, 'pki_alt_key_alg', 'Alternative Algorithm',
                       'Where the post-quantum half of a hybrid certificate ' +
                       'goes, so the list is the post-quantum algorithms ' +
                       'that can sign — a hybrid certificate whose second ' +
                       'key is also RSA is a certificate signed twice by the ' +
                       'same century.',
                       wb.alternativeKeyAlgorithms.map(function (one) {
                         return { value: one.id, group: one.family,
                                  label: one.label +
                                         (one.slow ? ' — slow to generate'
                                                   : '') };
                       })) +
      self.checkField(draft, 'pki_alt_reuse_key', 'reuse the pair below',
                      'Certify the alternative pair already in the boxes ' +
                      'instead of generating a new one.') +
      '<button type="submit" name="generatealt" value="1"' +
        kit.tip('Generate the alternative key pair now. Issuing under the ' +
                  'Hybrid approach generates one anyway if these boxes are ' +
                  'empty.') + '>Generate the alternative pair</button>' +
      '</div>' +
      self.areaField(draft, 'pki_alt_private_key', 'Alternative Private Key',
                     'PKCS#8 PEM. For a self-signed certificate this is what ' +
                     'signs the preTBSCertificate; for an issued one the ' +
                     'issuer\'s own alternative private key is used instead ' +
                     'and this one is only certified.', 3) +
      self.areaField(draft, 'pki_alt_public_key', 'Alternative Public Key',
                     'SubjectPublicKeyInfo PEM. This is what goes into the ' +
                     'subjectAltPublicKeyInfo extension.', 2) +
      '<div class="pki-group">Export</div>' +
      kit.note(
        'Writes out the key pair of the object SELECTED in the store below, ' +
        'or the pair in the boxes above when nothing is selected. It is the ' +
        'same export <code>/admin/keys</code> uses &mdash; ' +
        '<code>common/vendored/key_material.js</code> &mdash; so a ' +
        '<code>.p12</code> from here and one from that page import ' +
        'identically into keytool, OpenSSL, Windows and macOS. <strong>It ' +
        'needs Admin Write</strong>, like every other door here that hands ' +
        'over a private key: reading this console needs Admin Read, and ' +
        'taking a key out of it needs the other role.',
        'What Download writes') +
      '<div class="pki-row">' +
      self.selectField(draft, 'pki_ks_format', 'Keystore Format',
                       'PEM: the private key and public key (and the chain, ' +
                       'if an object is selected) in one file. DER: two ' +
                       'binary files, of which the PRIVATE one is sent — ' +
                       'this service will not take a zip dependency to send ' +
                       'two, and the public half comes out of the private ' +
                       'one with one openssl command. JWK: a JWK set. ' +
                       'PKCS#12: a password-protected .p12 holding the key ' +
                       'and its certificate chain.',
                       wb.keystoreFormats.map(function (one) {
                         return { value: one, label: one.toUpperCase() };
                       })) +
      '<label' + kit.tip('Required for PKCS#12. For PEM and DER it ' +
        'encrypts the private key as a PBES2 EncryptedPrivateKeyInfo; for ' +
        'JWK it wraps the set in a PBES2 JWE. Left empty, the private key is ' +
        'written out in the clear.') + '>Password <input type="password" ' +
        'name="pki_ks_password" value="" ' +
        'autocomplete="new-password"></label> ' +
      self.checkField(draft, 'pki_ks_include_chain', 'include the chain',
                      'Put the selected object\'s whole certificate chain in ' +
                      'the file, which is what makes a PKCS#12 importable as ' +
                      'an identity rather than as a bare key.') +
      '<button type="submit" name="export" value="1" ' +
        'formaction="/admin/pki/export"' +
        kit.tip('Download the key pair. This button posts the same form to ' +
                  'a different endpoint, because the answer is a FILE rather ' +
                  'than a page.') + '>Download</button>' +
      '</div>' +
      '</div>';
    return html;
  }

  // The Subject Distinguished Name column.
  static subjectColumn(json: Json, draft: Json) {
    const self = this;
    const titles = {
      pki_dn_cn: 'commonName (2.5.4.3) — what this certificate is called. ' +
                 'The profile fills it in and replaces its own default when ' +
                 'the profile changes, but never a name you typed. For a TLS ' +
                 'server the name a client actually checks is in ' +
                 'subjectAltName, not here.',
      pki_dn_o: 'organizationName (2.5.4.10) — who the subject belongs to. ' +
                'It is filled from pki.organisation, which is what the ' +
                'hierarchy above carries, because two certificates from one ' +
                'realm reading O=Example and O=sts are two organisations as ' +
                'far as a path validator is concerned.',
      pki_dn_ou: 'organizationalUnitName (2.5.4.11) — the division within ' +
                 'the organization. Repeat it by adding OU=… lines to ' +
                 'Further attributes below; a DN may carry several.',
      pki_dn_l: 'localityName (2.5.4.7) — the city or town.',
      pki_dn_st: 'stateOrProvinceName (2.5.4.8) — spelled out rather than ' +
                 'abbreviated, which is what the CA/Browser Forum asks for.',
      pki_dn_c: 'countryName (2.5.4.6). Two letters, encoded as a ' +
                'PrintableString — a country encoded as UTF8String parses ' +
                'perfectly and is refused by several validators.',
      pki_dn_email: 'emailAddress (1.2.840.113549.1.9.1) — a legacy PKCS#9 ' +
                    'attribute in the DN. S/MIME clients read the rfc822Name ' +
                    'in subjectAltName instead, so an address here alone is ' +
                    'decorative.',
      pki_dn_dc: 'domainComponent (0.9.2342.19200300.100.1.25) — one label ' +
                 'of a DNS name, as Active Directory writes a DN ' +
                 '(DC=example, DC=com). Add further DC=… lines to Further ' +
                 'attributes below, in order.',
      pki_dn_uid: 'userId (0.9.2342.19200300.100.1.1) — the account name, as ' +
                  'a directory holds it.',
      pki_dn_serialnumber: 'The DN attribute called serialNumber (2.5.4.5). ' +
                           'Nothing to do with the certificate\'s serial ' +
                           'number in the first column.'
    };
    const labels = {
      pki_dn_cn: 'CN (Common Name)', pki_dn_o: 'O (Organization)',
      pki_dn_ou: 'OU (Organizational Unit)', pki_dn_l: 'L (Locality)',
      pki_dn_st: 'ST (State / Province)', pki_dn_c: 'C (Country)',
      pki_dn_email: 'emailAddress', pki_dn_dc: 'DC (Domain Component)',
      pki_dn_uid: 'UID', pki_dn_serialnumber: 'serialNumber (DN attribute)'
    };
    const boxes = json.workbench.dnFields.map(function (one) {
      return self.textField(draft, one.field, labels[one.field] || one.attr,
                            titles[one.field] || '',
                            one.field === 'pki_dn_c' ? ' size="4" maxlength="2"'
                                                     : ' size="28"');
    }).join('');
    const html =
      '<div class="pki-col">' +
      '<div class="pki-group">Subject Distinguished Name</div>' +
      kit.note(
        'Written in the order shown &mdash; a Name is an ordered ' +
        'RDNSequence, and a reordered DN is a different name that chains to ' +
        'nothing. For a TLS server, note that the name a client checks is in ' +
        '<code>subjectAltName</code> and not here: every current browser ' +
        'ignores the Common Name entirely.',
        'Why the order matters, and where a TLS name really lives') +
      '<div class="pki-row">' + boxes + '</div>' +
      self.areaField(draft, 'pki_dn_extra',
                     'Further attributes (one NAME=value or OID=value per ' +
                     'line)',
                     'Appended in order. Recognised names include SN, GN, ' +
                     'title, description, businessCategory, postalCode, ' +
                     'STREET, initials, pseudonym, dnQualifier, ' +
                     'generationQualifier and the three EV jurisdiction ' +
                     'attributes; anything else is taken as an OID.', 3,
                     'businessCategory=Private ' +
                     'Organization\n1.3.6.1.4.1.311.60.2.1.3=US') +
      '</div>';
    return html;
  }

  // ---------------------------------------------------------------------------
  // THE STORE, AND WHY IT IS INSIDE THE SAME FORM.
  //
  // *Use this key pair* has to load a key into the boxes above WITHOUT throwing
  // away the subject somebody has been typing, and with no script the only way
  // to keep the rest of the form is to submit it. So these buttons are submit
  // buttons of the one form, each carrying the object's id as its own VALUE —
  // which is also why they have names of their own rather than sharing
  // `action`.
  // ---------------------------------------------------------------------------
  static storeTable(json: Json, draft: Json) {
    const self = this;
    const wb = json.workbench;
    if (!wb.objects.length) {
      // **THE SELECTION IS A FIELD AND IT HAS TO SURVIVE AN EMPTY STORE.** The
      // radio column below carries `pki_selected`, so with no rows there is no
      // control carrying it at all — and a field that is on the form on one
      // render and absent on the next falls back to its default every time the
      // store happens to be empty, which is exactly the kind of control that
      // quietly undoes itself. `tests/pki_authoring.js` compares the drawn
      // fields against the declared ones and caught this.
      return '<input type="hidden" name="pki_selected" value="' +
        esc(String(draft.pki_selected || '')) + '">' +
        kit.note(
        'Nothing has been issued from the pane above in this realm. What is ' +
        'issued here is kept in the <strong>same keystore row as the ' +
        'hierarchy</strong> — sealed under the same key-encryption key, gone ' +
        'with the realm, and in development mode gone with the process, ' +
        'which is the rule the signing key already follows.',
        'The store is empty');
    }
    const rows = wb.objects.slice().reverse().map(function (one) {
      return '<tr>' +
        '<td><label class="pki-flag"><input type="radio" name="pki_selected" ' +
          'value="' + esc(one.id) + '"' +
          (draft.pki_selected === one.id ? ' checked' : '') + '> ' +
          (one.ca ? '<strong>CA</strong>' : 'leaf') + '</label></td>' +
        '<td><code>' + esc(one.subject) + '</code>' +
          (one.selfSigned ? '<br><em>self-signed</em>'
                          : '<br><small>issued by <code>' +
                            esc(one.issuerSubject) + '</code></small>') +
          '</td>' +
        '<td>' + esc(one.profileLabel) + '</td>' +
        '<td><code>' + esc(one.serialHex.slice(0, 16)) +
        '&hellip;</code></td><td>' + esc(String(one.notAfter).slice(0, 10)) +
          (one.expired ? ' <strong>(expired)</strong>' : '') + '</td>' +
        '<td><code>' + esc(one.keyAlg) + '</code> / <code>' +
          esc(one.signatureAlg) + '</code>' +
          PqcBadgeView.badge(one.pqc) +
          (one.altKeyAlg
            ? '<br><small>alt <code>' + esc(one.altKeyAlg) + '</code>' +
              (one.altSigned ? ', signed' : ', key only') + '</small>'
            : '') + '</td>' +
        '<td>' + (one.hasPrivateKey ? 'yes'
          : '<em>no — it cannot sign or be exported</em>') + '</td>' +
        '<td>' +
          (one.hasPrivateKey
            ? '<button type="submit" name="use" value="' + esc(one.id) + '"' +
              kit.tip('Load this key pair into the boxes above and tick ' +
                        '"reuse the key pair below", so the next issue ' +
                        'certifies THIS key — a CA renewing its own ' +
                        'certificate. Everything else on the form is kept.') +
              '>Use this key pair</button> '
            : '') +
          '<button type="submit" name="remove" value="' + esc(one.id) + '"' +
          kit.tip('Remove this object. Anything it issued is KEPT — those ' +
                    'certificates are still valid documents — and will say ' +
                    'that their issuer is missing.') + '>Remove</button>' +
        '</td></tr>' +
        '<tr><td colspan="8">' +
          CertificateDialogView.link('/admin/pki', one.thumbprint,
                                     'workbench') +
          '<details><summary>Certificate (PEM)' +
          (one.hasCsr ? ' and certification request' : '') + '</summary><pre>' +
          esc(one.certificatePem) + (one.csrPem ? '\n' + esc(one.csrPem) : '') +
          '</pre></details></td></tr>';
    }).join('');
    return '<table><thead><tr><th>Select</th><th>Subject</th><th>Profile</th>' +
      '<th>Serial</th><th>Expires</th><th>Key / signature</th>' +
      '<th>Private key</th><th></th></tr></thead><tbody>' + rows + '</tbody>' +
      '</table>' +
      '<div class="pki-row"><button type="submit" name="clearstore" value="1"' +
      kit.tip('Discard every key pair and certificate this pane has issued ' +
                'in this realm. The hierarchy above is NOT touched.') +
      '>Clear the store</button></div>';
  }

  // The whole pane: the three columns, the extensions, the buttons and the
  // store, in one form.
  /**
   * Draws the Certificate & Key Configuration pane: its three columns, the
   * extensions, the buttons and the store, in one form.
   *
   * @param json - `pkiJson()`'s model
   * @param draft - the pane's draft
   * @returns the pane's markup
   */
  static certificatePane(json: Json, draft: Json) {
    const self = this;
    const wb = json.workbench;
    const html =
      '<h3 id="workbench">Certificate &amp; Key Configuration</h3>' +
      kit.note(
        '<strong>This is the parent project&rsquo;s <em>PKI / X.509</em> ' +
        'workflow, on the server.</strong> Build a certificate authority and ' +
        'issue the leaf certificates any of them can sign: TLS server, TLS ' +
        'client for mutual authentication, code signing, S/MIME, OCSP ' +
        'responder, time stamping, smartcard logon and Kerberos PKINIT. ' +
        'Every X.509v3 extension RFC 5280 defines is below, plus the ones in ' +
        'common use that it does not, plus anything at all by OID. The ' +
        'encoder is <code>common/vendored/x509.js</code>, that ' +
        'project&rsquo;s own PKI code byte-identical, so a certificate ' +
        'issued here and one issued there are built by <em>one</em> ' +
        'encoder.<p><strong>What is different is where the computation ' +
        'happens.</strong> That page runs Web Crypto in your browser and ' +
        'filters its menus as you change them; this console is ' +
        '<code>script-src &#39;none&#39;</code>, so every choice is a form ' +
        'field and every computation is here. The two <em>Apply</em> buttons ' +
        'are what that costs: narrowing a menu or rewriting the extension ' +
        'boxes from a profile is a round trip rather than an event ' +
        'handler.</p><p><strong>A <code>cRLDistributionPoints</code> or an ' +
        '<code>authorityInfoAccess</code> you type below is a URL you are ' +
        'ASSERTING, and this pane keeps no promise about it.</strong> That ' +
        'was true of every address on this page until 2026-09-11 and it is ' +
        'still true of every address <em>you type</em> &mdash; what changed ' +
        'is that the certificates this service issues <em>itself</em> now ' +
        'name addresses it really answers: each authority signs a CRL and ' +
        'runs an OCSP responder, and anything issued from one of them can be ' +
        'revoked in the pane below. An object minted here from an authority ' +
        'whose key is in this process is in that register too. One typed at ' +
        'a URL of your own is not, and nothing here will pretend ' +
        'otherwise.</p>',
        'What this pane is, and how it differs from the page it is ' +
        'modelled on') +
      '<form method="post" action="/admin/pki/certificate">' +
      '<input type="hidden" name="action" value="issue-certificate">' +
      '<div class="pki-cols">' +
      self.certificateColumn(json, draft) +
      self.keyPairColumn(json, draft) +
      self.subjectColumn(json, draft) +
      '</div>' +
      '<div class="pki-group">X.509v3 Extensions</div>' +
      kit.note(
        'Every extension RFC 5280 defines, plus the ones in common use that ' +
        'it does not, plus anything at all by OID. <strong>The ' +
        '<em>critical</em> flag is separately settable on each</strong>: a ' +
        'validator must reject a certificate carrying a critical extension ' +
        'it does not understand, so making the wrong one critical is a good ' +
        'way to find out what your stack actually implements. Four of them ' +
        'are fixed critical because RFC 5280 says MUST or SHOULD and a box ' +
        'that could clear it would produce a certificate nothing profiles — ' +
        'policyMappings, policyConstraints and inhibitAnyPolicy.',
        'Which extensions are here, and what the critical flag costs') +
      self.extensionCards(json, draft) +
      '<div class="pki-row">' +
      '<button type="submit"' +
      kit.tip('Generate a key pair unless "reuse the key pair below" is ' +
                'ticked, build the certificate, sign it, and keep both in ' +
                'the store below.') +
      '>Generate key pair &amp; issue certificate</button>' +
      '</div>' +
      '<h3>Keys &amp; Certificates</h3>' +
      kit.note(
        'Everything issued from the pane above, in this realm, newest first. ' +
        'Select a row to export it or to load its key pair back into the ' +
        'form. At most ' + esc(String(wb.maxObjects)) +
        ' are kept: past that the oldest goes and the reply says so, because ' +
        'every one of these is sealed, written to the store and pushed to ' +
        'every request worker when it changes.',
        'What this store is') +
      self.storeTable(json, draft) +
      '</form>';
    return html;
  }

  // ===========================================================================
  // THE HIERARCHY AS A TREE (2026-09-11).
  //
  // One Root for the service, an Intermediate per scope, and an Issuing CA per
  // use case under each — with what that authority has actually certified
  // listed beneath it, because a tree of authorities with nothing under them
  // cannot be told from a tree that is wired to nothing.
  //
  // **THE SCOPES IT WALKS ARE THIS REALM'S**, which is `pkiJson()`'s doing and
  // not this function's: it draws whatever `json.tree.scopes` holds, so the
  // question of which branches a reader gets is asked once, above, and this
  // renderer would draw fifty realms just as happily if it were ever handed
  // them.
  //
  // It is drawn as nested lists and not as a diagram. This console has two
  // drawings and both are laid out by `@dagrejs/dagre` on the server; a CA
  // hierarchy is a tree with one root and fixed depth, which indentation says
  // exactly as well and a reader can select text out of.
  // ===========================================================================
  static tierRow(tier: Json, depth: Json, extra?: Json) {
    const self = this;
    if (!tier) {
      return '';
    }
    return '<tr>' +
      '<td style="padding-left:' + (depth * 1.4) + 'rem">' +
      (depth ? '<span class="pki-branch">&#9492;&#9472;</span> ' : '') +
      '<strong>' + esc(tier.label) + '</strong>' +
      (tier.imported ? ' <em>(imported)</em>' : '') +
      (extra || '') + '</td>' +
      '<td><code>' + esc(tier.subject) + '</code></td>' +
      '<td>' + esc(String(tier.notAfter).slice(0, 10)) +
        (tier.expired ? ' <strong>(expired)</strong>' : '') + '</td>' +
      '<td><code>' + esc(tier.keyAlg) + '</code> / <code>' +
        esc(tier.signatureAlg) + '</code>' +
        PqcBadgeView.badge(tier.pqc) +
        self.alternativeNote(tier) + '</td>' +
      '<td><code>' + esc(String(tier.thumbprint).slice(0, 16)) +
      '&hellip;</code><br>' +
      CertificateDialogView.link('/admin/pki', tier.thumbprint, 'pki-tree') +
      '</td></tr>';
  }

  static treeSection(json: Json) {
    const self = this;
    const tree = json.tree;
    if (!tree || !tree.rootBuilt) {
      return kit.warn(
        '<strong>This service has no Root CA.</strong> It is built at ' +
        'startup unless <code>pki.autoBuild</code> is off, so seeing this ' +
        'means either that setting is off or the build failed — the startup ' +
        'log says which. Every key this service holds is self-signed until ' +
        'there is one, which is what this service did before 2026-09-11.',
        'No certificate authority');
    }
    let rows = self.tierRow(tree.root, 0);
    tree.scopes.forEach(function (scope) {
      if (!scope.built) {
        rows += '<tr><td style="padding-left:1.4rem">' +
          '<span class="pki-branch">&#9492;&#9472;</span> <em>' +
          esc(scope.label) + ' — not built</em></td>' +
          '<td colspan="4"><em>This scope has no Intermediate CA. Build it ' +
          'below.</em></td></tr>';
        return;
      }
      rows += self.tierRow(scope.intermediate, 1,
                           ' <span class="pki-scope">' +
                           esc(scope.kind === 'process' ? 'process'
                                                        : 'realm ' +
                                                        scope.label) +
                           '</span>');
      scope.issuing.forEach(function (one) {
        if (!one.built) {
          return;
        }
        rows += self.tierRow(one.ca, 2,
                             ' <span class="pki-scope">' + esc(one.id) +
                             '</span>');
        // What it has certified. Indented under its own authority, because the
        // question a reader brings to a tree of CAs is which of them is
        // actually doing anything.
        one.certified.forEach(function (cert) {
          rows += '<tr><td style="padding-left:4.2rem"><span ' +
            'class="pki-branch">&#9492;&#9472;</span> ' + esc(cert.label) +
            (cert.pinned ? ' <em>(your key)</em>' : '') + '</td>' +
            '<td><code>' + esc(cert.subject) + '</code></td>' +
            '<td>' + esc(String(cert.notAfter).slice(0, 10)) +
              (cert.expired ? ' <strong>(expired)</strong>' : '') + '</td>' +
            '<td><code>' + esc(cert.alg || cert.keyAlg || '') + '</code>' +
              PqcBadgeView.badge(cert.pqc) +
              '</td>' +
            '<td><code>' + esc(String(cert.thumbprint).slice(0, 16)) +
              '&hellip;</code><br>' +
              CertificateDialogView.link('/admin/pki', cert.thumbprint,
                                     'pki-tree') + '</td></tr>';
        });
        if (!one.certified.length) {
          rows += '<tr><td style="padding-left:4.2rem"><em>nothing certified ' +
            'yet</em></td><td colspan="4"><em>' + esc(one.what) +
            '</em></td></tr>';
        }
      });
    });
    return '<table><thead><tr><th>Authority</th><th>Subject</th>' +
      '<th>Expires</th><th>Key / signature</th><th>SHA-256</th></tr></thead>' +
      '<tbody>' + rows + '</tbody></table>';
  }

  static pinnedSection(json: Json) {
    const model = json.pinnedSigners || { on: false, keys: [] };
    const warnings = model.keys.filter(function (one: Json) {
      return one.expiringSoon;
    }).map(function (one: Json) {
      return kit.warn('The certificate of the pinned <code>' +
        esc(one.unit) + '</code> signing key <code>' + esc(one.kid) +
        '</code> ' + (one.expired
          ? '<strong>has expired</strong> (' + esc(one.notAfter) + '), and ' +
            'the key still signs. Relying parties that check it refuse ' +
            'what it signs.'
          : 'expires on ' + esc(String(one.notAfter).slice(0, 10)) + ' (' +
            one.daysLeft + ' day(s)).') + ' A pinned key is never rotated: ' +
        'pin a renewed key pair, or unpin it below.',
        'A pinned signing key is near the end of its life');
    }).join('');
    const rows = model.keys.map(function (one: Json) {
      return '<tr><td><code>' + esc(one.unit) + '</code></td>' +
        '<td><code>' + esc(one.kid) + '</code></td>' +
        '<td>' + esc(one.role === 'active' ? 'signing'
                      : one.role === 'pending'
                        ? 'published; signs from ' + one.activatesAt
                        : 'unpinned; verifies until ' + one.retiredUntil) +
        '</td>' +
        '<td>' + esc(String(one.notAfter).slice(0, 10)) +
          (one.expired ? ' <strong>(expired)</strong>' : '') + '</td>' +
        '<td>' + (one.operatorCertificate ? 'yours' : 'this realm&rsquo;s ' +
          esc(one.useCase) + ' Issuing CA') + '</td>' +
        '<td>' + (one.role === 'retired' ? '' :
          '<form method="post" action="/admin/pki">' +
          '<input type="hidden" name="action" value="unpin-key">' +
          '<input type="hidden" name="useCase" value="' + esc(one.useCase) +
          '"><input type="hidden" name="slot" value="' + esc(one.slot) +
          '"><button type="submit"' + kit.tip('Stop signing with this ' +
            'key. The key this service generated signs again at once — it ' +
            'was published all along — and this one stays published, ' +
            'verifying what it signed, through the unit\'s grace. A ' +
            'signing-key-rotated event is sent.') + '>Unpin</button></form>') +
        '</td></tr>';
    }).join('');
    return '<h3 id="pki-pinned">Pinned signing keys</h3>' +
      kit.note(model.on
        ? '<strong>This realm signs with pinned keys</strong> ' +
          '(<code>pki.pinnedSigners</code>): a key pair pinned into a ' +
          '<em>jose</em> or <em>xml</em> slot below is published at once ' +
          'and signs for that algorithm after <code>' +
          'pki.pinnedSignerLeadMinutes</code> (' + model.leadMinutes +
          ' minute(s)). <strong>Its lifecycle is yours</strong>: it is ' +
          'never rotated, and it ends when its certificate does.'
        : 'Off in this realm (<code>pki.pinnedSigners</code>): the realm ' +
          'signs with the keys it generates, and a pin into a slot it signs ' +
          'from is refused. Turn the setting on to sign with a key pair of ' +
          'your own &mdash; and take over its lifecycle.') +
      warnings +
      (rows ? '<table><thead><tr><th>Unit</th><th>kid</th><th>State</th>' +
              '<th>Expires</th><th>Certificate</th><th></th></tr></thead>' +
              '<tbody>' + rows + '</tbody></table>'
            : '<p><em>Nothing is pinned in this realm.</em></p>');
  }

  static scopeControls(json: Json, scope: Json) {
    const self = this;
    const label = scope.kind === 'process' ? 'the process'
                                           : 'the ' + scope.label + ' realm';
    let html = '<h4>' + esc(scope.kind === 'process' ? 'Process'
                                                    : 'Realm: ' + scope.label) +
      '</h4>';
    html +=
      '<form method="post" action="/admin/pki">' +
      '<input type="hidden" name="action" value="build-scope">' +
      '<input type="hidden" name="scope" value="' + esc(scope.scope) + '">' +
      '<label' + kit.tip('The key algorithm every CA in this branch is ' +
        'generated with. The Root keeps its own — a branch built with a ' +
        'different algorithm from the Root is perfectly legal, and the ' +
        'SIGNATURE on each tier is the one its issuer can produce whatever ' +
        'this says.') + '>Key algorithm <select name="keyAlg">' +
      self.algorithmOptions(json, scope.keyAlg ||
                            json.pageDefaults.keyAlgorithm) +
                            '</select></label> ' +
      self.alternativeField(json, scope.altKeyAlg) +
      '<button type="submit"' +
      kit.tip('Replace this branch: a new Intermediate CA and a new ' +
                'Issuing CA for every use case under it. The Root is NOT ' +
                'touched — every other scope hangs from it. Everything this ' +
                'branch had issued chains to nothing the moment this ' +
                'returns, which is why the certificates under it are ' +
                're-minted in the same act.') +
      '>' + (scope.built ? 'Rebuild' : 'Build') + ' this branch</button>' +
      '</form>';
    if (!scope.built) {
      return html;
    }
    html += '<table><thead><tr><th>Use case</th><th>Issuing ' +
      'CA</th><th>Certified</th><th>Reissue</th><th>Your own ' +
      'CA</th></tr></thead><tbody>';
    scope.issuing.forEach(function (one) {
      html += '<tr>' +
        '<td><strong>' + esc(one.label) + '</strong>' +
          kit.note(esc(one.what)) + '</td>' +
        '<td>' + (one.ca
          ? '<code>' + esc(one.ca.subject) + '</code>' +
            (one.ca.imported ? '<br><em>imported — a CA you supplied</em>' : '')
          : '<em>not built</em>') + '</td>' +
        '<td>' + one.certified.length + '</td>' +
        '<td>' +
          '<form method="post" action="/admin/pki"><input type="hidden" ' +
          'name="action" value="reissue-use-case"><input type="hidden" ' +
          'name="scope" value="' + esc(scope.scope) + '">' +
          '<input type="hidden" name="useCase" value="' + esc(one.id) + '">' +
          '<button type="submit"' +
          kit.tip('Generate a new key pair for this Issuing CA and ' +
                    're-issue it from this scope’s Intermediate, then ' +
                    're-certify everything that hung under it. The other use ' +
                    'cases are untouched, which is the whole reason each has ' +
                    'an authority of its own.') +
          '>Reissue this CA</button></form>' +
          (one.certified.length
            ? '<form method="post" action="/admin/pki">' +
              '<input type="hidden" name="action" value="recertify">' +
              '<input type="hidden" name="scope" value="' + esc(scope.scope) +
              '"><input ' +
              'type="hidden" name="useCase" value="' + esc(one.id) + '">' +
              '<button type="submit"' +
              kit.tip('Re-issue the certificates under this CA from the ' +
                        'same authority, with fresh serials and a fresh ' +
                        'validity window. The KEYS are untouched — this is a ' +
                        'renewal, not a regeneration, so nothing that ' +
                        'verifies against the published keys stops ' +
                        'verifying.') +
              '>Renew certificates</button></form>'
            : '') +
        '</td>' +
        '<td>' +
          (one.certified.length
            ? '<details><summary>Use your own key pair</summary>' +
              kit.note(
                'Replace what this service generated for one SLOT with a key ' +
                'pair of your own. <strong>With no certificate this service ' +
                'issues one</strong> from the authority above, so your key ' +
                'chains to this service&rsquo;s Root exactly as a generated ' +
                'one would; with a certificate, the pair is used as you ' +
                'supplied it and chains wherever that certificate chains.') +
              '<form method="post" action="/admin/pki">' +
              '<input type="hidden" name="action" value="pin-key">' +
              '<input type="hidden" name="scope" value="' + esc(scope.scope) +
              '"><input ' +
              'type="hidden" name="useCase" value="' + esc(one.id) + '">' +
              '<label>Slot <select name="slot">' +
              one.certified.map(function (cert) {
                return '<option value="' + esc(cert.slot) + '">' +
                  esc(cert.slot) + '</option>';
              }).join('') + '</select></label><div ' +
              'class="pki-field"><label>Private key (PEM)<textarea ' +
              'name="privateKeyPem" rows="3"></textarea></label></div><div ' +
              'class="pki-field"><label>Certificate (PEM, optional)<textarea ' +
              'name="certificatePem" ' +
              'rows="2"></textarea></label></div><div ' +
              'class="pki-field"><label>Its chain, leaf&rsquo;s issuer ' +
              'first (PEM, optional; published as the x5c of a pinned ' +
              'signing key)<textarea name="chainPem" ' +
              'rows="2"></textarea></label></div><button type="submit">Use ' +
              'this key pair</button></form></details>'
            : '') +
          '<details><summary>Import a CA</summary><form method="post" ' +
          'action="/admin/pki"><input type="hidden" name="action" ' +
          'value="import-ca"><input type="hidden" name="scope" value="' +
          esc(scope.scope) + '">' +
          '<input type="hidden" name="useCase" value="' + esc(one.id) + '">' +
          '<div class="pki-field"><label>Certificate (PEM)' +
          '<textarea name="certificatePem" rows="3"></textarea></label></div>' +
          '<div class="pki-field"><label>Private key (PEM)' +
          '<textarea name="privateKeyPem" rows="3"></textarea></label></div>' +
          '<button type="submit">Use this as the Issuing CA</button>' +
          '</form></details>' +
        '</td></tr>';
    });
    html += '</tbody></table>';
    return html;
  }

  // The Root's own controls. Separate from a scope's because replacing it is a
  // different act with a different consequence: every branch in the process
  // hangs from it.
  static rootControls(json: Json) {
    const self = this;
    const tree = json.tree;
    return '<h4>The Root CA</h4>' +
      kit.warn(
        '<strong>Replacing the Root replaces the trust anchor for the whole ' +
        'service.</strong> Every scope’s Intermediate is signed by it, so ' +
        'rebuilding it here re-signs all of them in the same act — and ' +
        'anything that was trusting the old Root stops trusting this service ' +
        'until it is given the new one. That is the cost of one anchor ' +
        'covering everything, and it is the reason the button says what it ' +
        'does.',
        'This replaces the anchor everything hangs from') +
      '<form method="post" action="/admin/pki">' +
      '<input type="hidden" name="action" value="build-root">' +
      '<label>Key algorithm <select name="keyAlg">' +
      self.algorithmOptions(json, (tree.root && tree.root.keyAlg) ||
                            json.pageDefaults.keyAlgorithm) +
                            '</select></label> ' +
      self.alternativeField(json, tree.root &&
                            (tree.root.altKeyAlg ||
                             (tree.rootBuilt ? 'none' : ''))) +
      '<label>Common name <input name="commonName" placeholder="' +
      esc(json.pageDefaults.organisation) + ' Root CA"></label> ' +
      '<label>Years <input name="years" size="4" placeholder="20"></label> ' +
      '<button type="submit">' + (tree.rootBuilt ? 'Replace' : 'Build') +
      ' the Root CA</button></form>' +
      '<details><summary>Import a Root of your own</summary>' +
      kit.note(
        'Paste a CA certificate and its private key and this service will ' +
        'hang every Intermediate from it instead of building one &mdash; so ' +
        'the whole tree chains to your own corporate authority and a relying ' +
        'party that already trusts it needs nothing new. <strong>The key is ' +
        'stored exactly as this service stores its own</strong>: in the ' +
        'realm keystore row, sealed under the key-encryption key wherever ' +
        'that key outlives the process, and in the clear in development mode ' +
        'where it does not.') +
      '<form method="post" action="/admin/pki">' +
      '<input type="hidden" name="action" value="import-ca">' +
      '<input type="hidden" name="scope" value="' + esc(json.serviceScope) +
      '"><input ' +
      'type="hidden" name="useCase" value="root"><div ' +
      'class="pki-field"><label>Certificate (PEM)<textarea ' +
      'name="certificatePem" rows="3"></textarea></label></div><div ' +
      'class="pki-field"><label>Private key (PEM)<textarea ' +
      'name="privateKeyPem" rows="3"></textarea></label></div><button ' +
      'type="submit">Use this as the Root CA</button></form></details>';
  }

  // ---------------------------------------------------------------------------
  // WHAT THIS TREE COVERS, SAID ON THE PAGE RATHER THAN LEFT TO BE DISCOVERED.
  //
  // **THIS WAS A WARNING ABOUT WHAT IT DID NOT COVER UNTIL 2026-09-13**, headed
  // *What one anchor does not cover*, and its first paragraph read: *One
  // family of key material in this service is deliberately NOT a leaf of this
  // tree: the eleven post-quantum signing keys per realm. They are generated by
  // common/pq_jose.js — this service's OWN reading of ML-DSA, SLH-DSA and the
  // composite algorithms, which is deliberately independent of the vendored
  // implementation the certificate encoder uses. Handing a key made by one to
  // the other would be exactly the defect that independence exists to expose,
  // so they carry no certificate at all and are published as bare AKP JWKs.*
  //
  // It was reversed by request, and the independence was kept rather than
  // argued away: only the PUBLIC key crosses, the one byte-layout difference is
  // written out in `common/pki.js`'s `pqSubjectPublicKeyPem()`, and
  // `tests/pq_key_certification.js` holds a `pq_jose.js` signature verifying
  // under the vendored reading against the certificate. `common/pki.js` argues
  // it above `PQ_JOSE_IN_X509`. The ML-DSA listener certificate, which was
  // self-signed beside the certified RSA one, came under the TLS Issuing CA the
  // same day. **It is still a note rather than nothing** because two keys
  // remain outside by their nature, and a reader deciding what to pin needs
  // both named.
  //
  // A page that drew a tree and let a reader conclude "everything is under it"
  // would be the most consequential untruth this console could tell about key
  // material — the whole value of one anchor is knowing exactly what it covers.
  //
  // **THIS NOTE LISTED TWO THINGS UNTIL 2026-09-11 AND NOW LISTS ONE.** The
  // second was the SPIFFE X.509 authority, and the paragraph read: *It is
  // self-signed on purpose: a trust domain whose root was also this
  // service's would conflate two unrelated trust decisions, which is what
  // `spiffe/spiffe_ca.ts` has said since it was written — one process, two
  // PKIs. There is a second, mechanical reason: an Issuing CA here carries
  // `pathLen: 0`, so it may sign leaves and no further authority, and a SPIFFE
  // authority signs SVIDs. The SPIFFE Issuing CA is built and ready above,
  // certifying nothing, so that reversing this is a decision rather than a
  // rebuild.*
  //
  // That last sentence is the one that was acted on. The `pathLen` half was a
  // real obstacle and was fixed rather than argued around — the `spiffe` use
  // case carries `pathLen: 1` and the realm Intermediate above it is widened to
  // match, which is what keeps `NewDownstreamX509CA` working —
  // and the trust-decision half is answered by the SPIFFE authority being a
  // SIBLING of the TLS one rather than the same certificate: narrowing trust to
  // SPIFFE alone is still sayable, by pinning that Issuing CA instead of the
  // Root. `spiffe/spiffe_ca.ts`'s own header carries the argument in full.
  // ---------------------------------------------------------------------------
  static coverageNote(json: Json) {
    return kit.note(
      '<strong>Every signing key pair this service generates is a leaf of ' +
      'this tree, the post-quantum ones included</strong> (2026-09-13). A ' +
      'realm&rsquo;s eleven post-quantum signing keys &mdash; ML-DSA, ' +
      'SLH-DSA and the six composites &mdash; are issued from that ' +
      'realm&rsquo;s own <code>JOSE signing</code> Issuing CA as they are ' +
      'made, and each is refused in any other realm by the Intermediate ' +
      'boundary every leaf here is held to. The keys are still generated and ' +
      'signed with by <code>common/pq_jose.js</code>, this service&rsquo;s ' +
      'own reading of those constructions: only the PUBLIC key reaches the ' +
      'certificate encoder, and a signature from one reading is checked to ' +
      'verify under the other against the certificate. The JWKS is unchanged ' +
      '&mdash; they are still published as AKP JWKs. An ML-DSA listener ' +
      'certificate (<code>tls.certificateAlgorithms</code>) is a leaf of the ' +
      '<code>TLS listeners</code> Issuing CA beside the RSA ' +
      'one.<p><strong>Two keys stay outside, by what they are.</strong> The ' +
      'SPIFFE <em>JWT</em> authority has no certificate to issue &mdash; a ' +
      'JWT-SVID is verified against a bare key in the bundle &mdash; and the ' +
      'OpenID4VCI request-encryption key only DECRYPTS and is trusted ' +
      'because a wallet read it out of the issuer&rsquo;s own ' +
      'metadata.</p><p><strong>The SPIFFE X.509 authority used to be on this ' +
      'list and is under this Root</strong> (2026-09-11) &mdash; it is the ' +
      '<code>SPIFFE authority</code> Issuing CA in each realm\'s branch ' +
      'above, and every X509-SVID this service mints is a leaf of it. It is ' +
      'the one Issuing CA in this hierarchy with <code>pathLen: 1</code> ' +
      'rather than <code>0</code>, because <code>NewDownstreamX509CA</code> ' +
      'on the SPIRE Server API asks it for a CA and not a leaf; the realm ' +
      'Intermediate above it is widened to <code>2</code> to match, and ' +
      '<code>common/pki.js</code> derives the second from the first so the ' +
      'two cannot drift. <a href="/admin/spiffe">The SPIFFE page</a> reports ' +
      'which authority each realm is actually using — a realm with no branch ' +
      'built still falls back to a self-signed one and says so.</p>',
      'What one anchor covers');
  }

  static reasonSelect(name: Json, reasons: Json[]) {
    return '<select name="' + esc(name) + '">' +
      reasons.map(function (one) {
        // `superseded` is preselected because it is what a rotation writes and
        // therefore what the overwhelming majority of these entries say. A
        // default of `unspecified` would be the one value RFC 5280 section
        // 5.3.1 says to OMIT the extension for, so the commonest act on this
        // pane would produce the least informative entry available.
        return '<option value="' + esc(one.id) + '"' +
               (one.id === 'superseded' ? ' selected' : '') + '>' +
               esc(one.id) + ' (' + one.code + ')</option>';
      }).join('') + '</select>';
  }

  static issuedRevocationRows(authority: Json, carry: string,
                               reasons: Json[]) {
    const self = this;
    if (!authority.issuedTotal) {
      return '<tr><td colspan="4"><em>This authority has issued nothing this ' +
             'process can still see.</em></td></tr>';
    }
    if (!authority.issued.length) {
      return '<tr><td colspan="4"><em>No certificate this authority issued ' +
             'matches the search above.</em></td></tr>';
    }
    return authority.issued.map(function (cert) {
      const state = cert.revoked
        ? '<span class="bad">revoked</span> ' +
          esc(String(cert.revokedReason)) +
          '<br><span class="muted">' + esc(String(cert.revokedAt)) + '</span>'
        : (cert.expired ? '<span class="muted">expired</span>'
                        : '<span class="ok">good</span>');
      const control = cert.revoked
        ? (cert.held
            ? '<form method="post" action="/admin/pki">' +
              '<input type="hidden" name="action" value="release-hold">' +
              carry +
              '<input type="hidden" name="scope" value="' +
                esc(authority.scope) + '">' +
              '<input type="hidden" name="ca" value="' + esc(authority.ca) +
              '"><input ' +
              'type="hidden" name="serialHex" value="' +
                esc(cert.serialHex) + '">' +
              '<button type="submit"' +
              kit.tip('Take this serial off the list. Only a ' +
                        '`certificateHold` can be released — every other ' +
                        'reason is permanent under RFC 5280, because a ' +
                        'validator is entitled to cache a permanent ' +
                        'revocation for as long as the CRL it read says it ' +
                        'is fresh.') +
              '>Release the hold</button></form>'
            : '<span class="muted">permanent</span>')
        : '<form method="post" action="/admin/pki">' +
          '<input type="hidden" name="action" value="revoke-certificate">' +
          carry +
          '<input type="hidden" name="scope" value="' + esc(authority.scope) +
          '"><input ' +
          'type="hidden" name="ca" value="' + esc(authority.ca) + '">' +
          '<input type="hidden" name="serialHex" value="' +
            esc(cert.serialHex) + '">' +
          '<input type="hidden" name="subject" value="' + esc(cert.subject) +
          '">' +
          self.reasonSelect('reason', reasons) +
          '<input type="text" name="note" placeholder="note (optional)" ' +
            'maxlength="200">' +
          '<button type="submit"' +
          kit.tip('Put this serial on ' + authority.label + '’s revocation ' +
                    'list. It changes nothing about who HOLDS the key — what ' +
                    'it changes is what this service’s CRL and OCSP ' +
                    'responder say about this serial from now on.') +
          '>Revoke</button></form>';
      return '<tr><td><code>' + esc(cert.serialHex) + '</code></td>' +
             '<td>' + esc(cert.subject) +
               (cert.label ? '<br><span class="muted">' + esc(cert.label) +
                             '</span>' : '') +
               '<br><span class="muted">' + esc(cert.kind) + '</span></td>' +
             '<td>' + state + '</td>' +
             '<td>' + control + '</td></tr>';
    }).join('');
  }

  static authorityBlock(authority: Json, listView: Json,
                         reasons: Json[]) {
    const self = this;
    // THIS AUTHORITY'S TWO PAGERS (#370), and every link carries every
    // list's state; so does every Revoke and Release form, as `back` with
    // the list it was pressed in, so the reader lands on the page they were
    // reading rather than on page 1 of everything.
    const issuedNav = kit.pageNavPair('/admin/pki', listView,
                                        authority.issuedPaging);
    const orphansNav = kit.pageNavPair('/admin/pki', listView,
                                         authority.orphansPaging);
    // `list` names the list's SEARCH parameter, because its box is the one
    // thing in the list that is always drawn: the pager's anchor exists only
    // when the list runs to a second page, and a return to an anchor nothing
    // carries lands at the top of the page (2026-09-30).
    const listName = authority.listName;
    const carry = '<input type="hidden" name="back" value="' +
      esc(kit.queryWith(listView, {})) + '">' +
      '<input type="hidden" name="list" value="' +
      esc(listName + '-issuedq') + '">';
    const search = function (list: string, label: string,
                             placeholder: string): string {
      return kit.sectionSearchForm({
        path: '/admin/pki', query: listView,
        param: listName + '-' + list + 'q',
        pageParam: listName + '-' + list + 'Page',
        label: label, placeholder: placeholder
      });
    };
    const orphans = authority.revokedNotIssuedTotal
      ? kit.note(
          '<p><strong>' + authority.revokedNotIssuedTotal + ' serial(s) on ' +
          'this list name a certificate this process no longer holds a ' +
          'record of.</strong> That is the ORDINARY case rather than an ' +
          'error: a certificate superseded by a rotation is revoked and then ' +
          'REPLACED in the register, so the old serial stays on the list ' +
          'with nothing left to point at. RFC 5280 does not ask a CA to ' +
          'still hold what it signed in order to revoke it &mdash; and a ' +
          'validator checking one of these is checking exactly the ' +
          'certificate it was meant to.</p>' +
          search('orphans', 'Search these serials',
                 'a serial, part of a subject, a reason') +
          (!authority.revokedNotIssued.length
            ? '<p><em>No revoked serial here matches the search.</em></p>'
            : orphansNav.head + '<table ' +
          'class="grid"><thead><tr><th>Serial</th><th>Revoked</th>' +
          '<th>Reason</th><th>Subject ' +
          'as recorded</th></tr></thead><tbody>' +
          authority.revokedNotIssued.map(function (entry) {
            return '<tr><td><code>' + esc(entry.serialHex) + '</code></td>' +
                   '<td>' + esc(String(entry.revokedAt)) + '</td>' +
                   '<td>' + esc(entry.reason) + ' (' + entry.reasonCode + ')' +
                   (entry.note ? '<br><span class="muted">' + esc(entry.note) +
                                 '</span>' : '') + '</td>' +
                   '<td>' + esc(entry.subject || '—') + '</td></tr>';
          }).join('') + '</tbody></table>' + orphansNav.foot),
          authority.revokedNotIssuedTotal + ' revoked serial(s) with no ' +
          'certificate left to show')
      : '';

    return '<h4>' + esc(authority.label) + '</h4>' +
      '<p><code>' + esc(authority.subject) + '</code></p>' +
      '<p class="muted">' + authority.issuedTotal + ' issued, ' +
      authority.revokedTotal + ' revoked. A client reads this ' +
      'authority&rsquo;s answer at ' +
      '<code>' + esc(authority.crl.http) + '</code> (HTTP), ' +
      '<code>' + esc(authority.crl.ldap) + '</code> (LDAP) or ' +
      '<code>' + esc(authority.ocsp) + '</code> (OCSP). ' +
      'Every certificate this authority signs names all three inside ' +
      'itself.</p>' +
      (authority.issuedTotal
        ? search('issued', 'Search what it issued',
                 'a serial, part of a subject or a name')
        : '') +
      issuedNav.head +
      '<table class="grid"><thead><tr><th>Serial</th><th>Subject</th>' +
      '<th>Status</th><th></th></tr></thead><tbody>' +
      self.issuedRevocationRows(authority, carry, reasons) +
      '</tbody></table>' + issuedNav.foot + orphans;
  }

  static revocationPane(json: Json, listView: Json) {
    const self = this;
    const model = json.revocation;
    if (!model.authorities.length) {
      return '<h3>Revoking a certificate</h3>' +
        kit.note('There is no certificate authority in the ' +
                   esc(json.realm) +
                   ' realm or on the process branch yet, so there is nothing ' +
                   'here to revoke and no list to publish. Build one above. ' +
                   'Another realm&rsquo;s authorities are not counted ' +
                   '&mdash; they are revoked in that realm.');
    }

    const what = kit.note(
      '<p><strong>A revocation is made BY AN ISSUER</strong>, which is why ' +
      'this pane is organised by authority rather than by certificate: a ' +
      'serial number is unique only within one issuer, so <em>revoke serial ' +
      '4f2a</em> is not a question this service can answer. It is also why ' +
      'there is one CRL and one OCSP responder per authority rather than one ' +
      'per realm &mdash; a list per realm would be a document with no valid ' +
      'issuer, and nothing could sign it.</p><p><strong>This is not the ' +
      '<em>Take the key pair off</em> control in the Applications table, and ' +
      'the difference matters.</strong> That one changes an ' +
      'application&rsquo;s directory entry, so this service stops ACCEPTING ' +
      'what the key signs &mdash; and the certificate goes on chaining to ' +
      'this realm&rsquo;s Root for anybody who only checks the chain. This ' +
      'one changes what the CRL and the OCSP responder SAY, and changes ' +
      'nothing about who holds what. An operator dealing with a compromised ' +
      'key pair almost certainly wants both, and they are two buttons ' +
      'because they are two acts with different blast ' +
      'radii.</p><p><strong>This service PUBLISHES revocation and cannot ' +
      'make anybody consult it.</strong> A certificate revoked here goes on ' +
      'the list and its responder answers <code>revoked</code>; whether that ' +
      'stops anything depends entirely on the relying party. That is true of ' +
      'every certificate authority there has ever been, and it is exactly ' +
      'why a client author would point their stack at this one. <strong>This ' +
      'service does not consult it either</strong> &mdash; a client ' +
      'certificate presented on the main port or on LDAPS 636 is checked ' +
      'against the anchors on <code>/tls/trust</code> and no CRL is fetched ' +
      'for it, so a certificate revoked here still gets in here.</p>',
      'What revoking here does, and the three things it does not do');

    const rotation = kit.note(
      '<p>Most entries on these lists were not put there by hand. ' +
      '<strong>Every rotation revokes what it replaced</strong>, as ' +
      '<code>superseded</code>: reissuing a use case&rsquo;s Issuing CA puts ' +
      'every leaf that CA had signed on its own list and puts the replaced ' +
      'CA on the Intermediate&rsquo;s, and replacing the Root does the same ' +
      'one tier up. That is what makes the lists worth reading &mdash; a ' +
      'service where only hand-revocations appeared would publish an empty ' +
      'CRL for ever while quietly leaving superseded certificates ' +
      'chaining.</p><p>A CRL is <strong>built and signed on demand rather ' +
      'than cached</strong>, so <code>thisUpdate</code> is always now and a ' +
      'revocation is visible to the next fetch. ' +
      '<code>pki.crlLifetimeMinutes</code> is ' +
      esc(String(model.crlLifetimeMinutes)) + ' minute(s), which is what ' +
      '<code>nextUpdate</code> and the HTTP cache header both say. The ' +
      'directory copy under <code>ou=crl</code> is ' +
      (model.publishedToDirectory
        ? 'republished as the list changes'
        : 'OFF (<code>pki.publishCrlToDirectory</code>), so the ' +
          '<code>ldap://</code> address inside ' +
          'these certificates resolve to nothing') + '.</p>',
      'Why these lists are not empty, and how fresh they are');

    const reasons = kit.note(
      '<p>RFC 5280 section 5.3.1 defines eleven values and this service ' +
      'offers nine. <code>7</code> is unused and has never meant anything; ' +
      '<code>removeFromCRL</code> is a delta-CRL verb rather than a reason, ' +
      'and this service publishes no delta CRLs, so offering it would be a ' +
      'control that could never be honoured.</p><ul>' +
      model.reasons.map(function (one) {
        return '<li><code>' + esc(one.id) + '</code> (' + one.code +
               ') &mdash; ' +
               esc(one.what.replace(/\*\*/g, '')) + '</li>';
      }).join('') + '</ul>',
      'The nine reasons, and the two that are deliberately missing');

    return '<h3>Revoking a certificate</h3>' + what + rotation + reasons +
      model.authorities.map(function (authority) {
        return self.authorityBlock(authority, listView, model.reasons);
      }).join('');
  }

  // THE PAGE'S BODY (#446), one method so that it can be one renderer. What
  // a POST answers above it — a banner, a private key handed over once — is
  // the route's, as the notice banner is everywhere else.
  /**
   * Draws the PKI page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - `pkiJson()`'s answer
   * @returns the body as HTML
   */
  static body(ctx: Json, json: Json) {
    const self = this;
    const certificate = json.certificateDetails;
    const chain = json.chain;
    const keyAlg = json.pageDefaults.keyAlgorithm;
    // The two key-pair tables' pages. Every paging link carries both tables'
    // state, and every Take-off button carries it as `back`, so moving or
    // changing one table leaves the other where the reader left it.
    // The rows each table shows are the view's (`issuedShown`,
    // `personsShown`, indices into the whole lists), with its paging.
    const paged = {
      applications: { paging: json.issuedPaging,
                      shown: json.issuedShown.map(function (i: number) {
                        return json.issued[i];
                      }) },
      people: { paging: json.personsPaging,
                shown: json.personsShown.map(function (i: number) {
                  return json.persons[i];
                }) }
    };
    const listView = self.keyPairListView(ctx.query);
    const applicationsNav = kit.pageNavPair('/admin/pki', listView,
                                              paged.applications.paging);
    const peopleNav = kit.pageNavPair('/admin/pki', listView,
                                        paged.people.paging);
    const carryBack = '<input type="hidden" name="back" value="' +
      esc(kit.queryWith(listView, {})) + '">';
    // Each table's search box (2026-09-30), over the list view so it carries
    // the other tables' pages and searches and nothing else.
    const applicationsSearch = kit.sectionSearchForm({
      path: '/admin/pki', query: listView, param: 'issuedq',
      pageParam: 'issuedPage', label: 'Search applications',
      placeholder: 'an identifier, a profile, a handle or an issuer'
    });
    const peopleSearch = kit.sectionSearchForm({
      path: '/admin/pki', query: listView, param: 'personsq',
      pageParam: 'personsPage', label: 'Search people',
      placeholder: 'a username, a handle or an issuer'
    });

    const tiles = '<div class="tiles">' +
      kit.tile(chain ? 'yes' : 'no', 'hierarchy built') +
      kit.tile(chain ? String(chain.tiers.length) : '0', 'CA tiers') +
      kit.tile(chain ? String(chain.issuedCount) : '0',
                 'certificates issued') +
      kit.tile(json.issued.filter(function (one) {
        return one.hasKeyPair;
      }).length,
                 'applications holding one') +
      kit.tile(json.persons.filter(function (one) {
        return one.hasKeyPair || one.saml.hasKeyPair;
      }).length,
                 'people holding one') +
      kit.tile(json.realm, 'trust realm') +
      '</div>';

    const what = kit.note(
      '<p>This page builds a <strong>certificate authority for this trust ' +
      'realm</strong> &mdash; a Root CA, an Intermediate CA and an Issuing ' +
      'CA &mdash; and issues signing key pairs from the bottom of it to ' +
      'applications. It exists because of <strong>RFC 7521 and RFC ' +
      '7523</strong>: an application can authenticate to the token endpoint, ' +
      'or present an authorization grant, with a signed assertion instead of ' +
      'a shared secret &mdash; and a signing key nobody vouched for is a key ' +
      'an operator has to move by hand.</p><p><strong>All three tiers are ' +
      'built in one act, or none is.</strong> A trust chain is only worth ' +
      'anything whole: an Issuing CA with no Intermediate above it is a ' +
      'two-tier chain wearing a three-tier name, and a half-built hierarchy ' +
      'is exactly the state in which somebody issues a certificate that ' +
      'verifies here and nowhere else.</p><p><strong>It is per ' +
      'realm.</strong> A trust realm is a logical identity service with its ' +
      'own signing key and its own applications; a CA shared across realms ' +
      'would be one authority vouching for several services, which is the ' +
      'one thing a realm boundary exists to prevent. This page shows the ' +
      '<code>' + esc(json.realm) + '</code> realm.</p><p>The encoder ' +
      'is <code>common/vendored/x509.js</code> &mdash; the parent ' +
      'project&rsquo;s own PKI code, byte-identical, the same one behind its ' +
      '<em>PKI / X.509</em> workflow page. So a certificate issued here and ' +
      'one issued there are built by <em>one</em> encoder, and a difference ' +
      'between them is a difference in the arguments rather than in two ' +
      'implementations that drifted.</p>',
      'What this page is');

    // **THIS BLOCK SAID *Nothing here is revoked, ever* UNTIL 2026-09-11**, and
    // it was true when it was written. What replaced it is narrower rather than
    // absent, because the interesting limit did not go away when the CRLs
    // arrived — it moved. It read *this service publishes revocation and
    // consults none* until 2026-09-12, when presented certificates began to be
    // checked (`common/revocation_status.js`); `json.revocationNote` is
    // `pki.report()`'s sentence and says what is consulted now.
    const limits = kit.warn(
      '<p><strong>Revocation here is PUBLISHED and never ENFORCED.</strong> ' +
      esc(json.revocationNote) + '</p><p>' + esc(json.residency) + '</p>',
      'What this certificate authority does not do');

    const buildForm =
      '<h3>' + (chain ? 'Rebuild' : 'Build') + ' the hierarchy</h3>' +
      (chain ? kit.warn(
        'A hierarchy already exists. Building again ' +
        '<strong>replaces</strong> it, and every certificate issued from the ' +
        'old one chains to nothing the moment it does &mdash; this service ' +
        'keeps no copy of what it issued, so none of them can be listed here.',
        'This replaces what is there') : '') +
      '<form method="post" action="/admin/pki">' +
      '<input type="hidden" name="action" value="build">' +
      '<label>Key algorithm <select name="keyAlg">' +
        self.algorithmOptions(json, keyAlg) + '</select></label> ' +
      '<label>Signature algorithm <select name="signatureAlg">' +
        self.signatureOptions(json, keyAlg) + '</select></label> ' +
      self.alternativeField(json, '') +
      '<label>Organisation (O=) <input name="organisation" value="' +
        esc(json.pageDefaults.organisation) + '"></label> <label>Country ' +
      '(C=) <input name="country" size="4" ' +
      'maxlength="2"></label><p>' + json.tierLabels.map(function (tier) {
        return '<label>' + esc(tier.label) + ' CN <input name="cn_' +
          esc(tier.id) + '" placeholder="(named after the ' +
          'organisation)"></label> <label>years <input ' +
          'name="years_' + esc(tier.id) +
          '" size="4" placeholder="' +
          esc(String((json.tiers.filter(function (t) {
            return t.id === tier.id;
          })[0] || {}).years || '')) + '"></label>';
      }).join(' ') + '</p>' +
      '<button type="submit">' + (chain ? 'Rebuild' : 'Build') +
      ' the certificate authority</button>' +
      '</form>' +
      (chain
        ? '<form method="post" action="/admin/pki">' +
          '<input type="hidden" name="action" value="clear">' +
          '<button type="submit">Remove the hierarchy</button></form>'
        : '');

    const purposeOptions = json.purposes.map(function (one) {
      return '<option value="' + esc(one.id) + '">' + esc(one.label) +
             '</option>';
    }).join('');

    const issueForm = chain
      ? '<h3>Issue a signing key pair to an application</h3>' +
        kit.tip(
          'The key pair is generated here, signed by the Issuing CA, and ' +
          'written onto that application’s entry. WHICH attributes depends ' +
          'on the profile: RFC 7523 writes seven &mdash; ' +
          'oauthAssertionPrivateKey, oauthAssertionCertificate, ' +
          'oauthAssertionCertificateChain, oauthAssertionJwks, ' +
          'oauthAssertionKid, oauthAssertionExpiresAt and ' +
          'oauthAssertionKeySource &mdash; and RFC 7522 writes six under ' +
          'oauthSamlAssertion*, with no JWKS among them because SAML has ' +
          'none: what a party registers for that profile is a certificate. ' +
          '<strong>They are separate key pairs and an application may hold ' +
          'both</strong>; neither can sign for the other’s profile, and ' +
          'taking one off leaves the other working. This service keeps NO ' +
          'second copy of the private key — the entry is where it lives, and ' +
          'it is SEALED there: AES-256-GCM under the same key-encryption key ' +
          'as the certificate authority above, wherever that key outlives ' +
          'the process. A directory dump, an ldif file, a database row or a ' +
          'backup holds ciphertext; this console and /admin-api open it for ' +
          'you, because the seal protects the store rather than the page you ' +
          'collect the key from. In development mode it is written in the ' +
          'clear, where the key-encryption key would not survive the restart ' +
          'the entry does. Issuing again replaces what is there.',
          'What issuing writes, and where') +
        '<form method="post" action="/admin/pki">' +
        '<input type="hidden" name="action" value="issue">' +
        '<label>Application <input name="identifier" required></label> ' +
        '<label>Profile <select name="purpose">' + purposeOptions +
          '</select></label> ' +
        '<label>Subject CN <input name="commonName" ' +
          'placeholder="(the application identifier)"></label> ' +
        '<label>Key algorithm <select name="leafKeyAlg">' +
          '<option value="">(the Issuing CA’s: ' + esc(chain.keyAlg) +
          ')</option>' + self.algorithmOptions(json, '') +
          '</select></label> ' +
        '<label>Days <input name="days" size="5" value="' +
          esc(String(json.pageDefaults.leafLifetimeDays)) + '"></label> ' +
        '<button type="submit">Generate and issue</button>' +
        '</form>'
      : kit.warn(
        'There is no certificate authority in this realm yet, so there is ' +
        'nothing to issue from. Build one above.',
        'Nothing to issue from');

    // -------------------------------------------------------------------------
    // AND THE SAME CONTROL FOR A PERSON (2026-09-11).
    //
    // It is a form of its own rather than a radio button on the one above, and
    // the reason is the POST target: this one goes to /admin/pki/person, which
    // answers with a PAGE carrying the private key, where every other control
    // on this page 303s with its message on the query string. A private key on
    // a query string is a private key in the browser history, the access log
    // and the next request's Referer header.
    //
    // The ACTION is the same `issue` and the field that tells them apart is
    // `target`, so `/admin-api/pki/issue` drives both — which is rule 7 with no
    // second operation invented for it.
    // -------------------------------------------------------------------------
    const personForm = chain
      ? '<h3>Issue a signing key pair to a person</h3>' +
        kit.tip(
          'RFC 7523 section 2.1 does not say the issuer of an assertion has ' +
          'to be an application. Claim 1 asks only that <code>iss</code> be ' +
          '“a unique identifier for the JWT issuer”, and claim 2 says the ' +
          '<code>sub</code> of an authorization grant “typically identifies ' +
          'an authorized accessor or resource owner”. So a person holding a ' +
          'key of their own, signing <em>this is me, issue a token for ' +
          'me</em>, is the profile read literally — and it is the shape a ' +
          'client author most often wants to exercise: no browser, no ' +
          'password, a signature and an access token. RFC 7522 reads the ' +
          'same way for a SAML <code>&lt;Issuer&gt;</code>. This writes ' +
          '<code>stsAssertion*</code> for the JWT profile or ' +
          '<code>stsSamlAssertion*</code> for the SAML one onto that ' +
          'person’s entry — two sets sharing no name, so neither key pair ' +
          'signs for the other — with the private half sealed exactly as an ' +
          'application’s is. The person’s own page under ' +
          '<code>/admin/users</code> draws both, and replaces either with an ' +
          'uploaded certificate.',
          'What a person’s key pair is for') +
        kit.warn(
          '<p><strong>A person’s assertion may only be about ' +
          'themselves.</strong> The <code>iss</code> and the ' +
          '<code>sub</code> must name the same person, and one naming ' +
          'anybody else is refused — a key issued to one resource owner is ' +
          'that person’s credential rather than permission to speak for the ' +
          'others, and without the rule anybody given a key here could ' +
          'obtain a token as anybody in this realm. <strong>A party that may ' +
          'assert about other people is an APPLICATION</strong> with the ' +
          'issuer declared on it as <code>oauthAssertionIssuer</code> (or ' +
          '<code>oauthSamlAssertionIssuer</code>), which is a decision an ' +
          'operator makes deliberately. That is the whole difference between ' +
          'the two controls.</p><p><strong>The private key is shown ' +
          'once.</strong> It comes back on the page this form posts to and ' +
          'there is no second door to it: it is sealed on the entry and ' +
          'nothing here opens it. An application’s is different because ' +
          '<code>/admin/applications</code> already opens that one, and a ' +
          'console page that printed a <em>person’s</em> private key on ' +
          'every visit would be a worse answer than this.</p>',
          'Two things to know before you press it') +
        '<form method="post" action="/admin/pki/person">' +
        '<input type="hidden" name="action" value="issue">' +
        '<input type="hidden" name="target" value="person">' +
        // BOTH PROFILES SINCE 2026-09-13, which is the select this form did not
        // have: the SAML bearer grant reads a person's RFC 7522 key pair now.
        '<label>Profile <select name="purpose">' +
          json.purposes.map(function (one) {
            return '<option value="' + esc(one.id) + '">' + esc(one.label) +
                   '</option>';
          }).join('') + '</select></label> ' +
        '<label>Person <input name="identifier" required ' +
          'placeholder="a username in ou=users"></label> ' +
        '<label>Declared issuer <input name="issuer" ' +
          'placeholder="(their username)"></label> ' +
        '<label>Subject CN <input name="commonName" ' +
          'placeholder="(their username)"></label> ' +
        '<label>Key algorithm <select name="leafKeyAlg">' +
          '<option value="">(the Issuing CA’s: ' + esc(chain.keyAlg) +
          ')</option>' + self.algorithmOptions(json, '') +
          '</select></label> ' +
        '<label>Days <input name="days" size="5" value="' +
          esc(String(json.pageDefaults.leafLifetimeDays)) + '"></label> ' +
        '<button type="submit">Generate and issue</button>' +
        '</form>'
      : '';

    const personRows = !json.personsStorable
      ? kit.warn(
        'This process has no directory, so nobody can hold an assertion key ' +
        'pair and an assertion naming a person as its issuer is refused for ' +
        'want of a registered issuer.', 'No directory')
      : (json.persons.length
        // A ROW PER PROFILE A PERSON HOLDS OR DECLARES (2026-09-13), for the
        // applications table's reason: every fact on the row — the handle, the
        // expiry, the declared issuer and the Take-off button — is per profile.
        ? peopleSearch + (!paged.people.shown.length
          ? '<p><em>Nobody matches the search.</em></p>'
          : peopleNav.head +
          '<table><thead><tr><th>Person</th><th>Profile</th>' +
          '<th>Key handle</th><th>Source</th><th>Expires</th>' +
          '<th>Asserts as</th><th></th></tr></thead><tbody>' +
          paged.people.shown.reduce(function (rows, one) {
            [{ id: 'jwt', label: 'RFC 7523 (JWT)', handleLabel: 'kid',
               fact: one, handle: one.kid },
             { id: 'saml', label: 'RFC 7522 (SAML 2.0)',
               handleLabel: 'thumbprint', fact: one.saml,
               handle: one.saml.thumbprint }].forEach(function (p) {
              if (!p.fact.hasKeyPair && !p.fact.declared) {
                return;
              }
              rows.push('<tr>' +
                '<td><a href="/admin/users?user=' +
                  encodeURIComponent(one.username) + '#credentials">' +
                  esc(one.username) + '</a></td>' +
                '<td>' + esc(p.label) + '</td>' +
                '<td><code>' + esc(p.handle || '—') + '</code>' +
                  (p.handle ? ' <small>(' + p.handleLabel + ')</small>' : '') +
                  PqcBadgeView.badge(p.fact.pqc) + '</td>' +
                '<td>' + esc(p.fact.source || '—') + '</td>' +
                '<td>' + esc(p.fact.expiresAt ? p.fact.expiresAt.slice(0, 8)
                                              : '—') + '</td>' +
                '<td>' + p.fact.issuers.map(function (iss) {
                    return '<code>' + esc(iss) + '</code>';
                  }).join('<br>') +
                  (p.fact.declared ? '' : ' <small>(their own name — nothing ' +
                                          'is declared)</small>') + '</td>' +
                '<td>' + (p.fact.hasKeyPair
                  ? '<form method="post" action="/admin/pki"><input ' +
                    'type="hidden" name="action" value="revoke"><input ' +
                    'type="hidden" name="target" value="person"><input ' +
                    'type="hidden" name="purpose" value="' + p.id + '">' +
                    '<input type="hidden" name="identifier" value="' +
                      esc(one.username) + '">' + carryBack +
                    '<button type="submit">Take this key pair off</button>' +
                    '</form>'
                  : '') + '</td>' +
                '</tr>');
            });
            return rows;
          }, []).join('') + '</tbody></table>' + peopleNav.foot)
        : '<p>Nobody in this realm holds an assertion key pair.</p>');

    const issuedRows = json.issued.length
      ? applicationsSearch + (!paged.applications.shown.length
        ? '<p><em>No application row matches the search.</em></p>'
        : applicationsNav.head +
        '<table><thead><tr><th>Application</th><th>Profile</th>' +
        '<th>Key handle</th><th>Expires</th>' +
        '<th>Declared issuer</th><th>Own keys</th><th></th></tr>' +
        '</thead><tbody>' +
        paged.applications.shown.map(function (one) {
          return '<tr>' +
            '<td><a href="/admin/applications?application=' +
              encodeURIComponent(one.identifier) + '">' +
              esc(one.identifier) + '</a></td>' +
            '<td>' + esc(one.purposeLabel) + '</td>' +
            '<td><code>' + esc(one.handle || '—') + '</code>' +
              (one.handle ? ' <small>(' + esc(one.handleLabel) + ')</small>' :
               '') + PqcBadgeView.badge(one.pqc) +
              '</td>' +
            '<td>' + esc(one.expiresAt ? one.expiresAt.slice(0, 8) : '—') +
              '</td>' +
            '<td>' + (one.assertionIssuers.length
              ? one.assertionIssuers.map(function (iss) {
                  return '<code>' + esc(iss) + '</code>';
                }).join('<br>')
              : '<em>none — it can authenticate, and cannot present an ' +
                'authorization grant</em>') + '</td>' +
            '<td>' + (one.registeredOwnKeys ? 'yes' : 'no') + '</td>' +
            '<td>' + (one.hasKeyPair
              ? '<form method="post" action="/admin/pki">' +
                '<input type="hidden" name="action" value="revoke">' +
                '<input type="hidden" name="identifier" value="' +
                  esc(one.identifier) + '">' +
                '<input type="hidden" name="purpose" value="' +
                  esc(one.purpose) + '">' + carryBack +
                '<button type="submit">Take this key pair off</button></form>'
              : '') + '</td>' +
            '</tr>';
        }).join('') + '</tbody></table>' + applicationsNav.foot)
      : '<p>No application in this realm holds a key pair issued here, and ' +
        'none declares an assertion issuer.</p>';

    const twoActs = kit.note(
      '<p>Holding a key pair and being <em>trusted to assert</em> are two ' +
      'different things, and this table shows both because an application ' +
      'commonly has one and not the other.</p><p><strong>A key pair</strong> ' +
      'lets an application sign. That is all RFC 7523 <em>section 2.2</em> ' +
      'needs &mdash; client authentication, where the assertion says who is ' +
      'calling &mdash; so an application with a key pair and no declared ' +
      'issuer can already authenticate at the token endpoint with ' +
      '<code>private_key_jwt</code>.</p><p><strong>A declared ' +
      '<code>iss</code></strong> (<code>oauthAssertionIssuer</code>, set on ' +
      'the application&rsquo;s own page) is what section <em>2.1</em> needs ' +
      '&mdash; the authorization grant, where the assertion says who the ' +
      'token is <em>for</em>. That grant has no browser, no password and no ' +
      'consent step in it, so the signature is the whole of its security: ' +
      'this service will not accept one from an issuer nobody declared, and ' +
      '<code>oauth2.jwtBearerRequireRegisteredIssuer</code> is on by default ' +
      'for the same reason federation refuses by default.</p><p>An assertion ' +
      'a client issues <em>about itself</em> needs no declaration: its ' +
      '<code>iss</code> is its own <code>client_id</code>, and that lookup ' +
      'already succeeds.</p><p><strong>RFC 7522 is the same two acts over a ' +
      'SAML 2.0 assertion</strong>, with its own key pair and its own ' +
      'declaration (<code>oauthSamlAssertionIssuer</code>). The two profiles ' +
      'are kept apart deliberately: an application trusted to assert as a ' +
      'JWT has not thereby been trusted to assert as SAML, and the key pairs ' +
      'cannot stand in for one another. There is one further difference, and ' +
      'it is the only place this service is <em>stricter</em> for SAML: a ' +
      'JWT assertion may carry its certificate chain in <code>x5c</code> and ' +
      'be accepted because the chain reaches this realm&rsquo;s Root, and a ' +
      'SAML assertion may not. A chain proves the <em>realm</em> issued a ' +
      'key; the URI subjectAltName in the leaf says who to, and the JWT ' +
      'grant reads it for exactly one purpose &mdash; holding a PERSON to ' +
      'asserting about themselves &mdash; rather than binding an ' +
      'application. So a chain still says nothing usable about ' +
      '<em>which</em> application holds a key, and accepting one here would ' +
      'let an application&rsquo;s RFC 7523 leaf sign a SAML assertion, which ' +
      'is exactly the crossing the two key pairs exist to prevent.</p>',
      'A key pair is not a trust decision');

    return tiles + what + limits + PqcBadgeView.legend() +
                  '<h3 id="pki-tree">The hierarchy</h3>' +
                  kit.note(
                    '<strong>One Root CA for the whole service, an ' +
                    'Intermediate CA per scope, and an Issuing CA for each ' +
                    'use case under it.</strong> Every key pair this service ' +
                    'generates is a leaf of this tree &mdash; the signing ' +
                    'keys of every realm, and the certificate the main port ' +
                    'and LDAPS 636 serve &mdash; so an operator installs ONE ' +
                    'anchor and it covers both of those sockets and every ' +
                    'token this service signs.<p><strong>A realm shares the ' +
                    'Root and has an Intermediate of its own</strong>, and ' +
                    'that is where the realm boundary is: with one Root, ' +
                    '&ldquo;this chains to our Root&rdquo; is true of every ' +
                    'realm&rsquo;s certificates, so a path is checked ' +
                    'against this realm&rsquo;s own Intermediate instead. A ' +
                    'certificate issued in one realm still does not verify ' +
                    'in another.</p><p><strong>What is drawn below is the ' +
                    esc(json.realm) + ' realm&rsquo;s, and only ' +
                    'that.</strong> The Root, because every realm hangs from ' +
                    'it; the <em>process</em> branch, because the TLS and ' +
                    'SPIFFE authorities certify sockets every realm answers ' +
                    'on; and this realm&rsquo;s own Intermediate with its ' +
                    'Issuing CAs. Another realm&rsquo;s branch is not here ' +
                    'and cannot be edited from here &mdash; <strong>switch ' +
                    'realms to reach it</strong>, which is how every other ' +
                    'setting on this console already works. <code>GET ' +
                    '/admin-api/pki</code> answers exactly this, in ' +
                    'whichever realm it is reached in.</p><p>It is built at ' +
                    'startup (<code>pki.autoBuild</code>). Turning that off ' +
                    'is how this service behaves as it did before ' +
                    '2026-09-11: nothing is built until Build is pressed and ' +
                    'every key carries the self-signed certificate it was ' +
                    'born with.</p>',
                    'What this tree is, and where the realm boundary went') +
                  self.treeSection(json) +
                  self.coverageNote(json) +
                  self.pinnedSection(json) +
                  '<h3>Edit the hierarchy</h3>' +
                  self.rootControls(json) +
                  (json.tree.scopes || []).map(function (scope) {
                    return self.scopeControls(json, scope);
                  }).join('') +
                  (chain ? '<h3 id="pki-chain">This realm&rsquo;s three-tier ' +
                           'view</h3>' +
                           kit.note(
                             'The Root, this realm&rsquo;s Intermediate and ' +
                             'its <em>application assertion</em> Issuing CA ' +
                             '&mdash; which is what <code>GET ' +
                             '/admin-api/pki</code> has always answered and ' +
                             'what RFC 7523 needs. The other Issuing CAs are ' +
                             'in the tree above.') +
                           self.chainTable(chain) +
                           self.pemBlocks(chain) : '') +
                  buildForm + issueForm +
                  '<h3 id="pki-applications">Applications</h3>' + twoActs +
                  // NO *Rows per table* CONTROL (2026-09-30). Every size it
                  // offered is above this page's ceiling of five and would be
                  // clamped back to it, and a select whose choices all do
                  // nothing is a control that lies about the page. `?per=`
                  // still shortens every list, by hand.
                  issuedRows +
                  personForm +
                  '<h3 id="pki-people">People</h3>' + personRows +
                  self.revocationPane(json, listView) +
                  self.certificatePane(json, json.workbench.draft) +
                  SettingsForms.forms(json.settings, '/admin/pki') +
                  (certificate
                    ? CertificateDialogView.dialog('/admin/pki', certificate,
                                               ctx.query.from)
                    : '');
  }
}

export = PkiPage;
