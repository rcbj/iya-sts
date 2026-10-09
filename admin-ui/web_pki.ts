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
  static chainTable(chain: Json, t: Json) {
    const self = this;
    if (!chain) {
      return '';
    }
    // A tier's label and what it is for are the view's. The tip's second
    // argument is what it always was: the tip takes a length there, and a
    // string in it changes nothing a reader sees.
    const rows = chain.tiers.map(function (tier) {
      return '<tr>' +
        '<td><strong>' + esc(tier.label) + '</strong></td>' +
        '<td><code>' + esc(tier.subject) + '</code></td>' +
        '<td><code>' + esc(tier.serialHex.slice(0, 16)) +
        '&hellip;</code></td>' + '<td>' + esc(tier.notAfter.slice(0, 10)) +
          (tier.expired ? ' <strong>' + t.html('consolePki.expired') +
                          '</strong>' : '') + '</td>' +
        '<td><code>' + esc(tier.keyAlg) + '</code> / <code>' +
          esc(tier.signatureAlg) + '</code>' +
          PqcBadgeView.badge(tier.pqc, t) +
          self.alternativeNote(tier, t) + '</td>' +
        '<td><code>' + esc(tier.thumbprint.slice(0, 16)) +
        '&hellip;</code><br>' +
        CertificateDialogView.link('/admin/pki', tier.thumbprint, 'pki-chain',
                                   undefined, t) +
        '</td></tr><tr><td ' +
        'colspan="6">' + kit.tip(tier.what,
          'What the ' + tier.label + ' is for') + '</td></tr>';
    }).join('');
    return '<table><thead><tr><th>' + t.html('consolePki.thTier') +
           '</th><th>' + t.html('consolePki.thSubject') + '</th><th>' +
           t.html('consolePki.thSerial') + '</th>' +
           '<th>' + t.html('consolePki.thExpires') + '</th><th>' +
           t.html('consolePki.thKeySignature') + '</th><th>SHA-256</th></tr>' +
           '</thead><tbody>' + rows + '</tbody></table>';
  }

  static pemBlocks(chain: Json, t: Json) {
    if (!chain) {
      return '';
    }
    // The certificates, in full, because the ONE thing a relying party has to
    // be given out of band is the Root — and a page that showed a thumbprint
    // and made somebody find the bytes elsewhere would be a page that stops at
    // the interesting part. They are public: a certificate is the half of a key
    // pair that is meant to be handed around.
    return chain.tiers.map(function (tier) {
      return '<details><summary>' +
        t.html('consolePki.certificatePem', { label: tier.label }) +
        '</summary><pre>' + esc(tier.certificatePem) +
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
  static alternativeField(json: Json, selected: Json, t: Json) {
    const chosen = String(selected || '') ||
                   String(json.pageDefaults.alternativeKeyAlgorithm);
    const options = (json.alternativeKeyAlgorithms || []).map(function (id) {
      return '<option value="' + esc(id) + '"' +
        (id === chosen ? ' selected' : '') + '>' +
        esc(id === 'none' ? t.text('consolePki.altNone') : id.toUpperCase()) +
        '</option>';
    }).join('');
    return '<label' + kit.tip(t.text('consolePki.altKeyTip')) +
      '>' + t.html('consolePki.altKey') + ' <select name="altKeyAlg">' +
      options + '</select></label> ';
  }

  // A tier's hybrid half (#68), under its classical algorithms: the key it
  // holds and the algorithm its own alternative signature was made with.
  static alternativeNote(tier: Json, t: Json) {
    if (!tier || !tier.altKeyAlg) {
      return '';
    }
    return '<br><small>' +
      t.html('consolePki.altNote', { alg: tier.altKeyAlg }) +
      (tier.altSignatureAlg
        ? t.html('consolePki.altSigned', { alg: tier.altSignatureAlg })
        : t.html('consolePki.altUnsigned')) + '</small>';
  }

  static signatureOptions(json: Json, keyAlg: Json, t: Json) {
    // Every algorithm, with the ones this key cannot produce marked rather than
    // hidden — a dropdown that silently drops half its entries when another
    // field changes is a dropdown nobody can reason about with no script to
    // explain it. An impossible pair is refused at the build with the list
    // beside it, which is a sentence rather than a mystery.
    const kind = (json.keyAlgorithms.filter(function (one) {
      return one.id === keyAlg;
    })[0] || {}).kind;
    return '<option value="">' + t.html('consolePki.sigRightOne') +
      '</option>' +
      json.signatureAlgorithms.map(function (one) {
        return '<option value="' + esc(one.id) + '">' + esc(one.label) +
          (one.kind !== kind ? t.html('consolePki.sigNeeds',
                                      { kind: one.kind }) : '') +
          (one.weak ? t.html('consolePki.sigWeakProduct') : '') +
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
  static extensionCards(json: Json, draft: Json, t: Json) {
    const self = this;
    const cards = [];
    // An extension's name and the word `critical` are X.509's own and are
    // drawn as they are; the tooltips and the box labels are translated
    // (#539). A tooltip's `<oid>`-style placeholders go in as parameters:
    // the tooltip strips tags, as it always has, and a message may not carry
    // an element it does not allow.
    const critical = 'critical';
    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_bc', 'basicConstraints',
                      t.text('consolePki.bcTip')) +
      self.checkField(draft, 'pki_bc_critical', critical,
                      t.text('consolePki.bcCriticalTip')),
      self.checkField(draft, 'pki_bc_ca', 'cA',
                      t.text('consolePki.bcCaTip')) +
      self.textField(draft, 'pki_bc_pathlen', 'pathLenConstraint',
                     t.text('consolePki.bcPathlenTip'),
                     ' size="6" placeholder="' +
                     esc(t.text('consolePki.unlimited')) + '"')));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_ku', 'keyUsage',
                      t.text('consolePki.kuTip')) +
      self.checkField(draft, 'pki_ku_critical', critical,
                      t.text('consolePki.kuCriticalTip')),
      '<div class="pki-flags">' +
      json.workbench.keyUsageBits.map(function (bit) {
        return self.checkField(draft, 'pki_ku_' + bit.name, bit.name, bit.what);
      }).join('') + '</div>'));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_eku', 'extendedKeyUsage',
                      t.text('consolePki.ekuTip')) +
      self.checkField(draft, 'pki_eku_critical', critical,
                      t.text('consolePki.ekuCriticalTip')),
      '<div class="pki-flags">' +
      json.workbench.extendedKeyUsages.map(function (one) {
        return self.checkField(draft, 'pki_eku_' + one.name, one.name, one.oid);
      }).join('') + '</div>' +
      self.areaField(draft, 'pki_eku_extra',
                     t.text('consolePki.ekuExtraLabel'),
                     t.text('consolePki.ekuExtraTip',
                            { n: json.workbench.extendedKeyUsages.length }),
                     1, '1.3.6.1.4.1.99999.1.1')));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_skid', 'subjectKeyIdentifier',
                      t.text('consolePki.skidTip')), ''));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_akid', 'authorityKeyIdentifier',
                      t.text('consolePki.akidTip')),
      self.checkField(draft, 'pki_akid_issuer_serial',
                      t.text('consolePki.akidIssuerSerial'),
                      t.text('consolePki.akidIssuerSerialTip'))));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_san', 'subjectAltName',
                      t.text('consolePki.sanTip')) +
      self.checkField(draft, 'pki_san_critical', critical,
                      t.text('consolePki.sanCriticalTip')),
      self.areaField(draft, 'pki_san', t.text('consolePki.namesPerLine'),
                     t.text('consolePki.sanSyntax',
                            { oid: '<oid>', der: '<base64 DER>' }),
                     2, 'dns:localhost\nip:127.0.0.1')));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_ian', 'issuerAltName',
                      t.text('consolePki.ianTip')) +
      self.checkField(draft, 'pki_ian_critical', critical,
                      t.text('consolePki.ianCriticalTip')),
      self.areaField(draft, 'pki_ian', t.text('consolePki.namesPerLine'),
                     t.text('consolePki.ianSyntax'), 1,
                     'uri:https://ca.example.com/')));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_cdp', 'cRLDistributionPoints',
                      t.text('consolePki.cdpTip')) +
      self.checkField(draft, 'pki_cdp_critical', critical,
                      t.text('consolePki.rarelyCritical')),
      self.areaField(draft, 'pki_cdp', t.text('consolePki.urlsPerLine'),
                     t.text('consolePki.cdpUrlsTip'), 1,
                     'http://crl.example.com/issuing.crl')));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_freshest', 'freshestCRL',
                      t.text('consolePki.freshestTip')),
      self.areaField(draft, 'pki_freshest', t.text('consolePki.urlsPerLine'),
                     t.text('consolePki.freshestUrlsTip'), 1,
                     'http://crl.example.com/delta.crl')));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_aia', 'authorityInfoAccess',
                      t.text('consolePki.aiaTip')),
      self.areaField(draft, 'pki_aia', t.text('consolePki.accessPerLine'),
                     t.text('consolePki.aiaSyntax',
                            { url: '<url>', oid: '<oid>' }), 2,
                     'ocsp:http://ocsp.example.com\n' +
                     'caissuers:http://example.com/ca.cer')));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_sia', 'subjectInfoAccess',
                      t.text('consolePki.siaTip')),
      self.areaField(draft, 'pki_sia', t.text('consolePki.accessPerLine'),
                     t.text('consolePki.siaSyntax'), 1,
                     'carepository:http://example.com/certs/')));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_policies', 'certificatePolicies',
                      t.text('consolePki.policiesTip')) +
      self.checkField(draft, 'pki_policies_critical', critical,
                      t.text('consolePki.policiesCriticalTip')),
      self.areaField(draft, 'pki_policies',
                     t.text('consolePki.policiesPerLine'),
                     t.text('consolePki.policiesSyntax',
                            { oid: '<policy oid>', uri: '<uri>',
                              text: '<text>' }), 2,
                     '1.3.6.1.4.1.99999.1.1|cps=https://example.com/cps' +
                     '|notice=Test certificates only')));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_policy_mappings', 'policyMappings',
                      t.text('consolePki.mappingsTip')),
      self.areaField(draft, 'pki_policy_mappings',
                     t.text('consolePki.mappingsPerLine'),
                     t.text('consolePki.mappingsSyntax',
                            { issuer: '<issuer policy oid>',
                              subject: '<subject policy oid>' }), 1,
                     '1.3.6.1.4.1.99999.1.1=1.3.6.1.4.1.88888.1.1')));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_policy_constraints', 'policyConstraints',
                      t.text('consolePki.policyConstraintsTip')),
      self.textField(draft, 'pki_require_explicit_policy',
                     'requireExplicitPolicy',
                     t.text('consolePki.requireExplicitTip'),
                     ' size="6" placeholder="' +
                     esc(t.text('consolePki.notSet')) + '"') +
      self.textField(draft, 'pki_inhibit_policy_mapping',
                     'inhibitPolicyMapping',
                     t.text('consolePki.inhibitMappingTip'),
                     ' size="6" placeholder="' +
                     esc(t.text('consolePki.notSet')) + '"')));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_name_constraints', 'nameConstraints',
                      t.text('consolePki.nameConstraintsTip')) +
      self.checkField(draft, 'pki_nc_critical', critical,
                      t.text('consolePki.mustBeCritical')),
      self.areaField(draft, 'pki_name_constraints',
                     t.text('consolePki.constraintsPerLine'),
                     t.text('consolePki.nameConstraintsSyntax',
                            { name: '<name>' }), 2,
                     'permit dns:example.com\npermit ip:10.0.0.0/8\nexclude ' +
                     'dns:bad.example.com')));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_inhibit_any', 'inhibitAnyPolicy',
                      t.text('consolePki.inhibitAnyTip')),
      self.textField(draft, 'pki_inhibit_any_skip', 'skipCerts',
                     t.text('consolePki.skipCertsTip'),
                     ' size="6" placeholder="0"')));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_pkup', 'privateKeyUsagePeriod',
                      t.text('consolePki.pkupTip')),
      self.textField(draft, 'pki_pkup_not_before', 'notBefore',
                     t.text('consolePki.pkupNotBeforeTip'),
                     ' size="18" placeholder="2026-01-01T00:00"') +
      self.textField(draft, 'pki_pkup_not_after', 'notAfter',
                     t.text('consolePki.pkupNotAfterTip'),
                     ' size="18" placeholder="2027-01-01T00:00"')));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_tls_feature', 'TLS Feature (RFC 7633)',
                      t.text('consolePki.tlsFeatureTip')),
      self.areaField(draft, 'pki_tls_feature',
                     t.text('consolePki.extensionNumbersPerLine'),
                     t.text('consolePki.tlsFeatureNumbersTip'), 1, '5')));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_ocsp_nocheck', 'id-pkix-ocsp-nocheck',
                      t.text('consolePki.ocspNocheckTip')), ''));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_ns_cert_type',
                      t.text('consolePki.nsCertType'),
                      t.text('consolePki.nsCertTypeTip')),
      '<div class="pki-flags">' +
      json.workbench.netscapeTypes.map(function (one) {
        return self.checkField(draft, 'pki_ns_' + one.name, one.name, '');
      }).join('') + '</div>'));

    cards.push(self.extCard(
      self.checkField(draft, 'pki_ext_ns_comment',
                      t.text('consolePki.nsComment'),
                      t.text('consolePki.nsCommentTip')),
      self.textField(draft, 'pki_ns_comment', t.text('consolePki.comment'),
                     t.text('consolePki.freeText'),
                     ' size="40" placeholder="Issued by IYA STS"')));

    cards.push(self.extCard(
      '<strong' + kit.tip(t.text('consolePki.anyOtherTip')) +
      '>' + t.html('consolePki.anyOther') + '</strong>',
      self.areaField(draft, 'pki_custom_extensions',
                     t.text('consolePki.onePerLine'),
                     t.text('consolePki.customSyntax',
                            { oid: '<oid>', critical: '<critical or ->',
                              der: '<base64 DER of the extension value>' }),
                     2, '1.3.6.1.4.1.99999.7.7|-|DANDYWJj')));

    return '<div class="pki-extlist">' + cards.join('') + '</div>';
  }

  // The Issue a Certificate column: what kind of certificate this is, who signs
  // it, how, with what serial and for how long.
  static certificateColumn(json: Json, draft: Json, t: Json) {
    const self = this;
    const wb = json.workbench;
    const profile = wb.profiles.filter(function (one) {
      return one.id === draft.pki_profile;
    })[0] || {};
    const mode = wb.pqModes.filter(function (one) {
      return one.id === wb.pqMode;
    })[0] || wb.pqModes[0];
    const issuerOptions = [{ value: '', label: wb.issuers.length
      ? t.text('consolePki.chooseOne') : t.text('consolePki.noCaYet') }]
      .concat(wb.issuers.map(function (one) {
        return { value: one.id, label: one.label };
      }));
    // A profile's, an issuer's and an approach's labels and the approach's
    // note are the view's, drawn as they come.
    const html =
      '<div class="pki-col">' +
      '<div class="pki-group">' + t.html('consolePki.issueCertificate') +
      '</div>' +
      kit.note(t.html('consolePki.profileNote'),
               t.html('consolePki.profileNoteTitle')) +
      '<div class="pki-row">' +
      self.selectField(draft, 'pki_profile', t.text('consolePki.profile'),
                       t.text('consolePki.profileTip'),
                       // **THE LABEL IS THE PROFILE'S OWN AND NOTHING IS
                       // APPENDED TO IT.** `root-ca` is already called "Root CA
                       // (self-signed)" in the encoder's table, so a page
                       // adding its own "(self-signed)" printed it twice —
                       // which is what happens every time a renderer restates a
                       // fact the table it is reading already carries.
                       wb.profiles.map(function (one) {
                         return { value: one.id, label: one.label };
                       })) +
      '<button type="submit" name="defaults" value="1" ' +
        'formaction="/admin/pki/certificate?action=apply-profile"' +
        kit.tip(t.text('consolePki.applyProfileTip')) +
        '>' + t.html('consolePki.applyProfile') + '</button>' +
      '</div>' +
      (profile.selfSigned
        ? kit.note(t.html('consolePki.selfSignedNote',
                          { label: profile.label }))
        : '') +
      '<div class="pki-row">' +
      self.selectField(draft, 'pki_issuer', t.text('consolePki.signedBy'),
                       t.text('consolePki.signedByTip'), issuerOptions) +
      '</div>' +
      '<div class="pki-row">' +
      self.selectField(draft, 'pki_pq_mode', t.text('consolePki.approach'),
                       t.text('consolePki.approachTip'),
                       wb.pqModes.map(function (one) {
                         return { value: one.id, label: one.label };
                       })) +
      '<button type="submit" name="defaults" value="1" ' +
        'formaction="/admin/pki/certificate?action=apply-profile"' +
        kit.tip(t.text('consolePki.applyApproachTip')) + '>' +
        t.html('consolePki.apply') + '</button>' +
      '</div>' +
      kit.note(esc(mode.note), mode.label) +
      '<div class="pki-row">' +
      self.selectField(draft, 'pki_sig_alg', t.text('consolePki.sigAlg'),
                       (wb.signerLabel
                         ? t.text('consolePki.sigAlgTipSigner',
                                  { signer: wb.signerLabel })
                         : t.text('consolePki.sigAlgTip')),
                       [{ value: '',
                       label: t.text('consolePki.sigRightOneSigning') }]
                    .concat(wb.signatureAlgorithms.map(function (one) {
                      return { value: one.id,
                               label: one.label + (one.weak
                                 ? t.text('consolePki.weakOnPurpose') : '') };
                    }))) +
      '</div>' +
      '<div class="pki-row">' +
      self.textField(draft, 'pki_serial', t.text('consolePki.serialHex'),
                     t.text('consolePki.serialTip'), ' size="36"') +
      self.textField(draft, 'pki_validity_years',
                     t.text('consolePki.validityYears'),
                     t.text('consolePki.validityYearsTip'), ' size="5"') +
      '</div>' +
      '<div class="pki-row">' +
      self.textField(draft, 'pki_not_before', t.text('consolePki.notBefore'),
                     t.text('consolePki.notBeforeTip'),
                     ' size="20" placeholder="2026-01-01T00:00"') +
      self.textField(draft, 'pki_not_after', t.text('consolePki.notAfter'),
                     t.text('consolePki.notAfterTip'),
                     ' size="20" placeholder="' +
                     esc(t.text('consolePki.notAfterPlaceholder')) + '"') +
      '</div>' +
      '</div>';
    return html;
  }

  // The Key Pair column: the pair this certificate certifies, the certification
  // request nothing here consumes, the hybrid half, and the export.
  static keyPairColumn(json: Json, draft: Json, t: Json) {
    const self = this;
    const wb = json.workbench;
    const algOptions = wb.keyAlgorithms.map(function (one) {
      return { value: one.id, group: one.family,
               label: one.label +
                      (one.slow ? t.text('consolePki.slowToGenerate') : '') +
                      (one.signs ? '' : t.text('consolePki.cannotSign')) };
    });
    const slow = wb.keyAlgorithms.filter(function (one) { return one.slow; });
    const html =
      '<div class="pki-col">' +
      '<div class="pki-group">' + t.html('consolePki.keyPair') + '</div>' +
      kit.note(t.html('consolePki.keyPairNote'),
               t.html('consolePki.keyPairNoteTitle')) +
      (slow.length
        ? kit.warn(
          t.html('consolePki.slowWarn',
                 { families: slow.map(function (one) { return one.family; })
                   .filter(function (v, i, a) { return a.indexOf(v) === i; })
                   .join(', ') }),
          t.html('consolePki.slowWarnTitle'))
        : '') +
      '<div class="pki-row">' +
      self.selectField(draft, 'pki_key_alg', t.text('consolePki.keyAlg'),
                       t.text('consolePki.keyAlgTip'),
                       algOptions) +
      self.checkField(draft, 'pki_key_jwk', t.text('consolePki.showJwk'),
                      t.text('consolePki.showJwkTip')) +
      '<button type="submit" name="generate" value="1" ' +
        'formaction="/admin/pki/certificate?action=generate-keys"' +
        kit.tip(t.text('consolePki.generateTip')) + '>' +
        t.html('consolePki.generate') + '</button>' +
      '</div>' +
      '<div class="pki-row">' +
      self.checkField(draft, 'pki_reuse_key', t.text('consolePki.reuseKey'),
                      t.text('consolePki.reuseKeyTip')) +
      self.checkField(draft, 'pki_save_keys',
                      t.text('consolePki.saveKeys'),
                      t.text('consolePki.saveKeysTip')) +
      '</div>' +
      self.areaField(draft, 'pki_private_key', t.text('consolePki.privateKey'),
                     t.text('consolePki.privateKeyTip'), 4) +
      self.areaField(draft, 'pki_public_key', t.text('consolePki.publicKey'),
                     t.text('consolePki.publicKeyTip'), 3) +
      '<div class="pki-row">' +
      self.checkField(draft, 'pki_gen_csr', t.text('consolePki.genCsr'),
                      t.text('consolePki.genCsrTip')) +
      '</div>' +
      self.areaField(draft, 'pki_csr', 'CSR (PKCS#10)',
                     t.text('consolePki.csrTip'), 3) +
      // The hybrid half. It is drawn ALWAYS rather than revealed, because
      // revealing it needs a script — and a pane that hid it would leave the
      // alternative key pair unreachable on the one console setting that uses
      // it. The heading says when it applies instead.
      '<div class="pki-group">' + t.html('consolePki.altPair') +
        (wb.pqMode === 'hybrid' ? '' : t.html('consolePki.notInUse')) +
        '</div>' +
      kit.note(t.html('consolePki.altPairNote'),
               t.html('consolePki.altPairNoteTitle')) +
      '<div class="pki-row">' +
      self.selectField(draft, 'pki_alt_key_alg', t.text('consolePki.altAlg'),
                       t.text('consolePki.altAlgTip'),
                       wb.alternativeKeyAlgorithms.map(function (one) {
                         return { value: one.id, group: one.family,
                                  label: one.label +
                                         (one.slow
                                           ? t.text(
                                             'consolePki.slowToGenerate')
                                           : '') };
                       })) +
      self.checkField(draft, 'pki_alt_reuse_key',
                      t.text('consolePki.altReuse'),
                      t.text('consolePki.altReuseTip')) +
      '<button type="submit" name="generatealt" value="1" ' +
        'formaction="/admin/pki/certificate?action=generate-alt-keys"' +
        kit.tip(t.text('consolePki.generateAltTip')) + '>' +
        t.html('consolePki.generateAlt') + '</button>' +
      '</div>' +
      self.areaField(draft, 'pki_alt_private_key',
                     t.text('consolePki.altPrivateKey'),
                     t.text('consolePki.altPrivateKeyTip'), 3) +
      self.areaField(draft, 'pki_alt_public_key',
                     t.text('consolePki.altPublicKey'),
                     t.text('consolePki.altPublicKeyTip'), 2) +
      '<div class="pki-group">' + t.html('consolePki.export') + '</div>' +
      kit.note(t.html('consolePki.exportNote'),
               t.html('consolePki.exportNoteTitle')) +
      '<div class="pki-row">' +
      self.selectField(draft, 'pki_ks_format', t.text('consolePki.ksFormat'),
                       t.text('consolePki.ksFormatTip'),
                       wb.keystoreFormats.map(function (one) {
                         return { value: one, label: one.toUpperCase() };
                       })) +
      '<label' + kit.tip(t.text('consolePki.ksPasswordTip')) + '>' +
        t.html('consolePki.password') + ' <input type="password" ' +
        'name="pki_ks_password" value="" ' +
        'autocomplete="new-password"></label> ' +
      self.checkField(draft, 'pki_ks_include_chain',
                      t.text('consolePki.includeChain'),
                      t.text('consolePki.includeChainTip')) +
      '<button type="submit" name="export" value="1" ' +
        'formaction="/admin/pki/certificate?action=export"' +
        kit.tip(t.text('consolePki.downloadTip')) + '>' +
        t.html('consolePki.download') + '</button>' +
      '</div>' +
      '</div>';
    return html;
  }

  // The Subject Distinguished Name column.
  static subjectColumn(json: Json, draft: Json, t: Json) {
    const self = this;
    const titles = {
      pki_dn_cn: t.text('consolePki.dnCnTip'),
      pki_dn_o: t.text('consolePki.dnOTip'),
      pki_dn_ou: t.text('consolePki.dnOuTip'),
      pki_dn_l: t.text('consolePki.dnLTip'),
      pki_dn_st: t.text('consolePki.dnStTip'),
      pki_dn_c: t.text('consolePki.dnCTip'),
      pki_dn_email: t.text('consolePki.dnEmailTip'),
      pki_dn_dc: t.text('consolePki.dnDcTip'),
      pki_dn_uid: t.text('consolePki.dnUidTip'),
      pki_dn_serialnumber: t.text('consolePki.dnSerialTip')
    };
    const labels = {
      pki_dn_cn: t.text('consolePki.dnCn'), pki_dn_o: t.text('consolePki.dnO'),
      pki_dn_ou: t.text('consolePki.dnOu'), pki_dn_l: t.text('consolePki.dnL'),
      pki_dn_st: t.text('consolePki.dnSt'), pki_dn_c: t.text('consolePki.dnC'),
      pki_dn_email: 'emailAddress', pki_dn_dc: t.text('consolePki.dnDc'),
      pki_dn_uid: 'UID', pki_dn_serialnumber: t.text('consolePki.dnSerial')
    };
    const boxes = json.workbench.dnFields.map(function (one) {
      return self.textField(draft, one.field, labels[one.field] || one.attr,
                            titles[one.field] || '',
                            one.field === 'pki_dn_c' ? ' size="4" maxlength="2"'
                                                     : ' size="28"');
    }).join('');
    const html =
      '<div class="pki-col">' +
      '<div class="pki-group">' + t.html('consolePki.subjectDn') + '</div>' +
      kit.note(t.html('consolePki.dnOrderNote'),
               t.html('consolePki.dnOrderNoteTitle')) +
      '<div class="pki-row">' + boxes + '</div>' +
      self.areaField(draft, 'pki_dn_extra',
                     t.text('consolePki.dnExtra'),
                     t.text('consolePki.dnExtraTip'), 3,
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
  static storeTable(json: Json, draft: Json, t: Json) {
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
        kit.note(t.html('consolePki.storeEmpty'),
                 t.html('consolePki.storeEmptyTitle'));
    }
    // An object's subject, profile label and algorithms are the view's.
    const rows = wb.objects.slice().reverse().map(function (one) {
      return '<tr>' +
        '<td><label class="pki-flag"><input type="radio" name="pki_selected" ' +
          'value="' + esc(one.id) + '"' +
          (draft.pki_selected === one.id ? ' checked' : '') + '> ' +
          (one.ca ? '<strong>CA</strong>' : t.html('consolePki.leaf')) +
          '</label></td>' +
        '<td><code>' + esc(one.subject) + '</code>' +
          (one.selfSigned ? '<br><em>' + t.html('consolePki.selfSigned') +
                            '</em>'
                          : '<br><small>' +
                            t.html('consolePki.issuedBy',
                                   { issuer: one.issuerSubject }) +
                            '</small>') +
          '</td>' +
        '<td>' + esc(one.profileLabel) + '</td>' +
        '<td><code>' + esc(one.serialHex.slice(0, 16)) +
        '&hellip;</code></td><td>' + esc(String(one.notAfter).slice(0, 10)) +
          (one.expired ? ' <strong>' + t.html('consolePki.expired') +
                         '</strong>' : '') + '</td>' +
        '<td><code>' + esc(one.keyAlg) + '</code> / <code>' +
          esc(one.signatureAlg) + '</code>' +
          PqcBadgeView.badge(one.pqc, t) +
          (one.altKeyAlg
            ? '<br><small>' +
              t.html('consolePki.altNote', { alg: one.altKeyAlg }) +
              (one.altSigned ? t.html('consolePki.altSignedShort')
                             : t.html('consolePki.altKeyOnly')) + '</small>'
            : '') + '</td>' +
        '<td>' + (one.hasPrivateKey ? t.html('consolePki.yes')
          : '<em>' + t.html('consolePki.noCannotSign') + '</em>') + '</td>' +
        '<td>' +
          (one.hasPrivateKey
            ? '<button type="submit" name="use" value="' + esc(one.id) +
              '" formaction="' + esc('/admin/pki/certificate?action=use-key&objectId=' +
                                     encodeURIComponent(one.id)) + '"' +
              kit.tip(t.text('consolePki.useKeyTip')) +
              '>' + t.html('consolePki.useKey') + '</button> '
            : '') +
          '<button type="submit" name="remove" value="' + esc(one.id) +
          '" formaction="' + esc('/admin/pki/certificate?action=remove-object&objectId=' +
                                 encodeURIComponent(one.id)) + '"' +
          kit.tip(t.text('consolePki.removeObjectTip')) + '>' +
          t.html('consolePki.remove') + '</button>' +
        '</td></tr>' +
        '<tr><td colspan="8">' +
          CertificateDialogView.link('/admin/pki', one.thumbprint,
                                     'workbench', undefined, t) +
          '<details><summary>' + t.html('consolePki.certificatePemShort') +
          (one.hasCsr ? t.html('consolePki.andCsr') : '') + '</summary><pre>' +
          esc(one.certificatePem) + (one.csrPem ? '\n' + esc(one.csrPem) : '') +
          '</pre></details></td></tr>';
    }).join('');
    return '<table><thead><tr><th>' + t.html('consolePki.thSelect') +
      '</th><th>' + t.html('consolePki.thSubject') + '</th><th>' +
      t.html('consolePki.profile') + '</th>' +
      '<th>' + t.html('consolePki.thSerial') + '</th><th>' +
      t.html('consolePki.thExpires') + '</th><th>' +
      t.html('consolePki.thKeySignature') + '</th>' +
      '<th>' + t.html('consolePki.thPrivateKey') +
      '</th><th></th></tr></thead><tbody>' + rows + '</tbody>' +
      '</table>' +
      '<div class="pki-row"><button type="submit" name="clearstore" ' +
      'value="1" formaction="/admin/pki/certificate?action=clear-store"' +
      kit.tip(t.text('consolePki.clearStoreTip')) +
      '>' + t.html('consolePki.clearStore') + '</button></div>';
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
  static certificatePane(json: Json, draft: Json, t: Json) {
    const self = this;
    const wb = json.workbench;
    const html =
      '<h3 id="workbench">' + t.html('consolePki.paneHeading') + '</h3>' +
      kit.note(t.html('consolePki.paneIntro') + '<p>' +
               t.html('consolePki.paneWhere') + '</p><p>' +
               t.html('consolePki.paneAsserting') + '</p>',
               t.html('consolePki.paneIntroTitle')) +
      // EVERY BUTTON BUT ISSUE NAMES ITS ACTION IN ITS `formaction` (#446):
      // the server read the pressed button's NAME first (`paneActionFrom()`),
      // and the static console sends the form to the operation its action
      // names, the query of a `formaction` taking the place of the hidden
      // `issue-certificate` — so Generate cannot be sent as an issue.
      '<form method="post" action="/admin/pki/certificate">' +
      '<input type="hidden" name="action" value="issue-certificate">' +
      '<div class="pki-cols">' +
      self.certificateColumn(json, draft, t) +
      self.keyPairColumn(json, draft, t) +
      self.subjectColumn(json, draft, t) +
      '</div>' +
      '<div class="pki-group">' + t.html('consolePki.extensionsGroup') +
      '</div>' +
      kit.note(t.html('consolePki.extensionsNote'),
               t.html('consolePki.extensionsNoteTitle')) +
      self.extensionCards(json, draft, t) +
      '<div class="pki-row">' +
      '<button type="submit"' +
      kit.tip(t.text('consolePki.issueTip')) +
      '>' + t.html('consolePki.issue') + '</button>' +
      '</div>' +
      '<h3>' + t.html('consolePki.keysAndCertificates') + '</h3>' +
      kit.note(t.html('consolePki.storeNote', { n: String(wb.maxObjects) }),
               t.html('consolePki.storeNoteTitle')) +
      self.storeTable(json, draft, t) +
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
  static tierRow(tier: Json, depth: Json, t: Json, extra?: Json) {
    const self = this;
    if (!tier) {
      return '';
    }
    return '<tr>' +
      '<td style="padding-left:' + (depth * 1.4) + 'rem">' +
      (depth ? '<span class="pki-branch">&#9492;&#9472;</span> ' : '') +
      '<strong>' + esc(tier.label) + '</strong>' +
      (tier.imported ? ' <em>' + t.html('consolePki.imported') + '</em>'
                     : '') +
      (extra || '') + '</td>' +
      '<td><code>' + esc(tier.subject) + '</code></td>' +
      '<td>' + esc(String(tier.notAfter).slice(0, 10)) +
        (tier.expired ? ' <strong>' + t.html('consolePki.expired') +
                        '</strong>' : '') + '</td>' +
      '<td><code>' + esc(tier.keyAlg) + '</code> / <code>' +
        esc(tier.signatureAlg) + '</code>' +
        PqcBadgeView.badge(tier.pqc, t) +
        self.alternativeNote(tier, t) + '</td>' +
      '<td><code>' + esc(String(tier.thumbprint).slice(0, 16)) +
      '&hellip;</code><br>' +
      CertificateDialogView.link('/admin/pki', tier.thumbprint, 'pki-tree',
                                 undefined, t) +
      '</td></tr>';
  }

  static treeSection(json: Json, t: Json) {
    const self = this;
    const tree = json.tree;
    if (!tree || !tree.rootBuilt) {
      return kit.warn(t.html('consolePki.noRoot'),
                      t.html('consolePki.noRootTitle'));
    }
    let rows = self.tierRow(tree.root, 0, t);
    // A scope's label, an authority's id and what it is for, and what it
    // certified are the view's.
    tree.scopes.forEach(function (scope) {
      if (!scope.built) {
        rows += '<tr><td style="padding-left:1.4rem">' +
          '<span class="pki-branch">&#9492;&#9472;</span> <em>' +
          t.html('consolePki.scopeNotBuilt', { label: scope.label }) +
          '</em></td>' +
          '<td colspan="4"><em>' + t.html('consolePki.noIntermediate') +
          '</em></td></tr>';
        return;
      }
      rows += self.tierRow(scope.intermediate, 1, t,
                           ' <span class="pki-scope">' +
                           esc(scope.kind === 'process'
                             ? t.text('consolePki.scopeProcess')
                             : t.text('consolePki.scopeRealm',
                                      { label: scope.label })) +
                           '</span>');
      scope.issuing.forEach(function (one) {
        if (!one.built) {
          return;
        }
        rows += self.tierRow(one.ca, 2, t,
                             ' <span class="pki-scope">' + esc(one.id) +
                             '</span>');
        // What it has certified. Indented under its own authority, because the
        // question a reader brings to a tree of CAs is which of them is
        // actually doing anything.
        one.certified.forEach(function (cert) {
          rows += '<tr><td style="padding-left:4.2rem"><span ' +
            'class="pki-branch">&#9492;&#9472;</span> ' + esc(cert.label) +
            (cert.pinned ? ' <em>' + t.html('consolePki.yourKey') + '</em>'
                         : '') + '</td>' +
            '<td><code>' + esc(cert.subject) + '</code></td>' +
            '<td>' + esc(String(cert.notAfter).slice(0, 10)) +
              (cert.expired ? ' <strong>' + t.html('consolePki.expired') +
                              '</strong>' : '') + '</td>' +
            '<td><code>' + esc(cert.alg || cert.keyAlg || '') + '</code>' +
              PqcBadgeView.badge(cert.pqc, t) +
              '</td>' +
            '<td><code>' + esc(String(cert.thumbprint).slice(0, 16)) +
              '&hellip;</code><br>' +
              CertificateDialogView.link('/admin/pki', cert.thumbprint,
                                     'pki-tree', undefined, t) +
              '</td></tr>';
        });
        if (!one.certified.length) {
          rows += '<tr><td style="padding-left:4.2rem"><em>' +
            t.html('consolePki.nothingCertified') +
            '</em></td><td colspan="4"><em>' + esc(one.what) +
            '</em></td></tr>';
        }
      });
    });
    return '<table><thead><tr><th>' + t.html('consolePki.thAuthority') +
      '</th><th>' + t.html('consolePki.thSubject') + '</th>' +
      '<th>' + t.html('consolePki.thExpires') + '</th><th>' +
      t.html('consolePki.thKeySignature') + '</th><th>SHA-256</th></tr>' +
      '</thead>' +
      '<tbody>' + rows + '</tbody></table>';
  }

  static pinnedSection(json: Json, t: Json) {
    const model = json.pinnedSigners || { on: false, keys: [] };
    const warnings = model.keys.filter(function (one: Json) {
      return one.expiringSoon;
    }).map(function (one: Json) {
      return kit.warn(
        (one.expired
          ? t.html('consolePki.pinExpired',
                   { unit: one.unit, kid: one.kid, when: one.notAfter })
          : t.html('consolePki.pinExpiring',
                   { unit: one.unit, kid: one.kid,
                     when: String(one.notAfter).slice(0, 10),
                     n: one.daysLeft })) +
        t.html('consolePki.pinNeverRotated'),
        t.html('consolePki.pinWarnTitle'));
    }).join('');
    const rows = model.keys.map(function (one: Json) {
      return '<tr><td><code>' + esc(one.unit) + '</code></td>' +
        '<td><code>' + esc(one.kid) + '</code></td>' +
        '<td>' + esc(one.role === 'active' ? t.text('consolePki.pinSigning')
                      : one.role === 'pending'
                        ? t.text('consolePki.pinPublished',
                                 { when: one.activatesAt })
                        : t.text('consolePki.pinUnpinned',
                                 { when: one.retiredUntil })) +
        '</td>' +
        '<td>' + esc(String(one.notAfter).slice(0, 10)) +
          (one.expired ? ' <strong>' + t.html('consolePki.expired') +
                         '</strong>' : '') + '</td>' +
        '<td>' + (one.operatorCertificate ? t.html('consolePki.yours')
          : t.html('consolePki.realmIssuingCa', { useCase: one.useCase })) +
        '</td>' +
        '<td>' + (one.role === 'retired' ? '' :
          '<form method="post" action="/admin/pki">' +
          '<input type="hidden" name="action" value="unpin-key">' +
          '<input type="hidden" name="useCase" value="' + esc(one.useCase) +
          '"><input type="hidden" name="slot" value="' + esc(one.slot) +
          '"><button type="submit"' + kit.tip(t.text('consolePki.unpinTip')) +
          '>' + t.html('consolePki.unpin') + '</button></form>') +
        '</td></tr>';
    }).join('');
    return '<h3 id="pki-pinned">' + t.html('consolePki.pinnedHeading') +
      '</h3>' +
      kit.note(model.on
        ? t.html('consolePki.pinnedOn', { n: model.leadMinutes })
        : t.html('consolePki.pinnedOff')) +
      warnings +
      (rows ? '<table><thead><tr><th>' + t.html('consolePki.thUnit') +
              '</th><th>kid</th><th>' + t.html('consolePki.thState') +
              '</th>' +
              '<th>' + t.html('consolePki.thExpires') + '</th><th>' +
              t.html('consolePki.thCertificate') +
              '</th><th></th></tr></thead>' +
              '<tbody>' + rows + '</tbody></table>'
            : '<p><em>' + t.html('consolePki.nothingPinned') + '</em></p>');
  }

  static scopeControls(json: Json, scope: Json, t: Json) {
    const self = this;
    const label = scope.kind === 'process' ? 'the process'
                                           : 'the ' + scope.label + ' realm';
    let html = '<h4>' + esc(scope.kind === 'process'
                              ? t.text('consolePki.processHeading')
                              : t.text('consolePki.realmHeading',
                                       { label: scope.label })) +
      '</h4>';
    html +=
      '<form method="post" action="/admin/pki">' +
      '<input type="hidden" name="action" value="build-scope">' +
      '<input type="hidden" name="scope" value="' + esc(scope.scope) + '">' +
      '<label' + kit.tip(t.text('consolePki.branchKeyAlgTip')) + '>' +
      t.html('consolePki.keyAlgorithm') + ' <select name="keyAlg">' +
      self.algorithmOptions(json, scope.keyAlg ||
                            json.pageDefaults.keyAlgorithm) +
                            '</select></label> ' +
      self.alternativeField(json, scope.altKeyAlg, t) +
      '<button type="submit"' +
      kit.tip(t.text('consolePki.buildBranchTip')) +
      '>' + (scope.built ? t.html('consolePki.rebuildBranch')
                         : t.html('consolePki.buildBranch')) +
      '</button>' +
      '</form>';
    if (!scope.built) {
      return html;
    }
    // A use case's label and what it is for are the view's.
    html += '<table><thead><tr><th>' + t.html('consolePki.thUseCase') +
      '</th><th>' + t.html('consolePki.thIssuingCa') + '</th><th>' +
      t.html('consolePki.thCertified') + '</th><th>' +
      t.html('consolePki.thReissue') + '</th><th>' +
      t.html('consolePki.thOwnCa') + '</th></tr></thead><tbody>';
    scope.issuing.forEach(function (one) {
      html += '<tr>' +
        '<td><strong>' + esc(one.label) + '</strong>' +
          kit.note(esc(one.what)) + '</td>' +
        '<td>' + (one.ca
          ? '<code>' + esc(one.ca.subject) + '</code>' +
            (one.ca.imported ? '<br><em>' +
                               t.html('consolePki.importedYours') + '</em>'
                             : '')
          : '<em>' + t.html('consolePki.notBuilt') + '</em>') + '</td>' +
        '<td>' + one.certified.length + '</td>' +
        '<td>' +
          '<form method="post" action="/admin/pki"><input type="hidden" ' +
          'name="action" value="reissue-use-case"><input type="hidden" ' +
          'name="scope" value="' + esc(scope.scope) + '">' +
          '<input type="hidden" name="useCase" value="' + esc(one.id) + '">' +
          '<button type="submit"' +
          kit.tip(t.text('consolePki.reissueTip')) +
          '>' + t.html('consolePki.reissue') + '</button></form>' +
          (one.certified.length
            ? '<form method="post" action="/admin/pki">' +
              '<input type="hidden" name="action" value="recertify">' +
              '<input type="hidden" name="scope" value="' + esc(scope.scope) +
              '"><input ' +
              'type="hidden" name="useCase" value="' + esc(one.id) + '">' +
              '<button type="submit"' +
              kit.tip(t.text('consolePki.renewTip')) +
              '>' + t.html('consolePki.renew') + '</button></form>'
            : '') +
        '</td>' +
        '<td>' +
          (one.certified.length
            ? '<details><summary>' + t.html('consolePki.useOwnPair') +
              '</summary>' +
              kit.note(t.html('consolePki.useOwnPairNote')) +
              '<form method="post" action="/admin/pki">' +
              '<input type="hidden" name="action" value="pin-key">' +
              '<input type="hidden" name="scope" value="' + esc(scope.scope) +
              '"><input ' +
              'type="hidden" name="useCase" value="' + esc(one.id) + '">' +
              '<label>' + t.html('consolePki.slot') +
              ' <select name="slot">' +
              one.certified.map(function (cert) {
                return '<option value="' + esc(cert.slot) + '">' +
                  esc(cert.slot) + '</option>';
              }).join('') + '</select></label><div ' +
              'class="pki-field"><label>' +
              t.html('consolePki.privateKeyPem') + '<textarea ' +
              'name="privateKeyPem" rows="3"></textarea></label></div><div ' +
              'class="pki-field"><label>' +
              t.html('consolePki.certificatePemOptional') + '<textarea ' +
              'name="certificatePem" ' +
              'rows="2"></textarea></label></div><div ' +
              'class="pki-field"><label>' + t.html('consolePki.chainPem') +
              '<textarea name="chainPem" ' +
              'rows="2"></textarea></label></div><button type="submit">' +
              t.html('consolePki.useKey') + '</button></form></details>'
            : '') +
          '<details><summary>' + t.html('consolePki.importCa') +
          '</summary><form method="post" ' +
          'action="/admin/pki"><input type="hidden" name="action" ' +
          'value="import-ca"><input type="hidden" name="scope" value="' +
          esc(scope.scope) + '">' +
          '<input type="hidden" name="useCase" value="' + esc(one.id) + '">' +
          '<div class="pki-field"><label>' +
          t.html('consolePki.certificatePemLabel') +
          '<textarea name="certificatePem" rows="3"></textarea></label></div>' +
          '<div class="pki-field"><label>' +
          t.html('consolePki.privateKeyPem') +
          '<textarea name="privateKeyPem" rows="3"></textarea></label></div>' +
          '<button type="submit">' + t.html('consolePki.useAsIssuing') +
          '</button>' +
          '</form></details>' +
        '</td></tr>';
    });
    html += '</tbody></table>';
    return html;
  }

  // The Root's own controls. Separate from a scope's because replacing it is a
  // different act with a different consequence: every branch in the process
  // hangs from it.
  static rootControls(json: Json, t: Json) {
    const self = this;
    const tree = json.tree;
    return '<h4>' + t.html('consolePki.rootHeading') + '</h4>' +
      kit.warn(t.html('consolePki.rootWarn'),
               t.html('consolePki.rootWarnTitle')) +
      '<form method="post" action="/admin/pki">' +
      '<input type="hidden" name="action" value="build-root">' +
      '<label>' + t.html('consolePki.keyAlgorithm') +
      ' <select name="keyAlg">' +
      self.algorithmOptions(json, (tree.root && tree.root.keyAlg) ||
                            json.pageDefaults.keyAlgorithm) +
                            '</select></label> ' +
      self.alternativeField(json, tree.root &&
                            (tree.root.altKeyAlg ||
                             (tree.rootBuilt ? 'none' : '')), t) +
      '<label>' + t.html('consolePki.commonName') +
      ' <input name="commonName" placeholder="' +
      esc(t.text('consolePki.rootCnPlaceholder',
                 { org: json.pageDefaults.organisation })) + '"></label> ' +
      '<label>' + t.html('consolePki.years') +
      ' <input name="years" size="4" placeholder="20"></label> ' +
      '<button type="submit">' + (tree.rootBuilt
        ? t.html('consolePki.replaceRoot') : t.html('consolePki.buildRoot')) +
      '</button></form>' +
      '<details><summary>' + t.html('consolePki.importRoot') + '</summary>' +
      kit.note(t.html('consolePki.importRootNote')) +
      '<form method="post" action="/admin/pki">' +
      '<input type="hidden" name="action" value="import-ca">' +
      '<input type="hidden" name="scope" value="' + esc(json.serviceScope) +
      '"><input ' +
      'type="hidden" name="useCase" value="root"><div ' +
      'class="pki-field"><label>' + t.html('consolePki.certificatePemLabel') +
      '<textarea ' +
      'name="certificatePem" rows="3"></textarea></label></div><div ' +
      'class="pki-field"><label>' + t.html('consolePki.privateKeyPem') +
      '<textarea ' +
      'name="privateKeyPem" rows="3"></textarea></label></div><button ' +
      'type="submit">' + t.html('consolePki.useAsRoot') +
      '</button></form></details>';
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
  static coverageNote(json: Json, t: Json) {
    // The SPIFFE page's link is markup a message cannot carry, so the last
    // paragraph is cut at it.
    return kit.note(
      t.html('consolePki.coverageEvery') + '<p>' +
      t.html('consolePki.coverageOutside') + '</p><p>' +
      t.html('consolePki.coverageSpiffe') +
      ' <a href="/admin/spiffe">' + t.html('consolePki.spiffePage') + '</a> ' +
      t.html('consolePki.coverageSpiffeAfter') + '</p>',
      t.html('consolePki.coverageTitle'));
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
                               reasons: Json[], t: Json) {
    const self = this;
    if (!authority.issuedTotal) {
      return '<tr><td colspan="4"><em>' +
             t.html('consolePki.issuedNothing') + '</em></td></tr>';
    }
    if (!authority.issued.length) {
      return '<tr><td colspan="4"><em>' +
             t.html('consolePki.issuedNoMatch') + '</em></td></tr>';
    }
    // A revocation reason, a subject and a kind are the view's.
    return authority.issued.map(function (cert) {
      const state = cert.revoked
        ? '<span class="bad">' + t.html('consolePki.revoked') + '</span> ' +
          esc(String(cert.revokedReason)) +
          '<br><span class="muted">' + esc(String(cert.revokedAt)) + '</span>'
        : (cert.expired ? '<span class="muted">' +
                          t.html('consolePki.expiredWord') + '</span>'
                        : '<span class="ok">' + t.html('consolePki.good') +
                          '</span>');
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
              kit.tip(t.text('consolePki.releaseHoldTip')) +
              '>' + t.html('consolePki.releaseHold') + '</button></form>'
            : '<span class="muted">' + t.html('consolePki.permanent') +
              '</span>')
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
          '<input type="text" name="note" placeholder="' +
            esc(t.text('consolePki.noteOptional')) + '" ' +
            'maxlength="200">' +
          '<button type="submit"' +
          kit.tip(t.text('consolePki.revokeTip', { label: authority.label })) +
          '>' + t.html('consolePki.revoke') + '</button></form>';
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
                         reasons: Json[], t: Json) {
    const self = this;
    // THIS AUTHORITY'S TWO PAGERS (#370), and every link carries every
    // list's state; so does every Revoke and Release form, as `back` with
    // the list it was pressed in, so the reader lands on the page they were
    // reading rather than on page 1 of everything.
    const issuedNav = kit.pageNavPair('/admin/pki', listView,
                                        authority.issuedPaging, t);
    const orphansNav = kit.pageNavPair('/admin/pki', listView,
                                         authority.orphansPaging, t);
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
      }, t);
    };
    const orphans = authority.revokedNotIssuedTotal
      ? kit.note(
          '<p>' + t.html('consolePki.orphansNote',
                         { n: authority.revokedNotIssuedTotal }) + '</p>' +
          search('orphans', t.text('consolePki.searchOrphans'),
                 t.text('consolePki.searchOrphansPlaceholder')) +
          (!authority.revokedNotIssued.length
            ? '<p><em>' + t.html('consolePki.orphansNoMatch') + '</em></p>'
            : orphansNav.head + '<table ' +
          'class="grid"><thead><tr><th>' + t.html('consolePki.thSerial') +
          '</th><th>' + t.html('consolePki.thRevoked') + '</th>' +
          '<th>' + t.html('consolePki.thReason') + '</th><th>' +
          t.html('consolePki.thSubjectRecorded') +
          '</th></tr></thead><tbody>' +
          authority.revokedNotIssued.map(function (entry) {
            return '<tr><td><code>' + esc(entry.serialHex) + '</code></td>' +
                   '<td>' + esc(String(entry.revokedAt)) + '</td>' +
                   '<td>' + esc(entry.reason) + ' (' + entry.reasonCode + ')' +
                   (entry.note ? '<br><span class="muted">' + esc(entry.note) +
                                 '</span>' : '') + '</td>' +
                   '<td>' + esc(entry.subject || '—') + '</td></tr>';
          }).join('') + '</tbody></table>' + orphansNav.foot),
          t.html('consolePki.orphansTitle',
                 { n: authority.revokedNotIssuedTotal }))
      : '';

    // An authority's label and subject and its three addresses are the
    // view's; the addresses and counts go into the sentence as parameters.
    return '<h4>' + esc(authority.label) + '</h4>' +
      '<p><code>' + esc(authority.subject) + '</code></p>' +
      '<p class="muted">' +
      t.html('consolePki.authorityCounts',
             { issued: authority.issuedTotal,
               revoked: authority.revokedTotal,
               http: authority.crl.http, ldap: authority.crl.ldap,
               ocsp: authority.ocsp }) + '</p>' +
      (authority.issuedTotal
        ? search('issued', t.text('consolePki.searchIssued'),
                 t.text('consolePki.searchIssuedPlaceholder'))
        : '') +
      issuedNav.head +
      '<table class="grid"><thead><tr><th>' + t.html('consolePki.thSerial') +
      '</th><th>' + t.html('consolePki.thSubject') + '</th>' +
      '<th>' + t.html('consolePki.thStatus') + '</th><th></th></tr></thead>' +
      '<tbody>' +
      self.issuedRevocationRows(authority, carry, reasons, t) +
      '</tbody></table>' + issuedNav.foot + orphans;
  }

  static revocationPane(json: Json, listView: Json, t: Json) {
    const self = this;
    const model = json.revocation;
    if (!model.authorities.length) {
      return '<h3>' + t.html('consolePki.revokingHeading') + '</h3>' +
        kit.note(t.html('consolePki.noAuthorityToRevoke',
                        { realm: json.realm }));
    }

    const what = kit.note(
      '<p>' + t.html('consolePki.revokeByIssuer') + '</p><p>' +
      t.html('consolePki.revokeNotTakeOff') + '</p><p>' +
      t.html('consolePki.revokePublishes') + '</p>',
      t.html('consolePki.revokeWhatTitle'));

    const rotation = kit.note(
      '<p>' + t.html('consolePki.rotationRevokes') + '</p><p>' +
      t.html('consolePki.crlOnDemand',
             { n: String(model.crlLifetimeMinutes) }) + ' ' +
      (model.publishedToDirectory
        ? t.html('consolePki.directoryCopyOn')
        : t.html('consolePki.directoryCopyOff')) + '</p>',
      t.html('consolePki.rotationTitle'));

    // A reason's description is the view's, drawn as it comes.
    const reasons = kit.note(
      '<p>' + t.html('consolePki.reasonsNote') + '</p><ul>' +
      model.reasons.map(function (one) {
        return '<li><code>' + esc(one.id) + '</code> (' + one.code +
               ') &mdash; ' +
               esc(one.what.replace(/\*\*/g, '')) + '</li>';
      }).join('') + '</ul>',
      t.html('consolePki.reasonsTitle'));

    return '<h3>' + t.html('consolePki.revokingHeading') + '</h3>' + what +
      rotation + reasons +
      model.authorities.map(function (authority) {
        return self.authorityBlock(authority, listView, model.reasons, t);
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
    const t = ctx.t;
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
                                              paged.applications.paging, t);
    const peopleNav = kit.pageNavPair('/admin/pki', listView,
                                        paged.people.paging, t);
    const carryBack = '<input type="hidden" name="back" value="' +
      esc(kit.queryWith(listView, {})) + '">';
    // Each table's search box (2026-09-30), over the list view so it carries
    // the other tables' pages and searches and nothing else.
    const applicationsSearch = kit.sectionSearchForm({
      path: '/admin/pki', query: listView, param: 'issuedq',
      pageParam: 'issuedPage',
      label: t.text('consolePki.searchApplications'),
      placeholder: t.text('consolePki.searchApplicationsPlaceholder')
    }, t);
    const peopleSearch = kit.sectionSearchForm({
      path: '/admin/pki', query: listView, param: 'personsq',
      pageParam: 'personsPage', label: t.text('consolePki.searchPeople'),
      placeholder: t.text('consolePki.searchPeoplePlaceholder')
    }, t);

    const tiles = '<div class="tiles">' +
      kit.tile(chain ? t.text('consolePki.yes') : t.text('consolePki.no'),
               t.text('consolePki.tileBuilt')) +
      kit.tile(chain ? String(chain.tiers.length) : '0',
               t.text('consolePki.tileTiers')) +
      kit.tile(chain ? String(chain.issuedCount) : '0',
                 t.text('consolePki.tileIssued')) +
      kit.tile(json.issued.filter(function (one) {
        return one.hasKeyPair;
      }).length,
                 t.text('consolePki.tileApplications')) +
      kit.tile(json.persons.filter(function (one) {
        return one.hasKeyPair || one.saml.hasKeyPair;
      }).length,
                 t.text('consolePki.tilePeople')) +
      kit.tile(json.realm, t.text('consolePki.tileRealm')) +
      '</div>';

    const what = kit.note(
      '<p>' + t.html('consolePki.whatCa') + '</p><p>' +
      t.html('consolePki.whatAllThree') + '</p><p>' +
      t.html('consolePki.whatPerRealm', { realm: json.realm }) + '</p><p>' +
      t.html('consolePki.whatEncoder') + '</p>',
      t.html('consolePki.whatTitle'));

    // **THIS BLOCK SAID *Nothing here is revoked, ever* UNTIL 2026-09-11**, and
    // it was true when it was written. What replaced it is narrower rather than
    // absent, because the interesting limit did not go away when the CRLs
    // arrived — it moved. It read *this service publishes revocation and
    // consults none* until 2026-09-12, when presented certificates began to be
    // checked (`common/revocation_status.js`); `json.revocationNote` is
    // `pki.report()`'s sentence and says what is consulted now.
    const limits = kit.warn(
      '<p>' + t.html('consolePki.publishedNotEnforced') + ' ' +
      esc(json.revocationNote) + '</p><p>' + esc(json.residency) + '</p>',
      t.html('consolePki.limitsTitle'));

    // A tier's label is the view's. The years placeholder's callback names
    // its tier `x`, so the translator `t` stays reachable inside it.
    const buildForm =
      '<h3>' + (chain ? t.html('consolePki.rebuildHierarchy')
                      : t.html('consolePki.buildHierarchy')) + '</h3>' +
      (chain ? kit.warn(t.html('consolePki.replacesWarn'),
                        t.html('consolePki.replacesWarnTitle')) : '') +
      '<form method="post" action="/admin/pki">' +
      '<input type="hidden" name="action" value="build">' +
      '<label>' + t.html('consolePki.keyAlgorithm') +
      ' <select name="keyAlg">' +
        self.algorithmOptions(json, keyAlg) + '</select></label> ' +
      '<label>' + t.html('consolePki.signatureAlgorithm') +
      ' <select name="signatureAlg">' +
        self.signatureOptions(json, keyAlg, t) + '</select></label> ' +
      self.alternativeField(json, '', t) +
      '<label>' + t.html('consolePki.organisation') +
      ' <input name="organisation" value="' +
        esc(json.pageDefaults.organisation) + '"></label> <label>' +
      t.html('consolePki.country') +
      ' <input name="country" size="4" ' +
      'maxlength="2"></label><p>' + json.tierLabels.map(function (tier) {
        return '<label>' + esc(tier.label) + ' CN <input name="cn_' +
          esc(tier.id) + '" placeholder="' +
          esc(t.text('consolePki.cnPlaceholder')) + '"></label> <label>' +
          t.html('consolePki.yearsLower') + ' <input ' +
          'name="years_' + esc(tier.id) +
          '" size="4" placeholder="' +
          esc(String((json.tiers.filter(function (x) {
            return x.id === tier.id;
          })[0] || {}).years || '')) + '"></label>';
      }).join(' ') + '</p>' +
      '<button type="submit">' + (chain ? t.html('consolePki.rebuildCa')
                                        : t.html('consolePki.buildCa')) +
      '</button>' +
      '</form>' +
      (chain
        ? '<form method="post" action="/admin/pki">' +
          '<input type="hidden" name="action" value="clear">' +
          '<button type="submit">' + t.html('consolePki.removeHierarchy') +
          '</button></form>'
        : '');

    const purposeOptions = json.purposes.map(function (one) {
      return '<option value="' + esc(one.id) + '">' + esc(one.label) +
             '</option>';
    }).join('');

    // `kit.tip()` is drawn here as it always was, a `title` attribute's text
    // standing in the page; its second argument is the tip's length and is
    // left as it was.
    const issueForm = chain
      ? '<h3>' + t.html('consolePki.issueToApplication') + '</h3>' +
        kit.tip(t.text('consolePki.issueWritesTip'),
          'What issuing writes, and where') +
        '<form method="post" action="/admin/pki">' +
        '<input type="hidden" name="action" value="issue">' +
        '<label>' + t.html('consolePki.application') +
        ' <input name="identifier" required></label> ' +
        '<label>' + t.html('consolePki.profile') +
        ' <select name="purpose">' + purposeOptions +
          '</select></label> ' +
        '<label>' + t.html('consolePki.subjectCn') +
        ' <input name="commonName" ' +
          'placeholder="' +
          esc(t.text('consolePki.applicationIdPlaceholder')) + '"></label> ' +
        '<label>' + t.html('consolePki.keyAlgorithm') +
        ' <select name="leafKeyAlg">' +
          '<option value="">' +
          t.html('consolePki.issuingCaAlg', { alg: chain.keyAlg }) +
          '</option>' + self.algorithmOptions(json, '') +
          '</select></label> ' +
        '<label>' + t.html('consolePki.days') +
        ' <input name="days" size="5" value="' +
          esc(String(json.pageDefaults.leafLifetimeDays)) + '"></label> ' +
        '<button type="submit">' + t.html('consolePki.generateAndIssue') +
        '</button>' +
        '</form>'
      : kit.warn(t.html('consolePki.nothingToIssue'),
                 t.html('consolePki.nothingToIssueTitle'));

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
      ? '<h3>' + t.html('consolePki.issueToPerson') + '</h3>' +
        kit.tip(t.text('consolePki.personKeyTip'),
          'What a person’s key pair is for') +
        kit.warn('<p>' + t.html('consolePki.personOnlyThemselves') +
          '</p><p>' + t.html('consolePki.personShownOnce') + '</p>',
          t.html('consolePki.personWarnTitle')) +
        '<form method="post" action="/admin/pki/person">' +
        '<input type="hidden" name="action" value="issue">' +
        '<input type="hidden" name="target" value="person">' +
        // BOTH PROFILES SINCE 2026-09-13, which is the select this form did not
        // have: the SAML bearer grant reads a person's RFC 7522 key pair now.
        '<label>' + t.html('consolePki.profile') +
        ' <select name="purpose">' +
          json.purposes.map(function (one) {
            return '<option value="' + esc(one.id) + '">' + esc(one.label) +
                   '</option>';
          }).join('') + '</select></label> ' +
        '<label>' + t.html('consolePki.person') +
        ' <input name="identifier" required ' +
          'placeholder="' + esc(t.text('consolePki.personPlaceholder')) +
          '"></label> ' +
        '<label>' + t.html('consolePki.declaredIssuer') +
        ' <input name="issuer" ' +
          'placeholder="' + esc(t.text('consolePki.theirUsername')) +
          '"></label> ' +
        '<label>' + t.html('consolePki.subjectCn') +
        ' <input name="commonName" ' +
          'placeholder="' + esc(t.text('consolePki.theirUsername')) +
          '"></label> ' +
        '<label>' + t.html('consolePki.keyAlgorithm') +
        ' <select name="leafKeyAlg">' +
          '<option value="">' +
          t.html('consolePki.issuingCaAlg', { alg: chain.keyAlg }) +
          '</option>' + self.algorithmOptions(json, '') +
          '</select></label> ' +
        '<label>' + t.html('consolePki.days') +
        ' <input name="days" size="5" value="' +
          esc(String(json.pageDefaults.leafLifetimeDays)) + '"></label> ' +
        '<button type="submit">' + t.html('consolePki.generateAndIssue') +
        '</button>' +
        '</form>'
      : '';

    const takeOff = t.html('consolePki.takeOff');
    const personRows = !json.personsStorable
      ? kit.warn(t.html('consolePki.noDirectory'),
                 t.html('consolePki.noDirectoryTitle'))
      : (json.persons.length
        // A ROW PER PROFILE A PERSON HOLDS OR DECLARES (2026-09-13), for the
        // applications table's reason: every fact on the row — the handle, the
        // expiry, the declared issuer and the Take-off button — is per profile.
        ? peopleSearch + (!paged.people.shown.length
          ? '<p><em>' + t.html('consolePki.nobodyMatches') + '</em></p>'
          : peopleNav.head +
          '<table><thead><tr><th>' + t.html('consolePki.person') +
          '</th><th>' + t.html('consolePki.profile') + '</th>' +
          '<th>' + t.html('consolePki.thKeyHandle') + '</th><th>' +
          t.html('consolePki.thSource') + '</th><th>' +
          t.html('consolePki.thExpires') + '</th>' +
          '<th>' + t.html('consolePki.thAssertsAs') +
          '</th><th></th></tr></thead><tbody>' +
          paged.people.shown.reduce(function (rows, one) {
            [{ id: 'jwt', label: 'RFC 7523 (JWT)', handleLabel: 'kid',
               fact: one, handle: one.kid },
             { id: 'saml', label: 'RFC 7522 (SAML 2.0)',
               handleLabel: t.html('consolePki.thumbprint'), fact: one.saml,
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
                  PqcBadgeView.badge(p.fact.pqc, t) + '</td>' +
                '<td>' + esc(p.fact.source || '—') + '</td>' +
                '<td>' + esc(p.fact.expiresAt ? p.fact.expiresAt.slice(0, 8)
                                              : '—') + '</td>' +
                '<td>' + p.fact.issuers.map(function (iss) {
                    return '<code>' + esc(iss) + '</code>';
                  }).join('<br>') +
                  (p.fact.declared ? '' : ' <small>' +
                                          t.html('consolePki.ownName') +
                                          '</small>') + '</td>' +
                '<td>' + (p.fact.hasKeyPair
                  ? '<form method="post" action="/admin/pki"><input ' +
                    'type="hidden" name="action" value="revoke"><input ' +
                    'type="hidden" name="target" value="person"><input ' +
                    'type="hidden" name="purpose" value="' + p.id + '">' +
                    '<input type="hidden" name="identifier" value="' +
                      esc(one.username) + '">' + carryBack +
                    '<button type="submit">' + takeOff + '</button>' +
                    '</form>'
                  : '') + '</td>' +
                '</tr>');
            });
            return rows;
          }, []).join('') + '</tbody></table>' + peopleNav.foot)
        : '<p>' + t.html('consolePki.nobodyHolds') + '</p>');

    // An application's profile label and handle label are the view's.
    const issuedRows = json.issued.length
      ? applicationsSearch + (!paged.applications.shown.length
        ? '<p><em>' + t.html('consolePki.noApplicationMatches') + '</em></p>'
        : applicationsNav.head +
        '<table><thead><tr><th>' + t.html('consolePki.application') +
        '</th><th>' + t.html('consolePki.profile') + '</th>' +
        '<th>' + t.html('consolePki.thKeyHandle') + '</th><th>' +
        t.html('consolePki.thExpires') + '</th>' +
        '<th>' + t.html('consolePki.declaredIssuer') + '</th><th>' +
        t.html('consolePki.thOwnKeys') + '</th><th></th></tr>' +
        '</thead><tbody>' +
        paged.applications.shown.map(function (one) {
          return '<tr>' +
            '<td><a href="/admin/applications?application=' +
              encodeURIComponent(one.identifier) + '">' +
              esc(one.identifier) + '</a></td>' +
            '<td>' + esc(one.purposeLabel) + '</td>' +
            '<td><code>' + esc(one.handle || '—') + '</code>' +
              (one.handle ? ' <small>(' + esc(one.handleLabel) + ')</small>' :
               '') + PqcBadgeView.badge(one.pqc, t) +
              '</td>' +
            '<td>' + esc(one.expiresAt ? one.expiresAt.slice(0, 8) : '—') +
              '</td>' +
            '<td>' + (one.assertionIssuers.length
              ? one.assertionIssuers.map(function (iss) {
                  return '<code>' + esc(iss) + '</code>';
                }).join('<br>')
              : '<em>' + t.html('consolePki.noIssuerDeclared') + '</em>') +
              '</td>' +
            '<td>' + (one.registeredOwnKeys ? t.html('consolePki.yes')
                                            : t.html('consolePki.no')) +
            '</td>' +
            '<td>' + (one.hasKeyPair
              ? '<form method="post" action="/admin/pki">' +
                '<input type="hidden" name="action" value="revoke">' +
                '<input type="hidden" name="identifier" value="' +
                  esc(one.identifier) + '">' +
                '<input type="hidden" name="purpose" value="' +
                  esc(one.purpose) + '">' + carryBack +
                '<button type="submit">' + takeOff + '</button></form>'
              : '') + '</td>' +
            '</tr>';
        }).join('') + '</tbody></table>' + applicationsNav.foot)
      : '<p>' + t.html('consolePki.noApplicationHolds') + '</p>';

    const twoActs = kit.note(
      '<p>' + t.html('consolePki.twoActsIntro') + '</p><p>' +
      t.html('consolePki.twoActsKeyPair') + '</p><p>' +
      t.html('consolePki.twoActsIssuer') + '</p><p>' +
      t.html('consolePki.twoActsSelf') + '</p><p>' +
      t.html('consolePki.twoActsSaml') + '</p>',
      t.html('consolePki.twoActsTitle'));

    return tiles + what + limits + PqcBadgeView.legend(t) +
                  '<h3 id="pki-tree">' + t.html('consolePki.hierarchy') +
                  '</h3>' +
                  kit.note(
                    t.html('consolePki.treeOneRoot') + '<p>' +
                    t.html('consolePki.treeRealmShares') + '</p><p>' +
                    t.html('consolePki.treeDrawn', { realm: json.realm }) +
                    '</p><p>' + t.html('consolePki.treeAutoBuild') + '</p>',
                    t.html('consolePki.treeTitle')) +
                  self.treeSection(json, t) +
                  self.coverageNote(json, t) +
                  self.pinnedSection(json, t) +
                  '<h3>' + t.html('consolePki.editHierarchy') + '</h3>' +
                  self.rootControls(json, t) +
                  (json.tree.scopes || []).map(function (scope) {
                    return self.scopeControls(json, scope, t);
                  }).join('') +
                  (chain ? '<h3 id="pki-chain">' +
                           t.html('consolePki.threeTierView') + '</h3>' +
                           kit.note(t.html('consolePki.threeTierNote')) +
                           self.chainTable(chain, t) +
                           self.pemBlocks(chain, t) : '') +
                  buildForm + issueForm +
                  '<h3 id="pki-applications">' +
                  t.html('consolePki.applications') + '</h3>' + twoActs +
                  // NO *Rows per table* CONTROL (2026-09-30). Every size it
                  // offered is above this page's ceiling of five and would be
                  // clamped back to it, and a select whose choices all do
                  // nothing is a control that lies about the page. `?per=`
                  // still shortens every list, by hand.
                  issuedRows +
                  personForm +
                  '<h3 id="pki-people">' + t.html('consolePki.people') +
                  '</h3>' + personRows +
                  self.revocationPane(json, listView, t) +
                  self.certificatePane(json, json.workbench.draft, t) +
                  SettingsForms.forms(json.settings, '/admin/pki', undefined,
                                      t) +
                  (certificate
                    ? CertificateDialogView.dialog('/admin/pki', certificate,
                                               ctx.query.from, t)
                    : '');
  }
}

export = PkiPage;
