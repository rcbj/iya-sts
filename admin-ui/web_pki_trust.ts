// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_pki_trust.ts
//
// ---------------------------------------------------------------------------
// PROTOCOLS → PKI TRUST, DRAWN FROM ITS VIEW ALONE (#1360, 2026-11-06).
//
// Draws `GET /admin-api/pki/trust`: paranoid PKI mode and every use case's row,
// this realm's signer truststore, what the realm has pinned and the status the
// daily audit last found, and a link to the client-certificate truststore,
// which is the process's and stays on a page of its own.
//
// AND SINCE #2118 (phase 4), from `GET /admin-api/truststores` composed in:
// the Truststores tab (every truststore this realm can name, named ones
// created, filled and deleted here, every other kind read-only with where it
// is changed), the Use cases tab (what each use case trusts, its default,
// and the assignment of one that takes one) and the System truststore tab
// (node's default store, read-only, filtered by the page's own `systemq`).
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');

type Json = any;

const PAGE = '/admin/pki/trust';

// The three tabs #2118 added, by the ids `WebPages.protocolTabs()` gives
// them: a form names its tab, so `web_forms.ts` resolves it to
// `/admin-api/truststores/<action>` and not to this page's own `add` and
// `remove`, which are the signer truststore's.
const TAB_STORES = 'pki-trust-tab-truststores';
const TAB_USES = 'pki-trust-tab-usecases';
const TAB_SYSTEM = 'pki-trust-tab-system';

// A status chip's class, for what the audit found.
const STATUS_CLASS: Record<string, string> = {
  valid: 'state-valid', 'self-signed': 'state-valid',
  'thumbprint-only': 'state-none', expiring: 'state-expired',
  expired: 'state-expired', 'not-yet-valid': 'state-invalid',
  revoked: 'state-revoked', 'chain-missing': 'state-invalid',
  unreadable: 'state-invalid'
};

/**
 * Draws the PKI trust page from the answer of `GET /admin-api/pki/trust`.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class PkiTrustPage {
  // A moment the view holds as milliseconds, as the reader's page shows dates.
  private static when(ms: number): string {
    return ms ? new Date(ms).toISOString().replace('.000Z', 'Z') : '—';
  }

  // The master's three choices as one form; the mode's answer is beside it.
  private static masterForm(json: Json, ctx: Json): string {
    const t = ctx.t;
    const master = json.master;
    const radio = function (value: string): string {
      return '<label><input type="radio" name="value" value="' + value + '"' +
        (master.value === value ? ' checked' : '') + '> <code>' + value +
        '</code></label> ';
    };
    const state = master.inForce ? t.html('consolePkiTrust.inForce')
                                 : t.html('consolePkiTrust.notInForce');
    const red = master.product && !master.inForce;
    return '<p class="' + (red ? 'state-revoked' : 'sub') + '">' + state +
      ' <span class="sub">' + kit.esc(master.decidedBy) + '</span></p>' +
      (ctx.write
        ? '<form method="post" action="' + PAGE + '">' +
          '<input type="hidden" name="action" value="set-row">' +
          '<input type="hidden" name="setting" value="pki.paranoid">' +
          radio('auto') + radio('on') + radio('off') +
          '<div class="formrow"><button type="submit">' +
          t.html('consolePkiTrust.saveMaster') + '</button></div></form>'
        : kit.note(t.html('consolePkiTrust.needsWrite')));
  }

  // One use case's row, red where it is off in product.
  private static rowOf(row: Json, json: Json, ctx: Json): string {
    const t = ctx.t;
    const red = json.master.product && !row.on;
    const exemptions = (row.exemptions || []).map(function (one: Json) {
      return '<li><code>' + kit.esc(one.check) + '</code>: ' +
        kit.esc(one.spec) + '</li>';
    }).join('');
    const control = ctx.write
      ? '<form method="post" action="' + PAGE + '">' +
        '<input type="hidden" name="action" value="set-row">' +
        '<input type="hidden" name="setting" value="' + kit.esc(row.setting) +
        '"><input type="hidden" name="value" value="' +
        (row.on ? 'false' : 'true') + '">' +
        '<button type="submit" class="secondary">' +
        (row.on ? t.html('consolePkiTrust.switchOff')
                : t.html('consolePkiTrust.switchOn')) + '</button></form>'
      : '';
    return '<tr' + (red ? ' class="state-revoked"' : '') + '><td><code>' +
      kit.esc(row.purpose) + '</code><div class="sub">' + kit.esc(row.title) +
      '</div><details><summary>' + t.html('consolePkiTrust.details') +
      '</summary><p>' + kit.esc(row.covers) + '</p><p>' + kit.esc(row.adds) +
      '</p><p class="sub"><code>' + kit.esc(row.setting) + '</code>; ' +
      t.html('consolePkiTrust.phase', { phase: String(row.phase) }) + '</p>' +
      (exemptions ? '<ul>' + exemptions + '</ul>' : '') +
      '</details></td><td>' + (row.on ? t.html('consolePkiTrust.on')
                                      : t.html('consolePkiTrust.off')) +
      '</td><td>' + (row.inForce ? t.html('consolePkiTrust.held')
                                 : t.html('consolePkiTrust.baseline')) +
      '</td><td>' + kit.esc(String(row.assessed)) + ' / ' +
      kit.esc(String(row.refused)) +
      (row.lastRefusal ? '<div class="sub">' + kit.esc(row.lastRefusal) +
        '</div>' : '') + '</td><td>' + control + '</td></tr>';
  }

  // One entry of the signer truststore.
  private static entryOf(entry: Json, ctx: Json): string {
    const t = ctx.t;
    return '<tr><td><code>' + kit.esc(entry.subject) + '</code>' +
      (entry.unadmittable ? '<div class="state-invalid">' +
        kit.esc(entry.unadmittable) + '</div>' : '') +
      '<div class="sub">' + kit.esc(entry.issuer) + '</div></td><td>' +
      kit.esc(entry.kind) + '</td><td>' +
      ((entry.purposes || []).map(kit.esc).join(', ') ||
       t.html('consolePkiTrust.everyPurpose')) + '</td><td class="sub">' +
      PkiTrustPage.when(entry.notBefore) + '<br>' +
      PkiTrustPage.when(entry.notAfter) + '</td><td class="sub"><code>' +
      kit.esc(entry.fingerprint256) + '</code></td><td>' +
      kit.esc(entry.source) + '</td><td>' +
      (ctx.write
        ? '<form method="post" action="' + PAGE + '">' +
          '<input type="hidden" name="action" value="remove">' +
          '<input type="hidden" name="fingerprint" value="' +
          kit.esc(entry.fingerprint256) + '"><button type="submit" ' +
          'class="secondary">' + t.html('consolePkiTrust.remove') +
          '</button></form>'
        : '<span class="sub">Admin Write</span>') + '</td></tr>';
  }

  // One pinned certificate, as the audit last found it.
  private static pinOf(pin: Json): string {
    const where = pin.href
      ? '<a href="' + kit.esc(pin.href) + '">' + kit.esc(pin.where) + '</a>'
      : kit.esc(pin.where);
    return '<tr><td>' + where + '<div class="sub"><code>' +
      kit.esc(pin.purpose) + '</code></div></td><td><code>' +
      kit.esc(pin.subject || pin.fingerprint256 || '—') +
      '</code></td><td class="sub">' + PkiTrustPage.when(pin.notBefore) +
      '<br>' + PkiTrustPage.when(pin.notAfter) + '</td><td>' +
      kit.esc(pin.chainedTo || '—') + '</td><td>' +
      kit.esc(pin.revocation || '—') + '</td><td class="' +
      (STATUS_CLASS[pin.status] || 'state-none') + '">' + kit.esc(pin.status) +
      '</td></tr>';
  }

  // ----- #2118 phase 4: named truststores, use cases, node's store --------

  // A truststore's kind, as a reader reads it.
  private static kindText(kind: string, t: Json): string {
    switch (kind) {
      case 'built-in':
        return t.html('consolePkiTrust.kindBuiltIn');
      case 'view':
        return t.html('consolePkiTrust.kindView');
      case 'setting':
        return t.html('consolePkiTrust.kindSetting');
      case 'spiffe':
        return t.html('consolePkiTrust.kindSpiffe');
      default:
        return t.html('consolePkiTrust.kindNamed');
    }
  }

  // Where a truststore this page cannot change is changed, as a sentence.
  private static whereChanged(row: Json, ctx: Json): string {
    const t = ctx.t;
    if (row.kind === 'built-in') {
      return t.html('consolePkiTrust.whereBuiltIn');
    }
    if (row.kind === 'view' && row.name === 'signers') {
      return t.html('consolePkiTrust.whereSigners');
    }
    if (row.kind === 'view' && row.storeKind === 'jwks') {
      return t.html('consolePkiTrust.whereRegistered');
    }
    if (row.kind === 'view') {
      return t.html('consolePkiTrust.whereClient') + ' <a href="' +
        '/admin/tls/trust">' + t.html('consolePkiTrust.clientLink') + '</a>';
    }
    if (row.kind === 'setting') {
      return t.html('consolePkiTrust.whereSetting', {
        key: String(row.name).replace(/^setting:/, '') });
    }
    if (row.kind === 'spiffe') {
      return t.html('consolePkiTrust.whereSpiffe');
    }
    return t.html('consolePkiTrust.whereShared');
  }

  // One certificate of a named truststore, with its remove control.
  private static storeCertificateOf(name: string, one: Json,
                                    writable: boolean, ctx: Json): string {
    const t = ctx.t;
    return '<tr><td><code>' + kit.esc(one.subject) + '</code>' +
      '<div class="sub">' + kit.esc(one.issuer) + '</div></td><td>' +
      kit.esc(one.kind) + '</td><td class="sub">' +
      PkiTrustPage.when(one.notBefore) + '<br>' +
      PkiTrustPage.when(one.notAfter) + '</td><td class="sub"><code>' +
      kit.esc(one.fingerprint256) + '</code></td><td>' +
      (writable
        ? '<form method="post" action="' + PAGE + '#' + TAB_STORES + '">' +
          '<input type="hidden" name="action" value="remove">' +
          '<input type="hidden" name="name" value="' + kit.esc(name) + '">' +
          '<input type="hidden" name="fingerprint" value="' +
          kit.esc(one.fingerprint256) + '"><button type="submit" ' +
          'class="secondary">' + t.html('consolePkiTrust.remove') +
          '</button></form>'
        : '') + '</td></tr>';
  }

  // A document truststore's row (#2152): which kind of Sigstore trust
  // material, how many documents, who trusts it, and for one this realm
  // holds, a form that replaces its document.
  private static documentOf(row: Json, writable: boolean, ctx: Json): string {
    const t = ctx.t;
    const named = row.kind === 'named';
    const detail = named && writable
      ? '<details><summary>' + t.html('consolePkiTrust.setKeysHeading') +
        '</summary><form method="post" action="' + PAGE + '#' + TAB_STORES +
        '"><input type="hidden" name="action" value="set-keys">' +
        '<input type="hidden" name="name" value="' + kit.esc(row.name) +
        '"><textarea name="document" rows="6" aria-label="' +
        kit.esc(t.text('consolePkiTrust.createDocument')) + '"></textarea>' +
        '<div class="formrow"><button type="submit">' +
        t.html('consolePkiTrust.setKeysButton') + '</button></div></form>' +
        '</details>'
      : '';
    const control = writable
      ? '<form method="post" action="' + PAGE + '#' + TAB_STORES + '">' +
        '<input type="hidden" name="action" value="delete">' +
        '<input type="hidden" name="name" value="' + kit.esc(row.name) + '">' +
        '<button type="submit" class="secondary">' +
        t.html('consolePkiTrust.deleteStore') + '</button></form>'
      : '<span class="sub">' + PkiTrustPage.whereChanged(row, ctx) +
        '</span>';
    return '<tr><td><code>' + kit.esc(row.name) + '</code>' +
      (row.description ? '<div class="sub">' + kit.esc(row.description) +
        '</div>' : '') +
      (row.problem ? '<div class="state-invalid">' + kit.esc(row.problem) +
        '</div>' : '') + detail + '</td><td>' +
      PkiTrustPage.kindText(row.kind, t) + '<div class="sub"><code>' +
      kit.esc(row.storeKind) + '</code></div></td><td>' +
      (row.scope === 'service' ? t.html('consolePkiTrust.scopeService')
                               : t.html('consolePkiTrust.scopeRealm')) +
      '</td><td>' + t.html('consolePkiTrust.documentsHeld',
                           { n: String(row.keys || 0) }) + '</td><td>' +
      ((row.usedBy || []).map(function (one: string) {
        return '<code>' + kit.esc(one) + '</code>';
      }).join(', ') || '<span class="sub">' +
        t.html('consolePkiTrust.nobody') + '</span>') + '</td><td>' +
      control + '</td></tr>';
  }

  // A key set's row (#2149): its party, its keys or jwks_uri, who trusts it,
  // and for one this realm holds, a form that replaces its keys.
  private static keySetOf(row: Json, writable: boolean, ctx: Json): string {
    const t = ctx.t;
    const named = row.kind === 'named';
    const ssh = row.storeKind === 'ssh';
    const holds = ssh ? t.html('consolePkiTrust.sshKeys',
                               { n: String(row.keys || 0) }) :
      !named ? t.html('consolePkiTrust.keySetRegistered') :
      '<div>' + t.html('consolePkiTrust.keySetFor', { party: row.party }) +
      '</div><div class="sub">' + (row.jwksUri
        ? t.html('consolePkiTrust.keySetUri', { uri: row.jwksUri })
        : t.html('consolePkiTrust.keySetKeys', { n: String(row.keys || 0) })) +
      '</div>';
    const detail = named && writable && ssh
      ? '<details><summary>' + t.html('consolePkiTrust.setKeysHeading') +
        '</summary><form method="post" action="' + PAGE + '#' + TAB_STORES +
        '"><input type="hidden" name="action" value="set-keys">' +
        '<input type="hidden" name="name" value="' + kit.esc(row.name) +
        '"><textarea name="sshKeys" rows="5" aria-label="' +
        kit.esc(t.text('consolePkiTrust.createSshKeys')) + '" placeholder=' +
        '"ssh-ed25519 AAAA…"></textarea><div class="formrow"><button ' +
        'type="submit">' + t.html('consolePkiTrust.setKeysButton') +
        '</button></div></form></details>'
      : named && writable
      ? '<details><summary>' + t.html('consolePkiTrust.setKeysHeading') +
        '</summary><form method="post" action="' + PAGE + '#' + TAB_STORES +
        '"><input type="hidden" name="action" value="set-keys">' +
        '<input type="hidden" name="name" value="' + kit.esc(row.name) +
        '"><textarea name="jwks" rows="5" aria-label="' +
        kit.esc(t.text('consolePkiTrust.createJwks')) + '" placeholder=' +
        '"{&quot;keys&quot;: [ … ]}"></textarea><div class="formrow">' +
        '<label>' + t.html('consolePkiTrust.createJwksUri') + ' <input ' +
        'type="url" name="jwksUri" size="48"></label></div>' +
        '<div class="formrow"><button type="submit">' +
        t.html('consolePkiTrust.setKeysButton') + '</button></div></form>' +
        '</details>'
      : '';
    const control = writable
      ? '<form method="post" action="' + PAGE + '#' + TAB_STORES + '">' +
        '<input type="hidden" name="action" value="delete">' +
        '<input type="hidden" name="name" value="' + kit.esc(row.name) + '">' +
        '<button type="submit" class="secondary">' +
        t.html('consolePkiTrust.deleteStore') + '</button></form>'
      : '<span class="sub">' + PkiTrustPage.whereChanged(row, ctx) +
        '</span>';
    return '<tr><td><code>' + kit.esc(row.name) + '</code>' +
      (row.description ? '<div class="sub">' + kit.esc(row.description) +
        '</div>' : '') +
      (row.problem ? '<div class="state-invalid">' + kit.esc(row.problem) +
        '</div>' : '') + detail + '</td><td>' +
      PkiTrustPage.kindText(row.kind, t) + '<div class="sub">' +
      (ssh ? t.html('consolePkiTrust.kindSshCa')
           : t.html('consolePkiTrust.kindKeySet')) + '</div></td><td>' +
      (row.scope === 'service' ? t.html('consolePkiTrust.scopeService')
                               : t.html('consolePkiTrust.scopeRealm')) +
      '</td><td>' + holds + '</td><td>' +
      ((row.usedBy || []).map(function (one: string) {
        return '<code>' + kit.esc(one) + '</code>';
      }).join(', ') || '<span class="sub">' +
        t.html('consolePkiTrust.nobody') + '</span>') + '</td><td>' +
      control + '</td></tr>';
  }

  // One truststore's row: what it is, what it holds, who trusts it, and for
  // a named truststore this realm holds, its certificates and controls.
  private static storeOf(row: Json, ctx: Json): string {
    const t = ctx.t;
    const writable = !row.readOnly && row.kind === 'named' && ctx.write;
    if (row.storeKind === 'jwks' || row.storeKind === 'ssh') {
      return PkiTrustPage.keySetOf(row, writable, ctx);
    }
    if (['cosign', 'sigstore-root', 'tuf-root']
          .indexOf(row.storeKind) >= 0) {
      return PkiTrustPage.documentOf(row, writable, ctx);
    }
    const holds = t.html('consolePkiTrust.holds', {
      anchors: String(row.anchors), intermediates: String(row.intermediates)
    }) + (row.kind === 'spiffe'
      ? '<div class="sub">' + t.html('consolePkiTrust.jwtKeys', {
        n: String(row.jwtKeys || 0) }) + '</div>' : '');
    const certificates = row.certificates || [];
    let detail = '';
    if (row.kind === 'named') {
      detail = '<details><summary>' + t.html('consolePkiTrust.certificates', {
        n: String(certificates.length) }) + '</summary>' +
        (certificates.length
          ? '<table><tr><th>' + t.html('consolePkiTrust.thSubject') +
            '</th><th>' + t.html('consolePkiTrust.thKind') + '</th><th>' +
            t.html('consolePkiTrust.thValidity') + '</th><th>' +
            t.html('consolePkiTrust.thFingerprint') + '</th><th></th></tr>' +
            certificates.map(function (one: Json) {
              return PkiTrustPage.storeCertificateOf(row.name, one,
                                                     writable, ctx);
            }).join('') + '</table>'
          : '<p class="sub">' + t.html('consolePkiTrust.emptyStore') +
            '</p>') +
        (writable
          ? '<form method="post" action="' + PAGE + '#' + TAB_STORES + '">' +
            '<input type="hidden" name="action" value="add">' +
            '<input type="hidden" name="name" value="' + kit.esc(row.name) +
            '"><textarea name="certificates" rows="6" ' +
            'placeholder="-----BEGIN CERTIFICATE-----"></textarea>' +
            '<div class="formrow"><button type="submit">' +
            t.html('consolePkiTrust.addToStore') + '</button></div></form>'
          : '') + '</details>';
    }
    const control = writable
      ? '<form method="post" action="' + PAGE + '#' + TAB_STORES + '">' +
        '<input type="hidden" name="action" value="delete">' +
        '<input type="hidden" name="name" value="' + kit.esc(row.name) + '">' +
        '<button type="submit" class="secondary">' +
        t.html('consolePkiTrust.deleteStore') + '</button></form>'
      : (row.readOnly || row.kind !== 'named'
        ? '<span class="sub">' + PkiTrustPage.whereChanged(row, ctx) +
          '</span>' : '');
    return '<tr><td><code>' + kit.esc(row.name) + '</code>' +
      (row.description ? '<div class="sub">' + kit.esc(row.description) +
        '</div>' : '') +
      (row.problem ? '<div class="state-invalid">' + kit.esc(row.problem) +
        '</div>' : '') + detail + '</td><td>' +
      PkiTrustPage.kindText(row.kind, t) + '</td><td>' +
      (row.scope === 'service' ? t.html('consolePkiTrust.scopeService')
                               : t.html('consolePkiTrust.scopeRealm')) +
      '</td><td>' + holds + '</td><td>' +
      ((row.usedBy || []).map(function (one: string) {
        return '<code>' + kit.esc(one) + '</code>';
      }).join(', ') || '<span class="sub">' +
        t.html('consolePkiTrust.nobody') + '</span>') + '</td><td>' +
      control + '</td></tr>';
  }

  // The Truststores tab.
  private static storesTab(view: Json, ctx: Json): string {
    const t = ctx.t;
    const limits = view.limits || {};
    const create = ctx.write
      ? kit.frame('<h3>' + t.html('consolePkiTrust.createHeading') + '</h3>' +
        kit.note(t.html('consolePkiTrust.createNote', {
          max: String(limits.maxStores) })) +
        '<form method="post" action="' + PAGE + '#' + TAB_STORES + '">' +
        '<input type="hidden" name="action" value="create">' +
        '<div class="formrow"><label for="truststore-name">' +
        t.html('consolePkiTrust.createName') + '</label><input type="text" ' +
        'id="truststore-name" name="name" size="32" ' +
        'pattern="[a-z0-9][a-z0-9-]{0,62}" required></div>' +
        '<div class="formrow"><label for="truststore-description">' +
        t.html('consolePkiTrust.createDescription') + '</label><input ' +
        'type="text" id="truststore-description" name="description" ' +
        'size="48"></div>' +
        // A KEY SET (#2149): bound to one party, its keys pasted or fetched.
        '<div class="formrow"><label for="truststore-kind">' +
        t.html('consolePkiTrust.createKind') + '</label><select ' +
        'id="truststore-kind" name="kind"><option value="x509">' +
        t.html('consolePkiTrust.createKindX509') + '</option><option ' +
        'value="jwks">' + t.html('consolePkiTrust.createKindJwks') +
        '</option><option value="ssh">' +
        t.html('consolePkiTrust.createKindSsh') + '</option>' +
        '<option value="cosign">' + t.html('consolePkiTrust.createKindCosign') +
        '</option><option value="sigstore-root">' +
        t.html('consolePkiTrust.createKindSigstoreRoot') + '</option>' +
        '<option value="tuf-root">' +
        t.html('consolePkiTrust.createKindTufRoot') + '</option>' +
        '</select></div>' +
        '<div class="formrow"><label for="truststore-party">' +
        t.html('consolePkiTrust.createParty') + '</label><input ' +
        'type="text" id="truststore-party" name="party" size="40" ' +
        'placeholder="client:my-client"></div>' +
        '<div class="formrow"><label for="truststore-jwks">' +
        t.html('consolePkiTrust.createJwks') + '</label><textarea ' +
        'id="truststore-jwks" name="jwks" rows="4"></textarea></div>' +
        '<div class="formrow"><label for="truststore-jwks-uri">' +
        t.html('consolePkiTrust.createJwksUri') + '</label><input ' +
        'type="url" id="truststore-jwks-uri" name="jwksUri" size="48">' +
        '</div><div class="formrow"><label for="truststore-ssh-keys">' +
        t.html('consolePkiTrust.createSshKeys') + '</label><textarea ' +
        'id="truststore-ssh-keys" name="sshKeys" rows="3"></textarea></div>' +
        '<div class="formrow"><label for="truststore-document">' +
        t.html('consolePkiTrust.createDocument') + '</label><textarea ' +
        'id="truststore-document" name="document" rows="4"></textarea>' +
        '</div>' +
        '<div class="formrow"><button type="submit">' +
        t.html('consolePkiTrust.createButton') + '</button></div></form>')
      : kit.note(t.html('consolePkiTrust.needsWrite'));
    return '<h2 data-tab="truststores">' +
      t.html('consolePkiTrust.truststores') + '</h2>' +
      kit.frame(kit.note(t.html('consolePkiTrust.truststoresNote')) +
      (limits.installed ? ''
        : kit.warn(t.html('consolePkiTrust.notInstalled'))) +
      '<table><tr><th>' + t.html('consolePkiTrust.thName') + '</th><th>' +
      t.html('consolePkiTrust.thKind') + '</th><th>' +
      t.html('consolePkiTrust.thScope') + '</th><th>' +
      t.html('consolePkiTrust.thHolds') + '</th><th>' +
      t.html('consolePkiTrust.thTrustedBy') + '</th><th></th></tr>' +
      (view.stores || []).map(function (row: Json) {
        return PkiTrustPage.storeOf(row, ctx);
      }).join('') + '</table>' + create);
  }

  // One use case's row, with its assignment control where it has one.
  private static useCaseOf(row: Json, realm: string, ctx: Json): string {
    const t = ctx.t;
    const names = function (list: string[]): string {
      return (list || []).map(function (one) {
        return '<code>' + kit.esc(one) + '</code>';
      }).join(', ');
    };
    let control = '';
    if (!row.assignable) {
      control = '<span class="sub">' +
        (row.kind === 'pins' ? t.html('consolePkiTrust.notAssignablePins')
          : row.kind === 'admission'
            ? t.html('consolePkiTrust.notAssignableAdmission')
            : t.html('consolePkiTrust.notAssignableFixed')) + '</span>';
    } else if (row.scope === 'service' && realm !== 'default' &&
               !row.overridable) {
      control = '<span class="sub">' +
        t.html('consolePkiTrust.assignedFromDefault') + '</span>';
    } else if (ctx.write) {
      control = '<form method="post" action="' + PAGE + '#' + TAB_USES +
        '"><input type="hidden" name="action" value="assign">' +
        '<input type="hidden" name="useCase" value="' + kit.esc(row.id) +
        '"><input type="text" name="truststores" size="28" value="' +
        kit.esc((row.names || []).join(', ')) + '" aria-label="' +
        kit.esc(t.text('consolePkiTrust.assignHint')) + '" title="' +
        kit.esc(t.text('consolePkiTrust.assignHint')) + '"> ' +
        '<button type="submit" class="secondary">' +
        t.html('consolePkiTrust.assignButton') + '</button></form>' +
        (row.assigned
          ? '<form method="post" action="' + PAGE + '#' + TAB_USES + '">' +
            '<input type="hidden" name="action" value="unassign">' +
            '<input type="hidden" name="useCase" value="' +
            kit.esc(row.id) + '"><button type="submit" class="secondary">' +
            t.html('consolePkiTrust.unassignButton') + '</button></form>'
          : '');
    }
    return '<tr><td><code>' + kit.esc(row.id) + '</code><div class="sub">' +
      kit.esc(row.title) + '</div><details><summary>' +
      t.html('consolePkiTrust.sites') + '</summary><p class="sub">' +
      (row.sites || []).map(function (one: string) {
        return '<code>' + kit.esc(one) + '</code>';
      }).join('<br>') + '</p></details></td><td>' +
      (row.direction === 'outbound' ? t.html('consolePkiTrust.outbound')
                                    : t.html('consolePkiTrust.inbound')) +
      '</td><td>' +
      (row.scope === 'service' ? t.html('consolePkiTrust.scopeService')
                               : t.html('consolePkiTrust.scopeRealm')) +
      '</td><td>' + (names(row.names) || '—') + '<div class="sub">' +
      (row.realmOverride ? t.html('consolePkiTrust.realmOverride')
        : row.assigned ? t.html('consolePkiTrust.assigned')
          : t.html('consolePkiTrust.byDefault')) + '</div></td><td>' +
      (names(row.defaults) || '—') +
      ((row.fallback || []).length
        ? '<div class="sub">' + t.html('consolePkiTrust.fallback') + ' ' +
          names(row.fallback) + '</div>' : '') + '</td><td>' + control +
      '</td></tr>';
  }

  // The Use cases tab.
  private static useCasesTab(view: Json, ctx: Json): string {
    const t = ctx.t;
    return '<h2 data-tab="usecases">' + t.html('consolePkiTrust.useCases') +
      '</h2>' + kit.frame(kit.note(t.html('consolePkiTrust.useCasesNote')) +
      (ctx.write ? '' : kit.note(t.html('consolePkiTrust.needsWrite'))) +
      '<table><tr><th>' + t.html('consolePkiTrust.thUseCase') + '</th><th>' +
      t.html('consolePkiTrust.thDirection') + '</th><th>' +
      t.html('consolePkiTrust.thScope') + '</th><th>' +
      t.html('consolePkiTrust.thTrustsNow') + '</th><th>' +
      t.html('consolePkiTrust.thDefault') + '</th><th></th></tr>' +
      (view.useCases || []).map(function (row: Json) {
        return PkiTrustPage.useCaseOf(row, String(view.realm || ''), ctx);
      }).join('') + '</table>');
  }

  // The System truststore tab: node's default store, filtered by the page's
  // own `systemq`, sorted by subject as the view sends it.
  private static systemTab(view: Json, ctx: Json): string {
    const t = ctx.t;
    const system = view.system || { count: 0, certificates: [] };
    const wanted = String(kit.queryOne(ctx.query || {}, 'systemq') || '')
      .trim();
    const needle = wanted.toLowerCase();
    const shown = (system.certificates || []).filter(function (one: Json) {
      return !needle ||
        [one.subject, one.issuer, one.fingerprint256].some(function (v) {
          return String(v || '').toLowerCase().indexOf(needle) >= 0;
        });
    });
    return '<h2 data-tab="system">' + t.html('consolePkiTrust.system') +
      '</h2>' + kit.frame(kit.note(t.html('consolePkiTrust.systemNote')) +
      '<div class="tiles">' + kit.tile(system.count,
        t.text('consolePkiTrust.tileSystem')) + '</div>' +
      '<form method="get" action="' + PAGE + '#' + TAB_SYSTEM + '">' +
      '<div class="formrow"><label for="systemq">' +
      t.html('consolePkiTrust.systemFilter') + '</label><input type="text" ' +
      'id="systemq" name="systemq" size="32" value="' + kit.esc(wanted) +
      '" placeholder="' + kit.esc(t.text('consolePkiTrust.systemHint')) +
      '"><button class="secondary">' + t.html('consoleKit.search') +
      '</button>' + (wanted ? ' <a href="' + PAGE + '#' + TAB_SYSTEM + '">' +
        t.html('consoleKit.clear') + '</a>' : '') + '</div></form>' +
      (wanted ? '<p class="sub">' + t.html('consolePkiTrust.systemShown', {
        shown: String(shown.length), n: String(system.count) }) + '</p>'
        : '') +
      '<table><tr><th>' + t.html('consolePkiTrust.thSubject') + '</th><th>' +
      t.html('consolePkiTrust.thIssuer') + '</th><th>' +
      t.html('consolePkiTrust.thValidity') + '</th><th>' +
      t.html('consolePkiTrust.thFingerprint') + '</th></tr>' +
      (shown.map(function (one: Json) {
        return '<tr><td>' + kit.esc(one.subject) + '</td><td class="sub">' +
          kit.esc(one.issuer) + '</td><td class="sub">' +
          PkiTrustPage.when(one.notBefore) + '<br>' +
          PkiTrustPage.when(one.notAfter) + '</td><td class="sub"><code>' +
          kit.esc(one.fingerprint256) + '</code></td></tr>';
      }).join('') || '<tr><td colspan="4">' +
        kit.esc(t.text('consolePkiTrust.emptySystem')) + '</td></tr>') +
      '</table>');
  }

  /**
   * Draws the page from its view.
   *
   * @param json - the answer of the page's management API operation
   * @param ctx - the render context (`WebKit.context()`)
   * @returns the body as HTML
   */
  static render(json: Json, ctx?: Json): string {
    const context = ctx || kit.context();
    const t = context.t;
    const store = json.truststore;
    const entries = store.entries || [];
    const purposeBoxes = (json.rows || []).map(function (row: Json) {
      return '<label class="sub"><input type="checkbox" name="purposes" ' +
        'value="' + kit.esc(row.purpose) + '"> <code>' +
        kit.esc(row.purpose) + '</code></label> ';
    }).join('');
    // FRAMED AS KEY PAIRS IS (`secframe`, rcbj 2026-11-16): each tab's
    // content after its heading, which stays at the top level for the tab
    // splitter, and the `<h3>` block a frame inside the Signers tab's.
    const addForm = context.write
      ? kit.frame('<h3>' + t.html('consolePkiTrust.addHeading') + '</h3>' +
        kit.note(t.html('consolePkiTrust.addNote')) +
        '<form method="post" action="' + PAGE + '">' +
        '<input type="hidden" name="action" value="add">' +
        '<textarea name="certificates" rows="8" ' +
        'placeholder="-----BEGIN CERTIFICATE-----"></textarea>' +
        '<p>' + t.html('consolePkiTrust.addPurposes') + '</p><p>' +
        purposeBoxes + '</p><p><label class="sub"><input type="checkbox" ' +
        'name="kind" value="accepted"> ' + t.html('consolePkiTrust.addAccept') +
        '</label></p><div class="formrow"><button type="submit">' +
        t.html('consolePkiTrust.addButton') + '</button></div></form>')
      : kit.note(t.html('consolePkiTrust.needsWrite'));
    const pinsNav = kit.pageNavPair(PAGE, kit.pageParamsOf(context.query),
      Object.assign({ offset: 0 }, json.pinsPaging), t);
    return kit.note(t.html('consolePkiTrust.intro')) +
      '<div class="tiles">' +
      kit.tile(store.anchors, t.text('consolePkiTrust.tileAnchors')) +
      kit.tile(store.intermediates,
               t.text('consolePkiTrust.tileIntermediates')) +
      kit.tile(json.pinsTotal, t.text('consolePkiTrust.tilePins')) +
      '</div>' +
      '<h2 data-tab="paranoid">' + t.html('consolePkiTrust.paranoid') +
      '</h2>' + kit.frame(kit.note(t.html('consolePkiTrust.paranoidNote')) +
      PkiTrustPage.masterForm(json, context) +
      '<table><tr><th>' + t.html('consolePkiTrust.thUseCase') + '</th><th>' +
      t.html('consolePkiTrust.thRow') + '</th><th>' +
      t.html('consolePkiTrust.thNow') + '</th><th>' +
      t.html('consolePkiTrust.thCounts') + '</th><th></th></tr>' +
      (json.rows || []).map(function (row: Json) {
        return PkiTrustPage.rowOf(row, json, context);
      }).join('') + '</table>') +
      '<h2 data-tab="signers">' + t.html('consolePkiTrust.signers') + '</h2>' +
      kit.frame(kit.note(t.html('consolePkiTrust.signersNote')) +
      kit.note(store.file
        ? t.html('consolePkiTrust.fileSet', {
          file: store.file, n: String(store.loadedFromFile) })
        : t.html('consolePkiTrust.fileUnset')) +
      '<table><tr><th>' + t.html('consolePkiTrust.thSubject') + '</th><th>' +
      t.html('consolePkiTrust.thKind') + '</th><th>' +
      t.html('consolePkiTrust.thPurposes') + '</th><th>' +
      t.html('consolePkiTrust.thValidity') + '</th><th>' +
      t.html('consolePkiTrust.thFingerprint') + '</th><th>' +
      t.html('consolePkiTrust.thSource') + '</th><th></th></tr>' +
      (entries.map(function (entry: Json) {
        return PkiTrustPage.entryOf(entry, context);
      }).join('') || '<tr><td colspan="7">' +
        kit.esc(t.text('consolePkiTrust.emptySigners')) + '</td></tr>') +
      '</table>' + addForm) +
      '<h2 data-tab="pins">' + t.html('consolePkiTrust.pins') + '</h2>' +
      kit.frame(kit.note(t.html('consolePkiTrust.pinsNote', {
        when: PkiTrustPage.when(json.assessedAt) })) +
      (context.write
        ? '<form method="post" action="' + PAGE + '">' +
          '<input type="hidden" name="action" value="recheck">' +
          '<div class="formrow"><button type="submit" class="secondary">' +
          t.html('consolePkiTrust.recheck') + '</button></div></form>'
        : '') + pinsNav.head +
      '<table><tr><th>' + t.html('consolePkiTrust.thWhere') + '</th><th>' +
      t.html('consolePkiTrust.thSubject') + '</th><th>' +
      t.html('consolePkiTrust.thValidity') + '</th><th>' +
      t.html('consolePkiTrust.thChained') + '</th><th>' +
      t.html('consolePkiTrust.thRevocation') + '</th><th>' +
      t.html('consolePkiTrust.thStatus') + '</th></tr>' +
      ((json.pins || []).map(PkiTrustPage.pinOf).join('') ||
       '<tr><td colspan="6">' + kit.esc(t.text('consolePkiTrust.emptyPins')) +
       '</td></tr>') + '</table>' + pinsNav.foot) +
      '<h2 data-tab="client">' + t.html('consolePkiTrust.client') + '</h2>' +
      kit.frame(kit.note(t.html('consolePkiTrust.clientNote', {
        n: String(json.clientTruststore.count) })) +
      kit.note('<a href="' + kit.esc(json.clientTruststore.href) + '">' +
               t.html('consolePkiTrust.clientLink') + '</a>')) +
      // #2118: drawn from `GET /admin-api/truststores`, composed into the
      // view as `truststores` (`web_pages.ts`).
      (json.truststores
        ? PkiTrustPage.storesTab(json.truststores, context) +
          PkiTrustPage.useCasesTab(json.truststores, context) +
          PkiTrustPage.systemTab(json.truststores, context)
        : '');
  }
}

export = PkiTrustPage;
