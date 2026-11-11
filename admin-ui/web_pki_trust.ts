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
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');

type Json = any;

const PAGE = '/admin/pki/trust';

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
    const addForm = context.write
      ? '<h3>' + t.html('consolePkiTrust.addHeading') + '</h3>' +
        kit.note(t.html('consolePkiTrust.addNote')) +
        '<form method="post" action="' + PAGE + '">' +
        '<input type="hidden" name="action" value="add">' +
        '<textarea name="certificates" rows="8" ' +
        'placeholder="-----BEGIN CERTIFICATE-----"></textarea>' +
        '<p>' + t.html('consolePkiTrust.addPurposes') + '</p><p>' +
        purposeBoxes + '</p><p><label class="sub"><input type="checkbox" ' +
        'name="kind" value="accepted"> ' + t.html('consolePkiTrust.addAccept') +
        '</label></p><div class="formrow"><button type="submit">' +
        t.html('consolePkiTrust.addButton') + '</button></div></form>'
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
      '</h2>' + kit.note(t.html('consolePkiTrust.paranoidNote')) +
      PkiTrustPage.masterForm(json, context) +
      '<table><tr><th>' + t.html('consolePkiTrust.thUseCase') + '</th><th>' +
      t.html('consolePkiTrust.thRow') + '</th><th>' +
      t.html('consolePkiTrust.thNow') + '</th><th>' +
      t.html('consolePkiTrust.thCounts') + '</th><th></th></tr>' +
      (json.rows || []).map(function (row: Json) {
        return PkiTrustPage.rowOf(row, json, context);
      }).join('') + '</table>' +
      '<h2 data-tab="signers">' + t.html('consolePkiTrust.signers') + '</h2>' +
      kit.note(t.html('consolePkiTrust.signersNote')) +
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
      '</table>' + addForm +
      '<h2 data-tab="pins">' + t.html('consolePkiTrust.pins') + '</h2>' +
      kit.note(t.html('consolePkiTrust.pinsNote', {
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
       '</td></tr>') + '</table>' + pinsNav.foot +
      '<h2 data-tab="client">' + t.html('consolePkiTrust.client') + '</h2>' +
      kit.note(t.html('consolePkiTrust.clientNote', {
        n: String(json.clientTruststore.count) })) +
      kit.note('<a href="' + kit.esc(json.clientTruststore.href) + '">' +
               t.html('consolePkiTrust.clientLink') + '</a>');
  }
}

export = PkiTrustPage;
