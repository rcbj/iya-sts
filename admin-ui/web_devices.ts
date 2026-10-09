// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_devices.ts
//
// ---------------------------------------------------------------------------
// DIRECTORY → DEVICES, PROTOCOLS → DEVICE REGISTRATION AND MONITORING →
// DEVICES, DRAWN FROM THEIR VIEWS ALONE (#446, 2026-10-05).
//
// Draws the device register's three pages: Directory → Devices (the list, or
// one device) from `GET /admin-api/devices`, Device registration from `GET
// /admin-api/device-registration` and Monitoring → Devices from `GET
// /admin-api/devices/monitor`.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// Its methods were `DevicesAdmin`'s in `admin-ui/devices_admin.ts`, moved with
// their comments; that module still draws the page until the console's
// cutover, by calling `render()` with its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');
import SettingsForms = require('./web_settings');

type Json = any;

// THE PAGE'S TRANSLATOR, ESCAPING AS THIS PAGE ALWAYS ESCAPED (#539). Much
// of what fills a message here is the view's own prose, and an apostrophe
// in it was drawn by `kit.esc()` as `&apos;` where the translator's
// escaping writes `&#39;`. Same character, different bytes — and the
// console's browser jobs compare bytes. So a message WITH parameters has
// its `&#39;` written as `&apos;`; no message of this page's catalog
// carries a literal `&#39;` for this to change. Every other member is the
// translator's own, through the prototype.
const kitEscaping = function (translator: Json): Json {
  const wrapped = Object.create(translator);
  wrapped.html = function (key: string, params?: Json): string {
    const out = translator.html(key, params);
    return params ? out.replace(/&#39;/g, '&apos;') : out;
  };
  return wrapped;
};

/**
 * Directory → Devices: the realm's device list, and one device by `?device=`.
 */
const LIST = '/admin/devices';

/**
 * Protocols → Device registration: how a device arrives and is recognised.
 */
const REGISTRATION = '/admin/device-registration';

/**
 * Monitoring → Devices: the register counted, and its events over time.
 */
const MONITOR = '/admin/devices/monitor';

/**
 * Draws the device register's three pages: Directory → Devices (the list, or
 * one device) from `GET /admin-api/devices`, Device registration from `GET
 * /admin-api/device-registration` and Monitoring → Devices from `GET
 * /admin-api/devices/monitor`.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class DevicesPage {
  /**
   * Draws the page's body from its view.
   *
   * @param view - the answer of the page's management API operation
   * @param ctx - the render context: the page's query and whether
   *   the reader may write (`WebKit.context()`)
   * @returns the body as HTML
   */
  static render(view: Json, ctx: Json): string {
    return DevicesPage.listBody(ctx, view);
  }

  // -------------------------------------------------------------------------
  // THE HTML
  // -------------------------------------------------------------------------
  static options(list: string[], chosen: string, blank: string): string {
    return (blank !== null ? '<option value="">' + kit.esc(blank) +
            '</option>' : '') + list.map(function (one) {
      return '<option value="' + kit.esc(one) + '"' +
        (one === chosen ? ' selected' : '') + '>' + kit.esc(one) +
        '</option>';
    }).join('');
  }

  static ownerCell(t: Json, r: Json): string {
    const esc = kit.esc.bind(kit);
    const link = r.ownerKind === 'application'
      ? '/admin/applications?application=' + encodeURIComponent(r.ownerName)
      : '/admin/users?user=' + encodeURIComponent(r.ownerName);
    return esc(r.ownerKind) + ' ' + (r.ownerFound
      ? '<a href="' + link + '">' + esc(r.ownerName) + '</a>'
      : '<em>' + t.html('consoleDevices.ownerCell.notInDirectory') +
        '</em>') + '<br><small><code>' +
      esc(r.owner) + '</code></small>';
  }

  static listHtml(ctx: Json, json: Json): string {
    // The page's words are its translator's (#539 phase 6); the view's
    // vocabulary (owner kinds, compliance states) is drawn as it comes,
    // because those values are what the forms submit.
    const t = kitEscaping(ctx.t);
    const self = this;
    const esc = kit.esc.bind(kit);
    const f = json.filter;
    const v = json.vocabulary;
    const filters = '<form method="get" action="' + LIST + '"><div ' +
      'class="formrow"><label for="dev-q">' +
      t.html('consoleDevices.listHtml.search') + '</label><input ' +
      'type="text" id="dev-q" name="q" size="24" value="' + esc(f.q || '') +
      '" placeholder="' + esc(t.text('consoleDevices.listHtml.searchHint')) +
      '">' +
      '<label for="dev-ok">' + t.html('consoleDevices.listHtml.owner') +
      '</label><select id="dev-ok" ' +
      'name="ownerKind">' +
      this.options(v.ownerKinds, f.ownerKind,
                   t.text('consoleDevices.listHtml.any')) +
      '</select><label for="dev-c">' +
      t.html('consoleDevices.listHtml.compliance') +
      '</label><select id="dev-c" ' +
      'name="compliance">' +
      this.options(v.compliance, f.compliance,
                   t.text('consoleDevices.listHtml.any')) +
      '</select><label for="dev-a">' +
      t.html('consoleDevices.listHtml.attestation') +
      '</label><select id="dev-a" ' +
      'name="attestation">' +
      this.options(v.attestation, f.attestation,
                   t.text('consoleDevices.listHtml.any')) +
      '</select><label for="dev-k">' + t.html('consoleDevices.listHtml.key') +
      '</label><select id="dev-k" ' +
      'name="keyKind">' +
      this.options(v.keyKinds, f.keyKind,
                   t.text('consoleDevices.listHtml.any')) +
      '</select><label for="dev-per">' +
      t.html('consoleDevices.listHtml.show') + '</label><select id="dev-per" ' +
      'name="per">' + kit.perPageOptions(json.perPage, t) + '</select>' +
      '<button type="submit">' + t.html('consoleDevices.listHtml.filter') +
      '</button>' +
      (Object.keys(f).length
        ? ' <a href="' + LIST + '">' + t.html('consoleDevices.listHtml.clear') +
          '</a>'
        : '') +
      '</div></form>';
    const nav = kit.pageNavPair(LIST, Object.assign({}, f,
      ctx.query && ctx.query.per ? { per: String(json.perPage) } : {}),
      json.devicesPaging, t);
    const rows = json.devices.map(function (r: Json): string {
      return '<tr><td><a href="' + LIST + '?device=' +
        encodeURIComponent(r.id) + '">' + esc(r.label) + '</a><br><small>' +
        '<code>' + esc(r.id) + '</code></small></td><td>' +
        self.ownerCell(t, r) + '</td><td>' + (r.keyKinds.length
          ? esc(r.keyKinds.join(', ')) : '—') + '</td><td>' +
        esc(r.attestation.level) + '</td><td>' + esc(r.compliance) +
        (r.status === 'compromised'
          ? ' <strong>' + t.html('consoleDevices.listHtml.compromised') +
            '</strong>'
          : '') +
        '</td><td>' +
        (r.nativeSso
          ? (r.sessionLive ? t.html('consoleDevices.listHtml.live')
                           : t.html('consoleDevices.listHtml.sessionEnded'))
          : '—') + '</td><td><small>' +
        esc(r.lastUsed || '—') + '</small></td></tr>';
    }).join('');
    const canWrite = ctx.write;
    const create = canWrite
      ? '<h2>' + t.html('consoleDevices.listHtml.registerHeading') + '</h2>' +
      kit.note(t.html('consoleDevices.listHtml.registerNote')) +
      '<form method="post" action="' + LIST + '">' +
      '<input type="hidden" name="action" value="create">' +
      '<div class="formrow"><label for="dev-n-label">' +
      t.html('consoleDevices.listHtml.label') + '</label>' +
      '<input type="text" id="dev-n-label" name="label" size="30" ' +
      'maxlength="128"></div>' +
      '<div class="formrow"><label for="dev-n-ok">' +
      t.html('consoleDevices.listHtml.ownerKind') + '</label>' +
      '<select id="dev-n-ok" name="ownerKind">' +
      this.options(v.ownerKinds, 'person', null) + '</select>' +
      '<label for="dev-n-owner">' + t.html('consoleDevices.listHtml.owner') +
      '</label><input type="text" ' +
      'id="dev-n-owner" name="owner" size="24" required></div>' +
      '<div class="formrow"><label for="dev-n-p">' +
      t.html('consoleDevices.listHtml.platform') + '</label>' +
      '<select id="dev-n-p" name="platform">' +
      this.options(v.platforms, '',
                   t.text('consoleDevices.listHtml.unstated')) +
      '</select>' +
      '<label for="dev-n-m">' + t.html('consoleDevices.listHtml.model') +
      '</label><input type="text" id="dev-n-m" ' +
      'name="model" size="20" maxlength="128"><label for="dev-n-os">' +
      t.html('consoleDevices.listHtml.os') +
      '</label><input type="text" id="dev-n-os" name="os" size="16" ' +
      'maxlength="128"></div>' +
      '<div class="formrow"><label for="dev-n-apps">' +
      t.html('consoleDevices.listHtml.applications') + '</label>' +
      '<input type="text" id="dev-n-apps" name="applications" size="40" ' +
      'placeholder="' + esc(t.text('consoleDevices.listHtml.appsHint')) +
      '"></div>' +
      '<div class="formrow"><label for="dev-n-kk">' +
      t.html('consoleDevices.listHtml.firstKey') + '</label>' +
      '<select id="dev-n-kk" name="keyKind">' +
      this.options(['x509', 'jwk', 'webauthn'], '',
                   t.text('consoleDevices.listHtml.none')) + '</select>' +
      '<textarea id="dev-n-key" name="key" rows="3" cols="60" ' +
      'placeholder="' + esc(t.text('consoleDevices.listHtml.keyHint')) +
      '"></textarea></div>' +
      '<div class="formrow"><button type="submit">' +
      t.html('consoleDevices.listHtml.register') + '</button></div>' +
      '</form>'
      : kit.note(t.html('consoleDevices.listHtml.readOnly'));
    // The note's three links carry hrefs, which a message may not: the
    // words between them are messages and the anchors are code.
    return '<div class="tiles">' +
      kit.tile(String(json.total),
               t.text('consoleDevices.listHtml.tileDevices')) +
      kit.tile(String(json.matched),
               t.text('consoleDevices.listHtml.tileMatched')) + '</div>' +
      kit.note(t.html('consoleDevices.listHtml.leadIntro') +
                 '<a href="' + MONITOR + '">' +
                 t.html('consoleDevices.listHtml.leadMonitor') + '</a>' +
                 t.html('consoleDevices.listHtml.leadCounts') +
                 '<a href="/admin/ldap/devices">' +
                 t.html('consoleDevices.listHtml.leadEntries') + '</a>' +
                 t.html('consoleDevices.listHtml.leadSame') +
                 '<a href="' + REGISTRATION + '">' +
                 t.html('consoleDevices.listHtml.leadRegistration') + '</a>' +
                 t.html('consoleDevices.listHtml.leadArrives'),
               t.text('consoleDevices.listHtml.whatThisIs')) +
      filters + nav.head + '<table class="grid"><thead><tr><th>' +
      t.html('consoleDevices.listHtml.thDevice') + '</th>' +
      '<th>' + t.html('consoleDevices.listHtml.thOwner') + '</th><th>' +
      t.html('consoleDevices.listHtml.thKeys') + '</th><th>' +
      t.html('consoleDevices.listHtml.thAttestation') + '</th><th>' +
      t.html('consoleDevices.listHtml.thCompliance') + '</th>' +
      '<th>' + t.html('consoleDevices.listHtml.thNativeSso') + '</th><th>' +
      t.html('consoleDevices.listHtml.thLastUsed') +
      '</th></tr></thead><tbody>' +
      (rows || '<tr><td colspan="7">' + (Object.keys(f).length
        ? t.html('consoleDevices.listHtml.noMatch')
        : t.html('consoleDevices.listHtml.noneYet')) + '</td></tr>') +
      '</tbody></table>' + nav.foot +
      create;
  }

  // THE LIST PAGE'S BODY (#446): every device, or one when the query names
  // it — one method, so that it can be one renderer.
  /**
   * Draws Directory → Devices: the list, or one device.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - `listView()`'s answer
   * @returns the body as HTML
   */
  static listBody(ctx: Json, json: Json): string {
    if (ctx.query && ctx.query.device !== undefined) {
      return json.device ? this.deviceHtml(ctx, json.device, json.vocabulary)
        : kit.warn('There is no such device in this realm.');
    }
    return this.listHtml(ctx, json);
  }

  static deviceHtml(ctx: Json, d: Json, vocabulary: Json): string {
    const t = kitEscaping(ctx.t);
    const esc = kit.esc.bind(kit);
    const canWrite = ctx.write;
    // A HOT PATH: once per field of every form on the page, so no
    // Entering/Leaving pair — it would drown the log.
    const hidden = function (name: string, value: string): string {
      return '<input type="hidden" name="' + name + '" value="' + esc(value) +
        '">';
    };
    // The words of a change are messages; the punctuation that joins the
    // optional actor and reason stays in the code, as it was.
    const change = function (c: Json): string {
      return c ? t.html('consoleDevices.deviceHtml.change',
                        { status: c.status, previous: c.previous,
                          at: c.at }) +
        (c.source ? t.html('consoleDevices.deviceHtml.by',
                           { who: c.source }) : '') +
        (c.actor ? ', ' + esc(c.actor) : '') +
        (c.reason ? ': ' + esc(c.reason) : '')
        : t.html('consoleDevices.deviceHtml.neverChanged');
    };
    const facts = '<table class="grid"><tbody>' +
      '<tr><th>' + t.html('consoleDevices.deviceHtml.thId') +
      '</th><td><code>' + esc(d.id) + '</code><br><small><code>' +
      esc(d.dn) + '</code></small></td></tr>' +
      '<tr><th>' + t.html('consoleDevices.deviceHtml.thOwner') + '</th><td>' +
      this.ownerCell(t, d) + '</td></tr>' +
      '<tr><th>' + t.html('consoleDevices.deviceHtml.thPlatform') +
      '</th><td>' +
      esc([d.platform, d.model, d.os].filter(Boolean).join(' · ') || '—') +
      '</td></tr>' +
      '<tr><th>' + t.html('consoleDevices.deviceHtml.thEnrolled') +
      '</th><td>' + esc(d.enrolment.method) +
      (d.enrolment.at ? t.html('consoleDevices.deviceHtml.at',
                               { at: d.enrolment.at }) : '') +
      (d.enrolment.actor ? t.html('consoleDevices.deviceHtml.by',
                                  { who: d.enrolment.actor }) : '') +
      '</td></tr>' +
      '<tr><th>' + t.html('consoleDevices.deviceHtml.thAttestation') +
      '</th><td><strong>' + esc(d.attestation.level) +
      '</strong>' + (d.attestation.level === 'attested'
        ? ' — ' + esc(d.attestation.format) + ': ' +
          esc(d.attestation.summary)
        : t.html('consoleDevices.deviceHtml.notVerified')) + '</td></tr>' +
      '<tr><th>' + t.html('consoleDevices.deviceHtml.thCompliance') +
      '</th><td><strong>' + esc(d.compliance) +
      '</strong><br><small>' + change(d.complianceChange) +
      '</small></td></tr>' +
      '<tr><th>' + t.html('consoleDevices.deviceHtml.thStatus') +
      '</th><td>' + esc(d.status) + '<br><small>' +
      change(d.statusChange) + '</small></td></tr>' +
      '<tr><th>' + t.html('consoleDevices.deviceHtml.thRisk') + '</th><td>' +
      esc(d.riskLevel) + (d.riskChange
        ? '<br><small>' + t.html('consoleDevices.deviceHtml.riskChange', {
            level: d.riskChange.level ||
                   t.text('consoleDevices.deviceHtml.unassessed'),
            previous: d.riskChange.previous ||
                      t.text('consoleDevices.deviceHtml.unassessed'),
            at: d.riskChange.at, who: d.riskChange.source }) +
          (d.riskChange.reason ? ': ' + esc(d.riskChange.reason) : '') +
          '</small>' : '') + '</td></tr>' +
      '<tr><th>' + t.html('consoleDevices.deviceHtml.thNativeSso') +
      '</th><td>' + (d.nativeSso ? (d.sessionLive
        ? t.html('consoleDevices.deviceHtml.ssoLive')
        : t.html('consoleDevices.deviceHtml.ssoEnded'))
        : t.html('consoleDevices.deviceHtml.ssoNone')) +
      '</td></tr>' +
      '<tr><th>' + t.html('consoleDevices.deviceHtml.thLastUsed') +
      '</th><td>' + esc(d.lastUsed || '—') + '</td></tr>' +
      '</tbody></table>';
    const apps = '<h2>' + t.html('consoleDevices.deviceHtml.appsHeading') +
      '</h2>' +
      (d.applications.length ? '<ul>' + d.applications.map(
        function (dn: string, i: number): string {
          const name = d.applicationNames[i];
          return '<li>' + (name ? '<a href="/admin/applications?' +
            'application=' + encodeURIComponent(name) + '">' + esc(name) +
            '</a> ' : '') + '<small><code>' + esc(dn) + '</code></small></li>';
        }).join('') + '</ul>'
        : kit.note(t.html('consoleDevices.deviceHtml.none')));
    const keyRows = d.keys.map(function (k: Json): string {
      return '<tr><td>' + esc(k.label) + '<br><small><code>' + esc(k.id) +
        '</code></small></td><td>' + esc(k.kind) + '</td><td><small><code>' +
        esc(k.thumbprint) + '</code></small></td><td>' + esc(k.proof) +
        '</td><td>' + esc(k.attestation.level) +
        (k.attestation.format !== 'none' ? '<br><small>' +
          esc(k.attestation.format) + '</small>' : '') +
        (k.attestation.summary ? '<br><small>' +
          esc(k.attestation.summary) + '</small>' : '') +
        (k.attestation.verifiedAt ? '<br><small>' +
          t.html('consoleDevices.deviceHtml.verifiedAt',
                 { at: k.attestation.verifiedAt }) + '</small>' : '') +
        '</td><td><small>' +
        esc(k.added) + (k.addedBy
          ? t.html('consoleDevices.deviceHtml.by', { who: k.addedBy }) : '') +
        '</small></td><td>' + (canWrite
          ? '<form method="post" action="' + LIST + '" class="inline">' +
            hidden('action', 'remove-key') + hidden('id', d.id) +
            hidden('key', k.id) + '<button type="submit" class="danger">' +
            t.html('consoleDevices.deviceHtml.remove') + '</button></form>'
          : '') + '</td></tr>';
    }).join('');
    const keys = '<h2>' + t.html('consoleDevices.deviceHtml.keysHeading') +
      '</h2>' + kit.note(t.html('consoleDevices.deviceHtml.keysNote')) +
      (keyRows
        ? '<table class="grid"><thead><tr><th>' +
          t.html('consoleDevices.deviceHtml.thKey') + '</th><th>' +
          t.html('consoleDevices.deviceHtml.thKind') + '</th>' +
          '<th>' + t.html('consoleDevices.deviceHtml.thThumbprint') +
          '</th><th>' + t.html('consoleDevices.deviceHtml.thProof') +
          '</th><th>' + t.html('consoleDevices.deviceHtml.thAttestation') +
          '</th><th>' + t.html('consoleDevices.deviceHtml.thAdded') +
          '</th><th></th></tr></thead><tbody>' + keyRows + '</tbody></table>'
        : kit.note(t.html('consoleDevices.deviceHtml.none')));
    const v = { platforms: vocabulary.platforms };
    const compliance = '<h2>' +
      t.html('consoleDevices.deviceHtml.complianceHeading') + '</h2>' +
      kit.note(t.html('consoleDevices.deviceHtml.complianceNote')) +
      '<form method="post" action="' + LIST + '">' +
      hidden('action', 'set-compliance') + hidden('id', d.id) +
      '<div class="formrow"><label for="dev-c-status">' +
      t.html('consoleDevices.deviceHtml.thCompliance') + '</label>' +
      '<select id="dev-c-status" name="status">' +
      this.options(vocabulary.compliance, d.compliance, null) +
      '</select><label for="dev-c-reason">' +
      t.html('consoleDevices.deviceHtml.reason') + '</label><input ' +
      'type="text" ' +
      'id="dev-c-reason" name="reason" size="40" maxlength="500"></div>' +
      '<div class="formrow"><button type="submit">' +
      t.html('consoleDevices.deviceHtml.setCompliance') + '</button>' +
      '</div></form>';
    const status = '<h2>' +
      t.html('consoleDevices.deviceHtml.compromiseHeading') + '</h2>' +
      (d.status === 'compromised'
      ? kit.note(t.html('consoleDevices.deviceHtml.compromisedNote')) +
        '<form method="post" action="' + LIST + '">' +
        hidden('action', 'set-status') + hidden('id', d.id) +
        hidden('status', 'active') + '<div class="formrow"><label ' +
        'for="dev-s-reason">' + t.html('consoleDevices.deviceHtml.reason') +
        '</label><input type="text" ' +
        'id="dev-s-reason" name="reason" size="40" maxlength="500">' +
        '<button type="submit">' +
        t.html('consoleDevices.deviceHtml.restore') + '</button></div></form>'
      : kit.note(t.html('consoleDevices.deviceHtml.markNote')) +
        '<form method="post" action="' + LIST + '">' +
        hidden('action', 'set-status') + hidden('id', d.id) +
        hidden('status', 'compromised') + '<div class="formrow"><label ' +
        'for="dev-s-reason">' + t.html('consoleDevices.deviceHtml.reason') +
        '</label><input type="text" ' +
        'id="dev-s-reason" name="reason" size="40" maxlength="500">' +
        '<button type="submit" class="danger">' +
        t.html('consoleDevices.deviceHtml.markCompromised') + '</button>' +
        '</div></form>');
    const forms = canWrite
      ? compliance + status +
        '<h2>' + t.html('consoleDevices.deviceHtml.addKeyHeading') +
        '</h2>' + kit.note(t.html('consoleDevices.deviceHtml.addKeyNote')) +
        '<form method="post" action="' + LIST + '">' +
        hidden('action', 'add-key') + hidden('id', d.id) +
        '<div class="formrow"><label for="dev-k-kind">' +
        t.html('consoleDevices.deviceHtml.thKind') + '</label>' +
        '<select id="dev-k-kind" name="kind">' +
        this.options(['x509', 'jwk', 'webauthn'], 'jwk', null) +
        '</select><label for="dev-k-label">' +
        t.html('consoleDevices.deviceHtml.label') + '</label><input ' +
        'type="text" id="dev-k-label" name="label" size="24" ' +
        'maxlength="128"></div><div class="formrow"><textarea ' +
        'id="dev-k-value" name="value" rows="4" cols="70" required ' +
        'placeholder="' + esc(t.text('consoleDevices.listHtml.keyHint')) +
        '"></textarea></div>' +
        '<div class="formrow"><button type="submit">' +
        t.html('consoleDevices.deviceHtml.addKey') + '</button>' +
        '</div></form>' +
        '<h2>' + t.html('consoleDevices.deviceHtml.editHeading') + '</h2>' +
        kit.note(t.html('consoleDevices.deviceHtml.editNote')) +
        '<form method="post" action="' + LIST + '">' +
        hidden('action', 'update') + hidden('id', d.id) +
        '<div class="formrow"><label for="dev-e-label">' +
        t.html('consoleDevices.deviceHtml.label') + '</label>' +
        '<input type="text" id="dev-e-label" name="label" size="30" ' +
        'maxlength="128" value="' + esc(d.label) + '"></div>' +
        '<div class="formrow"><label for="dev-e-ok">' +
        t.html('consoleDevices.listHtml.ownerKind') + '</label>' +
        '<select id="dev-e-ok" name="ownerKind">' +
        this.options(vocabulary.ownerKinds, d.ownerKind, null) +
        '</select><label for="dev-e-owner">' +
        t.html('consoleDevices.listHtml.owner') + '</label><input ' +
        'type="text" ' +
        'id="dev-e-owner" name="owner" size="24" value="' +
        esc(d.ownerName) + '"></div>' +
        '<div class="formrow"><label for="dev-e-p">' +
        t.html('consoleDevices.listHtml.platform') + '</label>' +
        '<select id="dev-e-p" name="platform">' +
        this.options(v.platforms, d.platform,
                     t.text('consoleDevices.listHtml.unstated')) +
        '</select>' +
        '<label for="dev-e-m">' + t.html('consoleDevices.listHtml.model') +
        '</label><input type="text" ' +
        'id="dev-e-m" name="model" size="20" maxlength="128" value="' +
        esc(d.model) + '"><label for="dev-e-os">' +
        t.html('consoleDevices.listHtml.os') + '</label><input ' +
        'type="text" id="dev-e-os" name="os" size="16" maxlength="128" ' +
        'value="' + esc(d.os) + '"></div>' +
        '<div class="formrow"><label for="dev-e-apps">' +
        t.html('consoleDevices.listHtml.applications') + '</label>' +
        '<input type="text" id="dev-e-apps" name="applications" size="40" ' +
        'value="' + esc(d.applicationNames.filter(Boolean).join(', ')) +
        '"></div><div class="formrow"><button type="submit">' +
        t.html('consoleDevices.deviceHtml.save') + '</button>' +
        '</div></form>' +
        '<h2>' + t.html('consoleDevices.deviceHtml.remove') + '</h2>' +
        kit.note(t.html('consoleDevices.deviceHtml.removeNote')) +
        '<form method="post" action="' + LIST + '">' +
        hidden('action', 'remove') + hidden('id', d.id) +
        '<button type="submit" class="danger">' +
        t.html('consoleDevices.deviceHtml.removeDevice') + '</button>' +
        '</form>'
      : kit.note(t.html('consoleDevices.deviceHtml.readOnly'));
    return facts + apps + keys + forms;
  }

  /**
   * Draws the state of Google's Android attestation status list (#256).
   *
   * @param t - the page's translator
   * @param status - the view's `androidStatus`
   * @returns the section as HTML
   */
  static androidStatusHtml(t: Json, status: Json): string {
    const s = status || {};
    // The Risk link carries an href, so the note is two messages around it;
    // where the list comes from is a `select`, so it stays one sentence.
    return '<h2>' + t.html('consoleDevices.androidStatusHtml.heading') +
      '</h2>' +
      kit.note(t.html('consoleDevices.androidStatusHtml.noteBefore') +
        '<a href="/admin/risk">' +
        t.html('consoleDevices.androidStatusHtml.risk') + '</a>' +
        t.html('consoleDevices.androidStatusHtml.noteAfter', {
          job: s.job || 'devices.android-status-refresh',
          from: s.url ? 'url' : 'nowhere', url: s.url || '' })) +
      '<table class="key"><tr><th>' +
      t.html('consoleDevices.androidStatusHtml.activeList') + '</th><td>' +
      (s.active
        ? t.html('consoleDevices.androidStatusHtml.active', {
            name: s.active, rows: String(s.rows || 0),
            loaded: s.loadedAt ? new Date(s.loadedAt).toISOString() : '?' }) +
          (s.stale ? ' — <strong class="state-expired">' +
                     t.html('consoleDevices.androidStatusHtml.stale') +
                     '</strong>' +
                     t.html('consoleDevices.androidStatusHtml.olderThan',
                            { hours: String(s.staleAfterHours) }) : '')
        : '<span class="state-none">' +
          t.html('consoleDevices.androidStatusHtml.noList') + '</span>') +
      '</td></tr><tr><th>' +
      t.html('consoleDevices.androidStatusHtml.unchecked') + '</th><td>' +
      (s.required ? t.html('consoleDevices.androidStatusHtml.notAttested')
                  : t.html('consoleDevices.androidStatusHtml.stillAttested')) +
      '</td></tr></table>';
  }

  // Called by `web_pages.ts`, whose page table hands it the view and, once
  // it passes one, the context (#539): without it the words are the
  // default translator's.
  /**
   * Draws Protocols → Device registration.
   *
   * @param json - the view `GET /admin-api/device-registration` answers
   * @param ctx - optional; the render context
   * @returns the body as HTML
   */
  static registrationHtml(json: Json, ctx?: Json): string {
    const t = kitEscaping((ctx || kit.context()).t);
    const esc = kit.esc.bind(kit);
    const state = function (built: boolean): string {
      return built
        ? '<span class="state-valid">' +
          t.html('consoleDevices.registrationHtml.built') + '</span>'
        : '<span class="state-none">' +
          t.html('consoleDevices.registrationHtml.notBuilt') + '</span>';
    };
    return kit.note(t.html('consoleDevices.registrationHtml.leadBefore') +
        '<a href="' + LIST + '">' +
        t.html('consoleDevices.registrationHtml.devices') + '</a>' +
        t.html('consoleDevices.registrationHtml.leadAfter'),
        t.text('consoleDevices.listHtml.whatThisIs')) +
      '<h2>' + t.html('consoleDevices.registrationHtml.registeredHeading') +
      '</h2><table class="grid"><thead><tr>' +
      '<th>' + t.html('consoleDevices.registrationHtml.thMethod') +
      '</th><th>' + t.html('consoleDevices.registrationHtml.thState') +
      '</th><th>' + t.html('consoleDevices.registrationHtml.thWhat') +
      '</th></tr></thead>' +
      '<tbody>' + json.enrolment.map(function (r: Json): string {
        return '<tr><td><code>' + esc(r.method) + '</code></td><td>' +
          state(r.built) + '</td><td>' + esc(r.what) + '</td></tr>';
      }).join('') + '</tbody></table>' +
      '<h2>' + t.html('consoleDevices.registrationHtml.recognisedHeading') +
      '</h2><table class="grid"><thead><tr>' +
      '<th>' + t.html('consoleDevices.deviceHtml.thKey') + '</th><th>' +
      t.html('consoleDevices.registrationHtml.thState') + '</th><th>' +
      t.html('consoleDevices.registrationHtml.thMatched') +
      '</th></tr></thead>' +
      '<tbody>' + json.recognition.map(function (r: Json): string {
        return '<tr><td><code>' + esc(r.kind) + '</code></td><td>' +
          state(r.built) + '</td><td>' + esc(r.what) + '</td></tr>';
      }).join('') + '</tbody></table>' +
      '<h2>' + t.html('consoleDevices.deviceHtml.thAttestation') + '</h2>' +
      kit.note(t.html('consoleDevices.registrationHtml.attestationNote',
                      { formats: json.attestationFormats.join(', ') }) +
        (json.unattestedKeys.accepted
          ? t.html('consoleDevices.registrationHtml.selfAssertedAccepted')
          : t.html('consoleDevices.registrationHtml.selfAssertedRefused')) +
        ' ' + esc(json.unattestedKeys.adminKeys) + '. ' +
        (json.freshKeyAttestation
          ? (json.freshKeyAttestation.required
            ? t.html('consoleDevices.registrationHtml.freshRequired',
                     { nonce: json.freshKeyAttestation.nonce })
            : t.html('consoleDevices.registrationHtml.freshUnproven',
                     { nonce: json.freshKeyAttestation.nonce })) +
            esc(json.freshKeyAttestation.scep) + '.'
          : '')) +
      '<table class="grid"><thead><tr><th>' +
      t.html('consoleDevices.registrationHtml.thStatement') + '</th><th>' +
      t.html('consoleDevices.registrationHtml.thAnchors') + '</th>' +
      '<th>' + t.html('consoleDevices.registrationHtml.thSetting') +
      '</th><th>' + t.html('consoleDevices.registrationHtml.thShipped') +
      '</th></tr></thead><tbody>' +
      json.trustAnchors.map(function (r: Json): string {
        return '<tr><td><code>' + esc(r.kind) + '</code></td><td>' +
          esc(r.count === null ? r.source : r.count + ' (' + r.source +
                                           ')') +
          '</td><td><code>' + esc(r.setting) + '</code></td><td>' +
          (r.shipped.length ? r.shipped.map(function (a: Json): string {
            return esc(a.subject) +
              t.html('consoleDevices.registrationHtml.until',
                     { date: a.notAfter }) +
              '<br><small>SHA-256 <code>' + esc(a.sha256) + '</code>' +
              (a.used ? ''
                      : ' <strong>' +
                        t.html('consoleDevices.registrationHtml.pinMismatch') +
                        '</strong>') +
              '</small>';
          }).join('<br>') : '—') + '</td></tr>';
      }).join('') + '</tbody></table>' +
      // GOOGLE'S ANDROID ATTESTATION STATUS LIST (#256).
      DevicesPage.androidStatusHtml(t, json.androidStatus) +
      '<h2>' + t.html('consoleDevices.registrationHtml.challengesHeading') +
      '</h2>' +
      kit.note(t.html('consoleDevices.registrationHtml.challengesNote', {
        store: json.challenges.store,
        ttl: String(json.challenges.ttlSeconds),
        live: String(json.challenges.live),
        max: String(json.challenges.max) })) +
      '<h2>' + t.html('consoleDevices.registrationHtml.recordedHeading') +
      '</h2>' +
      kit.note(t.html('consoleDevices.registrationHtml.recordedNote', {
        signIn: json.recordedAt.signIn,
        token: json.recordedAt.tokenEndpoint })) +
      '<h2>' + t.html('consoleDevices.deviceHtml.complianceHeading') +
      '</h2>' +
      kit.note(t.html('consoleDevices.registrationHtml.complianceNote',
                      { sources: json.complianceSources.join(', ') })) +
      '<table class="grid"><thead><tr><th>' +
      t.html('consoleDevices.registrationHtml.thDoor') + '</th><th>' +
      t.html('consoleDevices.registrationHtml.thState') + '</th>' +
      '<th>' + t.html('consoleDevices.registrationHtml.thHow') +
      '</th></tr></thead><tbody>' +
      // The rows' links carry hrefs: the words around each are messages.
      '<tr><td>' + t.html('consoleDevices.registrationHtml.doorAdmin') +
      '</td><td>' + state(true) + '</td><td>' +
      t.html('consoleDevices.registrationHtml.adminBefore') +
      '<a href="' + LIST + '">' +
      t.html('consoleDevices.registrationHtml.devices') + '</a>' +
      t.html('consoleDevices.registrationHtml.adminAfter') + '</td></tr>' +
      '<tr><td>' + t.html('consoleDevices.registrationHtml.doorMdm') +
      '</td><td>' + state(true) + '</td><td>' +
      t.html('consoleDevices.registrationHtml.mdmHow', {
        path: json.mdmFeed.path, scope: json.mdmFeed.scope,
        max: String(json.mdmFeed.maxReports),
        by: json.mdmFeed.identifiedBy.join(', ') }) + '</td></tr>' +
      '<tr><td>' + t.html('consoleDevices.registrationHtml.doorTest') +
      '</td><td>' + (json.testControl.open
        ? '<span class="state-valid">' +
          t.html('consoleDevices.registrationHtml.testOpen') + '</span>'
        : '<span class="state-none">' +
          t.html('consoleDevices.registrationHtml.testRefused') +
          '</span>') +
      '</td><td>' + t.html('consoleDevices.registrationHtml.testHow',
                           { path: json.testControl.path }) + '</td></tr>' +
      '<tr><td>' + t.html('consoleDevices.registrationHtml.doorCaep') +
      '</td><td>' +
      state(true) + '</td><td>' +
      t.html('consoleDevices.registrationHtml.caepBefore') +
      '<a href="/admin/federation">' +
      t.html('consoleDevices.registrationHtml.federation') + '</a>' +
      t.html('consoleDevices.registrationHtml.caepMiddle') +
      '<a href="/admin/ssf/transmitters">' +
      t.html('consoleDevices.registrationHtml.partners') + '</a>' +
      t.html('consoleDevices.registrationHtml.caepAfter') +
      '</td></tr></tbody></table>' +
      '<h2>' + t.html('consoleDevices.registrationHtml.signalsHeading') +
      '</h2>' +
      kit.note(t.html('consoleDevices.registrationHtml.signalsNote', {
        caep: json.signals.caep.join('; '),
        risc: json.signals.risc.join(' and '),
        subject: json.signals.subject })) +
      '<h2>' + t.html('consoleDevices.registrationHtml.decidesHeading') +
      '</h2>' +
      // Every choice in the sentence is a `select`, so a translator sees
      // the whole of it.
      kit.note(t.html('consoleDevices.registrationHtml.decidesNote', {
        signals: json.decisions.riskSignals.join(', '),
        expect: json.decisions.expectRegistered ? 'yes' : 'no',
        policy: json.decisions.policy,
        refuse: json.decisions.refuseCompromised ? 'yes' : 'no',
        require: json.decisions.requireCompliantDevice
          ? (json.decisions.compliantDeviceAttested ? 'attested' : 'yes')
          : 'no',
        acr: json.decisions.acr, claim: json.decisions.claim })) +
      '<h2>' + t.html('consoleDevices.registrationHtml.settings') + '</h2>' +
      SettingsForms.forms(json.settings, REGISTRATION, undefined, t);
  }

  // Called by `web_pages.ts` like registrationHtml(), and for the same
  // reason takes an optional context.
  /**
   * Draws Monitoring → Devices.
   *
   * @param json - the view `GET /admin-api/devices/monitor` answers
   * @param ctx - optional; the render context
   * @returns the body as HTML
   */
  static monitorHtml(json: Json, ctx?: Json): string {
    const t = kitEscaping((ctx || kit.context()).t);
    const esc = kit.esc.bind(kit);
    const c = json.counts;
    // A table's title arrives translated, as text the kit escapes.
    const table = function (title: string, counts: Json): string {
      return '<h2>' + esc(title) + '</h2><table class="grid"><tbody>' +
        Object.keys(counts).map(function (k) {
          return '<tr><th>' + esc(k) + '</th><td>' + esc(String(counts[k])) +
            '</td></tr>';
        }).join('') + '</tbody></table>';
    };
    // The timeline was `t` until #539 made `t` the translator.
    const tl = json.timeline;
    const sources: string[] = json.complianceSources;
    return '<div class="tiles">' +
      kit.tile(String(c.total), t.text('consoleDevices.monitorHtml.devices')) +
      kit.tile(String(c.keys), t.text('consoleDevices.monitorHtml.keys')) +
      kit.tile(String(c.nativeSso.live),
               t.text('consoleDevices.monitorHtml.liveSso')) +
      kit.tile(String(tl.totals.created),
               t.text('consoleDevices.monitorHtml.registered')) +
      kit.tile(String(tl.totals.removed),
               t.text('consoleDevices.monitorHtml.removed')) +
      kit.tile(String(tl.totals.evicted),
               t.text('consoleDevices.monitorHtml.evicted')) + '</div>' +
      kit.note(t.html('consoleDevices.monitorHtml.leadBefore') +
        (tl.since ? t.html('consoleDevices.monitorHtml.since',
                           { since: tl.since }) : '') +
        t.html('consoleDevices.monitorHtml.leadAfter'),
        t.text('consoleDevices.listHtml.whatThisIs')) +
      table(t.text('consoleDevices.monitorHtml.byOwner'), c.byOwnerKind) +
      table(t.text('consoleDevices.monitorHtml.byCompliance'),
            c.byCompliance) +
      table(t.text('consoleDevices.monitorHtml.byRisk'),
            c.byRiskLevel || {}) +
      table(t.text('consoleDevices.monitorHtml.changesBySource'),
            tl.totals.compliance || {}) +
      table(t.text('consoleDevices.monitorHtml.byAttestation'),
            c.byAttestation) +
      table(t.text('consoleDevices.monitorHtml.byKey'), c.byKeyKind) +
      table(t.text('consoleDevices.monitorHtml.byEnrolment'),
            c.byEnrolment) +
      table(t.text('consoleDevices.monitorHtml.nativeSso'), c.nativeSso) +
      table(t.text('consoleDevices.monitorHtml.keysByFormat'),
            c.byKeyAttestationFormat || {}) +
      kit.note(t.html('consoleDevices.monitorHtml.countersNote',
                      { scope: json.activity.scope }),
               t.text('consoleDevices.monitorHtml.countersLabel')) +
      table(t.text('consoleDevices.monitorHtml.recognitions'),
            json.activity.recognitions) +
      table(t.text('consoleDevices.monitorHtml.enrolments'),
            json.activity.enrolments) +
      table(t.text('consoleDevices.monitorHtml.enrolledByLevel'),
            json.activity.attestationLevels) +
      table(t.text('consoleDevices.monitorHtml.enrolledByFormat'),
            json.activity.attestationFormats) +
      table(t.text('consoleDevices.monitorHtml.refused'),
            json.activity.attestationRefusals) +
      '<h2>' + t.html('consoleDevices.monitorHtml.lastDays',
                      { days: String(tl.days) }) + '</h2>' +
      '<table class="grid"><thead><tr><th>' +
      t.html('consoleDevices.monitorHtml.thDay') + '</th><th>' +
      t.html('consoleDevices.monitorHtml.thRegistered') +
      '</th><th>' + t.html('consoleDevices.monitorHtml.thRemoved') +
      '</th><th>' + t.html('consoleDevices.monitorHtml.thEvicted') + '</th>' +
      sources.map(function (src: string): string {
        return '<th>' + t.html('consoleDevices.monitorHtml.thCompliance',
                               { source: src }) + '</th>';
      }).join('') + '</tr></thead><tbody>' +
      tl.rows.slice(0).reverse().map(function (r: Json): string {
        return '<tr><td>' + esc(r.day) + '</td><td>' + r.created +
          '</td><td>' + r.removed + '</td><td>' + r.evicted + '</td>' +
          sources.map(function (src: string): string {
            return '<td>' + esc(String((r.compliance || {})[src] || 0)) +
              '</td>';
          }).join('') + '</tr>';
      }).join('') + '</tbody></table>';
  }
}

export = DevicesPage;
