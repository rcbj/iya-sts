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

  static ownerCell(r: Json): string {
    const esc = kit.esc.bind(kit);
    const link = r.ownerKind === 'application'
      ? '/admin/applications?application=' + encodeURIComponent(r.ownerName)
      : '/admin/users?user=' + encodeURIComponent(r.ownerName);
    return esc(r.ownerKind) + ' ' + (r.ownerFound
      ? '<a href="' + link + '">' + esc(r.ownerName) + '</a>'
      : '<em>not in the directory</em>') + '<br><small><code>' +
      esc(r.owner) + '</code></small>';
  }

  static listHtml(ctx: Json, json: Json): string {
    const self = this;
    const esc = kit.esc.bind(kit);
    const f = json.filter;
    const v = json.vocabulary;
    const filters = '<form method="get" action="' + LIST + '"><div ' +
      'class="formrow"><label for="dev-q">Search</label><input type="text" ' +
      'id="dev-q" name="q" size="24" value="' + esc(f.q || '') +
      '" placeholder="id, label, owner, thumbprint">' +
      '<label for="dev-ok">Owner</label><select id="dev-ok" ' +
      'name="ownerKind">' + this.options(v.ownerKinds, f.ownerKind, 'any') +
      '</select><label for="dev-c">Compliance</label><select id="dev-c" ' +
      'name="compliance">' + this.options(v.compliance, f.compliance, 'any') +
      '</select><label for="dev-a">Attestation</label><select id="dev-a" ' +
      'name="attestation">' + this.options(v.attestation, f.attestation,
                                           'any') +
      '</select><label for="dev-k">Key</label><select id="dev-k" ' +
      'name="keyKind">' + this.options(v.keyKinds, f.keyKind, 'any') +
      '</select><label for="dev-per">Show</label><select id="dev-per" ' +
      'name="per">' + kit.perPageOptions(json.perPage) + '</select>' +
      '<button type="submit">Filter</button>' +
      (Object.keys(f).length ? ' <a href="' + LIST + '">clear</a>' : '') +
      '</div></form>';
    const nav = kit.pageNavPair(LIST, Object.assign({}, f,
      ctx.query && ctx.query.per ? { per: String(json.perPage) } : {}),
      json.devicesPaging);
    const rows = json.devices.map(function (r: Json): string {
      return '<tr><td><a href="' + LIST + '?device=' +
        encodeURIComponent(r.id) + '">' + esc(r.label) + '</a><br><small>' +
        '<code>' + esc(r.id) + '</code></small></td><td>' +
        self.ownerCell(r) + '</td><td>' + (r.keyKinds.length
          ? esc(r.keyKinds.join(', ')) : '—') + '</td><td>' +
        esc(r.attestation.level) + '</td><td>' + esc(r.compliance) +
        (r.status === 'compromised' ? ' <strong>compromised</strong>' : '') +
        '</td><td>' + (r.nativeSso ? (r.sessionLive ? 'live'
                                                    : 'session ended')
                                   : '—') + '</td><td><small>' +
        esc(r.lastUsed || '—') + '</small></td></tr>';
    }).join('');
    const canWrite = ctx.write;
    const create = canWrite ? '<h2>Register a device</h2>' +
      kit.note('Owned by ONE person (a username) or ONE application (its ' +
                 'identifier). A key typed here is public material — a PEM ' +
                 'certificate, a public JWK, or the credential id of a ' +
                 'security key the owner enrolled — and is recorded as ' +
                 'proven by nobody and <strong>self-asserted</strong>. A ' +
                 'person at <code>devices.maxPerPerson</code> is refused ' +
                 'rather than losing a device to make room.') +
      '<form method="post" action="' + LIST + '">' +
      '<input type="hidden" name="action" value="create">' +
      '<div class="formrow"><label for="dev-n-label">Label</label>' +
      '<input type="text" id="dev-n-label" name="label" size="30" ' +
      'maxlength="128"></div>' +
      '<div class="formrow"><label for="dev-n-ok">Owner kind</label>' +
      '<select id="dev-n-ok" name="ownerKind">' +
      this.options(v.ownerKinds, 'person', null) + '</select>' +
      '<label for="dev-n-owner">Owner</label><input type="text" ' +
      'id="dev-n-owner" name="owner" size="24" required></div>' +
      '<div class="formrow"><label for="dev-n-p">Platform</label>' +
      '<select id="dev-n-p" name="platform">' +
      this.options(v.platforms, '', 'unstated') + '</select>' +
      '<label for="dev-n-m">Model</label><input type="text" id="dev-n-m" ' +
      'name="model" size="20" maxlength="128"><label for="dev-n-os">OS' +
      '</label><input type="text" id="dev-n-os" name="os" size="16" ' +
      'maxlength="128"></div>' +
      '<div class="formrow"><label for="dev-n-apps">Applications</label>' +
      '<input type="text" id="dev-n-apps" name="applications" size="40" ' +
      'placeholder="client ids or identifiers, comma separated"></div>' +
      '<div class="formrow"><label for="dev-n-kk">First key</label>' +
      '<select id="dev-n-kk" name="keyKind">' +
      this.options(['x509', 'jwk', 'webauthn'], '', 'none') + '</select>' +
      '<textarea id="dev-n-key" name="key" rows="3" cols="60" ' +
      'placeholder="PEM, JWK JSON or credential id"></textarea></div>' +
      '<div class="formrow"><button type="submit">Register</button></div>' +
      '</form>'
      : kit.note('Registering, editing or removing a device needs ' +
                   '<strong>Admin Write</strong>.');
    return '<div class="tiles">' + kit.tile(String(json.total), 'devices') +
      kit.tile(String(json.matched), 'matched') + '</div>' +
      kit.note('Every device this realm knows, each an entry under ' +
                 '<code>ou=devices</code> owned by one person or one ' +
                 'application. <a href="' + MONITOR + '">Monitoring &rarr; ' +
                 'Devices</a> counts them; <a href="/admin/ldap/devices">' +
                 'Device entries</a> is the same register attribute by ' +
                 'attribute; <a href="' + REGISTRATION + '">Device ' +
                 'registration</a> is how one arrives.', 'What this page is') +
      filters + nav.head + '<table class="grid"><thead><tr><th>Device</th>' +
      '<th>Owner</th><th>Keys</th><th>Attestation</th><th>Compliance</th>' +
      '<th>Native SSO</th><th>Last used</th></tr></thead><tbody>' +
      (rows || '<tr><td colspan="7">' + (Object.keys(f).length
        ? 'No device matches. The filter above may be hiding some.'
        : 'None yet.') + '</td></tr>') + '</tbody></table>' + nav.foot +
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
    const esc = kit.esc.bind(kit);
    const canWrite = ctx.write;
    // A HOT PATH: once per field of every form on the page, so no
    // Entering/Leaving pair — it would drown the log.
    const hidden = function (name: string, value: string): string {
      return '<input type="hidden" name="' + name + '" value="' + esc(value) +
        '">';
    };
    const change = function (c: Json): string {
      return c ? esc(c.status) + ' (was ' + esc(c.previous) + ') at ' +
        esc(c.at) + (c.source ? ' by ' + esc(c.source) : '') +
        (c.actor ? ', ' + esc(c.actor) : '') +
        (c.reason ? ': ' + esc(c.reason) : '') : 'never changed';
    };
    const facts = '<table class="grid"><tbody>' +
      '<tr><th>Id</th><td><code>' + esc(d.id) + '</code><br><small><code>' +
      esc(d.dn) + '</code></small></td></tr>' +
      '<tr><th>Owner</th><td>' + this.ownerCell(d) + '</td></tr>' +
      '<tr><th>Platform, model, OS</th><td>' +
      esc([d.platform, d.model, d.os].filter(Boolean).join(' · ') || '—') +
      '</td></tr>' +
      '<tr><th>Enrolled</th><td>' + esc(d.enrolment.method) +
      (d.enrolment.at ? ' at ' + esc(d.enrolment.at) : '') +
      (d.enrolment.actor ? ' by ' + esc(d.enrolment.actor) : '') +
      '</td></tr>' +
      '<tr><th>Attestation</th><td><strong>' + esc(d.attestation.level) +
      '</strong>' + (d.attestation.level === 'attested'
        ? ' — ' + esc(d.attestation.format) + ': ' +
          esc(d.attestation.summary)
        : ' — no key\'s attestation was verified') + '</td></tr>' +
      '<tr><th>Compliance</th><td><strong>' + esc(d.compliance) +
      '</strong><br><small>' + change(d.complianceChange) +
      '</small></td></tr>' +
      '<tr><th>Status</th><td>' + esc(d.status) + '<br><small>' +
      change(d.statusChange) + '</small></td></tr>' +
      '<tr><th>Risk level</th><td>' + esc(d.riskLevel) + (d.riskChange
        ? '<br><small>' + esc(d.riskChange.level || 'unassessed') +
          ' (was ' + esc(d.riskChange.previous || 'unassessed') + ') at ' +
          esc(d.riskChange.at) + ' by ' + esc(d.riskChange.source) +
          (d.riskChange.reason ? ': ' + esc(d.riskChange.reason) : '') +
          '</small>' : '') + '</td></tr>' +
      '<tr><th>Native SSO</th><td>' + (d.nativeSso ? (d.sessionLive
        ? 'a secret, bound to a <strong>live</strong> sign-on session'
        : 'a secret whose sign-on session has ended') : 'no secret') +
      '</td></tr>' +
      '<tr><th>Last used</th><td>' + esc(d.lastUsed || '—') + '</td></tr>' +
      '</tbody></table>';
    const apps = '<h2>Applications that used it</h2>' +
      (d.applications.length ? '<ul>' + d.applications.map(
        function (dn: string, i: number): string {
          const name = d.applicationNames[i];
          return '<li>' + (name ? '<a href="/admin/applications?' +
            'application=' + encodeURIComponent(name) + '">' + esc(name) +
            '</a> ' : '') + '<small><code>' + esc(dn) + '</code></small></li>';
        }).join('') + '</ul>' : kit.note('None.'));
    const keyRows = d.keys.map(function (k: Json): string {
      return '<tr><td>' + esc(k.label) + '<br><small><code>' + esc(k.id) +
        '</code></small></td><td>' + esc(k.kind) + '</td><td><small><code>' +
        esc(k.thumbprint) + '</code></small></td><td>' + esc(k.proof) +
        '</td><td>' + esc(k.attestation.level) +
        (k.attestation.format !== 'none' ? '<br><small>' +
          esc(k.attestation.format) + '</small>' : '') +
        (k.attestation.summary ? '<br><small>' +
          esc(k.attestation.summary) + '</small>' : '') +
        (k.attestation.verifiedAt ? '<br><small>verified ' +
          esc(k.attestation.verifiedAt) + '</small>' : '') +
        '</td><td><small>' +
        esc(k.added) + (k.addedBy ? ' by ' + esc(k.addedBy) : '') +
        '</small></td><td>' + (canWrite
          ? '<form method="post" action="' + LIST + '" class="inline">' +
            hidden('action', 'remove-key') + hidden('id', d.id) +
            hidden('key', k.id) + '<button type="submit" class="danger">' +
            'Remove</button></form>' : '') + '</td></tr>';
    }).join('');
    const keys = '<h2>Keys</h2>' + kit.note('Each is a way the device is ' +
      'recognised. The thumbprint is SHA-256 over the certificate\'s ' +
      'SubjectPublicKeyInfo, or RFC 7638 over the JWK — which is DPoP\'s ' +
      '<code>jkt</code>.') +
      (keyRows ? '<table class="grid"><thead><tr><th>Key</th><th>Kind</th>' +
        '<th>Thumbprint</th><th>Proof</th><th>Attestation</th><th>Added' +
        '</th><th></th></tr></thead><tbody>' + keyRows + '</tbody></table>'
        : kit.note('None.'));
    const v = { platforms: vocabulary.platforms };
    const compliance = '<h2>Compliance</h2>' + kit.note('An ' +
        'administrator\'s vouch, recorded with source <code>admin</code>. ' +
        'A change a receiver can be told — CAEP knows compliant and ' +
        'not-compliant, and unknown is sent as not-compliant — goes out as ' +
        'CAEP device-compliance-change.') +
      '<form method="post" action="' + LIST + '">' +
      hidden('action', 'set-compliance') + hidden('id', d.id) +
      '<div class="formrow"><label for="dev-c-status">Compliance</label>' +
      '<select id="dev-c-status" name="status">' +
      this.options(vocabulary.compliance, d.compliance, null) +
      '</select><label for="dev-c-reason">Reason</label><input type="text" ' +
      'id="dev-c-reason" name="reason" size="40" maxlength="500"></div>' +
      '<div class="formrow"><button type="submit">Set compliance</button>' +
      '</div></form>';
    const status = '<h2>Compromise</h2>' + (d.status === 'compromised'
      ? kit.note('This device is marked <strong>compromised</strong>. ' +
          'Restoring it puts back the risk level the compromise raised; ' +
          'nothing revoked comes back — a certificate is re-issued and a ' +
          'Native SSO secret re-minted at the next sign-in.') +
        '<form method="post" action="' + LIST + '">' +
        hidden('action', 'set-status') + hidden('id', d.id) +
        hidden('status', 'active') + '<div class="formrow"><label ' +
        'for="dev-s-reason">Reason</label><input type="text" ' +
        'id="dev-s-reason" name="reason" size="40" maxlength="500">' +
        '<button type="submit">Restore to active</button></div></form>'
      : kit.note('Marking it compromised ends every sign-on session one ' +
          'of its keys authenticated, revokes its Native SSO secret and ' +
          'every certificate this service\'s EST or SCEP Issuing CA issued ' +
          'it (keyCompromise), raises its risk level to HIGH, and — for a ' +
          'person\'s device — sends RISC credential-compromise and ' +
          'sessions-revoked. It stays in the register, recognised and ' +
          'saying so.') +
        '<form method="post" action="' + LIST + '">' +
        hidden('action', 'set-status') + hidden('id', d.id) +
        hidden('status', 'compromised') + '<div class="formrow"><label ' +
        'for="dev-s-reason">Reason</label><input type="text" ' +
        'id="dev-s-reason" name="reason" size="40" maxlength="500">' +
        '<button type="submit" class="danger">Mark compromised</button>' +
        '</div></form>');
    const forms = canWrite
      ? compliance + status +
        '<h2>Add a key</h2>' + kit.note('Public material only; recorded ' +
          'as proven by nobody and self-asserted.') +
        '<form method="post" action="' + LIST + '">' +
        hidden('action', 'add-key') + hidden('id', d.id) +
        '<div class="formrow"><label for="dev-k-kind">Kind</label>' +
        '<select id="dev-k-kind" name="kind">' +
        this.options(['x509', 'jwk', 'webauthn'], 'jwk', null) +
        '</select><label for="dev-k-label">Label</label><input ' +
        'type="text" id="dev-k-label" name="label" size="24" ' +
        'maxlength="128"></div><div class="formrow"><textarea ' +
        'id="dev-k-value" name="value" rows="4" cols="70" required ' +
        'placeholder="PEM, JWK JSON or credential id"></textarea></div>' +
        '<div class="formrow"><button type="submit">Add the key</button>' +
        '</div></form>' +
        '<h2>Edit</h2>' + kit.note('A new owner takes the device without ' +
          'its Native SSO secret, which was bound to the old owner\'s ' +
          'session; its keys go with it. The applications field replaces ' +
          'the list.') +
        '<form method="post" action="' + LIST + '">' +
        hidden('action', 'update') + hidden('id', d.id) +
        '<div class="formrow"><label for="dev-e-label">Label</label>' +
        '<input type="text" id="dev-e-label" name="label" size="30" ' +
        'maxlength="128" value="' + esc(d.label) + '"></div>' +
        '<div class="formrow"><label for="dev-e-ok">Owner kind</label>' +
        '<select id="dev-e-ok" name="ownerKind">' +
        this.options(vocabulary.ownerKinds, d.ownerKind, null) +
        '</select><label for="dev-e-owner">Owner</label><input type="text" ' +
        'id="dev-e-owner" name="owner" size="24" value="' +
        esc(d.ownerName) + '"></div>' +
        '<div class="formrow"><label for="dev-e-p">Platform</label>' +
        '<select id="dev-e-p" name="platform">' +
        this.options(v.platforms, d.platform, 'unstated') + '</select>' +
        '<label for="dev-e-m">Model</label><input type="text" ' +
        'id="dev-e-m" name="model" size="20" maxlength="128" value="' +
        esc(d.model) + '"><label for="dev-e-os">OS</label><input ' +
        'type="text" id="dev-e-os" name="os" size="16" maxlength="128" ' +
        'value="' + esc(d.os) + '"></div>' +
        '<div class="formrow"><label for="dev-e-apps">Applications</label>' +
        '<input type="text" id="dev-e-apps" name="applications" size="40" ' +
        'value="' + esc(d.applicationNames.filter(Boolean).join(', ')) +
        '"></div><div class="formrow"><button type="submit">Save</button>' +
        '</div></form>' +
        '<h2>Remove</h2>' + kit.note('Removing it revokes the ' +
          'certificates this service issued it (cessationOfOperation, or ' +
          'keyCompromise when it is compromised) and ends the sign-on ' +
          'sessions it authenticated.') +
        '<form method="post" action="' + LIST + '">' +
        hidden('action', 'remove') + hidden('id', d.id) +
        '<button type="submit" class="danger">Remove this device</button>' +
        '</form>'
      : kit.note('Editing needs <strong>Admin Write</strong>.');
    return facts + apps + keys + forms;
  }

  static registrationHtml(json: Json): string {
    const esc = kit.esc.bind(kit);
    const state = function (built: boolean): string {
      return built ? '<span class="state-valid">built</span>'
                   : '<span class="state-none">not built yet</span>';
    };
    return kit.note('A device is an entry under <code>ou=devices</code>, ' +
        'owned by ONE person or ONE application, holding the keys it is ' +
        'recognised by. <a href="' + LIST + '">Devices</a> is the register; ' +
        'this page is how a device gets into it and how it is known again.',
        'What this page is') +
      '<h2>How a device is registered</h2><table class="grid"><thead><tr>' +
      '<th>Method</th><th>State</th><th>What happens</th></tr></thead>' +
      '<tbody>' + json.enrolment.map(function (r: Json): string {
        return '<tr><td><code>' + esc(r.method) + '</code></td><td>' +
          state(r.built) + '</td><td>' + esc(r.what) + '</td></tr>';
      }).join('') + '</tbody></table>' +
      '<h2>How a device is recognised</h2><table class="grid"><thead><tr>' +
      '<th>Key</th><th>State</th><th>How it is matched</th></tr></thead>' +
      '<tbody>' + json.recognition.map(function (r: Json): string {
        return '<tr><td><code>' + esc(r.kind) + '</code></td><td>' +
          state(r.built) + '</td><td>' + esc(r.what) + '</td></tr>';
      }).join('') + '</tbody></table>' +
      '<h2>Attestation</h2>' +
      kit.note('A device is <strong>attested</strong> when a verifier ' +
        'checked an attestation statement for one of its keys and it ' +
        'chained to a trust anchor below, and <strong>self-asserted' +
        '</strong> otherwise. The formats it records: ' +
        esc(json.attestationFormats.join(', ')) + '. A statement that ' +
        'does not verify is refused in both modes; one that verifies and ' +
        'chains to nothing here is self-asserted. ' +
        (json.unattestedKeys.accepted
          ? 'This realm (development) registers a self-asserted key a ' +
            'device or its owner presents.'
          : 'This realm (product) REFUSES a self-asserted key a device or ' +
            'its owner presents (STS-DEVICE-0024).') + ' ' +
        esc(json.unattestedKeys.adminKeys) + '.') +
      '<table class="grid"><thead><tr><th>Statement</th><th>Anchors</th>' +
      '<th>Setting</th><th>Shipped</th></tr></thead><tbody>' +
      json.trustAnchors.map(function (r: Json): string {
        return '<tr><td><code>' + esc(r.kind) + '</code></td><td>' +
          esc(r.count === null ? r.source : r.count + ' (' + r.source +
                                           ')') +
          '</td><td><code>' + esc(r.setting) + '</code></td><td>' +
          (r.shipped.length ? r.shipped.map(function (a: Json): string {
            return esc(a.subject) + ' — until ' + esc(a.notAfter) +
              '<br><small>SHA-256 <code>' + esc(a.sha256) + '</code>' +
              (a.used ? '' : ' <strong>not used: pin mismatch</strong>') +
              '</small>';
          }).join('<br>') : '—') + '</td></tr>';
      }).join('') + '</tbody></table>' +
      '<h2>Enrolment challenges</h2>' +
      kit.note('The challenges <code>/portal/devices</code> issues are ' +
        'held in <code>' + esc(json.challenges.store) + '</code>, per ' +
        'realm and persisted, one per session and purpose, answered once ' +
        'across the cluster and for ' +
        esc(String(json.challenges.ttlSeconds)) + ' seconds; ' +
        esc(String(json.challenges.live)) + ' are live, of at most ' +
        esc(String(json.challenges.max)) + '.') +
      '<h2>Where a recognised device is recorded</h2>' +
      kit.note('At a sign-in: ' + esc(json.recordedAt.signIn) + '. At ' +
        'the token endpoint: ' + esc(json.recordedAt.tokenEndpoint) + '. ' +
        'A compromised device is still recognised, and says so.') +
      '<h2>Compliance</h2>' +
      kit.note('A device is <code>compliant</code>, ' +
        '<code>not-compliant</code> or <code>unknown</code> (where it ' +
        'starts); every change records its previous value and who set it ' +
        '— ' + esc(json.complianceSources.join(', ')) + '.') +
      '<table class="grid"><thead><tr><th>Door</th><th>State</th>' +
      '<th>How</th></tr></thead><tbody>' +
      '<tr><td>An administrator</td><td>' + state(true) + '</td><td>' +
      'Set compliance on a device\'s page under <a href="' + LIST + '">' +
      'Devices</a>, or <code>POST /admin-api/devices/set-compliance</code> ' +
      '(Admin Write). Source <code>admin</code>.</td></tr>' +
      '<tr><td>An MDM or posture feed</td><td>' + state(true) + '</td><td>' +
      '<code>' + esc(json.mdmFeed.path) + '</code> with an access token ' +
      'carrying <code>' + esc(json.mdmFeed.scope) + '</code> — a PROTECTED ' +
      'scope, issued only to a client that declares it, and the only ' +
      'scope that operation takes: the feed needs no admin scope and gets ' +
      'none. Up to ' + esc(String(json.mdmFeed.maxReports)) + ' reports, ' +
      'each naming its device by ' + esc(json.mdmFeed.identifiedBy.join(', ')) +
      '. Source <code>mdm</code>, the client as actor.</td></tr>' +
      '<tr><td>The test control</td><td>' + (json.testControl.open
        ? '<span class="state-valid">open (development)</span>'
        : '<span class="state-none">refused (product)</span>') +
      '</td><td><code>' + esc(json.testControl.path) + '</code>, no ' +
      'credential, development only (<code>mode.opensTestControls()</code>). ' +
      'Source <code>test-control</code>.</td></tr>' +
      '<tr><td>A received CAEP device-compliance-change</td><td>' +
      state(true) + '</td><td>From a federation partner whose Shared ' +
      'Signals this realm receives — a device manager is an ' +
      '<code>ssf</code> relationship on <a href="/admin/federation">' +
      'Federation</a> — as the <code>signal-response</code> policy permits ' +
      '(#373, #374), its device named by id or key thumbprint. Source ' +
      '<code>caep</code>; arrivals on <a href="/admin/ssf/transmitters">' +
      'Signals from partners</a>.</td></tr></tbody></table>' +
      '<h2>What goes out over Shared Signals</h2>' +
      kit.note('CAEP: ' + esc(json.signals.caep.join('; ')) + '. RISC, ' +
        'for a person\'s device compromised or removed: ' +
        esc(json.signals.risc.join(' and ')) + '. The subject is ' +
        esc(json.signals.subject) + '. A compliance change goes out only ' +
        'when what a receiver can be told moved: CAEP knows compliant and ' +
        'not-compliant, and unknown is sent as not-compliant.') +
      '<h2>What decides on a device</h2>' +
      kit.note('Risk scoring: the signals ' +
        esc(json.decisions.riskSignals.join(', ')) + ' — the last two ' +
        'lower the score; unregistered-device fires ' +
        (json.decisions.expectRegistered ? 'for anybody here ' +
          '(devices.expectRegistered)' : 'only for a person who registered ' +
          'a device') + '. The issuance policy (' +
        esc(json.decisions.policy) + '): a compromised device is ' +
        (json.decisions.refuseCompromised ? '<strong>refused</strong>'
                                          : 'only a risk signal') +
        '; a compliant registered device is ' +
        (json.decisions.requireCompliantDevice
          ? '<strong>required</strong>' + (json.decisions
              .compliantDeviceAttested ? ', and attested' : '')
          : 'not required (off by default)') + '. The acr <code>' +
        esc(json.decisions.acr) + '</code>, and the claim ' +
        esc(json.decisions.claim) + '.') +
      '<h2>Settings</h2>' + SettingsForms.forms(json.settings, REGISTRATION);
  }

  static monitorHtml(json: Json): string {
    const esc = kit.esc.bind(kit);
    const c = json.counts;
    const table = function (title: string, counts: Json): string {
      return '<h2>' + esc(title) + '</h2><table class="grid"><tbody>' +
        Object.keys(counts).map(function (k) {
          return '<tr><th>' + esc(k) + '</th><td>' + esc(String(counts[k])) +
            '</td></tr>';
        }).join('') + '</tbody></table>';
    };
    const t = json.timeline;
    const sources: string[] = json.complianceSources;
    return '<div class="tiles">' + kit.tile(String(c.total), 'devices') +
      kit.tile(String(c.keys), 'keys') +
      kit.tile(String(c.nativeSso.live), 'live Native SSO') +
      kit.tile(String(t.totals.created), 'registered') +
      kit.tile(String(t.totals.removed), 'removed') +
      kit.tile(String(t.totals.evicted), 'evicted') + '</div>' +
      kit.note('What this realm\'s register holds, counted now, and what ' +
        'happened to it: every registration, removal, and eviction at a ' +
        'person\'s <code>devices.maxPerPerson</code>, kept up to ' +
        '<code>devices.eventsKept</code>, and every compliance change by ' +
        'who made it — admin, mdm, test-control, caep' + (t.since
          ? ' (the oldest is ' +
        'from ' + esc(t.since) + ')' : '') + '. A device removed by an ' +
        '<code>ldapdelete</code> on the socket is not an event here — the ' +
        'register never sees it.', 'What this page is') +
      table('By owner', c.byOwnerKind) +
      table('By compliance', c.byCompliance) +
      table('By risk level', c.byRiskLevel || {}) +
      table('Compliance changes kept, by source', t.totals.compliance || {}) +
      table('By attestation', c.byAttestation) +
      table('By key', c.byKeyKind) +
      table('By enrolment', c.byEnrolment) +
      table('Native SSO', c.nativeSso) +
      table('Keys by attestation format', c.byKeyAttestationFormat || {}) +
      kit.note('Counted in this process since it started (' +
        esc(json.activity.scope) + '): a page served by one node of a ' +
        'cluster shows that node\'s.', 'The counters below') +
      table('Recognitions, by key', json.activity.recognitions) +
      table('Enrolments by a device or its owner, by method',
            json.activity.enrolments) +
      table('Enrolled keys, by attestation', json.activity.attestationLevels) +
      table('Enrolled keys, by attestation format',
            json.activity.attestationFormats) +
      table('Attestations refused', json.activity.attestationRefusals) +
      '<h2>The last ' + esc(String(t.days)) + ' days</h2>' +
      '<table class="grid"><thead><tr><th>Day (UTC)</th><th>Registered' +
      '</th><th>Removed</th><th>Evicted</th>' +
      sources.map(function (src: string): string {
        return '<th>Compliance: ' + esc(src) + '</th>';
      }).join('') + '</tr></thead><tbody>' +
      t.rows.slice(0).reverse().map(function (r: Json): string {
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
