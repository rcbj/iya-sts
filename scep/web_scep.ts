// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_scep.ts
//
// ---------------------------------------------------------------------------
// PROTOCOLS → SCEP AND MONITORING → SCEP ENROLLMENTS, DRAWN FROM THEIR VIEWS
// ALONE (#446, 2026-10-05).
//
// Draws SCEP from the answer of `GET /admin-api/scep` — the endpoints, the
// Issuing CA and RA, the profiles, challenge passwords, host names,
// certificates, the documented exceptions and the settings — and SCEP
// enrollments from that of `GET /admin-api/scep/monitor`.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// Its methods were `ScepAdmin`'s in `scep/scep_admin.ts`, moved with their
// comments; that module still draws the page until the console's cutover, by
// calling `render()` with its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('../admin-ui/web_kit');
import SettingsForms = require('../admin-ui/web_settings');

type Json = any;

// The console's escaping, under the name the moved code calls it by.
const esc = kit.esc;

/**
 * Draws SCEP from the answer of `GET /admin-api/scep` — the endpoints, the
 * Issuing CA and RA, the profiles, challenge passwords, host names,
 * certificates, the documented exceptions and the settings — and SCEP
 * enrollments from that of `GET /admin-api/scep/monitor`.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class ScepPage {
  /**
   * Draws the page's body from its view.
   *
   * @param view - the answer of the page's management API operation
   * @param ctx - the render context: the page's query and whether
   *   the reader may write (`WebKit.context()`)
   * @returns the body as HTML
   */
  static render(view: Json, ctx: Json): string {
    return ScepPage.body(ctx, view);
  }

  /**
   * Draws a value as escaped `<code>`.
   *
   * @param value - the value
   * @returns the markup
   */
  static code(value) {
    return '<code>' + esc(value == null ? '' : value) + '</code>';
  }

  /**
   * Draws a muted placeholder for an empty cell.
   *
   * @param text - the text; `none` when omitted
   * @returns the markup
   */
  static none(text) {
    return '<span class="sub">' + esc(text || 'none') + '</span>';
  }

  /**
   * Draws a hidden form field.
   *
   * @param name - the field's name
   * @param value - its value
   * @returns the markup
   */
  static hidden(name, value) {
    return '<input type="hidden" name="' + esc(name) + '" value="' +
           esc(value) + '">';
  }

  /**
   * Draws an entry's URN as a link to its person or application page.
   *
   * @param entry - the entry's `kind` and `id`, or null
   * @param uri - the entry's `urn:sts:` URI, which its row carries
   * @returns the markup
   */
  static entryLink(entry, uri) {
    if (!entry) {
      return this.none('none');
    }
    const href = entry.kind === 'person'
      ? '/admin/users?user=' + encodeURIComponent(entry.id)
      : '/admin/applications?application=' + encodeURIComponent(entry.id);
    return '<a href="' + esc(href) + '">' + this.code(uri) +
           '</a>';
  }

  /**
   * Draws the select choosing a person or an application.
   *
   * @returns the markup
   */
  static kindSelect() {
    return '<select name="kind"><option value="person">person</option>' +
           '<option value="application">application</option></select>';
  }

  /**
   * Draws the endpoints section.
   *
   * @param json - the view
   * @returns the markup
   */
  static sectionEndpoints(json) {
    const self = this;
    const rows = Object.keys(json.endpoints).map(function (name) {
      return '<tr><th>' + esc(name) + '</th><td>' +
             self.code(json.endpoints[name]) + '</td></tr>';
    }).join('');
    return '<h2>Endpoints</h2><table class="kv">' + rows +
      '<tr><th>GetCACaps answers</th><td>' +
      json.capabilities.map(this.code.bind(this)).join(' ') + '</td></tr>' +
      '<tr><th>Messages answered</th><td>' +
      Object.keys(json.messageTypes).filter(function (n) {
        return n !== '3';
      }).map(function (n) {
        return self.code(json.messageTypes[n] + ' (' + n + ')');
      }).join(' ') + '</td></tr></table>';
  }

  /**
   * Draws the Issuing CA and RA certificate section.
   *
   * @param json - the view
   * @returns the markup
   */
  static sectionAuthority(json) {
    const a = json.authority;
    const r = json.ra;
    const authority = a
      ? '<table class="kv"><tr><th>Subject</th><td>' + this.code(a.subject) +
        '</td></tr><tr><th>Serial</th><td>' + this.code(a.serialHex) +
        '</td></tr><tr><th>Key</th><td>' + esc(a.keyAlg) + ', signs ' +
        esc(a.signatureAlg) + '</td></tr><tr><th>Valid until</th><td>' +
        esc(a.notAfter) + '</td></tr><tr><th>Chain</th><td>' +
        (a.intermediate ? this.code(a.intermediate.subject) : '') + ' → ' +
        (a.root ? this.code(a.root.subject) : '') + '</td></tr></table>'
      : kit.warn(esc(json.authorityNote));
    const raTable = r.present
      ? '<table class="kv"><tr><th>Subject</th><td>' + this.code(r.subject) +
        '</td></tr><tr><th>Serial</th><td>' + this.code(r.serialHex) +
        '</td></tr><tr><th>Key</th><td>' + esc(r.keyAlgorithm) +
        (r.keyAlgorithm !== r.wantedKeyAlgorithm
          ? ' <span class="sub">(scep.raKeyAlgorithm is ' +
            esc(r.wantedKeyAlgorithm) + ')</span>' : '') +
        '</td></tr><tr><th>Valid until</th><td>' + esc(r.notAfter) +
        '</td></tr><tr><th>Status</th><td>' + esc(r.status) +
        '</td></tr></table>'
      : '<p class="sub">No RA certificate yet; the first GetCACert or ' +
        'PKIOperation issues one (' + esc(r.keyAlgorithm) + ').</p>';
    return '<h2>SCEP Issuing CA</h2>' + authority +
      '<h2>RA certificate</h2>' +
      kit.note('The certificate a client encrypts its request to and ' +
        'verifies a CertRep with. RSA whatever the Issuing CA is, because ' +
        'SCEP key transport is RSA; a leaf of the SCEP Issuing CA, re-issued ' +
        'when it is missing, expires within thirty days, or is not the size ' +
        '<code>scep.raKeyAlgorithm</code> names.') + raTable +
      '<form method="post" action="/admin/scep">' +
      this.hidden('action', 'reissue-ra') +
      '<button type="submit">Re-issue the RA certificate</button></form>';
  }

  /**
   * Draws the profiles section: each profile, whether it is allowed and what it
   * needs.
   *
   * @param json - the view
   * @returns the markup
   */
  static sectionProfiles(json) {
    const self = this;
    const rows = json.profiles.map(function (p) {
      return '<tr><td>' + self.code(p.id) + '</td><td>' +
        (p.allowed ? 'yes' : '<strong>no</strong>') + '</td><td>' +
        (p.needs ? esc(p.needs) : self.none('nothing beyond the entry')) +
        '</td><td>' + esc(p.keys) + '</td><td>' + self.code(p.url) +
        '</td></tr>';
    }).join('');
    const refused = json.refusedProfiles.map(function (p) {
      return '<tr><td>' + self.code(p.id) + '</td><td>' + esc(p.why) +
             '</td></tr>';
    }).join('');
    return '<h2>Profiles</h2><table><thead><tr><th>Profile</th><th>Allowed ' +
      'here</th><th>Needs</th><th>Keys</th><th>SCEP ' +
      'URL</th></tr></thead><tbody>' + rows + '</tbody></table>' +
      '<h3>Never issued over an enrollment protocol</h3><table><thead><tr>' +
      '<th>Profile</th><th>Why</th></tr></thead><tbody>' + refused +
      '</tbody></table>';
  }

  /**
   * Draws the challenge passwords section with its create and delete forms,
   * paged.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the view
   * @returns the markup
   */
  static sectionChallenges(ctx, json) {
    const self = this;
    const nav = kit.pageNavPair('/admin/scep', ctx.query,
      Object.assign({}, json.challenges.paging, { param: 'credentialsPage' }));
    const rows = json.challenges.rows.length
      ? json.challenges.rows.map(function (c) {
        return '<tr><td>' + self.code(c.id) + '</td><td>' +
               self.entryLink(c.entry, c.entryUri) +
          '</td><td>' + self.code(c.profile) + '</td><td>' + esc(c.status) +
          '</td><td>' + esc(c.expiresAt) + '</td><td>' +
          esc(c.createdBy || '—') + '</td><td><form method="post" ' +
          'action="/admin/scep">' + self.hidden('action', 'delete-challenge') +
          self.hidden('id', c.id) +
          '<button type="submit" class="danger">Delete' +
          '</button></form></td></tr>';
      }).join('')
      : '<tr><td colspan="7" class="sub">No challenge passwords in this ' +
        'realm.</td></tr>';
    const options = json.profiles.filter(function (p) {
      return p.allowed;
    }).map(function (p) {
      return '<option value="' + esc(p.id) + '"' +
        (p.id === json.defaultProfile ? ' selected' : '') + '>' + esc(p.id) +
        '</option>';
    }).join('');
    return '<h2 id="list-credentialsPage">Challenge passwords</h2>' +
      kit.note('A challenge authorizes ONE enrollment for ONE entry and ' +
                 'ONE ' +
        'profile, and whoever redeems it is issued a certificate AS that ' +
        'entry. It is shown once when it is made and kept only as a digest.') +
      '<form method="post" action="/admin/scep" class="inline">' +
      this.hidden('action', 'create-challenge') + this.kindSelect() +
      ' <input name="identifier" placeholder="username or application" ' +
      'required> <select name="profile">' + options + '</select> ' +
      '<input name="lifetimeS" type="number" min="60" placeholder="lifetime ' +
      '(seconds)"> <button type="submit">Create a challenge</button></form>' +
      nav.head + '<table><thead><tr><th>Id</th><th>For</th><th>Profile</th>' +
      '<th>Status</th><th>Expires</th><th>Created by</th><th></th></tr>' +
      '</thead><tbody>' + rows + '</tbody></table>' + nav.foot;
  }

  /**
   * Draws the registered host names section with its add and remove forms.
   *
   * @param json - the view
   * @returns the markup
   */
  static sectionHostNames(json) {
    const self = this;
    const rows = json.hostNames.length
      ? json.hostNames.map(function (h) {
        return '<tr><td>' + self.entryLink(h.entry, h.entryUri) +
          '</td><td>' +
          h.hostNames.map(function (name) {
            return self.code(name) +
                   ' <form method="post" action="/admin/scep" ' +
              'class="inline">' + self.hidden('action', 'remove-host-name') +
              self.hidden('kind', h.entry.kind) +
              self.hidden('identifier', h.entry.id) +
              self.hidden('hostName', name) + '<button type="submit" ' +
              'class="danger">Remove</button></form>';
          }).join('<br>') + '</td></tr>';
      }).join('')
      : '<tr><td colspan="2" class="sub">No entry in this realm has a ' +
        'registered host name.</td></tr>';
    return '<h2>Registered host names</h2>' +
      kit.note('A dNSName or iPAddress is issued only when it is ' +
                 'registered ' +
        'on the entry the certificate is for. This service never proves ' +
        'control of a name by dialling it.') +
      '<form method="post" action="/admin/scep" class="inline">' +
      this.hidden('action', 'add-host-name') + this.kindSelect() +
      ' <input name="identifier" placeholder="username or application" ' +
      'required> <input name="hostName" placeholder="host.example.com" ' +
      'required> <button type="submit">Register</button></form>' +
      '<table><thead><tr><th>Entry</th><th>Host names</th></tr></thead>' +
      '<tbody>' + rows + '</tbody></table>';
  }

  /**
   * Draws the enrolled certificates section with its revoke forms, paged.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the view
   * @returns the markup
   */
  static sectionCertificates(ctx, json) {
    const self = this;
    const nav = kit.pageNavPair('/admin/scep', ctx.query,
      Object.assign({}, json.certificates.paging,
                    { param: 'certificatesPage' }));
    const reasons = json.revokeReasons.map(function (r) {
      return '<option value="' + esc(r) + '">' + esc(r) + '</option>';
    }).join('');
    const rows = json.certificates.rows.length
      ? json.certificates.rows.map(function (c) {
        const control = c.status === 'revoked'
          ? self.none('revoked ' + ((c.revoked && c.revoked.reason) || ''))
          : '<form method="post" action="/admin/scep" class="inline">' +
            self.hidden('action', 'revoke-certificate') +
            self.hidden('serial', c.serialHex) + '<select name="reason">' +
            reasons + '</select> <button type="submit" class="danger">' +
            'Revoke</button></form>';
        return '<tr><td>' + self.code(c.serialHex) + '</td><td>' +
          self.entryLink(c.entry, c.entryUri) + '</td><td>' +
          self.code(c.profile) +
          '</td><td>' +
          esc(c.keyAlg) + '</td><td>' + esc(c.status) + '</td><td>' +
          esc(c.notAfter) + '</td><td>' + control + '</td></tr>';
      }).join('')
      : '<tr><td colspan="7" class="sub">Nothing has been issued over SCEP ' +
        'in this realm.</td></tr>';
    return '<h2 id="list-certificatesPage">Enrolled certificates</h2>' +
      nav.head + '<table><thead><tr><th>Serial</th><th>For</th><th>Profile' +
      '</th><th>Key</th><th>Status</th><th>Expires</th><th></th></tr></thead>' +
      '<tbody>' + rows + '</tbody></table>' + nav.foot;
  }

  /**
   * Draws what SCEP here does not do, and the mode's note.
   *
   * @param json - the view
   * @returns the markup
   */
  static sectionExceptions(json) {
    const rows = json.exceptions.map(function (x) {
      return '<tr><th>' + esc(x.what) + '</th><td>' + esc(x.why) + '</td></tr>';
    }).join('');
    const m = json.mode;
    return '<h2>What SCEP here does not do</h2><table class="kv">' + rows +
      '</table><h2>Mode</h2>' +
      kit.note('<strong>This realm is in ' + esc(m.mode) +
                 ' mode.</strong> ' +
        esc(m.scep) +
        (m.requirement ? ' Development: ' + esc(m.requirement.development) +
         ' Product: ' + esc(m.requirement.product) : ''));
  }

  // THE TWO PAGES' BODIES (#446), each one method so that it can be one
  // renderer: Protocols → SCEP and Monitoring → SCEP enrollments.
  /**
   * Draws Protocols → SCEP from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - `scepView()`'s answer
   * @returns the body as HTML
   */
  static body(ctx, json) {
    const inner =
      kit.note('<strong>SCEP (RFC 8894) for this trust realm.</strong> A ' +
        'device gets the RA and CA certificates with GetCACert, and sends a ' +
        'PKCS#10 request signed and encrypted in CMS, carrying a challenge ' +
        'password made below or on the user portal. ' +
        (json.enabled ? '' : '<strong>SCEP is turned off in this realm.' +
         '</strong>')) +
      this.sectionEndpoints(json) + this.sectionAuthority(json) +
      this.sectionProfiles(json) +
      this.sectionChallenges(ctx, json) + this.sectionHostNames(json) +
      this.sectionCertificates(ctx, json) + this.sectionExceptions(json) +
      SettingsForms.forms(json.settings, '/admin/scep') +
      '<p class="links"><a href="/admin/scep?format=json">JSON</a> · ' +
      '<code>GET /admin-api/scep</code> · <a href="/admin/scep/monitor">SCEP ' +
      'enrollments (monitoring)</a> · <a href="/admin/pki">PKI</a> · ' +
      '<a href="/admin/error-codes">Error codes</a></p>';
    return inner;
  }

  // ---------------------------------------------------------------------------
  // GET /admin/scep/monitor
  // ---------------------------------------------------------------------------
  /**
   * Draws a table of counts, largest first, for the monitor page.
   *
   * @param title - the table's heading
   * @param counts - the counts, by name
   * @returns the markup
   */
  static table(title, counts) {
    const self = this;
    const keys = Object.keys(counts || {}).sort(function (a, b) {
      return counts[b] - counts[a];
    });
    return '<h2>' + esc(title) + '</h2>' + (keys.length
      ? '<table><tbody>' + keys.map(function (k) {
        return '<tr><td>' + self.code(k) + '</td><td class="num">' + counts[k] +
               '</td></tr>';
      }).join('') + '</tbody></table>'
      : '<p class="sub">None yet.</p>');
  }

  /**
   * Draws Monitoring → SCEP enrollments from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - `scepMonitorView()`'s answer
   * @returns the body as HTML
   */
  static monitorBody(ctx, json) {
    const self = this;
    const t = json.totals;
    const nav = kit.pageNavPair('/admin/scep/monitor', ctx.query,
                                  json.paging);
    const rows = json.recent.length ? json.recent.map(function (r) {
      return '<tr><td>' + esc(r.at) + '</td><td>' + self.code(r.operation) +
        '</td><td>' + esc(r.outcome) + '</td><td>' + esc(r.failInfo || '') +
        '</td><td>' + esc(r.profile || '') + '</td><td>' +
        esc(r.principal || '') + '</td><td>' + esc(r.target || '') +
        '</td><td>' + esc(r.errorCode || '') + '</td><td>' +
        esc(r.serialHex || '') + '</td></tr>';
    }).join('') : '<tr><td colspan="9" class="sub">No SCEP request in this ' +
      'realm yet.</td></tr>';
    const inner =
      kit.note('<strong>What the SCEP server has done in this ' +
        'realm</strong>, counted since ' + esc(json.since) + ' across ' +
        esc(json.processes) + ' process(es). A refused PKIOperation is an ' +
        'HTTP 200 CertRep FAILURE, so it is counted by its failInfo.') +
      '<div class="tiles">' + kit.tile(t.requests, 'requests') +
      kit.tile(t.issued, 'issued') + kit.tile(t.refused, 'refused') +
      kit.tile(t.revoked, 'revoked') +
      kit.tile(t.challengesCreated, 'challenges created') +
      kit.tile(json.issuedCertificates, 'certificates held') + '</div>' +
      self.table('By operation', json.operations) +
      self.table('By failInfo', json.failInfo) +
      self.table('Refusals by error code', json.errorCodes) +
      self.table('By profile', json.profiles) +
      self.table('By principal', json.principals) +
      '<h2 id="list-page">Recent</h2>' + nav.head + '<table><thead><tr>' +
      '<th>At</th><th>Operation</th><th>Outcome</th><th>failInfo</th>' +
      '<th>Profile</th><th>Principal</th><th>Target</th><th>Code</th>' +
      '<th>Serial</th></tr></thead><tbody>' + rows + '</tbody></table>' +
      nav.foot +
      kit.note('There is no reset; the durable record of each act is the ' +
        '<a href="/admin/audit">Audit log</a>.') +
      '<p class="links"><a href="/admin/scep/monitor?format=json">JSON</a> ' +
      '· <code>GET /admin-api/scep/monitor</code> · <a ' +
      'href="/admin/scep">SCEP</a></p>';
    return inner;
  }
}

export = ScepPage;
