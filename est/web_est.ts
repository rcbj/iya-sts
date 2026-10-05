// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_est.ts
//
// ---------------------------------------------------------------------------
// PROTOCOLS → EST AND MONITORING → EST ENROLLMENTS, DRAWN FROM THEIR VIEWS
// ALONE (#446, 2026-10-05).
//
// Draws EST from the answer of `GET /admin-api/est` — the endpoints, the
// Issuing CA, the profiles, server key generation, host names, certificates
// and settings — and EST enrollments from that of `GET
// /admin-api/est/monitor`.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// Its methods were `EstAdmin`'s in `est/est_admin.ts`, moved with their
// comments; that module still draws the page until the console's cutover, by
// calling `render()` with its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('../admin-ui/web_kit');
import SettingsForms = require('../admin-ui/web_settings');

type Json = any;

// The console's escaping, under the name the moved code calls it by.
const esc = kit.esc;

/**
 * Draws EST from the answer of `GET /admin-api/est` — the endpoints, the
 * Issuing CA, the profiles, server key generation, host names, certificates
 * and settings — and EST enrollments from that of `GET
 * /admin-api/est/monitor`.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class EstPage {
  /**
   * Draws the page's body from its view.
   *
   * @param view - the answer of the page's management API operation
   * @param ctx - the render context: the page's query and whether
   *   the reader may write (`WebKit.context()`)
   * @returns the body as HTML
   */
  static render(view: Json, ctx: Json): string {
    return EstPage.estPageBody(ctx, view);
  }

  /**
   * Draws the `<option>` elements of a select.
   *
   * @param values - the values
   * @param selected - the value selected
   * @returns the HTML
   */
  static options(values, selected) {
    return values.map(function (one) {
      return '<option value="' + esc(one) + '"' +
             (one === selected ? ' selected' : '') + '>' + esc(one) +
             '</option>';
    }).join('');
  }

  /**
   * Draws a flag as `yes` or a muted `no`.
   *
   * @param flag - the flag
   * @returns the HTML
   */
  static yesNo(flag) {
    return flag ? 'yes' : '<span class="sub">no</span>';
  }

  /**
   * Draws a hidden form field.
   *
   * @param name - the field's name
   * @param value - its value
   * @returns the HTML
   */
  static hidden(name, value) {
    return '<input type="hidden" name="' + esc(name) + '" value="' +
           esc(value) + '">';
  }

  /**
   * Draws a link to a person's or an application's console page.
   *
   * @param entry - `{ kind, id }`, or nothing
   * @returns the HTML
   */
  static entryLink(entry) {
    if (!entry) {
      return '<span class="sub">—</span>';
    }
    const href = entry.kind === 'person'
      ? '/admin/users?user=' + encodeURIComponent(entry.id)
      : '/admin/applications?application=' + encodeURIComponent(entry.id);
    return '<a href="' + esc(href) + '"><code>' + esc(entry.kind + ':' +
           entry.id) + '</code></a>';
  }

  // ---------------------------------------------------------------------------
  // The body of /admin/est, from the view.
  // ---------------------------------------------------------------------------
  /**
   * Draws the body of `/admin/est` from the view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - `est_console.ts`'s `estView()`
   * @returns the HTML
   */
  static estPageBody(ctx, json) {
    const self = this;
    const endpointRows = json.endpoints.map(function (one) {
      return '<tr><td><code>' + esc(one.method) + '</code></td><td><code>' +
             esc(one.url) + '</code>' + (one.labelFormUrl
               ? '<div class="sub">or <code>' + esc(one.labelFormUrl) +
                 '</code></div>' : '') + '</td><td>' + esc(one.what) +
             '</td><td>RFC 7030 ' + esc(one.section) + '</td></tr>';
    }).join('');
    const labelFormNote = json.labelForm
      ? '<p class="sub"><strong>The label form</strong> <code>' +
        esc(json.labelForm.base) + '</code>. ' + esc(json.labelForm.note) +
        '</p>'
      : '';
    const authority = json.hierarchy.authority;
    const caBlock = json.hierarchy.built && authority
      ? '<table class="kv"><tr><th>Subject</th><td><code>' +
        esc(authority.subject) + '</code></td></tr><tr><th>Serial</th><td>' +
        '<code>' + esc(authority.serialHex) + '</code></td></tr><tr><th>Key' +
        '</th><td>' + esc(authority.keyAlg) + '</td></tr><tr><th>Valid' +
        '</th><td>' + esc(authority.notBefore) + ' — ' +
        esc(authority.notAfter) + '</td></tr><tr><th>SHA-256</th><td><code>' +
        esc(authority.thumbprint) + '</code></td></tr><tr><th>Chain</th><td>' +
        json.hierarchy.chainPem.length + ' certificate(s): the EST Issuing ' +
        'CA, this realm\'s Intermediate and the service Root — what ' +
        '<code>/cacerts</code> returns</td></tr></table>'
      : kit.warn(esc(json.hierarchy.note));
    const profileRows = json.profiles.map(function (one) {
      return '<tr><td><code>' + esc(one.id) + '</code>' +
             (one.isDefault ? ' <span class="sub">(unlabelled)</span>' : '') +
             '</td><td>' + self.yesNo(one.allowed) + '</td><td>' +
             (one.needs ? esc(one.needs) : '<span class="sub">nothing ' +
              'beyond the identity rule</span>') + '</td><td><code>' +
             esc(one.urls.simpleenroll) + '</code><div class="sub">' +
             esc(one.urls.simplereenroll) + '<br>' +
             esc(one.urls.serverkeygen) + '<br>' + esc(one.urls.csrattrs) +
             '</div></td></tr>';
    }).join('');
    const refusedRows = json.refusedProfiles.map(function (one) {
      return '<tr><td><code>' + esc(one.id) + '</code></td><td>' +
             esc(one.why) + '</td></tr>';
    }).join('');
    const credentialRows = json.authentication.credentials.map(function (one) {
      return '<tr><td>' + esc(one.kind) + '</td><td>' + esc(one.what) +
             '</td><td><a href="' + esc(one.managedAt) + '">' +
             esc(one.managedAt) + '</a></td></tr>';
    }).join('');
    const allowedProfiles = json.profiles.filter(function (one) {
      return one.allowed;
    }).map(function (one) {
      return one.id;
    });
    const issueForm = '<form method="post" action="/admin/est">' +
      this.hidden('action', 'issue-server-key') +
      '<table class="kv"><tr><th>For</th><td><select name="kind">' +
      this.options(['person', 'application'], 'person') + '</select> ' +
      '<input type="text" name="identifier" required maxlength="256" ' +
      'placeholder="username or application identifier"></td></tr>' +
      '<tr><th>Profile</th><td><select name="profile">' +
      this.options(allowedProfiles, json.defaultProfile) +
      '</select></td></tr>' +
      '<tr><th>Key algorithm</th><td><select name="keyAlg">' +
      this.options(json.keyAlgorithms, 'ec-p256') +
      '</select></td></tr></table><button type="submit">Issue with a ' +
      'server-generated key</button></form>';
    const hostRows = json.hostNames.length ? json.hostNames.map(function (row) {
      return '<tr><td>' + self.entryLink(row.entry) + '</td><td>' +
        row.hostNames.map(function (name) {
          return '<form method="post" action="/admin/est" class="inline">' +
            self.hidden('action', 'remove-host-name') +
            self.hidden('kind', row.entry.kind) +
            self.hidden('identifier', row.entry.id) +
            self.hidden('hostName', name) + '<code>' + esc(name) + '</code> ' +
            '<button type="submit" class="danger">Remove</button></form>';
        }).join(' ') + '</td></tr>';
    }).join('') : '<tr><td colspan="2" class="sub">No entry in this realm ' +
                  'has ' +
      'a certificate host name registered, so no tls-server or ' +
      'tls-server-client certificate can be issued.</td></tr>';
    const hostForm = '<form method="post" action="/admin/est">' +
      this.hidden('action', 'add-host-name') + '<select name="kind">' +
      this.options(['person', 'application'], 'application') + '</select> ' +
      '<input type="text" name="identifier" required maxlength="256" ' +
      'placeholder="identifier"> <input type="text" name="hostName" required ' +
      'maxlength="253" placeholder="host.example.com or 192.0.2.1"> ' +
      '<button type="submit">Register</button></form>';
    const nav = kit.pageNavPair('/admin/est', ctx.query,
      Object.assign({}, json.certificates.paging,
                    { param: 'certificatesPage' }));
    const certificateRows = json.certificates.rows.length
      ? json.certificates.rows.map(function (one) {
        const control = one.status === 'revoked'
          ? '<span class="sub">revoked ' + esc(one.revoked ? one.revoked.reason
                                                            : '') + '</span>'
          : '<form method="post" action="/admin/est">' +
            self.hidden('action', 'revoke-certificate') +
            self.hidden('serialHex', one.serialHex) + '<select name="reason">' +
            self.options(json.revocationReasons, 'unspecified') + '</select> ' +
            '<button type="submit" class="danger">Revoke</button></form>';
        return '<tr><td><code>' + esc(one.serialHex) + '</code></td><td>' +
          self.entryLink(one.entry) + '</td><td><code>' + esc(one.profile) +
          '</code><div class="sub">' + esc(one.keyAlg || '') + ' · key from ' +
          esc(one.keySource) + '</div></td><td>' + one.names.map(function (n) {
            return '<code>' + esc(n) + '</code>';
          }).join('<br>') + '</td><td>' + esc(one.status) + '</td><td>' +
          esc(one.notAfter) + '</td><td>' + esc(one.requestedBy
            ? one.requestedBy.kind + ':' + one.requestedBy.id : '') +
          '</td><td>' + control + '</td></tr>';
      }).join('')
      : '<tr><td colspan="8" class="sub">Nothing has been enrolled over EST ' +
        'in this realm.</td></tr>';
    const html =
      kit.note('<strong>Enrollment over Secure Transport (RFC 7030, with ' +
        'RFC 8951).</strong> A client authenticates with a password, a ' +
        'client secret or a TLS client certificate this realm issued, sends ' +
        'a base64 PKCS#10 request, and receives a certificate from this ' +
        'realm\'s EST Issuing CA. A person may enroll only for themselves, ' +
        'an application only for itself, and a holder of Admin Write for any ' +
        'entry in the realm. ' + (json.enabled ? '' :
          '<strong>EST is turned off in this realm.</strong>')) +
      kit.warn('<strong>Mode: ' + esc(json.mode.current) + '.</strong> ' +
        'Development: ' + esc(json.mode.development) + ' Product: ' +
        esc(json.mode.product)) +
      '<h2>Endpoints</h2><table><thead><tr><th>Method</th><th>URL</th><th>' +
      'What</th><th>Section</th></tr></thead><tbody>' + endpointRows +
      '</tbody></table>' + labelFormNote +
      '<h2>EST Issuing CA</h2>' + caBlock +
      '<h2>Profiles</h2><p class="sub">A label in the path names the ' +
      'certificate profile ' +
      '(<code>/.well-known/est/&lt;profile&gt;/…</code>); ' +
      'the unlabelled path issues <code>' + esc(json.defaultProfile) +
      '</code>.</p><table><thead><tr><th>Profile</th><th>Allowed</th><th>' +
      'Needs</th><th>Labelled URLs</th></tr></thead><tbody>' + profileRows +
      '</tbody></table>' +
      '<h3>Never issued over ' +
      'EST</h3><table><thead><tr><th>Profile</th><th>Why' +
      '</th></tr></thead><tbody>' + refusedRows + '</tbody></table>' +
      '<h2>Credentials</h2><p class="sub">EST has no credential of its own: ' +
      'Basic ' + this.yesNo(json.authentication.basic) +
      ', client certificates ' +
      this.yesNo(json.authentication.certificate) + ', /serverkeygen ' +
      this.yesNo(json.authentication.serverKeyGeneration) +
      '.</p><table><thead><tr><th>Credential</th><th>What</th><th>Managed ' +
      'at</th></tr></thead><tbody>' + credentialRows + '</tbody></table>' +
      '<h2>Issue a certificate with a server-generated key</h2><p ' +
      'class="sub">The console\'s /serverkeygen: the private key is shown ' +
      'once on the next page and a sealed copy is kept on the entry.</p>' +
      issueForm +
      '<h2>Certificate host names</h2><p class="sub">A dNSName or iPAddress ' +
      'is issued only when it is registered on the entry.</p><table><thead>' +
      '<tr><th>Entry</th><th>Host names</th></tr></thead><tbody>' + hostRows +
      '</tbody></table>' + hostForm +
      '<h2 id="list-certificatesPage">Enrolled certificates</h2>' + nav.head +
      '<table><thead><tr><th>Serial</th><th>Entry</th><th>Profile</th><th>' +
      'Names</th><th>Status</th><th>Expires</th><th>Requested by</th><th>' +
      '</th></tr></thead><tbody>' + certificateRows + '</tbody></table>' +
      nav.foot +
      '<h2>Settings</h2>' + SettingsForms.forms(json.settings, '/admin/est') +
      '<p class="links"><a href="/admin/est?format=json">JSON</a> · ' +
      '<code>GET /admin-api/est</code> · <a href="/admin/est/monitor">EST ' +
      'enrollments (monitoring)</a> · <a href="/admin/pki">PKI</a> · <a ' +
      'href="/admin/error-codes">Error codes</a></p>';
    return html;
  }

  // ---------------------------------------------------------------------------
  // GET /admin/est/monitor
  // ---------------------------------------------------------------------------
  /**
   * Draws a titled table of counts.
   *
   * @param title - the heading
   * @param rows - `{ name, count }` rows
   * @returns the HTML
   */
  static countTable(title, rows) {
    return '<h3>' + esc(title) + '</h3><table><tbody>' + (rows.length
      ? rows.map(function (row) {
        return '<tr><td><code>' + esc(row.name) + '</code></td><td ' +
               'class="num">' + row.count + '</td></tr>';
      }).join('')
      : '<tr><td class="sub">none yet</td></tr>') + '</tbody></table>';
  }

  // MONITORING → EST ENROLLMENTS' BODY (#446), one method so that it can be
  // one renderer, as the EST page's is.
  /**
   * Draws Monitoring → EST enrollments from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - `estMonitorView()`'s answer
   * @returns the body as HTML
   */
  static monitorBody(ctx, json) {
    const self = this;
    const t = json.totals;
    const tiles = '<div class="tiles">' +
      kit.tile(t.requests, 'requests') + kit.tile(t.issued, 'issued') +
      kit.tile(t.refused, 'refused') + kit.tile(t.revoked, 'revoked') +
      kit.tile(json.certificates.valid, 'valid certificates') +
      kit.tile(json.certificates.revoked, 'revoked certificates') +
      '</div>';
    const nav = kit.pageNavPair('/admin/est/monitor', ctx.query,
      Object.assign({}, json.paging, { param: 'page' }));
    const recentRows = json.recent.length ? json.recent.map(function (row) {
      return '<tr><td>' + esc(row.at) + '</td><td><code>' +
             esc(row.operation) + '</code></td><td>' + esc(row.outcome) +
             '</td><td class="num">' + esc(row.status || '') + '</td><td>' +
             esc(row.profile || '') + '</td><td>' + esc(row.principal || '') +
             '</td><td>' + esc(row.target || '') + '</td><td>' +
             (row.errorCode ? '<code>' + esc(row.errorCode) + '</code>' :
              '') +
             '</td><td><code>' + esc(row.serialHex || '') +
             '</code></td></tr>';
    }).join('') : '<tr><td colspan="9" class="sub">No EST request has been ' +
      'answered in this realm since the process started.</td></tr>';
    const inner =
      kit.note('<strong>What the EST server has done</strong> in this ' +
                 'trust ' +
        'realm since ' + esc(json.since || 'the process started') +
        ', across ' +
        json.processes +
        ' process(es). Every request is counted, issued or ' +
        'refused; the durable record of each is the <a ' +
        'href="/admin/audit">Audit log</a>.') + tiles +
      self.countTable('By operation', json.operations) +
      self.countTable('By profile', json.profiles) +
      self.countTable('By principal', json.principals) +
      self.countTable('Refusals by error code', json.errorCodes) +
      self.countTable('By HTTP status', json.statuses) +
      '<h2 id="list-page">Recent requests</h2>' + nav.head +
      '<table><thead><tr><th>At</th><th>Operation</th><th>Outcome</th><th>' +
      'Status</th><th>Profile</th><th>Principal</th><th>Target</th><th>Code' +
      '</th><th>Serial</th></tr></thead><tbody>' + recentRows +
      '</tbody></table>' + nav.foot +
      kit.note('There is no reset. The counters are per realm and start ' +
        'with the process.') +
      '<p class="links"><a href="/admin/est/monitor?format=json">JSON</a> ' +
      '· <code>GET /admin-api/est/monitor</code> · <a ' +
      'href="/admin/est">EST</a></p>';
    return inner;
  }
}

export = EstPage;
