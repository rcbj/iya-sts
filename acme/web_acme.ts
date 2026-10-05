// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_acme.ts
//
// ---------------------------------------------------------------------------
// PROTOCOLS → ACME AND MONITORING → ACME ENROLLMENTS, DRAWN FROM THEIR VIEWS
// ALONE (#446, 2026-10-05).
//
// Draws ACME from the answer of `GET /admin-api/acme` — the directory,
// endpoints, Issuing CA, profiles, External Account Binding keys, accounts,
// certificates, host names and settings — and ACME enrollments from that of
// `GET /admin-api/acme/monitor`.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// Its methods were `AcmeAdmin`'s in `acme/acme_admin.ts`, moved with their
// comments; that module still draws the page until the console's cutover, by
// calling `render()` with its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('../admin-ui/web_kit');
import SettingsForms = require('../admin-ui/web_settings');

type Json = any;

// The console's escaping, under the name the moved code calls it by.
const esc = kit.esc;

/**
 * Draws ACME from the answer of `GET /admin-api/acme` — the directory,
 * endpoints, Issuing CA, profiles, External Account Binding keys, accounts,
 * certificates, host names and settings — and ACME enrollments from that of
 * `GET /admin-api/acme/monitor`.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class AcmePage {
  /**
   * Draws the page's body from its view.
   *
   * @param view - the answer of the page's management API operation
   * @param ctx - the render context: the page's query and whether
   *   the reader may write (`WebKit.context()`)
   * @returns the body as HTML
   */
  static render(view: Json, ctx: Json): string {
    return AcmePage.body(ctx, view);
  }

  /**
   * Draws a value as code, or a dash for none.
   *
   * @param value - the value
   * @returns the markup
   */
  static code(value) {
    return value ? '<code>' + esc(value) + '</code>'
                 : '<span class="sub">—</span>';
  }

  /**
   * Draws the pager pair for one paged list on `/admin/acme`.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param list - the paged list from the view model
   * @param param - the list's page parameter
   * @returns the pager markup
   */
  static nav(ctx, list, param) {
    return kit.pageNavPair('/admin/acme', ctx.query,
                             Object.assign({}, list.paging,
                                           { param: param, noun: 'rows' }));
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
   * Draws the person-or-application selector.
   *
   * @returns the markup
   */
  static kindSelect() {
    return '<select name="kind"><option value="person">person</option>' +
           '<option value="application">application</option></select>';
  }

  // ---------------------------------------------------------------------------
  // THE SECTIONS OF /admin/acme.
  // ---------------------------------------------------------------------------
  /**
   * Draws the realm's ACME endpoints.
   *
   * @param json - the view model's answer
   * @returns the markup
   */
  static endpointsHtml(json) {
    return '<table class="kv">' + Object.keys(json.endpoints).map(
      function (name) {
        return '<tr><th>' + esc(name) + '</th><td><code>' +
               esc(json.endpoints[name]) + '</code></td></tr>';
      }).join('') + '</table>';
  }

  /**
   * Draws the ACME Issuing CA.
   *
   * @param json - the view model's answer
   * @returns the markup
   */
  static authorityHtml(json) {
    const a = json.authority;
    if (!a.present) {
      return kit.warn(esc(a.note));
    }
    return '<table class="kv"><tr><th>Subject</th><td>' + this.code(a.subject) +
      '</td></tr><tr><th>Serial</th><td>' + this.code(a.serialHex) +
      '</td></tr>' +
      '<tr><th>Key / signs with</th><td>' + this.code(a.keyAlg) + ' / ' +
      this.code(a.signatureAlg) + '</td></tr><tr><th>Valid until</th><td>' +
      esc(a.notAfter) + '</td></tr><tr><th>Under</th><td>' +
      this.code(a.intermediate) + ' &larr; ' + this.code(a.root) +
      '</td></tr></table>' +
      '<p class="sub">A certificate is served with this Issuing CA and the ' +
      'realm Intermediate, never the Root. <a href="/admin/pki">PKI</a> ' +
      'manages the hierarchy; the CRL is ' +
      '<code>/pki/crl/{realm}/acme</code>.</p>';
  }

  /**
   * Draws the certificate profiles and the refused ones.
   *
   * @param json - the view model's answer
   * @returns the markup
   */
  static profilesHtml(json) {
    const rows = json.profiles.map(function (p) {
      return '<tr><td><code>' + esc(p.id) + '</code>' +
        (p.isDefault ? ' <span class="sub">default</span>' : '') + '</td><td>' +
        esc(p.description) + '</td><td>' + (p.needs ? esc(p.needs) :
                                             '<span class="sub">—</span>') +
        '</td><td>' + (p.allowed ? 'yes' : '<strong>no</strong> ' +
                       '<span class="sub">not in acme.allowedProfiles</span>') +
        '</td></tr>';
    }).join('');
    const refused = json.refusedProfiles.map(function (p) {
      return '<tr><td><code>' + esc(p.id) + '</code></td><td colspan="3">' +
             '<strong>never issued over ACME.</strong> ' + esc(p.why) +
             '</td></tr>';
    }).join('');
    return '<table><thead><tr><th>Profile</th><th>What</th><th>Needs</th>' +
           '<th>Allowed here</th></tr></thead><tbody>' + rows + refused +
           '</tbody></table><p class="sub">An order names one in its ' +
           '<code>profile</code> member (draft-ietf-acme-profiles); the ' +
           'directory advertises the allowed ones in ' +
           '<code>meta.profiles</code>. An order naming none is issued ' +
           '<code>tls-server</code> when every identifier is a ' +
           '<code>dns</code> or <code>ip</code> name and that profile is ' +
           'allowed here, and the default above otherwise.</p>';
  }

  /**
   * Draws the EAB keys, paged, with their delete controls and the form that
   * creates one.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the view model's answer
   * @returns the markup
   */
  static eabHtml(ctx, json) {
    const self = this;
    const list = json.eabKeys;
    const pager = this.nav(ctx, list, 'credentialsPage');
    const rows = list.rows.length ? list.rows.map(function (k) {
      return '<tr><td><code>' + esc(k.kid) + '</code></td><td>' +
        self.code(k.entryUri) + '</td><td>' + esc(k.status) + '</td><td>' +
        esc(k.createdAt) + '<div class="sub">by ' + esc(k.createdBy || '—') +
        '</div></td><td>' + esc(k.expiresAt) + '</td><td>' +
        self.code(k.boundAccount) + '</td><td><form method="post" ' +
        'action="/admin/acme">' + self.hidden('action', 'delete-eab') +
        self.hidden('kid', k.kid) +
        '<button type="submit" class="danger">Delete' +
        '</button></form></td></tr>';
    }).join('') : '<tr><td colspan="7" class="sub">No External Account ' +
                  'Binding key has been issued in this realm.</td></tr>';
    return '<form method="post" action="/admin/acme" class="inline">' +
      this.hidden('action', 'create-eab') + '<label>For ' + this.kindSelect() +
      '</label> <label>identifier <input name="identifier" size="24" ' +
      'required></label> <label>lifetime (s) <input name="lifetimeS" ' +
      'size="8" placeholder="' + esc(String(json.eabLifetimeS || '')) +
      '"></label> <button type="submit">Create EAB key</button></form>' +
      '<p class="sub">The key is shown once, on the page that answers this ' +
      'form, with a ready-to-paste certbot line. It binds ONE account, which ' +
      'is bound to that entry for life.</p>' + pager.head +
      '<table id="list-credentialsPage"><thead><tr><th>Key id</th><th>Entry' +
      '</th><th>Status</th><th>Created</th><th>Expires</th><th>Bound account' +
      '</th><th></th></tr></thead><tbody>' + rows + '</tbody></table>' +
      pager.foot;
  }

  /**
   * Draws the ACME accounts, paged, with their deactivate controls.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the view model's answer
   * @returns the markup
   */
  static accountsHtml(ctx, json) {
    const self = this;
    const list = json.accounts;
    const pager = this.nav(ctx, list, 'accountsPage');
    const rows = list.rows.length ? list.rows.map(function (a) {
      return '<tr><td><code>' + esc(a.id) + '</code></td><td>' +
        self.code(a.entryUri) + '</td><td>' + esc(a.status) + '</td><td>' +
        self.code(a.eabKid) + '</td><td>' + esc((a.contact || []).join(', ') ||
                                          '—') + '</td><td class="num">' +
        a.orders + '</td><td>' + esc(a.createdAt) + '</td><td>' +
        (a.status === 'valid' ? '<form method="post" action="/admin/acme">' +
         self.hidden('action', 'deactivate-account') +
         self.hidden('account', a.id) +
         '<button type="submit" class="danger">Deactivate</button></form>'
                              : '<span class="sub">' + esc(a.status) +
                                '</span>') + '</td></tr>';
    }).join('') : '<tr><td colspan="8" class="sub">No ACME account exists in ' +
                  'this realm.</td></tr>';
    return pager.head + '<table id="list-accountsPage"><thead><tr><th>Account' +
      '</th><th>Bound to</th><th>Status</th><th>EAB key</th><th>Contact</th>' +
      '<th>Orders</th><th>Created</th><th></th></tr></thead><tbody>' + rows +
      '</tbody></table>' + pager.foot;
  }

  /**
   * Draws the certificates issued through ACME, paged, with their revoke
   * controls.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the view model's answer
   * @returns the markup
   */
  static certificatesHtml(ctx, json) {
    const self = this;
    const list = json.certificates;
    const pager = this.nav(ctx, list, 'certificatesPage');
    const reasons = json.revocationReasons.map(function (r) {
      return '<option value="' + esc(r) + '">' + esc(r) + '</option>';
    }).join('');
    const rows = list.rows.length ? list.rows.map(function (c) {
      const control = c.revoked
        ? '<span class="sub">revoked ' + esc(c.revoked.at || '') + ' (' +
          esc(c.revoked.reason || '') + ')</span>'
        : '<form method="post" action="/admin/acme">' +
          self.hidden('action', 'revoke-certificate') +
          self.hidden('serial', c.serialHex) +
          '<select name="reason">' + reasons + '</select> <button ' +
          'type="submit" class="danger">Revoke</button></form>';
      return '<tr><td><code>' + esc(c.serialHex) + '</code></td><td>' +
        self.code(c.profile) + '</td><td>' + self.code(c.entryUri) +
        '<div class="sub">' +
        esc((c.names || []).join(', ')) + '</div></td><td>' + esc(c.status) +
        '</td><td>' + esc(c.notAfter) + '</td><td>' + self.code(c.account) +
        '</td><td>' + control + '</td></tr>';
    }).join('') : '<tr><td colspan="7" class="sub">No certificate has been ' +
                  'issued over ACME in this realm.</td></tr>';
    return pager.head + '<table id="list-certificatesPage"><thead><tr><th>' +
      'Serial</th><th>Profile</th><th>Entry and names</th><th>Status</th><th>' +
      'Expires</th><th>Account</th><th></th></tr></thead><tbody>' + rows +
      '</tbody></table>' + pager.foot;
  }

  /**
   * Draws the host names registered on entries, paged, with the add and remove
   * controls.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the view model's answer
   * @returns the markup
   */
  static hostNamesHtml(ctx, json) {
    const self = this;
    const list = json.hostNames;
    const pager = this.nav(ctx, list, 'hostNamesPage');
    const rows = list.rows.length ? list.rows.map(function (h) {
      return '<tr><td>' + self.code(h.entryUri) + '</td><td>' +
        h.hostNames.map(function (name) {
          return '<form method="post" action="/admin/acme" class="inline">' +
            self.hidden('action', 'remove-host-name') +
            self.hidden('kind', h.entry.kind) +
            self.hidden('identifier', h.entry.id) +
            self.hidden('hostName', name) +
            '<code>' + esc(name) + '</code> <button type="submit" ' +
            'class="danger">Remove</button></form>';
        }).join(' ') + '</td></tr>';
    }).join('') : '<tr><td colspan="2" class="sub">No host name is ' +
                  'registered on any entry in this realm.</td></tr>';
    return '<form method="post" action="/admin/acme" class="inline">' +
      this.hidden('action', 'add-host-name') + '<label>On ' +
      this.kindSelect() +
      '</label> <label>identifier <input name="identifier" size="20" ' +
      'required></label> <label>host name or address <input name="hostName" ' +
      'size="28" required></label> <button type="submit">Register</button>' +
      '</form><p class="sub">A dns or ip identifier is authorized for an ' +
      'account only when it is registered on the entry the account is bound ' +
      'to. Nothing is ever fetched to prove control of a name.</p>' +
      pager.head + '<table id="list-hostNamesPage"><thead><tr><th>Entry</th>' +
      '<th>Registered host names</th></tr></thead><tbody>' + rows +
      '</tbody></table>' + pager.foot;
  }

  // ---------------------------------------------------------------------------
  // GET /admin/acme/monitor
  // ---------------------------------------------------------------------------
  /**
   * Draws one table of counts on the monitoring page.
   *
   * @param title - the table's heading
   * @param rows - `{ name, count }` rows
   * @returns the markup
   */
  static countsTable(title, rows) {
    return '<h2>' + esc(title) + '</h2><table><thead><tr><th>Name</th><th>' +
      'Count</th></tr></thead><tbody>' + (rows.length ? rows.map(function (r) {
        return '<tr><td><code>' + esc(r.name) + '</code></td><td class="num">' +
               r.count + '</td></tr>';
      }).join('') : '<tr><td colspan="2" class="sub">none</td></tr>') +
      '</tbody></table>';
  }

  // THE TWO PAGES' BODIES (#446), each one method so that it can be one
  // renderer: Protocols → ACME and Monitoring → ACME enrollments.
  /**
   * Draws Protocols → ACME from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - `acmeView()`'s answer
   * @returns the body as HTML
   */
  static body(ctx, json) {
    const self = this;
    const inner =
      kit.note('<strong>ACME (RFC 8555), one server per trust ' +
        'realm.</strong> A client registers an account with an External ' +
        'Account Binding issued for one person or application, orders ' +
        'certificates for identifiers that ' +
        'entry owns, and finalizes with a ' +
        'CSR. The directory is <a href="' + esc(json.directory) + '"><code>' +
        esc(json.directory) + '</code></a>.' +
        (json.enabled ? '' : ' <strong>ACME is turned off in this realm.' +
                             '</strong>')) +
      kit.warn('<strong>No challenge dials out.</strong> An ' +
                 'authorization is ' +
        'created valid, with one <code>' + esc(json.challengeType) +
        '</code> challenge, for an identifier the bound entry owns — a ' +
        'registered host name, the person\'s mail, the entry itself — and ' +
        'an identifier it does not own is refused at newOrder with ' +
        'rejectedIdentifier. EAB MACs are verified in every mode.') +
      '<h2>Directory</h2><p><code>' + esc(json.directory) + '</code></p>' +
      '<h2>Endpoints</h2>' + self.endpointsHtml(json) +
      '<h2>ACME Issuing CA</h2>' + self.authorityHtml(json) +
      '<h2>Profiles</h2>' + self.profilesHtml(json) +
      '<h2 id="eab">External Account Binding keys</h2>' +
      self.eabHtml(ctx, json) +
      '<h2>Accounts</h2>' + self.accountsHtml(ctx, json) +
      '<h2>Certificates issued over ACME</h2>' +
      self.certificatesHtml(ctx, json) +
      '<h2>Registered host names</h2>' + self.hostNamesHtml(ctx, json) +
      '<h2>Mode</h2>' + kit.note('<strong>' + esc(json.mode.current) +
        '</strong>: ' + esc(json.mode.inForce) + '<div class="sub">' +
        'Development: ' + esc(json.mode.development) + '</div><div ' +
        'class="sub">Product: ' + esc(json.mode.product) + '</div>') +
      '<h2>Settings</h2>' + SettingsForms.forms(json.settings, '/admin/acme') +
      '<p class="links"><a href="/admin/acme?format=json">JSON</a> · ' +
      '<code>GET /admin-api/acme</code> · <a ' +
      'href="/admin/acme/monitor">ACME enrollments (monitoring)</a> · <a ' +
      'href="/admin/pki">PKI</a> · <a href="/admin/error-codes">Error ' +
      'codes</a></p>';
    return inner;
  }

  /**
   * Draws Monitoring → ACME enrollments from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - `acmeMonitorView()`'s answer
   * @returns the body as HTML
   */
  static monitorBody(ctx, json) {
    const self = this;
    const t = json.totals;
    const pager = kit.pageNavPair('/admin/acme/monitor', ctx.query,
                                    Object.assign({}, json.paging,
                                                  { param: 'page',
                                                    noun: 'requests' }));
    const recent = json.recent.length ? json.recent.map(function (r) {
      return '<tr><td>' + esc(r.at) + '</td><td><code>' + esc(r.operation) +
        '</code></td><td>' + esc(r.outcome) + '</td><td class="num">' +
        esc(r.status || '') + '</td><td>' + self.code(r.profile) +
        '</td><td>' +
        self.code(r.principal) + '</td><td>' + self.code(r.target) +
        '</td><td>' +
        self.code(r.errorCode) + '</td><td>' + self.code(r.serialHex) +
        '</td></tr>';
    }).join('') : '<tr><td colspan="9" class="sub">Nothing has been asked ' +
                  'of the ACME server in this realm since the process ' +
                  'started.</td></tr>';
    const inner =
      kit.note('<strong>What the ACME server has done</strong> ' +
        'in this realm since ' + esc(json.since) + ', across ' +
        esc(json.processes) + ' process(es).') +
      '<div class="tiles">' + kit.tile(t.requests, 'requests') +
      kit.tile(t.issued, 'certificates issued') +
      kit.tile(t.revoked, 'revoked') + kit.tile(t.refused, 'refused') +
      kit.tile(t.accountsBound, 'accounts bound') +
      kit.tile(t.accounts, 'accounts held') +
      kit.tile(t.certificatesHeld, 'certificates held') + '</div>' +
      self.countsTable('By operation', json.operations) +
      self.countsTable('By profile', json.profiles) +
      self.countsTable('Refusals by error code', json.errorCodes) +
      self.countsTable('By HTTP status', json.statuses) +
      self.countsTable('Who asked', json.principals) +
      '<h2 id="list-page">Recent requests</h2>' + pager.head +
      '<table><thead><tr><th>At</th><th>Operation</th><th>Outcome</th><th>' +
      'Status</th><th>Profile</th><th>Principal</th><th>Entry</th><th>Code' +
      '</th><th>Serial</th></tr></thead><tbody>' + recent +
      '</tbody></table>' +
      pager.foot +
      kit.note('There is no reset. The durable record of each act is the ' +
                 '<a href="/admin/audit">Audit log</a>.') +
      '<p class="links"><a href="/admin/acme/monitor?format=json">JSON</a> ' +
      '· <code>GET /admin-api/acme/monitor</code> · <a ' +
      'href="/admin/acme">ACME</a></p>';
    return inner;
  }
}

export = AcmePage;
