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
                                           { param: param, noun: 'rows' }),
                           ctx.t);
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
   * @param t - the page's translator (#539)
   * @returns the markup
   */
  static kindSelect(t) {
    return '<select name="kind"><option value="person">' +
           t.html('consoleAcme.kindPerson') + '</option>' +
           '<option value="application">' +
           t.html('consoleAcme.kindApplication') + '</option></select>';
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
   * @param t - the page's translator (#539)
   * @returns the markup
   */
  static authorityHtml(json, t) {
    const a = json.authority;
    // The note is the view's sentence, drawn as it comes.
    if (!a.present) {
      return kit.warn(esc(a.note));
    }
    // The link is markup a message cannot carry, so the sentence is cut at
    // it; the CRL's path goes in as a parameter because of its braces.
    return '<table class="kv"><tr><th>' + t.html('consoleAcme.subject') +
      '</th><td>' + this.code(a.subject) +
      '</td></tr><tr><th>' + t.html('consoleAcme.serial') + '</th><td>' +
      this.code(a.serialHex) +
      '</td></tr>' +
      '<tr><th>' + t.html('consoleAcme.keySignsWith') + '</th><td>' +
      this.code(a.keyAlg) + ' / ' +
      this.code(a.signatureAlg) + '</td></tr><tr><th>' +
      t.html('consoleAcme.validUntil') + '</th><td>' +
      esc(a.notAfter) + '</td></tr><tr><th>' + t.html('consoleAcme.under') +
      '</th><td>' +
      this.code(a.intermediate) + ' &larr; ' + this.code(a.root) +
      '</td></tr></table>' +
      '<p class="sub">' + t.html('consoleAcme.servedWith') +
      ' <a href="/admin/pki">PKI</a> ' +
      t.html('consoleAcme.managesHierarchy',
             { crl: '/pki/crl/{realm}/acme' }) + '</p>';
  }

  /**
   * Draws the certificate profiles and the refused ones.
   *
   * @param json - the view model's answer
   * @param t - the page's translator (#539)
   * @returns the markup
   */
  static profilesHtml(json, t) {
    // A profile's description and needs, and a refused one's reason, are
    // the view's, drawn as they come.
    const rows = json.profiles.map(function (p) {
      return '<tr><td><code>' + esc(p.id) + '</code>' +
        (p.isDefault ? ' <span class="sub">' + t.html('consoleAcme.default') +
                       '</span>' : '') + '</td><td>' +
        esc(p.description) + '</td><td>' + (p.needs ? esc(p.needs) :
                                             '<span class="sub">—</span>') +
        '</td><td>' + (p.allowed ? t.html('consoleAcme.yes')
                                 : t.html('consoleAcme.no') + ' ' +
                       '<span class="sub">' +
                       t.html('consoleAcme.notAllowed') + '</span>') +
        '</td></tr>';
    }).join('');
    const refused = json.refusedProfiles.map(function (p) {
      return '<tr><td><code>' + esc(p.id) + '</code></td><td colspan="3">' +
             t.html('consoleAcme.neverIssued') + ' ' + esc(p.why) +
             '</td></tr>';
    }).join('');
    return '<table><thead><tr><th>' + t.html('consoleAcme.thProfile') +
           '</th><th>' + t.html('consoleAcme.thWhat') + '</th><th>' +
           t.html('consoleAcme.thNeeds') + '</th>' +
           '<th>' + t.html('consoleAcme.thAllowed') + '</th></tr></thead>' +
           '<tbody>' + rows + refused +
           '</tbody></table><p class="sub">' +
           t.html('consoleAcme.profilesNote') + '</p>';
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
    const t = ctx.t;
    const list = json.eabKeys;
    const pager = this.nav(ctx, list, 'credentialsPage');
    const rows = list.rows.length ? list.rows.map(function (k) {
      return '<tr><td><code>' + esc(k.kid) + '</code></td><td>' +
        self.code(k.entryUri) + '</td><td>' + esc(k.status) + '</td><td>' +
        esc(k.createdAt) + '<div class="sub">' +
        t.html('consoleAcme.by', { who: k.createdBy || '—' }) +
        '</div></td><td>' + esc(k.expiresAt) + '</td><td>' +
        self.code(k.boundAccount) + '</td><td><form method="post" ' +
        'action="/admin/acme">' + self.hidden('action', 'delete-eab') +
        self.hidden('kid', k.kid) +
        '<button type="submit" class="danger">' +
        t.html('consoleAcme.delete') +
        '</button></form></td></tr>';
    }).join('') : '<tr><td colspan="7" class="sub">' +
                  t.html('consoleAcme.noEab') + '</td></tr>';
    return '<form method="post" action="/admin/acme" class="inline">' +
      this.hidden('action', 'create-eab') + '<label>' +
      t.html('consoleAcme.for') + ' ' + this.kindSelect(t) +
      '</label> <label>' + t.html('consoleAcme.identifier') +
      ' <input name="identifier" size="24" ' +
      'required></label> <label>' + t.html('consoleAcme.lifetime') +
      ' <input name="lifetimeS" ' +
      'size="8" placeholder="' + esc(String(json.eabLifetimeS || '')) +
      '"></label> <button type="submit">' + t.html('consoleAcme.createEab') +
      '</button></form>' +
      '<p class="sub">' + t.html('consoleAcme.eabNote') + '</p>' +
      pager.head +
      '<table id="list-credentialsPage"><thead><tr><th>' +
      t.html('consoleAcme.thKeyId') + '</th><th>' +
      t.html('consoleAcme.thEntry') +
      '</th><th>' + t.html('consoleAcme.thStatus') + '</th><th>' +
      t.html('consoleAcme.thCreated') + '</th><th>' +
      t.html('consoleAcme.thExpires') + '</th><th>' +
      t.html('consoleAcme.thBoundAccount') +
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
    const t = ctx.t;
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
         '<button type="submit" class="danger">' +
         t.html('consoleAcme.deactivate') + '</button></form>'
                              : '<span class="sub">' + esc(a.status) +
                                '</span>') + '</td></tr>';
    }).join('') : '<tr><td colspan="8" class="sub">' +
                  t.html('consoleAcme.noAccount') + '</td></tr>';
    return pager.head + '<table id="list-accountsPage"><thead><tr><th>' +
      t.html('consoleAcme.thAccount') +
      '</th><th>' + t.html('consoleAcme.thBoundTo') + '</th><th>' +
      t.html('consoleAcme.thStatus') + '</th><th>' +
      t.html('consoleAcme.thEabKey') + '</th><th>' +
      t.html('consoleAcme.thContact') + '</th>' +
      '<th>' + t.html('consoleAcme.thOrders') + '</th><th>' +
      t.html('consoleAcme.thCreated') + '</th><th></th></tr></thead><tbody>' +
      rows +
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
    const t = ctx.t;
    const list = json.certificates;
    const pager = this.nav(ctx, list, 'certificatesPage');
    const reasons = json.revocationReasons.map(function (r) {
      return '<option value="' + esc(r) + '">' + esc(r) + '</option>';
    }).join('');
    const rows = list.rows.length ? list.rows.map(function (c) {
      const control = c.revoked
        ? '<span class="sub">' +
          t.html('consoleAcme.revokedAt', { at: c.revoked.at || '',
                                            reason: c.revoked.reason || '' }) +
          '</span>'
        : '<form method="post" action="/admin/acme">' +
          self.hidden('action', 'revoke-certificate') +
          self.hidden('serial', c.serialHex) +
          '<select name="reason">' + reasons + '</select> <button ' +
          'type="submit" class="danger">' + t.html('consoleAcme.revoke') +
          '</button></form>';
      return '<tr><td><code>' + esc(c.serialHex) + '</code></td><td>' +
        self.code(c.profile) + '</td><td>' + self.code(c.entryUri) +
        '<div class="sub">' +
        esc((c.names || []).join(', ')) + '</div></td><td>' + esc(c.status) +
        '</td><td>' + esc(c.notAfter) + '</td><td>' + self.code(c.account) +
        '</td><td>' + control + '</td></tr>';
    }).join('') : '<tr><td colspan="7" class="sub">' +
                  t.html('consoleAcme.noCertificate') + '</td></tr>';
    return pager.head + '<table id="list-certificatesPage"><thead><tr><th>' +
      t.html('consoleAcme.serial') + '</th><th>' +
      t.html('consoleAcme.thProfile') + '</th><th>' +
      t.html('consoleAcme.thEntryNames') + '</th><th>' +
      t.html('consoleAcme.thStatus') + '</th><th>' +
      t.html('consoleAcme.thExpires') + '</th><th>' +
      t.html('consoleAcme.thAccount') + '</th><th></th></tr></thead><tbody>' +
      rows +
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
    const t = ctx.t;
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
            'class="danger">' + t.html('consoleAcme.remove') +
            '</button></form>';
        }).join(' ') + '</td></tr>';
    }).join('') : '<tr><td colspan="2" class="sub">' +
                  t.html('consoleAcme.noHostName') + '</td></tr>';
    return '<form method="post" action="/admin/acme" class="inline">' +
      this.hidden('action', 'add-host-name') + '<label>' +
      t.html('consoleAcme.on') + ' ' +
      this.kindSelect(t) +
      '</label> <label>' + t.html('consoleAcme.identifier') +
      ' <input name="identifier" size="20" ' +
      'required></label> <label>' + t.html('consoleAcme.hostNameLabel') +
      ' <input name="hostName" ' +
      'size="28" required></label> <button type="submit">' +
      t.html('consoleAcme.register') + '</button>' +
      '</form><p class="sub">' + t.html('consoleAcme.hostNameNote') + '</p>' +
      pager.head + '<table id="list-hostNamesPage"><thead><tr><th>' +
      t.html('consoleAcme.thEntry') + '</th>' +
      '<th>' + t.html('consoleAcme.thHostNames') +
      '</th></tr></thead><tbody>' + rows +
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
   * @param t - the page's translator (#539)
   * @returns the markup
   */
  static countsTable(title, rows, t) {
    return '<h2>' + esc(title) + '</h2><table><thead><tr><th>' +
      t.html('consoleAcme.thName') + '</th><th>' +
      t.html('consoleAcme.thCount') + '</th></tr></thead><tbody>' +
      (rows.length ? rows.map(function (r) {
        return '<tr><td><code>' + esc(r.name) + '</code></td><td class="num">' +
               r.count + '</td></tr>';
      }).join('') : '<tr><td colspan="2" class="sub">' +
                    t.html('consoleAcme.none') + '</td></tr>') +
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
    const t = ctx.t;
    // The directory link is markup a message cannot carry, so the first
    // note is cut at it. The mode's sentences are the view's.
    const inner =
      kit.note(t.html('consoleAcme.intro') + ' <a href="' +
        esc(json.directory) + '"><code>' +
        esc(json.directory) + '</code></a>.' +
        (json.enabled ? '' : ' ' + t.html('consoleAcme.turnedOff'))) +
      kit.warn(t.html('consoleAcme.noDialOut',
                      { challenge: json.challengeType })) +
      '<h2>' + t.html('consoleAcme.hDirectory') + '</h2><p><code>' +
      esc(json.directory) + '</code></p>' +
      '<h2>' + t.html('consoleAcme.hEndpoints') + '</h2>' +
      self.endpointsHtml(json) +
      '<h2>' + t.html('consoleAcme.hIssuingCa') + '</h2>' +
      self.authorityHtml(json, t) +
      '<h2>' + t.html('consoleAcme.hProfiles') + '</h2>' +
      self.profilesHtml(json, t) +
      '<h2 id="eab">' + t.html('consoleAcme.hEab') + '</h2>' +
      self.eabHtml(ctx, json) +
      '<h2>' + t.html('consoleAcme.hAccounts') + '</h2>' +
      self.accountsHtml(ctx, json) +
      '<h2>' + t.html('consoleAcme.hCertificates') + '</h2>' +
      self.certificatesHtml(ctx, json) +
      '<h2>' + t.html('consoleAcme.hHostNames') + '</h2>' +
      self.hostNamesHtml(ctx, json) +
      '<h2>' + t.html('consoleAcme.hMode') + '</h2>' +
      kit.note('<strong>' + esc(json.mode.current) +
        '</strong>: ' + esc(json.mode.inForce) + '<div class="sub">' +
        t.html('consoleAcme.development') + ' ' +
        esc(json.mode.development) + '</div><div ' +
        'class="sub">' + t.html('consoleAcme.product') + ' ' +
        esc(json.mode.product) + '</div>') +
      '<h2>' + t.html('consoleAcme.hSettings') + '</h2>' +
      SettingsForms.forms(json.settings, '/admin/acme', undefined, t) +
      '<p class="links"><a href="/admin/acme?format=json">JSON</a> · ' +
      '<code>GET /admin-api/acme</code> · <a ' +
      'href="/admin/acme/monitor">' + t.html('consoleAcme.linkMonitor') +
      '</a> · <a ' +
      'href="/admin/pki">PKI</a> · <a href="/admin/error-codes">' +
      t.html('consoleAcme.linkErrorCodes') + '</a></p>';
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
    // The translator is `t` (#539), so the totals, which were `t`, are
    // `totals`.
    const t = ctx.t;
    const totals = json.totals;
    const pager = kit.pageNavPair('/admin/acme/monitor', ctx.query,
                                    Object.assign({}, json.paging,
                                                  { param: 'page',
                                                    noun: 'requests' }), t);
    const recent = json.recent.length ? json.recent.map(function (r) {
      return '<tr><td>' + esc(r.at) + '</td><td><code>' + esc(r.operation) +
        '</code></td><td>' + esc(r.outcome) + '</td><td class="num">' +
        esc(r.status || '') + '</td><td>' + self.code(r.profile) +
        '</td><td>' +
        self.code(r.principal) + '</td><td>' + self.code(r.target) +
        '</td><td>' +
        self.code(r.errorCode) + '</td><td>' + self.code(r.serialHex) +
        '</td></tr>';
    }).join('') : '<tr><td colspan="9" class="sub">' +
                  t.html('consoleAcme.nothingAsked') + '</td></tr>';
    const inner =
      kit.note(t.html('consoleAcme.monitorIntro',
                      { since: json.since, n: json.processes })) +
      '<div class="tiles">' +
      kit.tile(totals.requests, t.text('consoleAcme.tileRequests')) +
      kit.tile(totals.issued, t.text('consoleAcme.tileIssued')) +
      kit.tile(totals.revoked, t.text('consoleAcme.tileRevoked')) +
      kit.tile(totals.refused, t.text('consoleAcme.tileRefused')) +
      kit.tile(totals.accountsBound, t.text('consoleAcme.tileBound')) +
      kit.tile(totals.accounts, t.text('consoleAcme.tileAccounts')) +
      kit.tile(totals.certificatesHeld,
               t.text('consoleAcme.tileCertificates')) + '</div>' +
      self.countsTable(t.text('consoleAcme.byOperation'), json.operations,
                       t) +
      self.countsTable(t.text('consoleAcme.byProfile'), json.profiles, t) +
      self.countsTable(t.text('consoleAcme.byErrorCode'), json.errorCodes,
                       t) +
      self.countsTable(t.text('consoleAcme.byStatus'), json.statuses, t) +
      self.countsTable(t.text('consoleAcme.whoAsked'), json.principals, t) +
      '<h2 id="list-page">' + t.html('consoleAcme.recent') + '</h2>' +
      pager.head +
      '<table><thead><tr><th>' + t.html('consoleAcme.thAt') + '</th><th>' +
      t.html('consoleAcme.thOperation') + '</th><th>' +
      t.html('consoleAcme.thOutcome') + '</th><th>' +
      t.html('consoleAcme.thStatus') + '</th><th>' +
      t.html('consoleAcme.thProfile') + '</th><th>' +
      t.html('consoleAcme.thPrincipal') + '</th><th>' +
      t.html('consoleAcme.thEntry') + '</th><th>' +
      t.html('consoleAcme.thCode') +
      '</th><th>' + t.html('consoleAcme.serial') +
      '</th></tr></thead><tbody>' + recent +
      '</tbody></table>' +
      pager.foot +
      kit.note(t.html('consoleAcme.noReset') +
                 ' <a href="/admin/audit">' + t.html('consoleAcme.auditLog') +
                 '</a>.') +
      '<p class="links"><a href="/admin/acme/monitor?format=json">JSON</a> ' +
      '· <code>GET /admin-api/acme/monitor</code> · <a ' +
      'href="/admin/acme">ACME</a></p>';
    return inner;
  }
}

export = AcmePage;
