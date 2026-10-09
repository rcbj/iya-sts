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
   * @param t - the page's translator (#539)
   * @returns the HTML
   */
  static yesNo(flag, t) {
    return flag ? t.html('consoleEst.yes')
                : '<span class="sub">' + t.html('consoleEst.no') + '</span>';
  }

  /**
   * Draws the person-or-application `<option>` elements, the values as they
   * are and the words in the reader's language (#539).
   *
   * @param selected - the value selected
   * @param t - the page's translator
   * @returns the HTML
   */
  static kindOptions(selected, t) {
    return '<option value="person"' +
           (selected === 'person' ? ' selected' : '') + '>' +
           t.html('consoleEst.kindPerson') + '</option>' +
           '<option value="application"' +
           (selected === 'application' ? ' selected' : '') + '>' +
           t.html('consoleEst.kindApplication') + '</option>';
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
    const t = ctx.t;
    // What an endpoint does, the label form's note, a profile's needs, a
    // refusal's reason and a credential's description are the view's,
    // drawn as they come (#539).
    const endpointRows = json.endpoints.map(function (one) {
      return '<tr><td><code>' + esc(one.method) + '</code></td><td><code>' +
             esc(one.url) + '</code>' + (one.labelFormUrl
               ? '<div class="sub">' +
                 t.html('consoleEst.orUrl', { url: one.labelFormUrl }) +
                 '</div>' : '') + '</td><td>' + esc(one.what) +
             '</td><td>RFC 7030 ' + esc(one.section) + '</td></tr>';
    }).join('');
    const labelFormNote = json.labelForm
      ? '<p class="sub">' + t.html('consoleEst.labelForm',
                                   { base: json.labelForm.base }) + ' ' +
        esc(json.labelForm.note) +
        '</p>'
      : '';
    const authority = json.hierarchy.authority;
    const caBlock = json.hierarchy.built && authority
      ? '<table class="kv"><tr><th>' + t.html('consoleEst.subject') +
        '</th><td><code>' +
        esc(authority.subject) + '</code></td></tr><tr><th>' +
        t.html('consoleEst.serial') + '</th><td>' +
        '<code>' + esc(authority.serialHex) + '</code></td></tr><tr><th>' +
        t.html('consoleEst.key') +
        '</th><td>' + esc(authority.keyAlg) + '</td></tr><tr><th>' +
        t.html('consoleEst.valid') +
        '</th><td>' + esc(authority.notBefore) + ' — ' +
        esc(authority.notAfter) + '</td></tr><tr><th>SHA-256</th><td><code>' +
        esc(authority.thumbprint) + '</code></td></tr><tr><th>' +
        t.html('consoleEst.chain') + '</th><td>' +
        t.html('consoleEst.chainNote',
               { n: json.hierarchy.chainPem.length }) + '</td></tr></table>'
      : kit.warn(esc(json.hierarchy.note));
    const profileRows = json.profiles.map(function (one) {
      return '<tr><td><code>' + esc(one.id) + '</code>' +
             (one.isDefault ? ' <span class="sub">' +
                              t.html('consoleEst.unlabelled') + '</span>'
                            : '') +
             '</td><td>' + self.yesNo(one.allowed, t) + '</td><td>' +
             (one.needs ? esc(one.needs) : '<span class="sub">' +
              t.html('consoleEst.nothingBeyond') + '</span>') +
             '</td><td><code>' +
             esc(one.urls.simpleenroll) + '</code><div class="sub">' +
             esc(one.urls.simplereenroll) + '<br>' +
             esc(one.urls.serverkeygen) + '<br>' + esc(one.urls.csrattrs) +
             (one.urls.nonce ? '<br>' + esc(one.urls.nonce) : '') +
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
      '<table class="kv"><tr><th>' + t.html('consoleEst.for') +
      '</th><td><select name="kind">' +
      this.kindOptions('person', t) + '</select> ' +
      '<input type="text" name="identifier" required maxlength="256" ' +
      'placeholder="' + esc(t.text('consoleEst.identifierPlaceholder')) +
      '"></td></tr>' +
      '<tr><th>' + t.html('consoleEst.profile') +
      '</th><td><select name="profile">' +
      this.options(allowedProfiles, json.defaultProfile) +
      '</select></td></tr>' +
      '<tr><th>' + t.html('consoleEst.keyAlgorithm') +
      '</th><td><select name="keyAlg">' +
      this.options(json.keyAlgorithms, 'ec-p256') +
      '</select></td></tr></table><button type="submit">' +
      t.html('consoleEst.issueServerKey') + '</button></form>';
    const hostRows = json.hostNames.length ? json.hostNames.map(function (row) {
      return '<tr><td>' + self.entryLink(row.entry) + '</td><td>' +
        row.hostNames.map(function (name) {
          return '<form method="post" action="/admin/est" class="inline">' +
            self.hidden('action', 'remove-host-name') +
            self.hidden('kind', row.entry.kind) +
            self.hidden('identifier', row.entry.id) +
            self.hidden('hostName', name) + '<code>' + esc(name) + '</code> ' +
            '<button type="submit" class="danger">' +
            t.html('consoleEst.remove') + '</button></form>';
        }).join(' ') + '</td></tr>';
    }).join('') : '<tr><td colspan="2" class="sub">' +
      t.html('consoleEst.noHostNames') + '</td></tr>';
    const hostForm = '<form method="post" action="/admin/est">' +
      this.hidden('action', 'add-host-name') + '<select name="kind">' +
      this.kindOptions('application', t) + '</select> ' +
      '<input type="text" name="identifier" required maxlength="256" ' +
      'placeholder="' + esc(t.text('consoleEst.identifier')) +
      '"> <input type="text" name="hostName" required ' +
      'maxlength="253" placeholder="' +
      esc(t.text('consoleEst.hostPlaceholder')) + '"> ' +
      '<button type="submit">' + t.html('consoleEst.register') +
      '</button></form>';
    const nav = kit.pageNavPair('/admin/est', ctx.query,
      Object.assign({}, json.certificates.paging,
                    { param: 'certificatesPage' }), t);
    const certificateRows = json.certificates.rows.length
      ? json.certificates.rows.map(function (one) {
        const control = one.status === 'revoked'
          ? '<span class="sub">' +
            t.html('consoleEst.revoked',
                   { reason: one.revoked ? one.revoked.reason : '' }) +
            '</span>'
          : '<form method="post" action="/admin/est">' +
            self.hidden('action', 'revoke-certificate') +
            self.hidden('serialHex', one.serialHex) + '<select name="reason">' +
            self.options(json.revocationReasons, 'unspecified') + '</select> ' +
            '<button type="submit" class="danger">' +
            t.html('consoleEst.revoke') + '</button></form>';
        return '<tr><td><code>' + esc(one.serialHex) + '</code></td><td>' +
          self.entryLink(one.entry) + '</td><td><code>' + esc(one.profile) +
          '</code><div class="sub">' + esc(one.keyAlg || '') + ' · ' +
          t.html('consoleEst.keyFrom', { source: one.keySource }) +
          '</div></td><td>' + one.names.map(function (n) {
            return '<code>' + esc(n) + '</code>';
          }).join('<br>') + '</td><td>' + esc(one.status) + '</td><td>' +
          esc(one.notAfter) + '</td><td>' + esc(one.requestedBy
            ? one.requestedBy.kind + ':' + one.requestedBy.id : '') +
          '</td><td>' + control + '</td></tr>';
      }).join('')
      : '<tr><td colspan="8" class="sub">' +
        t.html('consoleEst.nothingEnrolled') + '</td></tr>';
    // The mode's sentences are the view's, drawn as they come.
    const html =
      kit.note(t.html('consoleEst.intro') + ' ' + (json.enabled ? '' :
          t.html('consoleEst.turnedOff'))) +
      kit.warn(t.html('consoleEst.mode', { mode: json.mode.current }) + ' ' +
        t.html('consoleEst.development') + ' ' + esc(json.mode.development) +
        ' ' + t.html('consoleEst.product') + ' ' +
        esc(json.mode.product)) +
      '<h2>' + t.html('consoleEst.hEndpoints') + '</h2><table><thead><tr>' +
      '<th>' + t.html('consoleEst.thMethod') + '</th><th>URL</th><th>' +
      t.html('consoleEst.thWhat') + '</th><th>' +
      t.html('consoleEst.thSection') + '</th></tr></thead><tbody>' +
      endpointRows +
      '</tbody></table>' + labelFormNote +
      '<h2>' + t.html('consoleEst.hIssuingCa') + '</h2>' + caBlock +
      '<h2>' + t.html('consoleEst.hProfiles') + '</h2><p class="sub">' +
      t.html('consoleEst.profilesNote', { profile: json.defaultProfile }) +
      '</p><table><thead><tr><th>' + t.html('consoleEst.profile') +
      '</th><th>' + t.html('consoleEst.thAllowed') + '</th><th>' +
      t.html('consoleEst.thNeeds') + '</th><th>' +
      t.html('consoleEst.thLabelledUrls') + '</th></tr></thead><tbody>' +
      profileRows +
      '</tbody></table>' +
      '<h3>' + t.html('consoleEst.hNeverIssued') +
      '</h3><table><thead><tr><th>' + t.html('consoleEst.profile') +
      '</th><th>' + t.html('consoleEst.thWhy') +
      '</th></tr></thead><tbody>' + refusedRows + '</tbody></table>' +
      '<h2>' + t.html('consoleEst.hCredentials') + '</h2><p class="sub">' +
      t.html('consoleEst.noCredential') + ' ' +
      'Basic ' + this.yesNo(json.authentication.basic, t) +
      ', ' + t.html('consoleEst.clientCertificates') + ' ' +
      this.yesNo(json.authentication.certificate, t) + ', /serverkeygen ' +
      this.yesNo(json.authentication.serverKeyGeneration, t) +
      '.</p><table><thead><tr><th>' + t.html('consoleEst.thCredential') +
      '</th><th>' + t.html('consoleEst.thWhat') + '</th><th>' +
      t.html('consoleEst.thManagedAt') +
      '</th></tr></thead><tbody>' + credentialRows + '</tbody></table>' +
      '<h2>' + t.html('consoleEst.hIssue') + '</h2><p ' +
      'class="sub">' + t.html('consoleEst.issueNote') + '</p>' +
      issueForm +
      '<h2>' + t.html('consoleEst.hHostNames') + '</h2><p class="sub">' +
      t.html('consoleEst.hostNamesNote') + '</p><table><thead>' +
      '<tr><th>' + t.html('consoleEst.thEntry') + '</th><th>' +
      t.html('consoleEst.thHostNames') + '</th></tr></thead><tbody>' +
      hostRows +
      '</tbody></table>' + hostForm +
      '<h2 id="list-certificatesPage">' + t.html('consoleEst.hEnrolled') +
      '</h2>' + nav.head +
      '<table><thead><tr><th>' + t.html('consoleEst.serial') + '</th><th>' +
      t.html('consoleEst.thEntry') + '</th><th>' +
      t.html('consoleEst.profile') + '</th><th>' +
      t.html('consoleEst.thNames') + '</th><th>' +
      t.html('consoleEst.thStatus') + '</th><th>' +
      t.html('consoleEst.thExpires') + '</th><th>' +
      t.html('consoleEst.thRequestedBy') + '</th><th>' +
      '</th></tr></thead><tbody>' + certificateRows + '</tbody></table>' +
      nav.foot +
      '<h2>' + t.html('consoleEst.hSettings') + '</h2>' +
      SettingsForms.forms(json.settings, '/admin/est', undefined, t) +
      '<p class="links"><a href="/admin/est?format=json">JSON</a> · ' +
      '<code>GET /admin-api/est</code> · <a href="/admin/est/monitor">' +
      t.html('consoleEst.linkMonitor') +
      '</a> · <a href="/admin/pki">PKI</a> · <a ' +
      'href="/admin/error-codes">' + t.html('consoleEst.linkErrorCodes') +
      '</a></p>';
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
   * @param t - the page's translator (#539)
   * @returns the HTML
   */
  static countTable(title, rows, t) {
    return '<h3>' + esc(title) + '</h3><table><tbody>' + (rows.length
      ? rows.map(function (row) {
        return '<tr><td><code>' + esc(row.name) + '</code></td><td ' +
               'class="num">' + row.count + '</td></tr>';
      }).join('')
      : '<tr><td class="sub">' + t.html('consoleEst.noneYet') +
        '</td></tr>') + '</tbody></table>';
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
    // The translator is `t` (#539), so the totals, which were `t`, are
    // `totals`.
    const t = ctx.t;
    const totals = json.totals;
    const tiles = '<div class="tiles">' +
      kit.tile(totals.requests, t.text('consoleEst.tileRequests')) +
      kit.tile(totals.issued, t.text('consoleEst.tileIssued')) +
      kit.tile(totals.refused, t.text('consoleEst.tileRefused')) +
      kit.tile(totals.revoked, t.text('consoleEst.tileRevoked')) +
      kit.tile(json.certificates.valid, t.text('consoleEst.tileValid')) +
      kit.tile(json.certificates.revoked,
               t.text('consoleEst.tileRevokedCertificates')) +
      '</div>';
    const nav = kit.pageNavPair('/admin/est/monitor', ctx.query,
      Object.assign({}, json.paging, { param: 'page' }), t);
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
    }).join('') : '<tr><td colspan="9" class="sub">' +
      t.html('consoleEst.noRequest') + '</td></tr>';
    // The audit log's link is markup a message cannot carry, so the
    // sentence is cut at it.
    const inner =
      kit.note(t.html('consoleEst.monitorIntro',
                      { since: json.since ||
                          t.text('consoleEst.processStarted'),
                        n: json.processes }) +
        ' <a href="/admin/audit">' + t.html('consoleEst.auditLog') +
        '</a>.') + tiles +
      self.countTable(t.text('consoleEst.byOperation'), json.operations, t) +
      self.countTable(t.text('consoleEst.byProfile'), json.profiles, t) +
      self.countTable(t.text('consoleEst.byPrincipal'), json.principals, t) +
      self.countTable(t.text('consoleEst.byErrorCode'), json.errorCodes, t) +
      self.countTable(t.text('consoleEst.byStatus'), json.statuses, t) +
      '<h2 id="list-page">' + t.html('consoleEst.recent') + '</h2>' +
      nav.head +
      '<table><thead><tr><th>' + t.html('consoleEst.thAt') + '</th><th>' +
      t.html('consoleEst.thOperation') + '</th><th>' +
      t.html('consoleEst.thOutcome') + '</th><th>' +
      t.html('consoleEst.thStatus') + '</th><th>' +
      t.html('consoleEst.profile') + '</th><th>' +
      t.html('consoleEst.thPrincipal') + '</th><th>' +
      t.html('consoleEst.thTarget') + '</th><th>' +
      t.html('consoleEst.thCode') +
      '</th><th>' + t.html('consoleEst.serial') + '</th></tr></thead><tbody>' +
      recentRows +
      '</tbody></table>' + nav.foot +
      kit.note(t.html('consoleEst.noReset')) +
      '<p class="links"><a href="/admin/est/monitor?format=json">JSON</a> ' +
      '· <code>GET /admin-api/est/monitor</code> · <a ' +
      'href="/admin/est">EST</a></p>';
    return inner;
  }
}

export = EstPage;
