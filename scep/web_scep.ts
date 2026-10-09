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
   * @param t - the page's translator (#539)
   * @returns the markup
   */
  static none(text, t) {
    return '<span class="sub">' +
           esc(text || t.text('consoleScep.none')) + '</span>';
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
   * @param t - the page's translator (#539)
   * @returns the markup
   */
  static entryLink(entry, uri, t) {
    if (!entry) {
      return this.none(t.text('consoleScep.none'), t);
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
   * @param t - the page's translator (#539)
   * @returns the markup
   */
  static kindSelect(t) {
    return '<select name="kind"><option value="person">' +
           t.html('consoleScep.kindPerson') + '</option>' +
           '<option value="application">' +
           t.html('consoleScep.kindApplication') + '</option></select>';
  }

  /**
   * Draws the endpoints section.
   *
   * @param json - the view
   * @param t - the page's translator (#539)
   * @returns the markup
   */
  static sectionEndpoints(json, t) {
    const self = this;
    const rows = Object.keys(json.endpoints).map(function (name) {
      return '<tr><th>' + esc(name) + '</th><td>' +
             self.code(json.endpoints[name]) + '</td></tr>';
    }).join('');
    return '<h2>' + t.html('consoleScep.hEndpoints') +
      '</h2><table class="kv">' + rows +
      '<tr><th>' + t.html('consoleScep.capsAnswers') + '</th><td>' +
      json.capabilities.map(this.code.bind(this)).join(' ') + '</td></tr>' +
      '<tr><th>' + t.html('consoleScep.messagesAnswered') + '</th><td>' +
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
   * @param t - the page's translator (#539)
   * @returns the markup
   */
  static sectionAuthority(json, t) {
    const a = json.authority;
    const r = json.ra;
    // The authority's note is the view's, drawn as it comes.
    const authority = a
      ? '<table class="kv"><tr><th>' + t.html('consoleScep.subject') +
        '</th><td>' + this.code(a.subject) +
        '</td></tr><tr><th>' + t.html('consoleScep.serial') + '</th><td>' +
        this.code(a.serialHex) +
        '</td></tr><tr><th>' + t.html('consoleScep.key') + '</th><td>' +
        t.html('consoleScep.keySigns', { key: a.keyAlg,
                                         signature: a.signatureAlg }) +
        '</td></tr><tr><th>' + t.html('consoleScep.validUntil') +
        '</th><td>' +
        esc(a.notAfter) + '</td></tr><tr><th>' + t.html('consoleScep.chain') +
        '</th><td>' +
        (a.intermediate ? this.code(a.intermediate.subject) : '') + ' → ' +
        (a.root ? this.code(a.root.subject) : '') + '</td></tr></table>'
      : kit.warn(esc(json.authorityNote));
    const raTable = r.present
      ? '<table class="kv"><tr><th>' + t.html('consoleScep.subject') +
        '</th><td>' + this.code(r.subject) +
        '</td></tr><tr><th>' + t.html('consoleScep.serial') + '</th><td>' +
        this.code(r.serialHex) +
        '</td></tr><tr><th>' + t.html('consoleScep.key') + '</th><td>' +
        esc(r.keyAlgorithm) +
        (r.keyAlgorithm !== r.wantedKeyAlgorithm
          ? ' <span class="sub">' +
            t.html('consoleScep.raKeyIs', { alg: r.wantedKeyAlgorithm }) +
            '</span>' : '') +
        '</td></tr><tr><th>' + t.html('consoleScep.validUntil') +
        '</th><td>' + esc(r.notAfter) +
        '</td></tr><tr><th>' + t.html('consoleScep.status') + '</th><td>' +
        esc(r.status) +
        '</td></tr></table>'
      : '<p class="sub">' + t.html('consoleScep.noRa',
                                   { alg: r.keyAlgorithm }) + '</p>';
    return '<h2>' + t.html('consoleScep.hIssuingCa') + '</h2>' + authority +
      '<h2>' + t.html('consoleScep.hRa') + '</h2>' +
      kit.note(t.html('consoleScep.raNote')) + raTable +
      '<form method="post" action="/admin/scep">' +
      this.hidden('action', 'reissue-ra') +
      '<button type="submit">' + t.html('consoleScep.reissueRa') +
      '</button></form>';
  }

  /**
   * Draws the profiles section: each profile, whether it is allowed and what it
   * needs.
   *
   * @param json - the view
   * @param t - the page's translator (#539)
   * @returns the markup
   */
  static sectionProfiles(json, t) {
    const self = this;
    // A profile's needs and keys and a refusal's reason are the view's.
    const rows = json.profiles.map(function (p) {
      return '<tr><td>' + self.code(p.id) + '</td><td>' +
        (p.allowed ? t.html('consoleScep.yes') : t.html('consoleScep.no')) +
        '</td><td>' +
        (p.needs ? esc(p.needs)
                 : self.none(t.text('consoleScep.nothingBeyond'), t)) +
        '</td><td>' + esc(p.keys) + '</td><td>' + self.code(p.url) +
        '</td></tr>';
    }).join('');
    const refused = json.refusedProfiles.map(function (p) {
      return '<tr><td>' + self.code(p.id) + '</td><td>' + esc(p.why) +
             '</td></tr>';
    }).join('');
    return '<h2>' + t.html('consoleScep.hProfiles') +
      '</h2><table><thead><tr><th>' + t.html('consoleScep.thProfile') +
      '</th><th>' + t.html('consoleScep.thAllowed') + '</th><th>' +
      t.html('consoleScep.thNeeds') + '</th><th>' +
      t.html('consoleScep.thKeys') + '</th><th>' +
      t.html('consoleScep.thUrl') + '</th></tr></thead><tbody>' + rows +
      '</tbody></table>' +
      '<h3>' + t.html('consoleScep.hNeverIssued') + '</h3><table><thead><tr>' +
      '<th>' + t.html('consoleScep.thProfile') + '</th><th>' +
      t.html('consoleScep.thWhy') + '</th></tr></thead><tbody>' + refused +
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
    const t = ctx.t;
    const nav = kit.pageNavPair('/admin/scep', ctx.query,
      Object.assign({}, json.challenges.paging, { param: 'credentialsPage' }),
      t);
    const rows = json.challenges.rows.length
      ? json.challenges.rows.map(function (c) {
        return '<tr><td>' + self.code(c.id) + '</td><td>' +
               self.entryLink(c.entry, c.entryUri, t) +
          '</td><td>' + self.code(c.profile) + '</td><td>' + esc(c.status) +
          '</td><td>' + esc(c.expiresAt) + '</td><td>' +
          esc(c.createdBy || '—') + '</td><td><form method="post" ' +
          'action="/admin/scep">' + self.hidden('action', 'delete-challenge') +
          self.hidden('id', c.id) +
          '<button type="submit" class="danger">' +
          t.html('consoleScep.delete') +
          '</button></form></td></tr>';
      }).join('')
      : '<tr><td colspan="7" class="sub">' +
        t.html('consoleScep.noChallenges') + '</td></tr>';
    const options = json.profiles.filter(function (p) {
      return p.allowed;
    }).map(function (p) {
      return '<option value="' + esc(p.id) + '"' +
        (p.id === json.defaultProfile ? ' selected' : '') + '>' + esc(p.id) +
        '</option>';
    }).join('');
    return '<h2 id="list-credentialsPage">' +
      t.html('consoleScep.hChallenges') + '</h2>' +
      kit.note(t.html('consoleScep.challengesNote')) +
      '<form method="post" action="/admin/scep" class="inline">' +
      this.hidden('action', 'create-challenge') + this.kindSelect(t) +
      ' <input name="identifier" placeholder="' +
      esc(t.text('consoleScep.identifierPlaceholder')) + '" ' +
      'required> <select name="profile">' + options + '</select> ' +
      '<input name="lifetimeS" type="number" min="60" placeholder="' +
      esc(t.text('consoleScep.lifetimePlaceholder')) +
      '"> <button type="submit">' + t.html('consoleScep.createChallenge') +
      '</button></form>' +
      nav.head + '<table><thead><tr><th>' + t.html('consoleScep.thId') +
      '</th><th>' + t.html('consoleScep.thFor') + '</th><th>' +
      t.html('consoleScep.thProfile') + '</th>' +
      '<th>' + t.html('consoleScep.status') + '</th><th>' +
      t.html('consoleScep.thExpires') + '</th><th>' +
      t.html('consoleScep.thCreatedBy') + '</th><th></th></tr>' +
      '</thead><tbody>' + rows + '</tbody></table>' + nav.foot;
  }

  /**
   * Draws the registered host names section with its add and remove forms.
   *
   * @param json - the view
   * @param t - the page's translator (#539)
   * @returns the markup
   */
  static sectionHostNames(json, t) {
    const self = this;
    const rows = json.hostNames.length
      ? json.hostNames.map(function (h) {
        return '<tr><td>' + self.entryLink(h.entry, h.entryUri, t) +
          '</td><td>' +
          h.hostNames.map(function (name) {
            return self.code(name) +
                   ' <form method="post" action="/admin/scep" ' +
              'class="inline">' + self.hidden('action', 'remove-host-name') +
              self.hidden('kind', h.entry.kind) +
              self.hidden('identifier', h.entry.id) +
              self.hidden('hostName', name) + '<button type="submit" ' +
              'class="danger">' + t.html('consoleScep.remove') +
              '</button></form>';
          }).join('<br>') + '</td></tr>';
      }).join('')
      : '<tr><td colspan="2" class="sub">' +
        t.html('consoleScep.noHostNames') + '</td></tr>';
    return '<h2>' + t.html('consoleScep.hHostNames') + '</h2>' +
      kit.note(t.html('consoleScep.hostNamesNote')) +
      '<form method="post" action="/admin/scep" class="inline">' +
      this.hidden('action', 'add-host-name') + this.kindSelect(t) +
      ' <input name="identifier" placeholder="' +
      esc(t.text('consoleScep.identifierPlaceholder')) + '" ' +
      'required> <input name="hostName" placeholder="host.example.com" ' +
      'required> <button type="submit">' + t.html('consoleScep.register') +
      '</button></form>' +
      '<table><thead><tr><th>' + t.html('consoleScep.thEntry') + '</th><th>' +
      t.html('consoleScep.thHostNames') + '</th></tr></thead>' +
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
    const t = ctx.t;
    const nav = kit.pageNavPair('/admin/scep', ctx.query,
      Object.assign({}, json.certificates.paging,
                    { param: 'certificatesPage' }), t);
    const reasons = json.revokeReasons.map(function (r) {
      return '<option value="' + esc(r) + '">' + esc(r) + '</option>';
    }).join('');
    const rows = json.certificates.rows.length
      ? json.certificates.rows.map(function (c) {
        const control = c.status === 'revoked'
          ? self.none(t.text('consoleScep.revoked',
                             { reason: (c.revoked && c.revoked.reason) ||
                                       '' }), t)
          : '<form method="post" action="/admin/scep" class="inline">' +
            self.hidden('action', 'revoke-certificate') +
            self.hidden('serial', c.serialHex) + '<select name="reason">' +
            reasons + '</select> <button type="submit" class="danger">' +
            t.html('consoleScep.revoke') + '</button></form>';
        return '<tr><td>' + self.code(c.serialHex) + '</td><td>' +
          self.entryLink(c.entry, c.entryUri, t) + '</td><td>' +
          self.code(c.profile) +
          '</td><td>' +
          esc(c.keyAlg) + '</td><td>' + esc(c.status) + '</td><td>' +
          esc(c.notAfter) + '</td><td>' + control + '</td></tr>';
      }).join('')
      : '<tr><td colspan="7" class="sub">' +
        t.html('consoleScep.nothingIssued') + '</td></tr>';
    return '<h2 id="list-certificatesPage">' +
      t.html('consoleScep.hEnrolled') + '</h2>' +
      nav.head + '<table><thead><tr><th>' + t.html('consoleScep.serial') +
      '</th><th>' + t.html('consoleScep.thFor') + '</th><th>' +
      t.html('consoleScep.thProfile') +
      '</th><th>' + t.html('consoleScep.key') + '</th><th>' +
      t.html('consoleScep.status') + '</th><th>' +
      t.html('consoleScep.thExpires') + '</th><th></th></tr></thead>' +
      '<tbody>' + rows + '</tbody></table>' + nav.foot;
  }

  /**
   * Draws what SCEP here does not do, and the mode's note.
   *
   * @param json - the view
   * @param t - the page's translator (#539)
   * @returns the markup
   */
  static sectionExceptions(json, t) {
    // The exceptions and the mode's sentences are the view's.
    const rows = json.exceptions.map(function (x) {
      return '<tr><th>' + esc(x.what) + '</th><td>' + esc(x.why) + '</td></tr>';
    }).join('');
    const m = json.mode;
    return '<h2>' + t.html('consoleScep.hNotDo') +
      '</h2><table class="kv">' + rows +
      '</table><h2>' + t.html('consoleScep.hMode') + '</h2>' +
      kit.note(t.html('consoleScep.realmMode', { mode: m.mode }) + ' ' +
        esc(m.scep) +
        (m.requirement ? ' ' + t.html('consoleScep.development') + ' ' +
         esc(m.requirement.development) +
         ' ' + t.html('consoleScep.product') + ' ' +
         esc(m.requirement.product) : ''));
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
    const t = ctx.t;
    const inner =
      kit.note(t.html('consoleScep.intro') + ' ' +
        (json.enabled ? '' : t.html('consoleScep.turnedOff'))) +
      this.sectionEndpoints(json, t) + this.sectionAuthority(json, t) +
      this.sectionProfiles(json, t) +
      this.sectionChallenges(ctx, json) + this.sectionHostNames(json, t) +
      this.sectionCertificates(ctx, json) + this.sectionExceptions(json, t) +
      SettingsForms.forms(json.settings, '/admin/scep', undefined, t) +
      '<p class="links"><a href="/admin/scep?format=json">JSON</a> · ' +
      '<code>GET /admin-api/scep</code> · <a href="/admin/scep/monitor">' +
      t.html('consoleScep.linkMonitor') + '</a> · ' +
      '<a href="/admin/pki">PKI</a> · ' +
      '<a href="/admin/error-codes">' + t.html('consoleScep.linkErrorCodes') +
      '</a></p>';
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
   * @param t - the page's translator (#539)
   * @returns the markup
   */
  static table(title, counts, t) {
    const self = this;
    const keys = Object.keys(counts || {}).sort(function (a, b) {
      return counts[b] - counts[a];
    });
    return '<h2>' + esc(title) + '</h2>' + (keys.length
      ? '<table><tbody>' + keys.map(function (k) {
        return '<tr><td>' + self.code(k) + '</td><td class="num">' + counts[k] +
               '</td></tr>';
      }).join('') + '</tbody></table>'
      : '<p class="sub">' + t.html('consoleScep.noneYet') + '</p>');
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
    // The translator is `t` (#539), so the totals, which were `t`, are
    // `totals`.
    const t = ctx.t;
    const totals = json.totals;
    const nav = kit.pageNavPair('/admin/scep/monitor', ctx.query,
                                  json.paging, t);
    const rows = json.recent.length ? json.recent.map(function (r) {
      return '<tr><td>' + esc(r.at) + '</td><td>' + self.code(r.operation) +
        '</td><td>' + esc(r.outcome) + '</td><td>' + esc(r.failInfo || '') +
        '</td><td>' + esc(r.profile || '') + '</td><td>' +
        esc(r.principal || '') + '</td><td>' + esc(r.target || '') +
        '</td><td>' + esc(r.errorCode || '') + '</td><td>' +
        esc(r.serialHex || '') + '</td></tr>';
    }).join('') : '<tr><td colspan="9" class="sub">' +
      t.html('consoleScep.noRequest') + '</td></tr>';
    const inner =
      kit.note(t.html('consoleScep.monitorIntro',
                      { since: json.since, n: json.processes })) +
      '<div class="tiles">' +
      kit.tile(totals.requests, t.text('consoleScep.tileRequests')) +
      kit.tile(totals.issued, t.text('consoleScep.tileIssued')) +
      kit.tile(totals.refused, t.text('consoleScep.tileRefused')) +
      kit.tile(totals.revoked, t.text('consoleScep.tileRevoked')) +
      kit.tile(totals.challengesCreated,
               t.text('consoleScep.tileChallenges')) +
      kit.tile(json.issuedCertificates,
               t.text('consoleScep.tileCertificates')) + '</div>' +
      self.table(t.text('consoleScep.byOperation'), json.operations, t) +
      self.table(t.text('consoleScep.byFailInfo'), json.failInfo, t) +
      self.table(t.text('consoleScep.byErrorCode'), json.errorCodes, t) +
      self.table(t.text('consoleScep.byProfile'), json.profiles, t) +
      self.table(t.text('consoleScep.byPrincipal'), json.principals, t) +
      '<h2 id="list-page">' + t.html('consoleScep.recent') + '</h2>' +
      nav.head + '<table><thead><tr>' +
      '<th>' + t.html('consoleScep.thAt') + '</th><th>' +
      t.html('consoleScep.thOperation') + '</th><th>' +
      t.html('consoleScep.thOutcome') + '</th><th>failInfo</th>' +
      '<th>' + t.html('consoleScep.thProfile') + '</th><th>' +
      t.html('consoleScep.thPrincipal') + '</th><th>' +
      t.html('consoleScep.thTarget') + '</th><th>' +
      t.html('consoleScep.thCode') + '</th>' +
      '<th>' + t.html('consoleScep.serial') + '</th></tr></thead><tbody>' +
      rows + '</tbody></table>' +
      nav.foot +
      kit.note(t.html('consoleScep.noReset') +
        ' <a href="/admin/audit">' + t.html('consoleScep.auditLog') +
        '</a>.') +
      '<p class="links"><a href="/admin/scep/monitor?format=json">JSON</a> ' +
      '· <code>GET /admin-api/scep/monitor</code> · <a ' +
      'href="/admin/scep">SCEP</a></p>';
    return inner;
  }
}

export = ScepPage;
