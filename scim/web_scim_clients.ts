// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_scim_clients.ts
//
// ---------------------------------------------------------------------------
// PROTOCOLS → SCIM → CLIENTS, DRAWN FROM ITS VIEW ALONE (#552, 2026-10-10).
//
// The outbound SCIM clients: each service provider this realm pushes its
// people and groups to, with its queue counts and its backoff pause, a form to
// add one, and — on `/admin/scim?client=<id>` — one client's page: its
// definition (an Edit form), what its service provider's discovery said, its
// retry queue and its dead letters, and the acts. Every form posts an action of
// `POST /admin-api/scim/clients/{action}` (rule 7), which the static console
// resolves through the operation's `mirrors`.
//
// **A CREDENTIAL BOX IS NEVER FILLED.** The view carries `passwordSet`,
// `oauthClientSecretSet` and `tlsPrivateKeySet` and no credential; the boxes
// are password inputs, empty, and left empty on a change keep the one set.
//
// **`enabled` IS A SELECT, NOT A CHECKBOX**, because an unticked checkbox
// posts nothing and an update keeps a member it was not given: a checkbox
// could turn a client on and never off.
//
// ITS WORDS ARE THE `consoleScimClients` NAMESPACE (#539). What the VIEW says
// — a problem sentence, a delivery's last error — is the server's and drawn
// as it comes, in English.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// ---------------------------------------------------------------------------

import kit = require('../admin-ui/web_kit');

type Json = any;

const esc = kit.esc;

/**
 * The page the forms post to.
 */
const PAGE = '/admin/scim';

/**
 * Draws the Clients tab of Protocols → SCIM, and one client's page.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class ScimClientsPage {
  // One text box. Its label and hint arrive translated.
  static text(name: string, label: string, value: unknown,
              hint?: string): string {
    return '<label>' + esc(label) + ' <input type="text" name="' + name +
      '" value="' + esc(value == null ? '' : value) + '"' +
      (hint ? ' placeholder="' + esc(hint) + '"' : '') + '></label>';
  }

  // One select over a closed set; the options are submitted as they are.
  static select(name: string, label: string, options: string[],
                value: string): string {
    return '<label>' + esc(label) + ' <select name="' + name + '">' +
      options.map(function (one) {
        return '<option' + (one === value ? ' selected' : '') + '>' +
               esc(one) + '</option>';
      }).join('') + '</select></label>';
  }

  // A write-only box: empty, with a placeholder saying whether one is kept.
  static secret(t: Json, name: string, label: string, set: boolean): string {
    return '<label>' + esc(label) + ' <input type="password" name="' + name +
      '" autocomplete="off" value="" placeholder="' +
      esc(set ? t.text('consoleScimClients.fields.kept')
              : t.text('consoleScimClients.fields.notSet')) + '"></label>';
  }

  // A text area.
  static area(name: string, label: string, value: unknown, rows: number,
              hint?: string): string {
    return '<div class="formrow"><label>' + esc(label) + ' <textarea name="' +
      name + '" rows="' + rows + '" cols="64"' +
      (hint ? ' placeholder="' + esc(hint) + '"' : '') + '>' +
      esc(value == null ? '' : value) + '</textarea></label></div>';
  }

  // The fields of a client's form, filled with `row` (null for a new one).
  static fields(t: Json, choices: Json, row: Json): string {
    const r = row || {};
    const c = choices || {};
    const list = function (v: Json): string {
      return Array.isArray(v) ? v.join('\n') : String(v || '');
    };
    return '<div class="formrow">' +
      this.text('name', t.text('consoleScimClients.fields.name'), r.name,
                'Partner IdP') +
      this.select('enabled', t.text('consoleScimClients.fields.enabled'),
                  ['false', 'true'], r.enabled ? 'true' : 'false') +
      '</div><div class="formrow">' +
      this.text('baseUrl', t.text('consoleScimClients.fields.baseUrl'),
                r.baseUrl, 'https://idp.example.com/scim/v2') +
      '</div><h4>' + t.html('consoleScimClients.fields.authentication') +
      '</h4><div class="formrow">' +
      this.select('authMethod', t.text('consoleScimClients.fields.authMethod'),
                  c.authMethods || [], r.authMethod || 'basic') +
      this.text('username', t.text('consoleScimClients.fields.username'),
                r.username) +
      this.secret(t, 'password', t.text('consoleScimClients.fields.password'),
                  !!r.passwordSet) +
      '</div><div class="formrow">' +
      this.text('tokenEndpoint',
                t.text('consoleScimClients.fields.tokenEndpoint'),
                r.tokenEndpoint, 'https://idp.example.com/oauth2/token') +
      this.text('oauthClientId',
                t.text('consoleScimClients.fields.oauthClientId'),
                r.oauthClientId) +
      this.secret(t, 'oauthClientSecret',
                  t.text('consoleScimClients.fields.oauthClientSecret'),
                  !!r.oauthClientSecretSet) +
      '</div><div class="formrow">' +
      this.select('oauthClientAuth',
                  t.text('consoleScimClients.fields.oauthClientAuth'),
                  c.oauthClientAuth || [],
                  r.oauthClientAuth || 'client_secret_basic') +
      this.text('oauthScope', t.text('consoleScimClients.fields.oauthScope'),
                r.oauthScope) +
      this.text('oauthResource',
                t.text('consoleScimClients.fields.oauthResource'),
                r.oauthResource) +
      '</div><div class="formrow">' +
      this.select('tlsSource', t.text('consoleScimClients.fields.tlsSource'),
                  c.tlsSources || [], r.tlsSource || 'none') +
      this.secret(t, 'tlsPrivateKey',
                  t.text('consoleScimClients.fields.tlsPrivateKey'),
                  !!r.tlsPrivateKeySet) + '</div>' +
      this.area('tlsCertificate',
                t.text('consoleScimClients.fields.tlsCertificate'),
                r.tlsSource === 'uploaded' ? r.tlsCertificate : '', 3,
                '-----BEGIN CERTIFICATE-----') +
      this.area('caCertificates',
                t.text('consoleScimClients.fields.caCertificates'),
                r.caCertificates, 3, '-----BEGIN CERTIFICATE-----') +
      '<h4>' + t.html('consoleScimClients.fields.who') + '</h4>' +
      '<div class="formrow">' +
      this.select('scopeMode', t.text('consoleScimClients.fields.scopeMode'),
                  c.scopeModes || [], r.scopeMode || 'all') +
      this.text('scopeFilter',
                t.text('consoleScimClients.fields.scopeFilter'),
                r.scopeFilter, '(departmentNumber=sales)') + '</div>' +
      this.area('scopeGroups',
                t.text('consoleScimClients.fields.scopeGroups'),
                list(r.scopeGroups), 2, 'staff') +
      '<div class="formrow">' +
      this.select('groupMode', t.text('consoleScimClients.fields.groupMode'),
                  c.groupModes || [], r.groupMode || 'none') +
      this.select('deprovision',
                  t.text('consoleScimClients.fields.deprovision'),
                  c.deprovision || [], r.deprovision || 'deactivate') +
      this.text('reconcileMinutes',
                t.text('consoleScimClients.fields.reconcileMinutes'),
                r.reconcileMinutes || '0', '1440') + '</div>' +
      this.area('groups', t.text('consoleScimClients.fields.groups'),
                list(r.groups), 2, 'engineering') +
      // A SERVICE DEPLOYED AS CELLS (#553): where the service provider is,
      // and which cells push to it. Read only there.
      '<h4>' + t.html('consoleScimClients.fields.cellsHeading') + '</h4>' +
      '<div class="formrow">' +
      this.text('jurisdiction',
                t.text('consoleScimClients.fields.jurisdiction'),
                r.jurisdiction, 'eu') + '</div>' +
      this.area('cells', t.text('consoleScimClients.fields.cells'),
                list(r.cells), 2, 'euc1');
  }

  // A form carrying one act and the client's id.
  static act(action: string, id: string, label: string,
             danger?: boolean): string {
    return '<form method="post" action="' + PAGE + '" class="inline">' +
      '<input type="hidden" name="action" value="' + action + '">' +
      '<input type="hidden" name="id" value="' + esc(id) + '">' +
      '<button type="submit"' + (danger ? ' class="danger"' : '') + '>' +
      esc(label) + '</button></form>';
  }

  // The queue counts of a client, as a cell.
  static counts(t: Json, n: Json): string {
    const c = n || {};
    return t.html('consoleScimClients.counts', {
      queued: c.queued || 0, retrying: c.retrying || 0, dead: c.dead || 0,
      sent: c.sent || 0 });
  }

  // One client's row on the tab.
  static row(t: Json, c: Json, ctx: Json): string {
    return '<tr><td class="who"><a href="' + PAGE + '?client=' +
      encodeURIComponent(c.identifier) + '">' + esc(c.name) + '</a>' +
      '<br><span class="sub">' + esc(c.identifier) + '</span></td><td>' +
      '<code>' + esc(c.baseUrl || '?') + '</code><br><span class="sub">' +
      esc(c.authMethod) + (c.tlsSource !== 'none'
        ? ' + ' + t.html('consoleScimClients.row.certificate') : '') +
      '</span></td><td>' + esc(c.scopeMode) + ' / ' + esc(c.groupMode) +
      '<br><span class="sub">' + esc(c.deprovision) + '</span></td><td>' +
      (c.enabled ? t.html('consoleScimClients.row.on')
                 : '<span class="state-none">' +
                   t.html('consoleScimClients.row.off') + '</span>') +
      (c.usable ? '' : '<br><span class="state-revoked">' +
                       t.html('consoleScimClients.row.notUsable') +
                       '</span>' + (c.problems || []).map(function (p: Json) {
                         return '<div class="sub">' + esc(p) + '</div>';
                       }).join('')) +
      (c.pausedUntil ? '<br><span class="state-revoked">' +
        t.html('consoleScimClients.row.paused', { until: c.pausedUntil,
                                                  failures: c.failures }) +
        '</span>' : '') + '</td><td>' + this.counts(t, c.counts) +
      (c.lastReconcileAt ? '<br><span class="sub">' +
        t.html('consoleScimClients.row.reconciled',
               { at: c.lastReconcileAt }) + '</span>' : '') + '</td>' +
      '<td class="act">' + (ctx.write && c.usable && c.enabled
        ? this.act('reconcile', c.identifier,
                   t.text('consoleScimClients.acts.reconcile'))
        : '') + '</td></tr>';
  }

  /**
   * Draws the Clients tab from `scimClients` of the SCIM view.
   *
   * @param ctx - the render context
   * @param json - `GET /admin-api/scim`'s `scimClients`, or the answer of
   *   `GET /admin-api/scim/clients`
   * @returns the tab's HTML
   */
  static tab(ctx: Json, json: Json): string {
    const t = ctx.t;
    if (!json) {
      return kit.warn(t.html('consoleScimClients.notLoaded'));
    }
    const rows = (json.clients || []).map((c: Json) =>
      this.row(t, c, ctx)).join('');
    return kit.note(t.html('consoleScimClients.lead')) +
      (json.httpAllowed ? kit.warn(t.html('consoleScimClients.httpAllowed'))
                        : '') +
      '<h3 id="scim-clients-list">' + t.html('consoleScimClients.clients') +
      '</h3><table><thead><tr><th>' +
      t.html('consoleScimClients.thClient') + '</th><th>' +
      t.html('consoleScimClients.thProvider') + '</th><th>' +
      t.html('consoleScimClients.thScope') + '</th><th>' +
      t.html('consoleScimClients.thState') + '</th><th>' +
      t.html('consoleScimClients.thQueues') + '</th><th></th></tr></thead>' +
      '<tbody>' + (rows || '<tr><td colspan="6"><span class="state-none">' +
                           t.html('consoleScimClients.none') +
                           '</span></td></tr>') + '</tbody></table>' +
      kit.note(t.html('consoleScimClients.queuesNote')) +
      (ctx.write
        ? '<h3 id="scim-clients-add">' + t.html('consoleScimClients.add') +
          '</h3><form method="post" action="' + PAGE + '">' +
          '<input type="hidden" name="action" value="add-client">' +
          '<div class="formrow">' +
          this.text('identifier', t.text('consoleScimClients.identifier'), '',
                    'partner-idp') + '</div>' +
          this.fields(t, json.choices, null) + '<button type="submit">' +
          t.html('consoleScimClients.addButton') + '</button></form>'
        : '') +
      '<p class="links"><code>GET /admin-api/scim/clients</code></p>';
  }

  // One queue's table.
  static queue(t: Json, rows: Json[], dead: boolean, ctx: Json): string {
    if (!rows || !rows.length) {
      return '<p class="sub">' + t.html('consoleScimClients.detail.empty') +
             '</p>';
    }
    return '<table><thead><tr><th>' +
      t.html('consoleScimClients.detail.thResource') + '</th><th>' +
      t.html('consoleScimClients.detail.thAttempts') + '</th><th>' +
      t.html('consoleScimClients.detail.thNext') + '</th><th>' +
      t.html('consoleScimClients.detail.thLast') + '</th><th></th></tr>' +
      '</thead><tbody>' + rows.map((r: Json) => {
        return '<tr><td><code>' + esc(r.type) + '</code> ' +
          esc(r.name || r.uuid) + '<br><span class="sub">' + esc(r.uuid) +
          (r.pendingChange ? ' · ' +
            t.html('consoleScimClients.detail.pendingChange') : '') +
          '</span></td><td class="num">' + esc(r.attempts || 0) + '</td><td>' +
          esc(r.nextAttemptAt || '') + '</td><td class="sub">' +
          esc(r.lastError || r.why || '') +
          (r.errorCode ? ' <code>' + esc(r.errorCode) + '</code>' : '') +
          '</td><td class="act">' + (dead && ctx.write
            ? '<form method="post" action="' + PAGE + '" class="inline">' +
              '<input type="hidden" name="action" value="retry-delivery">' +
              '<input type="hidden" name="id" value="' + esc(r.id) + '">' +
              '<button type="submit">' +
              t.html('consoleScimClients.acts.retry') + '</button></form>'
            : '') + '</td></tr>';
      }).join('') + '</tbody></table>';
  }

  /**
   * Draws one client's page from `scimClients` of the SCIM view with
   * `?client=`.
   *
   * @param ctx - the render context
   * @param json - the SCIM view, or `GET /admin-api/scim/clients?client=`'s
   *   answer
   * @returns the page's HTML
   */
  static detail(ctx: Json, json: Json): string {
    const t = ctx.t;
    const view = json && json.scimClients !== undefined ? json.scimClients
                                                        : json;
    const c = view && view.client;
    if (!c) {
      return kit.warn(t.html('consoleScimClients.detail.missing',
                             { client: (view && view.missing) || '' })) +
             '<p class="links"><a href="' + PAGE + '#clients">' +
             t.html('consoleScimClients.detail.back') + '</a></p>';
    }
    const d = c.discovery;
    const q = c.queues || {};
    const cert = c.certificate;
    return '<p class="links"><a href="' + PAGE + '#clients">' +
      t.html('consoleScimClients.detail.back') + '</a></p>' +
      '<div class="tiles">' +
      kit.tile(q.counts ? q.counts.queued : 0,
               t.text('consoleScimClients.detail.tileQueued')) +
      kit.tile(q.counts ? q.counts.retrying : 0,
               t.text('consoleScimClients.detail.tileRetrying')) +
      kit.tile(q.counts ? q.counts.dead : 0,
               t.text('consoleScimClients.detail.tileDead')) +
      kit.tile(q.counts ? q.counts.sent : 0,
               t.text('consoleScimClients.detail.tileSent')) +
      kit.tile(c.linked || 0, t.text('consoleScimClients.detail.tileLinked')) +
      '</div>' +
      (c.usable ? '' : kit.warn('<strong>' +
        t.html('consoleScimClients.row.notUsable') + '</strong> ' +
        (c.problems || []).map(esc).join(' '))) +
      (c.pausedUntil ? kit.warn(t.html('consoleScimClients.row.paused',
        { until: c.pausedUntil, failures: c.failures })) : '') +
      (ctx.write
        ? '<p>' + this.act('test-connection', c.identifier,
                           t.text('consoleScimClients.acts.test')) + ' ' +
          this.act('reconcile', c.identifier,
                   t.text('consoleScimClients.acts.reconcile')) + ' ' +
          this.act('deliver-now', c.identifier,
                   t.text('consoleScimClients.acts.deliverNow')) + ' ' +
          this.act('issue-certificate', c.identifier,
                   t.text('consoleScimClients.acts.issueCertificate')) +
          '</p>'
        : '') +
      '<h3 id="scim-client-discovery">' +
      t.html('consoleScimClients.detail.discovery') + '</h3>' +
      (d ? '<table><tr><th>PATCH</th><td>' + (d.patch ? '✓' : '—') +
           '</td></tr><tr><th>filter</th><td>' + (d.filter ? '✓' : '—') +
           (d.maxResults ? ' (maxResults ' + esc(d.maxResults) + ')' : '') +
           '</td></tr><tr><th>ETag</th><td>' + (d.etag ? '✓' : '—') +
           '</td></tr><tr><th>/Users</th><td><code>' +
           esc((d.endpoints || {}).User) + '</code></td></tr>' +
           '<tr><th>/Groups</th><td><code>' +
           esc((d.endpoints || {}).Group) + '</code></td></tr>' +
           '<tr><th>' + t.html('consoleScimClients.detail.read') +
           '</th><td>' + esc(d.at) + (d.ok ? '' : ' — ' + esc(d.why)) +
           '</td></tr></table>'
         : '<p class="sub">' + t.html('consoleScimClients.detail.notRead') +
           '</p>') +
      (cert ? '<h3>' + t.html('consoleScimClients.detail.certificate') +
              '</h3><p><code>' + esc(cert.subject || cert.error || '') +
              '</code><br><span class="sub">' + esc(cert.issuer || '') +
              ' · ' + esc(cert.notAfter || '') + '</span></p>' : '') +
      '<h3 id="scim-client-retrying">' +
      t.html('consoleScimClients.detail.retrying') + '</h3>' +
      this.queue(t, (q.retrying || []).concat(q.queued || []), false, ctx) +
      '<h3 id="scim-client-dead">' +
      t.html('consoleScimClients.detail.dead') + '</h3>' +
      this.queue(t, q.dead || [], true, ctx) +
      (ctx.write && q.counts && q.counts.dead
        ? '<p>' + this.act('retry-dead', c.identifier,
                           t.text('consoleScimClients.acts.retryDead')) + ' ' +
          this.act('purge-dead', c.identifier,
                   t.text('consoleScimClients.acts.purgeDead'), true) + '</p>'
        : '') +
      (ctx.write
        ? '<h3 id="scim-client-edit">' +
          t.html('consoleScimClients.detail.edit') + '</h3>' +
          '<form method="post" action="' + PAGE + '">' +
          '<input type="hidden" name="action" value="update-client">' +
          '<input type="hidden" name="id" value="' + esc(c.identifier) +
          '">' + this.fields(t, view.choices, c) + '<button type="submit">' +
          t.html('consoleScimClients.detail.save') + '</button></form>' +
          '<p>' + this.act('remove-client', c.identifier,
                           t.text('consoleScimClients.acts.remove'), true) +
          '</p>'
        : '') +
      '<p class="links"><code>GET /admin-api/scim/clients?client=' +
      esc(c.identifier) + '</code></p>';
  }
}

export = ScimClientsPage;
