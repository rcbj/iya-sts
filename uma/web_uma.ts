// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_uma.ts
//
// ---------------------------------------------------------------------------
// PROTOCOLS -> UMA, DRAWN FROM ITS VIEW ALONE (#1168 phase 6, #1195).
//
// Draws the page from the answer of `GET /admin-api/uma`
// (`uma/uma_console.ts`'s `view()`), every form posting to `/admin/uma`,
// which the console runtime sends to `POST /admin-api/uma/{action}` by the
// operation's `mirrors`. GNAP's page (`gnap/web_gnap.ts`) is the sibling:
// Metadata first, then a tab per list, the settings last.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_`
// modules only, logs nothing, and is bundled for a browser by
// `build-typescript.sh`.
// ---------------------------------------------------------------------------

import kit = require('../admin-ui/web_kit');
import SettingsForms = require('../admin-ui/web_settings');

type Json = any;

const PAGE = '/admin/uma';

/**
 * Draws Protocols -> UMA from the answer of `GET /admin-api/uma`.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class UmaPage {
  /**
   * Draws the page's body from its view.
   *
   * @param view - the answer of the page's management API operation
   * @param ctx - the render context (`WebKit.context()`)
   * @returns the body as HTML
   */
  static render(view: Json, ctx: Json): string {
    return UmaPage.body(ctx, view);
  }

  static when(seconds: number): string {
    return seconds ? kit.whenText(seconds * 1000) : '—';
  }

  // A permission list: each resource's name (or id) and its scopes.
  static permissions(list: Json[]): string {
    const esc = kit.esc;
    return (list || []).map(function (p: Json) {
      return '<code>' + esc(p.name || p.resource) + '</code> ' +
        '<span class="sub">' + esc((p.scopes || []).join(', ')) + '</span>';
    }).join('<br>');
  }

  // A one-button form posting one act to the page.
  static button(action: string, fields: Json, label: string,
                danger: boolean): string {
    const esc = kit.esc;
    return '<form method="post" action="' + PAGE + '">' +
      '<input type="hidden" name="action" value="' + esc(action) + '">' +
      Object.keys(fields).map(function (name) {
        return '<input type="hidden" name="' + esc(name) + '" value="' +
          esc(fields[name]) + '">';
      }).join('') + '<button type="submit"' +
      (danger ? ' class="danger"' : '') + '>' + label + '</button></form>';
  }

  // The resource servers tab: one row per application declared for uma.
  static servers(json: Json, t: Json, write: boolean): string {
    const esc = kit.esc;
    const yes = t.html('consoleUma.yes');
    const no = t.html('consoleUma.no');
    const rows = json.resourceServers.length
      ? json.resourceServers.map(function (row: Json) {
        const id = row.identifier;
        const controls = write
          ? UmaPage.button('set-owns-resources',
              { application: id, value: row.ownsResources ? 'FALSE'
                                                           : 'TRUE' },
              row.ownsResources ? t.html('consoleUma.ownsOff')
                                : t.html('consoleUma.ownsOn'), false) +
            UmaPage.button('disable-resource-server', { application: id },
                           t.html('consoleUma.disable'), true)
          : '';
        return '<tr><td><a href="/admin/applications?application=' +
          encodeURIComponent(id) + '"><code>' + esc(id) + '</code></a>' +
          (row.name ? '<div class="sub">' + esc(row.name) + '</div>' : '') +
          '</td><td>' + (row.ownsResources
            ? '<a href="' + PAGE + '?owner=' + encodeURIComponent(id) +
              '#uma-tab-owner">' + yes + '</a>' : no) +
          '</td><td>' + (row.protectionGranted ? yes
            : '<strong>' + no + '</strong>') + '</td>' +
          '<td class="num"><a href="' + PAGE + '?resourceServer=' +
          encodeURIComponent(id) + '#uma-tab-resources">' + row.resources +
          '</a></td><td class="num">' + row.rpts + '</td><td>' + controls +
          '</td></tr>';
      }).join('')
      : '<tr><td colspan="6" class="sub">' + t.html('consoleUma.noServers') +
        '</td></tr>';
    const enable = write
      ? '<form method="post" action="' + PAGE + '">' +
        '<input type="hidden" name="action" value="enable-resource-server">' +
        '<label>' + t.html('consoleUma.enableLabel') + ' <input type="text" ' +
        'name="application" size="30" required></label> <button ' +
        'type="submit">' + t.html('consoleUma.enable') + '</button></form>'
      : '';
    return '<h2 data-tab="servers">' + t.html('consoleUma.servers') +
      '</h2>' + kit.note(t.html('consoleUma.serversLead')) +
      '<table><thead><tr><th>' + t.html('consoleUma.thApplication') +
      '</th><th>' + t.html('consoleUma.thOwns') + '</th><th>' +
      t.html('consoleUma.thProtection') + '</th><th>' +
      t.html('consoleUma.thResources') + '</th><th>' +
      t.html('consoleUma.thRpts') + '</th><th></th></tr></thead><tbody>' +
      rows + '</tbody></table>' + enable;
  }

  // The resources tab, filtered by resource server and owner.
  static resources(json: Json, ctx: Json, write: boolean): string {
    const t = ctx.t;
    const esc = kit.esc;
    const nav = kit.pageNavPair(PAGE, ctx.query,
      Object.assign({}, json.resources.paging, { param: 'resourcesPage' }),
      t);
    const filter = json.filter || {};
    const rows = json.resources.rows.length
      ? json.resources.rows.map(function (row: Json) {
        return '<tr><td><code>' + esc(row.id) + '</code>' +
          kit.copyButton(row.id, t) + '</td><td>' + esc(row.name) +
          (row.type ? '<div class="sub">' + esc(row.type) + '</div>' : '') +
          '</td><td>' + esc(row.scopes.join(', ')) + '</td><td><code>' +
          esc(row.resourceServer) + '</code></td><td><a href="' + PAGE +
          '?owner=' + encodeURIComponent(row.owner) + '#uma-tab-owner">' +
          esc(row.owner) + '</a> <span class="sub">' + esc(row.ownerKind) +
          '</span></td><td>' + esc(UmaPage.when(row.createdAt)) +
          '</td><td>' + (write ? UmaPage.button('delete-resource',
            { resource: row.id }, t.html('consoleUma.delete'), true) : '') +
          '</td></tr>';
      }).join('')
      : '<tr><td colspan="7" class="sub">' +
        t.html('consoleUma.noResources') + '</td></tr>';
    const form = '<form method="get" action="' + PAGE +
      '#uma-tab-resources"><label>' + t.html('consoleUma.thResourceServer') +
      ' <input type="text" name="resourceServer" value="' +
      esc(filter.resourceServer || '') + '"></label> <label>' +
      t.html('consoleUma.thOwner') + ' <input type="text" name="owner" ' +
      'value="' + esc(filter.owner || '') + '"></label> <button ' +
      'type="submit">' + t.html('consoleUma.filter') + '</button></form>';
    return '<h2 id="list-resourcesPage" data-tab="resources">' +
      t.html('consoleUma.resources') + '</h2>' + form + nav.head +
      '<table><thead><tr><th>' + t.html('consoleUma.thId') + '</th><th>' +
      t.html('consoleUma.thName') + '</th><th>' +
      t.html('consoleUma.thScopes') + '</th><th>' +
      t.html('consoleUma.thResourceServer') + '</th><th>' +
      t.html('consoleUma.thOwner') + '</th><th>' +
      t.html('consoleUma.thRegistered') + '</th><th></th></tr></thead>' +
      '<tbody>' + rows + '</tbody></table>' + nav.foot;
  }

  // The tokens tab: live tickets, then live RPTs with a Revoke each.
  static tokens(json: Json, ctx: Json, write: boolean): string {
    const t = ctx.t;
    const esc = kit.esc;
    const ticketNav = kit.pageNavPair(PAGE, ctx.query,
      Object.assign({}, json.tickets.paging, { param: 'ticketsPage' }), t);
    const rptNav = kit.pageNavPair(PAGE, ctx.query,
      Object.assign({}, json.rpts.paging, { param: 'rptsPage' }), t);
    const tickets = json.tickets.rows.length
      ? json.tickets.rows.map(function (row: Json) {
        return '<tr><td><code>' + esc(row.key) + '…</code></td><td>' +
          esc(row.state) + '</td><td><code>' + esc(row.resourceServer) +
          '</code></td><td>' + esc(row.owner) + '</td><td>' +
          UmaPage.permissions(row.permissions) + '</td><td>' +
          esc(UmaPage.when(row.expiresAt)) + '</td></tr>';
      }).join('')
      : '<tr><td colspan="6" class="sub">' + t.html('consoleUma.noTickets') +
        '</td></tr>';
    const rpts = json.rpts.rows.length
      ? json.rpts.rows.map(function (row: Json) {
        return '<tr><td><code>' + esc(row.jti) + '</code></td><td>' +
          esc(row.requestingParty) + '</td><td><code>' + esc(row.client) +
          '</code></td><td><code>' + esc(row.resourceServer) +
          '</code></td><td>' + UmaPage.permissions(row.permissions) +
          '</td><td>' + esc(UmaPage.when(row.exp)) + '</td><td>' +
          (write ? UmaPage.button('revoke-rpt', { rpt: row.jti },
                                  t.html('consoleUma.revoke'), true) : '') +
          '</td></tr>';
      }).join('')
      : '<tr><td colspan="7" class="sub">' + t.html('consoleUma.noRpts') +
        '</td></tr>';
    return '<h2 id="list-ticketsPage" data-tab="tokens">' +
      t.html('consoleUma.tickets') + '</h2>' +
      kit.note(t.html('consoleUma.ticketsLead')) + ticketNav.head +
      '<table><thead><tr><th>' + t.html('consoleUma.thTicket') +
      '</th><th>' + t.html('consoleUma.thState') + '</th><th>' +
      t.html('consoleUma.thResourceServer') + '</th><th>' +
      t.html('consoleUma.thOwner') + '</th><th>' +
      t.html('consoleUma.thPermissions') + '</th><th>' +
      t.html('consoleUma.thExpires') + '</th></tr></thead><tbody>' +
      tickets + '</tbody></table>' + ticketNav.foot +
      '<h3 id="list-rptsPage">' + t.html('consoleUma.rpts') + '</h3>' +
      rptNav.head + '<table><thead><tr><th>jti</th><th>' +
      t.html('consoleUma.thParty') + '</th><th>' +
      t.html('consoleUma.thClient') + '</th><th>' +
      t.html('consoleUma.thResourceServer') + '</th><th>' +
      t.html('consoleUma.thPermissions') + '</th><th>' +
      t.html('consoleUma.thExpires') + '</th><th></th></tr></thead>' +
      '<tbody>' + rpts + '</tbody></table>' + rptNav.foot;
  }

  // A table of requests waiting for an owner; `owner` adds the answer
  // buttons, for an application's document only.
  static pendingTable(rows: Json[], t: Json, owner: string): string {
    const esc = kit.esc;
    if (!rows.length) {
      return kit.note(t.html('consoleUma.noPending'));
    }
    return '<table><thead><tr><th>' + t.html('consoleUma.thOwner') +
      '</th><th>' + t.html('consoleUma.thParty') + '</th><th>' +
      t.html('consoleUma.thClient') + '</th><th>' +
      t.html('consoleUma.thPermissions') + '</th><th>' +
      t.html('consoleUma.thExpires') + '</th><th></th></tr></thead><tbody>' +
      rows.map(function (row: Json) {
        const controls = owner
          ? UmaPage.button('owner-approve', { owner: owner, pending: row.id },
                           t.html('consoleUma.approve'), false) +
            UmaPage.button('owner-refuse', { owner: owner, pending: row.id },
                           t.html('consoleUma.refuse'), true)
          : '';
        return '<tr><td>' + esc(row.owner) + '</td><td>' +
          esc(row.requester) + '</td><td><code>' + esc(row.client) +
          '</code></td><td>' + UmaPage.permissions(row.permissions) +
          '</td><td>' + esc(UmaPage.when(row.expiresAt)) + '</td><td>' +
          controls + '</td></tr>';
      }).join('') + '</tbody></table>';
  }

  // The pending tab: every request waiting for an owner in the realm.
  static pending(json: Json, ctx: Json): string {
    const t = ctx.t;
    const nav = kit.pageNavPair(PAGE, ctx.query,
      Object.assign({}, json.pending.paging, { param: 'pendingPage' }), t);
    return '<h2 id="list-pendingPage" data-tab="pending">' +
      t.html('consoleUma.pending') + '</h2>' +
      kit.note(t.html('consoleUma.pendingLead')) + nav.head +
      UmaPage.pendingTable(json.pending.rows, t, '') + nav.foot;
  }

  // The share form for an application's own document.
  static shareForm(owner: Json, t: Json): string {
    const esc = kit.esc;
    const options = (owner.resources || []).map(function (row: Json) {
      return '<option value="' + esc(row.id) + '">' +
        esc(row.name || row.id) + '</option>';
    }).join('');
    if (!options) {
      return '';
    }
    return '<h3>' + t.html('consoleUma.shareHeading') + '</h3>' +
      '<form method="post" action="' + PAGE + '#uma-tab-owner">' +
      '<input type="hidden" name="action" value="owner-share">' +
      '<input type="hidden" name="owner" value="' + esc(owner.owner) + '">' +
      '<label>' + t.html('consoleUma.thResource') + ' <select ' +
      'name="resource">' + options + '</select></label> <label>' +
      t.html('consoleUma.thScopes') + ' <input type="text" name="scope" ' +
      'required></label> <label>' + t.html('consoleUma.recipientKind') +
      ' <select name="recipientKind"><option value="person">' +
      t.html('consoleUma.kindPerson') + '</option><option value="group">' +
      t.html('consoleUma.kindGroup') + '</option><option value="realm">' +
      t.html('consoleUma.kindRealm') + '</option><option value="claim">' +
      t.html('consoleUma.kindClaim') + '</option></select></label> ' +
      '<label>' + t.html('consoleUma.recipient') + ' <input type="text" ' +
      'name="recipient"></label> <label>' + t.html('consoleUma.claim') +
      ' <input type="text" name="claim"></label> <label>' +
      t.html('consoleUma.expires') + ' <input type="date" name="expires">' +
      '</label> <label><input type="checkbox" name="askMe" value="on"> ' +
      t.html('consoleUma.askMe') + '</label> <button type="submit">' +
      t.html('consoleUma.share') + '</button></form>';
  }

  // The owner tab: `?owner=` chooses, and an application that owns
  // resources is edited here; a person's is read here only.
  static owner(json: Json, ctx: Json): string {
    const t = ctx.t;
    const esc = kit.esc;
    const asked = (json.filter && json.filter.owner) || '';
    const form = '<form method="get" action="' + PAGE + '#uma-tab-owner">' +
      '<label>' + t.html('consoleUma.ownerLabel') + ' <input type="text" ' +
      'name="owner" value="' + esc(asked) + '"></label> <button ' +
      'type="submit">' + t.html('consoleUma.open') + '</button></form>';
    const head = '<h2 data-tab="owner">' + t.html('consoleUma.owner') +
      '</h2>' + kit.note(t.html('consoleUma.ownerLead')) + form;
    const owner = json.owner;
    if (!owner) {
      return head;
    }
    if (!owner.found) {
      return head + kit.warn(t.html('consoleUma.ownerNotFound',
                                    { owner: owner.asked }));
    }
    const editable = !!owner.editable && ctx.write === true;
    const shares = owner.document && owner.document.ok
      ? (owner.document.shares || []) : [];
    const shareRows = shares.length
      ? shares.map(function (share: Json) {
        const recipient = share.recipient || {};
        return '<tr><td><code>' + esc(share.resource) + '</code></td><td>' +
          esc((share.scopes || []).join(', ')) + '</td><td>' +
          esc(recipient.kind || '') + ' ' + esc(recipient.label ||
            recipient.value || '') + '</td><td>' +
          (editable ? UmaPage.button('owner-unshare',
            { owner: owner.owner, share: share.id },
            t.html('consoleUma.unshare'), true) : '') + '</td></tr>';
      }).join('')
      : '<tr><td colspan="4" class="sub">' + t.html('consoleUma.noShares') +
        '</td></tr>';
    const unreadable = owner.document && !owner.document.ok
      ? kit.warn(esc(owner.document.why || '')) : '';
    return head + '<h3>' + esc(owner.owner) + ' <span class="sub">' +
      esc(owner.kind) + '</span></h3>' +
      (owner.kind === 'user'
        ? kit.note(t.html('consoleUma.personReadOnly'))
        : (owner.ownsResources ? ''
           : kit.warn(t.html('consoleUma.notOwning')))) + unreadable +
      '<table><thead><tr><th>' + t.html('consoleUma.thResource') +
      '</th><th>' + t.html('consoleUma.thScopes') + '</th><th>' +
      t.html('consoleUma.recipient') + '</th><th></th></tr></thead><tbody>' +
      shareRows + '</tbody></table>' +
      (editable ? UmaPage.shareForm(owner, t) : '') +
      '<h3>' + t.html('consoleUma.pending') + '</h3>' +
      UmaPage.pendingTable(owner.pending || [], t,
                           editable ? owner.owner : '') +
      (owner.documentXml
        ? '<details><summary>' + t.html('consoleUma.documentXml') +
          '</summary><pre>' + esc(owner.documentXml) + '</pre></details>'
        : '');
  }

  // The what-if: every layer's answer for one permission, a dry run.
  static whatIf(json: Json, ctx: Json): string {
    const t = ctx.t;
    const esc = kit.esc;
    const q = ctx.query || {};
    const field = function (name: string, label: string): string {
      return '<label>' + label + ' <input type="text" name="' + name +
        '" value="' + esc(q[name] || '') + '"></label> ';
    };
    const form = '<form method="get" action="' + PAGE + '#uma-tab-whatif">' +
      field('resource', t.html('consoleUma.thResource')) +
      field('scope', t.html('consoleUma.thScope')) +
      field('party', t.html('consoleUma.thParty')) +
      field('client', t.html('consoleUma.thClient')) +
      '<button type="submit">' + t.html('consoleUma.ask') + '</button></form>';
    const answer = json.whatIf;
    let result = '';
    if (answer && answer.problem) {
      result = kit.warn(t.html('consoleUma.whatIfProblem',
                               { which: answer.problem }));
    } else if (answer) {
      result = '<p><strong>' + esc(answer.outcome) + '</strong>' +
        (answer.code ? ' <code>' + esc(answer.code) + '</code>' : '') +
        '</p><table><thead><tr><th>' + t.html('consoleUma.thLayer') +
        '</th><th>' + t.html('consoleUma.thOutcome') + '</th><th>' +
        t.html('consoleUma.thPolicy') + '</th><th>' +
        t.html('consoleUma.thWhy') + '</th></tr></thead><tbody>' +
        answer.layers.map(function (layer: Json) {
          return '<tr><td>' + esc(layer.layer) + '</td><td>' +
            esc(layer.outcome) + (layer.decision ? ' <span class="sub">' +
              esc(layer.decision) + '</span>' : '') + '</td><td><code>' +
            esc(layer.policy) + '</code></td><td>' + esc(layer.why) +
            (layer.missing.length ? '<div class="sub">' +
              esc(layer.missing.join(', ')) + '</div>' : '') + '</td></tr>';
        }).join('') + '</tbody></table>';
    }
    return '<h2 data-tab="whatif">' + t.html('consoleUma.whatIf') + '</h2>' +
      kit.note(t.html('consoleUma.whatIfLead')) + form + result;
  }

  /**
   * Draws Protocols -> UMA from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - `view()`'s answer
   * @returns the body as HTML
   */
  static body(ctx: Json, json: Json): string {
    const t = ctx.t;
    const esc = kit.esc;
    const write = ctx.write === true;
    const endpoints = json.endpoints || {};
    const endpointRows = Object.keys(endpoints).filter(function (name) {
      return typeof endpoints[name] === 'string' &&
        /^https?:/.test(endpoints[name]);
    }).map(function (name) {
      return '<tr><th>' + esc(name) + '</th><td><code>' +
        esc(endpoints[name]) + '</code>' + kit.copyButton(endpoints[name], t) +
        '</td></tr>';
    }).join('');
    const monitor = json.monitor;
    return kit.note(t.html('consoleUma.intro') +
        (json.enabled ? '' : ' ' + t.html('consoleUma.turnedOff'))) +
      '<h2>' + t.html('consoleUma.endpoints') + '</h2>' +
      (endpointRows ? '<table class="kv">' + endpointRows + '</table>'
                    : kit.note(t.html('consoleUma.noEndpoints'))) +
      (monitor ? '<p>' + kit.tile(monitor.decisions || 0,
                                  t.html('consoleUma.decisions')) +
                 kit.tile(monitor.allowed || 0, t.html('consoleUma.allowed')) +
                 kit.tile(monitor.refused || 0, t.html('consoleUma.refused')) +
                 '</p>' : '') +
      UmaPage.servers(json, t, write) +
      UmaPage.resources(json, ctx, write) +
      UmaPage.tokens(json, ctx, write) +
      UmaPage.pending(json, ctx) +
      UmaPage.owner(json, ctx) +
      UmaPage.whatIf(json, ctx) +
      '<h2 data-tab="settings">' + t.html('consoleUma.settings') + '</h2>' +
      SettingsForms.forms(json.settings, PAGE, undefined, t) +
      '<p class="links" data-metadata><a href="' + PAGE +
      '?format=json">JSON</a> · <code>GET /admin-api/uma</code> · ' +
      '<a href="/admin/xacml/monitor">' + t.html('consoleUma.linkMonitor') +
      '</a> · <a href="/admin/error-codes">' +
      t.html('consoleUma.linkErrorCodes') + '</a></p>';
  }
}

export = UmaPage;
