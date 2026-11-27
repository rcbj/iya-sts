// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_access_requests.ts
//
// ---------------------------------------------------------------------------
// `/portal/access-requests`, DRAWN IN THE BROWSER (#1180), from
// `GET /account-api/access-requests` (`portal_access_requests.ts`): the
// AuthZEN access requests waiting for the signed-in approver, a card each
// with who it is about, what it asks, through which PEP, and the Approve and
// Deny buttons. A second list is the live approvals that person gave, each
// with Revoke (#1203).
//
// The subject, action, resource, PEP and application are the denied
// tuple's — DATA, shown as code and never as wording, in every language.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import kit = require('./web_portal_kit');

type Json = any;
type PortalPage = import('../types/account-api').PortalPage;

const PATH = kit.BASE + '/access-requests';

/**
 * `/portal/access-requests`. A static utility class.
 */
class AccessRequestPages {
  /**
   * One answer's form.
   *
   * @param action - `approve`, `deny` or `revoke`
   * @param id - the request
   * @param label - the button's label, already HTML
   * @param danger - whether the button is the dangerous one
   * @returns the HTML
   */
  static form(action: string, id: string, label: string,
              danger: boolean): string {
    return '<form method="post" action="' + PATH + '" ' +
      'class="inline-form">' +
      '<input type="hidden" name="action" value="' + action + '">' +
      '<input type="hidden" name="request" value="' + kit.esc(id) + '">' +
      '<button type="submit"' + (danger ? ' class="danger"' : '') +
      ' id="access-request-' + action + '-' + kit.esc(id.slice(4, 16)) +
      '">' + label + '</button></form> ';
  }

  /**
   * One request's card.
   *
   * @param row - the request
   * @param t - the translator
   * @param kind - `pending` (the default) or `granted`
   * @returns the HTML
   */
  static card(row: Json, t: Json, kind?: string): string {
    const code = function (value: unknown): string {
      return '<code>' + kit.esc(String(value == null ? '' : value)) +
        '</code>';
    };
    const subject = row.subject || {};
    const resource = row.resource || {};
    const action = row.action || {};
    const granted = kind === 'granted';
    const approval = row.approval || {};
    const when = granted
      ? t.html('portalAccessRequests.until',
               { when: t.date(Number(approval.approvedUntil) * 1000) })
      : t.html('portalAccessRequests.waits',
               { when: t.date(Number(row.expiresAt) * 1000) });
    const buttons = granted
      ? AccessRequestPages.form('revoke', String(row.id),
                                t.html('portalAccessRequests.revoke'), true)
      : AccessRequestPages.form('approve', String(row.id),
                                t.html('portalAccessRequests.approve'),
                                false) +
        AccessRequestPages.form('deny', String(row.id),
                                t.html('portalAccessRequests.deny'), true);
    return '<div class="card access-request" id="access-request-' +
      kit.esc(String(row.id).slice(4, 16)) + '"><p>' +
      t.html('portalAccessRequests.asks') + '</p><table>' +
      '<tr><th>' + t.html('portalAccessRequests.subject') + '</th><td>' +
      code(subject.type) + ' ' + code(subject.id) + '</td></tr>' +
      '<tr><th>' + t.html('portalAccessRequests.action') + '</th><td>' +
      code(action.name) + '</td></tr>' +
      '<tr><th>' + t.html('portalAccessRequests.resource') + '</th><td>' +
      code(resource.type) + ' ' + code(resource.id) + '</td></tr>' +
      '<tr><th>' + t.html('portalAccessRequests.application') +
      '</th><td>' + code(row.application) + '</td></tr>' +
      '<tr><th>' + t.html('portalAccessRequests.requester') + '</th><td>' +
      code(row.requester) + '</td></tr>' +
      // The catalog item the request chose (#1204), when it chose one.
      (row.entitlement ? '<tr><th>' +
        t.html('portalAccessRequests.entitlement') + '</th><td>' +
        code(row.entitlement) + '</td></tr>' : '') +
      // The verified actor chain (#1204, the ACTOR companion), immediate
      // actor first.
      (row.actor && Array.isArray(row.actor.chain) && row.actor.chain.length
        ? '<tr><th>' + t.html('portalAccessRequests.actor') + '</th><td>' +
          row.actor.chain.map(function (one: Json): string {
            return code(one.id);
          }).join(' → ') + '</td></tr>' : '') + '</table>' +
      '<p class="sub">' + when + '</p>' + buttons + '</div>';
  }

  /**
   * The page's body.
   *
   * @param view - `GET /account-api/access-requests`'s answer
   * @param ctx - the render context
   * @returns the HTML
   */
  static render(view: Json, ctx: Json): string {
    const t = ctx.t;
    const rows: Json[] = view.rows || [];
    const granted: Json[] = view.granted || [];
    const waiting = rows.map(function (row: Json): string {
      return AccessRequestPages.card(row, t, 'pending');
    }).join('');
    const yours = granted.length
      ? '<div class="card"><p class="sub">' +
        t.html('portalAccessRequests.yours') + '</p></div>' +
        granted.map(function (row: Json): string {
          return AccessRequestPages.card(row, t, 'granted');
        }).join('')
      : '';
    const empty = rows.length || granted.length
      ? ''
      : '<div class="card"><p class="sub">' +
        t.html('portalAccessRequests.none') + '</p></div>';
    return '<div class="card"><p class="sub">' +
      t.html('portalAccessRequests.sub') +
      (view.enabled ? '' : ' ' + t.html('portalAccessRequests.off')) +
      '</p></div>' + waiting + yours + empty;
  }

  /**
   * The pages, for `web_portal_pages.ts`.
   */
  static readonly PAGES: PortalPage[] = [
    { path: PATH, operation: '/account-api/access-requests',
      render: AccessRequestPages.render }
  ];
}

export = AccessRequestPages;
