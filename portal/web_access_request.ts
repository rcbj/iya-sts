// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_access_request.ts
//
// ---------------------------------------------------------------------------
// `/portal/access-request`, DRAWN IN THE BROWSER (#1204), from
// `GET /account-api/access-request` (`portal_access_request.ts`): an
// AuthZEN requestable denial's hosted form (`form_url`), a request's ticket
// (`links.ticket`), or the requests about the signed-in person.
//
// The form shows what the denial asks — for whom, to do what, on what, for
// which application — and takes a business justification, how long the
// approval should last, and emergency access where the policy allows it. A
// real submit button. It never shows who may approve.
//
// The subject, action, resource and application are the denied tuple's —
// DATA, shown as code and never as wording, in every language. A policy's
// own `display` text is shown as the policy wrote it.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import kit = require('./web_portal_kit');

type Json = any;
type PortalPage = import('../types/account-api').PortalPage;

const PATH = kit.BASE + '/access-request';

// The approval lengths the form offers, in seconds; each is cut to the
// policy's longest by the service.
const DURATIONS = [3600, 86400, 604800];

/**
 * `/portal/access-request`. A static utility class.
 */
class AccessRequestFormPages {
  /**
   * A value of the denied tuple, as code.
   *
   * @param value - the value
   * @returns the HTML
   */
  static code(value: unknown): string {
    return '<code>' + kit.esc(String(value == null ? '' : value)) +
      '</code>';
  }

  /**
   * What a denial or a request asks, as a table.
   *
   * @param row - the denial or the request
   * @param t - the translator
   * @returns the HTML
   */
  static asks(row: Json, t: Json): string {
    const code = AccessRequestFormPages.code;
    const subject = row.subject || {};
    const resource = row.resource || {};
    const action = row.action || {};
    return '<table>' +
      '<tr><th>' + t.html('portalAccessRequest.subject') + '</th><td>' +
      code(subject.type) + ' ' + code(subject.id) + '</td></tr>' +
      '<tr><th>' + t.html('portalAccessRequest.action') + '</th><td>' +
      code(action.name) + '</td></tr>' +
      '<tr><th>' + t.html('portalAccessRequest.resource') + '</th><td>' +
      code(resource.type) + ' ' + code(resource.id) + '</td></tr>' +
      '<tr><th>' + t.html('portalAccessRequest.application') +
      '</th><td>' + code(row.application) + '</td></tr></table>';
  }

  /**
   * The form for a denial.
   *
   * @param request - the view's `request`
   * @param t - the translator
   * @returns the HTML
   */
  static form(request: Json, t: Json): string {
    const display = request.display || {};
    const policyWords = (display.title || display.description)
      ? '<div class="card" id="access-request-display">' +
        (display.title ? '<h2>' + kit.esc(display.title) + '</h2>' : '') +
        (display.description ? '<p>' + kit.esc(display.description) +
          '</p>' : '') + '</div>'
      : '';
    const longest = Number(request.maxApprovalS) || 0;
    const options = '<option value="">' +
      t.html('portalAccessRequest.durationLongest') + '</option>' +
      DURATIONS.filter(function (seconds: number): boolean {
        return !longest || seconds < longest;
      }).map(function (seconds: number): string {
        return '<option value="' + seconds + '">' +
          t.html('portalAccessRequest.duration' + seconds) + '</option>';
      }).join('');
    const emergency = request.emergency
      ? '<p><label><input type="checkbox" name="emergency" value="true" ' +
        'id="access-request-emergency"> ' +
        t.html('portalAccessRequest.emergency') + '</label></p>'
      : '';
    return policyWords +
      '<div class="card" id="access-request-form"><h2>' +
      t.html('portalAccessRequest.formHeading') + '</h2><p>' +
      t.html('portalAccessRequest.asks') + '</p>' +
      AccessRequestFormPages.asks(request, t) +
      '<p class="sub">' + t.html('portalAccessRequest.until',
        { when: t.date(Number(request.expiresAt) * 1000) }) + '</p>' +
      '<form method="post" action="' + PATH + '">' +
      '<input type="hidden" name="evaluation_id" value="' +
      kit.esc(request.evaluationId) + '">' +
      '<p><label>' + t.html('portalAccessRequest.justification') +
      '<br><textarea name="business_justification" maxlength="1024" ' +
      'rows="3" id="access-request-justification"></textarea></label>' +
      '<br><span class="sub">' +
      t.html('portalAccessRequest.justificationHint') + '</span></p>' +
      '<p><label>' + t.html('portalAccessRequest.duration') +
      ' <select name="duration" id="access-request-duration">' + options +
      '</select></label></p>' + emergency +
      '<button type="submit" id="access-request-submit">' +
      t.html('portalAccessRequest.submit') + '</button></form></div>';
  }

  /**
   * A request made, or the ticket.
   *
   * @param task - the view's `task`
   * @param t - the translator
   * @returns the HTML
   */
  static task(task: Json, t: Json): string {
    const until = task.approvedUntil
      ? '<p>' + t.html('portalAccessRequest.approvedUntil',
        { when: t.date(Number(task.approvedUntil) * 1000) }) + '</p>'
      : '';
    return '<div class="card" id="access-request-task"><h2>' +
      t.html('portalAccessRequest.taskHeading') + '</h2>' +
      '<p class="state-' + kit.esc(task.status) + '" ' +
      'id="access-request-status">' +
      t.html('portalAccessRequest.status', { status: task.status }) +
      '</p>' + until +
      AccessRequestFormPages.asks(task, t) +
      '<p class="sub">' + t.html('portalAccessRequest.made', {
        origin: task.origin,
        when: t.date(Number(task.createdAt) * 1000) }) + '</p></div>';
  }

  /**
   * The requests about the person.
   *
   * @param mine - the view's `mine`
   * @param t - the translator
   * @returns the HTML
   */
  static mine(mine: Json[], t: Json): string {
    if (!mine.length) {
      return '<div class="card"><p class="sub">' +
        t.html('portalAccessRequest.noneMine') + '</p></div>';
    }
    return '<div class="card"><h2>' +
      t.html('portalAccessRequest.mineHeading') + '</h2><table>' +
      mine.map(function (row: Json): string {
        const action = row.action || {};
        const resource = row.resource || {};
        return '<tr><td>' + AccessRequestFormPages.code(action.name) + ' ' +
          AccessRequestFormPages.code(resource.type) + ' ' +
          AccessRequestFormPages.code(resource.id) + '</td><td>' +
          AccessRequestFormPages.code(row.application) + '</td><td>' +
          t.html('portalAccessRequest.status', { status: row.status }) +
          '</td><td><a href="' + PATH + '?request=' +
          encodeURIComponent(String(row.id)) + '">' +
          t.html('portalAccessRequest.open') + '</a></td></tr>';
      }).join('') + '</table></div>';
  }

  /**
   * The page's body.
   *
   * @param view - `GET /account-api/access-request`'s answer
   * @param ctx - the render context
   * @returns the HTML
   */
  static render(view: Json, ctx: Json): string {
    const t = ctx.t;
    const intro = '<div class="card"><p class="sub">' +
      t.html('portalAccessRequest.sub') +
      (view.enabled ? '' : ' ' + t.html('portalAccessRequest.off')) +
      '</p></div>';
    if (view.mode === 'denial' && view.request) {
      return intro + AccessRequestFormPages.form(view.request, t);
    }
    if (view.mode === 'task' && view.task) {
      return intro + AccessRequestFormPages.task(view.task, t);
    }
    if (view.mode === 'mine') {
      return intro + AccessRequestFormPages.mine(view.mine || [], t);
    }
    return intro;
  }

  /**
   * The pages, for `web_portal_pages.ts`.
   */
  static readonly PAGES: PortalPage[] = [
    { path: PATH, operation: '/account-api/access-request',
      render: AccessRequestFormPages.render }
  ];
}

export = AccessRequestFormPages;
