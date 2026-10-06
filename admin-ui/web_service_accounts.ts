// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_service_accounts.ts
//
// ---------------------------------------------------------------------------
// MONITORING → SERVICE ACCOUNTS (#221), DRAWN FROM ITS VIEW ALONE.
//
// Draws the answer of `GET /admin-api/service-accounts`: every service
// account in the realm, its push destination, and the state of its password
// rotation — last rotated, next due, failures in a row and the alarm. A
// service account is a PERSON, so its own page is on Users; this page is the
// rotation's, which is why it is filed under Monitoring.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');

type Json = any;

/**
 * The console path of Monitoring → Service accounts.
 */
const PAGE = '/admin/service-accounts';

/**
 * Draws Monitoring → Service accounts from the answer of
 * `GET /admin-api/service-accounts`.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class ServiceAccountsPage {
  /**
   * Draws the page's body from its view.
   *
   * @param view - the answer of the page's management API operation
   * @param ctx - the render context (`WebKit.context()`)
   * @returns the body as HTML
   */
  static render(view: Json, ctx: Json): string {
    const c = ctx || kit.context();
    const policy = view.policy || {};
    const totals = view.totals || {};
    const params = { failing: view.filter && view.filter.failing
                       ? 'true' : '' };
    const nav = kit.pageNavPair(PAGE, params, view.paging);
    const tiles = '<div class="tiles">' +
      kit.tile(String(totals.accounts), 'service accounts') +
      kit.tile(String(totals.rotating), 'rotating') +
      kit.tile(String(totals.failing), 'last rotation failed') +
      kit.tile(String(totals.alarms), 'alarms') +
      '</div>';
    const lead = kit.note('A <strong>service account</strong> is a person ' +
      'entry used by a program (#221). Where this realm\'s <a ' +
      'href="/admin/policies#serviceAccount">service-account policy</a> ' +
      'turns rotation on, the <code>service-accounts.rotate</code> job gives ' +
      'every account that names a push destination a new password each ' +
      'interval: pushed to the destination FIRST, committed here only once ' +
      'the push succeeded, the previous password still accepted for the ' +
      'overlap. A failed push changes nothing and is tried again at the next ' +
      'run. Rotation is <strong>' + (policy.rotationEnabled ? 'on' : 'off') +
      '</strong> in this realm' + (policy.rotationEnabled
        ? ': every ' + kit.esc(String(policy.intervalDays)) + ' days, the ' +
          'previous password working for ' +
          kit.esc(String(policy.overlapMinutes)) + ' minutes, an alarm ' +
          'after ' + kit.esc(String(policy.alarmFailures)) + ' failures in ' +
          'a row'
        : '') + '.');
    const filter = '<form method="get" action="' + PAGE + '"><div ' +
      'class="formrow"><label><input type="checkbox" name="failing" ' +
      'value="true"' + (params.failing ? ' checked' : '') + '> only accounts ' +
      'whose last rotation failed</label><button class="secondary">Filter' +
      '</button></div></form>';
    const rows = (view.accounts || []).map(function (row: Json): string {
      const r = row.rotation || {};
      return '<tr><td><a href="' + kit.esc('/admin/users' +
        kit.queryWith({ user: row.username }, {})) + '#service-account">' +
        kit.esc(row.username) + '</a></td><td>' +
        (row.destination ? '<code>' + kit.esc(row.destination) +
          '</code><br><code>' + kit.esc(row.secretName || '') + '</code>'
          : '<span class="state-none">none</span>') + '</td><td>' +
        kit.esc(row.rotatedAt || 'never') + '</td><td>' +
        kit.esc(r.nextDueAt || (r.rotates ? 'now' : '—')) + '</td><td>' +
        kit.esc(row.previousPasswordUntil || '—') + '</td><td' +
        (r.alarm ? ' class="state-expired"' : '') + '>' +
        kit.esc(String(r.failures || 0)) + (r.lastError
          ? ' <code>' + kit.esc(r.lastError) + '</code>' : '') + '</td></tr>';
    }).join('');
    const table = '<table><tr><th>Account</th><th>Push destination</th>' +
      '<th>Last rotated</th><th>Next due</th><th>Previous password until' +
      '</th><th>Failures in a row</th></tr>' + (rows ||
        '<tr><td colspan="6"><span class="state-none">No service accounts ' +
        'in this realm.</span></td></tr>') + '</table>';
    void c;
    return tiles + lead + filter + nav.head + table + nav.foot +
      kit.note('The same over JSON is <code>GET /admin-api/' +
               'service-accounts</code>; Rotate now is on each account\'s ' +
               'page and at <code>POST /admin-api/users/rotate-password' +
               '</code>.');
  }
}

export = ServiceAccountsPage;
