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
    // The page's words are its translator's (#539 phase 6); what the view
    // carries — names, times, a push's error — is drawn as it comes.
    const t = c.t;
    const policy = view.policy || {};
    const totals = view.totals || {};
    const params = { failing: view.filter && view.filter.failing
                       ? 'true' : '' };
    const nav = kit.pageNavPair(PAGE, params, view.paging, t);
    const tiles = '<div class="tiles">' +
      kit.tile(String(totals.accounts),
               t.text('consoleServiceAccounts.tileAccounts')) +
      kit.tile(String(totals.rotating),
               t.text('consoleServiceAccounts.tileRotating')) +
      kit.tile(String(totals.failing),
               t.text('consoleServiceAccounts.tileFailing')) +
      kit.tile(String(totals.alarms),
               t.text('consoleServiceAccounts.tileAlarms')) +
      '</div>';
    // The policy link carries an href, which a message may not, so the
    // sentence around it is three messages with the anchor in the code.
    const lead = kit.note(t.html('consoleServiceAccounts.leadBefore') +
      '<a href="/admin/policies#serviceAccount">' +
      t.html('consoleServiceAccounts.leadLink') + '</a>' +
      t.html('consoleServiceAccounts.leadAfter') +
      t.html('consoleServiceAccounts.rotationState',
             { state: policy.rotationEnabled ? 'on' : 'off' }) +
      (policy.rotationEnabled
        ? t.html('consoleServiceAccounts.rotationDetail',
                 { days: String(policy.intervalDays),
                   minutes: String(policy.overlapMinutes),
                   failures: String(policy.alarmFailures) })
        : '') + '.');
    const filter = '<form method="get" action="' + PAGE + '"><div ' +
      'class="formrow"><label><input type="checkbox" name="failing" ' +
      'value="true"' + (params.failing ? ' checked' : '') + '> ' +
      t.html('consoleServiceAccounts.onlyFailing') +
      '</label><button class="secondary">' +
      t.html('consoleServiceAccounts.filter') +
      '</button></div></form>';
    const rows = (view.accounts || []).map(function (row: Json): string {
      const r = row.rotation || {};
      return '<tr><td><a href="' + kit.esc('/admin/users' +
        kit.queryWith({ user: row.username }, {})) + '#service-account">' +
        kit.esc(row.username) + '</a></td><td>' +
        (row.destination ? '<code>' + kit.esc(row.destination) +
          '</code><br><code>' + kit.esc(row.secretName || '') + '</code>'
          : '<span class="state-none">' +
            t.html('consoleServiceAccounts.none') + '</span>') + '</td><td>' +
        (row.rotatedAt ? kit.esc(row.rotatedAt)
                       : t.html('consoleServiceAccounts.never')) +
        '</td><td>' +
        (r.nextDueAt ? kit.esc(r.nextDueAt)
                     : (r.rotates ? t.html('consoleServiceAccounts.now')
                                  : '—')) + '</td><td>' +
        kit.esc(row.previousPasswordUntil || '—') + '</td><td' +
        (r.alarm ? ' class="state-expired"' : '') + '>' +
        kit.esc(String(r.failures || 0)) + (r.lastError
          ? ' <code>' + kit.esc(r.lastError) + '</code>' : '') + '</td></tr>';
    }).join('');
    const table = '<table><tr><th>' +
      t.html('consoleServiceAccounts.thAccount') + '</th><th>' +
      t.html('consoleServiceAccounts.thDestination') + '</th><th>' +
      t.html('consoleServiceAccounts.thRotated') + '</th><th>' +
      t.html('consoleServiceAccounts.thNextDue') + '</th><th>' +
      t.html('consoleServiceAccounts.thPreviousUntil') + '</th><th>' +
      t.html('consoleServiceAccounts.thFailures') + '</th></tr>' + (rows ||
        '<tr><td colspan="6"><span class="state-none">' +
        t.html('consoleServiceAccounts.noAccounts') +
        '</span></td></tr>') + '</table>';
    return tiles + lead + filter + nav.head + table + nav.foot +
      kit.note(t.html('consoleServiceAccounts.footer'));
  }
}

export = ServiceAccountsPage;
