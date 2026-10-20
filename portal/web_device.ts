// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_device.ts
//
// ---------------------------------------------------------------------------
// `/portal/device`, DRAWN IN THE BROWSER (#568), from `GET
// /account-api/device` (`portal_device.ts`): RFC 8628's verification URI.
// The find form always; above it, while a code brought one up, the request
// — the client and the scopes, and a warning — with Approve and Deny as a
// second, separate act (section 5.4). A real submit button and no script.
//
// WHICH ACCOUNT APPROVES, WHERE THE BROWSER HOLDS SEVERAL (#561): the
// approval is this tab's account's — the access token's subject, on the
// sign-on session it was issued on (`portal_device.ts`) — and the device is
// then signed in as that person. With more than one account signed in to
// this browser that is no longer obvious, and section 5.4's whole defence is
// showing the person what they are authorizing; so the request names the
// account it will be approved as (`device-as`). Drawn only then: with
// `authn.multipleAccounts` off, or one account, the page is the one it was.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import kit = require('./web_portal_kit');
import WebAccounts = require('../common/web_accounts');

type Json = any;
type PortalPage = import('../types/account-api').PortalPage;

const PATH = kit.BASE + '/device';

/**
 * `/portal/device`. A static utility class.
 */
class DevicePages {
  // "<client> asks to sign you in on a device showing the code <code>": the
  // two names carry ids a test or a reader's tools find them by, and a
  // catalog message may hold no attributes (#539). So the message is drawn
  // with two placeholder words, and each is replaced by its element after
  // the message is formatted. The placeholders are letters only, so
  // formatting escapes nothing in them, and the names go in escaped.
  /**
   * The sentence naming the client and the code.
   *
   * @param t - the translator
   * @param record - the request
   * @returns the HTML
   */
  static asks(t: Json, record: Json): string {
    const CLIENT = 'XDEVICECLIENTX';
    const CODE = 'XDEVICECODEX';
    return String(t.html('portalDevice.request.asks',
                         { client: CLIENT, code: CODE }))
      .replace(CLIENT, '<strong id="device-client">' +
               kit.esc(record.clientName || record.clientId) + '</strong>')
      .replace(CODE, '<code id="device-code">' + kit.esc(record.userCode) +
               '</code>');
  }

  /**
   * One answer's form.
   *
   * @param record - the request
   * @param action - `approve` or `deny`
   * @param label - the button's label
   * @param danger - whether the button is the dangerous one
   * @returns the HTML
   */
  static answer(record: Json, action: string, label: string,
                danger: boolean): string {
    return '<form method="post" action="' + PATH + '" ' +
      'style="display:inline">' +
      '<input type="hidden" name="action" value="' + action + '">' +
      '<input type="hidden" name="user_code" value="' +
      kit.esc(record.userCode) + '">' +
      '<button type="submit"' + (danger ? ' class="danger"' : '') +
      ' id="device-' + action + '">' + label + '</button></form> ';
  }

  /**
   * The page's body.
   *
   * @param view - `GET /account-api/device`'s answer
   * @param ctx - the render context
   * @returns the HTML
   */
  /**
   * The sentence naming the account the request will be approved as, where
   * the browser holds more than one signed-in account; '' otherwise.
   *
   * @param t - the translator
   * @param ctx - the render context: `me`, `accounts`
   * @returns the HTML, or ''
   */
  static approvingAs(t: Json, ctx: Json): string {
    const me = (ctx && ctx.me && ctx.me.user) || null;
    if (!me || WebAccounts.live(ctx.accounts).length < 2) {
      return '';
    }
    return '<p id="device-as">' + t.html('portalDevice.request.as',
      { name: String(me.username || '') }) + '</p>';
  }

  static render(view: Json, ctx: Json): string {
    const t = ctx.t;
    const record = view.record;
    const confirm = record
      ? '<div class="card" id="device-request"><h2>' +
        t.html('portalDevice.request.heading') + '</h2><p>' +
        DevicePages.asks(t, record) + '</p><p class="sub">' +
        t.html('portalDevice.request.access', {
          scope: record.scope || t.text('portalDevice.request.noScope'),
          when: t.date(record.expiresAt) }) + '</p>' +
        '<p>' + t.html('portalDevice.request.warning') + '</p>' +
        DevicePages.approvingAs(t, ctx) +
        DevicePages.answer(record, 'approve',
                           t.html('portalDevice.request.approve'), false) +
        DevicePages.answer(record, 'deny',
                           t.html('portalDevice.request.deny'), true) +
        '</div>'
      : '';
    return confirm +
      '<div class="card"><h2>' + t.html('portalDevice.find.heading') +
      '</h2><p class="sub">' + t.html('portalDevice.find.sub') +
      (view.enabled ? '' : ' ' + t.html('portalDevice.find.off')) + '</p>' +
      '<form method="get" action="' + PATH + '">' +
      '<label>' + t.html('portalDevice.find.code') + ' <input type="text" ' +
      'name="user_code" maxlength="32" required autocomplete="off" ' +
      'autocapitalize="characters" value="' + kit.esc(view.typed || '') +
      '"></label> <button type="submit" id="device-find">' +
      t.html('portalDevice.find.continue') + '</button></form></div>';
  }

  /**
   * The pages, for `web_portal_pages.ts`.
   */
  static readonly PAGES: PortalPage[] = [
    { path: PATH, operation: '/account-api/device',
      render: DevicePages.render }
  ];
}

export = DevicePages;
