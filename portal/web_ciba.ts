// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_ciba.ts
//
// ---------------------------------------------------------------------------
// `/portal/ciba`, DRAWN IN THE BROWSER (#568), from `GET /account-api/ciba`
// (`portal_ciba.ts`): the CIBA sign-in requests waiting for the person, each
// with Approve and Deny; the person's CIBA user code; and the GNAP grants
// waiting for them as their owner, each right with its checkbox and its
// limit controls (#432). An approval stronger than the session proved is
// answered `stepUp` and the runtime signs in again; nothing here asks for
// it.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import kit = require('./web_portal_kit');

type Json = any;
type PortalPage = import('../types/account-api').PortalPage;

const PATH = kit.BASE + '/ciba';

/**
 * `/portal/ciba`. A static utility class.
 */
class CibaPages {
  /**
   * One CIBA request's answer.
   *
   * @param action - `approve` or `deny`
   * @param id - the request
   * @param label - the button's label
   * @param danger - whether the button is the dangerous one
   * @returns the HTML
   */
  static form(action: string, id: string, label: string,
              danger: boolean): string {
    return '<form method="post" action="' + PATH + '" ' +
      'style="display:inline">' +
      '<input type="hidden" name="action" value="' + action + '">' +
      '<input type="hidden" name="id" value="' + kit.esc(id) + '">' +
      '<button type="submit"' + (danger ? ' class="danger"' : '') +
      ' id="ciba-' + action + '">' + label + '</button></form> ';
  }

  /**
   * One CIBA request.
   *
   * @param one - the request
   * @param t - the translator
   * @returns the HTML
   */
  static request(one: Json, t: Json): string {
    // The binding message keeps its `id`, which a catalog message may not
    // carry, so the sentence is two messages around it.
    return '<div class="card ciba-request" id="ciba-' +
      kit.esc(String(one.id).slice(0, 12)) + '"><p>' +
      t.html('portalCiba.request.asks', { client: one.clientName }) +
      '</p>' +
      (one.bindingMessage
        ? '<p>' + t.html('portalCiba.request.says') +
          ' <strong id="ciba-binding">' + kit.esc(one.bindingMessage) +
          '</strong> ' + t.html('portalCiba.request.saysCheck') + '</p>'
        : '') +
      (one.requestContext
        ? '<p class="sub" id="ciba-context">' +
          t.html('portalCiba.request.context') + ' ' +
          one.requestContext.map(function (pair: Json): string {
            return kit.esc(pair.name) + ' <code>' + kit.esc(pair.value) +
              '</code>';
          }).join('; ') + '</p>' : '') +
      '<p class="sub">' + ((one.acrValues || []).length
        ? t.html('portalCiba.request.accessLevel',
            { scope: one.scope, level: one.acrValues.join(' '),
              when: t.date(one.expiresAt) })
        : t.html('portalCiba.request.access',
            { scope: one.scope, when: t.date(one.expiresAt) })) + '</p>' +
      CibaPages.form('approve', one.id, t.html('portalCiba.approve'), false) +
      CibaPages.form('deny', one.id, t.html('portalCiba.deny'), true) +
      '</div>';
  }

  /**
   * One GNAP right's description.
   *
   * @param right - `{ reference }` or `{ type, parts }`
   * @param t - the translator
   * @returns the HTML
   */
  static right(right: Json, t: Json): string {
    if (right.reference !== undefined) {
      return '<code>' + kit.esc(right.reference) + '</code>';
    }
    return '<code>' + kit.esc(right.type) + '</code> ' +
      (right.parts ? kit.esc(right.parts)
                   : t.html('portalCiba.gnap.everyAction'));
  }

  /**
   * The GNAP grants waiting for the person, or '' where none is.
   *
   * @param waiting - the view's `gnap`
   * @param t - the translator
   * @returns the HTML
   */
  static gnap(waiting: Json[], t: Json): string {
    if (!waiting || !waiting.length) {
      return '';
    }
    const cards = waiting.map(function (one: Json): string {
      let rows = (one.rights || []).map(function (right: Json): string {
        // `limitsHtml` is the server's drawing of the right's limit
        // controls (`LimitsForm.controls()`), escaped there.
        return '<li><label><input type="checkbox" name="right" value="' +
          kit.esc(right.field) + '" checked> ' + CibaPages.right(right, t) +
          '</label>' + String(right.limitsHtml || '') + '</li>';
      }).join('');
      if (one.subject) {
        rows += '<li><label><input type="checkbox" name="subject" ' +
          'value="yes" checked> ' + t.html('portalCiba.gnap.whoYouAre') +
          '</label></li>';
      }
      const short = kit.esc(String(one.id).slice(0, 12));
      const form = function (action: string, label: string, inner: string,
                             danger: boolean): string {
        return '<form method="post" action="' + PATH + '">' +
          '<input type="hidden" name="action" value="' + action + '">' +
          '<input type="hidden" name="id" value="' + kit.esc(one.id) + '">' +
          inner + '<button type="submit"' + (danger ? ' class="danger"' : '') +
          ' id="' + action + '-' + short + '">' + label + '</button></form>';
      };
      // `declared` and `using` are yes/no selects, so the sentence is one
      // message a translation can reorder (#539).
      return '<div class="card gnap-request" id="gnap-' + short + '"><p>' +
        t.html('portalCiba.gnap.asks', {
          display: one.display, client: one.client,
          declared: one.declared ? 'yes' : 'no',
          using: one.requestedBy ? 'yes' : 'no',
          by: one.requestedBy || '' }) + '</p>' +
        ((one.acr || []).length ? '<p class="sub">' +
          t.html('portalCiba.gnap.level', { level: one.acr.join(' '),
            path: PATH + '?gnapstepup=' + encodeURIComponent(one.id) }) +
          '</p>' : '') +
        '<p class="sub">' + t.html('portalCiba.gnap.expires',
          { when: t.date(Number(one.expiresAt) * 1000) }) + '</p>' +
        form('gnap-approve', t.html('portalCiba.approve'),
             '<ul class="rights">' + rows + '</ul>', false) +
        form('gnap-deny', t.html('portalCiba.deny'), '', true) + '</div>';
    });
    return '<div class="card"><h2>' + t.html('portalCiba.gnap.heading') +
      '</h2><p class="sub">' + t.html('portalCiba.gnap.intro') + '</p>' +
      '</div>' + cards.join('');
  }

  /**
   * The page's body.
   *
   * @param view - `GET /account-api/ciba`'s answer
   * @param ctx - the render context
   * @returns the HTML
   */
  static render(view: Json, ctx: Json): string {
    const t = ctx.t;
    const requests: Json[] = view.requests || [];
    return '<div class="card"><h2>' +
      t.html('portalCiba.requests.heading') + '</h2>' +
      '<p class="sub">' + t.html('portalCiba.requests.intro') +
      (view.enabled ? '' : ' ' + t.html('portalCiba.requests.off')) +
      '</p>' +
      (requests.length ? requests.map(function (one: Json): string {
        return CibaPages.request(one, t);
      }).join('') : '<p id="ciba-none">' +
        t.html('portalCiba.requests.none') + '</p>') + '</div>' +
      '<div class="card"><h2>' + t.html('portalCiba.code.heading') +
      '</h2><p class="sub">' + t.html('portalCiba.code.intro') + ' ' +
      (view.hasCode ? t.html('portalCiba.code.isSet')
                    : t.html('portalCiba.code.notSet')) + '</p>' +
      '<form method="post" action="' + PATH + '">' +
      '<input type="hidden" name="action" value="set-code">' +
      '<label>' + t.html('portalCiba.code.new') +
      ' <input type="password" name="code" minlength="4" maxlength="64" ' +
      'required autocomplete="off"></label> ' +
      '<button type="submit" id="ciba-set-code">' +
      t.html('portalCiba.code.set') + '</button></form>' +
      (view.hasCode ? '<form method="post" action="' + PATH + '">' +
        '<input type="hidden" name="action" value="clear-code">' +
        '<button class="danger" type="submit">' +
        t.html('portalCiba.code.clear') + '</button></form>' : '') +
      '</div>' + CibaPages.gnap(view.gnap, t);
  }

  /**
   * The pages, for `web_portal_pages.ts`.
   */
  static readonly PAGES: PortalPage[] = [
    { path: PATH, operation: '/account-api/ciba', render: CibaPages.render }
  ];
}

export = CibaPages;
