// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_consent_screen.ts
//
// ---------------------------------------------------------------------------
// THE OAUTH CONSENT SCREEN, DRAWN IN THE BROWSER (#576, 2026-10-12).
//
// `/oauth2/consent` was `consent_screen.ts`'s `consentPage()` until #576;
// this is its renderer, over `GET /authn-api/consent/{id}`'s view
// (`ConsentScreen.consentView()`), and the page is a route of the sign-in
// surface (`authn/web_authn_pages.ts`), whose runtime sends Allow or Deny to
// `POST /authn-api/consent/{id}` with the limits a person lowered.
//
// WHAT IT DRAWS IS WHAT THE SERVER DREW, element for element: the heading,
// who is signed in and where, which application asks (its name, and the
// client_id under it where the two differ), one row per scope with the
// permission's description where it resolves to one, RFC 9396 section
// 11.2's detail rows member by member, what was already agreed under a fold,
// a detail's limits as controls a person may lower (`common/
// web_limits_form.ts`, the same markup GNAP's approval page draws), Allow and
// Deny with the ids they always had (`consent-allow`, `consent-deny` — the
// conformance suite's person and `consent_screen.js` press them), and the
// request's own parameters at the foot. Words from the `consent` catalogs
// (#539); what the request carried is data and drawn as it is.
//
// A `web_` MODULE: it requires only other `web_` modules and logs nothing.
// ---------------------------------------------------------------------------

import WebLimitsForm = require('../common/web_limits_form');

type Json = any;

/**
 * Escapes text for HTML, as `Html.esc()` does.
 *
 * @param value - anything
 * @returns the escaped text
 */
function esc(value: unknown): string {
  return String(value == null ? '' : value)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/**
 * The consent screen's renderer. A static utility class.
 */
class WebConsentScreen {
  /**
   * The page's path, where its form is sent from.
   */
  static readonly PATH = '/oauth2/consent';

  /**
   * One scope's row: the scope, and what it means here.
   *
   * @param one - `{ scope, permission }`
   * @param t - the translator
   * @returns the row
   */
  static scopeRow(one: Json, t: Json): string {
    const permission = one.permission;
    return '<li><code>' + esc(one.scope) + '</code>' +
      (permission
        ? '<span>' + t.html('consent.scope.permission', {
            description: permission.description ||
              t.text('consent.scope.permissionNamed',
                     { name: permission.name }),
            identifier: permission.identifier,
            baseUri: permission.baseUri }) + '</span>'
        : '<span>' + t.html('consent.scope.ordinary') + '</span>') +
      '</li>';
  }

  /**
   * One authorization detail's row (RFC 9396 section 11.2): its type, what
   * it is and where the token goes, and every member.
   *
   * @param one - `{ type, description, resource, audience, members }`
   * @param t - the translator
   * @returns the row
   */
  static detailRow(one: Json, t: Json): string {
    const where = { resource: one.resource, audience: one.audience };
    const members = Array.isArray(one.members) ? one.members : [];
    return '<li class="detail"><code>' + esc(one.type) + '</code>' +
      '<span>' + (one.description
        ? t.html('consent.detail.described',
                 Object.assign({ description: one.description }, where))
        : t.html('consent.detail.understood', where)) + '</span>' +
      (members.length
        ? '<dl>' + members.map(function (member: Json): string {
          return '<dt>' + esc(member.name) + '</dt><dd><code>' +
            esc(member.value) + '</code></dd>';
        }).join('') + '</dl>'
        : '') +
      '</li>';
  }

  /**
   * What the whole request asked for that is already agreed, under a fold.
   *
   * @param already - `[{ scope, global, at }]`
   * @param t - the translator
   * @returns the fold, or ''
   */
  static already(already: Json[], t: Json): string {
    if (!already.length) {
      return '';
    }
    return '<details><summary>' + t.html('consent.already.summary',
                                         { count: already.length }) +
      '</summary><ul class="scopes">' +
      already.map(function (one: Json): string {
        return '<li><code>' + esc(one.scope) + '</code><span>' +
          (one.global
            ? t.html('consent.already.global')
            : (one.at ? t.html('consent.already.byYouAt', { at: one.at })
                      : t.html('consent.already.byYou'))) +
          '</span></li>';
      }).join('') + '</ul></details>';
  }

  /**
   * The limits a person may lower, each detail's under its type.
   *
   * @param limits - `[{ r, type, limits, rows }]`
   * @returns the list, or ''
   */
  static limits(limits: Json[]): string {
    const rows = limits.map(function (one: Json): string {
      const controls = WebLimitsForm.controls(one.limits, one.rows || [], 0,
                                              Number(one.r) || 0, esc);
      return controls ? '<li class="detail"><code>' + esc(one.type) +
        '</code>' + controls + '</li>' : '';
    }).join('');
    return rows ? '<ul class="scopes">' + rows + '</ul>' : '';
  }

  /**
   * The page's body, under the language chooser.
   *
   * @param view - `GET /authn-api/consent/{id}`'s view
   * @param ctx - the surface's context: `t`, and an act's `error`
   * @returns the body
   */
  static render(view: Json, ctx: Json): string {
    const t = ctx.t;
    const v = view || {};
    const client = v.client || {};
    const scopes = Array.isArray(v.scopes) ? v.scopes : [];
    const details = Array.isArray(v.authorizationDetails)
      ? v.authorizationDetails : [];
    const error = String((ctx && ctx.error) || '');
    return '<h1>' + t.html('consent.heading') + '</h1>' +
      '<p class="sub">' + t.html('consent.signedInAs',
        { username: String(v.username || ''), base: String(v.base || '') }) +
      '</p>' +
      (error ? '<div class="err" id="consent-error">' + esc(error) +
               '</div>' : '') +
      '<p class="app">' + t.html('consent.asking',
                                 { client: String(client.name || '') }) +
      (client.name === client.id ? ''
        : '<br><code>' + esc(client.id) + '</code>') + '</p>' +
      '<ul class="scopes">' + scopes.map(function (one: Json): string {
        return WebConsentScreen.scopeRow(one, t);
      }).join('') + details.map(function (one: Json): string {
        return WebConsentScreen.detailRow(one, t);
      }).join('') + '</ul>' +
      (details.length
        ? '<p class="app">' + t.html('consent.detailsNote',
            { count: details.length }) + '</p>'
        : '') +
      WebConsentScreen.already(Array.isArray(v.already) ? v.already : [], t) +
      '<form method="post" action="' + WebConsentScreen.PATH + '">' +
      WebConsentScreen.limits(Array.isArray(v.limits) ? v.limits : []) +
      '<div class="row"><button type="submit" id="consent-allow" ' +
      'name="action" value="allow">' + t.html('consent.allow') +
      '</button><button type="submit" id="consent-deny" name="action" ' +
      'value="deny" class="secondary">' + t.html('consent.deny') +
      '</button></div></form>' +
      '<div class="meta"><div>' + t.html('consent.meta.allow',
        { attribute: String(v.attribute || '') }) + '</div><div>' +
      t.html('consent.meta.nothingIssued') + '</div><div>' +
      t.html('consent.meta.consentingFor',
             { protocol: String(v.protocol || '') }) + '</div>' +
      (Array.isArray(v.details) ? v.details : []).map(function (d: Json) {
        return '<div>' + esc(d.label) + ': <code>' +
          esc(d.value == null ? '' : d.value) + '</code>' +
          (d.note ? ' (' + esc(d.note) + ')' : '') + '</div>';
      }).join('') + '</div>';
  }

  /**
   * The document's title.
   *
   * @param view - the view
   * @param ctx - the context
   * @returns the title, as text
   */
  static title(view: Json, ctx: Json): string {
    void view;
    return ctx.t.text('consent.title');
  }
}

export = WebConsentScreen;
