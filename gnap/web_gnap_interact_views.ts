// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_gnap_interact_views.ts
//
// ---------------------------------------------------------------------------
// GNAP'S INTERACTION PAGES, DRAWN IN THE BROWSER (#578, 2026-10-12).
//
// The pages a resource owner reads in an RFC 9635 section 4 interaction were
// drawn by `gnap/gnap_interact.ts` until #578; these are their renderers,
// moved with their markup, over the views that module now answers:
//
//   * the user code page — `GET /gnap-api/code`'s view, which carries
//     nothing but its kind: the page is the same for everybody;
//   * the approval page — `GET /gnap-api/approve/{id}`'s view
//     (`GnapInteract.approvalView()`): the client as it is registered and as
//     it describes itself, each right as the request's own facts (RFC 9635
//     section 8) with its limit controls, what the issuance policy narrowed,
//     the subject information asked for, and what follows;
//   * what is said after — a decision made (`done`), a request sent to the
//     person it names (`sent`), and a refusal (`problem`, English, as every
//     refusal here), each the view a shell carries in `data-sts-state` or an
//     act answers.
//
// The words are the `gnap` catalogs #539 wrote for these pages; the
// dimension names and values, the identifiers and the URIs are the
// request's own and are drawn as they are. A right's limit controls are
// drawn from the limits and their rows in the view by
// `common/web_limits_form.ts` — the consent screen's drawing since #576 —
// because every page that asks about limits must draw them alike.
//
// A `web_` MODULE: it requires only another `web_` module and logs nothing.
// ---------------------------------------------------------------------------

import WebLimitsForm = require('../common/web_limits_form');

type Json = any;

/**
 * The renderers of GNAP's interaction pages. A static utility class.
 */
class WebGnapInteractViews {
  /**
   * Escapes text for HTML, as `Html.esc()` does.
   *
   * @param value - anything
   * @returns the escaped text
   */
  static esc(value: unknown): string {
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  /**
   * Draws a page's body from its view, by the view's kind.
   *
   * @param view - the view
   * @param ctx - the surface's context: `t`
   * @returns the body
   */
  static render(view: Json, ctx: Json): string {
    const v = view || {};
    switch (v.kind) {
      case 'code':
        return WebGnapInteractViews.code(v, ctx);
      case 'approve':
        return WebGnapInteractViews.approve(v, ctx);
      case 'done':
        return WebGnapInteractViews.done(v, ctx);
      case 'sent':
        return WebGnapInteractViews.sent(v, ctx);
      default:
        return WebGnapInteractViews.problem(v);
    }
  }

  /**
   * The document's title for a view.
   *
   * @param view - the view
   * @param ctx - the context
   * @returns the title, as text
   */
  static title(view: Json, ctx: Json): string {
    const t = ctx.t;
    const v = view || {};
    const titled = function (title: string): string {
      return t.text('gnap.pageTitle', { title: title });
    };
    switch (v.kind) {
      case 'code':
        return titled(t.text('gnap.code.title'));
      case 'approve':
        return titled(t.text('gnap.approve.heading'));
      case 'done':
        return titled(v.approved ? t.text('gnap.done.approvedTitle')
                                 : t.text('gnap.done.deniedTitle'));
      case 'sent':
        return titled(t.text('gnap.sent.title'));
      default:
        // A refusal is English (#539's decision 6), its title too.
        return String(v.heading || 'Something went wrong') +
          ' — GNAP authorization server';
    }
  }

  /**
   * The user code page (RFC 9635 sections 4.1.2 and 4.1.3).
   *
   * @param view - the view
   * @param ctx - the context
   * @returns the body
   */
  static code(view: Json, ctx: Json): string {
    const t = ctx.t;
    void view;
    return '<h1>' + t.html('gnap.code.heading') + '</h1><p class="sub">' +
      t.html('gnap.code.sub') + '</p>' +
      '<form method="post" action="/gnap/code">' +
      '<input type="text" class="code" name="code" id="gnap-code" ' +
      'autocomplete="one-time-code" autocapitalize="characters" ' +
      'spellcheck="false" autofocus required><div class="row"><button ' +
      'type="submit" id="gnap-code-continue">' + t.html('gnap.code.continue') +
      '</button></div></form><div class="meta"><div>' +
      t.html('gnap.code.meta') + '</div></div>';
  }

  /**
   * One access right, as the request named it.
   *
   * @param right - the right's facts
   * @param t - the translator
   * @returns the markup
   */
  static right(right: Json, t: Json): string {
    const esc = WebGnapInteractViews.esc;
    const r = right || {};
    if (r.reference !== undefined) {
      return '<code>' + esc(r.reference) + '</code><span>' + (r.registered
        ? t.html('gnap.right.registered', {
          rs: String(r.registered.rs),
          access: (r.registered.access || []).join(', ') })
        : t.html('gnap.right.reference')) + '</span>';
    }
    const parts = (r.dimensions || []).map(function (one: Json): string {
      return one.name + ': ' + (one.values || []).join(', ');
    });
    if (r.identifier) {
      parts.push('identifier: ' + r.identifier);
    }
    return '<code>' + esc(r.type) + '</code><span>' +
      (parts.length ? esc(parts.join('; '))
                    : t.html('gnap.right.everyAction')) + '</span>';
  }

  /**
   * The approval page.
   *
   * @param view - `GnapInteract.approvalView()`'s view
   * @param ctx - the context
   * @returns the body
   */
  static approve(view: Json, ctx: Json): string {
    const t = ctx.t;
    const esc = WebGnapInteractViews.esc;
    const client = view.client || {};
    // A logo only where the view carries one: a `data:` image the
    // application ENTRY registered, never one the request declared.
    const logo = client.logo
      ? '<img class="logo" alt="" src="' + esc(client.logo) + '">' : '';
    const unverified = ' <span class="sub">' +
      t.html('gnap.approve.unverified') + '</span>';
    let rows = '';
    (view.tokens || []).forEach(function (token: Json) {
      rows += token.heading
        ? '<li><strong>' + t.html('gnap.approve.token',
            { label: token.label || String(token.number) }) + '</strong>' +
          (token.bearer ? ' ' + t.html('gnap.approve.bearer') : '') + '</li>'
        : '';
      (token.rights || []).forEach(function (one: Json) {
        rows += '<li><label><input type="checkbox" name="right" value="' +
          esc(one.field) + '" checked><span>' +
          WebGnapInteractViews.right(one.right, t) + '</span></label>' +
          WebLimitsForm.controls(one.limits, one.limitRows || [],
                                 Number(one.token), Number(one.index), esc) +
          '</li>';
      });
    });
    const narrowed = (view.narrowed || []).map(function (one: Json): string {
      const taken = (one.changes || []).map(function (c: Json): string {
        return c.how === 'removed'
          ? c.dimension + ' ' + (c.values || []).join(', ')
          : t.text('gnap.approve.limitedTo',
                   { dimension: c.dimension,
                     values: (c.values || []).join(', ') });
      });
      return '<li><code>' + esc(one.type) + '</code>: ' +
        esc(taken.join('; ') || t.text('gnap.approve.narrowed')) + '</li>';
    }).join('');
    if (view.subject) {
      rows += '<li><label><input type="checkbox" name="subject" value="yes" ' +
        'checked><span><strong>' + t.html('gnap.approve.subject') +
        '</strong><span>' + t.html('gnap.approve.subjectDetail', {
          ids: (view.subject.ids || []).join(', ') ||
               t.text('gnap.approve.none'),
          assertions: (view.subject.assertions || []).join(', ') ||
                      t.text('gnap.approve.none') }) +
        '</span></span></label></li>';
    }
    const finish = view.finish;
    return logo + '<h1>' + t.html('gnap.approve.heading') + '</h1>' +
      '<p class="sub">' + t.html('gnap.approve.signedInAs',
                                 { name: String(view.username) }) + '</p>' +
      '<p class="app"><strong>' + esc(client.name || client.identifier) +
      '</strong>' + (client.nameDeclared ? unverified : '') + ' ' +
      t.html('gnap.approve.asking') +
      (client.uri ? '<br><a href="' + esc(client.uri) + '" ' +
          'rel="noreferrer">' + esc(client.uri) + '</a>' +
        (client.uriDeclared ? unverified : '') : '') + '</p>' +
      '<form method="post" action="/gnap/approve/' + esc(view.id) + '">' +
      (narrowed ? '<p class="sub">' + t.html('gnap.approve.narrowedIntro') +
        '</p><ul class="rights">' + narrowed + '</ul>' : '') +
      '<ul class="rights">' + (rows || '<li>' +
        t.html('gnap.approve.nothing') + '</li>') +
      '</ul><div class="row"><button type="submit" id="gnap-allow" ' +
      'name="action" value="allow">' + t.html('gnap.approve.allow') +
      '</button><button type="submit" id="gnap-deny" name="action" ' +
      'value="deny" class="secondary">' + t.html('gnap.approve.deny') +
      '</button></div></form><div class="meta"><div>' +
      t.html('gnap.approve.untick') + '</div>' +
      (finish ? '<div>' + (finish.method === 'redirect'
        ? t.html('gnap.approve.afterRedirect', { uri: String(finish.uri) })
        : t.html('gnap.approve.afterPush', { uri: String(finish.uri) })) +
        '</div>'
        : '<div>' + t.html('gnap.approve.afterClose') + '</div>') +
      '<div>' + t.html('gnap.approve.client', {
        id: String(client.identifier), proof: String(client.proof) }) +
      (client.classId ? ' · ' +
        t.html('gnap.approve.class', { classId: String(client.classId) }) +
        (client.classIdDeclared
          ? ' (' + t.html('gnap.approve.selfDeclared') + ')' : '') : '') +
      '</div><div>' + t.html('gnap.approve.server',
                             { endpoint: String(view.grantEndpoint) }) +
      '</div></div>';
  }

  /**
   * What is said once the decision is made and the finish followed.
   *
   * @param view - `GnapInteract.doneView()`'s view
   * @param ctx - the context
   * @returns the body
   */
  static done(view: Json, ctx: Json): string {
    const t = ctx.t;
    const name = String(view.name || '');
    return '<h1>' + (view.approved ? t.html('gnap.done.approved')
                                   : t.html('gnap.done.denied')) +
      '</h1><p class="sub">' + (view.pushed === true
        ? t.html('gnap.done.told', { name: name })
        : (view.pushed === false
          ? t.html('gnap.done.notTold', { name: name })
          : t.html('gnap.done.returnTo', { name: name }))) + '</p>';
  }

  /**
   * What is said when the request names somebody else, and waits for them.
   *
   * @param view - the view
   * @param ctx - the context
   * @returns the body
   */
  static sent(view: Json, ctx: Json): string {
    const t = ctx.t;
    void view;
    return '<h1>' + t.html('gnap.sent.heading') + '</h1><p class="sub">' +
      t.html('gnap.sent.sub') + '</p>';
  }

  /**
   * A refusal: a link, a code or an answer this service cannot take. In
   * English, as every refusal here is.
   *
   * @param view - `{ heading, detail }`
   * @returns the body
   */
  static problem(view: Json): string {
    const esc = WebGnapInteractViews.esc;
    return '<h1>' + esc(view.heading || 'Something went wrong') +
      '</h1><p class="err">' + esc(view.detail || '') + '</p><div ' +
      'class="meta"><div>Nothing was approved and nothing was sent to any ' +
      'application. Start again from the application that sent you ' +
      'here.</div></div>';
  }
}

export = WebGnapInteractViews;
