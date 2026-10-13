// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_authn_spnego.ts
//
// ---------------------------------------------------------------------------
// THE SPNEGO SIGN-IN'S PAGES, DRAWN IN THE BROWSER (#575, 2026-10-12).
//
// `GET /authn/spnego` (`kerberos/spnego_authn.ts`) is an RFC 4559 exchange,
// and that exchange is NOT converted (#569's rule): the 401 with
// `WWW-Authenticate: Negotiate`, the `Authorization` round trips, the final
// mutual-authentication token, the 403 when the door is off and the 303 to
// `returnTo` keep their statuses, their headers and the top-level navigation
// that carries them. The runtime never drives Negotiate through `fetch()`.
//
// What changed is the BODY a person sees on three of those responses, which
// is now the sign-in surface's shell carrying the state its page is drawn
// from (`data-sts-state` on `<html>`, read by `authn/web_authn.ts`):
//
//   * `challenge` — the first 401's body: what the Negotiate challenge is,
//     the link back to the password screen for the request that is waiting,
//     and what to do when nothing happened (a browser not configured for
//     this host), with the service principal a program asks a ticket for.
//   * `off` — the 403 when `krb5.spnegoAuthentication` is false, naming the
//     setting. A refusal, so its sentences are English (#539's decision 6)
//     — only the link back to the password screen is translated.
//   * `signed-in` — the 200 when nothing was interrupted (no `returnTo`):
//     who is now signed in, the session, and what the ticket claimed.
//
// The acceptor's checks are the negotiation's diagnostics and are drawn in
// English, as `spnego.js`'s `checksTable()` draws them.
//
// A `web_` MODULE: it requires nothing and logs nothing. It sits beside
// `spnego_authn.ts` and is reached only from the sign-in surface's page table
// (`authn/web_authn_pages.ts`); no file of the parent project's COPY closure
// requires it.
// ---------------------------------------------------------------------------

type Json = any;

// The password screen a waiting sign-in can go back to, and the console page
// the door is turned on from — `authn.LOGIN_PATH` and `/admin/kerberos`,
// root-relative, so the surface's realm rewrite puts them under the realm.
const LOGIN_PATH = '/authn/login';
const CONSOLE_PATH = '/admin/kerberos';

/**
 * The SPNEGO sign-in's renderers. A static utility class.
 */
class WebAuthnSpnego {
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
   * The link back to the password screen for the request that is waiting,
   * or the sentence saying nothing is (`spnego_authn.ts`'s `fallbackHtml()`
   * until #575).
   *
   * @param view - the page's view; `pending` is `{ id, protocol,
   *   application }` or null
   * @param t - the translator
   * @returns the HTML
   */
  static fallback(view: Json, t: Json): string {
    const esc = WebAuthnSpnego.esc;
    const pending = view && view.pending;
    if (!pending || !pending.id) {
      return '<p class="sub">' + t.html('spnego.fallback.none') + '</p>';
    }
    return '<p><a id="spnego-password" href="' + esc(LOGIN_PATH) +
      '?authn=' + encodeURIComponent(String(pending.id)) + '">' +
      t.html('spnego.fallback.instead') + '</a> ' +
      t.html('spnego.fallback.stillWaiting') + '</p>' +
      '<p class="sub">' + t.html('spnego.fallback.signingInFor',
                                 { protocol: String(pending.protocol || '') }) +
      (pending.application
         ? ' &middot; <code>' + esc(pending.application) + '</code>'
         : '') + '</p>';
  }

  /**
   * The acceptor's checks, in English (`spnego.js`'s `checksTable()`).
   *
   * @param checks - `[{ name, ok, detail }]`
   * @param t - the translator, for the heading
   * @returns the HTML, '' for none
   */
  static checks(checks: Json, t: Json): string {
    const esc = WebAuthnSpnego.esc;
    if (!Array.isArray(checks) || !checks.length) {
      return '';
    }
    return '<h2>' + t.html('spnego.checked') + '</h2>' +
      '<table id="spnego-checks"><tr><th>Check</th><th>Result</th>' +
      '<th>Detail</th></tr>' +
      checks.map(function (c: Json): string {
        return '<tr><td>' + esc(c.name) + '</td><td class="' +
          (c.ok ? 'pass">passed' : 'fail">FAILED') + '</td><td>' +
          esc(c.detail == null ? '' : String(c.detail)) + '</td></tr>';
      }).join('') + '</table>';
  }

  /**
   * The service principal, its realm and the hosts the acceptor answers
   * for (`spnFacts()` until #575).
   *
   * @param view - the view: `spn`, `realm`, `hosts`
   * @param t - the translator
   * @returns the HTML
   */
  static facts(view: Json, t: Json): string {
    const esc = WebAuthnSpnego.esc;
    return '<table id="spnego-facts">' +
      '<tr><th>' + t.html('spnego.facts.what') + '</th><th>' +
      t.html('spnego.facts.value') + '</th></tr>' +
      '<tr><td>' + t.html('spnego.facts.spn') + '</td><td><code>' +
      esc(String(view.spn || '') + '@' + String(view.realm || '')) +
      '</code></td></tr>' +
      '<tr><td>' + t.html('spnego.facts.realm') + '</td><td><code>' +
      esc(view.realm) + '</code></td></tr>' +
      // No row where there are no such hosts (product mode, where the KDC
      // knows only the SPN above): an empty "also answers for" read as a
      // promise about every host.
      ((view.hosts || []).length
        ? '<tr><td>' + t.html('spnego.facts.hosts') + '</td><td><code>' +
          esc(view.hosts.join(', ')) + '</code></td></tr>'
        : '') + '</table>';
  }

  /**
   * The first 401's page.
   *
   * @param view - the view
   * @param t - the translator
   * @returns the HTML
   */
  static challenge(view: Json, t: Json): string {
    return '<h1>' + t.html('spnego.first.heading') + '</h1>' +
      '<p>' + t.html('spnego.first.lead') + '</p>' +
      WebAuthnSpnego.checks(view.checks, t) +
      WebAuthnSpnego.fallback(view, t) +
      '<h2>' + t.html('spnego.ifNothing.heading') + '</h2><p>' +
      t.html('spnego.ifNothing.browsers') + '</p><p class="sub">' +
      t.html('spnego.ifNothing.program') + '</p>' +
      WebAuthnSpnego.facts(view, t);
  }

  /**
   * The 403's page: the door is off. English, as a refusal is.
   *
   * @param view - the view: `setting` (a `demoPath`, the demonstration page,
   *   until #595 moved it to the development companion)
   * @param t - the translator, for the link back only
   * @returns the HTML
   */
  static off(view: Json, t: Json): string {
    const esc = WebAuthnSpnego.esc;
    return '<h1>403 &mdash; integrated authentication is off</h1>' +
      '<div class="err" id="spnego-off">This service can sign people in ' +
      'with a Kerberos ticket, and <code>' + esc(view.setting) +
      '</code> is set to false.</div><p>Turn it on at <a href="' +
      esc(CONSOLE_PATH) + '">' + esc(CONSOLE_PATH) + '</a>, or ' +
      'with <code>POST /admin-api/config/set</code>.</p>' +
      WebAuthnSpnego.fallback(view, t);
  }

  /**
   * The signed-in page, when nothing was interrupted.
   *
   * @param view - the view
   * @param t - the translator
   * @returns the HTML
   */
  static signedIn(view: Json, t: Json): string {
    const esc = WebAuthnSpnego.esc;
    const amr: string[] = view.amr || [];
    const row = function (label: string, value: string): string {
      return '<tr><td>' + label + '</td><td>' + value + '</td></tr>';
    };
    const code = function (value: unknown): string {
      return '<code>' + esc(value) + '</code>';
    };
    return '<h1>' + t.html('spnego.signedIn.heading') + '</h1>' +
      '<div class="ok" id="spnego-signed-in">' +
      t.html('spnego.signedIn.as', { name: String(view.username || ''),
                                     principal: String(view.principal ||
                                                       '') }) +
      '</div>' +
      '<p>' + t.html('spnego.signedIn.cookie') + '</p>' +
      '<table id="spnego-session">' +
      '<tr><th>' + t.html('spnego.facts.what') + '</th><th>' +
      t.html('spnego.facts.value') + '</th></tr>' +
      row(t.html('spnego.signedIn.session'), code(view.session)) +
      row(t.html('spnego.signedIn.subject'), code(view.subject)) +
      row(t.html('spnego.signedIn.flags'),
          code((view.flags || []).join(', ') || 'none')) +
      row(t.html('spnego.signedIn.indicators'),
          code((view.indicators || []).join(', ') || 'none')) +
      row('amr', code(amr.join(', ') || '(none claimed)') +
          (amr.length ? '' : ' ' + t.html('spnego.signedIn.noAmr'))) +
      row('acr', code(view.acr)) +
      row(t.html('spnego.signedIn.mechanism'), code(view.mechanism) +
          (view.bare ? ' ' + t.html('spnego.signedIn.bare') : '')) +
      row('mechListMIC', view.mic
        ? '<span class="pass">' + t.html('spnego.signedIn.verified') +
          '</span>'
        : '<span class="fail">' + t.html('spnego.signedIn.notSent') +
          '</span>') +
      '</table>' +
      WebAuthnSpnego.checks(view.checks, t) +
      '<p class="sub"><a href="/admin/users">/admin/users</a> ' +
      t.html('spnego.signedIn.usersRow') + ' <a href="/logout">/logout</a> ' +
      t.html('spnego.signedIn.logoutEnds') + '</p>';
  }

  /**
   * The page's body, by the view's `kind`.
   *
   * @param view - the state the shell carried
   * @param ctx - the surface's context: `t`
   * @returns the body
   */
  static render(view: Json, ctx: Json): string {
    const v = view || {};
    const t = ctx.t;
    if (v.kind === 'signed-in') {
      return WebAuthnSpnego.signedIn(v, t);
    }
    if (v.kind === 'off') {
      return WebAuthnSpnego.off(v, t);
    }
    return WebAuthnSpnego.challenge(v, t);
  }

  /**
   * The document's title.
   *
   * @param view - the view
   * @param ctx - the context
   * @returns the title, as text
   */
  static title(view: Json, ctx: Json): string {
    const v = view || {};
    if (v.kind === 'signed-in') {
      return ctx.t.text('spnego.signedIn.title');
    }
    if (v.kind === 'off') {
      return 'Integrated authentication is off';
    }
    return ctx.t.text('spnego.first.title');
  }
}

export = WebAuthnSpnego;
