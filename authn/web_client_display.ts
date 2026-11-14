// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_client_display.ts
//
// ---------------------------------------------------------------------------
// WHO IS ASKING, DRAWN IN THE BROWSER (#1300, 2026-11-04).
//
// OpenID Connect Registration section 2: a client's `logo_uri` — "the
// server SHOULD display this image to the End-User during approval" — and
// its `policy_uri` and `tos_uri`, which the OP SHOULD display too. The
// sign-in pages' views and the consent screen's carry them as
// `clientDisplay` (`Authn.clientDisplay()`, over
// `applications.clientDisplayOf()`), and the sign-in surface's frame
// (`web_authn_pages.ts`) draws this above whichever page the view is for,
// so every page of the surface that knows the client shows the same thing
// the same way: the client's name, its logo as an `<img>` whose alternative
// text is that name, and its two documents as links that open in a new tab
// with `rel="noopener noreferrer"`.
//
// THE BROWSER LOADS THE LOGO STRAIGHT FROM THE CLIENT; THIS SERVICE NEVER
// FETCHES IT. The page's `img-src` names exactly that origin
// (`ShellDocument`'s `images`), and `referrerpolicy="no-referrer"` keeps the
// pending sign-in's address off the request the browser makes for it.
//
// A view with no `clientDisplay` — no client, a client that registered
// none of the three — draws nothing at all.
//
// A `web_` MODULE: it requires nothing and logs nothing — it runs in a
// browser, and in node where `tests/web_surfaces.js` draws it.
// ---------------------------------------------------------------------------

type Json = any;

/**
 * The client's name, logo and documents on the sign-in surface. A static
 * utility class.
 */
class WebClientDisplay {
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
   * Whether a value is an https URL, which is all the server answers; a
   * view that carried anything else is drawn without it.
   *
   * @param value - the value
   * @returns true for an https URL
   */
  static https(value: unknown): boolean {
    return typeof value === 'string' && /^https:\/\/[^\s"'<>]+$/i.test(value);
  }

  /**
   * The block drawn above a page for its client.
   *
   * @param shown - the view's `clientDisplay`: `name`, `logo`, `policy`,
   *   `tos`
   * @param t - the translator
   * @param ns - the catalog namespace the labels are in: `authn`, or
   *   `consent` on the consent screen, which loads only its own
   * @returns the markup, or '' where there is nothing to show
   */
  static render(shown: Json, t: Json, ns: string): string {
    if (!shown || typeof shown !== 'object') {
      return '';
    }
    const esc = WebClientDisplay.esc;
    const name = String(shown.name || '');
    const link = function (id: string, href: string, key: string): string {
      return '<a id="' + id + '" href="' + esc(href) + '" target="_blank" ' +
        'rel="noopener noreferrer">' + t.html(ns + '.' + key) + '</a>';
    };
    const links = [
      WebClientDisplay.https(shown.policy)
        ? link('client-policy', shown.policy, 'client.policy') : '',
      WebClientDisplay.https(shown.tos)
        ? link('client-tos', shown.tos, 'client.tos') : ''
    ].filter(Boolean);
    const logo = WebClientDisplay.https(shown.logo)
      ? '<img id="client-logo" class="client-logo" src="' + esc(shown.logo) +
        '" alt="' + esc(name) + '" referrerpolicy="no-referrer">' : '';
    if (!logo && !links.length) {
      return '';
    }
    return '<div class="client-display" id="client-display">' + logo +
      (name ? '<div class="client-name" id="client-name">' + esc(name) +
              '</div>' : '') +
      (links.length ? '<div class="client-links">' + links.join(' ') +
                      '</div>' : '') + '</div>';
  }
}

export = WebClientDisplay;
