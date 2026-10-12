// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_portal_shell.ts
//
// ---------------------------------------------------------------------------
// THE USER PORTAL'S FRAME, DRAWN IN THE BROWSER (#568).
//
// What `Portal.shell()`, `page()` and `bare()` drew on the server until the
// portal became a static application, moved here and drawn from the answer
// of `GET /account-api/me` (who is signed in, the realm, the language data,
// the build) instead of from a session:
//
//   * ONE SIGNED-IN PAGE: the heading with Refresh, Sign out and the language
//     chooser in one row, the navigation column, the message or error a just-
//     finished act left, and the page's cards (`frame()`).
//   * A PAGE DRAWN FOR NOBODY — an activation, a password reset, the
//     forgot-password form, an address verification — with no column
//     (`bare()`).
//
// **THE SIGN OUT BUTTON IS IN THE HEADER AND SO IS ON EVERY PAGE**, the
// decision `portal/CLAUDE.md` records. It is still a form, posting to
// `/portal/signout`; the runtime answers it (`PortalRuntime.signOut()`), as
// the console's runtime answers the console's.
//
// **REFRESH IS A GET FORM TO THE PAGE IT IS ON** carrying only the
// parameters a page reads to draw itself (`REFRESH_KEPT` and `<list>Page`),
// for #538's reason: a value a link put on the URL is never drawn back.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import kit = require('./web_portal_kit');

type Json = any;

/**
 * The parameters the Refresh button and the chooser's return carry besides
 * `<list>Page`.
 */
const REFRESH_KEPT = ['page', 'per', 'stepup', 'gnapstepup', 'enrolled',
                      'named'];

/**
 * The portal's frame. A static utility class; it holds no state.
 */
class PortalShell {
  /**
   * The module's `REFRESH_KEPT`.
   */
  static readonly REFRESH_KEPT = REFRESH_KEPT;
  /**
   * Where the Sign out form posts; the runtime answers it.
   */
  static readonly SIGNOUT_PATH = kit.BASE + '/signout';

  /**
   * The parameters of a page's query that a redraw of it keeps.
   *
   * @param query - the page's query
   * @returns `[name, value]` pairs
   */
  static keptParams(query: Json): string[][] {
    return Object.keys(query || {}).filter(function (name) {
      return REFRESH_KEPT.indexOf(name) >= 0 ||
        /^[a-z][A-Za-z]*Page$/.test(name);
    }).map(function (name) {
      return [name, String(query[name])];
    });
  }

  /**
   * The heading of a page, from the column's table.
   *
   * @param active - the page's path
   * @param t - the translator
   * @returns the heading, as text
   */
  static headingFor(active: string, t: Json): string {
    const row = kit.navPages().filter(function (one: Json): boolean {
      return one.path === active;
    })[0];
    // A COMPOSED KEY, built first: the catalog test's scan reads only a
    // literal key quoted in the call, and holds `NAV` to the catalog by its
    // `portal` check instead (as `portal.ts` did).
    const key = 'portal.nav.' + kit.navSlug(row ? row.path : kit.BASE) +
      '.heading';
    return t.text(key);
  }

  /**
   * The navigation column.
   *
   * @param active - the page's path
   * @param t - the translator
   * @returns the column's HTML
   */
  static navBar(active: string, t: Json): string {
    // Composed keys, built first, for `headingFor()`'s reason.
    const label = function (item: Json): string {
      const key = 'portal.nav.' + kit.navSlug(item.path) + '.label';
      return t.html(key);
    };
    return '<nav aria-label="' + kit.esc(t.text('portal.shell.navAria')) +
      '">' + kit.NAV.map(function (section: Json): string {
        const here = section.items.some(function (item: Json): boolean {
          return item.path === active;
        });
        const what = 'portal.section.' + section.key + '.what';
        const title = 'portal.section.' + section.key + '.title';
        return '<div class="navsec' + (here ? ' open' : '') + '">' +
          '<p class="navhead" title="' + kit.esc(t.text(what)) + '">' +
          t.html(title) + '</p><ul>' +
          section.items.map(function (item: Json): string {
            // A SPAN AND NOT A LINK for the page that is open, and
            // `aria-current` for a screen reader.
            if (item.path === active) {
              return '<li><span class="here" aria-current="page">' +
                label(item) + '</span></li>';
            }
            return '<li><a href="' + kit.esc(item.path) + '">' + label(item) +
              '</a></li>';
          }).join('') + '</ul></div>';
      }).join('') + '</nav>';
  }

  /**
   * The Refresh button: a GET form reloading the page it is on.
   *
   * @param active - the page's path
   * @param query - the page's query
   * @param t - the translator
   * @returns the form's HTML
   */
  static refreshForm(active: string, query: Json, t: Json): string {
    return '<form method="get" action="' + kit.esc(active) + '">' +
      PortalShell.keptParams(query).map(function (pair) {
        return '<input type="hidden" name="' + kit.esc(pair[0]) +
          '" value="' + kit.esc(pair[1]) + '">';
      }).join('') +
      '<button class="secondary" title="' +
      kit.esc(t.text('portal.shell.refreshTitle')) + '">' +
      t.html('portal.shell.refresh') + '</button></form>';
  }

  // THE LANGUAGE CHOOSER (#539), the markup `PageLocale.chooser()` draws on
  // the server's pages: a form posting to the sign-in service's
  // `/authn/language`, which is not a portal path, so the runtime leaves it to
  // the browser. That sets the cookie and comes back to `returnTo`, and the
  // page signs in again silently and is drawn in the new language. The return
  // carries the realm's prefix itself, because a value is not rewritten.
  /**
   * Draws the language chooser.
   *
   * @param t - the translator
   * @param locale - `me.locale`: `negotiated` and `offered`
   * @param returnTo - the path to come back to, prefix included
   * @returns the chooser's HTML, or '' when nothing is offered
   */
  static chooser(t: Json, locale: Json, returnTo: string): string {
    const offered: Json[] = (locale && locale.offered) || [];
    if (!offered.length) {
      return '';
    }
    const current = String(t.locale || '').toLowerCase();
    const language = current.split('-')[0];
    const exact = offered.filter(function (one: Json): boolean {
      return String(one.tag).toLowerCase() === current;
    })[0];
    const same = offered.filter(function (one: Json): boolean {
      return String(one.tag).toLowerCase().split('-')[0] === language;
    })[0];
    const selected = (exact || same || offered[0]).tag;
    return '<form class="language-chooser" method="post" ' +
      'action="/authn/language">' +
      '<input type="hidden" name="return" value="' + kit.esc(returnTo) +
      '"><label for="sts-language">' + t.html('chooser.label') +
      '</label> <select id="sts-language" name="lang">' +
      offered.map(function (one: Json): string {
        return '<option value="' + kit.esc(one.tag) + '" lang="' +
          kit.esc(one.tag) + '"' + (one.tag === selected ? ' selected' : '') +
          '>' + kit.esc(one.name) + '</option>';
      }).join('') + '</select> <button type="submit">' +
      t.html('chooser.change') + '</button></form>';
  }

  // WHICH BUILD THIS IS, on every page including the ones nobody is signed
  // in to: the surfaces a person reaches when something has gone wrong are
  // the ones where "which build were you on" is most likely to be asked.
  /**
   * Wraps a page's body with the version line.
   *
   * @param inner - the body
   * @param wide - whether the page has the navigation column
   * @param version - `{ version, buildInfo }`
   * @returns the page's HTML
   */
  static page(inner: string, wide: boolean, version: Json): string {
    const v = version || {};
    return '<div class="wrap' + (wide ? ' wide' : '') + '">' + inner +
      '<p class="ver" title="' + kit.esc(v.buildInfo || '') + '">' +
      'iya-sts <code>' + kit.esc(v.version || '') + '</code></p></div>';
  }

  /**
   * Draws a signed-in page.
   *
   * @param me - `GET /account-api/me`'s answer
   * @param page - `active` (the page's path), `query`, `message`, `error`,
   *   `cards` (the body), `prefix` (the realm's) and `t`
   * @returns the page's HTML
   */
  static frame(me: Json, page: Json): string {
    const t = page.t;
    const user = (me && me.user) || {};
    const kept = PortalShell.keptParams(page.query);
    const returnTo = (page.prefix || '') + page.active +
      (kept.length ? '?' + new URLSearchParams(kept).toString() : '');
    return PortalShell.page(
      '<header class="pagehead"><div><h1>' +
      kit.esc(PortalShell.headingFor(page.active, t)) + '</h1>' +
      '<p class="who">' + t.html('portal.shell.signedInAs',
        { name: user.username || '' }) + '</p></div>' +
      '<div class="acts">' +
      PortalShell.refreshForm(page.active, page.query, t) +
      '<form method="post" action="' + PortalShell.SIGNOUT_PATH + '">' +
      '<button class="secondary" title="' +
      kit.esc(t.text('portal.shell.signOutTitle')) + '">' +
      t.html('portal.shell.signOut') + '</button></form>' +
      PortalShell.chooser(t, me && me.locale, returnTo) + '</div></header>' +
      '<div class="shell"><div class="side"><div class="card">' +
      PortalShell.navBar(page.active, t) + '</div></div><div class="main">' +
      (page.error ? '<div class="err">' + kit.esc(page.error) + '</div>' : '') +
      (page.message ? '<div class="ok">' + kit.esc(page.message) + '</div>'
                    : '') +
      page.cards + '</div></div>', true, me && me.version);
  }

  /**
   * Draws a page for nobody: no column, no header.
   *
   * @param inner - the page's cards
   * @param version - `{ version, buildInfo }`
   * @returns the page's HTML
   */
  static bare(inner: string, version: Json): string {
    return PortalShell.page(inner, false, version);
  }
}

export = PortalShell;
