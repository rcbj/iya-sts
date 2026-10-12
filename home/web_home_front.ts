// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_home_front.ts
//
// ---------------------------------------------------------------------------
// THE FRONT DOOR'S ONE PAGE, DRAWN IN THE BROWSER (#579, 2026-10-12).
//
// `GET /` was a server-drawn card until #579; it is now the first public
// surface on #570's foundation (`common/CLAUDE.md` 3cl), and this is its
// renderer: the card's body drawn from `GET /home-api/front`'s view — the
// name, the version and its provenance, what a sign-in here checks, the
// image, and the five links — in the page's language, from the `home`
// catalog namespace the server-drawn page used, word for word.
//
// THE VIEW IS LANGUAGE-FREE (`home/home.ts`, `frontView()`): each link is an
// `id` and an address, and THIS module turns the id into its label and note.
// What a sign-in means is two facts of the mode (`verifiesCredentials`,
// `gatesConsole`) and the sentences are chosen here, as `signInMeans()` chose
// them on the server — one copy of the choice, drawn on both rows.
//
// IT LISTS NO ENDPOINTS, AND THAT IS STILL THE ONE RULE (`home/CLAUDE.md`):
// the links are the five the view names and nothing else.
//
// A `web_` MODULE (`admin-ui/web_kit.ts`'s terms): it requires nothing at
// all — not even the surface's runtime, so the renderers' bundle is the
// renderers — and logs nothing, because it runs in a browser as well as
// here, where `tests/web_surfaces.js` draws it from the same view to compare.
// ---------------------------------------------------------------------------

type Json = any;

/**
 * Each link the view may name: its label's and its note's message keys.
 * The console's and the portal's notes are assembled from several
 * sentences, by `noteOf()`.
 */
const LINKS: Record<string, { label: string; note: string }> = {
  repo: { label: 'home.repoLabel', note: 'home.repoNote' },
  issues: { label: 'home.issuesLabel', note: 'home.issuesNote' },
  docs: { label: 'home.docsLabel', note: 'home.docsNote' },
  console: { label: 'home.consoleLabel', note: 'home.consoleNote' },
  portal: { label: 'home.portalLabel', note: 'home.portalNote' }
};

/**
 * The front door's renderers. A static utility class.
 */
class WebHomeFront {
  /**
   * The band with the logo, or nothing where the service has no image.
   * Drawn by the surface's frame, above the language chooser, as the
   * server-drawn card had it.
   *
   * @param view - the front view, or nothing (a problem page)
   * @param t - the page's translator
   * @returns the band's markup, or ''
   */
  static hero(view: Json, t: Json): string {
    const logo = view && view.logo;
    if (!logo || !logo.src) {
      return '';
    }
    return '<div class="hero"><img src="' + WebHomeFront.esc(logo.src) +
      '" width="' + WebHomeFront.esc(logo.width) + '" height="' +
      WebHomeFront.esc(logo.height) + '" alt="' +
      WebHomeFront.esc(t.text('home.logoAlt')) + '"></div>';
  }

  /**
   * What a sign-in on either surface checks: a fact of the mode, not of the
   * surface, so one sentence for both rows.
   *
   * @param view - the front view
   * @param t - the page's translator
   * @returns the sentence, as HTML
   */
  static signInMeans(view: Json, t: Json): string {
    return view.mode && view.mode.verifiesCredentials
      ? t.html('home.signInProduct')
      : t.html('home.signInDevelopment');
  }

  /**
   * A link's note: one message, or for the console and the portal the
   * sentences the mode selects.
   *
   * @param id - the link's id
   * @param view - the front view
   * @param t - the page's translator
   * @returns the note, as HTML
   */
  static noteOf(id: string, view: Json, t: Json): string {
    const note = t.html(LINKS[id].note);
    if (id === 'console') {
      return note + ' ' +
        (view.mode && view.mode.gatesConsole
          ? WebHomeFront.signInMeans(view, t) + ' ' +
            t.html('home.consoleRoles')
          : t.html('home.consoleOpen')) +
        ' ' + t.html('home.consoleMetadata');
    }
    if (id === 'portal') {
      return note + ' ' + WebHomeFront.signInMeans(view, t) + ' ' +
        t.html('home.portalNoRole');
    }
    return note;
  }

  /**
   * One link's row. The label and note are translated HTML, which escapes
   * its own parameters.
   *
   * @param link - `{ id, href, external }`
   * @param view - the front view
   * @param t - the page's translator
   * @returns the row, or '' for a link this page has no words for
   */
  static linkRow(link: Json, view: Json, t: Json): string {
    if (!link || !LINKS[link.id]) {
      return '';
    }
    return '<li><a href="' + WebHomeFront.esc(link.href) + '"' +
      (link.external ? ' target="_blank" rel="noopener noreferrer"' : '') +
      '>' + t.html(LINKS[link.id].label) + '</a><span class="note">' +
      WebHomeFront.noteOf(link.id, view, t) + '</span></li>';
  }

  /**
   * The front page's body, under the chooser: the name, what this service
   * is, the version with its build in the tooltip, the warning, and the
   * links.
   *
   * @param view - `GET /home-api/front`'s view
   * @param ctx - the surface's context; its `t` is the page's translator
   * @returns the body
   */
  static render(view: Json, ctx: Json): string {
    const t = ctx.t;
    const v = view || {};
    return '<h1>' + WebHomeFront.esc(v.name) + '</h1>' +
      '<p class="sub">' + t.html('home.sub') + '</p>' +
      // THE VERSION, WITH ITS PROVENANCE IN THE TOOLTIP: the number is what
      // a bug report quotes, the build instant and commit what somebody
      // needs when two instances of the same M.N differ.
      '<p class="ver" title="' + WebHomeFront.esc(v.build) + '">' +
      t.html('home.version', { version: String(v.version || '') }) +
      '</p>' +
      '<div class="warn">' + t.html('home.warn') + '</div><ul>' +
      (Array.isArray(v.links) ? v.links : []).map(function (link: Json) {
        return WebHomeFront.linkRow(link, v, t);
      }).join('') + '</ul>';
  }

  /**
   * The card around a page: the band, then the body with the chooser. A
   * problem page (no view) draws its own card and is left as it is.
   *
   * @param body - the chooser and the page's body
   * @param ctx - the surface's context, with the page's `view`
   * @returns the framed markup
   */
  static frame(body: string, ctx: Json): string {
    if (!ctx || !ctx.view) {
      return body;
    }
    return '<div class="card">' + WebHomeFront.hero(ctx.view, ctx.t) +
      '<div class="body">' + body + '</div></div>';
  }

  /**
   * The document's title.
   *
   * @param view - the front view
   * @returns the title, as text
   */
  static title(view: Json): string {
    return String((view && view.name) || 'IYA STS');
  }

  /**
   * Escapes text for HTML, as `Html.esc()` and `WebSurface.esc()` do.
   *
   * @param value - anything
   * @returns the escaped text
   */
  static esc(value: unknown): string {
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
}

export = WebHomeFront;
