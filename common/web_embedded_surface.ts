// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_embedded_surface.ts
//
// ---------------------------------------------------------------------------
// THE RUNTIME OF A SURFACE WHOSE PAGES ARE THE SHELL'S (#583, 2026-10-12).
//
// `common/web_surface.ts` draws a page from what its API answers to a GET.
// Some pages have nothing to fetch: what they say exists only on the
// response that carried them — a verdict, a refusal, a description of the
// very request that asked for the page. Their server answers the shell with
// the page's view in `data-sts-state` (`kerberos/spnego_authn.ts`'s
// arrangement, #575), and the runtime draws it from there.
//
// `federation/web_federation_surface.ts` (#580) was the third runtime to do
// this, each with its own copy; this is that runtime with the federation
// taken out, for the two surfaces of #583 — the TLS diagnostic pages
// (deleted by #597, now a console page) and the SPNEGO demonstration pages
// (moved to the development companion by #595). Neither stands on it now;
// it is kept as the runtime the three older embedded ones may move onto
// (`common/CLAUDE.md`). A surface built on it:
//
//   * HAS NO API TO FETCH A PAGE FROM: every row of its table is the
//     shell's, drawn from the state and never fetched; a shell that carried
//     none says so.
//   * LEAVES EVERY LINK TO THE BROWSER: another of its paths is a request
//     the server answers — a description of THAT request, a negotiation —
//     and not a page this runtime could draw in place.
//   * SENDS NOTHING unless the subclass says how (`submit()`): the language
//     chooser posts to `/authn/language` (`web_i18n.ts`) and the page is
//     drawn again from the view in hand, in the language chosen.
//
// A row's `path` may end in `/:id`; `match()` answers the row and the id.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// Its browser objects arrive in `env`.
// ---------------------------------------------------------------------------

import WebSurface = require('./web_surface');
import WebPage = require('./web_page');

type Json = any;

/**
 * What an embedded surface is: `web_surface.ts`'s options without an API.
 */
interface EmbeddedOptions {
  // The surface's first path.
  base: string;
  // The page table: `{ path, render, title? }`, every row the shell's.
  pages: Json[];
  // The catalog namespaces its pages draw.
  namespaces: string[];
  // The frame around a page's body (`web_surface.ts`'s).
  frame?: (body: string, ctx: Json) => string;
  // What follows a title in the document's title.
  brand?: string;
}

/**
 * The runtime of a surface whose every page is drawn from its shell's
 * state.
 */
class WebEmbeddedSurface extends WebSurface {
  // The person's own language, where the shell carried it.
  protected own: Json;

  /**
   * Makes the runtime.
   *
   * @param env - the browser's objects
   * @param options - the surface: its base, pages and namespaces
   */
  constructor(env: Json, options: EmbeddedOptions) {
    super(env, { base: options.base, api: '', pages: options.pages,
                 namespaces: options.namespaces, frame: options.frame,
                 brand: options.brand });
    this.own = undefined;
  }

  /**
   * The row a path is, and the id in it where the row names one.
   *
   * @param pages - the page table
   * @param path - the surface's path
   * @returns `{ row, id }`, or null for a path that is not a page
   */
  static match(pages: Json[], path: string): Json {
    const p = String(path || '');
    for (let i = 0; i < pages.length; i++) {
      const row = pages[i];
      if (row.path === p) {
        return { row: row, id: '' };
      }
      if (/\/:id$/.test(row.path)) {
        const base = row.path.slice(0, -':id'.length);
        const rest = p.indexOf(base) === 0 ? p.slice(base.length) : '';
        if (rest && /^[^/]+$/.test(rest)) {
          return { row: row, id: decodeURIComponent(rest) };
        }
      }
    }
    return null;
  }

  /**
   * The page row for a path, an id in it or not.
   *
   * @param path - the surface's path
   * @returns the row, or null
   */
  find(path: string): Json {
    const found = WebEmbeddedSurface.match(this.options.pages, path);
    return found ? found.row : null;
  }

  /**
   * The state the shell carried, or null where it carried none or it does
   * not read.
   *
   * @param env - the browser's objects
   * @returns `{ view, preferredLanguage?, ... }`, or null
   */
  static embeddedState(env: Json): Json {
    const text = WebPage.attribute(env, 'data-sts-state');
    if (!text) {
      return null;
    }
    try {
      const state = JSON.parse(text);
      return state && typeof state === 'object' && state.view ? state : null;
    } catch (e) {
      // Not JSON: the page says it could not be drawn.
      return null;
    }
  }

  /**
   * Draws the page the location names from the shell's state.
   *
   * @returns nothing
   */
  async route(): Promise<void> {
    const path = this.surfacePath(this.env.location.pathname) ||
      this.options.base;
    const query = WebPage.queryOf(this.env.location.search);
    const state = WebEmbeddedSurface.embeddedState(this.env);
    this.own = state ? state.preferredLanguage : undefined;
    this.t = await this.i18n.load({ uiLocales: query.ui_locales || '',
                                    own: this.own });
    if (!state) {
      this.view = null;
      this.drawProblem('This page could not be drawn',
                       'The service sent no state for it.');
      return;
    }
    const row = this.find(path) || this.options.pages[0];
    this.lastAnswer = state;
    this.view = { page: row, query: query, json: state.view };
    this.drawView();
  }

  /**
   * Draws the page in hand again in the language just chosen, from the
   * view in hand: there is no operation to fetch it again from.
   *
   * @returns nothing
   */
  redraw(): void {
    if (!this.view) {
      this.route();
      return;
    }
    const self = this;
    const query = WebPage.queryOf(this.env.location.search);
    this.i18n.load({ uiLocales: query.ui_locales || '', own: this.own })
      .then(function (t: Json) {
        self.t = t;
        self.drawView();
        return t;
      }, function () {
        // The catalogs could not be read: the page stays as it is.
        self.drawView();
      });
  }

  /**
   * Draws a view in place of the page in hand — what an act answered —
   * keeping the page's row and query.
   *
   * @param view - the view
   * @returns nothing
   */
  drawInPlace(view: Json): void {
    const row = (this.view && this.view.page) || this.options.pages[0];
    const query = this.view ? this.view.query
                            : WebPage.queryOf(this.env.location.search);
    this.view = { page: row, query: query, json: view };
    this.drawView();
  }

  /**
   * Leaves every link to the browser: each of these paths is answered by
   * the server, never drawn in place.
   *
   * @param event - the click
   * @returns nothing
   */
  onClick(event: Json): void {
    void event;
  }

  /**
   * Refuses a form: a surface that sends something says how, by
   * overriding this.
   *
   * @param form - the form
   * @param submitter - the button pressed, if any
   * @returns nothing
   */
  async submit(form: Json, submitter: Json): Promise<void> {
    void form;
    void submitter;
    this.flash = { error: 'This page sends nothing, so the form was not ' +
                          'sent.' };
    this.redraw();
  }
}

export = WebEmbeddedSurface;
