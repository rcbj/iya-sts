// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_federation_surface.ts
//
// ---------------------------------------------------------------------------
// THE FEDERATION PAGES' RUNTIME (#580, 2026-10-12).
//
// `federation/federation-pages-spa.js`, served at `/federation/pages.js`, is
// built from this: the public surfaces' runtime (`common/web_surface.ts`)
// over the federation pages' table (`web_federation_pages.ts`), with what
// pages that only SAY something need beyond it:
//
//   * EVERY PAGE IS THE SHELL'S: its view is in `data-sts-state`
//     (`federation_pages.ts`), drawn from it and never fetched, so there is
//     no API and no operation; a shell that carried none says so.
//   * EVERY LINK IS THE BROWSER'S: a link to another of these paths is a
//     request the server answers — a sign-in started, a redirect — and not
//     a page this runtime could draw in place.
//   * NOTHING IS SENT: the only form on these pages is the language
//     chooser, which posts to `/authn/language` (`web_i18n.ts`) and draws
//     the page again, from the same view, in the language chosen.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// Its browser objects arrive in `env`.
// ---------------------------------------------------------------------------

import WebSurface = require('../common/web_surface');
import WebPage = require('../common/web_page');
import FederationWebPages = require('./web_federation_pages');

type Json = any;

/**
 * The federation pages' runtime.
 */
class FederationSurface extends WebSurface {
  // The person's own language, where the shell carried it.
  protected own: Json;

  /**
   * Makes the runtime.
   *
   * @param env - the browser's objects
   */
  constructor(env: Json) {
    super(env, { base: '/federation', api: '',
                 pages: FederationWebPages.PAGES as Json,
                 namespaces: ['federationPages', 'handoff'],
                 frame: FederationWebPages.frame, brand: '' });
    this.own = undefined;
  }

  /**
   * The page row for a path, an id in it or not.
   *
   * @param path - the surface's path
   * @returns the row, or null
   */
  find(path: string): Json {
    const found = FederationWebPages.match(path);
    return found ? found.row : null;
  }

  /**
   * The state the shell carried, or null where it carried none or it does
   * not read.
   *
   * @param env - the browser's objects
   * @returns `{ view, preferredLanguage? }`, or null
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
    const found = FederationWebPages.match(path);
    const state = FederationSurface.embeddedState(this.env);
    this.own = state ? state.preferredLanguage : undefined;
    this.t = await this.i18n.load({ uiLocales: query.ui_locales || '',
                                    own: this.own });
    if (!state) {
      this.view = null;
      this.drawProblem('This page could not be drawn',
                       'The service sent no state for it.');
      return;
    }
    this.lastAnswer = state;
    this.view = { page: found ? found.row : this.options.pages[0],
                  query: query, json: state.view };
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
   * Refuses a form these pages do not have: nothing here is sent.
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

declare const window: any;
declare const document: any;

if (typeof window !== 'undefined' && typeof document !== 'undefined') {
  new FederationSurface({
    fetch: window.fetch.bind(window), location: window.location,
    history: window.history, document: document,
    navigator: window.navigator, window: window
  }).start();
}

export = FederationSurface;
