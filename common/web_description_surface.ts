// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_description_surface.ts
//
// ---------------------------------------------------------------------------
// THE DESCRIPTION PAGES' RUNTIME (#584, 2026-10-12).
//
// `common/description-pages-spa.js` is built from this, and served at
// `/saml2/description.js`, `/saml11/description.js`,
// `/xacml/description.js`, `/ssf/description.js`, `/scim/description.js`
// and `/spiffe/description.js` — ONE file at six paths, each a path of its
// family's hosted application (#472), so a shell on that application's own
// listener loads it from there (`description_pages.ts` argues the one
// bundle). It is the public surfaces' runtime (`common/web_surface.ts`)
// over the six pages' table (`web_description_pages.ts`), with what pages
// that only DESCRIBE need beyond it — `federation/web_federation_surface.ts`'s
// arrangement (#580):
//
//   * THE PAGE IS THE SHELL'S: its view is in `data-sts-state`, drawn from
//     it and never fetched, so there is no API and no operation; a shell
//     that carried none says so. The view's `kind` says which family's page
//     it is, and so which path is the surface's base and which catalog
//     namespace is loaded — one, not six.
//   * EVERY LINK IS THE BROWSER'S: an endpoint a page links to is answered
//     by the server, never drawn in place.
//   * NOTHING IS SENT: the only form is the language chooser, which posts to
//     `/authn/language` (`web_i18n.ts`) and draws the page again, from the
//     same view, in the language chosen.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// Its browser objects arrive in `env`.
// ---------------------------------------------------------------------------

import WebSurface = require('./web_surface');
import WebPage = require('./web_page');
import DescriptionWebPages = require('./web_description_pages');

type Json = any;

/**
 * The description pages' runtime.
 */
class DescriptionSurface extends WebSurface {
  // The page row the shell's view names, or null.
  protected row: Json;

  /**
   * Makes the runtime for the page the shell carries.
   *
   * @param env - the browser's objects
   */
  constructor(env: Json) {
    super(env, DescriptionSurface.optionsFor(
      DescriptionSurface.rowOf(DescriptionSurface.embeddedState(env))));
    this.row = DescriptionSurface.rowOf(DescriptionSurface.embeddedState(env));
  }

  /**
   * The surface's options for a page row: its path the base, its
   * namespace the one loaded.
   *
   * @param row - the row, or null
   * @returns the options
   */
  static optionsFor(row: Json): Json {
    return { base: row ? row.path : '/', api: '',
             pages: DescriptionWebPages.PAGES as Json,
             namespaces: row ? [row.namespace] : [],
             frame: DescriptionWebPages.frame };
  }

  /**
   * The page row a state's view names.
   *
   * @param state - the shell's state, or null
   * @returns the row, or null
   */
  static rowOf(state: Json): Json {
    return state ? DescriptionWebPages.byKind(state.view.kind) : null;
  }

  /**
   * The state the shell carried, or null where it carried none or it does
   * not read.
   *
   * @param env - the browser's objects
   * @returns `{ view }`, or null
   */
  static embeddedState(env: Json): Json {
    const text = WebPage.attribute(env, 'data-sts-state');
    if (!text) {
      return null;
    }
    try {
      const state = JSON.parse(text);
      return state && typeof state === 'object' && state.view &&
        typeof state.view === 'object' ? state : null;
    } catch (e) {
      // Not JSON: the page says it could not be drawn.
      return null;
    }
  }

  /**
   * Draws the page the shell carries.
   *
   * @returns nothing
   */
  async route(): Promise<void> {
    const query = WebPage.queryOf(this.env.location.search);
    const state = DescriptionSurface.embeddedState(this.env);
    this.t = await this.i18n.load({ uiLocales: query.ui_locales || '' });
    if (!state || !this.row) {
      this.view = null;
      this.drawProblem('This page could not be drawn',
                       state ? 'The service sent a view this page does not ' +
                               'know (' + String(state.view.kind) + ').'
                             : 'The service sent no state for it.');
      return;
    }
    this.lastAnswer = state;
    this.view = { page: this.row, query: query, json: state.view };
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
    this.i18n.load({ uiLocales: query.ui_locales || '' })
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
   * Leaves every link to the browser: each endpoint a page names is
   * answered by the server, never drawn in place.
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
  new DescriptionSurface({
    fetch: window.fetch.bind(window), location: window.location,
    history: window.history, document: document,
    navigator: window.navigator, window: window
  }).start();
}

export = DescriptionSurface;
