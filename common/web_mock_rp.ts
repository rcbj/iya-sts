// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_mock_rp.ts
//
// ---------------------------------------------------------------------------
// THE MOCK RELYING PARTIES' RUNTIME (#581, 2026-10-12).
//
// `common/mock-rp-spa.js`, served at `/wsfed/rp/mock-rp.js`,
// `/saml2/sp/mock-rp.js` and `/saml11/rp/mock-rp.js` — the same file under
// each family's own path, so a listener-mapped family loads it from its own
// listener (#472) — is built from this: the public surfaces' runtime
// (`common/web_surface.ts`) over the page table (`web_mock_rp_pages.ts`),
// with what these pages need beyond it:
//
//   * WHICH MOCK THIS IS: the shell's `data-sts-mock-rp` names the family,
//     and its base is the surface's base.
//   * A VERDICT THE SHELL CARRIES: what a receiving door verified exists
//     only on that response (`mock_rp_surface.ts`), so it is drawn from
//     `data-sts-state` and nothing is fetched.
//   * EVERY LINK IS THE BROWSER'S: a sign-in request, a sign-out, the
//     metadata and the artifact loaded again are protocol messages, and
//     Start another sign-in loads the page afresh — the start view MINTS a
//     relying party's state, and a verdict's own URL is the receiving door
//     (reloaded, a POST sent again or an artifact asked again: the one-shot
//     demonstration). So nothing is followed in place, and the history is
//     the browser's own.
//   * NO ACTS: nothing here posts, so there is no API index and no CSRF
//     token to carry; the start view is a GET.
//
// `mock-rp-spa.js` and never `mock_rp_surface.js` on disk, the name of the
// compiled server module beside it.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// Its browser objects arrive in `env`.
// ---------------------------------------------------------------------------

import WebSurface = require('./web_surface');
import WebPage = require('./web_page');
import MockRpPagesModule = require('./web_mock_rp_pages');

type Json = any;

/**
 * The mock relying parties' runtime.
 */
class MockRpSurfaceRuntime extends WebSurface {
  /**
   * Makes the runtime for the family the shell names.
   *
   * @param env - the browser's objects
   */
  constructor(env: Json) {
    super(env, { base: MockRpSurfaceRuntime.baseOf(env), api: '',
                 pages: MockRpPagesModule.PAGES as Json,
                 namespaces: ['mockRp'] });
  }

  /**
   * The family's base, from the shell's `data-sts-mock-rp`.
   *
   * @param env - the browser's objects
   * @returns the base; WS-Federation's where the shell names none
   */
  static baseOf(env: Json): string {
    const family = WebPage.attribute(env, 'data-sts-mock-rp');
    return MockRpPagesModule.BASES[family] || MockRpPagesModule.BASES.wsfed;
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
      return state && typeof state === 'object' && state.view ? state : null;
    } catch (e) {
      // Not JSON: the page asks the start view instead.
      return null;
    }
  }

  /**
   * Draws the page the location names: the verdict the shell carries, or
   * the start view its operation answers.
   *
   * @returns nothing
   */
  async route(): Promise<void> {
    const state = MockRpSurfaceRuntime.embeddedState(this.env);
    if (!state) {
      await super.route();
      return;
    }
    const query = WebPage.queryOf(this.env.location.search);
    this.t = await this.i18n.load({ uiLocales: query.ui_locales || '' });
    this.lastAnswer = state;
    this.view = { page: this.find(this.options.base) || this.options.pages[0],
                  query: query, json: state.view };
    this.drawView();
  }

  /**
   * Draws the page in hand again in the language just chosen — from the
   * view in hand: a verdict has nothing to fetch it again from, and asking
   * the start view again would mint new state for nothing.
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
   * Leaves every link to the browser: none of them is a page to draw in
   * place (see the header).
   *
   * @param _event - the click, which the browser follows
   * @returns nothing
   */
  onClick(_event: Json): void {
    // Nothing is prevented: the browser follows the link.
  }
}

declare const window: any;
declare const document: any;

if (typeof window !== 'undefined' && typeof document !== 'undefined') {
  new MockRpSurfaceRuntime({
    fetch: window.fetch.bind(window), location: window.location,
    history: window.history, document: document,
    navigator: window.navigator, window: window
  }).start();
}

export = MockRpSurfaceRuntime;
