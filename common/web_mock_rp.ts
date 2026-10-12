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
//   * THE APPLICATION ASKS ITS OWN BACK END (#590): a mock relying party
//     answers a response that passed with a session of its own and a 303
//     to its page, as a real one does, so the page asks
//     `<base>/api/session` — with the cookie the browser sends — who is
//     signed in, or what was refused; and the start view where the session
//     holds nothing, or where the address asks for it (`?start=1`, Start
//     another sign-in while signed in).
//   * EVERY LINK IS THE BROWSER'S: a sign-in request, the metadata and the
//     artifact loaded again are protocol messages, and Start another
//     sign-in loads the page afresh — the start view MINTS a relying
//     party's state. So nothing is followed in place, and the history is
//     the browser's own.
//   * THE ONE FORM IS THE BROWSER'S TOO: the relying party's own Sign out,
//     posted as a form to `<base>/sign-out`, which ends the session and
//     answers with a 303 — a relying party's sign-out, not an API call.
//     So the runtime handles the language chooser and lets every other
//     form go.
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
                 namespaces: ['mockRp'],
                 frame: MockRpPagesModule.frame });
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
   * Draws the page the location names: what the relying party's session
   * holds, or the start view its operation answers where it holds nothing
   * or the address asks for the start (`?start=1`).
   *
   * @returns nothing
   */
  async route(): Promise<void> {
    const query = WebPage.queryOf(this.env.location.search);
    if (query.start) {
      await super.route();
      return;
    }
    this.t = await this.i18n.load({ uiLocales: query.ui_locales || '' });
    const answer = await this.publicJson('GET', this.options.base +
                                                '/api/session');
    const json = answer.json || {};
    if (answer.status !== 200 || !json.view) {
      await super.route();
      return;
    }
    this.lastAnswer = json;
    this.view = { page: this.find(this.options.base) || this.options.pages[0],
                  query: query, json: json.view };
    this.drawView();
  }

  /**
   * Draws the page in hand again in the language just chosen — from the
   * view in hand: a refusal is answered once, and asking the start view
   * again would mint new state for nothing.
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

  /**
   * Handles the language chooser, and leaves every other form — the
   * relying party's own Sign out — to the browser, which posts it.
   *
   * @param event - the submit event
   * @returns nothing
   */
  onSubmit(event: Json): void {
    const self = this;
    this.i18n.onSubmit(event, function () {
      self.redraw();
    });
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
