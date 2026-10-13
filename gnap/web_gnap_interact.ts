// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_gnap_interact.ts
//
// ---------------------------------------------------------------------------
// THE GNAP INTERACTION SURFACE'S RUNTIME (#578, 2026-10-12).
//
// `gnap/gnap-interaction-spa.js`, served at `/gnap/interaction.js`, is built
// from this. It is the public surfaces' runtime (`common/web_surface.ts`)
// over GNAP's page table (`web_gnap_interact_pages.ts`), with what these
// pages need beyond it:
//
//   * PAGES ADDRESSED BY A HANDLE: the approval page is
//     `/gnap/approve/{id}`, the id an RFC 9635 section 4 interaction handle;
//     its view is asked of `/gnap-api/approve/{id}`.
//   * PAGES THE SHELL CARRIES: a refused start link, a decision made on the
//     approval page's GET (a cancelled sign-in, a remembered approval) and
//     a request sent to the person it names are the shell with the page's
//     state in `data-sts-state` (`gnap_interact.ts`, `sendShell()`), drawn
//     from it and never fetched — the state exists only on that response.
//   * BACK TO THE PAGE: where a view or an act answers `next: page`, the
//     approval page's GET has a redirect to answer first (the sign-in
//     screen, a step-up, a remembered approval's finish), and the browser
//     loads it.
//   * THE CSRF BINDING (#571's three, `gnap_interact.ts`'s `bound()`): every
//     act carries `X-CSRF-Token` — the `csrf` the page's view answered, the
//     token of the browser's `sts_session` cookie — and `Content-Type:
//     application/json`; the browser adds the `Origin`.
//   * THE ANSWER of an act: `location` — the client's finish URI with
//     `hash` and `interact_ref`, or the page again — is followed; a `view`
//     (`done`, or a refusal that ends the page) is drawn in place; anything
//     else draws the page again with the sentence over it.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// Its browser objects arrive in `env`.
// ---------------------------------------------------------------------------

import WebSurface = require('../common/web_surface');
import WebPage = require('../common/web_page');
import GnapInteractPages = require('./web_gnap_interact_pages');

type Json = any;

/**
 * The GNAP interaction surface's runtime.
 */
class GnapInteractSurface extends WebSurface {
  // The person's own language, where an answer or the shell carried it.
  protected own: Json;

  /**
   * Makes the runtime.
   *
   * @param env - the browser's objects
   */
  constructor(env: Json) {
    super(env, { base: '/gnap', api: '/gnap-api',
                 pages: GnapInteractPages.PAGES as Json,
                 namespaces: ['gnap'],
                 frame: GnapInteractPages.frame, brand: '' });
    this.own = undefined;
  }

  /**
   * The page row for a path, a handle in it or not.
   *
   * @param path - the surface's path
   * @returns the row, or null
   */
  find(path: string): Json {
    const found = GnapInteractPages.match(path);
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
   * Draws the page the location names: from the shell's state where it
   * carried one, otherwise from its operation's answer.
   *
   * @returns nothing
   */
  async route(): Promise<void> {
    const path = this.surfacePath(this.env.location.pathname) ||
      this.options.base;
    const query = WebPage.queryOf(this.env.location.search);
    const found = GnapInteractPages.match(path);
    const state = GnapInteractSurface.embeddedState(this.env);
    if (state) {
      this.own = state.preferredLanguage;
      this.t = await this.i18n.load({ uiLocales: query.ui_locales || '',
                                      own: this.own });
      this.lastAnswer = state;
      this.view = { page: found ? found.row : this.options.pages[0],
                    query: query, json: state.view };
      this.drawView();
      return;
    }
    this.t = await this.i18n.load({ uiLocales: query.ui_locales || '' });
    if (!found || found.row.embedded) {
      this.view = null;
      this.drawProblem(found ? 'This page could not be drawn' : 'Not a page',
        found ? 'The service sent no state for it.'
              : path + ' is not a page here.');
      return;
    }
    const answer = await this.publicJson('GET',
                                         found.row.operation(query, found.id));
    const json = answer.json;
    if (!json) {
      this.view = null;
      this.drawProblem('This page could not be drawn',
        'The service answered ' + answer.status + ' with no JSON.');
      return;
    }
    // THE PAGE'S GET HAS SOMETHING TO ANSWER FIRST: the browser loads it.
    if (json.location) {
      this.env.location.assign(String(json.location));
      return;
    }
    if ((answer.status !== 200 || json.ok === false) && !json.view) {
      this.view = null;
      this.drawProblem('This page could not be drawn',
        (json.errors || []).join(' ') ||
        'The service answered ' + answer.status + '.');
      return;
    }
    if (json.preferredLanguage && json.preferredLanguage.value) {
      this.own = json.preferredLanguage;
      this.t = await this.i18n.load({ uiLocales: query.ui_locales || '',
                                      own: this.own });
    }
    this.lastAnswer = json;
    this.view = { page: found.row, query: query, json: json.view };
    this.drawView();
  }

  /**
   * Draws the page in hand; a refusal's view says its own sentence, so an
   * act's is not said over it a second time.
   *
   * @returns nothing
   */
  drawView(): void {
    if (this.view && this.view.json && this.view.json.kind === 'problem') {
      this.flash = null;
    }
    super.drawView();
  }

  /**
   * Draws the page in hand again in the language just chosen — from the
   * view in hand, which a decision drawn in place has no operation to
   * fetch again from.
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
   * Sends an act: JSON, with the page's CSRF token.
   *
   * @param path - the operation's path, its `{id}` filled
   * @param body - the act's fields
   * @returns `{ status, json }`
   */
  async send(path: string, body: Json): Promise<Json> {
    const csrf = String((this.lastAnswer && this.lastAnswer.csrf) || '');
    const res = await this.env.fetch(this.url(path), {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Accept': 'application/json',
                 'Content-Type': 'application/json',
                 'X-CSRF-Token': csrf },
      body: JSON.stringify(body) });
    const json = await res.json().catch(function () {
      return null;
    });
    return { status: res.status, json: json };
  }

  /**
   * Sends a form of this surface to the operation the API's index says
   * mirrors it — the user code, or the approval's answer — and draws what
   * it answered.
   *
   * @param form - the form
   * @param submitter - the button pressed, if any
   * @returns nothing
   */
  async submit(form: Json, submitter: Json): Promise<void> {
    const target = new URL(form.getAttribute('action') || this.here(),
                           this.env.location.href);
    const path = this.surfacePath(target.pathname) || '';
    const found = GnapInteractPages.match(path);
    const mirrors = found ? 'POST ' + found.row.path.replace(':id', '{id}')
                          : '';
    if (!await this.ensureFormTable()) {
      this.flash = { error: 'The service\'s API could not be reached.' };
      this.redraw();
      return;
    }
    const op = mirrors ? this.formTable[mirrors] : null;
    if (!op || found.row.embedded) {
      this.flash = { error: 'This control has no API operation (' + path +
        '), so the page refuses it rather than guess.' };
      this.redraw();
      return;
    }
    const fields = this.formFields(form, submitter);
    const body = found.row.path === '/gnap/code'
      ? { code: fields.code } : fields;
    const answer = await this.send(String(op.path)
      .replace('{id}', encodeURIComponent(found.id)), body);
    // A refusal that leaves the page standing (a stale token, a raised
    // limit) draws it again from a fresh view, with the sentence over it.
    await this.answered(path, answer);
  }
}

declare const window: any;
declare const document: any;

if (typeof window !== 'undefined' && typeof document !== 'undefined') {
  new GnapInteractSurface({
    fetch: window.fetch.bind(window), location: window.location,
    history: window.history, document: document,
    navigator: window.navigator, window: window
  }).start();
}

export = GnapInteractSurface;
