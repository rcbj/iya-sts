// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_surface.ts
//
// ---------------------------------------------------------------------------
// THE RUNTIME OF A STATIC PUBLIC SURFACE (#570, 2026-10-12).
//
// #569 converts every human-facing page this service draws outside `/admin`
// and `/portal` into a static application on the console's pattern, one
// bundle per surface (rcbj's decision 2 on #570): the front door (#579),
// the sign-in screen (#571 and its steps), consent (#576), the sign-out
// (#577), GNAP's interaction (#578), the error and outcome pages (#580), the
// demonstration pages (#581–#584). Unlike the console and the portal these
// are NOT OAuth clients and hold no token: the sign-on session is the
// `sts_session` cookie, which a same-origin `fetch()` sends, and their APIs
// are unauthenticated or bound to it (#569's decision 3). So this runtime is
// `WebPage` and no `SpaClient`, and what it does is the portal's runtime
// with the sign-in taken out:
//
//   * ROUTING ON REAL PATHS: a surface owns a base (`/authn`, `/logout`);
//     the page is the row of its table whose `path` is the location's path
//     under that base, drawn from what its `operation` answers to a GET
//     with the location's query. A same-origin link to another of the
//     surface's paths is followed in place (the history API), so a deep
//     link and the back button work as they did; a link anywhere else is
//     the browser's.
//   * TRANSLATION IN THE BROWSER (`web_i18n.ts`), in today's order, with the
//     chooser drawn by the runtime and sent rather than posted.
//   * FORMS AS API CALLS: a GET form navigates; a POST form goes, as JSON, to
//     the operation the surface's API index says MIRRORS it (`GET <api>`
//     lists `{ id, method, path, mirrors }` — `/account-api`'s convention,
//     #568), and a form no operation mirrors is REFUSED rather than guessed.
//     What the act answered decides what is drawn, by the conventions every
//     such API keeps (`answered()`).
//   * ERRORS ARE ENGLISH (#539's decision 6) and drawn where they happened:
//     a refusal over the page (`.err`), a page that cannot be drawn as a
//     problem page of its own (`drawProblem()`).
//
// SCRIPT IS REQUIRED (rcbj's decision on #569): the shell's `<noscript>`
// says so, and there is no server-drawn fallback to keep in step.
//
// SIGN IN WITH ANOTHER ACCOUNT ON EVERY PAGE (#561, delivery step 6), with
// `authn.multipleAccounts` on: beside the chooser, the browser's signed-in
// accounts and a link that starts the user portal's sign-in with
// `prompt=login` (`web_accounts.ts`'s control). Read once as the surface
// starts (`loadAccounts()`), from this page's own origin; OFF — the setting
// off, or nothing answering there — draws exactly the page it drew before,
// fetches none of the control's words, and asks the list nothing again.
// Never on a page that is a specification's exchange
// (`NO_ACCOUNT_CONTROL`), and never on the picker, which is that list.
// After an act the list is read again, and a change the act made is
// announced to the browser's other tabs.
//
// THE CONTRACT A SURFACE KEEPS — the recipe its ticket follows is in
// `common/CLAUDE.md`, *Static public surfaces*:
//
//   * a page table: `{ path, operation, render(json, ctx), title?(json,
//     ctx) }`, the renderers `web_` modules beside the surface's server
//     module, held by `tests/web_surfaces.js`'s round trip;
//   * a `web_<surface>.ts` entry that builds `new WebSurface(env, options)`
//     and calls `start()`;
//   * the shell, drawn by `ShellDocument` with `PageLocale.shellAttributes()`
//     and `data-sts-prefix`, and the bundle, built by `build-typescript.sh`'s
//     `bundle_surface`.
//
// A `web_` MODULE, on `admin-ui/web_kit.ts`'s terms: it requires other `web_`
// modules only, logs nothing, and touches the browser only through `env`.
// ---------------------------------------------------------------------------

import WebPage = require('./web_page');
import WebI18n = require('./web_i18n');
import webMessages = require('./web_messages');
import WebAccounts = require('./web_accounts');

type Json = any;

/**
 * One page of a surface.
 */
interface SurfacePage {
  // The page's path, without the realm's prefix: `/authn/login`.
  path: string;
  // The GET operation its view is the answer of, without the prefix — asked
  // with the location's query; or, where a page's operation names its
  // resource in the PATH (#571's `/authn-api/pending/{id}`), a function of
  // the query answering the whole path.
  operation: string | ((query: Json) => string);
  // Draws the page's body from the view and the context.
  render: (json: Json, ctx: Json) => string;
  // The document's title for the view, as text.
  title?: (json: Json, ctx: Json) => string;
}

/**
 * What a surface is.
 */
interface SurfaceOptions {
  // The surface's first path; every page is under it or is it.
  base: string;
  // The API's index path, which lists the operations and what each
  // mirrors; '' for a surface that posts nothing.
  api: string;
  // The page table.
  pages: SurfacePage[];
  // The catalog namespaces its pages draw.
  namespaces: string[];
  // Wraps a page's body (and the chooser) in the surface's frame; the body
  // as it is where left out. Its context carries the page's `view` where a
  // page is drawn (#579: the front door's band is drawn from it), and none
  // on a problem page, which draws its own card.
  frame?: (body: string, ctx: Json) => string;
  // What follows a title in the document's title.
  brand?: string;
}

/**
 * A static public surface's runtime: routing, translation and forms.
 */
class WebSurface extends WebPage {
  // THE PATHS THE ACCOUNT CONTROL IS NEVER DRAWN ON (#561): RFC 4559's
  // exchange answers its person-facing bodies on this surface (#575), and
  // a specification's response gets no control; the account picker IS the
  // list. Each is a prefix of the surface's path, on a segment boundary.
  static readonly NO_ACCOUNT_CONTROL = ['/authn/spnego', '/authn/accounts'];
  protected options: SurfaceOptions;
  protected i18n: WebI18n;
  protected t: Json;
  protected formTable: Json;
  protected view: Json;
  // What an act left to say on the next page drawn: `{ message, error }`.
  protected flash: Json;
  // The path and query of the page last drawn: a `popstate` that changes
  // neither is a fragment's, which the browser has already answered.
  protected drawnAt: string;
  // The whole answer the page in hand was drawn from — its view and what
  // the API answered beside it (#571: the sign-in screen's `csrf`).
  protected lastAnswer: Json;
  // THE BROWSER'S ACCOUNTS (#561): the list as last read, how many pages
  // have been drawn (the first one's list is the one `start()` read), and
  // the channel changes are heard and announced on.
  protected accounts: Json;
  protected drawn: number;
  protected accountChannel: Json;

  /**
   * Makes the runtime.
   *
   * @param env - the browser's objects: `fetch`, `location`, `history`,
   *   `document`, `navigator`, `window`; for a test, `formDataOf`
   * @param options - the surface: its base, API, pages and namespaces
   */
  constructor(env: Json, options: SurfaceOptions) {
    // THE REALM'S PREFIX is the shell's `data-sts-prefix` — the server knows
    // it, and a surface at `/` cannot find it in its own path — and the
    // path's own reading where the shell names none.
    super(env, WebPage.attribute(env, 'data-sts-prefix') ||
               WebPage.prefixAt(env.location.pathname, options.base),
          { '/authn': 'data-sts-authn', '/oauth2': 'data-sts-oauth' });
    this.options = options;
    this.i18n = new WebI18n(env, this, options.namespaces);
    this.t = webMessages.WebTranslator.fromData(null);
    this.formTable = null;
    this.view = null;
    this.flash = null;
    this.drawnAt = '';
    this.lastAnswer = null;
    this.accounts = WebAccounts.off();
    this.drawn = 0;
    this.accountChannel = null;
  }

  // --- the browser's accounts (#561) ---------------------------------------

  /**
   * Reads the browser's account list as the surface starts; with it on, the
   * control's words are loaded with the page's and other tabs' changes are
   * listened for.
   *
   * @returns nothing
   */
  async loadAccounts(): Promise<void> {
    this.accounts = await WebAccounts.fetchList(this.env, this.prefix);
    if (!this.accounts.enabled) {
      return;
    }
    this.i18n.include('accounts');
    const self = this;
    this.accountChannel = WebAccounts.openChannel(this.env, function () {
      self.refreshAccounts(false);
    });
  }

  /**
   * Reads the list again and draws the control again in place; a change
   * this page's own act made is announced to the other tabs.
   *
   * @param announce - whether a change is this page's to announce (never
   *   when a message asked)
   * @returns nothing
   */
  async refreshAccounts(announce: boolean): Promise<void> {
    if (!this.accounts.enabled) {
      return;
    }
    const before = this.accounts;
    const after = await WebAccounts.fetchList(this.env, this.prefix);
    if (!after.enabled) {
      return;
    }
    this.accounts = after;
    if (announce && WebAccounts.changed(before, after) &&
        this.accountChannel) {
      this.accountChannel.post('changed');
    }
    const doc = this.env.document;
    const slot = doc && doc.getElementById
      ? doc.getElementById('sts-accounts-slot') : null;
    if (slot) {
      slot.innerHTML = WebSurface.realmLinks(
        WebAccounts.controlHtml(after, this.t), this.prefix);
    }
  }

  /**
   * The account control for the page being drawn: '' with the list off and
   * on a path that never carries it.
   *
   * @returns the control in its slot, or ''
   */
  accountControl(): string {
    if (!this.accounts.enabled) {
      return '';
    }
    const path = this.surfacePath(this.env.location.pathname) || '';
    const excluded = WebSurface.NO_ACCOUNT_CONTROL.some(function (one) {
      return path === one || path.indexOf(one + '/') === 0;
    });
    if (excluded) {
      return '';
    }
    return '<div id="sts-accounts-slot">' +
      WebAccounts.controlHtml(this.accounts, this.t) + '</div>';
  }

  // --- paths ---------------------------------------------------------------

  /**
   * The surface's path of a full path under this realm, or null for one that
   * is not the surface's.
   *
   * @param pathname - the path
   * @returns the path without the prefix, or null
   */
  surfacePath(pathname: string): string | null {
    const path = String(pathname || '');
    if (path.indexOf(this.prefix) !== 0) {
      return null;
    }
    const rest = path.slice(this.prefix.length) || '/';
    const base = this.options.base;
    if (base === '/') {
      return rest;
    }
    return rest === base || rest.indexOf(base + '/') === 0 ? rest : null;
  }

  /**
   * The page row for a path.
   *
   * @param path - the surface's path
   * @returns the row, or null
   */
  find(path: string): SurfacePage | null {
    const rows = this.options.pages.filter(function (one) {
      return one.path === path;
    });
    return rows.length ? rows[0] : null;
  }

  /**
   * The path and query being shown, without the realm prefix.
   *
   * @returns the path and query
   */
  here(): string {
    const path = this.surfacePath(this.env.location.pathname) ||
      this.options.base;
    return path + (this.env.location.search || '');
  }

  // --- drawing -------------------------------------------------------------

  /**
   * The context a renderer is handed.
   *
   * @param query - the location's query
   * @returns the context
   */
  context(query: Json): Json {
    return { t: this.t, query: query, prefix: this.prefix,
             origin: this.env.location.origin,
             here: this.prefix + this.here() };
  }

  /**
   * Puts a page in the document, with the chooser, and wires it.
   *
   * @param title - the document's title, as text
   * @param body - the page's body
   * @param ctx - the context it was drawn with
   * @returns nothing
   */
  put(title: string, body: string, ctx: Json): void {
    const doc = this.env.document;
    const chooser = this.i18n.chooser(this.t, ctx.here) +
      this.accountControl();
    const framed = this.options.frame ? this.options.frame(chooser + body, ctx)
                                      : chooser + body;
    doc.title = title + (this.options.brand === undefined ? ' — IYA STS'
                                                          : this.options.brand);
    doc.body.innerHTML = WebSurface.realmLinks(framed, this.prefix);
    this.drawnAt = this.env.location.pathname + this.env.location.search;
    this.targetFragment();
    // A PAGE AFTER THE FIRST follows an act or a navigation, which may have
    // changed the browser's accounts (a sign-out, a forget): the list is
    // read again, and a change announced (#561). Only with the list on.
    this.drawn++;
    if (this.drawn > 1 && this.accounts.enabled) {
      this.refreshAccounts(true);
    }
  }

  /**
   * Draws a page that says something went wrong: in English, as every
   * refusal here is.
   *
   * @param title - what went wrong
   * @param detail - the detail
   * @returns nothing
   */
  drawProblem(title: string, detail: string): void {
    const ctx = this.context(WebPage.queryOf(this.env.location.search));
    this.put(title, '<div class="card"><h1>' + WebSurface.esc(title) +
      '</h1><div class="err">' + WebSurface.esc(detail) + '</div></div>',
      ctx);
  }

  /**
   * Draws the page in hand from its view, with what an act left to say.
   *
   * @returns nothing
   */
  drawView(): void {
    const v = this.view;
    const ctx = this.context(v.query);
    const flash = this.flash || {};
    this.flash = null;
    const said = (flash.error ? '<div class="err">' +
                    WebSurface.esc(flash.error) + '</div>' : '') +
                 (flash.message ? '<div class="ok">' +
                    WebSurface.esc(flash.message) + '</div>' : '');
    const title = v.page.title ? v.page.title(v.json, ctx) : 'IYA STS';
    // The frame is handed the view as well (#579); the renderer is not, so
    // what it draws is a function of its view and the context alone.
    this.put(title, said + v.page.render(v.json, ctx),
             Object.assign({ view: v.json }, ctx));
  }

  /**
   * Draws the page the location names: its operation asked with the
   * location's query, and its renderer over the answer.
   *
   * @returns nothing
   */
  async route(): Promise<void> {
    const path = this.surfacePath(this.env.location.pathname) ||
      this.options.base;
    const query = WebPage.queryOf(this.env.location.search);
    this.t = await this.i18n.load({ uiLocales: query.ui_locales || '' });
    const page = this.find(path);
    if (!page) {
      this.view = null;
      this.drawProblem('Not a page', path + ' is not a page here.');
      return;
    }
    const qs = new URLSearchParams(query).toString();
    const answer = await this.publicJson('GET',
      typeof page.operation === 'function' ? page.operation(query)
                                           : page.operation +
                                             (qs ? '?' + qs : ''));
    const json = answer.json || {};
    if (answer.json === null) {
      this.drawProblem('This page could not be drawn',
        'The service answered ' + answer.status + ' with no JSON.');
      return;
    }
    // ANOTHER PAGE INSTEAD (#571: a chooser with fewer than two partners
    // left is the sign-in screen): the address is replaced, not added to.
    if (json.go && answer.status === 200 && this.env.history) {
      this.env.history.replaceState(null, '', this.prefix + String(json.go));
      await this.route();
      return;
    }
    // A REFUSED VIEW IS A PROBLEM PAGE: with no view there is nothing for
    // the page's renderer to draw (#571: a pending id that expired).
    if ((answer.status !== 200 || json.ok === false) && !json.view) {
      this.view = null;
      this.drawProblem('This page could not be drawn',
        (json.errors || []).join(' ') ||
        'The service answered ' + answer.status + '.');
      return;
    }
    // A person's own language, where the API answered it, outranks the
    // browser's (#539's order), and so does a `ui_locales` the API holds
    // for the request in progress (#571: the protocol request's, kept on
    // the pending sign-in); the translator is loaded again with them.
    const ui = query.ui_locales || String(json.uiLocales || '');
    if ((json.preferredLanguage && json.preferredLanguage.value) ||
        ui !== (query.ui_locales || '')) {
      this.t = await this.i18n.load({ uiLocales: ui,
                                      own: json.preferredLanguage });
    }
    if (answer.status !== 200 || json.ok === false) {
      this.flash = { error: (json.errors || []).join(' ') ||
                            'The service answered ' + answer.status + '.' };
    }
    this.lastAnswer = json;
    this.view = { page: page, query: query, json: json.view || json };
    this.drawView();
  }

  /**
   * Goes to one of the surface's paths, adding it to the history.
   *
   * @param to - the path and query under the realm
   * @returns nothing
   */
  async go(to: string): Promise<void> {
    this.env.history.pushState(null, '', this.prefix + to);
    await this.route();
  }

  // --- forms and links -----------------------------------------------------

  /**
   * The operation table, once: which operation each form goes to.
   *
   * @returns whether it is in hand
   */
  async ensureFormTable(): Promise<boolean> {
    if (this.formTable) {
      return true;
    }
    if (!this.options.api) {
      this.formTable = {};
      return true;
    }
    const index = await this.publicJson('GET', this.options.api);
    if (index.status !== 200 || !index.json) {
      return false;
    }
    const table: Json = {};
    (index.json.operations || []).forEach(function (op: Json) {
      if (op.mirrors) {
        table[op.mirrors] = op;
      }
    });
    this.formTable = table;
    return true;
  }

  /**
   * Sends a POST form to the operation that mirrors it, and draws what it
   * answered.
   *
   * @param form - the form
   * @param submitter - the button pressed, if any
   * @returns nothing
   */
  async submit(form: Json, submitter: Json): Promise<void> {
    const posted = (submitter && submitter.getAttribute &&
                    submitter.getAttribute('formaction')) ||
                   form.getAttribute('action') || this.here();
    const target = new URL(posted, this.env.location.href);
    const path = this.surfacePath(target.pathname);
    const fields = this.formFields(form, submitter);
    target.searchParams.forEach(function (value: string, name: string) {
      fields[name] = value;
    });
    if (!await this.ensureFormTable()) {
      this.flash = { error: 'The service\'s API could not be reached.' };
      this.redraw();
      return;
    }
    const op = path ? this.formTable['POST ' + path] : null;
    if (!op) {
      this.flash = { error: 'This control has no API operation (' +
        (path || target.pathname) + '), so the page refuses it rather ' +
        'than guess.' };
      this.redraw();
      return;
    }
    const answer = await this.publicJson('POST', op.path, fields);
    await this.answered(path, answer);
  }

  /**
   * Draws the page in hand again, or the location's page where none is.
   *
   * @returns nothing
   */
  redraw(): void {
    if (this.view) {
      this.drawView();
      return;
    }
    this.route();
  }

  // WHAT AN ACT ANSWERED, AND WHAT IS DRAWN FOR IT — the conventions of
  // `/account-api` (`account-api/CLAUDE.md`), which every surface's API
  // keeps:
  //   * `location`: another address (a client's redirect URI after a
  //     sign-in) — the window goes there.
  //   * `view`: the page drawn from it, in place.
  //   * `go`: another of the surface's pages, with the message.
  //   * otherwise the page asked again, with `message` or the `errors`.
  /**
   * Draws what an act answered.
   *
   * @param path - the surface's path the form was on
   * @param answer - `{ status, json }`
   * @returns nothing
   */
  async answered(path: string | null, answer: Json): Promise<void> {
    const json = answer.json || { ok: answer.status < 400 };
    const said = json.ok === false
      ? { error: (json.errors || []).join(' ') ||
                 'Refused (' + answer.status + ').' }
      : { message: String(json.message || '') };
    if (json.location) {
      this.env.location.assign(String(json.location));
      return;
    }
    if (json.view) {
      const page = path ? this.find(path) : null;
      const row = page || (this.view && this.view.page);
      if (row) {
        this.view = { page: row, query: this.view && this.view.page === row
          ? this.view.query : {}, json: json.view };
        this.flash = said;
        this.drawView();
        return;
      }
    }
    this.flash = said;
    if (json.go) {
      await this.go(String(json.go));
      return;
    }
    await this.route();
  }

  /**
   * Follows a link in place when it is one of the surface's pages on this
   * origin.
   *
   * @param event - the click
   * @returns nothing
   */
  onClick(event: Json): void {
    if (event.defaultPrevented || event.button !== 0 || event.metaKey ||
        event.ctrlKey || event.shiftKey || event.altKey) {
      return;
    }
    let el = event.target;
    while (el && el.tagName !== 'A') {
      el = el.parentElement;
    }
    if (!el || el.target === '_blank' || el.hasAttribute('download')) {
      return;
    }
    const url = new URL(el.getAttribute('href') || '', this.env.location.href);
    const path = url.origin === this.env.location.origin
      ? this.surfacePath(url.pathname) : null;
    if (!path || !this.find(path)) {
      return;
    }
    event.preventDefault();
    if (url.pathname === this.env.location.pathname &&
        url.search === this.env.location.search && url.hash) {
      this.env.location.hash = url.hash;
      return;
    }
    this.go(path + url.search + url.hash);
  }

  /**
   * Handles a submitted form: the language chooser, a GET form's
   * navigation, or an act.
   *
   * @param event - the submit event
   * @returns nothing
   */
  onSubmit(event: Json): void {
    const self = this;
    if (this.i18n.onSubmit(event, function () {
      self.redraw();
    })) {
      return;
    }
    const form = event.target;
    const target = new URL(form.getAttribute('action') || this.here(),
                           this.env.location.href);
    const path = target.origin === this.env.location.origin
      ? this.surfacePath(target.pathname) : null;
    // A FORM THAT IS NOT THE SURFACE'S is the browser's.
    if (!path) {
      return;
    }
    event.preventDefault();
    const method = String(form.getAttribute('method') || 'get').toLowerCase();
    if (method !== 'post') {
      const fields = this.formFields(form, null);
      const qs = new URLSearchParams(fields).toString();
      this.go(path + (qs ? '?' + qs : '') + target.hash);
      return;
    }
    this.submit(form, event.submitter || null);
  }

  /**
   * Starts the surface: wires the document and draws the first page.
   *
   * @returns nothing
   */
  async start(): Promise<void> {
    const self = this;
    this.env.document.addEventListener('click', function (event: Json) {
      self.onClick(event);
    });
    this.env.document.addEventListener('submit', function (event: Json) {
      self.onSubmit(event);
    });
    if (this.env.window) {
      this.env.window.addEventListener('popstate', function () {
        if (self.env.location.pathname + self.env.location.search ===
            self.drawnAt) {
          return;
        }
        self.route();
      });
    }
    // THE BROWSER'S ACCOUNTS (#561), before the first page: their words are
    // loaded with the page's where the list is on.
    await this.loadAccounts();
    await this.route();
  }

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
}

export = WebSurface;
