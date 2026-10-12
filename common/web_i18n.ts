// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_i18n.ts
//
// ---------------------------------------------------------------------------
// THE BROWSER TRANSLATES (#570, rcbj's decision 3, 2026-10-12).
//
// A static public surface draws its words in the reader's language with no
// help from the API it draws from: the APIs stay language-free, and errors
// stay English (#539's decision 6). This is how a runtime gets there:
//
//   1. THE INDEX: `GET /web/locales/catalogs.json?v=<build>` — which
//      catalogs exist and which locales the chooser offers, the same
//      `common/locales/catalogs.json` the server reads
//      (`common/public_assets.ts` serves it, cacheable for good under the
//      build's version, which the shell names in `data-sts-version`).
//   2. THE LANGUAGE, in today's order (`WebLocale.preferences()`, the
//      server's own): `ui_locales` where the surface's request carries one;
//      the person's `preferredLanguage` where the surface's API answered it;
//      the chooser's choice (`data-sts-lang` — the cookie is HttpOnly, so
//      the shell says what it holds); the browser's languages
//      (`navigator.languages`, what it sends as `Accept-Language`); and the
//      locale policy's default for the surface's application
//      (`data-sts-locale-default`) as the last resort.
//   3. THE CATALOGS: one `GET /web/locales/<namespace>/<catalog>.json?v=`
//      per namespace the surface draws and catalog of the chain, and a
//      `WebTranslator` (`web_messages.ts`) over them — the one formatter the
//      server and the console use.
//
// AND THE CHOOSER, drawn by the runtime (`chooser()`, the same markup
// `PageLocale.chooser()` draws) instead of a page posting it: a submit is
// SENT, to the same `POST /authn/language` — which sets the cookie and, for
// a signed-in person, writes their `preferredLanguage` — and the surface
// draws the page again in the language chosen, with no navigation. The
// endpoint answers a 303 to a local path, which a `fetch()` with `redirect:
// 'manual'` sees as an opaque redirect: that, or any 2xx/3xx, is success.
//
// A `web_` MODULE, on `admin-ui/web_kit.ts`'s terms: it requires other `web_`
// modules only, logs nothing, and reaches the browser only through the page
// it is handed (`WebPage`: `env`, `url()`).
// ---------------------------------------------------------------------------

import WebLocale = require('./web_locale');
import webMessages = require('./web_messages');

type Json = any;

/**
 * What a page's language is chosen from, beyond what the browser and the
 * shell say: what the surface's own request and API know.
 */
interface LoadInputs {
  // `ui_locales` from the request the surface is drawing, if any.
  uiLocales?: string;
  // The person's `preferredLanguage`, where the API answered it, and
  // whether the locale policy populated it.
  own?: { value: string; populated: boolean };
}

/**
 * The page a translator is loaded for: its browser objects and its
 * addresses (a `WebPage`).
 */
interface PageLike {
  url(path: string): string;
}

/**
 * Loads the catalogs a surface draws with, negotiates the page's language,
 * and runs the language chooser.
 */
class WebI18n {
  private readonly env: Json;
  private readonly page: PageLike;
  private readonly namespaces: string[];
  private index: Json;
  private parts: Json[];
  // Catalog files already fetched, by `<namespace>/<tag>`.
  private files: Json;
  // A choice made on this page load, which outranks the shell's attribute.
  private chosen: string;

  /**
   * Makes the loader.
   *
   * @param env - the browser's objects: `fetch`, `document`, `navigator`
   * @param page - the page, for its addresses
   * @param namespaces - the catalog namespaces the surface draws
   *   (`['home', 'chooser']`)
   */
  constructor(env: Json, page: PageLike, namespaces: string[]) {
    this.env = env;
    this.page = page;
    this.namespaces = (namespaces || []).slice();
    if (this.namespaces.indexOf('chooser') < 0) {
      this.namespaces.push('chooser');
    }
    this.index = null;
    this.parts = [];
    this.files = {};
    this.chosen = '';
  }

  /**
   * One attribute of the shell's `<html>`.
   *
   * @param name - the attribute
   * @returns its value, or ''
   */
  attribute(name: string): string {
    const root = this.env.document && this.env.document.documentElement;
    return root && typeof root.getAttribute === 'function'
      ? String(root.getAttribute(name) || '') : '';
  }

  /**
   * The query every catalog address carries: the build, so a new build's
   * catalogs are new addresses and an old one's can be kept for good.
   *
   * @returns `?v=<build>`, or '' where the shell names none
   */
  versionQuery(): string {
    const v = this.attribute('data-sts-version');
    return v ? '?v=' + encodeURIComponent(v) : '';
  }

  /**
   * Fetches one JSON file, or null where it cannot be had.
   *
   * @param path - the path under the realm
   * @returns the JSON, or null
   */
  async fetchJson(path: string): Promise<Json> {
    try {
      const res = await this.env.fetch(this.page.url(path),
        { headers: { 'Accept': 'application/json' } });
      if (!res || res.status !== 200) {
        return null;
      }
      return await res.json();
    } catch (e) {
      // Unreachable or not JSON: the caller falls back along the chain, and
      // English is always in the bundle's own words at worst.
      return null;
    }
  }

  /**
   * The catalog index, once.
   *
   * @returns the index, `{ source, catalogs, offered }`
   */
  async ensureIndex(): Promise<Json> {
    if (!this.index) {
      const got = await this.fetchJson('/web/locales/catalogs.json' +
                                       this.versionQuery());
      this.index = got || { source: WebLocale.SOURCE, offered: [],
        catalogs: [{ tag: WebLocale.SOURCE, name: 'English' }] };
      this.parts = WebLocale.catalogParts(this.index.catalogs || []);
    }
    return this.index;
  }

  /**
   * The browser's languages as an `Accept-Language` value.
   *
   * @returns the tags, comma-separated, best first
   */
  browserLanguages(): string {
    const nav = this.env.navigator || {};
    const list = Array.isArray(nav.languages) && nav.languages.length
      ? nav.languages : (nav.language ? [nav.language] : []);
    return list.join(',');
  }

  /**
   * Negotiates the page's language in today's order.
   *
   * @param input - `ui_locales` and the person's own language, where known
   * @returns the negotiation
   */
  async negotiate(input?: LoadInputs): Promise<Json> {
    await this.ensureIndex();
    const asked = input || {};
    const preferences = WebLocale.preferences({
      uiLocales: asked.uiLocales || '',
      own: asked.own,
      chooser: this.chosen || this.attribute('data-sts-lang'),
      acceptLanguage: this.browserLanguages()
    });
    return WebLocale.negotiate(preferences,
      this.attribute('data-sts-locale-default') || WebLocale.SOURCE,
      this.parts);
  }

  /**
   * Loads the page's translator: negotiates, fetches the namespaces'
   * catalogs along the chain, and marks the document's language and
   * direction. It is also the default a helper handed no translator draws
   * with.
   *
   * @param input - `ui_locales` and the person's own language, where known
   * @returns the translator
   */
  async load(input?: LoadInputs): Promise<Json> {
    const negotiated = await this.negotiate(input);
    const catalogs: Json = {};
    for (const tag of negotiated.chain) {
      const flat: Json = {};
      for (const ns of this.namespaces) {
        const key = ns + '/' + tag;
        if (!(key in this.files)) {
          this.files[key] = await this.fetchJson('/web/locales/' +
            encodeURIComponent(ns) + '/' + encodeURIComponent(tag) + '.json' +
            this.versionQuery()) || {};
        }
        const own = this.files[key];
        Object.keys(own).forEach(function (name) {
          if (typeof own[name] === 'string') {
            flat[ns + '.' + name] = own[name];
          }
        });
      }
      catalogs[tag] = flat;
    }
    const t = webMessages.WebTranslator.fromData({ negotiated: negotiated,
                                                   catalogs: catalogs });
    webMessages.WebTranslator.setDefault(function () {
      return t;
    });
    const root = this.env.document && this.env.document.documentElement;
    if (root && typeof root.setAttribute === 'function') {
      root.setAttribute('lang', t.lang);
      root.setAttribute('dir', t.dir);
    }
    return t;
  }

  /**
   * Draws the language chooser for a page drawn with `t`.
   *
   * @param t - the page's translator
   * @param returnTo - the page's own path and query, the realm's prefix
   *   included
   * @returns the chooser's markup, or '' before the index is loaded
   */
  chooser(t: Json, returnTo: string): string {
    if (!this.index) {
      return '';
    }
    return WebLocale.chooserHtml(t, this.index.offered || [], this.parts,
                                 returnTo);
  }

  /**
   * Sends a choice to the chooser endpoint, as its form would have posted
   * it, and keeps it for this page load.
   *
   * @param lang - the tag chosen
   * @param returnTo - the return path the form carried
   * @returns whether the endpoint took it
   */
  async choose(lang: string, returnTo: string): Promise<boolean> {
    const target = this.page.url(WebLocale.CHOOSER_ACTION);
    let ok = false;
    try {
      const res = await this.env.fetch(target, {
        method: 'POST', redirect: 'manual', credentials: 'include',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ lang: lang,
          'return': WebLocale.safeReturn(returnTo) }).toString() });
      ok = !!res && (res.type === 'opaqueredirect' ||
                     (res.status >= 200 && res.status < 400));
    } catch (e) {
      // Not sent: the page stays in the language it is in.
      ok = false;
    }
    if (ok) {
      this.chosen = WebLocale.canonical(lang);
    }
    return ok;
  }

  /**
   * Answers a submit of the chooser drawn on the page: the choice is sent
   * and `then` draws the page again. Any other form is left alone.
   *
   * @param event - the submit event
   * @param then - what to do once the choice is taken
   * @returns whether the event was the chooser's
   */
  onSubmit(event: Json, then: () => void): boolean {
    const form = event && event.target;
    if (!form || !form.classList || !form.classList.contains ||
        !form.classList.contains('language-chooser')) {
      return false;
    }
    event.preventDefault();
    const select = form.querySelector ? form.querySelector('select') : null;
    const back = form.querySelector
      ? form.querySelector('input[name="return"]') : null;
    const self = this;
    this.choose(String((select && select.value) || ''),
                String((back && back.value) || '/'))
      .then(function (ok: boolean) {
        if (ok) {
          then();
        }
        return self;
      }, function () {
        // `choose()` catches its own failures; nothing reaches here.
        return self;
      });
    return true;
  }
}

export = WebI18n;
