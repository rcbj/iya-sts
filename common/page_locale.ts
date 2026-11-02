// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: page_locale.ts
//
// ---------------------------------------------------------------------------
// WHICH LANGUAGE A PAGE IS DRAWN IN (#539, 2026-10-09).
//
// `common/i18n.ts` negotiates a list of tags against the catalogs; this module
// says which list a REQUEST offers, in the order rcbj decided on #539:
//
//   1. `ui_locales` — OpenID Connect Core 1.0 section 3.1.2.1, the relying
//      party's request for the sign-in and consent screens, where a page is
//      drawn for an authorization request that carried one;
//   2. the person's own `preferredLanguage` (RFC 2798 section 2.7), where the
//      page knows who it is drawn for — unless it is still the value the
//      locale policy POPULATED, which is the policy's choice and ranks after
//      4 (rcbj on #539);
//   3. the LANGUAGE CHOOSER's cookie, `sts_lang`, which every user-facing page
//      offers and which works before anybody has signed in;
//   4. the browser's `Accept-Language` (RFC 9110 section 12.5.4);
//   5. the LOCALE POLICY's default for the application the page is drawn for
//      and, where the page knows them, the person — whose groups may name a
//      profile too (`common/locale_policy.ts`, #1238) — and English if that
//      answers nothing.
//
// The first that a catalog answers wins (`I18n.negotiate()`); a preference no
// catalog answers is passed over rather than ending the search, so a reader
// whose entry says `de` and whose browser says `fr` reads French until a
// German catalog exists.
//
// A signed-in person's choice in the chooser ALSO writes their
// `preferredLanguage` (the endpoint, `authn/authn.ts`'s `POST
// /authn/language`), since the entry outranks the cookie and a choice that
// changed nothing would mislead; so 2 and 3 never disagree for long.
//
// THE CHOOSER is drawn here, once, for every server-drawn surface: a real
// form, a real select and a real submit button, so it works with script
// blocked — every page it sits on is `script-src 'none'` or names one
// resource. It posts the language and a RETURN PATH, which `safeReturn()`
// holds to a local path: anything else becomes `/`, so the endpoint cannot
// be made an open redirect.
//
// SINCE #570 THE ORDER, THE CHOOSER'S MARKUP AND THE RETURN-PATH RULE ARE
// `common/web_locale.ts`'s, a `web_` module a static surface's runtime runs
// in the browser (rcbj's decision 3 on #570: the browser translates). This
// module reads the inputs off a request and hands them over, so a page drawn
// here and one drawn by a runtime choose the same language and the same
// chooser. `shellAttributes()` is what a static surface's shell carries for
// its runtime: the chooser's cookie is HttpOnly, so the browser is told it.
//
// A LIBRARY (rule 3): `i18n` and `locale_policy` (leaves), `helpers`,
// `config`, `version` and `web_locale`. It reads the request it is handed
// and requires no route module; the caller passes who the page is for and
// which application, because only the caller knows.
// ---------------------------------------------------------------------------

import helpers = require('./helpers');
import config = require('./config');
import i18n = require('./i18n');
import localePolicy = require('./locale_policy');
import version = require('./version');
import WebLocale = require('./web_locale');

const { log } = helpers;

/**
 * What a caller knows about the page it is drawing.
 */
interface PageFor {
  // The application the page is drawn for: an OAuth client_id, or the
  // hosted surface's own (`sts-user-portal`, `sts-admin-console`).
  application?: string;
  // An OpenID Connect `ui_locales` value from the request in progress.
  uiLocales?: string;
  // The person the page is drawn for, where known: a username or a subject.
  username?: string;
}

type Translator = InstanceType<typeof i18n.Translator>;

/**
 * The chooser's cookie.
 */
const COOKIE = 'sts_lang';

/**
 * Which language a page is drawn in, and the language chooser.
 *
 * A static utility class; it holds no state.
 */
class PageLocale {
  /**
   * The chooser's cookie name.
   */
  static readonly COOKIE = COOKIE;

  // A request's cookie by name, from its header: the parse every module here
  // writes for itself, kept small.
  private static cookieOf(req: any, name: string): string {
    log.debug("Entering PageLocale.cookieOf().");
    const header = String((req && req.headers && req.headers.cookie) || '');
    let out = '';
    header.split(';').forEach(function (part) {
      const at = part.indexOf('=');
      if (at > 0 && part.slice(0, at).trim() === name) {
        try {
          out = decodeURIComponent(part.slice(at + 1).trim());
        } catch (e) {
          log.debug("Caught in PageLocale.cookieOf(): " +
                    ((e && e.message) || e));
          out = '';
        }
      }
    });
    log.debug("Leaving PageLocale.cookieOf().");
    return out;
  }

  /**
   * Lists a request's language preferences, best first, in #539's order —
   * everything but the policy's default, which is the last resort.
   *
   * @param req - the request
   * @param page - what the caller knows about the page
   * @returns canonical tags, best first, each once
   */
  static preferences(req: any, page?: PageFor): string[] {
    log.debug("Entering PageLocale.preferences().");
    const asked = page || {};
    // The ORDER is `web_locale.ts`'s (#570), which a static surface's runtime
    // asks in the browser; this reads its inputs off the request.
    const out = WebLocale.preferences({
      uiLocales: asked.uiLocales || '',
      own: asked.username ? localePolicy.languageOf(asked.username)
                          : { value: '', populated: false },
      chooser: PageLocale.cookieOf(req, COOKIE),
      acceptLanguage: req && req.headers && req.headers['accept-language']
    });
    log.debug("Leaving PageLocale.preferences(). " + out.join(' '));
    return out;
  }

  /**
   * Builds the translator a page is drawn with.
   *
   * @param req - the request
   * @param page - the application, `ui_locales` and person, where known
   * @returns the translator
   */
  static translatorFor(req: any, page?: PageFor): Translator {
    log.debug("Entering PageLocale.translatorFor().");
    const asked = page || {};
    let lastResort = 'en';
    try {
      // THE PERSON TOO, where the page knows one (#1238): their groups may
      // name a locale profile that outranks the application's. A page drawn
      // before anybody is known is chosen by its application alone.
      lastResort = localePolicy.defaultLocaleFor(asked.application || '',
                                                 asked.username || '');
    } catch (e) {
      // A policy that cannot be read leaves English as the last resort; a
      // page is still drawn.
      log.debug("Caught in PageLocale.translatorFor(): " +
                ((e && e.message) || e));
      lastResort = 'en';
    }
    const out = i18n.translator(PageLocale.preferences(req, asked),
                                lastResort);
    log.debug("Leaving PageLocale.translatorFor(). " + out.locale);
    return out;
  }

  /**
   * The request this code runs inside, where there is one: `audit.js`'s
   * ambient request, reached LAZILY as `passkey_policy.ts` reaches it, so
   * this module stays a leaf.
   *
   * @returns the request, or null
   */
  static ambientRequest(): any {
    log.debug("Entering PageLocale.ambientRequest().");
    let req = null;
    try {
      req = require('./audit').currentRequest() || null;
    } catch (e) {
      log.debug("Caught in PageLocale.ambientRequest(): " +
                ((e && e.message) || e));
      req = null;
    }
    log.debug("Leaving PageLocale.ambientRequest(). " +
              (req ? 'A request.' : 'None.'));
    return req;
  }

  /**
   * Builds the translator for a page drawn inside the AMBIENT request — for a
   * page builder that is not handed the request, which is most of them: they
   * are called from dozens of places, many inside a POST. The builder passes
   * what it knows (the application, `ui_locales`, the person); the request's
   * cookie and `Accept-Language` come from the ambient request.
   *
   * @param page - the application, `ui_locales` and person, where known
   * @returns the translator
   */
  static forPage(page?: PageFor): Translator {
    log.debug("Entering PageLocale.forPage().");
    const out = PageLocale.translatorFor(PageLocale.ambientRequest(), page);
    log.debug("Leaving PageLocale.forPage(). " + out.locale);
    return out;
  }

  /**
   * The path of the ambient request, where it was a GET: what the chooser
   * returns to on a page that a GET drew. A page drawn in answer to a POST
   * names the GET that redraws it instead.
   *
   * @param fallback - the path when the request was not a GET
   * @returns the path, with its query
   */
  //
  // **IT NEVER COPIES THE REQUEST'S WHOLE URL** (the integrator's finding on
  // #539 phase 3). It once answered a GET's `originalUrl`, so whatever
  // parameter a link carried — `/portal?user=<somebody else>` — was drawn
  // back into the page in the chooser's hidden field: reflection that
  // `sts_portal_sessions` exists to forbid. It answers the caller's own path
  // now, which names the parameters that page needs to be drawn again (its
  // pending id, its step id), and of the request's own parameters only those
  // the caller lists in `keep`, on a GET, that the path does not already
  // carry. Nothing a request merely adds is drawn back.
  /**
   * The path the chooser returns to: the caller's own, plus the listed
   * parameters of the current GET.
   *
   * @param path - the page's own path and the query it needs
   * @param keep - the request's parameters to carry as well, on a GET
   * @returns the path
   */
  static herePath(path: string, keep?: string[]): string {
    log.debug("Entering PageLocale.herePath().");
    let out = String(path || '/');
    const req = PageLocale.ambientRequest();
    if (keep && keep.length && req &&
        String(req.method || '').toUpperCase() === 'GET') {
      const url = new URL(out, 'http://here.invalid');
      const query = req.query || {};
      keep.forEach(function (name) {
        const value = query[name];
        if (typeof value === 'string' && !url.searchParams.has(name)) {
          url.searchParams.set(name, value);
        }
      });
      out = url.pathname + url.search;
    }
    log.debug("Leaving PageLocale.herePath().");
    return out;
  }

  /**
   * The admin console's language (#539 phase 5): the negotiation for the
   * signed-in administrator and the console's own application, its catalogs
   * as data for the browser's `WebTranslator`, and the locales the chooser
   * offers. `GET /admin-api/console` answers it as its `locale` member.
   *
   * @param req - the request
   * @param page - the console's application and the administrator
   * @returns `{ negotiated, catalogs, offered }`
   */
  static consoleData(req: any, page: PageFor) {
    log.debug("Entering PageLocale.consoleData().");
    const t = PageLocale.translatorFor(req, page);
    const out = Object.assign(i18n.catalogData(t.negotiated, 'console'),
                              { offered: i18n.offered() });
    log.debug("Leaving PageLocale.consoleData(). " + t.locale);
    return out;
  }

  /**
   * Holds a return path to a local path: one that starts with a single `/`,
   * names no scheme or host, and carries no control character or backslash.
   * Anything else is `/`.
   *
   * @param value - the path the chooser posted
   * @returns a safe local path
   */
  static safeReturn(value: unknown): string {
    log.debug("Entering PageLocale.safeReturn().");
    const out = WebLocale.safeReturn(value);
    log.debug("Leaving PageLocale.safeReturn(). " +
              (out === '/' && value !== '/' ? '/' : 'kept'));
    return out;
  }

  /**
   * The `Set-Cookie` line for the chooser's choice: a year, the whole site,
   * `SameSite=Lax`, `HttpOnly`, and `Secure` where the service is https.
   *
   * @param tag - the canonical tag chosen
   * @returns the header value
   */
  static cookieLine(tag: string): string {
    log.debug("Entering PageLocale.cookieLine().");
    log.debug("Leaving PageLocale.cookieLine().");
    return COOKIE + '=' + encodeURIComponent(tag) + '; Path=/; ' +
      'Max-Age=31536000; HttpOnly; SameSite=Lax' +
      (config.value('global.https') ? '; Secure' : '');
  }

  /**
   * The attributes of a page's `<html>` element: `lang` and `dir`.
   *
   * @param t - the page's translator
   * @returns ` lang="…" dir="…"`, escaped
   */
  static htmlAttributes(t: Translator): string {
    log.debug("Entering PageLocale.htmlAttributes().");
    log.debug("Leaving PageLocale.htmlAttributes().");
    return ' lang="' + PageLocale.esc(t.lang) + '" dir="' +
      PageLocale.esc(t.dir) + '"';
  }

  /**
   * Draws the language chooser: a form posting to the chooser endpoint, the
   * offered locales by their own names, and a submit button.
   *
   * @param t - the page's translator
   * @param base - the realm's path prefix (`''`, or `/realm/acme`). NOT put
   *   on the form's action: `app.js` adds the realm's prefix to every
   *   root-relative action in a page drawn inside a realm, so prefixing it
   *   here posted to `/realm/acme/realm/acme/authn/language`. Kept so the
   *   callers did not change; the return path carries its own prefix,
   *   because a value is not rewritten.
   * @param returnTo - the path to come back to; held to a local one
   * @returns the chooser as HTML
   */
  static chooser(t: Translator, base: string, returnTo: string): string {
    log.debug("Entering PageLocale.chooser().");
    // The markup is `web_locale.ts`'s (#570): a static surface's runtime
    // draws the same form from the same catalogs.
    const out = WebLocale.chooserHtml(t, i18n.offered(), i18n.parts(),
                                      returnTo);
    log.debug("Leaving PageLocale.chooser().");
    return out;
  }

  /**
   * The language attributes a static surface's shell carries on its
   * `<html>` (#570), for its runtime to choose the page's language in the
   * browser: the build the catalogs are versioned by, the chooser's choice
   * (the cookie is HttpOnly, so the browser cannot read it), and the locale
   * policy's default for the surface's application and, where known, its
   * person. Each value is canonical or the build number, so nothing a
   * request sent is drawn back as it arrived.
   *
   * @param req - the request for the shell
   * @param application - the surface's application, for the policy
   * @param person - the person the shell is drawn for, where the route
   *   serving it already holds one (#1238: their groups may name the
   *   profile); '' where nobody is known yet
   * @returns `[[name, value], ...]`, for `ShellDocument.document()`
   */
  static shellAttributes(req: any, application: string,
                         person?: string): Array<[string, string]> {
    log.debug("Entering PageLocale.shellAttributes().");
    let lastResort = 'en';
    try {
      lastResort = localePolicy.defaultLocaleFor(application || '',
                                                 person || '');
    } catch (e) {
      // A policy that cannot be read leaves English as the last resort, as
      // `translatorFor()` does.
      log.debug("Caught in PageLocale.shellAttributes(): " +
                ((e && e.message) || e));
      lastResort = 'en';
    }
    const out: Array<[string, string]> = [
      ['data-sts-version', String(version.load().version || '')],
      ['data-sts-lang', i18n.canonical(PageLocale.cookieOf(req, COOKIE))],
      ['data-sts-locale-default', i18n.canonical(lastResort) || 'en']
    ];
    log.debug("Leaving PageLocale.shellAttributes().");
    return out;
  }

  // Escaping, as `Html.esc()` does. Per value drawn, so no Entering/Leaving
  // pair — the hot-path exception the code style allows, stated.
  private static esc(value: unknown): string {
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
}

export = PageLocale;
