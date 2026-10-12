// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_locale.ts
//
// ---------------------------------------------------------------------------
// WHICH LANGUAGE A PAGE IS DRAWN IN, AS PURE FUNCTIONS — FOR THE SERVER AND
// FOR A BROWSER (#570, 2026-10-12).
//
// rcbj's decision 3 on #570: THE BROWSER TRANSLATES. A static surface's
// runtime picks the locale itself, in today's order, from the catalogs the
// server publishes as static JSON (`common/public_assets.ts`), and the APIs
// it draws from stay language-free. Today's order and today's negotiation
// were `common/page_locale.ts`'s and `common/i18n.ts`'s, which are server
// modules (a logger, `fs`, the directory). Two copies — one the server
// negotiates with and one a browser does — would be two answers to "which
// language is this page in", and the first sign of the difference would be
// a sign-in screen that changes language when it moves into the browser. So
// the part that knows nothing of a request or a file moved HERE, on a `web_`
// module's terms, and both server modules hand their work to it:
//
//   * TAGS: `canonical()` (RFC 5646 well-formedness and canonical case,
//     `Intl.getCanonicalLocales()`), `partsOf()` (language, script, region
//     — maximised by CLDR's likely subtags — the region a tag NAMES, and the
//     text direction), `acceptLanguage()` (RFC 9110 section 12.5.4, and an
//     entry's `preferredLanguage`, RFC 2798 section 2.7, which has the same
//     syntax) and `uiLocales()` (OpenID Connect Core 1.0 section 3.1.2.1).
//   * THE ORDER (`preferences()`), rcbj's on #539: `ui_locales`; the person's
//     own `preferredLanguage` unless the locale policy POPULATED it; the
//     chooser's choice; `Accept-Language`; a populated `preferredLanguage`;
//     and, as the last resort a caller passes to `negotiate()`, the locale
//     policy's default for the application. The server reads the inputs off
//     the request (`PageLocale.preferences()`); a browser reads them off its
//     shell, its query and `navigator.languages` (`web_i18n.ts`).
//   * NEGOTIATION (`chainFor()`, `negotiate()`): RFC 4647 lookup with the
//     script made explicit, against a list of catalogs' parts — the server's
//     loaded index or the browser's fetched `catalogs.json`, the same file.
//   * THE CHOOSER'S MARKUP (`chooserHtml()`) and its return path
//     (`safeReturn()`), so a chooser drawn by the server and one drawn by a
//     runtime are the same form to the byte.
//
// `common/i18n.ts`'s header argues the negotiation and `page_locale.ts`'s the
// order; neither argument moved, only the code.
//
// A `web_` MODULE, on `admin-ui/web_kit.ts`'s terms: it requires nothing,
// logs nothing (it runs in a browser, which the code style exempts, and the
// server wrappers keep their Entering/Leaving lines), and is bundled for a
// browser by `build-typescript.sh`. Its catches answer the value a caller
// falls back to and say why beside it, which is what a `web_` module does
// with an exception: there is no log in a browser to send it to.
// ---------------------------------------------------------------------------

/**
 * A tag taken apart.
 */
interface TagParts {
  tag: string;
  language: string;
  script: string;
  region: string;
  explicitRegion: string;
  direction: 'ltr' | 'rtl';
}

/**
 * A negotiation's answer: the locale, the catalogs to read in order, the
 * first of them, the text direction, and whether a catalog answered.
 */
interface Negotiated {
  locale: string;
  chain: string[];
  catalog: string;
  direction: 'ltr' | 'rtl';
  matched: boolean;
}

/**
 * What a page's language is chosen from, in the order it is asked. Each is
 * optional; a missing one is passed over.
 */
interface PreferenceInputs {
  // OpenID Connect's `ui_locales`, from the request in progress.
  uiLocales?: string;
  // The person's own `preferredLanguage`, and whether the locale policy
  // populated it (then it is the policy's choice and ranks after 4).
  own?: { value: string; populated: boolean };
  // The language chooser's choice (the `sts_lang` cookie's value).
  chooser?: string;
  // `Accept-Language`, or a browser's `navigator.languages` joined by commas.
  acceptLanguage?: string;
}

/**
 * One locale the chooser offers.
 */
interface OfferedLocale {
  tag: string;
  name: string;
}

/**
 * What the chooser draws its words with: a translator's `html()`, its locale
 * and its negotiation.
 */
interface ChooserTranslator {
  locale: string;
  negotiated: Negotiated;
  html(key: string, params?: Record<string, unknown>): string;
}

/**
 * The catalog every chain ends in.
 */
const SOURCE = 'en';

/**
 * The longest return path the chooser keeps.
 */
const MAX_RETURN = 2048;

/**
 * The chooser endpoint (`authn/authn.ts`'s `POST /authn/language`).
 */
const CHOOSER_ACTION = '/authn/language';

/**
 * Tags, the order of preferences, negotiation and the chooser. A static
 * utility class; it holds no state.
 */
class WebLocale {
  /**
   * The catalog every chain ends in.
   */
  static readonly SOURCE = SOURCE;
  /**
   * The chooser endpoint the chooser's form posts to.
   */
  static readonly CHOOSER_ACTION = CHOOSER_ACTION;

  // -------------------------------------------------------------------------
  // TAGS.
  // -------------------------------------------------------------------------
  /**
   * Canonicalises a language tag, or answers '' for one that is not
   * well-formed (RFC 5646). `tl` becomes `fil`, `iw` becomes `he`, and case
   * is normalised.
   *
   * @param tag - the tag as given
   * @returns the canonical tag, or ''
   */
  static canonical(tag: unknown): string {
    const text = String(tag == null ? '' : tag).trim();
    if (!text || text.length > 64 || text === '*') {
      return '';
    }
    try {
      return Intl.getCanonicalLocales(text)[0] || '';
    } catch (e) {
      // Not a language tag: '' is the answer a caller skips.
      return '';
    }
  }

  /**
   * Takes a tag apart: language, script and region, the region it NAMES, and
   * its text direction. Throws on a tag `Intl.Locale` refuses.
   *
   * @param tag - a canonical tag
   * @returns the parts
   */
  static partsOf(tag: string): TagParts {
    const given = new Intl.Locale(tag);
    let full: Intl.Locale = given;
    try {
      full = given.maximize();
    } catch (e) {
      // No likely subtags for it: the tag as given is what is compared.
      full = given;
    }
    const info = (full as any).textInfo ||
      (typeof (full as any).getTextInfo === 'function'
        ? (full as any).getTextInfo() : null);
    return {
      tag: tag,
      language: full.language,
      script: full.script || '',
      region: full.region || '',
      explicitRegion: given.region || '',
      direction: info && info.direction === 'rtl' ? 'rtl' : 'ltr'
    };
  }

  /**
   * Reads an `Accept-Language` value — or a `preferredLanguage`, which has
   * the same syntax — into tags, best first. A `q=0` tag and the wildcard
   * are left out; a tag that is not well-formed is skipped.
   *
   * @param value - the header or attribute value
   * @returns canonical tags, best first
   */
  static acceptLanguage(value: unknown): string[] {
    const rows: { tag: string; q: number; at: number }[] = [];
    String(value == null ? '' : value).split(',').slice(0, 32)
      .forEach(function (part, at) {
        const bits = part.trim().split(';');
        const tag = WebLocale.canonical(bits[0]);
        if (!tag) {
          return;
        }
        let q = 1;
        bits.slice(1).forEach(function (param) {
          const m = /^\s*q\s*=\s*([0-9.]+)\s*$/i.exec(param);
          if (m) {
            q = Number(m[1]);
          }
        });
        if (!(q > 0)) {
          return;
        }
        rows.push({ tag: tag, q: Math.min(q, 1), at: at });
      });
    rows.sort(function (a, b) {
      return b.q - a.q || a.at - b.at;
    });
    const out: string[] = [];
    rows.forEach(function (row) {
      if (out.indexOf(row.tag) < 0) {
        out.push(row.tag);
      }
    });
    return out;
  }

  /**
   * Reads an OpenID Connect `ui_locales` value: a space-separated list of
   * tags, best first.
   *
   * @param value - the parameter
   * @returns canonical tags, best first
   */
  static uiLocales(value: unknown): string[] {
    const out: string[] = [];
    String(value == null ? '' : value).split(/\s+/).slice(0, 32)
      .forEach(function (part) {
        const tag = WebLocale.canonical(part);
        if (tag && out.indexOf(tag) < 0) {
          out.push(tag);
        }
      });
    return out;
  }

  // -------------------------------------------------------------------------
  // THE ORDER (#539).
  // -------------------------------------------------------------------------
  /**
   * Lists a page's language preferences, best first, in #539's order —
   * everything but the locale policy's default, which is the last resort a
   * caller hands `negotiate()`.
   *
   * @param input - what the page's language is chosen from
   * @returns canonical tags, best first, each once
   */
  static preferences(input: PreferenceInputs): string[] {
    const asked = input || {};
    const out: string[] = [];
    const add = function (tags: string[]): void {
      tags.forEach(function (tag) {
        if (tag && out.indexOf(tag) < 0) {
          out.push(tag);
        }
      });
    };
    add(WebLocale.uiLocales(asked.uiLocales || ''));
    // THE PERSON'S OWN LANGUAGE — but one the locale policy POPULATED when
    // their entry was made, and nobody has changed since, is the policy's
    // choice rather than theirs (rcbj on #539), so it ranks after the
    // browser's, just ahead of the policy's own default.
    const own = asked.own || { value: '', populated: false };
    if (own.value && !own.populated) {
      add(WebLocale.acceptLanguage(own.value));
    }
    add([WebLocale.canonical(asked.chooser || '')]);
    add(WebLocale.acceptLanguage(asked.acceptLanguage || ''));
    if (own.value && own.populated) {
      add(WebLocale.acceptLanguage(own.value));
    }
    return out;
  }

  // -------------------------------------------------------------------------
  // NEGOTIATION.
  // -------------------------------------------------------------------------
  /**
   * Returns the catalogs that answer one tag, most specific first and English
   * last: a regional overlay naming the tag's region, then the base catalog
   * of its language and script.
   *
   * @param tag - a canonical tag
   * @param catalogs - every catalog's parts, in `catalogs.json`'s order
   * @returns the chain, which ends in English; `matched` says whether
   *   anything before English answered, or English itself did
   */
  static chainFor(tag: string, catalogs: TagParts[]): {
    chain: string[]; matched: boolean; direction: 'ltr' | 'rtl'; } {
    let want: TagParts;
    try {
      want = WebLocale.partsOf(tag);
    } catch (e) {
      // Not a tag `Intl.Locale` takes: nothing answers it.
      return { chain: [SOURCE], matched: false, direction: 'ltr' };
    }
    const sameLanguage = catalogs.filter(function (has) {
      return has.language === want.language && has.script === want.script;
    });
    const regional = sameLanguage.filter(function (has) {
      return has.explicitRegion && has.explicitRegion === want.region;
    });
    const bases = sameLanguage.filter(function (has) {
      return !has.explicitRegion;
    });
    const chain: string[] = [];
    regional.concat(bases).forEach(function (has) {
      if (chain.indexOf(has.tag) < 0) {
        chain.push(has.tag);
      }
    });
    const matched = chain.length > 0;
    if (chain.indexOf(SOURCE) < 0) {
      chain.push(SOURCE);
    }
    return { chain: chain, matched: matched, direction: want.direction };
  }

  /**
   * Negotiates a list of preferences, best first, against the catalogs: the
   * first one a catalog answers wins; when none does, the last resort does,
   * and English when that answers nothing either.
   *
   * @param preferences - tags, best first
   * @param lastResort - the tag to use when no preference is answered (the
   *   locale policy's default)
   * @param catalogs - every catalog's parts, in `catalogs.json`'s order
   * @returns the locale, its catalog chain and its direction
   */
  static negotiate(preferences: string[], lastResort: string | undefined,
                   catalogs: TagParts[]): Negotiated {
    const tried = preferences.concat(lastResort ? [lastResort] : []);
    for (const raw of tried) {
      const tag = WebLocale.canonical(raw);
      if (!tag) {
        continue;
      }
      const found = WebLocale.chainFor(tag, catalogs);
      if (found.matched) {
        return { locale: tag, chain: found.chain, catalog: found.chain[0],
                 direction: found.direction, matched: true };
      }
    }
    return { locale: SOURCE, chain: [SOURCE], catalog: SOURCE,
             direction: 'ltr', matched: false };
  }

  /**
   * Takes every catalog of a `catalogs.json` index apart, skipping one
   * `Intl.Locale` refuses (the server's loader logs that; a browser cannot).
   *
   * @param catalogs - the index's `catalogs`
   * @returns their parts, in order
   */
  static catalogParts(catalogs: { tag: string }[]): TagParts[] {
    const out: TagParts[] = [];
    (catalogs || []).forEach(function (info) {
      try {
        out.push(WebLocale.partsOf(String(info.tag)));
      } catch (e) {
        // A catalog row whose tag is not a locale answers nothing.
        return;
      }
    });
    return out;
  }

  // -------------------------------------------------------------------------
  // THE CHOOSER.
  // -------------------------------------------------------------------------
  /**
   * Holds a return path to a local path: one that starts with a single `/`,
   * names no scheme or host, and carries no control character or backslash.
   * Anything else is `/`.
   *
   * @param value - the path the chooser posted
   * @returns a safe local path
   */
  static safeReturn(value: unknown): string {
    const text = String(value == null ? '' : value);
    const ok = text.length > 0 && text.length <= MAX_RETURN &&
      text.charAt(0) === '/' && text.charAt(1) !== '/' &&
      !/[\\\u0000-\u001f\u007f]/.test(text) &&
      !/^\/[^/?#]*:/.test(text);
    return ok ? text : '/';
  }

  /**
   * Draws the language chooser: a form posting to the chooser endpoint, the
   * offered locales by their own names, and a submit button. A static
   * surface's runtime sends the same form as a request
   * (`WebI18n.wireChooser()`) and draws the page again; a server-drawn page
   * posts it.
   *
   * @param t - the page's translator
   * @param offered - the locales the chooser offers, each with its endonym
   * @param catalogs - every catalog's parts, for which offered locale the
   *   page is read in
   * @param returnTo - the path to come back to; held to a local one
   * @returns the chooser as HTML
   */
  static chooserHtml(t: ChooserTranslator, offered: OfferedLocale[],
                     catalogs: TagParts[], returnTo: string): string {
    const here = WebLocale.safeReturn(returnTo);
    const current = t.locale.toLowerCase();
    // The current locale is selected; where it is not one of the offered
    // ones (`es-AR`, read from a browser), the offered locale it is read in
    // is, by its catalog's language.
    const exact = offered.filter(function (one) {
      return one.tag.toLowerCase() === current;
    })[0];
    const sameCatalog = offered.filter(function (one) {
      return WebLocale.negotiate([one.tag], undefined, catalogs).catalog ===
        t.negotiated.catalog;
    })[0];
    const selected = (exact || sameCatalog || offered[0] || { tag: '' }).tag;
    const drawn = offered.map(function (one) {
      return '<option value="' + WebLocale.esc(one.tag) + '" lang="' +
        WebLocale.esc(one.tag) + '"' +
        (one.tag === selected ? ' selected' : '') + '>' +
        WebLocale.esc(one.name) + '</option>';
    }).join('');
    return '<form class="language-chooser" method="post" action="' +
      WebLocale.esc(CHOOSER_ACTION) + '">' +
      '<input type="hidden" name="return" value="' + WebLocale.esc(here) +
      '"><label for="sts-language">' + t.html('chooser.label') +
      '</label> <select id="sts-language" name="lang">' + drawn +
      '</select> <button type="submit">' + t.html('chooser.change') +
      '</button></form>';
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

export = WebLocale;
