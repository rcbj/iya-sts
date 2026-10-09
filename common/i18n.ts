// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: i18n.ts
//
// ---------------------------------------------------------------------------
// THE LANGUAGES A PAGE MAY BE DRAWN IN (#539, 2026-10-09).
//
// rcbj: "I want to add multi-lingual support to the admin portal,
// authentication service, logout service, and user portal. It should be able
// to handle any locale + language." This module is the half of that which
// knows nothing about a request: the CATALOGS, the NEGOTIATION of a list of
// BCP 47 language tags against them, and the FORMATTING of one message.
// `common/page_locale.ts` is the other half — which tags a request offers,
// in rcbj's order — and it requires this; nothing here requires it back.
//
// ---------------------------------------------------------------------------
// THE CATALOGS ARE DATA, IN `common/locales/`.
//
//   common/locales/catalogs.json      which catalogs exist, each one's
//                                     endonym, its STATUS, and the locales the
//                                     language chooser offers
//   common/locales/<ns>/<tag>.json    one NAMESPACE's messages in one catalog:
//                                     a flat object, key → message
//
// A namespace is a surface (`authn`, `logout`, `portal`, `chooser`, ...), so
// two surfaces are translated in two files and never collide on a key. A
// catalog file may hold a SUBSET of the keys: a key it lacks is looked up
// along the fallback chain, and English — the SOURCE catalog, where every key
// exists — is the end of every chain. `tests/i18n_catalogs.js` holds that:
// every key of every catalog exists in English, and every message carries
// exactly the placeholders and markup its English one does.
//
// Adding a language is adding files and a row in `catalogs.json`; no code
// changes. A REGIONAL catalog (`fr-CA`) is an OVERLAY on its base (`fr`) and
// holds only the messages whose wording differs there — "courriel" for
// "e-mail" — so a region costs what is different about it and no more.
//
// rcbj's decision 2 on #539: every catalog but English was written by Claude
// and says so — `status: "machine-unreviewed"` in `catalogs.json` — and the
// console shows the status, so a native reviewer can find what needs reading
// and mark it `reviewed`.
//
// ---------------------------------------------------------------------------
// NEGOTIATION IS RFC 4647 LOOKUP, WITH THE SCRIPT MADE EXPLICIT.
//
// A tag is canonicalised by `Intl.getCanonicalLocales()` (which turns `tl`
// into `fil` and `iw` into `he`) and MAXIMISED by `Intl.Locale.maximize()`
// (Unicode CLDR's likely subtags), so `zh-TW` is `zh-Hant-TW`, `zh` is
// `zh-Hans-CN` and `fr` is `fr-Latn-FR`. A catalog matches a preference when
// its language and script are the preference's, and its region — where the
// catalog's own tag NAMES one — is the preference's too. So `zh-HK` never
// falls through to the Simplified catalog, which a plain prefix match
// (`zh-HK` → `zh`) would do, and `fr` (France) does not get Canadian wording.
//
// The FIRST preference that any non-English catalog — or English itself —
// answers wins; a preference no catalog answers is skipped rather than
// sending the reader to English while a later preference would have been
// understood. The locale handed to `Intl` for dates and numbers is the
// PREFERENCE, not the catalog: `es-PA` reads the Spanish catalog and formats
// a date the way Panama does, which is the "any locale" half of the request.
//
// TEXT DIRECTION comes from the maximised tag's `textInfo`, so a right-to-left
// catalog added later is drawn `dir="rtl"` with nothing here changed.
//
// ---------------------------------------------------------------------------
// A MESSAGE is ICU MessageFormat's common subset, implemented here on node's
// own `Intl` rather than taken from a library:
//
//   {name}                                    a parameter
//   {count, plural, one {# key} other {# keys}}   CLDR plural categories
//                                             (Intl.PluralRules), `=0`
//                                             exact matches, `#` the number
//   {kind, select, passkey {...} other {...}}    a choice by value
//
// A literal brace cannot be written; no message needs one, and the catalog
// test refuses one rather than this parser guessing. A message may carry a
// small set of inline elements — <strong>, <em>, <code>, <br> — and
// `html()` passes them through while ESCAPING EVERY PARAMETER; `text()`
// strips them. The catalogs are this repository's own files, so their markup
// is trusted the way a page's literal markup is; a parameter never is.
//
// ---------------------------------------------------------------------------
// rcbj's decision 6 on #539: ERRORS STAY ENGLISH. Nothing here decides that —
// a refusal is simply never looked up in a catalog — but it is why the
// namespaces hold titles, labels, buttons, instructions and success messages
// and no refusal text.
//
// A LIBRARY (rule 3) AND A LEAF: `helpers` (the logger), `error_codes`, the
// instance slot, `fs` and `path`. It registers nothing.
// ---------------------------------------------------------------------------

import fs = require('fs');
import path = require('path');
import helpers = require('./helpers');
import errorCodes = require('./error_codes');
import InstanceSlot = require('./instance_slot');

const { log } = helpers;

/**
 * One catalog, as `catalogs.json` describes it.
 */
interface CatalogInfo {
  tag: string;
  name: string;
  english: string;
  status: 'source' | 'machine-unreviewed' | 'reviewed';
  base?: string;
}

/**
 * One locale the language chooser offers.
 */
interface OfferedLocale {
  tag: string;
  name: string;
}

/**
 * What `catalogs.json` holds.
 */
interface CatalogIndex {
  source: string;
  catalogs: CatalogInfo[];
  offered: OfferedLocale[];
}

/**
 * A tag taken apart: its language, script, and the region it names or
 * implies.
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
 * The answer of a negotiation: the preference that won, the catalogs to read
 * in order, and the text direction.
 */
interface Negotiated {
  locale: string;
  chain: string[];
  catalog: string;
  direction: 'ltr' | 'rtl';
  matched: boolean;
}

// One node of a parsed message.
type MessageNode = string | {
  arg: string;
  kind: 'simple' | 'plural' | 'select';
  options?: Record<string, MessageNode[]>;
} | { hash: true };

/**
 * The parameters of a message: values by name.
 */
type MessageParams = Record<string, unknown>;

/**
 * The dependencies the instance is built from.
 */
interface I18nDeps {
  log: typeof helpers.log;
  errorCodes: { tag(code: string): string };
  directory: string;
}

/**
 * The inline elements a message may carry, by name. Anything else is refused
 * by the catalog test and stripped by `text()`.
 */
const INLINE_ELEMENTS = ['strong', 'em', 'code', 'br'];

/**
 * The catalog every chain ends in, and in which every key exists.
 */
const SOURCE = 'en';

/**
 * One translator: a negotiated locale and the catalogs it reads, with the
 * three ways of turning a key into words.
 */
class Translator {
  /**
   * Builds a translator over a negotiation.
   *
   * @param owner - the catalogs
   * @param negotiated - the locale, its catalog chain and its direction
   */
  constructor(private readonly owner: I18n,
              readonly negotiated: Negotiated) {
    log.debug("Entering Translator.constructor().");
    log.debug("Leaving Translator.constructor(). " + negotiated.locale);
  }

  /**
   * The locale `Intl` formats for: the preference that won, such as `es-PA`.
   */
  get locale(): string {
    return this.negotiated.locale;
  }

  /**
   * The value of a page's `lang` attribute: the locale, which says more than
   * the catalog read for it.
   */
  get lang(): string {
    return this.negotiated.locale;
  }

  /**
   * The value of a page's `dir` attribute.
   */
  get dir(): 'ltr' | 'rtl' {
    return this.negotiated.direction;
  }

  // Called for every string on every page, so no Entering/Leaving pair —
  // the hot-path exception the code style allows, stated as it requires.
  /**
   * Formats a message as HTML: its own inline markup kept, every parameter
   * escaped.
   *
   * @param key - `namespace.key`
   * @param params - the parameters
   * @returns the message as HTML
   */
  html(key: string, params?: MessageParams): string {
    return this.owner.format(this.negotiated, key, params || {}, true);
  }

  // The hot-path exception, as html() above.
  /**
   * Formats a message as plain text, for an attribute value, a title or a
   * header: its markup stripped and nothing escaped (the caller escapes).
   *
   * @param key - `namespace.key`
   * @param params - the parameters
   * @returns the message as text
   */
  text(key: string, params?: MessageParams): string {
    return this.owner.format(this.negotiated, key, params || {}, false);
  }

  /**
   * Formats a date and time for this locale.
   *
   * @param when - the instant
   * @param options - `Intl.DateTimeFormat` options; date and time, medium,
   * when omitted
   * @returns the text
   */
  date(when: Date | number | string,
       options?: Intl.DateTimeFormatOptions): string {
    log.debug("Entering Translator.date().");
    const value = when instanceof Date ? when : new Date(when);
    let out: string;
    try {
      // UTC, AND SAID, unless asked otherwise: this service's pages give
      // times in UTC, and a time in the server's own zone with no zone named
      // is a time nobody can read correctly.
      const fallback: Intl.DateTimeFormatOptions =
        { dateStyle: 'medium', timeStyle: 'long' };
      const asked: Intl.DateTimeFormatOptions =
        Object.assign({ timeZone: 'UTC' }, options || fallback);
      out = new Intl.DateTimeFormat(this.locale, asked).format(value);
    } catch (e) {
      log.debug("Caught in Translator.date(): " +
                ((e && e.message) || e));
      out = isNaN(value.getTime()) ? String(when) : value.toISOString();
    }
    log.debug("Leaving Translator.date().");
    return out;
  }

  /**
   * Formats a number for this locale.
   *
   * @param value - the number
   * @param options - `Intl.NumberFormat` options
   * @returns the text
   */
  number(value: number, options?: Intl.NumberFormatOptions): string {
    log.debug("Entering Translator.number().");
    let out: string;
    try {
      out = new Intl.NumberFormat(this.locale, options).format(value);
    } catch (e) {
      log.debug("Caught in Translator.number(): " +
                ((e && e.message) || e));
      out = String(value);
    }
    log.debug("Leaving Translator.number().");
    return out;
  }
}

/**
 * The catalogs, the negotiation of a list of language tags against them, and
 * the formatting of one message.
 */
class I18n {
  /**
   * The catalog every chain ends in.
   */
  static readonly SOURCE = SOURCE;
  /**
   * The inline elements a message may carry.
   */
  static readonly INLINE_ELEMENTS = INLINE_ELEMENTS;

  private index: CatalogIndex | null = null;
  // namespace → catalog tag → key → message
  private messages: Record<string, Record<string, Record<string, string>>> =
    {};
  // `namespace.key` + NUL + catalog → parsed message
  private parsed = new Map<string, MessageNode[]>();
  private catalogParts: Record<string, TagParts> = {};
  private loadProblems: string[] = [];

  /**
   * Builds the catalogs; nothing is read until first asked.
   *
   * @param deps - the logger, the error codes and the catalog directory
   */
  constructor(private readonly deps: I18nDeps) {
    deps.log.debug("Entering I18n.constructor().");
    deps.log.debug("Leaving I18n.constructor(). " + deps.directory);
  }

  /**
   * Returns the dependencies the default instance is built from.
   *
   * @returns the service's own modules and `common/locales`
   */
  static defaultDeps(): I18nDeps {
    log.debug("Entering I18n.defaultDeps().");
    log.debug("Leaving I18n.defaultDeps().");
    return { log: log, errorCodes: errorCodes,
             directory: path.join(__dirname, 'locales') };
  }

  // -------------------------------------------------------------------------
  // LOADING. Read once, synchronously, on first use: the files are this
  // repository's own and small, and a page cannot be drawn without them. A
  // file that cannot be read or parsed costs its messages, never the start:
  // the chain falls through to English, and the problem is logged under its
  // code and listed for the console.
  // -------------------------------------------------------------------------
  private load(): void {
    const { log, errorCodes, directory } = this.deps;
    if (this.index) {
      return;
    }
    log.debug("Entering I18n.load(). " + directory);
    let index: CatalogIndex;
    try {
      index = JSON.parse(fs.readFileSync(path.join(directory,
                                                   'catalogs.json'), 'utf8'));
    } catch (e) {
      log.debug("Caught in I18n.load(): " + ((e && e.message) || e));
      // Without the index there is English, from the source files, and
      // nothing else: a page is still drawn.
      log.error(errorCodes.tag('STS-I18N-0001') + 'i18n: ' +
                'common/locales/catalogs.json could not be read (' +
                ((e && e.message) || e) + '), so every page is drawn in ' +
                'English.');
      this.loadProblems.push('catalogs.json could not be read: ' +
                             ((e && e.message) || e));
      index = { source: SOURCE, offered: [],
                catalogs: [{ tag: SOURCE, name: 'English',
                             english: 'English', status: 'source' }] };
    }
    this.index = index;
    index.catalogs.forEach((info) => {
      this.catalogParts[info.tag] = I18n.partsOf(info.tag);
    });
    let names: string[] = [];
    try {
      names = fs.readdirSync(directory, { withFileTypes: true })
        .filter(function (entry) {
          return entry.isDirectory();
        }).map(function (entry) {
          return entry.name;
        });
    } catch (e) {
      log.debug("Caught in I18n.load(): " + ((e && e.message) || e));
      names = [];
    }
    names.forEach((ns) => {
      this.messages[ns] = {};
      index.catalogs.forEach((info) => {
        const file = path.join(directory, ns, info.tag + '.json');
        if (!fs.existsSync(file)) {
          return;
        }
        try {
          const body = JSON.parse(fs.readFileSync(file, 'utf8'));
          const flat: Record<string, string> = {};
          Object.keys(body).forEach(function (key) {
            if (typeof body[key] === 'string') {
              flat[key] = body[key];
            }
          });
          this.messages[ns][info.tag] = flat;
        } catch (e) {
          log.debug("Caught in I18n.load(): " + ((e && e.message) || e));
          log.error(errorCodes.tag('STS-I18N-0001') + 'i18n: ' + ns + '/' +
                    info.tag + '.json could not be read (' +
                    ((e && e.message) || e) + '); its messages fall back ' +
                    'along the chain to English.');
          this.loadProblems.push(ns + '/' + info.tag + '.json could not be ' +
                                 'read: ' + ((e && e.message) || e));
        }
      });
    });
    log.debug("Leaving I18n.load(). " + index.catalogs.length +
              " catalog(s), " + names.length + " namespace(s).");
  }

  /**
   * Lists the catalogs: each one's tag, endonym, English name, status and
   * the base it overlays.
   *
   * @returns the catalogs, in `catalogs.json`'s order
   */
  catalogs(): CatalogInfo[] {
    log.debug("Entering I18n.catalogs().");
    this.load();
    log.debug("Leaving I18n.catalogs().");
    return this.index.catalogs.map(function (info) {
      return Object.assign({}, info);
    });
  }

  /**
   * Lists the locales the language chooser offers, each with its endonym.
   *
   * @returns the offered locales
   */
  offered(): OfferedLocale[] {
    log.debug("Entering I18n.offered().");
    this.load();
    log.debug("Leaving I18n.offered().");
    return this.index.offered.map(function (one) {
      return Object.assign({}, one);
    });
  }

  /**
   * Lists the namespaces: the directories under `common/locales`.
   *
   * @returns the namespace names
   */
  namespaces(): string[] {
    log.debug("Entering I18n.namespaces().");
    this.load();
    log.debug("Leaving I18n.namespaces().");
    return Object.keys(this.messages).sort();
  }

  /**
   * Returns one namespace's messages in one catalog, as stored, for the
   * catalog test and the console's own catalog.
   *
   * @param ns - the namespace
   * @param tag - the catalog
   * @returns the messages, key → message; empty when there are none
   */
  messagesOf(ns: string, tag: string): Record<string, string> {
    log.debug("Entering I18n.messagesOf(). " + ns + '/' + tag);
    this.load();
    const found = (this.messages[ns] || {})[tag] || {};
    log.debug("Leaving I18n.messagesOf(). " + Object.keys(found).length);
    return Object.assign({}, found);
  }

  /**
   * Lists what went wrong while the catalogs were read.
   *
   * @returns the problems, as sentences
   */
  problems(): string[] {
    log.debug("Entering I18n.problems().");
    this.load();
    log.debug("Leaving I18n.problems().");
    return this.loadProblems.slice();
  }

  // -------------------------------------------------------------------------
  // TAGS.
  // -------------------------------------------------------------------------
  /**
   * Canonicalises a language tag, or answers '' for one that is not
   * well-formed (RFC 5646).
   *
   * `tl` becomes `fil`, `iw` becomes `he`, and case is normalised.
   *
   * @param tag - the tag as given
   * @returns the canonical tag, or ''
   */
  static canonical(tag: unknown): string {
    log.debug("Entering I18n.canonical().");
    const text = String(tag == null ? '' : tag).trim();
    if (!text || text.length > 64 || text === '*') {
      log.debug("Leaving I18n.canonical(). Empty or a wildcard.");
      return '';
    }
    try {
      const out = Intl.getCanonicalLocales(text)[0] || '';
      log.debug("Leaving I18n.canonical(). " + out);
      return out;
    } catch (e) {
      log.debug("Caught in I18n.canonical(): " + ((e && e.message) || e));
      log.debug("Leaving I18n.canonical(). Not a language tag.");
      return '';
    }
  }

  /**
   * Takes a tag apart: language, script and region, the region it NAMES, and
   * its text direction.
   *
   * @param tag - a canonical tag
   * @returns the parts
   */
  static partsOf(tag: string): TagParts {
    log.debug("Entering I18n.partsOf(). " + tag);
    const given = new Intl.Locale(tag);
    let full: Intl.Locale = given;
    try {
      full = given.maximize();
    } catch (e) {
      log.debug("Caught in I18n.partsOf(): " + ((e && e.message) || e));
      full = given;
    }
    const info = (full as any).textInfo ||
      (typeof (full as any).getTextInfo === 'function'
        ? (full as any).getTextInfo() : null);
    const out: TagParts = {
      tag: tag,
      language: full.language,
      script: full.script || '',
      region: full.region || '',
      explicitRegion: given.region || '',
      direction: info && info.direction === 'rtl' ? 'rtl' : 'ltr'
    };
    log.debug("Leaving I18n.partsOf(). " + full.toString());
    return out;
  }

  /**
   * Reads an `Accept-Language` value (RFC 9110 section 12.5.4) — or an
   * entry's `preferredLanguage`, which RFC 2798 section 2.7 says has the same
   * syntax — into tags, best first. A `q=0` tag and the wildcard are left out;
   * a tag that is not well-formed is skipped.
   *
   * @param value - the header or attribute value
   * @returns canonical tags, best first
   */
  static acceptLanguage(value: unknown): string[] {
    log.debug("Entering I18n.acceptLanguage().");
    const rows: { tag: string; q: number; at: number }[] = [];
    String(value == null ? '' : value).split(',').slice(0, 32)
      .forEach(function (part, at) {
        const bits = part.trim().split(';');
        const tag = I18n.canonical(bits[0]);
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
    log.debug("Leaving I18n.acceptLanguage(). " + out.join(' '));
    return out;
  }

  /**
   * Reads an OpenID Connect `ui_locales` value (Core 1.0 section 3.1.2.1): a
   * space-separated list of tags, best first.
   *
   * @param value - the parameter
   * @returns canonical tags, best first
   */
  static uiLocales(value: unknown): string[] {
    log.debug("Entering I18n.uiLocales().");
    const out: string[] = [];
    String(value == null ? '' : value).split(/\s+/).slice(0, 32)
      .forEach(function (part) {
        const tag = I18n.canonical(part);
        if (tag && out.indexOf(tag) < 0) {
          out.push(tag);
        }
      });
    log.debug("Leaving I18n.uiLocales(). " + out.join(' '));
    return out;
  }

  // -------------------------------------------------------------------------
  // NEGOTIATION.
  // -------------------------------------------------------------------------
  /**
   * Returns the catalogs that answer one tag, most specific first and English
   * last: a regional overlay naming the tag's region, then the base catalog of
   * its language and script.
   *
   * @param tag - a canonical tag
   * @returns the chain, which ends in English; `matched` says whether
   * anything before English answered, or English itself did
   */
  chainFor(tag: string): { chain: string[]; matched: boolean;
                           direction: 'ltr' | 'rtl' } {
    log.debug("Entering I18n.chainFor(). " + tag);
    this.load();
    let want: TagParts;
    try {
      want = I18n.partsOf(tag);
    } catch (e) {
      log.debug("Caught in I18n.chainFor(): " + ((e && e.message) || e));
      log.debug("Leaving I18n.chainFor(). Not a tag.");
      return { chain: [SOURCE], matched: false, direction: 'ltr' };
    }
    const sameLanguage = this.index.catalogs.filter((info) => {
      const has = this.catalogParts[info.tag];
      return has.language === want.language && has.script === want.script;
    });
    const regional = sameLanguage.filter((info) => {
      const has = this.catalogParts[info.tag];
      return has.explicitRegion && has.explicitRegion === want.region;
    });
    const bases = sameLanguage.filter((info) => {
      return !this.catalogParts[info.tag].explicitRegion;
    });
    const chain: string[] = [];
    regional.concat(bases).forEach(function (info) {
      if (chain.indexOf(info.tag) < 0) {
        chain.push(info.tag);
      }
    });
    const matched = chain.length > 0;
    if (chain.indexOf(SOURCE) < 0) {
      chain.push(SOURCE);
    }
    log.debug("Leaving I18n.chainFor(). " + chain.join(' > '));
    return { chain: chain, matched: matched, direction: want.direction };
  }

  /**
   * Negotiates a list of preferences, best first, against the catalogs: the
   * first one a catalog answers wins; when none does, the last resort does,
   * and English when that answers nothing either.
   *
   * @param preferences - canonical tags, best first
   * @param lastResort - the tag to use when no preference is answered (the
   * locale policy's default)
   * @returns the locale, its catalog chain and its direction
   */
  negotiate(preferences: string[], lastResort?: string): Negotiated {
    log.debug("Entering I18n.negotiate(). " + preferences.join(' '));
    const tried = preferences.concat(lastResort ? [lastResort] : []);
    for (const raw of tried) {
      const tag = I18n.canonical(raw);
      if (!tag) {
        continue;
      }
      const found = this.chainFor(tag);
      if (found.matched) {
        log.debug("Leaving I18n.negotiate(). " + tag);
        return { locale: tag, chain: found.chain, catalog: found.chain[0],
                 direction: found.direction, matched: true };
      }
    }
    log.debug("Leaving I18n.negotiate(). Nothing answered; English.");
    return { locale: SOURCE, chain: [SOURCE], catalog: SOURCE,
             direction: 'ltr', matched: false };
  }

  /**
   * Builds a translator for a list of preferences.
   *
   * @param preferences - canonical tags, best first
   * @param lastResort - the tag to use when none is answered
   * @returns the translator
   */
  translator(preferences: string[], lastResort?: string): Translator {
    log.debug("Entering I18n.translator().");
    const out = new Translator(this, this.negotiate(preferences, lastResort));
    log.debug("Leaving I18n.translator().");
    return out;
  }

  /**
   * Says whether some catalog other than English's fallback answers a tag.
   *
   * @param tag - a tag
   * @returns true when a catalog answers it
   */
  answers(tag: string): boolean {
    log.debug("Entering I18n.answers().");
    const canonical = I18n.canonical(tag);
    const out = !!canonical && this.chainFor(canonical).matched;
    log.debug("Leaving I18n.answers(). " + out);
    return out;
  }

  // -------------------------------------------------------------------------
  // MESSAGES.
  // -------------------------------------------------------------------------
  // The message for a key along a chain. Called for every string, so no
  // Entering/Leaving pair (the hot-path exception, stated).
  private lookup(chain: string[], key: string):
      { message: string; catalog: string } | null {
    const dot = key.indexOf('.');
    const ns = dot > 0 ? key.slice(0, dot) : '';
    const rest = dot > 0 ? key.slice(dot + 1) : key;
    const space = this.messages[ns] || {};
    for (const tag of chain) {
      const found = (space[tag] || {})[rest];
      if (typeof found === 'string') {
        return { message: found, catalog: tag };
      }
    }
    return null;
  }

  /**
   * Parses a message into nodes, or throws on one that is malformed.
   *
   * @param message - the message
   * @returns the nodes
   */
  static parse(message: string): MessageNode[] {
    log.debug("Entering I18n.parse().");
    const at = { i: 0 };
    const nodes = I18n.parseNodes(message, at, false, false);
    if (at.i < message.length) {
      throw new Error('an unmatched } at ' + at.i);
    }
    log.debug("Leaving I18n.parse(). " + nodes.length + " node(s).");
    return nodes;
  }

  // The recursive half of parse(): text up to a `}` (when nested) or the end.
  private static parseNodes(message: string, at: { i: number },
                            nested: boolean,
                            inPlural: boolean): MessageNode[] {
    log.debug("Entering I18n.parseNodes().");
    const nodes: MessageNode[] = [];
    let text = '';
    while (at.i < message.length) {
      const c = message[at.i];
      if (c === '}') {
        if (!nested) {
          throw new Error('an unmatched } at ' + at.i);
        }
        break;
      }
      if (c === '#' && inPlural) {
        if (text) {
          nodes.push(text);
          text = '';
        }
        nodes.push({ hash: true });
        at.i += 1;
        continue;
      }
      if (c === '{') {
        if (text) {
          nodes.push(text);
          text = '';
        }
        nodes.push(I18n.parseArgument(message, at));
        continue;
      }
      text += c;
      at.i += 1;
    }
    if (text) {
      nodes.push(text);
    }
    log.debug("Leaving I18n.parseNodes().");
    return nodes;
  }

  // `{name}`, `{name, plural, ...}` or `{name, select, ...}`, from its `{`.
  private static parseArgument(message: string,
                               at: { i: number }): MessageNode {
    log.debug("Entering I18n.parseArgument().");
    const close = message.indexOf('}', at.i);
    const comma = message.indexOf(',', at.i);
    if (close < 0) {
      throw new Error('an unclosed { at ' + at.i);
    }
    if (comma < 0 || comma > close) {
      const arg = message.slice(at.i + 1, close).trim();
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(arg)) {
        throw new Error('"' + arg + '" is not a parameter name');
      }
      at.i = close + 1;
      log.debug("Leaving I18n.parseArgument(). Simple.");
      return { arg: arg, kind: 'simple' };
    }
    const arg = message.slice(at.i + 1, comma).trim();
    const afterKind = message.indexOf(',', comma + 1);
    if (afterKind < 0) {
      throw new Error('"' + arg + '" has a kind but no options');
    }
    const kind = message.slice(comma + 1, afterKind).trim();
    if (kind !== 'plural' && kind !== 'select') {
      throw new Error('"' + kind + '" is not plural or select');
    }
    at.i = afterKind + 1;
    const options: Record<string, MessageNode[]> = {};
    for (;;) {
      while (at.i < message.length && /\s/.test(message[at.i])) {
        at.i += 1;
      }
      if (message[at.i] === '}') {
        at.i += 1;
        break;
      }
      const m = /^(=?[A-Za-z0-9_-]+)\s*\{/.exec(message.slice(at.i));
      if (!m) {
        throw new Error('an option of "' + arg + '" is malformed at ' + at.i);
      }
      at.i += m[0].length;
      options[m[1]] = I18n.parseNodes(message, at, true, kind === 'plural');
      if (message[at.i] !== '}') {
        throw new Error('option ' + m[1] + ' of "' + arg + '" is unclosed');
      }
      at.i += 1;
    }
    if (!options.other) {
      throw new Error('"' + arg + '" has no `other` option');
    }
    log.debug("Leaving I18n.parseArgument(). " + kind + ".");
    return { arg: arg, kind: kind, options: options };
  }

  /**
   * Lists a message's parameter names and its inline elements, so the catalog
   * test can hold every translation to its English message.
   *
   * @param message - the message
   * @returns the sorted parameter names and the sorted element names
   */
  static shapeOf(message: string): { params: string[]; elements: string[] } {
    log.debug("Entering I18n.shapeOf().");
    const params: string[] = [];
    const walk = function (nodes: MessageNode[]): void {
      nodes.forEach(function (node) {
        if (typeof node === 'string' || 'hash' in node) {
          return;
        }
        if (params.indexOf(node.arg) < 0) {
          params.push(node.arg);
        }
        Object.keys(node.options || {}).forEach(function (k) {
          walk(node.options[k]);
        });
      });
    };
    walk(I18n.parse(message));
    const elements: string[] = [];
    const re = /<\/?([A-Za-z][A-Za-z0-9]*)\b[^>]*>/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(message)) !== null) {
      elements.push(m[0].replace(/\s.*>$/, '>').toLowerCase());
    }
    log.debug("Leaving I18n.shapeOf().");
    return { params: params.sort(), elements: elements.sort() };
  }

  // A node list as text. Called for every string, so no Entering/Leaving
  // pair (the hot-path exception, stated).
  private render(nodes: MessageNode[], params: MessageParams,
                 locale: string, asHtml: boolean, count?: number): string {
    let out = '';
    for (const node of nodes) {
      if (typeof node === 'string') {
        out += node;
        continue;
      }
      if ('hash' in node) {
        out += this.numberText(locale, count);
        continue;
      }
      const value = params[node.arg];
      if (node.kind === 'simple') {
        const text = value == null ? '' : String(value);
        out += asHtml ? I18n.esc(text) : text;
        continue;
      }
      const options = node.options || {};
      if (node.kind === 'select') {
        const chosen = options[String(value)] || options.other;
        out += this.render(chosen, params, locale, asHtml, count);
        continue;
      }
      const n = Number(value);
      let chosen = options['=' + n];
      if (!chosen) {
        let category = 'other';
        try {
          category = new Intl.PluralRules(locale).select(n);
        } catch (e) {
          log.debug("Caught in I18n.render(): " + ((e && e.message) || e));
          category = 'other';
        }
        chosen = options[category] || options.other;
      }
      out += this.render(chosen, params, locale, asHtml, n);
    }
    return out;
  }

  // `#` in a plural, per string: the hot-path exception, as render().
  private numberText(locale: string, n: number | undefined): string {
    try {
      return new Intl.NumberFormat(locale).format(Number(n));
    } catch (e) {
      log.debug("Caught in I18n.numberText(): " + ((e && e.message) || e));
      return String(n);
    }
  }

  // Escaping, as `Html.esc()` does; here so this module stays a leaf. Per
  // parameter: the hot-path exception, as render().
  private static esc(value: string): string {
    return value.replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  // Called for every string on every page, through Translator: no
  // Entering/Leaving pair (the hot-path exception, stated).
  /**
   * Formats one message for a negotiated locale.
   *
   * A key no catalog has is answered with the key itself and logged; the
   * catalog test is what keeps that from shipping.
   *
   * @param negotiated - the locale and its chain
   * @param key - `namespace.key`
   * @param params - the parameters
   * @param asHtml - keep the message's markup and escape the parameters
   * (true), or strip the markup and escape nothing (false)
   * @returns the formatted message
   */
  format(negotiated: Negotiated, key: string, params: MessageParams,
         asHtml: boolean): string {
    this.load();
    const found = this.lookup(negotiated.chain, key);
    if (!found) {
      log.warn(this.deps.errorCodes.tag('STS-I18N-0002') + 'i18n: no ' +
               'catalog has the message ' + key + ', so its key is drawn.');
      return asHtml ? I18n.esc(key) : key;
    }
    const cacheKey = key + '\u0000' + found.catalog;
    let nodes = this.parsed.get(cacheKey);
    if (!nodes) {
      try {
        nodes = I18n.parse(found.message);
      } catch (e) {
        log.debug("Caught in I18n.format(): " + ((e && e.message) || e));
        log.warn(this.deps.errorCodes.tag('STS-I18N-0002') + 'i18n: the ' +
                 found.catalog + ' message ' + key + ' is malformed (' +
                 ((e && e.message) || e) + '), so it is drawn as written.');
        nodes = [found.message];
      }
      this.parsed.set(cacheKey, nodes);
    }
    // PLURAL RULES ARE THE LANGUAGE'S WHOSE WORDS ARE DRAWN. A message that
    // fell through to another language's catalog — English, for a key a
    // translation lacks — is pluralised by that catalog's rules: Filipino's
    // `one` covers 2, and "2 key" is what English words under Filipino rules
    // came out as.
    const ownLanguage = this.catalogParts[found.catalog] &&
      this.catalogParts[negotiated.catalog] &&
      this.catalogParts[found.catalog].language ===
        this.catalogParts[negotiated.catalog].language;
    const out = this.render(nodes, params,
                            ownLanguage ? negotiated.locale : found.catalog,
                            asHtml);
    return asHtml ? out : out.replace(/<[^>]*>/g, '');
  }
}

const slot = new InstanceSlot<I18n>(
  'common/i18n',
  () => new I18n(I18n.defaultDeps()),
  null,
  log);

slot.buildNowUnlessDeferred();

/**
 * The catalogs (#539): the languages a page may be drawn in, the negotiation
 * of a list of tags against them, and the formatting of one message. The
 * exports forward to the instance the composition root installs; the tag
 * helpers are static and need none.
 *
 * @namespace
 */
export = {
  I18n: I18n,
  Translator: Translator,
  /**
   * Installs the instance the module-level functions forward to.
   */
  installInstance: (instance: I18n): void => slot.install(instance),
  /**
   * Says where the installed instance came from.
   */
  instanceOrigin: (): string => slot.origin(),
  SOURCE: I18n.SOURCE,
  INLINE_ELEMENTS: I18n.INLINE_ELEMENTS,
  canonical: I18n.canonical,
  partsOf: I18n.partsOf,
  acceptLanguage: I18n.acceptLanguage,
  uiLocales: I18n.uiLocales,
  parse: I18n.parse,
  shapeOf: I18n.shapeOf,
  catalogs: slot.forward('catalogs'),
  offered: slot.forward('offered'),
  namespaces: slot.forward('namespaces'),
  messagesOf: slot.forward('messagesOf'),
  problems: slot.forward('problems'),
  chainFor: slot.forward('chainFor'),
  negotiate: slot.forward('negotiate'),
  translator: slot.forward('translator'),
  answers: slot.forward('answers')
};
