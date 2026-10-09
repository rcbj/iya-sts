// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_messages.ts
//
// ---------------------------------------------------------------------------
// ONE MESSAGE FORMATTER, FOR THE SERVER AND THE CONSOLE (#539 phase 5,
// 2026-10-09).
//
// The pages this process draws are translated through `common/i18n.ts`; the
// admin console is a static application whose `web_*.ts` renderers run in a
// browser (#446) and may require nothing but each other. Both need the same
// thing — a message's ICU subset parsed, its parameters escaped, its plural
// chosen by the language's rules — and two parsers would be two answers to
// "what does this message say". So the formatter lives HERE, on a `web_`
// module's terms (no logger, nothing of node's, loadable in a browser), and
// `common/i18n.ts` keeps the catalogs and the negotiation and hands every
// message to this file. A library requiring a `web_` module is the one
// direction that is safe: this file requires nothing.
//
// WHAT IS HERE:
//
//   * `WebMessages` — parse a message, list its parameters and elements (the
//     catalog test's shape check), and render parsed nodes. `common/i18n.ts`
//     header documents the message syntax: `{name}`, `{n, plural, ...}`,
//     `{x, select, ...}`, `#`, and four inline elements, no literal braces.
//   * `WebTranslator` — a negotiated locale and a way to FIND a message by
//     catalog tag and key. On the server the finder reads the loaded files;
//     in the browser it reads the catalogs `GET /admin-api/console` answered
//     with. The locale `Intl` formats for is the reader's (`es-PA`), and a
//     message's plural rules are the language's whose words are drawn — an
//     English message that a translation lacked is pluralised as English.
//
// **NO ENTERING/LEAVING LINES**: it runs in a browser, which the code style
// exempts, and every string on every page passes through it, which is the
// hot-path exception besides. A problem (a missing key, a malformed
// message) is reported to the caller's `onProblem`, which the server logs
// under its error code; the browser passes none.
// ---------------------------------------------------------------------------

/**
 * One node of a parsed message.
 */
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
 * What a translator is built from.
 */
interface TranslatorSpec {
  negotiated: Negotiated;
  // The message for a key in one catalog, or undefined.
  find: (tag: string, key: string) => string | undefined;
  // A problem worth reporting: `missing` (no catalog has the key) or
  // `malformed` (the message would not parse).
  onProblem?: (kind: 'missing' | 'malformed', key: string,
               detail: string) => void;
}

// Parsed messages by text, shared by every translator: a page asks for the
// same few hundred messages again and again. Bounded, so a catalog cannot
// grow it without end.
const PARSED = new Map<string, MessageNode[]>();
const PARSED_MAX = 20000;

// THE TRANSLATOR A CONTEXT GETS WHEN IT IS GIVEN NONE. In the browser
// nothing sets it — the runtime hands every page its own — and it draws each
// key. In node `common/i18n.ts` sets it to English, so a page drawn
// server-side or by a test without a translator reads as it always did.
let defaultTranslator: (() => any) | null = null;

/**
 * The message syntax: parse, shape and render. A static utility class.
 */
class WebMessages {
  /**
   * Parses a message into nodes, or throws on one that is malformed.
   *
   * @param message - the message
   * @returns the nodes
   */
  static parse(message: string): MessageNode[] {
    const at = { i: 0 };
    const nodes = WebMessages.parseNodes(message, at, false, false);
    if (at.i < message.length) {
      throw new Error('an unmatched } at ' + at.i);
    }
    return nodes;
  }

  /**
   * Parses a message once and keeps it.
   *
   * @param message - the message
   * @returns the nodes
   */
  static parsed(message: string): MessageNode[] {
    let nodes = PARSED.get(message);
    if (!nodes) {
      nodes = WebMessages.parse(message);
      if (PARSED.size >= PARSED_MAX) {
        PARSED.clear();
      }
      PARSED.set(message, nodes);
    }
    return nodes;
  }

  // The recursive half of parse(): text up to a `}` (when nested) or the end.
  private static parseNodes(message: string, at: { i: number },
                            nested: boolean,
                            inPlural: boolean): MessageNode[] {
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
        nodes.push(WebMessages.parseArgument(message, at));
        continue;
      }
      text += c;
      at.i += 1;
    }
    if (text) {
      nodes.push(text);
    }
    return nodes;
  }

  // `{name}`, `{name, plural, ...}` or `{name, select, ...}`, from its `{`.
  private static parseArgument(message: string,
                               at: { i: number }): MessageNode {
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
      options[m[1]] = WebMessages.parseNodes(message, at, true,
                                             kind === 'plural');
      if (message[at.i] !== '}') {
        throw new Error('option ' + m[1] + ' of "' + arg + '" is unclosed');
      }
      at.i += 1;
    }
    if (!options.other) {
      throw new Error('"' + arg + '" has no `other` option');
    }
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
    walk(WebMessages.parse(message));
    const elements: string[] = [];
    const re = /<\/?([A-Za-z][A-Za-z0-9]*)\b[^>]*>/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(message)) !== null) {
      elements.push(m[0].replace(/\s.*>$/, '>').toLowerCase());
    }
    return { params: params.sort(), elements: elements.sort() };
  }

  /**
   * Renders parsed nodes.
   *
   * @param nodes - the parsed message
   * @param params - the parameters
   * @param locale - the locale plural rules and `#` are chosen by
   * @param asHtml - escape the parameters (true) or not (false)
   * @param count - the number `#` stands for, inside a plural
   * @returns the text
   */
  static render(nodes: MessageNode[], params: MessageParams, locale: string,
                asHtml: boolean, count?: number): string {
    let out = '';
    for (const node of nodes) {
      if (typeof node === 'string') {
        out += node;
        continue;
      }
      if ('hash' in node) {
        out += WebMessages.numberText(locale, count);
        continue;
      }
      const value = params[node.arg];
      if (node.kind === 'simple') {
        const text = value == null ? '' : String(value);
        out += asHtml ? WebMessages.esc(text) : text;
        continue;
      }
      const options = node.options || {};
      if (node.kind === 'select') {
        const chosen = options[String(value)] || options.other;
        out += WebMessages.render(chosen, params, locale, asHtml, count);
        continue;
      }
      const n = Number(value);
      let chosen = options['=' + n];
      if (!chosen) {
        let category = 'other';
        try {
          category = new Intl.PluralRules(locale).select(n);
        } catch (e) {
          // A locale Intl does not know pluralises as `other`.
          category = 'other';
        }
        chosen = options[category] || options.other;
      }
      out += WebMessages.render(chosen, params, locale, asHtml, n);
    }
    return out;
  }

  // `#` in a plural.
  private static numberText(locale: string, n: number | undefined): string {
    try {
      return new Intl.NumberFormat(locale).format(Number(n));
    } catch (e) {
      // A locale Intl does not know: the plain number.
      return String(n);
    }
  }

  /**
   * Escapes text for HTML, as `Html.esc()` does.
   *
   * @param value - the text
   * @returns the escaped text
   */
  static esc(value: string): string {
    return value.replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  /**
   * The language subtag of a catalog tag (`zh` for `zh-Hant-HK`).
   *
   * @param tag - a tag
   * @returns its language
   */
  static languageOf(tag: string): string {
    return String(tag || '').split('-')[0].toLowerCase();
  }
}

/**
 * One translator: a negotiated locale and the catalogs it reads, with the
 * ways of turning a key into words, a date or a number.
 */
class WebTranslator {
  /**
   * The negotiation the translator was built over.
   */
  readonly negotiated: Negotiated;
  private readonly find: TranslatorSpec['find'];
  private readonly onProblem: TranslatorSpec['onProblem'];

  /**
   * Builds a translator.
   *
   * @param spec - the negotiation, a finder and a problem reporter
   */
  constructor(spec: TranslatorSpec) {
    this.negotiated = spec.negotiated;
    this.find = spec.find;
    this.onProblem = spec.onProblem;
  }

  /**
   * Builds a translator over catalogs held as plain data — what
   * `GET /admin-api/console` answers: `{ negotiated, catalogs: { <tag>:
   * { 'ns.key': message } } }`.
   *
   * @param data - the negotiation and the catalogs
   * @returns the translator
   */
  static fromData(data: any): WebTranslator {
    const catalogs = (data && data.catalogs) || {};
    const negotiated = (data && data.negotiated) || { locale: 'en',
      chain: ['en'], catalog: 'en', direction: 'ltr', matched: false };
    return new WebTranslator({
      negotiated: negotiated,
      find: function (tag: string, key: string): string | undefined {
        const found = (catalogs[tag] || {})[key];
        return typeof found === 'string' ? found : undefined;
      }
    });
  }

  /**
   * Sets what `fallback()` builds.
   *
   * @param make - a function answering a translator, or null
   * @returns nothing
   */
  static setDefault(make: (() => any) | null): void {
    defaultTranslator = make;
  }

  /**
   * The translator for a context given none: the default `setDefault()`
   * installed, or one with no catalogs.
   *
   * @returns the translator
   */
  static fallback(): WebTranslator {
    return defaultTranslator ? defaultTranslator()
                             : WebTranslator.fromData(null);
  }

  /**
   * The locale `Intl` formats for: the preference that won, such as `es-PA`.
   */
  get locale(): string {
    return this.negotiated.locale;
  }

  /**
   * The value of a page's `lang` attribute.
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

  /**
   * Formats a message as HTML: its own inline markup kept, every parameter
   * escaped.
   *
   * @param key - `namespace.key`
   * @param params - the parameters
   * @returns the message as HTML
   */
  html(key: string, params?: MessageParams): string {
    return this.format(key, params || {}, true);
  }

  /**
   * Formats a message as plain text, for an attribute value, a title or a
   * header: its markup stripped and nothing escaped (the caller escapes).
   *
   * @param key - `namespace.key`
   * @param params - the parameters
   * @returns the message as text
   */
  text(key: string, params?: MessageParams): string {
    return this.format(key, params || {}, false);
  }

  /**
   * Says whether some catalog of the chain has a message for a key.
   *
   * @param key - `namespace.key`
   * @returns true when one does
   */
  has(key: string): boolean {
    return this.negotiated.chain.some((tag) => {
      return this.find(tag, key) !== undefined;
    });
  }

  // One message, along the chain.
  private format(key: string, params: MessageParams,
                 asHtml: boolean): string {
    let message: string | undefined;
    let catalog = '';
    for (const tag of this.negotiated.chain) {
      message = this.find(tag, key);
      if (message !== undefined) {
        catalog = tag;
        break;
      }
    }
    if (message === undefined) {
      if (this.onProblem) {
        this.onProblem('missing', key, '');
      }
      return asHtml ? WebMessages.esc(key) : key;
    }
    let nodes: MessageNode[];
    try {
      nodes = WebMessages.parsed(message);
    } catch (e) {
      if (this.onProblem) {
        this.onProblem('malformed', key, String((e && e.message) || e));
      }
      nodes = [message];
    }
    // PLURAL RULES ARE THE LANGUAGE'S WHOSE WORDS ARE DRAWN: a message that
    // fell through to another language's catalog — English, for a key a
    // translation lacks — is pluralised by that catalog's rules.
    const own = WebMessages.languageOf(catalog) ===
      WebMessages.languageOf(this.negotiated.catalog);
    const out = WebMessages.render(nodes, params,
                                   own ? this.negotiated.locale : catalog,
                                   asHtml);
    return asHtml ? out : out.replace(/<[^>]*>/g, '');
  }

  /**
   * Formats a date and time for this locale: in UTC, saying so, unless the
   * options name another zone.
   *
   * @param when - the instant
   * @param options - `Intl.DateTimeFormat` options; date and time, medium
   * and long, when omitted
   * @returns the text
   */
  date(when: Date | number | string,
       options?: Intl.DateTimeFormatOptions): string {
    const value = when instanceof Date ? when : new Date(when);
    try {
      const fallback: Intl.DateTimeFormatOptions =
        { dateStyle: 'medium', timeStyle: 'long' };
      const asked: Intl.DateTimeFormatOptions =
        Object.assign({ timeZone: 'UTC' }, options || fallback);
      return new Intl.DateTimeFormat(this.locale, asked).format(value);
    } catch (e) {
      // An instant Intl cannot draw: the ISO form, or what was given.
      return isNaN(value.getTime()) ? String(when) : value.toISOString();
    }
  }

  /**
   * Formats a number for this locale.
   *
   * @param value - the number
   * @param options - `Intl.NumberFormat` options
   * @returns the text
   */
  number(value: number, options?: Intl.NumberFormatOptions): string {
    try {
      return new Intl.NumberFormat(this.locale, options).format(value);
    } catch (e) {
      // A locale Intl does not know: the plain number.
      return String(value);
    }
  }
}

export = { WebMessages: WebMessages, WebTranslator: WebTranslator };
