// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: sentence.ts
//
// ---------------------------------------------------------------------------
// A REFUSAL A PERSON READS, AS A CATALOG MESSAGE (#2006, rcbj 2026-11-23).
//
// #539 kept every refusal English, and #1326 reversed that for the page that
// ENDS a browser flow. #2006 reverses it for every static surface (#570): the
// sentence the sign-in screen, a step after it, consent, sign-out, GNAP's
// interaction pages and federation's pages show when an act is refused is
// drawn in the page's language.
//
// **THE BROWSER TRANSLATES** (#570's decision 3 holds): an answer that
// refuses keeps `errors: [English]`, which is what a program reads, and
// gains `messages: [{ key, params }]` beside it, one per sentence, `null`
// where a sentence has no catalog message. The runtime draws each with the
// page's `t` (`WebSurface.said()`), falling back to the English where the
// catalog has no such key, so a missing key never draws its name.
//
// **A `Sentence` IS STILL ENGLISH EVERYWHERE ELSE.** `String(s)`, `'' + s`,
// `JSON.stringify(s)` and `[s].join(' ')` all give the English, formatted
// from `common/locales/refusals/en.json` — so a log line, an audit row's
// note, a pending record put in the store, and every caller that only ever
// treated the sentence as text, read exactly what they read before. Only the
// few lines that ANSWER a refusal (`authn.ts`'s `screenRefused()`,
// `stepRefused()` and their kin) ask `Sentence.messagesOf()` for the keys.
//
// **THE ENGLISH LIVES IN THE CATALOG, NOT IN THE SOURCE**: a call site names
// `Sentence.say('refusals.authn.failedFor', { username })`, a literal key, so
// `tests/i18n_catalogs.js`'s scan (test E) finds every key a refusal names,
// and one English copy means one wording. The namespace is `refusals`, which
// every static surface's runtime loads (`common/web_i18n.ts`), because a
// refusal is often written by a library the surface does not own (the
// authentication policy, the passkey policy, the account's state).
//
// **A PARAMETER IS DATA OR ANOTHER SENTENCE.** A username, a number, a
// setting's name are drawn as they are; a parameter that is itself words (a
// check that failed, a factor's name) is a `Sentence`, sent as its own
// `{ key, params }` and translated by the browser before it is placed.
//
// A library with no state and no dependencies but the catalogs, so a static
// utility class (#50's rule); the English is formatted by `common/i18n.ts`,
// a leaf, so any module may require this one.
// ---------------------------------------------------------------------------

import helpers = require('./helpers');
import i18n = require('./i18n');
import errorCodes = require('./error_codes');

const { log } = helpers;

/**
 * A parameter of a sentence: a value drawn as it is, or a sentence drawn in
 * the page's language before it is placed.
 */
type SentenceParam = string | number | Sentence;

/**
 * One sentence as an answer carries it beside its English.
 */
interface SentenceMessage {
  key: string;
  params?: Record<string, string | number | SentenceMessage>;
}

/**
 * A refusal's sentence: its catalog key and parameters, and its English.
 */
// A `String` OBJECT WHOSE VALUE IS THE ENGLISH (the merger's review of
// #2006): a sentence reaches code written for text — a protocol's error
// builder, an XML escaper, a log line — and every string method there
// (`replace()`, `indexOf()`, `slice()`, `length`) answers as the English
// would. `typeof` still says `object`, which is why the issuance gate and the
// rate limiter hand protocol code their English as text and the sentence
// beside it (`said`), and why `oauth21.js`'s `sanitizeDescription()` makes
// any object text before it checks the character set.
class Sentence extends String {
  // The catalog key, `refusals.<area>.<name>`.
  readonly key: string;
  // The parameters, by name.
  readonly params: Record<string, SentenceParam>;
  // The English, formatted from the source catalog.
  readonly text: string;

  /**
   * Makes a sentence. Callers use `Sentence.say()`.
   *
   * @param key - the catalog key
   * @param params - the parameters
   */
  private constructor(key: string, params: Record<string, SentenceParam>,
                      text: string) {
    super(text);
    log.debug("Entering Sentence.constructor(). " + key);
    this.key = key;
    this.params = params;
    this.text = text;
    log.debug("Leaving Sentence.constructor().");
  }

  /**
   * The English of a key and its parameters, from the source catalog.
   *
   * @param key - the catalog key
   * @param params - the parameters
   * @returns the English
   */
  private static englishOf(key: string,
                           params: Record<string, SentenceParam>): string {
    log.debug("Entering Sentence.englishOf(). " + key);
    const english: Record<string, string | number> = {};
    Object.keys(params).forEach(function (name) {
      const value = params[name];
      english[name] = value instanceof Sentence ? value.text
        : (typeof value === 'number' ? value : String(value == null
          ? '' : value));
    });
    const out = i18n.translator([i18n.SOURCE]).text(key, english);
    log.debug("Leaving Sentence.englishOf().");
    return out;
  }

  /**
   * A sentence from the `refusals` catalogs.
   *
   * @param key - the catalog key, a literal (`refusals.authn.failedFor`)
   * @param params - the parameters, by name
   * @param fallback - the English to send where the English catalog has no
   *   such key: a sentence read back from a store (`VcSignin.revived()`)
   * @returns the sentence
   */
  static say(key: string, params?: Record<string, SentenceParam>,
             fallback?: string): Sentence {
    log.debug("Entering Sentence.say().");
    const given = params || {};
    // A KEY THE ENGLISH CATALOG DOES NOT HAVE is never sent as its name
    // (the merger's review of #2006): a sentence a store kept under another
    // build, read back after a rollback or during a rolling deploy, says the
    // English it was given — or a general sentence — and carries no key, so
    // no page looks one up either.
    if (!i18n.translator([i18n.SOURCE]).has(key)) {
      log.warn(errorCodes.tag('STS-I18N-0016') + 'sentence: the English ' +
               'catalog has no ' + key + '; its fallback is sent instead.');
      const out = new Sentence('', {}, String(fallback ||
        Sentence.englishOf('refusals.web.refusedGeneral', {})));
      log.debug("Leaving Sentence.say(). No such key.");
      return out;
    }
    const out = new Sentence(key, given, Sentence.englishOf(key, given));
    log.debug("Leaving Sentence.say().");
    return out;
  }

  // NO ENTERING/LEAVING PAIR: called every time a sentence is concatenated,
  // logged or written, so a pair here would drown the log — the hot-path
  // exception the code style allows.
  /**
   * Whether a value is a sentence.
   *
   * @param value - anything
   * @returns true for a `Sentence`
   */
  static is(value: unknown): value is Sentence {
    return value instanceof Sentence;
  }

  // NO ENTERING/LEAVING PAIR: called every time a sentence is concatenated,
  // logged or written, so a pair here would drown the log — the hot-path
  // exception the code style allows.
  /**
   * The English: what every caller that treats a sentence as text reads.
   *
   * @returns the English
   */
  toString(): string {
    return this.text;
  }

  // NO ENTERING/LEAVING PAIR, for `toString()`'s reason: `+` and template
  // literals call it.
  /**
   * The English, for `+` and a template literal.
   *
   * @returns the English
   */
  valueOf(): string {
    return this.text;
  }

  // NO ENTERING/LEAVING PAIR: called every time a sentence is concatenated,
  // logged or written, so a pair here would drown the log — the hot-path
  // exception the code style allows.
  /**
   * The English, so a sentence put in a store or an answer is its words.
   *
   * @returns the English
   */
  toJSON(): string {
    return this.text;
  }

  /**
   * The sentence in a page's language, for a page the SERVER draws (the
   * signed-out document): its parameters that are sentences said in it
   * too, and its English where the translator lacks its key.
   *
   * @param t - the page's translator (`PageLocale.forPage()`)
   * @returns the sentence, as text
   */
  textIn(t: any): string {
    log.debug("Entering Sentence.textIn(). " + this.key);
    if (!this.key || !t || typeof t.has !== 'function' || !t.has(this.key)) {
      log.debug("Leaving Sentence.textIn(). English.");
      return this.text;
    }
    const params: Record<string, string | number> = {};
    Object.keys(this.params).forEach((name) => {
      const value = this.params[name];
      params[name] = value instanceof Sentence ? value.textIn(t)
        : (typeof value === 'number' ? value : String(value == null
          ? '' : value));
    });
    const out = t.text(this.key, params);
    log.debug("Leaving Sentence.textIn().");
    return out;
  }

  /**
   * The sentence as an answer carries it: its key and its parameters, a
   * parameter that is a sentence carried the same way.
   *
   * @returns `{ key, params }`
   */
  message(): SentenceMessage {
    log.debug("Entering Sentence.message(). " + this.key);
    const out: SentenceMessage = { key: this.key };
    const names = Object.keys(this.params);
    if (names.length) {
      const params: Record<string, string | number | SentenceMessage> = {};
      names.forEach((name) => {
        const value = this.params[name];
        params[name] = value instanceof Sentence ? value.message()
          : (typeof value === 'number' ? value : String(value == null
            ? '' : value));
      });
      out.params = params;
    }
    log.debug("Leaving Sentence.message().");
    return out;
  }

  /**
   * The `messages` member of an answer whose `errors` are these sentences:
   * one entry per sentence, `null` for one that is only text. Undefined
   * where none is a `Sentence`, so an answer with no catalog sentence
   * carries no member it would not have carried before.
   *
   * @param list - the sentences, `Sentence`s or text
   * @returns the messages, or undefined
   */
  static messagesOf(list: unknown[]): (SentenceMessage | null)[] | undefined {
    log.debug("Entering Sentence.messagesOf().");
    const items = Array.isArray(list) ? list : [];
    if (!items.some(function (s) {
      return s instanceof Sentence && !!s.key;
    })) {
      log.debug("Leaving Sentence.messagesOf(). Text only.");
      return undefined;
    }
    const out = items.map(function (s) {
      return s instanceof Sentence && s.key ? s.message() : null;
    });
    log.debug("Leaving Sentence.messagesOf(). " + out.length + ".");
    return out;
  }

  /**
   * The message a stored sentence was, for a record that keeps a refusal
   * to show on a later view (the screen's `screenError`): a store keeps
   * the English (`toJSON()`), so the key is kept beside it.
   *
   * @param value - the sentence, or text
   * @returns `{ key, params }`, or null for text
   */
  static stored(value: unknown): SentenceMessage | null {
    log.debug("Entering Sentence.stored().");
    const out = value instanceof Sentence && value.key ? value.message()
      : null;
    log.debug("Leaving Sentence.stored().");
    return out;
  }
}

export = Sentence;
