// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_said.ts
//
// ---------------------------------------------------------------------------
// A REFUSAL IN THE PAGE'S LANGUAGE, IN A BROWSER (#2006, rcbj 2026-11-23).
//
// An API that refuses answers `errors` in English and, beside them,
// `messages: [{ key, params }]` — one per sentence, `null` where a sentence
// has no catalog message (`common/sentence.ts`, the server's half). This
// draws each with the page's translator, from the `refusals` catalogs every
// surface loads (`common/web_i18n.ts`); a sentence whose key, or a
// parameter's key, the catalogs do not have is drawn in the English it was
// sent with, so a missing key never draws its name.
//
// Its own file rather than `WebSurface`'s, so a page's renderer can draw a
// view's refusal without requiring the runtime.
//
// A `web_` module, on `admin-ui/web_kit.ts`'s terms: it requires nothing and
// logs nothing (it runs in a browser, which the code style exempts).
// ---------------------------------------------------------------------------

type Json = any;

/**
 * Draws an answer's refusal in the page's language. A static utility class.
 */
class WebSaid {
  /**
   * One catalog message in the page's language, its parameters that are
   * messages drawn first; '' where the translator lacks any key it needs.
   *
   * @param t - the page's translator
   * @param message - `{ key, params }`
   * @returns the sentence, or ''
   */
  static sentence(t: Json, message: Json): string {
    if (!message || typeof message !== 'object' || !message.key ||
        !t || typeof t.has !== 'function' || !t.has(String(message.key))) {
      return '';
    }
    const params: Json = {};
    const given = message.params && typeof message.params === 'object'
      ? message.params : {};
    let whole = true;
    Object.keys(given).forEach(function (name) {
      const value = given[name];
      if (value && typeof value === 'object') {
        const inner = WebSaid.sentence(t, value);
        whole = whole && inner !== '';
        params[name] = inner;
        return;
      }
      params[name] = value;
    });
    return whole ? t.text(String(message.key), params) : '';
  }

  /**
   * What an answer's `errors` say, in the page's language where its
   * `messages` name a catalog message, and in its English otherwise.
   *
   * @param t - the page's translator
   * @param json - the answer
   * @returns the sentences, joined, or '' where it has none
   */
  static saidWith(t: Json, json: Json): string {
    const errors = (json && Array.isArray(json.errors)) ? json.errors : [];
    const messages = (json && Array.isArray(json.messages))
      ? json.messages : [];
    return errors.map(function (english: unknown, i: number) {
      return WebSaid.sentence(t, messages[i]) || String(english || '');
    }).filter(Boolean).join(' ');
  }
}

export = WebSaid;
