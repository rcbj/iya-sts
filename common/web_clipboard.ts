// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_clipboard.ts
//
// ---------------------------------------------------------------------------
// A COPY BUTTON THAT WORKS, OR SAYS IT DID NOT (#2220, ASVS 5.0.0 3.1.1).
//
// `navigator.clipboard` exists only in a secure context, and a browser may
// refuse it there too. The console has always fallen back to a selected,
// hidden text area and `document.execCommand('copy')` — the parent
// project's `copyField()`, and the deleted `/admin/copy.js` — while the
// portal's Copy did nothing at all without the clipboard, and said nothing.
// This is that fallback, one copy for both, and `label()` the button's
// words afterwards, in the page's language (`browser.copied`,
// `browser.copyFailed`), so a failed copy is said rather than silent.
//
// A `web_` MODULE: it requires nothing and logs nothing. It runs in a
// browser; a test drives it with stand-ins.
// ---------------------------------------------------------------------------

type Json = any;

/**
 * Copying text from a page. A static utility class.
 */
class WebClipboard {
  /**
   * How long a button says what happened, in milliseconds.
   */
  static readonly SAID_MS = 1500;

  /**
   * Copies through a selected, hidden text area and `execCommand('copy')`.
   *
   * @param doc - the document
   * @param text - the text
   * @returns whether the browser said it copied
   */
  static fallback(doc: Json, text: string): boolean {
    if (!doc || !doc.body || typeof doc.createElement !== 'function') {
      return false;
    }
    const area = doc.createElement('textarea');
    area.value = text;
    area.setAttribute('readonly', '');
    area.style.position = 'fixed';
    area.style.opacity = '0';
    doc.body.appendChild(area);
    let ok = false;
    try {
      area.focus();
      area.select();
      ok = typeof doc.execCommand === 'function' &&
        doc.execCommand('copy') === true;
    } catch (e) {
      // A browser that has dropped execCommand: the copy failed.
      ok = false;
    }
    doc.body.removeChild(area);
    return ok;
  }

  /**
   * Copies text: the clipboard where the browser has one, the fallback
   * where it has none or refuses.
   *
   * @param doc - the document
   * @param nav - the navigator
   * @param text - the text
   * @returns the promise of whether it was copied
   */
  static copy(doc: Json, nav: Json, text: string): Promise<boolean> {
    if (nav && nav.clipboard && typeof nav.clipboard.writeText === 'function') {
      return Promise.resolve(nav.clipboard.writeText(text))
        .then(function (): boolean {
          return true;
        }, function (): boolean {
          return WebClipboard.fallback(doc, text);
        });
    }
    return Promise.resolve(WebClipboard.fallback(doc, text));
  }

  /**
   * What a button says after a copy, in the page's language.
   *
   * @param t - the page's translator, or null
   * @param ok - whether it copied
   * @returns `{ label, hint }`: the button's words, and for a failure what
   *   to do instead ('' for a success)
   */
  static label(t: Json, ok: boolean): Json {
    const said = function (key: string, english: string): string {
      return t && t.has && t.has(key) ? t.text(key) : english;
    };
    return ok
      ? { label: said('browser.copied', 'Copied'), hint: '' }
      : { label: said('browser.copyFailed', 'Copy failed'),
          hint: said('browser.copyFailed.hint', 'This browser could not ' +
            'copy the text. Select it and copy it yourself.') };
  }

  /**
   * Copies a button's text and says on the button what happened, for
   * `SAID_MS`; a failure also says, as the button's title, what to do.
   *
   * @param doc - the document
   * @param nav - the navigator
   * @param t - the page's translator, or null
   * @param button - the button pressed
   * @param text - the text
   * @param later - optional; `setTimeout`, or a stand-in
   * @returns the promise of whether it was copied
   */
  static copyFrom(doc: Json, nav: Json, t: Json, button: Json, text: string,
                  later?: Json): Promise<boolean> {
    const wait = later || (typeof setTimeout === 'function'
      ? setTimeout : null);
    return WebClipboard.copy(doc, nav, text).then(function (ok: boolean) {
      const was = button.textContent;
      const wasTitle = button.getAttribute ? button.getAttribute('title')
                                           : null;
      const words = WebClipboard.label(t, ok);
      button.textContent = words.label;
      if (words.hint && button.setAttribute) {
        button.setAttribute('title', words.hint);
      }
      if (wait) {
        wait(function () {
          button.textContent = was;
          if (words.hint && button.removeAttribute && wasTitle === null) {
            button.removeAttribute('title');
          } else if (words.hint && button.setAttribute) {
            button.setAttribute('title', wasTitle);
          }
        }, WebClipboard.SAID_MS);
      }
      return ok;
    });
  }
}

export = WebClipboard;
