// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_browser_check.ts
//
// ---------------------------------------------------------------------------
// THE FIRST SCRIPT EVERY SHELL RUNS: WHETHER THIS BROWSER CAN RUN THE PAGE
// AT ALL (#2220, ASVS 5.0.0 3.1.1).
//
// Every static surface's runtime is built for ECMAScript 2022
// (`build-typescript.sh`, `--target=es2022`) and calls `fetch`,
// `TextEncoder`, `URL` and `URLSearchParams` without asking. A browser
// without one used to show the shell's "Loading…" and nothing else: a
// bundle whose syntax it cannot parse never runs, and one that parses fails
// at its first call. So each shell (`common/shell_document.ts`) carries,
// before its bundle, this file as `/web/browser-check.js`, and a notice
// drawn HIDDEN by the server in the request's language (`#sts-browser-check`,
// with a link to what this service needs from a browser). This script:
//
//   * asks for what every runtime uses (`missing()`): `fetch`, `Promise`,
//     `TextEncoder`, `TextDecoder`, `URL`, `URLSearchParams`,
//     `history.pushState`, and ECMAScript 2022 — which a script cannot test
//     by parsing without `eval`, which `script-src 'self'` refuses, so its
//     built-ins stand in: `Object.hasOwn` and `Array.prototype.at`, which
//     came in that edition and which every browser that parses it has;
//   * where anything is missing, shows the notice, names what is missing in
//     it, and marks `<html data-sts-unsupported="1">`, which every
//     runtime's entry reads before it starts, so nothing draws over it;
//   * and where nothing is, still listens until the document has loaded for
//     a `SyntaxError` — the bundle's syntax this browser cannot parse,
//     which no built-in predicts exactly — and shows the notice then.
//
// IT IS WRITTEN IN ECMASCRIPT 5, so the browser it is for can run it: `var`
// and functions, no class, no arrow, no `let` or `const` (`declare var` for
// the browser's globals too: esbuild refuses even a declared `const` at
// that target). That is why this `web_` module is not a class, as a
// converted module otherwise is (the root CLAUDE.md's style): ES5 has no
// class syntax, and esbuild does not lower one to it.
// `build-typescript.sh` bundles it with `--target=es5`, which fails the image
// build on anything newer, and `tests/browser_check.js` parses the bundle as
// ES5. It is drawn in no language: the server drew the words.
//
// A `web_` MODULE: it requires nothing and logs nothing. It runs in a
// browser; a test drives it with stand-ins.
// ---------------------------------------------------------------------------

declare var window: any;
declare var document: any;

/**
 * Whether a value is a function.
 *
 * @param value - anything
 * @returns true for a function
 */
function isFunction(value: any): boolean {
  return typeof value === 'function';
}

/**
 * Whether a browser can run this service's pages.
 */
var BrowserCheck = {
  // The notice the shell draws hidden, and where the missing names go.
  NOTICE_ID: 'sts-browser-check',
  MISSING_ID: 'sts-browser-missing',
  // What `<html>` carries once the notice is shown.
  MARK: 'data-sts-unsupported',

  /**
   * What this browser lacks that every runtime uses.
   *
   * @param w - the window
   * @returns the names of what is missing, empty when nothing is
   */
  missing: function (w: any): string[] {
    var out: string[] = [];
    var fn = isFunction;
    var o = w && w.Object;
    var a = w && w.Array;
    if (!w || !fn(w.fetch)) {
      out.push('fetch');
    }
    if (!w || !fn(w.Promise)) {
      out.push('Promise');
    }
    var names = ['TextEncoder', 'TextDecoder', 'URL', 'URLSearchParams'];
    for (var i = 0; i < names.length; i++) {
      if (!w || !fn(w[names[i]])) {
        out.push(names[i]);
      }
    }
    if (!w || !w.history || !fn(w.history.pushState)) {
      out.push('history.pushState');
    }
    if (!o || !fn(o.hasOwn) || !a || !a.prototype || !fn(a.prototype.at)) {
      out.push('ECMAScript 2022');
    }
    return out;
  },

  /**
   * Shows the shell's notice, names what is missing in it and marks the
   * document, once.
   *
   * @param doc - the document
   * @param names - what is missing
   * @returns whether a notice was there to show
   */
  reveal: function (doc: any, names: string[]): boolean {
    if (!doc || !doc.getElementById) {
      return false;
    }
    var root = doc.documentElement;
    if (root && root.setAttribute) {
      root.setAttribute(BrowserCheck.MARK, '1');
    }
    var notice = doc.getElementById(BrowserCheck.NOTICE_ID);
    if (!notice) {
      return false;
    }
    var named = doc.getElementById(BrowserCheck.MISSING_ID);
    if (named && names && names.length) {
      // Text, never markup: the names are this file's own.
      named.textContent = ' (' + names.join(', ') + ')';
    }
    notice.hidden = false;
    if (notice.removeAttribute) {
      notice.removeAttribute('hidden');
    }
    return true;
  },

  /**
   * Checks the browser, and shows the notice where it falls short — now,
   * or when a script that follows turns out not to parse.
   *
   * @param w - the window
   * @param doc - the document
   * @returns what is missing now
   */
  run: function (w: any, doc: any): string[] {
    var names = BrowserCheck.missing(w);
    if (names.length) {
      BrowserCheck.reveal(doc, names);
      return names;
    }
    if (!w || !isFunction(w.addEventListener)) {
      return names;
    }
    // A BUNDLE THIS BROWSER CANNOT PARSE: its `SyntaxError` reaches the
    // window as an `error` event before the document has loaded (the
    // bundle is deferred, after this). A later one is the page's own, and
    // not this file's to report.
    var onError = function (event: any): void {
      var error = event && event.error;
      var said = String((event && event.message) || '');
      if ((error && error.name === 'SyntaxError') ||
          /SyntaxError/.test(said)) {
        BrowserCheck.reveal(doc, ['ECMAScript 2022']);
      }
    };
    w.addEventListener('error', onError);
    var loaded = function (): void {
      w.removeEventListener('error', onError);
    };
    if (doc && isFunction(doc.addEventListener)) {
      doc.addEventListener('DOMContentLoaded', loaded);
    }
    return names;
  }
};

if (typeof window !== 'undefined' && typeof document !== 'undefined') {
  BrowserCheck.run(window, document);
}

export = BrowserCheck;
