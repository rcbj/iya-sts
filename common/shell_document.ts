// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: shell_document.ts
//
// ---------------------------------------------------------------------------
// THE ONE DOCUMENT A STATIC SURFACE ANSWERS, AND HOW ITS FILES ARE SENT
// (#570, 2026-10-12).
//
// A static surface — the admin console (#446), the user portal (#568), and
// every public page #569 converts — answers every path it owns with ONE
// document, the SHELL: a doctype, an `<html>` whose attributes tell the
// runtime where things are, the surface's stylesheet and script, a notice
// for a browser that runs no script, and nothing else. The console and the
// portal each wrote theirs by hand; this is the one writer, and they draw
// theirs through it byte for byte (`tests/web_foundation.js` holds the bytes).
//
// WHAT A SHELL CARRIES, AND WHY EACH IS HERE:
//
//   * `<html lang>` and, where given, `dir`; then the `data-sts-*`
//     ATTRIBUTES, each drawn only where it has a value — the bases of the
//     applications on other listeners (#472), which `web_page.ts` reads, and
//     for a translated surface `PageLocale.shellAttributes()` (the build, the
//     chooser's choice, the locale policy's default). A service with no
//     custom listener draws the document it always did.
//   * THE STYLESHEETS AND THE SCRIPT, root-relative, so `common/app.js`'s
//     realm rewrite puts them under the realm the shell was asked in. The
//     script is `defer`.
//   * A `<noscript>` NOTICE AND NOTHING ELSE for a browser with script
//     blocked: rcbj's decision on #569 is that script is REQUIRED on every
//     static surface, with no server-drawn fallback, so the notice says what
//     the page is and that it needs its script.
//   * A REFUSAL in place of the notice, and NO script, where the surface
//     already knows it cannot work here (the console's callback refused).
//
// HOW IT IS SENT (`serve()`): `Cache-Control: no-store` — the document is
// public and carries nothing, but its attributes are per request — and the
// CONTENT SECURITY POLICY ONLY THROUGH `app.contentSecurityPolicy()`, which
// re-adds `frame-ancestors` and `base-uri` whatever is asked (the root
// CLAUDE.md's rule): `script-src 'self'`, `connect-src 'self'` plus the
// origins of the other listeners the runtime calls, `style-src`, and what a
// surface adds. Compressed or not, as the surface says: a compressed body
// passes `app.js`'s realm rewrite untouched, so `serve()` does the rewrite
// first — and the uncompressed one is left to that rewrite, as every page is.
//
// AND A SURFACE'S OWN FILES (`readFile()`, `sendFile()`): its built bundle
// with the `.br` and `.gz` the image build wrote beside it, read once, and
// sent in the coding the request accepts (`acceptedEncoding()`, `q=0`
// refusing one), with `Vary: Accept-Encoding`. Only a surface's own static
// files are compressed: an API or protocol answer often carries a secret
// beside text the caller chose, which is what BREACH reads through
// compression. `AdminConsole.sendConsoleFile()` was this code until #570.
//
// A LIBRARY (rule 3) and a static utility class: `helpers` (the logger) and
// node's `zlib`, `fs` and `path`. It takes the express app as an argument
// rather than requiring `common/app`, so a module that cannot require the
// app at load can still draw a shell, and it registers nothing.
// ---------------------------------------------------------------------------

import zlib = require('zlib');
import fs = require('fs');
import path = require('path');
import helpers = require('./helpers');

const { log } = helpers;

type Json = any;

/**
 * What a shell document is drawn from.
 */
interface ShellSpec {
  // The document's title, as text.
  title: string;
  // `<html lang>`; `en` where left out.
  lang?: string;
  // `<html dir>`, drawn only where given.
  dir?: string;
  // `data-sts-*` attributes, in order; one with an empty value is left out.
  attributes?: Array<[string, string]>;
  // The viewport meta's content.
  viewport?: string;
  // The stylesheets' hrefs, root-relative.
  stylesheets: string[];
  // The script's src, root-relative; left out with a refusal.
  script: string;
  // The body's markup before the notice, and after it.
  open: string;
  close: string;
  // The `<noscript>` notice's markup, and the markup after it while the
  // script loads.
  noscript: string;
  loading: string;
  // Markup drawn instead of the notice, with no script, where the surface
  // cannot work here; null or undefined where it can.
  refusal?: string | null;
  // How an attribute value or the title is escaped; `&#39;` for an
  // apostrophe where left out (the console passes its `&apos;` one).
  esc?: (value: unknown) => string;
}

/**
 * How a shell is sent.
 */
interface ServeOptions {
  // The origins of other listeners the runtime calls, for `connect-src`.
  connect?: string[];
  // Directives beyond `script-src`, `connect-src` and `style-src`, or
  // replacing them; `frame-ancestors` and `base-uri` cannot be.
  csp?: Record<string, string>;
  // Compress the document where the request accepts it.
  compress?: boolean;
  // The realm's path prefix, for the rewrite a compressed body needs.
  prefix?: string;
}

/**
 * A surface's file as built: the text and its precompressed forms.
 */
interface BuiltFile {
  raw: Buffer;
  br: Buffer | null;
  gzip: Buffer | null;
  // Whether the build wrote it, or `raw` is the placeholder.
  built: boolean;
}

/**
 * The default viewport.
 */
const VIEWPORT = 'width=device-width, initial-scale=1';

/**
 * The static surfaces' shell document and file sending. A static utility
 * class; it holds no state.
 */
class ShellDocument {
  /**
   * Escapes text for HTML.
   *
   * @param value - anything
   * @returns the escaped text
   */
  // Per value drawn, so no Entering/Leaving pair — the hot-path exception
  // the code style allows, stated.
  static esc(value: unknown): string {
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  /**
   * Draws a shell document.
   *
   * @param spec - what it is drawn from
   * @returns the document, ending in a newline
   */
  static document(spec: ShellSpec): string {
    log.debug("Entering ShellDocument.document(). " + spec.title);
    const esc = spec.esc || ShellDocument.esc;
    const refused = spec.refusal !== null && spec.refusal !== undefined;
    const attributes = (spec.attributes || []).filter(function (one) {
      return one && one[1];
    }).map(function (one) {
      return ' ' + one[0] + '="' + esc(one[1]) + '"';
    }).join('');
    const html = '<!DOCTYPE html>\n<html lang="' + esc(spec.lang || 'en') +
      '"' + (spec.dir ? ' dir="' + esc(spec.dir) + '"' : '') + attributes +
      '><head><meta charset="utf-8"><meta name="viewport" content="' +
      esc(spec.viewport || VIEWPORT) + '"><title>' + esc(spec.title) +
      '</title>' + spec.stylesheets.map(function (href) {
        return '<link rel="stylesheet" href="' + esc(href) + '">';
      }).join('') +
      (refused ? '' : '<script src="' + esc(spec.script) +
                      '" defer></script>') +
      '</head><body>' + spec.open +
      (refused ? spec.refusal
               : '<noscript>' + spec.noscript + '</noscript>' + spec.loading) +
      spec.close + '</body></html>\n';
    log.debug("Leaving ShellDocument.document(). " + html.length +
              " characters.");
    return html;
  }

  /**
   * The distinct origins of a list of bases, for `connect-src`.
   *
   * @param bases - absolute URLs, or ''
   * @returns their origins, each once
   */
  static originsOf(bases: string[]): string[] {
    log.debug("Entering ShellDocument.originsOf().");
    const out = (bases || []).filter(Boolean)
      .map(function (one: string): string {
        return new URL(one).origin;
      }).filter(function (one: string, at: number, all: string[]): boolean {
        return all.indexOf(one) === at;
      });
    log.debug("Leaving ShellDocument.originsOf(). " + out.length);
    return out;
  }

  /**
   * The Content-Security-Policy a shell is sent with, through
   * `app.contentSecurityPolicy()`.
   *
   * @param app - the express app, for its policy builder
   * @param options - the other listeners' origins and extra directives
   * @returns the header value
   */
  static policy(app: Json, options?: ServeOptions): string {
    log.debug("Entering ShellDocument.policy().");
    const asked = options || {};
    const directives = Object.assign({
      'script-src': "'self'",
      'connect-src': ["'self'"].concat(asked.connect || []).join(' '),
      'style-src': "'self' 'unsafe-inline'"
    }, asked.csp || {});
    const out = app.contentSecurityPolicy(directives);
    log.debug("Leaving ShellDocument.policy().");
    return out;
  }

  /**
   * Sends a shell: its policy, `no-store`, and the document, compressed
   * where the surface asks and the request accepts.
   *
   * @param app - the express app, for its policy and its realm rewrite
   * @param req - the request
   * @param res - the response
   * @param html - the document
   * @param options - the policy's origins and directives, and compression
   * @returns nothing
   */
  static serve(app: Json, req: Json, res: Json, html: string,
               options?: ServeOptions): void {
    log.debug("Entering ShellDocument.serve().");
    const asked = options || {};
    res.set('Content-Security-Policy', ShellDocument.policy(app, asked));
    res.status(200).type('text/html').set('Cache-Control', 'no-store');
    if (!asked.compress) {
      // The realm's prefix goes on the shell's links in `app.js`'s `send()`,
      // as on every page.
      res.send(html);
      log.debug("Leaving ShellDocument.serve(). Uncompressed.");
      return;
    }
    const prefix = asked.prefix || '';
    ShellDocument.sendCompressed(req, res, html, null, function (text) {
      return app.withRealmLinks(text, prefix);
    });
    log.debug("Leaving ShellDocument.serve().");
  }

  // WHICH ENCODING A RESPONSE TAKES (rcbj, 2026-10-05): brotli where the
  // request accepts it, else gzip, else none — `q=0` refuses one.
  /**
   * The content coding to answer a request with.
   *
   * @param header - the request's Accept-Encoding
   * @returns `br`, `gzip` or '' for none
   */
  static acceptedEncoding(header: unknown): string {
    log.debug("Entering ShellDocument.acceptedEncoding().");
    const offered = {};
    String(header || '').split(',').forEach(function (part) {
      const bits = part.trim().split(';');
      const name = bits[0].trim().toLowerCase();
      const q = /q=([0-9.]+)/.exec(bits.slice(1).join(';'));
      if (name) {
        offered[name] = q ? Number(q[1]) : 1;
      }
    });
    const takes = function (name: string): boolean {
      log.debug("Entering takes(). " + name);
      const q = name in offered ? offered[name] : offered['*'];
      log.debug("Leaving takes().");
      return q !== undefined && q > 0;
    };
    const out = takes('br') ? 'br' : (takes('gzip') ? 'gzip' : '');
    log.debug("Leaving ShellDocument.acceptedEncoding(). " +
              (out || 'identity'));
    return out;
  }

  // ONE OF A SURFACE'S FILES, COMPRESSED WHERE THE REQUEST ACCEPTS IT:
  // `packed` is a build's precompressed bytes, used when present; anything
  // else is compressed now, at a level that costs about a millisecond for a
  // stylesheet or a shell. `finish` is what the realm middleware's `send()`
  // does to an HTML string (its links prefixed with the realm's), done here
  // first because compressed bytes pass that override untouched — and NOT
  // done to the plain string, which the override still rewrites.
  /**
   * Sends a surface's file, compressed when the request accepts it; the
   * caller has set its type and caching.
   *
   * @param req - the request
   * @param res - the response
   * @param text - the file as served uncompressed
   * @param packed - precompressed forms (`br`, `gzip`), or null
   * @param finish - what the realm middleware would do to the text, or null
   * @returns nothing
   */
  static sendCompressed(req: Json, res: Json, text: string | Buffer,
                        packed: Json, finish: ((s: string) => string) | null)
                        : void {
    log.debug("Entering ShellDocument.sendCompressed().");
    res.vary('Accept-Encoding');
    const encoding = ShellDocument.acceptedEncoding(
      req.headers && req.headers['accept-encoding']);
    if (!encoding) {
      res.send(text);
      log.debug("Leaving ShellDocument.sendCompressed(). Uncompressed.");
      return;
    }
    let bytes = packed && packed[encoding];
    if (!bytes) {
      const final = Buffer.isBuffer(text) ? text
        : Buffer.from(finish ? finish(text) : text, 'utf8');
      bytes = encoding === 'br'
        ? zlib.brotliCompressSync(final, { params: {
            [zlib.constants.BROTLI_PARAM_QUALITY]: 5,
            [zlib.constants.BROTLI_PARAM_SIZE_HINT]: final.length } })
        : zlib.gzipSync(final, { level: 6 });
    }
    res.set('Content-Encoding', encoding).send(bytes);
    log.debug("Leaving ShellDocument.sendCompressed(). " + encoding + ", " +
              bytes.length + " bytes.");
  }

  /**
   * Reads a surface's built file and the `.br` and `.gz` beside it. A tree
   * that was never built (a checkout) has none: `raw` is then the
   * placeholder, a script that says so.
   *
   * @param dir - the directory the build wrote it in
   * @param name - its file name, `portal-spa.js`
   * @param placeholder - what to serve when it was not built
   * @returns the file and its precompressed forms
   */
  static readFile(dir: string, name: string,
                  placeholder: string): BuiltFile {
    log.debug("Entering ShellDocument.readFile(). " + name);
    const read = function (file: string): Buffer | null {
      log.debug("Entering read(). " + file);
      try {
        const bytes = fs.readFileSync(path.join(dir, file));
        log.debug("Leaving read(). " + bytes.length + " bytes.");
        return bytes;
      } catch (e) {
        // Not built, or that coding was not written: the placeholder, or
        // the coding compressed per request instead.
        log.debug("Caught in read(): " + ((e && e.message) || e));
        log.debug("Leaving read(). None.");
        return null;
      }
    };
    const raw = read(name);
    const out: BuiltFile = {
      raw: raw || Buffer.from(placeholder, 'utf8'),
      br: raw ? read(name + '.br') : null,
      gzip: raw ? read(name + '.gz') : null,
      built: !!raw
    };
    log.debug("Leaving ShellDocument.readFile(). " +
              (out.built ? 'Built.' : 'Not built; the placeholder.'));
    return out;
  }

  /**
   * Sends a surface's built file: its type, `no-cache` (a new build is
   * picked up on the next load, with no version in the address), and the
   * coding the request accepts.
   *
   * @param req - the request
   * @param res - the response
   * @param file - `readFile()`'s answer
   * @param type - its media type, `application/javascript`
   * @returns nothing
   */
  static sendFile(req: Json, res: Json, file: BuiltFile, type: string): void {
    log.debug("Entering ShellDocument.sendFile().");
    res.set('Cache-Control', 'no-cache').type(type);
    ShellDocument.sendCompressed(req, res, file.raw,
                                 { br: file.br, gzip: file.gzip }, null);
    log.debug("Leaving ShellDocument.sendFile().");
  }
}

export = ShellDocument;
