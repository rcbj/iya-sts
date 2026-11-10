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
//   * `data-sts-accounts="on"` WHERE `authn.multipleAccounts` IS ON in the
//     ambient realm (#561), and nothing at all where it is off. Every
//     runtime reads its browser's account list (`GET /authn-api/accounts`)
//     only where the shell says so (`WebAccounts.announced()`), so with the
//     setting off a page makes exactly the requests it made before #561 and
//     its shell is to the byte the one it was. Drawn HERE rather than by
//     each surface so that no shell can forget it: every static surface's
//     document comes through `document()`.
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
import config = require('./config');

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
  // WHETHER THE REALM'S SIGN-IN APPEARANCE APPLIES (#717,
  // `common/branding.ts`): its stylesheet after the others, its layout and
  // brand facts on `<html>`. Left out, it applies to a shell that links the
  // card (`/web/card.css`) and to no other; true or false says so outright
  // (the portal, which has a stylesheet of its own).
  branded?: boolean;
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
  // THE ORIGINS OF IMAGES THE PAGE LOADS FROM ELSEWHERE (#1300), for
  // `img-src` beside the base policy's `'self' data:`: a client's logo on
  // the sign-in and consent screens, which the browser loads and this
  // service never fetches. Only an https origin is named — anything else
  // given (a path, a wildcard, a scheme alone, http) is dropped, so this
  // door cannot widen `img-src` past the exact origins asked for.
  images?: string[];
  // Compress the document where the request accepts it.
  compress?: boolean;
  // The realm's path prefix, for the rewrite a compressed body needs.
  prefix?: string;
  // AN APPLICATION THAT IS NEVER OPENED BY ANOTHER SITE (Qualys QIDs 531930
  // and 531928, 2026-11-10): the console, the portal and the reports
  // application. `Cross-Origin-Opener-Policy: same-origin-allow-popups`, so a
  // window another site opened cannot keep a reference to it, while the
  // windows it opens itself keep theirs (the console's re-authentication
  // popup, `admin-ui/web_runtime.ts`); not `same-origin`, which would cut
  // that one off as it passes through the sign-in. And
  // `Cross-Origin-Resource-Policy: same-origin`, since no other site embeds
  // the document. NOT for the sign-in screens: a relying party may open
  // those in a popup and read the answer through its opener.
  isolated?: boolean;
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
 * The card's stylesheet (`common/public_assets.ts`), whose shells take the
 * realm's sign-in appearance (#717).
 */
const CARD_PATH = '/web/card.css';

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
   * Whether the ambient realm lets one browser hold several signed-in
   * accounts (#561): what `data-sts-accounts` says to the runtime.
   *
   * @returns `authn.multipleAccounts`; false where it cannot be read
   */
  static accountsOn(): boolean {
    log.debug("Entering ShellDocument.accountsOn().");
    let on = false;
    try {
      on = config.value('authn.multipleAccounts') === true;
    } catch (e) {
      // A setting that cannot be read is its default, which is off; the
      // shell is then the one it always was.
      log.debug("Caught in ShellDocument.accountsOn(): " +
                ((e && e.message) || e));
      on = false;
    }
    log.debug("Leaving ShellDocument.accountsOn(). " + on);
    return on;
  }

  /**
   * The ambient realm's sign-in appearance as a shell carries it (#717): its
   * stylesheet and its `<html>` attributes, or nothing for a shell it does
   * not apply to and for a realm that has set nothing.
   *
   * @param spec - the shell being drawn
   * @returns `{ attributes, stylesheet }`
   */
  static brandParts(spec: ShellSpec): { attributes: Array<[string, string]>,
                                        stylesheet: string } {
    log.debug("Entering ShellDocument.brandParts().");
    const none = { attributes: [] as Array<[string, string]>,
                   stylesheet: '' };
    const applies = spec.branded === undefined
      ? (spec.stylesheets || []).some(function (href: string): boolean {
        return String(href).split('?')[0] === CARD_PATH;
      })
      : spec.branded === true;
    if (!applies) {
      log.debug("Leaving ShellDocument.brandParts(). Not a branded shell.");
      return none;
    }
    let out = none;
    try {
      // LAZILY: `branding.ts` draws its preview with this file's escaping
      // and sending, so a require here at load would close a cycle.
      out = require('./branding').shellParts();
    } catch (e) {
      // An appearance that cannot be read draws the shell as it always was.
      log.debug("Caught in ShellDocument.brandParts(): " +
                ((e && (e as Error).message) || e));
      out = none;
    }
    log.debug("Leaving ShellDocument.brandParts(). " +
              (out.stylesheet ? 'Branded.' : 'As always.'));
    return out;
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
    const brand = ShellDocument.brandParts(spec);
    const stylesheets = spec.stylesheets.slice();
    if (brand.stylesheet) {
      // After the card's, which it overrides; at the end where a shell
      // links no card.
      const at = stylesheets.findIndex(function (href: string): boolean {
        return href.split('?')[0] === CARD_PATH;
      });
      stylesheets.splice(at >= 0 ? at + 1 : stylesheets.length, 0,
                         brand.stylesheet);
    }
    const attributes = (spec.attributes || []).concat(
      [['data-sts-accounts', ShellDocument.accountsOn() ? 'on' : ''] as
        [string, string]], brand.attributes
    ).filter(function (one) {
      return one && one[1];
    }).map(function (one) {
      return ' ' + one[0] + '="' + esc(one[1]) + '"';
    }).join('');
    const html = '<!DOCTYPE html>\n<html lang="' + esc(spec.lang || 'en') +
      '"' + (spec.dir ? ' dir="' + esc(spec.dir) + '"' : '') + attributes +
      '><head><meta charset="utf-8"><meta name="viewport" content="' +
      esc(spec.viewport || VIEWPORT) + '"><title>' + esc(spec.title) +
      '</title>' + stylesheets.map(function (href) {
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
   * The `img-src` a shell names other origins in (#1300): the base policy's
   * `'self' data:` and each https origin given exactly, or nothing to add
   * where none is usable.
   *
   * @param origins - the origins asked for
   * @returns `{ 'img-src': … }`, or an empty object
   */
  static imageSources(origins?: string[]): Record<string, string> {
    log.debug("Entering ShellDocument.imageSources().");
    const named = (origins || []).filter(function (one: string): boolean {
      let url: URL | null = null;
      try {
        url = new URL(String(one));
      } catch (e) {
        log.debug("Caught in ShellDocument.imageSources(): " +
                  ((e && (e as Error).message) || e));
        // Not a URL: named nowhere.
        url = null;
      }
      return !!url && url.protocol === 'https:' && url.origin === one;
    }).filter(function (one: string, at: number, all: string[]): boolean {
      return all.indexOf(one) === at;
    });
    log.debug("Leaving ShellDocument.imageSources(). " + named.length);
    // The base policy's own `img-src` (`common/app.js`), then the origins.
    return named.length ? { 'img-src': ["'self'", 'data:'].concat(named)
                                         .join(' ') } : {};
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
    }, ShellDocument.imageSources(asked.images), asked.csp || {});
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
    if (asked.isolated) {
      res.set('Cross-Origin-Opener-Policy', 'same-origin-allow-popups');
      res.set('Cross-Origin-Resource-Policy', 'same-origin');
    }
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
