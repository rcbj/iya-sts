// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_footer.ts
//
// ---------------------------------------------------------------------------
// THE FOOTER ON EVERY HUMAN-FACING PAGE (rcbj, 2026-11-14).
//
// rcbj: "add a footer to all pages on all applications that is modeled after
// the footer for the id-proto-debugger. Keep the Documentation, Contact, and
// About links, but point at the iya-sts equivalent. For the social media
// icons, include linkedin, github icons."
//
// The model is the parent project's `client/public/partials/footer.html` and
// `client/public/css/footer.css`. What is kept from it, in its order: the
// three links (to this service's documentation, issues and repository), the
// social icons as inline `<svg>` that take the text colour through
// `fill="currentColor"`, the copyright line, and the version line with the
// build in its `title`. Its logo, its Home, Supported Standards, Terms and
// Privacy links, its "Supported by" block and its Medium, X and Mastodon
// icons are not.
//
// ONE BUILDER, TWO CALLERS. The server draws the footer into every shell and
// every error page (`common/page_footer.ts`, which reads the version from
// `common/version.js`), and a static surface's runtime draws it again each
// time it replaces the body, in the language the browser chose. Both call
// `html()` here, so the markup cannot differ between the two. The runtime
// knows no version of its own: it reads the facts off the footer the shell
// drew (`factsOf()`), so the version a page shows is the one the server
// read, and a shell drawn with NO footer — a specification's document —
// gets none from its runtime either (`drawnIn()` answers '').
//
// IT NEEDS NO SCRIPT. The links and icons are plain markup, so a page whose
// script is blocked still shows the footer the shell drew, and a
// server-drawn page under `script-src 'none'` carries it as it is.
//
// THE STYLE IS ONE RULE SET, `CSS`, served as `/web/footer.css`
// (`common/public_assets.ts`), which every shell links
// (`common/shell_document.ts`), and inlined in the error page's `<style>`
// (`common/error_page.ts`), which links no stylesheet. Its colours are the
// card's custom properties with the model's greys as their fallbacks, so a
// realm's appearance (#717) reaches the footer too; at 500px or less the
// links stack, as the model's do.
//
// A `web_` MODULE: it requires nothing, logs nothing, and names nothing of
// node's (`common/CLAUDE.md` 3cl).
// ---------------------------------------------------------------------------

type Json = any;

/**
 * What a translator offers the footer: the server's and the browser's both
 * have these two.
 */
interface FooterTranslator {
  has(key: string): boolean;
  text(key: string, params?: Record<string, unknown>): string;
}

/**
 * The facts a footer draws that are not words.
 */
interface FooterFacts {
  // M.N.O.<build>, from `common/version.js`.
  version: string;
  // `version.buildInfo()`'s line, for the title.
  buildInfo: string;
  // The current year, as the server read it.
  year: string;
}

/**
 * The three links, in the model's order.
 */
const LINKS = [
  { key: 'documentation', english: 'Documentation',
    href: 'https://rcbj.github.io/iya-sts/' },
  { key: 'contact', english: 'Contact',
    href: 'https://github.com/rcbj/iya-sts/issues' },
  { key: 'about', english: 'About',
    href: 'https://github.com/rcbj/iya-sts' }
];

// The social accounts. The icons are inlined rather than linked so they
// take the surrounding text colour through fill="currentColor" and cost no
// request; the path data is the parent project's footer's (itself the
// artwork of the footer of rcbj.net), rewrapped to 80 columns at token
// boundaries -- a line break here only ever replaces a separator between
// two path tokens, never a character inside a number, and the pieces are
// joined with a space.
const SOCIAL = [
  { name: 'LinkedIn', href: 'https://www.linkedin.com/company/18811689/',
    viewBox: '0 0 24 24',
    d: [
      'M19 3a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0',
      '1 2-2zm-.5 15.5v-5.3a3.26 3.26 0 0 0-3.26-3.26c-.85 0-1.84.52',
      '-2.32 1.3v-1.11h-2.79v8.37h2.79v-4.93c0-.77.62-1.4 1.39-1.4a',
      '1.4 1.4 0 0 1 1.4 1.4v4.93zM6.88 8.56a1.68 1.68 0 0 0 1.68',
      '-1.68c0-.93-.75-1.69-1.68-1.69a1.69 1.69 0 0 0-1.69 1.69c0 .93',
      '.76 1.68 1.69 1.68m1.39 9.94v-8.37H5.5v8.37z'
    ] },
  { name: 'GitHub', href: 'https://github.com/rcbj',
    viewBox: '0 0 496 512',
    d: [
      'M165.9 397.4c0 2-2.3 3.6-5.2 3.6-3.3.3-5.6-1.3-5.6-3.6 0-2 2.3',
      '-3.6 5.2-3.6 3-.3 5.6 1.3 5.6 3.6zm-31.1-4.5c-.7 2 1.3 4.3 4.3',
      '4.9 2.6 1 5.6 0 6.2-2s-1.3-4.3-4.3-5.2c-2.6-.7-5.5.3-6.2 2.3zm',
      '44.2-1.7c-2.9.7-4.9 2.6-4.6 4.9.3 2 2.9 3.3 5.9 2.6 2.9-.7 4.9',
      '-2.6 4.6-4.6-.3-1.9-3-3.2-5.9-2.9zM244.8 8C106.1 8 0 113.3 0',
      '252c0 110.9 69.8 205.8 169.5 239.2 12.8 2.3 17.3-5.6 17.3-12.1',
      '0-6.2-.3-40.4-.3-61.4 0 0-70 15-84.7-29.8 0 0-11.4-29.1-27.8',
      '-36.6 0 0-22.9-15.7 1.6-15.4 0 0 24.9 2 38.6 25.8 21.9 38.6',
      '58.6 27.5 72.9 20.9 2.3-16 8.8-27.1 16-33.7-55.9-6.2-112.3',
      '-14.3-112.3-110.5 0-27.5 7.6-41.3 23.6-58.9-2.6-6.5-11.1-33.3',
      '2.6-67.9 20.9-6.5 69 27 69 27 20-5.6 41.5-8.5 62.8-8.5s42.8',
      '2.9 62.8 8.5c0 0 48.1-33.6 69-27 13.7 34.7 5.2 61.4 2.6 67.9',
      '16 17.7 25.8 31.5 25.8 58.9 0 96.5-58.9 104.2-114.8 110.5 9.2',
      '7.9 17 22.9 17 46.4 0 33.7-.3 75.4-.3 83.6 0 6.5 4.6 14.4 17.3',
      '12.1C428.2 457.8 496 362.9 496 252 496 113.3 383.5 8 244.8 8zM',
      '97.2 352.9c-1.3 1-1 3.3.7 5.2 1.6 1.6 3.9 2.3 5.2 1 1.3-1 1',
      '-3.3-.7-5.2-1.6-1.6-3.9-2.3-5.2-1zm-10.8-8.1c-.7 1.3.3 2.9 2.3',
      '3.9 1.6 1 3.6.7 4.3-.7.7-1.3-.3-2.9-2.3-3.9-2-.6-3.6-.3-4.3.7z',
      'm32.4 35.6c-1.6 1.3-1 4.3 1.3 6.2 2.3 2.3 5.2 2.6 6.5 1 1.3',
      '-1.3.7-4.3-1.3-6.2-2.2-2.3-5.2-2.6-6.5-1zm-11.4-14.7c-1.6 1',
      '-1.6 3.6 0 5.9 1.6 2.3 4.3 3.3 5.6 2.3 1.6-1.3 1.6-3.9 0-6.2',
      '-1.4-2.3-4-3.3-5.6-2z'
    ] }
];

/**
 * The English of each message, where a translator does not have it (a
 * runtime whose catalogs have not arrived yet).
 */
const ENGLISH: Record<string, string> = {
  documentation: 'Documentation',
  contact: 'Contact',
  about: 'About',
  linksLabel: 'About this service',
  socialLabel: 'Iya CyberSecurity Solutions on social media',
  copyright: '© {years} Iya CyberSecurity Solutions, LLC. All rights ' +
             'reserved.',
  version: 'Version {version}'
};

/**
 * The footer's stylesheet: one rule set, for `/web/footer.css` and the
 * error page's `<style>`.
 */
const CSS =
  // On a card surface `body` is a centred flex row; the footer takes a line
  // of its own below the card (`flex-wrap`), and the two stay centred
  // together. Elsewhere `width:100%` is all it needs.
  'body:has(>.sts-footer){flex-wrap:wrap;align-content:center}' +
  '.sts-footer{flex:none;width:100%;box-sizing:border-box;clear:both;' +
  'margin:24px 0 0;padding:16px 10px 10px;text-align:center;' +
  'border-top:1px solid var(--sts-border,#ddd);' +
  'font-family:system-ui,-apple-system,"Segoe UI",Arial,sans-serif;' +
  'color:var(--sts-muted,#555);font-size:14px;line-height:1.4}' +
  // A surface's own rules for a list (the front door's rows have a rule
  // above each) must not reach the footer's two lists.
  '.sts-footer li{border:0;margin:0;padding:0;background:none}' +
  '.sts-footer :where(ul){border:0;margin:0;list-style:none}' +
  '.sts-footer-links{display:flex;flex-wrap:wrap;justify-content:center;' +
  'gap:4px;margin:0;padding:0;list-style:none}' +
  '.sts-footer-links a{display:inline-block;padding:8px 12px;' +
  'border-radius:4px;color:inherit;text-decoration:none;' +
  'font-size:16px}' +
  '.sts-footer-links a:hover,.sts-footer-links a:focus-visible{' +
  'background:rgba(127,127,127,.15);color:var(--sts-accent,#1e90ff)}' +
  '.sts-footer-social{display:flex;flex-wrap:wrap;justify-content:center;' +
  'align-items:center;gap:24px;margin:0;padding:10px 12px 0;' +
  'list-style:none}' +
  '.sts-footer-social a{display:inline-flex;align-items:center;' +
  'padding:4px;color:var(--sts-muted,#555)}' +
  '.sts-footer-social a:hover,.sts-footer-social a:focus-visible{' +
  'color:var(--sts-accent,#1e90ff)}' +
  '.sts-footer-social svg{display:block;width:18px;height:18px}' +
  '.sts-footer-copyright{padding:12px 12px 0}' +
  '.sts-footer-version{padding:2px 12px 0;font-size:11px;' +
  'color:var(--sts-faint,#999);letter-spacing:.02em;cursor:help}' +
  '@media screen and (max-width:500px){.sts-footer-links{' +
  'flex-direction:column;align-items:flex-start}' +
  '.sts-footer-links a{display:block;text-align:left}' +
  '.sts-footer-social{gap:18px}}';

/**
 * The footer's markup, its facts and its stylesheet. A static utility
 * class; it holds no state.
 */
class WebFooter {
  /**
   * The stylesheet.
   */
  static readonly CSS = CSS;
  /**
   * The three links.
   */
  static readonly LINKS = LINKS;
  /**
   * The two social accounts.
   */
  static readonly SOCIAL = SOCIAL;
  /**
   * The catalog namespace of its words.
   */
  static readonly NAMESPACE = 'footer';

  /**
   * Escapes text for HTML.
   *
   * @param value - anything
   * @returns the escaped text
   */
  static esc(value: unknown): string {
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  /**
   * One message, as text: the translator's where it has it, else English.
   *
   * @param t - a translator, or null
   * @param key - the key within the namespace
   * @param params - the values it names
   * @returns the text
   */
  static word(t: FooterTranslator | null, key: string,
              params?: Record<string, unknown>): string {
    const full = WebFooter.NAMESPACE + '.' + key;
    if (t && typeof t.has === 'function' && t.has(full)) {
      return t.text(full, params || {});
    }
    return String(ENGLISH[key] || key).replace(/\{([a-z]+)\}/g,
      function (whole: string, name: string): string {
        return params && params[name] !== undefined ? String(params[name])
                                                    : whole;
      });
  }

  /**
   * The footer.
   *
   * @param t - a translator, or null for English
   * @param facts - the version, the build line and the year
   * @returns the `<footer>` element's markup
   */
  static html(t: FooterTranslator | null, facts: FooterFacts): string {
    const esc = WebFooter.esc;
    const links = LINKS.map(function (one): string {
      return '<li><a href="' + esc(one.href) + '" target="_blank" ' +
        'rel="noopener noreferrer">' + esc(WebFooter.word(t, one.key)) +
        '</a></li>';
    }).join('');
    const social = SOCIAL.map(function (one): string {
      return '<li><a href="' + esc(one.href) + '" target="_blank" ' +
        'rel="noopener noreferrer" aria-label="' + esc(one.name) +
        '" title="' + esc(one.name) + '"><svg viewBox="' + one.viewBox +
        '" aria-hidden="true" focusable="false"><path fill="currentColor" ' +
        'd="' + one.d.join(' ') + '"/></svg></a></li>';
    }).join('');
    return '<footer class="sts-footer" data-sts-footer-version="' +
      esc(facts.version) + '" data-sts-footer-build="' +
      esc(facts.buildInfo) + '" data-sts-footer-year="' + esc(facts.year) +
      '"><ul class="sts-footer-links" aria-label="' +
      esc(WebFooter.word(t, 'linksLabel')) + '">' + links + '</ul>' +
      '<ul class="sts-footer-social" aria-label="' +
      esc(WebFooter.word(t, 'socialLabel')) + '">' + social + '</ul>' +
      '<div class="sts-footer-copyright">' +
      esc(WebFooter.word(t, 'copyright',
                         { years: WebFooter.years(facts.year) })) +
      '</div>' +
      '<div class="sts-footer-version" title="' + esc(facts.buildInfo) +
      '">' + esc(WebFooter.word(t, 'version', { version: facts.version })) +
      '</div></footer>';
  }

  /**
   * The copyright's years: the first year alone while it is still the
   * current one ("© 2026"), and the range once the year has moved on
   * ("© 2026–2027"). A year that cannot be read is the first year.
   *
   * @param year - the current year, as the footer's facts carry it
   * @returns the years the copyright names
   */
  static years(year: string): string {
    const first = 2026;
    const now = Number(year);
    return Number.isInteger(now) && now > first
      ? String(first) + '–' + String(now) : String(first);
  }

  /**
   * The facts of the footer a document already holds — the one its shell
   * drew — or null where it holds none.
   *
   * @param doc - the document
   * @returns `{ version, buildInfo, year }`, or null
   */
  static factsOf(doc: Json): FooterFacts | null {
    const el = doc && typeof doc.querySelector === 'function'
      ? doc.querySelector('footer.sts-footer') : null;
    if (!el) {
      return null;
    }
    return { version: String(el.getAttribute('data-sts-footer-version') ||
                             ''),
             buildInfo: String(el.getAttribute('data-sts-footer-build') ||
                               ''),
             year: String(el.getAttribute('data-sts-footer-year') || '') };
  }

  /**
   * The footer a runtime draws again with a page it puts in place of the
   * body: the shell's facts in the translator's language, or '' where the
   * shell drew none.
   *
   * @param doc - the document, before its body is replaced
   * @param t - the page's translator
   * @returns the markup, or ''
   */
  static drawnIn(doc: Json, t: FooterTranslator | null): string {
    const facts = WebFooter.factsOf(doc);
    return facts ? WebFooter.html(t, facts) : '';
  }

  /**
   * Draws the document's footer again in place, for a runtime that does
   * not replace the body (the reports application draws only its `<main>`).
   *
   * @param doc - the document
   * @param t - the page's translator
   * @param replace - how an element is replaced with markup
   *   (`WebSafeDom.replace`)
   * @returns whether there was a footer
   */
  static redraw(doc: Json, t: FooterTranslator | null,
                replace: (el: Json, markup: string) => void): boolean {
    const facts = WebFooter.factsOf(doc);
    if (!facts) {
      return false;
    }
    replace(doc.querySelector('footer.sts-footer'),
            WebFooter.html(t, facts));
    return true;
  }
}

export = WebFooter;
