// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

// File: common/web_safe_dom.ts
// ---------------------------------------------------------------------------
// THE ONE PLACE A BROWSER RUNTIME TURNS MARKUP INTO THE PAGE (#1460, ASVS 5.0.0
// 3.2.2).
//
// The static surfaces build their pages as strings, with every value escaped
// as it is written in. A missed escape is the failure that design leaves open,
// and there are thousands of those sites. So each page goes through here: the
// markup is parsed in an inert `<template>`, where nothing loads and nothing
// runs, what could execute is taken out, and only then is it adopted.
//
// Script is already blocked by each surface's policy (`script-src 'self'`).
// This is the second layer, for the day a policy is wrong.
// `tests/web_safe_dom.js` fails on an `.innerHTML =` assignment outside this
// file.
//
// AND IT IS WHERE A PAGE IN A TRUST REALM GETS THE REALM'S PREFIX (#2098).
// The renderers draw root-relative addresses (`/admin/users`), and a page
// drawn whole had them prefixed by `WebPage.realmLinks()`; markup drawn
// LATER — a redrawn list, a search's results, a table an inspection
// answered — went in without it, so in a realm a form posted natively to
// the DEFAULT realm's path, which the runtime does not claim and the
// default realm refuses. Every draw comes through here, so the prefix is
// applied here, to every root-relative `href`, `action`, `formaction` and
// `src`, on every draw: the page's runtime names where its prefix is read
// from once (`realmFrom()`, which `WebPage`'s constructor calls), and a
// value that already carries the prefix is left as it is, so a page the
// runtime prefixed first and a caller that passes the prefix in itself
// (#2096's `derivedBindings()`) are not prefixed twice. An address a
// `data-*` attribute carries (`data-wsp-redraw`) is prefixed where it
// becomes one of those four, in the markup it is drawn into.
// `tests/web_realm_links.js` holds it.
//
// Runs in a browser, so no Entering/Leaving pair.
// ---------------------------------------------------------------------------

const REMOVED = ['script', 'iframe', 'frame', 'frameset', 'object', 'embed',
  'base', 'meta', 'link', 'animate', 'animatemotion', 'animatetransform',
  'set'];
const URL_ATTRIBUTES = ['href', 'xlink:href', 'src', 'action', 'formaction',
  'poster', 'background'];
const SAFE_URL = /^(?:https?:|mailto:|tel:|blob:|data:image\/|[^:]*$)/i;
// A KEY OR A CERTIFICATE HANDED OVER ONCE is drawn as a link with `download`
// and a `data:` address, so that it is never at a URL anything could log: a
// keytab, a key pair, a PKCS#12. A browser saves such a link and renders
// nothing, and only these file types qualify, so a `data:` document is still
// taken out, with or without `download`.
const DOWNLOAD_URL = new RegExp('^data:application/(?:octet-stream|json|' +
  'jwk\\+json|jose|pkcs8|x-pem-file|x-pkcs12);base64,', 'i');

// Where the page's realm prefix is read, asked at each draw because a runtime
// may move between realms (`/report`'s realm switch, the console's back
// button across realms).
let realmPrefix: () => string = function (): string {
  return '';
};

class WebSafeDom {
  /**
   * Names where the page's realm prefix is read from, for every draw after
   * this call. A page has one runtime, and its base (`WebPage`) calls this.
   *
   * @param source - answers the prefix, `/realm/acme`, or '' in the default
   *   realm
   */
  static realmFrom(source: () => string): void {
    realmPrefix = typeof source === 'function' ? source
      : function (): string {
        return '';
      };
  }

  /**
   * Prefixes every root-relative `href`, `action`, `formaction` and `src`
   * with a realm's path prefix, except one that already carries it:
   * `common/app.js`'s `withRealmLinks()`, in the browser.
   *
   * @param html - the markup
   * @param prefix - the realm's path prefix, or '' for the default realm
   * @returns the markup with its links in the realm
   */
  static realmLinks(html: string, prefix: string): string {
    if (!prefix) {
      return String(html);
    }
    // THE PREFIX GOES INSIDE AN ATTRIBUTE, so it is escaped as one (Qualys
    // QID 150938, 2026-11-10). It comes from the shell's own
    // `data-sts-prefix` or from `location.pathname`, which a browser has
    // already percent-encoded, so nothing could break out of the quotes; the
    // escape makes that a property of this function rather than of its
    // callers.
    const safe = String(prefix).replace(/&/g, '&amp;').replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    // ALREADY IN THE REALM is the prefix followed by the end of a path
    // segment, so `/realm/acme` is not taken for `/realm/acmeco`; that is
    // what makes a second draw of the same markup harmless.
    const own = safe.slice(1).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const link = new RegExp('\\b(href|action|formaction|src)="\\/(?!\\/)' +
                            '(?!' + own + '(?:[/?#"]))', 'g');
    // `$` is doubled because the replacement is a pattern.
    return String(html).replace(link,
                                '$1="' + safe.replace(/\$/g, '$$$$') + '/');
  }

  // The markup, as text, with the page's realm prefix on its links.
  private static inRealm(markup: unknown): string {
    const html = markup === null || markup === undefined ? '' : String(markup);
    return WebSafeDom.realmLinks(html, String(realmPrefix() || ''));
  }

  /**
   * Sets an element's content to text, never markup.
   *
   * @param element - the element
   * @param value - the text
   */
  static text(element: any, value: unknown): void {
    element.textContent = value === null || value === undefined
      ? '' : String(value);
  }

  /**
   * Takes what could execute out of a parsed tree.
   *
   * @param root - the tree
   */
  static clean(root: any): void {
    const all = Array.prototype.slice.call(root.querySelectorAll('*'));
    all.forEach(function (node: any): void {
      if (REMOVED.indexOf(String(node.localName).toLowerCase()) >= 0) {
        node.remove();
        return;
      }
      const attributes = Array.prototype.slice.call(node.attributes);
      const saved = attributes.some(function (a: any): boolean {
        return String(a.name).toLowerCase() === 'download';
      });
      attributes.forEach(function (a: any) {
        const name = String(a.name).toLowerCase();
        const value = String(a.value).replace(/[\u0000- ]/g, '');
        const safeUrl = SAFE_URL.test(value) ||
          (saved && name === 'href' && DOWNLOAD_URL.test(value));
        if (name.indexOf('on') === 0 || name === 'srcdoc' ||
            (URL_ATTRIBUTES.indexOf(name) >= 0 && !safeUrl)) {
          node.removeAttribute(a.name);
        }
      });
    });
  }

  /**
   * Replaces an element's content with markup, once it is safe to adopt.
   *
   * @param element - the element
   * @param markup - the markup
   */
  static render(element: any, markup: unknown): void {
    const html = WebSafeDom.inRealm(markup);
    // Every element in a page has an owner document; a test's stand-in has
    // none.
    if (!element.ownerDocument) {
      element.innerHTML = html;
      return;
    }
    element.replaceChildren(WebSafeDom.fragment(element.ownerDocument, html));
  }

  // Parsed and cleaned, ready to adopt.
  private static fragment(document: any, markup: unknown): any {
    const template = document.createElement('template');
    template.innerHTML = String(markup === null || markup === undefined
      ? '' : markup);
    WebSafeDom.clean(template.content);
    return template.content;
  }

  /**
   * Puts markup at the start or the end of an element.
   *
   * @param element - the element
   * @param position - `afterbegin` or `beforeend`
   * @param markup - the markup
   */
  static insert(element: any, position: string, markup: unknown): void {
    const html = WebSafeDom.inRealm(markup);
    if (!element.ownerDocument) {
      element.insertAdjacentHTML(position, html);
      return;
    }
    const content = WebSafeDom.fragment(element.ownerDocument, html);
    if (position === 'afterbegin') {
      element.prepend(content);
    } else {
      element.append(content);
    }
  }

  /**
   * Replaces an element, itself included, with markup.
   *
   * @param element - the element
   * @param markup - the markup
   */
  static replace(element: any, markup: unknown): void {
    const html = WebSafeDom.inRealm(markup);
    if (!element.ownerDocument) {
      element.outerHTML = html;
      return;
    }
    element.replaceWith(WebSafeDom.fragment(element.ownerDocument, html));
  }
}

export = WebSafeDom;
