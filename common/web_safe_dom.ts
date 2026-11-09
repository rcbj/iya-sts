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
// Runs in a browser, so no Entering/Leaving pair.
// ---------------------------------------------------------------------------

const REMOVED = ['script', 'iframe', 'frame', 'frameset', 'object', 'embed',
  'base', 'meta', 'link', 'animate', 'animatemotion', 'animatetransform',
  'set'];
const URL_ATTRIBUTES = ['href', 'xlink:href', 'src', 'action', 'formaction',
  'poster', 'background'];
const SAFE_URL = /^(?:https?:|mailto:|tel:|blob:|data:image\/|[^:]*$)/i;

class WebSafeDom {
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
      Array.prototype.slice.call(node.attributes).forEach(function (a: any) {
        const name = String(a.name).toLowerCase();
        const value = String(a.value).replace(/[\u0000- ]/g, '');
        if (name.indexOf('on') === 0 || name === 'srcdoc' ||
            (URL_ATTRIBUTES.indexOf(name) >= 0 && !SAFE_URL.test(value))) {
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
    // Every element in a page has an owner document; a test's stand-in has
    // none.
    if (!element.ownerDocument) {
      element.innerHTML = String(markup === null || markup === undefined
        ? '' : markup);
      return;
    }
    element.replaceChildren(
      WebSafeDom.fragment(element.ownerDocument, markup));
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
    if (!element.ownerDocument) {
      element.insertAdjacentHTML(position, String(markup));
      return;
    }
    const content = WebSafeDom.fragment(element.ownerDocument, markup);
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
    if (!element.ownerDocument) {
      element.outerHTML = String(markup);
      return;
    }
    element.replaceWith(WebSafeDom.fragment(element.ownerDocument, markup));
  }
}

export = WebSafeDom;
