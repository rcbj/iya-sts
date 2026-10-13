// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_description.ts
//
// ---------------------------------------------------------------------------
// THE ONE DESCRIPTION RENDERER'S PARTS (#584, 2026-10-12, under #569).
//
// Six protocol families answer a page at the root of their own path that
// says what the family is HERE — `/saml2`, `/saml11`, `/xacml`, `/ssf`,
// `/scim` and `/spiffe` — and #584 draws all six in the browser from the
// view each shell carries (`common/description_pages.ts`). The six pages
// say different things, so each family has a renderer of its own beside
// its server module (`saml/web_saml_description.ts` and the four others);
// what they share is drawn HERE, once: the page's card, a section, a
// table, a list, a note, a link, and the one move every one of them needs
// that the translator does not make — a message whose sentence holds a link
// or a run of markup (`rich()`).
//
// WORDS ARE THE CATALOG'S, FACTS ARE THE VIEW'S. A renderer's own sentences
// come from its family's namespace (`describeSaml2`, `describeSaml11`,
// `describeXacml`, `describeSsf`, `describeScim`, `describeSpiffe`); what
// the view says — an endpoint's `what`, a "does not do" line, a refusal a
// negative produces, a setting's note — is the family's description
// document, the same JSON its `?format=json` has always answered, and is
// drawn as it comes, in English (#539's decision 6, and the document is the
// family's, not this page's). Every value is escaped here or by the
// translator; only markup built HERE goes in raw.
//
// A `web_` MODULE: it requires nothing and logs nothing.
// ---------------------------------------------------------------------------

type Json = any;

// The two characters that bracket a raw slot's name in `rich()`: neither is
// escaped by the translator and neither can appear in a catalog message
// (`tests/description_pages.js` asserts the second).
const SLOT_OPEN = '';
const SLOT_CLOSE = '';

/**
 * A link: where it goes and its label, as MARKUP (a catalog message or a
 * name escaped by the caller).
 */
interface Link {
  href: string;
  label: string;
}

/**
 * What the six description pages share. A static utility class.
 */
class WebDescription {
  /**
   * Escapes text for HTML, as `Html.esc()` does.
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
   * A value as code.
   *
   * @param value - anything
   * @returns `<code>…</code>`, escaped
   */
  static code(value: unknown): string {
    return '<code>' + WebDescription.esc(value) + '</code>';
  }

  /**
   * A link.
   *
   * @param href - where it goes, as text
   * @param label - its label, as markup
   * @returns `<a href>`
   */
  static link(href: string, label: string): string {
    return '<a href="' + WebDescription.esc(href) + '">' + label + '</a>';
  }

  /**
   * A message whose sentence holds markup the translator cannot carry: a
   * link, or a run of `<code>` built from a list. `text` parameters are
   * escaped by the translator as always; each `raw` one is put in where
   * its placeholder is, as the markup it is.
   *
   * @param t - the translator
   * @param key - `namespace.key`
   * @param text - the parameters drawn as text
   * @param raw - the parameters drawn as markup
   * @returns the message as HTML
   */
  static rich(t: Json, key: string, text: Json, raw: Json): string {
    const params: Json = Object.assign({}, text || {});
    const slots = raw || {};
    Object.keys(slots).forEach(function (name: string): void {
      params[name] = SLOT_OPEN + name + SLOT_CLOSE;
    });
    let out = String(t.html(key, params));
    Object.keys(slots).forEach(function (name: string): void {
      out = out.split(SLOT_OPEN + name + SLOT_CLOSE).join(String(slots[name]));
    });
    return out;
  }

  /**
   * A message whose sentence holds links, by name.
   *
   * @param t - the translator
   * @param key - `namespace.key`
   * @param text - the parameters drawn as text
   * @param links - each link by its placeholder's name
   * @returns the message as HTML
   */
  static linked(t: Json, key: string, text: Json,
                links: { [name: string]: Link }): string {
    const raw: Json = {};
    Object.keys(links).forEach(function (name: string): void {
      raw[name] = WebDescription.link(links[name].href, links[name].label);
    });
    return WebDescription.rich(t, key, text, raw);
  }

  /**
   * Values as a run of code, joined.
   *
   * @param values - the values
   * @param joiner - between two, as markup (', ' by default)
   * @returns the markup
   */
  static codes(values: unknown[], joiner?: string): string {
    return (Array.isArray(values) ? values : []).map(function (one) {
      return WebDescription.code(one);
    }).join(joiner === undefined ? ', ' : joiner);
  }

  /**
   * A table.
   *
   * @param heads - the header cells, as markup
   * @param rows - each row's cells, as markup
   * @param empty - the one row drawn when there are none, as markup
   * @returns `<table>`
   */
  static table(heads: string[], rows: string[][], empty?: string): string {
    const body = rows.length
      ? rows.map(function (cells: string[]): string {
          return '<tr>' + cells.map(function (cell: string): string {
            return '<td>' + cell + '</td>';
          }).join('') + '</tr>';
        }).join('')
      : (empty === undefined ? ''
          : '<tr><td colspan="' + heads.length + '">' + empty +
            '</td></tr>');
    return '<table><tr>' + heads.map(function (head: string): string {
      return '<th>' + head + '</th>';
    }).join('') + '</tr>' + body + '</table>';
  }

  /**
   * A list of TEXT, each item escaped: a description document's lines.
   *
   * @param items - the lines
   * @returns `<ul>`
   */
  static textList(items: unknown): string {
    return WebDescription.list((Array.isArray(items) ? items : [])
      .map(function (one: unknown): string {
        return WebDescription.esc(one);
      }));
  }

  /**
   * A list of MARKUP.
   *
   * @param items - each item, as markup
   * @returns `<ul>`
   */
  static list(items: string[]): string {
    return '<ul>' + items.map(function (one: string): string {
      return '<li>' + one + '</li>';
    }).join('') + '</ul>';
  }

  /**
   * A section's heading.
   *
   * @param text - the heading, as markup
   * @returns `<h2>`
   */
  static h2(text: string): string {
    return '<h2>' + text + '</h2>';
  }

  /**
   * A paragraph, of a class or none.
   *
   * @param body - the paragraph, as markup
   * @param cls - its class: `sub`, `note`, `warn`, `meta` or none
   * @returns `<p>`
   */
  static p(body: string, cls?: string): string {
    return '<p' + (cls ? ' class="' + cls + '"' : '') + '>' + body + '</p>';
  }

  /**
   * The ways on at a page's foot: links joined by a middle dot.
   *
   * @param links - the links
   * @returns `<p class="sub">`
   */
  static foot(links: Link[]): string {
    return WebDescription.p(links.map(function (one: Link): string {
      return WebDescription.link(one.href, one.label);
    }).join(' &middot; '), 'sub');
  }
}

export = WebDescription;
