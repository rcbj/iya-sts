// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_nav_sections.ts
//
// ---------------------------------------------------------------------------
// A NAVIGATION COLUMN OF COLLAPSIBLE SECTIONS, ONE OPEN AT A TIME (#750,
// #1229).
//
// The console's sidebar became this with #750 (rcbj: "Have everything
// collapsed by default and stay collapsed until the user opens a section.
// Only one section of the list should be open at a time."), and the user
// portal's column the same way with #1229 ("behave the same way as the
// Admin Console. Ideally, code is reused"). What the two share is here, and
// what each keeps is its own list, its own labels and its own palette:
//
//   * THE MARKUP (`section()`): a section is a `<details class="navsec"
//     name="<group>" data-section="<key>">` whose `<summary class="navhead">`
//     is the heading and whose `<ul>` holds the caller's items. The heading
//     is not a link: there is no page behind a section, and what it does is
//     open and close it. `current` marks the section holding the page being
//     drawn whether or not it is open, so a reader on a deep link can see
//     where they are without opening every section.
//   * THE ONE-OPEN RULE is the shared `name` (an exclusive accordion, no
//     script). `toggled()`, fed every `toggle` in the capture phase (it does
//     not bubble), closes the others itself for a browser that predates
//     `name`, and says what the reader's choice now is.
//   * THE READER'S CHOICE is held by each runtime, NOT in storage: `null`
//     until the first drawing, which opens the section holding the page
//     (`initial()`); after that the key the reader opened, or `''` when they
//     closed it, so a section stays as they left it from page to page.
//   * THE STYLE OF THE HEADING (`css()`, `narrowCss()`): a triangle that
//     turns, a pointer, a focus ring, and the rule down the left of the
//     current section — in the caller's colours.
//
// A `web_` MODULE, on `admin-ui/web_kit.ts`'s terms: it requires nothing,
// logs nothing (code that runs in a browser is exempt from the Entering /
// Leaving rule), and reaches the browser only through what it is handed. The
// two server modules that build a stylesheet (`admin-ui/admin.ts`,
// `portal/web_portal_kit.ts`) read `css()` from it as well.
// ---------------------------------------------------------------------------

type Json = any;

/**
 * The collapsible sections of a navigation column. A static utility class;
 * it holds no state — the reader's choice is the runtime's.
 */
class WebNavSections {
  /**
   * Draws one section.
   *
   * @param section - `group` (the shared `name`), `key` (its
   *   `data-section`), `current` (it holds the page), `open`, `title` (the
   *   heading, as HTML), `what` (the heading's tooltip, as text) and `items`
   *   (the `<li>`s, as HTML)
   * @returns the `<details>` as HTML
   */
  static section(section: Json): string {
    const esc = WebNavSections.esc;
    return '<details class="navsec' + (section.current ? ' current' : '') +
      '" name="' + esc(section.group) + '" data-section="' +
      esc(section.key) + '"' + (section.open ? ' open' : '') + '>' +
      '<summary class="navhead" title="' + esc(section.what) + '">' +
      section.title + '</summary><ul>' + section.items + '</ul></details>';
  }

  // A RELOAD HAS NO REMEMBERED SECTION. The choice starts `null`, so the
  // first drawing opens the section that holds the page. A toggle after
  // that records what the reader opened, or '' when they closed it, and
  // that is what later drawings use.
  /**
   * The section to draw open.
   *
   * @param chosen - the runtime's choice so far, `null` before any drawing
   * @param holding - the key of the section holding the page, '' for none
   * @returns the choice from here on
   */
  static initial(chosen: string | null, holding: string): string {
    return chosen === null ? holding : chosen;
  }

  // Opening one records it and closes any other: the shared `name` already
  // does that in a browser that knows it, where the loop finds nothing open,
  // and in one that predates it the loop IS the one-open rule. Closing the
  // one recorded forgets it; the `toggle` for a section the browser closed
  // because another opened does not, whichever order the two arrive in.
  /**
   * Answers a `toggle` on the column: the reader's choice after it.
   *
   * @param doc - the document, for the other open sections
   * @param selector - selects this column's open sections
   * @param target - the element the `toggle` was fired at
   * @param chosen - the reader's choice before it
   * @returns the reader's choice after it (unchanged for any other element)
   */
  static toggled(doc: Json, selector: string, target: Json,
                 chosen: string | null): string | null {
    if (!target || !target.classList ||
        !target.classList.contains('navsec') ||
        typeof target.getAttribute !== 'function') {
      return chosen;
    }
    const key = String(target.getAttribute('data-section') || '');
    if (!target.open) {
      return chosen === key ? '' : chosen;
    }
    const open = doc && doc.querySelectorAll
      ? doc.querySelectorAll(selector) : [];
    for (let i = 0; i < open.length; i++) {
      if (open[i] !== target) {
        open[i].open = false;
      }
    }
    return key;
  }

  // The section heading, a `<summary>`: it opens and closes the section,
  // and nothing else. Not a link and it must not look like one — there is
  // no page behind a section — so it keeps the small capitals and gains
  // only a triangle and a pointer. `list-style:none` and the WebKit
  // pseudo-element take the browser's own marker off, so the triangle is
  // drawn once, here, and turns when the section opens. The padding is
  // what makes a heading this small an easy thing to hit.
  //
  // The section the current page is in, open or closed, carries a rule down
  // its left rather than a background, so that the mark reads as "you are in
  // here" and not as a second selected item beside the selected one — and,
  // on a closed section, as the way back to the page you are on.
  /**
   * The sections' rules for the wide layout.
   *
   * @param accent - the brand colour: hover, focus and the current section
   * @param muted - a heading's colour otherwise
   * @param inset - the column card's left padding, in px, which the current
   *   section's rule sits in
   * @returns the CSS
   */
  static css(accent: string, muted: string, inset: number): string {
    return '.navsec{margin:0 0 4px}.navsec:last-child{margin-bottom:4px}' +
      '.navhead{display:block;cursor:pointer;list-style:none;margin:0;' +
      'padding:4px 0;font-size:.7em;text-transform:uppercase;' +
      'letter-spacing:.06em;color:' + muted + ';font-weight:700}' +
      '.navhead::-webkit-details-marker{display:none}' +
      '.navhead::before{content:"\\25B8";display:inline-block;width:1.1em;' +
      'transition:transform .15s}.navsec[open]>.navhead::before{transform:' +
      'rotate(90deg)}.navsec[open]>.navhead{margin-bottom:4px}' +
      '.navsec[open]{margin-bottom:10px}.navhead:hover{color:' + accent +
      '}.navhead:focus-visible{outline:2px solid ' + accent +
      ';outline-offset:2px;border-radius:3px}' +
      '.navsec.current{border-left:3px solid ' + accent + ';margin-left:-' +
      inset + 'px;padding-left:' + (inset - 3) + 'px}.navsec.current>' +
      '.navhead{color:' + accent + '}';
  }

  // One column on a narrow screen, and the sections laid out across the top
  // rather than stacked; the current section's rule moves to its top edge.
  /**
   * The sections' rules inside the narrow layout's media query.
   *
   * @param accent - the brand colour
   * @param minWidth - a section's least width
   * @returns the CSS, to be placed inside the caller's `@media`
   */
  static narrowCss(accent: string, minWidth: string): string {
    return '.navsec{display:inline-block;vertical-align:top;min-width:' +
      minWidth + ';margin-right:1.2em}.navsec.current{margin-left:0;' +
      'padding-left:0;border-left:0;border-top:3px solid ' + accent +
      ';padding-top:6px}';
  }

  /**
   * Escapes text for HTML.
   *
   * @param value - the text
   * @returns the escaped text
   */
  static esc(value: unknown): string {
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
}

export = WebNavSections;
