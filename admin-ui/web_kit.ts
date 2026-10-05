// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_kit.ts
//
// ---------------------------------------------------------------------------
// THE CONSOLE'S RENDERING KIT, AS A MODULE A BROWSER CAN LOAD (#446,
// 2026-10-05).
//
// The admin console is being converted from pages this process draws into a
// static application that draws them in the browser from `/admin-api`'s JSON
// (#446). rcbj's decision is that the pages are NOT rewritten for it: they are
// TypeScript functions from a view to a string of markup already, and those
// functions are kept and bundled for the browser as they are
// (`build-typescript.sh`, esbuild). This file is the first of them — the
// helpers every page is drawn with — and every file whose name begins
// `web_` is on the same terms.
//
// **WHAT A `web_` MODULE MAY REQUIRE: ANOTHER `web_` MODULE, AND NOTHING
// ELSE.** No logger, no `config`, no `realms`, no store, nothing of node's.
// It runs in two places — in this process, where the server-rendered console
// calls it until the cutover, and in a browser — and the second has none of
// those. The bundler is the proof: esbuild is run for a browser, so a
// `web_` module that reaches a server module does not build, and
// `tests/console_web_bundle.js` holds the rule on the sources as well.
//
// **A STATIC UTILITY CLASS** (issue #50's rule for small helpers): it holds no
// state and takes no dependencies.
//
// **NO ENTERING/LEAVING LINES, for two reasons that each suffice.** It runs in
// a browser, which the code style exempts; and these are the console's hot
// path — `note()` alone is called about three hundred times to draw
// `/admin/config` — which `admin-ui/admin.ts` has always exempted, with the
// argument beside the methods there that are now delegates to these.
//
// **WHAT MOVED HERE WAS MOVED VERBATIM** from `AdminConsole` in
// `admin-ui/admin.ts`: `plainTextOf()` to `wideTable()` below, with their
// comments, and the three measures a fold is decided against. `esc()` is
// `common/helpers.js`'s `xmlEscape()`, which is what `AdminConsole.esc()`
// has always called, written out because this file may not require it:
// `&apos;` for an apostrophe, where `common/html.ts` writes `&#39;` — the
// difference is invisible in a browser and visible in a byte comparison, and
// a page drawn here must be the page the console drew.
// ---------------------------------------------------------------------------

// About one rendered line of `.note` text in this console's content column.
// The column is 62rem at `.note`'s .78em, so a line is nearer 130 characters
// than this; the number is deliberately under that, because the test worth
// applying is "does this read as a paragraph" rather than "does it wrap".
const ONE_LINE_CHARS = 110;

// A summary has to fit on one line beside its marker, whatever the note it
// opens. Past this the opening sentence is truncated rather than allowed to
// become the wall of text this exists to fold away.
const SUMMARY_CHARS = 96;

// A tooltip may run to a couple of lines where a summary may not: it is drawn
// over the page rather than in it, so length costs a reader nothing until they
// ask for it. Past this it is truncated, because a browser renders a title of
// any length and one of them will happily draw a paragraph the width of the
// screen.
const TIP_CHARS = 190;

/**
 * The console's rendering kit: escaping, the statistics tile, and the prose
 * helpers that fold a paragraph longer than a line. Loadable in a browser;
 * it requires nothing.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class WebKit {
  /**
   * About one rendered line of `.note` text: past this a note is folded.
   */
  static readonly ONE_LINE_CHARS = ONE_LINE_CHARS;

  /**
   * The longest summary a fold may carry.
   */
  static readonly SUMMARY_CHARS = SUMMARY_CHARS;

  /**
   * The longest tooltip `tip()` writes by default.
   */
  static readonly TIP_CHARS = TIP_CHARS;

  // `common/helpers.js`'s `xmlEscape()`, to the byte — see the header.
  /**
   * Escapes a value for HTML, drawing null and undefined as empty.
   *
   * @param v - the value to escape
   * @returns the escaped text, with an apostrophe as `&apos;`
   */
  static esc(v): string {
    return String(v == null ? '' : v)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&apos;');
  }

  /**
   * Draws one statistics tile.
   *
   * @param n - the number
   * @param label - what it counts
   * @returns the tile as HTML
   */
  static tile(n, label): string {
    return '<div class="tile"><div class="n">' + WebKit.esc(n) +
           '</div><div class="l">' + WebKit.esc(label) + '</div></div>';
  }

  // The visible text of a fragment of markup — tags removed, whitespace
  // collapsed, AND ENTITIES LEFT EXACTLY AS THEY WERE.
  //
  // Leaving them is the whole of the fix for a bug this had twice: `&apos;` and
  // `&rarr;` appeared in summaries as themselves. Decoding an entity here and
  // escaping the result on the way into a <summary> turns `&apos;` into
  // `&amp;apos;`, and the escaping cannot be dropped without deciding whether
  // the text was escaped in the first place.
  //
  // So the rule is the other one, and it holds for every caller in this file:
  // WHAT COMES IN IS A VALID HTML FRAGMENT — prose written as markup, or a
  // value already through esc() — so what comes out is valid HTML text and goes
  // into a <summary> UNESCAPED. A caller that hands this an unescaped `<` loses
  // it to the tag stripper either way, which is the same thing escaping would
  // have done to it.
  /**
   * Returns a fragment's visible text: tags removed, whitespace collapsed.
   *
   * Entities are left as they were, so the result is still valid HTML text.
   *
   * @param html - an HTML fragment
   * @returns the text
   */
  static plainTextOf(html) {
    return String(html == null ? '' : html)
      .replace(/<[^>]*>/g, '')
      .replace(/\s+/g, ' ')
      .trim();
  }

  // How long that text READS, which is not its length: `&mdash;` is one dash
  // and seven characters. Only the two measurements use this — what goes on the
  // page is always plainTextOf()'s own output.
  /**
   * Measures how long text reads, counting each entity as one character.
   *
   * @param text - plainTextOf()'s output
   * @returns the length
   */
  static visibleLength(text) {
    return text.replace(/&(?:#\d+|#x[0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]*);/g,
                        '-').length;
  }

  // Where the opening sentence ends, as an offset INTO THE MARKUP — or -1 if it
  // cannot be cut there.
  //
  // The cut has to be at element depth zero and nowhere else. A sentence that
  // ends inside a `<strong>` is the ordinary case in this file's prose
  // ("<strong> This is not a second door. It posts to…</strong>"), and cutting
  // there would hand the summary an unclosed tag and the body an unopened one —
  // which no browser reports and every browser renders differently. So depth is
  // tracked and a boundary inside anything is refused; the caller then falls
  // back to a truncation, which repeats the opening in the body and is merely
  // untidy rather than broken.
  //
  // A boundary is a full stop, question or exclamation mark followed by
  // whitespace. The whitespace is what keeps `oauth2.rfc9700` and `RFC 7644`
  // out of it: an abbreviation's stop is followed by a letter, not a space. The
  // thirty-character minimum is what keeps a leading "e.g. " — or any other
  // short opener — from becoming the whole summary.
  /**
   * Finds where the opening sentence ends, as an offset into the markup.
   *
   * Only at element depth zero and at least thirty characters in.
   *
   * @param html - an HTML fragment
   * @returns the offset after the sentence's stop, or -1
   */
  static sentenceEnd(html) {
    let depth = 0;
    for (let i = 0; i < html.length; i++) {
      const c = html[i];
      if (c === '<') {
        const close = html.indexOf('>', i);
        if (close < 0) {
          return -1;
        }
        const tag = html.slice(i, close + 1);
        if (/^<\//.test(tag)) {
          depth -= 1;
        } else if (!/\/>$/.test(tag) &&
                   !/^<(br|hr|img|input|meta|link)\b/i.test(tag)) {
          depth += 1;
        }
        i = close;
        continue;
      }
      // A COLON IS NOT A SENTENCE END HERE, though it looks like one. It almost
      // always INTRODUCES the rest — "The same two halves for the assertions:
      // ..." — so cutting there produced summaries that were a fragment with
      // nothing after them, which is worse than no summary at all. A colon
      // still ends a headline (see foldOf), because a title ending in one is a
      // title.
      if (depth === 0 && i >= 30 && /[.!?]/.test(c) &&
          /^\s/.test(html.slice(i + 1, i + 2))) {
        return i + 1;
      }
    }
    return -1;
  }

  // The opening sentence, cut short at a word boundary if it is longer than a
  // summary line. The ellipsis is not decoration: it is what tells a reader
  // that the words in the summary are the words the body opens with, so that
  // the repetition below reads as *read more* rather than as the same sentence
  // printed twice.
  /**
   * Cuts text to a summary line at a word boundary, ending in an ellipsis.
   *
   * @param text - the text
   * @param max - optional; the length, SUMMARY_CHARS by default
   * @returns the text, cut if it was longer
   */
  static teaserOf(text, max?) {
    const limit = max || SUMMARY_CHARS;
    if (WebKit.visibleLength(text) <= limit) {
      return text;
    }
    let cut = text.slice(0, limit);
    const space = cut.lastIndexOf(' ');
    if (space > 40) {
      cut = cut.slice(0, space);
    }
    // ---------------------------------------------------------------------
    // A CUT CAN LAND INSIDE AN ENTITY — `&mda` — which a browser renders
    // literally, so the half is dropped rather than shown.
    //
    // **AND IT CAN LAND IMMEDIATELY AFTER A WHOLE ONE, WHICH IS THE CASE THIS
    // MISSED UNTIL 2026-09-11.** The two replacements ran in the order
    // entity-then-punctuation, and `;` is in the punctuation class — so a cut
    // ending `&mdash;` survived the first replacement intact (it is complete),
    // lost its semicolon to the second, and reached the page as the literal
    // text `&mdash`. Nothing on this console had ever been cut in that exact
    // place before `/admin/spiffe`'s authority note, which is why a bug in a
    // function every folded note goes through went years without being seen.
    //
    // The `;?` is the whole fix: a trailing entity is taken WHOLE where there
    // is one, and the punctuation strip then only ever sees ordinary text.
    // ---------------------------------------------------------------------
    return cut.replace(/&[a-zA-Z0-9#]*;?$/, '').replace(/[\s,.;:—-]+$/, '') +
           '&hellip;';
  }

  // The entities a title attribute cannot show, resolved. Only tip() needs it —
  // see the comment in there. `&amp;` is resolved LAST so that `&amp;lt;` comes
  // out as the four characters somebody wrote rather than as a `<`.
  /**
   * Resolves the entities a title attribute cannot show.
   *
   * @param text - the text
   * @returns the text with those entities resolved, `&amp;` last
   */
  static unescapeText(text) {
    return String(text)
      .replace(/&mdash;|&ndash;/g, '\u2014')
      .replace(/&middot;/g, '\u00b7')
      .replace(/&rarr;/g, '\u2192')
      .replace(/&hellip;/g, '\u2026')
      .replace(/&nbsp;/g, ' ')
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&quot;|&ldquo;|&rdquo;/g, '"')
      .replace(/&#39;|&apos;|&rsquo;|&lsquo;/g, "'")
      .replace(/&amp;/g, '&');
  }

  // A TOOLTIP, AS AN ATTRIBUTE READY TO GO INTO A TAG — including its leading
  // space, so a caller can drop it into markup without deciding whether one is
  // needed.
  //
  // This is the other half of the folds and it answers the other half of the
  // problem: prose long enough to be an argument folds, and prose short enough
  // to be a caption belongs ON the control it captions rather than under it.
  // Every label in this console that grows one gets the dotted underline and
  // the help cursor from a `label[title]` rule in page(), so the affordance
  // arrives with the tooltip and cannot be forgotten separately.
  //
  // NOTHING IS EVER SAID ONLY IN A TOOLTIP, and that is the rule to hold on to
  // rather than the mechanism: a title attribute is unreachable from a
  // keyboard, invisible on a touch screen and unread by most screen readers.
  // What goes in one is a shorter saying of something the page still carries —
  // which is why shortened() above, this console's first tooltip, puts the FULL
  // value in the title and the truncation on the page rather than the other way
  // round. `max` OVERRIDES THE 190-CHARACTER TEASER, AND A CALLER THAT PASSES
  // ONE IS SAYING THIS TOOLTIP IS THE ONLY COPY (2026-09-05).
  //
  // The default truncates, which was right while everything a tooltip carried
  // was also in a fold under the control — a teaser is a preview of something
  // the reader can go and read. **A field whose fold has been removed has no
  // such thing**, so truncating there would not be hiding the rest of the
  // sentence, it would be DELETING it: the median setting description is 384
  // characters and the default teaser is 190, so more than half of every one
  // would have left the product rather than the screen.
  //
  // So a field that is tooltip-only passes `Infinity` and the title carries the
  // whole text. Browsers wrap a long title perfectly well; the reason the
  // default is short is that a teaser competes with the fold under it, and
  // where there is no fold there is nothing to compete with.
  /**
   * Builds a `title` attribute, with its leading space, from prose.
   *
   * @param text - the prose, as markup or plain text
   * @param max - optional; the length, TIP_CHARS by default; `Infinity`
   *   keeps the whole text
   * @returns the attribute; empty when there is no text
   */
  static tip(text, max?) {
    const plain = WebKit.plainTextOf(text);
    if (!plain) {
      return '';
    }
    // Escaped, unlike a summary: a title attribute is TEXT rather than markup —
    // a browser shows `&mdash;` in one literally — and this is also the one
    // helper here that is handed raw strings out of config.js as often as it is
    // handed markup. esc() on an already-escaped fragment would double it, so
    // the entities are resolved for this one path.
    return ' title="' +
           WebKit.esc(WebKit.unescapeText(
             WebKit.teaserOf(plain, max || TIP_CHARS))) +
           '"';
  }

  // The summary and the body of one collapsed block. Where the opening sentence
  // could be cut out of the markup cleanly it becomes the summary and the body
  // is what is left, so nothing is said twice; where it could not, the summary
  // is a truncation and the body is the whole note.
  /**
   * Splits a note into the summary and the body of a fold.
   *
   * @param html - the note as HTML
   * @param label - a summary to use instead of the derived one, or nothing
   * @returns the `summary` and `body`, both as HTML
   */
  static foldOf(html, label) {
    if (label) {
      // A LABEL IS THE ONE THING THAT IS ESCAPED. Everything else here is text
      // taken out of markup the caller already built; a label is a plain string
      // a caller passed — a setting's own name, most often — and has been
      // through nothing.
      return { summary: WebKit.esc(label), body: html };
    }
    // THE COMMONEST SHAPE IN THIS FILE IS A BOLDED HEADLINE AND THEN THE
    // ARGUMENT FOR IT — `<strong>This is not a second door.</strong> The form
    // below posts to…` — and that headline is a better summary than any
    // sentence-splitting could find, because somebody wrote it to be one. It is
    // taken only when it ends in sentence punctuation: a bolded PHRASE opening
    // a sentence that runs on ("<strong>THE KEY</strong>, exactly as…") is part
    // of the first sentence rather than a title for the paragraph. A headline
    // under about two dozen characters is a PREFIX rather than a title —
    // `<strong>Restart to apply:</strong>` is the one that showed it, and
    // taking it left a fold whose summary was two words and whose body held the
    // reason somebody opened it for.
    const headline = /^\s*<(strong|b|em)>([\s\S]*?)<\/\1>/.exec(html);
    if (headline) {
      const title = WebKit.plainTextOf(headline[2]);
      if (title.length >= 24 && title.length <= SUMMARY_CHARS &&
          /[.:!?]$/.test(title)) {
        return { summary: title,
                 body: html.slice(headline[0].length).replace(/^\s+/, '') };
      }
    }
    const cut = WebKit.sentenceEnd(html);
    const head = cut > 0 ? WebKit.plainTextOf(html.slice(0, cut)) : '';
    if (head && head.length <= SUMMARY_CHARS) {
      return { summary: head, body: html.slice(cut).replace(/^\s+/, '') };
    }
    return { summary: WebKit.teaserOf(WebKit.plainTextOf(html)), body: html };
  }

  // A paragraph of explanation. Short ones are the paragraph they always were;
  // long ones fold. `label` overrides the derived summary and forces the fold,
  // because a caller that bothered to name a block wanted the block.
  /**
   * Draws a paragraph of explanation, folded when longer than a line.
   *
   * @param html - the paragraph as HTML
   * @param label - optional; a summary, which also forces the fold
   * @returns the note as HTML
   */
  static note(html, label?) {
    // Coerced once, here: a caller may hand this a number of rows or a
    // fragment built by a .map(), and everything below slices and measures.
    html = String(html == null ? '' : html);
    const text = WebKit.plainTextOf(html);
    if (!label && WebKit.visibleLength(text) <= ONE_LINE_CHARS) {
      return '<p class="note">' + html + '</p>';
    }
    const fold = WebKit.foldOf(html, label);
    return '<details class="note fold"><summary>' + fold.summary +
           '</summary><div class="foldbody">' + fold.body + '</div></details>';
  }

  // The same, for the amber box. A warning folds like anything else and for the
  // same reason — most of them here are a headline and three sentences of why —
  // but the box KEEPS ITS COLOUR CLOSED, so a page with a caveat on it still
  // looks like a page with a caveat on it. Folding a warning into something
  // that looks like body text would be the one case where this change hid a
  // fact rather than tidying it.
  /**
   * Draws a warning box, folded when longer than a line.
   *
   * @param html - the warning as HTML
   * @param label - optional; a summary, which also forces the fold
   * @returns the warning as HTML
   */
  static warn(html, label?) {
    // Coerced once, here: a caller may hand this a number of rows or a
    // fragment built by a .map(), and everything below slices and measures.
    html = String(html == null ? '' : html);
    const text = WebKit.plainTextOf(html);
    if (!label && WebKit.visibleLength(text) <= ONE_LINE_CHARS) {
      return '<div class="warn">' + html + '</div>';
    }
    const fold = WebKit.foldOf(html, label);
    return '<details class="warn fold"><summary>' + fold.summary +
           '</summary><div class="foldbody">' + fold.body + '</div></details>';
  }

  // A TABLE TOO WIDE FOR THE CARD, IN A BOX THAT SCROLLS SIDEWAYS. The caller
  // hands over the whole `<table>…</table>` and gets it back inside the
  // scroller `.wide` describes.
  //
  // `tabindex="0"` is not decoration: a scroll container that only a pointer
  // can move leaves the columns past its right-hand edge unreachable from a
  // keyboard, and this console has no script to give them back. Making the box
  // focusable is what lets the arrow keys move it, and it is the whole reason
  // this is a helper rather than a `<div class="wide">` written at each call
  // site — the attribute is the part somebody copying the markup would drop.
  //
  // `aria-label` names WHICH table, because a page with two of these otherwise
  // announces two identical regions and the label is the only thing telling a
  // reader arriving in one of them which it is.
  /**
   * Wraps a wide table in a focusable box that scrolls sideways.
   *
   * @param label - the region's accessible name
   * @param html - the whole table as HTML
   * @returns the wrapped table as HTML
   */
  static wideTable(label, html) {
    return '<div class="wide" tabindex="0" role="region" aria-label="' +
      WebKit.esc(label) + '">' + html + '</div>';
  }
}

export = WebKit;
