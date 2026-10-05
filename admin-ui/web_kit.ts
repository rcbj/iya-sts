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

// ---------------------------------------------------------------------------
// THE SAME IDEA FOR A COLUMN OF THEM, AND WHY IT IS NOT shortened().
//
// shortened() above is for ONE identifier in a narrow column — a jti, eighteen
// characters and a native tooltip — and it has been right for the tokens page
// for as long as that page has existed. This is for the directory dumps, where
// the shape of the problem is different in three ways that together make a
// second function cheaper than a mode flag on the first:
//
//   * THERE ARE HUNDREDS OF THEM IN ONE CELL. `/admin/ldap/directory` prints
//     EVERY attribute of every entry, and an entry that has authenticated
//     over TLS carries a certificate subject, a serial, two thumbprints and a
//     DN — none under forty characters, several over two hundred. Wrapping
//     them (which is what the cell did before) made rows four and five lines
//     deep, so a page of fifty entries was a mile long and unreadable; NOT
//     wrapping them pushed the table out past the white card, which is the
//     complaint this was written for. Cutting them is the only answer that
//     leaves a table shaped like a table.
//   * THE VALUE IS THE POINT, so it must be recoverable. A shortened DN that
//     cannot be read in full is a dump that has quietly stopped being a dump.
//   * IT MUST BE COPYABLE, which a `title` attribute is not. Somebody hovering
//     `oauthClientSecret` here is going to paste it into a client's
//     configuration, and a native tooltip cannot be selected. So the full
//     value is a real element — see `.trunc` in page() — that the pointer can
//     move into, with `user-select:all` on it so one click takes the whole
//     thing.
//
// The `title` is set as well and is not redundant: it is what a keyboard user
// and most screen readers get, and it is what a browser with the popup
// scrolled off the edge of the window still shows. Nothing here is said only
// in a tooltip — the rule tip() states — because the full value is in the
// document twice over.
//
// `keep` is a CHARACTER count and not a width, deliberately. These cells are
// monospace and the values are opaque, so characters are the honest measure;
// a CSS width would cut mid-glyph at whatever the browser's font happened to
// be and would give the reader no idea how much was missing. The count in the
// hint is the other half of that: "218 characters" tells somebody at a glance
// whether they are looking at a thumbprint or a whole certificate.
// ---------------------------------------------------------------------------
const CLIP_CHARS = 46;

// WHICH QUERY PARAMETERS BELONG TO A SECTION'S LIST rather than to the page
// under it — the filter the reader typed and the page they had reached.
//
// It is a WHITELIST per section rather than "everything that is not ours", for
// the same reason the tokens page rebuilds its `back` field from a list of
// names instead of echoing it: what comes out of here is put into a URL this
// service hands to a browser, so the set of names has to be one this file
// wrote. It is also why a section that cannot be drilled into has no row —
// carrying a filter through a page nothing hangs under would be state nobody
// can get back to.
const LIST_PARAMS = {
  // `factor` arrived on 2026-09-10 with the second-factor roster /admin/mfa
  // used to draw. It is a VIEW of this list like `q` and `protocol` — a
  // narrowing somebody chose and expects to still be there after they clear
  // an enrolment — so it is carried through the Clear buttons on the
  // drill-down like the other two.
  '/admin/users': ['q', 'protocol', 'factor', 'per', 'page'],
  '/admin/groups': ['q', 'per', 'page'],
  // `application`, `subject`, `subjectKind` and `kind` are the PREVIEW's own
  // parameters and are deliberately NOT here: they are a question somebody
  // asked once, not a view, so carrying them through a Remove button would
  // re-ask it on every write and put a stale answer above the table. The same
  // reasoning NOT_A_VIEW applies to `notice` and `error`.
  '/admin/roles': ['q', 'per', 'page'],
  '/admin/policies': ['per', 'page'],
  '/admin/applications': ['q', 'kind', 'per', 'page'],
  '/admin/saml2': ['q', 'per', 'page'],
  '/admin/saml11': ['q', 'per', 'page'],
  '/admin/authorization-servers': ['per', 'page'],
  // GNAP's two lists and the grant state filter (gnap/gnap_admin.ts).
  '/admin/gnap': ['state', 'per', 'grantsPage', 'resourcesPage'],
  '/admin/gnap/monitor': ['per', 'page'],
  // ===== certificate enrollment list params (2026-09-13) =====
  '/admin/acme': ['per', 'certificatesPage', 'credentialsPage',
                  'accountsPage', 'hostNamesPage'],
  '/admin/acme/monitor': ['per', 'page'],
  '/admin/est': ['per', 'certificatesPage'],
  '/admin/est/monitor': ['per', 'page'],
  '/admin/scep': ['per', 'certificatesPage', 'credentialsPage'],
  '/admin/scep/monitor': ['per', 'page'],
  // The pushed-request filter and both lists' paging (2026-09-13). The page
  // rebuilds a Withdraw's `back` from its own copy of this list, because
  // `listViewFromBack()` is not exported; the two must name the same keys.
  '/admin/oauth2/monitor': ['state', 'client_id', 'per', 'page',
                            'clientsPage'],
  '/admin/spiffe/entries': ['q', 'origin', 'per', 'page'],
  '/admin/spiffe/agents': ['q', 'per', 'page'],
  '/admin/spiffe/brokers': ['q', 'per', 'page'],
  // `personq` and `personfrom` are the grant pane's search (2026-09-13), so a
  // grant or a Revoke lands back on the results the reader was working
  // through. `person` is deliberately NOT here: it is the one they picked, and
  // carrying it through the grant it was picked FOR would redraw a grant form
  // for somebody who already holds the role.
  '/admin/rbac': ['q', 'role', 'personq', 'personfrom', 'per', 'page'],
  // `family` rather than `q`: this page's filter is a family and there are ten
  // of them, so it is chosen by clicking a row of the summary table rather than
  // typed. `user` is deliberately NOT here — it is the drill-down's own leaf,
  // not the list's filter, and carrying it in the section crumb would make the
  // way back point at the page the reader is already on.
  // The delegation table's five filters and its paging. `/admin/delegation/map`
  // is the drill-down that spends them, and it carries the filters onward
  // through a form of its own — the picture and the table are filtered by one
  // control, so a reader who narrowed the table and then drew it gets the
  // picture of what they were looking at.
  // The four names after `page` are the two CHOOSER SEARCHES and their offsets
  // (chooserPane(), 2026-08-26). They are in here for the same reason `q` is:
  // a reader who searched for `esb` and clicked the one result should come back
  // from the drill-down to the page they left, and the drill-down's own copy of
  // the chooser should open holding the search they were in the middle of. It
  // is also what keeps the two searches independent of each other — each names
  // its own pair, so paging one cannot move the other.
  //
  // The eight names after those are the SEVEN LISTS' page numbers and the two
  // section searches (2026-09-01). Every list on that page is paged separately
  // and they share one `per`, so each needs a parameter of its own — and every
  // one of them has to survive a drill-down for the reason `page` does: a
  // reader who paged the grants table to 4, clicked a client and came back
  // should come back to page 4 of the grants table and not to the top of a
  // page they have already read three screens of.
  // Protocols → Delegation (2026-10-01): the register's two searches and two
  // pagings, the same names they have on Monitoring → Delegation, so a
  // Remove or Revoke answers on the page and the search it was pressed on.
  '/admin/delegation-settings': ['per', 'permq', 'grantq', 'permissionsPage',
                                 'grantsPage'],
  '/admin/delegation': ['type', 'mode', 'outcome', 'protocol', 'q', 'per',
                        'page',
                        'appq', 'appfrom', 'userq', 'userfrom',
                        'permq', 'grantq',
                        'chainsPage', 'permissionsPage', 'grantsPage',
                        'pairsPage', 'flagsPage', 'mechanismsPage'],
  // The tokens page's own three filters and its paging, here since 2026-08-26
  // because that page now HAS a drill-down: every identifier links to
  // /admin/tokens/credential, and without this entry the way back from it
  // landed on page 1 of an unfiltered list of everything this service has ever
  // issued. `session` joined the tokens page's three filters on 2026-09-04,
  // when /admin/sessions started linking to it: every row there links to the
  // credentials issued on that session, and there was no way to ask for them.
  '/admin/tokens': ['family', 'kind', 'state', 'session', 'per', 'page'],
  '/admin/sessions': ['q', 'protocol', 'per', 'page'],
  // The Shared Signals inbox's own search and paging (2026-09-10). It has no
  // drill-down, so the only thing that spends these is the Clear button's
  // `back` — which is enough on its own: a reader who searched for a username,
  // read what came back and pressed Clear should not be returned to an
  // unfiltered page 1 of a list that is now empty for two different reasons.
  '/admin/signals': ['sigq', 'per', 'receivedPage'],
  // The dead letters' two exact narrowings, their search and their paging
  // (2026-09-14). No control on that page posts, so what spends these is the
  // links between its own tables — a stream row's letters, a cause's letters
  // — each of which keeps the rest of the view as the reader left it.
  '/admin/ssf/dead-letters': ['dlq', 'dlstream', 'dlcause', 'per',
                              'lettersPage'],
  // The truststore's one list (2026-09-12). Spent by the Remove button's
  // `back`, so removing the last row on page 3 lands on page 3 — clamped to the
  // last page there is — rather than on page 1.
  '/admin/tls/trust': ['per', 'page'],
  // The Kerberos principals' two lists (2026-09-12), paged separately and
  // sharing one `per`. Spent by every row button's `back`.
  '/admin/kerberos/principals': ['per', 'peoplePage', 'servicesPage'],
  // The back-channel deliveries' filter, search and paging (2026-09-17),
  // spent by the Retry button's `back`.
  '/admin/logout': ['family', 'per', 'page', 'deliveryState', 'deliveryq',
                    'backchannelDeliveriesPage'],
  '/admin/realms': ['per', 'page'],
  '/admin/federation': ['q', 'role', 'per', 'page'],
  '/admin/oidfed': [],
  // TWO lists on one page — the global overrides and the recorded answers —
  // so each gets a page parameter of its own and they share one `per`, which
  // is the arrangement /admin/delegation already has and pagingOf()'s
  // `options.name` exists for. `q` searches the recorded half only; the
  // overrides table is one row per (application, scope) and is short by
  // construction, because somebody typed every one of them.
  '/admin/consent': ['q', 'per', 'page', 'globalsPage', 'usersPage'],
  // The CAEP page's SESSION CHOOSER (2026-09-03), which replaced a
  // `<select name="session_id">` for the reason chooserPane() gives about the
  // application one: a control here must be the same size whatever the
  // register holds, and this register grows by one row per sign-in for the
  // life of the process. `sessq` is the search, `sessfrom` its offset, and
  // `session` the one the reader picked — all three carried, because every
  // control on this page is a GET that reloads it and a reader who searched
  // for a username, paged to the second twenty and picked a session must not
  // lose any of that to pressing Emit.
  '/admin/caep': ['sessq', 'sessfrom', 'session'],
  // The CAEP SESSIONS list (2026-09-04), which has a drill-down of its own
  // since the per-session detail moved off it: every session identifier on
  // that table links to /admin/caep-sessions/session. `sessq` is the search
  // over that one table and `sessionsPage` its page, named after the list for
  // pagingOf()'s reason — that page carries a second table (the streams) and
  // a bare `page` could not serve both. `per` is shared, as it is everywhere
  // a page holds more than one list.
  // The RISC pages, on exactly the CAEP pair's terms. `acctq2` is the
  // chooser's search on the settings page and `acctq` the search on the
  // monitoring one — two names because the two are different controls on two
  // pages, and a shared name would carry a chooser's offset into a table's
  // filter. `rappq` and `rapplicationsPage` are the per-receiver section's,
  // named apart from the CAEP page's `appq` for the same reason.
  '/admin/risc': ['acctq2', 'acctfrom'],
  '/admin/risc-accounts': ['acctq', 'per', 'accountsPage',
                           'rappq', 'rapplicationsPage'],
  '/admin/caep-sessions': ['sessq', 'per', 'sessionsPage',
                          // The per-receiver section's own search and page
                          // (2026-09-04). Carried for the reason every other
                          // list's are: a reader who narrowed that table and
                          // then opened a session should come back to what
                          // they were reading.
                          'appq', 'applicationsPage']
};

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

  /**
   * How much of a long value `clipped()` draws before the full text is
   * behind a hover.
   */
  static readonly CLIP_CHARS = CLIP_CHARS;

  // `admin-core/admin_views.ts`'s `queryWith()`, written out because this
  // file may not require it; `tests/console_web_bundle.js` compares the two.
  /**
   * Builds a query string from page parameters, with some overridden; an
   * empty, null or undefined value is left out.
   *
   * @param params - the parameters to carry
   * @param overrides - the parameters to set or clear
   * @returns the query string with its `?`, or '' when nothing is left
   */
  static queryWith(params, overrides): string {
    const merged = Object.assign({}, params, overrides);
    const parts = [];
    Object.keys(merged).forEach(function (key) {
      const value = merged[key];
      if (value === '' || value === null || value === undefined) {
        return;
      }
      parts.push(encodeURIComponent(key) + '=' +
                 encodeURIComponent(String(value)));
    });
    return parts.length ? '?' + parts.join('&') : '';
  }

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

  // The three formatters below are deliberately without entering/leaving logs:
  // they are called once per table cell and would drown everything else in the
  // log.
  /**
   * Formats an instant as a UTC date and time without milliseconds.
   *
   * @param ms - milliseconds since the epoch
   * @returns the text; a dash when there is none
   */
  static whenText(ms) {
    if (!ms) return '—';
    return new Date(ms).toISOString().replace('T', ' ').replace(/\.\d+Z$/, 'Z');
  }

  // A long opaque value, shortened for the table but recoverable: the full
  // string is the title attribute, so it can be hovered and read. Truncating
  // with no way back would make the jti column decorative, and the jti is the
  // thing every button on the tokens page acts on.
  /**
   * Draws a long opaque value shortened, with the whole value in the title.
   *
   * @param value - the value to draw; a dash when empty
   * @param keep - how many characters to keep (18 when not given)
   * @returns a <code> element as HTML
   */
  static shortened(value, keep) {
    const text = String(value || '');
    if (text.length <= (keep || 18)) {
      return '<code title="' + WebKit.esc(text) + '">' +
             WebKit.esc(text || '—') + '</code>';
    }
    return '<code title="' + WebKit.esc(text) + '">' +
           WebKit.esc(text.slice(0, keep || 18)) +
           '&hellip;</code>';
  }

  /**
   * Draws a value clipped to a limit, with the whole of it on focus.
   *
   * A value over the limit gets a hover/focus panel holding the full text.
   *
   * @param value - the value to draw; a dash when null or empty
   * @param keep - the character limit (CLIP_CHARS when not given)
   * @returns the clipped value as HTML
   */
  static clipped(value, keep) {
    const text = String(value == null ? '' : value);
    const limit = keep || CLIP_CHARS;
    if (!text) {
      return '<code>&mdash;</code>';
    }
    if (text.length <= limit) {
      return '<code>' + WebKit.esc(text) + '</code>';
    }
    return '<span class="trunc" tabindex="0" title="' + WebKit.esc(text) +
      '">' +
      '<code>' + WebKit.esc(text.slice(0, limit)) + '&hellip;</code>' +
      '<span class="full"><code>' + WebKit.esc(text) + '</code>' +
      '<span class="hint">' + text.length + ' characters &mdash; click the ' +
      'value to select it all, then copy</span></span></span>';
  }

  // One attribute's values, clipped, one per line. Written once because four
  // directory pages draw exactly this cell and a fifth written by hand is the
  // one that goes back to printing the raw value.
  /**
   * Draws an attribute's values, each clipped, one per line.
   *
   * @param values - one value or an array of them
   * @param keep - optional; the character limit passed to clipped()
   * @returns the values as one inline-block column of HTML
   */
  static clippedValues(values, keep?) {
    const self = this;
    const list = Array.isArray(values) ? values : [values];
    if (!list.length) {
      return '<code>&mdash;</code>';
    }
    // ONE VALUE PER LINE, INSIDE AN INLINE BLOCK, and the wrapper is the whole
    // point of it. Joined with a bare `<br>` the second value of a multi-valued
    // attribute starts at the cell's left margin — under the attribute NAME
    // rather than under the first value — so `member` with three DNs on it read
    // as one attribute followed by two nameless ones. `display:inline-block`
    // makes the values a column of their own that begins where the first one
    // does. (They were joined with " | " on one line before 2026-09-01, which
    // has the opposite failure: five values of forty characters is a line
    // nothing can align.)
    return '<span class="vals">' + list.map(function (one) {
      return self.clipped(one, keep);
    }).join('<br>') + '</span>';
  }

  // The paging control. Drawn above and below the table both, because the
  // reason to want the next page is usually that you have just read to the
  // bottom of this one.
  //
  // The numbered links are a WINDOW around the current page rather than one per
  // page: 5,000 tokens at 50 a page is 100 links, which is a worse navigation
  // aid than none. First and last are always offered so the ends stay one click
  // away.
  //
  // IT RETURNS THE TWO COPIES RATHER THAN ONE STRING, AND THAT IS THE WHOLE
  // REASON THIS FUNCTION WAS RENAMED ON 2026-08-27.
  //
  // Every link here is a page load, and a page load lands at the top of the
  // document — so `next ›` threw the reader back past the sidebar, the folded
  // prose and the filter row to read the rows they had asked for, on pages that
  // are several thousand pixels long. The fix is the one chooserPane() and the
  // delegation filter use: the control submits to a FRAGMENT naming itself, so
  // the browser puts it back under the reader's eyes. This console runs no
  // script (app.js sets `script-src 'none'`), so nothing can restore a scroll
  // offset after the navigation and there is no other fix available.
  //
  // The fragment has to name ONE element, and this control is drawn TWICE with
  // the table between the copies. An id must be unique in a document, and the
  // two copies are not interchangeable anyway: whichever copy was clicked, the
  // reader wants the TOP of the page they have just asked for, which is the
  // head copy. So the head copy carries the id and the foot copy does not, and
  // the call site says which it is drawing — `nav.head` above the table,
  // `nav.foot` below it. Building both from one call is what stops the two from
  // drifting into controls that page different lists.
  //
  // The id is the list's OWN paging parameter, which is already unique per list
  // on a page for the reason pagingOf() gives — a drill-down draws five of
  // these and each must send its reader back to its own table, not to the first
  // one.
  /**
   * Builds the paging control for one list, as a head and a foot copy.
   *
   * Only the head copy carries the id its links' fragment names; both are
   * empty when the list fits on one page.
   *
   * @param path - the page the links point at
   * @param params - the page parameters every link carries
   * @param pg - the list's paging object from pagingOf()
   * @returns an object whose head and foot are each the control as HTML
   */
  static pageNavPair(path, params, pg) {
    const self = this;
    if (pg.pages <= 1) {
      return { head: '', foot: '' };
    }
    const anchor = 'list-' + pg.param;
    function link(page, label, title?) {
      const move = {};
      // The list's OWN parameter, off pg, so that a drill-down's five controls
      // move five different lists. Everything else in `params` rides along
      // untouched, which is what keeps the other four where the reader left
      // them.
      move[pg.param] = page;
      // The fragment is the head copy of THIS control — see the header. It
      // rides on the href rather than on the page's own URL, so a link somebody
      // copies out of here still opens where they were looking.
      return '<a href="' +
             self.esc(path + WebKit.queryWith(params, move)) + '#' +
             self.esc(anchor) +
             '"' + (title ? ' title="' + self.esc(title) + '"' :
                    '') + '>' + label + '</a>';
    }
    const out = [];
    if (pg.page > 1) {
      out.push(link(1, '&laquo; first', 'The newest rows'));
      out.push(link(pg.page - 1, '&lsaquo; prev'));
    } else {
      out.push('<span class="off">&laquo; first</span><span ' +
               'class="off">&lsaquo; prev</span>');
    }
    const from = Math.max(1, Math.min(pg.page - 3, pg.pages - 6));
    const to = Math.min(pg.pages, Math.max(pg.page + 3, 7));
    for (let n = from; n <= to; n++) {
      out.push(n === pg.page ? '<span class="here">' + n + '</span>' :
               link(n, String(n)));
    }
    if (pg.page < pg.pages) {
      out.push(link(pg.page + 1, 'next &rsaquo;'));
      out.push(link(pg.pages, 'last &raquo;', 'The oldest rows still held'));
    } else {
      out.push('<span class="off">next &rsaquo;</span><span class="off">last ' +
               '&raquo;</span>');
    }
    out.push('<span class="where">page ' + pg.page + ' of ' + pg.pages + ' — ' +
             pg.noun + ' ' +
             pg.firstRow + '&ndash;' + pg.lastRow + ' of ' + pg.total +
             '</span>');
    const inner = out.join('') + '</div>';
    return {
      head: '<div class="pagenav" id="' + WebKit.esc(anchor) + '">' + inner,
      // The same control, without the id. A list drawn with ONE copy uses
      // `head` whichever end of the table it is at, because an anchor nothing
      // points to is the bug this exists to prevent.
      foot: '<div class="pagenav">' + inner
    };
  }

  // The paging sizes the rows-per-page select offers: `admin_views.ts`'s
  // DEFAULT_PER_PAGE and MAX_ROWS, which argue the numbers. Written out
  // because this module may require no server module;
  // `tests/console_web_bundle.js` holds them equal.
  static readonly DEFAULT_PER_PAGE = 50;

  static readonly MAX_ROWS = 300;

  // Each section's list parameters, by the section's path: see the table's
  // own comment above the class.
  static readonly LIST_PARAMS = LIST_PARAMS;

  // How many results a chooser pane shows at a time: one number for the
  // console and for the replies that page the same list, so a page and its
  // resource cannot come to show different twenties. `admin_views.ts` reads
  // it from here (#446).
  static readonly CHOOSER_HITS = 20;

  // The per-page select, written once because five surfaces offer it and a
  // sixth written by hand is the one that forgets to add a hand-typed size to
  // the list.
  //
  // MAX_ROWS is offered as the largest choice so the old behaviour — everything
  // on one page, up to the cap — is still one click away for anyone who wants
  // to search the table with the browser's own find.
  //
  // A hand-typed `?per=7` is ADDED to the list rather than ignored, or the
  // select would show a size that is not the one being used and would silently
  // change it on the next Filter — which is a control that lies about the page
  // it is on.
  /**
   * Draws the options of the rows-per-page select.
   *
   * A size that is not one of the offered choices is added to the list.
   *
   * @param perPage - the page size in use, which is marked selected
   * @returns the <option> elements as HTML
   */
  static perPageOptions(perPage) {
    const choices = [25, WebKit.DEFAULT_PER_PAGE, 100, WebKit.MAX_ROWS];
    if (choices.indexOf(perPage) < 0) {
      choices.push(perPage);
      choices.sort(function (a, b) { return a - b; });
    }
    return choices.map(function (n) {
      return '<option value="' + n + '"' + (n === perPage ? ' selected' : '') +
             '>' +
             n + ' rows</option>';
    }).join('');
  }

  // The same control as a form of its own, for the two DRILL-DOWNS — which have
  // no filter form to hang it on, and which need it more than the lists do
  // because they carry several tables at once.
  //
  // Submitting it drops every page parameter, which is deliberate rather than
  // an oversight of the hidden inputs: a GET form posts its own fields and
  // nothing else, and page 4 of fifty-row pages is not page 4 of anything after
  // the size changes. Going back to the top of each list is the only answer
  // that is true of all of them.
  //
  // `carry` is the list's FILTER, and it has to be spelt out as hidden inputs
  // for the reason above: a GET form posts its own fields and nothing else, so
  // without them this control quietly empties the breadcrumb's way back to the
  // list the reader came from. Its PAGE is deliberately not carried — `per` is
  // the thing this form changes, and page 4 of fifty-row pages is not page 4 of
  // anything afterwards, which is the same sentence as the paragraph above
  // about the tables below.
  /**
   * Draws a stand-alone rows-per-table form for a drill-down page.
   *
   * Submitting it resets every table's page to the first.
   *
   * @param path - the page the form submits to
   * @param key - the name of the hidden parameter that selects the drill-down
   * @param value - that parameter's value
   * @param perPage - the page size in use
   * @param extraNote - optional; a sentence added to the form's note
   * @param carry - optional; the list filter to carry as hidden inputs
   * @returns the form as HTML
   */
  static perPageForm(path, key, value, perPage, extraNote?, carry?) {
    const carried = Object.keys(carry || {}).map(function (name) {
      return '<input type="hidden" name="' + WebKit.esc(name) + '" value="' +
             WebKit.esc(carry[name]) + '">';
    }).join('');
    const html = '<form method="get" action="' + WebKit.esc(path) + '"><div ' +
      'class="formrow"><input type="hidden" ' +
      'name="' + WebKit.esc(key) + '" value="' + WebKit.esc(value) + '">' +
      carried +
      '<label for="per">Rows per table</label>' +
      '<select id="per" name="per">' + WebKit.perPageOptions(perPage) +
      '</select><button class="secondary">Apply</button>' +
      WebKit.note('Every table below is paged separately and they share this ' +
      'size. Changing it starts each of them at its first page.' +
      (extraNote ? ' ' + extraNote : '')) +
      '</div></form>';
    return html;
  }

  // A COPY BUTTON BESIDE A VALUE (rcbj, 2026-10-01), first beside every
  // endpoint in a Protocols page's Endpoints section. The button is drawn
  // HIDDEN and carries the value it copies: `/admin/copy.js` reveals it and
  // copies on a click. With the script blocked the page is exactly what it
  // was, and the value beside it can still be selected by hand. `respond()`
  // sees the attribute and is what adds the script and relaxes the policy,
  // for that page only.
  /**
   * Draws a hidden Copy button for a value, which `/admin/copy.js` reveals.
   *
   * @param value - the text the button copies
   * @returns the markup
   */
  static copyButton(value) {
    return ' <button type="button" class="copybtn" hidden data-copy="' +
      WebKit.esc(String(value == null ? '' : value)) + '" title="Copy ' +
      'to the clipboard">Copy</button>';
  }

  // The drill-down. Its one list is the ATTRIBUTE table, which is paged under a
  // name of its own (`attributesPage`) rather than the bare `page` — the
  // convention pagingOf()'s header describes for a view that holds more than
  // the list views do, and the shape to grow into when this page gains a second
  // list.
  // ---------------------------------------------------------------------------
  // TABS WITH NO SCRIPT (2026-10-01).
  //
  // rcbj asked for an application's page to be tabs across the top, one per
  // section, so a reader does not scroll past a dozen sections to reach one.
  // This console is `script-src 'none'`, so a tab is a LINK to its panel's
  // fragment and the stylesheet shows the panel that is `:target`, or holds
  // the target (`:has(:target)`), and the first one when nothing is targeted.
  // That is what makes every control on a tab come back to it: a form's
  // answer lands at a fragment inside its own panel (withReturnAnchors(), or
  // the anchor its handler names), so the panel is shown and the page opens
  // where the button was. Every panel is in the page, so a search of the
  // page, a printout and a browser without `:has()` (which shows them all)
  // see everything. A panel with nothing in it gets no tab.
  // ---------------------------------------------------------------------------
  /**
   * Draws panels as tabs: a bar of links, then each panel with something in
   * it, the first shown when no fragment picks one.
   *
   * @param cls - an extra class for the container
   * @param panels - `{ id, label, html }` in tab order
   * @returns the tabs as HTML
   */
  static tabbedPanels(cls, panels) {
    const shown = panels.filter(function (one) {
      return String(one.html || '').trim() !== '';
    });
    return '<div class="tabs ' + WebKit.esc(cls) + '">' +
      '<nav class="tabbar" aria-label="Sections of this page">' +
      shown.map(function (one, n) {
        return '<a' + (n === 0 ? ' class="first"' : '') + ' href="#' +
          WebKit.esc(one.id) + '">' + WebKit.esc(one.label) + '</a>';
      }).join('') + '</nav>' +
      shown.map(function (one, n) {
        return '<section class="tabpanel' + (n === 0 ? ' first' : '') +
          '" id="' + WebKit.esc(one.id) + '">' + one.html + '</section>';
      }).join('') + '</div>';
  }

  // A DURATION AS A READER SAYS IT: "4 min 12 s", "2 h 5 min", "90 d" —
  // two units at most. `cluster/scheduler.ts`'s until #446, whose
  // `Scheduler.span()` now calls this.
  /**
   * Formats a duration in at most two units, such as "4 min 12 s".
   *
   * @param ms - the duration in milliseconds
   * @returns the text
   */
  static span(ms: number): string {
    const s = Math.max(0, Math.round(ms / 1000));
    const units: Array<[number, string]> = [[86400, 'd'], [3600, 'h'],
                                             [60, 'min'], [1, 's']];
    const parts: string[] = [];
    let left = s;
    units.forEach(function (unit: [number, string]): void {
      if (parts.length < 2 && (left >= unit[0] ||
                               (unit[0] === 1 && !parts.length))) {
        const n = Math.floor(left / unit[0]);
        left -= n * unit[0];
        parts.push(n + ' ' + unit[1]);
      }
    });
    return parts.join(' ');
  }

  // One query parameter's first value as text, '' when absent: Express hands
  // back an array for a repeated parameter. `admin_views.ts`'s, which calls
  // this (#446).
  /**
   * Returns one query parameter's first value as text.
   *
   * @param query - the query
   * @param key - the parameter's name
   * @returns the value, or '' when absent
   */
  static queryOne(query, key) {
    const raw = (query || {})[key];
    const value = Array.isArray(raw) ? raw[0] : raw;
    return value === undefined || value === null ? '' : String(value);
  }

  // ---------------------------------------------------------------------------
  // A ONE-BOX SEARCH OVER ONE SECTION OF A PAGE THAT CARRIES SEVERAL.
  //
  // The list views have a filter form each and they can: a page with one table
  // on it can put the filter, the page size and the search in one row above it
  // and every control there is unambiguous. /admin/delegation is seven tables,
  // and a second `q` would have been a box the reader has to guess the scope
  // of. So each searchable section gets its own parameter and its own box,
  // drawn immediately under its own heading, and the box says in its label
  // WHICH table it narrows.
  //
  // It is deliberately NOT chooserPane(). That control is a SEARCH FOR ONE
  // THING — it draws a scrolling pane of candidates and every hit is a link
  // away from this page — and this one narrows a table the reader is going to
  // stay and read. Sharing an implementation would have meant one function with
  // a mode flag deciding whether its results were the answer or the rows, which
  // is two controls wearing one name.
  //
  // THE FRAGMENT IS THE SAME TRICK AND FOR THE SAME REASON chooserPane()'s
  // header argues at length: this is a GET that reloads the page, a reload
  // lands at the top of the document, and this console runs no script (app.js
  // sets `script-src 'none'`) so nothing can restore a scroll offset
  // afterwards. Submitting to `#find-<param>` puts the box back under the
  // reader's eyes. Submitting a GET form replaces the action URL's QUERY and
  // leaves its FRAGMENT alone, which is why the anchor cannot be a hidden
  // input.
  //
  // TWO NAMES COME OUT OF THE CARRIED SET AND EACH FOR ITS OWN REASON. The
  // search term, because the text input re-emits it and a hidden input beside
  // it would submit the old one; and the section's PAGE NUMBER, because a new
  // search starts at its first page — carrying page 4 into a two-page result
  // would be clamped by pagingOf() and read as the box ignoring what was typed.
  //
  // `spec`: { path, query, param, pageParam, label, placeholder, what }
  /**
   * Draws a one-box search form over one section of a multi-table page.
   *
   * The form submits to a fragment naming itself, carries every other page
   * parameter, and drops the search term and the section's page number.
   *
   * @param spec - the path, query, param, pageParam, label, placeholder
   *   and what of the search
   * @returns the form, and the optional note under it, as HTML
   */
  static sectionSearchForm(spec) {
    const esc = WebKit.esc;
    const query = spec.query || {};
    const wanted = WebKit.queryOne(query, spec.param).trim();
    const anchor = 'find-' + spec.param;
    const carried = WebKit.pageParamsOf(query);
    delete carried[spec.param];
    delete carried[spec.pageParam];
    const hidden = Object.keys(carried).map(function (name) {
      return '<input type="hidden" name="' + esc(name) + '" value="' +
             esc(carried[name]) + '">';
    }).join('');
    return '<form method="get" id="' + esc(anchor) +
           '" class="finder" action="' +
      esc(spec.path) + '#' + esc(anchor) + '">' +
      '<div class="formrow">' + hidden +
        '<label for="' + esc(spec.param) + '">' + esc(spec.label) +
        '</label><input type="text" id="' + esc(spec.param) + '" name="' +
      esc(spec.param) +
          '" size="32" value="' + esc(wanted) + '" placeholder="' +
          esc(spec.placeholder) + '">' +
        '<button class="secondary">Search</button>' +
        (wanted
          ? ' <a href="' +
            esc(spec.path + WebKit.queryWith(carried, {})) + '#' +
            esc(anchor) +
            '">clear</a>'
          : '') +
      '</div></form>' +
      // OUTSIDE the form rather than in it. A note() longer than a line is a
      // `<details>`, and a disclosure widget inside a form is legal but reads
      // as part of the control — this sentence is about the TABLE under the
      // box.
      (spec.what ? WebKit.note(spec.what) : '');
  }
  // Seconds as a person reads them. Deliberately approximate above an hour and
  // exact below one: the interesting settings on this page are the short ones,
  // and "90 minutes" is the answer somebody wants for 5400 while "1.04 days" is
  // nobody's answer for 90000. The exact number is always beside it in its own
  // column, so this is a gloss rather than the value.
  /**
   * Words a number of seconds as a person reads it: exact below a minute,
   * to one decimal place in minutes, hours or days above.
   *
   * @param seconds - the number of seconds
   * @returns the phrase, or "no allowance at all" for zero
   */
  static humanSeconds(seconds) {
    const n = Number(seconds) || 0;
    if (n === 0) {
      return 'no allowance at all';
    }
    if (n < 60) {
      return n + ' second' + (n === 1 ? '' : 's');
    }
    if (n < 3600) {
      const minutes = n / 60;
      return (Number.isInteger(minutes) ? minutes : minutes.toFixed(1)) +
             ' minute' + (minutes === 1 ? '' : 's');
    }
    if (n < 86400) {
      const hours = n / 3600;
      return (Number.isInteger(hours) ? hours : hours.toFixed(1)) +
             ' hour' + (hours === 1 ? '' : 's');
    }
    const days = n / 86400;
    return (Number.isInteger(days) ? days :
            days.toFixed(1)) + ' day' + (days === 1 ? '' : 's');
  }

  // Does one catalogue entry match what was typed? Case-insensitive, over
  // every spelling the entry has. `admin_views.ts`'s, which calls this
  // (#446); its reasoning is there.
  /**
   * Answers whether any of an entry's names contains what was typed.
   *
   * @param names - every spelling of the entry
   * @param wanted - what was typed; '' matches everything
   * @returns true when it matches
   */
  static chooserMatches(names, wanted) {
    if (!wanted) {
      return true;
    }
    const needle = wanted.toLowerCase();
    return (names || []).some(function (name) {
      return String(name == null ? '' : name).toLowerCase().indexOf(needle) >=
             0;
    });
  }

  // The search box, the scrolling pane of results and the line under it, for
  // either kind of party. Written once because it is drawn six times — the two
  // choosers on /admin/delegation, both again on /admin/delegation/map, and one
  // each on the two drill-downs — and six hand-written copies of a control with
  // an offset in it is five chances to page one list with another's parameter.
  //
  // `spec`:
  //   here        { path, query } — THE PAGE THIS IS DRAWN ON, not the page a
  //               result opens. The form submits back to here, so a search
  //               neither leaves the page nor loses the table's filter, its
  //               paging or the other chooser's search: everything in the
  //               current query rides along as hidden inputs.
  //   param       the search box's name — `appq` / `userq`
  //   fromParam   the offset's name — `appfrom` / `userfrom`
  //   label       the box's label; `placeholder` what to type in it
  //   entries     the catalogue, each { key, names, label, detail, href }
  //   selectedKey the entry this page is already showing, marked in the pane
  //   nothing     what to say when the search matched none of them
  //   slice       optional, { matched, from }: `entries` is then the pane's
  //               results already searched and paged — by the view, for a
  //               catalogue too big to send whole (#446) — and these say how
  //               many matched and where the page starts
  /**
   * Draws a search box and a paged, scrolling pane of matching entries,
   * shared by every chooser on the console.
   *
   * The form submits back to the page it is drawn on, carrying the rest of
   * the query, with a fragment that returns the reader to the pane; a
   * stale offset is clamped to the first page.
   *
   * @param spec - here, param, fromParam, label, placeholder, entries,
   *   selectedKey and nothing, as the comment above describes
   * @returns the form, the pane and its paging note as HTML
   */
  static chooserPane(spec) {
    const esc = WebKit.esc;
    const query = (spec.here && spec.here.query) || {};
    const path = (spec.here && spec.here.path) || '';
    const wanted = WebKit.queryOne(query, spec.param).trim();

    // WHERE THE READER IS STANDING, SPELT AS A FRAGMENT SO THAT SEARCHING DOES
    // NOT MOVE THEM.
    //
    // Every control in this pane is a GET that reloads the page, and a reload
    // lands at the top of the document — so a reader who had scrolled past four
    // hundred rows of the table to reach this chooser was thrown back to the
    // heading by the very click that answered them, with the results they asked
    // for now somewhere below the fold. It got worse the longer the page was,
    // which is the same complaint the sidebar had.
    //
    // A fragment on the form's own action is the fix, and there is no other one
    // available here: this console runs no script (see app.js's `script-src
    // 'none'`), so nothing can restore a scroll offset after the navigation.
    // What the fragment CAN do is put this pane back under the reader's eyes,
    // which is what they were looking at when they pressed the button.
    //
    // It works because of a detail of the HTML form algorithm that is easy to
    // doubt and was checked in a browser rather than assumed: submitting a GET
    // form replaces the action URL's QUERY and leaves its FRAGMENT alone, so
    // `action="/admin/delegation#find-appq"` arrives as
    // `/admin/delegation?appq=x#find-appq`. That is the "mutate action URL"
    // step of the HTML standard, which sets `url`'s query and touches nothing
    // else — so a hidden input cannot do this job and there is nowhere else to
    // put the fragment.
    //
    // The name is the search box's own parameter, which is what makes it unique
    // on a page that draws this control twice — `appq` and `userq` never appear
    // in one pane, and the two panes must not send each other's readers to the
    // wrong half of the page.
    const anchor = 'find-' + spec.param;
    const sliced = spec.slice || null;
    const matched = sliced ? [] : spec.entries.filter(function (entry) {
      return WebKit.chooserMatches(entry.names, wanted);
    });
    const matchedCount = sliced ? sliced.matched : matched.length;

    // A STALE OFFSET IS CLAMPED RATHER THAN OBEYED. `?appfrom=40` is a link the
    // reader followed when 57 matched; narrowing the search to 6 would
    // otherwise answer with an empty pane under a line saying 6 matched, which
    // reads as the search being broken by the term that worked.
    let from = parseInt(WebKit.queryOne(query, spec.fromParam), 10);
    if (!isFinite(from) || from < 0 || from >= matchedCount) {
      from = 0;
    }
    if (sliced) {
      from = sliced.from;
    }
    const shown = sliced ? spec.entries
                         : matched.slice(from, from + WebKit.CHOOSER_HITS);

    // What every control here carries with it. Two names come OUT of it and
    // each for its own reason: the search term, because the text input re-emits
    // it and a hidden input beside it would submit the old one; and the offset,
    // because a NEW search starts at the first twenty — carrying 40 into a
    // two-hit search is the stale-offset case above, arrived at by typing
    // rather than by clicking.
    const carried = WebKit.pageParamsOf(query);
    delete carried[spec.param];
    delete carried[spec.fromParam];
    const hidden = Object.keys(carried).map(function (name) {
      return '<input type="hidden" name="' + esc(name) + '" value="' +
             esc(carried[name]) + '">';
    }).join('');

    // The pager's own base keeps the search term — it is paging THESE results —
    // and overrides only the offset. An offset of nothing rather than of 0, so
    // the first page of a search is the same URL whether it was reached by
    // typing or by clicking `previous`.
    const paging = WebKit.pageParamsOf(query);
    const pageLink = function (at, label, title) {
      // pageNavPair()'s own idiom, and for its reason: the control's OWN
      // parameter is the only one it sets, so the other chooser's offset and
      // the table's page stay where the reader left them.
      const move = {};
      move[spec.fromParam] = at > 0 ? at : '';
      // The anchor for the reason above: paging the results is the same click
      // as searching them, and it is a page reload just as much.
      return '<a href="' + esc(path + WebKit.queryWith(paging, move)) + '#' +
        esc(anchor) +
        '" title="' + esc(title) + '">' + label + '</a>';
    };

    const rows = shown.map(function (entry) {
      return '<li' + (entry.key && entry.key === spec.selectedKey
                        ? ' class="on"' : '') + '>' +
        '<a href="' + esc(entry.href) + '">' + esc(entry.label) +
        '</a>' +
        (entry.detail
          ? '<span class="hitwhat">' + esc(entry.detail) + '</span>' :
            '') +
        '</li>';
    }).join('');

    const pane = '<div class="chooser">' +
      (rows
        ? '<ul class="hits">' + rows + '</ul>'
        : '<p class="none">' + esc(spec.nothing) + '</p>') +
      '</div>';

    const noun = wanted
      ? (matchedCount === 1 ? 'match' : 'matches')
      : 'in the list';
    const count = matchedCount
      ? (matchedCount > WebKit.CHOOSER_HITS
          ? 'Showing ' + (from + 1) + '&ndash;' + (from + shown.length) +
            ' of ' + matchedCount + ' ' + noun + '. '
          : matchedCount + ' ' + noun + '. ')
      : '';
    const more = [];
    if (from > 0) {
      more.push(pageLink(from - WebKit.CHOOSER_HITS, '&larr; previous ' +
        WebKit.CHOOSER_HITS,
        'The twenty before these'));
    }
    if (from + WebKit.CHOOSER_HITS < matchedCount) {
      more.push(pageLink(from + WebKit.CHOOSER_HITS,
                         'next ' + WebKit.CHOOSER_HITS + ' &rarr;',
        'The twenty after these'));
    }

    return '<form method="get" id="' + esc(anchor) +
           '" class="finder" action="' +
      esc(path) + '#' + esc(anchor) + '">' +
      '<div class="formrow">' + hidden +
        '<label for="' + esc(spec.param) + '">' + esc(spec.label) +
        '</label><input type="text" id="' + esc(spec.param) + '" name="' +
          esc(spec.param) + '" size="32" value="' + esc(wanted) +
          '" placeholder="' + esc(spec.placeholder) + '">' +
        '<button class="secondary">Search</button>' +
        (wanted
          ? ' <a href="' + esc(path + WebKit.queryWith(carried, {})) + '#' +
            esc(anchor) +
            '">clear</a>'
          : '') +
      '</div></form>' +
      pane +
      (count || more.length
        ? '<p class="note">' + count + more.join(' &middot; ') + '</p>'
        : '');
  }

  // The list AS THE READER LEFT IT, picked out of a query by that table.
  //
  // This is what makes the trail a way back to where somebody was rather than
  // to the top of an unfiltered list. A drill-down link carries it, every
  // control on the drill-down carries it onward (pageParamsOf() takes
  // the whole
  // query through), and the trail's section crumb spends it. Nothing on the
  // drill-down reads these keys for anything else: their names belong to the
  // list's filter form, and a page showing one application has no `q`.
  /**
   * Picks a list page's filter and page parameters out of a query.
   *
   * Only the keys LIST_PARAMS names for the section are kept; the first of a
   * repeated parameter wins.
   *
   * @param section - the list page's path
   * @param query - the request's query object
   * @returns the list view, as parameter names to strings
   */
  static listViewOf(section, query) {
    const out = {};
    (LIST_PARAMS[section] || []).forEach(function (key) {
      const raw = (query || {})[key];
      // Express hands back an array when a parameter is repeated, and String()
      // on one is "a,b" — a filter nothing matches, reached by a link somebody
      // clicked twice. The same first-wins rule pageParamsOf() uses.
      const value = Array.isArray(raw) ? raw[0] : raw;
      if (value !== undefined && value !== null && String(value) !== '') {
        out[key] = String(value);
      }
    });
    return out;
  }

  // The same thing out of a form's `back` field, which is a query string a
  // browser sent us rather than one we are looking at.
  //
  // It is REBUILT and never echoed: the names come from LIST_PARAMS, the values
  // are re-encoded by queryWith(), and anything else in the field is
  // dropped.
  // That is the guarantee backTo() gives the tokens page and it is needed here
  // for the same reason — a redirect target taken out of a request body is an
  // open redirect, and one carrying a newline is a header injection. The worst
  // a hand-written `back` can now reach is another page of the same list.
  /**
   * Rebuilds a list view from a form's `back` query string.
   *
   * It is rebuilt through listViewOf() and never echoed, so it cannot carry
   * an open redirect or a header injection.
   *
   * @param section - the list page's path
   * @param raw - the `back` field's value
   * @returns the list view; empty when the field cannot be parsed
   */
  static listViewFromBack(section, raw) {
    let params = null;
    try {
      params = new URLSearchParams(String(raw || '').replace(/^\?/, ''));
    } catch (e) {
      // Unparseable; the bare list is the right answer and is what a form
      // carrying no `back` at all gets anyway.
      return {};
    }
    const query = {};
    params.forEach(function (value, key) {
      // First wins, for the reason listViewOf() takes the first of a repeated
      // parameter: a field sent twice is one value, not "a,b".
      if (!Object.prototype.hasOwnProperty.call(query, key)) {
        query[key] = value;
      }
    });
    return WebKit.listViewOf(section, query);
  }

  /**
   * Formats a duration as days, hours, minutes and seconds.
   *
   * @param ms - the duration in milliseconds
   * @returns the text, such as `1d 2h 3m 4s`
   */
  static durationText(ms) {
    const s = Math.floor((ms || 0) / 1000);
    const days = Math.floor(s / 86400);
    const hours = Math.floor((s % 86400) / 3600);
    const minutes = Math.floor((s % 3600) / 60);
    const parts = [];
    if (days) parts.push(days + 'd');
    if (days || hours) parts.push(hours + 'h');
    parts.push(minutes + 'm');
    parts.push((s % 60) + 's');
    return parts.join(' ');
  }

  // The FILTER half of a carried list view — everything except the two
  // parameters that describe how the list was being paged. Written once because
  // both of the controls that need it need the same half: a form that changes
  // the page size, and anything else that lands the reader at the top of a list
  // rather than where they were in it.
  /**
   * Returns a list view without its `page` and `per` parameters.
   *
   * @param view - the list view's parameters
   * @returns a new object holding every other parameter
   */
  static filterOnly(view) {
    const out = {};
    Object.keys(view || {}).forEach(function (key) {
      if (key !== 'page' && key !== 'per') {
        out[key] = view[key];
      }
    });
    return out;
  }

  // One application's kinds as cells, since a record commonly carries two — an
  // OAuth client that asked for the openid scope is also a relying party, and a
  // wtrealm handed a SAML 2.0 assertion in one request and the 1.1 default in
  // the next is both of those. The registry accumulates rather than choosing,
  // so the cell has to.
  /**
   * Draws an application's kinds as one cell, one per line, or `unstated`.
   *
   * @param kinds - the kinds to draw
   * @returns the cell's HTML
   */
  static kindCells(kinds) {
    if (!kinds.length) {
      return '<span class="state-none">unstated</span>';
    }
    return kinds.map(function (kind) {
      return '<code>' + WebKit.esc(kind) + '</code>';
    }).join('<br>');
  }

  /**
   * The trash-can icon a list box's delete button carries, inline so the
   * console still makes no image request.
   *
   * @returns the SVG as HTML
   */
  static trashIcon() {
    return '<svg viewBox="0 0 16 16" width="14" height="14" ' +
      'aria-hidden="true" ' +
      'focusable="false"><path fill="currentColor" d="M6 1h4l1 1h3v2H2V2h3z' +
      'M3 5h10l-1 10H4zm3 2v6h1V7zm3 0v6h1V7z"/></svg>';
  }

  // The classes that make a block appear only when one of its families is
  // ticked. `pf` is what the stylesheet hides; each `pf-<id>` is what a checked
  // box shows. A block serving several families carries several, and appears
  // when ANY of them is ticked — which is what `samlEntityId` needs, since it
  // is the identifier of both SAML profiles.
  //
  // A block with NO families is not given `pf` at all: it is unconditional, and
  // tagging it would hide it forever.
  /**
   * Returns the CSS classes that show a block only while one of its
   * families is ticked.
   *
   * @param ids - the family ids the block serves
   * @returns `pf pf-<id> ...`, or an empty string for an unconditional block
   */
  static familyClasses(ids) {
    const list = (ids || []).filter(function (id) { return !!id; });
    if (!list.length) {
      return '';
    }
    return 'pf ' + list.map(function (id) { return 'pf-' + id; }).join(' ');
  }

  /**
   * Draws one field of the grid: its name (with its sentence as a tooltip),
   * the families it belongs to, and the control its type needs.
   *
   * @param row - the field's row, typed by `gridFieldTyped()`
   * @param values - the grid's values by attribute
   * @param options - `redraw` (the route "+" and delete post to), `showSet`
   *   (show a cell holding a value whatever is ticked), `generateSecret`,
   *   and `protocols`, the families a cell's labels are named from
   * @returns the cell as HTML
   */
  static fieldGridCell(row, values, options) {
    const opts = options || {};
    const name = 'field.' + row.attribute;
    const id = 'fg-' + row.attribute;
    const held = values[row.attribute] || [];
    const first = held.length ? String(held[0]) : '';
    const hint = WebKit.tip(row.what || row.attribute);
    const defaultText = row.described
      ? 'default — currently ' + row.described.text : '';
    // THE GUIDANCE IN AN EMPTY BOX (rcbj, 2026-10-01): an example of a valid
    // value, as a placeholder — grey, and gone as soon as somebody types — and
    // for a setting override the default beside it. `applications.
    // fieldExample()` is the one table of them.
    const guidance = row.example
      ? 'e.g. ' + row.example + (defaultText ? ' (' + defaultText + ')' : '')
      : (defaultText || 'not set');
    let control = '';
    // A VALUE THAT IS NOT ONE OF THE CHOICES (an older write, an
    // ldapmodify) is still offered, marked, so a save does not drop it
    // silently.
    const offered = function (choices) {
      return choices.concat(held.filter(function (one) {
        return String(one).trim() !== '' && choices.indexOf(String(one)) < 0;
      }).map(String));
    };
    const outside = function (choices, value) {
      return choices.indexOf(value) < 0
        ? ' <span class="state-none">(not one of the allowed values)</span>'
        : '';
    };
    if (row.type === 'array' && row.choices && row.choices.length) {
      // A LIST FROM A CLOSED SET is a checkbox per value. An unticked box
      // posts nothing, so no box can be empty, and the form's `present` list
      // is what clears the attribute when every box is unticked.
      control = '<div class="fg-checks" role="group"' + hint +
        ' aria-label="' + WebKit.esc(row.attribute) + '">' +
        offered(row.choices).map(function (value, n) {
          return '<label class="fg-radio"><input type="checkbox" name="' +
            WebKit.esc(name + '.' + n) + '" value="' + WebKit.esc(value) + '"' +
            (held.map(String).indexOf(value) >= 0 ? ' checked' : '') + '>' +
            WebKit.esc(value) + outside(row.choices, value) + '</label>';
        }).join('') + '</div>';
    } else if (row.type === 'array') {
      control = '<div class="fg-list">' + held.map(function (value, n) {
        return '<div class="fg-item"><input type="text" id="' +
          WebKit.esc(id + '-' + n) + '" name="' + WebKit.esc(name + '.' + n) +
          '" value="' + WebKit.esc(value) + '"' + hint +
          (row.example ? ' placeholder="' + WebKit.esc('e.g. ' + row.example) +
                         '"' : '') + ' aria-label="' +
          WebKit.esc(row.attribute + ' value ' + (n + 1)) + '">' +
          '<button type="submit" class="secondary fg-drop" name="drop" ' +
          'value="' + WebKit.esc(row.attribute + '.' + n) + '" formaction="' +
          WebKit.esc(opts.redraw + '#fgc-' + row.attribute) +
            '" formnovalidate ' +
          'title="Delete this ' +
          'value" aria-label="Delete value ' + (n + 1) + ' of ' +
          WebKit.esc(row.attribute) + '">' + WebKit.trashIcon() +
          '</button></div>';
      }).join('') +
      (held.length ? '' : '<span class="state-none">no values</span>') +
      '<button type="submit" class="secondary fg-grow" name="grow" value="' +
      WebKit.esc(row.attribute) + '" formaction="' +
      WebKit.esc(opts.redraw + '#fgc-' + row.attribute) +
      '" formnovalidate title="Add a value" aria-label="Add a value to ' +
      WebKit.esc(row.attribute) + '">+</button></div>';
    } else if (row.type === 'boolean') {
      const upper = first.toUpperCase();
      const radio = function (value, label) {
        return '<label class="fg-radio"><input type="radio" name="' +
          WebKit.esc(name) + '" value="' + value + '"' +
          (upper === value ? ' checked' : '') + '>' + WebKit.esc(label) +
          '</label>';
      };
      control = '<div class="fg-bool" role="radiogroup"' + hint +
        ' aria-label="' + WebKit.esc(row.attribute) + '">' +
        radio('TRUE', 'true') +
        radio('FALSE', 'false') +
        radio('', defaultText || 'not set') + '</div>';
    } else if (row.type === 'enum') {
      // ONE VALUE FROM A CLOSED SET is a radio per value, and a last one for
      // none (the setting's default, for an override), the boolean's shape.
      control = '<div class="fg-bool fg-choices" role="radiogroup"' +
        hint + ' aria-label="' + WebKit.esc(row.attribute) + '">' +
        offered(row.choices || []).map(function (value) {
          return '<label class="fg-radio"><input type="radio" name="' +
            WebKit.esc(name) + '" value="' + WebKit.esc(value) + '"' +
            (value === first ? ' checked' : '') + '>' + WebKit.esc(value) +
            outside(row.choices || [], value) + '</label>';
        }).join('') +
        '<label class="fg-radio"><input type="radio" name="' +
        WebKit.esc(name) + '" value=""' + (first === '' ? ' checked' : '') +
        '>' + WebKit.esc(defaultText || 'not set') + '</label></div>';
    } else if (row.long) {
      control = '<textarea id="' + WebKit.esc(id) + '" name="' +
        WebKit.esc(name) + '" rows="3"' + hint + ' placeholder="' +
        WebKit.esc(guidance) + '">' +
        WebKit.esc(held.join('\n')) + '</textarea>';
    } else {
      const d = row.described;
      control = '<input type="' + (row.type === 'int' ? 'number' : 'text') +
        '" id="' + WebKit.esc(id) + '" name="' + WebKit.esc(name) +
        '" value="' +
        WebKit.esc(first) + '"' + hint +
        (d && typeof d.min === 'number' ? ' min="' + d.min + '"' : '') +
        (d && typeof d.max === 'number' ? ' max="' + d.max + '"' : '') +
        ' placeholder="' + WebKit.esc(guidance) + '">' +
        (row.attribute === 'oauthClientSecret' && opts.generateSecret
          ? ' <button type="submit" class="secondary" name="action" ' +
            'value="generate-secret" formaction="' +
            WebKit.esc(opts.generateSecret) + '" formnovalidate' +
            WebKit.tip('Mint a client secret the way POST /oauth2/register ' +
                     'does and put it in this box. Nothing is written until ' +
                     'the application is created. Everything else you have ' +
                     'typed on this page is kept.') +
            '>Generate Secret</button>'
          : '');
    }
    const labels = row.forText !== undefined ? String(row.forText)
      : row.everyFamily ? 'every protocol'
      : row.families.map(function (family) {
        const known = (opts.protocols || []).filter(function (one) {
          return one.id === family;
        })[0];
        return known ? known.label : family;
      }).join(', ');
    const conditional = !row.everyFamily && row.families.length &&
      !(opts.showSet && held.some(function (one) {
        return String(one).trim() !== '';
      }));
    // The cell's id is what "+" and the bin come back to (withReturnAnchors()).
    return '<div id="fgc-' + WebKit.esc(row.attribute) + '" class="fg-cell' +
      (conditional
        ? ' ' + WebKit.esc(WebKit.familyClasses(row.families)) : '') + '">' +
      // A label names one control; a list and a radio group are several, so
      // their name is a heading of the cell rather than a label.
      (row.type === 'array' || row.type === 'boolean'
        ? '<span class="fg-name"' + hint + '><code>' +
          WebKit.esc(row.attribute) + '</code></span>'
        : '<label class="fg-name" for="' + WebKit.esc(id) + '"' + hint +
          '><code>' + WebKit.esc(row.attribute) + '</code></label>') +
      '<span class="fg-for">' + WebKit.esc(labels) +
      (row.type === 'array' ? ' &middot; a list' : '') +
      (row.sensitive ? ' &middot; a credential' : '') + '</span>' +
      control + '</div>';
  }

  /**
   * Reads the grid's values out of a posted form, keeping every list box —
   * an empty one included — in box order, and applies a "+" or a delete.
   *
   * @param draft - the posted form
   * @param longText - optional; the attributes one box holds whole
   *   (`applications.LONG_TEXT_ATTRIBUTES`)
   * @returns the values by attribute
   */
  static gridValuesFromDraft(draft, longText?) {
    const out = {};
    const boxes = {};
    const long = longText || [];
    Object.keys(draft || {}).forEach(function (key) {
      if (key.indexOf('field.') !== 0) {
        return;
      }
      const name = key.slice('field.'.length);
      const value = String(draft[key] === undefined ? '' : draft[key]);
      const box = /^(.+)\.(\d+)$/.exec(name);
      if (box) {
        (boxes[box[1]] = boxes[box[1]] || []).push({ n: Number(box[2]),
                                                     value: value });
        return;
      }
      // A box of the older shape — one value per line — or a single value.
      out[name] = long.indexOf(name) >= 0 ? [value]
        : value.split(/\r?\n/).filter(function (one) {
          return one.trim() !== '';
        });
    });
    Object.keys(boxes).forEach(function (name) {
      out[name] = boxes[name].sort(function (a, b) { return a.n - b.n; })
        .map(function (one) { return one.value; });
    });
    const grow = String((draft && draft.grow) || '');
    if (grow) {
      out[grow] = (out[grow] || []).concat(['']);
    }
    const drop = /^(.+)\.(\d+)$/.exec(String((draft && draft.drop) || ''));
    if (drop && out[drop[1]]) {
      out[drop[1]].splice(Number(drop[2]), 1);
    }
    return out;
  }

  // THE "MAIL IT TO THEM" BOX (#63): `deliver=mail` on the reset link and
  // the activation link, TICKED when the realm has a mail transport — an
  // administrator who never sees a person's link cannot be the one who used
  // it — and absent, with the reason, when it has none.
  /**
   * Draws the ticked "mail it to them" checkbox (`deliver=mail`) for a
   * link, or a note that the realm has no mail transport.
   *
   * @param what - what is mailed, as the sentence names it
   * @param available - optional; whether the realm has a mail transport
   * @returns the box or the note as HTML
   */
  static mailLinkBox(what, available?) {
    if (!available) {
      return WebKit.note('This realm has no mail transport ' +
        '(<a href="/admin/mail">Mail</a>), so ' + WebKit.esc(what) + ' is ' +
        'shown to you to pass on.');
    }
    return '<div class="formrow"><label><input type="checkbox" ' +
      'name="deliver" value="mail" checked> mail ' + WebKit.esc(what) +
      ' to the address on their entry, and do not show it to me</label>' +
      '</div>';
  }

  // A query's VIEW parameters — every one but the three that are not part
  // of what is being looked at (`format`, and the `notice` and `error` a
  // redirect brought back) — first value each. `admin_views.ts`'s, which
  // calls this one (#446): a renderer carries a page's parameters on its
  // links and must name the same ones the server does.
  /**
   * Returns a query's view parameters, first value each, without `format`,
   * `notice` and `error`.
   *
   * @param query - the query
   * @returns the parameters
   */
  static pageParamsOf(query): Record<string, any> {
    const out: Record<string, any> = {};
    Object.keys(query || {}).forEach(function (key) {
      if (['format', 'notice', 'error'].indexOf(key) >= 0) {
        return;
      }
      // Express hands back an array when a parameter is repeated. The first
      // is taken rather than String()'d, because String(['2','5']) is "2,5"
      // — a page number nothing can parse, silently reached by a link
      // somebody clicked twice.
      const value = Array.isArray(query[key]) ? query[key][0] : query[key];
      out[key] = value == null ? '' : String(value);
    });
    return out;
  }

  // -------------------------------------------------------------------------
  // WHAT A RENDERER IS TOLD BESIDE ITS VIEW (#446).
  //
  // A page is drawn from the answer of its management API operation. Two
  // things a page draws are not in that answer and are not this process's
  // either — they belong to the READER:
  //
  //   * `query` — the page's own query parameters: which page of a list, a
  //     filter, a drill-down. A paging link has to carry the others forward,
  //     and a Withdraw has to come back to the page the reader was on.
  //   * `write` — whether the reader may write, which decides whether a
  //     control is drawn at all. It is `GET /admin-api/me`'s `write`.
  //     DRAWING A BUTTON IS NOT WHAT REFUSES THE ACT: the operation behind it
  //     checks the role, here as in the console.
  //
  // The server-rendered console builds one from its request
  // (`AdminConsole.renderContext()`); the static console's runtime builds
  // one from the address bar and its `me` answer. Nothing else belongs in
  // it: a fact about the SERVICE goes in the view, where a caller of the
  // API can read it too.
  // -------------------------------------------------------------------------
  /**
   * Builds the render context a page's renderer takes beside its view.
   *
   * @param query - the page's query parameters, by name
   * @param write - whether the reader may write
   * @returns `{ query, write }`, the query copied and `write` a boolean
   */
  static context(query?, write?) {
    const copy = {};
    Object.keys(query || {}).forEach(function (name) {
      copy[name] = query[name];
    });
    return { query: copy, write: write === true };
  }

  // A list of names, each in its own <code>. Written as a function because the
  // obvious one-liner — join with the markup and escape the result — escapes
  // the markup too, and the page then shows the tags it was supposed to render.
  // It did.
  /**
   * Draws a list of names, each in its own `<code>`, joined with commas.
   *
   * @param names - the names to draw
   * @returns the list as HTML
   */
  static codeList(names) {
    return names.map(function (name) { return '<code>' + WebKit.esc(name) +
                                       '</code>'; })
                .join(', ');
  }
}

export = WebKit;
