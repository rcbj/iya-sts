// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_dashboard.ts
//
// ---------------------------------------------------------------------------
// THE CONSOLE INDEX, DRAWN FROM ITS VIEW ALONE (#446, 2026-10-05).
//
// Draws `/admin` from the answer of `GET /admin-api/status`: the totals, every
// page this reader may see grouped as the sidebar is, what the console
// deliberately does not do, and where the JSON is.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// It was drawn inside the route of `/admin` in `admin-ui/admin.ts`, which
// still draws the page until the console's cutover by calling this with its
// view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');

type Json = any;

/**
 * Draws `/admin` from the answer of `GET /admin-api/status`: the totals, every
 * page this reader may see grouped as the sidebar is, what the console
 * deliberately does not do, and where the JSON is.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class DashboardPage {
  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static body(ctx, json) {
    // THE WORDS ARE THE READER'S LANGUAGE (#539): every message below is
    // `consoleDashboard.*`, and its English is exactly what was drawn before.
    // A link is MARKUP the catalog cannot carry, so a paragraph with a link
    // in it is several messages with the `<a>` between them in code.
    const t = ctx.t;
    const link = function (href, text) {
      return '<a href="' + href + '">' + text + '</a>';
    };
    const inner = '<div class="tiles">' +
        kit.tile(json.calls, t.text('consoleDashboard.tile.calls')) +
        kit.tile(json.tokensHeld,
                 t.text('consoleDashboard.tile.tokensIssued')) +
        kit.tile(json.tokensRevoked,
                 t.text('consoleDashboard.tile.tokensRevoked')) +
        kit.tile(json.artifactsHeld,
                 t.text('consoleDashboard.tile.artifacts')) +
        kit.tile(json.usersKnown, t.text('consoleDashboard.tile.users')) +
        kit.tile(json.signOnSessions,
                 t.text('consoleDashboard.tile.sessions')) +
        kit.tile(kit.durationText(json.uptimeMs),
                 t.text('consoleDashboard.tile.uptime')) +
      '</div>' +
      '<h2>' + t.html('consoleDashboard.what.heading') + '</h2>' +
      kit.note(t.html('consoleDashboard.what.clients')) +
      kit.note(t.html('consoleDashboard.what.derived')) +
      DashboardPage.consoleGuide('/admin', json.sections, t) +
      '<h2>' + t.html('consoleDashboard.not.heading') + '</h2>' +
      kit.note(t.html('consoleDashboard.not.intro')) +
      '<ul>' +
      kit.bullet(t.html('consoleDashboard.not.invalidate')) +
      kit.bullet(t.html('consoleDashboard.not.endSessionA') + ' ' +
      link('/admin/logout', '/admin/logout') + ' ' +
      t.html('consoleDashboard.not.endSessionB') + ' ' +
      link('/logout', '/logout') +
      t.html('consoleDashboard.not.endSessionC')) +
      kit.bullet(t.html('consoleDashboard.not.keepTokens')) +
      kit.bullet(t.html('consoleDashboard.not.restart') + ' ' +
      (json.persistence.enabled
        ? t.html('consoleDashboard.not.surviveOn',
                 { mode: json.persistence.mode }) + ' ' +
          t.html('consoleDashboard.not.see') + ' ' +
          link('/admin/persistence',
               t.html('consoleDashboard.link.persistence')) +
          t.html('consoleDashboard.not.seeEnd')
        : t.html('consoleDashboard.not.surviveOff') + ' ' +
          t.html('consoleDashboard.not.see') + ' ' +
          link('/admin/persistence',
               t.html('consoleDashboard.link.persistence')) +
          t.html('consoleDashboard.not.offByDefault'))) +
      kit.bullet(t.html('consoleDashboard.not.rememberA') + ' ' +
      t.html('consoleDashboard.not.forgottenOn') + ' ' +
      link('/admin/metrics', t.html('consoleDashboard.link.metrics')) +
      t.html('consoleDashboard.not.droppedOn') + ' ' +
      link('/admin/audit', t.html('consoleDashboard.link.audit')) +
      t.html('consoleDashboard.not.rememberB')) +
      kit.bullet(t.html('consoleDashboard.not.password')) +
      kit.bullet(t.html('consoleDashboard.not.enforceA') + ' ' +
      link('/admin/oauth2', t.html('consoleDashboard.link.oauth')) + ' ' +
      t.html('consoleDashboard.not.enforceB') + ' ' +
      link('/admin/scim', 'SCIM') +
      t.html('consoleDashboard.not.enforceC') + ' ' +
      link('/admin/federation', t.html('consoleDashboard.link.federation')) +
      ' ' + t.html('consoleDashboard.not.enforceD')) +
      kit.bullet(t.html('consoleDashboard.not.delegateA') + ' ' +
      link('/admin/delegation', t.html('consoleDashboard.link.delegation')) +
      ' ' + t.html('consoleDashboard.not.delegateB')) +
      kit.bullet(t.html('consoleDashboard.not.attestA') + ' ' +
      link('/admin/spiffe', 'SPIFFE') + ' ' +
      t.html('consoleDashboard.not.attestB')) +
      // `{id}` in the SCIM path is a literal brace, which no message may
      // hold, so the path stays in code between two messages.
      kit.bullet(t.html('consoleDashboard.not.deleteA') + ' ' +
      link('/admin/users', t.html('consoleDashboard.link.users')) + ' ' +
      t.html('consoleDashboard.not.deleteB') + ' ' +
      link('/admin/scim', 'SCIM') + ' ' +
      t.html('consoleDashboard.not.deleteC') +
      ' <code>DELETE /scim/v2/Users/{id}</code> ' +
      t.html('consoleDashboard.not.deleteD')) +
      kit.bullet(t.html('consoleDashboard.not.oneRealm')) +
      kit.bullet(t.html('consoleDashboard.not.scriptA') + ' ' +
      link('/admin/delegation/map',
           t.html('consoleDashboard.link.picture')) + ' ' +
      t.html('consoleDashboard.not.scriptB')) +
      '</ul>' +
      '<h2>' + t.html('consoleDashboard.test.heading') + '</h2>' +
      kit.note(t.html('consoleDashboard.test.noteA') + ' ' +
      link('/admin-api', '/admin-api') +
      t.html('consoleDashboard.test.noteB')) +
      '<ul><li><code>GET ' + kit.esc(json.base) +
      '/admin/metrics?format=json</code></li>' +
      kit.bullet('<code>GET ' + kit.esc(json.base) +
                  '/admin/groups?format=json</code>' +
      t.html('consoleDashboard.test.and') + ' ' +
      '<code>GET ' + kit.esc(json.base) +
      '/admin/groups?group=cn=developers,ou=groups,...&amp;format=json' +
      '</code> ' + t.html('consoleDashboard.test.groups')) +
      kit.bullet('<code>GET ' + kit.esc(json.base) +
                  '/admin/users?format=json</code>' +
      t.html('consoleDashboard.test.and') + ' ' +
      '<code>GET ' + kit.esc(json.base) +
      '/admin/users?user=alice&amp;format=json</code> ' +
      t.html('consoleDashboard.test.users')) +
      kit.bullet('<code>GET ' + kit.esc(json.base) +
      '/admin/tokens?format=json&amp;page=1&amp;per=100</code> ' +
      t.html('consoleDashboard.test.tokens')) +
      kit.bullet('<code>GET ' + kit.esc(json.base) +
      '/admin/sts-metadata?format=json</code> ' +
      t.html('consoleDashboard.test.metadata')) +
      kit.bullet('<code>GET ' + kit.esc(json.base) +
      '/admin/delegation/map?format=json</code> ' +
      t.html('consoleDashboard.test.map')) +
      '<li><code>POST ' + kit.esc(json.base) + '/admin/tokens</code> ' +
      t.html('consoleDashboard.test.with') + ' ' +
      '<code>{"action":"revoke","target":"&lt;jti or ' +
      'token&gt;"}</code></li><li><code>POST ' + kit.esc(json.base) +
      '/admin/claims</code> ' + t.html('consoleDashboard.test.with') + ' ' +
      '<code>' +
      '{"action":"replace","set":"id_token","claims":[{"name":"dept",' +
      '"value":"engineering"}]}</code></li></ul>';
    return inner;
  }

  /**
   * Draws the overview's list of every page, grouped as the sidebar is.
   *
   * The page being drawn on is left out, and so is a section left empty.
   *
   * @param activePath - the path of the page the list is drawn on
   * @param sections - the sections this reader may see
   *   (`visibleSections()`'s answer, carried as the dashboard's `sections`)
   * @param t - the page's translator (#539)
   * @returns the guide as HTML
   */
  static consoleGuide(activePath, sections, t) {
    const out = [];
    sections.forEach(function (section) {
      const items = [];
      // One list of rows, a group drawn as its heading over its own rows —
      // which may hold a group again (Cert issuance › SPIFFE) — and dropped
      // when the page being drawn was all it held.
      const rows = function (list, out) {
        list.forEach(function (item) {
          if (DashboardPage.isNavGroup(item)) {
            const inner = [];
            rows(item.items, inner);
            if (!inner.length) {
              return;
            }
            // The group's own description folds like a page's, for the same
            // reason: SAML's runs to five lines and sat between the heading
            // and the three pages under it.
            out.push('<li><span class="grp">' + kit.esc(item.title) +
                     '</span>' +
                     kit.note(kit.esc(item.what)) +
                     '<ul>' + inner.join('') + '</ul></li>');
            return;
          }
          if (item.path === activePath) {
            return;
          }
          out.push(DashboardPage.guideItem(item, t));
        });
      };
      rows(section.items, items);
      if (!items.length) {
        return;
      }
      out.push('<h3>' + kit.esc(section.title) + '</h3>' +
               kit.note(kit.esc(section.what)) +
               '<ul>' + items.join('') + '</ul>');
    });
    return '<div class="guide">' + out.join('') + '</div>';
  }

  // ---------------------------------------------------------------------------
  // THE OVERVIEW PAGE'S OWN LIST OF WHAT IS HERE, DERIVED FROM `SECTIONS`.
  //
  // It was a hand-written `<ul>` in the route below until 2026-08-25, and it
  // had drifted to describing SEVEN of twenty-five pages — so the one page
  // whose whole job is to point at the others was the least complete
  // description of this console in the repository. Nothing could have shown
  // that: a list of links is correct-looking whatever it omits, which is
  // exactly the shape of problem `/admin/sts-metadata` exists to make
  // impossible for endpoints.
  //
  // So it is built from the same table the sidebar is built from, and three
  // rules follow from that rather than from taste:
  //
  //   * **A page with no `blurb` is DRAWN, marked as undescribed.** The
  //     tempting alternative — skip it — is the bug over again with a mechanism
  //     behind it, since a page added to `SECTIONS` and not described here
  //     would silently vanish from the front door exactly as nineteen of them
  //     had.
  //   * **The page being drawn ON is dropped**, which is `/admin` and only ever
  //     `/admin`. `trailBar()`'s last-crumb rule is the same one: a link that
  //     reloads the page you are standing on teaches a reader not to trust the
  //     ones beside it. A section left empty by that drop is dropped with it,
  //     rather than leaving a heading over nothing.
  //   * **The GROUPS are kept**, unlike `sectionPages()`, which flattens them.
  //     The sidebar's grouping is a fact about the sidebar — but this list is
  //     the sidebar EXPLAINED, and a reader looking for `Registration entries`
  //     needs the same "these three are SPIFFE" that made the group worth
  //     having.
  //
  // The blurbs are prose in `SECTIONS` beside each page's `path` and `label`.
  // This function knows nothing about any particular page, which is what stops
  // it becoming a second place a page has to be described.
  /**
   * Draws one page's entry in the overview's list of pages.
   *
   * A page with no blurb in SECTIONS is drawn and marked as undescribed.
   *
   * @param page - a page row from SECTIONS
   * @param t - the page's translator (#539)
   * @returns an <li> as HTML
   */
  static guideItem(page, t) {
    if (!page.blurb) {
      // NOT an omission and not a throw. A console that will not start is worse
      // than one line that says what is missing — the same call `admin_rbac.js`
      // makes about a slot nobody filled — and this is the only report anything
      // makes about a page nobody described.
      return kit.bullet('<a href="' + kit.esc(page.path) + '">' +
                         kit.esc(page.label) +
             '</a> — <span class="undescribed">' +
             t.html('consoleDashboard.undescribed') + '</span>');
    }
    // THE LINK STAYS ON THE ROW AND THE BLURB FOLDS UNDER IT. Every blurb in
    // SECTIONS runs to between three and six lines — they are the description
    // of a page rather than a caption for it — so this list, which is the one
    // page in this console whose whole job is pointing at the others, was
    // twenty-six paragraphs deep and the twenty-six links were scattered
    // through it. It is an index again: the labels are a column somebody can
    // run an eye down, and the paragraph is under whichever one they stopped
    // at.
    //
    // The link is deliberately NOT inside the summary. kit.bullet() refuses to
    // fold an item that opens with one for the reason given there — a link
    // inside a <summary> is a control inside a control — and this row would
    // have been the first place that bit.
    return '<li><a href="' + kit.esc(page.path) + '">' + kit.esc(page.label) +
           '</a>' +
           kit.note(page.blurb) + '</li>';
  }

  // Is this row of a section's `items` a GROUP of pages rather than a page? One
  // predicate, used by both the flattening and the sidebar, so the two cannot
  // disagree about what they are looking at. A group has `items`; a page has a
  // `path` and never has `items`.
  /**
   * Tells whether a row of a section's items is a group of pages.
   *
   * @param item - a row of a section's `items`
   * @returns true when the row has an `items` array
   */
  static isNavGroup(item) {
    return item != null && Array.isArray(item.items);
  }
}

export = DashboardPage;
