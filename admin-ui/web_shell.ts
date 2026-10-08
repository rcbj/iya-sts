// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_shell.ts
//
// ---------------------------------------------------------------------------
// THE CONSOLE'S SHELL, DRAWN FROM ITS VIEW ALONE (#446, 2026-10-05).
//
// Every console page is a body inside one frame: the sidebar (the brand, the
// trust realm chooser, the sections this reader may see), the head row (the
// title, the refresh link, the account menu), the trail, the gate's banner,
// a realm's retirement banner, and the foot (what is persisted, the build,
// what this process runs as). `AdminConsole.page()` drew it while it read
// the realms, the gate and the process; here it is drawn from the console's
// SHELL ANSWER (`AdminConsole.shellJson()`), which the static console
// fetches once and the server-rendered console builds per request.
//
// What depends on the page being drawn is `page`: its title, the path that
// marks the nav, the drill-down's way up, the body, and the realm-relative
// path and query it was asked with (the refresh link and the realm chooser
// carry it).
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');
import DashboardPage = require('./web_dashboard');

type Json = any;

/**
 * Draws the console's frame around a page's body.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class WebShell {
  // The constants the frame draws with, owned here since #446 and read by
  // the console's routes from here.
  static readonly ACTIVE_NAV_FOCUS = ' tabindex="-1" autofocus';
  static readonly MAX_CRUMB = 44;
  static readonly REALM_SWITCH_PATH = '/admin/realm-switch';
  static readonly SIGNOUT_PATH = '/admin/signout';

  /**
   * Draws a page's body inside the console's frame: the sidebar, the head
   * row, the trail, the banners, the body and the foot.
   *
   * @param shell - the console's shell answer (`AdminConsole.shellJson()`)
   * @param page - `title`, `active` (the path that marks the nav), `up` (a
   *   drill-down's way up, or null), `inner` (the body) and `path` (the
   *   realm-relative path and query the page was asked with)
   * @returns the frame and the body, as the document's `<body>` content
   */
  static frame(shell: Json, page: Json): string {
    return '<div class="shell">' +
    WebShell.sideColumn(shell, page) +
    '<div class="main"><div class="card">' +
    // THE HEAD ROW: the page's title, and the controls that are on every page
    // of this console. See refreshLink() for why it is a link, and userMenu()
    // for why the second one is a <details> and not a script. Two controls
    // rather than one, so they are grouped: `.pagehead` is a space-between
    // row and a bare second child would push the first away from the heading
    // rather than sitting beside it.
    '<div class="pagehead"><h1>' + kit.esc(page.title) + '</h1>' +
      '<div class="pagetools">' + WebShell.refreshLink(shell, page) +
      WebShell.userMenu(shell) +
      '</div></div>' +
    WebShell.trailBar(page.active, page.up, page.title,
                      shell.navLabels) +
    WebShell.gateBanner(shell) +
    WebShell.retiringBanner(shell) +
    WebShell.withDerivedTips(page.inner) +
    '<div class="meta">' +
    // The one sentence drawn at the foot of EVERY page in this console, which
    // is why it is the sentence most worth keeping true. It said "everything
    // here is held in memory" for the whole life of this service and that
    // stopped being true on 2026-08-27 for exactly three things. It is less
    // true again since 2026-09-06: in product mode on postgres what this
    // service MINTS persists too, and product mode keeps its signing keys
    // (persistence/CLAUDE.md, common/CLAUDE.md) — which the sentence below
    // does not yet say.
    '<div>' + (shell.persistence.enabled
      ? 'The embedded directory, the trust realms and the settings changed ' +
        'here are written down (<a ' +
        'href="/admin/persistence">persistence.mode=' +
        kit.esc(shell.persistence.mode) + '</a>) and come back on the ' +
        'next start. Everything this service MINTS is still held in memory ' +
        'and dies with the process — the sessions, the tokens, the ' +
        'artifacts and the tickets — like the signing key it regenerates ' +
        'on every start, because a token that outlived the key it was ' +
        'signed under would verify against nothing.'
      : 'Everything on these pages is held in memory and dies with the ' +
        'process, like the signing key this service regenerates on every ' +
        'start. A statistics file that outlived the key that signed the ' +
        'tokens it described would be worse than none — though the ' +
        'directory, the trust realms and the settings changed here CAN be ' +
        'kept, which is <a href="/admin/persistence">Persistence</a> and ' +
        'is off by default.') + '</div><div>Every page here also answers ' +
    '<code>?format=json</code>, and every form also accepts a JSON body, ' +
    'so a test can drive this console without a browser.</div>' +
    // WHICH BUILD OF THIS SERVICE YOU ARE LOOKING AT, on every page of the
    // console for the reason the sentence above it is here: this is the
    // surface that CHANGES what every protocol endpoint does, so "was that
    // fixed in the build I am on" is a question asked in front of it
    // constantly, and an answer that is one page away is an answer somebody
    // guesses instead.
    //
    // The number is what gets quoted; the tooltip carries the provenance —
    // the build instant, the commit where there is one, and whether this is a
    // stamped artifact or a checkout being run. That last distinction is the
    // one worth a tooltip rather than a footnote: two instances reporting
    // different build numbers mean nothing if neither was ever built.
    '<div title="' + kit.esc(shell.version.buildInfo) +
    '">iya-sts version <code>' +
    kit.esc(shell.version.version) + '</code>' +
    (shell.version.stamped ? '' : ' (not a stamped build — this process is a ' +
     'checkout, and the build number is when it started)') + '</div>' +
    // AND WHAT THIS PROCESS IS RUNNING AS — dispatch or single process, the
    // mode, the store and the secret stores. See runtimeFooter().
    WebShell.runtimeFooter(shell) +
    // FOUR closing divs now, not two: the .meta block, the .card it is
    // inside, the .main column that holds the card and the .shell that holds
    // the two columns. Getting this wrong leaves a document that renders and
    // does not parse, which is the kind of thing only a parser notices — and
    // with a flex layout it is worse than that, because one missing tag nests
    // the next page's sidebar inside the last one's card and the failure
    // looks like a CSS bug.
    '</div></div></div></div>';
  }

  // The banner on every page while the gate is off: a warning, since then
  // nothing here checks a credential.
  /**
   * Draws the banner shown while the console's gate is off.
   *
   * @returns the banner as HTML
   */
  static openBanner(): string {
    return kit.warn('<strong>This console is not protected.</strong> The ' +
    'gate is OFF, so nothing here checks a credential — and nothing else in ' +
    'this service does either: the username typed at the sign-in screen is ' +
    'the identity in every token it issues. Anyone who can reach this port ' +
    'can revoke every token and change what the next one contains. That is ' +
    'fine on a laptop or a compose network and is not fine on a public ' +
    'address. Say who may get in on <a href="/admin/rbac">Admin roles</a>, ' +
    'which draws ' +
    'every setting behind this page.');
  }

  // ---------------------------------------------------------------------------
  // THE SIDEBAR COLUMN, AND WHO GETS ONE (2026-09-10).
  //
  // **IT IS DRAWN ONLY FOR A READER WHO CAN REACH SOMETHING IN IT**, which is
  // the same test `signOutControl()` above applies to its own button, read one
  // step further. Every row of that nav is a console page behind the gate: with
  // the gate ON and no session, every one of them answers a redirect to the
  // sign-in screen, so the column is forty links that all go to one place.
  //
  // **THE PAGE THAT FOUND IT IS THE SIGN-OUT PAGE.** `POST /admin/signout`
  // draws its confirmation through `page()` with the gate state read again —
  // which is right, and is what takes the Sign out button out of the corner —
  // and left the whole navigation column standing beside a page whose subject
  // is that the session it navigates with has ended. The realm switcher went
  // with it, and that one is worse than the links: it is a FORM, so using it
  // posted to a console that no longer had a session for it.
  //
  // TWO STATES GET THE COLUMN AND WHAT DECIDES IT IS THE GATE, NOT THE SESSION.
  // A service with the gate off has no session either and every page in that
  // nav is reachable, so `enforced` is what the test reads first and `session`
  // only decides it when the gate is on. A caller that passes no gate state at
  // all (the query refusal further down this file) is treated as the ordinary
  // case, because that page is drawn AFTER the gate has let the request
  // through.
  //
  // WHAT REPLACES IT IS NOTHING. `.main` is `flex:1 1 32rem`, so the card takes
  // the width the column was holding. A column emptied of its nav and keeping
  // its two brand lines would be an inch of white space with nothing in it —
  // and what those lines say is which REALM the pages are about, which is a
  // sentence about pages that are not there.
  // ---------------------------------------------------------------------------
  /**
   * Draws the sidebar: the realm being shown and the navigation.
   *
   * @param active - the path of the page being drawn
   * @param up - upTo()'s answer on a drill-down, or nothing
   * @param req - the request
   * @param gate - the gate state
   * @returns the `<aside>` as HTML; empty when the gate is on and nobody is
   *   signed in
   */
  static sideColumn(shell, page) {
    const gate = shell.gate;
    if (gate && gate.enforced && !gate.session) {
      return '';
    }
    const html =
        '<aside class="side">' +
        '<p class="brand">IYA STS admin</p>' +
        // WHAT THIS SERVICE IS AND WHICH REALM YOU ARE IN, rather than the
        // WS-Trust issuer identifier that used to be here.
        //
        // That identifier was `wstrust.issuer`, and it was never the name of
        // this service — it was what ONE of the sixteen protocol families put
        // in an <Issuer> element (since #523 every family's is one name, the
        // realm's OAuth issuer, which the title below carries). In the corner of a console whose other
        // fifteen families never mention it, it read as the service's identity
        // and is not; and it is the one line on the page that is drawn before
        // the reader knows what the page is about, so it should say something
        // true of the whole of it.
        //
        // THE REALM IS THE THING WORTH SAYING THERE. Every page in this console
        // shows exactly one realm, `/admin/config` WRITES the one it is read
        // in, and a realm is a whole logical copy of this service — so "which
        // one am I looking at" is the question a reader most needs answered
        // before they act. The switcher below says it too, but only when a
        // realm has been DEFINED: it is absent in the ordinary case, which is
        // precisely the case where the corner was saying nothing useful at all.
        //
        // THE ISSUER IDENTIFIER IS NOT IN THIS SHELL AT ALL ANY MORE, and that
        // is the second half of one decision rather than a later reversal of
        // it. It came out of this corner on 2026-08-24 into the line under the
        // heading, and off the shell entirely on 2026-08-25, for the reason
        // above read once more: a name that ONE of sixteen protocol families
        // uses, repeated at the top of every page in the console, reads as the
        // service's identity on all of them and means something on the handful
        // about WS-Trust.
        //
        // NOTHING IS LOST, and here is where each half of it went. It is on
        // `/admin/sts-metadata`, the one page whose subject is what this
        // service IS; it is on `/admin/config` under WS-Trust, which is where
        // it is SET; and it is in this line's tooltip, because somebody who had
        // learnt to read it off the shell should find it where they look rather
        // than have to hunt.
        '<p class="brandsub" title="' +
          kit.esc('This console is showing the trust realm "' +
                   shell.realm.name +
                   '" (id: ' + shell.realm.id + '). Its issuer ' +
                   'identifier, in every protocol (#523), ' +
                   'is ' + shell.wsTrustIssuer + ': every SAML <Issuer>, ' +
                   'every identity provider entityID and every JWT\'s ' +
                   'iss.') +
          '">IYA STS &middot; ' + kit.esc(shell.realm.name) + '</p>' +
        WebShell.navBar(shell, page) +
        '</aside>';
    return html;
  }

  // `up` is set on a drill-down — a page reached from a link on one of the
  // sections below rather than one of the sections itself — and what it changes
  // is the ACTIVE TAB.
  //
  // That tab was drawn as plain text on every page whose `active` matched, and
  // `active` is the section's path on the list page and on every page
  // underneath it alike. So on a drill-down the one control that pointed at the
  // list was the one control this shell had turned off, and the only way back
  // from /admin/applications?application=x was the browser's own Back button or
  // a link at the foot of a long page. On a drill-down the tab is a LINK: still
  // bold, because the reader is inside that section, and underlined so that
  // "the section you are in" cannot be read as "not clickable".
  //
  // It is one `<nav>` holding one `<ul>` per section with a heading above it.
  // The heading is plain text and NOT a link, for the reason the section is not
  // a crumb: there is no page behind it. The section containing the page being
  // drawn is marked, so a reader who arrived on a deep link can see where they
  // are without reading every label.
  //
  // A GROUP inside a section is drawn as an `<li>` holding a heading and a
  // `<ul>` of its own, rather than as a second `<ul>` beside the first: a group
  // belongs INSIDE the section's list — it is three of that list's items said
  // together — and a sibling list would tell a screen reader the section ended
  // where the group began. Its heading is plain text for the same reason the
  // section's is, and the marker on the group holding the current page is a
  // rule down the left like the section's, one level in.
  /**
   * Draws the console's navigation: the realm chooser and every section.
   *
   * A realm administrator sees only the pages of their realm and no chooser.
   *
   * @param active - the path of the page being drawn
   * @param up - upTo()'s answer on a drill-down, or nothing
   * @param req - the request, or nothing
   * @returns the `<nav>` as HTML
   */
  static navBar(shell, page) {
    const active = page.active;
    const up = page.up;
    // A REALM ADMINISTRATOR'S SIDEBAR (2026-09-14, #32) leaves out the pages
    // that belong to the whole service, which the gate would refuse them, and
    // the realm switcher, since their console is one realm. The service
    // administrator's is unchanged.
    const realmOnly = shell.navAuthority === 'realm';
    const html = '<nav aria-label="Admin console sections">' +
      // FIRST, inside this card rather than above it. It does not select a page
      // — it selects which service the pages are about — but it is the first
      // question a reader has about the column, so it is the first thing in it.
      (realmOnly ? '' : WebShell.realmChooser(shell, page)) +
      shell.sections.map(function (section) {
        const inThisSection = WebShell.sectionPages(section)
          .filter(function (item) {
          return item.path === active;
        }).length > 0;
        const links = section.items.map(function (item) {
          return WebShell.navItem(item, active, up);
        }).join('');
        return '<div class="navsec' + (inThisSection ? ' open' : '') + '">' +
          '<p class="navhead" title="' + kit.esc(section.what) + '">' +
          kit.esc(section.title) + '</p><ul>' + links + '</ul></div>';
      }).join('') + '</nav>';
    return html;
  }

  // One row of a section's list: a page, or a group holding pages.
  /**
   * Draws one row of a section's list: a page, or a group holding pages.
   *
   * @param item - the row
   * @param active - the path of the page being drawn
   * @param up - upTo()'s answer on a drill-down, or nothing
   * @returns the `<li>` as HTML
   */
  static navItem(item, active, up) {
    if (!DashboardPage.isNavGroup(item)) {
      return WebShell.navLink(item, active, up);
    }
    const open = WebShell.groupPages(item.items).filter(function (page) {
      return page.path === active;
    }).length > 0;
    // A row of a group may itself be a group (Cert issuance › SPIFFE), so
    // each row is drawn by this method again rather than by navLink().
    const html = '<li class="navgrp' + (open ? ' open' : '') + '">' +
      '<p class="navsub" title="' + kit.esc(item.what) + '">' +
      kit.esc(item.title) +
      '</p><ul>' + item.items.map(function (row) {
        return WebShell.navItem(row, active, up);
      }).join('') + '</ul></li>';
    return html;
  }

  /**
   * Draws one page's nav entry.
   *
   * The active page is plain text, or a link back up on a drill-down.
   *
   * @param item - the page's NAV row
   * @param active - the path of the page being drawn
   * @param up - upTo()'s answer on a drill-down, or nothing
   * @returns the `<li>` as HTML
   */
  static navLink(item, active, up) {
    if (item.path === active) {
      if (up) {
        return '<li><a class="here" href="' + kit.esc(up.href) + '"' +
               ' title="Back to ' + kit.esc(up.label) + '"' +
               // A drill-down's active item IS a link, so it is already in the
               // tab order and must stay there — only the autofocus is added.
               ' autofocus>' + kit.esc(item.label) + '</a></li>';
      }
      return '<li><span class="here"' + WebShell.ACTIVE_NAV_FOCUS +
             ' aria-current="page">' + kit.esc(item.label) + '</span></li>';
    }
    return '<li><a href="' + kit.esc(item.path) + '">' + kit.esc(item.label) +
           '</a></li>';
  }

  // The pages in a list of rows, in order, every group at every depth
  // flattened into it. The one walk `sectionPages()`, the sidebar's open
  // state and the guide share, so none of them can stop a level short.
  /**
   * Lists the pages in a list of section rows, groups flattened at any depth.
   *
   * @param items - a section's or a group's `items`
   * @returns the pages, in sidebar order
   */
  static groupPages(items) {
    const pages = [];
    items.forEach(function (item) {
      if (DashboardPage.isNavGroup(item)) {
        WebShell.groupPages(item.items).forEach(function (page) {
          pages.push(page);
        });
        return;
      }
      pages.push(item);
    });
    return pages;
  }

  // Every PAGE in one section, in sidebar order, with a group's pages spliced
  // in where the group sits — and a group inside a group spliced in the same
  // way (Cert issuance › SPIFFE, 2026-10-01). See the note above SECTIONS.
  /**
   * Lists every page in one section, in sidebar order, groups flattened.
   *
   * @param section - a row of SECTIONS
   * @returns the section's pages
   */
  static sectionPages(section) {
    const pages = WebShell.groupPages(section.items);
    return pages;
  }

  /**
   * Draws the trust realm switcher, a GET form to the realm switch route.
   *
   * @param req - the request
   * @returns the form as HTML; empty when no realm is defined
   */
  static realmChooser(shell, page) {
    if (!shell.realms) {
      return '';
    }
    const currentId = shell.realm.id;
    const options = shell.realms.map(function (realm) {
      return '<option value="' + kit.esc(realm.id) + '"' +
        (realm.id === currentId ? ' selected' : '') + '>' +
        kit.esc(realm.name) + '</option>';
    }).join('');
    return '<form class="realmpick" method="get" action="' +
      kit.esc(shell.realmRoot + WebShell.REALM_SWITCH_PATH) + '">' +
      '<label for="realmpick">Trust realm</label>' +
      '<input type="hidden" name="to" value="' +
        kit.esc(page.path) + '">' +
      '<div class="realmpickrow">' +
        '<select id="realmpick" name="realm">' + options + '</select>' +
        '<button class="secondary">Go</button>' +
      '</div></form>';
  }

  // THE BREADCRUMB TRAIL, AND IT IS ON EVERY PAGE RATHER THAN ONLY ON A
  // DRILL-DOWN.
  //
  // One line under the nav saying where the reader is and offering every level
  // above them: `Admin console › Applications › rfc9700-debugger`. The nav
  // answers "what else is there"; the trail answers "where am I and how do I
  // get back", which are different questions — the tab for the section you are
  // standing in is exactly the tab that tells you nothing about the page you
  // are standing on.
  //
  // Three things about it are deliberate.
  //
  // The section crumb on a drill-down is `up.href`, which carries THE FILTER
  // AND THE PAGE the reader clicked in from (see kit.listViewOf()), so the
  // trail goes back to where they were rather than to the top of an unfiltered
  // list. That is the whole difference between a breadcrumb and a link to the
  // section.
  //
  // The last crumb is NOT a link. It is the page being drawn, and a crumb that
  // reloads the page you are on is a control that does nothing — which teaches
  // a reader not to trust the ones beside it.
  //
  // The root crumb is `Admin console` on every page including `/admin` itself,
  // where it is the only crumb and is not a link. A trail that appeared on some
  // pages and not others would be a trail nobody looks for.
  /**
   * Draws the breadcrumb trail from `Admin console` to the current page.
   *
   * On a drill-down the section crumb goes back to the filter and page the
   * reader came from. The last crumb is never a link.
   *
   * @param active - the path of the page being drawn, or empty
   * @param up - upTo()'s answer on a drill-down, or nothing
   * @param title - the page's title, used where the page has no NAV row
   * @param labels - every console page's nav label by path (the shell
   *   answer's `navLabels`)
   * @returns the trail as HTML
   */
  static trailBar(active, up, title, labels) {
    const crumbs: any[] = [{ label: 'Admin console',
                      href: active === '/admin' ? null : '/admin' }];
    if (active !== '/admin') {
      const known = labels || {};
      const item = Object.prototype.hasOwnProperty.call(known, active)
        ? { label: known[active] } : null;
      // THE TITLE WHEN THE PAGE IS NOT IN THE NAV, which is every page this
      // shell draws that is not a console page: the sign-out confirmation, the
      // callback's refusal, the gate's own. Those pass `active` as '' or null,
      // so the leaf was an EMPTY crumb — "Admin console ›" with nothing after
      // it — on exactly the pages whose title is the only thing saying what
      // happened.
      const label = item ? item.label : (active || title);
      if (up) {
        crumbs.push({ label: label, href: up.href,
                      // Said in the tooltip rather than in the crumb, because
                      // "as you left it" is reassurance for somebody who
                      // wonders and noise for everybody else — and a crumb
                      // whose text changes with the filter is a crumb that
                      // moves under the pointer.
                      title: up.filtered
                        ? 'Back to ' + label + ' — the filter and page you ' +
                                               'came from'
                        : 'Back to ' + label });
        crumbs.push({ label: WebShell.shortCrumb(up.leaf || title),
                      title: String(up.leaf || title) });
      } else {
        crumbs.push({ label: label });
      }
    }
    const html = '<p class="crumb">' + crumbs.map(function (crumb, index) {
      const sep = index ? '<span class="sep">&rsaquo;</span>' : '';
      if (!crumb.href) {
        return sep + '<span class="leaf"' +
          (crumb.title ? ' title="' + kit.esc(crumb.title) + '"' : '') + '>' +
          kit.esc(crumb.label) + '</span>';
      }
      return sep + '<a href="' + kit.esc(crumb.href) + '"' +
        (crumb.title ? ' title="' + kit.esc(crumb.title) + '"' : '') + '>' +
        kit.esc(crumb.label) + '</a>';
    }).join('') + '</p>';
    return html;
  }

  /**
   * Shortens a crumb's text to MAX_CRUMB characters with an ellipsis.
   *
   * @param text - the crumb's text
   * @returns the text, cut if it was longer
   */
  static shortCrumb(text) {
    const value = String(text == null ? '' : text);
    return value.length > WebShell.MAX_CRUMB
      ? value.slice(0, WebShell.MAX_CRUMB - 1) + '…' :
           value;
  }

  /**
   * Draws the banner saying what the gate makes of this reader.
   *
   * It covers the gate off, nobody signed in, the open and bootstrap windows,
   * an unclaimed product console, a closed console and the roles held.
   *
   * @param gate - the gate state
   * @returns the banner as HTML
   */
  static gateBanner(shell) {
    const gate = shell.gate;
    const info = gate || {};
    if (!info.enforced) {
      return WebShell.openBanner();
    }
    // ---------------------------------------------------------------------
    // NOBODY IS SIGNED IN, WHICH IS A FOURTH STATE THIS BANNER DID NOT HAVE
    // (2026-09-10) — AND IT WAS REACHED ON THE ONE PAGE THAT IS ABOUT IT.
    //
    // Three pages are drawn in this state: the sign-out confirmation, the
    // callback's refusal, and the 401 a form POSTed without a session gets.
    // With no fourth branch every one of them fell through to the last one
    // below and read **"Signed in as `(nobody)`, holding no console role. This
    // is a READ-ONLY view"** — three sentences of which the first is false, the
    // second is meaningless and the third describes a console this reader
    // cannot open at all. Directly above a page whose whole text is that they
    // have just signed out.
    //
    // It is a branch rather than an empty string for the reason the banner is
    // on every page in the first place: this is the line that says what the
    // gate makes of the request, and a page that says nothing about it leaves a
    // reader who has met the other three states to guess which one this is.
    // `sideColumn()` below takes the NAVIGATION away in this state and this
    // keeps the SENTENCE, which is the difference between a control that cannot
    // work and a fact about why.
    // ---------------------------------------------------------------------
    if (!info.session) {
      return '<div class="warn"><strong>Nobody is signed in on this ' +
        'browser.</strong> This console needs a session of its own — it is ' +
        'an ordinary OpenID Connect client of this service, ' +
        '<code>sts-admin-console</code> in the registry — so every page of ' +
        'it will run the sign-in flow again. <a href="/admin">Open the ' +
        'console</a> to start one.</div>';
    }
    const who = '<code>' + kit.esc(info.username || '(nobody)') + '</code>';
    const elsewhere = WebShell.foreignSessionNote(info);
    if (info.open && info.bootstrap && info.bootstrap.seeded) {
      return kit.warn('<strong>Signed in as ' + who + ', and holding both ' +
        'roles because <code>' + kit.esc(info.bootstrap.username) +
        '</code> has not ' +
        'signed in to this console yet.</strong> Until this service\'s ' +
        'bootstrap administrator first signs in here, anyone who signs in ' +
        'has the whole console (<code>admin.openWhenEmpty</code>). From that ' +
        'moment only members of <code>' + kit.esc(info.readGroup) +
        '</code> and ' +
        '<code>' + kit.esc(info.writeGroup) + '</code> may use it — so ' +
        'grant yourself a role on <a href="/admin/rbac">Admin roles</a> ' +
        'first if you will need one.' + elsewhere);
    }
    if (info.open) {
      return kit.warn('<strong>Signed in as ' + who + ', and holding both ' +
        'roles because NOBODY HOLDS EITHER.</strong> This console always ' +
        'asks you to sign in — but neither <code>' + kit.esc(info.readGroup) +
        '</code> nor ' +
        '<code>' + kit.esc(info.writeGroup) + '</code> has a single member, ' +
        'and while that is true anyone who signs in has the whole console. ' +
        'This service has no password to bootstrap an administrator with, ' +
        'which is why the empty roster opens rather than closes ' +
        '(<code>admin.openWhenEmpty</code>). <strong>Grant somebody a role ' +
        'on <a href="/admin/rbac">Admin roles</a></strong> and the roster is ' +
        'enforced from that moment — including against you, so grant ' +
        'yourself one first.' + elsewhere);
    }
    // PRODUCT MODE, BEFORE THE CLAIM (2026-09-22, #103): the window does not
    // open, so a reader drawn a page here is being refused, and the sentence
    // says what would let them in.
    if (info.bootstrapPasswordRequired || info.windowWithheld) {
      const boot = info.bootstrap && info.bootstrap.username
        ? '<code>' + kit.esc(info.bootstrap.username) + '</code>'
        : 'the bootstrap administrator';
      return kit.warn('<strong>Signed in as ' + who + ', holding no ' +
        'console role: this console has not been claimed yet.</strong> In ' +
        'product mode only the bootstrap administrator, ' + boot + ', ' +
        'signing in with its password, can use this console until it does. ' +
        'Nobody else holds a role until one is granted, and a sign-in as ' +
        boot + ' by a federation partner, a certificate, a wallet or a ' +
        'Kerberos ticket does not count.' + elsewhere);
    }
    if (info.closed) {
      // Rendered for completeness rather than because a reader will meet it: a
      // request in this state is refused before a page is drawn. It is
      // reachable on the refusal page itself, which IS drawn.
      return '<div class="err"><strong>Nobody can use this console.</strong> ' +
        'No role has a member, and ' +
        (info.bootstrap && info.bootstrap.seeded && info.bootstrap.claimedAt
          ? 'the bootstrap administrator has already signed in, which closed ' +
            'the open window. '
          : (info.windowOpens === false
              ? 'this is product mode, which never opens the console to ' +
                'whoever signs in. '
              : '<code>admin.openWhenEmpty</code> is off. ')) +
        '<code>POST /admin-api/rbac/grant</code> is the way back in — it ' +
        'takes an access token carrying <code>admin:write</code> rather than ' +
        'this console\'s session, which is why it still works when this page ' +
        'cannot.</div>';
    }
    const held = (info.roles || []).map(function (id) {
      const label = (shell.roleLabels || {})[id];
      return '<strong>' + kit.esc(label || id) + '</strong>';
    }).join(' and ');
    return '<div class="ok">Signed in as ' + who + ', holding ' +
      (held || '<strong>no console role</strong>') + '. ' +
      (info.write
        ? 'Every control on these pages is yours.'
        : 'This is a READ-ONLY view: the forms are drawn so that you can see ' +
          'what they do, and posting one is ' +
          'refused. ' + kit.esc(info.writeGroup) + ' ' +
          'is the role that changes that.') +
      ' <a href="/admin/rbac">Who holds what</a>. Ending this session: <a ' +
      'href="/logout">/logout</a> signs you out of everything this service ' +
      'holds — every protocol at once — and <a ' +
      'href="/oauth2/logout">/oauth2/logout</a> is OIDC\'s own RP-initiated ' +
      'one. <a href="/admin/logout">/admin/logout</a> is the operator\'s ' +
      'view of the same lists, for somebody else.' + elsewhere + '</div>';
  }

  // SAID WHEN — AND ONLY WHEN — THE SESSION BELONGS TO ANOTHER REALM.
  //
  // **NOT DRAWN SINCE 2026-09-06.** `consoleRpSession()` (admin-core/
  // admin_views.js) answers `foreign: false` always — a relying-party session
  // belongs to the surface that minted it — so `info.foreignSession` is never
  // true and this returns ''. It is kept because the banner still reads the
  // member; the text below describes the arrangement it was written for.
  //
  // The console follows its reader across realms (the function that did it,
  // `sessionAnywhere()` in authn.js, is `consoleSession()` now), which is what
  // makes the switcher a switcher rather than a sign-in screen. Doing it
  // silently would be the wrong kind of quiet: a realm is a whole logical copy
  // of this service, so a reader looking at the default realm's tokens on a
  // session minted in `acme` is one keystroke from believing the two realms
  // share the sessions as well — and the next thing they conclude is that
  // `/oauth2/authorize` would have accepted it, which it would not.
  //
  // So the banner names the realm the session is held by, and says the one
  // thing that is easy to get wrong about it. It is empty in every other case,
  // including every service that has defined no realm.
  /**
   * Draws the sentence saying the session belongs to another realm.
   *
   * It is empty in practice: a console session is never foreign now.
   *
   * @param info - the gate state
   * @returns the sentence as HTML, or an empty string
   */
  static foreignSessionNote(info) {
    if (!info.foreignSession || !info.sessionRealm) {
      return '';
    }
    return ' Your session belongs to the trust realm <strong>' +
      kit.esc(info.sessionRealm.name) + '</strong> (<code>' +
      kit.esc(info.sessionRealm.id) +
      '</code>) and this console follows it into every realm, because the ' +
      'two console roles are groups in the one shared directory. <strong>The ' +
      'protocol endpoints do not:</strong> in this realm ' +
      '<code>/oauth2/authorize</code>, <code>/wsfed</code> and the two SAML ' +
      'profiles see no session at all and would ask you to sign in. <a ' +
      'href="/admin/realms">What a realm separates</a>.';
  }

  // The one line every console page of a realm being removed carries (#294),
  // pointing at the page that says the rest.
  /**
   * Draws the line every console page of a realm being removed carries,
   * linking to the realm's own page.
   *
   * @returns the banner as HTML, or an empty string when the realm is not
   *   being removed or no realm registry answers
   */
  static retiringBanner(shell) {
    const state = shell.retiring;
    if (!state) {
      return '';
    }
    return kit.warn('<strong>This realm is ' +
      (state.interrupted ? 'stuck half way through its removal'
                         : 'being removed') + '.</strong> ' +
      kit.esc(state.why) + ' <a href="/admin/realms?realm=' +
      encodeURIComponent(shell.realm.id) + '">Its page</a> says what ' +
      'is refused and how to finish.');
  }

  // THE REFRESH CONTROL, at the top of every page in this console.
  //
  // A LINK RATHER THAN A BUTTON, and this service's own CSP is the reason
  // rather than taste: `script-src 'none'` (see CLAUDE.md) means there is no
  // `location.reload()` to be had anywhere in here, and a <form method="get">
  // to the same path would silently drop the query string it was submitted with
  // unless every parameter were re-emitted as a hidden field. An <a> to the
  // current URL fetches the page again either way, because respond() sends
  // every page `Cache-Control: no-store` — so this is a real refresh and not a
  // possibly-cached one.
  //
  // It is worth having at all because every page in this console describes LIVE
  // state held in memory — counts, sessions, tokens expiring while they are
  // being read, a directory something else is writing — so "is this still
  // true?" is a question a reader has on all of them, and until now the only
  // answer was the browser's own reload with a stale `?notice=` still on the
  // URL.
  //
  // It is drawn in the QUIET form of a.btn on purpose. It is on every page
  // beside the heading, and a solid dark button in that position would read as
  // the most important thing on the page on all of them.
  //
  // **AND IT IS DRAWN ONLY WHERE THERE IS A PAGE TO RELOAD (2026-09-10)**,
  // which is `signOutControl()`'s test below and `sideColumn()`'s, met by a
  // third control on the same page. The sign-out confirmation is the answer to
  // a POST: its URL is `/admin/signout`, so Refresh there is a GET of a route
  // that has no GET — the gate sees no session and sends the reader into a
  // fresh sign-in flow. A control labelled *load this page again* that instead
  // starts a sign-in is worse than one that is missing, and the sentence above
  // is not true of that page either: what it describes is a session that has
  // ENDED, which is the one thing on this console that will not have changed
  // since it was drawn.
  /**
   * Draws the Refresh link at the top of a page.
   *
   * @param req - the request
   * @param gate - the gate state
   * @returns the link as HTML; empty when the gate is on and nobody is
   *   signed in
   */
  static refreshLink(shell, page) {
    const gate = shell.gate;
    if (gate && gate.enforced && !gate.session) {
      return '';
    }
    return '<a class="btn secondary" href="' +
      kit.esc(WebShell.refreshHref(page.path)) +
      '" title="Load this page again. Everything in this console is live ' +
      'state held in memory.">Refresh</a>';
  }

  // WHERE "REFRESH" POINTS: the page the reader is on, with the message
  // parameters taken back off.
  //
  // Root-relative and WITHOUT the realm prefix, which is the one thing here
  // that is easy to get wrong. app.js rewrites every `href="/…` on the way out
  // to carry the realm being read, so handing it `req.originalUrl` — which
  // already carries one — would produce /realm/acme/realm/acme/admin/tokens and
  // a 404 a long way from this function. realmRelativePath() is that same URL
  // with the prefix off, which is exactly what the rewrite expects to be given.
  //
  // `notice` and `error` come off because respondToAction() puts them there on
  // the redirect after a form POST: they describe something that has ALREADY
  // happened, and a Refresh that carried them would re-announce "12 tokens
  // revoked" over a page where nothing had been revoked this time. Everything
  // else survives — the filter, the page number, the search — because that is
  // what the reader is looking at, which is why this is a subtraction and not a
  // bare path.
  /**
   * Returns where Refresh points: this page without `notice` and `error`.
   *
   * @param req - the request
   * @returns the root-relative path and query, without the realm prefix
   */
  static refreshHref(path) {
    const here = String(path || '/admin');
    const cut = here.indexOf('?');
    if (cut < 0) {
      return here;
    }
    const params = new URLSearchParams(here.slice(cut + 1));
    params.delete('notice');
    params.delete('error');
    const query = params.toString();
    return query ? here.slice(0, cut) + '?' + query : here.slice(0, cut);
  }

  // ---------------------------------------------------------------------------
  // THE ACCOUNT MENU, at the top of every page in this console (2026-09-10).
  //
  // It holds two things — a link to this person's OWN account in the user
  // portal, and the Sign out button that used to sit bare in that corner. They
  // belong together because they are the two controls on this console that are
  // about the READER rather than about the service: everything else on every
  // page here changes what some protocol endpoint does for somebody else.
  //
  // **IT IS A `<details>`, WHICH IS TO SAY IT IS NOT A SCRIPT.** `script-src
  // 'none'` covers every page of this console but `/admin/api-explorer` (see
  // CLAUDE.md), and the test for an exception is that the page CANNOT work
  // without one — which a menu plainly can: `<details>`/`<summary>` opens and
  // closes with no JavaScript at all, and it is the same answer the console's
  // collapsible prose got. A new scripted page needs the argument made from
  // scratch and "it is a menu, menus have scripts" is not one.
  //
  // **WHAT THAT COSTS IS SAID OUT LOUD RATHER THAN LEFT TO BE DISCOVERED**: an
  // open `<details>` does not close when you click somewhere else on the page,
  // because closing it would take a listener on the document. It closes when
  // the summary is clicked again, and it is closed on every page load because
  // nothing remembers it. That is the same trade the two pictures made when
  // they lost pan and zoom, and the collapse-all switch the console does not
  // have.
  //
  // **IT IS DRAWN ONLY WHEN SOMEBODY IS SIGNED IN**, which is
  // `signOutControl()`'s test read once more rather than a new one: with the
  // gate off there may be no session at all, and a menu whose first row is
  // "your account" and whose second signs nobody out would be two controls that
  // cannot do anything. The summary is the USERNAME, so the answer to "who am I
  // signed in as here" is on every page of this console without opening
  // anything — which the bare button never gave.
  // ---------------------------------------------------------------------------
  /**
   * Draws the account menu: the reader's portal link and Sign out.
   *
   * It is a `<details>`, so it needs no script.
   *
   * @param req - the request
   * @param gate - the gate state
   * @returns the menu as HTML; empty when there is no session
   */
  static userMenu(shell) {
    const gate = shell.gate;
    if (!gate || !gate.session) {
      return '';
    }
    const html = '<details class="usermenu">' +
      '<summary title="' +
      kit.esc('Your own account. This console is read as ' + gate.username +
               ', and the two controls in here are the ones about YOU rather ' +
               'than about the service.') + '">' + kit.esc(gate.username) +
               '</summary>' +
      '<div class="usermenupanel">' +
      '<p class="usermenuwho">Signed in as <strong>' + kit.esc(gate.username) +
      '</strong></p>' +
      '<a href="' + kit.esc(shell.portalHref) + '" title="' +
      kit.esc('Your own account in the user portal — your password, your ' +
               'authenticator app, your security keys and the applications ' +
               'you can be signed in to. It is a different application from ' +
               'this console and it signs you in with the session you ' +
               'already hold, so nothing is typed again. The link is to the ' +
               'portal of the realm you signed in through, because that is ' +
               'where your account is, whichever realm you are reading.') +
               '">My account</a>' +
      WebShell.signOutControl(gate) +
      '</div></details>';
    return html;
  }

  // ---------------------------------------------------------------------------
  // THE SIGN OUT BUTTON, at the top of every page in this console (2026-09-06).
  //
  // **A FORM AND NOT A LINK, WHICH IS THE OPPOSITE OF refreshLink() ABOVE**,
  // and the two are worth reading together because the reasons are opposite
  // too. A refresh is a GET of the page you are on: safe, repeatable, and a
  // browser or a scanner following it costs nothing. A sign-out CHANGES STATE,
  // and a GET that ends somebody's session is one a link prefetcher, a mail
  // scanner or a `<link rel=prefetch>` can fire without anybody clicking
  // anything — so it is a POST, it carries this session's CSRF token
  // (`withCsrf()` puts it there, and the gate checks it), and it cannot be
  // triggered by navigation.
  //
  // **IT IS DRAWN ONLY WHEN SOMEBODY IS SIGNED IN.** With the gate off there
  // may be no session at all, and a Sign out button that signs nobody out is a
  // control whose only possible outcome is a refusal — the same test that keeps
  // `/admin/applications/new`'s conditional fields off a form that cannot use
  // them, and `newUserPage()`'s whole form off a process with no directory.
  // ---------------------------------------------------------------------------
  /**
   * Draws the Sign out button, a POST form to the console's sign-out path.
   *
   * @param gate - the gate state
   * @returns the form as HTML; empty when there is no session
   */
  static signOutControl(gate) {
    if (!gate || !gate.session) {
      return '';
    }
    return '<form class="signout" method="post" action="' +
           kit.esc(WebShell.SIGNOUT_PATH) +
      '"><button ' +
      'class="secondary" title="' +
      kit.esc('End this console session and the sign-on session behind it. ' +
               'You are signed in as ' + gate.username + '. Signing out of ' +
               'the console alone would not sign you out: the next page ' +
               'would run the sign-in flow, meet the sign-on session that is ' +
               'still live and let you straight back in.') +
               '">Sign out</button></form>';
  }

  // **NOT DRAWN FOR A READER WITH NO SESSION**, on the rule `refreshLink()` and
  // `sideColumn()` follow: the shell draws the sign-out page, the callback's
  // refusal and a 401 for somebody the gate has not let in, and this line names
  // a database host and the paths secrets are read from. Those belong to people
  // who may read `/admin/persistence` and `/admin/secrets`, not to anybody who
  // can reach the sign-out page.
  /**
   * Draws the footer line of runtime facts.
   *
   * A realm administrator sees only the mode.
   *
   * @param gate - the gate state
   * @returns the line as HTML; empty when the gate is on and nobody is
   *   signed in
   */
  static runtimeFooter(shell) {
    const gate = shell.gate;
    if (gate && gate.enforced && !gate.session) {
      return '';
    }
    const facts = shell.runtime || {};
    // A REALM ADMINISTRATOR (2026-09-14, #32) may not read `/admin/persistence`
    // or `/admin/secrets`, so they are not handed the database host, the
    // secret-store paths or the process arrangement those pages draw — nor the
    // two links, which would only answer 403. The realm's mode is theirs.
    if (gate && gate.authority === 'realm') {
      return '<div class="runtime">mode <code>' + kit.esc(facts.mode) +
        '</code></div>';
    }
    const html = '<div class="runtime">' +
      'running as <code>' + kit.esc(facts.process) + '</code>' +
      ' &middot; mode <code>' + kit.esc(facts.mode) + '</code>' +
      ' &middot; database <code>' + kit.esc(facts.database) + '</code>' +
      ' &middot; secret store: key-encryption key <code>' +
      kit.esc(facts.keyEncryptionKey) + '</code>, database password <code>' +
      kit.esc(facts.databasePassword) + '</code>' +
      ' &middot; <a href="/admin/persistence">persistence</a>, ' +
      '<a href="/admin/secrets">secrets</a></div>';
    return html;
  }

  // ---------------------------------------------------------------------------
  // EVERY SECTION HEADING AND EVERY FIELD GETS A TOOLTIP, DERIVED (2026-09-05).
  //
  // **IT IS A PASS OVER THE RENDERED BODY AND NOT 391 EDITED CALL SITES**, and
  // that is the same decision the folds made: the test is on the RENDERED text,
  // not on the caller's judgement. A page written tomorrow gets its tooltips
  // with nothing added to it, and none of them can drift from the prose they
  // are taken from, because they ARE that prose read at render time. A
  // hand-written hint beside each control would have been 391 new strings and a
  // second copy of every explanation on this console — the exact drift the
  // derived-summary rule exists to prevent.
  //
  // TWO RULES, and they differ because the two things differ:
  //
  //   * **A HEADING** takes the opening sentence of the FIRST note that follows
  //     it, before the next heading. That note is what the section is about, so
  //     its first sentence is what the heading means. The note stays where it
  //     is — sections keep their folds — so this adds a hover and removes
  //     nothing.
  //   * **A FIELD** takes the nearest note ABOVE it, because a hand-built form
  //     is explained by the paragraph introducing it rather than per control.
  //     Every field in one form therefore shares a tooltip, which is honest:
  //     that paragraph is genuinely what all of them are for, and a per-field
  //     sentence does not exist to be derived. Where a real per-field
  //     description DOES exist the caller has already set `title` itself —
  //     `configRow()` and the two other settings rows do — and this pass never
  //     touches an element that has one.
  //
  // **IT ONLY EVER ADDS.** An element that already carries a `title` is left
  // exactly as it was, so every hand-placed tooltip in this file still wins and
  // this can never overwrite a better one.
  //
  // The regexes are deliberately narrow — `<h2>`/`<h3>` with no attributes at
  // all, and `<label>` with none — because this console generates its own
  // markup and those are the two shapes it generates. Anything with an
  // attribute already is either hand-tooltipped or doing something this pass
  // should not guess about.
  /**
   * Adds tooltips to headings and labels from the prose beside them.
   *
   * A heading takes the first note after it, a label the nearest note above
   * it. An element that already has a `title` is left as it was.
   *
   * @param inner - the page body as HTML
   * @returns the body with the tooltips added
   */
  static withDerivedTips(inner) {
    const body = String(inner || '');
    let added = 0;

    // The plain text of the first note or fold summary in a fragment.
    const firstProseIn = function (fragment) {
      const summary = /<summary[^>]*>([\s\S]*?)<\/summary>/.exec(fragment);
      if (summary) {
        return kit.plainTextOf(summary[1]);
      }
      const note = /<p class="note"[^>]*>([\s\S]*?)<\/p>/.exec(fragment);
      return note ? kit.plainTextOf(note[1]) : '';
    };

    // HEADINGS. The window is from the heading to the next heading, so a
    // section with no prose of its own borrows nothing from the one below it.
    //
    // The tag may already carry attributes — `<h3 id="member">` is how every
    // anchored subsection on this console is written — so the match keeps them
    // and inserts the title beside them. A tag that already has a `title` is
    // skipped whole, which is the "it only ever adds" rule.
    const out = body.replace(/<(h2|h3)([^>]*)>/g,
                             function (whole, tag, attrs, at) {
      if (/\stitle=/.test(attrs)) {
        return whole;
      }
      const rest = body.slice(at);
      const next = /<h[123][\s>]/.exec(rest.slice(whole.length));
      const window = next ? rest.slice(0, whole.length + next.index) : rest;
      const prose = firstProseIn(window);
      if (!prose) {
        return whole;
      }
      added += 1;
      return '<' + tag + attrs + kit.tip(prose, Infinity) + '>';
    });

    // FIELDS. `lastIndexOf` rather than a forward scan: the note that explains
    // a form is above it, and the nearest one above is the one that explains
    // this form rather than the previous section's.
    //
    // `<label for="...">` is the settings rows' shape and they set their own
    // title, so those are skipped by the same rule as the headings — but a
    // hand-built `<label for="x">` with no title is not, which is why the match
    // cannot simply be the bare tag.
    const withFields = out.replace(/<label([^>]*)>/g,
                                   function (whole, attrs, at) {
      if (/\stitle=/.test(attrs)) {
        return whole;
      }
      const before = out.slice(0, at);
      const start = Math.max(before.lastIndexOf('<p class="note"'),
                             before.lastIndexOf('<summary'));
      if (start < 0) {
        return whole;
      }
      const prose = firstProseIn(before.slice(start));
      if (!prose) {
        return whole;
      }
      added += 1;
      return '<label' + attrs + kit.tip(prose, Infinity) + '>';
    });

    return withFields;
  }
}

export = WebShell;
