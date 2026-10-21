// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_delegate.ts
//
// ---------------------------------------------------------------------------
// `/portal/delegate`, DRAWN IN THE BROWSER (#568), from `GET
// /account-api/delegate` (`portal_delegate.ts`): who may act for the person
// (RFC 8693 `may_act`), a form to name them and one to clear it.
//
// AND A SEARCH (2026-10-20, rcbj): a box that finds the native people of
// this realm by part of their username (`GET
// /account-api/delegate/candidates?q=`), each listed with a button that
// names them through the same POST the DN form sends. The DN form stays:
// an application is still named by its DN, and so may anybody.
//
// **IT ASKS AFTER THREE SECONDS WITHOUT A KEYSTROKE, AND NOT BEFORE**
// (rcbj: "only run it after the user has stopped typing for three seconds
// to avoid unnecessary searching"), and only for three characters or more;
// Enter asks at once. Every keystroke makes any answer still on its way
// STALE — `DelegateSearch`'s sequence number — so a slow answer to an older
// text is never drawn over a newer one. The timer is the browser's, in
// this page; the service's no-periodic-timers rule is about the server.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import kit = require('./web_portal_kit');

type Json = any;
type PortalPage = import('../types/account-api').PortalPage;

const PATH = kit.BASE + '/delegate';
// The search's operation, its fewest characters and how long it waits.
const SEARCH_OPERATION = '/account-api/delegate/candidates';
const SEARCH_MIN = 3;
const SEARCH_IDLE_MS = 3000;
// The element ids the search is wired by.
const SEARCH_FORM_ID = 'delegate-search';
const SEARCH_INPUT_ID = 'delegate-search-q';
const SEARCH_RESULTS_ID = 'delegate-search-results';

/**
 * The search's timing and ordering, apart from the document so it can be
 * driven by a test: `typed()` for a keystroke, `submitted()` for Enter.
 */
class DelegateSearch {
  private seq: number;
  private timer: unknown;

  /**
   * Makes the search.
   *
   * @param ask - asks the operation for a text, answering
   *   `{ status, json }` or null
   * @param draw - draws an answer for a text (or null: clear the results)
   * @param timers - `set(fn, ms)` and `clear(handle)`
   * @param idleMs - how long without a keystroke before it asks
   */
  constructor(private readonly ask: (q: string) => Promise<Json>,
              private readonly draw: (q: string, answer: Json) => void,
              private readonly timers: { set(fn: () => void, ms: number):
                                           unknown;
                                         clear(handle: unknown): void },
              private readonly idleMs: number = SEARCH_IDLE_MS) {
    this.seq = 0;
    this.timer = null;
  }

  /**
   * A keystroke: any answer still on its way is stale from now, and the
   * text is asked for once nothing more is typed for the idle time — when
   * it is long enough.
   *
   * @param value - the box's text
   * @returns nothing
   */
  typed(value: string): void {
    const self = this;
    this.seq += 1;
    this.cancel();
    const q = String(value || '').trim();
    if (q.length < SEARCH_MIN) {
      this.draw(q, null);
      return;
    }
    this.timer = this.timers.set(function () {
      self.timer = null;
      self.run(q);
    }, this.idleMs);
  }

  /**
   * Enter: asks at once, whatever the length — the operation says why a
   * text is too short, in the person's language.
   *
   * @param value - the box's text
   * @returns a promise of nothing
   */
  submitted(value: string): Promise<void> {
    this.cancel();
    return this.run(String(value || '').trim());
  }

  /**
   * Asks for a text and draws the answer, unless a newer keystroke or
   * search made it stale while it was on its way.
   *
   * @param q - the text
   * @returns a promise of nothing
   */
  async run(q: string): Promise<void> {
    this.seq += 1;
    const mine = this.seq;
    const answer = await this.ask(q);
    if (mine !== this.seq || !answer) {
      return;
    }
    this.draw(q, answer);
  }

  // The pending ask, if any, dropped.
  private cancel(): void {
    if (this.timer !== null) {
      this.timers.clear(this.timer);
      this.timer = null;
    }
  }
}

/**
 * `/portal/delegate`. A static utility class.
 */
class DelegatePages {
  /**
   * The page's body.
   *
   * @param view - `GET /account-api/delegate`'s answer
   * @param ctx - the render context
   * @returns the HTML
   */
  static render(view: Json, ctx: Json): string {
    const t = ctx.t;
    // The DN is data and goes in as a parameter (#539); which of the three
    // sentences is drawn is the code's choice, as it was.
    const current = view.mayAct
      ? '<p>' + (view.delegate
          ? (view.delegate.kind === 'person'
            ? t.html('portalDelegate.currentPerson', { dn: view.mayAct })
            : t.html('portalDelegate.currentApplication',
                     { dn: view.mayAct }))
          : t.html('portalDelegate.currentStale', { dn: view.mayAct })) +
        '</p>'
      : '<p>' + t.html('portalDelegate.nobody') + '</p>';
    return '<div class="card"><h2>' + t.html('portalDelegate.heading') +
      '</h2><p class="sub">' + t.html('portalDelegate.sub') + '</p>' +
      current +
      (view.notDelegated
        ? '<div class="err">' + t.html('portalDelegate.notDelegated') +
          '</div>' : '') +
      DelegatePages.searchForm(t) +
      '<form method="post" action="' + PATH + '">' +
      '<input type="hidden" name="action" value="set">' +
      '<p><label>' + t.html('portalDelegate.dnLabel') +
      ' <input type="text" name="delegate" size="60" maxlength="1024" ' +
      'required value="' + kit.esc(view.mayAct || '') +
      '" placeholder="uid=bob,ou=users,..."></label></p><p>' +
      '<button type="submit">' + t.html('portalDelegate.name') +
      '</button></p></form>' +
      (view.mayAct
        ? '<form method="post" action="' + PATH + '">' +
          '<input type="hidden" name="action" value="clear">' +
          '<p><button class="danger" type="submit">' +
          t.html('portalDelegate.clear') + '</button></p></form>' : '') +
      '</div>';
  }

  /**
   * The search's box: a form of its own, sent by the wiring below and
   * never to a portal path, and the place its answers are drawn.
   *
   * @param t - the translator
   * @returns the HTML
   */
  static searchForm(t: Json): string {
    return '<h3>' + t.html('portalDelegate.searchHeading') + '</h3>' +
      '<p class="sub">' + t.html('portalDelegate.searchSub') + '</p>' +
      '<form id="' + SEARCH_FORM_ID + '" role="search">' +
      '<p><label>' + t.html('portalDelegate.searchLabel') +
      ' <input type="search" id="' + SEARCH_INPUT_ID + '" name="q" ' +
      'size="30" maxlength="256" autocomplete="off" spellcheck="false">' +
      '</label> <button type="submit">' +
      t.html('portalDelegate.searchButton') + '</button></p></form>' +
      '<div id="' + SEARCH_RESULTS_ID + '" aria-live="polite"></div>';
  }

  /**
   * One answer of the search, drawn: a refusal, nobody, or the people with
   * a button each that names them. Every value is escaped.
   *
   * @param q - the text asked for
   * @param answer - `{ status, json }`
   * @param t - the translator
   * @returns the HTML
   */
  static results(q: string, answer: Json, t: Json): string {
    const json = (answer && answer.json) || {};
    if (!answer || answer.status !== 200) {
      return '<div class="err">' + kit.esc((json.errors || []).join(' ') ||
        t.text('portalDelegate.searchFailed')) + '</div>';
    }
    const people = Array.isArray(json.people) ? json.people : [];
    if (!people.length) {
      return '<p>' + t.html('portalDelegate.searchNone', { q: q }) + '</p>';
    }
    return '<table><tr><th>' + t.html('portalDelegate.colUid') +
      '</th><th>' + t.html('portalDelegate.colCn') + '</th><th>' +
      t.html('portalDelegate.colDn') + '</th><th></th></tr>' +
      people.map(function (one: Json): string {
        return '<tr><td><code>' + kit.esc(one.uid) + '</code></td><td>' +
          kit.esc(one.cn) + '</td><td><code>' + kit.esc(one.dn) +
          '</code></td><td><form method="post" action="' + PATH + '">' +
          '<input type="hidden" name="action" value="set">' +
          '<input type="hidden" name="delegate" value="' + kit.esc(one.dn) +
          '"><button type="submit">' + t.html('portalDelegate.choose') +
          '</button></form></td></tr>';
      }).join('') + '</table>' +
      (json.more ? '<p class="sub">' + t.html('portalDelegate.searchMore') +
                   '</p>' : '');
  }

  /**
   * Wires the search on a drawn page, when the page has one: a keystroke
   * waits for the idle time, Enter asks at once, and the form never
   * reaches the portal's own form handling.
   *
   * @param doc - the document
   * @param win - the window, for its timers
   * @param ask - asks the operation for a text (`{ status, json }`, or null)
   * @param t - the translator
   * @returns the search, or null where the page has none
   */
  static wire(doc: Json, win: Json, ask: (path: string) => Promise<Json>,
              t: Json): DelegateSearch | null {
    const form = doc && doc.getElementById
      ? doc.getElementById(SEARCH_FORM_ID) : null;
    const input = form ? doc.getElementById(SEARCH_INPUT_ID) : null;
    const out = form ? doc.getElementById(SEARCH_RESULTS_ID) : null;
    if (!form || !input || !out) {
      return null;
    }
    const search = new DelegateSearch(function (q: string): Promise<Json> {
      return ask(SEARCH_OPERATION + '?q=' + encodeURIComponent(q));
    }, function (q: string, answer: Json): void {
      out.innerHTML = answer ? DelegatePages.results(q, answer, t) : '';
    }, {
      set: function (fn: () => void, ms: number): unknown {
        return win.setTimeout(fn, ms);
      },
      clear: function (handle: unknown): void {
        win.clearTimeout(handle);
      }
    });
    input.addEventListener('input', function () {
      search.typed(String(input.value || ''));
    });
    // NOT THE PORTAL'S FORM HANDLING: stopped here, at the form, before
    // the document's listener sends it anywhere.
    form.addEventListener('submit', function (event: Json) {
      event.preventDefault();
      event.stopPropagation();
      search.submitted(String(input.value || ''));
    });
    return search;
  }

  /**
   * The search's timing and ordering, for a test that drives it without a
   * document.
   */
  static readonly Search = DelegateSearch;

  /**
   * The pages, for `web_portal_pages.ts`.
   */
  static readonly PAGES: PortalPage[] = [
    { path: PATH, operation: '/account-api/delegate',
      render: DelegatePages.render }
  ];
}

export = DelegatePages;
