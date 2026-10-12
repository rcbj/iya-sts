// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_vc_demo.ts
//
// ---------------------------------------------------------------------------
// THE OPENID4VC DEMONSTRATION'S RUNTIME (#582, 2026-10-12).
//
// `oid4vc/vc-demo-spa.js`, served at `/issuer/demo.js`, is built from this.
// It is the public surfaces' runtime (`common/web_surface.ts`) over the
// demonstration's page table (`web_vc_demo_pages.ts`), with what these pages
// need beyond it:
//
//   * TWO BASES: the issuer's pages are under `/issuer` and the bar door's
//     under `/oid4vp`, where the protocol's own endpoints are too — so a
//     path is the surface's only where it is one of the table's five pages.
//   * THE START PAGES ACT AT ONCE. `/issuer/offer` and `/oid4vp/start` are
//     links a person follows, and following one makes an offer or starts a
//     presentation; the view a GET answers creates nothing (#574's rule), so
//     once the page is drawn the runtime sends the act — `POST
//     /vc-demo-api/offer` or `/start`, with the page's query as its body and
//     the view's CSRF token — once per page load. A `location` (the wallet,
//     on this device) REPLACES the page in the history, so Back does not make
//     a second; a `view` (the QR page for another device) is drawn in place;
//     a refusal is a problem page, in English.
//   * THE QR PAGE'S POLL is the wallet sign-in's (`web_vc_signin.ts`'s
//     `WalletFlow`, #574): one browser timer at a time, re-armed by each
//     answer, asking `GET /vc-demo-api/done?state=` every `pollSeconds`; once
//     the wallet on the other device has answered, the page moves on to the
//     outcome (`/oid4vp/done`), which replaces it in the history. The issuer's
//     QR page does not poll: an issuer is not told when a wallet redeems.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// Its browser objects arrive in `env`.
// ---------------------------------------------------------------------------

import WebSurface = require('../common/web_surface');
import WebVcSignin = require('./web_vc_signin');
import WebVcDemoPages = require('./web_vc_demo_pages');

type Json = any;

// The act each start page sends, by its view's kind.
const ACTS: Json = {
  offerStart: '/vc-demo-api/offer',
  presentStart: '/vc-demo-api/start'
};

/**
 * The QR page's poll: the wallet sign-in's flow, asking the demonstration's
 * API whether the Verifier has been answered.
 */
class DemoPoll extends WebVcSignin.Flow {
  /**
   * Called once a page is in the document: arms the poll on the request's
   * QR page, and stops any other.
   *
   * @param view - the page's view
   * @param ctx - its context
   * @returns nothing
   */
  onPut(view: Json, ctx: Json): void {
    this.stop();
    if (!view || view.kind !== 'request' || !view.state) {
      return;
    }
    this.armedFor = String(view.state);
    this.schedule(view, ctx.query || {});
  }

  /**
   * Asks whether the wallet has answered; moves on to the outcome when it
   * has.
   *
   * @param view - the request's view
   * @param query - the page's query
   * @param manual - unused: the page offers the outcome as a link
   * @returns whether it is still waiting
   */
  async check(view: Json, query: Json, manual: boolean): Promise<boolean> {
    void query;
    void manual;
    if (this.busy) {
      return true;
    }
    const state = String(view.state);
    this.busy = true;
    const answer = await this.surface.publicJson('GET',
      '/vc-demo-api/done?state=' + encodeURIComponent(state));
    this.busy = false;
    const json = answer.json;
    if (answer.status === 200 && json && json.view && !json.view.received) {
      return true;
    }
    this.stop();
    if (answer.status === 200 && json && json.view) {
      await this.surface.moveTo('/oid4vp/done?state=' +
                                encodeURIComponent(state));
    }
    return false;
  }
}

/**
 * The OpenID4VC demonstration's runtime.
 */
class VcDemoSurface extends WebSurface {
  // The poll of the request's QR page.
  private poll: DemoPoll;
  // Whether the page last routed to may still send its act: ONE act per
  // navigation, whatever is drawn again (the language chooser draws the
  // page again from the view in hand, without routing).
  private mayAct: boolean;

  /**
   * Makes the runtime.
   *
   * @param env - the browser's objects
   */
  constructor(env: Json) {
    super(env, { base: '/issuer', api: '/vc-demo-api',
                 pages: WebVcDemoPages.PAGES as Json,
                 namespaces: ['vcDemo'],
                 frame: WebVcDemoPages.frame });
    this.poll = new DemoPoll(this);
    this.mayAct = false;
  }

  /**
   * Draws the page the location names; a start page drawn by it may send
   * its act once.
   *
   * @returns nothing
   */
  async route(): Promise<void> {
    this.poll.stop();
    this.mayAct = true;
    await super.route();
  }

  /**
   * The surface's path of a full path under this realm: one of the table's
   * pages, under `/issuer` or `/oid4vp`; null otherwise.
   *
   * @param pathname - the path
   * @returns the path without the prefix, or null
   */
  surfacePath(pathname: string): string | null {
    const path = String(pathname || '');
    if (path.indexOf(this.prefix) !== 0) {
      return null;
    }
    const rest = path.slice(this.prefix.length) || '/';
    return WebVcDemoPages.find(rest) ? rest : null;
  }

  /**
   * Goes to one of the surface's pages in place of the one in hand.
   *
   * @param to - the path and query under the realm
   * @returns nothing
   */
  async moveTo(to: string): Promise<void> {
    this.env.history.replaceState(null, '', this.prefix + to);
    await this.route();
  }

  /**
   * Draws the page in hand; then a start page sends its act, and a QR page
   * arms its poll.
   *
   * @returns nothing
   */
  drawView(): void {
    super.drawView();
    const v = this.view;
    if (!v) {
      return;
    }
    const json = v.json || {};
    this.poll.onPut(json, this.context(v.query));
    if (ACTS[json.kind] && this.mayAct) {
      this.mayAct = false;
      this.act(ACTS[json.kind], v.query || {});
    }
  }

  /**
   * Sends a start page's act: the page's query as the body, with the
   * view's CSRF token; and draws what it answered.
   *
   * @param path - the operation's path
   * @param query - the page's query
   * @returns nothing
   */
  async act(path: string, query: Json): Promise<void> {
    const body: Json = {};
    Object.keys(query).forEach(function (name) {
      // The language a person asked for is the page's, not the act's.
      if (name !== 'ui_locales') {
        body[name] = String(query[name]);
      }
    });
    const csrf = String((this.lastAnswer && this.lastAnswer.csrf) || '');
    let status = 0;
    let json: Json = null;
    try {
      const res = await this.env.fetch(this.url(path), {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Accept': 'application/json',
                   'Content-Type': 'application/json',
                   'X-CSRF-Token': csrf },
        body: JSON.stringify(body) });
      status = res.status;
      json = await res.json().catch(function () {
        return null;
      });
    } catch (e) {
      // The service could not be reached: said as a problem page below.
      json = null;
    }
    if (json && json.ok && json.location) {
      // THE WALLET, ON THIS DEVICE: it replaces this page, so Back does not
      // make a second offer or request.
      this.env.location.replace(String(json.location));
      return;
    }
    if (json && json.ok && json.view && this.view) {
      this.view = { page: this.view.page, query: this.view.query,
                    json: json.view };
      this.drawView();
      return;
    }
    this.view = null;
    this.drawProblem('This page could not be drawn',
      (json && (json.errors || []).join(' ')) ||
      'The service answered ' + (status || 'nothing') + '.');
  }
}

declare const window: any;
declare const document: any;

if (typeof window !== 'undefined' && typeof document !== 'undefined') {
  new VcDemoSurface({
    fetch: window.fetch.bind(window), location: window.location,
    history: window.history, document: document,
    navigator: window.navigator, window: window
  }).start();
}

export = VcDemoSurface;
