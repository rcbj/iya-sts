// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_tls_surface.ts
//
// ---------------------------------------------------------------------------
// THE TLS DIAGNOSTIC PAGES' RUNTIME (#583, 2026-10-12).
//
// `tls/tls-pages-spa.js`, served at `/tls/pages.js`, is built from this:
// the runtime of a surface whose pages are the shell's
// (`common/web_embedded_surface.ts`) over the TLS pages' table
// (`web_tls_pages.ts`), with the two acts the `/tls` page has:
//
//   * THE ACTS ARE API CALLS (#583's plan, step 1): `Trust these` and `Empty
//     the truststore` are sent to `POST /tls/trust` and `POST
//     /tls/trust/clear` — the test-control API every script already calls,
//     under the mode gate it always had — as JSON, never as a form, and
//     what they answered is drawn in place: how many anchors were added or
//     removed, or the refusal, English.
//   * THE CSRF BINDING (rcbj's decision 2 on #571, as every act of #569's
//     surfaces): the act carries `X-CSRF-Token` — the `csrf` the shell's
//     state carried, the token of the page's own cookie — and
//     `Content-Type: application/json`; the browser adds the `Origin`
//     (`tls_pages.ts`'s `bound()` checks all three).
//   * A FORM THE PAGE DOES NOT KNOW IS REFUSED rather than guessed.
//
// `tls-pages-spa.js` and never `tls_pages.js` on disk, the name
// `tls_pages.ts` compiles to.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// Its browser objects arrive in `env`.
// ---------------------------------------------------------------------------

import WebEmbeddedSurface = require('../common/web_embedded_surface');
import TlsWebPages = require('./web_tls_pages');

type Json = any;

// The two acts, by the surface path their form posts to.
const TRUST_PATH = '/tls/trust';
const CLEAR_PATH = '/tls/trust/clear';

/**
 * The TLS diagnostic pages' runtime.
 */
class TlsSurface extends WebEmbeddedSurface {
  /**
   * Makes the runtime.
   *
   * @param env - the browser's objects
   */
  constructor(env: Json) {
    super(env, { base: '/tls', pages: TlsWebPages.PAGES as Json,
                 namespaces: ['tlsPages'], frame: TlsWebPages.frame,
                 brand: '' });
  }

  /**
   * Sends an act: JSON, with the page's CSRF token.
   *
   * @param path - the act's path, without the realm's prefix
   * @param body - the act's fields
   * @returns `{ status, json }`
   */
  async send(path: string, body: Json): Promise<Json> {
    const csrf = String((this.lastAnswer && this.lastAnswer.csrf) || '');
    const res = await this.env.fetch(this.url(path), {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Accept': 'application/json',
                 'Content-Type': 'application/json',
                 'X-CSRF-Token': csrf },
      body: JSON.stringify(body) });
    const json = await res.json().catch(function () {
      return null;
    });
    return { status: res.status, json: json };
  }

  /**
   * Sends one of the `/tls` page's two forms to its act, and draws what it
   * answered in place.
   *
   * @param form - the form
   * @param submitter - the button pressed, if any
   * @returns nothing
   */
  async submit(form: Json, submitter: Json): Promise<void> {
    const target = new URL(form.getAttribute('action') || '',
                           this.env.location.href);
    const path = this.surfacePath(target.pathname);
    if (path !== TRUST_PATH && path !== CLEAR_PATH) {
      this.flash = { error: 'This control has no API operation (' +
        (path || target.pathname) + '), so the page refuses it rather ' +
        'than guess.' };
      this.redraw();
      return;
    }
    const fields = this.formFields(form, submitter);
    let answer: Json;
    try {
      answer = path === TRUST_PATH
        ? await this.send(path, { certificates:
                                    String(fields.certificates || '') })
        : await this.send(path, {});
    } catch (e) {
      // The service could not be reached: the page says so over itself.
      this.flash = { error: 'The service could not be reached.' };
      this.redraw();
      return;
    }
    this.drawInPlace(TlsSurface.outcomeOf(path, answer));
  }

  /**
   * The view an act's answer is drawn as.
   *
   * @param path - the act's path
   * @param answer - `{ status, json }`
   * @returns the view
   */
  static outcomeOf(path: string, answer: Json): Json {
    const json = answer.json || {};
    if (answer.status !== 200 || json.error) {
      return { kind: 'notAdded',
               act: path === TRUST_PATH ? 'trust' : 'clear',
               error: String(json.error || ('The service answered ' +
                                            answer.status + '.')) };
    }
    return path === TRUST_PATH
      ? { kind: 'trusted', added: Number(json.added) || 0,
          anchors: Number(json.anchors) || 0 }
      : { kind: 'cleared', removed: Number(json.removed) || 0 };
  }
}

declare const window: any;
declare const document: any;

if (typeof window !== 'undefined' && typeof document !== 'undefined') {
  new TlsSurface({
    fetch: window.fetch.bind(window), location: window.location,
    history: window.history, document: document,
    navigator: window.navigator, window: window
  }).start();
}

export = TlsSurface;
