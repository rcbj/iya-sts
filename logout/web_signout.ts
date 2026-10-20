// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_signout.ts
//
// ---------------------------------------------------------------------------
// THE SIGN-OUT'S RUNTIME (#577, 2026-10-12).
//
// `logout/signout-spa.js`, served at `/logout/signout.js`, is built from
// this: the public surfaces' runtime (`common/web_surface.ts`) over the
// sign-out's page table (`web_signout_pages.ts`), with what a sign-out needs
// beyond a form sent as JSON:
//
//   * THE CSRF BINDING (rcbj's decision 2 on #571): the act carries
//     `X-CSRF-Token` — the `csrf` the page's view answered, the token of the
//     browser's `sts_session` cookie — and `Content-Type: application/json`;
//     the browser adds the `Origin` (`authn/authn_api.ts` checks all three).
//   * WHICH OPERATION THE FORMS ARE: the one the API's index says mirrors
//     `POST /logout`, and a page with none refuses rather than guess.
//   * NOTHING TICKED ENDS NOTHING, as the page says under the button: the
//     ticked-items button with no box ticked sends nothing. (An act with an
//     empty selection is a GLOBAL sign-out — the JSON door's documented
//     default — so the page keeps its own promise here.)
//   * THE RESULT: where the act answers the signed-out document's `form`,
//     it is POSTED AS A NAVIGATION, so that document — the Front-Channel
//     Logout iframes, the cleanup images, the LogoutRequest links and the
//     partner sign-outs, under its own policy — is the browser's page, as it
//     was; where it answers a `view`, the result is drawn in place.
//
// `signout-spa.js` and never `signout.js` on disk, the name a compiled
// server module beside it would have.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// Its browser objects arrive in `env`.
// ---------------------------------------------------------------------------

import WebSurface = require('../common/web_surface');
import SignoutPages = require('./web_signout_pages');

type Json = any;

declare const HTMLFormElement: any;

/**
 * The sign-out's runtime.
 */
class SignoutSurface extends WebSurface {
  /**
   * Makes the runtime.
   *
   * @param env - the browser's objects
   */
  constructor(env: Json) {
    super(env, { base: '/logout', api: '/authn-api',
                 pages: SignoutPages.PAGES, namespaces: ['logout'],
                 brand: '' });
  }

  /**
   * Sends the act: JSON, with the page's CSRF token.
   *
   * @param path - the operation's path
   * @param body - the act's fields
   * @returns `{ status, json }`
   */
  async send(path: string, body: Json): Promise<Json> {
    const csrf = String((this.lastAnswer && this.lastAnswer.csrf) || '');
    let res: Json = null;
    try {
      res = await this.env.fetch(this.url(path), {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Accept': 'application/json',
                   'Content-Type': 'application/json',
                   'X-CSRF-Token': csrf },
        body: JSON.stringify(body) });
    } catch (e) {
      // THE SERVICE COULD NOT BE REACHED (#731): the act was never answered,
      // so nothing is known to have been signed out — and a page that said
      // nothing, the act's rejection unhandled, left the person to assume
      // it had been. It is a refusal drawn over the page, in English as
      // every refusal here is, and the page and the account control are
      // left as they were (nothing changed, so nothing is announced).
      return { status: 0, json: { ok: false, errors: [
        'The service could not be reached, so nothing was signed out. ' +
        'Check the connection and try again.'] } };
    }
    const json = await res.json().catch(function () {
      return null;
    });
    return { status: res.status, json: json };
  }

  /**
   * Sends one of the page's two forms to the operation that mirrors
   * `POST /logout`, and draws what it answered.
   *
   * @param form - the form
   * @param submitter - the button pressed, if any
   * @returns nothing
   */
  async submit(form: Json, submitter: Json): Promise<void> {
    const fields = this.formFields(form, submitter);
    // THE ACCOUNT STEP (#561): which account to sign out, or every one.
    if (form.getAttribute && form.getAttribute('data-sts-step') ===
        'accounts') {
      await this.chooseAccount(fields);
      return;
    }
    const select = fields.select === undefined ? []
      : [].concat(fields.select);
    if (fields.scope === 'selected' && !select.length) {
      this.flash = { error: 'Nothing is ticked, so nothing was ended.' };
      this.redraw();
      return;
    }
    if (!await this.ensureFormTable()) {
      this.flash = { error: 'The service\'s API could not be reached.' };
      this.redraw();
      return;
    }
    const op = this.formTable['POST /logout'];
    if (!op) {
      this.flash = { error: 'This control has no API operation (/logout), ' +
        'so the page refuses it rather than guess.' };
      this.redraw();
      return;
    }
    const body: Json = { scope: fields.scope === 'global' ? 'global'
                                                          : 'selected' };
    if (body.scope === 'selected') {
      body.select = select;
    }
    if (fields.username) {
      body.username = String(fields.username);
    }
    if (fields.account) {
      body.account = String(fields.account);
    }
    await this.signedOut(await this.send(String(op.path), body));
  }

  /**
   * Sends the account step's choice (#561): one account goes to that
   * person's inventory, drawn in place; every account is signed out, and
   * its result followed as the act's is.
   *
   * @param fields - the step's fields
   * @returns nothing
   */
  async chooseAccount(fields: Json): Promise<void> {
    if (!fields.account) {
      this.flash = { error: 'Choose an account, or every account.' };
      this.redraw();
      return;
    }
    if (!await this.ensureFormTable()) {
      this.flash = { error: 'The service\'s API could not be reached.' };
      this.redraw();
      return;
    }
    const op = this.formTable['POST /logout/accounts'];
    if (!op) {
      this.flash = { error: 'This control has no API operation ' +
        '(/logout/accounts), so the page refuses it rather than guess.' };
      this.redraw();
      return;
    }
    const answer = await this.send(String(op.path),
                                   { account: String(fields.account) });
    const json = answer.json;
    if (json && json.ok && json.next === 'inventory' && json.location) {
      await this.go(String(json.location));
      return;
    }
    if (json && !json.ok && json.view) {
      this.flash = { error: (json.errors || []).join(' ') };
      this.view = { page: (this.view && this.view.page) ||
                          this.find('/logout'),
                    query: {}, json: json.view };
      this.drawView();
      return;
    }
    await this.signedOut(answer);
  }

  /**
   * Follows the act's answer: the signed-out document as a navigation, the
   * result drawn in place, or the refusal over the page.
   *
   * @param answer - `{ status, json }`
   * @returns nothing
   */
  async signedOut(answer: Json): Promise<void> {
    const json = answer.json;
    if (json && json.ok && json.form) {
      this.sendForm(json.form);
      return;
    }
    if (json && json.ok && json.view) {
      const page = (this.view && this.view.page) || this.find('/logout');
      this.view = { page: page, query: {}, json: json.view };
      this.drawView();
      return;
    }
    this.flash = { error: (json && (json.errors || []).join(' ')) ||
                          'The service answered ' + answer.status + '.' };
    this.redraw();
  }

  /**
   * Posts the signed-out document's form as a navigation: its method, its
   * address and its fields, natively — the document is the browser's page,
   * not this surface's to draw.
   *
   * @param form - `{ method, action, fields }`
   * @returns nothing
   */
  sendForm(form: Json): void {
    const doc = this.env.document;
    const el = doc.createElement('form');
    el.method = 'post';
    el.action = String(form.action);
    Object.keys(form.fields || {}).forEach(function (name) {
      const input = doc.createElement('input');
      input.type = 'hidden';
      input.name = name;
      input.value = String(form.fields[name]);
      el.appendChild(input);
    });
    doc.body.appendChild(el);
    HTMLFormElement.prototype.submit.call(el);
  }

  /**
   * Follows a link in place, except one marked `data-sts-navigate`: the way
   * back from a page with nobody on it, which the server answers by sending
   * the browser to sign in first.
   *
   * @param event - the click
   * @returns nothing
   */
  onClick(event: Json): void {
    let el = event.target;
    while (el && el.tagName !== 'A') {
      el = el.parentElement;
    }
    if (el && el.getAttribute && el.getAttribute('data-sts-navigate')) {
      return;
    }
    super.onClick(event);
  }
}

declare const window: any;
declare const document: any;

if (typeof window !== 'undefined' && typeof document !== 'undefined') {
  new SignoutSurface({
    fetch: window.fetch.bind(window), location: window.location,
    history: window.history, document: document,
    navigator: window.navigator, window: window
  }).start();
}

export = SignoutSurface;
