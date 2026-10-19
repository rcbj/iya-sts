// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_authn.ts
//
// ---------------------------------------------------------------------------
// THE SIGN-IN SURFACE'S RUNTIME (#571, 2026-10-12).
//
// `authn/authn-spa.js`, served at `/authn/signin.js`, is built from this. It
// is the public surfaces' runtime (`common/web_surface.ts`) over the sign-in
// page table (`web_authn_pages.ts`), with what a sign-in needs beyond a form
// sent as JSON:
//
//   * THE CSRF BINDING (rcbj's decision 2 on #571): every act carries
//     `X-CSRF-Token` — the `csrf` the page's view answered, the token of the
//     browser's `sts_session` cookie — and `Content-Type: application/json`;
//     the browser adds the `Origin` (`authn/authn_api.ts` checks all three).
//   * WHICH OPERATION A BUTTON IS: the screen is one form with several
//     submit buttons, and each button's `action` is one operation, read off
//     the API's index (`mirrors` and `action`) — a control no operation is
//     the door of is refused rather than guessed, the surface's rule.
//   * THE NEXT STEP an act answers: `redirect`, `mfa` and `password-change`
//     navigate to `location`; `home-cell` sends the form it names exactly as
//     the re-post page #98 drew did (its method, its address, its fields);
//     a refusal draws the screen again with the sentence, from a fresh view.
//   * THE PASSKEY WITH NO USERNAME (#474): the button and the username
//     field's autofill (conditional mediation, WebAuthn Level 3 section
//     5.1.4) run the ceremony here — `/authn/webauthn.js` did it for the
//     server-drawn screen — over `POST …/passkey/options` and `POST
//     …/passkey`, a refused credential nobody holds signalled to the
//     credential manager (section 5.1.10), and the autofill not armed again
//     after a refusal, or an authenticator that answers it unasked loops.
//   * THE STEPS AFTER THE SCREEN (#572, #573): the second-factor pages and
//     the emailed factor's, each act a `POST /authn-api/mfa/{id}/…` named by
//     the form's page and the button pressed (`STEP_ACTS`); the passkey
//     step's ceremony (`stepPasskey()`), armed by `…/webauthn/options` and
//     answered to `…/webauthn` over `common/web_webauthn.ts`, which the
//     portal's ceremonies and the screen's passkey share — the script
//     `/authn/webauthn.js` ran it until #572; the waiting page of a mailed
//     link asking again every few seconds (`poll()`), which was a `<meta>`
//     refresh; and an answer that ENDS an emailed factor's page (`end`),
//     drawn as the end page the server drew.
//   * THE BROWSER FINGERPRINT (#62 P6), only where the view says the realm
//     asks for one: `/authn/fingerprint.js` loaded beside this script — the
//     library is not a `web_` module and cannot be bundled into one — and
//     its visitorId sent with the act.
//
//   * THE SPNEGO SIGN-IN'S BODIES (#575): `/authn/spnego`'s first 401, its
//     403 when off and its signed-in 200 are the shell with the page's
//     state in `data-sts-state`, drawn from it and never fetched — the
//     RFC 4559 exchange is the browser's navigation, untouched.
//
//   * THE OAUTH CONSENT SCREEN (#576): `/oauth2/consent` is a page of this
//     surface although it is not under `/authn` — the address the
//     authorization endpoint has always sent a person to — so the runtime
//     owns that one path beside its base (`surfacePath()`). Allow and Deny
//     go to `POST /authn-api/consent/{id}` with the limits a person
//     lowered, bound as every act here is, and the answer names the
//     authorization request to go back to. The bundle is served at
//     `/oauth2/consent.js` as well as `/authn/signin.js`, so the page's
//     listener serves its script whichever listener `/authn` is on (#472).
//
// `authn-spa.js` and never `authn.js` on disk: `authn/authn.js` is the server
// module `authn.ts` compiles to, and the bundle would overwrite it.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// Its browser objects arrive in `env`.
// ---------------------------------------------------------------------------

import WebSurface = require('../common/web_surface');
import WebPage = require('../common/web_page');
import WebWebAuthn = require('../common/web_webauthn');
import AuthnPages = require('./web_authn_pages');
// THE WALLET'S PAGES RUN (#574): the start, the poll, the Digital
// Credentials API call — `/authn/wallet.js` until then.
import WebVcSignin = require('../oid4vc/web_vc_signin');

type Json = any;

declare const HTMLFormElement: any;

// The script the fingerprint comes from, and the window member it leaves
// the visitorId in.
const FINGERPRINT_SCRIPT = '/authn/fingerprint.js';

// The consent screen's page (#576): the one path of this surface outside
// `/authn`.
const CONSENT_PATH = '/oauth2/consent';

// How long a pressed ceremony waits before asking once more, where it was
// refused as pending just after it aborted the autofill.
const PENDING_RETRY_MS = 300;

// THE STEPS' ACTS (#572, #573): for each page, the `action` of each of its
// buttons, the operation under `/authn-api/mfa/{id}/` it is, and the body
// it sends from the form's fields (and, for the mailed link, the token off
// the location). A button this table does not name is refused rather than
// guessed, the surface's rule.
const STEP_ACTS: Json = {
  '/authn/totp': {
    totp: { op: 'totp', body: function (f: Json): Json {
      return { code: f.code };
    } } },
  '/authn/backup-code': {
    'backup-code': { op: 'backup-code', body: function (f: Json): Json {
      return { code: f.code };
    } } },
  '/authn/password-factor': {
    password: { op: 'password', body: function (f: Json): Json {
      return { password: f.password };
    } } },
  '/authn/mfa-setup': {
    totp: { op: 'setup/totp', body: function (): Json {
      return {};
    } },
    'confirm-totp': { op: 'setup/confirm', body: function (f: Json): Json {
      return { code: f.code };
    } },
    webauthn: { op: 'setup/webauthn', body: function (): Json {
      return {};
    } },
    ignore: { op: 'skip', body: function (): Json {
      return {};
    } } },
  '/authn/email-code': {
    send: { op: 'email/send', body: function (): Json {
      return { kind: 'code' };
    } },
    verify: { op: 'email/code', body: function (f: Json): Json {
      return { code: f.code };
    } } },
  '/authn/email-link': {
    send: { op: 'email/send', body: function (): Json {
      return { kind: 'link' };
    } } },
  '/authn/email-link/open': {
    open: { op: 'email-link/open', body: function (f: Json, q: Json): Json {
      return { t: q.t || undefined };
    } } }
};

/**
 * The sign-in surface's runtime.
 */
class AuthnSurface extends WebSurface {
  // The sentence the last act was refused with, drawn once.
  private actError: string;
  // Whether the passkey autofill may be armed (not after a refused passkey).
  private autofill: boolean;
  // The conditional ceremony in flight, to abort for the button's own.
  private pendingAutofill: Json;
  // ONE WEBAUTHN REQUEST AT A TIME (#660, 2026-10-16): a document has one pending
  // request, a second is refused with an OperationError ("A request is
  // already pending" in Chrome), and an aborted one is pending until its
  // promise settles. `lastCall` settles when the last call did, and
  // `pressed` is a button's ceremony in flight, so a second press is
  // ignored rather than refused.
  private lastCall: Promise<void>;
  private pressed: boolean;
  // The RP ID of the last ceremony, for a signal.
  private rpId: string;
  // Whether the fingerprint's script is on the page.
  private fingerprintLoaded: boolean;
  // What a step's act left to say on the page drawn next (#573: `resent`).
  private notice: string;
  // The waiting page's next poll (#573), cleared whenever a page is drawn.
  private pollTimer: Json;
  // The wallet sign-in's pages' runtime (#574).
  private walletFlow: Json;

  /**
   * Makes the runtime.
   *
   * @param env - the browser's objects
   */
  constructor(env: Json) {
    super(env, { base: '/authn', api: '/authn-api',
                 pages: AuthnPages.PAGES,
                 namespaces: AuthnSurface.namespacesAt(env),
                 frame: AuthnPages.frame, brand: '' });
    this.actError = '';
    this.autofill = true;
    this.pendingAutofill = null;
    this.lastCall = Promise.resolve();
    this.pressed = false;
    this.rpId = '';
    this.fingerprintLoaded = false;
    this.notice = '';
    this.pollTimer = null;
    this.walletFlow = new WebVcSignin.Flow(this);
  }

  /**
   * The context a renderer is handed: the surface's, with the refusal of
   * the last act and whether the autofill is armed.
   *
   * @param query - the location's query
   * @returns the context
   */
  context(query: Json): Json {
    const ctx = super.context(query);
    ctx.error = this.actError;
    ctx.autofill = this.autofill;
    ctx.notice = this.notice;
    return ctx;
  }

  /**
   * Puts a page in the document, then wires what a page of this surface
   * runs: the passkey autofill and the fingerprint.
   *
   * @param title - the document's title
   * @param body - the page's body
   * @param ctx - the context
   * @returns nothing
   */
  put(title: string, body: string, ctx: Json): void {
    // A PAGE WITH NOWHERE TO GO. The language chooser redraws this same
    // page. A link or a button is a way on. The problem page — a sign-in
    // this service no longer has, and any other refusal that drew no view —
    // and every other screen that draws neither, tell the person to close
    // the browser tab or window and start over, and link the realm's root
    // page. The problem page draws its own card, and the line goes in it.
    if (!AuthnSurface.hasWayOn(body)) {
      const way = AuthnSurface.wayOut(this.t);
      const close = '</div>';
      if (body.indexOf('<div class="card">') === 0 &&
          body.slice(-close.length) === close) {
        body = body.slice(0, -close.length) + way + close;
      } else {
        body += way;
      }
    }
    super.put(title, body, ctx);
    this.actError = '';
    this.notice = '';
    if (this.pollTimer && this.env.window) {
      this.env.window.clearTimeout(this.pollTimer);
    }
    this.pollTimer = null;
    const view = ctx && ctx.view;
    // A wallet page's start, poll and button (#574); any other page stops
    // a poll the last one armed.
    this.walletFlow.onPut(view, ctx);
    if (!view) {
      return;
    }
    // THE WAITING PAGE ASKS AGAIN (#573), as its `<meta>` refresh did.
    // (`kind` too: a wallet's view carries a `state` of its own, #574.)
    if (view.state === 'wait' && view.kind === 'link' && this.env.window) {
      const self = this;
      this.pollTimer = this.env.window.setTimeout(function () {
        self.poll();
      }, Math.max(1, Number(view.seconds) || 4) * 1000);
    }
    if (view.fingerprint) {
      this.loadFingerprint();
    }
    // No username field to fill where none is asked for (#608).
    if (view.passkey && !view.usernameless && this.autofill) {
      this.armAutofill();
    } else {
      // THE AUTOFILL ENDS WITH ITS PAGE (#660, 2026-10-16): a page drawn in place
      // keeps the document, so the username screen's autofill was still
      // pending on the passkey step after a password, and the step's
      // ceremony was refused as pending at every press.
      this.stopAutofill();
    }
  }

  // --- the SPNEGO sign-in's bodies (#575) -----------------------------------
  //
  // `/authn/spnego` is an RFC 4559 exchange this runtime never drives: the
  // browser's own Negotiate (or a person reading a 401) is the navigation,
  // and the response it got is the shell, carrying the state its page is
  // drawn from in `data-sts-state` — there is nothing to fetch and no
  // operation to fetch it from, since the verdict and the session it drew
  // exist only on that one response. So an EMBEDDED page is drawn from the
  // shell, a link on it is the browser's (to the password screen, a full
  // navigation that mints its arrival cookie as `/authn/login` always does),
  // and a chosen language draws it again from the same state.

  /**
   * The catalog namespaces the page at the location draws: the SPNEGO
   * sign-in's `spnego` beside `authn` there, the consent screen's `consent`
   * alone (#576), `authn` and `wallet` (#574) everywhere else.
   *
   * @param env - the browser's objects
   * @returns the namespaces
   */
  static namespacesAt(env: Json): string[] {
    const path = String((env && env.location && env.location.pathname) || '');
    // THE WALLET'S CATALOG (#574) on every other page: the screen's wallet
    // button is followed IN PLACE, to a page drawn from it.
    // THE EMAILED FACTOR'S (#573) on every page but SPNEGO's, for the same
    // reason: the screen's email buttons are followed in place.
    if (/\/oauth2\/consent$/.test(path)) {
      // THE CONSENT SCREEN'S OWN (#576): it draws nothing of the sign-in's.
      return ['consent'];
    }
    return /\/authn\/spnego$/.test(path) ? ['authn', 'spnego']
                                          : ['authn', 'wallet', 'emailFactor'];
  }

  /**
   * The state the shell carried, or null where it carried none or it does
   * not read.
   *
   * @param env - the browser's objects
   * @returns `{ view, uiLocales?, preferredLanguage? }`, or null
   */
  static embeddedState(env: Json): Json {
    const text = WebPage.attribute(env, 'data-sts-state');
    if (!text) {
      return null;
    }
    try {
      const state = JSON.parse(text);
      return state && typeof state === 'object' && state.view ? state : null;
    } catch (e) {
      // Not JSON: the page says it could not be drawn.
      return null;
    }
  }

  /**
   * Whether the page in hand is an embedded one.
   *
   * @returns true on the SPNEGO sign-in's bodies
   */
  embeddedHere(): boolean {
    const path = this.surfacePath(this.env.location.pathname) || '';
    const page: Json = this.find(path);
    return !!(page && page.embedded);
  }

  /**
   * Draws the page the location names; an embedded page from the shell's
   * state, any other from its operation.
   *
   * @returns nothing
   */
  async route(): Promise<void> {
    if (!this.embeddedHere()) {
      await super.route();
      return;
    }
    const path = this.surfacePath(this.env.location.pathname) || '';
    const page: Json = this.find(path);
    const query = WebPage.queryOf(this.env.location.search);
    const state = AuthnSurface.embeddedState(this.env);
    const ui = query.ui_locales ||
      String((state && state.uiLocales) || '');
    this.t = await this.i18n.load({
      uiLocales: ui, own: state ? state.preferredLanguage : undefined });
    if (!state) {
      this.view = null;
      this.drawProblem('This page could not be drawn',
        'The service sent no state for it.');
      return;
    }
    this.lastAnswer = state;
    this.view = { page: page, query: query, json: state.view };
    this.drawView();
  }

  /**
   * Draws the page in hand again — an embedded page from its state, in the
   * language just chosen.
   *
   * @returns nothing
   */
  redraw(): void {
    if (this.embeddedHere()) {
      this.route();
      return;
    }
    super.redraw();
  }

  /**
   * Follows a link in place, except on an embedded page, whose links are
   * the browser's — and except a link TO an embedded page, which is a
   * navigation the server has to answer: the SPNEGO sign-in's state (and
   * the RFC 4559 challenge itself) arrives only on that response, so a page
   * routed in place had none and said it could not be drawn (2026-10-12).
   *
   * @param event - the click
   * @returns nothing
   */
  onClick(event: Json): void {
    if (this.embeddedHere()) {
      return;
    }
    let el = event && event.target;
    while (el && el.tagName !== 'A') {
      el = el.parentElement;
    }
    if (el && el.getAttribute) {
      const url = new URL(el.getAttribute('href') || '',
                          this.env.location.href);
      const path = url.origin === this.env.location.origin
        ? this.surfacePath(url.pathname) : null;
      const page: Json = path ? this.find(path) : null;
      if (page && page.embedded) {
        return;
      }
    }
    super.onClick(event);
  }

  // --- the consent screen (#576) --------------------------------------------

  /**
   * The surface's path of a full path, or null: every path under `/authn`,
   * and the consent screen's, which the authorization endpoint sends a
   * person to at `/oauth2/consent` (#576).
   *
   * @param pathname - the path
   * @returns the path without the prefix, or null
   */
  surfacePath(pathname: string): string | null {
    const own = super.surfacePath(pathname);
    if (own !== null) {
      return own;
    }
    const path = String(pathname || '');
    return path === this.prefix + CONSENT_PATH ? CONSENT_PATH : null;
  }

  /**
   * Sends Allow or Deny, with the limits a person lowered, to the
   * operation the index says is the consent screen's door.
   *
   * @param fields - the form's fields: `action` and the limit controls
   * @returns nothing
   */
  async consentAct(fields: Json): Promise<void> {
    if (!await this.ensureIndex()) {
      this.refused('The service\'s API could not be reached.');
      return;
    }
    const op = this.operationFor(CONSENT_PATH, String(fields.action || ''));
    if (!op) {
      this.refused('This control has no API operation (' + CONSENT_PATH +
                   '), so the page refuses it rather than guess.');
      return;
    }
    const answer = await this.send(String(op.path)
      .replace('{id}', encodeURIComponent(this.idHere())), fields);
    await this.next(answer);
  }

  // --- the act ---------------------------------------------------------------

  /**
   * The pending sign-in's or the step's id, off the location.
   *
   * @returns the id
   */
  idHere(): string {
    const query = WebPage.queryOf(this.env.location.search);
    return String(query.authn || query.change || query.mfa ||
                  query.consent || '');
  }

  /**
   * Sends an act: JSON, with the page's CSRF token.
   *
   * @param path - the operation's path, its `{id}` filled
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
   * The operation a form's button is, from the API's index.
   *
   * @param path - the surface's path the form is on
   * @param action - the button's `action`, for the screen
   * @returns the operation, or null
   */
  operationFor(path: string, action: string): Json {
    const rows = (this.indexRows || []).filter(function (op: Json) {
      return op.method === 'POST' && op.mirrors === 'POST ' + path &&
        (path !== '/authn/login' || op.action === action);
    });
    return rows.length ? rows[0] : null;
  }

  // The index's operations, once; the wallet's runtime reads them too.
  indexRows: Json[] | null = null;

  /**
   * Reads the API's index, once.
   *
   * @returns whether it is in hand
   */
  async ensureIndex(): Promise<boolean> {
    if (this.indexRows) {
      return true;
    }
    const index = await this.publicJson('GET', '/authn-api');
    if (index.status !== 200 || !index.json) {
      return false;
    }
    this.indexRows = index.json.operations || [];
    return true;
  }

  /**
   * The fingerprint to send, where the script computed one.
   *
   * @returns the visitorId, or ''
   */
  fingerprint(): string {
    const field = this.env.document.getElementById &&
      this.env.document.getElementById('device-fp');
    const own = field && field.value ? String(field.value) : '';
    return own || String((this.env.window &&
                          this.env.window.stsDeviceFingerprint) || '');
  }

  /**
   * Sends a form of this surface to the operation its button is.
   *
   * @param form - the form
   * @param submitter - the button pressed, if any
   * @returns nothing
   */
  async submit(form: Json, submitter: Json): Promise<void> {
    const target = new URL(form.getAttribute('action') || this.here(),
                           this.env.location.href);
    const path = this.surfacePath(target.pathname) || '';
    const fields = this.formFields(form, submitter);
    // START OVER (rcbj, 2026-10-12): the one button every step's page
    // carries, whichever page it is on, so it is asked before the page's own
    // acts — the passkey page's form is otherwise always its ceremony.
    if (String(fields.action || '') === 'start-over') {
      await this.startOver();
      return;
    }
    if (path === '/authn/webauthn') {
      await this.stepPasskey(String(fields.key || ''));
      return;
    }
    if (path === CONSENT_PATH) {
      await this.consentAct(fields);
      return;
    }
    if (STEP_ACTS[path]) {
      await this.stepAct(path, fields);
      return;
    }
    const pressed = String(fields.action || 'login');
    const action = pressed === 'email-code' || pressed === 'email-link'
      ? 'email' : pressed;
    if (!await this.ensureIndex()) {
      this.refused('The service\'s API could not be reached.');
      return;
    }
    const op = action === 'passkey'
      ? this.operationFor(path, 'passkey') : this.operationFor(path, action);
    if (!op) {
      this.refused('This control has no API operation (' + path + ' ' +
                   action + '), so the page refuses it rather than guess.');
      return;
    }
    if (action === 'passkey') {
      await this.passkey(false);
      return;
    }
    const fp = this.fingerprint();
    const remember = fields.remember_browser ? '1' : undefined;
    let body: Json = {};
    // THE FORCED PASSWORD CHANGE IS ASKED BY ITS PATH, FIRST: its form posts
    // no `action`, so `pressed` defaults to `login`, and asked after the
    // login branch it sent a login body — no new_password reached the
    // service, which answered "Enter a new password." to every try and the
    // change could never be made (2026-10-12, a fresh product instance).
    if (path === '/authn/password-change') {
      body = { new_password: fields.new_password,
               confirm_password: fields.confirm_password };
    } else if (action === 'login') {
      body = { username: fields.username, password: fields.password,
               use_webauthn: fields.use_webauthn ? '1' : undefined,
               webauthn_only: fields.webauthn_only ? '1' : undefined,
               remember_browser: remember, device_fp: fp || undefined };
    } else if (action === 'anonymous') {
      body = { remember_browser: remember, device_fp: fp || undefined };
    } else if (action === 'email') {
      body = { username: fields.username,
               kind: pressed === 'email-link' ? 'link' : 'code',
               remember_browser: remember, device_fp: fp || undefined };
    }
    const answer = await this.send(String(op.path)
      .replace('{id}', encodeURIComponent(this.idHere())), body);
    await this.next(answer);
  }

  /**
   * Draws a view an act answered in place of the page in hand, under the
   * act's sentence (#574: a wallet sign-in's refusal), or a problem page
   * where the answer carried none.
   *
   * @param json - the view, or null
   * @param error - the sentence, English
   * @returns nothing
   */
  showView(json: Json, error: string): void {
    const page = this.find(this.surfacePath(this.env.location.pathname) ||
                           '');
    if (!page || !json) {
      this.view = null;
      this.drawProblem('Nobody was signed in', error);
      return;
    }
    this.view = { page: page, query: WebPage.queryOf(this.env.location.search),
                  json: json };
    this.flash = error ? { error: error } : null;
    this.drawView();
  }

  /**
   * Draws the screen again with a refusal on it, from a fresh view.
   *
   * @param why - the sentence, English
   * @returns nothing
   */
  refused(why: string): void {
    this.actError = why;
    this.route();
  }

  // ---------------------------------------------------------------------------
  // WHAT AN ACT ANSWERED: the next step.
  // ---------------------------------------------------------------------------
  /**
   * Follows an act's answer.
   *
   * @param answer - `{ status, json }`
   * @returns nothing
   */
  async next(answer: Json): Promise<void> {
    const json = answer.json;
    if (!json) {
      this.refused('The service answered ' + answer.status + '.');
      return;
    }
    if (json.ok && json.next === 'stay') {
      this.notice = String(json.notice || '');
      await this.route();
      return;
    }
    if (json.ok && (json.next === 'redirect' || json.next === 'mfa' ||
                    json.next === 'password-change') && json.location) {
      await this.goTo(String(json.location));
      return;
    }
    // AN EMAILED FACTOR'S PAGE ENDS HERE (#573): the end page, as the
    // server drew it, from the answer.
    if (json.end && this.view) {
      this.view = { page: this.view.page, query: this.view.query,
                    json: { state: 'end', title: String(json.end.title),
                            sentence: (json.errors || []).join(' ') } };
      this.drawView();
      return;
    }
    // A SESSION REFUSED AT THE END OF A STEP (#572): the screen says it.
    if (json.location && json.next === 'refused') {
      await this.goTo(String(json.location));
      return;
    }
    if (json.ok && json.next === 'home-cell' && json.form) {
      this.sendForm(json.form);
      return;
    }
    if (json.passkey) {
      this.autofill = !!json.passkey.autofill;
      this.signalUnknown(String(json.passkey.unknownCredential || ''));
    }
    this.refused((json.errors || []).join(' ') ||
                 'The service answered ' + answer.status + '.');
  }

  /**
   * Sends the form a restart at the home cell names, as the page #98 drew
   * sent it: a GET is followed, a POST is posted with its fields.
   *
   * @param form - `{ method, action, fields }`
   * @returns nothing
   */
  sendForm(form: Json): void {
    if (String(form.method).toUpperCase() !== 'POST') {
      this.env.location.assign(String(form.action));
      return;
    }
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
    // A native submit: the protocol request goes to its endpoint as it
    // arrived, which is not this surface's to send as JSON.
    HTMLFormElement.prototype.submit.call(el);
  }

  /**
   * Goes where an answer names: in place where it is one of this surface's
   * pages on this origin — a step after the screen, the same page again —
   * and as a navigation otherwise (back to the caller, another surface).
   *
   * @param location - the address, as the answer named it
   * @returns nothing
   */
  async goTo(location: string): Promise<void> {
    const url = new URL(location, this.env.location.href);
    const path = url.origin === this.env.location.origin
      ? this.surfacePath(url.pathname) : null;
    if (path && this.find(path) && this.env.history) {
      await this.go(path + url.search);
      return;
    }
    this.env.location.assign(url.toString());
  }

  /**
   * Draws the page in hand; an end page carries its own refusal, so the
   * view's status is not said over it a second time.
   *
   * @returns nothing
   */
  drawView(): void {
    if (this.view && this.view.json && this.view.json.state === 'end') {
      this.flash = null;
    }
    super.drawView();
  }

  /**
   * A page that could not be drawn: where an act was just refused and the
   * page it was on can no longer be drawn (the step it named is gone), the
   * act's sentence is the one that says why. `put()` adds the way off,
   * since this page draws neither a link nor a button.
   *
   * @param title - what went wrong
   * @param detail - the detail
   * @returns nothing
   */
  drawProblem(title: string, detail: string): void {
    super.drawProblem(title, this.actError || detail);
  }

  /**
   * Whether a page's body already offers a way on: a link, or a button.
   * The language chooser is drawn around the body and is not one.
   *
   * @param body - the page's body
   * @returns true when the body has a link or a button
   */
  static hasWayOn(body: string): boolean {
    const html = String(body || '');
    return /<a\b[^>]*\bhref\s*=/i.test(html) ||
      /<button\b/i.test(html) ||
      /<input\b[^>]*\btype\s*=\s*["']submit["']/i.test(html);
  }

  /**
   * The way off a page that has none: close this tab and start over, and
   * a link to the realm's root page (`href="/"`, prefixed with the realm
   * when the page is put). In the page's language where the `authn`
   * catalog is loaded, and in English where it is not — the consent
   * screen loads none of it, and a refusal's own sentence stays English
   * either way. The English here is `authn/en.json`'s `stuck.close` and
   * `stuck.home`.
   *
   * @param t - the page's translator
   * @returns the markup
   */
  static wayOut(t: Json): string {
    const known = t && typeof t.has === 'function';
    const close = known && t.has('authn.stuck.close')
      ? t.html('authn.stuck.close')
      : 'Close this browser tab or window and start over.';
    const home = known && t.has('authn.stuck.home')
      ? t.html('authn.stuck.home')
      : 'Return to the home page';
    return '<p class="meta" id="authn-way-out">' + close + '</p>' +
      '<p><a id="authn-home" href="/">' + home + '</a></p>';
  }

  // --- the steps after the screen (#572, #573) -------------------------------

  /**
   * Sends a step's form to the operation its button is.
   *
   * @param path - the page the form is on
   * @param fields - the form's fields, the pressed button's `action` among
   *   them
   * @returns nothing
   */
  async stepAct(path: string, fields: Json): Promise<void> {
    const acts = STEP_ACTS[path] || {};
    const action = String(fields.action || Object.keys(acts)[0] || '');
    const act = acts[action];
    if (!act) {
      this.refused('This control has no API operation (' + path + ' ' +
                   action + '), so the page refuses it rather than guess.');
      return;
    }
    const query = WebPage.queryOf(this.env.location.search);
    const answer = await this.send('/authn-api/mfa/' +
      encodeURIComponent(this.idHere()) + '/' + act.op,
      act.body(fields, query));
    await this.next(answer);
  }

  /**
   * A step's Start over: the step named in the location (`mfa` for a second
   * factor, set-up or emailed factor, `change` for the forced password
   * change) is ended, and the answer sends the browser to the sign-in screen
   * for the same request.
   *
   * @returns nothing
   */
  async startOver(): Promise<void> {
    const query = WebPage.queryOf(this.env.location.search);
    const path = query.mfa
      ? '/authn-api/mfa/' + encodeURIComponent(String(query.mfa)) +
        '/start-over'
      : (query.change
        ? '/authn-api/password-change/' +
          encodeURIComponent(String(query.change)) + '/start-over'
        : '');
    if (!path) {
      this.refused('This page names no sign-in step to start over from.');
      return;
    }
    const answer = await this.send(path, {});
    await this.next(answer);
  }

  /**
   * The passkey step's ceremony: armed by the API, run by the browser, and
   * its result sent back — a registration where the step enrols a key, an
   * assertion otherwise (the API's `mode`).
   *
   * @param key - the passkey chosen (#534), or ''
   * @returns nothing
   */
  async stepPasskey(key: string): Promise<void> {
    if (this.pressed) {
      return;
    }
    this.pressed = true;
    try {
      const aborted = this.stopAutofill();
      const base = '/authn-api/mfa/' + encodeURIComponent(this.idHere());
      const armed = await this.send(base + '/webauthn/options',
                                    key ? { key: key } : {});
      if (!armed.json || !armed.json.ok) {
        await this.next(armed);
        return;
      }
      const c = armed.json;
      this.rpId = String(c.rpId || '');
      const nav = this.env.navigator;
      let credential: Json = null;
      if (!nav || !nav.credentials) {
        credential = { error: 'NotSupportedError',
                       message: 'no WebAuthn in this browser' };
      } else {
        try {
          credential = c.mode === 'create'
            ? WebWebAuthn.created(await this.webauthn('create',
                { publicKey: AuthnSurface.creationOptions(c) }, aborted))
            : WebWebAuthn.asserted(await this.webauthn('get',
                { publicKey: AuthnSurface.stepRequestOptions(c) }, aborted));
        } catch (e) {
          // The browser's error is deliberately ambiguous — no credential,
          // declined and timed out are one — so it is reported as given.
          credential = { error: e && e.name, message: e && e.message };
        }
      }
      const answer = await this.send(base + '/webauthn',
                                     { credential: JSON.stringify(credential) });
      await this.next(answer);
    } finally {
      this.pressed = false;
    }
  }

  /**
   * Runs one WebAuthn call once the last has settled (`lastCall`).
   *
   * @param kind - `get` or `create`
   * @param ask - the call's options
   * @param retry - whether this ceremony just aborted the autofill: Chrome
   *   can refuse the next call as pending for a moment after an abort, so
   *   an OperationError is asked once more
   * @returns the credential, or null
   */
  async webauthn(kind: string, ask: Json, retry: boolean): Promise<Json> {
    const nav = this.env.navigator;
    const settled = function (): void {
      return undefined;
    };
    for (let attempt = 0; ; attempt++) {
      await this.lastCall;
      const call = kind === 'create' ? nav.credentials.create(ask)
                                     : nav.credentials.get(ask);
      this.lastCall = Promise.resolve(call).then(settled, settled);
      try {
        return await call;
      } catch (e) {
        if (!retry || attempt > 0 || !e || e.name !== 'OperationError') {
          throw e;
        }
      }
      await this.pause(PENDING_RETRY_MS);
    }
  }

  /**
   * A promise that resolves after a while.
   *
   * @param ms - how long, in milliseconds
   * @returns the promise
   */
  pause(ms: number): Promise<void> {
    const win = this.env.window;
    return new Promise(function (resolve: () => void) {
      win.setTimeout(resolve, ms);
    });
  }

  /**
   * Aborts the autofill's ceremony, where one is in flight.
   *
   * @returns whether one was
   */
  stopAutofill(): boolean {
    const pending = this.pendingAutofill;
    if (!pending) {
      return false;
    }
    this.pendingAutofill = null;
    pending.abort();
    return true;
  }

  /**
   * A registration's options from the armed step: what `/authn/webauthn.js`
   * built from the page's data attributes.
   *
   * @param c - `POST …/webauthn/options`'s answer
   * @returns the publicKey options
   */
  static creationOptions(c: Json): Json {
    const o = c.options || {};
    const user = c.user || {};
    const algs = (o.algorithms && o.algorithms.length ? o.algorithms
                                                       : [-7, -257])
      .map(function (a: number): Json {
        return { type: 'public-key', alg: a };
      });
    return {
      rp: o.rp || { name: 'IYA STS', id: c.rpId },
      // THE USER HANDLE (#474): random bytes, never the username.
      user: { id: WebWebAuthn.bytes(String(user.id || '')),
              name: String(user.name || ''),
              displayName: String(user.displayName || user.name || '') },
      challenge: WebWebAuthn.bytes(c.challenge),
      pubKeyCredParams: algs,
      authenticatorSelection: o.authenticatorSelection ||
                              { userVerification: 'preferred' },
      // WebAuthn's own "do not enrol this authenticator twice".
      excludeCredentials: (c.exclude || []).map(function (id: string): Json {
        return { type: 'public-key', id: WebWebAuthn.bytes(id) };
      }),
      // credProps, and CTAP 2.1's minPinLength where the passkey policy
      // asks for it (#529).
      extensions: (o.credProps || o.minPinLength) ? Object.assign({},
        o.credProps ? { credProps: true } : {},
        o.minPinLength ? { minPinLength: true } : {}) : undefined,
      hints: o.hints && o.hints.length ? o.hints : undefined,
      attestation: o.attestation || 'direct',
      timeout: o.timeout || 60000 };
  }

  /**
   * An assertion's options from the armed step: every key of the step's
   * role, the authenticator picking.
   *
   * @param c - `POST …/webauthn/options`'s answer
   * @returns the publicKey options
   */
  static stepRequestOptions(c: Json): Json {
    const o = c.options || {};
    const allow = c.allow || [];
    return { challenge: WebWebAuthn.bytes(c.challenge),
             rpId: o.rpId || c.rpId,
             allowCredentials: allow.length ? allow.map(function (id: string) {
               return { type: 'public-key', id: WebWebAuthn.bytes(id) };
             }) : undefined,
             userVerification: o.userVerification || 'preferred',
             hints: o.hints && o.hints.length ? o.hints : undefined,
             timeout: o.timeout || 60000 };
  }

  /**
   * The waiting page asks whether its link was opened; the page is drawn
   * again only when the answer changed (opened elsewhere, ended).
   *
   * @returns nothing
   */
  async poll(): Promise<void> {
    this.pollTimer = null;
    const row = this.view && this.view.page;
    if (!row || typeof row.operation !== 'function') {
      return;
    }
    const answer = await this.publicJson('GET',
      row.operation(this.view.query));
    const json = answer.json || {};
    if (answer.status === 200 && json.view && json.view.state === 'wait') {
      const self = this;
      this.pollTimer = this.env.window.setTimeout(function () {
        self.poll();
      }, Math.max(1, Number(json.view.seconds) || 4) * 1000);
      return;
    }
    await this.route();
  }

  // --- the passkey -----------------------------------------------------------

  /**
   * The ceremony's request options from the armed challenge.
   *
   * @param armed - `POST …/passkey/options`'s answer
   * @returns the publicKey options
   */
  static requestOptions(armed: Json): Json {
    const o = armed.options || {};
    return { challenge: WebWebAuthn.bytes(armed.challenge),
             rpId: o.rpId || armed.rpId, allowCredentials: [],
             hints: o.hints && o.hints.length ? o.hints : undefined,
             userVerification: 'required', timeout: o.timeout || 60000 };
  }

  /**
   * Arms a ceremony on the pending sign-in.
   *
   * @returns the armed options, or null with the refusal drawn
   */
  async armPasskey(): Promise<Json> {
    const answer = await this.send('/authn-api/pending/' +
      encodeURIComponent(this.idHere()) + '/passkey/options', {});
    if (!answer.json || !answer.json.ok) {
      await this.next(answer);
      return null;
    }
    this.rpId = String(answer.json.rpId || '');
    return answer.json;
  }

  /**
   * Sends a ceremony's result (or why there is none) to the sign-in.
   *
   * @param credential - the assertion's JSON form, or `{ error, message }`
   * @returns nothing
   */
  async sendPasskey(credential: Json): Promise<void> {
    const remember = this.env.document.getElementById &&
      this.env.document.getElementById('remember_browser');
    const answer = await this.send('/authn-api/pending/' +
      encodeURIComponent(this.idHere()) + '/passkey', {
        credential: JSON.stringify(credential),
        remember_browser: remember && remember.checked ? '1' : undefined,
        device_fp: this.fingerprint() || undefined });
    await this.next(answer);
  }

  /**
   * The button's ceremony, or the autofill's.
   *
   * @param conditional - the autofill's (conditional mediation)
   * @returns nothing
   */
  async passkey(conditional: boolean): Promise<void> {
    if (conditional) {
      await this.autofillCeremony();
      return;
    }
    if (this.pressed) {
      return;
    }
    this.pressed = true;
    try {
      const aborted = this.stopAutofill();
      const nav = this.env.navigator;
      const armed = await this.armPasskey();
      if (!armed) {
        return;
      }
      if (!nav || !nav.credentials) {
        await this.sendPasskey({ error: 'NotSupportedError',
                                 message: 'no WebAuthn in this browser' });
        return;
      }
      let credential: Json = null;
      try {
        const a = await this.webauthn('get',
          { publicKey: AuthnSurface.requestOptions(armed) }, aborted);
        credential = a ? WebWebAuthn.asserted(a) : null;
      } catch (e) {
        credential = { error: e && e.name, message: e && e.message };
      }
      if (credential) {
        await this.sendPasskey(credential);
      }
    } finally {
      this.pressed = false;
    }
  }

  /**
   * The username field's autofill (conditional mediation). Its controller is
   * claimed before the first await, so a page drawn twice arms it once, and
   * a page drawn meanwhile can abort it before it asks.
   *
   * @returns nothing
   */
  async autofillCeremony(): Promise<void> {
    const nav = this.env.navigator;
    const controller = new this.env.window.AbortController();
    this.pendingAutofill = controller;
    const self = this;
    const mine = function (): boolean {
      return self.pendingAutofill === controller;
    };
    const armed = await this.armPasskey();
    if (!armed || !mine() || !nav || !nav.credentials) {
      if (mine()) {
        this.pendingAutofill = null;
      }
      return;
    }
    let credential: Json = null;
    try {
      const a = await this.webauthn('get', {
        publicKey: AuthnSurface.requestOptions(armed),
        mediation: 'conditional', signal: controller.signal }, false);
      credential = a ? WebWebAuthn.asserted(a) : null;
    } catch (e) {
      // An aborted or declined autofill is the page going on as a form.
      credential = null;
    }
    if (!mine()) {
      return;
    }
    this.pendingAutofill = null;
    if (credential) {
      await this.sendPasskey(credential);
    }
  }

  /**
   * Arms the username field's passkey autofill where the browser has it.
   *
   * @returns nothing
   */
  armAutofill(): void {
    const PKC = this.env.window && this.env.window.PublicKeyCredential;
    if (this.pendingAutofill || !PKC ||
        !PKC.isConditionalMediationAvailable ||
        !this.env.window.AbortController) {
      return;
    }
    const self = this;
    PKC.isConditionalMediationAvailable().then(function (yes: boolean) {
      if (yes && !self.pendingAutofill) {
        return self.passkey(true);
      }
      return null;
    }).catch(function () {
      return null;
    });
  }

  /**
   * Tells the credential manager of a credential this realm holds for
   * nobody (WebAuthn Level 3 section 5.1.10), where the answer named one.
   *
   * @param credentialId - the credential's id, or ''
   * @returns nothing
   */
  signalUnknown(credentialId: string): void {
    const PKC = this.env.window && this.env.window.PublicKeyCredential;
    if (!credentialId || !PKC || !PKC.signalUnknownCredential) {
      return;
    }
    PKC.signalUnknownCredential({ rpId: this.rpId,
                                  credentialId: credentialId })
      .catch(function () {
        return null;
      });
  }

  // --- the fingerprint -------------------------------------------------------

  /**
   * Loads `/authn/fingerprint.js` once, where the view asks for it.
   *
   * @returns nothing
   */
  loadFingerprint(): void {
    if (this.fingerprintLoaded || !this.env.document.createElement) {
      return;
    }
    this.fingerprintLoaded = true;
    const el = this.env.document.createElement('script');
    el.src = this.url(FINGERPRINT_SCRIPT);
    this.env.document.head.appendChild(el);
  }
}

declare const window: any;
declare const document: any;

if (typeof window !== 'undefined' && typeof document !== 'undefined') {
  new AuthnSurface({
    fetch: window.fetch.bind(window), location: window.location,
    history: window.history, document: document,
    navigator: window.navigator, window: window
  }).start();
}

export = AuthnSurface;
