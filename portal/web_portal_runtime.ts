// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_portal_runtime.ts
//
// ---------------------------------------------------------------------------
// THE USER PORTAL'S RUNTIME (#568).
//
// The portal in the browser, on the admin console's pattern (#446) and with
// its OAuth half shared (`admin-ui/web_spa_client.ts`): it signs in as the
// public client `sts-user-portal`, holds its tokens in memory bound to a
// non-extractable DPoP key, draws every page from its `/account-api` answer
// with the renderers `web_portal_pages.ts` lists, and sends every form to the
// operation that mirrors it. rcbj's decisions on #568: the console's pattern
// (a public client with DPoP, reversing #444's D9 for the portal too),
// `/account-api`, and the pages nobody is signed in to drawn here as well.
//
// What it does, in the order a page load meets it:
//
//   * A PAGE FOR NOBODY — an activation or reset link, the forgot-password
//     form, an address verification — is drawn from an operation that takes
//     no token, with no column (`PortalShell.bare()`), and never sends the
//     browser to sign in.
//   * EVERY OTHER PAGE signs in first: the authorization code flow with PKCE
//     at the authorization server of the realm the portal was opened in,
//     `resource` that realm's `/account-api`, back at `/portal/callback`. A
//     reload signs in again, silently while the sign-on session lasts.
//   * ROUTING on the portal's own paths and queries, so a deep link — the
//     device page's `?user_code=`, a CIBA request, a link in a mail — and the
//     browser's history work as they did.
//   * FORMS: a GET form navigates; a POST form goes to the operation whose
//     `mirrors` names it (`GET /account-api` lists them), as JSON, and is
//     refused rather than guessed where none does. What it answers decides
//     what is drawn (`answered()`): the page again with a message, the page
//     drawn from a view the answer carries (a secret shown once), a step-up
//     sign-in, another address, a file.
//   * STEP-UP: an answer carrying `stepUp` sends the browser to sign in
//     again with `prompt=login` and the `acr_values` it names, and back to
//     the page — the CIBA and GNAP approvals' re-sign-in.
//
// A SESSION THAT ENDS sends the window to sign in again, back to the page it
// was on. The console's popup and form restore (#508) are not carried over;
// the portal's forms are short.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// Everything it touches in the browser arrives through the constructor.
// ---------------------------------------------------------------------------

import SpaClient = require('../admin-ui/web_spa_client');
import WebMessages = require('../admin-ui/web_messages');
import kit = require('./web_portal_kit');
import PortalShell = require('./web_portal_shell');
import PortalPages = require('./web_portal_pages');
import PortalWebAuthn = require('./web_portal_webauthn');

type Json = any;

// The portal's client: public, DPoP-bound (`sender_constraints.js`).
const CLIENT_ID = 'sts-user-portal';
// An ID Token for who signed in, and the one scope the account API takes.
const SCOPE = 'openid account:manage';
// The key the sign-in's one-use values cross the redirect under.
const SIGNIN_KEY = 'sts-portal-signin';
// How long before an access token's expiry it is refreshed, in seconds.
const REFRESH_EARLY = 30;
// The account API's base.
const API = '/account-api';
// What `sendOnce()` answers when the request needs a sign-in first.
const NEEDS_SIGN_IN = { needsSignIn: true };

/**
 * The user portal's runtime: sign-in, routing and forms.
 */
class PortalRuntime extends SpaClient {
  private me: Json;
  // `GET /account-api/locale`'s answer, for a page drawn for nobody: its
  // language data and the build.
  private nobody: Json;
  private t: Json;
  private formTable: Json;
  private view: Json;
  // What an act left to say on the next page drawn: `{ message, error }`.
  private flash: Json;
  // The path and query of the page last drawn: a `popstate` that changes
  // neither is a fragment's, which the browser has already answered.
  private drawnAt: string;

  /**
   * Makes the runtime.
   *
   * @param env - the browser's objects (`SpaClient`'s), and for a test
   *   `formDataOf`
   */
  constructor(env: Json) {
    super(env, PortalRuntime.prefixOf(env.location.pathname), {
      clientId: CLIENT_ID, scope: SCOPE,
      elsewhere: { '/oauth2': 'data-sts-oauth', '/logout': 'data-sts-authn' }
    });
    this.me = null;
    this.nobody = null;
    this.t = WebMessages.WebTranslator.fromData(null);
    this.formTable = null;
    this.view = null;
    this.flash = null;
    this.drawnAt = '';
  }

  // --- paths ---------------------------------------------------------------

  /**
   * Splits a path at the portal: the realm prefix before `/portal`.
   *
   * @param pathname - a path
   * @returns the prefix, '' in the default realm
   */
  static prefixOf(pathname: string): string {
    const m = /^(.*?)\/portal(?:\/.*)?$/.exec(String(pathname || ''));
    return m ? m[1] : '';
  }

  /**
   * The portal path of a full path under this realm, or null.
   *
   * @param pathname - the path
   * @returns `/portal...` without the prefix, or null
   */
  portalPath(pathname: string): string | null {
    const path = String(pathname || '');
    if (path.indexOf(this.prefix + kit.BASE) !== 0) {
      return null;
    }
    const rest = path.slice(this.prefix.length);
    return /^\/portal(\/|$)/.test(rest) ? rest.replace(/\/+$/, '') ||
      kit.BASE : null;
  }

  /**
   * The path and query being shown, without the realm prefix.
   *
   * @returns `/portal/...?...`
   */
  here(): string {
    const path = this.portalPath(this.env.location.pathname) || kit.BASE;
    return path + (this.env.location.search || '');
  }

  /**
   * The account API this portal's tokens are audienced to.
   *
   * @returns the resource indicator
   */
  resource(): string {
    return this.url(API);
  }

  // --- signing in ----------------------------------------------------------

  /**
   * The realm's authorization request for this client.
   *
   * @param state - the state
   * @param verifier - the PKCE verifier
   * @param extra - `prompt` and `acr_values` for a step-up, or nothing
   * @returns the URL
   */
  async authorizeUrl(state: string, verifier: string,
                     extra?: Json): Promise<string> {
    const params: Json = {
      response_type: 'code', client_id: CLIENT_ID,
      redirect_uri: this.url(kit.BASE + '/callback'), scope: SCOPE,
      state: state, code_challenge: await this.sha256(verifier),
      code_challenge_method: 'S256', resource: this.resource()
    };
    Object.keys(extra || {}).forEach(function (name) {
      if (extra[name]) {
        params[name] = String(extra[name]);
      }
    });
    // Pushed first where the realm requires it (RFC 9126, `SpaClient`).
    return this.authorizationRequestUrl(params);
  }

  /**
   * Sends the browser to sign in, remembering where to come back to.
   *
   * @param returnTo - the path and query to land on after
   * @param extra - `prompt` and `acr_values` for a step-up, or nothing
   * @returns nothing
   */
  async beginSignIn(returnTo: string, extra?: Json): Promise<void> {
    const verifier = this.random(32);
    const state = this.random(16);
    this.env.sessionStorage.setItem(SIGNIN_KEY, JSON.stringify({
      verifier: verifier, state: state, returnTo: returnTo,
      prefix: this.prefix }));
    this.env.location.assign(await this.authorizeUrl(state, verifier, extra));
  }

  /**
   * Finishes a sign-in on the callback.
   *
   * @returns nothing
   */
  async finishSignIn(): Promise<void> {
    const query = SpaClient.queryOf(this.env.location.search);
    let saved: Json = null;
    try {
      saved = JSON.parse(this.env.sessionStorage.getItem(SIGNIN_KEY) ||
                         'null');
    } catch (e) {
      // Not JSON: no sign-in this page started, which the check below says.
      saved = null;
    }
    this.env.sessionStorage.removeItem(SIGNIN_KEY);
    if (query.error) {
      this.drawProblem('Signing in was refused',
                       String(query.error_description || query.error));
      return;
    }
    if (!saved || !query.code || query.state !== saved.state) {
      this.drawProblem('This sign-in cannot be finished',
        'The answer from the authorization server does not belong to a ' +
        'sign-in this page started. Open the portal again to sign in.');
      return;
    }
    const answer = await this.tokenRequest({
      grant_type: 'authorization_code', code: query.code,
      redirect_uri: this.url(kit.BASE + '/callback'), client_id: CLIENT_ID,
      code_verifier: saved.verifier, resource: this.resource()
    });
    if (answer.status !== 200 || !answer.json.access_token) {
      this.drawProblem('Signing in failed',
        String(answer.json.error_description || answer.json.error ||
               'The token endpoint answered ' + answer.status + '.'));
      return;
    }
    this.keepTokens(answer.json);
    this.me = null;
    this.env.history.replaceState(null, '',
      this.prefix + String(saved.returnTo || kit.BASE));
    await this.route();
  }

  /**
   * Swaps the refresh token for a new pair.
   *
   * @returns whether it worked
   */
  async refresh(): Promise<boolean> {
    if (!this.refreshToken) {
      return false;
    }
    const answer = await this.tokenRequest({
      grant_type: 'refresh_token', refresh_token: this.refreshToken,
      client_id: CLIENT_ID, resource: this.resource()
    });
    if (answer.status !== 200 || !answer.json.access_token) {
      this.refreshToken = '';
      return false;
    }
    this.keepTokens(answer.json);
    return true;
  }

  // --- the account API -----------------------------------------------------

  /**
   * Sends one request with the tokens in hand, refreshing them where they
   * have run out.
   *
   * @param method - the method
   * @param target - the absolute URL
   * @param body - an object, sent as JSON, or nothing
   * @returns the response, or NEEDS_SIGN_IN
   */
  async sendOnce(method: string, target: string, body?: Json): Promise<Json> {
    const now = this.env.now ? this.env.now() : Date.now();
    if (this.accessToken && now > this.expiresAt - REFRESH_EARLY * 1000) {
      await this.refresh();
    }
    if (!this.accessToken) {
      return NEEDS_SIGN_IN;
    }
    for (let attempt = 0; attempt < 3; attempt++) {
      const headers: Json = {
        'Authorization': 'DPoP ' + this.accessToken,
        'DPoP': await this.proof(method, target, this.accessToken),
        'Accept': 'application/json'
      };
      if (body !== undefined && body !== null) {
        headers['Content-Type'] = 'application/json';
      }
      const res = await this.env.fetch(target, { method: method,
        headers: headers,
        body: body !== undefined && body !== null ? JSON.stringify(body)
                                                  : undefined });
      this.keepNonce(res);
      if (res.status !== 401) {
        return res;
      }
      const challenge = String((res.headers && res.headers.get &&
                                res.headers.get('WWW-Authenticate')) || '');
      if (/use_dpop_nonce/.test(challenge) && attempt === 0) {
        continue;
      }
      if (/invalid_token/.test(challenge) && await this.refresh()) {
        continue;
      }
      break;
    }
    this.accessToken = '';
    return NEEDS_SIGN_IN;
  }

  /**
   * Calls the account API with the person's token and reads its JSON; a
   * request that needs a sign-in sends the window to one, back to this page.
   *
   * @param method - GET or POST
   * @param path - the path under the realm, `/account-api/...` with its
   *   query
   * @param body - for a POST, an object
   * @returns `{ status, json, res }`, or null when a sign-in began
   */
  async apiJson(method: string, path: string, body?: Json): Promise<Json> {
    const res = await this.sendOnce(method, this.url(path), body);
    if (res === NEEDS_SIGN_IN) {
      await this.beginSignIn(this.here() + String(this.env.location.hash ||
                                                  ''));
      return null;
    }
    const json = await res.json().catch(function () {
      return null;
    });
    return { status: res.status, json: json, res: res };
  }

  /**
   * Calls an operation that takes no token.
   *
   * @param method - GET or POST
   * @param path - the path under the realm
   * @param body - for a POST, an object
   * @returns `{ status, json, res }`
   */
  async publicJson(method: string, path: string, body?: Json): Promise<Json> {
    const res = await this.env.fetch(this.url(path), {
      method: method,
      headers: Object.assign({ 'Accept': 'application/json' },
        body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      body: body !== undefined ? JSON.stringify(body) : undefined });
    const json = await res.json().catch(function () {
      return null;
    });
    return { status: res.status, json: json, res: res };
  }

  /**
   * The operation table, once: which operation each form goes to.
   *
   * @returns whether it is in hand
   */
  async ensureFormTable(): Promise<boolean> {
    if (this.formTable) {
      return true;
    }
    const index = await this.publicJson('GET', API);
    if (index.status !== 200 || !index.json) {
      return false;
    }
    const table: Json = {};
    (index.json.operations || []).forEach(function (op: Json) {
      if (op.mirrors) {
        table[op.mirrors] = op;
      }
    });
    this.formTable = table;
    return true;
  }

  // --- drawing -------------------------------------------------------------

  /**
   * Builds the translator from language data, and marks the document's
   * language and direction.
   *
   * @param locale - `{ negotiated, catalogs }`
   * @returns nothing
   */
  applyLocale(locale: Json): void {
    this.t = WebMessages.WebTranslator.fromData(locale);
    const root = this.env.document && this.env.document.documentElement;
    if (root && typeof root.setAttribute === 'function') {
      root.setAttribute('lang', this.t.lang);
      root.setAttribute('dir', this.t.dir);
    }
  }

  // A PAGE UNDER A REALM'S PREFIX LINKS INTO THAT REALM: the renderers draw
  // root-relative addresses, and the server-rendered portal had every one
  // prefixed on the way out (`common/app.js`); here the runtime does it.
  /**
   * Prefixes every root-relative `href`, `action`, `formaction` and `src`.
   *
   * @param html - the page
   * @param prefix - the realm's path prefix
   * @returns the page with its links in the realm
   */
  static realmLinks(html: string, prefix: string): string {
    if (!prefix) {
      return html;
    }
    return String(html).replace(/\b(href|action|formaction|src)="\/(?!\/)/g,
                                '$1="' + prefix + '/');
  }

  /**
   * Puts a page in the document and wires what it carries.
   *
   * @param title - the document's title
   * @param html - the page
   * @returns nothing
   */
  put(title: string, html: string): void {
    const doc = this.env.document;
    doc.title = title + ' — IYA STS';
    doc.body.innerHTML = PortalRuntime.realmLinks(html, this.prefix);
    this.drawnAt = this.env.location.pathname + this.env.location.search;
    this.wire();
    this.targetFragment();
  }

  /**
   * Draws a page that says something went wrong, with no frame.
   *
   * @param title - what went wrong
   * @param detail - the detail
   * @returns nothing
   */
  drawProblem(title: string, detail: string): void {
    this.put(title, PortalShell.bare('<div class="card"><h1>' +
      kit.esc(title) + '</h1><div class="err">' + kit.esc(detail) +
      '</div><p><a href="' + kit.BASE + '">' +
      (this.t.has('portal.signIn') ? this.t.html('portal.signIn')
                                   : 'Sign in') +
      '</a></p></div>', (this.me || this.nobody || {}).version));
  }

  // A TAB OR A SECTION IS A FRAGMENT, and `:target` is set only by a
  // navigation, so after a page is drawn the fragment is navigated to again
  // (the console's `targetFragment()`).
  /**
   * Makes the address's fragment the target of the page just drawn.
   *
   * @returns nothing
   */
  targetFragment(): void {
    const loc = this.env.location;
    const hash = String(loc.hash || '');
    if (!hash || !this.env.history || !loc.replace) {
      return;
    }
    this.env.history.replaceState(null, '', loc.pathname + loc.search);
    loc.replace(loc.pathname + loc.search + hash);
  }

  /**
   * Draws the page in hand from its view.
   *
   * @returns nothing
   */
  drawView(): void {
    const v = this.view;
    const nobody = this.nobody || {};
    const ctx = { t: this.t, query: v.query, prefix: this.prefix,
                  origin: this.env.location.origin, me: this.me,
                  locale: this.me ? this.me.locale : nobody.locale,
                  version: this.me ? this.me.version : nobody.version,
                  here: this.prefix + this.here() };
    const flash = this.flash || {};
    this.flash = null;
    const body = v.page.render(v.json, ctx);
    if ((v.page.access || 'person') !== 'person') {
      const title = v.page.title ? v.page.title(v.json, ctx) : 'IYA STS';
      this.put(title, PortalShell.bare(
        (flash.error ? '<div class="err">' + kit.esc(flash.error) + '</div>'
                     : '') +
        (flash.message ? '<div class="ok">' + kit.esc(flash.message) +
                         '</div>' : '') + body,
        ctx.version));
      return;
    }
    this.put(PortalShell.headingFor(v.page.path, this.t),
      PortalShell.frame(this.me, { active: v.page.path, query: v.query,
        message: flash.message || '', error: flash.error || '',
        cards: body, prefix: this.prefix, t: this.t }));
  }

  /**
   * Draws the page the location names.
   *
   * @returns nothing
   */
  async route(): Promise<void> {
    const path = this.portalPath(this.env.location.pathname) || kit.BASE;
    if (path === kit.BASE + '/callback') {
      await this.finishSignIn();
      return;
    }
    const query = SpaClient.queryOf(this.env.location.search);
    const page = PortalPages.find(path);
    const forNobody = page && (page.access || 'person') !== 'person';
    if (!forNobody && !this.accessToken) {
      await this.beginSignIn(this.here() + String(this.env.location.hash ||
                                                  ''));
      return;
    }
    if (forNobody && !this.me) {
      const locale = await this.publicJson('GET', API + '/locale');
      if (locale.status === 200 && locale.json) {
        this.nobody = locale.json;
        this.applyLocale(locale.json.locale);
      }
    }
    if (!forNobody && !this.me) {
      const me = await this.apiJson('GET', API + '/me');
      if (!me) {
        return;
      }
      if (me.status !== 200 || !me.json) {
        this.drawProblem('The portal could not be drawn',
          (me.json && me.json.errors && me.json.errors.join(' ')) ||
          'The account API answered ' + me.status + '.');
        return;
      }
      this.me = me.json;
      this.applyLocale(this.me.locale);
    }
    if (!page) {
      this.view = null;
      this.put('Not a page', PortalShell.bare('<div class="card"><p>' +
        '<code>' + kit.esc(path) + '</code> is not a page of this portal.' +
        '</p><p><a href="' + kit.BASE + '">' + kit.BASE + '</a></p></div>',
        this.me && this.me.version));
      return;
    }
    const qs = new URLSearchParams(query).toString();
    const target = page.operation + (qs ? '?' + qs : '');
    const answer = forNobody ? await this.publicJson('GET', target)
                             : await this.apiJson('GET', target);
    if (!answer) {
      return;
    }
    const json = answer.json || {};
    // A STEP-UP the page asked for (`?stepup=`): sign in again with what the
    // answer names, and back to the page without the marker.
    if (json.stepUp) {
      const back = Object.assign({}, query);
      delete back.stepup;
      delete back.gnapstepup;
      await this.beginSignIn(path + kit.queryOf(back), {
        prompt: json.stepUp.prompt || 'login',
        acr_values: json.stepUp.acrValues || '',
        max_age: json.stepUp.maxAge });
      return;
    }
    // A REFUSAL IS SAID whether or not it carries a view to draw the page
    // from (an unknown device code, a lockout) — unless that view draws it
    // itself (`answered()`'s rule).
    const own = json.view && (json.view.refused || json.view.notOffered ||
                              json.view.tooMany);
    if ((answer.status !== 200 || json.ok === false) && !own) {
      this.flash = { error: (json.errors || []).join(' ') ||
                            'The account API answered ' + answer.status + '.' };
    }
    this.view = { page: page, query: query, json: json.view || json };
    this.drawView();
  }

  /**
   * Goes to a portal path, adding it to the history.
   *
   * @param to - the path and query under the realm, `/portal/...`
   * @returns nothing
   */
  async go(to: string): Promise<void> {
    this.env.history.pushState(null, '', this.prefix + to);
    await this.route();
  }

  // --- forms and links -----------------------------------------------------

  /**
   * A form's fields as an object: a repeated name is an array, and the CSRF
   * field a form drawn by the server carried is left out (the token is the
   * credential here).
   *
   * @param form - the form element
   * @param submitter - the button pressed, if any
   * @returns the fields
   */
  fieldsOf(form: Json, submitter: Json): Json {
    const data = this.env.formDataOf ? this.env.formDataOf(form)
                                     : new FormData(form);
    if (submitter && submitter.name) {
      data.delete(submitter.name);
      data.append(submitter.name, submitter.value);
    }
    const out: Json = {};
    data.forEach(function (value: Json, name: string) {
      if (name === 'csrf_token' || typeof value !== 'string') {
        return;
      }
      if (Object.prototype.hasOwnProperty.call(out, name)) {
        out[name] = [].concat(out[name], value);
      } else {
        out[name] = value;
      }
    });
    return out;
  }

  /**
   * Sends a POST form to the operation that mirrors it, and draws what it
   * answered.
   *
   * @param form - the form
   * @param submitter - the button pressed, if any
   * @returns nothing
   */
  async submit(form: Json, submitter: Json): Promise<void> {
    const posted = (submitter && submitter.getAttribute &&
                    submitter.getAttribute('formaction')) ||
                   form.getAttribute('action') || this.here();
    const target = new URL(posted, this.env.location.href);
    const path = this.portalPath(target.pathname);
    const fields = this.fieldsOf(form, submitter);
    target.searchParams.forEach(function (value: string, name: string) {
      fields[name] = value;
    });
    if (!await this.ensureFormTable()) {
      this.flash = { error: 'The account API could not be reached.' };
      this.drawView();
      return;
    }
    const op = path ? this.formTable['POST ' + path] : null;
    if (!op) {
      this.flash = { error: 'This control has no /account-api operation (' +
        (path || target.pathname) + '), so the portal refuses it rather ' +
        'than guess.' };
      if (this.view) {
        this.drawView();
      }
      return;
    }
    const forNobody = op.access !== 'person';
    const answer = forNobody ? await this.publicJson('POST', op.path, fields)
                             : await this.apiJson('POST', op.path, fields);
    if (!answer) {
      return;
    }
    await this.answered(path, answer);
  }

  // WHAT AN ACT ANSWERED, AND WHAT IS DRAWN FOR IT — the conventions every
  // operation of `/account-api` keeps (`account-api/CLAUDE.md`):
  //   * `files`: each saved, as the page's download did.
  //   * `location`: another site (a claim source's sign-in) — the window goes.
  //   * `stepUp`: sign in again with what it names, back to this page.
  //   * `view`: the page drawn from it, in place — a secret shown once never
  //     reaches a URL or the history.
  //   * `go`: another portal page, with the message.
  //   * otherwise the page asked again, with `message` or the `errors`.
  /**
   * Draws what an act answered.
   *
   * @param path - the portal path the form was on
   * @param answer - `{ status, json }`
   * @returns nothing
   */
  async answered(path: string | null, answer: Json): Promise<void> {
    const json = answer.json || { ok: answer.status < 400 };
    // A VIEW THAT DRAWS ITS OWN REFUSAL — a link page's one sentence, the
    // forgotten-password form when reset is not offered or the rate limit
    // was met — says so (`refused`, `notOffered`, `tooMany`), and the
    // refusal is not drawn a second time above it.
    const v = json.view || {};
    const ownRefusal = !!(v.refused || v.notOffered || v.tooMany);
    const said = json.ok === false
      ? (ownRefusal ? {} : { error: (json.errors || []).join(' ') ||
                                    'Refused (' + answer.status + ').' })
      : { message: String(json.message || '') };
    if (Array.isArray(json.files) && json.files.length) {
      const self = this;
      json.files.forEach(function (one: Json) {
        self.saveBase64(String(one.name), String(one.mime ||
                        'application/octet-stream'), String(one.base64));
      });
    }
    if (json.location) {
      this.env.location.assign(String(json.location));
      return;
    }
    if (json.stepUp) {
      await this.beginSignIn(this.here(), {
        prompt: json.stepUp.prompt || 'login',
        acr_values: json.stepUp.acrValues || '',
        max_age: json.stepUp.maxAge });
      return;
    }
    if (json.signedOut) {
      this.signOut();
      return;
    }
    if (json.view) {
      const page = path ? PortalPages.find(path) : null;
      const row = page || (this.view && this.view.page);
      if (row) {
        this.view = { page: row, query: this.view && this.view.page === row
          ? this.view.query : {}, json: json.view };
        this.flash = said;
        this.drawView();
        return;
      }
    }
    this.flash = said;
    if (json.go) {
      await this.go(String(json.go));
      return;
    }
    await this.route();
  }

  /**
   * Saves a file an answer carried as base64.
   *
   * @param name - its file name
   * @param mime - its media type
   * @param base64 - its bytes
   * @returns nothing
   */
  saveBase64(name: string, mime: string, base64: string): void {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    const href = URL.createObjectURL(new Blob([bytes], { type: mime }));
    const a = this.env.document.createElement('a');
    a.href = href;
    a.download = name.replace(/[\/\\]/g, '_');
    this.env.document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(href);
  }

  /**
   * Follows a link in place when it is a portal page of this origin.
   *
   * @param event - the click
   * @returns nothing
   */
  onClick(event: Json): void {
    if (event.defaultPrevented || event.button !== 0 || event.metaKey ||
        event.ctrlKey || event.shiftKey || event.altKey) {
      return;
    }
    let el = event.target;
    while (el && el.tagName !== 'A') {
      el = el.parentElement;
    }
    if (!el || el.target === '_blank' || el.hasAttribute('download')) {
      return;
    }
    const url = new URL(el.getAttribute('href') || '', this.env.location.href);
    const path = url.origin === this.env.location.origin
      ? this.portalPath(url.pathname) : null;
    if (!path || path === kit.BASE + '/callback') {
      return;
    }
    event.preventDefault();
    if (url.pathname === this.env.location.pathname &&
        url.search === this.env.location.search && url.hash) {
      this.env.location.hash = url.hash;
      return;
    }
    this.go(path + url.search + url.hash);
  }

  /**
   * Handles a submitted form: the sign-out, a GET form's navigation, or an
   * act.
   *
   * @param event - the submit event
   * @returns nothing
   */
  onSubmit(event: Json): void {
    const form = event.target;
    const target = new URL(form.getAttribute('action') || this.here(),
                           this.env.location.href);
    const path = target.origin === this.env.location.origin
      ? this.portalPath(target.pathname) : null;
    // A FORM THAT IS NOT THE PORTAL'S — the language chooser at
    // `/authn/language`, the wider sign-out at `/logout` — is the browser's.
    if (!path) {
      return;
    }
    event.preventDefault();
    if (path === PortalShell.SIGNOUT_PATH) {
      this.signOut();
      return;
    }
    const method = String(form.getAttribute('method') || 'get').toLowerCase();
    if (method !== 'post') {
      const fields = this.fieldsOf(form, null);
      this.go(path + kit.queryOf(fields) + target.hash);
      return;
    }
    this.submit(form, event.submitter || null);
  }

  // SIGNING OUT ends the tokens here and the sign-on session they came from:
  // the protocol-independent sign-out ends the session, and every token
  // issued on it stops working (`account_api.ts`'s session check).
  /**
   * Signs out.
   *
   * @returns nothing
   */
  signOut(): void {
    this.accessToken = '';
    this.refreshToken = '';
    this.env.location.assign(this.url('/logout'));
  }

  // THE COPY BUTTONS (`/portal/copy.js` until #568): drawn hidden, so the
  // box beside them is the mechanism where they cannot work; revealed here,
  // and a click writes the text to the clipboard.
  /**
   * Wires the page drawn: the copy buttons and the WebAuthn ceremony.
   *
   * @returns nothing
   */
  wire(): void {
    const doc = this.env.document;
    const self = this;
    const nav = this.env.navigator;
    const buttons = doc.querySelectorAll
      ? doc.querySelectorAll('button[data-copy], button[data-copy-from]') : [];
    for (let i = 0; i < buttons.length; i++) {
      const button = buttons[i];
      button.hidden = false;
      button.addEventListener('click', function (event: Json) {
        if (event && event.preventDefault) {
          event.preventDefault();
        }
        const from = button.getAttribute('data-copy-from');
        const source = from ? doc.getElementById(from) : null;
        const text = source ? String(source.value || source.textContent || '')
                            : String(button.getAttribute('data-copy') || '');
        if (nav && nav.clipboard && nav.clipboard.writeText) {
          nav.clipboard.writeText(text).then(function () {
            return undefined;
          }, function () {
            return undefined;
          });
        }
      });
    }
    PortalWebAuthn.wire(doc, this.env.window || {}, function (form: Json) {
      self.submit(form, null);
    });
  }

  /**
   * Starts the portal: wires the document and draws the first page.
   *
   * @returns nothing
   */
  async start(): Promise<void> {
    const self = this;
    this.env.document.addEventListener('click', function (event: Json) {
      self.onClick(event);
    });
    this.env.document.addEventListener('submit', function (event: Json) {
      self.onSubmit(event);
    });
    if (this.env.window) {
      this.env.window.addEventListener('popstate', function () {
        // A FRAGMENT'S OWN NAVIGATION changes neither path nor query, and
        // the browser has already shown its target.
        if (self.env.location.pathname + self.env.location.search ===
            self.drawnAt) {
          return;
        }
        self.prefix = PortalRuntime.prefixOf(self.env.location.pathname);
        self.route();
      });
    }
    await this.route();
  }
}

export = PortalRuntime;
